#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "logger.hpp"

#include <imgui.h>

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {
using detail::activate_panel;
using detail::clamp_to_size_t;
using detail::same_selection;
} // namespace

void UiApp::toggle_bookmark_at_selection() {
    if (!model_.has_file()) {
        return;
    }
    const bool has_va = current_selection_.virtual_address.has_value();
    const bool has_off = current_selection_.file_offset.has_value();
    if (!has_va && !has_off) {
        return;
    }
    const bool is_off = !has_va && has_off;
    const std::uint64_t addr = has_va ? *current_selection_.virtual_address : *current_selection_.file_offset;
    if (model_.find_bookmark(addr, is_off) != nullptr) {
        model_.remove_bookmark_at(addr, is_off);
        Log().info("Removed bookmark at {}{:X}", is_off ? "off+0x" : "0x", addr);
    } else {
        std::string label = current_selection_.label;
        if (label.empty()) {
            label = is_off ? std::format("off_{:X}", addr) : std::format("loc_{:X}", addr);
        }
        model_.add_or_update_bookmark(Bookmark{
            .address = addr,
            .is_file_offset = is_off,
            .label = std::move(label),
            .category = "User",
            .note = {},
        });
        open_references();
        Log().info("Added bookmark at {}{:X}", is_off ? "off+0x" : "0x", addr);
    }
}

void UiApp::open_references() {
    references_panel_.set_visible(true);
    focus_references_ = true;
}

void UiApp::open_strings() {
    strings_panel_.set_visible(true);
    focus_strings_ = true;
}

void UiApp::open_structure_view(std::string_view type_name,
                                std::optional<std::uint64_t> address,
                                bool is_file_offset) {
    struct_view_panel_.set_visible(true);
    focus_struct_view_ = true;
    if (address) {
        struct_view_panel_.apply_structure_at(type_name, *address, is_file_offset, 1);
    } else if (!type_name.empty()) {
        const bool use_off = !model_.is_live_process() && !current_selection_.virtual_address.has_value();
        const std::uint64_t addr = use_off
            ? current_selection_.file_offset.value_or(0)
            : current_selection_.virtual_address.value_or(model_.view_base_address());
        struct_view_panel_.apply_structure_at(type_name, addr, use_off, 1);
    }
}

    void UiApp::render_disassembly_panel() {
    if (rendered_edit_revision_ != model_.edit_revision()) {
        rendered_edit_revision_ = model_.edit_revision();
        if (disassembly_location_)
            disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
    }
    ImGui::Begin("Disassembly");
    std::optional<std::uint64_t> follow_target;
    std::optional<int> scroll_to_row;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_Space)) switch_analysis_view(true);
        const auto selected = std::ranges::find_if(current_instructions_, [this](const auto& instruction) {
            return current_selection_.virtual_address == instruction.address;
        });
        if (selected != current_instructions_.end() && ImGui::IsKeyPressed(ImGuiKey_Enter)) follow_target = selected->branch_target;
        if (!current_instructions_.empty() && (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
            auto index = selected == current_instructions_.end() ? std::ptrdiff_t{0} : selected - current_instructions_.begin();
            if (selected != current_instructions_.end()) index += ImGui::IsKeyPressed(ImGuiKey_UpArrow) ? -1 : 1;
            index = std::clamp(index, std::ptrdiff_t{0}, static_cast<std::ptrdiff_t>(current_instructions_.size() - 1));
            const auto& instruction = current_instructions_[static_cast<std::size_t>(index)];
            if (const auto offset = model_.virtual_address_to_offset(instruction.address)) {
                const auto root = navigation_graph_root(instruction.address);
                current_selection_ = {.kind = SelectionKind::ByteRange, .label = instruction.to_string(),
                    .file_offset = *offset, .virtual_address = instruction.address, .size = instruction.bytes.size(),
                    .preferred_view = PreferredView::Disassembly, .graph_root = root};
                scroll_to_row = index > static_cast<std::ptrdiff_t>(std::numeric_limits<int>::max())
                                    ? std::optional<int>{}
                                    : std::optional<int>(static_cast<int>(index));
                last_navigation_selection_ = current_selection_;
                hex_panel_.navigate_to_range(*offset, instruction.bytes.size());
            }
        }
    }

    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::TextDisabled("No file or live process loaded, or disassembler not initialized.");
        ImGui::End();
        return;
    }

    if (disasm_.architecture() == Architecture::ARM32 && ImGui::Checkbox("Thumb mode", &thumb_mode_)) {
        if (disasm_.set_thumb_mode(thumb_mode_)) {
            pending_call_graph_root_ = active_graph_root_;
            if (disassembly_location_)
                disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
        } else {
            thumb_mode_ = !thumb_mode_;
            Log().error("Unable to change ARM instruction mode");
        }
    }
    if (!disasm_status_.empty()) ImGui::TextWrapped("%s", disasm_status_.c_str());

    const std::optional<std::uint64_t> active_debug_ip =
        (model_.debug_session() != nullptr &&
         model_.debug_session()->state() == peelf::debugger::DebugSessionState::Paused)
            ? std::optional<std::uint64_t>(model_.debug_session()->stop_status().instruction_pointer)
            : std::nullopt;

    // Simple table view with debugger breakpoint + current IP/PC gutter
    std::optional<std::uint64_t> pending_bp_toggle_va;
    if (ImGui::BeginTable("DisasmTableReadable", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("BP", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 36.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, ImGui::CalcTextSize("0000000000000000").x + 16.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 22.0f);
        ImGui::TableSetupColumn("Symbol / annotation", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 28.0f);
        ImGui::TableSetupScrollFreeze(2, 1);
        ImGui::TableHeadersRow();

        const int clipped_inst_count =
            current_instructions_.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
                ? std::numeric_limits<int>::max()
                : static_cast<int>(current_instructions_.size());
        ImGuiListClipper clipper;
        clipper.Begin(clipped_inst_count);
        if (scroll_to_row && *scroll_to_row >= 0 && *scroll_to_row < clipped_inst_count) {
            clipper.IncludeItemByIndex(*scroll_to_row);
        }
        while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& inst = current_instructions_[static_cast<std::size_t>(row)];
            const auto* row_bp = model_.find_breakpoint_at(inst.address);
            const bool is_ip = active_debug_ip.has_value() && *active_debug_ip == inst.address;

            ImGui::TableNextRow();
            if (is_ip) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                       ImGui::GetColorU32(ImVec4(0.08f, 0.34f, 0.42f, 0.48f)));
            }

            // Debugger Gutter (Breakpoint badge + Current IP/PC arrow)
            ImGui::TableNextColumn();
            ImGui::PushID(row * 2 + 1);
            if (row_bp != nullptr) {
                const ImVec4 bp_col = row_bp->enabled
                    ? ImVec4(0.95f, 0.28f, 0.28f, 1.0f)
                    : ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
                ImGui::TextColored(bp_col, row_bp->enabled ? "●" : "○");
                if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && model_.is_debug_session()) {
                    pending_bp_toggle_va = inst.address;
                }
            } else if (model_.is_debug_session() && !is_ip) {
                if (ImGui::Selectable("##BpGutter", false, 0, ImVec2(14.0f, 0.0f))) {
                    pending_bp_toggle_va = inst.address;
                }
            }
            if (is_ip) {
                if (row_bp != nullptr) ImGui::SameLine(0.0f, 2.0f);
                ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.98f, 1.0f), "▶");
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Current instruction pointer (IP/PC)");
                }
            }
            ImGui::PopID();

            // Address
            ImGui::TableNextColumn();
            ImGui::PushID(row * 2);
            if (ImGui::Selectable(std::format("{:016X}", inst.address).c_str(),
                current_selection_.virtual_address == inst.address, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) follow_target = inst.branch_target;
                if (const auto offset = model_.virtual_address_to_offset(inst.address)) {
                    const auto root = navigation_graph_root(inst.address);
                    hex_panel_.navigate_to_range(*offset, inst.bytes.size());
                    current_selection_ = ViewerSelection{
                        .kind = SelectionKind::ByteRange,
                        .label = "Instruction: " + inst.to_string(),
                        .file_offset = *offset,
                        .virtual_address = inst.address,
                        .size = inst.bytes.size(),
                        .preferred_view = PreferredView::Disassembly,
                        .graph_root = root
                    };
                    last_navigation_selection_ = current_selection_;
                }
            }
            ImGui::PopID();

            // Bytes
            if (scroll_to_row && row == *scroll_to_row) ImGui::SetScrollHereY();
            // Bytes (highlight if any instruction byte is staged or committed)
            ImGui::TableNextColumn();
            BytePatchState inst_patch_state = BytePatchState::Unchanged;
            if (const auto base_off = model_.virtual_address_to_offset(inst.address)) {
                for (std::size_t bi = 0; bi < inst.bytes.size(); ++bi) {
                    const BytePatchState st = model_.byte_patch_state_at_offset(*base_off + bi);
                    if (st == BytePatchState::Staged) {
                        inst_patch_state = BytePatchState::Staged;
                        break;
                    }
                    if (st == BytePatchState::Committed) {
                        inst_patch_state = BytePatchState::Committed;
                    }
                }
            }
            std::string bytes_str;
            bytes_str.reserve(inst.bytes.size() * 3);
            for (const std::uint8_t b : inst.bytes) {
                bytes_str += std::format("{:02X} ", b);
            }
            if (inst_patch_state == BytePatchState::Staged) {
                ImGui::TextColored(ImVec4(1.0f, 0.78f, 0.25f, 1.0f), "%s", bytes_str.c_str());
            } else if (inst_patch_state == BytePatchState::Committed) {
                ImGui::TextColored(ImVec4(0.35f, 0.92f, 0.55f, 1.0f), "%s", bytes_str.c_str());
            } else {
                ImGui::TextDisabled("%s", bytes_str.c_str());
            }

            // Mnemonic (color-coded)
            ImGui::TableNextColumn();
            ImVec4 color = get_mnemonic_color(inst.mnemonic);
            ImGui::TextColored(color, "%s", inst.mnemonic.c_str());

            // Operands
            ImGui::TableNextColumn();
            ImGui::Text("%s", inst.operands.c_str());
            if (inst.branch_target) {
                const auto* target = symbol_index_.find_containing_address(*inst.branch_target);
                if (target && target->virtual_address) {
                    const auto delta = *inst.branch_target - *target->virtual_address;
                    const std::string& tname = target->display_name(model_.demangle_symbols());
                    const auto label = delta ? std::format("{}+0x{:X}", tname, delta) : tname;
                    ImGui::SameLine();
                    ImGui::TextDisabled("; %s", label.c_str());
                    if (ImGui::IsItemHovered() && tname != target->name) {
                        ImGui::SetTooltip("Raw symbol: %s", target->name.c_str());
                    }
                }
            }
            ImGui::TableNextColumn();
            const SourceLineMapping* exact_src = model_.find_source_line(inst.address, 0);
            const SourceLineMapping* near_src = exact_src != nullptr
                ? exact_src
                : model_.find_source_line(inst.address, 32);
            std::string col_text;
            std::string raw_tooltip;
            if (const auto* note = annotations_.find(inst.address); note && (!note->name.empty() || !note->comment.empty())) {
                col_text = note->name + (note->comment.empty() ? "" : " ; " + note->comment);
            } else if (const auto* symbol = symbol_index_.find_containing_address(inst.address); symbol && symbol->virtual_address) {
                const auto offset = inst.address - *symbol->virtual_address;
                const std::string& sname = symbol->display_name(model_.demangle_symbols());
                col_text = offset == 0 ? sname : std::format("{}+0x{:X}", sname, offset);
                if (sname != symbol->name) {
                    raw_tooltip = symbol->name;
                }
            }
            if (exact_src != nullptr) {
                const std::string src_tag = std::format("[{}:{}]",
                    !exact_src->file_name.empty() ? exact_src->file_name : exact_src->file_path,
                    exact_src->line);
                col_text = col_text.empty() ? src_tag : (col_text + "  " + src_tag);
            }
            if (!col_text.empty()) {
                ImGui::TextUnformatted(col_text.c_str());
                if (ImGui::IsItemHovered() && (!raw_tooltip.empty() || near_src != nullptr)) {
                    if (!raw_tooltip.empty() && near_src != nullptr) {
                        ImGui::SetTooltip("Raw symbol: %s\nSource: %s:%u",
                                          raw_tooltip.c_str(), near_src->file_path.c_str(), near_src->line);
                    } else if (!raw_tooltip.empty()) {
                        ImGui::SetTooltip("Raw symbol: %s", raw_tooltip.c_str());
                    } else if (near_src != nullptr) {
                        ImGui::SetTooltip("Source: %s:%u", near_src->file_path.c_str(), near_src->line);
                    }
                }
            }
        }
        }

        ImGui::EndTable();
                          }
    if (pending_bp_toggle_va.has_value() && model_.is_debug_session()) {
        (void)model_.toggle_software_breakpoint(*pending_bp_toggle_va);
    }

    ImGui::End();
    if (follow_target) enqueue_navigation(*follow_target);
}

std::optional<SymbolRecord> UiApp::navigation_graph_root(std::uint64_t address) const {
    if (current_selection_.virtual_address == address && current_selection_.graph_root)
        return current_selection_.graph_root;
    if (active_graph_root_ && current_call_graph_ && current_call_graph_->id == "function_cfg") {
        for (const auto& node : current_call_graph_->nodes) {
            if (node.kind != CallGraphNodeKind::BasicBlock || !node.bytes.start.virtual_address) continue;
            const auto start = *node.bytes.start.virtual_address;
            if (address >= start && address - start < node.bytes.size) return active_graph_root_;
        }
    }
    if (const auto* image = model_.image()) {
        if (const auto* symbol = symbol_index_.find_containing_address(address); symbol && symbol_has_code(*image, *symbol))
            return *symbol;
    }
    return std::nullopt;
}

void UiApp::navigate_to_address(std::uint64_t address, PreferredView view) {
    if (!model_.has_file()) {
        return;
    }

    std::optional<std::uint64_t> offset = model_.virtual_address_to_offset(address);
    if (!offset && model_.is_live_process()) {
        if (model_.navigate_to_virtual_address(address)) {
            sync_live_process_view(false);
            offset = model_.virtual_address_to_offset(address);
        }
    }
    if (!offset || *offset >= model_.view_size()) {
        Log().warn("Address 0x{:X} is not mapped in the active image or memory map", address);
        return;
    }

    navigation_history_.visit(current_selection_);
    const auto* symbol = symbol_index_.find_containing_address(address);
    auto root = navigation_graph_root(address);
    const std::optional<std::uint64_t> static_file_off =
        model_.image() != nullptr ? model_.image()->virtual_address_to_file_offset(address) : offset;
    if (!root) {
        root = SymbolRecord{
            .name = std::format("loc_{:X}", address),
            .virtual_address = address,
            .file_offset = static_file_off.value_or(*offset),
        };
    }
    current_selection_ = {
        .kind = SelectionKind::ByteRange,
        .label = symbol ? symbol->name : std::format("loc_{:X}", address),
        .file_offset = *offset,
        .virtual_address = address,
        .size = 1,
        .preferred_view = view,
        .graph_root = root,
    };
    hex_panel_.navigate_to_range(*offset, 1);
    disassemble_at_offset(*offset, address);
    last_navigation_selection_ = current_selection_;
    if (view == PreferredView::Graph && model_.image() != nullptr) {
        if (!active_graph_root_ || active_graph_root_->virtual_address != root->virtual_address) {
            pending_call_graph_root_ = *root;
            pending_call_graph_delay_frames_ = 0;
        }
        show_call_graph_panel_ = true;
        focus_graph_ = true;
        center_graph_selection_ = true;
    } else if (view == PreferredView::Hex) {
        hex_panel_.set_visible(true);
        activate_panel("Hex View");
    } else {
        show_disassembly_panel_ = true;
        focus_listing_ = true;
    }
    navigation_history_.visit(current_selection_);
}

void UiApp::enqueue_navigation(std::uint64_t address,
                               PreferredView view,
                               std::size_t highlight_size,
                               bool request_decompile) {
    pending_navigations_.enqueue_address(address, view, highlight_size, request_decompile);
}

void UiApp::drain_pending_navigations() {
    pending_navigations_.drain([this](DeferredNavigationRequest& req) {
        switch (req.kind) {
            case DeferredNavigationRequest::Kind::Address: {
                navigate_to_address(req.target, req.preferred_view);
                if (req.highlight_size > 1) {
                    if (const auto off = model_.virtual_address_to_offset(req.target)) {
                        hex_panel_.navigate_to_range(*off, req.highlight_size);
                    }
                }
                if (req.request_decompile) {
                    request_decompile();
                }
                break;
            }
            case DeferredNavigationRequest::Kind::Offset: {
                if (req.target >= model_.view_size()) {
                    break;
                }
                const auto va = model_.offset_to_virtual_address(req.target);
                const std::uint64_t sz = std::max<std::uint64_t>(1u, req.highlight_size);
                current_selection_ = ViewerSelection{
                    .kind = SelectionKind::ByteRange,
                    .label = std::format("off+0x{:X}", req.target),
                    .file_offset = req.target,
                    .virtual_address = va,
                    .size = sz,
                    .preferred_view = PreferredView::Hex,
                };
                hex_panel_.set_visible(true);
                hex_panel_.navigate_to_range(req.target, sz);
                if (va) {
                    disassemble_at_offset(req.target, *va);
                }
                last_navigation_selection_ = current_selection_;
                break;
            }
            case DeferredNavigationRequest::Kind::ModuleIndex: {
                const auto module_index = clamp_to_size_t(req.target);
                auto res = model_.select_process_module(module_index);
                if (!res) {
                    Log().error("Failed to select module: {}", res.error().message);
                    break;
                }
                sync_live_process_view(true);
                break;
            }
            case DeferredNavigationRequest::Kind::MemoryRegionIndex: {
                const auto region_index = clamp_to_size_t(req.target);
                if (region_index >= model_.memory_regions().size()) {
                    break;
                }
                const peelf::MemoryRegion reg_copy = model_.memory_regions()[region_index];
                auto res = model_.select_memory_region(region_index, req.prefer_module_context);
                if (!res) {
                    Log().error("Failed to select memory region: {}", res.error().message);
                    break;
                }
                sync_live_process_view(false);
                const std::uint64_t offset =
                    model_.virtual_address_to_offset(reg_copy.start_address).value_or(0u);
                current_selection_ = selection_from_memory_region(
                    reg_copy, static_cast<std::uint64_t>(region_index), offset);
                hex_panel_.navigate_to_range(offset, std::min<std::uint64_t>(reg_copy.size(), 16u));
                if (reg_copy.protection.executable) {
                    const auto disasm_win = static_cast<std::size_t>(
                        std::clamp<std::uint64_t>(reg_copy.size(), 4096u, 65536u));
                    disassemble_at_offset(offset, reg_copy.start_address, disasm_win);
                    show_disassembly_panel_ = true;
                    focus_listing_ = true;
                }
                last_navigation_selection_ = current_selection_;
                break;
            }
            case DeferredNavigationRequest::Kind::Custom: {
                if (req.custom_action) {
                    req.custom_action();
                }
                break;
            }
        }
    });
}

void UiApp::navigate_history(bool forward) {
    navigation_history_.visit(current_selection_);
    const auto destination = forward ? navigation_history_.forward() : navigation_history_.back();
    if (!destination) return;
    // Set the destination first so the common navigation path preserves the cursor.
    current_selection_ = *destination;
    if (destination->virtual_address) {
        navigate_to_address(*destination->virtual_address, destination->preferred_view);
        current_selection_ = *destination;
        last_navigation_selection_ = current_selection_;
        if (destination->file_offset) {
            hex_panel_.navigate_to_range(*destination->file_offset,
                                         std::max<std::uint64_t>(1u, destination->size));
        }
    }
    else { last_navigation_selection_.reset(); apply_structure_selection_navigation(); }
}

void UiApp::switch_analysis_view(bool graph) {
    auto selection = current_selection_;
    if (current_selection_.virtual_address) {
        navigate_to_address(*current_selection_.virtual_address, graph ? PreferredView::Graph : PreferredView::Disassembly);
        selection.graph_root = current_selection_.graph_root;
        selection.preferred_view = graph ? PreferredView::Graph : PreferredView::Disassembly;
        current_selection_ = std::move(selection);
        last_navigation_selection_ = current_selection_;
        if (current_selection_.file_offset) {
            hex_panel_.navigate_to_range(*current_selection_.file_offset,
                                         std::max<std::uint64_t>(1u, current_selection_.size));
        }
    }
}

    void UiApp::apply_structure_selection_navigation() {
        if (current_selection_.kind == SelectionKind::None ||
            current_selection_.kind == SelectionKind::Group ||
            current_selection_.kind == SelectionKind::Process) {
            return;
        }
        if (last_navigation_selection_ &&
            same_selection(*last_navigation_selection_, current_selection_)) {
            return;
        }

        if (current_selection_.kind == SelectionKind::ProcessModule && model_.is_live_process()) {
            const auto mod_idx = static_cast<std::size_t>(current_selection_.object_index);
            if (model_.active_module_index() != mod_idx && mod_idx < model_.process_modules().size()) {
                const ViewerSelection saved_sel = current_selection_;
                if (model_.select_process_module(mod_idx)) {
                    sync_live_process_view(true);
                    current_selection_ = saved_sel;
                }
            }
            last_navigation_selection_ = current_selection_;
            return;
        }

        if (current_selection_.kind == SelectionKind::MemoryRegion && model_.is_live_process()) {
            const auto reg_idx = static_cast<std::size_t>(current_selection_.object_index);
            if (reg_idx < model_.memory_regions().size()) {
                const peelf::MemoryRegion reg_copy = model_.memory_regions()[reg_idx];
                const ViewerSelection saved_sel = current_selection_;
                if (model_.select_memory_region(reg_idx, true)) {
                    sync_live_process_view(false);
                    current_selection_ = saved_sel;
                    const std::uint64_t off = model_.virtual_address_to_offset(reg_copy.start_address).value_or(0u);
                    current_selection_.file_offset = off;
                    hex_panel_.navigate_to_range(off, std::min<std::uint64_t>(reg_copy.size(), 16u));
                    if (reg_copy.protection.executable) {
                        const auto disasm_win = static_cast<std::size_t>(
                            std::clamp<std::uint64_t>(reg_copy.size(), 4096u, 65536u));
                        disassemble_at_offset(off, reg_copy.start_address, disasm_win);
                    }
                }
            }
            last_navigation_selection_ = current_selection_;
            return;
        }

        std::optional<std::uint64_t> nav_offset = current_selection_.file_offset;
        if (model_.is_live_process() && current_selection_.virtual_address) {
            if (const auto live_off = model_.virtual_address_to_offset(*current_selection_.virtual_address)) {
                nav_offset = live_off;
            }
        } else if (!nav_offset && current_selection_.virtual_address) {
            nav_offset = model_.virtual_address_to_offset(*current_selection_.virtual_address);
        }

        if (!nav_offset) {
            last_navigation_selection_ = current_selection_;
            return;
        }

        const std::uint64_t size = current_selection_.size != 0 ? current_selection_.size : 1u;
        hex_panel_.navigate_to_range(*nav_offset, size);

        if (current_selection_.preferred_view == PreferredView::Disassembly) {
            const std::uint64_t display_address = current_selection_.virtual_address
                ? *current_selection_.virtual_address
                : *nav_offset;
            disassemble_at_offset(*nav_offset, display_address);
        }

        last_navigation_selection_ = current_selection_;
    }




    void UiApp::disassemble_section(const std::string& section_name, std::size_t max_size) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            fprintf(stderr, "No binary image loaded\n");
            return;
        }
        const peelf::Section* section = nullptr;
        for (const auto& s : img->sections()) {
            if (s.name == section_name) {
                section = &s;
                break;
            }
        }
        if (section == nullptr) {
            fprintf(stderr, "Section '%s' not found\n", section_name.c_str());
            return;
        }
        if (!section->executable) {
            fprintf(stderr, "Warning: Section '%s' is not marked executable\n", section_name.c_str());
        }

        const std::uint64_t window_off = model_.is_live_process()
            ? model_.virtual_address_to_offset(section->virtual_address).value_or(0u)
            : section->file_offset;
        const std::size_t size = std::min<std::size_t>(
            max_size,
            clamp_to_size_t(section->file_size != 0u ? section->file_size : section->virtual_size));
        const auto sample = model_.read_effective_bytes(window_off, size);
        if (!sample.has_value() || sample->empty()) {
            fprintf(stderr, "Failed to read section data\n");
            return;
        }

        const std::uint64_t va = section->virtual_address;
        const auto instructions = disasm_.disassemble(sample->data(), sample->size(), va);

        const std::uint64_t end_va =
            section->virtual_size > std::numeric_limits<std::uint64_t>::max() - va
                ? std::numeric_limits<std::uint64_t>::max()
                : (va + section->virtual_size);
        Log().info("Section: {} (0x{:X} - 0x{:X})",
                   section_name,
                   va,
                   end_va);

        for (const auto& inst : instructions) {
            std::string bytes_str;
            bytes_str.reserve(inst.bytes.size() * 3);
            for (const std::uint8_t b : inst.bytes) {
                bytes_str += std::format("{:02X} ", b);
            }

            Log().info("{:016X}  {:<24}  {}",
                       inst.address,
                       bytes_str,
                       inst.to_string());
        }
    }
    void UiApp::disassemble_at(std::uint64_t rva, std::size_t size) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            Log().error("No binary image loaded");
            return;
        }
        if (rva > std::numeric_limits<std::uint64_t>::max() - img->image_base()) {
            Log().error("RVA 0x{:X} overflows image base 0x{:X}", rva, img->image_base());
            return;
        }
        const std::uint64_t va = img->image_base() + rva;
        const auto window_off = model_.virtual_address_to_offset(va);
        if (!window_off.has_value()) {
            Log().error("Failed to convert RVA 0x{:X} to offset", rva);
            return;
        }

        const auto sample = model_.read_effective_bytes(*window_off, size);
        if (!sample.has_value() || sample->empty()) {
            Log().error("Failed to read {} bytes at offset 0x{:X}", size, *window_off);
            return;
        }

        const auto instructions = disasm_.disassemble(sample->data(), sample->size(), va);
        for (const auto& inst : instructions) {
            std::string bytes_str;
            bytes_str.reserve(inst.bytes.size() * 3);
            for (const std::uint8_t b : inst.bytes) {
                bytes_str += std::format("{:02X} ", b);
            }

            Log().info("{:016X}  {:<24}  {}",
                       inst.address,
                       bytes_str,
                       inst.to_string());
        }
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset) {
        const std::uint64_t display_address =
            model_.offset_to_virtual_address(file_offset).value_or(file_offset);
        disassemble_at_offset(file_offset, display_address, 4096u);
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset, std::uint64_t display_address) {
        disassemble_at_offset(file_offset, display_address, 4096u);
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset,
                                      std::uint64_t display_address,
                                      std::size_t max_window_bytes) {
        disassembly_location_ = DisassemblyLocation{file_offset, display_address};
        if (!file_loaded_ || !disasm_.is_initialized()) {
            return;
        }
        const std::uint64_t total_size = model_.view_size();
        if (file_offset >= total_size) {
            return;
        }
        last_disasm_offset_ = file_offset;
        last_disasm_address_ = display_address;
        last_disasm_window_ = std::clamp<std::size_t>(max_window_bytes, 256u, 65536u);

        const auto sample = model_.read_window_sample(file_offset, last_disasm_window_);
        std::size_t readable_len = 0;
        if (sample) {
            while (readable_len < sample->valid.size() && sample->valid[readable_len] != 0) {
                ++readable_len;
            }
        }
        if (readable_len == 0) {
            current_instructions_.clear();
            disasm_status_ = std::format(
                "Memory at 0x{:X} is unreadable (guard page or unmapped region).",
                display_address);
            return;
        }
        disasm_status_.clear();
        current_instructions_ = disasm_.disassemble(sample->bytes.data(), readable_len, display_address);
    }

    void UiApp::refresh_disassembly() {
        if (last_disasm_offset_) {
            disassemble_at_offset(*last_disasm_offset_, last_disasm_address_, last_disasm_window_);
        }
    }

    void UiApp::disassemble_entry_point(std::size_t max_size) {
        current_instructions_.clear();
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            Log().error("Failed to get loaded binary image\n");
            return;
        }

        const std::uint64_t va = img->entry_point();
        const auto offset = model_.virtual_address_to_offset(va);
        if (!offset.has_value()) {
            Log().error("Failed to get entry point offset\n");
            return;
        }

        for (const auto& s : img->sections()) {
            const std::uint64_t sec_span = s.file_size != 0u ? s.file_size : s.virtual_size;
            if (va >= s.virtual_address && (va - s.virtual_address) < sec_span) {
                const auto remaining = clamp_to_size_t(sec_span - (va - s.virtual_address));
                max_size = std::min(max_size, remaining);
                break;
            }
        }

        const auto sample = model_.read_effective_bytes(*offset, max_size);
        if (!sample.has_value() || sample->empty()) {
            Log().error("Failed to read entry point code\n");
            return;
        }

        current_instructions_ = disasm_.disassemble(sample->data(), sample->size(), va);

        Log().info("Entry Point: 0x{:X}", va);

        for (const auto& inst : current_instructions_) {
            std::string bytes_str;
            bytes_str.reserve(inst.bytes.size() * 3);
            for (const std::uint8_t b : inst.bytes) {
                bytes_str += std::format("{:02X} ", b);
            }

            Log().info("{:016X}  {:24}  {}",
                       inst.address,
                       bytes_str,
                       inst.to_string());
        }
    }

    ImVec4 UiApp::get_mnemonic_color(const std::string& mnemonic) const {
    if (mnemonic.empty()) {
        return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }

    // Branch/control flow - Blue
    if (mnemonic[0] == 'j' ||
        mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" ||
        mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "syscall" || mnemonic == "sysret" ||
        mnemonic == "b" || mnemonic == "bl" || mnemonic == "bx" || mnemonic == "blx" ||
        mnemonic == "cbz" || mnemonic == "cbnz") {
        return ImGui::GetStyleColorVec4(ImGuiCol_CheckMark);
    }

    // SIMD/Vector - Green
    if (mnemonic[0] == 'v' ||  // AVX
        mnemonic.find("movap") == 0 || mnemonic.find("movup") == 0 ||
        mnemonic.find("movdq") == 0 || mnemonic.find("movss") == 0 ||
        mnemonic.find("movsd") == 0 || mnemonic.find("addp") == 0 ||
        mnemonic.find("subp") == 0 || mnemonic.find("mulp") == 0 ||
        mnemonic.find("divp") == 0 || mnemonic.find("xmm") != std::string::npos ||
        mnemonic.find("ymm") != std::string::npos ||
        mnemonic.find("zmm") != std::string::npos) {
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotLines);
    }

    // NOP/padding - Gray
    if (mnemonic == "nop" || mnemonic == "int3" || mnemonic == "ud2") {
        return ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    }

    // Data movement - Light yellow
    if (mnemonic.find("mov") == 0 || mnemonic == "lea" ||
        mnemonic == "push" || mnemonic == "pop" ||
        mnemonic == "xchg" || mnemonic == "ldr" || mnemonic == "str") {
        return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }

    // Arithmetic - Orange
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "mul" ||
        mnemonic == "div" || mnemonic == "inc" || mnemonic == "dec" ||
        mnemonic == "imul" || mnemonic == "idiv" || mnemonic == "neg") {
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotHistogram);
    }

    // Logic/bitwise - Purple
    if (mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "not" || mnemonic == "shl" || mnemonic == "shr" ||
        mnemonic == "sar" || mnemonic == "rol" || mnemonic == "ror" ||
        mnemonic == "test" || mnemonic == "cmp") {
        return ImGui::GetStyleColorVec4(ImGuiCol_CheckMark);
    }

    // Compare/test - Cyan
    if (mnemonic == "cmp" || mnemonic == "test" ||
        mnemonic.find("cmp") == 0 || mnemonic.find("test") == 0) {
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotLines);
    }

    // Default - White
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}
} // namespace viewer
