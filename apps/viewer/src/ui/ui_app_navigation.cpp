#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "logger.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cinttypes>
#include <cmath>
#include <cstdio>
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

[[nodiscard]] std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex_u64(std::string_view sv) noexcept {
    sv = trim_ascii(sv);
    if (sv.size() > 2u && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) {
        sv.remove_prefix(2);
    }
    if (sv.empty()) {
        return std::nullopt;
    }
    std::uint64_t val = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), val, 16);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return std::nullopt;
    }
    return val;
}

[[nodiscard]] bool icontains_ascii(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || needle.size() > hay.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const int a = std::tolower(static_cast<unsigned char>(hay[i + j]));
            const int b = std::tolower(static_cast<unsigned char>(needle[j]));
            if (a != b) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && icontains_ascii(a, b);
}

[[nodiscard]] const peelf::Section* find_image_section_by_va(
    const peelf::IBinaryImage& image,
    std::uint64_t va) noexcept {
    for (const peelf::Section& sec : image.sections()) {
        const std::uint64_t span = std::max(sec.file_size, sec.virtual_size);
        if (span != 0u && va >= sec.virtual_address && va - sec.virtual_address < span) {
            return &sec;
        }
    }
    return nullptr;
}

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

std::optional<std::uint64_t> UiApp::resolve_disasm_goto_query(std::string_view query) const {
    query = trim_ascii(query);
    if (query.empty() || !model_.has_file()) {
        return std::nullopt;
    }

    const bool is_arm32 = disasm_.architecture() == Architecture::ARM32;
    const auto normalize_va = [is_arm32](std::uint64_t va) noexcept -> std::uint64_t {
        return is_arm32 ? (va & ~std::uint64_t{1u}) : va;
    };

    const std::uint64_t base_va = model_.image() != nullptr
        ? model_.image()->image_base()
        : model_.view_base_address();

    if (query.front() == '+') {
        if (const auto rva = parse_hex_u64(query.substr(1))) {
            if (*rva <= std::numeric_limits<std::uint64_t>::max() - base_va) {
                const std::uint64_t va = normalize_va(base_va + *rva);
                if (model_.virtual_address_to_offset(va).has_value() || model_.is_live_process()) {
                    return va;
                }
            }
        }
    }

    if (const auto expr_res = evaluate_address_expression(
            query, make_address_expression_context(model_, &symbol_index_, &annotations_));
        expr_res.has_value()) {
        if (expr_res->virtual_address.has_value()) {
            const std::uint64_t candidate_va = normalize_va(*expr_res->virtual_address);
            if (model_.virtual_address_to_offset(candidate_va).has_value() ||
                model_.is_live_process()) {
                return candidate_va;
            }
            if (base_va != 0u && *expr_res->virtual_address < base_va &&
                *expr_res->virtual_address <= std::numeric_limits<std::uint64_t>::max() - base_va) {
                const std::uint64_t rva_candidate =
                    normalize_va(base_va + *expr_res->virtual_address);
                if (model_.virtual_address_to_offset(rva_candidate).has_value()) {
                    return rva_candidate;
                }
            }
        }
        if (expr_res->file_offset.has_value()) {
            if (const auto mapped_va = model_.offset_to_virtual_address(*expr_res->file_offset)) {
                return normalize_va(*mapped_va);
            }
        }
    }

    if (query.starts_with("off:") || query.starts_with("OFF:") ||
        query.starts_with("offset:") || query.starts_with("OFFSET:")) {
        const std::size_t colon = query.find(':');
        if (const auto off = parse_hex_u64(query.substr(colon + 1u))) {
            if (const auto va = model_.offset_to_virtual_address(*off)) {
                return normalize_va(*va);
            }
        }
    }

    if (const auto parsed_num = parse_hex_u64(query)) {
        const std::uint64_t candidate_va = normalize_va(*parsed_num);
        if (model_.virtual_address_to_offset(candidate_va).has_value()) {
            return candidate_va;
        }
        if (base_va != 0u && *parsed_num < base_va &&
            *parsed_num <= std::numeric_limits<std::uint64_t>::max() - base_va) {
            const std::uint64_t rva_candidate = normalize_va(base_va + *parsed_num);
            if (model_.virtual_address_to_offset(rva_candidate).has_value()) {
                return rva_candidate;
            }
        }
        if (model_.is_live_process()) {
            return candidate_va;
        }
    }

    for (const auto& [addr, note] : annotations_.records()) {
        if (!note.name.empty() && iequals_ascii(note.name, query)) {
            return normalize_va(addr);
        }
    }

    const bool demangle_syms = model_.demangle_symbols();
    for (const auto& fn : model_.function_index().entries()) {
        const std::string& disp = fn.display_name(demangle_syms);
        if (iequals_ascii(fn.name, query) || iequals_ascii(disp, query)) {
            return normalize_va(fn.virtual_address);
        }
    }

    for (const auto& sym : symbol_index_.records()) {
        if (!sym.virtual_address.has_value()) {
            continue;
        }
        const std::string& demangled = sym.display_name(true);
        if (iequals_ascii(sym.name, query) || iequals_ascii(demangled, query)) {
            return normalize_va(*sym.virtual_address);
        }
    }

    for (const auto& [addr, note] : annotations_.records()) {
        if (!note.name.empty() && icontains_ascii(note.name, query)) {
            return normalize_va(addr);
        }
    }
    for (const auto& fn : model_.function_index().entries()) {
        const std::string& disp = fn.display_name(demangle_syms);
        if (icontains_ascii(disp, query) || icontains_ascii(fn.name, query)) {
            return normalize_va(fn.virtual_address);
        }
    }
    for (const auto& sym : symbol_index_.records()) {
        if (!sym.virtual_address.has_value()) {
            continue;
        }
        const std::string& demangled = sym.display_name(true);
        if (icontains_ascii(demangled, query) || icontains_ascii(sym.name, query)) {
            return normalize_va(*sym.virtual_address);
        }
    }

    return std::nullopt;
}

    void UiApp::render_disassembly_panel() {
    if (rendered_edit_revision_ != model_.edit_revision()) {
        rendered_edit_revision_ = model_.edit_revision();
        if (disassembly_location_) {
            disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
        }
    }

    ImGui::Begin("Disassembly");

    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::TextDisabled("No file or live process loaded, or disassembler not initialized.");
        ImGui::End();
        return;
    }

    (void)linear_disasm_.sync_with_model(model_, thumb_mode_, thumb_mode_user_forced_);

    const auto select_instruction = [this](const Instruction& inst, bool sync_hex) {
        const auto offset = model_.virtual_address_to_offset(inst.address);
        const auto root = navigation_graph_root(inst.address);
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = "Instruction: " + inst.to_string(),
            .file_offset = offset,
            .virtual_address = inst.address,
            .size = std::max<std::size_t>(1u, inst.bytes.size()),
            .preferred_view = PreferredView::Disassembly,
            .graph_root = root,
        };
        last_navigation_selection_ = current_selection_;
        if (offset.has_value()) {
            disassembly_location_ = DisassemblyLocation{*offset, inst.address};
        }
        if (sync_hex) {
            if (offset.has_value() && *offset < model_.view_size()) {
                hex_panel_.navigate_to_range(*offset, std::max<std::size_t>(1u, inst.bytes.size()));
            } else {
                const HexAvailabilityStatus avail =
                    evaluate_hex_selection_availability(model_, current_selection_);
                if (!avail.available) {
                    hex_panel_.set_unavailable_reason(avail.unavailable_reason);
                }
            }
        }
    };

    const auto execute_goto_query = [this](std::string_view raw_query) -> bool {
        if (const auto target_va = resolve_disasm_goto_query(raw_query)) {
            disasm_goto_status_.clear();
            return navigate_to_address(*target_va, PreferredView::Disassembly);
        }
        disasm_goto_status_ = std::format("Unresolved target: '{}'", trim_ascii(raw_query));
        return false;
    };

    // --- Toolbar Row 1: Address Mode, Sync & Source Toggles, ARM/Thumb, Quick Go-to ---
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Addr:");
    ImGui::SameLine(0.0f, 4.0f);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 6.8f);
    {
        const char* const addr_labels[] = {"VA", "RVA", "File Offset"};
        int mode_idx = static_cast<int>(disasm_address_mode_);
        if (ImGui::Combo("##DisasmAddrMode", &mode_idx, addr_labels, 3)) {
            disasm_address_mode_ = static_cast<AddressDisplayMode>(std::clamp(mode_idx, 0, 2));
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Address column format (Virtual Address / RVA / File Offset)");
        }
    }

    ImGui::SameLine();
    ImGui::Checkbox("Follow Hex", &disasm_follow_hex_);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Keep Hex View synchronized when selecting or stepping instructions");
    }

    ImGui::SameLine();
    ImGui::Checkbox("Source Lines", &disasm_show_source_lines_);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Display interleaved [file:line] DWARF / PDB source annotations");
    }

    if (disasm_.architecture() == Architecture::ARM32) {
        ImGui::SameLine();
        bool next_thumb = thumb_mode_;
        if (ImGui::Checkbox("Thumb", &next_thumb)) {
            if (disasm_.set_thumb_mode(next_thumb)) {
                thumb_mode_ = next_thumb;
                thumb_mode_user_forced_ = true;
                model_.set_analysis_thumb_mode(thumb_mode_);
                linear_disasm_.set_thumb_mode(thumb_mode_, true);
                pending_call_graph_root_ = active_graph_root_;
                if (disassembly_location_) {
                    disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
                }
            } else {
                Log().error("Unable to change ARM instruction mode");
            }
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Toggle ARM32 (A32) vs Thumb/Thumb-2 (T32) decoding");
        }
        if (thumb_mode_user_forced_) {
            ImGui::SameLine(0.0f, 4.0f);
            if (ImGui::SmallButton("Auto")) {
                thumb_mode_user_forced_ = false;
                linear_disasm_.clear_thumb_mode_override();
                const std::uint64_t ref_va = disassembly_location_
                    ? disassembly_location_->address
                    : (model_.image() != nullptr ? model_.image()->entry_point()
                                                 : model_.view_base_address());
                thumb_mode_ = ((ref_va & 1u) != 0u) || linear_disasm_.resolve_thumb_at_address(ref_va);
                (void)disasm_.set_thumb_mode(thumb_mode_);
                model_.set_analysis_thumb_mode(thumb_mode_);
                linear_disasm_.set_thumb_mode(thumb_mode_, false);
                if (disassembly_location_) {
                    disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Restore automatic per-symbol $a/$t & Thumb LSB mode hints");
            }
        }
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::max(140.0f, ImGui::GetFontSize() * 14.0f));
    if (ImGui::InputTextWithHint("##DisasmGotoBar",
                                 "Go to VA / +RVA / Symbol (G)...",
                                 disasm_goto_buf_,
                                 sizeof(disasm_goto_buf_),
                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
        (void)execute_goto_query(disasm_goto_buf_);
    }
    ImGui::SameLine(0.0f, 4.0f);
    if (ImGui::Button("Go##DisasmGotoBtn")) {
        (void)execute_goto_query(disasm_goto_buf_);
    }
    if (!disasm_goto_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.50f, 0.42f, 1.0f), "%s", disasm_goto_status_.c_str());
    }

    // --- Toolbar Row 2: Active Section / Function Breadcrumb + Hotkey Hint ---
    {
        const std::uint64_t active_va = current_selection_.virtual_address.value_or(
            disassembly_location_ ? disassembly_location_->address : 0u);
        std::string section_crumb = "<unmapped>";
        if (const auto* span = linear_disasm_.span_for_address(active_va)) {
            section_crumb = span->name;
        } else if (model_.image() != nullptr) {
            if (const auto* sec = find_image_section_by_va(*model_.image(), active_va)) {
                section_crumb = sec->name.empty() ? "<section>" : sec->name;
            }
        }

        std::string fn_crumb;
        if (const auto* note = annotations_.find(active_va); note != nullptr && !note->name.empty()) {
            fn_crumb = note->name;
        } else if (const auto* fn = model_.function_index().find_containing(active_va)) {
            const std::uint64_t delta = active_va - fn->virtual_address;
            const std::string& fname = fn->display_name(model_.demangle_symbols());
            fn_crumb = delta == 0u ? fname : std::format("{}+0x{:X}", fname, delta);
        } else if (const auto* sym = symbol_index_.find_containing_address(active_va);
                   sym != nullptr && sym->virtual_address.has_value()) {
            const std::uint64_t delta = active_va - *sym->virtual_address;
            const std::string& sname = sym->display_name(model_.demangle_symbols());
            fn_crumb = delta == 0u ? sname : std::format("{}+0x{:X}", sname, delta);
        } else {
            fn_crumb = std::format("0x{:X}", active_va);
        }

        ImGui::TextColored(ImVec4(0.58f, 0.78f, 0.96f, 1.0f), "[%s]", section_crumb.c_str());
        ImGui::SameLine(0.0f, 6.0f);
        ImGui::TextDisabled(">");
        ImGui::SameLine(0.0f, 6.0f);
        ImGui::TextUnformatted(fn_crumb.c_str());
        ImGui::SameLine(0.0f, 14.0f);
        ImGui::TextDisabled("|  %zu rows  (%zu/%zu LRU chunks)  |  Keys: [G]o  [N]ame  [;]Comment  [X]refs  [Enter]/Esc  [Space]CFG",
                            linear_disasm_.total_rows(),
                            linear_disasm_.cached_chunk_count(),
                            linear_disasm_.options().max_cached_chunks);
    }

    if (!disasm_status_.empty()) {
        ImGui::TextWrapped("%s", disasm_status_.c_str());
    }

    // --- Focused RE Single-Key Shortcuts ---
    std::optional<std::uint64_t> follow_target;
    std::optional<std::size_t> scroll_to_row_index;
    if (pending_disasm_scroll_va_.has_value()) {
        if (const auto target_row = linear_disasm_.find_row_for_address(*pending_disasm_scroll_va_)) {
            scroll_to_row_index = *target_row;
        }
        pending_disasm_scroll_va_.reset();
    }

    const bool any_popup_open =
        ImGui::IsPopupOpen("DisasmGotoPopup") ||
        ImGui::IsPopupOpen("DisasmRenamePopup") ||
        ImGui::IsPopupOpen("DisasmCommentPopup");

    const std::optional<std::uint64_t> active_va_opt =
        current_selection_.virtual_address.has_value()
            ? current_selection_.virtual_address
            : (disassembly_location_ ? std::optional<std::uint64_t>(disassembly_location_->address)
                                     : std::nullopt);

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::GetIO().WantTextInput &&
        !any_popup_open) {
        const ImGuiIO& io = ImGui::GetIO();
        const bool no_ctrl_super = !io.KeyCtrl && !io.KeySuper;

        if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_Space)) {
            switch_analysis_view(true);
        } else if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_G)) {
            open_disasm_goto_popup_ = true;
        } else if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_N) && active_va_opt.has_value()) {
            disasm_modal_target_va_ = *active_va_opt;
            const auto* note = annotations_.find(disasm_modal_target_va_);
            std::snprintf(disasm_rename_buf_, sizeof(disasm_rename_buf_), "%s",
                          note != nullptr ? note->name.c_str() : "");
            open_disasm_rename_popup_ = true;
        } else if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_Semicolon) && active_va_opt.has_value()) {
            disasm_modal_target_va_ = *active_va_opt;
            const auto* note = annotations_.find(disasm_modal_target_va_);
            std::snprintf(disasm_comment_buf_, sizeof(disasm_comment_buf_), "%s",
                          note != nullptr ? note->comment.c_str() : "");
            open_disasm_comment_popup_ = true;
        } else if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_X) && active_va_opt.has_value()) {
            if (const auto sel_inst = linear_disasm_.find_instruction_at_address(*active_va_opt)) {
                select_instruction(*sel_inst, disasm_follow_hex_);
            }
            references_panel_.focus_incoming_to_selection();
            open_references();
        } else if (no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_Enter) && active_va_opt.has_value()) {
            if (const auto sel_inst = linear_disasm_.find_instruction_at_address(*active_va_opt);
                sel_inst.has_value() && sel_inst->branch_target.has_value()) {
                follow_target = *sel_inst->branch_target;
            }
        } else if ((no_ctrl_super && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_Escape)) ||
                   (io.KeyAlt && !io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_LeftArrow))) {
            if (navigation_history_.can_back()) {
                navigate_history(false);
            }
        } else if (io.KeyAlt && !io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) {
            if (navigation_history_.can_forward()) {
                navigate_history(true);
            }
        } else if (linear_disasm_.total_rows() > 0u &&
                   (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
            const std::size_t total_rows = linear_disasm_.total_rows();
            std::size_t cur_idx = 0u;
            bool had_row = false;
            if (active_va_opt.has_value()) {
                if (const auto found_idx = linear_disasm_.find_row_for_address(*active_va_opt)) {
                    cur_idx = *found_idx;
                    had_row = true;
                }
            }
            if (had_row) {
                if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
                    cur_idx = cur_idx > 0u ? (cur_idx - 1u) : 0u;
                } else if (cur_idx + 1u < total_rows) {
                    cur_idx += 1u;
                }
            }
            if (const Instruction* next_inst = linear_disasm_.instruction_at_row(cur_idx);
                next_inst != nullptr) {
                select_instruction(*next_inst, disasm_follow_hex_);
                scroll_to_row_index = cur_idx;
            }
        }
    }

    // --- Inline RE Popups (G: Go-to, N: Rename Label, ;: Comment) ---
    if (open_disasm_goto_popup_) {
        ImGui::OpenPopup("DisasmGotoPopup");
        open_disasm_goto_popup_ = false;
    }
    if (ImGui::BeginPopup("DisasmGotoPopup")) {
        ImGui::TextUnformatted("Go to Address / Expression (VA, rva:0x..., off:0x..., Symbol+Offset):");
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 26.0f);
        const bool submitted = ImGui::InputTextWithHint(
            "##PopupDisasmGoto",
            "e.g. 0x140001000, main+0x20, .text+0x40, rva:0x1000",
            disasm_goto_buf_,
            sizeof(disasm_goto_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue);
        if (submitted || ImGui::Button("Jump")) {
            if (execute_goto_query(disasm_goto_buf_)) {
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        if (!disasm_goto_status_.empty()) {
            ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s", disasm_goto_status_.c_str());
        }
        ImGui::EndPopup();
    }

    if (open_disasm_rename_popup_) {
        ImGui::OpenPopup("DisasmRenamePopup");
        open_disasm_rename_popup_ = false;
    }
    if (ImGui::BeginPopup("DisasmRenamePopup")) {
        ImGui::Text("Rename label at 0x%" PRIX64 ":", disasm_modal_target_va_);
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 22.0f);
        const bool submitted = ImGui::InputTextWithHint(
            "##PopupDisasmRename",
            "User label (leave empty to clear label)",
            disasm_rename_buf_,
            sizeof(disasm_rename_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue);
        if (submitted || ImGui::Button("Save Label")) {
            const auto* existing = annotations_.find(disasm_modal_target_va_);
            const std::string keep_comment = existing != nullptr ? existing->comment : std::string{};
            annotations_.set(disasm_modal_target_va_, disasm_rename_buf_, keep_comment);
            ++annotation_revision_;
            ++symbol_revision_;
            model_.bump_annotation_revision();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if (open_disasm_comment_popup_) {
        ImGui::OpenPopup("DisasmCommentPopup");
        open_disasm_comment_popup_ = false;
    }
    if (ImGui::BeginPopup("DisasmCommentPopup")) {
        ImGui::Text("Edit comment at 0x%" PRIX64 ":", disasm_modal_target_va_);
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28.0f);
        const bool submitted = ImGui::InputTextWithHint(
            "##PopupDisasmComment",
            "Inline repeatable comment...",
            disasm_comment_buf_,
            sizeof(disasm_comment_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue);
        if (submitted || ImGui::Button("Save Comment")) {
            const auto* existing = annotations_.find(disasm_modal_target_va_);
            const std::string keep_name = existing != nullptr ? existing->name : std::string{};
            annotations_.set(disasm_modal_target_va_, keep_name, disasm_comment_buf_);
            ++annotation_revision_;
            model_.bump_annotation_revision();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    const std::optional<std::uint64_t> active_debug_ip =
        (model_.debug_session() != nullptr &&
         model_.debug_session()->state() == peelf::debugger::DebugSessionState::Paused)
            ? std::optional<std::uint64_t>(model_.debug_session()->stop_status().instruction_pointer)
            : std::nullopt;

    constexpr std::size_t kMaxArcLanes = 8u;
    constexpr float kArcGutterWidth = 72.0f;

    struct RenderedRowCoord {
        std::size_t global_row = 0u;
        std::uint64_t address = 0u;
        float y_center = 0.0f;
    };
    std::vector<RenderedRowCoord> rendered_rows;
    float gutter_col_x0 = 0.0f;
    float gutter_col_x1 = 0.0f;
    float table_body_y0 = 0.0f;
    float table_body_y1 = 0.0f;
    bool have_gutter_bounds = false;

    std::optional<std::uint64_t> pending_bp_toggle_va;
    std::optional<std::uint64_t> pending_open_xrefs_va;

    if (ImGui::BeginTable("DisasmTableReadable", 7,
                          ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Arcs", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, kArcGutterWidth);
        ImGui::TableSetupColumn("BP", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 34.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("0000000000000000").x + 18.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 172.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 88.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 23.0f);
        ImGui::TableSetupColumn("Xrefs / Source / Comment", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 32.0f);
        ImGui::TableSetupScrollFreeze(3, 1);
        ImGui::TableHeadersRow();

        table_body_y0 = ImGui::GetCursorScreenPos().y;
        table_body_y1 = ImGui::GetWindowPos().y + ImGui::GetWindowHeight();

        const std::size_t est_rows = linear_disasm_.total_rows();
        const int clipped_inst_count =
            est_rows > static_cast<std::size_t>(std::numeric_limits<int>::max() - 1)
                ? (std::numeric_limits<int>::max() - 1)
                : static_cast<int>(est_rows);

        const std::uint64_t image_base = model_.image() != nullptr
            ? model_.image()->image_base()
            : model_.view_base_address();
        const bool is_64bit_target = model_.image() != nullptr
            ? model_.image()->is_64bit()
            : model_.target_layout().is_64bit();
        const LinearMetadataContext meta_ctx{
            .symbols = &symbol_index_,
            .functions = &model_.function_index(),
            .references = &reference_index_,
            .annotations = &annotations_,
            .source_lines = model_.source_lines(),
            .demangle_symbols = model_.demangle_symbols(),
            .max_xref_preview = 3u,
        };

        ImGuiListClipper clipper;
        std::optional<PendingEntityContextAction> pending_ctx_action;
        clipper.Begin(clipped_inst_count);
        if (scroll_to_row_index.has_value() &&
            *scroll_to_row_index < static_cast<std::size_t>(clipped_inst_count)) {
            clipper.IncludeItemByIndex(static_cast<int>(*scroll_to_row_index));
        }

        while (clipper.Step()) {
            const std::size_t step_start = static_cast<std::size_t>(std::max(0, clipper.DisplayStart));
            const std::size_t step_end = static_cast<std::size_t>(std::max(clipper.DisplayStart, clipper.DisplayEnd));
            const std::size_t step_count = step_end - step_start;

            std::optional<std::uint64_t> prev_before_step_va;
            if (step_start > 0u) {
                if (const Instruction* prev_ptr = linear_disasm_.instruction_at_row(step_start - 1u);
                    prev_ptr != nullptr) {
                    prev_before_step_va = prev_ptr->address;
                }
            }
            const std::vector<Instruction> slice = linear_disasm_.collect_rows(step_start, step_count);

            for (std::size_t local_i = 0u; local_i < slice.size(); ++local_i) {
                const std::size_t global_row = step_start + local_i;
                const int row = static_cast<int>(global_row);
                const Instruction& inst = slice[local_i];
                const std::optional<std::uint64_t> prev_inst_va = local_i > 0u
                    ? std::optional<std::uint64_t>(slice[local_i - 1u].address)
                    : prev_before_step_va;

                const InstructionRowMetadata meta = describe_instruction_row(
                    inst,
                    meta_ctx,
                    prev_inst_va);

                const auto* row_bp = model_.find_breakpoint_at(inst.address);
                const bool is_ip = active_debug_ip.has_value() && *active_debug_ip == inst.address;
                const bool is_selected = current_selection_.virtual_address == inst.address;

                ImGui::TableNextRow();
                if (is_ip) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                           ImGui::GetColorU32(ImVec4(0.08f, 0.34f, 0.42f, 0.48f)));
                } else if (meta.has_header_banner) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                           ImGui::GetColorU32(ImVec4(0.16f, 0.22f, 0.34f, 0.38f)));
                }

                // Col 0: Branch Arc Gutter placeholder + screen coordinate capture
                ImGui::TableNextColumn();
                const ImVec2 cell_pos = ImGui::GetCursorScreenPos();
                if (!have_gutter_bounds) {
                    gutter_col_x0 = cell_pos.x;
                    gutter_col_x1 = cell_pos.x + ImGui::GetColumnWidth();
                    have_gutter_bounds = true;
                }
                const float line_h = ImGui::GetTextLineHeight();
                const std::size_t extra_banner_lines =
                    (meta.has_header_banner ? 1u : 0u) +
                    ((disasm_show_source_lines_ && meta.is_new_source_line) ? 1u : 0u);
                const float inst_line_y_offset =
                    static_cast<float>(extra_banner_lines) * ImGui::GetTextLineHeightWithSpacing();
                ImGui::Dummy(ImVec2(kArcGutterWidth - 8.0f, inst_line_y_offset + line_h));
                rendered_rows.push_back(RenderedRowCoord{
                    .global_row = global_row,
                    .address = inst.address,
                    .y_center = cell_pos.y + inst_line_y_offset + line_h * 0.5f,
                });

                // Col 1: Breakpoint / Current IP Gutter
                ImGui::TableNextColumn();
                if (extra_banner_lines > 0u) {
                    ImGui::Dummy(ImVec2(1.0f, inst_line_y_offset));
                }
                ImGui::PushID(row * 4 + 1);
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
                    if (row_bp != nullptr) {
                        ImGui::SameLine(0.0f, 2.0f);
                    }
                    ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.98f, 1.0f), "▶");
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Current instruction pointer (IP/PC)");
                    }
                }
                ImGui::PopID();

                // Col 2: Address (VA / RVA / File Offset)
                ImGui::TableNextColumn();
                if (extra_banner_lines > 0u) {
                    ImGui::Dummy(ImVec2(1.0f, inst_line_y_offset));
                }
                ImGui::PushID(row * 4);
                const std::string addr_str = format_instruction_address(
                    disasm_address_mode_,
                    inst.address,
                    model_.virtual_address_to_offset(inst.address),
                    image_base,
                    is_64bit_target);
                if (ImGui::Selectable(addr_str.c_str(),
                                      is_selected,
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && inst.branch_target.has_value()) {
                        follow_target = *inst.branch_target;
                    }
                    select_instruction(inst, disasm_follow_hex_);
                }
                draw_inspectable_entity_context_menu(
                    "DisasmRowCtx",
                    model_,
                    pending_ctx_action,
                    [this, &inst]() -> InspectableEntity {
                        const bool static_img = model_has_static_image(model_);
                        std::string bytes_hex;
                        bytes_hex.reserve(inst.bytes.size() * 2u);
                        for (const std::uint8_t b : inst.bytes) {
                            bytes_hex += std::format("{:02X}", b);
                        }
                        return InspectableEntity{
                            .va = inst.address,
                            .file_offset = static_img
                                ? model_.virtual_address_to_offset(inst.address)
                                : std::nullopt,
                            .size = inst.bytes.size(),
                            .symbol_or_label = inst.to_string(),
                            .module_name = model_.file_info().path,
                            .extra_json_fields = {
                                {"mnemonic", inst.mnemonic},
                                {"operands", inst.operands},
                                {"bytes", std::move(bytes_hex)},
                            },
                        };
                    });
                ImGui::PopID();

                if (scroll_to_row_index.has_value() && global_row == *scroll_to_row_index) {
                    ImGui::SetScrollHereY(0.35f);
                }

                // Col 3: Bytes (with Staged amber / Committed emerald patch tint)
                ImGui::TableNextColumn();
                if (extra_banner_lines > 0u) {
                    ImGui::Dummy(ImVec2(1.0f, inst_line_y_offset));
                }
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
                bytes_str.reserve(inst.bytes.size() * 3u);
                for (const std::uint8_t b : inst.bytes) {
                    bytes_str += std::format("{:02X} ", b);
                }
                if (inst_patch_state == BytePatchState::Staged) {
                    ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.28f, 1.0f), "%s", bytes_str.c_str());
                } else if (inst_patch_state == BytePatchState::Committed) {
                    ImGui::TextColored(ImVec4(0.35f, 0.94f, 0.56f, 1.0f), "%s", bytes_str.c_str());
                } else {
                    ImGui::TextDisabled("%s", bytes_str.c_str());
                }

                // Col 4: Mnemonic (+ Function Header Banner / Source Line indicator)
                ImGui::TableNextColumn();
                if (meta.has_header_banner) {
                    ImGui::TextColored(ImVec4(0.95f, 0.80f, 0.38f, 1.0f), "fn");
                }
                if (disasm_show_source_lines_ && meta.is_new_source_line) {
                    ImGui::TextColored(ImVec4(0.55f, 0.78f, 0.96f, 1.0f), "src");
                }
                const ImVec4 mnem_color = get_mnemonic_color(inst.mnemonic);
                ImGui::TextColored(mnem_color, "%s", inst.mnemonic.c_str());

                // Col 5: Operands (+ Inline Function Header / Source Banner + Clickable Branch Target)
                ImGui::TableNextColumn();
                if (meta.has_header_banner) {
                    ImGui::TextColored(ImVec4(0.96f, 0.82f, 0.42f, 1.0f), "%s", meta.header_banner.c_str());
                }
                if (disasm_show_source_lines_ && meta.is_new_source_line) {
                    ImGui::TextColored(ImVec4(0.56f, 0.80f, 0.98f, 1.0f), "%s", meta.source_tag.c_str());
                    if (ImGui::IsItemHovered() && !meta.source_full_path.empty()) {
                        ImGui::SetTooltip("Source: %s:%u", meta.source_full_path.c_str(), meta.source_line);
                    }
                }
                ImGui::PushID(row * 4 + 2);
                if (inst.branch_target.has_value()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.52f, 0.84f, 1.0f, 1.0f));
                    if (ImGui::Selectable(inst.operands.c_str(),
                                          false,
                                          ImGuiSelectableFlags_AllowDoubleClick,
                                          ImVec2(ImGui::CalcTextSize(inst.operands.c_str()).x + 4.0f, 0.0f))) {
                        select_instruction(inst, disasm_follow_hex_);
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) || ImGui::GetIO().KeyCtrl) {
                            follow_target = *inst.branch_target;
                        }
                    }
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Target VA: 0x%" PRIX64 " (Double-click, Ctrl+click, or press Enter to follow)",
                                          *inst.branch_target);
                    }

                    std::string target_sym_label;
                    std::string target_raw_name;
                    if (const auto* tnote = annotations_.find(*inst.branch_target);
                        tnote != nullptr && !tnote->name.empty()) {
                        target_sym_label = tnote->name;
                    } else if (const auto* target = symbol_index_.find_containing_address(*inst.branch_target);
                               target != nullptr && target->virtual_address.has_value()) {
                        const auto delta = *inst.branch_target - *target->virtual_address;
                        const std::string& tname = target->display_name(model_.demangle_symbols());
                        target_sym_label = delta != 0u ? std::format("{}+0x{:X}", tname, delta) : tname;
                        if (tname != target->name) {
                            target_raw_name = target->name;
                        }
                    }
                    if (!target_sym_label.empty()) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("-> %s", target_sym_label.c_str());
                        if (ImGui::IsItemHovered() && !target_raw_name.empty()) {
                            ImGui::SetTooltip("Raw symbol: %s", target_raw_name.c_str());
                        }
                    }
                } else {
                    ImGui::TextUnformatted(inst.operands.c_str());
                }
                ImGui::PopID();

                // Col 6: Xrefs / Source / Comment
                ImGui::TableNextColumn();
                ImGui::PushID(row * 4 + 3);
                if (meta.has_header_banner && meta.incoming_xref_count > 0u) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.88f, 0.72f, 1.0f));
                    if (ImGui::Selectable(meta.xref_summary.c_str(), false)) {
                        select_instruction(inst, disasm_follow_hex_);
                        pending_open_xrefs_va = inst.address;
                    }
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Click or press X to open incoming references");
                    }
                } else if (meta.has_header_banner) {
                    ImGui::Dummy(ImVec2(1.0f, line_h));
                }
                if (disasm_show_source_lines_ && meta.is_new_source_line) {
                    ImGui::TextDisabled("%s", meta.source_full_path.c_str());
                }

                bool printed_meta_item = false;
                if (!meta.has_header_banner && meta.incoming_xref_count > 0u) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.88f, 0.72f, 1.0f));
                    if (ImGui::SmallButton(std::format("XREFS({})", meta.incoming_xref_count).c_str())) {
                        select_instruction(inst, disasm_follow_hex_);
                        pending_open_xrefs_va = inst.address;
                    }
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s\nClick or press X to open References panel", meta.xref_summary.c_str());
                    }
                    printed_meta_item = true;
                }
                if (!meta.user_label.empty()) {
                    if (printed_meta_item) {
                        ImGui::SameLine();
                    }
                    ImGui::TextColored(ImVec4(0.98f, 0.82f, 0.36f, 1.0f), "<%s>", meta.user_label.c_str());
                    printed_meta_item = true;
                } else if (!meta.symbol_name.empty() && !meta.has_header_banner) {
                    if (printed_meta_item) {
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("%s", meta.symbol_name.c_str());
                    if (ImGui::IsItemHovered() && !meta.raw_symbol_name.empty()) {
                        ImGui::SetTooltip("Raw symbol: %s", meta.raw_symbol_name.c_str());
                    }
                    printed_meta_item = true;
                }
                if (disasm_show_source_lines_ && !meta.source_tag.empty() && !meta.is_new_source_line) {
                    if (printed_meta_item) {
                        ImGui::SameLine();
                    }
                    ImGui::TextColored(ImVec4(0.52f, 0.74f, 0.90f, 1.0f), "%s", meta.source_tag.c_str());
                    printed_meta_item = true;
                }
                if (!meta.user_comment.empty()) {
                    if (printed_meta_item) {
                        ImGui::SameLine();
                    }
                    ImGui::TextColored(ImVec4(0.58f, 0.88f, 0.56f, 1.0f), "; %s", meta.user_comment.c_str());
                }
                ImGui::PopID();
            }
        }

        // --- Draw Branch Arcs inside Gutter Column via ImDrawList ---
        if (have_gutter_bounds && !rendered_rows.empty() && table_body_y1 > table_body_y0 + 4.0f) {
            constexpr std::size_t kArcContextPad = 48u;
            const std::size_t first_vis_row = rendered_rows.front().global_row;
            const std::size_t last_vis_row = rendered_rows.back().global_row;
            const std::size_t pad_start = first_vis_row > kArcContextPad ? (first_vis_row - kArcContextPad) : 0u;
            const std::size_t pad_end = std::min(est_rows, last_vis_row + 1u + kArcContextPad);
            const std::vector<Instruction> arc_window =
                linear_disasm_.collect_rows(pad_start, pad_end - pad_start);
            const std::vector<BranchArc> arcs = compute_branch_arcs(
                arc_window,
                current_selection_.virtual_address,
                kMaxArcLanes,
                &model_.function_index());

            const auto find_rendered_y = [&rendered_rows](std::size_t global_r) -> std::optional<float> {
                const auto it = std::ranges::lower_bound(
                    rendered_rows, global_r, {}, &RenderedRowCoord::global_row);
                if (it != rendered_rows.end() && it->global_row == global_r) {
                    return it->y_center;
                }
                return std::nullopt;
            };

            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->PushClipRect(
                ImVec2(gutter_col_x0, table_body_y0),
                ImVec2(gutter_col_x1, table_body_y1),
                true);

            const float x_right = gutter_col_x1 - 5.0f;
            for (const BranchArc& arc : arcs) {
                const std::size_t src_global = pad_start + arc.source_row;
                const std::optional<std::size_t> dst_global = arc.target_row.has_value()
                    ? std::optional<std::size_t>(pad_start + *arc.target_row)
                    : std::nullopt;

                // Skip arcs completely above or completely below the rendered viewport
                const std::size_t arc_min_r = dst_global.has_value()
                    ? std::min(src_global, *dst_global)
                    : (arc.is_upward ? 0u : src_global);
                const std::size_t arc_max_r = dst_global.has_value()
                    ? std::max(src_global, *dst_global)
                    : (arc.is_upward ? src_global : est_rows);
                if (arc_max_r < first_vis_row || arc_min_r > last_vis_row) {
                    continue;
                }

                const float lane_x = std::max(
                    gutter_col_x0 + 4.0f,
                    x_right - 7.0f - static_cast<float>(arc.lane) * 7.5f);

                const ImU32 col = arc.is_selected
                    ? IM_COL32(255, 212, 74, 255)
                    : (arc.is_conditional
                           ? (arc.is_upward ? IM_COL32(242, 138, 82, 215)
                                            : IM_COL32(98, 186, 250, 215))
                           : IM_COL32(96, 222, 158, 215));
                const float thickness = arc.is_selected ? 2.1f : 1.35f;

                const std::optional<float> src_y_opt = find_rendered_y(src_global);
                const std::optional<float> dst_y_opt = dst_global.has_value()
                    ? find_rendered_y(*dst_global)
                    : std::nullopt;

                const float y_src = src_y_opt.has_value()
                    ? (*src_y_opt + (arc.is_upward ? -2.0f : 2.0f))
                    : (src_global < first_vis_row ? (table_body_y0 + 2.0f) : (table_body_y1 - 2.0f));
                const float y_dst = dst_y_opt.has_value()
                    ? *dst_y_opt
                    : (arc.is_upward ? (table_body_y0 + 5.0f) : (table_body_y1 - 5.0f));

                if (src_y_opt.has_value()) {
                    draw_list->AddLine(ImVec2(x_right, y_src), ImVec2(lane_x, y_src), col, thickness);
                }
                draw_list->AddLine(ImVec2(lane_x, y_src), ImVec2(lane_x, y_dst), col, thickness);

                if (dst_y_opt.has_value()) {
                    draw_list->AddLine(ImVec2(lane_x, y_dst), ImVec2(x_right - 2.0f, y_dst), col, thickness);
                    draw_list->AddTriangleFilled(
                        ImVec2(x_right + 1.5f, y_dst),
                        ImVec2(x_right - 4.5f, y_dst - 3.4f),
                        ImVec2(x_right - 4.5f, y_dst + 3.4f),
                        col);
                } else if (arc.is_upward) {
                    draw_list->AddTriangleFilled(
                        ImVec2(lane_x, table_body_y0 + 1.5f),
                        ImVec2(lane_x - 3.2f, table_body_y0 + 6.5f),
                        ImVec2(lane_x + 3.2f, table_body_y0 + 6.5f),
                        col);
                } else {
                    draw_list->AddTriangleFilled(
                        ImVec2(lane_x, table_body_y1 - 1.5f),
                        ImVec2(lane_x - 3.2f, table_body_y1 - 6.5f),
                        ImVec2(lane_x + 3.2f, table_body_y1 - 6.5f),
                        col);
                }
            }

            draw_list->PopClipRect();
        }

        ImGui::EndTable();
        if (pending_ctx_action.has_value()) {
            dispatch_entity_context_action(pending_ctx_action->kind, pending_ctx_action->entity);
        }
    }

    if (pending_bp_toggle_va.has_value() && model_.is_debug_session()) {
        (void)model_.toggle_software_breakpoint(*pending_bp_toggle_va);
    }
    if (pending_open_xrefs_va.has_value()) {
        references_panel_.focus_incoming_to_selection();
        open_references();
    }

    ImGui::End();
    if (follow_target) {
        enqueue_navigation(*follow_target);
    }
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

bool UiApp::navigate_to_address(std::uint64_t address, PreferredView view) {
    if (!model_.has_file()) {
        return false;
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
        return false;
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
    } else if (view == PreferredView::Disassembly) {
        show_disassembly_panel_ = true;
        focus_listing_ = true;
    }
    navigation_history_.visit(current_selection_);
    return true;
}

void UiApp::dispatch_entity_context_action(
    ContextActionKind kind,
    const InspectableEntity& entity) {
    if (const auto clip = format_context_copy_payload(kind, entity); clip.has_value()) {
        if (ImGui::GetCurrentContext() != nullptr) {
            ImGui::SetClipboardText(clip->c_str());
        }
        return;
    }

    switch (kind) {
        case ContextActionKind::FollowInHex:
        case ContextActionKind::FollowInDisassembly:
        case ContextActionKind::FollowInDecompiler:
        case ContextActionKind::FollowInStructureView: {
            (void)enqueue_context_navigation_action(
                pending_navigations_,
                kind,
                entity,
                model_has_static_image(model_));
            return;
        }
        case ContextActionKind::AddBookmark: {
            pending_navigations_.enqueue_custom([this, entity]() {
                if (!model_.has_file()) {
                    return;
                }
                const bool has_va = entity.va.has_value();
                const bool has_off = entity.file_offset.has_value();
                if (!has_va && !has_off) {
                    return;
                }
                const bool is_off = !has_va && has_off;
                const std::uint64_t addr = has_va ? *entity.va : *entity.file_offset;
                const Bookmark* existing = model_.find_bookmark(addr, is_off);
                std::string label = entity.symbol_or_label;
                if (label.empty()) {
                    label = existing != nullptr && !existing->label.empty()
                                ? existing->label
                                : (is_off ? std::format("off_{:X}", addr) : std::format("loc_{:X}", addr));
                }
                model_.add_or_update_bookmark(Bookmark{
                    .address = addr,
                    .is_file_offset = is_off,
                    .label = std::move(label),
                    .category = existing != nullptr ? existing->category : std::string{"User"},
                    .note = existing != nullptr ? existing->note : std::string{},
                });
                open_references();
                Log().info("Added bookmark at {}{:X}", is_off ? "off+0x" : "0x", addr);
            });
            return;
        }
        case ContextActionKind::ToggleSoftwareBreakpoint: {
            if (!entity.va.has_value()) {
                return;
            }
            const std::uint64_t bp_va = *entity.va;
            pending_navigations_.enqueue_custom([this, bp_va]() {
                if (!model_.is_debug_session()) {
                    return;
                }
                if (auto r = model_.toggle_software_breakpoint(bp_va); r) {
                    Log().info("{} software breakpoint at 0x{:X}", *r ? "Set" : "Removed", bp_va);
                } else {
                    Log().error("Breakpoint toggle at 0x{:X}: {}", bp_va, r.error().message);
                }
            });
            return;
        }
        case ContextActionKind::CopyVirtualAddress:
        case ContextActionKind::CopyFileOffset:
        case ContextActionKind::CopyLabel:
        case ContextActionKind::CopyJsonSummary:
            return;
    }
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
                if (!navigate_to_address(req.target, req.preferred_view)) {
                    break;
                }
                if (req.highlight_size > 1) {
                    if (const auto off = model_.virtual_address_to_offset(req.target)) {
                        hex_panel_.navigate_to_range(*off, req.highlight_size);
                    }
                }
                if (req.request_decompile) {
                    request_decompile();
                }
                if (req.open_structure_view) {
                    open_structure_view({}, req.target, false);
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
                    .preferred_view = req.preferred_view,
                };
                if (req.preferred_view == PreferredView::Disassembly) {
                    disassemble_at_offset(req.target, va.value_or(req.target));
                    show_disassembly_panel_ = true;
                    focus_listing_ = true;
                } else if (req.open_structure_view) {
                    hex_panel_.navigate_to_range(req.target, sz);
                    open_structure_view({}, req.target, true);
                } else {
                    hex_panel_.set_visible(true);
                    hex_panel_.navigate_to_range(req.target, sz);
                    activate_panel("Hex View");
                    if (va) {
                        disassemble_at_offset(req.target, *va);
                    }
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
            current_selection_.kind == SelectionKind::Process ||
            current_selection_.kind == SelectionKind::ProcessHandle) {
            return;
        }
        if (last_navigation_selection_ &&
            same_selection(*last_navigation_selection_, current_selection_)) {
            return;
        }

        if (current_selection_.kind == SelectionKind::ProcessThread && model_.is_live_process()) {
            const auto thr_idx = static_cast<std::size_t>(current_selection_.object_index);
            if (thr_idx < model_.threads().size()) {
                model_.select_thread(model_.threads()[thr_idx].tid);
            }
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

        const HexAvailabilityStatus sel_avail =
            evaluate_hex_selection_availability(model_, current_selection_);
        if (!sel_avail.available && current_selection_.size > 0u) {
            hex_panel_.set_unavailable_reason(sel_avail.unavailable_reason);
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
        if (disasm_.architecture() == Architecture::ARM32 && !thumb_mode_user_forced_ &&
            (display_address & 1u) != 0u) {
            display_address &= ~std::uint64_t{1u};
        }
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

        (void)linear_disasm_.sync_with_model(model_, thumb_mode_, thumb_mode_user_forced_);

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

        if (linear_disasm_.contains_executable_address(display_address)) {
            linear_disasm_.clear_fallback_span();
        } else {
            LinearDisassemblySpan fallback{
                .name = "data_window",
                .virtual_address = display_address,
                .file_offset = file_offset,
                .byte_size = static_cast<std::uint64_t>(readable_len),
                .executable = false,
                .fallback_data = true,
            };
            if (!model_.is_live_process() && model_.image() != nullptr) {
                if (const auto* sec = find_image_section_by_va(*model_.image(), display_address);
                    sec != nullptr && sec->file_size > 0u && sec->file_offset < total_size) {
                    const std::uint64_t clamped_size =
                        std::min(sec->file_size, total_size - sec->file_offset);
                    if (display_address >= sec->virtual_address &&
                        display_address - sec->virtual_address < clamped_size) {
                        fallback.name = sec->name.empty() ? "section" : sec->name;
                        fallback.virtual_address = sec->virtual_address;
                        fallback.file_offset = sec->file_offset;
                        fallback.byte_size = clamped_size;
                    }
                }
            }
            linear_disasm_.set_fallback_span(std::move(fallback));
        }

        pending_disasm_scroll_va_ = display_address;
        current_instructions_ = linear_disasm_.decode_window_from_address(display_address, 256u);
        if (current_instructions_.empty()) {
            current_instructions_ = disasm_.disassemble(sample->bytes.data(), readable_len, display_address);
        }
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
