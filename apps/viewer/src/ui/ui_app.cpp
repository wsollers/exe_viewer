#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "analysis/project.hpp"
#include "graph/call_graph.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace viewer {
namespace {
using detail::activate_panel;
using detail::clamp_to_size_t;
} // namespace

UiApp::UiApp(BinaryModel& model, VulkanManager& vulkan)
    : model_(model)
    , vulkan_(vulkan)
    , file_panel_(model)
    , memory_map_panel_(model, current_selection_)
    , structure_panel_(structure_tree_, current_selection_)
    , details_panel_(current_selection_, &model)
    , sections_panel_(model)
    , hex_panel_(model)
    , patch_set_panel_(model, current_selection_)
    , shellcode_panel_(model, current_selection_)
    , imports_panel_(model)
    , exports_panel_(model)
    , symbols_panel_(symbol_index_, current_selection_, model)
    , functions_panel_(model, current_selection_)
    , threads_panel_(model)
    , thread_locals_panel_(model)
    , memory_search_panel_(model)
    , runtime_flags_panel_(model)
    , handlers_panel_(model)
    , references_panel_(reference_index_, annotations_, symbol_index_, current_selection_)
    , strings_panel_(model, strings_index_, reference_index_, annotations_, current_selection_)
    , struct_view_panel_(model, current_selection_)
    , process_internals_panel_(model)
    , dependencies_panel_(model, symbol_index_, reference_index_, current_selection_)
    , binary_diff_panel_(
          model,
          current_selection_,
          [this](std::uint64_t address, PreferredView view) { enqueue_navigation(address, view); },
          [this]() {
              if (on_analysis_file_) on_analysis_file_(3);
          })
    , debugger_panel_(
          model,
          [this](std::uint64_t address, PreferredView view) { enqueue_navigation(address, view); },
          [this]() { on_process_attached(); },
          [this]() { open_attach_process_modal(); })
    , capabilities_panel_(model)
    , executable_settings_panel_(
          model,
          [this](std::uint64_t address, PreferredView view) { enqueue_navigation(address, view); })
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{
    references_panel_.set_visible(false);
    strings_panel_.set_visible(false);
    struct_view_panel_.set_visible(false);
    process_internals_panel_.set_visible(false);
    binary_diff_panel_.set_visible(false);
    debugger_panel_.set_visible(false);
    capabilities_panel_.set_visible(false);
    executable_settings_panel_.set_visible(false);
    dependencies_panel_.set_visible(false);
    initialize_decompiler();
    recent_binaries_path_ = decompiler_directory_ / "recent_binaries.ini";
#ifdef _WIN32
    recent_binaries_.load(recent_binaries_path_, decompiler_directory_ / "peelf_viewer.exe");
#else
    recent_binaries_.load(recent_binaries_path_, decompiler_directory_ / "peelf_viewer");
#endif
    if (!recent_binaries_.save(recent_binaries_path_)) Log().error("Could not save recent binary history");
    patch_set_panel_.set_analysis_context(&symbol_index_, &thumb_mode_);
    references_panel_.set_scanner(&reference_scanner_);
    references_panel_.set_navigate_callback([this](std::uint64_t address) {
        enqueue_navigation(address, PreferredView::Disassembly);
    });
    references_panel_.set_rebuild_callback([this] { references_dirty_ = true; });
    strings_panel_.set_rebuild_callback([this](std::size_t, bool) { strings_dirty_ = true; });
    strings_panel_.set_string_selected_callback([this](const ExtractedString& s) {
        pending_navigations_.enqueue_custom([this, s_copy = s]() {
            std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(s_copy.virtual_address);
            if (!nav_offset && !model_.is_live_process()) {
                nav_offset = s_copy.file_offset;
            }
            if (!nav_offset && model_.is_live_process() && model_.navigate_to_virtual_address(s_copy.virtual_address)) {
                sync_live_process_view(false);
                nav_offset = model_.virtual_address_to_offset(s_copy.virtual_address);
            }
            navigation_history_.visit(current_selection_);
            const std::uint64_t byte_len = std::max<std::uint64_t>(s_copy.byte_length, 1u);
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::ByteRange,
                .label = "String: " + format_single_line_string_preview(s_copy.preview, 96),
                .file_offset = nav_offset,
                .virtual_address = s_copy.virtual_address,
                .size = byte_len,
                .preferred_view = PreferredView::Hex,
            };
            if (nav_offset) {
                hex_panel_.set_visible(true);
                hex_panel_.navigate_to_range(*nav_offset, byte_len);
            }
            last_navigation_selection_ = current_selection_;
            navigation_history_.visit(current_selection_);
        });
    });
    struct_view_panel_.set_extra_types_provider([this]() -> std::span<const DataTypeRecord> {
        return decompiled_.types;
    });
    struct_view_panel_.set_field_selected_callback(
        [this](std::optional<std::uint64_t> window_offset,
               std::optional<std::uint64_t> virtual_address,
               std::uint64_t size,
               std::string label) {
            pending_navigations_.enqueue_custom(
                [this, window_offset, virtual_address, size, label = std::move(label)]() mutable {
                    const std::uint64_t byte_len = std::max<std::uint64_t>(1u, size);
                    current_selection_ = ViewerSelection{
                        .kind = SelectionKind::ByteRange,
                        .label = std::move(label),
                        .file_offset = model_.is_live_process() ? std::nullopt : window_offset,
                        .virtual_address = virtual_address,
                        .size = byte_len,
                        .object_index = 0,
                        .preferred_view = PreferredView::Hex,
                        .graph_root = std::nullopt,
                    };
                    if (window_offset) {
                        hex_panel_.set_visible(true);
                        hex_panel_.navigate_to_range(*window_offset, byte_len);
                    } else if (virtual_address && model_.is_live_process() &&
                               model_.navigate_to_virtual_address(*virtual_address)) {
                        sync_live_process_view(false);
                        if (const auto off = model_.virtual_address_to_offset(*virtual_address)) {
                            hex_panel_.set_visible(true);
                            hex_panel_.navigate_to_range(*off, byte_len);
                        }
                    }
                });
        });
    struct_view_panel_.set_pointer_activated_callback([this](std::uint64_t target_va) {
        enqueue_navigation(target_va, PreferredView::Hex);
    });
    hex_panel_.set_apply_structure_callback([this](std::uint64_t address, bool is_file_offset) {
        open_structure_view({}, address, is_file_offset);
    });
    strings_panel_.set_referrer_activated_callback(
        [this](const StringReferrer& ref, StringReferrerTargetView target) {
            pending_navigations_.enqueue_custom([this, ref_copy = ref, target]() {
                if (target == StringReferrerTargetView::FlowGraph) {
                    navigate_to_address(ref_copy.instruction_address, PreferredView::Graph);
                    return;
                }
                if (target == StringReferrerTargetView::Decompile) {
                    navigate_to_address(ref_copy.function_address.value_or(ref_copy.instruction_address),
                                        PreferredView::Disassembly);
                    selected_code_address_ = ref_copy.instruction_address;
                    request_decompile();
                    return;
                }
                navigate_to_address(ref_copy.instruction_address, PreferredView::Disassembly);
                if (target == StringReferrerTargetView::SyncAllOpen) {
                    if (show_call_graph_panel_ && model_.image() != nullptr) {
                        if (const auto root = navigation_graph_root(ref_copy.instruction_address)) {
                            if (!active_graph_root_ || active_graph_root_->virtual_address != root->virtual_address) {
                                pending_call_graph_root_ = *root;
                                pending_call_graph_delay_frames_ = 0;
                            }
                            center_graph_selection_ = true;
                        }
                    }
                    if (show_decompiler_) {
                        selected_code_address_ = ref_copy.instruction_address;
                        request_decompile();
                    }
                }
            });
        });
    references_panel_.set_model(&model_);
    references_panel_.set_navigate_offset_callback([this](std::uint64_t off) {
        pending_navigations_.enqueue_offset(off, 1);
    });
    references_panel_.set_pause_callback([this] { reference_scanner_.pause(); });
    references_panel_.set_resume_callback([this] { reference_scanner_.resume(reference_index_); });
    references_panel_.set_scan_full_callback([this] {
        if (reference_scanner_.has_resumable_work()) {
            reference_scanner_.scan_full(reference_index_);
        } else if (const auto* image = model_.image()) {
            std::vector<std::uint8_t> snapshot;
            if (model_.changed_intervals().empty()) {
                const auto span = model_.analysis_image_bytes();
                snapshot.assign(span.begin(), span.end());
            } else if (auto patched = model_.read_effective_bytes(0, model_.bytes().size())) {
                snapshot = std::move(*patched);
            }
            if (!snapshot.empty()) {
                reference_scanner_.start(
                    reference_index_,
                    *image,
                    std::move(snapshot),
                    thumb_mode_,
                    std::numeric_limits<std::size_t>::max(),
                    &symbol_index_);
            }
        }
    });
    symbols_panel_.set_display_name_resolver([this](const SymbolRecord& symbol) {
        const auto* annotation = symbol.virtual_address ? annotations_.find(*symbol.virtual_address) : nullptr;
        if (annotation && !annotation->name.empty()) {
            return annotation->name;
        }
        return symbol.display_name(model_.demangle_symbols());
    });
    symbols_panel_.set_demangle_changed_callback([this](bool) { ++symbol_revision_; });
    functions_panel_.set_demangle_changed_callback([this](bool) { ++symbol_revision_; });
    hex_panel_.set_byte_activated_callback([this](std::uint64_t off, std::uint64_t size) {
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = "Hex selection",
            .file_offset = off,
            .virtual_address = model_.offset_to_virtual_address(off),
            .size = size,
            .preferred_view = PreferredView::Hex
        };
        last_navigation_selection_ = current_selection_;
        disassemble_at_offset(off);
    });
    hex_panel_.set_bytes_patched_callback([this](std::uint64_t) {
        refresh_disassembly();
    });

    auto on_refresh_map = [this]() {
        auto res = model_.refresh_process_map();
        if (!res) {
            Log().error("Failed to refresh process memory map: {}", res.error().message);
            return;
        }
        sync_live_process_view(false);
        Log().info("Refreshed process memory map ({} regions, {} modules)",
                   model_.memory_regions().size(),
                   model_.process_modules().size());
    };
    auto on_detach_proc = [this]() {
        model_.detach_process();
        on_file_loaded();
        Log().info("Detached from live process");
    };

    auto on_toggle_pause = [this]() {
        if (!model_.is_live_process()) {
            return;
        }
        const peelf::SubsystemStatus st = model_.is_process_suspended()
            ? model_.resume_process()
            : model_.suspend_process();
        if (st.availability == peelf::Availability::Unavailable) {
            Log().warn("Process pause/resume: {}", st.detail);
        } else {
            Log().info("{}", st.detail);
        }
    };

    file_panel_.set_attach_requested_callback([this]() { open_attach_process_modal(); });
    file_panel_.set_refresh_requested_callback(on_refresh_map);
    file_panel_.set_detach_requested_callback(on_detach_proc);
    file_panel_.set_pause_toggle_callback(on_toggle_pause);

    memory_map_panel_.set_attach_requested_callback([this]() {
        open_attach_process_modal();
    });
    memory_map_panel_.set_refresh_requested_callback(on_refresh_map);
    memory_map_panel_.set_detach_requested_callback(on_detach_proc);
    memory_map_panel_.set_pause_toggle_callback(on_toggle_pause);
    memory_map_panel_.set_module_selected_callback([this](std::size_t module_index) {
        pending_navigations_.enqueue_module(module_index);
    });
    memory_map_panel_.set_region_activated_callback([this](std::size_t region_index, bool prefer_module_context) {
        pending_navigations_.enqueue_memory_region(region_index, prefer_module_context);
    });

    functions_panel_.set_function_activated_callback([this](std::uint64_t va, bool want_decompile) {
        enqueue_navigation(va, PreferredView::Disassembly, 0, want_decompile);
    });
    threads_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv, bool want_decompile) {
        enqueue_navigation(va, pv, 0, want_decompile);
    });
    thread_locals_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        enqueue_navigation(va, pv);
    });
    memory_search_panel_.set_address_activated_callback([this](std::uint64_t va, std::size_t match_size) {
        enqueue_navigation(va, PreferredView::Hex, std::max<std::size_t>(1u, match_size));
    });
    runtime_flags_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        enqueue_navigation(va, pv);
    });
    handlers_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        enqueue_navigation(va, pv);
    });

    patch_set_panel_.set_patch_activated_callback([this](const ViewerSelection& sel) {
        const ViewerSelection sel_copy = sel;
        pending_navigations_.enqueue_custom([this, sel_copy]() {
            std::optional<std::uint64_t> off = sel_copy.file_offset;
            if (!off && sel_copy.virtual_address) {
                if (model_.is_live_process() && !model_.virtual_address_to_offset(*sel_copy.virtual_address)) {
                    if (model_.navigate_to_virtual_address(*sel_copy.virtual_address)) {
                        sync_live_process_view(false);
                    }
                }
                off = model_.virtual_address_to_offset(*sel_copy.virtual_address);
            }
            if (off) {
                const std::uint64_t sz = sel_copy.size != 0 ? sel_copy.size : 1u;
                hex_panel_.navigate_to_range(*off, sz);
                disassemble_at_offset(*off, sel_copy.virtual_address.value_or(*off));
            }
            last_navigation_selection_ = sel_copy;
        });
    });
    patch_set_panel_.set_patch_mutated_callback([this]() {
        refresh_disassembly();
    });
    shellcode_panel_.set_patch_changed_callback([this]() {
        refresh_disassembly();
    });

    sections_panel_.set_section_activated_callback(
        [this](const peelf::Section& section, std::uint64_t object_index) {
            const peelf::Section section_copy = section;
            pending_navigations_.enqueue_custom([this, section_copy, object_index]() {
                const std::optional<std::uint64_t> nav_offset =
                    model_.is_live_process()
                        ? model_.virtual_address_to_offset(section_copy.virtual_address)
                        : std::optional<std::uint64_t>(section_copy.file_offset);
                if (!nav_offset) {
                    Log().warn("Section '{}' at 0x{:X} is outside the active window",
                               section_copy.name,
                               section_copy.virtual_address);
                    return;
                }
                const std::uint64_t range_size =
                    section_copy.file_size != 0 ? section_copy.file_size : section_copy.virtual_size;
                current_selection_ = ViewerSelection{
                    .kind = SelectionKind::Section,
                    .label = section_copy.name,
                    .file_offset = *nav_offset,
                    .virtual_address = section_copy.virtual_address,
                    .size = std::max(section_copy.file_size, section_copy.virtual_size),
                    .object_index = object_index,
                    .preferred_view = section_copy.executable ? PreferredView::Disassembly : PreferredView::Hex
                };
                hex_panel_.navigate_to_range(*nav_offset, std::max<std::uint64_t>(range_size, 1u));
                if (section_copy.executable) {
                    const auto disasm_win = static_cast<std::size_t>(
                        std::clamp<std::uint64_t>(range_size, 4096u, 65536u));
                    disassemble_at_offset(*nav_offset, section_copy.virtual_address, disasm_win);
                }
                last_navigation_selection_ = current_selection_;
            });
        });
    symbols_panel_.set_symbol_activated_callback([this](const SymbolRecord& symbol, std::uint64_t object_index) {
        const SymbolRecord symbol_copy = symbol;
        pending_navigations_.enqueue_custom([this, symbol_copy, object_index]() {
            focus_graph_ = true;
            activate_panel(details_panel_.name().c_str());
            activate_panel("Disassembly");
            if (model_.image() == nullptr) {
                return;
            }

            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Symbol, .label = symbol_copy.name,
                .file_offset = symbol_copy.file_offset, .virtual_address = symbol_copy.virtual_address,
                .size = symbol_copy.size, .object_index = object_index,
                .preferred_view = PreferredView::Details
            };
            auto file_offset = symbol_copy.virtual_address
                ? model_.virtual_address_to_offset(*symbol_copy.virtual_address)
                : symbol_copy.file_offset;
            if (!file_offset && model_.is_live_process() && symbol_copy.virtual_address &&
                model_.navigate_to_virtual_address(*symbol_copy.virtual_address)) {
                sync_live_process_view(false);
                file_offset = model_.virtual_address_to_offset(*symbol_copy.virtual_address);
            }
            const peelf::IBinaryImage* img = model_.image();
            pending_call_graph_root_.reset();
            current_instructions_.clear();
            disassembly_location_.reset();
            hex_panel_.clear_selection();
            if (!file_offset || img == nullptr) {
                Log().warn("Symbol '{}' at 0x{:X} does not map to file bytes",
                           symbol_copy.name.empty() ? "<unnamed>" : symbol_copy.name,
                           symbol_copy.virtual_address.value_or(0));
                current_instructions_.clear();
                return;
            }

            const std::uint64_t highlight_size = symbol_copy.size != 0 ? symbol_copy.size : 1u;
            const bool has_code = symbol_has_code(*img, symbol_copy);
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Symbol,
                .label = symbol_copy.name.empty() ? "<unnamed>" : symbol_copy.name,
                .file_offset = *file_offset,
                .virtual_address = symbol_copy.virtual_address,
                .size = symbol_copy.size,
                .object_index = object_index,
                .preferred_view = has_code ? PreferredView::Graph : PreferredView::Hex
            };
            hex_panel_.navigate_to_range(*file_offset, highlight_size);
            if (has_code) {
                current_selection_.graph_root = symbol_copy;
                disassemble_at_offset(*file_offset, *symbol_copy.virtual_address);
                pending_call_graph_root_ = symbol_copy;
                pending_call_graph_delay_frames_ = 1;
                show_call_graph_panel_ = true;
                call_graph_status_ = "Analyzing " + symbol_copy.name;
            }
            last_navigation_selection_ = current_selection_;
        });
    });
    imports_panel_.set_import_activated_callback([this](const peelf::ImportEntry& entry, std::uint64_t object_index) {
        const peelf::ImportEntry entry_copy = entry;
        pending_navigations_.enqueue_custom([this, entry_copy, object_index]() {
            if (model_.image() == nullptr || entry_copy.address == 0) {
                return;
            }

            std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(entry_copy.address);
            if (!nav_offset && model_.is_live_process() && model_.navigate_to_virtual_address(entry_copy.address)) {
                sync_live_process_view(false);
                nav_offset = model_.virtual_address_to_offset(entry_copy.address);
            }
            const peelf::IBinaryImage* img = model_.image();
            if (!nav_offset || img == nullptr) {
                Log().warn("Import '{}!{}' at 0x{:X} does not map to bytes",
                           entry_copy.library,
                           entry_copy.name.empty() ? "<ordinal-or-library>" : entry_copy.name,
                           entry_copy.address);
                return;
            }

            const std::uint64_t pointer_size = img->is_64bit() ? 8u : 4u;
            std::string label = entry_copy.library;
            if (!entry_copy.name.empty()) {
                label += "!";
                label += entry_copy.name;
            }
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Import,
                .label = std::move(label),
                .file_offset = *nav_offset,
                .virtual_address = entry_copy.address,
                .size = pointer_size,
                .object_index = object_index,
                .preferred_view = PreferredView::Hex
            };
            hex_panel_.navigate_to_range(*nav_offset, pointer_size);
            last_navigation_selection_ = current_selection_;
        });
    });
    exports_panel_.set_export_activated_callback([this](const peelf::ExportEntry& entry, std::uint64_t object_index) {
        const peelf::ExportEntry entry_copy = entry;
        pending_navigations_.enqueue_custom([this, entry_copy, object_index]() {
            if (model_.image() == nullptr || entry_copy.virtual_address == 0) {
                return;
            }

            std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(entry_copy.virtual_address);
            if (!nav_offset && model_.is_live_process() &&
                model_.navigate_to_virtual_address(entry_copy.virtual_address)) {
                sync_live_process_view(false);
                nav_offset = model_.virtual_address_to_offset(entry_copy.virtual_address);
            }
            if (!nav_offset) {
                Log().warn("Export '{}' at 0x{:X} does not map to bytes",
                           entry_copy.name.empty() ? "<unnamed>" : entry_copy.name,
                           entry_copy.virtual_address);
                return;
            }

            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Export,
                .label = entry_copy.name.empty() ? "<unnamed>" : entry_copy.name,
                .file_offset = *nav_offset,
                .virtual_address = entry_copy.virtual_address,
                .size = 1,
                .object_index = object_index,
                .preferred_view = PreferredView::Disassembly
            };
            hex_panel_.navigate_to_range(*nav_offset, 1);
            disassemble_at_offset(*nav_offset, entry_copy.virtual_address);
            last_navigation_selection_ = current_selection_;
        });
    });
}

UiApp::~UiApp() {
    decompile_controller_.shutdown();
    call_graph_texture_.reset();
}

void UiApp::render() {
    if (const auto stop_ip = model_.sync_debugger_stop_state(); stop_ip.has_value()) {
        sync_live_process_view(false);
        navigate_to_address(*stop_ip, PreferredView::Disassembly);
    }
    render_main_menu();
    auto* viewport = ImGui::GetMainViewport();
    if (ImGui::BeginViewportSideBar("##workspace-actions", viewport, ImGuiDir_Up,
            ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_CheckMark), "PE / ELF");
        ImGui::SameLine(0, 24);
        if (ImGui::Button("Open binary") && on_open_file_) on_open_file_();
        ImGui::SameLine();
        if (ImGui::Button("Attach process")) open_attach_process_modal();
        ImGui::SameLine();
        if (ImGui::Button("Debugger")) {
            debugger_panel_.set_visible(true);
            activate_panel(debugger_panel_.name().c_str());
            if (!model_.is_debug_session()) {
                debugger_panel_.open_opt_in_modal();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Capabilities")) {
            capabilities_panel_.set_visible(true);
            activate_panel(capabilities_panel_.name().c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("Settings")) {
            executable_settings_panel_.set_visible(true);
            activate_panel(executable_settings_panel_.name().c_str());
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(!model_.has_file());
        if (ImGui::Button("Functions")) {
            functions_panel_.set_visible(true);
            activate_panel(functions_panel_.name().c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("Strings")) open_strings();
        ImGui::SameLine();
        if (ImGui::Button("Decompile")) request_decompile();
        ImGui::SameLine();
        if (ImGui::Button("Search")) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (model_.is_live_process()) {
            ImGui::SameLine();
            if (ImGui::Button(model_.is_process_suspended() ? "Resume" : "Pause")) {
                const auto st = model_.is_process_suspended() ? model_.resume_process() : model_.suspend_process();
                Log().info("{}", st.detail);
            }
            ImGui::SameLine();
            if (ImGui::Button("Threads")) {
                threads_panel_.set_visible(true);
                activate_panel(threads_panel_.name().c_str());
            }
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(!navigation_history_.can_back());
        if (ImGui::Button("Back")) navigate_history(false);
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(!navigation_history_.can_forward());
        if (ImGui::Button("Forward")) navigate_history(true);
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Listing")) switch_analysis_view(false);
        ImGui::SameLine();
        if (ImGui::Button("Graph")) switch_analysis_view(true);
        ImGui::SameLine();
        if (ImGui::Button("Entry") && model_.image()) navigate_to_address(model_.image()->entry_point());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
        ImGui::InputScalar("##JumpVA", ImGuiDataType_U64, &jump_address_, nullptr, nullptr, "%" PRIX64, ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Jump to virtual address (hexadecimal)");
        ImGui::SameLine();
        if (ImGui::Button("Jump") && model_.has_file()) {
            navigate_to_address(jump_address_);
        }
        ImGui::SameLine();
        if (ImGui::Button("References")) open_references();
        ImGui::SameLine();
        if (ImGui::Button("Bookmark")) toggle_bookmark_at_selection();
        if (!model_.is_live_process()) {
            ImGui::SameLine();
            if (ImGui::Button("Patches")) patch_set_panel_.set_visible(true);
            ImGui::SameLine();
            if (ImGui::Button("Export copy") && on_save_patched_as_) on_save_patched_as_();
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0, 24);
        ImGui::TextDisabled("%s", model_.has_file()
            ? std::filesystem::path(model_.file_info().path).filename().string().c_str()
            : "Ready to inspect");
    }
    ImGui::End();
    if (ImGui::BeginViewportSideBar("##section-map", viewport, ImGuiDir_Up,
            ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("SEGMENTS");
        if (const auto* image = model_.image()) {
            for (const auto& section : image->sections()) {
                const std::uint64_t sec_size = std::max(section.file_size, section.virtual_size);
                if (sec_size == 0) continue;
                ImGui::SameLine();
                ImGui::PushID(static_cast<int>((section.virtual_address ^ section.file_offset) & 0x7FFFFFFFu));
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(section.executable ? ImGuiCol_HeaderActive : ImGuiCol_FrameBg));
                if (ImGui::Button(section.name.c_str())) {
                    const auto nav_off = model_.is_live_process()
                        ? model_.virtual_address_to_offset(section.virtual_address)
                        : std::optional<std::uint64_t>(section.file_offset);
                    if (nav_off) {
                        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_off), 1);
                        if (section.executable) {
                            const auto disasm_win = static_cast<std::size_t>(
                                std::clamp<std::uint64_t>(sec_size, 4096u, 65536u));
                            disassemble_at_offset(*nav_off, section.virtual_address, disasm_win);
                        }
                        current_selection_ = ViewerSelection{
                            .kind = SelectionKind::Section,
                            .label = section.name,
                            .file_offset = *nav_off,
                            .virtual_address = section.virtual_address,
                            .size = sec_size,
                            .preferred_view = section.executable ? PreferredView::Disassembly : PreferredView::Hex
                        };
                    }
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("VA 0x%" PRIX64 " | %" PRIu64 " bytes%s",
                    section.virtual_address, sec_size,
                    section.executable ? " | executable" : "");
                ImGui::PopID();
            }
        } else { ImGui::SameLine(); ImGui::TextDisabled("Open an image to navigate its sections"); }
    }
    ImGui::End();
    render_dockspace();
    render_recovery_banner();
    render_attach_process_modal();
    debugger_panel_.render_opt_in_modal();
    render_relocate_project_modal();

    file_panel_.draw();
    memory_map_panel_.draw();
    structure_panel_.draw();
    details_panel_.draw();
    sections_panel_.draw();
    ImGui::PushFont(code_font_, 0.0f);
    hex_panel_.draw();
    ImGui::PopFont();
    patch_set_panel_.draw();
    shellcode_panel_.draw();
    imports_panel_.draw();
    exports_panel_.draw();
    symbols_panel_.draw();
    functions_panel_.draw();
    threads_panel_.draw();
    thread_locals_panel_.draw();
    memory_search_panel_.draw();
    runtime_flags_panel_.draw();
    handlers_panel_.draw();
    if (show_data_types_) render_data_types();
    references_panel_.draw();
    strings_panel_.draw();
    struct_view_panel_.draw();
    process_internals_panel_.draw();
    dependencies_panel_.draw();
    binary_diff_panel_.draw();
    debugger_panel_.draw();
    capabilities_panel_.draw();
    executable_settings_panel_.draw();
    if (show_decompiler_) render_decompiler();
    if (focus_references_) {
        activate_panel(references_panel_.name().c_str());
        focus_references_ = false;
    }
    if (focus_strings_) {
        activate_panel(strings_panel_.name().c_str());
        focus_strings_ = false;
    }
    if (focus_struct_view_) {
        activate_panel(struct_view_panel_.name().c_str());
        focus_struct_view_ = false;
    }
    pe_headers_panel_.draw();
    pe_imports_panel_.draw();
    pe_exports_panel_.draw();
    log_panel_.draw();

    if (show_disassembly_panel_) {
        ImGui::PushFont(code_font_, 0.0f);
        render_disassembly_panel();
        ImGui::PopFont();
    }
    if (show_call_graph_panel_) {
        render_call_graph_panel();
        if (focus_graph_) { activate_panel("Flow Graph"); focus_graph_ = false; }
    }
    if (show_demo_window_)
        ImGui::ShowDemoWindow(&show_demo_window_);
    apply_structure_selection_navigation();
    drain_pending_navigations();
    if (focus_listing_) { activate_panel("Disassembly"); focus_listing_ = false; }
    navigation_history_.visit(current_selection_);
    if (focus_workspace_) {
        activate_panel(symbols_panel_.name().c_str());
        activate_panel(details_panel_.name().c_str());
        activate_panel("Disassembly");
        focus_workspace_ = false;
    }
}

void UiApp::rebuild_strings() {
    StringScanOptions opts;
    opts.min_length = strings_panel_.requested_min_length();
    opts.include_all_live_regions = strings_panel_.scan_all_live_regions();

    if (model_.is_live_process() && model_.process_session() != nullptr) {
        std::optional<std::uint64_t> active_base;
        if (const auto mod_idx = model_.active_module_index();
            mod_idx && *mod_idx < model_.process_modules().size()) {
            active_base = model_.process_modules()[*mod_idx].base_address;
        }
        if (!opts.include_all_live_regions && model_.image() != nullptr &&
            !model_.analysis_image_bytes().empty()) {
            strings_index_ = StringsIndex::extract(*model_.image(), model_.analysis_image_bytes(), opts);
        } else {
            strings_index_ = StringsIndex::extract_live(
                *model_.process_session(),
                model_.memory_regions(),
                model_.image(),
                active_base,
                opts);
        }
    } else if (const auto* image = model_.image()) {
        if (model_.changed_intervals().empty()) {
            strings_index_ = StringsIndex::extract(*image, model_.analysis_image_bytes(), opts);
        } else if (auto patched = model_.read_effective_bytes(0, model_.bytes().size())) {
            strings_index_ = StringsIndex::extract(*image, *patched, opts);
        } else {
            strings_index_.clear();
        }
    } else {
        strings_index_.clear();
    }

    strings_index_.refresh_xrefs(
        reference_index_, &model_.function_index(), &symbol_index_, symbol_revision_);
    strings_revision_ = model_.edit_revision();
    strings_dirty_ = false;
}

void UiApp::rebuild_references() {
    const auto* image = model_.image();
    if (!image) return;
    reference_scanner_.cancel(&reference_index_);

    std::span<const std::uint8_t> direct_span;
    std::vector<std::uint8_t> owned_bytes;
    if (model_.changed_intervals().empty()) {
        direct_span = model_.analysis_image_bytes();
    } else if (auto bytes = model_.read_effective_bytes(0, model_.bytes().size())) {
        owned_bytes = std::move(*bytes);
        direct_span = owned_bytes;
    } else {
        reference_index_ = {};
        Log().warn("Unable to read patched bytes for reference analysis");
        reference_revision_ = model_.edit_revision();
        reference_thumb_mode_ = thumb_mode_;
        references_dirty_ = false;
        return;
    }

    if (direct_span.size() <= ReferenceIndex::kDefaultChunkBytes) {
        reference_index_ = ReferenceIndex::build(
            *image, direct_span, thumb_mode_, ReferenceIndex::kDefaultByteBudget, &symbol_index_);
    } else {
        if (owned_bytes.empty()) {
            owned_bytes.assign(direct_span.begin(), direct_span.end());
        }
        reference_scanner_.start(
            reference_index_,
            *image,
            std::move(owned_bytes),
            thumb_mode_,
            ReferenceIndex::kDefaultByteBudget,
            &symbol_index_);
    }
    reference_revision_ = model_.edit_revision();
    reference_thumb_mode_ = thumb_mode_;
    references_dirty_ = false;
}

void UiApp::process_deferred_gpu_work() {
    if (auto completed = decompile_controller_.poll_completed(current_decompile_stamp())) {
        if (completed->cache_key && completed->unit.status == DecompileStatus::Ready) {
            decompile_cache_.put(*completed->cache_key, completed->unit);
        }
        if (completed->root_symbol) {
            decompiled_root_ = std::move(completed->root_symbol);
        }
        decompile_revision_ = completed->stamp.edit_revision;
        decompile_generation_ = completed->stamp.file_generation;
        decompiler_thumb_ = completed->thumb;
        decompile_annotation_revision_ = annotations_.revision();
        decompile_symbol_revision_ = symbol_revision_;
        decompiled_ = std::move(completed->unit);
    } else if (decompile_controller_.consume_stale_discard_notice()) {
        decompiled_ = DecompiledUnit{
            .status = DecompileStatus::Failed,
            .provider = "Decompiler",
            .diagnostic = "Bytes or symbols changed during analysis; press F5 to analyze the updated state.",
        };
    }
    reference_scanner_.poll(reference_index_);
    if (reference_revision_ != model_.edit_revision() || reference_thumb_mode_ != thumb_mode_)
        references_dirty_ = true;
    if ((references_panel_.visible() || strings_panel_.visible() || show_call_graph_panel_) &&
        references_dirty_ && model_.image())
        rebuild_references();
    if (strings_revision_ != model_.edit_revision())
        strings_dirty_ = true;
    if (strings_panel_.visible() && model_.has_file()) {
        if (strings_dirty_) {
            rebuild_strings();
        }
        strings_index_.refresh_xrefs(
            reference_index_, &model_.function_index(), &symbol_index_, symbol_revision_);
    }
    if (annotation_revision_ != annotations_.revision()) {
        annotation_revision_ = annotations_.revision();
        if (active_graph_root_) pending_call_graph_root_ = active_graph_root_;
    }
    poll_project_autosave(false);
    if (active_graph_root_ && graph_revision_ != model_.edit_revision()) {
        pending_call_graph_root_ = active_graph_root_;
        graph_revision_ = model_.edit_revision();
    }
    if (pending_call_graph_request_) {
        if (pending_call_graph_request_->delay_frames > 0) {
            --pending_call_graph_request_->delay_frames;
        } else {
            const CallGraphSample sample = pending_call_graph_request_->sample;
            pending_call_graph_request_.reset();
            load_call_graph_sample(sample);
            return;
        }
    }

    if (pending_call_graph_root_ && pending_call_graph_delay_frames_ > 0) {
        --pending_call_graph_delay_frames_;
    } else if (pending_call_graph_root_) {
        const peelf::IBinaryImage* img = model_.image();
        const SymbolRecord root = *pending_call_graph_root_;
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        if (img != nullptr) {
            active_graph_root_ = root;
            graph_revision_ = model_.edit_revision();
            graph_pan_ = {};
            graph_zoom_ = 1.0f;
            SymbolRecord root_for_extent = root;
            if (root.virtual_address) {
                root_for_extent.file_offset = img->virtual_address_to_file_offset(*root.virtual_address);
            }
            const std::size_t analysis_size = model_.analysis_image_size();
            if (function_cfg_ && root_for_extent.file_offset && root_for_extent.virtual_address &&
                *root_for_extent.file_offset < analysis_size) {
                const auto extent = discover_function_extent(*img, symbol_index_, root_for_extent, analysis_size);
                if (!extent) {
                    call_graph_status_ = "No executable extent available for " + root.name;
                    return;
                }
                const auto size = static_cast<std::size_t>(extent->size);
                if (const auto bytes = model_.read_virtual_bytes(extent->virtual_address, size)) {
                    const auto window_off = model_.virtual_address_to_offset(extent->virtual_address)
                        .value_or(extent->file_offset);
                    const GraphByteReader va_reader = [this](std::uint64_t va, std::size_t len)
                        -> std::vector<std::uint8_t> {
                        auto res = model_.read_virtual_bytes(va, len);
                        return res ? std::move(*res) : std::vector<std::uint8_t>{};
                    };
                    load_call_graph_from_graph(
                        build_function_cfg_call_graph(
                            *bytes,
                            *root_for_extent.virtual_address,
                            img->architecture(),
                            img->endianness(),
                            static_cast<std::size_t>(window_off),
                            root.name,
                            thumb_mode_,
                            extent->source == FunctionExtentSource::ExecutableRegion ||
                                extent->source == FunctionExtentSource::NextSymbol,
                            va_reader),
                        "function_cfg");
                    if (current_call_graph_) {
                        call_graph_status_ = root.name + std::format(
                            "  |  {} bytes  |  {}{}",
                            size,
                            function_extent_source_name(extent->source),
                            extent->truncated ? " (limited)" : "");
                    }
                }
            } else if (model_.is_live_process()) {
                const GraphByteReader reader = [this](std::uint64_t offset, std::size_t length)
                    -> std::vector<std::uint8_t> {
                    if (const auto va = model_.offset_to_virtual_address(offset)) {
                        if (auto vbytes = model_.read_virtual_bytes(*va, length)) {
                            return std::move(*vbytes);
                        }
                    }
                    auto sample = model_.read_window_sample(offset, length);
                    if (!sample || sample->bytes.empty()) {
                        return {};
                    }
                    std::size_t readable_prefix = 0;
                    while (readable_prefix < sample->valid.size() && sample->valid[readable_prefix] != 0) {
                        ++readable_prefix;
                    }
                    sample->bytes.resize(readable_prefix);
                    return std::move(sample->bytes);
                };
                load_call_graph_from_graph(
                    build_symbol_fanout_call_graph(*img, reader, symbol_index_, root),
                    "function_calls");
                if (current_call_graph_) {
                    call_graph_status_ = root.name + "  |  Calls";
                }
            } else {
                load_call_graph_from_graph(
                    build_symbol_fanout_call_graph(*img, model_.bytes(), symbol_index_, root),
                    "function_calls");
                if (current_call_graph_) {
                    call_graph_status_ = root.name + "  |  Calls";
                }
            }
        }
    }
}

    // Called after a file (PE or ELF) is loaded into the model, or after detaching.
    void UiApp::on_file_loaded() {
        pending_navigations_.clear();
        patch_set_panel_.reset_preview();
        binary_diff_panel_.invalidate();
        decompile_controller_.reset_for_new_target();
        ++file_generation_;
        decompiled_ = {};
        annotations_.clear();
        debug_types_.clear(); ++symbol_revision_; decompiled_root_.reset();
        selected_code_ranges_.clear(); selected_code_address_.reset();
        reference_scanner_.cancel(&reference_index_);
        reference_index_ = {};
        references_dirty_ = true;
        strings_index_.clear();
        strings_dirty_ = true;
        strings_panel_.reset_selection();
        struct_view_panel_.reset_for_new_binary();
        navigation_history_.clear();
        disassembly_location_.reset();
        thumb_mode_ = false;
        current_project_path_.clear();
        current_project_saved_ms_ = 0;
        pending_recovery_project_.reset();
        pending_recovery_key_path_.clear();
        mark_autosave_baseline();
        if (model_.is_live_process()) {
            on_process_attached();
            return;
        }
        if (!model_.file_info().path.empty()) {
            const std::filesystem::path bin_path(model_.file_info().path);
            if (auto rec = check_newer_recovery_journal(bin_path, 0)) {
                pending_recovery_project_ = std::move(*rec);
                pending_recovery_key_path_ = bin_path;
            }
        }

        const peelf::IBinaryImage* img = model_.image();
        if (!img) {
            symbol_index_ = {};
            file_loaded_ = false;
            structure_tree_.reset();
            current_selection_ = {};
            last_navigation_selection_.reset();
            last_disasm_offset_.reset();
            current_instructions_.clear();
            disasm_status_.clear();
            pending_call_graph_root_.reset();
            pending_call_graph_delay_frames_ = 0;
            pending_call_graph_request_.reset();
            return;
        }

        structure_tree_ = build_structure_tree(*img);
        recent_binaries_.remember(model_.file_info().path);
        if (!recent_binaries_.save(recent_binaries_path_)) Log().error("Could not save recent binary history");
        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        pending_call_graph_request_.reset();
        if (const std::optional<std::filesystem::path> pdb = find_local_codeview_pdb(*img, model_.file_info().path)) {
            load_debug_symbols(*pdb);
        } else if (!img->pe_debug_directories().empty()) {
            for (const peelf::PeDebugDirectory& debug : img->pe_debug_directories()) {
                if (!debug.codeview_pdb_path.empty()) {
                    Log().info("CodeView references PDB '{}'; use File > Open Debug Symbols... if it is elsewhere",
                               debug.codeview_pdb_path);
                    break;
                }
            }
        }
        current_selection_ = structure_tree_->selection;
        last_navigation_selection_.reset();
        Log().info("Loaded {} symbol records ({} debug types, {} source lines)",
                   model_.symbol_index().size(),
                   model_.debug_types().size(),
                   model_.source_lines().size());

        // Map the unified architecture onto the disassembler's enum.
        const std::optional<viewer::Architecture> arch = to_disassembler_architecture(img->architecture());
        if (!arch) {
            Log().error(std::string("Disassembly is not supported for architecture: ") +
                        std::string(peelf::to_string(img->architecture())));
            file_loaded_ = false;
            current_instructions_.clear();
            return;
        }

        if (!disasm_.init(*arch, to_disassembler_endianness(img->endianness()))) {
            Log().error(std::string("Failed to initialize disassembler: ") + disasm_.get_error());
            file_loaded_ = false;
            return;
        }
        file_loaded_ = true;
        current_instructions_.clear();
        disasm_status_.clear();

        if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            hex_panel_.navigate_to_range(clamp_to_size_t(*entry_offset), 1);
            last_navigation_selection_ = current_selection_;
            disassemble_at_offset(static_cast<std::size_t>(*entry_offset), img->entry_point());
        }

        call_graph_sample_ = CallGraphSample::LoadedImage;
        active_graph_root_.reset();
        if (const auto offset = img->virtual_address_to_file_offset(img->entry_point())) {
            const auto* symbol = symbol_index_.find_containing_address(img->entry_point());
            pending_call_graph_root_ = symbol ? *symbol : SymbolRecord{.name = "Entry point", .virtual_address = img->entry_point(), .file_offset = *offset};
            function_cfg_ = true;
            show_call_graph_panel_ = true;
            focus_graph_ = true;
        }
        call_graph_status_ = "Analyzing entry point";
        call_graph_texture_.reset();
    }

    void UiApp::load_debug_symbols(const std::filesystem::path& path) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            Log().warn("Cannot load debug symbols without a loaded image");
            return;
        }

        DebugSymbolLoadResult result = load_debug_symbols_file(path, *img);
        if (result.status != DebugSymbolLoadStatus::Loaded) {
            Log().warn("Debug symbols not loaded ({}): {}",
                       to_string(result.status),
                       result.diagnostic);
            return;
        }

        model_.apply_debug_symbol_result(result);
        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
        ++symbol_revision_;
        Log().info("Loaded {} debug symbols, {} types, and {} source lines from {}; symbol index now has {} records",
                   result.symbols.size(),
                   result.types.size(),
                   result.lines.size(),
                   path.string(),
                   model_.symbol_index().size());

        call_graph_status_ = "Debug symbols loaded. Use Reload to rebuild the call graph.";
        pending_call_graph_request_.reset();
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        call_graph_texture_.reset();
    }

} // namespace viewer
