#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "analysis/project.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"
#include "theme.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#ifndef PEELF_VERSION_STRING
#define PEELF_VERSION_STRING "1.0.0"
#endif

namespace viewer {
namespace {
using detail::activate_panel;

struct WorkspaceSettingsIniState {
    std::uint32_t loaded_schema_version{0u};
    WorkspacePreset active_preset{WorkspacePreset::StaticReverseEngineering};
    bool saw_ini_section{false};
};

// Trivial static storage so ImGui::DestroyContext() INI flush after ~UiApp() remains valid.
WorkspaceSettingsIniState g_workspace_ini_state{};

[[nodiscard]] std::string_view trim_ini_token(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
        sv.remove_suffix(1);
    }
    return sv;
}

void* workspace_settings_read_open(
    ImGuiContext* /*ctx*/,
    ImGuiSettingsHandler* /*handler*/,
    const char* name) {
    if (name != nullptr && std::string_view(name) == "State") {
        g_workspace_ini_state.saw_ini_section = true;
        return &g_workspace_ini_state;
    }
    return nullptr;
}

void workspace_settings_read_line(
    ImGuiContext* /*ctx*/,
    ImGuiSettingsHandler* /*handler*/,
    void* entry,
    const char* line) {
    auto* state = static_cast<WorkspaceSettingsIniState*>(entry);
    if (state == nullptr || line == nullptr) {
        return;
    }
    const std::string_view sv = trim_ini_token(line);
    const std::size_t eq = sv.find('=');
    if (eq == std::string_view::npos) {
        return;
    }
    const std::string_view key = trim_ini_token(sv.substr(0, eq));
    const std::string_view val = trim_ini_token(sv.substr(eq + 1));
    if (key == "SchemaVersion") {
        std::uint32_t parsed = 0u;
        const auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), parsed);
        if (ec == std::errc{} && ptr == val.data() + val.size()) {
            state->loaded_schema_version = parsed;
        }
    } else if (key == "ActivePreset") {
        if (const auto preset = parse_workspace_preset_id(val); preset.has_value()) {
            state->active_preset = *preset;
        }
    }
}

void workspace_settings_write_all(
    ImGuiContext* /*ctx*/,
    ImGuiSettingsHandler* handler,
    ImGuiTextBuffer* out_buf) {
    if (handler == nullptr || out_buf == nullptr) {
        return;
    }
    const std::string_view preset_id = workspace_preset_id(g_workspace_ini_state.active_preset);
    out_buf->appendf("[%s][State]\n", handler->TypeName);
    out_buf->appendf("SchemaVersion=%u\n", kWorkspaceLayoutSchemaVersion);
    out_buf->appendf(
        "ActivePreset=%.*s\n\n",
        static_cast<int>(preset_id.size()),
        preset_id.data());
}

void build_imgui_dock_subtree(
    const DockNodeSpec& node,
    ImGuiID node_id,
    std::vector<WorkspacePanelId>& out_active_tabs,
    ImGuiID& fallback_leaf_id) {
    if (node.is_leaf()) {
        if (fallback_leaf_id == 0) {
            fallback_leaf_id = node_id;
        }
        for (const WorkspacePanelId panel : node.tabbed_panels) {
            const std::string title(workspace_panel_window_name(panel));
            ImGui::DockBuilderDockWindow(title.c_str(), node_id);
        }
        if (node.active_tab.has_value()) {
            out_active_tabs.push_back(*node.active_tab);
            if (auto* dock_node = ImGui::DockBuilderGetNode(node_id)) {
                const std::string active_title(workspace_panel_window_name(*node.active_tab));
                dock_node->SelectedTabId = ImHashStr(active_title.c_str());
            }
        }
        return;
    }

    if (node.first == nullptr || node.second == nullptr) {
        return;
    }

    ImGuiID first_id = 0;
    ImGuiID second_id = 0;
    const ImGuiDir split_dir =
        (node.split_axis == DockSplitAxis::Horizontal) ? ImGuiDir_Left : ImGuiDir_Up;
    ImGui::DockBuilderSplitNode(node_id, split_dir, node.split_ratio, &first_id, &second_id);
    build_imgui_dock_subtree(*node.first, first_id, out_active_tabs, fallback_leaf_id);
    build_imgui_dock_subtree(*node.second, second_id, out_active_tabs, fallback_leaf_id);
}

} // namespace

void UiApp::register_workspace_settings_handler() {
    if (ImGui::GetCurrentContext() == nullptr) {
        return;
    }
    if (ImGui::FindSettingsHandler("WorkspaceLayout") != nullptr) {
        return;
    }
    g_workspace_ini_state = {};
    ImGuiSettingsHandler handler{};
    handler.TypeName = "WorkspaceLayout";
    handler.TypeHash = ImHashStr("WorkspaceLayout");
    handler.ReadOpenFn = workspace_settings_read_open;
    handler.ReadLineFn = workspace_settings_read_line;
    handler.WriteAllFn = workspace_settings_write_all;
    ImGui::AddSettingsHandler(&handler);
}

void UiApp::sync_workspace_ini_state() const noexcept {
    g_workspace_ini_state.saw_ini_section = true;
    g_workspace_ini_state.loaded_schema_version = loaded_layout_schema_version_;
    g_workspace_ini_state.active_preset = active_workspace_preset_;
}

void UiApp::request_workspace_preset(WorkspacePreset preset) noexcept {
    pending_workspace_preset_ = preset;
}

void UiApp::request_workspace_reset() noexcept {
    pending_workspace_preset_ = active_workspace_preset_;
    reset_dock_layout_ = true;
}

void UiApp::set_workspace_panel_visible(WorkspacePanelId panel, bool visible) noexcept {
    switch (panel) {
        case WorkspacePanelId::FileInfo:           file_panel_.set_visible(visible); break;
        case WorkspacePanelId::MemoryMap:          memory_map_panel_.set_visible(visible); break;
        case WorkspacePanelId::MemoryHeatmap:      memory_heatmap_panel_.set_visible(visible); break;
        case WorkspacePanelId::ByteEntropyViz:     byte_viz_panel_.set_visible(visible); break;
        case WorkspacePanelId::Structure:          structure_panel_.set_visible(visible); break;
        case WorkspacePanelId::Details:            details_panel_.set_visible(visible); break;
        case WorkspacePanelId::Sections:           sections_panel_.set_visible(visible); break;
        case WorkspacePanelId::HexView:            hex_panel_.set_visible(visible); break;
        case WorkspacePanelId::PatchSet:           patch_set_panel_.set_visible(visible); break;
        case WorkspacePanelId::Shellcode:          shellcode_panel_.set_visible(visible); break;
        case WorkspacePanelId::Scripting:          scripting_panel_.set_visible(visible); break;
        case WorkspacePanelId::Imports:            imports_panel_.set_visible(visible); break;
        case WorkspacePanelId::Exports:            exports_panel_.set_visible(visible); break;
        case WorkspacePanelId::Symbols:            symbols_panel_.set_visible(visible); break;
        case WorkspacePanelId::Functions:          functions_panel_.set_visible(visible); break;
        case WorkspacePanelId::ThreadsAndStack:    threads_panel_.set_visible(visible); break;
        case WorkspacePanelId::ThreadLocals:       thread_locals_panel_.set_visible(visible); break;
        case WorkspacePanelId::MemorySearch:       memory_search_panel_.set_visible(visible); break;
        case WorkspacePanelId::RuntimeAndFlags:    runtime_flags_panel_.set_visible(visible); break;
        case WorkspacePanelId::Handlers:           handlers_panel_.set_visible(visible); break;
        case WorkspacePanelId::DataStructures:     show_data_types_ = visible; break;
        case WorkspacePanelId::ReferencesAndNotes:  references_panel_.set_visible(visible); break;
        case WorkspacePanelId::Strings:             strings_panel_.set_visible(visible); break;
        case WorkspacePanelId::SignaturesAndCrypto: signatures_panel_.set_visible(visible); break;
        case WorkspacePanelId::StructureView:       struct_view_panel_.set_visible(visible); break;
        case WorkspacePanelId::ProcessInternals:   process_internals_panel_.set_visible(visible); break;
        case WorkspacePanelId::Dependencies:       dependencies_panel_.set_visible(visible); break;
        case WorkspacePanelId::BinaryDiff:         binary_diff_panel_.set_visible(visible); break;
        case WorkspacePanelId::Debugger:           debugger_panel_.set_visible(visible); break;
        case WorkspacePanelId::TargetCapabilities: capabilities_panel_.set_visible(visible); break;
        case WorkspacePanelId::ExecutableSettings: executable_settings_panel_.set_visible(visible); break;
        case WorkspacePanelId::ExecutionTimeline:  timeline_panel_.set_visible(visible); break;
        case WorkspacePanelId::Decompiler:         show_decompiler_ = visible; break;
        case WorkspacePanelId::PeHeaders:          pe_headers_panel_.set_visible(visible); break;
        case WorkspacePanelId::PeImports:          pe_imports_panel_.set_visible(visible); break;
        case WorkspacePanelId::PeExports:          pe_exports_panel_.set_visible(visible); break;
        case WorkspacePanelId::Disassembly:        show_disassembly_panel_ = visible; break;
        case WorkspacePanelId::FlowGraph:          show_call_graph_panel_ = visible; break;
        case WorkspacePanelId::Log:                log_panel_.set_visible(visible); break;
    }
}

bool UiApp::is_workspace_panel_visible(WorkspacePanelId panel) const noexcept {
    switch (panel) {
        case WorkspacePanelId::FileInfo:           return file_panel_.visible();
        case WorkspacePanelId::MemoryMap:          return memory_map_panel_.visible();
        case WorkspacePanelId::MemoryHeatmap:      return memory_heatmap_panel_.visible();
        case WorkspacePanelId::ByteEntropyViz:     return byte_viz_panel_.visible();
        case WorkspacePanelId::Structure:          return structure_panel_.visible();
        case WorkspacePanelId::Details:            return details_panel_.visible();
        case WorkspacePanelId::Sections:           return sections_panel_.visible();
        case WorkspacePanelId::HexView:            return hex_panel_.visible();
        case WorkspacePanelId::PatchSet:           return patch_set_panel_.visible();
        case WorkspacePanelId::Shellcode:          return shellcode_panel_.visible();
        case WorkspacePanelId::Scripting:          return scripting_panel_.visible();
        case WorkspacePanelId::Imports:            return imports_panel_.visible();
        case WorkspacePanelId::Exports:            return exports_panel_.visible();
        case WorkspacePanelId::Symbols:            return symbols_panel_.visible();
        case WorkspacePanelId::Functions:          return functions_panel_.visible();
        case WorkspacePanelId::ThreadsAndStack:    return threads_panel_.visible();
        case WorkspacePanelId::ThreadLocals:       return thread_locals_panel_.visible();
        case WorkspacePanelId::MemorySearch:       return memory_search_panel_.visible();
        case WorkspacePanelId::RuntimeAndFlags:    return runtime_flags_panel_.visible();
        case WorkspacePanelId::Handlers:           return handlers_panel_.visible();
        case WorkspacePanelId::DataStructures:     return show_data_types_;
        case WorkspacePanelId::ReferencesAndNotes:  return references_panel_.visible();
        case WorkspacePanelId::Strings:             return strings_panel_.visible();
        case WorkspacePanelId::SignaturesAndCrypto: return signatures_panel_.visible();
        case WorkspacePanelId::StructureView:       return struct_view_panel_.visible();
        case WorkspacePanelId::ProcessInternals:   return process_internals_panel_.visible();
        case WorkspacePanelId::Dependencies:       return dependencies_panel_.visible();
        case WorkspacePanelId::BinaryDiff:         return binary_diff_panel_.visible();
        case WorkspacePanelId::Debugger:           return debugger_panel_.visible();
        case WorkspacePanelId::TargetCapabilities: return capabilities_panel_.visible();
        case WorkspacePanelId::ExecutableSettings: return executable_settings_panel_.visible();
        case WorkspacePanelId::ExecutionTimeline:  return timeline_panel_.visible();
        case WorkspacePanelId::Decompiler:         return show_decompiler_;
        case WorkspacePanelId::PeHeaders:          return pe_headers_panel_.visible();
        case WorkspacePanelId::PeImports:          return pe_imports_panel_.visible();
        case WorkspacePanelId::PeExports:          return pe_exports_panel_.visible();
        case WorkspacePanelId::Disassembly:        return show_disassembly_panel_;
        case WorkspacePanelId::FlowGraph:          return show_call_graph_panel_;
        case WorkspacePanelId::Log:                return log_panel_.visible();
    }
    return false;
}

void UiApp::render_main_menu() {
    if (!ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
            if (ImGui::GetIO().KeyCtrl && model_.is_live_process()) {
                if (auto result = model_.refresh_process_map()) sync_live_process_view(false);
                else Log().error("Refresh failed: {}", result.error().message);
            } else if (!ImGui::GetIO().KeyCtrl && model_.is_debug_session()) {
                if (auto* dbg = model_.debug_session();
                    dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Paused) {
                    if (auto r = dbg->continue_execution(false); !r) Log().error("Debugger continue: {}", r.error().message);
                }
            } else if (!ImGui::GetIO().KeyCtrl) {
                request_decompile();
            }
        }
        if (model_.is_debug_session()) {
            auto* dbg = model_.debug_session();
            if (ImGui::IsKeyPressed(ImGuiKey_F9) && current_selection_.virtual_address.has_value()) {
                if (auto r = model_.toggle_software_breakpoint(*current_selection_.virtual_address); r) {
                    Log().info("{} software breakpoint at 0x{:X}",
                               *r ? "Set" : "Removed",
                               *current_selection_.virtual_address);
                } else {
                    Log().error("Breakpoint toggle: {}", r.error().message);
                }
            }
            if (dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Paused) {
                if (ImGui::IsKeyPressed(ImGuiKey_F10)) {
                    if (auto r = dbg->step_over(model_.selected_thread_id()); !r) {
                        Log().error("Step over: {}", r.error().message);
                    }
                }
                if (ImGui::IsKeyPressed(ImGuiKey_F11)) {
                    auto r = ImGui::GetIO().KeyShift
                        ? dbg->step_out(model_.selected_thread_id())
                        : dbg->step_into(model_.selected_thread_id());
                    if (!r) {
                        Log().error("Step: {}", r.error().message);
                    }
                }
            }
        }
    }
    if (!ImGui::GetIO().WantTextInput && ImGui::Shortcut(ImGuiKey_X, ImGuiInputFlags_RouteGlobal)) open_references();
    if (!ImGui::GetIO().WantTextInput &&
        ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_B, ImGuiInputFlags_RouteGlobal) &&
        model_.has_file()) {
        toggle_bookmark_at_selection();
    }
    if (!ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_LeftArrow) ||
            ImGui::IsKeyChordPressed(ImGuiKey_Backspace)) navigate_history(false);
        if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_RightArrow) ||
            ImGui::IsKeyChordPressed(ImGuiMod_Shift | ImGuiKey_Backspace)) navigate_history(true);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_K, ImGuiInputFlags_RouteGlobal) ||
        ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_P, ImGuiInputFlags_RouteGlobal)) {
        open_command_palette();
    }
    if (!ImGui::GetIO().WantTextInput &&
        ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_G, ImGuiInputFlags_RouteGlobal)) {
        open_command_palette(":");
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O, ImGuiInputFlags_RouteGlobal) && on_open_file_) on_open_file_();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S, ImGuiInputFlags_RouteGlobal) && model_.has_file() && on_save_patched_as_) on_save_patched_as_();
    if (!ImGui::BeginMainMenuBar())
        return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) {
            if (on_open_file_) { on_open_file_(); }
        }
        if (ImGui::MenuItem("Open Crash Dump...", nullptr, false, static_cast<bool>(on_analysis_file_))) {
            on_analysis_file_(4);
        }
        if (ImGui::BeginMenu("Recent Binaries")) {
            std::optional<std::filesystem::path> selected;
            for (const auto& path : recent_binaries_.paths()) {
                const auto utf8 = path.generic_u8string();
                const std::string label(utf8.begin(), utf8.end());
                ImGui::PushID(label.c_str());
                if (ImGui::MenuItem(label.c_str())) selected = path;
                ImGui::PopID();
            }
            ImGui::EndMenu();
            if (selected) {
                BinaryModel opened;
                if (opened.load_file(selected->string())) {
                    model_ = std::move(opened);
                    on_file_loaded();
                } else Log().error("Cannot open recent binary: {}", selected->string());
            }
        }
        if (ImGui::MenuItem("Open Analysis Project...", nullptr, false, static_cast<bool>(on_analysis_file_))) on_analysis_file_(0);
        if (ImGui::MenuItem("Save Analysis Project...", nullptr, false, model_.has_file() && static_cast<bool>(on_analysis_file_))) on_analysis_file_(1);
        if (ImGui::MenuItem("Export Patch Report...", nullptr, false, model_.has_file() && static_cast<bool>(on_analysis_file_))) on_analysis_file_(2);
        if (ImGui::MenuItem("Compare With Binary...", nullptr, false, model_.has_file())) {
            binary_diff_panel_.set_visible(true);
            activate_panel(binary_diff_panel_.name().c_str());
            if (on_analysis_file_) on_analysis_file_(3);
        }
        if (ImGui::MenuItem("Compare Active Live Module vs. Disk", nullptr, false, model_.is_live_process())) {
            binary_diff_panel_.set_visible(true);
            activate_panel(binary_diff_panel_.name().c_str());
            if (auto r = binary_diff_panel_.compare_active_live_module_vs_disk(); !r) {
                Log().error("Live Module Integrity Diff: {}", r.error().message);
            }
        }
        if (ImGui::MenuItem("Attach to Process...", "Ctrl+P")) {
            open_attach_process_modal();
        }
        if (ImGui::MenuItem("Refresh Process Memory Map", "Ctrl+F5", false, model_.is_live_process())) {
            auto res = model_.refresh_process_map();
            if (res) {
                sync_live_process_view(false);
                Log().info("Refreshed process memory map");
            } else {
                Log().error("Refresh failed: {}", res.error().message);
            }
        }
        if (ImGui::MenuItem(model_.is_process_suspended() ? "Resume Process" : "Pause Process",
                            nullptr,
                            false,
                            model_.is_live_process() && !model_.is_crash_dump())) {
            const auto st = model_.is_process_suspended() ? model_.resume_process() : model_.suspend_process();
            Log().info("{}", st.detail);
        }
        if (ImGui::MenuItem(model_.is_crash_dump() ? "Close Crash Dump" : "Detach from Process",
                            nullptr,
                            false,
                            model_.is_live_process())) {
            model_.detach_process();
            on_file_loaded();
            Log().info("{}", model_.is_crash_dump() ? "Closed crash dump" : "Detached from live process");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Open Debug Symbols...", nullptr, false, model_.image() != nullptr)) {
            if (on_open_debug_symbols_) { on_open_debug_symbols_(); }
        }
        if (ImGui::MenuItem("Save Patched As...",
                            nullptr,
                            false,
                            !model_.is_live_process() && model_.editable_image() != nullptr)) {
            if (on_save_patched_as_) { on_save_patched_as_(); }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) {
            if (on_exit_) on_exit_();
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Edit")) {
        const auto* image = model_.editable_image();
        if (ImGui::MenuItem("Undo patch", nullptr, false, !model_.is_live_process() && image && image->can_undo())) {
            if (auto result = model_.undo_patch(); !result) Log().error("{}", result.error().message);
        }
        if (ImGui::MenuItem("Redo patch", nullptr, false, !model_.is_live_process() && image && image->can_redo())) {
            if (auto result = model_.redo_patch(); !result) Log().error("{}", result.error().message);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Memory Search", nullptr, false, model_.has_file())) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Patch workspace", nullptr, false, !model_.is_live_process())) patch_set_panel_.set_visible(true);
        if (ImGui::MenuItem("Byte input workspace", nullptr, false, !model_.is_live_process())) shellcode_panel_.set_visible(true);
        if (ImGui::MenuItem("Scripting console")) {
            scripting_panel_.set_visible(true);
            activate_panel(scripting_panel_.name().c_str());
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Navigate")) {
        if (ImGui::MenuItem("Command Palette / Omni-Search...", "Ctrl+K")) {
            open_command_palette();
        }
        if (ImGui::MenuItem("Go to Address / Expression...", "Ctrl+G")) {
            open_command_palette(":");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Back", "Alt+Left", false, navigation_history_.can_back())) navigate_history(false);
        if (ImGui::MenuItem("Forward", "Alt+Right", false, navigation_history_.can_forward())) navigate_history(true);
        ImGui::Separator();
        if (ImGui::MenuItem("Entry point", nullptr, false, model_.image() != nullptr)) {
            const auto* image = model_.image();
            navigate_to_address(image->entry_point());
        }
        if (ImGui::MenuItem("Functions")) {
            functions_panel_.set_visible(true);
            activate_panel(functions_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Symbols")) symbols_panel_.set_visible(true);
        if (ImGui::MenuItem("Strings", nullptr, false, model_.has_file())) open_strings();
        if (ImGui::MenuItem("Threads & Stack", nullptr, false, model_.is_live_process())) {
            threads_panel_.set_visible(true);
            activate_panel(threads_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Thread Locals", nullptr, false, model_.has_file())) {
            thread_locals_panel_.set_visible(true);
            activate_panel(thread_locals_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Memory Search", nullptr, false, model_.has_file())) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (ImGui::MenuItem("PEB / TEB & Flags", nullptr, false, model_.has_file())) {
            runtime_flags_panel_.set_visible(true);
            activate_panel(runtime_flags_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Handlers (VEH / SEH / atexit)", nullptr, false, model_.has_file())) {
            handlers_panel_.set_visible(true);
            activate_panel(handlers_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Process Internals (Handles / Sockets / Security)",
                            nullptr,
                            false,
                            model_.is_live_process())) {
            process_internals_panel_.set_visible(true);
            activate_panel(process_internals_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Execution Timeline")) {
            timeline_panel_.set_visible(true);
            activate_panel(timeline_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Memory Heatmap")) {
            memory_heatmap_panel_.set_visible(true);
            activate_panel(memory_heatmap_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Entropy & Digram")) {
            byte_viz_panel_.set_visible(true);
            activate_panel(byte_viz_panel_.name().c_str());
        }
        if (ImGui::MenuItem("References & Notes", "X", false, model_.has_file())) open_references();
        if (ImGui::MenuItem("Bookmark selection", "Ctrl+B", false, model_.has_file())) {
            toggle_bookmark_at_selection();
        }
        if (ImGui::MenuItem("Decompile selection", "F5", false, model_.has_file())) request_decompile();
        if (ImGui::MenuItem("Structure")) structure_panel_.set_visible(true);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Analyze")) {
        ImGui::MenuItem("Disassembly", nullptr, &show_disassembly_panel_);
        ImGui::MenuItem("Call graph", nullptr, &show_call_graph_panel_);
        if (ImGui::MenuItem("Rebuild loaded call graph", nullptr, false, model_.has_file())) queue_call_graph_sample(CallGraphSample::LoadedImage);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Inspect")) {
        if (ImGui::MenuItem("Start / Attach Debugger (Opt-in)...")) {
            debugger_panel_.set_visible(true);
            activate_panel(debugger_panel_.name().c_str());
            debugger_panel_.open_opt_in_modal();
        }
        if (ImGui::MenuItem("Attach to Process (Read-Only Default)...", "Ctrl+P")) {
            open_attach_process_modal();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Connect GDB Remote / QEMU (Read-Only)...")) {
            open_gdb_remote_modal(false);
        }
        if (ImGui::MenuItem("Connect GDB Remote Debugger (Opt-in)...")) {
            open_gdb_remote_modal(true);
        }
        ImGui::Separator();
        auto* dbg = model_.debug_session();
        const bool dbg_paused = dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Paused;
        const bool dbg_running = dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Running;
        if (ImGui::MenuItem("Continue", "F5", false, dbg_paused)) {
            (void)dbg->continue_execution(false);
        }
        if (ImGui::MenuItem("Pause", nullptr, false, dbg_running)) {
            (void)dbg->pause_execution();
        }
        if (ImGui::MenuItem("Step Into", "F11", false, dbg_paused)) {
            (void)dbg->step_into(model_.selected_thread_id());
        }
        if (ImGui::MenuItem("Step Over", "F10", false, dbg_paused)) {
            (void)dbg->step_over(model_.selected_thread_id());
        }
        if (ImGui::MenuItem("Step Out", "Shift+F11", false, dbg_paused)) {
            (void)dbg->step_out(model_.selected_thread_id());
        }
        if (ImGui::MenuItem("Toggle Breakpoint at Selection",
                            "F9",
                            false,
                            dbg_paused && current_selection_.virtual_address.has_value())) {
            (void)model_.toggle_software_breakpoint(*current_selection_.virtual_address);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Detach Debugger Cleanly", nullptr, false, dbg_paused || dbg_running)) {
            model_.cancel_and_join_workers();
            if (auto r = dbg->detach(); !r.has_value()) {
                model_.refresh_debug_breakpoints();
                Log().error("Detach failed (target remains attached): {}", r.error().message);
            } else {
                model_.detach_process();
                on_file_loaded();
            }
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        if (ImGui::BeginMenu("Workspaces")) {
            for (const WorkspacePreset preset : kAllWorkspacePresets) {
                const std::string label(workspace_preset_display_name(preset));
                const bool is_active = (active_workspace_preset_ == preset);
                if (ImGui::MenuItem(label.c_str(), nullptr, is_active)) {
                    request_workspace_preset(preset);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Reset Current Workspace Layout")) {
                request_workspace_reset();
            }
            ImGui::EndMenu();
        }
        ImGui::Separator();
        ImGui::MenuItem("Data Structures", nullptr, &show_data_types_);
        {
            bool demangle = model_.demangle_symbols();
            if (ImGui::MenuItem("Demangle symbols", nullptr, &demangle)) {
                model_.set_demangle_symbols(demangle);
                ++symbol_revision_;
            }
        }
        if (ImGui::MenuItem("Reset Layout")) {
            request_workspace_reset();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Reload theme")) ui::load_theme();
        if (ImGui::BeginMenu("Interface scale")) {
            for (const float scale : {1.0f, 1.25f, 1.5f, 2.0f}) {
                const auto label = std::format("{:.0f}%", scale * 100);
                if (ImGui::MenuItem(label.c_str(), nullptr, ImGui::GetStyle().FontScaleMain == scale))
                    ImGui::GetStyle().FontScaleMain = scale;
            }
            ImGui::EndMenu();
        }

        {
            bool v = file_panel_.visible();
            if (ImGui::MenuItem(file_panel_.name().c_str(), nullptr, &v))
                file_panel_.set_visible(v);
        }

        {
            bool v = memory_map_panel_.visible();
            if (ImGui::MenuItem(memory_map_panel_.name().c_str(), nullptr, &v))
                memory_map_panel_.set_visible(v);
        }

        {
            bool v = memory_heatmap_panel_.visible();
            if (ImGui::MenuItem(memory_heatmap_panel_.name().c_str(), nullptr, &v))
                memory_heatmap_panel_.set_visible(v);
        }

        {
            bool v = byte_viz_panel_.visible();
            if (ImGui::MenuItem(byte_viz_panel_.name().c_str(), nullptr, &v))
                byte_viz_panel_.set_visible(v);
        }

        {
            bool v = structure_panel_.visible();
            if (ImGui::MenuItem(structure_panel_.name().c_str(), nullptr, &v))
                structure_panel_.set_visible(v);
        }

        {
            bool v = details_panel_.visible();
            if (ImGui::MenuItem(details_panel_.name().c_str(), nullptr, &v))
                details_panel_.set_visible(v);
        }

        {
            bool v = sections_panel_.visible();
            if (ImGui::MenuItem(sections_panel_.name().c_str(), nullptr, &v))
                sections_panel_.set_visible(v);
        }

        {
            bool v = hex_panel_.visible();
            if (ImGui::MenuItem(hex_panel_.name().c_str(), nullptr, &v))
                hex_panel_.set_visible(v);
        }

        {
            bool v = patch_set_panel_.visible();
            if (ImGui::MenuItem(patch_set_panel_.name().c_str(), nullptr, &v))
                patch_set_panel_.set_visible(v);
        }

        {
            bool v = shellcode_panel_.visible();
            if (ImGui::MenuItem(shellcode_panel_.name().c_str(), nullptr, &v))
                shellcode_panel_.set_visible(v);
        }

        {
            bool v = imports_panel_.visible();
            if (ImGui::MenuItem(imports_panel_.name().c_str(), nullptr, &v))
                imports_panel_.set_visible(v);
        }

        {
            bool v = exports_panel_.visible();
            if (ImGui::MenuItem(exports_panel_.name().c_str(), nullptr, &v))
                exports_panel_.set_visible(v);
        }

        {
            bool v = symbols_panel_.visible();
            if (ImGui::MenuItem(symbols_panel_.name().c_str(), nullptr, &v))
                symbols_panel_.set_visible(v);
        }

        for (UiPanel* extra : {static_cast<UiPanel*>(&capabilities_panel_),
                               static_cast<UiPanel*>(&executable_settings_panel_),
                               static_cast<UiPanel*>(&timeline_panel_),
                               static_cast<UiPanel*>(&scripting_panel_),
                               static_cast<UiPanel*>(&debugger_panel_),
                               static_cast<UiPanel*>(&binary_diff_panel_),
                               static_cast<UiPanel*>(&dependencies_panel_),
                               static_cast<UiPanel*>(&functions_panel_),
                               static_cast<UiPanel*>(&strings_panel_),
                               static_cast<UiPanel*>(&signatures_panel_),
                               static_cast<UiPanel*>(&struct_view_panel_),
                               static_cast<UiPanel*>(&references_panel_),
                               static_cast<UiPanel*>(&threads_panel_),
                               static_cast<UiPanel*>(&thread_locals_panel_),
                               static_cast<UiPanel*>(&memory_search_panel_),
                               static_cast<UiPanel*>(&runtime_flags_panel_),
                               static_cast<UiPanel*>(&handlers_panel_),
                               static_cast<UiPanel*>(&process_internals_panel_)}) {
            bool v = extra->visible();
            if (ImGui::MenuItem(extra->name().c_str(), nullptr, &v)) {
                extra->set_visible(v);
            }
        }

        {
            bool v = pe_headers_panel_.visible();
            if (ImGui::MenuItem(pe_headers_panel_.name().c_str(), nullptr, &v))
                pe_headers_panel_.set_visible(v);
        }

        {
            bool v = pe_imports_panel_.visible();
            if (ImGui::MenuItem(pe_imports_panel_.name().c_str(), nullptr, &v))
                pe_imports_panel_.set_visible(v);
        }

        {
            bool v = pe_exports_panel_.visible();
            if (ImGui::MenuItem(pe_exports_panel_.name().c_str(), nullptr, &v))
                pe_exports_panel_.set_visible(v);
        }

        {
            ImGui::MenuItem("Disassembly", nullptr, &show_disassembly_panel_);
        }

        {
            ImGui::MenuItem("Flow Graph", nullptr, &show_call_graph_panel_);
        }

        {
            ImGui::MenuItem("Decompiler", nullptr, &show_decompiler_);
        }

        {
            bool v = log_panel_.visible();
            if (ImGui::MenuItem(log_panel_.name().c_str(), nullptr, &v))
                log_panel_.set_visible(v);
        }

        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About PE/ELF Explorer")) show_about_ = true;
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
    if (show_about_) {
        ImGui::OpenPopup("About PE/ELF Explorer");
        show_about_ = false;
    }
    if (ImGui::BeginPopupModal("About PE/ELF Explorer", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("PE/ELF Explorer v" PEELF_VERSION_STRING);
        ImGui::Separator();
        ImGui::TextUnformatted("Inspect binaries, resolve symbols, and stage byte patches.");
        ImGui::Spacing();
        ImGui::TextDisabled("Ctrl+O  Open binary    |    Ctrl+Shift+S  Export patched copy");
        ImGui::TextDisabled("Theme: resources/theme.ini  |  View > Reload theme");
        ImGui::Spacing();
        if (ImGui::Button("Close", ImVec2(100, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void UiApp::render_dockspace() {
    register_workspace_settings_handler();

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("MainDockSpaceHost", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    const ImGuiID dockspace_id = ImGui::GetID("AnalysisWorkspaceV12");
    const ImGuiDockNodeFlags dock_flags = ImGuiDockNodeFlags_None;
    const bool compact = viewport->WorkSize.x < ImGui::GetFontSize() * 100.0f;
    const bool missing_dockspace = (ImGui::DockBuilderGetNode(dockspace_id) == nullptr);

    bool needs_migration = false;
    if (!workspace_layout_checked_) {
        workspace_layout_checked_ = true;
        if (g_workspace_ini_state.saw_ini_section) {
            loaded_layout_schema_version_ = g_workspace_ini_state.loaded_schema_version;
            active_workspace_preset_ = g_workspace_ini_state.active_preset;
        }
        if (should_migrate_workspace_layout(loaded_layout_schema_version_)) {
            needs_migration = true;
            Log().info(
                "Migrating workspace layout from schema v{} to v{} ({})",
                loaded_layout_schema_version_,
                kWorkspaceLayoutSchemaVersion,
                workspace_preset_display_name(active_workspace_preset_));
        }
    }

    if (pending_workspace_preset_.has_value() || reset_dock_layout_ || missing_dockspace ||
        needs_migration || (compact_dock_layout_ && *compact_dock_layout_ != compact)) {
        const WorkspacePreset target_preset =
            pending_workspace_preset_.value_or(active_workspace_preset_);
        pending_workspace_preset_.reset();
        reset_dock_layout_ = false;
        apply_workspace_preset(target_preset, dockspace_id, viewport->WorkSize);
    }
    compact_dock_layout_ = compact;
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dock_flags);

    ImGui::End();
}

void UiApp::apply_workspace_preset(
    WorkspacePreset preset,
    ImGuiID dockspace_id,
    const ImVec2& dockspace_size) {
    WorkspacePresetSpec spec = build_workspace_preset(preset);
    if (const auto validation = validate_workspace_preset(spec); !validation) {
        Log().error("Invalid workspace preset '{}': {}", spec.display_name, validation.error().message);
        spec = build_workspace_preset(WorkspacePreset::StaticReverseEngineering);
        preset = WorkspacePreset::StaticReverseEngineering;
    }

    active_workspace_preset_ = preset;
    loaded_layout_schema_version_ = spec.schema_version;
    g_workspace_ini_state.active_preset = preset;
    g_workspace_ini_state.loaded_schema_version = spec.schema_version;
    g_workspace_ini_state.saw_ini_section = true;

    std::unordered_set<WorkspacePanelId> visible_set;
    visible_set.reserve(spec.visible_panels.size());
    for (const WorkspacePanelId panel : spec.visible_panels) {
        visible_set.insert(panel);
    }
    for (const WorkspacePanelId panel : all_workspace_panels()) {
        set_workspace_panel_visible(panel, visible_set.contains(panel));
    }

    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

    std::vector<WorkspacePanelId> active_tabs;
    ImGuiID fallback_leaf_id = 0;
    build_imgui_dock_subtree(spec.root, dockspace_id, active_tabs, fallback_leaf_id);

    if (fallback_leaf_id != 0) {
        for (const WorkspacePanelId panel : all_workspace_panels()) {
            if (!visible_set.contains(panel)) {
                const std::string title(workspace_panel_window_name(panel));
                ImGui::DockBuilderDockWindow(title.c_str(), fallback_leaf_id);
            }
        }
    }

    ImGui::DockBuilderFinish(dockspace_id);
    ImGui::MarkIniSettingsDirty();

    pending_preset_active_tabs_ = std::move(active_tabs);
    focus_workspace_ = false;
}

void UiApp::build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size) {
    apply_workspace_preset(WorkspacePreset::StaticReverseEngineering, dockspace_id, dockspace_size);
}

namespace {

int command_palette_input_callback(ImGuiInputTextCallbackData* /*data*/) {
    // Consume history callback so Up/Down arrow keys move list selection without clearing InputText.
    return 0;
}

[[nodiscard]] ImVec4 palette_category_badge_color(PaletteCategory cat) noexcept {
    switch (cat) {
        case PaletteCategory::GoTo:     return ImVec4(0.22f, 0.56f, 0.36f, 0.95f);
        case PaletteCategory::Command:  return ImVec4(0.24f, 0.44f, 0.68f, 0.95f);
        case PaletteCategory::Panel:    return ImVec4(0.30f, 0.38f, 0.54f, 0.95f);
        case PaletteCategory::Preset:   return ImVec4(0.46f, 0.34f, 0.64f, 0.95f);
        case PaletteCategory::Function: return ImVec4(0.62f, 0.42f, 0.18f, 0.95f);
        case PaletteCategory::Symbol:   return ImVec4(0.52f, 0.46f, 0.22f, 0.95f);
        case PaletteCategory::String:   return ImVec4(0.20f, 0.52f, 0.52f, 0.95f);
        case PaletteCategory::Type:     return ImVec4(0.54f, 0.28f, 0.48f, 0.95f);
        case PaletteCategory::Bookmark: return ImVec4(0.64f, 0.48f, 0.16f, 0.95f);
        case PaletteCategory::Rule:     return ImVec4(0.66f, 0.26f, 0.26f, 0.95f);
    }
    return ImVec4(0.30f, 0.38f, 0.54f, 0.95f);
}

void render_highlighted_palette_title(
    std::string_view title,
    std::span<const FuzzyMatchSpan> spans,
    bool enabled) {
    const ImVec4 normal_col = enabled
                                  ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                  : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    const ImVec4 match_col = enabled
                                 ? ImVec4(0.98f, 0.82f, 0.32f, 1.0f)
                                 : ImVec4(0.72f, 0.62f, 0.32f, 0.85f);

    if (spans.empty() || title.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, normal_col);
        ImGui::TextUnformatted(title.data(), title.data() + title.size());
        ImGui::PopStyleColor();
        return;
    }

    std::size_t cursor = 0u;
    bool first_piece = true;
    for (const FuzzyMatchSpan span : spans) {
        const std::size_t start = std::min<std::size_t>(span.offset, title.size());
        const std::size_t end =
            std::min<std::size_t>(start + static_cast<std::size_t>(span.length), title.size());
        if (start > cursor) {
            if (!first_piece) {
                ImGui::SameLine(0.0f, 0.0f);
            }
            ImGui::PushStyleColor(ImGuiCol_Text, normal_col);
            ImGui::TextUnformatted(title.data() + cursor, title.data() + start);
            ImGui::PopStyleColor();
            first_piece = false;
        }
        if (end > start) {
            if (!first_piece) {
                ImGui::SameLine(0.0f, 0.0f);
            }
            ImGui::PushStyleColor(ImGuiCol_Text, match_col);
            ImGui::TextUnformatted(title.data() + start, title.data() + end);
            ImGui::PopStyleColor();
            first_piece = false;
            cursor = end;
        }
    }
    if (cursor < title.size()) {
        if (!first_piece) {
            ImGui::SameLine(0.0f, 0.0f);
        }
        ImGui::PushStyleColor(ImGuiCol_Text, normal_col);
        ImGui::TextUnformatted(title.data() + cursor, title.data() + title.size());
        ImGui::PopStyleColor();
    }
}

} // namespace

void UiApp::open_command_palette(std::string_view initial_query) {
    command_palette_query_buf_.fill('\0');
    if (!initial_query.empty()) {
        const std::size_t copy_len =
            std::min(initial_query.size(), command_palette_query_buf_.size() - 1u);
        std::copy_n(initial_query.data(), copy_len, command_palette_query_buf_.data());
    }
    command_palette_last_query_.assign(command_palette_query_buf_.data());
    command_palette_selected_idx_ = 0u;
    command_palette_scroll_to_selection_ = true;
    open_command_palette_next_frame_ = true;
    command_palette_focus_input_ = true;
}

void UiApp::enqueue_palette_action(const PaletteAction& action) {
    if (!action.valid()) {
        return;
    }
    if (auto nav_req = build_palette_navigation_request(action); nav_req.has_value()) {
        pending_navigations_.enqueue(std::move(*nav_req));
        return;
    }

    switch (action.kind) {
        case PaletteActionKind::FocusPanel: {
            const WorkspacePanelId panel = action.panel_id;
            pending_navigations_.enqueue_custom([this, panel]() {
                if (panel == WorkspacePanelId::Strings && model_.has_file()) {
                    open_strings();
                    return;
                }
                if (panel == WorkspacePanelId::ReferencesAndNotes && model_.has_file()) {
                    open_references();
                    return;
                }
                set_workspace_panel_visible(panel, true);
                const std::string wname(workspace_panel_window_name(panel));
                activate_panel(wname.c_str());
            });
            break;
        }
        case PaletteActionKind::TogglePanel: {
            const WorkspacePanelId panel = action.panel_id;
            pending_navigations_.enqueue_custom([this, panel]() {
                const bool next = !is_workspace_panel_visible(panel);
                set_workspace_panel_visible(panel, next);
                if (next) {
                    const std::string wname(workspace_panel_window_name(panel));
                    activate_panel(wname.c_str());
                }
            });
            break;
        }
        case PaletteActionKind::ApplyWorkspacePreset: {
            const WorkspacePreset preset = action.preset;
            pending_navigations_.enqueue_custom([this, preset]() {
                request_workspace_preset(preset);
            });
            break;
        }
        case PaletteActionKind::OpenStructureView: {
            const std::string type_name = action.type_name;
            pending_navigations_.enqueue_custom([this, type_name]() {
                open_structure_view(type_name);
            });
            break;
        }
        case PaletteActionKind::RunCommand: {
            const PaletteCommandId cmd = action.command_id;
            pending_navigations_.enqueue_custom([this, cmd]() {
                switch (cmd) {
                    case PaletteCommandId::OpenBinary:
                        if (on_open_file_) {
                            on_open_file_();
                        }
                        break;
                    case PaletteCommandId::AttachToProcess:
                        open_attach_process_modal();
                        break;
                    case PaletteCommandId::ConnectGdbRemote:
                        open_gdb_remote_modal(false);
                        break;
                    case PaletteCommandId::OpenCrashDump:
                        if (on_analysis_file_) {
                            on_analysis_file_(4);
                        }
                        break;
                    case PaletteCommandId::OpenDebugSymbols:
                        if (model_.image() != nullptr && on_open_debug_symbols_) {
                            on_open_debug_symbols_();
                        }
                        break;
                    case PaletteCommandId::SaveProject:
                        if (model_.has_file() && on_analysis_file_) {
                            on_analysis_file_(1);
                        }
                        break;
                    case PaletteCommandId::SavePatchedAs:
                        if (!model_.is_live_process() && model_.editable_image() != nullptr &&
                            on_save_patched_as_) {
                            on_save_patched_as_();
                        }
                        break;
                    case PaletteCommandId::DecompileCurrentFunction:
                        if (model_.has_file()) {
                            request_decompile();
                        }
                        break;
                    case PaletteCommandId::ScanFullReferences:
                        if (model_.has_file()) {
                            open_references();
                            if (reference_scanner_.has_resumable_work()) {
                                reference_scanner_.scan_full(reference_index_);
                            } else if (const auto* image = model_.image()) {
                                std::vector<std::uint8_t> snapshot;
                                if (model_.changed_intervals().empty()) {
                                    const auto span = model_.analysis_image_bytes();
                                    snapshot.assign(span.begin(), span.end());
                                } else if (auto patched =
                                               model_.read_effective_bytes(0, model_.bytes().size())) {
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
                        }
                        break;
                    case PaletteCommandId::ToggleDemangleSymbols:
                        model_.set_demangle_symbols(!model_.demangle_symbols());
                        ++symbol_revision_;
                        break;
                    case PaletteCommandId::SwitchFlowGraphGalaxy:
                        show_call_graph_panel_ = true;
                        call_galaxy_.enabled = !call_galaxy_.enabled;
                        if (call_galaxy_.enabled) {
                            call_galaxy_.dirty = true;
                            call_galaxy_.fit_requested = true;
                        }
                        activate_panel("Flow Graph");
                        break;
                    case PaletteCommandId::ResetWorkspaceLayout:
                        request_workspace_reset();
                        break;
                    case PaletteCommandId::GoToEntryPoint:
                        if (model_.image() != nullptr) {
                            navigate_to_address(model_.image()->entry_point());
                        }
                        break;
                    case PaletteCommandId::GoToAddressPrompt:
                        open_command_palette(":");
                        break;
                    case PaletteCommandId::DefineCustomCTypes:
                        open_structure_view();
                        struct_view_panel_.open_custom_c_editor();
                        break;
                }
            });
            break;
        }
        case PaletteActionKind::None:
        case PaletteActionKind::NavigateAddress:
        case PaletteActionKind::NavigateFileOffset:
            break;
    }
}

void UiApp::render_command_palette_overlay() {
    if (open_command_palette_next_frame_) {
        ImGui::OpenPopup("##CommandPalettePopup");
        open_command_palette_next_frame_ = false;
    }

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float palette_width =
        std::clamp(viewport->WorkSize.x * 0.56f, 520.0f, 880.0f);
    const ImVec2 popup_pos(
        viewport->WorkPos.x + (viewport->WorkSize.x - palette_width) * 0.5f,
        viewport->WorkPos.y + viewport->WorkSize.y * 0.08f);

    ImGui::SetNextWindowPos(popup_pos, ImGuiCond_Always);
    ImGui::SetNextWindowSizeConstraints(
        ImVec2(palette_width, 160.0f),
        ImVec2(palette_width, std::max(320.0f, viewport->WorkSize.y * 0.68f)));

    const ImGuiWindowFlags popup_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_AlwaysAutoResize;

    if (!ImGui::BeginPopup("##CommandPalettePopup", popup_flags)) {
        return;
    }

    const std::string_view current_raw_query(command_palette_query_buf_.data());
    const ParsedPaletteQuery parsed_preview = parse_palette_query(current_raw_query);

    // Lazily populate strings index when user explicitly searches `#` Strings on a static file.
    if (strings_dirty_ && model_.has_file() && !model_.is_live_process() &&
        (parsed_preview.mode == PalettePrefixMode::Strings ||
         (parsed_preview.mode == PalettePrefixMode::Omni && !parsed_preview.filter.empty()))) {
        rebuild_strings();
    }

    // Merge UI debug types with BinaryModel debug types if both are populated.
    std::vector<DataTypeRecord> merged_types{};
    std::span<const DataTypeRecord> effective_debug_types = debug_types_;
    if (effective_debug_types.empty()) {
        effective_debug_types = model_.debug_types();
    } else if (!model_.debug_types().empty()) {
        merged_types.reserve(debug_types_.size() + model_.debug_types().size());
        merged_types.insert(merged_types.end(), debug_types_.begin(), debug_types_.end());
        merged_types.insert(
            merged_types.end(), model_.debug_types().begin(), model_.debug_types().end());
        effective_debug_types = merged_types;
    }

    PaletteDataSources sources = make_palette_data_sources(
        model_,
        &symbol_index_,
        &annotations_,
        &strings_index_,
        effective_debug_types,
        decompiled_.types);
    sources.active_preset = active_workspace_preset_;
    sources.flow_galaxy_enabled = call_galaxy_.enabled;
    sources.has_panel_visibility = true;
    for (const WorkspacePanelId panel : all_workspace_panels()) {
        sources.panel_visibility[static_cast<std::size_t>(panel)] =
            is_workspace_panel_visible(panel);
    }

    // Search Input Bar
    if (command_palette_focus_input_) {
        ImGui::SetKeyboardFocusHere();
        command_palette_focus_input_ = false;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint(
        "##CommandPaletteSearchInput",
        "Omni-search commands (>), symbols (@), strings (#), types (type:), rules (?), or expression (:main+0x20)...",
        command_palette_query_buf_.data(),
        command_palette_query_buf_.size(),
        ImGuiInputTextFlags_CallbackHistory,
        command_palette_input_callback);

    const std::string_view updated_query(command_palette_query_buf_.data());
    if (updated_query != command_palette_last_query_) {
        command_palette_last_query_.assign(updated_query);
        command_palette_selected_idx_ = 0u;
        command_palette_scroll_to_selection_ = true;
    }

    // Prefix Shortcut Hint Bar (`>?@#`)
    {
        const auto set_prefix = [this](std::string_view pfx) {
            command_palette_query_buf_.fill('\0');
            std::copy_n(pfx.data(), pfx.size(), command_palette_query_buf_.data());
            command_palette_last_query_.assign(pfx);
            command_palette_selected_idx_ = 0u;
            command_palette_scroll_to_selection_ = true;
            command_palette_focus_input_ = true;
        };
        ImGui::TextDisabled("Mode:");
        ImGui::SameLine(0.0f, 6.0f);
        if (ImGui::SmallButton("All")) set_prefix("");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton("> Commands")) set_prefix(">");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton("@ Symbols")) set_prefix("@");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton("# Strings")) set_prefix("#");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton(": GoTo Expr")) set_prefix(":");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton("type: Structs")) set_prefix("type:");
        ImGui::SameLine(0.0f, 4.0f);
        if (ImGui::SmallButton("? Rules/Marks")) set_prefix("?");
    }

    const PaletteQueryResult result = command_palette_.query(updated_query, sources);
    if (command_palette_selected_idx_ >= result.items.size()) {
        command_palette_selected_idx_ =
            result.items.empty() ? 0u : (result.items.size() - 1u);
    }

    // Keyboard Handling (`Up`/`Down`, `Ctrl+P`/`Ctrl+N`, `Enter`/`Shift+Enter`/`Ctrl+Enter`, `Esc`)
    const ImGuiIO& io = ImGui::GetIO();
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    const bool move_down =
        ImGui::IsKeyPressed(ImGuiKey_DownArrow) ||
        (io.KeyCtrl && !io.KeyShift && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_N));
    const bool move_up =
        ImGui::IsKeyPressed(ImGuiKey_UpArrow) ||
        (io.KeyCtrl && !io.KeyShift && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_P));

    if (!result.items.empty()) {
        if (move_down) {
            command_palette_selected_idx_ =
                (command_palette_selected_idx_ + 1u) % result.items.size();
            command_palette_scroll_to_selection_ = true;
        } else if (move_up) {
            command_palette_selected_idx_ =
                (command_palette_selected_idx_ == 0u)
                    ? (result.items.size() - 1u)
                    : (command_palette_selected_idx_ - 1u);
            command_palette_scroll_to_selection_ = true;
        }
    }

    bool should_close = false;
    const auto trigger_item = [&](const PaletteItem& item, bool force_hex, bool force_decompile) {
        if (!item.enabled) {
            return;
        }
        command_palette_.record_execution(item.id);
        if (item.primary_action.kind == PaletteActionKind::RunCommand &&
            item.primary_action.command_id == PaletteCommandId::GoToAddressPrompt) {
            open_command_palette(":");
            open_command_palette_next_frame_ = false;
            return;
        }
        if (force_decompile && item.tertiary_decompile_action.valid()) {
            enqueue_palette_action(item.tertiary_decompile_action);
        } else if (force_hex && item.secondary_hex_action.valid()) {
            enqueue_palette_action(item.secondary_hex_action);
        } else {
            enqueue_palette_action(item.primary_action);
        }
        should_close = true;
    };

    const bool enter_pressed =
        ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
        ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
    if (enter_pressed && command_palette_selected_idx_ < result.items.size()) {
        trigger_item(
            result.items[command_palette_selected_idx_],
            io.KeyShift,
            io.KeyCtrl);
    }

    ImGui::Separator();

    if (!result.expression_error.empty()) {
        ImGui::TextColored(
            ImVec4(0.95f, 0.48f, 0.40f, 1.0f),
            "Expression: %s",
            result.expression_error.c_str());
    } else if (result.resolved_expression.has_value()) {
        ImGui::TextColored(
            ImVec4(0.48f, 0.88f, 0.62f, 1.0f),
            "Resolved: %s",
            result.resolved_expression->canonical_summary.c_str());
    }

    // Results List
    const float row_height = ImGui::GetTextLineHeightWithSpacing() * 2.05f + 4.0f;
    const float list_height = std::clamp(
        static_cast<float>(std::max<std::size_t>(1u, result.items.size())) * row_height + 8.0f,
        72.0f,
        std::max(220.0f, viewport->WorkSize.y * 0.48f));

    if (ImGui::BeginChild(
            "##CommandPaletteResults",
            ImVec2(palette_width - ImGui::GetStyle().WindowPadding.x * 2.0f, list_height),
            ImGuiChildFlags_Borders)) {
        if (result.items.empty()) {
            ImGui::Spacing();
            ImGui::TextDisabled(
                "%s",
                result.parsed_query.mode == PalettePrefixMode::GoToAddress
                    ? "Type a VA, rva:0x1000, off:0x400, $entry, .text+0x20, or symbol+offset..."
                    : "No matching commands, symbols, strings, types, or rules.");
        }

        for (std::size_t i = 0u; i < result.items.size(); ++i) {
            const PaletteItem& item = result.items[i];
            const bool is_selected = (i == command_palette_selected_idx_);
            ImGui::PushID(static_cast<int>(i));

            const ImVec2 row_start = ImGui::GetCursorPos();
            if (ImGui::Selectable(
                    "##PaletteRow",
                    is_selected,
                    ImGuiSelectableFlags_AllowOverlap,
                    ImVec2(0.0f, row_height - 2.0f))) {
                command_palette_selected_idx_ = i;
                trigger_item(item, io.KeyShift, io.KeyCtrl);
            }
            if (is_selected && command_palette_scroll_to_selection_) {
                ImGui::SetScrollHereY(0.35f);
                command_palette_scroll_to_selection_ = false;
            }

            const float content_right = ImGui::GetContentRegionAvail().x + row_start.x;
            ImGui::SetCursorPos(ImVec2(row_start.x + 6.0f, row_start.y + 2.0f));

            // Category Badge
            const std::string_view cat_str = to_string(item.category);
            ImGui::PushStyleColor(ImGuiCol_Button, palette_category_badge_color(item.category));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, palette_category_badge_color(item.category));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, palette_category_badge_color(item.category));
            ImGui::SmallButton(std::string(cat_str).c_str());
            ImGui::PopStyleColor(3);

            ImGui::SameLine(0.0f, 8.0f);
            render_highlighted_palette_title(
                item.title, item.title_match.highlight_spans(), item.enabled);

            // Right-aligned VA/RVA/Shortcut Badge + quick Hex/Decompile buttons on selected row
            float right_cursor = content_right - 6.0f;
            if (is_selected && item.enabled) {
                if (item.tertiary_decompile_action.valid()) {
                    const float btn_w = ImGui::CalcTextSize("Decompile").x +
                                        ImGui::GetStyle().FramePadding.x * 2.0f;
                    right_cursor -= btn_w;
                    ImGui::SetCursorPos(ImVec2(right_cursor, row_start.y + 2.0f));
                    if (ImGui::SmallButton("Decompile")) {
                        trigger_item(item, false, true);
                    }
                    right_cursor -= 4.0f;
                }
                if (item.secondary_hex_action.valid() &&
                    item.secondary_hex_action.kind != PaletteActionKind::TogglePanel) {
                    const float btn_w = ImGui::CalcTextSize("Hex").x +
                                        ImGui::GetStyle().FramePadding.x * 2.0f;
                    right_cursor -= btn_w;
                    ImGui::SetCursorPos(ImVec2(right_cursor, row_start.y + 2.0f));
                    if (ImGui::SmallButton("Hex")) {
                        trigger_item(item, true, false);
                    }
                    right_cursor -= 6.0f;
                }
            }

            if (!item.right_badge.empty()) {
                const float badge_w = ImGui::CalcTextSize(item.right_badge.c_str()).x;
                if (right_cursor > row_start.x + badge_w + 120.0f) {
                    ImGui::SetCursorPos(ImVec2(right_cursor - badge_w, row_start.y + 3.0f));
                    ImGui::TextDisabled("%s", item.right_badge.c_str());
                }
            }

            // Subtitle provenance line
            ImGui::SetCursorPos(
                ImVec2(row_start.x + 10.0f,
                       row_start.y + ImGui::GetTextLineHeightWithSpacing() + 3.0f));
            ImGui::TextDisabled("%s", item.subtitle.c_str());

            ImGui::SetCursorPos(ImVec2(row_start.x, row_start.y + row_height));
            ImGui::PopID();
        }
    }
    ImGui::EndChild();

    ImGui::TextDisabled(
        "Enter: Open  |  Shift+Enter: Hex View  |  Ctrl+Enter: Decompile  |  Up/Down (Ctrl+P/N): Navigate  |  Esc: Close");

    if (should_close) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

} // namespace viewer
