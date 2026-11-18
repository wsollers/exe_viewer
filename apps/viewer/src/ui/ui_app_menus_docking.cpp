#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "analysis/project.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"
#include "theme.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

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
        case WorkspacePanelId::ReferencesAndNotes: references_panel_.set_visible(visible); break;
        case WorkspacePanelId::Strings:            strings_panel_.set_visible(visible); break;
        case WorkspacePanelId::StructureView:      struct_view_panel_.set_visible(visible); break;
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
        case WorkspacePanelId::ReferencesAndNotes: return references_panel_.visible();
        case WorkspacePanelId::Strings:            return strings_panel_.visible();
        case WorkspacePanelId::StructureView:      return struct_view_panel_.visible();
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
        ImGui::TextUnformatted("PE/ELF Explorer");
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

    const ImGuiID dockspace_id = ImGui::GetID("AnalysisWorkspaceV9");
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

} // namespace viewer
