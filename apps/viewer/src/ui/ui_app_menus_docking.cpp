#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "analysis/project.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"
#include "theme.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <filesystem>
#include <format>
#include <string>
#include <utility>

namespace viewer {
namespace {
using detail::activate_panel;
} // namespace

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
            (void)dbg->detach();
            model_.detach_process();
            on_process_attached();
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Data Structures", nullptr, &show_data_types_);
        {
            bool demangle = model_.demangle_symbols();
            if (ImGui::MenuItem("Demangle symbols", nullptr, &demangle)) {
                model_.set_demangle_symbols(demangle);
                ++symbol_revision_;
            }
        }
        if (ImGui::MenuItem("Reset Layout")) {
            reset_dock_layout_ = true;
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

        for (UiPanel* extra : {static_cast<UiPanel*>(&debugger_panel_),
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

    const ImGuiID dockspace_id = ImGui::GetID("AnalysisWorkspaceV7");
    const ImGuiDockNodeFlags dock_flags = ImGuiDockNodeFlags_None;
    const bool compact = viewport->WorkSize.x < ImGui::GetFontSize() * 100.0f;
    if (reset_dock_layout_ || ImGui::DockBuilderGetNode(dockspace_id) == nullptr ||
        (compact_dock_layout_ && *compact_dock_layout_ != compact)) {
        build_default_dock_layout(dockspace_id, viewport->WorkSize);
        reset_dock_layout_ = false;
    }
    compact_dock_layout_ = compact;
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dock_flags);

    ImGui::End();
}

void UiApp::build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size) {
    focus_workspace_ = true;
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

    ImGuiID main_id = dockspace_id;
    const bool compact = dockspace_size.x < ImGui::GetFontSize() * 100.0f;
    const ImGuiID bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.12f, nullptr, &main_id);
    const ImGuiID left_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Left, compact ? 0.25f : 0.19f, nullptr, &main_id);
    const ImGuiID right_id = compact ? left_id : ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Right, 0.25f, nullptr, &main_id);
    const ImGuiID center_bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.26f, nullptr, &main_id);

    ImGui::DockBuilderDockWindow(structure_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(memory_map_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(functions_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(symbols_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(sections_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow("Data Structures", left_id);

    ImGui::DockBuilderDockWindow(file_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(details_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(threads_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(thread_locals_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(runtime_flags_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(handlers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(references_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(strings_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(struct_view_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(process_internals_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(dependencies_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(exports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(patch_set_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_headers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_exports_panel_.name().c_str(), right_id);

    ImGui::DockBuilderDockWindow(hex_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow(debugger_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow(memory_search_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow(shellcode_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow("Disassembly", main_id);
    ImGui::DockBuilderDockWindow(binary_diff_panel_.name().c_str(), main_id);
    ImGui::DockBuilderDockWindow("Flow Graph", main_id);
    ImGui::DockBuilderDockWindow("Decompiler", right_id);
    if (auto* node = ImGui::DockBuilderGetNode(left_id)) node->SelectedTabId = ImHashStr(functions_panel_.name().c_str());
    if (auto* node = ImGui::DockBuilderGetNode(right_id)) node->SelectedTabId = ImHashStr(details_panel_.name().c_str());
    ImGui::DockBuilderDockWindow(log_panel_.name().c_str(), bottom_id);

    ImGui::DockBuilderFinish(dockspace_id);
}

} // namespace viewer
