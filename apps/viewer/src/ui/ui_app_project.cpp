#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "analysis/project.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"

#include <imgui.h>

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <filesystem>
#include <format>
#include <string>
#include <tuple>
#include <utility>

namespace viewer {
namespace {
using detail::activate_panel;
} // namespace

std::filesystem::path UiApp::active_recovery_key_path() const {
    if (!current_project_path_.empty()) {
        return current_project_path_;
    }
    if (!model_.is_live_process() && !model_.file_info().path.empty()) {
        return std::filesystem::path(model_.file_info().path);
    }
    return {};
}

void UiApp::mark_autosave_baseline() noexcept {
    last_autosave_revisions_ = {
        model_.edit_revision(),
        annotations_.revision(),
        model_.bookmark_revision(),
        model_.structure_binding_revision(),
    };
    last_autosave_check_ = std::chrono::steady_clock::now();
}

void UiApp::poll_project_autosave(bool force_now) {
    if (model_.is_live_process() || model_.image() == nullptr) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (!force_now && (now - last_autosave_check_) < std::chrono::seconds(2)) {
        return;
    }
    last_autosave_check_ = now;
    const auto current_revs = std::make_tuple(
        model_.edit_revision(),
        annotations_.revision(),
        model_.bookmark_revision(),
        model_.structure_binding_revision());
    if (current_revs == last_autosave_revisions_) {
        return;
    }
    const auto key = active_recovery_key_path();
    if (key.empty()) {
        return;
    }
    std::vector<DebugSymbol> debug_syms;
    for (const auto& s : symbol_index_.records()) {
        if (s.source == SymbolSource::DebugSymbol && s.virtual_address) {
            debug_syms.push_back({
                s.name,
                *s.virtual_address >= model_.image()->image_base()
                    ? *s.virtual_address - model_.image()->image_base()
                    : 0,
                *s.virtual_address,
                s.size,
                s.function.value_or(false),
            });
        }
    }
    std::size_t layout_size = 0;
    const char* layout_ptr = ImGui::GetCurrentContext() ? ImGui::SaveIniSettingsToMemory(&layout_size) : nullptr;
    std::string layout_str = layout_ptr ? std::string(layout_ptr, layout_size) : std::string{};
    layout_str = stamp_workspace_layout_metadata(
        layout_str, active_workspace_preset_, kWorkspaceLayoutSchemaVersion);
    const AnalysisProject snapshot = build_analysis_project(
        model_,
        current_project_path_,
        annotations_.records(),
        debug_syms,
        navigation_history_.entries(),
        navigation_history_.cursor(),
        std::move(layout_str),
        thumb_mode_);
    if (write_recovery_journal(snapshot, key)) {
        last_autosave_revisions_ = current_revs;
    }
}

void UiApp::apply_loaded_project_metadata(const AnalysisProject& project) {
    thumb_mode_ = project.thumb;
    if (model_.image() != nullptr && model_.image()->architecture() == peelf::Architecture::ARM) {
        disasm_.set_thumb_mode(thumb_mode_);
    }
    if (!project.symbols.empty()) {
        model_.add_debug_symbols(project.symbols);
    }
    model_.clear_bookmarks();
    for (const Bookmark& bm : project.bookmarks) {
        model_.add_or_update_bookmark(bm);
    }
    model_.clear_applied_structures();
    for (const AppliedStructureBinding& sb : project.structure_bindings) {
        model_.add_applied_structure(sb);
    }
    symbol_index_ = model_.symbol_index();
    annotations_.clear();
    for (const auto& [address, note] : project.annotations) {
        annotations_.set(address, note.name, note.comment);
    }
    navigation_history_.restore(project.history, project.cursor);
    if (!project.history.empty()) {
        current_selection_ = project.history[project.cursor];
        if (current_selection_.virtual_address) {
            auto selection = current_selection_;
            navigate_to_address(*selection.virtual_address, selection.preferred_view);
            current_selection_ = selection;
            last_navigation_selection_ = selection;
        } else {
            last_navigation_selection_.reset();
            apply_structure_selection_navigation();
        }
        navigation_history_.restore(project.history, project.cursor);
    }
    if (!project.layout.empty()) {
        const PersistedWorkspaceLayoutMetadata meta = parse_workspace_layout_metadata(project.layout);
        if (should_migrate_workspace_layout_ini(project.layout)) {
            active_workspace_preset_ = meta.active_preset;
            pending_workspace_preset_ = meta.active_preset;
            loaded_layout_schema_version_ = kWorkspaceLayoutSchemaVersion;
            Log().info(
                "Project layout schema v{} differs from v{}; migrating to '{}' workspace preset",
                meta.schema_version,
                kWorkspaceLayoutSchemaVersion,
                workspace_preset_display_name(meta.active_preset));
        } else {
            active_workspace_preset_ = meta.active_preset;
            loaded_layout_schema_version_ = meta.schema_version;
            if (ImGui::GetCurrentContext() != nullptr) {
                ImGui::LoadIniSettingsFromMemory(project.layout.c_str(), project.layout.size());
            }
        }
    }
    focus_workspace_ = false;
    references_dirty_ = true;
    strings_dirty_ = true;
}

peelf::Result<void> UiApp::save_project(const std::filesystem::path& path) {
    if (!model_.image()) return peelf::make_error("No binary loaded");
    std::error_code ec;
    if (std::filesystem::equivalent(path, model_.file_info().path, ec)) {
        return peelf::make_error("Project cannot replace the source binary");
    }
    navigation_history_.visit(current_selection_);
    std::vector<DebugSymbol> debug_syms;
    for (const auto& s : symbol_index_.records()) {
        if (s.source == SymbolSource::DebugSymbol && s.virtual_address) {
            debug_syms.push_back({
                s.name,
                *s.virtual_address >= model_.image()->image_base()
                    ? *s.virtual_address - model_.image()->image_base()
                    : 0,
                *s.virtual_address,
                s.size,
                s.function.value_or(false),
            });
        }
    }
    std::size_t size = 0;
    const char* layout = ImGui::GetCurrentContext() ? ImGui::SaveIniSettingsToMemory(&size) : nullptr;
    std::string layout_str = layout ? std::string(layout, size) : std::string{};
    layout_str = stamp_workspace_layout_metadata(
        layout_str, active_workspace_preset_, kWorkspaceLayoutSchemaVersion);
    const AnalysisProject project = build_analysis_project(
        model_,
        path,
        annotations_.records(),
        debug_syms,
        navigation_history_.entries(),
        navigation_history_.cursor(),
        std::move(layout_str),
        thumb_mode_);
    auto written = write_analysis_file(path, encode_project(project));
    if (written) {
        current_project_path_ = path;
        current_project_saved_ms_ = project.saved_unix_ms;
        clear_recovery_journal(path);
        if (!model_.file_info().path.empty()) {
            clear_recovery_journal(std::filesystem::path(model_.file_info().path));
        }
        pending_recovery_project_.reset();
        mark_autosave_baseline();
    }
    return written;
}

peelf::Result<void> UiApp::open_project(const std::filesystem::path& path,
                                        const std::filesystem::path& relocated_binary,
                                        bool allow_modified_binary,
                                        bool skip_mismatched_patches) {
    auto text = read_project_file(path);
    if (!text) return std::unexpected(text.error());
    auto project = decode_project(*text);
    if (!project) return std::unexpected(project.error());

    const ProjectBinaryResolution resolved =
        resolve_project_binary_path(*project, path, relocated_binary);
    if (resolved.status == ProjectBinaryMatchStatus::RelocationNeeded ||
        resolved.status == ProjectBinaryMatchStatus::ReadError ||
        (resolved.status == ProjectBinaryMatchStatus::ModifiedMismatch && !allow_modified_binary)) {
        pending_relocation_project_ = *project;
        pending_relocation_peproj_path_ = path;
        pending_relocation_resolution_ = resolved;
        relocate_modal_error_.clear();
        const std::string initial_path = !resolved.resolved_path.empty()
                                             ? resolved.resolved_path.string()
                                             : project->source;
        const std::size_t copy_len = std::min(sizeof(relocate_binary_buf_) - 1, initial_path.size());
        std::copy_n(initial_path.data(), copy_len, relocate_binary_buf_);
        relocate_binary_buf_[copy_len] = '\0';
        open_relocate_modal_next_frame_ = true;
        return peelf::make_error(resolved.diagnostic);
    }

    BinaryModel restored;
    if (!restored.load_file(resolved.resolved_path.string())) {
        return peelf::make_error("Cannot open project's source binary");
    }
    if (!skip_mismatched_patches) {
        auto patches = restore_project_patches(restored, *project, allow_modified_binary);
        if (!patches) return patches;
    } else if (!project->patches.empty()) {
        auto patches = restore_project_patches(restored, *project, true);
        if (!patches) {
            Log().warn("Skipped incompatible saved patches on modified binary: {}", patches.error().message);
        }
    }

    model_ = std::move(restored);
    on_file_loaded();
    current_project_path_ = path;
    current_project_saved_ms_ = project->saved_unix_ms;
    apply_loaded_project_metadata(*project);
    mark_autosave_baseline();

    if (auto recovery = check_newer_recovery_journal(path, project->saved_unix_ms)) {
        pending_recovery_project_ = std::move(*recovery);
        pending_recovery_key_path_ = path;
    }
    return {};
}

void UiApp::render_recovery_banner() {
    if (!pending_recovery_project_) {
        return;
    }
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (ImGui::BeginViewportSideBar("##recovery-banner",
                                    viewport,
                                    ImGuiDir_Up,
                                    ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2.0f,
                                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(
            ImVec4(1.0f, 0.80f, 0.30f, 1.0f),
            "Crash-recovery autosave found (%zu annotations, %zu bookmarks, %zu patches).",
            pending_recovery_project_->annotations.size(),
            pending_recovery_project_->bookmarks.size(),
            pending_recovery_project_->patches.size());
        ImGui::SameLine(0.0f, 16.0f);
        if (ImGui::Button("Restore Autosave")) {
            const AnalysisProject rec = *pending_recovery_project_;
            if (!rec.patches.empty() && model_.changed_intervals().empty()) {
                (void)restore_project_patches(model_, rec, true);
            }
            apply_loaded_project_metadata(rec);
            mark_autosave_baseline();
            pending_recovery_project_.reset();
            Log().info("Restored crash-recovery autosave session");
        }
        ImGui::SameLine();
        if (ImGui::Button("Discard Autosave")) {
            if (!pending_recovery_key_path_.empty()) {
                clear_recovery_journal(pending_recovery_key_path_);
            }
            pending_recovery_project_.reset();
        }
    }
    ImGui::End();
}

void UiApp::render_relocate_project_modal() {
    if (open_relocate_modal_next_frame_) {
        ImGui::OpenPopup("Relocate or Verify Project Binary");
        open_relocate_modal_next_frame_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(720.0f, 0.0f), ImGuiCond_Appearing);
    bool modal_open = true;
    if (!ImGui::BeginPopupModal("Relocate or Verify Project Binary", &modal_open, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    if (!pending_relocation_project_) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    const bool is_mismatch =
        pending_relocation_resolution_.status == ProjectBinaryMatchStatus::ModifiedMismatch;
    ImGui::TextColored(
        is_mismatch ? ImVec4(1.0f, 0.78f, 0.25f, 1.0f) : ImVec4(0.95f, 0.45f, 0.40f, 1.0f),
        "%s",
        pending_relocation_resolution_.diagnostic.c_str());

    if (!pending_relocation_project_->source_sha256.empty()) {
        ImGui::TextDisabled("Expected SHA-256: %s (%" PRIu64 " bytes)",
                            pending_relocation_project_->source_sha256.c_str(),
                            pending_relocation_project_->source_size);
    }
    if (!pending_relocation_resolution_.actual_sha256.empty()) {
        ImGui::TextDisabled("Found SHA-256:    %s (%" PRIu64 " bytes)",
                            pending_relocation_resolution_.actual_sha256.c_str(),
                            pending_relocation_resolution_.actual_size);
    }

    ImGui::Separator();
    ImGui::TextUnformatted("Specify path to target binary:");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##RelocPath", "Path to PE/ELF binary...", relocate_binary_buf_, sizeof(relocate_binary_buf_));

    if (!relocate_modal_error_.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s", relocate_modal_error_.c_str());
    }

    if (ImGui::Button("Open with Specified Path")) {
        auto reopened = open_project(pending_relocation_peproj_path_, std::filesystem::path(relocate_binary_buf_));
        if (reopened) {
            pending_relocation_project_.reset();
            ImGui::CloseCurrentPopup();
        } else {
            relocate_modal_error_ = reopened.error().message;
        }
    }
    if (is_mismatch) {
        ImGui::SameLine();
        if (ImGui::Button("Load Annotations & Bookmarks Anyway")) {
            const std::filesystem::path target = relocate_binary_buf_[0] != '\0'
                                                     ? std::filesystem::path(relocate_binary_buf_)
                                                     : pending_relocation_resolution_.resolved_path;
            auto reopened = open_project(pending_relocation_peproj_path_, target, true, true);
            if (reopened) {
                pending_relocation_project_.reset();
                ImGui::CloseCurrentPopup();
            } else {
                relocate_modal_error_ = reopened.error().message;
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        pending_relocation_project_.reset();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

peelf::Result<void> UiApp::save_patch_report(const std::filesystem::path& path) {
    if (!model_.image()) return peelf::make_error("No binary loaded");
    std::error_code ec;
    if (std::filesystem::equivalent(path,model_.file_info().path,ec)) return peelf::make_error("Report cannot replace the source binary");
    return write_analysis_file(path,patch_report(model_));
}

peelf::Result<void> UiApp::compare_with_binary(const std::filesystem::path& path) {
    auto res = binary_diff_panel_.compare_with_file(path);
    if (res) {
        binary_diff_panel_.set_visible(true);
        activate_panel(binary_diff_panel_.name().c_str());
    }
    return res;
}

} // namespace viewer
