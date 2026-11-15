#include "ui_panels.hpp"
#include <imgui.h>

namespace viewer {

    FilePanel::FilePanel(BinaryModel& model)
        : UiPanel("File Info")
        , model_(model)
    {}

    void FilePanel::draw_contents() {
        if (!model_.has_file()) {
            ImGui::TextUnformatted("No file or live process loaded.");
            ImGui::Separator();
            ImGui::TextWrapped("Open a PE/ELF file from disk or attach to a running process to inspect memory and symbols.");
            if (on_attach_requested_ && ImGui::Button("Attach to Process...")) {
                on_attach_requested_();
            }
            return;
        }

        if (model_.is_live_process()) {
            if (const peelf::IProcessSession* sess = model_.process_session()) {
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
                                   "LIVE PROCESS: %s (PID %llu)",
                                   sess->info().name.empty() ? "<process>" : sess->info().name.c_str(),
                                   static_cast<unsigned long long>(sess->pid()));
                if (ImGui::SmallButton("Refresh Map")) {
                    if (on_refresh_requested_) {
                        on_refresh_requested_();
                    }
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Switch Process...")) {
                    if (on_attach_requested_) {
                        on_attach_requested_();
                    }
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Detach")) {
                    if (on_detach_requested_) {
                        on_detach_requested_();
                    }
                }
                ImGui::Text("Staged RAM patches: %zu | Committed: %zu",
                            model_.staged_live_patches().size(),
                            model_.committed_live_patches().size());
                ImGui::Separator();
            }
        }

        const auto& info = model_.file_info();

        ImGui::TextWrapped("Path: %s", info.path.c_str());
        ImGui::Text("Format: %s", info.format_str.c_str());
        ImGui::Text("Arch: %s", info.arch_str.c_str());
        ImGui::Text("Window Base: 0x%llX",
                    static_cast<unsigned long long>(model_.view_base_address()));
        ImGui::Text("Window Size: %llu bytes (0x%llX)",
                    static_cast<unsigned long long>(info.size_bytes),
                    static_cast<unsigned long long>(info.size_bytes));
        ImGui::Text("Entry point: 0x%llX",
                    static_cast<unsigned long long>(info.entry_point));
        ImGui::Separator();

        if (!info.flags.empty()) {
            ImGui::TextUnformatted("Attributes:");
            for (const auto& f : info.flags) {
                ImGui::BulletText("%s", f.c_str());
            }
        }
    }

} // namespace viewer