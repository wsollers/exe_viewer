#include "ui_panels.hpp"
#include <imgui.h>
#include <format>

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
                const bool paused = model_.is_process_suspended();
                ImGui::TextColored(paused ? ImVec4(1.0f, 0.78f, 0.25f, 1.0f)
                                          : ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
                                   "%s LIVE PROCESS: %s (PID %llu) [Read-Only]",
                                   paused ? "[PAUSED]" : "[RUNNING]",
                                   sess->info().name.empty() ? "<process>" : sess->info().name.c_str(),
                                   static_cast<unsigned long long>(sess->pid()));
                if (ImGui::SmallButton(paused ? "Resume Process" : "Pause Process")) {
                    if (on_pause_toggle_) {
                        on_pause_toggle_();
                    }
                }
                ImGui::SameLine();
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
                if (model_.resolved_executable_path()) {
                    ImGui::TextDisabled("Backing binary: %s",
                                        model_.resolved_executable_path()->string().c_str());
                }
                ImGui::Separator();
            }
        }

        const auto& info = model_.file_info();

        if (ImGui::CollapsingHeader("Image properties", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (ImGui::BeginTable("ImageProperties", 2, ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                const auto row = [](const char* label, const std::string& value) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", label);
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(value.c_str());
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", value.c_str());
                };
                row("Path", info.path);
                row("Format", info.format_str);
                row("Architecture", info.arch_str);
                row("Size", std::format("{} bytes", info.size_bytes));
                row("Window base", std::format("0x{:X}", model_.view_base_address()));
                row("Entry point", std::format("0x{:X}", info.entry_point));
                ImGui::EndTable();
            }
        }

        if (!info.flags.empty() && ImGui::CollapsingHeader("Image flags", ImGuiTreeNodeFlags_DefaultOpen)) {
            for (const auto& f : info.flags) {
                ImGui::BulletText("%s", f.c_str());
            }
        }
    }

} // namespace viewer
