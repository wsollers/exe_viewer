#include "ui_panels.hpp"
#include <imgui.h>

namespace viewer {

    FilePanel::FilePanel(BinaryModel& model)
        : UiPanel("File Info")
        , model_(model)
    {}

    void FilePanel::draw_contents() {
        if (!model_.has_file()) {
            ImGui::TextUnformatted("Start an inspection");
            ImGui::Separator();
            ImGui::TextWrapped("Open a PE or ELF binary using File > Open or Ctrl+O.");
            ImGui::Spacing();
            ImGui::TextDisabled("Inspect  /  Navigate  /  Patch  /  Export");
            return;
        }

        const auto& info = model_.file_info();

        ImGui::Text("Path: %s", info.path.c_str());
        ImGui::Text("Format: %s", info.format_str.c_str());
        ImGui::Text("Arch: %s", info.arch_str.c_str());
        ImGui::Text("Size: %llu bytes",
                    static_cast<unsigned long long>(info.size_bytes));
        ImGui::Text("Entry point: 0x%llX",
                    static_cast<unsigned long long>(info.entry_point));
        ImGui::Separator();

        if (!info.flags.empty()) {
            ImGui::TextUnformatted("Flags:");
            for (const auto& f : info.flags) {
                ImGui::BulletText("%s", f.c_str());
            }
        }
    }

} // namespace viewer
