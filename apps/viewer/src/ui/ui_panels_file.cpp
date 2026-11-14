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
            ImGui::TextUnformatted("Start an inspection");
            ImGui::Separator();
            ImGui::TextWrapped("Open a PE or ELF binary using File > Open or Ctrl+O.");
            ImGui::Spacing();
            ImGui::TextDisabled("Inspect  /  Navigate  /  Patch  /  Export");
            return;
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
