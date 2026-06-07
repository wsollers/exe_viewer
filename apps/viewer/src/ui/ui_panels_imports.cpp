#include "ui_panels.hpp"

#include <imgui.h>

#include <string>

namespace viewer {

ImportsPanel::ImportsPanel(BinaryModel& model)
    : UiPanel("Imports")
    , model_(model)
{
    filter_buf_[0] = '\0';
}

void ImportsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (!img || img->imports().empty()) {
        ImGui::TextUnformatted("No imports.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Library or symbol...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();

    ImGui::Separator();
    if (ImGui::BeginTable("UnifiedImportsTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableHeadersRow();

        for (const peelf::ImportEntry& entry : img->imports()) {
            if (has_filter &&
                entry.library.find(filter) == std::string::npos &&
                entry.name.find(filter) == std::string::npos) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.library.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.name.empty() ? "-" : entry.name.c_str());
            ImGui::TableNextColumn();
            if (entry.address == 0) {
                ImGui::TextUnformatted("-");
            } else {
                ImGui::Text("0x%llX", static_cast<unsigned long long>(entry.address));
            }
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
