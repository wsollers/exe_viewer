#include "ui_panels.hpp"

#include <imgui.h>

#include <string>

namespace viewer {

ExportsPanel::ExportsPanel(BinaryModel& model)
    : UiPanel("Exports")
    , model_(model)
{
    filter_buf_[0] = '\0';
}

void ExportsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (!img || img->exports().empty()) {
        ImGui::TextUnformatted("No exports.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Name or forwarder...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();

    ImGui::Separator();
    if (ImGui::BeginTable("UnifiedExportsTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Forwarder", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const peelf::ExportEntry& entry : img->exports()) {
            if (has_filter &&
                entry.name.find(filter) == std::string::npos &&
                entry.forwarder.find(filter) == std::string::npos) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.name.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%u", entry.ordinal);
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(entry.virtual_address));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.forwarder.empty() ? "-" : entry.forwarder.c_str());
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
