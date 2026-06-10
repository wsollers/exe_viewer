#include "ui_panels.hpp"

#include <imgui.h>

#include <cstdint>
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
    if (ImGui::BeginTable("UnifiedImportsTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableHeadersRow();

        std::uint64_t row_id = 0;
        for (const peelf::ImportEntry& entry : img->imports()) {
            const std::string symbol_name = entry.import_by_ordinal
                ? "#" + std::to_string(entry.ordinal)
                : entry.name;
            if (has_filter &&
                entry.library.find(filter) == std::string::npos &&
                symbol_name.find(filter) == std::string::npos) {
                ++row_id;
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row_id));
            if (ImGui::Selectable(entry.library.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_import_activated_) {
                    on_import_activated_(entry, row_id);
                }
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol_name.empty() ? "-" : symbol_name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.delay_load ? "Delay" : "Import");
            ImGui::TableNextColumn();
            if (entry.address == 0) {
                ImGui::TextUnformatted("-");
            } else {
                ImGui::Text("0x%llX", static_cast<unsigned long long>(entry.address));
            }
            ++row_id;
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
