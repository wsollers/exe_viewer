#include "ui_panels.hpp"

#include <imgui.h>

#include <string>

namespace viewer {

SymbolsPanel::SymbolsPanel(BinaryModel& model)
    : UiPanel("Symbols")
    , model_(model)
{
    filter_buf_[0] = '\0';
}

void SymbolsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (!img || img->symbols().empty()) {
        ImGui::TextUnformatted("No symbols.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Name...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();

    ImGui::Separator();
    if (ImGui::BeginTable("SymbolsTable", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Bind", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Table", ImGuiTableColumnFlags_WidthFixed, 64.0f);
        ImGui::TableHeadersRow();

        for (const peelf::Symbol& symbol : img->symbols()) {
            if (has_filter && symbol.name.find(filter) == std::string::npos) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol.name.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(symbol.virtual_address));
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(symbol.size));
            ImGui::TableNextColumn();
            ImGui::Text("%u", static_cast<unsigned>(symbol.binding));
            ImGui::TableNextColumn();
            ImGui::Text("%u", static_cast<unsigned>(symbol.type));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol.dynamic ? "dynsym" : "symtab");
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
