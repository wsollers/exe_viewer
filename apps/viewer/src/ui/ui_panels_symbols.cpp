#include "ui_panels.hpp"

#include <imgui.h>

#include <cstdint>
#include <string>

namespace viewer {

SymbolsPanel::SymbolsPanel(const SymbolIndex& index, const ViewerSelection& selection, const BinaryModel& model)
    : UiPanel("Functions & Names")
    , index_(index)
    , model_(model)
    , selection_(selection)
{
    filter_buf_[0] = '\0';
}

void SymbolsPanel::draw_contents() {
    if (index_.empty()) {
        ImGui::TextUnformatted("No symbols.");
        return;
    }

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##Filter", "Search functions or names...", filter_buf_, sizeof(filter_buf_));
    ImGui::Checkbox("Functions only", &functions_only_);
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();
    const auto records = index_.records();
    std::optional<std::size_t> selected_index;
    for (std::size_t i = 0; i < records.size(); ++i)
        if (selection_.label == records[i].name && selection_.virtual_address == records[i].virtual_address) {
            selected_index = i;
            break;
        }
    if (!selected_index) last_scrolled_selected_.reset();

    ImGui::Separator();
    if (ImGui::BeginTable("SymbolsTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 14);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        std::vector<std::size_t> matches;
        std::optional<int> selected_row;
        for (std::size_t i = 0; i < records.size(); ++i)
            if ((!has_filter || symbol_name_matches(records[i].name, filter) ||
                 (display_name_resolver_ && symbol_name_matches(display_name_resolver_(records[i]), filter))) &&
                (!functions_only_ || (model_.image() && symbol_has_code(*model_.image(), records[i])))) {
                if (selected_index == i) selected_row = static_cast<int>(matches.size());
                matches.push_back(i);
            }
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(matches.size()));
        if (selected_row && last_scrolled_selected_ != selected_index)
            clipper.IncludeItemByIndex(*selected_row);
        while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto row_id = matches[static_cast<std::size_t>(row)];
            const auto& symbol = records[row_id];

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row_id));
            const std::string resolved_name = display_name_resolver_ ? display_name_resolver_(symbol) : symbol.name;
            const char* display_name = resolved_name.empty() ? "<unnamed>" : resolved_name.c_str();
            const bool selected = selection_.label == symbol.name && selection_.virtual_address == symbol.virtual_address;
            if (ImGui::Selectable(display_name, selected, ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_symbol_activated_) {
                    on_symbol_activated_(symbol, row_id);
                }
            }
            if (ImGui::IsItemHovered() && resolved_name != symbol.name)
                ImGui::SetTooltip("Original symbol: %s", symbol.name.c_str());
            if (selected && last_scrolled_selected_ != row_id) {
                ImGui::SetScrollHereY(0.5f);
                last_scrolled_selected_ = row_id;
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            if (symbol.virtual_address) ImGui::Text("0x%llX", static_cast<unsigned long long>(*symbol.virtual_address));
            else ImGui::TextDisabled("Unmapped");
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(symbol.size));
            const char* source = "Embedded";
            switch (symbol.source) {
                case SymbolSource::DebugSymbol: source = "PDB"; break;
                case SymbolSource::Import: source = "Import"; break;
                case SymbolSource::Export: source = "Export"; break;
                case SymbolSource::EntryPoint: source = "Entry point"; break;
                case SymbolSource::ImageSymbol: break;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Source: %s", source);
        }
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
