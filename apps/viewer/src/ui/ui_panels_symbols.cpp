#include "ui_panels.hpp"

#include <imgui.h>

#include <cstdint>
#include <string>

namespace viewer {

SymbolsPanel::SymbolsPanel(const SymbolIndex& index, const ViewerSelection& selection)
    : UiPanel("Symbols")
    , index_(index)
    , selection_(selection)
{
    filter_buf_[0] = '\0';
}

void SymbolsPanel::draw_contents() {
    if (index_.empty()) {
        ImGui::TextUnformatted("No symbols.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Any part of a name...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();
    const std::optional<std::uint64_t> selected_index = selection_.kind == SelectionKind::Symbol ? std::optional(selection_.object_index) : std::nullopt;
    if (!selected_index) {
        last_scrolled_selected_.reset();
    }

    ImGui::Separator();
    if (ImGui::BeginTable("SymbolsTable", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("External", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Dynamic", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableHeadersRow();

        const auto records = index_.records();
        std::vector<std::size_t> matches;
        for (std::size_t i = 0; i < records.size(); ++i)
            if (!has_filter || symbol_name_matches(records[i].name, filter)) matches.push_back(i);
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(matches.size()));
        while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto row_id = matches[static_cast<std::size_t>(row)];
            const auto& symbol = records[row_id];

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row_id));
            const char* display_name = symbol.name.empty() ? "<unnamed>" : symbol.name.c_str();
            const bool selected = selection_.label == symbol.name && selection_.virtual_address == symbol.virtual_address;
            if (ImGui::Selectable(display_name, selected, ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_symbol_activated_) {
                    on_symbol_activated_(symbol, row_id);
                }
            }
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
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol.external ? "Yes" : "No");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol.dynamic ? "Yes" : "No");
            ImGui::TableNextColumn();
            const char* source = "Embedded";
            switch (symbol.source) {
                case SymbolSource::DebugSymbol: source = "PDB"; break;
                case SymbolSource::Import: source = "Import"; break;
                case SymbolSource::Export: source = "Export"; break;
                case SymbolSource::EntryPoint: source = "Entry point"; break;
                case SymbolSource::ImageSymbol: break;
            }
            ImGui::TextUnformatted(source);
        }
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
