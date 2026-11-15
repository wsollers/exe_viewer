#include "ui_panels.hpp"

#include <imgui.h>

#include <cinttypes>
#include <cstdint>
#include <string>

namespace viewer {

SymbolsPanel::SymbolsPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Symbols")
    , model_(model)
    , selection_(selection)
{
    filter_buf_[0] = '\0';
}

void SymbolsPanel::draw_contents() {
    const SymbolIndex& sym_index = model_.symbol_index();
    const auto records = sym_index.records();
    if (records.empty()) {
        ImGui::TextUnformatted("No symbols.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Name or library...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();
    const std::optional<std::uint64_t> selected_index =
        selected_symbol_record_index(selection_, sym_index);
    if (!selected_index) {
        last_scrolled_selected_.reset();
    }

    ImGui::TextDisabled("%zu unified symbol record%s",
                        records.size(),
                        records.size() == 1 ? "" : "s");
    ImGui::Separator();
    if (ImGui::BeginTable("SymbolsTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Virtual Address", ImGuiTableColumnFlags_WidthFixed, 136.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Scope", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < records.size(); ++i) {
            const SymbolRecord& record = records[i];
            const auto row_id = static_cast<std::uint64_t>(i);
            if (has_filter && record.name.find(filter) == std::string::npos) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            const char* display_name = record.name.empty() ? "<unnamed>" : record.name.c_str();
            const bool selected = selected_index && *selected_index == row_id;
            if (ImGui::Selectable(display_name, selected, ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_symbol_record_activated_) {
                    on_symbol_record_activated_(record, row_id);
                }
            }
            if (selected && last_scrolled_selected_ != row_id) {
                ImGui::SetScrollHereY(0.5f);
                last_scrolled_selected_ = row_id;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            if (record.virtual_address) {
                ImGui::Text("0x%" PRIX64, *record.virtual_address);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::Text("0x%" PRIX64, record.size);

            ImGui::TableNextColumn();
            if (record.source == SymbolSource::ImageSymbol) {
                ImGui::TextUnformatted(record.dynamic ? "dynsym" : "symtab");
            } else {
                ImGui::TextUnformatted(to_string(record.source));
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(record.external ? "ext" : "def");
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
