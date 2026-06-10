#include "ui_panels.hpp"

#include <imgui.h>

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
    const peelf::IBinaryImage* img = model_.image();
    if (!img || img->symbols().empty()) {
        ImGui::TextUnformatted("No symbols.");
        return;
    }

    ImGui::InputTextWithHint("Filter", "Name...", filter_buf_, sizeof(filter_buf_));
    const std::string filter = filter_buf_;
    const bool has_filter = !filter.empty();
    const std::optional<std::uint64_t> selected_index = selected_symbol_index(selection_, *img);
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
        ImGui::TableSetupColumn("Bind", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Table", ImGuiTableColumnFlags_WidthFixed, 64.0f);
        ImGui::TableHeadersRow();

        std::uint64_t row_id = 0;
        for (const peelf::Symbol& symbol : img->symbols()) {
            if (has_filter && symbol.name.find(filter) == std::string::npos) {
                ++row_id;
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row_id));
            const char* display_name = symbol.name.empty() ? "<unnamed>" : symbol.name.c_str();
            const bool selected = selected_index && *selected_index == row_id;
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
            ImGui::Text("0x%llX", static_cast<unsigned long long>(symbol.virtual_address));
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(symbol.size));
            ImGui::TableNextColumn();
            ImGui::Text("%u", static_cast<unsigned>(symbol.binding));
            ImGui::TableNextColumn();
            ImGui::Text("%u", static_cast<unsigned>(symbol.type));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol.dynamic ? "dynsym" : "symtab");
            ++row_id;
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
