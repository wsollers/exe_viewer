#include "ui_panels.hpp"

#include <imgui.h>

#include <cinttypes>
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

    std::optional<PendingEntityContextAction> pending_ctx_action;
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
            if (ImGui::Selectable(entry.library.empty() ? "<default>" : entry.library.c_str(),
                                  false,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_import_activated_) {
                    on_import_activated_(entry, row_id);
                }
            }
            draw_inspectable_entity_context_menu(
                "ImportRowCtx",
                model_,
                pending_ctx_action,
                [&]() -> InspectableEntity {
                    const std::optional<std::uint64_t> imp_va =
                        entry.address != 0 ? std::optional<std::uint64_t>(entry.address) : std::nullopt;
                    const bool static_img = model_has_static_image(model_);
                    return InspectableEntity{
                        .va = imp_va,
                        .file_offset = (imp_va.has_value() && static_img)
                            ? img->virtual_address_to_file_offset(*imp_va)
                            : std::nullopt,
                        .size = img->is_64bit() ? 8u : 4u,
                        .symbol_or_label = symbol_name,
                        .module_name = entry.library,
                        .extra_json_fields = {
                            {"kind", entry.delay_load ? "delay_import" : "import"},
                            {"ordinal", std::to_string(entry.ordinal)},
                        },
                    };
                });
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(symbol_name.empty() ? "-" : symbol_name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.delay_load ? "Delay" : "Import");
            ImGui::TableNextColumn();
            if (entry.address == 0) {
                ImGui::TextUnformatted("-");
            } else {
                ImGui::Text("0x%" PRIX64, entry.address);
            }
            ++row_id;
        }

        ImGui::EndTable();
    }
    if (pending_ctx_action.has_value() && on_context_action_) {
        on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
    }
}

} // namespace viewer
