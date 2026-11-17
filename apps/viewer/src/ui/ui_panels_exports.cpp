#include "ui_panels.hpp"

#include <imgui.h>

#include <cinttypes>
#include <cstdint>
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

    std::optional<PendingEntityContextAction> pending_ctx_action;
    ImGui::Separator();
    if (ImGui::BeginTable("UnifiedExportsTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Forwarder", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        std::uint64_t row_id = 0;
        for (const peelf::ExportEntry& entry : img->exports()) {
            if (has_filter &&
                entry.name.find(filter) == std::string::npos &&
                entry.forwarder.find(filter) == std::string::npos) {
                ++row_id;
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row_id));
            const char* display_name = entry.name.empty() ? "<unnamed>" : entry.name.c_str();
            if (ImGui::Selectable(display_name, false, ImGuiSelectableFlags_SpanAllColumns)) {
                if (on_export_activated_) {
                    on_export_activated_(entry, row_id);
                }
            }
            draw_inspectable_entity_context_menu(
                "ExportRowCtx",
                model_,
                pending_ctx_action,
                [&]() -> InspectableEntity {
                    const std::optional<std::uint64_t> exp_va =
                        entry.virtual_address != 0
                            ? std::optional<std::uint64_t>(entry.virtual_address)
                            : std::nullopt;
                    const bool static_img = model_has_static_image(model_);
                    return InspectableEntity{
                        .va = exp_va,
                        .file_offset = (exp_va.has_value() && static_img)
                            ? img->virtual_address_to_file_offset(*exp_va)
                            : std::nullopt,
                        .size = 1u,
                        .symbol_or_label = entry.name,
                        .module_name = model_.file_info().path,
                        .extra_json_fields = {
                            {"kind", "export"},
                            {"ordinal", std::to_string(entry.ordinal)},
                            {"forwarder", entry.forwarder},
                        },
                    };
                });
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::Text("%u", entry.ordinal);
            ImGui::TableNextColumn();
            ImGui::Text("0x%" PRIX64, entry.virtual_address);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(entry.forwarder.empty() ? "-" : entry.forwarder.c_str());
            ++row_id;
        }

        ImGui::EndTable();
    }
    if (pending_ctx_action.has_value() && on_context_action_) {
        on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
    }
}

} // namespace viewer
