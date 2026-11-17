#include "ui/ui_context_menu.hpp"

#include <format>
#include <string>
#include <vector>

namespace viewer {

bool model_has_static_image(const BinaryModel& model) noexcept {
    return !model.is_live_process() && model.image() != nullptr;
}

bool draw_inspectable_entity_context_menu_items(
    const InspectableEntity& entity,
    const BinaryModel& model,
    std::optional<PendingEntityContextAction>& out_pending) {
    const bool has_static_img = model_has_static_image(model);
    const bool has_debugger = model.is_debug_session();
    const std::vector<EvaluatedContextAction> actions = evaluate_context_actions(
        entity,
        model.capability_matrix(),
        has_static_img,
        has_debugger);

    if (!entity.symbol_or_label.empty()) {
        ImGui::TextDisabled("%s", entity.symbol_or_label.c_str());
        ImGui::Separator();
    } else if (entity.va.has_value()) {
        const std::string hdr = std::format("0x{:X}", *entity.va);
        ImGui::TextDisabled("%s", hdr.c_str());
        ImGui::Separator();
    }

    bool triggered = false;
    for (const EvaluatedContextAction& action : actions) {
        if (action.kind == ContextActionKind::FollowInHex ||
            action.kind == ContextActionKind::AddBookmark) {
            ImGui::Separator();
        }

        if (!action.enabled) {
            ImGui::BeginDisabled(true);
            (void)ImGui::MenuItem(action.label.c_str(), nullptr, false, true);
            ImGui::EndDisabled();
            if (!action.disabled_reason.empty() &&
                ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip("%s", action.disabled_reason.c_str());
            }
            continue;
        }

        if (ImGui::MenuItem(action.label.c_str())) {
            triggered = true;
            if (const auto clip = format_context_copy_payload(action.kind, entity)) {
                ImGui::SetClipboardText(clip->c_str());
            } else {
                out_pending = PendingEntityContextAction{
                    .kind = action.kind,
                    .entity = entity,
                };
            }
        }
    }

    return triggered;
}

bool draw_inspectable_entity_context_menu(
    const char* popup_id,
    const InspectableEntity& entity,
    const BinaryModel& model,
    std::optional<PendingEntityContextAction>& out_pending) {
    if (!ImGui::BeginPopupContextItem(popup_id)) {
        return false;
    }
    const bool triggered = draw_inspectable_entity_context_menu_items(entity, model, out_pending);
    ImGui::EndPopup();
    return triggered;
}

} // namespace viewer
