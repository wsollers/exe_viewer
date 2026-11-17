#pragma once

#include "model/binary_model.hpp"
#include "ui/context_actions.hpp"

#include <imgui.h>

#include <concepts>
#include <functional>
#include <optional>
#include <utility>

namespace viewer {

/// Deferred non-clipboard action selected from an entity context popup.
/// Stored during widget/table rendering and dispatched strictly post-loop.
struct PendingEntityContextAction {
    ContextActionKind kind{ContextActionKind::CopyJsonSummary};
    InspectableEntity entity{};
};

using EntityContextActionCallback =
    std::function<void(ContextActionKind kind, const InspectableEntity& entity)>;

/// Returns true when `model` currently exposes an on-disk static container image
/// (as opposed to a live process / crash dump / empty model).
[[nodiscard]] bool model_has_static_image(const BinaryModel& model) noexcept;

/// Renders the universal capability-aware context menu items inside an already-open
/// Dear ImGui popup (`BeginPopupContextItem` / `BeginPopup`).
/// `Copy*` actions write to the clipboard immediately; `FollowIn*`, `AddBookmark`, and
/// `ToggleSoftwareBreakpoint` populate `out_pending` without mutating model/panel state.
bool draw_inspectable_entity_context_menu_items(
    const InspectableEntity& entity,
    const BinaryModel& model,
    std::optional<PendingEntityContextAction>& out_pending);

/// Opens `ImGui::BeginPopupContextItem(popup_id)` for the last-submitted item and renders
/// the capability-aware universal context menu.
bool draw_inspectable_entity_context_menu(
    const char* popup_id,
    const InspectableEntity& entity,
    const BinaryModel& model,
    std::optional<PendingEntityContextAction>& out_pending);

/// Zero-overhead lazy overload: `build_entity` is invoked ONLY while the context popup
/// for the last-submitted item is actually open.
template <typename EntityBuilder>
    requires std::invocable<EntityBuilder>
bool draw_inspectable_entity_context_menu(
    const char* popup_id,
    const BinaryModel& model,
    std::optional<PendingEntityContextAction>& out_pending,
    EntityBuilder&& build_entity) {
    if (!ImGui::BeginPopupContextItem(popup_id)) {
        return false;
    }
    const InspectableEntity entity = std::forward<EntityBuilder>(build_entity)();
    const bool triggered = draw_inspectable_entity_context_menu_items(entity, model, out_pending);
    ImGui::EndPopup();
    return triggered;
}

} // namespace viewer
