#pragma once

#include "navigation/viewer_navigation.hpp"

#include <peelf/capability_matrix.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {

/// Universal, UI-independent coordinate & metadata bundle for any inspectable row/entity
/// across Sections, Imports, Exports, Symbols, Disassembly, Memory Map, Security Audit, etc.
struct InspectableEntity {
    std::optional<std::uint64_t> va{};
    std::optional<std::uint64_t> file_offset{};
    std::uint64_t size{0};
    std::string symbol_or_label{};
    std::string module_name{};
    std::vector<std::pair<std::string, std::string>> extra_json_fields{};
};

/// Universal context menu actions evaluated identically across all viewer entity panels.
enum class ContextActionKind : std::uint8_t {
    CopyVirtualAddress = 0,
    CopyFileOffset,
    CopyLabel,
    CopyJsonSummary,
    FollowInHex,
    FollowInDisassembly,
    FollowInDecompiler,
    FollowInStructureView,
    AddBookmark,
    ToggleSoftwareBreakpoint,
};

inline constexpr std::size_t kContextActionCount = 10u;

[[nodiscard]] constexpr std::string_view to_string(ContextActionKind kind) noexcept {
    switch (kind) {
        case ContextActionKind::CopyVirtualAddress:       return "CopyVirtualAddress";
        case ContextActionKind::CopyFileOffset:           return "CopyFileOffset";
        case ContextActionKind::CopyLabel:                return "CopyLabel";
        case ContextActionKind::CopyJsonSummary:          return "CopyJsonSummary";
        case ContextActionKind::FollowInHex:              return "FollowInHex";
        case ContextActionKind::FollowInDisassembly:      return "FollowInDisassembly";
        case ContextActionKind::FollowInDecompiler:       return "FollowInDecompiler";
        case ContextActionKind::FollowInStructureView:    return "FollowInStructureView";
        case ContextActionKind::AddBookmark:              return "AddBookmark";
        case ContextActionKind::ToggleSoftwareBreakpoint: return "ToggleSoftwareBreakpoint";
    }
    return "CopyJsonSummary";
}

/// Evaluated menu item with capability-sourced or coordinate-sourced disablement reason.
struct EvaluatedContextAction {
    ContextActionKind kind{ContextActionKind::CopyJsonSummary};
    std::string label{};
    bool enabled{false};
    std::string disabled_reason{};
};

/// Evaluates all universal context actions for `entity` against `capabilities`, static-image
/// backing availability, and active-debugger session state without touching any UI globals.
[[nodiscard]] std::vector<EvaluatedContextAction> evaluate_context_actions(
    const InspectableEntity& entity,
    const peelf::TargetCapabilityMatrix& capabilities,
    bool has_static_image,
    bool has_active_debugger);

/// Formats `entity` as a deterministic RFC 8259 JSON summary object with escaped strings.
[[nodiscard]] std::string format_entity_json_summary(const InspectableEntity& entity);

/// Formats the clipboard text payload for a `Copy*` context action (`std::nullopt` for non-copy actions
/// or missing coordinate/label).
[[nodiscard]] std::optional<std::string> format_context_copy_payload(
    ContextActionKind kind,
    const InspectableEntity& entity);

/// Builds a pure `DeferredNavigationRequest` (`NavigationRequest`) for `FollowIn*` context actions
/// without mutating UI or model state mid-loop. Returns `std::nullopt` for non-navigation actions
/// or when required coordinates are absent.
[[nodiscard]] std::optional<NavigationRequest> build_context_navigation_request(
    ContextActionKind kind,
    const InspectableEntity& entity,
    bool has_static_image = true) noexcept;

/// Enqueues a `FollowIn*` action onto `queue` so cross-panel navigation executes strictly
/// after ImGui table/widget iteration finishes. Returns `true` if a request was enqueued.
bool enqueue_context_navigation_action(
    NavigationRequestQueue& queue,
    ContextActionKind kind,
    const InspectableEntity& entity,
    bool has_static_image = true);

} // namespace viewer
