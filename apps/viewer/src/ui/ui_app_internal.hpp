#pragma once

#include "navigation/viewer_navigation.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <cstddef>
#include <cstdint>
#include <limits>

namespace viewer::detail {

inline void activate_panel(const char* name) {
    if (auto* window = ImGui::FindWindowByName(name)) {
        if (window->DockNode && window->DockNode->TabBar) {
            window->DockNode->TabBar->NextSelectedTabId = window->TabId;
        }
        ImGui::FocusWindow(window);
    }
}

[[nodiscard]] inline bool same_selection(const ViewerSelection& lhs, const ViewerSelection& rhs) {
    return lhs.kind == rhs.kind &&
           lhs.object_index == rhs.object_index &&
           lhs.virtual_address == rhs.virtual_address && lhs.file_offset == rhs.file_offset &&
           lhs.size == rhs.size && lhs.preferred_view == rhs.preferred_view &&
           lhs.label == rhs.label;
}

[[nodiscard]] constexpr std::size_t clamp_to_size_t(std::uint64_t value) noexcept {
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::numeric_limits<std::size_t>::max();
    }
    return static_cast<std::size_t>(value);
}

} // namespace viewer::detail
