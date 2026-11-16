#pragma once

#include "../model/binary_model.hpp"
#include "ui_panel.hpp"

#include <peelf/execution_timeline.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace viewer {

class ExecutionTimelinePanel final : public UiPanel {
public:
    using NavigateTargetCallback = std::function<void(const peelf::TimelineNavigationTarget& target)>;

    explicit ExecutionTimelinePanel(BinaryModel& model,
                                    NavigateTargetCallback on_navigate = {});

protected:
    void draw_contents() override;

private:
    void draw_toolbar_and_banners();
    void draw_sources_strip();
    void draw_filter_bar();
    void draw_swimlanes_tab(std::span<const peelf::TimelineEvent* const> filtered_events);
    void draw_event_table_tab(std::span<const peelf::TimelineEvent* const> filtered_events);
    void draw_event_inspector(const peelf::TimelineEvent* selected_event);

    [[nodiscard]] bool passes_filter(const peelf::TimelineEvent& ev) const;
    [[nodiscard]] const peelf::TimelineEvent* find_selected_event() const noexcept;
    void dispatch_navigation(const peelf::TimelineNavigationTarget& target);

    BinaryModel& model_;
    NavigateTargetCallback on_navigate_{};

    std::array<bool, peelf::kTimelineEventKindCount> kind_enabled_{};
    std::array<char, 160> text_filter_{};
    std::optional<peelf::ThreadIdentity> lane_filter_{};
    bool global_lane_only_{false};
    bool pause_during_capture_{false};
    bool auto_scroll_table_{true};
    int capacity_preset_idx_{1}; // 0=1024, 1=4096, 2=16384, 3=65536

    std::optional<std::uint64_t> selected_sequence_{};
    std::optional<peelf::TimelineNavigationTarget> pending_navigation_{};
    std::optional<peelf::ThreadId> pending_select_tid_{};
    bool pending_record_snapshot_delta_{false};
    bool pending_clear_timeline_{false};
    std::optional<std::size_t> pending_capacity_change_{};
    std::string status_message_{};
};

} // namespace viewer
