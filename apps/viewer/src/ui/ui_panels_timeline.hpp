#pragma once

#include "../model/binary_model.hpp"
#include "../vulkan/gpu_offscreen_canvas.hpp"
#include "../vulkan/shaders/timeline_span_spirv.hpp"
#include "../vulkan/vulkan_manager.h"
#include "ui_panel.hpp"

#include <peelf/execution_timeline.hpp>
#include <peelf/timeline_viewport.hpp>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace viewer {

class ExecutionTimelinePanel final : public UiPanel {
public:
    using NavigateTargetCallback = std::function<void(const peelf::TimelineNavigationTarget& target)>;

    ExecutionTimelinePanel(BinaryModel& model,
                           VulkanManager& vulkan,
                           NavigateTargetCallback on_navigate = {});
    ~ExecutionTimelinePanel() override;

    ExecutionTimelinePanel(const ExecutionTimelinePanel&) = delete;
    ExecutionTimelinePanel& operator=(const ExecutionTimelinePanel&) = delete;

    void cancel_and_reset() noexcept;
    void reset_for_new_target() noexcept { cancel_and_reset(); }
    void shutdown() noexcept;
    void record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index);

protected:
    void draw_contents() override;

private:
    enum class LiveMonitorRate : int {
        Off = 0,
        Hz4 = 1,
        Hz10 = 2,
        Hz20 = 3,
        Hz50 = 4,
    };

    struct SelectedThreadSpanState {
        peelf::ThreadIdentity thread{};
        peelf::ThreadStateSpan span{};
        peelf::ProvenanceTag provenance{peelf::ProvenanceTag::ProcOrOsApi};
    };

    struct TidEpochHash {
        std::size_t operator()(const peelf::ThreadIdentity& id) const noexcept {
            const std::size_t h1 = std::hash<peelf::ThreadId>{}(id.tid);
            const std::size_t h2 = std::hash<std::uint64_t>{}(id.epoch);
            return h1 ^ (h2 + 0x9E3779B97F4A7C15ULL + (h1 << 6u) + (h1 >> 2u));
        }
    };

    struct TidEpochEq {
        bool operator()(const peelf::ThreadIdentity& a,
                        const peelf::ThreadIdentity& b) const noexcept {
            return a.same_lane(b);
        }
    };

    void sync_target_and_monitor();
    void ensure_monitor_worker_started();
    void stop_monitor_worker() noexcept;
    void monitor_worker_loop(std::stop_token stop_token);

    void rebuild_viewport_index_if_needed();
    void fit_view_to_domain() noexcept;
    void zoom_view_at_ratio(double anchor_ratio, double factor) noexcept;

    void draw_toolbar_and_banners();
    void draw_sources_strip();
    void draw_filter_bar();
    void draw_swimlanes_tab(std::span<const peelf::TimelineEvent* const> filtered_events);
    void draw_event_table_tab(std::span<const peelf::TimelineEvent* const> filtered_events);
    void draw_event_inspector(const peelf::TimelineEvent* selected_event);

    [[nodiscard]] bool passes_filter(const peelf::TimelineEvent& ev) const;
    [[nodiscard]] std::uint64_t compute_filter_signature() const noexcept;
    [[nodiscard]] const peelf::TimelineEvent* find_selected_event() const noexcept;
    void dispatch_navigation(const peelf::TimelineNavigationTarget& target);

    BinaryModel& model_;
    VulkanManager& vulkan_;
    NavigateTargetCallback on_navigate_{};

    // Background non-intrusive LiveThreadMonitor worker (`Off`, `4 Hz`, `10 Hz`, `20 Hz`, `50 Hz`).
    peelf::LiveThreadMonitor live_monitor_{};
    std::mutex worker_mutex_{};
    std::condition_variable_any worker_cv_{};
    std::shared_ptr<peelf::IProcessSession> worker_session_{};
    LiveMonitorRate monitor_rate_{LiveMonitorRate::Off};
    std::jthread monitor_worker_{};
    std::atomic<std::uint64_t> latest_monitor_seq_{0};
    bool crash_dump_seeded_{false};
    std::uint32_t tracked_pid_{0};
    const void* tracked_session_ptr_{nullptr};

    // Cached LOD index & frame output.
    peelf::Observed<peelf::LiveThreadMonitorSnapshot> cached_monitor_observed_{
        peelf::Observed<peelf::LiveThreadMonitorSnapshot>::unavailable(
            peelf::ProvenanceTag::ProcOrOsApi, "Monitor idle")};
    peelf::TimelineViewportIndex viewport_index_{};
    peelf::TimelineViewportFrame current_frame_{};
    std::uint64_t indexed_timeline_next_seq_{0};
    std::size_t indexed_timeline_size_{0};
    std::size_t indexed_lane_count_{0};
    std::uint64_t indexed_monitor_seq_{0};
    std::uint64_t indexed_filter_sig_{0};
    bool index_dirty_{true};

    // Tracy-style camera, sparkline, and Shift+drag dt ruler state.
    std::uint64_t view_start_ns_{0};
    std::uint64_t view_end_ns_{1'000'000ULL};
    bool view_initialized_{false};
    bool follow_live_tail_{true};
    bool show_sparklines_{true};
    std::unordered_set<peelf::ThreadIdentity, TidEpochHash, TidEpochEq> muted_sparkline_lanes_{};
    float lane_scroll_y_px_{0.0f};
    bool is_panning_{false};
    bool pan_exceeded_drag_slop_{false};
    float pan_press_x_{0.0f};
    float pan_press_y_{0.0f};
    std::uint64_t pan_anchor_start_ns_{0};
    std::uint64_t pan_anchor_end_ns_{0};
    float pan_anchor_scroll_y_{0.0f};

    bool is_measuring_dt_{false};
    bool has_dt_ruler_{false};
    std::uint64_t dt_start_ns_{0};
    std::uint64_t dt_end_ns_{0};

    // Vulkan offscreen canvas, 2D instanced SDF pipeline, ring buffer, & CPU fallback buffer.
    GpuOffscreenCanvas canvas_{};
    GpuGraphics2DPipeline graphics_pipeline_{};
    GpuHostRingBuffer instance_ring_{};
    std::vector<std::uint8_t> cpu_rgba8_scratch_{};
    shaders::TimelineViewportPushConstants pending_push_constants_{};
    std::uint32_t hovered_hit_id_{peelf::kInvalidTimelineHitId};
    std::uint32_t selected_hit_id_{peelf::kInvalidTimelineHitId};
    bool canvas_initialized_{false};
    bool graphics_pipeline_attempted_{false};
    bool needs_gpu_record_this_frame_{false};

    // Filters, presets, selection, & deferred mutations.
    std::array<bool, peelf::kTimelineEventKindCount> kind_enabled_{};
    std::array<char, 160> text_filter_{};
    std::optional<peelf::ThreadIdentity> lane_filter_{};
    bool global_lane_only_{false};
    bool pause_during_capture_{false};
    bool auto_scroll_table_{true};
    int capacity_preset_idx_{1}; // 1,024 .. 1,048,576

    std::optional<std::uint64_t> selected_sequence_{};
    std::optional<SelectedThreadSpanState> selected_thread_span_{};
    std::optional<peelf::TimelineNavigationTarget> pending_navigation_{};
    std::optional<peelf::ThreadId> pending_select_tid_{};
    bool pending_record_snapshot_delta_{false};
    bool pending_clear_timeline_{false};
    std::optional<std::size_t> pending_capacity_change_{};
    std::string status_message_{};
};

} // namespace viewer
