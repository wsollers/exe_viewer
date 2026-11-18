#pragma once

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui/ui_context_menu.hpp"
#include "ui/ui_panel.hpp"
#include "vulkan/gpu_offscreen_canvas.hpp"
#include "vulkan/shaders/memory_heatmap_comp_spirv.hpp"
#include "vulkan/viewport_camera_2d.hpp"
#include "vulkan/vulkan_manager.h"

#include <peelf/memory_heatmap.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace viewer {

enum class HeatmapPollCadence : std::uint8_t {
    Hz10 = 0,
    Hz4 = 1,
    Hz1 = 2,
    ManualSnapshot = 3,
};

class MemoryHeatmapPanel final : public UiPanel {
public:
    MemoryHeatmapPanel(BinaryModel& model,
                       VulkanManager& vulkan,
                       ViewerSelection& selection,
                       NavigationRequestQueue& nav_queue,
                       EntityContextActionCallback on_context_action = {});
    ~MemoryHeatmapPanel() override;

    MemoryHeatmapPanel(const MemoryHeatmapPanel&) = delete;
    MemoryHeatmapPanel& operator=(const MemoryHeatmapPanel&) = delete;

    /// Cancels and joins any in-flight background sample worker and clears target-specific state.
    /// Must be called from `BinaryModel`'s session teardown hook and `UiApp::reset_target_dependent_state()`.
    void cancel_and_reset() noexcept;

    /// Releases Vulkan offscreen canvas, compute pipeline, SSBO ring, and stops background worker.
    void shutdown() noexcept;

    /// Records Vulkan compute dispatch (or automatic CPU RGBA8 fallback upload) before swapchain pass.
    void record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index);

    void set_context_action_callback(EntityContextActionCallback cb) {
        on_context_action_ = std::move(cb);
    }

protected:
    void draw_contents() override;

private:
    struct FocusTargetOption {
        std::string label{};
        std::uint64_t start_va{0};
        std::uint64_t end_va{0};
    };

    struct AsyncSampleJob {
        std::shared_ptr<peelf::IProcessSession> session{};
        peelf::MemoryHeatmapConfig config{};
        std::uint64_t generation{0};
        bool reset_tracker{false};
    };

    struct AsyncSampleResult {
        peelf::Observed<peelf::MemoryHeatmapSnapshot> observed{};
        std::uint64_t generation{0};
    };

    void ensure_worker_started();
    void stop_worker() noexcept;
    void worker_loop(std::stop_token stop_token);

    void sync_target_and_schedule_sampling();
    void request_immediate_sample(bool reset_history = false);
    void sample_static_target_now(bool reset_history);
    void rebuild_focus_options();
    [[nodiscard]] peelf::MemoryHeatmapConfig build_active_config() const;
    void fit_camera_to_grid(double canvas_w, double canvas_h) noexcept;

    [[nodiscard]] InspectableEntity build_cell_entity(
        const peelf::MemoryHeatmapCell& cell) const;
    void render_toolbar();
    void render_summary_strip() const;
    void render_canvas_and_interactions();
    void render_hover_tooltip(std::size_t cell_index) const;
    void render_cell_context_popup(std::optional<PendingEntityContextAction>& out_pending_ctx);

    BinaryModel& model_;
    VulkanManager& vulkan_;
    ViewerSelection& selection_;
    NavigationRequestQueue& nav_queue_;
    EntityContextActionCallback on_context_action_{};

    // UI controls & configuration
    peelf::MemoryHeatmapLayout layout_mode_{peelf::MemoryHeatmapLayout::HilbertCurve};
    peelf::MemoryHeatmapScope scope_mode_{peelf::MemoryHeatmapScope::CompactAddressSpace};
    peelf::MemoryHeatmapColorMode color_mode_{peelf::MemoryHeatmapColorMode::AllocatorAndWriteHeat};
    HeatmapPollCadence poll_cadence_{HeatmapPollCadence::Hz4};
    bool live_watch_enabled_{true};
    bool show_cell_grid_{true};
    float heat_decay_{0.82f};
    std::size_t selected_focus_option_{0};
    std::vector<FocusTargetOption> focus_options_{};

    // Target change tracking
    bool last_was_live_{false};
    bool last_was_crash_dump_{false};
    peelf::ProcessId last_pid_{0};
    const peelf::IBinaryImage* last_static_image_{nullptr};
    std::uint64_t last_static_edit_revision_{0};
    std::size_t last_region_count_{0};
    bool dirty_sample_{true};
    bool pending_tracker_reset_{true};
    std::chrono::steady_clock::time_point last_sample_request_time_{};

    // Snapshot & static tracker (UI thread)
    peelf::MemoryHeatmapTracker static_tracker_{};
    peelf::Observed<peelf::MemoryHeatmapSnapshot> latest_observed_{};
    bool has_snapshot_{false};

    // Camera & hit-testing state
    ViewportCamera2D camera_{};
    bool needs_fit_view_{true};
    std::uint32_t last_fitted_grid_w_{0};
    std::uint32_t last_fitted_grid_h_{0};
    std::optional<std::uint32_t> hovered_cell_index_{};
    std::optional<std::uint32_t> selected_cell_index_{};
    std::optional<std::uint64_t> selected_cell_va_{};

    // Right-click context menu state
    std::optional<std::uint32_t> context_cell_index_{};
    peelf::MemoryHeatmapCell context_cell_{};
    InspectableEntity context_entity_{};
    std::string watchpoint_status_note_{};

    // Vulkan compute + offscreen canvas + CPU fallback state
    GpuOffscreenCanvas canvas_{};
    GpuComputePipeline compute_pipeline_{};
    GpuHostRingBuffer ssbo_ring_{};
    bool canvas_initialized_{false};
    bool compute_pipeline_attempted_{false};
    bool needs_gpu_record_this_frame_{false};
    shaders::MemoryHeatmapPushConstants pending_push_constants_{};
    std::vector<std::uint8_t> cpu_rgba_scratch_{};

    // Background live-sampling worker (`std::jthread` + `std::stop_token`)
    std::mutex worker_mutex_{};
    std::condition_variable_any worker_cv_{};
    std::optional<AsyncSampleJob> pending_job_{};
    std::optional<AsyncSampleResult> completed_result_{};
    std::uint64_t worker_generation_{0};
    bool worker_busy_{false};
    std::jthread worker_thread_{};
};

} // namespace viewer
