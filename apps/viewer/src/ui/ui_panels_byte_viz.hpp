#pragma once

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui/ui_context_menu.hpp"
#include "ui/ui_panel.hpp"
#include "vulkan/gpu_offscreen_canvas.hpp"
#include "vulkan/shaders/byte_viz_comp_spirv.hpp"
#include "vulkan/viewport_camera_2d.hpp"
#include "vulkan/vulkan_manager.h"

#include <peelf/byte_viz.hpp>

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
#include <utility>
#include <vector>

namespace viewer {

struct ActiveDiffOverlaySnapshot {
    std::uint64_t revision{0};
    std::vector<peelf::ByteVizDiffRange> ranges{};
};

using DiffOverlayProviderCallback = std::function<ActiveDiffOverlaySnapshot(bool prefer_virtual_addresses)>;

class ByteEntropyVizPanel final : public UiPanel {
public:
    ByteEntropyVizPanel(BinaryModel& model,
                        VulkanManager& vulkan,
                        ViewerSelection& selection,
                        NavigationRequestQueue& nav_queue,
                        EntityContextActionCallback on_context_action = {},
                        DiffOverlayProviderCallback diff_overlay_provider = {});
    ~ByteEntropyVizPanel() override;

    ByteEntropyVizPanel(const ByteEntropyVizPanel&) = delete;
    ByteEntropyVizPanel& operator=(const ByteEntropyVizPanel&) = delete;

    /// Cancels and joins any in-flight background worker and clears target-bound state.
    /// Wired into `BinaryModel::set_session_teardown_hook` and `UiApp::reset_target_dependent_state()`.
    void cancel_and_reset() noexcept;

    /// Releases Vulkan offscreen canvas, compute pipeline, SSBO ring, and joins background worker.
    void shutdown() noexcept;

    /// Records Vulkan compute dispatch (or automatic CPU RGBA8 fallback upload) before swapchain pass.
    void record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index);

    void set_context_action_callback(EntityContextActionCallback cb) {
        on_context_action_ = std::move(cb);
    }

    void set_diff_overlay_provider(DiffOverlayProviderCallback cb) {
        diff_overlay_provider_ = std::move(cb);
    }

protected:
    void draw_contents() override;

private:
    enum class ScopeKind : std::uint8_t {
        WholeStaticBinary = 0,
        StaticSection = 1,
        LiveMemoryRegion = 2,
    };

    struct ScopeOption {
        ScopeKind kind{ScopeKind::WholeStaticBinary};
        std::string label{};
        std::string short_label{};
        std::uint64_t start_address{0};
        std::uint64_t end_address{0};
        peelf::MemoryRegion live_region{};
    };

    enum class AsyncJobKind : std::uint8_t {
        FullSnapshot = 0,
        BrushCantorOnly = 1,
    };

    struct AsyncAnalysisJob {
        AsyncJobKind kind{AsyncJobKind::FullSnapshot};
        std::uint64_t generation{0};
        bool is_live{false};

        // Static job inputs (either immutable IBinaryImage or pre-snapshotted effective bytes)
        const peelf::IBinaryImage* static_image{nullptr};
        std::span<const std::uint8_t> static_raw_bytes{};
        bool use_owned_effective_bytes{false};
        std::vector<std::uint8_t> owned_effective_bytes{};
        std::uint64_t owned_base_address{0};
        std::vector<peelf::PatchInterval> patch_intervals{};
        std::vector<peelf::ByteVizSectionSpan> owned_sections{};

        // Live / crash-dump job inputs
        std::shared_ptr<peelf::IProcessSession> session{};
        peelf::MemoryRegion live_region{};

        // Shared configuration & overlays
        peelf::ByteVizConfig config{};
        std::vector<peelf::ByteVizDiffRange> diff_ranges{};
        std::uint64_t brush_start{0};
        std::uint64_t brush_end{0};
    };

    struct AsyncAnalysisResult {
        AsyncJobKind kind{AsyncJobKind::FullSnapshot};
        std::uint64_t generation{0};
        peelf::Observed<peelf::ByteVizSnapshot> snapshot_observed{};
        peelf::Observed<peelf::CantorDustDigram> brush_cantor_observed{};
        std::pair<std::uint64_t, std::uint64_t> brush_range{0u, 0u};
    };

    void ensure_worker_started();
    void stop_worker() noexcept;
    void worker_loop(std::stop_token thread_stop_token);

    void rebuild_scope_options();
    void sync_target_and_schedule_analysis();
    void schedule_full_snapshot_analysis();
    void schedule_brush_cantor_analysis(std::uint64_t brush_start, std::uint64_t brush_end);
    void clear_brush() noexcept;

    [[nodiscard]] const peelf::CantorDustDigram* active_cantor_digram() const noexcept;
    void fit_camera_to_active_domain(double canvas_w, double canvas_h) noexcept;

    void navigate_to_address_or_offset(std::uint64_t offset_or_va,
                                       bool addresses_are_virtual,
                                       bool executable_hint,
                                       std::size_t highlight_bytes);

    [[nodiscard]] InspectableEntity build_tile_entity(const peelf::ByteVizTile& tile) const;
    [[nodiscard]] InspectableEntity build_cantor_bin_entity(std::uint8_t first_byte,
                                                            std::uint8_t second_byte) const;

    void render_toolbar();
    void render_summary_strip() const;
    void render_canvas_and_interactions();
    void render_entropy_hover_tooltip(std::size_t tile_index) const;
    void render_cantor_hover_tooltip(std::uint32_t bin_index) const;
    void render_context_popup(std::optional<PendingEntityContextAction>& out_pending_ctx);

    BinaryModel& model_;
    VulkanManager& vulkan_;
    ViewerSelection& selection_;
    NavigationRequestQueue& nav_queue_;
    EntityContextActionCallback on_context_action_{};
    DiffOverlayProviderCallback diff_overlay_provider_{};

    // Toolbar & mode configuration
    peelf::ByteVizMode viz_mode_{peelf::ByteVizMode::EntropyAndByteClass2D};
    peelf::ByteVizLayout layout_mode_{peelf::ByteVizLayout::HilbertCurve};
    peelf::ByteVizColorMode color_mode_{peelf::ByteVizColorMode::EntropySpectrum};
    bool show_guides_{true};
    std::size_t selected_scope_index_{0};
    std::vector<ScopeOption> scope_options_{};

    // Target / patch / diff revision tracking
    bool last_was_live_{false};
    bool last_was_crash_dump_{false};
    peelf::ProcessId last_pid_{0};
    const peelf::IBinaryImage* last_static_image_{nullptr};
    std::size_t last_scope_source_count_{0};
    std::uint64_t last_edit_revision_{0};
    std::uint64_t last_diff_revision_{0};
    bool dirty_analysis_{true};

    // Active snapshot & optional brushed Cantor digram
    peelf::Observed<peelf::ByteVizSnapshot> latest_observed_{};
    bool has_snapshot_{false};

    bool is_brushing_{false};
    std::pair<std::uint64_t, std::uint64_t> brush_anchor_span_{0u, 0u};
    std::optional<std::pair<std::uint64_t, std::uint64_t>> brushed_range_{};
    std::optional<peelf::Observed<peelf::CantorDustDigram>> brushed_cantor_observed_{};
    bool viewing_brushed_cantor_{false};

    // Camera & hover / selection state
    ViewportCamera2D camera_{};
    bool needs_fit_view_{true};
    peelf::ByteVizMode last_fitted_mode_{peelf::ByteVizMode::EntropyAndByteClass2D};
    std::uint32_t last_fitted_domain_w_{0};
    std::uint32_t last_fitted_domain_h_{0};

    std::optional<std::uint32_t> hovered_index_{};
    std::optional<std::uint32_t> selected_tile_index_{};
    std::optional<std::uint64_t> selected_tile_addr_{};
    std::optional<std::uint32_t> selected_cantor_bin_{};

    // Right-click context menu state
    bool context_is_cantor_{false};
    std::optional<std::uint32_t> context_index_{};
    peelf::ByteVizTile context_tile_{};
    InspectableEntity context_entity_{};

    // Vulkan compute + offscreen canvas + CPU RGBA8 fallback state
    GpuOffscreenCanvas canvas_{};
    GpuComputePipeline compute_pipeline_{};
    GpuHostRingBuffer ssbo_ring_{};
    bool canvas_initialized_{false};
    bool compute_pipeline_attempted_{false};
    bool needs_gpu_record_this_frame_{false};
    shaders::ByteVizPushConstants pending_push_constants_{};
    std::vector<std::uint8_t> cpu_rgba_scratch_{};

    // Background worker (`std::jthread` + `std::stop_token` + per-job `std::stop_source`)
    std::mutex worker_mutex_{};
    std::condition_variable_any worker_cv_{};
    std::stop_source active_job_stop_{};
    std::optional<AsyncAnalysisJob> pending_job_{};
    std::vector<AsyncAnalysisResult> completed_results_{};
    std::uint64_t worker_generation_{0};
    bool worker_busy_{false};
    std::jthread worker_thread_{};
};

} // namespace viewer
