#pragma once

// Tracy-Style GPU-Instanced Thread & Execution Timeline Viewport (WU-32).
//
// Pure C++23 headless thread-state sampler, multi-resolution LOD span pyramid,
// adaptive nanosecond ruler, spatial hit-tester, and deterministic CPU RGBA8
// reference rasterizer with zero Vulkan or ImGui dependencies:
//
//   1. `LiveThreadMonitor`:
//      Non-intrusively samples `IProcessSession::threads()` (plus cached
//      `IProcessSession::memory_regions()` stack attribution) without pausing
//      or stopping the target process, and supports offline seeding from
//      `ICrashDumpSession`. Tracks per-`ThreadIdentity` (`tid`,
//      `creation_identity`, `epoch`) continuous `ThreadStateSpan` intervals
//      and bounded `ThreadMetricPoint` CPU% delta + kernel-share + stack-depth
//      time-series rings with `Observed<T>` provenance.
//
//   2. `TimelineViewportIndex`:
//      Indexes `ExecutionTimeline` (`events()` + `thread_lanes()`) and optional
//      `LiveThreadMonitorSnapshot` onto a unified monotonic nanosecond axis
//      (with deterministic sequence-derived virtual nanosecond fallback when
//      `monotonic_ns == 0`). Builds per-lane sorted spans + binary power-of-two
//      mip LOD pyramids so querying `[view_start_ns, view_end_ns]` across
//      100,000-1,000,000+ spans runs in O(log N + K_visible) time, coalescing
//      sub-pixel spans into `CoalescedCluster` records while strictly preserving
//      visual priority (`DroppedEvents` > `DebuggerEvent` > `SamplingGap` >
//      `Syscall` > `SnapshotDelta` > `Running` > `Waiting`/`Sleeping`).
//
//   3. `rasterize_timeline_viewport_rgba8` / `rasterize_timeline_viewport_rgba8_into`:
//      Deterministic CPU reference rasterizer matching the Vulkan 2D SDF shader
//      (`timeline_span.vert.glsl` / `timeline_span.frag.glsl`) for headless
//      verification and automatic GPU fallback.

#include <peelf/crash_dump.hpp>
#include <peelf/error.hpp>
#include <peelf/execution_timeline.hpp>
#include <peelf/process.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/provenance.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace peelf {

inline constexpr std::uint32_t kInvalidTimelineHitId = 0xFFFF'FFFFu;
inline constexpr std::uint64_t kDefaultVirtualSequenceStepNs = 1'000ULL; // 1 us per synthetic sequence step
inline constexpr std::size_t kMinThreadMonitorRingCapacity = 64u;
inline constexpr std::size_t kDefaultThreadMonitorMetricCapacity = 8'192u;
inline constexpr std::size_t kDefaultThreadMonitorSpanCapacity = 8'192u;
inline constexpr std::size_t kMaxThreadMonitorRingCapacity = 65'536u;

[[nodiscard]] constexpr std::uint32_t pack_timeline_rgba8(
    std::uint8_t r,
    std::uint8_t g,
    std::uint8_t b,
    std::uint8_t a = 255u) noexcept {
    return static_cast<std::uint32_t>(r) |
           (static_cast<std::uint32_t>(g) << 8u) |
           (static_cast<std::uint32_t>(b) << 16u) |
           (static_cast<std::uint32_t>(a) << 24u);
}

// Continuous thread execution state tracked by `LiveThreadMonitor`.
enum class ThreadSpanState : std::uint8_t {
    Running = 0,
    Sleeping = 1,
    Waiting = 2,
    Stopped = 3,
    Zombie = 4,
    Syscall = 5,
    SamplingGap = 6,
};

[[nodiscard]] constexpr std::string_view to_string(ThreadSpanState state) noexcept {
    switch (state) {
        case ThreadSpanState::Running:     return "Running";
        case ThreadSpanState::Sleeping:    return "Sleeping";
        case ThreadSpanState::Waiting:     return "Waiting";
        case ThreadSpanState::Stopped:     return "Stopped";
        case ThreadSpanState::Zombie:      return "Zombie";
        case ThreadSpanState::Syscall:     return "Syscall";
        case ThreadSpanState::SamplingGap: return "Sampling Gap";
    }
    return "Running";
}

// Visual priority taxonomy ordered strictly ascending so `std::max(a, b)` selects
// the higher-priority visual kind during mip pyramid construction and sub-pixel
// cluster coalescing:
//   DroppedEvents > DebuggerEvent > SamplingGap > Syscall > SnapshotDelta >
//   Running > Zombie/Stopped > Waiting > Sleeping.
enum class TimelineVisualKind : std::uint8_t {
    Sleeping = 0,
    Waiting = 1,
    Stopped = 2,
    Zombie = 3,
    Running = 4,
    SnapshotDelta = 5,
    Syscall = 6,
    SamplingGap = 7,
    DebuggerEvent = 8,
    DroppedEvents = 9,
};

[[nodiscard]] constexpr std::string_view to_string(TimelineVisualKind kind) noexcept {
    switch (kind) {
        case TimelineVisualKind::Sleeping:      return "Sleeping";
        case TimelineVisualKind::Waiting:       return "Waiting";
        case TimelineVisualKind::Stopped:       return "Stopped";
        case TimelineVisualKind::Zombie:        return "Zombie";
        case TimelineVisualKind::Running:       return "Running";
        case TimelineVisualKind::SnapshotDelta: return "Snapshot Delta";
        case TimelineVisualKind::Syscall:       return "Syscall";
        case TimelineVisualKind::SamplingGap:   return "Sampling Gap";
        case TimelineVisualKind::DebuggerEvent: return "Debugger Event";
        case TimelineVisualKind::DroppedEvents: return "Dropped Events";
    }
    return "Running";
}

[[nodiscard]] constexpr TimelineVisualKind visual_kind_for_thread_state(
    ThreadSpanState state) noexcept {
    switch (state) {
        case ThreadSpanState::Running:     return TimelineVisualKind::Running;
        case ThreadSpanState::Sleeping:    return TimelineVisualKind::Sleeping;
        case ThreadSpanState::Waiting:     return TimelineVisualKind::Waiting;
        case ThreadSpanState::Stopped:     return TimelineVisualKind::Stopped;
        case ThreadSpanState::Zombie:      return TimelineVisualKind::Zombie;
        case ThreadSpanState::Syscall:     return TimelineVisualKind::Syscall;
        case ThreadSpanState::SamplingGap: return TimelineVisualKind::SamplingGap;
    }
    return TimelineVisualKind::Running;
}

[[nodiscard]] constexpr TimelineVisualKind visual_kind_for_timeline_event(
    TimelineEventKind kind) noexcept {
    switch (kind) {
        case TimelineEventKind::DroppedEvents: return TimelineVisualKind::DroppedEvents;
        case TimelineEventKind::DebuggerEvent: return TimelineVisualKind::DebuggerEvent;
        case TimelineEventKind::SamplingGap:   return TimelineVisualKind::SamplingGap;
        case TimelineEventKind::SyscallEntry:
        case TimelineEventKind::SyscallExit:   return TimelineVisualKind::Syscall;
        case TimelineEventKind::ModuleDelta:
        case TimelineEventKind::RegionDelta:
        case TimelineEventKind::ThreadDelta:
        case TimelineEventKind::HandleDelta:
        case TimelineEventKind::SocketDelta:   return TimelineVisualKind::SnapshotDelta;
    }
    return TimelineVisualKind::SnapshotDelta;
}

// Sampled continuous thread interval `[start_ns, end_ns]`.
struct ThreadStateSpan {
    std::uint64_t start_ns{0};
    std::uint64_t end_ns{0};
    ThreadSpanState state{ThreadSpanState::Running};
    std::uint32_t sample_count{1};
    std::optional<std::uint64_t> instruction_pointer{};
    std::optional<std::uint64_t> stack_pointer{};
    std::optional<std::int64_t> syscall_number{};
    std::string wait_channel{};
    float peak_cpu_ratio{0.0f};
    std::uint64_t peak_stack_depth_bytes{0};

    [[nodiscard]] constexpr std::uint64_t duration_ns() const noexcept {
        return end_ns >= start_ns ? (end_ns - start_ns) : 0ULL;
    }
};

// Instantaneous per-sample CPU% delta, kernel share, and stack depth.
struct ThreadMetricPoint {
    std::uint64_t timestamp_ns{0};
    float cpu_ratio{0.0f};          // Clamped to [0.0f, 1.0f].
    float kernel_share_ratio{0.0f}; // Clamped to [0.0f, 1.0f].
    std::uint64_t stack_depth_bytes{0};
    bool stack_depth_valid{false};
};

// Per-`ThreadIdentity` state & metric history produced by `LiveThreadMonitor`.
struct ThreadMonitorLane {
    ThreadIdentity identity{};
    std::string name{};
    bool active{true};
    bool tid_recycled{false};
    bool is_faulting_thread{false};
    ThreadSpanState latest_state{ThreadSpanState::Running};
    float latest_cpu_ratio{0.0f};
    float latest_kernel_share_ratio{0.0f};
    std::uint64_t latest_stack_depth_bytes{0};
    std::uint64_t high_water_stack_depth_bytes{0};
    std::uint64_t stack_low_address{0};
    std::uint64_t stack_high_address{0};
    std::optional<std::uint64_t> latest_instruction_pointer{};
    std::optional<std::uint64_t> latest_stack_pointer{};
    std::optional<std::int64_t> latest_syscall_number{};
    std::string latest_wait_channel{};
    std::uint64_t dropped_span_count{0};
    std::uint64_t dropped_metric_count{0};
    std::vector<ThreadStateSpan> spans{};
    std::vector<ThreadMetricPoint> metrics{};
};

struct LiveThreadMonitorSnapshot {
    std::uint32_t pid{0};
    std::uint64_t sample_sequence{0};
    std::uint64_t first_sample_ns{0};
    std::uint64_t last_sample_ns{0};
    bool seeded_from_crash_dump{false};
    std::vector<ThreadMonitorLane> lanes{};
};

struct LiveThreadMonitorConfig {
    std::size_t max_spans_per_lane{kDefaultThreadMonitorSpanCapacity};
    std::size_t max_metrics_per_lane{kDefaultThreadMonitorMetricCapacity};
    std::uint32_t region_refresh_stride_samples{16u};
    // When > 0 and consecutive samples exceed this wall delta, inserts an
    // explicit `SamplingGap` interval rather than stretching the prior span.
    std::uint64_t sampling_gap_threshold_ns{500'000'000ULL};
    // Minimum synthetic span duration assigned when seeding offline crash dumps.
    std::uint64_t crash_dump_span_duration_ns{1'000'000ULL};
};

using ThreadCreationIdentityResolver =
    std::function<std::uint64_t(std::uint32_t pid, std::uint32_t tid)>;

// Thread-safe non-intrusive sampler over `IProcessSession` / `ICrashDumpSession`.
// Never calls `suspend()`, `resume()`, `suspend_thread()`, or any mutating API.
class LiveThreadMonitor {
public:
    explicit LiveThreadMonitor(
        LiveThreadMonitorConfig config = {},
        ThreadCreationIdentityResolver identity_resolver = {});

    void reset() noexcept;
    void set_config(LiveThreadMonitorConfig config);
    [[nodiscard]] LiveThreadMonitorConfig config() const noexcept;

    // Samples `session.threads()` (and periodically refreshes cached
    // `session.memory_regions()` for stack bounds). Optional `explicit_timestamp_ns`
    // enables deterministic synthetic unit testing without wall-clock sleeps.
    [[nodiscard]] Result<std::size_t> sample(
        IProcessSession& session,
        std::stop_token stop_token = {},
        std::optional<std::uint64_t> explicit_timestamp_ns = std::nullopt);

    // Offline seeding from a crash dump (`Minidump` / `ELF Core`), populating
    // thread state spans, PC/SP addresses, stack depth against dump memory
    // regions, and faulting-thread provenance.
    [[nodiscard]] Result<std::size_t> seed_from_crash_dump(
        ICrashDumpSession& dump_session,
        std::optional<std::uint64_t> explicit_timestamp_ns = std::nullopt);

    [[nodiscard]] std::uint64_t sample_sequence() const noexcept;
    [[nodiscard]] std::size_t lane_count() const noexcept;
    [[nodiscard]] Observed<LiveThreadMonitorSnapshot> snapshot() const;

private:
    struct InternalLane {
        ThreadIdentity identity{};
        std::string name{};
        bool active{true};
        bool tid_recycled{false};
        bool is_faulting_thread{false};
        ThreadSpanState latest_state{ThreadSpanState::Running};
        float latest_cpu_ratio{0.0f};
        float latest_kernel_share_ratio{0.0f};
        std::uint64_t latest_stack_depth_bytes{0};
        std::uint64_t high_water_stack_depth_bytes{0};
        std::uint64_t stack_low_address{0};
        std::uint64_t stack_high_address{0};
        std::optional<std::uint64_t> latest_instruction_pointer{};
        std::optional<std::uint64_t> latest_stack_pointer{};
        std::optional<std::int64_t> latest_syscall_number{};
        std::string latest_wait_channel{};
        std::optional<std::uint64_t> prev_user_time_ns{};
        std::optional<std::uint64_t> prev_kernel_time_ns{};
        std::uint64_t last_sample_ns{0};
        std::uint64_t dropped_span_count{0};
        std::uint64_t dropped_metric_count{0};
        std::deque<ThreadStateSpan> spans{};
        std::deque<ThreadMetricPoint> metrics{};
    };

    struct TidTracker {
        std::uint32_t tid{0};
        std::uint64_t creation_identity{0};
        std::uint64_t epoch{1};
        std::size_t lane_index{0};
        bool currently_alive{false};
    };

    void refresh_cached_regions_locked(
        IProcessSession& session,
        std::span<const ThreadInfo> threads,
        bool force_refresh);

    [[nodiscard]] std::size_t resolve_or_create_lane_locked(
        std::uint32_t pid,
        const ThreadInfo& thread_info);

    mutable std::mutex mutex_{};
    LiveThreadMonitorConfig config_{};
    ThreadCreationIdentityResolver identity_resolver_{};
    std::uint32_t tracked_pid_{0};
    std::uint64_t sample_sequence_{0};
    std::uint64_t first_sample_ns_{0};
    std::uint64_t last_sample_ns_{0};
    std::uint32_t samples_since_region_refresh_{0};
    bool seeded_from_crash_dump_{false};
    bool region_cache_partial_{false};
    ProvenanceTag provenance_{ProvenanceTag::ProcOrOsApi};
    std::string provider_detail_{};
    std::vector<MemoryRegion> cached_regions_{};
    std::vector<InternalLane> lanes_{};
    std::vector<TidTracker> tid_trackers_{};
};

// ============================================================================
// GPU Instance Encoding (`TimelineGpuInstance`, `alignas(16)`, `sizeof == 32`)
// ============================================================================

enum class TimelineInstanceShape : std::uint8_t {
    RoundedSpan = 0,
    InstantDiamond = 1,
    HatchedUncertaintyBand = 2,
    SparklineColumn = 3,
    FlatRectOrLine = 4,
};

struct TimelineInstanceFlags {
    static constexpr std::uint32_t kShapeMask        = 0x0000'000Fu;
    static constexpr std::uint32_t kHovered          = 1u << 4u;
    static constexpr std::uint32_t kSelected         = 1u << 5u;
    static constexpr std::uint32_t kCoalescedCluster = 1u << 6u;
    static constexpr std::uint32_t kGlobalBand       = 1u << 7u;

    [[nodiscard]] static constexpr std::uint32_t pack(
        TimelineInstanceShape shape,
        std::uint32_t flags = 0u) noexcept {
        return (static_cast<std::uint32_t>(shape) & kShapeMask) | (flags & ~kShapeMask);
    }

    [[nodiscard]] static constexpr TimelineInstanceShape unpack_shape(
        std::uint32_t shape_and_flags) noexcept {
        const std::uint32_t raw = shape_and_flags & kShapeMask;
        if (raw <= static_cast<std::uint32_t>(TimelineInstanceShape::FlatRectOrLine)) {
            return static_cast<TimelineInstanceShape>(raw);
        }
        return TimelineInstanceShape::FlatRectOrLine;
    }
};

struct alignas(16) TimelineGpuInstance {
    float x0_px{0.0f};
    float y0_px{0.0f};
    float x1_px{0.0f};
    float y1_px{0.0f};
    std::uint32_t fill_rgba8{0u};
    std::uint32_t border_rgba8{0u};
    std::uint32_t shape_and_flags{0u};
    std::uint32_t hit_id{kInvalidTimelineHitId};
};

static_assert(sizeof(TimelineGpuInstance) == 32, "TimelineGpuInstance must be exactly 32 bytes");
static_assert(alignof(TimelineGpuInstance) == 16, "TimelineGpuInstance must be 16-byte aligned");
static_assert(std::is_trivially_copyable_v<TimelineGpuInstance>,
              "TimelineGpuInstance must be trivially copyable");

// ============================================================================
// Adaptive Nanosecond Ruler Formatting & Tick Generation
// ============================================================================

struct TimelineRulerTick {
    std::uint64_t timestamp_ns{0};
    float x_px{0.0f};
    bool is_major{false};
    std::string label{};
};

struct TimelineRulerConfig {
    std::uint64_t view_start_ns{0};
    std::uint64_t view_end_ns{1'000'000ULL};
    std::uint64_t origin_ns{0};
    float track_x0_px{0.0f};
    float track_width_px{800.0f};
    float target_major_spacing_px{110.0f};
};

struct TimelineRulerResult {
    std::uint64_t major_step_ns{1ULL};
    std::uint64_t minor_step_ns{1ULL};
    std::vector<TimelineRulerTick> ticks{};
};

[[nodiscard]] std::string format_timeline_duration_ns(std::uint64_t duration_ns);
[[nodiscard]] std::string format_timeline_offset_ns(
    std::int64_t delta_from_origin_ns,
    std::uint64_t step_ns = 1ULL);

[[nodiscard]] TimelineRulerResult generate_timeline_ruler_ticks(
    const TimelineRulerConfig& config);

// ============================================================================
// Hit-Testing & Coalesced LOD Cluster Metadata
// ============================================================================

enum class TimelineHitKind : std::uint8_t {
    None = 0,
    TimelineEvent = 1,
    ThreadStateSpan = 2,
    CoalescedCluster = 3,
};

[[nodiscard]] constexpr std::string_view to_string(TimelineHitKind kind) noexcept {
    switch (kind) {
        case TimelineHitKind::None:             return "None";
        case TimelineHitKind::TimelineEvent:    return "Timeline Event";
        case TimelineHitKind::ThreadStateSpan:  return "Thread State Span";
        case TimelineHitKind::CoalescedCluster: return "Coalesced Cluster";
    }
    return "None";
}

struct CoalescedClusterInfo {
    std::uint64_t min_start_ns{0};
    std::uint64_t max_end_ns{0};
    std::uint32_t merged_count{0};
    TimelineVisualKind dominant_kind{TimelineVisualKind::Running};
    float max_cpu_ratio{0.0f};
    std::uint64_t max_stack_depth_bytes{0};
    std::optional<std::uint64_t> representative_sequence{};
    std::optional<std::uint64_t> representative_va{};
};

struct TimelineHitRecord {
    std::uint32_t hit_id{kInvalidTimelineHitId};
    TimelineHitKind kind{TimelineHitKind::None};
    std::size_t lane_index{0};
    bool is_global_lane{false};
    bool is_foreground_item{true};
    std::optional<ThreadIdentity> thread{};
    float x0_px{0.0f};
    float y0_px{0.0f};
    float x1_px{0.0f};
    float y1_px{0.0f};
    std::uint64_t start_ns{0};
    std::uint64_t end_ns{0};
    TimelineVisualKind visual_kind{TimelineVisualKind::Running};
    std::optional<TimelineEventKind> event_kind{};
    std::optional<std::uint64_t> event_sequence{};
    std::optional<ThreadStateSpan> thread_span{};
    CoalescedClusterInfo cluster{};
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> stack_pointer{};
    ProvenanceTag provenance{ProvenanceTag::ProcOrOsApi};
    std::string summary{};
};

struct TimelineLaneLayout {
    std::size_t lane_index{0};
    bool is_global_lane{false};
    std::optional<ThreadIdentity> thread{};
    std::string label{};
    bool active{true};
    bool tid_recycled{false};
    bool is_faulting_thread{false};
    std::optional<ThreadSpanState> latest_state{};
    float latest_cpu_ratio{0.0f};
    std::uint64_t latest_stack_depth_bytes{0};
    std::uint64_t high_water_stack_depth_bytes{0};
    std::size_t total_item_count{0};
    float y0_px{0.0f};
    float y1_px{0.0f};
    float span_track_y0_px{0.0f};
    float span_track_y1_px{0.0f};
    float sparkline_y0_px{0.0f};
    float sparkline_y1_px{0.0f};
    std::uint32_t hit_begin{0};
    std::uint32_t hit_count{0};
};

// ============================================================================
// Hierarchical Multi-Resolution LOD Span Pyramid (`TimelineViewportIndex`)
// ============================================================================

struct TimelineBuildOptions {
    std::uint64_t virtual_sequence_step_ns{kDefaultVirtualSequenceStepNs};
    // Optional filter predicate for `ExecutionTimeline::events()`.
    std::function<bool(const TimelineEvent&)> event_filter{};
    // Optional lane filter (`std::nullopt` includes all lanes).
    std::optional<ThreadIdentity> filter_thread{};
    bool include_global_lane{true};
};

struct TimelineViewportQuery {
    std::uint64_t view_start_ns{0};
    std::uint64_t view_end_ns{1'000'000ULL};
    float viewport_width_px{960.0f};
    float viewport_height_px{480.0f};
    float ruler_height_px{26.0f};
    float lane_height_px{34.0f};
    float sparkline_height_px{16.0f};
    float lane_scroll_y_px{0.0f};
    float min_merge_px{1.5f};
    std::size_t max_instances{65'536u};
    bool show_sparklines{true};
    bool emit_ruler_and_separators{true};
    std::optional<std::uint64_t> selected_event_sequence{};
    std::optional<ThreadIdentity> selected_lane{};
};

struct TimelineViewportFrame {
    std::uint64_t view_start_ns{0};
    std::uint64_t view_end_ns{0};
    std::uint64_t origin_ns{0};
    float viewport_width_px{0.0f};
    float viewport_height_px{0.0f};
    float ruler_height_px{0.0f};
    float total_lanes_content_height_px{0.0f};
    std::size_t culled_subtree_nodes{0};
    std::size_t coalesced_cluster_count{0};
    TimelineRulerResult ruler{};
    std::vector<TimelineLaneLayout> lane_layouts{};
    std::vector<TimelineGpuInstance> instances{};
    std::vector<TimelineHitRecord> hit_records{};
};

struct TimelineHitQuery {
    float x_px{0.0f};
    float y_px{0.0f};
    float slop_px{4.0f};
};

class TimelineViewportIndex {
public:
    TimelineViewportIndex() = default;

    void clear() noexcept;

    void build(
        const ExecutionTimeline& timeline,
        const LiveThreadMonitorSnapshot* monitor_snapshot = nullptr,
        const TimelineBuildOptions& options = {});

    [[nodiscard]] bool empty() const noexcept { return total_indexed_items_ == 0u && lanes_.empty(); }
    [[nodiscard]] std::size_t lane_count() const noexcept { return lanes_.size(); }
    [[nodiscard]] std::size_t total_indexed_items() const noexcept { return total_indexed_items_; }
    [[nodiscard]] std::uint64_t origin_ns() const noexcept { return origin_ns_; }
    [[nodiscard]] std::uint64_t min_time_ns() const noexcept { return min_time_ns_; }
    [[nodiscard]] std::uint64_t max_time_ns() const noexcept { return max_time_ns_; }
    [[nodiscard]] bool uses_virtual_sequence_axis() const noexcept { return uses_virtual_axis_; }

    // Queries the multi-resolution LOD pyramid for `[view_start_ns, view_end_ns]`
    // in O(log N + K_visible) time and emits bounded `TimelineGpuInstance` quads.
    [[nodiscard]] TimelineViewportFrame query(
        const TimelineViewportQuery& params,
        std::stop_token stop_token = {}) const;

    // Spatial hit-testing from viewport-local `(x_px, y_px)` in O(log L + log K_lane).
    [[nodiscard]] static std::optional<TimelineHitRecord> hit_test(
        const TimelineViewportFrame& frame,
        const TimelineHitQuery& cursor) noexcept;

    // Resolves the lane index under `y_px`, even over empty lane background.
    [[nodiscard]] static std::optional<std::size_t> lane_at_y(
        const TimelineViewportFrame& frame,
        float y_px) noexcept;

private:
    struct BaseItem {
        std::uint64_t start_ns{0};
        std::uint64_t end_ns{0};
        TimelineVisualKind visual_kind{TimelineVisualKind::Running};
        bool is_thread_state_span{false};
        bool is_uncertainty{false};
        std::optional<TimelineEventKind> event_kind{};
        std::optional<std::uint64_t> event_sequence{};
        ThreadStateSpan thread_span{};
        float cpu_ratio{0.0f};
        std::uint64_t stack_depth_bytes{0};
        std::optional<std::uint64_t> virtual_address{};
        std::optional<std::uint64_t> stack_pointer{};
        ProvenanceTag provenance{ProvenanceTag::ProcOrOsApi};
        std::string summary{};
    };

    struct MipNode {
        std::uint64_t min_start_ns{0};
        std::uint64_t max_end_ns{0};
        std::uint32_t first_base_index{0};
        std::uint32_t item_count{0};
        std::uint32_t representative_base_index{0};
        TimelineVisualKind dominant_kind{TimelineVisualKind::Running};
        float max_cpu_ratio{0.0f};
        std::uint64_t max_stack_depth_bytes{0};
        bool has_uncertainty{false};
    };

    struct MipPyramid {
        std::vector<BaseItem> base_items{};
        // Level 0 mirrors `base_items` 1:1; Level k merges pairs of Level k-1.
        std::vector<std::vector<MipNode>> levels{};

        void build_from_unsorted(std::vector<BaseItem> items);
    };

    struct MetricMipNode {
        std::uint64_t min_ts_ns{0};
        std::uint64_t max_ts_ns{0};
        float max_cpu_ratio{0.0f};
        float max_kernel_share_ratio{0.0f};
        std::uint64_t max_stack_depth_bytes{0};
        bool any_stack_valid{false};
    };

    struct MetricPyramid {
        std::vector<ThreadMetricPoint> points{};
        std::vector<std::vector<MetricMipNode>> levels{};

        void build_from_points(std::span<const ThreadMetricPoint> src);
    };

    struct IndexedLane {
        bool is_global_lane{false};
        std::optional<ThreadIdentity> thread{};
        std::string label{};
        bool active{true};
        bool tid_recycled{false};
        bool is_faulting_thread{false};
        std::optional<ThreadSpanState> latest_state{};
        float latest_cpu_ratio{0.0f};
        std::uint64_t latest_stack_depth_bytes{0};
        std::uint64_t high_water_stack_depth_bytes{0};
        MipPyramid state_pyramid{};
        MipPyramid event_pyramid{};
        MetricPyramid metric_pyramid{};
    };

    std::vector<IndexedLane> lanes_{};
    std::size_t total_indexed_items_{0};
    std::uint64_t origin_ns_{0};
    std::uint64_t min_time_ns_{0};
    std::uint64_t max_time_ns_{0};
    bool uses_virtual_axis_{false};
};

// ============================================================================
// Deterministic CPU Reference Rasterizer (RGBA8)
// ============================================================================

struct TimelineRasterConfig {
    std::uint32_t width{0};
    std::uint32_t height{0};
    std::uint32_t clear_rgba8{pack_timeline_rgba8(14u, 16u, 22u, 255u)};
    float corner_radius_px{3.0f};
    float border_width_px{1.0f};
    float hatch_period_px{8.0f};
    std::uint32_t hovered_hit_id{kInvalidTimelineHitId};
    std::uint32_t selected_hit_id{kInvalidTimelineHitId};
};

void rasterize_timeline_viewport_rgba8_into(
    std::span<const TimelineGpuInstance> instances,
    const TimelineRasterConfig& config,
    std::vector<std::uint8_t>& out_rgba8,
    std::stop_token stop_token = {});

[[nodiscard]] std::vector<std::uint8_t> rasterize_timeline_viewport_rgba8(
    std::span<const TimelineGpuInstance> instances,
    const TimelineRasterConfig& config,
    std::stop_token stop_token = {});

// Canonical color palette helpers shared by GPU & UI legend badges.
[[nodiscard]] constexpr std::uint32_t timeline_fill_color_rgba8(
    TimelineVisualKind kind,
    std::uint8_t alpha = 230u) noexcept {
    switch (kind) {
        case TimelineVisualKind::DroppedEvents:
            return pack_timeline_rgba8(228u, 72u, 72u, alpha);
        case TimelineVisualKind::DebuggerEvent:
            return pack_timeline_rgba8(245u, 148u, 56u, alpha);
        case TimelineVisualKind::SamplingGap:
            return pack_timeline_rgba8(215u, 178u, 64u, alpha);
        case TimelineVisualKind::Syscall:
            return pack_timeline_rgba8(192u, 118u, 242u, alpha);
        case TimelineVisualKind::SnapshotDelta:
            return pack_timeline_rgba8(82u, 178u, 245u, alpha);
        case TimelineVisualKind::Running:
            return pack_timeline_rgba8(68u, 206u, 126u, alpha);
        case TimelineVisualKind::Stopped:
            return pack_timeline_rgba8(228u, 114u, 88u, alpha);
        case TimelineVisualKind::Zombie:
            return pack_timeline_rgba8(152u, 96u, 116u, alpha);
        case TimelineVisualKind::Waiting:
            return pack_timeline_rgba8(116u, 138u, 178u, alpha);
        case TimelineVisualKind::Sleeping:
            return pack_timeline_rgba8(74u, 92u, 124u, alpha);
    }
    return pack_timeline_rgba8(82u, 178u, 245u, alpha);
}

[[nodiscard]] constexpr std::uint32_t timeline_border_color_rgba8(
    TimelineVisualKind kind,
    std::uint8_t alpha = 255u) noexcept {
    switch (kind) {
        case TimelineVisualKind::DroppedEvents:
            return pack_timeline_rgba8(255u, 132u, 132u, alpha);
        case TimelineVisualKind::DebuggerEvent:
            return pack_timeline_rgba8(255u, 206u, 122u, alpha);
        case TimelineVisualKind::SamplingGap:
            return pack_timeline_rgba8(248u, 218u, 120u, alpha);
        case TimelineVisualKind::Syscall:
            return pack_timeline_rgba8(228u, 178u, 255u, alpha);
        case TimelineVisualKind::SnapshotDelta:
            return pack_timeline_rgba8(148u, 218u, 255u, alpha);
        case TimelineVisualKind::Running:
            return pack_timeline_rgba8(136u, 244u, 178u, alpha);
        case TimelineVisualKind::Stopped:
            return pack_timeline_rgba8(255u, 170u, 148u, alpha);
        case TimelineVisualKind::Zombie:
            return pack_timeline_rgba8(198u, 142u, 162u, alpha);
        case TimelineVisualKind::Waiting:
            return pack_timeline_rgba8(162u, 184u, 222u, alpha);
        case TimelineVisualKind::Sleeping:
            return pack_timeline_rgba8(116u, 138u, 174u, alpha);
    }
    return pack_timeline_rgba8(148u, 218u, 255u, alpha);
}

} // namespace peelf
