#pragma once

#include <peelf/capability_matrix.hpp>
#include <peelf/debugger.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/provenance.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace peelf {

/// Event categories unified onto the monotonic `ExecutionTimeline` axis (`WU-24`).
enum class TimelineEventKind : std::uint8_t {
    DebuggerEvent = 0,
    ModuleDelta,
    RegionDelta,
    ThreadDelta,
    HandleDelta,
    SocketDelta,
    SyscallEntry,
    SyscallExit,
    DroppedEvents,
    SamplingGap,
};

inline constexpr std::size_t kTimelineEventKindCount = 10u;

[[nodiscard]] constexpr std::string_view to_string(TimelineEventKind kind) noexcept {
    switch (kind) {
        case TimelineEventKind::DebuggerEvent: return "DebuggerEvent";
        case TimelineEventKind::ModuleDelta:   return "ModuleDelta";
        case TimelineEventKind::RegionDelta:   return "RegionDelta";
        case TimelineEventKind::ThreadDelta:   return "ThreadDelta";
        case TimelineEventKind::HandleDelta:   return "HandleDelta";
        case TimelineEventKind::SocketDelta:   return "SocketDelta";
        case TimelineEventKind::SyscallEntry:  return "SyscallEntry";
        case TimelineEventKind::SyscallExit:   return "SyscallExit";
        case TimelineEventKind::DroppedEvents: return "DroppedEvents";
        case TimelineEventKind::SamplingGap:   return "SamplingGap";
    }
    return "DebuggerEvent";
}

[[nodiscard]] constexpr bool is_timeline_uncertainty_marker(TimelineEventKind kind) noexcept {
    return kind == TimelineEventKind::DroppedEvents || kind == TimelineEventKind::SamplingGap;
}

[[nodiscard]] constexpr bool is_timeline_snapshot_delta(TimelineEventKind kind) noexcept {
    switch (kind) {
        case TimelineEventKind::ModuleDelta:
        case TimelineEventKind::RegionDelta:
        case TimelineEventKind::ThreadDelta:
        case TimelineEventKind::HandleDelta:
        case TimelineEventKind::SocketDelta:
            return true;
        default:
            return false;
    }
}

/// Unique identity of a single OS thread lifetime on the execution timeline.
/// Combines `ThreadId`, optional OS creation timestamp/ticks (`creation_identity`),
/// and a monotonic per-TID collector `epoch` (`1, 2, ...`) so recycled OS TIDs
/// never merge onto the same thread swimlane.
struct ThreadIdentity {
    ThreadId tid{0};
    std::optional<std::uint64_t> creation_identity{};
    std::uint64_t epoch{1};

    /// Returns true when two `ThreadIdentity` tags refer to the same thread lane.
    /// Allows an observation without OS `creation_identity` (e.g. a fast debugger trap)
    /// to match a snapshot observation of the same live `(tid, epoch)`, while strictly
    /// separating distinct epochs or conflicting `creation_identity` stamps.
    [[nodiscard]] constexpr bool same_lane(const ThreadIdentity& other) const noexcept {
        if (tid == 0u || tid != other.tid || epoch != other.epoch) {
            return false;
        }
        if (creation_identity.has_value() && other.creation_identity.has_value()) {
            return *creation_identity == *other.creation_identity;
        }
        return true;
    }

    auto operator<=>(const ThreadIdentity&) const = default;
};

/// Bounded `[earliest, latest]` observation window attached to snapshot-derived
/// timeline events and `SamplingGap` markers (`WU-24`).
struct TimelineInterval {
    CaptureStamp earliest{};
    CaptureStamp latest{};

    [[nodiscard]] constexpr std::uint64_t duration_ns() const noexcept {
        return latest.monotonic_ns >= earliest.monotonic_ns
                   ? (latest.monotonic_ns - earliest.monotonic_ns)
                   : 0u;
    }

    [[nodiscard]] constexpr std::uint64_t duration_unix_ms() const noexcept {
        return latest.captured_unix_ms >= earliest.captured_unix_ms
                   ? (latest.captured_unix_ms - earliest.captured_unix_ms)
                   : 0u;
    }

    auto operator<=>(const TimelineInterval&) const = default;
};

/// Payload for optional syscall stop / kernel trace events (`SyscallEntry` / `SyscallExit`).
struct SyscallEventPayload {
    std::uint64_t syscall_number{0};
    std::string name{};
    std::array<std::uint64_t, 6> arguments{0, 0, 0, 0, 0, 0};
    std::uint8_t argument_count{0};
    std::optional<std::int64_t> return_value{};
    std::optional<std::uint64_t> instruction_pointer{};
    std::string detail{};

    auto operator<=>(const SyscallEventPayload&) const = default;
};

/// Explicit accounting payload emitted when ring capacity or producer poll buffers overflow.
struct DroppedEventsPayload {
    std::uint64_t dropped_count{0};
    std::uint64_t first_dropped_sequence{0};
    std::uint64_t last_dropped_sequence{0};
    std::string source_name{};
    std::string reason{};

    auto operator<=>(const DroppedEventsPayload&) const = default;
};

/// Explicit interval uncertainty marker emitted between non-continuous process snapshots.
struct SamplingGapPayload {
    std::uint64_t before_revision{0};
    std::uint64_t after_revision{0};
    std::uint64_t unobserved_monotonic_ns{0};
    std::uint64_t unobserved_unix_ms{0};
    bool target_executed_unobserved{true};
    std::vector<SnapshotUncertainty> uncertainties{};
    std::string reason{};

    auto operator<=>(const SamplingGapPayload&) const = default;
};

/// Variant payload carried by every `TimelineEvent`.
using TimelinePayload = std::variant<
    std::monostate,
    debugger::DebugEvent,
    ModuleDelta,
    RegionDelta,
    ThreadDelta,
    HandleDelta,
    SocketDelta,
    SyscallEventPayload,
    DroppedEventsPayload,
    SamplingGapPayload>;

/// Single ordered observation or uncertainty marker in `ExecutionTimeline`.
struct TimelineEvent {
    std::uint64_t sequence{0};
    TimelineEventKind kind{TimelineEventKind::DebuggerEvent};
    CaptureStamp stamp{};
    std::optional<TimelineInterval> observation_interval{};
    std::optional<ThreadIdentity> thread{};
    std::optional<std::uint64_t> virtual_address{};
    ProvenanceTag provenance{ProvenanceTag::ProcOrOsApi};
    std::string summary{};
    TimelinePayload payload{};

    [[nodiscard]] constexpr bool is_global_lane() const noexcept {
        return !thread.has_value() || thread->tid == 0u;
    }
};

/// Metadata describing one per-`ThreadIdentity` swimlane tracked by `ExecutionTimeline`.
struct TimelineLane {
    ThreadIdentity identity{};
    std::string name{};
    bool active{true};
    bool tid_recycled{false};
    std::uint64_t event_count{0};
    std::uint64_t first_sequence{0};
    std::uint64_t last_sequence{0};
};

/// Primary viewer destination for click-to-navigate on a `TimelineEvent`.
enum class TimelineTargetPanel : std::uint8_t {
    None = 0,
    Disassembly,
    Hex,
    ProcessInternals,
    Debugger,
    ExecutableSettings,
};

[[nodiscard]] constexpr std::string_view to_string(TimelineTargetPanel panel) noexcept {
    switch (panel) {
        case TimelineTargetPanel::None:               return "None";
        case TimelineTargetPanel::Disassembly:        return "Disassembly";
        case TimelineTargetPanel::Hex:                return "Hex";
        case TimelineTargetPanel::ProcessInternals:   return "Process Internals";
        case TimelineTargetPanel::Debugger:           return "Debugger";
        case TimelineTargetPanel::ExecutableSettings: return "Executable Settings";
    }
    return "None";
}

/// Pure navigation payload resolved from a `TimelineEvent` for deferred UI dispatch.
struct TimelineNavigationTarget {
    TimelineTargetPanel primary_panel{TimelineTargetPanel::None};
    std::optional<std::uint64_t> virtual_address{};
    std::uint64_t byte_size{0};
    std::optional<ThreadIdentity> thread{};
    std::optional<std::uint64_t> snapshot_revision{};
    bool executable_target{false};
    std::string description{};
};

/// Computes the canonical deferred navigation target (`Disassembly`, `Hex`,
/// `Process Internals`, `Debugger`, or `Executable Settings`) for `event`,
/// optionally overriding `primary_panel` while retaining resolved address/thread context.
[[nodiscard]] TimelineNavigationTarget resolve_timeline_navigation(
    const TimelineEvent& event,
    std::optional<TimelineTargetPanel> override_panel = std::nullopt);

// ---------------------------------------------------------------------------
// Extensible `ITimelineSource` Provider Contract (`WU-24`)
// ---------------------------------------------------------------------------

enum class TimelineSourceKind : std::uint8_t {
    DebuggerEvents = 0,
    SnapshotDiffPoller,
    SyscallTrace,
    EtwOrKernelTrace,
    RemoteStubStream,
    Custom,
};

[[nodiscard]] constexpr std::string_view to_string(TimelineSourceKind kind) noexcept {
    switch (kind) {
        case TimelineSourceKind::DebuggerEvents:     return "DebuggerEvents";
        case TimelineSourceKind::SnapshotDiffPoller: return "SnapshotDiffPoller";
        case TimelineSourceKind::SyscallTrace:       return "SyscallTrace";
        case TimelineSourceKind::EtwOrKernelTrace:   return "EtwOrKernelTrace";
        case TimelineSourceKind::RemoteStubStream:   return "RemoteStubStream";
        case TimelineSourceKind::Custom:             return "Custom";
    }
    return "Custom";
}

struct TimelineSourceDescriptor {
    TimelineSourceKind kind{TimelineSourceKind::Custom};
    std::string name{};
    SupportState support_state{SupportState::Unsupported};
    bool provider_available{false};
    ProvenanceTag provenance{ProvenanceTag::ProcOrOsApi};
    SubsystemStatus status{};

    [[nodiscard]] constexpr bool is_supported() const noexcept {
        return support_state != SupportState::Unsupported;
    }

    [[nodiscard]] constexpr bool can_poll() const noexcept {
        return is_supported() && provider_available;
    }
};

class ExecutionTimeline;

/// Extensible event-stream producer feeding `ExecutionTimeline`.
/// Optional sources lacking a validated backend (such as kernel syscall stop tracing
/// or ETW kernel providers) report `SupportState::Unsupported` honestly rather than
/// pretending to capture zero events silently.
class ITimelineSource {
public:
    virtual ~ITimelineSource() = default;

    [[nodiscard]] virtual TimelineSourceDescriptor descriptor() const = 0;
    [[nodiscard]] virtual SupportState support_state() const noexcept = 0;

    /// Drains newly observed events into `timeline`, returning the count of timeline
    /// records (including any `DroppedEvents` / `SamplingGap` markers) emitted.
    /// Returns an error when `support_state() == SupportState::Unsupported` or the
    /// underlying session failed.
    [[nodiscard]] virtual Result<std::size_t> poll(ExecutionTimeline& timeline) = 0;

    virtual void reset() noexcept = 0;
};

/// Options controlling `ExecutionTimeline::ingest_snapshot_diff`.
struct SnapshotTimelineIngestOptions {
    /// Set true only when the target process was held paused continuously across the
    /// entire `[before_stamp, after_stamp]` window with zero resumed execution in between.
    bool target_continuously_paused{false};
};

/// Bounded-capacity multi-thread execution & state-delta timeline collector (`WU-24`).
///
/// Guarantees:
/// - Strictly monotonic `sequence` numbers across interleaved `debugger::DebugEvent`s,
///   `SnapshotDiff` deltas, syscall records, and uncertainty markers.
/// - Never silently evicts old events on capacity overflow: coalesces evicted events into
///   an explicit front `TimelineEventKind::DroppedEvents` marker with overflow-checked
///   exact `dropped_count` conservation (`sum(DroppedEvents.dropped_count) == total_dropped_events()`).
/// - Automatically inserts `TimelineEventKind::SamplingGap` across non-continuous snapshot
///   intervals `[earliest, latest]`.
/// - Tracks per-TID creation identities & epochs so recycled OS TIDs always occupy
///   distinct `ThreadIdentity` lanes.
class ExecutionTimeline {
public:
    static constexpr std::size_t kDefaultCapacity = 4096u;
    static constexpr std::size_t kMinCapacity = 2u;

    explicit ExecutionTimeline(std::size_t max_events = kDefaultCapacity);

    void set_target_instance(TargetInstanceId target_id) noexcept { target_id_ = std::move(target_id); }
    [[nodiscard]] const TargetInstanceId& target_instance() const noexcept { return target_id_; }

    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    void set_capacity(std::size_t max_events);

    [[nodiscard]] std::size_t size() const noexcept { return events_.size(); }
    [[nodiscard]] bool empty() const noexcept { return events_.empty(); }
    [[nodiscard]] const std::deque<TimelineEvent>& events() const noexcept { return events_; }
    [[nodiscard]] const TimelineEvent* find_event(std::uint64_t sequence) const noexcept;

    [[nodiscard]] std::span<const TimelineLane> thread_lanes() const noexcept { return lanes_; }
    [[nodiscard]] const TimelineLane* find_lane(const ThreadIdentity& identity) const noexcept;

    [[nodiscard]] std::uint64_t next_sequence() const noexcept { return next_sequence_; }
    [[nodiscard]] std::uint64_t total_emitted_events() const noexcept { return total_emitted_events_; }
    [[nodiscard]] std::uint64_t total_dropped_events() const noexcept { return total_dropped_events_; }
    [[nodiscard]] std::uint64_t sampling_gap_count() const noexcept { return sampling_gap_count_; }
    [[nodiscard]] std::uint64_t event_kind_count(TimelineEventKind kind) const noexcept;

    void clear(bool reset_sources = false) noexcept;

    /// Pre-populates known live thread identities (`tid`, `creation_identity`, `name`) from an
    /// initial baseline `ProcessStateSnapshot` without emitting synthetic delta events.
    void seed_threads_from_snapshot(const ProcessStateSnapshot& snapshot);

    /// Ingests a discrete `debugger::DebugEvent`, assigning the next monotonic collector
    /// `sequence` and resolving the appropriate `Process / Global` or `ThreadIdentity` lane.
    std::uint64_t ingest_debug_event(
        const debugger::DebugEvent& event,
        std::optional<CaptureStamp> stamp = std::nullopt,
        std::optional<std::uint64_t> thread_creation_identity = std::nullopt,
        std::string_view thread_name = {});

    /// Ingests all deltas from a `TargetInstanceId`-verified `SnapshotDiff`, automatically
    /// emitting `SamplingGap` markers across non-continuous capture intervals and tagging
    /// every delta with `[before_stamp, after_stamp]` observation bounds.
    /// Returns the number of timeline records emitted (`0` if `diff.rejected_target_mismatch`).
    std::size_t ingest_snapshot_diff(
        const SnapshotDiff& diff,
        const SnapshotTimelineIngestOptions& options = {});

    /// Ingests a syscall entry or exit record onto its `ThreadIdentity` lane.
    std::uint64_t ingest_syscall_event(
        bool is_exit,
        ThreadId tid,
        SyscallEventPayload payload,
        std::optional<CaptureStamp> stamp = std::nullopt,
        std::optional<std::uint64_t> thread_creation_identity = std::nullopt,
        std::string_view thread_name = {});

    /// Explicitly records `dropped_count` events lost upstream (e.g. debugger ring overflow)
    /// at the current point in the monotonic timeline stream.
    std::uint64_t record_dropped_events(
        std::uint64_t dropped_count,
        std::optional<CaptureStamp> stamp = std::nullopt,
        std::string_view source_name = "timeline",
        std::string_view reason = "Producer event buffer overflowed");

    // --- Extensible `ITimelineSource` Registration & Polling ---
    void register_source(std::shared_ptr<ITimelineSource> source);
    void clear_sources() noexcept { sources_.clear(); }
    [[nodiscard]] std::span<const std::shared_ptr<ITimelineSource>> sources() const noexcept {
        return sources_;
    }
    [[nodiscard]] std::vector<TimelineSourceDescriptor> source_descriptors() const;

    /// Polls all registered sources whose `descriptor().can_poll()` is true, skipping
    /// `Unsupported` sources cleanly and returning total newly emitted events.
    ForgivingValue<std::size_t> poll_sources();

private:
    struct ActiveTidState {
        std::uint64_t current_epoch{0};
        std::optional<std::uint64_t> creation_identity{};
        bool active{false};
    };

    [[nodiscard]] CaptureStamp resolve_or_stamp_now(
        std::optional<CaptureStamp> provided,
        bool paused_default) const;

    ThreadIdentity resolve_thread_for_observation(
        ThreadId tid,
        std::optional<std::uint64_t> creation_identity,
        std::string_view thread_name,
        bool force_new_lifetime,
        bool mark_exited_after);

    TimelineLane& ensure_lane(
        const ThreadIdentity& identity,
        std::string_view thread_name,
        bool recycled_tid);

    std::uint64_t append_event(TimelineEvent event);
    void enforce_capacity_before_push(const CaptureStamp& fallback_stamp);

    TargetInstanceId target_id_{};
    std::size_t capacity_{kDefaultCapacity};
    std::uint64_t next_sequence_{1};
    std::uint64_t total_emitted_events_{0};
    std::uint64_t total_dropped_events_{0};
    std::uint64_t sampling_gap_count_{0};
    std::array<std::uint64_t, kTimelineEventKindCount> kind_counts_{};

    std::optional<CaptureStamp> last_snapshot_after_stamp_{};
    std::deque<TimelineEvent> events_{};
    std::vector<TimelineLane> lanes_{};
    std::vector< std::pair<ThreadId, ActiveTidState> > tid_states_{};
    std::vector<std::shared_ptr<ITimelineSource>> sources_{};
};

/// Concrete `ITimelineSource` polling `debugger::IDebugSession::events()`, automatically
/// detecting sequence gaps when the debugger's internal event deque wraps between polls.
class DebugSessionTimelineSource final : public ITimelineSource {
public:
    using ThreadCreationIdentityQuery =
        std::function<std::optional<std::uint64_t>(ProcessId, ThreadId)>;

    explicit DebugSessionTimelineSource(
        std::shared_ptr<debugger::IDebugSession> session,
        TargetInstanceId target_id = {},
        ThreadCreationIdentityQuery creation_query = query_thread_creation_identity);

    [[nodiscard]] TimelineSourceDescriptor descriptor() const override;
    [[nodiscard]] SupportState support_state() const noexcept override;
    [[nodiscard]] Result<std::size_t> poll(ExecutionTimeline& timeline) override;
    void reset() noexcept override;

    [[nodiscard]] std::uint64_t last_polled_sequence() const noexcept {
        return last_polled_sequence_;
    }

private:
    std::shared_ptr<debugger::IDebugSession> session_{};
    TargetInstanceId target_id_{};
    ThreadCreationIdentityQuery creation_query_{};
    std::uint64_t last_polled_sequence_{0};
    std::vector<std::pair<ThreadId, std::optional<std::uint64_t>>> cached_tid_identities_{};
};

/// Honest placeholder `ITimelineSource` reporting `SupportState::Unsupported` for optional
/// kernel/OS telemetry streams (syscall stop tracing, ETW kernel providers) that are not
/// backed by an active provider.
class UnsupportedTimelineSource final : public ITimelineSource {
public:
    UnsupportedTimelineSource(
        TimelineSourceKind kind,
        std::string name,
        std::string reason);

    [[nodiscard]] TimelineSourceDescriptor descriptor() const override;
    [[nodiscard]] SupportState support_state() const noexcept override {
        return SupportState::Unsupported;
    }
    [[nodiscard]] Result<std::size_t> poll(ExecutionTimeline& timeline) override;
    void reset() noexcept override {}

private:
    TimelineSourceKind kind_{TimelineSourceKind::Custom};
    std::string name_{};
    std::string reason_{};
};

[[nodiscard]] std::shared_ptr<ITimelineSource> create_syscall_timeline_source();
[[nodiscard]] std::shared_ptr<ITimelineSource> create_etw_timeline_source();

}  // namespace peelf
