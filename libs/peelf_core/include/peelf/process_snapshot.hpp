#pragma once

#include <peelf/executable_settings.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/provenance.hpp>
#include <peelf/stack_tls.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

/// Query OS-specific thread creation timestamp/ticks for `(pid, tid)` when accessible
/// (Linux `/proc/<pid>/task/<tid>/stat` field 22 `starttime`; Win32 `GetThreadTimes`
/// `CreationTime`) so TID reuse never silently equates unrelated threads.
[[nodiscard]] std::optional<std::uint64_t> query_thread_creation_identity(
    ProcessId pid,
    ThreadId tid) noexcept;

/// Point-in-time per-thread capture combining OS `ThreadInfo`, optional `ThreadContext`,
/// bounded stack bytes with per-byte validity (`MemorySample::valid`), and unwound top frames.
struct ThreadSnapshot {
    ThreadInfo info{};
    std::optional<std::uint64_t> creation_identity{};
    Observed<ThreadContext> context{};
    std::uint64_t stack_capture_address{0};
    MemorySample stack_bytes{};
    std::vector<StackFrame> top_frames{};
};

/// Options controlling `capture_process_snapshot`.
struct CaptureOptions {
    std::optional<TargetInstanceId> target_id{};
    std::uint64_t snapshot_revision{0};  ///< 0 = assign next monotonic process-snapshot revision.
    bool pause_target_during_capture{false};
    bool capture_thread_contexts{true};
    bool capture_thread_stacks{true};
    std::size_t max_stack_bytes_per_thread{4096u};
    bool unwind_top_frames{true};
    std::size_t max_unwind_frames{16u};
    bool capture_handles_and_sockets{true};
    bool capture_environment{true};
    EnvironmentRedactionPolicy environment_redaction_policy{
        EnvironmentRedactionPolicy::RedactSensitiveDefault};
    bool launched_by_session{false};
    bool probe_module_identities{false};
};

/// Immutable point-in-time snapshot of an attached process or crash dump (`WU-23`).
/// Every collection carries its own independent `CaptureStamp` recording exact capture
/// time, `TargetInstanceId`, pause state, and `CaptureAvailability`.
struct ProcessStateSnapshot {
    TargetInstanceId target_id{};
    std::uint64_t snapshot_revision{0};
    CaptureStamp snapshot_stamp{};
    ProcessInfo process_info{};
    bool paused_during_capture{false};

    Observed<std::vector<ModuleInfo>> modules{};
    std::vector<std::pair<std::uint64_t, BackingImageIdentity>> module_identities{};
    Observed<std::vector<MemoryRegion>> regions{};
    Observed<std::vector<ThreadSnapshot>> threads{};
    Observed<std::vector<ProcessHandleEntry>> handles{};
    Observed<std::vector<ProcessSocketEntry>> sockets{};
    Observed<ProcessSecurityProfile> security{};
    Observed<LaunchEnvironmentSettings> launch_environment{};
};

/// Captures a timestamped `ProcessStateSnapshot` from `session`, stamping each collection
/// (`modules`, `regions`, `threads`, `handles`, `sockets`, `security`, `launch_environment`)
/// with its own accurate per-collection `CaptureStamp`.
[[nodiscard]] ProcessStateSnapshot capture_process_snapshot(
    IProcessSession& session,
    const CaptureOptions& options = {});

/// Populates `report.launch_environment` and `report.observed_runtime` directly from an
/// already-captured `ProcessStateSnapshot` without re-querying OS handles/threads.
void populate_runtime_settings_from_snapshot(
    ExecutableSettingsReport& report,
    const ProcessStateSnapshot& snapshot,
    std::span<const std::uint64_t> timeline_proven_dynamic_bases = {});

// ---------------------------------------------------------------------------
// Interval- & Identity-Aware `SnapshotDiff` (`WU-23`)
// ---------------------------------------------------------------------------

enum class DiffDomain : std::uint8_t {
    TargetIdentity = 0,
    Modules,
    Regions,
    Threads,
    Handles,
    Sockets,
};

[[nodiscard]] constexpr std::string_view to_string(DiffDomain domain) noexcept {
    switch (domain) {
        case DiffDomain::TargetIdentity: return "TargetIdentity";
        case DiffDomain::Modules:        return "Modules";
        case DiffDomain::Regions:        return "Regions";
        case DiffDomain::Threads:        return "Threads";
        case DiffDomain::Handles:        return "Handles";
        case DiffDomain::Sockets:        return "Sockets";
    }
    return "TargetIdentity";
}

enum class DiffUncertaintyKind : std::uint8_t {
    TargetIdentityMismatch = 0,
    CollectionUnavailable,
    PartialBeforeCapture,
    PartialAfterCapture,
    PartialBothCaptures,
};

[[nodiscard]] constexpr std::string_view to_string(DiffUncertaintyKind kind) noexcept {
    switch (kind) {
        case DiffUncertaintyKind::TargetIdentityMismatch: return "TargetIdentityMismatch";
        case DiffUncertaintyKind::CollectionUnavailable:  return "CollectionUnavailable";
        case DiffUncertaintyKind::PartialBeforeCapture:   return "PartialBeforeCapture";
        case DiffUncertaintyKind::PartialAfterCapture:    return "PartialAfterCapture";
        case DiffUncertaintyKind::PartialBothCaptures:    return "PartialBothCaptures";
    }
    return "CollectionUnavailable";
}

struct SnapshotUncertainty {
    DiffDomain domain{DiffDomain::TargetIdentity};
    DiffUncertaintyKind kind{DiffUncertaintyKind::CollectionUnavailable};
    CaptureAvailability before_availability{CaptureAvailability::Unavailable};
    CaptureAvailability after_availability{CaptureAvailability::Unavailable};
    std::size_t suppressed_removal_count{0};
    std::size_t suppressed_addition_count{0};
    std::string message{};

    auto operator<=>(const SnapshotUncertainty&) const = default;
};

enum class ModuleDeltaKind : std::uint8_t {
    Loaded = 0,
    Unloaded,
    Relocated,
    Modified,
};

[[nodiscard]] constexpr std::string_view to_string(ModuleDeltaKind kind) noexcept {
    switch (kind) {
        case ModuleDeltaKind::Loaded:    return "Loaded";
        case ModuleDeltaKind::Unloaded:  return "Unloaded";
        case ModuleDeltaKind::Relocated: return "Relocated";
        case ModuleDeltaKind::Modified:  return "Modified";
    }
    return "Loaded";
}

struct ModuleDelta {
    ModuleDeltaKind kind{ModuleDeltaKind::Loaded};
    std::optional<ModuleInfo> before{};
    std::optional<ModuleInfo> after{};
    bool base_address_reused{false};
    bool backing_identity_changed{false};
    std::string detail{};
};

enum class RegionDeltaKind : std::uint8_t {
    Mapped = 0,
    Unmapped,
    ProtectionChanged,
    BackingChanged,
    Split,
    Merged,
    ResidentChanged,
};

[[nodiscard]] constexpr std::string_view to_string(RegionDeltaKind kind) noexcept {
    switch (kind) {
        case RegionDeltaKind::Mapped:            return "Mapped";
        case RegionDeltaKind::Unmapped:          return "Unmapped";
        case RegionDeltaKind::ProtectionChanged: return "ProtectionChanged";
        case RegionDeltaKind::BackingChanged:    return "BackingChanged";
        case RegionDeltaKind::Split:             return "Split";
        case RegionDeltaKind::Merged:            return "Merged";
        case RegionDeltaKind::ResidentChanged:   return "ResidentChanged";
    }
    return "Mapped";
}

struct RegionDelta {
    RegionDeltaKind kind{RegionDeltaKind::Mapped};
    std::uint64_t start_address{0};
    std::uint64_t end_address{0};
    std::optional<MemoryProtection> before_protection{};
    std::optional<MemoryProtection> after_protection{};
    std::optional<MemoryRegion> before_region{};
    std::optional<MemoryRegion> after_region{};
    bool was_split{false};
    bool was_merged{false};
    bool va_reused{false};
    bool became_rwx{false};
    bool became_executable{false};
    bool jit_rw_to_rx{false};
    std::optional<std::int64_t> delta_rss_bytes{};
    std::optional<std::int64_t> delta_pss_bytes{};
    std::optional<std::int64_t> delta_swap_bytes{};
    std::string detail{};

    [[nodiscard]] constexpr std::uint64_t size() const noexcept {
        return end_address >= start_address ? (end_address - start_address) : 0u;
    }
};

enum class ThreadDeltaKind : std::uint8_t {
    Created = 0,
    Exited,
    StateOrContextChanged,
};

[[nodiscard]] constexpr std::string_view to_string(ThreadDeltaKind kind) noexcept {
    switch (kind) {
        case ThreadDeltaKind::Created:               return "Created";
        case ThreadDeltaKind::Exited:                return "Exited";
        case ThreadDeltaKind::StateOrContextChanged: return "StateOrContextChanged";
    }
    return "Created";
}

struct ThreadDelta {
    ThreadDeltaKind kind{ThreadDeltaKind::Created};
    ThreadId tid{0};
    std::optional<ThreadSnapshot> before{};
    std::optional<ThreadSnapshot> after{};
    bool tid_reused{false};
    bool state_changed{false};
    bool instruction_pointer_changed{false};
    bool stack_pointer_changed{false};
    bool stack_sample_changed{false};
    std::string detail{};
};

enum class HandleDeltaKind : std::uint8_t {
    Opened = 0,
    Closed,
    Modified,
};

[[nodiscard]] constexpr std::string_view to_string(HandleDeltaKind kind) noexcept {
    switch (kind) {
        case HandleDeltaKind::Opened:   return "Opened";
        case HandleDeltaKind::Closed:   return "Closed";
        case HandleDeltaKind::Modified: return "Modified";
    }
    return "Opened";
}

struct HandleDelta {
    HandleDeltaKind kind{HandleDeltaKind::Opened};
    std::uint64_t handle_or_fd{0};
    std::optional<ProcessHandleEntry> before{};
    std::optional<ProcessHandleEntry> after{};
    bool fd_reused{false};
    std::string detail{};
};

enum class SocketDeltaKind : std::uint8_t {
    Opened = 0,
    Closed,
    StateChanged,
};

[[nodiscard]] constexpr std::string_view to_string(SocketDeltaKind kind) noexcept {
    switch (kind) {
        case SocketDeltaKind::Opened:       return "Opened";
        case SocketDeltaKind::Closed:       return "Closed";
        case SocketDeltaKind::StateChanged: return "StateChanged";
    }
    return "Opened";
}

struct SocketDelta {
    SocketDeltaKind kind{SocketDeltaKind::Opened};
    std::optional<ProcessSocketEntry> before{};
    std::optional<ProcessSocketEntry> after{};
    bool fd_or_endpoint_reused{false};
    std::string detail{};
};

struct SnapshotDiffOptions {
    bool allow_cross_target{false};
    bool include_resident_only_region_deltas{true};
};

struct SnapshotDiff {
    TargetInstanceId before_target_id{};
    TargetInstanceId after_target_id{};
    std::uint64_t before_revision{0};
    std::uint64_t after_revision{0};
    CaptureStamp before_stamp{};
    CaptureStamp after_stamp{};

    bool target_identity_matched{true};
    bool rejected_target_mismatch{false};

    std::vector<ModuleDelta> modules{};
    std::vector<RegionDelta> regions{};
    std::vector<ThreadDelta> threads{};
    std::vector<HandleDelta> handles{};
    std::vector<SocketDelta> sockets{};
    std::vector<SnapshotUncertainty> uncertainties{};
    std::string summary{};

    [[nodiscard]] bool has_uncertainties() const noexcept {
        return !uncertainties.empty();
    }
    [[nodiscard]] bool has_changes() const noexcept {
        return !modules.empty() || !regions.empty() || !threads.empty() ||
               !handles.empty() || !sockets.empty();
    }
};

/// Computes an interval- & identity-aware diff between `before` and `after`:
/// - Verifies `TargetInstanceId::same_instance` (rejecting PID reuse unless `allow_cross_target`).
/// - Splits memory regions at canonical interval endpoints using overflow-checked `uint64_t`
///   arithmetic to classify `Mapped`, `Unmapped`, `ProtectionChanged` (`R-X -> RWX`, `RW- -> R-X`),
///   `BackingChanged`, `Split`, `Merged`, and `ResidentChanged`.
/// - Guards against VA/TID/FD/socket reuse using module backing identity, thread creation/start
///   identity, `(fd, kind, type_name, target, inode, mount_id)`, and socket inode/tuple identity.
/// - Preserves partial-capture honesty: never claims unseen items were removed when `before` or
///   `after` is `Partial` or `Unavailable`, emitting explicit `SnapshotUncertainty` records instead.
[[nodiscard]] SnapshotDiff diff_process_snapshots(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    const SnapshotDiffOptions& options = {});

/// Extracts base addresses of modules observed `Loaded` in `diff` (when `target_identity_matched`
/// and `!rejected_target_mismatch`) for honest `declared_vs_loaded` timeline reconciliation.
[[nodiscard]] std::vector<std::uint64_t> collect_loaded_module_bases_from_diff(
    const SnapshotDiff& diff);

}  // namespace peelf
