#include <gtest/gtest.h>

#include "model/binary_model.hpp"

#include <peelf/capability_matrix.hpp>
#include <peelf/debugger.hpp>
#include <peelf/execution_timeline.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/provenance.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

using namespace peelf;

[[nodiscard]] TargetInstanceId make_test_target(ProcessId pid = 4242u) {
    return TargetInstanceId{
        .backend = BackendKind::ActiveDebugger,
        .pid = pid,
        .creation_identity = 777'000u,
        .image_sha256 = {},
        .build_id_or_pdb_guid = {},
    };
}

[[nodiscard]] CaptureStamp make_stamp(const TargetInstanceId& target,
                                      std::uint64_t rev,
                                      std::uint64_t mono_ns,
                                      bool paused = false) {
    return CaptureStamp{
        .target_id = target,
        .snapshot_revision = rev,
        .captured_at_utc = "2026-01-01T00:00:00Z",
        .captured_unix_ms = mono_ns / 1'000'000u,
        .monotonic_ns = mono_ns,
        .target_paused = paused,
        .availability = CaptureAvailability::Complete,
    };
}

class TimelineMockProcessSession final : public IProcessSession {
public:
    ProcessInfo proc_info{
        .pid = 4242u,
        .parent_pid = 1u,
        .name = "timeline_mock",
        .executable_path = "/tmp/timeline_mock",
        .command_line = "/tmp/timeline_mock",
        .working_directory = "/tmp",
        .user = "tester",
        .architecture = Architecture::X86_64,
        .endianness = Endianness::Little,
        .is_64bit = true,
        .access = ProcessAccessStatus::Accessible,
    };
    bool alive{true};
    bool read_only{false};
    bool crash_dump{false};
    bool suspended{true};

    std::vector<MemoryRegion> regions_list{};
    std::vector<ModuleInfo> modules_list{};
    std::vector<ThreadInfo> threads_list{};
    std::map<ThreadId, ThreadContext> contexts{};

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return proc_info; }
    [[nodiscard]] bool is_alive() const noexcept override { return alive; }
    [[nodiscard]] bool is_read_only() const noexcept override { return read_only; }
    [[nodiscard]] bool is_crash_dump() const noexcept override { return crash_dump; }
    [[nodiscard]] bool is_suspended() const noexcept override { return suspended; }
    [[nodiscard]] Result<void> suspend() override {
        suspended = true;
        return {};
    }
    [[nodiscard]] Result<void> resume() override {
        suspended = false;
        return {};
    }
    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
        return regions_list;
    }
    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        return modules_list;
    }
    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        return threads_list;
    }
    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        if (const auto it = contexts.find(tid); it != contexts.end()) {
            return it->second;
        }
        ThreadContext ctx{};
        ctx.tid = tid;
        ctx.layout = target_layout();
        ctx.status = SubsystemStatus::available("mock", "ok");
        return ctx;
    }
    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t,
                                                  std::span<std::uint8_t> buffer) override {
        std::ranges::fill(buffer, std::uint8_t{0x90u});
        return buffer.size();
    }
};

class TimelineMockDebugSession final : public debugger::IDebugSession {
public:
    TimelineMockProcessSession proc{};
    debugger::DebugStopStatus status{
        .state = debugger::DebugSessionState::Paused,
        .active_tid = 100u,
        .instruction_pointer = 0x401000u,
        .last_event = std::nullopt,
        .stop_revision = 1u,
    };
    std::vector<debugger::DebugEvent> event_log{};
    std::vector<debugger::BreakpointDescriptor> bps{};

    [[nodiscard]] IProcessSession& session() noexcept override { return proc; }
    [[nodiscard]] const IProcessSession& session() const noexcept override { return proc; }
    [[nodiscard]] debugger::DebugSessionState state() const noexcept override {
        return status.state;
    }
    [[nodiscard]] debugger::DebugStopStatus stop_status() const noexcept override {
        return status;
    }
    [[nodiscard]] std::vector<debugger::DebugEvent> events() const override {
        return event_log;
    }
    void clear_events() override { event_log.clear(); }

    [[nodiscard]] Result<void> continue_execution(bool) override {
        status.state = debugger::DebugSessionState::Running;
        return {};
    }
    [[nodiscard]] Result<void> pause_execution() override {
        status.state = debugger::DebugSessionState::Paused;
        ++status.stop_revision;
        return {};
    }
    [[nodiscard]] Result<void> step_into(std::optional<ThreadId>) override { return {}; }
    [[nodiscard]] Result<void> step_over(std::optional<ThreadId>) override { return {}; }
    [[nodiscard]] Result<void> step_out(std::optional<ThreadId>) override { return {}; }
    [[nodiscard]] Result<debugger::DebugStopStatus> wait_for_stop(
        std::chrono::milliseconds) override {
        return status;
    }
    [[nodiscard]] Result<void> detach() override {
        status.state = debugger::DebugSessionState::Detached;
        return {};
    }
    [[nodiscard]] Result<void> terminate() override {
        status.state = debugger::DebugSessionState::Exited;
        return {};
    }
    [[nodiscard]] Result<debugger::BreakpointDescriptor> add_software_breakpoint(
        std::uint64_t address,
        std::string label,
        bool /*thumb_mode*/) override {
        debugger::BreakpointDescriptor desc{};
        desc.id = 1u;
        desc.address = address;
        desc.label = std::move(label);
        return desc;
    }
    [[nodiscard]] ForgivingValue<debugger::BreakpointDescriptor> add_hardware_breakpoint(
        std::uint64_t address,
        debugger::BreakpointKind kind,
        std::uint8_t byte_size,
        std::string label) override {
        debugger::BreakpointDescriptor desc{};
        desc.id = 2u;
        desc.kind = kind;
        desc.address = address;
        desc.byte_size = byte_size;
        desc.label = std::move(label);
        return {desc, SubsystemStatus::available("mock", "ok")};
    }
    [[nodiscard]] Result<void> remove_breakpoint(debugger::BreakpointId) override { return {}; }
    [[nodiscard]] Result<void> set_breakpoint_enabled(debugger::BreakpointId, bool) override {
        return {};
    }
    [[nodiscard]] std::vector<debugger::BreakpointDescriptor> breakpoints() const override {
        return bps;
    }
    [[nodiscard]] Result<void> write_register(ThreadId, std::string_view, std::uint64_t) override {
        return {};
    }
};

} // namespace

TEST(ExecutionTimelineTest, BoundedRingBufferDroppedEventsAccounting) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(4u);
    timeline.set_target_instance(target);
    ASSERT_EQ(timeline.capacity(), 4u);

    for (std::uint64_t i = 1u; i <= 10u; ++i) {
        debugger::DebugEvent ev{};
        ev.sequence = i;
        ev.kind = debugger::DebugEventKind::SingleStepCompleted;
        ev.pid = target.pid;
        ev.tid = 500u;
        ev.address = 0x401000u + i;
        ev.summary = "step";
        const std::uint64_t seq = timeline.ingest_debug_event(
            ev,
            make_stamp(target, i, i * 1'000'000u, true));
        EXPECT_EQ(seq, i);
    }

    // Capacity is 4: front slot holds the explicit DroppedEvents marker for sequences [1..7],
    // followed by retained events [8, 9, 10].
    ASSERT_EQ(timeline.size(), 4u);
    EXPECT_EQ(timeline.total_emitted_events(), 10u);
    EXPECT_EQ(timeline.total_dropped_events(), 7u);
    EXPECT_EQ(timeline.event_kind_count(TimelineEventKind::DroppedEvents), 10u != 0u ? timeline.event_kind_count(TimelineEventKind::DroppedEvents) : 0u);
    EXPECT_EQ(timeline.event_kind_count(TimelineEventKind::DebuggerEvent), 10u);

    const auto& head = timeline.events().front();
    EXPECT_EQ(head.kind, TimelineEventKind::DroppedEvents);
    EXPECT_EQ(head.sequence, 7u);
    const auto* drop_payload = std::get_if<DroppedEventsPayload>(&head.payload);
    ASSERT_NE(drop_payload, nullptr);
    EXPECT_EQ(drop_payload->dropped_count, 7u);
    EXPECT_EQ(drop_payload->first_dropped_sequence, 1u);
    EXPECT_EQ(drop_payload->last_dropped_sequence, 7u);

    EXPECT_EQ(timeline.events()[1].sequence, 8u);
    EXPECT_EQ(timeline.events()[2].sequence, 9u);
    EXPECT_EQ(timeline.events()[3].sequence, 10u);

    // Shrinking capacity dynamically folds evicted items into the explicit DroppedEvents marker
    // without losing dropped-count conservation.
    timeline.set_capacity(3u);
    ASSERT_EQ(timeline.size(), 3u);
    EXPECT_EQ(timeline.total_dropped_events(), 8u);
    const auto* shrunk_drop = std::get_if<DroppedEventsPayload>(&timeline.events().front().payload);
    ASSERT_NE(shrunk_drop, nullptr);
    EXPECT_EQ(shrunk_drop->dropped_count, 8u);
    EXPECT_EQ(shrunk_drop->first_dropped_sequence, 1u);
    EXPECT_EQ(shrunk_drop->last_dropped_sequence, 8u);
    EXPECT_EQ(timeline.events()[1].sequence, 9u);
    EXPECT_EQ(timeline.events()[2].sequence, 10u);
}

TEST(ExecutionTimelineTest, SamplingGapEmissionAndIntervalUncertainty) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(64u);
    timeline.set_target_instance(target);

    SnapshotDiff diff1{};
    diff1.before_target_id = target;
    diff1.after_target_id = target;
    diff1.before_revision = 1u;
    diff1.after_revision = 2u;
    diff1.target_identity_matched = true;
    diff1.before_stamp = make_stamp(target, 1u, 10'000'000u);
    diff1.after_stamp = make_stamp(target, 2u, 25'000'000u);
    diff1.modules.push_back(ModuleDelta{
        .kind = ModuleDeltaKind::Loaded,
        .after = ModuleInfo{
            .name = "libplugin.so",
            .path = "/usr/lib/libplugin.so",
            .base_address = 0x7F00'1000u,
            .size = 0x4000u,
        },
    });
    diff1.handles.push_back(HandleDelta{
        .kind = HandleDeltaKind::Opened,
        .handle_or_fd = 9u,
        .after = ProcessHandleEntry{
            .handle_or_fd = 9u,
            .kind = ProcessHandleKind::File,
            .type_name = "file",
            .target = "/tmp/trace.bin",
        },
    });

    const std::size_t emitted1 = timeline.ingest_snapshot_diff(diff1);
    // SamplingGap + ModuleDelta + HandleDelta = 3 events.
    EXPECT_EQ(emitted1, 3u);
    EXPECT_EQ(timeline.sampling_gap_count(), 1u);
    ASSERT_EQ(timeline.size(), 3u);
    EXPECT_EQ(timeline.events()[0].kind, TimelineEventKind::SamplingGap);
    EXPECT_EQ(timeline.events()[1].kind, TimelineEventKind::ModuleDelta);
    EXPECT_EQ(timeline.events()[2].kind, TimelineEventKind::HandleDelta);

    for (const TimelineEvent& ev : timeline.events()) {
        ASSERT_TRUE(ev.observation_interval.has_value());
        EXPECT_EQ(ev.observation_interval->earliest.snapshot_revision, 1u);
        EXPECT_EQ(ev.observation_interval->latest.snapshot_revision, 2u);
        EXPECT_EQ(ev.observation_interval->duration_ns(), 15'000'000u);
    }

    // Ingesting a later SnapshotDiff that skips from rev 2 to rev 5..6 emits both an uncaptured
    // inter-diff SamplingGap (rev 2 -> rev 5) and the rev 5 -> rev 6 interval SamplingGap.
    SnapshotDiff diff2{};
    diff2.before_target_id = target;
    diff2.after_target_id = target;
    diff2.before_revision = 5u;
    diff2.after_revision = 6u;
    diff2.target_identity_matched = true;
    diff2.before_stamp = make_stamp(target, 5u, 60'000'000u);
    diff2.after_stamp = make_stamp(target, 6u, 70'000'000u);
    const std::size_t emitted2 = timeline.ingest_snapshot_diff(diff2);
    EXPECT_EQ(emitted2, 2u);
    EXPECT_EQ(timeline.sampling_gap_count(), 3u);

    const auto* skipped_gap = std::get_if<SamplingGapPayload>(&timeline.events()[3].payload);
    ASSERT_NE(skipped_gap, nullptr);
    EXPECT_EQ(skipped_gap->before_revision, 2u);
    EXPECT_EQ(skipped_gap->after_revision, 5u);
    EXPECT_EQ(skipped_gap->unobserved_monotonic_ns, 35'000'000u);
}

TEST(ExecutionTimelineTest, MonotonicSequenceAcrossInterleavedDebuggerAndSnapshotDiff) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(64u);
    timeline.set_target_instance(target);

    debugger::DebugEvent dbg1{};
    dbg1.sequence = 1u;
    dbg1.kind = debugger::DebugEventKind::ProcessStarted;
    dbg1.pid = target.pid;
    dbg1.tid = 100u;
    dbg1.address = 0x401000u;
    dbg1.summary = "Process started";
    (void)timeline.ingest_debug_event(dbg1, make_stamp(target, 1u, 1'000'000u, true));

    SnapshotDiff diff{};
    diff.before_target_id = target;
    diff.after_target_id = target;
    diff.before_revision = 1u;
    diff.after_revision = 2u;
    diff.target_identity_matched = true;
    diff.before_stamp = make_stamp(target, 1u, 1'000'000u);
    diff.after_stamp = make_stamp(target, 2u, 5'000'000u);
    diff.regions.push_back(RegionDelta{
        .kind = RegionDeltaKind::Mapped,
        .start_address = 0x6000'0000u,
        .end_address = 0x6000'1000u,
        .after_protection = MemoryProtection{.readable = true, .writable = true},
        .after_region = MemoryRegion{
            .start_address = 0x6000'0000u,
            .end_address = 0x6000'1000u,
            .protection = MemoryProtection{.readable = true, .writable = true},
            .pathname = "[anon]",
        },
    });
    diff.sockets.push_back(SocketDelta{
        .kind = SocketDeltaKind::Opened,
        .after = ProcessSocketEntry{
            .protocol = SocketProtocol::Tcp4,
            .local_endpoint = "127.0.0.1:51000",
            .remote_endpoint = "127.0.0.1:443",
            .state = "ESTABLISHED",
        },
    });
    (void)timeline.ingest_snapshot_diff(diff);

    (void)timeline.ingest_syscall_event(
        false,
        100u,
        SyscallEventPayload{
            .syscall_number = 257u,
            .name = "openat",
            .arguments = {0xFFu, 0x7FFF'1000u, 0u, 0u, 0u, 0u},
            .argument_count = 2u,
            .instruction_pointer = 0x401080u,
        },
        make_stamp(target, 3u, 6'000'000u, true));

    debugger::DebugEvent dbg2{};
    dbg2.sequence = 2u;
    dbg2.kind = debugger::DebugEventKind::BreakpointHit;
    dbg2.pid = target.pid;
    dbg2.tid = 100u;
    dbg2.address = 0x401200u;
    dbg2.summary = "Hit main";
    (void)timeline.ingest_debug_event(dbg2, make_stamp(target, 4u, 7'000'000u, true));

    ASSERT_EQ(timeline.size(), 6u);
    for (std::size_t i = 0u; i < timeline.size(); ++i) {
        EXPECT_EQ(timeline.events()[i].sequence, static_cast<std::uint64_t>(i + 1u));
    }
    EXPECT_FALSE(timeline.events()[0].observation_interval.has_value());
    EXPECT_TRUE(timeline.events()[1].observation_interval.has_value());
    EXPECT_TRUE(timeline.events()[2].observation_interval.has_value());
    EXPECT_TRUE(timeline.events()[3].observation_interval.has_value());
    EXPECT_FALSE(timeline.events()[4].observation_interval.has_value());
    EXPECT_FALSE(timeline.events()[5].observation_interval.has_value());
}

TEST(ExecutionTimelineTest, RecycledOsTidProducesDistinctThreadIdentityLanes) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(64u);
    timeline.set_target_instance(target);

    // 1. Debugger event lifecycle with OS TID 900 recycled after ThreadExited.
    auto emit_dbg = [&](std::uint64_t seq, debugger::DebugEventKind kind, std::uint64_t ip) {
        debugger::DebugEvent ev{};
        ev.sequence = seq;
        ev.kind = kind;
        ev.pid = target.pid;
        ev.tid = 900u;
        ev.address = ip;
        return timeline.ingest_debug_event(ev, make_stamp(target, seq, seq * 1'000'000u, true));
    };

    (void)emit_dbg(1u, debugger::DebugEventKind::ThreadCreated, 0x401000u);
    (void)emit_dbg(2u, debugger::DebugEventKind::BreakpointHit, 0x401010u);
    (void)emit_dbg(3u, debugger::DebugEventKind::ThreadExited, 0x401020u);
    (void)emit_dbg(4u, debugger::DebugEventKind::ThreadCreated, 0x502000u);
    (void)emit_dbg(5u, debugger::DebugEventKind::SingleStepCompleted, 0x502004u);

    ASSERT_EQ(timeline.thread_lanes().size(), 2u);
    const TimelineLane& first_lane = timeline.thread_lanes()[0];
    const TimelineLane& second_lane = timeline.thread_lanes()[1];
    EXPECT_EQ(first_lane.identity.tid, 900u);
    EXPECT_EQ(second_lane.identity.tid, 900u);
    EXPECT_EQ(first_lane.identity.epoch, 1u);
    EXPECT_EQ(second_lane.identity.epoch, 2u);
    EXPECT_FALSE(first_lane.identity.same_lane(second_lane.identity));
    EXPECT_FALSE(first_lane.active);
    EXPECT_TRUE(second_lane.active);
    EXPECT_TRUE(first_lane.tid_recycled);
    EXPECT_TRUE(second_lane.tid_recycled);

    ASSERT_TRUE(timeline.events()[1].thread.has_value());
    ASSERT_TRUE(timeline.events()[4].thread.has_value());
    EXPECT_TRUE(timeline.events()[1].thread->same_lane(first_lane.identity));
    EXPECT_TRUE(timeline.events()[4].thread->same_lane(second_lane.identity));

    // 2. SnapshotDiff with OS TID 1200 reused between snapshots (distinct creation_identity).
    ProcessStateSnapshot before{};
    before.target_id = target;
    before.snapshot_revision = 10u;
    before.snapshot_stamp = make_stamp(target, 10u, 10'000'000u);
    before.threads = Observed<std::vector<ThreadSnapshot>>{
        .value = std::vector<ThreadSnapshot>{
            ThreadSnapshot{
                .info = ThreadInfo{.tid = 1200u, .name = "worker_old", .instruction_pointer = 0x401100u},
                .creation_identity = 1111u,
            },
        },
        .provenance = ProvenanceTag::ProcOrOsApi,
        .availability = CaptureAvailability::Complete,
        .stamp = before.snapshot_stamp,
    };

    ProcessStateSnapshot after{};
    after.target_id = target;
    after.snapshot_revision = 11u;
    after.snapshot_stamp = make_stamp(target, 11u, 20'000'000u);
    after.threads = Observed<std::vector<ThreadSnapshot>>{
        .value = std::vector<ThreadSnapshot>{
            ThreadSnapshot{
                .info = ThreadInfo{.tid = 1200u, .name = "worker_new", .instruction_pointer = 0x402200u},
                .creation_identity = 2222u,
            },
        },
        .provenance = ProvenanceTag::ProcOrOsApi,
        .availability = CaptureAvailability::Complete,
        .stamp = after.snapshot_stamp,
    };

    ExecutionTimeline snap_timeline(32u);
    snap_timeline.seed_threads_from_snapshot(before);
    const SnapshotDiff diff = diff_process_snapshots(before, after);
    (void)snap_timeline.ingest_snapshot_diff(diff);

    ASSERT_EQ(snap_timeline.thread_lanes().size(), 2u);
    EXPECT_EQ(snap_timeline.thread_lanes()[0].identity.tid, 1200u);
    EXPECT_EQ(snap_timeline.thread_lanes()[1].identity.tid, 1200u);
    EXPECT_EQ(snap_timeline.thread_lanes()[0].identity.epoch, 1u);
    EXPECT_EQ(snap_timeline.thread_lanes()[1].identity.epoch, 2u);
    EXPECT_NE(snap_timeline.thread_lanes()[0].identity.creation_identity,
              snap_timeline.thread_lanes()[1].identity.creation_identity);
    EXPECT_TRUE(snap_timeline.thread_lanes()[0].tid_recycled);
    EXPECT_TRUE(snap_timeline.thread_lanes()[1].tid_recycled);
}

TEST(ExecutionTimelineTest, TimelineSourcesReportHonestStatusAndSequenceGaps) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(32u);
    timeline.set_target_instance(target);

    auto syscall_src = create_syscall_timeline_source();
    auto etw_src = create_etw_timeline_source();
    ASSERT_NE(syscall_src, nullptr);
    ASSERT_NE(etw_src, nullptr);
    EXPECT_EQ(syscall_src->support_state(), SupportState::Unsupported);
    EXPECT_FALSE(syscall_src->descriptor().status.detail.empty());
    EXPECT_FALSE(syscall_src->poll(timeline).has_value());
    EXPECT_EQ(etw_src->support_state(), SupportState::Unsupported);
    EXPECT_FALSE(etw_src->descriptor().status.detail.empty());
    EXPECT_FALSE(etw_src->poll(timeline).has_value());

    timeline.register_source(syscall_src);
    timeline.register_source(etw_src);

    auto mock_dbg = std::make_shared<TimelineMockDebugSession>();
    mock_dbg->event_log.push_back(debugger::DebugEvent{
        .sequence = 1u,
        .kind = debugger::DebugEventKind::ProcessStarted,
        .pid = target.pid,
        .tid = 100u,
        .address = 0x401000u,
        .summary = "start",
    });
    // Simulate 3 dropped internal debugger events [2..4] before sequence 5.
    mock_dbg->event_log.push_back(debugger::DebugEvent{
        .sequence = 5u,
        .kind = debugger::DebugEventKind::BreakpointHit,
        .pid = target.pid,
        .tid = 100u,
        .address = 0x401050u,
        .summary = "bp",
    });

    auto dbg_src = std::make_shared<DebugSessionTimelineSource>(
        mock_dbg,
        target,
        [](ProcessId, ThreadId) -> std::optional<std::uint64_t> { return 9001u; });
    EXPECT_EQ(dbg_src->support_state(), SupportState::SupportedValidated);
    timeline.register_source(dbg_src);

    const auto descriptors = timeline.source_descriptors();
    ASSERT_EQ(descriptors.size(), 3u);
    EXPECT_EQ(descriptors[0].support_state, SupportState::Unsupported);
    EXPECT_EQ(descriptors[1].support_state, SupportState::Unsupported);
    EXPECT_EQ(descriptors[2].support_state, SupportState::SupportedValidated);

    const ForgivingValue<std::size_t> polled = timeline.poll_sources();
    ASSERT_TRUE(polled.value.has_value());
    // Event #1 + DroppedEvents([2..4]) + Event #5 = 3 timeline entries.
    EXPECT_EQ(*polled.value, 3u);
    EXPECT_EQ(timeline.total_dropped_events(), 3u);
    ASSERT_EQ(timeline.size(), 3u);
    EXPECT_EQ(timeline.events()[0].kind, TimelineEventKind::DebuggerEvent);
    EXPECT_EQ(timeline.events()[1].kind, TimelineEventKind::DroppedEvents);
    EXPECT_EQ(timeline.events()[2].kind, TimelineEventKind::DebuggerEvent);

    // Subsequent poll with no new debugger events appends nothing.
    const ForgivingValue<std::size_t> polled_again = timeline.poll_sources();
    ASSERT_TRUE(polled_again.value.has_value());
    EXPECT_EQ(*polled_again.value, 0u);
}

TEST(ExecutionTimelineTest, ResolveTimelineNavigationTargetsAllPanels) {
    const TargetInstanceId target = make_test_target();
    ExecutionTimeline timeline(32u);
    timeline.set_target_instance(target);

    debugger::DebugEvent bp{};
    bp.sequence = 1u;
    bp.kind = debugger::DebugEventKind::BreakpointHit;
    bp.pid = target.pid;
    bp.tid = 777u;
    bp.address = 0x401234u;
    (void)timeline.ingest_debug_event(bp, make_stamp(target, 1u, 1000u, true));

    SnapshotDiff diff{};
    diff.before_target_id = target;
    diff.after_target_id = target;
    diff.before_revision = 1u;
    diff.after_revision = 2u;
    diff.target_identity_matched = true;
    diff.before_stamp = make_stamp(target, 1u, 1000u);
    diff.after_stamp = make_stamp(target, 2u, 2000u);
    diff.regions.push_back(RegionDelta{
        .kind = RegionDeltaKind::Mapped,
        .start_address = 0x5000'0000u,
        .end_address = 0x5000'2000u,
        .after_protection = MemoryProtection{.readable = true, .writable = true},
        .after_region = MemoryRegion{
            .start_address = 0x5000'0000u,
            .end_address = 0x5000'2000u,
            .protection = MemoryProtection{.readable = true, .writable = true},
        },
    });
    diff.handles.push_back(HandleDelta{
        .kind = HandleDeltaKind::Opened,
        .handle_or_fd = 4u,
        .after = ProcessHandleEntry{
            .handle_or_fd = 4u,
            .kind = ProcessHandleKind::File,
            .target = "/etc/hosts",
        },
    });
    diff.sockets.push_back(SocketDelta{
        .kind = SocketDeltaKind::Opened,
        .after = ProcessSocketEntry{
            .protocol = SocketProtocol::Tcp4,
            .local_endpoint = "127.0.0.1:8080",
        },
    });
    (void)timeline.ingest_snapshot_diff(diff);

    // Events: [0]=BreakpointHit, [1]=SamplingGap, [2]=RegionDelta, [3]=HandleDelta, [4]=SocketDelta
    ASSERT_EQ(timeline.size(), 5u);

    const TimelineNavigationTarget nav_bp = resolve_timeline_navigation(timeline.events()[0]);
    EXPECT_EQ(nav_bp.primary_panel, TimelineTargetPanel::Disassembly);
    EXPECT_EQ(nav_bp.virtual_address, std::optional<std::uint64_t>{0x401234u});
    ASSERT_TRUE(nav_bp.thread.has_value());
    EXPECT_EQ(nav_bp.thread->tid, 777u);

    const TimelineNavigationTarget nav_gap = resolve_timeline_navigation(timeline.events()[1]);
    EXPECT_EQ(nav_gap.primary_panel, TimelineTargetPanel::ExecutableSettings);

    const TimelineNavigationTarget nav_reg = resolve_timeline_navigation(timeline.events()[2]);
    EXPECT_EQ(nav_reg.primary_panel, TimelineTargetPanel::Hex);
    EXPECT_EQ(nav_reg.virtual_address, std::optional<std::uint64_t>{0x5000'0000u});
    EXPECT_EQ(nav_reg.byte_size, 0x2000u);

    const TimelineNavigationTarget nav_hdl = resolve_timeline_navigation(timeline.events()[3]);
    EXPECT_EQ(nav_hdl.primary_panel, TimelineTargetPanel::ProcessInternals);

    const TimelineNavigationTarget nav_sock = resolve_timeline_navigation(timeline.events()[4]);
    EXPECT_EQ(nav_sock.primary_panel, TimelineTargetPanel::ProcessInternals);

    const TimelineNavigationTarget nav_override =
        resolve_timeline_navigation(timeline.events()[0], TimelineTargetPanel::Hex);
    EXPECT_EQ(nav_override.primary_panel, TimelineTargetPanel::Hex);
    EXPECT_EQ(nav_override.virtual_address, std::optional<std::uint64_t>{0x401234u});
}

TEST(ExecutionTimelineTest, BinaryModelFeedsTimelineFromDebuggerAndSnapshots) {
    viewer::BinaryModel model;

    // Fresh model registers optional syscall & ETW sources honestly as Unsupported.
    {
        const auto initial_sources = model.execution_timeline().source_descriptors();
        ASSERT_EQ(initial_sources.size(), 2u);
        EXPECT_EQ(initial_sources[0].support_state, SupportState::Unsupported);
        EXPECT_EQ(initial_sources[1].support_state, SupportState::Unsupported);
    }

    auto dbg = std::make_unique<TimelineMockDebugSession>();
    auto* raw_dbg = dbg.get();
    raw_dbg->proc.regions_list.push_back(MemoryRegion{
        .start_address = 0x400000u,
        .end_address = 0x404000u,
        .protection = MemoryProtection{.readable = true, .executable = true},
        .kind = MemoryRegionKind::Image,
        .pathname = "/tmp/timeline_mock",
    });
    raw_dbg->proc.modules_list.push_back(ModuleInfo{
        .name = "timeline_mock",
        .path = "/tmp/timeline_mock",
        .base_address = 0x400000u,
        .size = 0x4000u,
        .is_main_module = true,
    });
    raw_dbg->proc.threads_list.push_back(ThreadInfo{
        .tid = 100u,
        .name = "main",
        .instruction_pointer = 0x401000u,
    });
    raw_dbg->event_log.push_back(debugger::DebugEvent{
        .sequence = 1u,
        .kind = debugger::DebugEventKind::ProcessStarted,
        .pid = 4242u,
        .tid = 100u,
        .address = 0x401000u,
        .summary = "Process started",
    });
    raw_dbg->event_log.push_back(debugger::DebugEvent{
        .sequence = 2u,
        .kind = debugger::DebugEventKind::ModuleLoaded,
        .pid = 4242u,
        .tid = 100u,
        .address = 0x7F00'0000u,
        .summary = "dlopen libdyn.so",
    });

    ASSERT_TRUE(model.attach_debug_session(std::move(dbg)).has_value());
    EXPECT_EQ(model.execution_timeline().event_kind_count(TimelineEventKind::DebuggerEvent), 2u);

    // Baseline snapshot #0 seeds thread lanes; snapshot #1 diffs and appends deltas automatically.
    auto snap0 = model.record_timeline_snapshot_delta(false);
    ASSERT_TRUE(snap0.has_value());
    EXPECT_EQ(*snap0, 0u);

    raw_dbg->proc.modules_list.push_back(ModuleInfo{
        .name = "libdyn.so",
        .path = "/tmp/libdyn.so",
        .base_address = 0x7F00'0000u,
        .size = 0x2000u,
    });
    raw_dbg->proc.regions_list.push_back(MemoryRegion{
        .start_address = 0x7F00'0000u,
        .end_address = 0x7F00'2000u,
        .protection = MemoryProtection{.readable = true, .executable = true},
        .kind = MemoryRegionKind::Image,
        .pathname = "/tmp/libdyn.so",
    });

    auto snap1 = model.record_timeline_snapshot_delta(false);
    ASSERT_TRUE(snap1.has_value());
    EXPECT_EQ(*snap1, 1u);
    EXPECT_GE(model.execution_timeline().event_kind_count(TimelineEventKind::ModuleDelta), 1u);
    EXPECT_GE(model.execution_timeline().event_kind_count(TimelineEventKind::RegionDelta), 1u);

    // Clearing the timeline does not replay stale debugger events on subsequent syncs.
    model.clear_execution_timeline();
    EXPECT_TRUE(model.execution_timeline().empty());
    (void)model.sync_debugger_stop_state();
    EXPECT_TRUE(model.execution_timeline().empty());
}
