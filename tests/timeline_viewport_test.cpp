#include <peelf/crash_dump.hpp>
#include <peelf/execution_timeline.hpp>
#include <peelf/process.hpp>
#include <peelf/timeline_viewport.hpp>

#include "vulkan/shaders/timeline_span_spirv.hpp"
#include "vulkan/spirv_validation.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace {

class FakeLiveProcessSession final : public peelf::IProcessSession {
public:
    explicit FakeLiveProcessSession(peelf::ProcessId pid = 4242u) {
        info_.pid = pid;
        info_.name = "synthetic_target";
        info_.architecture = peelf::Architecture::X86_64;
        info_.endianness = peelf::Endianness::Little;
        info_.is_64bit = true;
        info_.access = peelf::ProcessAccessStatus::ReadOnly;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return alive_; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        ++memory_region_queries_;
        return regions_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t /*address*/,
        std::span<std::uint8_t> /*buffer*/) override {
        return std::size_t{0};
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        ++thread_queries_;
        return threads_;
    }

    [[nodiscard]] peelf::Result<void> suspend() override {
        ++suspend_calls_;
        return {};
    }

    [[nodiscard]] peelf::Result<void> suspend_thread(peelf::ThreadId /*tid*/) override {
        ++suspend_thread_calls_;
        return {};
    }

    peelf::ProcessInfo info_{};
    bool alive_{true};
    std::vector<peelf::MemoryRegion> regions_{};
    std::vector<peelf::ThreadInfo> threads_{};
    std::size_t memory_region_queries_{0};
    std::size_t thread_queries_{0};
    std::size_t suspend_calls_{0};
    std::size_t suspend_thread_calls_{0};
};

class FakeCrashDumpSession final : public peelf::ICrashDumpSession {
public:
    FakeCrashDumpSession() {
        info_.pid = 9001u;
        info_.name = "crashed_worker";
        info_.architecture = peelf::Architecture::X86_64;
        info_.endianness = peelf::Endianness::Little;
        info_.is_64bit = true;

        summary_.kind = peelf::CrashDumpKind::ElfCore;
        summary_.pid = 9001u;
        summary_.process_name = "crashed_worker";
        summary_.timestamp_unix = 1'700'000'000u;
        summary_.exception = peelf::CrashExceptionInfo{
            .thread_id = 9002u,
            .fault_code = 11u,
            .fault_name = "SIGSEGV",
            .fault_address = 0xDEAD'BEEFULL,
            .instruction_pointer = 0x401234ULL,
            .description = "Segmentation fault reading 0xDEADBEEF",
        };
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t /*address*/,
        std::span<std::uint8_t> /*buffer*/) override {
        return std::size_t{0};
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return threads_;
    }

    [[nodiscard]] const peelf::CrashDumpSummary& crash_summary() const noexcept override {
        return summary_;
    }

    [[nodiscard]] const peelf::ProcessInternalsSnapshot& crash_internals() const noexcept override {
        return internals_;
    }

    peelf::ProcessInfo info_{};
    peelf::CrashDumpSummary summary_{};
    peelf::ProcessInternalsSnapshot internals_{};
    std::vector<peelf::MemoryRegion> regions_{};
    std::vector<peelf::ThreadInfo> threads_{};
};

} // namespace

TEST(TimelineViewportShaderAndAbiTest, StructLayoutsAndSpirvValidation) {
    EXPECT_EQ(sizeof(peelf::TimelineGpuInstance), 32u);
    EXPECT_EQ(alignof(peelf::TimelineGpuInstance), 16u);
    EXPECT_LE(sizeof(viewer::shaders::TimelineViewportPushConstants), 128u);
    EXPECT_EQ(sizeof(viewer::shaders::TimelineViewportPushConstants), 32u);

    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kTimelineSpanVertSpirv));
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kTimelineSpanFragSpirv));
}

TEST(LiveThreadMonitorTest, NonIntrusiveSamplingSpanCoalescingCpuClampingAndStackDepth) {
    FakeLiveProcessSession session(5500u);

    peelf::MemoryRegion stack_region{};
    stack_region.start_address = 0x7FFF'0000'0000ULL;
    stack_region.end_address = 0x7FFF'0010'0000ULL; // 1 MiB stack
    stack_region.protection = {.readable = true, .writable = true, .executable = false};
    stack_region.kind = peelf::MemoryRegionKind::Stack;
    stack_region.pathname = "[stack]";
    stack_region.usage.owner_tid = 5501u;
    session.regions_.push_back(stack_region);

    peelf::LiveThreadMonitorConfig cfg{};
    cfg.max_spans_per_lane = 256u;
    cfg.max_metrics_per_lane = 256u;
    cfg.sampling_gap_threshold_ns = 100'000'000ULL; // 100 ms

    peelf::LiveThreadMonitor monitor(cfg);

    // Sample 1 @ t = 10 ms: Running, SP uses 16 KiB of stack.
    peelf::ThreadInfo t1{};
    t1.tid = 5501u;
    t1.name = "render_worker";
    t1.state = peelf::ThreadRunState::Running;
    t1.start_address = 0x401000ULL;
    t1.instruction_pointer = 0x402100ULL;
    t1.stack_pointer = 0x7FFF'0010'0000ULL - 16'384ULL;
    t1.user_time_ns = 1'000'000ULL;
    t1.kernel_time_ns = 500'000ULL;
    session.threads_ = {t1};

    auto r1 = monitor.sample(session, {}, 10'000'000ULL);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 1u);

    // Sample 2 @ t = 20 ms (+10 ms wall): still Running -> coalesces into span #0!
    // CPU delta = (+4 ms user + +1 ms kernel) / 10 ms = 0.50 (kernel share = 0.20), SP uses 32 KiB.
    t1.instruction_pointer = 0x402180ULL;
    t1.stack_pointer = 0x7FFF'0010'0000ULL - 32'768ULL;
    t1.user_time_ns = 5'000'000ULL;
    t1.kernel_time_ns = 1'500'000ULL;
    session.threads_ = {t1};
    ASSERT_TRUE(monitor.sample(session, {}, 20'000'000ULL).has_value());

    // Sample 3 @ t = 30 ms (+10 ms wall): transitions to Waiting -> splits new Waiting span!
    t1.state = peelf::ThreadRunState::Waiting;
    t1.wait_channel = "futex_wait_queue_me";
    t1.stack_pointer = 0x7FFF'0010'0000ULL - 24'576ULL;
    t1.user_time_ns = 5'200'000ULL;
    t1.kernel_time_ns = 1'800'000ULL;
    session.threads_ = {t1};
    ASSERT_TRUE(monitor.sample(session, {}, 30'000'000ULL).has_value());

    // Sample 4 @ t = 40 ms (+10 ms wall): transitions back to Running with over-100% OS tick jump
    // (+15 ms CPU delta in 10 ms wall) -> clamps cpu_ratio cleanly to 1.0f!
    t1.state = peelf::ThreadRunState::Running;
    t1.wait_channel.clear();
    t1.user_time_ns = 17'200'000ULL;
    t1.kernel_time_ns = 4'800'000ULL;
    session.threads_ = {t1};
    ASSERT_TRUE(monitor.sample(session, {}, 40'000'000ULL).has_value());

    // Sample 5 @ t = 300 ms (+260 ms > 100 ms threshold): inserts explicit SamplingGap span!
    t1.user_time_ns = 20'000'000ULL;
    t1.kernel_time_ns = 5'000'000ULL;
    session.threads_ = {t1};
    ASSERT_TRUE(monitor.sample(session, {}, 300'000'000ULL).has_value());

    // Non-intrusive guarantee: target process and threads were never paused or suspended.
    EXPECT_EQ(session.suspend_calls_, 0u);
    EXPECT_EQ(session.suspend_thread_calls_, 0u);

    const auto obs = monitor.snapshot();
    ASSERT_TRUE(obs.has_value());
    ASSERT_EQ(obs.value->lanes.size(), 1u);

    const peelf::ThreadMonitorLane& lane = obs.value->lanes[0];
    EXPECT_EQ(lane.identity.tid, 5501u);
    EXPECT_EQ(lane.identity.epoch, 1u);
    EXPECT_EQ(lane.high_water_stack_depth_bytes, 32'768ULL);
    EXPECT_EQ(lane.latest_stack_depth_bytes, 24'576ULL);

    // Expected spans:
    //   [0] Running (coalesced samples 1 & 2, 10 ms .. 30 ms)
    //   [1] Waiting (sample 3, 30 ms .. 40 ms)
    //   [2] Running (sample 4, 40 ms .. 40 ms+)
    //   [3] SamplingGap (40 ms .. 300 ms)
    //   [4] Running (sample 5 @ 300 ms)
    ASSERT_GE(lane.spans.size(), 5u);
    EXPECT_EQ(lane.spans[0].state, peelf::ThreadSpanState::Running);
    EXPECT_EQ(lane.spans[0].sample_count, 2u);
    EXPECT_EQ(lane.spans[0].peak_stack_depth_bytes, 32'768ULL);
    EXPECT_EQ(lane.spans[1].state, peelf::ThreadSpanState::Waiting);
    EXPECT_EQ(lane.spans[1].wait_channel, "futex_wait_queue_me");
    EXPECT_EQ(lane.spans[2].state, peelf::ThreadSpanState::Running);
    EXPECT_FLOAT_EQ(lane.spans[2].peak_cpu_ratio, 1.0f);
    EXPECT_EQ(lane.spans[3].state, peelf::ThreadSpanState::SamplingGap);
    EXPECT_EQ(lane.spans[4].state, peelf::ThreadSpanState::Running);

    ASSERT_EQ(lane.metrics.size(), 5u);
    EXPECT_NEAR(lane.metrics[1].cpu_ratio, 0.50f, 1e-4f);
    EXPECT_NEAR(lane.metrics[1].kernel_share_ratio, 0.20f, 1e-4f);
    EXPECT_TRUE(lane.metrics[1].stack_depth_valid);
    EXPECT_EQ(lane.metrics[1].stack_depth_bytes, 32'768ULL);
    EXPECT_FLOAT_EQ(lane.metrics[3].cpu_ratio, 1.0f); // Clamped to [0.0, 1.0]
}

TEST(LiveThreadMonitorTest, RecycledTidSeparatesEpochsAndCrashDumpSeeding) {
    FakeLiveProcessSession session(7700u);
    std::uint64_t mocked_creation_ticks = 100ULL;

    peelf::LiveThreadMonitor monitor(
        {},
        [&](std::uint32_t /*pid*/, std::uint32_t tid) -> std::uint64_t {
            return tid == 8001u ? mocked_creation_ticks : 0ULL;
        });

    peelf::ThreadInfo worker{};
    worker.tid = 8001u;
    worker.name = "ephemeral_1";
    worker.state = peelf::ThreadRunState::Running;
    session.threads_ = {worker};
    ASSERT_TRUE(monitor.sample(session, {}, 1'000'000ULL).has_value());

    // Thread exits in sample 2.
    session.threads_.clear();
    ASSERT_TRUE(monitor.sample(session, {}, 2'000'000ULL).has_value());

    // OS recycles TID 8001 for a brand-new thread with distinct creation identity!
    mocked_creation_ticks = 250ULL;
    worker.name = "ephemeral_2";
    worker.state = peelf::ThreadRunState::Sleeping;
    session.threads_ = {worker};
    ASSERT_TRUE(monitor.sample(session, {}, 3'000'000ULL).has_value());

    const auto live_obs = monitor.snapshot();
    ASSERT_TRUE(live_obs.has_value());
    ASSERT_EQ(live_obs.value->lanes.size(), 2u);
    EXPECT_EQ(live_obs.value->lanes[0].identity.tid, 8001u);
    EXPECT_EQ(live_obs.value->lanes[0].identity.epoch, 1u);
    EXPECT_FALSE(live_obs.value->lanes[0].active);
    EXPECT_EQ(live_obs.value->lanes[1].identity.tid, 8001u);
    EXPECT_EQ(live_obs.value->lanes[1].identity.epoch, 2u);
    EXPECT_TRUE(live_obs.value->lanes[1].tid_recycled);
    EXPECT_TRUE(live_obs.value->lanes[1].active);

    // Also verify offline seeding from ICrashDumpSession.
    FakeCrashDumpSession dump;
    peelf::MemoryRegion dump_stack{};
    dump_stack.start_address = 0x7FFF'8000'0000ULL;
    dump_stack.end_address = 0x7FFF'8004'0000ULL;
    dump_stack.protection = {.readable = true, .writable = true};
    dump_stack.kind = peelf::MemoryRegionKind::Stack;
    dump.regions_ = {dump_stack};

    peelf::ThreadInfo crash_t{};
    crash_t.tid = 9002u;
    crash_t.name = "faulting_main";
    crash_t.state = peelf::ThreadRunState::Stopped;
    crash_t.instruction_pointer = 0x401234ULL;
    crash_t.stack_pointer = 0x7FFF'8004'0000ULL - 4096ULL;
    dump.threads_ = {crash_t};

    ASSERT_TRUE(monitor.seed_from_crash_dump(dump, 50'000'000ULL).has_value());
    const auto dump_obs = monitor.snapshot();
    ASSERT_TRUE(dump_obs.has_value());
    EXPECT_TRUE(dump_obs.value->seeded_from_crash_dump);
    EXPECT_EQ(dump_obs.provenance, peelf::ProvenanceTag::CrashDump);
    ASSERT_EQ(dump_obs.value->lanes.size(), 1u);
    EXPECT_TRUE(dump_obs.value->lanes[0].is_faulting_thread);
    EXPECT_EQ(dump_obs.value->lanes[0].latest_stack_depth_bytes, 4096ULL);
}

TEST(TimelineViewportIndexTest, Scalability250kSpansPriorityPreservationZoomAndHitTest) {
    // 250,000 total items:
    //   - 200,000 continuous ThreadStateSpans across 4 worker lanes (50,000 per lane)
    //   - 50,000 ExecutionTimeline events (including isolated high-priority DroppedEvents
    //     and DebuggerEvent markers surrounded by low-priority Sleeping spans!)
    peelf::ExecutionTimeline timeline(60'000u);

    constexpr std::uint64_t kOriginNs = 1'000'000'000ULL;
    constexpr std::uint64_t kStepNs = 1'000ULL; // 1 us per span -> 50 ms domain

    peelf::LiveThreadMonitorSnapshot mon_snap{};
    mon_snap.pid = 1234u;
    mon_snap.sample_sequence = 50'000u;
    mon_snap.first_sample_ns = kOriginNs;
    mon_snap.last_sample_ns = kOriginNs + 50'000ULL * kStepNs;

    for (std::uint32_t lane_i = 0u; lane_i < 4u; ++lane_i) {
        peelf::ThreadMonitorLane lane{};
        lane.identity = peelf::ThreadIdentity{
            .tid = 1000u + lane_i,
            .creation_identity = 5000ULL + lane_i,
            .epoch = 1u,
        };
        lane.name = "worker_" + std::to_string(lane_i);
        lane.active = true;
        lane.latest_state = peelf::ThreadSpanState::Sleeping;
        lane.spans.reserve(50'000u);

        for (std::size_t s = 0u; s < 50'000u; ++s) {
            const std::uint64_t t0 = kOriginNs + s * kStepNs;
            peelf::ThreadStateSpan sp{};
            sp.start_ns = t0;
            sp.end_ns = t0 + 800ULL;
            sp.state = (s % 17u == 0u) ? peelf::ThreadSpanState::Running
                                       : peelf::ThreadSpanState::Sleeping;
            sp.instruction_pointer = 0x400000ULL + s;
            sp.stack_pointer = 0x7FFF'0008'0000ULL - (s % 4096u);
            sp.peak_cpu_ratio = (sp.state == peelf::ThreadSpanState::Running) ? 0.75f : 0.01f;
            sp.peak_stack_depth_bytes = 2048ULL + (s % 4096u);
            lane.spans.push_back(sp);
        }
        mon_snap.lanes.push_back(std::move(lane));
    }

    const peelf::ThreadIdentity lane0_id = mon_snap.lanes[0].identity;
    const std::uint64_t critical_dbg_ns = kOriginNs + 25'000ULL * kStepNs + 200ULL;
    const std::uint64_t critical_drop_ns = kOriginNs + 37'500ULL * kStepNs + 200ULL;
    std::uint64_t critical_dbg_seq = 0u;

    for (std::size_t e = 0u; e < 50'000u; ++e) {
        const std::uint64_t ts = kOriginNs + e * kStepNs + 200ULL;
        peelf::CaptureStamp stamp{};
        stamp.snapshot_revision = e + 1u;
        stamp.monotonic_ns = ts;
        stamp.availability = peelf::CaptureAvailability::Complete;

        if (ts == critical_dbg_ns) {
            peelf::debugger::DebugEvent dbg{};
            dbg.sequence = e + 1u;
            dbg.kind = peelf::debugger::DebugEventKind::BreakpointHit;
            dbg.pid = 1234u;
            dbg.tid = lane0_id.tid;
            dbg.address = 0x40DEADULL;
            dbg.summary = "SIGTRAP breakpoint hit at 0x40DEAD";
            critical_dbg_seq = timeline.ingest_debug_event(
                dbg, stamp, lane0_id.creation_identity, "worker_0");
        } else if (ts == critical_drop_ns) {
            (void)timeline.record_dropped_events(
                12u, stamp, "test", "Ring overflow dropped 12 events");
        } else if (e % 10u == 0u) {
            // Global process-level module event (tid == 0 -> Process / Global lane)
            // surrounding the isolated `DroppedEvents` marker!
            peelf::debugger::DebugEvent mod_ev{};
            mod_ev.sequence = e + 1u;
            mod_ev.kind = peelf::debugger::DebugEventKind::DebugOutput;
            mod_ev.pid = 1234u;
            mod_ev.tid = 0u;
            mod_ev.summary = "trace output";
            (void)timeline.ingest_debug_event(mod_ev, stamp);
        } else {
            const auto& target_id = mon_snap.lanes[e % 4u].identity;
            peelf::SyscallEventPayload sys{};
            sys.syscall_number = 0u;
            sys.name = "read";
            (void)timeline.ingest_syscall_event(
                false,
                target_id.tid,
                std::move(sys),
                stamp,
                target_id.creation_identity);
        }
    }

    peelf::TimelineViewportIndex index;
    index.build(timeline, &mon_snap);
    EXPECT_EQ(index.total_indexed_items(), 250'000u);

    // 1. Wide full-domain query bounded strictly by `max_instances`.
    peelf::TimelineViewportQuery wide_q{};
    wide_q.view_start_ns = index.min_time_ns();
    wide_q.view_end_ns = index.max_time_ns();
    wide_q.viewport_width_px = 1000.0f;
    wide_q.viewport_height_px = 320.0f;
    wide_q.min_merge_px = 2.0f;
    wide_q.max_instances = 4096u;

    const peelf::TimelineViewportFrame wide_frame = index.query(wide_q);
    EXPECT_LE(wide_frame.instances.size(), wide_q.max_instances);
    EXPECT_GT(wide_frame.coalesced_cluster_count, 0u);

    // Verify priority preservation: neither DebuggerEvent nor DroppedEvents is hidden
    // behind lower-priority Sleeping / SyscallEntry / DebugEvent clusters!
    bool saw_debugger_priority = false;
    bool saw_dropped_priority = false;
    for (const peelf::TimelineHitRecord& rec : wide_frame.hit_records) {
        if (rec.start_ns <= critical_dbg_ns && rec.end_ns >= critical_dbg_ns &&
            rec.thread.has_value() && rec.thread->same_lane(lane0_id) &&
            rec.is_foreground_item) {
            if (rec.visual_kind == peelf::TimelineVisualKind::DebuggerEvent ||
                rec.cluster.dominant_kind == peelf::TimelineVisualKind::DebuggerEvent) {
                saw_debugger_priority = true;
            }
        }
        if (rec.start_ns <= critical_drop_ns && rec.end_ns >= critical_drop_ns &&
            !rec.thread.has_value() && rec.is_foreground_item) {
            if (rec.visual_kind == peelf::TimelineVisualKind::DroppedEvents ||
                rec.cluster.dominant_kind == peelf::TimelineVisualKind::DroppedEvents) {
                saw_dropped_priority = true;
            }
        }
    }
    EXPECT_TRUE(saw_debugger_priority);
    EXPECT_TRUE(saw_dropped_priority);

    // 2. Zoom-in refinement around `critical_dbg_ns` (4 us window -> individual spans & exact event!).
    peelf::TimelineViewportQuery zoom_q = wide_q;
    zoom_q.view_start_ns = critical_dbg_ns - 2'000ULL;
    zoom_q.view_end_ns = critical_dbg_ns + 2'000ULL;
    const peelf::TimelineViewportFrame zoom_frame = index.query(zoom_q);

    // Verify sub-microsecond ruler ticks exist in a 4 us window!
    EXPECT_LT(zoom_frame.ruler.major_step_ns, 2'000ULL);
    EXPECT_FALSE(zoom_frame.ruler.ticks.empty());

    const peelf::TimelineHitRecord* exact_dbg_hit = nullptr;
    for (const peelf::TimelineHitRecord& rec : zoom_frame.hit_records) {
        if (rec.kind == peelf::TimelineHitKind::TimelineEvent &&
            rec.event_sequence == critical_dbg_seq) {
            exact_dbg_hit = &rec;
            break;
        }
    }
    ASSERT_NE(exact_dbg_hit, nullptr);
    EXPECT_EQ(exact_dbg_hit->virtual_address, 0x40DEADULL);

    // Verify cursor spatial hit-testing hits the exact DebuggerEvent marker!
    const float hit_cx = 0.5f * (exact_dbg_hit->x0_px + exact_dbg_hit->x1_px);
    const float hit_cy = 0.5f * (exact_dbg_hit->y0_px + exact_dbg_hit->y1_px);
    const auto resolved = peelf::TimelineViewportIndex::hit_test(
        zoom_frame,
        peelf::TimelineHitQuery{.x_px = hit_cx, .y_px = hit_cy, .slop_px = 3.0f});
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->kind, peelf::TimelineHitKind::TimelineEvent);
    EXPECT_EQ(resolved->event_sequence, critical_dbg_seq);
}

TEST(TimelineRulerAndCpuRasterizerTest, NanosecondRulerAndDeterministicSdfRasterizer) {
    // Verify 10 ns / sub-microsecond ruler tick formatting.
    const peelf::TimelineRulerResult ns_ruler = peelf::generate_timeline_ruler_ticks(
        peelf::TimelineRulerConfig{
            .view_start_ns = 5'000'000ULL,
            .view_end_ns = 5'000'080ULL, // 80 ns window
            .origin_ns = 5'000'000ULL,
            .track_x0_px = 0.0f,
            .track_width_px = 800.0f,
            .target_major_spacing_px = 100.0f,
        });
    EXPECT_LE(ns_ruler.major_step_ns, 20ULL);
    EXPECT_GE(ns_ruler.major_step_ns, 1ULL);
    bool has_ns_label = false;
    for (const peelf::TimelineRulerTick& t : ns_ruler.ticks) {
        if (t.is_major && t.label.find("ns") != std::string::npos) {
            has_ns_label = true;
            break;
        }
    }
    EXPECT_TRUE(has_ns_label);

    // Deterministic CPU reference rasterizer verification across all 2D SDF shapes.
    const std::uint32_t clear_rgba = peelf::pack_timeline_rgba8(14u, 16u, 22u, 255u);
    std::vector<peelf::TimelineGpuInstance> instances = {
        // Rounded span
        peelf::TimelineGpuInstance{
            .x0_px = 12.0f,
            .y0_px = 10.0f,
            .x1_px = 92.0f,
            .y1_px = 30.0f,
            .fill_rgba8 = peelf::pack_timeline_rgba8(68u, 206u, 126u, 240u),
            .border_rgba8 = peelf::pack_timeline_rgba8(120u, 245u, 170u, 255u),
            .shape_and_flags = peelf::TimelineInstanceFlags::pack(
                peelf::TimelineInstanceShape::RoundedSpan,
                peelf::TimelineInstanceFlags::kCoalescedCluster),
            .hit_id = 1u,
        },
        // Instant diamond
        peelf::TimelineGpuInstance{
            .x0_px = 110.0f,
            .y0_px = 12.0f,
            .x1_px = 126.0f,
            .y1_px = 28.0f,
            .fill_rgba8 = peelf::pack_timeline_rgba8(245u, 148u, 56u, 255u),
            .border_rgba8 = peelf::pack_timeline_rgba8(255u, 220u, 160u, 255u),
            .shape_and_flags = peelf::TimelineInstanceFlags::pack(
                peelf::TimelineInstanceShape::InstantDiamond),
            .hit_id = 2u,
        },
        // Hatched uncertainty band (SamplingGap / DroppedEvents)
        peelf::TimelineGpuInstance{
            .x0_px = 140.0f,
            .y0_px = 8.0f,
            .x1_px = 200.0f,
            .y1_px = 48.0f,
            .fill_rgba8 = peelf::pack_timeline_rgba8(215u, 178u, 64u, 220u),
            .border_rgba8 = peelf::pack_timeline_rgba8(245u, 212u, 98u, 255u),
            .shape_and_flags = peelf::TimelineInstanceFlags::pack(
                peelf::TimelineInstanceShape::HatchedUncertaintyBand),
            .hit_id = 3u,
        },
        // Sparkline bar
        peelf::TimelineGpuInstance{
            .x0_px = 210.0f,
            .y0_px = 36.0f,
            .x1_px = 224.0f,
            .y1_px = 54.0f,
            .fill_rgba8 = peelf::pack_timeline_rgba8(82u, 198u, 250u, 230u),
            .border_rgba8 = peelf::pack_timeline_rgba8(82u, 198u, 250u, 255u),
            .shape_and_flags = peelf::TimelineInstanceFlags::pack(
                peelf::TimelineInstanceShape::SparklineColumn),
            .hit_id = peelf::kInvalidTimelineHitId,
        },
    };

    peelf::TimelineRasterConfig rcfg{};
    rcfg.width = 240u;
    rcfg.height = 64u;
    rcfg.clear_rgba8 = clear_rgba;

    const std::vector<std::uint8_t> img_a =
        peelf::rasterize_timeline_viewport_rgba8(instances, rcfg);
    const std::vector<std::uint8_t> img_b =
        peelf::rasterize_timeline_viewport_rgba8(instances, rcfg);
    ASSERT_EQ(img_a.size(), 240u * 64u * 4u);
    EXPECT_EQ(img_a, img_b); // Strictly deterministic

    const auto pixel_u32 = [&](const std::vector<std::uint8_t>& buf,
                               std::uint32_t x,
                               std::uint32_t y) -> std::uint32_t {
        const std::size_t off = (static_cast<std::size_t>(y) * rcfg.width + x) * 4u;
        return peelf::pack_timeline_rgba8(
            buf[off + 0u], buf[off + 1u], buf[off + 2u], buf[off + 3u]);
    };

    // Center of rounded span, diamond, hatched band, and sparkline differ from clear background.
    EXPECT_NE(pixel_u32(img_a, 50u, 20u), clear_rgba);
    EXPECT_NE(pixel_u32(img_a, 118u, 20u), clear_rgba);
    EXPECT_NE(pixel_u32(img_a, 170u, 28u), clear_rgba);
    EXPECT_NE(pixel_u32(img_a, 216u, 44u), clear_rgba);

    // Selection highlight modifies rendered span pixels deterministically.
    rcfg.selected_hit_id = 1u;
    const std::vector<std::uint8_t> img_sel =
        peelf::rasterize_timeline_viewport_rgba8(instances, rcfg);
    EXPECT_NE(pixel_u32(img_sel, 50u, 20u), pixel_u32(img_a, 50u, 20u));
}
