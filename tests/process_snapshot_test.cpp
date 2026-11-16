#include <gtest/gtest.h>

#include "model/binary_model.hpp"

#include <peelf/executable_settings.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/provenance.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace peelf;

class MockProcessSession final : public IProcessSession {
public:
    ProcessInfo proc_info{};
    bool alive{true};
    bool read_only{true};
    bool crash_dump{false};
    bool suspended{false};

    Result<std::vector<MemoryRegion>> regions_result{std::vector<MemoryRegion>{}};
    Result<std::vector<ModuleInfo>> modules_result{std::vector<ModuleInfo>{}};
    Result<std::vector<ThreadInfo>> threads_result{std::vector<ThreadInfo>{}};
    std::map<ThreadId, ThreadContext> thread_contexts{};
    ForgivingValue<std::vector<std::string>> env_result{
        std::nullopt,
        SubsystemStatus::unavailable("mock", "no environment configured")};
    std::map<std::uint64_t, std::vector<std::uint8_t>> readable_pages{};

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
        return regions_result;
    }
    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        return modules_result;
    }
    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        return threads_result;
    }

    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        if (const auto it = thread_contexts.find(tid); it != thread_contexts.end()) {
            return it->second;
        }
        ThreadContext ctx{};
        ctx.tid = tid;
        ctx.layout = target_layout();
        ctx.status = SubsystemStatus::unavailable("mock", "context missing");
        return ctx;
    }

    [[nodiscard]] Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0u};
        }
        std::size_t copied = 0u;
        for (std::size_t i = 0u; i < buffer.size(); ++i) {
            if (address > std::numeric_limits<std::uint64_t>::max() - i) {
                break;
            }
            const std::uint64_t va = address + i;
            bool byte_found = false;
            for (const auto& [base, data] : readable_pages) {
                if (va >= base && (va - base) < data.size()) {
                    buffer[i] = data[static_cast<std::size_t>(va - base)];
                    byte_found = true;
                    break;
                }
            }
            if (!byte_found) {
                if (copied == 0u) {
                    return make_error("unmapped or guard page in mock session");
                }
                break;
            }
            ++copied;
        }
        return copied;
    }

    [[nodiscard]] ForgivingValue<std::vector<std::string>> environment_variables() override {
        return env_result;
    }
};

[[nodiscard]] TargetInstanceId make_target_id(
    ProcessId pid,
    std::uint64_t creation_ticks) noexcept {
    TargetInstanceId tid{};
    tid.backend = BackendKind::LiveNativeReadOnly;
    tid.pid = pid;
    tid.creation_identity = creation_ticks;
    return tid;
}

[[nodiscard]] ProcessStateSnapshot make_complete_baseline_snapshot(
    const TargetInstanceId& tid,
    std::uint64_t rev) {
    ProcessStateSnapshot snap{};
    snap.target_id = tid;
    snap.snapshot_revision = rev;
    snap.snapshot_stamp = CaptureStamp::capture_now(tid, rev, true, CaptureAvailability::Complete);
    snap.paused_during_capture = true;

    const auto stamp_complete = [&]() {
        return CaptureStamp::capture_now(tid, rev, true, CaptureAvailability::Complete);
    };

    snap.modules = Observed<std::vector<ModuleInfo>>::complete(
        std::vector<ModuleInfo>{
            ModuleInfo{
                .name = "app",
                .path = "/opt/bin/app",
                .base_address = 0x400000u,
                .size = 0x4000u,
                .entry_point = 0x401000u,
            },
            ModuleInfo{
                .name = "libalpha.so",
                .path = "/usr/lib/libalpha.so",
                .base_address = 0x7F00100000u,
                .size = 0x8000u,
                .entry_point = 0x7F00101000u,
            },
        },
        ProvenanceTag::ProcOrOsApi,
        stamp_complete());

    snap.regions = Observed<std::vector<MemoryRegion>>::complete(
        std::vector<MemoryRegion>{
            MemoryRegion{
                .start_address = 0x400000u,
                .end_address = 0x403000u,
                .protection = {.readable = true, .writable = false, .executable = true},
                .kind = MemoryRegionKind::Image,
                .pathname = "/opt/bin/app",
                .module_name = "app",
            },
            MemoryRegion{
                .start_address = 0x600000u,
                .end_address = 0x601000u,
                .protection = {.readable = true, .writable = true, .executable = false},
                .kind = MemoryRegionKind::Heap,
                .pathname = "[heap]",
            },
            MemoryRegion{
                .start_address = 0x601000u,
                .end_address = 0x602000u,
                .protection = {.readable = true, .writable = true, .executable = false},
                .kind = MemoryRegionKind::Heap,
                .pathname = "[heap]",
            },
        },
        ProvenanceTag::ProcOrOsApi,
        stamp_complete());

    ThreadSnapshot main_t{};
    main_t.info.tid = 1001u;
    main_t.info.state = ThreadRunState::Running;
    main_t.info.instruction_pointer = 0x401100u;
    main_t.info.stack_pointer = 0x7FFF0000u;
    main_t.creation_identity = 500001u;
    main_t.context = Observed<ThreadContext>::unavailable(
        ProvenanceTag::ProcOrOsApi, "not needed", stamp_complete());

    snap.threads = Observed<std::vector<ThreadSnapshot>>::complete(
        std::vector<ThreadSnapshot>{main_t},
        ProvenanceTag::ProcOrOsApi,
        stamp_complete());

    snap.handles = Observed<std::vector<ProcessHandleEntry>>::complete(
        std::vector<ProcessHandleEntry>{
            ProcessHandleEntry{
                .handle_or_fd = 3u,
                .kind = ProcessHandleKind::File,
                .type_name = "File",
                .target = "/var/log/app.log",
                .access_or_flags = "0100002",
                .offset = 128u,
                .inode = 9001u,
                .mount_id = 25u,
            },
        },
        ProvenanceTag::ProcOrOsApi,
        stamp_complete());

    snap.sockets = Observed<std::vector<ProcessSocketEntry>>::complete(
        std::vector<ProcessSocketEntry>{
            ProcessSocketEntry{
                .protocol = SocketProtocol::Tcp4,
                .fd = 4u,
                .inode = 77001u,
                .local_endpoint = "127.0.0.1:51234",
                .remote_endpoint = "10.0.0.5:443",
                .state = "ESTABLISHED",
            },
        },
        ProvenanceTag::ProcOrOsApi,
        stamp_complete());

    return snap;
}

}  // namespace

TEST(ProcessSnapshotTest, CaptureProcessSnapshotStampsCollectionsAndTolerantStackBytes) {
    MockProcessSession session{};
    session.proc_info.pid = 4242u;
    session.proc_info.name = "demo_target";
    session.proc_info.executable_path = "/opt/demo/demo_target";
    session.proc_info.working_directory = "/opt/demo";
    session.proc_info.command_line = "/opt/demo/demo_target --port 8080";
    session.proc_info.architecture = Architecture::X86_64;
    session.proc_info.is_64bit = true;

    session.regions_result = std::vector<MemoryRegion>{
        MemoryRegion{
            .start_address = 0x400000u,
            .end_address = 0x402000u,
            .protection = {.readable = true, .writable = false, .executable = true},
            .kind = MemoryRegionKind::Image,
            .pathname = "/opt/demo/demo_target",
        },
        MemoryRegion{
            .start_address = 0x7FFF0000u,
            .end_address = 0x7FFF1000u,
            .protection = {.readable = true, .writable = true, .executable = false},
            .kind = MemoryRegionKind::Stack,
            .pathname = "[stack]",
        },
    };
    session.modules_result = std::vector<ModuleInfo>{
        ModuleInfo{
            .name = "demo_target",
            .path = "/opt/demo/demo_target",
            .base_address = 0x400000u,
            .size = 0x2000u,
            .entry_point = 0x401000u,
        },
    };
    session.threads_result = std::vector<ThreadInfo>{
        ThreadInfo{
            .tid = 4242u,
            .name = "main",
            .state = ThreadRunState::Stopped,
        },
    };

    ThreadContext ctx{};
    ctx.tid = 4242u;
    ctx.layout = TargetLayout::from_arch(Architecture::X86_64, true, Endianness::Little);
    ctx.instruction_pointer = 0x401080u;
    ctx.stack_pointer = 0x7FFF0F80u;
    ctx.frame_pointer = 0u;
    ctx.status = SubsystemStatus::available("mock", "ok");
    session.thread_contexts[4242u] = ctx;

    // Map only first 32 bytes at SP [0x7FFF0F80, 0x7FFF0FA0); leave [0x7FFF0FA0, 0x7FFF0FC0) unmapped
    // so per-byte stack validity marks 32 readable bytes and 32 invalid bytes.
    session.readable_pages[0x7FFF0F80u] = std::vector<std::uint8_t>(32u, 0xCCu);
    session.env_result = {
        std::vector<std::string>{"APP_ENV=staging", "API_TOKEN=tok_secret_value"},
        SubsystemStatus::available("mock", "2 entries"),
    };

    CaptureOptions opts{};
    opts.pause_target_during_capture = true;
    opts.max_stack_bytes_per_thread = 64u;
    opts.capture_handles_and_sockets = false;

    const ProcessStateSnapshot snap = capture_process_snapshot(session, opts);
    EXPECT_FALSE(session.is_suspended());  // ScopedProcessPause resumed cleanly after capture.
    EXPECT_TRUE(snap.paused_during_capture);
    EXPECT_GT(snap.snapshot_revision, 0u);
    EXPECT_FALSE(snap.snapshot_stamp.captured_at_utc.empty());

    ASSERT_TRUE(snap.modules.has_value());
    EXPECT_EQ(snap.modules.availability, CaptureAvailability::Complete);
    EXPECT_EQ(snap.modules.stamp.snapshot_revision, snap.snapshot_revision);
    EXPECT_FALSE(snap.modules.stamp.captured_at_utc.empty());

    ASSERT_TRUE(snap.regions.has_value());
    EXPECT_EQ(snap.regions.availability, CaptureAvailability::Complete);
    EXPECT_EQ(snap.regions.stamp.snapshot_revision, snap.snapshot_revision);

    ASSERT_TRUE(snap.threads.has_value());
    ASSERT_EQ(snap.threads.value->size(), 1u);
    const ThreadSnapshot& ts = (*snap.threads.value)[0];
    EXPECT_TRUE(ts.context.has_value());
    EXPECT_EQ(ts.stack_capture_address, 0x7FFF0F80u);
    ASSERT_EQ(ts.stack_bytes.bytes.size(), 64u);
    ASSERT_EQ(ts.stack_bytes.valid.size(), 64u);
    EXPECT_EQ(ts.stack_bytes.readable_count, 32u);
    for (std::size_t i = 0u; i < 32u; ++i) {
        EXPECT_EQ(ts.stack_bytes.valid[i], 1u);
        EXPECT_EQ(ts.stack_bytes.bytes[i], 0xCCu);
    }
    for (std::size_t i = 32u; i < 64u; ++i) {
        EXPECT_EQ(ts.stack_bytes.valid[i], 0u);
    }

    EXPECT_TRUE(snap.handles.is_unavailable());
    EXPECT_TRUE(snap.sockets.is_unavailable());
    ASSERT_TRUE(snap.launch_environment.has_value());
    EXPECT_EQ(snap.launch_environment.value->capture_origin,
              EnvironmentCaptureOrigin::AttachedCurrentState);
}

TEST(ProcessSnapshotTest, PartialAndUnavailableCapturesEmitUncertaintyWithoutFalseRemovals) {
    const TargetInstanceId tid = make_target_id(9001u, 123456789u);
    const ProcessStateSnapshot before = make_complete_baseline_snapshot(tid, 1u);
    ProcessStateSnapshot after = make_complete_baseline_snapshot(tid, 2u);

    const auto partial_stamp = [&]() {
        return CaptureStamp::capture_now(tid, 2u, false, CaptureAvailability::Partial);
    };
    const auto unavail_stamp = [&]() {
        return CaptureStamp::capture_now(tid, 2u, false, CaptureAvailability::Unavailable);
    };

    // Simulate a partial `after` capture that missed `libalpha.so`, heap regions, TID 1001, and socket,
    // while `handles` failed completely (`Unavailable`).
    after.modules = Observed<std::vector<ModuleInfo>>::partial(
        std::vector<ModuleInfo>{(*before.modules.value)[0]},
        ProvenanceTag::ProcOrOsApi,
        "truncated module walk",
        partial_stamp());

    // Keep `[0x400000, 0x403000)` but transition to RWX, while omitting `[0x600000, 0x602000)` in partial map!
    MemoryRegion rwx_app = (*before.regions.value)[0];
    rwx_app.protection.writable = true;
    after.regions = Observed<std::vector<MemoryRegion>>::partial(
        std::vector<MemoryRegion>{rwx_app},
        ProvenanceTag::ProcOrOsApi,
        "partial maps read",
        partial_stamp());

    after.threads = Observed<std::vector<ThreadSnapshot>>::partial(
        std::vector<ThreadSnapshot>{},
        ProvenanceTag::ProcOrOsApi,
        "partial /proc/<pid>/task scan",
        partial_stamp());

    after.handles = Observed<std::vector<ProcessHandleEntry>>::unavailable(
        ProvenanceTag::ProcOrOsApi,
        "permission denied opening /proc/<pid>/fd",
        unavail_stamp());

    after.sockets = Observed<std::vector<ProcessSocketEntry>>::partial(
        std::vector<ProcessSocketEntry>{},
        ProvenanceTag::ProcOrOsApi,
        "partial socket table",
        partial_stamp());

    const SnapshotDiff diff = diff_process_snapshots(before, after);
    EXPECT_TRUE(diff.target_identity_matched);
    EXPECT_FALSE(diff.rejected_target_mismatch);

    // Zero false removals across every partial/unavailable collection!
    for (const ModuleDelta& md : diff.modules) {
        EXPECT_NE(md.kind, ModuleDeltaKind::Unloaded);
    }
    for (const RegionDelta& rd : diff.regions) {
        EXPECT_NE(rd.kind, RegionDeltaKind::Unmapped);
    }
    EXPECT_TRUE(diff.threads.empty());
    EXPECT_TRUE(diff.handles.empty());
    EXPECT_TRUE(diff.sockets.empty());

    // Positively observed in-place R-X -> RWX protection transition IS still reported!
    ASSERT_EQ(diff.regions.size(), 1u);
    EXPECT_EQ(diff.regions[0].kind, RegionDeltaKind::ProtectionChanged);
    EXPECT_TRUE(diff.regions[0].became_rwx);

    // Every degraded collection emitted an explicit `SnapshotUncertainty` record.
    ASSERT_EQ(diff.uncertainties.size(), 5u);
    const auto find_unc = [&](DiffDomain dom) -> const SnapshotUncertainty* {
        for (const SnapshotUncertainty& u : diff.uncertainties) {
            if (u.domain == dom) {
                return &u;
            }
        }
        return nullptr;
    };

    const SnapshotUncertainty* mod_u = find_unc(DiffDomain::Modules);
    ASSERT_NE(mod_u, nullptr);
    EXPECT_EQ(mod_u->kind, DiffUncertaintyKind::PartialAfterCapture);
    EXPECT_EQ(mod_u->suppressed_removal_count, 1u);

    const SnapshotUncertainty* reg_u = find_unc(DiffDomain::Regions);
    ASSERT_NE(reg_u, nullptr);
    EXPECT_EQ(reg_u->kind, DiffUncertaintyKind::PartialAfterCapture);
    EXPECT_EQ(reg_u->suppressed_removal_count, 2u);

    const SnapshotUncertainty* th_u = find_unc(DiffDomain::Threads);
    ASSERT_NE(th_u, nullptr);
    EXPECT_EQ(th_u->suppressed_removal_count, 1u);

    const SnapshotUncertainty* hnd_u = find_unc(DiffDomain::Handles);
    ASSERT_NE(hnd_u, nullptr);
    EXPECT_EQ(hnd_u->kind, DiffUncertaintyKind::CollectionUnavailable);

    const SnapshotUncertainty* sck_u = find_unc(DiffDomain::Sockets);
    ASSERT_NE(sck_u, nullptr);
    EXPECT_EQ(sck_u->suppressed_removal_count, 1u);
}

TEST(ProcessSnapshotTest, PidTidFdSocketAndModuleVaReuseGuards) {
    // 1. PID reuse: identical PID 5555, different OS creation_identity -> rejected!
    {
        const ProcessStateSnapshot s1 =
            make_complete_baseline_snapshot(make_target_id(5555u, 1000u), 1u);
        const ProcessStateSnapshot s2 =
            make_complete_baseline_snapshot(make_target_id(5555u, 2000u), 2u);
        const SnapshotDiff pid_diff = diff_process_snapshots(s1, s2);
        EXPECT_FALSE(pid_diff.target_identity_matched);
        EXPECT_TRUE(pid_diff.rejected_target_mismatch);
        EXPECT_FALSE(pid_diff.has_changes());
        ASSERT_EQ(pid_diff.uncertainties.size(), 1u);
        EXPECT_EQ(pid_diff.uncertainties[0].domain, DiffDomain::TargetIdentity);
        EXPECT_EQ(pid_diff.uncertainties[0].kind, DiffUncertaintyKind::TargetIdentityMismatch);
    }

    // 2. TID, FD, Socket, and Module VA reuse within the same target instance:
    const TargetInstanceId tid = make_target_id(7777u, 999001u);
    const ProcessStateSnapshot before = make_complete_baseline_snapshot(tid, 10u);
    ProcessStateSnapshot after = make_complete_baseline_snapshot(tid, 11u);

    // Module VA reuse at 0x7F00100000: unload libalpha.so, load libbeta.so at exact same base VA!
    (*after.modules.value)[1] = ModuleInfo{
        .name = "libbeta.so",
        .path = "/usr/lib/libbeta.so",
        .base_address = 0x7F00100000u,
        .size = 0x9000u,
        .entry_point = 0x7F00102000u,
    };

    // TID reuse: TID 1001 exited (creation 500001) and a brand new thread reused TID 1001 (creation 500999).
    (*after.threads.value)[0].creation_identity = 500999u;
    (*after.threads.value)[0].info.instruction_pointer = 0x402000u;

    // FD reuse: FD 3 closed (/var/log/app.log, inode 9001) and reopened on /tmp/session.db (inode 9555).
    (*after.handles.value)[0] = ProcessHandleEntry{
        .handle_or_fd = 3u,
        .kind = ProcessHandleKind::File,
        .type_name = "File",
        .target = "/tmp/session.db",
        .access_or_flags = "0100002",
        .offset = 0u,
        .inode = 9555u,
        .mount_id = 25u,
    };

    // Socket FD reuse: FD 4 closed (inode 77001) and reused by a new socket (inode 88002).
    (*after.sockets.value)[0] = ProcessSocketEntry{
        .protocol = SocketProtocol::Tcp4,
        .fd = 4u,
        .inode = 88002u,
        .local_endpoint = "127.0.0.1:51234",
        .remote_endpoint = "10.0.0.99:8443",
        .state = "SYN_SENT",
    };

    const SnapshotDiff diff = diff_process_snapshots(before, after);
    EXPECT_TRUE(diff.target_identity_matched);
    EXPECT_FALSE(diff.has_uncertainties());

    // Modules: Unloaded (libalpha.so) + Loaded (libbeta.so), both flagging base_address_reused.
    ASSERT_EQ(diff.modules.size(), 2u);
    bool saw_mod_unload = false;
    bool saw_mod_load = false;
    for (const ModuleDelta& md : diff.modules) {
        EXPECT_TRUE(md.base_address_reused);
        if (md.kind == ModuleDeltaKind::Unloaded && md.before.has_value()) {
            EXPECT_EQ(md.before->name, "libalpha.so");
            saw_mod_unload = true;
        } else if (md.kind == ModuleDeltaKind::Loaded && md.after.has_value()) {
            EXPECT_EQ(md.after->name, "libbeta.so");
            saw_mod_load = true;
        }
    }
    EXPECT_TRUE(saw_mod_unload);
    EXPECT_TRUE(saw_mod_load);

    // Threads: Exited + Created, both flagging tid_reused (never StateOrContextChanged!).
    ASSERT_EQ(diff.threads.size(), 2u);
    bool saw_tid_exit = false;
    bool saw_tid_create = false;
    for (const ThreadDelta& td : diff.threads) {
        EXPECT_EQ(td.tid, 1001u);
        EXPECT_TRUE(td.tid_reused);
        saw_tid_exit = saw_tid_exit || (td.kind == ThreadDeltaKind::Exited);
        saw_tid_create = saw_tid_create || (td.kind == ThreadDeltaKind::Created);
    }
    EXPECT_TRUE(saw_tid_exit);
    EXPECT_TRUE(saw_tid_create);

    // Handles: Closed + Opened, both flagging fd_reused.
    ASSERT_EQ(diff.handles.size(), 2u);
    bool saw_fd_close = false;
    bool saw_fd_open = false;
    for (const HandleDelta& hd : diff.handles) {
        EXPECT_EQ(hd.handle_or_fd, 3u);
        EXPECT_TRUE(hd.fd_reused);
        saw_fd_close = saw_fd_close || (hd.kind == HandleDeltaKind::Closed);
        saw_fd_open = saw_fd_open || (hd.kind == HandleDeltaKind::Opened);
    }
    EXPECT_TRUE(saw_fd_close);
    EXPECT_TRUE(saw_fd_open);

    // Sockets: Closed + Opened, both flagging fd_or_endpoint_reused.
    ASSERT_EQ(diff.sockets.size(), 2u);
    bool saw_sock_close = false;
    bool saw_sock_open = false;
    for (const SocketDelta& sd : diff.sockets) {
        EXPECT_TRUE(sd.fd_or_endpoint_reused);
        saw_sock_close = saw_sock_close || (sd.kind == SocketDeltaKind::Closed);
        saw_sock_open = saw_sock_open || (sd.kind == SocketDeltaKind::Opened);
    }
    EXPECT_TRUE(saw_sock_close);
    EXPECT_TRUE(saw_sock_open);
}

TEST(ProcessSnapshotTest, SplitMergedRegionsRwxTransitionsAndHighAddressOverflowSafety) {
    const TargetInstanceId tid = make_target_id(8080u, 4444u);
    ProcessStateSnapshot before = make_complete_baseline_snapshot(tid, 1u);
    ProcessStateSnapshot after = make_complete_baseline_snapshot(tid, 2u);

    // Include a high-VA region abutting UINT64_MAX in both to verify overflow-free endpoint splitting.
    constexpr std::uint64_t kHighStart = std::numeric_limits<std::uint64_t>::max() - 0xFFFULL;
    constexpr std::uint64_t kHighEnd = std::numeric_limits<std::uint64_t>::max();
    before.regions.value->push_back(MemoryRegion{
        .start_address = kHighStart,
        .end_address = kHighEnd,
        .protection = {.readable = true, .writable = true, .executable = false},
        .kind = MemoryRegionKind::Anonymous,
    });

    // In `after`:
    // 1) Split `[0x400000, 0x403000) R-X` into:
    //    - `[0x400000, 0x401000) R-X` (Split)
    //    - `[0x401000, 0x402000) RWX` (ProtectionChanged + became_rwx + was_split)
    //    - `[0x402000, 0x403000) R-X` (Split)
    // 2) Merge `[0x600000, 0x601000) RW-` + `[0x601000, 0x602000) RW-` into `[0x600000, 0x602000) RW-`.
    // 3) Transition high-VA `[kHighStart, kHighEnd)` from `RW-` to `R-X` (JIT W^X transition).
    after.regions.value->clear();
    after.regions.value->push_back(MemoryRegion{
        .start_address = 0x400000u,
        .end_address = 0x401000u,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = MemoryRegionKind::Image,
        .pathname = "/opt/bin/app",
    });
    after.regions.value->push_back(MemoryRegion{
        .start_address = 0x401000u,
        .end_address = 0x402000u,
        .protection = {.readable = true, .writable = true, .executable = true},
        .kind = MemoryRegionKind::Image,
        .pathname = "/opt/bin/app",
    });
    after.regions.value->push_back(MemoryRegion{
        .start_address = 0x402000u,
        .end_address = 0x403000u,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = MemoryRegionKind::Image,
        .pathname = "/opt/bin/app",
    });
    after.regions.value->push_back(MemoryRegion{
        .start_address = 0x600000u,
        .end_address = 0x602000u,
        .protection = {.readable = true, .writable = true, .executable = false},
        .kind = MemoryRegionKind::Heap,
        .pathname = "[heap]",
    });
    after.regions.value->push_back(MemoryRegion{
        .start_address = kHighStart,
        .end_address = kHighEnd,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = MemoryRegionKind::Anonymous,
    });

    const SnapshotDiff diff = diff_process_snapshots(before, after);
    ASSERT_EQ(diff.regions.size(), 6u);

    EXPECT_EQ(diff.regions[0].start_address, 0x400000u);
    EXPECT_EQ(diff.regions[0].end_address, 0x401000u);
    EXPECT_EQ(diff.regions[0].kind, RegionDeltaKind::Split);
    EXPECT_TRUE(diff.regions[0].was_split);
    EXPECT_FALSE(diff.regions[0].became_rwx);

    EXPECT_EQ(diff.regions[1].start_address, 0x401000u);
    EXPECT_EQ(diff.regions[1].end_address, 0x402000u);
    EXPECT_EQ(diff.regions[1].kind, RegionDeltaKind::ProtectionChanged);
    EXPECT_TRUE(diff.regions[1].was_split);
    EXPECT_TRUE(diff.regions[1].became_rwx);
    EXPECT_FALSE(diff.regions[1].became_executable);  // Was already executable (R-X -> RWX).

    EXPECT_EQ(diff.regions[2].start_address, 0x402000u);
    EXPECT_EQ(diff.regions[2].end_address, 0x403000u);
    EXPECT_EQ(diff.regions[2].kind, RegionDeltaKind::Split);
    EXPECT_TRUE(diff.regions[2].was_split);

    EXPECT_EQ(diff.regions[3].start_address, 0x600000u);
    EXPECT_EQ(diff.regions[3].end_address, 0x601000u);
    EXPECT_EQ(diff.regions[3].kind, RegionDeltaKind::Merged);
    EXPECT_TRUE(diff.regions[3].was_merged);

    EXPECT_EQ(diff.regions[4].start_address, 0x601000u);
    EXPECT_EQ(diff.regions[4].end_address, 0x602000u);
    EXPECT_EQ(diff.regions[4].kind, RegionDeltaKind::Merged);
    EXPECT_TRUE(diff.regions[4].was_merged);

    EXPECT_EQ(diff.regions[5].start_address, kHighStart);
    EXPECT_EQ(diff.regions[5].end_address, kHighEnd);
    EXPECT_EQ(diff.regions[5].size(), 0xFFFULL);
    EXPECT_EQ(diff.regions[5].kind, RegionDeltaKind::ProtectionChanged);
    EXPECT_TRUE(diff.regions[5].jit_rw_to_rx);
    EXPECT_TRUE(diff.regions[5].became_executable);
    EXPECT_FALSE(diff.regions[5].became_rwx);
}

TEST(ProcessSnapshotTest, DefaultEnvironmentSecretRedactionSessionOptInAndCaptureOrigin) {
    auto session = std::make_unique<MockProcessSession>();
    session->proc_info.pid = 6161u;
    session->proc_info.name = "svc";
    session->proc_info.executable_path = "/usr/bin/svc";
    session->proc_info.working_directory = "/srv/svc";
    session->proc_info.command_line = "/usr/bin/svc --workers 4";
    session->proc_info.architecture = Architecture::X86_64;
    session->proc_info.is_64bit = true;
    session->regions_result = std::vector<MemoryRegion>{
        MemoryRegion{
            .start_address = 0x400000u,
            .end_address = 0x401000u,
            .protection = {.readable = true, .writable = false, .executable = true},
            .kind = MemoryRegionKind::Image,
            .pathname = "/usr/bin/svc",
        },
    };
    session->modules_result = std::vector<ModuleInfo>{
        ModuleInfo{
            .name = "svc",
            .path = "/usr/bin/svc",
            .base_address = 0x400000u,
            .size = 0x1000u,
        },
    };
    session->env_result = {
        std::vector<std::string>{
            "PATH=/usr/local/bin:/usr/bin",
            "AWS_SECRET_ACCESS_KEY=AKIA_TOP_SECRET_VALUE_999",
            "GITHUB_TOKEN=ghp_super_confidential_token",
            "DB_DSN=postgres://svc_user: hunter2_pw @db.local:5432/prod",
            "LOG_LEVEL=info",
        },
        SubsystemStatus::available("mock", "5 vars"),
    };

    // Verify launch-captured vs attach-captured vs crash-dump origin distinction.
    {
        RuntimeSettingsOptions launch_opts{};
        launch_opts.launched_by_session = true;
        launch_opts.query_process_internals = false;
        const auto launch_env = extract_launch_environment_settings(
            *session, make_target_id(6161u, 11u), 1u, launch_opts);
        ASSERT_TRUE(launch_env.has_value());
        EXPECT_EQ(launch_env.value->capture_origin, EnvironmentCaptureOrigin::LaunchCaptured);

        session->crash_dump = true;
        const auto dump_env = extract_launch_environment_settings(
            *session, make_target_id(6161u, 11u), 2u, RuntimeSettingsOptions{.query_process_internals = false});
        ASSERT_TRUE(dump_env.has_value());
        EXPECT_EQ(dump_env.value->capture_origin, EnvironmentCaptureOrigin::CrashDumpState);
        session->crash_dump = false;
    }

    viewer::BinaryModel model{};
    ASSERT_TRUE(model.attach_session(std::move(session)).has_value());

    // Default policy on attach MUST be RedactSensitiveDefault and MUST NOT leak secrets in display or JSON!
    EXPECT_EQ(model.environment_redaction_policy(),
              EnvironmentRedactionPolicy::RedactSensitiveDefault);
    const ExecutableSettingsReport& default_report = model.executable_settings();
    ASSERT_TRUE(default_report.launch_environment.has_value());
    EXPECT_EQ(default_report.launch_environment.value->capture_origin,
              EnvironmentCaptureOrigin::AttachedCurrentState);
    ASSERT_TRUE(default_report.launch_environment.value->environment.has_value());

    const auto& vars = *default_report.launch_environment.value->environment.value;
    ASSERT_EQ(vars.size(), 5u);
    EXPECT_FALSE(vars[0].redacted);
    EXPECT_EQ(vars[0].display_value, "/usr/local/bin:/usr/bin");
    EXPECT_TRUE(vars[1].redacted);
    EXPECT_EQ(vars[1].availability, CaptureAvailability::Redacted);
    EXPECT_EQ(vars[1].display_value.find("AKIA_TOP_SECRET_VALUE_999"), std::string::npos);
    EXPECT_TRUE(vars[2].redacted);
    EXPECT_EQ(vars[2].display_value.find("ghp_super_confidential_token"), std::string::npos);
    EXPECT_TRUE(vars[3].redacted);
    EXPECT_EQ(vars[3].display_value.find("hunter2_pw"), std::string::npos);
    EXPECT_FALSE(vars[4].redacted);
    EXPECT_EQ(vars[4].display_value, "info");

    const std::string json_redacted = format_executable_settings_json(default_report);
    EXPECT_EQ(json_redacted.find("AKIA_TOP_SECRET_VALUE_999"), std::string::npos);
    EXPECT_EQ(json_redacted.find("ghp_super_confidential_token"), std::string::npos);
    EXPECT_NE(json_redacted.find("\"capture_origin\": \"AttachedCurrentState\""), std::string::npos);

    // Explicit session opt-in reveals values for current session, and detach resets back to default!
    model.set_environment_redaction_policy(EnvironmentRedactionPolicy::RevealUnredactedOptIn);
    const auto& revealed_vars =
        *model.executable_settings().launch_environment.value->environment.value;
    EXPECT_FALSE(revealed_vars[1].redacted);
    EXPECT_EQ(revealed_vars[1].display_value, "AKIA_TOP_SECRET_VALUE_999");

    model.detach_process();
    EXPECT_EQ(model.environment_redaction_policy(),
              EnvironmentRedactionPolicy::RedactSensitiveDefault);
}

TEST(ProcessSnapshotTest, DeclaredVsLoadedModuleReconciliationTimelineProofAndStaticUnavailable) {
    // 1. Static-only load must explicitly mark runtime sections `Unavailable` (never blank/ambiguous).
    viewer::BinaryModel static_model{};
    ASSERT_TRUE(static_model.load_file(PEELF_CALLGRAPH_FIXTURE_EXE));
    const ExecutableSettingsReport& static_rep = static_model.executable_settings();
    EXPECT_TRUE(static_rep.declared_in_file.has_value());
    EXPECT_TRUE(static_rep.launch_environment.is_unavailable());
    EXPECT_FALSE(static_rep.launch_environment.note.empty());
    EXPECT_TRUE(static_rep.observed_runtime.is_unavailable());
    EXPECT_FALSE(static_rep.observed_runtime.note.empty());

    // 2. Reconcile ELF declared dependencies (including symlink-resolved `libstdc++.so.6.0.30` and PT_INTERP)
    //    against loaded modules, keeping unmatched modules honest until proven by snapshot timeline delta!
    DeclaredSettings decl{};
    decl.format = Format::ELF;
    decl.kind = ImageKind::Executable;
    decl.architecture = Architecture::X86_64;
    decl.is_64bit = true;
    decl.declared_dependencies = {"libc.so.6", "libstdc++.so.6", "libmissing_opt.so.1"};
    ElfDeclaredSettings elf_s{};
    elf_s.interpreter = "/lib64/ld-linux-x86-64.so.2";
    elf_s.needed_libraries = decl.declared_dependencies;
    decl.elf_settings_state = MetadataFieldState::Present;
    decl.elf_settings = Observed<ElfDeclaredSettings>::complete(std::move(elf_s), ProvenanceTag::DiskFile);

    const TargetInstanceId tid = make_target_id(31337u, 8888u);
    const CaptureStamp s1 = CaptureStamp::capture_now(tid, 1u, true, CaptureAvailability::Complete);
    const auto decl_obs =
        Observed<DeclaredSettings>::complete(std::move(decl), ProvenanceTag::DiskFile, s1);

    std::vector<ModuleInfo> initial_mods = {
        ModuleInfo{.name = "app_bin", .path = "/opt/app/app_bin", .base_address = 0x400000u, .size = 0x5000u},
        ModuleInfo{.name = "ld-linux-x86-64.so.2", .path = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", .base_address = 0x7F00010000u, .size = 0x3000u},
        ModuleInfo{.name = "libc.so.6", .path = "/usr/lib/x86_64-linux-gnu/libc.so.6", .base_address = 0x7F00100000u, .size = 0x20000u},
        ModuleInfo{.name = "libstdc++.so.6.0.30", .path = "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30", .base_address = 0x7F00200000u, .size = 0x30000u},
        ModuleInfo{.name = "libgcc_s.so.1", .path = "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1", .base_address = 0x7F00300000u, .size = 0x8000u},
    };
    const auto mods_obs_1 = Observed<std::vector<ModuleInfo>>::complete(
        initial_mods, ProvenanceTag::ProcOrOsApi, s1);

    const auto cmp_without_timeline = reconcile_declared_vs_loaded_modules(
        decl_obs, mods_obs_1, "/opt/app/app_bin");
    ASSERT_TRUE(cmp_without_timeline.has_value());
    EXPECT_EQ(cmp_without_timeline.value->matched_declared,
              (std::vector<std::string>{"libc.so.6", "libstdc++.so.6"}));
    EXPECT_EQ(cmp_without_timeline.value->missing_declared,
              (std::vector<std::string>{"libmissing_opt.so.1"}));
    ASSERT_EQ(cmp_without_timeline.value->unmatched_loaded.size(), 1u);
    EXPECT_EQ(cmp_without_timeline.value->unmatched_loaded[0].module_name, "libgcc_s.so.1");
    EXPECT_FALSE(cmp_without_timeline.value->runtime_load_proven_by_timeline);
    EXPECT_NE(cmp_without_timeline.value->unmatched_loaded[0].provenance_note.find("not asserted"),
              std::string::npos);

    // Now simulate snapshot #2 where `libhotplug.so` is dynamically loaded at `0x7F00900000`,
    // and feed `collect_loaded_module_bases_from_diff` into reconciliation!
    ProcessStateSnapshot snap_before = make_complete_baseline_snapshot(tid, 1u);
    snap_before.modules = mods_obs_1;

    std::vector<ModuleInfo> after_mods = initial_mods;
    after_mods.push_back(ModuleInfo{
        .name = "libhotplug.so",
        .path = "/opt/app/plugins/libhotplug.so",
        .base_address = 0x7F00900000u,
        .size = 0x4000u,
    });
    const CaptureStamp s2 = CaptureStamp::capture_now(tid, 2u, true, CaptureAvailability::Complete);
    ProcessStateSnapshot snap_after = make_complete_baseline_snapshot(tid, 2u);
    snap_after.modules =
        Observed<std::vector<ModuleInfo>>::complete(after_mods, ProvenanceTag::ProcOrOsApi, s2);

    const SnapshotDiff mod_diff = diff_process_snapshots(snap_before, snap_after);
    const std::vector<std::uint64_t> proven_bases =
        collect_loaded_module_bases_from_diff(mod_diff);
    ASSERT_EQ(proven_bases, (std::vector<std::uint64_t>{0x7F00900000u}));

    const auto cmp_with_timeline = reconcile_declared_vs_loaded_modules(
        decl_obs, snap_after.modules, "/opt/app/app_bin", proven_bases);
    ASSERT_TRUE(cmp_with_timeline.has_value());
    EXPECT_TRUE(cmp_with_timeline.value->runtime_load_proven_by_timeline);
    ASSERT_EQ(cmp_with_timeline.value->unmatched_loaded.size(), 2u);
    EXPECT_EQ(cmp_with_timeline.value->unmatched_loaded[0].module_name, "libgcc_s.so.1");
    EXPECT_NE(cmp_with_timeline.value->unmatched_loaded[0].provenance_note.find("not asserted"),
              std::string::npos);
    EXPECT_EQ(cmp_with_timeline.value->unmatched_loaded[1].module_name, "libhotplug.so");
    EXPECT_NE(cmp_with_timeline.value->unmatched_loaded[1].provenance_note.find(
                  "Observed newly loaded across session snapshots"),
              std::string::npos);
}
