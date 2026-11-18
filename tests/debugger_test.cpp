#include <gtest/gtest.h>

#include "model/binary_model.hpp"

#include <peelf/debugger.hpp>
#include <peelf/process.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <csignal>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace peelf;
using namespace peelf::debugger;

TEST(DebuggerCoreUnit, MultiArchSoftwareTrapSelection) {
    // x86 / x86_64 -> 1-byte INT3 (0xCC) with 1-byte PC rewind
    {
        const auto x64 = select_software_trap(Architecture::X86_64, Endianness::Little, false);
        ASSERT_TRUE(x64.has_value());
        EXPECT_EQ(x64->size, 1u);
        EXPECT_EQ(x64->bytes[0], 0xCCu);
        EXPECT_TRUE(x64->rewinds_pc_on_hit);

        const auto x86 = select_software_trap(Architecture::X86, Endianness::Little, false);
        ASSERT_TRUE(x86.has_value());
        EXPECT_EQ(x86->size, 1u);
        EXPECT_EQ(x86->bytes[0], 0xCCu);
        EXPECT_TRUE(x86->rewinds_pc_on_hit);
    }

    // AArch64 -> 4-byte BRK #0 (0xD4200000 LE) with 0-byte PC rewind
    {
        const auto a64 = select_software_trap(Architecture::ARM64, Endianness::Little, false);
        ASSERT_TRUE(a64.has_value());
        EXPECT_EQ(a64->size, 4u);
        const std::array<std::uint8_t, 4> expected{0x00u, 0x00u, 0x20u, 0xD4u};
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), a64->span().begin()));
        EXPECT_FALSE(a64->rewinds_pc_on_hit);
    }

    // ARM32 vs Thumb BKPT #0
    {
        const auto arm = select_software_trap(Architecture::ARM, Endianness::Little, false);
        ASSERT_TRUE(arm.has_value());
        EXPECT_EQ(arm->size, 4u);
        EXPECT_EQ(arm->bytes[0], 0x70u);
        EXPECT_EQ(arm->bytes[3], 0xE1u);

        const auto thumb = select_software_trap(Architecture::ARM, Endianness::Little, true);
        ASSERT_TRUE(thumb.has_value());
        EXPECT_EQ(thumb->size, 2u);
        EXPECT_EQ(thumb->bytes[0], 0x00u);
        EXPECT_EQ(thumb->bytes[1], 0xBEu);
    }

    // RISC-V EBREAK -> 0x00100073 LE
    {
        const auto rv = select_software_trap(Architecture::RISCV64, Endianness::Little, false);
        ASSERT_TRUE(rv.has_value());
        EXPECT_EQ(rv->size, 4u);
        const std::array<std::uint8_t, 4> expected{0x73u, 0x00u, 0x10u, 0x00u};
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), rv->span().begin()));
    }

    // PowerPC big-endian vs little-endian trap
    {
        const auto ppc_be = select_software_trap(Architecture::PowerPC, Endianness::Big, false);
        ASSERT_TRUE(ppc_be.has_value());
        const std::array<std::uint8_t, 4> expected_be{0x7Fu, 0xE0u, 0x00u, 0x08u};
        EXPECT_TRUE(std::equal(expected_be.begin(), expected_be.end(), ppc_be->span().begin()));

        const auto ppc_le = select_software_trap(Architecture::PowerPC64, Endianness::Little, false);
        ASSERT_TRUE(ppc_le.has_value());
        const std::array<std::uint8_t, 4> expected_le{0x08u, 0x00u, 0xE0u, 0x7Fu};
        EXPECT_TRUE(std::equal(expected_le.begin(), expected_le.end(), ppc_le->span().begin()));
    }
}

TEST(DebuggerCoreUnit, ShadowFilterMasksArmedSoftwareTrapsCleanly) {
    // Original buffer in target RAM has 0xCC at offset 2 and 4-byte BRK at offset 8..12.
    std::vector<std::uint8_t> raw_ram = {
        0x55, 0x48, 0xCC, 0xE5,
        0x90, 0x90, 0x90, 0x90,
        0x00, 0x00, 0x20, 0xD4,
        0xC3, 0xCC, 0x90, 0x90,
    };

    BreakpointDescriptor bp1{};
    bp1.id = 1;
    bp1.kind = BreakpointKind::Software;
    bp1.address = 0x401002;
    bp1.byte_size = 1;
    bp1.enabled = true;
    bp1.armed_in_target = true;
    bp1.original_bytes = {0x89};

    BreakpointDescriptor bp2{};
    bp2.id = 2;
    bp2.kind = BreakpointKind::Software;
    bp2.address = 0x401008;
    bp2.byte_size = 4;
    bp2.enabled = true;
    bp2.armed_in_target = true;
    bp2.original_bytes = {0x48, 0x83, 0xEC, 0x20};

    // Disarmed breakpoint at offset 13 should NOT overwrite RAM bytes!
    BreakpointDescriptor bp_disarmed{};
    bp_disarmed.id = 3;
    bp_disarmed.kind = BreakpointKind::Software;
    bp_disarmed.address = 0x40100D;
    bp_disarmed.byte_size = 1;
    bp_disarmed.enabled = false;
    bp_disarmed.armed_in_target = false;
    bp_disarmed.original_bytes = {0xAA};

    const std::vector<BreakpointDescriptor> bps{bp1, bp2, bp_disarmed};
    apply_software_breakpoint_shadow_filter(0x401000, raw_ram, bps);

    EXPECT_EQ(raw_ram[2], 0x89u);
    EXPECT_EQ(raw_ram[8], 0x48u);
    EXPECT_EQ(raw_ram[9], 0x83u);
    EXPECT_EQ(raw_ram[10], 0xECu);
    EXPECT_EQ(raw_ram[11], 0x20u);
    EXPECT_EQ(raw_ram[13], 0xCCu);  // unarmed -> untouched

    // Partial boundary overlap test: reading 2 bytes starting at 0x40100A (middle of bp2)
    std::array<std::uint8_t, 2> partial{0x20u, 0xD4u};
    apply_software_breakpoint_shadow_filter(0x40100A, partial, bps);
    EXPECT_EQ(partial[0], 0xECu);
    EXPECT_EQ(partial[1], 0x20u);
}

TEST(DebuggerCoreUnit, X86DebugRegisterDr7EncodingAndSlotLimits) {
    BreakpointDescriptor exec_bp{
        .id = 10,
        .kind = BreakpointKind::HardwareExecute,
        .address = 0x401000,
        .byte_size = 1,
        .enabled = true,
    };
    BreakpointDescriptor write_4b{
        .id = 11,
        .kind = BreakpointKind::HardwareWrite,
        .address = 0x602000,
        .byte_size = 4,
        .enabled = true,
    };
    BreakpointDescriptor rw_8b{
        .id = 12,
        .kind = BreakpointKind::HardwareReadWrite,
        .address = 0x602008,
        .byte_size = 8,
        .enabled = true,
    };
    BreakpointDescriptor write_2b{
        .id = 13,
        .kind = BreakpointKind::HardwareWrite,
        .address = 0x602012,
        .byte_size = 2,
        .enabled = true,
    };

    const std::vector<BreakpointDescriptor> four_bps{exec_bp, write_4b, rw_8b, write_2b};
    const auto plan = build_x86_debug_register_plan(Architecture::X86_64, four_bps);
    ASSERT_TRUE(plan.has_value()) << plan.status.detail;
    EXPECT_TRUE(plan.value->slot_used[0]);
    EXPECT_TRUE(plan.value->slot_used[1]);
    EXPECT_TRUE(plan.value->slot_used[2]);
    EXPECT_TRUE(plan.value->slot_used[3]);
    EXPECT_EQ(plan.value->dr_address[0], 0x401000u);
    EXPECT_EQ(plan.value->dr_address[2], 0x602008u);

    // Verify local enable bits L0..L3 (bits 0, 2, 4, 6) are all set:
    EXPECT_EQ(plan.value->dr7 & 0x55ULL, 0x55ULL);
    // Slot 1: Write (RW=01) + 4B (LEN=11) -> nibble 0b1101 = 0xD at shift 20
    EXPECT_EQ((plan.value->dr7 >> 20u) & 0xFULL, 0xDULL);
    // Slot 2: ReadWrite (RW=11) + 8B (LEN=10) -> nibble 0b1011 = 0xB at shift 24
    EXPECT_EQ((plan.value->dr7 >> 24u) & 0xFULL, 0xBULL);

    // DR6 trigger matching (bit 2 = B2 -> hardware slot 2, owned by BreakpointId 12):
    const auto triggered_slot = match_x86_dr6_triggered_slot(0x04ULL, *plan.value);
    ASSERT_EQ(triggered_slot, std::optional<std::uint8_t>{2u});
    EXPECT_EQ(plan.value->slot_owner_id[*triggered_slot], 12u);
    EXPECT_EQ(match_x86_dr6_triggered_slot(0x00ULL, *plan.value), std::nullopt);

    // 5th hardware breakpoint -> clear slot exhaustion diagnostic!
    std::vector<BreakpointDescriptor> five_bps = four_bps;
    five_bps.push_back(BreakpointDescriptor{
        .id = 14,
        .kind = BreakpointKind::HardwareExecute,
        .address = 0x401020,
        .byte_size = 1,
        .enabled = true,
    });
    const auto exhausted = build_x86_debug_register_plan(Architecture::X86_64, five_bps);
    EXPECT_FALSE(exhausted.has_value());
    EXPECT_NE(exhausted.status.detail.find("DR0..DR3"), std::string::npos);

    // Unaligned 4-byte watchpoint -> rejected cleanly!
    const std::vector<BreakpointDescriptor> unaligned{BreakpointDescriptor{
        .id = 15,
        .kind = BreakpointKind::HardwareWrite,
        .address = 0x602002,
        .byte_size = 4,
        .enabled = true,
    }};
    EXPECT_FALSE(build_x86_debug_register_plan(Architecture::X86_64, unaligned).has_value());

    // 8-byte watchpoint on 32-bit x86 -> rejected cleanly!
    EXPECT_FALSE(build_x86_debug_register_plan(Architecture::X86, std::span{&rw_8b, 1}).has_value());

    // Non-x86 host architecture -> clear unavailable SubsystemStatus!
    const auto arm_hw = build_x86_debug_register_plan(Architecture::ARM64, std::span{&exec_bp, 1});
    EXPECT_FALSE(arm_hw.has_value());
}

TEST(DebuggerCoreUnit, StepOverCallFallthroughDecoding) {
    // x86_64 direct near call: E8 10 00 00 00 (5 bytes)
    const std::array<std::uint8_t, 5> rel_call{0xE8, 0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x401000, rel_call),
              std::optional<std::uint64_t>{0x401005});

    // x86_64 indirect call via RIP-relative slot: FF 15 20 30 00 00 (6 bytes)
    const std::array<std::uint8_t, 6> rip_call{0xFF, 0x15, 0x20, 0x30, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x402000, rip_call),
              std::optional<std::uint64_t>{0x402006});

    // x86_64 REX + indirect register call: 41 FF D0 (call r8 -> 3 bytes)
    const std::array<std::uint8_t, 3> reg_call{0x41, 0xFF, 0xD0};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x403000, reg_call),
              std::optional<std::uint64_t>{0x403003});

    // Non-call instruction (mov eax, 1 -> B8 01 00 00 00) -> nullopt (fallback to step_into)
    const std::array<std::uint8_t, 5> mov_eax{0xB8, 0x01, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x404000, mov_eax),
              std::nullopt);

    // ARM64 BL #0x20 -> 0x94000008 LE (4 bytes)
    const std::array<std::uint8_t, 4> a64_bl{0x08, 0x00, 0x00, 0x94};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::ARM64, Endianness::Little, 0x500000, a64_bl),
              std::optional<std::uint64_t>{0x500004});

    // 32-bit x86 `66 E8 rel16` (operand-size override near call -> 4 bytes)
    const std::array<std::uint8_t, 6> call_66_e8{0x66, 0xE8, 0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86, Endianness::Little, 0x401000, call_66_e8),
              std::optional<std::uint64_t>{0x401004});

    // 64-bit x86_64 `66 E8 ...` and multi-prefix `2E 66 E8 ...` + `48 E8 rel32` + `66 48 E8 rel32`
    const auto x64_66_e8 = compute_step_over_fallthrough(
        Architecture::X86_64, Endianness::Little, 0x401000, call_66_e8);
    ASSERT_TRUE(x64_66_e8.has_value());
    const std::array<std::uint8_t, 7> seg_66_e8{0x2E, 0x66, 0xE8, 0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x401000, seg_66_e8),
              std::optional<std::uint64_t>{*x64_66_e8 + 1u});

    const std::array<std::uint8_t, 6> rex_w_call{0x48, 0xE8, 0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x401000, rex_w_call),
              std::optional<std::uint64_t>{0x401006});

    const std::array<std::uint8_t, 7> p66_rex_w_call{0x66, 0x48, 0xE8, 0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(compute_step_over_fallthrough(Architecture::X86_64, Endianness::Little, 0x401000, p66_rex_w_call),
              std::optional<std::uint64_t>{0x401007});

    // Overflow guard near UINT64_MAX: must return nullopt rather than wrapping past 0
    EXPECT_EQ(compute_step_over_fallthrough(
                  Architecture::X86_64,
                  Endianness::Little,
                  std::numeric_limits<std::uint64_t>::max() - 2u,
                  rel_call),
              std::nullopt);
}

#if defined(__linux__) && defined(__x86_64__)

extern "C" void peelf_dbg_test_callee();
extern "C" std::uint64_t peelf_dbg_test_sequence();
extern "C" const std::uint8_t peelf_dbg_bp_entry[];
extern "C" const std::uint8_t peelf_dbg_call_site[];
extern "C" const std::uint8_t peelf_dbg_after_call[];

// Exact, compiler-optimization-proof x86_64 instruction layout for deterministic
// software breakpoint, RIP rewind, step_into, step_over across CALL, and clean detach tests!
asm(
    ".text\n"
    ".globl peelf_dbg_test_callee\n"
    ".type peelf_dbg_test_callee, @function\n"
    "peelf_dbg_test_callee:\n"
    "    mov $0x12345678, %eax\n"
    "    ret\n"
    ".size peelf_dbg_test_callee, .-peelf_dbg_test_callee\n"
    "\n"
    ".globl peelf_dbg_test_sequence\n"
    ".globl peelf_dbg_bp_entry\n"
    ".globl peelf_dbg_call_site\n"
    ".globl peelf_dbg_after_call\n"
    ".type peelf_dbg_test_sequence, @function\n"
    "peelf_dbg_test_sequence:\n"
    "peelf_dbg_bp_entry:\n"
    "    nop\n"
    "peelf_dbg_call_site:\n"
    "    call peelf_dbg_test_callee\n"
    "peelf_dbg_after_call:\n"
    "    add $0x2, %rax\n"
    "    ret\n"
    ".size peelf_dbg_test_sequence, .-peelf_dbg_test_sequence\n"
);

struct DebugChildAnchors {
    std::uint64_t bp_entry_va{0};
    std::uint64_t call_site_va{0};
    std::uint64_t after_call_va{0};
};

struct ScopedFd {
    int fd{-1};

    ScopedFd() noexcept = default;
    explicit ScopedFd(int f) noexcept : fd(f) {}
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : fd(other.fd) { other.fd = -1; }
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }
    ~ScopedFd() noexcept { reset(); }

    void reset(int new_fd = -1) noexcept {
        if (fd >= 0) {
            ::close(fd);
        }
        fd = new_fd;
    }

    [[nodiscard]] int release() noexcept {
        const int out = fd;
        fd = -1;
        return out;
    }
};

struct ScopedDebugChildGuard {
    pid_t pid{-1};
    int go_write_fd{-1};

    ScopedDebugChildGuard(pid_t p, int fd) noexcept : pid(p), go_write_fd(fd) {}
    ScopedDebugChildGuard(const ScopedDebugChildGuard&) = delete;
    ScopedDebugChildGuard& operator=(const ScopedDebugChildGuard&) = delete;
    ScopedDebugChildGuard(ScopedDebugChildGuard&&) = delete;
    ScopedDebugChildGuard& operator=(ScopedDebugChildGuard&&) = delete;

    ~ScopedDebugChildGuard() noexcept {
        if (go_write_fd >= 0) {
            ::close(go_write_fd);
            go_write_fd = -1;
        }
        if (pid > 0) {
            int st = 0;
            const pid_t polled = ::waitpid(pid, &st, WNOHANG);
            if (polled == 0 || (polled < 0 && errno == EINTR)) {
                (void)::kill(pid, SIGKILL);
                (void)::kill(pid, SIGCONT);
                while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {
                }
            }
            pid = -1;
        }
    }
};

TEST(DebuggerLinuxLiveTest, DefaultProcessAttachRemainsStrictlyReadOnly) {
    const pid_t sleep_child = ::fork();
    ASSERT_GE(sleep_child, 0);
    if (sleep_child == 0) {
        char arg0[] = "/bin/sleep";
        char arg1[] = "5";
        char* const argv[] = {arg0, arg1, nullptr};
        ::execv("/bin/sleep", argv);
        ::_exit(127);
    }
    ScopedDebugChildGuard guard{sleep_child, -1};
    // Wait briefly for execv("/bin/sleep") to settle so BinaryModel hydrates tiny /bin/sleep (~35 KB)
    std::this_thread::sleep_for(std::chrono::milliseconds(25));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_process(static_cast<ProcessId>(sleep_child)).has_value());
    EXPECT_TRUE(model.is_live_process());
    EXPECT_TRUE(model.is_read_only());
    EXPECT_FALSE(model.is_debug_session());
    EXPECT_EQ(model.debug_session(), nullptr);
}

TEST(DebuggerLinuxLiveTest, BreakpointHitRipRewindShadowReadStepIntoStepOverWriteRegAndCleanDetach) {
    int raw_ready_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(raw_ready_pipe), 0);
    ScopedFd ready_r(raw_ready_pipe[0]);
    ScopedFd ready_w(raw_ready_pipe[1]);

    int raw_go_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(raw_go_pipe), 0);
    ScopedFd go_r(raw_go_pipe[0]);
    ScopedFd go_w(raw_go_pipe[1]);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);

    if (child == 0) {
        ready_r.reset();
        go_w.reset();
        // Allow our parent process to PTRACE_ATTACH even when Yama ptrace_scope == 1.
#ifdef PR_SET_PTRACER
        (void)::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
        DebugChildAnchors anchors{
            .bp_entry_va = reinterpret_cast<std::uint64_t>(peelf_dbg_bp_entry),
            .call_site_va = reinterpret_cast<std::uint64_t>(peelf_dbg_call_site),
            .after_call_va = reinterpret_cast<std::uint64_t>(peelf_dbg_after_call),
        };
        (void)::write(ready_w.fd, &anchors, sizeof(anchors));
        ready_w.reset();

        char go = 0;
        if (::read(go_r.fd, &go, 1) != 1) {
            ::_exit(2);
        }
        go_r.reset();

        // First call hits our software breakpoint, steps through, and receives modified RAX!
        const std::uint64_t first = peelf_dbg_test_sequence();
        // Second call runs AFTER detach(): proves 0xCC was disarmed and restored to 0x90 NOP!
        const std::uint64_t second = peelf_dbg_test_sequence();
        if (first == 0x77770002ULL && second == 0x1234567AULL) {
            ::_exit(0);
        }
        ::_exit(3);
    }

    ready_w.reset();
    go_r.reset();
    ScopedDebugChildGuard guard{child, go_w.release()};

    DebugChildAnchors anchors{};
    ASSERT_EQ(::read(ready_r.fd, &anchors, sizeof(anchors)), static_cast<ssize_t>(sizeof(anchors)));
    ready_r.reset();

    ASSERT_EQ(anchors.call_site_va, anchors.bp_entry_va + 1u);
    ASSERT_EQ(anchors.after_call_va, anchors.call_site_va + 5u);

    auto backend = create_native_debug_backend();
    auto attached = backend->attach(static_cast<ProcessId>(child));
    ASSERT_TRUE(attached.has_value()) << attached.error().message;
    IDebugSession* dbg = attached->get();
    ASSERT_NE(dbg, nullptr);
    EXPECT_EQ(dbg->state(), DebugSessionState::Paused);

    // 1. Set software breakpoint at peelf_dbg_bp_entry (which is a 0x90 NOP).
    auto bp_res = dbg->add_software_breakpoint(anchors.bp_entry_va, "peelf_dbg_bp_entry");
    ASSERT_TRUE(bp_res.has_value()) << bp_res.error().message;
    ASSERT_EQ(bp_res->original_bytes.size(), 1u);
    EXPECT_EQ(bp_res->original_bytes[0], 0x90u);

    // 2. Shadow-filtered read_memory MUST return clean 0x90 NOP, never 0xCC!
    std::array<std::uint8_t, 6> shadow_buf{};
    auto rd = dbg->session().read_memory(anchors.bp_entry_va, shadow_buf);
    ASSERT_TRUE(rd.has_value()) << rd.error().message;
    EXPECT_EQ(shadow_buf[0], 0x90u);
    EXPECT_EQ(shadow_buf[1], 0xE8u);  // CALL rel32 opcode

    // 3. Unblock child from pipe read and resume execution until it hits the software breakpoint!
    const char go_byte = 'G';
    ASSERT_EQ(::write(guard.go_write_fd, &go_byte, 1), 1);
    ::close(guard.go_write_fd);
    guard.go_write_fd = -1;

    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto hit_stop = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(hit_stop.has_value()) << hit_stop.error().message;
    EXPECT_EQ(hit_stop->state, DebugSessionState::Paused);
    // Verify RIP was rewound by 1 byte from (bp_entry + 1) back to bp_entry!
    EXPECT_EQ(hit_stop->instruction_pointer, anchors.bp_entry_va);
    ASSERT_TRUE(hit_stop->last_event.has_value());
    EXPECT_EQ(hit_stop->last_event->kind, DebugEventKind::BreakpointHit);
    EXPECT_EQ(dbg->breakpoints().front().hit_count, 1u);

    // Shadow read while paused at armed breakpoint still shows 0x90!
    ASSERT_TRUE(dbg->session().read_memory(anchors.bp_entry_va, shadow_buf).has_value());
    EXPECT_EQ(shadow_buf[0], 0x90u);

    // 4. step_into() across the 1-byte NOP (disarms 0xCC, single-steps, re-arms 0xCC, lands on CALL)!
    ASSERT_TRUE(dbg->step_into().has_value());
    auto step1 = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(step1.has_value()) << step1.error().message;
    EXPECT_EQ(step1->state, DebugSessionState::Paused);
    EXPECT_EQ(step1->instruction_pointer, anchors.call_site_va);

    // 5. step_over() across the 5-byte CALL instruction -> lands directly on after_call_va
    //    with RAX == 0x12345678 (returned by peelf_dbg_test_callee)!
    ASSERT_TRUE(dbg->step_over().has_value());
    auto step2 = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(step2.has_value()) << step2.error().message;
    EXPECT_EQ(step2->state, DebugSessionState::Paused);
    EXPECT_EQ(step2->instruction_pointer, anchors.after_call_va);
    const ThreadContext after_call_ctx = dbg->session().thread_context(step2->active_tid);
    bool verified_callee_rax = false;
    for (const RegisterValue& rv : after_call_ctx.registers) {
        if (rv.name == "rax") {
            EXPECT_EQ(rv.value_u64, 0x12345678ULL);
            verified_callee_rax = true;
        }
    }
    EXPECT_TRUE(verified_callee_rax);

    // 6. Test opt-in write_register: set RAX = 0x77770000 so `add $2, %rax` yields 0x77770002!
    ASSERT_TRUE(dbg->write_register(step2->active_tid, "rax", 0x77770000ULL).has_value());
    const ThreadContext updated_ctx = dbg->session().thread_context(step2->active_tid);
    bool found_rax = false;
    for (const RegisterValue& rv : updated_ctx.registers) {
        if (rv.name == "rax") {
            EXPECT_EQ(rv.value_u64, 0x77770000ULL);
            found_rax = true;
        }
    }
    EXPECT_TRUE(found_rax);

    // 7. Clean detach(): disarms 0xCC at peelf_dbg_bp_entry and detaches so the child executes
    //    both the remainder of call #1 AND a full second call to peelf_dbg_test_sequence() cleanly
    //    and exits with code 0!
    ASSERT_TRUE(dbg->detach().has_value());
    EXPECT_EQ(dbg->state(), DebugSessionState::Detached);

    int wstatus = 0;
    ASSERT_EQ(::waitpid(child, &wstatus, 0), child);
    guard.pid = -1;
    ASSERT_TRUE(WIFEXITED(wstatus)) << "Child killed by signal " << WTERMSIG(wstatus);
    EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

TEST(DebuggerLinuxLiveTest, LaunchExecutableStopsAtInitialTrapStepsAndDetachesCleanly) {
    const std::filesystem::path fixture_exe(PEELF_CALLGRAPH_FIXTURE_EXE);
    ASSERT_TRUE(std::filesystem::exists(fixture_exe));

    ScopedDebugChildGuard child_guard{-1, -1};
    viewer::BinaryModel model;
    auto launched = model.launch_debug_process(fixture_exe);
    ASSERT_TRUE(launched.has_value()) << launched.error().message;
    ASSERT_TRUE(model.is_debug_session());
    IDebugSession* dbg_ptr = model.debug_session();
    ASSERT_NE(dbg_ptr, nullptr);
    IDebugSession& dbg = *dbg_ptr;

    EXPECT_EQ(dbg.state(), DebugSessionState::Paused);
    const ProcessId child_pid = dbg.session().pid();
    ASSERT_GT(child_pid, 0u);
    child_guard.pid = static_cast<pid_t>(child_pid);
    EXPECT_NE(dbg.stop_status().instruction_pointer, 0u);
    ASSERT_TRUE(dbg.stop_status().last_event.has_value());
    EXPECT_EQ(dbg.stop_status().last_event->kind, DebugEventKind::ProcessStarted);

    auto regions = dbg.session().memory_regions();
    ASSERT_TRUE(regions.has_value());
    EXPECT_FALSE(regions->empty());

    const std::uint64_t initial_ip = dbg.stop_status().instruction_pointer;
    // Toggle software breakpoint on & off via BinaryModel helper:
    ASSERT_TRUE(model.toggle_software_breakpoint(initial_ip, "entry_trap").has_value());
    EXPECT_NE(model.find_breakpoint_at(initial_ip), nullptr);
    ASSERT_TRUE(model.toggle_software_breakpoint(initial_ip, "entry_trap").has_value());
    EXPECT_EQ(model.find_breakpoint_at(initial_ip), nullptr);

    ASSERT_TRUE(dbg.step_into().has_value());
    auto after_step = dbg.wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(after_step.has_value());
    EXPECT_NE(after_step->instruction_pointer, initial_ip);
    EXPECT_TRUE(model.sync_debugger_stop_state());
    EXPECT_TRUE(model.has_debug_register_changed("rip", after_step->instruction_pointer));
    EXPECT_EQ(model.previous_debug_register_value("rip"), std::optional<std::uint64_t>{initial_ip});

    ASSERT_TRUE(dbg.detach().has_value());
    model.detach_process();
    int wstatus = 0;
    ASSERT_EQ(::waitpid(static_cast<pid_t>(child_pid), &wstatus, 0), static_cast<pid_t>(child_pid));
    child_guard.pid = -1;
    EXPECT_TRUE(WIFEXITED(wstatus));
}

extern "C" void peelf_dbg_fault_sequence();
extern "C" const std::uint8_t peelf_dbg_fault_insn[];

asm(
    ".text\n"
    ".globl peelf_dbg_fault_sequence\n"
    ".globl peelf_dbg_fault_insn\n"
    ".type peelf_dbg_fault_sequence, @function\n"
    "peelf_dbg_fault_sequence:\n"
    "    xor %eax, %eax\n"
    "peelf_dbg_fault_insn:\n"
    "    mov (%rax), %ecx\n"
    "    ret\n"
    ".size peelf_dbg_fault_sequence, .-peelf_dbg_fault_sequence\n"
);

TEST(DebuggerLinuxLiveTest, StepOffBreakpointOnFaultingInstructionReportsSigsegvWithoutReapingSiblingChild) {
    // Spawn an unrelated exited child process BEFORE running the debugger event loop;
    // LinuxDebugSession must NEVER steal its exit status via waitpid(-1, ...).
    const pid_t unrelated_child = ::fork();
    ASSERT_GE(unrelated_child, 0);
    if (unrelated_child == 0) {
        ::_exit(42);
    }
    ScopedDebugChildGuard unrelated_guard{unrelated_child, -1};

    int raw_ready_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(raw_ready_pipe), 0);
    ScopedFd ready_r(raw_ready_pipe[0]);
    ScopedFd ready_w(raw_ready_pipe[1]);

    int raw_go_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(raw_go_pipe), 0);
    ScopedFd go_r(raw_go_pipe[0]);
    ScopedFd go_w(raw_go_pipe[1]);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ready_r.reset();
        go_w.reset();
#ifdef PR_SET_PTRACER
        (void)::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
        const auto fault_va = reinterpret_cast<std::uint64_t>(peelf_dbg_fault_insn);
        (void)::write(ready_w.fd, &fault_va, sizeof(fault_va));
        ready_w.reset();

        char go = 0;
        if (::read(go_r.fd, &go, 1) != 1) {
            ::_exit(2);
        }
        go_r.reset();
        peelf_dbg_fault_sequence();
        ::_exit(0);
    }

    ready_w.reset();
    go_r.reset();
    ScopedDebugChildGuard guard{child, go_w.release()};

    std::uint64_t fault_va = 0u;
    ASSERT_EQ(::read(ready_r.fd, &fault_va, sizeof(fault_va)), static_cast<ssize_t>(sizeof(fault_va)));
    ready_r.reset();

    auto backend = create_native_debug_backend();
    auto attached = backend->attach(static_cast<ProcessId>(child));
    ASSERT_TRUE(attached.has_value()) << attached.error().message;
    IDebugSession* dbg = attached->get();
    ASSERT_NE(dbg, nullptr);

    auto bp_res = dbg->add_software_breakpoint(fault_va, "fault_mov");
    ASSERT_TRUE(bp_res.has_value()) << bp_res.error().message;
    ASSERT_EQ(bp_res->original_bytes.size(), 1u);
    EXPECT_EQ(bp_res->original_bytes[0], 0x8Bu);

    const char go_byte = 'G';
    ASSERT_EQ(::write(guard.go_write_fd, &go_byte, 1), 1);
    ::close(guard.go_write_fd);
    guard.go_write_fd = -1;

    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto bp_stop = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(bp_stop.has_value()) << bp_stop.error().message;
    ASSERT_TRUE(bp_stop->last_event.has_value());
    EXPECT_EQ(bp_stop->last_event->kind, DebugEventKind::BreakpointHit);
    EXPECT_EQ(bp_stop->instruction_pointer, fault_va);

    // Stepping off the software breakpoint executes `mov (%rax), %ecx` with RAX=0,
    // which faults with SIGSEGV: debugger must re-arm the breakpoint and report SIGSEGV!
    ASSERT_TRUE(dbg->step_into().has_value());
    auto fault_stop = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(fault_stop.has_value()) << fault_stop.error().message;
    EXPECT_EQ(fault_stop->state, DebugSessionState::Paused);
    EXPECT_EQ(fault_stop->instruction_pointer, fault_va);
    ASSERT_TRUE(fault_stop->last_event.has_value());
    EXPECT_EQ(fault_stop->last_event->kind, DebugEventKind::ExceptionOrSignal);
    EXPECT_EQ(fault_stop->last_event->signal_or_exception_code, std::optional<std::int64_t>{SIGSEGV});
    ASSERT_FALSE(dbg->breakpoints().empty());
    EXPECT_TRUE(dbg->breakpoints().front().armed_in_target);

    // Continuing again (suppressing prior signal) steps off the re-armed breakpoint and
    // must report SIGSEGV again rather than swallowing the fault!
    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto fault_stop2 = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(fault_stop2.has_value()) << fault_stop2.error().message;
    ASSERT_TRUE(fault_stop2->last_event.has_value());
    EXPECT_EQ(fault_stop2->last_event->kind, DebugEventKind::ExceptionOrSignal);
    EXPECT_EQ(fault_stop2->last_event->signal_or_exception_code, std::optional<std::int64_t>{SIGSEGV});

    ASSERT_TRUE(dbg->terminate().has_value());
    int child_st = 0;
    (void)::waitpid(child, &child_st, 0);
    guard.pid = -1;

    // Verify the unrelated sibling child was NOT reaped by LinuxDebugSession!
    int unrelated_st = 0;
    ASSERT_EQ(::waitpid(unrelated_child, &unrelated_st, 0), unrelated_child);
    unrelated_guard.pid = -1;
    ASSERT_TRUE(WIFEXITED(unrelated_st));
    EXPECT_EQ(WEXITSTATUS(unrelated_st), 42);
}

#endif  // defined(__linux__) && defined(__x86_64__)

}  // namespace
