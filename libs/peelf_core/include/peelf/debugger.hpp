#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf::debugger {

using BreakpointId = std::uint64_t;

enum class DebugSessionState : std::uint8_t {
    Idle = 0,
    Running,
    Paused,
    Exited,
    Detached,
    Error,
};

[[nodiscard]] constexpr std::string_view to_string(DebugSessionState state) noexcept {
    switch (state) {
        case DebugSessionState::Idle:     return "Idle";
        case DebugSessionState::Running:  return "Running";
        case DebugSessionState::Paused:   return "Paused";
        case DebugSessionState::Exited:   return "Exited";
        case DebugSessionState::Detached: return "Detached";
        case DebugSessionState::Error:    return "Error";
    }
    return "Idle";
}

enum class BreakpointKind : std::uint8_t {
    Software = 0,
    HardwareExecute,
    HardwareWrite,
    HardwareReadWrite,
};

[[nodiscard]] constexpr std::string_view to_string(BreakpointKind kind) noexcept {
    switch (kind) {
        case BreakpointKind::Software:          return "Software";
        case BreakpointKind::HardwareExecute:   return "HardwareExecute";
        case BreakpointKind::HardwareWrite:     return "HardwareWrite";
        case BreakpointKind::HardwareReadWrite: return "HardwareReadWrite";
    }
    return "Software";
}

[[nodiscard]] constexpr bool is_hardware_breakpoint(BreakpointKind kind) noexcept {
    return kind != BreakpointKind::Software;
}

struct SoftwareTrapSpec {
    std::array<std::uint8_t, 4> bytes{};
    std::uint8_t size{0};
    bool rewinds_pc_on_hit{false};  ///< True on x86/x86_64 (`INT3` `0xCC` stops at `addr + 1`)
    std::string_view mnemonic{};

    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
        return std::span<const std::uint8_t>(bytes.data(), size);
    }
};

/// Selects the architecture- and endianness-appropriate software breakpoint trap encoding
/// (`0xCC` on x86/x86_64, `BRK #0` on ARM64, `BKPT` on ARM/Thumb, `EBREAK` on RISC-V,
/// `trap` on PowerPC, `break` on MIPS).
[[nodiscard]] Result<SoftwareTrapSpec> select_software_trap(
    Architecture arch,
    Endianness endian = Endianness::Little,
    bool thumb_mode = false) noexcept;

struct BreakpointDescriptor {
    BreakpointId id{0};
    BreakpointKind kind{BreakpointKind::Software};
    std::uint64_t address{0};
    std::uint8_t byte_size{1};  ///< Software trap length, or 1/2/4/8 for hardware watchpoints
    bool enabled{true};
    bool armed_in_target{false};
    std::optional<std::uint8_t> hardware_slot{};  ///< 0..3 (`DR0..DR3`) when `is_hardware_breakpoint(kind)`
    std::uint64_t hit_count{0};
    std::string label{};  ///< Optional symbol or user expression label
    std::vector<std::uint8_t> original_bytes{};
    SubsystemStatus status{};
};

/// Masks any armed software-breakpoint trap bytes overlapping `[read_address, read_address + buffer.size())`
/// back to their saved `original_bytes`, ensuring Hex View, Disassembly, Decompile, Binary Diff,
/// and SHA-256 always observe clean original code bytes rather than injected `0xCC`/`BRK` opcodes.
void apply_software_breakpoint_shadow_filter(
    std::uint64_t read_address,
    std::span<std::uint8_t> buffer,
    std::span<const BreakpointDescriptor> breakpoints) noexcept;

/// Decodes the instruction at `instruction_pointer` (`insn_bytes`) and returns the fallthrough
/// return address if and only if the instruction is a subroutine `CALL` / `BL` / `BLR` / `JAL(ra)`.
/// Returns `std::nullopt` for non-call instructions so `step_over` falls back to `step_into`.
[[nodiscard]] std::optional<std::uint64_t> compute_step_over_fallthrough(
    Architecture arch,
    Endianness endian,
    std::uint64_t instruction_pointer,
    std::span<const std::uint8_t> insn_bytes,
    bool thumb_mode = false) noexcept;

/// Hardware debug register layout (`DR0..DR3` + `DR7`) for x86 / x86_64 targets.
struct X86DebugRegisterPlan {
    std::array<std::uint64_t, 4> dr_address{0, 0, 0, 0};
    std::array<bool, 4> slot_used{false, false, false, false};
    std::array<BreakpointId, 4> slot_owner_id{0, 0, 0, 0};
    std::uint64_t dr7{0};
    SubsystemStatus status{};
};

/// Validates and encodes up to 4 active hardware breakpoints/watchpoints into x86/x86_64
/// `DR0..DR3` and `DR7` control bits (`L0..L3`, `R/W0..3`, `LEN0..3`).
/// Returns `Unavailable` / `Partial` diagnostics when >4 slots are requested, sizes are invalid,
/// or addresses are unaligned for their watchpoint width.
[[nodiscard]] ForgivingValue<X86DebugRegisterPlan> build_x86_debug_register_plan(
    Architecture arch,
    std::span<const BreakpointDescriptor> breakpoints);

/// Identifies which hardware slot (`0..3`) fired from an x86/x86_64 `DR6` status word.
[[nodiscard]] std::optional<std::uint8_t> match_x86_dr6_triggered_slot(
    std::uint64_t dr6,
    const X86DebugRegisterPlan& plan) noexcept;

enum class DebugEventKind : std::uint8_t {
    ProcessStarted = 0,
    BreakpointHit,
    SingleStepCompleted,
    ExceptionOrSignal,
    ThreadCreated,
    ThreadExited,
    ModuleLoaded,
    ModuleUnloaded,
    DebugOutput,
    ProcessExited,
};

[[nodiscard]] constexpr std::string_view to_string(DebugEventKind kind) noexcept {
    switch (kind) {
        case DebugEventKind::ProcessStarted:      return "ProcessStarted";
        case DebugEventKind::BreakpointHit:       return "BreakpointHit";
        case DebugEventKind::SingleStepCompleted: return "SingleStepCompleted";
        case DebugEventKind::ExceptionOrSignal:   return "ExceptionOrSignal";
        case DebugEventKind::ThreadCreated:       return "ThreadCreated";
        case DebugEventKind::ThreadExited:        return "ThreadExited";
        case DebugEventKind::ModuleLoaded:        return "ModuleLoaded";
        case DebugEventKind::ModuleUnloaded:      return "ModuleUnloaded";
        case DebugEventKind::DebugOutput:         return "DebugOutput";
        case DebugEventKind::ProcessExited:       return "ProcessExited";
    }
    return "ProcessStarted";
}

struct DebugEvent {
    std::uint64_t sequence{0};
    DebugEventKind kind{DebugEventKind::ProcessStarted};
    ProcessId pid{0};
    ThreadId tid{0};
    std::optional<std::uint64_t> address{};
    std::optional<BreakpointId> breakpoint_id{};
    std::optional<std::int64_t> signal_or_exception_code{};
    std::optional<std::int32_t> exit_code{};
    std::string summary{};
};

struct DebugStopStatus {
    DebugSessionState state{DebugSessionState::Idle};
    ThreadId active_tid{0};
    std::uint64_t instruction_pointer{0};
    std::optional<DebugEvent> last_event{};
    std::uint64_t stop_revision{0};  ///< Increments each time target transitions into `Paused`/`Exited`/`Detached`
};

struct DebugLaunchOptions {
    std::filesystem::path executable{};
    std::vector<std::string> args{};
    std::filesystem::path working_dir{};
};

/// Opt-in interactive debugger session (`BSD-2-Clause` clean; completely separate from
/// default read-only `IProcessSession` attach).
///
/// Ownership & safety guarantees:
/// - Exposes `session()` (`IProcessSession&`) whose `read_memory(...)` shadow-filters all
///   armed software breakpoints so every inspection panel sees clean original bytes.
/// - `detach()` and `~IDebugSession()` disarm all armed software/hardware breakpoints and
///   restore original target bytes before detaching from the debuggee.
class IDebugSession {
public:
    virtual ~IDebugSession() = default;

    /// Returns the shadow-filtered `IProcessSession` view of the debuggee so all existing
    /// inspection panels (`Disassembly`, `Hex View`, `Memory Map`, `Threads & Stack`,
    /// `Thread Locals`, `Structure View`, `Decompile`) work seamlessly while paused.
    [[nodiscard]] virtual IProcessSession& session() noexcept = 0;
    [[nodiscard]] virtual const IProcessSession& session() const noexcept = 0;

    [[nodiscard]] virtual DebugSessionState state() const noexcept = 0;
    [[nodiscard]] virtual DebugStopStatus stop_status() const = 0;

    // --- Execution Control ---
    [[nodiscard]] virtual Result<void> continue_execution(bool pass_signal_or_exception = false) = 0;
    [[nodiscard]] virtual Result<void> pause_execution() = 0;
    [[nodiscard]] virtual Result<void> step_into(std::optional<ThreadId> tid = std::nullopt) = 0;
    [[nodiscard]] virtual Result<void> step_over(std::optional<ThreadId> tid = std::nullopt) = 0;
    [[nodiscard]] virtual Result<void> step_out(std::optional<ThreadId> tid = std::nullopt) = 0;

    /// Waits until the session leaves `DebugSessionState::Running` (e.g. hits a breakpoint,
    /// finishes a step, receives a signal/exception, exits, or detaches) or `timeout` elapses.
    [[nodiscard]] virtual Result<DebugStopStatus> wait_for_stop(
        std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) = 0;

    /// Disarms and restores all software/hardware breakpoints and detaches cleanly so the
    /// target process resumes normal execution.
    [[nodiscard]] virtual Result<void> detach() = 0;

    /// Terminates the debuggee process.
    [[nodiscard]] virtual Result<void> terminate() = 0;

    // --- Breakpoints & Watchpoints ---
    [[nodiscard]] virtual Result<BreakpointDescriptor> add_software_breakpoint(
        std::uint64_t address,
        std::string label = {},
        bool thumb_mode = false) = 0;

    [[nodiscard]] virtual ForgivingValue<BreakpointDescriptor> add_hardware_breakpoint(
        std::uint64_t address,
        BreakpointKind kind = BreakpointKind::HardwareExecute,
        std::uint8_t byte_size = 1,
        std::string label = {}) = 0;

    [[nodiscard]] virtual Result<void> remove_breakpoint(BreakpointId id) = 0;
    [[nodiscard]] virtual Result<void> set_breakpoint_enabled(BreakpointId id, bool enabled) = 0;
    [[nodiscard]] virtual std::vector<BreakpointDescriptor> breakpoints() const = 0;

    // --- Opt-in Register Modification & Event History ---
    /// Modifies a general-purpose, pointer, or flags register on a paused thread.
    /// Available ONLY on opt-in `IDebugSession` (never on read-only `IProcessSession`).
    [[nodiscard]] virtual Result<void> write_register(
        ThreadId tid,
        std::string_view reg_name,
        std::uint64_t value_u64) = 0;

    [[nodiscard]] virtual std::vector<DebugEvent> events() const = 0;
    virtual void clear_events() = 0;
};

class IDebugBackend {
public:
    virtual ~IDebugBackend() = default;

    [[nodiscard]] virtual Result<std::unique_ptr<IDebugSession>> launch(
        const std::filesystem::path& executable,
        std::span<const std::string> args = {},
        const std::filesystem::path& working_dir = {}) = 0;

    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> launch(const DebugLaunchOptions& opts) {
        return launch(opts.executable, opts.args, opts.working_dir);
    }

    [[nodiscard]] virtual Result<std::unique_ptr<IDebugSession>> attach(ProcessId pid) = 0;
};

/// Creates the host platform's native opt-in debugger backend (`ptrace` tracer thread on Linux,
/// Win32 debug-event loop thread on Windows).
[[nodiscard]] std::shared_ptr<IDebugBackend> create_native_debug_backend();

}  // namespace peelf::debugger
