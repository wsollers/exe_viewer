#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <peelf/debugger.hpp>

#ifdef __linux__

#include <peelf/stack_tls.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <filesystem>
#include <format>
#include <future>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace peelf::debugger {
namespace {

constexpr std::size_t kMaxEventHistory = 512u;

[[nodiscard]] Architecture host_debug_arch() noexcept {
#if defined(__x86_64__)
    return Architecture::X86_64;
#elif defined(__i386__)
    return Architecture::X86;
#elif defined(__aarch64__)
    return Architecture::ARM64;
#elif defined(__arm__)
    return Architecture::ARM;
#elif defined(__riscv) && (__riscv_xlen == 64)
    return Architecture::RISCV64;
#elif defined(__riscv) && (__riscv_xlen == 32)
    return Architecture::RISCV32;
#else
    return Architecture::Unknown;
#endif
}

[[nodiscard]] constexpr Endianness host_debug_endian() noexcept {
    return std::endian::native == std::endian::big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] std::string lower_ascii_str(std::string_view sv) {
    std::string out(sv.size(), '\0');
    for (std::size_t i = 0; i < sv.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(sv[i])));
    }
    return out;
}

[[nodiscard]] std::string_view signal_short_name(int sig) noexcept {
    switch (sig) {
        case SIGHUP:  return "SIGHUP";
        case SIGINT:  return "SIGINT";
        case SIGQUIT: return "SIGQUIT";
        case SIGILL:  return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGFPE:  return "SIGFPE";
        case SIGKILL: return "SIGKILL";
        case SIGSEGV: return "SIGSEGV";
        case SIGPIPE: return "SIGPIPE";
        case SIGALRM: return "SIGALRM";
        case SIGTERM: return "SIGTERM";
        case SIGSTOP: return "SIGSTOP";
        case SIGCONT: return "SIGCONT";
        default:      return "SIGNAL";
    }
}

[[nodiscard]] Result<void> ptrace_read_bytes(ThreadId tid,
                                             std::uint64_t address,
                                             std::span<std::uint8_t> out) {
    if (out.empty()) {
        return {};
    }
    constexpr std::size_t kWord = sizeof(long);
    std::size_t offset = 0u;
    while (offset < out.size()) {
        const std::uint64_t cur = address + offset;
        const std::uint64_t aligned = cur & ~static_cast<std::uint64_t>(kWord - 1u);
        const auto lane = static_cast<std::size_t>(cur - aligned);
        const std::size_t chunk = std::min<std::size_t>(kWord - lane, out.size() - offset);

        errno = 0;
        const long word = ::ptrace(PTRACE_PEEKDATA,
                                   static_cast<pid_t>(tid),
                                   reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)),
                                   nullptr);
        if (word == -1L && errno != 0) {
            return make_error(std::format("PTRACE_PEEKDATA failed at 0x{:X}: {}",
                                          aligned,
                                          std::strerror(errno)));
        }
        std::array<std::uint8_t, kWord> raw{};
        std::memcpy(raw.data(), &word, kWord);
        std::copy_n(raw.data() + lane, chunk, out.data() + offset);
        offset += chunk;
    }
    return {};
}

[[nodiscard]] Result<void> ptrace_write_bytes(ThreadId tid,
                                              std::uint64_t address,
                                              std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return {};
    }
    constexpr std::size_t kWord = sizeof(long);
    std::size_t offset = 0u;
    while (offset < data.size()) {
        const std::uint64_t cur = address + offset;
        const std::uint64_t aligned = cur & ~static_cast<std::uint64_t>(kWord - 1u);
        const auto lane = static_cast<std::size_t>(cur - aligned);
        const std::size_t chunk = std::min<std::size_t>(kWord - lane, data.size() - offset);

        std::array<std::uint8_t, kWord> raw{};
        if (chunk < kWord) {
            errno = 0;
            const long orig = ::ptrace(PTRACE_PEEKDATA,
                                       static_cast<pid_t>(tid),
                                       reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)),
                                       nullptr);
            if (orig == -1L && errno != 0) {
                return make_error(std::format("PTRACE_PEEKDATA before poke failed at 0x{:X}: {}",
                                              aligned,
                                              std::strerror(errno)));
            }
            std::memcpy(raw.data(), &orig, kWord);
        }
        std::copy_n(data.data() + offset, chunk, raw.data() + lane);

        long modified = 0L;
        std::memcpy(&modified, raw.data(), kWord);
        if (::ptrace(PTRACE_POKEDATA,
                     static_cast<pid_t>(tid),
                     reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)),
                     reinterpret_cast<void*>(modified)) == -1L) {
            return make_error(std::format("PTRACE_POKEDATA failed at 0x{:X}: {}",
                                          aligned,
                                          std::strerror(errno)));
        }
        offset += chunk;
    }
    return {};
}

[[nodiscard]] Result<ThreadContext> read_ptrace_thread_context(ThreadId tid) {
    std::array<std::uint8_t, 512> raw_regs{};
    iovec iov{};
    iov.iov_base = raw_regs.data();
    iov.iov_len = raw_regs.size();
    if (::ptrace(PTRACE_GETREGSET, static_cast<pid_t>(tid), reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1L) {
        return make_error(std::format("PTRACE_GETREGSET failed for TID {}: {}", tid, std::strerror(errno)));
    }
    const TargetLayout host_layout{
        .architecture = host_debug_arch(),
        .address_width = sizeof(void*) == 8u ? AddressWidth::Bits64 : AddressWidth::Bits32,
        .endianness = host_debug_endian(),
    };
    ThreadContext ctx = decode_linux_prstatus_regset(
        tid,
        host_layout,
        std::span<const std::uint8_t>(raw_regs.data(), iov.iov_len));
    if (ctx.status.availability == Availability::Unavailable) {
        return make_error(ctx.status.detail);
    }
    return ctx;
}

#if defined(__x86_64__)
[[nodiscard]] Result<void> write_ptrace_register_by_name(ThreadId tid,
                                                         std::string_view reg_name,
                                                         std::uint64_t val) {
    user_regs_struct regs{};
    iovec iov{};
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (::ptrace(PTRACE_GETREGSET, static_cast<pid_t>(tid), reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1L) {
        return make_error(std::format("PTRACE_GETREGSET failed for TID {}: {}", tid, std::strerror(errno)));
    }

    const std::string key = lower_ascii_str(reg_name);
    if (key == "rax" || key == "eax")       regs.rax = val;
    else if (key == "rbx" || key == "ebx")  regs.rbx = val;
    else if (key == "rcx" || key == "ecx")  regs.rcx = val;
    else if (key == "rdx" || key == "edx")  regs.rdx = val;
    else if (key == "rsi" || key == "esi")  regs.rsi = val;
    else if (key == "rdi" || key == "edi")  regs.rdi = val;
    else if (key == "rbp" || key == "ebp")  regs.rbp = val;
    else if (key == "rsp" || key == "esp")  regs.rsp = val;
    else if (key == "r8")                   regs.r8 = val;
    else if (key == "r9")                   regs.r9 = val;
    else if (key == "r10")                  regs.r10 = val;
    else if (key == "r11")                  regs.r11 = val;
    else if (key == "r12")                  regs.r12 = val;
    else if (key == "r13")                  regs.r13 = val;
    else if (key == "r14")                  regs.r14 = val;
    else if (key == "r15")                  regs.r15 = val;
    else if (key == "rip" || key == "eip" || key == "pc") regs.rip = val;
    else if (key == "rflags" || key == "eflags" || key == "flags") regs.eflags = val;
    else if (key == "fs_base")              regs.fs_base = val;
    else if (key == "gs_base")              regs.gs_base = val;
    else {
        return make_error(std::format("Unsupported x86_64 register name '{}' for write_register", reg_name));
    }

    if (::ptrace(PTRACE_SETREGSET, static_cast<pid_t>(tid), reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1L) {
        return make_error(std::format("PTRACE_SETREGSET failed for TID {}: {}", tid, std::strerror(errno)));
    }
    return {};
}

[[nodiscard]] Result<void> apply_x86_debug_registers(ThreadId tid, const X86DebugRegisterPlan& plan) {
    // Clear DR7 first before updating DR0..DR3
    if (::ptrace(PTRACE_POKEUSER,
                 static_cast<pid_t>(tid),
                 reinterpret_cast<void*>(offsetof(user, u_debugreg[7])),
                 reinterpret_cast<void*>(0UL)) == -1L) {
        return make_error(std::format("Failed to clear DR7 on TID {}: {}", tid, std::strerror(errno)));
    }
    // Clear DR6 status bits
    (void)::ptrace(PTRACE_POKEUSER,
                   static_cast<pid_t>(tid),
                   reinterpret_cast<void*>(offsetof(user, u_debugreg[6])),
                   reinterpret_cast<void*>(0UL));

    for (std::size_t s = 0u; s < 4u; ++s) {
        const auto addr = static_cast<unsigned long>(plan.slot_used[s] ? plan.dr_address[s] : 0ULL);
        if (::ptrace(PTRACE_POKEUSER,
                     static_cast<pid_t>(tid),
                     reinterpret_cast<void*>(offsetof(user, u_debugreg[0]) + s * sizeof(unsigned long)),
                     reinterpret_cast<void*>(addr)) == -1L) {
            return make_error(std::format("Failed to program DR{} on TID {}: {}", s, tid, std::strerror(errno)));
        }
    }

    if (plan.dr7 != 0u) {
        if (::ptrace(PTRACE_POKEUSER,
                     static_cast<pid_t>(tid),
                     reinterpret_cast<void*>(offsetof(user, u_debugreg[7])),
                     reinterpret_cast<void*>(static_cast<unsigned long>(plan.dr7))) == -1L) {
            return make_error(std::format("Failed to program DR7 (0x{:X}) on TID {}: {}",
                                          plan.dr7, tid, std::strerror(errno)));
        }
    }
    return {};
}

[[nodiscard]] std::uint64_t read_x86_dr6(ThreadId tid) noexcept {
    errno = 0;
    const long v = ::ptrace(PTRACE_PEEKUSER,
                            static_cast<pid_t>(tid),
                            reinterpret_cast<void*>(offsetof(user, u_debugreg[6])),
                            nullptr);
    if (v == -1L && errno != 0) {
        return 0u;
    }
    return static_cast<std::uint64_t>(static_cast<unsigned long>(v));
}

void clear_x86_dr6(ThreadId tid) noexcept {
    (void)::ptrace(PTRACE_POKEUSER,
                   static_cast<pid_t>(tid),
                   reinterpret_cast<void*>(offsetof(user, u_debugreg[6])),
                   reinterpret_cast<void*>(0UL));
}
#else
[[nodiscard]] Result<void> write_ptrace_register_by_name(ThreadId tid,
                                                         std::string_view reg_name,
                                                         std::uint64_t val) {
    (void)tid;
    (void)reg_name;
    (void)val;
    return make_error("write_register is not implemented on this host CPU architecture");
}

[[nodiscard]] Result<void> apply_x86_debug_registers(ThreadId, const X86DebugRegisterPlan&) {
    return make_error("x86 DR0..DR7 debug registers are unavailable on non-x86 host");
}

[[nodiscard]] std::uint64_t read_x86_dr6(ThreadId) noexcept { return 0u; }
void clear_x86_dr6(ThreadId) noexcept {}
#endif

[[nodiscard]] std::vector<ThreadId> list_proc_tids(ProcessId pid) {
    std::vector<ThreadId> out;
    const std::string dir_path = std::format("/proc/{}/task", pid);
    DIR* dir = ::opendir(dir_path.c_str());
    if (dir == nullptr) {
        out.push_back(pid);
        return out;
    }
    while (dirent* ent = ::readdir(dir)) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char* endp = nullptr;
        const unsigned long v = std::strtoul(ent->d_name, &endp, 10);
        if (endp != ent->d_name && *endp == '\0' && v > 0UL) {
            out.push_back(static_cast<ThreadId>(v));
        }
    }
    ::closedir(dir);
    if (out.empty()) {
        out.push_back(pid);
    }
    std::ranges::sort(out);
    return out;
}

struct InternalTempBreakpoint {
    std::uint64_t address{0};
    SoftwareTrapSpec trap{};
    std::vector<std::uint8_t> original_bytes{};
    bool armed{false};
};

class LinuxDebugSession final : public IDebugSession {
public:
    enum class InitMode : std::uint8_t {
        Launch,
        Attach,
    };

    LinuxDebugSession(InitMode mode,
                      std::filesystem::path executable,
                      std::vector<std::string> args,
                      std::filesystem::path working_dir,
                      ProcessId attach_pid)
        : shadow_session_(*this) {
        std::promise<Result<void>> init_promise;
        auto init_future = init_promise.get_future();

        tracer_thread_ = std::thread(
            &LinuxDebugSession::tracer_main,
            this,
            mode,
            std::move(executable),
            std::move(args),
            std::move(working_dir),
            attach_pid,
            std::move(init_promise));

        init_result_ = init_future.get();
        if (!init_result_.has_value() && tracer_thread_.joinable()) {
            tracer_thread_.join();
        }
    }

    ~LinuxDebugSession() override {
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Running || cur == DebugSessionState::Paused) {
            (void)detach();
        }
        {
            std::lock_guard<std::mutex> lk(mutex_);
            shutdown_requested_ = true;
            cmd_cv_.notify_all();
        }
        if (tracer_thread_.joinable()) {
            tracer_thread_.join();
        }
    }

    LinuxDebugSession(const LinuxDebugSession&) = delete;
    LinuxDebugSession& operator=(const LinuxDebugSession&) = delete;

    [[nodiscard]] const Result<void>& init_result() const noexcept { return init_result_; }

    [[nodiscard]] IProcessSession& session() noexcept override { return shadow_session_; }
    [[nodiscard]] const IProcessSession& session() const noexcept override { return shadow_session_; }

    [[nodiscard]] DebugSessionState state() const noexcept override {
        return state_.load(std::memory_order_acquire);
    }

    [[nodiscard]] DebugStopStatus stop_status() const override {
        std::lock_guard<std::mutex> lk(mutex_);
        DebugStopStatus s = stop_status_;
        s.state = state_.load(std::memory_order_acquire);
        return s;
    }

    [[nodiscard]] Result<void> continue_execution(bool pass_signal_or_exception) override {
        return enqueue_command([this, pass_signal_or_exception]() -> Result<void> {
            return tracer_continue(pass_signal_or_exception);
        });
    }

    [[nodiscard]] Result<void> pause_execution() override {
        return enqueue_command([this]() -> Result<void> {
            return tracer_pause();
        });
    }

    [[nodiscard]] Result<void> step_into(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> {
            return tracer_step_into(tid);
        });
    }

    [[nodiscard]] Result<void> step_over(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> {
            return tracer_step_over(tid);
        });
    }

    [[nodiscard]] Result<void> step_out(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> {
            return tracer_step_out(tid);
        });
    }

    [[nodiscard]] Result<DebugStopStatus> wait_for_stop(std::chrono::milliseconds timeout) override {
        std::unique_lock<std::mutex> lk(mutex_);
        const bool ok = state_cv_.wait_for(lk, timeout, [this]() {
            return state_.load(std::memory_order_acquire) != DebugSessionState::Running;
        });
        if (!ok) {
            return make_error("Timed out waiting for debuggee to stop");
        }
        DebugStopStatus st = stop_status_;
        st.state = state_.load(std::memory_order_acquire);
        return st;
    }

    [[nodiscard]] Result<void> detach() override {
        return enqueue_command([this]() -> Result<void> {
            return tracer_detach();
        });
    }

    [[nodiscard]] Result<void> terminate() override {
        return enqueue_command([this]() -> Result<void> {
            return tracer_terminate();
        });
    }

    [[nodiscard]] Result<BreakpointDescriptor> add_software_breakpoint(
        std::uint64_t address,
        std::string label,
        bool thumb_mode) override {
        Result<BreakpointDescriptor> out = make_error("Uninitialized");
        auto rc = enqueue_command([&]() -> Result<void> {
            auto r = tracer_add_software_breakpoint(address, std::move(label), thumb_mode);
            if (!r.has_value()) {
                return std::unexpected(r.error());
            }
            out = std::move(*r);
            return {};
        });
        if (!rc.has_value()) {
            return std::unexpected(rc.error());
        }
        return out;
    }

    [[nodiscard]] ForgivingValue<BreakpointDescriptor> add_hardware_breakpoint(
        std::uint64_t address,
        BreakpointKind kind,
        std::uint8_t byte_size,
        std::string label) override {
        ForgivingValue<BreakpointDescriptor> out{
            std::nullopt,
            SubsystemStatus::unavailable("debugger_hw", "Debugger session not paused"),
        };
        auto rc = enqueue_command([&]() -> Result<void> {
            out = tracer_add_hardware_breakpoint(address, kind, byte_size, std::move(label));
            return {};
        });
        if (!rc.has_value()) {
            return {
                std::nullopt,
                SubsystemStatus::unavailable("debugger_hw", rc.error().message),
            };
        }
        return out;
    }

    [[nodiscard]] Result<void> remove_breakpoint(BreakpointId id) override {
        return enqueue_command([this, id]() -> Result<void> {
            return tracer_remove_breakpoint(id);
        });
    }

    [[nodiscard]] Result<void> set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        return enqueue_command([this, id, enabled]() -> Result<void> {
            return tracer_set_breakpoint_enabled(id, enabled);
        });
    }

    [[nodiscard]] std::vector<BreakpointDescriptor> breakpoints() const override {
        std::lock_guard<std::mutex> lk(mutex_);
        return breakpoints_;
    }

    [[nodiscard]] Result<void> write_register(
        ThreadId tid,
        std::string_view reg_name,
        std::uint64_t value_u64) override {
        const std::string name_copy(reg_name);
        return enqueue_command([this, tid, name_copy, value_u64]() -> Result<void> {
            return tracer_write_register(tid, name_copy, value_u64);
        });
    }

    [[nodiscard]] std::vector<DebugEvent> events() const override {
        std::lock_guard<std::mutex> lk(mutex_);
        return std::vector<DebugEvent>(events_.begin(), events_.end());
    }

    void clear_events() override {
        std::lock_guard<std::mutex> lk(mutex_);
        events_.clear();
    }

private:
    class ShadowProcessSession final : public IProcessSession {
    public:
        explicit ShadowProcessSession(LinuxDebugSession& owner) noexcept : owner_(owner) {}

        [[nodiscard]] const ProcessInfo& info() const noexcept override {
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            if (owner_.inner_session_ != nullptr) {
                return owner_.inner_session_->info();
            }
            return owner_.fallback_info_;
        }

        [[nodiscard]] bool is_alive() const noexcept override {
            const DebugSessionState st = owner_.state();
            return st == DebugSessionState::Paused || st == DebugSessionState::Running;
        }

        [[nodiscard]] bool is_read_only() const noexcept override { return true; }

        [[nodiscard]] bool is_suspended() const noexcept override {
            return owner_.state() == DebugSessionState::Paused;
        }

        [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner == nullptr) {
                return make_error("Debug session has no active process backing");
            }
            return inner->memory_regions();
        }

        [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner == nullptr) {
                return make_error("Debug session has no active process backing");
            }
            return inner->modules();
        }

        [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            if (!owner_.paused_threads_.empty()) {
                return owner_.paused_threads_;
            }
            if (owner_.inner_session_ != nullptr) {
                return owner_.inner_session_->threads();
            }
            return make_error("No threads available in debug session");
        }

        [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            if (const auto it = owner_.paused_contexts_.find(tid); it != owner_.paused_contexts_.end()) {
                return it->second;
            }
            ThreadContext empty{};
            empty.tid = tid;
            empty.layout = TargetLayout::from_arch(host_debug_arch(), sizeof(void*) == 8u, host_debug_endian());
            empty.status = SubsystemStatus::unavailable(
                "debugger_ptrace",
                owner_.state() == DebugSessionState::Running
                    ? "Pause the debuggee to inspect live thread registers"
                    : std::format("No ptrace register snapshot for TID {}", tid));
            return empty;
        }

        [[nodiscard]] ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner != nullptr) {
                return inner->proc_auxv();
            }
            return {std::nullopt, SubsystemStatus::unavailable("debugger_ptrace", "Process not active")};
        }

        [[nodiscard]] ForgivingValue<std::string> proc_status_text() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner != nullptr) {
                return inner->proc_status_text();
            }
            return {std::nullopt, SubsystemStatus::unavailable("debugger_ptrace", "Process not active")};
        }

        [[nodiscard]] ForgivingValue<std::vector<std::string>> environment_variables() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner != nullptr) {
                return inner->environment_variables();
            }
            return {std::nullopt, SubsystemStatus::unavailable("debugger_ptrace", "Process not active")};
        }

        [[nodiscard]] ForgivingValue<ProcessMemorySummary> memory_summary(
            std::span<const MemoryRegion> regions) override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner != nullptr) {
                return inner->memory_summary(regions);
            }
            return IProcessSession::memory_summary(regions);
        }

        [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                      std::span<std::uint8_t> buffer) override {
            if (buffer.empty()) {
                return std::size_t{0};
            }

            std::size_t bytes_read = 0u;
            {
                std::unique_lock<std::mutex> lk(owner_.mutex_);
                IProcessSession* inner = owner_.inner_session_.get();
                lk.unlock();
                if (inner != nullptr) {
                    if (auto r = inner->read_memory(address, buffer); r.has_value()) {
                        bytes_read = *r;
                    }
                }
            }

            if (bytes_read == 0u && owner_.state() == DebugSessionState::Paused) {
                // Fallback to tracer-thread `PTRACE_PEEKDATA` when `/proc/<pid>/mem` is restricted
                auto peek_rc = owner_.enqueue_command([&]() -> Result<void> {
                    const ThreadId tid = owner_.active_tid_ != 0u ? owner_.active_tid_ : owner_.pid_;
                    auto pr = ptrace_read_bytes(tid, address, buffer);
                    if (!pr.has_value()) {
                        return pr;
                    }
                    bytes_read = buffer.size();
                    return {};
                });
                if (!peek_rc.has_value()) {
                    return std::unexpected(peek_rc.error());
                }
            }

            if (bytes_read == 0u) {
                return make_error(std::format("Unable to read debuggee memory at 0x{:X}", address));
            }

            // Shadow-filter armed software breakpoints (+ internal step-over temp breakpoint!)
            // so callers NEVER see injected `0xCC` / trap opcodes!
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            apply_software_breakpoint_shadow_filter(
                address, buffer.first(bytes_read), owner_.breakpoints_);
            if (owner_.temp_step_bp_.has_value() && owner_.temp_step_bp_->armed) {
                BreakpointDescriptor tmp{};
                tmp.kind = BreakpointKind::Software;
                tmp.address = owner_.temp_step_bp_->address;
                tmp.armed_in_target = true;
                tmp.original_bytes = owner_.temp_step_bp_->original_bytes;
                const std::array<BreakpointDescriptor, 1> tmp_arr{std::move(tmp)};
                apply_software_breakpoint_shadow_filter(address, buffer.first(bytes_read), tmp_arr);
            }
            return bytes_read;
        }

    private:
        LinuxDebugSession& owner_;
    };

    struct QueuedCommand {
        std::function<Result<void>()> fn;
        std::promise<Result<void>> done;
    };

    template <typename Fn>
    [[nodiscard]] Result<void> enqueue_command(Fn&& fn) {
        if (std::this_thread::get_id() == tracer_thread_.get_id()) {
            return fn();
        }
        auto cmd = std::make_shared<QueuedCommand>();
        cmd->fn = std::forward<Fn>(fn);
        auto fut = cmd->done.get_future();
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (tracer_exited_) {
                return make_error("Debugger session is no longer active");
            }
            cmd_queue_.push_back(cmd);
        }
        cmd_cv_.notify_one();
        return fut.get();
    }

    void push_event_locked(DebugEvent ev) {
        ev.sequence = ++next_event_seq_;
        ev.pid = pid_;
        events_.push_back(ev);
        while (events_.size() > kMaxEventHistory) {
            events_.pop_front();
        }
        stop_status_.last_event = ev;
    }

    void refresh_paused_snapshot_locked() {
        paused_contexts_.clear();
        paused_threads_.clear();
        for (ThreadId tid : traced_tids_) {
            if (auto ctx = read_ptrace_thread_context(tid); ctx.has_value()) {
                ThreadInfo ti{};
                ti.tid = tid;
                ti.name = (tid == pid_) ? fallback_info_.name : std::format("LWP {}", tid);
                ti.state = ThreadRunState::Stopped;
                ti.is_suspended = true;
                ti.instruction_pointer = ctx->instruction_pointer;
                ti.stack_pointer = ctx->stack_pointer;
                ti.tls_base = ctx->tls_pointer;
                ti.wait_channel = (tid == active_tid_) ? "Debugger Stopped" : "Stopped";
                ti.status = ctx->status;
                paused_threads_.push_back(std::move(ti));
                paused_contexts_.emplace(tid, std::move(*ctx));
            }
        }
        if (const auto it = paused_contexts_.find(active_tid_); it != paused_contexts_.end()) {
            stop_status_.active_tid = active_tid_;
            stop_status_.instruction_pointer = it->second.instruction_pointer;
        }
        ++stop_status_.stop_revision;
    }

    [[nodiscard]] BreakpointDescriptor* find_armed_software_bp_locked(std::uint64_t addr) noexcept {
        for (BreakpointDescriptor& bp : breakpoints_) {
            if (bp.kind == BreakpointKind::Software && bp.enabled && bp.armed_in_target && bp.address == addr) {
                return &bp;
            }
        }
        return nullptr;
    }

    [[nodiscard]] Result<void> arm_software_bp_locked(BreakpointDescriptor& bp) {
        if (bp.armed_in_target) {
            return {};
        }
        const auto trap = select_software_trap(target_arch_, target_endian_, bp.byte_size == 2u);
        if (!trap.has_value()) {
            return std::unexpected(trap.error());
        }
        const ThreadId tid = active_tid_ != 0u ? active_tid_ : pid_;
        bp.original_bytes.resize(trap->size);
        if (auto rr = ptrace_read_bytes(tid, bp.address, bp.original_bytes); !rr.has_value()) {
            bp.status = SubsystemStatus::unavailable("debugger_bp", rr.error().message);
            return rr;
        }
        if (auto wr = ptrace_write_bytes(tid, bp.address, trap->span()); !wr.has_value()) {
            bp.status = SubsystemStatus::unavailable("debugger_bp", wr.error().message);
            return wr;
        }
        bp.byte_size = trap->size;
        bp.armed_in_target = true;
        bp.status = SubsystemStatus::available(
            "debugger_bp", std::format("Armed {} software trap at 0x{:X}", trap->mnemonic, bp.address));
        return {};
    }

    [[nodiscard]] Result<void> disarm_software_bp_locked(BreakpointDescriptor& bp) {
        if (!bp.armed_in_target || bp.original_bytes.empty()) {
            bp.armed_in_target = false;
            return {};
        }
        const ThreadId tid = active_tid_ != 0u ? active_tid_ : pid_;
        auto wr = ptrace_write_bytes(tid, bp.address, bp.original_bytes);
        bp.armed_in_target = false;
        if (wr.has_value()) {
            bp.status = SubsystemStatus::available("debugger_bp", "Disarmed (original bytes restored)");
        }
        return wr;
    }

    void disarm_temp_step_bp_locked() noexcept {
        if (temp_step_bp_.has_value()) {
            if (temp_step_bp_->armed && !temp_step_bp_->original_bytes.empty()) {
                const ThreadId tid = active_tid_ != 0u ? active_tid_ : pid_;
                (void)ptrace_write_bytes(tid, temp_step_bp_->address, temp_step_bp_->original_bytes);
            }
            temp_step_bp_.reset();
        }
    }

    [[nodiscard]] Result<void> sync_hardware_breakpoints_locked() {
        const auto plan_res = build_x86_debug_register_plan(target_arch_, breakpoints_);
        if (!plan_res.has_value()) {
            return make_error(plan_res.status.detail);
        }
        hw_plan_ = *plan_res.value;
        for (BreakpointDescriptor& bp : breakpoints_) {
            if (!is_hardware_breakpoint(bp.kind)) {
                continue;
            }
            bp.hardware_slot.reset();
            bp.armed_in_target = false;
            if (!bp.enabled) {
                bp.status = SubsystemStatus::available("debugger_hw", "Disabled");
                continue;
            }
            for (std::uint8_t s = 0u; s < 4u; ++s) {
                if (hw_plan_.slot_used[s] && hw_plan_.slot_owner_id[s] == bp.id) {
                    bp.hardware_slot = s;
                    bp.armed_in_target = true;
                    bp.status = SubsystemStatus::available(
                        "debugger_hw", std::format("Armed in DR{} at 0x{:X}", s, bp.address));
                    break;
                }
            }
        }
        for (ThreadId tid : traced_tids_) {
            if (auto r = apply_x86_debug_registers(tid, hw_plan_); !r.has_value()) {
                return r;
            }
        }
        return {};
    }

    /// Steps `tid` across an armed software breakpoint currently sitting at `ip`, restoring
    /// original bytes -> `PTRACE_SINGLESTEP` -> re-arming the software trap!
    /// Returns `true` if the process exited during that single instruction.
    [[nodiscard]] Result<bool> step_past_breakpoint_at_ip_locked(ThreadId tid, BreakpointDescriptor& bp) {
        if (auto dr = disarm_software_bp_locked(bp); !dr.has_value()) {
            return std::unexpected(dr.error());
        }

        if (::ptrace(PTRACE_SINGLESTEP, static_cast<pid_t>(tid), nullptr, reinterpret_cast<void*>(0L)) == -1L) {
            (void)arm_software_bp_locked(bp);
            return make_error(std::format("PTRACE_SINGLESTEP failed on TID {}: {}", tid, std::strerror(errno)));
        }

        int wstatus = 0;
        if (::waitpid(static_cast<pid_t>(tid), &wstatus, __WALL) < 0) {
            return make_error(std::format("waitpid after single-step failed: {}", std::strerror(errno)));
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            handle_process_exit_locked(wstatus);
            return true;
        }

        if (bp.enabled) {
            (void)arm_software_bp_locked(bp);
        }
        return false;
    }

    void handle_process_exit_locked(int wstatus) {
        traced_tids_.clear();
        paused_contexts_.clear();
        paused_threads_.clear();
        temp_step_bp_.reset();
        const int code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -WTERMSIG(wstatus);
        DebugEvent ev{};
        ev.kind = DebugEventKind::ProcessExited;
        ev.tid = active_tid_;
        ev.exit_code = code;
        ev.summary = WIFEXITED(wstatus)
            ? std::format("Process {} exited with code {}", pid_, code)
            : std::format("Process {} terminated by signal {} ({})",
                          pid_, WTERMSIG(wstatus), signal_short_name(WTERMSIG(wstatus)));
        push_event_locked(std::move(ev));
        ++stop_status_.stop_revision;
        state_.store(DebugSessionState::Exited, std::memory_order_release);
        state_cv_.notify_all();
    }

    void handle_wait_event_locked(ThreadId stopped_tid, int wstatus) {
        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            if (stopped_tid == pid_ || traced_tids_.size() <= 1u) {
                handle_process_exit_locked(wstatus);
            } else {
                traced_tids_.erase(stopped_tid);
                DebugEvent ev{};
                ev.kind = DebugEventKind::ThreadExited;
                ev.tid = stopped_tid;
                ev.summary = std::format("Thread {} exited", stopped_tid);
                push_event_locked(std::move(ev));
            }
            return;
        }

        if (!WIFSTOPPED(wstatus)) {
            return;
        }

        traced_tids_.insert(stopped_tid);
        active_tid_ = stopped_tid;
        const int sig = WSTOPSIG(wstatus);
        const unsigned int ptrace_ev = (static_cast<unsigned int>(wstatus) >> 16u) & 0xFFFFu;

        if (sig == SIGTRAP && ptrace_ev == PTRACE_EVENT_CLONE) {
            unsigned long new_tid = 0UL;
            if (::ptrace(PTRACE_GETEVENTMSG, static_cast<pid_t>(stopped_tid), nullptr, &new_tid) == 0L && new_tid > 0UL) {
                traced_tids_.insert(static_cast<ThreadId>(new_tid));
                DebugEvent ev{};
                ev.kind = DebugEventKind::ThreadCreated;
                ev.tid = static_cast<ThreadId>(new_tid);
                ev.summary = std::format("Thread {} created", new_tid);
                push_event_locked(std::move(ev));
            }
            (void)::ptrace(PTRACE_CONT, static_cast<pid_t>(stopped_tid), nullptr, reinterpret_cast<void*>(0L));
            return;
        }

        if (sig == SIGTRAP && ptrace_ev == PTRACE_EVENT_EXEC) {
            DebugEvent ev{};
            ev.kind = DebugEventKind::ModuleLoaded;
            ev.tid = stopped_tid;
            ev.summary = "Target completed execve()";
            push_event_locked(std::move(ev));
            (void)::ptrace(PTRACE_CONT, static_cast<pid_t>(stopped_tid), nullptr, reinterpret_cast<void*>(0L));
            return;
        }

        last_stop_signal_ = 0;

        auto ctx_res = read_ptrace_thread_context(stopped_tid);
        std::uint64_t ip = ctx_res.has_value() ? ctx_res->instruction_pointer : 0u;

        if (sig == SIGTRAP) {
            const auto trap = select_software_trap(target_arch_, target_endian_, false);
            const std::uint64_t trap_cand =
                (trap.has_value() && trap->rewinds_pc_on_hit && ip >= trap->size)
                    ? (ip - trap->size)
                    : ip;

            // 1. Check internal one-shot `step_over` / `step_out` temp breakpoint!
            const bool hit_temp = temp_step_bp_.has_value() &&
                                  temp_step_bp_->armed &&
                                  temp_step_bp_->address == trap_cand;
            BreakpointDescriptor* hit_user_bp = find_armed_software_bp_locked(trap_cand);

            if (hit_temp || hit_user_bp != nullptr) {
                if (trap.has_value() && trap->rewinds_pc_on_hit && ip != trap_cand) {
                    (void)write_ptrace_register_by_name(stopped_tid, "rip", trap_cand);
                    ip = trap_cand;
                }
                if (hit_temp) {
                    disarm_temp_step_bp_locked();
                }
                if (hit_user_bp != nullptr) {
                    ++hit_user_bp->hit_count;
                    DebugEvent ev{};
                    ev.kind = DebugEventKind::BreakpointHit;
                    ev.tid = stopped_tid;
                    ev.address = hit_user_bp->address;
                    ev.breakpoint_id = hit_user_bp->id;
                    ev.summary = std::format(
                        "Hit software breakpoint #{} at 0x{:X}{} (hits: {})",
                        hit_user_bp->id,
                        hit_user_bp->address,
                        hit_user_bp->label.empty() ? "" : (" <" + hit_user_bp->label + ">"),
                        hit_user_bp->hit_count);
                    push_event_locked(std::move(ev));
                } else {
                    DebugEvent ev{};
                    ev.kind = DebugEventKind::SingleStepCompleted;
                    ev.tid = stopped_tid;
                    ev.address = ip;
                    ev.summary = std::format("Step completed at 0x{:X}", ip);
                    push_event_locked(std::move(ev));
                }

                refresh_paused_snapshot_locked();
                state_.store(DebugSessionState::Paused, std::memory_order_release);
                state_cv_.notify_all();
                return;
            }

            // 2. Check hardware debug register (`DR6`) hit!
            const std::uint64_t dr6 = read_x86_dr6(stopped_tid);
            if (const auto slot = match_x86_dr6_triggered_slot(dr6, hw_plan_); slot.has_value()) {
                clear_x86_dr6(stopped_tid);
                disarm_temp_step_bp_locked();
                const BreakpointId owner_id = hw_plan_.slot_owner_id[*slot];
                for (BreakpointDescriptor& bp : breakpoints_) {
                    if (bp.id == owner_id) {
                        ++bp.hit_count;
                        DebugEvent ev{};
                        ev.kind = DebugEventKind::BreakpointHit;
                        ev.tid = stopped_tid;
                        ev.address = bp.address;
                        ev.breakpoint_id = bp.id;
                        ev.summary = std::format(
                            "Hit {} breakpoint #{} (DR{}) at 0x{:X} (IP 0x{:X}, hits: {})",
                            to_string(bp.kind),
                            bp.id,
                            *slot,
                            bp.address,
                            ip,
                            bp.hit_count);
                        push_event_locked(std::move(ev));
                        break;
                    }
                }
                refresh_paused_snapshot_locked();
                state_.store(DebugSessionState::Paused, std::memory_order_release);
                state_cv_.notify_all();
                return;
            }

            // Generic SIGTRAP
            disarm_temp_step_bp_locked();
            DebugEvent ev{};
            ev.kind = DebugEventKind::ExceptionOrSignal;
            ev.tid = stopped_tid;
            ev.address = ip;
            ev.signal_or_exception_code = SIGTRAP;
            ev.summary = std::format("Stopped on SIGTRAP at 0x{:X}", ip);
            push_event_locked(std::move(ev));
            refresh_paused_snapshot_locked();
            state_.store(DebugSessionState::Paused, std::memory_order_release);
            state_cv_.notify_all();
            return;
        }

        // Non-SIGTRAP signal (e.g. SIGSEGV, SIGABRT, or user pause SIGSTOP)
        disarm_temp_step_bp_locked();
        if (sig != SIGSTOP) {
            last_stop_signal_ = sig;
        }
        DebugEvent ev{};
        ev.kind = DebugEventKind::ExceptionOrSignal;
        ev.tid = stopped_tid;
        ev.address = ip;
        ev.signal_or_exception_code = sig;
        ev.summary = std::format("Thread {} stopped with {} ({}) at 0x{:X}",
                                 stopped_tid, signal_short_name(sig), sig, ip);
        push_event_locked(std::move(ev));
        refresh_paused_snapshot_locked();
        state_.store(DebugSessionState::Paused, std::memory_order_release);
        state_cv_.notify_all();
    }

    [[nodiscard]] Result<void> tracer_continue(bool pass_signal) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("continue_execution requires debuggee to be in Paused state");
        }

        const ThreadId tid = active_tid_ != 0u ? active_tid_ : pid_;
        if (const auto it = paused_contexts_.find(tid); it != paused_contexts_.end()) {
            if (BreakpointDescriptor* bp = find_armed_software_bp_locked(it->second.instruction_pointer);
                bp != nullptr) {
                auto stepped = step_past_breakpoint_at_ip_locked(tid, *bp);
                if (!stepped.has_value()) {
                    return std::unexpected(stepped.error());
                }
                if (*stepped) {
                    return {};  // Exited during single instruction
                }
            }
        }

        const long deliver_sig = pass_signal ? static_cast<long>(last_stop_signal_) : 0L;
        last_stop_signal_ = 0;

        for (ThreadId t : traced_tids_) {
            const long sig_for_t = (t == tid) ? deliver_sig : 0L;
            if (::ptrace(PTRACE_CONT, static_cast<pid_t>(t), nullptr, reinterpret_cast<void*>(sig_for_t)) == -1L &&
                errno != ESRCH) {
                return make_error(std::format("PTRACE_CONT failed for TID {}: {}", t, std::strerror(errno)));
            }
        }

        last_resume_tp_ = std::chrono::steady_clock::now();
        state_.store(DebugSessionState::Running, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> tracer_pause() {
        std::lock_guard<std::mutex> lk(mutex_);
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Paused) {
            return {};
        }
        if (cur != DebugSessionState::Running) {
            return make_error("Cannot pause: debuggee is not running");
        }

        const ThreadId target_tid = active_tid_ != 0u ? active_tid_ : pid_;
        (void)::syscall(SYS_tgkill, static_cast<pid_t>(pid_), static_cast<pid_t>(target_tid), SIGSTOP);

        int wstatus = 0;
        const pid_t got = ::waitpid(static_cast<pid_t>(target_tid), &wstatus, __WALL);
        if (got < 0) {
            return make_error(std::format("waitpid during pause failed: {}", std::strerror(errno)));
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            handle_process_exit_locked(wstatus);
            return {};
        }

        disarm_temp_step_bp_locked();
        active_tid_ = static_cast<ThreadId>(got);
        last_stop_signal_ = 0;
        refresh_paused_snapshot_locked();
        DebugEvent ev{};
        ev.kind = DebugEventKind::ExceptionOrSignal;
        ev.tid = active_tid_;
        ev.address = stop_status_.instruction_pointer;
        ev.summary = std::format("Paused execution at 0x{:X}", stop_status_.instruction_pointer);
        push_event_locked(std::move(ev));
        state_.store(DebugSessionState::Paused, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> tracer_step_into(std::optional<ThreadId> requested_tid) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("step_into requires debuggee to be in Paused state");
        }

        const ThreadId tid = requested_tid.value_or(active_tid_ != 0u ? active_tid_ : pid_);
        active_tid_ = tid;
        disarm_temp_step_bp_locked();

        std::uint64_t cur_ip = 0u;
        if (const auto it = paused_contexts_.find(tid); it != paused_contexts_.end()) {
            cur_ip = it->second.instruction_pointer;
        }

        if (BreakpointDescriptor* bp = find_armed_software_bp_locked(cur_ip); bp != nullptr) {
            auto stepped = step_past_breakpoint_at_ip_locked(tid, *bp);
            if (!stepped.has_value()) {
                return std::unexpected(stepped.error());
            }
            if (*stepped) {
                return {};
            }
        } else {
            if (::ptrace(PTRACE_SINGLESTEP, static_cast<pid_t>(tid), nullptr, reinterpret_cast<void*>(0L)) == -1L) {
                return make_error(std::format("PTRACE_SINGLESTEP failed on TID {}: {}", tid, std::strerror(errno)));
            }
            int wstatus = 0;
            if (::waitpid(static_cast<pid_t>(tid), &wstatus, __WALL) < 0) {
                return make_error(std::format("waitpid after PTRACE_SINGLESTEP failed: {}", std::strerror(errno)));
            }
            if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
                handle_process_exit_locked(wstatus);
                return {};
            }
            if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) != SIGTRAP) {
                last_stop_signal_ = WSTOPSIG(wstatus);
                refresh_paused_snapshot_locked();
                DebugEvent ev{};
                ev.kind = DebugEventKind::ExceptionOrSignal;
                ev.tid = tid;
                ev.address = stop_status_.instruction_pointer;
                ev.signal_or_exception_code = last_stop_signal_;
                ev.summary = std::format("Single-step faulted with {} at 0x{:X}",
                                         signal_short_name(last_stop_signal_),
                                         stop_status_.instruction_pointer);
                push_event_locked(std::move(ev));
                state_cv_.notify_all();
                return {};
            }
        }

        last_stop_signal_ = 0;
        clear_x86_dr6(tid);
        refresh_paused_snapshot_locked();

        // If the new IP landed directly on an enabled user breakpoint, report BreakpointHit!
        if (BreakpointDescriptor* landed = find_armed_software_bp_locked(stop_status_.instruction_pointer);
            landed != nullptr) {
            ++landed->hit_count;
            DebugEvent ev{};
            ev.kind = DebugEventKind::BreakpointHit;
            ev.tid = tid;
            ev.address = landed->address;
            ev.breakpoint_id = landed->id;
            ev.summary = std::format("Stepped onto breakpoint #{} at 0x{:X}", landed->id, landed->address);
            push_event_locked(std::move(ev));
        } else {
            DebugEvent ev{};
            ev.kind = DebugEventKind::SingleStepCompleted;
            ev.tid = tid;
            ev.address = stop_status_.instruction_pointer;
            ev.summary = std::format("Single-stepped TID {} to 0x{:X}", tid, stop_status_.instruction_pointer);
            push_event_locked(std::move(ev));
        }

        state_.store(DebugSessionState::Paused, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> arm_temp_breakpoint_and_continue_locked(ThreadId tid,
                                                                       std::uint64_t target_va) {
        disarm_temp_step_bp_locked();

        // Only inject temp trap if no user software breakpoint is already armed at `target_va`.
        if (find_armed_software_bp_locked(target_va) == nullptr) {
            const auto trap = select_software_trap(target_arch_, target_endian_, false);
            if (!trap.has_value()) {
                return std::unexpected(trap.error());
            }
            InternalTempBreakpoint tmp{};
            tmp.address = target_va;
            tmp.trap = *trap;
            tmp.original_bytes.resize(trap->size);
            if (auto rr = ptrace_read_bytes(tid, target_va, tmp.original_bytes); !rr.has_value()) {
                return rr;
            }
            if (auto wr = ptrace_write_bytes(tid, target_va, trap->span()); !wr.has_value()) {
                return wr;
            }
            tmp.armed = true;
            temp_step_bp_ = std::move(tmp);
        }

        // Step past current IP if sitting on an armed user breakpoint
        if (const auto it = paused_contexts_.find(tid); it != paused_contexts_.end()) {
            if (BreakpointDescriptor* bp = find_armed_software_bp_locked(it->second.instruction_pointer);
                bp != nullptr) {
                auto stepped = step_past_breakpoint_at_ip_locked(tid, *bp);
                if (!stepped.has_value()) {
                    disarm_temp_step_bp_locked();
                    return std::unexpected(stepped.error());
                }
                if (*stepped) {
                    return {};
                }
                // Check if that single instruction already reached `target_va`!
                if (auto after_ctx = read_ptrace_thread_context(tid);
                    after_ctx.has_value() && after_ctx->instruction_pointer == target_va) {
                    disarm_temp_step_bp_locked();
                    refresh_paused_snapshot_locked();
                    DebugEvent ev{};
                    ev.kind = DebugEventKind::SingleStepCompleted;
                    ev.tid = tid;
                    ev.address = target_va;
                    ev.summary = std::format("Step completed at 0x{:X}", target_va);
                    push_event_locked(std::move(ev));
                    state_.store(DebugSessionState::Paused, std::memory_order_release);
                    state_cv_.notify_all();
                    return {};
                }
            }
        }

        last_stop_signal_ = 0;
        for (ThreadId t : traced_tids_) {
            if (::ptrace(PTRACE_CONT, static_cast<pid_t>(t), nullptr, reinterpret_cast<void*>(0L)) == -1L &&
                errno != ESRCH) {
                disarm_temp_step_bp_locked();
                return make_error(std::format("PTRACE_CONT failed for TID {}: {}", t, std::strerror(errno)));
            }
        }

        last_resume_tp_ = std::chrono::steady_clock::now();
        state_.store(DebugSessionState::Running, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> tracer_step_over(std::optional<ThreadId> requested_tid) {
        ThreadId tid = 0u;
        std::uint64_t ip = 0u;
        std::array<std::uint8_t, 16> clean_insn{};
        std::size_t valid_len = 0u;

        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
                return make_error("step_over requires debuggee to be in Paused state");
            }
            tid = requested_tid.value_or(active_tid_ != 0u ? active_tid_ : pid_);
            active_tid_ = tid;
            const auto it = paused_contexts_.find(tid);
            if (it == paused_contexts_.end()) {
                return make_error(std::format("No register context for TID {}", tid));
            }
            ip = it->second.instruction_pointer;

            for (std::size_t want : {16u, 8u, 4u, 2u, 1u}) {
                if (ptrace_read_bytes(tid, ip, std::span<std::uint8_t>(clean_insn.data(), want)).has_value()) {
                    valid_len = want;
                    break;
                }
            }
            if (valid_len > 0u) {
                apply_software_breakpoint_shadow_filter(
                    ip, std::span<std::uint8_t>(clean_insn.data(), valid_len), breakpoints_);
            }
        }

        const auto fallthrough = compute_step_over_fallthrough(
            target_arch_,
            target_endian_,
            ip,
            std::span<const std::uint8_t>(clean_insn.data(), valid_len),
            false);

        if (!fallthrough.has_value()) {
            return tracer_step_into(tid);
        }

        std::lock_guard<std::mutex> lk(mutex_);
        return arm_temp_breakpoint_and_continue_locked(tid, *fallthrough);
    }

    [[nodiscard]] Result<void> tracer_step_out(std::optional<ThreadId> requested_tid) {
        std::uint64_t return_va = 0u;
        ThreadId tid = 0u;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
                return make_error("step_out requires debuggee to be in Paused state");
            }
            tid = requested_tid.value_or(active_tid_ != 0u ? active_tid_ : pid_);
            active_tid_ = tid;
            const auto it = paused_contexts_.find(tid);
            if (it == paused_contexts_.end()) {
                return make_error(std::format("No register context for TID {}", tid));
            }
            const ThreadContext& ctx = it->second;

            // Try frame-pointer / link-register / return-slot resolution
            if (ctx.frame_pointer != 0u) {
                std::array<std::uint8_t, 8> ret_buf{};
                const std::size_t ptr_sz = ctx.layout.pointer_size();
                if (ptrace_read_bytes(tid,
                                      ctx.frame_pointer + ptr_sz,
                                      std::span<std::uint8_t>(ret_buf.data(), ptr_sz)).has_value()) {
                    const EndianReader rd(std::span<const std::uint8_t>(ret_buf.data(), ptr_sz), ctx.layout);
                    return_va = rd.read_pointer(0u).value_or(0u);
                }
            }
            if (return_va == 0u && ctx.link_register.has_value() && *ctx.link_register != 0u) {
                return_va = *ctx.link_register;
            }
            if (return_va == 0u && ctx.stack_pointer != 0u) {
                std::array<std::uint8_t, 8> ret_buf{};
                const std::size_t ptr_sz = ctx.layout.pointer_size();
                if (ptrace_read_bytes(tid,
                                      ctx.stack_pointer,
                                      std::span<std::uint8_t>(ret_buf.data(), ptr_sz)).has_value()) {
                    const EndianReader rd(std::span<const std::uint8_t>(ret_buf.data(), ptr_sz), ctx.layout);
                    return_va = rd.read_pointer(0u).value_or(0u);
                }
            }
        }

        if (return_va == 0u) {
            return make_error("Unable to determine caller return address for step_out");
        }

        std::lock_guard<std::mutex> lk(mutex_);
        return arm_temp_breakpoint_and_continue_locked(tid, return_va);
    }

    [[nodiscard]] Result<BreakpointDescriptor> tracer_add_software_breakpoint(
        std::uint64_t address,
        std::string label,
        bool thumb_mode) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("Pause the debuggee before adding a software breakpoint");
        }

        for (const BreakpointDescriptor& existing : breakpoints_) {
            if (existing.kind == BreakpointKind::Software && existing.address == address) {
                return existing;
            }
        }

        const auto trap = select_software_trap(target_arch_, target_endian_, thumb_mode);
        if (!trap.has_value()) {
            return std::unexpected(trap.error());
        }

        BreakpointDescriptor bp{};
        bp.id = ++next_bp_id_;
        bp.kind = BreakpointKind::Software;
        bp.address = address;
        bp.byte_size = trap->size;
        bp.enabled = true;
        bp.label = std::move(label);

        if (auto ar = arm_software_bp_locked(bp); !ar.has_value()) {
            return std::unexpected(ar.error());
        }
        breakpoints_.push_back(bp);
        return bp;
    }

    [[nodiscard]] ForgivingValue<BreakpointDescriptor> tracer_add_hardware_breakpoint(
        std::uint64_t address,
        BreakpointKind kind,
        std::uint8_t byte_size,
        std::string label) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!is_hardware_breakpoint(kind)) {
            return {
                std::nullopt,
                SubsystemStatus::unavailable("debugger_hw", "Expected HardwareExecute/Write/ReadWrite kind"),
            };
        }
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return {
                std::nullopt,
                SubsystemStatus::unavailable("debugger_hw", "Pause the debuggee before setting hardware breakpoints"),
            };
        }

        BreakpointDescriptor cand{};
        cand.id = ++next_bp_id_;
        cand.kind = kind;
        cand.address = address;
        cand.byte_size = byte_size;
        cand.enabled = true;
        cand.label = std::move(label);

        std::vector<BreakpointDescriptor> trial = breakpoints_;
        trial.push_back(cand);
        const auto plan = build_x86_debug_register_plan(target_arch_, trial);
        if (!plan.has_value()) {
            return {std::nullopt, plan.status};
        }

        breakpoints_.push_back(cand);
        if (auto sr = sync_hardware_breakpoints_locked(); !sr.has_value()) {
            breakpoints_.pop_back();
            return {
                std::nullopt,
                SubsystemStatus::unavailable("debugger_hw", sr.error().message),
            };
        }
        return {breakpoints_.back(), breakpoints_.back().status};
    }

    [[nodiscard]] Result<void> tracer_remove_breakpoint(BreakpointId id) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("Pause the debuggee before removing breakpoints");
        }
        const auto it = std::ranges::find_if(breakpoints_, [id](const BreakpointDescriptor& b) {
            return b.id == id;
        });
        if (it == breakpoints_.end()) {
            return make_error(std::format("Breakpoint #{} not found", id));
        }
        const bool was_hw = is_hardware_breakpoint(it->kind);
        if (!was_hw) {
            (void)disarm_software_bp_locked(*it);
        }
        breakpoints_.erase(it);
        if (was_hw) {
            return sync_hardware_breakpoints_locked();
        }
        return {};
    }

    [[nodiscard]] Result<void> tracer_set_breakpoint_enabled(BreakpointId id, bool enabled) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("Pause the debuggee before toggling breakpoints");
        }
        const auto it = std::ranges::find_if(breakpoints_, [id](const BreakpointDescriptor& b) {
            return b.id == id;
        });
        if (it == breakpoints_.end()) {
            return make_error(std::format("Breakpoint #{} not found", id));
        }
        if (it->enabled == enabled) {
            return {};
        }
        it->enabled = enabled;
        if (is_hardware_breakpoint(it->kind)) {
            return sync_hardware_breakpoints_locked();
        }
        return enabled ? arm_software_bp_locked(*it) : disarm_software_bp_locked(*it);
    }

    [[nodiscard]] Result<void> tracer_write_register(
        ThreadId tid,
        std::string_view reg_name,
        std::uint64_t val) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("write_register requires debuggee to be in Paused state");
        }
        const ThreadId eff_tid = tid != 0u ? tid : (active_tid_ != 0u ? active_tid_ : pid_);
        if (auto wr = write_ptrace_register_by_name(eff_tid, reg_name, val); !wr.has_value()) {
            return wr;
        }
        refresh_paused_snapshot_locked();
        return {};
    }

    [[nodiscard]] Result<void> tracer_detach() {
        std::lock_guard<std::mutex> lk(mutex_);
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Detached || cur == DebugSessionState::Exited) {
            shutdown_requested_ = true;
            return {};
        }

        // 1. If currently running, stop traced threads first so we can safely restore original code bytes!
        if (cur == DebugSessionState::Running && pid_ > 0u) {
            for (ThreadId tid : traced_tids_) {
                (void)::syscall(SYS_tgkill, static_cast<pid_t>(pid_), static_cast<pid_t>(tid), SIGSTOP);
            }
            for (ThreadId tid : traced_tids_) {
                int wstatus = 0;
                (void)::waitpid(static_cast<pid_t>(tid), &wstatus, __WALL);
            }
        }

        // 2. Disarm ALL temporary and user software breakpoints (restoring original instruction bytes!)
        //    and clear hardware debug registers (`DR0..DR7`)!
        disarm_temp_step_bp_locked();
        for (BreakpointDescriptor& bp : breakpoints_) {
            if (bp.kind == BreakpointKind::Software && bp.armed_in_target) {
                (void)disarm_software_bp_locked(bp);
            } else {
                bp.armed_in_target = false;
            }
        }
        const X86DebugRegisterPlan zero_hw{};
        for (ThreadId tid : traced_tids_) {
            (void)apply_x86_debug_registers(tid, zero_hw);
        }

        // 3. Detach cleanly from every traced thread without delivering synthetic SIGSTOP.
        for (ThreadId tid : traced_tids_) {
            (void)::ptrace(PTRACE_DETACH, static_cast<pid_t>(tid), nullptr, reinterpret_cast<void*>(0L));
        }
        traced_tids_.clear();
        paused_contexts_.clear();
        paused_threads_.clear();

        DebugEvent ev{};
        ev.kind = DebugEventKind::ProcessExited;
        ev.tid = active_tid_;
        ev.summary = std::format("Detached cleanly from PID {} (all breakpoints disarmed and restored)", pid_);
        push_event_locked(std::move(ev));

        ++stop_status_.stop_revision;
        state_.store(DebugSessionState::Detached, std::memory_order_release);
        shutdown_requested_ = true;
        state_cv_.notify_all();
        cmd_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> tracer_terminate() {
        std::lock_guard<std::mutex> lk(mutex_);
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Exited || cur == DebugSessionState::Detached) {
            shutdown_requested_ = true;
            return {};
        }

        if (pid_ > 0u) {
            (void)::kill(static_cast<pid_t>(pid_), SIGKILL);
            int wstatus = 0;
            (void)::waitpid(static_cast<pid_t>(pid_), &wstatus, __WALL);
        }
        traced_tids_.clear();
        paused_contexts_.clear();
        paused_threads_.clear();
        temp_step_bp_.reset();

        DebugEvent ev{};
        ev.kind = DebugEventKind::ProcessExited;
        ev.tid = active_tid_;
        ev.exit_code = -SIGKILL;
        ev.summary = std::format("Terminated debuggee PID {}", pid_);
        push_event_locked(std::move(ev));

        ++stop_status_.stop_revision;
        state_.store(DebugSessionState::Exited, std::memory_order_release);
        shutdown_requested_ = true;
        state_cv_.notify_all();
        cmd_cv_.notify_all();
        return {};
    }

    void tracer_main(InitMode mode,
                     std::filesystem::path executable,
                     std::vector<std::string> args,
                     std::filesystem::path working_dir,
                     ProcessId attach_pid,
                     std::promise<Result<void>> init_promise) {
        auto fail_init = [&](std::string msg) {
            std::lock_guard<std::mutex> lk(mutex_);
            state_.store(DebugSessionState::Error, std::memory_order_release);
            tracer_exited_ = true;
            init_promise.set_value(make_error(std::move(msg)));
        };

        if (mode == InitMode::Launch) {
            if (executable.empty()) {
                fail_init("Cannot launch debugger: executable path is empty");
                return;
            }
            int err_pipe[2]{-1, -1};
            if (::pipe2(err_pipe, O_CLOEXEC) != 0) {
                fail_init(std::format("pipe2 failed: {}", std::strerror(errno)));
                return;
            }

            std::vector<std::string> argv_storage;
            argv_storage.reserve(args.size() + 1u);
            argv_storage.push_back(executable.string());
            for (const std::string& a : args) {
                argv_storage.push_back(a);
            }
            std::vector<char*> argv_ptrs;
            argv_ptrs.reserve(argv_storage.size() + 1u);
            for (std::string& s : argv_storage) {
                argv_ptrs.push_back(s.data());
            }
            argv_ptrs.push_back(nullptr);

            const std::string exe_str = executable.string();
            const std::string cwd_str = working_dir.string();

            const pid_t child = ::fork();
            if (child < 0) {
                ::close(err_pipe[0]);
                ::close(err_pipe[1]);
                fail_init(std::format("fork() failed: {}", std::strerror(errno)));
                return;
            }

            if (child == 0) {
                ::close(err_pipe[0]);
                if (!cwd_str.empty() && ::chdir(cwd_str.c_str()) != 0) {
                    const int e = errno;
                    (void)::write(err_pipe[1], &e, sizeof(e));
                    ::_exit(127);
                }
                if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1L) {
                    const int e = errno;
                    (void)::write(err_pipe[1], &e, sizeof(e));
                    ::_exit(127);
                }
                ::execvp(exe_str.c_str(), argv_ptrs.data());
                const int e = errno;
                (void)::write(err_pipe[1], &e, sizeof(e));
                ::_exit(127);
            }

            ::close(err_pipe[1]);
            int child_err = 0;
            const ssize_t nread = ::read(err_pipe[0], &child_err, sizeof(child_err));
            ::close(err_pipe[0]);

            if (nread > 0) {
                int dummy = 0;
                (void)::waitpid(child, &dummy, 0);
                fail_init(std::format("Failed to launch '{}': {}",
                                      exe_str, std::strerror(child_err)));
                return;
            }

            int wstatus = 0;
            if (::waitpid(child, &wstatus, __WALL) < 0) {
                fail_init(std::format("waitpid on launched child failed: {}", std::strerror(errno)));
                return;
            }
            if (!WIFSTOPPED(wstatus)) {
                fail_init(std::format("Launched child '{}' exited before initial trap", exe_str));
                return;
            }

            (void)::ptrace(PTRACE_SETOPTIONS,
                           child,
                           nullptr,
                           reinterpret_cast<void*>(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));

            {
                std::lock_guard<std::mutex> lk(mutex_);
                pid_ = static_cast<ProcessId>(child);
                active_tid_ = pid_;
                traced_tids_.insert(pid_);
                fallback_info_.pid = pid_;
                fallback_info_.name = executable.filename().string();
                fallback_info_.executable_path = executable;
                fallback_info_.architecture = host_debug_arch();
                fallback_info_.endianness = host_debug_endian();
                fallback_info_.is_64bit = (sizeof(void*) == 8u);
                fallback_info_.access = ProcessAccessStatus::ReadOnly;

                auto backend = create_native_process_backend();
                if (auto opened = backend->open_process(pid_); opened.has_value()) {
                    inner_session_ = std::move(*opened);
                    target_arch_ = inner_session_->info().architecture != Architecture::Unknown
                        ? inner_session_->info().architecture
                        : host_debug_arch();
                    target_endian_ = inner_session_->info().endianness;
                } else {
                    target_arch_ = host_debug_arch();
                    target_endian_ = host_debug_endian();
                }

                refresh_paused_snapshot_locked();
                DebugEvent ev{};
                ev.kind = DebugEventKind::ProcessStarted;
                ev.tid = active_tid_;
                ev.address = stop_status_.instruction_pointer;
                ev.summary = std::format("Launched '{}' (PID {}) paused at 0x{:X}",
                                         fallback_info_.name, pid_, stop_status_.instruction_pointer);
                push_event_locked(std::move(ev));
                state_.store(DebugSessionState::Paused, std::memory_order_release);
            }
            init_promise.set_value({});
        } else {
            if (attach_pid == 0u || attach_pid == static_cast<ProcessId>(::getpid())) {
                fail_init("Invalid target PID for opt-in debugger attach");
                return;
            }
            const std::vector<ThreadId> tids = list_proc_tids(attach_pid);
            std::vector<ThreadId> attached;
            for (ThreadId tid : tids) {
                if (::ptrace(PTRACE_ATTACH, static_cast<pid_t>(tid), nullptr, nullptr) == 0L) {
                    int wstatus = 0;
                    if (::waitpid(static_cast<pid_t>(tid), &wstatus, __WALL) > 0 && WIFSTOPPED(wstatus)) {
                        (void)::ptrace(PTRACE_SETOPTIONS,
                                       static_cast<pid_t>(tid),
                                       nullptr,
                                       reinterpret_cast<void*>(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));
                        attached.push_back(tid);
                    }
                }
            }
            if (attached.empty()) {
                fail_init(std::format("PTRACE_ATTACH failed for PID {}: {}",
                                      attach_pid, std::strerror(errno)));
                return;
            }

            {
                std::lock_guard<std::mutex> lk(mutex_);
                pid_ = attach_pid;
                active_tid_ = attached.front();
                for (ThreadId t : attached) {
                    traced_tids_.insert(t);
                }
                fallback_info_.pid = pid_;
                fallback_info_.name = std::format("pid_{}", pid_);
                fallback_info_.architecture = host_debug_arch();
                fallback_info_.endianness = host_debug_endian();
                fallback_info_.is_64bit = (sizeof(void*) == 8u);
                fallback_info_.access = ProcessAccessStatus::ReadOnly;

                auto backend = create_native_process_backend();
                if (auto opened = backend->open_process(pid_); opened.has_value()) {
                    inner_session_ = std::move(*opened);
                    fallback_info_ = inner_session_->info();
                    target_arch_ = inner_session_->info().architecture != Architecture::Unknown
                        ? inner_session_->info().architecture
                        : host_debug_arch();
                    target_endian_ = inner_session_->info().endianness;
                } else {
                    target_arch_ = host_debug_arch();
                    target_endian_ = host_debug_endian();
                }

                refresh_paused_snapshot_locked();
                DebugEvent ev{};
                ev.kind = DebugEventKind::ProcessStarted;
                ev.tid = active_tid_;
                ev.address = stop_status_.instruction_pointer;
                ev.summary = std::format("Attached opt-in debugger to '{}' (PID {}) at 0x{:X}",
                                         fallback_info_.name, pid_, stop_status_.instruction_pointer);
                push_event_locked(std::move(ev));
                state_.store(DebugSessionState::Paused, std::memory_order_release);
            }
            init_promise.set_value({});
        }

        // Main tracer event & command loop
        while (true) {
            std::shared_ptr<QueuedCommand> next_cmd;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                if (!cmd_queue_.empty()) {
                    next_cmd = std::move(cmd_queue_.front());
                    cmd_queue_.pop_front();
                } else if (shutdown_requested_) {
                    break;
                } else if (state_.load(std::memory_order_acquire) == DebugSessionState::Running) {
                    // Non-blocking poll for tracee stops + adaptive wait so step/breakpoint hits
                    // complete in microseconds while steady-state running uses ~0% CPU!
                    int wstatus = 0;
                    const pid_t stopped = ::waitpid(-1, &wstatus, __WALL | WNOHANG);
                    if (stopped > 0) {
                        handle_wait_event_locked(static_cast<ThreadId>(stopped), wstatus);
                        continue;
                    }
                    if (stopped < 0 && errno == ECHILD) {
                        handle_process_exit_locked(0);
                        continue;
                    }
                    const auto since_resume = std::chrono::steady_clock::now() - last_resume_tp_;
                    const auto sleep_dur = (since_resume < std::chrono::milliseconds(15))
                        ? std::chrono::microseconds(100)
                        : std::chrono::microseconds(1500);
                    cmd_cv_.wait_for(lk, sleep_dur, [this]() {
                        return !cmd_queue_.empty() || shutdown_requested_;
                    });
                    continue;
                } else {
                    cmd_cv_.wait(lk, [this]() {
                        return !cmd_queue_.empty() || shutdown_requested_;
                    });
                    continue;
                }
            }

            if (next_cmd) {
                Result<void> res = next_cmd->fn();
                next_cmd->done.set_value(std::move(res));
            }
        }

        std::lock_guard<std::mutex> lk(mutex_);
        while (!cmd_queue_.empty()) {
            cmd_queue_.front()->done.set_value(make_error("Debugger session closed"));
            cmd_queue_.pop_front();
        }
        tracer_exited_ = true;
    }

    mutable std::mutex mutex_;
    std::condition_variable cmd_cv_;
    std::condition_variable state_cv_;
    std::deque<std::shared_ptr<QueuedCommand>> cmd_queue_;
    std::atomic<DebugSessionState> state_{DebugSessionState::Idle};
    bool shutdown_requested_{false};
    bool tracer_exited_{false};
    Result<void> init_result_{};

    ProcessId pid_{0};
    ThreadId active_tid_{0};
    Architecture target_arch_{Architecture::X86_64};
    Endianness target_endian_{Endianness::Little};
    ProcessInfo fallback_info_{};
    std::unique_ptr<IProcessSession> inner_session_{};
    std::set<ThreadId> traced_tids_{};
    std::unordered_map<ThreadId, ThreadContext> paused_contexts_{};
    std::vector<ThreadInfo> paused_threads_{};

    BreakpointId next_bp_id_{0};
    std::vector<BreakpointDescriptor> breakpoints_{};
    std::optional<InternalTempBreakpoint> temp_step_bp_{};
    X86DebugRegisterPlan hw_plan_{};

    int last_stop_signal_{0};
    std::uint64_t next_event_seq_{0};
    std::deque<DebugEvent> events_{};
    DebugStopStatus stop_status_{};
    std::chrono::steady_clock::time_point last_resume_tp_{};

    ShadowProcessSession shadow_session_;
    std::thread tracer_thread_;
};

class LinuxDebugBackend final : public IDebugBackend {
public:
    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> launch(
        const std::filesystem::path& executable,
        std::span<const std::string> args,
        const std::filesystem::path& working_dir) override {
        std::vector<std::string> args_vec(args.begin(), args.end());
        auto sess = std::make_unique<LinuxDebugSession>(
            LinuxDebugSession::InitMode::Launch,
            executable,
            std::move(args_vec),
            working_dir,
            ProcessId{0});
        if (!sess->init_result().has_value()) {
            return std::unexpected(sess->init_result().error());
        }
        return sess;
    }

    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> attach(ProcessId pid) override {
        auto sess = std::make_unique<LinuxDebugSession>(
            LinuxDebugSession::InitMode::Attach,
            std::filesystem::path{},
            std::vector<std::string>{},
            std::filesystem::path{},
            pid);
        if (!sess->init_result().has_value()) {
            return std::unexpected(sess->init_result().error());
        }
        return sess;
    }
};

}  // namespace

std::shared_ptr<IDebugBackend> create_native_debug_backend() {
    return std::make_shared<LinuxDebugBackend>();
}

}  // namespace peelf::debugger

#endif  // __linux__
