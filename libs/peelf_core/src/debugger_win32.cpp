#include <peelf/debugger.hpp>
#include <peelf/subprocess.hpp>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <format>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace peelf::debugger {
namespace {

constexpr std::size_t kMaxEventHistory = 512u;
constexpr DWORD kStatusWx86Breakpoint = 0x4000001FUL;
constexpr DWORD kStatusWx86SingleStep = 0x4000001EUL;

[[nodiscard]] Architecture host_win32_arch() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return Architecture::X86_64;
#elif defined(_M_IX86) || defined(__i386__)
    return Architecture::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return Architecture::ARM64;
#else
    return Architecture::Unknown;
#endif
}

[[nodiscard]] std::string lower_ascii_win(std::string_view sv) {
    std::string out(sv.size(), '\0');
    for (std::size_t i = 0; i < sv.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(sv[i])));
    }
    return out;
}

[[nodiscard]] std::wstring quote_win32_arg(std::string_view s) {
    const std::string quoted_utf8 = quote_windows_arg(s);
    if (quoted_utf8.empty()) {
        return {};
    }
    const int wide_len = ::MultiByteToWideChar(
        CP_UTF8, 0, quoted_utf8.data(), static_cast<int>(quoted_utf8.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(std::max(0, wide_len)), L'\0');
    if (wide_len > 0) {
        ::MultiByteToWideChar(
            CP_UTF8, 0, quoted_utf8.data(), static_cast<int>(quoted_utf8.size()), w.data(), wide_len);
    }
    return w;
}

[[nodiscard]] Result<void> win32_write_process_bytes(HANDLE hproc,
                                                     std::uint64_t address,
                                                     std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
    void* remote = reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
    SIZE_T written = 0;
    if (::WriteProcessMemory(hproc, remote, bytes.data(), bytes.size(), &written) &&
        written == bytes.size()) {
        ::FlushInstructionCache(hproc, remote, bytes.size());
        return {};
    }

    DWORD old_prot = 0;
    if (!::VirtualProtectEx(hproc, remote, bytes.size(), PAGE_EXECUTE_READWRITE, &old_prot)) {
        return make_error(std::format("VirtualProtectEx failed at 0x{:X} (Win32 error {})",
                                      address, ::GetLastError()));
    }
    const BOOL ok = ::WriteProcessMemory(hproc, remote, bytes.data(), bytes.size(), &written);
    const DWORD write_err = ::GetLastError();
    ::FlushInstructionCache(hproc, remote, bytes.size());
    DWORD dummy = 0;
    (void)::VirtualProtectEx(hproc, remote, bytes.size(), old_prot, &dummy);

    if (!ok || written != bytes.size()) {
        return make_error(std::format("WriteProcessMemory failed at 0x{:X} (Win32 error {})",
                                      address, write_err));
    }
    return {};
}

[[nodiscard]] Result<void> win32_read_process_bytes(HANDLE hproc,
                                                    std::uint64_t address,
                                                    std::span<std::uint8_t> out) {
    if (out.empty()) {
        return {};
    }
    SIZE_T got = 0;
    if (!::ReadProcessMemory(hproc,
                             reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
                             out.data(),
                             out.size(),
                             &got) ||
        got != out.size()) {
        return make_error(std::format("ReadProcessMemory failed at 0x{:X} (Win32 error {})",
                                      address, ::GetLastError()));
    }
    return {};
}

struct InternalTempBp {
    std::uint64_t address{0};
    SoftwareTrapSpec trap{};
    std::vector<std::uint8_t> original_bytes{};
    bool armed{false};
};

class Win32DebugSession final : public IDebugSession {
public:
    enum class InitMode : std::uint8_t {
        Launch,
        Attach,
    };

    Win32DebugSession(InitMode mode,
                      std::filesystem::path executable,
                      std::vector<std::string> args,
                      std::filesystem::path working_dir,
                      ProcessId attach_pid)
        : shadow_session_(*this) {
        std::promise<Result<void>> init_promise;
        auto init_fut = init_promise.get_future();

        loop_thread_ = std::thread(
            &Win32DebugSession::debug_loop_main,
            this,
            mode,
            std::move(executable),
            std::move(args),
            std::move(working_dir),
            attach_pid,
            std::move(init_promise));

        init_result_ = init_fut.get();
        if (!init_result_.has_value() && loop_thread_.joinable()) {
            loop_thread_.join();
        }
    }

    ~Win32DebugSession() noexcept override {
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Running || cur == DebugSessionState::Paused) {
            try {
                (void)detach();
            } catch (...) {
            }
        }
        {
            std::lock_guard<std::mutex> lk(mutex_);
            shutdown_requested_ = true;
            cmd_cv_.notify_all();
        }
        if (loop_thread_.joinable()) {
            loop_thread_.join();
        }
    }

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
            return loop_continue(pass_signal_or_exception);
        });
    }

    [[nodiscard]] Result<void> pause_execution() override {
        return enqueue_command([this]() -> Result<void> { return loop_pause(); });
    }

    [[nodiscard]] Result<void> step_into(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> { return loop_step_into(tid); });
    }

    [[nodiscard]] Result<void> step_over(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> { return loop_step_over(tid); });
    }

    [[nodiscard]] Result<void> step_out(std::optional<ThreadId> tid) override {
        return enqueue_command([this, tid]() -> Result<void> { return loop_step_out(tid); });
    }

    [[nodiscard]] Result<DebugStopStatus> wait_for_stop(std::chrono::milliseconds timeout) override {
        std::unique_lock<std::mutex> lk(mutex_);
        const bool ok = state_cv_.wait_for(lk, timeout, [this]() {
            return state_.load(std::memory_order_acquire) != DebugSessionState::Running;
        });
        if (!ok) {
            return make_error("Timed out waiting for Win32 debuggee to stop");
        }
        DebugStopStatus st = stop_status_;
        st.state = state_.load(std::memory_order_acquire);
        return st;
    }

    [[nodiscard]] Result<void> detach() override {
        return enqueue_command([this]() -> Result<void> { return loop_detach(); });
    }

    [[nodiscard]] Result<void> terminate() override {
        return enqueue_command([this]() -> Result<void> { return loop_terminate(); });
    }

    [[nodiscard]] Result<BreakpointDescriptor> add_software_breakpoint(
        std::uint64_t address,
        std::string label,
        bool thumb_mode) override {
        Result<BreakpointDescriptor> out = make_error("Uninitialized");
        auto rc = enqueue_command([&]() -> Result<void> {
            auto r = loop_add_software_bp(address, std::move(label), thumb_mode);
            if (!r.has_value()) return std::unexpected(r.error());
            out = std::move(*r);
            return {};
        });
        if (!rc.has_value()) return std::unexpected(rc.error());
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
            out = loop_add_hardware_bp(address, kind, byte_size, std::move(label));
            return {};
        });
        if (!rc.has_value()) {
            return {std::nullopt, SubsystemStatus::unavailable("debugger_hw", rc.error().message)};
        }
        return out;
    }

    [[nodiscard]] Result<void> remove_breakpoint(BreakpointId id) override {
        return enqueue_command([this, id]() -> Result<void> { return loop_remove_bp(id); });
    }

    [[nodiscard]] Result<void> set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        return enqueue_command([this, id, enabled]() -> Result<void> { return loop_enable_bp(id, enabled); });
    }

    [[nodiscard]] std::vector<BreakpointDescriptor> breakpoints() const override {
        std::lock_guard<std::mutex> lk(mutex_);
        return breakpoints_;
    }

    [[nodiscard]] Result<void> write_register(
        ThreadId tid,
        std::string_view reg_name,
        std::uint64_t value_u64) override {
        const std::string copy(reg_name);
        return enqueue_command([this, tid, copy, value_u64]() -> Result<void> {
            return loop_write_register(tid, copy, value_u64);
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
        explicit ShadowProcessSession(Win32DebugSession& owner) noexcept : owner_(owner) {}

        [[nodiscard]] const ProcessInfo& info() const noexcept override {
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            if (owner_.inner_session_ != nullptr) return owner_.inner_session_->info();
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
            if (inner == nullptr) return make_error("Debug session inactive");
            return inner->memory_regions();
        }

        [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner == nullptr) return make_error("Debug session inactive");
            return inner->modules();
        }

        [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner == nullptr) return make_error("Debug session inactive");
            return inner->threads();
        }

        [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
            std::unique_lock<std::mutex> lk(owner_.mutex_);
            IProcessSession* inner = owner_.inner_session_.get();
            lk.unlock();
            if (inner != nullptr) return inner->thread_context(tid);
            ThreadContext empty{};
            empty.tid = tid;
            empty.status = SubsystemStatus::unavailable("debugger_win32", "Debug session inactive");
            return empty;
        }

        [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                      std::span<std::uint8_t> buffer) override {
            if (buffer.empty()) return std::size_t{0};
            std::size_t got = 0u;
            {
                std::unique_lock<std::mutex> lk(owner_.mutex_);
                IProcessSession* inner = owner_.inner_session_.get();
                HANDLE hp = owner_.process_handle_;
                lk.unlock();
                if (inner != nullptr) {
                    if (auto r = inner->read_memory(address, buffer); r.has_value()) {
                        got = *r;
                    }
                }
                if (got == 0u && hp != nullptr) {
                    SIZE_T rd = 0;
                    if (::ReadProcessMemory(hp,
                                            reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
                                            buffer.data(),
                                            buffer.size(),
                                            &rd) && rd > 0) {
                        got = static_cast<std::size_t>(rd);
                    }
                }
            }
            if (got == 0u) {
                return make_error(std::format("ReadProcessMemory failed at 0x{:X}", address));
            }
            std::lock_guard<std::mutex> lk(owner_.mutex_);
            apply_software_breakpoint_shadow_filter(address, buffer.first(got), owner_.breakpoints_);
            if (owner_.temp_step_bp_.has_value() && owner_.temp_step_bp_->armed) {
                BreakpointDescriptor tmp{};
                tmp.kind = BreakpointKind::Software;
                tmp.address = owner_.temp_step_bp_->address;
                tmp.armed_in_target = true;
                tmp.original_bytes = owner_.temp_step_bp_->original_bytes;
                const std::array<BreakpointDescriptor, 1> tmp_arr{std::move(tmp)};
                apply_software_breakpoint_shadow_filter(address, buffer.first(got), tmp_arr);
            }
            return got;
        }

    private:
        Win32DebugSession& owner_;
    };

    struct QueuedCommand {
        std::function<Result<void>()> fn;
        std::promise<Result<void>> done;
    };

    template <typename Fn>
    [[nodiscard]] Result<void> enqueue_command(Fn&& fn) {
        if (std::this_thread::get_id() == loop_thread_.get_id()) {
            return fn();
        }
        auto cmd = std::make_shared<QueuedCommand>();
        cmd->fn = std::forward<Fn>(fn);
        auto fut = cmd->done.get_future();
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (loop_exited_) return make_error("Debugger session closed");
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

    [[nodiscard]] HANDLE open_or_find_thread_locked(ThreadId tid) {
        if (const auto it = thread_handles_.find(tid); it != thread_handles_.end() && it->second != nullptr) {
            return it->second;
        }
        HANDLE ht = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                 FALSE,
                                 static_cast<DWORD>(tid));
        if (ht != nullptr) {
            thread_handles_[tid] = ht;
        }
        return ht;
    }

#if defined(_M_X64) || defined(__x86_64__)
    [[nodiscard]] std::uint64_t read_win_ip_locked(ThreadId tid) {
        HANDLE ht = open_or_find_thread_locked(tid);
        if (ht == nullptr) return 0u;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (::GetThreadContext(ht, &ctx)) return ctx.Rip;
        return 0u;
    }

    [[nodiscard]] Result<void> set_win_ip_and_tf_locked(ThreadId tid,
                                                        std::optional<std::uint64_t> new_ip,
                                                        bool trap_flag) {
        HANDLE ht = open_or_find_thread_locked(tid);
        if (ht == nullptr) return make_error("OpenThread failed");
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!::GetThreadContext(ht, &ctx)) {
            return make_error(std::format("GetThreadContext failed (Win32 error {})", ::GetLastError()));
        }
        if (new_ip.has_value()) ctx.Rip = *new_ip;
        if (trap_flag) ctx.EFlags |= 0x100UL;
        else           ctx.EFlags &= ~0x100UL;
        if (!::SetThreadContext(ht, &ctx)) {
            return make_error(std::format("SetThreadContext failed (Win32 error {})", ::GetLastError()));
        }
        return {};
    }

    [[nodiscard]] Result<void> apply_win_hw_plan_locked() {
        const auto plan = build_x86_debug_register_plan(target_arch_, breakpoints_);
        if (!plan.has_value()) return make_error(plan.status.detail);
        hw_plan_ = *plan.value;
        for (auto& [tid, ht] : thread_handles_) {
            if (ht == nullptr) continue;
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!::GetThreadContext(ht, &ctx)) continue;
            ctx.Dr0 = hw_plan_.slot_used[0] ? hw_plan_.dr_address[0] : 0ULL;
            ctx.Dr1 = hw_plan_.slot_used[1] ? hw_plan_.dr_address[1] : 0ULL;
            ctx.Dr2 = hw_plan_.slot_used[2] ? hw_plan_.dr_address[2] : 0ULL;
            ctx.Dr3 = hw_plan_.slot_used[3] ? hw_plan_.dr_address[3] : 0ULL;
            ctx.Dr6 = 0ULL;
            ctx.Dr7 = hw_plan_.dr7;
            (void)::SetThreadContext(ht, &ctx);
        }
        return {};
    }
#else
    [[nodiscard]] std::uint64_t read_win_ip_locked(ThreadId) { return 0u; }
    [[nodiscard]] Result<void> set_win_ip_and_tf_locked(ThreadId, std::optional<std::uint64_t>, bool) {
        return make_error("Unsupported Win32 host CPU architecture");
    }
    [[nodiscard]] Result<void> apply_win_hw_plan_locked() {
        return make_error("Hardware breakpoints unsupported on non-x64 Win32 build");
    }
#endif

    [[nodiscard]] BreakpointDescriptor* find_armed_sw_bp_locked(std::uint64_t addr) noexcept {
        for (BreakpointDescriptor& bp : breakpoints_) {
            if (bp.kind == BreakpointKind::Software && bp.enabled && bp.armed_in_target && bp.address == addr) {
                return &bp;
            }
        }
        return nullptr;
    }

    [[nodiscard]] Result<void> arm_sw_bp_locked(BreakpointDescriptor& bp) {
        if (bp.armed_in_target) return {};
        const auto trap = select_software_trap(target_arch_, Endianness::Little, bp.byte_size == 2u);
        if (!trap.has_value()) return std::unexpected(trap.error());
        bp.original_bytes.resize(trap->size);
        if (auto rr = win32_read_process_bytes(process_handle_, bp.address, bp.original_bytes); !rr.has_value()) {
            return rr;
        }
        if (auto wr = win32_write_process_bytes(process_handle_, bp.address, trap->span()); !wr.has_value()) {
            return wr;
        }
        bp.byte_size = trap->size;
        bp.armed_in_target = true;
        bp.status = SubsystemStatus::available("debugger_bp", "Armed software trap");
        return {};
    }

    [[nodiscard]] Result<void> clear_win_hw_breakpoints_locked() {
#if defined(_M_X64) || defined(__x86_64__)
        std::string errs;
        for (auto& [tid, ht] : thread_handles_) {
            if (ht == nullptr) continue;
            DWORD exit_code = 0;
            if (::GetExitCodeThread(ht, &exit_code) && exit_code != STILL_ACTIVE) {
                continue;
            }
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!::GetThreadContext(ht, &ctx)) {
                const DWORD err = ::GetLastError();
                if (!errs.empty()) errs += "; ";
                errs += std::format("GetThreadContext(TID {}) failed (Win32 error {})", tid, err);
                continue;
            }
            ctx.Dr0 = 0ULL;
            ctx.Dr1 = 0ULL;
            ctx.Dr2 = 0ULL;
            ctx.Dr3 = 0ULL;
            ctx.Dr6 = 0ULL;
            ctx.Dr7 = 0ULL;
            if (!::SetThreadContext(ht, &ctx)) {
                const DWORD err = ::GetLastError();
                if (!errs.empty()) errs += "; ";
                errs += std::format("SetThreadContext(TID {}) failed (Win32 error {})", tid, err);
            }
        }
        if (!errs.empty()) {
            return make_error(errs);
        }
        hw_plan_ = X86DebugRegisterPlan{};
        return {};
#else
        return make_error("Hardware breakpoints unsupported on non-x64 Win32 build");
#endif
    }

    [[nodiscard]] Result<void> disarm_sw_bp_locked(BreakpointDescriptor& bp) {
        if (!bp.armed_in_target || bp.original_bytes.empty()) {
            bp.armed_in_target = false;
            return {};
        }
        auto wr = win32_write_process_bytes(process_handle_, bp.address, bp.original_bytes);
        if (!wr.has_value()) {
            bp.status = SubsystemStatus::unavailable("debugger_bp", wr.error().message);
            return wr;
        }
        bp.armed_in_target = false;
        bp.status = SubsystemStatus::available("debugger_bp", "Disarmed (original bytes restored)");
        return {};
    }

    [[nodiscard]] Result<void> try_disarm_temp_bp_locked() {
        if (!temp_step_bp_.has_value()) {
            return {};
        }
        if (temp_step_bp_->armed && !temp_step_bp_->original_bytes.empty()) {
            if (auto wr = win32_write_process_bytes(
                    process_handle_, temp_step_bp_->address, temp_step_bp_->original_bytes);
                !wr.has_value()) {
                return wr;
            }
        }
        temp_step_bp_.reset();
        return {};
    }

    void disarm_temp_bp_locked() noexcept {
        (void)try_disarm_temp_bp_locked();
        temp_step_bp_.reset();
    }

    [[nodiscard]] Result<void> loop_continue(bool pass_exception) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("continue_execution requires Paused state");
        }
        const std::uint64_t ip = read_win_ip_locked(active_tid_);
        if (BreakpointDescriptor* bp = find_armed_sw_bp_locked(ip); bp != nullptr) {
            (void)disarm_sw_bp_locked(*bp);
            (void)set_win_ip_and_tf_locked(active_tid_, std::nullopt, true);
            rearm_bp_id_after_step_ = bp->id;
            stop_after_rearm_step_ = false;
        }
        const DWORD status = pass_exception ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
        if (!::ContinueDebugEvent(static_cast<DWORD>(pid_), static_cast<DWORD>(active_tid_), status)) {
            return make_error(std::format("ContinueDebugEvent failed (Win32 error {})", ::GetLastError()));
        }
        state_.store(DebugSessionState::Running, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> loop_pause() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Running) {
            return {};
        }
        if (process_handle_ == nullptr || !::DebugBreakProcess(process_handle_)) {
            return make_error(std::format("DebugBreakProcess failed (Win32 error {})", ::GetLastError()));
        }
        pause_break_pending_ = true;
        return {};
    }

    [[nodiscard]] Result<void> loop_step_into(std::optional<ThreadId> req_tid) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("step_into requires Paused state");
        }
        const ThreadId tid = req_tid.value_or(active_tid_);
        active_tid_ = tid;
        const std::uint64_t ip = read_win_ip_locked(tid);
        if (BreakpointDescriptor* bp = find_armed_sw_bp_locked(ip); bp != nullptr) {
            (void)disarm_sw_bp_locked(*bp);
            rearm_bp_id_after_step_ = bp->id;
        }
        stop_after_rearm_step_ = true;
        if (auto r = set_win_ip_and_tf_locked(tid, std::nullopt, true); !r.has_value()) {
            return r;
        }
        if (!::ContinueDebugEvent(static_cast<DWORD>(pid_), static_cast<DWORD>(tid), DBG_CONTINUE)) {
            return make_error("ContinueDebugEvent failed");
        }
        state_.store(DebugSessionState::Running, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> loop_step_over(std::optional<ThreadId> req_tid) {
        ThreadId tid = 0u;
        std::uint64_t ip = 0u;
        std::array<std::uint8_t, 16> insn{};
        std::size_t got = 0u;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
                return make_error("step_over requires Paused state");
            }
            tid = req_tid.value_or(active_tid_);
            ip = read_win_ip_locked(tid);
            SIZE_T rd = 0;
            if (::ReadProcessMemory(process_handle_,
                                    reinterpret_cast<const void*>(static_cast<std::uintptr_t>(ip)),
                                    insn.data(),
                                    insn.size(),
                                    &rd) && rd > 0) {
                got = static_cast<std::size_t>(rd);
                apply_software_breakpoint_shadow_filter(ip, std::span<std::uint8_t>(insn.data(), got), breakpoints_);
            }
        }
        const auto fallthrough = compute_step_over_fallthrough(
            target_arch_, Endianness::Little, ip, std::span<const std::uint8_t>(insn.data(), got), false);
        if (!fallthrough.has_value()) {
            return loop_step_into(tid);
        }

        std::lock_guard<std::mutex> lk(mutex_);
        disarm_temp_bp_locked();
        if (find_armed_sw_bp_locked(*fallthrough) == nullptr) {
            if (const auto trap = select_software_trap(target_arch_, Endianness::Little, false); trap.has_value()) {
                InternalTempBp tmp{};
                tmp.address = *fallthrough;
                tmp.trap = *trap;
                tmp.original_bytes.resize(trap->size);
                if (win32_read_process_bytes(process_handle_, *fallthrough, tmp.original_bytes).has_value() &&
                    win32_write_process_bytes(process_handle_, *fallthrough, trap->span()).has_value()) {
                    tmp.armed = true;
                    temp_step_bp_ = std::move(tmp);
                }
            }
        }
        if (BreakpointDescriptor* bp = find_armed_sw_bp_locked(ip); bp != nullptr) {
            (void)disarm_sw_bp_locked(*bp);
            (void)set_win_ip_and_tf_locked(tid, std::nullopt, true);
            rearm_bp_id_after_step_ = bp->id;
            stop_after_rearm_step_ = false;
        }
        if (!::ContinueDebugEvent(static_cast<DWORD>(pid_), static_cast<DWORD>(tid), DBG_CONTINUE)) {
            disarm_temp_bp_locked();
            return make_error("ContinueDebugEvent failed");
        }
        state_.store(DebugSessionState::Running, std::memory_order_release);
        state_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> loop_step_out(std::optional<ThreadId> req_tid) {
        return loop_step_over(req_tid);
    }

    [[nodiscard]] Result<BreakpointDescriptor> loop_add_software_bp(
        std::uint64_t address,
        std::string label,
        bool thumb_mode) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("Pause debuggee before adding software breakpoint");
        }
        const auto trap = select_software_trap(target_arch_, Endianness::Little, thumb_mode);
        if (!trap.has_value()) return std::unexpected(trap.error());
        BreakpointDescriptor bp{};
        bp.id = ++next_bp_id_;
        bp.kind = BreakpointKind::Software;
        bp.address = address;
        bp.byte_size = trap->size;
        bp.enabled = true;
        bp.label = std::move(label);
        if (auto r = arm_sw_bp_locked(bp); !r.has_value()) return std::unexpected(r.error());
        breakpoints_.push_back(bp);
        return bp;
    }

    [[nodiscard]] ForgivingValue<BreakpointDescriptor> loop_add_hardware_bp(
        std::uint64_t address,
        BreakpointKind kind,
        std::uint8_t byte_size,
        std::string label) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return {std::nullopt, SubsystemStatus::unavailable("debugger_hw", "Pause debuggee first")};
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
        if (!plan.has_value()) return {std::nullopt, plan.status};
        breakpoints_.push_back(cand);
        if (auto r = apply_win_hw_plan_locked(); !r.has_value()) {
            breakpoints_.pop_back();
            return {std::nullopt, SubsystemStatus::unavailable("debugger_hw", r.error().message)};
        }
        for (std::uint8_t s = 0u; s < 4u; ++s) {
            if (hw_plan_.slot_used[s] && hw_plan_.slot_owner_id[s] == breakpoints_.back().id) {
                breakpoints_.back().hardware_slot = s;
                breakpoints_.back().armed_in_target = true;
                breakpoints_.back().status = SubsystemStatus::available("debugger_hw", "Armed in DR slot");
            }
        }
        return {breakpoints_.back(), breakpoints_.back().status};
    }

    [[nodiscard]] Result<void> loop_remove_bp(BreakpointId id) {
        std::lock_guard<std::mutex> lk(mutex_);
        const auto it = std::ranges::find_if(breakpoints_, [id](const BreakpointDescriptor& b) { return b.id == id; });
        if (it == breakpoints_.end()) return make_error("Breakpoint not found");
        const bool hw = is_hardware_breakpoint(it->kind);
        if (!hw) (void)disarm_sw_bp_locked(*it);
        breakpoints_.erase(it);
        return hw ? apply_win_hw_plan_locked() : Result<void>{};
    }

    [[nodiscard]] Result<void> loop_enable_bp(BreakpointId id, bool enabled) {
        std::lock_guard<std::mutex> lk(mutex_);
        const auto it = std::ranges::find_if(breakpoints_, [id](const BreakpointDescriptor& b) { return b.id == id; });
        if (it == breakpoints_.end()) return make_error("Breakpoint not found");
        it->enabled = enabled;
        if (is_hardware_breakpoint(it->kind)) return apply_win_hw_plan_locked();
        return enabled ? arm_sw_bp_locked(*it) : disarm_sw_bp_locked(*it);
    }

    [[nodiscard]] Result<void> loop_write_register(ThreadId tid,
                                                   std::string_view reg_name,
                                                   std::uint64_t val) {
#if defined(_M_X64) || defined(__x86_64__)
        std::lock_guard<std::mutex> lk(mutex_);
        if (state_.load(std::memory_order_acquire) != DebugSessionState::Paused) {
            return make_error("write_register requires Paused state");
        }
        HANDLE ht = open_or_find_thread_locked(tid != 0u ? tid : active_tid_);
        if (ht == nullptr) return make_error("OpenThread failed");
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
        if (!::GetThreadContext(ht, &ctx)) return make_error("GetThreadContext failed");
        const std::string k = lower_ascii_win(reg_name);
        if (k == "rax")      ctx.Rax = val;
        else if (k == "rbx") ctx.Rbx = val;
        else if (k == "rcx") ctx.Rcx = val;
        else if (k == "rdx") ctx.Rdx = val;
        else if (k == "rsi") ctx.Rsi = val;
        else if (k == "rdi") ctx.Rdi = val;
        else if (k == "rbp") ctx.Rbp = val;
        else if (k == "rsp") ctx.Rsp = val;
        else if (k == "r8")  ctx.R8 = val;
        else if (k == "r9")  ctx.R9 = val;
        else if (k == "r10") ctx.R10 = val;
        else if (k == "r11") ctx.R11 = val;
        else if (k == "r12") ctx.R12 = val;
        else if (k == "r13") ctx.R13 = val;
        else if (k == "r14") ctx.R14 = val;
        else if (k == "r15") ctx.R15 = val;
        else if (k == "rip" || k == "pc") ctx.Rip = val;
        else if (k == "rflags" || k == "eflags") ctx.EFlags = static_cast<DWORD>(val);
        else return make_error(std::format("Unsupported register '{}'", reg_name));
        if (!::SetThreadContext(ht, &ctx)) return make_error("SetThreadContext failed");
        stop_status_.instruction_pointer = ctx.Rip;
        ++stop_status_.stop_revision;
        return {};
#else
        (void)tid; (void)reg_name; (void)val;
        return make_error("write_register unsupported on this Win32 host architecture");
#endif
    }

    [[nodiscard]] Result<void> loop_detach() {
        std::lock_guard<std::mutex> lk(mutex_);
        const DebugSessionState cur = state_.load(std::memory_order_acquire);
        if (cur == DebugSessionState::Detached || cur == DebugSessionState::Exited) {
            shutdown_requested_ = true;
            return {};
        }

        if (process_handle_ != nullptr) {
            DWORD proc_exit = 0;
            if (::GetExitCodeProcess(process_handle_, &proc_exit) && proc_exit != STILL_ACTIVE) {
                close_handles_locked();
                state_.store(DebugSessionState::Exited, std::memory_order_release);
                ++stop_status_.stop_revision;
                shutdown_requested_ = true;
                state_cv_.notify_all();
                cmd_cv_.notify_all();
                return {};
            }
        }

        auto append_err = [](std::string& dst, std::string_view item) {
            if (dst.empty()) {
                dst.assign(item);
            } else {
                dst += "; ";
                dst.append(item);
            }
        };

        std::string restore_errors;
        if (auto tr = try_disarm_temp_bp_locked(); !tr.has_value()) {
            append_err(restore_errors,
                       std::format("failed to restore temporary step breakpoint at 0x{:X}: {}",
                                   temp_step_bp_->address,
                                   tr.error().message));
        }

        bool any_hw_armed = (hw_plan_.dr7 != 0u);
        for (BreakpointDescriptor& bp : breakpoints_) {
            if (bp.kind == BreakpointKind::Software && bp.armed_in_target) {
                if (auto dr = disarm_sw_bp_locked(bp); !dr.has_value()) {
                    append_err(restore_errors,
                               std::format("failed to restore software breakpoint #{} at 0x{:X}: {}",
                                           bp.id,
                                           bp.address,
                                           dr.error().message));
                } else {
                    bp.enabled = false;
                }
            } else if (is_hardware_breakpoint(bp.kind) && bp.armed_in_target) {
                any_hw_armed = true;
            }
        }

        if (any_hw_armed) {
            if (auto hr = clear_win_hw_breakpoints_locked(); !hr.has_value()) {
                append_err(restore_errors,
                           "failed to clear hardware debug registers: " + hr.error().message);
            } else {
                for (BreakpointDescriptor& bp : breakpoints_) {
                    if (is_hardware_breakpoint(bp.kind)) {
                        bp.enabled = false;
                        bp.armed_in_target = false;
                    }
                }
            }
        }

        if (!restore_errors.empty()) {
            // Preserve attached state and un-restored breakpoint descriptors on failure.
            return make_error("detach aborted before DebugActiveProcessStop: " + restore_errors);
        }

        if (cur == DebugSessionState::Paused && pid_ != 0u && active_tid_ != 0u) {
            if (!::ContinueDebugEvent(
                    static_cast<DWORD>(pid_), static_cast<DWORD>(active_tid_), DBG_CONTINUE)) {
                const DWORD err = ::GetLastError();
                return make_error(std::format(
                    "ContinueDebugEvent(PID {}, TID {}) failed during detach (Win32 error {})",
                    pid_,
                    active_tid_,
                    err));
            }
            state_.store(DebugSessionState::Running, std::memory_order_release);
        }

        if (pid_ != 0u) {
            if (!::DebugActiveProcessStop(static_cast<DWORD>(pid_))) {
                const DWORD err = ::GetLastError();
                DWORD proc_exit = 0;
                const bool target_exited =
                    process_handle_ != nullptr &&
                    ::GetExitCodeProcess(process_handle_, &proc_exit) &&
                    proc_exit != STILL_ACTIVE;
                if (!target_exited) {
                    return make_error(std::format(
                        "DebugActiveProcessStop(PID {}) failed (Win32 error {})", pid_, err));
                }
            }
        }

        close_handles_locked();
        state_.store(DebugSessionState::Detached, std::memory_order_release);
        ++stop_status_.stop_revision;
        shutdown_requested_ = true;
        state_cv_.notify_all();
        cmd_cv_.notify_all();
        return {};
    }

    [[nodiscard]] Result<void> loop_terminate() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (process_handle_ != nullptr) {
            (void)::TerminateProcess(process_handle_, 1);
        }
        if (pid_ != 0u) {
            (void)::DebugActiveProcessStop(static_cast<DWORD>(pid_));
        }
        close_handles_locked();
        state_.store(DebugSessionState::Exited, std::memory_order_release);
        ++stop_status_.stop_revision;
        shutdown_requested_ = true;
        state_cv_.notify_all();
        cmd_cv_.notify_all();
        return {};
    }

    void close_handles_locked() noexcept {
        for (auto& [tid, ht] : thread_handles_) {
            if (ht != nullptr) ::CloseHandle(ht);
        }
        thread_handles_.clear();
        if (process_handle_ != nullptr) {
            ::CloseHandle(process_handle_);
            process_handle_ = nullptr;
        }
    }

    void debug_loop_main(InitMode mode,
                         std::filesystem::path executable,
                         std::vector<std::string> args,
                         std::filesystem::path working_dir,
                         ProcessId attach_pid,
                         std::promise<Result<void>> init_promise) {
        bool init_sent = false;
        auto fail_init = [&](std::string msg) {
            std::lock_guard<std::mutex> lk(mutex_);
            state_.store(DebugSessionState::Error, std::memory_order_release);
            loop_exited_ = true;
            if (!init_sent) {
                init_sent = true;
                init_promise.set_value(make_error(std::move(msg)));
            }
        };

        if (mode == InitMode::Launch) {
            std::wstring cmdline = quote_win32_arg(executable.string());
            for (const std::string& a : args) {
                cmdline += L" ";
                cmdline += quote_win32_arg(a);
            }
            const std::wstring exe_w = executable.wstring();
            const std::wstring cwd_w = working_dir.wstring();

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (!::CreateProcessW(exe_w.c_str(),
                                  cmdline.data(),
                                  nullptr,
                                  nullptr,
                                  FALSE,
                                  DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                                  nullptr,
                                  cwd_w.empty() ? nullptr : cwd_w.c_str(),
                                  &si,
                                  &pi)) {
                fail_init(std::format("CreateProcessW(DEBUG_ONLY_THIS_PROCESS) failed (Win32 error {})",
                                      ::GetLastError()));
                return;
            }
            (void)::DebugSetProcessKillOnExit(FALSE);
            pid_ = pi.dwProcessId;
            active_tid_ = pi.dwThreadId;
            process_handle_ = pi.hProcess;
            thread_handles_[active_tid_] = pi.hThread;
            fallback_info_.pid = pid_;
            fallback_info_.name = executable.filename().string();
            fallback_info_.executable_path = executable;
            fallback_info_.architecture = host_win32_arch();
            fallback_info_.is_64bit = (sizeof(void*) == 8u);
        } else {
            if (!::DebugActiveProcess(static_cast<DWORD>(attach_pid))) {
                fail_init(std::format("DebugActiveProcess({}) failed (Win32 error {})",
                                      attach_pid, ::GetLastError()));
                return;
            }
            (void)::DebugSetProcessKillOnExit(FALSE);
            pid_ = attach_pid;
            process_handle_ = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, static_cast<DWORD>(pid_));
            fallback_info_.pid = pid_;
            fallback_info_.name = std::format("pid_{}", pid_);
            fallback_info_.architecture = host_win32_arch();
            fallback_info_.is_64bit = (sizeof(void*) == 8u);
        }

        auto backend = create_native_process_backend();
        if (auto opened = backend->open_process(pid_); opened.has_value()) {
            inner_session_ = std::move(*opened);
            fallback_info_ = inner_session_->info();
            target_arch_ = inner_session_->info().architecture != Architecture::Unknown
                ? inner_session_->info().architecture
                : host_win32_arch();
        } else {
            target_arch_ = host_win32_arch();
        }

        state_.store(DebugSessionState::Running, std::memory_order_release);

        while (true) {
            std::shared_ptr<QueuedCommand> cmd;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                if (!cmd_queue_.empty()) {
                    cmd = std::move(cmd_queue_.front());
                    cmd_queue_.pop_front();
                } else if (shutdown_requested_) {
                    break;
                } else if (state_.load(std::memory_order_acquire) != DebugSessionState::Running) {
                    cmd_cv_.wait(lk, [this]() { return !cmd_queue_.empty() || shutdown_requested_; });
                    continue;
                }
            }

            if (cmd) {
                cmd->done.set_value(cmd->fn());
                continue;
            }

            DEBUG_EVENT dev{};
            if (!::WaitForDebugEvent(&dev, 5)) {
                continue;
            }

            std::lock_guard<std::mutex> lk(mutex_);
            active_tid_ = dev.dwThreadId;

            if (dev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                if (dev.u.CreateProcessInfo.hFile != nullptr) {
                    ::CloseHandle(dev.u.CreateProcessInfo.hFile);
                }
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                if (dev.u.LoadDll.hFile != nullptr) {
                    ::CloseHandle(dev.u.LoadDll.hFile);
                }
                DebugEvent ev{};
                ev.kind = DebugEventKind::ModuleLoaded;
                ev.tid = dev.dwThreadId;
                ev.address = reinterpret_cast<std::uintptr_t>(dev.u.LoadDll.lpBaseOfDll);
                ev.summary = std::format("Loaded DLL at 0x{:X}", *ev.address);
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
                DebugEvent ev{};
                ev.kind = DebugEventKind::ModuleUnloaded;
                ev.tid = dev.dwThreadId;
                ev.address = reinterpret_cast<std::uintptr_t>(dev.u.UnloadDll.lpBaseOfDll);
                ev.summary = std::format("Unloaded DLL at 0x{:X}", *ev.address);
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                DebugEvent ev{};
                ev.kind = DebugEventKind::ThreadCreated;
                ev.tid = dev.dwThreadId;
                ev.summary = std::format("Thread {} created", dev.dwThreadId);
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                if (auto it = thread_handles_.find(dev.dwThreadId); it != thread_handles_.end()) {
                    if (it->second != nullptr) ::CloseHandle(it->second);
                    thread_handles_.erase(it);
                }
                DebugEvent ev{};
                ev.kind = DebugEventKind::ThreadExited;
                ev.tid = dev.dwThreadId;
                ev.summary = std::format("Thread {} exited", dev.dwThreadId);
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
                DebugEvent ev{};
                ev.kind = DebugEventKind::DebugOutput;
                ev.tid = dev.dwThreadId;
                ev.summary = "OutputDebugString event";
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                DebugEvent ev{};
                ev.kind = DebugEventKind::ProcessExited;
                ev.tid = dev.dwThreadId;
                ev.exit_code = static_cast<std::int32_t>(dev.u.ExitProcess.dwExitCode);
                ev.summary = std::format("Process exited with code {}", dev.u.ExitProcess.dwExitCode);
                push_event_locked(std::move(ev));
                ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                close_handles_locked();
                state_.store(DebugSessionState::Exited, std::memory_order_release);
                ++stop_status_.stop_revision;
                state_cv_.notify_all();
                if (!init_sent) {
                    init_sent = true;
                    init_promise.set_value(make_error("Process exited during debugger initialization"));
                }
                break;
            }

            if (dev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                const DWORD code = dev.u.Exception.ExceptionRecord.ExceptionCode;
                const auto exc_addr = reinterpret_cast<std::uintptr_t>(
                    dev.u.Exception.ExceptionRecord.ExceptionAddress);

                if (!initial_break_seen_ &&
                    (code == EXCEPTION_BREAKPOINT || code == kStatusWx86Breakpoint)) {
                    initial_break_seen_ = true;
                    stop_status_.active_tid = active_tid_;
                    stop_status_.instruction_pointer = read_win_ip_locked(active_tid_);
                    ++stop_status_.stop_revision;
                    DebugEvent ev{};
                    ev.kind = DebugEventKind::ProcessStarted;
                    ev.tid = active_tid_;
                    ev.address = stop_status_.instruction_pointer;
                    ev.summary = std::format("Initial loader breakpoint at 0x{:X}",
                                             stop_status_.instruction_pointer);
                    push_event_locked(std::move(ev));
                    state_.store(DebugSessionState::Paused, std::memory_order_release);
                    state_cv_.notify_all();
                    if (!init_sent) {
                        init_sent = true;
                        init_promise.set_value({});
                    }
                    continue;
                }

                if ((code == EXCEPTION_SINGLE_STEP || code == kStatusWx86SingleStep) &&
                    rearm_bp_id_after_step_.has_value()) {
                    const BreakpointId bid = *rearm_bp_id_after_step_;
                    rearm_bp_id_after_step_.reset();
                    for (BreakpointDescriptor& bp : breakpoints_) {
                        if (bp.id == bid && bp.enabled) {
                            (void)arm_sw_bp_locked(bp);
                            break;
                        }
                    }
                    if (!stop_after_rearm_step_) {
                        ::ContinueDebugEvent(dev.dwProcessId, dev.dwThreadId, DBG_CONTINUE);
                        continue;
                    }
                }

                // Software / temp breakpoint hit
                if (code == EXCEPTION_BREAKPOINT || code == kStatusWx86Breakpoint) {
                    const bool hit_tmp = temp_step_bp_.has_value() &&
                                         temp_step_bp_->armed &&
                                         temp_step_bp_->address == exc_addr;
                    BreakpointDescriptor* hit_bp = find_armed_sw_bp_locked(exc_addr);
                    if (hit_tmp || hit_bp != nullptr) {
                        (void)set_win_ip_and_tf_locked(active_tid_, exc_addr, false);
                        if (hit_tmp) disarm_temp_bp_locked();
                        if (hit_bp != nullptr) {
                            ++hit_bp->hit_count;
                            DebugEvent ev{};
                            ev.kind = DebugEventKind::BreakpointHit;
                            ev.tid = active_tid_;
                            ev.address = exc_addr;
                            ev.breakpoint_id = hit_bp->id;
                            ev.summary = std::format("Hit software breakpoint #{} at 0x{:X}",
                                                     hit_bp->id, exc_addr);
                            push_event_locked(std::move(ev));
                        } else {
                            DebugEvent ev{};
                            ev.kind = DebugEventKind::SingleStepCompleted;
                            ev.tid = active_tid_;
                            ev.address = exc_addr;
                            ev.summary = std::format("Step completed at 0x{:X}", exc_addr);
                            push_event_locked(std::move(ev));
                        }
                        stop_status_.active_tid = active_tid_;
                        stop_status_.instruction_pointer = exc_addr;
                        ++stop_status_.stop_revision;
                        state_.store(DebugSessionState::Paused, std::memory_order_release);
                        state_cv_.notify_all();
                        continue;
                    }
                }

                stop_status_.active_tid = active_tid_;
                stop_status_.instruction_pointer = read_win_ip_locked(active_tid_);
                ++stop_status_.stop_revision;
                DebugEvent ev{};
                ev.kind = (code == EXCEPTION_SINGLE_STEP || code == kStatusWx86SingleStep)
                    ? DebugEventKind::SingleStepCompleted
                    : DebugEventKind::ExceptionOrSignal;
                ev.tid = active_tid_;
                ev.address = stop_status_.instruction_pointer;
                ev.signal_or_exception_code = static_cast<std::int64_t>(code);
                ev.summary = pause_break_pending_
                    ? std::format("Paused execution at 0x{:X}", stop_status_.instruction_pointer)
                    : std::format("Stopped on Win32 debug event 0x{:08X} at 0x{:X}",
                                  code, stop_status_.instruction_pointer);
                pause_break_pending_ = false;
                push_event_locked(std::move(ev));
                state_.store(DebugSessionState::Paused, std::memory_order_release);
                state_cv_.notify_all();
            }
        }

        std::lock_guard<std::mutex> lk(mutex_);
        while (!cmd_queue_.empty()) {
            cmd_queue_.front()->done.set_value(make_error("Debugger closed"));
            cmd_queue_.pop_front();
        }
        loop_exited_ = true;
    }

    mutable std::mutex mutex_;
    std::condition_variable cmd_cv_;
    std::condition_variable state_cv_;
    std::deque<std::shared_ptr<QueuedCommand>> cmd_queue_;
    std::atomic<DebugSessionState> state_{DebugSessionState::Idle};
    bool shutdown_requested_{false};
    bool loop_exited_{false};
    bool initial_break_seen_{false};
    bool pause_break_pending_{false};
    Result<void> init_result_{};

    ProcessId pid_{0};
    ThreadId active_tid_{0};
    HANDLE process_handle_{nullptr};
    std::unordered_map<ThreadId, HANDLE> thread_handles_{};
    Architecture target_arch_{Architecture::X86_64};
    ProcessInfo fallback_info_{};
    std::unique_ptr<IProcessSession> inner_session_{};

    BreakpointId next_bp_id_{0};
    std::vector<BreakpointDescriptor> breakpoints_{};
    std::optional<InternalTempBp> temp_step_bp_{};
    std::optional<BreakpointId> rearm_bp_id_after_step_{};
    bool stop_after_rearm_step_{false};
    X86DebugRegisterPlan hw_plan_{};

    std::uint64_t next_event_seq_{0};
    std::deque<DebugEvent> events_{};
    DebugStopStatus stop_status_{};

    ShadowProcessSession shadow_session_;
    std::thread loop_thread_;
};

class Win32DebugBackend final : public IDebugBackend {
public:
    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> launch(
        const std::filesystem::path& executable,
        std::span<const std::string> args,
        const std::filesystem::path& working_dir) override {
        std::vector<std::string> av(args.begin(), args.end());
        auto s = std::make_unique<Win32DebugSession>(
            Win32DebugSession::InitMode::Launch, executable, std::move(av), working_dir, ProcessId{0});
        if (!s->init_result().has_value()) return std::unexpected(s->init_result().error());
        return s;
    }

    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> attach(ProcessId pid) override {
        auto s = std::make_unique<Win32DebugSession>(
            Win32DebugSession::InitMode::Attach, std::filesystem::path{},
            std::vector<std::string>{}, std::filesystem::path{}, pid);
        if (!s->init_result().has_value()) return std::unexpected(s->init_result().error());
        return s;
    }
};

}  // namespace

std::shared_ptr<IDebugBackend> create_native_debug_backend() {
    return std::make_shared<Win32DebugBackend>();
}

}  // namespace peelf::debugger

#elif !defined(__linux__)

namespace peelf::debugger {
namespace {

class UnsupportedDebugBackend final : public IDebugBackend {
public:
    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> launch(
        const std::filesystem::path&,
        std::span<const std::string>,
        const std::filesystem::path&) override {
        return make_error("Opt-in native debugger is not implemented on this host platform");
    }

    [[nodiscard]] Result<std::unique_ptr<IDebugSession>> attach(ProcessId) override {
        return make_error("Opt-in native debugger is not implemented on this host platform");
    }
};

}  // namespace

std::shared_ptr<IDebugBackend> create_native_debug_backend() {
    return std::make_shared<UnsupportedDebugBackend>();
}

}  // namespace peelf::debugger

#endif
