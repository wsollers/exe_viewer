#include <peelf/subprocess.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <condition_variable>
#include <mutex>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace peelf {

namespace {

template <typename CharT>
[[nodiscard]] std::basic_string<CharT> quote_windows_arg_impl(std::basic_string_view<CharT> arg) {
    constexpr CharT kSpace = static_cast<CharT>(' ');
    constexpr CharT kTab = static_cast<CharT>('\t');
    constexpr CharT kNewline = static_cast<CharT>('\n');
    constexpr CharT kVTab = static_cast<CharT>('\v');
    constexpr CharT kCr = static_cast<CharT>('\r');
    constexpr CharT kQuote = static_cast<CharT>('"');
    constexpr CharT kBackslash = static_cast<CharT>('\\');

    bool needs_quotes = arg.empty();
    if (!needs_quotes) {
        for (const CharT ch : arg) {
            if (ch == kSpace || ch == kTab || ch == kNewline || ch == kVTab || ch == kCr ||
                ch == kQuote) {
                needs_quotes = true;
                break;
            }
        }
    }
    if (!needs_quotes) {
        return std::basic_string<CharT>(arg);
    }

    std::basic_string<CharT> out;
    out.reserve(arg.size() + 2u);
    out.push_back(kQuote);

    for (std::size_t i = 0; i < arg.size(); ++i) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == kBackslash) {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            // Backslashes immediately preceding the closing quote must be doubled.
            out.append(backslashes * 2u, kBackslash);
            break;
        }
        if (arg[i] == kQuote) {
            // Backslashes immediately preceding an embedded quote must be doubled, plus one escape.
            out.append(backslashes * 2u + 1u, kBackslash);
            out.push_back(kQuote);
        } else {
            // Ordinary backslashes (e.g. path separators or UNC prefixes) remain literal.
            out.append(backslashes, kBackslash);
            out.push_back(arg[i]);
        }
    }

    out.push_back(kQuote);
    return out;
}

#if !defined(_WIN32)
[[nodiscard]] bool is_regular_executable(const std::filesystem::path& p) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec) || ec) {
        return false;
    }
    return ::access(p.c_str(), X_OK) == 0;
}
#endif

[[nodiscard]] std::filesystem::path resolve_executable_path(const std::filesystem::path& executable,
                                                            bool search_path,
                                                            std::string& error_out) {
    const std::string raw = executable.string();
    if (raw.empty()) {
        error_out = "empty executable path";
        return {};
    }

#if defined(_WIN32)
    const bool has_dir = raw.find_first_of("\\/:") != std::string::npos;
#else
    const bool has_dir = raw.find('/') != std::string::npos;
#endif

    if (!search_path || has_dir) {
        return executable;
    }

#if defined(_WIN32)
    const std::wstring exe_w = executable.wstring();
    const wchar_t* default_ext = executable.has_extension() ? nullptr : L".exe";
    const DWORD needed = ::SearchPathW(nullptr, exe_w.c_str(), default_ext, 0, nullptr, nullptr);
    if (needed == 0u) {
        error_out = std::format("executable '{}' not found in PATH", raw);
        return {};
    }
    std::wstring buf(static_cast<std::size_t>(needed), L'\0');
    const DWORD copied = ::SearchPathW(
        nullptr, exe_w.c_str(), default_ext, needed, buf.data(), nullptr);
    if (copied == 0u || copied >= needed) {
        error_out = std::format("executable '{}' not found in PATH", raw);
        return {};
    }
    buf.resize(static_cast<std::size_t>(copied));
    return std::filesystem::path(std::move(buf));
#else
    const char* path_env = std::getenv("PATH");
    const std::string_view sv = (path_env != nullptr && *path_env != '\0')
                                    ? std::string_view(path_env)
                                    : std::string_view("/usr/local/bin:/usr/bin:/bin");
    std::size_t start = 0;
    while (start <= sv.size()) {
        const std::size_t sep = sv.find(':', start);
        const std::string_view dir_sv =
            sep == std::string_view::npos ? sv.substr(start) : sv.substr(start, sep - start);
        if (!dir_sv.empty()) {
            const std::filesystem::path cand = std::filesystem::path(dir_sv) / executable;
            if (is_regular_executable(cand)) {
                return cand;
            }
        }
        if (sep == std::string_view::npos) {
            break;
        }
        start = sep + 1u;
    }
    error_out = std::format("executable '{}' not found in PATH", raw);
    return {};
#endif
}

#if defined(_WIN32)
struct ScopedWinHandle {
    HANDLE handle{nullptr};

    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE h) noexcept : handle(h) {}
    ~ScopedWinHandle() noexcept { reset(); }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;

    ScopedWinHandle(ScopedWinHandle&& other) noexcept
        : handle(std::exchange(other.handle, nullptr)) {}
    ScopedWinHandle& operator=(ScopedWinHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle = std::exchange(other.handle, nullptr);
        }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE get() const noexcept { return handle; }

    void reset(HANDLE next = nullptr) noexcept {
        if (valid()) {
            ::CloseHandle(handle);
        }
        handle = next;
    }
};

struct ScopedProcThreadAttrList {
    LPPROC_THREAD_ATTRIBUTE_LIST list{nullptr};

    ScopedProcThreadAttrList() = default;
    explicit ScopedProcThreadAttrList(LPPROC_THREAD_ATTRIBUTE_LIST p) noexcept : list(p) {}
    ~ScopedProcThreadAttrList() noexcept {
        if (list != nullptr) {
            ::DeleteProcThreadAttributeList(list);
        }
    }

    ScopedProcThreadAttrList(const ScopedProcThreadAttrList&) = delete;
    ScopedProcThreadAttrList& operator=(const ScopedProcThreadAttrList&) = delete;
};

struct ScopedWinProcess {
    ScopedWinHandle process{};
    ScopedWinHandle thread{};
    bool reaped{false};

    ScopedWinProcess() = default;
    explicit ScopedWinProcess(const PROCESS_INFORMATION& pi) noexcept
        : process(pi.hProcess), thread(pi.hThread) {}

    ~ScopedWinProcess() noexcept {
        if (process.valid() && !reaped) {
            (void)::TerminateProcess(process.get(), 137u);
            (void)::WaitForSingleObject(process.get(), 5000u);
        }
    }

    ScopedWinProcess(const ScopedWinProcess&) = delete;
    ScopedWinProcess& operator=(const ScopedWinProcess&) = delete;
};

[[nodiscard]] std::wstring utf8_to_wide(std::string_view utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), needed);
    return out;
}
#else
struct ScopedFd {
    int fd{-1};

    ScopedFd() = default;
    explicit ScopedFd(int f) noexcept : fd(f) {}
    ~ScopedFd() noexcept { reset(); }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd = std::exchange(other.fd, -1);
        }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept { return fd >= 0; }
    [[nodiscard]] int get() const noexcept { return fd; }
    [[nodiscard]] int release() noexcept { return std::exchange(fd, -1); }

    void reset(int next = -1) noexcept {
        if (fd >= 0) {
            (void)::close(fd);
        }
        fd = next;
    }
};

[[nodiscard]] bool make_cloexec_pipe(ScopedFd& rd, ScopedFd& wr) noexcept {
    int raw[2]{-1, -1};
#if defined(__linux__)
    if (::pipe2(raw, O_CLOEXEC) == 0) {
        rd.reset(raw[0]);
        wr.reset(raw[1]);
        return true;
    }
#endif
    if (::pipe(raw) != 0) {
        return false;
    }
    rd.reset(raw[0]);
    wr.reset(raw[1]);
    for (const int fd : {rd.get(), wr.get()}) {
        const int flags = ::fcntl(fd, F_GETFD);
        if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
            rd.reset();
            wr.reset();
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool set_nonblocking(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Suppresses SIGPIPE on the calling thread without mutating process-wide signal handlers.
class ScopedThreadSigpipeGuard {
public:
    explicit ScopedThreadSigpipeGuard(int write_fd) noexcept {
#if defined(F_SETNOSIGPIPE)
        (void)::fcntl(write_fd, F_SETNOSIGPIPE, 1);
#else
        (void)write_fd;
        struct sigaction sa{};
        if (::sigaction(SIGPIPE, nullptr, &sa) == 0 && sa.sa_handler == SIG_IGN) {
            return;
        }
        sigemptyset(&pipe_set_);
        sigaddset(&pipe_set_, SIGPIPE);
        sigemptyset(&orig_set_);
        if (::pthread_sigmask(SIG_BLOCK, nullptr, &orig_set_) == 0 &&
            ::sigismember(&orig_set_, SIGPIPE) == 0) {
            if (::pthread_sigmask(SIG_BLOCK, &pipe_set_, &orig_set_) == 0) {
                blocked_here_ = true;
            }
        }
#endif
    }

    ~ScopedThreadSigpipeGuard() noexcept {
#if !defined(F_SETNOSIGPIPE)
        if (blocked_here_) {
            drain_pending();
            (void)::pthread_sigmask(SIG_SETMASK, &orig_set_, nullptr);
        }
#endif
    }

    ScopedThreadSigpipeGuard(const ScopedThreadSigpipeGuard&) = delete;
    ScopedThreadSigpipeGuard& operator=(const ScopedThreadSigpipeGuard&) = delete;

    void drain_pending() noexcept {
#if defined(__linux__) && !defined(F_SETNOSIGPIPE)
        if (!blocked_here_) {
            return;
        }
        timespec zero_ts{0, 0};
        while (::sigtimedwait(&pipe_set_, nullptr, &zero_ts) == SIGPIPE) {
        }
#endif
    }

private:
#if !defined(F_SETNOSIGPIPE)
    sigset_t pipe_set_{};
    sigset_t orig_set_{};
    bool blocked_here_{false};
#endif
};

class ScopedPosixChild {
public:
    ScopedPosixChild() = default;
    explicit ScopedPosixChild(pid_t pid) noexcept : pid_(pid) {}

    ~ScopedPosixChild() noexcept {
        if (pid_ > 0 && !reaped_) {
            int dummy = 0;
            terminate_and_reap(dummy);
        }
    }

    ScopedPosixChild(const ScopedPosixChild&) = delete;
    ScopedPosixChild& operator=(const ScopedPosixChild&) = delete;

    void kill_process_group() const noexcept {
        if (pid_ > 0 && !reaped_) {
            (void)::kill(-pid_, SIGKILL);
            (void)::kill(pid_, SIGKILL);
        }
    }

    [[nodiscard]] bool try_reap_nonblocking(int& status_out) noexcept {
        if (pid_ <= 0 || reaped_) {
            return true;
        }
        while (true) {
            const pid_t r = ::waitpid(pid_, &status_out, WNOHANG);
            if (r == pid_) {
                reaped_ = true;
                return true;
            }
            if (r == 0) {
                return false;
            }
            if (errno != EINTR) {
                reaped_ = true;
                return true;
            }
        }
    }

    void reap_blocking(int& status_out) noexcept {
        if (pid_ <= 0 || reaped_) {
            return;
        }
        while (::waitpid(pid_, &status_out, 0) < 0) {
            if (errno != EINTR) {
                break;
            }
        }
        reaped_ = true;
    }

    void terminate_and_reap(int& status_out) noexcept {
        if (pid_ <= 0 || reaped_) {
            return;
        }
        kill_process_group();
        reap_blocking(status_out);
    }

private:
    pid_t pid_{-1};
    bool reaped_{false};
};
#endif

} // namespace

std::string quote_windows_arg(std::string_view arg) {
    return quote_windows_arg_impl<char>(arg);
}

#if !defined(_WIN32)
namespace detail {

bool prepare_posix_child_stdio(int& in_rd,
                               int& out_wr,
                               int& err_wr,
                               int& exec_wr) noexcept {
    auto relocate_above_stdio = [](int fd) noexcept -> int {
        if (fd < 0) {
            errno = EBADF;
            return -1;
        }
        if (fd >= 3) {
            return fd;
        }
        return ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
    };

    const int orig_in = in_rd;
    const int orig_out = out_wr;
    const int orig_err = err_wr;
    const int orig_exec = exec_wr;

    const int safe_in = relocate_above_stdio(orig_in);
    const int safe_out = relocate_above_stdio(orig_out);
    const int safe_err = relocate_above_stdio(orig_err);
    const int safe_exec = (orig_exec >= 0) ? relocate_above_stdio(orig_exec) : -1;

    auto close_if_relocated = [](int safe_fd, int orig_fd) noexcept {
        if (safe_fd >= 0 && safe_fd != orig_fd) {
            (void)::close(safe_fd);
        }
    };

    if (safe_in < 3 || safe_out < 3 || safe_err < 3 || (orig_exec >= 0 && safe_exec < 3)) {
        const int saved_err = errno;
        close_if_relocated(safe_in, orig_in);
        close_if_relocated(safe_out, orig_out);
        close_if_relocated(safe_err, orig_err);
        close_if_relocated(safe_exec, orig_exec);
        errno = saved_err;
        return false;
    }

    // Close any original pipe FDs that landed in 0..2 before dup2 overwrites 0..2.
    unsigned closed_low_mask = 0u;
    for (const int orig : {orig_in, orig_out, orig_err, orig_exec}) {
        if (orig >= 0 && orig < 3) {
            const unsigned bit = 1u << static_cast<unsigned>(orig);
            if ((closed_low_mask & bit) == 0u) {
                (void)::close(orig);
                closed_low_mask |= bit;
            }
        }
    }

    exec_wr = safe_exec;
    in_rd = safe_in;
    out_wr = safe_out;
    err_wr = safe_err;

    auto dup2_retry = [](int src_fd, int dst_fd) noexcept -> bool {
        while (::dup2(src_fd, dst_fd) < 0) {
            if (errno != EINTR) {
                return false;
            }
        }
        return true;
    };

    if (!dup2_retry(in_rd, STDIN_FILENO) ||
        !dup2_retry(out_wr, STDOUT_FILENO) ||
        !dup2_retry(err_wr, STDERR_FILENO)) {
        return false;
    }

    if (in_rd >= 3 && in_rd != exec_wr) {
        (void)::close(in_rd);
    }
    if (out_wr >= 3 && out_wr != in_rd && out_wr != exec_wr) {
        (void)::close(out_wr);
    }
    if (err_wr >= 3 && err_wr != in_rd && err_wr != out_wr && err_wr != exec_wr) {
        (void)::close(err_wr);
    }

    in_rd = STDIN_FILENO;
    out_wr = STDOUT_FILENO;
    err_wr = STDERR_FILENO;
    return true;
}

} // namespace detail
#endif

SubprocessResult run_subprocess_bounded(
    const std::filesystem::path& executable,
    std::span<const std::string> args,
    const SubprocessOptions& options) {
    SubprocessResult res;
    if (options.stop_token.stop_requested()) {
        res.cancelled = true;
        res.exit_code = -1;
        return res;
    }

    const std::filesystem::path resolved_exe =
        resolve_executable_path(executable, options.search_path, res.launch_error);
    if (resolved_exe.empty()) {
        return res;
    }

    const auto effective_timeout =
        options.timeout > std::chrono::milliseconds::zero()
            ? options.timeout
            : std::chrono::milliseconds{1};
    const auto deadline = std::chrono::steady_clock::now() + effective_timeout;

#if defined(_WIN32)
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE raw_in_rd = nullptr, raw_in_wr = nullptr;
    HANDLE raw_out_rd = nullptr, raw_out_wr = nullptr;
    HANDLE raw_err_rd = nullptr, raw_err_wr = nullptr;

    if (!::CreatePipe(&raw_in_rd, &raw_in_wr, &sa, 0)) {
        res.launch_error = "CreatePipe(stdin) failed";
        return res;
    }
    ScopedWinHandle stdin_rd(raw_in_rd), stdin_wr(raw_in_wr);

    if (!::CreatePipe(&raw_out_rd, &raw_out_wr, &sa, 0)) {
        res.launch_error = "CreatePipe(stdout) failed";
        return res;
    }
    ScopedWinHandle stdout_rd(raw_out_rd), stdout_wr(raw_out_wr);

    if (!::CreatePipe(&raw_err_rd, &raw_err_wr, &sa, 0)) {
        res.launch_error = "CreatePipe(stderr) failed";
        return res;
    }
    ScopedWinHandle stderr_rd(raw_err_rd), stderr_wr(raw_err_wr);

    if (!::SetHandleInformation(stdin_wr.get(), HANDLE_FLAG_INHERIT, 0) ||
        !::SetHandleInformation(stdout_rd.get(), HANDLE_FLAG_INHERIT, 0) ||
        !::SetHandleInformation(stderr_rd.get(), HANDLE_FLAG_INHERIT, 0)) {
        res.launch_error = "SetHandleInformation(HANDLE_FLAG_INHERIT=0) failed";
        return res;
    }

    ScopedWinHandle cancel_event(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!cancel_event.valid()) {
        res.launch_error = "CreateEventW failed";
        return res;
    }

    // Dedicated non-inheritable Job Object with KILL_ON_JOB_CLOSE ensures all child and
    // grandchild processes exit and release inherited pipe handles when the job closes.
    ScopedWinHandle job(::CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) {
        res.launch_error = "CreateJobObjectW failed";
        return res;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!::SetInformationJobObject(
            job.get(), JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        res.launch_error = "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed";
        return res;
    }

    SIZE_T attr_size = 0;
    (void)::InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    if (attr_size == 0) {
        res.launch_error = "InitializeProcThreadAttributeList(size) failed";
        return res;
    }
    auto attr_storage = std::make_unique<std::byte[]>(attr_size);
    auto* raw_attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_storage.get());
    if (!::InitializeProcThreadAttributeList(raw_attr_list, 1, 0, &attr_size)) {
        res.launch_error = "InitializeProcThreadAttributeList failed";
        return res;
    }
    ScopedProcThreadAttrList attr_guard(raw_attr_list);

    // Restrict handle inheritance strictly to the three explicit child stdio pipe ends.
    std::array<HANDLE, 3> inherited_handles{
        stdin_rd.get(),
        stdout_wr.get(),
        stderr_wr.get(),
    };
    if (!::UpdateProcThreadAttribute(
            raw_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited_handles.data(),
            inherited_handles.size() * sizeof(HANDLE),
            nullptr,
            nullptr)) {
        res.launch_error = "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST) failed";
        return res;
    }

    const std::wstring app_w = resolved_exe.wstring();
    std::wstring cmdline = quote_windows_arg_impl<wchar_t>(app_w);
    for (const std::string& a : args) {
        cmdline.push_back(L' ');
        cmdline += quote_windows_arg_impl<wchar_t>(utf8_to_wide(a));
    }

    STARTUPINFOEXW siex{};
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    siex.StartupInfo.hStdInput = stdin_rd.get();
    siex.StartupInfo.hStdOutput = stdout_wr.get();
    siex.StartupInfo.hStdError = stderr_wr.get();
    siex.lpAttributeList = raw_attr_list;

    PROCESS_INFORMATION pi{};
    const BOOL created = ::CreateProcessW(
        app_w.c_str(),
        cmdline.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        &siex.StartupInfo,
        &pi);
    const DWORD create_err = created ? ERROR_SUCCESS : ::GetLastError();

    stdin_rd.reset();
    stdout_wr.reset();
    stderr_wr.reset();

    if (!created) {
        res.launch_error = std::format("CreateProcessW failed (Win32 error {})", create_err);
        return res;
    }

    ScopedWinProcess child(pi);
    if (!::AssignProcessToJobObject(job.get(), child.process.get())) {
        const DWORD assign_err = ::GetLastError();
        (void)::TerminateProcess(child.process.get(), 137u);
        (void)::WaitForSingleObject(child.process.get(), 5000u);
        child.reaped = true;
        res.launch_error =
            std::format("AssignProcessToJobObject failed (Win32 error {})", assign_err);
        return res;
    }

    if (::ResumeThread(child.thread.get()) == static_cast<DWORD>(-1)) {
        const DWORD resume_err = ::GetLastError();
        (void)::TerminateJobObject(job.get(), 137u);
        job.reset();
        (void)::WaitForSingleObject(child.process.get(), 5000u);
        child.reaped = true;
        res.launch_error = std::format("ResumeThread failed (Win32 error {})", resume_err);
        return res;
    }

    res.launched = true;

    std::mutex io_mu;
    std::condition_variable io_cv;
    int active_io_threads = 3;

    auto finish_io_worker = [&]() noexcept {
        std::lock_guard<std::mutex> lk(io_mu);
        --active_io_threads;
        io_cv.notify_all();
    };

    const std::string_view stdin_payload = options.stdin_payload;
    const std::size_t max_output_bytes = options.max_output_bytes;

    std::jthread stdin_writer([in_handle = std::move(stdin_wr), stdin_payload, &finish_io_worker]() mutable {
        std::size_t offset = 0;
        while (offset < stdin_payload.size()) {
            const std::size_t rem = stdin_payload.size() - offset;
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 65536u));
            DWORD written = 0;
            if (!::WriteFile(
                    in_handle.get(), stdin_payload.data() + offset, chunk, &written, nullptr) ||
                written == 0) {
                break;
            }
            offset += static_cast<std::size_t>(written);
        }
        in_handle.reset();
        finish_io_worker();
    });

    auto make_drainer = [&](ScopedWinHandle rd_handle, std::string& dst) {
        return std::jthread([h = std::move(rd_handle), &dst, max_output_bytes, &finish_io_worker]() mutable {
            std::array<char, 8192> buf{};
            DWORD n = 0;
            while (::ReadFile(h.get(), buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr) &&
                   n > 0) {
                if (dst.size() < max_output_bytes) {
                    const std::size_t keep = std::min<std::size_t>(
                        static_cast<std::size_t>(n), max_output_bytes - dst.size());
                    dst.append(buf.data(), keep);
                }
            }
            h.reset();
            finish_io_worker();
        });
    };

    std::jthread stdout_drainer = make_drainer(std::move(stdout_rd), res.stdout_text);
    std::jthread stderr_drainer = make_drainer(std::move(stderr_rd), res.stderr_text);

    // Declared AFTER the jthreads so reverse stack unwinding always terminates/closes the
    // Job Object (breaking remote pipe handles) BEFORE jthread destructors block in join().
    struct ScopedJobCloser {
        ScopedWinHandle& job_ref;
        ~ScopedJobCloser() noexcept {
            if (job_ref.valid()) {
                (void)::TerminateJobObject(job_ref.get(), 137u);
                job_ref.reset();
            }
        }
    } job_closer{job};

    auto on_stop = [&]() noexcept {
        (void)::SetEvent(cancel_event.get());
        io_cv.notify_all();
    };
    std::stop_callback<decltype(on_stop)> stop_cb(options.stop_token, on_stop);

    const std::array<HANDLE, 2> wait_handles{child.process.get(), cancel_event.get()};
    while (true) {
        if (options.stop_token.stop_requested()) {
            res.cancelled = true;
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            break;
        }
        const auto rem_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const DWORD wait_slice = static_cast<DWORD>(std::clamp<long long>(
            rem_ms, 1LL, static_cast<long long>(std::numeric_limits<DWORD>::max() - 1u)));
        const DWORD wait_rc = ::WaitForMultipleObjects(
            static_cast<DWORD>(wait_handles.size()), wait_handles.data(), FALSE, wait_slice);
        if (wait_rc == WAIT_OBJECT_0) {
            child.reaped = true;
            break;
        }
        if (wait_rc == WAIT_OBJECT_0 + 1u) {
            res.cancelled = true;
            break;
        }
        if (wait_rc != WAIT_TIMEOUT) {
            child.reaped = true;
            break;
        }
    }

    DWORD exit_code = 1;
    bool got_exit_code = false;
    if (!res.timed_out && !res.cancelled) {
        got_exit_code = ::GetExitCodeProcess(child.process.get(), &exit_code) != 0;

        // Bound pipe drainer completion by the same deadline + stop_token in case a spawned
        // grandchild is still alive holding inherited stdout/stderr handles open.
        std::unique_lock<std::mutex> lk(io_mu);
        const bool drained = io_cv.wait_until(lk, deadline, [&]() {
            return active_io_threads == 0 || options.stop_token.stop_requested();
        });
        if (active_io_threads > 0) {
            if (options.stop_token.stop_requested()) {
                res.cancelled = true;
            } else if (!drained) {
                res.timed_out = true;
            }
        }
    }

    // Closing/terminating the Job Object kills any remaining primary or descendant processes
    // and closes their inherited pipe handles in the kernel, guaranteeing immediate EOF/broken-pipe
    // for all three I/O threads before join().
    if (job.valid()) {
        if (res.timed_out || res.cancelled) {
            (void)::TerminateJobObject(job.get(), 137u);
        }
        job.reset();
    }
    if (!child.reaped) {
        (void)::WaitForSingleObject(child.process.get(), 5000u);
        child.reaped = true;
    }

    stdin_writer.join();
    stdout_drainer.join();
    stderr_drainer.join();

    if (res.timed_out || res.cancelled) {
        res.exit_code = -1;
        return res;
    }

    res.exit_code = got_exit_code ? static_cast<int>(exit_code) : 1;
    return res;
#else
    ScopedFd in_rd, in_wr;
    ScopedFd out_rd, out_wr;
    ScopedFd err_rd, err_wr;
    ScopedFd exec_rd, exec_wr;
    ScopedFd cancel_rd, cancel_wr;
    if (!make_cloexec_pipe(in_rd, in_wr) ||
        !make_cloexec_pipe(out_rd, out_wr) ||
        !make_cloexec_pipe(err_rd, err_wr) ||
        !make_cloexec_pipe(exec_rd, exec_wr)) {
        res.launch_error = "pipe() failed";
        return res;
    }
    if (options.stop_token.stop_possible()) {
        if (!make_cloexec_pipe(cancel_rd, cancel_wr) ||
            !set_nonblocking(cancel_rd.get()) ||
            !set_nonblocking(cancel_wr.get())) {
            res.launch_error = "pipe(cancel) failed";
            return res;
        }
    }

    const std::string exe_str = resolved_exe.string();
    std::vector<std::string> owned_argv;
    owned_argv.reserve(args.size() + 1u);
    owned_argv.push_back(exe_str);
    for (const std::string& a : args) {
        owned_argv.push_back(a);
    }
    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(owned_argv.size() + 1u);
    for (std::string& s : owned_argv) {
        argv_ptrs.push_back(s.data());
    }
    argv_ptrs.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        res.launch_error = "fork() failed";
        return res;
    }

    if (pid == 0) {
        (void)::setpgid(0, 0);

        in_wr.reset();
        out_rd.reset();
        err_rd.reset();
        exec_rd.reset();
        cancel_rd.reset();
        cancel_wr.reset();

        int child_in = in_rd.release();
        int child_out = out_wr.release();
        int child_err = err_wr.release();
        int child_exec = exec_wr.release();

        if (!detail::prepare_posix_child_stdio(child_in, child_out, child_err, child_exec)) {
            const int err = errno;
            if (child_exec >= 0) {
                (void)::write(child_exec, &err, sizeof(err));
            }
            _exit(127);
        }

        // child_exec (>= 3) retains FD_CLOEXEC so successful execv() signals EOF to parent.
        ::execv(exe_str.c_str(), argv_ptrs.data());
        const int err = errno;
        (void)::write(child_exec, &err, sizeof(err));
        _exit(127);
    }

    // Set child PGID in parent as well to eliminate the fork-to-setpgid scheduling race.
    (void)::setpgid(pid, pid);
    ScopedPosixChild child(pid);
    in_rd.reset();
    out_wr.reset();
    err_wr.reset();
    exec_wr.reset();

    int child_exec_errno = 0;
    ssize_t exec_read = 0;
    do {
        exec_read = ::read(exec_rd.get(), &child_exec_errno, sizeof(child_exec_errno));
    } while (exec_read < 0 && errno == EINTR);
    exec_rd.reset();

    if (exec_read > 0) {
        in_wr.reset();
        out_rd.reset();
        err_rd.reset();
        int status = 0;
        child.reap_blocking(status);
        res.launched = false;
        res.launch_error = std::format(
            "execv('{}') failed: {}", exe_str, std::strerror(child_exec_errno));
        return res;
    }

    res.launched = true;

    auto on_stop = [&]() noexcept {
        if (cancel_wr.valid()) {
            const char b = 1;
            (void)::write(cancel_wr.get(), &b, 1);
        }
    };
    std::stop_callback<decltype(on_stop)> stop_cb(options.stop_token, on_stop);

    ScopedThreadSigpipeGuard sigpipe_guard(in_wr.get());
    if (options.stdin_payload.empty()) {
        in_wr.reset();
    } else if (!set_nonblocking(in_wr.get())) {
        res.launch_error = "fcntl(O_NONBLOCK) failed on stdin pipe";
        return res;
    }
    if (!set_nonblocking(out_rd.get()) || !set_nonblocking(err_rd.get())) {
        res.launch_error = "fcntl(O_NONBLOCK) failed on output pipe";
        return res;
    }

    std::size_t stdin_offset = 0;
    std::array<char, 8192> buf{};

    auto drain_fd = [&](ScopedFd& fd, std::string& dst) {
        while (fd.valid()) {
            const ssize_t n = ::read(fd.get(), buf.data(), buf.size());
            if (n > 0) {
                if (dst.size() < options.max_output_bytes) {
                    const std::size_t keep = std::min<std::size_t>(
                        static_cast<std::size_t>(n), options.max_output_bytes - dst.size());
                    dst.append(buf.data(), keep);
                }
                continue;
            }
            if (n == 0) {
                fd.reset();
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            fd.reset();
            break;
        }
    };

    while (in_wr.valid() || out_rd.valid() || err_rd.valid()) {
        if (options.stop_token.stop_requested()) {
            res.cancelled = true;
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            break;
        }

        const auto rem_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const int poll_ms = static_cast<int>(std::clamp<long long>(
            rem_ms, 1LL, static_cast<long long>(std::numeric_limits<int>::max())));

        std::array<pollfd, 4> pfds{{
            pollfd{.fd = in_wr.get(), .events = POLLOUT, .revents = 0},
            pollfd{.fd = out_rd.get(), .events = POLLIN, .revents = 0},
            pollfd{.fd = err_rd.get(), .events = POLLIN, .revents = 0},
            pollfd{.fd = cancel_rd.get(), .events = POLLIN, .revents = 0},
        }};

        const int pr = ::poll(pfds.data(), pfds.size(), poll_ms);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            continue;
        }

        if (pfds[3].revents != 0 && options.stop_token.stop_requested()) {
            res.cancelled = true;
            break;
        }
        if (pfds[1].revents != 0 && out_rd.valid()) {
            drain_fd(out_rd, res.stdout_text);
        }
        if (pfds[2].revents != 0 && err_rd.valid()) {
            drain_fd(err_rd, res.stderr_text);
        }
        if (pfds[0].revents != 0 && in_wr.valid()) {
            while (stdin_offset < options.stdin_payload.size()) {
                const std::size_t chunk = std::min<std::size_t>(
                    options.stdin_payload.size() - stdin_offset, 65536u);
                const ssize_t w = ::write(
                    in_wr.get(), options.stdin_payload.data() + stdin_offset, chunk);
                if (w > 0) {
                    stdin_offset += static_cast<std::size_t>(w);
                    continue;
                }
                if (w < 0 && errno == EINTR) {
                    continue;
                }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if ((pfds[0].revents & (POLLERR | POLLHUP)) != 0 &&
                        (pfds[0].revents & POLLOUT) == 0) {
                        sigpipe_guard.drain_pending();
                        in_wr.reset();
                    }
                    break;
                }
                sigpipe_guard.drain_pending();
                in_wr.reset();
                break;
            }
            if (stdin_offset >= options.stdin_payload.size()) {
                in_wr.reset();
            }
        }
    }

    int status = 0;
    if (res.timed_out || res.cancelled) {
        // Kill the entire process group (-pid) BEFORE final nonblocking drains & reap so any
        // descendant holding pipe write ends exits while pid still pins the PGID.
        child.kill_process_group();
        if (out_rd.valid()) {
            drain_fd(out_rd, res.stdout_text);
        }
        if (err_rd.valid()) {
            drain_fd(err_rd, res.stderr_text);
        }
        in_wr.reset();
        out_rd.reset();
        err_rd.reset();
        child.terminate_and_reap(status);
        res.exit_code = -1;
        return res;
    }

    in_wr.reset();
    out_rd.reset();
    err_rd.reset();

    while (!child.try_reap_nonblocking(status)) {
        if (options.stop_token.stop_requested()) {
            res.cancelled = true;
            child.terminate_and_reap(status);
            res.exit_code = -1;
            return res;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            child.terminate_and_reap(status);
            res.exit_code = -1;
            return res;
        }
        const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::this_thread::sleep_for(std::min(rem, std::chrono::milliseconds{2}));
    }

    if (WIFEXITED(status)) {
        res.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        res.exit_code = 128 + WTERMSIG(status);
    } else {
        res.exit_code = -1;
    }
    return res;
#endif
}

SubprocessResult run_subprocess_bounded(
    const std::filesystem::path& executable,
    std::span<const std::string> args,
    std::string_view stdin_payload,
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    SubprocessOptions opts{};
    opts.stdin_payload = stdin_payload;
    opts.timeout = timeout;
    opts.stop_token = std::move(stop_token);
    return run_subprocess_bounded(executable, args, opts);
}

} // namespace peelf
