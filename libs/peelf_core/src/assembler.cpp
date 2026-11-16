#include <peelf/assembler.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if PEELF_ASMTK_AVAILABLE
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#endif
#include <asmjit/x86.h>
#include <asmtk/asmtk.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#endif

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
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

[[nodiscard]] std::string trim_ascii(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return std::string(sv);
}

struct SourceLineIndex {
    std::vector<std::size_t> line_starts{};
    std::vector<std::string> lines{};

    explicit SourceLineIndex(std::string_view text) {
        line_starts.push_back(0);
        std::size_t start = 0;
        for (std::size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '\n') {
                std::string_view line = text.substr(start, i - start);
                if (!line.empty() && line.back() == '\r') {
                    line.remove_suffix(1);
                }
                lines.emplace_back(line);
                start = i + 1;
                line_starts.push_back(start);
            }
        }
        std::string_view tail = text.substr(start);
        if (!tail.empty() && tail.back() == '\r') {
            tail.remove_suffix(1);
        }
        lines.emplace_back(tail);
    }

    [[nodiscard]] std::pair<std::uint32_t, std::uint32_t> offset_to_line_col(std::size_t byte_off) const noexcept {
        if (line_starts.empty()) {
            return {1u, 1u};
        }
        const auto it = std::upper_bound(line_starts.begin(), line_starts.end(), byte_off);
        const std::size_t idx = (it == line_starts.begin())
                                    ? 0u
                                    : static_cast<std::size_t>(std::distance(line_starts.begin(), it) - 1);
        const std::size_t col = byte_off >= line_starts[idx] ? (byte_off - line_starts[idx]) : 0u;
        return {static_cast<std::uint32_t>(idx + 1u), static_cast<std::uint32_t>(col + 1u)};
    }

    [[nodiscard]] std::string line_at(std::uint32_t one_based_line) const {
        if (one_based_line == 0 || one_based_line > lines.size()) {
            return {};
        }
        return lines[one_based_line - 1u];
    }
};

// Replaces `; ...`, `// ...`, and `# ...` comments outside quotes with spaces in-place,
// preserving exact byte offsets and newline positions 1:1 for accurate line/column diagnostics.
[[nodiscard]] std::string strip_comments_preserving_offsets(std::string_view src) {
    std::string cleaned(src);
    bool in_single_quote = false;
    bool in_double_quote = false;
    for (std::size_t i = 0; i < cleaned.size(); ++i) {
        const char ch = cleaned[i];
        if (ch == '\n') {
            in_single_quote = false;
            in_double_quote = false;
            continue;
        }
        if (ch == '\'' && !in_double_quote) {
            in_single_quote = !in_single_quote;
            continue;
        }
        if (ch == '"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
            continue;
        }
        if (!in_single_quote && !in_double_quote) {
            const bool semi_or_hash = (ch == ';' || ch == '#');
            const bool slash_slash = (ch == '/' && i + 1 < cleaned.size() && cleaned[i + 1] == '/');
            if (semi_or_hash || slash_slash) {
                while (i < cleaned.size() && cleaned[i] != '\n' && cleaned[i] != '\r') {
                    cleaned[i] = ' ';
                    ++i;
                }
                if (i < cleaned.size() && cleaned[i] == '\r') {
                    continue;
                }
                in_single_quote = false;
                in_double_quote = false;
            }
        }
    }
    return cleaned;
}

[[nodiscard]] bool has_non_whitespace(std::string_view sv) noexcept {
    return std::ranges::any_of(sv, [](unsigned char ch) { return !std::isspace(ch); });
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

// Quote a single argv element per Win32 CommandLineToArgvW rules (used directly with
// CreateProcessW lpApplicationName != nullptr, never via cmd.exe).
[[nodiscard]] std::wstring quote_win32_arg(std::wstring_view arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(arg);
    }
    std::wstring out;
    out.push_back(L'"');
    for (std::size_t i = 0; i < arg.size(); ++i) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (arg[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(arg[i]);
        }
    }
    out.push_back(L'"');
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

    void reset(int next = -1) noexcept {
        if (fd >= 0) {
            (void)::close(fd);
        }
        fd = next;
    }
};

[[nodiscard]] bool make_cloexec_pipe(ScopedFd& rd, ScopedFd& wr) noexcept {
    int raw[2]{-1, -1};
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
        (void)::kill(-pid_, SIGKILL);
        (void)::kill(pid_, SIGKILL);
        reap_blocking(status_out);
    }

private:
    pid_t pid_{-1};
    bool reaped_{false};
};
#endif

} // namespace

SubprocessResult run_argv_process(
    const std::filesystem::path& exe_path,
    std::span<const std::string> args,
    std::string_view stdin_payload,
    std::chrono::milliseconds timeout) {
    SubprocessResult res;
    if (exe_path.empty()) {
        res.launch_error = "empty executable path";
        return res;
    }

    const auto effective_timeout =
        timeout > std::chrono::milliseconds::zero() ? timeout : std::chrono::milliseconds{1};
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

    ::SetHandleInformation(stdin_wr.get(), HANDLE_FLAG_INHERIT, 0);
    ::SetHandleInformation(stdout_rd.get(), HANDLE_FLAG_INHERIT, 0);
    ::SetHandleInformation(stderr_rd.get(), HANDLE_FLAG_INHERIT, 0);

    const std::wstring app_w = exe_path.wstring();
    std::wstring cmdline = quote_win32_arg(app_w);
    for (const std::string& a : args) {
        cmdline.push_back(L' ');
        cmdline += quote_win32_arg(utf8_to_wide(a));
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_rd.get();
    si.hStdOutput = stdout_wr.get();
    si.hStdError = stderr_wr.get();

    PROCESS_INFORMATION pi{};
    const BOOL ok = ::CreateProcessW(
        app_w.c_str(),
        cmdline.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    stdin_rd.reset();
    stdout_wr.reset();
    stderr_wr.reset();

    if (!ok) {
        res.launch_error = "CreateProcessW failed";
        return res;
    }

    ScopedWinProcess child(pi);
    res.launched = true;

    std::jthread stdin_writer([in_handle = std::move(stdin_wr), stdin_payload]() mutable {
        std::size_t offset = 0;
        while (offset < stdin_payload.size()) {
            const std::size_t rem = stdin_payload.size() - offset;
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 65536u));
            DWORD written = 0;
            if (!::WriteFile(in_handle.get(), stdin_payload.data() + offset, chunk, &written, nullptr) ||
                written == 0) {
                break;
            }
            offset += static_cast<std::size_t>(written);
        }
        in_handle.reset();
    });

    auto make_drainer = [](ScopedWinHandle rd_handle, std::string& dst) {
        return std::jthread([h = std::move(rd_handle), &dst]() mutable {
            std::array<char, 8192> buf{};
            DWORD n = 0;
            while (::ReadFile(h.get(), buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr) &&
                   n > 0) {
                dst.append(buf.data(), static_cast<std::size_t>(n));
            }
            h.reset();
        });
    };

    std::jthread stdout_drainer = make_drainer(std::move(stdout_rd), res.stdout_text);
    std::jthread stderr_drainer = make_drainer(std::move(stderr_rd), res.stderr_text);

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            break;
        }
        const auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const DWORD wait_slice = static_cast<DWORD>(
            std::clamp<long long>(rem_ms, 1LL, static_cast<long long>(std::numeric_limits<DWORD>::max() - 1u)));
        const DWORD wait_rc = ::WaitForSingleObject(child.process.get(), wait_slice);
        if (wait_rc == WAIT_OBJECT_0) {
            child.reaped = true;
            break;
        }
        if (wait_rc != WAIT_TIMEOUT) {
            child.reaped = true;
            break;
        }
    }

    if (res.timed_out) {
        (void)::TerminateProcess(child.process.get(), 137u);
        (void)::WaitForSingleObject(child.process.get(), 5000u);
        child.reaped = true;
        if (stdin_writer.joinable()) {
            (void)::CancelSynchronousIo(stdin_writer.native_handle());
        }
        if (stdout_drainer.joinable()) {
            (void)::CancelSynchronousIo(stdout_drainer.native_handle());
        }
        if (stderr_drainer.joinable()) {
            (void)::CancelSynchronousIo(stderr_drainer.native_handle());
        }
    }

    stdin_writer.join();
    stdout_drainer.join();
    stderr_drainer.join();

    if (res.timed_out) {
        res.exit_code = -1;
        return res;
    }

    DWORD exit_code = 1;
    if (::GetExitCodeProcess(child.process.get(), &exit_code)) {
        res.exit_code = static_cast<int>(exit_code);
    }
    return res;
#else
    ScopedFd in_rd, in_wr;
    ScopedFd out_rd, out_wr;
    ScopedFd err_rd, err_wr;
    ScopedFd exec_rd, exec_wr;
    if (!make_cloexec_pipe(in_rd, in_wr) ||
        !make_cloexec_pipe(out_rd, out_wr) ||
        !make_cloexec_pipe(err_rd, err_wr) ||
        !make_cloexec_pipe(exec_rd, exec_wr)) {
        res.launch_error = "pipe() failed";
        return res;
    }

    const std::string exe_str = exe_path.string();
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
        auto bind_std_fd = [](int src_fd, int dst_fd) noexcept -> bool {
            if (src_fd == dst_fd) {
                return ::fcntl(dst_fd, F_SETFD, 0) == 0;
            }
            return ::dup2(src_fd, dst_fd) == dst_fd;
        };
        if (!bind_std_fd(in_rd.get(), STDIN_FILENO) ||
            !bind_std_fd(out_wr.get(), STDOUT_FILENO) ||
            !bind_std_fd(err_wr.get(), STDERR_FILENO)) {
            const int err = errno;
            (void)::write(exec_wr.get(), &err, sizeof(err));
            _exit(127);
        }
        in_rd.reset();
        in_wr.reset();
        out_rd.reset();
        out_wr.reset();
        err_rd.reset();
        err_wr.reset();
        exec_rd.reset();
        // exec_wr remains FD_CLOEXEC so successful execv() signals EOF to parent.
        ::execv(exe_str.c_str(), argv_ptrs.data());
        const int err = errno;
        (void)::write(exec_wr.get(), &err, sizeof(err));
        _exit(127);
    }

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

    ScopedThreadSigpipeGuard sigpipe_guard(in_wr.get());
    if (stdin_payload.empty()) {
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
                dst.append(buf.data(), static_cast<std::size_t>(n));
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
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            break;
        }

        const auto rem_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const int poll_ms = static_cast<int>(
            std::clamp<long long>(rem_ms, 1LL, static_cast<long long>(std::numeric_limits<int>::max())));

        std::array<pollfd, 3> pfds{{
            pollfd{.fd = in_wr.get(), .events = POLLOUT, .revents = 0},
            pollfd{.fd = out_rd.get(), .events = POLLIN, .revents = 0},
            pollfd{.fd = err_rd.get(), .events = POLLIN, .revents = 0},
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

        if (pfds[1].revents != 0 && out_rd.valid()) {
            drain_fd(out_rd, res.stdout_text);
        }
        if (pfds[2].revents != 0 && err_rd.valid()) {
            drain_fd(err_rd, res.stderr_text);
        }
        if (pfds[0].revents != 0 && in_wr.valid()) {
            while (stdin_offset < stdin_payload.size()) {
                const std::size_t chunk =
                    std::min<std::size_t>(stdin_payload.size() - stdin_offset, 65536u);
                const ssize_t w =
                    ::write(in_wr.get(), stdin_payload.data() + stdin_offset, chunk);
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
            if (stdin_offset >= stdin_payload.size()) {
                in_wr.reset();
            }
        }
    }

    in_wr.reset();
    out_rd.reset();
    err_rd.reset();

    int status = 0;
    if (res.timed_out) {
        child.terminate_and_reap(status);
        res.exit_code = -1;
        return res;
    }

    while (!child.try_reap_nonblocking(status)) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            res.timed_out = true;
            child.terminate_and_reap(status);
            res.exit_code = -1;
            return res;
        }
        const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::this_thread::sleep_for(
            std::min(rem, std::chrono::milliseconds{2}));
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

namespace {

[[nodiscard]] bool is_executable_file(const std::filesystem::path& p) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) {
        return false;
    }
#if defined(_WIN32)
    return true;
#else
    return ::access(p.c_str(), X_OK) == 0;
#endif
}

[[nodiscard]] std::filesystem::path discover_llvm_mc_executable(
    const std::filesystem::path& explicit_path) {
    if (!explicit_path.empty()) {
        return is_executable_file(explicit_path) ? explicit_path : std::filesystem::path{};
    }

    if (const char* env_override = std::getenv("PEELF_LLVM_MC");
        env_override != nullptr && *env_override != '\0') {
        const std::filesystem::path p(env_override);
        if (is_executable_file(p)) {
            return p;
        }
    }

#if defined(_WIN32)
    constexpr std::array<std::string_view, 2> candidates{"llvm-mc.exe", "llvm-mc"};
    constexpr char path_sep = ';';
#else
    constexpr std::array<std::string_view, 8> candidates{
        "llvm-mc", "llvm-mc-20", "llvm-mc-19", "llvm-mc-18",
        "llvm-mc-17", "llvm-mc-16", "llvm-mc-15", "llvm-mc-14"};
    constexpr char path_sep = ':';
#endif

    if (const char* path_env = std::getenv("PATH"); path_env != nullptr && *path_env != '\0') {
        const std::string_view sv(path_env);
        std::size_t start = 0;
        while (start <= sv.size()) {
            const std::size_t sep = sv.find(path_sep, start);
            const std::string_view dir_sv =
                sep == std::string_view::npos ? sv.substr(start) : sv.substr(start, sep - start);
            if (!dir_sv.empty()) {
                const std::filesystem::path dir(dir_sv);
                for (std::string_view name : candidates) {
                    const std::filesystem::path cand = dir / name;
                    if (is_executable_file(cand)) {
                        return cand;
                    }
                }
            }
            if (sep == std::string_view::npos) {
                break;
            }
            start = sep + 1u;
        }
    }

#if defined(_WIN32)
    const std::filesystem::path llvm_default = "C:\\Program Files\\LLVM\\bin\\llvm-mc.exe";
    if (is_executable_file(llvm_default)) {
        return llvm_default;
    }
#endif
    return {};
}

[[nodiscard]] std::optional<std::uint8_t> parse_hex_byte_token(std::string_view tok) noexcept {
    tok = std::string_view(tok);
    while (!tok.empty() && std::isspace(static_cast<unsigned char>(tok.front()))) {
        tok.remove_prefix(1);
    }
    while (!tok.empty() && std::isspace(static_cast<unsigned char>(tok.back()))) {
        tok.remove_suffix(1);
    }
    if (tok.starts_with("0x") || tok.starts_with("0X")) {
        tok.remove_prefix(2);
    }
    if (tok.empty() || tok.size() > 2) {
        return std::nullopt;
    }
    unsigned int value = 0;
    for (char ch : tok) {
        value <<= 4u;
        if (ch >= '0' && ch <= '9') {
            value |= static_cast<unsigned int>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            value |= static_cast<unsigned int>(10 + (ch - 'a'));
        } else if (ch >= 'A' && ch <= 'F') {
            value |= static_cast<unsigned int>(10 + (ch - 'A'));
        } else {
            return std::nullopt;
        }
    }
    return static_cast<std::uint8_t>(value);
}

void parse_llvm_mc_diagnostics_text(std::string_view text,
                                    std::vector<AssembleDiagnostic>& out) {
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t nl = text.find('\n', start);
        std::string_view line = nl == std::string_view::npos
                                    ? text.substr(start)
                                    : text.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }

        // Format: <stdin>:LINE:COL: error: MESSAGE   (or warning: MESSAGE)
        const std::size_t err_pos = line.find(": error:");
        const std::size_t warn_pos = line.find(": warning:");
        const std::size_t tag_pos = err_pos != std::string_view::npos ? err_pos : warn_pos;
        if (tag_pos != std::string_view::npos) {
            const bool is_err = (err_pos != std::string_view::npos);
            const std::size_t msg_start = tag_pos + (is_err ? 8u : 10u);
            const std::string msg = trim_ascii(line.substr(msg_start));

            std::uint32_t line_num = 0;
            std::uint32_t col_num = 0;
            const std::string_view prefix = line.substr(0, tag_pos);
            const std::size_t c2 = prefix.rfind(':');
            if (c2 != std::string_view::npos && c2 > 0) {
                const std::size_t c1 = prefix.rfind(':', c2 - 1u);
                if (c1 != std::string_view::npos) {
                    const std::string s_line(prefix.substr(c1 + 1u, c2 - c1 - 1u));
                    const std::string s_col(prefix.substr(c2 + 1u));
                    char* e1 = nullptr;
                    char* e2 = nullptr;
                    const unsigned long lval = std::strtoul(s_line.c_str(), &e1, 10);
                    const unsigned long cval = std::strtoul(s_col.c_str(), &e2, 10);
                    if (e1 && *e1 == '\0' && e2 && *e2 == '\0') {
                        line_num = static_cast<std::uint32_t>(lval);
                        col_num = static_cast<std::uint32_t>(cval);
                    }
                }
            }

            out.push_back(AssembleDiagnostic{
                .line_number = line_num,
                .column_number = col_num,
                .is_error = is_err,
                .message = msg,
                .line_text = {},
            });
        }

        if (nl == std::string_view::npos) {
            break;
        }
        start = nl + 1u;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// AsmTkAssemblerProvider
// ---------------------------------------------------------------------------

SubsystemStatus AsmTkAssemblerProvider::availability() const {
#if PEELF_ASMTK_AVAILABLE
    return SubsystemStatus::available(
        "AsmTK (AsmJit)",
        "In-process x86/x86_64 Intel-syntax assembler enabled");
#else
    return SubsystemStatus::unavailable(
        "AsmTK",
        "Disabled at build time (PEELF_ENABLE_ASMTK=OFF)");
#endif
}

bool AsmTkAssemblerProvider::supports_target(Architecture architecture,
                                             Endianness endianness,
                                             bool is_64bit,
                                             bool thumb_mode) const noexcept {
#if PEELF_ASMTK_AVAILABLE
    if (endianness != Endianness::Little || thumb_mode) {
        return false;
    }
    if (architecture == Architecture::X86 && !is_64bit) {
        return true;
    }
    if (architecture == Architecture::X86_64 && is_64bit) {
        return true;
    }
    return false;
#else
    (void)architecture;
    (void)endianness;
    (void)is_64bit;
    (void)thumb_mode;
    return false;
#endif
}

Result<AssembleOutput> AsmTkAssemblerProvider::assemble(const AssembleRequest& request) const {
#if !PEELF_ASMTK_AVAILABLE
    (void)request;
    return make_error("AsmTK assembler provider is disabled (built with PEELF_ENABLE_ASMTK=OFF)");
#else
    if (!supports_target(request.architecture, request.endianness, request.is_64bit, request.thumb_mode)) {
        return make_error(std::format(
            "AsmTK supports little-endian x86 (32-bit) and x86_64 (64-bit) only (requested {})",
            to_string(request.architecture)));
    }
    if (request.syntax == AssemblySyntax::Att) {
        return make_error("AsmTK parses Intel assembly syntax; switch syntax to Intel/Default or use llvm-mc for AT&T syntax");
    }
    if (!has_non_whitespace(request.source_text)) {
        return make_error("Assembly source text is empty");
    }

    const SourceLineIndex line_index(request.source_text);
    const std::string cleaned = strip_comments_preserving_offsets(request.source_text);
    if (!has_non_whitespace(cleaned)) {
        return make_error("Assembly source contains only comments/whitespace");
    }

    struct CapturingErrorHandler final : public asmjit::ErrorHandler {
        asmjit::Error last_error{asmjit::kErrorOk};
        std::string last_message{};

        void handle_error(asmjit::Error err,
                          const char* message,
                          asmjit::BaseEmitter* /*origin*/) override {
            last_error = err;
            if (message != nullptr) {
                last_message = message;
            }
        }
    };

    const asmjit::Environment env(request.is_64bit ? asmjit::Arch::kX64 : asmjit::Arch::kX86);
    asmjit::CodeHolder code;
    const asmjit::Error init_err = code.init(env, request.base_address);
    if (init_err != asmjit::kErrorOk) {
        return make_error(std::format("AsmJit CodeHolder::init failed: {}",
                                      asmjit::DebugUtils::error_as_string(init_err)));
    }

    CapturingErrorHandler err_handler;
    code.set_error_handler(&err_handler);

    asmjit::x86::Assembler assembler(&code);
    assembler.add_diagnostic_options(asmjit::DiagnosticOptions::kValidateAssembler);
    asmtk::AsmParser parser(&assembler);
    parser.set_input(cleaned.data(), cleaned.size());

    AssembleOutput out;
    out.provider_name = std::string(name());
    out.base_address = request.base_address;

    while (!parser.is_end_of_input()) {
        const std::size_t bytes_before = code.text_section()->buffer_size();
        const asmjit::Error parse_err = parser.parse_command();
        const std::size_t cmd_off = parser.current_command_offset();
        const auto [line_no, col_no] = line_index.offset_to_line_col(cmd_off);
        const std::string src_line = trim_ascii(line_index.line_at(line_no));

        if (parse_err != asmjit::kErrorOk) {
            const std::string detail = !err_handler.last_message.empty()
                                           ? err_handler.last_message
                                           : asmjit::DebugUtils::error_as_string(parse_err);
            return make_error(std::format(
                "Line {}:{}: {} (near '{}')",
                line_no,
                col_no,
                detail,
                src_line));
        }

        const std::size_t bytes_after = code.text_section()->buffer_size();
        if (bytes_after > bytes_before) {
            const std::uint64_t span_off = static_cast<std::uint64_t>(bytes_before);
            const std::uint64_t span_sz = static_cast<std::uint64_t>(bytes_after - bytes_before);
            out.instruction_spans.push_back(AssembledInstructionSpan{
                .line_number = line_no,
                .byte_offset = span_off,
                .byte_size = span_sz,
                .virtual_address = request.base_address + span_off,
                .source_text = src_line,
            });
        }
    }

    if (code.has_unresolved_fixups()) {
        std::string unresolved_names;
        std::uint32_t first_line = 0;
        for (const asmjit::LabelEntry& le : code._label_entries) {
            if (!le.is_bound() && le.has_fixups()) {
                const std::string_view sym_name =
                    (le.has_name() && le.name() != nullptr) ? std::string_view(le.name())
                                                            : std::string_view("<anonymous>");
                if (!unresolved_names.empty()) {
                    unresolved_names += ", ";
                }
                unresolved_names += sym_name;

                if (first_line == 0 && !sym_name.empty() && sym_name != "<anonymous>") {
                    auto is_ident = [](char c) noexcept {
                        const auto uc = static_cast<unsigned char>(c);
                        return std::isalnum(uc) != 0 || c == '_' || c == '.' || c == '$' || c == '@';
                    };
                    std::size_t search_pos = 0;
                    while (search_pos < cleaned.size()) {
                        const std::size_t hit = cleaned.find(sym_name, search_pos);
                        if (hit == std::string::npos) {
                            break;
                        }
                        const bool left_ok = (hit == 0) || !is_ident(cleaned[hit - 1u]);
                        const std::size_t end = hit + sym_name.size();
                        const bool right_ok = (end >= cleaned.size()) || !is_ident(cleaned[end]);
                        if (left_ok && right_ok) {
                            first_line = line_index.offset_to_line_col(hit).first;
                            break;
                        }
                        search_pos = hit + 1u;
                    }
                }
            }
        }
        if (first_line > 0) {
            return make_error(std::format(
                "Line {}: Unresolved label/symbol reference(s): {} (define label locally or use an explicit virtual address)",
                first_line,
                unresolved_names.empty() ? "<unknown>" : unresolved_names));
        }
        return make_error(std::format(
            "Unresolved label/symbol reference(s): {} (define label locally or use an explicit virtual address)",
            unresolved_names.empty() ? "<unknown>" : unresolved_names));
    }

    if (const asmjit::Error flat_err = code.flatten(); flat_err != asmjit::kErrorOk) {
        return make_error(std::format("AsmJit flatten failed: {}",
                                      asmjit::DebugUtils::error_as_string(flat_err)));
    }
    if (const asmjit::Error fix_err = code.resolve_cross_section_fixups(); fix_err != asmjit::kErrorOk) {
        return make_error(std::format("AsmJit fixup resolution failed: {}",
                                      asmjit::DebugUtils::error_as_string(fix_err)));
    }
    if (const asmjit::Error reloc_err = code.relocate_to_base(request.base_address);
        reloc_err != asmjit::kErrorOk) {
        return make_error(std::format(
            "Branch/displacement relocation to base VA {:#x} failed: {}",
            request.base_address,
            asmjit::DebugUtils::error_as_string(reloc_err)));
    }
    if (code._address_table_section != nullptr && code._address_table_section->buffer_size() > 0) {
        return make_error(std::format(
            "Target branch address is out of 32-bit relative displacement range from base VA {:#x}",
            request.base_address));
    }

    const asmjit::CodeBuffer& text_buf = code.text_section()->buffer();
    if (text_buf.size() == 0) {
        return make_error("Assembly produced 0 machine code bytes");
    }
    out.bytes.assign(text_buf.data(), text_buf.data() + text_buf.size());
    return out;
#endif
}

// ---------------------------------------------------------------------------
// llvm-mc helpers & LlvmMcAssemblerProvider
// ---------------------------------------------------------------------------

std::optional<std::string> llvm_mc_triple_for_target(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode) {
    switch (architecture) {
        case Architecture::X86:
            return endianness == Endianness::Little ? std::optional<std::string>("i686-unknown-none-elf")
                                                    : std::nullopt;
        case Architecture::X86_64:
            return endianness == Endianness::Little ? std::optional<std::string>("x86_64-unknown-none-elf")
                                                    : std::nullopt;
        case Architecture::ARM:
            if (thumb_mode) {
                return endianness == Endianness::Big
                           ? std::optional<std::string>("thumbebv7-unknown-none-eabi")
                           : std::optional<std::string>("thumbv7-unknown-none-eabi");
            }
            return endianness == Endianness::Big
                       ? std::optional<std::string>("armebv7-unknown-none-eabi")
                       : std::optional<std::string>("armv7-unknown-none-eabi");
        case Architecture::ARM64:
            return endianness == Endianness::Big
                       ? std::optional<std::string>("aarch64_be-unknown-none-elf")
                       : std::optional<std::string>("aarch64-unknown-none-elf");
        case Architecture::RISCV32:
            return endianness == Endianness::Little ? std::optional<std::string>("riscv32-unknown-none-elf")
                                                    : std::nullopt;
        case Architecture::RISCV64:
            return endianness == Endianness::Little ? std::optional<std::string>("riscv64-unknown-none-elf")
                                                    : std::nullopt;
        case Architecture::PowerPC:
            return endianness == Endianness::Little
                       ? std::optional<std::string>("powerpcle-unknown-none-elf")
                       : std::optional<std::string>("powerpc-unknown-none-elf");
        case Architecture::PowerPC64:
            return endianness == Endianness::Little
                       ? std::optional<std::string>("powerpc64le-unknown-none-elf")
                       : std::optional<std::string>("powerpc64-unknown-none-elf");
        case Architecture::MIPS32:
            return endianness == Endianness::Little
                       ? std::optional<std::string>("mipsel-unknown-none-elf")
                       : std::optional<std::string>("mips-unknown-none-elf");
        case Architecture::MIPS64:
            return endianness == Endianness::Little
                       ? std::optional<std::string>("mips64el-unknown-none-elf")
                       : std::optional<std::string>("mips64-unknown-none-elf");
        case Architecture::Unknown:
            (void)is_64bit;
            return std::nullopt;
    }
    return std::nullopt;
}

Result<AssembleOutput> parse_llvm_mc_show_encoding_output(
    std::string_view stdout_text,
    std::string_view stderr_text,
    std::uint64_t base_address,
    std::string_view provider_name) {
    AssembleOutput out;
    out.provider_name = std::string(provider_name);
    out.base_address = base_address;

    parse_llvm_mc_diagnostics_text(stderr_text, out.diagnostics);
    parse_llvm_mc_diagnostics_text(stdout_text, out.diagnostics);

    for (const AssembleDiagnostic& d : out.diagnostics) {
        if (d.is_error) {
            if (d.line_number > 0) {
                return make_error(std::format("Line {}:{}: {}",
                                              d.line_number, d.column_number, d.message));
            }
            return make_error(d.message);
        }
    }

    std::uint32_t emitted_index = 0;
    std::size_t start = 0;
    while (start <= stdout_text.size()) {
        const std::size_t nl = stdout_text.find('\n', start);
        std::string_view line = nl == std::string_view::npos
                                    ? stdout_text.substr(start)
                                    : stdout_text.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }

        // Detect unresolved symbolic fixup lines emitted by `llvm-mc --show-encoding`, e.g.:
        //   # fixup A - offset: 0, value: external_sym, kind: fixup_...
        const std::size_t fixup_pos = line.find("fixup ");
        if (fixup_pos != std::string_view::npos && line.find("offset:") != std::string_view::npos &&
            line.find("value:") != std::string_view::npos) {
            const std::string fixup_desc = trim_ascii(line.substr(fixup_pos));
            return make_error(std::format(
                "Relocation/external fixup cannot be encoded as a fixed byte patch ({})",
                fixup_desc));
        }

        const std::size_t enc_pos = line.find("encoding:");
        if (enc_pos != std::string_view::npos) {
            const std::size_t lb = line.find('[', enc_pos);
            const std::size_t rb = (lb != std::string_view::npos) ? line.find(']', lb + 1u)
                                                                  : std::string_view::npos;
            if (lb != std::string_view::npos && rb != std::string_view::npos && rb > lb + 1u) {
                const std::uint64_t span_start = static_cast<std::uint64_t>(out.bytes.size());
                const std::string_view list = line.substr(lb + 1u, rb - lb - 1u);
                std::size_t p = 0;
                while (p <= list.size()) {
                    const std::size_t comma = list.find(',', p);
                    const std::string_view tok =
                        comma == std::string_view::npos ? list.substr(p) : list.substr(p, comma - p);
                    const auto parsed_byte = parse_hex_byte_token(tok);
                    if (!parsed_byte.has_value()) {
                        return make_error(std::format(
                            "Symbolic or non-constant byte '{}' in llvm-mc encoding cannot be emitted without relocation",
                            trim_ascii(tok)));
                    }
                    out.bytes.push_back(*parsed_byte);
                    if (comma == std::string_view::npos) {
                        break;
                    }
                    p = comma + 1u;
                }

                // Extract instruction text before comment marker (`#`, `//`, `@`, `;`)
                std::string_view insn_part = line.substr(0, enc_pos);
                while (!insn_part.empty() &&
                       (std::isspace(static_cast<unsigned char>(insn_part.back())) ||
                        insn_part.back() == '#' || insn_part.back() == '/' ||
                        insn_part.back() == '@' || insn_part.back() == ';')) {
                    insn_part.remove_suffix(1);
                }
                ++emitted_index;
                const std::uint64_t span_sz = static_cast<std::uint64_t>(out.bytes.size()) - span_start;
                if (span_sz > 0) {
                    out.instruction_spans.push_back(AssembledInstructionSpan{
                        .line_number = emitted_index,
                        .byte_offset = span_start,
                        .byte_size = span_sz,
                        .virtual_address = base_address + span_start,
                        .source_text = trim_ascii(insn_part),
                    });
                }
            }
        }

        if (nl == std::string_view::npos) {
            break;
        }
        start = nl + 1u;
    }

    if (out.bytes.empty()) {
        const std::string err_trimmed = trim_ascii(stderr_text);
        if (!err_trimmed.empty()) {
            return make_error(err_trimmed);
        }
        return make_error("llvm-mc produced 0 encoded instruction bytes");
    }
    return out;
}

LlvmMcAssemblerProvider::LlvmMcAssemblerProvider(std::filesystem::path explicit_llvm_mc_path) {
    llvm_mc_path_ = discover_llvm_mc_executable(explicit_llvm_mc_path);
    if (llvm_mc_path_.empty()) {
        if (!explicit_llvm_mc_path.empty()) {
            status_ = SubsystemStatus::unavailable(
                "llvm-mc",
                std::format("Configured llvm-mc path '{}' was not found or is not executable",
                            explicit_llvm_mc_path.string()));
        } else {
            status_ = SubsystemStatus::unavailable(
                "llvm-mc",
                "llvm-mc executable not found on PATH (install LLVM tools or set PEELF_LLVM_MC for ARM/AArch64/RISC-V/MIPS/PowerPC assembly)");
        }
        return;
    }

    const std::array<std::string, 1> ver_args{"--version"};
    const SubprocessResult probe =
        run_argv_process(llvm_mc_path_, ver_args, {}, std::chrono::milliseconds{5000});
    if (!probe.launched || probe.timed_out || probe.exit_code != 0) {
        status_ = SubsystemStatus::unavailable(
            "llvm-mc",
            std::format("Failed to run '{} --version': {}",
                        llvm_mc_path_.string(),
                        probe.timed_out ? "process timed out"
                        : (!probe.launch_error.empty() ? probe.launch_error
                                                       : trim_ascii(probe.stderr_text))));
        llvm_mc_path_.clear();
        return;
    }

    std::string first_line = trim_ascii(probe.stdout_text);
    if (const std::size_t nl = first_line.find('\n'); nl != std::string::npos) {
        first_line = trim_ascii(std::string_view(first_line).substr(0, nl));
    }
    status_ = SubsystemStatus::available(
        llvm_mc_path_.string(),
        first_line.empty() ? "External multi-arch llvm-mc assembler ready" : first_line);
}

SubsystemStatus LlvmMcAssemblerProvider::availability() const {
    return status_;
}

bool LlvmMcAssemblerProvider::supports_target(Architecture architecture,
                                              Endianness endianness,
                                              bool is_64bit,
                                              bool thumb_mode) const noexcept {
    return llvm_mc_triple_for_target(architecture, endianness, is_64bit, thumb_mode).has_value();
}

Result<AssembleOutput> LlvmMcAssemblerProvider::assemble(const AssembleRequest& request) const {
    const auto triple = llvm_mc_triple_for_target(
        request.architecture, request.endianness, request.is_64bit, request.thumb_mode);
    if (!triple.has_value()) {
        return make_error(std::format(
            "Target architecture {} ({}) is not supported by llvm-mc adapter",
            to_string(request.architecture),
            request.endianness == Endianness::Big ? "big-endian" : "little-endian"));
    }
    if (!status_.ok() || llvm_mc_path_.empty()) {
        return make_error(std::format(
            "Assembler is not available for architecture {}: {}",
            to_string(request.architecture),
            status_.detail));
    }
    if (!has_non_whitespace(request.source_text)) {
        return make_error("Assembly source text is empty");
    }

    std::vector<std::string> args;
    args.push_back("--triple=" + *triple);
    args.push_back("--show-encoding");
    if (request.architecture == Architecture::X86 || request.architecture == Architecture::X86_64) {
        args.push_back(request.syntax == AssemblySyntax::Att
                           ? "--x86-asm-syntax=att"
                           : "--x86-asm-syntax=intel");
    }

    std::string payload = request.source_text;
    if (!payload.ends_with('\n')) {
        payload.push_back('\n');
    }

    const SubprocessResult run = run_argv_process(llvm_mc_path_, args, payload);
    if (!run.launched) {
        return make_error(std::format("Failed to invoke llvm-mc: {}", run.launch_error));
    }
    if (run.timed_out) {
        return make_error("llvm-mc timed out while assembling input");
    }
    if (run.exit_code != 0) {
        auto parsed_err = parse_llvm_mc_show_encoding_output(
            run.stdout_text, run.stderr_text, request.base_address, name());
        if (!parsed_err.has_value()) {
            return parsed_err;
        }
        return make_error(std::format("llvm-mc exited with status {}: {}",
                                      run.exit_code,
                                      trim_ascii(run.stderr_text)));
    }
    return parse_llvm_mc_show_encoding_output(
        run.stdout_text, run.stderr_text, request.base_address, name());
}

// ---------------------------------------------------------------------------
// AssemblerRegistry & facade
// ---------------------------------------------------------------------------

AssemblerRegistry::AssemblerRegistry() {
    providers_.push_back(std::make_shared<AsmTkAssemblerProvider>());
    providers_.push_back(std::make_shared<LlvmMcAssemblerProvider>());
}

AssemblerRegistry::AssemblerRegistry(std::vector<std::shared_ptr<IAssemblerProvider>> providers)
    : providers_(std::move(providers)) {}

void AssemblerRegistry::register_provider(std::shared_ptr<IAssemblerProvider> provider) {
    if (provider) {
        providers_.push_back(std::move(provider));
    }
}

const IAssemblerProvider* AssemblerRegistry::select_provider(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode) const noexcept {
    for (const auto& provider : providers_) {
        if (provider &&
            provider->supports_target(architecture, endianness, is_64bit, thumb_mode) &&
            provider->availability().ok()) {
            return provider.get();
        }
    }
    return nullptr;
}

SubsystemStatus AssemblerRegistry::target_status(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode) const {
    if (const IAssemblerProvider* active =
            select_provider(architecture, endianness, is_64bit, thumb_mode)) {
        const SubsystemStatus st = active->availability();
        return SubsystemStatus::available(
            std::string(active->name()),
            st.detail);
    }

    std::string reasons;
    for (const auto& provider : providers_) {
        if (provider && provider->supports_target(architecture, endianness, is_64bit, thumb_mode)) {
            const SubsystemStatus st = provider->availability();
            if (!reasons.empty()) {
                reasons += "; ";
            }
            reasons += std::format("{}: {}", provider->name(), st.detail);
        }
    }
    if (reasons.empty()) {
        reasons = std::format("No registered assembler provider supports {} ({})",
                              to_string(architecture),
                              endianness == Endianness::Big ? "BE" : "LE");
    }
    return SubsystemStatus::unavailable(
        "AssemblerRegistry",
        std::format("Assembler is not available for architecture {} ({})",
                    to_string(architecture),
                    reasons));
}

Result<AssembleOutput> AssemblerRegistry::assemble(const AssembleRequest& request) const {
    // Prefer a syntax-compatible available provider (e.g. AT&T x86 falls back to llvm-mc if installed).
    for (const auto& provider : providers_) {
        if (!provider ||
            !provider->supports_target(request.architecture, request.endianness,
                                       request.is_64bit, request.thumb_mode) ||
            !provider->availability().ok()) {
            continue;
        }
        if (request.syntax == AssemblySyntax::Att && provider->name() == "AsmTK") {
            continue;
        }
        return provider->assemble(request);
    }

    const SubsystemStatus st = target_status(
        request.architecture, request.endianness, request.is_64bit, request.thumb_mode);
    if (request.syntax == AssemblySyntax::Att) {
        if (const IAssemblerProvider* asmtk =
                select_provider(request.architecture, request.endianness,
                                request.is_64bit, request.thumb_mode)) {
            return asmtk->assemble(request);
        }
    }
    return make_error(st.detail);
}

const AssemblerRegistry& default_assembler_registry() {
    static const AssemblerRegistry instance{};
    return instance;
}

Result<AssembleOutput> assemble_instructions(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode,
    std::uint64_t base_va,
    std::string_view asm_text,
    AssemblySyntax syntax) {
    AssembleRequest req;
    req.architecture = architecture;
    req.endianness = endianness;
    req.is_64bit = is_64bit;
    req.thumb_mode = thumb_mode;
    req.syntax = syntax;
    req.base_address = base_va;
    req.source_text = std::string(asm_text);
    return default_assembler_registry().assemble(req);
}

} // namespace peelf
