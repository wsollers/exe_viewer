#include <gtest/gtest.h>

#include "graph/call_graph.hpp"

#include <peelf/debugger.hpp>
#include <peelf/process.hpp>
#include <peelf/subprocess.hpp>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#endif

namespace {

// Exact reference implementation of Win32 / MSVC CRT argument parsing rules (post-argv[0])
// used to verify round-trip fidelity of peelf::quote_windows_arg across arbitrary inputs.
[[nodiscard]] std::vector<std::string> parse_windows_args_reference(std::string_view cmdline) {
    std::vector<std::string> args;
    std::size_t i = 0;
    while (i < cmdline.size()) {
        while (i < cmdline.size() && (cmdline[i] == ' ' || cmdline[i] == '\t')) {
            ++i;
        }
        if (i >= cmdline.size()) {
            break;
        }

        std::string cur;
        bool in_quotes = false;
        while (i < cmdline.size()) {
            std::size_t backslashes = 0;
            while (i < cmdline.size() && cmdline[i] == '\\') {
                ++backslashes;
                ++i;
            }
            if (i < cmdline.size() && cmdline[i] == '"') {
                cur.append(backslashes / 2u, '\\');
                if ((backslashes % 2u) == 0u) {
                    if (in_quotes && (i + 1u) < cmdline.size() && cmdline[i + 1u] == '"') {
                        cur.push_back('"');
                        ++i;
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    cur.push_back('"');
                }
                ++i;
                continue;
            }
            cur.append(backslashes, '\\');
            if (i >= cmdline.size()) {
                break;
            }
            if (!in_quotes && (cmdline[i] == ' ' || cmdline[i] == '\t')) {
                break;
            }
            cur.push_back(cmdline[i]);
            ++i;
        }
        args.push_back(std::move(cur));
    }
    return args;
}

TEST(SubprocessQuoteTest, OrdinaryPathsAndUncPathsNeverDoubleBackslashes) {
    EXPECT_EQ(peelf::quote_windows_arg(R"(C:\tools\dot.exe)"), R"(C:\tools\dot.exe)");
    EXPECT_EQ(peelf::quote_windows_arg(R"(\\server\share\tools\dot.exe)"),
              R"(\\server\share\tools\dot.exe)");
    EXPECT_EQ(peelf::quote_windows_arg(R"(C:\trailing\)"), R"(C:\trailing\)");
    EXPECT_EQ(peelf::quote_windows_arg("-Tsvg"), "-Tsvg");
}

TEST(SubprocessQuoteTest, SpacesEmbeddedQuotesUncAndTrailingBackslashesFollowCommandLineToArgvW) {
    EXPECT_EQ(peelf::quote_windows_arg(""), "\"\"");

    struct QuoteCase {
        std::string_view input;
        std::string_view expected;
    };
    constexpr std::array<QuoteCase, 6> kCases{{
        // Ordinary path separators inside a quoted path with spaces must NOT be doubled.
        {R"(C:\Program Files\Graphviz\bin\dot.exe)",
         R"("C:\Program Files\Graphviz\bin\dot.exe")"},
        // UNC prefix inside a quoted path with spaces must remain \\ (not \\\\).
        {R"(\\server\share name\Graphviz\dot.exe)",
         R"("\\server\share name\Graphviz\dot.exe")"},
        // Trailing backslashes immediately before the closing quote MUST be doubled.
        {R"(C:\Program Files\Graphviz\)",
         R"("C:\Program Files\Graphviz\\")"},
        {R"(C:\Program Files\Graphviz\\)",
         R"("C:\Program Files\Graphviz\\\\")"},
        // Embedded quotes and backslashes immediately preceding embedded quotes.
        {R"(label="main")", R"("label=\"main\"")"},
        {R"(C:\dir\"quoted"\file)", R"("C:\dir\\\"quoted\"\file")"},
    }};
    for (const auto& tc : kCases) {
        EXPECT_EQ(peelf::quote_windows_arg(tc.input), tc.expected);
    }

    const std::vector<std::string> vectors = {
        "",
        R"(C:\tools\dot.exe)",
        R"(C:\Program Files\Graphviz\bin\dot.exe)",
        R"(\\server\share\dot.exe)",
        R"(\\server\share with spaces\sub\dot.exe)",
        R"(C:\trailing\)",
        R"(C:\trailing with space\)",
        R"(C:\trailing two\\)",
        R"(arg with "quotes" and \"escaped\" quotes\)",
        "tab\there",
        "newline\nhere",
        R"(\\\"\\\")",
    };

    std::string cmdline;
    for (std::size_t i = 0; i < vectors.size(); ++i) {
        if (i > 0u) {
            cmdline.push_back(' ');
        }
        cmdline += peelf::quote_windows_arg(vectors[i]);
    }
    const std::vector<std::string> parsed = parse_windows_args_reference(cmdline);
    ASSERT_EQ(parsed.size(), vectors.size());
    for (std::size_t i = 0; i < vectors.size(); ++i) {
        EXPECT_EQ(parsed[i], vectors[i]) << "Mismatch at index " << i;
    }
}

TEST(SubprocessRunnerTest, GrandchildHoldingPipesRespectsDeadlineWithoutHanging) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const std::array<std::string, 1> args{"spawn-grandchild-hold"};
    const auto t0 = std::chrono::steady_clock::now();
    const peelf::SubprocessResult res = peelf::run_subprocess_bounded(
        fixture, args, "", std::chrono::milliseconds{250});
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();

    EXPECT_TRUE(res.launched);
    EXPECT_TRUE(res.timed_out);
    EXPECT_FALSE(res.cancelled);
    EXPECT_EQ(res.exit_code, -1);
    EXPECT_EQ(res.stdout_text, "parent-done");
    EXPECT_EQ(res.stderr_text, "parent-err");
    // Grandchild sleeps for 30,000 ms; bounded runner must return promptly near the 250 ms deadline.
    EXPECT_LT(elapsed_ms, 4000);
}

TEST(SubprocessRunnerTest, StopTokenCancelsRunningChildPromptly) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    std::stop_source stop_src;
    std::jthread canceller([&stop_src]() {
        std::this_thread::sleep_for(std::chrono::milliseconds{120});
        stop_src.request_stop();
    });

    const std::array<std::string, 1> args{"sleep"};
    const auto t0 = std::chrono::steady_clock::now();
    const peelf::SubprocessResult res = peelf::run_subprocess_bounded(
        fixture, args, "", std::chrono::milliseconds{15000}, stop_src.get_token());
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();

    EXPECT_TRUE(res.launched);
    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.exit_code, -1);
    EXPECT_LT(elapsed_ms, 4000);
}

TEST(SubprocessRunnerTest, DefaultProcessRunnerEnforcesTimeoutAndExecutesWithoutShell) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    {
        const viewer::DefaultProcessRunner bounded_runner(std::chrono::milliseconds{200});
        const std::array<std::string, 1> hang_args{"spawn-grandchild-hold"};
        const auto t0 = std::chrono::steady_clock::now();
        const viewer::GraphRenderResult r = bounded_runner.run(fixture.string(), hang_args);
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - t0)
                                    .count();
        EXPECT_FALSE(r.success);
        EXPECT_EQ(r.exit_code, -1);
        EXPECT_NE(r.diagnostic.find("timed out"), std::string::npos);
        EXPECT_LT(elapsed_ms, 4000);
    }

    {
        // Pass shell metacharacters in argv[2] to prove zero shell interpolation occurs.
        const viewer::DefaultProcessRunner runner(std::chrono::milliseconds{5000});
        const std::string literal_arg = "literal; $( disallowed ) & | `raw`";
        const std::array<std::string, 2> echo_args{"echo-stdio", literal_arg};
        const viewer::GraphRenderResult r = runner.run(fixture.string(), echo_args);
        EXPECT_TRUE(r.success) << r.diagnostic;
        EXPECT_EQ(r.exit_code, 0);
    }
}

TEST(SubprocessRunnerTest, ClampsMaxMillisecondsTimeoutWithoutOverflow) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    {
        const std::array<std::string, 2> args{"echo-stdio", "err-ok"};
        const peelf::SubprocessResult res = peelf::run_subprocess_bounded(
            fixture, args, "in-ok", std::chrono::milliseconds::max());
        EXPECT_TRUE(res.launched);
        EXPECT_FALSE(res.timed_out);
        EXPECT_FALSE(res.cancelled);
        EXPECT_EQ(res.exit_code, 0);
        EXPECT_EQ(res.stdout_text, "OUT:in-ok");
        EXPECT_EQ(res.stderr_text, "ERR:err-ok");
    }

    {
        std::stop_source stop_src;
        std::jthread canceller([&stop_src]() {
            std::this_thread::sleep_for(std::chrono::milliseconds{80});
            stop_src.request_stop();
        });
        const std::array<std::string, 1> args{"sleep"};
        const auto t0 = std::chrono::steady_clock::now();
        const peelf::SubprocessResult res = peelf::run_subprocess_bounded(
            fixture, args, "", std::chrono::milliseconds::max(), stop_src.get_token());
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - t0)
                                    .count();
        EXPECT_TRUE(res.launched);
        EXPECT_TRUE(res.cancelled);
        EXPECT_EQ(res.exit_code, -1);
        EXPECT_LT(elapsed_ms, 4000);
    }
}

TEST(SubprocessRunnerTest, ContinuousStdoutFloodRespectsDeadline) {
    peelf::SubprocessOptions opts{};
    opts.timeout = std::chrono::milliseconds{200};
    opts.search_path = true;
    opts.max_output_bytes = 64u * 1024u;

#if defined(_WIN32)
    const std::filesystem::path exe{"cmd.exe"};
    const std::array<std::string, 2> args{
        "/c", "for /L %i in (1,0,2) do @echo continuous_stdout_flood_0123456789abcdef"};
#else
    const std::filesystem::path exe{"yes"};
    const std::array<std::string, 1> args{"continuous_stdout_flood_0123456789abcdef"};
#endif

    const auto t0 = std::chrono::steady_clock::now();
    const peelf::SubprocessResult res = peelf::run_subprocess_bounded(exe, args, opts);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();

    if (!res.launched) {
        GTEST_SKIP() << "stream generator unavailable in PATH: " << res.launch_error;
    }
    EXPECT_TRUE(res.timed_out);
    EXPECT_FALSE(res.cancelled);
    EXPECT_EQ(res.exit_code, -1);
    EXPECT_FALSE(res.stdout_text.empty());
    EXPECT_LE(res.stdout_text.size(), opts.max_output_bytes);
    EXPECT_LT(elapsed_ms, 4000);
}

#if !defined(_WIN32)
TEST(PosixChildStdioTest, WaitpidEchildFailurePropagatesExplicitErrorInsteadOfZeroExit) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const pid_t helper = ::fork();
    ASSERT_GE(helper, 0);
    if (helper == 0) {
        struct sigaction sa{};
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_NOCLDWAIT;
        sigemptyset(&sa.sa_mask);
        if (::sigaction(SIGCHLD, &sa, nullptr) != 0) {
            _exit(30);
        }

        const std::array<std::string, 1> args{"early-exit"};
        const peelf::SubprocessResult sub = peelf::run_subprocess_bounded(
            fixture, args, "", std::chrono::milliseconds{5000});
        if (sub.exit_code == 0 || sub.exit_code != -1 ||
            sub.launch_error.find("waitpid") == std::string::npos) {
            _exit(31);
        }
        _exit(0);
    }

    int wstatus = 0;
    ASSERT_EQ(::waitpid(helper, &wstatus, 0), helper);
    ASSERT_TRUE(WIFEXITED(wstatus));
    EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

TEST(PosixChildStdioTest, PreservesPreExistingPendingSigpipeAcrossBrokenStdinWrite) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const pid_t helper = ::fork();
    ASSERT_GE(helper, 0);
    if (helper == 0) {
        sigset_t set{};
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        if (::pthread_sigmask(SIG_BLOCK, &set, nullptr) != 0) {
            _exit(40);
        }
        if (::kill(::getpid(), SIGPIPE) != 0) {
            _exit(41);
        }

        sigset_t pend{};
        sigemptyset(&pend);
        if (::sigpending(&pend) != 0 || ::sigismember(&pend, SIGPIPE) != 1) {
            _exit(42);
        }

        const std::string big_stdin(1024u * 1024u, 'S');
        const std::array<std::string, 1> args{"early-exit"};
        const peelf::SubprocessResult sub = peelf::run_subprocess_bounded(
            fixture, args, big_stdin, std::chrono::milliseconds{5000});
        if (!sub.launched || sub.exit_code != 42) {
            _exit(43);
        }

        sigemptyset(&pend);
        if (::sigpending(&pend) != 0 || ::sigismember(&pend, SIGPIPE) != 1) {
            _exit(44);
        }

        int sig = 0;
        (void)::sigwait(&set, &sig);
        _exit(0);
    }

    int wstatus = 0;
    ASSERT_EQ(::waitpid(helper, &wstatus, 0), helper);
    ASSERT_TRUE(WIFEXITED(wstatus));
    EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

TEST(PosixChildStdioTest, PrepareChildStdioSafelyRelocatesScrambledLowDescriptors) {
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);

    if (child == 0) {
        // Close 0, 1, 2 in the isolated forked child so subsequent pipe() calls allocate FDs 0..2.
        (void)::close(STDIN_FILENO);
        (void)::close(STDOUT_FILENO);
        (void)::close(STDERR_FILENO);

        int out_pipe[2]{-1, -1};
        int err_pipe[2]{-1, -1};
        int in_pipe[2]{-1, -1};
        int exec_pipe[2]{-1, -1};
        if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0 || ::pipe(in_pipe) != 0 ||
            ::pipe(exec_pipe) != 0) {
            _exit(2);
        }

        // Deliberately scramble child pipe ends inside 0..2:
        // out_wr -> 0, err_wr -> 1, in_rd -> 2, exec_wr -> 3!
        int out_wr = out_pipe[1];
        int err_wr = err_pipe[1];
        int in_rd = in_pipe[0];
        int exec_wr = exec_pipe[1];

        // Force exact scrambled slots 0, 1, 2, 3 via F_DUPFD >= 10 then dup2 into 0..3.
        const int p_in_wr = ::fcntl(in_pipe[1], F_DUPFD, 10);
        const int p_out_rd = ::fcntl(out_pipe[0], F_DUPFD, 10);
        const int p_err_rd = ::fcntl(err_pipe[0], F_DUPFD, 10);
        const int p_exec_rd = ::fcntl(exec_pipe[0], F_DUPFD, 10);
        const int tmp_out_wr = ::fcntl(out_wr, F_DUPFD, 10);
        const int tmp_err_wr = ::fcntl(err_wr, F_DUPFD, 10);
        const int tmp_in_rd = ::fcntl(in_rd, F_DUPFD, 10);
        const int tmp_exec_wr = ::fcntl(exec_wr, F_DUPFD, 10);
        for (int fd : {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1],
                       in_pipe[0], in_pipe[1], exec_pipe[0], exec_pipe[1]}) {
            (void)::close(fd);
        }

        if (::dup2(tmp_out_wr, 0) != 0 || ::dup2(tmp_err_wr, 1) != 1 ||
            ::dup2(tmp_in_rd, 2) != 2 || ::dup2(tmp_exec_wr, 3) != 3) {
            _exit(3);
        }
        (void)::fcntl(3, F_SETFD, FD_CLOEXEC);
        for (int fd : {tmp_out_wr, tmp_err_wr, tmp_in_rd, tmp_exec_wr}) {
            (void)::close(fd);
        }

        out_wr = 0;
        err_wr = 1;
        in_rd = 2;
        exec_wr = 3;

        if (!peelf::detail::prepare_posix_child_stdio(in_rd, out_wr, err_wr, exec_wr)) {
            _exit(4);
        }
        if (in_rd != STDIN_FILENO || out_wr != STDOUT_FILENO || err_wr != STDERR_FILENO ||
            exec_wr < 3) {
            _exit(5);
        }
        const int exec_flags = ::fcntl(exec_wr, F_GETFD);
        if (exec_flags < 0 || (exec_flags & FD_CLOEXEC) == 0) {
            _exit(6);
        }

        if (::write(p_in_wr, "IN_OK", 5) != 5) {
            _exit(7);
        }
        (void)::close(p_in_wr);

        char in_buf[8]{};
        if (::read(STDIN_FILENO, in_buf, sizeof(in_buf)) != 5 ||
            std::string_view(in_buf, 5) != "IN_OK") {
            _exit(8);
        }
        if (::write(STDOUT_FILENO, "OUT_OK", 6) != 6 ||
            ::write(STDERR_FILENO, "ERR_OK", 6) != 6 ||
            ::write(exec_wr, "EX_OK", 5) != 5) {
            _exit(9);
        }

        char out_buf[8]{};
        char err_buf[8]{};
        char ex_buf[8]{};
        if (::read(p_out_rd, out_buf, sizeof(out_buf)) != 6 ||
            std::string_view(out_buf, 6) != "OUT_OK") {
            _exit(10);
        }
        if (::read(p_err_rd, err_buf, sizeof(err_buf)) != 6 ||
            std::string_view(err_buf, 6) != "ERR_OK") {
            _exit(11);
        }
        if (::read(p_exec_rd, ex_buf, sizeof(ex_buf)) != 5 ||
            std::string_view(ex_buf, 5) != "EX_OK") {
            _exit(12);
        }
        _exit(0);
    }

    int wstatus = 0;
    ASSERT_EQ(::waitpid(child, &wstatus, 0), child);
    ASSERT_TRUE(WIFEXITED(wstatus));
    EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

TEST(PosixChildStdioTest, RunSubprocessBoundedWorksWhenParentStdioDescriptorsAreClosed) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const pid_t helper = ::fork();
    ASSERT_GE(helper, 0);

    if (helper == 0) {
        (void)::close(STDIN_FILENO);
        (void)::close(STDOUT_FILENO);
        (void)::close(STDERR_FILENO);

        const std::array<std::string, 2> args{"echo-stdio", "stderr-tag"};
        const peelf::SubprocessResult sub = peelf::run_subprocess_bounded(
            fixture, args, "stdin-tag", std::chrono::milliseconds{5000});
        if (!sub.launched || sub.timed_out || sub.exit_code != 0 ||
            sub.stdout_text != "OUT:stdin-tag" || sub.stderr_text != "ERR:stderr-tag") {
            _exit(20);
        }
        _exit(0);
    }

    int wstatus = 0;
    ASSERT_EQ(::waitpid(helper, &wstatus, 0), helper);
    ASSERT_TRUE(WIFEXITED(wstatus));
    EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}
#endif

#if defined(__linux__)
struct ScopedReapChild {
    explicit ScopedReapChild(pid_t child_pid) noexcept : pid(child_pid) {}
    ScopedReapChild(const ScopedReapChild&) = delete;
    ScopedReapChild& operator=(const ScopedReapChild&) = delete;
    ScopedReapChild(ScopedReapChild&&) = delete;
    ScopedReapChild& operator=(ScopedReapChild&&) = delete;
    ~ScopedReapChild() noexcept {
        if (pid > 0) {
            (void)::kill(pid, SIGKILL);
            int st = 0;
            (void)::waitpid(pid, &st, 0);
        }
    }

    pid_t pid{-1};
};

TEST(ProcessResumeFailureTest, RetainsFailedThreadInSuspendedSetAndClearsOnRetry) {
    int ready_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(ready_pipe), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        (void)::close(ready_pipe[0]);
#if defined(PR_SET_PTRACER)
        (void)::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
        std::atomic<pid_t> worker_tid{0};
        std::thread worker([&worker_tid]() {
            worker_tid.store(static_cast<pid_t>(::syscall(SYS_gettid)), std::memory_order_release);
            std::this_thread::sleep_for(std::chrono::seconds(30));
        });
        while (worker_tid.load(std::memory_order_acquire) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const pid_t wt = worker_tid.load(std::memory_order_acquire);
        (void)::write(ready_pipe[1], &wt, sizeof(wt));
        (void)::close(ready_pipe[1]);
        worker.join();
        _exit(0);
    }

    ScopedReapChild guard{child};
    (void)::close(ready_pipe[1]);

    pid_t raw_worker_tid = 0;
    ASSERT_EQ(::read(ready_pipe[0], &raw_worker_tid, sizeof(raw_worker_tid)),
              static_cast<ssize_t>(sizeof(raw_worker_tid)));
    (void)::close(ready_pipe[0]);

    const auto leader_tid = static_cast<peelf::ThreadId>(child);
    const auto worker_tid = static_cast<peelf::ThreadId>(raw_worker_tid);

    auto backend = peelf::create_native_process_backend();
    auto opened = backend->open_process(static_cast<peelf::ProcessId>(child));
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::IProcessSession& session = **opened;

    // Check whether ptrace seize is permitted in this environment (vs SIGSTOP fallback).
    bool ptrace_permitted = false;
    if (::ptrace(PTRACE_SEIZE, static_cast<pid_t>(leader_tid), nullptr, nullptr) == 0) {
        ptrace_permitted = true;
        if (::ptrace(PTRACE_INTERRUPT, static_cast<pid_t>(leader_tid), nullptr, nullptr) == 0) {
            int probe_status = 0;
            while (::waitpid(static_cast<pid_t>(leader_tid), &probe_status, __WALL) < 0 &&
                   errno == EINTR) {
            }
        }
        EXPECT_EQ(::ptrace(PTRACE_DETACH, static_cast<pid_t>(leader_tid), nullptr, nullptr), 0);
    }
    if (!ptrace_permitted) {
        // Still verify clean suspend + resume round-trip under SIGSTOP fallback.
        ASSERT_TRUE(session.suspend().has_value());
        EXPECT_TRUE(session.is_suspended());
        ASSERT_TRUE(session.resume().has_value());
        EXPECT_FALSE(session.is_suspended());
        return;
    }

    // Seize worker_tid on a dedicated helper OS thread (Linux binds ptrace ownership per tracer TID),
    // then call session.suspend() on the main thread so leader_tid is seized by main thread.
    std::atomic<int> phase{0};
    peelf::Result<void> aux_suspend_res{};
    peelf::Result<void> aux_retry_resume_res{};

    std::jthread aux_tracer([&](std::stop_token st) {
        aux_suspend_res = session.suspend_thread(worker_tid);
        phase.store(1, std::memory_order_release);
        while (!st.stop_requested() && phase.load(std::memory_order_acquire) < 2) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        aux_retry_resume_res = session.resume();
        phase.store(3, std::memory_order_release);
    });

    struct ScopedAuxTracerCleanup {
        ScopedAuxTracerCleanup(std::jthread& t, std::atomic<int>& p) noexcept
            : tracer(t), phase_ref(p) {}
        ScopedAuxTracerCleanup(const ScopedAuxTracerCleanup&) = delete;
        ScopedAuxTracerCleanup& operator=(const ScopedAuxTracerCleanup&) = delete;
        ScopedAuxTracerCleanup(ScopedAuxTracerCleanup&&) = delete;
        ScopedAuxTracerCleanup& operator=(ScopedAuxTracerCleanup&&) = delete;
        ~ScopedAuxTracerCleanup() noexcept {
            phase_ref.store(2, std::memory_order_release);
            tracer.request_stop();
            if (tracer.joinable()) {
                tracer.join();
            }
        }

        std::jthread& tracer;
        std::atomic<int>& phase_ref;
    } aux_cleanup{aux_tracer, phase};

    while (phase.load(std::memory_order_acquire) < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(aux_suspend_res.has_value()) << aux_suspend_res.error().message;

    auto full_suspend = session.suspend();
    ASSERT_TRUE(full_suspend.has_value()) << full_suspend.error().message;
    EXPECT_TRUE(session.is_suspended());

    // Calling resume() on main thread detaches leader_tid cleanly, but MUST fail on worker_tid
    // (owned by aux_tracer), retain worker_tid in suspended_tids_, keep is_suspended() == true,
    // and return an explicit Error naming worker_tid!
    auto partial_resume = session.resume();
    EXPECT_FALSE(partial_resume.has_value());
    EXPECT_TRUE(session.is_suspended());
    if (!partial_resume.has_value()) {
        EXPECT_NE(partial_resume.error().message.find(std::to_string(worker_tid)),
                  std::string::npos);
        EXPECT_EQ(partial_resume.error().message.find(std::to_string(leader_tid)),
                  std::string::npos);
    }

    // Retrying resume() from aux_tracer detaches the retained worker_tid and clears suspended_!
    phase.store(2, std::memory_order_release);
    while (phase.load(std::memory_order_acquire) < 3) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(aux_retry_resume_res.has_value())
        << (aux_retry_resume_res.has_value() ? "" : aux_retry_resume_res.error().message);
    EXPECT_FALSE(session.is_suspended());
}

#if defined(__x86_64__)
TEST(DebuggerDetachFailureTest, SurfacesBreakpointRestoreFailureAndPreservesAttachedState) {
    int addr_pipe[2]{-1, -1};
    int go_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(addr_pipe), 0);
    ASSERT_EQ(::pipe(go_pipe), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        (void)::close(addr_pipe[0]);
        (void)::close(go_pipe[1]);
#if defined(PR_SET_PTRACER)
        (void)::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
        void* page = ::mmap(nullptr,
                            4096u,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS,
                            -1,
                            0);
        if (page == MAP_FAILED) {
            _exit(2);
        }
        auto* code = static_cast<std::uint8_t*>(page);
        code[0] = 0x90u; // nop
        code[1] = 0xC3u; // ret

        const auto va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(page));
        (void)::write(addr_pipe[1], &va, sizeof(va));
        (void)::close(addr_pipe[1]);

        // Wait until debugger attaches, arms breakpoint, and signals go_pipe.
        char go = 0;
        while (::read(go_pipe[0], &go, 1) < 0 && errno == EINTR) {
        }
        (void)::close(go_pipe[0]);

        // Unmap `page` while running so restoring the original byte on detach() will fail!
        if (::munmap(page, 4096u) != 0) {
            _exit(3);
        }

        // Pause cleanly so debugger attempts detach() while `page` is guaranteed unmapped.
        ::raise(SIGSTOP);
        _exit(0);
    }

    ScopedReapChild guard{child};
    (void)::close(addr_pipe[1]);
    (void)::close(go_pipe[0]);

    std::uint64_t scratch_va = 0;
    ASSERT_EQ(::read(addr_pipe[0], &scratch_va, sizeof(scratch_va)),
              static_cast<ssize_t>(sizeof(scratch_va)));
    (void)::close(addr_pipe[0]);
    ASSERT_NE(scratch_va, 0u);

    auto dbg_backend = peelf::debugger::create_native_debug_backend();
    auto attached = dbg_backend->attach(static_cast<peelf::ProcessId>(child));
    if (!attached.has_value()) {
        (void)::close(go_pipe[1]);
        GTEST_SKIP() << "ptrace attach unavailable in current environment: "
                     << attached.error().message;
    }
    std::unique_ptr<peelf::debugger::IDebugSession> dbg = std::move(*attached);
    ASSERT_EQ(dbg->state(), peelf::debugger::DebugSessionState::Paused);

    auto bp_id = dbg->add_software_breakpoint(scratch_va, "scratch_unmap_bp");
    ASSERT_TRUE(bp_id.has_value()) << bp_id.error().message;
    ASSERT_EQ(dbg->breakpoints().size(), 1u);
    EXPECT_TRUE(dbg->breakpoints().front().armed_in_target);

    // Release child from go_pipe and let it execute munmap(page) + raise(SIGSTOP).
    const char go = '1';
    ASSERT_EQ(::write(go_pipe[1], &go, 1), 1);
    (void)::close(go_pipe[1]);

    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto stop2 = dbg->wait_for_stop(std::chrono::milliseconds(4000));
    ASSERT_TRUE(stop2.has_value()) << stop2.error().message;
    ASSERT_EQ(dbg->state(), peelf::debugger::DebugSessionState::Paused);

    // detach() MUST fail because scratch_va is now unmapped, preserving Paused + armed_in_target!
    auto det = dbg->detach();
    EXPECT_FALSE(det.has_value());
    EXPECT_EQ(dbg->state(), peelf::debugger::DebugSessionState::Paused);
    ASSERT_EQ(dbg->breakpoints().size(), 1u);
    EXPECT_TRUE(dbg->breakpoints().front().armed_in_target);

    // Clean termination still works and destructor remains noexcept.
    int st = 0;
    ASSERT_TRUE(dbg->terminate().has_value());
    (void)::waitpid(child, &st, 0);
    guard.pid = -1;
}
#endif
#endif

} // namespace
