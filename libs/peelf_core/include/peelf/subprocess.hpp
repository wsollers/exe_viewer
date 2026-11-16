#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

namespace peelf {

struct SubprocessResult {
    int exit_code{-1};
    bool launched{false};
    bool timed_out{false};
    bool cancelled{false};
    std::string stdout_text{};
    std::string stderr_text{};
    std::string launch_error{};
};

struct SubprocessOptions {
    std::string_view stdin_payload{};
    std::chrono::milliseconds timeout{15000};
    std::stop_token stop_token{};
    bool search_path{false};
    std::size_t max_output_bytes{64u * 1024u * 1024u};
};

/// Quotes a single command-line argument using exact Win32 `CommandLineToArgvW` / MSVC CRT rules:
/// - Non-empty arguments containing no whitespace (`' '`, `'\t'`, `'\n'`, `'\v'`, `'\r'`) or `"`
///   are returned verbatim (ordinary backslashes such as `C:\tools\dot.exe` or `\\srv\share\a`
///   are never doubled).
/// - Empty arguments or arguments containing whitespace/quotes are wrapped in `"..."`, doubling
///   backslashes ONLY immediately before `"` or the closing `"`.
[[nodiscard]] std::string quote_windows_arg(std::string_view arg);

/// Executes `executable` directly via OS process creation (`CreateProcessW` on Windows with
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `fork`+`execv`
/// with dedicated process group `setpgid(0, 0)` on POSIX -- never through a shell).
/// Bounds both child lifetime and descendant pipe-drainer joins by `options.timeout` and
/// `options.stop_token`.
[[nodiscard]] SubprocessResult run_subprocess_bounded(
    const std::filesystem::path& executable,
    std::span<const std::string> args,
    const SubprocessOptions& options = {});

[[nodiscard]] SubprocessResult run_subprocess_bounded(
    const std::filesystem::path& executable,
    std::span<const std::string> args,
    std::string_view stdin_payload,
    std::chrono::milliseconds timeout,
    std::stop_token stop_token = {});

#if !defined(_WIN32)
namespace detail {

/// Safely binds child `in_rd`, `out_wr`, `err_wr` onto `STDIN_FILENO` (0), `STDOUT_FILENO` (1),
/// and `STDERR_FILENO` (2) while keeping `exec_wr` (`>= 3`, `FD_CLOEXEC`) intact, even when one or
/// more of parent `fd 0, 1, 2` were closed and pipe ends landed inside `0..2`.
[[nodiscard]] bool prepare_posix_child_stdio(int& in_rd,
                                             int& out_wr,
                                             int& err_wr,
                                             int& exec_wr) noexcept;

} // namespace detail
#endif

} // namespace peelf
