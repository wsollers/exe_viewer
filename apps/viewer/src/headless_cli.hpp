#pragma once

#include <peelf/error.hpp>
#include <peelf/scripting.hpp>

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace viewer {

enum class HeadlessScriptOutputFormat : std::uint8_t {
    Text = 0,
    Json,
};

struct HeadlessScriptCliOptions {
    std::filesystem::path binary_path{};
    std::filesystem::path script_path{};
    std::optional<std::string> slice_selector{};
    std::optional<std::filesystem::path> output_report_path{};
    std::optional<std::filesystem::path> output_binary_path{};
    std::optional<std::filesystem::path> project_path{};
    HeadlessScriptOutputFormat format{HeadlessScriptOutputFormat::Text};
    bool allow_mutations{false};
    bool allow_modified_binary{false};
    peelf::ScriptLimits limits{};
};

struct HeadlessScriptRunReport {
    std::filesystem::path binary_path{};
    std::filesystem::path script_path{};
    std::size_t selected_slice_index{0u};
    std::string selected_slice_arch{};
    bool allow_mutations{false};
    bool output_binary_written{false};
    bool project_written{false};
    peelf::ScriptExecutionResult execution{};
};

[[nodiscard]] peelf::Result<HeadlessScriptRunReport> run_headless_script(
    const HeadlessScriptCliOptions& options);

[[nodiscard]] std::string format_headless_script_report_text(
    const HeadlessScriptRunReport& report);

[[nodiscard]] std::string format_headless_script_report_json(
    const HeadlessScriptRunReport& report);

/// Handles `--help` / `-h` and `--headless` CLI invocations for `peelf_viewer`.
/// Supports `--headless <binary> --script <file.lua>` (with `--slice`,
/// `--script-allow-mutations`, `--allow-modified-binary`, `--output-binary`,
/// `--project`, `--script-max-instructions`, `--script-timeout-ms`,
/// `--format text|json`, `--output`) and delegates standard headless
/// static/security inspection to `peelf::try_run_headless_or_help_cli`.
[[nodiscard]] std::optional<int> try_run_headless_or_help_cli(
    std::span<const std::string_view> args,
    std::ostream& stdout_stream,
    std::ostream& stderr_stream);

} // namespace viewer
