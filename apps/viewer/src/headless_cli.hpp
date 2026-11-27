#pragma once

#include "graph/call_graph.hpp"

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

enum class HeadlessGraphKind : std::uint8_t {
    Entry = 0,
    Fanout,
    Cfg,
};

enum class HeadlessGraphFormat : std::uint8_t {
    Dot = 0,
    Svg,
    Png,
    Json,
};

[[nodiscard]] constexpr std::string_view to_string(HeadlessGraphKind kind) noexcept {
    switch (kind) {
        case HeadlessGraphKind::Entry:  return "entry";
        case HeadlessGraphKind::Fanout: return "fanout";
        case HeadlessGraphKind::Cfg:    return "cfg";
    }
    return "entry";
}

[[nodiscard]] constexpr std::string_view to_string(HeadlessGraphFormat format) noexcept {
    switch (format) {
        case HeadlessGraphFormat::Dot:  return "dot";
        case HeadlessGraphFormat::Svg:  return "svg";
        case HeadlessGraphFormat::Png:  return "png";
        case HeadlessGraphFormat::Json: return "json";
    }
    return "dot";
}

struct HeadlessOptions {
    std::filesystem::path binary_path{};
    std::optional<std::string> slice_selector{};
    HeadlessGraphKind graph_kind{HeadlessGraphKind::Entry};
    std::optional<std::string> symbol{};
    std::size_t graph_depth{3u};
    std::size_t graph_max_nodes{64u};
    std::optional<HeadlessGraphFormat> graph_format{};
    std::optional<std::filesystem::path> output_path{};
};

using HeadlessGraphCliOptions = HeadlessOptions;

struct HeadlessGraphRunReport {
    HeadlessGraphKind kind{HeadlessGraphKind::Entry};
    std::string root{};
    CallGraph graph{};
};

[[nodiscard]] HeadlessGraphFormat resolve_headless_graph_format(
    const HeadlessOptions& options) noexcept;

[[nodiscard]] peelf::Result<HeadlessGraphRunReport> build_headless_graph(
    const HeadlessOptions& options);

[[nodiscard]] std::string format_headless_graph_json(
    HeadlessGraphKind kind,
    std::string_view root,
    const CallGraph& graph);

[[nodiscard]] peelf::Result<void> export_headless_graph(
    const HeadlessOptions& options,
    std::ostream& stdout_stream,
    const IProcessRunner* runner_override = nullptr);

/// Handles `--help` / `-h`, `--version` / `-V`, and `--headless` CLI invocations for `peelf_viewer`.
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
