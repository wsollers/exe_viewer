#pragma once

#include <peelf/peelf.hpp>

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/symbol_index.hpp"
#include "ui/context_actions.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

struct DetailPropertyRow {
    std::string key{};
    std::string value{};
};

/// Builds a rich, format- and target-aware 2-column property table for `selection`
/// against `model` (`P6-11`), suitable for both Dear ImGui rendering and headless unit tests.
[[nodiscard]] std::vector<DetailPropertyRow> build_selection_detail_properties(
    const ViewerSelection& selection,
    const BinaryModel& model);

/// Builds a capability-ready `InspectableEntity` for right-click context actions on any
/// `StructureNavigatorPanel` node (`P6-9`).
[[nodiscard]] InspectableEntity build_inspectable_entity_from_selection(
    const ViewerSelection& selection,
    const BinaryModel* model = nullptr);

/// Enqueues explicit double-click / `Enter` activation for a `StructureNavigatorPanel`
/// selection onto `queue` according to `selection.preferred_view` (`P6-9` / `P6-20`).
bool enqueue_structure_selection_activation(
    NavigationRequestQueue& queue,
    const ViewerSelection& selection,
    BinaryModel* model = nullptr);

struct ScriptStarterTemplate {
    std::string_view title{};
    std::string_view summary{};
    bool requires_mutations{false};
    std::string_view source{};
};

inline constexpr std::size_t kScriptStarterTemplateCount = 4u;

/// Tokenizes a shell-style command-line argument string for debugger target launch.
/// Preserves explicit empty quoted arguments (`""` or `''`), supports `\"` and `\\`
/// escapes inside double quotes, and rejects unmatched single or double quotes.
[[nodiscard]] peelf::Result<std::vector<std::string>> tokenize_launch_arguments(
    std::string_view raw);

/// Resolves a breakpoint target expression against `symbols`:
///   1. Explicit `0x`/`0X` hex prefix parses as hexadecimal virtual address.
///   2. Exact symbol name / display name match resolves before bare hex so valid
///      hex-letter symbol names (`fade`, `dead`, `cafe`, `babe`, `add`, `dec`)
///      resolve to symbols unless prefixed with `0x`.
///   3. Bare hexadecimal virtual address.
///   4. Case-insensitive substring symbol match fallback.
[[nodiscard]] std::optional<std::uint64_t> resolve_breakpoint_target(
    std::string_view raw,
    const SymbolIndex& symbols,
    bool demangle = true);

/// Returns the built-in Lua starter templates exposed by the Scripting panel.
[[nodiscard]] std::span<const ScriptStarterTemplate> scripting_starter_templates() noexcept;

/// Clamps a `std::size_t` item count to `ImGuiListClipper::Begin(int)`'s non-negative `int` range.
[[nodiscard]] int clamp_imgui_clipper_count(std::size_t count) noexcept;

/// Replaces embedded `\r`, `\n`, `\t`, and ASCII control characters so untrusted
/// OS/binary strings cannot inject multiline rows or control codes into ImGui tables.
[[nodiscard]] std::string sanitize_single_line_control_chars(std::string_view text);

/// Constructs a `std::filesystem::path` from a UTF-8 `std::string_view` via `std::u8string_view`.
[[nodiscard]] std::filesystem::path utf8_to_filesystem_path(std::string_view utf8_text);

} // namespace viewer
