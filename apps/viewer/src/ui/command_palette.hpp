#pragma once

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "analysis/strings_index.hpp"
#include "analysis/structure_interpreter.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/data_types.hpp"
#include "symbols/symbol_index.hpp"
#include "ui/workspace_layout.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/process.hpp>
#include <peelf/security_audit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

// ---------------------------------------------------------------------------
// Allocation-Free Fuzzy Scorer
// ---------------------------------------------------------------------------

struct FuzzyMatchSpan {
    std::uint16_t offset = 0u;
    std::uint16_t length = 0u;

    bool operator==(const FuzzyMatchSpan&) const noexcept = default;
};

inline constexpr std::size_t kMaxFuzzyMatchedIndices = 64u;
inline constexpr std::size_t kMaxFuzzyMatchSpans = 32u;

struct FuzzyMatchResult {
    int score = 0;
    std::array<std::uint16_t, kMaxFuzzyMatchedIndices> matched_indices{};
    std::uint8_t matched_count = 0u;
    std::array<FuzzyMatchSpan, kMaxFuzzyMatchSpans> spans{};
    std::uint8_t span_count = 0u;

    [[nodiscard]] std::span<const std::uint16_t> indices() const noexcept {
        return std::span<const std::uint16_t>(matched_indices.data(), matched_count);
    }

    [[nodiscard]] std::span<const FuzzyMatchSpan> highlight_spans() const noexcept {
        return std::span<const FuzzyMatchSpan>(spans.data(), span_count);
    }
};

/// Fast, deterministic, allocation-free subsequence + contiguous-substring + prefix +
/// word/camelCase/underscore/alpha-digit boundary scorer.
/// Guarantees tier ordering: exact > prefix > word-boundary acronym > substring > subsequence.
/// Returns `std::nullopt` when `query` is not a subsequence of `candidate`.
[[nodiscard]] std::optional<int> fuzzy_match_score(
    std::string_view query,
    std::string_view candidate,
    FuzzyMatchResult* out_match = nullptr) noexcept;

// ---------------------------------------------------------------------------
// Rich Address & Symbol Expression Evaluator
// ---------------------------------------------------------------------------

struct ResolvedAddressExpression {
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> file_offset{};
    bool is_file_offset_only = false;
    std::string canonical_summary{};
    std::string matched_symbol_or_section{};

    bool operator==(const ResolvedAddressExpression&) const noexcept = default;
};

struct AddressExpressionContext {
    const peelf::IBinaryImage* image = nullptr;
    std::optional<std::uint64_t> image_base{};
    std::optional<std::uint64_t> entry_point{};
    std::optional<std::uint64_t> file_size{};

    // Optional active thread / debugger register state (`$pc` / `$ip` / `$sp` / `$fp`)
    std::optional<std::uint64_t> instruction_pointer{};
    std::optional<std::uint64_t> stack_pointer{};
    std::optional<std::uint64_t> frame_pointer{};
    std::span<const peelf::RegisterValue> registers{};

    // Optional explicit section / live-module lists
    std::span<const peelf::Section> sections{};
    std::span<const peelf::ModuleInfo> modules{};

    // Optional analysis & user stores
    const FunctionIndex* functions = nullptr;
    const SymbolIndex* symbols = nullptr;
    const AnnotationStore* annotations = nullptr;
    std::span<const Bookmark> bookmarks{};
};

/// Populates an `AddressExpressionContext` from a `BinaryModel` and optional UI symbol/annotation stores.
[[nodiscard]] AddressExpressionContext make_address_expression_context(
    const BinaryModel& model,
    const SymbolIndex* ui_symbols = nullptr,
    const AnnotationStore* annotations = nullptr) noexcept;

/// Parses and evaluates reverse-engineering address expressions with checked 64-bit arithmetic:
/// - Hex (`0x140001000`, `140001000h`, `$401000`), decimal (`4096`),
///   explicit prefixes (`va:0x...`, `rva:0x1000`, `off:0x400` / `file:0x400`).
/// - Named tokens: `$entry`/`entry`, `$base`/`image_base`, `$pc`/`$ip`/`$sp`,
///   section names (`.text`, `__TEXT,__text`), module names (`kernel32.dll`, `libc.so.6`),
///   user `AnnotationStore` labels, `Bookmark` labels, `FunctionIndex`, and `SymbolIndex`
///   raw or demangled C++/Rust names.
/// - Binary `+` and `-` arithmetic and parentheses (`(CreateFileW + 0x10) - 4`).
[[nodiscard]] peelf::Result<ResolvedAddressExpression> evaluate_address_expression(
    std::string_view expression,
    const AddressExpressionContext& context = {});

// ---------------------------------------------------------------------------
// Unified Command Palette Catalog, Prefix Modes & Ranking Engine
// ---------------------------------------------------------------------------

enum class PalettePrefixMode : std::uint8_t {
    Omni = 0,          // Mixed omni-search + live expression pinning
    Commands,          // `>` Commands, Panels & Workspaces
    Symbols,           // `@` Functions, Symbols & User Labels
    Strings,           // `#` Extracted Strings
    GoToAddress,       // `:` Go to Address / Expression
    Types,             // `struct:` / `type:` Structures & Debug Types
    BookmarksAndRules, // `?` / `*` Bookmarks & Security Audit Findings/Rules
};

[[nodiscard]] constexpr std::string_view to_string(PalettePrefixMode mode) noexcept {
    switch (mode) {
        case PalettePrefixMode::Omni:              return "Omni";
        case PalettePrefixMode::Commands:          return "Commands";
        case PalettePrefixMode::Symbols:           return "Symbols";
        case PalettePrefixMode::Strings:           return "Strings";
        case PalettePrefixMode::GoToAddress:       return "GoTo";
        case PalettePrefixMode::Types:             return "Types";
        case PalettePrefixMode::BookmarksAndRules: return "Bookmarks & Rules";
    }
    return "Omni";
}

struct ParsedPaletteQuery {
    PalettePrefixMode mode = PalettePrefixMode::Omni;
    std::string_view filter{};
    std::string_view raw_trimmed{};
};

[[nodiscard]] ParsedPaletteQuery parse_palette_query(std::string_view raw_query) noexcept;

enum class PaletteCategory : std::uint8_t {
    Panel = 0,
    Preset,
    Command,
    Function,
    Symbol,
    String,
    Type,
    Bookmark,
    Rule,
    GoTo,
};

[[nodiscard]] constexpr std::string_view to_string(PaletteCategory category) noexcept {
    switch (category) {
        case PaletteCategory::Panel:    return "Panel";
        case PaletteCategory::Preset:   return "Preset";
        case PaletteCategory::Command:  return "Command";
        case PaletteCategory::Function: return "Function";
        case PaletteCategory::Symbol:   return "Symbol";
        case PaletteCategory::String:   return "String";
        case PaletteCategory::Type:     return "Type";
        case PaletteCategory::Bookmark: return "Bookmark";
        case PaletteCategory::Rule:     return "Rule";
        case PaletteCategory::GoTo:     return "GoTo";
    }
    return "Command";
}

enum class PaletteCommandId : std::uint8_t {
    OpenBinary = 0,
    AttachToProcess,
    ConnectGdbRemote,
    OpenCrashDump,
    OpenDebugSymbols,
    SaveProject,
    SavePatchedAs,
    DecompileCurrentFunction,
    ScanFullReferences,
    ToggleDemangleSymbols,
    SwitchFlowGraphGalaxy,
    ResetWorkspaceLayout,
    GoToEntryPoint,
    GoToAddressPrompt,
};

enum class PaletteActionKind : std::uint8_t {
    None = 0,
    FocusPanel,
    TogglePanel,
    ApplyWorkspacePreset,
    RunCommand,
    NavigateAddress,
    NavigateFileOffset,
    OpenStructureView,
};

struct PaletteAction {
    PaletteActionKind kind = PaletteActionKind::None;
    WorkspacePanelId panel_id = WorkspacePanelId::Disassembly;
    WorkspacePreset preset = WorkspacePreset::StaticReverseEngineering;
    PaletteCommandId command_id = PaletteCommandId::OpenBinary;
    std::uint64_t target_address = 0u;
    PreferredView preferred_view = PreferredView::Disassembly;
    std::size_t highlight_size = 0u;
    bool request_decompile = false;
    std::string type_name{};

    [[nodiscard]] bool valid() const noexcept { return kind != PaletteActionKind::None; }
};

/// Translates an address/offset palette action into a `DeferredNavigationRequest` suitable
/// for enqueueing on `NavigationRequestQueue` without mutating UI state mid-frame.
[[nodiscard]] std::optional<DeferredNavigationRequest> build_palette_navigation_request(
    const PaletteAction& action) noexcept;

struct PaletteItem {
    std::string id{};
    PaletteCategory category = PaletteCategory::Command;
    std::string title{};
    std::string subtitle{};
    std::string right_badge{};
    int score = 0;
    bool pinned = false;
    bool enabled = true;
    FuzzyMatchResult title_match{};
    PaletteAction primary_action{};
    PaletteAction secondary_hex_action{};
    PaletteAction tertiary_decompile_action{};
};

inline constexpr std::size_t kDefaultPaletteMaxResults = 64u;

struct PaletteQueryOptions {
    std::size_t max_results = kDefaultPaletteMaxResults;
};

struct PaletteDataSources {
    AddressExpressionContext expr_context{};
    const FunctionIndex* functions = nullptr;
    const SymbolIndex* symbols = nullptr;
    const AnnotationStore* annotations = nullptr;
    const StringsIndex* strings = nullptr;
    const StructureCatalog* structure_catalog = nullptr;
    std::span<const DataTypeRecord> debug_types{};
    std::span<const DataTypeRecord> secondary_types{};
    std::span<const Bookmark> bookmarks{};
    const peelf::SecurityAuditReport* security_audit = nullptr;

    std::array<bool, kWorkspacePanelCount> panel_visibility{};
    bool has_panel_visibility = false;
    WorkspacePreset active_preset = WorkspacePreset::StaticReverseEngineering;
    bool demangle_symbols = true;
    bool has_file = false;
    bool is_live_process = false;
    bool flow_galaxy_enabled = false;
    bool include_rule_catalog_fallback = true;
};

[[nodiscard]] PaletteDataSources make_palette_data_sources(
    const BinaryModel& model,
    const SymbolIndex* ui_symbols = nullptr,
    const AnnotationStore* annotations = nullptr,
    const StringsIndex* strings = nullptr,
    std::span<const DataTypeRecord> ui_debug_types = {},
    std::span<const DataTypeRecord> secondary_types = {}) noexcept;

struct PaletteQueryResult {
    ParsedPaletteQuery parsed_query{};
    std::optional<ResolvedAddressExpression> resolved_expression{};
    std::string expression_error{};
    std::vector<PaletteItem> items{};
};

class CommandPalette {
public:
    CommandPalette();

    [[nodiscard]] PaletteQueryResult query(
        std::string_view raw_query,
        const PaletteDataSources& sources,
        PaletteQueryOptions options = {}) const;

    void record_execution(std::string_view item_id);
    void clear_mru() noexcept;

    [[nodiscard]] int mru_boost_for(std::string_view item_id) const noexcept;
    [[nodiscard]] std::uint64_t mru_sequence_for(std::string_view item_id) const noexcept;

private:
    struct MruEntry {
        std::string id{};
        std::uint64_t sequence = 0u;
    };

    static constexpr std::size_t kMaxMruEntries = 64u;
    std::vector<MruEntry> mru_entries_{};
    std::uint64_t next_mru_sequence_ = 1u;
};

} // namespace viewer
