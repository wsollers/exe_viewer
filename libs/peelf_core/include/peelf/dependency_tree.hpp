#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/process.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class DependencyResolutionStatus : std::uint8_t {
    RootModule,
    ResolvedOnDisk,
    ResolvedInLiveProcess,
    VirtualApiSet,
    SystemSharedCache,
    ArchitectureMismatch,
    Unresolved,
    CycleSkipped,
};

[[nodiscard]] constexpr std::string_view to_string(DependencyResolutionStatus status) noexcept {
    switch (status) {
        case DependencyResolutionStatus::RootModule:            return "Root";
        case DependencyResolutionStatus::ResolvedOnDisk:        return "Resolved (Disk)";
        case DependencyResolutionStatus::ResolvedInLiveProcess: return "Resolved (Live RAM)";
        case DependencyResolutionStatus::VirtualApiSet:         return "Virtual API-Set";
        case DependencyResolutionStatus::SystemSharedCache:     return "System Shared Cache";
        case DependencyResolutionStatus::ArchitectureMismatch:  return "Arch Mismatch";
        case DependencyResolutionStatus::Unresolved:            return "Unresolved";
        case DependencyResolutionStatus::CycleSkipped:          return "Cycle Skipped";
    }
    return "Unresolved";
}

enum class DependencyEdgeKind : std::uint8_t {
    StandardImport,
    DelayLoadImport,
    ForwardedExport,
    DynamicLinkerInterp,
    WeakDylib,
    ReexportDylib,
    LazyDylib,
    UpwardDylib,
    DyldLinker,
};

[[nodiscard]] constexpr std::string_view to_string(DependencyEdgeKind kind) noexcept {
    switch (kind) {
        case DependencyEdgeKind::StandardImport:      return "Import";
        case DependencyEdgeKind::DelayLoadImport:     return "Delay-Load";
        case DependencyEdgeKind::ForwardedExport:     return "Forwarded Export";
        case DependencyEdgeKind::DynamicLinkerInterp: return "PT_INTERP Linker";
        case DependencyEdgeKind::WeakDylib:           return "Weak Dylib";
        case DependencyEdgeKind::ReexportDylib:       return "Re-Export Dylib";
        case DependencyEdgeKind::LazyDylib:           return "Lazy Dylib";
        case DependencyEdgeKind::UpwardDylib:         return "Upward Dylib";
        case DependencyEdgeKind::DyldLinker:          return "LC_LOAD_DYLINKER";
    }
    return "Import";
}

enum class ImportedSymbolStatus : std::uint8_t {
    BoundExport,
    BoundForwardedExport,
    BoundWeakOptional,
    UnboundMissingExport,
    UncheckedVirtualApiSet,
    UncheckedSystemSharedCache,
    UncheckedTargetUnavailable,
};

[[nodiscard]] constexpr std::string_view to_string(ImportedSymbolStatus status) noexcept {
    switch (status) {
        case ImportedSymbolStatus::BoundExport:                return "Bound";
        case ImportedSymbolStatus::BoundForwardedExport:       return "Forwarded";
        case ImportedSymbolStatus::BoundWeakOptional:          return "Weak (Optional)";
        case ImportedSymbolStatus::UnboundMissingExport:       return "Missing Export";
        case ImportedSymbolStatus::UncheckedVirtualApiSet:     return "API-Set Contract";
        case ImportedSymbolStatus::UncheckedSystemSharedCache: return "dyld Shared Cache";
        case ImportedSymbolStatus::UncheckedTargetUnavailable: return "Target Missing";
    }
    return "Target Missing";
}

struct ImportedSymbolBinding {
    std::string name{};
    std::uint32_t ordinal{0};
    bool import_by_ordinal{false};
    bool delay_load{false};
    bool weak_symbol{false};
    ImportedSymbolStatus status{ImportedSymbolStatus::UncheckedTargetUnavailable};
    std::uint64_t call_site_va{0};       ///< IAT thunk VA (PE) or GOT/PLT relocation VA (ELF), 0 if none.
    std::uint64_t resolved_export_va{0}; ///< Exported symbol VA in resolved child module, 0 if none.
    std::string forwarded_to{};          ///< Non-empty when child PE export is a forwarder (e.g. "NTDLL.RtlAlloc").
    std::string note{};
};

struct DependencyNode {
    std::size_t id{0};
    std::string requested_name{};
    std::string display_name{};
    std::string soname{};
    std::filesystem::path resolved_path{};
    DependencyResolutionStatus status{DependencyResolutionStatus::Unresolved};
    std::string resolution_reason{};
    std::vector<std::filesystem::path> searched_paths{};
    std::vector<std::string> origin_assumptions{};

    Format format{Format::Unknown};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Little};
    bool is_64bit{false};
    std::optional<std::uint64_t> live_base_va{};
    std::size_t export_count{0};

    std::vector<std::string> elf_rpaths{};
    std::vector<std::string> elf_runpaths{};
    std::string elf_interpreter{};
    std::vector<std::string> macho_rpaths{};
    std::string macho_install_name{};
    std::string macho_dylinker{};
    std::vector<ImportedSymbolBinding> unresolved_symbols{};
};

struct DependencyEdge {
    std::size_t parent_node_id{0};
    std::size_t child_node_id{0};
    std::string requested_name{};
    DependencyEdgeKind kind{DependencyEdgeKind::StandardImport};
    DependencyResolutionStatus resolution_status{DependencyResolutionStatus::Unresolved};
    std::filesystem::path resolved_path{};
    std::string resolution_reason{};
    std::vector<std::filesystem::path> searched_paths{};
    std::vector<std::string> origin_assumptions{};
    std::vector<ImportedSymbolBinding> symbol_bindings{};
};

struct DependencyTreeItem {
    std::size_t node_id{0};
    std::optional<std::size_t> edge_index{};
    std::string requested_name{};
    DependencyEdgeKind edge_kind{DependencyEdgeKind::StandardImport};
    DependencyResolutionStatus status{DependencyResolutionStatus::RootModule};
    std::uint32_t depth{0};
    bool is_cycle{false};
    bool is_diamond_ref{false};
    bool truncated_by_depth{false};
    std::vector<DependencyTreeItem> children{};
};

struct DependencySummary {
    std::size_t direct_dependencies{0};
    std::size_t transitive_dependencies{0};
    std::size_t resolved_count{0};
    std::size_t resolved_live_count{0};
    std::size_t virtual_api_sets{0};
    std::size_t system_shared_cache{0};
    std::size_t missing_libraries{0};
    std::size_t architecture_mismatches{0};
    std::size_t cycle_edges{0};
    std::size_t unresolved_symbols{0};
};

struct DependencyGraph {
    std::vector<DependencyNode> nodes{};
    std::vector<DependencyEdge> edges{};
    DependencyTreeItem root_tree{};
    DependencySummary summary{};
};

struct DependencyResolveOptions {
    std::uint32_t max_depth{8};
    std::filesystem::path root_path{};
    std::vector<std::filesystem::path> search_roots{};
    std::vector<std::filesystem::path> ld_library_paths{};
    std::filesystem::path sysroot{};
    bool use_env_ld_library_path{false};
    bool include_default_system_dirs{true};
    std::string elf_lib_token{};
    std::string elf_platform_token{};
};

/// Returns true if `dll_name` names a Windows API Set virtual contract DLL
/// (`api-ms-win-*` or `ext-ms-win-*`, case-insensitive, with or without `.dll`).
[[nodiscard]] bool is_windows_api_set_dll(std::string_view dll_name) noexcept;

/// Expands ELF `$ORIGIN` / `${ORIGIN}`, `$LIB` / `${LIB}`, and `$PLATFORM` / `${PLATFORM}`
/// tokens in a single `DT_RPATH` / `DT_RUNPATH` segment and appends any expansion
/// assumptions used to `assumptions_out`.
[[nodiscard]] std::string expand_elf_dynamic_tokens(
    std::string_view raw_path,
    const std::filesystem::path& origin_dir,
    std::string_view lib_token,
    std::string_view platform_token,
    std::vector<std::string>* assumptions_out = nullptr);

/// Returns true if `install_name` names a macOS / Darwin dyld shared-cache system path
/// (e.g. `/usr/lib/...`, `/System/Library/...`, `/System/iOSSupport/...`) that resides in
/// Apple's dyld shared cache rather than standalone files on modern macOS or non-Apple hosts.
[[nodiscard]] bool is_macos_dyld_shared_cache_path(std::string_view install_name) noexcept;

/// Expands Mach-O `@executable_path` and `@loader_path` prefixes in a dylib install name
/// or `LC_RPATH` entry and appends any fallback assumptions used to `assumptions_out`.
[[nodiscard]] std::string expand_macho_loader_tokens(
    std::string_view raw_path,
    const std::filesystem::path& executable_dir,
    const std::filesystem::path& loader_dir,
    std::vector<std::string>* assumptions_out = nullptr);

/// Splits a `:` or `;` separated search-root string into non-empty filesystem paths.
[[nodiscard]] std::vector<std::filesystem::path> parse_search_roots_list(std::string_view text);

/// Builds a recursive, cycle-guarded, depth-bounded dependency graph & tree for a
/// parsed root `IBinaryImage` (static file or live attached `IProcessSession`).
[[nodiscard]] DependencyGraph build_dependency_graph(
    const IBinaryImage& root_image,
    const DependencyResolveOptions& options = {},
    IProcessSession* live_session = nullptr);

/// Convenience overload parsing `binary_path` from disk first.
[[nodiscard]] Result<DependencyGraph> build_dependency_graph_from_file(
    const std::filesystem::path& binary_path,
    DependencyResolveOptions options = {},
    IProcessSession* live_session = nullptr);

} // namespace peelf
