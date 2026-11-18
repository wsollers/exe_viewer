#pragma once

#include <peelf/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

inline constexpr std::uint32_t kWorkspaceLayoutSchemaVersion = 11u;
inline constexpr float kMinDockSplitRatio = 0.05f;
inline constexpr float kMaxDockSplitRatio = 0.95f;

enum class WorkspacePreset : std::uint8_t {
    StaticReverseEngineering = 0,
    LiveProcessAndVmmap,
    Debugger,
    BinaryDiff,
    Minimal,
};

inline constexpr std::size_t kWorkspacePresetCount = 5u;

inline constexpr std::array<WorkspacePreset, kWorkspacePresetCount> kAllWorkspacePresets{{
    WorkspacePreset::StaticReverseEngineering,
    WorkspacePreset::LiveProcessAndVmmap,
    WorkspacePreset::Debugger,
    WorkspacePreset::BinaryDiff,
    WorkspacePreset::Minimal,
}};

[[nodiscard]] constexpr std::string_view workspace_preset_id(WorkspacePreset preset) noexcept {
    switch (preset) {
        case WorkspacePreset::StaticReverseEngineering: return "StaticReverseEngineering";
        case WorkspacePreset::LiveProcessAndVmmap:      return "LiveProcessAndVmmap";
        case WorkspacePreset::Debugger:                 return "Debugger";
        case WorkspacePreset::BinaryDiff:               return "BinaryDiff";
        case WorkspacePreset::Minimal:                  return "Minimal";
    }
    return "StaticReverseEngineering";
}

[[nodiscard]] constexpr std::string_view workspace_preset_display_name(WorkspacePreset preset) noexcept {
    switch (preset) {
        case WorkspacePreset::StaticReverseEngineering: return "Static Reverse Engineering";
        case WorkspacePreset::LiveProcessAndVmmap:      return "Live Process / VMMap";
        case WorkspacePreset::Debugger:                 return "Debugger";
        case WorkspacePreset::BinaryDiff:               return "Binary Diff";
        case WorkspacePreset::Minimal:                  return "Minimal";
    }
    return "Static Reverse Engineering";
}

[[nodiscard]] std::optional<WorkspacePreset> parse_workspace_preset_id(std::string_view id) noexcept;

enum class WorkspacePanelId : std::uint8_t {
    FileInfo = 0,
    MemoryMap,
    MemoryHeatmap,
    ByteEntropyViz,
    Structure,
    Details,
    Sections,
    HexView,
    PatchSet,
    Shellcode,
    Scripting,
    Imports,
    Exports,
    Symbols,
    Functions,
    ThreadsAndStack,
    ThreadLocals,
    MemorySearch,
    RuntimeAndFlags,
    Handlers,
    DataStructures,
    ReferencesAndNotes,
    Strings,
    StructureView,
    ProcessInternals,
    Dependencies,
    BinaryDiff,
    Debugger,
    TargetCapabilities,
    ExecutableSettings,
    ExecutionTimeline,
    Decompiler,
    PeHeaders,
    PeImports,
    PeExports,
    Disassembly,
    FlowGraph,
    Log,
};

inline constexpr std::size_t kWorkspacePanelCount = 38u;

[[nodiscard]] std::span<const WorkspacePanelId> all_workspace_panels() noexcept;
[[nodiscard]] std::string_view workspace_panel_window_name(WorkspacePanelId panel) noexcept;
[[nodiscard]] std::optional<WorkspacePanelId> workspace_panel_from_window_name(
    std::string_view window_name) noexcept;

enum class DockSplitAxis : std::uint8_t {
    Leaf = 0,
    Horizontal, // first = Left, second = Right
    Vertical,   // first = Top,  second = Bottom
};

struct DockNodeSpec {
    DockSplitAxis split_axis{DockSplitAxis::Leaf};
    float split_ratio{0.5f};
    std::unique_ptr<DockNodeSpec> first{};
    std::unique_ptr<DockNodeSpec> second{};
    std::vector<WorkspacePanelId> tabbed_panels{};
    std::optional<WorkspacePanelId> active_tab{};

    DockNodeSpec() = default;
    ~DockNodeSpec() noexcept = default;

    DockNodeSpec(const DockNodeSpec& other);
    DockNodeSpec& operator=(const DockNodeSpec& other);

    DockNodeSpec(DockNodeSpec&&) noexcept = default;
    DockNodeSpec& operator=(DockNodeSpec&&) noexcept = default;

    [[nodiscard]] constexpr bool is_leaf() const noexcept {
        return split_axis == DockSplitAxis::Leaf;
    }

    [[nodiscard]] static DockNodeSpec make_leaf(
        std::vector<WorkspacePanelId> panels,
        std::optional<WorkspacePanelId> selected_tab = std::nullopt);

    [[nodiscard]] static DockNodeSpec make_split(
        DockSplitAxis axis,
        float ratio,
        DockNodeSpec first_child,
        DockNodeSpec second_child);
};

struct WorkspacePresetSpec {
    WorkspacePreset preset{WorkspacePreset::StaticReverseEngineering};
    std::string display_name{};
    std::uint32_t schema_version{kWorkspaceLayoutSchemaVersion};
    DockNodeSpec root{};
    std::vector<WorkspacePanelId> visible_panels{};
};

[[nodiscard]] WorkspacePresetSpec build_workspace_preset(WorkspacePreset preset);
[[nodiscard]] peelf::Result<void> validate_workspace_preset(const WorkspacePresetSpec& spec);
[[nodiscard]] std::vector<WorkspacePanelId> collect_dock_leaf_panels(const DockNodeSpec& root);

[[nodiscard]] constexpr bool should_migrate_workspace_layout(std::uint32_t saved_version) noexcept {
    return saved_version != kWorkspaceLayoutSchemaVersion;
}

struct PersistedWorkspaceLayoutMetadata {
    std::uint32_t schema_version{0u};
    WorkspacePreset active_preset{WorkspacePreset::StaticReverseEngineering};
    bool has_metadata_section{false};
};

[[nodiscard]] PersistedWorkspaceLayoutMetadata parse_workspace_layout_metadata(
    std::string_view ini_text) noexcept;
[[nodiscard]] bool should_migrate_workspace_layout_ini(std::string_view ini_text) noexcept;
[[nodiscard]] std::string stamp_workspace_layout_metadata(
    std::string_view ini_text,
    WorkspacePreset active_preset,
    std::uint32_t schema_version = kWorkspaceLayoutSchemaVersion);

} // namespace viewer
