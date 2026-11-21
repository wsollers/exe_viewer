#include "workspace_layout.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <format>
#include <sstream>
#include <utility>

namespace viewer {
namespace {

constexpr std::array<WorkspacePanelId, kWorkspacePanelCount> kAllPanels{{
    WorkspacePanelId::FileInfo,
    WorkspacePanelId::MemoryMap,
    WorkspacePanelId::MemoryHeatmap,
    WorkspacePanelId::ByteEntropyViz,
    WorkspacePanelId::Structure,
    WorkspacePanelId::Details,
    WorkspacePanelId::Sections,
    WorkspacePanelId::HexView,
    WorkspacePanelId::PatchSet,
    WorkspacePanelId::Shellcode,
    WorkspacePanelId::Scripting,
    WorkspacePanelId::Imports,
    WorkspacePanelId::Exports,
    WorkspacePanelId::Symbols,
    WorkspacePanelId::Functions,
    WorkspacePanelId::ThreadsAndStack,
    WorkspacePanelId::ThreadLocals,
    WorkspacePanelId::MemorySearch,
    WorkspacePanelId::RuntimeAndFlags,
    WorkspacePanelId::Handlers,
    WorkspacePanelId::DataStructures,
    WorkspacePanelId::ReferencesAndNotes,
    WorkspacePanelId::Strings,
    WorkspacePanelId::SignaturesAndCrypto,
    WorkspacePanelId::StructureView,
    WorkspacePanelId::ProcessInternals,
    WorkspacePanelId::Dependencies,
    WorkspacePanelId::BinaryDiff,
    WorkspacePanelId::Debugger,
    WorkspacePanelId::TargetCapabilities,
    WorkspacePanelId::ExecutableSettings,
    WorkspacePanelId::ExecutionTimeline,
    WorkspacePanelId::Decompiler,
    WorkspacePanelId::PeHeaders,
    WorkspacePanelId::PeImports,
    WorkspacePanelId::PeExports,
    WorkspacePanelId::ClrMetadata,
    WorkspacePanelId::Disassembly,
    WorkspacePanelId::FlowGraph,
    WorkspacePanelId::Log,
}};

[[nodiscard]] constexpr bool is_valid_panel_id(WorkspacePanelId panel) noexcept {
    return static_cast<std::size_t>(panel) < kWorkspacePanelCount;
}

[[nodiscard]] std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
        sv.remove_suffix(1);
    }
    return sv;
}

void collect_leaf_panels_recursive(const DockNodeSpec& node,
                                   std::vector<WorkspacePanelId>& out,
                                   std::size_t depth) {
    if (depth > 32u) {
        return;
    }
    if (node.is_leaf()) {
        out.insert(out.end(), node.tabbed_panels.begin(), node.tabbed_panels.end());
        return;
    }
    if (node.first != nullptr) {
        collect_leaf_panels_recursive(*node.first, out, depth + 1u);
    }
    if (node.second != nullptr) {
        collect_leaf_panels_recursive(*node.second, out, depth + 1u);
    }
}

[[nodiscard]] peelf::Result<void> validate_dock_node_recursive(
    const DockNodeSpec& node,
    std::span<const WorkspacePanelId> visible_panels,
    std::array<bool, kWorkspacePanelCount>& seen_in_leaves,
    std::size_t depth) {
    if (depth > 32u) {
        return peelf::make_error("DockNodeSpec tree exceeds maximum depth (32)");
    }

    switch (node.split_axis) {
        case DockSplitAxis::Leaf: {
            if (node.first != nullptr || node.second != nullptr) {
                return peelf::make_error("Leaf DockNodeSpec must not own child split nodes");
            }
            if (node.tabbed_panels.empty()) {
                return peelf::make_error("Leaf DockNodeSpec must have a non-empty tabbed_panels list");
            }
            for (const WorkspacePanelId panel : node.tabbed_panels) {
                if (!is_valid_panel_id(panel)) {
                    return peelf::make_error("Leaf DockNodeSpec contains out-of-range WorkspacePanelId");
                }
                const auto idx = static_cast<std::size_t>(panel);
                if (seen_in_leaves[idx]) {
                    return peelf::make_error(std::format(
                        "Duplicate WorkspacePanelId '{}' across DockNodeSpec leaves",
                        workspace_panel_window_name(panel)));
                }
                seen_in_leaves[idx] = true;
                if (std::ranges::find(visible_panels, panel) == visible_panels.end()) {
                    return peelf::make_error(std::format(
                        "Leaf tab '{}' is missing from WorkspacePresetSpec::visible_panels",
                        workspace_panel_window_name(panel)));
                }
            }
            if (!node.active_tab.has_value()) {
                return peelf::make_error("Leaf DockNodeSpec must specify a deterministic active_tab");
            }
            if (std::ranges::find(node.tabbed_panels, *node.active_tab) == node.tabbed_panels.end()) {
                return peelf::make_error(std::format(
                    "Leaf active_tab '{}' is not present in leaf tabbed_panels",
                    workspace_panel_window_name(*node.active_tab)));
            }
            return {};
        }
        case DockSplitAxis::Horizontal:
        case DockSplitAxis::Vertical: {
            if (!std::isfinite(node.split_ratio) ||
                node.split_ratio < kMinDockSplitRatio ||
                node.split_ratio > kMaxDockSplitRatio) {
                return peelf::make_error(std::format(
                    "Split DockNodeSpec split_ratio ({:.3f}) violates [0.05, 0.95] bounds",
                    node.split_ratio));
            }
            if (node.first == nullptr || node.second == nullptr) {
                return peelf::make_error("Split DockNodeSpec must define both first and second child nodes");
            }
            if (!node.tabbed_panels.empty() || node.active_tab.has_value()) {
                return peelf::make_error("Split DockNodeSpec must not carry leaf tabbed_panels or active_tab");
            }
            if (auto r1 = validate_dock_node_recursive(
                    *node.first, visible_panels, seen_in_leaves, depth + 1u);
                !r1) {
                return r1;
            }
            return validate_dock_node_recursive(
                *node.second, visible_panels, seen_in_leaves, depth + 1u);
        }
    }
    return peelf::make_error("DockNodeSpec has invalid DockSplitAxis");
}

[[nodiscard]] WorkspacePresetSpec finalize_preset(WorkspacePreset preset, DockNodeSpec root) {
    WorkspacePresetSpec spec;
    spec.preset = preset;
    spec.display_name = std::string(workspace_preset_display_name(preset));
    spec.schema_version = kWorkspaceLayoutSchemaVersion;
    spec.visible_panels = collect_dock_leaf_panels(root);
    spec.root = std::move(root);
    return spec;
}

} // namespace

std::optional<WorkspacePreset> parse_workspace_preset_id(std::string_view id) noexcept {
    const std::string_view trimmed = trim_ascii(id);
    for (const WorkspacePreset preset : kAllWorkspacePresets) {
        if (workspace_preset_id(preset) == trimmed ||
            workspace_preset_display_name(preset) == trimmed) {
            return preset;
        }
    }
    return std::nullopt;
}

std::span<const WorkspacePanelId> all_workspace_panels() noexcept {
    return kAllPanels;
}

std::string_view workspace_panel_window_name(WorkspacePanelId panel) noexcept {
    switch (panel) {
        case WorkspacePanelId::FileInfo:           return "File Info";
        case WorkspacePanelId::MemoryMap:          return "Memory Map";
        case WorkspacePanelId::MemoryHeatmap:      return "Memory Heatmap";
        case WorkspacePanelId::ByteEntropyViz:     return "Entropy & Digram";
        case WorkspacePanelId::Structure:          return "Structure";
        case WorkspacePanelId::Details:            return "Details";
        case WorkspacePanelId::Sections:           return "Sections";
        case WorkspacePanelId::HexView:            return "Hex View";
        case WorkspacePanelId::PatchSet:           return "Patch Set";
        case WorkspacePanelId::Shellcode:          return "Shellcode";
        case WorkspacePanelId::Scripting:          return "Scripting";
        case WorkspacePanelId::Imports:            return "Imports";
        case WorkspacePanelId::Exports:            return "Exports";
        case WorkspacePanelId::Symbols:            return "Functions & Names";
        case WorkspacePanelId::Functions:          return "Functions";
        case WorkspacePanelId::ThreadsAndStack:    return "Threads & Stack";
        case WorkspacePanelId::ThreadLocals:       return "Thread Locals";
        case WorkspacePanelId::MemorySearch:       return "Memory Search";
        case WorkspacePanelId::RuntimeAndFlags:    return "PEB / TEB & Flags";
        case WorkspacePanelId::Handlers:           return "Handlers";
        case WorkspacePanelId::DataStructures:      return "Data Structures";
        case WorkspacePanelId::ReferencesAndNotes:  return "References & Notes";
        case WorkspacePanelId::Strings:             return "Strings";
        case WorkspacePanelId::SignaturesAndCrypto: return "Signatures & Crypto";
        case WorkspacePanelId::StructureView:       return "Structure View";
        case WorkspacePanelId::ProcessInternals:   return "Process Internals";
        case WorkspacePanelId::Dependencies:       return "Dependencies";
        case WorkspacePanelId::BinaryDiff:         return "Binary Diff";
        case WorkspacePanelId::Debugger:           return "Debugger";
        case WorkspacePanelId::TargetCapabilities: return "Target Capabilities";
        case WorkspacePanelId::ExecutableSettings: return "Executable Settings";
        case WorkspacePanelId::ExecutionTimeline:  return "Execution Timeline";
        case WorkspacePanelId::Decompiler:         return "Decompiler";
        case WorkspacePanelId::PeHeaders:          return "PE Headers";
        case WorkspacePanelId::PeImports:          return "PE Imports";
        case WorkspacePanelId::PeExports:          return "PE Exports";
        case WorkspacePanelId::ClrMetadata:        return ".NET / CLR";
        case WorkspacePanelId::Disassembly:        return "Disassembly";
        case WorkspacePanelId::FlowGraph:          return "Flow Graph";
        case WorkspacePanelId::Log:                return "Log";
    }
    return "Disassembly";
}

std::optional<WorkspacePanelId> workspace_panel_from_window_name(
    std::string_view window_name) noexcept {
    for (const WorkspacePanelId panel : kAllPanels) {
        if (workspace_panel_window_name(panel) == window_name) {
            return panel;
        }
    }
    return std::nullopt;
}

DockNodeSpec::DockNodeSpec(const DockNodeSpec& other)
    : split_axis(other.split_axis)
    , split_ratio(other.split_ratio)
    , first(other.first != nullptr ? std::make_unique<DockNodeSpec>(*other.first) : nullptr)
    , second(other.second != nullptr ? std::make_unique<DockNodeSpec>(*other.second) : nullptr)
    , tabbed_panels(other.tabbed_panels)
    , active_tab(other.active_tab) {}

DockNodeSpec& DockNodeSpec::operator=(const DockNodeSpec& other) {
    if (this == &other) {
        return *this;
    }
    DockNodeSpec copy(other);
    *this = std::move(copy);
    return *this;
}

DockNodeSpec DockNodeSpec::make_leaf(std::vector<WorkspacePanelId> panels,
                                     std::optional<WorkspacePanelId> selected_tab) {
    DockNodeSpec leaf;
    leaf.split_axis = DockSplitAxis::Leaf;
    leaf.split_ratio = 0.5f;
    if (!selected_tab.has_value() && !panels.empty()) {
        selected_tab = panels.front();
    }
    leaf.tabbed_panels = std::move(panels);
    leaf.active_tab = selected_tab;
    return leaf;
}

DockNodeSpec DockNodeSpec::make_split(DockSplitAxis axis,
                                      float ratio,
                                      DockNodeSpec first_child,
                                      DockNodeSpec second_child) {
    DockNodeSpec split;
    split.split_axis = axis;
    split.split_ratio = ratio;
    split.first = std::make_unique<DockNodeSpec>(std::move(first_child));
    split.second = std::make_unique<DockNodeSpec>(std::move(second_child));
    return split;
}

std::vector<WorkspacePanelId> collect_dock_leaf_panels(const DockNodeSpec& root) {
    std::vector<WorkspacePanelId> panels;
    collect_leaf_panels_recursive(root, panels, 0u);
    return panels;
}

WorkspacePresetSpec build_workspace_preset(WorkspacePreset preset) {
    using P = WorkspacePanelId;

    switch (preset) {
        case WorkspacePreset::StaticReverseEngineering: {
            auto left = DockNodeSpec::make_leaf(
                {P::Structure, P::Functions, P::Symbols, P::Sections, P::Imports, P::Exports, P::Dependencies},
                P::Functions);
            auto center_top = DockNodeSpec::make_leaf(
                {P::Disassembly, P::FlowGraph, P::Decompiler},
                P::Disassembly);
            auto center_bottom = DockNodeSpec::make_leaf(
                {P::HexView, P::MemoryHeatmap, P::ByteEntropyViz, P::ReferencesAndNotes, P::Strings, P::SignaturesAndCrypto, P::PatchSet, P::Shellcode, P::Scripting, P::MemorySearch},
                P::HexView);
            auto right = DockNodeSpec::make_leaf(
                {P::Details, P::FileInfo, P::ExecutableSettings, P::TargetCapabilities,
                 P::StructureView, P::DataStructures, P::RuntimeAndFlags, P::Handlers,
                 P::PeHeaders, P::PeImports, P::PeExports, P::ClrMetadata},
                P::Details);
            auto bottom = DockNodeSpec::make_leaf({P::Log}, P::Log);

            auto center = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.72f, std::move(center_top), std::move(center_bottom));
            auto center_and_right = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.72f, std::move(center), std::move(right));
            auto main_columns = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.20f, std::move(left), std::move(center_and_right));
            auto root = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.87f, std::move(main_columns), std::move(bottom));
            return finalize_preset(preset, std::move(root));
        }

        case WorkspacePreset::LiveProcessAndVmmap: {
            auto left = DockNodeSpec::make_leaf(
                {P::Structure, P::Dependencies, P::FileInfo, P::ExecutableSettings, P::TargetCapabilities},
                P::Structure);
            auto center_top = DockNodeSpec::make_leaf(
                {P::MemoryMap, P::MemoryHeatmap, P::ByteEntropyViz},
                P::MemoryMap);
            auto center_bottom = DockNodeSpec::make_leaf(
                {P::HexView, P::Disassembly, P::MemorySearch, P::ExecutionTimeline},
                P::HexView);
            auto right = DockNodeSpec::make_leaf(
                {P::ProcessInternals, P::ThreadsAndStack, P::ThreadLocals,
                 P::RuntimeAndFlags, P::Handlers, P::Details, P::StructureView},
                P::ProcessInternals);
            auto bottom = DockNodeSpec::make_leaf({P::Log}, P::Log);

            auto center = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.56f, std::move(center_top), std::move(center_bottom));
            auto center_and_right = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.68f, std::move(center), std::move(right));
            auto main_columns = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.20f, std::move(left), std::move(center_and_right));
            auto root = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.87f, std::move(main_columns), std::move(bottom));
            return finalize_preset(preset, std::move(root));
        }

        case WorkspacePreset::Debugger: {
            auto left = DockNodeSpec::make_leaf(
                {P::Functions, P::Symbols, P::Structure, P::Sections},
                P::Functions);
            auto center_top = DockNodeSpec::make_leaf(
                {P::Disassembly, P::Decompiler, P::FlowGraph},
                P::Disassembly);
            auto center_bottom = DockNodeSpec::make_leaf(
                {P::ExecutionTimeline, P::HexView, P::MemoryMap, P::MemoryHeatmap, P::MemorySearch},
                P::ExecutionTimeline);
            auto right = DockNodeSpec::make_leaf(
                {P::Debugger, P::ThreadsAndStack, P::ThreadLocals, P::RuntimeAndFlags,
                 P::Handlers, P::Details, P::TargetCapabilities, P::ExecutableSettings},
                P::Debugger);
            auto bottom = DockNodeSpec::make_leaf({P::Log}, P::Log);

            auto center = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.68f, std::move(center_top), std::move(center_bottom));
            auto center_and_right = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.66f, std::move(center), std::move(right));
            auto main_columns = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.18f, std::move(left), std::move(center_and_right));
            auto root = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.86f, std::move(main_columns), std::move(bottom));
            return finalize_preset(preset, std::move(root));
        }

        case WorkspacePreset::BinaryDiff: {
            auto left = DockNodeSpec::make_leaf(
                {P::Sections, P::Functions, P::Symbols, P::Structure, P::Imports, P::Exports},
                P::Sections);
            auto center_top = DockNodeSpec::make_leaf(
                {P::BinaryDiff, P::Disassembly, P::Decompiler},
                P::BinaryDiff);
            auto center_bottom = DockNodeSpec::make_leaf(
                {P::HexView, P::ByteEntropyViz, P::ReferencesAndNotes, P::PatchSet},
                P::HexView);
            auto right = DockNodeSpec::make_leaf(
                {P::Details, P::FileInfo, P::ExecutableSettings, P::Dependencies, P::TargetCapabilities},
                P::Details);
            auto bottom = DockNodeSpec::make_leaf({P::Log}, P::Log);

            auto center = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.74f, std::move(center_top), std::move(center_bottom));
            auto center_and_right = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.74f, std::move(center), std::move(right));
            auto main_columns = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.19f, std::move(left), std::move(center_and_right));
            auto root = DockNodeSpec::make_split(
                DockSplitAxis::Vertical, 0.88f, std::move(main_columns), std::move(bottom));
            return finalize_preset(preset, std::move(root));
        }

        case WorkspacePreset::Minimal: {
            auto left = DockNodeSpec::make_leaf(
                {P::Structure},
                P::Structure);
            auto center = DockNodeSpec::make_leaf(
                {P::Disassembly, P::HexView},
                P::Disassembly);
            auto right = DockNodeSpec::make_leaf(
                {P::Details},
                P::Details);

            auto center_and_right = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.75f, std::move(center), std::move(right));
            auto root = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal, 0.20f, std::move(left), std::move(center_and_right));
            return finalize_preset(preset, std::move(root));
        }
    }

    return build_workspace_preset(WorkspacePreset::StaticReverseEngineering);
}

peelf::Result<void> validate_workspace_preset(const WorkspacePresetSpec& spec) {
    if (spec.display_name.empty()) {
        return peelf::make_error("WorkspacePresetSpec::display_name must not be empty");
    }
    if (spec.schema_version == 0u) {
        return peelf::make_error("WorkspacePresetSpec::schema_version must be non-zero");
    }
    if (spec.visible_panels.empty()) {
        return peelf::make_error("WorkspacePresetSpec::visible_panels must not be empty");
    }

    std::array<bool, kWorkspacePanelCount> seen_visible{};
    for (const WorkspacePanelId panel : spec.visible_panels) {
        if (!is_valid_panel_id(panel)) {
            return peelf::make_error("WorkspacePresetSpec::visible_panels contains invalid WorkspacePanelId");
        }
        const auto idx = static_cast<std::size_t>(panel);
        if (seen_visible[idx]) {
            return peelf::make_error(std::format(
                "Duplicate WorkspacePanelId '{}' in WorkspacePresetSpec::visible_panels",
                workspace_panel_window_name(panel)));
        }
        seen_visible[idx] = true;
    }

    std::array<bool, kWorkspacePanelCount> seen_in_leaves{};
    if (auto res = validate_dock_node_recursive(spec.root, spec.visible_panels, seen_in_leaves, 0u);
        !res) {
        return res;
    }

    for (const WorkspacePanelId panel : spec.visible_panels) {
        const auto idx = static_cast<std::size_t>(panel);
        if (!seen_in_leaves[idx]) {
            return peelf::make_error(std::format(
                "Visible panel '{}' is not assigned to any DockNodeSpec leaf",
                workspace_panel_window_name(panel)));
        }
    }

    return {};
}

PersistedWorkspaceLayoutMetadata parse_workspace_layout_metadata(
    std::string_view ini_text) noexcept {
    PersistedWorkspaceLayoutMetadata meta{};
    bool in_section = false;

    std::size_t pos = 0u;
    while (pos <= ini_text.size()) {
        const std::size_t nl = ini_text.find('\n', pos);
        const std::string_view raw_line =
            nl == std::string_view::npos ? ini_text.substr(pos) : ini_text.substr(pos, nl - pos);
        const std::string_view line = trim_ascii(raw_line);

        if (!line.empty() && line.front() != ';') {
            if (line.front() == '[' && line.back() == ']') {
                in_section = (line == "[WorkspaceLayout][State]");
                if (in_section) {
                    meta.has_metadata_section = true;
                }
            } else if (in_section) {
                const std::size_t eq = line.find('=');
                if (eq != std::string_view::npos) {
                    const std::string_view key = trim_ascii(line.substr(0u, eq));
                    const std::string_view val = trim_ascii(line.substr(eq + 1u));
                    if (key == "SchemaVersion") {
                        std::uint32_t parsed = 0u;
                        const auto [ptr, ec] =
                            std::from_chars(val.data(), val.data() + val.size(), parsed);
                        if (ec == std::errc{} && ptr == val.data() + val.size()) {
                            meta.schema_version = parsed;
                        }
                    } else if (key == "Preset") {
                        if (const auto preset = parse_workspace_preset_id(val)) {
                            meta.active_preset = *preset;
                        }
                    }
                }
            }
        }

        if (nl == std::string_view::npos) {
            break;
        }
        pos = nl + 1u;
    }

    return meta;
}

bool should_migrate_workspace_layout_ini(std::string_view ini_text) noexcept {
    if (ini_text.empty()) {
        return true;
    }
    const PersistedWorkspaceLayoutMetadata meta = parse_workspace_layout_metadata(ini_text);
    if (!meta.has_metadata_section) {
        return true;
    }
    return should_migrate_workspace_layout(meta.schema_version);
}

std::string stamp_workspace_layout_metadata(std::string_view ini_text,
                                            WorkspacePreset active_preset,
                                            std::uint32_t schema_version) {
    std::ostringstream out;
    bool skipping_old_section = false;

    std::size_t pos = 0u;
    while (pos <= ini_text.size()) {
        const std::size_t nl = ini_text.find('\n', pos);
        const std::string_view raw_line =
            nl == std::string_view::npos ? ini_text.substr(pos) : ini_text.substr(pos, nl - pos);
        const std::string_view trimmed = trim_ascii(raw_line);

        if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']') {
            skipping_old_section = (trimmed == "[WorkspaceLayout][State]");
        }
        if (!skipping_old_section) {
            out << trimmed << '\n';
        }

        if (nl == std::string_view::npos) {
            break;
        }
        pos = nl + 1u;
    }

    out << "[WorkspaceLayout][State]\n"
        << "SchemaVersion=" << schema_version << '\n'
        << "Preset=" << workspace_preset_id(active_preset) << '\n';
    return out.str();
}

} // namespace viewer
