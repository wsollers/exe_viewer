#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

#include "symbols/symbol_index.hpp"

namespace viewer {

enum class PreferredView : std::uint8_t {
    Details,
    Hex,
    Disassembly,
    Graph
};

enum class SelectionKind : std::uint8_t {
    None,
    Image,
    Header,
    Section,
    Segment,
    Import,
    Export,
    Symbol,
    Relocation,
    DebugDirectory,
    RuntimeFunction,
    TlsDirectory,
    Certificate,
    LoadConfig,
    BoundImport,
    ResourceDirectory,
    ResourceData,
    ClrHeader,
    DynamicEntry,
    Note,
    HashTable,
    Interpreter,
    CallGraphNode,
    Patch,
    ByteRange,
    Process,
    ProcessModule,
    MemoryRegion,
    Group
};

struct ViewerSelection {
    SelectionKind kind = SelectionKind::None;
    std::string label;
    std::optional<std::uint64_t> file_offset;
    std::optional<std::uint64_t> virtual_address;
    std::uint64_t size = 0;
    std::uint64_t object_index = 0;
    PreferredView preferred_view = PreferredView::Details;
    // Keep the analysis origin independently of the selected interior instruction.
    std::optional<SymbolRecord> graph_root;
};

// Headless navigation state. Revisiting the current address does not add noise;
// navigating after Back drops the abandoned forward branch.
class NavigationHistory {
public:
    void visit(const ViewerSelection& selection);
    [[nodiscard]] std::optional<ViewerSelection> back();
    [[nodiscard]] std::optional<ViewerSelection> forward();
    [[nodiscard]] bool can_back() const noexcept { return !entries_.empty() && cursor_ > 0; }
    [[nodiscard]] bool can_forward() const noexcept { return cursor_ + 1 < entries_.size(); }
    void clear() noexcept { entries_.clear(); cursor_ = 0; }
    [[nodiscard]] const std::vector<ViewerSelection>& entries() const noexcept { return entries_; }
    [[nodiscard]] std::size_t cursor() const noexcept { return cursor_; }
    bool restore(std::vector<ViewerSelection> entries, std::size_t cursor) {
        if (entries.size() > 256 || (entries.empty() ? cursor != 0 : cursor >= entries.size())) return false;
        entries_ = std::move(entries); cursor_ = cursor; return true;
    }
private:
    std::vector<ViewerSelection> entries_;
    std::size_t cursor_ = 0;
};

struct StructureNode {
    ViewerSelection selection;
    std::vector<StructureNode> children;
};

[[nodiscard]] StructureNode build_structure_tree(const peelf::IBinaryImage& image);
[[nodiscard]] StructureNode build_live_process_structure_tree(
    const peelf::ProcessInfo& process,
    std::span<const peelf::ModuleInfo> modules,
    std::span<const peelf::MemoryRegion> regions,
    const peelf::IBinaryImage* active_image,
    std::optional<std::size_t> active_module_index = std::nullopt);
struct CallGraphNode;
[[nodiscard]] ViewerSelection selection_from_call_graph_node(const CallGraphNode& node,
                                                            const peelf::IBinaryImage& image);
[[nodiscard]] ViewerSelection selection_from_patch_interval(const peelf::PatchInterval& patch,
                                                            std::uint64_t patch_index);
[[nodiscard]] ViewerSelection selection_from_live_patch_interval(
    const peelf::PatchInterval& patch,
    std::uint64_t patch_index,
    std::optional<std::uint64_t> window_offset,
    std::string_view prefix = "Staged");
[[nodiscard]] ViewerSelection selection_from_memory_region(
    const peelf::MemoryRegion& region,
    std::uint64_t region_index,
    std::optional<std::uint64_t> window_offset = std::nullopt);
[[nodiscard]] ViewerSelection selection_from_symbol_record(
    const SymbolRecord& record,
    std::uint64_t record_index);
[[nodiscard]] std::optional<std::uint64_t> selected_symbol_index(const ViewerSelection& selection,
                                                                 const peelf::IBinaryImage& image);
[[nodiscard]] std::optional<std::uint64_t> selected_symbol_record_index(
    const ViewerSelection& selection,
    const SymbolIndex& symbol_index);

} // namespace viewer
