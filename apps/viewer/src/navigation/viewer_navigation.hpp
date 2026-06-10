#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <peelf/binary_image.hpp>

namespace viewer {

enum class PreferredView : std::uint8_t {
    Details,
    Hex,
    Disassembly
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
};

struct StructureNode {
    ViewerSelection selection;
    std::vector<StructureNode> children;
};

[[nodiscard]] StructureNode build_structure_tree(const peelf::IBinaryImage& image);
struct CallGraphNode;
[[nodiscard]] ViewerSelection selection_from_call_graph_node(const CallGraphNode& node,
                                                            const peelf::IBinaryImage& image);

} // namespace viewer
