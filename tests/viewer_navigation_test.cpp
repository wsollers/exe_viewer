#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "graph/call_graph.hpp"
#include "navigation/viewer_navigation.hpp"
#include <peelf/binary_image.hpp>

TEST(NavigationHistory, BackForwardAndBranchingPreserveSelections) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection a{.label="a", .file_offset=10, .virtual_address=0x1000, .size=4,
        .preferred_view=viewer::PreferredView::Graph};
    auto b = a; b.virtual_address=0x2000; b.file_offset=20;
    auto c = a; c.virtual_address=0x3000; c.file_offset=30;
    EXPECT_FALSE(history.back());
    history.visit(a); history.visit(b); history.visit(b);
    ASSERT_TRUE(history.can_back());
    const auto previous = history.back();
    ASSERT_TRUE(previous);
    EXPECT_EQ(previous->virtual_address,a.virtual_address);
    EXPECT_EQ(previous->size,4);
    EXPECT_EQ(previous->preferred_view,viewer::PreferredView::Graph);
    EXPECT_FALSE(history.can_back());
    ASSERT_TRUE(history.forward());
    ASSERT_TRUE(history.back());
    history.visit(c);
    EXPECT_FALSE(history.can_forward());
    EXPECT_EQ(history.back()->virtual_address,a.virtual_address);
    history.clear();
    EXPECT_FALSE(history.can_back()); EXPECT_FALSE(history.can_forward());
}

TEST(NavigationHistory, ViewChangesUpdateCurrentEntryAndHistoryIsBounded) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection selection{.file_offset=0, .virtual_address=0, .preferred_view=viewer::PreferredView::Graph};
    history.visit(selection);
    selection.preferred_view=viewer::PreferredView::Disassembly;
    history.visit(selection);
    EXPECT_FALSE(history.can_back());
    for (std::uint64_t i=1; i<300; ++i) {
        selection.file_offset=i; selection.virtual_address=i;
        history.visit(selection);
    }
    int count=0;
    while (history.back()) ++count;
    EXPECT_EQ(count,255);
    history.clear();
    history.visit({});
    EXPECT_FALSE(history.forward()); EXPECT_FALSE(history.back());
}

TEST(NavigationHistory, RetainsUnsymbolizedGraphOriginAcrossViewsAndOtherFunctions) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection block{.file_offset=0x40, .virtual_address=0x1040,
        .preferred_view=viewer::PreferredView::Graph,
        .graph_root=viewer::SymbolRecord{.name="sub_1000", .virtual_address=0x1000, .file_offset=0, .size=0}};
    history.visit(block);
    block.preferred_view=viewer::PreferredView::Disassembly;
    history.visit(block);
    auto callee=block;
    callee.virtual_address=0x2040;
    callee.file_offset=0x1040;
    callee.graph_root=viewer::SymbolRecord{.name="sub_2000", .virtual_address=0x2000, .file_offset=0x1000};
    history.visit(callee);
    const auto restored=history.back();
    ASSERT_TRUE(restored);
    ASSERT_TRUE(restored->graph_root);
    EXPECT_EQ(restored->virtual_address,0x1040);
    EXPECT_EQ(restored->graph_root->virtual_address,0x1000);
    EXPECT_EQ(restored->preferred_view,viewer::PreferredView::Disassembly);
    const auto next=history.forward();
    ASSERT_TRUE(next);
    ASSERT_TRUE(next->graph_root);
    EXPECT_EQ(next->graph_root->virtual_address,0x2000);
}

namespace {

[[nodiscard]] std::vector<std::uint8_t> read_fixture(const std::string& name) {
    const std::filesystem::path path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

[[nodiscard]] std::unique_ptr<peelf::IBinaryImage> parse_fixture(const std::string& name) {
    std::vector<std::uint8_t> bytes = read_fixture(name);
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    EXPECT_TRUE(parsed.has_value()) << name;
    if (!parsed) {
        return {};
    }
    return std::move(*parsed);
}

[[nodiscard]] const viewer::StructureNode* find_child(const viewer::StructureNode& node,
                                                      const std::string& label) {
    const auto it = std::ranges::find_if(node.children, [&](const viewer::StructureNode& child) {
        return child.selection.label == label;
    });
    return it == node.children.end() ? nullptr : &*it;
}

[[nodiscard]] const viewer::StructureNode* find_kind(const viewer::StructureNode& node,
                                                     viewer::SelectionKind kind) {
    if (node.selection.kind == kind) {
        return &node;
    }
    for (const viewer::StructureNode& child : node.children) {
        if (const viewer::StructureNode* found = find_kind(child, kind)) {
            return found;
        }
    }
    return nullptr;
}

} // namespace

TEST(ViewerNavigation, BuildsElfStructureTreeWithSelectableExecutableSection) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);

    const viewer::StructureNode tree = viewer::build_structure_tree(*image);

    EXPECT_EQ(tree.selection.kind, viewer::SelectionKind::Image);
    EXPECT_EQ(tree.selection.label, "ELF Image");
    ASSERT_TRUE(tree.selection.virtual_address.has_value());
    EXPECT_EQ(*tree.selection.virtual_address, image->entry_point());

    const viewer::StructureNode* headers = find_child(tree, "Headers");
    ASSERT_NE(headers, nullptr);
    EXPECT_NE(find_child(*headers, "ELF File Header"), nullptr);

    const viewer::StructureNode* sections = find_child(tree, "Sections");
    ASSERT_NE(sections, nullptr);
    const viewer::StructureNode* text = find_child(*sections, ".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->selection.kind, viewer::SelectionKind::Section);
    EXPECT_EQ(text->selection.preferred_view, viewer::PreferredView::Disassembly);
    ASSERT_TRUE(text->selection.file_offset.has_value());
    ASSERT_TRUE(text->selection.virtual_address.has_value());
    EXPECT_GT(text->selection.size, 0u);

    EXPECT_NE(find_child(tree, "Segments"), nullptr);
    EXPECT_NE(find_child(tree, "Dynamic Entries"), nullptr);
    EXPECT_NE(find_child(tree, "Relocations"), nullptr);
    EXPECT_NE(find_child(tree, "Notes"), nullptr);
    EXPECT_NE(find_child(tree, "Hash Tables"), nullptr);
    EXPECT_NE(find_kind(tree, viewer::SelectionKind::Symbol), nullptr);
}

TEST(ViewerNavigation, BuildsPeStructureTreeWithRelocationAndDebugSelections) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::StructureNode tree = viewer::build_structure_tree(*image);

    EXPECT_EQ(tree.selection.kind, viewer::SelectionKind::Image);
    EXPECT_EQ(tree.selection.label, "PE Image");

    const viewer::StructureNode* headers = find_child(tree, "Headers");
    ASSERT_NE(headers, nullptr);
    EXPECT_NE(find_child(*headers, "DOS Header"), nullptr);
    EXPECT_NE(find_child(*headers, "PE/COFF Headers"), nullptr);

    const viewer::StructureNode* sections = find_child(tree, "Sections");
    ASSERT_NE(sections, nullptr);
    EXPECT_NE(find_child(*sections, ".text"), nullptr);

    const viewer::StructureNode* imports = find_child(tree, "Imports");
    ASSERT_NE(imports, nullptr);
    EXPECT_NE(find_child(*imports, "USER32.dll!MessageBoxA (delay)"), nullptr);

    const viewer::StructureNode* relocations = find_child(tree, "Base Relocations");
    ASSERT_NE(relocations, nullptr);
    ASSERT_FALSE(relocations->children.empty());
    EXPECT_EQ(relocations->children.front().selection.kind, viewer::SelectionKind::Relocation);
    EXPECT_EQ(relocations->children.front().selection.preferred_view, viewer::PreferredView::Details);
    EXPECT_GT(relocations->children.front().selection.size, 0u);

    const viewer::StructureNode* debug = find_child(tree, "Debug Directories");
    ASSERT_NE(debug, nullptr);
    ASSERT_FALSE(debug->children.empty());
    EXPECT_EQ(debug->children.front().selection.kind, viewer::SelectionKind::DebugDirectory);
    EXPECT_TRUE(debug->children.front().selection.file_offset.has_value());
    EXPECT_GT(debug->children.front().selection.size, 0u);

    const viewer::StructureNode* runtime_functions = find_child(tree, "Runtime Functions");
    ASSERT_NE(runtime_functions, nullptr);
    ASSERT_FALSE(runtime_functions->children.empty());
    EXPECT_EQ(runtime_functions->children.front().selection.kind, viewer::SelectionKind::RuntimeFunction);
    EXPECT_TRUE(runtime_functions->children.front().selection.file_offset.has_value());
    EXPECT_GT(runtime_functions->children.front().selection.size, 0u);

    const viewer::StructureNode* tls = find_child(tree, "TLS Directory");
    ASSERT_NE(tls, nullptr);
    EXPECT_EQ(tls->selection.kind, viewer::SelectionKind::TlsDirectory);
    EXPECT_TRUE(tls->selection.virtual_address.has_value());

    const viewer::StructureNode* certificates = find_child(tree, "Certificates");
    ASSERT_NE(certificates, nullptr);
    ASSERT_FALSE(certificates->children.empty());
    EXPECT_EQ(certificates->children.front().selection.kind, viewer::SelectionKind::Certificate);
    EXPECT_TRUE(certificates->children.front().selection.file_offset.has_value());
    EXPECT_GT(certificates->children.front().selection.size, 0u);

    const viewer::StructureNode* load_config = find_child(tree, "Load Config");
    ASSERT_NE(load_config, nullptr);
    EXPECT_EQ(load_config->selection.kind, viewer::SelectionKind::LoadConfig);
    EXPECT_TRUE(load_config->selection.file_offset.has_value());
    EXPECT_GT(load_config->selection.size, 0u);

    const viewer::StructureNode* bound_imports = find_child(tree, "Bound Imports");
    ASSERT_NE(bound_imports, nullptr);
    ASSERT_FALSE(bound_imports->children.empty());
    EXPECT_EQ(bound_imports->children.front().selection.kind, viewer::SelectionKind::BoundImport);
    EXPECT_TRUE(bound_imports->children.front().selection.file_offset.has_value());
    EXPECT_GT(bound_imports->children.front().selection.size, 0u);

    const viewer::StructureNode* resource = find_child(tree, "Resource Directory");
    ASSERT_NE(resource, nullptr);
    EXPECT_EQ(resource->selection.kind, viewer::SelectionKind::ResourceDirectory);
    EXPECT_TRUE(resource->selection.file_offset.has_value());
    EXPECT_GT(resource->selection.size, 0u);
    ASSERT_FALSE(resource->children.empty());
    EXPECT_EQ(resource->children.front().selection.kind, viewer::SelectionKind::ResourceData);
    EXPECT_TRUE(resource->children.front().selection.file_offset.has_value());
    EXPECT_EQ(resource->children.front().selection.size, 0x10u);

    const viewer::StructureNode* clr = find_child(tree, "CLR Header");
    ASSERT_NE(clr, nullptr);
    EXPECT_EQ(clr->selection.kind, viewer::SelectionKind::ClrHeader);
    EXPECT_TRUE(clr->selection.file_offset.has_value());
    EXPECT_EQ(clr->selection.size, 0x48u);
}

TEST(ViewerNavigation, BuildsSelectionPayloadFromCallGraphFunctionNode) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraphNode node{
        .id = "root",
        .label = "known_export",
        .kind = viewer::CallGraphNodeKind::Function,
        .bytes = viewer::GraphByteRange{
            .start = viewer::GraphAddress{
                .virtual_address = 0x140001000,
            },
            .size = 0x10,
        },
        .symbol = viewer::GraphSymbolRef{
            .name = "known_export",
            .symbol_index = 3,
        },
    };

    const viewer::ViewerSelection selection = viewer::selection_from_call_graph_node(node, *image);

    EXPECT_EQ(selection.kind, viewer::SelectionKind::CallGraphNode);
    EXPECT_EQ(selection.label, "known_export");
    EXPECT_EQ(selection.preferred_view, viewer::PreferredView::Disassembly);
    EXPECT_EQ(selection.object_index, 3u);
    ASSERT_TRUE(selection.virtual_address.has_value());
    EXPECT_EQ(*selection.virtual_address, 0x140001000u);
    ASSERT_TRUE(selection.file_offset.has_value());
    EXPECT_EQ(*selection.file_offset, 0x220u);
    EXPECT_EQ(selection.size, 0x10u);
}

TEST(ViewerNavigation, BuildsDetailsOnlySelectionForUnmappedCallGraphNode) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraphNode node{
        .id = "imports_summary",
        .label = "Imports",
        .kind = viewer::CallGraphNodeKind::Import,
    };

    const viewer::ViewerSelection selection = viewer::selection_from_call_graph_node(node, *image);

    EXPECT_EQ(selection.kind, viewer::SelectionKind::CallGraphNode);
    EXPECT_EQ(selection.label, "Imports");
    EXPECT_EQ(selection.preferred_view, viewer::PreferredView::Details);
    EXPECT_FALSE(selection.file_offset.has_value());
    EXPECT_FALSE(selection.virtual_address.has_value());
    EXPECT_EQ(selection.size, 0u);
}

TEST(ViewerNavigation, MapsSymbolAndCallGraphSelectionsToSymbolRows) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);
    const auto symbol_it = std::ranges::find_if(image->symbols(), [](const peelf::Symbol& symbol) {
        return !symbol.name.empty() && symbol.virtual_address != 0;
    });
    ASSERT_NE(symbol_it, image->symbols().end());
    const std::uint64_t symbol_index = static_cast<std::uint64_t>(std::distance(image->symbols().begin(), symbol_it));

    const viewer::ViewerSelection symbol_selection{
        .kind = viewer::SelectionKind::Symbol,
        .label = symbol_it->name,
        .object_index = symbol_index,
    };
    EXPECT_EQ(viewer::selected_symbol_index(symbol_selection, *image), symbol_index);

    const viewer::ViewerSelection graph_selection{
        .kind = viewer::SelectionKind::CallGraphNode,
        .label = symbol_it->name,
        .virtual_address = symbol_it->virtual_address,
        .object_index = symbol_index,
    };
    EXPECT_EQ(viewer::selected_symbol_index(graph_selection, *image), symbol_index);
}

TEST(ViewerNavigation, DoesNotMapUnresolvedCallGraphSelectionToFirstSymbol) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);
    ASSERT_FALSE(image->symbols().empty());

    const viewer::ViewerSelection graph_selection{
        .kind = viewer::SelectionKind::CallGraphNode,
        .label = "Imports",
        .object_index = 0,
    };

    EXPECT_EQ(viewer::selected_symbol_index(graph_selection, *image), std::nullopt);
}
