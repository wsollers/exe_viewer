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

#include "navigation/viewer_navigation.hpp"
#include <peelf/binary_image.hpp>

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

    const viewer::StructureNode* clr = find_child(tree, "CLR Header");
    ASSERT_NE(clr, nullptr);
    EXPECT_EQ(clr->selection.kind, viewer::SelectionKind::ClrHeader);
    EXPECT_TRUE(clr->selection.file_offset.has_value());
    EXPECT_EQ(clr->selection.size, 0x48u);
}
