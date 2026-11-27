#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "graph/call_graph.hpp"
#include "headless_cli.hpp"
#include <cstdlib>
#include <sstream>
#include "navigation/viewer_navigation.hpp"
#include "symbols/debug_symbols.hpp"
#include "ui/panel_helpers.hpp"
#include <peelf/binary_image.hpp>

TEST(CallGraphRelations, SeparatesDirectionsDeduplicatesAndPreservesRecursion) {
    viewer::CallGraph graph;
    graph.edges = {
        {.from_node_id="a", .to_node_id="b", .kind=viewer::CallGraphEdgeKind::Call},
        {.from_node_id="a", .to_node_id="b", .kind=viewer::CallGraphEdgeKind::Call},
        {.from_node_id="a", .to_node_id="a", .kind=viewer::CallGraphEdgeKind::Call},
        {.from_node_id="b", .to_node_id="c", .kind=viewer::CallGraphEdgeKind::Fallthrough}
    };
    EXPECT_EQ(viewer::call_neighbors(graph, "a", false), (std::vector<std::string>{"b", "a"}));
    EXPECT_EQ(viewer::call_neighbors(graph, "b", true), (std::vector<std::string>{"a"}));
    EXPECT_TRUE(viewer::call_neighbors(graph, "c", true).empty());
    EXPECT_TRUE(viewer::call_neighbors(graph, "missing", false).empty());
}

namespace {

class FakeProcessRunner final : public viewer::IProcessRunner {
public:
    [[nodiscard]] viewer::GraphRenderResult run(std::string_view executable,
                                                std::span<const std::string> arguments) const override {
        executable_ = std::string(executable);
        arguments_.assign(arguments.begin(), arguments.end());
        return result_;
    }

    mutable std::string executable_;
    mutable std::vector<std::string> arguments_;
    viewer::GraphRenderResult result_{.success = true, .exit_code = 0, .diagnostic = {}};
};

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

[[nodiscard]] std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

[[nodiscard]] std::unique_ptr<peelf::IBinaryImage> parse_file(const std::filesystem::path& path) {
    std::vector<std::uint8_t> bytes = read_file(path);
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    EXPECT_TRUE(parsed.has_value()) << path.string();
    if (!parsed) {
        return {};
    }
    return std::move(*parsed);
}

[[nodiscard]] const viewer::SymbolRecord* find_symbol_containing(const viewer::SymbolIndex& index,
                                                                 std::string_view needle) {
    const auto records = index.records();
    const auto it = std::ranges::find_if(records, [&](const viewer::SymbolRecord& record) {
        return record.name.find(needle) != std::string::npos;
    });
    return it == records.end() ? nullptr : &*it;
}

[[nodiscard]] const viewer::CallGraphNode* find_node(const viewer::CallGraph& graph,
                                                     std::string_view id) {
    const auto it = std::ranges::find_if(graph.nodes, [&](const viewer::CallGraphNode& node) {
        return node.id == id;
    });
    return it == graph.nodes.end() ? nullptr : &*it;
}

[[nodiscard]] bool has_edge(const viewer::CallGraph& graph,
                            std::string_view from,
                            std::string_view to,
                            viewer::CallGraphEdgeKind kind) {
    return std::ranges::any_of(graph.edges, [&](const viewer::CallGraphEdge& edge) {
        return edge.from_node_id == from && edge.to_node_id == to && edge.kind == kind;
    });
}

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value, peelf::Endianness endian) {
    ASSERT_LE(offset + 4u, bytes.size());
    if (endian == peelf::Endianness::Big) {
        bytes[offset] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
        bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
        bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
        bytes[offset + 3u] = static_cast<std::uint8_t>(value & 0xFFu);
    } else {
        bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
        bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
        bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
        bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
    }
}

[[nodiscard]] std::uint32_t encode_riscv_jal(std::int64_t offset) {
    const auto imm = static_cast<std::uint32_t>(offset);
    return 0x000000EFu |
           ((imm & 0x00100000u) << 11u) |
           ((imm & 0x000007FEu) << 20u) |
           ((imm & 0x00000800u) << 9u) |
           (imm & 0x000FF000u);
}

void patch_direct_call(std::vector<std::uint8_t>& bytes,
                       const peelf::IBinaryImage& image,
                       std::uint64_t root_va,
                       std::uint64_t target_va) {
    const std::optional<std::uint64_t> root_file_offset = image.virtual_address_to_file_offset(root_va);
    ASSERT_TRUE(root_file_offset);
    const std::size_t root = static_cast<std::size_t>(*root_file_offset);
    ASSERT_LE(root + 8u, bytes.size());

    switch (image.architecture()) {
        case peelf::Architecture::X86:
        case peelf::Architecture::X86_64: {
            const std::int64_t rel64 =
                static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(root_va + 5u);
            ASSERT_GE(rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()));
            ASSERT_LE(rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()));
            const auto rel32 = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel64));
            bytes[root] = 0xE8u;
            bytes[root + 1u] = static_cast<std::uint8_t>(rel32 & 0xFFu);
            bytes[root + 2u] = static_cast<std::uint8_t>((rel32 >> 8u) & 0xFFu);
            bytes[root + 3u] = static_cast<std::uint8_t>((rel32 >> 16u) & 0xFFu);
            bytes[root + 4u] = static_cast<std::uint8_t>((rel32 >> 24u) & 0xFFu);
            bytes[root + 5u] = 0xC3u;
            break;
        }
        case peelf::Architecture::ARM: {
            ASSERT_EQ(image.endianness(), peelf::Endianness::Little);
            const std::int64_t offset = static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(root_va + 8u);
            ASSERT_EQ(offset % 4, 0);
            const auto imm24 = static_cast<std::uint32_t>((offset / 4) & 0x00FFFFFF);
            write_u32(bytes, root, 0xEB000000u | imm24, image.endianness());
            write_u32(bytes, root + 4u, 0xE12FFF1Eu, image.endianness());
            break;
        }
        case peelf::Architecture::ARM64: {
            ASSERT_EQ(image.endianness(), peelf::Endianness::Little);
            const std::int64_t offset = static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(root_va);
            ASSERT_EQ(offset % 4, 0);
            const auto imm26 = static_cast<std::uint32_t>((offset / 4) & 0x03FFFFFF);
            write_u32(bytes, root, 0x94000000u | imm26, image.endianness());
            write_u32(bytes, root + 4u, 0xD65F03C0u, image.endianness());
            break;
        }
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64: {
            ASSERT_EQ(image.endianness(), peelf::Endianness::Little);
            const std::int64_t offset = static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(root_va);
            ASSERT_EQ(offset % 2, 0);
            write_u32(bytes, root, encode_riscv_jal(offset), image.endianness());
            write_u32(bytes, root + 4u, 0x00008067u, image.endianness());
            break;
        }
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64: {
            ASSERT_EQ(image.endianness(), peelf::Endianness::Big);
            const std::uint32_t word = 0x0C000000u | static_cast<std::uint32_t>((target_va >> 2u) & 0x03FFFFFFu);
            write_u32(bytes, root, word, image.endianness());
            write_u32(bytes, root + 4u, 0x00000000u, image.endianness());
            break;
        }
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64: {
            ASSERT_EQ(image.endianness(), peelf::Endianness::Big);
            const std::int64_t offset = static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(root_va);
            ASSERT_GE(offset, -0x02000000);
            ASSERT_LT(offset, 0x02000000);
            const auto li = static_cast<std::uint32_t>(offset) & 0x03FFFFFCu;
            write_u32(bytes, root, 0x48000001u | li, image.endianness());
            write_u32(bytes, root + 4u, 0x4E800020u, image.endianness());
            break;
        }
        default:
            FAIL() << "unsupported architecture for direct-call patch";
    }
}

struct BinMatrixCase {
    const char* fixture_stem;
    peelf::Architecture architecture;
    peelf::Endianness endianness;
    bool is_64bit;
};

[[nodiscard]] std::filesystem::path bin_matrix_sidecar_path(const std::filesystem::path& image_path) {
    if (image_path.extension() == ".so" || image_path.extension() == ".dll") {
        return std::filesystem::path(image_path.string() + ".debug");
    }
    std::filesystem::path sidecar = image_path;
    sidecar.replace_extension(".debug");
    return sidecar;
}

void assert_known_callgraph_fixture(const BinMatrixCase& fixture) {
    const std::string name = std::string(fixture.fixture_stem) + ".elf";
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
    const std::filesystem::path sidecar = bin_matrix_sidecar_path(path);
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();
    ASSERT_TRUE(std::filesystem::exists(sidecar)) << sidecar.string();
    const std::vector<std::uint8_t> bytes = read_file(path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(path);
    ASSERT_NE(image, nullptr);
    ASSERT_EQ(image->format(), peelf::Format::ELF) << name;
    ASSERT_EQ(image->architecture(), fixture.architecture) << name;
    ASSERT_EQ(image->endianness(), fixture.endianness) << name;
    ASSERT_EQ(image->is_64bit(), fixture.is_64bit) << name;
    ASSERT_NE(image->entry_point(), 0U) << name;
    ASSERT_TRUE(image->virtual_address_to_file_offset(image->entry_point()).has_value()) << name;

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* main = index.find_by_name("main");
    const viewer::SymbolRecord* first = index.find_by_name("first");
    const viewer::SymbolRecord* second = index.find_by_name("second");
    const viewer::SymbolRecord* leaf = index.find_by_name("leaf");
    ASSERT_NE(main, nullptr) << name;
    ASSERT_NE(first, nullptr) << name;
    ASSERT_NE(second, nullptr) << name;
    ASSERT_NE(leaf, nullptr) << name;

    const viewer::CallGraph main_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string main_dot = viewer::to_dot(main_graph);
    EXPECT_NE(main_dot.find("main fan-out"), std::string::npos) << name << "\n" << main_dot;
    EXPECT_NE(main_dot.find("first"), std::string::npos) << name << "\n" << main_dot;
    EXPECT_NE(main_dot.find("second"), std::string::npos) << name << "\n" << main_dot;
    EXPECT_EQ(main_dot.find("call target\\n0x"), std::string::npos) << name << "\n" << main_dot;

    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);
    EXPECT_NE(first_dot.find("first fan-out"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_NE(first_dot.find("leaf"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos) << name << "\n" << first_dot;
}

void assert_known_function_cfg_fixture(const BinMatrixCase& fixture) {
    const std::string name = std::string(fixture.fixture_stem) + ".elf";
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();
    const std::vector<std::uint8_t> bytes = read_file(path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(path);
    ASSERT_NE(image, nullptr);
    ASSERT_EQ(image->architecture(), fixture.architecture) << name;
    ASSERT_EQ(image->endianness(), fixture.endianness) << name;

    const viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* first = index.find_by_name("first");
    ASSERT_NE(first, nullptr) << name;
    ASSERT_TRUE(first->virtual_address) << name;
    ASSERT_TRUE(first->file_offset) << name;
    ASSERT_GT(first->size, 0u) << name;
    ASSERT_LE(*first->file_offset, bytes.size()) << name;
    ASSERT_LE(first->size, static_cast<std::uint64_t>(bytes.size() - static_cast<std::size_t>(*first->file_offset))) << name;

    const std::size_t start = static_cast<std::size_t>(*first->file_offset);
    const std::size_t size = static_cast<std::size_t>(first->size);
    const viewer::CallGraph cfg = viewer::build_function_cfg_call_graph(
        std::span<const std::uint8_t>(bytes.data() + start, size),
        *first->virtual_address,
        image->architecture(),
        image->endianness(),
        *first->file_offset,
        name + " first CFG");

    EXPECT_EQ(cfg.architecture, fixture.architecture) << name;
    EXPECT_EQ(cfg.endianness, fixture.endianness) << name;
    for (const auto& node : cfg.nodes) {
        if (node.kind != viewer::CallGraphNodeKind::BasicBlock) continue;
        ASSERT_EQ(node.instructions.size(), node.instruction_count) << name;
        ASSERT_FALSE(node.instructions.empty()) << name;
        EXPECT_EQ(node.instructions.front().address, node.bytes.start.virtual_address) << name;
        for (const auto& instruction : node.instructions) {
            EXPECT_FALSE(instruction.mnemonic.empty()) << name;
            EXPECT_GE(instruction.address, *node.bytes.start.virtual_address) << name;
            EXPECT_LT(instruction.address - *node.bytes.start.virtual_address, node.bytes.size) << name;
        }
    }
    EXPECT_FALSE(cfg.nodes.empty()) << name;
    EXPECT_NE(find_node(cfg, "bb_0"), nullptr) << name;
    EXPECT_TRUE(std::ranges::any_of(cfg.nodes, [](const viewer::CallGraphNode& node) {
        return node.kind == viewer::CallGraphNodeKind::BasicBlock &&
               node.bytes.start.virtual_address &&
               node.bytes.start.file_offset &&
               node.bytes.size != 0 &&
               node.instruction_count != 0;
    })) << name;
    EXPECT_TRUE(std::ranges::any_of(cfg.edges, [](const viewer::CallGraphEdge& edge) {
        return edge.kind == viewer::CallGraphEdgeKind::Return;
    })) << name << "\n" << viewer::to_dot(cfg);
}

void assert_known_shared_library_fixture(const BinMatrixCase& fixture) {
    const std::string name = std::string(fixture.fixture_stem) + ".so";
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
    const std::filesystem::path sidecar = bin_matrix_sidecar_path(path);
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();
    ASSERT_TRUE(std::filesystem::exists(sidecar)) << sidecar.string();
    const std::vector<std::uint8_t> bytes = read_file(path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(path);
    ASSERT_NE(image, nullptr);
    ASSERT_EQ(image->format(), peelf::Format::ELF) << name;
    ASSERT_EQ(image->kind(), peelf::ImageKind::SharedLibrary) << name;
    ASSERT_EQ(image->architecture(), fixture.architecture) << name;
    ASSERT_EQ(image->endianness(), fixture.endianness) << name;
    ASSERT_EQ(image->is_64bit(), fixture.is_64bit) << name;

    const auto libc = std::ranges::find_if(image->imports(), [](const peelf::ImportEntry& entry) {
        return entry.library == "libc.so.6";
    });
    ASSERT_NE(libc, image->imports().end()) << name;

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* first = index.find_by_name("first");
    const viewer::SymbolRecord* second = index.find_by_name("second");
    const viewer::SymbolRecord* leaf = index.find_by_name("leaf");
    const viewer::SymbolRecord* shared_anchor = index.find_by_name("shared_anchor");
    ASSERT_NE(first, nullptr) << name;
    ASSERT_NE(second, nullptr) << name;
    ASSERT_NE(leaf, nullptr) << name;
    ASSERT_NE(shared_anchor, nullptr) << name;
    EXPECT_GT(first->size, 0u) << name;
    EXPECT_GT(second->size, 0u) << name;
    EXPECT_GT(leaf->size, 0u) << name;
    EXPECT_GT(shared_anchor->size, 0u) << name;
    EXPECT_LT(shared_anchor->size, 0x100u) << name;
    EXPECT_GT(first->size, 0u) << name;
    EXPECT_GT(second->size, 0u) << name;
    EXPECT_GT(leaf->size, 0u) << name;
    EXPECT_GT(shared_anchor->size, 0u) << name;
    EXPECT_LT(shared_anchor->size, 0x100u) << name;

    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);
    EXPECT_NE(first_dot.find("first fan-out"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_NE(first_dot.find("leaf"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos) << name << "\n" << first_dot;

    const viewer::CallGraph anchor_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *shared_anchor);
    const std::string anchor_dot = viewer::to_dot(anchor_graph);
    EXPECT_NE(anchor_dot.find("shared_anchor fan-out"), std::string::npos) << name << "\n" << anchor_dot;
    EXPECT_NE(anchor_dot.find("first"), std::string::npos) << name << "\n" << anchor_dot;
    EXPECT_NE(anchor_dot.find("second"), std::string::npos) << name << "\n" << anchor_dot;
    if (fixture.is_64bit) {
        EXPECT_EQ(anchor_dot.find("call target\\n0x"), std::string::npos) << name << "\n" << anchor_dot;
    }
}

void assert_known_pe_dll_fixture(const BinMatrixCase& fixture) {
    const std::string name = std::string(fixture.fixture_stem) + ".dll";
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
    const std::filesystem::path sidecar = bin_matrix_sidecar_path(path);
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();
    ASSERT_TRUE(std::filesystem::exists(sidecar)) << sidecar.string();
    const std::vector<std::uint8_t> bytes = read_file(path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(path);
    ASSERT_NE(image, nullptr);
    ASSERT_EQ(image->format(), peelf::Format::PE) << name;
    ASSERT_EQ(image->kind(), peelf::ImageKind::SharedLibrary) << name;
    ASSERT_EQ(image->architecture(), fixture.architecture) << name;
    ASSERT_EQ(image->endianness(), fixture.endianness) << name;
    ASSERT_EQ(image->is_64bit(), fixture.is_64bit) << name;
    ASSERT_FALSE(image->imports().empty()) << name;

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* first = index.find_by_name("first");
    const viewer::SymbolRecord* second = index.find_by_name("second");
    const viewer::SymbolRecord* leaf = index.find_by_name("leaf");
    const viewer::SymbolRecord* shared_anchor = index.find_by_name("shared_anchor");
    ASSERT_NE(first, nullptr) << name;
    ASSERT_NE(second, nullptr) << name;
    ASSERT_NE(leaf, nullptr) << name;
    ASSERT_NE(shared_anchor, nullptr) << name;

    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);
    EXPECT_NE(first_dot.find("first fan-out"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_NE(first_dot.find("leaf"), std::string::npos) << name << "\n" << first_dot;
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos) << name << "\n" << first_dot;

    const viewer::CallGraph anchor_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *shared_anchor);
    const std::string anchor_dot = viewer::to_dot(anchor_graph);
    EXPECT_NE(anchor_dot.find("shared_anchor fan-out"), std::string::npos) << name << "\n" << anchor_dot;
    EXPECT_NE(anchor_dot.find("first"), std::string::npos) << name << "\n" << anchor_dot;
    EXPECT_NE(anchor_dot.find("second"), std::string::npos) << name << "\n" << anchor_dot;
    if (fixture.is_64bit) {
        EXPECT_EQ(anchor_dot.find("call target\\n0x"), std::string::npos) << name << "\n" << anchor_dot;
    }
}

void assert_known_pe_dll_cfg_fixture(const BinMatrixCase& fixture) {
    const std::string name = std::string(fixture.fixture_stem) + ".dll";
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();
    const std::vector<std::uint8_t> bytes = read_file(path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(path);
    ASSERT_NE(image, nullptr);
    ASSERT_EQ(image->format(), peelf::Format::PE) << name;
    ASSERT_EQ(image->kind(), peelf::ImageKind::SharedLibrary) << name;
    ASSERT_EQ(image->architecture(), fixture.architecture) << name;
    ASSERT_EQ(image->endianness(), fixture.endianness) << name;

    const viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* first = index.find_by_name("first");
    ASSERT_NE(first, nullptr) << name;
    ASSERT_TRUE(first->virtual_address) << name;
    ASSERT_TRUE(first->file_offset) << name;
    ASSERT_GT(first->size, 0u) << name;
    ASSERT_LE(*first->file_offset, bytes.size()) << name;
    ASSERT_LE(first->size, static_cast<std::uint64_t>(bytes.size() - static_cast<std::size_t>(*first->file_offset))) << name;

    const std::size_t start = static_cast<std::size_t>(*first->file_offset);
    const std::size_t size = static_cast<std::size_t>(first->size);
    const viewer::CallGraph cfg = viewer::build_function_cfg_call_graph(
        std::span<const std::uint8_t>(bytes.data() + start, size),
        *first->virtual_address,
        image->architecture(),
        image->endianness(),
        *first->file_offset,
        name + " first CFG");

    EXPECT_EQ(cfg.architecture, fixture.architecture) << name;
    EXPECT_EQ(cfg.endianness, fixture.endianness) << name;
    EXPECT_NE(find_node(cfg, "bb_0"), nullptr) << name;
    EXPECT_TRUE(std::ranges::any_of(cfg.nodes, [](const viewer::CallGraphNode& node) {
        return node.kind == viewer::CallGraphNodeKind::BasicBlock &&
               node.bytes.start.virtual_address &&
               node.bytes.start.file_offset &&
               node.bytes.size != 0 &&
               node.instruction_count != 0;
    })) << name;
    EXPECT_TRUE(std::ranges::any_of(cfg.edges, [](const viewer::CallGraphEdge& edge) {
        return edge.kind == viewer::CallGraphEdgeKind::Return;
    })) << name << "\n" << viewer::to_dot(cfg);
}

[[nodiscard]] viewer::CallGraph sample_graph() {
    return viewer::CallGraph{
        .id = "entry",
        .label = "Entry flow",
        .architecture = peelf::Architecture::ARM64,
        .endianness = peelf::Endianness::Little,
        .nodes = {
            viewer::CallGraphNode{
                .id = "entry",
                .label = "entry",
                .kind = viewer::CallGraphNodeKind::Function,
                .bytes = viewer::GraphByteRange{
                    .start = viewer::GraphAddress{
                        .virtual_address = 0x140001000,
                        .relative_virtual_address = 0x1000,
                        .file_offset = 0x400,
                    },
                    .size = 0x20,
                },
                .symbol = viewer::GraphSymbolRef{.name = "entry", .symbol_index = 3, .dynamic = false},
            },
            viewer::CallGraphNode{
                .id = "winmain",
                .label = "WinMain",
                .kind = viewer::CallGraphNodeKind::External,
                .symbol = viewer::GraphSymbolRef{.name = "WinMain", .symbol_index = 4, .dynamic = false},
            },
        },
        .edges = {
            viewer::CallGraphEdge{
                .from_node_id = "entry",
                .to_node_id = "winmain",
                .kind = viewer::CallGraphEdgeKind::Call,
                .label = "call",
            },
        },
        .indirect_recoveries = {},
    };
}

} // namespace

TEST(CallGraph, EmitsDotWithStableIdsAddressesAndEdges) {
    const std::string dot = viewer::to_dot(sample_graph());

    EXPECT_NE(dot.find("digraph \"entry\""), std::string::npos);
    EXPECT_NE(dot.find("\"entry\" [shape=\"box\""), std::string::npos);
    EXPECT_NE(dot.find("VA 0x140001000"), std::string::npos);
    EXPECT_NE(dot.find("file 0x400"), std::string::npos);
    EXPECT_NE(dot.find("\"entry\" -> \"winmain\""), std::string::npos);
    EXPECT_NE(dot.find("label=\"call\""), std::string::npos);
}

TEST(CallGraph, BuildsGraphvizSvgAndPngCommandsWithoutAssumingArchitecture) {
    const viewer::GraphRenderCommand svg = viewer::make_graphviz_render_command("entry.dot", "entry.svg",
                                                                                 viewer::GraphRenderFormat::Svg,
                                                                                 "dot-test");
    EXPECT_EQ(svg.executable, "dot-test");
    ASSERT_EQ(svg.arguments.size(), 4);
    EXPECT_EQ(svg.arguments[0], "-Tsvg");
    EXPECT_EQ(svg.arguments[1], "-o");
    EXPECT_EQ(svg.arguments[2], "entry.svg");
    EXPECT_EQ(svg.arguments[3], "entry.dot");

    const viewer::GraphRenderCommand png = viewer::make_graphviz_render_command("entry.dot", "entry.png",
                                                                                 viewer::GraphRenderFormat::Png,
                                                                                 "dot-test");
    ASSERT_FALSE(png.arguments.empty());
    EXPECT_EQ(png.arguments[0], "-Tpng");

    const viewer::GraphRenderCommand bmp = viewer::make_graphviz_render_command("entry.dot", "entry.bmp",
                                                                                 viewer::GraphRenderFormat::Bmp,
                                                                                 "dot-test");
    ASSERT_FALSE(bmp.arguments.empty());
    EXPECT_EQ(bmp.arguments[0], "-Tbmp");

    const viewer::GraphRenderCommand plain = viewer::make_graphviz_render_command("entry.dot", "entry.plain",
                                                                                  viewer::GraphRenderFormat::Plain,
                                                                                  "dot-test");
    ASSERT_FALSE(plain.arguments.empty());
    EXPECT_EQ(plain.arguments[0], "-Tplain");
}

TEST(CallGraph, ParsesGraphvizPlainNodeLayout) {
    constexpr std::string_view plain =
        "graph 1 4 2\n"
        "node main 1 1 0.75 0.5 main solid box black lightgrey\n"
        "stop\n";

    const std::optional<viewer::GraphLayout> layout = viewer::parse_graphviz_plain_layout(plain);

    ASSERT_TRUE(layout.has_value());
    EXPECT_DOUBLE_EQ(layout->width, 4.0);
    EXPECT_DOUBLE_EQ(layout->height, 2.0);
    ASSERT_EQ(layout->nodes.size(), 1u);
    EXPECT_EQ(layout->nodes.front().node_id, "main");
    EXPECT_DOUBLE_EQ(layout->nodes.front().center_x, 1.0);
}

TEST(CallGraph, RenderWritesDotAndInvokesInjectedRunner) {
    const std::filesystem::path output_path = std::filesystem::temp_directory_path() / "peelf_call_graph_test.svg";
    const std::filesystem::path dot_path = output_path.string() + ".dot";
    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);

    const FakeProcessRunner runner;
    const viewer::GraphRenderResult result =
        viewer::render_graph_with_graphviz(sample_graph(), output_path, viewer::GraphRenderFormat::Svg, runner);

    EXPECT_TRUE(result.success);
    EXPECT_FALSE(runner.executable_.empty());
    ASSERT_EQ(runner.arguments_.size(), 4);
    EXPECT_EQ(runner.arguments_[0], "-Tsvg");
    EXPECT_EQ(runner.arguments_[1], "-o");
    EXPECT_EQ(runner.arguments_[2], output_path.string());
    EXPECT_EQ(runner.arguments_[3], dot_path.string());
    EXPECT_TRUE(std::filesystem::exists(dot_path));

    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);
}

TEST(CallGraph, BuildsFunctionCfgWithConditionalBranchFallthroughAndReturn) {
    const std::array<std::uint8_t, 11> bytes{
        0x83, 0xF8, 0x01,             // cmp eax, 1
        0x74, 0x05,                   // je 0x100A
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
        0xC3,                         // ret
    };

    const viewer::CallGraph graph = viewer::build_function_cfg_call_graph(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        0x1000,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        0x200,
        "conditional fixture");

    EXPECT_EQ(graph.nodes.size(), 4u);
    EXPECT_EQ(graph.edges.size(), 4u);
    ASSERT_NE(find_node(graph, "bb_0"), nullptr);
    ASSERT_NE(find_node(graph, "bb_1"), nullptr);
    ASSERT_NE(find_node(graph, "bb_2"), nullptr);
    ASSERT_NE(find_node(graph, "return"), nullptr);

    const viewer::CallGraphNode* entry = find_node(graph, "bb_0");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->kind, viewer::CallGraphNodeKind::BasicBlock);
    EXPECT_EQ(entry->bytes.start.virtual_address, 0x1000u);
    EXPECT_EQ(entry->bytes.start.relative_virtual_address, 0u);
    EXPECT_EQ(entry->bytes.start.file_offset, 0x200u);
    EXPECT_EQ(entry->bytes.size, 5u);
    EXPECT_EQ(entry->first_instruction_index, 0u);
    EXPECT_EQ(entry->instruction_count, 2u);
    ASSERT_EQ(entry->instructions.size(), 2u);
    EXPECT_EQ(entry->instructions.front().address, 0x1000u);
    EXPECT_EQ(entry->instructions.back().mnemonic, "je");
    EXPECT_NE(viewer::to_dot(graph).find("rankdir=\"TB\""), std::string::npos);
    EXPECT_NE(viewer::to_dot(graph).find("je"), std::string::npos);

    EXPECT_TRUE(has_edge(graph, "bb_0", "bb_2", viewer::CallGraphEdgeKind::ConditionalBranch));
    EXPECT_TRUE(has_edge(graph, "bb_0", "bb_1", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(graph, "bb_1", "bb_2", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(graph, "bb_2", "return", viewer::CallGraphEdgeKind::Return));
}

TEST(CallGraph, ThumbCfgCarriesInstructionBodies) {
    const std::array<std::uint8_t, 4> bytes{0x00, 0xBF, 0x70, 0x47};
    const auto graph = viewer::build_function_cfg_call_graph(bytes, 0x1000,
        peelf::Architecture::ARM, peelf::Endianness::Little, 0x200, "Thumb function", true);
    const auto* block = find_node(graph, "bb_0");
    ASSERT_NE(block, nullptr);
    ASSERT_EQ(block->instructions.size(), 2u);
    EXPECT_EQ(block->instructions[0].mnemonic, "nop");
    EXPECT_EQ(block->instructions[1].mnemonic, "bx");
    EXPECT_EQ(block->instructions[1].address, 0x1002u);
    EXPECT_TRUE(has_edge(graph, "bb_0", "return", viewer::CallGraphEdgeKind::Return));
}

TEST(FunctionAnalysis, ExtentUsesSymbolAndRejectsUnmappedOrMismatchedOffsets) {
    const auto bytes = read_fixture("known-win-x64.exe");
    const auto image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);
    auto symbols = viewer::SymbolIndex::build(*image);
    viewer::SymbolRecord root{.name="test", .virtual_address=image->entry_point(),
        .file_offset=image->virtual_address_to_file_offset(image->entry_point()), .size=32};
    ASSERT_TRUE(root.file_offset);
    auto extent = viewer::discover_function_extent(*image, symbols, root, bytes.size());
    ASSERT_TRUE(extent);
    EXPECT_EQ(extent->size, 32u);
    EXPECT_EQ(extent->source, viewer::FunctionExtentSource::Symbol);
    EXPECT_FALSE(extent->truncated);
    extent = viewer::discover_function_extent(*image, symbols, root, bytes.size(), 8);
    ASSERT_TRUE(extent);
    EXPECT_EQ(extent->size, 8u);
    EXPECT_TRUE(extent->truncated);
    EXPECT_FALSE(viewer::discover_function_extent(*image, symbols, root, *root.file_offset));
    ++*root.file_offset;
    EXPECT_FALSE(viewer::discover_function_extent(*image, symbols, root, bytes.size()));
}

TEST(FunctionAnalysis, SizedFunctionIsNotCutAtOverlappingSymbol) {
    const auto bytes = read_fixture("known-win-x64.exe");
    const auto image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);
    auto symbols = viewer::SymbolIndex::build(*image);
    const std::array debug{viewer::DebugSymbol{.name="overlapping", .virtual_address=image->entry_point()+4,
        .size=4, .function=true}};
    symbols.add_debug_symbols(*image, debug);
    viewer::SymbolRecord root{.name="test", .virtual_address=image->entry_point(), .size=32};
    auto extent = viewer::discover_function_extent(*image, symbols, root, bytes.size());
    ASSERT_TRUE(extent);
    EXPECT_EQ(extent->size, 32u);
    root.size = 0;
    extent = viewer::discover_function_extent(*image, symbols, root, bytes.size());
    ASSERT_TRUE(extent);
    // A runtime table, if present, is stronger evidence than an interior symbol.
    if (extent->source != viewer::FunctionExtentSource::RuntimeMetadata) {
        EXPECT_EQ(extent->size, 4u);
        EXPECT_EQ(extent->source, viewer::FunctionExtentSource::NextSymbol);
    }
}

TEST(FunctionAnalysis, RuntimeMetadataProvidesExtentWithoutSymbols) {
    const auto bytes = read_file(PEELF_CALLGRAPH_FIXTURE_EXE);
    const auto image = parse_file(PEELF_CALLGRAPH_FIXTURE_EXE);
    ASSERT_NE(image, nullptr);
    if (image->format() != peelf::Format::PE || image->architecture() != peelf::Architecture::X86_64) GTEST_SKIP();
    ASSERT_FALSE(image->pe_runtime_functions().empty());
    const auto runtime = image->pe_runtime_functions().front();
    viewer::SymbolRecord root{.name="stripped", .virtual_address=image->image_base()+runtime.begin_address_rva};
    const auto extent = viewer::discover_function_extent(*image, viewer::SymbolIndex{}, root, bytes.size());
    ASSERT_TRUE(extent);
    EXPECT_EQ(extent->source, viewer::FunctionExtentSource::RuntimeMetadata);
    EXPECT_EQ(extent->size, runtime.end_address_rva-runtime.begin_address_rva);
}

TEST(CallGraph, IndirectBranchesAreExplicitAndDoNotFallThrough) {
    const std::array<std::uint8_t, 3> bytes{0xFF,0xE0,0xC3}; // jmp rax; ret
    const auto graph = viewer::build_function_cfg_call_graph(bytes, 0x1000,
        peelf::Architecture::X86_64, peelf::Endianness::Little);
    ASSERT_NE(find_node(graph, "external_bb_0"), nullptr);
    EXPECT_TRUE(has_edge(graph,"bb_0","external_bb_0",viewer::CallGraphEdgeKind::UnconditionalBranch));
    EXPECT_FALSE(has_edge(graph,"bb_0","bb_1",viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_FALSE(find_node(graph,"bb_0")->instructions.front().branch_target);
}

TEST(CallGraph, Arm64IndirectCallIsNotPowerPcReturn) {
    const std::array<std::uint8_t,8> bytes{0x00,0x00,0x3F,0xD6,0xC0,0x03,0x5F,0xD6}; // blr x0; ret
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::ARM64,peelf::Endianness::Little);
    const auto* block = find_node(graph,"bb_0");
    ASSERT_NE(block,nullptr);
    EXPECT_EQ(block->instruction_count,2u);
    EXPECT_TRUE(has_edge(graph,"bb_0","return",viewer::CallGraphEdgeKind::Return));
}

TEST(CallGraph, Arm64ConditionalBranchUsesFinalImmediate) {
    const std::array<std::uint8_t,12> bytes{0x40,0x00,0x00,0x36,0xC0,0x03,0x5F,0xD6,0xC0,0x03,0x5F,0xD6}; // tbz w0,#0,+8
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::ARM64,peelf::Endianness::Little);
    EXPECT_TRUE(has_edge(graph,"bb_0","bb_2",viewer::CallGraphEdgeKind::ConditionalBranch));
    ASSERT_NE(find_node(graph,"bb_0"),nullptr);
    EXPECT_EQ(find_node(graph,"bb_0")->instructions.front().branch_target,0x1008u);
}

TEST(CallGraph, ArmConditionalReturnPreservesFallthrough) {
    const std::array<std::uint8_t,8> bytes{0x1E,0xFF,0x2F,0x11,0x1E,0xFF,0x2F,0xE1}; // bxne lr; bx l
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::ARM,peelf::Endianness::Little);
    EXPECT_TRUE(has_edge(graph,"bb_0","return",viewer::CallGraphEdgeKind::Return));
    EXPECT_TRUE(has_edge(graph,"bb_0","bb_1",viewer::CallGraphEdgeKind::Fallthrough));
}

TEST(CallGraph, MipsReturnIncludesItsDelaySlot) {
    const std::array<std::uint8_t,8> bytes{0x03,0xE0,0x00,0x08,0x24,0x02,0x00,0x01}; // jr ra; addiu v0,zero,1
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::MIPS32,peelf::Endianness::Big);
    ASSERT_NE(find_node(graph,"bb_0"),nullptr);
    EXPECT_EQ(find_node(graph,"bb_0")->instruction_count,2u);
    EXPECT_TRUE(has_edge(graph,"bb_0","return",viewer::CallGraphEdgeKind::Return));
}

TEST(CallGraph, MipsRegisterJumpIsNotAReturn) {
    const std::array<std::uint8_t,8> bytes{0x01,0x00,0x00,0x08,0,0,0,0}; // jr t0; nop
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::MIPS32,peelf::Endianness::Big);
    EXPECT_FALSE(has_edge(graph,"bb_0","return",viewer::CallGraphEdgeKind::Return));
    EXPECT_TRUE(has_edge(graph,"bb_0","external_bb_0",viewer::CallGraphEdgeKind::UnconditionalBranch));
}

TEST(CallGraph, RiscVZeroDestinationJumpDoesNotFallThrough) {
    const std::array<std::uint8_t,12> bytes{0x6F,0x00,0x80,0x00,0x67,0x80,0x00,0x00,0x67,0x80,0x00,0x00};
    for (const auto arch : {peelf::Architecture::RISCV32,peelf::Architecture::RISCV64}) {
        const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,arch,peelf::Endianness::Little);
        EXPECT_TRUE(has_edge(graph,"bb_0","bb_2",viewer::CallGraphEdgeKind::UnconditionalBranch));
        EXPECT_FALSE(has_edge(graph,"bb_0","bb_1",viewer::CallGraphEdgeKind::Fallthrough));
    }
}

TEST(CallGraph, ReachablePreviewExcludesDeadBlocksButPreservesExplicitFullExtent) {
    const std::array<std::uint8_t,4> bytes{0xEB,0x01,0xC3,0xC3};
    const auto preview = viewer::build_function_cfg_call_graph(bytes,0x1000,peelf::Architecture::X86_64,
        peelf::Endianness::Little,std::nullopt,"preview",false,true);
    EXPECT_EQ(find_node(preview,"bb_1"),nullptr);
    EXPECT_NE(find_node(preview,"bb_2"),nullptr);
    EXPECT_TRUE(has_edge(preview,"bb_0","bb_2",viewer::CallGraphEdgeKind::UnconditionalBranch));
    const auto full = viewer::build_function_cfg_call_graph(bytes,0x1000,peelf::Architecture::X86_64,
        peelf::Endianness::Little);
    EXPECT_NE(find_node(full,"bb_1"),nullptr);
}

TEST(CallGraph, MipsBranchLikelyExposesUnsupportedAnnulSemantics) {
    const std::array<std::uint8_t,12> bytes{0x50,0x00,0x00,0x01,0,0,0,0,0,0,0,0}; // beql zero,zero,+1; slots
    const auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::MIPS32,peelf::Endianness::Big);
    const auto* unresolved = find_node(graph,"external_bb_0");
    ASSERT_NE(unresolved,nullptr);
    EXPECT_NE(unresolved->label.find("annulled"),std::string::npos);
    EXPECT_TRUE(has_edge(graph,"bb_0","external_bb_0",viewer::CallGraphEdgeKind::Unknown));
}

TEST(CallGraph, GuardedAbsoluteJumpTableRecoversCasesAndRejectsInvalidPointers) {
    std::vector<std::uint8_t> bytes{
        0x83,0xF8,0x01, // cmp eax,1
        0x77,0x09, // ja 0x100E
        0xFF,0x24,0x85,0x10,0x10,0x00,0x00, // jmp [eax*4+0x1010]
        0xC3,0xC3,0xC3,0x90, // two cases, default, alignment
        0x0C,0x10,0x00,0x00,0x0D,0x10,0x00,0x00};
    auto graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::X86,peelf::Endianness::Little);
    EXPECT_TRUE(std::ranges::any_of(graph.edges,[](const auto& edge){return edge.label=="case 0";}));
    EXPECT_TRUE(std::ranges::any_of(graph.edges,[](const auto& edge){return edge.label=="case 1";}));
    bytes[16] = 0xFF; // out-of-range destination: never invent a case edge
    graph = viewer::build_function_cfg_call_graph(bytes,0x1000,
        peelf::Architecture::X86,peelf::Endianness::Little);
    EXPECT_FALSE(std::ranges::any_of(graph.edges,[](const auto& edge){return edge.label.starts_with("case ");}));
    EXPECT_NE(find_node(graph,"external_bb_1"),nullptr);
}

TEST(CallGraph, BuildsFunctionCfgWithUnconditionalBranch) {
    const std::array<std::uint8_t, 8> bytes{
        0xEB, 0x05,                   // jmp 0x3007
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xC3,                         // ret
    };

    const viewer::CallGraph graph = viewer::build_function_cfg_call_graph(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        0x3000,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        std::nullopt,
        "jump fixture");

    EXPECT_EQ(graph.nodes.size(), 4u);
    ASSERT_NE(find_node(graph, "bb_0"), nullptr);
    ASSERT_NE(find_node(graph, "bb_1"), nullptr);
    ASSERT_NE(find_node(graph, "bb_2"), nullptr);
    EXPECT_TRUE(has_edge(graph, "bb_0", "bb_2", viewer::CallGraphEdgeKind::UnconditionalBranch));
    EXPECT_FALSE(has_edge(graph, "bb_0", "bb_1", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(graph, "bb_1", "bb_2", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(graph, "bb_2", "return", viewer::CallGraphEdgeKind::Return));
}

TEST(CallGraph, BuildsLoadedElfStartupGraphFromParsedImage) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("hello.elf");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*image);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_EQ(graph.architecture, peelf::Architecture::X86_64);
    EXPECT_NE(dot.find("_start"), std::string::npos);
    EXPECT_NE(dot.find("main"), std::string::npos);
    EXPECT_NE(dot.find("__libc_start_main"), std::string::npos);
    EXPECT_NE(dot.find("main callback"), std::string::npos);
}

TEST(CallGraph, BuildsLoadedPeEntryGraphFromParsedImage) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*image);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_EQ(graph.architecture, peelf::Architecture::X86_64);
    EXPECT_NE(dot.find("Entry Point"), std::string::npos);
    EXPECT_NE(dot.find("known_export"), std::string::npos);
    EXPECT_NE(dot.find("KERNEL32.dll!ExitProcess"), std::string::npos);
    EXPECT_NE(dot.find("import table"), std::string::npos);
    EXPECT_EQ(dot.find("import ref"), std::string::npos);
    EXPECT_NE(dot.find("WinMain"), std::string::npos);
    EXPECT_NE(dot.find("symbol lookup pending"), std::string::npos);
}

TEST(CallGraph, UsesLoadedDebugSymbolsForPeUserEntry) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "WinMain",
            .relative_virtual_address = 0x1000,
            .virtual_address = image->entry_point(),
            .size = 0x30,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*image, index);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("WinMain"), std::string::npos);
    EXPECT_EQ(dot.find("unresolved from current symbols"), std::string::npos);
    EXPECT_NE(dot.find("user entry symbol"), std::string::npos);
}

TEST(CallGraph, DoesNotTreatMainSubstringAsPeUserEntry) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "?render_main_menu@UiApp@viewer@@AEAAXXZ",
            .relative_virtual_address = 0x1339E0,
            .virtual_address = 0x1401339E0,
            .size = 0x80,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*image, index);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_EQ(dot.find("render_main_menu"), std::string::npos);
    EXPECT_NE(dot.find("unresolved from current symbols"), std::string::npos);
}

TEST(CallGraph, PrefersExactMainOverSymbolsContainingMain) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "?render_main_menu@UiApp@viewer@@AEAAXXZ",
            .relative_virtual_address = 0x1339E0,
            .virtual_address = 0x1401339E0,
            .size = 0x80,
            .function = true,
        },
        viewer::DebugSymbol{
            .name = "main",
            .relative_virtual_address = 0x1200,
            .virtual_address = 0x140001200,
            .size = 0x40,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*image, index);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("main"), std::string::npos);
    EXPECT_NE(dot.find("user entry symbol"), std::string::npos);
    EXPECT_EQ(dot.find("render_main_menu"), std::string::npos);
}

TEST(CallGraph, BuildsSymbolFanoutGraphWithoutResolvedCalls) {
    const std::vector<std::uint8_t> bytes = read_fixture("known-win-x64.exe");
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    const std::unique_ptr<peelf::IBinaryImage> image = std::move(*parsed);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "main",
            .relative_virtual_address = 0x1000,
            .virtual_address = image->entry_point(),
            .size = 1,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);
    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);

    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("main fan-out"), std::string::npos);
    EXPECT_NE(dot.find("No direct call targets resolved"), std::string::npos);
}

TEST(CallGraph, LabelsFanoutTargetsWithNearestSymbolsAndOffsets) {
    std::vector<std::uint8_t> bytes = read_fixture("known-win-x64.exe");
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    const std::unique_ptr<peelf::IBinaryImage> image = std::move(*parsed);

    const std::uint64_t root_va = image->entry_point();
    const std::optional<std::uint64_t> root_file_offset = image->virtual_address_to_file_offset(root_va);
    ASSERT_TRUE(root_file_offset);
    ASSERT_LE(*root_file_offset + 8u, bytes.size());

    const std::uint64_t helper_va = root_va + 0x20u;
    const std::uint64_t call_target_va = helper_va + 0x4u;
    const std::int64_t rel64 = static_cast<std::int64_t>(call_target_va) - static_cast<std::int64_t>(root_va + 5u);
    ASSERT_GE(rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()));
    ASSERT_LE(rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()));
    const auto rel32 = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel64));

    const std::size_t start = static_cast<std::size_t>(*root_file_offset);
    bytes[start] = 0xE8u;
    bytes[start + 1u] = static_cast<std::uint8_t>(rel32 & 0xFFu);
    bytes[start + 2u] = static_cast<std::uint8_t>((rel32 >> 8u) & 0xFFu);
    bytes[start + 3u] = static_cast<std::uint8_t>((rel32 >> 16u) & 0xFFu);
    bytes[start + 4u] = static_cast<std::uint8_t>((rel32 >> 24u) & 0xFFu);
    bytes[start + 5u] = 0xC3u;

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "main",
            .virtual_address = root_va,
            .size = 8,
            .function = true,
        },
        viewer::DebugSymbol{
            .name = "helper_target",
            .virtual_address = helper_va,
            .size = 0,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);
    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);

    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("helper_target+0x4"), std::string::npos);
    EXPECT_NE(dot.find("VA 0x"), std::string::npos);
    EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos);
}

TEST(CallGraph, LabelsDirectCallTargetsAcrossArchitectureFixtures) {
    struct FixtureCase {
        const char* name;
        peelf::Architecture architecture;
        peelf::Endianness endianness;
    };

    constexpr std::array<FixtureCase, 10> fixtures{{
        {"known-linux-x64.elf", peelf::Architecture::X86_64, peelf::Endianness::Little},
        {"known-linux-x86-elf32-le.elf", peelf::Architecture::X86, peelf::Endianness::Little},
        {"known-linux-arm-elf32-le.elf", peelf::Architecture::ARM, peelf::Endianness::Little},
        {"known-linux-arm64.elf", peelf::Architecture::ARM64, peelf::Endianness::Little},
        {"known-linux-riscv32-elf32-le.elf", peelf::Architecture::RISCV32, peelf::Endianness::Little},
        {"known-linux-riscv64.elf", peelf::Architecture::RISCV64, peelf::Endianness::Little},
        {"known-linux-mips-elf32-be.elf", peelf::Architecture::MIPS32, peelf::Endianness::Big},
        {"known-linux-mips64-elf64-be.elf", peelf::Architecture::MIPS64, peelf::Endianness::Big},
        {"known-linux-ppc-elf32-be.elf", peelf::Architecture::PowerPC, peelf::Endianness::Big},
        {"known-linux-ppc64-elf64-be.elf", peelf::Architecture::PowerPC64, peelf::Endianness::Big},
    }};

    for (const FixtureCase& fixture : fixtures) {
        std::vector<std::uint8_t> bytes = read_fixture(fixture.name);
        auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        ASSERT_TRUE(parsed.has_value()) << fixture.name;
        const std::unique_ptr<peelf::IBinaryImage> image = std::move(*parsed);
        ASSERT_EQ(image->architecture(), fixture.architecture) << fixture.name;
        ASSERT_EQ(image->endianness(), fixture.endianness) << fixture.name;

        const std::uint64_t root_va = image->entry_point();
        const std::uint64_t target_va = root_va + 0x4u;
        ASSERT_TRUE(image->virtual_address_to_file_offset(root_va)) << fixture.name;
        ASSERT_TRUE(image->virtual_address_to_file_offset(target_va)) << fixture.name;
        patch_direct_call(bytes, *image, root_va, target_va);

        viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
        const viewer::DebugSymbol symbols[] = {
            viewer::DebugSymbol{
                .name = "arch_root",
                .virtual_address = root_va,
                .size = 8,
                .function = true,
            },
            viewer::DebugSymbol{
                .name = "arch_callee",
                .virtual_address = target_va,
                .size = 4,
                .function = true,
            },
        };
        index.add_debug_symbols(*image, symbols);
        const viewer::SymbolRecord* root = index.find_by_name("arch_root");
        ASSERT_NE(root, nullptr) << fixture.name;

        const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
            *image,
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            index,
            *root);
        const std::string dot = viewer::to_dot(graph);

        EXPECT_NE(dot.find("arch_root fan-out"), std::string::npos) << fixture.name << "\n" << dot;
        EXPECT_NE(dot.find("arch_callee"), std::string::npos) << fixture.name << "\n" << dot;
        EXPECT_NE(dot.find("label=\"call\""), std::string::npos) << fixture.name << "\n" << dot;
        EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos) << fixture.name << "\n" << dot;
    }
}

TEST(CallGraph, LabelsFanoutImportThunksWithImportNames) {
    std::vector<std::uint8_t> bytes = read_fixture("known-win-x64.exe");
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    const std::unique_ptr<peelf::IBinaryImage> image = std::move(*parsed);
    ASSERT_FALSE(image->imports().empty());

    const peelf::ImportEntry* imported = nullptr;
    for (const peelf::ImportEntry& entry : image->imports()) {
        if (entry.address != 0 && !entry.name.empty()) {
            imported = &entry;
            break;
        }
    }
    ASSERT_NE(imported, nullptr);

    const std::uint64_t root_va = image->entry_point();
    const std::optional<std::uint64_t> root_file_offset = image->virtual_address_to_file_offset(root_va);
    ASSERT_TRUE(root_file_offset);
    const std::uint64_t thunk_va = root_va + 0x20u;
    const std::optional<std::uint64_t> thunk_file_offset = image->virtual_address_to_file_offset(thunk_va);
    ASSERT_TRUE(thunk_file_offset);
    ASSERT_LE(*root_file_offset + 8u, bytes.size());
    ASSERT_LE(*thunk_file_offset + 8u, bytes.size());

    const auto call_rel32 = static_cast<std::uint32_t>(
        static_cast<std::int32_t>(static_cast<std::int64_t>(thunk_va) - static_cast<std::int64_t>(root_va + 5u)));
    const std::size_t root = static_cast<std::size_t>(*root_file_offset);
    bytes[root] = 0xE8u;
    bytes[root + 1u] = static_cast<std::uint8_t>(call_rel32 & 0xFFu);
    bytes[root + 2u] = static_cast<std::uint8_t>((call_rel32 >> 8u) & 0xFFu);
    bytes[root + 3u] = static_cast<std::uint8_t>((call_rel32 >> 16u) & 0xFFu);
    bytes[root + 4u] = static_cast<std::uint8_t>((call_rel32 >> 24u) & 0xFFu);
    bytes[root + 5u] = 0xC3u;

    const std::int64_t thunk_rel64 =
        static_cast<std::int64_t>(imported->address) - static_cast<std::int64_t>(thunk_va + 6u);
    ASSERT_GE(thunk_rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()));
    ASSERT_LE(thunk_rel64, static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()));
    const auto thunk_rel32 = static_cast<std::uint32_t>(static_cast<std::int32_t>(thunk_rel64));
    const std::size_t thunk = static_cast<std::size_t>(*thunk_file_offset);
    bytes[thunk] = 0xFFu;
    bytes[thunk + 1u] = 0x25u;
    bytes[thunk + 2u] = static_cast<std::uint8_t>(thunk_rel32 & 0xFFu);
    bytes[thunk + 3u] = static_cast<std::uint8_t>((thunk_rel32 >> 8u) & 0xFFu);
    bytes[thunk + 4u] = static_cast<std::uint8_t>((thunk_rel32 >> 16u) & 0xFFu);
    bytes[thunk + 5u] = static_cast<std::uint8_t>((thunk_rel32 >> 24u) & 0xFFu);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "main",
            .virtual_address = root_va,
            .size = 8,
            .function = true,
        },
    };
    index.add_debug_symbols(*image, symbols);
    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);

    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find(imported->name), std::string::npos);
    EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos);
}

TEST(CallGraph, DebugFixtureNamesTargetsAndSupportsSecondHopFanout) {
    const std::filesystem::path exe_path = PEELF_CALLGRAPH_FIXTURE_EXE;
    const std::filesystem::path pdb_path = PEELF_CALLGRAPH_FIXTURE_PDB;
    ASSERT_TRUE(std::filesystem::exists(exe_path)) << exe_path.string();
    if (pdb_path.empty() || !std::filesystem::exists(pdb_path)) {
        GTEST_SKIP() << "debug fixture PDB not available: " << pdb_path.string();
    }

    const std::vector<std::uint8_t> bytes = read_file(exe_path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(exe_path);
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbolLoadResult pdb = viewer::load_pdb_debug_symbols(pdb_path, *image);
    if (pdb.status != viewer::DebugSymbolLoadStatus::Loaded) {
        GTEST_SKIP() << "PDB load unavailable: " << viewer::to_string(pdb.status) << " " << pdb.diagnostic;
    }
    index.add_debug_symbols(*image, pdb.symbols);

    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph main_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string main_dot = viewer::to_dot(main_graph);

    EXPECT_NE(main_dot.find("first"), std::string::npos);
    EXPECT_NE(main_dot.find("second"), std::string::npos);
    EXPECT_EQ(main_dot.find("call target\\n0x"), std::string::npos);

    const viewer::SymbolRecord* first = find_symbol_containing(index, "first");
    ASSERT_NE(first, nullptr);
    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);

    EXPECT_NE(first_dot.find("first"), std::string::npos);
    EXPECT_NE(first_dot.find("leaf"), std::string::npos);
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos);
}

TEST(CallGraph, DebugElfFixtureNamesTargetsAndSupportsSecondHopFanout) {
    const std::filesystem::path exe_path = PEELF_CALLGRAPH_FIXTURE_EXE;
    ASSERT_TRUE(std::filesystem::exists(exe_path)) << exe_path.string();

    const std::vector<std::uint8_t> bytes = read_file(exe_path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(exe_path);
    ASSERT_NE(image, nullptr);
    if (image->format() != peelf::Format::ELF) {
        GTEST_SKIP() << "call graph debug fixture is not an ELF binary on this platform";
    }

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph main_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string main_dot = viewer::to_dot(main_graph);

    EXPECT_NE(main_dot.find("first"), std::string::npos) << main_dot;
    EXPECT_NE(main_dot.find("second"), std::string::npos) << main_dot;
    EXPECT_EQ(main_dot.find("call target\\n0x"), std::string::npos) << main_dot;

    const viewer::SymbolRecord* first = find_symbol_containing(index, "first");
    ASSERT_NE(first, nullptr);
    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);

    EXPECT_NE(first_dot.find("first"), std::string::npos) << first_dot;
    EXPECT_NE(first_dot.find("leaf"), std::string::npos) << first_dot;
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos) << first_dot;
}

TEST(CallGraph, BinMatrixFixturesParseEntryAndKnownCallGraphsAcrossArchitectures) {
    constexpr std::array<BinMatrixCase, 9> fixtures{{
        {"elf-linux-x86_64-64-le-callgraph", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"elf-linux-x86-32-le-callgraph", peelf::Architecture::X86, peelf::Endianness::Little, false},
        {"elf-linux-arm-32-le-callgraph", peelf::Architecture::ARM, peelf::Endianness::Little, false},
        {"elf-linux-arm64-64-le-callgraph", peelf::Architecture::ARM64, peelf::Endianness::Little, true},
        {"elf-linux-riscv64-64-le-callgraph", peelf::Architecture::RISCV64, peelf::Endianness::Little, true},
        {"elf-linux-mips-32-be-callgraph", peelf::Architecture::MIPS32, peelf::Endianness::Big, false},
        {"elf-linux-mips64-64-be-callgraph", peelf::Architecture::MIPS64, peelf::Endianness::Big, true},
        {"elf-linux-ppc-32-be-callgraph", peelf::Architecture::PowerPC, peelf::Endianness::Big, false},
        {"elf-linux-ppc64-64-be-callgraph", peelf::Architecture::PowerPC64, peelf::Endianness::Big, true},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_callgraph_fixture(fixture);
    }
}

TEST(CallGraph, BinMatrixFunctionCfgsBuildAcrossArchitectures) {
    constexpr std::array<BinMatrixCase, 9> fixtures{{
        {"elf-linux-x86_64-64-le-callgraph", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"elf-linux-x86-32-le-callgraph", peelf::Architecture::X86, peelf::Endianness::Little, false},
        {"elf-linux-arm-32-le-callgraph", peelf::Architecture::ARM, peelf::Endianness::Little, false},
        {"elf-linux-arm64-64-le-callgraph", peelf::Architecture::ARM64, peelf::Endianness::Little, true},
        {"elf-linux-riscv64-64-le-callgraph", peelf::Architecture::RISCV64, peelf::Endianness::Little, true},
        {"elf-linux-mips-32-be-callgraph", peelf::Architecture::MIPS32, peelf::Endianness::Big, false},
        {"elf-linux-mips64-64-be-callgraph", peelf::Architecture::MIPS64, peelf::Endianness::Big, true},
        {"elf-linux-ppc-32-be-callgraph", peelf::Architecture::PowerPC, peelf::Endianness::Big, false},
        {"elf-linux-ppc64-64-be-callgraph", peelf::Architecture::PowerPC64, peelf::Endianness::Big, true},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_function_cfg_fixture(fixture);
    }
}

TEST(CallGraph, BinMatrixSharedLibrariesParseImportsAndKnownCallGraphsAcrossArchitectures) {
    constexpr std::array<BinMatrixCase, 9> fixtures{{
        {"elf-linux-x86_64-64-le-callgraph", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"elf-linux-x86-32-le-callgraph", peelf::Architecture::X86, peelf::Endianness::Little, false},
        {"elf-linux-arm-32-le-callgraph", peelf::Architecture::ARM, peelf::Endianness::Little, false},
        {"elf-linux-arm64-64-le-callgraph", peelf::Architecture::ARM64, peelf::Endianness::Little, true},
        {"elf-linux-riscv64-64-le-callgraph", peelf::Architecture::RISCV64, peelf::Endianness::Little, true},
        {"elf-linux-mips-32-be-callgraph", peelf::Architecture::MIPS32, peelf::Endianness::Big, false},
        {"elf-linux-mips64-64-be-callgraph", peelf::Architecture::MIPS64, peelf::Endianness::Big, true},
        {"elf-linux-ppc-32-be-callgraph", peelf::Architecture::PowerPC, peelf::Endianness::Big, false},
        {"elf-linux-ppc64-64-be-callgraph", peelf::Architecture::PowerPC64, peelf::Endianness::Big, true},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_shared_library_fixture(fixture);
    }
}

TEST(CallGraph, BinMatrixPeDllsParseExportsImportsAndKnownCallGraphsAcrossArchitectures) {
    constexpr std::array<BinMatrixCase, 2> fixtures{{
        {"pe-windows-x86_64-64-le-callgraph", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"pe-windows-x86-32-le-callgraph", peelf::Architecture::X86, peelf::Endianness::Little, false},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_pe_dll_fixture(fixture);
    }
}

TEST(CallGraph, BinMatrixPeDllFunctionCfgsBuildAcrossArchitectures) {
    constexpr std::array<BinMatrixCase, 2> fixtures{{
        {"pe-windows-x86_64-64-le-callgraph", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"pe-windows-x86-32-le-callgraph", peelf::Architecture::X86, peelf::Endianness::Little, false},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_pe_dll_cfg_fixture(fixture);
    }
}

TEST(CallGraph, DebugViewerGuiEntryFanoutResolvesRealTargetNames) {
#if !defined(PEELF_VIEWER_DEBUG_EXE) || !defined(PEELF_VIEWER_DEBUG_PDB)
    GTEST_SKIP() << "viewer debug executable path was not configured";
#else
    const std::filesystem::path exe_path = PEELF_VIEWER_DEBUG_EXE;
    const std::filesystem::path pdb_path = PEELF_VIEWER_DEBUG_PDB;
    ASSERT_TRUE(std::filesystem::exists(exe_path)) << exe_path.string();
    if (pdb_path.empty() || !std::filesystem::exists(pdb_path)) {
        GTEST_SKIP() << "viewer debug PDB not available: " << pdb_path.string();
    }

    const std::vector<std::uint8_t> bytes = read_file(exe_path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(exe_path);
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbolLoadResult pdb = viewer::load_pdb_debug_symbols(pdb_path, *image);
    if (pdb.status != viewer::DebugSymbolLoadStatus::Loaded) {
        GTEST_SKIP() << "PDB load unavailable: " << viewer::to_string(pdb.status) << " " << pdb.diagnostic;
    }
    index.add_debug_symbols(*image, pdb.symbols);

    // The DLL export may point at an incremental-link jump thunk. Analyze the
    // PDB function body, whose extent describes the actual direct calls.
    const viewer::SymbolRecord* main = nullptr;
    for (const auto& symbol : index.records()) {
        if (symbol.name == "peelf_run_gui" && symbol.source == viewer::SymbolSource::DebugSymbol && symbol.size > 0) {
            main = &symbol;
            break;
        }
    }
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("peelf_run_gui fan-out"), std::string::npos) << dot;
    EXPECT_NE(dot.find("label=\"call\""), std::string::npos) << dot;
    EXPECT_NE(dot.find("viewer::Application::init"), std::string::npos) << dot;
    EXPECT_NE(dot.find("viewer::Application::run"), std::string::npos) << dot;
    EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos) << dot;
#endif
}

TEST(CallGraph, DebugElfViewerGuiEntryFanoutResolvesRealTargetNames) {
#if !defined(PEELF_VIEWER_DEBUG_EXE)
    GTEST_SKIP() << "viewer debug executable path was not configured";
#else
    const std::filesystem::path exe_path = PEELF_VIEWER_DEBUG_EXE;
    ASSERT_TRUE(std::filesystem::exists(exe_path)) << exe_path.string();

    const std::vector<std::uint8_t> bytes = read_file(exe_path);
    const std::unique_ptr<peelf::IBinaryImage> image = parse_file(exe_path);
    ASSERT_NE(image, nullptr);
    if (image->format() != peelf::Format::ELF) {
        GTEST_SKIP() << "viewer debug executable is not an ELF binary on this platform";
    }

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::SymbolRecord* main = index.find_by_name("peelf_run_gui");
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("peelf_run_gui fan-out"), std::string::npos) << dot;
    EXPECT_NE(dot.find("label=\"call\""), std::string::npos) << dot;
    EXPECT_NE(dot.find("Application"), std::string::npos) << dot;
    EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos) << dot;
#endif
}

TEST(CallGraph, DefaultRunnerRendersSvgWhenGraphvizIsAvailable) {
#if defined(PEELF_GRAPHVIZ_DOT_AVAILABLE) && PEELF_GRAPHVIZ_DOT_AVAILABLE
    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "peelf_call_graph_graphviz_test.svg";
    const std::filesystem::path dot_path = output_path.string() + ".dot";
    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);

    const viewer::DefaultProcessRunner runner;
    const viewer::GraphRenderResult result =
        viewer::render_graph_with_graphviz(sample_graph(), output_path, viewer::GraphRenderFormat::Svg, runner);

    EXPECT_TRUE(result.success) << result.diagnostic << " exit=" << result.exit_code;
    EXPECT_TRUE(std::filesystem::exists(output_path));
    EXPECT_GT(std::filesystem::file_size(output_path), 0U);

    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);
#else
    GTEST_SKIP() << "Graphviz dot was not detected by CMake";
#endif
}

TEST(CallGraph, FindsSymbolsByVirtualAddressAcrossArchitectures) {
    const std::unique_ptr<peelf::IBinaryImage> x64 = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(x64, nullptr);
    ASSERT_FALSE(x64->symbols().empty());
    const peelf::Symbol& x64_symbol = x64->symbols().front();
    const std::optional<viewer::GraphSymbolRef> x64_ref =
        viewer::find_symbol_for_address(*x64, x64_symbol.virtual_address);
    ASSERT_TRUE(x64_ref.has_value());
    EXPECT_EQ(x64_ref->name, x64_symbol.name);

    const std::unique_ptr<peelf::IBinaryImage> riscv64 = parse_fixture("known-linux-riscv64.elf");
    ASSERT_NE(riscv64, nullptr);
    ASSERT_FALSE(riscv64->symbols().empty());
    const peelf::Symbol& riscv_symbol = riscv64->symbols().front();
    const std::optional<viewer::GraphSymbolRef> riscv_ref =
        viewer::find_symbol_for_address(*riscv64, riscv_symbol.virtual_address);
    ASSERT_TRUE(riscv_ref.has_value());
    EXPECT_EQ(riscv_ref->name, riscv_symbol.name);
}

#include "graph/layout_edit.hpp"
TEST(CallGraph, MovingCardsRespectsZoomAndPreservesOtherNodes) {
    viewer::GraphLayout layout{10,10,{{"a",2,3,1,1},{"b",6,7,2,2}}};
    EXPECT_TRUE(viewer::move_graph_card(layout,"a",100,50,50));
    EXPECT_DOUBLE_EQ(layout.nodes[0].center_x,4);
    EXPECT_DOUBLE_EQ(layout.nodes[0].center_y,2);
    EXPECT_DOUBLE_EQ(layout.nodes[1].center_x,6);
    EXPECT_DOUBLE_EQ(layout.nodes[1].center_y,7);
    EXPECT_DOUBLE_EQ(layout.nodes[0].width,1);
    EXPECT_FALSE(viewer::move_graph_card(layout,"missing",1,2,50));
    EXPECT_FALSE(viewer::move_graph_card(layout,"a",1,2,0));
    EXPECT_TRUE(viewer::move_graph_card(layout,"a",-250,-100,50));
    EXPECT_DOUBLE_EQ(layout.nodes[0].center_x,-1);
    EXPECT_DOUBLE_EQ(layout.nodes[0].center_y,4);
}

TEST(CallGraph, RecoversX64RipRelativeSignedOffsetJumpTableViaExternalReader) {
    // 0x1000: cmp edi, 2
    // 0x1003: ja 0x1024 (default)
    // 0x1005: mov eax, edi
    // 0x1007: lea rcx, [rip + 0xFF2] -> 0x2000 (.rodata table)
    // 0x100E: movsxd rax, dword ptr [rcx + rax*4]
    // 0x1012: add rax, rcx
    // 0x1015: jmp rax
    // 0x1017: mov eax, 10; ret (case 0)
    // 0x101D: xor eax, eax; ret (case 1)
    // 0x1020: mov al, 2; nop; ret (case 2)
    // 0x1024: or eax, -1; ret (default)
    const std::vector<std::uint8_t> code{
        0x83, 0xFF, 0x02,
        0x77, 0x1F,
        0x89, 0xF8,
        0x48, 0x8D, 0x0D, 0xF2, 0x0F, 0x00, 0x00,
        0x48, 0x63, 0x04, 0x81,
        0x48, 0x01, 0xC8,
        0xFF, 0xE0,
        0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3,
        0x31, 0xC0, 0xC3,
        0xB0, 0x02, 0x90, 0xC3,
        0x83, 0xC8, 0xFF, 0xC3,
    };
    const std::array<std::uint8_t, 12> rodata_table{
        0x17, 0xF0, 0xFF, 0xFF, // 0x1017 - 0x2000
        0x1D, 0xF0, 0xFF, 0xFF, // 0x101D - 0x2000
        0x20, 0xF0, 0xFF, 0xFF, // 0x1020 - 0x2000
    };
    const viewer::GraphByteReader reader = [&](std::uint64_t va, std::size_t len) -> std::vector<std::uint8_t> {
        if (va == 0x2000 && len == rodata_table.size()) {
            return std::vector<std::uint8_t>(rodata_table.begin(), rodata_table.end());
        }
        return {};
    };

    const viewer::CallGraph graph = viewer::build_function_cfg_call_graph(
        code,
        0x1000,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        0x400,
        "switch_fn",
        false,
        true,
        reader);

    EXPECT_TRUE(std::ranges::any_of(graph.edges, [](const auto& e) { return e.label == "case 0"; }));
    EXPECT_TRUE(std::ranges::any_of(graph.edges, [](const auto& e) { return e.label == "case 1"; }));
    EXPECT_TRUE(std::ranges::any_of(graph.edges, [](const auto& e) { return e.label == "case 2"; }));
    ASSERT_EQ(graph.indirect_recoveries.size(), 1u);
    EXPECT_EQ(graph.indirect_recoveries[0].confidence, "IndirectTable");
    EXPECT_EQ(graph.indirect_recoveries[0].target_count, 3u);
    EXPECT_NE(graph.indirect_recoveries[0].evidence.find("RIP-relative i32 jump table @ 0x2000"), std::string::npos);
}

TEST(CallGraph, RecoversThumb2TbbJumpTable) {
    // 0x1000: cmp r0, #1      (01 28)
    // 0x1002: bhi 0x100E      (04 D8)
    // 0x1004: tbb [pc, r0]    (DF E8 00 F0)
    // 0x1008: .byte 1, 2      (01 02 -> targets 0x100A, 0x100C)
    // 0x100A: bx lr           (70 47)
    // 0x100C: bx lr           (70 47)
    // 0x100E: bx lr           (70 47)
    const std::vector<std::uint8_t> code{
        0x01, 0x28,
        0x04, 0xD8,
        0xDF, 0xE8, 0x00, 0xF0,
        0x01, 0x02,
        0x70, 0x47,
        0x70, 0x47,
        0x70, 0x47,
    };
    const viewer::CallGraph graph = viewer::build_function_cfg_call_graph(
        code,
        0x1000,
        peelf::Architecture::ARM,
        peelf::Endianness::Little,
        std::nullopt,
        "thumb_switch",
        true);

    EXPECT_TRUE(std::ranges::any_of(graph.edges, [](const auto& e) { return e.label == "case 0"; }));
    EXPECT_TRUE(std::ranges::any_of(graph.edges, [](const auto& e) { return e.label == "case 1"; }));
    ASSERT_EQ(graph.indirect_recoveries.size(), 1u);
    EXPECT_EQ(graph.indirect_recoveries[0].confidence, "IndirectTable");
    EXPECT_NE(graph.indirect_recoveries[0].evidence.find("Thumb-2 tbb"), std::string::npos);
}

TEST(CallGraph, ResolvesRipRelativeIatSlotIndirectCallsInFanoutGraph) {
    std::vector<std::uint8_t> bytes = read_fixture("known-win-x64.exe");
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    const std::unique_ptr<peelf::IBinaryImage> image = std::move(*parsed);

    const peelf::ImportEntry* imported = nullptr;
    for (const peelf::ImportEntry& entry : image->imports()) {
        if (entry.address != 0 && !entry.name.empty()) {
            imported = &entry;
            break;
        }
    }
    ASSERT_NE(imported, nullptr);

    const std::uint64_t root_va = image->entry_point();
    const auto root_off = image->virtual_address_to_file_offset(root_va);
    ASSERT_TRUE(root_off.has_value());
    ASSERT_LE(*root_off + 8u, bytes.size());

    const std::uint64_t slot_va = imported->address;
    const auto disp32 = static_cast<std::uint32_t>(
        static_cast<std::int32_t>(static_cast<std::int64_t>(slot_va) - static_cast<std::int64_t>(root_va + 6u)));
    const auto pos = static_cast<std::size_t>(*root_off);
    bytes[pos + 0] = 0xFFu;
    bytes[pos + 1] = 0x15u; // call qword ptr [rip + disp32]
    bytes[pos + 2] = static_cast<std::uint8_t>(disp32 & 0xFFu);
    bytes[pos + 3] = static_cast<std::uint8_t>((disp32 >> 8u) & 0xFFu);
    bytes[pos + 4] = static_cast<std::uint8_t>((disp32 >> 16u) & 0xFFu);
    bytes[pos + 5] = static_cast<std::uint8_t>((disp32 >> 24u) & 0xFFu);
    bytes[pos + 6] = 0xC3u;

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol syms[] = {
        viewer::DebugSymbol{.name = "iat_caller", .virtual_address = root_va, .size = 7, .function = true, .library = {}},
    };
    index.add_debug_symbols(*image, syms);
    const viewer::SymbolRecord* root = index.find_by_name("iat_caller");
    ASSERT_NE(root, nullptr);

    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image, std::span<const std::uint8_t>(bytes), index, *root);
    const std::string dot = viewer::to_dot(graph);
    EXPECT_NE(dot.find(imported->name), std::string::npos) << dot;
    ASSERT_FALSE(graph.indirect_recoveries.empty());
    EXPECT_EQ(graph.indirect_recoveries.front().confidence, "IndirectPointerSlot");
}

TEST(CallGraph, EscapesRecordDelimitersForCppTemplatesOperatorsAndBraces) {
    viewer::CallGraph graph{
        .id = "function_cfg",
        .label = "std::less<int>::operator|(a, b)",
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .nodes = {
            viewer::CallGraphNode{
                .id = "bb_0",
                .label = "std::less<int>::operator|{entry}",
                .kind = viewer::CallGraphNodeKind::BasicBlock,
                .instructions = {
                    viewer::GraphInstruction{
                        .address = 0x1000u,
                        .mnemonic = "call",
                        .operands = "std::less<int>::operator|(x, y) ; {closure<T>}",
                    },
                    viewer::GraphInstruction{
                        .address = 0x1005u,
                        .mnemonic = "ret",
                        .operands = "",
                    },
                },
            },
        },
        .edges = {},
        .indirect_recoveries = {},
    };

    const std::string dot = viewer::to_dot(graph);
    EXPECT_NE(dot.find("shape=\"record\""), std::string::npos) << dot;
    // Intentional outer {header|body} compartment delimiters remain intact while inner
    // record characters (<, >, |, {, }) in C++ template/operator text are backslash-escaped.
    EXPECT_NE(dot.find("label=\"{std::less\\<int\\>::operator\\|\\{entry\\}|"), std::string::npos) << dot;
    EXPECT_NE(dot.find("std::less\\<int\\>::operator\\|(x, y) ; \\{closure\\<T\\>\\}"), std::string::npos) << dot;

#if defined(PEELF_GRAPHVIZ_DOT_AVAILABLE) && PEELF_GRAPHVIZ_DOT_AVAILABLE
    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "peelf_call_graph_record_escape_test.svg";
    const std::filesystem::path dot_path = output_path.string() + ".dot";
    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);

    const viewer::DefaultProcessRunner runner;
    const viewer::GraphRenderResult rendered =
        viewer::render_graph_with_graphviz(graph, output_path, viewer::GraphRenderFormat::Svg, runner);
    EXPECT_TRUE(rendered.success) << rendered.diagnostic << "\n" << dot;
    EXPECT_EQ(rendered.exit_code, 0);

    std::filesystem::remove(output_path);
    std::filesystem::remove(dot_path);
#endif
}

TEST(CallGraph, RejectsJumpTableWhenIndexOrFlagsClobberedBetweenCmpGuardAndDispatch) {
    const std::array<std::uint8_t, 12> rodata_table{
        0x1A, 0xF0, 0xFF, 0xFF,
        0x20, 0xF0, 0xFF, 0xFF,
        0x23, 0xF0, 0xFF, 0xFF,
    };
    const viewer::GraphByteReader reader = [&](std::uint64_t va, std::size_t len) -> std::vector<std::uint8_t> {
        if (va == 0x2000u && len == rodata_table.size()) {
            return std::vector<std::uint8_t>(rodata_table.begin(), rodata_table.end());
        }
        return {};
    };

    // Case 1: index register (eax) is clobbered with a constant (`mov eax, 1`) after `ja`,
    // disconnecting `rax` in `[rcx + rax*4]` from the guarded `edi`.
    const std::vector<std::uint8_t> clobbered_index_code{
        0x83, 0xFF, 0x02,                         // 0x1000: cmp edi, 2
        0x77, 0x22,                               // 0x1003: ja 0x1027
        0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1005: mov eax, 1  (clobbers eax!)
        0x48, 0x8D, 0x0D, 0xEF, 0x0F, 0x00, 0x00, // 0x100A: lea rcx, [rip + 0xFEF] -> 0x2000
        0x48, 0x63, 0x04, 0x81,                   // 0x1011: movsxd rax, dword ptr [rcx + rax*4]
        0x48, 0x01, 0xC8,                         // 0x1015: add rax, rcx
        0xFF, 0xE0,                               // 0x1018: jmp rax
        0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3,       // 0x101A
        0x31, 0xC0, 0xC3,                         // 0x1020
        0xB0, 0x02, 0x90, 0xC3,                   // 0x1023
        0x83, 0xC8, 0xFF, 0xC3,                   // 0x1027
    };
    const viewer::CallGraph g_idx = viewer::build_function_cfg_call_graph(
        clobbered_index_code,
        0x1000u,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        std::nullopt,
        "clobbered_idx_switch",
        false,
        true,
        reader);
    EXPECT_TRUE(g_idx.indirect_recoveries.empty());
    EXPECT_FALSE(std::ranges::any_of(g_idx.edges, [](const auto& e) { return e.label.starts_with("case "); }));

    // Case 2: EFLAGS is clobbered (`xor edx, edx`) between `cmp edi, 2` and `ja`,
    // invalidating the unsigned upper-bound guard.
    const std::vector<std::uint8_t> clobbered_flags_code{
        0x83, 0xFF, 0x02,                         // 0x1000: cmp edi, 2
        0x31, 0xD2,                               // 0x1003: xor edx, edx (clobbers EFLAGS!)
        0x77, 0x1F,                               // 0x1005: ja 0x1026
        0x89, 0xF8,                               // 0x1007: mov eax, edi
        0x48, 0x8D, 0x0D, 0xF0, 0x0F, 0x00, 0x00, // 0x1009: lea rcx, [rip + 0xFF0] -> 0x2000
        0x48, 0x63, 0x04, 0x81,                   // 0x1010: movsxd rax, dword ptr [rcx + rax*4]
        0x48, 0x01, 0xC8,                         // 0x1014: add rax, rcx
        0xFF, 0xE0,                               // 0x1017: jmp rax
        0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3,       // 0x1019
        0x31, 0xC0, 0xC3,                         // 0x101F
        0xB0, 0x02, 0x90, 0xC3,                   // 0x1022
        0x83, 0xC8, 0xFF, 0xC3,                   // 0x1026
    };
    const viewer::CallGraph g_flags = viewer::build_function_cfg_call_graph(
        clobbered_flags_code,
        0x1000u,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        std::nullopt,
        "clobbered_flags_switch",
        false,
        true,
        reader);
    EXPECT_TRUE(g_flags.indirect_recoveries.empty());
    EXPECT_FALSE(std::ranges::any_of(g_flags.edges, [](const auto& e) { return e.label.starts_with("case "); }));
}

TEST(CallGraph, FindSymbolForAddressHandlesHighVirtualAddressWithoutUint64Overflow) {
    class HighVaImage final : public peelf::IBinaryImage {
    public:
        HighVaImage() {
            symbols_.push_back(peelf::Symbol{
                .name = "high_va_kernel_stub",
                .virtual_address = 0xFFFF'FFFF'FFFF'FFF0ULL,
                .size = 0x20ULL, // virtual_address + size wraps 64-bit unsigned!
            });
        }
        [[nodiscard]] peelf::Format format() const noexcept override { return peelf::Format::ELF; }
        [[nodiscard]] peelf::ImageKind kind() const noexcept override { return peelf::ImageKind::Executable; }
        [[nodiscard]] peelf::Architecture architecture() const noexcept override { return peelf::Architecture::X86_64; }
        [[nodiscard]] peelf::Endianness endianness() const noexcept override { return peelf::Endianness::Little; }
        [[nodiscard]] bool is_64bit() const noexcept override { return true; }
        [[nodiscard]] std::uint64_t image_base() const noexcept override { return 0; }
        [[nodiscard]] std::uint64_t entry_point() const noexcept override { return 0xFFFF'FFFF'FFFF'FFF0ULL; }
        [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override { return sections_; }
        [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override { return segments_; }
        [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override { return symbols_; }
        [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override { return imports_; }
        [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override { return exports_; }
        [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(std::uint64_t) const noexcept override {
            return std::nullopt;
        }
        [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(std::uint64_t) const noexcept override {
            return std::nullopt;
        }

    private:
        std::vector<peelf::Section> sections_{};
        std::vector<peelf::Segment> segments_{};
        std::vector<peelf::Symbol> symbols_{};
        std::vector<peelf::ImportEntry> imports_{};
        std::vector<peelf::ExportEntry> exports_{};
    };

    const HighVaImage image;
    const auto hit = viewer::find_symbol_for_address(image, 0xFFFF'FFFF'FFFF'FFF8ULL);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->name, "high_va_kernel_stub");
    EXPECT_FALSE(viewer::find_symbol_for_address(image, 0xFFFF'FFFF'FFFF'FFE0ULL).has_value());
}

namespace {

void write_pe_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t val) {
    buf[off + 0u] = static_cast<std::uint8_t>(val & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
}

void write_pe_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t val) {
    buf[off + 0u] = static_cast<std::uint8_t>(val & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((val >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((val >> 24u) & 0xFFu);
}

void write_pe_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t val) {
    write_pe_u32_le(buf, off + 0u, static_cast<std::uint32_t>(val & 0xFFFFFFFFu));
    write_pe_u32_le(buf, off + 4u, static_cast<std::uint32_t>((val >> 32u) & 0xFFFFFFFFu));
}

void write_pe_cstr(std::vector<std::uint8_t>& buf, std::size_t off, std::string_view s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        buf[off + i] = static_cast<std::uint8_t>(s[i]);
    }
    buf[off + s.size()] = 0u;
}

void emit_rel32_at(std::vector<std::uint8_t>& buf,
                   std::size_t opcode_file_off,
                   std::uint8_t opcode,
                   std::uint64_t inst_va,
                   std::uint64_t target_va) {
    const auto rel = static_cast<std::uint32_t>(
        static_cast<std::int32_t>(static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(inst_va + 5u)));
    buf[opcode_file_off] = opcode;
    write_pe_u32_le(buf, opcode_file_off + 1u, rel);
}

void emit_x64_call_rip_iat(std::vector<std::uint8_t>& buf,
                           std::size_t file_off,
                           std::uint64_t inst_va,
                           std::uint64_t slot_va) {
    const auto disp = static_cast<std::uint32_t>(
        static_cast<std::int32_t>(static_cast<std::int64_t>(slot_va) - static_cast<std::int64_t>(inst_va + 6u)));
    buf[file_off + 0u] = 0xFFu;
    buf[file_off + 1u] = 0x15u;
    write_pe_u32_le(buf, file_off + 2u, disp);
}

[[nodiscard]] std::vector<std::uint8_t> build_stripped_pe_crt_fixture(bool pe64) {
    // Layout:
    //   0x000..0x3FF: DOS + PE headers + 2 section headers (.text @ RVA 0x1000, .idata @ RVA 0x2000)
    //   0x400..0x7FF: .text (raw 0x400, RVA 0x1000)
    //   0x800..0xBFF: .idata (raw 0x800, RVA 0x2000) importing KERNEL32.dll:
    //                   slot 0 (@ RVA 0x2050): GetStartupInfoW
    //                   slot 1 (@ RVA 0x2058 / 0x2054): GetCommandLineW
    //                   slot 2 (@ RVA 0x2060 / 0x2058): ExitProcess
    std::vector<std::uint8_t> b(0xC00u, 0u);
    b[0u] = 'M';
    b[1u] = 'Z';
    write_pe_u32_le(b, 0x3Cu, 0x80u);

    b[0x80u] = 'P';
    b[0x81u] = 'E';
    write_pe_u16_le(b, 0x84u, pe64 ? 0x8664u : 0x014Cu);
    write_pe_u16_le(b, 0x86u, 2u);
    const std::uint16_t opt_size = pe64 ? 0xF0u : 0xE0u;
    write_pe_u16_le(b, 0x94u, opt_size);
    write_pe_u16_le(b, 0x96u, pe64 ? 0x0022u : 0x0102u);

    constexpr std::size_t kOpt = 0x98u;
    write_pe_u16_le(b, kOpt + 0x00u, pe64 ? 0x020Bu : 0x010Bu);
    write_pe_u32_le(b, kOpt + 0x10u, 0x1000u); // AddressOfEntryPoint
    if (pe64) {
        write_pe_u64_le(b, kOpt + 0x18u, 0x140000000ULL);
        write_pe_u32_le(b, kOpt + 0x20u, 0x1000u);
        write_pe_u32_le(b, kOpt + 0x24u, 0x200u);
        write_pe_u32_le(b, kOpt + 0x38u, 0x3000u);
        write_pe_u32_le(b, kOpt + 0x3Cu, 0x400u);
        write_pe_u16_le(b, kOpt + 0x44u, 3u); // CUI
        write_pe_u32_le(b, kOpt + 0x6Cu, 16u);
        write_pe_u32_le(b, kOpt + 0x78u, 0x2000u); // Import Directory RVA
        write_pe_u32_le(b, kOpt + 0x7Cu, 40u);
    } else {
        write_pe_u32_le(b, kOpt + 0x1Cu, 0x00400000u);
        write_pe_u32_le(b, kOpt + 0x20u, 0x1000u);
        write_pe_u32_le(b, kOpt + 0x24u, 0x200u);
        write_pe_u32_le(b, kOpt + 0x38u, 0x3000u);
        write_pe_u32_le(b, kOpt + 0x3Cu, 0x400u);
        write_pe_u16_le(b, kOpt + 0x44u, 3u); // CUI
        write_pe_u32_le(b, kOpt + 0x5Cu, 16u);
        write_pe_u32_le(b, kOpt + 0x68u, 0x2000u); // Import Directory RVA
        write_pe_u32_le(b, kOpt + 0x6Cu, 40u);
    }

    const auto write_sec = [&](std::size_t idx, std::string_view name, std::uint32_t rva,
                               std::uint32_t raw_off, std::uint32_t chars) {
        const std::size_t sh = kOpt + opt_size + idx * 40u;
        for (std::size_t i = 0; i < name.size() && i < 8u; ++i) {
            b[sh + i] = static_cast<std::uint8_t>(name[i]);
        }
        write_pe_u32_le(b, sh + 8u, 0x400u);
        write_pe_u32_le(b, sh + 12u, rva);
        write_pe_u32_le(b, sh + 16u, 0x400u);
        write_pe_u32_le(b, sh + 20u, raw_off);
        write_pe_u32_le(b, sh + 36u, chars);
    };
    write_sec(0u, ".text", 0x1000u, 0x400u, 0x60000020u);
    write_sec(1u, ".idata", 0x2000u, 0x800u, 0x40000040u);

    // Populate .idata (raw 0x800 == RVA 0x2000)
    write_pe_u32_le(b, 0x800u + 0u, 0x2030u);  // OriginalFirstThunk
    write_pe_u32_le(b, 0x800u + 12u, 0x2080u); // Name ("KERNEL32.dll")
    write_pe_u32_le(b, 0x800u + 16u, 0x2050u); // FirstThunk (IAT)
    write_pe_cstr(b, 0x880u, "KERNEL32.dll");

    write_pe_u16_le(b, 0x8A0u, 1u);
    write_pe_cstr(b, 0x8A2u, "GetStartupInfoW");
    write_pe_u16_le(b, 0x8C0u, 2u);
    write_pe_cstr(b, 0x8C2u, "GetCommandLineW");
    write_pe_u16_le(b, 0x8E0u, 3u);
    write_pe_cstr(b, 0x8E2u, "ExitProcess");

    const std::array<std::uint32_t, 3> ibn_rvas{0x20A0u, 0x20C0u, 0x20E0u};
    for (std::size_t i = 0; i < ibn_rvas.size(); ++i) {
        if (pe64) {
            write_pe_u64_le(b, 0x830u + i * 8u, ibn_rvas[i]);
            write_pe_u64_le(b, 0x850u + i * 8u, ibn_rvas[i]);
        } else {
            write_pe_u32_le(b, 0x830u + i * 4u, ibn_rvas[i]);
            write_pe_u32_le(b, 0x850u + i * 4u, ibn_rvas[i]);
        }
    }

    if (pe64) {
        // PE32+ x64 MSVC UCRT 2-hop chain:
        //   0x140001000 (entry): sub rsp,0x28; call 0x140001020 (__security_init_cookie); add rsp,0x28; jmp 0x140001040
        //   0x140001020: ret
        //   0x140001040 (__scrt_common_main_seh): sub rsp,0x28; call [GetStartupInfoW]; call 0x140001080 (invoke_main);
        //                                         mov ecx,eax; call [ExitProcess]; int3
        //   0x140001080 (invoke_main): sub rsp,0x28; call [GetCommandLineW]; call 0x140001100 (user_main); add rsp,0x28; ret
        //   0x140001100 (user_main): mov eax, 42; ret
        constexpr std::uint64_t kBase = 0x140000000ULL;
        // 0x140001000 (raw 0x400):
        b[0x400u] = 0x48u; b[0x401u] = 0x83u; b[0x402u] = 0xECu; b[0x403u] = 0x28u;
        emit_rel32_at(b, 0x404u, 0xE8u, kBase + 0x1004u, kBase + 0x1020u);
        b[0x409u] = 0x48u; b[0x40Au] = 0x83u; b[0x40Bu] = 0xC4u; b[0x40Cu] = 0x28u;
        emit_rel32_at(b, 0x40Du, 0xE9u, kBase + 0x100Du, kBase + 0x1040u);

        // 0x140001020 (raw 0x420):
        b[0x420u] = 0xC3u;

        // 0x140001040 (raw 0x440):
        b[0x440u] = 0x48u; b[0x441u] = 0x83u; b[0x442u] = 0xECu; b[0x443u] = 0x28u;
        emit_x64_call_rip_iat(b, 0x444u, kBase + 0x1044u, kBase + 0x2050u); // GetStartupInfoW
        emit_rel32_at(b, 0x44Au, 0xE8u, kBase + 0x104Au, kBase + 0x1080u);  // invoke_main
        b[0x44Fu] = 0x89u; b[0x450u] = 0xC1u;                               // mov ecx, eax
        emit_x64_call_rip_iat(b, 0x451u, kBase + 0x1051u, kBase + 0x2060u); // ExitProcess
        b[0x457u] = 0xCCu;

        // 0x140001080 (raw 0x480):
        b[0x480u] = 0x48u; b[0x481u] = 0x83u; b[0x482u] = 0xECu; b[0x483u] = 0x28u;
        emit_x64_call_rip_iat(b, 0x484u, kBase + 0x1084u, kBase + 0x2058u); // GetCommandLineW
        emit_rel32_at(b, 0x48Au, 0xE8u, kBase + 0x108Au, kBase + 0x1100u);  // user_main
        b[0x48Fu] = 0x48u; b[0x490u] = 0x83u; b[0x491u] = 0xC4u; b[0x492u] = 0x28u;
        b[0x493u] = 0xC3u;

        // 0x140001100 (raw 0x500):
        b[0x500u] = 0xB8u; write_pe_u32_le(b, 0x501u, 42u);
        b[0x505u] = 0xC3u;
    } else {
        // PE32 x86 1-hop CRT chain:
        //   0x00401000 (entry): call 0x00401010 (__security_init_cookie); jmp 0x00401020 (__tmainCRTStartup)
        //   0x00401010: ret
        //   0x00401020 (__tmainCRTStartup): call [0x402050]; call [0x402054]; call 0x00401080 (main);
        //                                   push eax; call [0x402058]; int3
        //   0x00401080 (main): mov eax, 7; ret
        constexpr std::uint64_t kBase = 0x00400000ULL;
        emit_rel32_at(b, 0x400u, 0xE8u, kBase + 0x1000u, kBase + 0x1010u);
        emit_rel32_at(b, 0x405u, 0xE9u, kBase + 0x1005u, kBase + 0x1020u);

        b[0x410u] = 0xC3u;

        // 0x00401020 (raw 0x420):
        b[0x420u] = 0xFFu; b[0x421u] = 0x15u; write_pe_u32_le(b, 0x422u, 0x00402050u); // GetStartupInfoW
        b[0x426u] = 0xFFu; b[0x427u] = 0x15u; write_pe_u32_le(b, 0x428u, 0x00402054u); // GetCommandLineW
        emit_rel32_at(b, 0x42Cu, 0xE8u, kBase + 0x102Cu, kBase + 0x1080u);             // user main
        b[0x431u] = 0x50u;                                                             // push eax
        b[0x432u] = 0xFFu; b[0x433u] = 0x15u; write_pe_u32_le(b, 0x434u, 0x00402058u); // ExitProcess
        b[0x438u] = 0xCCu;

        // 0x00401080 (raw 0x480):
        b[0x480u] = 0xB8u; write_pe_u32_le(b, 0x481u, 7u);
        b[0x485u] = 0xC3u;
    }

    return b;
}

} // namespace

TEST(CallGraph, EmitsDeterministicGoldenDotSnapshot) {
    const viewer::CallGraph graph{
        .id = "function_cfg",
        .label = "golden_cfg",
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .nodes = {
            viewer::CallGraphNode{
                .id = "bb_0",
                .label = "entry_block",
                .kind = viewer::CallGraphNodeKind::BasicBlock,
                .instructions = {
                    viewer::GraphInstruction{
                        .address = 0x1000u,
                        .mnemonic = "test",
                        .operands = "edi, edi",
                    },
                    viewer::GraphInstruction{
                        .address = 0x1002u,
                        .mnemonic = "je",
                        .operands = "0x100c",
                        .branch_target = 0x100Cu,
                    },
                },
            },
            viewer::CallGraphNode{
                .id = "bb_1",
                .label = "taken_call",
                .kind = viewer::CallGraphNodeKind::Function,
                .bytes = viewer::GraphByteRange{
                    .start = viewer::GraphAddress{
                        .virtual_address = 0x1004u,
                        .file_offset = 0x200u,
                    },
                    .size = 8u,
                },
                .symbol = viewer::GraphSymbolRef{
                    .name = "helper_fn",
                    .symbol_index = 1u,
                },
            },
            viewer::CallGraphNode{
                .id = "imp_exit",
                .label = "KERNEL32.dll!ExitProcess",
                .kind = viewer::CallGraphNodeKind::Import,
            },
            viewer::CallGraphNode{
                .id = "return",
                .label = "return",
                .kind = viewer::CallGraphNodeKind::External,
            },
        },
        .edges = {
            viewer::CallGraphEdge{
                .from_node_id = "bb_0",
                .to_node_id = "return",
                .kind = viewer::CallGraphEdgeKind::ConditionalBranch,
                .label = "true",
            },
            viewer::CallGraphEdge{
                .from_node_id = "bb_0",
                .to_node_id = "bb_1",
                .kind = viewer::CallGraphEdgeKind::Fallthrough,
                .label = "false",
            },
            viewer::CallGraphEdge{
                .from_node_id = "bb_1",
                .to_node_id = "imp_exit",
                .kind = viewer::CallGraphEdgeKind::DirectCall,
                .label = "call",
            },
            viewer::CallGraphEdge{
                .from_node_id = "bb_1",
                .to_node_id = "return",
                .kind = viewer::CallGraphEdgeKind::Return,
            },
        },
    };

    constexpr std::string_view kExpectedDot =
        "digraph \"function_cfg\" {\n"
        "  graph [rankdir=\"TB\", labelloc=\"t\", label=\"golden_cfg\"];\n"
        "  node [fontname=\"Consolas\", fontsize=\"10\"];\n"
        "  edge [fontname=\"Consolas\", fontsize=\"9\"];\n"
        "  \"bb_0\" [shape=\"record\", label=\"{entry_block|0x1000  test edi, edi\\n0x1002  je 0x100c}\"];\n"
        "  \"bb_1\" [shape=\"box\", label=\"taken_call\\nVA 0x1004\\nfile 0x200\\nhelper_fn\"];\n"
        "  \"imp_exit\" [shape=\"component\", label=\"KERNEL32.dll!ExitProcess\"];\n"
        "  \"return\" [shape=\"oval\", label=\"return\"];\n"
        "  \"bb_0\" -> \"return\" [color=\"#ff7f0e\",style=\"dashed\", label=\"true\"];\n"
        "  \"bb_0\" -> \"bb_1\" [color=\"#2ca02c\", label=\"false\"];\n"
        "  \"bb_1\" -> \"imp_exit\" [color=\"#1f77b4\", label=\"call\"];\n"
        "  \"bb_1\" -> \"return\" [color=\"#9467bd\"];\n"
        "}\n";

    EXPECT_EQ(viewer::to_dot(graph), kExpectedDot);
}

TEST(CallGraph, ClassifiesConditionalTrueFalseUnconditionalFallthroughAndReturnAcrossArchitectures) {
    // 1. x86_64 diamond:
    //   bb_0 (0x1000): test edi, edi; je 0x1009 (bb_2)
    //   bb_1 (0x1004): mov eax, 1; jmp 0x100B (bb_3)
    //   bb_2 (0x1009): xor eax, eax (falls through to bb_3)
    //   bb_3 (0x100B): ret -> return
    const std::array<std::uint8_t, 12> x64_diamond{
        0x85u, 0xFFu,                         // 0x1000: test edi, edi
        0x74u, 0x05u,                         // 0x1002: je 0x1009
        0xB8u, 0x01u, 0x00u, 0x00u, 0x00u,    // 0x1004: mov eax, 1
        0xEBu, 0x02u,                         // 0x1009? wait -> let's check offsets!
        0xC3u,
    };
    (void)x64_diamond;

    const std::array<std::uint8_t, 14> x64_cfg_bytes{
        0x85u, 0xFFu,                         // 0x1000: test edi, edi (2)
        0x74u, 0x07u,                         // 0x1002: je 0x100B     (2 -> next 0x1004, +7 = 0x100B)
        0xB8u, 0x01u, 0x00u, 0x00u, 0x00u,    // 0x1004: mov eax, 1    (5)
        0xEBu, 0x02u,                         // 0x1009: jmp 0x100D    (2 -> next 0x100B, +2 = 0x100D)
        0x31u, 0xC0u,                         // 0x100B: xor eax, eax  (2 -> falls through to 0x100D)
        0xC3u,                                // 0x100D: ret           (1)
    };
    const viewer::CallGraph x64_cfg = viewer::build_function_cfg_call_graph(
        x64_cfg_bytes, 0x1000u, peelf::Architecture::X86_64, peelf::Endianness::Little, std::nullopt, "x64_diamond");
    EXPECT_TRUE(has_edge(x64_cfg, "bb_0", "bb_2", viewer::CallGraphEdgeKind::ConditionalBranch));
    EXPECT_TRUE(has_edge(x64_cfg, "bb_0", "bb_1", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(x64_cfg, "bb_1", "bb_3", viewer::CallGraphEdgeKind::UnconditionalBranch));
    EXPECT_FALSE(has_edge(x64_cfg, "bb_1", "bb_2", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(x64_cfg, "bb_2", "bb_3", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(x64_cfg, "bb_3", "return", viewer::CallGraphEdgeKind::Return));

    // 2. ARM64 diamond:
    //   bb_0 (0x2000): cbz w0, 0x200C (bb_2)
    //   bb_1 (0x2004): mov w0, #1; b 0x2010 (bb_3)
    //   bb_2 (0x200C): mov w0, #0 (falls through to bb_3)
    //   bb_3 (0x2010): ret
    const std::array<std::uint8_t, 20> arm64_cfg_bytes{
        0x60u, 0x00u, 0x00u, 0x34u, // 0x2000: cbz w0, #0x200c
        0x20u, 0x00u, 0x80u, 0x52u, // 0x2004: mov w0, #1
        0x02u, 0x00u, 0x00u, 0x14u, // 0x2008: b #0x2010
        0x00u, 0x00u, 0x80u, 0x52u, // 0x200C: mov w0, #0
        0xC0u, 0x03u, 0x5Fu, 0xD6u, // 0x2010: ret
    };
    const viewer::CallGraph arm64_cfg = viewer::build_function_cfg_call_graph(
        arm64_cfg_bytes, 0x2000u, peelf::Architecture::ARM64, peelf::Endianness::Little, std::nullopt, "arm64_diamond");
    EXPECT_TRUE(has_edge(arm64_cfg, "bb_0", "bb_2", viewer::CallGraphEdgeKind::ConditionalBranch));
    EXPECT_TRUE(has_edge(arm64_cfg, "bb_0", "bb_1", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(arm64_cfg, "bb_1", "bb_3", viewer::CallGraphEdgeKind::UnconditionalBranch));
    EXPECT_FALSE(has_edge(arm64_cfg, "bb_1", "bb_2", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(arm64_cfg, "bb_2", "bb_3", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(arm64_cfg, "bb_3", "return", viewer::CallGraphEdgeKind::Return));

    // 3. RISC-V64 diamond:
    //   bb_0 (0x3000): beq a0, zero, +12 (0x300C -> bb_2)
    //   bb_1 (0x3004): addi a0, zero, 1; jal zero, +8 (0x3010 -> bb_3)
    //   bb_2 (0x300C): addi a0, zero, 0 (falls through to bb_3)
    //   bb_3 (0x3010): jalr zero, ra, 0 (ret)
    const std::array<std::uint8_t, 20> rv64_cfg_bytes{
        0x63u, 0x06u, 0x05u, 0x00u, // 0x3000: beq a0, zero, +12 -> 0x300C
        0x13u, 0x05u, 0x10u, 0x00u, // 0x3004: addi a0, zero, 1
        0x6Fu, 0x00u, 0x80u, 0x00u, // 0x3008: jal zero, +8 -> 0x3010
        0x13u, 0x05u, 0x00u, 0x00u, // 0x300C: addi a0, zero, 0
        0x67u, 0x80u, 0x00u, 0x00u, // 0x3010: ret (jalr zero, ra, 0)
    };
    const viewer::CallGraph rv64_cfg = viewer::build_function_cfg_call_graph(
        rv64_cfg_bytes, 0x3000u, peelf::Architecture::RISCV64, peelf::Endianness::Little, std::nullopt, "rv64_diamond");
    EXPECT_TRUE(has_edge(rv64_cfg, "bb_0", "bb_2", viewer::CallGraphEdgeKind::ConditionalBranch));
    EXPECT_TRUE(has_edge(rv64_cfg, "bb_0", "bb_1", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(rv64_cfg, "bb_1", "bb_3", viewer::CallGraphEdgeKind::UnconditionalBranch));
    EXPECT_FALSE(has_edge(rv64_cfg, "bb_1", "bb_2", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(rv64_cfg, "bb_2", "bb_3", viewer::CallGraphEdgeKind::Fallthrough));
    EXPECT_TRUE(has_edge(rv64_cfg, "bb_3", "return", viewer::CallGraphEdgeKind::Return));
}

TEST(CallGraph, RecoversStrippedPeX64AndX86CrtToUserMainCallFlow) {
    // 1. Stripped PE32+ x64 (2-hop entry -> __scrt_common_main_seh -> invoke_main -> user WinMain/main)
    {
        const std::vector<std::uint8_t> pe64_bytes = build_stripped_pe_crt_fixture(true);
        auto parsed64 = peelf::parse_image(pe64_bytes);
        ASSERT_TRUE(parsed64.has_value());
        const std::unique_ptr<peelf::IBinaryImage> pe64 = std::move(*parsed64);
        ASSERT_TRUE(pe64->symbols().empty());

        const viewer::CallGraph graph = viewer::build_entry_call_graph(*pe64);
        EXPECT_EQ(find_node(graph, "winmain_unresolved"), nullptr);

        const viewer::CallGraphNode* crt_node = find_node(graph, "crt_startup");
        const viewer::CallGraphNode* user_node = find_node(graph, "user_entry");
        ASSERT_NE(crt_node, nullptr);
        ASSERT_NE(user_node, nullptr);
        ASSERT_NE(find_node(graph, "entry_symbol"), nullptr);
        EXPECT_EQ(crt_node->bytes.start.virtual_address, std::optional<std::uint64_t>{0x140001040ULL});
        EXPECT_EQ(user_node->bytes.start.virtual_address, std::optional<std::uint64_t>{0x140001100ULL});
        EXPECT_TRUE(has_edge(graph, "entry_symbol", "crt_startup", viewer::CallGraphEdgeKind::DirectCall));
        EXPECT_TRUE(has_edge(graph, "crt_startup", "user_entry", viewer::CallGraphEdgeKind::DirectCall));
    }

    // 2. Stripped PE32 x86 (1-hop entry -> __tmainCRTStartup -> user main)
    {
        const std::vector<std::uint8_t> pe32_bytes = build_stripped_pe_crt_fixture(false);
        auto parsed32 = peelf::parse_image(pe32_bytes);
        ASSERT_TRUE(parsed32.has_value());
        const std::unique_ptr<peelf::IBinaryImage> pe32 = std::move(*parsed32);
        ASSERT_TRUE(pe32->symbols().empty());

        const viewer::CallGraph graph = viewer::build_entry_call_graph(*pe32);
        EXPECT_EQ(find_node(graph, "winmain_unresolved"), nullptr);

        const viewer::CallGraphNode* crt_node = find_node(graph, "crt_startup");
        const viewer::CallGraphNode* user_node = find_node(graph, "user_entry");
        ASSERT_NE(crt_node, nullptr);
        ASSERT_NE(user_node, nullptr);
        ASSERT_NE(find_node(graph, "entry_symbol"), nullptr);
        EXPECT_EQ(crt_node->bytes.start.virtual_address, std::optional<std::uint64_t>{0x00401020ULL});
        EXPECT_EQ(user_node->bytes.start.virtual_address, std::optional<std::uint64_t>{0x00401080ULL});
        EXPECT_TRUE(has_edge(graph, "entry_symbol", "crt_startup", viewer::CallGraphEdgeKind::DirectCall));
        EXPECT_TRUE(has_edge(graph, "crt_startup", "user_entry", viewer::CallGraphEdgeKind::DirectCall));
    }
}

TEST(CallGraph, GraphNodeClickSelectionRoundTripsThroughNavigationRequestQueue) {
    const std::vector<std::uint8_t> pe64_bytes = build_stripped_pe_crt_fixture(true);
    auto parsed64 = peelf::parse_image(pe64_bytes);
    ASSERT_TRUE(parsed64.has_value());
    const std::unique_ptr<peelf::IBinaryImage> pe64 = std::move(*parsed64);

    const viewer::CallGraph graph = viewer::build_entry_call_graph(*pe64);
    const viewer::CallGraphNode* user_node = find_node(graph, "user_entry");
    ASSERT_NE(user_node, nullptr);

    // Simulate clicking the recovered user_entry node on the Flow Graph canvas.
    const viewer::ViewerSelection sel = viewer::selection_from_call_graph_node(*user_node, *pe64);
    EXPECT_EQ(sel.kind, viewer::SelectionKind::CallGraphNode);
    EXPECT_EQ(sel.preferred_view, viewer::PreferredView::Disassembly);
    EXPECT_EQ(sel.virtual_address, std::optional<std::uint64_t>{0x140001100ULL});
    EXPECT_EQ(sel.file_offset, std::optional<std::uint64_t>{0x500ULL});

    viewer::NavigationRequestQueue queue{};
    viewer::NavigationHistory history{};
    ASSERT_TRUE(viewer::enqueue_structure_selection_activation(queue, sel));

    std::optional<std::uint64_t> navigated_va{};
    viewer::PreferredView navigated_view = viewer::PreferredView::Details;
    const std::size_t drained = queue.drain([&](viewer::DeferredNavigationRequest& req) {
        if (req.kind == viewer::DeferredNavigationRequest::Kind::Address) {
            navigated_va = req.target;
            navigated_view = req.preferred_view;
            history.visit(sel);
        }
    });

    EXPECT_EQ(drained, 1u);
    EXPECT_EQ(navigated_va, std::optional<std::uint64_t>{0x140001100ULL});
    EXPECT_EQ(navigated_view, viewer::PreferredView::Disassembly);
    ASSERT_FALSE(history.entries().empty());
    EXPECT_EQ(history.entries()[history.cursor()].virtual_address,
              std::optional<std::uint64_t>{0x140001100ULL});
}


namespace {

void set_test_env(const char* key, const char* value) {
#ifdef _WIN32
    _putenv_s(key, value != nullptr ? value : "");
#else
    if (value != nullptr) {
        ::setenv(key, value, 1);
    } else {
        ::unsetenv(key);
    }
#endif
}

} // namespace

TEST(HeadlessGraphCli, HelpListsGraphFlagsAndFormatInferenceFollowsContract) {
    std::ostringstream out_ss;
    std::ostringstream err_ss;
    const std::array<std::string_view, 1> help_args{"--help"};
    const auto help_rc = viewer::try_run_headless_or_help_cli(help_args, out_ss, err_ss);
    ASSERT_TRUE(help_rc.has_value());
    EXPECT_EQ(*help_rc, 0);
    EXPECT_NE(out_ss.str().find("--graph <entry|fanout|cfg>"), std::string::npos);
    EXPECT_NE(out_ss.str().find("--symbol <name-or-va>"), std::string::npos);
    EXPECT_NE(out_ss.str().find("--graph-depth <N>"), std::string::npos);
    EXPECT_NE(out_ss.str().find("--graph-max-nodes <N>"), std::string::npos);
    EXPECT_NE(out_ss.str().find("--graph-format <dot|svg|png|json>"), std::string::npos);

    viewer::HeadlessOptions opts{};
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Dot);

    opts.output_path = std::filesystem::path("flow.svg");
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Svg);

    opts.output_path = std::filesystem::path("flow.dot");
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Dot);

    opts.output_path = std::filesystem::path("flow.png");
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Png);

    opts.output_path = std::filesystem::path("flow.json");
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Json);

    opts.output_path = std::filesystem::path("flow.unknown");
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Svg);

    opts.graph_format = viewer::HeadlessGraphFormat::Json;
    EXPECT_EQ(viewer::resolve_headless_graph_format(opts), viewer::HeadlessGraphFormat::Json);
}

TEST(HeadlessGraphCli, ExportsEntryFanoutAndCfgWithDemangledHexAndSubstringLookup) {
    const std::filesystem::path hello_path =
        std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "hello.elf";
    const std::string hello_str = hello_path.string();

    // 1. Entry graph to stdout defaults to DOT
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 4> args{
            "--headless", hello_str, "--graph", "entry"};
        const auto rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        EXPECT_NE(out_ss.str().find("digraph"), std::string::npos);
        EXPECT_NE(out_ss.str().find("main"), std::string::npos);
    }

    // 2. Fanout on `add` discovers caller `main` and emits valid deterministic JSON
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 8> args{
            "--headless", hello_str,
            "--graph", "fanout",
            "--symbol", "add",
            "--graph-format", "json"};
        const auto rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        const std::string json = out_ss.str();
        EXPECT_NE(json.find("\"kind\": \"fanout\""), std::string::npos);
        EXPECT_NE(json.find("\"root\": \"add\""), std::string::npos);
        EXPECT_NE(json.find("\"label\": \"main\""), std::string::npos);
        EXPECT_NE(json.find("\"label\": \"caller\""), std::string::npos);
    }

    // 3. CFG on `main` via hex VA (0x1161) resolves basic blocks + call targets (`add`, `printf`)
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 8> args{
            "--headless", hello_str,
            "--graph", "cfg",
            "--symbol", "0x1161",
            "--graph-format", "json"};
        const auto rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        const std::string json = out_ss.str();
        EXPECT_NE(json.find("\"kind\": \"cfg\""), std::string::npos);
        EXPECT_NE(json.find("\"kind\": \"basic_block\""), std::string::npos);
        EXPECT_NE(json.find("add"), std::string::npos);
    }

    // 4. C++ Itanium mangled symbol (`_Z14handle_requesti`) resolved by base name `handle_request`
    //    and by unique substring `handle_req`
    {
        std::vector<std::uint8_t> mangled_elf = read_fixture("hello.elf");
        const std::string_view old_sym = "__do_global_dtors_aux";
        const std::string_view new_sym = "_Z10handle_reqi";
        ASSERT_LT(new_sym.size(), old_sym.size());
        const auto pos = std::search(
            mangled_elf.begin(), mangled_elf.end(), old_sym.begin(), old_sym.end());
        ASSERT_NE(pos, mangled_elf.end());
        std::fill(pos, pos + static_cast<std::ptrdiff_t>(old_sym.size()), std::uint8_t{0});
        std::copy(new_sym.begin(), new_sym.end(), pos);

        const std::filesystem::path tmp_elf =
            std::filesystem::current_path() / "headless_mangled_test_fixture.elf";
        {
            std::ofstream ofs(tmp_elf, std::ios::binary);
            ASSERT_TRUE(ofs);
            ofs.write(
                reinterpret_cast<const char*>(mangled_elf.data()),
                static_cast<std::streamsize>(mangled_elf.size()));
        }

        const std::string tmp_elf_str = tmp_elf.string();
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 8> base_args{
            "--headless", tmp_elf_str,
            "--graph", "fanout",
            "--symbol", "handle_req",
            "--graph-format", "json"};
        const auto rc1 = viewer::try_run_headless_or_help_cli(base_args, out_ss, err_ss);
        ASSERT_TRUE(rc1.has_value());
        EXPECT_EQ(*rc1, 0) << err_ss.str();
        EXPECT_NE(out_ss.str().find("handle_req(int)"), std::string::npos);

        out_ss.str("");
        err_ss.str("");
        const std::array<std::string_view, 8> sub_args{
            "--headless", tmp_elf_str,
            "--graph", "cfg",
            "--symbol", "ndle_re",
            "--graph-format", "dot"};
        const auto rc2 = viewer::try_run_headless_or_help_cli(sub_args, out_ss, err_ss);
        ASSERT_TRUE(rc2.has_value());
        EXPECT_EQ(*rc2, 0) << err_ss.str();
        EXPECT_NE(out_ss.str().find("handle_req(int)"), std::string::npos);

        std::error_code ec{};
        std::filesystem::remove(tmp_elf, ec);
    }
}

TEST(HeadlessGraphCli, RendersWithRunnerCleansSidecarAndFailsClearlyWhenDotMissing) {
    const std::filesystem::path hello_path =
        std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "hello.elf";
    const std::filesystem::path out_svg =
        std::filesystem::current_path() / "headless_graph_cli_test_out.svg";
    const std::filesystem::path sidecar_dot = out_svg.string() + ".dot";
    std::error_code ec{};
    std::filesystem::remove(out_svg, ec);
    std::filesystem::remove(sidecar_dot, ec);

    // Injected FakeProcessRunner exercises SVG render + sidecar DOT cleanup deterministically
    {
        FakeProcessRunner fake{};
        viewer::HeadlessOptions opts{};
        opts.binary_path = hello_path;
        opts.graph_kind = viewer::HeadlessGraphKind::Entry;
        opts.output_path = out_svg;
        std::ostringstream out_ss;
        const auto res = viewer::export_headless_graph(opts, out_ss, &fake);
        ASSERT_TRUE(res.has_value()) << res.error().message;
        EXPECT_FALSE(fake.arguments_.empty());
        EXPECT_FALSE(std::filesystem::exists(sidecar_dot));
    }

    // Missing Graphviz `dot` returns non-zero with clear diagnostic
    {
        set_test_env("PEELF_DOT_EXECUTABLE", "/nonexistent_dir/missing_dot_binary");
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::string hello_str = hello_path.string();
        const std::string out_svg_str = out_svg.string();
        const std::array<std::string_view, 6> args{
            "--headless", hello_str, "--graph", "entry", "--output", out_svg_str};
        const auto rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        set_test_env("PEELF_DOT_EXECUTABLE", nullptr);

        ASSERT_TRUE(rc.has_value());
        EXPECT_NE(*rc, 0);
        EXPECT_NE(err_ss.str().find("Graphviz 'dot'"), std::string::npos);
    }

    // CLI validation errors (missing --headless, missing --symbol for cfg)
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::string hello_str = hello_path.string();
        const std::array<std::string_view, 3> no_headless{hello_str, "--graph", "entry"};
        const auto rc1 = viewer::try_run_headless_or_help_cli(no_headless, out_ss, err_ss);
        ASSERT_TRUE(rc1.has_value());
        EXPECT_NE(*rc1, 0);

        out_ss.str("");
        err_ss.str("");
        const std::array<std::string_view, 4> no_sym{"--headless", hello_str, "--graph", "cfg"};
        const auto rc2 = viewer::try_run_headless_or_help_cli(no_sym, out_ss, err_ss);
        ASSERT_TRUE(rc2.has_value());
        EXPECT_NE(*rc2, 0);
        EXPECT_NE(err_ss.str().find("--symbol"), std::string::npos);
    }

    std::filesystem::remove(out_svg, ec);
    std::filesystem::remove(sidecar_dot, ec);
}

