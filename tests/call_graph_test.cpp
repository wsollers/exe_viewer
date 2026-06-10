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
#include "symbols/debug_symbols.hpp"
#include <peelf/binary_image.hpp>

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
    const char* image_name;
    peelf::Architecture architecture;
    peelf::Endianness endianness;
    bool is_64bit;
};

void assert_known_callgraph_fixture(const BinMatrixCase& fixture) {
    const std::string name = fixture.image_name;
    const std::filesystem::path path = std::filesystem::path(PEELF_BIN_MATRIX_DIR) / fixture.image_name;
    std::filesystem::path sidecar = path;
    sidecar.replace_extension(".debug");
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
        {"elf-linux-x86_64-64-le-callgraph.elf", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"elf-linux-x86-32-le-callgraph.elf", peelf::Architecture::X86, peelf::Endianness::Little, false},
        {"elf-linux-arm-32-le-callgraph.elf", peelf::Architecture::ARM, peelf::Endianness::Little, false},
        {"elf-linux-arm64-64-le-callgraph.elf", peelf::Architecture::ARM64, peelf::Endianness::Little, true},
        {"elf-linux-riscv64-64-le-callgraph.elf", peelf::Architecture::RISCV64, peelf::Endianness::Little, true},
        {"elf-linux-mips-32-be-callgraph.elf", peelf::Architecture::MIPS32, peelf::Endianness::Big, false},
        {"elf-linux-mips64-64-be-callgraph.elf", peelf::Architecture::MIPS64, peelf::Endianness::Big, true},
        {"elf-linux-ppc-32-be-callgraph.elf", peelf::Architecture::PowerPC, peelf::Endianness::Big, false},
        {"elf-linux-ppc64-64-be-callgraph.elf", peelf::Architecture::PowerPC64, peelf::Endianness::Big, true},
    }};

    for (const BinMatrixCase& fixture : fixtures) {
        assert_known_callgraph_fixture(fixture);
    }
}

TEST(CallGraph, DebugViewerMainFanoutResolvesRealTargetNames) {
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

    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("main fan-out"), std::string::npos) << dot;
    EXPECT_NE(dot.find("label=\"call\""), std::string::npos) << dot;
    EXPECT_NE(dot.find("viewer::Application::init"), std::string::npos) << dot;
    EXPECT_NE(dot.find("viewer::Application::run"), std::string::npos) << dot;
    EXPECT_EQ(dot.find("call target\\n0x"), std::string::npos) << dot;
#endif
}

TEST(CallGraph, DebugElfViewerMainFanoutResolvesRealTargetNames) {
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
    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);
    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *main);
    const std::string dot = viewer::to_dot(graph);

    EXPECT_NE(dot.find("main fan-out"), std::string::npos) << dot;
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
