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

    EXPECT_NE(main_dot.find("peelf_fixture_first"), std::string::npos);
    EXPECT_NE(main_dot.find("peelf_fixture_second"), std::string::npos);
    EXPECT_EQ(main_dot.find("call target\\n0x"), std::string::npos);

    const viewer::SymbolRecord* first = index.find_by_name("peelf_fixture_first");
    ASSERT_NE(first, nullptr);
    const viewer::CallGraph first_graph = viewer::build_symbol_fanout_call_graph(
        *image,
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        index,
        *first);
    const std::string first_dot = viewer::to_dot(first_graph);

    EXPECT_NE(first_dot.find("peelf_fixture_first fan-out"), std::string::npos);
    EXPECT_NE(first_dot.find("peelf_fixture_leaf"), std::string::npos);
    EXPECT_EQ(first_dot.find("No direct call targets resolved"), std::string::npos);
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
