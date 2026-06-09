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
