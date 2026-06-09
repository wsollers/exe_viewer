#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>

namespace viewer {

struct GraphAddress {
    std::optional<std::uint64_t> virtual_address;
    std::optional<std::uint64_t> relative_virtual_address;
    std::optional<std::uint64_t> file_offset;
};

struct GraphByteRange {
    GraphAddress start;
    std::uint64_t size = 0;
};

struct GraphSymbolRef {
    std::string name;
    std::uint64_t symbol_index = 0;
    bool dynamic = false;
};

enum class CallGraphNodeKind : std::uint8_t {
    Function,
    BasicBlock,
    Instruction,
    Import,
    External,
    Unknown
};

enum class CallGraphEdgeKind : std::uint8_t {
    Call,
    ConditionalBranch,
    UnconditionalBranch,
    Fallthrough,
    Return,
    DataReference,
    Unknown
};

struct CallGraphNode {
    std::string id;
    std::string label;
    CallGraphNodeKind kind = CallGraphNodeKind::Unknown;
    GraphByteRange bytes;
    std::optional<GraphSymbolRef> symbol;
    std::uint64_t first_instruction_index = 0;
    std::uint64_t instruction_count = 0;
};

struct CallGraphEdge {
    std::string from_node_id;
    std::string to_node_id;
    CallGraphEdgeKind kind = CallGraphEdgeKind::Unknown;
    std::string label;
};

struct CallGraph {
    std::string id;
    std::string label;
    peelf::Architecture architecture = peelf::Architecture::Unknown;
    peelf::Endianness endianness = peelf::Endianness::Little;
    std::vector<CallGraphNode> nodes;
    std::vector<CallGraphEdge> edges;
};

enum class GraphRenderFormat : std::uint8_t {
    Svg,
    Png,
    Bmp
};

struct GraphRenderCommand {
    std::string executable;
    std::vector<std::string> arguments;
};

struct GraphRenderResult {
    bool success = false;
    std::int32_t exit_code = -1;
    std::string diagnostic;
};

class IProcessRunner {
public:
    virtual ~IProcessRunner() = default;
    [[nodiscard]] virtual GraphRenderResult run(std::string_view executable,
                                                std::span<const std::string> arguments) const = 0;
};

class DefaultProcessRunner final : public IProcessRunner {
public:
    [[nodiscard]] GraphRenderResult run(std::string_view executable,
                                        std::span<const std::string> arguments) const override;
};

[[nodiscard]] std::string to_dot(const CallGraph& graph);
[[nodiscard]] CallGraph build_entry_call_graph(const peelf::IBinaryImage& image);
[[nodiscard]] std::string_view graphviz_format_name(GraphRenderFormat format) noexcept;
[[nodiscard]] std::optional<GraphSymbolRef> find_symbol_for_address(const peelf::IBinaryImage& image,
                                                                    std::uint64_t virtual_address);
[[nodiscard]] GraphRenderCommand make_graphviz_render_command(const std::filesystem::path& dot_path,
                                                              const std::filesystem::path& output_path,
                                                              GraphRenderFormat format,
                                                              std::string dot_executable = {});
[[nodiscard]] GraphRenderResult render_graph_with_graphviz(const CallGraph& graph,
                                                           const std::filesystem::path& output_path,
                                                           GraphRenderFormat format,
                                                           const IProcessRunner& runner);

} // namespace viewer
