#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>

#include "symbols/symbol_index.hpp"

namespace viewer {

struct GraphAddress {
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> relative_virtual_address{};
    std::optional<std::uint64_t> file_offset{};
};

struct GraphByteRange {
    GraphAddress start{};
    std::uint64_t size = 0;
};

struct GraphSymbolRef {
    std::string name{};
    std::string demangled_name{};
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

struct GraphInstruction {
    std::uint64_t address = 0;
    std::string mnemonic{};
    std::string operands{};
    std::optional<std::uint64_t> branch_target{};
};

enum class FunctionExtentSource : std::uint8_t { Symbol, RuntimeMetadata, NextSymbol, ExecutableRegion };

struct FunctionExtent {
    std::uint64_t file_offset = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t size = 0;
    FunctionExtentSource source = FunctionExtentSource::ExecutableRegion;
    bool truncated = false;
};

// Bounds are always limited to mapped executable bytes and the supplied file size.
[[nodiscard]] std::optional<FunctionExtent> discover_function_extent(
    const peelf::IBinaryImage& image, const SymbolIndex& symbols, const SymbolRecord& root,
    std::uint64_t image_size, std::uint64_t max_bytes = 16384);
[[nodiscard]] std::string_view function_extent_source_name(FunctionExtentSource source) noexcept;

struct CallGraphNode {
    std::string id{};
    std::string label{};
    CallGraphNodeKind kind = CallGraphNodeKind::Unknown;
    GraphByteRange bytes{};
    std::optional<GraphSymbolRef> symbol{};
    std::uint64_t first_instruction_index = 0;
    std::uint64_t instruction_count = 0;
    std::vector<GraphInstruction> instructions{};
};

struct CallGraphEdge {
    std::string from_node_id{};
    std::string to_node_id{};
    CallGraphEdgeKind kind = CallGraphEdgeKind::Unknown;
    std::string label{};
};

struct IndirectRecoveryNote {
    std::uint64_t source_address = 0;
    std::uint64_t table_or_slot_address = 0;
    std::size_t target_count = 0;
    std::string confidence;
    std::string evidence;
};

struct CallGraph {
    std::string id;
    std::string label;
    peelf::Architecture architecture = peelf::Architecture::Unknown;
    peelf::Endianness endianness = peelf::Endianness::Little;
    std::vector<CallGraphNode> nodes;
    std::vector<CallGraphEdge> edges;
    std::vector<IndirectRecoveryNote> indirect_recoveries{};
};

// Relationships are limited to the currently analyzed graph, not a whole-image call index.
[[nodiscard]] inline std::vector<std::string> call_neighbors(const CallGraph& graph,
                                                            std::string_view node_id, bool callers) {
    std::vector<std::string> result;
    for (const auto& edge : graph.edges) {
        if (edge.kind != CallGraphEdgeKind::Call) continue;
        if ((callers ? edge.to_node_id : edge.from_node_id) != node_id) continue;
        const auto& id = callers ? edge.from_node_id : edge.to_node_id;
        bool seen = false;
        for (const auto& existing : result) if (existing == id) { seen = true; break; }
        if (!seen) result.push_back(id);
    }
    return result;
}

struct GraphLayoutNode {
    std::string node_id;
    double center_x = 0.0;
    double center_y = 0.0;
    double width = 0.0;
    double height = 0.0;
};

struct GraphLayout {
    double width = 0.0;
    double height = 0.0;
    std::vector<GraphLayoutNode> nodes;
};

enum class GraphRenderFormat : std::uint8_t {
    Svg,
    Png,
    Bmp,
    Plain
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
    DefaultProcessRunner() = default;
    explicit DefaultProcessRunner(std::chrono::milliseconds timeout,
                                  std::stop_token stop_token = {}) noexcept
        : timeout_(timeout), stop_token_(std::move(stop_token)) {}

    [[nodiscard]] GraphRenderResult run(std::string_view executable,
                                        std::span<const std::string> arguments) const override;

private:
    std::chrono::milliseconds timeout_{15000};
    std::stop_token stop_token_{};
};

using GraphByteReader = std::function<std::vector<std::uint8_t>(std::uint64_t offset, std::size_t size)>;

[[nodiscard]] std::string to_dot(const CallGraph& graph);
[[nodiscard]] CallGraph build_entry_call_graph(const peelf::IBinaryImage& image);
[[nodiscard]] CallGraph build_entry_call_graph(const peelf::IBinaryImage& image, const SymbolIndex& symbol_index);
[[nodiscard]] CallGraph build_symbol_fanout_call_graph(const peelf::IBinaryImage& image,
                                                       std::span<const std::uint8_t> image_bytes,
                                                       const SymbolIndex& symbol_index,
                                                       const SymbolRecord& root);
[[nodiscard]] CallGraph build_symbol_fanout_call_graph(const peelf::IBinaryImage& image,
                                                       const GraphByteReader& read_bytes,
                                                       const SymbolIndex& symbol_index,
                                                       const SymbolRecord& root);
[[nodiscard]] CallGraph build_function_cfg_call_graph(std::span<const std::uint8_t> function_bytes,
                                                      std::uint64_t virtual_address,
                                                      peelf::Architecture architecture,
                                                      peelf::Endianness endianness,
                                                      std::optional<std::uint64_t> file_offset = std::nullopt,
                                                      std::string label = "function",
                                                      bool thumb_mode = false,
                                                      bool reachable_only = false,
                                                      const GraphByteReader& read_virtual_bytes = {});
[[nodiscard]] std::string_view graphviz_format_name(GraphRenderFormat format) noexcept;
[[nodiscard]] std::optional<GraphLayout> parse_graphviz_plain_layout(std::string_view plain);
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
