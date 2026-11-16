#include "graph/call_graph.hpp"
#include "graph/call_graph_internal.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace viewer {
namespace {
using detail::format_hex;

[[nodiscard]] std::string dot_executable_from_build() {
#if defined(PEELF_GRAPHVIZ_DOT_AVAILABLE) && PEELF_GRAPHVIZ_DOT_AVAILABLE
    return PEELF_GRAPHVIZ_DOT_EXECUTABLE;
#else
    return "dot";
#endif
}

[[nodiscard]] std::string dot_escape(std::string_view text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char ch : text) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                break;
            default:
                escaped.push_back(ch);
                break;
        }
    }
    return escaped;
}

[[nodiscard]] std::string node_shape(CallGraphNodeKind kind) {
    switch (kind) {
        case CallGraphNodeKind::Function:
            return "box";
        case CallGraphNodeKind::BasicBlock:
            return "record";
        case CallGraphNodeKind::Instruction:
            return "plain";
        case CallGraphNodeKind::Import:
            return "component";
        case CallGraphNodeKind::External:
            return "oval";
        case CallGraphNodeKind::Unknown:
            return "box";
    }
    return "box";
}

[[nodiscard]] std::string edge_style(CallGraphEdgeKind kind) {
    switch (kind) {
        case CallGraphEdgeKind::Call:
            return "color=\"#1f77b4\"";
        case CallGraphEdgeKind::ConditionalBranch:
            return "color=\"#ff7f0e\",style=\"dashed\"";
        case CallGraphEdgeKind::UnconditionalBranch:
            return "color=\"#d62728\"";
        case CallGraphEdgeKind::Fallthrough:
            return "color=\"#2ca02c\"";
        case CallGraphEdgeKind::Return:
            return "color=\"#9467bd\"";
        case CallGraphEdgeKind::DataReference:
            return "color=\"#8c564b\",style=\"dotted\"";
        case CallGraphEdgeKind::Unknown:
            return "color=\"#7f7f7f\"";
    }
    return "color=\"#7f7f7f\"";
}

[[nodiscard]] std::optional<double> parse_double_token(std::string_view token) {
    std::string copy(token);
    char* end = nullptr;
    const double value = std::strtod(copy.c_str(), &end);
    if (end == copy.c_str() || *end != '\0') {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::string parse_plain_node_id(std::string_view token) {
    if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
        token.remove_prefix(1);
        token.remove_suffix(1);
    }
    return std::string(token);
}

[[nodiscard]] std::string node_label(const CallGraphNode& node) {
    const std::string base_label = node.label.empty() ? node.id : node.label;
    std::string label = base_label;
    if (!node.instructions.empty()) {
        for (const auto& instruction : node.instructions)
            label += "\n" + format_hex(instruction.address) + "  " + instruction.mnemonic + " " + instruction.operands;
        return label;
    }
    if (node.bytes.start.virtual_address) {
        label += "\nVA " + format_hex(*node.bytes.start.virtual_address);
    }
    if (node.bytes.start.file_offset) {
        label += "\nfile " + format_hex(*node.bytes.start.file_offset);
    }
    if (node.symbol && !node.symbol->name.empty() && node.symbol->name != base_label) {
        label += "\n" + node.symbol->name;
    }
    return label;
}

#ifdef _WIN32
[[nodiscard]] std::wstring widen(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int required = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), required);
    return out;
}

[[nodiscard]] std::wstring quote_windows_arg(std::wstring_view arg) {
    std::wstring quoted = L"\"";
    for (const wchar_t ch : arg) {
        if (ch == L'\\' || ch == L'"') {
            quoted.push_back(L'\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back(L'"');
    return quoted;
}
#else
[[nodiscard]] std::string quote_shell_arg(std::string_view arg) {
    std::string quoted = "'";
    for (const char ch : arg) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(ch);
        }
    }
    quoted.push_back('\'');
    return quoted;
}
#endif

} // namespace

std::string to_dot(const CallGraph& graph) {
    std::ostringstream out;
    out << "digraph \"" << dot_escape(graph.id.empty() ? "call_graph" : graph.id) << "\" {\n";
    out << "  graph [rankdir=\"" << (graph.id == "function_cfg" ? "TB" : "LR")
        << "\", labelloc=\"t\", label=\"" << dot_escape(graph.label) << "\"];\n";
    out << "  node [fontname=\"Consolas\", fontsize=\"10\"];\n";
    out << "  edge [fontname=\"Consolas\", fontsize=\"9\"];\n";

    for (const CallGraphNode& node : graph.nodes) {
        out << "  \"" << dot_escape(node.id) << "\" [shape=\"" << node_shape(node.kind) << "\", label=\""
            << dot_escape(node_label(node)) << "\"];\n";
    }

    for (const CallGraphEdge& edge : graph.edges) {
        out << "  \"" << dot_escape(edge.from_node_id) << "\" -> \"" << dot_escape(edge.to_node_id) << "\" ["
            << edge_style(edge.kind);
        if (!edge.label.empty()) {
            out << ", label=\"" << dot_escape(edge.label) << "\"";
        }
        out << "];\n";
    }

    out << "}\n";
    return out.str();
}

std::optional<GraphLayout> parse_graphviz_plain_layout(std::string_view plain) {
    std::istringstream input{std::string(plain)};
    GraphLayout layout;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream row(line);
        std::string kind;
        row >> kind;
        if (kind == "graph") {
            std::string scale;
            std::string width;
            std::string height;
            row >> scale >> width >> height;
            const std::optional<double> w = parse_double_token(width);
            const std::optional<double> h = parse_double_token(height);
            if (w && h) {
                layout.width = *w;
                layout.height = *h;
            }
        } else if (kind == "node") {
            std::string id;
            std::string x;
            std::string y;
            std::string width;
            std::string height;
            row >> id >> x >> y >> width >> height;
            const std::optional<double> cx = parse_double_token(x);
            const std::optional<double> cy = parse_double_token(y);
            const std::optional<double> w = parse_double_token(width);
            const std::optional<double> h = parse_double_token(height);
            if (cx && cy && w && h) {
                layout.nodes.push_back(GraphLayoutNode{
                    .node_id = parse_plain_node_id(id),
                    .center_x = *cx,
                    .center_y = *cy,
                    .width = *w,
                    .height = *h,
                });
            }
        }
    }
    if (layout.width <= 0.0 || layout.height <= 0.0) {
        return std::nullopt;
    }
    return layout;
}

std::string_view graphviz_format_name(GraphRenderFormat format) noexcept {
    switch (format) {
        case GraphRenderFormat::Svg:
            return "svg";
        case GraphRenderFormat::Png:
            return "png";
        case GraphRenderFormat::Bmp:
            return "bmp";
        case GraphRenderFormat::Plain:
            return "plain";
    }
    return "svg";
}

GraphRenderCommand make_graphviz_render_command(const std::filesystem::path& dot_path,
                                                const std::filesystem::path& output_path,
                                                GraphRenderFormat format,
                                                std::string dot_executable) {
    if (dot_executable.empty()) {
        dot_executable = dot_executable_from_build();
    }
    return GraphRenderCommand{
        .executable = std::move(dot_executable),
        .arguments = {
            "-T" + std::string(graphviz_format_name(format)),
            "-o",
            output_path.string(),
            dot_path.string(),
        },
    };
}

GraphRenderResult render_graph_with_graphviz(const CallGraph& graph,
                                             const std::filesystem::path& output_path,
                                             GraphRenderFormat format,
                                             const IProcessRunner& runner) {
    const std::filesystem::path dot_path = output_path.string() + ".dot";
    {
        std::ofstream out(dot_path, std::ios::binary);
        if (!out) {
            return GraphRenderResult{.success = false, .exit_code = -1, .diagnostic = "failed to create DOT file"};
        }
        out << to_dot(graph);
    }

    const GraphRenderCommand command = make_graphviz_render_command(dot_path, output_path, format);
    return runner.run(command.executable, command.arguments);
}

GraphRenderResult DefaultProcessRunner::run(std::string_view executable,
                                            std::span<const std::string> arguments) const {
#ifdef _WIN32
    std::wstring command_line = quote_windows_arg(widen(executable));
    for (const std::string& argument : arguments) {
        command_line.push_back(L' ');
        command_line += quote_windows_arg(widen(argument));
    }

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);
    PROCESS_INFORMATION process_info{};
    std::wstring mutable_command_line = command_line;
    const BOOL created = CreateProcessW(nullptr,
                                        mutable_command_line.data(),
                                        nullptr,
                                        nullptr,
                                        FALSE,
                                        CREATE_NO_WINDOW,
                                        nullptr,
                                        nullptr,
                                        &startup_info,
                                        &process_info);
    if (!created) {
        return GraphRenderResult{.success = false,
                                 .exit_code = static_cast<std::int32_t>(GetLastError()),
                                 .diagnostic = "CreateProcessW failed"};
    }

    WaitForSingleObject(process_info.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process_info.hProcess, &exit_code);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    return GraphRenderResult{.success = exit_code == 0,
                             .exit_code = static_cast<std::int32_t>(exit_code),
                             .diagnostic = exit_code == 0 ? std::string{} : "Graphviz dot failed"};
#else
    std::string command = quote_shell_arg(executable);
    for (const std::string& argument : arguments) {
        command.push_back(' ');
        command += quote_shell_arg(argument);
    }
    const int exit_code = std::system(command.c_str());
    return GraphRenderResult{.success = exit_code == 0,
                             .exit_code = exit_code,
                             .diagnostic = exit_code == 0 ? std::string{} : "Graphviz dot failed"};
#endif
}

} // namespace viewer
