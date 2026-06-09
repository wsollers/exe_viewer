#include "graph/call_graph.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace viewer {
namespace {

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

[[nodiscard]] std::string format_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}

[[nodiscard]] bool contains_case_sensitive(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::string image_label(const peelf::IBinaryImage& image) {
    std::ostringstream out;
    out << peelf::to_string(image.format()) << ' ' << peelf::to_string(image.architecture())
        << " entry graph\\nEntry " << format_hex(image.entry_point());
    return out.str();
}

[[nodiscard]] std::optional<std::size_t> find_symbol_index_by_name(const peelf::IBinaryImage& image,
                                                                    std::string_view name) {
    const std::vector<peelf::Symbol>& symbols = image.symbols();
    const auto it = std::ranges::find_if(symbols, [&](const peelf::Symbol& symbol) {
        return symbol.name == name;
    });
    if (it == symbols.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(symbols.begin(), it));
}

[[nodiscard]] std::optional<std::size_t> find_symbol_index_containing(const peelf::IBinaryImage& image,
                                                                      std::string_view name) {
    const std::vector<peelf::Symbol>& symbols = image.symbols();
    const auto it = std::ranges::find_if(symbols, [&](const peelf::Symbol& symbol) {
        return contains_case_sensitive(symbol.name, name);
    });
    if (it == symbols.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(symbols.begin(), it));
}

[[nodiscard]] std::optional<std::size_t> find_import_index_containing(const peelf::IBinaryImage& image,
                                                                      std::string_view name) {
    const std::vector<peelf::ImportEntry>& imports = image.imports();
    const auto it = std::ranges::find_if(imports, [&](const peelf::ImportEntry& entry) {
        return contains_case_sensitive(entry.name, name) || contains_case_sensitive(entry.library, name);
    });
    if (it == imports.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(imports.begin(), it));
}

[[nodiscard]] GraphByteRange symbol_range(const peelf::IBinaryImage& image, const peelf::Symbol& symbol) {
    return GraphByteRange{
        .start = GraphAddress{
            .virtual_address = symbol.virtual_address,
            .file_offset = image.virtual_address_to_file_offset(symbol.virtual_address),
        },
        .size = symbol.size,
    };
}

[[nodiscard]] CallGraphNode symbol_node(const peelf::IBinaryImage& image,
                                        const peelf::Symbol& symbol,
                                        std::size_t index,
                                        std::string id) {
    return CallGraphNode{
        .id = std::move(id),
        .label = symbol.name.empty() ? "<unnamed symbol>" : symbol.name,
        .kind = CallGraphNodeKind::Function,
        .bytes = symbol_range(image, symbol),
        .symbol = GraphSymbolRef{
            .name = symbol.name,
            .symbol_index = static_cast<std::uint64_t>(index),
            .dynamic = symbol.dynamic,
        },
    };
}

[[nodiscard]] std::string import_label(const peelf::ImportEntry& entry) {
    if (entry.library.empty()) {
        return entry.name.empty() ? "<import>" : entry.name;
    }
    if (entry.name.empty()) {
        return entry.library;
    }
    return entry.library + "!" + entry.name;
}

void add_edge_if_missing(CallGraph& graph, CallGraphEdge edge) {
    const auto exists = std::ranges::any_of(graph.edges, [&](const CallGraphEdge& existing) {
        return existing.from_node_id == edge.from_node_id &&
               existing.to_node_id == edge.to_node_id &&
               existing.label == edge.label;
    });
    if (!exists) {
        graph.edges.push_back(std::move(edge));
    }
}

[[nodiscard]] std::string node_label(const CallGraphNode& node) {
    const std::string base_label = node.label.empty() ? node.id : node.label;
    std::string label = base_label;
    if (node.bytes.start.virtual_address) {
        label += "\\nVA " + format_hex(*node.bytes.start.virtual_address);
    }
    if (node.bytes.start.file_offset) {
        label += "\\nfile " + format_hex(*node.bytes.start.file_offset);
    }
    if (node.symbol && !node.symbol->name.empty() && node.symbol->name != base_label) {
        label += "\\n" + node.symbol->name;
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
    out << "  graph [rankdir=\"LR\", labelloc=\"t\", label=\"" << dot_escape(graph.label) << "\"];\n";
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

CallGraph build_entry_call_graph(const peelf::IBinaryImage& image) {
    CallGraph graph{
        .id = "loaded_entry_call_graph",
        .label = image_label(image),
        .architecture = image.architecture(),
        .endianness = image.endianness(),
    };

    const std::uint64_t entry_va = image.entry_point();
    const std::optional<GraphSymbolRef> entry_ref = find_symbol_for_address(image, entry_va);
    std::string entry_id = "entry";
    GraphByteRange entry_range{
        .start = GraphAddress{
            .virtual_address = entry_va,
            .file_offset = image.virtual_address_to_file_offset(entry_va),
        },
        .size = 1,
    };

    if (entry_ref && entry_ref->symbol_index <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        const std::size_t index = static_cast<std::size_t>(entry_ref->symbol_index);
        if (index < image.symbols().size()) {
            entry_range = symbol_range(image, image.symbols()[index]);
            entry_id = "sym_" + std::to_string(index);
        }
    }

    graph.nodes.push_back(CallGraphNode{
        .id = entry_id,
        .label = entry_ref && !entry_ref->name.empty() ? entry_ref->name : "Entry Point",
        .kind = CallGraphNodeKind::Function,
        .bytes = entry_range,
        .symbol = entry_ref,
    });

    for (std::size_t i = 0; i < image.exports().size(); ++i) {
        const peelf::ExportEntry& entry = image.exports()[i];
        if (entry.virtual_address != entry_va) {
            continue;
        }
        const std::string export_id = "export_" + std::to_string(i);
        graph.nodes.push_back(CallGraphNode{
            .id = export_id,
            .label = entry.name.empty() ? "<export>" : entry.name,
            .kind = CallGraphNodeKind::External,
            .bytes = GraphByteRange{
                .start = GraphAddress{
                    .virtual_address = entry.virtual_address,
                    .file_offset = image.virtual_address_to_file_offset(entry.virtual_address),
                },
                .size = 1,
            },
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = export_id,
            .to_node_id = entry_id,
            .kind = CallGraphEdgeKind::DataReference,
            .label = "export target",
        });
    }

    constexpr std::size_t max_import_nodes = 16;
    for (std::size_t i = 0; i < std::min(image.imports().size(), max_import_nodes); ++i) {
        const peelf::ImportEntry& import = image.imports()[i];
        const std::string import_id = "import_" + std::to_string(i);
        graph.nodes.push_back(CallGraphNode{
            .id = import_id,
            .label = import_label(import),
            .kind = CallGraphNodeKind::Import,
            .bytes = GraphByteRange{
                .start = GraphAddress{
                    .virtual_address = import.address == 0 ? std::optional<std::uint64_t>{} : std::optional(import.address),
                    .file_offset = import.address == 0 ? std::optional<std::uint64_t>{}
                                                       : image.virtual_address_to_file_offset(import.address),
                },
                .size = image.is_64bit() ? 8u : 4u,
            },
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = entry_id,
            .to_node_id = import_id,
            .kind = CallGraphEdgeKind::Call,
            .label = "import ref",
        });
    }

    const std::optional<std::size_t> start_symbol = find_symbol_index_by_name(image, "_start");
    const std::optional<std::size_t> main_symbol = find_symbol_index_by_name(image, "main");
    const std::optional<std::size_t> libc_start_import = find_import_index_containing(image, "__libc_start_main");
    const std::optional<std::size_t> libc_start_symbol = find_symbol_index_containing(image, "__libc_start_main");
    if (start_symbol && main_symbol) {
        const std::string start_id = "sym_" + std::to_string(*start_symbol);
        const std::string main_id = "sym_" + std::to_string(*main_symbol);
        if (start_id != entry_id) {
            graph.nodes.push_back(symbol_node(image, image.symbols()[*start_symbol], *start_symbol, start_id));
        }
        graph.nodes.push_back(symbol_node(image, image.symbols()[*main_symbol], *main_symbol, main_id));

        if (libc_start_import) {
            const std::string libc_id = "import_" + std::to_string(*libc_start_import);
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = start_id,
                .to_node_id = libc_id,
                .kind = CallGraphEdgeKind::Call,
                .label = "startup call",
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = libc_id,
                .to_node_id = main_id,
                .kind = CallGraphEdgeKind::Call,
                .label = "main callback",
            });
        } else if (libc_start_symbol) {
            const std::string libc_id = "sym_" + std::to_string(*libc_start_symbol);
            graph.nodes.push_back(CallGraphNode{
                .id = libc_id,
                .label = image.symbols()[*libc_start_symbol].name,
                .kind = CallGraphNodeKind::External,
                .symbol = GraphSymbolRef{
                    .name = image.symbols()[*libc_start_symbol].name,
                    .symbol_index = static_cast<std::uint64_t>(*libc_start_symbol),
                    .dynamic = image.symbols()[*libc_start_symbol].dynamic,
                },
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = start_id,
                .to_node_id = libc_id,
                .kind = CallGraphEdgeKind::Call,
                .label = "startup call",
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = libc_id,
                .to_node_id = main_id,
                .kind = CallGraphEdgeKind::Call,
                .label = "main callback",
            });
        } else {
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = start_id,
                .to_node_id = main_id,
                .kind = CallGraphEdgeKind::Call,
                .label = "startup target",
            });
        }
    }

    if (image.format() == peelf::Format::PE && find_symbol_index_by_name(image, "WinMain") == std::nullopt) {
        graph.nodes.push_back(CallGraphNode{
            .id = "crt_startup_unresolved",
            .label = "CRT startup\\nmainCRTStartup / WinMainCRTStartup\\nunresolved",
            .kind = CallGraphNodeKind::Unknown,
        });
        graph.nodes.push_back(CallGraphNode{
            .id = "winmain_unresolved",
            .label = "WinMain\\nunresolved from current symbols",
            .kind = CallGraphNodeKind::External,
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = entry_id,
            .to_node_id = "crt_startup_unresolved",
            .kind = CallGraphEdgeKind::Unknown,
            .label = "startup recovery pending",
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = "crt_startup_unresolved",
            .to_node_id = "winmain_unresolved",
            .kind = CallGraphEdgeKind::Unknown,
            .label = "symbol lookup pending",
        });
    }

    return graph;
}

std::string_view graphviz_format_name(GraphRenderFormat format) noexcept {
    switch (format) {
        case GraphRenderFormat::Svg:
            return "svg";
        case GraphRenderFormat::Png:
            return "png";
        case GraphRenderFormat::Bmp:
            return "bmp";
    }
    return "svg";
}

std::optional<GraphSymbolRef> find_symbol_for_address(const peelf::IBinaryImage& image,
                                                       std::uint64_t virtual_address) {
    const std::vector<peelf::Symbol>& symbols = image.symbols();
    for (std::uint64_t index = 0; index < symbols.size(); ++index) {
        const peelf::Symbol& symbol = symbols[static_cast<std::size_t>(index)];
        const std::uint64_t symbol_size = std::max<std::uint64_t>(symbol.size, 1);
        if (virtual_address >= symbol.virtual_address && virtual_address < symbol.virtual_address + symbol_size) {
            return GraphSymbolRef{
                .name = symbol.name,
                .symbol_index = index,
                .dynamic = symbol.dynamic,
            };
        }
    }
    return std::nullopt;
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
