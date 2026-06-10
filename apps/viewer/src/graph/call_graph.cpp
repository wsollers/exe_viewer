#include "graph/call_graph.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>

#include "disasm/disassembler.hpp"

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

[[nodiscard]] std::optional<std::uint64_t> parse_hex_u64(std::string_view text) {
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::uint64_t> parse_direct_call_target(std::string_view operands) {
    if (operands.find('[') != std::string_view::npos) {
        return std::nullopt;
    }
    const std::size_t begin = operands.find("0x");
    if (begin == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t end = begin + 2;
    while (end < operands.size() && std::isxdigit(static_cast<unsigned char>(operands[end])) != 0) {
        ++end;
    }
    return parse_hex_u64(operands.substr(begin, end - begin));
}

[[nodiscard]] bool is_call_instruction(const Instruction& instruction) {
    return instruction.mnemonic == "call" ||
           instruction.mnemonic == "bl" ||
           instruction.mnemonic == "blx" ||
           instruction.mnemonic == "jal" ||
           instruction.mnemonic == "jalr";
}

[[nodiscard]] std::optional<Architecture> disassembler_architecture(peelf::Architecture arch) {
    switch (arch) {
        case peelf::Architecture::X86:       return Architecture::X86_32;
        case peelf::Architecture::X86_64:    return Architecture::X86_64;
        case peelf::Architecture::ARM:       return Architecture::ARM32;
        case peelf::Architecture::ARM64:     return Architecture::ARM64;
        case peelf::Architecture::MIPS32:    return Architecture::MIPS32;
        case peelf::Architecture::MIPS64:    return Architecture::MIPS64;
        case peelf::Architecture::PowerPC:   return Architecture::PowerPC32;
        case peelf::Architecture::PowerPC64: return Architecture::PowerPC64;
        case peelf::Architecture::RISCV32:   return Architecture::RISCV32;
        case peelf::Architecture::RISCV64:   return Architecture::RISCV64;
        default:                             return std::nullopt;
    }
}

[[nodiscard]] Endianness disassembler_endianness(peelf::Endianness endianness) {
    return endianness == peelf::Endianness::Big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] bool contains_case_sensitive(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
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

[[nodiscard]] GraphByteRange record_range(const SymbolRecord& record) {
    return GraphByteRange{
        .start = GraphAddress{
            .virtual_address = record.virtual_address,
            .file_offset = record.file_offset,
        },
        .size = record.size,
    };
}

[[nodiscard]] std::string_view msvc_decorated_function_name(std::string_view symbol) {
    if (symbol.starts_with('?')) {
        symbol.remove_prefix(1);
        const std::size_t at = symbol.find('@');
        if (at != std::string_view::npos) {
            return symbol.substr(0, at);
        }
    }
    return symbol;
}

[[nodiscard]] bool is_exact_or_decorated_function_name(std::string_view symbol, std::string_view expected) {
    return symbol == expected || msvc_decorated_function_name(symbol) == expected;
}

[[nodiscard]] std::string image_label(const peelf::IBinaryImage& image) {
    std::ostringstream out;
    out << peelf::to_string(image.format()) << ' ' << peelf::to_string(image.architecture())
        << " entry graph\nEntry " << format_hex(image.entry_point());
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

[[nodiscard]] const SymbolRecord* find_symbol_record_containing_name(const SymbolIndex& index,
                                                                     std::string_view name) {
    const auto records = index.records();
    const auto it = std::ranges::find_if(records, [&](const SymbolRecord& record) {
        return contains_case_sensitive(record.name, name);
    });
    if (it == records.end()) {
        return nullptr;
    }
    return &*it;
}

[[nodiscard]] const SymbolRecord* find_first_symbol_record_containing_name(const SymbolIndex& index,
                                                                           std::span<const std::string_view> names) {
    for (const std::string_view name : names) {
        if (const SymbolRecord* record = find_symbol_record_containing_name(index, name)) {
            return record;
        }
    }
    return nullptr;
}

[[nodiscard]] const SymbolRecord* find_first_symbol_record_exact_function_name(
    const SymbolIndex& index,
    std::span<const std::string_view> names) {
    const auto records = index.records();
    for (const std::string_view name : names) {
        const auto it = std::ranges::find_if(records, [&](const SymbolRecord& record) {
            return is_exact_or_decorated_function_name(record.name, name);
        });
        if (it != records.end()) {
            return &*it;
        }
    }
    return nullptr;
}

[[nodiscard]] std::optional<GraphSymbolRef> graph_ref_from_record(const SymbolRecord* record) {
    if (record == nullptr) {
        return std::nullopt;
    }
    return GraphSymbolRef{
        .name = record->name,
        .symbol_index = record->source_index,
        .dynamic = record->dynamic,
    };
}

[[nodiscard]] CallGraphNode node_from_record(const SymbolRecord& record, std::string id) {
    const bool external = record.external || record.source == SymbolSource::Import;
    return CallGraphNode{
        .id = std::move(id),
        .label = record.name,
        .kind = external ? CallGraphNodeKind::External : CallGraphNodeKind::Function,
        .bytes = record_range(record),
        .symbol = GraphSymbolRef{
            .name = record.name,
            .symbol_index = record.source_index,
            .dynamic = record.dynamic,
        },
    };
}

[[nodiscard]] CallGraphNode node_from_call_target(const peelf::IBinaryImage& image,
                                                  const SymbolRecord& record,
                                                  std::uint64_t target,
                                                  std::string id) {
    const bool external = record.external || record.source == SymbolSource::Import;
    std::string label = record.name;
    if (record.virtual_address && target > *record.virtual_address) {
        label += "+" + format_hex(target - *record.virtual_address);
    }

    return CallGraphNode{
        .id = std::move(id),
        .label = std::move(label),
        .kind = external ? CallGraphNodeKind::External : CallGraphNodeKind::Function,
        .bytes = GraphByteRange{
            .start = GraphAddress{
                .virtual_address = target,
                .file_offset = image.virtual_address_to_file_offset(target),
            },
            .size = record.size == 0 ? 1u : record.size,
        },
        .symbol = GraphSymbolRef{
            .name = record.name,
            .symbol_index = record.source_index,
            .dynamic = record.dynamic,
        },
    };
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
    return import_symbol_name(entry);
}

[[nodiscard]] std::string imports_summary_label(const peelf::IBinaryImage& image) {
    constexpr std::size_t max_names = 8;
    std::ostringstream out;
    out << "Imports\n" << image.imports().size() << " entries";
    for (std::size_t i = 0; i < std::min(image.imports().size(), max_names); ++i) {
        out << '\n' << import_label(image.imports()[i]);
    }
    if (image.imports().size() > max_names) {
        out << "\n...";
    }
    return out.str();
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

CallGraph build_entry_call_graph(const peelf::IBinaryImage& image) {
    const SymbolIndex symbol_index = SymbolIndex::build(image);
    return build_entry_call_graph(image, symbol_index);
}

CallGraph build_entry_call_graph(const peelf::IBinaryImage& image, const SymbolIndex& symbol_index) {
    CallGraph graph{
        .id = "loaded_entry_call_graph",
        .label = image_label(image),
        .architecture = image.architecture(),
        .endianness = image.endianness(),
    };

    const std::uint64_t entry_va = image.entry_point();
    const SymbolRecord* entry_record = symbol_index.find_by_name("Entry Point");
    const std::optional<GraphSymbolRef> entry_ref = entry_record ? graph_ref_from_record(entry_record)
                                                                 : find_symbol_for_address(image, entry_va);
    std::string entry_id = "entry";
    GraphByteRange entry_range{
        .start = GraphAddress{
            .virtual_address = entry_va,
            .file_offset = image.virtual_address_to_file_offset(entry_va),
        },
        .size = 1,
    };

    if (entry_record != nullptr) {
        entry_range = GraphByteRange{
            .start = GraphAddress{
                .virtual_address = entry_record->virtual_address,
                .file_offset = entry_record->file_offset,
            },
            .size = entry_record->size,
        };
        entry_id = "entry_symbol";
    } else if (entry_ref && entry_ref->symbol_index <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
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

    if (!image.imports().empty()) {
        graph.nodes.push_back(CallGraphNode{
            .id = "imports_summary",
            .label = imports_summary_label(image),
            .kind = CallGraphNodeKind::Import,
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = entry_id,
            .to_node_id = "imports_summary",
            .kind = CallGraphEdgeKind::DataReference,
            .label = "import table",
        });
    }

    const std::optional<std::size_t> start_symbol = find_symbol_index_by_name(image, "_start");
    const std::optional<std::size_t> main_symbol = find_symbol_index_by_name(image, "main");
    const SymbolRecord* libc_start_record = find_symbol_record_containing_name(symbol_index, "__libc_start_main");
    if (start_symbol && main_symbol) {
        const std::string start_id = "sym_" + std::to_string(*start_symbol);
        const std::string main_id = "sym_" + std::to_string(*main_symbol);
        if (start_id != entry_id) {
            graph.nodes.push_back(symbol_node(image, image.symbols()[*start_symbol], *start_symbol, start_id));
        }
        graph.nodes.push_back(symbol_node(image, image.symbols()[*main_symbol], *main_symbol, main_id));

        if (libc_start_record) {
            const std::string libc_id = "symbol_record_" + std::to_string(libc_start_record->source_index);
            graph.nodes.push_back(CallGraphNode{
                .id = libc_id,
                .label = libc_start_record->name,
                .kind = libc_start_record->source == SymbolSource::Import ? CallGraphNodeKind::Import
                                                                           : CallGraphNodeKind::External,
                .bytes = GraphByteRange{
                    .start = GraphAddress{
                        .virtual_address = libc_start_record->virtual_address,
                        .file_offset = libc_start_record->file_offset,
                    },
                    .size = libc_start_record->size,
                },
                .symbol = GraphSymbolRef{
                    .name = libc_start_record->name,
                    .symbol_index = libc_start_record->source_index,
                    .dynamic = libc_start_record->dynamic,
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

    if (image.format() == peelf::Format::PE) {
        constexpr std::array<std::string_view, 4> crt_names{
            "WinMainCRTStartup",
            "mainCRTStartup",
            "wWinMainCRTStartup",
            "wmainCRTStartup",
        };
        constexpr std::array<std::string_view, 4> user_entry_names{
            "WinMain",
            "wWinMain",
            "main",
            "wmain",
        };
        const SymbolRecord* crt_record = find_first_symbol_record_containing_name(symbol_index, crt_names);
        const SymbolRecord* user_entry_record =
            find_first_symbol_record_exact_function_name(symbol_index, user_entry_names);

        graph.nodes.push_back(CallGraphNode{
            .id = "crt_startup",
            .label = crt_record != nullptr ? crt_record->name
                                           : "CRT startup\nmainCRTStartup / WinMainCRTStartup\nunresolved",
            .kind = crt_record != nullptr ? CallGraphNodeKind::Function : CallGraphNodeKind::Unknown,
            .bytes = GraphByteRange{
                .start = GraphAddress{
                    .virtual_address = crt_record != nullptr ? crt_record->virtual_address
                                                             : std::optional<std::uint64_t>{},
                    .file_offset = crt_record != nullptr ? crt_record->file_offset
                                                         : std::optional<std::uint64_t>{},
                },
                .size = crt_record != nullptr ? crt_record->size : 0,
            },
            .symbol = graph_ref_from_record(crt_record),
        });
        add_edge_if_missing(graph, CallGraphEdge{
            .from_node_id = entry_id,
            .to_node_id = "crt_startup",
            .kind = CallGraphEdgeKind::Unknown,
            .label = crt_record != nullptr ? "startup symbol" : "startup recovery pending",
        });

        if (user_entry_record != nullptr) {
            graph.nodes.push_back(node_from_record(*user_entry_record, "user_entry"));
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = "crt_startup",
                .to_node_id = "user_entry",
                .kind = CallGraphEdgeKind::Call,
                .label = "user entry symbol",
            });
        } else {
            graph.nodes.push_back(CallGraphNode{
                .id = "winmain_unresolved",
                .label = "WinMain\nunresolved from current symbols",
                .kind = CallGraphNodeKind::External,
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = "crt_startup",
                .to_node_id = "winmain_unresolved",
                .kind = CallGraphEdgeKind::Unknown,
                .label = "symbol lookup pending",
            });
        }
    }

    return graph;
}

CallGraph build_symbol_fanout_call_graph(const peelf::IBinaryImage& image,
                                         std::span<const std::uint8_t> image_bytes,
                                         const SymbolIndex& symbol_index,
                                         const SymbolRecord& root) {
    CallGraph graph{
        .id = "symbol_fanout_call_graph",
        .label = root.name + " fan-out",
        .architecture = image.architecture(),
        .endianness = image.endianness(),
    };

    graph.nodes.push_back(node_from_record(root, "root"));

    constexpr std::size_t max_function_scan = 4096;
    bool resolved_any_call = false;

    if (root.file_offset && root.virtual_address) {
        const std::optional<Architecture> arch = disassembler_architecture(image.architecture());
        if (arch) {
            Disassembler disassembler;
            if (disassembler.init(*arch, disassembler_endianness(image.endianness()))) {
                const std::uint64_t requested_size = root.size != 0 ? root.size : max_function_scan;
                const std::size_t start = static_cast<std::size_t>(*root.file_offset);
                const std::size_t bytes_to_read = static_cast<std::size_t>(
                    std::min<std::uint64_t>(requested_size, max_function_scan));

                if (start <= image_bytes.size() && bytes_to_read <= image_bytes.size() - start) {
                    const auto instructions = disassembler.disassemble(image_bytes.data() + start,
                                                                        bytes_to_read,
                                                                        *root.virtual_address);
                    std::uint64_t call_index = 0;
                    for (const Instruction& instruction : instructions) {
                        if (!is_call_instruction(instruction)) {
                            continue;
                        }
                        const std::optional<std::uint64_t> target = parse_direct_call_target(instruction.operands);
                        if (!target) {
                            continue;
                        }

                        const SymbolRecord* callee = symbol_index.find_containing_address(*target);
                        if (callee == nullptr) {
                            constexpr std::uint64_t max_symbol_offset = 4096;
                            callee = symbol_index.find_nearest_preceding_address(*target, max_symbol_offset);
                        }
                        const std::string callee_id = "callee_" + std::to_string(call_index++);
                        if (callee != nullptr && callee->name != root.name) {
                            graph.nodes.push_back(node_from_call_target(image, *callee, *target, callee_id));
                            graph.edges.push_back(CallGraphEdge{
                                .from_node_id = "root",
                                .to_node_id = callee_id,
                                .kind = CallGraphEdgeKind::Call,
                                .label = "call",
                            });
                            resolved_any_call = true;
                        } else {
                            graph.nodes.push_back(CallGraphNode{
                                .id = callee_id,
                                .label = "call target\n" + format_hex(*target),
                                .kind = CallGraphNodeKind::Unknown,
                                .bytes = GraphByteRange{
                                    .start = GraphAddress{.virtual_address = *target},
                                    .size = 1,
                                },
                            });
                            graph.edges.push_back(CallGraphEdge{
                                .from_node_id = "root",
                                .to_node_id = callee_id,
                                .kind = CallGraphEdgeKind::Call,
                                .label = "unresolved call",
                            });
                            resolved_any_call = true;
                        }
                    }
                }
            }
        }
    }

    if (!resolved_any_call) {
        graph.nodes.push_back(CallGraphNode{
            .id = "no_calls",
            .label = "No direct call targets resolved\nsymbols/disassembly may be missing",
            .kind = CallGraphNodeKind::Unknown,
        });
        graph.edges.push_back(CallGraphEdge{
            .from_node_id = "root",
            .to_node_id = "no_calls",
            .kind = CallGraphEdgeKind::Unknown,
            .label = "fan-out unavailable",
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
        case GraphRenderFormat::Plain:
            return "plain";
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
