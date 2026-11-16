#include "graph/call_graph.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

#include <peelf/demangle.hpp>

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

[[nodiscard]] std::optional<std::int64_t> parse_last_decimal_token(std::string_view operands) {
    std::size_t end = operands.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(operands[end - 1])) != 0) {
        --end;
    }
    std::size_t begin = end;
    while (begin > 0 && std::isdigit(static_cast<unsigned char>(operands[begin - 1])) != 0) {
        --begin;
    }
    if (begin > 0 && operands[begin - 1] == '-') {
        --begin;
    }
    if (begin == end) {
        return std::nullopt;
    }

    std::int64_t value = 0;
    const auto [ptr, ec] = std::from_chars(operands.data() + begin, operands.data() + end, value, 10);
    if (ec != std::errc{} || ptr != operands.data() + end) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::int64_t> parse_last_integer_token(std::string_view operands) {
    std::optional<std::int64_t> result;
    for (std::size_t i = 0; i < operands.size();) {
        const bool negative = operands[i] == '-';
        if (negative) {
            ++i;
        }
        if (i >= operands.size() || !std::isdigit(static_cast<unsigned char>(operands[i]))) {
            ++i;
            continue;
        }

        const std::size_t begin = negative ? i - 1u : i;
        int base = 10;
        if (i + 1u < operands.size() && operands[i] == '0' && (operands[i + 1u] == 'x' || operands[i + 1u] == 'X')) {
            base = 16;
            i += 2u;
        }
        while (i < operands.size() && (base == 16 ? std::isxdigit(static_cast<unsigned char>(operands[i])) != 0
                                                  : std::isdigit(static_cast<unsigned char>(operands[i])) != 0)) {
            ++i;
        }

        std::int64_t value = 0;
        std::string_view token = operands.substr(begin, i - begin);
        if (base == 16 && negative) {
            token.remove_prefix(3);
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
            if (ec == std::errc{} && ptr == token.data() + token.size()) {
                result = -value;
            }
        } else if (base == 16) {
            token.remove_prefix(2);
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
            if (ec == std::errc{} && ptr == token.data() + token.size()) {
                result = value;
            }
        } else {
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 10);
            if (ec == std::errc{} && ptr == token.data() + token.size()) {
                result = value;
            }
        }
    }
    return result;
}

[[nodiscard]] std::optional<std::uint64_t> resolve_riscv_auipc_jalr_target(const Instruction& previous,
                                                                           const Instruction& instruction) {
    if (previous.mnemonic != "auipc" || instruction.mnemonic != "jalr") {
        return std::nullopt;
    }
    const std::optional<std::int64_t> high = parse_last_integer_token(previous.operands);
    const std::optional<std::int64_t> low = parse_last_integer_token(instruction.operands);
    if (!high || !low) {
        return std::nullopt;
    }
    const std::int64_t target =
        static_cast<std::int64_t>(previous.address) + (*high << 12) + *low;
    if (target < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(target);
}

[[nodiscard]] std::optional<std::uint64_t> parse_direct_call_target(const Instruction& instruction) {
    if (const std::optional<std::uint64_t> hex_target = parse_direct_call_target(instruction.operands)) {
        return hex_target;
    }
    const std::optional<std::int64_t> decimal_target = parse_last_decimal_token(instruction.operands);
    if (!decimal_target) {
        return std::nullopt;
    }

    constexpr std::int64_t relative_immediate_limit = 0x100000;
    if ((instruction.mnemonic == "bal" || instruction.mnemonic == "jal" || instruction.mnemonic == "j") &&
        *decimal_target > -relative_immediate_limit && *decimal_target < relative_immediate_limit) {
        const std::int64_t absolute =
            static_cast<std::int64_t>(instruction.address) + *decimal_target;
        if (absolute < 0) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(absolute);
    }
    if (*decimal_target < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(*decimal_target);
}

[[nodiscard]] std::optional<std::uint64_t> parse_x86_rip_relative_memory_target(const Instruction& instruction) {
    const std::string_view operands = instruction.operands;
    const std::size_t rip = operands.find("rip");
    if (rip == std::string_view::npos || instruction.bytes.empty()) {
        return std::nullopt;
    }

    const std::size_t plus = operands.find('+', rip);
    const std::size_t minus = operands.find('-', rip);
    const bool negative = minus != std::string_view::npos && (plus == std::string_view::npos || minus < plus);
    const std::size_t sign = negative ? minus : plus;
    if (sign == std::string_view::npos) {
        return std::nullopt;
    }

    const std::size_t begin = operands.find("0x", sign);
    if (begin == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t end = begin + 2;
    while (end < operands.size() && std::isxdigit(static_cast<unsigned char>(operands[end])) != 0) {
        ++end;
    }

    const std::optional<std::uint64_t> displacement = parse_hex_u64(operands.substr(begin, end - begin));
    if (!displacement) {
        return std::nullopt;
    }

    const std::uint64_t next_instruction =
        instruction.address + static_cast<std::uint64_t>(instruction.bytes.size());
    if (negative && *displacement > next_instruction) {
        return std::nullopt;
    }
    if (!negative && next_instruction > std::numeric_limits<std::uint64_t>::max() - *displacement) {
        return std::nullopt;
    }
    return negative ? next_instruction - *displacement : next_instruction + *displacement;
}

[[nodiscard]] bool is_call_instruction(const Instruction& instruction) {
    return instruction.mnemonic == "call" ||
           instruction.mnemonic == "bl" ||
           instruction.mnemonic == "blx" ||
           instruction.mnemonic == "bal" ||
           instruction.mnemonic == "jal" ||
           instruction.mnemonic == "jalr";
}

[[nodiscard]] bool is_indirect_branch_instruction(const Instruction& instruction) {
    return instruction.mnemonic == "jmp" || instruction.mnemonic == "call";
}

[[nodiscard]] bool is_return_instruction(const Instruction& instruction) {
    return instruction.mnemonic == "ret" ||
           instruction.mnemonic == "retn" ||
           instruction.mnemonic == "retq" ||
           instruction.mnemonic == "jr" ||
           instruction.mnemonic == "blr" ||
           (instruction.mnemonic == "bx" && instruction.operands == "lr") ||
           ((instruction.mnemonic == "pop" || instruction.mnemonic == "ldm" || instruction.mnemonic == "ldmia") &&
            instruction.operands.find("pc") != std::string::npos);
}

[[nodiscard]] bool is_unconditional_branch_instruction(const Instruction& instruction) {
    return instruction.mnemonic == "jmp" ||
           instruction.mnemonic == "j" ||
           instruction.mnemonic == "b" ||
           instruction.mnemonic == "br";
}

[[maybe_unused]] [[nodiscard]] bool is_conditional_branch_instruction(const Instruction& instruction) {
    const std::string& mnemonic = instruction.mnemonic;
    if (mnemonic.empty() || is_unconditional_branch_instruction(instruction) || is_call_instruction(instruction) ||
        is_return_instruction(instruction)) {
        return false;
    }
    if (mnemonic[0] == 'j') {
        return true;
    }
    return mnemonic == "cbz" ||
           mnemonic == "cbnz" ||
           mnemonic == "tbz" ||
           mnemonic == "tbnz" ||
           mnemonic == "beq" ||
           mnemonic == "bne" ||
           mnemonic == "blt" ||
           mnemonic == "bge" ||
           mnemonic == "bltu" ||
           mnemonic == "bgeu" ||
           mnemonic == "bc";
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
        .demangled_name = record->demangled_name,
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
            .demangled_name = record.demangled_name,
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
            .demangled_name = record.demangled_name,
            .symbol_index = record.source_index,
            .dynamic = record.dynamic,
        },
    };
}

[[nodiscard]] const SymbolRecord* resolve_call_target_symbol(const peelf::IBinaryImage& image,
                                                             const GraphByteReader& read_bytes,
                                                             Disassembler& disassembler,
                                                             const SymbolIndex& symbol_index,
                                                             std::uint64_t target,
                                                             std::uint8_t depth = 0) {
    if (depth > 3) {
        return nullptr;
    }

    if (const SymbolRecord* exact_or_containing = symbol_index.find_containing_address(target)) {
        return exact_or_containing;
    }

    if (const std::optional<std::uint64_t> target_file_offset = image.virtual_address_to_file_offset(target)) {
        constexpr std::size_t max_thunk_bytes = 16;
        const std::vector<std::uint8_t> thunk_bytes =
            read_bytes ? read_bytes(*target_file_offset, max_thunk_bytes) : std::vector<std::uint8_t>{};
        if (!thunk_bytes.empty()) {
            const std::vector<Instruction> thunk =
                disassembler.disassemble_count(thunk_bytes.data(), thunk_bytes.size(), target, 2);
            if (!thunk.empty() && is_indirect_branch_instruction(thunk.front())) {
                if (const std::optional<std::uint64_t> indirect_address =
                        parse_x86_rip_relative_memory_target(thunk.front())) {
                    if (const SymbolRecord* import_or_symbol =
                            symbol_index.find_containing_address(*indirect_address)) {
                        return import_or_symbol;
                    }
                }
                if (const std::optional<std::uint64_t> branch_target =
                        parse_direct_call_target(thunk.front())) {
                    if (*branch_target != target) {
                        if (const SymbolRecord* chained =
                                resolve_call_target_symbol(image,
                                                           read_bytes,
                                                           disassembler,
                                                           symbol_index,
                                                           *branch_target,
                                                           static_cast<std::uint8_t>(depth + 1u))) {
                            return chained;
                        }
                    }
                }
            }
        }
    }

    constexpr std::uint64_t max_symbol_offset = 4096;
    return symbol_index.find_nearest_preceding_address(target, max_symbol_offset);
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
            .demangled_name = peelf::demangle_symbol(symbol.name).demangled,
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
        .nodes = {},
        .edges = {},
        .indirect_recoveries = {},
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
                    .demangled_name = libc_start_record->demangled_name,
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
    const GraphByteReader reader = [image_bytes](std::uint64_t offset,
                                                 std::size_t size) -> std::vector<std::uint8_t> {
        if (offset >= static_cast<std::uint64_t>(image_bytes.size()) || size == 0) {
            return {};
        }
        const auto start = static_cast<std::size_t>(offset);
        const std::size_t avail = std::min(size, image_bytes.size() - start);
        return std::vector<std::uint8_t>(image_bytes.begin() + static_cast<std::ptrdiff_t>(start),
                                         image_bytes.begin() + static_cast<std::ptrdiff_t>(start + avail));
    };
    return build_symbol_fanout_call_graph(image, reader, symbol_index, root);
}

CallGraph build_symbol_fanout_call_graph(const peelf::IBinaryImage& image,
                                         const GraphByteReader& read_bytes,
                                         const SymbolIndex& symbol_index,
                                         const SymbolRecord& root) {
    CallGraph graph{
        .id = "symbol_fanout_call_graph",
        .label = root.name + " fan-out",
        .architecture = image.architecture(),
        .endianness = image.endianness(),
        .nodes = {},
        .edges = {},
        .indirect_recoveries = {},
    };

    graph.nodes.push_back(node_from_record(root, "root"));

    constexpr std::size_t max_function_scan = 4096;
    bool resolved_any_call = false;

    std::vector<const peelf::ElfSymbol*> dynsyms;
    for (const auto& es : image.elf_symbols()) {
        if (es.dynamic) dynsyms.push_back(&es);
    }

    const auto lookup_pointer_slot_callee = [&](std::uint64_t slot_va) -> std::optional<SymbolRecord> {
        if (const SymbolRecord* rec = symbol_index.find_containing_address(slot_va)) {
            if (rec->virtual_address == slot_va) {
                return *rec;
            }
        }
        for (const auto& imp : image.imports()) {
            if (imp.address == slot_va && (!imp.name.empty() || !imp.library.empty())) {
                SymbolRecord synth{};
                synth.name = imp.library.empty() ? imp.name
                    : (imp.name.empty() ? imp.library : (imp.library + "!" + imp.name));
                synth.virtual_address = slot_va;
                synth.file_offset = image.virtual_address_to_file_offset(slot_va);
                synth.size = image.is_64bit() ? 8u : 4u;
                synth.source = SymbolSource::Import;
                synth.external = true;
                synth.dynamic = true;
                return synth;
            }
        }
        for (const auto& rel : image.elf_relocations()) {
            if (rel.offset == slot_va && rel.symbol_index < dynsyms.size() &&
                !dynsyms[rel.symbol_index]->name.empty()) {
                SymbolRecord synth{};
                synth.name = dynsyms[rel.symbol_index]->name;
                synth.virtual_address = slot_va;
                synth.file_offset = image.virtual_address_to_file_offset(slot_va);
                synth.size = image.is_64bit() ? 8u : 4u;
                synth.source = SymbolSource::Import;
                synth.external = true;
                synth.dynamic = true;
                return synth;
            }
        }
        return std::nullopt;
    };

    if (root.file_offset && root.virtual_address && read_bytes) {
        const std::optional<Architecture> arch = to_disassembler_architecture(image.architecture());
        if (arch) {
            Disassembler disassembler;
            if (disassembler.init(*arch, to_disassembler_endianness(image.endianness()))) {
                const std::uint64_t requested_size = root.size != 0 ? root.size : max_function_scan;
                const std::size_t bytes_to_read = static_cast<std::size_t>(
                    std::min<std::uint64_t>(requested_size, max_function_scan));
                const std::vector<std::uint8_t> fn_bytes = read_bytes(*root.file_offset, bytes_to_read);

                if (!fn_bytes.empty()) {
                    const auto instructions = disassembler.disassemble(fn_bytes.data(),
                                                                        fn_bytes.size(),
                                                                        *root.virtual_address);

                    // Track ARM64 ADRP + LDR pointer-slot pairs for indirect BLR calls
                    std::map<std::string, std::uint64_t> arm64_page_by_reg;
                    std::map<std::string, std::uint64_t> arm64_slot_by_reg;

                    std::uint64_t call_index = 0;
                    const Instruction* previous_instruction = nullptr;
                    for (const Instruction& instruction : instructions) {
                        if (image.architecture() == peelf::Architecture::ARM64) {
                            if (instruction.mnemonic == "adrp") {
                                const auto comma = instruction.operands.find(',');
                                if (comma != std::string::npos) {
                                    const std::string reg = instruction.operands.substr(0, comma);
                                    const auto hex_pos = instruction.operands.find("0x", comma);
                                    if (hex_pos != std::string::npos) {
                                        std::size_t end = hex_pos + 2;
                                        while (end < instruction.operands.size() &&
                                               std::isxdigit(static_cast<unsigned char>(instruction.operands[end])) != 0) {
                                            ++end;
                                        }
                                        if (const auto page = parse_hex_u64(
                                                std::string_view(instruction.operands).substr(hex_pos, end - hex_pos))) {
                                            arm64_page_by_reg[reg] = *page;
                                            arm64_slot_by_reg.erase(reg);
                                        }
                                    }
                                }
                            } else if (instruction.mnemonic == "ldr") {
                                const auto comma = instruction.operands.find(',');
                                const auto lbr = instruction.operands.find('[', comma == std::string::npos ? 0 : comma);
                                const auto rbr = instruction.operands.find(']', lbr == std::string::npos ? 0 : lbr);
                                if (comma != std::string::npos && lbr != std::string::npos && rbr != std::string::npos) {
                                    const std::string dst = instruction.operands.substr(0, comma);
                                    const std::string mem_expr = instruction.operands.substr(lbr + 1, rbr - lbr - 1);
                                    const auto inner_comma = mem_expr.find(',');
                                    const std::string base = inner_comma == std::string::npos
                                        ? mem_expr : mem_expr.substr(0, inner_comma);
                                    if (const auto page_it = arm64_page_by_reg.find(base); page_it != arm64_page_by_reg.end()) {
                                        std::uint64_t disp = 0;
                                        if (inner_comma != std::string::npos) {
                                            const auto hex_pos = mem_expr.find("0x", inner_comma);
                                            if (hex_pos != std::string::npos) {
                                                std::size_t end = hex_pos + 2;
                                                while (end < mem_expr.size() &&
                                                       std::isxdigit(static_cast<unsigned char>(mem_expr[end])) != 0) {
                                                    ++end;
                                                }
                                                disp = parse_hex_u64(std::string_view(mem_expr).substr(hex_pos, end - hex_pos))
                                                           .value_or(0u);
                                            }
                                        }
                                        arm64_slot_by_reg[dst] = page_it->second + disp;
                                    } else {
                                        arm64_slot_by_reg.erase(dst);
                                    }
                                    arm64_page_by_reg.erase(dst);
                                }
                            }
                        }

                        const bool is_call = is_call_instruction(instruction) || instruction.flow == InstructionFlow::Call;
                        if (!is_call) {
                            previous_instruction = &instruction;
                            continue;
                        }
                        std::optional<std::uint64_t> target;
                        if (previous_instruction != nullptr) {
                            target = resolve_riscv_auipc_jalr_target(*previous_instruction, instruction);
                        }
                        if (!target) {
                            target = parse_direct_call_target(instruction);
                        }

                        if (!target) {
                            // Check IAT / GOT / PLT pointer-slot indirect calls:
                            // x86-64 call [rip + disp], x86-32 call dword ptr [0x...], ARM64 adrp+ldr+bl
                            std::optional<std::uint64_t> slot_va = parse_x86_rip_relative_memory_target(instruction);
                            if (!slot_va && image.architecture() == peelf::Architecture::X86 &&
                                instruction.operands.find("ptr [0x") != std::string::npos &&
                                instruction.operands.find('+') == std::string::npos &&
                                instruction.operands.find('*') == std::string::npos) {
                                const auto hex_pos = instruction.operands.find("0x");
                                std::size_t end = hex_pos + 2;
                                while (end < instruction.operands.size() &&
                                       std::isxdigit(static_cast<unsigned char>(instruction.operands[end])) != 0) {
                                    ++end;
                                }
                                slot_va = parse_hex_u64(std::string_view(instruction.operands).substr(hex_pos, end - hex_pos));
                            }
                            if (!slot_va && image.architecture() == peelf::Architecture::ARM64 &&
                                instruction.mnemonic == "blr") {
                                if (const auto it = arm64_slot_by_reg.find(instruction.operands); it != arm64_slot_by_reg.end()) {
                                    slot_va = it->second;
                                }
                            }

                            if (slot_va) {
                                if (const auto slot_callee = lookup_pointer_slot_callee(*slot_va)) {
                                    if (slot_callee->name != root.name) {
                                        const std::string callee_id = "callee_" + std::to_string(call_index++);
                                        graph.nodes.push_back(node_from_call_target(image, *slot_callee, *slot_va, callee_id));
                                        graph.edges.push_back(CallGraphEdge{
                                            .from_node_id = "root",
                                            .to_node_id = callee_id,
                                            .kind = CallGraphEdgeKind::Call,
                                            .label = "indirect call",
                                        });
                                        graph.indirect_recoveries.push_back(IndirectRecoveryNote{
                                            .source_address = instruction.address,
                                            .table_or_slot_address = *slot_va,
                                            .target_count = 1,
                                            .confidence = "IndirectPointerSlot",
                                            .evidence = std::format("Indirect pointer slot [0x{:X}] -> {}",
                                                                    *slot_va, slot_callee->name),
                                        });
                                        resolved_any_call = true;
                                    }
                                }
                            }
                            previous_instruction = &instruction;
                            continue;
                        }

                        const SymbolRecord* callee =
                            resolve_call_target_symbol(image, read_bytes, disassembler, symbol_index, *target);
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
                                    .start = GraphAddress{
                                        .virtual_address = *target,
                                        .relative_virtual_address = std::nullopt,
                                        .file_offset = std::nullopt,
                                    },
                                    .size = 1,
                                },
                                .symbol = std::nullopt,
                            });
                            graph.edges.push_back(CallGraphEdge{
                                .from_node_id = "root",
                                .to_node_id = callee_id,
                                .kind = CallGraphEdgeKind::Call,
                                .label = "unresolved call",
                            });
                            resolved_any_call = true;
                        }
                        previous_instruction = &instruction;
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
            .bytes = {},
            .symbol = std::nullopt,
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

std::string_view function_extent_source_name(FunctionExtentSource source) noexcept {
    switch (source) {
        case FunctionExtentSource::Symbol: return "Symbol extent";
        case FunctionExtentSource::RuntimeMetadata: return "Runtime function extent";
        case FunctionExtentSource::NextSymbol: return "Bounded by next function";
        case FunctionExtentSource::ExecutableRegion: return "Executable region preview";
    }
    return "Unknown extent";
}

std::optional<FunctionExtent> discover_function_extent(const peelf::IBinaryImage& image,
    const SymbolIndex& symbols, const SymbolRecord& root, std::uint64_t image_size, std::uint64_t max_bytes) {
    if (!root.virtual_address || max_bytes == 0) return std::nullopt;
    const auto mapped = image.virtual_address_to_file_offset(*root.virtual_address);
    if (!mapped || *mapped >= image_size || (root.file_offset && *root.file_offset != *mapped)) return std::nullopt;
    const auto address = *root.virtual_address;
    std::uint64_t region_size = 0;
    const auto consider_region = [&](const auto& region) {
        if (!region.executable || *mapped < region.file_offset) return;
        const auto delta = *mapped - region.file_offset;
        if (delta >= region.file_size) return;
        const auto size = std::min(region.file_size - delta, image_size - *mapped);
        if (region_size == 0 || size < region_size) region_size = size;
    };
    for (const auto& section : image.sections()) consider_region(section);
    if (region_size == 0) for (const auto& segment : image.segments()) consider_region(segment);
    if (region_size == 0) return std::nullopt;
    FunctionExtent result{*mapped, address, region_size, FunctionExtentSource::ExecutableRegion, false};
    if (root.size != 0 && root.source != SymbolSource::EntryPoint) {
        result.size = root.size;
        result.source = FunctionExtentSource::Symbol;
    } else if (image.format() == peelf::Format::PE && image.architecture() == peelf::Architecture::X86_64 &&
               address >= image.image_base()) {
        const auto rva = address - image.image_base();
        for (const auto& runtime : image.pe_runtime_functions()) {
            if (runtime.begin_address_rva <= rva && runtime.end_address_rva > rva) {
                result.size = runtime.end_address_rva - rva;
                result.source = FunctionExtentSource::RuntimeMetadata;
                break;
            }
        }
    }
    if (result.source == FunctionExtentSource::ExecutableRegion) {
        for (const auto& symbol : symbols.records()) {
            if (!symbol.virtual_address || *symbol.virtual_address <= address || !symbol_has_code(image, symbol)) continue;
            const auto distance = *symbol.virtual_address - address;
            if (distance < result.size) {
                result.size = distance;
                result.source = FunctionExtentSource::NextSymbol;
            }
        }
    }
    const auto bounded = std::min({result.size, region_size, max_bytes});
    result.truncated = bounded < result.size;
    result.size = bounded;
    return result;
}

namespace {

[[nodiscard]] int cfg_norm_x86_gpr(unsigned reg) noexcept {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: return 0;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: return 1;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: return 2;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: return 3;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 4;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 5;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 6;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 7;
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return 8;
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return 9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
    default: return -1;
    }
}

[[nodiscard]] int cfg_norm_arm_gpr(int reg) noexcept {
    switch (reg) {
    case ARM_REG_R0: return 0; case ARM_REG_R1: return 1; case ARM_REG_R2: return 2; case ARM_REG_R3: return 3;
    case ARM_REG_R4: return 4; case ARM_REG_R5: return 5; case ARM_REG_R6: return 6; case ARM_REG_R7: return 7;
    case ARM_REG_R8: return 8; case ARM_REG_R9: return 9; case ARM_REG_R10: return 10; case ARM_REG_R11: return 11;
    case ARM_REG_R12: return 12; case ARM_REG_SP: return 13; case ARM_REG_LR: return 14; case ARM_REG_PC: return 15;
    default: return -1;
    }
}

[[nodiscard]] int cfg_norm_arm64_gpr(unsigned reg) noexcept {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return static_cast<int>(reg - ARM64_REG_X0);
    if (reg == ARM64_REG_FP) return 29;
    if (reg == ARM64_REG_LR) return 30;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return static_cast<int>(reg - ARM64_REG_W0);
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return 31;
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return 32;
    return -1;
}

[[nodiscard]] std::uint64_t cfg_read_uint(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    std::uint64_t v = 0;
    if (endian == peelf::Endianness::Big) {
        for (std::size_t i = 0; i < width; ++i) v = (v << 8u) | p[i];
    } else {
        for (std::size_t i = 0; i < width; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8u);
    }
    return v;
}

[[nodiscard]] std::int64_t cfg_read_sint(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    const std::uint64_t u = cfg_read_uint(p, width, endian);
    switch (width) {
    case 1: return static_cast<std::int8_t>(u & 0xFFu);
    case 2: return static_cast<std::int16_t>(u & 0xFFFFu);
    case 4: return static_cast<std::int32_t>(u & 0xFFFFFFFFu);
    default: return static_cast<std::int64_t>(u);
    }
}

void recover_cfg_jump_tables(
    std::span<const std::uint8_t> function_bytes,
    std::uint64_t virtual_address,
    peelf::Architecture architecture,
    peelf::Endianness endianness,
    bool thumb_mode,
    const std::vector<Instruction>& instructions,
    const std::map<std::uint64_t, std::size_t>& instruction_by_address,
    const GraphByteReader& read_virtual_bytes,
    std::set<std::uint64_t>& leaders,
    std::map<std::size_t, std::vector<std::uint64_t>>& jump_tables,
    std::vector<IndirectRecoveryNote>& recovery_notes) {

    const auto read_table = [&](std::uint64_t table_va, std::size_t byte_len) -> std::vector<std::uint8_t> {
        if (byte_len == 0) return {};
        if (table_va >= virtual_address) {
            const auto off = table_va - virtual_address;
            if (off <= function_bytes.size() && byte_len <= function_bytes.size() - static_cast<std::size_t>(off)) {
                return std::vector<std::uint8_t>(
                    function_bytes.begin() + static_cast<std::ptrdiff_t>(off),
                    function_bytes.begin() + static_cast<std::ptrdiff_t>(off + byte_len));
            }
        }
        if (read_virtual_bytes) {
            auto ext = read_virtual_bytes(table_va, byte_len);
            if (ext.size() == byte_len) return ext;
        }
        return {};
    };

    const auto has_direct_bypass = [&](std::size_t guard_idx, std::size_t dispatch_idx) {
        for (const Instruction& ins : instructions) {
            if (!ins.branch_target) continue;
            for (std::size_t k = guard_idx + 1u; k <= dispatch_idx; ++k) {
                if (*ins.branch_target == instructions[k].address) return true;
            }
        }
        return false;
    };

    cs_arch cs_target{};
    unsigned cs_mode_flags = endianness == peelf::Endianness::Big
        ? static_cast<unsigned>(CS_MODE_BIG_ENDIAN)
        : static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN);
    switch (architecture) {
    case peelf::Architecture::X86: cs_target = CS_ARCH_X86; cs_mode_flags = static_cast<unsigned>(CS_MODE_32); break;
    case peelf::Architecture::X86_64: cs_target = CS_ARCH_X86; cs_mode_flags = static_cast<unsigned>(CS_MODE_64); break;
    case peelf::Architecture::ARM:
        cs_target = CS_ARCH_ARM;
        cs_mode_flags |= thumb_mode ? static_cast<unsigned>(CS_MODE_THUMB) : static_cast<unsigned>(CS_MODE_ARM);
        break;
    case peelf::Architecture::ARM64: cs_target = CS_ARCH_ARM64; break;
    default: return;
    }

    csh handle = 0;
    if (cs_open(cs_target, static_cast<cs_mode>(cs_mode_flags), &handle) != CS_ERR_OK) return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* raw = nullptr;
    const std::size_t count_insns = cs_disasm(handle, function_bytes.data(), function_bytes.size(), virtual_address, 0, &raw);
    if (count_insns == 0 || raw == nullptr) {
        cs_close(&handle);
        return;
    }

    const std::size_t limit = std::min(count_insns, instructions.size());

    const auto find_x86_guard = [&](std::size_t search_end_exclusive,
                                    int idx_reg,
                                    std::size_t& out_guard_idx) -> std::optional<std::size_t> {
        if (idx_reg < 0 || search_end_exclusive < 2) return std::nullopt;
        int tracked = idx_reg;
        bool saw_guard = false;
        bool strict_above = true;
        for (std::size_t pos = search_end_exclusive; pos-- > 0;) {
            const cs_insn& ins = raw[pos];
            if (!ins.detail) continue;
            if (pos + 1u < search_end_exclusive &&
                (ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET)) break;
            const auto& x86 = ins.detail->x86;
            if (!saw_guard) {
                if ((ins.id == X86_INS_JA || ins.id == X86_INS_JAE) &&
                    instructions[pos].branch_target &&
                    *instructions[pos].branch_target != instructions[search_end_exclusive].address) {
                    saw_guard = true;
                    strict_above = (ins.id == X86_INS_JA);
                    out_guard_idx = pos;
                    continue;
                }
                if ((ins.id == X86_INS_MOV || ins.id == X86_INS_MOVZX || ins.id == X86_INS_MOVSXD) &&
                    x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                    cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    tracked = cfg_norm_x86_gpr(x86.operands[1].reg);
                }
            } else {
                if (ins.id == X86_INS_CMP && x86.op_count == 2 &&
                    x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM &&
                    x86.operands[1].imm >= 0 && cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    const std::uint64_t cases = strict_above
                        ? (static_cast<std::uint64_t>(x86.operands[1].imm) + 1u)
                        : static_cast<std::uint64_t>(x86.operands[1].imm);
                    if (cases >= 1u && cases <= 256u) return static_cast<std::size_t>(cases);
                    return std::nullopt;
                }
                if ((ins.id == X86_INS_MOV || ins.id == X86_INS_MOVZX || ins.id == X86_INS_MOVSXD) &&
                    x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                    cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    tracked = cfg_norm_x86_gpr(x86.operands[1].reg);
                }
            }
        }
        return std::nullopt;
    };

    for (std::size_t i = 2; i < limit; ++i) {
        const cs_insn& dispatch = raw[i];
        if (!dispatch.detail) continue;

        if (architecture == peelf::Architecture::X86 || architecture == peelf::Architecture::X86_64) {
            const auto& x86 = dispatch.detail->x86;
            // 1) Guarded absolute u32/u64 jump table
            if (dispatch.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_MEM) {
                const auto& mem = x86.operands[0].mem;
                const std::uint8_t esz = x86.operands[0].size;
                if (mem.base == X86_REG_INVALID && mem.index != X86_REG_INVALID &&
                    mem.segment == X86_REG_INVALID && mem.disp >= 0 &&
                    (esz == 4 || esz == 8) && mem.scale == esz) {
                    std::size_t guard_idx = 0;
                    const auto count = find_x86_guard(i, cfg_norm_x86_gpr(mem.index), guard_idx);
                    if (count && !has_direct_bypass(guard_idx, i)) {
                        const auto table_va = static_cast<std::uint64_t>(mem.disp);
                        const auto bytes = read_table(table_va, *count * esz);
                        if (!bytes.empty()) {
                            std::vector<std::uint64_t> targets;
                            targets.reserve(*count);
                            for (std::size_t c = 0; c < *count; ++c) {
                                const std::uint64_t dst = cfg_read_uint(bytes.data() + c * esz, esz, endianness);
                                if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                                targets.push_back(dst);
                            }
                            if (!targets.empty()) {
                                for (const auto t : targets) leaders.insert(t);
                                recovery_notes.push_back(IndirectRecoveryNote{
                                    .source_address = dispatch.address,
                                    .table_or_slot_address = table_va,
                                    .target_count = targets.size(),
                                    .confidence = "IndirectTable",
                                    .evidence = std::format("Guarded absolute u{} jump table @ 0x{:X} ({} cases)",
                                                            static_cast<unsigned>(esz * 8u), table_va, targets.size()),
                                });
                                jump_tables.emplace(i, std::move(targets));
                            }
                        }
                    }
                }
            }

            // 2) Guarded x86-64 RIP-relative signed 32-bit offset jump table
            if (architecture == peelf::Architecture::X86_64 &&
                dispatch.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_REG) {
                const int jmp_reg = cfg_norm_x86_gpr(x86.operands[0].reg);
                int cand_a = -1;
                int cand_b = -1;
                int matched_base = -1;
                int matched_idx = -1;
                std::int64_t extra_disp = 0;
                std::size_t movsxd_pos = 0;
                bool found_movsxd = false;

                for (std::size_t p = i; p-- > 0 && (i - p) <= 12u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    if (ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET) break;
                    const auto& d = ins.detail->x86;
                    if (cand_a < 0) {
                        if (ins.id == X86_INS_ADD && d.op_count == 2 &&
                            d.operands[0].type == X86_OP_REG && d.operands[1].type == X86_OP_REG &&
                            cfg_norm_x86_gpr(d.operands[0].reg) == jmp_reg) {
                            cand_a = jmp_reg;
                            cand_b = cfg_norm_x86_gpr(d.operands[1].reg);
                        } else if (ins.id == X86_INS_LEA && d.op_count == 2 &&
                                   d.operands[0].type == X86_OP_REG && d.operands[1].type == X86_OP_MEM &&
                                   cfg_norm_x86_gpr(d.operands[0].reg) == jmp_reg &&
                                   d.operands[1].mem.base != X86_REG_INVALID &&
                                   d.operands[1].mem.index != X86_REG_INVALID &&
                                   d.operands[1].mem.scale == 1 && d.operands[1].mem.disp == 0) {
                            cand_a = cfg_norm_x86_gpr(d.operands[1].mem.base);
                            cand_b = cfg_norm_x86_gpr(d.operands[1].mem.index);
                        }
                    } else if ((ins.id == X86_INS_MOVSXD || ins.id == X86_INS_MOVSX) &&
                               d.op_count == 2 && d.operands[0].type == X86_OP_REG &&
                               d.operands[1].type == X86_OP_MEM && d.operands[1].mem.scale == 4 &&
                               d.operands[1].mem.base != X86_REG_INVALID &&
                               d.operands[1].mem.index != X86_REG_INVALID) {
                        const int dst_r = cfg_norm_x86_gpr(d.operands[0].reg);
                        const int base_r = cfg_norm_x86_gpr(d.operands[1].mem.base);
                        if ((dst_r == cand_a && base_r == cand_b) || (dst_r == cand_b && base_r == cand_a)) {
                            matched_base = base_r;
                            matched_idx = cfg_norm_x86_gpr(d.operands[1].mem.index);
                            extra_disp = d.operands[1].mem.disp;
                            movsxd_pos = p;
                            found_movsxd = true;
                            break;
                        }
                    }
                }

                if (found_movsxd && matched_base >= 0 && matched_idx >= 0) {
                    std::optional<std::uint64_t> anchor_va;
                    for (std::size_t p = movsxd_pos; p-- > 0 && (movsxd_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        if (ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET) break;
                        const auto& d = ins.detail->x86;
                        if (ins.id == X86_INS_LEA && d.op_count == 2 &&
                            d.operands[0].type == X86_OP_REG &&
                            cfg_norm_x86_gpr(d.operands[0].reg) == matched_base &&
                            d.operands[1].type == X86_OP_MEM &&
                            d.operands[1].mem.base == X86_REG_RIP &&
                            d.operands[1].mem.index == X86_REG_INVALID) {
                            anchor_va = ins.address + ins.size + static_cast<std::uint64_t>(d.operands[1].mem.disp);
                            break;
                        }
                        if (d.op_count >= 1 && d.operands[0].type == X86_OP_REG &&
                            ins.id != X86_INS_CMP && ins.id != X86_INS_TEST &&
                            cfg_norm_x86_gpr(d.operands[0].reg) == matched_base) {
                            break;
                        }
                    }

                    std::size_t guard_idx = 0;
                    const auto count = find_x86_guard(movsxd_pos, matched_idx, guard_idx);
                    if (anchor_va && count && !has_direct_bypass(guard_idx, i)) {
                        const auto table_va = static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(*anchor_va) + extra_disp);
                        const auto bytes = read_table(table_va, *count * 4u);
                        if (!bytes.empty()) {
                            std::vector<std::uint64_t> targets;
                            targets.reserve(*count);
                            for (std::size_t c = 0; c < *count; ++c) {
                                const std::int64_t rel = cfg_read_sint(bytes.data() + c * 4u, 4u, endianness);
                                const auto dst = static_cast<std::uint64_t>(
                                    static_cast<std::int64_t>(*anchor_va) + rel);
                                if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                                targets.push_back(dst);
                            }
                            if (!targets.empty()) {
                                for (const auto t : targets) leaders.insert(t);
                                recovery_notes.push_back(IndirectRecoveryNote{
                                    .source_address = dispatch.address,
                                    .table_or_slot_address = table_va,
                                    .target_count = targets.size(),
                                    .confidence = "IndirectTable",
                                    .evidence = std::format("RIP-relative i32 jump table @ 0x{:X} ({} cases)",
                                                            table_va, targets.size()),
                                });
                                jump_tables.emplace(i, std::move(targets));
                            }
                        }
                    }
                }
            }
        } else if (architecture == peelf::Architecture::ARM && thumb_mode) {
            const auto& arm = dispatch.detail->arm;
            if ((dispatch.id == ARM_INS_TBB || dispatch.id == ARM_INS_TBH) &&
                arm.op_count == 1 && arm.operands[0].type == ARM_OP_MEM &&
                arm.operands[0].mem.base == ARM_REG_PC && arm.operands[0].mem.index != ARM_REG_INVALID) {
                int tracked = cfg_norm_arm_gpr(arm.operands[0].mem.index);
                bool saw_guard = false;
                bool strict_above = true;
                std::size_t guard_idx = 0;
                std::optional<std::size_t> count;
                for (std::size_t p = i; p-- > 0 && (i - p) <= 8u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    const auto& d = ins.detail->arm;
                    if (!saw_guard) {
                        if (ins.id == ARM_INS_B && (d.cc == ARM_CC_HI || d.cc == ARM_CC_HS)) {
                            saw_guard = true;
                            strict_above = (d.cc == ARM_CC_HI);
                            guard_idx = p;
                        } else if (ins.id == ARM_INS_MOV && d.op_count == 2 &&
                                   d.operands[0].type == ARM_OP_REG && d.operands[1].type == ARM_OP_REG &&
                                   cfg_norm_arm_gpr(d.operands[0].reg) == tracked) {
                            tracked = cfg_norm_arm_gpr(d.operands[1].reg);
                        }
                    } else if (ins.id == ARM_INS_CMP && d.op_count == 2 &&
                               d.operands[0].type == ARM_OP_REG && d.operands[1].type == ARM_OP_IMM &&
                               d.operands[1].imm >= 0 && cfg_norm_arm_gpr(d.operands[0].reg) == tracked) {
                        const std::uint64_t cases = strict_above
                            ? (static_cast<std::uint64_t>(d.operands[1].imm) + 1u)
                            : static_cast<std::uint64_t>(d.operands[1].imm);
                        if (cases >= 1u && cases <= 256u) count = static_cast<std::size_t>(cases);
                        break;
                    }
                }
                if (count && !has_direct_bypass(guard_idx, i)) {
                    const std::size_t esz = (dispatch.id == ARM_INS_TBH) ? 2u : 1u;
                    const std::uint64_t table_va = dispatch.address + 4u;
                    const auto bytes = read_table(table_va, *count * esz);
                    if (!bytes.empty()) {
                        std::vector<std::uint64_t> targets;
                        targets.reserve(*count);
                        for (std::size_t c = 0; c < *count; ++c) {
                            const std::uint64_t e = cfg_read_uint(bytes.data() + c * esz, esz, endianness);
                            const std::uint64_t dst = (table_va + e * 2u) & ~std::uint64_t{1};
                            if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                            targets.push_back(dst);
                        }
                        if (!targets.empty()) {
                            for (const auto t : targets) leaders.insert(t);
                            recovery_notes.push_back(IndirectRecoveryNote{
                                .source_address = dispatch.address,
                                .table_or_slot_address = table_va,
                                .target_count = targets.size(),
                                .confidence = "IndirectTable",
                                .evidence = std::format("Thumb-2 {} jump table @ 0x{:X} ({} cases)",
                                                        dispatch.id == ARM_INS_TBH ? "tbh" : "tbb",
                                                        table_va, targets.size()),
                            });
                            jump_tables.emplace(i, std::move(targets));
                        }
                    }
                }
            }
        } else if (architecture == peelf::Architecture::ARM64) {
            const auto& a64 = dispatch.detail->arm64;
            if (dispatch.id == ARM64_INS_BR && a64.op_count == 1 && a64.operands[0].type == ARM64_OP_REG) {
                const int target_reg = cfg_norm_arm64_gpr(a64.operands[0].reg);

                const auto resolve_a64_va = [&](std::size_t before_pos, int reg) -> std::optional<std::uint64_t> {
                    if (reg < 0) return std::nullopt;
                    int cur = reg;
                    std::optional<std::uint64_t> add_off;
                    for (std::size_t p = before_pos; p-- > 0 && (before_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        const auto& d = ins.detail->arm64;
                        if ((ins.id == ARM64_INS_ADR || ins.id == ARM64_INS_ADRP) &&
                            d.op_count == 2 && d.operands[0].type == ARM64_OP_REG &&
                            cfg_norm_arm64_gpr(d.operands[0].reg) == cur &&
                            d.operands[1].type == ARM64_OP_IMM) {
                            return static_cast<std::uint64_t>(d.operands[1].imm) + add_off.value_or(0ULL);
                        }
                        if (!add_off && ins.id == ARM64_INS_ADD && d.op_count == 3 &&
                            d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                            d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 &&
                            cfg_norm_arm64_gpr(d.operands[0].reg) == cur) {
                            const std::uint64_t sh = d.operands[2].shift.type == ARM64_SFT_LSL
                                ? d.operands[2].shift.value : 0u;
                            add_off = static_cast<std::uint64_t>(d.operands[2].imm) << sh;
                            cur = cfg_norm_arm64_gpr(d.operands[1].reg);
                            continue;
                        }
                        if (d.op_count >= 1 && d.operands[0].type == ARM64_OP_REG &&
                            ins.id != ARM64_INS_CMP && ins.id != ARM64_INS_TST &&
                            cfg_norm_arm64_gpr(d.operands[0].reg) == cur) {
                            break;
                        }
                    }
                    return std::nullopt;
                };

                const auto find_a64_guard = [&](std::size_t before_pos,
                                                int idx_reg,
                                                std::size_t& out_guard) -> std::optional<std::size_t> {
                    if (idx_reg < 0 || before_pos < 2) return std::nullopt;
                    int tracked = idx_reg;
                    bool saw_guard = false;
                    bool strict_above = true;
                    for (std::size_t p = before_pos; p-- > 0 && (before_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        const auto& d = ins.detail->arm64;
                        if (!saw_guard) {
                            if (ins.id == ARM64_INS_B && (d.cc == ARM64_CC_HI || d.cc == ARM64_CC_HS)) {
                                saw_guard = true;
                                strict_above = (d.cc == ARM64_CC_HI);
                                out_guard = p;
                            } else if (ins.id == ARM64_INS_MOV && d.op_count == 2 &&
                                       d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                                       cfg_norm_arm64_gpr(d.operands[0].reg) == tracked) {
                                tracked = cfg_norm_arm64_gpr(d.operands[1].reg);
                            }
                        } else {
                            if ((ins.id == ARM64_INS_CMP && d.op_count >= 2 &&
                                 d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_IMM &&
                                 d.operands[1].imm >= 0 && cfg_norm_arm64_gpr(d.operands[0].reg) == tracked) ||
                                (ins.id == ARM64_INS_SUBS && d.op_count >= 3 &&
                                 cfg_norm_arm64_gpr(d.operands[0].reg) == 31 &&
                                 d.operands[1].type == ARM64_OP_REG && d.operands[2].type == ARM64_OP_IMM &&
                                 d.operands[2].imm >= 0 && cfg_norm_arm64_gpr(d.operands[1].reg) == tracked)) {
                                const unsigned imm_op = (ins.id == ARM64_INS_SUBS) ? 2u : 1u;
                                const std::uint64_t sh = d.operands[imm_op].shift.type == ARM64_SFT_LSL
                                    ? d.operands[imm_op].shift.value : 0u;
                                const std::uint64_t imm = static_cast<std::uint64_t>(d.operands[imm_op].imm) << sh;
                                const std::uint64_t cases = strict_above ? (imm + 1u) : imm;
                                if (cases >= 1u && cases <= 256u) return static_cast<std::size_t>(cases);
                                return std::nullopt;
                            }
                        }
                    }
                    return std::nullopt;
                };

                for (std::size_t p = i; p-- > 0 && (i - p) <= 8u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    const auto& d = ins.detail->arm64;
                    if (ins.id == ARM64_INS_ADD && d.op_count == 3 &&
                        d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                        d.operands[2].type == ARM64_OP_REG &&
                        cfg_norm_arm64_gpr(d.operands[0].reg) == target_reg) {
                        const int anchor_r = cfg_norm_arm64_gpr(d.operands[1].reg);
                        const int off_r = cfg_norm_arm64_gpr(d.operands[2].reg);
                        const unsigned shift = d.operands[2].shift.value;
                        const bool ext_signed =
                            d.operands[2].ext == ARM64_EXT_SXTB ||
                            d.operands[2].ext == ARM64_EXT_SXTH ||
                            d.operands[2].ext == ARM64_EXT_SXTW;

                        for (std::size_t lp = p; lp-- > 0 && (p - lp) <= 8u;) {
                            const cs_insn& lins = raw[lp];
                            if (!lins.detail) continue;
                            const auto& ld = lins.detail->arm64;
                            if ((lins.id == ARM64_INS_LDRB || lins.id == ARM64_INS_LDRSB ||
                                 lins.id == ARM64_INS_LDRH || lins.id == ARM64_INS_LDRSH ||
                                 lins.id == ARM64_INS_LDRSW || lins.id == ARM64_INS_LDR) &&
                                ld.op_count == 2 && ld.operands[0].type == ARM64_OP_REG &&
                                cfg_norm_arm64_gpr(ld.operands[0].reg) == off_r &&
                                ld.operands[1].type == ARM64_OP_MEM &&
                                ld.operands[1].mem.base != ARM64_REG_INVALID &&
                                ld.operands[1].mem.index != ARM64_REG_INVALID &&
                                ld.operands[1].mem.disp == 0) {
                                std::size_t esz = 4;
                                bool is_signed = ext_signed;
                                switch (lins.id) {
                                case ARM64_INS_LDRB: esz = 1; break;
                                case ARM64_INS_LDRSB: esz = 1; is_signed = true; break;
                                case ARM64_INS_LDRH: esz = 2; break;
                                case ARM64_INS_LDRSH: esz = 2; is_signed = true; break;
                                case ARM64_INS_LDRSW: esz = 4; is_signed = true; break;
                                default: break;
                                }
                                const int base_r = cfg_norm_arm64_gpr(ld.operands[1].mem.base);
                                const int idx_r = cfg_norm_arm64_gpr(ld.operands[1].mem.index);
                                const auto table_va = resolve_a64_va(lp, base_r);
                                const auto anchor_va = (anchor_r == base_r) ? table_va : resolve_a64_va(p, anchor_r);
                                std::size_t guard_idx = 0;
                                const auto count = find_a64_guard(lp, idx_r, guard_idx);
                                if (table_va && anchor_va && count && !has_direct_bypass(guard_idx, i)) {
                                    const auto bytes = read_table(*table_va, *count * esz);
                                    if (!bytes.empty()) {
                                        std::vector<std::uint64_t> targets;
                                        targets.reserve(*count);
                                        for (std::size_t c = 0; c < *count; ++c) {
                                            std::uint64_t dst = 0;
                                            if (is_signed) {
                                                const std::int64_t rel =
                                                    cfg_read_sint(bytes.data() + c * esz, esz, endianness) *
                                                    (std::int64_t{1} << shift);
                                                dst = static_cast<std::uint64_t>(
                                                    static_cast<std::int64_t>(*anchor_va) + rel);
                                            } else {
                                                const std::uint64_t rel =
                                                    cfg_read_uint(bytes.data() + c * esz, esz, endianness) << shift;
                                                dst = *anchor_va + rel;
                                            }
                                            if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                                            targets.push_back(dst);
                                        }
                                        if (!targets.empty()) {
                                            for (const auto t : targets) leaders.insert(t);
                                            recovery_notes.push_back(IndirectRecoveryNote{
                                                .source_address = dispatch.address,
                                                .table_or_slot_address = *table_va,
                                                .target_count = targets.size(),
                                                .confidence = "IndirectTable",
                                                .evidence = std::format("ARM64 jump table @ 0x{:X} ({} cases)",
                                                                        *table_va, targets.size()),
                                            });
                                            jump_tables.emplace(i, std::move(targets));
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    cs_free(raw, count_insns);
    cs_close(&handle);
}

} // namespace

CallGraph build_function_cfg_call_graph(std::span<const std::uint8_t> function_bytes,
                                        std::uint64_t virtual_address,
                                        peelf::Architecture architecture,
                                        peelf::Endianness endianness,
                                        std::optional<std::uint64_t> file_offset,
                                        std::string label,
                                        bool thumb_mode,
                                        bool reachable_only,
                                        const GraphByteReader& read_virtual_bytes) {
    CallGraph graph{
        .id = "function_cfg",
        .label = std::move(label),
        .architecture = architecture,
        .endianness = endianness,
        .nodes = {},
        .edges = {},
        .indirect_recoveries = {},
    };

    const std::optional<Architecture> arch = to_disassembler_architecture(architecture);
    if (!arch || function_bytes.empty()) {
        return graph;
    }
    if (function_bytes.size() > std::numeric_limits<std::uint64_t>::max() - virtual_address) return graph;
    if (file_offset && function_bytes.size() > std::numeric_limits<std::uint64_t>::max() - *file_offset) return graph;

    Disassembler disassembler;
    if (!disassembler.init(*arch, to_disassembler_endianness(endianness))) {
        return graph;
    }
    if (architecture == peelf::Architecture::ARM && !disassembler.set_thumb_mode(thumb_mode)) return graph;

    const std::vector<Instruction> instructions =
        disassembler.disassemble(function_bytes.data(), function_bytes.size(), virtual_address);
    if (instructions.empty()) {
        return graph;
    }

    std::map<std::uint64_t, std::size_t> instruction_by_address;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        instruction_by_address.emplace(instructions[index].address, index);
    }

    const std::uint64_t function_end =
        virtual_address + static_cast<std::uint64_t>(function_bytes.size());
    std::set<std::uint64_t> leaders{instructions.front().address};
    const auto conditional = [](const Instruction& i) { return i.flow == InstructionFlow::ConditionalBranch; };
    const auto branch = [](const Instruction& i) { return i.flow == InstructionFlow::Branch; };
    const auto returns = [](const Instruction& i) {
        return i.flow == InstructionFlow::Return || i.flow == InstructionFlow::ConditionalReturn;
    };
    const auto terminates = [&](const Instruction& i) { return conditional(i) || branch(i) || returns(i); };

    std::map<std::size_t, std::vector<std::uint64_t>> jump_tables;
    recover_cfg_jump_tables(
        function_bytes,
        virtual_address,
        architecture,
        endianness,
        thumb_mode,
        instructions,
        instruction_by_address,
        read_virtual_bytes,
        leaders,
        jump_tables,
        graph.indirect_recoveries);

    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const Instruction& instruction = instructions[index];
        const auto after = index + (instruction.delay_slot ? 2u : 1u);
        const std::uint64_t next_address = after < instructions.size() ? instructions[after].address : function_end;
        const std::optional<std::uint64_t> target = instruction.branch_target;
        const bool target_in_function = target && *target >= virtual_address && *target < function_end &&
                                        instruction_by_address.contains(*target);

        if (conditional(instruction)) {
            if (target_in_function) {
                leaders.insert(*target);
            }
            if (index + 1u < instructions.size()) {
                leaders.insert(next_address);
            }
        } else if (branch(instruction) || returns(instruction)) {
            if (target_in_function) {
                leaders.insert(*target);
            }
            if (index + 1u < instructions.size()) {
                leaders.insert(next_address);
            }
        }
    }

    struct Block {
        std::string id;
        std::size_t first_instruction = 0;
        std::size_t instruction_count = 0;
        std::uint64_t start = 0;
        std::uint64_t end = 0;
    };

    std::vector<Block> blocks;
    std::map<std::uint64_t, std::string> block_by_start;
    std::size_t index = 0;
    while (index < instructions.size()) {
        const std::size_t first = index;
        const std::uint64_t start = instructions[index].address;
        ++index;
        while (index < instructions.size() && !leaders.contains(instructions[index].address)) {
            const Instruction& previous = instructions[index - 1u];
            if (terminates(previous)) {
                if (previous.delay_slot && index < instructions.size()) ++index;
                break;
            }
            ++index;
        }

        const Instruction& last = instructions[index - 1u];
        const std::uint64_t end = last.address + static_cast<std::uint64_t>(last.bytes.size());
        const std::string id = "bb_" + std::to_string(blocks.size());
        block_by_start.emplace(start, id);
        blocks.push_back(Block{
            .id = id,
            .first_instruction = first,
            .instruction_count = index - first,
            .start = start,
            .end = end,
        });
    }

    graph.nodes.reserve(blocks.size() + 1u);
    for (const Block& block : blocks) {
        const std::optional<std::uint64_t> block_file_offset =
            file_offset ? std::optional(*file_offset + (block.start - virtual_address)) : std::nullopt;
        graph.nodes.push_back(CallGraphNode{
            .id = block.id,
            .label = "loc_" + format_hex(block.start),
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{
                .start = GraphAddress{
                    .virtual_address = block.start,
                    .relative_virtual_address = block.start - virtual_address,
                    .file_offset = block_file_offset,
                },
                .size = block.end - block.start,
            },
            .first_instruction_index = static_cast<std::uint64_t>(block.first_instruction),
            .instruction_count = static_cast<std::uint64_t>(block.instruction_count),
        });
        auto& node = graph.nodes.back();
        for (std::size_t i = block.first_instruction; i < block.first_instruction + block.instruction_count; ++i) {
            const auto& instruction = instructions[i];
            node.instructions.push_back({instruction.address, instruction.mnemonic, instruction.operands, instruction.branch_target});
        }
    }

    graph.nodes.push_back(CallGraphNode{
        .id = "return",
        .label = "return",
        .kind = CallGraphNodeKind::External,
    });

    for (std::size_t block_index = 0; block_index < blocks.size(); ++block_index) {
        const Block& block = blocks[block_index];
        const auto last_index = block.first_instruction + block.instruction_count - 1u;
        const auto control_index = block.instruction_count > 1 && instructions[last_index - 1].delay_slot &&
            terminates(instructions[last_index - 1]) ? last_index - 1 : last_index;
        const Instruction& last = instructions[control_index];
        const std::uint64_t next_address = block.end;
        const auto target = last.branch_target;
        const bool target_in_function = target && block_by_start.contains(*target);

        const auto unresolved = [&](CallGraphEdgeKind kind, std::string reason) {
            const auto id = "external_" + block.id;
            const auto known_target = kind == CallGraphEdgeKind::Unknown ? std::nullopt : target;
            graph.nodes.push_back(CallGraphNode{.id = id,
                .label = known_target ? format_hex(*known_target) + " (outside analyzed blocks)" : std::move(reason),
                .kind = known_target ? CallGraphNodeKind::External : CallGraphNodeKind::Unknown,
                .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = known_target}}});
            graph.edges.push_back({block.id, id, kind, known_target ? "external" : "unresolved"});
        };

        if (last.annulled_delay_slot) {
            unresolved(CallGraphEdgeKind::Unknown, "Unresolved branch-likely (annulled delay slot)");
            continue;
        }
        if (last.delay_slot && control_index == last_index && terminates(last)) {
            unresolved(CallGraphEdgeKind::Unknown, "Missing delay slot");
            continue;
        }

        if (returns(last)) {
            graph.edges.push_back(CallGraphEdge{
                .from_node_id = block.id,
                .to_node_id = "return",
                .kind = CallGraphEdgeKind::Return,
                .label = "return",
            });
            if (last.flow == InstructionFlow::ConditionalReturn && block_by_start.contains(next_address))
                graph.edges.push_back({block.id, block_by_start.at(next_address), CallGraphEdgeKind::Fallthrough, "not returned"});
            continue;
        }

        if (conditional(last)) {
            if (target_in_function) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[*target],
                    .kind = CallGraphEdgeKind::ConditionalBranch,
                    .label = "taken",
                });
            } else {
                unresolved(CallGraphEdgeKind::ConditionalBranch, "Unresolved conditional branch");
            }
            if (block_by_start.contains(next_address)) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[next_address],
                    .kind = CallGraphEdgeKind::Fallthrough,
                    .label = "fallthrough",
                });
            }
            continue;
        }

        if (branch(last)) {
            if (const auto table = jump_tables.find(control_index); table != jump_tables.end()) {
                for (std::size_t case_index = 0; case_index < table->second.size(); ++case_index) {
                    graph.edges.push_back({block.id, block_by_start.at(table->second[case_index]),
                        CallGraphEdgeKind::UnconditionalBranch, "case " + std::to_string(case_index)});
                }
            } else if (target_in_function) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[*target],
                    .kind = CallGraphEdgeKind::UnconditionalBranch,
                    .label = "branch",
                });
            } else {
                unresolved(CallGraphEdgeKind::UnconditionalBranch, "Unresolved indirect branch / jump table");
            }
            continue;
        }

        if (block_index + 1u < blocks.size() && block_by_start.contains(next_address)) {
            graph.edges.push_back(CallGraphEdge{
                .from_node_id = block.id,
                .to_node_id = block_by_start[next_address],
                .kind = CallGraphEdgeKind::Fallthrough,
                .label = "fallthrough",
            });
        }
    }

    if (reachable_only) {
        std::set<std::string> reachable{"bb_0"};
        std::vector<std::string> pending{"bb_0"};
        for (std::size_t i = 0; i < pending.size(); ++i) {
            for (const auto& edge : graph.edges) {
                if (edge.from_node_id == pending[i] && reachable.insert(edge.to_node_id).second)
                    pending.push_back(edge.to_node_id);
            }
        }
        std::erase_if(graph.nodes, [&](const auto& node) { return !reachable.contains(node.id); });
        std::erase_if(graph.edges, [&](const auto& edge) {
            return !reachable.contains(edge.from_node_id) || !reachable.contains(edge.to_node_id);
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
                .demangled_name = peelf::demangle_symbol(symbol.name).demangled,
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

} // namespace viewe
