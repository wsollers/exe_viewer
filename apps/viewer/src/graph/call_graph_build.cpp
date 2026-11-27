#include "graph/call_graph.hpp"
#include "graph/call_graph_internal.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <peelf/demangle.hpp>
#include <peelf/endian_reader.hpp>

#include "disasm/disassembler.hpp"

namespace viewer {
namespace {
using detail::format_hex;

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

        std::uint64_t mag = 0;
        std::string_view digits = operands.substr(begin, i - begin);
        if (negative) {
            digits.remove_prefix(1u);
        }
        if (base == 16) {
            digits.remove_prefix(2u);
        }
        const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), mag, base);
        if (ec == std::errc{} && ptr == digits.data() + digits.size()) {
            constexpr std::uint64_t kMaxNegMag =
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL;
            if (negative) {
                if (mag == kMaxNegMag) {
                    result = std::numeric_limits<std::int64_t>::min();
                } else if (mag < kMaxNegMag) {
                    result = -static_cast<std::int64_t>(mag);
                }
            } else if (mag <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                result = static_cast<std::int64_t>(mag);
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
    const auto hi_disp = peelf::checked_scale_signed_displacement(*high, 12u);
    if (!hi_disp.has_value()) {
        return std::nullopt;
    }
    const auto page_va = peelf::checked_apply_signed_displacement(previous.address, *hi_disp);
    if (!page_va.has_value()) {
        return std::nullopt;
    }
    return peelf::checked_apply_signed_displacement(*page_va, *low);
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
        return peelf::checked_apply_signed_displacement(instruction.address, *decimal_target);
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

[[nodiscard]] bool contains_case_sensitive(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
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

[[nodiscard]] bool ascii_icontains(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || needle.size() > hay.size()) {
        return false;
    }
    const auto it = std::search(
        hay.begin(),
        hay.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != hay.end();
}

[[nodiscard]] bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && ascii_icontains(a, b);
}

[[nodiscard]] std::string_view trim_x86_import_decoration(std::string_view name) noexcept {
    if (name.starts_with("_imp__")) {
        name.remove_prefix(6);
    } else if (name.starts_with("__imp_")) {
        name.remove_prefix(6);
    }
    if (name.starts_with('_') && !name.starts_with("__p_") && !name.starts_with("__get") &&
        !name.starts_with("__wget") && !name.starts_with("_initterm") &&
        !name.starts_with("_cexit") && !name.starts_with("_c_exit") &&
        !name.starts_with("_exit") && !name.starts_with("_get_") &&
        !name.starts_with("_configure_") && !name.starts_with("_initialize_")) {
        name.remove_prefix(1);
    }
    const std::size_t at = name.find('@');
    if (at != std::string_view::npos && at > 0u) {
        name = name.substr(0, at);
    }
    return name;
}

[[nodiscard]] bool is_pe_crt_arg_setup_import(std::string_view raw_name) noexcept {
    const std::string_view fn = trim_x86_import_decoration(raw_name);
    constexpr std::array<std::string_view, 15> kArgSetupNames{
        "GetCommandLineA",
        "GetCommandLineW",
        "GetStartupInfoA",
        "GetStartupInfoW",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "__p___argc",
        "__p___argv",
        "__p___wargv",
        "__getmainargs",
        "__wgetmainargs",
        "_get_narrow_winmain_command_line",
        "_get_wide_winmain_command_line",
        "_configure_narrow_argv",
        "_configure_wide_argv",
    };
    return std::ranges::any_of(kArgSetupNames, [&](std::string_view pat) {
        return ascii_iequals(fn, pat);
    });
}

[[nodiscard]] bool is_pe_crt_hallmark_import(std::string_view raw_name) noexcept {
    if (is_pe_crt_arg_setup_import(raw_name)) {
        return true;
    }
    const std::string_view fn = trim_x86_import_decoration(raw_name);
    constexpr std::array<std::string_view, 7> kCrtInitNames{
        "_initterm",
        "_initterm_e",
        "_initialize_narrow_environment",
        "_initialize_wide_environment",
        "_initialize_onexit_table",
        "__set_app_type",
        "_set_fmode",
    };
    return std::ranges::any_of(kCrtInitNames, [&](std::string_view pat) {
        return ascii_iequals(fn, pat);
    });
}

[[nodiscard]] bool is_pe_crt_exit_import(std::string_view raw_name) noexcept {
    const std::string_view fn = trim_x86_import_decoration(raw_name);
    constexpr std::array<std::string_view, 7> kExitNames{
        "exit",
        "_exit",
        "_cexit",
        "_c_exit",
        "ExitProcess",
        "quick_exit",
        "terminate",
    };
    return std::ranges::any_of(kExitNames, [&](std::string_view pat) {
        return ascii_iequals(fn, pat);
    });
}

[[nodiscard]] std::optional<std::uint64_t> parse_x86_abs_memory_target(const Instruction& instruction) {
    const std::string_view ops = instruction.operands;
    const std::size_t open_br = ops.find('[');
    const std::size_t close_br = ops.find(']', open_br == std::string_view::npos ? 0u : open_br + 1u);
    if (open_br == std::string_view::npos || close_br == std::string_view::npos || close_br <= open_br + 1u) {
        return std::nullopt;
    }
    std::string_view inner = ops.substr(open_br + 1u, close_br - open_br - 1u);
    while (!inner.empty() && std::isspace(static_cast<unsigned char>(inner.front())) != 0) {
        inner.remove_prefix(1u);
    }
    while (!inner.empty() && std::isspace(static_cast<unsigned char>(inner.back())) != 0) {
        inner.remove_suffix(1u);
    }
    if (!inner.starts_with("0x") && !inner.starts_with("0X")) {
        return std::nullopt;
    }
    return parse_hex_u64(inner);
}

[[nodiscard]] std::optional<std::uint64_t> parse_pe_iat_slot_operand(const Instruction& instruction,
                                                                     bool is_64bit) {
    if (is_64bit) {
        return parse_x86_rip_relative_memory_target(instruction);
    }
    return parse_x86_abs_memory_target(instruction);
}

[[nodiscard]] const peelf::Section* find_executable_pe_section_at_va(const peelf::IBinaryImage& image,
                                                                     std::uint64_t va) noexcept {
    for (const peelf::Section& sec : image.sections()) {
        if (!sec.executable) {
            continue;
        }
        const std::uint64_t span = std::max(sec.file_size, sec.virtual_size);
        if (span != 0u && va >= sec.virtual_address && (va - sec.virtual_address) < span) {
            return &sec;
        }
    }
    return nullptr;
}

[[nodiscard]] std::string_view find_pe_import_name_at_slot(const peelf::IBinaryImage& image,
                                                           std::uint64_t slot_va) noexcept {
    for (const peelf::ImportEntry& imp : image.imports()) {
        if (imp.address == slot_va && !imp.name.empty()) {
            return imp.name;
        }
    }
    return {};
}

[[nodiscard]] std::string_view resolve_pe_thunk_import_name(const peelf::IBinaryImage& image,
                                                            Disassembler& disasm,
                                                            std::uint64_t target_va,
                                                            std::uint8_t depth = 0) {
    if (depth > 2u) {
        return {};
    }
    const auto off = image.virtual_address_to_file_offset(target_va);
    if (!off.has_value()) {
        return {};
    }
    const auto raw = image.read_bytes_at_offset(*off, 16u);
    if (!raw.has_value() || raw->empty()) {
        return {};
    }
    const std::vector<Instruction> insts = disasm.disassemble_count(raw->data(), raw->size(), target_va, 2u);
    if (insts.empty() || insts.front().mnemonic != "jmp") {
        return {};
    }
    if (const auto slot_va = parse_pe_iat_slot_operand(insts.front(), image.is_64bit()); slot_va.has_value()) {
        return find_pe_import_name_at_slot(image, *slot_va);
    }
    if (const auto next_va = parse_direct_call_target(insts.front());
        next_va.has_value() && *next_va != target_va) {
        return resolve_pe_thunk_import_name(image, disasm, *next_va, static_cast<std::uint8_t>(depth + 1u));
    }
    return {};
}

struct ScannedPeStartupFunction {
    std::uint64_t start_va = 0;
    std::uint64_t byte_size = 0;
    struct InternalCallSite {
        std::size_t inst_index = 0;
        std::uint64_t target_va = 0;
        bool is_tail_jump = false;
    };
    struct ImportCallSite {
        std::size_t inst_index = 0;
        std::string name{};
    };
    std::vector<InternalCallSite> internal_calls{};
    std::vector<ImportCallSite> import_calls{};
    bool has_arg_setup_import = false;
    bool has_hallmark_import = false;
    std::optional<std::size_t> first_exit_inst_index{};
};

[[nodiscard]] std::optional<ScannedPeStartupFunction> scan_pe_startup_function(
    const peelf::IBinaryImage& image,
    Disassembler& disasm,
    std::uint64_t fn_va,
    std::size_t max_bytes = 384u) {
    const peelf::Section* sec = find_executable_pe_section_at_va(image, fn_va);
    const auto file_off = image.virtual_address_to_file_offset(fn_va);
    if (sec == nullptr || !file_off.has_value() || sec->file_size == 0u) {
        return std::nullopt;
    }
    const std::uint64_t sec_end_off = sec->file_offset + sec->file_size;
    if (*file_off >= sec_end_off) {
        return std::nullopt;
    }
    const auto read_len = static_cast<std::size_t>(
        std::min<std::uint64_t>(max_bytes, sec_end_off - *file_off));
    const auto raw = image.read_bytes_at_offset(*file_off, read_len);
    if (!raw.has_value() || raw->empty()) {
        return std::nullopt;
    }

    const std::vector<Instruction> insts =
        disasm.disassemble_count(raw->data(), raw->size(), fn_va, 96u);
    if (insts.empty()) {
        return std::nullopt;
    }

    ScannedPeStartupFunction out{};
    out.start_va = fn_va;
    std::uint64_t max_local_branch_va = fn_va;
    std::map<std::string, std::string> reg_imports{};

    const auto trim_token = [](std::string_view sv) noexcept {
        while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
            sv.remove_prefix(1u);
        }
        while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
            sv.remove_suffix(1u);
        }
        return sv;
    };

    for (std::size_t i = 0u; i < insts.size(); ++i) {
        const Instruction& inst = insts[i];
        if (inst.mnemonic == "int3") {
            break;
        }
        out.byte_size = (inst.address - fn_va) + static_cast<std::uint64_t>(inst.bytes.size());

        auto record_import = [&](std::string_view imp_name, bool is_call) {
            if (imp_name.empty()) {
                return;
            }
            if (is_pe_crt_arg_setup_import(imp_name)) {
                out.has_arg_setup_import = true;
                out.has_hallmark_import = true;
            } else if (is_pe_crt_hallmark_import(imp_name)) {
                out.has_hallmark_import = true;
            }
            if (is_call) {
                out.import_calls.push_back(ScannedPeStartupFunction::ImportCallSite{
                    .inst_index = i,
                    .name = std::string(imp_name),
                });
                if (is_pe_crt_exit_import(imp_name) && !out.first_exit_inst_index.has_value()) {
                    out.first_exit_inst_index = i;
                }
            }
        };

        if (inst.mnemonic == "mov" || inst.mnemonic == "lea") {
            const std::size_t comma = inst.operands.find(',');
            if (comma != std::string_view::npos) {
                const std::string dst(trim_token(std::string_view(inst.operands).substr(0u, comma)));
                if (const auto slot = parse_pe_iat_slot_operand(inst, image.is_64bit()); slot.has_value()) {
                    const std::string_view imp = find_pe_import_name_at_slot(image, *slot);
                    if (!imp.empty()) {
                        reg_imports[dst] = std::string(imp);
                        record_import(imp, false);
                    } else {
                        reg_imports.erase(dst);
                    }
                } else {
                    reg_imports.erase(dst);
                }
            }
            continue;
        }

        if (inst.mnemonic == "call" || inst.mnemonic == "jmp") {
            const bool is_jmp = (inst.mnemonic == "jmp");
            if (const auto slot = parse_pe_iat_slot_operand(inst, image.is_64bit()); slot.has_value()) {
                record_import(find_pe_import_name_at_slot(image, *slot), true);
            } else if (const auto target = parse_direct_call_target(inst); target.has_value()) {
                if (is_jmp && inst.address < max_local_branch_va &&
                    *target > fn_va && *target < fn_va + read_len &&
                    (*target - fn_va) < 256u && i + 1u < insts.size()) {
                    max_local_branch_va = std::max(max_local_branch_va, *target);
                } else {
                    const std::string_view thunk_imp = resolve_pe_thunk_import_name(image, disasm, *target);
                    if (!thunk_imp.empty()) {
                        record_import(thunk_imp, true);
                    } else if (*target != fn_va &&
                               find_executable_pe_section_at_va(image, *target) != nullptr) {
                        out.internal_calls.push_back(ScannedPeStartupFunction::InternalCallSite{
                            .inst_index = i,
                            .target_va = *target,
                            .is_tail_jump = is_jmp,
                        });
                    }
                }
            } else {
                const std::string op_reg(trim_token(inst.operands));
                if (const auto it = reg_imports.find(op_reg); it != reg_imports.end()) {
                    record_import(it->second, true);
                }
            }

            if (is_jmp && inst.address >= max_local_branch_va) {
                break;
            }
            continue;
        }

        if (inst.mnemonic.starts_with('j')) {
            if (const auto br_target = parse_direct_call_target(inst);
                br_target.has_value() && *br_target > fn_va && *br_target < fn_va + read_len) {
                max_local_branch_va = std::max(max_local_branch_va, *br_target);
            }
            continue;
        }

        if ((inst.mnemonic == "ret" || inst.mnemonic == "retn") &&
            inst.address >= max_local_branch_va) {
            break;
        }
    }

    return out;
}

struct RecoveredPeStartupFlow {
    std::uint64_t crt_va = 0;
    std::uint64_t crt_size = 1;
    std::optional<std::uint64_t> invoke_main_va{};
    std::uint64_t user_entry_va = 0;
    std::uint64_t user_entry_size = 1;
    bool entry_tail_jumped_to_crt = false;
};

[[nodiscard]] std::optional<std::uint64_t> match_pe_invoke_main_wrapper(
    const peelf::IBinaryImage& image,
    Disassembler& disasm,
    std::uint64_t candidate_va) {
    const auto fn = scan_pe_startup_function(image, disasm, candidate_va, 128u);
    if (!fn.has_value() || fn->first_exit_inst_index.has_value()) {
        return std::nullopt;
    }
    if (!fn->has_arg_setup_import || fn->internal_calls.size() != 1u) {
        return std::nullopt;
    }
    return fn->internal_calls.front().target_va;
}

[[nodiscard]] std::optional<RecoveredPeStartupFlow> select_user_entry_from_crt_candidate(
    const peelf::IBinaryImage& image,
    Disassembler& disasm,
    const ScannedPeStartupFunction& crt_fn,
    bool entry_tail_jumped) {
    if (crt_fn.internal_calls.empty()) {
        return std::nullopt;
    }
    if (!crt_fn.has_hallmark_import && !crt_fn.first_exit_inst_index.has_value()) {
        return std::nullopt;
    }

    const std::size_t cutoff =
        crt_fn.first_exit_inst_index.value_or(std::numeric_limits<std::size_t>::max());

    // 1. Check for MSVC UCRT 2-hop `invoke_main` wrapper among internal calls before exit.
    for (auto it = crt_fn.internal_calls.rbegin(); it != crt_fn.internal_calls.rend(); ++it) {
        if (it->inst_index >= cutoff || it->is_tail_jump) {
            continue;
        }
        if (const auto inner_user_va = match_pe_invoke_main_wrapper(image, disasm, it->target_va);
            inner_user_va.has_value()) {
            const auto user_scan = scan_pe_startup_function(image, disasm, *inner_user_va, 128u);
            return RecoveredPeStartupFlow{
                .crt_va = crt_fn.start_va,
                .crt_size = std::max<std::uint64_t>(1u, crt_fn.byte_size),
                .invoke_main_va = it->target_va,
                .user_entry_va = *inner_user_va,
                .user_entry_size = user_scan.has_value()
                                       ? std::max<std::uint64_t>(1u, user_scan->byte_size)
                                       : 1u,
                .entry_tail_jumped_to_crt = entry_tail_jumped,
            };
        }
    }

    // 2. If CRT argument-setup imports (`GetCommandLine*`, `GetStartupInfo*`, `__p___argc`,
    //    `__getmainargs`) appear in `crt_fn`, prefer the internal call immediately following the
    //    last argument-setup import before `exit`/`ExitProcess`.
    std::optional<std::size_t> last_arg_setup_idx{};
    for (const auto& imp : crt_fn.import_calls) {
        if (imp.inst_index < cutoff && is_pe_crt_arg_setup_import(imp.name)) {
            last_arg_setup_idx = imp.inst_index;
        }
    }
    std::optional<std::uint64_t> chosen_user_va{};
    if (last_arg_setup_idx.has_value()) {
        for (const auto& call : crt_fn.internal_calls) {
            if (call.inst_index > *last_arg_setup_idx && call.inst_index < cutoff &&
                !call.is_tail_jump) {
                chosen_user_va = call.target_va;
                break;
            }
        }
    }

    // 3. Otherwise take the final internal `call` prior to `exit`/`_cexit`/`ExitProcess`
    //    (or final internal call when CRT init hallmarks are present).
    if (!chosen_user_va.has_value()) {
        for (auto it = crt_fn.internal_calls.rbegin(); it != crt_fn.internal_calls.rend(); ++it) {
            if (it->inst_index < cutoff && !it->is_tail_jump) {
                chosen_user_va = it->target_va;
                break;
            }
        }
    }
    if (!chosen_user_va.has_value()) {
        return std::nullopt;
    }

    const auto user_scan = scan_pe_startup_function(image, disasm, *chosen_user_va, 128u);
    return RecoveredPeStartupFlow{
        .crt_va = crt_fn.start_va,
        .crt_size = std::max<std::uint64_t>(1u, crt_fn.byte_size),
        .invoke_main_va = std::nullopt,
        .user_entry_va = *chosen_user_va,
        .user_entry_size = user_scan.has_value()
                               ? std::max<std::uint64_t>(1u, user_scan->byte_size)
                               : 1u,
        .entry_tail_jumped_to_crt = entry_tail_jumped,
    };
}

[[nodiscard]] std::optional<RecoveredPeStartupFlow> recover_pe_crt_startup_flow(
    const peelf::IBinaryImage& image) {
    if (image.format() != peelf::Format::PE) {
        return std::nullopt;
    }
    if (image.architecture() != peelf::Architecture::X86 &&
        image.architecture() != peelf::Architecture::X86_64) {
        return std::nullopt;
    }

    Disassembler disasm{};
    const Architecture cs_arch =
        image.architecture() == peelf::Architecture::X86_64 ? Architecture::X86_64 : Architecture::X86_32;
    if (!disasm.init(cs_arch, Endianness::Little)) {
        return std::nullopt;
    }

    const std::uint64_t entry_va = image.entry_point();
    const auto entry_scan = scan_pe_startup_function(image, disasm, entry_va);
    if (!entry_scan.has_value()) {
        return std::nullopt;
    }

    // Hop 1..2: inspect internal targets called/tail-jumped from `entry_point_va` (preferring
    // the final call/tail-jump such as `__scrt_common_main_seh` over `__security_init_cookie`).
    std::size_t inspected = 0u;
    for (auto it = entry_scan->internal_calls.rbegin();
         it != entry_scan->internal_calls.rend() && inspected < 4u;
         ++it, ++inspected) {
        const auto hop1 = scan_pe_startup_function(image, disasm, it->target_va);
        if (!hop1.has_value()) {
            continue;
        }
        if (auto recovered = select_user_entry_from_crt_candidate(
                image, disasm, *hop1, it->is_tail_jump);
            recovered.has_value()) {
            return recovered;
        }
    }

    // Hop 0: inlined CRT startup directly at `entry_point_va`.
    return select_user_entry_from_crt_candidate(image, disasm, *entry_scan, false);
}

} // namespace

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
        const std::optional<RecoveredPeStartupFlow> recovered_flow =
            (crt_record == nullptr || user_entry_record == nullptr)
                ? recover_pe_crt_startup_flow(image)
                : std::nullopt;

        if (crt_record != nullptr) {
            graph.nodes.push_back(CallGraphNode{
                .id = "crt_startup",
                .label = crt_record->name,
                .kind = CallGraphNodeKind::Function,
                .bytes = GraphByteRange{
                    .start = GraphAddress{
                        .virtual_address = crt_record->virtual_address,
                        .file_offset = crt_record->file_offset,
                    },
                    .size = crt_record->size,
                },
                .symbol = graph_ref_from_record(crt_record),
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = entry_id,
                .to_node_id = "crt_startup",
                .kind = CallGraphEdgeKind::DirectCall,
                .label = "startup symbol",
            });
        } else if (recovered_flow.has_value()) {
            const std::uint64_t crt_va = recovered_flow->crt_va;
            const std::optional<std::uint64_t> crt_rva =
                crt_va >= image.image_base()
                    ? std::optional<std::uint64_t>{crt_va - image.image_base()}
                    : std::nullopt;
            std::string crt_label = crt_va == entry_va
                ? ("CRT startup (inlined)\n" + format_hex(crt_va))
                : ("CRT startup\n__scrt_common_main_seh\n" + format_hex(crt_va));
            if (recovered_flow->invoke_main_va.has_value()) {
                crt_label += "\nvia invoke_main " + format_hex(*recovered_flow->invoke_main_va);
            }
            graph.nodes.push_back(CallGraphNode{
                .id = "crt_startup",
                .label = std::move(crt_label),
                .kind = CallGraphNodeKind::Function,
                .bytes = GraphByteRange{
                    .start = GraphAddress{
                        .virtual_address = crt_va,
                        .relative_virtual_address = crt_rva,
                        .file_offset = image.virtual_address_to_file_offset(crt_va),
                    },
                    .size = recovered_flow->crt_size,
                },
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = entry_id,
                .to_node_id = "crt_startup",
                .kind = CallGraphEdgeKind::DirectCall,
                .label = crt_va == entry_va
                             ? "inlined CRT startup"
                             : (recovered_flow->entry_tail_jumped_to_crt ? "startup tail-jump" : "startup call"),
            });
        } else {
            graph.nodes.push_back(CallGraphNode{
                .id = "crt_startup",
                .label = "CRT startup\nmainCRTStartup / WinMainCRTStartup\nunresolved",
                .kind = CallGraphNodeKind::Unknown,
                .bytes = {},
                .symbol = std::nullopt,
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = entry_id,
                .to_node_id = "crt_startup",
                .kind = CallGraphEdgeKind::Unknown,
                .label = "startup recovery pending",
            });
        }

        if (user_entry_record != nullptr) {
            graph.nodes.push_back(node_from_record(*user_entry_record, "user_entry"));
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = "crt_startup",
                .to_node_id = "user_entry",
                .kind = CallGraphEdgeKind::DirectCall,
                .label = "user entry symbol",
            });
        } else if (recovered_flow.has_value()) {
            const std::uint64_t user_va = recovered_flow->user_entry_va;
            const std::optional<std::uint64_t> user_rva =
                user_va >= image.image_base()
                    ? std::optional<std::uint64_t>{user_va - image.image_base()}
                    : std::nullopt;
            const bool is_gui = image.pe_header() != nullptr && image.pe_header()->subsystem == 2u;
            const char* entry_stem = is_gui ? "WinMain" : "main";
            const SymbolRecord* sym_at_user = symbol_index.find_containing_address(user_va);
            const bool exact_sym = sym_at_user != nullptr &&
                                   sym_at_user->virtual_address.has_value() &&
                                   *sym_at_user->virtual_address == user_va &&
                                   sym_at_user->source != SymbolSource::EntryPoint;
            std::string user_label = exact_sym
                ? sym_at_user->name
                : (std::string(entry_stem) + " (recovered)\n" + format_hex(user_va));
            graph.nodes.push_back(CallGraphNode{
                .id = "user_entry",
                .label = std::move(user_label),
                .kind = CallGraphNodeKind::Function,
                .bytes = GraphByteRange{
                    .start = GraphAddress{
                        .virtual_address = user_va,
                        .relative_virtual_address = user_rva,
                        .file_offset = image.virtual_address_to_file_offset(user_va),
                    },
                    .size = recovered_flow->user_entry_size,
                },
                .symbol = exact_sym ? graph_ref_from_record(sym_at_user) : std::nullopt,
            });
            add_edge_if_missing(graph, CallGraphEdge{
                .from_node_id = "crt_startup",
                .to_node_id = "user_entry",
                .kind = CallGraphEdgeKind::DirectCall,
                .label = recovered_flow->invoke_main_va.has_value()
                             ? "CRT invoke_main -> user entry"
                             : "CRT -> user entry",
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

std::optional<GraphSymbolRef> find_symbol_for_address(const peelf::IBinaryImage& image,
                                                       std::uint64_t virtual_address) {
    const std::vector<peelf::Symbol>& symbols = image.symbols();
    for (std::uint64_t index = 0; index < symbols.size(); ++index) {
        const peelf::Symbol& symbol = symbols[static_cast<std::size_t>(index)];
        const std::uint64_t symbol_size = std::max<std::uint64_t>(symbol.size, 1);
        if (virtual_address >= symbol.virtual_address && virtual_address - symbol.virtual_address < symbol_size) {
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

const SymbolRecord* resolve_call_target_for_address(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> image_bytes,
    const SymbolIndex& symbol_index,
    std::uint64_t target_virtual_address) {
    const GraphByteReader reader = [image_bytes](std::uint64_t offset, std::size_t size) {
        if (offset >= image_bytes.size() || size == 0u) {
            return std::vector<std::uint8_t>{};
        }
        const std::size_t avail = std::min<std::size_t>(
            size, static_cast<std::size_t>(image_bytes.size() - offset));
        return std::vector<std::uint8_t>(
            image_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            image_bytes.begin() + static_cast<std::ptrdiff_t>(offset + avail));
    };
    const std::optional<Architecture> arch = to_disassembler_architecture(image.architecture());
    if (!arch) {
        return symbol_index.find_containing_address(target_virtual_address);
    }
    Disassembler disasm{};
    if (!disasm.init(*arch, to_disassembler_endianness(image.endianness()))) {
        return symbol_index.find_containing_address(target_virtual_address);
    }
    return resolve_call_target_symbol(
        image, reader, disasm, symbol_index, target_virtual_address);
}

} // namespace viewer
