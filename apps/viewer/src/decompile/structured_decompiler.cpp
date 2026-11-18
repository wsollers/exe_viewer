#include "decompile/structured_decompiler.hpp"

#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace viewer {
namespace {

constexpr std::string_view kStructuredProvider = "Built-in Structured Pseudo-C";
constexpr std::string_view kRetDecProvider = "RetDec";

[[nodiscard]] bool is_64bit_arch(peelf::Architecture arch) noexcept {
    switch (arch) {
        case peelf::Architecture::X86_64:
        case peelf::Architecture::ARM64:
        case peelf::Architecture::RISCV64:
        case peelf::Architecture::PowerPC64:
        case peelf::Architecture::MIPS64:
            return true;
        case peelf::Architecture::X86:
        case peelf::Architecture::ARM:
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::Unknown:
            return false;
    }
    return false;
}

[[nodiscard]] std::uint64_t default_insn_size(peelf::Architecture arch, bool thumb) noexcept {
    switch (arch) {
        case peelf::Architecture::X86:
        case peelf::Architecture::X86_64:
            return 1u;
        case peelf::Architecture::ARM:
            return thumb ? 2u : 4u;
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:
            return 2u;
        case peelf::Architecture::ARM64:
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64:
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64:
        case peelf::Architecture::Unknown:
            return 4u;
    }
    return 4u;
}

[[nodiscard]] std::string_view trim_sv(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) {
        s.remove_prefix(1u);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) {
        s.remove_suffix(1u);
    }
    return s;
}

[[nodiscard]] std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char ch : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] std::string escape_c_string(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 4u);
    for (const char ch : text) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': break;
            case '\t': out += "\\t"; break;
            default:   out.push_back(ch); break;
        }
    }
    return out;
}

struct ResolvedSymbol {
    std::string raw_name;
    std::string c_ident;
    std::string library_comment;
    SymbolSource source{SymbolSource::ImageSymbol};
    bool is_function{false};
};

[[nodiscard]] std::string sanitize_c_identifier(std::string_view raw, std::string_view fallback = "sym") {
    // Strip library! prefix and @version / @plt suffixes for identifier portion.
    if (const std::size_t bang = raw.rfind('!'); bang != std::string_view::npos && bang + 1u < raw.size()) {
        raw = raw.substr(bang + 1u);
    }
    if (const std::size_t at = raw.find('@'); at != std::string_view::npos && at > 0u) {
        // Handle MSVC ?name@class@@ mangling vs ELF sym@plt / sym@@GLIBC.
        if (raw.front() == '?') {
            raw.remove_prefix(1u);
            const std::size_t msvc_at = raw.find('@');
            if (msvc_at != std::string_view::npos && msvc_at > 0u) {
                raw = raw.substr(0u, msvc_at);
            }
        } else {
            raw = raw.substr(0u, at);
        }
    }
    if (raw.starts_with('#') && raw.size() > 1u) {
        std::string ord_name = "ord_";
        ord_name.append(raw.substr(1u));
        return sanitize_c_identifier(ord_name, fallback);
    }

    std::string ident;
    ident.reserve(raw.size() + 2u);
    bool prev_underscore = false;
    for (const char ch : raw) {
        const auto uch = static_cast<unsigned char>(ch);
        if (std::isalnum(uch) != 0 || ch == '_') {
            ident.push_back(ch);
            prev_underscore = (ch == '_');
        } else if (!prev_underscore && !ident.empty()) {
            ident.push_back('_');
            prev_underscore = true;
        }
    }
    while (!ident.empty() && ident.back() == '_') {
        ident.pop_back();
    }
    if (ident.empty()) {
        ident = std::string(fallback);
    }
    if (std::isdigit(static_cast<unsigned char>(ident.front())) != 0) {
        ident.insert(ident.begin(), '_');
    }
    // Avoid C keywords gently.
    if (ident == "return" || ident == "if" || ident == "else" || ident == "while" ||
        ident == "for" || ident == "do" || ident == "switch" || ident == "case" ||
        ident == "default" || ident == "goto" || ident == "break" || ident == "continue" ||
        ident == "int" || ident == "void" || ident == "char" || ident == "long" ||
        ident == "register" || ident == "auto" || ident == "static" || ident == "struct") {
        ident += "_fn";
    }
    return ident;
}

[[nodiscard]] std::uint8_t symbol_source_rank(SymbolSource s) noexcept {
    switch (s) {
        case SymbolSource::DebugSymbol: return 0u;
        case SymbolSource::Import:      return 1u;
        case SymbolSource::ImageSymbol: return 2u;
        case SymbolSource::Export:      return 3u;
        case SymbolSource::EntryPoint:  return 4u;
    }
    return 5u;
}

[[nodiscard]] std::map<std::uint64_t, ResolvedSymbol> build_symbol_table(
    const std::vector<SymbolRecord>& records,
    peelf::Architecture arch) {
    std::map<std::uint64_t, ResolvedSymbol> table;
    for (const SymbolRecord& rec : records) {
        if (!rec.virtual_address.has_value() || rec.name.empty()) {
            continue;
        }
        std::uint64_t va = *rec.virtual_address;
        if (arch == peelf::Architecture::ARM && rec.function.value_or(false)) {
            va &= ~std::uint64_t{1u};
        }
        std::string lib_comment;
        if (rec.name.find('!') != std::string::npos) {
            lib_comment = rec.name;
        } else if (!rec.library.empty()) {
            lib_comment = rec.library + "!" + rec.name;
        }
        ResolvedSymbol resolved{
            .raw_name = rec.name,
            .c_ident = sanitize_c_identifier(rec.name, std::format("sub_{:X}", va)),
            .library_comment = std::move(lib_comment),
            .source = rec.source,
            .is_function = rec.function.value_or(rec.source == SymbolSource::Import || rec.source == SymbolSource::Export),
        };
        auto [it, inserted] = table.try_emplace(va, std::move(resolved));
        if (!inserted) {
            const bool cur_generic = it->second.raw_name == "Entry Point" || it->second.raw_name.starts_with("sub_");
            const bool cand_generic = rec.name == "Entry Point" || rec.name.starts_with("sub_");
            if ((cur_generic && !cand_generic) ||
                (cur_generic == cand_generic &&
                 symbol_source_rank(rec.source) < symbol_source_rank(it->second.source))) {
                it->second = ResolvedSymbol{
                    .raw_name = rec.name,
                    .c_ident = sanitize_c_identifier(rec.name, std::format("sub_{:X}", va)),
                    .library_comment = rec.name.find('!') != std::string::npos
                                           ? rec.name
                                           : (!rec.library.empty() ? rec.library + "!" + rec.name : std::string{}),
                    .source = rec.source,
                    .is_function = rec.function.value_or(it->second.is_function),
                };
            }
        }
        // If ARM Thumb symbol had bit 0 set, also register exact raw VA.
        if (*rec.virtual_address != va && !table.contains(*rec.virtual_address)) {
            table.emplace(*rec.virtual_address, table.at(va));
        }
    }
    return table;
}

[[nodiscard]] std::vector<std::string> split_operands(std::string_view operands) {
    std::vector<std::string> parts;
    std::string current;
    int bracket_depth = 0;
    int paren_depth = 0;
    int brace_depth = 0;

    for (const char ch : operands) {
        if (ch == '[') {
            ++bracket_depth;
        } else if (ch == ']' && bracket_depth > 0) {
            --bracket_depth;
        } else if (ch == '(') {
            ++paren_depth;
        } else if (ch == ')' && paren_depth > 0) {
            --paren_depth;
        } else if (ch == '{') {
            ++brace_depth;
        } else if (ch == '}' && brace_depth > 0) {
            --brace_depth;
        } else if (ch == ',' && bracket_depth == 0 && paren_depth == 0 && brace_depth == 0) {
            const std::string_view trimmed = trim_sv(current);
            if (!trimmed.empty()) {
                parts.emplace_back(trimmed);
            }
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    const std::string_view tail = trim_sv(current);
    if (!tail.empty()) {
        parts.emplace_back(tail);
    }
    return parts;
}

[[nodiscard]] std::optional<std::int64_t> parse_signed_int(std::string_view text) noexcept {
    text = trim_sv(text);
    if (text.starts_with('#')) {
        text.remove_prefix(1u);
        text = trim_sv(text);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    bool negative = false;
    if (text.front() == '-') {
        negative = true;
        text.remove_prefix(1u);
    } else if (text.front() == '+') {
        text.remove_prefix(1u);
    }
    text = trim_sv(text);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        base = 16;
        text.remove_prefix(2u);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t mag = 0u;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), mag, base);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    if (negative) {
        constexpr std::uint64_t kMaxNegMag =
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL;
        if (mag > kMaxNegMag) {
            return std::nullopt;
        }
        if (mag == kMaxNegMag) {
            return std::numeric_limits<std::int64_t>::min();
        }
        return -static_cast<std::int64_t>(mag);
    }
    return static_cast<std::int64_t>(mag);
}

[[nodiscard]] std::optional<std::uint64_t> parse_unsigned_addr(std::string_view text) noexcept {
    text = trim_sv(text);
    if (text.starts_with('#')) {
        text.remove_prefix(1u);
        text = trim_sv(text);
    }
    if (text.empty() || text.front() == '-') {
        return std::nullopt;
    }
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        base = 16;
        text.remove_prefix(2u);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0u;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::string clean_atom(std::string_view op) {
    op = trim_sv(op);
    if (op.starts_with('#')) {
        op.remove_prefix(1u);
        op = trim_sv(op);
    }
    if (op.starts_with('$') && op.size() > 1u) {
        op.remove_prefix(1u);
    }
    if (op == "xzr" || op == "wzr" || op == "zero" || op == "r0_zero") {
        return "0";
    }
    return std::string(op);
}

[[nodiscard]] bool is_zero_register(std::string_view op, peelf::Architecture arch) noexcept {
    op = trim_sv(op);
    if (op.starts_with('$')) {
        op.remove_prefix(1u);
    }
    if (op == "xzr" || op == "wzr" || op == "zero") {
        return true;
    }
    if ((arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) && op == "x0") {
        return true;
    }
    if ((arch == peelf::Architecture::MIPS32 || arch == peelf::Architecture::MIPS64) && op == "0") {
        return true;
    }
    return false;
}

[[nodiscard]] bool is_memory_operand(std::string_view op) noexcept {
    op = trim_sv(op);
    if (op.find('[') != std::string_view::npos && op.find(']') != std::string_view::npos) {
        return true;
    }
    const std::size_t lp = op.find('(');
    const std::size_t rp = op.find(')');
    return lp != std::string_view::npos && rp != std::string_view::npos && rp > lp;
}

[[nodiscard]] std::optional<std::uint64_t> extract_rip_target(
    std::string_view expr,
    std::uint64_t insn_addr,
    std::uint64_t insn_size) {
    const std::size_t lb = expr.find('[');
    const std::size_t rb = expr.find(']');
    if (lb == std::string_view::npos || rb == std::string_view::npos || rb <= lb) {
        return std::nullopt;
    }
    const std::string_view inside = trim_sv(expr.substr(lb + 1u, rb - lb - 1u));
    const std::string lower = to_lower_ascii(inside);
    std::size_t pc_pos = lower.find("rip");
    bool is_eip = false;
    if (pc_pos == std::string::npos) {
        pc_pos = lower.find("eip");
        is_eip = (pc_pos != std::string::npos);
    }
    if (pc_pos == std::string::npos) {
        return std::nullopt;
    }
    const std::string_view rest = trim_sv(inside.substr(pc_pos + 3u));
    if (is_eip) {
        const std::uint64_t next_pc = (insn_addr + insn_size) & 0xFFFF'FFFFULL;
        if (rest.empty()) {
            return next_pc;
        }
        if (rest.front() != '+' && rest.front() != '-') {
            return std::nullopt;
        }
        const bool neg = rest.front() == '-';
        const auto disp = parse_signed_int(rest.substr(1u));
        if (!disp.has_value()) {
            return std::nullopt;
        }
        const std::uint64_t udisp = peelf::unsigned_magnitude_of_signed(*disp);
        const bool eff_neg = neg != (*disp < 0);
        return (eff_neg ? (next_pc - udisp) : (next_pc + udisp)) & 0xFFFF'FFFFULL;
    }

    const auto next_pc = peelf::checked_add_u64(insn_addr, insn_size);
    if (!next_pc.has_value()) {
        return std::nullopt;
    }
    if (rest.empty()) {
        return *next_pc;
    }
    if (rest.front() != '+' && rest.front() != '-') {
        return std::nullopt;
    }
    const bool neg = rest.front() == '-';
    const auto disp = parse_signed_int(rest.substr(1u));
    if (!disp.has_value()) {
        return std::nullopt;
    }
    const std::uint64_t udisp = peelf::unsigned_magnitude_of_signed(*disp);
    const bool eff_neg = neg != (*disp < 0);
    if (eff_neg) {
        if (udisp > *next_pc) {
            return std::nullopt;
        }
        return *next_pc - udisp;
    }
    return peelf::checked_add_u64(*next_pc, udisp);
}

[[nodiscard]] std::string pointer_width_c_type(
    std::string_view mem_operand,
    std::string_view mnemonic,
    bool arch_64) {
    const std::string lower_op = to_lower_ascii(mem_operand);
    if (lower_op.find("byte ptr") != std::string::npos) {
        return "uint8_t";
    }
    if (lower_op.find("xmmword ptr") != std::string::npos) {
        return "__uint128_t";
    }
    if (lower_op.find("qword ptr") != std::string::npos) {
        return "uint64_t";
    }
    if (lower_op.find("dword ptr") != std::string::npos) {
        return "uint32_t";
    }
    if (lower_op.find("word ptr") != std::string::npos) {
        return "uint16_t";
    }

    if (mnemonic == "ldrb" || mnemonic == "strb" || mnemonic == "lb" || mnemonic == "lbu" ||
        mnemonic == "sb" || mnemonic == "lbz" || mnemonic == "stb") {
        return "uint8_t";
    }
    if (mnemonic == "ldrsb") {
        return "int8_t";
    }
    if (mnemonic == "ldrh" || mnemonic == "strh" || mnemonic == "lh" || mnemonic == "lhu" ||
        mnemonic == "sh" || mnemonic == "lhz" || mnemonic == "sth") {
        return "uint16_t";
    }
    if (mnemonic == "ldrsh" || mnemonic == "lha") {
        return "int16_t";
    }
    if (mnemonic == "ldrsw" || mnemonic == "lwa") {
        return "int32_t";
    }
    if (mnemonic == "lw" || mnemonic == "lwu" || mnemonic == "sw" || mnemonic == "lwz" ||
        mnemonic == "stw" || mnemonic == "stwu" || mnemonic == "c.lw" || mnemonic == "c.sw" ||
        mnemonic == "c.lwsp" || mnemonic == "c.swsp") {
        return "uint32_t";
    }
    if (mnemonic == "ld" || mnemonic == "sd" || mnemonic == "std" || mnemonic == "stdu" ||
        mnemonic == "c.ld" || mnemonic == "c.sd" || mnemonic == "c.ldsp" || mnemonic == "c.sdsp") {
        return "uint64_t";
    }
    return arch_64 ? "uint64_t" : "uint32_t";
}

[[nodiscard]] std::optional<std::string> try_stack_variable(
    std::string_view inside_addr,
    std::set<std::string>& stack_locals) {
    inside_addr = trim_sv(inside_addr);
    // Forms: "rbp - 0x10", "ebp - 8", "rsp + 0x20", "x29, #-16", "fp, #-8", "sp, #0x10"
    auto try_base_offset = [&](std::string_view base, std::int64_t offset) -> std::optional<std::string> {
        const std::string b = to_lower_ascii(clean_atom(base));
        const bool is_frame = (b == "rbp" || b == "ebp" || b == "x29" || b == "fp" || b == "s0" || b == "r31");
        const bool is_sp = (b == "rsp" || b == "esp" || b == "sp" || b == "r1");
        if (!is_frame && !is_sp) {
            return std::nullopt;
        }
        const std::uint64_t mag = peelf::unsigned_magnitude_of_signed(offset);
        if (mag > 0x10000ULL) {
            return std::nullopt;
        }
        std::string var_name;
        if (is_frame && offset < 0) {
            var_name = std::format("stack_var_{:X}", mag);
        } else if (is_frame && offset >= 0) {
            var_name = std::format("stack_arg_{:X}", mag);
        } else {
            var_name = std::format("stack_slot_{:X}", mag);
        }
        stack_locals.insert(var_name);
        return var_name;
    };

    // Comma form: "x29, #-16" or "sp, #0x18" or "sp"
    if (const std::size_t comma = inside_addr.find(','); comma != std::string_view::npos) {
        const std::string_view base = trim_sv(inside_addr.substr(0u, comma));
        const std::string_view disp = trim_sv(inside_addr.substr(comma + 1u));
        if (const auto off = parse_signed_int(disp)) {
            return try_base_offset(base, *off);
        }
        return std::nullopt;
    }

    // Plus / minus form without index register: "rbp - 0x14" or "rsp + 0x20"
    if (inside_addr.find('*') == std::string_view::npos) {
        std::size_t op_pos = inside_addr.find('+');
        bool neg = false;
        if (op_pos == std::string_view::npos) {
            op_pos = inside_addr.find('-');
            neg = (op_pos != std::string_view::npos);
        }
        if (op_pos != std::string_view::npos && op_pos > 0u) {
            const std::string_view base = trim_sv(inside_addr.substr(0u, op_pos));
            const std::string_view disp = trim_sv(inside_addr.substr(op_pos + 1u));
            if (const auto off = parse_signed_int(disp)) {
                if (neg && *off == std::numeric_limits<std::int64_t>::min()) {
                    return std::nullopt;
                }
                return try_base_offset(base, neg ? -*off : *off);
            }
        } else {
            return try_base_offset(inside_addr, 0);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::string format_effective_address(std::string_view raw_inside) {
    raw_inside = trim_sv(raw_inside);
    if (const std::size_t comma = raw_inside.find(','); comma != std::string_view::npos) {
        std::string base = clean_atom(raw_inside.substr(0u, comma));
        const std::string rest = clean_atom(raw_inside.substr(comma + 1u));
        if (rest.empty() || rest == "0" || rest == "0x0") {
            return base;
        }
        if (rest.starts_with('-')) {
            return std::format("{} - {}", base, trim_sv(std::string_view(rest).substr(1u)));
        }
        return std::format("{} + {}", base, rest);
    }
    return clean_atom(raw_inside);
}

[[nodiscard]] std::string format_memory_access(
    std::string_view op,
    std::string_view mnemonic,
    std::uint64_t insn_addr,
    std::uint64_t insn_size,
    bool arch_64,
    const std::map<std::uint64_t, ResolvedSymbol>& symbols,
    std::set<std::string>& stack_locals,
    bool address_only = false) {
    op = trim_sv(op);

    // RIP-relative memory operand on x86/x86-64.
    if (const auto rip_va = extract_rip_target(op, insn_addr, insn_size)) {
        if (const auto it = symbols.find(*rip_va); it != symbols.end()) {
            if (address_only) {
                return std::format("&{} /* 0x{:X} */", it->second.c_ident, *rip_va);
            }
            return it->second.c_ident;
        }
        if (address_only) {
            return std::format("0x{:X}", *rip_va);
        }
        const std::string ctype = pointer_width_c_type(op, mnemonic, arch_64);
        return std::format("*({}*)0x{:X}", ctype, *rip_va);
    }

    // Bracket syntax: [base + disp] or [x29, #-16]!
    if (const std::size_t lb = op.find('['); lb != std::string_view::npos) {
        const std::size_t rb = op.find(']', lb);
        if (rb != std::string_view::npos) {
            const std::string_view inside = op.substr(lb + 1u, rb - lb - 1u);
            if (!address_only) {
                if (const auto stack_var = try_stack_variable(inside, stack_locals)) {
                    return *stack_var;
                }
            } else if (const auto stack_var = try_stack_variable(inside, stack_locals)) {
                return "&" + *stack_var;
            }
            std::string addr_expr = format_effective_address(inside);
            if (address_only) {
                return addr_expr;
            }
            const std::string ctype = pointer_width_c_type(op, mnemonic, arch_64);
            return std::format("*({}*)({})", ctype, addr_expr);
        }
    }

    // Parenthesis syntax (RISC-V / MIPS / PowerPC): -16(s0), 0x10($sp), 8(r3)
    if (const std::size_t lp = op.find('('); lp != std::string_view::npos) {
        const std::size_t rp = op.find(')', lp);
        if (rp != std::string_view::npos) {
            const std::string_view disp_sv = trim_sv(op.substr(0u, lp));
            const std::string_view base_sv = trim_sv(op.substr(lp + 1u, rp - lp - 1u));
            const std::int64_t disp = disp_sv.empty() ? 0 : parse_signed_int(disp_sv).value_or(0);
            std::string combined =
                disp < 0
                    ? std::format("{} - 0x{:X}", clean_atom(base_sv), peelf::unsigned_magnitude_of_signed(disp))
                    : (disp > 0 ? std::format("{} + 0x{:X}", clean_atom(base_sv), static_cast<std::uint64_t>(disp))
                                : clean_atom(base_sv));
            if (const auto stack_var = try_stack_variable(combined, stack_locals)) {
                return address_only ? ("&" + *stack_var) : *stack_var;
            }
            if (address_only) {
                return combined;
            }
            const std::string ctype = pointer_width_c_type(op, mnemonic, arch_64);
            return std::format("*({}*)({})", ctype, combined);
        }
    }

    return clean_atom(op);
}

[[nodiscard]] std::optional<std::string> extract_memory_index_expr(std::string_view op) {
    const std::size_t lb = op.find('[');
    const std::size_t rb = op.find(']', lb == std::string_view::npos ? 0u : lb);
    if (lb == std::string_view::npos || rb == std::string_view::npos || rb <= lb) {
        return std::nullopt;
    }
    const std::string_view inside = trim_sv(op.substr(lb + 1u, rb - lb - 1u));
    if (inside.empty()) {
        return std::nullopt;
    }

    // Scaled index form: `[eax*4 + 0x1020]`, `[rcx + rax*4]`, `[4*rax + rcx]`
    if (inside.find('*') != std::string_view::npos) {
        std::size_t start = 0u;
        while (start < inside.size()) {
            std::size_t end = start;
            while (end < inside.size() && inside[end] != '+' && inside[end] != '-') {
                ++end;
            }
            const std::string_view term = trim_sv(inside.substr(start, end - start));
            if (const std::size_t star = term.find('*'); star != std::string_view::npos) {
                const std::string_view lhs_raw = trim_sv(term.substr(0u, star));
                const std::string_view rhs_raw = trim_sv(term.substr(star + 1u));
                if (parse_signed_int(rhs_raw).has_value() && !parse_signed_int(lhs_raw).has_value()) {
                    std::string idx = clean_atom(lhs_raw);
                    if (!idx.empty()) {
                        return idx;
                    }
                } else if (parse_signed_int(lhs_raw).has_value() && !parse_signed_int(rhs_raw).has_value()) {
                    std::string idx = clean_atom(rhs_raw);
                    if (!idx.empty()) {
                        return idx;
                    }
                }
            }
            start = end + 1u;
        }
    }

    // Comma-indexed form: `[pc, r0]`, `[pc, r0, lsl #1]`, `[x8, w0, uxtw #2]`
    if (const std::size_t comma = inside.find(','); comma != std::string_view::npos) {
        const std::string_view after_base = trim_sv(inside.substr(comma + 1u));
        const std::size_t comma2 = after_base.find(',');
        const std::string_view second_part =
            trim_sv(comma2 == std::string_view::npos ? after_base : after_base.substr(0u, comma2));
        if (!second_part.empty() && !parse_signed_int(second_part).has_value()) {
            std::string idx = clean_atom(second_part);
            if (!idx.empty()) {
                return idx;
            }
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::string format_value_expr(
    std::string_view op,
    std::string_view mnemonic,
    std::uint64_t insn_addr,
    std::uint64_t insn_size,
    peelf::Architecture arch,
    const std::map<std::uint64_t, ResolvedSymbol>& symbols,
    std::set<std::string>& stack_locals) {
    if (is_zero_register(op, arch)) {
        return "0";
    }
    if (is_memory_operand(op)) {
        return format_memory_access(
            op, mnemonic, insn_addr, insn_size, is_64bit_arch(arch), symbols, stack_locals, false);
    }
    std::string atom = clean_atom(op);
    if (const auto addr = parse_unsigned_addr(atom); addr.has_value() && *addr >= 0x1000u) {
        if (const auto it = symbols.find(*addr); it != symbols.end()) {
            return std::format("&{} /* 0x{:X} */", it->second.c_ident, *addr);
        }
    }
    return atom;
}

[[nodiscard]] std::string canonical_reg_family(std::string_view reg, peelf::Architecture arch) {
    std::string r = to_lower_ascii(clean_atom(reg));
    if (arch == peelf::Architecture::X86_64 || arch == peelf::Architecture::X86) {
        if (r == "rax" || r == "eax" || r == "ax" || r == "al") return arch == peelf::Architecture::X86_64 ? "rax" : "eax";
        if (r == "rbx" || r == "ebx" || r == "bx" || r == "bl") return arch == peelf::Architecture::X86_64 ? "rbx" : "ebx";
        if (r == "rcx" || r == "ecx" || r == "cx" || r == "cl") return arch == peelf::Architecture::X86_64 ? "rcx" : "ecx";
        if (r == "rdx" || r == "edx" || r == "dx" || r == "dl") return arch == peelf::Architecture::X86_64 ? "rdx" : "edx";
        if (r == "rsi" || r == "esi" || r == "si" || r == "sil") return arch == peelf::Architecture::X86_64 ? "rsi" : "esi";
        if (r == "rdi" || r == "edi" || r == "di" || r == "dil") return arch == peelf::Architecture::X86_64 ? "rdi" : "edi";
        if (r == "r8" || r == "r8d" || r == "r8w" || r == "r8b") return "r8";
        if (r == "r9" || r == "r9d" || r == "r9w" || r == "r9b") return "r9";
    } else if (arch == peelf::Architecture::ARM64) {
        if (r.size() >= 2u && r.front() == 'w' && std::isdigit(static_cast<unsigned char>(r[1u])) != 0) {
            r.front() = 'x';
        }
    }
    return r;
}

[[nodiscard]] std::string_view return_register_name(peelf::Architecture arch) noexcept {
    switch (arch) {
        case peelf::Architecture::X86_64:    return "rax";
        case peelf::Architecture::X86:       return "eax";
        case peelf::Architecture::ARM64:     return "x0";
        case peelf::Architecture::ARM:       return "r0";
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:   return "a0";
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64:    return "v0";
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64: return "r3";
        case peelf::Architecture::Unknown:   return "r0";
    }
    return "r0";
}

[[nodiscard]] bool is_known_void_callee(std::string_view ident) noexcept {
    return ident == "exit" || ident == "_exit" || ident == "abort" ||
           ident == "__stack_chk_fail" || ident == "ExitProcess" ||
           ident == "free" || ident == "puts" || ident == "perror";
}

[[nodiscard]] std::string normalize_mnemonic(std::string_view raw, peelf::Architecture arch) {
    std::string m = to_lower_ascii(trim_sv(raw));
    // Strip ARM Thumb width suffixes (.w / .n) without touching ARM64 b.eq.
    if (arch == peelf::Architecture::ARM) {
        if (m.ends_with(".w") || m.ends_with(".n")) {
            m.resize(m.size() - 2u);
        }
    }
    // Strip PowerPC branch prediction suffixes (+/-).
    if ((arch == peelf::Architecture::PowerPC || arch == peelf::Architecture::PowerPC64) &&
        !m.empty() && (m.back() == '+' || m.back() == '-')) {
        m.pop_back();
    }
    return m;
}

[[nodiscard]] bool is_prologue_or_epilogue_noise(
    std::string_view m,
    const std::vector<std::string>& ops,
    peelf::Architecture arch) {
    if (m == "nop" || m == "fnop" || m == "endbr64" || m == "endbr32" ||
        m == "hint" || m == "paciasp" || m == "autiasp" || m == "cldemote") {
        return true;
    }

    if (arch == peelf::Architecture::X86 || arch == peelf::Architecture::X86_64) {
        if (m == "leave") {
            return true;
        }
        if ((m == "push" || m == "pop") && ops.size() == 1u) {
            const std::string r = to_lower_ascii(clean_atom(ops[0]));
            if (r == "rbp" || r == "ebp") {
                return true;
            }
        }
        if (m == "mov" && ops.size() == 2u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            const std::string s = to_lower_ascii(clean_atom(ops[1]));
            if ((d == "rbp" && s == "rsp") || (d == "ebp" && s == "esp") ||
                (d == "rsp" && s == "rbp") || (d == "esp" && s == "ebp")) {
                return true;
            }
        }
        if ((m == "sub" || m == "add") && ops.size() == 2u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            if (d == "rsp" || d == "esp") {
                return true;
            }
        }
    }

    if (arch == peelf::Architecture::ARM64) {
        if ((m == "stp" || m == "ldp") && ops.size() >= 3u) {
            const std::string a = to_lower_ascii(clean_atom(ops[0]));
            const std::string b = to_lower_ascii(clean_atom(ops[1]));
            if ((a == "x29" || a == "fp") && (b == "x30" || b == "lr") &&
                to_lower_ascii(ops[2]).find("sp") != std::string::npos) {
                return true;
            }
        }
        if (m == "mov" && ops.size() == 2u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            const std::string s = to_lower_ascii(clean_atom(ops[1]));
            if ((d == "x29" || d == "fp") && s == "sp") {
                return true;
            }
        }
        if ((m == "sub" || m == "add") && ops.size() >= 3u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            const std::string s = to_lower_ascii(clean_atom(ops[1]));
            if (d == "sp" && s == "sp") {
                return true;
            }
        }
    }

    if (arch == peelf::Architecture::ARM) {
        if (m == "push" && !ops.empty() && ops[0].find("lr") != std::string::npos) {
            return true;
        }
        if ((m == "sub" || m == "add") && ops.size() >= 2u &&
            to_lower_ascii(clean_atom(ops[0])) == "sp") {
            return true;
        }
    }

    if (arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) {
        if (m == "c.addi16sp") {
            return true;
        }
        if ((m == "addi" || m == "c.addi") && ops.size() >= 2u &&
            to_lower_ascii(clean_atom(ops[0])) == "sp") {
            return true;
        }
        if ((m == "sd" || m == "ld" || m == "sw" || m == "lw" ||
             m == "c.sdsp" || m == "c.ldsp" || m == "c.swsp" || m == "c.lwsp") &&
            ops.size() == 2u) {
            const std::string r = to_lower_ascii(clean_atom(ops[0]));
            if ((r == "ra" || r == "s0" || r == "fp") &&
                to_lower_ascii(ops[1]).find("sp") != std::string::npos) {
                return true;
            }
        }
        if (m == "addi" && ops.size() == 3u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            const std::string s = to_lower_ascii(clean_atom(ops[1]));
            if ((d == "s0" || d == "fp") && s == "sp") {
                return true;
            }
        }
    }

    if (arch == peelf::Architecture::PowerPC || arch == peelf::Architecture::PowerPC64) {
        if (m == "mflr" || m == "mtlr") {
            return true;
        }
        if ((m == "stwu" || m == "stdu" || m == "addi") && !ops.empty() &&
            to_lower_ascii(clean_atom(ops[0])) == "r1") {
            return true;
        }
    }

    if (arch == peelf::Architecture::MIPS32 || arch == peelf::Architecture::MIPS64) {
        if ((m == "addiu" || m == "daddiu") && ops.size() >= 2u &&
            to_lower_ascii(clean_atom(ops[0])) == "sp") {
            return true;
        }
        if ((m == "sw" || m == "lw" || m == "sd" || m == "ld") && ops.size() == 2u) {
            const std::string r = to_lower_ascii(clean_atom(ops[0]));
            if ((r == "ra" || r == "fp" || r == "s8") &&
                to_lower_ascii(ops[1]).find("sp") != std::string::npos) {
                return true;
            }
        }
        if (m == "move" && ops.size() == 2u) {
            const std::string d = to_lower_ascii(clean_atom(ops[0]));
            const std::string s = to_lower_ascii(clean_atom(ops[1]));
            if ((d == "fp" && s == "sp") || (d == "sp" && s == "fp")) {
                return true;
            }
        }
    }

    return false;
}

struct FlagState {
    std::string lhs{"flags"};
    std::string rhs{"0"};
    bool valid{false};
};

[[nodiscard]] std::optional<std::string_view> condition_code_op(std::string_view cc) noexcept {
    if (cc == "e" || cc == "z" || cc == "eq") return "==";
    if (cc == "ne" || cc == "nz") return "!=";
    if (cc == "l" || cc == "lt" || cc == "nge" || cc == "mi") return "<";
    if (cc == "le" || cc == "ng") return "<=";
    if (cc == "g" || cc == "gt" || cc == "nle") return ">";
    if (cc == "ge" || cc == "nl" || cc == "pl") return ">=";
    if (cc == "b" || cc == "c" || cc == "nae" || cc == "lo" || cc == "cc" || cc == "ltu") return "<";
    if (cc == "be" || cc == "na" || cc == "ls") return "<=";
    if (cc == "a" || cc == "nbe" || cc == "hi") return ">";
    if (cc == "ae" || cc == "nb" || cc == "nc" || cc == "hs" || cc == "cs" || cc == "geu") return ">=";
    return std::nullopt;
}

[[nodiscard]] bool is_unsigned_cc(std::string_view cc) noexcept {
    return cc == "b" || cc == "c" || cc == "nae" || cc == "lo" || cc == "cc" ||
           cc == "be" || cc == "na" || cc == "ls" ||
           cc == "a" || cc == "nbe" || cc == "hi" ||
           cc == "ae" || cc == "nb" || cc == "nc" || cc == "hs" || cc == "cs" ||
           cc == "ltu" || cc == "geu";
}

[[nodiscard]] std::string build_flag_condition(
    std::string_view cc,
    const FlagState& flags,
    bool arch_64) {
    const auto rel = condition_code_op(cc);
    if (!rel.has_value()) {
        return std::format("__cond_{}({})", cc, flags.valid ? flags.lhs : "flags");
    }
    if (!flags.valid) {
        return std::format("flags {} 0", *rel);
    }
    if (is_unsigned_cc(cc) && flags.rhs != "0") {
        const std::string_view utype = arch_64 ? "uint64_t" : "uint32_t";
        return std::format("({}){} {} ({}){}", utype, flags.lhs, *rel, utype, flags.rhs);
    }
    return std::format("{} {} {}", flags.lhs, *rel, flags.rhs);
}

[[nodiscard]] std::string invert_condition(std::string_view cond) {
    cond = trim_sv(cond);
    struct Flip {
        std::string_view from;
        std::string_view to;
    };
    constexpr std::array<Flip, 6> kFlips{{
        {" == ", " != "},
        {" != ", " == "},
        {" <= ", " > "},
        {" >= ", " < "},
        {" < ",  " >= "},
        {" > ",  " <= "},
    }};
    // Only flip top-level simple comparisons without logical && / ||.
    if (cond.find("&&") == std::string_view::npos && cond.find("||") == std::string_view::npos) {
        for (const Flip& flip : kFlips) {
            if (const std::size_t pos = cond.find(flip.from); pos != std::string_view::npos) {
                std::string inverted;
                inverted.reserve(cond.size() + 2u);
                inverted.append(cond.substr(0u, pos));
                inverted.append(flip.to);
                inverted.append(cond.substr(pos + flip.from.size()));
                return inverted;
            }
        }
    }
    if (cond.starts_with("!(") && cond.ends_with(')')) {
        return std::string(cond.substr(2u, cond.size() - 3u));
    }
    return std::format("!({})", cond);
}

[[nodiscard]] std::string extract_branch_condition(
    std::string_view m,
    const std::vector<std::string>& ops,
    peelf::Architecture arch,
    const FlagState& flags) {
    const bool arch_64 = is_64bit_arch(arch);

    // Direct register-test branches (ARM/ARM64 cbz/cbnz/tbz/tbnz, RISC-V/MIPS beq/bne/blt/bge...).
    if ((m == "cbz" || m == "beqz" || m == "c.beqz") && !ops.empty()) {
        return std::format("{} == 0", clean_atom(ops[0]));
    }
    if ((m == "cbnz" || m == "bnez" || m == "c.bnez") && !ops.empty()) {
        return std::format("{} != 0", clean_atom(ops[0]));
    }
    if (m == "tbz" && ops.size() >= 2u) {
        return std::format("(({} >> {}) & 1) == 0", clean_atom(ops[0]), clean_atom(ops[1]));
    }
    if (m == "tbnz" && ops.size() >= 2u) {
        return std::format("(({} >> {}) & 1) != 0", clean_atom(ops[0]), clean_atom(ops[1]));
    }

    if (arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64 ||
        arch == peelf::Architecture::MIPS32 || arch == peelf::Architecture::MIPS64) {
        if ((m == "beq" || m == "bne" || m == "blt" || m == "bge" || m == "bltu" || m == "bgeu") &&
            ops.size() >= 3u) {
            const std::string lhs = is_zero_register(ops[0], arch) ? "0" : clean_atom(ops[0]);
            const std::string rhs = is_zero_register(ops[1], arch) ? "0" : clean_atom(ops[1]);
            const std::string_view cc = m.substr(1u);
            return build_flag_condition(cc, FlagState{lhs, rhs, true}, arch_64);
        }
        if (m == "blez" && !ops.empty()) return std::format("{} <= 0", clean_atom(ops[0]));
        if (m == "bgtz" && !ops.empty()) return std::format("{} > 0", clean_atom(ops[0]));
        if (m == "bltz" && !ops.empty()) return std::format("{} < 0", clean_atom(ops[0]));
        if (m == "bgez" && !ops.empty()) return std::format("{} >= 0", clean_atom(ops[0]));
    }

    if (m == "jrcxz" || m == "jecxz" || m == "jcxz") {
        return m == "jrcxz" ? "rcx == 0" : "ecx == 0";
    }
    if (m == "bdnz") {
        return "(--ctr) != 0";
    }
    if (m == "bdz") {
        return "(--ctr) == 0";
    }

    // ARM64 b.cc
    if (m.starts_with("b.") && m.size() > 2u) {
        return build_flag_condition(m.substr(2u), flags, arch_64);
    }
    // x86 jcc
    if (m.starts_with('j') && m.size() > 1u && m != "jmp" && m != "jr" && m != "jal" && m != "jalr") {
        return build_flag_condition(m.substr(1u), flags, arch_64);
    }
    // ARM / PowerPC b<cc>
    if (m.starts_with('b') && m.size() >= 3u && m != "blr" && m != "blrl" && m != "blx") {
        return build_flag_condition(m.substr(1u), flags, arch_64);
    }

    return flags.valid ? std::format("{} != {}", flags.lhs, flags.rhs) : "cond";
}

struct LiftedStmt {
    std::uint64_t address{0};
    std::uint64_t size{1};
    std::string code;
};

enum class TermKind : std::uint8_t {
    Fallthrough,
    Return,
    ConditionalReturn,
    Jump,
    CondBranch,
    Switch,
    TailOrExternal,
};

struct BlockIR {
    std::size_t index{0};
    std::string node_id;
    std::uint64_t start_va{0};
    std::uint64_t first_insn_size{1};
    std::vector<LiftedStmt> body;
    std::vector<CodeRange> all_ranges;
    TermKind term_kind{TermKind::Fallthrough};
    std::uint64_t term_addr{0};
    std::uint64_t term_size{1};
    std::string cond_expr;
    std::string return_stmt;
    std::string external_stmt;
    std::optional<std::size_t> taken_block;
    std::optional<std::size_t> fall_block;
    std::optional<std::size_t> jump_block;
    std::vector<std::pair<std::string, std::size_t>> switch_cases;
    FlagState out_flags{};
};

[[nodiscard]] bool is_call_mnemonic(std::string_view m, std::string_view ops, peelf::Architecture arch) noexcept {
    if (m == "call" || m == "bl" || m == "blx" || m == "blr_call" ||
        m == "bal" || m == "jalx" || m == "c.jal" || m == "c.jalr" ||
        m == "blrl" || m == "bctrl" || m == "bla") {
        return true;
    }
    if (arch == peelf::Architecture::ARM64 && m == "blr") {
        return true;
    }
    if (m == "jal" || m == "jalr") {
        const std::string_view trimmed = trim_sv(ops);
        const auto istarts_with = [](std::string_view sv, std::string_view lower_prefix) noexcept -> bool {
            if (sv.size() < lower_prefix.size()) return false;
            for (std::size_t i = 0; i < lower_prefix.size(); ++i) {
                const char c = (sv[i] >= 'A' && sv[i] <= 'Z') ? static_cast<char>(sv[i] - 'A' + 'a') : sv[i];
                if (c != lower_prefix[i]) return false;
            }
            return true;
        };
        if ((arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) &&
            (istarts_with(trimmed, "zero,") || istarts_with(trimmed, "x0,"))) {
            return false;
        }
        return true;
    }
    return false;
}

[[nodiscard]] bool is_return_mnemonic(std::string_view m, std::string_view ops, peelf::Architecture arch) noexcept {
    if (m == "ret" || m == "retn" || m == "retq") {
        return true;
    }
    if ((arch == peelf::Architecture::PowerPC || arch == peelf::Architecture::PowerPC64) && m == "blr") {
        return true;
    }
    if ((arch == peelf::Architecture::MIPS32 || arch == peelf::Architecture::MIPS64) &&
        m == "jr" && (ops.find("ra") != std::string_view::npos || ops.find("$31") != std::string_view::npos)) {
        return true;
    }
    if ((arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) &&
        m == "jr" && ops.find("ra") != std::string_view::npos) {
        return true;
    }
    if (arch == peelf::Architecture::ARM) {
        if (m == "bx" && trim_sv(ops) == "lr") {
            return true;
        }
        if ((m == "pop" || m == "ldm" || m == "ldmia") && ops.find("pc") != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string build_call_statement(
    const GraphInstruction& insn,
    std::uint64_t insn_size,
    const std::vector<std::string>& ops,
    peelf::Architecture arch,
    const std::map<std::uint64_t, ResolvedSymbol>& symbols,
    const std::map<std::string, std::uint64_t>& reg_const_va,
    const std::set<std::string>& block_written_regs,
    bool result_overwritten_or_unused,
    bool has_win_imports) {
    std::optional<std::uint64_t> callee_va = insn.branch_target;
    if (!callee_va.has_value() && !ops.empty()) {
        callee_va = extract_rip_target(ops[0], insn.address, insn_size);
    }
    if (!callee_va.has_value() && !ops.empty() && !is_memory_operand(ops[0])) {
        const std::string last_op = clean_atom(ops.back());
        callee_va = parse_unsigned_addr(last_op);
        if (!callee_va.has_value()) {
            if (const auto it = reg_const_va.find(canonical_reg_family(last_op, arch));
                it != reg_const_va.end()) {
                callee_va = it->second;
            }
        }
    }

    std::string callee_expr;
    std::string trailing_comment;
    bool is_void_fn = false;

    if (callee_va.has_value()) {
        const std::uint64_t lookup_va =
            arch == peelf::Architecture::ARM ? (*callee_va & ~std::uint64_t{1u}) : *callee_va;
        if (const auto it = symbols.find(lookup_va); it != symbols.end()) {
            callee_expr = it->second.c_ident;
            is_void_fn = is_known_void_callee(callee_expr);
            if (!it->second.library_comment.empty()) {
                trailing_comment = std::format(" /* {} */", it->second.library_comment);
            }
        } else {
            callee_expr = std::format("sub_{:X}", lookup_va);
        }
    } else if (!ops.empty()) {
        callee_expr = std::format("((fn_t)({}))", clean_atom(ops.back()));
    } else {
        callee_expr = "indirect_call";
    }

    // Collect ABI arguments written in the block prior to the call.
    std::vector<std::string_view> abi_regs;
    switch (arch) {
        case peelf::Architecture::X86_64: {
            const bool win64 =
                has_win_imports ||
                (block_written_regs.contains("rcx") && !block_written_regs.contains("rdi"));
            if (win64) {
                abi_regs = {"rcx", "rdx", "r8", "r9"};
            } else {
                abi_regs = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
            }
            break;
        }
        case peelf::Architecture::X86:
            abi_regs = {"ecx", "edx"};
            break;
        case peelf::Architecture::ARM64:
            abi_regs = {"x0", "x1", "x2", "x3"};
            break;
        case peelf::Architecture::ARM:
            abi_regs = {"r0", "r1", "r2", "r3"};
            break;
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64:
            abi_regs = {"a0", "a1", "a2", "a3"};
            break;
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64:
            abi_regs = {"r3", "r4", "r5", "r6"};
            break;
        case peelf::Architecture::Unknown:
            break;
    }

    std::size_t arg_count = 0u;
    for (std::size_t i = 0u; i < abi_regs.size(); ++i) {
        if (block_written_regs.contains(std::string(abi_regs[i]))) {
            arg_count = i + 1u;
        }
    }
    std::string arg_list;
    for (std::size_t i = 0u; i < arg_count; ++i) {
        if (i > 0u) {
            arg_list += ", ";
        }
        arg_list += abi_regs[i];
    }

    if (is_void_fn || result_overwritten_or_unused) {
        return std::format("{}({}){};", callee_expr, arg_list, trailing_comment);
    }
    return std::format("{} = {}({}){};", return_register_name(arch), callee_expr, arg_list, trailing_comment);
}

[[nodiscard]] std::optional<std::string> lift_general_instruction(
    const GraphInstruction& insn,
    std::uint64_t insn_size,
    peelf::Architecture arch,
    const std::map<std::uint64_t, ResolvedSymbol>& symbols,
    std::set<std::string>& stack_locals,
    std::map<std::string, std::uint64_t>& reg_const_va,
    std::set<std::string>& block_written_regs,
    std::set<std::string>& func_written_regs,
    FlagState& flags,
    bool call_result_unused,
    bool has_win_imports) {
    const std::string m = normalize_mnemonic(insn.mnemonic, arch);
    const std::vector<std::string> ops = split_operands(insn.operands);
    const bool arch_64 = is_64bit_arch(arch);
    const bool is_x86 = (arch == peelf::Architecture::X86 || arch == peelf::Architecture::X86_64);

    if (is_prologue_or_epilogue_noise(m, ops, arch)) {
        if ((is_x86 && (m == "add" || m == "sub")) || m == "adds" || m == "subs") {
            flags = FlagState{};
        }
        return std::nullopt;
    }

    auto mark_write = [&](std::string_view dst_op) {
        if (!is_memory_operand(dst_op) && !is_zero_register(dst_op, arch)) {
            const std::string fam = canonical_reg_family(dst_op, arch);
            block_written_regs.insert(fam);
            func_written_regs.insert(fam);
            reg_const_va.erase(fam);
        }
    };

    auto val_expr = [&](std::size_t idx) -> std::string {
        if (idx >= ops.size()) {
            return "0";
        }
        return format_value_expr(ops[idx], m, insn.address, insn_size, arch, symbols, stack_locals);
    };

    auto dst_expr = [&](std::size_t idx) -> std::string {
        if (idx >= ops.size()) {
            return "tmp";
        }
        if (is_memory_operand(ops[idx])) {
            return format_memory_access(
                ops[idx], m, insn.address, insn_size, arch_64, symbols, stack_locals, false);
        }
        return clean_atom(ops[idx]);
    };

    // Calls
    if (is_call_mnemonic(m, insn.operands, arch)) {
        std::string stmt = build_call_statement(
            insn, insn_size, ops, arch, symbols, reg_const_va,
            block_written_regs, call_result_unused, has_win_imports);
        const std::string ret_fam = canonical_reg_family(return_register_name(arch), arch);
        block_written_regs.insert(ret_fam);
        func_written_regs.insert(ret_fam);
        reg_const_va.erase(ret_fam);
        flags = FlagState{};
        return stmt;
    }

    // Comparisons & flag tests (produce no standalone C line when followed by conditional jump/setcc).
    if ((m == "cmp" || m == "cmpw" || m == "cmpd" || m == "cmpl" || m == "cmplw" || m == "cmpld" ||
         m == "cmpwi" || m == "cmpdi" || m == "cmplwi" || m == "cmpldi") &&
        ops.size() >= 2u) {
        const std::size_t lhs_i = (ops.size() >= 3u && to_lower_ascii(ops[0]).starts_with("cr")) ? 1u : 0u;
        flags = FlagState{val_expr(lhs_i), val_expr(lhs_i + 1u), true};
        return std::nullopt;
    }
    if (m == "cmn" && ops.size() >= 2u) {
        flags = FlagState{val_expr(0u), "-" + val_expr(1u), true};
        return std::nullopt;
    }
    if ((m == "test" || m == "tst") && ops.size() >= 2u) {
        const std::string a = val_expr(0u);
        const std::string b = val_expr(1u);
        if (a == b) {
            flags = FlagState{a, "0", true};
        } else {
            flags = FlagState{std::format("({} & {})", a, b), "0", true};
        }
        return std::nullopt;
    }

    // Zero-init idioms: xor eax, eax / sub eax, eax / eor w0, w0, w0
    if ((m == "xor" || m == "sub" || m == "eor") && ops.size() >= 2u) {
        const std::string d = clean_atom(ops[0]);
        const std::string a = clean_atom(ops[1]);
        const std::string b = ops.size() >= 3u ? clean_atom(ops[2]) : d;
        if (!is_memory_operand(ops[0]) && a == b && d == a) {
            mark_write(ops[0]);
            flags = FlagState{d, "0", true};
            return std::format("{} = 0;", d);
        }
    }

    // PC-relative page / address formation: lea, adrp, adr, auipc, lui
    if (m == "lea" && ops.size() == 2u) {
        const std::string dst = dst_expr(0u);
        const std::string addr = format_memory_access(
            ops[1], m, insn.address, insn_size, arch_64, symbols, stack_locals, true);
        mark_write(ops[0]);
        if (const auto rip_va = extract_rip_target(ops[1], insn.address, insn_size)) {
            reg_const_va[canonical_reg_family(ops[0], arch)] = *rip_va;
        }
        return std::format("{} = {};", dst, addr);
    }
    if ((m == "adrp" || m == "adr") && ops.size() == 2u) {
        const std::string dst = dst_expr(0u);
        const auto imm_va = parse_unsigned_addr(ops[1]);
        mark_write(ops[0]);
        if (imm_va.has_value()) {
            reg_const_va[canonical_reg_family(ops[0], arch)] = *imm_va;
            if (m == "adr") {
                if (const auto it = symbols.find(*imm_va); it != symbols.end()) {
                    return std::format("{} = &{}; /* 0x{:X} */", dst, it->second.c_ident, *imm_va);
                }
            }
            return std::format("{} = 0x{:X};", dst, *imm_va);
        }
        return std::format("{} = {};", dst, val_expr(1u));
    }
    if (m == "auipc" && ops.size() == 2u) {
        const std::string dst = dst_expr(0u);
        const auto imm = parse_signed_int(ops[1]);
        mark_write(ops[0]);
        if (imm.has_value()) {
            std::uint64_t target = insn.address + (static_cast<std::uint64_t>(*imm) << 12u);
            if (arch == peelf::Architecture::RISCV32) {
                target &= 0xFFFF'FFFFULL;
            }
            reg_const_va[canonical_reg_family(ops[0], arch)] = target;
            return std::format("{} = 0x{:X};", dst, target);
        }
        return std::format("{} = pc + ({} << 12);", dst, val_expr(1u));
    }
    if ((m == "lui" || m == "lis") && ops.size() == 2u) {
        const std::string dst = dst_expr(0u);
        const auto imm = parse_signed_int(ops[1]);
        mark_write(ops[0]);
        if (imm.has_value()) {
            const std::uint64_t shifted =
                (static_cast<std::uint64_t>(*imm) & 0xFFFF'FFFFULL) << (m == "lui" && (arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) ? 12u : 16u);
            reg_const_va[canonical_reg_family(ops[0], arch)] = shifted;
            return std::format("{} = 0x{:X};", dst, shifted);
        }
        return std::format("{} = {} << 16;", dst, val_expr(1u));
    }

    // Moves, loads, and stores
    if ((m == "mov" || m == "movabs" || m == "mv" || m == "c.mv" || m == "mr" || m == "mr." ||
         m == "move" || m == "li" || m == "c.li" || m == "la" || m == "dla" || m == "movz") &&
        ops.size() >= 2u) {
        const std::string lhs = dst_expr(0u);
        const std::string rhs = val_expr(1u);
        mark_write(ops[0]);
        if (const auto c = parse_unsigned_addr(ops[1])) {
            reg_const_va[canonical_reg_family(ops[0], arch)] = *c;
        }
        if (m == "mr.") {
            flags = FlagState{lhs, "0", true};
        }
        return std::format("{} = {};", lhs, rhs);
    }
    if (m == "movn" && ops.size() >= 2u) {
        const std::string lhs = dst_expr(0u);
        mark_write(ops[0]);
        return std::format("{} = ~({});", lhs, val_expr(1u));
    }
    if (m == "movk" && ops.size() >= 2u) {
        const std::string lhs = dst_expr(0u);
        mark_write(ops[0]);
        if (ops.size() >= 3u) {
            return std::format("{} |= ({} /* {} */);", lhs, val_expr(1u), clean_atom(ops[2]));
        }
        return std::format("{} = ({} & ~0xFFFFULL) | {};", lhs, lhs, val_expr(1u));
    }
    if ((m == "movzx" || m == "movsx" || m == "movsxd") && ops.size() == 2u) {
        const std::string lhs = dst_expr(0u);
        const std::string rhs = val_expr(1u);
        mark_write(ops[0]);
        const std::string_view cast_t =
            m == "movzx" ? "uint32_t" : (arch_64 ? "int64_t" : "int32_t");
        return std::format("{} = ({})({});", lhs, cast_t, rhs);
    }

    // Loads (ARM/RISC-V/MIPS/PPC: reg, mem)
    if ((m == "ldr" || m == "ldrb" || m == "ldrh" || m == "ldrsb" || m == "ldrsh" || m == "ldrsw" ||
         m == "ldur" || m == "lb" || m == "lbu" || m == "lh" || m == "lhu" || m == "lw" || m == "lwu" ||
         m == "ld" || m == "c.lw" || m == "c.ld" || m == "c.lwsp" || m == "c.ldsp" ||
         m == "lbz" || m == "lhz" || m == "lha" || m == "lwz" || m == "lwa") &&
        ops.size() >= 2u) {
        const std::string dst = dst_expr(0u);
        const std::string src = val_expr(1u);
        mark_write(ops[0]);
        return std::format("{} = {};", dst, src);
    }
    if (m == "ldp" && ops.size() >= 3u) {
        const std::string d1 = dst_expr(0u);
        const std::string d2 = dst_expr(1u);
        const std::string base_mem = val_expr(2u);
        mark_write(ops[0]);
        mark_write(ops[1]);
        return std::format("{} = {}; {} = *(&{} + 1);", d1, base_mem, d2, base_mem);
    }

    // Stores (ARM/RISC-V/MIPS/PPC: src_reg, mem)
    if ((m == "str" || m == "strb" || m == "strh" || m == "stur" ||
         m == "sb" || m == "sh" || m == "sw" || m == "sd" ||
         m == "c.sw" || m == "c.sd" || m == "c.swsp" || m == "c.sdsp" ||
         m == "stb" || m == "sth" || m == "stw" || m == "std" || m == "stwu" || m == "stdu") &&
        ops.size() >= 2u) {
        const std::string src = is_zero_register(ops[0], arch) ? "0" : val_expr(0u);
        const std::string mem = dst_expr(1u);
        return std::format("{} = {};", mem, src);
    }
    if (m == "stp" && ops.size() >= 3u) {
        const std::string s1 = is_zero_register(ops[0], arch) ? "0" : val_expr(0u);
        const std::string s2 = is_zero_register(ops[1], arch) ? "0" : val_expr(1u);
        const std::string mem = dst_expr(2u);
        return std::format("{} = {}; *(&{} + 1) = {};", mem, s1, mem, s2);
    }

    // Stack push/pop (non-prologue)
    if (m == "push" && ops.size() == 1u) {
        return std::format("__push({});", val_expr(0u));
    }
    if (m == "pop" && ops.size() == 1u) {
        const std::string dst = dst_expr(0u);
        mark_write(ops[0]);
        return std::format("{} = __pop();", dst);
    }

    // Sign-extension helpers (cdqe, cdq, cqo, sxtw)
    if (m == "cdqe") {
        mark_write("rax");
        return "rax = (int64_t)(int32_t)eax;";
    }
    if (m == "cdq" || m == "cqo") {
        mark_write("rdx");
        return m == "cqo" ? "rdx = (rax < 0) ? -1 : 0;" : "edx = (eax < 0) ? -1 : 0;";
    }
    if (m == "sxtw" && ops.size() == 2u) {
        const std::string d = dst_expr(0u);
        mark_write(ops[0]);
        return std::format("{} = (int64_t)(int32_t){};", d, val_expr(1u));
    }

    // Unary arithmetic & bitwise
    if (m == "inc" && ops.size() == 1u) {
        const std::string d = dst_expr(0u);
        mark_write(ops[0]);
        flags = FlagState{d, "0", true};
        return std::format("{}++;", d);
    }
    if (m == "dec" && ops.size() == 1u) {
        const std::string d = dst_expr(0u);
        mark_write(ops[0]);
        flags = FlagState{d, "0", true};
        return std::format("{}--;", d);
    }
    if ((m == "neg" || m == "negs" || m == "neg." || m == "negw") && !ops.empty()) {
        const std::string d = dst_expr(0u);
        const std::string s = ops.size() >= 2u ? val_expr(1u) : d;
        mark_write(ops[0]);
        if (is_x86 || m == "negs" || m == "neg.") {
            flags = FlagState{d, "0", true};
        }
        return std::format("{} = -{};", d, s);
    }
    if ((m == "not" || m == "mvn") && !ops.empty()) {
        const std::string d = dst_expr(0u);
        const std::string s = ops.size() >= 2u ? val_expr(1u) : d;
        mark_write(ops[0]);
        return std::format("{} = ~{};", d, s);
    }

    // Conditional set / select: setcc, cset, cmovcc, csel
    if (m.starts_with("set") && m.size() > 3u && ops.size() == 1u) {
        const std::string d = dst_expr(0u);
        const std::string cond = build_flag_condition(m.substr(3u), flags, arch_64);
        mark_write(ops[0]);
        return std::format("{} = ({}) ? 1 : 0;", d, cond);
    }
    if (m == "cset" && ops.size() == 2u) {
        const std::string d = dst_expr(0u);
        const std::string cond = build_flag_condition(to_lower_ascii(clean_atom(ops[1])), flags, arch_64);
        mark_write(ops[0]);
        return std::format("{} = ({}) ? 1 : 0;", d, cond);
    }
    if (m.starts_with("cmov") && m.size() > 4u && ops.size() == 2u) {
        const std::string d = dst_expr(0u);
        const std::string s = val_expr(1u);
        const std::string cond = build_flag_condition(m.substr(4u), flags, arch_64);
        mark_write(ops[0]);
        return std::format("{} = ({}) ? {} : {};", d, cond, s, d);
    }
    if (m == "csel" && ops.size() >= 4u) {
        const std::string d = dst_expr(0u);
        const std::string cond = build_flag_condition(to_lower_ascii(clean_atom(ops[3])), flags, arch_64);
        mark_write(ops[0]);
        return std::format("{} = ({}) ? {} : {};", d, cond, val_expr(1u), val_expr(2u));
    }

    // Binary arithmetic & bitwise helper
    auto emit_binop = [&](std::string_view c_op, bool sets_flags = false, bool rhs_complement = false)
        -> std::optional<std::string> {
        if (ops.size() < 2u) {
            return std::nullopt;
        }
        // Check ADRP/AUIPC/LUI + ADD/ADDI symbol combination!
        if (c_op == "+" && ops.size() >= 3u && !is_memory_operand(ops[0])) {
            const std::string src_fam = canonical_reg_family(ops[1], arch);
            if (const auto base_it = reg_const_va.find(src_fam); base_it != reg_const_va.end()) {
                if (const auto delta = parse_signed_int(ops[2])) {
                    std::uint64_t combined = base_it->second + static_cast<std::uint64_t>(*delta);
                    if (!arch_64) {
                        combined &= 0xFFFF'FFFFULL;
                    }
                    const std::string dst = dst_expr(0u);
                    mark_write(ops[0]);
                    reg_const_va[canonical_reg_family(ops[0], arch)] = combined;
                    if (sets_flags) {
                        flags = FlagState{dst, "0", true};
                    }
                    if (const auto sym_it = symbols.find(combined); sym_it != symbols.end()) {
                        return std::format("{} = &{}; /* 0x{:X} */", dst, sym_it->second.c_ident, combined);
                    }
                    return std::format("{} = 0x{:X};", dst, combined);
                }
            }
        }

        const bool discard_dst = is_zero_register(ops[0], arch);
        const std::string dst = dst_expr(0u);
        std::string lhs = ops.size() >= 3u ? val_expr(1u) : dst;
        std::string rhs = ops.size() >= 3u ? val_expr(2u) : val_expr(1u);
        if (rhs_complement) {
            rhs = "~(" + rhs + ")";
        }

        if (discard_dst) {
            if (sets_flags) {
                if (c_op == "-") {
                    flags = FlagState{lhs, rhs, true};
                } else {
                    flags = FlagState{std::format("({} {} {})", lhs, c_op, rhs), "0", true};
                }
            }
            return std::nullopt;
        }

        mark_write(ops[0]);
        if (sets_flags) {
            if (c_op == "-" && ops.size() >= 3u) {
                flags = FlagState{lhs, rhs, true};
            } else {
                flags = FlagState{dst, "0", true};
            }
        }
        if (dst == lhs && !rhs_complement) {
            return std::format("{} {}= {};", dst, c_op, rhs);
        }
        return std::format("{} = {} {} {};", dst, lhs, c_op, rhs);
    };

    if (m == "add" || m == "adds" || m == "add." || m == "addic." || m == "addw" ||
        m == "addi" || m == "addiw" || m == "addiu" || m == "daddiu" ||
        m == "addu" || m == "daddu" || m == "c.add" || m == "c.addi") {
        return emit_binop("+", (is_x86 && m == "add") || m == "adds" || m == "add." || m == "addic.");
    }
    if (m == "sub" || m == "subs" || m == "sub." || m == "subw" || m == "subi" ||
        m == "subu" || m == "dsubu" || m == "c.sub") {
        return emit_binop("-", (is_x86 && m == "sub") || m == "subs" || m == "sub.");
    }
    if ((m == "subf" || m == "subf.") && ops.size() >= 3u) {
        const std::string d = dst_expr(0u);
        mark_write(ops[0]);
        if (m == "subf.") {
            flags = FlagState{d, "0", true};
        }
        return std::format("{} = {} - {};", d, val_expr(2u), val_expr(1u));
    }
    if (m == "imul" || m == "mul" || m == "muls" || m == "mulw" ||
        m == "mullw" || m == "mullw." || m == "mulld" || m == "mulld.") {
        if (is_x86 || m == "muls" || m.ends_with('.')) {
            flags = FlagState{};
        }
        if (m == "imul" && ops.size() == 1u) {
            const std::string_view acc = arch_64 ? "rax" : "eax";
            mark_write(acc);
            return std::format("{} *= {};", acc, val_expr(0u));
        }
        return emit_binop("*");
    }
    if (m == "div" || m == "idiv") {
        if (is_x86) {
            flags = FlagState{};
        }
        if (ops.size() == 1u) {
            const std::string_view acc = arch_64 ? "rax" : "eax";
            mark_write(acc);
            return std::format("{} /= {};", acc, val_expr(0u));
        }
        return emit_binop("/");
    }
    if (m == "udiv" || m == "sdiv" || m == "divw" || m == "divw." ||
        m == "divuw" || m == "divuw." || m == "divd" || m == "divd." ||
        m == "divdu" || m == "divdu.") {
        if (m.ends_with('.')) {
            flags = FlagState{};
        }
        return emit_binop("/");
    }
    if (m == "rem" || m == "remu" || m == "remw" || m == "remuw") {
        return emit_binop("%");
    }
    if (m == "and" || m == "ands" || m == "and." || m == "andi" || m == "andi." ||
        m == "c.and" || m == "c.andi") {
        return emit_binop("&", (is_x86 && m == "and") || m == "ands" || m == "and." || m == "andi.");
    }
    if (m == "bic" || m == "bics" || m == "andc" || m == "andc.") {
        return emit_binop("&", m == "bics" || m == "andc.", true);
    }
    if (m == "or" || m == "ors" || m == "orr" || m == "ori" || m == "or." || m == "ori." || m == "c.or") {
        return emit_binop("|", (is_x86 && m == "or") || m == "ors" || m == "or." || m == "ori.");
    }
    if (m == "orn" || m == "orns" || m == "orc" || m == "orc.") {
        return emit_binop("|", m == "orns" || m == "orc.", true);
    }
    if (m == "xor" || m == "eor" || m == "eors" || m == "xor." || m == "xori" || m == "xori." || m == "c.xor") {
        return emit_binop("^", (is_x86 && m == "xor") || m == "eors" || m == "xor." || m == "xori.");
    }
    if (m == "shl" || m == "sal" || m == "lsl" || m == "lsls" || m == "sll" || m == "slli" || m == "slliw" ||
        m == "sllv" || m == "dsll" || m == "slw" || m == "slw." || m == "sld" || m == "sld." || m == "c.slli") {
        return emit_binop("<<", (is_x86 && (m == "shl" || m == "sal")) ||
                                    m == "lsls" || m == "slw." || m == "sld.");
    }
    if (m == "shr" || m == "lsr" || m == "lsrs" || m == "srl" || m == "srli" || m == "srliw" ||
        m == "srlv" || m == "dsrl" || m == "srw" || m == "srw." || m == "srd" || m == "srd." ||
        m == "sar" || m == "asr" || m == "asrs" || m == "sra" || m == "srai" || m == "sraiw" ||
        m == "srav" || m == "dsra" || m == "sraw" || m == "sraw." || m == "srad" || m == "srad.") {
        return emit_binop(">>", (is_x86 && (m == "shr" || m == "sar")) ||
                                    m == "lsrs" || m == "asrs" ||
                                    m == "srw." || m == "srd." || m == "sraw." || m == "srad.");
    }

    if ((is_x86 && m != "xchg" && m != "bswap" && !m.starts_with("mov") && !m.starts_with("prefetch")) ||
        m.ends_with('.') || m == "ccmp" || m == "ccmn" || m == "adcs" || m == "sbcs" || m == "rscs" || m == "teq") {
        flags = FlagState{};
    }

    // Fallback: preserve full instruction fidelity via intrinsic call!
    return std::format(
        "__asm_insn(\"{}\", \"{}\");",
        escape_c_string(insn.mnemonic),
        escape_c_string(insn.operands));
}

struct OutputItem {
    bool is_label_placeholder{false};
    std::size_t block_idx{0};
    std::uint64_t address{0};
    std::vector<CodeRange> ranges;
    std::size_t indent{0};
    std::string text;
};

struct LoopContext {
    std::size_t header_idx{0};
    std::optional<std::size_t> exit_idx;
};

}  // namespace

DecompiledUnit StructuredPseudoCDecompiler::decompile(
    const DecompileRequest& request,
    std::stop_token stop) const {
    auto make_status = [](DecompileStatus st, std::string diag) {
        return DecompiledUnit{
            .status = st,
            .provider = std::string(kStructuredProvider),
            .diagnostic = std::move(diag),
            .lines = {},
            .types = {},
        };
    };

    if (stop.stop_requested()) {
        return make_status(DecompileStatus::Cancelled, "Decompilation cancelled");
    }
    if (request.architecture == peelf::Architecture::Unknown) {
        return make_status(DecompileStatus::Unsupported, "Unsupported or unknown CPU architecture");
    }
    if (request.fallback_graph.nodes.empty()) {
        return make_status(DecompileStatus::NoFunction, "No basic blocks available for function");
    }

    // Extract ordered basic-block nodes with instructions.
    std::vector<const CallGraphNode*> raw_blocks;
    raw_blocks.reserve(request.fallback_graph.nodes.size());
    for (const CallGraphNode& node : request.fallback_graph.nodes) {
        if (!node.instructions.empty()) {
            raw_blocks.push_back(&node);
        }
    }
    if (raw_blocks.empty()) {
        return make_status(DecompileStatus::NoFunction, "Function graph contains no decoded instructions");
    }

    const std::size_t num_blocks = raw_blocks.size();
    std::map<std::string, std::size_t> id_to_block;
    std::map<std::string, const CallGraphNode*> id_to_node;
    for (const CallGraphNode& node : request.fallback_graph.nodes) {
        id_to_node.emplace(node.id, &node);
    }
    for (std::size_t i = 0u; i < num_blocks; ++i) {
        id_to_block.emplace(raw_blocks[i]->id, i);
    }

    const std::map<std::uint64_t, ResolvedSymbol> symbols =
        build_symbol_table(request.symbols, request.architecture);

    bool has_win_imports = false;
    for (const SymbolRecord& sr : request.symbols) {
        if (sr.source == SymbolSource::Import &&
            (to_lower_ascii(sr.library).ends_with(".dll") || to_lower_ascii(sr.name).find(".dll!") != std::string::npos)) {
            has_win_imports = true;
            break;
        }
    }

    // Determine function identifier at request.address.
    std::string func_name;
    if (const auto sym_it = symbols.find(request.address); sym_it != symbols.end() &&
        sym_it->second.raw_name != "Entry Point") {
        func_name = sym_it->second.c_ident;
    } else if (!request.fallback_graph.label.empty() &&
               request.fallback_graph.label != "function" &&
               request.fallback_graph.label != "Entry Point") {
        func_name = sanitize_c_identifier(request.fallback_graph.label, std::format("sub_{:X}", request.address));
    } else if (const auto ep_it = symbols.find(request.address); ep_it != symbols.end()) {
        func_name = ep_it->second.c_ident;
    } else {
        func_name = std::format("sub_{:X}", request.address);
    }

    // Pre-compute outgoing / incoming block edges.
    std::vector<std::vector<const CallGraphEdge*>> out_edges(num_blocks);
    std::vector<std::size_t> forward_preds(num_blocks, 0u);
    std::vector<std::size_t> back_preds(num_blocks, 0u);
    std::vector<std::vector<std::size_t>> all_preds(num_blocks);
    std::vector<std::optional<std::size_t>> max_back_latch(num_blocks);

    for (const CallGraphEdge& edge : request.fallback_graph.edges) {
        const auto from_it = id_to_block.find(edge.from_node_id);
        if (from_it == id_to_block.end()) {
            continue;
        }
        const std::size_t u = from_it->second;
        out_edges[u].push_back(&edge);

        const auto to_it = id_to_block.find(edge.to_node_id);
        if (to_it != id_to_block.end()) {
            const std::size_t v = to_it->second;
            all_preds[v].push_back(u);
            if (u < v) {
                ++forward_preds[v];
            } else {
                ++back_preds[v];
                if (!max_back_latch[v].has_value() || u > *max_back_latch[v]) {
                    max_back_latch[v] = u;
                }
            }
        }
    }

    // Lift all basic blocks into BlockIR.
    std::set<std::string> stack_locals;
    std::set<std::string> func_written_regs;
    std::vector<BlockIR> ir_blocks(num_blocks);

    const std::uint64_t fallback_sz = default_insn_size(request.architecture, request.thumb);
    const std::string ret_reg_family =
        canonical_reg_family(return_register_name(request.architecture), request.architecture);

    // Quick pre-scan to detect whether any instruction before a return writes the return register.
    for (std::size_t b = 0u; b < num_blocks; ++b) {
        for (const GraphInstruction& gi : raw_blocks[b]->instructions) {
            const std::string m = normalize_mnemonic(gi.mnemonic, request.architecture);
            const std::vector<std::string> ops = split_operands(gi.operands);
            if (is_prologue_or_epilogue_noise(m, ops, request.architecture)) {
                continue;
            }
            if (is_call_mnemonic(m, gi.operands, request.architecture)) {
                func_written_regs.insert(ret_reg_family);
            } else if (!ops.empty() && !is_memory_operand(ops[0]) &&
                       m != "cmp" && m != "test" && m != "tst" &&
                       !is_return_mnemonic(m, gi.operands, request.architecture)) {
                func_written_regs.insert(canonical_reg_family(ops[0], request.architecture));
            }
        }
    }
    const bool function_writes_ret_reg = func_written_regs.contains(ret_reg_family);

    for (std::size_t b = 0u; b < num_blocks; ++b) {
        if (stop.stop_requested()) {
            return make_status(DecompileStatus::Cancelled, "Decompilation cancelled");
        }
        const CallGraphNode& node = *raw_blocks[b];
        BlockIR& ir = ir_blocks[b];
        ir.index = b;
        ir.node_id = node.id;
        ir.start_va = node.instructions.front().address;

        // Compute exact instruction byte sizes from consecutive addresses and block byte size.
        const std::size_t insn_count = node.instructions.size();
        std::vector<std::uint64_t> insn_sizes(insn_count, fallback_sz);
        const std::uint64_t block_end =
            (node.bytes.start.virtual_address.has_value() && node.bytes.size > 0u)
                ? (*node.bytes.start.virtual_address + node.bytes.size)
                : 0u;
        for (std::size_t i = 0u; i < insn_count; ++i) {
            if (i + 1u < insn_count && node.instructions[i + 1u].address > node.instructions[i].address) {
                insn_sizes[i] = node.instructions[i + 1u].address - node.instructions[i].address;
            } else if (i + 1u == insn_count && block_end > node.instructions[i].address) {
                insn_sizes[i] = block_end - node.instructions[i].address;
            }
            insn_sizes[i] = std::max<std::uint64_t>(1u, insn_sizes[i]);
            ir.all_ranges.push_back(CodeRange{node.instructions[i].address, insn_sizes[i]});
        }
        ir.first_insn_size = insn_sizes.front();

        // Classify outgoing edges for block b.
        bool has_return_edge = false;
        const CallGraphEdge* external_edge = nullptr;
        for (const CallGraphEdge* edge : out_edges[b]) {
            if (edge->kind == CallGraphEdgeKind::Return || edge->to_node_id == "return") {
                has_return_edge = true;
                continue;
            }
            const auto target_it = id_to_block.find(edge->to_node_id);
            if (target_it == id_to_block.end()) {
                external_edge = edge;
                continue;
            }
            const std::size_t target_idx = target_it->second;
            if (edge->kind == CallGraphEdgeKind::ConditionalBranch ||
                edge->label == "taken" || edge->label == "true") {
                ir.taken_block = target_idx;
            } else if (edge->kind == CallGraphEdgeKind::Fallthrough ||
                       edge->label == "fallthrough" || edge->label == "false" ||
                       edge->label == "not returned") {
                ir.fall_block = target_idx;
            } else if (edge->kind == CallGraphEdgeKind::UnconditionalBranch) {
                if (edge->label.starts_with("case ")) {
                    ir.switch_cases.emplace_back(edge->label, target_idx);
                } else {
                    ir.jump_block = target_idx;
                }
            }
        }

        // Determine which instruction is the control-flow terminator (accounting for MIPS delay slots).
        const bool has_branch_or_ret =
            has_return_edge || ir.taken_block.has_value() || ir.jump_block.has_value() ||
            !ir.switch_cases.empty() || external_edge != nullptr;
        std::optional<std::size_t> control_idx;
        if (has_branch_or_ret) {
            control_idx = insn_count - 1u;
            if ((request.architecture == peelf::Architecture::MIPS32 ||
                 request.architecture == peelf::Architecture::MIPS64) &&
                insn_count >= 2u) {
                const std::string last_m = normalize_mnemonic(node.instructions.back().mnemonic, request.architecture);
                const std::string prev_m = normalize_mnemonic(node.instructions[insn_count - 2u].mnemonic, request.architecture);
                if (!is_return_mnemonic(last_m, node.instructions.back().operands, request.architecture) &&
                    !last_m.starts_with('b') && !last_m.starts_with('j') &&
                    (is_return_mnemonic(prev_m, node.instructions[insn_count - 2u].operands, request.architecture) ||
                     prev_m.starts_with('b') || prev_m.starts_with('j'))) {
                    control_idx = insn_count - 2u;
                }
            }
        }

        // Inherit flag state from single immediate predecessor when helpful.
        FlagState flags{};
        if (all_preds[b].size() == 1u && all_preds[b][0] < b) {
            flags = ir_blocks[all_preds[b][0]].out_flags;
        }
        const FlagState entry_flags = flags;
        std::map<std::string, std::uint64_t> reg_const_va;
        std::set<std::string> block_written_regs;

        for (std::size_t i = 0u; i < insn_count; ++i) {
            if (control_idx.has_value() && i == *control_idx) {
                continue;
            }
            const GraphInstruction& gi = node.instructions[i];

            // Detect if a call's return value is immediately overwritten by the next instruction (e.g., xor eax, eax; ret).
            bool call_unused = false;
            if (i + 1u < insn_count) {
                const GraphInstruction& next_gi = node.instructions[i + 1u];
                const std::string next_m = normalize_mnemonic(next_gi.mnemonic, request.architecture);
                const std::vector<std::string> next_ops = split_operands(next_gi.operands);
                if ((next_m == "xor" || next_m == "mov" || next_m == "li") && next_ops.size() >= 2u &&
                    canonical_reg_family(next_ops[0], request.architecture) == ret_reg_family &&
                    (next_m != "mov" || canonical_reg_family(next_ops[1], request.architecture) != ret_reg_family)) {
                    call_unused = true;
                }
            }

            if (auto stmt = lift_general_instruction(
                    gi,
                    insn_sizes[i],
                    request.architecture,
                    symbols,
                    stack_locals,
                    reg_const_va,
                    block_written_regs,
                    func_written_regs,
                    flags,
                    call_unused,
                    has_win_imports)) {
                ir.body.push_back(LiftedStmt{
                    .address = gi.address,
                    .size = insn_sizes[i],
                    .code = std::move(*stmt),
                });
            }
        }

        ir.out_flags = flags;

        if (!control_idx.has_value()) {
            ir.term_kind = TermKind::Fallthrough;
            ir.term_addr = node.instructions.back().address;
            ir.term_size = insn_sizes.back();
            continue;
        }

        const GraphInstruction& term_insn = node.instructions[*control_idx];
        const std::uint64_t term_sz = insn_sizes[*control_idx];
        ir.term_addr = term_insn.address;
        ir.term_size = term_sz;
        const std::string term_m = normalize_mnemonic(term_insn.mnemonic, request.architecture);
        const std::vector<std::string> term_ops = split_operands(term_insn.operands);

        if (has_return_edge) {
            ir.return_stmt = function_writes_ret_reg
                                 ? std::format("return {};", return_register_name(request.architecture))
                                 : std::string("return;");
            if (ir.fall_block.has_value()) {
                ir.term_kind = TermKind::ConditionalReturn;
                ir.cond_expr = extract_branch_condition(term_m, term_ops, request.architecture, flags);
            } else {
                ir.term_kind = TermKind::Return;
            }
        } else if (!ir.switch_cases.empty()) {
            ir.term_kind = TermKind::Switch;
            auto recover_switch_selector = [&]() -> std::string {
                if (!term_ops.empty()) {
                    if (auto mem_idx = extract_memory_index_expr(term_ops[0])) {
                        return *mem_idx;
                    }
                }
                const std::size_t scan_limit = control_idx.value_or(insn_count);
                std::optional<std::string> table_index;
                for (std::size_t rev = scan_limit; rev > 0u; --rev) {
                    const GraphInstruction& gi = node.instructions[rev - 1u];
                    const std::string gm = normalize_mnemonic(gi.mnemonic, request.architecture);
                    const std::vector<std::string> gops = split_operands(gi.operands);
                    if ((gm == "cmp" || gm == "cmpw" || gm == "cmpd" || gm == "cmpl" ||
                         gm == "cmpwi" || gm == "cmpdi" || gm == "cmplwi" || gm == "cmpldi") &&
                        gops.size() >= 2u) {
                        const std::size_t lhs_i =
                            (gops.size() >= 3u && to_lower_ascii(gops[0]).starts_with("cr")) ? 1u : 0u;
                        std::string sel = format_value_expr(
                            gops[lhs_i], gm, gi.address, insn_sizes[rev - 1u],
                            request.architecture, symbols, stack_locals);
                        if (!sel.empty()) {
                            return sel;
                        }
                    }
                    if (!table_index.has_value()) {
                        for (const std::string& gop : gops) {
                            if (auto idx = extract_memory_index_expr(gop)) {
                                table_index = std::move(*idx);
                                break;
                            }
                        }
                    }
                }
                if (entry_flags.valid && !entry_flags.lhs.empty() && entry_flags.lhs != "flags") {
                    return entry_flags.lhs;
                }
                if (table_index.has_value()) {
                    return *table_index;
                }
                if (!term_ops.empty()) {
                    if (is_memory_operand(term_ops[0])) {
                        return format_value_expr(
                            term_ops[0], term_m, term_insn.address, term_sz,
                            request.architecture, symbols, stack_locals);
                    }
                    std::string cleaned = clean_atom(term_ops[0]);
                    if (!cleaned.empty()) {
                        return cleaned;
                    }
                }
                return "index";
            };
            ir.cond_expr = recover_switch_selector();
        } else if (ir.taken_block.has_value() ||
                   (external_edge != nullptr && external_edge->kind == CallGraphEdgeKind::ConditionalBranch)) {
            ir.term_kind = TermKind::CondBranch;
            ir.cond_expr = extract_branch_condition(term_m, term_ops, request.architecture, flags);
            if (!ir.taken_block.has_value() && external_edge != nullptr) {
                std::optional<std::uint64_t> ext_va = term_insn.branch_target;
                if (!ext_va.has_value()) {
                    if (const auto n_it = id_to_node.find(external_edge->to_node_id);
                        n_it != id_to_node.end() && n_it->second->bytes.start.virtual_address.has_value()) {
                        ext_va = n_it->second->bytes.start.virtual_address;
                    }
                }
                if (ext_va.has_value()) {
                    if (const auto s_it = symbols.find(*ext_va); s_it != symbols.end()) {
                        ir.external_stmt = std::format("return {}();", s_it->second.c_ident);
                    } else {
                        ir.external_stmt = std::format("return sub_{:X}();", *ext_va);
                    }
                } else {
                    ir.external_stmt = "/* unresolved external branch */ return 0;";
                }
            }
        } else if (ir.jump_block.has_value()) {
            ir.term_kind = TermKind::Jump;
        } else if (external_edge != nullptr) {
            ir.term_kind = TermKind::TailOrExternal;
            std::optional<std::uint64_t> ext_va = term_insn.branch_target;
            if (!ext_va.has_value() && !term_ops.empty()) {
                ext_va = extract_rip_target(term_ops[0], term_insn.address, term_sz);
            }
            if (!ext_va.has_value()) {
                if (const auto n_it = id_to_node.find(external_edge->to_node_id);
                    n_it != id_to_node.end() && n_it->second->bytes.start.virtual_address.has_value()) {
                    ext_va = n_it->second->bytes.start.virtual_address;
                }
            }
            if (ext_va.has_value()) {
                const std::string call_stmt = build_call_statement(
                    term_insn, term_sz, term_ops, request.architecture, symbols,
                    reg_const_va, block_written_regs, false, has_win_imports);
                // Convert `rax = foo(args);` into `return foo(args);` for tail call.
                const std::string prefix = std::format("{} = ", return_register_name(request.architecture));
                if (call_stmt.starts_with(prefix)) {
                    ir.external_stmt = "return " + call_stmt.substr(prefix.size());
                } else {
                    ir.external_stmt = call_stmt + " return 0;";
                }
            } else {
                ir.external_stmt = std::format(
                    "__asm_insn(\"{}\", \"{}\"); return 0;",
                    escape_c_string(term_insn.mnemonic),
                    escape_c_string(term_insn.operands));
            }
        }
    }

    // Control-flow structuring over ir_blocks[0 .. num_blocks - 1].
    std::vector<bool> emitted(num_blocks, false);
    std::set<std::size_t> goto_targets;
    std::vector<OutputItem> out_items;
    std::vector<LoopContext> loop_stack;

    auto block_label_name = [&](std::size_t idx) -> std::string {
        return std::format("block_{:X}", ir_blocks[idx].start_va);
    };

    auto push_code = [&](std::uint64_t addr,
                         std::vector<CodeRange> ranges,
                         std::size_t indent,
                         std::string text) {
        if (ranges.empty()) {
            ranges.push_back(CodeRange{addr, 1u});
        }
        out_items.push_back(OutputItem{
            .is_label_placeholder = false,
            .block_idx = 0u,
            .address = addr,
            .ranges = std::move(ranges),
            .indent = indent,
            .text = std::move(text),
        });
    };

    auto push_label_slot = [&](std::size_t idx, std::size_t indent) {
        out_items.push_back(OutputItem{
            .is_label_placeholder = true,
            .block_idx = idx,
            .address = ir_blocks[idx].start_va,
            .ranges = {CodeRange{ir_blocks[idx].start_va, ir_blocks[idx].first_insn_size}},
            .indent = indent > 0u ? indent - 1u : 0u,
            .text = {},
        });
    };

    // Check if single-entry subgraph starting at `entry` stays self-contained and merges at `merge` (or returns).
    auto region_merges_cleanly = [&](std::size_t entry, std::optional<std::size_t> merge) -> bool {
        if (emitted[entry] || back_preds[entry] != 0u || forward_preds[entry] != 1u) {
            return false;
        }
        if (merge.has_value() && entry >= *merge) {
            return false;
        }
        std::set<std::size_t> region{entry};
        std::vector<std::size_t> queue{entry};
        while (!queue.empty()) {
            const std::size_t u = queue.back();
            queue.pop_back();
            if (region.size() > 24u) {
                return false;
            }
            const BlockIR& bir = ir_blocks[u];
            if (bir.term_kind == TermKind::Switch) {
                return false;
            }
            auto check_succ = [&](std::optional<std::size_t> s) -> bool {
                if (!s.has_value()) {
                    return true;
                }
                if (merge.has_value() && *s == *merge) {
                    return true;
                }
                if (!loop_stack.empty()) {
                    if (*s == loop_stack.back().header_idx) {
                        return true;
                    }
                    if (loop_stack.back().exit_idx.has_value() && *s == *loop_stack.back().exit_idx) {
                        return true;
                    }
                }
                if (*s <= u || emitted[*s]) {
                    return false;
                }
                if (merge.has_value() && *s > *merge) {
                    return false;
                }
                if (!region.contains(*s)) {
                    region.insert(*s);
                    queue.push_back(*s);
                }
                return true;
            };
            if (!check_succ(bir.taken_block) || !check_succ(bir.fall_block) || !check_succ(bir.jump_block)) {
                return false;
            }
        }
        for (const std::size_t r : region) {
            if (r == entry) {
                continue;
            }
            for (const std::size_t p : all_preds[r]) {
                if (!region.contains(p)) {
                    return false;
                }
            }
        }
        return true;
    };

    // Find common merge block for a 2-way branch (a, b).
    auto find_diamond_merge = [&](std::size_t a, std::size_t b, std::optional<std::size_t> limit)
        -> std::optional<std::size_t> {
        const std::size_t start_cand = std::max(a, b) + 1u;
        const std::size_t end_cand = limit.value_or(num_blocks);
        for (std::size_t m = start_cand; m < end_cand && m <= start_cand + 16u; ++m) {
            if (!emitted[m] && region_merges_cleanly(a, m) && region_merges_cleanly(b, m)) {
                return m;
            }
        }
        if (region_merges_cleanly(a, limit) && region_merges_cleanly(b, limit)) {
            return limit;
        }
        return std::nullopt;
    };

    auto emit_goto_or_loop_jump = [&](std::size_t target,
                                      std::optional<std::size_t> stop_block,
                                      std::uint64_t addr,
                                      std::uint64_t sz,
                                      std::size_t indent) {
        if (stop_block.has_value() && target == *stop_block) {
            return;
        }
        if (!loop_stack.empty()) {
            if (target == loop_stack.back().header_idx) {
                push_code(addr, {CodeRange{addr, sz}}, indent, "continue;");
                return;
            }
            if (loop_stack.back().exit_idx.has_value() && target == *loop_stack.back().exit_idx) {
                push_code(addr, {CodeRange{addr, sz}}, indent, "break;");
                return;
            }
        }
        goto_targets.insert(target);
        push_code(addr, {CodeRange{addr, sz}}, indent, std::format("goto {};", block_label_name(target)));
    };

    constexpr std::size_t kMaxStructureDepth = 128u;
    constexpr std::size_t kMaxIndent = 64u;

    auto emit_truncated_fallthrough = [&](std::uint64_t term_addr,
                                          std::uint64_t term_size,
                                          std::size_t indent) {
        if (const auto fall_va = peelf::checked_add_u64(term_addr, term_size)) {
            push_code(term_addr,
                      {CodeRange{term_addr, term_size}},
                      indent,
                      std::format("/* truncated disassembly window: missing fallthrough to 0x{:X} */",
                                  *fall_va));
            push_code(term_addr,
                      {CodeRange{term_addr, term_size}},
                      indent,
                      std::format("return sub_{:X}();", *fall_va));
        } else {
            push_code(term_addr,
                      {CodeRange{term_addr, term_size}},
                      indent,
                      "/* truncated disassembly window: missing fallthrough arm */");
            push_code(term_addr, {CodeRange{term_addr, term_size}}, indent, "return 0;");
        }
    };

    auto emit_region = [&](auto& self,
                           std::size_t b,
                           std::optional<std::size_t> stop_block,
                           std::size_t indent,
                           std::optional<std::size_t> suppress_loop_at,
                           std::size_t depth) -> void {
        while (!stop.stop_requested() && b < num_blocks) {
            if (stop_block.has_value() && b == *stop_block) {
                return;
            }
            if (emitted[b]) {
                emit_goto_or_loop_jump(
                    b, stop_block, ir_blocks[b].start_va, ir_blocks[b].first_insn_size, indent);
                return;
            }

            const BlockIR& bir = ir_blocks[b];

            // Natural loop detection at header `b`.
            if (depth < kMaxStructureDepth && max_back_latch[b].has_value() &&
                (!suppress_loop_at.has_value() || *suppress_loop_at != b)) {
                const std::size_t latch = *max_back_latch[b];

                // L1: Single-block self-loop `do { ... } while (cond);`
                if (latch == b && bir.term_kind == TermKind::CondBranch &&
                    (bir.taken_block == b || bir.fall_block == b)) {
                    emitted[b] = true;
                    push_label_slot(b, indent);
                    push_code(bir.start_va, {CodeRange{bir.start_va, bir.first_insn_size}}, indent, "do {");
                    for (const LiftedStmt& st : bir.body) {
                        push_code(st.address, {CodeRange{st.address, st.size}}, indent + 1u, st.code);
                    }
                    const bool taken_loops = (bir.taken_block == b);
                    const std::string loop_cond = taken_loops ? bir.cond_expr : invert_condition(bir.cond_expr);
                    const std::optional<std::size_t> exit_blk = taken_loops ? bir.fall_block : bir.taken_block;
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                              std::format("}} while ({});", loop_cond));
                    if (exit_blk.has_value()) {
                        b = *exit_blk;
                        suppress_loop_at = std::nullopt;
                        continue;
                    }
                    if (taken_loops) {
                        emit_truncated_fallthrough(bir.term_addr, bir.term_size, indent);
                    } else if (!bir.external_stmt.empty()) {
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                  bir.external_stmt);
                    }
                    return;
                }

                // L2: Top-tested `while (cond) { ... }` where `b` branches into `(b, latch]` vs `exit > latch`.
                if (latch > b && (!stop_block.has_value() || latch < *stop_block) &&
                    bir.term_kind == TermKind::CondBranch &&
                    bir.taken_block.has_value() && bir.fall_block.has_value()) {
                    const std::size_t t = *bir.taken_block;
                    const std::size_t f = *bir.fall_block;
                    const bool t_in = (t > b && t <= latch);
                    const bool f_in = (f > b && f <= latch);
                    const bool t_out = (t > latch);
                    const bool f_out = (f > latch);

                    if ((t_in && f_out) || (f_in && t_out)) {
                        const std::size_t body_blk = t_in ? t : f;
                        const std::size_t exit_blk = t_in ? f : t;
                        const std::string stay_cond = t_in ? bir.cond_expr : invert_condition(bir.cond_expr);

                        emitted[b] = true;
                        push_label_slot(b, indent);
                        if (bir.body.empty()) {
                            push_code(bir.term_addr, bir.all_ranges, indent, std::format("while ({}) {{", stay_cond));
                        } else {
                            push_code(bir.start_va, {CodeRange{bir.start_va, bir.first_insn_size}}, indent,
                                      "while (1) {");
                            for (const LiftedStmt& st : bir.body) {
                                push_code(st.address, {CodeRange{st.address, st.size}}, indent + 1u, st.code);
                            }
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u,
                                      std::format("if ({}) break;", invert_condition(stay_cond)));
                        }

                        loop_stack.push_back(LoopContext{.header_idx = b, .exit_idx = exit_blk});
                        self(self, body_blk, b, indent + 1u, std::nullopt, depth + 1u);
                        for (std::size_t k = b + 1u; k <= latch; ++k) {
                            if (!emitted[k] && goto_targets.contains(k)) {
                                self(self, k, b, indent + 1u, std::nullopt, depth + 1u);
                            }
                        }
                        loop_stack.pop_back();

                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                        b = exit_blk;
                        suppress_loop_at = std::nullopt;
                        continue;
                    }
                }

                // L3: Bottom-tested `do { ... } while (cond);` where `latch > b` branches back to `b`.
                if (latch > b && (!stop_block.has_value() || latch < *stop_block) &&
                    !emitted[latch] && ir_blocks[latch].term_kind == TermKind::CondBranch &&
                    (ir_blocks[latch].taken_block == b || ir_blocks[latch].fall_block == b)) {
                    const BlockIR& lir = ir_blocks[latch];
                    const bool taken_loops = (lir.taken_block == b);
                    const std::optional<std::size_t> exit_blk = taken_loops ? lir.fall_block : lir.taken_block;
                    if (!exit_blk.has_value() || *exit_blk > latch) {
                        push_label_slot(b, indent);
                        push_code(bir.start_va, {CodeRange{bir.start_va, bir.first_insn_size}}, indent, "do {");

                        loop_stack.push_back(LoopContext{.header_idx = b, .exit_idx = exit_blk});
                        self(self, b, latch, indent + 1u, b, depth + 1u);
                        for (std::size_t k = b + 1u; k < latch; ++k) {
                            if (!emitted[k] && goto_targets.contains(k)) {
                                self(self, k, latch, indent + 1u, std::nullopt, depth + 1u);
                            }
                        }
                        if (!emitted[latch]) {
                            emitted[latch] = true;
                            push_label_slot(latch, indent + 1u);
                            for (const LiftedStmt& st : lir.body) {
                                push_code(st.address, {CodeRange{st.address, st.size}}, indent + 1u, st.code);
                            }
                        }
                        loop_stack.pop_back();

                        const std::string stay_cond = taken_loops ? lir.cond_expr : invert_condition(lir.cond_expr);
                        push_code(lir.term_addr, {CodeRange{lir.term_addr, lir.term_size}}, indent,
                                  std::format("}} while ({});", stay_cond));
                        if (exit_blk.has_value()) {
                            b = *exit_blk;
                            suppress_loop_at = std::nullopt;
                            continue;
                        }
                        if (taken_loops) {
                            emit_truncated_fallthrough(lir.term_addr, lir.term_size, indent);
                        } else if (!lir.external_stmt.empty()) {
                            push_code(lir.term_addr, {CodeRange{lir.term_addr, lir.term_size}}, indent,
                                      lir.external_stmt);
                        }
                        return;
                    }
                }
            }

            // Standard basic block emission.
            emitted[b] = true;
            push_label_slot(b, indent);
            for (const LiftedStmt& st : bir.body) {
                push_code(st.address, {CodeRange{st.address, st.size}}, indent, st.code);
            }

            std::optional<std::size_t> next_b;
            switch (bir.term_kind) {
                case TermKind::Fallthrough: {
                    if (bir.fall_block.has_value()) {
                        const std::size_t next = *bir.fall_block;
                        if (stop_block.has_value() && next == *stop_block) {
                            return;
                        }
                        if (!emitted[next]) {
                            next_b = next;
                        } else {
                            emit_goto_or_loop_jump(next, stop_block, bir.term_addr, bir.term_size, indent);
                        }
                    }
                    break;
                }

                case TermKind::Return: {
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, bir.return_stmt);
                    break;
                }

                case TermKind::ConditionalReturn: {
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                              std::format("if ({}) {{", bir.cond_expr));
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u, bir.return_stmt);
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                    if (bir.fall_block.has_value()) {
                        next_b = *bir.fall_block;
                    }
                    break;
                }

                case TermKind::TailOrExternal: {
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, bir.external_stmt);
                    break;
                }

                case TermKind::Jump: {
                    if (bir.jump_block.has_value()) {
                        const std::size_t dst = *bir.jump_block;
                        if (stop_block.has_value() && dst == *stop_block) {
                            return;
                        }
                        if (!emitted[dst] && forward_preds[dst] == 1u && back_preds[dst] == 0u && dst > b) {
                            next_b = dst;
                        } else {
                            emit_goto_or_loop_jump(dst, stop_block, bir.term_addr, bir.term_size, indent);
                        }
                    }
                    break;
                }

                case TermKind::Switch: {
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                              std::format("switch ({}) {{", bir.cond_expr));
                    for (const auto& [case_label, target_idx] : bir.switch_cases) {
                        goto_targets.insert(target_idx);
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u,
                                  std::format("{}: goto {};", case_label, block_label_name(target_idx)));
                    }
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                    break;
                }

                case TermKind::CondBranch: {
                    // External taken branch + internal (or truncated) fallthrough.
                    if (!bir.taken_block.has_value()) {
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                  std::format("if ({}) {{", bir.cond_expr));
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u,
                                  bir.external_stmt.empty() ? "return 0;" : bir.external_stmt);
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                        if (bir.fall_block.has_value()) {
                            next_b = *bir.fall_block;
                        } else {
                            emit_truncated_fallthrough(bir.term_addr, bir.term_size, indent);
                        }
                        break;
                    }
                    if (!bir.fall_block.has_value()) {
                        goto_targets.insert(*bir.taken_block);
                        push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                  std::format("if ({}) goto {};",
                                              bir.cond_expr,
                                              block_label_name(*bir.taken_block)));
                        emit_truncated_fallthrough(bir.term_addr, bir.term_size, indent);
                        break;
                    }

                    const std::size_t t = *bir.taken_block;
                    const std::size_t f = *bir.fall_block;

                    // Loop break / continue idioms.
                    if (!loop_stack.empty()) {
                        const LoopContext& lc = loop_stack.back();
                        if (lc.exit_idx.has_value() && t == *lc.exit_idx && !emitted[f]) {
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                      std::format("if ({}) {{", bir.cond_expr));
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u,
                                      "break;");
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                            next_b = f;
                            break;
                        }
                        if (lc.exit_idx.has_value() && f == *lc.exit_idx && !emitted[t]) {
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                      std::format("if ({}) {{", invert_condition(bir.cond_expr)));
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent + 1u,
                                      "break;");
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                            next_b = t;
                            break;
                        }
                    }

                    if (depth < kMaxStructureDepth) {
                        // Half-diamond 1: `if (!cond) { fall_region }` merging into `taken`.
                        if (t > f && (!stop_block.has_value() || t <= *stop_block) &&
                            region_merges_cleanly(f, t)) {
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                      std::format("if ({}) {{", invert_condition(bir.cond_expr)));
                            self(self, f, t, indent + 1u, std::nullopt, depth + 1u);
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                            next_b = t;
                            break;
                        }

                        // Half-diamond 2: `if (cond) { taken_region }` merging into `fall`.
                        if ((!stop_block.has_value() || f <= *stop_block) && region_merges_cleanly(t, f)) {
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                      std::format("if ({}) {{", bir.cond_expr));
                            self(self, t, f, indent + 1u, std::nullopt, depth + 1u);
                            push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                            next_b = f;
                            break;
                        }

                        // Full `if (...) { ... } else { ... }` diamond.
                        if (!emitted[f] && !emitted[t] && f != t &&
                            forward_preds[f] == 1u && forward_preds[t] == 1u &&
                            back_preds[f] == 0u && back_preds[t] == 0u) {
                            const auto merge = find_diamond_merge(f, t, stop_block);
                            if (merge.has_value() ||
                                (region_merges_cleanly(f, std::nullopt) &&
                                 region_merges_cleanly(t, std::nullopt))) {
                                push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                          std::format("if ({}) {{", invert_condition(bir.cond_expr)));
                                self(self, f, merge, indent + 1u, std::nullopt, depth + 1u);
                                push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                                          "} else {");
                                self(self, t, merge, indent + 1u, std::nullopt, depth + 1u);
                                push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent, "}");
                                if (merge.has_value() && (!stop_block.has_value() || *merge != *stop_block)) {
                                    next_b = *merge;
                                }
                                break;
                            }
                        }
                    }

                    // Irreducible / multi-predecessor / depth-bounded fallback: emit conditional goto + fallthrough.
                    goto_targets.insert(t);
                    push_code(bir.term_addr, {CodeRange{bir.term_addr, bir.term_size}}, indent,
                              std::format("if ({}) goto {};", bir.cond_expr, block_label_name(t)));
                    if (!stop_block.has_value() || f != *stop_block) {
                        if (!emitted[f]) {
                            next_b = f;
                        } else {
                            emit_goto_or_loop_jump(f, stop_block, bir.term_addr, bir.term_size, indent);
                        }
                    }
                    break;
                }
            }

            if (next_b.has_value()) {
                b = *next_b;
                suppress_loop_at = std::nullopt;
                continue;
            }
            return;
        }
    };

    emit_region(emit_region, 0u, std::nullopt, 1u, std::nullopt, 0u);

    // Ensure every basic block in `fallback_graph` is emitted exactly once in address order.
    for (std::size_t i = 0u; i < num_blocks; ++i) {
        if (!emitted[i]) {
            emit_region(emit_region, i, std::nullopt, 1u, std::nullopt, 0u);
        }
    }

    if (stop.stop_requested()) {
        return make_status(DecompileStatus::Cancelled, "Decompilation cancelled");
    }

    // Assemble final DecompiledUnit with signature, stack locals, body, and closing brace.
    const bool arch_64 = is_64bit_arch(request.architecture);
    const std::string_view int_type = arch_64 ? "int64_t" : "int32_t";
    const std::uint64_t entry_addr = ir_blocks.front().start_va;
    const std::uint64_t entry_sz = ir_blocks.front().first_insn_size;

    DecompiledUnit unit{
        .status = DecompileStatus::Ready,
        .provider = std::string(kStructuredProvider),
        .diagnostic = std::format(
            "Structured {} basic block{} ({})",
            num_blocks,
            num_blocks == 1u ? "" : "s",
            peelf::to_string(request.architecture)),
        .lines = {},
        .types = request.types,
    };
    unit.lines.reserve(out_items.size() + stack_locals.size() + 4u);

    unit.lines.push_back(DecompiledLine{
        .address = entry_addr,
        .text = std::format("{} {}(void) {{", int_type, func_name),
        .ranges = {CodeRange{entry_addr, entry_sz}},
    });

    for (const std::string& local_var : stack_locals) {
        unit.lines.push_back(DecompiledLine{
            .address = entry_addr,
            .text = std::format("    {} {};", int_type, local_var),
            .ranges = {CodeRange{entry_addr, entry_sz}},
        });
    }
    if (!stack_locals.empty()) {
        unit.lines.push_back(DecompiledLine{
            .address = std::nullopt,
            .text = {},
            .ranges = {},
        });
    }

    for (const OutputItem& item : out_items) {
        const std::size_t clamped_indent = std::min<std::size_t>(item.indent, kMaxIndent);
        if (item.is_label_placeholder) {
            if (!goto_targets.contains(item.block_idx)) {
                continue;
            }
            const std::string pad(clamped_indent * 4u, ' ');
            unit.lines.push_back(DecompiledLine{
                .address = item.address,
                .text = std::format("{}{}:", pad, block_label_name(item.block_idx)),
                .ranges = item.ranges,
            });
            continue;
        }
        const std::string pad(clamped_indent * 4u, ' ');
        unit.lines.push_back(DecompiledLine{
            .address = item.address,
            .text = pad + item.text,
            .ranges = item.ranges,
        });
    }

    const BlockIR& last_ir = ir_blocks.back();
    unit.lines.push_back(DecompiledLine{
        .address = last_ir.term_addr != 0u ? last_ir.term_addr : last_ir.start_va,
        .text = "}",
        .ranges = {CodeRange{
            last_ir.term_addr != 0u ? last_ir.term_addr : last_ir.start_va,
            std::max<std::uint64_t>(1u, last_ir.term_size)}},
    });

    return unit;
}

namespace {

[[nodiscard]] std::string read_env_var(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t len = 0u;
    if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) {
        return {};
    }
    std::string out(value);
    std::free(value);
    return out;
#else
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string{};
#endif
}

[[nodiscard]] bool is_executable_file(const std::filesystem::path& candidate) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(candidate, ec)) {
        return false;
    }
#ifdef _WIN32
    return true;
#else
    return ::access(candidate.c_str(), X_OK) == 0;
#endif
}

[[nodiscard]] std::filesystem::path probe_candidate_extensions(const std::filesystem::path& base) {
    if (is_executable_file(base)) {
        return base;
    }
#ifdef _WIN32
    if (!base.has_extension()) {
        for (const char* ext : {".exe", ".py", ".cmd", ".bat"}) {
            std::filesystem::path with_ext = base;
            with_ext += ext;
            if (is_executable_file(with_ext)) {
                return with_ext;
            }
        }
    }
#else
    if (!base.has_extension()) {
        std::filesystem::path with_py = base;
        with_py += ".py";
        if (is_executable_file(with_py)) {
            return with_py;
        }
    }
#endif
    return {};
}

[[nodiscard]] std::optional<std::uint64_t> parse_retdec_comment_address(std::string_view line) noexcept {
    const std::size_t comment = line.find("//");
    if (comment == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view tail = line.substr(comment + 2u);
    const std::size_t hex_pos = tail.find("0x");
    if (hex_pos == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t end = hex_pos + 2u;
    while (end < tail.size() && std::isxdigit(static_cast<unsigned char>(tail[end])) != 0) {
        ++end;
    }
    if (end == hex_pos + 2u) {
        return std::nullopt;
    }
    std::uint64_t addr = 0u;
    const std::string_view digits = tail.substr(hex_pos + 2u, end - (hex_pos + 2u));
    const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), addr, 16);
    if (ec != std::errc{} || ptr != digits.data() + digits.size()) {
        return std::nullopt;
    }
    return addr;
}

}  // namespace

std::filesystem::path RetDecDecompiler::find_on_path(std::filesystem::path preferred) {
    if (preferred.empty()) {
        preferred = "retdec-decompiler";
    }
    if (preferred.has_parent_path()) {
        return probe_candidate_extensions(preferred);
    }

    const std::string path_env = read_env_var("PATH");
    if (path_env.empty()) {
        return {};
    }

#ifdef _WIN32
    constexpr char kPathSep = ';';
#else
    constexpr char kPathSep = ':';
#endif

    std::size_t start = 0u;
    while (start <= path_env.size()) {
        const std::size_t delim = path_env.find(kPathSep, start);
        const std::size_t end = (delim == std::string::npos) ? path_env.size() : delim;
        std::string_view entry(path_env.data() + start, end - start);
        if (entry.size() >= 2u && entry.front() == '"' && entry.back() == '"') {
            entry.remove_prefix(1u);
            entry.remove_suffix(1u);
        }
        if (!entry.empty()) {
            const std::filesystem::path found =
                probe_candidate_extensions(std::filesystem::path(entry) / preferred);
            if (!found.empty()) {
                return found;
            }
        }
        if (delim == std::string::npos) {
            break;
        }
        start = delim + 1u;
    }
    return {};
}

DecompiledUnit RetDecDecompiler::decompile(
    const DecompileRequest& request,
    std::stop_token stop) const {
    auto failure = [](DecompileStatus status, std::string message) {
        return DecompiledUnit{
            .status = status,
            .provider = std::string(kRetDecProvider),
            .diagnostic = std::move(message),
            .lines = {},
            .types = {},
        };
    };

    if (stop.stop_requested()) {
        return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    }
    if (request.architecture == peelf::Architecture::Unknown) {
        return failure(DecompileStatus::Unsupported, "Unknown CPU architecture");
    }

    const std::filesystem::path exe = find_on_path(executable_);
    if (exe.empty()) {
        return failure(
            DecompileStatus::Unavailable,
            "retdec-decompiler was not found on PATH. Built-in Structured Pseudo-C is available immediately.");
    }

    if (request.image_bytes.empty()) {
        return failure(DecompileStatus::Failed, "Empty binary snapshot");
    }

    const int effective_timeout = std::clamp(timeout_seconds_, 5, 3600);

    static std::atomic<std::uint64_t> serial{0u};
    const std::filesystem::path workspace_dir =
        std::filesystem::temp_directory_path() /
        std::format(
            "peelf-retdec-{}-{}",
            std::chrono::steady_clock::now().time_since_epoch().count(),
            ++serial);

    std::error_code ec;
    if (!std::filesystem::create_directory(workspace_dir, ec)) {
        return failure(DecompileStatus::Failed, "Cannot create RetDec workspace");
    }
    struct ScopedWorkspace {
        std::filesystem::path path;
        explicit ScopedWorkspace(std::filesystem::path p) : path(std::move(p)) {}
        ScopedWorkspace(const ScopedWorkspace&) = delete;
        ScopedWorkspace& operator=(const ScopedWorkspace&) = delete;
        ~ScopedWorkspace() {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } cleanup{workspace_dir};

    const std::filesystem::path input = workspace_dir / "input.bin";
    const std::filesystem::path output_c = workspace_dir / "output.c";
    {
        std::ofstream out_bin(input, std::ios::binary);
        out_bin.write(
            reinterpret_cast<const char*>(request.image_bytes.data()),
            static_cast<std::streamsize>(request.image_bytes.size()));
        out_bin.close();
        if (!out_bin) {
            return failure(DecompileStatus::Failed, "Cannot write binary snapshot for RetDec");
        }
    }

    const std::uint64_t range_span = std::max<std::uint64_t>(16u, request.function_size);
    const std::uint64_t range_end =
        request.address > std::numeric_limits<std::uint64_t>::max() - range_span
            ? std::numeric_limits<std::uint64_t>::max()
            : request.address + range_span;

    const std::vector<std::string> args{
        input.string(),
        "-o",
        output_c.string(),
        "--select-ranges",
        std::format("0x{:x}-0x{:x}", request.address, range_end),
    };

    const BackendProcessResult proc =
        runner_.run(exe, args, std::chrono::seconds(effective_timeout), stop);
    if (proc.cancelled) {
        return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    }
    if (proc.timed_out) {
        return failure(
            DecompileStatus::Timeout,
            std::format("RetDec exceeded the {}-second deadline.", effective_timeout));
    }
    if (!std::filesystem::is_regular_file(output_c, ec) || proc.exit_code != 0) {
        return failure(
            proc.exit_code < 0 ? DecompileStatus::Unavailable : DecompileStatus::Failed,
            std::format("RetDec failed (exit {}).", proc.exit_code));
    }

    const std::uintmax_t file_sz = std::filesystem::file_size(output_c, ec);
    if (ec || file_sz == 0u || file_sz > 4u * 1024u * 1024u) {
        return failure(DecompileStatus::Failed, "Invalid RetDec C output size");
    }

    std::ifstream in_c(output_c, std::ios::binary);
    std::string content(static_cast<std::size_t>(file_sz), '\0');
    if (!in_c.read(content.data(), static_cast<std::streamsize>(file_sz))) {
        return failure(DecompileStatus::Failed, "Cannot read RetDec C output");
    }

    DecompiledUnit unit{
        .status = DecompileStatus::Ready,
        .provider = std::string(kRetDecProvider),
        .diagnostic = "Decompiled with RetDec",
        .lines = {},
        .types = request.types,
    };

    std::istringstream stream(content);
    std::string raw_line;
    std::optional<std::uint64_t> active_addr = request.address;
    const std::uint64_t step_sz = default_insn_size(request.architecture, request.thumb);

    while (std::getline(stream, raw_line)) {
        if (!raw_line.empty() && raw_line.back() == '\r') {
            raw_line.pop_back();
        }
        if (const auto comment_addr = parse_retdec_comment_address(raw_line)) {
            active_addr = comment_addr;
        }
        const std::string_view trimmed = trim_sv(raw_line);
        const bool attach_addr =
            active_addr.has_value() && !trimmed.empty() && !trimmed.starts_with('#');
        unit.lines.push_back(DecompiledLine{
            .address = attach_addr ? active_addr : std::nullopt,
            .text = std::move(raw_line),
            .ranges = attach_addr
                          ? std::vector<CodeRange>{CodeRange{*active_addr, std::max<std::uint64_t>(1u, step_sz)}}
                          : std::vector<CodeRange>{},
        });
    }

    if (unit.lines.empty()) {
        return failure(DecompileStatus::NoFunction, "RetDec produced empty output");
    }
    return unit;
}

}  // namespace viewer
