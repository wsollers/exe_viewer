#include "analysis/function_index.hpp"

#include "disasm/disassembler.hpp"

#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {

constexpr std::size_t kMaxSectionScanBytes = 2u * 1024u * 1024u;
constexpr std::size_t kDisasmChunkBytes = 64u * 1024u;
constexpr std::uint64_t kMaxInferredFunctionSize = 256u * 1024u;

constexpr std::uint8_t kElfSttObject = 1u;
constexpr std::uint8_t kElfSttFunc = 2u;
constexpr std::uint8_t kElfSttSection = 3u;
constexpr std::uint8_t kElfSttFile = 4u;
constexpr std::uint8_t kElfSttCommon = 5u;
constexpr std::uint8_t kElfSttTls = 6u;
constexpr std::uint8_t kElfSttGnuIfunc = 10u;

constexpr std::uint32_t kElfPtLoad = 1u;

constexpr std::uint64_t kElfDtInit = 12u;
constexpr std::uint64_t kElfDtFini = 13u;
constexpr std::uint64_t kElfDtInitArray = 25u;
constexpr std::uint64_t kElfDtFiniArray = 26u;
constexpr std::uint64_t kElfDtInitArraySz = 27u;
constexpr std::uint64_t kElfDtFiniArraySz = 28u;
constexpr std::uint64_t kElfDtPreinitArray = 32u;
constexpr std::uint64_t kElfDtPreinitArraySz = 33u;

[[nodiscard]] bool is_elf_mapping_symbol(std::string_view name) noexcept {
    return name.starts_with("$a") || name.starts_with("$d") ||
           name.starts_with("$t") || name.starts_with("$x");
}

[[nodiscard]] std::uint8_t origin_priority(FunctionOrigin origin) noexcept {
    switch (origin) {
        case FunctionOrigin::DebugInfo:             return 0u;
        case FunctionOrigin::SymbolTable:           return 1u;
        case FunctionOrigin::ExportedEntry:         return 2u;
        case FunctionOrigin::EntryPoint:            return 3u;
        case FunctionOrigin::InitFiniOrTlsCallback: return 4u;
        case FunctionOrigin::PeRuntimePdata:        return 5u;
        case FunctionOrigin::CallTargetDiscovery:   return 6u;
    }
    return 7u;
}

[[nodiscard]] FunctionOrigin map_symbol_source(SymbolSource source) noexcept {
    switch (source) {
        case SymbolSource::DebugSymbol: return FunctionOrigin::DebugInfo;
        case SymbolSource::Export:      return FunctionOrigin::ExportedEntry;
        case SymbolSource::EntryPoint:  return FunctionOrigin::EntryPoint;
        case SymbolSource::ImageSymbol: return FunctionOrigin::SymbolTable;
        case SymbolSource::Import:      return FunctionOrigin::SymbolTable;
    }
    return FunctionOrigin::SymbolTable;
}

[[nodiscard]] bool is_generic_name(std::string_view name) noexcept {
    return name.empty() ||
           name == "Entry Point" ||
           name == "<export>" ||
           name.starts_with("sub_") ||
           name.starts_with("init_fn_") ||
           name.starts_with("fini_fn_") ||
           name.starts_with("tls_callback_");
}

[[nodiscard]] const peelf::Section* find_executable_section(
    const peelf::IBinaryImage& image,
    std::uint64_t virtual_address) noexcept {
    for (const peelf::Section& sec : image.sections()) {
        if (!sec.executable) {
            continue;
        }
        const std::uint64_t span = sec.virtual_size != 0u ? sec.virtual_size : sec.file_size;
        if (span == 0u) {
            continue;
        }
        if (virtual_address >= sec.virtual_address &&
            virtual_address - sec.virtual_address < span) {
            return &sec;
        }
    }
    return nullptr;
}

[[nodiscard]] const peelf::Section* find_any_section(
    const peelf::IBinaryImage& image,
    std::uint64_t virtual_address) noexcept {
    for (const peelf::Section& sec : image.sections()) {
        const std::uint64_t span = sec.virtual_size != 0u ? sec.virtual_size : sec.file_size;
        if (span == 0u) {
            continue;
        }
        if (virtual_address >= sec.virtual_address &&
            virtual_address - sec.virtual_address < span) {
            return &sec;
        }
    }
    return nullptr;
}

[[nodiscard]] const peelf::Segment* find_executable_segment(
    const peelf::IBinaryImage& image,
    std::uint64_t virtual_address) noexcept {
    for (const peelf::Segment& seg : image.segments()) {
        if (!seg.executable) {
            continue;
        }
        const std::uint64_t span = seg.virtual_size != 0u ? seg.virtual_size : seg.file_size;
        if (span == 0u) {
            continue;
        }
        if (virtual_address >= seg.virtual_address &&
            virtual_address - seg.virtual_address < span) {
            return &seg;
        }
    }
    return nullptr;
}

[[nodiscard]] bool is_executable_address(
    const peelf::IBinaryImage& image,
    std::uint64_t virtual_address) noexcept {
    if (virtual_address == 0u) {
        return false;
    }
    const std::uint64_t lookup_va =
        image.architecture() == peelf::Architecture::ARM
            ? (virtual_address & ~std::uint64_t{1u})
            : virtual_address;
    if (find_executable_section(image, lookup_va) != nullptr) {
        return true;
    }
    if (image.sections().empty() && find_executable_segment(image, lookup_va) != nullptr) {
        return true;
    }
    // Some ELF binaries have section headers stripped selectively while segments mark code RX.
    if (find_any_section(image, lookup_va) == nullptr &&
        find_executable_segment(image, lookup_va) != nullptr) {
        return true;
    }
    return false;
}

[[nodiscard]] std::string resolve_section_name(
    const peelf::IBinaryImage& image,
    std::uint64_t virtual_address) {
    const std::uint64_t lookup_va =
        image.architecture() == peelf::Architecture::ARM
            ? (virtual_address & ~std::uint64_t{1u})
            : virtual_address;
    if (const peelf::Section* exec_sec = find_executable_section(image, lookup_va)) {
        return exec_sec->name;
    }
    if (const peelf::Section* any_sec = find_any_section(image, lookup_va)) {
        return any_sec->name;
    }
    if (find_executable_segment(image, lookup_va) != nullptr) {
        return "PT_LOAD";
    }
    return {};
}

[[nodiscard]] bool detect_is_thunk(
    std::string_view name,
    std::string_view section_name,
    std::optional<std::uint64_t> file_offset,
    std::span<const std::uint8_t> image_bytes,
    peelf::Architecture arch) noexcept {
    if (section_name == ".plt" || section_name == ".plt.got" ||
        section_name == ".plt.sec" || section_name == ".MIPS.stubs") {
        return true;
    }
    if (name.ends_with("@plt") || name.starts_with("j_") || name.starts_with("__imp_")) {
        return true;
    }
    if (file_offset && !image_bytes.empty() && *file_offset < image_bytes.size()) {
        const std::size_t off = static_cast<std::size_t>(*file_offset);
        const std::size_t rem = image_bytes.size() - off;
        if ((arch == peelf::Architecture::X86 || arch == peelf::Architecture::X86_64) && rem >= 6u) {
            // FF 25 xx xx xx xx : jmp [rip+disp32] / jmp [disp32]
            if (image_bytes[off] == 0xFFu && image_bytes[off + 1u] == 0x25u) {
                return true;
            }
            // F3 0F 1E FA FF 25 ... : endbr64; jmp [rip+disp32]
            if (rem >= 10u &&
                image_bytes[off] == 0xF3u && image_bytes[off + 1u] == 0x0Fu &&
                image_bytes[off + 2u] == 0x1Eu && image_bytes[off + 3u] == 0xFAu &&
                image_bytes[off + 4u] == 0xFFu && image_bytes[off + 5u] == 0x25u) {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] std::optional<Architecture> to_disasm_arch(peelf::Architecture arch) noexcept {
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
        case peelf::Architecture::Unknown:   return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] Endianness to_disasm_endian(peelf::Endianness endian) noexcept {
    return endian == peelf::Endianness::Big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] std::size_t instruction_alignment(peelf::Architecture arch, bool thumb_mode) noexcept {
    switch (arch) {
        case peelf::Architecture::X86:
        case peelf::Architecture::X86_64:
            return 1u;
        case peelf::Architecture::ARM:
            return thumb_mode ? 2u : 4u;
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:
            return 2u;
        case peelf::Architecture::ARM64:
        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64:
        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64:
        case peelf::Architecture::Unknown:
            return 4u;
    }
    return 4u;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex_token(std::string_view token) noexcept {
    if (token.starts_with("0x") || token.starts_with("0X")) {
        token.remove_prefix(2u);
    }
    if (token.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0u;
    const auto [end_ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (ec != std::errc{} || end_ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::int64_t> parse_last_signed_integer(std::string_view operands) noexcept {
    std::optional<std::int64_t> last;
    for (std::size_t i = 0u; i < operands.size();) {
        if (operands[i] == '#') {
            ++i;
            continue;
        }
        const bool negative = operands[i] == '-';
        const std::size_t sign_pos = i;
        if (negative) {
            ++i;
        }
        if (i >= operands.size() || std::isdigit(static_cast<unsigned char>(operands[i])) == 0) {
            ++i;
            continue;
        }
        // Skip register names such as x0, r12, s0, a0, cr0.
        if (sign_pos > 0u) {
            const unsigned char prev = static_cast<unsigned char>(operands[sign_pos - 1u]);
            if (std::isalpha(prev) != 0 || prev == '_' || prev == '$') {
                while (i < operands.size() && std::isalnum(static_cast<unsigned char>(operands[i])) != 0) {
                    ++i;
                }
                continue;
            }
        }
        int base = 10;
        if (i + 1u < operands.size() && operands[i] == '0' &&
            (operands[i + 1u] == 'x' || operands[i + 1u] == 'X')) {
            base = 16;
            i += 2u;
        }
        const std::size_t digits_begin = i;
        while (i < operands.size() &&
               (base == 16 ? std::isxdigit(static_cast<unsigned char>(operands[i])) != 0
                           : std::isdigit(static_cast<unsigned char>(operands[i])) != 0)) {
            ++i;
        }
        if (digits_begin == i) {
            continue;
        }
        std::uint64_t mag = 0u;
        const std::string_view digits = operands.substr(digits_begin, i - digits_begin);
        const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), mag, base);
        if (ec == std::errc{} && ptr == digits.data() + digits.size() &&
            mag <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            const std::int64_t signed_val = static_cast<std::int64_t>(mag);
            last = negative ? -signed_val : signed_val;
        }
    }
    return last;
}

[[nodiscard]] std::optional<std::uint64_t> parse_immediate_call_operand(
    const Instruction& insn,
    peelf::Architecture arch) noexcept {
    if (insn.branch_target.has_value()) {
        return insn.branch_target;
    }
    const std::string_view ops = insn.operands;
    if (ops.find('[') != std::string_view::npos || ops.find('(') != std::string_view::npos) {
        return std::nullopt;
    }
    if (const std::size_t hex_pos = ops.find("0x"); hex_pos != std::string_view::npos) {
        // Ensure not negative relative offset like -0x20 unless RISC-V/MIPS PC-relative.
        if (hex_pos == 0u || ops[hex_pos - 1u] != '-') {
            std::size_t end = hex_pos + 2u;
            while (end < ops.size() && std::isxdigit(static_cast<unsigned char>(ops[end])) != 0) {
                ++end;
            }
            if (const auto parsed = parse_hex_token(ops.substr(hex_pos, end - hex_pos))) {
                if (arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) {
                    std::uint64_t target = insn.address + *parsed;
                    if (arch == peelf::Architecture::RISCV32) {
                        target &= 0xFFFF'FFFFULL;
                    }
                    return target;
                }
                return parsed;
            }
        }
    }
    const auto dec = parse_last_signed_integer(ops);
    if (!dec.has_value()) {
        return std::nullopt;
    }
    if (arch == peelf::Architecture::RISCV32 || arch == peelf::Architecture::RISCV64) {
        const std::uint64_t target =
            insn.address + static_cast<std::uint64_t>(*dec);
        return arch == peelf::Architecture::RISCV32 ? (target & 0xFFFF'FFFFULL) : target;
    }
    if (*dec <= 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(*dec);
}

[[nodiscard]] std::optional<std::uint64_t> resolve_auipc_jalr_pair(
    const Instruction& prev,
    const Instruction& curr,
    peelf::Architecture arch) noexcept {
    if ((arch != peelf::Architecture::RISCV32 && arch != peelf::Architecture::RISCV64) ||
        prev.mnemonic != "auipc" || curr.mnemonic != "jalr") {
        return std::nullopt;
    }
    const auto hi = parse_last_signed_integer(prev.operands);
    const auto lo = parse_last_signed_integer(curr.operands);
    if (!hi || !lo) {
        return std::nullopt;
    }
    const std::uint64_t page = static_cast<std::uint64_t>(*hi) << 12u;
    std::uint64_t target = prev.address + page + static_cast<std::uint64_t>(*lo);
    if (arch == peelf::Architecture::RISCV32) {
        target &= 0xFFFF'FFFFULL;
    }
    return target;
}

[[nodiscard]] bool is_direct_call_mnemonic(const Instruction& insn) noexcept {
    if (insn.flow == InstructionFlow::Call) {
        return true;
    }
    const std::string_view m = insn.mnemonic;
    return m == "call" || m == "bl" || m == "blx" || m == "bal" ||
           m == "jal" || m == "c.jal";
}

void upsert_function(
    std::map<std::uint64_t, FunctionEntry>& by_va,
    FunctionEntry candidate) {
    if (candidate.virtual_address == 0u) {
        return;
    }
    auto [it, inserted] = by_va.emplace(candidate.virtual_address, std::move(candidate));
    if (inserted) {
        return;
    }

    FunctionEntry& cur = it->second;
    const std::uint8_t cand_prio = origin_priority(candidate.origin);
    const std::uint8_t cur_prio = origin_priority(cur.origin);

    const bool cand_has_real_name = !is_generic_name(candidate.name);
    const bool cur_has_real_name = !is_generic_name(cur.name);

    if (cand_prio < cur_prio) {
        cur.origin = candidate.origin;
        if (cand_has_real_name || !cur_has_real_name) {
            cur.name = std::move(candidate.name);
        }
    } else if (!cur_has_real_name && cand_has_real_name) {
        cur.name = std::move(candidate.name);
    }

    if (cur.size == 0u && candidate.size != 0u) {
        cur.size = candidate.size;
    } else if (candidate.origin == FunctionOrigin::PeRuntimePdata &&
               candidate.size != 0u && cur.size == 0u) {
        cur.size = candidate.size;
    }

    if (!cur.file_offset.has_value() && candidate.file_offset.has_value()) {
        cur.file_offset = candidate.file_offset;
    }
    if (cur.section_name.empty() && !candidate.section_name.empty()) {
        cur.section_name = std::move(candidate.section_name);
    }
    if (cur.library.empty() && !candidate.library.empty()) {
        cur.library = std::move(candidate.library);
    }
    cur.is_thunk = cur.is_thunk || candidate.is_thunk;
}

[[nodiscard]] FunctionEntry build_entry(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> image_bytes,
    std::string name,
    std::uint64_t va,
    std::uint64_t size,
    FunctionOrigin origin,
    std::string library = {},
    std::optional<std::uint64_t> known_offset = std::nullopt) {
    const std::uint64_t lookup_va =
        image.architecture() == peelf::Architecture::ARM
            ? (va & ~std::uint64_t{1u})
            : va;
    std::optional<std::uint64_t> file_off =
        known_offset.has_value() ? known_offset : image.virtual_address_to_file_offset(lookup_va);
    std::string sec_name = resolve_section_name(image, lookup_va);
    const bool thunk = detect_is_thunk(name, sec_name, file_off, image_bytes, image.architecture());
    return FunctionEntry{
        .name = std::move(name),
        .virtual_address = va,
        .file_offset = file_off,
        .size = size,
        .origin = origin,
        .section_name = std::move(sec_name),
        .library = std::move(library),
        .is_thunk = thunk,
    };
}

void enrich_symbol_index(
    const peelf::IBinaryImage& image,
    SymbolIndex& symbol_index,
    const std::string& name,
    std::uint64_t va,
    std::uint64_t size) {
    const std::uint64_t lookup_va =
        image.architecture() == peelf::Architecture::ARM
            ? (va & ~std::uint64_t{1u})
            : va;
    symbol_index.add_discovered_symbol(SymbolRecord{
        .name = name,
        .source = SymbolSource::ImageSymbol,
        .source_index = 0u,
        .virtual_address = va,
        .file_offset = image.virtual_address_to_file_offset(lookup_va),
        .size = size,
        .dynamic = false,
        .external = false,
        .function = true,
        .library = {},
    });
}

}  // namespace

FunctionIndex FunctionIndex::discover(
    const peelf::IBinaryImage& image,
    SymbolIndex& symbol_index,
    std::span<const std::uint8_t> image_bytes,
    bool thumb_mode) {
    FunctionIndex index;
    std::map<std::uint64_t, FunctionEntry> by_va;

    // Build ELF symbol type map (VA -> st_type) so STT_FUNC / STT_GNU_IFUNC are recognized
    // and non-code ELF symbols (STT_OBJECT, STT_TLS, STT_SECTION, STT_FILE) are excluded.
    std::map<std::uint64_t, std::uint8_t> elf_sym_types;
    if (image.format() == peelf::Format::ELF) {
        for (const peelf::ElfSymbol& es : image.elf_symbols()) {
            if (es.value == 0u || es.section_index == 0u || is_elf_mapping_symbol(es.name)) {
                continue;
            }
            const std::uint8_t st_type = static_cast<std::uint8_t>(es.type & 0x0Fu);
            auto [it, inserted] = elf_sym_types.emplace(es.value, st_type);
            if (!inserted && (st_type == kElfSttFunc || st_type == kElfSttGnuIfunc)) {
                it->second = st_type;
            }
        }
    }

    // 1. SymbolTable / DebugInfo / existing SymbolIndex records.
    const std::vector<SymbolRecord> existing_records(
        symbol_index.records().begin(),
        symbol_index.records().end());
    for (const SymbolRecord& rec : existing_records) {
        if (rec.source == SymbolSource::Import || rec.external || !rec.virtual_address.has_value()) {
            continue;
        }
        const std::uint64_t va = *rec.virtual_address;
        if (va == 0u || rec.name.empty() || is_elf_mapping_symbol(rec.name)) {
            continue;
        }
        if (rec.function.has_value() && !*rec.function) {
            continue;
        }

        bool elf_is_func = false;
        bool elf_is_non_func = false;
        if (image.format() == peelf::Format::ELF) {
            std::optional<std::uint8_t> sym_type;
            if (rec.source == SymbolSource::ImageSymbol &&
                rec.source_index < image.symbols().size()) {
                sym_type = static_cast<std::uint8_t>(
                    image.symbols()[static_cast<std::size_t>(rec.source_index)].type & 0x0Fu);
            } else if (const auto it = elf_sym_types.find(va); it != elf_sym_types.end()) {
                sym_type = it->second;
            }
            if (sym_type.has_value()) {
                elf_is_func = (*sym_type == kElfSttFunc || *sym_type == kElfSttGnuIfunc);
                elf_is_non_func = (*sym_type == kElfSttObject || *sym_type == kElfSttSection ||
                                   *sym_type == kElfSttFile || *sym_type == kElfSttCommon ||
                                   *sym_type == kElfSttTls);
            }
        }
        if (elf_is_non_func) {
            continue;
        }

        const bool is_debug_func =
            rec.source == SymbolSource::DebugSymbol && rec.function.value_or(false);
        const bool has_code =
            symbol_has_code(image, rec) || is_executable_address(image, va);
        if (!has_code && !is_debug_func && !elf_is_func) {
            continue;
        }

        // SymbolIndex assigns size = 1 as a placeholder for Entry Point; keep 0 so real bounds backfill.
        const std::uint64_t effective_size =
            (rec.source == SymbolSource::EntryPoint && rec.size <= 1u) ? 0u : rec.size;

        upsert_function(
            by_va,
            build_entry(
                image,
                image_bytes,
                rec.name,
                va,
                effective_size,
                map_symbol_source(rec.source),
                rec.library,
                rec.file_offset));
    }

    // Also inspect raw ELF symbols in case any STT_FUNC symbol was not yet indexed.
    if (image.format() == peelf::Format::ELF) {
        for (const peelf::ElfSymbol& es : image.elf_symbols()) {
            const std::uint8_t st_type = static_cast<std::uint8_t>(es.type & 0x0Fu);
            if (es.value == 0u || es.section_index == 0u || es.name.empty() ||
                is_elf_mapping_symbol(es.name) ||
                (st_type != kElfSttFunc && st_type != kElfSttGnuIfunc)) {
                continue;
            }
            upsert_function(
                by_va,
                build_entry(
                    image,
                    image_bytes,
                    es.name,
                    es.value,
                    es.size,
                    FunctionOrigin::SymbolTable));
        }
    }

    // 2. Entry point.
    if (const std::uint64_t ep = image.entry_point();
        ep != 0u && is_executable_address(image, ep)) {
        upsert_function(
            by_va,
            build_entry(
                image,
                image_bytes,
                "Entry Point",
                ep,
                0u,
                FunctionOrigin::EntryPoint));
    }

    // 3. Exports in executable sections/segments (excluding forwarders).
    for (const peelf::ExportEntry& exp : image.exports()) {
        if (exp.virtual_address == 0u || !exp.forwarder.empty() ||
            !is_executable_address(image, exp.virtual_address)) {
            continue;
        }
        std::string exp_name = exp.name.empty()
                                   ? std::format("ord_{}", exp.ordinal)
                                   : exp.name;
        upsert_function(
            by_va,
            build_entry(
                image,
                image_bytes,
                std::move(exp_name),
                exp.virtual_address,
                0u,
                FunctionOrigin::ExportedEntry));
    }

    // 4. PE .pdata runtime functions (unwind directory).
    for (const peelf::PeRuntimeFunction& rf : image.pe_runtime_functions()) {
        if (rf.end_address_rva <= rf.begin_address_rva) {
            continue;
        }
        const std::uint64_t begin_rva = static_cast<std::uint64_t>(rf.begin_address_rva);
        if (image.image_base() > std::numeric_limits<std::uint64_t>::max() - begin_rva) {
            continue;
        }
        const std::uint64_t va = image.image_base() + begin_rva;
        const std::uint64_t fn_size =
            static_cast<std::uint64_t>(rf.end_address_rva - rf.begin_address_rva);

        if (auto it = by_va.find(va); it != by_va.end()) {
            if (it->second.size == 0u) {
                it->second.size = fn_size;
            }
            continue;
        }

        if (!is_executable_address(image, va) &&
            !image.virtual_address_to_file_offset(va).has_value()) {
            continue;
        }

        std::string generated_name = std::format("sub_{:X}", va);
        enrich_symbol_index(image, symbol_index, generated_name, va, fn_size);
        upsert_function(
            by_va,
            build_entry(
                image,
                image_bytes,
                std::move(generated_name),
                va,
                fn_size,
                FunctionOrigin::PeRuntimePdata));
    }

    // 5. Init / Fini / TLS Callbacks.
    if (const peelf::PeTlsDirectory* tls = image.pe_tls_directory(); tls != nullptr) {
        for (std::size_t idx = 0u; idx < tls->callbacks.size(); ++idx) {
            const std::uint64_t cb_va = tls->callbacks[idx];
            if (cb_va == 0u || !is_executable_address(image, cb_va)) {
                continue;
            }
            std::string cb_name = std::format("tls_callback_{}_{:X}", idx, cb_va);
            enrich_symbol_index(image, symbol_index, cb_name, cb_va, 0u);
            upsert_function(
                by_va,
                build_entry(
                    image,
                    image_bytes,
                    std::move(cb_name),
                    cb_va,
                    0u,
                    FunctionOrigin::InitFiniOrTlsCallback));
        }
    }

    if (image.format() == peelf::Format::ELF) {
        std::size_t init_idx = 0u;
        std::size_t fini_idx = 0u;
        bool saw_init_sec = false;
        bool saw_fini_sec = false;
        bool saw_preinit_arr = false;
        bool saw_init_arr = false;
        bool saw_fini_arr = false;

        const peelf::TargetLayout layout = peelf::TargetLayout::from_image(image);
        const peelf::EndianReader reader(image_bytes, layout);
        const std::size_t ptr_size = reader.pointer_size();

        const auto register_elf_callback = [&](std::uint64_t raw_va,
                                               std::uint64_t known_size,
                                               bool is_fini) {
            if (raw_va == 0u || raw_va == std::numeric_limits<std::uint64_t>::max() ||
                (!image.is_64bit() && raw_va == 0xFFFF'FFFFULL)) {
                return;
            }
            std::uint64_t fn_va = raw_va;
            if (image.architecture() == peelf::Architecture::ARM &&
                (fn_va & 1u) != 0u &&
                !by_va.contains(fn_va) &&
                symbol_index.find_exact_address(fn_va) == nullptr) {
                fn_va &= ~std::uint64_t{1u};
            }
            if (!is_executable_address(image, fn_va)) {
                return;
            }
            const std::size_t ordinal = is_fini ? fini_idx++ : init_idx++;
            std::string fn_name = is_fini
                                      ? std::format("fini_fn_{}_{:X}", ordinal, fn_va)
                                      : std::format("init_fn_{}_{:X}", ordinal, fn_va);
            enrich_symbol_index(image, symbol_index, fn_name, fn_va, known_size);
            upsert_function(
                by_va,
                build_entry(
                    image,
                    image_bytes,
                    std::move(fn_name),
                    fn_va,
                    known_size,
                    FunctionOrigin::InitFiniOrTlsCallback));
        };

        const auto scan_pointer_array = [&](std::uint64_t file_offset,
                                            std::uint64_t byte_length,
                                            bool is_fini) {
            if (image_bytes.empty() || ptr_size == 0u ||
                file_offset >= image_bytes.size()) {
                return;
            }
            const std::size_t start = static_cast<std::size_t>(file_offset);
            const std::size_t max_avail = image_bytes.size() - start;
            const std::size_t capped_len = static_cast<std::size_t>(
                std::min<std::uint64_t>(byte_length, static_cast<std::uint64_t>(max_avail)));
            for (std::size_t off = 0u; off + ptr_size <= capped_len; off += ptr_size) {
                const auto ptr = reader.read_pointer(start + off);
                if (!ptr.has_value()) {
                    break;
                }
                register_elf_callback(*ptr, 0u, is_fini);
            }
        };

        for (const peelf::Section& sec : image.sections()) {
            const std::uint64_t sec_span =
                sec.virtual_size != 0u ? sec.virtual_size : sec.file_size;
            if (sec.name == ".init" && sec.virtual_address != 0u && sec_span != 0u) {
                saw_init_sec = true;
                register_elf_callback(sec.virtual_address, sec_span, false);
            } else if (sec.name == ".fini" && sec.virtual_address != 0u && sec_span != 0u) {
                saw_fini_sec = true;
                register_elf_callback(sec.virtual_address, sec_span, true);
            } else if (sec.name == ".preinit_array") {
                saw_preinit_arr = true;
                scan_pointer_array(sec.file_offset, sec.file_size != 0u ? sec.file_size : sec.virtual_size, false);
            } else if (sec.name == ".init_array") {
                saw_init_arr = true;
                scan_pointer_array(sec.file_offset, sec.file_size != 0u ? sec.file_size : sec.virtual_size, false);
            } else if (sec.name == ".fini_array") {
                saw_fini_arr = true;
                scan_pointer_array(sec.file_offset, sec.file_size != 0u ? sec.file_size : sec.virtual_size, true);
            }
        }

        // Fallback to PT_DYNAMIC tags if section headers were stripped.
        if (!image.elf_dynamic_entries().empty()) {
            std::optional<std::uint64_t> dt_init;
            std::optional<std::uint64_t> dt_fini;
            std::optional<std::uint64_t> dt_preinit_va;
            std::uint64_t dt_preinit_sz = 0u;
            std::optional<std::uint64_t> dt_init_arr_va;
            std::uint64_t dt_init_arr_sz = 0u;
            std::optional<std::uint64_t> dt_fini_arr_va;
            std::uint64_t dt_fini_arr_sz = 0u;

            for (const peelf::ElfDynamicEntry& dyn : image.elf_dynamic_entries()) {
                switch (dyn.tag) {
                    case kElfDtInit:           dt_init = dyn.value; break;
                    case kElfDtFini:           dt_fini = dyn.value; break;
                    case kElfDtPreinitArray:   dt_preinit_va = dyn.value; break;
                    case kElfDtPreinitArraySz: dt_preinit_sz = dyn.value; break;
                    case kElfDtInitArray:      dt_init_arr_va = dyn.value; break;
                    case kElfDtInitArraySz:    dt_init_arr_sz = dyn.value; break;
                    case kElfDtFiniArray:      dt_fini_arr_va = dyn.value; break;
                    case kElfDtFiniArraySz:    dt_fini_arr_sz = dyn.value; break;
                    default: break;
                }
            }

            if (!saw_init_sec && dt_init.has_value()) {
                register_elf_callback(*dt_init, 0u, false);
            }
            if (!saw_fini_sec && dt_fini.has_value()) {
                register_elf_callback(*dt_fini, 0u, true);
            }
            if (!saw_preinit_arr && dt_preinit_va.has_value() && dt_preinit_sz != 0u) {
                if (const auto off = image.virtual_address_to_file_offset(*dt_preinit_va)) {
                    scan_pointer_array(*off, dt_preinit_sz, false);
                }
            }
            if (!saw_init_arr && dt_init_arr_va.has_value() && dt_init_arr_sz != 0u) {
                if (const auto off = image.virtual_address_to_file_offset(*dt_init_arr_va)) {
                    scan_pointer_array(*off, dt_init_arr_sz, false);
                }
            }
            if (!saw_fini_arr && dt_fini_arr_va.has_value() && dt_fini_arr_sz != 0u) {
                if (const auto off = image.virtual_address_to_file_offset(*dt_fini_arr_va)) {
                    scan_pointer_array(*off, dt_fini_arr_sz, true);
                }
            }
        }
    }

    // 6. Direct Call Target Analysis across executable sections (or PT_LOAD segments if stripped).
    if (!image_bytes.empty()) {
        if (const auto dis_arch = to_disasm_arch(image.architecture()); dis_arch.has_value()) {
            Disassembler disasm;
            if (disasm.init(*dis_arch, to_disasm_endian(image.endianness()))) {
                if (image.architecture() == peelf::Architecture::ARM) {
                    (void)disasm.set_thumb_mode(thumb_mode);
                }

                struct CodeSpan {
                    std::uint64_t virtual_address{0};
                    std::uint64_t file_offset{0};
                    std::uint64_t byte_size{0};
                };
                std::vector<CodeSpan> spans;
                for (const peelf::Section& sec : image.sections()) {
                    if (sec.executable && sec.file_size != 0u && sec.file_offset < image_bytes.size()) {
                        spans.push_back(CodeSpan{
                            .virtual_address = sec.virtual_address,
                            .file_offset = sec.file_offset,
                            .byte_size = sec.file_size,
                        });
                    }
                }
                if (spans.empty()) {
                    for (const peelf::Segment& seg : image.segments()) {
                        if (seg.executable &&
                            (image.format() != peelf::Format::ELF || seg.type == kElfPtLoad || seg.type == 0u) &&
                            seg.file_size != 0u && seg.file_offset < image_bytes.size()) {
                            spans.push_back(CodeSpan{
                                .virtual_address = seg.virtual_address,
                                .file_offset = seg.file_offset,
                                .byte_size = seg.file_size,
                            });
                        }
                    }
                }

                const std::size_t step_align = instruction_alignment(image.architecture(), thumb_mode);
                for (const CodeSpan& span : spans) {
                    const std::size_t base_off = static_cast<std::size_t>(span.file_offset);
                    const std::size_t avail = image_bytes.size() - base_off;
                    const std::size_t scan_limit = std::min<std::size_t>(
                        {static_cast<std::size_t>(std::min<std::uint64_t>(
                             span.byte_size,
                             static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))),
                         avail,
                         kMaxSectionScanBytes});

                    std::size_t cursor = 0u;
                    while (cursor < scan_limit) {
                        const std::size_t chunk = std::min<std::size_t>(scan_limit - cursor, kDisasmChunkBytes);
                        const std::uint64_t chunk_va =
                            span.virtual_address + static_cast<std::uint64_t>(cursor);
                        const std::vector<Instruction> insns = disasm.disassemble(
                            image_bytes.data() + base_off + cursor,
                            chunk,
                            chunk_va);

                        if (insns.empty()) {
                            cursor += std::min<std::size_t>(step_align, scan_limit - cursor);
                            continue;
                        }

                        const Instruction* prev = nullptr;
                        for (const Instruction& insn : insns) {
                            std::optional<std::uint64_t> target_va;
                            if (prev != nullptr) {
                                target_va = resolve_auipc_jalr_pair(*prev, insn, image.architecture());
                            }
                            if (!target_va.has_value() && is_direct_call_mnemonic(insn)) {
                                target_va = parse_immediate_call_operand(insn, image.architecture());
                            }

                            if (target_va.has_value()) {
                                std::uint64_t callee_va = *target_va;
                                if (image.architecture() == peelf::Architecture::ARM) {
                                    callee_va &= ~std::uint64_t{1u};
                                }
                                const std::uint64_t next_va =
                                    insn.address + static_cast<std::uint64_t>(insn.bytes.size());
                                // Ignore x86 PIC `call $+5` instruction-pointer reads and self-loops.
                                const bool x86_get_pc_idiom =
                                    image.architecture() == peelf::Architecture::X86 &&
                                    callee_va == next_va;
                                if (callee_va != 0u &&
                                    callee_va != insn.address &&
                                    !x86_get_pc_idiom &&
                                    !by_va.contains(callee_va) &&
                                    is_executable_address(image, callee_va)) {
                                    std::string sub_name = std::format("sub_{:X}", callee_va);
                                    enrich_symbol_index(image, symbol_index, sub_name, callee_va, 0u);
                                    upsert_function(
                                        by_va,
                                        build_entry(
                                            image,
                                            image_bytes,
                                            std::move(sub_name),
                                            callee_va,
                                            0u,
                                            FunctionOrigin::CallTargetDiscovery));
                                }
                            }
                            prev = &insn;
                        }

                        const Instruction& last = insns.back();
                        const std::uint64_t decoded_end =
                            last.address + static_cast<std::uint64_t>(last.bytes.size());
                        if (decoded_end <= chunk_va) {
                            cursor += std::min<std::size_t>(step_align, scan_limit - cursor);
                        } else {
                            const std::size_t consumed = static_cast<std::size_t>(decoded_end - chunk_va);
                            cursor += std::max<std::size_t>(1u, consumed);
                        }
                    }
                }
            }
        }
    }

    // Materialize sorted entries and infer missing sizes from next function in the same section.
    index.entries_.reserve(by_va.size());
    for (auto& [va, entry] : by_va) {
        (void)va;
        index.entries_.push_back(std::move(entry));
    }

    std::ranges::sort(index.entries_, {}, &FunctionEntry::virtual_address);

    for (std::size_t i = 0u; i + 1u < index.entries_.size(); ++i) {
        FunctionEntry& cur = index.entries_[i];
        if (cur.size != 0u) {
            continue;
        }
        const FunctionEntry& next = index.entries_[i + 1u];
        if (next.virtual_address <= cur.virtual_address) {
            continue;
        }
        const bool same_exec_region =
            !cur.section_name.empty() && cur.section_name == next.section_name;
        if (!same_exec_region) {
            continue;
        }
        const std::uint64_t distance = next.virtual_address - cur.virtual_address;
        if (distance <= kMaxInferredFunctionSize) {
            cur.size = distance;
        } else {
            cur.size = kMaxInferredFunctionSize;
        }
    }

    return index;
}

const FunctionEntry* FunctionIndex::find_exact(std::uint64_t virtual_address) const noexcept {
    const auto it = std::ranges::lower_bound(
        entries_,
        virtual_address,
        {},
        &FunctionEntry::virtual_address);
    if (it != entries_.end() && it->virtual_address == virtual_address) {
        return &*it;
    }
    return nullptr;
}

const FunctionEntry* FunctionIndex::find_containing(std::uint64_t virtual_address) const noexcept {
    if (entries_.empty()) {
        return nullptr;
    }
    const auto upper = std::ranges::upper_bound(
        entries_,
        virtual_address,
        {},
        &FunctionEntry::virtual_address);
    if (upper == entries_.begin()) {
        return nullptr;
    }

    auto it = std::prev(upper);
    for (std::size_t checked = 0u; checked < 8u; ++checked) {
        const FunctionEntry& entry = *it;
        if (entry.virtual_address == virtual_address) {
            return &entry;
        }
        if (entry.size != 0u && virtual_address >= entry.virtual_address &&
            virtual_address - entry.virtual_address < entry.size) {
            return &entry;
        }
        if (it == entries_.begin()) {
            break;
        }
        --it;
    }
    return nullptr;
}

}  // namespace viewer
