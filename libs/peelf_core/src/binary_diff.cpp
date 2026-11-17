#include <peelf/binary_diff.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <peelf/demangle.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/macho_image.hpp>
#include <peelf/sha256.hpp>

namespace peelf {

namespace {

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] std::string stem_lower(std::string_view name_or_path) {
    const std::size_t slash = name_or_path.find_last_of("/\\");
    std::string_view base = (slash == std::string_view::npos) ? name_or_path : name_or_path.substr(slash + 1u);
    std::string low = to_lower_ascii(base);
    if (low.ends_with(".dll") || low.ends_with(".exe") || low.ends_with(".sys")) {
        low.resize(low.size() - 4u);
    } else if (low.ends_with(".dylib")) {
        low.resize(low.size() - 6u);
    } else {
        const std::size_t so_pos = low.find(".so");
        if (so_pos != std::string::npos) {
            low.resize(so_pos);
        }
    }
    return low;
}

[[nodiscard]] std::string macho_diff_arch_name(const IBinaryImage& img) {
    const MachOHeader* mh = img.macho_header();
    if (mh == nullptr) {
        return std::string(to_string(img.architecture()));
    }
    if (mh->cpu_type == macho::kCpuTypeArm64) {
        return mh->is_arm64e ? "arm64e" : "arm64";
    }
    if (mh->cpu_type == macho::kCpuTypeArm64_32) {
        return "arm64_32";
    }
    if (mh->cpu_type == macho::kCpuTypeX86_64) {
        const std::uint32_t sub = mh->cpu_subtype & ~macho::kCpuSubtypeMask;
        return sub == macho::kCpuSubtypeX86_64H ? "x86_64h" : "x86_64";
    }
    if (mh->cpu_type == macho::kCpuTypeX86) {
        return "i386";
    }
    if (mh->cpu_type == macho::kCpuTypeArm) {
        return "armv7";
    }
    return std::string(to_string(img.architecture()));
}

[[nodiscard]] std::string macho_diff_filetype_name(std::uint32_t ft) {
    switch (ft) {
        case macho::kMhObject:     return std::format("MH_OBJECT (0x{:X})", ft);
        case macho::kMhExecute:    return std::format("MH_EXECUTE (0x{:X})", ft);
        case macho::kMhDylib:      return std::format("MH_DYLIB (0x{:X})", ft);
        case macho::kMhDylinker:   return std::format("MH_DYLINKER (0x{:X})", ft);
        case macho::kMhBundle:     return std::format("MH_BUNDLE (0x{:X})", ft);
        case macho::kMhDsym:       return std::format("MH_DSYM (0x{:X})", ft);
        case macho::kMhKextBundle: return std::format("MH_KEXT_BUNDLE (0x{:X})", ft);
        case macho::kMhFileset:    return std::format("MH_FILESET (0x{:X})", ft);
        default:                   return std::format("0x{:X}", ft);
    }
}

[[nodiscard]] std::string macho_diff_flags_summary(std::uint32_t flags) {
    std::vector<std::string_view> names;
    if ((flags & macho::kMhNoUndefs) != 0u)            names.push_back("MH_NOUNDEFS");
    if ((flags & macho::kMhDyldLink) != 0u)            names.push_back("MH_DYLDLINK");
    if ((flags & macho::kMhTwoLevel) != 0u)            names.push_back("MH_TWOLEVEL");
    if ((flags & macho::kMhForceFlat) != 0u)           names.push_back("MH_FORCE_FLAT");
    if ((flags & macho::kMhAllowStackExecution) != 0u) names.push_back("MH_ALLOW_STACK_EXECUTION");
    if ((flags & macho::kMhPie) != 0u)                 names.push_back("MH_PIE");
    if ((flags & macho::kMhNoHeapExecution) != 0u)     names.push_back("MH_NO_HEAP_EXECUTION");
    if ((flags & macho::kMhAppExtensionSafe) != 0u)    names.push_back("MH_APP_EXTENSION_SAFE");
    std::string out = std::format("0x{:08X}", flags);
    if (!names.empty()) {
        out += " [";
        for (std::size_t i = 0u; i < names.size(); ++i) {
            if (i > 0u) out += " | ";
            out += names[i];
        }
        out += "]";
    }
    return out;
}

[[nodiscard]] std::string macho_diff_uuid_string(const IBinaryImage& img) {
    const auto uuid = img.macho_uuid();
    if (!uuid.has_value()) {
        return "<absent>";
    }
    const auto& b = *uuid;
    return std::format(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-"
        "{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

[[nodiscard]] std::string macho_diff_platform_summary(const IBinaryImage& img) {
    if (img.macho_build_versions().empty()) {
        return "<absent>";
    }
    std::string out;
    for (std::size_t i = 0u; i < img.macho_build_versions().size(); ++i) {
        if (i > 0u) out += "; ";
        const MachOBuildVersion& bv = img.macho_build_versions()[i];
        out += std::format("{} min {} sdk {}",
                           macho::platform_to_string(bv.platform),
                           macho::format_packed_version(bv.minos),
                           macho::format_packed_version(bv.sdk));
    }
    return out;
}

[[nodiscard]] std::string macho_diff_dylibs_summary(const IBinaryImage& img) {
    std::vector<std::string> items;
    for (const MachODylibDependency& dy : img.macho_dylibs()) {
        if (dy.ordinal == 0u) {
            continue;
        }
        items.push_back(std::format("{} ({})",
                                    dy.name,
                                    macho::format_packed_version(dy.current_version)));
    }
    if (items.empty()) {
        return "0 []";
    }
    std::string joined = std::format("{} [", items.size());
    for (std::size_t i = 0u; i < items.size(); ++i) {
        if (i > 0u) joined += ", ";
        joined += items[i];
    }
    joined += "]";
    return joined;
}

[[nodiscard]] std::string macho_diff_rpaths_summary(const IBinaryImage& img) {
    if (img.macho_rpaths().empty()) {
        return "<none>";
    }
    std::string out;
    for (std::size_t i = 0u; i < img.macho_rpaths().size(); ++i) {
        if (i > 0u) out += " : ";
        out += img.macho_rpaths()[i].path;
    }
    return out;
}

[[nodiscard]] std::string macho_diff_codesig_summary(const IBinaryImage& img) {
    const MachOCodeSignatureInfo* cs = img.macho_code_signature();
    if (cs == nullptr || !cs->present) {
        return "Unsigned";
    }
    if (!cs->superblob_valid || !cs->has_code_directory) {
        return "Corrupt / Truncated LC_CODE_SIGNATURE";
    }
    return std::format(
        "flags=0x{:08X}, adhoc={}, runtime={}, id='{}', cms={}, trust={}",
        cs->cd_flags,
        cs->is_adhoc() ? 1 : 0,
        cs->has_hardened_runtime() ? 1 : 0,
        cs->identifier.empty() ? "<none>" : cs->identifier,
        cs->has_nonempty_cms_signature ? "nonempty" : "empty",
        cs->cryptographically_verified ? "verified" : "unverified_offline");
}

[[nodiscard]] std::string macho_diff_security_posture(const IBinaryImage& img) {
    const MachOHeader* mh = img.macho_header();
    if (mh == nullptr) {
        return "<n/a>";
    }
    bool has_pz = false;
    bool has_rwx = mh->allows_stack_execution();
    for (const MachOSegmentCommand& seg : img.macho_segments()) {
        if (seg.is_pagezero() && seg.virtual_address == 0u && seg.virtual_size >= 4096u &&
            seg.initprot == 0u && seg.maxprot == 0u) {
            has_pz = true;
        }
        if (seg.init_is_wx() || seg.max_is_wx()) {
            has_rwx = true;
        }
    }
    const MachOEncryptionInfo* enc = img.macho_encryption_info();
    const bool encrypted = (enc != nullptr && enc->is_encrypted());
    return std::format("PIE={}, __PAGEZERO={}, W^X={}, PAC={}, Encrypted={}",
                       mh->has_pie() ? 1 : 0,
                       has_pz ? 1 : 0,
                       has_rwx ? "VIOLATION" : "ok",
                       mh->is_arm64e ? "arm64e" : "none",
                       encrypted ? 1 : 0);
}

[[nodiscard]] std::string format_hex(std::uint64_t value, unsigned width = 0u) {
    if (width > 0u) {
        return std::format("0x{:0{}X}", value, width);
    }
    return std::format("0x{:X}", value);
}

[[nodiscard]] std::string section_perms_string(const Section& s) {
    std::string out = "---";
    if (s.readable) out[0] = 'r';
    if (s.writable) out[1] = 'w';
    if (s.executable) out[2] = 'x';
    return out;
}

[[nodiscard]] constexpr bool add_u64_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return b > std::numeric_limits<std::uint64_t>::max() - a;
}

[[nodiscard]] constexpr std::uint64_t saturating_add_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    return add_u64_overflows(a, b) ? std::numeric_limits<std::uint64_t>::max() : (a + b);
}

[[nodiscard]] constexpr std::uint64_t add_signed_offset_wrapping(
    std::uint64_t base,
    std::int64_t offset) noexcept {
    return base + static_cast<std::uint64_t>(offset);
}

[[nodiscard]] std::span<const std::uint8_t> slice_safe(
    std::span<const std::uint8_t> bytes,
    std::uint64_t offset,
    std::uint64_t size) noexcept {
    if (offset >= bytes.size() || size == 0u) {
        return {};
    }
    const std::uint64_t avail = static_cast<std::uint64_t>(bytes.size()) - offset;
    const std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(avail, size));
    return bytes.subspan(static_cast<std::size_t>(offset), take);
}

[[nodiscard]] std::uint64_t estimate_image_span(const IBinaryImage& img) noexcept {
    if (const PeHeader* pe = img.pe_header(); pe != nullptr && pe->size_of_image > 0u) {
        return pe->size_of_image;
    }
    const std::uint64_t base = img.image_base();
    std::uint64_t max_end = base;
    for (const Section& sec : img.sections()) {
        const std::uint64_t span = std::max(sec.virtual_size, sec.file_size);
        if (sec.virtual_address >= base && span > 0u) {
            if (const auto end = checked_add_u64(sec.virtual_address, span); end.has_value()) {
                max_end = std::max(max_end, *end);
            }
        }
    }
    for (const Segment& seg : img.segments()) {
        if (seg.virtual_address >= base && seg.virtual_size > 0u) {
            if (const auto end = checked_add_u64(seg.virtual_address, seg.virtual_size);
                end.has_value()) {
                max_end = std::max(max_end, *end);
            }
        }
    }
    const std::uint64_t computed = max_end > base ? (max_end - base) : 0u;
    return computed > 0u ? computed : 0x100000ull;
}

[[nodiscard]] std::uint32_t read_le32(std::span<const std::uint8_t> b, std::size_t off) noexcept {
    return static_cast<std::uint32_t>(b[off]) |
           (static_cast<std::uint32_t>(b[off + 1u]) << 8u) |
           (static_cast<std::uint32_t>(b[off + 2u]) << 16u) |
           (static_cast<std::uint32_t>(b[off + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t read_le64(std::span<const std::uint8_t> b, std::size_t off) noexcept {
    return static_cast<std::uint64_t>(read_le32(b, off)) |
           (static_cast<std::uint64_t>(read_le32(b, off + 4u)) << 32u);
}

void write_le32(std::span<std::uint8_t> b, std::size_t off, std::uint32_t val) noexcept {
    b[off + 0u] = static_cast<std::uint8_t>(val & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
    b[off + 2u] = static_cast<std::uint8_t>((val >> 16u) & 0xFFu);
    b[off + 3u] = static_cast<std::uint8_t>((val >> 24u) & 0xFFu);
}

void write_le64(std::span<std::uint8_t> b, std::size_t off, std::uint64_t val) noexcept {
    write_le32(b, off, static_cast<std::uint32_t>(val & 0xFFFF'FFFFull));
    write_le32(b, off + 4u, static_cast<std::uint32_t>(val >> 32u));
}

[[nodiscard]] std::uint32_t read_u32_endian(std::span<const std::uint8_t> b,
                                            std::size_t off,
                                            Endianness endian) noexcept {
    if (endian == Endianness::Big) {
        return (static_cast<std::uint32_t>(b[off]) << 24u) |
               (static_cast<std::uint32_t>(b[off + 1u]) << 16u) |
               (static_cast<std::uint32_t>(b[off + 2u]) << 8u) |
               static_cast<std::uint32_t>(b[off + 3u]);
    }
    return read_le32(b, off);
}

void write_u32_endian(std::span<std::uint8_t> b,
                      std::size_t off,
                      std::uint32_t val,
                      Endianness endian) noexcept {
    if (endian == Endianness::Big) {
        b[off + 0u] = static_cast<std::uint8_t>((val >> 24u) & 0xFFu);
        b[off + 1u] = static_cast<std::uint8_t>((val >> 16u) & 0xFFu);
        b[off + 2u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
        b[off + 3u] = static_cast<std::uint8_t>(val & 0xFFu);
    } else {
        write_le32(b, off, val);
    }
}

[[nodiscard]] std::uint64_t read_ptr_endian(std::span<const std::uint8_t> b,
                                            std::size_t off,
                                            bool is64,
                                            Endianness endian) noexcept {
    if (!is64) {
        return read_u32_endian(b, off, endian);
    }
    if (endian == Endianness::Big) {
        return (static_cast<std::uint64_t>(read_u32_endian(b, off, Endianness::Big)) << 32u) |
               static_cast<std::uint64_t>(read_u32_endian(b, off + 4u, Endianness::Big));
    }
    return read_le64(b, off);
}

void write_ptr_endian(std::span<std::uint8_t> b,
                      std::size_t off,
                      std::uint64_t val,
                      bool is64,
                      Endianness endian) noexcept {
    if (!is64) {
        write_u32_endian(b, off, static_cast<std::uint32_t>(val & 0xFFFF'FFFFull), endian);
        return;
    }
    if (endian == Endianness::Big) {
        write_u32_endian(b, off, static_cast<std::uint32_t>(val >> 32u), Endianness::Big);
        write_u32_endian(b, off + 4u, static_cast<std::uint32_t>(val & 0xFFFF'FFFFull), Endianness::Big);
    } else {
        write_le64(b, off, val);
    }
}

struct VaInterval {
    std::uint64_t start{0};
    std::uint64_t end{0};
};

[[nodiscard]] std::vector<VaInterval> collect_relocation_va_intervals(const IBinaryImage& img) {
    std::vector<VaInterval> out;
    const std::uint64_t base = img.image_base();
    for (const PeBaseRelocationBlock& blk : img.pe_base_relocations()) {
        for (const PeBaseRelocationEntry& e : blk.entries) {
            std::uint64_t width = 0;
            switch (e.type) {
                case 1u: width = 2u; break;  // HIGH
                case 2u: width = 2u; break;  // LOW
                case 3u: width = 4u; break;  // HIGHLOW
                case 4u: width = 4u; break;  // HIGHADJ
                case 10u: width = 8u; break; // DIR64
                default: break;
            }
            if (width > 0u) {
                if (const auto va = checked_add_u64(base, e.rva); va.has_value()) {
                    if (const auto va_end = checked_add_u64(*va, width); va_end.has_value()) {
                        out.push_back(VaInterval{*va, *va_end});
                    }
                }
            }
        }
    }
    const std::uint64_t ptr_sz = img.is_64bit() ? 8u : 4u;
    for (const ElfRelocation& rel : img.elf_relocations()) {
        if (rel.offset != 0u) {
            if (const auto rel_end = checked_add_u64(rel.offset, ptr_sz); rel_end.has_value()) {
                out.push_back(VaInterval{rel.offset, *rel_end});
            }
        }
    }
    std::ranges::sort(out, [](const VaInterval& a, const VaInterval& b) {
        return std::tie(a.start, a.end) < std::tie(b.start, b.end);
    });
    return out;
}

[[nodiscard]] bool range_fully_covered_by_relocs(
    const std::vector<VaInterval>& sorted_relocs,
    std::uint64_t va_start,
    std::uint64_t va_end) noexcept {
    if (va_start >= va_end || sorted_relocs.empty()) {
        return false;
    }
    std::uint64_t cur = va_start;
    auto it = std::lower_bound(
        sorted_relocs.begin(),
        sorted_relocs.end(),
        va_start,
        [](const VaInterval& iv, std::uint64_t v) { return iv.end <= v; });
    while (it != sorted_relocs.end() && it->start <= cur && cur < va_end) {
        cur = std::max(cur, it->end);
        ++it;
    }
    return cur >= va_end;
}

// Lightweight x86/x86_64 instruction boundary & displacement masker so RIP-relative
// memory operands (`[rip + disp32]`), inter-function `call`/`jmp`/`jcc rel32`, and
// absolute image-base immediates normalize cleanly without linking Capstone in peelf_core.
void mask_x86_function_displacements(std::span<std::uint8_t> buf,
                                     std::uint64_t func_va,
                                     bool is64,
                                     std::uint64_t image_base,
                                     std::uint64_t image_end) noexcept {
    const auto in_func = [&](std::uint64_t target) noexcept {
        return target >= func_va && (target - func_va) < buf.size();
    };
    std::size_t i = 0;
    while (i < buf.size()) {
        const std::size_t insn_start = i;
        bool operand_16 = false;
        bool rex_w = false;

        // Legacy & REX prefixes
        while (i < buf.size()) {
            const std::uint8_t p = buf[i];
            if (p == 0x66u) {
                operand_16 = true;
                ++i;
            } else if (p == 0x67u || p == 0xF0u || p == 0xF2u || p == 0xF3u ||
                       p == 0x26u || p == 0x2Eu || p == 0x36u || p == 0x3Eu ||
                       p == 0x64u || p == 0x65u) {
                ++i;
            } else if (is64 && p >= 0x40u && p <= 0x4Fu) {
                rex_w = (p & 0x08u) != 0u;
                ++i;
            } else {
                break;
            }
            if (i - insn_start >= 8u) {
                break;
            }
        }
        if (i >= buf.size()) {
            break;
        }

        const std::uint8_t op = buf[i++];

        // ENDBR64 / ENDBR32 (`F3 0F 1E FA` / `F3 0F 1E FB`)
        if (op == 0x0Fu && i < buf.size() && buf[i] == 0x1Eu) {
            i = std::min(buf.size(), i + 2u);
            continue;
        }

        // Single-byte no-operand instructions (NOP, PUSH/POP reg, RET, LEAVE, INT3, etc.)
        if (op == 0x90u || op == 0xC3u || op == 0xC9u || op == 0xCCu || op == 0xCBu ||
            op == 0x98u || op == 0x99u || op == 0xF4u || op == 0xFCu || op == 0xFDu ||
            (op >= 0x50u && op <= 0x5Fu)) {
            continue;
        }

        // Short conditional/unconditional jump `70..7F rel8` / `EB rel8`
        if ((op >= 0x70u && op <= 0x7Fu) || op == 0xEBu) {
            if (i < buf.size()) {
                const auto rel8 = static_cast<std::int8_t>(buf[i]);
                const std::uint64_t next_va = func_va + static_cast<std::uint64_t>(i + 1u);
                const std::uint64_t target =
                    add_signed_offset_wrapping(next_va, static_cast<std::int64_t>(rel8));
                if (!in_func(target)) {
                    buf[i] = 0u;
                }
                ++i;
            }
            continue;
        }

        // Near CALL rel32 (`E8`) or JMP rel32 (`E9`)
        if (op == 0xE8u || op == 0xE9u) {
            if (i + 4u <= buf.size()) {
                const auto rel32 = static_cast<std::int32_t>(read_le32(buf, i));
                const std::uint64_t next_va = func_va + static_cast<std::uint64_t>(i + 4u);
                const std::uint64_t target =
                    add_signed_offset_wrapping(next_va, static_cast<std::int64_t>(rel32));
                if (op == 0xE8u || !in_func(target)) {
                    std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                }
                i += 4u;
            } else {
                break;
            }
            continue;
        }

        // Two-byte `0F xx` opcodes
        bool has_modrm = false;
        std::size_t imm_size = 0;
        if (op == 0x0Fu) {
            if (i >= buf.size()) {
                break;
            }
            const std::uint8_t op2 = buf[i++];
            // `0F 80..8F rel32` (near Jcc)
            if (op2 >= 0x80u && op2 <= 0x8Fu) {
                if (i + 4u <= buf.size()) {
                    const auto rel32 = static_cast<std::int32_t>(read_le32(buf, i));
                    const std::uint64_t next_va = func_va + static_cast<std::uint64_t>(i + 4u);
                    const std::uint64_t target =
                        add_signed_offset_wrapping(next_va, static_cast<std::int64_t>(rel32));
                    if (!in_func(target)) {
                        std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                    }
                    i += 4u;
                } else {
                    break;
                }
                continue;
            }
            // Common 2-byte ModR/M opcodes (MOVZX/MOVSX B6/B7/BE/BF, CMOV 40..4F, SETcc 90..9F,
            // NOP 1F, SSE 10/11/28/29/2E/2F/57/6F/7F/D6, IMUL AF)
            if ((op2 >= 0x40u && op2 <= 0x4Fu) || (op2 >= 0x90u && op2 <= 0x9Fu) ||
                op2 == 0x1Fu || op2 == 0xAFu || op2 == 0xB6u || op2 == 0xB7u ||
                op2 == 0xBEu || op2 == 0xBFu || op2 == 0x10u || op2 == 0x11u ||
                op2 == 0x28u || op2 == 0x29u || op2 == 0x2Eu || op2 == 0x2Fu ||
                op2 == 0x57u || op2 == 0x6Fu || op2 == 0x7Fu || op2 == 0xB3u ||
                op2 == 0xABu || op2 == 0xBAu) {
                has_modrm = true;
                if (op2 == 0xBAu) {
                    imm_size = 1u;
                }
            } else {
                // Unknown 0F opcode: advance conservatively
                continue;
            }
        } else if (op >= 0xB8u && op <= 0xBFu) {
            // MOV reg, imm16/32/64
            const std::size_t width = rex_w ? 8u : (operand_16 ? 2u : 4u);
            if (i + width <= buf.size()) {
                if (width == 8u) {
                    const std::uint64_t v = read_le64(buf, i);
                    if (image_end > image_base && v >= image_base && v < image_end) {
                        std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 8, std::uint8_t{0});
                    }
                } else if (width == 4u) {
                    const std::uint32_t v = read_le32(buf, i);
                    if (image_end > image_base && v >= image_base && v < image_end) {
                        std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                    }
                }
                i += width;
            } else {
                break;
            }
            continue;
        } else if (op >= 0xB0u && op <= 0xB7u) {
            i = std::min(buf.size(), i + 1u);
            continue;
        } else if (op == 0x6Au || op == 0x04u || op == 0x0Cu || op == 0x14u || op == 0x1Cu ||
                   op == 0x24u || op == 0x2Cu || op == 0x34u || op == 0x3Cu || op == 0xA8u ||
                   op == 0xCDu) {
            i = std::min(buf.size(), i + 1u);
            continue;
        } else if (op == 0x68u || op == 0x05u || op == 0x0Du || op == 0x15u || op == 0x1Du ||
                   op == 0x25u || op == 0x2Du || op == 0x35u || op == 0x3Du || op == 0xA9u) {
            const std::size_t width = operand_16 ? 2u : 4u;
            if (i + width <= buf.size()) {
                if (width == 4u && !is64) {
                    const std::uint32_t v = read_le32(buf, i);
                    if (image_end > image_base && v >= image_base && v < image_end) {
                        std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                    }
                }
                i += width;
            } else {
                break;
            }
            continue;
        } else if (op == 0xC2u) {
            i = std::min(buf.size(), i + 2u);
            continue;
        } else if ((op & 0xFCu) == 0x00u || (op & 0xFCu) == 0x08u || (op & 0xFCu) == 0x10u ||
                   (op & 0xFCu) == 0x18u || (op & 0xFCu) == 0x20u || (op & 0xFCu) == 0x28u ||
                   (op & 0xFCu) == 0x30u || (op & 0xFCu) == 0x38u ||
                   (op >= 0x84u && op <= 0x8Fu) || op == 0x63u ||
                   op == 0x80u || op == 0x81u || op == 0x82u || op == 0x83u ||
                   op == 0xC0u || op == 0xC1u || op == 0xC6u || op == 0xC7u ||
                   op == 0xD0u || op == 0xD1u || op == 0xD2u || op == 0xD3u ||
                   op == 0xF6u || op == 0xF7u || op == 0xFEu || op == 0xFFu ||
                   op == 0x69u || op == 0x6Bu) {
            has_modrm = true;
            if (op == 0x80u || op == 0x82u || op == 0x83u || op == 0xC0u ||
                op == 0xC1u || op == 0xC6u || op == 0x6Bu) {
                imm_size = 1u;
            } else if (op == 0x81u || op == 0xC7u || op == 0x69u) {
                imm_size = operand_16 ? 2u : 4u;
            }
        }

        if (has_modrm) {
            if (i >= buf.size()) {
                break;
            }
            const std::uint8_t modrm = buf[i++];
            const std::uint8_t mod = (modrm >> 6u) & 0x03u;
            const std::uint8_t reg = (modrm >> 3u) & 0x07u;
            const std::uint8_t rm = modrm & 0x07u;

            if ((op == 0xF6u || op == 0xF7u) && (reg == 0u || reg == 1u)) {
                imm_size = (op == 0xF6u) ? 1u : (operand_16 ? 2u : 4u);
            }

            if (mod != 3u) {
                bool sib_disp32 = false;
                if (rm == 4u) {
                    if (i >= buf.size()) {
                        break;
                    }
                    const std::uint8_t sib = buf[i++];
                    if (mod == 0u && (sib & 0x07u) == 5u) {
                        sib_disp32 = true;
                    }
                }
                if (mod == 0u && rm == 5u) {
                    // 64-bit: `[rip + disp32]`; 32-bit: `[disp32]`
                    if (i + 4u <= buf.size()) {
                        if (is64) {
                            std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                        } else {
                            const std::uint32_t addr = read_le32(buf, i);
                            if (image_end > image_base && addr >= image_base && addr < image_end) {
                                std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                            }
                        }
                        i += 4u;
                    } else {
                        break;
                    }
                } else if (mod == 1u) {
                    i = std::min(buf.size(), i + 1u);
                } else if (mod == 2u || sib_disp32) {
                    if (i + 4u <= buf.size()) {
                        if (!is64 && sib_disp32) {
                            const std::uint32_t addr = read_le32(buf, i);
                            if (image_end > image_base && addr >= image_base && addr < image_end) {
                                std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                            }
                        }
                        i += 4u;
                    } else {
                        break;
                    }
                }
            }

            if (imm_size > 0u) {
                if (i + imm_size <= buf.size()) {
                    if (imm_size == 4u && !is64) {
                        const std::uint32_t v = read_le32(buf, i);
                        if (image_end > image_base && v >= image_base && v < image_end) {
                            std::fill_n(buf.begin() + static_cast<std::ptrdiff_t>(i), 4, std::uint8_t{0});
                        }
                    }
                    i += imm_size;
                } else {
                    break;
                }
            }
        }
    }
}

void mask_fixed_width_risc_displacements(std::span<std::uint8_t> buf,
                                         std::uint64_t func_va,
                                         Architecture arch,
                                         Endianness endian) noexcept {
    const auto in_func = [&](std::uint64_t target) noexcept {
        return target >= func_va && (target - func_va) < buf.size();
    };
    for (std::size_t off = 0; off + 4u <= buf.size(); off += 4u) {
        const std::uint64_t pc = func_va + static_cast<std::uint64_t>(off);
        std::uint32_t insn = read_u32_endian(buf, off, endian);
        bool modified = false;

        switch (arch) {
            case Architecture::ARM64: {
                // B / BL (`000101` or `100101` in top 6 bits)
                if ((insn & 0x7C00'0000u) == 0x1400'0000u) {
                    std::int64_t imm26 = static_cast<std::int64_t>(insn & 0x03FF'FFFFu);
                    if ((imm26 & (1ll << 25)) != 0) {
                        imm26 -= (1ll << 26);
                    }
                    const std::uint64_t target = add_signed_offset_wrapping(pc, imm26 * 4);
                    const bool is_bl = (insn & 0x8000'0000u) != 0u;
                    if (is_bl || !in_func(target)) {
                        insn &= 0xFC00'0000u;
                        modified = true;
                    }
                } else if ((insn & 0x1F00'0000u) == 0x1000'0000u) {
                    // ADR / ADRP: mask immlo [30:29] and immhi [23:5]
                    insn &= 0x9F00'001Fu;
                    modified = true;
                }
                break;
            }
            case Architecture::ARM: {
                // ARM32 B / BL (`cond 101L imm24`)
                if ((insn & 0x0E00'0000u) == 0x0A00'0000u) {
                    std::int64_t imm24 = static_cast<std::int64_t>(insn & 0x00FF'FFFFu);
                    if ((imm24 & (1ll << 23)) != 0) {
                        imm24 -= (1ll << 24);
                    }
                    const std::uint64_t target = add_signed_offset_wrapping(pc + 8u, imm24 * 4);
                    const bool is_bl = (insn & 0x0100'0000u) != 0u;
                    if (is_bl || !in_func(target)) {
                        insn &= 0xFF00'0000u;
                        modified = true;
                    }
                }
                break;
            }
            case Architecture::RISCV32:
            case Architecture::RISCV64: {
                const std::uint32_t opcode = insn & 0x7Fu;
                // AUIPC (0x17) or JAL (0x6F)
                if (opcode == 0x17u || opcode == 0x6Fu) {
                    insn &= 0x0000'0FFFu;
                    modified = true;
                }
                break;
            }
            case Architecture::PowerPC:
            case Architecture::PowerPC64: {
                // B / BL (`opcode == 18`)
                if ((insn >> 26u) == 18u) {
                    insn &= 0xFC00'0003u;
                    modified = true;
                }
                break;
            }
            case Architecture::MIPS32:
            case Architecture::MIPS64: {
                const std::uint32_t op6 = insn >> 26u;
                // J (2) / JAL (3)
                if (op6 == 2u || op6 == 3u) {
                    insn &= 0xFC00'0000u;
                    modified = true;
                }
                break;
            }
            default:
                break;
        }

        if (modified) {
            write_u32_endian(buf, off, insn, endian);
        }
    }
}

struct ExtractedFunction {
    std::string raw_name{};
    std::string canonical_name{};
    bool has_real_name{false};
    std::uint64_t va{0};
    std::uint64_t file_offset{0};
    std::uint64_t size{0};
    std::span<const std::uint8_t> raw_bytes{};
    std::vector<std::uint8_t> normalized_bytes{};
    std::string normalized_sha256{};
};

[[nodiscard]] const Section* find_exec_section_containing_va(
    const IBinaryImage& img,
    std::uint64_t va) noexcept {
    for (const Section& sec : img.sections()) {
        if (!sec.executable) {
            continue;
        }
        const std::uint64_t span = std::max(sec.virtual_size, sec.file_size);
        if (va >= sec.virtual_address && (va - sec.virtual_address) < span) {
            return &sec;
        }
    }
    return nullptr;
}

[[nodiscard]] std::vector<ExtractedFunction> extract_functions_for_diff(
    const IBinaryImage& img,
    std::span<const std::uint8_t> raw_image_bytes) {
    struct Candidate {
        std::uint64_t va{0};
        std::uint64_t explicit_size{0};
        std::string name{};
        int priority{0}; // 3 = named symbol, 2 = export, 1 = pdata/entry
    };

    std::map<std::uint64_t, Candidate> by_va;

    auto upsert = [&](std::uint64_t va, std::uint64_t sz, std::string_view nm, int prio) {
        if (va == 0u || find_exec_section_containing_va(img, va) == nullptr) {
            return;
        }
        auto [it, inserted] = by_va.try_emplace(va, Candidate{va, sz, std::string(nm), prio});
        if (!inserted) {
            if (prio > it->second.priority && !nm.empty()) {
                it->second.name = std::string(nm);
                it->second.priority = prio;
            }
            if (it->second.explicit_size == 0u && sz > 0u) {
                it->second.explicit_size = sz;
            }
        }
    };

    for (const Symbol& sym : img.symbols()) {
        // ELF STT_NOTYPE (0) or STT_FUNC (2); ignore STT_OBJECT (1), STT_SECTION (3), STT_FILE (4)
        if (sym.type == 1u || sym.type == 3u || sym.type == 4u) {
            continue;
        }
        if (sym.name.empty() || sym.name.starts_with("$x") || sym.name.starts_with("$d") ||
            sym.name.starts_with("$a") || sym.name.starts_with("$t")) {
            continue;
        }
        upsert(sym.virtual_address, sym.size, sym.name, 3);
    }

    for (const ExportEntry& exp : img.exports()) {
        if (!exp.forwarder.empty() || exp.virtual_address == 0u) {
            continue;
        }
        const std::string exp_name =
            exp.name.empty() ? std::format("ordinal_{}", exp.ordinal) : exp.name;
        upsert(exp.virtual_address, 0u, exp_name, 2);
    }

    const std::uint64_t base = img.image_base();
    for (const PeRuntimeFunction& rf : img.pe_runtime_functions()) {
        if (rf.end_address_rva > rf.begin_address_rva) {
            if (const auto fn_va = checked_add_u64(base, rf.begin_address_rva); fn_va.has_value()) {
                upsert(*fn_va,
                       static_cast<std::uint64_t>(rf.end_address_rva - rf.begin_address_rva),
                       {},
                       1);
            }
        }
    }

    if (img.entry_point() != 0u) {
        upsert(img.entry_point(), 0u, "_entry", 1);
    }

    std::vector<Candidate> ordered;
    ordered.reserve(by_va.size());
    for (auto& [va, cand] : by_va) {
        ordered.push_back(std::move(cand));
    }

    std::vector<ExtractedFunction> result;
    result.reserve(ordered.size());

    for (std::size_t idx = 0; idx < ordered.size(); ++idx) {
        const Candidate& c = ordered[idx];
        const Section* sec = find_exec_section_containing_va(img, c.va);
        if (sec == nullptr) {
            continue;
        }
        const auto file_off = img.virtual_address_to_file_offset(c.va);
        if (!file_off.has_value() || *file_off >= raw_image_bytes.size()) {
            continue;
        }

        const std::uint64_t sec_limit_span =
            sec->file_size > 0u ? sec->file_size : sec->virtual_size;
        const std::uint64_t offset_in_sec = c.va - sec->virtual_address;
        std::uint64_t sz = c.explicit_size;
        if (sz == 0u) {
            std::uint64_t max_rem =
                offset_in_sec < sec_limit_span ? (sec_limit_span - offset_in_sec) : 0u;
            if (idx + 1u < ordered.size() && ordered[idx + 1u].va > c.va) {
                max_rem = std::min(max_rem, ordered[idx + 1u].va - c.va);
            }
            sz = std::min<std::uint64_t>(max_rem, 4096u);
        }
        if (sz == 0u) {
            continue;
        }

        const auto bytes = slice_safe(raw_image_bytes, *file_off, sz);
        if (bytes.empty()) {
            continue;
        }

        ExtractedFunction fn;
        fn.va = c.va;
        fn.file_offset = *file_off;
        fn.size = bytes.size();
        fn.raw_bytes = bytes;
        fn.has_real_name = !c.name.empty() && c.name != "_entry";
        fn.raw_name = c.name.empty() ? std::format("sub_{:X}", c.va) : c.name;
        fn.canonical_name = fn.has_real_name ? demangle_or_raw(fn.raw_name) : fn.raw_name;
        fn.normalized_bytes = normalize_function_bytes_for_diff(bytes, c.va, img);
        fn.normalized_sha256 = sha256_hex(fn.normalized_bytes);
        result.push_back(std::move(fn));
    }

    return result;
}

[[nodiscard]] double compute_normalized_similarity(
    std::span<const std::uint8_t> a,
    std::span<const std::uint8_t> b) {
    if (a.empty() && b.empty()) {
        return 1.0;
    }
    if (a.empty() || b.empty()) {
        return 0.0;
    }
    if (a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin())) {
        return 1.0;
    }

    // Blend positional byte agreement on common prefix with 4-gram multiset Jaccard similarity
    // so mid-function insertions/deletions still score accurately in O(N).
    const std::size_t min_len = std::min(a.size(), b.size());
    const std::size_t max_len = std::max(a.size(), b.size());
    std::size_t pos_matches = 0;
    for (std::size_t i = 0; i < min_len; ++i) {
        if (a[i] == b[i]) {
            ++pos_matches;
        }
    }
    const double pos_score = static_cast<double>(pos_matches) / static_cast<double>(max_len);

    if (min_len < 4u) {
        return pos_score;
    }

    const std::size_t cap_a = std::min<std::size_t>(a.size(), 2048u);
    const std::size_t cap_b = std::min<std::size_t>(b.size(), 2048u);
    std::unordered_map<std::uint32_t, std::uint32_t> grams_a;
    grams_a.reserve(cap_a);
    for (std::size_t i = 0; i + 4u <= cap_a; ++i) {
        ++grams_a[read_le32(a, i)];
    }

    std::size_t intersection = 0;
    const std::size_t total_a = cap_a - 3u;
    const std::size_t total_b = cap_b - 3u;
    for (std::size_t i = 0; i + 4u <= cap_b; ++i) {
        const std::uint32_t g = read_le32(b, i);
        if (auto it = grams_a.find(g); it != grams_a.end() && it->second > 0u) {
            --it->second;
            ++intersection;
        }
    }
    const std::size_t uni = total_a + total_b - intersection;
    const double jaccard = uni > 0u ? (static_cast<double>(intersection) / static_cast<double>(uni)) : 0.0;
    return std::clamp(0.45 * pos_score + 0.55 * jaccard, 0.0, 0.9999);
}

[[nodiscard]] std::string describe_code_detour_hint(
    std::span<const std::uint8_t> live_bytes,
    Architecture arch) {
    if (live_bytes.empty()) {
        return {};
    }
    if (arch == Architecture::X86 || arch == Architecture::X86_64) {
        if (live_bytes[0] == 0xE9u && live_bytes.size() >= 5u) {
            return " (near jmp rel32 detour opcode E9)";
        }
        if (live_bytes[0] == 0xE8u && live_bytes.size() >= 5u) {
            return " (near call rel32 hook opcode E8)";
        }
        if (live_bytes[0] == 0xEBu && live_bytes.size() >= 2u) {
            return " (short jmp rel8 hotpatch EB)";
        }
        if (live_bytes.size() >= 6u && live_bytes[0] == 0xFFu && live_bytes[1] == 0x25u) {
            return " (indirect jmp [rip/mem] trampoline FF 25)";
        }
        if (live_bytes.size() >= 12u && live_bytes[0] == 0x48u && live_bytes[1] == 0xB8u &&
            live_bytes[10] == 0xFFu && (live_bytes[11] == 0xE0u || live_bytes[11] == 0xD0u)) {
            return " (64-bit absolute mov rax, imm64; jmp/call rax detour)";
        }
        if (live_bytes[0] == 0xCCu) {
            return " (INT3 software breakpoint 0xCC)";
        }
    } else if (arch == Architecture::ARM64 && live_bytes.size() >= 8u) {
        const std::uint32_t w0 = read_le32(live_bytes, 0);
        const std::uint32_t w1 = read_le32(live_bytes, 4);
        if ((w0 & 0xFF00'001Fu) == 0x5800'0010u && (w1 & 0xFFFF'FC1Fu) == 0xD61F'0000u) {
            return " (AArch64 LDR X16, #8; BR X16 absolute trampoline)";
        }
    }
    return {};
}

[[nodiscard]] bool pe_import_matches_loaded_module(
    std::string_view requested_dll,
    std::string_view actual_mod_name) {
    const std::string req = stem_lower(requested_dll);
    const std::string act = stem_lower(actual_mod_name);
    if (req == act) {
        return true;
    }
    // Legitimate Windows API-set / kernel32 -> kernelbase / ntdll / ucrtbase host forwarding
    if (req.starts_with("api-ms-win-") || req.starts_with("ext-ms-win-")) {
        return act == "kernelbase" || act == "kernel32" || act == "ntdll" ||
               act == "ucrtbase" || act == "msvcrt" || act == "advapi32" ||
               act == "sechost" || act == "user32" || act == "win32u" || act == "rpcrt4";
    }
    if (req == "kernel32" && (act == "kernelbase" || act == "ntdll")) {
        return true;
    }
    if (req == "advapi32" && (act == "sechost" || act == "kernelbase" || act == "ntdll")) {
        return true;
    }
    return false;
}

} // namespace

std::vector<std::uint8_t> normalize_function_bytes_for_diff(
    std::span<const std::uint8_t> func_bytes,
    std::uint64_t func_va,
    const IBinaryImage& image) {
    std::vector<std::uint8_t> norm(func_bytes.begin(), func_bytes.end());
    if (norm.empty()) {
        return norm;
    }

    const std::uint64_t norm_len = static_cast<std::uint64_t>(norm.size());
    const std::vector<VaInterval> relocs = collect_relocation_va_intervals(image);

    // 1. Mask explicit PE/ELF relocation fixup spans inside [func_va, func_va + norm_len)
    for (const VaInterval& iv : relocs) {
        if (iv.end <= func_va || iv.start >= iv.end) {
            continue;
        }
        const std::uint64_t s = (iv.start > func_va) ? (iv.start - func_va) : 0u;
        if (s >= norm_len) {
            continue;
        }
        const std::uint64_t e = std::min(iv.end - func_va, norm_len);
        std::fill(norm.begin() + static_cast<std::ptrdiff_t>(s),
                  norm.begin() + static_cast<std::ptrdiff_t>(e),
                  std::uint8_t{0});
    }

    // 2. Mask PC/RIP-relative call/branch displacements and absolute image-base addresses
    const std::uint64_t img_base = image.image_base();
    const std::uint64_t img_end = saturating_add_u64(img_base, estimate_image_span(image));
    const Architecture arch = image.architecture();
    if (arch == Architecture::X86 || arch == Architecture::X86_64) {
        mask_x86_function_displacements(norm, func_va, image.is_64bit(), img_base, img_end);
    } else {
        mask_fixed_width_risc_displacements(norm, func_va, arch, image.endianness());
    }

    return norm;
}

Result<BinaryDiffReport> compare_binaries(
    const IBinaryImage& lhs_image,
    std::span<const std::uint8_t> lhs_bytes,
    const IBinaryImage& rhs_image,
    std::span<const std::uint8_t> rhs_bytes,
    const BinaryDiffOptions& options) {
    auto report_progress = [&](std::size_t completed, std::size_t total, std::string_view stage) {
        if (options.progress_callback) {
            options.progress_callback(completed, total, stage);
        }
    };
    if (options.stop_token.stop_requested()) {
        return make_error("Binary diff cancelled");
    }
    report_progress(0u, 5u, "Comparing headers & cryptographic hashes");

    BinaryDiffReport report;

    // 1. Header & identity comparison
    HeaderDiffSummary& hdr = report.header;
    hdr.lhs_label = options.lhs_label;
    hdr.rhs_label = options.rhs_label;
    hdr.lhs_sha256 = sha256_hex(lhs_bytes);
    hdr.rhs_sha256 = sha256_hex(rhs_bytes);
    hdr.lhs_size = lhs_bytes.size();
    hdr.rhs_size = rhs_bytes.size();
    hdr.identical_files = (hdr.lhs_size == hdr.rhs_size) && (hdr.lhs_sha256 == hdr.rhs_sha256);

    hdr.format_matches = (lhs_image.format() == rhs_image.format());
    hdr.arch_matches = (lhs_image.architecture() == rhs_image.architecture());
    hdr.bitness_matches = (lhs_image.is_64bit() == rhs_image.is_64bit());
    hdr.endianness_matches = (lhs_image.endianness() == rhs_image.endianness());
    hdr.image_base_matches = (lhs_image.image_base() == rhs_image.image_base());
    hdr.entry_point_matches = (lhs_image.entry_point() == rhs_image.entry_point());

    const std::uint64_t lhs_entry_rva =
        lhs_image.entry_point() >= lhs_image.image_base()
            ? (lhs_image.entry_point() - lhs_image.image_base())
            : lhs_image.entry_point();
    const std::uint64_t rhs_entry_rva =
        rhs_image.entry_point() >= rhs_image.image_base()
            ? (rhs_image.entry_point() - rhs_image.image_base())
            : rhs_image.entry_point();
    hdr.entry_rva_matches = (lhs_entry_rva == rhs_entry_rva);

    auto add_field = [&](std::string_view name, std::string lv, std::string rv) {
        const bool changed = (lv != rv);
        hdr.fields.push_back(MetadataFieldDiff{
            .field_name = std::string(name),
            .lhs_value = std::move(lv),
            .rhs_value = std::move(rv),
            .changed = changed,
        });
    };

    add_field("Format", std::string(to_string(lhs_image.format())), std::string(to_string(rhs_image.format())));
    add_field("Image Kind", std::string(to_string(lhs_image.kind())), std::string(to_string(rhs_image.kind())));
    add_field("Architecture", std::string(to_string(lhs_image.architecture())), std::string(to_string(rhs_image.architecture())));
    add_field("Bitness", lhs_image.is_64bit() ? "64-bit" : "32-bit", rhs_image.is_64bit() ? "64-bit" : "32-bit");
    add_field("Endianness", std::string(to_string(lhs_image.endianness())), std::string(to_string(rhs_image.endianness())));
    add_field("File Size", std::format("{} B", hdr.lhs_size), std::format("{} B", hdr.rhs_size));
    add_field("SHA-256", hdr.lhs_sha256, hdr.rhs_sha256);
    add_field("Image Base", format_hex(lhs_image.image_base()), format_hex(rhs_image.image_base()));
    add_field("Entry Point VA", format_hex(lhs_image.entry_point()), format_hex(rhs_image.entry_point()));
    add_field("Entry Point RVA", format_hex(lhs_entry_rva), format_hex(rhs_entry_rva));
    add_field("Sections", std::to_string(lhs_image.sections().size()), std::to_string(rhs_image.sections().size()));
    add_field("Imports", std::to_string(lhs_image.imports().size()), std::to_string(rhs_image.imports().size()));
    add_field("Exports", std::to_string(lhs_image.exports().size()), std::to_string(rhs_image.exports().size()));
    add_field("Symbols", std::to_string(lhs_image.symbols().size()), std::to_string(rhs_image.symbols().size()));

    if (const PeHeader* lpe = lhs_image.pe_header(); lpe != nullptr) {
        if (const PeHeader* rpe = rhs_image.pe_header(); rpe != nullptr) {
            add_field("PE Subsystem", format_hex(lpe->subsystem, 4), format_hex(rpe->subsystem, 4));
            add_field("PE DllCharacteristics", format_hex(lpe->dll_characteristics, 4), format_hex(rpe->dll_characteristics, 4));
            add_field("PE Characteristics", format_hex(lpe->characteristics, 4), format_hex(rpe->characteristics, 4));
            add_field("PE SizeOfImage", format_hex(lpe->size_of_image), format_hex(rpe->size_of_image));
            add_field("PE Checksum", format_hex(lpe->checksum, 8), format_hex(rpe->checksum, 8));
            add_field("PE TimeDateStamp", format_hex(lpe->time_date_stamp, 8), format_hex(rpe->time_date_stamp, 8));
        }
    }
    if (const ElfHeader* lelf = lhs_image.elf_header(); lelf != nullptr) {
        if (const ElfHeader* relf = rhs_image.elf_header(); relf != nullptr) {
            add_field("ELF Type", format_hex(lelf->type, 4), format_hex(relf->type, 4));
            add_field("ELF Flags", format_hex(lelf->flags, 8), format_hex(relf->flags, 8));
            add_field("ELF Interpreter",
                      std::string(lhs_image.elf_interpreter()),
                      std::string(rhs_image.elf_interpreter()));
        }
    }
    if (const MachOHeader* lmh = lhs_image.macho_header(); lmh != nullptr) {
        if (const MachOHeader* rmh = rhs_image.macho_header(); rmh != nullptr) {
            auto describe_slice = [](const IBinaryImage& img, std::span<const std::uint8_t> raw) {
                if (img.is_universal_slice()) {
                    return std::format("Universal slice #{} ({}, off=0x{:X}, size={} B)",
                                       img.container_slice_index(),
                                       macho_diff_arch_name(img),
                                       img.container_slice_offset(),
                                       img.container_slice_size());
                }
                return std::format("Thin Mach-O ({}, {} B)",
                                   macho_diff_arch_name(img),
                                   raw.size());
            };
            add_field("Mach-O Slice",
                      describe_slice(lhs_image, lhs_bytes),
                      describe_slice(rhs_image, rhs_bytes));
            if (lhs_image.is_universal_slice() || rhs_image.is_universal_slice()) {
                const auto l_sub = lhs_image.is_universal_slice()
                    ? slice_safe(lhs_bytes, lhs_image.container_slice_offset(), lhs_image.container_slice_size())
                    : lhs_bytes;
                const auto r_sub = rhs_image.is_universal_slice()
                    ? slice_safe(rhs_bytes, rhs_image.container_slice_offset(), rhs_image.container_slice_size())
                    : rhs_bytes;
                add_field("Mach-O Slice SHA-256", sha256_hex(l_sub), sha256_hex(r_sub));
            }
            add_field("Mach-O CPU / Arch",
                      std::format("{} (0x{:08X} / 0x{:08X})",
                                  macho_diff_arch_name(lhs_image), lmh->cpu_type, lmh->cpu_subtype),
                      std::format("{} (0x{:08X} / 0x{:08X})",
                                  macho_diff_arch_name(rhs_image), rmh->cpu_type, rmh->cpu_subtype));
            add_field("Mach-O File Type",
                      macho_diff_filetype_name(lmh->file_type),
                      macho_diff_filetype_name(rmh->file_type));
            add_field("Mach-O Flags",
                      macho_diff_flags_summary(lmh->flags),
                      macho_diff_flags_summary(rmh->flags));
            add_field("Mach-O Load Commands",
                      std::format("{} cmds ({} B)", lmh->ncmds, lmh->sizeofcmds),
                      std::format("{} cmds ({} B)", rmh->ncmds, rmh->sizeofcmds));
            add_field("Mach-O UUID",
                      macho_diff_uuid_string(lhs_image),
                      macho_diff_uuid_string(rhs_image));
            add_field("Mach-O Platform / MinOS",
                      macho_diff_platform_summary(lhs_image),
                      macho_diff_platform_summary(rhs_image));
            add_field("Mach-O Dylibs",
                      macho_diff_dylibs_summary(lhs_image),
                      macho_diff_dylibs_summary(rhs_image));
            add_field("Mach-O RPATHs",
                      macho_diff_rpaths_summary(lhs_image),
                      macho_diff_rpaths_summary(rhs_image));
            add_field("Mach-O Code Signature",
                      macho_diff_codesig_summary(lhs_image),
                      macho_diff_codesig_summary(rhs_image));
            add_field("Mach-O Security Posture",
                      macho_diff_security_posture(lhs_image),
                      macho_diff_security_posture(rhs_image));
        }
    }

    // 2. Section comparison & coalesced byte hunks
    const std::vector<VaInterval> lhs_relocs = collect_relocation_va_intervals(lhs_image);
    const std::vector<VaInterval> rhs_relocs = collect_relocation_va_intervals(rhs_image);

    auto append_hunks_between_spans = [&](std::string_view sec_name,
                                          std::span<const std::uint8_t> lb,
                                          std::span<const std::uint8_t> rb,
                                          std::uint64_t l_file_base,
                                          std::uint64_t r_file_base,
                                          std::optional<std::uint64_t> l_va_base,
                                          std::optional<std::uint64_t> r_va_base,
                                          ByteHunkClassification default_cls) -> std::uint64_t {
        const std::size_t common = std::min(lb.size(), rb.size());
        std::uint64_t changed_total = 0;

        std::size_t pos = 0;
        while (pos < common) {
            if (lb[pos] == rb[pos]) {
                ++pos;
                continue;
            }
            const std::size_t hunk_start = pos;
            std::size_t hunk_end = pos + 1u;
            std::uint64_t diff_cnt = 1u;
            ++pos;

            while (pos < common) {
                if (lb[pos] != rb[pos]) {
                    hunk_end = pos + 1u;
                    ++diff_cnt;
                    ++pos;
                } else {
                    std::size_t lookahead = pos;
                    while (lookahead < common &&
                           (lookahead - pos) < options.coalesce_gap_bytes &&
                           lb[lookahead] == rb[lookahead]) {
                        ++lookahead;
                    }
                    if (lookahead < common && (lookahead - pos) <= options.coalesce_gap_bytes &&
                        lb[lookahead] != rb[lookahead]) {
                        pos = lookahead;
                    } else {
                        break;
                    }
                }
            }

            changed_total = saturating_add_u64(changed_total, diff_cnt);
            if (report.byte_hunks.size() < options.max_byte_hunks) {
                const std::size_t hunk_len = hunk_end - hunk_start;
                const std::size_t samp_len = std::min(hunk_len, options.sample_bytes_per_hunk);
                ByteDiffHunk hunk;
                hunk.section_name = std::string(sec_name);
                hunk.lhs_file_offset = saturating_add_u64(l_file_base, hunk_start);
                hunk.rhs_file_offset = saturating_add_u64(r_file_base, hunk_start);
                if (l_va_base.has_value()) hunk.lhs_va = checked_add_u64(*l_va_base, hunk_start);
                if (r_va_base.has_value()) hunk.rhs_va = checked_add_u64(*r_va_base, hunk_start);
                hunk.size = hunk_len;
                hunk.differing_bytes = diff_cnt;
                hunk.lhs_sample.assign(lb.begin() + static_cast<std::ptrdiff_t>(hunk_start),
                                       lb.begin() + static_cast<std::ptrdiff_t>(hunk_start + samp_len));
                hunk.rhs_sample.assign(rb.begin() + static_cast<std::ptrdiff_t>(hunk_start),
                                       rb.begin() + static_cast<std::ptrdiff_t>(hunk_start + samp_len));

                ByteHunkClassification cls = default_cls;
                const auto lhs_va_end =
                    hunk.lhs_va.has_value() ? checked_add_u64(*hunk.lhs_va, hunk_len) : std::nullopt;
                const auto rhs_va_end =
                    hunk.rhs_va.has_value() ? checked_add_u64(*hunk.rhs_va, hunk_len) : std::nullopt;
                if (lhs_va_end.has_value() && rhs_va_end.has_value() &&
                    (range_fully_covered_by_relocs(lhs_relocs, *hunk.lhs_va, *lhs_va_end) ||
                     range_fully_covered_by_relocs(rhs_relocs, *hunk.rhs_va, *rhs_va_end))) {
                    cls = ByteHunkClassification::RelocationOnly;
                }
                hunk.classification = cls;
                report.byte_hunks.push_back(std::move(hunk));
            } else {
                report.byte_hunks_truncated = true;
            }
        }

        if (lb.size() != rb.size()) {
            const std::size_t extra = std::max(lb.size(), rb.size()) - common;
            changed_total = saturating_add_u64(changed_total, extra);
            if (report.byte_hunks.size() < options.max_byte_hunks) {
                const std::size_t samp_len = std::min(extra, options.sample_bytes_per_hunk);
                ByteDiffHunk tail;
                tail.section_name = std::string(sec_name);
                tail.lhs_file_offset = saturating_add_u64(l_file_base, common);
                tail.rhs_file_offset = saturating_add_u64(r_file_base, common);
                if (l_va_base.has_value()) tail.lhs_va = checked_add_u64(*l_va_base, common);
                if (r_va_base.has_value()) tail.rhs_va = checked_add_u64(*r_va_base, common);
                tail.size = extra;
                tail.differing_bytes = extra;
                tail.classification = default_cls;
                tail.detail = lb.size() > rb.size() ? "Trailing bytes removed in comparison"
                                                    : "Trailing bytes added in comparison";
                if (lb.size() > common) {
                    tail.lhs_sample.assign(lb.begin() + static_cast<std::ptrdiff_t>(common),
                                           lb.begin() + static_cast<std::ptrdiff_t>(common + samp_len));
                }
                if (rb.size() > common) {
                    tail.rhs_sample.assign(rb.begin() + static_cast<std::ptrdiff_t>(common),
                                           rb.begin() + static_cast<std::ptrdiff_t>(common + samp_len));
                }
                report.byte_hunks.push_back(std::move(tail));
            } else {
                report.byte_hunks_truncated = true;
            }
        }

        return changed_total;
    };

    // Header byte diff before first raw section (slice-relative when comparing Universal Mach-O slices)
    auto slice_header_window = [](const IBinaryImage& img,
                                  std::span<const std::uint8_t> raw)
        -> std::pair<std::uint64_t, std::span<const std::uint8_t>> {
        const std::uint64_t base_off =
            img.is_universal_slice() ? img.container_slice_offset() : 0u;
        if (base_off >= raw.size()) {
            return {base_off, {}};
        }
        const std::uint64_t max_avail =
            img.is_universal_slice() && img.container_slice_size() > 0u
                ? std::min<std::uint64_t>(img.container_slice_size(), raw.size() - base_off)
                : (raw.size() - base_off);
        std::uint64_t min_rel_sec = max_avail;
        for (const Section& s : img.sections()) {
            if (s.file_size > 0u && s.file_offset > base_off) {
                min_rel_sec = std::min<std::uint64_t>(min_rel_sec, s.file_offset - base_off);
            }
        }
        const auto hdr_len =
            static_cast<std::size_t>(std::min<std::uint64_t>(min_rel_sec, std::min<std::uint64_t>(max_avail, 4096u)));
        return {base_off, raw.subspan(static_cast<std::size_t>(base_off), hdr_len)};
    };

    const auto [lhs_hdr_base, lhs_hdr_span] = slice_header_window(lhs_image, lhs_bytes);
    const auto [rhs_hdr_base, rhs_hdr_span] = slice_header_window(rhs_image, rhs_bytes);
    if (!lhs_hdr_span.empty() && !rhs_hdr_span.empty()) {
        report.total_changed_bytes += append_hunks_between_spans(
            "<headers>",
            lhs_hdr_span,
            rhs_hdr_span,
            lhs_hdr_base,
            rhs_hdr_base,
            lhs_image.image_base(),
            rhs_image.image_base(),
            ByteHunkClassification::HeaderChange);
    }

    const auto& l_secs = lhs_image.sections();
    const auto& r_secs = rhs_image.sections();
    std::vector<bool> r_matched(r_secs.size(), false);
    std::unordered_map<std::string, std::size_t> lhs_name_occ;

    if (options.stop_token.stop_requested()) {
        return make_error("Binary diff cancelled");
    }
    report_progress(1u, 5u, "Comparing sections & byte hunks");

    for (const Section& ls : l_secs) {
        if (options.stop_token.stop_requested()) {
            return make_error("Binary diff cancelled");
        }
        const std::size_t occ = lhs_name_occ[ls.name]++;
        std::size_t cur_occ = 0;
        std::optional<std::size_t> match_idx;
        for (std::size_t ri = 0; ri < r_secs.size(); ++ri) {
            if (r_secs[ri].name == ls.name) {
                if (cur_occ == occ && !r_matched[ri]) {
                    match_idx = ri;
                    break;
                }
                ++cur_occ;
            }
        }

        const auto l_slice = slice_safe(lhs_bytes, ls.file_offset, ls.file_size);
        const std::string l_hash = sha256_hex(l_slice);

        if (!match_idx.has_value()) {
            SectionDiffEntry entry;
            entry.name = ls.name;
            entry.status = DiffChangeKind::Removed;
            entry.lhs_va = ls.virtual_address;
            entry.lhs_virtual_size = ls.virtual_size;
            entry.lhs_file_offset = ls.file_offset;
            entry.lhs_file_size = ls.file_size;
            entry.lhs_flags = ls.raw_flags;
            entry.lhs_permissions = section_perms_string(ls);
            entry.lhs_sha256 = l_hash;
            entry.changed_byte_count = l_slice.size();
            report.total_changed_bytes += l_slice.size();
            ++report.sections_removed;
            report.sections.push_back(std::move(entry));
            continue;
        }

        r_matched[*match_idx] = true;
        const Section& rs = r_secs[*match_idx];
        const auto r_slice = slice_safe(rhs_bytes, rs.file_offset, rs.file_size);
        const std::string r_hash = sha256_hex(r_slice);

        const ByteHunkClassification cls =
            (ls.executable || rs.executable) ? ByteHunkClassification::CodeChange
                                             : ByteHunkClassification::DataChange;
        const std::uint64_t changed_in_sec = append_hunks_between_spans(
            ls.name,
            l_slice,
            r_slice,
            ls.file_offset,
            rs.file_offset,
            ls.virtual_address != 0u ? std::optional<std::uint64_t>(ls.virtual_address) : std::nullopt,
            rs.virtual_address != 0u ? std::optional<std::uint64_t>(rs.virtual_address) : std::nullopt,
            cls);

        report.total_changed_bytes += changed_in_sec;

        const bool meta_diff = (ls.virtual_size != rs.virtual_size) ||
                               (ls.file_size != rs.file_size) ||
                               (ls.raw_flags != rs.raw_flags) ||
                               (l_hash != r_hash);

        SectionDiffEntry entry;
        entry.name = ls.name;
        entry.status = meta_diff ? DiffChangeKind::Modified : DiffChangeKind::Unchanged;
        entry.lhs_va = ls.virtual_address;
        entry.rhs_va = rs.virtual_address;
        entry.lhs_virtual_size = ls.virtual_size;
        entry.rhs_virtual_size = rs.virtual_size;
        entry.lhs_file_offset = ls.file_offset;
        entry.rhs_file_offset = rs.file_offset;
        entry.lhs_file_size = ls.file_size;
        entry.rhs_file_size = rs.file_size;
        entry.lhs_flags = ls.raw_flags;
        entry.rhs_flags = rs.raw_flags;
        entry.lhs_permissions = section_perms_string(ls);
        entry.rhs_permissions = section_perms_string(rs);
        entry.lhs_sha256 = l_hash;
        entry.rhs_sha256 = r_hash;
        entry.changed_byte_count = changed_in_sec;

        if (meta_diff) {
            ++report.sections_modified;
        } else {
            ++report.sections_unchanged;
        }
        report.sections.push_back(std::move(entry));
    }

    for (std::size_t ri = 0; ri < r_secs.size(); ++ri) {
        if (r_matched[ri]) {
            continue;
        }
        const Section& rs = r_secs[ri];
        const auto r_slice = slice_safe(rhs_bytes, rs.file_offset, rs.file_size);
        SectionDiffEntry entry;
        entry.name = rs.name;
        entry.status = DiffChangeKind::Added;
        entry.rhs_va = rs.virtual_address;
        entry.rhs_virtual_size = rs.virtual_size;
        entry.rhs_file_offset = rs.file_offset;
        entry.rhs_file_size = rs.file_size;
        entry.rhs_flags = rs.raw_flags;
        entry.rhs_permissions = section_perms_string(rs);
        entry.rhs_sha256 = sha256_hex(r_slice);
        entry.changed_byte_count = r_slice.size();
        report.total_changed_bytes += r_slice.size();
        ++report.sections_added;
        report.sections.push_back(std::move(entry));
    }

    // Fallback raw diff if both images have 0 sections
    if (l_secs.empty() && r_secs.empty()) {
        report.total_changed_bytes = append_hunks_between_spans(
            "<raw>",
            lhs_bytes,
            rhs_bytes,
            0u,
            0u,
            lhs_image.image_base(),
            rhs_image.image_base(),
            ByteHunkClassification::DataChange);
    }

    // 3. Import comparison
    if (options.stop_token.stop_requested()) {
        return make_error("Binary diff cancelled");
    }
    report_progress(2u, 5u, "Comparing imports & exports");
    auto import_key = [](const ImportEntry& imp, Format fmt) -> std::pair<std::string, std::string> {
        const std::string lib = (fmt == Format::PE) ? to_lower_ascii(imp.library) : imp.library;
        const std::string sym = imp.import_by_ordinal
                                    ? std::format("ordinal#{}", imp.ordinal)
                                    : imp.name;
        return {lib, sym};
    };

    std::map<std::pair<std::string, std::string>, ImportEntry> l_imps;
    for (const ImportEntry& imp : lhs_image.imports()) {
        l_imps[import_key(imp, lhs_image.format())] = imp;
    }
    std::map<std::pair<std::string, std::string>, ImportEntry> r_imps;
    for (const ImportEntry& imp : rhs_image.imports()) {
        r_imps[import_key(imp, rhs_image.format())] = imp;
    }

    std::set<std::pair<std::string, std::string>> all_imp_keys;
    for (const auto& [k, _] : l_imps) all_imp_keys.insert(k);
    for (const auto& [k, _] : r_imps) all_imp_keys.insert(k);

    for (const auto& key : all_imp_keys) {
        const auto lit = l_imps.find(key);
        const auto rit = r_imps.find(key);
        ImportDiffEntry d;
        if (lit != l_imps.end() && rit == r_imps.end()) {
            d.library = lit->second.library;
            d.symbol_or_ordinal = key.second;
            d.status = DiffChangeKind::Removed;
            if (lit->second.ordinal != 0u) d.lhs_ordinal = lit->second.ordinal;
            if (lit->second.address >= lhs_image.image_base() && lit->second.address != 0u) {
                d.lhs_rva = lit->second.address - lhs_image.image_base();
            }
            d.lhs_delay_load = lit->second.delay_load;
            ++report.imports_removed;
        } else if (lit == l_imps.end() && rit != r_imps.end()) {
            d.library = rit->second.library;
            d.symbol_or_ordinal = key.second;
            d.status = DiffChangeKind::Added;
            if (rit->second.ordinal != 0u) d.rhs_ordinal = rit->second.ordinal;
            if (rit->second.address >= rhs_image.image_base() && rit->second.address != 0u) {
                d.rhs_rva = rit->second.address - rhs_image.image_base();
            }
            d.rhs_delay_load = rit->second.delay_load;
            ++report.imports_added;
        } else if (lit != l_imps.end() && rit != r_imps.end()) {
            const ImportEntry& li = lit->second;
            const ImportEntry& ri = rit->second;
            d.library = !ri.library.empty() ? ri.library : li.library;
            d.symbol_or_ordinal = key.second;
            if (li.ordinal != 0u) d.lhs_ordinal = li.ordinal;
            if (ri.ordinal != 0u) d.rhs_ordinal = ri.ordinal;
            if (li.address >= lhs_image.image_base() && li.address != 0u) {
                d.lhs_rva = li.address - lhs_image.image_base();
            }
            if (ri.address >= rhs_image.image_base() && ri.address != 0u) {
                d.rhs_rva = ri.address - rhs_image.image_base();
            }
            d.lhs_delay_load = li.delay_load;
            d.rhs_delay_load = ri.delay_load;
            const bool changed = (li.ordinal != ri.ordinal) ||
                                 (li.delay_load != ri.delay_load) ||
                                 (d.lhs_rva != d.rhs_rva);
            d.status = changed ? DiffChangeKind::Modified : DiffChangeKind::Unchanged;
            if (changed) {
                ++report.imports_modified;
                if (li.delay_load != ri.delay_load) {
                    d.detail = "Delay-load attribute changed";
                } else if (li.ordinal != ri.ordinal) {
                    d.detail = "Ordinal changed";
                } else {
                    d.detail = "IAT slot RVA shifted";
                }
            }
        }
        report.imports.push_back(std::move(d));
    }

    // 4. Export comparison
    auto export_key = [](const ExportEntry& exp) -> std::string {
        return exp.name.empty() ? std::format("ordinal#{}", exp.ordinal) : exp.name;
    };

    std::map<std::string, ExportEntry> l_exps;
    for (const ExportEntry& exp : lhs_image.exports()) l_exps[export_key(exp)] = exp;
    std::map<std::string, ExportEntry> r_exps;
    for (const ExportEntry& exp : rhs_image.exports()) r_exps[export_key(exp)] = exp;

    std::set<std::string> all_exp_keys;
    for (const auto& [k, _] : l_exps) all_exp_keys.insert(k);
    for (const auto& [k, _] : r_exps) all_exp_keys.insert(k);

    for (const std::string& key : all_exp_keys) {
        const auto lit = l_exps.find(key);
        const auto rit = r_exps.find(key);
        ExportDiffEntry d;
        d.name = key;
        if (lit != l_exps.end() && rit == r_exps.end()) {
            d.status = DiffChangeKind::Removed;
            d.lhs_ordinal = lit->second.ordinal;
            if (lit->second.virtual_address >= lhs_image.image_base()) {
                d.lhs_rva = lit->second.virtual_address - lhs_image.image_base();
            }
            d.lhs_forwarder = lit->second.forwarder;
            ++report.exports_removed;
        } else if (lit == l_exps.end() && rit != r_exps.end()) {
            d.status = DiffChangeKind::Added;
            d.rhs_ordinal = rit->second.ordinal;
            if (rit->second.virtual_address >= rhs_image.image_base()) {
                d.rhs_rva = rit->second.virtual_address - rhs_image.image_base();
            }
            d.rhs_forwarder = rit->second.forwarder;
            ++report.exports_added;
        } else if (lit != l_exps.end() && rit != r_exps.end()) {
            const ExportEntry& le = lit->second;
            const ExportEntry& re = rit->second;
            d.lhs_ordinal = le.ordinal;
            d.rhs_ordinal = re.ordinal;
            if (le.virtual_address >= lhs_image.image_base()) {
                d.lhs_rva = le.virtual_address - lhs_image.image_base();
            }
            if (re.virtual_address >= rhs_image.image_base()) {
                d.rhs_rva = re.virtual_address - rhs_image.image_base();
            }
            d.lhs_forwarder = le.forwarder;
            d.rhs_forwarder = re.forwarder;
            const bool changed = (le.ordinal != re.ordinal) ||
                                 (d.lhs_rva != d.rhs_rva) ||
                                 (le.forwarder != re.forwarder);
            d.status = changed ? DiffChangeKind::Modified : DiffChangeKind::Unchanged;
            if (changed) {
                ++report.exports_modified;
                if (le.forwarder != re.forwarder) {
                    d.detail = "Forwarder target changed";
                } else if (le.ordinal != re.ordinal) {
                    d.detail = "Export ordinal changed";
                } else {
                    d.detail = "Export RVA changed";
                }
            }
        }
        report.exports.push_back(std::move(d));
    }

    // 5. Three-tier relocation- & address-shift-tolerant function matching
    if (options.stop_token.stop_requested()) {
        return make_error("Binary diff cancelled");
    }
    report_progress(3u, 5u, "Extracting & normalizing functions");
    const std::vector<ExtractedFunction> l_funcs = extract_functions_for_diff(lhs_image, lhs_bytes);
    if (options.stop_token.stop_requested()) {
        return make_error("Binary diff cancelled");
    }
    const std::vector<ExtractedFunction> r_funcs = extract_functions_for_diff(rhs_image, rhs_bytes);
    report_progress(4u, 5u, "Matching functions across builds");

    std::vector<bool> l_used(l_funcs.size(), false);
    std::vector<bool> r_used(r_funcs.size(), false);

    auto record_matched_pair = [&](std::size_t li, std::size_t ri, std::string_view basis) {
        l_used[li] = true;
        r_used[ri] = true;
        const ExtractedFunction& lf = l_funcs[li];
        const ExtractedFunction& rf = r_funcs[ri];

        FunctionDiffEntry fe;
        fe.display_name = lf.has_real_name ? lf.canonical_name
                                           : (rf.has_real_name ? rf.canonical_name : lf.canonical_name);
        fe.raw_lhs_name = lf.raw_name;
        fe.raw_rhs_name = rf.raw_name;
        fe.match_basis = std::string(basis);
        fe.lhs_va = lf.va;
        fe.rhs_va = rf.va;
        fe.lhs_file_offset = lf.file_offset;
        fe.rhs_file_offset = rf.file_offset;
        fe.lhs_size = lf.size;
        fe.rhs_size = rf.size;
        fe.size_delta = static_cast<std::int64_t>(rf.size) - static_cast<std::int64_t>(lf.size);
        fe.lhs_normalized_sha256 = lf.normalized_sha256;
        fe.rhs_normalized_sha256 = rf.normalized_sha256;

        const bool raw_equal = (lf.raw_bytes.size() == rf.raw_bytes.size()) &&
                               std::equal(lf.raw_bytes.begin(), lf.raw_bytes.end(), rf.raw_bytes.begin());
        const bool norm_equal = (lf.size == rf.size) && (lf.normalized_sha256 == rf.normalized_sha256);

        if (raw_equal && lf.va == rf.va) {
            fe.status = FunctionMatchKind::Identical;
            fe.similarity = 1.0;
            ++report.functions_identical;
        } else if (raw_equal || norm_equal) {
            fe.status = FunctionMatchKind::IdenticalRelocated;
            fe.similarity = 1.0;
            ++report.functions_relocated;
        } else {
            fe.status = FunctionMatchKind::Modified;
            fe.similarity = compute_normalized_similarity(lf.normalized_bytes, rf.normalized_bytes);
            ++report.functions_modified;
        }
        report.functions.push_back(std::move(fe));
    };

    // Pass 1: Exact canonical/demangled symbol name match
    std::unordered_map<std::string, std::vector<std::size_t>> r_by_name;
    for (std::size_t ri = 0; ri < r_funcs.size(); ++ri) {
        if (r_funcs[ri].has_real_name) {
            r_by_name[r_funcs[ri].canonical_name].push_back(ri);
        }
    }
    for (std::size_t li = 0; li < l_funcs.size(); ++li) {
        if (!l_funcs[li].has_real_name) {
            continue;
        }
        auto it = r_by_name.find(l_funcs[li].canonical_name);
        if (it == r_by_name.end()) {
            continue;
        }
        for (const std::size_t ri : it->second) {
            if (!r_used[ri]) {
                record_matched_pair(li, ri, "ExactName");
                break;
            }
        }
    }

    // Pass 2: Normalized instruction/byte fingerprint hash match (handles stripped & renamed functions)
    std::unordered_map<std::string, std::vector<std::size_t>> r_by_norm_hash;
    for (std::size_t ri = 0; ri < r_funcs.size(); ++ri) {
        if (!r_used[ri]) {
            r_by_norm_hash[r_funcs[ri].normalized_sha256].push_back(ri);
        }
    }
    for (std::size_t li = 0; li < l_funcs.size(); ++li) {
        if (l_used[li]) {
            continue;
        }
        auto it = r_by_norm_hash.find(l_funcs[li].normalized_sha256);
        if (it == r_by_norm_hash.end()) {
            continue;
        }
        std::optional<std::size_t> best_ri;
        std::uint64_t best_dist = std::numeric_limits<std::uint64_t>::max();
        for (const std::size_t ri : it->second) {
            if (r_used[ri] || r_funcs[ri].size != l_funcs[li].size) {
                continue;
            }
            const std::uint64_t dist = l_funcs[li].va > r_funcs[ri].va
                                           ? (l_funcs[li].va - r_funcs[ri].va)
                                           : (r_funcs[ri].va - l_funcs[li].va);
            if (dist < best_dist) {
                best_dist = dist;
                best_ri = ri;
            }
        }
        if (best_ri.has_value()) {
            record_matched_pair(li, *best_ri, "NormalizedFingerprint");
        }
    }

    // Pass 3: Size & normalized 4-gram similarity fallback for modified anonymous/renamed functions
    for (std::size_t li = 0; li < l_funcs.size(); ++li) {
        if (options.stop_token.stop_requested()) {
            return make_error("Binary diff cancelled");
        }
        if (l_used[li] || l_funcs[li].size < 8u) {
            continue;
        }
        double best_sim = options.min_function_similarity;
        std::optional<std::size_t> best_ri;
        for (std::size_t ri = 0; ri < r_funcs.size(); ++ri) {
            if (r_used[ri] || r_funcs[ri].size < 8u) {
                continue;
            }
            const std::uint64_t min_sz = std::min(l_funcs[li].size, r_funcs[ri].size);
            const std::uint64_t max_sz = std::max(l_funcs[li].size, r_funcs[ri].size);
            if ((max_sz - min_sz) > min_sz) {
                continue;
            }
            const double sim = compute_normalized_similarity(
                l_funcs[li].normalized_bytes, r_funcs[ri].normalized_bytes);
            if (sim > best_sim) {
                best_sim = sim;
                best_ri = ri;
            }
        }
        if (best_ri.has_value()) {
            record_matched_pair(li, *best_ri, "Similarity");
        }
    }

    // Emit remaining unmatched functions as Removed / Added
    for (std::size_t li = 0; li < l_funcs.size(); ++li) {
        if (l_used[li]) continue;
        const ExtractedFunction& lf = l_funcs[li];
        FunctionDiffEntry fe;
        fe.display_name = lf.canonical_name;
        fe.raw_lhs_name = lf.raw_name;
        fe.status = FunctionMatchKind::Removed;
        fe.match_basis = "Unmatched";
        fe.lhs_va = lf.va;
        fe.lhs_file_offset = lf.file_offset;
        fe.lhs_size = lf.size;
        fe.size_delta = -static_cast<std::int64_t>(lf.size);
        fe.similarity = 0.0;
        fe.lhs_normalized_sha256 = lf.normalized_sha256;
        ++report.functions_removed;
        report.functions.push_back(std::move(fe));
    }

    for (std::size_t ri = 0; ri < r_funcs.size(); ++ri) {
        if (r_used[ri]) continue;
        const ExtractedFunction& rf = r_funcs[ri];
        FunctionDiffEntry fe;
        fe.display_name = rf.canonical_name;
        fe.raw_rhs_name = rf.raw_name;
        fe.status = FunctionMatchKind::Added;
        fe.match_basis = "Unmatched";
        fe.rhs_va = rf.va;
        fe.rhs_file_offset = rf.file_offset;
        fe.rhs_size = rf.size;
        fe.size_delta = static_cast<std::int64_t>(rf.size);
        fe.similarity = 0.0;
        fe.rhs_normalized_sha256 = rf.normalized_sha256;
        ++report.functions_added;
        report.functions.push_back(std::move(fe));
    }

    std::ranges::sort(report.functions, [](const FunctionDiffEntry& a, const FunctionDiffEntry& b) {
        const std::uint64_t va_a = a.lhs_va.value_or(a.rhs_va.value_or(0u));
        const std::uint64_t va_b = b.lhs_va.value_or(b.rhs_va.value_or(0u));
        return std::tie(va_a, a.display_name) < std::tie(va_b, b.display_name);
    });

    report_progress(5u, 5u, "Comparison complete");
    return report;
}

Result<ResolvedDiffImagePair> open_matched_diff_images(
    std::span<const std::uint8_t> lhs_bytes,
    std::span<const std::uint8_t> rhs_bytes,
    const BinaryDiffOptions& options) {
    ResolvedDiffImagePair pair{};
    if (auto lc = inspect_binary_container(lhs_bytes); lc.has_value()) {
        pair.lhs_container = std::move(*lc);
    }
    if (auto rc = inspect_binary_container(rhs_bytes); rc.has_value()) {
        pair.rhs_container = std::move(*rc);
    }

    BinaryOpenOptions lhs_opts{};
    if (options.lhs_slice_index.has_value()) {
        lhs_opts.selected_slice_index = *options.lhs_slice_index;
    } else if (!options.lhs_arch_name.empty()) {
        lhs_opts.preferred_arch_name = options.lhs_arch_name;
    } else if (pair.lhs_container.is_universal_container &&
               !pair.rhs_container.is_universal_container &&
               pair.rhs_container.slices.size() == 1u) {
        // Match Universal LHS slice against thin RHS architecture automatically.
        lhs_opts.preferred_arch_name = pair.rhs_container.slices.front().arch_name;
        lhs_opts.preferred_architecture = pair.rhs_container.slices.front().arch;
    }

    auto lhs_img = open_binary_image(lhs_bytes, lhs_opts);
    if (!lhs_img.has_value()) {
        return std::unexpected(lhs_img.error());
    }
    pair.lhs_image = std::move(*lhs_img);

    BinaryOpenOptions rhs_opts{};
    if (options.rhs_slice_index.has_value()) {
        rhs_opts.selected_slice_index = *options.rhs_slice_index;
    } else if (!options.rhs_arch_name.empty()) {
        rhs_opts.preferred_arch_name = options.rhs_arch_name;
    } else if (pair.rhs_container.is_universal_container) {
        // Match Universal RHS slice against the active LHS slice architecture.
        std::string target_arch_name;
        const std::size_t l_idx = pair.lhs_image->container_slice_index();
        if (l_idx < pair.lhs_container.slices.size()) {
            target_arch_name = pair.lhs_container.slices[l_idx].arch_name;
        } else {
            target_arch_name = macho_diff_arch_name(*pair.lhs_image);
        }
        const Architecture target_arch = pair.lhs_image->architecture();
        bool has_compatible_rhs_slice = false;
        for (const BinarySliceDescriptor& sl : pair.rhs_container.slices) {
            if (sl.arch == target_arch || (!target_arch_name.empty() && sl.arch_name == target_arch_name)) {
                has_compatible_rhs_slice = true;
                break;
            }
        }
        if (has_compatible_rhs_slice) {
            rhs_opts.preferred_architecture = target_arch;
            if (!target_arch_name.empty()) {
                const bool exact_in_rhs = std::ranges::any_of(
                    pair.rhs_container.slices,
                    [&](const BinarySliceDescriptor& sl) { return sl.arch_name == target_arch_name; });
                if (exact_in_rhs) {
                    rhs_opts.preferred_arch_name = target_arch_name;
                }
            }
        }
    }

    auto rhs_img = open_binary_image(rhs_bytes, rhs_opts);
    if (!rhs_img.has_value()) {
        return std::unexpected(rhs_img.error());
    }
    pair.rhs_image = std::move(*rhs_img);
    return pair;
}

Result<BinaryDiffReport> compare_binaries(
    std::span<const std::uint8_t> lhs_bytes,
    std::span<const std::uint8_t> rhs_bytes,
    const BinaryDiffOptions& options) {
    auto opened = open_matched_diff_images(lhs_bytes, rhs_bytes, options);
    if (!opened.has_value()) {
        return std::unexpected(opened.error());
    }
    return compare_binaries(*opened->lhs_image, lhs_bytes, *opened->rhs_image, rhs_bytes, options);
}

Result<BinaryDiffReport> compare_binary_files(
    const std::filesystem::path& lhs_path,
    const std::filesystem::path& rhs_path,
    const BinaryDiffOptions& options) {
    auto read_all = [](const std::filesystem::path& p) -> Result<std::vector<std::uint8_t>> {
        std::ifstream ifs(p, std::ios::binary | std::ios::ate);
        if (!ifs) {
            return make_error(std::format("Failed to open '{}' for binary comparison", p.string()));
        }
        const auto end_pos = ifs.tellg();
        if (end_pos < 0) {
            return make_error(std::format("Failed to determine file size of '{}'", p.string()));
        }
        std::vector<std::uint8_t> data(static_cast<std::size_t>(end_pos));
        ifs.seekg(0, std::ios::beg);
        if (!data.empty() && !ifs.read(reinterpret_cast<char*>(data.data()),
                                       static_cast<std::streamsize>(data.size()))) {
            return make_error(std::format("Failed while reading '{}'", p.string()));
        }
        return data;
    };

    auto lhs = read_all(lhs_path);
    if (!lhs.has_value()) return std::unexpected(lhs.error());
    if (options.stop_token.stop_requested()) return make_error("Binary diff cancelled");
    auto rhs = read_all(rhs_path);
    if (!rhs.has_value()) return std::unexpected(rhs.error());
    if (options.stop_token.stop_requested()) return make_error("Binary diff cancelled");

    BinaryDiffOptions eff = options;
    if (eff.lhs_label == "Primary") eff.lhs_label = lhs_path.filename().string();
    if (eff.rhs_label == "Comparison") eff.rhs_label = rhs_path.filename().string();
    return compare_binaries(*lhs, *rhs, eff);
}

// ---------------------------------------------------------------------------
// On-Disk vs. Live-Attached RAM Integrity & Hook Diff
// ---------------------------------------------------------------------------

Result<LiveModuleIntegrityReport> compare_module_disk_to_live(
    const IBinaryImage& disk_image,
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    const LiveIntegrityDiffOptions& options) {
    if (disk_file_bytes.empty()) {
        return make_error("On-disk module byte buffer is empty");
    }
    if (live_module.base_address == 0u) {
        return make_error("Live module base address is zero");
    }
    auto report_progress = [&](std::size_t completed, std::size_t total, std::string_view stage) {
        if (options.progress_callback) {
            options.progress_callback(completed, total, stage);
        }
    };
    if (options.stop_token.stop_requested()) {
        return make_error("Live integrity diff cancelled");
    }
    report_progress(0u, 3u, "Preparing expected module sections & relocations");

    LiveModuleIntegrityReport report;
    report.module_name = live_module.name;
    report.disk_path = live_module.path.string();
    report.static_preferred_base = disk_image.image_base();
    report.live_base_address = live_module.base_address;
    report.aslr_load_bias = static_cast<std::int64_t>(
        live_module.base_address - disk_image.image_base());
    report.disk_sha256 = sha256_hex(disk_file_bytes);

    const std::uint64_t static_base = disk_image.image_base();
    const std::uint64_t live_base = live_module.base_address;
    const std::uint64_t bias_u64 = live_base - static_base;
    const bool is64 = disk_image.is_64bit();
    const Endianness endian = disk_image.endianness();
    const std::size_t ptr_size = is64 ? 8u : 4u;

    std::vector<ModuleInfo> all_modules;
    if (auto mods = session.modules(); mods.has_value()) {
        all_modules = std::move(*mods);
    }
    std::vector<MemoryRegion> all_regions;
    if (auto regs = session.memory_regions(); regs.has_value()) {
        all_regions = std::move(*regs);
    }

    report.live_provenance =
        session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::LiveMemory;
    report.backing_identity = verify_live_module_backing_identity(
        disk_image,
        disk_file_bytes,
        session,
        live_module,
        all_regions);
    {
        TargetInstanceId tid;
        tid.backend = session.is_crash_dump()
                          ? BackendKind::CrashDumpElfCore
                          : BackendKind::LiveNativeReadOnly;
        tid.pid = session.pid();
        tid.creation_identity =
            session.is_crash_dump() ? std::nullopt : query_process_creation_identity(session.pid());
        tid.image_sha256 = report.disk_sha256;
        tid.build_id_or_pdb_guid = report.backing_identity.live_identifier;
        report.live_capture_stamp = CaptureStamp::capture_now(
            tid,
            1u,
            session.is_suspended(),
            CaptureAvailability::Complete);
    }

    auto find_module_for_va = [&](std::uint64_t va) -> const ModuleInfo* {
        for (const ModuleInfo& m : all_modules) {
            if (m.size > 0u && va >= m.base_address && (va - m.base_address) < m.size) {
                return &m;
            }
        }
        return nullptr;
    };

    auto find_region_for_va = [&](std::uint64_t va) -> const MemoryRegion* {
        for (const MemoryRegion& r : all_regions) {
            if (va >= r.start_address && va < r.end_address) {
                return &r;
            }
        }
        return nullptr;
    };

    // Map symbol names by RVA for clear inline-hook attribution
    struct SymSpan {
        std::uint64_t rva_start{0};
        std::uint64_t rva_end{0};
        std::string name{};
    };
    std::vector<SymSpan> sym_spans;
    for (const Symbol& s : disk_image.symbols()) {
        if (s.virtual_address >= static_base && !s.name.empty()) {
            const std::uint64_t rva = s.virtual_address - static_base;
            sym_spans.push_back(SymSpan{
                rva,
                saturating_add_u64(rva, std::max<std::uint64_t>(s.size, 1u)),
                demangle_or_raw(s.name)});
        }
    }
    for (const ExportEntry& e : disk_image.exports()) {
        if (e.forwarder.empty() && e.virtual_address >= static_base && !e.name.empty()) {
            const std::uint64_t rva = e.virtual_address - static_base;
            sym_spans.push_back(SymSpan{rva, saturating_add_u64(rva, 16u), demangle_or_raw(e.name)});
        }
    }
    auto resolve_rva_symbol = [&](std::uint64_t rva) -> std::string {
        for (const SymSpan& sp : sym_spans) {
            if (rva >= sp.rva_start && rva < sp.rva_end) {
                return sp.name;
            }
        }
        return {};
    };

    // Build per-section expected RAM buffers with legitimate relocations applied
    struct PreparedSection {
        const Section* sec{nullptr};
        std::uint64_t rva{0};
        std::uint64_t live_va{0};
        std::vector<std::uint8_t> expected{};
        std::vector<std::uint8_t> ignore_mask{}; // 1 = handled via IAT/GOT/security_cookie
    };

    std::vector<PreparedSection> prepared;
    for (const Section& sec : disk_image.sections()) {
        const std::uint64_t map_len =
            sec.file_size > 0u
                ? std::min<std::uint64_t>(std::max(sec.virtual_size, sec.file_size), 64ull * 1024ull * 1024ull)
                : 0u;
        if (map_len == 0u || sec.virtual_address < static_base ||
            add_u64_overflows(sec.virtual_address, map_len)) {
            continue;
        }
        const std::uint64_t rva = sec.virtual_address - static_base;
        if (add_u64_overflows(rva, map_len)) {
            continue;
        }
        const auto live_va = checked_add_u64(live_base, rva);
        if (!live_va.has_value() || add_u64_overflows(*live_va, map_len)) {
            continue;
        }
        PreparedSection ps;
        ps.sec = &sec;
        ps.rva = rva;
        ps.live_va = *live_va;
        ps.expected.assign(static_cast<std::size_t>(map_len), 0u);
        ps.ignore_mask.assign(static_cast<std::size_t>(map_len), 0u);

        const auto disk_slice = slice_safe(disk_file_bytes, sec.file_offset, std::min(sec.file_size, map_len));
        std::copy(disk_slice.begin(), disk_slice.end(), ps.expected.begin());
        prepared.push_back(std::move(ps));
    }

    auto find_prepared_rva = [&](std::uint64_t rva, std::size_t width) -> std::pair<PreparedSection*, std::size_t> {
        for (PreparedSection& ps : prepared) {
            if (rva >= ps.rva &&
                width <= ps.expected.size() &&
                (rva - ps.rva) <= (ps.expected.size() - width)) {
                return {&ps, static_cast<std::size_t>(rva - ps.rva)};
            }
        }
        return {nullptr, 0u};
    };

    // Apply PE base relocations (.reloc)
    for (const PeBaseRelocationBlock& blk : disk_image.pe_base_relocations()) {
        for (const PeBaseRelocationEntry& rel : blk.entries) {
            if (rel.type == 10u) { // IMAGE_REL_BASED_DIR64
                if (auto [ps, off] = find_prepared_rva(rel.rva, 8u); ps != nullptr) {
                    const std::uint64_t orig = read_le64(ps->expected, off);
                    write_le64(ps->expected, off, orig + bias_u64);
                    ++report.normalized_relocation_count;
                }
            } else if (rel.type == 3u) { // IMAGE_REL_BASED_HIGHLOW
                if (auto [ps, off] = find_prepared_rva(rel.rva, 4u); ps != nullptr) {
                    const std::uint32_t orig = read_le32(ps->expected, off);
                    write_le32(ps->expected, off, orig + static_cast<std::uint32_t>(bias_u64));
                    ++report.normalized_relocation_count;
                }
            } else if (rel.type == 1u) { // IMAGE_REL_BASED_HIGH
                if (auto [ps, off] = find_prepared_rva(rel.rva, 2u); ps != nullptr) {
                    const auto orig = static_cast<std::uint16_t>(
                        ps->expected[off] | (static_cast<std::uint16_t>(ps->expected[off + 1u]) << 8u));
                    const auto reb = static_cast<std::uint16_t>(orig + ((bias_u64 >> 16u) & 0xFFFFu));
                    ps->expected[off] = static_cast<std::uint8_t>(reb & 0xFFu);
                    ps->expected[off + 1u] = static_cast<std::uint8_t>((reb >> 8u) & 0xFFu);
                    ++report.normalized_relocation_count;
                }
            } else if (rel.type == 2u) { // IMAGE_REL_BASED_LOW
                if (auto [ps, off] = find_prepared_rva(rel.rva, 2u); ps != nullptr) {
                    const auto orig = static_cast<std::uint16_t>(
                        ps->expected[off] | (static_cast<std::uint16_t>(ps->expected[off + 1u]) << 8u));
                    const auto reb = static_cast<std::uint16_t>(orig + (bias_u64 & 0xFFFFu));
                    ps->expected[off] = static_cast<std::uint8_t>(reb & 0xFFu);
                    ps->expected[off + 1u] = static_cast<std::uint8_t>((reb >> 8u) & 0xFFu);
                    ++report.normalized_relocation_count;
                }
            }
        }
    }

    // Normalize PE LoadConfig __security_cookie (Windows loader initializes it at process start)
    if (const PeLoadConfigDirectory* lc = disk_image.pe_load_config_directory();
        lc != nullptr && lc->security_cookie >= static_base) {
        const std::uint64_t cookie_rva = lc->security_cookie - static_base;
        if (auto [ps, off] = find_prepared_rva(cookie_rva, ptr_size); ps != nullptr) {
            std::fill_n(ps->ignore_mask.begin() + static_cast<std::ptrdiff_t>(off), ptr_size, std::uint8_t{1});
        }
    }

    // Apply ELF relative relocations & collect GOT/PLT dynamic symbol slots
    struct LoaderSlotCandidate {
        std::string category{};
        std::string library{};
        std::string symbol_name{};
        std::uint64_t rva{0};
    };
    std::vector<LoaderSlotCandidate> slot_candidates;

    for (const ImportEntry& imp : disk_image.imports()) {
        if (imp.address >= static_base && imp.address != 0u) {
            slot_candidates.push_back(LoaderSlotCandidate{
                .category = "IAT",
                .library = imp.library,
                .symbol_name = imp.import_by_ordinal ? std::format("ordinal#{}", imp.ordinal) : imp.name,
                .rva = imp.address - static_base,
            });
        }
    }

    const Architecture arch = disk_image.architecture();
    for (const ElfRelocation& rel : disk_image.elf_relocations()) {
        if (rel.offset < static_base) {
            continue;
        }
        const std::uint64_t rva = rel.offset - static_base;

        bool is_relative = false;
        bool is_got_plt = false;
        if (arch == Architecture::X86_64) {
            is_relative = (rel.type == 8u || rel.type == 37u); // R_X86_64_RELATIVE / IRELATIVE
            is_got_plt = (rel.type == 6u || rel.type == 7u || rel.type == 1u); // GLOB_DATA / JUMP_SLOT / 64
        } else if (arch == Architecture::X86) {
            is_relative = (rel.type == 8u || rel.type == 42u);
            is_got_plt = (rel.type == 6u || rel.type == 7u || rel.type == 1u);
        } else if (arch == Architecture::ARM64) {
            is_relative = (rel.type == 1027u || rel.type == 1032u);
            is_got_plt = (rel.type == 1025u || rel.type == 1026u || rel.type == 257u);
        } else if (arch == Architecture::ARM) {
            is_relative = (rel.type == 23u);
            is_got_plt = (rel.type == 21u || rel.type == 22u || rel.type == 2u);
        } else if (arch == Architecture::RISCV32 || arch == Architecture::RISCV64) {
            is_relative = (rel.type == 3u);
            is_got_plt = (rel.type == 1u || rel.type == 2u || rel.type == 5u);
        }

        if (is_relative && rel.symbol_index == 0u) {
            if (auto [ps, off] = find_prepared_rva(rva, ptr_size); ps != nullptr) {
                if (rel.type == 37u || rel.type == 42u || rel.type == 1032u) {
                    // IRELATIVE resolvers compute CPU-specific target in GOT at startup
                    std::fill_n(ps->ignore_mask.begin() + static_cast<std::ptrdiff_t>(off),
                                ptr_size,
                                std::uint8_t{1});
                } else {
                    const std::uint64_t expected_val =
                        rel.has_addend
                            ? add_signed_offset_wrapping(live_base, rel.addend)
                            : (read_ptr_endian(ps->expected, off, is64, endian) + bias_u64);
                    write_ptr_endian(ps->expected, off, expected_val, is64, endian);
                }
                ++report.normalized_relocation_count;
            }
        } else if (is_got_plt) {
            slot_candidates.push_back(LoaderSlotCandidate{
                .category = "GOT/PLT",
                .library = {},
                .symbol_name = rel.symbol_name.empty() ? std::format("sym#{}", rel.symbol_index) : rel.symbol_name,
                .rva = rva,
            });
        }
    }

    // Also ignore the first 3 reserved GOT header entries in `.got.plt` (`_DYNAMIC`, `link_map*`, `_dl_runtime_resolve`)
    for (PreparedSection& ps : prepared) {
        if ((ps.sec->name == ".got.plt" || ps.sec->name == ".got") && ps.expected.size() >= ptr_size * 3u) {
            if (ps.sec->name == ".got.plt") {
                std::fill_n(ps.ignore_mask.begin(), ptr_size * 3u, std::uint8_t{1});
            }
        }
    }

    // Evaluate IAT / GOT pointer slots against live RAM
    if (options.stop_token.stop_requested()) {
        return make_error("Live integrity diff cancelled");
    }
    report_progress(1u, 3u, "Inspecting live IAT / GOT pointer slots");
    const std::uint64_t disk_image_span = estimate_image_span(disk_image);
    std::set<std::uint64_t> seen_slot_rvas;
    for (const LoaderSlotCandidate& cand : slot_candidates) {
        if (options.stop_token.stop_requested()) {
            return make_error("Live integrity diff cancelled");
        }
        if (!seen_slot_rvas.insert(cand.rva).second) {
            continue;
        }
        auto [ps, off] = find_prepared_rva(cand.rva, ptr_size);
        if (ps == nullptr) {
            continue;
        }
        std::fill_n(ps->ignore_mask.begin() + static_cast<std::ptrdiff_t>(off), ptr_size, std::uint8_t{1});

        const std::uint64_t disk_val = read_ptr_endian(ps->expected, off, is64, endian);
        const std::uint64_t slot_va = ps->live_va + off;
        const MemorySample samp = read_memory_tolerant(session, all_regions, slot_va, ptr_size);
        if (options.stop_token.stop_requested()) {
            return make_error("Live integrity diff cancelled");
        }
        if (samp.readable_count < ptr_size) {
            continue;
        }

        const std::uint64_t live_ptr = read_ptr_endian(samp.bytes, 0u, is64, endian);
        const ModuleInfo* target_mod = find_module_for_va(live_ptr);
        const MemoryRegion* target_reg = find_region_for_va(live_ptr);

        LiveLoaderSlotEntry slot;
        slot.category = cand.category;
        slot.library = cand.library;
        slot.symbol_name = demangle_or_raw(cand.symbol_name);
        slot.live_slot_va = slot_va;
        slot.rva = cand.rva;
        slot.disk_value = disk_val;
        slot.live_target_va = live_ptr;
        if (target_mod != nullptr) {
            slot.target_module_name = target_mod->name;
        }

        const std::uint64_t rebased_disk_val =
            (disk_val >= static_base && (disk_val - static_base) < disk_image_span)
                ? (disk_val + bias_u64)
                : disk_val;

        bool hooked = false;
        if (live_ptr == disk_val || live_ptr == rebased_disk_val) {
            slot.detail = "Unresolved lazy stub / matches on-disk thunk";
        } else if (target_reg != nullptr && target_reg->protection.writable && target_reg->protection.executable) {
            hooked = true;
            slot.detail = std::format("{} slot points into RWX memory region at 0x{:X}", cand.category, live_ptr);
        } else if (target_mod == nullptr && (!all_modules.empty() || !all_regions.empty())) {
            // Allow Linux `[vdso]` time/gettimeofday fast-path resolution
            if (target_reg != nullptr && target_reg->kind == MemoryRegionKind::Vdso) {
                slot.detail = "Resolved into kernel [vdso] fast path";
            } else {
                hooked = true;
                slot.detail = std::format("{} slot points to unbacked/unknown address 0x{:X}", cand.category, live_ptr);
            }
        } else if (target_mod != nullptr) {
            if (disk_image.format() == Format::PE && !cand.library.empty()) {
                if (target_mod->base_address == live_base) {
                    hooked = true;
                    slot.detail = std::format(
                        "IAT import {}!{} redirected back inside module '{}' (0x{:X})",
                        cand.library,
                        slot.symbol_name,
                        target_mod->name,
                        live_ptr);
                } else if (!pe_import_matches_loaded_module(cand.library, target_mod->name)) {
                    hooked = true;
                    slot.detail = std::format(
                        "IAT import {}!{} redirected to unexpected module '{}' (0x{:X})",
                        cand.library,
                        slot.symbol_name,
                        target_mod->name,
                        live_ptr);
                } else {
                    slot.detail = std::format("Resolved to {} (0x{:X})", target_mod->name, live_ptr);
                }
            } else {
                slot.detail = std::format("Resolved to {} (0x{:X})", target_mod->name, live_ptr);
            }
        } else {
            slot.detail = std::format("Resolved pointer 0x{:X}", live_ptr);
        }

        slot.is_hooked = hooked;
        if (hooked) {
            ++report.iat_got_hook_count;
            if (report.findings.size() < options.max_hunks) {
                ByteDiffHunk h;
                h.section_name = ps->sec->name;
                h.lhs_file_offset = saturating_add_u64(ps->sec->file_offset, off);
                h.lhs_va = ps->sec->virtual_address + off;
                h.rhs_va = slot_va;
                h.size = ptr_size;
                h.differing_bytes = ptr_size;
                h.classification = ByteHunkClassification::IatGotPointerHook;
                h.lhs_sample.assign(ps->expected.begin() + static_cast<std::ptrdiff_t>(off),
                                    ps->expected.begin() + static_cast<std::ptrdiff_t>(off + ptr_size));
                h.rhs_sample.assign(samp.bytes.begin(), samp.bytes.end());
                h.symbol_context = slot.symbol_name;
                h.detail = slot.detail;
                report.findings.push_back(std::move(h));
            }
        } else {
            ++report.normalized_loader_slot_count;
        }
        report.loader_slots.push_back(std::move(slot));
    }

    // Compare each mapped section against live process memory
    bool any_readable = false;
    std::size_t sec_idx = 0u;
    for (const PreparedSection& ps : prepared) {
        if (options.stop_token.stop_requested()) {
            return make_error("Live integrity diff cancelled");
        }
        report_progress(
            2u,
            3u,
            std::format("Scanning live section {} ({}/{})", ps.sec->name, sec_idx + 1u, prepared.size()));
        ++sec_idx;
        const MemorySample live = read_memory_tolerant(session, all_regions, ps.live_va, ps.expected.size());
        if (options.stop_token.stop_requested()) {
            return make_error("Live integrity diff cancelled");
        }
        if (live.readable_count > 0u) {
            any_readable = true;
        }
        report.unreadable_live_bytes += (ps.expected.size() - live.readable_count);

        const bool is_exec = ps.sec->executable;
        const bool is_writable_data = ps.sec->writable && !ps.sec->executable;

        std::size_t pos = 0;
        const std::size_t n = ps.expected.size();
        while (pos < n) {
            if (live.valid[pos] == 0u || ps.ignore_mask[pos] != 0u ||
                live.bytes[pos] == ps.expected[pos]) {
                ++pos;
                continue;
            }

            const std::size_t hunk_start = pos;
            std::size_t hunk_end = pos + 1u;
            std::uint64_t diff_cnt = 1u;
            ++pos;

            while (pos < n) {
                if (live.valid[pos] != 0u && ps.ignore_mask[pos] == 0u &&
                    live.bytes[pos] != ps.expected[pos]) {
                    hunk_end = pos + 1u;
                    ++diff_cnt;
                    ++pos;
                } else {
                    std::size_t look = pos;
                    while (look < n && (look - pos) < options.coalesce_gap_bytes &&
                           (live.valid[look] == 0u || ps.ignore_mask[look] != 0u ||
                            live.bytes[look] == ps.expected[look])) {
                        ++look;
                    }
                    if (look < n && (look - pos) <= options.coalesce_gap_bytes &&
                        live.valid[look] != 0u && ps.ignore_mask[look] == 0u &&
                        live.bytes[look] != ps.expected[look]) {
                        pos = look;
                    } else {
                        break;
                    }
                }
            }

            if (is_writable_data) {
                report.writable_data_changed_bytes += diff_cnt;
                if (!options.include_writable_data_hunks) {
                    continue;
                }
            }

            const std::size_t hunk_len = hunk_end - hunk_start;
            const std::size_t samp_len = std::min(hunk_len, options.sample_bytes_per_hunk);
            const std::uint64_t hunk_rva = ps.rva + hunk_start;

            ByteHunkClassification cls = ByteHunkClassification::ReadOnlyDataModified;
            if (is_exec) {
                cls = ByteHunkClassification::InlineCodeHook;
                ++report.inline_code_hook_count;
            } else if (is_writable_data) {
                cls = ByteHunkClassification::WritableRuntimeData;
            } else {
                ++report.readonly_data_diff_count;
            }

            if (report.findings.size() < options.max_hunks) {
                ByteDiffHunk h;
                h.section_name = ps.sec->name;
                h.lhs_file_offset = saturating_add_u64(ps.sec->file_offset, hunk_start);
                h.lhs_va = ps.sec->virtual_address + hunk_start;
                h.rhs_va = ps.live_va + hunk_start;
                h.size = hunk_len;
                h.differing_bytes = diff_cnt;
                h.classification = cls;
                h.lhs_sample.assign(ps.expected.begin() + static_cast<std::ptrdiff_t>(hunk_start),
                                    ps.expected.begin() + static_cast<std::ptrdiff_t>(hunk_start + samp_len));
                h.rhs_sample.assign(live.bytes.begin() + static_cast<std::ptrdiff_t>(hunk_start),
                                    live.bytes.begin() + static_cast<std::ptrdiff_t>(hunk_start + samp_len));
                h.symbol_context = resolve_rva_symbol(hunk_rva);
                if (is_exec) {
                    const std::size_t ctx_len = std::min<std::size_t>(16u, live.bytes.size() - hunk_start);
                    const auto live_insn_ctx =
                        std::span<const std::uint8_t>(live.bytes).subspan(hunk_start, ctx_len);
                    const std::string detour = describe_code_detour_hint(live_insn_ctx, arch);
                    h.detail = std::format("Executable code modified in {} at VA 0x{:X}{}",
                                           ps.sec->name,
                                           *h.rhs_va,
                                           detour);
                } else if (is_writable_data) {
                    h.detail = std::format("Writable runtime data modified in {}", ps.sec->name);
                } else {
                    h.detail = std::format("Read-only section {} modified at VA 0x{:X}",
                                           ps.sec->name,
                                           *h.rhs_va);
                }
                report.findings.push_back(std::move(h));
            }
        }
    }

    if (options.stop_token.stop_requested()) {
        return make_error("Live integrity diff cancelled");
    }
    report_progress(3u, 3u, "Live integrity comparison complete");

    if (!any_readable) {
        report.live_capture_stamp.availability = CaptureAvailability::Unavailable;
        report.status = SubsystemStatus::unavailable(
            "live_module_diff", "Unable to read mapped sections from live process memory");
    } else if (report.backing_identity.has_mismatch()) {
        report.live_capture_stamp.availability = CaptureAvailability::Partial;
        report.status = SubsystemStatus::partial(
            "live_module_diff",
            std::format("Backing image identity mismatch ({}); diffs may reflect a different build rather than runtime hooks",
                        report.backing_identity.summary));
    } else if (report.unreadable_live_bytes > 0u) {
        report.live_capture_stamp.availability = CaptureAvailability::Partial;
        report.status = SubsystemStatus::partial(
            "live_module_diff",
            std::format("Compared live module with {} unreadable byte(s) skipped",
                        report.unreadable_live_bytes));
    } else {
        report.status = SubsystemStatus::available(
            "live_module_diff",
            std::format("Compared '{}' against disk (ASLR bias {:+#x}): {} inline code hook(s), {} IAT/GOT hook(s)",
                        report.module_name,
                        report.aslr_load_bias,
                        report.inline_code_hook_count,
                        report.iat_got_hook_count));
    }

    return report;
}

Result<LiveModuleIntegrityReport> compare_module_disk_to_live(
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    const LiveIntegrityDiffOptions& options) {
    auto disk_img = parse_image(disk_file_bytes);
    if (!disk_img.has_value()) {
        return std::unexpected(disk_img.error());
    }
    return compare_module_disk_to_live(**disk_img, disk_file_bytes, session, live_module, options);
}

} // namespace peelf
