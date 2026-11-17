#include "image_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {
namespace {

using detail::align4;
using detail::checked_add_u64;
using detail::checked_mul_u64;
using detail::fits_range;
using detail::rd16;
using detail::rd32;
using detail::rd64;
using detail::read_c_string;
using detail::wr16_endian;
using detail::wr32_endian;
using detail::wr64_endian;

struct ElfParseBudget {
    static constexpr std::size_t kMaxTotalSymbols = 262144u;
    static constexpr std::size_t kMaxTotalRelocations = 262144u;
    static constexpr std::size_t kMaxTotalNotes = 16384u;
    static constexpr std::size_t kMaxTotalNoteBytes = 16u * 1024u * 1024u;
    static constexpr std::size_t kMaxTotalDynamicEntries = 65536u;

    std::size_t remaining_symbols = kMaxTotalSymbols;
    std::size_t remaining_relocations = kMaxTotalRelocations;
    std::size_t remaining_notes = kMaxTotalNotes;
    std::size_t remaining_note_bytes = kMaxTotalNoteBytes;
    std::size_t remaining_dynamic_entries = kMaxTotalDynamicEntries;
    bool warned_symbols = false;
    bool warned_relocations = false;
    bool warned_notes = false;
    bool warned_dynamic = false;
};

class ElfImage final : public detail::ImageBase {
public:
    [[nodiscard]] const ElfHeader* elf_header() const noexcept override { return &elf_header_; }
    [[nodiscard]] const std::vector<ElfProgramHeader>& elf_program_headers() const noexcept override {
        return program_headers_;
    }
    [[nodiscard]] const std::vector<ElfSectionHeader>& elf_section_headers() const noexcept override {
        return section_headers_;
    }
    [[nodiscard]] const std::vector<ElfSymbol>& elf_symbols() const noexcept override {
        return elf_symbols_;
    }
    [[nodiscard]] const std::vector<ElfDynamicEntry>& elf_dynamic_entries() const noexcept override {
        return dynamic_entries_;
    }
    [[nodiscard]] const std::vector<ElfRelocation>& elf_relocations() const noexcept override {
        return relocations_;
    }
    [[nodiscard]] const std::vector<ElfNote>& elf_notes() const noexcept override {
        return notes_;
    }
    [[nodiscard]] const std::vector<ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept override {
        return sysv_hash_tables_;
    }
    [[nodiscard]] const std::vector<ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept override {
        return gnu_hash_tables_;
    }
    [[nodiscard]] std::string_view elf_interpreter() const noexcept override {
        return interpreter_;
    }
    [[nodiscard]] static Result<std::unique_ptr<ElfImage>> parse(std::span<const std::uint8_t> b);
    [[nodiscard]] static Result<std::unique_ptr<IBinaryImage>> parse_mapped(
        std::span<const std::uint8_t> mapped_bytes,
        std::uint64_t live_base);
    void rebase_to_live_base(std::uint64_t live_base) override;

private:
    void append_symbol_imports_and_exports();
    void recover_dynamic_from_program_headers(std::span<const std::uint8_t> b,
                                              bool is64,
                                              bool big,
                                              std::uint64_t live_base,
                                              std::uint64_t static_base,
                                              ElfParseBudget& budget,
                                              bool is_mapped);

    ElfHeader elf_header_;
    std::vector<ElfProgramHeader> program_headers_;
    std::vector<ElfSectionHeader> section_headers_;
    std::vector<ElfSymbol> elf_symbols_;
    std::vector<ElfDynamicEntry> dynamic_entries_;
    std::vector<ElfRelocation> relocations_;
    std::vector<ElfNote> notes_;
    std::vector<ElfSysvHashTable> sysv_hash_tables_;
    std::vector<ElfGnuHashTable> gnu_hash_tables_;
    std::string interpreter_;
};

Architecture elf_arch(std::uint16_t machine, bool is64) noexcept {
    switch (machine) {
        case 3:   return Architecture::X86;        // EM_386
        case 62:  return Architecture::X86_64;     // EM_X86_64
        case 40:  return Architecture::ARM;        // EM_ARM
        case 183: return Architecture::ARM64;      // EM_AARCH64
        case 243: return is64 ? Architecture::RISCV64 : Architecture::RISCV32;  // EM_RISCV
        case 20:  return Architecture::PowerPC;    // EM_PPC
        case 21:  return Architecture::PowerPC64;  // EM_PPC64
        case 8:   return is64 ? Architecture::MIPS64 : Architecture::MIPS32;    // EM_MIPS
        default:  return Architecture::Unknown;
    }
}

ImageKind elf_kind(std::uint16_t e_type) noexcept {
    switch (e_type) {
        case 1:  return ImageKind::Object;        // ET_REL
        case 2:  return ImageKind::Executable;    // ET_EXEC
        case 3:  return ImageKind::SharedLibrary; // ET_DYN (also PIE executables)
        case 4:  return ImageKind::Core;          // ET_CORE
        default: return ImageKind::Unknown;
    }
}

void parse_elf_notes(std::span<const std::uint8_t> b, bool big, std::uint64_t offset,
                     std::uint64_t size, bool from_program_header,
                     std::vector<ElfNote>& notes_out,
                     std::vector<std::string>& warnings_out,
                     ElfParseBudget& budget) {
    if (size == 0) {
        return;
    }
    if (!fits_range(offset, size, static_cast<std::uint64_t>(b.size()))) {
        warnings_out.push_back(std::format(
            "ELF {} note payload truncated: offset 0x{:X} + {} bytes exceeds file size ({} bytes)",
            from_program_header ? "PT_NOTE" : "SHT_NOTE", offset, size, b.size()));
        if (offset >= b.size()) {
            return;
        }
        size = static_cast<std::uint64_t>(b.size()) - offset;
    }

    const std::uint64_t end = offset + size;
    std::uint64_t cursor = offset;
    while (cursor <= end && (end - cursor) >= 12u) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t name_size = rd32(b, off + 0x00, big);
        const std::uint32_t descriptor_size = rd32(b, off + 0x04, big);
        const std::uint32_t type = rd32(b, off + 0x08, big);
        cursor += 12u;

        const std::uint64_t aligned_name_size = align4(name_size);
        const std::uint64_t aligned_descriptor_size = align4(descriptor_size);
        if (cursor > end || aligned_name_size > end - cursor) {
            warnings_out.push_back(std::format(
                "ELF {} note entry has truncated name field at offset 0x{:X}",
                from_program_header ? "PT_NOTE" : "SHT_NOTE", off));
            break;
        }
        const std::uint64_t name_offset = cursor;
        cursor += aligned_name_size;
        if (cursor > end || aligned_descriptor_size > end - cursor) {
            warnings_out.push_back(std::format(
                "ELF {} note entry has truncated descriptor field at offset 0x{:X}",
                from_program_header ? "PT_NOTE" : "SHT_NOTE", off));
            break;
        }
        const std::uint64_t descriptor_offset = cursor;
        cursor += aligned_descriptor_size;

        constexpr std::uint32_t kMaxNoteNameBytes = 4096u;
        const std::uint32_t bounded_name_len = std::min(name_size, kMaxNoteNameBytes);
        const std::uint64_t note_cost =
            static_cast<std::uint64_t>(bounded_name_len) + static_cast<std::uint64_t>(descriptor_size);
        if (budget.remaining_notes == 0u || note_cost > budget.remaining_note_bytes) {
            if (!budget.warned_notes) {
                warnings_out.push_back("ELF note parsing capped at aggregate budget");
                budget.warned_notes = true;
            }
            return;
        }
        --budget.remaining_notes;
        budget.remaining_note_bytes -= static_cast<std::size_t>(note_cost);

        ElfNote note;
        note.type = type;
        note.from_program_header = from_program_header;
        for (std::uint32_t i = 0; i < bounded_name_len && name_offset + i < end; ++i) {
            const std::uint8_t ch = b[static_cast<std::size_t>(name_offset + i)];
            if (ch == 0) {
                break;
            }
            note.name.push_back(static_cast<char>(ch));
        }
        if (descriptor_size != 0 && descriptor_offset + descriptor_size <= end) {
            note.descriptor.reserve(descriptor_size);
            for (std::uint32_t i = 0; i < descriptor_size; ++i) {
                note.descriptor.push_back(b[static_cast<std::size_t>(descriptor_offset + i)]);
            }
        }
        notes_out.push_back(std::move(note));
    }
}

void parse_elf_sysv_hash(std::span<const std::uint8_t> b, bool big,
                         const ElfSectionHeader& sh,
                         std::vector<ElfSysvHashTable>& hash_tables_out,
                         std::vector<std::string>* warnings_out = nullptr) {
    if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size())) || sh.size < 8) {
        if (warnings_out != nullptr) {
            warnings_out->push_back(std::format(
                "ELF SHT_HASH section '{}' is truncated or out of file bounds",
                sh.name.empty() ? ".hash" : sh.name));
        }
        return;
    }

    const std::size_t off = static_cast<std::size_t>(sh.offset);
    const std::uint32_t bucket_count = rd32(b, off + 0x00, big);
    const std::uint32_t chain_count = rd32(b, off + 0x04, big);
    const std::uint64_t bucket_bytes = static_cast<std::uint64_t>(bucket_count) * 4u;
    const std::uint64_t chain_bytes = static_cast<std::uint64_t>(chain_count) * 4u;
    if (bucket_bytes > std::numeric_limits<std::uint64_t>::max() - 8u ||
        chain_bytes > std::numeric_limits<std::uint64_t>::max() - 8u - bucket_bytes ||
        8u + bucket_bytes + chain_bytes > sh.size) {
        if (warnings_out != nullptr) {
            warnings_out->push_back(std::format(
                "ELF SHT_HASH section '{}' header counts ({} buckets, {} chains) exceed section size ({} bytes)",
                sh.name.empty() ? ".hash" : sh.name, bucket_count, chain_count, sh.size));
        }
        return;
    }

    ElfSysvHashTable table;
    table.section_name = sh.name;
    table.bucket_count = bucket_count;
    table.chain_count = chain_count;
    table.buckets.reserve(bucket_count);
    table.chains.reserve(chain_count);
    std::uint64_t cursor = sh.offset + 8u;
    for (std::uint32_t i = 0; i < bucket_count; ++i, cursor += 4u) {
        table.buckets.push_back(rd32(b, static_cast<std::size_t>(cursor), big));
    }
    for (std::uint32_t i = 0; i < chain_count; ++i, cursor += 4u) {
        table.chains.push_back(rd32(b, static_cast<std::size_t>(cursor), big));
    }
    hash_tables_out.push_back(std::move(table));
}

void parse_elf_gnu_hash(std::span<const std::uint8_t> b, bool is64, bool big,
                        const ElfSectionHeader& sh,
                        std::vector<ElfGnuHashTable>& hash_tables_out,
                        std::vector<std::string>* warnings_out = nullptr) {
    if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size())) || sh.size < 16) {
        if (warnings_out != nullptr) {
            warnings_out->push_back(std::format(
                "ELF SHT_GNU_HASH section '{}' is truncated or out of file bounds",
                sh.name.empty() ? ".gnu.hash" : sh.name));
        }
        return;
    }

    const std::size_t off = static_cast<std::size_t>(sh.offset);
    const std::uint32_t bucket_count = rd32(b, off + 0x00, big);
    const std::uint32_t symbol_offset = rd32(b, off + 0x04, big);
    const std::uint32_t bloom_word_count = rd32(b, off + 0x08, big);
    const std::uint32_t bloom_shift = rd32(b, off + 0x0C, big);
    const std::uint64_t bloom_word_size = is64 ? 8u : 4u;
    const std::uint64_t bloom_bytes = static_cast<std::uint64_t>(bloom_word_count) * bloom_word_size;
    const std::uint64_t bucket_bytes = static_cast<std::uint64_t>(bucket_count) * 4u;
    if (bloom_bytes > std::numeric_limits<std::uint64_t>::max() - 16u ||
        bucket_bytes > std::numeric_limits<std::uint64_t>::max() - 16u - bloom_bytes ||
        16u + bloom_bytes + bucket_bytes > sh.size) {
        if (warnings_out != nullptr) {
            warnings_out->push_back(std::format(
                "ELF SHT_GNU_HASH section '{}' header counts exceed section size ({} bytes)",
                sh.name.empty() ? ".gnu.hash" : sh.name, sh.size));
        }
        return;
    }

    ElfGnuHashTable table;
    table.section_name = sh.name;
    table.bucket_count = bucket_count;
    table.symbol_offset = symbol_offset;
    table.bloom_word_count = bloom_word_count;
    table.bloom_shift = bloom_shift;
    table.bloom.reserve(bloom_word_count);
    table.buckets.reserve(bucket_count);

    std::uint64_t cursor = sh.offset + 16u;
    for (std::uint32_t i = 0; i < bloom_word_count; ++i, cursor += bloom_word_size) {
        table.bloom.push_back(is64 ? rd64(b, static_cast<std::size_t>(cursor), big)
                                   : rd32(b, static_cast<std::size_t>(cursor), big));
    }
    for (std::uint32_t i = 0; i < bucket_count; ++i, cursor += 4u) {
        table.buckets.push_back(rd32(b, static_cast<std::size_t>(cursor), big));
    }

    const std::uint64_t chain_bytes = sh.size - (cursor - sh.offset);
    if (warnings_out != nullptr && (chain_bytes % 4u) != 0u) {
        warnings_out->push_back(std::format(
            "ELF SHT_GNU_HASH section '{}' has trailing unaligned chain bytes",
            sh.name.empty() ? ".gnu.hash" : sh.name));
    }
    const std::uint64_t chain_count = chain_bytes / 4u;
    table.chains.reserve(static_cast<std::size_t>(chain_count));
    for (std::uint64_t i = 0; i < chain_count; ++i, cursor += 4u) {
        table.chains.push_back(rd32(b, static_cast<std::size_t>(cursor), big));
    }
    hash_tables_out.push_back(std::move(table));
}

void parse_elf_segments(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t phoff, std::uint16_t phentsize,
                        std::uint32_t phnum, std::vector<ElfProgramHeader>& headers_out,
                        std::vector<Segment>& segments_out, std::string& interpreter_out,
                        std::vector<ElfNote>& notes_out,
                        std::vector<std::string>& warnings_out,
                        ElfParseBudget& budget) {
    if (phoff == 0 && phnum == 0) {
        return;
    }
    if (phoff == 0 || phnum == 0) {
        if (phnum != 0) {
            warnings_out.push_back("ELF header declares non-zero e_phnum with e_phoff == 0");
        }
        return;
    }
    const std::uint16_t min_ph = is64 ? 0x38 : 0x20;
    if (phentsize < min_ph) {
        warnings_out.push_back(std::format(
            "ELF program header entry size ({}) is smaller than minimum ({})", phentsize, min_ph));
        return;
    }
    if (phnum > 65536u) {
        warnings_out.push_back(std::format(
            "ELF program header count ({}) exceeds maximum supported limit", phnum));
        return;
    }
    const std::uint64_t table_size = static_cast<std::uint64_t>(phnum) * phentsize;
    std::uint32_t avail_phnum = phnum;
    if (!fits_range(phoff, table_size, static_cast<std::uint64_t>(b.size()))) {
        warnings_out.push_back(std::format(
            "ELF program header table truncated: offset 0x{:X} + {} entries ({} bytes) exceeds file size ({} bytes)",
            phoff, phnum, table_size, b.size()));
        if (phoff >= b.size()) {
            return;
        }
        avail_phnum = static_cast<std::uint32_t>((static_cast<std::uint64_t>(b.size()) - phoff) / phentsize);
        if (avail_phnum == 0) {
            return;
        }
    }

    headers_out.reserve(avail_phnum);
    segments_out.reserve(avail_phnum);
    for (std::uint32_t i = 0; i < avail_phnum; ++i) {
        const std::uint64_t hdr64 = phoff + static_cast<std::uint64_t>(i) * phentsize;
        const std::size_t hdr = static_cast<std::size_t>(hdr64);

        ElfProgramHeader phdr;
        if (is64) {
            phdr.type             = rd32(b, hdr + 0x00, big);
            phdr.flags            = rd32(b, hdr + 0x04, big);
            phdr.offset           = rd64(b, hdr + 0x08, big);
            phdr.virtual_address  = rd64(b, hdr + 0x10, big);
            phdr.physical_address = rd64(b, hdr + 0x18, big);
            phdr.file_size        = rd64(b, hdr + 0x20, big);
            phdr.memory_size      = rd64(b, hdr + 0x28, big);
            phdr.alignment        = rd64(b, hdr + 0x30, big);
        } else {
            phdr.type             = rd32(b, hdr + 0x00, big);
            phdr.offset           = rd32(b, hdr + 0x04, big);
            phdr.virtual_address  = rd32(b, hdr + 0x08, big);
            phdr.physical_address = rd32(b, hdr + 0x0C, big);
            phdr.file_size        = rd32(b, hdr + 0x10, big);
            phdr.memory_size      = rd32(b, hdr + 0x14, big);
            phdr.flags            = rd32(b, hdr + 0x18, big);
            phdr.alignment        = rd32(b, hdr + 0x1C, big);
        }

        Segment seg;
        seg.type            = phdr.type;
        seg.file_offset     = phdr.offset;
        seg.virtual_address = phdr.virtual_address;
        seg.file_size       = phdr.file_size;
        seg.virtual_size    = phdr.memory_size;
        seg.executable = (phdr.flags & 0x1u) != 0;  // PF_X
        seg.writable   = (phdr.flags & 0x2u) != 0;  // PF_W
        seg.readable   = (phdr.flags & 0x4u) != 0;  // PF_R

        headers_out.push_back(phdr);
        segments_out.push_back(seg);
        if (phdr.type == 3) {
            if (fits_range(phdr.offset, phdr.file_size, static_cast<std::uint64_t>(b.size()))) {
                interpreter_out = read_c_string(b, phdr.offset, phdr.file_size);
            } else {
                warnings_out.push_back("ELF PT_INTERP segment payload is truncated or out of file bounds");
            }
        }
        if (phdr.type == 4) {
            parse_elf_notes(b, big, phdr.offset, phdr.file_size, true, notes_out, warnings_out, budget);
        }
    }
}

// Parse the ELF section header table into `out`. Best-effort and fully bounds-
// checked: on any inconsistency it records explicit diagnostics in `warnings_out`
// and recovers complete prefix entries where safe.
void parse_elf_sections(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t shoff, std::uint16_t shentsize,
                        std::uint32_t shnum, std::uint32_t shstrndx,
                        std::vector<ElfSectionHeader>& headers, std::vector<Section>& out,
                        std::vector<ElfSymbol>& elf_symbols_out, std::vector<Symbol>& symbols_out,
                        std::vector<ElfDynamicEntry>& dynamic_entries_out,
                        std::vector<ElfRelocation>& relocations_out,
                        std::vector<ElfNote>& notes_out,
                        std::vector<ElfSysvHashTable>& sysv_hash_tables_out,
                        std::vector<ElfGnuHashTable>& gnu_hash_tables_out,
                        std::vector<ImportEntry>& imports_out,
                        std::vector<std::string>& warnings_out,
                        ElfParseBudget& budget) {
    if (shoff == 0 && shnum == 0) {
        return;
    }
    if (shoff == 0 || shnum == 0) {
        if (shnum != 0) {
            warnings_out.push_back("ELF header declares non-zero e_shnum with e_shoff == 0");
        }
        return;
    }
    const std::uint16_t min_sh = is64 ? 0x40 : 0x28;
    if (shentsize < min_sh) {
        warnings_out.push_back(std::format(
            "ELF section header entry size ({}) is smaller than minimum ({})", shentsize, min_sh));
        return;
    }
    if (shnum > 262144u) {
        warnings_out.push_back(std::format(
            "ELF section header count ({}) exceeds maximum supported limit", shnum));
        return;
    }
    const std::uint64_t table_size = static_cast<std::uint64_t>(shnum) * shentsize;
    std::uint32_t avail_shnum = shnum;
    if (!fits_range(shoff, table_size, static_cast<std::uint64_t>(b.size()))) {
        warnings_out.push_back(std::format(
            "ELF section header table truncated: offset 0x{:X} + {} entries ({} bytes) exceeds file size ({} bytes)",
            shoff, shnum, table_size, b.size()));
        if (shoff >= b.size()) {
            return;
        }
        avail_shnum = static_cast<std::uint32_t>((static_cast<std::uint64_t>(b.size()) - shoff) / shentsize);
        if (avail_shnum == 0) {
            return;
        }
    }

    const auto read_sh = [&](std::size_t hdr) {
        ElfSectionHeader s{};
        s.name_offset = rd32(b, hdr + 0, big);
        s.type = rd32(b, hdr + 4, big);
        if (is64) {
            s.flags  = rd64(b, hdr + 0x08, big);
            s.address = rd64(b, hdr + 0x10, big);
            s.offset = rd64(b, hdr + 0x18, big);
            s.size   = rd64(b, hdr + 0x20, big);
            s.link   = rd32(b, hdr + 0x28, big);
            s.info = rd32(b, hdr + 0x2C, big);
            s.address_alignment = rd64(b, hdr + 0x30, big);
            s.entry_size = rd64(b, hdr + 0x38, big);
        } else {
            s.flags  = rd32(b, hdr + 0x08, big);
            s.address = rd32(b, hdr + 0x0C, big);
            s.offset = rd32(b, hdr + 0x10, big);
            s.size   = rd32(b, hdr + 0x14, big);
            s.link   = rd32(b, hdr + 0x18, big);
            s.info = rd32(b, hdr + 0x1C, big);
            s.address_alignment = rd32(b, hdr + 0x20, big);
            s.entry_size = rd32(b, hdr + 0x24, big);
        }
        return s;
    };

    headers.reserve(avail_shnum);
    for (std::uint32_t i = 0; i < avail_shnum; ++i) {
        const std::uint64_t hdr = shoff + static_cast<std::uint64_t>(i) * shentsize;
        headers.push_back(read_sh(static_cast<std::size_t>(hdr)));
    }

    // Section-name string table = section[eff_shstrndx].
    std::uint64_t strtab_off = 0;
    std::uint64_t strtab_size = 0;
    if (shstrndx != 0) {
        if (shstrndx < avail_shnum) {
            const auto& sh = headers[shstrndx];
            strtab_off = sh.offset;
            strtab_size = sh.size;
            if (!fits_range(strtab_off, strtab_size, static_cast<std::uint64_t>(b.size()))) {
                warnings_out.push_back(
                    "ELF section-name string table (.shstrtab) is truncated or out of file bounds");
                strtab_size = strtab_off < b.size() ? (static_cast<std::uint64_t>(b.size()) - strtab_off) : 0u;
            }
        } else {
            warnings_out.push_back(std::format(
                "ELF shstrndx ({}) is out of range for {} available section headers",
                shstrndx, avail_shnum));
        }
    }
    const auto read_string = [&](std::uint64_t base, std::uint64_t size,
                                 std::uint32_t name_off) -> std::string {
        if (base == 0) {
            return {};
        }
        if (name_off >= size || !fits_range(base, size, static_cast<std::uint64_t>(b.size()))) {
            return {};
        }
        std::string s;
        const std::uint64_t end = base + size;
        for (std::uint64_t i = base + name_off; i < end && b[static_cast<std::size_t>(i)] != 0;
             ++i) {
            s.push_back(static_cast<char>(b[static_cast<std::size_t>(i)]));
            if (s.size() >= 256) {
                break;
            }
        }
        return s;
    };
    const auto read_section_name = [&](std::uint32_t name_off) -> std::string {
        return read_string(strtab_off, strtab_size, name_off);
    };

    out.reserve(avail_shnum);
    for (std::uint32_t i = 0; i < avail_shnum; ++i) {
        const auto& sh = headers[i];
        Section sec;
        headers[i].name = read_section_name(sh.name_offset);
        sec.name            = headers[i].name;
        sec.virtual_address = sh.address;
        sec.virtual_size    = (sh.type == 0u) ? 0u : sh.size; // SHT_NULL sh_size stores extended e_shnum
        sec.file_offset     = sh.offset;
        sec.file_size       = (sh.type == 0u || sh.type == 8u) ? 0u : sh.size; // SHT_NULL / SHT_NOBITS have no file data
        sec.raw_flags       = sh.flags;
        sec.readable   = (sh.flags & 0x2) != 0;  // SHF_ALLOC
        sec.writable   = (sh.flags & 0x1) != 0;  // SHF_WRITE
        sec.executable = (sh.flags & 0x4) != 0;  // SHF_EXECINSTR
        out.push_back(std::move(sec));
    }

    for (std::uint32_t section_index = 0; section_index < avail_shnum; ++section_index) {
        const auto& sh = headers[section_index];
        const bool is_symtab = sh.type == 2;   // SHT_SYMTAB
        const bool is_dynsym = sh.type == 11;  // SHT_DYNSYM
        if (!is_symtab && !is_dynsym) {
            continue;
        }
        const std::string_view sec_label =
            !sh.name.empty() ? std::string_view{sh.name} : (is_dynsym ? ".dynsym" : ".symtab");

        const std::uint64_t min_sym = is64 ? 0x18 : 0x10;
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_sym;
        if (entry_size < min_sym) {
            warnings_out.push_back(std::format(
                "ELF symbol table '{}' has undersized sh_entsize ({} < {})",
                sec_label, entry_size, min_sym));
            continue;
        }
        if (sh.link >= headers.size()) {
            warnings_out.push_back(std::format(
                "ELF symbol table '{}' has out-of-range string-table sh_link ({})",
                sec_label, sh.link));
            continue;
        }

        const auto& strings = headers[sh.link];
        std::uint64_t eff_str_size = strings.size;
        if (!fits_range(strings.offset, strings.size, static_cast<std::uint64_t>(b.size()))) {
            warnings_out.push_back(std::format(
                "ELF string table linked by '{}' is truncated or out of file bounds", sec_label));
            eff_str_size = strings.offset < b.size()
                               ? (static_cast<std::uint64_t>(b.size()) - strings.offset)
                               : 0u;
        }

        std::uint64_t eff_sym_bytes = sh.size;
        if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            warnings_out.push_back(std::format(
                "ELF symbol table '{}' truncated: offset 0x{:X} + {} bytes exceeds file size ({} bytes)",
                sec_label, sh.offset, sh.size, b.size()));
            if (sh.offset >= b.size()) {
                continue;
            }
            eff_sym_bytes = static_cast<std::uint64_t>(b.size()) - sh.offset;
        } else if ((sh.size % entry_size) != 0u) {
            warnings_out.push_back(std::format(
                "ELF symbol table '{}' size ({}) is not a multiple of entry size ({}); trailing partial entry ignored",
                sec_label, sh.size, entry_size));
        }

        const std::uint64_t count = eff_sym_bytes / entry_size;
        for (std::uint64_t i = 0; i < count; ++i) {
            if (budget.remaining_symbols == 0u) {
                if (!budget.warned_symbols) {
                    warnings_out.push_back(std::format(
                        "ELF symbol parsing capped at {} aggregate entries",
                        ElfParseBudget::kMaxTotalSymbols));
                    budget.warned_symbols = true;
                }
                break;
            }
            const auto rel_off = checked_mul_u64(i, entry_size);
            const auto sym_off = rel_off.has_value()
                ? checked_add_u64(sh.offset, *rel_off)
                : std::nullopt;
            if (!sym_off.has_value() ||
                !fits_range(*sym_off, min_sym, static_cast<std::uint64_t>(b.size()))) {
                break;
            }
            --budget.remaining_symbols;

            const std::size_t off = static_cast<std::size_t>(*sym_off);
            ElfSymbol elf_symbol;
            std::uint8_t info = 0;
            std::uint8_t other = 0;
            if (is64) {
                elf_symbol.name_offset = rd32(b, off + 0x00, big);
                info = b[off + 0x04];
                other = b[off + 0x05];
                elf_symbol.section_index = rd16(b, off + 0x06, big);
                elf_symbol.value = rd64(b, off + 0x08, big);
                elf_symbol.size = rd64(b, off + 0x10, big);
            } else {
                elf_symbol.name_offset = rd32(b, off + 0x00, big);
                elf_symbol.value = rd32(b, off + 0x04, big);
                elf_symbol.size = rd32(b, off + 0x08, big);
                info = b[off + 0x0C];
                other = b[off + 0x0D];
                elf_symbol.section_index = rd16(b, off + 0x0E, big);
            }
            elf_symbol.info = info;
            elf_symbol.other = other;
            elf_symbol.binding = static_cast<std::uint8_t>(info >> 4);
            elf_symbol.type = static_cast<std::uint8_t>(info & 0x0F);
            elf_symbol.visibility = static_cast<std::uint8_t>(other & 0x03);
            elf_symbol.dynamic = is_dynsym;
            elf_symbol.name = read_string(strings.offset, eff_str_size, elf_symbol.name_offset);

            if (!elf_symbol.name.empty()) {
                Symbol symbol;
                symbol.name = elf_symbol.name;
                symbol.virtual_address = elf_symbol.value;
                symbol.size = elf_symbol.size;
                symbol.binding = elf_symbol.binding;
                symbol.type = elf_symbol.type;
                symbol.section_index = elf_symbol.section_index;
                symbol.dynamic = elf_symbol.dynamic;
                symbols_out.push_back(std::move(symbol));
            }
            elf_symbols_out.push_back(std::move(elf_symbol));
        }
    }

    for (const auto& sh : headers) {
        if (sh.type != 6) {  // SHT_DYNAMIC
            continue;
        }
        const std::string_view sec_label = !sh.name.empty() ? std::string_view{sh.name} : ".dynamic";
        const std::uint64_t min_dyn = is64 ? 0x10 : 0x08;
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_dyn;
        if (entry_size < min_dyn) {
            warnings_out.push_back(std::format(
                "ELF dynamic section '{}' has undersized sh_entsize ({} < {})",
                sec_label, entry_size, min_dyn));
            continue;
        }
        if (sh.link >= headers.size()) {
            warnings_out.push_back(std::format(
                "ELF dynamic section '{}' has out-of-range string-table sh_link ({})",
                sec_label, sh.link));
            continue;
        }

        const auto& strings = headers[sh.link];
        std::uint64_t eff_str_size = strings.size;
        if (!fits_range(strings.offset, strings.size, static_cast<std::uint64_t>(b.size()))) {
            warnings_out.push_back(std::format(
                "ELF dynamic string table linked by '{}' is truncated or out of file bounds", sec_label));
            eff_str_size = strings.offset < b.size()
                               ? (static_cast<std::uint64_t>(b.size()) - strings.offset)
                               : 0u;
        }

        std::uint64_t eff_dyn_bytes = sh.size;
        if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            warnings_out.push_back(std::format(
                "ELF dynamic section '{}' truncated: offset 0x{:X} + {} bytes exceeds file size ({} bytes)",
                sec_label, sh.offset, sh.size, b.size()));
            if (sh.offset >= b.size()) {
                continue;
            }
            eff_dyn_bytes = static_cast<std::uint64_t>(b.size()) - sh.offset;
        } else if ((sh.size % entry_size) != 0u) {
            warnings_out.push_back(std::format(
                "ELF dynamic section '{}' size ({}) is not a multiple of entry size ({}); trailing partial entry ignored",
                sec_label, sh.size, entry_size));
        }

        const std::uint64_t count = eff_dyn_bytes / entry_size;
        bool saw_dt_null = false;
        bool capped_dynamic = false;
        for (std::uint64_t i = 0; i < count; ++i) {
            if (budget.remaining_dynamic_entries == 0u) {
                if (!budget.warned_dynamic) {
                    warnings_out.push_back(std::format(
                        "ELF dynamic table parsing capped at {} aggregate entries",
                        ElfParseBudget::kMaxTotalDynamicEntries));
                    budget.warned_dynamic = true;
                }
                capped_dynamic = true;
                break;
            }
            const auto rel_off = checked_mul_u64(i, entry_size);
            const auto dyn_off = rel_off.has_value()
                ? checked_add_u64(sh.offset, *rel_off)
                : std::nullopt;
            if (!dyn_off.has_value() ||
                !fits_range(*dyn_off, min_dyn, static_cast<std::uint64_t>(b.size()))) {
                break;
            }
            --budget.remaining_dynamic_entries;

            const std::size_t off = static_cast<std::size_t>(*dyn_off);
            const std::uint64_t tag = is64 ? rd64(b, off + 0x00, big)
                                           : static_cast<std::uint64_t>(rd32(b, off + 0x00, big));
            const std::uint64_t value = is64 ? rd64(b, off + 0x08, big)
                                             : static_cast<std::uint64_t>(rd32(b, off + 0x04, big));
            ElfDynamicEntry raw_entry;
            raw_entry.tag = tag;
            raw_entry.value = value;
            if ((tag == 1 || tag == 14 || tag == 15 || tag == 29) &&
                value <= std::numeric_limits<std::uint32_t>::max()) {
                raw_entry.string_value = read_string(strings.offset, eff_str_size,
                                                     static_cast<std::uint32_t>(value));
                if (tag == 1) {  // DT_NEEDED
                    raw_entry.needed_library = raw_entry.string_value;
                }
            }
            dynamic_entries_out.push_back(raw_entry);
            if (tag == 0) {  // DT_NULL
                saw_dt_null = true;
                break;
            }
            if (!raw_entry.needed_library.empty()) {
                ImportEntry entry;
                entry.library = raw_entry.needed_library;
                imports_out.push_back(std::move(entry));
            }
        }
        if (count > 0 && !saw_dt_null && !capped_dynamic) {
            warnings_out.push_back(std::format(
                "ELF dynamic section '{}' is missing DT_NULL terminator", sec_label));
        }
    }

    for (const auto& sh : headers) {
        if (sh.type == 7) {  // SHT_NOTE
            parse_elf_notes(b, big, sh.offset, sh.size, false, notes_out, warnings_out, budget);
        }
    }

    for (const auto& sh : headers) {
        if (sh.type == 5) {  // SHT_HASH
            parse_elf_sysv_hash(b, big, sh, sysv_hash_tables_out, &warnings_out);
        } else if (sh.type == 0x6FFF'FFF6u) {  // SHT_GNU_HASH
            parse_elf_gnu_hash(b, is64, big, sh, gnu_hash_tables_out, &warnings_out);
        }
    }

    for (const auto& sh : headers) {
        const bool has_addend = sh.type == 4;     // SHT_RELA
        const bool no_addend = sh.type == 9;      // SHT_REL
        if (!has_addend && !no_addend) {
            continue;
        }
        const std::string_view sec_label =
            !sh.name.empty() ? std::string_view{sh.name} : (has_addend ? ".rela" : ".rel");

        const std::uint64_t min_reloc = has_addend
            ? (is64 ? 0x18 : 0x0C)
            : (is64 ? 0x10 : 0x08);
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_reloc;
        if (entry_size < min_reloc) {
            warnings_out.push_back(std::format(
                "ELF relocation section '{}' has undersized sh_entsize ({} < {})",
                sec_label, entry_size, min_reloc));
            continue;
        }
        std::uint64_t eff_rel_bytes = sh.size;
        if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            warnings_out.push_back(std::format(
                "ELF relocation section '{}' truncated: offset 0x{:X} + {} bytes exceeds file size ({} bytes)",
                sec_label, sh.offset, sh.size, b.size()));
            if (sh.offset >= b.size()) {
                continue;
            }
            eff_rel_bytes = static_cast<std::uint64_t>(b.size()) - sh.offset;
        } else if ((sh.size % entry_size) != 0u) {
            warnings_out.push_back(std::format(
                "ELF relocation section '{}' size ({}) is not a multiple of entry size ({}); trailing partial entry ignored",
                sec_label, sh.size, entry_size));
        }

        const std::uint64_t count = eff_rel_bytes / entry_size;
        for (std::uint64_t i = 0; i < count; ++i) {
            if (budget.remaining_relocations == 0u) {
                if (!budget.warned_relocations) {
                    warnings_out.push_back(std::format(
                        "ELF relocation parsing capped at {} aggregate entries",
                        ElfParseBudget::kMaxTotalRelocations));
                    budget.warned_relocations = true;
                }
                break;
            }
            const auto rel_off = checked_mul_u64(i, entry_size);
            const auto reloc_off = rel_off.has_value()
                ? checked_add_u64(sh.offset, *rel_off)
                : std::nullopt;
            if (!reloc_off.has_value() ||
                !fits_range(*reloc_off, min_reloc, static_cast<std::uint64_t>(b.size()))) {
                break;
            }
            --budget.remaining_relocations;

            const std::size_t off = static_cast<std::size_t>(*reloc_off);
            ElfRelocation relocation;
            relocation.section_name = sh.name;
            relocation.has_addend = has_addend;
            if (is64) {
                relocation.offset = rd64(b, off + 0x00, big);
                relocation.info = rd64(b, off + 0x08, big);
                relocation.symbol_index = relocation.info >> 32;
                relocation.type = relocation.info & 0xFFFF'FFFFull;
                if (has_addend) {
                    relocation.addend = static_cast<std::int64_t>(rd64(b, off + 0x10, big));
                }
            } else {
                relocation.offset = rd32(b, off + 0x00, big);
                relocation.info = rd32(b, off + 0x04, big);
                relocation.symbol_index = relocation.info >> 8;
                relocation.type = relocation.info & 0xFFu;
                if (has_addend) {
                    relocation.addend = static_cast<std::int32_t>(rd32(b, off + 0x08, big));
                }
            }
            if (relocation.symbol_index != 0 && sh.link < headers.size()) {
                const ElfSectionHeader& sym_sh = headers[sh.link];
                const std::uint64_t min_sym = is64 ? 0x18 : 0x10;
                const std::uint64_t sym_ent_sz = sym_sh.entry_size != 0 ? sym_sh.entry_size : min_sym;
                if ((sym_sh.type == 2 || sym_sh.type == 11) && sym_ent_sz >= min_sym &&
                    sym_sh.link < headers.size() &&
                    relocation.symbol_index < (sym_sh.size / sym_ent_sz)) {
                    const auto sym_rel_off = checked_mul_u64(relocation.symbol_index, sym_ent_sz);
                    const auto sym_off = sym_rel_off.has_value()
                        ? checked_add_u64(sym_sh.offset, *sym_rel_off)
                        : std::nullopt;
                    if (sym_off.has_value() &&
                        fits_range(*sym_off, min_sym, static_cast<std::uint64_t>(b.size()))) {
                        const ElfSectionHeader& str_sh = headers[sym_sh.link];
                        std::uint64_t eff_str_sz = str_sh.size;
                        if (!fits_range(str_sh.offset, str_sh.size, static_cast<std::uint64_t>(b.size()))) {
                            eff_str_sz = str_sh.offset < b.size()
                                ? (static_cast<std::uint64_t>(b.size()) - str_sh.offset)
                                : 0u;
                        }
                        const std::uint32_t name_off = rd32(b, static_cast<std::size_t>(*sym_off), big);
                        relocation.symbol_name = read_string(str_sh.offset, eff_str_sz, name_off);
                    }
                }
            }
            relocations_out.push_back(std::move(relocation));
        }
    }
}

void resolve_powerpc64_function_descriptors(std::span<const std::uint8_t> b,
                                            bool big,
                                            const std::vector<ElfSectionHeader>& headers,
                                            std::vector<Symbol>& symbols) {
    for (Symbol& symbol : symbols) {
        constexpr std::uint8_t stt_func = 2;
        if (symbol.type != stt_func || symbol.section_index >= headers.size()) {
            continue;
        }

        const ElfSectionHeader& section = headers[symbol.section_index];
        if (section.name != ".opd" || symbol.virtual_address < section.address) {
            continue;
        }

        const std::uint64_t descriptor_delta = symbol.virtual_address - section.address;
        if (descriptor_delta > section.size ||
            descriptor_delta > std::numeric_limits<std::uint64_t>::max() - section.offset) {
            continue;
        }

        const std::uint64_t descriptor_offset = section.offset + descriptor_delta;
        if (!fits_range(descriptor_offset, 8u, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        symbol.virtual_address = rd64(b, static_cast<std::size_t>(descriptor_offset), big);
    }
}

Result<std::unique_ptr<ElfImage>> ElfImage::parse(std::span<const std::uint8_t> b) {
    if (b.size() < 0x18) {
        return make_error("ELF: too small for identification header");
    }
    const std::uint8_t ei_class = b[4]; // 1 = ELF32, 2 = ELF64
    const std::uint8_t ei_data  = b[5]; // 1 = little-endian, 2 = big-endian
    if (ei_class != 1 && ei_class != 2) {
        return make_error("ELF: invalid EI_CLASS");
    }
    if (ei_data != 1 && ei_data != 2) {
        return make_error("ELF: invalid EI_DATA");
    }

    const bool is64 = (ei_class == 2);
    const bool big  = (ei_data == 2);

    const std::size_t ehsize = is64 ? 0x40 : 0x34;
    if (b.size() < ehsize) {
        return make_error("ELF: truncated file header");
    }

    const std::uint16_t e_type    = rd16(b, 0x10, big);
    const std::uint16_t e_machine = rd16(b, 0x12, big);
    const std::uint32_t e_version = rd32(b, 0x14, big);
    const std::uint64_t e_entry   = is64 ? rd64(b, 0x18, big)
                                         : static_cast<std::uint64_t>(rd32(b, 0x18, big));
    const std::uint64_t e_phoff = is64 ? rd64(b, 0x20, big)
                                       : static_cast<std::uint64_t>(rd32(b, 0x1C, big));
    const std::uint64_t e_shoff = is64 ? rd64(b, 0x28, big)
                                       : static_cast<std::uint64_t>(rd32(b, 0x20, big));
    const std::uint32_t e_flags = rd32(b, is64 ? 0x30 : 0x24, big);
    const std::uint16_t e_ehsize = rd16(b, is64 ? 0x34 : 0x28, big);
    const std::uint16_t e_phentsize = rd16(b, is64 ? 0x36 : 0x2A, big);
    const std::uint16_t e_phnum = rd16(b, is64 ? 0x38 : 0x2C, big);
    const std::uint16_t e_shentsize = rd16(b, is64 ? 0x3A : 0x2E, big);
    const std::uint16_t e_shnum = rd16(b, is64 ? 0x3C : 0x30, big);
    const std::uint16_t e_shstrndx = rd16(b, is64 ? 0x3E : 0x32, big);

    auto img = std::make_unique<ElfImage>();
    if (e_ehsize != 0u && e_ehsize != ehsize) {
        img->add_warning(std::format(
            "ELF header declares non-standard e_ehsize {} (expected {})", e_ehsize, ehsize));
    }

    // ELF extended numbering (P1-5): shdr[0] carries overflow counts when
    // e_shnum == 0 (with e_shoff != 0), e_shstrndx == SHN_XINDEX (0xFFFF), or e_phnum == PN_XNUM (0xFFFF).
    std::uint32_t eff_phnum = e_phnum == 0xFFFFu ? 0u : static_cast<std::uint32_t>(e_phnum);
    std::uint32_t eff_shnum = static_cast<std::uint32_t>(e_shnum);
    std::uint32_t eff_shstrndx = e_shstrndx == 0xFFFFu ? 0u : static_cast<std::uint32_t>(e_shstrndx);
    const std::uint16_t min_shent = is64 ? 0x40u : 0x28u;
    const bool wants_extended =
        (e_shnum == 0u && e_shoff != 0u) || e_shstrndx == 0xFFFFu || e_phnum == 0xFFFFu;
    if (wants_extended) {
        if (e_shoff == 0u || e_shentsize < min_shent ||
            !fits_range(e_shoff, e_shentsize, static_cast<std::uint64_t>(b.size()))) {
            img->add_warning(
                "ELF extended numbering requested, but section header 0 is missing or truncated");
        } else {
            const auto sh0 = static_cast<std::size_t>(e_shoff);
            const std::uint32_t sh0_type = rd32(b, sh0 + 4u, big);
            if (sh0_type != 0u) {
                img->add_warning(
                    "ELF extended numbering requested, but section header 0 is not SHT_NULL");
            } else {
                const std::uint64_t sh0_size =
                    is64 ? rd64(b, sh0 + 0x20u, big)
                         : static_cast<std::uint64_t>(rd32(b, sh0 + 0x14u, big));
                const std::uint32_t sh0_link = rd32(b, sh0 + (is64 ? 0x28u : 0x18u), big);
                const std::uint32_t sh0_info = rd32(b, sh0 + (is64 ? 0x2Cu : 0x1Cu), big);
                if (e_shnum == 0u) {
                    if (sh0_size > 0u && sh0_size <= 262144ull) {
                        eff_shnum = static_cast<std::uint32_t>(sh0_size);
                    } else if (sh0_size > 262144ull) {
                        img->add_warning(
                            "ELF extended section count in shdr[0].sh_size exceeds maximum supported limit");
                    }
                }
                if (e_shstrndx == 0xFFFFu) {
                    eff_shstrndx = sh0_link;
                }
                if (e_phnum == 0xFFFFu) {
                    if (sh0_info <= 65536u) {
                        eff_phnum = sh0_info;
                    } else {
                        img->add_warning(
                            "ELF extended program header count in shdr[0].sh_info exceeds maximum supported limit");
                    }
                }
            }
        }
    }

    img->format_ = Format::ELF;
    img->is_64_  = is64;
    img->endian_ = big ? Endianness::Big : Endianness::Little;
    img->kind_   = elf_kind(e_type);
    img->arch_   = elf_arch(e_machine, is64);
    img->entry_  = e_entry;
    img->elf_header_ = ElfHeader{
        .elf_class = ei_class,
        .data_encoding = ei_data,
        .ident_version = b[6],
        .os_abi = b[7],
        .abi_version = b[8],
        .type = e_type,
        .machine = e_machine,
        .version = e_version,
        .entry = e_entry,
        .program_header_offset = e_phoff,
        .section_header_offset = e_shoff,
        .flags = e_flags,
        .header_size = e_ehsize,
        .program_header_entry_size = e_phentsize,
        .program_header_count = e_phnum,
        .section_header_entry_size = e_shentsize,
        .section_header_count = e_shnum,
        .section_name_string_table_index = e_shstrndx,
        .effective_program_header_count = eff_phnum,
        .effective_section_header_count = eff_shnum,
        .effective_shstrndx = eff_shstrndx,
    };

    ElfParseBudget budget{};

    // Sections (P2-1), best-effort: identity above is already valid.
    parse_elf_segments(b, is64, big, e_phoff, e_phentsize, eff_phnum,
                       img->program_headers_, img->segments_, img->interpreter_, img->notes_,
                       img->parse_warnings_, budget);

    // Determine static link-time load base from PT_LOAD segments (0 for PIE/ET_DYN, e.g. 0x400000 for ET_EXEC).
    bool found_zero_off_load = false;
    std::uint64_t min_load_base = 0;
    bool any_load = false;
    for (const ElfProgramHeader& ph : img->program_headers_) {
        if (ph.type != 1) {  // PT_LOAD
            continue;
        }
        if (ph.offset == 0) {
            img->image_base_ = ph.virtual_address;
            found_zero_off_load = true;
            break;
        }
        const std::uint64_t candidate =
            ph.virtual_address >= ph.offset ? (ph.virtual_address - ph.offset) : ph.virtual_address;
        if (!any_load || candidate < min_load_base) {
            min_load_base = candidate;
            any_load = true;
        }
    }
    if (!found_zero_off_load && any_load) {
        img->image_base_ = min_load_base;
    }

    parse_elf_sections(b, is64, big, e_shoff, e_shentsize, eff_shnum, eff_shstrndx,
                       img->section_headers_, img->sections_, img->elf_symbols_, img->symbols_,
                       img->dynamic_entries_, img->relocations_, img->notes_, img->sysv_hash_tables_,
                       img->gnu_hash_tables_, img->imports_, img->parse_warnings_, budget);
    // Recover PT_DYNAMIC entries, DT_NEEDED dependencies, dynamic symbols, hash tables, and
    // dynamic relocations on sectionless / sstrip ELFs where the section header table is absent.
    img->recover_dynamic_from_program_headers(b, is64, big, 0u, img->image_base_, budget, false);
    if (img->elf_header_.type == 3 &&
        (!img->interpreter_.empty() || std::any_of(img->dynamic_entries_.begin(), img->dynamic_entries_.end(),
            [](const auto& entry) { return entry.tag == 0x6ffffffb && (entry.value & 0x08000000u) != 0; })))
        img->kind_ = ImageKind::Executable;
    img->append_symbol_imports_and_exports();
    if (img->arch_ == Architecture::PowerPC64 && img->endian_ == Endianness::Big) {
        resolve_powerpc64_function_descriptors(b, big, img->section_headers_, img->symbols_);
    }
    img->parse_gnu_debuglink_section(b, big);

    return img;
}

[[nodiscard]] std::optional<std::size_t> normalize_dynamic_ptr_to_offset(
    std::uint64_t raw_ptr,
    std::uint64_t live_base,
    std::uint64_t static_base,
    std::size_t mapped_size) noexcept {
    if (raw_ptr == 0) {
        return std::nullopt;
    }
    if (live_base != 0 && raw_ptr >= live_base &&
        (raw_ptr - live_base) < static_cast<std::uint64_t>(mapped_size)) {
        return static_cast<std::size_t>(raw_ptr - live_base);
    }
    if (raw_ptr >= static_base &&
        (raw_ptr - static_base) < static_cast<std::uint64_t>(mapped_size)) {
        return static_cast<std::size_t>(raw_ptr - static_base);
    }
    return std::nullopt;
}

[[nodiscard]] std::uint32_t count_gnu_hash_dynsyms(std::span<const std::uint8_t> b,
                                                   std::size_t hash_off,
                                                   bool is64,
                                                   bool big) noexcept {
    if (!fits_range(hash_off, 16, static_cast<std::uint64_t>(b.size()))) {
        return 0;
    }
    const std::uint32_t nbuckets = rd32(b, hash_off + 0, big);
    const std::uint32_t symoffset = rd32(b, hash_off + 4, big);
    const std::uint32_t bloom_size = rd32(b, hash_off + 8, big);
    const std::size_t word_sz = is64 ? 8u : 4u;
    const std::uint64_t buckets_off64 =
        static_cast<std::uint64_t>(hash_off) + 16ull +
        static_cast<std::uint64_t>(bloom_size) * static_cast<std::uint64_t>(word_sz);
    const std::uint64_t buckets_bytes = static_cast<std::uint64_t>(nbuckets) * 4ull;
    if (nbuckets == 0 || !fits_range(buckets_off64, buckets_bytes, static_cast<std::uint64_t>(b.size()))) {
        return symoffset;
    }

    const auto buckets_off = static_cast<std::size_t>(buckets_off64);
    std::uint32_t max_sym = 0;
    for (std::uint32_t i = 0; i < nbuckets; ++i) {
        const std::uint32_t bucket = rd32(b, buckets_off + static_cast<std::size_t>(i) * 4u, big);
        if (bucket > max_sym) {
            max_sym = bucket;
        }
    }
    if (max_sym < symoffset) {
        return symoffset;
    }

    const std::uint64_t chains_off64 = buckets_off64 + buckets_bytes;
    std::uint32_t idx = max_sym;
    constexpr std::uint32_t kMaxChainWalk = 1u << 20;
    for (std::uint32_t step = 0; step < kMaxChainWalk; ++step) {
        const std::uint64_t entry_off =
            chains_off64 + static_cast<std::uint64_t>(idx - symoffset) * 4ull;
        if (!fits_range(entry_off, 4, static_cast<std::uint64_t>(b.size()))) {
            break;
        }
        const std::uint32_t chain_val = rd32(b, static_cast<std::size_t>(entry_off), big);
        ++idx;
        if ((chain_val & 1u) != 0) {
            break;
        }
    }
    return idx;
}


void ElfImage::rebase_to_live_base(std::uint64_t live_base) {
    const std::uint64_t static_base = image_base_;
    const std::uint64_t bias = live_base - static_base;

    image_base_ = live_base;
    is_live_mapped_ = true;
    if (entry_ != 0) {
        entry_ += bias;
        elf_header_.entry = entry_;
    }

    std::uint64_t max_end = 4096;

    for (ElfProgramHeader& ph : program_headers_) {
        if (ph.type == 1 || ph.virtual_address != 0) {
            ph.virtual_address += bias;
            if (ph.physical_address != 0) {
                ph.physical_address += bias;
            }
            if (ph.virtual_address >= live_base) {
                ph.offset = ph.virtual_address - live_base;
            }
            ph.file_size = std::max(ph.memory_size, ph.file_size);
        }
    }

    for (Segment& seg : segments_) {
        if (seg.type == 1 || seg.virtual_address != 0) {
            seg.virtual_address += bias;
            if (seg.virtual_address >= live_base) {
                seg.file_offset = seg.virtual_address - live_base;
            }
            seg.file_size = std::max(seg.virtual_size, seg.file_size);
            if (seg.type == 1 && seg.virtual_address >= live_base) {
                max_end = std::max(max_end, (seg.virtual_address - live_base) + seg.file_size);
            }
        }
    }

    for (std::size_t i = 0; i < sections_.size(); ++i) {
        Section& sec = sections_[i];
        const bool is_alloc = (i < section_headers_.size())
                                  ? ((section_headers_[i].flags & 0x2ull) != 0)
                                  : (sec.readable || sec.writable || sec.executable);
        if (is_alloc) {
            sec.virtual_address += bias;
            if (sec.virtual_address >= live_base) {
                sec.file_offset = sec.virtual_address - live_base;
            }
            sec.file_size = std::max(sec.virtual_size, sec.file_size);
            if (sec.virtual_address >= live_base) {
                max_end = std::max(max_end, (sec.virtual_address - live_base) + sec.file_size);
            }
            if (i < section_headers_.size()) {
                section_headers_[i].address = sec.virtual_address;
                section_headers_[i].offset = sec.file_offset;
            }
        } else {
            sec.virtual_address = 0;
            sec.file_offset = 0;
            sec.file_size = 0;
        }
    }

    // If section headers were stripped/unmapped in RAM, synthesize navigable sections from PT_LOAD.
    if (sections_.empty()) {
        std::size_t load_index = 0;
        for (const Segment& seg : segments_) {
            if (seg.type != 1 || seg.file_size == 0) {
                continue;
            }
            Section sec;
            if (seg.executable) {
                sec.name = load_index == 0 ? ".text" : (".load_rx_" + std::to_string(load_index));
            } else if (seg.writable) {
                sec.name = ".data_rw_" + std::to_string(load_index);
            } else {
                sec.name = load_index == 0 ? ".rodata_hdr" : (".rodata_" + std::to_string(load_index));
            }
            sec.virtual_address = seg.virtual_address;
            sec.virtual_size = seg.virtual_size != 0 ? seg.virtual_size : seg.file_size;
            sec.file_offset = seg.file_offset;
            sec.file_size = seg.file_size;
            sec.readable = seg.readable;
            sec.writable = seg.writable;
            sec.executable = seg.executable;
            sections_.push_back(std::move(sec));
            ++load_index;
        }
    }

    mapped_span_size_ = max_end;

    for (Symbol& sym : symbols_) {
        const bool defined_in_section = sym.section_index != 0 && sym.section_index < 0xFF00u;
        const bool undef_with_plt_stub = sym.section_index == 0 && sym.virtual_address != 0;
        if (defined_in_section || undef_with_plt_stub) {
            sym.virtual_address += bias;
        }
    }

    for (ElfSymbol& esym : elf_symbols_) {
        const bool defined_in_section = esym.section_index != 0 && esym.section_index < 0xFF00u;
        const bool undef_with_plt_stub = esym.section_index == 0 && esym.value != 0;
        if (defined_in_section || undef_with_plt_stub) {
            esym.value += bias;
        }
    }

    for (ImportEntry& imp : imports_) {
        if (imp.address != 0) {
            imp.address += bias;
        }
    }

    for (ExportEntry& exp : exports_) {
        if (exp.virtual_address != 0) {
            exp.virtual_address += bias;
        }
    }

    for (ElfRelocation& rel : relocations_) {
        if (rel.offset != 0) {
            rel.offset += bias;
        }
    }
}

void ElfImage::append_symbol_imports_and_exports() {
    for (const auto& symbol : elf_symbols_) {
        if (!symbol.dynamic || symbol.name.empty() ||
            (symbol.binding != 1 && symbol.binding != 2)) {
            continue;
        }
        if (symbol.section_index == 0) {
            ImportEntry entry;
            entry.name = symbol.name;
            imports_.push_back(std::move(entry));
        } else if (symbol.visibility == 0 || symbol.visibility == 3) {
            ExportEntry entry;
            entry.name = symbol.name;
            entry.virtual_address = symbol.value;
            exports_.push_back(std::move(entry));
        }
    }
}

void ElfImage::recover_dynamic_from_program_headers(
    std::span<const std::uint8_t> b,
    bool is64,
    bool big,
    std::uint64_t live_base,
    std::uint64_t static_base,
    ElfParseBudget& budget,
    bool is_mapped) {
    if (!dynamic_entries_.empty()) {
        return;
    }

    auto translate_pt_load = [&](std::uint64_t va) -> std::optional<std::size_t> {
        for (const ElfProgramHeader& load_ph : program_headers_) {
            if (load_ph.type != 1u || va < load_ph.virtual_address) {
                continue;
            }
            const std::uint64_t file_backed =
                std::min(load_ph.file_size, load_ph.memory_size);
            const std::uint64_t delta = va - load_ph.virtual_address;
            if (delta < file_backed) {
                const auto off = checked_add_u64(load_ph.offset, delta);
                if (off.has_value() && *off < b.size()) {
                    return static_cast<std::size_t>(*off);
                }
            }
        }
        return std::nullopt;
    };

    auto resolve_ptr = [&](std::uint64_t val) -> std::optional<std::size_t> {
        if (val == 0u) {
            return std::nullopt;
        }
        if (const auto off = translate_pt_load(val)) {
            return off;
        }
        if (!is_mapped) {
            return std::nullopt;
        }
        return normalize_dynamic_ptr_to_offset(val, live_base, static_base, b.size());
    };

    for (const ElfProgramHeader& ph : program_headers_) {
        if (ph.type != 2u || ph.file_size == 0u) {
            continue;
        }
        std::uint64_t eff_dyn_bytes = ph.file_size;
        if (!fits_range(ph.offset, ph.file_size, static_cast<std::uint64_t>(b.size()))) {
            add_warning(std::format(
                "ELF PT_DYNAMIC segment truncated: offset 0x{:X} + {} bytes exceeds file size ({} bytes)",
                ph.offset, ph.file_size, b.size()));
            if (ph.offset >= b.size()) {
                continue;
            }
            eff_dyn_bytes = static_cast<std::uint64_t>(b.size()) - ph.offset;
        }
        const std::size_t dyn_ent_sz = is64 ? 16u : 8u;
        if ((ph.file_size % dyn_ent_sz) != 0u) {
            add_warning(std::format(
                "ELF PT_DYNAMIC segment size ({}) is not a multiple of entry size ({})",
                ph.file_size, dyn_ent_sz));
        }
        const std::size_t count = static_cast<std::size_t>(eff_dyn_bytes) / dyn_ent_sz;
        std::optional<std::size_t> strtab_off;
        std::uint64_t strtab_sz = 0u;
        std::optional<std::size_t> symtab_off;
        std::uint64_t syment_sz = is64 ? 24u : 16u;
        std::optional<std::size_t> sysv_hash_off;
        std::optional<std::size_t> gnu_hash_off;
        std::optional<std::size_t> rela_off;
        std::uint64_t rela_sz = 0u;
        std::uint64_t rela_ent = is64 ? 24u : 12u;
        std::optional<std::size_t> rel_off;
        std::uint64_t rel_sz = 0u;
        std::uint64_t rel_ent = is64 ? 16u : 8u;
        std::optional<std::size_t> jmprel_off;
        std::uint64_t jmprel_sz = 0u;
        std::uint64_t pltrel_kind = is64 ? 7u : 17u; // DT_RELA (7) or DT_REL (17)

        for (std::size_t i = 0; i < count; ++i) {
            if (budget.remaining_dynamic_entries == 0u) {
                if (!budget.warned_dynamic) {
                    add_warning(std::format(
                        "ELF dynamic table parsing capped at {} aggregate entries",
                        ElfParseBudget::kMaxTotalDynamicEntries));
                    budget.warned_dynamic = true;
                }
                break;
            }
            --budget.remaining_dynamic_entries;
            const std::size_t off = static_cast<std::size_t>(ph.offset) + i * dyn_ent_sz;
            const std::int64_t tag =
                is64 ? static_cast<std::int64_t>(rd64(b, off, big))
                     : static_cast<std::int64_t>(static_cast<std::int32_t>(rd32(b, off, big)));
            const std::uint64_t val =
                is64 ? rd64(b, off + 8u, big)
                     : static_cast<std::uint64_t>(rd32(b, off + 4u, big));
            ElfDynamicEntry de;
            de.tag = static_cast<std::uint64_t>(tag);
            de.value = val;
            dynamic_entries_.push_back(de);
            if (tag == 0) {
                break;
            }
            switch (tag) {
                case 2:  jmprel_sz = val; break;                     // DT_PLTRELSZ
                case 4:  sysv_hash_off = resolve_ptr(val); break;    // DT_HASH
                case 5:  strtab_off = resolve_ptr(val); break;       // DT_STRTAB
                case 6:  symtab_off = resolve_ptr(val); break;       // DT_SYMTAB
                case 7:  rela_off = resolve_ptr(val); break;         // DT_RELA
                case 8:  rela_sz = val; break;                       // DT_RELASZ
                case 9:  if (val != 0u) rela_ent = val; break;       // DT_RELAENT
                case 10: strtab_sz = val; break;                     // DT_STRSZ
                case 11: if (val != 0u) syment_sz = val; break;      // DT_SYMENT
                case 17: rel_off = resolve_ptr(val); break;          // DT_REL
                case 18: rel_sz = val; break;                        // DT_RELSZ
                case 19: if (val != 0u) rel_ent = val; break;        // DT_RELENT
                case 20: pltrel_kind = val; break;                   // DT_PLTREL
                case 23: jmprel_off = resolve_ptr(val); break;       // DT_JMPREL
                case 0x6ffffef5ll: gnu_hash_off = resolve_ptr(val); break; // DT_GNU_HASH
                default: break;
            }
        }

        if (sysv_hash_off && sysv_hash_tables_.empty() && *sysv_hash_off < b.size()) {
            ElfSectionHeader synthetic_sh{};
            synthetic_sh.name = ".hash";
            synthetic_sh.offset = *sysv_hash_off;
            synthetic_sh.size = b.size() - *sysv_hash_off;
            parse_elf_sysv_hash(b, big, synthetic_sh, sysv_hash_tables_);
        }

        std::uint32_t gnu_sym_end = 0u;
        if (gnu_hash_off && *gnu_hash_off < b.size()) {
            gnu_sym_end = count_gnu_hash_dynsyms(b, *gnu_hash_off, is64, big);
            if (gnu_hash_tables_.empty() && fits_range(*gnu_hash_off, 16u, static_cast<std::uint64_t>(b.size()))) {
                const std::uint32_t nbuckets = rd32(b, *gnu_hash_off + 0u, big);
                const std::uint32_t symoffset = rd32(b, *gnu_hash_off + 4u, big);
                const std::uint32_t bloom_cnt = rd32(b, *gnu_hash_off + 8u, big);
                const std::uint64_t bloom_sz = static_cast<std::uint64_t>(bloom_cnt) * (is64 ? 8ull : 4ull);
                const std::uint64_t chain_cnt = gnu_sym_end > symoffset ? (gnu_sym_end - symoffset) : 0u;
                const std::uint64_t total_sz = 16ull + bloom_sz +
                                               static_cast<std::uint64_t>(nbuckets) * 4ull +
                                               chain_cnt * 4ull;
                if (fits_range(*gnu_hash_off, total_sz, static_cast<std::uint64_t>(b.size()))) {
                    ElfSectionHeader synthetic_sh{};
                    synthetic_sh.name = ".gnu.hash";
                    synthetic_sh.offset = *gnu_hash_off;
                    synthetic_sh.size = total_sz;
                    parse_elf_gnu_hash(b, is64, big, synthetic_sh, gnu_hash_tables_);
                }
            }
        }

        if (strtab_off && *strtab_off < b.size()) {
            const std::size_t max_str =
                strtab_sz != 0u
                    ? static_cast<std::size_t>(std::min<std::uint64_t>(
                          strtab_sz, static_cast<std::uint64_t>(b.size() - *strtab_off)))
                    : (b.size() - *strtab_off);
            const auto read_dynstr = [&](std::uint32_t name_off) -> std::string {
                if (name_off >= max_str) {
                    return {};
                }
                return read_c_string(
                    std::span<const std::uint8_t>(b.data() + *strtab_off, max_str),
                    name_off);
            };

            for (ElfDynamicEntry& de : dynamic_entries_) {
                if ((de.tag == 1u || de.tag == 14u || de.tag == 15u || de.tag == 29u) &&
                    de.value <= std::numeric_limits<std::uint32_t>::max()) {
                    de.string_value = read_dynstr(static_cast<std::uint32_t>(de.value));
                    if (de.tag == 1u) {  // DT_NEEDED
                        de.needed_library = de.string_value;
                        if (!de.needed_library.empty()) {
                            ImportEntry imp;
                            imp.library = de.needed_library;
                            imports_.push_back(std::move(imp));
                        }
                    }
                }
            }

            if (symtab_off && elf_symbols_.empty() && syment_sz >= (is64 ? 24u : 16u)) {
                std::uint32_t sym_count = 0u;
                if (sysv_hash_off &&
                    fits_range(*sysv_hash_off, 8u, static_cast<std::uint64_t>(b.size()))) {
                    sym_count = rd32(b, *sysv_hash_off + 4u, big);
                } else if (gnu_sym_end > 0u) {
                    sym_count = gnu_sym_end;
                } else if (*strtab_off > *symtab_off) {
                    sym_count = static_cast<std::uint32_t>(
                        (*strtab_off - *symtab_off) / static_cast<std::size_t>(syment_sz));
                }

                const std::size_t sym_cap = std::min<std::size_t>(
                    static_cast<std::size_t>(sym_count),
                    budget.remaining_symbols);
                if (static_cast<std::size_t>(sym_count) > sym_cap && !budget.warned_symbols) {
                    add_warning(std::format(
                        "ELF symbol parsing capped at {} aggregate entries",
                        ElfParseBudget::kMaxTotalSymbols));
                    budget.warned_symbols = true;
                }
                // Include index 0 (STN_UNDEF) in elf_symbols_ so relocation symbol_index lookups align 1:1!
                for (std::uint32_t idx = 0u; idx < static_cast<std::uint32_t>(sym_cap); ++idx) {
                    const auto sym_rel = checked_mul_u64(idx, syment_sz);
                    const auto ent_off64 = sym_rel.has_value()
                        ? checked_add_u64(static_cast<std::uint64_t>(*symtab_off), *sym_rel)
                        : std::nullopt;
                    if (!ent_off64.has_value() ||
                        !fits_range(*ent_off64, syment_sz, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }
                    --budget.remaining_symbols;
                    const auto ent = static_cast<std::size_t>(*ent_off64);
                    std::uint32_t st_name = 0u;
                    std::uint8_t st_info = 0u;
                    std::uint8_t st_other = 0u;
                    std::uint16_t st_shndx = 0u;
                    std::uint64_t st_value = 0u;
                    std::uint64_t st_size = 0u;
                    if (is64) {
                        st_name = rd32(b, ent + 0u, big);
                        st_info = b[ent + 4u];
                        st_other = b[ent + 5u];
                        st_shndx = rd16(b, ent + 6u, big);
                        st_value = rd64(b, ent + 8u, big);
                        st_size = rd64(b, ent + 16u, big);
                    } else {
                        st_name = rd32(b, ent + 0u, big);
                        st_value = rd32(b, ent + 4u, big);
                        st_size = rd32(b, ent + 8u, big);
                        st_info = b[ent + 12u];
                        st_other = b[ent + 13u];
                        st_shndx = rd16(b, ent + 14u, big);
                    }

                    ElfSymbol es;
                    es.name_offset = st_name;
                    es.name = idx == 0u ? std::string{} : read_dynstr(st_name);
                    es.info = st_info;
                    es.other = st_other;
                    es.value = st_value;
                    es.size = st_size;
                    es.binding = static_cast<std::uint8_t>(st_info >> 4u);
                    es.type = static_cast<std::uint8_t>(st_info & 0x0Fu);
                    es.visibility = static_cast<std::uint8_t>(st_other & 0x03u);
                    es.section_index = st_shndx;
                    es.dynamic = true;

                    if (idx > 0u && !es.name.empty()) {
                        Symbol s;
                        s.name = es.name;
                        s.virtual_address = st_value;
                        s.size = st_size;
                        s.binding = es.binding;
                        s.type = es.type;
                        s.section_index = st_shndx;
                        s.dynamic = true;
                        symbols_.push_back(std::move(s));
                    }
                    elf_symbols_.push_back(std::move(es));
                }
            }
        }

        auto parse_dyn_reloc_table = [&](std::optional<std::size_t> table_off,
                                         std::uint64_t table_sz,
                                         std::uint64_t ent_sz,
                                         bool has_addend,
                                         std::string_view sec_label) {
            if (!table_off.has_value() || table_sz == 0u) {
                return;
            }
            const std::uint64_t min_ent = has_addend ? (is64 ? 24u : 12u) : (is64 ? 16u : 8u);
            if (ent_sz < min_ent) {
                add_warning(std::format(
                    "ELF dynamic relocation table '{}' has undersized entry size ({} < {})",
                    sec_label, ent_sz, min_ent));
                return;
            }
            std::uint64_t eff_table_sz = table_sz;
            if (!fits_range(*table_off, table_sz, static_cast<std::uint64_t>(b.size()))) {
                add_warning(std::format(
                    "ELF dynamic relocation table '{}' is truncated or out of file bounds",
                    sec_label));
                if (*table_off >= b.size()) {
                    return;
                }
                eff_table_sz = static_cast<std::uint64_t>(b.size() - *table_off);
            } else if ((table_sz % ent_sz) != 0u) {
                add_warning(std::format(
                    "ELF dynamic relocation table '{}' size ({}) is not a multiple of entry size ({})",
                    sec_label, table_sz, ent_sz));
            }
            const std::uint64_t rel_count = eff_table_sz / ent_sz;
            for (std::uint64_t i = 0u; i < rel_count; ++i) {
                if (budget.remaining_relocations == 0u) {
                    if (!budget.warned_relocations) {
                        add_warning(std::format(
                            "ELF relocation parsing capped at {} aggregate entries",
                            ElfParseBudget::kMaxTotalRelocations));
                        budget.warned_relocations = true;
                    }
                    break;
                }
                const auto rel_off = checked_mul_u64(i, ent_sz);
                const auto roff64 = rel_off.has_value()
                    ? checked_add_u64(static_cast<std::uint64_t>(*table_off), *rel_off)
                    : std::nullopt;
                if (!roff64.has_value() ||
                    !fits_range(*roff64, min_ent, static_cast<std::uint64_t>(b.size()))) {
                    break;
                }
                --budget.remaining_relocations;
                const auto roff = static_cast<std::size_t>(*roff64);
                ElfRelocation rel{};
                rel.section_name = std::string(sec_label);
                rel.has_addend = has_addend;
                if (is64) {
                    rel.offset = rd64(b, roff + 0u, big);
                    rel.info = rd64(b, roff + 8u, big);
                    rel.symbol_index = rel.info >> 32u;
                    rel.type = rel.info & 0xFFFF'FFFFull;
                    if (has_addend) {
                        rel.addend = static_cast<std::int64_t>(rd64(b, roff + 16u, big));
                    }
                } else {
                    rel.offset = rd32(b, roff + 0u, big);
                    rel.info = rd32(b, roff + 4u, big);
                    rel.symbol_index = rel.info >> 8u;
                    rel.type = rel.info & 0xFFull;
                    if (has_addend) {
                        rel.addend = static_cast<std::int32_t>(rd32(b, roff + 8u, big));
                    }
                }
                if (rel.symbol_index > 0u && rel.symbol_index < elf_symbols_.size()) {
                    rel.symbol_name = elf_symbols_[static_cast<std::size_t>(rel.symbol_index)].name;
                }
                relocations_.push_back(std::move(rel));
            }
        };

        if (relocations_.empty()) {
            parse_dyn_reloc_table(rela_off, rela_sz, rela_ent, true, ".rela.dyn");
            parse_dyn_reloc_table(rel_off, rel_sz, rel_ent, false, ".rel.dyn");
            const bool plt_is_rela = (pltrel_kind == 7u);
            parse_dyn_reloc_table(jmprel_off,
                                  jmprel_sz,
                                  plt_is_rela ? (is64 ? 24u : 12u) : (is64 ? 16u : 8u),
                                  plt_is_rela,
                                  plt_is_rela ? ".rela.plt" : ".rel.plt");
        }
        break;
    }
}

Result<std::unique_ptr<IBinaryImage>> ElfImage::parse_mapped(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    if (mapped_bytes.size() < 0x34) {
        return make_error("ELF mapped image too small");
    }
    const std::uint8_t ei_class = mapped_bytes[4];
    const std::uint8_t ei_data = mapped_bytes[5];
    if ((ei_class != 1 && ei_class != 2) || (ei_data != 1 && ei_data != 2)) {
        return make_error("ELF mapped image has invalid ident");
    }
    const bool is64 = (ei_class == 2);
    const bool big = (ei_data == 2);
    if (mapped_bytes.size() < (is64 ? 0x40u : 0x34u)) {
        return make_error("ELF mapped image truncated header");
    }

    std::vector<std::uint8_t> norm(mapped_bytes.begin(), mapped_bytes.end());

    const std::uint64_t e_phoff =
        is64 ? rd64(norm, 0x20, big) : static_cast<std::uint64_t>(rd32(norm, 0x1C, big));
    const std::uint16_t e_phentsize = rd16(norm, is64 ? 0x36 : 0x2A, big);
    const std::uint16_t e_phnum = rd16(norm, is64 ? 0x38 : 0x2C, big);

    std::uint64_t static_base = 0;
    bool found_zero_load = false;
    bool any_load = false;
    const std::size_t min_phent = is64 ? 0x38u : 0x20u;
    if (e_phentsize >= min_phent &&
        fits_range(e_phoff,
                   static_cast<std::uint64_t>(e_phentsize) * static_cast<std::uint64_t>(e_phnum),
                   static_cast<std::uint64_t>(norm.size()))) {
        for (std::uint16_t i = 0; i < e_phnum; ++i) {
            const std::size_t ph =
                static_cast<std::size_t>(e_phoff) + static_cast<std::size_t>(i) * e_phentsize;
            const std::uint32_t p_type = rd32(norm, ph + 0, big);
            if (p_type != 1) {
                continue;
            }
            const std::uint64_t p_offset =
                is64 ? rd64(norm, ph + 8, big) : static_cast<std::uint64_t>(rd32(norm, ph + 4, big));
            const std::uint64_t p_vaddr =
                is64 ? rd64(norm, ph + 16, big) : static_cast<std::uint64_t>(rd32(norm, ph + 8, big));
            if (p_offset == 0) {
                static_base = p_vaddr;
                found_zero_load = true;
                break;
            }
            const std::uint64_t cand = p_vaddr >= p_offset ? (p_vaddr - p_offset) : p_vaddr;
            if (!any_load || cand < static_base) {
                static_base = cand;
                any_load = true;
            }
        }

        // If a prelinked in-memory image (e.g. some vDSOs) already uses live_base as p_vaddr,
        // static_base equals live_base and (p_vaddr - static_base) still gives exact buffer offsets!
        (void)found_zero_load;

        for (std::uint16_t i = 0; i < e_phnum; ++i) {
            const std::size_t ph =
                static_cast<std::size_t>(e_phoff) + static_cast<std::size_t>(i) * e_phentsize;
            const std::uint32_t p_type = rd32(norm, ph + 0, big);
            if (p_type == 0) {
                continue;
            }
            const std::uint64_t p_vaddr =
                is64 ? rd64(norm, ph + 16, big) : static_cast<std::uint64_t>(rd32(norm, ph + 8, big));
            const std::uint64_t p_memsz =
                is64 ? rd64(norm, ph + 40, big)
                     : static_cast<std::uint64_t>(rd32(norm, ph + 20, big));
            if (p_vaddr >= static_base &&
                (p_vaddr - static_base) < static_cast<std::uint64_t>(norm.size())) {
                const std::uint64_t new_off = p_vaddr - static_base;
                const std::uint64_t avail = static_cast<std::uint64_t>(norm.size()) - new_off;
                const std::uint64_t new_filesz = std::min(p_memsz, avail);
                if (is64) {
                    wr64_endian(norm, ph + 8, new_off, big);
                    wr64_endian(norm, ph + 32, new_filesz, big);
                } else {
                    wr32_endian(norm, ph + 4, static_cast<std::uint32_t>(new_off), big);
                    wr32_endian(norm, ph + 16, static_cast<std::uint32_t>(new_filesz), big);
                }
            }
        }
    }

    // Validate whether section headers are genuinely present in mapped memory (e.g. [vdso]).
    const std::uint64_t e_shoff =
        is64 ? rd64(norm, 0x28, big) : static_cast<std::uint64_t>(rd32(norm, 0x20, big));
    const std::uint16_t e_shentsize = rd16(norm, is64 ? 0x3A : 0x2E, big);
    const std::uint16_t e_shnum = rd16(norm, is64 ? 0x3C : 0x30, big);
    const std::uint16_t e_shstrndx = rd16(norm, is64 ? 0x3E : 0x32, big);
    const std::size_t min_shent = is64 ? 0x40u : 0x28u;
    bool sh_valid = false;
    if (e_shoff != 0 && e_shentsize >= min_shent && e_shnum > 0 && e_shstrndx < e_shnum &&
        fits_range(e_shoff,
                   static_cast<std::uint64_t>(e_shentsize) * static_cast<std::uint64_t>(e_shnum),
                   static_cast<std::uint64_t>(norm.size()))) {
        // First section header must be SHT_NULL (type == 0) and shstrtab must be SHT_STRTAB (type == 3).
        const std::uint32_t sh0_type = rd32(norm, static_cast<std::size_t>(e_shoff) + 4, big);
        const std::size_t str_sh =
            static_cast<std::size_t>(e_shoff) + static_cast<std::size_t>(e_shstrndx) * e_shentsize;
        const std::uint32_t str_type = rd32(norm, str_sh + 4, big);
        const std::uint64_t str_off =
            is64 ? rd64(norm, str_sh + 24, big) : static_cast<std::uint64_t>(rd32(norm, str_sh + 16, big));
        const std::uint64_t str_sz =
            is64 ? rd64(norm, str_sh + 32, big) : static_cast<std::uint64_t>(rd32(norm, str_sh + 20, big));
        sh_valid = (sh0_type == 0 && str_type == 3 && str_sz > 0 &&
                    fits_range(str_off, str_sz, static_cast<std::uint64_t>(norm.size())));
    }
    if (!sh_valid) {
        if (is64) {
            wr64_endian(norm, 0x28, 0, big);
            wr16_endian(norm, 0x3C, 0, big);
            wr16_endian(norm, 0x3E, 0, big);
        } else {
            wr32_endian(norm, 0x20, 0, big);
            wr16_endian(norm, 0x30, 0, big);
            wr16_endian(norm, 0x32, 0, big);
        }
    }

    auto parsed = ElfImage::parse(norm);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }

    ElfImage* elf = parsed->get();
    // When ld.so has relocated DT_STRTAB / DT_SYMTAB in-place to live_base + rva,
    // recover_dynamic_from_program_headers with live_base resolves them cleanly.
    if (elf->elf_symbols_.empty()) {
        elf->dynamic_entries_.clear();
        elf->imports_.clear();
        elf->exports_.clear();
        ElfParseBudget mapped_budget{};
        elf->recover_dynamic_from_program_headers(
            norm, is64, big, live_base, static_base, mapped_budget, true);
        elf->append_symbol_imports_and_exports();
    }

    elf->rebase_to_live_base(live_base);
    elf->attach_raw_bytes(mapped_bytes);
    for (Segment& seg : elf->segments_) {
        if (seg.file_size != 0u) {
            const std::uint64_t avail = seg.file_offset < mapped_bytes.size()
                ? (static_cast<std::uint64_t>(mapped_bytes.size()) - seg.file_offset)
                : 0u;
            seg.file_size = std::min(seg.file_size, avail);
        }
    }
    for (Section& sec : elf->sections_) {
        if (sec.file_size != 0u) {
            const std::uint64_t avail = sec.file_offset < mapped_bytes.size()
                ? (static_cast<std::uint64_t>(mapped_bytes.size()) - sec.file_offset)
                : 0u;
            sec.file_size = std::min(sec.file_size, avail);
        }
    }
    elf->mapped_span_size_ =
        std::max<std::uint64_t>(elf->mapped_span_size_, static_cast<std::uint64_t>(mapped_bytes.size()));
    return std::unique_ptr<IBinaryImage>(std::move(*parsed));
}

} // namespace

namespace detail {

Result<std::unique_ptr<ImageBase>> parse_elf_image_impl(std::span<const std::uint8_t> bytes) {
    auto parsed = ElfImage::parse(bytes);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::unique_ptr<ImageBase>(std::move(*parsed));
}

Result<std::unique_ptr<IBinaryImage>> parse_elf_mapped_image_impl(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    return ElfImage::parse_mapped(mapped_bytes, live_base);
}

} // namespace detail
} // namespace peelf
