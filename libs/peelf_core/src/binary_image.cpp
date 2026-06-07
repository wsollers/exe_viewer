#include <peelf/binary_image.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>

namespace peelf {

namespace {

// ---------------------------------------------------------------------------
// Endian-aware fixed-width readers. Manual shifts (no <bit>/<cstring> needed);
// callers must ensure the offsets are in range before calling.
// ---------------------------------------------------------------------------
std::uint16_t rd16(std::span<const std::uint8_t> b, std::size_t o, bool big) noexcept {
    return big
        ? static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[o]) << 8) | b[o + 1])
        : static_cast<std::uint16_t>(b[o] | (static_cast<std::uint16_t>(b[o + 1]) << 8));
}

std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t o, bool big) noexcept {
    if (big) {
        return (static_cast<std::uint32_t>(b[o]) << 24) |
               (static_cast<std::uint32_t>(b[o + 1]) << 16) |
               (static_cast<std::uint32_t>(b[o + 2]) << 8) |
               (static_cast<std::uint32_t>(b[o + 3]));
    }
    return (static_cast<std::uint32_t>(b[o])) |
           (static_cast<std::uint32_t>(b[o + 1]) << 8) |
           (static_cast<std::uint32_t>(b[o + 2]) << 16) |
           (static_cast<std::uint32_t>(b[o + 3]) << 24);
}

std::uint64_t rd64(std::span<const std::uint8_t> b, std::size_t o, bool big) noexcept {
    if (big) {
        return (static_cast<std::uint64_t>(rd32(b, o, true)) << 32) |
               static_cast<std::uint64_t>(rd32(b, o + 4, true));
    }
    return (static_cast<std::uint64_t>(rd32(b, o + 4, false)) << 32) |
           static_cast<std::uint64_t>(rd32(b, o, false));
}

[[nodiscard]] bool fits_range(std::uint64_t offset, std::uint64_t size,
                              std::uint64_t total) noexcept {
    return offset <= total && size <= (total - offset);
}

[[nodiscard]] std::optional<std::uint64_t> checked_add_u64(std::uint64_t lhs,
                                                           std::uint64_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs) {
        return std::nullopt;
    }
    return lhs + rhs;
}

// ---------------------------------------------------------------------------
// Common storage for the parsed identity, shared by the concrete images.
// ---------------------------------------------------------------------------
class ImageBase : public IBinaryImage {
public:
    [[nodiscard]] Format format() const noexcept override { return format_; }
    [[nodiscard]] ImageKind kind() const noexcept override { return kind_; }
    [[nodiscard]] Architecture architecture() const noexcept override { return arch_; }
    [[nodiscard]] Endianness endianness() const noexcept override { return endian_; }
    [[nodiscard]] bool is_64bit() const noexcept override { return is_64_; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return entry_; }
    [[nodiscard]] const std::vector<Section>& sections() const noexcept override { return sections_; }
    [[nodiscard]] const std::vector<Segment>& segments() const noexcept override { return segments_; }
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept override { return symbols_; }
    [[nodiscard]] const std::vector<ImportEntry>& imports() const noexcept override { return imports_; }
    [[nodiscard]] const std::vector<ExportEntry>& exports() const noexcept override { return exports_; }
    [[nodiscard]] const ElfHeader* elf_header() const noexcept override { return nullptr; }
    [[nodiscard]] const std::vector<ElfProgramHeader>& elf_program_headers() const noexcept override {
        static const std::vector<ElfProgramHeader> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfSectionHeader>& elf_section_headers() const noexcept override {
        static const std::vector<ElfSectionHeader> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfSymbol>& elf_symbols() const noexcept override {
        static const std::vector<ElfSymbol> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfDynamicEntry>& elf_dynamic_entries() const noexcept override {
        static const std::vector<ElfDynamicEntry> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfRelocation>& elf_relocations() const noexcept override {
        static const std::vector<ElfRelocation> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfNote>& elf_notes() const noexcept override {
        static const std::vector<ElfNote> empty;
        return empty;
    }
    [[nodiscard]] std::string_view elf_interpreter() const noexcept override {
        return {};
    }
    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override {
        for (const Section& section : sections_) {
            if (section.file_size == 0) {
                continue;
            }
            if (file_offset >= section.file_offset && file_offset - section.file_offset < section.file_size) {
                return checked_add_u64(section.virtual_address, file_offset - section.file_offset);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept override {
        for (const Section& section : sections_) {
            const std::uint64_t mapped_size = section.virtual_size != 0 ? section.virtual_size : section.file_size;
            if (mapped_size == 0) {
                continue;
            }
            if (virtual_address >= section.virtual_address &&
                virtual_address - section.virtual_address < mapped_size) {
                const std::uint64_t delta = virtual_address - section.virtual_address;
                if (delta >= section.file_size) {
                    return std::nullopt;
                }
                return checked_add_u64(section.file_offset, delta);
            }
        }
        return std::nullopt;
    }

protected:
    Format       format_ = Format::Unknown;
    ImageKind    kind_   = ImageKind::Unknown;
    Architecture arch_   = Architecture::Unknown;
    Endianness   endian_ = Endianness::Little;
    bool         is_64_  = false;
    std::uint64_t entry_ = 0;
    std::vector<Section> sections_;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
    std::vector<ImportEntry> imports_;
    std::vector<ExportEntry> exports_;
};

class ElfImage final : public ImageBase {
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
    [[nodiscard]] std::string_view elf_interpreter() const noexcept override {
        return interpreter_;
    }
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);

private:
    ElfHeader elf_header_;
    std::vector<ElfProgramHeader> program_headers_;
    std::vector<ElfSectionHeader> section_headers_;
    std::vector<ElfSymbol> elf_symbols_;
    std::vector<ElfDynamicEntry> dynamic_entries_;
    std::vector<ElfRelocation> relocations_;
    std::vector<ElfNote> notes_;
    std::string interpreter_;
};

class PeImage final : public ImageBase {
public:
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);
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

Architecture pe_arch(std::uint16_t machine) noexcept {
    switch (machine) {
        case 0x014c: return Architecture::X86;     // IMAGE_FILE_MACHINE_I386
        case 0x8664: return Architecture::X86_64;  // IMAGE_FILE_MACHINE_AMD64
        case 0x01c0:                               // IMAGE_FILE_MACHINE_ARM
        case 0x01c4: return Architecture::ARM;     // IMAGE_FILE_MACHINE_ARMNT
        case 0xaa64: return Architecture::ARM64;   // IMAGE_FILE_MACHINE_ARM64
        default:     return Architecture::Unknown;
    }
}

std::string read_c_string(std::span<const std::uint8_t> b, std::uint64_t offset,
                          std::uint64_t max_len = 256) {
    if (offset >= b.size()) {
        return {};
    }
    std::string result;
    const std::uint64_t remaining = static_cast<std::uint64_t>(b.size()) - offset;
    const std::uint64_t max_end = offset + std::min(max_len, remaining);
    for (std::uint64_t i = offset; i < max_end && b[static_cast<std::size_t>(i)] != 0; ++i) {
        result.push_back(static_cast<char>(b[static_cast<std::size_t>(i)]));
    }
    return result;
}

std::optional<std::uint64_t> pe_rva_to_file_offset(const std::vector<Section>& sections,
                                                   std::uint64_t image_base,
                                                   std::uint32_t rva) noexcept {
    for (const Section& section : sections) {
        if (section.virtual_address < image_base) {
            continue;
        }
        const std::uint64_t section_rva = section.virtual_address - image_base;
        const std::uint64_t mapped_size = section.virtual_size != 0 ? section.virtual_size : section.file_size;
        if (mapped_size == 0) {
            continue;
        }
        if (rva >= section_rva && static_cast<std::uint64_t>(rva) - section_rva < mapped_size) {
            const std::uint64_t delta = static_cast<std::uint64_t>(rva) - section_rva;
            if (delta >= section.file_size) {
                return std::nullopt;
            }
            return checked_add_u64(section.file_offset, delta);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::uint64_t align4(std::uint64_t value) noexcept {
    return (value + 3u) & ~std::uint64_t{3u};
}

void parse_elf_notes(std::span<const std::uint8_t> b, bool big, std::uint64_t offset,
                     std::uint64_t size, bool from_program_header,
                     std::vector<ElfNote>& notes_out) {
    if (!fits_range(offset, size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = offset + size;
    std::uint64_t cursor = offset;
    while (cursor + 12u <= end) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t name_size = rd32(b, off + 0x00, big);
        const std::uint32_t descriptor_size = rd32(b, off + 0x04, big);
        const std::uint32_t type = rd32(b, off + 0x08, big);
        cursor += 12u;

        const std::uint64_t aligned_name_size = align4(name_size);
        const std::uint64_t aligned_descriptor_size = align4(descriptor_size);
        if (cursor > end || aligned_name_size > end - cursor) {
            break;
        }
        const std::uint64_t name_offset = cursor;
        cursor += aligned_name_size;
        if (cursor > end || aligned_descriptor_size > end - cursor) {
            break;
        }
        const std::uint64_t descriptor_offset = cursor;
        cursor += aligned_descriptor_size;

        ElfNote note;
        note.type = type;
        note.from_program_header = from_program_header;
        for (std::uint32_t i = 0; i < name_size && name_offset + i < end; ++i) {
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

void parse_elf_segments(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t phoff, std::uint16_t phentsize,
                        std::uint16_t phnum, std::vector<ElfProgramHeader>& headers_out,
                        std::vector<Segment>& segments_out, std::string& interpreter_out,
                        std::vector<ElfNote>& notes_out) {
    if (phoff == 0 || phnum == 0 || phentsize == 0) {
        return;
    }
    const std::uint16_t min_ph = is64 ? 0x38 : 0x20;
    if (phentsize < min_ph) {
        return;
    }
    const std::uint64_t table_size = static_cast<std::uint64_t>(phnum) * phentsize;
    if (!fits_range(phoff, table_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    headers_out.reserve(phnum);
    segments_out.reserve(phnum);
    for (std::uint16_t i = 0; i < phnum; ++i) {
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
        if (phdr.type == 3 && fits_range(phdr.offset, phdr.file_size, static_cast<std::uint64_t>(b.size()))) {
            interpreter_out = read_c_string(b, phdr.offset, phdr.file_size);
        }
        if (phdr.type == 4) {
            parse_elf_notes(b, big, phdr.offset, phdr.file_size, true, notes_out);
        }
    }
}

// Parse the ELF section header table into `out`. Best-effort and fully bounds-
// checked: on any inconsistency it returns leaving `out` as-is (identity parsing
// has already succeeded by the time this runs).
void parse_elf_sections(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t shoff, std::uint16_t shentsize,
                        std::uint16_t shnum, std::uint16_t shstrndx,
                        std::vector<ElfSectionHeader>& headers, std::vector<Section>& out,
                        std::vector<ElfSymbol>& elf_symbols_out, std::vector<Symbol>& symbols_out,
                        std::vector<ElfDynamicEntry>& dynamic_entries_out,
                        std::vector<ElfRelocation>& relocations_out,
                        std::vector<ElfNote>& notes_out,
                        std::vector<ImportEntry>& imports_out) {
    if (shoff == 0 || shnum == 0 || shentsize == 0) {
        return;
    }
    const std::uint16_t min_sh = is64 ? 0x40 : 0x28;
    if (shentsize < min_sh) {
        return;
    }
    const std::uint64_t table_size = static_cast<std::uint64_t>(shnum) * shentsize;
    if (!fits_range(shoff, table_size, static_cast<std::uint64_t>(b.size()))) {
        return;  // truncated table
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

    headers.reserve(shnum);
    for (std::uint16_t i = 0; i < shnum; ++i) {
        const std::uint64_t hdr = shoff + static_cast<std::uint64_t>(i) * shentsize;
        headers.push_back(read_sh(static_cast<std::size_t>(hdr)));
    }

    // Section-name string table = section[e_shstrndx].
    std::uint64_t strtab_off = 0;
    std::uint64_t strtab_size = 0;
    if (shstrndx != 0 && shstrndx < shnum && shstrndx != 0xFFFF) {
        const auto& sh = headers[shstrndx];
        strtab_off = sh.offset;
        strtab_size = sh.size;
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

    out.reserve(shnum);
    for (std::uint16_t i = 0; i < shnum; ++i) {
        const auto& sh = headers[i];
        Section sec;
        headers[i].name = read_section_name(sh.name_offset);
        sec.name            = headers[i].name;
        sec.virtual_address = sh.address;
        sec.virtual_size    = sh.size;
        sec.file_offset     = sh.offset;
        sec.file_size       = (sh.type == 8) ? 0 : sh.size;  // SHT_NOBITS has no file data
        sec.readable   = (sh.flags & 0x2) != 0;  // SHF_ALLOC
        sec.writable   = (sh.flags & 0x1) != 0;  // SHF_WRITE
        sec.executable = (sh.flags & 0x4) != 0;  // SHF_EXECINSTR
        out.push_back(std::move(sec));
    }

    for (std::uint16_t section_index = 0; section_index < shnum; ++section_index) {
        const auto& sh = headers[section_index];
        const bool is_symtab = sh.type == 2;   // SHT_SYMTAB
        const bool is_dynsym = sh.type == 11;  // SHT_DYNSYM
        if (!is_symtab && !is_dynsym) {
            continue;
        }

        const std::uint64_t min_sym = is64 ? 0x18 : 0x10;
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_sym;
        if (entry_size < min_sym || sh.link >= headers.size() ||
            !fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        const auto& strings = headers[sh.link];
        if (!fits_range(strings.offset, strings.size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        const std::uint64_t count = sh.size / entry_size;
        for (std::uint64_t i = 0; i < count; ++i) {
            const std::uint64_t sym_off = sh.offset + i * entry_size;
            if (!fits_range(sym_off, min_sym, static_cast<std::uint64_t>(b.size()))) {
                break;
            }

            const std::size_t off = static_cast<std::size_t>(sym_off);
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
            elf_symbol.name = read_string(strings.offset, strings.size, elf_symbol.name_offset);

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
        const std::uint64_t min_dyn = is64 ? 0x10 : 0x08;
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_dyn;
        if (entry_size < min_dyn || sh.link >= headers.size() ||
            !fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        const auto& strings = headers[sh.link];
        if (!fits_range(strings.offset, strings.size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        const std::uint64_t count = sh.size / entry_size;
        for (std::uint64_t i = 0; i < count; ++i) {
            const std::uint64_t dyn_off = sh.offset + i * entry_size;
            if (!fits_range(dyn_off, min_dyn, static_cast<std::uint64_t>(b.size()))) {
                break;
            }

            const std::size_t off = static_cast<std::size_t>(dyn_off);
            const std::uint64_t tag = is64 ? rd64(b, off + 0x00, big)
                                           : static_cast<std::uint64_t>(rd32(b, off + 0x00, big));
            const std::uint64_t value = is64 ? rd64(b, off + 0x08, big)
                                             : static_cast<std::uint64_t>(rd32(b, off + 0x04, big));
            ElfDynamicEntry raw_entry;
            raw_entry.tag = tag;
            raw_entry.value = value;
            if (tag == 1 && value <= std::numeric_limits<std::uint32_t>::max()) {  // DT_NEEDED
                raw_entry.needed_library = read_string(strings.offset, strings.size,
                                                       static_cast<std::uint32_t>(value));
            }
            dynamic_entries_out.push_back(raw_entry);
            if (tag == 0) {  // DT_NULL
                break;
            }
            if (!raw_entry.needed_library.empty()) {
                ImportEntry entry;
                entry.library = raw_entry.needed_library;
                imports_out.push_back(std::move(entry));
            }
        }
    }

    for (const auto& sh : headers) {
        if (sh.type == 7) {  // SHT_NOTE
            parse_elf_notes(b, big, sh.offset, sh.size, false, notes_out);
        }
    }

    for (const auto& sh : headers) {
        const bool has_addend = sh.type == 4;     // SHT_RELA
        const bool no_addend = sh.type == 9;      // SHT_REL
        if (!has_addend && !no_addend) {
            continue;
        }

        const std::uint64_t min_reloc = has_addend
            ? (is64 ? 0x18 : 0x0C)
            : (is64 ? 0x10 : 0x08);
        const std::uint64_t entry_size = sh.entry_size != 0 ? sh.entry_size : min_reloc;
        if (entry_size < min_reloc ||
            !fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        const std::uint64_t count = sh.size / entry_size;
        for (std::uint64_t i = 0; i < count; ++i) {
            const std::uint64_t reloc_off = sh.offset + i * entry_size;
            if (!fits_range(reloc_off, min_reloc, static_cast<std::uint64_t>(b.size()))) {
                break;
            }

            const std::size_t off = static_cast<std::size_t>(reloc_off);
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
            relocations_out.push_back(relocation);
        }
    }
}

Result<std::unique_ptr<IBinaryImage>> ElfImage::parse(std::span<const std::uint8_t> b) {
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

    auto img = std::unique_ptr<ElfImage>(new ElfImage());
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
    };

    // Sections (P2-1), best-effort: identity above is already valid.
    parse_elf_segments(b, is64, big, e_phoff, e_phentsize, e_phnum,
                       img->program_headers_, img->segments_, img->interpreter_, img->notes_);
    parse_elf_sections(b, is64, big, e_shoff, e_shentsize, e_shnum, e_shstrndx,
                       img->section_headers_, img->sections_, img->elf_symbols_, img->symbols_,
                       img->dynamic_entries_, img->relocations_, img->notes_, img->imports_);

    return std::unique_ptr<IBinaryImage>(std::move(img));
}

Result<std::unique_ptr<IBinaryImage>> PeImage::parse(std::span<const std::uint8_t> b) {
    if (b.size() < 0x40) {
        return make_error("PE: too small for DOS header");
    }
    if (!(b[0] == 'M' && b[1] == 'Z')) {
        return make_error("PE: missing MZ signature");
    }

    const std::uint32_t e_lfanew = rd32(b, 0x3C, false);
    // Need the PE signature (4) + COFF file header (20).
    if (!fits_range(e_lfanew, 4 + 20, static_cast<std::uint64_t>(b.size()))) {
        return make_error("PE: e_lfanew out of range");
    }
    if (!(b[e_lfanew] == 'P' && b[e_lfanew + 1] == 'E' &&
          b[e_lfanew + 2] == 0 && b[e_lfanew + 3] == 0)) {
        return make_error("PE: missing PE signature");
    }

    const std::size_t coff = static_cast<std::size_t>(e_lfanew) + 4;
    const std::uint16_t machine         = rd16(b, coff + 0, false);
    const std::uint16_t size_of_opt     = rd16(b, coff + 16, false);
    const std::uint16_t characteristics = rd16(b, coff + 18, false);

    const std::size_t opt = coff + 20;
    if (size_of_opt < 2 || !fits_range(opt, size_of_opt, static_cast<std::uint64_t>(b.size()))) {
        return make_error("PE: invalid optional header size");
    }

    const std::uint16_t magic = rd16(b, opt + 0, false); // 0x10b = PE32, 0x20b = PE32+
    if (magic != 0x10b && magic != 0x20b) {
        return make_error("PE: unsupported optional header magic");
    }
    const bool is64 = (magic == 0x20b);
    const std::uint16_t min_optional_size = is64 ? 32 : 32;
    if (size_of_opt < min_optional_size) {
        return make_error("PE: optional header too small for identity fields");
    }

    // entry VA = ImageBase + AddressOfEntryPoint.
    // AddressOfEntryPoint: optional-header offset 16 (both PE32 and PE32+).
    // ImageBase: PE32 -> u32 @ offset 28; PE32+ -> u64 @ offset 24.
    std::uint64_t image_base = 0;
    if (is64) {
        image_base = rd64(b, opt + 24, false);
    } else {
        image_base = rd32(b, opt + 28, false);
    }
    const std::uint32_t entry_rva = rd32(b, opt + 16, false);
    const std::uint32_t export_dir_rva = (size_of_opt >= (is64 ? 0x78 : 0x68))
                                             ? rd32(b, opt + (is64 ? 0x70 : 0x60), false)
                                             : 0;
    const std::uint32_t export_dir_size = (size_of_opt >= (is64 ? 0x78 : 0x68))
                                              ? rd32(b, opt + (is64 ? 0x74 : 0x64), false)
                                              : 0;
    const std::uint32_t import_dir_rva = (size_of_opt >= (is64 ? 0x80 : 0x70))
                                             ? rd32(b, opt + (is64 ? 0x78 : 0x68), false)
                                             : 0;
    const std::uint32_t import_dir_size = (size_of_opt >= (is64 ? 0x80 : 0x70))
                                              ? rd32(b, opt + (is64 ? 0x7C : 0x6C), false)
                                              : 0;

    auto img = std::unique_ptr<PeImage>(new PeImage());
    img->format_ = Format::PE;
    img->endian_ = Endianness::Little;
    img->is_64_  = is64;
    img->arch_   = pe_arch(machine);
    // IMAGE_FILE_DLL = 0x2000.
    img->kind_   = (characteristics & 0x2000) ? ImageKind::SharedLibrary : ImageKind::Executable;
    img->entry_  = image_base + entry_rva;

    // Sections (P2-1): the section table follows the optional header.
    const std::uint16_t num_sections = rd16(b, coff + 2, false);
    const std::size_t   sect_table   = opt + size_of_opt;
    constexpr std::size_t kSectHdr = 0x28;  // 40-byte section header
    img->sections_.reserve(num_sections);
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::uint64_t hdr64 = static_cast<std::uint64_t>(sect_table) +
                                    static_cast<std::uint64_t>(i) * kSectHdr;
        if (!fits_range(hdr64, kSectHdr, static_cast<std::uint64_t>(b.size()))) {
            break;  // truncated
        }
        const std::size_t hdr = static_cast<std::size_t>(hdr64);
        std::string name;
        for (std::size_t j = 0; j < 8 && b[hdr + j] != 0; ++j) {
            name.push_back(static_cast<char>(b[hdr + j]));
        }
        const std::uint32_t vsize   = rd32(b, hdr + 8, false);
        const std::uint32_t vaddr   = rd32(b, hdr + 12, false);
        const std::uint32_t rawsize = rd32(b, hdr + 16, false);
        const std::uint32_t rawptr  = rd32(b, hdr + 20, false);
        const std::uint32_t chars   = rd32(b, hdr + 36, false);

        Section sec;
        sec.name            = std::move(name);
        sec.virtual_address = image_base + vaddr;
        sec.virtual_size    = vsize;
        sec.file_offset     = rawptr;
        sec.file_size       = rawsize;
        sec.executable = (chars & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
        sec.readable   = (chars & 0x40000000u) != 0;  // IMAGE_SCN_MEM_READ
        sec.writable   = (chars & 0x80000000u) != 0;  // IMAGE_SCN_MEM_WRITE
        img->sections_.push_back(std::move(sec));
    }

    if (export_dir_rva != 0 && export_dir_size >= 40) {
        const auto export_off = pe_rva_to_file_offset(img->sections_, image_base, export_dir_rva);
        if (export_off && fits_range(*export_off, 40, static_cast<std::uint64_t>(b.size()))) {
            const std::size_t ed = static_cast<std::size_t>(*export_off);
            const std::uint32_t ordinal_base = rd32(b, ed + 16, false);
            const std::uint32_t number_of_functions = rd32(b, ed + 20, false);
            const std::uint32_t number_of_names = rd32(b, ed + 24, false);
            const std::uint32_t functions_rva = rd32(b, ed + 28, false);
            const std::uint32_t names_rva = rd32(b, ed + 32, false);
            const std::uint32_t ordinals_rva = rd32(b, ed + 36, false);

            const auto functions_off = pe_rva_to_file_offset(img->sections_, image_base, functions_rva);
            const auto names_off = pe_rva_to_file_offset(img->sections_, image_base, names_rva);
            const auto ordinals_off = pe_rva_to_file_offset(img->sections_, image_base, ordinals_rva);
            if (functions_off && names_off && ordinals_off) {
                for (std::uint32_t i = 0; i < number_of_names; ++i) {
                    const std::uint64_t name_ptr_off = *names_off + static_cast<std::uint64_t>(i) * 4;
                    const std::uint64_t ordinal_off = *ordinals_off + static_cast<std::uint64_t>(i) * 2;
                    if (!fits_range(name_ptr_off, 4, static_cast<std::uint64_t>(b.size())) ||
                        !fits_range(ordinal_off, 2, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }

                    const std::uint32_t name_rva = rd32(b, static_cast<std::size_t>(name_ptr_off), false);
                    const std::uint16_t ordinal_index = rd16(b, static_cast<std::size_t>(ordinal_off), false);
                    if (ordinal_index >= number_of_functions) {
                        continue;
                    }

                    const auto name_off = pe_rva_to_file_offset(img->sections_, image_base, name_rva);
                    const std::uint64_t function_off = *functions_off +
                                                       static_cast<std::uint64_t>(ordinal_index) * 4;
                    if (!name_off ||
                        !fits_range(function_off, 4, static_cast<std::uint64_t>(b.size()))) {
                        continue;
                    }

                    const std::uint32_t function_rva = rd32(b, static_cast<std::size_t>(function_off), false);
                    ExportEntry entry;
                    entry.name = read_c_string(b, *name_off);
                    entry.ordinal = ordinal_base + ordinal_index;
                    entry.virtual_address = image_base + function_rva;
                    if (function_rva >= export_dir_rva &&
                        static_cast<std::uint64_t>(function_rva) <
                            static_cast<std::uint64_t>(export_dir_rva) + export_dir_size) {
                        if (const auto forwarder_off = pe_rva_to_file_offset(img->sections_, image_base, function_rva)) {
                            entry.forwarder = read_c_string(b, *forwarder_off);
                        }
                    }
                    if (!entry.name.empty()) {
                        img->exports_.push_back(std::move(entry));
                    }
                }
            }
        }
    }

    if (import_dir_rva != 0 && import_dir_size >= 20) {
        const auto import_off = pe_rva_to_file_offset(img->sections_, image_base, import_dir_rva);
        if (import_off) {
            const std::uint64_t max_descriptors = import_dir_size / 20;
            for (std::uint64_t desc_index = 0; desc_index < max_descriptors; ++desc_index) {
                const std::uint64_t desc_off = *import_off + desc_index * 20;
                if (!fits_range(desc_off, 20, static_cast<std::uint64_t>(b.size()))) {
                    break;
                }

                const std::size_t desc = static_cast<std::size_t>(desc_off);
                const std::uint32_t original_first_thunk = rd32(b, desc + 0, false);
                const std::uint32_t name_rva = rd32(b, desc + 12, false);
                const std::uint32_t first_thunk = rd32(b, desc + 16, false);
                if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
                    break;
                }

                const auto dll_name_off = pe_rva_to_file_offset(img->sections_, image_base, name_rva);
                const std::string library = dll_name_off ? read_c_string(b, *dll_name_off) : std::string{};
                const std::uint32_t thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
                const auto thunk_off = pe_rva_to_file_offset(img->sections_, image_base, thunk_rva);
                if (library.empty() || !thunk_off || first_thunk == 0) {
                    continue;
                }

                const std::uint64_t thunk_size = is64 ? 8 : 4;
                for (std::uint64_t thunk_index = 0; thunk_index < 4096; ++thunk_index) {
                    const std::uint64_t entry_off = *thunk_off + thunk_index * thunk_size;
                    if (!fits_range(entry_off, thunk_size, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }

                    const std::uint64_t thunk_value = is64
                        ? rd64(b, static_cast<std::size_t>(entry_off), false)
                        : static_cast<std::uint64_t>(rd32(b, static_cast<std::size_t>(entry_off), false));
                    if (thunk_value == 0) {
                        break;
                    }

                    const std::uint64_t ordinal_mask = is64 ? (1ull << 63) : (1ull << 31);
                    if ((thunk_value & ordinal_mask) != 0) {
                        continue;
                    }

                    const auto hint_name_off = pe_rva_to_file_offset(
                        img->sections_, image_base, static_cast<std::uint32_t>(thunk_value));
                    if (!hint_name_off || !fits_range(*hint_name_off, 2, static_cast<std::uint64_t>(b.size()))) {
                        continue;
                    }

                    ImportEntry entry;
                    entry.library = library;
                    entry.name = read_c_string(b, *hint_name_off + 2);
                    entry.address = image_base + first_thunk + thunk_index * thunk_size;
                    if (!entry.name.empty()) {
                        img->imports_.push_back(std::move(entry));
                    }
                }
            }
        }
    }

    return std::unique_ptr<IBinaryImage>(std::move(img));
}

} // namespace

std::string_view to_string(Format f) noexcept {
    switch (f) {
        case Format::PE:  return "PE";
        case Format::ELF: return "ELF";
        default:          return "Unknown";
    }
}

std::string_view to_string(ImageKind k) noexcept {
    switch (k) {
        case ImageKind::Executable:    return "Executable";
        case ImageKind::SharedLibrary: return "Shared library";
        case ImageKind::Object:        return "Object";
        case ImageKind::Core:          return "Core dump";
        default:                       return "Unknown";
    }
}

std::string_view to_string(Architecture a) noexcept {
    switch (a) {
        case Architecture::X86:       return "x86";
        case Architecture::X86_64:    return "x86-64";
        case Architecture::ARM:       return "ARM";
        case Architecture::ARM64:     return "ARM64";
        case Architecture::RISCV32:   return "RISC-V 32";
        case Architecture::RISCV64:   return "RISC-V 64";
        case Architecture::PowerPC:   return "PowerPC";
        case Architecture::PowerPC64: return "PowerPC64";
        case Architecture::MIPS32:    return "MIPS32";
        case Architecture::MIPS64:    return "MIPS64";
        default:                      return "Unknown";
    }
}

std::string_view to_string(Endianness e) noexcept {
    return e == Endianness::Big ? "big-endian" : "little-endian";
}

Format detect_format(std::span<const std::uint8_t> b) noexcept {
    if (b.size() >= 4 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        return Format::ELF;
    }
    if (b.size() >= 2 && b[0] == 'M' && b[1] == 'Z') {
        return Format::PE;
    }
    return Format::Unknown;
}

Result<std::unique_ptr<IBinaryImage>> parse_image(std::span<const std::uint8_t> bytes) {
    switch (detect_format(bytes)) {
        case Format::ELF: return ElfImage::parse(bytes);
        case Format::PE:  return PeImage::parse(bytes);
        default:          return make_error("Unknown or unsupported binary format");
    }
}

} // namespace peelf
