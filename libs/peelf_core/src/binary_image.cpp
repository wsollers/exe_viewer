#include <peelf/binary_image.hpp>

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
};

class ElfImage final : public ImageBase {
public:
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);
};

class PeImage final : public ImageBase {
public:
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);
};

Architecture elf_arch(std::uint16_t machine) noexcept {
    switch (machine) {
        case 3:   return Architecture::X86;        // EM_386
        case 62:  return Architecture::X86_64;     // EM_X86_64
        case 40:  return Architecture::ARM;        // EM_ARM
        case 183: return Architecture::ARM64;      // EM_AARCH64
        case 243: return Architecture::RISCV64;    // EM_RISCV
        case 21:  return Architecture::PowerPC64;  // EM_PPC64
        case 8:   return Architecture::MIPS;       // EM_MIPS
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

void parse_elf_segments(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t phoff, std::uint16_t phentsize,
                        std::uint16_t phnum, std::vector<Segment>& out) {
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

    out.reserve(phnum);
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const std::uint64_t hdr64 = phoff + static_cast<std::uint64_t>(i) * phentsize;
        const std::size_t hdr = static_cast<std::size_t>(hdr64);

        Segment seg;
        if (is64) {
            seg.type            = rd32(b, hdr + 0x00, big);
            const std::uint32_t flags = rd32(b, hdr + 0x04, big);
            seg.file_offset     = rd64(b, hdr + 0x08, big);
            seg.virtual_address = rd64(b, hdr + 0x10, big);
            seg.file_size       = rd64(b, hdr + 0x20, big);
            seg.virtual_size    = rd64(b, hdr + 0x28, big);
            seg.executable = (flags & 0x1u) != 0;  // PF_X
            seg.writable   = (flags & 0x2u) != 0;  // PF_W
            seg.readable   = (flags & 0x4u) != 0;  // PF_R
        } else {
            seg.type            = rd32(b, hdr + 0x00, big);
            seg.file_offset     = rd32(b, hdr + 0x04, big);
            seg.virtual_address = rd32(b, hdr + 0x08, big);
            seg.file_size       = rd32(b, hdr + 0x10, big);
            seg.virtual_size    = rd32(b, hdr + 0x14, big);
            const std::uint32_t flags = rd32(b, hdr + 0x18, big);
            seg.executable = (flags & 0x1u) != 0;  // PF_X
            seg.writable   = (flags & 0x2u) != 0;  // PF_W
            seg.readable   = (flags & 0x4u) != 0;  // PF_R
        }
        out.push_back(seg);
    }
}

// Parse the ELF section header table into `out`. Best-effort and fully bounds-
// checked: on any inconsistency it returns leaving `out` as-is (identity parsing
// has already succeeded by the time this runs).
void parse_elf_sections(std::span<const std::uint8_t> b, bool is64, bool big,
                        std::uint64_t shoff, std::uint16_t shentsize,
                        std::uint16_t shnum, std::uint16_t shstrndx,
                        std::vector<Section>& out) {
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

    struct ShFields {
        std::uint32_t name = 0;
        std::uint32_t type = 0;
        std::uint64_t flags = 0;
        std::uint64_t addr = 0;
        std::uint64_t offset = 0;
        std::uint64_t size = 0;
    };
    const auto read_sh = [&](std::size_t hdr) {
        ShFields s{};
        s.name = rd32(b, hdr + 0, big);
        s.type = rd32(b, hdr + 4, big);
        if (is64) {
            s.flags  = rd64(b, hdr + 0x08, big);
            s.addr   = rd64(b, hdr + 0x10, big);
            s.offset = rd64(b, hdr + 0x18, big);
            s.size   = rd64(b, hdr + 0x20, big);
        } else {
            s.flags  = rd32(b, hdr + 0x08, big);
            s.addr   = rd32(b, hdr + 0x0C, big);
            s.offset = rd32(b, hdr + 0x10, big);
            s.size   = rd32(b, hdr + 0x14, big);
        }
        return s;
    };

    // Section-name string table = section[e_shstrndx].
    std::uint64_t strtab_off = 0;
    if (shstrndx != 0 && shstrndx < shnum && shstrndx != 0xFFFF) {
        const std::uint64_t hdr = shoff + static_cast<std::uint64_t>(shstrndx) * shentsize;
        const auto sh = read_sh(static_cast<std::size_t>(hdr));
        strtab_off = sh.offset;
    }
    const auto read_name = [&](std::uint32_t name_off) -> std::string {
        if (strtab_off == 0) {
            return {};
        }
        if (!fits_range(strtab_off, name_off, static_cast<std::uint64_t>(b.size()))) {
            return {};
        }
        std::string s;
        for (std::uint64_t i = strtab_off + name_off; i < b.size() && b[static_cast<std::size_t>(i)] != 0;
             ++i) {
            s.push_back(static_cast<char>(b[static_cast<std::size_t>(i)]));
            if (s.size() >= 256) {
                break;
            }
        }
        return s;
    };

    out.reserve(shnum);
    for (std::uint16_t i = 0; i < shnum; ++i) {
        const std::uint64_t hdr = shoff + static_cast<std::uint64_t>(i) * shentsize;
        const auto sh = read_sh(static_cast<std::size_t>(hdr));
        Section sec;
        sec.name            = read_name(sh.name);
        sec.virtual_address = sh.addr;
        sec.virtual_size    = sh.size;
        sec.file_offset     = sh.offset;
        sec.file_size       = (sh.type == 8) ? 0 : sh.size;  // SHT_NOBITS has no file data
        sec.readable   = (sh.flags & 0x2) != 0;  // SHF_ALLOC
        sec.writable   = (sh.flags & 0x1) != 0;  // SHF_WRITE
        sec.executable = (sh.flags & 0x4) != 0;  // SHF_EXECINSTR
        out.push_back(std::move(sec));
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

    // e_entry sits at 0x18: 8 bytes for ELF64, 4 bytes for ELF32.
    const std::size_t need = is64 ? 0x20 : 0x1C;
    if (b.size() < need) {
        return make_error("ELF: truncated before e_entry");
    }

    const std::uint16_t e_type    = rd16(b, 0x10, big);
    const std::uint16_t e_machine = rd16(b, 0x12, big);
    const std::uint64_t e_entry   = is64 ? rd64(b, 0x18, big)
                                         : static_cast<std::uint64_t>(rd32(b, 0x18, big));

    auto img = std::unique_ptr<ElfImage>(new ElfImage());
    img->format_ = Format::ELF;
    img->is_64_  = is64;
    img->endian_ = big ? Endianness::Big : Endianness::Little;
    img->kind_   = elf_kind(e_type);
    img->arch_   = elf_arch(e_machine);
    img->entry_  = e_entry;

    // Sections (P2-1), best-effort: identity above is already valid.
    const std::size_t ehsize = is64 ? 0x40 : 0x34;
    if (b.size() >= ehsize) {
        const std::uint64_t phoff     = is64 ? rd64(b, 0x20, big)
                                             : static_cast<std::uint64_t>(rd32(b, 0x1C, big));
        const std::uint16_t phentsize = rd16(b, is64 ? 0x36 : 0x2A, big);
        const std::uint16_t phnum     = rd16(b, is64 ? 0x38 : 0x2C, big);
        const std::uint64_t shoff     = is64 ? rd64(b, 0x28, big)
                                             : static_cast<std::uint64_t>(rd32(b, 0x20, big));
        const std::uint16_t shentsize = rd16(b, is64 ? 0x3A : 0x2E, big);
        const std::uint16_t shnum     = rd16(b, is64 ? 0x3C : 0x30, big);
        const std::uint16_t shstrndx  = rd16(b, is64 ? 0x3E : 0x32, big);
        parse_elf_segments(b, is64, big, phoff, phentsize, phnum, img->segments_);
        parse_elf_sections(b, is64, big, shoff, shentsize, shnum, shstrndx, img->sections_);
    }

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
        case Architecture::RISCV64:   return "RISC-V 64";
        case Architecture::PowerPC64: return "PowerPC64";
        case Architecture::MIPS:      return "MIPS";
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
