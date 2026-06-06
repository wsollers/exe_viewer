#include <peelf/binary_image.hpp>

#include <cstddef>
#include <cstdint>
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

protected:
    Format       format_ = Format::Unknown;
    ImageKind    kind_   = ImageKind::Unknown;
    Architecture arch_   = Architecture::Unknown;
    Endianness   endian_ = Endianness::Little;
    bool         is_64_  = false;
    std::uint64_t entry_ = 0;
    std::vector<Section> sections_;
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
    if (static_cast<std::uint64_t>(e_lfanew) + 4 + 20 > b.size()) {
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
    if (size_of_opt < 2 || opt + size_of_opt > b.size()) {
        return make_error("PE: invalid optional header size");
    }

    const std::uint16_t magic = rd16(b, opt + 0, false); // 0x10b = PE32, 0x20b = PE32+
    const bool is64 = (magic == 0x20b);

    // entry VA = ImageBase + AddressOfEntryPoint.
    // AddressOfEntryPoint: optional-header offset 16 (both PE32 and PE32+).
    // ImageBase: PE32 -> u32 @ offset 28; PE32+ -> u64 @ offset 24.
    std::uint64_t entry_va = 0;
    if (opt + 20 <= b.size()) {
        const std::uint32_t entry_rva = rd32(b, opt + 16, false);
        std::uint64_t image_base = 0;
        if (is64) {
            if (opt + 32 <= b.size()) {
                image_base = rd64(b, opt + 24, false);
            }
        } else {
            if (opt + 32 <= b.size()) {
                image_base = rd32(b, opt + 28, false);
            }
        }
        entry_va = image_base + entry_rva;
    }

    auto img = std::unique_ptr<PeImage>(new PeImage());
    img->format_ = Format::PE;
    img->endian_ = Endianness::Little;
    img->is_64_  = is64;
    img->arch_   = pe_arch(machine);
    // IMAGE_FILE_DLL = 0x2000.
    img->kind_   = (characteristics & 0x2000) ? ImageKind::SharedLibrary : ImageKind::Executable;
    img->entry_  = entry_va;
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
