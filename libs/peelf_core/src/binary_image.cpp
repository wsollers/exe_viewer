#include <peelf/binary_image.hpp>

#include <algorithm>
#include <charconv>
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
    [[nodiscard]] std::uint64_t image_base() const noexcept override { return image_base_; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return entry_; }
    [[nodiscard]] const std::vector<Section>& sections() const noexcept override { return sections_; }
    [[nodiscard]] const std::vector<Segment>& segments() const noexcept override { return segments_; }
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept override { return symbols_; }
    [[nodiscard]] const std::vector<ImportEntry>& imports() const noexcept override { return imports_; }
    [[nodiscard]] const std::vector<ExportEntry>& exports() const noexcept override { return exports_; }
    [[nodiscard]] const GnuDebugLink* gnu_debuglink() const noexcept override {
        return gnu_debuglink_.has_value() ? &*gnu_debuglink_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeDataDirectory>& pe_data_directories() const noexcept override {
        static const std::vector<PeDataDirectory> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<PeBaseRelocationBlock>& pe_base_relocations() const noexcept override {
        static const std::vector<PeBaseRelocationBlock> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<PeDebugDirectory>& pe_debug_directories() const noexcept override {
        static const std::vector<PeDebugDirectory> empty;
        return empty;
    }
    [[nodiscard]] const PeTlsDirectory* pe_tls_directory() const noexcept override {
        return nullptr;
    }
    [[nodiscard]] const std::vector<PeCertificate>& pe_certificates() const noexcept override {
        static const std::vector<PeCertificate> empty;
        return empty;
    }
    [[nodiscard]] const PeLoadConfigDirectory* pe_load_config_directory() const noexcept override {
        return nullptr;
    }
    [[nodiscard]] const std::vector<PeRuntimeFunction>& pe_runtime_functions() const noexcept override {
        static const std::vector<PeRuntimeFunction> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<PeBoundImport>& pe_bound_imports() const noexcept override {
        static const std::vector<PeBoundImport> empty;
        return empty;
    }
    [[nodiscard]] const PeResourceDirectory* pe_resource_directory() const noexcept override {
        return nullptr;
    }
    [[nodiscard]] const std::vector<PeResourceDataEntry>& pe_resource_data_entries() const noexcept override {
        static const std::vector<PeResourceDataEntry> empty;
        return empty;
    }
    [[nodiscard]] const PeClrHeader* pe_clr_header() const noexcept override {
        return nullptr;
    }
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
    [[nodiscard]] const std::vector<ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept override {
        static const std::vector<ElfSysvHashTable> empty;
        return empty;
    }
    [[nodiscard]] const std::vector<ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept override {
        static const std::vector<ElfGnuHashTable> empty;
        return empty;
    }
    [[nodiscard]] std::string_view elf_interpreter() const noexcept override {
        return {};
    }
    [[nodiscard]] bool has_elf_pt_load() const noexcept {
        for (const auto& segment : segments_) {
            if (segment.type == 1) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override {
        if (format_ == Format::ELF && has_elf_pt_load()) {
            for (const auto& segment : segments_) {
                if (segment.type == 1 && file_offset >= segment.file_offset &&
                    file_offset - segment.file_offset < std::min(segment.file_size, segment.virtual_size)) {
                    return checked_add_u64(segment.virtual_address, file_offset - segment.file_offset);
                }
            }
            // When PT_LOAD program headers exist, section headers are not a loader mapping
            // (non-SHF_ALLOC debug sections may have VA zero).
            return std::nullopt;
        }
        for (const Section& section : sections_) {
            if (section.file_size == 0) {
                continue;
            }
            if (format_ == Format::ELF && !section.readable && !section.writable &&
                !section.executable) {
                continue;
            }
            if (file_offset >= section.file_offset && file_offset - section.file_offset < section.file_size) {
                return checked_add_u64(section.virtual_address, file_offset - section.file_offset);
            }
        }
        if (is_live_mapped_ && file_offset < mapped_span_size_) {
            return checked_add_u64(image_base_, file_offset);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept override {
        if (format_ == Format::ELF && has_elf_pt_load()) {
            for (const auto& segment : segments_) {
                if (segment.type == 1 && virtual_address >= segment.virtual_address &&
                    virtual_address - segment.virtual_address < std::min(segment.file_size, segment.virtual_size)) {
                    return checked_add_u64(segment.file_offset, virtual_address - segment.virtual_address);
                }
            }
            return std::nullopt;
        }
        for (const Section& section : sections_) {
            if (format_ == Format::ELF && !section.readable && !section.writable &&
                !section.executable) {
                continue;
            }
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
        if (is_live_mapped_ && virtual_address >= image_base_ &&
            (virtual_address - image_base_) < mapped_span_size_) {
            return virtual_address - image_base_;
        }
        return std::nullopt;
    }

protected:
    Format       format_ = Format::Unknown;
    ImageKind    kind_   = ImageKind::Unknown;
    Architecture arch_   = Architecture::Unknown;
    Endianness   endian_ = Endianness::Little;
    bool         is_64_  = false;
    bool         is_live_mapped_ = false;
    std::uint64_t mapped_span_size_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint64_t entry_ = 0;
    std::vector<Section> sections_;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
    std::vector<ImportEntry> imports_;
    std::vector<ExportEntry> exports_;
    std::optional<GnuDebugLink> gnu_debuglink_;

    void parse_gnu_debuglink_section(std::span<const std::uint8_t> b, bool big) {
        for (const Section& sec : sections_) {
            if (sec.name != ".gnu_debuglink" || sec.file_size < 5 ||
                !fits_range(sec.file_offset, sec.file_size, static_cast<std::uint64_t>(b.size()))) {
                continue;
            }
            const auto start = static_cast<std::size_t>(sec.file_offset);
            const auto max_len = static_cast<std::size_t>(std::min<std::uint64_t>(sec.file_size, 1024));
            std::size_t nul_rel = 0;
            while (nul_rel < max_len && b[start + nul_rel] != 0) {
                ++nul_rel;
            }
            if (nul_rel == 0 || nul_rel >= max_len) {
                continue;
            }
            GnuDebugLink link;
            link.filename.assign(reinterpret_cast<const char*>(b.data() + start), nul_rel);
            const std::size_t crc_rel = (nul_rel + 1u + 3u) & ~std::size_t{3u};
            if (crc_rel + 4u <= sec.file_size) {
                link.crc32 = rd32(b, start + crc_rel, big);
            }
            gnu_debuglink_ = std::move(link);
            return;
        }
    }
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
    [[nodiscard]] const std::vector<ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept override {
        return sysv_hash_tables_;
    }
    [[nodiscard]] const std::vector<ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept override {
        return gnu_hash_tables_;
    }
    [[nodiscard]] std::string_view elf_interpreter() const noexcept override {
        return interpreter_;
    }
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);
    static Result<std::unique_ptr<IBinaryImage>> parse_mapped(std::span<const std::uint8_t> mapped_bytes,
                                                              std::uint64_t live_base);
    void rebase_to_live_base(std::uint64_t live_base);

private:
    void recover_dynamic_from_program_headers(std::span<const std::uint8_t> b,
                                              bool is64,
                                              bool big,
                                              std::uint64_t live_base,
                                              std::uint64_t static_base);

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

class PeImage final : public ImageBase {
public:
    [[nodiscard]] const PeHeader* pe_header() const noexcept override {
        return &pe_header_;
    }
    [[nodiscard]] const std::vector<PeDataDirectory>& pe_data_directories() const noexcept override {
        return data_directories_;
    }
    [[nodiscard]] const std::vector<PeBaseRelocationBlock>& pe_base_relocations() const noexcept override {
        return base_relocations_;
    }
    [[nodiscard]] const std::vector<PeDebugDirectory>& pe_debug_directories() const noexcept override {
        return debug_directories_;
    }
    [[nodiscard]] const PeTlsDirectory* pe_tls_directory() const noexcept override {
        return tls_directory_ ? &*tls_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeCertificate>& pe_certificates() const noexcept override {
        return certificates_;
    }
    [[nodiscard]] const PeLoadConfigDirectory* pe_load_config_directory() const noexcept override {
        return load_config_directory_ ? &*load_config_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeRuntimeFunction>& pe_runtime_functions() const noexcept override {
        return runtime_functions_;
    }
    [[nodiscard]] const std::vector<PeBoundImport>& pe_bound_imports() const noexcept override {
        return bound_imports_;
    }
    [[nodiscard]] const PeResourceDirectory* pe_resource_directory() const noexcept override {
        return resource_directory_ ? &*resource_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeResourceDataEntry>& pe_resource_data_entries() const noexcept override {
        return resource_data_entries_;
    }
    [[nodiscard]] const PeClrHeader* pe_clr_header() const noexcept override {
        return clr_header_ ? &*clr_header_ : nullptr;
    }
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);
    void rebase_to_live_base(std::uint64_t live_base);

private:
    PeHeader pe_header_;
    std::vector<PeDataDirectory> data_directories_;
    std::vector<PeBaseRelocationBlock> base_relocations_;
    std::vector<PeDebugDirectory> debug_directories_;
    std::optional<PeTlsDirectory> tls_directory_;
    std::vector<PeCertificate> certificates_;
    std::optional<PeLoadConfigDirectory> load_config_directory_;
    std::vector<PeRuntimeFunction> runtime_functions_;
    std::vector<PeBoundImport> bound_imports_;
    std::optional<PeResourceDirectory> resource_directory_;
    std::vector<PeResourceDataEntry> resource_data_entries_;
    std::optional<PeClrHeader> clr_header_;
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

void parse_pe_base_relocations(std::span<const std::uint8_t> b,
                               const std::vector<Section>& sections,
                               std::uint64_t image_base,
                               std::uint32_t directory_rva,
                               std::uint32_t directory_size,
                               std::vector<PeBaseRelocationBlock>& relocations_out) {
    if (directory_rva == 0 || directory_size < 8) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = *directory_off + directory_size;
    std::uint64_t cursor = *directory_off;
    while (cursor + 8u <= end) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t page_rva = rd32(b, off + 0x00, false);
        const std::uint32_t block_size = rd32(b, off + 0x04, false);
        if (block_size < 8 || block_size > end - cursor) {
            break;
        }

        PeBaseRelocationBlock block;
        block.page_rva = page_rva;
        block.block_size = block_size;
        const std::uint64_t entry_count = (block_size - 8u) / 2u;
        block.entries.reserve(static_cast<std::size_t>(entry_count));
        std::uint64_t entry_cursor = cursor + 8u;
        for (std::uint64_t i = 0; i < entry_count; ++i, entry_cursor += 2u) {
            const std::uint16_t raw = rd16(b, static_cast<std::size_t>(entry_cursor), false);
            PeBaseRelocationEntry entry;
            entry.page_rva = page_rva;
            entry.type = static_cast<std::uint16_t>(raw >> 12);
            entry.offset = static_cast<std::uint16_t>(raw & 0x0FFFu);
            entry.rva = page_rva + entry.offset;
            block.entries.push_back(entry);
        }
        relocations_out.push_back(std::move(block));
        cursor += block_size;
    }
}

void parse_pe_debug_directories(std::span<const std::uint8_t> b,
                                const std::vector<Section>& sections,
                                std::uint64_t image_base,
                                std::uint32_t directory_rva,
                                std::uint32_t directory_size,
                                std::vector<PeDebugDirectory>& debug_out) {
    if (directory_rva == 0 || directory_size < 0x1C) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    constexpr std::uint64_t kDebugDirectorySize = 0x1C;
    const std::uint64_t count = directory_size / kDebugDirectorySize;
    debug_out.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t entry_off = *directory_off + i * kDebugDirectorySize;
        if (!fits_range(entry_off, kDebugDirectorySize, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t off = static_cast<std::size_t>(entry_off);
        PeDebugDirectory entry;
        entry.characteristics = rd32(b, off + 0x00, false);
        entry.time_date_stamp = rd32(b, off + 0x04, false);
        entry.major_version = rd16(b, off + 0x08, false);
        entry.minor_version = rd16(b, off + 0x0A, false);
        entry.type = rd32(b, off + 0x0C, false);
        entry.size_of_data = rd32(b, off + 0x10, false);
        entry.address_of_raw_data = rd32(b, off + 0x14, false);
        entry.pointer_to_raw_data = rd32(b, off + 0x18, false);

        if (entry.type == 2 && entry.size_of_data >= 24 &&
            fits_range(entry.pointer_to_raw_data, entry.size_of_data, static_cast<std::uint64_t>(b.size()))) {
            const std::uint64_t cv_off64 = entry.pointer_to_raw_data;
            const std::size_t cv = static_cast<std::size_t>(cv_off64);
            entry.codeview_signature = rd32(b, cv + 0x00, false);
            constexpr std::uint32_t kRsds = 0x5344'5352u;
            if (entry.codeview_signature == kRsds) {
                entry.codeview_guid.reserve(16);
                for (std::uint64_t byte_index = 0; byte_index < 16; ++byte_index) {
                    entry.codeview_guid.push_back(b[static_cast<std::size_t>(cv_off64 + 4u + byte_index)]);
                }
                entry.codeview_age = rd32(b, cv + 0x14, false);
                entry.codeview_pdb_path = read_c_string(b, cv_off64 + 0x18, entry.size_of_data - 0x18u);
            }
        }
        debug_out.push_back(std::move(entry));
    }
}

void parse_pe_runtime_functions(std::span<const std::uint8_t> b,
                                const std::vector<Section>& sections,
                                std::uint64_t image_base,
                                std::uint32_t directory_rva,
                                std::uint32_t directory_size,
                                std::vector<PeRuntimeFunction>& runtime_functions_out) {
    if (directory_rva == 0 || directory_size < 12) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    constexpr std::uint64_t kRuntimeFunctionSize = 12;
    const std::uint64_t count = directory_size / kRuntimeFunctionSize;
    runtime_functions_out.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t entry_off = *directory_off + i * kRuntimeFunctionSize;
        if (!fits_range(entry_off, kRuntimeFunctionSize, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t off = static_cast<std::size_t>(entry_off);
        PeRuntimeFunction entry;
        entry.begin_address_rva = rd32(b, off + 0x00, false);
        entry.end_address_rva = rd32(b, off + 0x04, false);
        entry.unwind_info_rva = rd32(b, off + 0x08, false);
        entry.file_offset = entry_off;
        runtime_functions_out.push_back(entry);
    }
}

[[nodiscard]] std::string read_pe_coff_symbol_name(std::span<const std::uint8_t> b,
                                                   std::size_t symbol_offset,
                                                   std::uint64_t string_table_offset,
                                                   std::uint64_t string_table_size) {
    if (rd32(b, symbol_offset, false) == 0) {
        const std::uint32_t name_offset = rd32(b, symbol_offset + 4u, false);
        if (name_offset < 4u || name_offset >= string_table_size) {
            return {};
        }
        return read_c_string(b, string_table_offset + name_offset);
    }

    std::string name;
    for (std::size_t i = 0; i < 8u && b[symbol_offset + i] != 0; ++i) {
        name.push_back(static_cast<char>(b[symbol_offset + i]));
    }
    return name;
}

void parse_pe_coff_symbols(std::span<const std::uint8_t> b,
                           const std::vector<Section>& sections,
                           std::uint32_t symbol_table_offset,
                           std::uint32_t symbol_count,
                           std::vector<Symbol>& symbols_out) {
    constexpr std::uint64_t kSymbolSize = 18;
    if (symbol_table_offset == 0 || symbol_count == 0 ||
        !fits_range(symbol_table_offset, static_cast<std::uint64_t>(symbol_count) * kSymbolSize,
                    static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t string_table_offset =
        static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(symbol_count) * kSymbolSize;
    std::uint64_t string_table_size = 0;
    if (fits_range(string_table_offset, 4, static_cast<std::uint64_t>(b.size()))) {
        string_table_size = rd32(b, static_cast<std::size_t>(string_table_offset), false);
        if (!fits_range(string_table_offset, string_table_size, static_cast<std::uint64_t>(b.size()))) {
            string_table_size = 0;
        }
    }

    const std::size_t original_size = symbols_out.size();
    for (std::uint32_t index = 0; index < symbol_count;) {
        const std::uint64_t symbol_offset64 =
            static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(index) * kSymbolSize;
        const std::size_t symbol_offset = static_cast<std::size_t>(symbol_offset64);
        const std::uint32_t value = rd32(b, symbol_offset + 8u, false);
        const auto section_number = static_cast<std::int16_t>(rd16(b, symbol_offset + 12u, false));
        const std::uint16_t type = rd16(b, symbol_offset + 14u, false);
        const std::uint8_t storage_class = b[symbol_offset + 16u];
        const std::uint8_t auxiliary_count = b[symbol_offset + 17u];

        const bool defined_section = section_number > 0 &&
                                     static_cast<std::size_t>(section_number) <= sections.size();
        constexpr std::uint16_t kFunctionDerivedType = 0x20;
        constexpr std::uint8_t kExternal = 2;
        constexpr std::uint8_t kStatic = 3;
        constexpr std::uint8_t kLabel = 6;
        const bool function = (type & kFunctionDerivedType) != 0;
        const bool useful_storage = storage_class == kExternal || storage_class == kStatic || storage_class == kLabel;

        if (defined_section && function && useful_storage) {
            Symbol symbol;
            symbol.name = read_pe_coff_symbol_name(b, symbol_offset, string_table_offset, string_table_size);
            if (!symbol.name.empty()) {
                const Section& section = sections[static_cast<std::size_t>(section_number - 1)];
                symbol.virtual_address = section.virtual_address + value;
                symbol.binding = storage_class;
                symbol.type = static_cast<std::uint8_t>(type & 0xFFu);
                symbol.section_index = static_cast<std::uint16_t>(section_number);
                symbol.dynamic = false;
                symbols_out.push_back(std::move(symbol));
            }
        }

        index += static_cast<std::uint32_t>(1u + auxiliary_count);
    }

    auto begin = symbols_out.begin() + static_cast<std::ptrdiff_t>(original_size);
    std::ranges::sort(begin, symbols_out.end(), [](const Symbol& lhs, const Symbol& rhs) {
        if (lhs.section_index != rhs.section_index) {
            return lhs.section_index < rhs.section_index;
        }
        return lhs.virtual_address < rhs.virtual_address;
    });

    for (auto it = begin; it != symbols_out.end(); ++it) {
        const auto next = std::find_if(std::next(it), symbols_out.end(), [&](const Symbol& candidate) {
            return candidate.section_index == it->section_index &&
                   candidate.virtual_address > it->virtual_address;
        });
        if (next != symbols_out.end()) {
            it->size = next->virtual_address - it->virtual_address;
        }
    }
}

void parse_pe_bound_imports(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            std::uint32_t directory_rva,
                            std::uint32_t directory_size,
                            std::vector<PeBoundImport>& bound_imports_out) {
    if (directory_rva == 0 || directory_size < 8) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = *directory_off + directory_size;
    for (std::uint64_t cursor = *directory_off; cursor + 8u <= end; cursor += 8u) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        PeBoundImport entry;
        entry.time_date_stamp = rd32(b, off + 0x00, false);
        entry.offset_module_name = rd16(b, off + 0x04, false);
        entry.forwarder_ref_count = rd16(b, off + 0x06, false);
        entry.file_offset = cursor;
        if (entry.time_date_stamp == 0 && entry.offset_module_name == 0 &&
            entry.forwarder_ref_count == 0) {
            break;
        }

        const std::uint64_t name_off = *directory_off + entry.offset_module_name;
        if (name_off < end) {
            entry.module_name = read_c_string(b, name_off, end - name_off);
        }
        bound_imports_out.push_back(std::move(entry));
    }
}

void parse_pe_resource_directory(std::span<const std::uint8_t> b,
                                 const std::vector<Section>& sections,
                                 std::uint64_t image_base,
                                 std::uint32_t directory_rva,
                                 std::uint32_t directory_size,
                                 std::optional<PeResourceDirectory>& resource_out,
                                 std::vector<PeResourceDataEntry>& data_entries_out) {
    if (directory_rva == 0 || directory_size < 16) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, 16, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeResourceDirectory resource;
    resource.rva = directory_rva;
    resource.file_offset = *directory_off;
    resource.characteristics = rd32(b, off + 0x00, false);
    resource.time_date_stamp = rd32(b, off + 0x04, false);
    resource.major_version = rd16(b, off + 0x08, false);
    resource.minor_version = rd16(b, off + 0x0A, false);
    resource.named_entry_count = rd16(b, off + 0x0C, false);
    resource.id_entry_count = rd16(b, off + 0x0E, false);

    const std::uint64_t total_entries = static_cast<std::uint64_t>(resource.named_entry_count) +
                                        static_cast<std::uint64_t>(resource.id_entry_count);
    const std::uint64_t max_entries = directory_size >= 16 ? (directory_size - 16u) / 8u : 0;
    const std::uint64_t parsed_entries = std::min(total_entries, max_entries);
    resource.entries.reserve(static_cast<std::size_t>(parsed_entries));
    for (std::uint64_t i = 0; i < parsed_entries; ++i) {
        const std::uint64_t entry_off = *directory_off + 16u + i * 8u;
        if (!fits_range(entry_off, 8, static_cast<std::uint64_t>(b.size()))) {
            break;
        }
        const std::size_t entry_pos = static_cast<std::size_t>(entry_off);
        PeResourceDirectoryEntry entry;
        entry.name_or_id = rd32(b, entry_pos + 0x00, false);
        entry.offset_to_data_or_directory = rd32(b, entry_pos + 0x04, false);
        entry.name_is_string = (entry.name_or_id & 0x8000'0000u) != 0;
        entry.data_is_directory = (entry.offset_to_data_or_directory & 0x8000'0000u) != 0;
        resource.entries.push_back(entry);
    }

    auto parse_resource_level = [&](auto&& self,
                                    std::uint64_t relative_directory_offset,
                                    std::uint32_t depth,
                                    std::uint32_t type_id,
                                    std::uint32_t name_id,
                                    std::uint32_t language_id) -> void {
        if (depth > 2 || relative_directory_offset > directory_size ||
            directory_size - relative_directory_offset < 16) {
            return;
        }

        const std::uint64_t directory_file_offset = *directory_off + relative_directory_offset;
        if (!fits_range(directory_file_offset, 16, static_cast<std::uint64_t>(b.size()))) {
            return;
        }

        const std::size_t dir = static_cast<std::size_t>(directory_file_offset);
        const std::uint16_t named_count = rd16(b, dir + 0x0C, false);
        const std::uint16_t id_count = rd16(b, dir + 0x0E, false);
        const std::uint64_t entry_count = static_cast<std::uint64_t>(named_count) +
                                          static_cast<std::uint64_t>(id_count);
        for (std::uint64_t i = 0; i < entry_count; ++i) {
            const std::uint64_t entry_off = directory_file_offset + 16u + i * 8u;
            if (!fits_range(entry_off, 8, static_cast<std::uint64_t>(b.size()))) {
                break;
            }

            const std::size_t entry_pos = static_cast<std::size_t>(entry_off);
            const std::uint32_t raw_name = rd32(b, entry_pos + 0x00, false);
            const std::uint32_t raw_target = rd32(b, entry_pos + 0x04, false);
            const std::uint32_t id = raw_name & 0x7FFF'FFFFu;
            const std::uint32_t next_type = depth == 0 ? id : type_id;
            const std::uint32_t next_name = depth == 1 ? id : name_id;
            const std::uint32_t next_language = depth == 2 ? id : language_id;

            const std::uint32_t target_offset = raw_target & 0x7FFF'FFFFu;
            if ((raw_target & 0x8000'0000u) != 0) {
                self(self, target_offset, depth + 1u, next_type, next_name, next_language);
                continue;
            }

            if (target_offset > directory_size || directory_size - target_offset < 16) {
                continue;
            }
            const std::uint64_t data_entry_off = *directory_off + target_offset;
            if (!fits_range(data_entry_off, 16, static_cast<std::uint64_t>(b.size()))) {
                continue;
            }

            const std::size_t data = static_cast<std::size_t>(data_entry_off);
            PeResourceDataEntry data_entry;
            data_entry.type_id = next_type;
            data_entry.name_id = next_name;
            data_entry.language_id = next_language;
            data_entry.data_rva = rd32(b, data + 0x00, false);
            data_entry.size = rd32(b, data + 0x04, false);
            data_entry.code_page = rd32(b, data + 0x08, false);
            data_entry.reserved = rd32(b, data + 0x0C, false);
            data_entry.entry_file_offset = data_entry_off;
            if (const auto data_off = pe_rva_to_file_offset(sections, image_base, data_entry.data_rva)) {
                data_entry.data_file_offset = *data_off;
            }
            data_entries_out.push_back(data_entry);
        }
    };

    parse_resource_level(parse_resource_level, 0, 0, 0, 0, 0);

    resource_out = std::move(resource);
}

void parse_pe_tls_directory(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            bool is64,
                            std::uint32_t directory_rva,
                            std::uint32_t directory_size,
                            std::optional<PeTlsDirectory>& tls_out) {
    const std::uint64_t min_size = is64 ? 0x28u : 0x18u;
    if (directory_rva == 0 || directory_size < min_size) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, min_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeTlsDirectory tls;
    if (is64) {
        tls.raw_data_start_va = rd64(b, off + 0x00, false);
        tls.raw_data_end_va = rd64(b, off + 0x08, false);
        tls.address_of_index = rd64(b, off + 0x10, false);
        tls.address_of_callbacks = rd64(b, off + 0x18, false);
        tls.size_of_zero_fill = rd32(b, off + 0x20, false);
        tls.characteristics = rd32(b, off + 0x24, false);
    } else {
        tls.raw_data_start_va = rd32(b, off + 0x00, false);
        tls.raw_data_end_va = rd32(b, off + 0x04, false);
        tls.address_of_index = rd32(b, off + 0x08, false);
        tls.address_of_callbacks = rd32(b, off + 0x0C, false);
        tls.size_of_zero_fill = rd32(b, off + 0x10, false);
        tls.characteristics = rd32(b, off + 0x14, false);
    }

    if (tls.address_of_callbacks != 0 && tls.address_of_callbacks >= image_base) {
        const std::uint64_t callbacks_rva64 = tls.address_of_callbacks - image_base;
        if (callbacks_rva64 <= std::numeric_limits<std::uint32_t>::max()) {
            const auto callbacks_off = pe_rva_to_file_offset(
                sections, image_base, static_cast<std::uint32_t>(callbacks_rva64));
            if (callbacks_off) {
                const std::uint64_t pointer_size = is64 ? 8u : 4u;
                for (std::uint64_t callback_index = 0; callback_index < b.size() / pointer_size; ++callback_index) {
                    const std::uint64_t callback_off = *callbacks_off + callback_index * pointer_size;
                    if (!fits_range(callback_off, pointer_size, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }
                    const std::uint64_t callback_va = is64
                        ? rd64(b, static_cast<std::size_t>(callback_off), false)
                        : static_cast<std::uint64_t>(rd32(b, static_cast<std::size_t>(callback_off), false));
                    if (callback_va == 0) {
                        break;
                    }
                    tls.callbacks.push_back(callback_va);
                }
            }
        }
    }

    tls_out = std::move(tls);
}

[[nodiscard]] std::uint64_t align8(std::uint64_t value) noexcept {
    return (value + 7u) & ~std::uint64_t{7u};
}

void parse_pe_certificates(std::span<const std::uint8_t> b,
                           std::uint32_t directory_file_offset,
                           std::uint32_t directory_size,
                           std::vector<PeCertificate>& certificates_out) {
    if (directory_file_offset == 0 || directory_size < 8) {
        return;
    }
    if (!fits_range(directory_file_offset, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = static_cast<std::uint64_t>(directory_file_offset) + directory_size;
    std::uint64_t cursor = directory_file_offset;
    while (cursor + 8u <= end) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t length = rd32(b, off + 0x00, false);
        if (length < 8 || length > end - cursor ||
            !fits_range(cursor, length, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        PeCertificate cert;
        cert.file_offset = static_cast<std::uint32_t>(cursor);
        cert.length = length;
        cert.revision = rd16(b, off + 0x04, false);
        cert.certificate_type = rd16(b, off + 0x06, false);
        cert.certificate.reserve(length - 8u);
        for (std::uint64_t i = 0; i < static_cast<std::uint64_t>(length - 8u); ++i) {
            cert.certificate.push_back(b[static_cast<std::size_t>(cursor + 8u + i)]);
        }
        certificates_out.push_back(std::move(cert));

        const std::uint64_t next = align8(cursor + length);
        if (next <= cursor) {
            break;
        }
        cursor = next;
    }
}

void parse_pe_load_config_directory(std::span<const std::uint8_t> b,
                                    const std::vector<Section>& sections,
                                    std::uint64_t image_base,
                                    bool is64,
                                    std::uint32_t directory_rva,
                                    std::uint32_t directory_size,
                                    std::optional<PeLoadConfigDirectory>& load_config_out) {
    const std::uint64_t min_size = is64 ? 0x94u : 0x5Cu;
    if (directory_rva == 0 || directory_size < min_size) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, min_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeLoadConfigDirectory load_config;
    load_config.rva = directory_rva;
    load_config.file_offset = *directory_off;
    load_config.size = rd32(b, off + 0x00, false);
    if (load_config.size < min_size ||
        !fits_range(*directory_off, load_config.size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    load_config.time_date_stamp = rd32(b, off + 0x04, false);
    load_config.major_version = rd16(b, off + 0x08, false);
    load_config.minor_version = rd16(b, off + 0x0A, false);
    load_config.global_flags_clear = rd32(b, off + 0x0C, false);
    load_config.global_flags_set = rd32(b, off + 0x10, false);
    load_config.critical_section_default_timeout = rd32(b, off + 0x14, false);

    if (is64) {
        load_config.decommit_free_block_threshold = rd64(b, off + 0x18, false);
        load_config.decommit_total_free_threshold = rd64(b, off + 0x20, false);
        load_config.lock_prefix_table = rd64(b, off + 0x28, false);
        load_config.maximum_allocation_size = rd64(b, off + 0x30, false);
        load_config.virtual_memory_threshold = rd64(b, off + 0x38, false);
        load_config.process_affinity_mask = rd64(b, off + 0x40, false);
        load_config.process_heap_flags = rd32(b, off + 0x48, false);
        load_config.csd_version = rd16(b, off + 0x4C, false);
        load_config.dependent_load_flags = rd16(b, off + 0x4E, false);
        load_config.edit_list = rd64(b, off + 0x50, false);
        load_config.security_cookie = rd64(b, off + 0x58, false);
        load_config.se_handler_table = rd64(b, off + 0x60, false);
        load_config.se_handler_count = rd64(b, off + 0x68, false);
        load_config.guard_cf_check_function_pointer = rd64(b, off + 0x70, false);
        load_config.guard_cf_dispatch_function_pointer = rd64(b, off + 0x78, false);
        load_config.guard_cf_function_table = rd64(b, off + 0x80, false);
        load_config.guard_cf_function_count = rd64(b, off + 0x88, false);
        load_config.guard_flags = rd32(b, off + 0x90, false);
        if (load_config.size >= 0x118u &&
            fits_range(*directory_off, 0x118u, static_cast<std::uint64_t>(b.size()))) {
            load_config.guard_eh_continuation_table = rd64(b, off + 0x108, false);
            load_config.guard_eh_continuation_count = rd64(b, off + 0x110, false);
        }
    } else {
        load_config.decommit_free_block_threshold = rd32(b, off + 0x18, false);
        load_config.decommit_total_free_threshold = rd32(b, off + 0x1C, false);
        load_config.lock_prefix_table = rd32(b, off + 0x20, false);
        load_config.maximum_allocation_size = rd32(b, off + 0x24, false);
        load_config.virtual_memory_threshold = rd32(b, off + 0x28, false);
        load_config.process_affinity_mask = rd32(b, off + 0x2C, false);
        load_config.process_heap_flags = rd32(b, off + 0x30, false);
        load_config.csd_version = rd16(b, off + 0x34, false);
        load_config.dependent_load_flags = rd16(b, off + 0x36, false);
        load_config.edit_list = rd32(b, off + 0x38, false);
        load_config.security_cookie = rd32(b, off + 0x3C, false);
        load_config.se_handler_table = rd32(b, off + 0x40, false);
        load_config.se_handler_count = rd32(b, off + 0x44, false);
        load_config.guard_cf_check_function_pointer = rd32(b, off + 0x48, false);
        load_config.guard_cf_dispatch_function_pointer = rd32(b, off + 0x4C, false);
        load_config.guard_cf_function_table = rd32(b, off + 0x50, false);
        load_config.guard_cf_function_count = rd32(b, off + 0x54, false);
        load_config.guard_flags = rd32(b, off + 0x58, false);
        if (load_config.size >= 0xACu &&
            fits_range(*directory_off, 0xACu, static_cast<std::uint64_t>(b.size()))) {
            load_config.guard_eh_continuation_table = rd32(b, off + 0xA4, false);
            load_config.guard_eh_continuation_count = rd32(b, off + 0xA8, false);
        }
    }

    load_config_out = load_config;
}

void parse_pe_import_thunks(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            bool is64,
                            std::string library,
                            std::uint32_t name_table_rva,
                            std::uint32_t address_table_rva,
                            bool delay_load,
                            std::vector<ImportEntry>& imports_out, bool thunk_values_are_va = false) {
    const auto thunk_off = pe_rva_to_file_offset(sections, image_base, name_table_rva);
    if (library.empty() || !thunk_off || address_table_rva == 0) {
        return;
    }

    const std::uint64_t thunk_size = is64 ? 8u : 4u;
    for (std::uint64_t thunk_index = 0; thunk_index < b.size() / thunk_size; ++thunk_index) {
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
            ImportEntry entry;
            entry.library = library;
            entry.ordinal = static_cast<std::uint16_t>(thunk_value & 0xFFFFu);
            entry.address = image_base + address_table_rva + thunk_index * thunk_size;
            entry.import_by_ordinal = true;
            entry.delay_load = delay_load;
            imports_out.push_back(std::move(entry));
            continue;
        }

        if (thunk_values_are_va && thunk_value < image_base) continue;
        const auto name_rva = thunk_values_are_va ? thunk_value - image_base : thunk_value;
        if (name_rva > std::numeric_limits<std::uint32_t>::max()) continue;
        const auto hint_name_off = pe_rva_to_file_offset(
            sections, image_base, static_cast<std::uint32_t>(name_rva));
        if (!hint_name_off || !fits_range(*hint_name_off, 2, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        ImportEntry entry;
        entry.library = library;
        entry.name = read_c_string(b, *hint_name_off + 2);
        entry.address = image_base + address_table_rva + thunk_index * thunk_size;
        entry.delay_load = delay_load;
        if (!entry.name.empty()) {
            imports_out.push_back(std::move(entry));
        }
    }
}

void parse_pe_delay_load_imports(std::span<const std::uint8_t> b,
                                 const std::vector<Section>& sections,
                                 std::uint64_t image_base,
                                 bool is64,
                                 std::uint32_t directory_rva,
                                 std::uint32_t directory_size,
                                 std::vector<ImportEntry>& imports_out) {
    if (directory_rva == 0 || directory_size < 32) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t max_descriptors = directory_size / 32u;
    for (std::uint64_t desc_index = 0; desc_index < max_descriptors; ++desc_index) {
        const std::uint64_t desc_off = *directory_off + desc_index * 32u;
        if (!fits_range(desc_off, 32, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t desc = static_cast<std::size_t>(desc_off);
        const std::uint32_t attributes = rd32(b, desc + 0x00, false);
        std::uint32_t name_rva = rd32(b, desc + 0x04, false);
        std::uint32_t import_address_table_rva = rd32(b, desc + 0x0C, false);
        std::uint32_t import_name_table_rva = rd32(b, desc + 0x10, false);
        if (attributes == 0 && name_rva == 0 && import_address_table_rva == 0 &&
            import_name_table_rva == 0) {
            break;
        }

        if ((attributes & 1u) == 0) {
            if (name_rva < image_base || import_address_table_rva < image_base ||
                import_name_table_rva < image_base) continue;
            name_rva = static_cast<std::uint32_t>(name_rva - image_base);
            import_address_table_rva = static_cast<std::uint32_t>(import_address_table_rva - image_base);
            import_name_table_rva = static_cast<std::uint32_t>(import_name_table_rva - image_base);
        }
        const auto dll_name_off = pe_rva_to_file_offset(sections, image_base, name_rva);
        const std::string library = dll_name_off ? read_c_string(b, *dll_name_off) : std::string{};
        parse_pe_import_thunks(b, sections, image_base, is64, library, import_name_table_rva,
                               import_address_table_rva, true, imports_out, (attributes & 1u) == 0);
    }
}

void parse_pe_clr_header(std::span<const std::uint8_t> b,
                         const std::vector<Section>& sections,
                         std::uint64_t image_base,
                         std::uint32_t directory_rva,
                         std::uint32_t directory_size,
                         std::optional<PeClrHeader>& clr_out) {
    if (directory_rva == 0 || directory_size < 0x48) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, 0x48, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeClrHeader clr;
    clr.rva = directory_rva;
    clr.file_offset = *directory_off;
    clr.size = rd32(b, off + 0x00, false);
    if (clr.size < 0x48 || !fits_range(*directory_off, clr.size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }
    clr.major_runtime_version = rd16(b, off + 0x04, false);
    clr.minor_runtime_version = rd16(b, off + 0x06, false);
    clr.metadata_rva = rd32(b, off + 0x08, false);
    clr.metadata_size = rd32(b, off + 0x0C, false);
    clr.flags = rd32(b, off + 0x10, false);
    clr.entry_point_token_or_rva = rd32(b, off + 0x14, false);
    clr.resources_rva = rd32(b, off + 0x18, false);
    clr.resources_size = rd32(b, off + 0x1C, false);
    clr.strong_name_signature_rva = rd32(b, off + 0x20, false);
    clr.strong_name_signature_size = rd32(b, off + 0x24, false);
    clr.code_manager_table_rva = rd32(b, off + 0x28, false);
    clr.code_manager_table_size = rd32(b, off + 0x2C, false);
    clr.vtable_fixups_rva = rd32(b, off + 0x30, false);
    clr.vtable_fixups_size = rd32(b, off + 0x34, false);
    clr.export_address_table_jumps_rva = rd32(b, off + 0x38, false);
    clr.export_address_table_jumps_size = rd32(b, off + 0x3C, false);
    clr.managed_native_header_rva = rd32(b, off + 0x40, false);
    clr.managed_native_header_size = rd32(b, off + 0x44, false);

    clr_out = clr;
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

void parse_elf_sysv_hash(std::span<const std::uint8_t> b, bool big,
                         const ElfSectionHeader& sh,
                         std::vector<ElfSysvHashTable>& hash_tables_out) {
    if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size())) || sh.size < 8) {
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
                        std::vector<ElfGnuHashTable>& hash_tables_out) {
    if (!fits_range(sh.offset, sh.size, static_cast<std::uint64_t>(b.size())) || sh.size < 16) {
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
                        std::vector<ElfNote>& notes_out) {
    if (phoff == 0 || phnum == 0 || phentsize == 0) {
        return;
    }
    const std::uint16_t min_ph = is64 ? 0x38 : 0x20;
    if (phentsize < min_ph || phnum > 65536u) {
        return;
    }
    const std::uint64_t table_size = static_cast<std::uint64_t>(phnum) * phentsize;
    if (!fits_range(phoff, table_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    headers_out.reserve(phnum);
    segments_out.reserve(phnum);
    for (std::uint32_t i = 0; i < phnum; ++i) {
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
                        std::uint32_t shnum, std::uint32_t shstrndx,
                        std::vector<ElfSectionHeader>& headers, std::vector<Section>& out,
                        std::vector<ElfSymbol>& elf_symbols_out, std::vector<Symbol>& symbols_out,
                        std::vector<ElfDynamicEntry>& dynamic_entries_out,
                        std::vector<ElfRelocation>& relocations_out,
                        std::vector<ElfNote>& notes_out,
                        std::vector<ElfSysvHashTable>& sysv_hash_tables_out,
                        std::vector<ElfGnuHashTable>& gnu_hash_tables_out,
                        std::vector<ImportEntry>& imports_out) {
    if (shoff == 0 || shnum == 0 || shentsize == 0) {
        return;
    }
    const std::uint16_t min_sh = is64 ? 0x40 : 0x28;
    if (shentsize < min_sh || shnum > 262144u) {
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
    for (std::uint32_t i = 0; i < shnum; ++i) {
        const std::uint64_t hdr = shoff + static_cast<std::uint64_t>(i) * shentsize;
        headers.push_back(read_sh(static_cast<std::size_t>(hdr)));
    }

    // Section-name string table = section[eff_shstrndx].
    std::uint64_t strtab_off = 0;
    std::uint64_t strtab_size = 0;
    if (shstrndx != 0 && shstrndx < shnum) {
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
    for (std::uint32_t i = 0; i < shnum; ++i) {
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

    for (std::uint32_t section_index = 0; section_index < shnum; ++section_index) {
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
            if ((tag == 1 || tag == 14 || tag == 15 || tag == 29) &&
                value <= std::numeric_limits<std::uint32_t>::max()) {
                raw_entry.string_value = read_string(strings.offset, strings.size,
                                                     static_cast<std::uint32_t>(value));
                if (tag == 1) {  // DT_NEEDED
                    raw_entry.needed_library = raw_entry.string_value;
                }
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
        if (sh.type == 5) {  // SHT_HASH
            parse_elf_sysv_hash(b, big, sh, sysv_hash_tables_out);
        } else if (sh.type == 0x6FFF'FFF6u) {  // SHT_GNU_HASH
            parse_elf_gnu_hash(b, is64, big, sh, gnu_hash_tables_out);
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
            if (relocation.symbol_index != 0 && sh.link < headers.size()) {
                const ElfSectionHeader& sym_sh = headers[sh.link];
                const std::uint64_t min_sym = is64 ? 0x18 : 0x10;
                const std::uint64_t sym_ent_sz = sym_sh.entry_size != 0 ? sym_sh.entry_size : min_sym;
                if ((sym_sh.type == 2 || sym_sh.type == 11) && sym_ent_sz >= min_sym &&
                    sym_sh.link < headers.size() &&
                    relocation.symbol_index < (sym_sh.size / sym_ent_sz)) {
                    const ElfSectionHeader& str_sh = headers[sym_sh.link];
                    const std::uint64_t sym_off = sym_sh.offset + relocation.symbol_index * sym_ent_sz;
                    if (fits_range(sym_off, 4u, static_cast<std::uint64_t>(b.size())) &&
                        fits_range(str_sh.offset, str_sh.size, static_cast<std::uint64_t>(b.size()))) {
                        const std::uint32_t name_off = rd32(b, static_cast<std::size_t>(sym_off), big);
                        relocation.symbol_name = read_string(str_sh.offset, str_sh.size, name_off);
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

    // ELF extended numbering (P1-5): shdr[0] carries overflow counts when
    // e_shnum == 0, e_shstrndx == SHN_XINDEX (0xFFFF), or e_phnum == PN_XNUM (0xFFFF).
    std::uint32_t eff_phnum = e_phnum == 0xFFFFu ? 0u : static_cast<std::uint32_t>(e_phnum);
    std::uint32_t eff_shnum = static_cast<std::uint32_t>(e_shnum);
    std::uint32_t eff_shstrndx = e_shstrndx == 0xFFFFu ? 0u : static_cast<std::uint32_t>(e_shstrndx);
    const std::uint16_t min_shent = is64 ? 0x40u : 0x28u;
    if ((e_shnum == 0u || e_shstrndx == 0xFFFFu || e_phnum == 0xFFFFu) &&
        e_shoff != 0u && e_shentsize >= min_shent &&
        fits_range(e_shoff, e_shentsize, static_cast<std::uint64_t>(b.size()))) {
        const auto sh0 = static_cast<std::size_t>(e_shoff);
        const std::uint32_t sh0_type = rd32(b, sh0 + 4u, big);
        if (sh0_type == 0u) {
            const std::uint64_t sh0_size = is64 ? rd64(b, sh0 + 0x20u, big)
                                                : static_cast<std::uint64_t>(rd32(b, sh0 + 0x14u, big));
            const std::uint32_t sh0_link = rd32(b, sh0 + (is64 ? 0x28u : 0x18u), big);
            const std::uint32_t sh0_info = rd32(b, sh0 + (is64 ? 0x2Cu : 0x1Cu), big);
            if (e_shnum == 0u && sh0_size > 0u && sh0_size <= 262144ull) {
                eff_shnum = static_cast<std::uint32_t>(sh0_size);
            }
            if (e_shstrndx == 0xFFFFu) {
                eff_shstrndx = sh0_link;
            }
            if (e_phnum == 0xFFFFu && sh0_info <= 65536u) {
                eff_phnum = sh0_info;
            }
        }
    }

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
        .effective_program_header_count = eff_phnum,
        .effective_section_header_count = eff_shnum,
        .effective_shstrndx = eff_shstrndx,
    };

    // Sections (P2-1), best-effort: identity above is already valid.
    parse_elf_segments(b, is64, big, e_phoff, e_phentsize, eff_phnum,
                       img->program_headers_, img->segments_, img->interpreter_, img->notes_);

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
                       img->gnu_hash_tables_, img->imports_);
    // Recover PT_DYNAMIC entries, DT_NEEDED dependencies, dynamic symbols, hash tables, and
    // dynamic relocations on sectionless / sstrip ELFs where the section header table is absent.
    img->recover_dynamic_from_program_headers(b, is64, big, 0u, img->image_base_);
    if (img->elf_header_.type == 3 &&
        (!img->interpreter_.empty() || std::any_of(img->dynamic_entries_.begin(), img->dynamic_entries_.end(),
            [](const auto& entry) { return entry.tag == 0x6ffffffb && (entry.value & 0x08000000u) != 0; })))
        img->kind_ = ImageKind::Executable;
    for (const auto& symbol : img->elf_symbols_) {
        if (!symbol.dynamic || symbol.name.empty() || (symbol.binding != 1 && symbol.binding != 2)) continue;
        if (symbol.section_index == 0) {
            ImportEntry entry;
            entry.name = symbol.name;
            img->imports_.push_back(std::move(entry));
        } else if (symbol.visibility == 0 || symbol.visibility == 3) {
            ExportEntry entry;
            entry.name = symbol.name;
            entry.virtual_address = symbol.value;
            img->exports_.push_back(std::move(entry));
        }
    }
    if (img->arch_ == Architecture::PowerPC64 && img->endian_ == Endianness::Big) {
        resolve_powerpc64_function_descriptors(b, big, img->section_headers_, img->symbols_);
    }
    img->parse_gnu_debuglink_section(b, big);

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
    const std::uint32_t symbol_table_offset = rd32(b, coff + 8, false);
    const std::uint32_t symbol_count = rd32(b, coff + 12, false);
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
    const std::uint32_t directory_count = size_of_opt >= (is64 ? 0x70 : 0x60)
        ? rd32(b, opt + (is64 ? 0x6C : 0x5C), false) : 0;
    const std::uint32_t export_dir_rva = (directory_count > 0 && size_of_opt >= (is64 ? 0x78 : 0x68))
                                             ? rd32(b, opt + (is64 ? 0x70 : 0x60), false)
                                             : 0;
    const std::uint32_t export_dir_size = (directory_count > 0 && size_of_opt >= (is64 ? 0x78 : 0x68))
                                              ? rd32(b, opt + (is64 ? 0x74 : 0x64), false)
                                              : 0;
    const std::uint32_t import_dir_rva = (directory_count > 1 && size_of_opt >= (is64 ? 0x80 : 0x70))
                                             ? rd32(b, opt + (is64 ? 0x78 : 0x68), false)
                                             : 0;
    const std::uint32_t import_dir_size = (directory_count > 1 && size_of_opt >= (is64 ? 0x80 : 0x70))
                                              ? rd32(b, opt + (is64 ? 0x7C : 0x6C), false)
                                              : 0;
    const std::uint32_t resource_dir_rva = (directory_count > 2 && size_of_opt >= (is64 ? 0x88 : 0x78))
                                               ? rd32(b, opt + (is64 ? 0x80 : 0x70), false)
                                               : 0;
    const std::uint32_t resource_dir_size = (directory_count > 2 && size_of_opt >= (is64 ? 0x88 : 0x78))
                                                ? rd32(b, opt + (is64 ? 0x84 : 0x74), false)
                                                : 0;
    const std::uint32_t exception_dir_rva = (directory_count > 3 && size_of_opt >= (is64 ? 0x90 : 0x80))
                                                ? rd32(b, opt + (is64 ? 0x88 : 0x78), false)
                                                : 0;
    const std::uint32_t exception_dir_size = (directory_count > 3 && size_of_opt >= (is64 ? 0x90 : 0x80))
                                                 ? rd32(b, opt + (is64 ? 0x8C : 0x7C), false)
                                                 : 0;
    const std::uint32_t certificate_table_file_offset = (directory_count > 4 && size_of_opt >= (is64 ? 0x98 : 0x88))
                                                            ? rd32(b, opt + (is64 ? 0x90 : 0x80), false)
                                                            : 0;
    const std::uint32_t certificate_table_size = (directory_count > 4 && size_of_opt >= (is64 ? 0x98 : 0x88))
                                                     ? rd32(b, opt + (is64 ? 0x94 : 0x84), false)
                                                     : 0;
    const std::uint32_t tls_dir_rva = (directory_count > 9 && size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xB8 : 0xA8), false)
        : 0;
    const std::uint32_t tls_dir_size = (directory_count > 9 && size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xBC : 0xAC), false)
        : 0;
    const std::uint32_t load_config_dir_rva = (directory_count > 10 && size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC0 : 0xB0), false)
        : 0;
    const std::uint32_t load_config_dir_size = (directory_count > 10 && size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC4 : 0xB4), false)
        : 0;
    const std::uint32_t bound_import_dir_rva = (directory_count > 11 && size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xC8 : 0xB8), false)
        : 0;
    const std::uint32_t bound_import_dir_size = (directory_count > 11 && size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xCC : 0xBC), false)
        : 0;
    const std::uint32_t delay_import_dir_rva = (directory_count > 13 && size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xD8 : 0xC8), false)
        : 0;
    const std::uint32_t delay_import_dir_size = (directory_count > 13 && size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xDC : 0xCC), false)
        : 0;
    const std::uint32_t clr_dir_rva = (directory_count > 14 && size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE0 : 0xD0), false)
        : 0;
    const std::uint32_t clr_dir_size = (directory_count > 14 && size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE4 : 0xD4), false)
        : 0;
    const std::uint32_t base_reloc_dir_rva = (directory_count > 5 && size_of_opt >= (is64 ? 0xA0 : 0x90))
        ? rd32(b, opt + (is64 ? 0x98 : 0x88), false)
        : 0;
    const std::uint32_t base_reloc_dir_size = (directory_count > 5 && size_of_opt >= (is64 ? 0xA0 : 0x90))
                                                  ? rd32(b, opt + (is64 ? 0x9C : 0x8C), false)
                                                  : 0;
    const std::uint32_t debug_dir_rva = (directory_count > 6 && size_of_opt >= (is64 ? 0xA8 : 0x98))
                                            ? rd32(b, opt + (is64 ? 0xA0 : 0x90), false)
                                            : 0;
    const std::uint32_t debug_dir_size = (directory_count > 6 && size_of_opt >= (is64 ? 0xA8 : 0x98))
                                             ? rd32(b, opt + (is64 ? 0xA4 : 0x94), false)
                                             : 0;

    auto img = std::unique_ptr<PeImage>(new PeImage());
    img->format_ = Format::PE;
    img->endian_ = Endianness::Little;
    img->is_64_  = is64;
    img->image_base_ = image_base;
    img->arch_   = pe_arch(machine);
    // IMAGE_FILE_DLL = 0x2000.
    img->kind_   = (characteristics & 0x2000) ? ImageKind::SharedLibrary : ImageKind::Executable;
    img->entry_  = entry_rva == 0 ? 0 : checked_add_u64(image_base, entry_rva).value_or(0);

    // Sections (P2-1): the section table follows the optional header.
    const std::uint16_t num_sections = rd16(b, coff + 2, false);
    const std::uint32_t time_date_stamp = rd32(b, coff + 4, false);
    img->pe_header_ = PeHeader{
        .machine = machine,
        .number_of_sections = num_sections,
        .time_date_stamp = time_date_stamp,
        .symbol_table_offset = symbol_table_offset,
        .number_of_symbols = symbol_count,
        .optional_header_size = size_of_opt,
        .characteristics = characteristics,
        .optional_magic = magic,
        .entry_point_rva = entry_rva,
        .section_alignment = size_of_opt >= 0x24 ? rd32(b, opt + 0x20, false) : 0u,
        .file_alignment = size_of_opt >= 0x28 ? rd32(b, opt + 0x24, false) : 0u,
        .size_of_image = size_of_opt >= 0x3C ? rd32(b, opt + 0x38, false) : 0u,
        .size_of_headers = size_of_opt >= 0x40 ? rd32(b, opt + 0x3C, false) : 0u,
        .checksum = size_of_opt >= 0x44 ? rd32(b, opt + 0x40, false) : 0u,
        .subsystem = size_of_opt >= 0x46 ? rd16(b, opt + 0x44, false) : std::uint16_t{0},
        .dll_characteristics = size_of_opt >= 0x48 ? rd16(b, opt + 0x46, false) : std::uint16_t{0},
        .stack_reserve = is64 ? (size_of_opt >= 0x50 ? rd64(b, opt + 0x48, false) : 0ull)
                              : (size_of_opt >= 0x4C ? static_cast<std::uint64_t>(rd32(b, opt + 0x48, false)) : 0ull),
        .stack_commit = is64 ? (size_of_opt >= 0x58 ? rd64(b, opt + 0x50, false) : 0ull)
                             : (size_of_opt >= 0x50 ? static_cast<std::uint64_t>(rd32(b, opt + 0x4C, false)) : 0ull),
        .heap_reserve = is64 ? (size_of_opt >= 0x60 ? rd64(b, opt + 0x58, false) : 0ull)
                             : (size_of_opt >= 0x54 ? static_cast<std::uint64_t>(rd32(b, opt + 0x50, false)) : 0ull),
        .heap_commit = is64 ? (size_of_opt >= 0x68 ? rd64(b, opt + 0x60, false) : 0ull)
                            : (size_of_opt >= 0x58 ? static_cast<std::uint64_t>(rd32(b, opt + 0x54, false)) : 0ull),
    };
    {
        static constexpr std::array<std::string_view, 16> kPeDirNames = {
            "Export", "Import", "Resource", "Exception",
            "Security", "BaseReloc", "Debug", "Architecture",
            "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
            "IAT", "DelayImport", "CLRRuntime", "Reserved",
        };
        const std::size_t dd_base_off = opt + (is64 ? 0x70u : 0x60u);
        const std::uint32_t capped_dirs = std::min<std::uint32_t>(directory_count, 16u);
        img->data_directories_.reserve(capped_dirs);
        for (std::uint32_t di = 0u; di < capped_dirs; ++di) {
            const std::size_t entry_off = dd_base_off + static_cast<std::size_t>(di) * 8u;
            if (entry_off + 8u > opt + size_of_opt ||
                !fits_range(entry_off, 8u, static_cast<std::uint64_t>(b.size()))) {
                break;
            }
            img->data_directories_.push_back(PeDataDirectory{
                .index = di,
                .name = std::string(kPeDirNames[di]),
                .rva = rd32(b, entry_off + 0u, false),
                .size = rd32(b, entry_off + 4u, false),
            });
        }
    }
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
        sec.raw_flags       = chars;
        if (sec.name.starts_with('/')) {
            std::uint32_t name_offset = 0;
            const auto parsed = std::from_chars(sec.name.data() + 1, sec.name.data() + sec.name.size(), name_offset);
            const std::uint64_t strings = static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(symbol_count) * 18;
            if (symbol_table_offset != 0 && parsed.ec == std::errc{} && parsed.ptr == sec.name.data() + sec.name.size() &&
                fits_range(strings, 4, b.size())) {
                const auto length = rd32(b, static_cast<std::size_t>(strings), false);
                if (name_offset >= 4 && name_offset < length && fits_range(strings, length, b.size()))
                    sec.name = read_c_string(b, strings + name_offset, length - name_offset);
            }
        }
        sec.executable = (chars & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
        sec.readable   = (chars & 0x40000000u) != 0;  // IMAGE_SCN_MEM_READ
        sec.writable   = (chars & 0x80000000u) != 0;  // IMAGE_SCN_MEM_WRITE
        img->sections_.push_back(std::move(sec));
    }

    parse_pe_coff_symbols(b, img->sections_, symbol_table_offset, symbol_count, img->symbols_);

    parse_pe_base_relocations(b, img->sections_, image_base, base_reloc_dir_rva,
                              base_reloc_dir_size, img->base_relocations_);
    parse_pe_debug_directories(b, img->sections_, image_base, debug_dir_rva,
                               debug_dir_size, img->debug_directories_);
    parse_pe_tls_directory(b, img->sections_, image_base, is64, tls_dir_rva,
                           tls_dir_size, img->tls_directory_);
    parse_pe_certificates(b, certificate_table_file_offset, certificate_table_size,
                          img->certificates_);
    parse_pe_load_config_directory(b, img->sections_, image_base, is64, load_config_dir_rva,
                                   load_config_dir_size, img->load_config_directory_);
    parse_pe_runtime_functions(b, img->sections_, image_base, exception_dir_rva,
                               exception_dir_size, img->runtime_functions_);
    parse_pe_bound_imports(b, img->sections_, image_base, bound_import_dir_rva,
                           bound_import_dir_size, img->bound_imports_);
    parse_pe_resource_directory(b, img->sections_, image_base, resource_dir_rva,
                                resource_dir_size, img->resource_directory_,
                                img->resource_data_entries_);
    parse_pe_clr_header(b, img->sections_, image_base, clr_dir_rva, clr_dir_size,
                        img->clr_header_);

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
            std::vector<bool> named_functions;
            if (functions_off && fits_range(*functions_off, static_cast<std::uint64_t>(number_of_functions) * 4, b.size()))
                named_functions.resize(number_of_functions);
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
                    if (function_rva == 0) continue;
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
                        if (ordinal_index < named_functions.size()) named_functions[ordinal_index] = true;
                        img->exports_.push_back(std::move(entry));
                    }
                }
            }
            for (std::size_t i = 0; i < named_functions.size(); ++i) {
                if (named_functions[i]) continue;
                const auto rva = rd32(b, static_cast<std::size_t>(*functions_off) + i * 4, false);
                if (rva == 0) continue;
                ExportEntry entry;
                entry.ordinal = ordinal_base + static_cast<std::uint32_t>(i);
                entry.virtual_address = checked_add_u64(image_base, rva).value_or(0);
                if (rva >= export_dir_rva && static_cast<std::uint64_t>(rva) - export_dir_rva < export_dir_size) {
                    if (const auto off = pe_rva_to_file_offset(img->sections_, image_base, rva))
                        entry.forwarder = read_c_string(b, *off);
                }
                img->exports_.push_back(std::move(entry));
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
                parse_pe_import_thunks(b, img->sections_, image_base, is64, library, thunk_rva,
                                       first_thunk, false, img->imports_);
            }
        }
    }

    parse_pe_delay_load_imports(b, img->sections_, image_base, is64, delay_import_dir_rva,
                                delay_import_dir_size, img->imports_);
    img->parse_gnu_debuglink_section(b, false);

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

namespace {

void wr16_endian(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v, bool big) noexcept {
    if (big) {
        b[off + 0] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
        b[off + 1] = static_cast<std::uint8_t>(v & 0xFFu);
    } else {
        b[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
        b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    }
}

void wr32_endian(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v, bool big) noexcept {
    for (std::size_t i = 0; i < 4; ++i) {
        const std::size_t idx = big ? (off + 3 - i) : (off + i);
        b[idx] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

void wr64_endian(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v, bool big) noexcept {
    for (std::size_t i = 0; i < 8; ++i) {
        const std::size_t idx = big ? (off + 7 - i) : (off + i);
        b[idx] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
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

}  // namespace

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

void ElfImage::recover_dynamic_from_program_headers(
    std::span<const std::uint8_t> b,
    bool is64,
    bool big,
    std::uint64_t live_base,
    std::uint64_t static_base) {
    if (!dynamic_entries_.empty()) {
        return;
    }

    auto resolve_ptr = [&](std::uint64_t val) -> std::optional<std::size_t> {
        if (val == 0u) {
            return std::nullopt;
        }
        if (const auto off = virtual_address_to_file_offset(val);
            off.has_value() && *off < b.size()) {
            return static_cast<std::size_t>(*off);
        }
        return normalize_dynamic_ptr_to_offset(val, live_base, static_base, b.size());
    };

    for (const ElfProgramHeader& ph : program_headers_) {
        if (ph.type != 2u || ph.file_size == 0u ||
            !fits_range(ph.offset, ph.file_size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }
        const std::size_t dyn_ent_sz = is64 ? 16u : 8u;
        const std::size_t count = static_cast<std::size_t>(ph.file_size) / dyn_ent_sz;
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

                constexpr std::uint32_t kMaxSyms = 262144u;
                sym_count = std::min(sym_count, kMaxSyms);
                // Include index 0 (STN_UNDEF) in elf_symbols_ so relocation symbol_index lookups align 1:1!
                for (std::uint32_t idx = 0u; idx < sym_count; ++idx) {
                    const std::uint64_t ent_off64 =
                        static_cast<std::uint64_t>(*symtab_off) +
                        static_cast<std::uint64_t>(idx) * syment_sz;
                    if (!fits_range(ent_off64, syment_sz, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }
                    const auto ent = static_cast<std::size_t>(ent_off64);
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
            if (ent_sz < min_ent ||
                !fits_range(*table_off, table_sz, static_cast<std::uint64_t>(b.size()))) {
                return;
            }
            const std::uint64_t rel_count = std::min<std::uint64_t>(table_sz / ent_sz, 262144ull);
            for (std::uint64_t i = 0u; i < rel_count; ++i) {
                const auto roff = static_cast<std::size_t>(*table_off + i * ent_sz);
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
        return parsed;
    }

    auto* elf = static_cast<ElfImage*>(parsed->get());
    // When ld.so has relocated DT_STRTAB / DT_SYMTAB in-place to live_base + rva,
    // recover_dynamic_from_program_headers with live_base resolves them cleanly.
    if (elf->elf_symbols_.empty()) {
        elf->dynamic_entries_.clear();
        elf->recover_dynamic_from_program_headers(norm, is64, big, live_base, static_base);
    }

    elf->rebase_to_live_base(live_base);
    elf->mapped_span_size_ =
        std::max<std::uint64_t>(elf->mapped_span_size_, static_cast<std::uint64_t>(mapped_bytes.size()));
    return parsed;
}

void PeImage::rebase_to_live_base(std::uint64_t live_base) {
    const std::uint64_t static_base = image_base_;
    const std::uint64_t bias = live_base - static_base;
    const std::uint64_t entry_rva = entry_ >= static_base ? (entry_ - static_base) : 0;

    image_base_ = live_base;
    entry_ = live_base + entry_rva;
    is_live_mapped_ = true;

    std::uint64_t max_end = 4096;
    for (Section& sec : sections_) {
        const std::uint64_t rva =
            sec.virtual_address >= static_base ? (sec.virtual_address - static_base) : 0;
        sec.virtual_address = live_base + rva;
        sec.file_offset = rva;
        sec.file_size = std::max(sec.virtual_size, sec.file_size);
        max_end = std::max(max_end, sec.file_offset + sec.file_size);
    }
    mapped_span_size_ = max_end;

    for (Symbol& sym : symbols_) {
        if (sym.virtual_address >= static_base && sym.section_index != 0) {
            sym.virtual_address += bias;
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

    for (PeDebugDirectory& dbg : debug_directories_) {
        if (dbg.address_of_raw_data != 0) {
            dbg.pointer_to_raw_data = dbg.address_of_raw_data;
        }
    }

    if (tls_directory_) {
        auto rebase_opt_va = [&](std::uint64_t& va) {
            if (va >= static_base && (va - static_base) < mapped_span_size_) {
                va += bias;
            }
        };
        rebase_opt_va(tls_directory_->raw_data_start_va);
        rebase_opt_va(tls_directory_->raw_data_end_va);
        rebase_opt_va(tls_directory_->address_of_index);
        rebase_opt_va(tls_directory_->address_of_callbacks);
        for (std::uint64_t& cb : tls_directory_->callbacks) {
            rebase_opt_va(cb);
        }
    }

    if (load_config_directory_) {
        load_config_directory_->file_offset = load_config_directory_->rva;
        auto rebase_opt_va = [&](std::uint64_t& va) {
            if (va >= static_base && (va - static_base) < mapped_span_size_) {
                va += bias;
            }
        };
        rebase_opt_va(load_config_directory_->security_cookie);
        rebase_opt_va(load_config_directory_->se_handler_table);
        rebase_opt_va(load_config_directory_->guard_cf_check_function_pointer);
        rebase_opt_va(load_config_directory_->guard_cf_dispatch_function_pointer);
        rebase_opt_va(load_config_directory_->guard_cf_function_table);
        rebase_opt_va(load_config_directory_->guard_eh_continuation_table);
    }

    for (PeRuntimeFunction& rf : runtime_functions_) {
        rf.file_offset = rf.begin_address_rva;
    }

    if (resource_directory_) {
        resource_directory_->file_offset = resource_directory_->rva;
    }

    for (PeResourceDataEntry& rde : resource_data_entries_) {
        rde.data_file_offset = rde.data_rva;
    }

    if (clr_header_) {
        clr_header_->file_offset = clr_header_->rva;
    }
}

std::vector<std::uint8_t> normalize_mapped_pe_for_file_parsers(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    std::vector<std::uint8_t> out(mapped_bytes.begin(), mapped_bytes.end());
    if (out.size() < 0x40 || out[0] != 'M' || out[1] != 'Z') {
        return out;
    }
    const std::uint32_t e_lfanew = rd32(out, 0x3C, false);
    if (!fits_range(e_lfanew, 24, static_cast<std::uint64_t>(out.size()))) {
        return out;
    }
    if (out[e_lfanew] != 'P' || out[e_lfanew + 1] != 'E' ||
        out[e_lfanew + 2] != 0 || out[e_lfanew + 3] != 0) {
        return out;
    }

    const std::size_t coff = static_cast<std::size_t>(e_lfanew) + 4;
    const std::uint16_t num_sections = rd16(out, coff + 2, false);
    const std::uint16_t size_of_opt = rd16(out, coff + 16, false);
    const std::size_t opt = coff + 20;
    if (size_of_opt < 32 || !fits_range(opt, size_of_opt, static_cast<std::uint64_t>(out.size()))) {
        return out;
    }

    const std::uint16_t magic = rd16(out, opt, false);
    const bool is64 = (magic == 0x20b);
    if (is64 && size_of_opt >= 32) {
        wr64_endian(out, opt + 24, live_base, false);
    } else if (magic == 0x10b && size_of_opt >= 32) {
        wr32_endian(out, opt + 28, static_cast<std::uint32_t>(live_base), false);
    }

    // Clear Certificate Table directory entry (index 4) since overlay certs are not mapped in RAM.
    const std::size_t cert_dir_off = opt + (is64 ? 0x70u : 0x60u) + 4u * 8u;
    if (size_of_opt >= ((is64 ? 0x70u : 0x60u) + 5u * 8u) &&
        fits_range(cert_dir_off, 8, static_cast<std::uint64_t>(out.size()))) {
        wr32_endian(out, cert_dir_off + 0, 0, false);
        wr32_endian(out, cert_dir_off + 4, 0, false);
    }

    const std::size_t sect_table = opt + size_of_opt;
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::uint64_t hdr64 =
            static_cast<std::uint64_t>(sect_table) + static_cast<std::uint64_t>(i) * 0x28ull;
        if (!fits_range(hdr64, 0x28, static_cast<std::uint64_t>(out.size()))) {
            break;
        }
        const auto hdr = static_cast<std::size_t>(hdr64);
        const std::uint32_t vsize = rd32(out, hdr + 8, false);
        const std::uint32_t vaddr = rd32(out, hdr + 12, false);
        const std::uint32_t rawsize = rd32(out, hdr + 16, false);
        const std::uint32_t span = std::max(vsize, rawsize);
        const std::uint32_t clamped_size =
            vaddr < out.size()
                ? static_cast<std::uint32_t>(
                      std::min<std::uint64_t>(span, static_cast<std::uint64_t>(out.size()) - vaddr))
                : 0u;
        wr32_endian(out, hdr + 16, clamped_size, false);
        wr32_endian(out, hdr + 20, vaddr, false);
    }

    return out;
}

Result<std::unique_ptr<IBinaryImage>> parse_rebased_image(
    std::span<const std::uint8_t> file_bytes,
    std::uint64_t live_base) {
    auto parsed = parse_image(file_bytes);
    if (!parsed) {
        return parsed;
    }
    if ((*parsed)->format() == Format::ELF) {
        static_cast<ElfImage*>(parsed->get())->rebase_to_live_base(live_base);
    } else if ((*parsed)->format() == Format::PE) {
        static_cast<PeImage*>(parsed->get())->rebase_to_live_base(live_base);
    }
    return parsed;
}

Result<std::unique_ptr<IBinaryImage>> parse_mapped_image(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    switch (detect_format(mapped_bytes)) {
        case Format::ELF:
            return ElfImage::parse_mapped(mapped_bytes, live_base);
        case Format::PE: {
            const std::vector<std::uint8_t> norm =
                normalize_mapped_pe_for_file_parsers(mapped_bytes, live_base);
            auto parsed = PeImage::parse(norm);
            if (!parsed) {
                return parsed;
            }
            static_cast<PeImage*>(parsed->get())->rebase_to_live_base(live_base);
            return parsed;
        }
        default:
            return make_error("Unknown or unsupported mapped binary format");
    }
}

} // namespace peelf
