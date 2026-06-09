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

private:
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
    [[nodiscard]] const PeClrHeader* pe_clr_header() const noexcept override {
        return clr_header_ ? &*clr_header_ : nullptr;
    }
    static Result<std::unique_ptr<IBinaryImage>> parse(std::span<const std::uint8_t> b);

private:
    std::vector<PeBaseRelocationBlock> base_relocations_;
    std::vector<PeDebugDirectory> debug_directories_;
    std::optional<PeTlsDirectory> tls_directory_;
    std::vector<PeCertificate> certificates_;
    std::optional<PeLoadConfigDirectory> load_config_directory_;
    std::vector<PeRuntimeFunction> runtime_functions_;
    std::vector<PeBoundImport> bound_imports_;
    std::optional<PeResourceDirectory> resource_directory_;
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
                                 std::optional<PeResourceDirectory>& resource_out) {
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
                for (std::uint64_t callback_index = 0; callback_index < 4096; ++callback_index) {
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
                            std::vector<ImportEntry>& imports_out) {
    const auto thunk_off = pe_rva_to_file_offset(sections, image_base, name_table_rva);
    if (library.empty() || !thunk_off || address_table_rva == 0) {
        return;
    }

    const std::uint64_t thunk_size = is64 ? 8u : 4u;
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
            sections, image_base, static_cast<std::uint32_t>(thunk_value));
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
        const std::uint32_t name_rva = rd32(b, desc + 0x04, false);
        const std::uint32_t import_address_table_rva = rd32(b, desc + 0x0C, false);
        const std::uint32_t import_name_table_rva = rd32(b, desc + 0x10, false);
        if (attributes == 0 && name_rva == 0 && import_address_table_rva == 0 &&
            import_name_table_rva == 0) {
            break;
        }

        const auto dll_name_off = pe_rva_to_file_offset(sections, image_base, name_rva);
        const std::string library = dll_name_off ? read_c_string(b, *dll_name_off) : std::string{};
        parse_pe_import_thunks(b, sections, image_base, is64, library, import_name_table_rva,
                               import_address_table_rva, true, imports_out);
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
                        std::vector<ElfSysvHashTable>& sysv_hash_tables_out,
                        std::vector<ElfGnuHashTable>& gnu_hash_tables_out,
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
                       img->dynamic_entries_, img->relocations_, img->notes_, img->sysv_hash_tables_,
                       img->gnu_hash_tables_, img->imports_);

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
    const std::uint32_t resource_dir_rva = (size_of_opt >= (is64 ? 0x88 : 0x78))
                                               ? rd32(b, opt + (is64 ? 0x80 : 0x70), false)
                                               : 0;
    const std::uint32_t resource_dir_size = (size_of_opt >= (is64 ? 0x88 : 0x78))
                                                ? rd32(b, opt + (is64 ? 0x84 : 0x74), false)
                                                : 0;
    const std::uint32_t exception_dir_rva = (size_of_opt >= (is64 ? 0x90 : 0x80))
                                                ? rd32(b, opt + (is64 ? 0x88 : 0x78), false)
                                                : 0;
    const std::uint32_t exception_dir_size = (size_of_opt >= (is64 ? 0x90 : 0x80))
                                                 ? rd32(b, opt + (is64 ? 0x8C : 0x7C), false)
                                                 : 0;
    const std::uint32_t certificate_table_file_offset = (size_of_opt >= (is64 ? 0x98 : 0x88))
                                                            ? rd32(b, opt + (is64 ? 0x90 : 0x80), false)
                                                            : 0;
    const std::uint32_t certificate_table_size = (size_of_opt >= (is64 ? 0x98 : 0x88))
                                                     ? rd32(b, opt + (is64 ? 0x94 : 0x84), false)
                                                     : 0;
    const std::uint32_t tls_dir_rva = (size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xB8 : 0xA8), false)
        : 0;
    const std::uint32_t tls_dir_size = (size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xBC : 0xAC), false)
        : 0;
    const std::uint32_t load_config_dir_rva = (size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC0 : 0xB0), false)
        : 0;
    const std::uint32_t load_config_dir_size = (size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC4 : 0xB4), false)
        : 0;
    const std::uint32_t bound_import_dir_rva = (size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xC8 : 0xB8), false)
        : 0;
    const std::uint32_t bound_import_dir_size = (size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xCC : 0xBC), false)
        : 0;
    const std::uint32_t delay_import_dir_rva = (size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xD8 : 0xC8), false)
        : 0;
    const std::uint32_t delay_import_dir_size = (size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xDC : 0xCC), false)
        : 0;
    const std::uint32_t clr_dir_rva = (size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE0 : 0xD0), false)
        : 0;
    const std::uint32_t clr_dir_size = (size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE4 : 0xD4), false)
        : 0;
    const std::uint32_t base_reloc_dir_rva = (size_of_opt >= (is64 ? 0xA0 : 0x90))
        ? rd32(b, opt + (is64 ? 0x98 : 0x88), false)
        : 0;
    const std::uint32_t base_reloc_dir_size = (size_of_opt >= (is64 ? 0xA0 : 0x90))
                                                  ? rd32(b, opt + (is64 ? 0x9C : 0x8C), false)
                                                  : 0;
    const std::uint32_t debug_dir_rva = (size_of_opt >= (is64 ? 0xA8 : 0x98))
                                            ? rd32(b, opt + (is64 ? 0xA0 : 0x90), false)
                                            : 0;
    const std::uint32_t debug_dir_size = (size_of_opt >= (is64 ? 0xA8 : 0x98))
                                             ? rd32(b, opt + (is64 ? 0xA4 : 0x94), false)
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
                                resource_dir_size, img->resource_directory_);
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
                parse_pe_import_thunks(b, img->sections_, image_base, is64, library, thunk_rva,
                                       first_thunk, false, img->imports_);
            }
        }
    }

    parse_pe_delay_load_imports(b, img->sections_, image_base, is64, delay_import_dir_rva,
                                delay_import_dir_size, img->imports_);

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
