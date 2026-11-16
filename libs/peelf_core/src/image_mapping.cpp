#include "image_internal.hpp"

#include <algorithm>

namespace peelf {

namespace detail {

std::string read_c_string(std::span<const std::uint8_t> b,
                          std::uint64_t offset,
                          std::uint64_t max_len) {
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
        const std::uint64_t mapped_size =
            section.virtual_size != 0 ? section.virtual_size : section.file_size;
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

const std::vector<PeDataDirectory>& ImageBase::pe_data_directories() const noexcept {
    static const std::vector<PeDataDirectory> empty;
    return empty;
}

const std::vector<PeBaseRelocationBlock>& ImageBase::pe_base_relocations() const noexcept {
    static const std::vector<PeBaseRelocationBlock> empty;
    return empty;
}

const std::vector<PeDebugDirectory>& ImageBase::pe_debug_directories() const noexcept {
    static const std::vector<PeDebugDirectory> empty;
    return empty;
}

const std::vector<PeCertificate>& ImageBase::pe_certificates() const noexcept {
    static const std::vector<PeCertificate> empty;
    return empty;
}

const std::vector<PeRuntimeFunction>& ImageBase::pe_runtime_functions() const noexcept {
    static const std::vector<PeRuntimeFunction> empty;
    return empty;
}

const std::vector<PeBoundImport>& ImageBase::pe_bound_imports() const noexcept {
    static const std::vector<PeBoundImport> empty;
    return empty;
}

const std::vector<PeResourceDataEntry>& ImageBase::pe_resource_data_entries() const noexcept {
    static const std::vector<PeResourceDataEntry> empty;
    return empty;
}

const std::vector<ElfProgramHeader>& ImageBase::elf_program_headers() const noexcept {
    static const std::vector<ElfProgramHeader> empty;
    return empty;
}

const std::vector<ElfSectionHeader>& ImageBase::elf_section_headers() const noexcept {
    static const std::vector<ElfSectionHeader> empty;
    return empty;
}

const std::vector<ElfSymbol>& ImageBase::elf_symbols() const noexcept {
    static const std::vector<ElfSymbol> empty;
    return empty;
}

const std::vector<ElfDynamicEntry>& ImageBase::elf_dynamic_entries() const noexcept {
    static const std::vector<ElfDynamicEntry> empty;
    return empty;
}

const std::vector<ElfRelocation>& ImageBase::elf_relocations() const noexcept {
    static const std::vector<ElfRelocation> empty;
    return empty;
}

const std::vector<ElfNote>& ImageBase::elf_notes() const noexcept {
    static const std::vector<ElfNote> empty;
    return empty;
}

const std::vector<ElfSysvHashTable>& ImageBase::elf_sysv_hash_tables() const noexcept {
    static const std::vector<ElfSysvHashTable> empty;
    return empty;
}

const std::vector<ElfGnuHashTable>& ImageBase::elf_gnu_hash_tables() const noexcept {
    static const std::vector<ElfGnuHashTable> empty;
    return empty;
}

bool ImageBase::has_elf_pt_load() const noexcept {
    for (const auto& segment : segments_) {
        if (segment.type == 1) {
            return true;
        }
    }
    return false;
}

std::optional<std::uint64_t> ImageBase::file_offset_to_virtual_address(
    std::uint64_t file_offset) const noexcept {
    if (format_ == Format::ELF && has_elf_pt_load()) {
        for (const auto& segment : segments_) {
            if (segment.type == 1 && file_offset >= segment.file_offset &&
                file_offset - segment.file_offset <
                    std::min(segment.file_size, segment.virtual_size)) {
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
        if (file_offset >= section.file_offset &&
            file_offset - section.file_offset < section.file_size) {
            return checked_add_u64(section.virtual_address, file_offset - section.file_offset);
        }
    }
    if (is_live_mapped_ && file_offset < mapped_span_size_) {
        return checked_add_u64(image_base_, file_offset);
    }
    return std::nullopt;
}

std::optional<std::uint64_t> ImageBase::virtual_address_to_file_offset(
    std::uint64_t virtual_address) const noexcept {
    if (format_ == Format::ELF && has_elf_pt_load()) {
        for (const auto& segment : segments_) {
            if (segment.type == 1 && virtual_address >= segment.virtual_address &&
                virtual_address - segment.virtual_address <
                    std::min(segment.file_size, segment.virtual_size)) {
                return checked_add_u64(segment.file_offset,
                                       virtual_address - segment.virtual_address);
            }
        }
        return std::nullopt;
    }
    for (const Section& section : sections_) {
        if (format_ == Format::ELF && !section.readable && !section.writable &&
            !section.executable) {
            continue;
        }
        const std::uint64_t mapped_size =
            section.virtual_size != 0 ? section.virtual_size : section.file_size;
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

void ImageBase::parse_gnu_debuglink_section(std::span<const std::uint8_t> b, bool big) {
    for (const Section& sec : sections_) {
        if (sec.name != ".gnu_debuglink" || sec.file_size < 5 ||
            !fits_range(sec.file_offset, sec.file_size, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }
        const auto start = static_cast<std::size_t>(sec.file_offset);
        const auto max_len =
            static_cast<std::size_t>(std::min<std::uint64_t>(sec.file_size, 1024));
        std::size_t nul_rel = 0;
        while (nul_rel < max_len && b[start + nul_rel] != 0) {
            ++nul_rel;
        }
        if (nul_rel == 0 || nul_rel >= max_len) {
            continue;
        }
        GnuDebugLink link;
        link.filename.reserve(nul_rel);
        for (std::size_t i = 0; i < nul_rel; ++i) {
            link.filename.push_back(static_cast<char>(b[start + i]));
        }
        const std::size_t crc_rel = (nul_rel + 1u + 3u) & ~std::size_t{3u};
        if (crc_rel + 4u <= sec.file_size) {
            link.crc32 = rd32(b, start + crc_rel, big);
        }
        gnu_debuglink_ = std::move(link);
        return;
    }
}

} // namespace detail

std::vector<std::uint8_t> normalize_mapped_pe_for_file_parsers(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    using detail::fits_range;
    using detail::rd16;
    using detail::rd32;
    using detail::wr32_endian;
    using detail::wr64_endian;

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

} // namespace peelf
