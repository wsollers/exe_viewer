#include "image_internal.hpp"

#include <peelf/macho_image.hpp>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

namespace {

[[nodiscard]] bool iequals_ascii(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto ca = static_cast<unsigned char>(lhs[i]);
        const auto cb = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(ca) != std::tolower(cb)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] Result<std::unique_ptr<detail::ImageBase>> parse_pe_or_elf_base(
    Format fmt,
    std::span<const std::uint8_t> bytes) {
    Result<std::unique_ptr<detail::ImageBase>> parsed =
        make_error("Unknown or unsupported binary format");
    switch (fmt) {
        case Format::ELF:
            parsed = detail::parse_elf_image_impl(bytes);
            break;
        case Format::PE:
            parsed = detail::parse_pe_image_impl(bytes);
            break;
        case Format::MachO:
        case Format::Unknown:
            return make_error("Unknown or unsupported binary format");
    }
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    (*parsed)->attach_raw_bytes(bytes);
    return parsed;
}

[[nodiscard]] std::vector<std::uint8_t> normalize_mapped_macho_for_file_parsers(
    std::span<const std::uint8_t> mapped_bytes) {
    using detail::fits_range;
    using detail::rd32;
    using detail::rd64;
    using detail::wr32_endian;
    using detail::wr64_endian;

    std::vector<std::uint8_t> out(mapped_bytes.begin(), mapped_bytes.end());
    if (out.size() < 32u) {
        return out;
    }

    const std::uint32_t magic_be = rd32(out, 0u, true);
    bool is_64 = false;
    bool big_endian = false;
    if (magic_be == macho::kMhMagic64) {
        is_64 = true;
        big_endian = true;
    } else if (magic_be == macho::kMhCigam64) {
        is_64 = true;
        big_endian = false;
    } else if (magic_be == macho::kMhMagic) {
        is_64 = false;
        big_endian = true;
    } else if (magic_be == macho::kMhCigam) {
        is_64 = false;
        big_endian = false;
    } else {
        return out;
    }

    const std::size_t hdr_sz = is_64 ? 32u : 28u;
    const std::uint32_t ncmds = rd32(out, 16u, big_endian);
    const std::uint32_t sizeofcmds = rd32(out, 20u, big_endian);
    if (!fits_range(hdr_sz, sizeofcmds, static_cast<std::uint64_t>(out.size()))) {
        return out;
    }

    const std::size_t lc_end = hdr_sz + static_cast<std::size_t>(sizeofcmds);
    std::optional<std::uint64_t> base_vmaddr{};
    {
        std::optional<std::uint64_t> lowest_vmaddr{};
        std::size_t cur = hdr_sz;
        for (std::uint32_t i = 0u; i < ncmds && cur + 8u <= lc_end; ++i) {
            const std::uint32_t cmd = rd32(out, cur, big_endian);
            const std::uint32_t cmdsize = rd32(out, cur + 4u, big_endian);
            if (cmdsize < 8u || cur + cmdsize > lc_end) {
                break;
            }
            if ((cmd == macho::kLcSegment64 && cmdsize >= 72u) ||
                (cmd == macho::kLcSegment && cmdsize >= 56u)) {
                std::string_view segname(
                    reinterpret_cast<const char*>(out.data() + cur + 8u), 16u);
                const std::size_t nul = segname.find('\0');
                if (nul != std::string_view::npos) {
                    segname = segname.substr(0u, nul);
                }
                const std::uint64_t vmaddr = (cmd == macho::kLcSegment64)
                    ? rd64(out, cur + 24u, big_endian)
                    : static_cast<std::uint64_t>(rd32(out, cur + 24u, big_endian));
                const std::uint32_t maxprot = (cmd == macho::kLcSegment64)
                    ? rd32(out, cur + 56u, big_endian)
                    : rd32(out, cur + 40u, big_endian);
                const std::uint32_t initprot = (cmd == macho::kLcSegment64)
                    ? rd32(out, cur + 60u, big_endian)
                    : rd32(out, cur + 44u, big_endian);
                if (segname != "__PAGEZERO" && (initprot != 0u || maxprot != 0u)) {
                    if (segname == "__TEXT" && !base_vmaddr.has_value()) {
                        base_vmaddr = vmaddr;
                    }
                    if (!lowest_vmaddr.has_value() || vmaddr < *lowest_vmaddr) {
                        lowest_vmaddr = vmaddr;
                    }
                }
            }
            cur += cmdsize;
        }
        if (!base_vmaddr.has_value()) {
            base_vmaddr = lowest_vmaddr;
        }
    }
    if (!base_vmaddr.has_value()) {
        return out;
    }

    struct SegRemap {
        std::uint64_t orig_off{0};
        std::uint64_t orig_sz{0};
        std::uint64_t new_off{0};
        bool mapped{false};
    };
    std::vector<SegRemap> remaps;

    std::size_t cur = hdr_sz;
    for (std::uint32_t i = 0u; i < ncmds && cur + 8u <= lc_end; ++i) {
        const std::uint32_t cmd = rd32(out, cur, big_endian);
        const std::uint32_t cmdsize = rd32(out, cur + 4u, big_endian);
        if (cmdsize < 8u || cur + cmdsize > lc_end) {
            break;
        }
        if ((cmd == macho::kLcSegment64 && cmdsize >= 72u) ||
            (cmd == macho::kLcSegment && cmdsize >= 56u)) {
            const bool seg64 = (cmd == macho::kLcSegment64);
            std::string_view segname(
                reinterpret_cast<const char*>(out.data() + cur + 8u), 16u);
            const std::size_t nul = segname.find('\0');
            if (nul != std::string_view::npos) {
                segname = segname.substr(0u, nul);
            }
            if (segname != "__PAGEZERO") {
                const std::uint64_t vmaddr = seg64
                    ? rd64(out, cur + 24u, big_endian)
                    : static_cast<std::uint64_t>(rd32(out, cur + 24u, big_endian));
                const std::uint64_t vmsize = seg64
                    ? rd64(out, cur + 32u, big_endian)
                    : static_cast<std::uint64_t>(rd32(out, cur + 28u, big_endian));
                const std::uint64_t fileoff = seg64
                    ? rd64(out, cur + 40u, big_endian)
                    : static_cast<std::uint64_t>(rd32(out, cur + 32u, big_endian));
                const std::uint64_t filesize = seg64
                    ? rd64(out, cur + 48u, big_endian)
                    : static_cast<std::uint64_t>(rd32(out, cur + 36u, big_endian));
                const std::uint32_t nsects = seg64
                    ? rd32(out, cur + 64u, big_endian)
                    : rd32(out, cur + 48u, big_endian);

                if (vmaddr >= *base_vmaddr) {
                    const std::uint64_t rva = vmaddr - *base_vmaddr;
                    if (rva < out.size()) {
                        const std::uint64_t clamped = std::min<std::uint64_t>(
                            vmsize, static_cast<std::uint64_t>(out.size()) - rva);
                        remaps.push_back(SegRemap{
                            .orig_off = fileoff,
                            .orig_sz = filesize,
                            .new_off = rva,
                            .mapped = true,
                        });
                        if (seg64) {
                            wr64_endian(out, cur + 40u, rva, big_endian);
                            wr64_endian(out, cur + 48u, clamped, big_endian);
                        } else if (rva <= 0xFFFF'FFFFull && clamped <= 0xFFFF'FFFFull) {
                            wr32_endian(out, cur + 32u, static_cast<std::uint32_t>(rva), big_endian);
                            wr32_endian(out, cur + 36u, static_cast<std::uint32_t>(clamped), big_endian);
                        }

                        const std::size_t seg_hdr_sz = seg64 ? 72u : 56u;
                        const std::size_t sec_hdr_sz = seg64 ? 80u : 68u;
                        for (std::uint32_t s = 0u; s < nsects; ++s) {
                            const std::uint64_t sec_off64 =
                                static_cast<std::uint64_t>(cur) + seg_hdr_sz +
                                static_cast<std::uint64_t>(s) * sec_hdr_sz;
                            if (!fits_range(sec_off64, sec_hdr_sz, lc_end)) {
                                break;
                            }
                            const auto sec_off = static_cast<std::size_t>(sec_off64);
                            const std::uint64_t sec_va = seg64
                                ? rd64(out, sec_off + 32u, big_endian)
                                : static_cast<std::uint64_t>(rd32(out, sec_off + 32u, big_endian));
                            const std::uint32_t sec_file_off = seg64
                                ? rd32(out, sec_off + 48u, big_endian)
                                : rd32(out, sec_off + 40u, big_endian);
                            if (sec_file_off != 0u && sec_va >= *base_vmaddr) {
                                const std::uint64_t sec_rva = sec_va - *base_vmaddr;
                                if (sec_rva < out.size() && sec_rva <= 0xFFFF'FFFFull) {
                                    wr32_endian(out,
                                                sec_off + (seg64 ? 48u : 40u),
                                                static_cast<std::uint32_t>(sec_rva),
                                                big_endian);
                                }
                            }
                        }
                    } else if (!fits_range(fileoff, filesize, static_cast<std::uint64_t>(out.size()))) {
                        remaps.push_back(SegRemap{
                            .orig_off = fileoff,
                            .orig_sz = filesize,
                            .new_off = 0u,
                            .mapped = false,
                        });
                        if (seg64) {
                            wr64_endian(out, cur + 40u, 0u, big_endian);
                            wr64_endian(out, cur + 48u, 0u, big_endian);
                        } else {
                            wr32_endian(out, cur + 32u, 0u, big_endian);
                            wr32_endian(out, cur + 36u, 0u, big_endian);
                        }
                    }
                }
            }
        }
        cur += cmdsize;
    }

    auto remap_u32_off = [&](std::size_t field_off) {
        const std::uint32_t orig = rd32(out, field_off, big_endian);
        if (orig == 0u) {
            return;
        }
        for (const SegRemap& rm : remaps) {
            if (rm.orig_sz > 0u && orig >= rm.orig_off && orig < rm.orig_off + rm.orig_sz) {
                if (rm.mapped) {
                    const std::uint64_t mapped_off = rm.new_off + (orig - rm.orig_off);
                    if (mapped_off < out.size() && mapped_off <= 0xFFFF'FFFFull) {
                        wr32_endian(out, field_off, static_cast<std::uint32_t>(mapped_off), big_endian);
                    }
                } else {
                    wr32_endian(out, field_off, 0u, big_endian);
                }
                return;
            }
        }
    };

    cur = hdr_sz;
    for (std::uint32_t i = 0u; i < ncmds && cur + 8u <= lc_end; ++i) {
        const std::uint32_t cmd = rd32(out, cur, big_endian);
        const std::uint32_t cmdsize = rd32(out, cur + 4u, big_endian);
        if (cmdsize < 8u || cur + cmdsize > lc_end) {
            break;
        }
        if (cmd == macho::kLcSymtab && cmdsize >= 24u) {
            remap_u32_off(cur + 8u);
            remap_u32_off(cur + 16u);
        } else if ((cmd == macho::kLcCodeSignature || cmd == macho::kLcFunctionStarts ||
                    cmd == macho::kLcDataInCode || cmd == macho::kLcDyldExportsTrie ||
                    cmd == macho::kLcDyldChainedFixups) &&
                   cmdsize >= 16u) {
            remap_u32_off(cur + 8u);
        }
        cur += cmdsize;
    }

    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// IBinaryImage non-pure format defaults & container offset helpers
// ---------------------------------------------------------------------------
std::optional<std::uint64_t> IBinaryImage::slice_relative_offset(
    std::uint64_t container_file_offset) const noexcept {
    const std::uint64_t base = container_slice_offset();
    if (container_file_offset < base) {
        return std::nullopt;
    }
    const std::uint64_t rel = container_file_offset - base;
    const std::uint64_t sz = container_slice_size();
    if (sz != 0u && rel >= sz) {
        return std::nullopt;
    }
    return rel;
}

std::optional<std::uint64_t> IBinaryImage::container_file_offset(
    std::uint64_t slice_rel_offset) const noexcept {
    const std::uint64_t sz = container_slice_size();
    if (sz != 0u && slice_rel_offset >= sz) {
        return std::nullopt;
    }
    return detail::checked_add_u64(container_slice_offset(), slice_rel_offset);
}

const std::vector<PeDataDirectory>& IBinaryImage::pe_data_directories() const noexcept {
    static const std::vector<PeDataDirectory> empty;
    return empty;
}

const std::vector<PeBaseRelocationBlock>& IBinaryImage::pe_base_relocations() const noexcept {
    static const std::vector<PeBaseRelocationBlock> empty;
    return empty;
}

const std::vector<PeDebugDirectory>& IBinaryImage::pe_debug_directories() const noexcept {
    static const std::vector<PeDebugDirectory> empty;
    return empty;
}

const std::vector<PeCertificate>& IBinaryImage::pe_certificates() const noexcept {
    static const std::vector<PeCertificate> empty;
    return empty;
}

const std::vector<PeRuntimeFunction>& IBinaryImage::pe_runtime_functions() const noexcept {
    static const std::vector<PeRuntimeFunction> empty;
    return empty;
}

const std::vector<PeBoundImport>& IBinaryImage::pe_bound_imports() const noexcept {
    static const std::vector<PeBoundImport> empty;
    return empty;
}

const std::vector<PeResourceDataEntry>& IBinaryImage::pe_resource_data_entries() const noexcept {
    static const std::vector<PeResourceDataEntry> empty;
    return empty;
}

const std::vector<ElfProgramHeader>& IBinaryImage::elf_program_headers() const noexcept {
    static const std::vector<ElfProgramHeader> empty;
    return empty;
}

const std::vector<ElfSectionHeader>& IBinaryImage::elf_section_headers() const noexcept {
    static const std::vector<ElfSectionHeader> empty;
    return empty;
}

const std::vector<ElfSymbol>& IBinaryImage::elf_symbols() const noexcept {
    static const std::vector<ElfSymbol> empty;
    return empty;
}

const std::vector<ElfDynamicEntry>& IBinaryImage::elf_dynamic_entries() const noexcept {
    static const std::vector<ElfDynamicEntry> empty;
    return empty;
}

const std::vector<ElfRelocation>& IBinaryImage::elf_relocations() const noexcept {
    static const std::vector<ElfRelocation> empty;
    return empty;
}

const std::vector<ElfNote>& IBinaryImage::elf_notes() const noexcept {
    static const std::vector<ElfNote> empty;
    return empty;
}

const std::vector<ElfSysvHashTable>& IBinaryImage::elf_sysv_hash_tables() const noexcept {
    static const std::vector<ElfSysvHashTable> empty;
    return empty;
}

const std::vector<ElfGnuHashTable>& IBinaryImage::elf_gnu_hash_tables() const noexcept {
    static const std::vector<ElfGnuHashTable> empty;
    return empty;
}

const std::vector<MachOLoadCommandInfo>& IBinaryImage::macho_load_commands() const noexcept {
    static const std::vector<MachOLoadCommandInfo> empty;
    return empty;
}

const std::vector<MachOSegmentCommand>& IBinaryImage::macho_segments() const noexcept {
    static const std::vector<MachOSegmentCommand> empty;
    return empty;
}

const std::vector<MachOSection>& IBinaryImage::macho_sections() const noexcept {
    static const std::vector<MachOSection> empty;
    return empty;
}

const std::vector<MachOSymbol>& IBinaryImage::macho_symbols() const noexcept {
    static const std::vector<MachOSymbol> empty;
    return empty;
}

const std::vector<MachODylibDependency>& IBinaryImage::macho_dylibs() const noexcept {
    static const std::vector<MachODylibDependency> empty;
    return empty;
}

const std::vector<MachORpathEntry>& IBinaryImage::macho_rpaths() const noexcept {
    static const std::vector<MachORpathEntry> empty;
    return empty;
}

const std::vector<MachOBuildVersion>& IBinaryImage::macho_build_versions() const noexcept {
    static const std::vector<MachOBuildVersion> empty;
    return empty;
}

Result<std::vector<std::uint8_t>> IBinaryImage::read_bytes_at_offset(
    std::uint64_t /*file_offset*/,
    std::size_t /*size*/) const {
    return make_error("Raw image bytes are not retained by this binary image instance");
}

Result<std::vector<std::uint8_t>> IBinaryImage::read_bytes_at_va(
    std::uint64_t /*virtual_address*/,
    std::size_t /*size*/) const {
    return make_error("Raw image bytes are not retained by this binary image instance");
}

std::string_view to_string(Format f) noexcept {
    switch (f) {
        case Format::PE:      return "PE";
        case Format::ELF:     return "ELF";
        case Format::MachO:   return "Mach-O";
        case Format::Unknown: return "Unknown";
    }
    return "Unknown";
}

std::string_view to_string(ImageKind k) noexcept {
    switch (k) {
        case ImageKind::Executable:    return "Executable";
        case ImageKind::SharedLibrary: return "Shared library";
        case ImageKind::Object:        return "Object";
        case ImageKind::Core:          return "Core dump";
        case ImageKind::Unknown:       return "Unknown";
    }
    return "Unknown";
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
        case Architecture::Unknown:   return "Unknown";
    }
    return "Unknown";
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
    if (macho::is_valid_macho_or_universal(b)) {
        return Format::MachO;
    }
    return Format::Unknown;
}

Result<BinaryContainerInfo> inspect_binary_container(std::span<const std::uint8_t> bytes) {
    if (macho::has_macho_or_fat_magic_prefix(bytes)) {
        return MachOImage::inspect_container(bytes);
    }
    const Format fmt = detect_format(bytes);
    if (fmt == Format::MachO) {
        return MachOImage::inspect_container(bytes);
    }
    if (fmt == Format::PE || fmt == Format::ELF) {
        auto parsed = parse_pe_or_elf_base(fmt, bytes);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        const IBinaryImage& img = **parsed;
        BinaryContainerInfo info;
        info.format = fmt;
        info.is_universal_container = false;
        BinarySliceDescriptor slice;
        slice.slice_index = 0;
        slice.arch = img.architecture();
        slice.bitness = img.is_64bit() ? 64u : 32u;
        slice.endianness = img.endianness();
        slice.arch_name = std::string(to_string(img.architecture()));
        slice.container_offset = 0;
        slice.slice_size = static_cast<std::uint64_t>(bytes.size());
        slice.align_log2 = 0;
        info.slices.push_back(std::move(slice));
        return info;
    }
    return make_error("Unknown or unsupported binary format");
}

Result<std::unique_ptr<IBinaryImage>> open_binary_image(
    std::span<const std::uint8_t> bytes,
    const BinaryOpenOptions& options) {
    if (macho::has_macho_or_fat_magic_prefix(bytes)) {
        auto parsed = MachOImage::parse(bytes, options);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        return std::unique_ptr<IBinaryImage>(std::move(*parsed));
    }
    const Format fmt = detect_format(bytes);
    if (fmt == Format::MachO) {
        auto parsed = MachOImage::parse(bytes, options);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        return std::unique_ptr<IBinaryImage>(std::move(*parsed));
    }
    if (fmt == Format::PE || fmt == Format::ELF) {
        if (options.selected_slice_index.has_value() && *options.selected_slice_index != 0u) {
            return make_error("Selected slice index is out of range for non-Universal binary");
        }
        auto parsed = parse_pe_or_elf_base(fmt, bytes);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (options.preferred_architecture.has_value() &&
            (*parsed)->architecture() != *options.preferred_architecture) {
            return make_error("Binary does not match requested architecture");
        }
        if (!options.preferred_arch_name.empty() &&
            !iequals_ascii(to_string((*parsed)->architecture()), options.preferred_arch_name)) {
            return make_error("Binary does not match requested architecture name");
        }
        return std::unique_ptr<IBinaryImage>(std::move(*parsed));
    }
    return make_error("Unknown or unsupported binary format");
}

Result<std::unique_ptr<IBinaryImage>> parse_image(std::span<const std::uint8_t> bytes) {
    return open_binary_image(bytes, BinaryOpenOptions{});
}

Result<std::unique_ptr<IBinaryImage>> parse_image(
    std::span<const std::uint8_t> bytes,
    const BinaryOpenOptions& options) {
    return open_binary_image(bytes, options);
}

Result<std::unique_ptr<IBinaryImage>> parse_rebased_image(
    std::span<const std::uint8_t> file_bytes,
    std::uint64_t live_base) {
    const Format fmt = detect_format(file_bytes);
    if (fmt == Format::MachO) {
        auto parsed = MachOImage::parse(file_bytes);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        (*parsed)->rebase_to_live_base(live_base);
        return std::unique_ptr<IBinaryImage>(std::move(*parsed));
    }
    auto parsed = parse_pe_or_elf_base(fmt, file_bytes);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    (*parsed)->rebase_to_live_base(live_base);
    return std::unique_ptr<IBinaryImage>(std::move(*parsed));
}

Result<std::unique_ptr<IBinaryImage>> parse_mapped_image(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base) {
    switch (detect_format(mapped_bytes)) {
        case Format::ELF:
            return detail::parse_elf_mapped_image_impl(mapped_bytes, live_base);
        case Format::PE: {
            const std::vector<std::uint8_t> norm =
                normalize_mapped_pe_for_file_parsers(mapped_bytes, live_base);
            auto parsed = detail::parse_pe_image_impl(norm);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            (*parsed)->attach_raw_bytes(norm);
            (*parsed)->rebase_to_live_base(live_base);
            return std::unique_ptr<IBinaryImage>(std::move(*parsed));
        }
        case Format::MachO: {
            const std::vector<std::uint8_t> norm =
                normalize_mapped_macho_for_file_parsers(mapped_bytes);
            auto parsed = MachOImage::parse(norm);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            (*parsed)->rebase_to_live_base(live_base);
            return std::unique_ptr<IBinaryImage>(std::move(*parsed));
        }
        case Format::Unknown:
            return make_error("Unknown or unsupported mapped binary format");
    }
    return make_error("Unknown or unsupported mapped binary format");
}

} // namespace peelf
