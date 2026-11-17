#include <peelf/macho_image.hpp>

#include <peelf/endian_reader.hpp>

#include "image_internal.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

namespace {

struct ThinMagicInfo {
    bool valid   = false;
    bool is_64   = false;
    bool is_big  = false;
    std::uint32_t target_magic = 0;
};

struct FatHeaderKind {
    bool candidate = false;
    bool is_64     = false;
    bool is_big    = true;
};

[[nodiscard]] constexpr ThinMagicInfo classify_thin_magic(
    std::span<const std::uint8_t> bytes,
    std::uint64_t offset = 0) noexcept {
    if (!detail::fits_range(offset, 4u, static_cast<std::uint64_t>(bytes.size()))) {
        return {};
    }
    const auto idx = static_cast<std::size_t>(offset);
    const std::uint8_t b0 = bytes[idx + 0];
    const std::uint8_t b1 = bytes[idx + 1];
    const std::uint8_t b2 = bytes[idx + 2];
    const std::uint8_t b3 = bytes[idx + 3];

    if (b0 == 0xFEu && b1 == 0xEDu && b2 == 0xFAu && b3 == 0xCEu) {
        return ThinMagicInfo{true, false, true, macho::kMhMagic};
    }
    if (b0 == 0xCEu && b1 == 0xFAu && b2 == 0xEDu && b3 == 0xFEu) {
        return ThinMagicInfo{true, false, false, macho::kMhMagic};
    }
    if (b0 == 0xFEu && b1 == 0xEDu && b2 == 0xFAu && b3 == 0xCFu) {
        return ThinMagicInfo{true, true, true, macho::kMhMagic64};
    }
    if (b0 == 0xCFu && b1 == 0xFAu && b2 == 0xEDu && b3 == 0xFEu) {
        return ThinMagicInfo{true, true, false, macho::kMhMagic64};
    }
    return {};
}

[[nodiscard]] constexpr FatHeaderKind classify_fat_magic(
    std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 4u) {
        return {};
    }
    const std::uint8_t b0 = bytes[0];
    const std::uint8_t b1 = bytes[1];
    const std::uint8_t b2 = bytes[2];
    const std::uint8_t b3 = bytes[3];

    // Canonical big-endian Darwin Universal magics (0xCAFEBABE / 0xCAFEBABF).
    if (b0 == 0xCAu && b1 == 0xFEu && b2 == 0xBAu && b3 == 0xBEu) {
        return FatHeaderKind{true, false, true};
    }
    if (b0 == 0xCAu && b1 == 0xFEu && b2 == 0xBAu && b3 == 0xBFu) {
        return FatHeaderKind{true, true, true};
    }
    // Byte-swapped little-endian Universal magics (0xBEBAFECA / 0xBFBAFECA).
    if (b0 == 0xBEu && b1 == 0xBAu && b2 == 0xFEu && b3 == 0xCAu) {
        return FatHeaderKind{true, false, false};
    }
    if (b0 == 0xBFu && b1 == 0xBAu && b2 == 0xFEu && b3 == 0xCAu) {
        return FatHeaderKind{true, true, false};
    }
    return {};
}

[[nodiscard]] constexpr Architecture map_macho_cpu_to_arch(
    std::uint32_t cpu_type,
    bool is_64_header) noexcept {
    switch (cpu_type) {
        case macho::kCpuTypeX86:
            return Architecture::X86;
        case macho::kCpuTypeX86_64:
            return Architecture::X86_64;
        case macho::kCpuTypeArm:
            return Architecture::ARM;
        case macho::kCpuTypeArm64:
        case macho::kCpuTypeArm64_32:
            return Architecture::ARM64;
        case macho::kCpuTypePowerPC:
            return Architecture::PowerPC;
        case macho::kCpuTypePowerPC64:
            return Architecture::PowerPC64;
        case macho::kCpuTypeRiscV:
            return is_64_header ? Architecture::RISCV64 : Architecture::RISCV32;
        case macho::kCpuTypeRiscV64:
            return Architecture::RISCV64;
        default:
            return Architecture::Unknown;
    }
}

[[nodiscard]] std::string format_macho_arch_name(
    std::uint32_t cpu_type,
    std::uint32_t cpu_subtype,
    bool is_64_header) {
    const std::uint32_t sub = cpu_subtype & 0x00FFFFFFu;
    switch (cpu_type) {
        case macho::kCpuTypeX86:
            return "x86";
        case macho::kCpuTypeX86_64:
            return sub == macho::kCpuSubtypeX86_64H ? "x86_64h" : "x86_64";
        case macho::kCpuTypeArm:
            if (sub == 9u) return "armv7";
            if (sub == 11u) return "armv7s";
            if (sub == 12u) return "armv7k";
            return "arm";
        case macho::kCpuTypeArm64:
            return (sub & 0xFFu) == macho::kCpuSubtypeArm64e ? "arm64e" : "arm64";
        case macho::kCpuTypeArm64_32:
            return "arm64_32";
        case macho::kCpuTypePowerPC:
            return "ppc";
        case macho::kCpuTypePowerPC64:
            return "ppc64";
        case macho::kCpuTypeRiscV:
            return is_64_header ? "riscv64" : "riscv32";
        case macho::kCpuTypeRiscV64:
            return "riscv64";
        default:
            return std::format("cpu_0x{:X}", cpu_type);
    }
}

[[nodiscard]] constexpr ImageKind map_macho_filetype(std::uint32_t filetype) noexcept {
    switch (filetype) {
        case macho::kMhExecute:
        case macho::kMhPreload:
        case macho::kMhDylinker:
        case macho::kMhFileset:
            return ImageKind::Executable;
        case macho::kMhFvmlib:
        case macho::kMhDylib:
        case macho::kMhBundle:
        case macho::kMhDylibStub:
        case macho::kMhKextBundle:
            return ImageKind::SharedLibrary;
        case macho::kMhObject:
        case macho::kMhDsym:
            return ImageKind::Object;
        case macho::kMhCore:
            return ImageKind::Core;
        default:
            return ImageKind::Unknown;
    }
}

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] bool matches_arch_alias(const BinarySliceDescriptor& slice,
                                      std::string_view requested) {
    const std::string req = to_lower_ascii(requested);
    const std::string actual = to_lower_ascii(slice.arch_name);
    if (req == actual) {
        return true;
    }
    if ((req == "i386" || req == "x86") && slice.arch == Architecture::X86) {
        return true;
    }
    if ((req == "x86-64" || req == "x86_64" || req == "amd64") &&
        slice.arch == Architecture::X86_64) {
        return true;
    }
    if ((req == "aarch64" || req == "arm64") && slice.arch == Architecture::ARM64) {
        return true;
    }
    if ((req == "powerpc" || req == "ppc" || req == "ppc32") &&
        slice.arch == Architecture::PowerPC) {
        return true;
    }
    if ((req == "powerpc64" || req == "ppc64") && slice.arch == Architecture::PowerPC64) {
        return true;
    }
    if (req == "riscv" &&
        (slice.arch == Architecture::RISCV32 || slice.arch == Architecture::RISCV64)) {
        return true;
    }
    return false;
}

[[nodiscard]] std::string read_fixed_string16(std::span<const std::uint8_t> bytes,
                                              std::size_t offset) {
    std::string out;
    out.reserve(16u);
    for (std::size_t i = 0; i < 16u && (offset + i) < bytes.size(); ++i) {
        const std::uint8_t ch = bytes[offset + i];
        if (ch == 0u) {
            break;
        }
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

[[nodiscard]] std::optional<std::string> read_bounded_lc_string(
    std::span<const std::uint8_t> slice,
    std::size_t cmd_offset,
    std::uint32_t cmd_size,
    std::uint32_t str_rel_offset,
    std::uint32_t min_header_size) {
    if (str_rel_offset < min_header_size || str_rel_offset >= cmd_size) {
        return std::nullopt;
    }
    const std::size_t start = cmd_offset + static_cast<std::size_t>(str_rel_offset);
    const std::size_t end   = cmd_offset + static_cast<std::size_t>(cmd_size);
    if (start > slice.size() || end > slice.size()) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(end - start);
    for (std::size_t p = start; p < end; ++p) {
        if (slice[p] == 0u) {
            break;
        }
        out.push_back(static_cast<char>(slice[p]));
    }
    return out;
}

[[nodiscard]] std::string read_bounded_blob_cstring(
    std::span<const std::uint8_t> blob,
    std::uint32_t rel_offset) {
    if (rel_offset == 0u || rel_offset >= blob.size()) {
        return {};
    }
    std::string out;
    for (std::size_t p = static_cast<std::size_t>(rel_offset); p < blob.size(); ++p) {
        if (blob[p] == 0u) {
            break;
        }
        out.push_back(static_cast<char>(blob[p]));
    }
    return out;
}

struct RawFatSliceRange {
    std::uint32_t cpu_type    = 0;
    std::uint32_t cpu_subtype = 0;
    std::uint64_t offset      = 0;
    std::uint64_t size        = 0;
    std::uint32_t align_log2  = 0;
    ThinMagicInfo thin_magic{};
};

// Shared validator used by both noexcept detect_format() and Result-returning
// inspect_container(). Disambiguates Universal 0xCAFEBABE binaries from Java .class files.
[[nodiscard]] bool validate_universal_slices_noexcept(
    std::span<const std::uint8_t> bytes,
    std::array<RawFatSliceRange, macho::kMaxFatArchCount>& out_slices,
    std::uint32_t& out_count,
    const char** out_reason = nullptr) noexcept {
    out_count = 0u;
    const auto set_reason = [&](const char* msg) noexcept {
        if (out_reason != nullptr) {
            *out_reason = msg;
        }
    };

    const FatHeaderKind fat = classify_fat_magic(bytes);
    if (!fat.candidate) {
        set_reason("Missing Universal Mach-O magic");
        return false;
    }
    if (bytes.size() < 8u) {
        set_reason("Truncated Universal Mach-O header");
        return false;
    }

    const std::uint32_t nfat_arch = detail::rd32(bytes, 4u, fat.is_big);
    if (nfat_arch == 0u || nfat_arch > macho::kMaxFatArchCount) {
        if (bytes[0] == 0xCAu && bytes[1] == 0xFEu && bytes[2] == 0xBAu && bytes[3] == 0xBEu) {
            const std::uint16_t java_major = detail::rd16(bytes, 6u, true);
            if (java_major >= 44u) {
                set_reason("Rejected Java .class file sharing 0xCAFEBABE magic");
                return false;
            }
        }
        set_reason("Universal Mach-O nfat_arch must be in [1, 32]");
        return false;
    }

    const std::uint64_t entry_size = fat.is_64 ? 32u : 20u;
    const std::uint64_t table_bytes = static_cast<std::uint64_t>(nfat_arch) * entry_size;
    const std::uint64_t fat_header_end = 8u + table_bytes;
    if (!detail::fits_range(8u, table_bytes, static_cast<std::uint64_t>(bytes.size()))) {
        set_reason("Universal Mach-O fat_arch table exceeds file bounds");
        return false;
    }

    const auto total_size = static_cast<std::uint64_t>(bytes.size());
    for (std::uint32_t i = 0u; i < nfat_arch; ++i) {
        const auto ent_off = static_cast<std::size_t>(8u + static_cast<std::uint64_t>(i) * entry_size);
        RawFatSliceRange s{};
        s.cpu_type    = detail::rd32(bytes, ent_off + 0u, fat.is_big);
        s.cpu_subtype = detail::rd32(bytes, ent_off + 4u, fat.is_big);
        if (fat.is_64) {
            s.offset     = detail::rd64(bytes, ent_off + 8u, fat.is_big);
            s.size       = detail::rd64(bytes, ent_off + 16u, fat.is_big);
            s.align_log2 = detail::rd32(bytes, ent_off + 24u, fat.is_big);
        } else {
            s.offset     = detail::rd32(bytes, ent_off + 8u, fat.is_big);
            s.size       = detail::rd32(bytes, ent_off + 12u, fat.is_big);
            s.align_log2 = detail::rd32(bytes, ent_off + 16u, fat.is_big);
        }

        if (s.align_log2 > macho::kMaxFatAlignLog2) {
            set_reason("Universal Mach-O slice alignment exponent exceeds 30");
            return false;
        }
        if (s.offset < fat_header_end) {
            set_reason("Universal Mach-O slice overlaps fat_header table");
            return false;
        }
        if (!detail::fits_range(s.offset, s.size, total_size)) {
            set_reason("Universal Mach-O slice [offset, offset + size] exceeds container size");
            return false;
        }

        const ThinMagicInfo tm = classify_thin_magic(bytes, s.offset);
        const std::uint64_t min_thin_hdr = tm.is_64 ? 32u : 28u;
        if (!tm.valid || s.size < min_thin_hdr) {
            set_reason("Universal Mach-O slice does not start with a valid thin Mach-O header");
            return false;
        }
        s.thin_magic = tm;

        const std::uint64_t cur_end = s.offset + s.size;
        for (std::uint32_t prev = 0u; prev < i; ++prev) {
            const std::uint64_t prev_start = out_slices[prev].offset;
            const std::uint64_t prev_end   = prev_start + out_slices[prev].size;
            if (s.offset < prev_end && prev_start < cur_end) {
                set_reason("Universal Mach-O slices overlap in container file");
                return false;
            }
        }
        out_slices[i] = s;
    }

    out_count = nfat_arch;
    return true;
}

[[nodiscard]] BinarySliceDescriptor build_thin_slice_descriptor(
    std::span<const std::uint8_t> slice_bytes,
    std::size_t slice_index,
    std::uint64_t container_offset,
    std::uint32_t align_log2,
    const ThinMagicInfo& tm) {
    const std::uint32_t hdr_cpu_type    = detail::rd32(slice_bytes, 4u, tm.is_big);
    const std::uint32_t hdr_cpu_subtype = detail::rd32(slice_bytes, 8u, tm.is_big);

    BinarySliceDescriptor desc{};
    desc.slice_index      = slice_index;
    desc.cpu_type         = hdr_cpu_type;
    desc.cpu_subtype      = hdr_cpu_subtype;
    desc.arch             = map_macho_cpu_to_arch(hdr_cpu_type, tm.is_64);
    desc.bitness          = tm.is_64 ? 64u : 32u;
    desc.endianness       = tm.is_big ? Endianness::Big : Endianness::Little;
    desc.arch_name        = format_macho_arch_name(hdr_cpu_type, hdr_cpu_subtype, tm.is_64);
    desc.container_offset = container_offset;
    desc.slice_size       = static_cast<std::uint64_t>(slice_bytes.size());
    desc.align_log2       = align_log2;
    return desc;
}

[[nodiscard]] constexpr bool is_zerofill_section_type(std::uint8_t sec_type) noexcept {
    return sec_type == macho::kSZeroFill ||
           sec_type == macho::kSGbZeroFill ||
           sec_type == macho::kSThreadLocalZeroFill;
}

} // namespace

namespace macho {

bool has_macho_or_fat_magic_prefix(std::span<const std::uint8_t> bytes) noexcept {
    return classify_thin_magic(bytes).valid || classify_fat_magic(bytes).candidate;
}

bool is_valid_macho_or_universal(std::span<const std::uint8_t> bytes) noexcept {
    const ThinMagicInfo tm = classify_thin_magic(bytes);
    if (tm.valid) {
        const std::size_t min_hdr = tm.is_64 ? 32u : 28u;
        return bytes.size() >= min_hdr;
    }
    if (classify_fat_magic(bytes).candidate) {
        std::array<RawFatSliceRange, kMaxFatArchCount> slices{};
        std::uint32_t count = 0u;
        return validate_universal_slices_noexcept(bytes, slices, count);
    }
    return false;
}

std::string format_packed_version(std::uint32_t packed) {
    const std::uint32_t major = (packed >> 16u) & 0xFFFFu;
    const std::uint32_t minor = (packed >> 8u) & 0xFFu;
    const std::uint32_t patch = packed & 0xFFu;
    if (patch != 0u) {
        return std::format("{}.{}.{}", major, minor, patch);
    }
    return std::format("{}.{}", major, minor);
}

std::string_view platform_to_string(std::uint32_t platform) noexcept {
    switch (platform) {
        case kPlatformMacOS:        return "macOS";
        case kPlatformIOS:          return "iOS";
        case kPlatformTvOS:         return "tvOS";
        case kPlatformWatchOS:      return "watchOS";
        case kPlatformBridgeOS:     return "bridgeOS";
        case kPlatformMacCatalyst:  return "Mac Catalyst";
        case kPlatformIOSSimulator: return "iOS Simulator";
        case kPlatformVisionOS:     return "visionOS";
        default:                    return "unknown";
    }
}

} // namespace macho

void MachOImage::add_warning(std::string warning) {
    if (!warning.empty() && parse_warnings_.size() < 64u) {
        parse_warnings_.push_back(std::move(warning));
    }
}

Result<BinaryContainerInfo> MachOImage::inspect_container(std::span<const std::uint8_t> bytes) {
    const ThinMagicInfo tm = classify_thin_magic(bytes);
    if (tm.valid) {
        const std::size_t min_hdr = tm.is_64 ? 32u : 28u;
        if (bytes.size() < min_hdr) {
            return make_error("Mach-O: truncated thin mach_header");
        }
        BinaryContainerInfo info{};
        info.format = Format::MachO;
        info.is_universal_container = false;
        info.slices.push_back(build_thin_slice_descriptor(bytes, 0u, 0u, 0u, tm));
        return info;
    }

    if (classify_fat_magic(bytes).candidate) {
        std::array<RawFatSliceRange, macho::kMaxFatArchCount> raw_slices{};
        std::uint32_t count = 0u;
        const char* reason = "Invalid Universal Mach-O container";
        if (!validate_universal_slices_noexcept(bytes, raw_slices, count, &reason)) {
            return make_error(reason);
        }

        BinaryContainerInfo info{};
        info.format = Format::MachO;
        info.is_universal_container = true;
        info.slices.reserve(count);
        for (std::uint32_t i = 0u; i < count; ++i) {
            const RawFatSliceRange& rs = raw_slices[i];
            const auto slice_span = bytes.subspan(
                static_cast<std::size_t>(rs.offset),
                static_cast<std::size_t>(rs.size));
            BinarySliceDescriptor desc = build_thin_slice_descriptor(
                slice_span,
                static_cast<std::size_t>(i),
                rs.offset,
                rs.align_log2,
                rs.thin_magic);
            // Preserve the FAT directory's CPU metadata if consistent, while thin header provides truth.
            desc.cpu_type    = rs.cpu_type != 0u ? rs.cpu_type : desc.cpu_type;
            desc.cpu_subtype = rs.cpu_type != 0u ? rs.cpu_subtype : desc.cpu_subtype;
            desc.arch        = map_macho_cpu_to_arch(desc.cpu_type, rs.thin_magic.is_64);
            desc.arch_name   = format_macho_arch_name(
                desc.cpu_type, desc.cpu_subtype, rs.thin_magic.is_64);
            info.slices.push_back(std::move(desc));
        }
        return info;
    }

    return make_error("Mach-O: unrecognized magic signature");
}

Result<std::unique_ptr<MachOImage>> MachOImage::parse(
    std::span<const std::uint8_t> bytes,
    const BinaryOpenOptions& options) {
    const auto container = inspect_container(bytes);
    if (!container) {
        return std::unexpected(container.error());
    }
    if (container->slices.empty()) {
        return make_error("Mach-O: container has no slices");
    }

    std::size_t chosen_index = 0u;
    if (options.selected_slice_index.has_value()) {
        if (*options.selected_slice_index >= container->slices.size()) {
            return make_error(std::format(
                "Mach-O: selected slice index {} is out of range (container has {} slice(s))",
                *options.selected_slice_index, container->slices.size()));
        }
        chosen_index = *options.selected_slice_index;
    } else if (!options.preferred_arch_name.empty()) {
        bool found = false;
        for (std::size_t i = 0u; i < container->slices.size(); ++i) {
            if (matches_arch_alias(container->slices[i], options.preferred_arch_name)) {
                chosen_index = i;
                found = true;
                break;
            }
        }
        if (!found) {
            return make_error(std::format(
                "Mach-O: no slice matches preferred_arch_name '{}'",
                options.preferred_arch_name));
        }
    } else if (options.preferred_architecture.has_value()) {
        bool found = false;
        for (std::size_t i = 0u; i < container->slices.size(); ++i) {
            if (container->slices[i].arch == *options.preferred_architecture) {
                chosen_index = i;
                found = true;
                break;
            }
        }
        if (!found) {
            return make_error("Mach-O: no slice matches preferred_architecture");
        }
    } else {
        // Deterministic default slice selection: first slice with a recognized Architecture,
        // falling back to slice 0 when all slices carry custom/unknown CPU types.
        for (std::size_t i = 0u; i < container->slices.size(); ++i) {
            if (container->slices[i].arch != Architecture::Unknown) {
                chosen_index = i;
                break;
            }
        }
    }

    const BinarySliceDescriptor& chosen = container->slices[chosen_index];
    if (!detail::fits_range(
            chosen.container_offset,
            chosen.slice_size,
            static_cast<std::uint64_t>(bytes.size()))) {
        return make_error("Mach-O: selected slice range exceeds container buffer");
    }

    const auto slice_span = bytes.subspan(
        static_cast<std::size_t>(chosen.container_offset),
        static_cast<std::size_t>(chosen.slice_size));
    return parse_thin_slice(
        slice_span,
        chosen.container_offset,
        chosen.slice_index,
        container->is_universal_container);
}

Result<std::unique_ptr<MachOImage>> MachOImage::parse_thin_slice(
    std::span<const std::uint8_t> slice,
    std::uint64_t container_offset,
    std::size_t slice_index,
    bool is_universal) {
    const ThinMagicInfo tm = classify_thin_magic(slice);
    if (!tm.valid) {
        return make_error("Mach-O: invalid thin header magic");
    }

    const std::size_t hdr_size = tm.is_64 ? 32u : 28u;
    if (slice.size() < hdr_size) {
        return make_error("Mach-O: truncated mach_header");
    }

    const Endianness endian = tm.is_big ? Endianness::Big : Endianness::Little;
    const EndianReader reader(
        slice,
        endian,
        tm.is_64 ? AddressWidth::Bits64 : AddressWidth::Bits32);

    auto img = std::unique_ptr<MachOImage>(new MachOImage());
    img->is_universal_slice_ = is_universal;
    img->slice_index_        = slice_index;
    img->slice_offset_       = container_offset;
    img->slice_size_         = static_cast<std::uint64_t>(slice.size());
    img->slice_bytes_.assign(slice.begin(), slice.end());
    img->endian_             = endian;
    img->is_64_              = tm.is_64;

    img->header_.magic       = *reader.read_u32(0u);
    img->header_.cpu_type    = *reader.read_u32(4u);
    img->header_.cpu_subtype = *reader.read_u32(8u);
    img->header_.file_type   = *reader.read_u32(12u);
    img->header_.ncmds       = *reader.read_u32(16u);
    img->header_.sizeofcmds  = *reader.read_u32(20u);
    img->header_.flags       = *reader.read_u32(24u);
    img->header_.reserved    = tm.is_64 ? *reader.read_u32(28u) : 0u;
    img->header_.is_64bit    = tm.is_64;

    if (img->header_.cpu_type == macho::kCpuTypeArm64 &&
        (img->header_.cpu_subtype & 0xFFu) == macho::kCpuSubtypeArm64e) {
        img->header_.is_arm64e = true;
        img->header_.ptrauth_abi =
            (img->header_.cpu_subtype & macho::kCpuSubtypePtrAuthAbi) != 0u;
        img->header_.ptrauth_version =
            static_cast<std::uint8_t>((img->header_.cpu_subtype >> 24u) & 0x0Fu);
    }

    img->kind_ = map_macho_filetype(img->header_.file_type);
    img->arch_ = map_macho_cpu_to_arch(img->header_.cpu_type, tm.is_64);

    if (!detail::fits_range(
            static_cast<std::uint64_t>(hdr_size),
            static_cast<std::uint64_t>(img->header_.sizeofcmds),
            static_cast<std::uint64_t>(slice.size()))) {
        return make_error("Mach-O: sizeofcmds exceeds binary slice size");
    }
    if (img->header_.ncmds == 0u && img->header_.sizeofcmds != 0u) {
        img->add_warning("Mach-O: ncmds is 0 while sizeofcmds is non-zero");
    }

    const std::size_t cmds_end = hdr_size + static_cast<std::size_t>(img->header_.sizeofcmds);
    std::size_t cmd_off = hdr_size;
    std::uint16_t next_dylib_ordinal = 1u;
    std::optional<std::uint64_t> unixthread_entry{};

    img->load_commands_.reserve(std::min<std::size_t>(img->header_.ncmds, 256u));

    for (std::uint32_t cmd_idx = 0u; cmd_idx < img->header_.ncmds; ++cmd_idx) {
        if (cmd_off > cmds_end || (cmds_end - cmd_off) < 8u) {
            return make_error(std::format(
                "Mach-O: load command {} header truncated inside sizeofcmds", cmd_idx));
        }

        const std::uint32_t cmd     = *reader.read_u32(cmd_off + 0u);
        const std::uint32_t cmdsize = *reader.read_u32(cmd_off + 4u);
        if (cmdsize < 8u) {
            return make_error(std::format(
                "Mach-O: load command {} (0x{:X}) has invalid cmdsize {} (< 8)",
                cmd_idx, cmd, cmdsize));
        }
        if (static_cast<std::uint64_t>(cmdsize) > static_cast<std::uint64_t>(cmds_end - cmd_off)) {
            return make_error(std::format(
                "Mach-O: load command {} (0x{:X}) cmdsize {} exceeds remaining sizeofcmds ({})",
                cmd_idx, cmd, cmdsize, cmds_end - cmd_off));
        }

        const std::uint32_t expected_align = tm.is_64 ? 8u : 4u;
        if ((cmdsize % expected_align) != 0u) {
            img->add_warning(std::format(
                "Mach-O: load command {} (0x{:X}) cmdsize {} is not {}-byte aligned",
                cmd_idx, cmd, cmdsize, expected_align));
        }

        const auto container_cmd_off =
            detail::checked_add_u64(container_offset, static_cast<std::uint64_t>(cmd_off))
                .value_or(container_offset);
        img->load_commands_.push_back(MachOLoadCommandInfo{
            .cmd = cmd,
            .cmdsize = cmdsize,
            .slice_offset = static_cast<std::uint64_t>(cmd_off),
            .container_offset = container_cmd_off,
        });

        switch (cmd) {
            case macho::kLcSegment:
            case macho::kLcSegment64: {
                const bool seg64 = (cmd == macho::kLcSegment64);
                const std::uint64_t seg_hdr_sz = seg64 ? 72u : 56u;
                const std::uint64_t sec_hdr_sz = seg64 ? 80u : 68u;
                if (cmdsize < seg_hdr_sz) {
                    return make_error("Mach-O: truncated LC_SEGMENT(_64) command");
                }

                MachOSegmentCommand seg{};
                seg.name = read_fixed_string16(slice, cmd_off + 8u);
                if (seg64) {
                    seg.virtual_address   = *reader.read_u64(cmd_off + 24u);
                    seg.virtual_size      = *reader.read_u64(cmd_off + 32u);
                    seg.slice_file_offset = *reader.read_u64(cmd_off + 40u);
                    seg.file_size         = *reader.read_u64(cmd_off + 48u);
                    seg.maxprot           = *reader.read_u32(cmd_off + 56u);
                    seg.initprot          = *reader.read_u32(cmd_off + 60u);
                    seg.nsects            = *reader.read_u32(cmd_off + 64u);
                    seg.flags             = *reader.read_u32(cmd_off + 68u);
                } else {
                    seg.virtual_address   = *reader.read_u32(cmd_off + 24u);
                    seg.virtual_size      = *reader.read_u32(cmd_off + 28u);
                    seg.slice_file_offset = *reader.read_u32(cmd_off + 32u);
                    seg.file_size         = *reader.read_u32(cmd_off + 36u);
                    seg.maxprot           = *reader.read_u32(cmd_off + 40u);
                    seg.initprot          = *reader.read_u32(cmd_off + 44u);
                    seg.nsects            = *reader.read_u32(cmd_off + 48u);
                    seg.flags             = *reader.read_u32(cmd_off + 52u);
                }

                if (static_cast<std::uint64_t>(seg.nsects) >
                    (static_cast<std::uint64_t>(cmdsize) - seg_hdr_sz) / sec_hdr_sz) {
                    return make_error(std::format(
                        "Mach-O: segment '{}' nsects ({}) overflows cmdsize ({})",
                        seg.name, seg.nsects, cmdsize));
                }

                const auto abs_seg_off = detail::checked_add_u64(
                    container_offset, seg.slice_file_offset);
                if (!abs_seg_off.has_value()) {
                    return make_error("Mach-O: segment file offset overflows 64-bit container offset");
                }
                seg.file_offset = *abs_seg_off;

                if (seg.file_size > 0u &&
                    !detail::fits_range(seg.slice_file_offset, seg.file_size,
                                        static_cast<std::uint64_t>(slice.size()))) {
                    img->add_warning(std::format(
                        "Mach-O: segment '{}' file range [0x{:X}, +0x{:X}) exceeds slice size (0x{:X})",
                        seg.name, seg.slice_file_offset, seg.file_size, slice.size()));
                }

                if (seg.name == "__PAGEZERO") {
                    img->has_pagezero_ = true;
                    img->pagezero_size_ = std::max(img->pagezero_size_, seg.virtual_size);
                }
                if (seg.name == "__RESTRICT") {
                    img->has_restrict_segment_or_section_ = true;
                }

                seg.sections.reserve(seg.nsects);
                for (std::uint32_t s_idx = 0u; s_idx < seg.nsects; ++s_idx) {
                    const auto sec_off = static_cast<std::size_t>(
                        static_cast<std::uint64_t>(cmd_off) + seg_hdr_sz +
                        static_cast<std::uint64_t>(s_idx) * sec_hdr_sz);

                    MachOSection msec{};
                    msec.section_name = read_fixed_string16(slice, sec_off + 0u);
                    msec.segment_name = read_fixed_string16(slice, sec_off + 16u);
                    msec.full_name = msec.segment_name.empty()
                        ? msec.section_name
                        : std::format("{},{}", msec.segment_name, msec.section_name);

                    std::uint32_t raw_sec_offset = 0u;
                    if (seg64) {
                        msec.virtual_address = *reader.read_u64(sec_off + 32u);
                        msec.virtual_size    = *reader.read_u64(sec_off + 40u);
                        raw_sec_offset       = *reader.read_u32(sec_off + 48u);
                        msec.align_log2      = *reader.read_u32(sec_off + 52u);
                        msec.reloff          = *reader.read_u32(sec_off + 56u);
                        msec.nreloc          = *reader.read_u32(sec_off + 60u);
                        msec.flags           = *reader.read_u32(sec_off + 64u);
                        msec.reserved1       = *reader.read_u32(sec_off + 68u);
                        msec.reserved2       = *reader.read_u32(sec_off + 72u);
                        msec.reserved3       = *reader.read_u32(sec_off + 76u);
                    } else {
                        msec.virtual_address = *reader.read_u32(sec_off + 32u);
                        msec.virtual_size    = *reader.read_u32(sec_off + 36u);
                        raw_sec_offset       = *reader.read_u32(sec_off + 40u);
                        msec.align_log2      = *reader.read_u32(sec_off + 44u);
                        msec.reloff          = *reader.read_u32(sec_off + 48u);
                        msec.nreloc          = *reader.read_u32(sec_off + 52u);
                        msec.flags           = *reader.read_u32(sec_off + 56u);
                        msec.reserved1       = *reader.read_u32(sec_off + 60u);
                        msec.reserved2       = *reader.read_u32(sec_off + 64u);
                    }

                    msec.slice_file_offset = raw_sec_offset;
                    msec.is_zerofill = is_zerofill_section_type(msec.section_type());
                    if (msec.is_zerofill) {
                        msec.file_offset = 0u;
                        msec.file_size   = 0u;
                    } else {
                        msec.file_offset = detail::checked_add_u64(
                            container_offset, static_cast<std::uint64_t>(raw_sec_offset))
                            .value_or(0u);
                        msec.file_size = msec.virtual_size;
                        if (msec.file_size > 0u &&
                            !detail::fits_range(msec.slice_file_offset, msec.file_size,
                                                static_cast<std::uint64_t>(slice.size()))) {
                            img->add_warning(std::format(
                                "Mach-O: section '{}' file range [0x{:X}, +0x{:X}) exceeds slice size",
                                msec.full_name, msec.slice_file_offset, msec.file_size));
                        }
                    }

                    const bool has_instr_attr =
                        (msec.flags & (macho::kSAttrPureInstructions |
                                       macho::kSAttrSomeInstructions)) != 0u;
                    msec.readable   = seg.readable();
                    msec.writable   = seg.writable();
                    msec.executable = seg.executable() || has_instr_attr;

                    if (msec.segment_name == "__RESTRICT" || msec.section_name == "__restrict") {
                        img->has_restrict_segment_or_section_ = true;
                    }

                    img->sections_.push_back(Section{
                        .name            = msec.full_name,
                        .virtual_address = msec.virtual_address,
                        .virtual_size    = msec.virtual_size,
                        .file_offset     = msec.file_offset,
                        .file_size       = msec.file_size,
                        .raw_flags       = msec.flags,
                        .readable        = msec.readable,
                        .writable        = msec.writable,
                        .executable      = msec.executable,
                    });
                    img->macho_sections_.push_back(msec);
                    seg.sections.push_back(std::move(msec));
                }

                img->segments_.push_back(Segment{
                    .type            = cmd,
                    .virtual_address = seg.virtual_address,
                    .virtual_size    = seg.virtual_size,
                    .file_offset     = seg.file_offset,
                    .file_size       = seg.file_size,
                    .readable        = seg.readable(),
                    .writable        = seg.writable(),
                    .executable      = seg.executable(),
                });
                img->macho_segments_.push_back(std::move(seg));
                break;
            }

            case macho::kLcMain: {
                if (cmdsize < 24u) {
                    img->add_warning("Mach-O: truncated LC_MAIN command");
                    break;
                }
                img->has_lc_main_      = true;
                img->lc_main_entryoff_ = *reader.read_u64(cmd_off + 8u);
                break;
            }

            case macho::kLcUnixThread: {
                std::size_t cursor = cmd_off + 8u;
                const std::size_t lc_end = cmd_off + static_cast<std::size_t>(cmdsize);
                while (cursor + 8u <= lc_end) {
                    const std::uint32_t flavor = *reader.read_u32(cursor + 0u);
                    const std::uint32_t count  = *reader.read_u32(cursor + 4u);
                    const std::uint64_t state_bytes = static_cast<std::uint64_t>(count) * 4u;
                    const std::size_t state_off = cursor + 8u;
                    if (state_bytes > static_cast<std::uint64_t>(lc_end - state_off)) {
                        img->add_warning("Mach-O: truncated LC_UNIXTHREAD thread state");
                        break;
                    }

                    if (!unixthread_entry.has_value()) {
                        switch (img->header_.cpu_type) {
                            case macho::kCpuTypeX86_64:
                                if (flavor == 4u && state_bytes >= 136u) {
                                    unixthread_entry = *reader.read_u64(state_off + 128u);
                                }
                                break;
                            case macho::kCpuTypeX86:
                                if (flavor == 1u && state_bytes >= 44u) {
                                    unixthread_entry = *reader.read_u32(state_off + 40u);
                                }
                                break;
                            case macho::kCpuTypeArm64:
                            case macho::kCpuTypeArm64_32:
                                if (flavor == 6u && state_bytes >= 264u) {
                                    std::uint64_t pc = *reader.read_u64(state_off + 256u);
                                    if (img->header_.is_arm64e && (pc >> 48u) != 0u &&
                                        (pc >> 48u) != 0xFFFFu) {
                                        pc &= 0x0000FFFFFFFFFFFFULL;
                                    }
                                    unixthread_entry = pc;
                                }
                                break;
                            case macho::kCpuTypeArm:
                                if (flavor == 1u && state_bytes >= 64u) {
                                    unixthread_entry = *reader.read_u32(state_off + 60u);
                                }
                                break;
                            case macho::kCpuTypePowerPC:
                                if (flavor == 1u && state_bytes >= 4u) {
                                    unixthread_entry = *reader.read_u32(state_off + 0u);
                                }
                                break;
                            case macho::kCpuTypePowerPC64:
                                if (flavor == 5u && state_bytes >= 8u) {
                                    unixthread_entry = *reader.read_u64(state_off + 0u);
                                }
                                break;
                            default:
                                break;
                        }
                    }

                    cursor = state_off + static_cast<std::size_t>(state_bytes);
                }
                break;
            }

            case macho::kLcLoadDylib:
            case macho::kLcLoadWeakDylib:
            case macho::kLcReexportDylib:
            case macho::kLcLazyLoadDylib:
            case macho::kLcLoadUpwardDylib:
            case macho::kLcIdDylib: {
                if (cmdsize < 24u) {
                    img->add_warning("Mach-O: truncated dylib_command");
                    break;
                }
                const std::uint32_t name_off = *reader.read_u32(cmd_off + 8u);
                const auto name = read_bounded_lc_string(slice, cmd_off, cmdsize, name_off, 24u);
                if (!name.has_value()) {
                    img->add_warning("Mach-O: dylib_command name offset out of bounds");
                    break;
                }
                MachODylibDependency dep{};
                dep.cmd                   = cmd;
                dep.name                  = *name;
                dep.timestamp             = *reader.read_u32(cmd_off + 12u);
                dep.current_version       = *reader.read_u32(cmd_off + 16u);
                dep.compatibility_version = *reader.read_u32(cmd_off + 20u);
                dep.weak                  = (cmd == macho::kLcLoadWeakDylib);
                dep.reexport              = (cmd == macho::kLcReexportDylib);
                dep.lazy                  = (cmd == macho::kLcLazyLoadDylib);
                dep.upward                = (cmd == macho::kLcLoadUpwardDylib);

                if (cmd == macho::kLcIdDylib) {
                    dep.ordinal = 0u;
                    img->id_dylib_ = std::move(dep);
                } else {
                    dep.ordinal = next_dylib_ordinal;
                    if (next_dylib_ordinal < std::numeric_limits<std::uint16_t>::max()) {
                        ++next_dylib_ordinal;
                    }
                    img->dylibs_.push_back(std::move(dep));
                }
                break;
            }

            case macho::kLcRpath: {
                if (cmdsize < 12u) {
                    img->add_warning("Mach-O: truncated LC_RPATH command");
                    break;
                }
                const std::uint32_t path_off = *reader.read_u32(cmd_off + 8u);
                const auto path = read_bounded_lc_string(slice, cmd_off, cmdsize, path_off, 12u);
                if (!path.has_value()) {
                    img->add_warning("Mach-O: LC_RPATH path offset out of bounds");
                    break;
                }
                img->rpaths_.push_back(MachORpathEntry{
                    .path             = *path,
                    .slice_offset     = static_cast<std::uint64_t>(cmd_off),
                    .container_offset = container_cmd_off,
                });
                break;
            }

            case macho::kLcLoadDylinker:
            case macho::kLcIdDylinker: {
                if (cmdsize < 12u) {
                    img->add_warning("Mach-O: truncated LC_LOAD_DYLINKER command");
                    break;
                }
                const std::uint32_t name_off = *reader.read_u32(cmd_off + 8u);
                if (const auto name = read_bounded_lc_string(slice, cmd_off, cmdsize, name_off, 12u);
                    name.has_value()) {
                    img->dylinker_ = *name;
                } else {
                    img->add_warning("Mach-O: LC_LOAD_DYLINKER string offset out of bounds");
                }
                break;
            }

            case macho::kLcSymtab: {
                if (cmdsize < 24u) {
                    img->add_warning("Mach-O: truncated LC_SYMTAB command");
                    break;
                }
                img->symtab_.present = true;
                img->symtab_.symoff  = *reader.read_u32(cmd_off + 8u);
                img->symtab_.nsyms   = *reader.read_u32(cmd_off + 12u);
                img->symtab_.stroff  = *reader.read_u32(cmd_off + 16u);
                img->symtab_.strsize = *reader.read_u32(cmd_off + 20u);
                img->symtab_.container_symoff =
                    detail::checked_add_u64(container_offset, img->symtab_.symoff).value_or(0u);
                img->symtab_.container_stroff =
                    detail::checked_add_u64(container_offset, img->symtab_.stroff).value_or(0u);
                break;
            }

            case macho::kLcDysymtab: {
                if (cmdsize < 80u) {
                    img->add_warning("Mach-O: truncated LC_DYSYMTAB command");
                    break;
                }
                img->dysymtab_.present        = true;
                img->dysymtab_.ilocalsym      = *reader.read_u32(cmd_off + 8u);
                img->dysymtab_.nlocalsym      = *reader.read_u32(cmd_off + 12u);
                img->dysymtab_.iextdefsym     = *reader.read_u32(cmd_off + 16u);
                img->dysymtab_.nextdefsym     = *reader.read_u32(cmd_off + 20u);
                img->dysymtab_.iundefsym      = *reader.read_u32(cmd_off + 24u);
                img->dysymtab_.nundefsym      = *reader.read_u32(cmd_off + 28u);
                img->dysymtab_.indirectsymoff = *reader.read_u32(cmd_off + 56u);
                img->dysymtab_.nindirectsyms  = *reader.read_u32(cmd_off + 60u);
                img->dysymtab_.container_indirectsymoff =
                    detail::checked_add_u64(container_offset, img->dysymtab_.indirectsymoff)
                        .value_or(0u);
                break;
            }

            case macho::kLcUuid: {
                if (cmdsize < 24u) {
                    img->add_warning("Mach-O: truncated LC_UUID command");
                    break;
                }
                std::array<std::uint8_t, 16> raw_uuid{};
                std::copy_n(slice.data() + cmd_off + 8u, 16u, raw_uuid.data());
                img->uuid_ = raw_uuid;
                img->uuid_string_ = std::format(
                    "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-"
                    "{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    raw_uuid[0], raw_uuid[1], raw_uuid[2], raw_uuid[3],
                    raw_uuid[4], raw_uuid[5], raw_uuid[6], raw_uuid[7],
                    raw_uuid[8], raw_uuid[9], raw_uuid[10], raw_uuid[11],
                    raw_uuid[12], raw_uuid[13], raw_uuid[14], raw_uuid[15]);
                break;
            }

            case macho::kLcBuildVersion: {
                if (cmdsize < 24u) {
                    img->add_warning("Mach-O: truncated LC_BUILD_VERSION command");
                    break;
                }
                MachOBuildVersion bv{};
                bv.cmd                      = cmd;
                bv.platform                 = *reader.read_u32(cmd_off + 8u);
                bv.minos                    = *reader.read_u32(cmd_off + 12u);
                bv.sdk                      = *reader.read_u32(cmd_off + 16u);
                bv.from_version_min_command = false;
                const std::uint32_t ntools  = *reader.read_u32(cmd_off + 20u);
                const std::uint64_t max_tools = (static_cast<std::uint64_t>(cmdsize) - 24u) / 8u;
                if (static_cast<std::uint64_t>(ntools) > max_tools) {
                    img->add_warning("Mach-O: LC_BUILD_VERSION ntools exceeds cmdsize");
                }
                const auto safe_ntools = static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(ntools, max_tools));
                bv.tools.reserve(safe_ntools);
                for (std::uint32_t t = 0u; t < safe_ntools; ++t) {
                    const std::size_t toff = cmd_off + 24u + static_cast<std::size_t>(t) * 8u;
                    bv.tools.push_back(MachOBuildToolVersion{
                        .tool    = *reader.read_u32(toff + 0u),
                        .version = *reader.read_u32(toff + 4u),
                    });
                }
                img->build_versions_.push_back(std::move(bv));
                break;
            }

            case macho::kLcVersionMinMacosx:
            case macho::kLcVersionMinIphoneos:
            case macho::kLcVersionMinTvos:
            case macho::kLcVersionMinWatchos: {
                if (cmdsize < 16u) {
                    img->add_warning("Mach-O: truncated LC_VERSION_MIN_* command");
                    break;
                }
                MachOBuildVersion bv{};
                bv.cmd = cmd;
                bv.platform = (cmd == macho::kLcVersionMinMacosx)   ? macho::kPlatformMacOS
                            : (cmd == macho::kLcVersionMinIphoneos) ? macho::kPlatformIOS
                            : (cmd == macho::kLcVersionMinTvos)     ? macho::kPlatformTvOS
                                                                    : macho::kPlatformWatchOS;
                bv.minos                    = *reader.read_u32(cmd_off + 8u);
                bv.sdk                      = *reader.read_u32(cmd_off + 12u);
                bv.from_version_min_command = true;
                img->build_versions_.push_back(std::move(bv));
                break;
            }

            case macho::kLcSourceVersion: {
                if (cmdsize < 16u) {
                    img->add_warning("Mach-O: truncated LC_SOURCE_VERSION command");
                    break;
                }
                img->source_version_ = *reader.read_u64(cmd_off + 8u);
                break;
            }

            case macho::kLcEncryptionInfo:
            case macho::kLcEncryptionInfo64: {
                const bool enc64 = (cmd == macho::kLcEncryptionInfo64);
                const std::uint32_t min_sz = enc64 ? 24u : 20u;
                if (cmdsize < min_sz) {
                    img->add_warning("Mach-O: truncated LC_ENCRYPTION_INFO(_64) command");
                    break;
                }
                MachOEncryptionInfo enc{};
                enc.is_64bit  = enc64;
                enc.cryptoff  = *reader.read_u32(cmd_off + 8u);
                enc.cryptsize = *reader.read_u32(cmd_off + 12u);
                enc.cryptid   = *reader.read_u32(cmd_off + 16u);
                enc.pad       = enc64 ? *reader.read_u32(cmd_off + 20u) : 0u;
                enc.container_cryptoff =
                    detail::checked_add_u64(container_offset, enc.cryptoff).value_or(0u);
                img->encryption_info_ = enc;
                break;
            }

            case macho::kLcDyldInfo:
            case macho::kLcDyldInfoOnly: {
                if (cmdsize < 48u) {
                    img->add_warning("Mach-O: truncated LC_DYLD_INFO(_ONLY) command");
                    break;
                }
                img->has_any_dyld_metadata_        = true;
                img->dyld_info_.has_dyld_info      = true;
                img->dyld_info_.dyld_info_only     = (cmd == macho::kLcDyldInfoOnly);
                img->dyld_info_.rebase_off         = *reader.read_u32(cmd_off + 8u);
                img->dyld_info_.rebase_size        = *reader.read_u32(cmd_off + 12u);
                img->dyld_info_.bind_off           = *reader.read_u32(cmd_off + 16u);
                img->dyld_info_.bind_size          = *reader.read_u32(cmd_off + 20u);
                img->dyld_info_.weak_bind_off      = *reader.read_u32(cmd_off + 24u);
                img->dyld_info_.weak_bind_size     = *reader.read_u32(cmd_off + 28u);
                img->dyld_info_.lazy_bind_off      = *reader.read_u32(cmd_off + 32u);
                img->dyld_info_.lazy_bind_size     = *reader.read_u32(cmd_off + 36u);
                img->dyld_info_.export_off         = *reader.read_u32(cmd_off + 40u);
                img->dyld_info_.export_size        = *reader.read_u32(cmd_off + 44u);
                img->dyld_info_.container_rebase_off = detail::checked_add_u64(
                    container_offset, img->dyld_info_.rebase_off).value_or(0u);
                img->dyld_info_.container_bind_off = detail::checked_add_u64(
                    container_offset, img->dyld_info_.bind_off).value_or(0u);
                img->dyld_info_.container_weak_bind_off = detail::checked_add_u64(
                    container_offset, img->dyld_info_.weak_bind_off).value_or(0u);
                img->dyld_info_.container_lazy_bind_off = detail::checked_add_u64(
                    container_offset, img->dyld_info_.lazy_bind_off).value_or(0u);
                img->dyld_info_.container_export_off = detail::checked_add_u64(
                    container_offset, img->dyld_info_.export_off).value_or(0u);
                break;
            }

            case macho::kLcDyldExportsTrie:
            case macho::kLcDyldChainedFixups:
            case macho::kLcFunctionStarts:
            case macho::kLcDataInCode: {
                if (cmdsize < 16u) {
                    img->add_warning("Mach-O: truncated linkedit_data_command");
                    break;
                }
                const std::uint32_t dataoff  = *reader.read_u32(cmd_off + 8u);
                const std::uint32_t datasize = *reader.read_u32(cmd_off + 12u);
                MachOLinkeditRange range{
                    .present          = true,
                    .cmd              = cmd,
                    .slice_offset     = dataoff,
                    .container_offset = detail::checked_add_u64(container_offset, dataoff).value_or(0u),
                    .size             = datasize,
                };
                img->has_any_dyld_metadata_ = true;
                if (cmd == macho::kLcDyldExportsTrie) {
                    img->dyld_info_.exports_trie = range;
                } else if (cmd == macho::kLcDyldChainedFixups) {
                    img->dyld_info_.chained_fixups = range;
                } else if (cmd == macho::kLcFunctionStarts) {
                    img->dyld_info_.function_starts = range;
                } else {
                    img->dyld_info_.data_in_code = range;
                }
                break;
            }

            case macho::kLcCodeSignature: {
                if (cmdsize < 16u) {
                    img->add_warning("Mach-O: truncated LC_CODE_SIGNATURE command");
                    break;
                }
                const std::uint32_t dataoff  = *reader.read_u32(cmd_off + 8u);
                const std::uint32_t datasize = *reader.read_u32(cmd_off + 12u);
                img->code_signature_.present          = true;
                img->code_signature_.slice_offset     = dataoff;
                img->code_signature_.container_offset =
                    detail::checked_add_u64(container_offset, dataoff).value_or(0u);
                img->code_signature_.data_size        = datasize;
                img->code_signature_.cryptographically_verified = false;

                if (!detail::fits_range(dataoff, datasize,
                                        static_cast<std::uint64_t>(slice.size())) ||
                    datasize < 12u) {
                    img->add_warning("Mach-O: LC_CODE_SIGNATURE payload out of slice bounds");
                    break;
                }

                // Embedded code signature SuperBlob and all nested blobs are ALWAYS big-endian.
                const auto cs_span = slice.subspan(
                    static_cast<std::size_t>(dataoff),
                    static_cast<std::size_t>(datasize));
                const EndianReader cs_be(cs_span, Endianness::Big, AddressWidth::Bits64);
                const std::uint32_t sb_magic  = *cs_be.read_u32(0u);
                const std::uint32_t sb_length = *cs_be.read_u32(4u);
                const std::uint32_t sb_count  = *cs_be.read_u32(8u);

                img->code_signature_.superblob_magic  = sb_magic;
                img->code_signature_.superblob_length = sb_length;
                img->code_signature_.blob_count       = sb_count;

                if (sb_magic != macho::kCsMagicEmbeddedSignature ||
                    sb_length < 12u ||
                    sb_length > cs_span.size() ||
                    !detail::fits_range(12u, static_cast<std::uint64_t>(sb_count) * 8u, sb_length)) {
                    img->add_warning("Mach-O: malformed CS_SuperBlob header in LC_CODE_SIGNATURE");
                    break;
                }
                img->code_signature_.superblob_valid = true;

                for (std::uint32_t bi = 0u; bi < sb_count; ++bi) {
                    const std::size_t idx_off = 12u + static_cast<std::size_t>(bi) * 8u;
                    const std::uint32_t slot_type   = *cs_be.read_u32(idx_off + 0u);
                    const std::uint32_t blob_offset = *cs_be.read_u32(idx_off + 4u);
                    if (!detail::fits_range(blob_offset, 8u, sb_length)) {
                        img->add_warning("Mach-O: CS_BlobIndex offset out of SuperBlob bounds");
                        continue;
                    }
                    const std::uint32_t sub_magic = *cs_be.read_u32(blob_offset + 0u);
                    const std::uint32_t sub_len   = *cs_be.read_u32(blob_offset + 4u);
                    if (sub_len < 8u || !detail::fits_range(blob_offset, sub_len, sb_length)) {
                        img->add_warning("Mach-O: CodeSignature sub-blob exceeds SuperBlob bounds");
                        continue;
                    }

                    const auto sub_span = cs_span.subspan(
                        static_cast<std::size_t>(blob_offset),
                        static_cast<std::size_t>(sub_len));
                    const EndianReader sub_be(sub_span, Endianness::Big, AddressWidth::Bits64);

                    if ((slot_type == macho::kCsSlotCodeDirectory ||
                         (!img->code_signature_.has_code_directory &&
                          slot_type >= 0x1000u && slot_type <= 0x1005u)) &&
                        sub_magic == macho::kCsMagicCodeDirectory && sub_len >= 44u) {
                        img->code_signature_.has_code_directory = true;
                        img->code_signature_.cd_version      = *sub_be.read_u32(8u);
                        img->code_signature_.cd_flags        = *sub_be.read_u32(12u);
                        const std::uint32_t ident_off        = *sub_be.read_u32(20u);
                        img->code_signature_.n_special_slots = *sub_be.read_u32(24u);
                        img->code_signature_.n_code_slots    = *sub_be.read_u32(28u);
                        img->code_signature_.code_limit      = *sub_be.read_u32(32u);
                        img->code_signature_.hash_size       = *sub_be.read_u8(36u);
                        img->code_signature_.hash_type       = *sub_be.read_u8(37u);
                        img->code_signature_.platform        = *sub_be.read_u8(38u);
                        img->code_signature_.page_size_log2  = *sub_be.read_u8(39u);
                        img->code_signature_.identifier =
                            read_bounded_blob_cstring(sub_span, ident_off);
                        if (img->code_signature_.cd_version >= 0x20200u && sub_len >= 52u) {
                            const std::uint32_t team_off = *sub_be.read_u32(48u);
                            img->code_signature_.team_id =
                                read_bounded_blob_cstring(sub_span, team_off);
                        }
                    } else if (slot_type == macho::kCsSlotRequirements &&
                               sub_magic == macho::kCsMagicRequirements) {
                        img->code_signature_.has_requirements_blob = true;
                    } else if (slot_type == macho::kCsSlotEntitlements &&
                               sub_magic == macho::kCsMagicEmbeddedEntitlements) {
                        img->code_signature_.has_entitlements_blob = true;
                    } else if (slot_type == macho::kCsSlotDerEntitlements &&
                               sub_magic == macho::kCsMagicEmbeddedDerEntitlements) {
                        img->code_signature_.has_der_entitlements_blob = true;
                    } else if (slot_type == macho::kCsSlotSignatureSlot &&
                               sub_magic == macho::kCsMagicBlobWrapper) {
                        img->code_signature_.has_cms_blob               = true;
                        img->code_signature_.cms_blob_size              = sub_len;
                        img->code_signature_.cms_payload_size           = sub_len - 8u;
                        img->code_signature_.has_nonempty_cms_signature = (sub_len > 8u);
                    }
                }
                break;
            }

            default:
                break;
        }

        cmd_off += static_cast<std::size_t>(cmdsize);
    }

    // Resolve preferred image base (__TEXT segment VM address, else lowest mapped segment).
    std::optional<std::uint64_t> text_vmaddr{};
    std::optional<std::uint64_t> text_fileoff{};
    std::optional<std::uint64_t> lowest_mapped_vmaddr{};
    for (const MachOSegmentCommand& seg : img->macho_segments_) {
        if (seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u && seg.file_size == 0u)) {
            continue;
        }
        if (seg.name == "__TEXT" && !text_vmaddr.has_value()) {
            text_vmaddr  = seg.virtual_address;
            text_fileoff = seg.slice_file_offset;
        }
        if (!lowest_mapped_vmaddr.has_value() || seg.virtual_address < *lowest_mapped_vmaddr) {
            lowest_mapped_vmaddr = seg.virtual_address;
        }
    }
    img->image_base_ = text_vmaddr.value_or(lowest_mapped_vmaddr.value_or(0u));

    // Resolve entry point: LC_MAIN (__TEXT.vmaddr + entryoff - __TEXT.fileoff) with LC_UNIXTHREAD fallback.
    if (img->has_lc_main_) {
        const std::uint64_t base_va  = text_vmaddr.value_or(img->image_base_);
        const std::uint64_t base_off = text_fileoff.value_or(0u);
        if (img->lc_main_entryoff_ >= base_off) {
            img->entry_ = detail::checked_add_u64(base_va, img->lc_main_entryoff_ - base_off)
                              .value_or(0u);
        } else {
            img->add_warning("Mach-O: LC_MAIN entryoff precedes __TEXT fileoff");
        }
    } else if (unixthread_entry.has_value()) {
        img->has_unixthread_entry_ = true;
        img->entry_                = *unixthread_entry;
    }

    // Parse LC_SYMTAB nlist / nlist_64 after dylibs_ are complete so 2-level ordinals resolve.
    if (img->symtab_.present && img->symtab_.nsyms > 0u) {
        const std::uint64_t nlist_sz = tm.is_64 ? 16u : 12u;
        const std::uint64_t sym_bytes = static_cast<std::uint64_t>(img->symtab_.nsyms) * nlist_sz;
        const bool sym_in_bounds = detail::fits_range(
            img->symtab_.symoff, sym_bytes, static_cast<std::uint64_t>(slice.size()));
        const bool str_in_bounds = detail::fits_range(
            img->symtab_.stroff, img->symtab_.strsize, static_cast<std::uint64_t>(slice.size()));

        if (!sym_in_bounds) {
            img->add_warning(std::format(
                "Mach-O: LC_SYMTAB symbol table [0x{:X}, +0x{:X}) exceeds slice size (0x{:X})",
                img->symtab_.symoff, sym_bytes, slice.size()));
        }
        if (!str_in_bounds) {
            img->add_warning(std::format(
                "Mach-O: LC_SYMTAB string table [0x{:X}, +0x{:X}) exceeds slice size (0x{:X})",
                img->symtab_.stroff, img->symtab_.strsize, slice.size()));
        }

        if (sym_in_bounds) {
            const std::span<const std::uint8_t> strtab = str_in_bounds
                ? slice.subspan(
                      static_cast<std::size_t>(img->symtab_.stroff),
                      static_cast<std::size_t>(img->symtab_.strsize))
                : std::span<const std::uint8_t>{};

            constexpr std::uint32_t kMaxParsedSymbols = 500000u;
            const std::uint32_t sym_count = std::min(img->symtab_.nsyms, kMaxParsedSymbols);
            if (sym_count < img->symtab_.nsyms) {
                img->add_warning("Mach-O: LC_SYMTAB symbol count capped at 500000 entries");
            }

            img->macho_symbols_.reserve(sym_count);
            for (std::uint32_t si = 0u; si < sym_count; ++si) {
                const auto ent = static_cast<std::size_t>(
                    static_cast<std::uint64_t>(img->symtab_.symoff) +
                    static_cast<std::uint64_t>(si) * nlist_sz);

                MachOSymbol ms{};
                ms.string_offset = *reader.read_u32(ent + 0u);
                ms.n_type        = *reader.read_u8(ent + 4u);
                ms.n_sect        = *reader.read_u8(ent + 5u);
                ms.n_desc        = *reader.read_u16(ent + 6u);
                ms.value         = tm.is_64 ? *reader.read_u64(ent + 8u)
                                            : static_cast<std::uint64_t>(*reader.read_u32(ent + 8u));

                if (ms.string_offset != 0u) {
                    if (str_in_bounds && ms.string_offset < strtab.size()) {
                        ms.name = detail::read_c_string(strtab, ms.string_offset, 2048u);
                    } else if (str_in_bounds) {
                        img->add_warning(std::format(
                            "Mach-O: symbol {} n_strx (0x{:X}) exceeds strsize (0x{:X})",
                            si, ms.string_offset, img->symtab_.strsize));
                    }
                }

                ms.is_stab             = (ms.n_type & macho::kNStab) != 0u;
                ms.is_private_external = (ms.n_type & macho::kNPext) != 0u;
                ms.is_external         = (ms.n_type & macho::kNExt) != 0u;
                const auto type_bits   = static_cast<std::uint8_t>(ms.n_type & macho::kNType);
                ms.is_undefined        = !ms.is_stab &&
                    ((type_bits == macho::kNUndf && ms.value == 0u) || type_bits == macho::kNPbud);
                ms.is_weak_ref         = (ms.n_desc & macho::kNWeakRef) != 0u;
                ms.is_weak_def         = (ms.n_desc & macho::kNWeakDef) != 0u;
                ms.is_thumb            = (img->arch_ == Architecture::ARM) &&
                                         ((ms.n_desc & macho::kNArmThumbDef) != 0u);

                ms.library_ordinal = static_cast<std::uint8_t>((ms.n_desc >> 8u) & 0xFFu);
                if (ms.is_undefined) {
                    if (ms.library_ordinal >= 1u &&
                        ms.library_ordinal <= img->dylibs_.size()) {
                        ms.library_name = img->dylibs_[ms.library_ordinal - 1u].name;
                    } else if (ms.library_ordinal == 0xFEu) {
                        ms.library_name = "@dynamic_lookup";
                    } else if (ms.library_ordinal == 0xFFu) {
                        ms.library_name = "@executable";
                    }
                }

                if (!ms.is_stab && !ms.name.empty()) {
                    const std::uint8_t binding = ms.is_external
                        ? ((ms.is_weak_def || ms.is_weak_ref) ? 2u : 1u)
                        : 0u;
                    img->symbols_.push_back(Symbol{
                        .name            = ms.name,
                        .virtual_address = ms.value,
                        .size            = 0u,
                        .binding         = binding,
                        .type            = ms.n_type,
                        .section_index   = ms.n_sect,
                        .dynamic         = ms.is_undefined || ms.is_external,
                    });

                    if (ms.is_external && ms.is_undefined) {
                        img->imports_.push_back(ImportEntry{
                            .library           = ms.library_name,
                            .name              = ms.name,
                            .ordinal           = 0u,
                            .address           = 0u,
                            .import_by_ordinal = false,
                            .delay_load        = false,
                        });
                    } else if (ms.is_external && !ms.is_private_external &&
                               (type_bits == macho::kNSect ||
                                type_bits == macho::kNAbs ||
                                type_bits == macho::kNIndr)) {
                        img->exports_.push_back(ExportEntry{
                            .name            = ms.name,
                            .ordinal         = 0u,
                            .virtual_address = ms.value,
                            .forwarder       = {},
                        });
                    }
                }

                img->macho_symbols_.push_back(std::move(ms));
            }
        }
    }

    return img;
}

std::uint64_t MachOImage::normalize_virtual_address(std::uint64_t va) const noexcept {
    if (!header_.is_arm64e || (va >> 48u) == 0u || (va >> 48u) == 0xFFFFu) {
        return va;
    }
    for (const MachOSegmentCommand& seg : macho_segments_) {
        if (!seg.is_pagezero() && va >= seg.virtual_address &&
            (va - seg.virtual_address) < seg.virtual_size) {
            return va;
        }
    }
    const std::uint64_t stripped = va & 0x0000FFFFFFFFFFFFULL;
    for (const MachOSegmentCommand& seg : macho_segments_) {
        if (!seg.is_pagezero() && stripped >= seg.virtual_address &&
            (stripped - seg.virtual_address) < seg.virtual_size) {
            return stripped;
        }
    }
    return va;
}

std::optional<std::uint64_t> MachOImage::file_offset_to_virtual_address(
    std::uint64_t file_offset) const noexcept {
    if (file_offset < slice_offset_) {
        return std::nullopt;
    }
    const std::uint64_t rel = file_offset - slice_offset_;
    if (rel >= slice_size_) {
        return std::nullopt;
    }

    for (const MachOSection& sec : macho_sections_) {
        if (sec.is_zerofill || sec.file_size == 0u) {
            continue;
        }
        if (file_offset >= sec.file_offset &&
            (file_offset - sec.file_offset) < std::min(sec.file_size, sec.virtual_size)) {
            return detail::checked_add_u64(sec.virtual_address, file_offset - sec.file_offset);
        }
    }

    for (const MachOSegmentCommand& seg : macho_segments_) {
        if (seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u)) {
            continue;
        }
        if (file_offset >= seg.file_offset &&
            (file_offset - seg.file_offset) < std::min(seg.file_size, seg.virtual_size)) {
            return detail::checked_add_u64(seg.virtual_address, file_offset - seg.file_offset);
        }
    }

    return std::nullopt;
}

std::optional<std::uint64_t> MachOImage::virtual_address_to_file_offset(
    std::uint64_t virtual_address) const noexcept {
    const std::uint64_t va = normalize_virtual_address(virtual_address);

    for (const MachOSegmentCommand& seg : macho_segments_) {
        if (seg.is_pagezero() && va >= seg.virtual_address &&
            (va - seg.virtual_address) < seg.virtual_size) {
            return std::nullopt;
        }
    }

    for (const MachOSection& sec : macho_sections_) {
        if (sec.virtual_size == 0u || va < sec.virtual_address) {
            continue;
        }
        const std::uint64_t delta = va - sec.virtual_address;
        if (delta >= sec.virtual_size) {
            continue;
        }
        if (sec.is_zerofill || delta >= sec.file_size) {
            return std::nullopt;
        }
        const auto rel_off = detail::checked_add_u64(sec.slice_file_offset, delta);
        if (!rel_off.has_value() || *rel_off >= slice_size_) {
            return std::nullopt;
        }
        return detail::checked_add_u64(sec.file_offset, delta);
    }

    for (const MachOSegmentCommand& seg : macho_segments_) {
        if (seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u)) {
            continue;
        }
        if (va < seg.virtual_address) {
            continue;
        }
        const std::uint64_t delta = va - seg.virtual_address;
        if (delta >= seg.virtual_size || delta >= seg.file_size) {
            continue;
        }
        const auto rel_off = detail::checked_add_u64(seg.slice_file_offset, delta);
        if (!rel_off.has_value() || *rel_off >= slice_size_) {
            return std::nullopt;
        }
        return detail::checked_add_u64(seg.file_offset, delta);
    }

    return std::nullopt;
}

Result<std::vector<std::uint8_t>> MachOImage::read_bytes_at_offset(
    std::uint64_t file_offset,
    std::size_t size) const {
    if (file_offset < slice_offset_) {
        return make_error("Mach-O: file offset precedes selected Universal slice");
    }
    const std::uint64_t rel = file_offset - slice_offset_;
    if (!detail::fits_range(
            rel, static_cast<std::uint64_t>(size),
            static_cast<std::uint64_t>(slice_bytes_.size()))) {
        return make_error("Mach-O: requested byte range exceeds slice bounds");
    }
    if (size == 0u) {
        return std::vector<std::uint8_t>{};
    }
    const auto begin_idx = static_cast<std::size_t>(rel);
    return std::vector<std::uint8_t>(
        slice_bytes_.begin() + static_cast<std::ptrdiff_t>(begin_idx),
        slice_bytes_.begin() + static_cast<std::ptrdiff_t>(begin_idx + size));
}

Result<std::vector<std::uint8_t>> MachOImage::read_bytes_at_va(
    std::uint64_t virtual_address,
    std::size_t size) const {
    constexpr std::size_t kMaxVaReadBytes = 64u * 1024u * 1024u;
    if (size > kMaxVaReadBytes) {
        return make_error("Mach-O: requested virtual-address read exceeds maximum single-read size");
    }

    const std::uint64_t start_va = normalize_virtual_address(virtual_address);
    if (!detail::checked_add_u64(start_va, static_cast<std::uint64_t>(size)).has_value()) {
        return make_error("Mach-O: virtual-address range overflows 64-bit address space");
    }

    const auto is_va_mapped = [&](std::uint64_t va) noexcept {
        for (const MachOSegmentCommand& seg : macho_segments_) {
            if (seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u)) {
                if (va >= seg.virtual_address && (va - seg.virtual_address) < seg.virtual_size) {
                    return false;
                }
                continue;
            }
            if (va >= seg.virtual_address && (va - seg.virtual_address) < seg.virtual_size) {
                return true;
            }
        }
        for (const MachOSection& sec : macho_sections_) {
            if (va >= sec.virtual_address && (va - sec.virtual_address) < sec.virtual_size) {
                return true;
            }
        }
        return false;
    };

    if (size == 0u) {
        if (is_va_mapped(start_va)) {
            return std::vector<std::uint8_t>{};
        }
        return make_error("Mach-O: virtual address is unmapped or inside __PAGEZERO");
    }

    std::vector<std::uint8_t> out(size, 0u);
    std::size_t written = 0u;

    while (written < size) {
        const std::uint64_t cur_va    = start_va + static_cast<std::uint64_t>(written);
        const std::uint64_t remaining = static_cast<std::uint64_t>(size - written);

        for (const MachOSegmentCommand& seg : macho_segments_) {
            if ((seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u)) &&
                cur_va >= seg.virtual_address &&
                (cur_va - seg.virtual_address) < seg.virtual_size) {
                return make_error("Mach-O: virtual address falls inside unmapped __PAGEZERO segment");
            }
        }

        bool advanced = false;
        for (const MachOSection& sec : macho_sections_) {
            if (sec.virtual_size == 0u || cur_va < sec.virtual_address) {
                continue;
            }
            const std::uint64_t delta = cur_va - sec.virtual_address;
            if (delta >= sec.virtual_size) {
                continue;
            }
            const std::uint64_t chunk = std::min(remaining, sec.virtual_size - delta);
            if (sec.is_zerofill) {
                // Zero-fill section (S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL):
                // `out` is already zero-initialized; advance without file backing.
                written += static_cast<std::size_t>(chunk);
            } else {
                const auto rel_off = detail::checked_add_u64(sec.slice_file_offset, delta);
                if (!rel_off.has_value() ||
                    !detail::fits_range(*rel_off, chunk,
                                        static_cast<std::uint64_t>(slice_bytes_.size()))) {
                    return make_error("Mach-O: section file backing is truncated");
                }
                const auto src_idx = static_cast<std::size_t>(*rel_off);
                const auto n = static_cast<std::size_t>(chunk);
                std::copy_n(slice_bytes_.data() + src_idx, n, out.data() + written);
                written += n;
            }
            advanced = true;
            break;
        }

        if (!advanced) {
            for (const MachOSegmentCommand& seg : macho_segments_) {
                if (seg.is_pagezero() || (seg.initprot == 0u && seg.maxprot == 0u) ||
                    seg.virtual_size == 0u || cur_va < seg.virtual_address) {
                    continue;
                }
                const std::uint64_t delta = cur_va - seg.virtual_address;
                if (delta >= seg.virtual_size) {
                    continue;
                }
                if (delta < seg.file_size) {
                    const std::uint64_t chunk = std::min(remaining, seg.file_size - delta);
                    const auto rel_off = detail::checked_add_u64(seg.slice_file_offset, delta);
                    if (!rel_off.has_value() ||
                        !detail::fits_range(*rel_off, chunk,
                                            static_cast<std::uint64_t>(slice_bytes_.size()))) {
                        return make_error("Mach-O: segment file backing is truncated");
                    }
                    const auto src_idx = static_cast<std::size_t>(*rel_off);
                    const auto n = static_cast<std::size_t>(chunk);
                    std::copy_n(slice_bytes_.data() + src_idx, n, out.data() + written);
                    written += n;
                } else {
                    const std::uint64_t chunk = std::min(remaining, seg.virtual_size - delta);
                    written += static_cast<std::size_t>(chunk);
                }
                advanced = true;
                break;
            }
        }

        if (!advanced) {
            return make_error("Mach-O: virtual address range is not mapped");
        }
    }

    return out;
}

void MachOImage::rebase_to_live_base(std::uint64_t live_base) noexcept {
    if (live_base == image_base_) {
        return;
    }
    const std::uint64_t slide = live_base - image_base_;
    image_base_ = live_base;
    if (entry_ != 0u) {
        entry_ += slide;
    }
    for (std::size_t i = 0u; i < macho_segments_.size(); ++i) {
        MachOSegmentCommand& mseg = macho_segments_[i];
        if (mseg.is_pagezero()) {
            continue;
        }
        mseg.virtual_address += slide;
        if (i < segments_.size()) {
            segments_[i].virtual_address += slide;
        }
        for (MachOSection& s : mseg.sections) {
            s.virtual_address += slide;
        }
    }
    for (MachOSection& msec : macho_sections_) {
        msec.virtual_address += slide;
    }
    for (Section& sec : sections_) {
        sec.virtual_address += slide;
    }
    for (MachOSymbol& msym : macho_symbols_) {
        if (!msym.is_stab && (msym.n_type & macho::kNType) == macho::kNSect && msym.value != 0u) {
            msym.value += slide;
        }
    }
    for (Symbol& sym : symbols_) {
        if ((sym.type & macho::kNType) == macho::kNSect && sym.virtual_address != 0u) {
            sym.virtual_address += slide;
        }
    }
    for (ExportEntry& exp : exports_) {
        if (exp.virtual_address != 0u) {
            exp.virtual_address += slide;
        }
    }
}

} // namespace peelf
