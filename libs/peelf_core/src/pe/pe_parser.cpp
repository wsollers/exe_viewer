#include <peelf/binary_image.hpp>
#include <peelf/peelf.hpp>

#include <cstdint>

namespace peelf {

namespace {

[[nodiscard]] std::uint16_t read_u16_le(std::span<const std::uint8_t> b, std::size_t off) noexcept {
    return static_cast<std::uint16_t>(b[off] | (static_cast<std::uint16_t>(b[off + 1u]) << 8u));
}

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> b, std::size_t off) noexcept {
    return static_cast<std::uint32_t>(b[off] |
        (static_cast<std::uint32_t>(b[off + 1u]) << 8u) |
        (static_cast<std::uint32_t>(b[off + 2u]) << 16u) |
        (static_cast<std::uint32_t>(b[off + 3u]) << 24u));
}

}  // namespace

Result<FileInfo> parse_pe_bytes(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 0x40u) {
        return make_error("PE file too small for DOS header");
    }
    if (!(bytes[0] == 'M' && bytes[1] == 'Z')) {
        return make_error("Missing MZ header");
    }

    const std::uint32_t e_lfanew = read_u32_le(bytes, 0x3Cu);
    // Use 64-bit arithmetic so e_lfanew values near UINT32_MAX (e.g. 0xFFFFFFF0) never wrap around.
    if (static_cast<std::uint64_t>(e_lfanew) + 24u > static_cast<std::uint64_t>(bytes.size())) {
        return make_error("Invalid e_lfanew (out of range)");
    }

    const auto sig_off = static_cast<std::size_t>(e_lfanew);
    if (!(bytes[sig_off + 0u] == 'P' && bytes[sig_off + 1u] == 'E' &&
          bytes[sig_off + 2u] == 0u && bytes[sig_off + 3u] == 0u)) {
        return make_error("Missing PE signature");
    }

    const std::size_t coff = sig_off + 4u;
    const std::uint16_t size_of_optional_header = read_u16_le(bytes, coff + 16u);
    const std::uint64_t opt_end =
        static_cast<std::uint64_t>(coff) + 20u + static_cast<std::uint64_t>(size_of_optional_header);
    if (size_of_optional_header < 2u || opt_end > static_cast<std::uint64_t>(bytes.size())) {
        return make_error("Invalid optional header size");
    }

    if (size_of_optional_header >= 32u) {
        auto parsed = parse_image(bytes);
        if (!parsed.has_value()) {
            return std::unexpected(parsed.error());
        }
        const PeHeader* hdr = (*parsed)->pe_header();
        if (hdr == nullptr) {
            return make_error("Not a valid PE image");
        }
        FileInfo info{};
        info.kind = FileKind::PE;
        info.summary = PeSummary{
            .machine = hdr->machine,
            .number_of_sections = hdr->number_of_sections,
            .time_date_stamp = hdr->time_date_stamp,
            .optional_magic = hdr->optional_magic,
        };
        return info;
    }

    // Minimal synthetic optional header (2 <= size_of_optional_header < 32): validate magic cleanly.
    const std::uint16_t optional_magic = read_u16_le(bytes, coff + 20u);
    if (optional_magic != 0x10bu && optional_magic != 0x20bu) {
        return make_error("Unsupported PE optional header magic");
    }

    FileInfo info{};
    info.kind = FileKind::PE;
    info.summary = PeSummary{
        .machine = read_u16_le(bytes, coff + 0u),
        .number_of_sections = read_u16_le(bytes, coff + 2u),
        .time_date_stamp = read_u32_le(bytes, coff + 4u),
        .optional_magic = optional_magic,
    };
    return info;
}

}  // namespace peelf
