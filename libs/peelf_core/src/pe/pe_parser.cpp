#include <peelf/peelf.hpp>

#include <cstdint>

namespace peelf {

static std::uint16_t read_u16_le(std::span<const std::uint8_t> b, std::size_t off) {
    return static_cast<std::uint16_t>(b[off] | (static_cast<std::uint16_t>(b[off + 1]) << 8));
}


static std::uint32_t read_u32_le(std::span<const std::uint8_t> b, std::size_t off) {
    return static_cast<std::uint32_t>(b[off] |
        (static_cast<std::uint32_t>(b[off + 1]) << 8) |
        (static_cast<std::uint32_t>(b[off + 2]) << 16) |
        (static_cast<std::uint32_t>(b[off + 3]) << 24));
}

std::expected<FileInfo, Error> parse_pe_bytes(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 0x40) {
        return std::unexpected(Error{"PE file too small for DOS header"});
    }
    if (!(bytes[0] == 'M' && bytes[1] == 'Z')) {
        return std::unexpected(Error{"Missing MZ header"});
    }

    const std::uint32_t e_lfanew = read_u32_le(bytes, 0x3C);
    if (e_lfanew + 4 + 20 > bytes.size()) {
        return std::unexpected(Error{"Invalid e_lfanew (out of range)"});
    }

    if (!(bytes[e_lfanew + 0] == 'P' && bytes[e_lfanew + 1] == 'E' &&
          bytes[e_lfanew + 2] == 0 && bytes[e_lfanew + 3] == 0)) {
        return std::unexpected(Error{"Missing PE signature"});
    }

    const std::size_t coff = e_lfanew + 4;
    const std::uint16_t machine = read_u16_le(bytes, coff + 0);
    const std::uint16_t number_of_sections = read_u16_le(bytes, coff + 2);
    const std::uint32_t time_date_stamp = read_u32_le(bytes, coff + 4);
    const std::uint16_t size_of_optional_header = read_u16_le(bytes, coff + 16);

    const std::size_t opt = coff + 20;
    if (opt + size_of_optional_header > bytes.size() || size_of_optional_header < 2) {
        return std::unexpected(Error{"Invalid optional header size"});
    }
    const std::uint16_t optional_magic = read_u16_le(bytes, opt + 0);

    FileInfo info;
    info.kind = FileKind::PE;
    info.summary = PeSummary{
        .machine = machine,
        .number_of_sections = number_of_sections,
        .time_date_stamp = time_date_stamp,
        .optional_magic = optional_magic,
    };
    return info;
}

} // namespace peelf
