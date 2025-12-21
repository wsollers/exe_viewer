#include <peelf/peelf.hpp>

#include <cstdint>

namespace peelf {

static std::uint16_t read_u16_le(std::span<const std::uint8_t> b, std::size_t off) {
    return static_cast<std::uint16_t>(b[off] | (static_cast<std::uint16_t>(b[off + 1]) << 8));
}

std::expected<FileInfo, Error> parse_elf_bytes(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 0x20) {
        return std::unexpected(Error{"ELF file too small"});
    }

    const std::uint8_t ei_class = bytes[4];
    const std::uint8_t ei_data  = bytes[5];

    if (ei_data != 1) {
        return std::unexpected(Error{"ELF big-endian not supported yet"});
    }

    const std::uint16_t e_type = read_u16_le(bytes, 0x10);
    const std::uint16_t e_machine = read_u16_le(bytes, 0x12);

    FileInfo info;
    info.kind = FileKind::ELF;
    info.summary = ElfSummary{
        .ei_class = ei_class,
        .ei_data = ei_data,
        .e_type = e_type,
        .e_machine = e_machine,
    };
    return info;
}

} // namespace peelf
