#include <peelf/binary_image.hpp>
#include <peelf/peelf.hpp>

namespace peelf {

Result<FileInfo> parse_elf_bytes(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 0x34u) {
        return make_error("ELF file too small");
    }
    if (!(bytes[0] == 0x7Fu && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F')) {
        return make_error("Missing ELF magic");
    }

    auto parsed = parse_image(bytes);
    if (!parsed.has_value()) {
        return std::unexpected(parsed.error());
    }
    const ElfHeader* hdr = (*parsed)->elf_header();
    if (hdr == nullptr) {
        return make_error("Not a valid ELF image");
    }

    FileInfo info{};
    info.kind = FileKind::ELF;
    info.summary = ElfSummary{
        .ei_class = hdr->elf_class,
        .ei_data = hdr->data_encoding,
        .e_type = hdr->type,
        .e_machine = hdr->machine,
    };
    return info;
}

}  // namespace peelf
