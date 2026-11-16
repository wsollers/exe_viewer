#include "image_internal.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

namespace {

[[nodiscard]] Result<std::unique_ptr<detail::ImageBase>> parse_image_base(
    std::span<const std::uint8_t> bytes) {
    switch (detect_format(bytes)) {
        case Format::ELF: return detail::parse_elf_image_impl(bytes);
        case Format::PE:  return detail::parse_pe_image_impl(bytes);
        default:          return make_error("Unknown or unsupported binary format");
    }
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
    auto parsed = parse_image_base(bytes);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::unique_ptr<IBinaryImage>(std::move(*parsed));
}

Result<std::unique_ptr<IBinaryImage>> parse_rebased_image(
    std::span<const std::uint8_t> file_bytes,
    std::uint64_t live_base) {
    auto parsed = parse_image_base(file_bytes);
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
            (*parsed)->rebase_to_live_base(live_base);
            return std::unique_ptr<IBinaryImage>(std::move(*parsed));
        }
        default:
            return make_error("Unknown or unsupported mapped binary format");
    }
}

} // namespace peelf
