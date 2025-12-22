#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <source_location>

#include <pe/pe_definitions.h>
#include <elf/elf_definitions.h>


namespace peelf {

struct IByteReader {
    [[nodiscard]] std::uint8_t  read_u8 (std::span<const std::uint8_t>, std::size_t) const;
    [[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t>, std::size_t) const ;
    [[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t>, std::size_t) const;
    [[nodiscard]] std::uint64_t read_u64(std::span<const std::uint8_t>, std::size_t) const;
};

template<std::endian HostEndian, std::endian FileEndian>
struct byte_reader final : IByteReader {
private:
    static constexpr bool needs_swap = (HostEndian != FileEndian);

    template<typename T>
    static constexpr T convert(T v) noexcept {
        if constexpr (needs_swap)
            return std::byteswap(v);
        else
            return v;
    }

public:
    [[nodiscard]] std::uint8_t read_u8(std::span<const std::uint8_t> b, std::size_t off) const {
        return b[off];
    }

    [[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t> b, std::size_t off) const{
        std::uint16_t v;
        std::memcpy(&v, b.data() + off, sizeof(v));
        return convert(v);
    }

    [[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t> b, std::size_t off) const{
        std::uint32_t v;
        std::memcpy(&v, b.data() + off, sizeof(v));
        return convert(v);
    }

    [[nodiscard]] std::uint64_t read_u64(std::span<const std::uint8_t> b, std::size_t off) const{
        std::uint64_t v;
        std::memcpy(&v, b.data() + off, sizeof(v));
        return convert(v);
    }
};

inline std::unique_ptr<IByteReader> make_reader(std::endian file_endian) {
    if (file_endian == std::endian::little) {
        return std::make_unique<byte_reader<
            std::endian::native,
            std::endian::little
        >>();
    } else {
        return std::make_unique<byte_reader<
            std::endian::native,
            std::endian::big
        >>();
    }
}

enum class FileKind { Unknown, ELF, PE };

struct Error {
    std::string message;
    std::source_location location{};
};

struct FileInfo {
    FileKind kind{FileKind::Unknown};
    std::variant<std::monostate, ElfSummary, PeSummary> summary{};
};

//std::expected<FileInfo, Error> parse_file(const std::filesystem::path& path);
std::string_view to_string(FileKind k);

} // namespace peelf
