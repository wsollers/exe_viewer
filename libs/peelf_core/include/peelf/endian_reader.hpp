#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class AddressWidth : std::uint8_t {
    Bits32 = 32,
    Bits64 = 64,
};

[[nodiscard]] constexpr std::string_view to_string(AddressWidth width) noexcept {
    return width == AddressWidth::Bits64 ? "64-bit" : "32-bit";
}

struct TargetLayout {
    Architecture architecture{Architecture::Unknown};
    AddressWidth address_width{AddressWidth::Bits64};
    Endianness endianness{Endianness::Little};

    [[nodiscard]] constexpr std::size_t pointer_size() const noexcept {
        return address_width == AddressWidth::Bits64 ? 8u : 4u;
    }

    [[nodiscard]] constexpr bool is_64bit() const noexcept {
        return address_width == AddressWidth::Bits64;
    }

    [[nodiscard]] static TargetLayout from_image(const IBinaryImage& image) noexcept {
        return TargetLayout{
            .architecture = image.architecture(),
            .address_width = image.is_64bit() ? AddressWidth::Bits64 : AddressWidth::Bits32,
            .endianness = image.endianness(),
        };
    }

    [[nodiscard]] static constexpr TargetLayout from_arch(
        Architecture arch,
        bool is_64bit,
        Endianness endian = Endianness::Little) noexcept {
        return TargetLayout{
            .architecture = arch,
            .address_width = is_64bit ? AddressWidth::Bits64 : AddressWidth::Bits32,
            .endianness = endian,
        };
    }

    auto operator<=>(const TargetLayout&) const = default;
};

/// Bounds-checked, alignment-safe, endian-aware binary reader for 32/64-bit
/// big-endian and little-endian target memory and file buffers.
class EndianReader {
public:
    constexpr EndianReader(std::span<const std::uint8_t> bytes, TargetLayout layout) noexcept
        : bytes_(bytes), layout_(layout) {}

    constexpr EndianReader(std::span<const std::uint8_t> bytes,
                           Endianness endianness,
                           AddressWidth address_width = AddressWidth::Bits64) noexcept
        : bytes_(bytes),
          layout_{Architecture::Unknown, address_width, endianness} {}

    [[nodiscard]] constexpr std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return bytes_.size(); }
    [[nodiscard]] constexpr TargetLayout layout() const noexcept { return layout_; }
    [[nodiscard]] constexpr Endianness endianness() const noexcept { return layout_.endianness; }
    [[nodiscard]] constexpr AddressWidth address_width() const noexcept {
        return layout_.address_width;
    }
    [[nodiscard]] constexpr std::size_t pointer_size() const noexcept {
        return layout_.pointer_size();
    }

    [[nodiscard]] constexpr bool can_read(std::size_t offset, std::size_t count) const noexcept {
        return offset <= bytes_.size() && count <= (bytes_.size() - offset);
    }

    [[nodiscard]] Result<std::uint8_t> read_u8(std::size_t offset) const;
    [[nodiscard]] Result<std::int8_t> read_i8(std::size_t offset) const;
    [[nodiscard]] Result<std::uint16_t> read_u16(std::size_t offset) const;
    [[nodiscard]] Result<std::int16_t> read_i16(std::size_t offset) const;
    [[nodiscard]] Result<std::uint32_t> read_u32(std::size_t offset) const;
    [[nodiscard]] Result<std::int32_t> read_i32(std::size_t offset) const;
    [[nodiscard]] Result<std::uint64_t> read_u64(std::size_t offset) const;
    [[nodiscard]] Result<std::int64_t> read_i64(std::size_t offset) const;
    [[nodiscard]] Result<float> read_f32(std::size_t offset) const;
    [[nodiscard]] Result<double> read_f64(std::size_t offset) const;
    [[nodiscard]] Result<std::uint64_t> read_pointer(std::size_t offset) const;
    [[nodiscard]] Result<std::int64_t> read_signed_pointer(std::size_t offset) const;

    [[nodiscard]] Result<std::string> read_c_string(std::size_t offset,
                                                    std::size_t max_bytes = 4096) const;
    [[nodiscard]] Result<std::string> read_utf16_string(std::size_t offset,
                                                        std::size_t max_code_units = 2048) const;

private:
    std::span<const std::uint8_t> bytes_;
    TargetLayout layout_;
};

[[nodiscard]] std::vector<std::uint8_t> encode_u8(std::uint8_t value);
[[nodiscard]] std::vector<std::uint8_t> encode_i8(std::int8_t value);
[[nodiscard]] std::vector<std::uint8_t> encode_u16(std::uint16_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_i16(std::int16_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_u32(std::uint32_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_i32(std::int32_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_u64(std::uint64_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_i64(std::int64_t value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_f32(float value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_f64(double value, Endianness endianness);
[[nodiscard]] std::vector<std::uint8_t> encode_pointer(std::uint64_t value, TargetLayout layout);
[[nodiscard]] std::vector<std::uint8_t> encode_utf16(std::string_view utf8, Endianness endianness);

}  // namespace peelf
