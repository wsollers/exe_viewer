#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace peelf {

enum class AddressWidth : std::uint8_t {
    Bits32 = 32,
    Bits64 = 64,
};

[[nodiscard]] constexpr std::string_view to_string(AddressWidth width) noexcept {
    return width == AddressWidth::Bits64 ? "64-bit" : "32-bit";
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        return std::nullopt;
    }
    return a + b;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_mul_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    if (a != 0u && b > std::numeric_limits<std::uint64_t>::max() / a) {
        return std::nullopt;
    }
    return a * b;
}

/// Returns `|value|` as `std::uint64_t` with zero `INT64_MIN` negation UB.
[[nodiscard]] constexpr std::uint64_t unsigned_magnitude_of_signed(
    std::int64_t value) noexcept {
    return value < 0
               ? (std::uint64_t{0} - static_cast<std::uint64_t>(value))
               : static_cast<std::uint64_t>(value);
}

/// Applies signed `displacement` to unsigned `base` without signed-overflow UB.
/// Returns `std::nullopt` if the target underflows `0` or exceeds `width`.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_apply_signed_displacement(
    std::uint64_t base,
    std::int64_t displacement,
    AddressWidth width = AddressWidth::Bits64) noexcept {
    const std::uint64_t max_addr = (width == AddressWidth::Bits32)
                                       ? std::uint64_t{0xFFFF'FFFFu}
                                       : std::numeric_limits<std::uint64_t>::max();
    if (base > max_addr) {
        return std::nullopt;
    }
    if (displacement >= 0) {
        const auto mag = static_cast<std::uint64_t>(displacement);
        if (mag > max_addr - base) {
            return std::nullopt;
        }
        return base + mag;
    }
    const auto mag = unsigned_magnitude_of_signed(displacement);
    if (mag > base) {
        return std::nullopt;
    }
    return base - mag;
}

/// Computes `value * 2^shift` in `std::int64_t` without signed-shift UB.
[[nodiscard]] constexpr std::optional<std::int64_t> checked_scale_signed_displacement(
    std::int64_t value,
    unsigned shift) noexcept {
    if (shift == 0u) {
        return value;
    }
    if (shift >= 64u) {
        return value == 0 ? std::optional<std::int64_t>{0} : std::nullopt;
    }
    if (value >= 0) {
        const auto u = static_cast<std::uint64_t>(value);
        const std::uint64_t max_u =
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) >> shift;
        if (u > max_u) {
            return std::nullopt;
        }
        return static_cast<std::int64_t>(u << shift);
    }
    const std::uint64_t mag = unsigned_magnitude_of_signed(value);
    constexpr std::uint64_t kMaxNegMag =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL;
    if (mag > (kMaxNegMag >> shift)) {
        return std::nullopt;
    }
    const std::uint64_t scaled_mag = mag << shift;
    if (scaled_mag == kMaxNegMag) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(scaled_mag);
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

    template <class R>
        requires (!std::is_lvalue_reference_v<R> &&
                  !std::same_as<std::remove_cvref_t<R>, EndianReader> &&
                  !std::ranges::borrowed_range<std::remove_cvref_t<R>> &&
                  std::convertible_to<R&&, std::span<const std::uint8_t>>)
    EndianReader(R&&, TargetLayout) = delete;

    template <class R>
        requires (!std::is_lvalue_reference_v<R> &&
                  !std::same_as<std::remove_cvref_t<R>, EndianReader> &&
                  !std::ranges::borrowed_range<std::remove_cvref_t<R>> &&
                  std::convertible_to<R&&, std::span<const std::uint8_t>>)
    EndianReader(R&&, Endianness, AddressWidth = AddressWidth::Bits64) = delete;

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

struct Utf16DecodeDiagnostics {
    bool odd_trailing_byte = false;
    std::size_t unpaired_high_surrogates = 0;
    std::size_t unpaired_low_surrogates = 0;
    bool truncated_at_max_units = false;

    [[nodiscard]] constexpr bool had_errors() const noexcept {
        return odd_trailing_byte ||
               unpaired_high_surrogates > 0 ||
               unpaired_low_surrogates > 0;
    }
};

/// Appends a single Unicode scalar value (`U+0000..U+10FFFF`, excluding
/// UTF-16 surrogates) as valid UTF-8, replacing out-of-range or surrogate
/// values with `U+FFFD` (`\xEF\xBF\xBD`).
void append_utf8_codepoint(std::string& out, std::uint32_t codepoint);

/// Decodes UTF-16LE or UTF-16BE bytes into valid UTF-8:
/// - Valid surrogate pairs (`0xD800..0xDBFF` + `0xDC00..0xDFFF`) produce
///   4-byte UTF-8 (`U+10000..U+10FFFF`).
/// - Lone/unpaired surrogates produce `U+FFFD` (`\xEF\xBF\xBD`) without
///   consuming a following non-low-surrogate code unit.
/// - When `stop_at_nul` is true, decoding stops at the first `0x0000` unit;
///   when false, embedded `0x0000` units are skipped.
[[nodiscard]] std::string decode_utf16_to_utf8(
    std::span<const std::uint8_t> bytes,
    Endianness endianness = Endianness::Little,
    bool stop_at_nul = true,
    std::size_t max_code_units = std::numeric_limits<std::size_t>::max(),
    Utf16DecodeDiagnostics* diagnostics = nullptr);

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
[[nodiscard]] Result<std::vector<std::uint8_t>> encode_pointer(std::uint64_t value,
                                                               TargetLayout layout);
[[nodiscard]] std::vector<std::uint8_t> encode_utf16(std::string_view utf8, Endianness endianness);

}  // namespace peelf
