#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace peelf::fuzz {

// Cap in-memory fuzz inputs to 256 KiB so random length fields cannot trigger
// multi-gigabyte allocations while still covering all repository binary fixtures.
inline constexpr std::size_t kMaxFuzzInputBytes = 256u * 1024u;

inline void sink_u64(std::uint64_t value) noexcept {
    volatile std::uint64_t sink = value;
    (void)sink;
}

// Portable deterministic FuzzedDataProvider-style slicer (consumes control scalars
// from the tail so leading magic headers remain stable under mutation, and byte
// slices from the head).
class FuzzByteReader {
  public:
    explicit constexpr FuzzByteReader(std::span<const std::uint8_t> bytes) noexcept
        : bytes_(bytes) {}

    [[nodiscard]] constexpr bool empty() const noexcept { return bytes_.empty(); }
    [[nodiscard]] constexpr std::size_t remaining() const noexcept { return bytes_.size(); }

    [[nodiscard]] constexpr std::uint8_t consume_u8(std::uint8_t fallback = 0u) noexcept {
        if (bytes_.empty()) {
            return fallback;
        }
        const std::uint8_t out = bytes_.back();
        bytes_ = bytes_.first(bytes_.size() - 1u);
        return out;
    }

    [[nodiscard]] constexpr bool consume_bool() noexcept { return (consume_u8(0u) & 1u) != 0u; }

    [[nodiscard]] constexpr std::uint16_t consume_u16() noexcept {
        const auto lo = static_cast<std::uint16_t>(consume_u8(0u));
        const auto hi = static_cast<std::uint16_t>(consume_u8(0u));
        return static_cast<std::uint16_t>(lo | static_cast<std::uint16_t>(hi << 8u));
    }

    [[nodiscard]] constexpr std::uint32_t consume_u32() noexcept {
        const auto lo = static_cast<std::uint32_t>(consume_u16());
        const auto hi = static_cast<std::uint32_t>(consume_u16());
        return lo | (hi << 16u);
    }

    [[nodiscard]] constexpr std::span<const std::uint8_t>
    consume_bytes(std::size_t count) noexcept {
        const std::size_t take = std::min(count, bytes_.size());
        const auto out = bytes_.first(take);
        bytes_ = bytes_.subspan(take);
        return out;
    }

    [[nodiscard]] constexpr std::span<const std::uint8_t>
    consume_sized_slice(std::size_t max_bytes) noexcept {
        if (bytes_.empty() || max_bytes == 0u) {
            return {};
        }
        const std::size_t limit = std::min(max_bytes, bytes_.size());
        const std::size_t want = static_cast<std::size_t>(consume_u16()) % (limit + 1u);
        return consume_bytes(want);
    }

    [[nodiscard]] constexpr std::span<const std::uint8_t> consume_remaining_bytes() noexcept {
        const auto out = bytes_;
        bytes_ = {};
        return out;
    }

    [[nodiscard]] static std::string_view
    as_string_view(std::span<const std::uint8_t> span) noexcept {
        if (span.empty()) {
            return {};
        }
        return {reinterpret_cast<const char*>(span.data()), span.size()};
    }

  private:
    std::span<const std::uint8_t> bytes_;
};

void fuzz_binary_image_one_input(std::span<const std::uint8_t> data) noexcept;
void fuzz_debug_formats_one_input(std::span<const std::uint8_t> data) noexcept;
void fuzz_crash_dumps_one_input(std::span<const std::uint8_t> data) noexcept;
void fuzz_parsers_dsl_one_input(std::span<const std::uint8_t> data) noexcept;

} // namespace peelf::fuzz
