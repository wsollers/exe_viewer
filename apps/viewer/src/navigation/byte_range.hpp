#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>

namespace viewer {

struct ByteRange {
    std::uint64_t offset;
    std::uint64_t size;
};

[[nodiscard]] constexpr std::optional<ByteRange> selected_byte_range(
    std::uint64_t anchor, std::uint64_t cursor, std::uint64_t file_size) noexcept {
    if (anchor >= file_size || cursor >= file_size) return std::nullopt;
    const auto first = std::min(anchor, cursor);
    return ByteRange{first, std::max(anchor, cursor) - first + 1};
}

} // namespace viewer
