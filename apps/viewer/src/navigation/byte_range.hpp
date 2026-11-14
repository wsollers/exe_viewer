#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>

namespace viewer {

struct ByteRange {
    std::size_t offset;
    std::size_t size;
};

[[nodiscard]] constexpr std::optional<ByteRange> selected_byte_range(
    std::size_t anchor, std::size_t cursor, std::size_t file_size) noexcept {
    if (anchor >= file_size || cursor >= file_size) return std::nullopt;
    const auto first = std::min(anchor, cursor);
    return ByteRange{first, std::max(anchor, cursor) - first + 1};
}

} // namespace viewer
