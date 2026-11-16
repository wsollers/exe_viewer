#pragma once

#include <cstdint>
#include <format>
#include <string>

namespace viewer::detail {

[[nodiscard]] inline std::string format_hex(std::uint64_t value) {
    return std::format("0x{:X}", value);
}

} // namespace viewer::detail
