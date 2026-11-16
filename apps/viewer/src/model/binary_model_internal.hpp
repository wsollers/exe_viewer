#pragma once

#include <cstdint>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>

namespace viewer::detail {

[[nodiscard]] inline std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

[[nodiscard]] inline std::string format_hex_addr(std::uint64_t value) {
    return std::format("0x{:X}", value);
}

} // namespace viewer::detail
