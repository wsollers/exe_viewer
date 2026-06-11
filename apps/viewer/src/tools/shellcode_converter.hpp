#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

struct ShellcodeParseResult {
    std::vector<std::uint8_t> bytes;
    std::string diagnostic;
    bool success = false;
};

[[nodiscard]] ShellcodeParseResult parse_hex_shellcode(std::string_view input);
[[nodiscard]] std::string format_shellcode_hex_view(std::span<const std::uint8_t> bytes,
                                                    std::size_t bytes_per_row = 16);

} // namespace viewer
