#include "tools/shellcode_converter.hpp"

#include "analysis/patch_preview.hpp"

#include <peelf/assembler.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <format>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>

namespace viewer {
namespace {

[[nodiscard]] bool is_hex_digit(char ch) {
    return std::isxdigit(static_cast<unsigned char>(ch)) != 0;
}

[[nodiscard]] bool is_identifier_char(char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

[[nodiscard]] std::optional<std::uint8_t> parse_byte_token(std::string_view token) {
    if (token.empty() || token.size() > 2) {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    const auto* first = token.data();
    const auto* last = token.data() + token.size();
    const std::from_chars_result parsed = std::from_chars(first, last, value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != last || value > std::numeric_limits<std::uint8_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::string byte_count_message(std::size_t count) {
    std::array<char, 64> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "Parsed %zu byte%s.", count, count == 1 ? "" : "s");
    return buffer.data();
}

bool append_hex_run(std::string_view token, std::vector<std::uint8_t>& bytes, std::string& diagnostic) {
    if (token.empty()) {
        return true;
    }
    if (token.size() % 2u != 0u) {
        diagnostic = "Odd-length hex token: " + std::string(token);
        return false;
    }

    for (std::size_t index = 0; index < token.size(); index += 2u) {
        const std::optional<std::uint8_t> byte = parse_byte_token(token.substr(index, 2u));
        if (!byte) {
            diagnostic = "Invalid hex byte: " + std::string(token.substr(index, 2u));
            return false;
        }
        bytes.push_back(*byte);
    }
    return true;
}

} // namespace

ShellcodeParseResult parse_hex_shellcode(std::string_view input) {
    ShellcodeParseResult result;

    for (std::size_t index = 0; index < input.size();) {
        const char ch = input[index];
        if (std::isalpha(static_cast<unsigned char>(ch)) != 0 || ch == '_') {
            const std::size_t word_start = index;
            std::size_t word_end = word_start;
            bool all_hex = true;
            while (word_end < input.size() && is_identifier_char(input[word_end])) {
                all_hex = all_hex && is_hex_digit(input[word_end]);
                ++word_end;
            }
            if (!all_hex) {
                index = word_end;
                continue;
            }
        }

        if (!is_hex_digit(ch) && ch != '\\') {
            ++index;
            continue;
        }

        if (ch == '\\') {
            if (index + 3u < input.size() && (input[index + 1u] == 'x' || input[index + 1u] == 'X') &&
                is_hex_digit(input[index + 2u]) && is_hex_digit(input[index + 3u])) {
                const std::optional<std::uint8_t> byte = parse_byte_token(input.substr(index + 2u, 2u));
                if (!byte) {
                    result.bytes.clear();
                    result.diagnostic = "Invalid escaped byte.";
                    return result;
                }
                result.bytes.push_back(*byte);
                index += 4u;
                continue;
            }
            result.bytes.clear();
            if (index + 1u < input.size() && (input[index + 1u] == 'x' || input[index + 1u] == 'X')) {
                result.diagnostic = "Malformed \\x hex escape: expected exactly two hex digits.";
            } else {
                result.diagnostic = "Invalid escape sequence: expected \\xHH.";
            }
            return result;
        }

        if (ch == '0' && index + 1u < input.size() && (input[index + 1u] == 'x' || input[index + 1u] == 'X')) {
            std::size_t token_start = index + 2u;
            std::size_t token_end = token_start;
            while (token_end < input.size() && is_hex_digit(input[token_end])) {
                ++token_end;
            }
            const std::string_view token = input.substr(token_start, token_end - token_start);
            if (token.empty() || token.size() > 2u) {
                result.bytes.clear();
                result.diagnostic = "Expected one byte after 0x prefix.";
                return result;
            }
            const std::optional<std::uint8_t> byte = parse_byte_token(token);
            if (!byte) {
                result.bytes.clear();
                result.diagnostic = "Invalid 0x byte: " + std::string(token);
                return result;
            }
            result.bytes.push_back(*byte);
            index = token_end;
            continue;
        }

        const std::size_t token_start = index;
        std::size_t token_end = token_start;
        while (token_end < input.size() && is_hex_digit(input[token_end])) {
            ++token_end;
        }
        const std::string_view token = input.substr(token_start, token_end - token_start);
        if (!append_hex_run(token, result.bytes, result.diagnostic)) {
            result.bytes.clear();
            return result;
        }
        index = token_end;
    }

    if (result.bytes.empty()) {
        result.diagnostic = "No hex bytes found.";
        return result;
    }

    result.success = true;
    result.diagnostic = byte_count_message(result.bytes.size());
    return result;
}

std::string format_shellcode_hex_view(std::span<const std::uint8_t> bytes, std::size_t bytes_per_row) {
    if (bytes.empty()) {
        return {};
    }
    if (bytes_per_row == 0u) {
        bytes_per_row = 16u;
    }

    std::string out;
    out.reserve(bytes.size() * 5u);

    for (std::size_t row = 0; row < bytes.size(); row += bytes_per_row) {
        std::array<char, 32> address{};
        std::snprintf(address.data(), address.size(), "%08zX: ", row);
        out += address.data();

        const std::size_t end = std::min(row + bytes_per_row, bytes.size());
        for (std::size_t index = row; index < end; ++index) {
            std::array<char, 4> byte{};
            std::snprintf(byte.data(), byte.size(), "%02X ", bytes[index]);
            out += byte.data();
        }

        const std::size_t missing = bytes_per_row - (end - row);
        out.append(missing * 3u, ' ');
        out += " ";

        for (std::size_t index = row; index < end; ++index) {
            const unsigned char ch = bytes[index];
            out.push_back((ch >= 32u && ch < 127u) ? static_cast<char>(ch) : '.');
        }
        if (end < bytes.size()) {
            out.push_back('\n');
        }
    }

    return out;
}

void ShellcodeScratchCache::invalidate() noexcept {
    active_target_.reset();
    output_bytes_.clear();
    hex_view_.clear();
    roundtrip_disasm_view_.clear();
    diagnostic_.clear();
}

void ShellcodeScratchCache::rebuild(const ShellcodeTargetConfig& target, std::string_view input) {
    active_target_ = target;
    output_bytes_.clear();
    hex_view_.clear();
    roundtrip_disasm_view_.clear();

    if (target.assembly_mode) {
        if (input.empty()) {
            diagnostic_ = std::format(
                "Enter {} assembly instructions (base VA 0x{:X}).",
                peelf::to_string(target.architecture),
                target.base_va);
            return;
        }
        auto res = peelf::assemble_instructions(target.architecture,
                                                target.endianness,
                                                target.is_64bit,
                                                target.thumb,
                                                target.base_va,
                                                input);
        if (!res.has_value()) {
            diagnostic_ = res.error().message;
            return;
        }
        output_bytes_ = std::move(res->bytes);
        diagnostic_ = std::format(
            "Assembled {} instruction(s) -> {} byte(s) via {} @ 0x{:X}",
            res->instruction_spans.size(),
            output_bytes_.size(),
            res->provider_name,
            target.base_va);
    } else {
        if (input.empty()) {
            diagnostic_ = "Paste hex bytes, shellcode escapes, or toggle Assembly input.";
            return;
        }
        const ShellcodeParseResult parsed = parse_hex_shellcode(input);
        if (!parsed.success) {
            diagnostic_ = parsed.diagnostic;
            return;
        }
        output_bytes_ = parsed.bytes;
        diagnostic_ = parsed.diagnostic;
    }

    if (!output_bytes_.empty()) {
        hex_view_ = format_shellcode_hex_view(
            std::span<const std::uint8_t>(output_bytes_.data(), output_bytes_.size()));
        const auto insns = disassemble_patch_bytes(output_bytes_,
                                                   target.base_va,
                                                   target.architecture,
                                                   target.endianness,
                                                   target.thumb);
        if (!insns.empty()) {
            std::ostringstream oss;
            for (const Instruction& inst : insns) {
                if (target.is_64bit || inst.address > 0xFFFFFFFFull) {
                    oss << std::format("0x{:016X}  {} {}\n",
                                       inst.address,
                                       inst.mnemonic,
                                       inst.operands);
                } else {
                    oss << std::format("0x{:08X}  {} {}\n",
                                       inst.address,
                                       inst.mnemonic,
                                       inst.operands);
                }
            }
            roundtrip_disasm_view_ = oss.str();
        }
    }
}

bool ShellcodeScratchCache::sync_target(const ShellcodeTargetConfig& target, std::string_view input) {
    if (active_target_.has_value() && *active_target_ == target) {
        return false;
    }
    invalidate();
    rebuild(target, input);
    return true;
}

} // namespace viewer
