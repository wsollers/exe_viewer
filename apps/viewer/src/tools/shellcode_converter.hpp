#pragma once

#include <peelf/binary_image.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
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

struct ShellcodeTargetConfig {
    peelf::Architecture architecture = peelf::Architecture::X86_64;
    peelf::Endianness endianness = peelf::Endianness::Little;
    bool is_64bit = true;
    bool thumb = false;
    std::uint64_t base_va = 0;
    bool assembly_mode = false;

    bool operator==(const ShellcodeTargetConfig&) const noexcept = default;
};

class ShellcodeScratchCache {
public:
    void invalidate() noexcept;
    void rebuild(const ShellcodeTargetConfig& target, std::string_view input);
    bool sync_target(const ShellcodeTargetConfig& target, std::string_view input);

    [[nodiscard]] std::optional<ShellcodeTargetConfig> active_target() const noexcept {
        return active_target_;
    }
    [[nodiscard]] std::span<const std::uint8_t> output_bytes() const noexcept {
        return output_bytes_;
    }
    [[nodiscard]] const std::string& hex_view() const noexcept { return hex_view_; }
    [[nodiscard]] const std::string& roundtrip_disasm_view() const noexcept {
        return roundtrip_disasm_view_;
    }
    [[nodiscard]] const std::string& diagnostic() const noexcept { return diagnostic_; }
    void set_diagnostic(std::string message) { diagnostic_ = std::move(message); }

private:
    std::optional<ShellcodeTargetConfig> active_target_;
    std::vector<std::uint8_t> output_bytes_;
    std::string hex_view_;
    std::string roundtrip_disasm_view_;
    std::string diagnostic_ = "Paste hex bytes, shellcode escapes, or toggle Assembly input.";
};

} // namespace viewer
