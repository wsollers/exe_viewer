#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace peelf {

enum class FileKind { Unknown, ELF, PE };

struct Error {
    std::string message;
};

struct ElfSummary {
    std::uint8_t ei_class{};  // 1=32-bit, 2=64-bit
    std::uint8_t ei_data{};   // 1=little, 2=big
    std::uint16_t e_type{};
    std::uint16_t e_machine{};
};

struct PeSummary {
    std::uint16_t machine{};
    std::uint16_t number_of_sections{};
    std::uint32_t time_date_stamp{};
    std::uint16_t optional_magic{}; // 0x10b (PE32), 0x20b (PE32+)
};

struct FileInfo {
    FileKind kind{FileKind::Unknown};
    std::variant<std::monostate, ElfSummary, PeSummary> summary{};
};

std::expected<FileInfo, Error> parse_file(const std::filesystem::path& path);
std::string_view to_string(FileKind k);

} // namespace peelf
