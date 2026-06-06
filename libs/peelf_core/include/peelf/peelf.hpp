#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <source_location>

#include <peelf/error.hpp>

#include <pe/pe_definitions.h>
#include <elf/elf_definitions.h>


namespace peelf {

// An endian-aware byte reader will be reintroduced with the unified binary model
// (see ToDo.md P1-4). The previous IByteReader/byte_reader/make_reader trio was
// removed in P0-8: it was entirely unused, and IByteReader's read_* methods were
// non-virtual (and undefined), so make_reader's std::unique_ptr<IByteReader> could
// never dispatch to byte_reader. Parsers currently use local little-endian helpers.

enum class FileKind { Unknown, ELF, PE };

struct FileInfo {
    FileKind kind{FileKind::Unknown};
    std::variant<std::monostate, ElfSummary, PeSummary> summary{};
};

// Parse the header bytes of a PE / ELF image into a FileInfo summary.
[[nodiscard]] Result<FileInfo> parse_pe_bytes(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<FileInfo> parse_elf_bytes(std::span<const std::uint8_t> bytes);

// Future: detect kind from a path and dispatch (ToDo.md P1-2).
// Result<FileInfo> parse_file(const std::filesystem::path& path);

std::string_view to_string(FileKind k);


} // namespace peelf
