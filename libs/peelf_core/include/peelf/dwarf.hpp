#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace peelf {

struct ElfDebugLinkInfo {
    std::string build_id_hex{};
    std::string debuglink_filename{};
    std::uint32_t debuglink_crc32 = 0;
    bool has_debuglink = false;
};

struct DwarfFunctionSymbol {
    std::string name{};
    std::string linkage_name{};
    std::string comp_unit{};
    std::uint64_t low_pc = 0;
    std::uint64_t relative_address = 0;
    std::uint64_t byte_size = 0;
    std::uint32_t decl_line = 0;
};

enum class DwarfAggregateKind : std::uint8_t {
    Struct,
    Class,
    Union,
};

struct DwarfMemberInfo {
    std::string name{};
    std::string type_name{};
    std::uint64_t byte_offset = 0;
    std::uint64_t byte_size = 0;
};

struct DwarfAggregateType {
    std::string name{};
    DwarfAggregateKind kind = DwarfAggregateKind::Struct;
    std::uint64_t byte_size = 0;
    std::vector<DwarfMemberInfo> members{};
};

struct DwarfLineEntry {
    std::uint64_t address = 0;
    std::uint64_t relative_address = 0;
    std::string file_path{};
    std::string file_name{};
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    bool is_stmt = true;
};

struct DwarfDebugData {
    std::uint64_t static_image_base = 0;
    std::vector<DwarfFunctionSymbol> functions{};
    std::vector<DwarfAggregateType> types{};
    std::vector<DwarfLineEntry> lines{};

    [[nodiscard]] bool empty() const noexcept {
        return functions.empty() && types.empty() && lines.empty();
    }
};

struct DwarfSectionViews {
    Endianness endian = Endianness::Little;
    std::uint8_t default_address_size = 8;
    std::uint64_t static_image_base = 0;
    std::vector<std::uint8_t> debug_info{};
    std::vector<std::uint8_t> debug_abbrev{};
    std::vector<std::uint8_t> debug_str{};
    std::vector<std::uint8_t> debug_line{};
    std::vector<std::uint8_t> debug_line_str{};
    std::vector<std::uint8_t> debug_str_offsets{};
    std::vector<std::uint8_t> debug_addr{};
};

/// Extracts `.note.gnu.build-id` and `.gnu_debuglink` metadata from an ELF image.
[[nodiscard]] ElfDebugLinkInfo extract_elf_debug_link_info(const IBinaryImage& image);

/// Searches standard separate-debug locations (ELF `.gnu_debuglink` sibling / `.debug/` /
/// `/usr/lib/debug`, `.note.gnu.build-id` `.build-id/xx/yyyy.debug`, `<bin>.debug`, and
/// Mach-O `LC_UUID`-verified `<bin>.dSYM/Contents/Resources/DWARF/*` bundles).
[[nodiscard]] std::optional<std::filesystem::path> find_separate_debug_file(
    const std::filesystem::path& binary_path,
    const IBinaryImage& image,
    std::span<const std::filesystem::path> extra_search_dirs = {});

/// Returns true if `image` contains non-empty ELF/MinGW `.debug_info`/`.debug_line`
/// or Mach-O `__DWARF,__debug_info`/`__DWARF,__debug_line` sections.
[[nodiscard]] bool has_embedded_dwarf(const IBinaryImage& image) noexcept;

/// Parses DWARF v2..v5 `.debug_info`, `.debug_abbrev`, `.debug_str`, `.debug_line_str`,
/// `.debug_str_offsets`, `.debug_addr`, and `.debug_line` from raw section buffers.
[[nodiscard]] Result<DwarfDebugData> parse_dwarf_sections(const DwarfSectionViews& views);

/// Parses DWARF v2..v5 debug info directly from a parsed ELF, MinGW PE, or Mach-O / `.dSYM` image
/// and its backing raw file bytes (either an unstripped binary or a separate debug companion).
[[nodiscard]] Result<DwarfDebugData> parse_dwarf_image(const IBinaryImage& image,
                                                       std::span<const std::uint8_t> file_bytes);

} // namespace peelf
