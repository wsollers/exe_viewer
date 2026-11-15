#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>

#include "symbols/symbol_index.hpp"
#include "symbols/data_types.hpp"

namespace viewer {

enum class DebugSymbolLoadStatus : std::uint8_t {
    Loaded,
    FileNotFound,
    UnsupportedFormat,
    BackendUnavailable,
    BackendError
};

struct SourceLineMapping {
    std::uint64_t virtual_address = 0;
    std::uint64_t relative_virtual_address = 0;
    std::string file_path{};
    std::string file_name{};
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    bool is_stmt = true;
};

struct DebugSymbolLoadResult {
    DebugSymbolLoadStatus status = DebugSymbolLoadStatus::BackendError;
    std::vector<DebugSymbol> symbols{};
    std::vector<DataTypeRecord> types{};
    std::vector<SourceLineMapping> lines{};
    std::string diagnostic{};
};

[[nodiscard]] std::optional<std::filesystem::path> find_local_codeview_pdb(const peelf::IBinaryImage& image,
                                                                           const std::filesystem::path& image_path);

[[nodiscard]] std::optional<std::filesystem::path> find_local_elf_debug_file(
    const peelf::IBinaryImage& image,
    const std::filesystem::path& image_path,
    std::span<const std::filesystem::path> extra_search_dirs = {});

[[nodiscard]] std::optional<std::filesystem::path> find_local_debug_symbols_file(
    const peelf::IBinaryImage& image,
    const std::filesystem::path& image_path);

[[nodiscard]] DebugSymbolLoadResult load_pdb_debug_symbols(const std::filesystem::path& pdb_path,
                                                           const peelf::IBinaryImage& image);

[[nodiscard]] DebugSymbolLoadResult load_dwarf_debug_symbols_from_image(
    const peelf::IBinaryImage& dwarf_source_image,
    std::span<const std::uint8_t> dwarf_source_bytes,
    const peelf::IBinaryImage& target_image,
    std::string_view diagnostic_label = {});

[[nodiscard]] DebugSymbolLoadResult load_dwarf_debug_symbols(const std::filesystem::path& debug_path,
                                                             const peelf::IBinaryImage& target_image);

[[nodiscard]] DebugSymbolLoadResult load_debug_symbols_file(const std::filesystem::path& debug_path,
                                                            const peelf::IBinaryImage& target_image);

[[nodiscard]] std::vector<DebugSymbol> rebase_debug_symbols(std::span<const DebugSymbol> symbols,
                                                            std::uint64_t image_base);

[[nodiscard]] std::vector<SourceLineMapping> rebase_source_lines(std::span<const SourceLineMapping> lines,
                                                                 std::uint64_t image_base);

[[nodiscard]] const char* to_string(DebugSymbolLoadStatus status) noexcept;

} // namespace viewer
