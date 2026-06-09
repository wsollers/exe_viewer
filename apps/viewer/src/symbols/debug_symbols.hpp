#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <peelf/binary_image.hpp>

#include "symbols/symbol_index.hpp"

namespace viewer {

enum class DebugSymbolLoadStatus : std::uint8_t {
    Loaded,
    FileNotFound,
    UnsupportedFormat,
    BackendUnavailable,
    BackendError
};

struct DebugSymbolLoadResult {
    DebugSymbolLoadStatus status = DebugSymbolLoadStatus::BackendError;
    std::vector<DebugSymbol> symbols;
    std::string diagnostic;
};

[[nodiscard]] std::optional<std::filesystem::path> find_local_codeview_pdb(const peelf::IBinaryImage& image,
                                                                           const std::filesystem::path& image_path);

[[nodiscard]] DebugSymbolLoadResult load_pdb_debug_symbols(const std::filesystem::path& pdb_path,
                                                           const peelf::IBinaryImage& image);

[[nodiscard]] const char* to_string(DebugSymbolLoadStatus status) noexcept;

} // namespace viewer
