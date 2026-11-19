#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <peelf/endian_reader.hpp>
#include "symbols/data_types.hpp"

namespace viewer {

inline constexpr std::size_t kMaxTypeNestingDepth = 32;
inline constexpr std::size_t kMaxCTypeSourceBytes = 2u * 1024u * 1024u;

/// User-selectable ABI override for custom C type compilation.
enum class CTypeAbiMode : std::uint8_t {
    AutoTarget = 0,
    Bits64 = 1,
    Bits32 = 2,
};

[[nodiscard]] constexpr std::string_view to_string(CTypeAbiMode mode) noexcept {
    switch (mode) {
        case CTypeAbiMode::AutoTarget: return "Auto from Target";
        case CTypeAbiMode::Bits64:     return "64-bit";
        case CTypeAbiMode::Bits32:     return "32-bit";
    }
    return "Auto from Target";
}

/// Controls sizeof(long) / sizeof(wchar_t) on 64-bit targets.
enum class CLongModel : std::uint8_t {
    Auto = 0,  ///< 4-byte long on 32-bit and 64-bit default (Win64 LLP64)
    LLP64 = 1, ///< Windows x64 / ARM64: long = 4 bytes, wchar_t = 2 bytes
    LP64 = 2,  ///< SysV / Linux / macOS 64-bit: long = 8 bytes, wchar_t = 4 bytes
};

enum class CTypeDiagnosticSeverity : std::uint8_t {
    Error = 0,
    Warning = 1,
};

struct CTypeParseDiagnostic {
    std::uint32_t line = 1;
    std::uint32_t column = 1;
    CTypeDiagnosticSeverity severity = CTypeDiagnosticSeverity::Error;
    std::string message{};

    auto operator<=>(const CTypeParseDiagnostic&) const = default;
};

struct CTypeAliasInfo {
    std::string alias{};
    std::string target_type{};
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;

    auto operator<=>(const CTypeAliasInfo&) const = default;
};

struct CTypeParseOptions {
    peelf::TargetLayout layout{};
    CLongModel long_model = CLongModel::Auto;
    std::span<const DataTypeRecord> external_types{};
};

struct CTypeParseResult {
    std::vector<DataTypeRecord> types{};
    std::vector<CTypeAliasInfo> typedefs{};
    std::unordered_map<std::string, std::int64_t> enum_constants{};
    std::vector<CTypeParseDiagnostic> diagnostics{};

    [[nodiscard]] bool has_errors() const noexcept {
        for (const CTypeParseDiagnostic& d : diagnostics) {
            if (d.severity == CTypeDiagnosticSeverity::Error) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool ok() const noexcept { return !has_errors(); }

    [[nodiscard]] std::string format_diagnostics() const;
};

/// Deterministically parses C struct, union, enum, and typedef declarations and
/// computes exact field byte offsets, bitfield positions, alignments, and sizes
/// for the specified target ABI layout.
[[nodiscard]] CTypeParseResult parse_c_types(std::string_view source,
                                             const CTypeParseOptions& options = {});

[[nodiscard]] CTypeParseResult parse_c_types(std::string_view source,
                                             const peelf::TargetLayout& layout);

/// Starter C header snippet shown as a placeholder / template in the Structure View editor.
[[nodiscard]] std::string_view default_custom_c_types_template() noexcept;

} // namespace viewer
