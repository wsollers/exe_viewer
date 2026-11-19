// SPDX-License-Identifier: BSD-2-Clause
// Clean-room cross-platform MSF 7.00 & CodeView PDB debug symbol/type/line parser.
#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace peelf {

struct PdbIdentity {
    std::uint32_t version = 0;
    std::uint32_t signature = 0;
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t info_age = 0;
    std::optional<std::uint32_t> dbi_age{};
};

enum class PdbAggregateKind : std::uint8_t {
    Struct,
    Class,
    Interface,
    Union,
};

struct PdbMemberInfo {
    std::string name{};
    std::string type_name{};
    std::uint64_t byte_offset = 0;
    std::uint64_t byte_size = 0;
    std::uint8_t bit_size = 0;
    std::uint8_t bit_offset = 0;
    bool is_bitfield = false;
    bool is_base_class = false;
};

struct PdbAggregateType {
    std::string name{};
    PdbAggregateKind kind = PdbAggregateKind::Struct;
    std::uint64_t byte_size = 0;
    std::vector<PdbMemberInfo> members{};
};

struct PdbEnumeratorInfo {
    std::string name{};
    std::int64_t signed_value = 0;
    std::uint64_t unsigned_value = 0;
    bool is_signed = true;
};

struct PdbEnumType {
    std::string name{};
    std::string underlying_type_name{};
    std::uint64_t byte_size = 0;
    std::vector<PdbEnumeratorInfo> enumerators{};
};

struct PdbSymbol {
    std::string name{};
    std::uint64_t relative_address = 0;
    std::uint64_t byte_size = 0;
    std::uint16_t segment = 0;
    std::uint32_t segment_offset = 0;
    bool is_function = false;
    bool is_public = false;
    std::string module_name{};
    std::string library_name{};
};

struct PdbLineEntry {
    std::uint64_t relative_address = 0;
    std::string file_path{};
    std::string file_name{};
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    bool is_stmt = true;
};

struct PdbDebugData {
    PdbIdentity identity{};
    std::uint16_t machine = 0;
    std::vector<PdbSymbol> symbols{};
    std::vector<PdbAggregateType> types{};
    std::vector<PdbEnumType> enums{};
    std::vector<PdbLineEntry> lines{};

    [[nodiscard]] bool empty() const noexcept {
        return symbols.empty() && types.empty() && enums.empty() && lines.empty();
    }
};

/// Returns true if `bytes` begins with the exact 32-byte MSF 7.00 file signature.
[[nodiscard]] bool has_msf7_signature(std::span<const std::uint8_t> bytes) noexcept;

/// Reads MSF 7.00 Stream 1 (`PdbInfo`) and optional Stream 3 (`DBI`) GUID + Age identity
/// from an in-memory PDB buffer without parsing TPI/symbol/line streams.
[[nodiscard]] Result<PdbIdentity> read_pdb_identity(std::span<const std::uint8_t> bytes);

/// Reads MSF 7.00 Stream 1 (`PdbInfo`) and optional Stream 3 (`DBI`) GUID + Age identity
/// from disk, reading only the MSF directory and header blocks.
[[nodiscard]] Result<PdbIdentity> read_pdb_identity(const std::filesystem::path& path);

/// Parses an MSF 7.00 PDB buffer (Stream 1 Info + `/names`, Stream 2 CodeView TPI types,
/// Stream 3 DBI + `IMAGE_SECTION_HEADER`/OMAP + global/public/module CodeView symbols
/// + C13 `DEBUG_S_LINES` / `DEBUG_S_FILECHKSMS` source line mappings).
[[nodiscard]] Result<PdbDebugData> parse_pdb_bytes(
    std::span<const std::uint8_t> bytes,
    std::span<const Section> fallback_pe_sections = {},
    std::uint64_t fallback_image_base = 0);

/// Parses an MSF 7.00 `.pdb` file from disk.
[[nodiscard]] Result<PdbDebugData> parse_pdb_file(
    const std::filesystem::path& path,
    std::span<const Section> fallback_pe_sections = {},
    std::uint64_t fallback_image_base = 0);

} // namespace peelf
