// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

// ---------------------------------------------------------------------------
// ECMA-335 COMIMAGE_FLAGS_* (IMAGE_COR20_HEADER.Flags)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kCorImageFlagsIlOnly           = 0x00000001u;
inline constexpr std::uint32_t kCorImageFlags32BitRequired    = 0x00000002u;
inline constexpr std::uint32_t kCorImageFlagsIlLibrary        = 0x00000004u;
inline constexpr std::uint32_t kCorImageFlagsStrongNameSigned = 0x00000008u;
inline constexpr std::uint32_t kCorImageFlagsNativeEntryPoint = 0x00000010u;
inline constexpr std::uint32_t kCorImageFlagsTrackDebugData   = 0x00010000u;
inline constexpr std::uint32_t kCorImageFlags32BitPreferred   = 0x00020000u;

[[nodiscard]] std::string format_cor20_flags(std::uint32_t flags);

// ---------------------------------------------------------------------------
// ECMA-335 Partition II Metadata Records
// ---------------------------------------------------------------------------

struct ClrStreamHeaderInfo {
    std::string name{};
    std::uint32_t offset{0};
    std::uint32_t size{0};
};

struct ClrModuleInfo {
    std::uint32_t token{0x00000001u};
    std::uint16_t generation{0};
    std::string name{};
    std::string mvid_guid{};
};

struct ClrAssemblyInfo {
    std::uint32_t token{0x20000001u};
    std::uint32_t hash_alg_id{0};
    std::uint16_t major_version{0};
    std::uint16_t minor_version{0};
    std::uint16_t build_number{0};
    std::uint16_t revision_number{0};
    std::uint32_t flags{0};
    std::string name{};
    std::string culture{};
    std::string public_key_hex{};

    [[nodiscard]] std::string version_string() const;
};

struct ClrAssemblyRef {
    std::uint32_t token{0};
    std::uint16_t major_version{0};
    std::uint16_t minor_version{0};
    std::uint16_t build_number{0};
    std::uint16_t revision_number{0};
    std::uint32_t flags{0};
    std::string name{};
    std::string culture{};
    std::string public_key_or_token_hex{};

    [[nodiscard]] std::string version_string() const;
};

struct ClrTypeRef {
    std::uint32_t token{0};
    std::uint32_t resolution_scope_token{0};
    std::string resolution_scope_summary{};
    std::string type_namespace{};
    std::string type_name{};

    [[nodiscard]] std::string full_name() const;
};

struct ClrTypeDef {
    std::uint32_t token{0};
    std::uint32_t flags{0};
    std::string visibility_summary{};
    std::string kind_summary{};
    std::string type_namespace{};
    std::string type_name{};
    std::uint32_t extends_token{0};
    std::string extends_name{};
    std::uint32_t field_start_index{0};   // 0-based index into ClrMetadata::fields
    std::uint32_t field_count{0};
    std::uint32_t method_start_index{0};  // 0-based index into ClrMetadata::methods
    std::uint32_t method_count{0};

    [[nodiscard]] std::string full_name() const;
};

struct ClrFieldDef {
    std::uint32_t token{0};
    std::uint32_t owning_type_token{0};
    std::string owning_type_name{};
    std::uint16_t flags{0};
    std::string flags_summary{};
    std::string name{};
    std::string type_signature{};
};

struct ClrParamDef {
    std::uint32_t token{0};
    std::uint16_t flags{0};
    std::uint16_t sequence{0};
    std::string name{};
};

struct ClrMethodDef {
    std::uint32_t token{0};
    std::uint32_t owning_type_token{0};
    std::string owning_type_name{};
    std::string name{};
    std::uint32_t rva{0};
    std::optional<std::uint64_t> file_offset{};
    std::uint16_t impl_flags{0};
    std::uint16_t flags{0};
    std::string flags_summary{};
    std::string return_type{};
    std::vector<std::string> parameter_types{};
    std::vector<std::string> parameter_names{};
    std::string signature_summary{};

    [[nodiscard]] std::string full_name() const {
        if (owning_type_name.empty()) {
            return name;
        }
        return owning_type_name + "::" + name;
    }
};

struct ClrMemberRef {
    std::uint32_t token{0};
    std::uint32_t parent_token{0};
    std::string declaring_parent{};
    std::string name{};
    std::string signature_summary{};
    bool is_field_ref{false};
};

struct ClrPInvokeEntry {
    std::uint32_t impl_map_token{0};
    std::uint32_t method_token{0};
    std::string method_full_name{};
    std::string module_name{};
    std::string entry_point_name{};
    std::uint16_t mapping_flags{0};
    std::string calling_convention{};
    std::string char_set{};
    bool supports_last_error{false};

    [[nodiscard]] std::string flags_summary() const {
        std::string out = calling_convention;
        if (!char_set.empty()) {
            if (!out.empty()) out += " | ";
            out += char_set;
        }
        if (supports_last_error) {
            if (!out.empty()) out += " | ";
            out += "SetLastError";
        }
        return out;
    }
};

struct ClrUserString {
    std::uint32_t token{0};
    std::string value{};
};

struct ClrMetadata {
    // IMAGE_COR20_HEADER summary
    std::uint16_t cor20_major_runtime_version{0};
    std::uint16_t cor20_minor_runtime_version{0};
    std::uint32_t cor20_flags{0};
    std::string cor20_flags_summary{};
    std::uint32_t entry_point_token_or_rva{0};
    bool il_only{false};
    bool requires_32bit{false};
    bool prefers_32bit{false};
    bool strong_name_signed{false};
    bool native_entry_point{false};
    bool track_debug_data{false};

    // BSJB Metadata Root
    std::uint64_t metadata_rva{0};
    std::uint64_t metadata_file_offset{0};
    std::uint32_t metadata_size{0};
    std::uint16_t md_major_version{0};
    std::uint16_t md_minor_version{0};
    std::string runtime_version{};
    std::uint16_t md_flags{0};
    bool compressed_tables{true};
    std::uint8_t heap_sizes{0};
    std::uint64_t valid_tables_mask{0};
    std::uint64_t sorted_tables_mask{0};
    std::array<std::uint32_t, 64> table_row_counts{};
    std::vector<ClrStreamHeaderInfo> streams{};

    // Structured ECMA-335 records
    std::optional<ClrModuleInfo> module{};
    std::optional<ClrAssemblyInfo> assembly{};
    std::vector<ClrAssemblyRef> assembly_refs{};
    std::vector<ClrTypeRef> type_refs{};
    std::vector<ClrTypeDef> type_defs{};
    std::vector<ClrFieldDef> fields{};
    std::vector<ClrParamDef> params{};
    std::vector<ClrMethodDef> methods{};
    std::vector<ClrMemberRef> member_refs{};
    std::vector<std::string> type_specs{};
    std::vector<std::string> module_refs{};
    std::vector<ClrPInvokeEntry> pinvoke_entries{};
    std::vector<ClrUserString> user_strings{};

    SubsystemStatus status{};
    std::vector<std::string> diagnostics{};

    /// Resolves any metadata token (`TypeDef`, `TypeRef`, `MethodDef`, `MemberRef`,
    /// `Field`, `AssemblyRef`, `ModuleRef`, or `#US` `0x70xxxxxx` string literal) to
    /// a concise human-readable display string, or `std::nullopt` if unresolvable.
    [[nodiscard]] std::optional<std::string> resolve_token(std::uint32_t token) const;
};

/// Clean-room ECMA-335 Partition II metadata parser.
/// Maps `IMAGE_COR20_HEADER.MetaData` via `image.va_to_file_offset`, validates the `BSJB`
/// root signature, parses streams (`#~`/`#-`, `#Strings`, `#US`, `#GUID`, `#Blob`), and
/// decodes metadata tables and signatures with strict bounds and overflow safety.
[[nodiscard]] Result<ClrMetadata> parse_clr_metadata(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes);

// ---------------------------------------------------------------------------
// ECMA-335 Partition III Clean-Room CIL Method Body Disassembler
// ---------------------------------------------------------------------------

enum class CilEhClauseKind : std::uint8_t {
    Catch,
    Filter,
    Finally,
    Fault,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(CilEhClauseKind kind) noexcept {
    switch (kind) {
        case CilEhClauseKind::Catch:   return "catch";
        case CilEhClauseKind::Filter:  return "filter";
        case CilEhClauseKind::Finally: return "finally";
        case CilEhClauseKind::Fault:   return "fault";
        case CilEhClauseKind::Unknown: return "unknown";
    }
    return "unknown";
}

struct CilEhClause {
    CilEhClauseKind kind{CilEhClauseKind::Catch};
    std::uint32_t raw_flags{0};
    std::uint32_t try_offset{0};
    std::uint32_t try_length{0};
    std::uint32_t handler_offset{0};
    std::uint32_t handler_length{0};
    std::uint32_t class_token_or_filter_offset{0};
    std::string catch_type_name{};
};

struct CilInstruction {
    std::uint32_t il_offset{0};
    std::uint32_t size{0};
    std::string raw_bytes_hex{};
    std::string mnemonic{};
    std::string operand_text{};
    std::optional<std::uint32_t> referenced_token{};
    std::optional<std::uint32_t> branch_target_il_offset{};
    std::vector<std::uint32_t> switch_target_il_offsets{};
};

struct CilMethodBody {
    std::uint32_t method_token{0};
    std::uint32_t rva{0};
    std::uint64_t file_offset{0};
    std::uint64_t code_file_offset{0};
    bool is_fat_header{false};
    bool init_locals{false};
    bool has_more_sections{false};
    std::uint16_t raw_flags{0};
    std::uint16_t max_stack{8};
    std::uint32_t code_size{0};
    std::uint32_t local_var_sig_tok{0};
    std::vector<CilInstruction> instructions{};
    std::vector<CilEhClause> eh_clauses{};
    SubsystemStatus status{};
    std::vector<std::string> diagnostics{};

    [[nodiscard]] std::uint32_t header_size() const noexcept {
        if (code_file_offset >= file_offset) {
            return static_cast<std::uint32_t>(code_file_offset - file_offset);
        }
        return is_fat_header ? 12u : 1u;
    }
};

/// Disassembles a Tiny or Fat ECMA-335 CIL method body (including aligned extra EH
/// clause sections and metadata token / branch target resolution).
[[nodiscard]] Result<CilMethodBody> disassemble_cil_method(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    const ClrMetadata& metadata,
    const ClrMethodDef& method);

/// Overload disassembling a CIL method body directly by RVA.
[[nodiscard]] Result<CilMethodBody> disassemble_cil_method_at_rva(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    const ClrMetadata& metadata,
    std::uint32_t method_rva,
    std::uint32_t method_token = 0u);

}  // namespace peelf
