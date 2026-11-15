#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

namespace peelf {

enum class DiffChangeKind : std::uint8_t {
    Unchanged = 0,
    Modified = 1,
    Added = 2,
    Removed = 3,
};

[[nodiscard]] constexpr std::string_view to_string(DiffChangeKind kind) noexcept {
    switch (kind) {
        case DiffChangeKind::Unchanged: return "Unchanged";
        case DiffChangeKind::Modified:  return "Modified";
        case DiffChangeKind::Added:     return "Added";
        case DiffChangeKind::Removed:   return "Removed";
    }
    return "Modified";
}

enum class FunctionMatchKind : std::uint8_t {
    Identical = 0,
    IdenticalRelocated = 1,
    Modified = 2,
    Added = 3,
    Removed = 4,
};

[[nodiscard]] constexpr std::string_view to_string(FunctionMatchKind kind) noexcept {
    switch (kind) {
        case FunctionMatchKind::Identical:          return "Identical";
        case FunctionMatchKind::IdenticalRelocated: return "IdenticalRelocated";
        case FunctionMatchKind::Modified:           return "Modified";
        case FunctionMatchKind::Added:              return "Added";
        case FunctionMatchKind::Removed:            return "Removed";
    }
    return "Modified";
}

enum class ByteHunkClassification : std::uint8_t {
    CodeChange = 0,
    DataChange = 1,
    HeaderChange = 2,
    RelocationOnly = 3,
    InlineCodeHook = 4,
    IatGotPointerHook = 5,
    NormalizedLoaderSlot = 6,
    ReadOnlyDataModified = 7,
    WritableRuntimeData = 8,
};

[[nodiscard]] constexpr std::string_view to_string(ByteHunkClassification cls) noexcept {
    switch (cls) {
        case ByteHunkClassification::CodeChange:           return "CodeChange";
        case ByteHunkClassification::DataChange:           return "DataChange";
        case ByteHunkClassification::HeaderChange:         return "HeaderChange";
        case ByteHunkClassification::RelocationOnly:       return "RelocationOnly";
        case ByteHunkClassification::InlineCodeHook:       return "InlineCodeHook";
        case ByteHunkClassification::IatGotPointerHook:    return "IatGotPointerHook";
        case ByteHunkClassification::NormalizedLoaderSlot: return "NormalizedLoaderSlot";
        case ByteHunkClassification::ReadOnlyDataModified: return "ReadOnlyDataModified";
        case ByteHunkClassification::WritableRuntimeData:  return "WritableRuntimeData";
    }
    return "DataChange";
}

struct MetadataFieldDiff {
    std::string field_name{};
    std::string lhs_value{};
    std::string rhs_value{};
    bool changed{false};
};

struct HeaderDiffSummary {
    std::string lhs_label{};
    std::string rhs_label{};
    std::string lhs_sha256{};
    std::string rhs_sha256{};
    std::uint64_t lhs_size{0};
    std::uint64_t rhs_size{0};
    bool identical_files{false};
    bool format_matches{false};
    bool arch_matches{false};
    bool bitness_matches{false};
    bool endianness_matches{false};
    bool image_base_matches{false};
    bool entry_point_matches{false};
    bool entry_rva_matches{false};
    std::vector<MetadataFieldDiff> fields{};
};

struct SectionDiffEntry {
    std::string name{};
    DiffChangeKind status{DiffChangeKind::Unchanged};
    std::optional<std::uint64_t> lhs_va{};
    std::optional<std::uint64_t> rhs_va{};
    std::uint64_t lhs_virtual_size{0};
    std::uint64_t rhs_virtual_size{0};
    std::uint64_t lhs_file_offset{0};
    std::uint64_t rhs_file_offset{0};
    std::uint64_t lhs_file_size{0};
    std::uint64_t rhs_file_size{0};
    std::uint64_t lhs_flags{0};
    std::uint64_t rhs_flags{0};
    std::string lhs_permissions{};
    std::string rhs_permissions{};
    std::string lhs_sha256{};
    std::string rhs_sha256{};
    std::uint64_t changed_byte_count{0};
};

struct ImportDiffEntry {
    std::string library{};
    std::string symbol_or_ordinal{};
    DiffChangeKind status{DiffChangeKind::Unchanged};
    std::optional<std::uint16_t> lhs_ordinal{};
    std::optional<std::uint16_t> rhs_ordinal{};
    std::optional<std::uint64_t> lhs_rva{};
    std::optional<std::uint64_t> rhs_rva{};
    bool lhs_delay_load{false};
    bool rhs_delay_load{false};
    std::string detail{};
};

struct ExportDiffEntry {
    std::string name{};
    DiffChangeKind status{DiffChangeKind::Unchanged};
    std::optional<std::uint32_t> lhs_ordinal{};
    std::optional<std::uint32_t> rhs_ordinal{};
    std::optional<std::uint64_t> lhs_rva{};
    std::optional<std::uint64_t> rhs_rva{};
    std::string lhs_forwarder{};
    std::string rhs_forwarder{};
    std::string detail{};
};

struct ByteDiffHunk {
    std::string section_name{};
    std::optional<std::uint64_t> lhs_file_offset{};
    std::optional<std::uint64_t> rhs_file_offset{};
    std::optional<std::uint64_t> lhs_va{};
    std::optional<std::uint64_t> rhs_va{};
    std::uint64_t size{0};
    std::uint64_t differing_bytes{0};
    ByteHunkClassification classification{ByteHunkClassification::DataChange};
    std::vector<std::uint8_t> lhs_sample{};
    std::vector<std::uint8_t> rhs_sample{};
    std::string symbol_context{};
    std::string detail{};
};

struct FunctionDiffEntry {
    std::string display_name{};
    std::string raw_lhs_name{};
    std::string raw_rhs_name{};
    FunctionMatchKind status{FunctionMatchKind::Identical};
    std::string match_basis{}; // "ExactName", "NormalizedFingerprint", "Similarity", "Unmatched"
    std::optional<std::uint64_t> lhs_va{};
    std::optional<std::uint64_t> rhs_va{};
    std::optional<std::uint64_t> lhs_file_offset{};
    std::optional<std::uint64_t> rhs_file_offset{};
    std::uint64_t lhs_size{0};
    std::uint64_t rhs_size{0};
    std::int64_t size_delta{0};
    double similarity{1.0}; // [0.0, 1.0] on relocation-normalized bytes
    std::string lhs_normalized_sha256{};
    std::string rhs_normalized_sha256{};
};

struct BinaryDiffOptions {
    std::string lhs_label{"Primary"};
    std::string rhs_label{"Comparison"};
    std::uint64_t coalesce_gap_bytes{4};
    std::size_t max_byte_hunks{4096};
    std::size_t sample_bytes_per_hunk{24};
    double min_function_similarity{0.55};
};

struct BinaryDiffReport {
    HeaderDiffSummary header{};
    std::vector<SectionDiffEntry> sections{};
    std::vector<ImportDiffEntry> imports{};
    std::vector<ExportDiffEntry> exports{};
    std::vector<FunctionDiffEntry> functions{};
    std::vector<ByteDiffHunk> byte_hunks{};
    bool byte_hunks_truncated{false};

    // Rollup counters
    std::size_t sections_added{0};
    std::size_t sections_removed{0};
    std::size_t sections_modified{0};
    std::size_t sections_unchanged{0};

    std::size_t imports_added{0};
    std::size_t imports_removed{0};
    std::size_t imports_modified{0};

    std::size_t exports_added{0};
    std::size_t exports_removed{0};
    std::size_t exports_modified{0};

    std::size_t functions_identical{0};
    std::size_t functions_relocated{0};
    std::size_t functions_modified{0};
    std::size_t functions_added{0};
    std::size_t functions_removed{0};

    std::uint64_t total_changed_bytes{0};
};

/// Normalizes a function's raw machine-code bytes so PC-relative / RIP-relative call & branch
/// displacements, PE `.reloc` / ELF relocation fixups, and absolute `[image_base, image_end)`
/// pointers do not cause false-positive function diffs when code shifts address between builds.
[[nodiscard]] std::vector<std::uint8_t> normalize_function_bytes_for_diff(
    std::span<const std::uint8_t> func_bytes,
    std::uint64_t func_va,
    const IBinaryImage& image);

[[nodiscard]] Result<BinaryDiffReport> compare_binaries(
    const IBinaryImage& lhs_image,
    std::span<const std::uint8_t> lhs_bytes,
    const IBinaryImage& rhs_image,
    std::span<const std::uint8_t> rhs_bytes,
    const BinaryDiffOptions& options = {});

[[nodiscard]] Result<BinaryDiffReport> compare_binaries(
    std::span<const std::uint8_t> lhs_bytes,
    std::span<const std::uint8_t> rhs_bytes,
    const BinaryDiffOptions& options = {});

[[nodiscard]] Result<BinaryDiffReport> compare_binary_files(
    const std::filesystem::path& lhs_path,
    const std::filesystem::path& rhs_path,
    const BinaryDiffOptions& options = {});

// ---------------------------------------------------------------------------
// On-Disk vs. Live-Attached RAM Integrity & Hook Diff
// ---------------------------------------------------------------------------

struct LiveLoaderSlotEntry {
    std::string category{}; // "IAT" or "GOT/PLT"
    std::string library{};
    std::string symbol_name{};
    std::uint64_t live_slot_va{0};
    std::uint64_t rva{0};
    std::uint64_t disk_value{0};
    std::uint64_t live_target_va{0};
    std::string target_module_name{};
    bool is_hooked{false};
    std::string detail{};
};

struct LiveIntegrityDiffOptions {
    std::uint64_t coalesce_gap_bytes{4};
    std::size_t max_hunks{2048};
    std::size_t sample_bytes_per_hunk{24};
    bool include_writable_data_hunks{false};
};

struct LiveModuleIntegrityReport {
    std::string module_name{};
    std::string disk_path{};
    std::uint64_t static_preferred_base{0};
    std::uint64_t live_base_address{0};
    std::int64_t aslr_load_bias{0};
    std::string disk_sha256{};

    std::size_t normalized_relocation_count{0};
    std::size_t normalized_loader_slot_count{0};
    std::size_t inline_code_hook_count{0};
    std::size_t iat_got_hook_count{0};
    std::size_t readonly_data_diff_count{0};
    std::uint64_t writable_data_changed_bytes{0};
    std::uint64_t unreadable_live_bytes{0};

    std::vector<ByteDiffHunk> findings{};
    std::vector<LiveLoaderSlotEntry> loader_slots{};
    SubsystemStatus status{};
};

[[nodiscard]] Result<LiveModuleIntegrityReport> compare_module_disk_to_live(
    const IBinaryImage& disk_image,
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    const LiveIntegrityDiffOptions& options = {});

[[nodiscard]] Result<LiveModuleIntegrityReport> compare_module_disk_to_live(
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    const LiveIntegrityDiffOptions& options = {});

} // namespace peelf
