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
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

namespace peelf {

inline constexpr std::uint32_t kPatchBundleSchemaVersion = 1u;

struct PatchBundleEntry {
    std::uint64_t offset{0};
    std::optional<std::uint64_t> virtual_address{};
    std::string label{};
    std::optional<std::string> asm_source{};
    std::vector<std::uint8_t> original_bytes{};
    std::vector<std::uint8_t> patched_bytes{};
};

struct PatchBundle {
    std::uint32_t schema_version{kPatchBundleSchemaVersion};
    std::string name{};
    std::string description{};
    Format target_format{Format::Unknown};
    Architecture target_arch{Architecture::Unknown};
    std::string expected_sha256{};
    std::uint64_t expected_size{0};
    std::vector<PatchBundleEntry> entries{};
};

enum class PatchEntryConflictKind : std::uint8_t {
    Clean = 0,
    AlreadyApplied = 1,
    OriginalBytesMismatch = 2,
    OutOfBounds = 3,
    OverlappingEntry = 4,
    InvalidEntrySize = 5,
};

[[nodiscard]] constexpr std::string_view to_string(PatchEntryConflictKind kind) noexcept {
    switch (kind) {
        case PatchEntryConflictKind::Clean:                 return "Clean";
        case PatchEntryConflictKind::AlreadyApplied:        return "AlreadyApplied";
        case PatchEntryConflictKind::OriginalBytesMismatch: return "OriginalBytesMismatch";
        case PatchEntryConflictKind::OutOfBounds:           return "OutOfBounds";
        case PatchEntryConflictKind::OverlappingEntry:      return "OverlappingEntry";
        case PatchEntryConflictKind::InvalidEntrySize:      return "InvalidEntrySize";
    }
    return "InvalidEntrySize";
}

struct PatchBundleEntryPreview {
    std::size_t entry_index{0};
    std::uint64_t offset{0};
    std::optional<std::uint64_t> virtual_address{};
    std::uint64_t size{0};
    std::string label{};
    PatchEntryConflictKind status{PatchEntryConflictKind::Clean};
    std::vector<std::uint8_t> actual_effective_bytes{};
    std::vector<std::uint8_t> actual_original_bytes{};
    std::string detail{};
};

struct PatchBundleApplyOptions {
    bool allow_hash_mismatch_if_original_bytes_match{false};
    bool allow_already_applied_entries{false};
    std::string transaction_label{};
};

struct PatchBundlePreview {
    std::string actual_sha256{};
    std::uint64_t actual_size{0};
    bool size_matches{false};
    bool sha256_matches{false};
    bool sha256_mismatch_overridden{false};
    std::size_t clean_count{0};
    std::size_t conflict_count{0};
    bool can_apply{false};
    std::string summary{};
    std::vector<PatchBundleEntryPreview> entry_previews{};
};

[[nodiscard]] std::string bytes_to_hex_string(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<std::vector<std::uint8_t>> hex_string_to_bytes(std::string_view hex);

/// Streams unpatched original bytes from `image` through `Sha256Hasher` without loading
/// the entire binary into memory at once.
[[nodiscard]] Result<std::string> compute_paged_image_original_sha256(const PagedBinaryImage& image);

/// Builds a `PatchBundle` capturing all currently staged dirty intervals in `editable`.
[[nodiscard]] Result<PatchBundle> export_patch_bundle_from_image(
    const PagedBinaryImage& editable,
    const IBinaryImage* parsed_image = nullptr,
    std::string name = {},
    std::string description = {});

[[nodiscard]] std::string encode_patch_bundle_json(const PatchBundle& bundle);
[[nodiscard]] Result<PatchBundle> decode_patch_bundle_json(std::string_view json_text);

[[nodiscard]] Result<void> save_patch_bundle_file(const PatchBundle& bundle,
                                                  const std::filesystem::path& path);
[[nodiscard]] Result<PatchBundle> load_patch_bundle_file(const std::filesystem::path& path);

/// Validates target SHA-256, file size, bounds, overlapping entries, and every entry's
/// `original_bytes` against `target` without modifying `target`.
/// Strictly rejects read-only live process sessions when `live_session != nullptr`.
[[nodiscard]] Result<PatchBundlePreview> preview_patch_bundle(
    const PatchBundle& bundle,
    const PagedBinaryImage& target,
    const PatchBundleApplyOptions& options = {},
    const IProcessSession* live_session = nullptr);

/// Validates and applies `bundle` atomically via `PagedBinaryImage::begin_transaction(...)`.
/// Any validation or write failure leaves `target` completely unmodified.
[[nodiscard]] Result<void> apply_patch_bundle(
    const PatchBundle& bundle,
    PagedBinaryImage& target,
    const PatchBundleApplyOptions& options = {},
    const IProcessSession* live_session = nullptr);

/// Explicit overload rejecting read-only live process sessions directly.
[[nodiscard]] Result<void> apply_patch_bundle(
    const PatchBundle& bundle,
    IProcessSession& live_session);

} // namespace peelf
