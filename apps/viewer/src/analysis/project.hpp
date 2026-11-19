#pragma once
#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

inline constexpr std::size_t kMaxProjectFileBytes = 64u * 1024u * 1024u;

struct AnalysisProject {
    static constexpr int kCurrentSchemaVersion = 2;

    int schema_version = kCurrentSchemaVersion;
    bool migrated_from_v1 = false;
    std::string source;
    std::string relative_source;
    std::string source_sha256;
    std::uint64_t source_size{};
    std::uint64_t fingerprint{};
    std::uint64_t saved_unix_ms{};
    std::vector<peelf::PatchInterval> patches;
    std::map<std::uint64_t, Annotation> annotations;
    std::vector<DebugSymbol> symbols;
    std::vector<Bookmark> bookmarks;
    std::vector<AppliedStructureBinding> structure_bindings;
    std::string custom_c_types_source;
    std::uint32_t custom_c_types_abi = 0;
    std::vector<DataTypeRecord> custom_types;
    std::vector<ViewerSelection> history;
    std::size_t cursor{};
    std::string layout;
    bool thumb = false;
};

enum class ProjectBinaryMatchStatus : std::uint8_t {
    ExactMatch,
    ModifiedMismatch,
    RelocationNeeded,
    ReadError,
};

struct ProjectBinaryResolution {
    ProjectBinaryMatchStatus status = ProjectBinaryMatchStatus::RelocationNeeded;
    std::filesystem::path resolved_path;
    std::vector<std::filesystem::path> tried_paths;
    std::string actual_sha256;
    std::uint64_t actual_size = 0;
    std::uint64_t actual_fingerprint = 0;
    std::string diagnostic;
};

[[nodiscard]] std::uint64_t binary_fingerprint(std::span<const std::uint8_t>) noexcept;
[[nodiscard]] std::uint64_t next_project_timestamp_ms() noexcept;

[[nodiscard]] AnalysisProject build_analysis_project(
    const BinaryModel& model,
    const std::filesystem::path& peproj_path = {},
    const std::map<std::uint64_t, Annotation>& annotations = {},
    std::span<const DebugSymbol> symbols = {},
    std::span<const ViewerSelection> history = {},
    std::size_t cursor = 0,
    std::string layout = {},
    bool thumb = false);

[[nodiscard]] std::string encode_project(const AnalysisProject&);
[[nodiscard]] peelf::Result<AnalysisProject> decode_project(std::string_view);

[[nodiscard]] ProjectBinaryResolution resolve_project_binary_path(
    const AnalysisProject& project,
    const std::filesystem::path& peproj_path,
    const std::filesystem::path& manual_relocated_path = {});

[[nodiscard]] peelf::Result<void> restore_project_patches(
    BinaryModel&,
    const AnalysisProject&,
    bool allow_modified_binary = false);

[[nodiscard]] peelf::Result<void> replace_project_patches_from_snapshot(
    BinaryModel&,
    const AnalysisProject&,
    bool allow_modified_binary = false);

[[nodiscard]] peelf::Result<std::string> read_project_file(const std::filesystem::path&);
[[nodiscard]] peelf::Result<void> write_analysis_file(const std::filesystem::path&, std::string_view);

// Off-/mnt/c autosave & crash-recovery journal helpers.
[[nodiscard]] std::filesystem::path default_project_recovery_directory();
[[nodiscard]] std::filesystem::path project_recovery_journal_path(
    const std::filesystem::path& key_path,
    const std::filesystem::path& recovery_dir = default_project_recovery_directory());
[[nodiscard]] peelf::Result<std::filesystem::path> write_recovery_journal(
    const AnalysisProject& project,
    const std::filesystem::path& key_path,
    const std::filesystem::path& recovery_dir = default_project_recovery_directory());
[[nodiscard]] std::optional<AnalysisProject> check_newer_recovery_journal(
    const std::filesystem::path& key_path,
    std::uint64_t baseline_saved_unix_ms = 0,
    const std::filesystem::path& recovery_dir = default_project_recovery_directory());
void clear_recovery_journal(
    const std::filesystem::path& key_path,
    const std::filesystem::path& recovery_dir = default_project_recovery_directory());

} // namespace viewer
