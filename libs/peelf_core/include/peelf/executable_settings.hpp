#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/provenance.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

/// Explicit structural state distinguishing genuinely absent optional metadata
/// from malformed or truncated payloads.
enum class MetadataFieldState : std::uint8_t {
    Present = 0,
    Absent,
    Malformed,
    Truncated,
    UnsupportedFormat,
};

[[nodiscard]] constexpr std::string_view to_string(MetadataFieldState state) noexcept {
    switch (state) {
        case MetadataFieldState::Present:           return "Present";
        case MetadataFieldState::Absent:            return "Absent";
        case MetadataFieldState::Malformed:         return "Malformed";
        case MetadataFieldState::Truncated:         return "Truncated";
        case MetadataFieldState::UnsupportedFormat: return "UnsupportedFormat";
    }
    return "Absent";
}

// ---------------------------------------------------------------------------
// PE Static Declared Metadata (`RT_MANIFEST`, `RT_VERSION`, `COR20` / `BSJB`)
// ---------------------------------------------------------------------------

struct PeAssemblyIdentity {
    std::string name;
    std::string version;
    std::string processor_architecture;
    std::string type;
    std::string public_key_token;
    std::string language;

    auto operator<=>(const PeAssemblyIdentity&) const = default;
};

struct PeSupportedOsEntry {
    std::string guid;
    std::string friendly_name;

    auto operator<=>(const PeSupportedOsEntry&) const = default;
};

struct PeManifestInfo {
    std::uint32_t resource_name_id{0};
    std::uint32_t language_id{0};
    std::uint32_t data_rva{0};
    std::uint64_t file_offset{0};
    std::uint32_t raw_size{0};
    std::string encoding;

    // UAC & execution settings
    std::string requested_execution_level;
    std::optional<bool> ui_access;
    std::optional<bool> auto_elevate;

    // Display, path, and heap settings
    std::string dpi_aware;
    std::string dpi_awareness;
    std::optional<bool> long_path_aware;
    std::string heap_type;
    std::optional<bool> disable_theming;
    std::optional<bool> printer_driver_isolation;

    // Compatibility & SxS assembly dependencies
    std::optional<PeAssemblyIdentity> assembly_identity;
    std::vector<PeAssemblyIdentity> dependent_assemblies;
    std::vector<PeSupportedOsEntry> supported_os;

    // Bounded UTF-8 normalized XML payload (<= 1 MiB)
    std::string raw_xml;
    std::vector<std::string> warnings;
};

struct PeFixedFileInfo {
    std::uint32_t signature{0};
    std::uint32_t struct_version{0};
    std::uint16_t file_version_major{0};
    std::uint16_t file_version_minor{0};
    std::uint16_t file_version_build{0};
    std::uint16_t file_version_revision{0};
    std::uint16_t product_version_major{0};
    std::uint16_t product_version_minor{0};
    std::uint16_t product_version_build{0};
    std::uint16_t product_version_revision{0};
    std::string file_version_string;
    std::string product_version_string;
    std::uint32_t file_flags_mask{0};
    std::uint32_t file_flags{0};
    std::vector<std::string> decoded_file_flags;
    std::uint32_t file_os{0};
    std::string decoded_file_os;
    std::uint32_t file_type{0};
    std::string decoded_file_type;
    std::uint32_t file_subtype{0};
};

struct PeStringTableBlock {
    std::string language_codepage_hex;
    std::uint16_t language_id{0};
    std::uint16_t code_page{0};
    std::uint32_t resource_language_id{0};
    std::vector<std::pair<std::string, std::string>> entries;
};

struct PeVarTranslation {
    std::uint16_t language_id{0};
    std::uint16_t code_page{0};

    auto operator<=>(const PeVarTranslation&) const = default;
};

struct PeVersionInfo {
    std::uint32_t data_rva{0};
    std::uint64_t file_offset{0};
    std::uint32_t raw_size{0};
    std::optional<PeFixedFileInfo> fixed_info;
    std::vector<PeStringTableBlock> string_tables;
    std::vector<PeVarTranslation> translations;
    std::vector<std::string> warnings;
};

struct PeClrStreamInfo {
    std::string name;
    std::uint32_t offset{0};
    std::uint32_t size{0};
    bool in_bounds{false};

    auto operator<=>(const PeClrStreamInfo&) const = default;
};

struct PeClrSummary {
    std::uint32_t header_rva{0};
    std::uint64_t header_file_offset{0};
    std::uint32_t header_size{0};
    std::uint16_t major_runtime_version{0};
    std::uint16_t minor_runtime_version{0};
    std::uint32_t cor20_flags{0};
    std::vector<std::string> decoded_flags;
    std::uint32_t entry_point_token_or_rva{0};
    std::uint32_t metadata_rva{0};
    std::uint64_t metadata_file_offset{0};
    std::uint32_t metadata_size{0};
    bool metadata_signature_valid{false};
    std::string runtime_version_string;
    std::vector<PeClrStreamInfo> streams;
    std::vector<std::string> warnings;
};

// ---------------------------------------------------------------------------
// ELF Static Declared Metadata (`PT_INTERP`, Notes, `DT_*`)
// ---------------------------------------------------------------------------

struct ElfAbiTag {
    std::uint32_t os_id{0};
    std::string os_name;
    std::uint32_t major{0};
    std::uint32_t minor{0};
    std::uint32_t patch{0};
    std::string min_kernel;

    auto operator<=>(const ElfAbiTag&) const = default;
};

struct ElfDeclaredSettings {
    std::optional<std::string> interpreter;
    std::optional<ElfAbiTag> abi_tag;
    std::optional<std::string> build_id_hex;
    std::optional<std::string> soname;
    std::string raw_rpath;
    std::vector<std::string> rpath_entries;
    std::string raw_runpath;
    std::vector<std::string> runpath_entries;
    std::vector<std::string> needed_libraries;
    std::optional<std::uint64_t> dt_flags;
    std::vector<std::string> decoded_dt_flags;
    std::optional<std::uint64_t> dt_flags_1;
    std::vector<std::string> decoded_dt_flags_1;
    bool is_pie{false};
    bool bind_now{false};
    bool no_dlopen{false};
    bool no_delete{false};
    std::vector<std::string> warnings;
};

// ---------------------------------------------------------------------------
// Unified 3-Section Executable & Settings Overview (`WU-22` + `WU-23`)
// ---------------------------------------------------------------------------

struct DeclaredSettings {
    Format format{Format::Unknown};
    ImageKind kind{ImageKind::Unknown};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Little};
    bool is_64bit{false};
    std::uint64_t image_base{0};
    std::uint64_t entry_point{0};

    // Format-level static configuration summary
    std::optional<std::uint16_t> pe_subsystem;
    std::string pe_subsystem_name;
    std::optional<std::uint64_t> pe_stack_reserve;
    std::optional<std::uint64_t> pe_stack_commit;
    std::optional<std::uint64_t> pe_heap_reserve;
    std::optional<std::uint64_t> pe_heap_commit;
    std::vector<std::string> declared_dependencies;

    // PE optional declared metadata blocks
    MetadataFieldState pe_manifest_state{MetadataFieldState::UnsupportedFormat};
    Observed<PeManifestInfo> pe_manifest;

    MetadataFieldState pe_version_state{MetadataFieldState::UnsupportedFormat};
    Observed<PeVersionInfo> pe_version;

    MetadataFieldState pe_clr_state{MetadataFieldState::UnsupportedFormat};
    Observed<PeClrSummary> pe_clr;

    // ELF declared metadata block
    MetadataFieldState elf_settings_state{MetadataFieldState::UnsupportedFormat};
    Observed<ElfDeclaredSettings> elf_settings;
};

/// Environment redaction policy (`WU-23`: redacted by default unless explicitly opted in).
enum class EnvironmentRedactionPolicy : std::uint8_t {
    RedactSensitiveDefault = 0,
    RedactAllValues,
    RevealUnredactedOptIn,
};

[[nodiscard]] constexpr std::string_view to_string(EnvironmentRedactionPolicy policy) noexcept {
    switch (policy) {
        case EnvironmentRedactionPolicy::RedactSensitiveDefault: return "RedactSensitiveDefault";
        case EnvironmentRedactionPolicy::RedactAllValues:        return "RedactAllValues";
        case EnvironmentRedactionPolicy::RevealUnredactedOptIn:  return "RevealUnredactedOptIn";
    }
    return "RedactSensitiveDefault";
}

/// Origin of observed process launch/environment telemetry (`WU-23`), explicitly
/// distinguishing launch-time capture from current state sampled after attach.
enum class EnvironmentCaptureOrigin : std::uint8_t {
    Unavailable = 0,
    LaunchCaptured,
    AttachedCurrentState,
    CrashDumpState,
};

[[nodiscard]] constexpr std::string_view to_string(EnvironmentCaptureOrigin origin) noexcept {
    switch (origin) {
        case EnvironmentCaptureOrigin::Unavailable:          return "Unavailable";
        case EnvironmentCaptureOrigin::LaunchCaptured:       return "LaunchCaptured";
        case EnvironmentCaptureOrigin::AttachedCurrentState: return "AttachedCurrentState";
        case EnvironmentCaptureOrigin::CrashDumpState:       return "CrashDumpState";
    }
    return "Unavailable";
}

struct EnvironmentVariableEntry {
    std::string key;
    std::string display_value;
    std::size_t raw_length{0};
    bool redacted{false};
    CaptureAvailability availability{CaptureAvailability::Complete};

    auto operator<=>(const EnvironmentVariableEntry&) const = default;
};

struct LaunchEnvironmentSettings {
    EnvironmentCaptureOrigin capture_origin{EnvironmentCaptureOrigin::Unavailable};
    std::filesystem::path executable_path;
    Observed<std::vector<std::string>> argv;
    Observed<std::filesystem::path> cwd;
    EnvironmentRedactionPolicy redaction_policy{
        EnvironmentRedactionPolicy::RedactSensitiveDefault};
    Observed<std::vector<EnvironmentVariableEntry>> environment;
    Observed<ProcessSecurityProfile> security_profile;
};

struct UnmatchedLoadedModule {
    std::string module_name;
    std::filesystem::path path;
    std::uint64_t base_address{0};
    std::string provenance_note;
};

struct DeclaredVsLoadedModuleComparison {
    std::vector<std::string> matched_declared;
    std::vector<std::string> missing_declared;
    std::vector<UnmatchedLoadedModule> unmatched_loaded;
    bool runtime_load_proven_by_timeline{false};
    std::string summary;
};

struct ObservedRuntimeConfiguration {
    Observed<std::vector<ModuleInfo>> loaded_modules;
    Observed<std::vector<ProcessHandleEntry>> open_handles;
    Observed<std::vector<ProcessSocketEntry>> sockets;
    Observed<DeclaredVsLoadedModuleComparison> declared_vs_loaded;
};

struct ExecutableSettingsReport {
    static constexpr std::uint32_t kSchemaVersion = 1u;

    std::uint32_t schema_version{kSchemaVersion};
    TargetProfile target_profile{};
    Observed<DeclaredSettings> declared_in_file;
    Observed<LaunchEnvironmentSettings> launch_environment;
    Observed<ObservedRuntimeConfiguration> observed_runtime;
};

/// Returns true if an environment variable name or value matches default secret/credential
/// heuristics (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*API_KEY*`, `AWS_*`, `AZURE_*`,
/// `GITHUB_*`, `GH_*`, credential URLs, etc.).
[[nodiscard]] bool is_sensitive_environment_variable(
    std::string_view key,
    std::string_view raw_value = {}) noexcept;

/// Applies `policy` to a raw `(key, value)` environment variable pair.
[[nodiscard]] EnvironmentVariableEntry format_environment_variable_entry(
    std::string_view key,
    std::string_view raw_value,
    EnvironmentRedactionPolicy policy = EnvironmentRedactionPolicy::RedactSensitiveDefault);

/// Extracts bounded, non-networked static `DeclaredSettings` from `image` + `raw_bytes`,
/// and marks `launch_environment` and `observed_runtime` explicitly `Unavailable` for
/// static-only loads (never leaving runtime sections ambiguously blank).
[[nodiscard]] ExecutableSettingsReport extract_executable_settings(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const CaptureStamp& static_stamp = {});

/// Options controlling live/crash-dump population of `ExecutableSettingsReport`
/// runtime sections (`launch_environment` and `observed_runtime`).
struct RuntimeSettingsOptions {
    EnvironmentRedactionPolicy redaction_policy{
        EnvironmentRedactionPolicy::RedactSensitiveDefault};
    bool launched_by_session{false};
    bool query_process_internals{true};
    std::filesystem::path resolved_executable_path{};
    std::span<const std::uint64_t> timeline_proven_dynamic_bases{};
};

/// Parse a `"KEY=VALUE"` environment entry and format it according to `policy`.
[[nodiscard]] EnvironmentVariableEntry parse_and_format_environment_entry(
    std::string_view raw_key_value,
    EnvironmentRedactionPolicy policy = EnvironmentRedactionPolicy::RedactSensitiveDefault);

/// Reconciles statically declared root library dependencies against observed loaded modules.
/// Unmatched loaded modules are reported honestly as unmatched against root imports unless
/// `timeline_proven_dynamic_bases` supplies explicit snapshot/timeline load delta evidence.
[[nodiscard]] Observed<DeclaredVsLoadedModuleComparison> reconcile_declared_vs_loaded_modules(
    const Observed<DeclaredSettings>& declared_in_file,
    const Observed<std::vector<ModuleInfo>>& loaded_modules,
    const std::filesystem::path& main_executable_path = {},
    std::span<const std::uint64_t> timeline_proven_dynamic_bases = {});

/// Builds `LaunchEnvironmentSettings` for `session` (`argv`, `cwd`, redacted-by-default
/// `environment`, and `ProcessSecurityProfile`), distinguishing `LaunchCaptured`,
/// `AttachedCurrentState`, and `CrashDumpState`.
[[nodiscard]] Observed<LaunchEnvironmentSettings> extract_launch_environment_settings(
    IProcessSession& session,
    const TargetInstanceId& target_id,
    std::uint64_t snapshot_revision,
    const RuntimeSettingsOptions& options = {},
    const Observed<ProcessSecurityProfile>* pre_captured_security = nullptr,
    const std::string* fallback_cwd = nullptr);

/// Populates `report.launch_environment` and `report.observed_runtime` from `session`
/// (reusing optional pre-captured internals/modules when provided).
void populate_runtime_executable_settings(
    ExecutableSettingsReport& report,
    IProcessSession& session,
    const TargetInstanceId& target_id,
    std::uint64_t snapshot_revision,
    const RuntimeSettingsOptions& options = {},
    const ProcessInternalsSnapshot* cached_internals = nullptr,
    const CaptureStamp* cached_internals_stamp = nullptr,
    std::span<const ModuleInfo> cached_modules = {},
    const CaptureStamp* cached_modules_stamp = nullptr,
    const std::string* fallback_cwd = nullptr);

/// Convenience entry point extracting both static `declared_in_file` (when `image != nullptr`)
/// and live/dump `launch_environment` + `observed_runtime` sections for `session`.
[[nodiscard]] ExecutableSettingsReport extract_executable_settings_for_session(
    const IBinaryImage* image,
    std::span<const std::uint8_t> raw_bytes,
    IProcessSession& session,
    const RuntimeSettingsOptions& options = {},
    const CaptureStamp& static_stamp = {});

/// Serializes `ExecutableSettingsReport` as deterministic versioned JSON (`schema_version: 1`).
/// `base_indent` shifts every line after the opening `{` so callers can embed it cleanly.
[[nodiscard]] std::string format_executable_settings_json(
    const ExecutableSettingsReport& report,
    std::size_t base_indent = 0);

} // namespace peelf
