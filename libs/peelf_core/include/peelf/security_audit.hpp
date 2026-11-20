#pragma once

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/dependency_tree.hpp>
#include <peelf/error.hpp>
#include <peelf/executable_settings.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/provenance.hpp>
#include <peelf/signatures.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class SecuritySeverity : std::uint8_t {
    Pass = 0,
    Note = 1,
    Warning = 2,
    Error = 3,
};

[[nodiscard]] constexpr std::string_view to_string(SecuritySeverity severity) noexcept {
    switch (severity) {
        case SecuritySeverity::Pass:    return "Pass";
        case SecuritySeverity::Note:    return "Note";
        case SecuritySeverity::Warning: return "Warning";
        case SecuritySeverity::Error:   return "Error";
    }
    return "Note";
}

enum class SecurityRuleDomain : std::uint8_t {
    PE = 0,
    ELF = 1,
    MachO = 2,
    LiveProcess = 3,
};

[[nodiscard]] constexpr std::string_view to_string(SecurityRuleDomain domain) noexcept {
    switch (domain) {
        case SecurityRuleDomain::PE:          return "PE";
        case SecurityRuleDomain::ELF:         return "ELF";
        case SecurityRuleDomain::MachO:       return "MachO";
        case SecurityRuleDomain::LiveProcess: return "LiveProcess";
    }
    return "PE";
}

struct SecurityRuleDescriptor {
    std::string_view id{};
    std::string_view name{};
    SecurityRuleDomain domain{SecurityRuleDomain::PE};
    SecuritySeverity default_failure_severity{SecuritySeverity::Warning};
    std::string_view short_description{};
    std::string_view help_text{};
};

struct SecurityFinding {
    std::string rule_id{};
    std::string rule_name{};
    SecurityRuleDomain domain{SecurityRuleDomain::PE};
    SecuritySeverity severity{SecuritySeverity::Pass};
    std::string subject{};
    std::string summary{};
    std::string evidence{};
    std::string remediation{};
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> file_offset{};
};

struct SecurityAuditReport {
    Format target_format{Format::Unknown};
    bool includes_live_process{false};
    std::size_t pass_count{0};
    std::size_t note_count{0};
    std::size_t warning_count{0};
    std::size_t error_count{0};
    std::vector<SecurityFinding> findings{};
    SubsystemStatus status{};
};

/// Returns the catalog of formalized security & hardening rules (`PE1001..PE1008`,
/// `ELF2001..ELF2008`, `MACHO4001..MACHO4006`, `LIVE3001..LIVE3003`).
[[nodiscard]] std::span<const SecurityRuleDescriptor> security_rule_catalog() noexcept;

/// Evaluates static PE (`PE1001..PE1008`), ELF (`ELF2001..ELF2008`), or Mach-O
/// (`MACHO4001..MACHO4006`) security rules against `image` (plus optional
/// `LIVE3001..LIVE3003` when `live_session != nullptr`).
[[nodiscard]] SecurityAuditReport audit_security(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes = {},
    IProcessSession* live_session = nullptr,
    const ProcessSecurityProfile* preloaded_security_profile = nullptr);

/// Evaluates live-process security rules (`LIVE3001..LIVE3003`) against an attached session.
[[nodiscard]] SecurityAuditReport audit_live_process_security(
    IProcessSession& session,
    const ProcessSecurityProfile* preloaded_security_profile = nullptr);

// ---------------------------------------------------------------------------
// Headless CLI Inspection, Comparison & Export (`WU-13`)
// ---------------------------------------------------------------------------

enum class HeadlessExportFormat : std::uint8_t {
    Json = 0,
    Sarif = 1,
    Csv = 2,
};

[[nodiscard]] constexpr std::string_view to_string(HeadlessExportFormat fmt) noexcept {
    switch (fmt) {
        case HeadlessExportFormat::Json:  return "json";
        case HeadlessExportFormat::Sarif: return "sarif";
        case HeadlessExportFormat::Csv:   return "csv";
    }
    return "json";
}

enum class HeadlessFailPolicy : std::uint8_t {
    None = 0,
    Error = 1,
    Warning = 2,
};

[[nodiscard]] constexpr std::string_view to_string(HeadlessFailPolicy policy) noexcept {
    switch (policy) {
        case HeadlessFailPolicy::None:    return "none";
        case HeadlessFailPolicy::Error:   return "error";
        case HeadlessFailPolicy::Warning: return "warning";
    }
    return "none";
}

struct HeadlessExtractedString {
    std::string value{};
    std::string encoding{}; // "ASCII" or "UTF-16LE" / "UTF-16BE"
    std::string section_name{};
    std::uint64_t virtual_address{0};
    std::uint64_t file_offset{0};
    std::size_t byte_length{0};
};

struct HeadlessCliOptions {
    std::filesystem::path binary_path{};
    std::optional<std::filesystem::path> compare_path{};
    std::optional<std::filesystem::path> output_path{};
    std::optional<std::string> slice_selector{};
    std::vector<std::filesystem::path> search_roots{};
    std::vector<std::filesystem::path> rule_paths{};
    HeadlessExportFormat format{HeadlessExportFormat::Json};
    HeadlessFailPolicy fail_on{HeadlessFailPolicy::None};
    bool include_builtin_rules{true};
    bool include_strings{false};
    std::size_t min_string_length{4};
    std::size_t max_strings{4096};
};

struct HeadlessAnalysisReport {
    std::filesystem::path binary_path{};
    std::string sha256{};
    std::uint64_t file_size{0};
    BinaryContainerInfo container_info{};
    std::size_t selected_slice_index{0};
    std::string selected_slice_arch{};
    std::unique_ptr<IBinaryImage> image{};
    std::unique_ptr<ICrashDumpSession> crash_dump{};
    TargetProfile target_profile{};
    TargetCapabilityMatrix capabilities{};
    CaptureStamp analysis_stamp{};
    ProvenanceTag primary_provenance{ProvenanceTag::DiskFile};
    DependencyGraph dependencies{};
    ExecutableSettingsReport executable_settings{};
    SecurityAuditReport security{};
    std::optional<PeRichHeader> pe_rich_header{};
    std::vector<CryptoSignatureHit> crypto_hits{};
    std::vector<SignatureRuleMatch> rule_matches{};
    bool strings_included{false};
    std::vector<HeadlessExtractedString> strings{};
    std::optional<BinaryDiffReport> comparison{};
};

/// Extracts printable ASCII and UTF-16 strings from mapped sections of `image`.
[[nodiscard]] std::vector<HeadlessExtractedString> extract_headless_strings(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    std::size_t min_length = 4,
    std::size_t max_strings = 4096);

/// Performs complete headless static analysis (identity, sections, imports, exports,
/// demangled symbols, `WU-10` dependency graph, `WU-13` security audit, optional strings,
/// and optional `WU-12` binary comparison).
[[nodiscard]] Result<HeadlessAnalysisReport> analyze_binary_headless(
    const HeadlessCliOptions& options);

/// Serializes `report` to deterministic JSON.
[[nodiscard]] std::string format_headless_report_json(
    const HeadlessAnalysisReport& report);

/// Serializes `report` to valid OASIS SARIF 2.1.0 JSON for CI / GitHub Code Scanning.
[[nodiscard]] std::string format_headless_report_sarif(
    const HeadlessAnalysisReport& report);

/// Serializes `report` to RFC 4180 CSV summary rows (summary, sections, imports, exports,
/// security findings, YARA-lite rule matches, and crypto/packer constant hits).
[[nodiscard]] std::string format_headless_report_csv(
    const HeadlessAnalysisReport& report);

/// Evaluates deterministic CI exit code (`0` = clean, `2` = policy violation triggered by `fail_on`).
[[nodiscard]] int evaluate_headless_policy_exit_code(
    const HeadlessAnalysisReport& report,
    HeadlessFailPolicy fail_on) noexcept;

/// Parses `argv` (excluding `argv[0]`) and executes `--headless` / `--help` workflows.
/// Returns `std::nullopt` if neither `--headless` nor `--help` was requested (meaning
/// `peelf_viewer` should proceed to normal GUI startup).
/// Otherwise returns the deterministic process exit code (`0`, `1`, or `2`).
[[nodiscard]] std::optional<int> try_run_headless_or_help_cli(
    std::span<const std::string_view> args,
    std::ostream& stdout_stream,
    std::ostream& stderr_stream);

} // namespace peelf
