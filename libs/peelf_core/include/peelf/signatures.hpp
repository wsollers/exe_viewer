// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/process.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

namespace detail {
struct CompiledSignatureRuleBody;
} // namespace detail

// ---------------------------------------------------------------------------
// A. PE Rich Header Decoder
// ---------------------------------------------------------------------------

struct PeRichCompIdEntry {
    std::uint16_t build_number{0};
    std::uint16_t prod_id{0};
    std::uint32_t use_count{0};
    std::string tool_category{};
    std::uint64_t file_offset{0};

    [[nodiscard]] constexpr std::uint32_t comp_id_dword() const noexcept {
        return (static_cast<std::uint32_t>(prod_id) << 16u) |
               static_cast<std::uint32_t>(build_number);
    }
};

struct PeRichHeader {
    std::uint64_t dans_offset{0};
    std::uint64_t rich_offset{0};
    std::uint64_t byte_length{0};
    std::uint32_t xor_key{0};
    std::uint32_t computed_checksum{0};
    bool checksum_valid{false};
    bool padding_valid{true};
    std::vector<PeRichCompIdEntry> entries{};
    std::string diagnostic{};
};

/// Maps a packed 32-bit `(prod_id << 16) | build_number` value to a human-friendly
/// Microsoft MSVC / MASM / Linker / Resource toolchain label.
[[nodiscard]] std::string describe_pe_rich_comp_id(std::uint32_t comp_id_dword);

/// Decodes and verifies the PE Rich header between `0x40` (`sizeof(IMAGE_DOS_HEADER)`)
/// and `e_lfanew` (`PE\0\0`). Safely returns `std::nullopt` for non-PE images,
/// stubless PEs, absent Rich headers, or truncated inputs without throwing or UB.
[[nodiscard]] std::optional<PeRichHeader> parse_pe_rich_header(
    std::span<const std::uint8_t> raw_bytes) noexcept;

// ---------------------------------------------------------------------------
// B. Crypto, Hash, Compression, & Packer Constant Detector
// ---------------------------------------------------------------------------

/// Computes Shannon byte entropy in `[0.0, 8.0]` bits/byte (`0.0` for empty input).
[[nodiscard]] double compute_shannon_entropy(std::span<const std::uint8_t> bytes) noexcept;

struct CryptoSignatureHit {
    std::string id{};
    std::string category{};
    std::string algorithm{};
    std::string summary{};
    std::string confidence{};
    std::optional<std::uint64_t> file_offset{};
    std::optional<std::uint64_t> virtual_address{};
    std::uint64_t byte_length{0};
    std::string section_name{};
};

/// Scans static binary bytes for symmetric cipher S-boxes/constants, cryptographic hash IVs/tables,
/// CRC lookup tables, compression headers/tables, packer markers/sections, and high-entropy
/// packed executable sections. Resolves file offsets to VAs and section names when `image != nullptr`.
[[nodiscard]] std::vector<CryptoSignatureHit> scan_crypto_and_packer_constants(
    std::span<const std::uint8_t> raw_bytes,
    const IBinaryImage* image = nullptr);

/// Scans readable memory regions of an attached live process or offline crash dump session
/// in bounded chunks for crypto constants, compression markers, and high-entropy executable regions.
[[nodiscard]] std::vector<CryptoSignatureHit> scan_crypto_and_packer_constants(
    IProcessSession& session,
    std::size_t max_bytes_per_region = 16u * 1024u * 1024u);

// ---------------------------------------------------------------------------
// C. Clean-Room YARA-Lite Rule Parser & Evaluator
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxSignatureHexJumpSpan = 4096u;

struct SignatureRuleSourceName {
    std::string_view value{"<inline>"};

    constexpr SignatureRuleSourceName() noexcept = default;
    constexpr SignatureRuleSourceName(std::string_view name) noexcept
        : value(name.empty() ? std::string_view{"<inline>"} : name) {}
    constexpr SignatureRuleSourceName(const char* name) noexcept
        : value((name != nullptr && *name != '\0') ? std::string_view{name}
                                                   : std::string_view{"<inline>"}) {}
};

struct SignatureRuleDiagnostic {
    std::string source_name{};
    std::uint32_t line{1};
    std::uint32_t column{1};
    std::string message{};
};

struct SignatureRule {
    std::string name{};
    std::vector<std::string> tags{};
    std::string description{};
    std::string severity{"warning"};
    std::string author{};
    std::string source_name{};
    std::vector<std::pair<std::string, std::string>> metadata{};
    std::shared_ptr<const detail::CompiledSignatureRuleBody> compiled{};
};

struct SignatureRuleSet {
    std::vector<SignatureRule> rules{};

    [[nodiscard]] bool empty() const noexcept { return rules.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return rules.size(); }

    void append(const SignatureRuleSet& other);
};

struct SignatureRuleParseResult {
    SignatureRuleSet ruleset{};
    std::vector<SignatureRuleDiagnostic> diagnostics{};

    [[nodiscard]] bool ok() const noexcept { return diagnostics.empty(); }
};

struct SignatureStringMatch {
    std::string identifier{};
    std::optional<std::uint64_t> file_offset{};
    std::optional<std::uint64_t> virtual_address{};
    std::uint64_t byte_length{0};
    std::string section_name{};
    std::string matched_preview{};
};

struct SignatureRuleMatch {
    std::string rule_name{};
    std::vector<std::string> tags{};
    std::string description{};
    std::string severity{"warning"};
    std::string author{};
    std::string source_name{};
    std::uint64_t total_match_count{0};
    std::vector<SignatureStringMatch> string_matches{};
};

/// Parses and compiles YARA-lite rules from text, collecting exact 1-based `line:column` diagnostics.
[[nodiscard]] SignatureRuleParseResult parse_signature_rules(
    std::string_view source,
    SignatureRuleSourceName source_name = {});

/// Reads a `.yar` / `.yara` / `.rules` file from disk and parses its rules.
[[nodiscard]] Result<SignatureRuleParseResult> load_signature_rules_file(
    const std::filesystem::path& path);

/// Returns the canonical source text of the built-in zero-false-positive starter rule pack.
[[nodiscard]] std::string_view builtin_signature_rules_source() noexcept;

/// Returns the precompiled built-in starter rule pack.
[[nodiscard]] const SignatureRuleSet& builtin_signature_rules();

/// Evaluates compiled YARA-lite rules against static binary bytes (resolving VAs & section names
/// via `image` when available).
[[nodiscard]] std::vector<SignatureRuleMatch> evaluate_signature_rules(
    const SignatureRuleSet& ruleset,
    std::span<const std::uint8_t> raw_bytes,
    const IBinaryImage* image = nullptr);

/// Evaluates compiled YARA-lite rules across readable memory regions of an attached live process
/// or offline crash dump session.
[[nodiscard]] std::vector<SignatureRuleMatch> evaluate_signature_rules(
    const SignatureRuleSet& ruleset,
    IProcessSession& session,
    std::size_t max_bytes_per_region = 16u * 1024u * 1024u);

} // namespace peelf
