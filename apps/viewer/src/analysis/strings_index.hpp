#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "symbols/symbol_index.hpp"

namespace viewer {

enum class StringEncoding : std::uint8_t {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
};

[[nodiscard]] constexpr std::string_view to_string(StringEncoding encoding) noexcept {
    switch (encoding) {
    case StringEncoding::Ascii:   return "ASCII";
    case StringEncoding::Utf8:    return "UTF-8";
    case StringEncoding::Utf16Le: return "UTF-16LE";
    case StringEncoding::Utf16Be: return "UTF-16BE";
    }
    return "ASCII";
}

struct StringReferrer {
    std::uint64_t instruction_address = 0;
    std::uint64_t target_address = 0;
    std::optional<std::uint64_t> function_address{};
    std::string function_name{};
    std::string instruction_text{};
    ReferenceKind kind = ReferenceKind::Data;
    ReferenceConfidence confidence = ReferenceConfidence::Direct;
};

struct ExtractedString {
    std::uint64_t virtual_address = 0;
    std::optional<std::uint64_t> file_offset{};
    std::size_t byte_length = 0;
    std::size_t char_length = 0;
    StringEncoding encoding = StringEncoding::Ascii;
    std::string section_or_region_name{};
    std::string preview{};
    std::size_t xref_count = 0;
    std::vector<StringReferrer> referrers{};
};

struct StringScanOptions {
    static constexpr std::size_t kDefaultMinLength = 4;
    static constexpr std::size_t kDefaultMaxStringChars = 2048;
    static constexpr std::size_t kDefaultByteBudget = 64u * 1024u * 1024u;
    static constexpr std::size_t kDefaultChunkBytes = 256u * 1024u;

    std::size_t min_length = kDefaultMinLength;
    std::size_t max_string_chars = kDefaultMaxStringChars;
    std::size_t byte_budget = kDefaultByteBudget;
    std::size_t chunk_bytes = kDefaultChunkBytes;
    bool include_executable_sections = true;
    bool include_metadata_sections = false;
    bool include_all_live_regions = false;
};

/// Single-line escaped display helper (`\n` -> `\n`, `\r` -> `\r`, `\t` -> `\t`).
[[nodiscard]] std::string format_single_line_string_preview(std::string_view utf8_text,
                                                            std::size_t max_bytes = 256);

class StringsIndex {
public:
    StringsIndex() = default;

    [[nodiscard]] static StringsIndex extract(
        const peelf::IBinaryImage& image,
        std::span<const std::uint8_t> bytes,
        const StringScanOptions& options = {},
        std::stop_token stop = {});

    [[nodiscard]] static StringsIndex extract_live(
        peelf::IProcessSession& session,
        std::span<const peelf::MemoryRegion> regions,
        const peelf::IBinaryImage* active_image = nullptr,
        std::optional<std::uint64_t> active_module_base = std::nullopt,
        const StringScanOptions& options = {},
        std::stop_token stop = {});

    [[nodiscard]] static StringsIndex extract_from_buffer(
        std::span<const std::uint8_t> bytes,
        std::uint64_t base_virtual_address,
        std::optional<std::uint64_t> base_file_offset,
        std::string_view section_or_region_name,
        peelf::Endianness hint_endian = peelf::Endianness::Little,
        const StringScanOptions& options = {},
        bool is_executable_code = false,
        std::stop_token stop = {});

    /// Refreshes `xref_count` and `referrers` on every extracted string using
    /// `ReferenceIndex::incoming(va, byte_length)` + `FunctionIndex` / `SymbolIndex`.
    /// Returns true if xrefs were recomputed (e.g. `references.revision()` advanced).
    bool refresh_xrefs(const ReferenceIndex& references,
                       const FunctionIndex* functions = nullptr,
                       const SymbolIndex* symbols = nullptr,
                       std::uint64_t symbol_revision = 0);

    void clear() noexcept { *this = StringsIndex{}; }
    [[nodiscard]] std::span<const ExtractedString> entries() const noexcept { return entries_; }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] std::size_t min_length() const noexcept { return min_length_; }
    [[nodiscard]] bool incomplete() const noexcept { return incomplete_; }
    [[nodiscard]] std::uint64_t linked_reference_revision() const noexcept { return linked_reference_revision_; }
    [[nodiscard]] std::vector<std::string> sections_or_regions() const;

    [[nodiscard]] const ExtractedString* find_containing(std::uint64_t virtual_address) const noexcept;

private:
    std::vector<ExtractedString> entries_;
    std::size_t min_length_ = StringScanOptions::kDefaultMinLength;
    bool incomplete_ = false;
    std::uint64_t linked_reference_revision_ = 0;
    std::uint64_t linked_symbol_revision_ = 0;
    bool xrefs_initialized_ = false;
};

} // namespace viewer
