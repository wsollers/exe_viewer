#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class SearchScope : std::uint8_t {
    Heap,
    SelectedRegion,
    ActiveModule,
    AllReadable,
};

[[nodiscard]] constexpr std::string_view to_string(SearchScope scope) noexcept {
    switch (scope) {
        case SearchScope::Heap:           return "Heap";
        case SearchScope::SelectedRegion: return "Selected Region";
        case SearchScope::ActiveModule:   return "Active Module";
        case SearchScope::AllReadable:    return "All Readable";
    }
    return "Heap";
}

enum class SearchValueKind : std::uint8_t {
    HexPattern,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float32,
    Float64,
    Utf8Text,
    Utf16Text,
};

[[nodiscard]] constexpr std::string_view to_string(SearchValueKind kind) noexcept {
    switch (kind) {
        case SearchValueKind::HexPattern: return "Hex Bytes";
        case SearchValueKind::Int8:       return "int8";
        case SearchValueKind::UInt8:      return "uint8";
        case SearchValueKind::Int16:      return "int16";
        case SearchValueKind::UInt16:     return "uint16";
        case SearchValueKind::Int32:      return "int32";
        case SearchValueKind::UInt32:     return "uint32";
        case SearchValueKind::Int64:      return "int64";
        case SearchValueKind::UInt64:     return "uint64";
        case SearchValueKind::Float32:    return "float32";
        case SearchValueKind::Float64:    return "float64";
        case SearchValueKind::Utf8Text:   return "UTF-8 / ASCII";
        case SearchValueKind::Utf16Text:  return "UTF-16";
    }
    return "Hex Bytes";
}

struct MemorySearchQuery {
    SearchScope scope{SearchScope::Heap};
    SearchValueKind kind{SearchValueKind::HexPattern};
    std::string query_text;
    Endianness endianness{Endianness::Little};
    bool case_sensitive{true};
    std::size_t alignment{1};
    std::size_t max_results{4096};
    std::uint64_t max_region_bytes{512ull * 1024ull * 1024ull};
    std::uint64_t max_total_bytes{2ull * 1024ull * 1024ull * 1024ull};
};

struct WildcardByte {
    std::uint8_t value{0};
    std::uint8_t mask{0xFF};

    [[nodiscard]] constexpr bool matches(std::uint8_t candidate) const noexcept {
        return (candidate & mask) == (value & mask);
    }
};

struct MemorySearchHit {
    std::uint64_t address{0};
    std::uint64_t view_offset{0};
    std::size_t match_length{0};
    MemoryRegionKind region_kind{MemoryRegionKind::Unknown};
    std::string region_label;
    std::vector<std::uint8_t> matched_bytes;
    std::string decoded_preview;
};

struct MemorySearchReport {
    std::vector<MemorySearchHit> hits;
    std::size_t regions_scanned{0};
    std::size_t regions_skipped_oversized{0};
    std::uint64_t bytes_scanned{0};
    bool truncated{false};
    SubsystemStatus status{};
};

[[nodiscard]] Result<std::vector<WildcardByte>> compile_search_pattern(
    const MemorySearchQuery& query);

[[nodiscard]] Result<MemorySearchReport> search_buffer(
    std::span<const std::uint8_t> buffer,
    std::uint64_t base_address,
    const MemorySearchQuery& query,
    std::string_view region_label = "File",
    MemoryRegionKind kind = MemoryRegionKind::Image);

[[nodiscard]] Result<MemorySearchReport> search_process_memory(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    const MemorySearchQuery& query,
    std::optional<MemoryRegion> selected_region = std::nullopt,
    std::optional<ModuleInfo> active_module = std::nullopt);

}  // namespace peelf
