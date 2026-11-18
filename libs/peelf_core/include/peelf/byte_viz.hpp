#pragma once

// 2D Binary Byte-Entropy & Cantor-Dust Digram Minimap (WU-31).
//
// Pure C++23 headless analysis & CPU-reference rasterizer module with zero Vulkan
// or ImGui dependencies. Supports two complementary visual-analytics modes over
// static binaries (`IBinaryImage` + optional `PagedBinaryImage` + `ByteVizDiffRange`)
// and live / crash-dump memory mappings (`IProcessSession` / `ICrashDumpSession`):
//
//   1. `ByteVizMode::EntropyAndByteClass2D`:
//      Adaptive power-of-two / Hilbert or linear 2D tiles (`ByteVizTile`,
//      `alignas(16)`, `sizeof == 16`, SSBO `uvec4` compatible) encoding exact
//      Shannon entropy in `[0.0, 8.0]` bits/byte, dominant `ByteClass`,
//      printable / zero / high-bit byte ratios, and staged-patch / binary-diff /
//      section-boundary / executable flags.
//
//   2. `ByteVizMode::CantorDustDigram256`:
//      256x256 (`65,536`-bin) adjacent byte-pair `(b[i], b[i + 1])` attractor
//      plot (`..cantor.dust..` style) with exact pair counts, GPU-ready packed
//      `uint32_t` log-density + semantic pair class words, and representative
//      first-occurrence offset/VA per non-empty bin for one-click navigation.

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/memory_heatmap.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/provenance.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace peelf {

inline constexpr std::size_t kCantorDigramAxis = 256u;
inline constexpr std::size_t kCantorDigramBinCount = kCantorDigramAxis * kCantorDigramAxis; // 65,536
inline constexpr std::uint64_t kInvalidByteVizAddress = std::numeric_limits<std::uint64_t>::max();
inline constexpr std::size_t kDefaultByteVizMaxReadBytes = 64ull * 1024ull * 1024ull; // 64 MiB

enum class ByteVizMode : std::uint8_t {
    EntropyAndByteClass2D = 0,
    CantorDustDigram256 = 1,
};

[[nodiscard]] constexpr std::string_view to_string(ByteVizMode mode) noexcept {
    switch (mode) {
        case ByteVizMode::EntropyAndByteClass2D: return "EntropyAndByteClass2D";
        case ByteVizMode::CantorDustDigram256:   return "CantorDustDigram256";
    }
    return "EntropyAndByteClass2D";
}

enum class ByteVizLayout : std::uint8_t {
    HilbertCurve = 0,
    LinearRows = 1,
};

[[nodiscard]] constexpr std::string_view to_string(ByteVizLayout layout) noexcept {
    switch (layout) {
        case ByteVizLayout::HilbertCurve: return "HilbertCurve";
        case ByteVizLayout::LinearRows:   return "LinearRows";
    }
    return "HilbertCurve";
}

[[nodiscard]] constexpr MemoryHeatmapLayout to_heatmap_layout(ByteVizLayout layout) noexcept {
    return layout == ByteVizLayout::HilbertCurve ? MemoryHeatmapLayout::HilbertCurve
                                                 : MemoryHeatmapLayout::LinearRows;
}

enum class ByteVizColorMode : std::uint8_t {
    EntropySpectrum = 0,
    ByteClassSemantic = 1,
    PrintableVsHighBit = 2,
    PatchAndDiffOverlay = 3,
};

[[nodiscard]] constexpr std::string_view to_string(ByteVizColorMode mode) noexcept {
    switch (mode) {
        case ByteVizColorMode::EntropySpectrum:     return "EntropySpectrum";
        case ByteVizColorMode::ByteClassSemantic:   return "ByteClassSemantic";
        case ByteVizColorMode::PrintableVsHighBit:  return "PrintableVsHighBit";
        case ByteVizColorMode::PatchAndDiffOverlay: return "PatchAndDiffOverlay";
    }
    return "EntropySpectrum";
}

enum class ByteClass : std::uint8_t {
    UnreadableOrEmpty = 0,
    AllZeroPadding = 1,
    TrapOrNopSlide = 2,
    AsciiText = 3,
    Utf16LeText = 4,
    CodeOrStructured = 5,
    HighEntropyPacked = 6,
};

[[nodiscard]] constexpr std::string_view to_string(ByteClass cls) noexcept {
    switch (cls) {
        case ByteClass::UnreadableOrEmpty: return "Unreadable / Empty";
        case ByteClass::AllZeroPadding:    return "Zero Padding";
        case ByteClass::TrapOrNopSlide:    return "NOP / Trap Sled";
        case ByteClass::AsciiText:         return "ASCII Text";
        case ByteClass::Utf16LeText:       return "UTF-16LE Text";
        case ByteClass::CodeOrStructured:  return "Code / Structured";
        case ByteClass::HighEntropyPacked: return "High-Entropy / Packed";
    }
    return "Code / Structured";
}

enum class CantorPairClass : std::uint8_t {
    ZeroZero = 0,
    AsciiAscii = 1,
    Utf16AsciiZero = 2,
    ControlOrLow = 3,
    HighBit = 4,
    TrapOrNop = 5,
};

[[nodiscard]] constexpr std::string_view to_string(CantorPairClass cls) noexcept {
    switch (cls) {
        case CantorPairClass::ZeroZero:       return "Zero-Zero (00,00)";
        case CantorPairClass::AsciiAscii:     return "ASCII-ASCII";
        case CantorPairClass::Utf16AsciiZero: return "UTF-16 ASCII/NUL";
        case CantorPairClass::ControlOrLow:   return "Low / Control";
        case CantorPairClass::HighBit:        return "High-Bit (>=0x80)";
        case CantorPairClass::TrapOrNop:      return "NOP / INT3 Sled";
    }
    return "Low / Control";
}

struct ByteVizTileFlagBits {
    static constexpr std::uint8_t kNone         = 0u;
    static constexpr std::uint8_t kPatchDirty   = 1u << 0u;
    static constexpr std::uint8_t kDiffModified = 1u << 1u;
    static constexpr std::uint8_t kDiffAdded    = 1u << 2u;
    static constexpr std::uint8_t kSectionStart = 1u << 3u;
    static constexpr std::uint8_t kExecutable   = 1u << 4u;
};

enum class ByteVizDiffKind : std::uint8_t {
    Modified = 0,
    Added = 1,
};

struct ByteVizDiffRange {
    std::uint64_t offset_or_va{0};
    std::uint64_t size_bytes{0};
    bool is_virtual_address{false};
    ByteVizDiffKind kind{ByteVizDiffKind::Modified};

    [[nodiscard]] constexpr std::uint64_t end_offset_or_va() const noexcept {
        return (size_bytes <= (std::numeric_limits<std::uint64_t>::max() - offset_or_va))
                   ? (offset_or_va + size_bytes)
                   : std::numeric_limits<std::uint64_t>::max();
    }

    auto operator<=>(const ByteVizDiffRange&) const = default;
};

/// Extracts byte-level diff overlays from a static `BinaryDiffReport` (`rhs`/comparison or `lhs`/primary).
[[nodiscard]] std::vector<ByteVizDiffRange> extract_byte_viz_diff_ranges(
    const BinaryDiffReport& report,
    bool use_lhs_coordinates = true);

/// Extracts live RAM integrity diff hunks (`InlineCodeHook`, `IatGotPointerHook`, etc.) as VA ranges.
[[nodiscard]] std::vector<ByteVizDiffRange> extract_byte_viz_diff_ranges(
    const LiveModuleIntegrityReport& report);

// ---------------------------------------------------------------------------
// Exact Byte-Entropy, ByteClass, and Cantor Pair Math Helpers
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr bool is_printable_ascii_byte(std::uint8_t b) noexcept {
    return (b >= 0x20u && b <= 0x7Eu) || b == 0x09u || b == 0x0Au || b == 0x0Du;
}

[[nodiscard]] constexpr bool is_cantor_ascii_quadrant_byte(std::uint8_t b) noexcept {
    return b >= 0x20u && b <= 0x7Eu;
}

/// Computes exact Shannon entropy `-sum(p_i * log2(p_i))` in `[0.0, 8.0]` bits/byte.
/// Returns `0.0` on empty or constant-symbol spans.
[[nodiscard]] double compute_shannon_entropy_bits(std::span<const std::uint8_t> bytes) noexcept;

[[nodiscard]] constexpr std::uint8_t quantize_entropy_u8(double bits_per_byte) noexcept {
    if (!(bits_per_byte > 0.0)) {
        return 0u;
    }
    if (bits_per_byte >= 8.0) {
        return 255u;
    }
    const double scaled = (bits_per_byte / 8.0) * 255.0 + 0.5;
    return static_cast<std::uint8_t>(scaled >= 255.0 ? 255u : scaled);
}

[[nodiscard]] constexpr double dequantize_entropy_bits(std::uint8_t entropy_u8) noexcept {
    return (static_cast<double>(entropy_u8) / 255.0) * 8.0;
}

struct ByteSpanMetrics {
    double entropy_bits{0.0};
    std::uint8_t entropy_u8{0};
    std::uint8_t printable_u8{0};
    std::uint8_t zero_u8{0};
    std::uint8_t high_bit_u8{0};
    ByteClass byte_class{ByteClass::UnreadableOrEmpty};
};

/// Computes Shannon entropy, quantized byte-composition ratios, and dominant `ByteClass` in one pass.
[[nodiscard]] ByteSpanMetrics analyze_byte_span(std::span<const std::uint8_t> bytes) noexcept;

/// Classifies a single Cantor byte pair `(x = b[i], y = b[i + 1])`.
[[nodiscard]] constexpr CantorPairClass classify_cantor_pair(
    std::uint8_t first_byte,
    std::uint8_t second_byte) noexcept {
    if (first_byte == 0x00u && second_byte == 0x00u) {
        return CantorPairClass::ZeroZero;
    }
    if ((first_byte == 0x90u || first_byte == 0xCCu) &&
        (second_byte == 0x90u || second_byte == 0xCCu)) {
        return CantorPairClass::TrapOrNop;
    }
    if ((is_printable_ascii_byte(first_byte) && second_byte == 0x00u) ||
        (first_byte == 0x00u && is_printable_ascii_byte(second_byte))) {
        return CantorPairClass::Utf16AsciiZero;
    }
    if (is_printable_ascii_byte(first_byte) && is_printable_ascii_byte(second_byte)) {
        return CantorPairClass::AsciiAscii;
    }
    if (first_byte >= 0x80u || second_byte >= 0x80u) {
        return CantorPairClass::HighBit;
    }
    return CantorPairClass::ControlOrLow;
}

[[nodiscard]] constexpr std::size_t cantor_bin_index(
    std::uint8_t first_byte,
    std::uint8_t second_byte) noexcept {
    return (static_cast<std::size_t>(second_byte) * kCantorDigramAxis) +
           static_cast<std::size_t>(first_byte);
}

// ---------------------------------------------------------------------------
// GPU-Ready 16-Byte Tile (`uvec4` SSBO Layout) & Packed Cantor Bin Words
// ---------------------------------------------------------------------------
//
// `ByteVizTile` bit layout (128 bits = 16 bytes = `uvec4`):
//   words[0]: low 32 bits of `base_offset_or_va`
//   words[1]: high 32 bits of `base_offset_or_va`
//   words[2]:
//     bits [ 0..19]: 20-bit `span_mantissa`
//     bit  [    20]: `span_page_scale` (0 => exact bytes, 1 => `mantissa << 12` 4 KiB pages)
//     bits [21..23]: `ByteClass` (0..6)
//     bits [24..31]: `flags` (`ByteVizTileFlagBits`)
//   words[3]:
//     bits [ 0.. 7]: `entropy_u8`   (0..255 => 0.0..8.0 bits/byte)
//     bits [ 8..15]: `printable_u8` (0..255 => 0%..100%)
//     bits [16..23]: `zero_u8`      (0..255 => 0%..100%)
//     bits [24..31]: `high_bit_u8`  (0..255 => 0%..100%)

struct alignas(16) ByteVizTile {
    std::array<std::uint32_t, 4> words{0u, 0u, 0u, 0u};

    [[nodiscard]] static constexpr ByteVizTile pack(
        std::uint64_t base_offset_or_va,
        std::uint64_t span_bytes,
        ByteClass byte_class,
        std::uint8_t entropy_u8,
        std::uint8_t printable_u8 = 0u,
        std::uint8_t zero_u8 = 0u,
        std::uint8_t high_bit_u8 = 0u,
        std::uint8_t flags = ByteVizTileFlagBits::kNone) noexcept {
        ByteVizTile tile{};
        tile.words[0] = static_cast<std::uint32_t>(base_offset_or_va & 0xFFFFFFFFull);
        tile.words[1] = static_cast<std::uint32_t>((base_offset_or_va >> 32u) & 0xFFFFFFFFull);

        std::uint32_t mantissa = 0u;
        std::uint32_t page_scale = 0u;
        if (span_bytes <= 0xFFFFFull) {
            mantissa = static_cast<std::uint32_t>(span_bytes);
        } else {
            page_scale = 1u;
            const std::uint64_t pages = (span_bytes + 4095ull) >> 12u;
            mantissa = static_cast<std::uint32_t>(std::min<std::uint64_t>(pages, 0xFFFFFull));
        }

        const auto cls_bits = static_cast<std::uint32_t>(byte_class) & 0x7u;
        tile.words[2] = (mantissa & 0xFFFFFu) |
                        (page_scale << 20u) |
                        (cls_bits << 21u) |
                        (static_cast<std::uint32_t>(flags) << 24u);

        tile.words[3] = static_cast<std::uint32_t>(entropy_u8) |
                        (static_cast<std::uint32_t>(printable_u8) << 8u) |
                        (static_cast<std::uint32_t>(zero_u8) << 16u) |
                        (static_cast<std::uint32_t>(high_bit_u8) << 24u);
        return tile;
    }

    [[nodiscard]] constexpr std::uint64_t base_offset_or_va() const noexcept {
        return static_cast<std::uint64_t>(words[0]) |
               (static_cast<std::uint64_t>(words[1]) << 32u);
    }

    [[nodiscard]] constexpr std::uint64_t span_bytes() const noexcept {
        const std::uint64_t mantissa = static_cast<std::uint64_t>(words[2] & 0xFFFFFu);
        const bool page_scaled = ((words[2] >> 20u) & 0x1u) != 0u;
        return page_scaled ? (mantissa << 12u) : mantissa;
    }

    [[nodiscard]] constexpr std::uint64_t end_offset_or_va() const noexcept {
        const std::uint64_t base = base_offset_or_va();
        const std::uint64_t span = span_bytes();
        return (span <= (std::numeric_limits<std::uint64_t>::max() - base))
                   ? (base + span)
                   : std::numeric_limits<std::uint64_t>::max();
    }

    [[nodiscard]] constexpr ByteClass byte_class() const noexcept {
        const auto raw = static_cast<std::uint8_t>((words[2] >> 21u) & 0x7u);
        return raw <= static_cast<std::uint8_t>(ByteClass::HighEntropyPacked)
                   ? static_cast<ByteClass>(raw)
                   : ByteClass::CodeOrStructured;
    }

    [[nodiscard]] constexpr std::uint8_t flags() const noexcept {
        return static_cast<std::uint8_t>((words[2] >> 24u) & 0xFFu);
    }

    [[nodiscard]] constexpr bool is_patch_dirty() const noexcept {
        return (flags() & ByteVizTileFlagBits::kPatchDirty) != 0u;
    }
    [[nodiscard]] constexpr bool is_diff_modified() const noexcept {
        return (flags() & ByteVizTileFlagBits::kDiffModified) != 0u;
    }
    [[nodiscard]] constexpr bool is_diff_added() const noexcept {
        return (flags() & ByteVizTileFlagBits::kDiffAdded) != 0u;
    }
    [[nodiscard]] constexpr bool is_section_start() const noexcept {
        return (flags() & ByteVizTileFlagBits::kSectionStart) != 0u;
    }
    [[nodiscard]] constexpr bool is_executable() const noexcept {
        return (flags() & ByteVizTileFlagBits::kExecutable) != 0u;
    }

    [[nodiscard]] constexpr std::uint8_t entropy_u8() const noexcept {
        return static_cast<std::uint8_t>(words[3] & 0xFFu);
    }
    [[nodiscard]] constexpr std::uint8_t printable_u8() const noexcept {
        return static_cast<std::uint8_t>((words[3] >> 8u) & 0xFFu);
    }
    [[nodiscard]] constexpr std::uint8_t zero_u8() const noexcept {
        return static_cast<std::uint8_t>((words[3] >> 16u) & 0xFFu);
    }
    [[nodiscard]] constexpr std::uint8_t high_bit_u8() const noexcept {
        return static_cast<std::uint8_t>((words[3] >> 24u) & 0xFFu);
    }

    [[nodiscard]] constexpr double entropy_bits() const noexcept {
        return dequantize_entropy_bits(entropy_u8());
    }
    [[nodiscard]] constexpr double printable_ratio() const noexcept {
        return static_cast<double>(printable_u8()) / 255.0;
    }
    [[nodiscard]] constexpr double zero_ratio() const noexcept {
        return static_cast<double>(zero_u8()) / 255.0;
    }
    [[nodiscard]] constexpr double high_bit_ratio() const noexcept {
        return static_cast<double>(high_bit_u8()) / 255.0;
    }

    auto operator<=>(const ByteVizTile&) const = default;
};

static_assert(sizeof(ByteVizTile) == 16, "ByteVizTile must be exactly 16 bytes (uvec4)");
static_assert(alignof(ByteVizTile) == 16, "ByteVizTile must be 16-byte aligned for std430 SSBO");
static_assert(std::is_trivially_copyable_v<ByteVizTile>);
static_assert(std::is_standard_layout_v<ByteVizTile>);

// Packed Cantor-Dust GPU bin word (`std::uint32_t`, 65,536 entries = 256 KiB SSBO):
//   bits [ 0..15]: `density_u16` (`0` when empty; `1..65535` normalized `log1p(count)/log1p(max)`)
//   bits [16..19]: `CantorPairClass` (`0..5`)
//   bit  [    20]: `has_occurrence` (`1` when `first_occurrence_addresses[bin]` is valid)

[[nodiscard]] constexpr std::uint32_t pack_cantor_gpu_bin(
    std::uint16_t density_u16,
    CantorPairClass pair_class,
    bool has_occurrence) noexcept {
    return static_cast<std::uint32_t>(density_u16) |
           ((static_cast<std::uint32_t>(pair_class) & 0xFu) << 16u) |
           (has_occurrence ? (1u << 20u) : 0u);
}

[[nodiscard]] constexpr std::uint16_t unpack_cantor_density_u16(std::uint32_t packed) noexcept {
    return static_cast<std::uint16_t>(packed & 0xFFFFu);
}

[[nodiscard]] constexpr CantorPairClass unpack_cantor_pair_class(std::uint32_t packed) noexcept {
    const auto raw = static_cast<std::uint8_t>((packed >> 16u) & 0xFu);
    return raw <= static_cast<std::uint8_t>(CantorPairClass::TrapOrNop)
               ? static_cast<CantorPairClass>(raw)
               : CantorPairClass::ControlOrLow;
}

[[nodiscard]] constexpr bool unpack_cantor_has_occurrence(std::uint32_t packed) noexcept {
    return ((packed >> 20u) & 0x1u) != 0u;
}

struct CantorDustDigram {
    std::vector<std::uint32_t> pair_counts{};              ///< 65,536 raw counts indexed by `y * 256 + x`
    std::vector<std::uint32_t> packed_gpu_bins{};          ///< 65,536 GPU words (`pack_cantor_gpu_bin`)
    std::vector<std::uint64_t> first_occurrence_addresses{}; ///< 65,536 representative first offset/VA (`kInvalidByteVizAddress` when empty)
    std::uint32_t max_bin_count{0};
    std::uint32_t occupied_bins{0};
    std::uint64_t total_pairs{0};
    std::uint64_t ascii_quadrant_pairs{0};
    std::uint64_t utf16_stripe_pairs{0};
    std::uint64_t zero_zero_pairs{0};
    std::uint64_t high_bit_pairs{0};
    std::uint64_t scope_start_address{0};
    std::uint64_t scope_end_address{0};
    bool addresses_are_virtual{false};

    [[nodiscard]] bool empty() const noexcept {
        return pair_counts.size() != kCantorDigramBinCount || total_pairs == 0u;
    }

    [[nodiscard]] std::uint32_t count_at(std::uint8_t x, std::uint8_t y) const noexcept {
        const std::size_t idx = cantor_bin_index(x, y);
        return idx < pair_counts.size() ? pair_counts[idx] : 0u;
    }

    [[nodiscard]] std::optional<std::uint64_t> first_occurrence_at(
        std::uint8_t x,
        std::uint8_t y) const noexcept {
        const std::size_t idx = cantor_bin_index(x, y);
        if (idx >= first_occurrence_addresses.size()) {
            return std::nullopt;
        }
        const std::uint64_t addr = first_occurrence_addresses[idx];
        if (addr == kInvalidByteVizAddress) {
            return std::nullopt;
        }
        return addr;
    }
};

struct ByteVizSectionSpan {
    std::string name{};
    std::uint64_t start_address{0}; ///< File offset when `!addresses_are_virtual`, else VA
    std::uint64_t size_bytes{0};
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> file_offset{};
    bool executable{false};
    bool writable{false};

    [[nodiscard]] constexpr std::uint64_t end_address() const noexcept {
        return (size_bytes <= (std::numeric_limits<std::uint64_t>::max() - start_address))
                   ? (start_address + size_bytes)
                   : std::numeric_limits<std::uint64_t>::max();
    }
};

struct ByteVizStats {
    std::uint64_t scope_start_address{0};
    std::uint64_t scope_end_address{0};
    std::uint64_t total_scope_bytes{0};
    std::uint64_t readable_bytes{0};
    std::uint64_t unreadable_bytes{0};
    std::size_t unreadable_gap_count{0};
    bool truncated_by_budget{false};

    double mean_entropy_bits{0.0};
    double peak_entropy_bits{0.0};
    std::size_t high_entropy_tile_count{0};
    std::size_t text_tile_count{0};
    std::size_t code_tile_count{0};
    std::size_t zero_tile_count{0};
    std::size_t trap_nop_tile_count{0};
    std::size_t unreadable_tile_count{0};
    std::size_t patch_dirty_tile_count{0};
    std::size_t diff_tile_count{0};
};

struct ByteVizSnapshot {
    std::string scope_label{};
    bool addresses_are_virtual{false};
    ByteVizLayout layout{ByteVizLayout::HilbertCurve};
    std::uint32_t hilbert_order{1};
    std::uint32_t grid_width{1};
    std::uint32_t grid_height{1};
    std::size_t nominal_tile_bytes{256};

    std::vector<ByteVizTile> tiles{};
    std::vector<ByteVizSectionSpan> sections{};
    CantorDustDigram cantor{};
    ByteVizStats stats{};

    /// Recomputes `hilbert_order`, `grid_width`, and `grid_height` in `O(1)` when switching
    /// between `HilbertCurve` and `LinearRows` without re-scanning the underlying bytes.
    void relayout(ByteVizLayout new_layout) noexcept;

    [[nodiscard]] HilbertCoord2D tile_grid_coords(std::size_t tile_index) const noexcept {
        return cell_index_to_grid_xy(
            to_heatmap_layout(layout), hilbert_order, grid_width, tile_index);
    }

    [[nodiscard]] std::optional<std::size_t> grid_coords_to_tile_index(
        std::uint32_t x,
        std::uint32_t y) const noexcept {
        if (x >= grid_width || y >= grid_height) {
            return std::nullopt;
        }
        const std::uint64_t idx = grid_xy_to_cell_index(
            to_heatmap_layout(layout), hilbert_order, grid_width, x, y);
        if (idx >= tiles.size()) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(idx);
    }

    [[nodiscard]] std::optional<std::size_t> find_tile_index_containing(
        std::uint64_t offset_or_va) const noexcept;

    [[nodiscard]] const ByteVizSectionSpan* find_section_at(
        std::uint64_t offset_or_va) const noexcept;
};

struct ByteVizConfig {
    ByteVizLayout layout{ByteVizLayout::HilbertCurve};
    std::size_t target_max_tiles{65536u};
    std::size_t min_tile_bytes{256u};
    std::size_t max_read_bytes{kDefaultByteVizMaxReadBytes};
    std::optional<std::pair<std::uint64_t, std::uint64_t>> scope_subrange{};
    std::string scope_label{};
    bool compute_tiles{true};
    bool compute_cantor{true};
};

/// Chooses an adaptive power-of-two tile byte span in `[min_tile_bytes, ...]` so `total_bytes`
/// produces at most `target_max_tiles` tiles (or exact `total_bytes` when smaller than `min_tile_bytes`).
[[nodiscard]] constexpr std::size_t choose_adaptive_tile_bytes(
    std::uint64_t total_bytes,
    std::size_t min_tile_bytes = 256u,
    std::size_t target_max_tiles = 65536u) noexcept {
    if (total_bytes == 0u) {
        return std::max<std::size_t>(min_tile_bytes, 1u);
    }
    const std::size_t floor_tile = std::max<std::size_t>(min_tile_bytes, 16u);
    if (total_bytes <= static_cast<std::uint64_t>(floor_tile)) {
        return static_cast<std::size_t>(total_bytes);
    }
    const std::size_t max_tiles = std::max<std::size_t>(target_max_tiles, 16u);
    std::uint64_t tile = 16u;
    while (tile < static_cast<std::uint64_t>(floor_tile)) {
        tile <<= 1u;
    }
    while (((total_bytes + tile - 1u) / tile) > static_cast<std::uint64_t>(max_tiles)) {
        if (tile >= (1ull << 30u)) {
            break;
        }
        tile <<= 1u;
    }
    return static_cast<std::size_t>(tile);
}

// ---------------------------------------------------------------------------
// Snapshot & Cantor-Digram Builders (Static Bytes, IBinaryImage, Live RAM)
// ---------------------------------------------------------------------------

[[nodiscard]] Observed<CantorDustDigram> compute_cantor_digram_from_bytes(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_address = 0u,
    bool addresses_are_virtual = false,
    std::stop_token stop_token = {});

[[nodiscard]] Observed<ByteVizSnapshot> compute_byte_viz_from_bytes(
    std::span<const std::uint8_t> bytes,
    const ByteVizConfig& config = {},
    std::uint64_t base_address = 0u,
    bool addresses_are_virtual = false,
    std::span<const ByteVizDiffRange> diff_ranges = {},
    std::span<const PatchInterval> patch_intervals = {},
    std::span<const ByteVizSectionSpan> sections = {},
    std::stop_token stop_token = {});

[[nodiscard]] Observed<ByteVizSnapshot> compute_static_byte_viz(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes,
    const ByteVizConfig& config = {},
    const PagedBinaryImage* patched_image = nullptr,
    std::span<const ByteVizDiffRange> diff_ranges = {},
    std::stop_token stop_token = {});

[[nodiscard]] Observed<ByteVizSnapshot> compute_static_byte_viz(
    const IBinaryImage& image,
    const ByteVizConfig& config = {},
    const PagedBinaryImage* patched_image = nullptr,
    std::span<const ByteVizDiffRange> diff_ranges = {},
    std::stop_token stop_token = {});

[[nodiscard]] Observed<CantorDustDigram> compute_static_cantor_digram(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes,
    std::uint64_t start_offset,
    std::uint64_t end_offset,
    const PagedBinaryImage* patched_image = nullptr,
    std::stop_token stop_token = {});

[[nodiscard]] Observed<ByteVizSnapshot> compute_live_region_byte_viz(
    IProcessSession& session,
    const MemoryRegion& region,
    const ByteVizConfig& config = {},
    std::span<const ByteVizDiffRange> diff_ranges = {},
    std::span<const PatchInterval> live_patches = {},
    std::stop_token stop_token = {});

[[nodiscard]] Observed<CantorDustDigram> compute_live_cantor_digram(
    IProcessSession& session,
    const MemoryRegion& region,
    std::uint64_t start_va,
    std::uint64_t end_va,
    std::size_t max_read_bytes = kDefaultByteVizMaxReadBytes,
    std::stop_token stop_token = {});

// ---------------------------------------------------------------------------
// Deterministic CPU Reference RGBA8 Rasterizer
// ---------------------------------------------------------------------------

struct ByteVizViewport {
    std::uint32_t width_px{256};
    std::uint32_t height_px{256};
    double center_x{128.0};
    double center_y{128.0};
    double scale_x{1.0}; ///< Pixels per world unit (1 tile in Entropy2D, 1 bin in Cantor256)
    double scale_y{1.0};
    bool show_guides_and_grid{true};

    // Optional active brush `[brush_start_address, brush_end_address)` in Entropy2D mode.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> brushed_address_range{};

    // Optional hover & selection indices (`tile_index` in Entropy2D, `bin_index` in Cantor256).
    std::optional<std::size_t> hovered_index{};
    std::optional<std::size_t> selected_index{};
};

void rasterize_byte_viz_rgba8_into(
    const ByteVizViewport& viewport,
    const ByteVizSnapshot& snapshot,
    ByteVizMode mode,
    ByteVizColorMode color_mode,
    std::vector<std::uint8_t>& out_rgba8);

[[nodiscard]] std::vector<std::uint8_t> rasterize_byte_viz_rgba8(
    const ByteVizViewport& viewport,
    const ByteVizSnapshot& snapshot,
    ByteVizMode mode = ByteVizMode::EntropyAndByteClass2D,
    ByteVizColorMode color_mode = ByteVizColorMode::EntropySpectrum);

} // namespace peelf
