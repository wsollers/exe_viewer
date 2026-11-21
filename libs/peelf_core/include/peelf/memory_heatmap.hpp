#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/error.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/provenance.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace peelf {

inline constexpr std::uint32_t kMinHilbertOrder = 1u;
inline constexpr std::uint32_t kMaxHilbertOrder = 16u;

struct HilbertCoord2D {
    std::uint32_t x{0};
    std::uint32_t y{0};

    constexpr auto operator<=>(const HilbertCoord2D&) const noexcept = default;
};

enum class MemoryHeatmapLayout : std::uint8_t {
    HilbertCurve = 0,
    LinearRows = 1,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryHeatmapLayout layout) noexcept {
    switch (layout) {
        case MemoryHeatmapLayout::HilbertCurve: return "HilbertCurve";
        case MemoryHeatmapLayout::LinearRows:   return "LinearRows";
    }
    return "HilbertCurve";
}

enum class MemoryHeatmapScope : std::uint8_t {
    CompactAddressSpace = 0,
    FocusedRange = 1,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryHeatmapScope scope) noexcept {
    switch (scope) {
        case MemoryHeatmapScope::CompactAddressSpace: return "CompactAddressSpace";
        case MemoryHeatmapScope::FocusedRange:        return "FocusedRange";
    }
    return "CompactAddressSpace";
}

enum class MemoryHeatmapColorMode : std::uint8_t {
    AllocatorAndWriteHeat = 0,
    CategoryAndResidency = 1,
    PermissionsAndRwx = 2,
    PageEntropy = 3,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryHeatmapColorMode mode) noexcept {
    switch (mode) {
        case MemoryHeatmapColorMode::AllocatorAndWriteHeat: return "AllocatorAndWriteHeat";
        case MemoryHeatmapColorMode::CategoryAndResidency:  return "CategoryAndResidency";
        case MemoryHeatmapColorMode::PermissionsAndRwx:     return "PermissionsAndRwx";
        case MemoryHeatmapColorMode::PageEntropy:           return "PageEntropy";
    }
    return "AllocatorAndWriteHeat";
}

enum class MemoryCellCategory : std::uint8_t {
    Unmapped = 0,
    ImageCode = 1,
    ImageRoData = 2,
    ImageRwData = 3,
    Heap = 4,
    ThreadStack = 5,
    AnonRw = 6,
    SharedMapped = 7,
    GuardPage = 8,
    PatchDirty = 9,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryCellCategory cat) noexcept {
    switch (cat) {
        case MemoryCellCategory::Unmapped:     return "Unmapped";
        case MemoryCellCategory::ImageCode:    return "ImageCode";
        case MemoryCellCategory::ImageRoData:  return "ImageRoData";
        case MemoryCellCategory::ImageRwData:  return "ImageRwData";
        case MemoryCellCategory::Heap:         return "Heap";
        case MemoryCellCategory::ThreadStack:  return "ThreadStack";
        case MemoryCellCategory::AnonRw:       return "AnonRw";
        case MemoryCellCategory::SharedMapped: return "SharedMapped";
        case MemoryCellCategory::GuardPage:    return "GuardPage";
        case MemoryCellCategory::PatchDirty:   return "PatchDirty";
    }
    return "Unmapped";
}

enum class MemoryCellResidency : std::uint8_t {
    Unknown = 0,
    Resident = 1,
    Swapped = 2,
    ZeroOrUncommitted = 3,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryCellResidency res) noexcept {
    switch (res) {
        case MemoryCellResidency::Unknown:           return "Unknown";
        case MemoryCellResidency::Resident:          return "Resident";
        case MemoryCellResidency::Swapped:           return "Swapped";
        case MemoryCellResidency::ZeroOrUncommitted: return "ZeroOrUncommitted";
    }
    return "Unknown";
}

namespace MemoryCellPermBits {
inline constexpr std::uint8_t kNone = 0u;
inline constexpr std::uint8_t kRead = 1u << 0u;
inline constexpr std::uint8_t kWrite = 1u << 1u;
inline constexpr std::uint8_t kExecute = 1u << 2u;
inline constexpr std::uint8_t kShared = 1u << 3u;
inline constexpr std::uint8_t kGuard = 1u << 4u;
inline constexpr std::uint8_t kRwxHazard = 1u << 5u;
} // namespace MemoryCellPermBits

namespace detail {

constexpr void hilbert_rot(std::uint64_t s,
                           std::uint64_t& x,
                           std::uint64_t& y,
                           std::uint64_t rx,
                           std::uint64_t ry) noexcept {
    if (ry == 0u) {
        if (rx == 1u) {
            x = (s - 1u) - x;
            y = (s - 1u) - y;
        }
        const std::uint64_t tmp = x;
        x = y;
        y = tmp;
    }
}

} // namespace detail

[[nodiscard]] constexpr bool is_valid_hilbert_order(std::uint32_t order) noexcept {
    return order >= kMinHilbertOrder && order <= kMaxHilbertOrder;
}

[[nodiscard]] constexpr std::uint32_t clamp_hilbert_order(std::uint32_t order) noexcept {
    if (order < kMinHilbertOrder) {
        return kMinHilbertOrder;
    }
    if (order > kMaxHilbertOrder) {
        return kMaxHilbertOrder;
    }
    return order;
}

[[nodiscard]] constexpr std::uint32_t choose_hilbert_order_for_cells(
    std::size_t cell_count) noexcept {
    std::uint32_t order = kMinHilbertOrder;
    while (order < kMaxHilbertOrder) {
        const std::uint64_t capacity = std::uint64_t{1} << (2u * order);
        if (capacity >= static_cast<std::uint64_t>(cell_count)) {
            break;
        }
        ++order;
    }
    return order;
}

/// Exact O(1) (fixed <= 16 iterations) 2D Hilbert curve index -> (x, y) mapping for
/// `order in [1, 16]` (up to 65536 x 65536 = 4G cells). Invalid `order == 0` returns `{0, 0}`;
/// `order > 16` is clamped to `16`, and out-of-range `index` is clamped to `(4^order) - 1`.
[[nodiscard]] constexpr HilbertCoord2D hilbert_index_to_xy(std::uint32_t order,
                                                           std::uint64_t index) noexcept {
    if (order == 0u) {
        return HilbertCoord2D{0u, 0u};
    }
    const std::uint32_t eff_order = order > kMaxHilbertOrder ? kMaxHilbertOrder : order;
    const std::uint64_t n = std::uint64_t{1} << eff_order;
    const std::uint64_t max_index = (n * n) - 1u;
    std::uint64_t t = index > max_index ? max_index : index;

    std::uint64_t x = 0u;
    std::uint64_t y = 0u;
    for (std::uint64_t s = 1u; s < n; s <<= 1u) {
        const std::uint64_t rx = 1u & (t >> 1u);
        const std::uint64_t ry = 1u & (t ^ rx);
        detail::hilbert_rot(s, x, y, rx, ry);
        x += s * rx;
        y += s * ry;
        t >>= 2u;
    }
    return HilbertCoord2D{
        .x = static_cast<std::uint32_t>(x),
        .y = static_cast<std::uint32_t>(y),
    };
}

/// Exact O(1) (fixed <= 16 iterations) 2D Hilbert curve (x, y) -> index inverse bijection for
/// `order in [1, 16]`. Invalid `order == 0` returns `0`; `order > 16` is clamped to `16`, and
/// coordinates `>= 2^order` are clamped to `(2^order) - 1`.
[[nodiscard]] constexpr std::uint64_t hilbert_xy_to_index(std::uint32_t order,
                                                          std::uint32_t x,
                                                          std::uint32_t y) noexcept {
    if (order == 0u) {
        return 0u;
    }
    const std::uint32_t eff_order = order > kMaxHilbertOrder ? kMaxHilbertOrder : order;
    const std::uint64_t n = std::uint64_t{1} << eff_order;
    std::uint64_t cx = x >= n ? (n - 1u) : static_cast<std::uint64_t>(x);
    std::uint64_t cy = y >= n ? (n - 1u) : static_cast<std::uint64_t>(y);

    std::uint64_t d = 0u;
    for (std::uint64_t s = n >> 1u; s > 0u; s >>= 1u) {
        const std::uint64_t rx = (cx & s) != 0u ? 1u : 0u;
        const std::uint64_t ry = (cy & s) != 0u ? 1u : 0u;
        d += (s * s) * ((3u * rx) ^ ry);
        cx &= (s - 1u);
        cy &= (s - 1u);
        detail::hilbert_rot(s, cx, cy, rx, ry);
    }
    return d;
}

[[nodiscard]] constexpr HilbertCoord2D cell_index_to_grid_xy(MemoryHeatmapLayout layout,
                                                             std::uint32_t order,
                                                             std::uint32_t grid_width,
                                                             std::uint64_t index) noexcept {
    if (layout == MemoryHeatmapLayout::LinearRows) {
        const std::uint32_t w = grid_width > 0u ? grid_width : 1u;
        return HilbertCoord2D{
            .x = static_cast<std::uint32_t>(index % w),
            .y = static_cast<std::uint32_t>(index / w),
        };
    }
    return hilbert_index_to_xy(order, index);
}

[[nodiscard]] constexpr std::uint64_t grid_xy_to_cell_index(MemoryHeatmapLayout layout,
                                                            std::uint32_t order,
                                                            std::uint32_t grid_width,
                                                            std::uint32_t x,
                                                            std::uint32_t y) noexcept {
    if (layout == MemoryHeatmapLayout::LinearRows) {
        const std::uint64_t w = grid_width > 0u ? grid_width : 1u;
        const std::uint64_t clamped_x = x >= w ? (w - 1u) : static_cast<std::uint64_t>(x);
        return static_cast<std::uint64_t>(y) * w + clamped_x;
    }
    return hilbert_xy_to_index(order, x, y);
}

static_assert(hilbert_xy_to_index(1u, hilbert_index_to_xy(1u, 0u).x, hilbert_index_to_xy(1u, 0u).y) == 0u);
static_assert(hilbert_xy_to_index(1u, hilbert_index_to_xy(1u, 3u).x, hilbert_index_to_xy(1u, 3u).y) == 3u);
static_assert(hilbert_xy_to_index(4u, hilbert_index_to_xy(4u, 137u).x, hilbert_index_to_xy(4u, 137u).y) == 137u);
static_assert(hilbert_xy_to_index(16u, hilbert_index_to_xy(16u, 0xDEADBEEFull).x, hilbert_index_to_xy(16u, 0xDEADBEEFull).y) == 0xDEADBEEFull);

/// Compact 16-byte GPU SSBO-compatible cell (`uvec4` in GLSL 450).
///
/// Word layout (little-endian `uvec4`):
/// - `words[0..1]` (`base_va`): 64-bit virtual address of cell start.
/// - `words[2]` (`span_and_perms`):
///     - bits `[0..23]` : 24-bit span mantissa
///     - bit  `[24]`    : span scale (`0` = exact bytes `< 16 MiB`, `1` = `mantissa << 12` 4 KiB pages)
///     - bits `[25..30]`: 6-bit permission mask (`R`, `W`, `X`, `Shared`, `Guard`, `RwxHazard`)
///     - bit  `[31]`    : `perm_transition` flag (e.g. `RW -> RX` JIT transition across ticks)
/// - `words[3]` (`attrs_packed`):
///     - bits `[0..7]`  : `heat_u8` (`0..255` exponential afterglow decay)
///     - bits `[8..15]` : `entropy_u8` (`0..255` normalized Shannon byte entropy)
///     - bits `[16..23]`: `mutation_count_u8` (`0..255` saturating mutation counter)
///     - bits `[24..27]`: `MemoryCellCategory` (`0..9`)
///     - bits `[28..29]`: `MemoryCellResidency` (`0..3`)
///     - bit  `[30]`    : `newly_allocated` flag
///     - bit  `[31]`    : `hot_focus` flag (crashing/active thread IP/SP or entry point page)
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324)
#endif
struct alignas(16) MemoryHeatmapCell {
    std::uint64_t base_va{0};
    std::uint32_t span_and_perms{0};
    std::uint32_t attrs_packed{0};

    static constexpr std::uint32_t kSpanMantissaMask = 0x00FF'FFFFu;
    static constexpr std::uint32_t kSpanPageScaleBit = 1u << 24u;
    static constexpr std::uint32_t kPermsShift = 25u;
    static constexpr std::uint32_t kPermsMask = 0x3Fu;
    static constexpr std::uint32_t kPermTransitionBit = 1u << 31u;

    static constexpr std::uint32_t kCategoryShift = 24u;
    static constexpr std::uint32_t kCategoryMask = 0x0Fu;
    static constexpr std::uint32_t kResidencyShift = 28u;
    static constexpr std::uint32_t kResidencyMask = 0x03u;
    static constexpr std::uint32_t kNewAllocBit = 1u << 30u;
    static constexpr std::uint32_t kHotFocusBit = 1u << 31u;

    [[nodiscard]] static constexpr std::uint32_t encode_span_field(std::uint32_t bytes) noexcept {
        if (bytes <= kSpanMantissaMask) {
            return bytes;
        }
        const std::uint64_t pages = (static_cast<std::uint64_t>(bytes) + 4095u) >> 12u;
        const auto clamped_pages = static_cast<std::uint32_t>(
            pages > 0x000F'FFFFu ? 0x000F'FFFFu : pages);
        return clamped_pages | kSpanPageScaleBit;
    }

    [[nodiscard]] constexpr std::uint32_t span_bytes() const noexcept {
        const std::uint32_t mantissa = span_and_perms & kSpanMantissaMask;
        if ((span_and_perms & kSpanPageScaleBit) != 0u) {
            const std::uint64_t scaled = static_cast<std::uint64_t>(mantissa) << 12u;
            return scaled > 0xFFFF'FFFFull ? 0xFFFF'FFFFu : static_cast<std::uint32_t>(scaled);
        }
        return mantissa;
    }

    constexpr void set_span_bytes(std::uint32_t bytes) noexcept {
        span_and_perms =
            (span_and_perms & ~(kSpanMantissaMask | kSpanPageScaleBit)) | encode_span_field(bytes);
    }

    [[nodiscard]] constexpr std::uint8_t perms() const noexcept {
        return static_cast<std::uint8_t>((span_and_perms >> kPermsShift) & kPermsMask);
    }

    constexpr void set_perms(std::uint8_t perm_bits) noexcept {
        span_and_perms = (span_and_perms & ~(kPermsMask << kPermsShift)) |
                         ((static_cast<std::uint32_t>(perm_bits) & kPermsMask) << kPermsShift);
    }

    [[nodiscard]] constexpr bool is_readable() const noexcept {
        return (perms() & MemoryCellPermBits::kRead) != 0u;
    }
    [[nodiscard]] constexpr bool is_writable() const noexcept {
        return (perms() & MemoryCellPermBits::kWrite) != 0u;
    }
    [[nodiscard]] constexpr bool is_executable() const noexcept {
        return (perms() & MemoryCellPermBits::kExecute) != 0u;
    }
    [[nodiscard]] constexpr bool is_shared() const noexcept {
        return (perms() & MemoryCellPermBits::kShared) != 0u;
    }
    [[nodiscard]] constexpr bool is_guarded() const noexcept {
        return (perms() & MemoryCellPermBits::kGuard) != 0u;
    }
    [[nodiscard]] constexpr bool has_rwx_hazard() const noexcept {
        return (perms() & MemoryCellPermBits::kRwxHazard) != 0u;
    }

    [[nodiscard]] constexpr bool has_perm_transition() const noexcept {
        return (span_and_perms & kPermTransitionBit) != 0u;
    }

    constexpr void set_perm_transition(bool enabled) noexcept {
        if (enabled) {
            span_and_perms |= kPermTransitionBit;
        } else {
            span_and_perms &= ~kPermTransitionBit;
        }
    }

    [[nodiscard]] constexpr std::uint8_t heat_u8() const noexcept {
        return static_cast<std::uint8_t>(attrs_packed & 0xFFu);
    }

    constexpr void set_heat_u8(std::uint8_t v) noexcept {
        attrs_packed = (attrs_packed & ~0xFFu) | static_cast<std::uint32_t>(v);
    }

    [[nodiscard]] constexpr std::uint8_t entropy_u8() const noexcept {
        return static_cast<std::uint8_t>((attrs_packed >> 8u) & 0xFFu);
    }

    constexpr void set_entropy_u8(std::uint8_t v) noexcept {
        attrs_packed = (attrs_packed & ~(0xFFu << 8u)) | (static_cast<std::uint32_t>(v) << 8u);
    }

    [[nodiscard]] constexpr std::uint8_t mutation_count_u8() const noexcept {
        return static_cast<std::uint8_t>((attrs_packed >> 16u) & 0xFFu);
    }

    constexpr void set_mutation_count_u8(std::uint8_t v) noexcept {
        attrs_packed = (attrs_packed & ~(0xFFu << 16u)) | (static_cast<std::uint32_t>(v) << 16u);
    }

    [[nodiscard]] constexpr MemoryCellCategory category() const noexcept {
        const auto raw = static_cast<std::uint8_t>((attrs_packed >> kCategoryShift) & kCategoryMask);
        if (raw > static_cast<std::uint8_t>(MemoryCellCategory::PatchDirty)) {
            return MemoryCellCategory::Unmapped;
        }
        return static_cast<MemoryCellCategory>(raw);
    }

    constexpr void set_category(MemoryCellCategory cat) noexcept {
        attrs_packed =
            (attrs_packed & ~(kCategoryMask << kCategoryShift)) |
            ((static_cast<std::uint32_t>(cat) & kCategoryMask) << kCategoryShift);
    }

    [[nodiscard]] constexpr MemoryCellResidency residency() const noexcept {
        return static_cast<MemoryCellResidency>((attrs_packed >> kResidencyShift) & kResidencyMask);
    }

    constexpr void set_residency(MemoryCellResidency res) noexcept {
        attrs_packed =
            (attrs_packed & ~(kResidencyMask << kResidencyShift)) |
            ((static_cast<std::uint32_t>(res) & kResidencyMask) << kResidencyShift);
    }

    [[nodiscard]] constexpr bool is_newly_allocated() const noexcept {
        return (attrs_packed & kNewAllocBit) != 0u;
    }

    constexpr void set_newly_allocated(bool enabled) noexcept {
        if (enabled) {
            attrs_packed |= kNewAllocBit;
        } else {
            attrs_packed &= ~kNewAllocBit;
        }
    }

    [[nodiscard]] constexpr bool has_hot_focus() const noexcept {
        return (attrs_packed & kHotFocusBit) != 0u;
    }

    constexpr void set_hot_focus(bool enabled) noexcept {
        if (enabled) {
            attrs_packed |= kHotFocusBit;
        } else {
            attrs_packed &= ~kHotFocusBit;
        }
    }

    [[nodiscard]] constexpr std::array<std::uint32_t, 4> to_uvec4() const noexcept {
        return {
            static_cast<std::uint32_t>(base_va & 0xFFFF'FFFFull),
            static_cast<std::uint32_t>((base_va >> 32u) & 0xFFFF'FFFFull),
            span_and_perms,
            attrs_packed,
        };
    }

    [[nodiscard]] static constexpr MemoryHeatmapCell pack(
        std::uint64_t va,
        std::uint32_t span,
        MemoryCellCategory cat,
        std::uint8_t perm_bits,
        MemoryCellResidency res,
        std::uint8_t heat = 0u,
        std::uint8_t entropy = 0u,
        std::uint8_t mutations = 0u,
        bool perm_transition = false,
        bool newly_allocated = false,
        bool hot_focus = false) noexcept {
        MemoryHeatmapCell cell{};
        cell.base_va = va;
        cell.set_span_bytes(span);
        cell.set_perms(perm_bits);
        cell.set_perm_transition(perm_transition);
        cell.set_category(cat);
        cell.set_residency(res);
        cell.set_heat_u8(heat);
        cell.set_entropy_u8(entropy);
        cell.set_mutation_count_u8(mutations);
        cell.set_newly_allocated(newly_allocated);
        cell.set_hot_focus(hot_focus);
        return cell;
    }

    constexpr auto operator<=>(const MemoryHeatmapCell&) const noexcept = default;
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static_assert(sizeof(MemoryHeatmapCell) == 16u, "MemoryHeatmapCell must be 16 bytes (uvec4 SSBO)");
static_assert(alignof(MemoryHeatmapCell) == 16u, "MemoryHeatmapCell must be 16-byte aligned");
static_assert(std::is_trivially_copyable_v<MemoryHeatmapCell>);
static_assert(std::is_standard_layout_v<MemoryHeatmapCell>);

[[nodiscard]] constexpr std::uint8_t pack_cell_permissions(const MemoryProtection& prot,
                                                           bool extra_rwx_hazard = false) noexcept {
    std::uint8_t bits = MemoryCellPermBits::kNone;
    if (prot.readable) {
        bits |= MemoryCellPermBits::kRead;
    }
    if (prot.writable) {
        bits |= MemoryCellPermBits::kWrite;
    }
    if (prot.executable) {
        bits |= MemoryCellPermBits::kExecute;
    }
    if (prot.shared) {
        bits |= MemoryCellPermBits::kShared;
    }
    if (prot.guarded) {
        bits |= MemoryCellPermBits::kGuard;
    }
    if ((prot.writable && prot.executable) || extra_rwx_hazard) {
        bits |= MemoryCellPermBits::kRwxHazard;
    }
    return bits;
}

struct MemoryHeatmapConfig {
    MemoryHeatmapLayout layout{MemoryHeatmapLayout::HilbertCurve};
    MemoryHeatmapScope scope{MemoryHeatmapScope::CompactAddressSpace};
    std::optional<std::uint64_t> focus_start_va{};
    std::optional<std::uint64_t> focus_end_va{};
    std::uint32_t base_page_bytes{4096u};
    std::uint32_t max_cells{65536u};
    std::size_t read_budget_bytes_per_tick{4u * 1024u * 1024u};
    float heat_decay_factor{0.82f};
    bool query_os_pagemap{true};
};

struct HeatmapRegionDescriptor {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0};
    std::string label{};
    std::string module_name{};
    MemoryProtection protection{};
    MemoryRegionKind kind{MemoryRegionKind::Anonymous};
    MemoryCellCategory default_category{MemoryCellCategory::AnonRw};
    ProvenanceTag provenance{ProvenanceTag::LiveMemory};

    [[nodiscard]] constexpr bool contains(std::uint64_t va) const noexcept {
        return end_va > start_va && va >= start_va && (va - start_va) < (end_va - start_va);
    }
};

struct MemoryHeatmapStats {
    std::uint64_t tick_sequence{0};
    std::size_t active_cell_count{0};
    std::size_t mapped_cell_count{0};
    std::size_t resident_cell_count{0};
    std::size_t swapped_cell_count{0};
    std::size_t uncommitted_or_zero_cell_count{0};
    std::size_t dirty_or_mutated_cell_count{0};
    std::size_t rwx_hazard_cell_count{0};
    std::size_t perm_transition_cell_count{0};
    std::size_t newly_allocated_region_count{0};
    std::size_t freed_region_count{0};
    std::size_t bytes_sampled_this_tick{0};
    bool pagemap_available{false};
    std::string pagemap_diagnostic{};
    std::optional<std::uint64_t> focus_ip_va{};
    std::optional<std::uint64_t> focus_sp_va{};
    std::optional<std::uint64_t> fault_va{};
};

struct MemoryHeatmapSnapshot {
    MemoryHeatmapLayout layout{MemoryHeatmapLayout::HilbertCurve};
    MemoryHeatmapScope scope{MemoryHeatmapScope::CompactAddressSpace};
    std::uint32_t hilbert_order{1u};
    std::uint32_t grid_width{2u};
    std::uint32_t grid_height{2u};
    std::uint32_t nominal_cell_bytes{4096u};
    std::vector<MemoryHeatmapCell> cells{};
    std::vector<HeatmapRegionDescriptor> regions{};
    MemoryHeatmapStats stats{};

    [[nodiscard]] const HeatmapRegionDescriptor* find_region_for_va(
        std::uint64_t va) const noexcept;

    [[nodiscard]] std::optional<std::size_t> find_cell_index_for_va(
        std::uint64_t va) const noexcept;
};

/// Fast 64-bit FNV-1a checksum used for rolling page-mutation detection.
[[nodiscard]] std::uint64_t compute_page_checksum_fnv1a64(
    std::span<const std::uint8_t> bytes) noexcept;

/// Computes normalized Shannon byte entropy in `[0, 255]` (`0` = uniform bytes, `255` = 8.0 bits/byte).
[[nodiscard]] std::uint8_t compute_page_entropy_u8(
    std::span<const std::uint8_t> bytes) noexcept;

/// Non-intrusive multi-tick memory residency, dirty-page, & allocator delta tracker.
/// Works seamlessly across live `IProcessSession` / `IDebugSession`, offline crash dumps
/// (`ICrashDumpSession`), and static `IBinaryImage` / `PagedBinaryImage` targets.
class MemoryHeatmapTracker {
public:
    MemoryHeatmapTracker() = default;
    ~MemoryHeatmapTracker() noexcept = default;

    MemoryHeatmapTracker(const MemoryHeatmapTracker&) = default;
    MemoryHeatmapTracker& operator=(const MemoryHeatmapTracker&) = default;
    MemoryHeatmapTracker(MemoryHeatmapTracker&&) noexcept = default;
    MemoryHeatmapTracker& operator=(MemoryHeatmapTracker&&) noexcept = default;

    void reset() noexcept;

    [[nodiscard]] std::uint64_t tick_sequence() const noexcept { return tick_sequence_; }

    /// Samples a live `IProcessSession` (or `IDebugSession::session()` / `ICrashDumpSession`).
    [[nodiscard]] Observed<MemoryHeatmapSnapshot> sample_process(
        IProcessSession& session,
        const MemoryHeatmapConfig& config = {},
        std::span<const PatchInterval> staged_live_patches = {});

    /// Samples an offline `ICrashDumpSession` (`Minidump` / `ET_CORE`), highlighting captured
    /// vs. uncaptured pages plus the crashing thread's stack & instruction pointer page.
    [[nodiscard]] Observed<MemoryHeatmapSnapshot> sample_crash_dump(
        ICrashDumpSession& dump,
        const MemoryHeatmapConfig& config = {});

    /// Samples a static `IBinaryImage` and optional `PagedBinaryImage` (highlighting `W^X`
    /// violations and staged `PatchDirty` pages).
    [[nodiscard]] Observed<MemoryHeatmapSnapshot> sample_static_image(
        const IBinaryImage& image,
        const PagedBinaryImage* patched_image = nullptr,
        const MemoryHeatmapConfig& config = {});

private:
    struct PageHistoryEntry {
        std::uint64_t checksum{0};
        std::uint8_t heat_u8{0};
        std::uint8_t entropy_u8{0};
        std::uint8_t mutation_count_u8{0};
        std::uint8_t last_perm_rwx{0};
        bool has_checksum{false};
        bool saw_soft_dirty{false};
    };

    struct PrevRegionRecord {
        std::uint64_t start_va{0};
        std::uint64_t end_va{0};
        MemoryProtection protection{};
    };

    enum class TrackedSourceTag : std::uint8_t {
        None = 0,
        LiveProcess = 1,
        CrashDump = 2,
        StaticImage = 3,
    };

    static constexpr std::size_t kMaxTrackedPages = 524'288u;

    TrackedSourceTag active_source_{TrackedSourceTag::None};
    ProcessId active_pid_{0};
    std::uintptr_t active_object_token_{0};
    std::uint64_t tick_sequence_{0};
    std::size_t round_robin_cursor_{0};
    std::vector<PrevRegionRecord> prev_regions_{};
    std::unordered_map<std::uint64_t, PageHistoryEntry> page_history_{};
};

/// Lightweight 2D camera/viewport parameters for CPU reference rasterization (`1.0` world unit = 1 grid cell).
struct MemoryHeatmapViewport {
    double center_x{0.0};
    double center_y{0.0};
    double scale_x{16.0};
    double scale_y{16.0};
    std::uint32_t width_px{256u};
    std::uint32_t height_px{256u};
    std::optional<std::uint32_t> hovered_cell_index{};
    std::optional<std::uint32_t> selected_cell_index{};
};

/// Deterministic CPU reference rasterizer rendering `(viewport, snapshot, color_mode)` into
/// a row-major `width_px * height_px * 4` RGBA8 pixel buffer.
/// Used both for headless unit tests and as automatic Vulkan fallback when compute storage
/// images are unsupported by the GPU driver.
[[nodiscard]] std::vector<std::uint8_t> rasterize_memory_heatmap_rgba8(
    const MemoryHeatmapViewport& viewport,
    const MemoryHeatmapSnapshot& snapshot,
    MemoryHeatmapColorMode color_mode = MemoryHeatmapColorMode::AllocatorAndWriteHeat);

void rasterize_memory_heatmap_rgba8_into(
    const MemoryHeatmapViewport& viewport,
    const MemoryHeatmapSnapshot& snapshot,
    MemoryHeatmapColorMode color_mode,
    std::vector<std::uint8_t>& out_rgba8);

} // namespace peelf
