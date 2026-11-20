#include <peelf/memory_heatmap.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace peelf {
namespace {

[[nodiscard]] constexpr std::uint64_t add_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    if (b > (std::numeric_limits<std::uint64_t>::max() - a)) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return a + b;
}

[[nodiscard]] constexpr std::uint64_t sub_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? (a - b) : 0u;
}

[[nodiscard]] constexpr std::uint8_t add_sat_u8(std::uint8_t a, std::uint8_t b) noexcept {
    const unsigned sum = static_cast<unsigned>(a) + static_cast<unsigned>(b);
    return sum > 255u ? static_cast<std::uint8_t>(255u) : static_cast<std::uint8_t>(sum);
}

[[nodiscard]] constexpr std::uint64_t align_down_u64(std::uint64_t val,
                                                     std::uint64_t align) noexcept {
    if (align <= 1u) {
        return val;
    }
    return (val / align) * align;
}

[[nodiscard]] constexpr std::uint64_t align_up_u64(std::uint64_t val,
                                                   std::uint64_t align) noexcept {
    if (align <= 1u) {
        return val;
    }
    const std::uint64_t rem = val % align;
    if (rem == 0u) {
        return val;
    }
    return add_sat_u64(val, align - rem);
}

[[nodiscard]] std::uint32_t sanitize_base_page_bytes(std::uint32_t requested) noexcept {
    if (requested >= 65536u) {
        return 65536u;
    }
    if (requested >= 16384u) {
        return 16384u;
    }
    return 4096u;
}

[[nodiscard]] std::uint32_t sanitize_max_cells(std::uint32_t requested) noexcept {
    constexpr std::uint32_t kMinCells = 16u;
    constexpr std::uint32_t kMaxCellsCap = 1u << 20u; // 1,048,576 cells max
    return std::clamp(requested, kMinCells, kMaxCellsCap);
}

[[nodiscard]] std::uint8_t decay_heat_value(std::uint8_t current_heat,
                                            float decay_factor) noexcept {
    if (current_heat == 0u) {
        return 0u;
    }
    const float clamped = std::clamp(
        std::isfinite(decay_factor) ? decay_factor : 0.82f, 0.0f, 0.995f);
    const float next = std::floor(static_cast<float>(current_heat) * clamped);
    if (next < 1.0f) {
        return 0u;
    }
    if (next >= 255.0f) {
        return 255u;
    }
    return static_cast<std::uint8_t>(next);
}

[[nodiscard]] constexpr int residency_priority(MemoryCellResidency res) noexcept {
    switch (res) {
        case MemoryCellResidency::Resident:          return 40;
        case MemoryCellResidency::Swapped:           return 30;
        case MemoryCellResidency::ZeroOrUncommitted: return 20;
        case MemoryCellResidency::Unknown:           return 10;
    }
    return 10;
}

struct VaInterval {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0};

    [[nodiscard]] constexpr bool overlaps(std::uint64_t a, std::uint64_t b) const noexcept {
        return start_va < b && a < end_va;
    }
};

[[nodiscard]] std::size_t count_overlapping_intervals(std::span<const VaInterval> intervals,
                                                      std::uint64_t start_va,
                                                      std::uint64_t end_va) noexcept {
    std::size_t count = 0u;
    for (const VaInterval& iv : intervals) {
        if (iv.overlaps(start_va, end_va)) {
            ++count;
        }
    }
    return count;
}

[[nodiscard]] bool address_in_span(std::optional<std::uint64_t> opt_va,
                                   std::uint64_t start_va,
                                   std::uint64_t end_va) noexcept {
    if (!opt_va.has_value()) {
        return false;
    }
    const std::uint64_t va = *opt_va;
    return va >= start_va && va < end_va;
}

[[nodiscard]] MemoryCellCategory classify_live_region(
    const MemoryRegion& reg,
    std::span<const ModuleInfo> modules,
    std::span<const std::uint64_t> thread_sps) noexcept {
    if (reg.protection.guarded) {
        return MemoryCellCategory::GuardPage;
    }
    if (reg.usage.is_reserved_only ||
        (!reg.protection.readable && !reg.protection.writable && !reg.protection.executable)) {
        return reg.protection.guarded ? MemoryCellCategory::GuardPage
                                      : MemoryCellCategory::Unmapped;
    }

    for (const std::uint64_t sp : thread_sps) {
        if (reg.contains(sp)) {
            return MemoryCellCategory::ThreadStack;
        }
    }
    if (reg.kind == MemoryRegionKind::Stack || reg.pathname.starts_with("[stack") ||
        reg.usage.owner_tid.has_value()) {
        return MemoryCellCategory::ThreadStack;
    }
    if (reg.kind == MemoryRegionKind::Heap || reg.pathname == "[heap]" ||
        reg.pathname.starts_with("[heap:") || reg.usage.heap_id.has_value()) {
        return MemoryCellCategory::Heap;
    }

    bool in_module = (reg.kind == MemoryRegionKind::Image) || !reg.module_name.empty();
    if (!in_module) {
        for (const ModuleInfo& mod : modules) {
            if (mod.contains(reg.start_address)) {
                in_module = true;
                break;
            }
        }
    }
    if (in_module || reg.kind == MemoryRegionKind::Vdso) {
        if (reg.protection.executable) {
            return MemoryCellCategory::ImageCode;
        }
        if (reg.protection.writable) {
            return MemoryCellCategory::ImageRwData;
        }
        return MemoryCellCategory::ImageRoData;
    }

    if (reg.protection.shared || reg.kind == MemoryRegionKind::MappedFile) {
        return MemoryCellCategory::SharedMapped;
    }
    return MemoryCellCategory::AnonRw;
}

struct OsPageFact {
    MemoryCellResidency residency{MemoryCellResidency::Unknown};
    bool soft_dirty{false};
    bool shared_or_file{false};
};

struct OsPagemapProbeResult {
    bool available{false};
    bool permission_restricted{false};
    std::string diagnostic{};
    std::unordered_map<std::uint64_t, OsPageFact> page_facts{};
};

#if defined(__linux__)
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd() noexcept { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

    void reset() noexcept {
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_{-1};
};
#endif

[[nodiscard]] OsPagemapProbeResult probe_os_page_residency(
    ProcessId pid,
    std::span<const std::uint64_t> query_vas,
    std::uint32_t cell_page_bytes) {
    OsPagemapProbeResult result{};
    if (pid == 0u || query_vas.empty()) {
        return result;
    }

#if defined(__linux__)
    const long raw_os_page = ::sysconf(_SC_PAGESIZE);
    const std::uint64_t os_page_bytes =
        raw_os_page > 0 ? static_cast<std::uint64_t>(raw_os_page) : 4096u;
    (void)cell_page_bytes;

    const std::string path = std::format("/proc/{}/pagemap", pid);
    const UniqueFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd.valid()) {
        const int err = errno;
        if (err == EACCES || err == EPERM) {
            result.permission_restricted = true;
            result.diagnostic = std::format(
                "{} restricted ({}); falling back to region RSS & delta checksums",
                path,
                std::strerror(err));
        } else {
            result.diagnostic = std::format("{} unavailable ({})", path, std::strerror(err));
        }
        return result;
    }

    constexpr std::uint64_t kMaxUserVaForPagemap = std::uint64_t{1} << 52u;
    constexpr std::size_t kMaxPagesPerBatch = 1024u;
    std::vector<std::uint64_t> raw_entries(kMaxPagesPerBatch, 0u);
    result.page_facts.reserve(query_vas.size());

    std::size_t idx = 0u;
    bool any_read_succeeded = false;
    while (idx < query_vas.size()) {
        const std::uint64_t first_va = align_down_u64(query_vas[idx], os_page_bytes);
        if (first_va >= kMaxUserVaForPagemap) {
            ++idx;
            continue;
        }

        std::size_t batch_len = 1u;
        while ((idx + batch_len) < query_vas.size() && batch_len < kMaxPagesPerBatch) {
            const std::uint64_t expected_va =
                first_va + static_cast<std::uint64_t>(batch_len) * os_page_bytes;
            const std::uint64_t candidate_va =
                align_down_u64(query_vas[idx + batch_len], os_page_bytes);
            if (candidate_va != expected_va) {
                break;
            }
            ++batch_len;
        }

        const std::uint64_t pagemap_index = first_va / os_page_bytes;
        if (pagemap_index >
            (static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) / 8u)) {
            idx += batch_len;
            continue;
        }

        const auto byte_offset = static_cast<off_t>(pagemap_index * 8u);
        const std::size_t byte_count = batch_len * sizeof(std::uint64_t);
        const ssize_t got = ::pread(fd.get(), raw_entries.data(), byte_count, byte_offset);
        if (got < static_cast<ssize_t>(sizeof(std::uint64_t))) {
            const int err = got < 0 ? errno : 0;
            if (err == EACCES || err == EPERM) {
                result.permission_restricted = true;
                result.diagnostic = std::format(
                    "{} pread restricted ({}); falling back to region RSS & delta checksums",
                    path,
                    std::strerror(err));
                break;
            }
            idx += batch_len;
            continue;
        }

        any_read_succeeded = true;
        const auto entries_read = static_cast<std::size_t>(got) / sizeof(std::uint64_t);
        for (std::size_t j = 0u; j < entries_read && (idx + j) < query_vas.size(); ++j) {
            const std::uint64_t entry = raw_entries[j];
            const bool present = (entry & (std::uint64_t{1} << 63u)) != 0u;
            const bool swapped = (entry & (std::uint64_t{1} << 62u)) != 0u;
            const bool file_or_shared = (entry & (std::uint64_t{1} << 61u)) != 0u;
            const bool soft_dirty = (entry & (std::uint64_t{1} << 55u)) != 0u;

            OsPageFact fact{};
            if (present) {
                fact.residency = MemoryCellResidency::Resident;
            } else if (swapped) {
                fact.residency = MemoryCellResidency::Swapped;
            } else {
                fact.residency = MemoryCellResidency::ZeroOrUncommitted;
            }
            fact.soft_dirty = soft_dirty;
            fact.shared_or_file = file_or_shared;
            result.page_facts[query_vas[idx + j]] = fact;
        }

        idx += batch_len;
    }

    result.available = any_read_succeeded;
    if (any_read_succeeded && result.diagnostic.empty()) {
        result.diagnostic = std::format("Linux pagemap sampled ({} entries)",
                                        result.page_facts.size());
    }
    return result;

#elif defined(_WIN32)
    (void)cell_page_bytes;
    struct ScopedWinHandle {
        HANDLE h{nullptr};
        ~ScopedWinHandle() noexcept {
            if (h != nullptr && h != INVALID_HANDLE_VALUE) {
                (void)::CloseHandle(h);
            }
        }
    };

    ScopedWinHandle proc{::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid))};
    if (proc.h == nullptr) {
        proc.h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    }
    if (proc.h == nullptr) {
        result.permission_restricted = true;
        result.diagnostic = "OpenProcess for QueryWorkingSetEx denied; using region fallback";
        return result;
    }

    constexpr std::size_t kMaxBatch = 4096u;
    const std::size_t count = std::min<std::size_t>(query_vas.size(), 16384u);
    std::vector<PSAPI_WORKING_SET_EX_INFORMATION> ws_info{};
    ws_info.reserve(std::min(count, kMaxBatch));
    result.page_facts.reserve(count);

    bool any_ok = false;
    for (std::size_t base = 0u; base < count; base += kMaxBatch) {
        const std::size_t chunk = std::min(kMaxBatch, count - base);
        ws_info.assign(chunk, PSAPI_WORKING_SET_EX_INFORMATION{});
        for (std::size_t i = 0u; i < chunk; ++i) {
            ws_info[i].VirtualAddress =
                reinterpret_cast<PVOID>(static_cast< std::uintptr_t >(query_vas[base + i]));
        }
        if (::QueryWorkingSetEx(
                proc.h,
                ws_info.data(),
                static_cast<DWORD>(chunk * sizeof(PSAPI_WORKING_SET_EX_INFORMATION))) == FALSE) {
            break;
        }
        any_ok = true;
        for (std::size_t i = 0u; i < chunk; ++i) {
            const auto& attr = ws_info[i].VirtualAttributes;
            OsPageFact fact{};
            fact.residency = attr.Valid != 0
                                 ? MemoryCellResidency::Resident
                                 : MemoryCellResidency::ZeroOrUncommitted;
            fact.shared_or_file = attr.Shared != 0;
            result.page_facts[query_vas[base + i]] = fact;
        }
    }
    result.available = any_ok;
    result.diagnostic = any_ok ? "Win32 QueryWorkingSetEx sampled"
                               : "QueryWorkingSetEx unavailable; using region fallback";
    return result;
#else
    (void)pid;
    (void)query_vas;
    (void)cell_page_bytes;
    result.diagnostic = "OS pagemap unsupported on this host";
    return result;
#endif
}

struct PlannedSpan {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0};
    std::optional<std::size_t> region_index{};
};

struct GridPlan {
    std::uint32_t cell_bytes{4096u};
    std::vector<PlannedSpan> spans{};
    std::size_t total_cells{0};
};

[[nodiscard]] GridPlan build_grid_plan(std::span<const HeatmapRegionDescriptor> regions,
                                       const MemoryHeatmapConfig& config) {
    GridPlan plan{};
    const std::uint32_t base_page = sanitize_base_page_bytes(config.base_page_bytes);
    const std::uint32_t max_cells = sanitize_max_cells(config.max_cells);

    if (config.scope == MemoryHeatmapScope::FocusedRange &&
        config.focus_start_va.has_value() && config.focus_end_va.has_value() &&
        *config.focus_end_va > *config.focus_start_va) {
        const std::uint64_t focus_lo = align_down_u64(*config.focus_start_va, base_page);
        const std::uint64_t focus_hi = align_up_u64(*config.focus_end_va, base_page);
        const std::uint64_t total_bytes = sub_sat_u64(focus_hi, focus_lo);

        std::uint64_t cell_bytes_u64 = base_page;
        while (total_bytes > 0u &&
               ((total_bytes + cell_bytes_u64 - 1u) / cell_bytes_u64) > max_cells &&
               cell_bytes_u64 < (std::uint64_t{1} << 30u)) {
            cell_bytes_u64 <<= 1u;
        }
        plan.cell_bytes = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(cell_bytes_u64, 0x8000'0000ull));

        // Partition [focus_lo, focus_hi) against sorted regions so holes become Unmapped cells.
        std::uint64_t cursor = focus_lo;
        for (std::size_t ri = 0u; ri < regions.size() && cursor < focus_hi; ++ri) {
            const HeatmapRegionDescriptor& reg = regions[ri];
            if (reg.end_va <= cursor) {
                continue;
            }
            if (reg.start_va >= focus_hi) {
                break;
            }
            if (reg.start_va > cursor) {
                const std::uint64_t gap_end = std::min(reg.start_va, focus_hi);
                plan.spans.push_back(PlannedSpan{
                    .start_va = cursor,
                    .end_va = gap_end,
                    .region_index = std::nullopt,
                });
                cursor = gap_end;
            }
            const std::uint64_t seg_start = std::max(cursor, reg.start_va);
            const std::uint64_t seg_end = std::min(focus_hi, reg.end_va);
            if (seg_end > seg_start) {
                plan.spans.push_back(PlannedSpan{
                    .start_va = seg_start,
                    .end_va = seg_end,
                    .region_index = ri,
                });
                cursor = seg_end;
            }
        }
        if (cursor < focus_hi) {
            plan.spans.push_back(PlannedSpan{
                .start_va = cursor,
                .end_va = focus_hi,
                .region_index = std::nullopt,
            });
        }

        std::size_t cells = 0u;
        for (const PlannedSpan& sp : plan.spans) {
            const std::uint64_t len = sub_sat_u64(sp.end_va, sp.start_va);
            cells += static_cast<std::size_t>((len + plan.cell_bytes - 1u) / plan.cell_bytes);
        }
        plan.total_cells = cells;
        return plan;
    }

    // CompactAddressSpace: pack mapped regions while preserving small inter-region gaps (<= 64 KiB)
    // as Unmapped separator cells and collapsing multi-MiB/TiB canonical VA holes.
    constexpr std::uint64_t kMaxPreservedGapBytes = 64u * 1024u;
    std::vector<PlannedSpan> raw_spans{};
    raw_spans.reserve(regions.size() * 2u);

    for (std::size_t ri = 0u; ri < regions.size(); ++ri) {
        const HeatmapRegionDescriptor& reg = regions[ri];
        if (reg.end_va <= reg.start_va) {
            continue;
        }
        if (!raw_spans.empty()) {
            const std::uint64_t prev_end = raw_spans.back().end_va;
            if (reg.start_va > prev_end) {
                const std::uint64_t gap = reg.start_va - prev_end;
                if (gap <= kMaxPreservedGapBytes) {
                    raw_spans.push_back(PlannedSpan{
                        .start_va = prev_end,
                        .end_va = reg.start_va,
                        .region_index = std::nullopt,
                    });
                } else {
                    // Insert a single compact separator cell so disjoint clusters remain visually separated.
                    raw_spans.push_back(PlannedSpan{
                        .start_va = prev_end,
                        .end_va = add_sat_u64(prev_end, base_page),
                        .region_index = std::nullopt,
                    });
                }
            }
        }
        raw_spans.push_back(PlannedSpan{
            .start_va = reg.start_va,
            .end_va = reg.end_va,
            .region_index = ri,
        });
    }

    auto count_cells_for_step = [&](std::uint64_t step_bytes) noexcept -> std::uint64_t {
        std::uint64_t total = 0u;
        for (const PlannedSpan& sp : raw_spans) {
            const std::uint64_t len = sub_sat_u64(sp.end_va, sp.start_va);
            if (len == 0u) {
                continue;
            }
            if (!sp.region_index.has_value() && len <= base_page) {
                total = add_sat_u64(total, 1u);
            } else {
                total = add_sat_u64(total, (len + step_bytes - 1u) / step_bytes);
            }
        }
        return total;
    };

    std::uint64_t step = base_page;
    while (count_cells_for_step(step) > max_cells && step < (std::uint64_t{1} << 30u)) {
        step <<= 1u;
    }

    plan.cell_bytes = static_cast<std::uint32_t>(std::min<std::uint64_t>(step, 0x8000'0000ull));
    plan.total_cells = static_cast<std::size_t>(
        std::min<std::uint64_t>(count_cells_for_step(plan.cell_bytes), max_cells));
    plan.spans = std::move(raw_spans);
    return plan;
}

void finalize_snapshot_dimensions(MemoryHeatmapSnapshot& snap, MemoryHeatmapLayout layout) noexcept {
    snap.layout = layout;
    const std::size_t cell_count = std::max<std::size_t>(snap.cells.size(), 1u);
    snap.hilbert_order = choose_hilbert_order_for_cells(cell_count);
    const std::uint32_t side = std::uint32_t{1} << snap.hilbert_order;
    snap.grid_width = side;
    if (layout == MemoryHeatmapLayout::LinearRows) {
        const auto rows = static_cast<std::uint32_t>((cell_count + side - 1u) / side);
        snap.grid_height = std::max(rows, 1u);
    } else {
        snap.grid_height = side;
    }
    snap.stats.active_cell_count = snap.cells.size();
}

void compute_snapshot_cell_kpis(MemoryHeatmapSnapshot& snap) noexcept {
    snap.stats.mapped_cell_count = 0u;
    snap.stats.resident_cell_count = 0u;
    snap.stats.swapped_cell_count = 0u;
    snap.stats.uncommitted_or_zero_cell_count = 0u;
    snap.stats.dirty_or_mutated_cell_count = 0u;
    snap.stats.rwx_hazard_cell_count = 0u;
    snap.stats.perm_transition_cell_count = 0u;

    for (const MemoryHeatmapCell& cell : snap.cells) {
        if (cell.category() != MemoryCellCategory::Unmapped) {
            ++snap.stats.mapped_cell_count;
        }
        switch (cell.residency()) {
            case MemoryCellResidency::Resident:
                ++snap.stats.resident_cell_count;
                break;
            case MemoryCellResidency::Swapped:
                ++snap.stats.swapped_cell_count;
                break;
            case MemoryCellResidency::ZeroOrUncommitted:
                ++snap.stats.uncommitted_or_zero_cell_count;
                break;
            case MemoryCellResidency::Unknown:
                break;
        }
        if (cell.mutation_count_u8() > 0u || cell.category() == MemoryCellCategory::PatchDirty ||
            cell.heat_u8() > 0u) {
            ++snap.stats.dirty_or_mutated_cell_count;
        }
        if (cell.has_rwx_hazard()) {
            ++snap.stats.rwx_hazard_cell_count;
        }
        if (cell.has_perm_transition()) {
            ++snap.stats.perm_transition_cell_count;
        }
    }
}

struct RgbFloat {
    float r{0.0f};
    float g{0.0f};
    float b{0.0f};
};

[[nodiscard]] constexpr RgbFloat lerp_rgb(RgbFloat a, RgbFloat b, float t) noexcept {
    const float u = t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t);
    return RgbFloat{
        .r = a.r + (b.r - a.r) * u,
        .g = a.g + (b.g - a.g) * u,
        .b = a.b + (b.b - a.b) * u,
    };
}

[[nodiscard]] constexpr RgbFloat magma_heat_ramp(float t) noexcept {
    const float x = t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t);
    constexpr std::array<RgbFloat, 5> kStops{{
        {0.08f, 0.06f, 0.16f}, // Deep cold indigo
        {0.42f, 0.11f, 0.45f}, // Violet
        {0.82f, 0.23f, 0.22f}, // Crimson-magma
        {0.97f, 0.58f, 0.12f}, // Glowing amber
        {1.00f, 0.95f, 0.65f}, // Incandescent yellow-white
    }};
    const float scaled = x * 4.0f;
    const auto seg = static_cast<std::size_t>(scaled >= 4.0f ? 3 : static_cast<int>(scaled));
    const float local_t = scaled - static_cast<float>(seg);
    return lerp_rgb(kStops[seg], kStops[seg + 1u], local_t);
}

[[nodiscard]] constexpr RgbFloat entropy_viridis_ramp(float t) noexcept {
    const float x = t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t);
    constexpr std::array<RgbFloat, 5> kStops{{
        {0.15f, 0.10f, 0.28f}, // 0.0 bits/byte (zero/uniform)
        {0.18f, 0.36f, 0.54f}, // Low-entropy structured
        {0.13f, 0.58f, 0.55f}, // Mid-entropy code/text
        {0.42f, 0.78f, 0.36f}, // Dense data
        {0.99f, 0.91f, 0.15f}, // ~8.0 bits/byte (packed/encrypted)
    }};
    const float scaled = x * 4.0f;
    const auto seg = static_cast<std::size_t>(scaled >= 4.0f ? 3 : static_cast<int>(scaled));
    const float local_t = scaled - static_cast<float>(seg);
    return lerp_rgb(kStops[seg], kStops[seg + 1u], local_t);
}

[[nodiscard]] constexpr RgbFloat category_base_color(MemoryCellCategory cat) noexcept {
    switch (cat) {
        case MemoryCellCategory::Unmapped:     return {0.10f, 0.12f, 0.16f};
        case MemoryCellCategory::ImageCode:    return {0.20f, 0.48f, 0.88f};
        case MemoryCellCategory::ImageRoData:  return {0.26f, 0.66f, 0.76f};
        case MemoryCellCategory::ImageRwData:  return {0.20f, 0.68f, 0.54f};
        case MemoryCellCategory::Heap:         return {0.34f, 0.76f, 0.32f};
        case MemoryCellCategory::ThreadStack:  return {0.64f, 0.36f, 0.86f};
        case MemoryCellCategory::AnonRw:       return {0.72f, 0.56f, 0.26f};
        case MemoryCellCategory::SharedMapped: return {0.28f, 0.62f, 0.68f};
        case MemoryCellCategory::GuardPage:    return {0.58f, 0.18f, 0.22f};
        case MemoryCellCategory::PatchDirty:   return {0.06f, 0.82f, 0.94f};
    }
    return {0.10f, 0.12f, 0.16f};
}

[[nodiscard]] constexpr RgbFloat permission_base_color(const MemoryHeatmapCell& cell) noexcept {
    if (cell.category() == MemoryCellCategory::Unmapped) {
        return {0.10f, 0.12f, 0.16f};
    }
    if (cell.is_guarded()) {
        return {0.58f, 0.18f, 0.22f};
    }
    if (cell.has_rwx_hazard() || (cell.is_writable() && cell.is_executable())) {
        return {0.95f, 0.18f, 0.52f};
    }
    if (cell.is_executable()) {
        return {0.22f, 0.52f, 0.92f};
    }
    if (cell.is_writable()) {
        return {0.86f, 0.60f, 0.20f};
    }
    if (cell.is_readable()) {
        return {0.30f, 0.68f, 0.64f};
    }
    return {0.22f, 0.24f, 0.30f};
}

[[nodiscard]] constexpr RgbFloat apply_residency_modulation(
    RgbFloat base,
    MemoryCellCategory cat,
    MemoryCellResidency res) noexcept {
    if (cat == MemoryCellCategory::Unmapped) {
        return base;
    }
    switch (res) {
        case MemoryCellResidency::Resident:
            return base;
        case MemoryCellResidency::Swapped:
            return lerp_rgb(
                RgbFloat{base.r * 0.52f, base.g * 0.48f, base.b * 0.58f},
                RgbFloat{0.42f, 0.24f, 0.62f},
                0.35f);
        case MemoryCellResidency::ZeroOrUncommitted:
            return RgbFloat{base.r * 0.34f, base.g * 0.35f, base.b * 0.38f};
        case MemoryCellResidency::Unknown:
            return RgbFloat{base.r * 0.78f, base.g * 0.78f, base.b * 0.80f};
    }
    return base;
}

[[nodiscard]] constexpr std::uint8_t float_to_u8(float v) noexcept {
    const float clamped = v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
    return static_cast<std::uint8_t>(clamped * 255.0f + 0.5f);
}

} // namespace

const HeatmapRegionDescriptor* MemoryHeatmapSnapshot::find_region_for_va(
    std::uint64_t va) const noexcept {
    const auto it = std::ranges::upper_bound(
        regions, va, {}, &HeatmapRegionDescriptor::start_va);
    if (it == regions.begin()) {
        return nullptr;
    }
    const auto prev = std::prev(it);
    if (prev->contains(va)) {
        return &(*prev);
    }
    return nullptr;
}

std::optional<std::size_t> MemoryHeatmapSnapshot::find_cell_index_for_va(
    std::uint64_t va) const noexcept {
    if (cells.empty()) {
        return std::nullopt;
    }
    const auto it = std::ranges::upper_bound(cells, va, {}, &MemoryHeatmapCell::base_va);
    if (it == cells.begin()) {
        return std::nullopt;
    }
    const std::size_t idx = static_cast<std::size_t>(std::distance(cells.begin(), std::prev(it)));
    const MemoryHeatmapCell& cell = cells[idx];
    const std::uint64_t end_va = add_sat_u64(cell.base_va, cell.span_bytes());
    if (va >= cell.base_va && va < end_va) {
        return idx;
    }
    return std::nullopt;
}

std::uint64_t compute_page_checksum_fnv1a64(std::span<const std::uint8_t> bytes) noexcept {
    constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    std::size_t i = 0u;
    const std::size_t word_limit = bytes.size() & ~std::size_t{7u};
    for (; i < word_limit; i += 8u) {
        std::uint64_t word = 0u;
        std::memcpy(&word, bytes.data() + i, sizeof(word));
        hash ^= word;
        hash *= kFnvPrime;
    }
    for (; i < bytes.size(); ++i) {
        hash ^= static_cast<std::uint64_t>(bytes[i]);
        hash *= kFnvPrime;
    }
    return hash;
}

std::uint8_t compute_page_entropy_u8(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return 0u;
    }
    std::array<std::uint32_t, 256> counts{};
    for (const std::uint8_t b : bytes) {
        ++counts[b];
    }

    const double inv_n = 1.0 / static_cast<double>(bytes.size());
    double entropy_bits = 0.0;
    std::uint32_t distinct = 0u;
    for (const std::uint32_t c : counts) {
        if (c == 0u) {
            continue;
        }
        ++distinct;
        const double p = static_cast<double>(c) * inv_n;
        entropy_bits -= p * std::log2(p);
    }
    if (distinct <= 1u || entropy_bits <= 0.0) {
        return 0u;
    }
    const double scaled = std::clamp((entropy_bits / 8.0) * 255.0, 0.0, 255.0);
    return static_cast<std::uint8_t>(std::lround(scaled));
}

void MemoryHeatmapTracker::reset() noexcept {
    active_source_ = TrackedSourceTag::None;
    active_pid_ = 0u;
    active_object_token_ = 0u;
    tick_sequence_ = 0u;
    round_robin_cursor_ = 0u;
    prev_regions_.clear();
    page_history_.clear();
}

Observed<MemoryHeatmapSnapshot> MemoryHeatmapTracker::sample_process(
    IProcessSession& session,
    const MemoryHeatmapConfig& config,
    std::span<const PatchInterval> staged_live_patches) {
    if (session.is_crash_dump()) {
        if (auto* dump = dynamic_cast<ICrashDumpSession*>(&session); dump != nullptr) {
            return sample_crash_dump(*dump, config);
        }
    }

    const auto session_token = reinterpret_cast<std::uintptr_t>(&session);
    if (active_source_ != TrackedSourceTag::LiveProcess ||
        active_pid_ != session.pid() ||
        active_object_token_ != session_token) {
        reset();
        active_source_ = TrackedSourceTag::LiveProcess;
        active_pid_ = session.pid();
        active_object_token_ = session_token;
    }

    ++tick_sequence_;
    if (tick_sequence_ > 1u) {
        for (auto& [va, hist] : page_history_) {
            (void)va;
            hist.heat_u8 = decay_heat_value(hist.heat_u8, config.heat_decay_factor);
        }
    }

    TargetInstanceId target_id{};
    target_id.backend = BackendKind::LiveNativeReadOnly;
    target_id.pid = session.pid();
    target_id.session_nonce = static_cast<std::uint64_t>(session_token);
    const CaptureStamp start_stamp =
        CaptureStamp::capture_now(target_id, tick_sequence_, session.is_suspended());

    Observed<MemoryHeatmapSnapshot> out{};
    out.provenance = ProvenanceTag::LiveMemory;
    out.evidence.push_back(Evidence{
        .tag = ProvenanceTag::LiveMemory,
        .source = "IProcessSession::memory_regions",
        .detail = std::format("pid={} tick={}", session.pid(), tick_sequence_),
    });

    auto regions_res = session.memory_regions();
    if (!regions_res) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::capture_interval(start_stamp, CaptureAvailability::Unavailable);
        out.note = regions_res.error().message;
        return out;
    }

    std::vector<MemoryRegion> raw_regions = std::move(*regions_res);
    std::ranges::sort(raw_regions, {}, &MemoryRegion::start_address);

    std::vector<ModuleInfo> modules{};
    if (auto mod_res = session.modules(); mod_res.has_value()) {
        modules = std::move(*mod_res);
    }

    std::vector<std::uint64_t> thread_sps{};
    std::vector<std::uint64_t> thread_ips{};
    if (auto thr_res = session.threads(); thr_res.has_value()) {
        for (const ThreadInfo& ti : *thr_res) {
            if (ti.stack_pointer.has_value() && *ti.stack_pointer != 0u) {
                thread_sps.push_back(*ti.stack_pointer);
            }
            if (ti.instruction_pointer.has_value() && *ti.instruction_pointer != 0u) {
                thread_ips.push_back(*ti.instruction_pointer);
            }
        }
    }

    MemoryHeatmapSnapshot snap{};
    snap.scope = config.scope;
    snap.stats.tick_sequence = tick_sequence_;
    if (!thread_ips.empty()) {
        snap.stats.focus_ip_va = thread_ips.front();
    }
    if (!thread_sps.empty()) {
        snap.stats.focus_sp_va = thread_sps.front();
    }

    // Diff region map against previous tick to detect newly allocated & freed regions.
    const bool has_prev_tick = (tick_sequence_ > 1u) && !prev_regions_.empty();
    auto find_prev_region_at = [&](std::uint64_t va) noexcept -> const PrevRegionRecord* {
        const auto it =
            std::ranges::upper_bound(prev_regions_, va, {}, &PrevRegionRecord::start_va);
        if (it == prev_regions_.begin()) {
            return nullptr;
        }
        const auto prev = std::prev(it);
        if (va >= prev->start_va && va < prev->end_va) {
            return &(*prev);
        }
        return nullptr;
    };

    if (has_prev_tick) {
        for (const MemoryRegion& cur : raw_regions) {
            if (cur.end_address <= cur.start_address) {
                continue;
            }
            if (find_prev_region_at(cur.start_address) == nullptr) {
                ++snap.stats.newly_allocated_region_count;
            }
        }
        for (const PrevRegionRecord& old_reg : prev_regions_) {
            const auto it = std::ranges::upper_bound(
                raw_regions, old_reg.start_va, {}, &MemoryRegion::start_address);
            bool still_covered = false;
            if (it != raw_regions.begin()) {
                const auto prev = std::prev(it);
                if (old_reg.start_va >= prev->start_address && old_reg.start_va < prev->end_address) {
                    still_covered = true;
                }
            }
            if (!still_covered && it != raw_regions.end() && it->start_address < old_reg.end_va) {
                still_covered = true;
            }
            if (!still_covered) {
                ++snap.stats.freed_region_count;
                std::erase_if(page_history_, [&](const auto& kv) {
                    return kv.first >= old_reg.start_va && kv.first < old_reg.end_va;
                });
            }
        }
    }

    snap.regions.reserve(raw_regions.size());
    for (const MemoryRegion& reg : raw_regions) {
        if (reg.end_address <= reg.start_address) {
            continue;
        }
        std::string mod_name = reg.module_name;
        if (mod_name.empty()) {
            for (const ModuleInfo& mod : modules) {
                if (mod.contains(reg.start_address)) {
                    mod_name = mod.name;
                    break;
                }
            }
        }
        std::string label = !reg.pathname.empty() ? reg.pathname : mod_name;
        if (label.empty()) {
            label = std::string(to_string(reg.kind));
        }
        snap.regions.push_back(HeatmapRegionDescriptor{
            .start_va = reg.start_address,
            .end_va = reg.end_address,
            .label = std::move(label),
            .module_name = std::move(mod_name),
            .protection = reg.protection,
            .kind = reg.kind,
            .default_category = classify_live_region(reg, modules, thread_sps),
            .provenance = ProvenanceTag::LiveMemory,
        });
    }

    std::vector<VaInterval> staged_intervals{};
    staged_intervals.reserve(staged_live_patches.size());
    for (const PatchInterval& p : staged_live_patches) {
        if (!p.patched.empty()) {
            staged_intervals.push_back(VaInterval{
                .start_va = p.offset,
                .end_va = add_sat_u64(p.offset, p.patched.size()),
            });
        }
    }

    const GridPlan plan = build_grid_plan(snap.regions, config);
    snap.nominal_cell_bytes = plan.cell_bytes;
    snap.cells.reserve(plan.total_cells);

    struct MappedCellRef {
        std::size_t cell_index{0};
        std::size_t region_index{0};
        bool high_priority_sample{false};
    };
    std::vector<MappedCellRef> sample_candidates{};
    sample_candidates.reserve(plan.total_cells);

    std::vector<std::uint64_t> pagemap_query_vas{};
    if (config.query_os_pagemap) {
        pagemap_query_vas.reserve(std::min<std::size_t>(plan.total_cells, 32768u));
    }

    for (const PlannedSpan& sp : plan.spans) {
        if (sp.end_va <= sp.start_va) {
            continue;
        }
        if (!sp.region_index.has_value()) {
            const std::uint64_t total_len = sub_sat_u64(sp.end_va, sp.start_va);
            const std::uint64_t step =
                (config.scope == MemoryHeatmapScope::CompactAddressSpace &&
                 total_len <= sanitize_base_page_bytes(config.base_page_bytes))
                    ? total_len
                    : static_cast<std::uint64_t>(plan.cell_bytes);
            for (std::uint64_t va = sp.start_va; va < sp.end_va; va = add_sat_u64(va, step)) {
                const auto cur_span =
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(step, sp.end_va - va));
                snap.cells.push_back(MemoryHeatmapCell::pack(
                    va,
                    cur_span,
                    MemoryCellCategory::Unmapped,
                    MemoryCellPermBits::kNone,
                    MemoryCellResidency::ZeroOrUncommitted));
            }
            continue;
        }

        const std::size_t ri = *sp.region_index;
        const HeatmapRegionDescriptor& reg_desc = snap.regions[ri];
        const MemoryRegion& orig_reg = raw_regions[ri];

        MemoryCellResidency fallback_res = MemoryCellResidency::Unknown;
        if (orig_reg.usage.is_reserved_only || orig_reg.protection.guarded) {
            fallback_res = MemoryCellResidency::ZeroOrUncommitted;
        } else if (orig_reg.usage.rss_bytes.has_value()) {
            if (*orig_reg.usage.rss_bytes == 0u) {
                fallback_res = orig_reg.usage.swap_bytes.value_or(0u) > 0u
                                   ? MemoryCellResidency::Swapped
                                   : MemoryCellResidency::ZeroOrUncommitted;
            } else if (*orig_reg.usage.rss_bytes >= orig_reg.size()) {
                fallback_res = MemoryCellResidency::Resident;
            }
        }

        for (std::uint64_t va = sp.start_va; va < sp.end_va;
             va = add_sat_u64(va, plan.cell_bytes)) {
            const std::uint64_t cell_end =
                std::min<std::uint64_t>(sp.end_va, add_sat_u64(va, plan.cell_bytes));
            const auto span_u32 = static_cast<std::uint32_t>(cell_end - va);

            bool newly_alloc = false;
            bool perm_flipped = false;
            bool jit_wx_hazard = false;
            if (has_prev_tick) {
                const PrevRegionRecord* prev_r = find_prev_region_at(va);
                if (prev_r == nullptr) {
                    newly_alloc = true;
                } else if (prev_r->protection.readable != reg_desc.protection.readable ||
                           prev_r->protection.writable != reg_desc.protection.writable ||
                           prev_r->protection.executable != reg_desc.protection.executable) {
                    perm_flipped = true;
                    if ((prev_r->protection.writable && reg_desc.protection.executable) ||
                        (reg_desc.protection.writable && prev_r->protection.executable)) {
                        jit_wx_hazard = true;
                    }
                }
            }

            PageHistoryEntry& hist = page_history_[va];
            if (newly_alloc || perm_flipped) {
                hist.heat_u8 = 255u;
                hist.mutation_count_u8 = add_sat_u8(hist.mutation_count_u8, 1u);
            }
            hist.last_perm_rwx = pack_cell_permissions(reg_desc.protection, jit_wx_hazard);

            MemoryCellCategory cat = reg_desc.default_category;
            const std::size_t patch_hits =
                count_overlapping_intervals(staged_intervals, va, cell_end);
            if (patch_hits > 0u) {
                cat = MemoryCellCategory::PatchDirty;
                hist.heat_u8 = std::max<std::uint8_t>(hist.heat_u8, 224u);
            }

            bool focus_hit = false;
            for (const std::uint64_t ip : thread_ips) {
                if (ip >= va && ip < cell_end) {
                    focus_hit = true;
                    break;
                }
            }
            if (!focus_hit) {
                for (const std::uint64_t tsp : thread_sps) {
                    if (tsp >= va && tsp < cell_end) {
                        focus_hit = true;
                        break;
                    }
                }
            }

            const std::size_t cell_idx = snap.cells.size();
            snap.cells.push_back(MemoryHeatmapCell::pack(
                va,
                span_u32,
                cat,
                pack_cell_permissions(reg_desc.protection, jit_wx_hazard),
                fallback_res,
                hist.heat_u8,
                hist.entropy_u8,
                hist.mutation_count_u8,
                perm_flipped,
                newly_alloc,
                focus_hit));

            if (config.query_os_pagemap && pagemap_query_vas.size() < 32768u &&
                cat != MemoryCellCategory::Unmapped) {
                pagemap_query_vas.push_back(va);
            }

            if (reg_desc.protection.readable && !reg_desc.protection.guarded &&
                !orig_reg.usage.is_reserved_only) {
                const bool high_prio = reg_desc.protection.writable || perm_flipped || newly_alloc;
                sample_candidates.push_back(MappedCellRef{
                    .cell_index = cell_idx,
                    .region_index = ri,
                    .high_priority_sample = high_prio,
                });
            }
        }
    }

    // Optional OS page residency & soft-dirty enrichment.
    CaptureAvailability final_availability = CaptureAvailability::Complete;
    if (config.query_os_pagemap && !pagemap_query_vas.empty()) {
        OsPagemapProbeResult pm =
            probe_os_page_residency(session.pid(), pagemap_query_vas, plan.cell_bytes);
        snap.stats.pagemap_available = pm.available;
        snap.stats.pagemap_diagnostic = std::move(pm.diagnostic);
        if (pm.available) {
            out.evidence.push_back(Evidence{
                .tag = ProvenanceTag::ProcOrOsApi,
                .source = "os_pagemap",
                .detail = snap.stats.pagemap_diagnostic,
            });
            for (MemoryHeatmapCell& cell : snap.cells) {
                const auto it = pm.page_facts.find(cell.base_va);
                if (it == pm.page_facts.end()) {
                    continue;
                }
                if (residency_priority(it->second.residency) >=
                    residency_priority(cell.residency()) ||
                    cell.residency() == MemoryCellResidency::Unknown) {
                    cell.set_residency(it->second.residency);
                }
                if (it->second.soft_dirty) {
                    PageHistoryEntry& hist = page_history_[cell.base_va];
                    if (!hist.saw_soft_dirty) {
                        hist.saw_soft_dirty = true;
                        if (tick_sequence_ == 1u && hist.heat_u8 < 96u) {
                            hist.heat_u8 = 96u;
                            cell.set_heat_u8(hist.heat_u8);
                        }
                    }
                }
            }
        } else if (pm.permission_restricted) {
            final_availability = CaptureAvailability::Partial;
            out.note = snap.stats.pagemap_diagnostic;
            out.evidence.push_back(Evidence{
                .tag = ProvenanceTag::ProcOrOsApi,
                .source = "os_pagemap",
                .detail = snap.stats.pagemap_diagnostic,
            });
        }
    }

    // Bounded round-robin read_memory sampling for rolling 64-bit checksums & page entropy.
    const std::size_t base_sample_unit =
        std::min<std::size_t>(plan.cell_bytes, sanitize_base_page_bytes(config.base_page_bytes));
    std::size_t budget_remaining = config.read_budget_bytes_per_tick;

    std::vector<std::size_t> ordered_candidates{};
    ordered_candidates.reserve(sample_candidates.size());

    std::vector<std::size_t> prio_indices{};
    std::vector<std::size_t> cold_indices{};
    prio_indices.reserve(sample_candidates.size());
    cold_indices.reserve(sample_candidates.size());

    for (std::size_t i = 0u; i < sample_candidates.size(); ++i) {
        if (sample_candidates[i].high_priority_sample) {
            prio_indices.push_back(i);
        } else {
            cold_indices.push_back(i);
        }
    }

    if (!prio_indices.empty()) {
        const std::size_t start_off = round_robin_cursor_ % prio_indices.size();
        for (std::size_t k = 0u; k < prio_indices.size(); ++k) {
            ordered_candidates.push_back(prio_indices[(start_off + k) % prio_indices.size()]);
        }
    }
    for (const std::size_t idx : cold_indices) {
        const MemoryHeatmapCell& cell = snap.cells[sample_candidates[idx].cell_index];
        const auto hit = page_history_.find(cell.base_va);
        if (hit == page_history_.end() || !hit->second.has_checksum) {
            ordered_candidates.push_back(idx);
        }
    }

    std::vector<std::uint8_t> read_buf{};
    std::size_t high_prio_sampled = 0u;
    std::size_t cursor_idx = 0u;
    while (cursor_idx < ordered_candidates.size() && budget_remaining >= base_sample_unit) {
        const MappedCellRef first_ref = sample_candidates[ordered_candidates[cursor_idx]];
        const MemoryHeatmapCell& first_cell = snap.cells[first_ref.cell_index];
        const std::size_t single_read_bytes =
            std::min<std::size_t>(first_cell.span_bytes(), base_sample_unit);
        if (single_read_bytes == 0u || single_read_bytes > budget_remaining) {
            ++cursor_idx;
            continue;
        }

        // Coalesce contiguous cells when each cell is exactly single_read_bytes wide.
        std::size_t batch_cells = 1u;
        constexpr std::size_t kMaxChunkBytes = 64u * 1024u;
        if (first_cell.span_bytes() == single_read_bytes) {
            while ((cursor_idx + batch_cells) < ordered_candidates.size()) {
                const std::size_t next_bytes = (batch_cells + 1u) * single_read_bytes;
                if (next_bytes > budget_remaining || next_bytes > kMaxChunkBytes) {
                    break;
                }
                const MappedCellRef next_ref =
                    sample_candidates[ordered_candidates[cursor_idx + batch_cells]];
                if (next_ref.region_index != first_ref.region_index) {
                    break;
                }
                const MemoryHeatmapCell& next_cell = snap.cells[next_ref.cell_index];
                const std::uint64_t expected_va =
                    first_cell.base_va +
                    static_cast<std::uint64_t>(batch_cells * single_read_bytes);
                if (next_cell.base_va != expected_va ||
                    next_cell.span_bytes() != single_read_bytes) {
                    break;
                }
                ++batch_cells;
            }
        }

        const std::size_t total_req = batch_cells * single_read_bytes;
        read_buf.assign(total_req, 0u);
        auto read_res = session.read_memory(first_cell.base_va, read_buf);

        const std::size_t bytes_got =
            read_res.has_value() ? std::min<std::size_t>(*read_res, total_req) : 0u;
        const std::size_t cells_completed = bytes_got / single_read_bytes;
        const std::size_t cells_advanced = std::max<std::size_t>(cells_completed, 1u);
        const std::size_t bytes_charged =
            std::min<std::size_t>(cells_advanced * single_read_bytes, budget_remaining);
        budget_remaining -= bytes_charged;
        snap.stats.bytes_sampled_this_tick += bytes_charged;

        for (std::size_t b = 0u; b < cells_advanced; ++b) {
            const MappedCellRef ref = sample_candidates[ordered_candidates[cursor_idx + b]];
            if (ref.high_priority_sample) {
                ++high_prio_sampled;
            }
            if (b >= cells_completed) {
                continue;
            }
            const std::size_t slice_off = b * single_read_bytes;

            MemoryHeatmapCell& cell = snap.cells[ref.cell_index];
            const std::span<const std::uint8_t> page_bytes(
                read_buf.data() + slice_off, single_read_bytes);
            const std::uint64_t csum = compute_page_checksum_fnv1a64(page_bytes);
            const std::uint8_t ent = compute_page_entropy_u8(page_bytes);

            PageHistoryEntry& hist = page_history_[cell.base_va];
            if (hist.has_checksum) {
                if (hist.checksum != csum) {
                    hist.checksum = csum;
                    hist.heat_u8 = 255u;
                    hist.mutation_count_u8 = add_sat_u8(hist.mutation_count_u8, 1u);
                }
            } else {
                hist.has_checksum = true;
                hist.checksum = csum;
            }
            hist.entropy_u8 = ent;

            if (cell.residency() == MemoryCellResidency::Unknown) {
                cell.set_residency(MemoryCellResidency::Resident);
            }
            cell.set_heat_u8(hist.heat_u8);
            cell.set_entropy_u8(hist.entropy_u8);
            cell.set_mutation_count_u8(hist.mutation_count_u8);
        }

        cursor_idx += cells_advanced;
    }

    if (!prio_indices.empty()) {
        round_robin_cursor_ =
            (round_robin_cursor_ + std::max<std::size_t>(high_prio_sampled, 1u)) %
            prio_indices.size();
    }

    if (page_history_.size() > kMaxTrackedPages) {
        page_history_.clear();
    }

    prev_regions_.clear();
    prev_regions_.reserve(raw_regions.size());
    for (const MemoryRegion& reg : raw_regions) {
        if (reg.end_address > reg.start_address) {
            prev_regions_.push_back(PrevRegionRecord{
                .start_va = reg.start_address,
                .end_va = reg.end_address,
                .protection = reg.protection,
            });
        }
    }

    finalize_snapshot_dimensions(snap, config.layout);
    compute_snapshot_cell_kpis(snap);

    out.value = std::move(snap);
    out.availability = final_availability;
    out.stamp = CaptureStamp::capture_interval(start_stamp, final_availability);
    return out;
}

Observed<MemoryHeatmapSnapshot> MemoryHeatmapTracker::sample_crash_dump(
    ICrashDumpSession& dump,
    const MemoryHeatmapConfig& config) {
    const auto dump_token = reinterpret_cast<std::uintptr_t>(&dump);
    if (active_source_ != TrackedSourceTag::CrashDump || active_object_token_ != dump_token) {
        reset();
        active_source_ = TrackedSourceTag::CrashDump;
        active_pid_ = dump.pid();
        active_object_token_ = dump_token;
    }
    ++tick_sequence_;

    const CrashDumpSummary& summary = dump.crash_summary();
    TargetInstanceId target_id{};
    if (summary.kind == CrashDumpKind::WindowsMinidump) {
        target_id.backend = BackendKind::CrashDumpMinidump;
    } else if (summary.kind == CrashDumpKind::MachOCore) {
        target_id.backend = BackendKind::CrashDumpMachOCore;
    } else {
        target_id.backend = BackendKind::CrashDumpElfCore;
    }
    target_id.pid = summary.pid;
    target_id.image_sha256 = summary.sha256;
    target_id.dump_nonce = static_cast<std::uint64_t>(dump_token);
    const CaptureStamp start_stamp =
        CaptureStamp::capture_now(target_id, tick_sequence_, true);

    Observed<MemoryHeatmapSnapshot> out{};
    out.provenance = ProvenanceTag::CrashDump;
    out.evidence.push_back(Evidence{
        .tag = ProvenanceTag::CrashDump,
        .source = std::string(to_string(summary.kind)),
        .detail = std::format("pid={} regions={}", summary.pid, summary.region_count),
    });

    auto regions_res = dump.memory_regions();
    if (!regions_res) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::capture_interval(start_stamp, CaptureAvailability::Unavailable);
        out.note = regions_res.error().message;
        return out;
    }

    std::vector<MemoryRegion> raw_regions = std::move(*regions_res);
    std::ranges::sort(raw_regions, {}, &MemoryRegion::start_address);

    std::vector<ModuleInfo> modules{};
    if (auto mod_res = dump.modules(); mod_res.has_value()) {
        modules = std::move(*mod_res);
    }

    std::optional<ThreadId> crash_tid{};
    std::optional<std::uint64_t> crash_ip{};
    std::optional<std::uint64_t> crash_sp{};
    std::optional<std::uint64_t> fault_va{};
    if (summary.exception.has_value()) {
        crash_tid = summary.exception->thread_id;
        crash_ip = summary.exception->instruction_pointer;
        fault_va = summary.exception->fault_address;
    }

    std::vector<std::uint64_t> thread_sps{};
    if (auto thr_res = dump.threads(); thr_res.has_value()) {
        for (const ThreadInfo& ti : *thr_res) {
            if (ti.stack_pointer.has_value() && *ti.stack_pointer != 0u) {
                thread_sps.push_back(*ti.stack_pointer);
                if (!crash_sp.has_value() &&
                    (!crash_tid.has_value() || ti.tid == *crash_tid)) {
                    crash_sp = ti.stack_pointer;
                }
            }
            if (!crash_ip.has_value() && ti.instruction_pointer.has_value() &&
                (!crash_tid.has_value() || ti.tid == *crash_tid)) {
                crash_ip = ti.instruction_pointer;
            }
        }
    }

    MemoryHeatmapSnapshot snap{};
    snap.scope = config.scope;
    snap.stats.tick_sequence = tick_sequence_;
    snap.stats.focus_ip_va = crash_ip;
    snap.stats.focus_sp_va = crash_sp;
    snap.stats.fault_va = fault_va;

    // Include captured regions plus uncaptured holes inside module spans so minidump holes are visible.
    snap.regions.reserve(raw_regions.size() + modules.size());
    for (const MemoryRegion& reg : raw_regions) {
        if (reg.end_address <= reg.start_address) {
            continue;
        }
        MemoryCellCategory cat = classify_live_region(reg, modules, thread_sps);
        if (crash_sp.has_value() && reg.contains(*crash_sp)) {
            cat = MemoryCellCategory::ThreadStack;
        }
        std::string label = !reg.pathname.empty() ? reg.pathname : reg.module_name;
        if (label.empty()) {
            label = std::string(to_string(reg.kind));
        }
        snap.regions.push_back(HeatmapRegionDescriptor{
            .start_va = reg.start_address,
            .end_va = reg.end_address,
            .label = std::move(label),
            .module_name = reg.module_name,
            .protection = reg.protection,
            .kind = reg.kind,
            .default_category = cat,
            .provenance = ProvenanceTag::CrashDump,
        });
    }

    // Add uncaptured module holes (bounded per module) when minidump omitted code/rodata pages.
    const std::uint32_t base_page = sanitize_base_page_bytes(config.base_page_bytes);
    for (const ModuleInfo& mod : modules) {
        if (mod.size == 0u) {
            continue;
        }
        const std::uint64_t mod_end =
            std::min(mod.end_address(), add_sat_u64(mod.base_address, 16ull * base_page));
        bool any_covered = false;
        for (const MemoryRegion& reg : raw_regions) {
            if (reg.start_address < mod.end_address() && mod.base_address < reg.end_address) {
                any_covered = true;
                break;
            }
        }
        if (!any_covered && mod_end > mod.base_address) {
            snap.regions.push_back(HeatmapRegionDescriptor{
                .start_va = mod.base_address,
                .end_va = mod_end,
                .label = mod.name + " (uncaptured module hole)",
                .module_name = mod.name,
                .protection = MemoryProtection{.readable = true, .executable = true},
                .kind = MemoryRegionKind::Image,
                .default_category = MemoryCellCategory::Unmapped,
                .provenance = ProvenanceTag::CrashDump,
            });
        }
    }
    std::ranges::sort(snap.regions, {}, &HeatmapRegionDescriptor::start_va);

    const GridPlan plan = build_grid_plan(snap.regions, config);
    snap.nominal_cell_bytes = plan.cell_bytes;
    snap.cells.reserve(plan.total_cells);

    std::size_t budget_remaining = config.read_budget_bytes_per_tick;
    const std::size_t sample_unit = std::min<std::size_t>(plan.cell_bytes, base_page);
    std::vector<std::uint8_t> buf(sample_unit, 0u);

    for (const PlannedSpan& sp : plan.spans) {
        if (sp.end_va <= sp.start_va) {
            continue;
        }
        if (!sp.region_index.has_value()) {
            const std::uint64_t total_len = sub_sat_u64(sp.end_va, sp.start_va);
            const std::uint64_t step =
                (config.scope == MemoryHeatmapScope::CompactAddressSpace && total_len <= base_page)
                    ? total_len
                    : static_cast<std::uint64_t>(plan.cell_bytes);
            for (std::uint64_t va = sp.start_va; va < sp.end_va; va = add_sat_u64(va, step)) {
                const auto span_u32 =
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(step, sp.end_va - va));
                const bool fault_hit = address_in_span(fault_va, va, va + span_u32);
                snap.cells.push_back(MemoryHeatmapCell::pack(
                    va,
                    span_u32,
                    MemoryCellCategory::Unmapped,
                    MemoryCellPermBits::kNone,
                    MemoryCellResidency::ZeroOrUncommitted,
                    fault_hit ? 255u : 0u,
                    0u,
                    0u,
                    false,
                    false,
                    fault_hit));
            }
            continue;
        }

        const HeatmapRegionDescriptor& reg = snap.regions[*sp.region_index];
        for (std::uint64_t va = sp.start_va; va < sp.end_va;
             va = add_sat_u64(va, plan.cell_bytes)) {
            const std::uint64_t cell_end =
                std::min<std::uint64_t>(sp.end_va, add_sat_u64(va, plan.cell_bytes));
            const auto span_u32 = static_cast<std::uint32_t>(cell_end - va);

            const bool ip_hit = address_in_span(crash_ip, va, cell_end);
            const bool sp_hit = address_in_span(crash_sp, va, cell_end);
            const bool fault_hit = address_in_span(fault_va, va, cell_end);
            const bool focus_hit = ip_hit || sp_hit || fault_hit;

            MemoryCellResidency res = reg.default_category == MemoryCellCategory::Unmapped
                                          ? MemoryCellResidency::ZeroOrUncommitted
                                          : MemoryCellResidency::Resident;
            std::uint8_t entropy = 0u;
            if (reg.default_category != MemoryCellCategory::Unmapped &&
                sample_unit > 0u && budget_remaining >= sample_unit) {
                const std::size_t req = std::min<std::size_t>(span_u32, sample_unit);
                buf.assign(req, 0u);
                auto rd = dump.read_memory(va, buf);
                budget_remaining -= req;
                snap.stats.bytes_sampled_this_tick += req;
                if (rd.has_value() && *rd > 0u) {
                    res = MemoryCellResidency::Resident;
                    entropy = compute_page_entropy_u8(std::span<const std::uint8_t>(buf.data(), *rd));
                } else {
                    res = MemoryCellResidency::ZeroOrUncommitted;
                }
            }

            std::uint8_t heat = 0u;
            if (focus_hit) {
                heat = 255u;
            } else if (reg.default_category == MemoryCellCategory::ThreadStack &&
                       crash_sp.has_value() && reg.contains(*crash_sp)) {
                heat = 160u;
            }

            snap.cells.push_back(MemoryHeatmapCell::pack(
                va,
                span_u32,
                reg.default_category,
                pack_cell_permissions(reg.protection),
                res,
                heat,
                entropy,
                0u,
                false,
                false,
                focus_hit));
        }
    }

    finalize_snapshot_dimensions(snap, config.layout);
    compute_snapshot_cell_kpis(snap);

    out.value = std::move(snap);
    out.availability = CaptureAvailability::Complete;
    out.stamp = CaptureStamp::capture_interval(start_stamp, CaptureAvailability::Complete);
    return out;
}

Observed<MemoryHeatmapSnapshot> MemoryHeatmapTracker::sample_static_image(
    const IBinaryImage& image,
    const PagedBinaryImage* patched_image,
    const MemoryHeatmapConfig& config) {
    const auto img_token = reinterpret_cast<std::uintptr_t>(&image);
    if (active_source_ != TrackedSourceTag::StaticImage || active_object_token_ != img_token) {
        reset();
        active_source_ = TrackedSourceTag::StaticImage;
        active_object_token_ = img_token;
    }
    ++tick_sequence_;

    TargetInstanceId target_id{};
    target_id.backend = BackendKind::StaticFile;
    target_id.session_nonce = static_cast<std::uint64_t>(img_token);
    const CaptureStamp start_stamp =
        CaptureStamp::capture_now(target_id, tick_sequence_, true);

    Observed<MemoryHeatmapSnapshot> out{};
    out.provenance = ProvenanceTag::DiskFile;
    out.evidence.push_back(Evidence{
        .tag = ProvenanceTag::DiskFile,
        .source = std::string(to_string(image.format())),
        .detail = std::format("image_base=0x{:X}", image.image_base()),
    });

    const std::uint32_t base_page = sanitize_base_page_bytes(config.base_page_bytes);

    struct StaticSpanSpec {
        HeatmapRegionDescriptor desc{};
        bool extra_wx_hazard{false};
        std::uint64_t backed_va_end{0};
    };
    std::vector<StaticSpanSpec> specs{};

    if (image.format() == Format::MachO && !image.macho_segments().empty()) {
        for (const MachOSegmentCommand& seg : image.macho_segments()) {
            if (seg.virtual_size == 0u && seg.file_size == 0u) {
                continue;
            }
            if (seg.is_pagezero()) {
                // Represent 4 GiB __PAGEZERO as a single guard page in compact mode.
                const std::uint64_t cap_size =
                    config.scope == MemoryHeatmapScope::CompactAddressSpace
                        ? static_cast<std::uint64_t>(base_page)
                        : seg.virtual_size;
                specs.push_back(StaticSpanSpec{
                    .desc = HeatmapRegionDescriptor{
                        .start_va = seg.virtual_address,
                        .end_va = add_sat_u64(seg.virtual_address, cap_size),
                        .label = seg.name,
                        .module_name = {},
                        .protection = MemoryProtection{.guarded = true},
                        .kind = MemoryRegionKind::Image,
                        .default_category = MemoryCellCategory::GuardPage,
                        .provenance = ProvenanceTag::DiskFile,
                    },
                    .extra_wx_hazard = false,
                    .backed_va_end = seg.virtual_address,
                });
                continue;
            }

            const bool seg_wx = seg.init_is_wx() || seg.max_is_wx();
            const MemoryProtection seg_prot{
                .readable = seg.readable(),
                .writable = seg.writable(),
                .executable = seg.executable(),
            };
            if (!seg.sections.empty()) {
                for (const MachOSection& sec : seg.sections) {
                    const std::uint64_t sz = std::max(sec.virtual_size, sec.file_size);
                    if (sz == 0u) {
                        continue;
                    }
                    const MemoryProtection prot{
                        .readable = sec.readable || seg_prot.readable,
                        .writable = sec.writable || seg_prot.writable,
                        .executable = sec.executable || seg_prot.executable,
                    };
                    MemoryCellCategory cat = MemoryCellCategory::ImageRoData;
                    if (prot.executable) {
                        cat = MemoryCellCategory::ImageCode;
                    } else if (prot.writable) {
                        cat = MemoryCellCategory::ImageRwData;
                    }
                    specs.push_back(StaticSpanSpec{
                        .desc = HeatmapRegionDescriptor{
                            .start_va = sec.virtual_address,
                            .end_va = add_sat_u64(sec.virtual_address, sz),
                            .label = !sec.full_name.empty() ? sec.full_name : sec.section_name,
                            .module_name = {},
                            .protection = prot,
                            .kind = MemoryRegionKind::Image,
                            .default_category = cat,
                            .provenance = ProvenanceTag::DiskFile,
                        },
                        .extra_wx_hazard = seg_wx,
                        .backed_va_end = sec.is_zerofill
                                             ? sec.virtual_address
                                             : add_sat_u64(sec.virtual_address, sec.file_size),
                    });
                }
            } else {
                const std::uint64_t sz = std::max(seg.virtual_size, seg.file_size);
                MemoryCellCategory cat = MemoryCellCategory::ImageRoData;
                if (seg_prot.executable) {
                    cat = MemoryCellCategory::ImageCode;
                } else if (seg_prot.writable) {
                    cat = MemoryCellCategory::ImageRwData;
                }
                specs.push_back(StaticSpanSpec{
                    .desc = HeatmapRegionDescriptor{
                        .start_va = seg.virtual_address,
                        .end_va = add_sat_u64(seg.virtual_address, sz),
                        .label = seg.name,
                        .module_name = {},
                        .protection = seg_prot,
                        .kind = MemoryRegionKind::Image,
                        .default_category = cat,
                        .provenance = ProvenanceTag::DiskFile,
                    },
                    .extra_wx_hazard = seg_wx,
                    .backed_va_end = add_sat_u64(seg.virtual_address, seg.file_size),
                });
            }
        }
    } else if (!image.sections().empty()) {
        for (const Section& sec : image.sections()) {
            const std::uint64_t sz = std::max(sec.virtual_size, sec.file_size);
            if (sz == 0u) {
                continue;
            }
            bool seg_wx = false;
            for (const Segment& seg : image.segments()) {
                const std::uint64_t seg_end =
                    add_sat_u64(seg.virtual_address, std::max(seg.virtual_size, seg.file_size));
                if (seg.writable && seg.executable &&
                    sec.virtual_address < seg_end &&
                    add_sat_u64(sec.virtual_address, sz) > seg.virtual_address) {
                    seg_wx = true;
                    break;
                }
            }
            const MemoryProtection prot{
                .readable = sec.readable,
                .writable = sec.writable,
                .executable = sec.executable,
            };
            MemoryCellCategory cat = MemoryCellCategory::ImageRoData;
            if (prot.executable) {
                cat = MemoryCellCategory::ImageCode;
            } else if (prot.writable) {
                cat = MemoryCellCategory::ImageRwData;
            }
            specs.push_back(StaticSpanSpec{
                .desc = HeatmapRegionDescriptor{
                    .start_va = sec.virtual_address,
                    .end_va = add_sat_u64(sec.virtual_address, sz),
                    .label = sec.name.empty() ? "<section>" : sec.name,
                    .module_name = {},
                    .protection = prot,
                    .kind = MemoryRegionKind::Image,
                    .default_category = cat,
                    .provenance = ProvenanceTag::DiskFile,
                },
                .extra_wx_hazard = seg_wx,
                .backed_va_end = add_sat_u64(sec.virtual_address, sec.file_size),
            });
        }
    } else {
        std::size_t seg_idx = 0u;
        for (const Segment& seg : image.segments()) {
            const std::uint64_t sz = std::max(seg.virtual_size, seg.file_size);
            if (sz == 0u) {
                ++seg_idx;
                continue;
            }
            const MemoryProtection prot{
                .readable = seg.readable,
                .writable = seg.writable,
                .executable = seg.executable,
            };
            MemoryCellCategory cat = MemoryCellCategory::ImageRoData;
            if (prot.executable) {
                cat = MemoryCellCategory::ImageCode;
            } else if (prot.writable) {
                cat = MemoryCellCategory::ImageRwData;
            }
            specs.push_back(StaticSpanSpec{
                .desc = HeatmapRegionDescriptor{
                    .start_va = seg.virtual_address,
                    .end_va = add_sat_u64(seg.virtual_address, sz),
                    .label = std::format("LOAD[{}]", seg_idx),
                    .module_name = {},
                    .protection = prot,
                    .kind = MemoryRegionKind::Image,
                    .default_category = cat,
                    .provenance = ProvenanceTag::DiskFile,
                },
                .extra_wx_hazard = seg.writable && seg.executable,
                .backed_va_end = add_sat_u64(seg.virtual_address, seg.file_size),
            });
            ++seg_idx;
        }
    }

    std::ranges::sort(specs, [](const StaticSpanSpec& a, const StaticSpanSpec& b) {
        return a.desc.start_va < b.desc.start_va;
    });

    // Convert PagedBinaryImage file-offset PatchIntervals into VA intervals.
    std::vector<VaInterval> patched_va_intervals{};
    if (patched_image != nullptr && patched_image->dirty()) {
        const std::vector<PatchInterval> file_patches = patched_image->changed_intervals();
        for (const PatchInterval& pi : file_patches) {
            if (pi.patched.empty()) {
                continue;
            }
            const std::uint64_t end_off = pi.end_offset();
            std::uint64_t off = pi.offset;
            while (off < end_off) {
                if (const auto mapped_va = image.file_offset_to_virtual_address(off)) {
                    const std::uint64_t step = std::min<std::uint64_t>(end_off - off, 256u);
                    patched_va_intervals.push_back(VaInterval{
                        .start_va = *mapped_va,
                        .end_va = add_sat_u64(*mapped_va, step),
                    });
                    off = add_sat_u64(off, step);
                } else {
                    const std::uint64_t step = std::min<std::uint64_t>(end_off - off, 256u);
                    off = add_sat_u64(off, std::max<std::uint64_t>(step, 1u));
                }
            }
        }
        if (!patched_va_intervals.empty()) {
            out.evidence.push_back(Evidence{
                .tag = ProvenanceTag::UserAnnotated,
                .source = "PagedBinaryImage::changed_intervals",
                .detail = std::format("{} patched VA spans", patched_va_intervals.size()),
            });
        }
    }

    MemoryHeatmapSnapshot snap{};
    snap.scope = config.scope;
    snap.stats.tick_sequence = tick_sequence_;
    if (image.entry_point() != 0u) {
        snap.stats.focus_ip_va = image.entry_point();
    }

    // Deduplicate/clip overlapping section start_vas so region lookup stays monotonic.
    snap.regions.reserve(specs.size());
    std::vector<bool> region_wx_flags{};
    std::vector<std::uint64_t> region_backed_ends{};
    region_wx_flags.reserve(specs.size());
    region_backed_ends.reserve(specs.size());

    std::uint64_t high_water = 0u;
    for (StaticSpanSpec& s : specs) {
        const std::uint64_t clipped_start = std::max(s.desc.start_va, high_water);
        if (s.desc.end_va <= clipped_start) {
            continue;
        }
        s.desc.start_va = clipped_start;
        high_water = s.desc.end_va;
        snap.regions.push_back(std::move(s.desc));
        region_wx_flags.push_back(s.extra_wx_hazard);
        region_backed_ends.push_back(s.backed_va_end);
    }

    const GridPlan plan = build_grid_plan(snap.regions, config);
    snap.nominal_cell_bytes = plan.cell_bytes;
    snap.cells.reserve(plan.total_cells);

    std::size_t budget_remaining = config.read_budget_bytes_per_tick;
    const std::size_t sample_unit = std::min<std::size_t>(plan.cell_bytes, base_page);

    for (const PlannedSpan& sp : plan.spans) {
        if (sp.end_va <= sp.start_va) {
            continue;
        }
        if (!sp.region_index.has_value()) {
            const std::uint64_t total_len = sub_sat_u64(sp.end_va, sp.start_va);
            const std::uint64_t step =
                (config.scope == MemoryHeatmapScope::CompactAddressSpace && total_len <= base_page)
                    ? total_len
                    : static_cast<std::uint64_t>(plan.cell_bytes);
            for (std::uint64_t va = sp.start_va; va < sp.end_va; va = add_sat_u64(va, step)) {
                const auto span_u32 =
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(step, sp.end_va - va));
                snap.cells.push_back(MemoryHeatmapCell::pack(
                    va,
                    span_u32,
                    MemoryCellCategory::Unmapped,
                    MemoryCellPermBits::kNone,
                    MemoryCellResidency::ZeroOrUncommitted));
            }
            continue;
        }

        const std::size_t ri = *sp.region_index;
        const HeatmapRegionDescriptor& reg = snap.regions[ri];
        const bool wx_flag = region_wx_flags[ri];
        const std::uint64_t backed_end = region_backed_ends[ri];

        for (std::uint64_t va = sp.start_va; va < sp.end_va;
             va = add_sat_u64(va, plan.cell_bytes)) {
            const std::uint64_t cell_end =
                std::min<std::uint64_t>(sp.end_va, add_sat_u64(va, plan.cell_bytes));
            const auto span_u32 = static_cast<std::uint32_t>(cell_end - va);

            const std::size_t patch_hits =
                count_overlapping_intervals(patched_va_intervals, va, cell_end);
            const MemoryCellCategory cat = patch_hits > 0u ? MemoryCellCategory::PatchDirty
                                                           : reg.default_category;
            const MemoryCellResidency res =
                (cat == MemoryCellCategory::GuardPage || va >= backed_end)
                    ? MemoryCellResidency::ZeroOrUncommitted
                    : MemoryCellResidency::Resident;

            std::uint8_t entropy = 0u;
            if (res == MemoryCellResidency::Resident && sample_unit > 0u &&
                budget_remaining >= sample_unit) {
                const std::size_t req = std::min<std::size_t>(span_u32, sample_unit);
                budget_remaining -= req;
                snap.stats.bytes_sampled_this_tick += req;

                bool computed = false;
                if (patched_image != nullptr) {
                    if (const auto foff = image.virtual_address_to_file_offset(va)) {
                        if (*foff < patched_image->size()) {
                            const std::uint64_t avail_len =
                                std::min<std::uint64_t>(req, patched_image->size() - *foff);
                            if (auto eff = patched_image->read_effective(*foff, avail_len);
                                eff.has_value()) {
                                entropy = compute_page_entropy_u8(*eff);
                                computed = true;
                            }
                        }
                    }
                }
                if (!computed) {
                    if (auto bytes_res = image.read_bytes_at_va(va, req); bytes_res.has_value()) {
                        entropy = compute_page_entropy_u8(*bytes_res);
                    }
                }
            }

            const std::uint8_t heat = patch_hits > 0u ? 255u : 0u;
            const auto mutations = static_cast<std::uint8_t>(
                std::min<std::size_t>(patch_hits, 255u));
            const bool entry_hit = address_in_span(snap.stats.focus_ip_va, va, cell_end);

            snap.cells.push_back(MemoryHeatmapCell::pack(
                va,
                span_u32,
                cat,
                pack_cell_permissions(reg.protection, wx_flag),
                res,
                heat,
                entropy,
                mutations,
                false,
                false,
                entry_hit));
        }
    }

    finalize_snapshot_dimensions(snap, config.layout);
    compute_snapshot_cell_kpis(snap);

    out.value = std::move(snap);
    out.availability = CaptureAvailability::Complete;
    out.stamp = CaptureStamp::capture_interval(start_stamp, CaptureAvailability::Complete);
    return out;
}

void rasterize_memory_heatmap_rgba8_into(
    const MemoryHeatmapViewport& viewport,
    const MemoryHeatmapSnapshot& snapshot,
    MemoryHeatmapColorMode color_mode,
    std::vector<std::uint8_t>& out_rgba8) {
    const std::uint32_t w = viewport.width_px;
    const std::uint32_t h = viewport.height_px;
    if (w == 0u || h == 0u) {
        out_rgba8.clear();
        return;
    }

    const std::size_t total_bytes =
        static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 4u;
    out_rgba8.resize(total_bytes);

    const double sx = (std::isfinite(viewport.scale_x) && viewport.scale_x > 1e-9)
                          ? viewport.scale_x
                          : 16.0;
    const double sy = (std::isfinite(viewport.scale_y) && viewport.scale_y > 1e-9)
                          ? viewport.scale_y
                          : 16.0;
    const double cx = std::isfinite(viewport.center_x) ? viewport.center_x : 0.0;
    const double cy = std::isfinite(viewport.center_y) ? viewport.center_y : 0.0;
    const double half_w = static_cast<double>(w) * 0.5;
    const double half_h = static_cast<double>(h) * 0.5;
    const double min_cell_px = std::min(sx, sy);
    const bool draw_grid = min_cell_px >= 6.0;

    const auto grid_w_d = static_cast<double>(snapshot.grid_width);
    const auto grid_h_d = static_cast<double>(snapshot.grid_height);

    for (std::uint32_t py = 0u; py < h; ++py) {
        const double wy = cy + ((static_cast<double>(py) + 0.5) - half_h) / sy;
        for (std::uint32_t px = 0u; px < w; ++px) {
            const double wx = cx + ((static_cast<double>(px) + 0.5) - half_w) / sx;
            const std::size_t out_off =
                (static_cast<std::size_t>(py) * static_cast<std::size_t>(w) +
                 static_cast<std::size_t>(px)) *
                4u;

            if (wx < 0.0 || wy < 0.0 || wx >= grid_w_d || wy >= grid_h_d) {
                out_rgba8[out_off + 0u] = 13u;
                out_rgba8[out_off + 1u] = 16u;
                out_rgba8[out_off + 2u] = 22u;
                out_rgba8[out_off + 3u] = 255u;
                continue;
            }

            const double floor_x = std::floor(wx);
            const double floor_y = std::floor(wy);
            const auto cell_x = static_cast<std::uint32_t>(floor_x);
            const auto cell_y = static_cast<std::uint32_t>(floor_y);
            const auto fx = static_cast<float>(wx - floor_x);
            const auto fy = static_cast<float>(wy - floor_y);

            const std::uint64_t cell_idx = grid_xy_to_cell_index(
                snapshot.layout, snapshot.hilbert_order, snapshot.grid_width, cell_x, cell_y);

            if (cell_idx >= snapshot.cells.size()) {
                out_rgba8[out_off + 0u] = 18u;
                out_rgba8[out_off + 1u] = 22u;
                out_rgba8[out_off + 2u] = 30u;
                out_rgba8[out_off + 3u] = 255u;
                continue;
            }

            const MemoryHeatmapCell& cell = snapshot.cells[static_cast<std::size_t>(cell_idx)];
            const MemoryCellCategory cat = cell.category();
            const MemoryCellResidency res = cell.residency();
            const float heat_t = static_cast<float>(cell.heat_u8()) / 255.0f;
            const float entropy_t = static_cast<float>(cell.entropy_u8()) / 255.0f;

            RgbFloat color{};
            switch (color_mode) {
                case MemoryHeatmapColorMode::AllocatorAndWriteHeat: {
                    const RgbFloat cat_col = apply_residency_modulation(
                        category_base_color(cat), cat, res);
                    const RgbFloat cold_base{
                        .r = cat_col.r * 0.42f,
                        .g = cat_col.g * 0.42f,
                        .b = cat_col.b * 0.48f,
                    };
                    if (heat_t > 0.001f) {
                        color = lerp_rgb(cold_base, magma_heat_ramp(heat_t),
                                         std::min(1.0f, 0.28f + 0.72f * heat_t));
                    } else {
                        color = cold_base;
                    }
                    break;
                }
                case MemoryHeatmapColorMode::CategoryAndResidency: {
                    color = apply_residency_modulation(category_base_color(cat), cat, res);
                    if (heat_t > 0.01f) {
                        color = lerp_rgb(color, magma_heat_ramp(heat_t), 0.45f * heat_t);
                    }
                    break;
                }
                case MemoryHeatmapColorMode::PermissionsAndRwx: {
                    color = apply_residency_modulation(permission_base_color(cell), cat, res);
                    if (heat_t > 0.01f) {
                        color = lerp_rgb(color, RgbFloat{1.0f, 0.82f, 0.35f}, 0.35f * heat_t);
                    }
                    break;
                }
                case MemoryHeatmapColorMode::PageEntropy: {
                    if (cat == MemoryCellCategory::Unmapped) {
                        color = RgbFloat{0.10f, 0.12f, 0.16f};
                    } else {
                        color = apply_residency_modulation(
                            entropy_viridis_ramp(entropy_t), cat, res);
                    }
                    break;
                }
            }

            const float edge_dist = std::min({fx, 1.0f - fx, fy, 1.0f - fy});
            const float px_border = static_cast<float>(
                1.35 / std::max(min_cell_px, 1.0));

            // Staged PatchDirty cyan corner badge.
            if (cat == MemoryCellCategory::PatchDirty && fx > 0.62f && fy < 0.38f) {
                color = RgbFloat{0.0f, 0.92f, 1.0f};
            }

            // RWX hazard or RW->RX JIT permission transition border pulse.
            if (cell.has_rwx_hazard() || cell.has_perm_transition()) {
                const float border_w = std::max(px_border * 1.5f, 0.14f);
                if (edge_dist < border_w) {
                    color = cell.has_perm_transition() ? RgbFloat{1.0f, 0.22f, 0.58f}
                                                       : RgbFloat{1.0f, 0.18f, 0.36f};
                }
            }

            // Hot focus marker (crashing IP/SP, live thread IP/SP, or entry point).
            if (cell.has_hot_focus()) {
                const float dx = fx - 0.5f;
                const float dy = fy - 0.5f;
                const float r2 = dx * dx + dy * dy;
                if (r2 < 0.07f || (edge_dist < std::max(px_border * 1.4f, 0.12f))) {
                    color = RgbFloat{1.0f, 0.96f, 0.72f};
                }
            }

            // Subtle cell grid lines at high zoom (>= 6 px per cell).
            if (draw_grid) {
                const auto grid_w_thresh = static_cast<float>(1.0 / min_cell_px);
                if ((1.0f - fx) <= grid_w_thresh || (1.0f - fy) <= grid_w_thresh) {
                    color = lerp_rgb(color, RgbFloat{0.05f, 0.06f, 0.09f}, 0.55f);
                }
            }

            // Hovered / selected cell outline.
            if (viewport.selected_cell_index.has_value() &&
                cell_idx == static_cast<std::uint64_t>(*viewport.selected_cell_index) &&
                edge_dist < std::max(px_border * 1.8f, 0.12f)) {
                color = RgbFloat{0.35f, 0.95f, 1.0f};
            } else if (viewport.hovered_cell_index.has_value() &&
                       cell_idx == static_cast<std::uint64_t>(*viewport.hovered_cell_index) &&
                       edge_dist < std::max(px_border * 1.5f, 0.10f)) {
                color = RgbFloat{1.0f, 1.0f, 1.0f};
            }

            out_rgba8[out_off + 0u] = float_to_u8(color.r);
            out_rgba8[out_off + 1u] = float_to_u8(color.g);
            out_rgba8[out_off + 2u] = float_to_u8(color.b);
            out_rgba8[out_off + 3u] = 255u;
        }
    }
}

std::vector<std::uint8_t> rasterize_memory_heatmap_rgba8(
    const MemoryHeatmapViewport& viewport,
    const MemoryHeatmapSnapshot& snapshot,
    MemoryHeatmapColorMode color_mode) {
    std::vector<std::uint8_t> rgba8{};
    rasterize_memory_heatmap_rgba8_into(viewport, snapshot, color_mode, rgba8);
    return rgba8;
}

} // namespace peelf
