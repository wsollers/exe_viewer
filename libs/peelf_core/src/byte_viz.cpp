#include <peelf/byte_viz.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] constexpr std::uint64_t add_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return (b <= (std::numeric_limits<std::uint64_t>::max() - a))
               ? (a + b)
               : std::numeric_limits<std::uint64_t>::max();
}

[[nodiscard]] constexpr std::uint64_t sub_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? (a - b) : 0u;
}

[[nodiscard]] constexpr bool ranges_overlap_u64(
    std::uint64_t start_a,
    std::uint64_t end_a,
    std::uint64_t start_b,
    std::uint64_t end_b) noexcept {
    return start_a < end_b && start_b < end_a;
}

[[nodiscard]] constexpr std::uint8_t ratio_to_u8(std::size_t numerator, std::size_t total) noexcept {
    if (total == 0u || numerator == 0u) {
        return 0u;
    }
    if (numerator >= total) {
        return 255u;
    }
    const double scaled =
        (static_cast<double>(numerator) / static_cast<double>(total)) * 255.0 + 0.5;
    return static_cast<std::uint8_t>(scaled >= 255.0 ? 255u : scaled);
}

struct RgbFloat {
    float r{0.0f};
    float g{0.0f};
    float b{0.0f};
};

[[nodiscard]] constexpr RgbFloat lerp_rgb(RgbFloat a, RgbFloat b, float t) noexcept {
    const float ct = std::clamp(t, 0.0f, 1.0f);
    return RgbFloat{
        .r = a.r + (b.r - a.r) * ct,
        .g = a.g + (b.g - a.g) * ct,
        .b = a.b + (b.b - a.b) * ct,
    };
}

[[nodiscard]] constexpr std::uint8_t float_to_u8(float v) noexcept {
    const float clamped = std::clamp(v, 0.0f, 1.0f);
    const auto scaled = static_cast<int>(clamped * 255.0f + 0.5f);
    return static_cast<std::uint8_t>(std::clamp(scaled, 0, 255));
}

[[nodiscard]] constexpr RgbFloat entropy_spectrum_ramp(float t) noexcept {
    const float ct = std::clamp(t, 0.0f, 1.0f);
    constexpr RgbFloat c0{.r = 0.09f, .g = 0.11f, .b = 0.24f};
    constexpr RgbFloat c1{.r = 0.14f, .g = 0.42f, .b = 0.68f};
    constexpr RgbFloat c2{.r = 0.16f, .g = 0.72f, .b = 0.56f};
    constexpr RgbFloat c3{.r = 0.92f, .g = 0.74f, .b = 0.22f};
    constexpr RgbFloat c4{.r = 0.98f, .g = 0.24f, .b = 0.30f};
    if (ct < 0.25f) {
        return lerp_rgb(c0, c1, ct * 4.0f);
    }
    if (ct < 0.50f) {
        return lerp_rgb(c1, c2, (ct - 0.25f) * 4.0f);
    }
    if (ct < 0.75f) {
        return lerp_rgb(c2, c3, (ct - 0.50f) * 4.0f);
    }
    return lerp_rgb(c3, c4, (ct - 0.75f) * 4.0f);
}

[[nodiscard]] constexpr RgbFloat cantor_density_ramp(float t) noexcept {
    const float ct = std::clamp(t, 0.0f, 1.0f);
    constexpr RgbFloat c0{.r = 0.14f, .g = 0.12f, .b = 0.34f};
    constexpr RgbFloat c1{.r = 0.16f, .g = 0.48f, .b = 0.86f};
    constexpr RgbFloat c2{.r = 0.20f, .g = 0.84f, .b = 0.68f};
    constexpr RgbFloat c3{.r = 0.96f, .g = 0.78f, .b = 0.26f};
    constexpr RgbFloat c4{.r = 1.00f, .g = 0.98f, .b = 0.88f};
    if (ct < 0.25f) {
        return lerp_rgb(c0, c1, ct * 4.0f);
    }
    if (ct < 0.55f) {
        return lerp_rgb(c1, c2, (ct - 0.25f) / 0.30f);
    }
    if (ct < 0.82f) {
        return lerp_rgb(c2, c3, (ct - 0.55f) / 0.27f);
    }
    return lerp_rgb(c3, c4, (ct - 0.82f) / 0.18f);
}

[[nodiscard]] constexpr RgbFloat byte_class_base_color(ByteClass cls, float entropy_t) noexcept {
    switch (cls) {
        case ByteClass::UnreadableOrEmpty:
            return RgbFloat{.r = 0.11f, .g = 0.13f, .b = 0.17f};
        case ByteClass::AllZeroPadding:
            return RgbFloat{.r = 0.16f, .g = 0.20f, .b = 0.28f};
        case ByteClass::TrapOrNopSlide:
            return RgbFloat{.r = 0.74f, .g = 0.34f, .b = 0.90f};
        case ByteClass::AsciiText:
            return RgbFloat{.r = 0.20f, .g = 0.78f, .b = 0.48f};
        case ByteClass::Utf16LeText:
            return RgbFloat{.r = 0.18f, .g = 0.76f, .b = 0.84f};
        case ByteClass::CodeOrStructured: {
            const float mod = 0.72f + 0.28f * std::clamp(entropy_t, 0.0f, 1.0f);
            return RgbFloat{.r = 0.26f * mod, .g = 0.52f * mod, .b = 0.92f * mod};
        }
        case ByteClass::HighEntropyPacked:
            return RgbFloat{.r = 0.96f, .g = 0.26f, .b = 0.32f};
    }
    return RgbFloat{.r = 0.26f, .g = 0.52f, .b = 0.92f};
}

[[nodiscard]] constexpr RgbFloat cantor_pair_class_color(CantorPairClass cls) noexcept {
    switch (cls) {
        case CantorPairClass::ZeroZero:
            return RgbFloat{.r = 0.45f, .g = 0.72f, .b = 1.00f};
        case CantorPairClass::AsciiAscii:
            return RgbFloat{.r = 0.24f, .g = 0.90f, .b = 0.52f};
        case CantorPairClass::Utf16AsciiZero:
            return RgbFloat{.r = 0.20f, .g = 0.86f, .b = 0.94f};
        case CantorPairClass::ControlOrLow:
            return RgbFloat{.r = 0.36f, .g = 0.56f, .b = 0.96f};
        case CantorPairClass::HighBit:
            return RgbFloat{.r = 0.98f, .g = 0.46f, .b = 0.28f};
        case CantorPairClass::TrapOrNop:
            return RgbFloat{.r = 0.82f, .g = 0.38f, .b = 0.96f};
    }
    return RgbFloat{.r = 0.36f, .g = 0.56f, .b = 0.96f};
}

class CantorAccumulator {
public:
    CantorAccumulator()
        : counts_(kCantorDigramBinCount, 0u),
          first_addresses_(kCantorDigramBinCount, kInvalidByteVizAddress) {}

    void reset_continuity() noexcept {
        has_prev_ = false;
    }

    [[nodiscard]] bool feed_contiguous_bytes(
        std::span<const std::uint8_t> bytes,
        std::uint64_t base_address,
        const std::stop_token& stop_token) noexcept {
        if (bytes.empty()) {
            return !stop_token.stop_requested();
        }

        std::size_t idx = 0u;
        if (has_prev_) {
            if (prev_next_expected_address_ == base_address) {
                record_pair(prev_byte_, bytes[0], prev_address_);
            }
            has_prev_ = false;
        }

        constexpr std::size_t kCheckMask = 0x3FFFu; // Check cancellation every 16 KiB
        while (idx + 1u < bytes.size()) {
            if (((idx & kCheckMask) == 0u) && stop_token.stop_requested()) {
                return false;
            }
            const std::uint64_t pair_addr = add_sat_u64(base_address, idx);
            record_pair(bytes[idx], bytes[idx + 1u], pair_addr);
            ++idx;
        }

        prev_byte_ = bytes.back();
        prev_address_ = add_sat_u64(base_address, bytes.size() - 1u);
        prev_next_expected_address_ = add_sat_u64(base_address, bytes.size());
        has_prev_ = true;
        return !stop_token.stop_requested();
    }

    [[nodiscard]] CantorDustDigram finalize(
        std::uint64_t scope_start,
        std::uint64_t scope_end,
        bool addresses_are_virtual) {
        CantorDustDigram out{};
        out.scope_start_address = scope_start;
        out.scope_end_address = scope_end;
        out.addresses_are_virtual = addresses_are_virtual;
        out.total_pairs = total_pairs_;
        out.pair_counts = std::move(counts_);
        out.first_occurrence_addresses = std::move(first_addresses_);
        out.packed_gpu_bins.resize(kCantorDigramBinCount, 0u);

        std::uint32_t max_count = 0u;
        std::uint32_t occupied = 0u;
        for (std::size_t bin = 0u; bin < kCantorDigramBinCount; ++bin) {
            const std::uint32_t cnt = out.pair_counts[bin];
            if (cnt > 0u) {
                ++occupied;
                if (cnt > max_count) {
                    max_count = cnt;
                }
            }
        }
        out.max_bin_count = max_count;
        out.occupied_bins = occupied;

        const double denom = max_count > 0u ? std::log1p(static_cast<double>(max_count)) : 1.0;

        for (std::size_t y = 0u; y < kCantorDigramAxis; ++y) {
            const auto b1 = static_cast<std::uint8_t>(y);
            for (std::size_t x = 0u; x < kCantorDigramAxis; ++x) {
                const auto b0 = static_cast<std::uint8_t>(x);
                const std::size_t bin = (y * kCantorDigramAxis) + x;
                const std::uint32_t cnt = out.pair_counts[bin];
                const CantorPairClass pcls = classify_cantor_pair(b0, b1);

                if (cnt > 0u) {
                    if (is_cantor_ascii_quadrant_byte(b0) && is_cantor_ascii_quadrant_byte(b1)) {
                        out.ascii_quadrant_pairs += cnt;
                    }
                    if (pcls == CantorPairClass::Utf16AsciiZero) {
                        out.utf16_stripe_pairs += cnt;
                    } else if (pcls == CantorPairClass::ZeroZero) {
                        out.zero_zero_pairs += cnt;
                    } else if (pcls == CantorPairClass::HighBit) {
                        out.high_bit_pairs += cnt;
                    }
                }

                std::uint16_t density_u16 = 0u;
                const bool has_occ =
                    (cnt > 0u) && (out.first_occurrence_addresses[bin] != kInvalidByteVizAddress);
                if (cnt > 0u && denom > 0.0) {
                    const double norm =
                        std::clamp(std::log1p(static_cast<double>(cnt)) / denom, 0.0, 1.0);
                    const auto scaled = static_cast<std::uint32_t>(norm * 65535.0 + 0.5);
                    density_u16 = static_cast<std::uint16_t>(
                        std::clamp<std::uint32_t>(scaled, 1u, 65535u));
                }
                out.packed_gpu_bins[bin] = pack_cantor_gpu_bin(density_u16, pcls, has_occ);
            }
        }
        return out;
    }

private:
    void record_pair(std::uint8_t b0, std::uint8_t b1, std::uint64_t addr) noexcept {
        const std::size_t bin = cantor_bin_index(b0, b1);
        if (counts_[bin] == 0u) {
            first_addresses_[bin] = addr;
        }
        if (counts_[bin] < std::numeric_limits<std::uint32_t>::max()) {
            ++counts_[bin];
        }
        ++total_pairs_;
    }

    std::vector<std::uint32_t> counts_;
    std::vector<std::uint64_t> first_addresses_;
    std::uint64_t total_pairs_{0};
    std::uint64_t prev_address_{0};
    std::uint64_t prev_next_expected_address_{0};
    std::uint8_t prev_byte_{0};
    bool has_prev_{false};
};

struct NormalizedFlagSpan {
    std::uint64_t start{0};
    std::uint64_t end{0};
    std::uint8_t flag_bits{0};
};

[[nodiscard]] std::uint8_t compute_tile_flags(
    std::uint64_t tile_start,
    std::uint64_t tile_end,
    std::span<const NormalizedFlagSpan> flag_spans,
    std::span<const ByteVizSectionSpan> sections) noexcept {
    std::uint8_t flags = ByteVizTileFlagBits::kNone;
    for (const NormalizedFlagSpan& fs : flag_spans) {
        if (ranges_overlap_u64(tile_start, tile_end, fs.start, fs.end)) {
            flags = static_cast<std::uint8_t>(flags | fs.flag_bits);
        }
    }
    for (const ByteVizSectionSpan& sec : sections) {
        const std::uint64_t sec_end = sec.end_address();
        if (sec.size_bytes == 0u || !ranges_overlap_u64(tile_start, tile_end, sec.start_address, sec_end)) {
            continue;
        }
        if (sec.executable) {
            flags = static_cast<std::uint8_t>(flags | ByteVizTileFlagBits::kExecutable);
        }
        if (sec.start_address >= tile_start && sec.start_address < tile_end) {
            flags = static_cast<std::uint8_t>(flags | ByteVizTileFlagBits::kSectionStart);
        }
    }
    return flags;
}

void finalize_snapshot_kpis(ByteVizSnapshot& snap) noexcept {
    snap.relayout(snap.layout);

    double weighted_entropy_sum = 0.0;
    std::uint64_t weighted_bytes = 0u;
    double peak_entropy = 0.0;

    snap.stats.high_entropy_tile_count = 0u;
    snap.stats.text_tile_count = 0u;
    snap.stats.code_tile_count = 0u;
    snap.stats.zero_tile_count = 0u;
    snap.stats.trap_nop_tile_count = 0u;
    snap.stats.unreadable_tile_count = 0u;
    snap.stats.patch_dirty_tile_count = 0u;
    snap.stats.diff_tile_count = 0u;

    for (const ByteVizTile& tile : snap.tiles) {
        const ByteClass cls = tile.byte_class();
        const double ent = tile.entropy_bits();
        const std::uint64_t span = tile.span_bytes();

        if (cls != ByteClass::UnreadableOrEmpty && span > 0u) {
            weighted_entropy_sum += ent * static_cast<double>(span);
            weighted_bytes = add_sat_u64(weighted_bytes, span);
            if (ent > peak_entropy) {
                peak_entropy = ent;
            }
        }

        switch (cls) {
            case ByteClass::UnreadableOrEmpty:
                ++snap.stats.unreadable_tile_count;
                break;
            case ByteClass::AllZeroPadding:
                ++snap.stats.zero_tile_count;
                break;
            case ByteClass::TrapOrNopSlide:
                ++snap.stats.trap_nop_tile_count;
                break;
            case ByteClass::AsciiText:
            case ByteClass::Utf16LeText:
                ++snap.stats.text_tile_count;
                break;
            case ByteClass::CodeOrStructured:
                ++snap.stats.code_tile_count;
                break;
            case ByteClass::HighEntropyPacked:
                ++snap.stats.high_entropy_tile_count;
                break;
        }

        if (tile.is_patch_dirty()) {
            ++snap.stats.patch_dirty_tile_count;
        }
        if (tile.is_diff_modified() || tile.is_diff_added()) {
            ++snap.stats.diff_tile_count;
        }
    }

    snap.stats.peak_entropy_bits = peak_entropy;
    snap.stats.mean_entropy_bits =
        weighted_bytes > 0u ? (weighted_entropy_sum / static_cast<double>(weighted_bytes)) : 0.0;
}

[[nodiscard]] std::uint64_t probe_binary_image_file_size(const IBinaryImage& image) {
    if (image.is_universal_slice() && image.container_slice_size() > 0u) {
        return add_sat_u64(image.container_slice_offset(), image.container_slice_size());
    }

    std::uint64_t lower_bound = 0u;
    for (const Section& sec : image.sections()) {
        lower_bound = std::max(lower_bound, add_sat_u64(sec.file_offset, sec.file_size));
    }
    for (const Segment& seg : image.segments()) {
        lower_bound = std::max(lower_bound, add_sat_u64(seg.file_offset, seg.file_size));
    }
    for (const PeCertificate& cert : image.pe_certificates()) {
        lower_bound = std::max(lower_bound, add_sat_u64(cert.file_offset, cert.length));
    }

    auto can_read_at = [&image](std::uint64_t pos) -> bool {
        const auto probe = image.read_bytes_at_offset(pos, 1u);
        return probe.has_value() && !probe->empty();
    };

    if (lower_bound > 0u && !can_read_at(lower_bound - 1u)) {
        lower_bound = 0u;
    }
    if (!can_read_at(lower_bound)) {
        return lower_bound;
    }

    std::uint64_t step = 4096u;
    std::uint64_t lo = lower_bound;
    std::uint64_t hi = add_sat_u64(lo, step);
    constexpr std::uint64_t kMaxProbeCap = 1ull << 34u; // 16 GiB sanity ceiling
    while (hi < kMaxProbeCap && can_read_at(hi)) {
        lo = hi;
        step = std::min<std::uint64_t>(step * 2u, 64ull * 1024ull * 1024ull);
        hi = add_sat_u64(lo, step);
    }

    while (lo + 1u < hi) {
        const std::uint64_t mid = lo + ((hi - lo) / 2u);
        if (can_read_at(mid)) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    return lo + 1u;
}

[[nodiscard]] std::vector<ByteVizSectionSpan> collect_static_sections(const IBinaryImage& image) {
    std::vector<ByteVizSectionSpan> out{};
    if (!image.sections().empty()) {
        out.reserve(image.sections().size());
        for (const Section& sec : image.sections()) {
            if (sec.file_size == 0u) {
                continue;
            }
            out.push_back(ByteVizSectionSpan{
                .name = sec.name.empty() ? "<section>" : sec.name,
                .start_address = sec.file_offset,
                .size_bytes = sec.file_size,
                .virtual_address = sec.virtual_address != 0u
                                       ? std::optional<std::uint64_t>(sec.virtual_address)
                                       : image.file_offset_to_virtual_address(sec.file_offset),
                .file_offset = sec.file_offset,
                .executable = sec.executable,
                .writable = sec.writable,
            });
        }
    } else {
        std::size_t idx = 0u;
        for (const Segment& seg : image.segments()) {
            if (seg.file_size == 0u) {
                ++idx;
                continue;
            }
            out.push_back(ByteVizSectionSpan{
                .name = std::format("LOAD[{}]", idx),
                .start_address = seg.file_offset,
                .size_bytes = seg.file_size,
                .virtual_address = seg.virtual_address,
                .file_offset = seg.file_offset,
                .executable = seg.executable,
                .writable = seg.writable,
            });
            ++idx;
        }
    }
    std::ranges::sort(out, [](const ByteVizSectionSpan& a, const ByteVizSectionSpan& b) {
        return a.start_address < b.start_address;
    });
    return out;
}

[[nodiscard]] bool read_static_effective_slice(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes,
    const PagedBinaryImage* patched_image,
    std::uint64_t file_offset,
    std::size_t length,
    std::vector<std::uint8_t>& scratch) {
    if (length == 0u) {
        scratch.clear();
        return true;
    }
    if (patched_image != nullptr && file_offset < patched_image->size()) {
        const std::uint64_t avail =
            std::min<std::uint64_t>(length, patched_image->size() - file_offset);
        if (auto eff = patched_image->read_effective(file_offset, avail); eff.has_value()) {
            scratch = std::move(*eff);
            return true;
        }
    }
    if (!raw_file_bytes.empty() && file_offset < raw_file_bytes.size()) {
        const std::size_t avail = std::min<std::size_t>(
            length,
            static_cast<std::size_t>(raw_file_bytes.size() - static_cast<std::size_t>(file_offset)));
        const auto sub = raw_file_bytes.subspan(static_cast<std::size_t>(file_offset), avail);
        scratch.assign(sub.begin(), sub.end());
        return true;
    }
    if (auto read_res = image.read_bytes_at_offset(file_offset, length); read_res.has_value()) {
        scratch = std::move(*read_res);
        return true;
    }
    scratch.clear();
    return false;
}

} // namespace

std::vector<ByteVizDiffRange> extract_byte_viz_diff_ranges(
    const BinaryDiffReport& report,
    bool use_lhs_coordinates) {
    std::vector<ByteVizDiffRange> ranges{};
    ranges.reserve(report.byte_hunks.size() + report.sections.size());

    for (const ByteDiffHunk& hunk : report.byte_hunks) {
        if (hunk.size == 0u) {
            continue;
        }
        const std::optional<std::uint64_t> primary_off =
            use_lhs_coordinates ? hunk.lhs_file_offset : hunk.rhs_file_offset;
        const std::optional<std::uint64_t> other_off =
            use_lhs_coordinates ? hunk.rhs_file_offset : hunk.lhs_file_offset;
        if (primary_off.has_value()) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = *primary_off,
                .size_bytes = hunk.size,
                .is_virtual_address = false,
                .kind = other_off.has_value() ? ByteVizDiffKind::Modified : ByteVizDiffKind::Added,
            });
            continue;
        }

        const std::optional<std::uint64_t> primary_va =
            use_lhs_coordinates ? hunk.lhs_va : hunk.rhs_va;
        const std::optional<std::uint64_t> other_va =
            use_lhs_coordinates ? hunk.rhs_va : hunk.lhs_va;
        if (primary_va.has_value()) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = *primary_va,
                .size_bytes = hunk.size,
                .is_virtual_address = true,
                .kind = other_va.has_value() ? ByteVizDiffKind::Modified : ByteVizDiffKind::Added,
            });
        }
    }

    for (const SectionDiffEntry& sec : report.sections) {
        if (!use_lhs_coordinates && sec.status == DiffChangeKind::Added && sec.rhs_file_size > 0u) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = sec.rhs_file_offset,
                .size_bytes = sec.rhs_file_size,
                .is_virtual_address = false,
                .kind = ByteVizDiffKind::Added,
            });
        } else if (use_lhs_coordinates && sec.status == DiffChangeKind::Removed &&
                   sec.lhs_file_size > 0u) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = sec.lhs_file_offset,
                .size_bytes = sec.lhs_file_size,
                .is_virtual_address = false,
                .kind = ByteVizDiffKind::Modified,
            });
        }
    }
    return ranges;
}

std::vector<ByteVizDiffRange> extract_byte_viz_diff_ranges(
    const LiveModuleIntegrityReport& report) {
    std::vector<ByteVizDiffRange> ranges{};
    ranges.reserve(report.findings.size() + report.loader_slots.size());
    for (const ByteDiffHunk& hunk : report.findings) {
        if (hunk.rhs_va.has_value() && hunk.size > 0u) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = *hunk.rhs_va,
                .size_bytes = hunk.size,
                .is_virtual_address = true,
                .kind = ByteVizDiffKind::Modified,
            });
        }
    }
    for (const LiveLoaderSlotEntry& slot : report.loader_slots) {
        if (slot.is_hooked && slot.live_slot_va != 0u) {
            ranges.push_back(ByteVizDiffRange{
                .offset_or_va = slot.live_slot_va,
                .size_bytes = 8u,
                .is_virtual_address = true,
                .kind = ByteVizDiffKind::Modified,
            });
        }
    }
    return ranges;
}

double compute_shannon_entropy_bits(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> counts{};
    for (const std::uint8_t b : bytes) {
        ++counts[b];
    }

    const std::size_t total = bytes.size();
    const double inv_total = 1.0 / static_cast<double>(total);
    double entropy = 0.0;
    for (const std::size_t c : counts) {
        if (c == 0u) {
            continue;
        }
        if (c == total) {
            return 0.0;
        }
        const double p = static_cast<double>(c) * inv_total;
        entropy -= p * std::log2(p);
    }
    return std::clamp(entropy, 0.0, 8.0);
}

ByteSpanMetrics analyze_byte_span(std::span<const std::uint8_t> bytes) noexcept {
    ByteSpanMetrics metrics{};
    const std::size_t n = bytes.size();
    if (n == 0u) {
        return metrics;
    }

    std::array<std::size_t, 256> counts{};
    std::size_t zero_count = 0u;
    std::size_t printable_count = 0u;
    std::size_t high_bit_count = 0u;
    std::size_t trap_nop_count = 0u;

    for (const std::uint8_t b : bytes) {
        ++counts[b];
        if (b == 0x00u) {
            ++zero_count;
        }
        if (is_printable_ascii_byte(b)) {
            ++printable_count;
        }
        if (b >= 0x80u) {
            ++high_bit_count;
        }
        if (b == 0x90u || b == 0xCCu) {
            ++trap_nop_count;
        }
    }

    std::size_t utf16_even_pairs = 0u;
    for (std::size_t i = 0u; i + 1u < n; i += 2u) {
        if (is_printable_ascii_byte(bytes[i]) && bytes[i + 1u] == 0x00u) {
            ++utf16_even_pairs;
        }
    }
    std::size_t utf16_odd_pairs = 0u;
    for (std::size_t i = 1u; i + 1u < n; i += 2u) {
        if (is_printable_ascii_byte(bytes[i]) && bytes[i + 1u] == 0x00u) {
            ++utf16_odd_pairs;
        }
    }
    const std::size_t best_utf16_pairs = std::max(utf16_even_pairs, utf16_odd_pairs);

    double entropy = 0.0;
    const double inv_n = 1.0 / static_cast<double>(n);
    for (const std::size_t c : counts) {
        if (c == 0u) {
            continue;
        }
        if (c == n) {
            entropy = 0.0;
            break;
        }
        const double p = static_cast<double>(c) * inv_n;
        entropy -= p * std::log2(p);
    }
    entropy = std::clamp(entropy, 0.0, 8.0);

    metrics.entropy_bits = entropy;
    metrics.entropy_u8 = quantize_entropy_u8(entropy);
    metrics.printable_u8 = ratio_to_u8(printable_count, n);
    metrics.zero_u8 = ratio_to_u8(zero_count, n);
    metrics.high_bit_u8 = ratio_to_u8(high_bit_count, n);

    const std::size_t half_units = n / 2u;
    const double max_possible_entropy =
        std::min(8.0, std::log2(static_cast<double>(std::max<std::size_t>(n, 2u))));

    if (zero_count == n || (zero_count * 100u >= n * 96u && entropy < 0.35)) {
        metrics.byte_class = ByteClass::AllZeroPadding;
    } else if (trap_nop_count * 4u >= n * 3u) {
        metrics.byte_class = ByteClass::TrapOrNopSlide;
    } else if (n >= 4u && best_utf16_pairs >= 2u &&
               best_utf16_pairs * 10u >= half_units * 7u) {
        metrics.byte_class = ByteClass::Utf16LeText;
    } else if (printable_count * 100u >= n * 85u && high_bit_count * 100u <= n * 5u) {
        metrics.byte_class = ByteClass::AsciiText;
    } else if ((n >= 256u && entropy >= 7.05) ||
               (n >= 32u && n < 256u && entropy >= (max_possible_entropy * 0.92) &&
                zero_count * 16u <= n)) {
        metrics.byte_class = ByteClass::HighEntropyPacked;
    } else {
        metrics.byte_class = ByteClass::CodeOrStructured;
    }

    return metrics;
}

void ByteVizSnapshot::relayout(ByteVizLayout new_layout) noexcept {
    layout = new_layout;
    const std::size_t tile_count = std::max<std::size_t>(tiles.size(), 1u);
    hilbert_order = choose_hilbert_order_for_cells(tile_count);
    const std::uint32_t side = std::uint32_t{1} << hilbert_order;
    grid_width = side;
    if (layout == ByteVizLayout::LinearRows) {
        const auto rows = static_cast<std::uint32_t>((tile_count + side - 1u) / side);
        grid_height = std::max(rows, 1u);
    } else {
        grid_height = side;
    }
}

std::optional<std::size_t> ByteVizSnapshot::find_tile_index_containing(
    std::uint64_t offset_or_va) const noexcept {
    if (tiles.empty()) {
        return std::nullopt;
    }
    const auto upper = std::ranges::upper_bound(
        tiles,
        offset_or_va,
        {},
        [](const ByteVizTile& t) { return t.base_offset_or_va(); });
    if (upper == tiles.begin()) {
        return std::nullopt;
    }
    const auto candidate = std::prev(upper);
    if (offset_or_va >= candidate->base_offset_or_va() &&
        offset_or_va < candidate->end_offset_or_va()) {
        return static_cast<std::size_t>(std::distance(tiles.begin(), candidate));
    }
    return std::nullopt;
}

const ByteVizSectionSpan* ByteVizSnapshot::find_section_at(
    std::uint64_t offset_or_va) const noexcept {
    for (const ByteVizSectionSpan& sec : sections) {
        if (offset_or_va >= sec.start_address && offset_or_va < sec.end_address()) {
            return &sec;
        }
    }
    return nullptr;
}

Observed<CantorDustDigram> compute_cantor_digram_from_bytes(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_address,
    bool addresses_are_virtual,
    std::stop_token stop_token) {
    const TargetInstanceId target_id{
        .backend = addresses_are_virtual ? BackendKind::LiveNativeReadOnly : BackendKind::StaticFile,
    };
    const CaptureStamp started = CaptureStamp::capture_now(target_id, 1u, true);

    Observed<CantorDustDigram> out{};
    out.provenance = addresses_are_virtual ? ProvenanceTag::LiveMemory : ProvenanceTag::DiskFile;

    if (stop_token.stop_requested()) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = "Cancelled via std::stop_token";
        return out;
    }

    CantorAccumulator acc{};
    if (!acc.feed_contiguous_bytes(bytes, base_address, stop_token)) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = "Cancelled via std::stop_token";
        return out;
    }

    const std::uint64_t end_addr = add_sat_u64(base_address, bytes.size());
    out.value = acc.finalize(base_address, end_addr, addresses_are_virtual);
    out.availability = CaptureAvailability::Complete;
    out.stamp = CaptureStamp::capture_interval(started, CaptureAvailability::Complete);
    out.evidence.push_back(Evidence{
        .tag = out.provenance,
        .source = "compute_cantor_digram_from_bytes",
        .detail = std::format("{} bytes ({} pairs)", bytes.size(), out.value->total_pairs),
    });
    return out;
}

Observed<ByteVizSnapshot> compute_byte_viz_from_bytes(
    std::span<const std::uint8_t> bytes,
    const ByteVizConfig& config,
    std::uint64_t base_address,
    bool addresses_are_virtual,
    std::span<const ByteVizDiffRange> diff_ranges,
    std::span<const PatchInterval> patch_intervals,
    std::span<const ByteVizSectionSpan> sections,
    std::stop_token stop_token) {
    const TargetInstanceId target_id{
        .backend = addresses_are_virtual ? BackendKind::LiveNativeReadOnly : BackendKind::StaticFile,
    };
    const CaptureStamp started = CaptureStamp::capture_now(target_id, 1u, true);

    Observed<ByteVizSnapshot> out{};
    out.provenance = addresses_are_virtual ? ProvenanceTag::LiveMemory : ProvenanceTag::DiskFile;

    if (stop_token.stop_requested()) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = "Cancelled via std::stop_token";
        return out;
    }

    const std::uint64_t full_end = add_sat_u64(base_address, bytes.size());
    std::uint64_t scope_start = base_address;
    std::uint64_t scope_end = full_end;
    if (config.scope_subrange.has_value()) {
        scope_start = std::clamp(config.scope_subrange->first, base_address, full_end);
        scope_end = std::clamp(config.scope_subrange->second, scope_start, full_end);
    }

    const std::uint64_t requested_len = sub_sat_u64(scope_end, scope_start);
    const std::uint64_t budget = static_cast<std::uint64_t>(
        config.max_read_bytes > 0u ? config.max_read_bytes : kDefaultByteVizMaxReadBytes);
    const bool truncated = requested_len > budget;
    const std::uint64_t effective_len = std::min(requested_len, budget);
    scope_end = add_sat_u64(scope_start, effective_len);

    const auto slice_offset = static_cast<std::size_t>(scope_start - base_address);
    const auto slice_len = static_cast<std::size_t>(effective_len);
    const std::span<const std::uint8_t> scoped_bytes = bytes.subspan(slice_offset, slice_len);

    std::vector<NormalizedFlagSpan> flag_spans{};
    flag_spans.reserve(diff_ranges.size() + patch_intervals.size());
    for (const PatchInterval& pi : patch_intervals) {
        if (!pi.patched.empty()) {
            flag_spans.push_back(NormalizedFlagSpan{
                .start = pi.offset,
                .end = pi.end_offset(),
                .flag_bits = ByteVizTileFlagBits::kPatchDirty,
            });
        }
    }
    for (const ByteVizDiffRange& dr : diff_ranges) {
        if (dr.size_bytes == 0u || dr.is_virtual_address != addresses_are_virtual) {
            continue;
        }
        flag_spans.push_back(NormalizedFlagSpan{
            .start = dr.offset_or_va,
            .end = dr.end_offset_or_va(),
            .flag_bits = dr.kind == ByteVizDiffKind::Added ? ByteVizTileFlagBits::kDiffAdded
                                                           : ByteVizTileFlagBits::kDiffModified,
        });
    }

    ByteVizSnapshot snap{};
    snap.scope_label = config.scope_label.empty() ? "Byte Buffer" : config.scope_label;
    snap.addresses_are_virtual = addresses_are_virtual;
    snap.layout = config.layout;
    snap.sections.assign(sections.begin(), sections.end());
    snap.stats.scope_start_address = scope_start;
    snap.stats.scope_end_address = scope_end;
    snap.stats.total_scope_bytes = requested_len;
    snap.stats.readable_bytes = effective_len;
    snap.stats.truncated_by_budget = truncated;

    const std::size_t tile_bytes = choose_adaptive_tile_bytes(
        effective_len, config.min_tile_bytes, config.target_max_tiles);
    snap.nominal_tile_bytes = tile_bytes;

    if (config.compute_tiles && effective_len > 0u) {
        const std::size_t est_tiles =
            static_cast<std::size_t>((effective_len + tile_bytes - 1u) / tile_bytes);
        snap.tiles.reserve(est_tiles);

        for (std::size_t pos = 0u; pos < scoped_bytes.size(); pos += tile_bytes) {
            if (stop_token.stop_requested()) {
                out.availability = CaptureAvailability::Unavailable;
                out.stamp = CaptureStamp::unavailable_for(target_id);
                out.note = "Cancelled via std::stop_token";
                return out;
            }
            const std::size_t len = std::min(tile_bytes, scoped_bytes.size() - pos);
            const std::uint64_t tile_addr = add_sat_u64(scope_start, pos);
            const std::uint64_t tile_end = add_sat_u64(tile_addr, len);
            const ByteSpanMetrics m = analyze_byte_span(scoped_bytes.subspan(pos, len));
            const std::uint8_t flags =
                compute_tile_flags(tile_addr, tile_end, flag_spans, snap.sections);

            snap.tiles.push_back(ByteVizTile::pack(
                tile_addr,
                len,
                m.byte_class,
                m.entropy_u8,
                m.printable_u8,
                m.zero_u8,
                m.high_bit_u8,
                flags));
        }
    }

    if (config.compute_cantor) {
        CantorAccumulator cantor_acc{};
        if (!cantor_acc.feed_contiguous_bytes(scoped_bytes, scope_start, stop_token)) {
            out.availability = CaptureAvailability::Unavailable;
            out.stamp = CaptureStamp::unavailable_for(target_id);
            out.note = "Cancelled via std::stop_token";
            return out;
        }
        snap.cantor = cantor_acc.finalize(scope_start, scope_end, addresses_are_virtual);
    }

    finalize_snapshot_kpis(snap);

    const CaptureAvailability avail =
        truncated ? CaptureAvailability::Partial : CaptureAvailability::Complete;
    out.value = std::move(snap);
    out.availability = avail;
    out.stamp = CaptureStamp::capture_interval(started, avail);
    out.evidence.push_back(Evidence{
        .tag = out.provenance,
        .source = "compute_byte_viz_from_bytes",
        .detail = std::format("{} tiles, {} pairs", out.value->tiles.size(), out.value->cantor.total_pairs),
    });
    if (!patch_intervals.empty() || !diff_ranges.empty()) {
        out.evidence.push_back(Evidence{
            .tag = ProvenanceTag::UserAnnotated,
            .source = "PatchAndDiffOverlay",
            .detail = std::format("{} patch spans, {} diff spans",
                                  patch_intervals.size(),
                                  diff_ranges.size()),
        });
    }
    return out;
}

Observed<ByteVizSnapshot> compute_static_byte_viz(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes,
    const ByteVizConfig& config,
    const PagedBinaryImage* patched_image,
    std::span<const ByteVizDiffRange> diff_ranges,
    std::stop_token stop_token) {
    const TargetInstanceId target_id{
        .backend = BackendKind::StaticFile,
    };
    const CaptureStamp started = CaptureStamp::capture_now(target_id, 1u, true);

    Observed<ByteVizSnapshot> out{};
    out.provenance = ProvenanceTag::DiskFile;

    if (stop_token.stop_requested()) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = "Cancelled via std::stop_token";
        return out;
    }

    std::uint64_t min_offset = 0u;
    std::uint64_t max_offset = 0u;
    if (image.is_universal_slice() && image.container_slice_size() > 0u) {
        min_offset = image.container_slice_offset();
        max_offset = add_sat_u64(min_offset, image.container_slice_size());
    } else if (patched_image != nullptr) {
        max_offset = patched_image->size();
    } else if (!raw_file_bytes.empty()) {
        max_offset = raw_file_bytes.size();
    } else {
        max_offset = probe_binary_image_file_size(image);
    }

    std::uint64_t scope_start = min_offset;
    std::uint64_t scope_end = max_offset;
    if (config.scope_subrange.has_value()) {
        scope_start = std::clamp(config.scope_subrange->first, min_offset, max_offset);
        scope_end = std::clamp(config.scope_subrange->second, scope_start, max_offset);
    }

    const std::uint64_t requested_len = sub_sat_u64(scope_end, scope_start);
    const std::uint64_t budget = static_cast<std::uint64_t>(
        config.max_read_bytes > 0u ? config.max_read_bytes : kDefaultByteVizMaxReadBytes);
    const bool truncated = requested_len > budget;
    const std::uint64_t effective_len = std::min(requested_len, budget);
    scope_end = add_sat_u64(scope_start, effective_len);

    std::vector<ByteVizSectionSpan> sections = collect_static_sections(image);

    std::vector<NormalizedFlagSpan> flag_spans{};
    std::size_t patch_span_count = 0u;
    if (patched_image != nullptr && patched_image->dirty()) {
        const std::vector<PatchInterval> patches = patched_image->changed_intervals();
        patch_span_count = patches.size();
        for (const PatchInterval& pi : patches) {
            if (!pi.patched.empty()) {
                flag_spans.push_back(NormalizedFlagSpan{
                    .start = pi.offset,
                    .end = pi.end_offset(),
                    .flag_bits = ByteVizTileFlagBits::kPatchDirty,
                });
            }
        }
    }

    for (const ByteVizDiffRange& dr : diff_ranges) {
        if (dr.size_bytes == 0u) {
            continue;
        }
        const std::uint8_t bit = dr.kind == ByteVizDiffKind::Added
                                     ? ByteVizTileFlagBits::kDiffAdded
                                     : ByteVizTileFlagBits::kDiffModified;
        if (!dr.is_virtual_address) {
            flag_spans.push_back(NormalizedFlagSpan{
                .start = dr.offset_or_va,
                .end = dr.end_offset_or_va(),
                .flag_bits = bit,
            });
        } else if (const auto mapped_off = image.virtual_address_to_file_offset(dr.offset_or_va)) {
            flag_spans.push_back(NormalizedFlagSpan{
                .start = *mapped_off,
                .end = add_sat_u64(*mapped_off, dr.size_bytes),
                .flag_bits = bit,
            });
        }
    }

    ByteVizSnapshot snap{};
    snap.scope_label = config.scope_label.empty() ? "Whole Binary" : config.scope_label;
    snap.addresses_are_virtual = false;
    snap.layout = config.layout;
    snap.sections = std::move(sections);
    snap.stats.scope_start_address = scope_start;
    snap.stats.scope_end_address = scope_end;
    snap.stats.total_scope_bytes = requested_len;
    snap.stats.truncated_by_budget = truncated;

    const std::size_t tile_bytes = choose_adaptive_tile_bytes(
        effective_len, config.min_tile_bytes, config.target_max_tiles);
    snap.nominal_tile_bytes = tile_bytes;

    if (config.compute_tiles && effective_len > 0u) {
        const std::size_t est_tiles =
            static_cast<std::size_t>((effective_len + tile_bytes - 1u) / tile_bytes);
        snap.tiles.reserve(est_tiles);
    }

    CantorAccumulator cantor_acc{};
    std::vector<std::uint8_t> chunk_buf{};
    // Stream in multiples of tile_bytes (>= 64 KiB) so tiles never split across chunk boundaries.
    const std::size_t tiles_per_chunk = std::max<std::size_t>(1u, (64u * 1024u) / tile_bytes);
    const std::size_t chunk_step = tile_bytes * tiles_per_chunk;

    for (std::uint64_t off = scope_start; off < scope_end;) {
        if (stop_token.stop_requested()) {
            out.availability = CaptureAvailability::Unavailable;
            out.stamp = CaptureStamp::unavailable_for(target_id);
            out.note = "Cancelled via std::stop_token";
            return out;
        }
        const auto req = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_step, scope_end - off));
        const bool ok = read_static_effective_slice(
            image, raw_file_bytes, patched_image, off, req, chunk_buf);

        if (!ok || chunk_buf.empty()) {
            cantor_acc.reset_continuity();
            snap.stats.unreadable_bytes = add_sat_u64(snap.stats.unreadable_bytes, req);
            ++snap.stats.unreadable_gap_count;
            if (config.compute_tiles) {
                for (std::size_t pos = 0u; pos < req; pos += tile_bytes) {
                    const std::size_t tlen = std::min(tile_bytes, req - pos);
                    const std::uint64_t tstart = add_sat_u64(off, pos);
                    const std::uint64_t tend = add_sat_u64(tstart, tlen);
                    const std::uint8_t flags =
                        compute_tile_flags(tstart, tend, flag_spans, snap.sections);
                    snap.tiles.push_back(ByteVizTile::pack(
                        tstart, tlen, ByteClass::UnreadableOrEmpty, 0u, 0u, 0u, 0u, flags));
                }
            }
            off = add_sat_u64(off, req);
            continue;
        }

        const std::size_t got = chunk_buf.size();
        snap.stats.readable_bytes = add_sat_u64(snap.stats.readable_bytes, got);

        if (config.compute_cantor) {
            if (!cantor_acc.feed_contiguous_bytes(chunk_buf, off, stop_token)) {
                out.availability = CaptureAvailability::Unavailable;
                out.stamp = CaptureStamp::unavailable_for(target_id);
                out.note = "Cancelled via std::stop_token";
                return out;
            }
        }

        if (config.compute_tiles) {
            const std::span<const std::uint8_t> span_view(chunk_buf);
            for (std::size_t pos = 0u; pos < got; pos += tile_bytes) {
                if (stop_token.stop_requested()) {
                    out.availability = CaptureAvailability::Unavailable;
                    out.stamp = CaptureStamp::unavailable_for(target_id);
                    out.note = "Cancelled via std::stop_token";
                    return out;
                }
                const std::size_t tlen = std::min(tile_bytes, got - pos);
                const std::uint64_t tstart = add_sat_u64(off, pos);
                const std::uint64_t tend = add_sat_u64(tstart, tlen);
                const ByteSpanMetrics m = analyze_byte_span(span_view.subspan(pos, tlen));
                const std::uint8_t flags =
                    compute_tile_flags(tstart, tend, flag_spans, snap.sections);
                snap.tiles.push_back(ByteVizTile::pack(
                    tstart,
                    tlen,
                    m.byte_class,
                    m.entropy_u8,
                    m.printable_u8,
                    m.zero_u8,
                    m.high_bit_u8,
                    flags));
            }
        }

        if (got < req) {
            const std::size_t missing = req - got;
            cantor_acc.reset_continuity();
            snap.stats.unreadable_bytes = add_sat_u64(snap.stats.unreadable_bytes, missing);
            ++snap.stats.unreadable_gap_count;
            off = add_sat_u64(off, req);
        } else {
            off = add_sat_u64(off, got);
        }
    }

    if (config.compute_cantor) {
        snap.cantor = cantor_acc.finalize(scope_start, scope_end, false);
    }
    finalize_snapshot_kpis(snap);

    const bool is_partial = truncated || (snap.stats.unreadable_bytes > 0u);
    const CaptureAvailability avail =
        is_partial ? CaptureAvailability::Partial : CaptureAvailability::Complete;

    out.value = std::move(snap);
    out.availability = avail;
    out.stamp = CaptureStamp::capture_interval(started, avail);
    out.evidence.push_back(Evidence{
        .tag = ProvenanceTag::DiskFile,
        .source = "IBinaryImage",
        .detail = std::format("{} bytes analyzed across {} tiles",
                              out.value->stats.readable_bytes,
                              out.value->tiles.size()),
    });
    if (patch_span_count > 0u || !diff_ranges.empty()) {
        out.evidence.push_back(Evidence{
            .tag = ProvenanceTag::UserAnnotated,
            .source = "PagedBinaryImage / BinaryDiffReport",
            .detail = std::format("{} staged patch intervals, {} diff ranges",
                                  patch_span_count,
                                  diff_ranges.size()),
        });
    }
    return out;
}

Observed<ByteVizSnapshot> compute_static_byte_viz(
    const IBinaryImage& image,
    const ByteVizConfig& config,
    const PagedBinaryImage* patched_image,
    std::span<const ByteVizDiffRange> diff_ranges,
    std::stop_token stop_token) {
    return compute_static_byte_viz(
        image, std::span<const std::uint8_t>{}, config, patched_image, diff_ranges, std::move(stop_token));
}

Observed<CantorDustDigram> compute_static_cantor_digram(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes,
    std::uint64_t start_offset,
    std::uint64_t end_offset,
    const PagedBinaryImage* patched_image,
    std::stop_token stop_token) {
    ByteVizConfig cfg{};
    cfg.scope_subrange = std::pair<std::uint64_t, std::uint64_t>{start_offset, end_offset};
    cfg.compute_tiles = false;
    cfg.compute_cantor = true;
    auto snap_obs = compute_static_byte_viz(
        image, raw_file_bytes, cfg, patched_image, {}, std::move(stop_token));

    Observed<CantorDustDigram> out{};
    out.provenance = snap_obs.provenance;
    out.availability = snap_obs.availability;
    out.stamp = snap_obs.stamp;
    out.evidence = std::move(snap_obs.evidence);
    out.note = std::move(snap_obs.note);
    if (snap_obs.has_value()) {
        out.value = std::move(snap_obs.value->cantor);
    }
    return out;
}

Observed<ByteVizSnapshot> compute_live_region_byte_viz(
    IProcessSession& session,
    const MemoryRegion& region,
    const ByteVizConfig& config,
    std::span<const ByteVizDiffRange> diff_ranges,
    std::span<const PatchInterval> live_patches,
    std::stop_token stop_token) {
    const bool is_dump = session.is_crash_dump();
    const ProvenanceTag primary_tag = is_dump ? ProvenanceTag::CrashDump : ProvenanceTag::LiveMemory;
    const TargetInstanceId target_id{
        .backend = is_dump ? BackendKind::CrashDumpMinidump : BackendKind::LiveNativeReadOnly,
        .pid = session.pid(),
    };
    const CaptureStamp started =
        CaptureStamp::capture_now(target_id, 1u, session.is_suspended());

    Observed<ByteVizSnapshot> out{};
    out.provenance = primary_tag;

    if (stop_token.stop_requested() || !session.is_alive() || region.size() == 0u) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = stop_token.stop_requested() ? "Cancelled via std::stop_token"
                                               : "Session inactive or empty memory region";
        return out;
    }

    std::uint64_t scope_start = region.start_address;
    std::uint64_t scope_end = region.end_address;
    if (config.scope_subrange.has_value()) {
        scope_start = std::clamp(config.scope_subrange->first, region.start_address, region.end_address);
        scope_end = std::clamp(config.scope_subrange->second, scope_start, region.end_address);
    }

    const std::uint64_t requested_len = sub_sat_u64(scope_end, scope_start);
    if (requested_len == 0u) {
        out.availability = CaptureAvailability::Unavailable;
        out.stamp = CaptureStamp::unavailable_for(target_id);
        out.note = "Empty subrange";
        return out;
    }

    const std::uint64_t budget = static_cast<std::uint64_t>(
        config.max_read_bytes > 0u ? config.max_read_bytes : kDefaultByteVizMaxReadBytes);
    const bool truncated = requested_len > budget;
    const std::uint64_t effective_len = std::min(requested_len, budget);
    scope_end = add_sat_u64(scope_start, effective_len);

    std::vector<NormalizedFlagSpan> flag_spans{};
    for (const PatchInterval& pi : live_patches) {
        if (!pi.patched.empty()) {
            flag_spans.push_back(NormalizedFlagSpan{
                .start = pi.offset,
                .end = pi.end_offset(),
                .flag_bits = ByteVizTileFlagBits::kPatchDirty,
            });
        }
    }
    for (const ByteVizDiffRange& dr : diff_ranges) {
        if (dr.size_bytes == 0u || !dr.is_virtual_address) {
            continue;
        }
        flag_spans.push_back(NormalizedFlagSpan{
            .start = dr.offset_or_va,
            .end = dr.end_offset_or_va(),
            .flag_bits = dr.kind == ByteVizDiffKind::Added ? ByteVizTileFlagBits::kDiffAdded
                                                           : ByteVizTileFlagBits::kDiffModified,
        });
    }

    ByteVizSnapshot snap{};
    snap.scope_label = !config.scope_label.empty()
                           ? config.scope_label
                           : (!region.module_name.empty() ? region.module_name : region.pathname);
    if (snap.scope_label.empty()) {
        snap.scope_label = std::format("0x{:X}..0x{:X}", scope_start, scope_end);
    }
    snap.addresses_are_virtual = true;
    snap.layout = config.layout;
    snap.sections.push_back(ByteVizSectionSpan{
        .name = snap.scope_label,
        .start_address = region.start_address,
        .size_bytes = region.size(),
        .virtual_address = region.start_address,
        .file_offset = std::nullopt,
        .executable = region.protection.executable,
        .writable = region.protection.writable,
    });
    snap.stats.scope_start_address = scope_start;
    snap.stats.scope_end_address = scope_end;
    snap.stats.total_scope_bytes = requested_len;
    snap.stats.truncated_by_budget = truncated;

    const std::size_t tile_bytes = choose_adaptive_tile_bytes(
        effective_len, config.min_tile_bytes, config.target_max_tiles);
    snap.nominal_tile_bytes = tile_bytes;

    if (config.compute_tiles) {
        const std::size_t est_tiles =
            static_cast<std::size_t>((effective_len + tile_bytes - 1u) / tile_bytes);
        snap.tiles.reserve(est_tiles);
    }

    CantorAccumulator cantor_acc{};
    constexpr std::size_t kOsPageChunk = 4096u;
    std::array<std::uint8_t, kOsPageChunk> page_buf{};
    bool in_unreadable_gap = false;

    if (tile_bytes <= kOsPageChunk) {
        // Read per 4 KiB OS page (or smaller remaining tail) and slice into tiles.
        for (std::uint64_t page_va = scope_start; page_va < scope_end;) {
            if (stop_token.stop_requested()) {
                out.availability = CaptureAvailability::Unavailable;
                out.stamp = CaptureStamp::unavailable_for(target_id);
                out.note = "Cancelled via std::stop_token";
                return out;
            }
            const auto req_len = static_cast<std::size_t>(
                std::min<std::uint64_t>(kOsPageChunk, scope_end - page_va));
            const auto read_res = session.read_memory(
                page_va, std::span<std::uint8_t>(page_buf.data(), req_len));
            const std::size_t got =
                read_res.has_value() ? std::min<std::size_t>(*read_res, req_len) : 0u;

            if (got > 0u) {
                in_unreadable_gap = false;
                snap.stats.readable_bytes = add_sat_u64(snap.stats.readable_bytes, got);
                const std::span<const std::uint8_t> readable_span(page_buf.data(), got);
                if (config.compute_cantor) {
                    if (!cantor_acc.feed_contiguous_bytes(readable_span, page_va, stop_token)) {
                        out.availability = CaptureAvailability::Unavailable;
                        out.stamp = CaptureStamp::unavailable_for(target_id);
                        out.note = "Cancelled via std::stop_token";
                        return out;
                    }
                }
                if (config.compute_tiles) {
                    for (std::size_t pos = 0u; pos < got; pos += tile_bytes) {
                        const std::size_t tlen = std::min(tile_bytes, got - pos);
                        const std::uint64_t tstart = add_sat_u64(page_va, pos);
                        const std::uint64_t tend = add_sat_u64(tstart, tlen);
                        const ByteSpanMetrics m = analyze_byte_span(readable_span.subspan(pos, tlen));
                        const std::uint8_t flags =
                            compute_tile_flags(tstart, tend, flag_spans, snap.sections);
                        snap.tiles.push_back(ByteVizTile::pack(
                            tstart,
                            tlen,
                            m.byte_class,
                            m.entropy_u8,
                            m.printable_u8,
                            m.zero_u8,
                            m.high_bit_u8,
                            flags));
                    }
                }
            }

            if (got < req_len) {
                const std::size_t unreadable_len = req_len - got;
                cantor_acc.reset_continuity();
                snap.stats.unreadable_bytes =
                    add_sat_u64(snap.stats.unreadable_bytes, unreadable_len);
                if (!in_unreadable_gap) {
                    ++snap.stats.unreadable_gap_count;
                    in_unreadable_gap = true;
                }
                if (config.compute_tiles) {
                    const std::uint64_t gap_base = add_sat_u64(page_va, got);
                    for (std::size_t pos = 0u; pos < unreadable_len; pos += tile_bytes) {
                        const std::size_t tlen = std::min(tile_bytes, unreadable_len - pos);
                        const std::uint64_t tstart = add_sat_u64(gap_base, pos);
                        const std::uint64_t tend = add_sat_u64(tstart, tlen);
                        const std::uint8_t flags =
                            compute_tile_flags(tstart, tend, flag_spans, snap.sections);
                        snap.tiles.push_back(ByteVizTile::pack(
                            tstart, tlen, ByteClass::UnreadableOrEmpty, 0u, 0u, 0u, 0u, flags));
                    }
                }
            }

            page_va = add_sat_u64(page_va, req_len);
        }
    } else {
        // Multi-page tiles (`tile_bytes > 4096`): stream 4 KiB pages per tile.
        std::vector<std::uint8_t> tile_readable{};
        tile_readable.reserve(tile_bytes);
        for (std::uint64_t tile_va = scope_start; tile_va < scope_end;) {
            if (stop_token.stop_requested()) {
                out.availability = CaptureAvailability::Unavailable;
                out.stamp = CaptureStamp::unavailable_for(target_id);
                out.note = "Cancelled via std::stop_token";
                return out;
            }
            const auto tile_len = static_cast<std::size_t>(
                std::min<std::uint64_t>(tile_bytes, scope_end - tile_va));
            const std::uint64_t tile_end = add_sat_u64(tile_va, tile_len);
            tile_readable.clear();

            for (std::uint64_t page_va = tile_va; page_va < tile_end;) {
                if (stop_token.stop_requested()) {
                    out.availability = CaptureAvailability::Unavailable;
                    out.stamp = CaptureStamp::unavailable_for(target_id);
                    out.note = "Cancelled via std::stop_token";
                    return out;
                }
                const auto req_len = static_cast<std::size_t>(
                    std::min<std::uint64_t>(kOsPageChunk, tile_end - page_va));
                const auto read_res = session.read_memory(
                    page_va, std::span<std::uint8_t>(page_buf.data(), req_len));
                const std::size_t got =
                    read_res.has_value() ? std::min<std::size_t>(*read_res, req_len) : 0u;

                if (got > 0u) {
                    in_unreadable_gap = false;
                    snap.stats.readable_bytes = add_sat_u64(snap.stats.readable_bytes, got);
                    const std::span<const std::uint8_t> readable_span(page_buf.data(), got);
                    if (config.compute_cantor) {
                        if (!cantor_acc.feed_contiguous_bytes(readable_span, page_va, stop_token)) {
                            out.availability = CaptureAvailability::Unavailable;
                            out.stamp = CaptureStamp::unavailable_for(target_id);
                            out.note = "Cancelled via std::stop_token";
                            return out;
                        }
                    }
                    if (config.compute_tiles) {
                        tile_readable.insert(
                            tile_readable.end(), readable_span.begin(), readable_span.end());
                    }
                }
                if (got < req_len) {
                    cantor_acc.reset_continuity();
                    snap.stats.unreadable_bytes =
                        add_sat_u64(snap.stats.unreadable_bytes, req_len - got);
                    if (!in_unreadable_gap) {
                        ++snap.stats.unreadable_gap_count;
                        in_unreadable_gap = true;
                    }
                }
                page_va = add_sat_u64(page_va, req_len);
            }

            if (config.compute_tiles) {
                const ByteSpanMetrics m = analyze_byte_span(tile_readable);
                const std::uint8_t flags =
                    compute_tile_flags(tile_va, tile_end, flag_spans, snap.sections);
                snap.tiles.push_back(ByteVizTile::pack(
                    tile_va,
                    tile_len,
                    m.byte_class,
                    m.entropy_u8,
                    m.printable_u8,
                    m.zero_u8,
                    m.high_bit_u8,
                    flags));
            }
            tile_va = tile_end;
        }
    }

    if (config.compute_cantor) {
        snap.cantor = cantor_acc.finalize(scope_start, scope_end, true);
    }
    finalize_snapshot_kpis(snap);

    const bool is_partial = truncated || (snap.stats.unreadable_bytes > 0u);
    const CaptureAvailability avail =
        is_partial ? CaptureAvailability::Partial : CaptureAvailability::Complete;

    out.value = std::move(snap);
    out.availability = avail;
    out.stamp = CaptureStamp::capture_interval(started, avail);
    out.evidence.push_back(Evidence{
        .tag = primary_tag,
        .source = is_dump ? "ICrashDumpSession::read_memory" : "IProcessSession::read_memory",
        .detail = std::format(
            "readable={} B, unreadable={} B ({} gaps){}",
            out.value->stats.readable_bytes,
            out.value->stats.unreadable_bytes,
            out.value->stats.unreadable_gap_count,
            truncated ? ", capped at read budget" : ""),
        .virtual_address = scope_start,
    });
    if (!live_patches.empty() || !diff_ranges.empty()) {
        out.evidence.push_back(Evidence{
            .tag = ProvenanceTag::UserAnnotated,
            .source = "LivePatch / IntegrityDiff",
            .detail = std::format("{} patches, {} diff ranges",
                                  live_patches.size(),
                                  diff_ranges.size()),
        });
    }
    return out;
}

Observed<CantorDustDigram> compute_live_cantor_digram(
    IProcessSession& session,
    const MemoryRegion& region,
    std::uint64_t start_va,
    std::uint64_t end_va,
    std::size_t max_read_bytes,
    std::stop_token stop_token) {
    ByteVizConfig cfg{};
    cfg.scope_subrange = std::pair<std::uint64_t, std::uint64_t>{start_va, end_va};
    cfg.max_read_bytes = max_read_bytes;
    cfg.compute_tiles = false;
    cfg.compute_cantor = true;
    auto snap_obs =
        compute_live_region_byte_viz(session, region, cfg, {}, {}, std::move(stop_token));

    Observed<CantorDustDigram> out{};
    out.provenance = snap_obs.provenance;
    out.availability = snap_obs.availability;
    out.stamp = snap_obs.stamp;
    out.evidence = std::move(snap_obs.evidence);
    out.note = std::move(snap_obs.note);
    if (snap_obs.has_value()) {
        out.value = std::move(snap_obs.value->cantor);
    }
    return out;
}

void rasterize_byte_viz_rgba8_into(
    const ByteVizViewport& viewport,
    const ByteVizSnapshot& snapshot,
    ByteVizMode mode,
    ByteVizColorMode color_mode,
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
                          : 1.0;
    const double sy = (std::isfinite(viewport.scale_y) && viewport.scale_y > 1e-9)
                          ? viewport.scale_y
                          : 1.0;
    const double cx = std::isfinite(viewport.center_x) ? viewport.center_x : 0.0;
    const double cy = std::isfinite(viewport.center_y) ? viewport.center_y : 0.0;
    const double half_w = static_cast<double>(w) * 0.5;
    const double half_h = static_cast<double>(h) * 0.5;
    const double min_cell_px = std::min(sx, sy);

    if (mode == ByteVizMode::EntropyAndByteClass2D) {
        const auto grid_w_d = static_cast<double>(snapshot.grid_width);
        const auto grid_h_d = static_cast<double>(snapshot.grid_height);
        const bool draw_grid = viewport.show_guides_and_grid && (min_cell_px >= 6.0);
        const bool has_brush = viewport.brushed_address_range.has_value() &&
                               (viewport.brushed_address_range->second >
                                viewport.brushed_address_range->first);
        const std::uint64_t brush_start =
            has_brush ? viewport.brushed_address_range->first : 0u;
        const std::uint64_t brush_end =
            has_brush ? viewport.brushed_address_range->second : 0u;

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

                const std::uint64_t tile_idx = grid_xy_to_cell_index(
                    to_heatmap_layout(snapshot.layout),
                    snapshot.hilbert_order,
                    snapshot.grid_width,
                    cell_x,
                    cell_y);

                if (tile_idx >= snapshot.tiles.size()) {
                    out_rgba8[out_off + 0u] = 18u;
                    out_rgba8[out_off + 1u] = 22u;
                    out_rgba8[out_off + 2u] = 30u;
                    out_rgba8[out_off + 3u] = 255u;
                    continue;
                }

                const ByteVizTile& tile = snapshot.tiles[static_cast<std::size_t>(tile_idx)];
                const ByteClass cls = tile.byte_class();
                const float entropy_t = static_cast<float>(tile.entropy_u8()) / 255.0f;
                const float printable_t = static_cast<float>(tile.printable_u8()) / 255.0f;
                const float zero_t = static_cast<float>(tile.zero_u8()) / 255.0f;
                const float high_bit_t = static_cast<float>(tile.high_bit_u8()) / 255.0f;

                RgbFloat color{};
                switch (color_mode) {
                    case ByteVizColorMode::EntropySpectrum:
                        color = (cls == ByteClass::UnreadableOrEmpty)
                                    ? RgbFloat{.r = 0.10f, .g = 0.12f, .b = 0.16f}
                                    : entropy_spectrum_ramp(entropy_t);
                        break;
                    case ByteVizColorMode::ByteClassSemantic:
                        color = byte_class_base_color(cls, entropy_t);
                        break;
                    case ByteVizColorMode::PrintableVsHighBit:
                        if (cls == ByteClass::UnreadableOrEmpty) {
                            color = RgbFloat{.r = 0.10f, .g = 0.12f, .b = 0.16f};
                        } else {
                            color = RgbFloat{
                                .r = 0.10f + 0.86f * high_bit_t,
                                .g = 0.10f + 0.84f * printable_t,
                                .b = 0.14f + 0.60f * (1.0f - zero_t) * (1.0f - 0.5f * printable_t),
                            };
                        }
                        break;
                    case ByteVizColorMode::PatchAndDiffOverlay: {
                        const float lum = 0.14f + 0.28f * entropy_t;
                        color = RgbFloat{.r = lum * 0.92f, .g = lum, .b = lum * 1.12f};
                        if (tile.is_patch_dirty()) {
                            color = RgbFloat{.r = 0.05f, .g = 0.90f, .b = 1.00f};
                        } else if (tile.is_diff_added()) {
                            color = RgbFloat{.r = 0.18f, .g = 0.92f, .b = 0.42f};
                        } else if (tile.is_diff_modified()) {
                            color = RgbFloat{.r = 1.00f, .g = 0.56f, .b = 0.14f};
                        }
                        break;
                    }
                }

                const float edge_dist = std::min({fx, 1.0f - fx, fy, 1.0f - fy});
                const auto px_border = static_cast<float>(1.35 / std::max(min_cell_px, 1.0));

                if (tile.is_section_start() && fx < 0.26f && fy < 0.26f) {
                    color = RgbFloat{.r = 0.98f, .g = 0.86f, .b = 0.38f};
                }
                if (tile.is_patch_dirty() && fx > 0.64f && fy < 0.36f) {
                    color = RgbFloat{.r = 0.0f, .g = 0.92f, .b = 1.0f};
                }
                if ((tile.is_diff_modified() || tile.is_diff_added()) &&
                    fx > 0.64f && fy > 0.64f) {
                    color = tile.is_diff_added()
                                ? RgbFloat{.r = 0.18f, .g = 0.92f, .b = 0.42f}
                                : RgbFloat{.r = 1.00f, .g = 0.56f, .b = 0.14f};
                }

                if (has_brush) {
                    const bool in_brush = ranges_overlap_u64(
                        tile.base_offset_or_va(), tile.end_offset_or_va(), brush_start, brush_end);
                    if (in_brush) {
                        color = lerp_rgb(color, RgbFloat{.r = 0.98f, .g = 0.90f, .b = 0.42f}, 0.22f);
                        if (edge_dist < std::max(px_border * 1.4f, 0.10f)) {
                            color = RgbFloat{.r = 1.00f, .g = 0.88f, .b = 0.30f};
                        }
                    } else {
                        color.r *= 0.55f;
                        color.g *= 0.55f;
                        color.b *= 0.60f;
                    }
                }

                if (draw_grid) {
                    const auto grid_thresh = static_cast<float>(1.0 / min_cell_px);
                    if ((1.0f - fx) <= grid_thresh || (1.0f - fy) <= grid_thresh) {
                        color = lerp_rgb(color, RgbFloat{.r = 0.05f, .g = 0.06f, .b = 0.09f}, 0.55f);
                    }
                }

                if (viewport.selected_index.has_value() &&
                    tile_idx == static_cast<std::uint64_t>(*viewport.selected_index) &&
                    edge_dist < std::max(px_border * 1.8f, 0.12f)) {
                    color = RgbFloat{.r = 0.35f, .g = 0.95f, .b = 1.0f};
                } else if (viewport.hovered_index.has_value() &&
                           tile_idx == static_cast<std::uint64_t>(*viewport.hovered_index) &&
                           edge_dist < std::max(px_border * 1.5f, 0.10f)) {
                    color = RgbFloat{.r = 1.0f, .g = 1.0f, .b = 1.0f};
                }

                out_rgba8[out_off + 0u] = float_to_u8(color.r);
                out_rgba8[out_off + 1u] = float_to_u8(color.g);
                out_rgba8[out_off + 2u] = float_to_u8(color.b);
                out_rgba8[out_off + 3u] = 255u;
            }
        }
        return;
    }

    // Mode 2: 256x256 Cantor-Dust Digram
    const bool has_bins = snapshot.cantor.packed_gpu_bins.size() == kCantorDigramBinCount;
    const std::optional<std::uint32_t> hov_x =
        viewport.hovered_index.has_value() && (*viewport.hovered_index < kCantorDigramBinCount)
            ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*viewport.hovered_index & 0xFFu))
            : std::nullopt;
    const std::optional<std::uint32_t> hov_y =
        viewport.hovered_index.has_value() && (*viewport.hovered_index < kCantorDigramBinCount)
            ? std::optional<std::uint32_t>(static_cast<std::uint32_t>((*viewport.hovered_index >> 8u) & 0xFFu))
            : std::nullopt;

    for (std::uint32_t py = 0u; py < h; ++py) {
        const double wy = cy + ((static_cast<double>(py) + 0.5) - half_h) / sy;
        for (std::uint32_t px = 0u; px < w; ++px) {
            const double wx = cx + ((static_cast<double>(px) + 0.5) - half_w) / sx;
            const std::size_t out_off =
                (static_cast<std::size_t>(py) * static_cast<std::size_t>(w) +
                 static_cast<std::size_t>(px)) *
                4u;

            if (wx < 0.0 || wy < 0.0 || wx >= 256.0 || wy >= 256.0) {
                out_rgba8[out_off + 0u] = 10u;
                out_rgba8[out_off + 1u] = 12u;
                out_rgba8[out_off + 2u] = 18u;
                out_rgba8[out_off + 3u] = 255u;
                continue;
            }

            const double floor_x = std::floor(wx);
            const double floor_y = std::floor(wy);
            const auto bx = static_cast<std::uint32_t>(floor_x);
            const auto by = static_cast<std::uint32_t>(floor_y);
            const auto fx = static_cast<float>(wx - floor_x);
            const auto fy = static_cast<float>(wy - floor_y);
            const std::size_t bin_idx =
                (static_cast<std::size_t>(by) * kCantorDigramAxis) + static_cast<std::size_t>(bx);

            const std::uint32_t packed = has_bins ? snapshot.cantor.packed_gpu_bins[bin_idx] : 0u;
            const std::uint16_t density_u16 = unpack_cantor_density_u16(packed);
            const CantorPairClass pcls = unpack_cantor_pair_class(packed);
            const float density_t = static_cast<float>(density_u16) / 65535.0f;

            RgbFloat color{.r = 0.05f, .g = 0.06f, .b = 0.09f};
            if (viewport.show_guides_and_grid &&
                bx >= 0x20u && bx <= 0x7Eu && by >= 0x20u && by <= 0x7Eu) {
                color = RgbFloat{.r = 0.06f, .g = 0.09f, .b = 0.11f};
            }

            if (density_u16 > 0u) {
                if (color_mode == ByteVizColorMode::ByteClassSemantic ||
                    color_mode == ByteVizColorMode::PrintableVsHighBit) {
                    const RgbFloat base = cantor_pair_class_color(pcls);
                    const float gain = 0.26f + 0.74f * density_t;
                    color = RgbFloat{
                        .r = base.r * gain,
                        .g = base.g * gain,
                        .b = base.b * gain,
                    };
                    if (density_t > 0.86f) {
                        color = lerp_rgb(
                            color,
                            RgbFloat{.r = 1.0f, .g = 0.99f, .b = 0.90f},
                            (density_t - 0.86f) / 0.14f);
                    }
                } else {
                    color = cantor_density_ramp(density_t);
                }
            }

            if (viewport.show_guides_and_grid) {
                const bool near_ascii_guide =
                    (std::abs(wx - 32.0) * sx < 0.75) ||
                    (std::abs(wx - 127.0) * sx < 0.75) ||
                    (std::abs(wy - 32.0) * sy < 0.75) ||
                    (std::abs(wy - 127.0) * sy < 0.75);
                const bool near_highbit_guide =
                    (std::abs(wx - 128.0) * sx < 0.85) ||
                    (std::abs(wy - 128.0) * sy < 0.85);
                if (near_highbit_guide) {
                    color = lerp_rgb(color, RgbFloat{.r = 0.46f, .g = 0.52f, .b = 0.68f}, 0.42f);
                } else if (near_ascii_guide) {
                    color = lerp_rgb(color, RgbFloat{.r = 0.24f, .g = 0.56f, .b = 0.46f}, 0.36f);
                }
            }

            if (hov_x.has_value() && hov_y.has_value() &&
                (bx == *hov_x || by == *hov_y) && !(bx == *hov_x && by == *hov_y)) {
                color = lerp_rgb(color, RgbFloat{.r = 0.75f, .g = 0.88f, .b = 1.0f}, 0.18f);
            }

            const float edge_dist = std::min({fx, 1.0f - fx, fy, 1.0f - fy});
            const auto px_border = static_cast<float>(1.35 / std::max(min_cell_px, 1.0));
            if (viewport.selected_index.has_value() &&
                bin_idx == *viewport.selected_index &&
                edge_dist < std::max(px_border * 1.8f, 0.22f)) {
                color = RgbFloat{.r = 0.35f, .g = 0.95f, .b = 1.0f};
            } else if (viewport.hovered_index.has_value() &&
                       bin_idx == *viewport.hovered_index &&
                       edge_dist < std::max(px_border * 1.5f, 0.18f)) {
                color = RgbFloat{.r = 1.0f, .g = 1.0f, .b = 1.0f};
            }

            out_rgba8[out_off + 0u] = float_to_u8(color.r);
            out_rgba8[out_off + 1u] = float_to_u8(color.g);
            out_rgba8[out_off + 2u] = float_to_u8(color.b);
            out_rgba8[out_off + 3u] = 255u;
        }
    }
}

std::vector<std::uint8_t> rasterize_byte_viz_rgba8(
    const ByteVizViewport& viewport,
    const ByteVizSnapshot& snapshot,
    ByteVizMode mode,
    ByteVizColorMode color_mode) {
    std::vector<std::uint8_t> rgba8{};
    rasterize_byte_viz_rgba8_into(viewport, snapshot, mode, color_mode, rgba8);
    return rgba8;
}

} // namespace peelf
