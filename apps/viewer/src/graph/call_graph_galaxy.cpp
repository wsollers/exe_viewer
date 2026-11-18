#include "graph/call_graph_galaxy.hpp"

#include <peelf/demangle.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <numbers>
#include <numeric>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace viewer {
namespace {

constexpr float kGoldenAngleRad =
    static_cast<float>(std::numbers::pi * (3.0 - 2.2360679774997896964));
constexpr float kMaxCoordMagnitude = 1.0e6f;

struct VaIntervalEntry {
    std::uint64_t start_va{0u};
    std::uint64_t end_va{0u};
    std::uint32_t index{0u};
};

[[nodiscard]] std::optional<std::uint32_t> find_interval_containing(
    std::span<const VaIntervalEntry> sorted_intervals,
    std::uint64_t va) noexcept {
    if (sorted_intervals.empty()) {
        return std::nullopt;
    }
    const auto it = std::upper_bound(
        sorted_intervals.begin(),
        sorted_intervals.end(),
        va,
        [](std::uint64_t needle, const VaIntervalEntry& entry) noexcept {
            return needle < entry.start_va;
        });
    if (it == sorted_intervals.begin()) {
        return std::nullopt;
    }
    const auto prev = std::prev(it);
    if (va >= prev->start_va && va < prev->end_va) {
        return prev->index;
    }
    return std::nullopt;
}

[[nodiscard]] constexpr GalaxySecuritySeverity map_finding_severity(
    peelf::SecuritySeverity sev) noexcept {
    switch (sev) {
        case peelf::SecuritySeverity::Pass:    return GalaxySecuritySeverity::Pass;
        case peelf::SecuritySeverity::Note:    return GalaxySecuritySeverity::Note;
        case peelf::SecuritySeverity::Warning: return GalaxySecuritySeverity::Warning;
        case peelf::SecuritySeverity::Error:   return GalaxySecuritySeverity::Error;
    }
    return GalaxySecuritySeverity::None;
}

[[nodiscard]] constexpr GalaxyDiffStatus map_function_diff_status(
    peelf::FunctionMatchKind st) noexcept {
    switch (st) {
        case peelf::FunctionMatchKind::Identical:          return GalaxyDiffStatus::Unchanged;
        case peelf::FunctionMatchKind::IdenticalRelocated: return GalaxyDiffStatus::Relocated;
        case peelf::FunctionMatchKind::Modified:           return GalaxyDiffStatus::Modified;
        case peelf::FunctionMatchKind::Added:              return GalaxyDiffStatus::Added;
        case peelf::FunctionMatchKind::Removed:            return GalaxyDiffStatus::Removed;
    }
    return GalaxyDiffStatus::Unchanged;
}

[[nodiscard]] std::string first_line_trimmed(std::string_view text) {
    const std::size_t nl = text.find('\n');
    std::string_view line = (nl == std::string_view::npos) ? text : text.substr(0u, nl);
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
        line.remove_suffix(1u);
    }
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
        line.remove_prefix(1u);
    }
    return std::string(line);
}

[[nodiscard]] constexpr std::uint32_t scale_rgba8_alpha(
    std::uint32_t rgba8,
    float alpha_scale) noexcept {
    const float base_a = static_cast<float>((rgba8 >> 24u) & 0xFFu);
    const float scaled = std::clamp(base_a * alpha_scale, 0.0f, 255.0f);
    const auto out_a = static_cast<std::uint32_t>(scaled + 0.5f);
    return (rgba8 & 0x00FF'FFFFu) | (out_a << 24u);
}

[[nodiscard]] std::uint32_t lerp_rgba8(
    std::uint32_t c0,
    std::uint32_t c1,
    float t) noexcept {
    const float tc = std::clamp(t, 0.0f, 1.0f);
    const float r0 = static_cast<float>(c0 & 0xFFu);
    const float g0 = static_cast<float>((c0 >> 8u) & 0xFFu);
    const float b0 = static_cast<float>((c0 >> 16u) & 0xFFu);
    const float a0 = static_cast<float>((c0 >> 24u) & 0xFFu);

    const float r1 = static_cast<float>(c1 & 0xFFu);
    const float g1 = static_cast<float>((c1 >> 8u) & 0xFFu);
    const float b1 = static_cast<float>((c1 >> 16u) & 0xFFu);
    const float a1 = static_cast<float>((c1 >> 24u) & 0xFFu);

    const auto r = static_cast<std::uint8_t>(std::clamp(r0 + (r1 - r0) * tc, 0.0f, 255.0f) + 0.5f);
    const auto g = static_cast<std::uint8_t>(std::clamp(g0 + (g1 - g0) * tc, 0.0f, 255.0f) + 0.5f);
    const auto b = static_cast<std::uint8_t>(std::clamp(b0 + (b1 - b0) * tc, 0.0f, 255.0f) + 0.5f);
    const auto a = static_cast<std::uint8_t>(std::clamp(a0 + (a1 - a0) * tc, 0.0f, 255.0f) + 0.5f);
    return pack_galaxy_rgba8(r, g, b, a);
}

[[nodiscard]] std::uint32_t heat_ramp_rgba8(float t) noexcept {
    const float x = std::clamp(t, 0.0f, 1.0f);
    if (x < 0.33f) {
        return lerp_rgba8(
            pack_galaxy_rgba8(48u, 96u, 210u, 240u),
            pack_galaxy_rgba8(42u, 198u, 196u, 245u),
            x / 0.33f);
    }
    if (x < 0.67f) {
        return lerp_rgba8(
            pack_galaxy_rgba8(42u, 198u, 196u, 245u),
            pack_galaxy_rgba8(244u, 192u, 66u, 250u),
            (x - 0.33f) / 0.34f);
    }
    return lerp_rgba8(
        pack_galaxy_rgba8(244u, 192u, 66u, 250u),
        pack_galaxy_rgba8(245u, 74u, 74u, 255u),
        (x - 0.67f) / 0.33f);
}

void blend_over_rgba8(
    std::uint8_t* dst_px,
    float src_r,
    float src_g,
    float src_b,
    float src_a_norm) noexcept {
    const float a = std::clamp(src_a_norm, 0.0f, 1.0f);
    if (a <= (1.0f / 512.0f)) {
        return;
    }
    const float inv_a = 1.0f - a;
    const float out_r = src_r * a + static_cast<float>(dst_px[0]) * inv_a;
    const float out_g = src_g * a + static_cast<float>(dst_px[1]) * inv_a;
    const float out_b = src_b * a + static_cast<float>(dst_px[2]) * inv_a;
    const float dst_a = static_cast<float>(dst_px[3]) * (1.0f / 255.0f);
    const float out_a = (a + dst_a * inv_a) * 255.0f;

    dst_px[0] = static_cast<std::uint8_t>(std::clamp(out_r, 0.0f, 255.0f) + 0.5f);
    dst_px[1] = static_cast<std::uint8_t>(std::clamp(out_g, 0.0f, 255.0f) + 0.5f);
    dst_px[2] = static_cast<std::uint8_t>(std::clamp(out_b, 0.0f, 255.0f) + 0.5f);
    dst_px[3] = static_cast<std::uint8_t>(std::clamp(out_a, 0.0f, 255.0f) + 0.5f);
}

[[nodiscard]] float smoothstep01(float edge0, float edge1, float x) noexcept {
    const float denom = edge1 - edge0;
    if (std::abs(denom) <= 1.0e-6f) {
        return (x >= edge1) ? 1.0f : 0.0f;
    }
    const float t = std::clamp((x - edge0) / denom, 0.0f, 1.0f);
    return t * t * (3.0f - 2.0f * t);
}

} // namespace

// ---------------------------------------------------------------------------
// CallGalaxyGraph methods
// ---------------------------------------------------------------------------

std::optional<std::uint32_t> CallGalaxyGraph::find_node_at_va(
    std::uint64_t virtual_address) const noexcept {
    if (virtual_address == 0u || nodes.empty()) {
        return std::nullopt;
    }
    std::optional<std::uint32_t> containing{};
    for (const CallGalaxyNode& node : nodes) {
        if (node.virtual_address == virtual_address) {
            return node.node_index;
        }
        const std::uint64_t span = std::max<std::uint64_t>(node.size_bytes, 1u);
        if (node.virtual_address != 0u &&
            virtual_address >= node.virtual_address &&
            (virtual_address - node.virtual_address) < span) {
            containing = node.node_index;
        }
    }
    return containing;
}

std::span<const std::uint32_t> CallGalaxyGraph::outgoing_edge_indices(
    std::uint32_t node_index) const noexcept {
    if (node_index >= nodes.size() || out_edge_offsets.size() != nodes.size() + 1u) {
        return {};
    }
    const std::uint32_t begin = out_edge_offsets[node_index];
    const std::uint32_t end = out_edge_offsets[node_index + 1u];
    return std::span<const std::uint32_t>(out_edge_indices).subspan(begin, end - begin);
}

std::span<const std::uint32_t> CallGalaxyGraph::incoming_edge_indices(
    std::uint32_t node_index) const noexcept {
    if (node_index >= nodes.size() || in_edge_offsets.size() != nodes.size() + 1u) {
        return {};
    }
    const std::uint32_t begin = in_edge_offsets[node_index];
    const std::uint32_t end = in_edge_offsets[node_index + 1u];
    return std::span<const std::uint32_t>(in_edge_indices).subspan(begin, end - begin);
}

void CallGalaxyGraph::rebuild_adjacency_and_metrics() {
    const std::size_t n = nodes.size();
    const std::size_t m = edges.size();

    out_edge_offsets.assign(n + 1u, 0u);
    in_edge_offsets.assign(n + 1u, 0u);
    out_edge_indices.assign(m, 0u);
    in_edge_indices.assign(m, 0u);

    for (std::size_t i = 0u; i < n; ++i) {
        nodes[i].node_index = static_cast<std::uint32_t>(i);
        nodes[i].in_degree = 0u;
        nodes[i].out_degree = 0u;
    }

    for (const CallGalaxyEdge& edge : edges) {
        if (edge.source_node < n && edge.target_node < n) {
            ++nodes[edge.source_node].out_degree;
            ++nodes[edge.target_node].in_degree;
            ++out_edge_offsets[static_cast<std::size_t>(edge.source_node) + 1u];
            ++in_edge_offsets[static_cast<std::size_t>(edge.target_node) + 1u];
        }
    }

    max_total_degree = 0u;
    for (std::size_t i = 0u; i < n; ++i) {
        max_total_degree = std::max(max_total_degree, nodes[i].total_degree());
        out_edge_offsets[i + 1u] += out_edge_offsets[i];
        in_edge_offsets[i + 1u] += in_edge_offsets[i];
    }

    std::vector<std::uint32_t> out_cursor = out_edge_offsets;
    std::vector<std::uint32_t> in_cursor = in_edge_offsets;
    for (std::size_t e = 0u; e < m; ++e) {
        const CallGalaxyEdge& edge = edges[e];
        if (edge.source_node < n && edge.target_node < n) {
            out_edge_indices[out_cursor[edge.source_node]++] = static_cast<std::uint32_t>(e);
            in_edge_indices[in_cursor[edge.target_node]++] = static_cast<std::uint32_t>(e);
        }
    }

    // Weakly connected components in deterministic node order.
    std::vector<std::uint8_t> visited(n, 0u);
    std::vector<std::uint32_t> queue{};
    queue.reserve(std::min<std::size_t>(n, 4096u));
    std::uint32_t comp_id = 0u;

    for (std::size_t start = 0u; start < n; ++start) {
        if (visited[start] != 0u) {
            continue;
        }
        visited[start] = 1u;
        queue.clear();
        queue.push_back(static_cast<std::uint32_t>(start));

        for (std::size_t q_head = 0u; q_head < queue.size(); ++q_head) {
            const std::uint32_t cur = queue[q_head];
            nodes[cur].component_id = comp_id;

            for (const std::uint32_t e_idx : outgoing_edge_indices(cur)) {
                const std::uint32_t nxt = edges[e_idx].target_node;
                if (nxt < n && visited[nxt] == 0u) {
                    visited[nxt] = 1u;
                    queue.push_back(nxt);
                }
            }
            for (const std::uint32_t e_idx : incoming_edge_indices(cur)) {
                const std::uint32_t nxt = edges[e_idx].source_node;
                if (nxt < n && visited[nxt] == 0u) {
                    visited[nxt] = 1u;
                    queue.push_back(nxt);
                }
            }
        }
        ++comp_id;
    }
    component_count = comp_id;

    // Dense rank-compressed cluster IDs combining `(component_id, section_cluster_id)`.
    std::vector<std::uint64_t> keys{};
    keys.reserve(n);
    for (const CallGalaxyNode& node : nodes) {
        const std::uint64_t key =
            (static_cast<std::uint64_t>(node.component_id) << 32u) |
            static_cast<std::uint64_t>(node.section_cluster_id);
        keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());

    for (CallGalaxyNode& node : nodes) {
        const std::uint64_t key =
            (static_cast<std::uint64_t>(node.component_id) << 32u) |
            static_cast<std::uint64_t>(node.section_cluster_id);
        const auto it = std::lower_bound(keys.begin(), keys.end(), key);
        node.cluster_id = static_cast<std::uint32_t>(std::distance(keys.begin(), it));
    }
}

// ---------------------------------------------------------------------------
// Overlays & Graph Builders
// ---------------------------------------------------------------------------

void apply_call_galaxy_overlays(
    CallGalaxyGraph& graph,
    const peelf::IBinaryImage* image,
    const CallGalaxyBuildOptions& options) {
    if (graph.nodes.empty()) {
        return;
    }

    std::vector<VaIntervalEntry> intervals{};
    intervals.reserve(graph.nodes.size());
    std::unordered_map<std::uint64_t, std::uint32_t> exact_va_to_node{};
    exact_va_to_node.reserve(graph.nodes.size());

    for (CallGalaxyNode& node : graph.nodes) {
        node.security_severity = GalaxySecuritySeverity::None;
        node.security_finding_count = 0u;
        node.top_security_finding.clear();
        node.diff_status = GalaxyDiffStatus::Unchanged;

        if (node.virtual_address != 0u) {
            exact_va_to_node.emplace(node.virtual_address, node.node_index);
            const std::uint64_t end_va =
                node.virtual_address + std::max<std::uint64_t>(node.size_bytes, 1u);
            if (end_va > node.virtual_address) {
                intervals.push_back(VaIntervalEntry{
                    .start_va = node.virtual_address,
                    .end_va = end_va,
                    .index = node.node_index,
                });
            }
        }
    }

    std::sort(
        intervals.begin(),
        intervals.end(),
        [](const VaIntervalEntry& a, const VaIntervalEntry& b) noexcept {
            if (a.start_va != b.start_va) {
                return a.start_va < b.start_va;
            }
            return a.end_va < b.end_va;
        });

    auto resolve_va_to_node = [&](std::uint64_t va) noexcept -> std::optional<std::uint32_t> {
        if (va == 0u) {
            return std::nullopt;
        }
        if (const auto exact_it = exact_va_to_node.find(va); exact_it != exact_va_to_node.end()) {
            return exact_it->second;
        }
        return find_interval_containing(intervals, va);
    };

    if (options.security_report != nullptr) {
        for (const peelf::SecurityFinding& finding : options.security_report->findings) {
            std::optional<std::uint64_t> finding_va = finding.virtual_address;
            if (!finding_va.has_value() && finding.file_offset.has_value() && image != nullptr) {
                finding_va = image->file_offset_to_virtual_address(*finding.file_offset);
            }
            if (!finding_va.has_value()) {
                continue;
            }
            const auto node_idx = resolve_va_to_node(*finding_va);
            if (!node_idx.has_value()) {
                continue;
            }
            CallGalaxyNode& node = graph.nodes[*node_idx];
            const GalaxySecuritySeverity mapped = map_finding_severity(finding.severity);
            ++node.security_finding_count;
            if (static_cast<std::uint8_t>(mapped) >=
                static_cast<std::uint8_t>(node.security_severity)) {
                node.security_severity = mapped;
                if (!finding.rule_id.empty() && !finding.rule_name.empty()) {
                    node.top_security_finding =
                        std::format("{}: {}", finding.rule_id, finding.rule_name);
                } else if (!finding.summary.empty()) {
                    node.top_security_finding = finding.summary;
                } else {
                    node.top_security_finding = finding.rule_id;
                }
            }
        }
    }

    if (options.diff_report != nullptr) {
        std::unordered_map<std::string_view, std::uint32_t> name_lookup{};
        name_lookup.reserve(graph.nodes.size());
        for (const CallGalaxyNode& node : graph.nodes) {
            if (!node.raw_name.empty()) {
                name_lookup.emplace(node.raw_name, node.node_index);
            }
            if (!node.display_name.empty()) {
                name_lookup.emplace(node.display_name, node.node_index);
            }
        }

        for (const peelf::FunctionDiffEntry& fn_diff : options.diff_report->functions) {
            std::optional<std::uint32_t> target_idx{};
            if (fn_diff.lhs_va.has_value()) {
                target_idx = resolve_va_to_node(*fn_diff.lhs_va);
            }
            if (!target_idx.has_value() && fn_diff.rhs_va.has_value()) {
                target_idx = resolve_va_to_node(*fn_diff.rhs_va);
            }
            if (!target_idx.has_value() && !fn_diff.raw_lhs_name.empty()) {
                if (const auto it = name_lookup.find(fn_diff.raw_lhs_name);
                    it != name_lookup.end()) {
                    target_idx = it->second;
                }
            }
            if (!target_idx.has_value() && !fn_diff.display_name.empty()) {
                if (const auto it = name_lookup.find(fn_diff.display_name);
                    it != name_lookup.end()) {
                    target_idx = it->second;
                }
            }
            if (target_idx.has_value()) {
                graph.nodes[*target_idx].diff_status = map_function_diff_status(fn_diff.status);
            }
        }

        for (const peelf::ByteDiffHunk& hunk : options.diff_report->byte_hunks) {
            if (hunk.classification == peelf::ByteHunkClassification::RelocationOnly ||
                hunk.classification == peelf::ByteHunkClassification::NormalizedLoaderSlot) {
                continue;
            }
            const std::optional<std::uint64_t> hunk_va =
                hunk.lhs_va.has_value() ? hunk.lhs_va : hunk.rhs_va;
            if (!hunk_va.has_value()) {
                continue;
            }
            if (const auto idx = resolve_va_to_node(*hunk_va); idx.has_value()) {
                CallGalaxyNode& node = graph.nodes[*idx];
                if (node.diff_status == GalaxyDiffStatus::Unchanged ||
                    node.diff_status == GalaxyDiffStatus::Relocated) {
                    node.diff_status = GalaxyDiffStatus::Modified;
                }
            }
        }
    }

    for (const peelf::ByteVizDiffRange& dr : options.diff_ranges) {
        if (dr.size_bytes == 0u) {
            continue;
        }
        std::optional<std::uint64_t> start_va{};
        if (dr.is_virtual_address) {
            start_va = dr.offset_or_va;
        } else if (image != nullptr) {
            start_va = image->file_offset_to_virtual_address(dr.offset_or_va);
        }
        if (!start_va.has_value() || *start_va == 0u || intervals.empty()) {
            continue;
        }
        const std::uint64_t end_va =
            (*start_va <= std::numeric_limits<std::uint64_t>::max() - dr.size_bytes)
                ? (*start_va + dr.size_bytes)
                : std::numeric_limits<std::uint64_t>::max();
        const GalaxyDiffStatus range_status =
            (dr.kind == peelf::ByteVizDiffKind::Added)
                ? GalaxyDiffStatus::Added
                : GalaxyDiffStatus::Modified;

        // Find first interval whose `end_va > *start_va` and mark all intervals overlapping `[start_va, end_va)`.
        auto it = std::upper_bound(
            intervals.begin(),
            intervals.end(),
            *start_va,
            [](std::uint64_t needle, const VaIntervalEntry& entry) noexcept {
                return needle < entry.start_va;
            });
        if (it != intervals.begin()) {
            --it;
        }
        for (; it != intervals.end() && it->start_va < end_va; ++it) {
            if (it->end_va <= *start_va) {
                continue;
            }
            CallGalaxyNode& node = graph.nodes[it->index];
            if (node.diff_status == GalaxyDiffStatus::Unchanged ||
                node.diff_status == GalaxyDiffStatus::Relocated) {
                node.diff_status = range_status;
            }
        }
    }
}

CallGalaxyGraph build_whole_binary_call_galaxy(
    const peelf::IBinaryImage& image,
    const SymbolIndex& symbols,
    const FunctionIndex& functions,
    const ReferenceIndex& references,
    const CallGalaxyBuildOptions& options,
    std::stop_token stop_token) {
    CallGalaxyGraph graph{};

    // Build section interval table for fast section name & cluster attribution.
    std::vector<VaIntervalEntry> section_intervals{};
    const auto& sections = image.sections();
    section_intervals.reserve(sections.size());
    for (std::size_t s = 0u; s < sections.size(); ++s) {
        const peelf::Section& sec = sections[s];
        const std::uint64_t sz = std::max(sec.virtual_size, sec.file_size);
        if (sec.virtual_address != 0u && sz > 0u) {
            section_intervals.push_back(VaIntervalEntry{
                .start_va = sec.virtual_address,
                .end_va = sec.virtual_address + sz,
                .index = static_cast<std::uint32_t>(s + 1u),
            });
        }
    }
    std::sort(
        section_intervals.begin(),
        section_intervals.end(),
        [](const VaIntervalEntry& a, const VaIntervalEntry& b) noexcept {
            return a.start_va < b.start_va;
        });

    std::unordered_map<std::uint64_t, bool> exported_vas{};
    for (const peelf::ExportEntry& exp : image.exports()) {
        if (exp.virtual_address != 0u) {
            exported_vas.emplace(exp.virtual_address, true);
        }
    }
    for (const SymbolRecord& sym : symbols.records()) {
        if (sym.source == SymbolSource::Export && sym.virtual_address.has_value() &&
            *sym.virtual_address != 0u) {
            exported_vas.emplace(*sym.virtual_address, true);
        }
    }

    // Collect internal functions from `FunctionIndex` (with `SymbolIndex` fallback).
    std::vector<FunctionEntry> seed_functions(
        functions.entries().begin(),
        functions.entries().end());
    if (seed_functions.empty()) {
        for (const SymbolRecord& sym : symbols.records()) {
            if (!sym.virtual_address.has_value() || *sym.virtual_address == 0u || sym.external) {
                continue;
            }
            const bool is_code_sym =
                sym.function.value_or(false) ||
                sym.source == SymbolSource::EntryPoint ||
                sym.source == SymbolSource::Export ||
                symbol_has_code(image, sym);
            if (!is_code_sym) {
                continue;
            }
            FunctionOrigin orig = FunctionOrigin::SymbolTable;
            if (sym.source == SymbolSource::EntryPoint) {
                orig = FunctionOrigin::EntryPoint;
            } else if (sym.source == SymbolSource::Export) {
                orig = FunctionOrigin::ExportedEntry;
            } else if (sym.source == SymbolSource::DebugSymbol) {
                orig = FunctionOrigin::DebugInfo;
            }
            FunctionEntry fe{};
            fe.name = sym.name;
            fe.raw_name = sym.raw_name;
            fe.demangled_name = sym.demangled_name;
            fe.virtual_address = *sym.virtual_address;
            fe.file_offset = sym.file_offset;
            fe.size = (sym.size > 0u) ? sym.size : 16u;
            fe.origin = orig;
            fe.library = sym.library;
            seed_functions.push_back(std::move(fe));
        }
    }

    std::sort(
        seed_functions.begin(),
        seed_functions.end(),
        [](const FunctionEntry& a, const FunctionEntry& b) noexcept {
            return a.virtual_address < b.virtual_address;
        });

    // Ensure non-overlapping spans and cover `image.entry_point()` if non-zero.
    const std::uint64_t image_ep = image.entry_point();
    bool ep_covered = (image_ep == 0u);
    for (std::size_t i = 0u; i < seed_functions.size(); ++i) {
        if (i + 1u < seed_functions.size() &&
            seed_functions[i].virtual_address + seed_functions[i].size >
                seed_functions[i + 1u].virtual_address) {
            seed_functions[i].size =
                seed_functions[i + 1u].virtual_address - seed_functions[i].virtual_address;
        }
        const std::uint64_t end_va =
            seed_functions[i].virtual_address +
            std::max<std::uint64_t>(seed_functions[i].size, 1u);
        if (!ep_covered && image_ep >= seed_functions[i].virtual_address && image_ep < end_va) {
            ep_covered = true;
        }
    }
    if (!ep_covered && image_ep != 0u) {
        FunctionEntry ep_fn{};
        ep_fn.name = "_entry";
        ep_fn.raw_name = "_entry";
        ep_fn.virtual_address = image_ep;
        ep_fn.size = 16u;
        ep_fn.origin = FunctionOrigin::EntryPoint;
        seed_functions.push_back(std::move(ep_fn));
        std::sort(
            seed_functions.begin(),
            seed_functions.end(),
            [](const FunctionEntry& a, const FunctionEntry& b) noexcept {
                return a.virtual_address < b.virtual_address;
            });
    }

    graph.nodes.reserve(seed_functions.size() + image.imports().size());
    std::vector<VaIntervalEntry> internal_intervals{};
    internal_intervals.reserve(seed_functions.size());
    std::unordered_map<std::uint64_t, std::uint32_t> exact_internal_va{};
    exact_internal_va.reserve(seed_functions.size());

    for (const FunctionEntry& fn : seed_functions) {
        if (stop_token.stop_requested()) {
            return {};
        }
        if (fn.virtual_address == 0u || exact_internal_va.contains(fn.virtual_address)) {
            continue;
        }

        const auto node_idx = static_cast<std::uint32_t>(graph.nodes.size());
        CallGalaxyNode node{};
        node.node_index = node_idx;
        node.virtual_address = fn.virtual_address;
        node.size_bytes = std::max<std::uint64_t>(fn.size, 1u);
        node.kind = GalaxyNodeKind::InternalFunction;
        node.origin = fn.origin;
        node.reachability = GalaxyReachability::UnreachableInternal;
        node.is_exported =
            exported_vas.contains(fn.virtual_address) ||
            (fn.origin == FunctionOrigin::ExportedEntry);

        if (const SymbolRecord* sym = symbols.find_exact_address(fn.virtual_address);
            sym != nullptr) {
            node.raw_name = !sym->raw_name.empty()
                                ? sym->raw_name
                                : (!sym->name.empty() ? sym->name : fn.name);
            node.display_name = !sym->demangled_name.empty() ? sym->demangled_name : node.raw_name;
        } else {
            node.raw_name = !fn.raw_name.empty() ? fn.raw_name : fn.name;
            if (!fn.demangled_name.empty()) {
                node.display_name = fn.demangled_name;
            } else if (!node.raw_name.empty()) {
                node.display_name = peelf::demangle_or_raw(node.raw_name);
            }
        }
        if (node.display_name.empty()) {
            node.display_name = std::format("sub_{:x}", fn.virtual_address);
        }

        if (const auto sec_id = find_interval_containing(section_intervals, fn.virtual_address);
            sec_id.has_value() && *sec_id >= 1u && (*sec_id - 1u) < sections.size()) {
            node.section_cluster_id = *sec_id;
            node.module_or_section = sections[*sec_id - 1u].name;
        } else if (!fn.section_name.empty()) {
            node.module_or_section = fn.section_name;
        }

        exact_internal_va.emplace(fn.virtual_address, node_idx);
        internal_intervals.push_back(VaIntervalEntry{
            .start_va = fn.virtual_address,
            .end_va = fn.virtual_address + node.size_bytes,
            .index = node_idx,
        });
        graph.nodes.push_back(std::move(node));
    }

    // Build import lookup table by IAT / stub virtual address.
    struct ImportMeta {
        std::string name{};
        std::string library{};
        std::uint32_t lib_cluster_id{0u};
    };
    std::unordered_map<std::uint64_t, ImportMeta> import_by_va{};
    std::unordered_map<std::string, std::uint32_t> lib_cluster_ids{};
    const auto base_lib_cluster = static_cast<std::uint32_t>(sections.size() + 16u);

    auto register_import_meta = [&](std::uint64_t addr,
                                    std::string_view name,
                                    std::string_view lib) {
        if (addr == 0u || import_by_va.contains(addr)) {
            return;
        }
        std::uint32_t cid = base_lib_cluster;
        if (!lib.empty()) {
            const auto [it, inserted] = lib_cluster_ids.emplace(
                std::string(lib),
                base_lib_cluster + static_cast<std::uint32_t>(lib_cluster_ids.size() + 1u));
            (void)inserted;
            cid = it->second;
        }
        import_by_va.emplace(
            addr,
            ImportMeta{
                .name = std::string(name),
                .library = std::string(lib),
                .lib_cluster_id = cid,
            });
    };

    for (const peelf::ImportEntry& imp : image.imports()) {
        const std::string imp_name =
            !imp.name.empty() ? imp.name : std::format("ord_{}", imp.ordinal);
        register_import_meta(imp.address, imp_name, imp.library);
    }
    for (const SymbolRecord& sym : symbols.records()) {
        if ((sym.source == SymbolSource::Import || sym.external) &&
            sym.virtual_address.has_value() && *sym.virtual_address != 0u) {
            register_import_meta(*sym.virtual_address, sym.name, sym.library);
        }
    }

    std::unordered_map<std::uint64_t, std::uint32_t> external_node_by_va{};
    auto ensure_external_node = [&](std::uint64_t target_va, bool is_known_import) -> std::uint32_t {
        if (const auto it = external_node_by_va.find(target_va); it != external_node_by_va.end()) {
            return it->second;
        }
        const auto node_idx = static_cast<std::uint32_t>(graph.nodes.size());
        CallGalaxyNode ext{};
        ext.node_index = node_idx;
        ext.virtual_address = target_va;
        ext.size_bytes = 0u;
        ext.origin = FunctionOrigin::SymbolTable;
        ext.reachability = GalaxyReachability::ExternalImport;

        if (const auto imp_it = import_by_va.find(target_va); imp_it != import_by_va.end()) {
            ext.kind = GalaxyNodeKind::ExternalImport;
            ext.raw_name = imp_it->second.name;
            ext.display_name = peelf::demangle_or_raw(ext.raw_name);
            ext.module_or_section = imp_it->second.library;
            ext.section_cluster_id = imp_it->second.lib_cluster_id;
        } else {
            ext.kind = is_known_import ? GalaxyNodeKind::ExternalImport
                                       : GalaxyNodeKind::ExternalTarget;
            if (const SymbolRecord* sym = symbols.find_exact_address(target_va); sym != nullptr) {
                ext.raw_name = !sym->raw_name.empty() ? sym->raw_name : sym->name;
                ext.display_name = !sym->demangled_name.empty() ? sym->demangled_name : ext.raw_name;
                ext.module_or_section = sym->library;
            }
            if (ext.display_name.empty()) {
                ext.display_name = std::format("ext_{:x}", target_va);
            }
            ext.section_cluster_id = base_lib_cluster;
        }

        external_node_by_va.emplace(target_va, node_idx);
        graph.nodes.push_back(std::move(ext));
        return node_idx;
    };

    if (options.include_unreferenced_imports) {
        for (const peelf::ImportEntry& imp : image.imports()) {
            if (imp.address != 0u && !exact_internal_va.contains(imp.address)) {
                (void)ensure_external_node(imp.address, true);
            }
        }
    }

    // Extract cross-function Call and Tail-Jump edges from `ReferenceIndex`.
    std::vector<CallGalaxyEdge> raw_edges{};
    const auto all_refs = references.records();
    raw_edges.reserve(all_refs.size() / 2u + 16u);

    std::size_t ref_counter = 0u;
    for (const Reference& ref : all_refs) {
        if ((++ref_counter & 0xFFFu) == 0u && stop_token.stop_requested()) {
            return {};
        }
        const bool is_call = (ref.kind == ReferenceKind::Call);
        const bool is_branch = (options.include_tail_jumps && ref.kind == ReferenceKind::Branch);
        if (!is_call && !is_branch) {
            continue;
        }

        const auto src_idx = find_interval_containing(internal_intervals, ref.source);
        if (!src_idx.has_value()) {
            continue;
        }

        std::optional<std::uint32_t> dst_idx{};
        if (const auto exact_it = exact_internal_va.find(ref.target);
            exact_it != exact_internal_va.end()) {
            dst_idx = exact_it->second;
        } else {
            dst_idx = find_interval_containing(internal_intervals, ref.target);
        }

        if (dst_idx.has_value()) {
            // Skip intra-function branches (local CFG jumps inside the same function).
            if (is_branch && *dst_idx == *src_idx) {
                continue;
            }
            raw_edges.push_back(CallGalaxyEdge{
                .source_node = *src_idx,
                .target_node = *dst_idx,
                .kind = is_call ? GalaxyEdgeKind::Call : GalaxyEdgeKind::TailJump,
                .weight = 1u,
            });
        } else if (ref.target != 0u) {
            const bool known_imp = import_by_va.contains(ref.target);
            if (is_call || known_imp) {
                const std::uint32_t ext_idx = ensure_external_node(ref.target, known_imp);
                raw_edges.push_back(CallGalaxyEdge{
                    .source_node = *src_idx,
                    .target_node = ext_idx,
                    .kind = is_call ? GalaxyEdgeKind::Call : GalaxyEdgeKind::TailJump,
                    .weight = 1u,
                });
            }
        }
    }

    // Deterministically sort and coalesce parallel `(source_node, target_node)` edges.
    std::sort(
        raw_edges.begin(),
        raw_edges.end(),
        [](const CallGalaxyEdge& a, const CallGalaxyEdge& b) noexcept {
            if (a.source_node != b.source_node) {
                return a.source_node < b.source_node;
            }
            if (a.target_node != b.target_node) {
                return a.target_node < b.target_node;
            }
            return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
        });

    graph.edges.reserve(raw_edges.size());
    for (const CallGalaxyEdge& edge : raw_edges) {
        if (!graph.edges.empty() &&
            graph.edges.back().source_node == edge.source_node &&
            graph.edges.back().target_node == edge.target_node) {
            graph.edges.back().weight += edge.weight;
            // `GalaxyEdgeKind::Call` (0) takes priority over `TailJump` (1), already sorted first.
        } else {
            graph.edges.push_back(edge);
        }
    }

    graph.rebuild_adjacency_and_metrics();

    // Entry-point reachability BFS.
    std::vector<std::uint32_t> bfs_queue{};
    for (CallGalaxyNode& node : graph.nodes) {
        if (node.kind != GalaxyNodeKind::InternalFunction) {
            continue;
        }
        const std::uint64_t end_va = node.virtual_address + std::max<std::uint64_t>(node.size_bytes, 1u);
        const bool covers_image_ep =
            (image_ep != 0u && image_ep >= node.virtual_address && image_ep < end_va);
        const bool is_entry_origin =
            (node.origin == FunctionOrigin::EntryPoint) ||
            (node.origin == FunctionOrigin::InitFiniOrTlsCallback) ||
            (options.treat_exports_as_roots && node.is_exported);

        if (covers_image_ep || is_entry_origin) {
            node.reachability = GalaxyReachability::EntryPoint;
            graph.primary_entry_nodes.push_back(node.node_index);
            bfs_queue.push_back(node.node_index);
        }
    }

    for (std::size_t q_head = 0u; q_head < bfs_queue.size(); ++q_head) {
        const std::uint32_t cur = bfs_queue[q_head];
        for (const std::uint32_t e_idx : graph.outgoing_edge_indices(cur)) {
            const std::uint32_t nxt = graph.edges[e_idx].target_node;
            if (nxt < graph.nodes.size() &&
                graph.nodes[nxt].kind == GalaxyNodeKind::InternalFunction &&
                graph.nodes[nxt].reachability == GalaxyReachability::UnreachableInternal) {
                graph.nodes[nxt].reachability = GalaxyReachability::ReachableFromEntry;
                bfs_queue.push_back(nxt);
            }
        }
    }

    apply_call_galaxy_overlays(graph, &image, options);
    return graph;
}

CallGalaxyGraph build_call_galaxy_from_call_graph(
    const CallGraph& graph,
    const CallGalaxyBuildOptions& options) {
    CallGalaxyGraph out{};
    if (graph.nodes.empty()) {
        return out;
    }

    out.nodes.reserve(graph.nodes.size());
    std::unordered_map<std::string_view, std::uint32_t> id_to_index{};
    id_to_index.reserve(graph.nodes.size());

    for (const CallGraphNode& src : graph.nodes) {
        const auto idx = static_cast<std::uint32_t>(out.nodes.size());
        id_to_index.emplace(src.id, idx);

        CallGalaxyNode node{};
        node.node_index = idx;
        node.virtual_address = src.bytes.start.virtual_address.value_or(0u);
        node.size_bytes = std::max<std::uint64_t>(src.bytes.size, 1u);
        if (src.symbol.has_value() && !src.symbol->name.empty()) {
            node.raw_name = src.symbol->name;
            node.display_name =
                !src.symbol->demangled_name.empty() ? src.symbol->demangled_name : src.symbol->name;
        } else {
            node.raw_name = first_line_trimmed(src.label);
            node.display_name = node.raw_name;
        }
        if (node.display_name.empty()) {
            node.display_name =
                (node.virtual_address != 0u)
                    ? std::format("0x{:X}", node.virtual_address)
                    : src.id;
        }

        switch (src.kind) {
            case CallGraphNodeKind::BasicBlock:
            case CallGraphNodeKind::Instruction:
                node.kind = GalaxyNodeKind::BasicBlock;
                node.reachability = GalaxyReachability::UnreachableInternal;
                break;
            case CallGraphNodeKind::Function:
            case CallGraphNodeKind::Unknown:
                node.kind = GalaxyNodeKind::InternalFunction;
                node.reachability = GalaxyReachability::UnreachableInternal;
                break;
            case CallGraphNodeKind::Import:
            case CallGraphNodeKind::External:
                node.kind = GalaxyNodeKind::ExternalImport;
                node.reachability = GalaxyReachability::ExternalImport;
                break;
        }
        out.nodes.push_back(std::move(node));
    }

    std::vector<CallGalaxyEdge> raw_edges{};
    raw_edges.reserve(graph.edges.size());
    for (const CallGraphEdge& ge : graph.edges) {
        if (ge.kind == CallGraphEdgeKind::DataReference) {
            continue;
        }
        const auto from_it = id_to_index.find(ge.from_node_id);
        const auto to_it = id_to_index.find(ge.to_node_id);
        if (from_it == id_to_index.end() || to_it == id_to_index.end()) {
            continue;
        }
        GalaxyEdgeKind ek = GalaxyEdgeKind::Call;
        switch (ge.kind) {
            case CallGraphEdgeKind::Call:                ek = GalaxyEdgeKind::Call; break;
            case CallGraphEdgeKind::ConditionalBranch:   ek = GalaxyEdgeKind::ConditionalBranch; break;
            case CallGraphEdgeKind::UnconditionalBranch: ek = GalaxyEdgeKind::UnconditionalBranch; break;
            case CallGraphEdgeKind::Fallthrough:         ek = GalaxyEdgeKind::Fallthrough; break;
            case CallGraphEdgeKind::Return:              ek = GalaxyEdgeKind::Return; break;
            case CallGraphEdgeKind::DataReference:
            case CallGraphEdgeKind::Unknown:             ek = GalaxyEdgeKind::Call; break;
        }
        raw_edges.push_back(CallGalaxyEdge{
            .source_node = from_it->second,
            .target_node = to_it->second,
            .kind = ek,
            .weight = 1u,
        });
    }

    std::sort(
        raw_edges.begin(),
        raw_edges.end(),
        [](const CallGalaxyEdge& a, const CallGalaxyEdge& b) noexcept {
            if (a.source_node != b.source_node) {
                return a.source_node < b.source_node;
            }
            if (a.target_node != b.target_node) {
                return a.target_node < b.target_node;
            }
            return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
        });

    out.edges.reserve(raw_edges.size());
    for (const CallGalaxyEdge& edge : raw_edges) {
        if (!out.edges.empty() &&
            out.edges.back().source_node == edge.source_node &&
            out.edges.back().target_node == edge.target_node) {
            out.edges.back().weight += edge.weight;
        } else {
            out.edges.push_back(edge);
        }
    }

    out.rebuild_adjacency_and_metrics();

    // Seed entry reachability from node 0 (entry block in CFG or root symbol in fanout).
    if (!out.nodes.empty() && out.nodes[0].kind != GalaxyNodeKind::ExternalImport) {
        out.nodes[0].reachability = GalaxyReachability::EntryPoint;
        out.primary_entry_nodes.push_back(0u);
        std::vector<std::uint32_t> q{0u};
        for (std::size_t head = 0u; head < q.size(); ++head) {
            const std::uint32_t cur = q[head];
            for (const std::uint32_t e_idx : out.outgoing_edge_indices(cur)) {
                const std::uint32_t nxt = out.edges[e_idx].target_node;
                if (nxt < out.nodes.size() &&
                    out.nodes[nxt].kind != GalaxyNodeKind::ExternalImport &&
                    out.nodes[nxt].reachability == GalaxyReachability::UnreachableInternal) {
                    out.nodes[nxt].reachability = GalaxyReachability::ReachableFromEntry;
                    q.push_back(nxt);
                }
            }
        }
    }

    apply_call_galaxy_overlays(out, nullptr, options);
    return out;
}

// ---------------------------------------------------------------------------
// BarnesHutGalaxyLayout
// ---------------------------------------------------------------------------

void BarnesHutGalaxyLayout::reset(
    const CallGalaxyGraph& graph,
    const BarnesHutLayoutConfig& config) {
    config_ = config;
    config_.theta = std::clamp(config_.theta, 0.1f, 2.0f);
    config_.damping = std::clamp(config_.damping, 0.05f, 0.99f);
    config_.cooling_factor = std::clamp(config_.cooling_factor, 0.5f, 0.9999f);
    config_.min_temperature = std::max(config_.min_temperature, 0.01f);
    config_.initial_temperature =
        std::max(config_.initial_temperature, config_.min_temperature);
    config_.softening_distance = std::max(config_.softening_distance, 0.25f);

    const std::size_t n = graph.nodes.size();
    pos_x_.assign(n, 0.0f);
    pos_y_.assign(n, 0.0f);
    vel_x_.assign(n, 0.0f);
    vel_y_.assign(n, 0.0f);
    force_x_.assign(n, 0.0f);
    force_y_.assign(n, 0.0f);
    node_mass_.assign(n, 1.0f);
    inv_degree_damp_.assign(n, 1.0f);
    node_cluster_.assign(n, 0u);
    pinned_.assign(n, 0u);
    total_iterations_ = 0u;
    temperature_ = config_.initial_temperature;
    cluster_count_ = 0u;

    if (n == 0u) {
        edges_.clear();
        return;
    }

    // Deterministic golden-angle spiral initialization ordered by `(cluster_id, virtual_address, node_index)`.
    std::vector<std::uint32_t> order(n, 0u);
    std::iota(order.begin(), order.end(), 0u);
    std::sort(
        order.begin(),
        order.end(),
        [&](std::uint32_t a, std::uint32_t b) noexcept {
            const CallGalaxyNode& na = graph.nodes[a];
            const CallGalaxyNode& nb = graph.nodes[b];
            if (na.cluster_id != nb.cluster_id) {
                return na.cluster_id < nb.cluster_id;
            }
            if (na.virtual_address != nb.virtual_address) {
                return na.virtual_address < nb.virtual_address;
            }
            return na.node_index < nb.node_index;
        });

    const float spiral_spacing = std::max(12.0f, config_.spring_length * 0.65f);
    for (std::size_t rank = 0u; rank < n; ++rank) {
        const std::uint32_t idx = order[rank];
        const CallGalaxyNode& node = graph.nodes[idx];
        const float r = spiral_spacing * std::sqrt(static_cast<float>(rank) + 0.5f);
        const float angle = static_cast<float>(rank) * kGoldenAngleRad;
        pos_x_[idx] = r * std::cos(angle);
        pos_y_[idx] = r * std::sin(angle);

        const float deg = static_cast<float>(node.total_degree());
        node_mass_[idx] = 1.0f + 0.35f * std::log2(1.0f + deg);
        inv_degree_damp_[idx] = 1.0f / std::sqrt(1.0f + 0.25f * deg);
        node_cluster_[idx] = node.cluster_id;
        cluster_count_ = std::max(cluster_count_, node.cluster_id + 1u);
    }

    edges_.clear();
    edges_.reserve(graph.edges.size());
    for (const CallGalaxyEdge& edge : graph.edges) {
        if (edge.source_node >= n || edge.target_node >= n ||
            edge.source_node == edge.target_node) {
            continue;
        }
        const float deg_sum = static_cast<float>(
            graph.nodes[edge.source_node].total_degree() +
            graph.nodes[edge.target_node].total_degree());
        const float w_scale =
            std::min(3.0f, 1.0f + 0.35f * std::log2(static_cast<float>(edge.weight)));
        const float desired_len =
            config_.spring_length * (1.0f + 0.08f * std::log2(1.0f + deg_sum));
        edges_.push_back(CompactEdge{
            .src = edge.source_node,
            .dst = edge.target_node,
            .weight_scale = w_scale,
            .desired_length = desired_len,
        });
    }

    quad_pool_.reserve(n * 2u + 16u);
    cluster_sum_x_.resize(cluster_count_, 0.0);
    cluster_sum_y_.resize(cluster_count_, 0.0);
    cluster_counts_.resize(cluster_count_, 0u);
}

void BarnesHutGalaxyLayout::reheat(float new_temperature) noexcept {
    const float target =
        (new_temperature > 0.0f) ? new_temperature : (config_.initial_temperature * 0.65f);
    temperature_ = std::max(config_.min_temperature, target);
}

void BarnesHutGalaxyLayout::set_node_position(
    std::uint32_t node_index,
    float world_x,
    float world_y,
    bool pin) noexcept {
    if (node_index >= pos_x_.size()) {
        return;
    }
    const float sx = std::isfinite(world_x)
                         ? std::clamp(world_x, -kMaxCoordMagnitude, kMaxCoordMagnitude)
                         : 0.0f;
    const float sy = std::isfinite(world_y)
                         ? std::clamp(world_y, -kMaxCoordMagnitude, kMaxCoordMagnitude)
                         : 0.0f;
    pos_x_[node_index] = sx;
    pos_y_[node_index] = sy;
    vel_x_[node_index] = 0.0f;
    vel_y_[node_index] = 0.0f;
    if (pin) {
        pinned_[node_index] = 1u;
    }
}

void BarnesHutGalaxyLayout::set_node_pinned(std::uint32_t node_index, bool pinned) noexcept {
    if (node_index >= pinned_.size()) {
        return;
    }
    pinned_[node_index] = pinned ? 1u : 0u;
    if (pinned) {
        vel_x_[node_index] = 0.0f;
        vel_y_[node_index] = 0.0f;
    }
}

bool BarnesHutGalaxyLayout::is_node_pinned(std::uint32_t node_index) const noexcept {
    return node_index < pinned_.size() && pinned_[node_index] != 0u;
}

void BarnesHutGalaxyLayout::unpin_all() noexcept {
    std::fill(pinned_.begin(), pinned_.end(), static_cast<std::uint8_t>(0u));
}

GalaxyWorldBounds BarnesHutGalaxyLayout::compute_bounds(float padding_world) const noexcept {
    if (pos_x_.empty()) {
        return GalaxyWorldBounds{
            .min_x = -padding_world,
            .min_y = -padding_world,
            .max_x = padding_world,
            .max_y = padding_world,
        };
    }
    float min_x = pos_x_[0];
    float max_x = pos_x_[0];
    float min_y = pos_y_[0];
    float max_y = pos_y_[0];
    for (std::size_t i = 1u; i < pos_x_.size(); ++i) {
        min_x = std::min(min_x, pos_x_[i]);
        max_x = std::max(max_x, pos_x_[i]);
        min_y = std::min(min_y, pos_y_[i]);
        max_y = std::max(max_y, pos_y_[i]);
    }
    const float pad = std::max(0.0f, padding_world);
    return GalaxyWorldBounds{
        .min_x = min_x - pad,
        .min_y = min_y - pad,
        .max_x = max_x + pad,
        .max_y = max_y + pad,
    };
}

void BarnesHutGalaxyLayout::insert_body_into_quad(
    std::uint32_t quad_idx,
    std::uint32_t body_idx,
    float bx,
    float by,
    float bmass,
    std::uint32_t depth) {
    std::uint32_t cur_idx = quad_idx;
    std::uint32_t cur_depth = depth;

    while (true) {
        // Update weighted center-of-mass accumulators (`com_x`/`com_y` store weighted sums until finalized).
        quad_pool_[cur_idx].mass += bmass;
        quad_pool_[cur_idx].com_x += bmass * bx;
        quad_pool_[cur_idx].com_y += bmass * by;

        if (!quad_pool_[cur_idx].is_internal) {
            if (quad_pool_[cur_idx].body_index == -1) {
                // Empty leaf: store single body and finish.
                quad_pool_[cur_idx].body_index = static_cast<std::int32_t>(body_idx);
                return;
            }
            if (cur_depth >= kMaxQuadtreeDepth || quad_pool_[cur_idx].half_size <= 1.0e-4f) {
                // Bounded max-depth leaf: coalesce coincident/near-coincident bodies safely.
                quad_pool_[cur_idx].body_index = -2;
                return;
            }

            // Subdivide leaf and push existing single body into its quadrant first.
            const std::int32_t existing_body = quad_pool_[cur_idx].body_index;
            quad_pool_[cur_idx].body_index = -1;
            quad_pool_[cur_idx].is_internal = true;

            if (existing_body >= 0) {
                const auto eb = static_cast<std::uint32_t>(existing_body);
                const float ex = pos_x_[eb];
                const float ey = pos_y_[eb];
                const float emass = node_mass_[eb];
                const float cx = quad_pool_[cur_idx].center_x;
                const float cy = quad_pool_[cur_idx].center_y;
                const float child_hs = quad_pool_[cur_idx].half_size * 0.5f;
                const std::uint32_t eq =
                    ((ex >= cx) ? 1u : 0u) | ((ey >= cy) ? 2u : 0u);
                const auto child_idx = static_cast<std::uint32_t>(quad_pool_.size());
                quad_pool_.push_back(QuadNode{
                    .center_x = cx + ((eq & 1u) != 0u ? child_hs : -child_hs),
                    .center_y = cy + ((eq & 2u) != 0u ? child_hs : -child_hs),
                    .half_size = child_hs,
                });
                quad_pool_[cur_idx].children[eq] = child_idx;
                insert_body_into_quad(child_idx, eb, ex, ey, emass, cur_depth + 1u);
            }
        }

        const float cx = quad_pool_[cur_idx].center_x;
        const float cy = quad_pool_[cur_idx].center_y;
        const float child_hs = quad_pool_[cur_idx].half_size * 0.5f;
        const std::uint32_t q_slot = ((bx >= cx) ? 1u : 0u) | ((by >= cy) ? 2u : 0u);
        std::uint32_t child_idx = quad_pool_[cur_idx].children[q_slot];
        if (child_idx == kInvalidQuad) {
            child_idx = static_cast<std::uint32_t>(quad_pool_.size());
            quad_pool_.push_back(QuadNode{
                .center_x = cx + ((q_slot & 1u) != 0u ? child_hs : -child_hs),
                .center_y = cy + ((q_slot & 2u) != 0u ? child_hs : -child_hs),
                .half_size = child_hs,
            });
            quad_pool_[cur_idx].children[q_slot] = child_idx;
        }
        cur_idx = child_idx;
        ++cur_depth;
    }
}

void BarnesHutGalaxyLayout::build_quadtree() {
    quad_pool_.clear();
    const std::size_t n = pos_x_.size();
    if (n == 0u) {
        return;
    }

    float min_x = pos_x_[0];
    float max_x = pos_x_[0];
    float min_y = pos_y_[0];
    float max_y = pos_y_[0];
    for (std::size_t i = 1u; i < n; ++i) {
        min_x = std::min(min_x, pos_x_[i]);
        max_x = std::max(max_x, pos_x_[i]);
        min_y = std::min(min_y, pos_y_[i]);
        max_y = std::max(max_y, pos_y_[i]);
    }

    const float root_cx = 0.5f * (min_x + max_x);
    const float root_cy = 0.5f * (min_y + max_y);
    const float span = std::max({max_x - min_x, max_y - min_y, 16.0f});
    const float root_half = span * 0.55f;

    quad_pool_.push_back(QuadNode{
        .center_x = root_cx,
        .center_y = root_cy,
        .half_size = root_half,
    });

    for (std::size_t i = 0u; i < n; ++i) {
        insert_body_into_quad(
            0u,
            static_cast<std::uint32_t>(i),
            pos_x_[i],
            pos_y_[i],
            node_mass_[i],
            0u);
    }

    // Finalize center-of-mass coordinates in a single flat linear pass.
    for (QuadNode& qn : quad_pool_) {
        if (qn.mass > 0.0f) {
            const float inv_m = 1.0f / qn.mass;
            qn.com_x *= inv_m;
            qn.com_y *= inv_m;
        } else {
            qn.com_x = qn.center_x;
            qn.com_y = qn.center_y;
        }
    }
}

BarnesHutStepResult BarnesHutGalaxyLayout::step(
    std::uint32_t iterations,
    std::stop_token stop_token) {
    BarnesHutStepResult result{};
    result.temperature = temperature_;

    const std::size_t n = pos_x_.size();
    if (n == 0u || iterations == 0u) {
        result.converged = true;
        return result;
    }

    const float theta_sq = config_.theta * config_.theta;
    const float soft_sq = config_.softening_distance * config_.softening_distance;

    for (std::uint32_t iter = 0u; iter < iterations; ++iter) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            break;
        }

        // Sanitize any non-finite positions before building the spatial quadtree.
        for (std::size_t i = 0u; i < n; ++i) {
            if (!std::isfinite(pos_x_[i]) || !std::isfinite(pos_y_[i])) {
                pos_x_[i] = 0.0f;
                pos_y_[i] = 0.0f;
                vel_x_[i] = 0.0f;
                vel_y_[i] = 0.0f;
            }
        }

        build_quadtree();
        std::fill(force_x_.begin(), force_x_.end(), 0.0f);
        std::fill(force_y_.begin(), force_y_.end(), 0.0f);

        // 1. Repulsive Coulomb force via iterative Barnes-Hut quadtree traversal.
        std::array<std::uint32_t, 128> stack{};
        for (std::size_t i = 0u; i < n; ++i) {
            if ((i & 0x1FFu) == 0u && stop_token.stop_requested()) {
                result.cancelled = true;
                return result;
            }
            if (pinned_[i] != 0u) {
                continue;
            }

            const float px = pos_x_[i];
            const float py = pos_y_[i];
            const float mi = node_mass_[i];
            float fx = 0.0f;
            float fy = 0.0f;

            std::size_t sp = 0u;
            stack[sp++] = 0u;

            while (sp > 0u) {
                const QuadNode& qn = quad_pool_[stack[--sp]];
                if (qn.mass <= 0.0f) {
                    continue;
                }

                float dx = px - qn.com_x;
                float dy = py - qn.com_y;
                float dist_sq = dx * dx + dy * dy;

                if (!qn.is_internal) {
                    if (qn.body_index == static_cast<std::int32_t>(i)) {
                        continue;
                    }
                    float eff_mass = qn.mass;
                    if (qn.body_index == -2) {
                        eff_mass = std::max(0.0f, qn.mass - mi);
                        if (eff_mass <= 0.0f) {
                            continue;
                        }
                    }
                    if (dist_sq < 1.0e-5f) {
                        // Deterministic golden-angle symmetry break for exact coincident positions.
                        const float ang = static_cast<float>(i + 1u) * kGoldenAngleRad;
                        dx = std::cos(ang);
                        dy = std::sin(ang);
                        dist_sq = 1.0f;
                    }
                    const float inv_d = 1.0f / std::sqrt(dist_sq + soft_sq);
                    const float mag =
                        (config_.repulsion_strength * mi * eff_mass) / (dist_sq + soft_sq);
                    fx += dx * inv_d * mag;
                    fy += dy * inv_d * mag;
                } else {
                    const float cell_w = qn.half_size * 2.0f;
                    if (cell_w * cell_w < theta_sq * dist_sq) {
                        const float inv_d = 1.0f / std::sqrt(dist_sq + soft_sq);
                        const float mag =
                            (config_.repulsion_strength * mi * qn.mass) / (dist_sq + soft_sq);
                        fx += dx * inv_d * mag;
                        fy += dy * inv_d * mag;
                    } else {
                        for (const std::uint32_t child : qn.children) {
                            if (child != kInvalidQuad && sp < stack.size()) {
                                stack[sp++] = child;
                            }
                        }
                    }
                }
            }

            force_x_[i] = fx;
            force_y_[i] = fy;
        }

        // 2. Attractive Hooke edge springs.
        for (const CompactEdge& e : edges_) {
            const float dx = pos_x_[e.dst] - pos_x_[e.src];
            const float dy = pos_y_[e.dst] - pos_y_[e.src];
            const float dist = std::sqrt(dx * dx + dy * dy);
            if (dist <= 1.0e-4f) {
                continue;
            }
            const float displacement = dist - e.desired_length;
            const float f_mag = config_.spring_stiffness * displacement * e.weight_scale;
            const float ux = dx / dist;
            const float uy = dy / dist;

            if (pinned_[e.src] == 0u) {
                force_x_[e.src] += ux * f_mag * inv_degree_damp_[e.src];
                force_y_[e.src] += uy * f_mag * inv_degree_damp_[e.src];
            }
            if (pinned_[e.dst] == 0u) {
                force_x_[e.dst] -= ux * f_mag * inv_degree_damp_[e.dst];
                force_y_[e.dst] -= uy * f_mag * inv_degree_damp_[e.dst];
            }
        }

        // 3. Gentle cluster cohesion + radial centering gravity.
        if (cluster_count_ > 0u && config_.cluster_gravity_strength > 0.0f) {
            std::fill(cluster_sum_x_.begin(), cluster_sum_x_.end(), 0.0);
            std::fill(cluster_sum_y_.begin(), cluster_sum_y_.end(), 0.0);
            std::fill(cluster_counts_.begin(), cluster_counts_.end(), 0u);
            for (std::size_t i = 0u; i < n; ++i) {
                const std::uint32_t cid = node_cluster_[i];
                if (cid < cluster_count_) {
                    cluster_sum_x_[cid] += static_cast<double>(pos_x_[i]);
                    cluster_sum_y_[cid] += static_cast<double>(pos_y_[i]);
                    ++cluster_counts_[cid];
                }
            }
            for (std::size_t i = 0u; i < n; ++i) {
                if (pinned_[i] != 0u) {
                    continue;
                }
                const std::uint32_t cid = node_cluster_[i];
                if (cid < cluster_count_ && cluster_counts_[cid] > 1u) {
                    const float cx = static_cast<float>(
                        cluster_sum_x_[cid] / static_cast<double>(cluster_counts_[cid]));
                    const float cy = static_cast<float>(
                        cluster_sum_y_[cid] / static_cast<double>(cluster_counts_[cid]));
                    force_x_[i] += (cx - pos_x_[i]) * config_.cluster_gravity_strength;
                    force_y_[i] += (cy - pos_y_[i]) * config_.cluster_gravity_strength;
                }
                force_x_[i] -= pos_x_[i] * config_.gravity_strength * node_mass_[i];
                force_y_[i] -= pos_y_[i] * config_.gravity_strength * node_mass_[i];
            }
        } else {
            for (std::size_t i = 0u; i < n; ++i) {
                if (pinned_[i] == 0u) {
                    force_x_[i] -= pos_x_[i] * config_.gravity_strength * node_mass_[i];
                    force_y_[i] -= pos_y_[i] * config_.gravity_strength * node_mass_[i];
                }
            }
        }

        // 4. Integrate velocities, clamp per-step displacement, enforce pinned invariance & finite bounds.
        const float max_step = std::max(temperature_, config_.min_temperature);
        double disp_sum = 0.0;
        float max_disp = 0.0f;
        std::size_t free_nodes = 0u;

        for (std::size_t i = 0u; i < n; ++i) {
            if (pinned_[i] != 0u) {
                vel_x_[i] = 0.0f;
                vel_y_[i] = 0.0f;
                continue;
            }
            ++free_nodes;
            float vx = (vel_x_[i] + force_x_[i] / node_mass_[i]) * config_.damping;
            float vy = (vel_y_[i] + force_y_[i] / node_mass_[i]) * config_.damping;
            if (!std::isfinite(vx) || !std::isfinite(vy)) {
                vx = 0.0f;
                vy = 0.0f;
            }

            const float speed = std::hypot(vx, vy);
            if (speed > max_step && speed > 0.0f) {
                const float scale = max_step / speed;
                vx *= scale;
                vy *= scale;
            }

            vel_x_[i] = vx;
            vel_y_[i] = vy;

            float nx = pos_x_[i] + vx;
            float ny = pos_y_[i] + vy;
            if (!std::isfinite(nx) || !std::isfinite(ny)) {
                nx = 0.0f;
                ny = 0.0f;
                vel_x_[i] = 0.0f;
                vel_y_[i] = 0.0f;
            }
            pos_x_[i] = std::clamp(nx, -kMaxCoordMagnitude, kMaxCoordMagnitude);
            pos_y_[i] = std::clamp(ny, -kMaxCoordMagnitude, kMaxCoordMagnitude);

            const float actual_disp = std::min(speed, max_step);
            disp_sum += static_cast<double>(actual_disp);
            max_disp = std::max(max_disp, actual_disp);
        }

        temperature_ = std::max(config_.min_temperature, temperature_ * config_.cooling_factor);
        ++total_iterations_;
        ++result.iterations_executed;
        result.max_displacement = max_disp;
        result.average_displacement =
            (free_nodes > 0u)
                ? static_cast<float>(disp_sum / static_cast<double>(free_nodes))
                : 0.0f;
        result.temperature = temperature_;

        if (result.average_displacement <= config_.convergence_threshold &&
            temperature_ <= config_.min_temperature * 1.25f) {
            result.converged = true;
            break;
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Ego-Network, Shortest Path, Hit-Testing, & GPU Instance Generation
// ---------------------------------------------------------------------------

GalaxyEgoMask compute_ego_network_mask(
    const CallGalaxyGraph& graph,
    std::uint32_t focus_node) {
    GalaxyEgoMask mask{};
    mask.focus_node = focus_node;
    mask.node_roles.assign(graph.nodes.size(), GalaxyEgoRole::None);
    mask.edge_active.assign(graph.edges.size(), 0u);

    if (focus_node >= graph.nodes.size()) {
        mask.focus_node = kInvalidGalaxyNode;
        return mask;
    }

    mask.node_roles[focus_node] = GalaxyEgoRole::Focus;

    for (const std::uint32_t e_idx : graph.outgoing_edge_indices(focus_node)) {
        mask.edge_active[e_idx] = 1u;
        const std::uint32_t dst = graph.edges[e_idx].target_node;
        if (dst < graph.nodes.size() && dst != focus_node) {
            mask.node_roles[dst] = GalaxyEgoRole::DirectCallee;
        }
    }

    for (const std::uint32_t e_idx : graph.incoming_edge_indices(focus_node)) {
        mask.edge_active[e_idx] = 1u;
        const std::uint32_t src = graph.edges[e_idx].source_node;
        if (src < graph.nodes.size() && src != focus_node) {
            if (mask.node_roles[src] == GalaxyEgoRole::DirectCallee) {
                mask.node_roles[src] = GalaxyEgoRole::MutualCallerCallee;
            } else {
                mask.node_roles[src] = GalaxyEgoRole::DirectCaller;
            }
        }
    }

    return mask;
}

GalaxyCallPath find_shortest_call_path_from_roots(
    const CallGalaxyGraph& graph,
    std::span<const std::uint32_t> root_nodes,
    std::uint32_t to_node) {
    GalaxyCallPath path{};
    const std::size_t n = graph.nodes.size();
    if (to_node >= n || root_nodes.empty()) {
        return path;
    }

    std::vector<std::uint8_t> visited(n, 0u);
    std::vector<std::uint32_t> parent_node(n, kInvalidGalaxyNode);
    std::vector<std::uint32_t> parent_edge(n, kInvalidGalaxyNode);
    std::vector<std::uint32_t> queue{};
    queue.reserve(std::min<std::size_t>(n, 1024u));

    for (const std::uint32_t root : root_nodes) {
        if (root >= n || visited[root] != 0u) {
            continue;
        }
        if (root == to_node) {
            path.nodes.push_back(root);
            return path;
        }
        visited[root] = 1u;
        queue.push_back(root);
    }

    bool found = false;
    for (std::size_t head = 0u; head < queue.size() && !found; ++head) {
        const std::uint32_t cur = queue[head];
        for (const std::uint32_t e_idx : graph.outgoing_edge_indices(cur)) {
            const std::uint32_t nxt = graph.edges[e_idx].target_node;
            if (nxt >= n || visited[nxt] != 0u) {
                continue;
            }
            visited[nxt] = 1u;
            parent_node[nxt] = cur;
            parent_edge[nxt] = e_idx;
            if (nxt == to_node) {
                found = true;
                break;
            }
            queue.push_back(nxt);
        }
    }

    if (!found) {
        return path;
    }

    for (std::uint32_t cur = to_node; cur != kInvalidGalaxyNode; cur = parent_node[cur]) {
        path.nodes.push_back(cur);
        if (parent_edge[cur] != kInvalidGalaxyNode) {
            path.edges.push_back(parent_edge[cur]);
        }
    }
    std::reverse(path.nodes.begin(), path.nodes.end());
    std::reverse(path.edges.begin(), path.edges.end());
    return path;
}

GalaxyCallPath find_shortest_call_path(
    const CallGalaxyGraph& graph,
    std::uint32_t from_node,
    std::uint32_t to_node) {
    const std::array<std::uint32_t, 1> roots{{from_node}};
    return find_shortest_call_path_from_roots(graph, roots, to_node);
}

float compute_galaxy_node_world_radius(const CallGalaxyNode& node) noexcept {
    const float deg_term = 1.65f * std::log2(1.0f + static_cast<float>(node.total_degree()));
    const float size_term =
        (node.size_bytes > 0u)
            ? (0.35f * std::log2(1.0f + static_cast<float>(node.size_bytes) / 32.0f))
            : 0.0f;
    const float entry_bonus =
        (node.reachability == GalaxyReachability::EntryPoint) ? 2.2f : 0.0f;
    return std::clamp(3.6f + deg_term + size_term + entry_bonus, 3.5f, 18.0f);
}

std::uint32_t compute_galaxy_node_fill_rgba8(
    const CallGalaxyGraph& graph,
    const CallGalaxyNode& node,
    GalaxyColorMode color_mode) noexcept {
    switch (color_mode) {
        case GalaxyColorMode::OriginAndSection: {
            if (node.kind == GalaxyNodeKind::ExternalImport ||
                node.kind == GalaxyNodeKind::ExternalTarget) {
                return pack_galaxy_rgba8(184u, 118u, 245u, 240u); // Violet import
            }
            if (node.reachability == GalaxyReachability::EntryPoint ||
                node.origin == FunctionOrigin::EntryPoint) {
                return pack_galaxy_rgba8(250u, 198u, 68u, 255u); // Gold entry
            }
            if (node.is_exported || node.origin == FunctionOrigin::ExportedEntry) {
                return pack_galaxy_rgba8(68u, 214u, 152u, 248u); // Mint export
            }
            // Distinct section/cluster palette for internal code/blocks.
            static constexpr std::array<std::uint32_t, 8> kSectionPalette{{
                pack_galaxy_rgba8(78u, 162u, 248u, 242u),
                pack_galaxy_rgba8(72u, 206u, 218u, 242u),
                pack_galaxy_rgba8(116u, 142u, 250u, 242u),
                pack_galaxy_rgba8(96u, 198u, 128u, 242u),
                pack_galaxy_rgba8(236u, 148u, 84u, 242u),
                pack_galaxy_rgba8(224u, 112u, 168u, 242u),
                pack_galaxy_rgba8(152u, 198u, 88u, 242u),
                pack_galaxy_rgba8(108u, 178u, 212u, 242u),
            }};
            return kSectionPalette[node.section_cluster_id % kSectionPalette.size()];
        }
        case GalaxyColorMode::EntryReachability: {
            switch (node.reachability) {
                case GalaxyReachability::EntryPoint:
                    return pack_galaxy_rgba8(255u, 206u, 72u, 255u);
                case GalaxyReachability::ReachableFromEntry:
                    return pack_galaxy_rgba8(68u, 188u, 246u, 244u);
                case GalaxyReachability::UnreachableInternal:
                    return pack_galaxy_rgba8(116u, 124u, 146u, 210u);
                case GalaxyReachability::ExternalImport:
                    return pack_galaxy_rgba8(192u, 124u, 248u, 238u);
            }
            return pack_galaxy_rgba8(116u, 124u, 146u, 210u);
        }
        case GalaxyColorMode::SecurityFindings: {
            switch (node.security_severity) {
                case GalaxySecuritySeverity::Error:
                    return pack_galaxy_rgba8(246u, 74u, 74u, 255u);
                case GalaxySecuritySeverity::Warning:
                    return pack_galaxy_rgba8(248u, 172u, 58u, 252u);
                case GalaxySecuritySeverity::Note:
                    return pack_galaxy_rgba8(82u, 184u, 250u, 245u);
                case GalaxySecuritySeverity::Pass:
                    return pack_galaxy_rgba8(74u, 208u, 132u, 240u);
                case GalaxySecuritySeverity::None:
                    return pack_galaxy_rgba8(74u, 82u, 102u, 185u);
            }
            return pack_galaxy_rgba8(74u, 82u, 102u, 185u);
        }
        case GalaxyColorMode::BinaryDiff: {
            switch (node.diff_status) {
                case GalaxyDiffStatus::Unchanged:
                    return pack_galaxy_rgba8(76u, 86u, 106u, 180u);
                case GalaxyDiffStatus::Relocated:
                    return pack_galaxy_rgba8(92u, 176u, 250u, 244u);
                case GalaxyDiffStatus::Modified:
                    return pack_galaxy_rgba8(250u, 182u, 56u, 255u);
                case GalaxyDiffStatus::Added:
                    return pack_galaxy_rgba8(72u, 218u, 126u, 255u);
                case GalaxyDiffStatus::Removed:
                    return pack_galaxy_rgba8(246u, 78u, 82u, 255u);
            }
            return pack_galaxy_rgba8(76u, 86u, 106u, 180u);
        }
        case GalaxyColorMode::CallDegreeHeat: {
            const float denom =
                std::log2(1.0f + static_cast<float>(std::max(1u, graph.max_total_degree)));
            const float numer = std::log2(1.0f + static_cast<float>(node.total_degree()));
            return heat_ramp_rgba8((denom > 0.0f) ? (numer / denom) : 0.0f);
        }
    }
    return pack_galaxy_rgba8(78u, 162u, 248u, 242u);
}

std::optional<std::uint32_t> hit_test_galaxy_node(
    const CallGalaxyGraph& graph,
    std::span<const float> world_x,
    std::span<const float> world_y,
    const ViewportCamera2D& camera,
    float viewport_width_px,
    float viewport_height_px,
    float cursor_x_px,
    float cursor_y_px,
    float hit_slop_px) noexcept {
    const std::size_t n = graph.nodes.size();
    if (n == 0u || world_x.size() < n || world_y.size() < n ||
        viewport_width_px <= 0.0f || viewport_height_px <= 0.0f) {
        return std::nullopt;
    }

    const auto vp_w = static_cast<double>(viewport_width_px);
    const auto vp_h = static_cast<double>(viewport_height_px);
    const auto zoom = static_cast<float>(0.5 * (camera.scale_x + camera.scale_y));
    const float slop = std::max(0.0f, hit_slop_px);
    std::optional<std::uint32_t> best_node{};
    float best_dist_sq = std::numeric_limits<float>::infinity();

    for (std::size_t i = 0u; i < n; ++i) {
        const Vec2d sp = camera.world_to_screen(
            static_cast<double>(world_x[i]),
            static_cast<double>(world_y[i]),
            vp_w,
            vp_h);
        const float r_px = std::clamp(
            compute_galaxy_node_world_radius(graph.nodes[i]) * zoom,
            2.5f,
            44.0f);
        const float hit_r = r_px + slop;
        const float dx = cursor_x_px - static_cast<float>(sp.x);
        const float dy = cursor_y_px - static_cast<float>(sp.y);
        const float d2 = dx * dx + dy * dy;
        if (d2 <= hit_r * hit_r && d2 <= best_dist_sq) {
            best_dist_sq = d2;
            best_node = static_cast<std::uint32_t>(i);
        }
    }
    return best_node;
}

GalaxyRenderBatch build_galaxy_render_batch(
    const CallGalaxyGraph& graph,
    std::span<const float> world_x,
    std::span<const float> world_y,
    const ViewportCamera2D& camera,
    const GalaxyRenderBuildOptions& options) {
    GalaxyRenderBatch batch{};
    const std::size_t n = graph.nodes.size();
    const std::size_t m = graph.edges.size();
    if (n == 0u || world_x.size() < n || world_y.size() < n ||
        options.viewport_width_px <= 0.0f || options.viewport_height_px <= 0.0f) {
        return batch;
    }

    const float vp_w = options.viewport_width_px;
    const float vp_h = options.viewport_height_px;
    const auto vp_wd = static_cast<double>(vp_w);
    const auto vp_hd = static_cast<double>(vp_h);
    const auto zoom = static_cast<float>(0.5 * (camera.scale_x + camera.scale_y));

    std::vector<std::uint8_t> on_path_node(n, 0u);
    std::vector<std::uint8_t> on_path_edge(m, 0u);
    const bool has_path =
        (options.highlighted_path != nullptr && !options.highlighted_path->empty());
    if (has_path) {
        for (const std::uint32_t ni : options.highlighted_path->nodes) {
            if (ni < n) {
                on_path_node[ni] = 1u;
            }
        }
        for (const std::uint32_t ei : options.highlighted_path->edges) {
            if (ei < m) {
                on_path_edge[ei] = 1u;
            }
        }
    }

    const bool has_ego =
        (options.ego_mask != nullptr &&
         options.ego_mask->focus_node < n &&
         options.ego_mask->node_roles.size() == n);

    // Pre-project all node centers & base colors so edge endpoint projection is O(1).
    std::vector<Vec2f> screen_pos(n);
    std::vector<float> screen_radius(n, 3.0f);
    std::vector<std::uint32_t> base_colors(n, 0u);
    std::vector<std::uint8_t> node_visible(n, 0u);
    constexpr float kCullMarginPx = 64.0f;

    for (std::size_t i = 0u; i < n; ++i) {
        const Vec2d spd = camera.world_to_screen(
            static_cast<double>(world_x[i]),
            static_cast<double>(world_y[i]),
            vp_wd,
            vp_hd);
        const Vec2f sp{
            .x = static_cast<float>(spd.x),
            .y = static_cast<float>(spd.y),
        };
        const float r_px = std::clamp(
            compute_galaxy_node_world_radius(graph.nodes[i]) * zoom,
            2.2f,
            42.0f);
        screen_pos[i] = sp;
        screen_radius[i] = r_px;
        base_colors[i] = compute_galaxy_node_fill_rgba8(
            graph,
            graph.nodes[i],
            options.color_mode);

        if (sp.x + r_px + kCullMarginPx >= 0.0f &&
            sp.x - r_px - kCullMarginPx <= vp_w &&
            sp.y + r_px + kCullMarginPx >= 0.0f &&
            sp.y - r_px - kCullMarginPx <= vp_h) {
            node_visible[i] = 1u;
        } else {
            ++batch.culled_nodes;
        }
    }

    // Build edges with frustum AABB culling + zoom-adaptive alpha & stride decimation.
    const std::size_t edge_cap = std::max<std::size_t>(256u, options.max_visible_edges);
    const std::size_t stride =
        (m > edge_cap) ? ((m + edge_cap - 1u) / edge_cap) : 1u;
    const float zoom_alpha = std::clamp(0.18f + 0.55f * std::sqrt(zoom), 0.14f, 0.78f);
    const bool dim_background = has_ego || has_path || options.has_active_search;

    std::vector<GalaxyEdgeGpuInstance> fg_edges{};
    batch.edges.reserve(std::min(m, edge_cap));

    for (std::size_t e = 0u; e < m; ++e) {
        const CallGalaxyEdge& edge = graph.edges[e];
        if (edge.source_node >= n || edge.target_node >= n ||
            edge.source_node == edge.target_node) {
            continue;
        }

        const Vec2f p0 = screen_pos[edge.source_node];
        const Vec2f p1 = screen_pos[edge.target_node];
        const float min_x = std::min(p0.x, p1.x);
        const float max_x = std::max(p0.x, p1.x);
        const float min_y = std::min(p0.y, p1.y);
        const float max_y = std::max(p0.y, p1.y);

        if (max_x < -16.0f || min_x > vp_w + 16.0f ||
            max_y < -16.0f || min_y > vp_h + 16.0f) {
            ++batch.culled_or_decimated_edges;
            continue;
        }
        const float seg_dx = p1.x - p0.x;
        const float seg_dy = p1.y - p0.y;
        if ((seg_dx * seg_dx + seg_dy * seg_dy) < 0.36f) {
            ++batch.culled_or_decimated_edges;
            continue;
        }

        const bool edge_on_path = (on_path_edge[e] != 0u);
        const bool edge_in_ego =
            has_ego && e < options.ego_mask->edge_active.size() &&
            options.ego_mask->edge_active[e] != 0u;
        const bool is_fg = edge_on_path || edge_in_ego;

        if (!is_fg && stride > 1u && edge.weight <= 1u && (e % stride) != 0u) {
            ++batch.culled_or_decimated_edges;
            continue;
        }

        std::uint32_t edge_flags = 0u;
        if (edge.kind == GalaxyEdgeKind::TailJump ||
            edge.kind == GalaxyEdgeKind::ConditionalBranch) {
            edge_flags |= kGalaxyEdgeFlagDashed;
        }

        float width_px = std::clamp(
            (1.0f + 0.35f * std::log2(static_cast<float>(edge.weight))) *
                std::clamp(zoom, 0.65f, 1.8f),
            0.85f,
            3.2f);
        std::uint32_t src_col = base_colors[edge.source_node];
        std::uint32_t dst_col = base_colors[edge.target_node];

        if (edge_on_path) {
            edge_flags |= (kGalaxyEdgeFlagHighlighted | kGalaxyEdgeFlagCallPath);
            width_px = std::max(width_px, 2.8f);
            src_col = pack_galaxy_rgba8(255u, 198u, 64u, 248u);
            dst_col = pack_galaxy_rgba8(255u, 242u, 148u, 255u);
        } else if (edge_in_ego) {
            edge_flags |= kGalaxyEdgeFlagHighlighted;
            width_px = std::max(width_px, 2.1f);
            src_col = scale_rgba8_alpha(src_col, 0.82f);
            dst_col = lerp_rgba8(dst_col, pack_galaxy_rgba8(240u, 248u, 255u, 250u), 0.35f);
        } else {
            const float bg_alpha = dim_background ? (zoom_alpha * 0.22f) : (zoom_alpha * 0.62f);
            src_col = scale_rgba8_alpha(src_col, bg_alpha * 0.65f);
            dst_col = scale_rgba8_alpha(dst_col, bg_alpha);
        }

        const auto width_q8 = static_cast<std::uint32_t>(
            std::clamp(std::lround(width_px * 256.0f), 96L, 8192L));

        const GalaxyEdgeGpuInstance inst{
            .x0_px = p0.x,
            .y0_px = p0.y,
            .x1_px = p1.x,
            .y1_px = p1.y,
            .color_src_rgba8 = src_col,
            .color_dst_rgba8 = dst_col,
            .width_q8_and_flags = (width_q8 & 0xFFFFu) | (edge_flags << 16u),
            .reserved = 0u,
        };

        if (is_fg) {
            fg_edges.push_back(inst);
        } else if (batch.edges.size() < edge_cap) {
            batch.edges.push_back(inst);
        } else {
            ++batch.culled_or_decimated_edges;
        }
    }

    batch.edges.insert(batch.edges.end(), fg_edges.begin(), fg_edges.end());

    // Build visible nodes & label candidates, sorting highlighted nodes on top.
    struct RankedNode {
        std::uint8_t layer{0u};
        GalaxyNodeGpuInstance inst{};
    };
    std::vector<RankedNode> ranked_nodes{};
    ranked_nodes.reserve(n - batch.culled_nodes);
    std::vector<GalaxyLabelCandidate> raw_labels{};

    for (std::size_t i = 0u; i < n; ++i) {
        if (node_visible[i] == 0u) {
            continue;
        }
        const auto node_idx = static_cast<std::uint32_t>(i);
        const CallGalaxyNode& node = graph.nodes[i];
        const bool is_hovered = (node_idx == options.hovered_node);
        const bool is_selected = (node_idx == options.selected_node);
        const bool is_pinned =
            (i < options.pinned_mask.size() && options.pinned_mask[i] != 0u);
        const bool is_on_path = (on_path_node[i] != 0u);
        const bool is_search_hit =
            (options.has_active_search &&
             i < options.search_match_mask.size() &&
             options.search_match_mask[i] != 0u);
        const GalaxyEgoRole ego_role =
            has_ego ? options.ego_mask->node_roles[i] : GalaxyEgoRole::None;
        const bool is_ego_member = (ego_role != GalaxyEgoRole::None);

        const bool is_foreground =
            is_hovered || is_selected || is_on_path || is_search_hit || is_ego_member;
        const bool is_dimmed = dim_background && !is_foreground;

        std::uint32_t flags = 0u;
        if (is_hovered) {
            flags |= kGalaxyNodeFlagHovered;
        }
        if (is_selected) {
            flags |= kGalaxyNodeFlagSelected;
        }
        if (is_pinned) {
            flags |= kGalaxyNodeFlagPinned;
        }
        if (is_on_path) {
            flags |= kGalaxyNodeFlagOnCallPath;
        }
        if (is_search_hit) {
            flags |= kGalaxyNodeFlagSearchMatch;
        }
        if (is_dimmed) {
            flags |= kGalaxyNodeFlagDimmed;
        }
        if (node.reachability == GalaxyReachability::EntryPoint) {
            flags |= kGalaxyNodeFlagEntryPoint;
        }
        if (node.kind == GalaxyNodeKind::ExternalImport ||
            node.kind == GalaxyNodeKind::ExternalTarget) {
            flags |= kGalaxyNodeFlagExternal;
        }

        std::uint32_t fill = base_colors[i];
        std::uint32_t ring = pack_galaxy_rgba8(226u, 234u, 248u, 215u);
        float halo_px = 0.0f;
        float radius_px = screen_radius[i];
        std::uint8_t layer = 1u;

        if (is_dimmed) {
            fill = scale_rgba8_alpha(fill, 0.24f);
            ring = pack_galaxy_rgba8(110u, 120u, 140u, 65u);
            layer = 0u;
        }
        if (ego_role == GalaxyEgoRole::DirectCaller) {
            ring = pack_galaxy_rgba8(102u, 214u, 255u, 250u);
            halo_px = std::max(halo_px, 4.5f);
            layer = 2u;
        } else if (ego_role == GalaxyEgoRole::DirectCallee ||
                   ego_role == GalaxyEgoRole::MutualCallerCallee) {
            ring = pack_galaxy_rgba8(114u, 242u, 172u, 250u);
            halo_px = std::max(halo_px, 4.5f);
            layer = 2u;
        }
        if (is_search_hit) {
            ring = pack_galaxy_rgba8(255u, 132u, 238u, 255u);
            halo_px = std::max(halo_px, 6.0f);
            radius_px = std::max(radius_px, 4.8f);
            layer = 3u;
        }
        if (is_on_path) {
            ring = pack_galaxy_rgba8(255u, 216u, 84u, 255u);
            halo_px = std::max(halo_px, 6.5f);
            radius_px = std::max(radius_px, 5.0f);
            layer = 4u;
        }
        if (is_pinned) {
            ring = pack_galaxy_rgba8(120u, 236u, 255u, 255u);
            halo_px = std::max(halo_px, 5.0f);
        }
        if (is_selected) {
            ring = pack_galaxy_rgba8(255u, 244u, 160u, 255u);
            halo_px = std::max(halo_px, 8.5f);
            radius_px += 1.4f;
            layer = 5u;
        }
        if (is_hovered) {
            ring = pack_galaxy_rgba8(255u, 255u, 255u, 255u);
            halo_px = std::max(halo_px, 9.0f);
            radius_px += 1.6f;
            layer = 6u;
        }

        ranked_nodes.push_back(RankedNode{
            .layer = layer,
            .inst = GalaxyNodeGpuInstance{
                .cx_px = screen_pos[i].x,
                .cy_px = screen_pos[i].y,
                .radius_px = radius_px,
                .halo_px = halo_px,
                .fill_rgba8 = fill,
                .ring_rgba8 = ring,
                .flags = flags,
                .node_index = node_idx,
            },
        });

        // Label eligibility: hovered/selected/path/search/ego, or high-degree hubs / zoomed-in view.
        const bool zoom_eligible = (zoom >= 1.35f) || (radius_px >= 7.5f);
        const bool hub_eligible =
            (node.reachability == GalaxyReachability::EntryPoint) ||
            (node.total_degree() >= 6u && radius_px >= 4.2f);
        if (!is_dimmed && (is_foreground || zoom_eligible || hub_eligible)) {
            float prio = static_cast<float>(node.total_degree()) + radius_px * 2.0f;
            if (node.reachability == GalaxyReachability::EntryPoint) {
                prio += 200.0f;
            }
            if (is_ego_member) {
                prio += 500.0f;
            }
            if (is_search_hit) {
                prio += 800.0f;
            }
            if (is_on_path) {
                prio += 1200.0f;
            }
            if (is_selected) {
                prio += 5000.0f;
            }
            if (is_hovered) {
                prio += 10000.0f;
            }
            raw_labels.push_back(GalaxyLabelCandidate{
                .node_index = node_idx,
                .screen_x_px = screen_pos[i].x,
                .screen_y_px = screen_pos[i].y,
                .radius_px = radius_px,
                .priority = prio,
            });
        }
    }

    std::stable_sort(
        ranked_nodes.begin(),
        ranked_nodes.end(),
        [](const RankedNode& a, const RankedNode& b) noexcept {
            return a.layer < b.layer;
        });

    batch.nodes.reserve(ranked_nodes.size());
    for (const RankedNode& rn : ranked_nodes) {
        batch.nodes.push_back(rn.inst);
    }

    // Greedy screen-space de-overlap for crisp ImGui node labels.
    std::sort(
        raw_labels.begin(),
        raw_labels.end(),
        [](const GalaxyLabelCandidate& a, const GalaxyLabelCandidate& b) noexcept {
            if (a.priority != b.priority) {
                return a.priority > b.priority;
            }
            return a.node_index < b.node_index;
        });

    batch.labels.reserve(std::min(raw_labels.size(), options.max_labels));
    for (const GalaxyLabelCandidate& cand : raw_labels) {
        if (batch.labels.size() >= options.max_labels) {
            break;
        }
        const bool always_show = (cand.priority >= 5000.0f);
        bool overlaps = false;
        if (!always_show) {
            for (const GalaxyLabelCandidate& kept : batch.labels) {
                if ( std::abs(cand.screen_x_px - kept.screen_x_px) < 92.0f &&
                     std::abs(cand.screen_y_px - kept.screen_y_px) < 18.0f ) {
                    overlaps = true;
                    break;
                }
            }
        }
        if (!overlaps) {
            batch.labels.push_back(cand);
        }
    }

    return batch;
}

// ---------------------------------------------------------------------------
// Deterministic CPU Reference Rasterizer (RGBA8)
// ---------------------------------------------------------------------------

void rasterize_call_galaxy_rgba8_into(
    std::span<const GalaxyEdgeGpuInstance> edges,
    std::span<const GalaxyNodeGpuInstance> nodes,
    const CallGalaxyRasterConfig& config,
    std::vector<std::uint8_t>& out_rgba8) {
    const std::size_t total_px =
        static_cast<std::size_t>(config.width) * static_cast<std::size_t>(config.height);
    out_rgba8.resize(total_px * 4u);
    if (total_px == 0u) {
        return;
    }

    const auto clear_r = static_cast<std::uint8_t>(config.clear_rgba8 & 0xFFu);
    const auto clear_g = static_cast<std::uint8_t>((config.clear_rgba8 >> 8u) & 0xFFu);
    const auto clear_b = static_cast<std::uint8_t>((config.clear_rgba8 >> 16u) & 0xFFu);
    const auto clear_a = static_cast<std::uint8_t>((config.clear_rgba8 >> 24u) & 0xFFu);
    for (std::size_t i = 0u; i < total_px; ++i) {
        out_rgba8[i * 4u + 0u] = clear_r;
        out_rgba8[i * 4u + 1u] = clear_g;
        out_rgba8[i * 4u + 2u] = clear_b;
        out_rgba8[i * 4u + 3u] = clear_a;
    }

    const auto w_i = static_cast<int>(config.width);
    const auto h_i = static_cast<int>(config.height);

    // Pass 1: Anti-aliased oriented line segments with directional source->target color gradient.
    for (const GalaxyEdgeGpuInstance& e : edges) {
        const float dx = e.x1_px - e.x0_px;
        const float dy = e.y1_px - e.y0_px;
        const float len_sq = dx * dx + dy * dy;
        if (len_sq <= 0.04f) {
            continue;
        }
        const float len = std::sqrt(len_sq);
        const float width_px =
            static_cast<float>(e.width_q8_and_flags & 0xFFFFu) * (1.0f / 256.0f);
        const std::uint32_t edge_flags = (e.width_q8_and_flags >> 16u);
        const bool is_dashed = (edge_flags & kGalaxyEdgeFlagDashed) != 0u;
        const float half_w = std::max(0.45f, width_px * 0.5f);
        const float pad = half_w + 1.25f;

        const int min_x = std::max(0, static_cast<int>(std::floor(std::min(e.x0_px, e.x1_px) - pad)));
        const int max_x = std::min(w_i - 1, static_cast<int>(std::ceil(std::max(e.x0_px, e.x1_px) + pad)));
        const int min_y = std::max(0, static_cast<int>(std::floor(std::min(e.y0_px, e.y1_px) - pad)));
        const int max_y = std::min(h_i - 1, static_cast<int>(std::ceil(std::max(e.y0_px, e.y1_px) + pad)));
        if (min_x > max_x || min_y > max_y) {
            continue;
        }

        const float sr0 = static_cast<float>(e.color_src_rgba8 & 0xFFu);
        const float sg0 = static_cast<float>((e.color_src_rgba8 >> 8u) & 0xFFu);
        const float sb0 = static_cast<float>((e.color_src_rgba8 >> 16u) & 0xFFu);
        const float sa0 = static_cast<float>((e.color_src_rgba8 >> 24u) & 0xFFu) * (1.0f / 255.0f);

        const float dr1 = static_cast<float>(e.color_dst_rgba8 & 0xFFu);
        const float dg1 = static_cast<float>((e.color_dst_rgba8 >> 8u) & 0xFFu);
        const float db1 = static_cast<float>((e.color_dst_rgba8 >> 16u) & 0xFFu);
        const float da1 = static_cast<float>((e.color_dst_rgba8 >> 24u) & 0xFFu) * (1.0f / 255.0f);

        const float inv_len_sq = 1.0f / len_sq;

        for (int py = min_y; py <= max_y; ++py) {
            const float cy = static_cast<float>(py) + 0.5f;
            for (int px = min_x; px <= max_x; ++px) {
                const float cx = static_cast<float>(px) + 0.5f;
                const float vx = cx - e.x0_px;
                const float vy = cy - e.y0_px;
                const float t = std::clamp((vx * dx + vy * dy) * inv_len_sq, 0.0f, 1.0f);
                const float proj_x = e.x0_px + t * dx;
                const float proj_y = e.y0_px + t * dy;
                const float dist = std::hypot(cx - proj_x, cy - proj_y);

                // Directional taper: slightly wider near target to indicate call direction.
                const float local_half_w = half_w * (0.82f + 0.36f * t);
                const float cov = 1.0f - smoothstep01(local_half_w - 0.55f, local_half_w + 0.65f, dist);
                if (cov <= 0.0f) {
                    continue;
                }
                if (is_dashed) {
                    const float phase = std::fmod(t * len, 10.0f);
                    if (phase > 6.2f) {
                        continue;
                    }
                }

                const float cr = sr0 + (dr1 - sr0) * t;
                const float cg = sg0 + (dg1 - sg0) * t;
                const float cb = sb0 + (db1 - sb0) * t;
                const float ca = (sa0 + (da1 - sa0) * t) * cov;

                const std::size_t off =
                    (static_cast<std::size_t>(py) * static_cast<std::size_t>(config.width) +
                     static_cast<std::size_t>(px)) *
                    4u;
                blend_over_rgba8(out_rgba8.data() + off, cr, cg, cb, ca);
            }
        }
    }

    // Pass 2: Anti-aliased SDF discs with outer halos and crisp ring borders.
    const float ring_w = std::max(0.75f, config.node_ring_width_px);
    for (const GalaxyNodeGpuInstance& nd : nodes) {
        const float outer_r = nd.radius_px + std::max(0.0f, nd.halo_px) + 1.5f;
        const int min_x = std::max(0, static_cast<int>(std::floor(nd.cx_px - outer_r)));
        const int max_x = std::min(w_i - 1, static_cast<int>(std::ceil(nd.cx_px + outer_r)));
        const int min_y = std::max(0, static_cast<int>(std::floor(nd.cy_px - outer_r)));
        const int max_y = std::min(h_i - 1, static_cast<int>(std::ceil(nd.cy_px + outer_r)));
        if (min_x > max_x || min_y > max_y) {
            continue;
        }

        const float fr = static_cast<float>(nd.fill_rgba8 & 0xFFu);
        const float fg = static_cast<float>((nd.fill_rgba8 >> 8u) & 0xFFu);
        const float fb = static_cast<float>((nd.fill_rgba8 >> 16u) & 0xFFu);
        const float fa = static_cast<float>((nd.fill_rgba8 >> 24u) & 0xFFu) * (1.0f / 255.0f);

        const float rr = static_cast<float>(nd.ring_rgba8 & 0xFFu);
        const float rg = static_cast<float>((nd.ring_rgba8 >> 8u) & 0xFFu);
        const float rb = static_cast<float>((nd.ring_rgba8 >> 16u) & 0xFFu);
        const float ra = static_cast<float>((nd.ring_rgba8 >> 24u) & 0xFFu) * (1.0f / 255.0f);

        const float eff_ring_w =
            ((nd.flags & (kGalaxyNodeFlagSelected | kGalaxyNodeFlagHovered)) != 0u)
                ? (ring_w + 0.85f)
                : ring_w;

        for (int py = min_y; py <= max_y; ++py) {
            const float cy = static_cast<float>(py) + 0.5f;
            for (int px = min_x; px <= max_x; ++px) {
                const float cx = static_cast<float>(px) + 0.5f;
                const float dist = std::hypot(cx - nd.cx_px, cy - nd.cy_px);
                const float sdf = dist - nd.radius_px;

                const std::size_t off =
                    (static_cast<std::size_t>(py) * static_cast<std::size_t>(config.width) +
                     static_cast<std::size_t>(px)) *
                    4u;

                if (nd.halo_px > 0.25f && sdf > -0.5f && sdf < nd.halo_px) {
                    const float ht = 1.0f - std::clamp(sdf / nd.halo_px, 0.0f, 1.0f);
                    const float halo_a = ra * 0.36f * ht * ht;
                    blend_over_rgba8(out_rgba8.data() + off, rr, rg, rb, halo_a);
                }

                const float disc_cov = 1.0f - smoothstep01(-0.55f, 0.55f, sdf);
                if (disc_cov > 0.0f) {
                    const float ring_mix = smoothstep01(-eff_ring_w - 0.45f, -eff_ring_w + 0.45f, sdf);
                    const float cr = fr + (rr - fr) * ring_mix;
                    const float cg = fg + (rg - fg) * ring_mix;
                    const float cb = fb + (rb - fb) * ring_mix;
                    const float ca = (fa + (ra - fa) * ring_mix) * disc_cov;
                    blend_over_rgba8(out_rgba8.data() + off, cr, cg, cb, ca);
                }
            }
        }
    }
}

std::vector<std::uint8_t> rasterize_call_galaxy_rgba8(
    std::span<const GalaxyEdgeGpuInstance> edges,
    std::span<const GalaxyNodeGpuInstance> nodes,
    const CallGalaxyRasterConfig& config) {
    std::vector<std::uint8_t> out{};
    rasterize_call_galaxy_rgba8_into(edges, nodes, config, out);
    return out;
}

} // namespace viewer
