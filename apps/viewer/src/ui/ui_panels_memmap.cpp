#include "panel_helpers.hpp"
#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {
namespace {

enum class CategoryBucket : int {
    Image = 0,
    Heap = 1,
    Stack = 2,
    MappedFile = 3,
    Anonymous = 4,
    Vdso = 5,
    Reserved = 6,
};

enum class FootprintBucket : int {
    PrivateDirty = 0,
    PrivateClean = 1,
    SharedDirty = 2,
    SharedClean = 3,
    Swapped = 4,
    UnresidentCommitted = 5,
};

enum class ProtectionBucket : int {
    Rx = 0,
    ReadOnly = 1,
    Rw = 2,
    Rwx = 3,
    NoAccessOrGuard = 4,
};

[[nodiscard]] bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    const auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

[[nodiscard]] ImVec4 protection_color(const peelf::MemoryProtection& p) noexcept {
    if (p.executable && p.writable) {
        return ImVec4(1.0f, 0.38f, 0.30f, 1.0f);  // RWX: high-attention coral
    }
    if (p.executable) {
        return ImVec4(0.45f, 0.85f, 1.0f, 1.0f);  // RX: code cyan
    }
    if (p.writable) {
        return ImVec4(0.50f, 0.92f, 0.58f, 1.0f);  // RW: data green
    }
    if (p.readable && !p.guarded) {
        return ImVec4(0.82f, 0.84f, 0.90f, 1.0f);  // R--: rodata light gray
    }
    return ImVec4(0.45f, 0.45f, 0.48f, 1.0f);      // ---: guard/reserved dim
}

[[nodiscard]] ImU32 category_color_u32(CategoryBucket cat) noexcept {
    switch (cat) {
        case CategoryBucket::Image:      return IM_COL32(82, 168, 242, 255);  // azure
        case CategoryBucket::Heap:       return IM_COL32(236, 164, 68, 255);  // warm amber
        case CategoryBucket::Stack:      return IM_COL32(172, 118, 238, 255); // violet
        case CategoryBucket::MappedFile: return IM_COL32(78, 196, 164, 255);  // teal
        case CategoryBucket::Anonymous:  return IM_COL32(114, 198, 118, 255); // green
        case CategoryBucket::Vdso:       return IM_COL32(224, 206, 88, 255);  // gold
        case CategoryBucket::Reserved:   return IM_COL32(88, 92, 104, 255);   // slate
    }
    return IM_COL32(120, 120, 120, 255);
}

[[nodiscard]] CategoryBucket classify_region_category(const peelf::MemoryRegion& reg) noexcept {
    if (reg.usage.is_reserved_only) {
        return CategoryBucket::Reserved;
    }
    switch (reg.kind) {
        case peelf::MemoryRegionKind::Image:      return CategoryBucket::Image;
        case peelf::MemoryRegionKind::Heap:       return CategoryBucket::Heap;
        case peelf::MemoryRegionKind::Stack:      return CategoryBucket::Stack;
        case peelf::MemoryRegionKind::MappedFile: return CategoryBucket::MappedFile;
        case peelf::MemoryRegionKind::Vdso:       return CategoryBucket::Vdso;
        case peelf::MemoryRegionKind::Anonymous:
        case peelf::MemoryRegionKind::Unknown:    return CategoryBucket::Anonymous;
    }
    return CategoryBucket::Anonymous;
}

[[nodiscard]] ProtectionBucket classify_region_protection(const peelf::MemoryRegion& reg) noexcept {
    const auto& p = reg.protection;
    if (p.guarded || (!p.readable && !p.writable && !p.executable)) {
        return ProtectionBucket::NoAccessOrGuard;
    }
    if (p.readable && p.writable && p.executable) {
        return ProtectionBucket::Rwx;
    }
    if (p.executable) {
        return p.writable ? ProtectionBucket::Rwx : ProtectionBucket::Rx;
    }
    if (p.writable) {
        return ProtectionBucket::Rw;
    }
    return ProtectionBucket::ReadOnly;
}

[[nodiscard]] bool region_matches_footprint(const peelf::MemoryRegion& reg,
                                            FootprintBucket bucket) noexcept {
    const auto& u = reg.usage;
    switch (bucket) {
        case FootprintBucket::PrivateDirty:
            return u.private_dirty_bytes.value_or(0) > 0;
        case FootprintBucket::PrivateClean:
            return u.private_clean_bytes.value_or(0) > 0;
        case FootprintBucket::SharedDirty:
            return u.shared_dirty_bytes.value_or(0) > 0;
        case FootprintBucket::SharedClean:
            return u.shared_clean_bytes.value_or(0) > 0;
        case FootprintBucket::Swapped:
            return u.swap_bytes.value_or(0) > 0;
        case FootprintBucket::UnresidentCommitted: {
            if (u.is_reserved_only) {
                return false;
            }
            const std::uint64_t comm = u.committed_bytes.value_or(reg.size());
            return comm > u.rss_bytes.value_or(0);
        }
    }
    return true;
}

[[nodiscard]] std::string format_bytes_human(std::uint64_t bytes) {
    std::array<char, 48> buf{};
    constexpr double kKiB = 1024.0;
    constexpr double kMiB = 1024.0 * 1024.0;
    constexpr double kGiB = 1024.0 * 1024.0 * 1024.0;
    constexpr double kTiB = 1024.0 * 1024.0 * 1024.0 * 1024.0;
    const auto d = static_cast<double>(bytes);
    if (d >= kTiB) {
        std::snprintf(buf.data(), buf.size(), "%.2f TiB", d / kTiB);
    } else if (d >= kGiB) {
        std::snprintf(buf.data(), buf.size(), "%.2f GiB", d / kGiB);
    } else if (d >= kMiB) {
        std::snprintf(buf.data(), buf.size(), "%.2f MiB", d / kMiB);
    } else if (d >= kKiB) {
        std::snprintf(buf.data(), buf.size(), "%.1f KiB", d / kKiB);
    } else {
        std::snprintf(buf.data(), buf.size(), "%" PRIu64 " B", bytes);
    }
    return buf.data();
}

[[nodiscard]] std::string format_size_short(std::uint64_t bytes) {
    std::array<char, 32> buf{};
    constexpr std::uint64_t kKiB = 1024u;
    constexpr std::uint64_t kMiB = 1024u * 1024u;
    constexpr std::uint64_t kGiB = 1024u * 1024u * 1024u;
    if (bytes >= kGiB && (bytes % kMiB) == 0) {
        std::snprintf(buf.data(), buf.size(), "%.1f GiB", static_cast<double>(bytes) / static_cast<double>(kGiB));
    } else if (bytes >= kMiB && (bytes % kMiB) == 0) {
        std::snprintf(buf.data(), buf.size(), "%" PRIu64 " MiB", bytes / kMiB);
    } else if (bytes >= kKiB && (bytes % kKiB) == 0) {
        std::snprintf(buf.data(), buf.size(), "%" PRIu64 " KiB", bytes / kKiB);
    } else {
        std::snprintf(buf.data(), buf.size(), "0x%" PRIX64, bytes);
    }
    return buf.data();
}

[[nodiscard]] std::string format_opt_bytes(const std::optional<std::uint64_t>& v) {
    if (!v.has_value()) {
        return "-";
    }
    if (*v == 0) {
        return "0 B";
    }
    return format_bytes_human(*v);
}

[[nodiscard]] std::string format_attribution_badge(const peelf::MemoryRegion& reg) {
    std::array<char, 64> buf{};
    if (reg.usage.owner_tid.has_value()) {
        std::snprintf(buf.data(),
                      buf.size(),
                      "TID %" PRIu64 "%s",
                      static_cast<std::uint64_t>(*reg.usage.owner_tid),
                      reg.usage.is_reserved_only ? " (guard)" : "");
        return buf.data();
    }
    if (reg.usage.heap_id.has_value()) {
        std::snprintf(buf.data(), buf.size(), "Heap #%u", *reg.usage.heap_id);
        return buf.data();
    }
    if (reg.usage.is_reserved_only) {
        return "Reserved";
    }
    return {};
}

struct StackedSlice {
    const char* label{""};
    std::uint64_t bytes{0};
    ImU32 color{0};
    int filter_id{0};
};

void draw_stacked_bar_row(const char* row_id,
                          const char* title,
                          std::span<const StackedSlice> slices,
                          int& active_filter) {
    std::uint64_t total = 0;
    for (const auto& s : slices) {
        total += s.bytes;
    }

    ImGui::PushID(row_id);
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("%-11s", title);
    ImGui::SameLine(96.0f);

    const float avail_w = std::max(80.0f, ImGui::GetContentRegionAvail().x);
    const float bar_h = 15.0f;
    const ImVec2 p0 = ImGui::GetCursorScreenPos();
    const ImVec2 p1(p0.x + avail_w, p0.y + bar_h);
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(p0, p1, IM_COL32(28, 31, 38, 255), 3.0f);

    ImGui::InvisibleButton("##bar", ImVec2(avail_w, bar_h));
    const bool hovered = ImGui::IsItemHovered();
    const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    const float mouse_x = ImGui::GetIO().MousePos.x;

    if (total > 0) {
        float x = p0.x;
        for (std::size_t i = 0; i < slices.size(); ++i) {
            const auto& sl = slices[i];
            if (sl.bytes == 0) {
                continue;
            }
            const float ratio =
                static_cast<float>(static_cast<double>(sl.bytes) / static_cast<double>(total));
            const float w = std::max(2.0f, avail_w * ratio);
            const float x_end = std::min(p1.x, x + w);
            const ImVec2 s0(x, p0.y);
            const ImVec2 s1(x_end, p1.y);

            dl->AddRectFilled(s0, s1, sl.color);
            if (active_filter == sl.filter_id) {
                dl->AddRect(s0, s1, IM_COL32(255, 255, 255, 240), 0.0f, 0, 2.0f);
            }

            if (hovered && mouse_x >= s0.x && mouse_x < s1.x) {
                dl->AddRect(s0, s1, IM_COL32(255, 245, 190, 255), 0.0f, 0, 1.5f);
                ImGui::BeginTooltip();
                ImGui::Text("%s: %s (%.1f%%)",
                            sl.label,
                            format_bytes_human(sl.bytes).c_str(),
                            static_cast<double>(ratio) * 100.0);
                ImGui::TextDisabled("Click to %s table filter",
                                    active_filter == sl.filter_id ? "clear" : "apply");
                ImGui::EndTooltip();
                if (clicked) {
                    active_filter = (active_filter == sl.filter_id) ? -1 : sl.filter_id;
                }
            }

            x = x_end;
            if (x >= p1.x) {
                break;
            }
        }
    }
    dl->AddRect(p0, p1, IM_COL32(70, 76, 92, 220), 3.0f);
    ImGui::PopID();
}

} // namespace

MemoryMapPanel::MemoryMapPanel(BinaryModel& model, ViewerSelection& selection)
    : UiPanel("Memory Map")
    , model_(model)
    , selection_(selection)
{
    filter_buf_[0] = '\0';
}

void MemoryMapPanel::draw_contents() {
    if (!model_.is_live_process()) {
        ImGui::TextDisabled("Not attached to a running process.");
        ImGui::Spacing();
        ImGui::TextWrapped("Attach to a running process (strictly read-only) to explore its virtual memory map, VMMap physical RSS/PSS footprint, canonical VA heat strip, symbols, disassembly & decompilation, thread stacks & TLS, heaps, and PEB/TEB/auxv.");
        ImGui::Spacing();
        if (on_attach_requested_ && ImGui::Button("Attach to Process...")) {
            on_attach_requested_();
        }
        return;
    }

    const peelf::IProcessSession* sess = model_.process_session();
    const auto& regions = model_.memory_regions();
    const auto& modules = model_.process_modules();
    const auto& summary_fv = model_.memory_summary();
    const peelf::ProcessMemorySummary summary =
        summary_fv.value.has_value() ? *summary_fv.value : peelf::summarize_process_memory(regions);

    if (sess != nullptr) {
        if (const peelf::CrashDumpSummary* dump = model_.crash_dump_summary(); dump != nullptr) {
            ImGui::TextColored(ImVec4(1.0f, 0.48f, 0.34f, 1.0f),
                               "[CRASH DUMP] PID %" PRIu64 ": %s (%s, Offline Read-Only)",
                               static_cast<std::uint64_t>(sess->pid()),
                               sess->info().name.empty() ? "<dump>" : sess->info().name.c_str(),
                               std::string(peelf::to_string(sess->info().architecture)).c_str());
            if (dump->exception.has_value()) {
                ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.28f, 1.0f),
                                   "Fault Summary: %s",
                                   dump->exception->description.c_str());
            }
        } else {
            const bool alive = sess->is_alive();
            const bool paused = model_.is_process_suspended();
            ImGui::TextColored(!alive ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f)
                                      : (paused ? ImVec4(1.0f, 0.78f, 0.25f, 1.0f)
                                                : ImVec4(0.35f, 0.90f, 0.55f, 1.0f)),
                               "%s PID %" PRIu64 ": %s (%s, Read-Only)",
                               !alive ? "[EXITED]" : (paused ? "[PAUSED]" : "[LIVE]"),
                               static_cast<std::uint64_t>(sess->pid()),
                               sess->info().name.empty() ? "<process>" : sess->info().name.c_str(),
                               std::string(peelf::to_string(sess->info().architecture)).c_str());
        }
    }

    if (!model_.is_crash_dump()) {
        if (ImGui::SmallButton(model_.is_process_suspended() ? "Resume" : "Pause")) {
            if (on_pause_toggle_) {
                on_pause_toggle_();
            }
        }
        ImGui::SameLine();
    }
    if (ImGui::SmallButton("Refresh")) {
        if (on_refresh_requested_) {
            on_refresh_requested_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Attach Other...")) {
        if (on_attach_requested_) {
            on_attach_requested_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(model_.is_crash_dump() ? "Close Dump" : "Detach")) {
        if (on_detach_requested_) {
            on_detach_requested_();
        }
        return;
    }
    if (summary.rwx_region_count > 0) {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.75f, 0.20f, 0.16f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.90f, 0.28f, 0.22f, 1.0f));
        std::array<char, 64> rwx_btn{};
        std::snprintf(rwx_btn.data(),
                      rwx_btn.size(),
                      "! RWX: %zu (%s)",
                      summary.rwx_region_count,
                      format_bytes_human(summary.rwx_bytes).c_str());
        if (ImGui::SmallButton(rwx_btn.data())) {
            const int target = static_cast<int>(ProtectionBucket::Rwx);
            protection_filter_ = (protection_filter_ == target) ? -1 : target;
        }
        ImGui::PopStyleColor(2);
    }

    // Summary KPI strip
    ImGui::Separator();
    ImGui::Text("Virtual: %s", format_bytes_human(summary.total_virtual_bytes).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("Committed: %s", format_bytes_human(summary.committed_bytes).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("RSS/WS: %s", format_opt_bytes(summary.rss_bytes).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("PSS: %s", format_opt_bytes(summary.pss_bytes).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("Priv Dirty: %s", format_opt_bytes(summary.private_dirty_bytes).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("Shared: %s", format_opt_bytes(summary.shared_bytes()).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("Swap: %s", format_opt_bytes(summary.swap_bytes).c_str());

    if (summary_fv.status.availability == peelf::Availability::Partial &&
        !summary_fv.status.detail.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.35f, 1.0f),
                           "Telemetry: %s",
                           summary_fv.status.detail.c_str());
    }

    // Collapsible VMMap Stacked Bars + Compressed VA Space Heat Strip
    if (ImGui::CollapsingHeader("VMMap Breakdown & Virtual Address Strip",
                                ImGuiTreeNodeFlags_DefaultOpen)) {
        const std::array<StackedSlice, 7> cat_slices{{
            {"Image", summary.image_bytes, category_color_u32(CategoryBucket::Image), 0},
            {"Heap", summary.heap_bytes, category_color_u32(CategoryBucket::Heap), 1},
            {"Stack", summary.stack_bytes, category_color_u32(CategoryBucket::Stack), 2},
            {"Mapped File", summary.mapped_file_bytes, category_color_u32(CategoryBucket::MappedFile), 3},
            {"Anonymous", summary.anonymous_bytes, category_color_u32(CategoryBucket::Anonymous), 4},
            {"vDSO/Kernel", summary.vdso_bytes, category_color_u32(CategoryBucket::Vdso), 5},
            {"Reserved", summary.reserved_bytes, category_color_u32(CategoryBucket::Reserved), 6},
        }};
        draw_stacked_bar_row("CatBar", "Category", cat_slices, category_filter_);

        const std::array<StackedSlice, 6> phys_slices{{
            {"Private Dirty", summary.private_dirty_bytes.value_or(0), IM_COL32(236, 106, 86, 255), 0},
            {"Private Clean", summary.private_clean_bytes.value_or(0), IM_COL32(236, 178, 86, 255), 1},
            {"Shared Dirty", summary.shared_dirty_bytes.value_or(0), IM_COL32(96, 178, 240, 255), 2},
            {"Shared Clean", summary.shared_clean_bytes.value_or(0), IM_COL32(84, 206, 176, 255), 3},
            {"Swapped", summary.swap_bytes.value_or(0), IM_COL32(182, 112, 232, 255), 4},
            {"Unresident Committed", summary.unresident_committed_bytes(), IM_COL32(72, 78, 92, 255), 5},
        }};
        draw_stacked_bar_row("PhysBar", "Physical", phys_slices, footprint_filter_);

        const std::array<StackedSlice, 5> prot_slices{{
            {"RX (Code)", summary.rx_bytes, IM_COL32(95, 205, 248, 255), 0},
            {"R-- (Read-Only)", summary.readonly_bytes, IM_COL32(190, 198, 214, 255), 1},
            {"RW- (Read-Write)", summary.rw_bytes, IM_COL32(114, 222, 138, 255), 2},
            {"RWX (Alert)", summary.rwx_bytes, IM_COL32(255, 88, 72, 255), 3},
            {"NoAccess/Guard", summary.noaccess_or_guard_bytes, IM_COL32(84, 86, 96, 255), 4},
        }};
        draw_stacked_bar_row("ProtBar", "Protection", prot_slices, protection_filter_);

        // Interactive Compressed Virtual Address Space Fragmentation / Heat Strip
        const auto& clusters = model_.address_space_clusters();
        if (!clusters.empty()) {
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%-11s", "VA Strip");
            ImGui::SameLine(96.0f);

            const float strip_w = std::max(80.0f, ImGui::GetContentRegionAvail().x);
            const float strip_h = 20.0f;
            const ImVec2 sp0 = ImGui::GetCursorScreenPos();
            const ImVec2 sp1(sp0.x + strip_w, sp0.y + strip_h);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(sp0, sp1, IM_COL32(22, 24, 30, 255), 3.0f);

            ImGui::InvisibleButton("##va_strip", ImVec2(strip_w, strip_h));
            const bool strip_hovered = ImGui::IsItemHovered();
            const bool strip_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
            const float mx = ImGui::GetIO().MousePos.x;

            const std::size_t num_gaps = clusters.size() > 1 ? (clusters.size() - 1) : 0;
            const float gap_px = num_gaps > 0 ? std::min(10.0f, (strip_w * 0.25f) / static_cast<float>(num_gaps)) : 0.0f;
            const float usable_w = std::max(10.0f, strip_w - gap_px * static_cast<float>(num_gaps));

            double total_weight = 0.0;
            std::vector<double> weights(clusters.size(), 1.0);
            for (std::size_t ci = 0; ci < clusters.size(); ++ci) {
                // Log-damped span weight so compact clusters ([stack], [vdso]) stay clickable next to multi-MiB heaps.
                const double span_kb =
                    std::max(4.0, static_cast<double>(clusters[ci].span_bytes()) / 1024.0);
                weights[ci] = std::log2(span_kb) + static_cast<double>(clusters[ci].region_indices.size()) * 0.35;
                total_weight += weights[ci];
            }

            const std::optional<std::size_t> active_reg_idx = model_.active_region_index();
            float cx = sp0.x;
            bool tooltip_shown = false;

            for (std::size_t ci = 0; ci < clusters.size(); ++ci) {
                const auto& cl = clusters[ci];
                if (ci > 0 && gap_px > 0.5f) {
                    const ImVec2 g0(cx, sp0.y);
                    const ImVec2 g1(cx + gap_px, sp1.y);
                    dl->AddRectFilled(g0, g1, IM_COL32(14, 15, 19, 255));
                    dl->AddLine(ImVec2(g0.x + gap_px * 0.5f, g0.y + 2.0f),
                                ImVec2(g0.x + gap_px * 0.5f, g1.y - 2.0f),
                                IM_COL32(95, 100, 118, 160),
                                1.0f);
                    if (strip_hovered && !tooltip_shown && mx >= g0.x && mx < g1.x) {
                        tooltip_shown = true;
                        ImGui::BeginTooltip();
                        ImGui::Text("Collapsed Canonical / Unmapped Hole");
                        ImGui::TextDisabled("Gap size: %s (0x%" PRIX64 " .. 0x%" PRIX64 ")",
                                            format_bytes_human(cl.preceding_gap_bytes).c_str(),
                                            clusters[ci - 1].end_address,
                                            cl.start_address);
                        ImGui::EndTooltip();
                    }
                    cx += gap_px;
                }

                const float cw =
                    static_cast<float>((weights[ci] / std::max(1.0, total_weight)) * static_cast<double>(usable_w));
                const std::uint64_t cl_span = std::max<std::uint64_t>(1u, cl.span_bytes());

                for (const std::size_t r_idx : cl.region_indices) {
                    if (r_idx >= regions.size()) {
                        continue;
                    }
                    const peelf::MemoryRegion& reg = regions[r_idx];
                    const float rel0 = static_cast<float>(
                        static_cast<double>(reg.start_address - cl.start_address) /
                        static_cast<double>(cl_span));
                    const float rel1 = static_cast<float>(
                        static_cast<double>(reg.end_address - cl.start_address) /
                        static_cast<double>(cl_span));
                    const float rx0 = cx + rel0 * cw;
                    const float rx1 = std::max(rx0 + 2.0f, std::min(cx + cw, cx + rel1 * cw));

                    const ImU32 fill =
                        (reg.protection.executable && reg.protection.writable)
                            ? IM_COL32(255, 82, 68, 255)
                            : category_color_u32(classify_region_category(reg));
                    dl->AddRectFilled(ImVec2(rx0, sp0.y + 1.0f), ImVec2(rx1, sp1.y - 1.0f), fill);

                    const bool is_sel =
                        (active_reg_idx && *active_reg_idx == r_idx) ||
                        (selection_.kind == SelectionKind::MemoryRegion &&
                         selection_.object_index == static_cast<std::uint64_t>(r_idx));
                    if (is_sel) {
                        dl->AddRect(ImVec2(rx0, sp0.y),
                                    ImVec2(rx1, sp1.y),
                                    IM_COL32(255, 232, 110, 255),
                                    0.0f,
                                    0,
                                    2.0f);
                    }

                    if (strip_hovered && !tooltip_shown && mx >= rx0 && mx < rx1) {
                        tooltip_shown = true;
                        ImGui::BeginTooltip();
                        ImGui::Text("0x%016" PRIX64 " - 0x%016" PRIX64 " (%s)",
                                    reg.start_address,
                                    reg.end_address,
                                    format_bytes_human(reg.size()).c_str());
                        const std::string_view kstr = peelf::to_string(reg.kind);
                        ImGui::Text("Perms: %s | Kind: %.*s | RSS: %s | PSS: %s",
                                    peelf::format_protection(reg.protection).c_str(),
                                    static_cast<int>(kstr.size()),
                                    kstr.data(),
                                    format_opt_bytes(reg.usage.rss_bytes).c_str(),
                                    format_opt_bytes(reg.usage.pss_bytes).c_str());
                        const std::string attr = format_attribution_badge(reg);
                        if (!attr.empty()) {
                            ImGui::Text("Attribution: %s", attr.c_str());
                        }
                        const std::string safe_strip_path =
                            sanitize_single_line_control_chars(reg.pathname);
                        ImGui::TextDisabled("%s",
                                            safe_strip_path.empty() ? "<anonymous>" : safe_strip_path.c_str());
                        ImGui::EndTooltip();
                        if (strip_clicked && on_region_activated_) {
                            on_region_activated_(r_idx, true);
                        }
                    }
                }
                cx += cw;
            }
            dl->AddRect(sp0, sp1, IM_COL32(70, 76, 92, 220), 3.0f);
        }

        if (category_filter_ >= 0 || footprint_filter_ >= 0 || protection_filter_ >= 0) {
            if (ImGui::SmallButton("Clear Chart Filters")) {
                category_filter_ = -1;
                footprint_filter_ = -1;
                protection_filter_ = -1;
            }
        }
    }

    // Active Module selector combo
    if (!modules.empty()) {
        const std::optional<std::size_t> active_mod = model_.active_module_index();
        std::string preview = "<Standalone Memory Region>";
        if (active_mod && *active_mod < modules.size()) {
            const auto& m = modules[*active_mod];
            const std::string mod_display = sanitize_single_line_control_chars(
                m.name.empty() ? m.path.string() : m.name);
            std::array<char, 256> pbuf{};
            std::snprintf(pbuf.data(),
                          pbuf.size(),
                          "%s @ 0x%" PRIX64 " (%s)",
                          mod_display.c_str(),
                          m.base_address,
                          format_size_short(m.size).c_str());
            preview = pbuf.data();
        }

        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::BeginCombo("##ActiveModuleCombo", preview.c_str())) {
            for (std::size_t i = 0; i < modules.size(); ++i) {
                const auto& m = modules[i];
                const std::string mod_display = sanitize_single_line_control_chars(
                    m.name.empty() ? m.path.string() : m.name);
                std::array<char, 320> item_label{};
                std::snprintf(item_label.data(),
                              item_label.size(),
                              "%s%s @ 0x%" PRIX64 " (%s)##mod%zu",
                              m.is_main_module ? "[main] " : "",
                              mod_display.c_str(),
                              m.base_address,
                              format_size_short(m.size).c_str(),
                              i);
                const bool is_sel = active_mod && *active_mod == i;
                if (ImGui::Selectable(item_label.data(), is_sel)) {
                    if (on_module_selected_) {
                        on_module_selected_(i);
                    }
                }
                if (is_sel) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
    }

    ImGui::InputTextWithHint(
        "Filter", "Address, module, [heap], [stack], TID...", filter_buf_, sizeof(filter_buf_));
    ImGui::Checkbox("Exec", &filter_exec_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Write", &filter_writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Modules", &filter_modules_only_);
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu regions, %zu modules)", regions.size(), modules.size());

    if (!model_.last_diagnostic().empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.72f, 0.30f, 1.0f),
                           "Note: %s",
                           model_.last_diagnostic().c_str());
    }

    ImGui::Separator();

    const std::string_view filter(filter_buf_);
    const std::optional<std::size_t> active_region = model_.active_region_index();

    std::vector<std::size_t> visible;
    visible.reserve(regions.size());
    for (std::size_t i = 0; i < regions.size(); ++i) {
        const peelf::MemoryRegion& reg = regions[i];
        if (filter_exec_only_ && !reg.protection.executable) {
            continue;
        }
        if (filter_writable_only_ && !reg.protection.writable) {
            continue;
        }
        if (filter_modules_only_ &&
            reg.kind != peelf::MemoryRegionKind::Image &&
            reg.kind != peelf::MemoryRegionKind::Vdso) {
            continue;
        }
        if (category_filter_ >= 0 &&
            static_cast<int>(classify_region_category(reg)) != category_filter_) {
            continue;
        }
        if (footprint_filter_ >= 0 &&
            !region_matches_footprint(reg, static_cast<FootprintBucket>(footprint_filter_))) {
            continue;
        }
        if (protection_filter_ >= 0 &&
            static_cast<int>(classify_region_protection(reg)) != protection_filter_) {
            continue;
        }

        if (!filter.empty()) {
            std::array<char, 40> start_hex{};
            std::snprintf(start_hex.data(), start_hex.size(), "0x%016" PRIX64, reg.start_address);
            const std::string_view kind_str = peelf::to_string(reg.kind);
            const std::string attr = format_attribution_badge(reg);
            if (!icontains(start_hex.data(), filter) &&
                !icontains(reg.pathname, filter) &&
                !icontains(kind_str, filter) &&
                !icontains(attr, filter)) {
                continue;
            }
        }
        visible.push_back(i);
    }

    enum MemColId : ImGuiID {
        kColStart = 1,
        kColEnd,
        kColSize,
        kColRss,
        kColPss,
        kColPriv,
        kColSwap,
        kColPerms,
        kColKind,
        kColOwner,
        kColFileOff,
        kColPath,
    };

    std::optional<PendingEntityContextAction> pending_ctx_action;
    if (ImGui::BeginTable("MemMapTable",
                          12,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_Sortable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Start VA", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 124.0f, kColStart);
        ImGui::TableSetupColumn("End VA", ImGuiTableColumnFlags_WidthFixed, 124.0f, kColEnd);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 72.0f, kColSize);
        ImGui::TableSetupColumn("RSS / WS", ImGuiTableColumnFlags_WidthFixed, 74.0f, kColRss);
        ImGui::TableSetupColumn("PSS", ImGuiTableColumnFlags_WidthFixed, 70.0f, kColPss);
        ImGui::TableSetupColumn("Private", ImGuiTableColumnFlags_WidthFixed, 72.0f, kColPriv);
        ImGui::TableSetupColumn("Swap", ImGuiTableColumnFlags_WidthFixed, 64.0f, kColSwap);
        ImGui::TableSetupColumn("Perms", ImGuiTableColumnFlags_WidthFixed, 50.0f, kColPerms);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 72.0f, kColKind);
        ImGui::TableSetupColumn("Thread / Heap", ImGuiTableColumnFlags_WidthFixed, 88.0f, kColOwner);
        ImGui::TableSetupColumn("File Off", ImGuiTableColumnFlags_WidthFixed, 68.0f, kColFileOff);
        ImGui::TableSetupColumn("Module / Mapping", ImGuiTableColumnFlags_WidthStretch, 0.0f, kColPath);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs();
            sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& sp = sort_specs->Specs[0];
            const bool asc = (sp.SortDirection != ImGuiSortDirection_Descending);
            std::ranges::stable_sort(visible, [&](std::size_t a, std::size_t b) {
                const auto& ra = regions[a];
                const auto& rb = regions[b];
                auto cmp = [&](auto va, auto vb) { return asc ? (va < vb) : (va > vb); };
                switch (sp.ColumnUserID) {
                    case kColStart:   return cmp(ra.start_address, rb.start_address);
                    case kColEnd:     return cmp(ra.end_address, rb.end_address);
                    case kColSize:    return cmp(ra.size(), rb.size());
                    case kColRss:     return cmp(ra.usage.rss_bytes.value_or(0), rb.usage.rss_bytes.value_or(0));
                    case kColPss:     return cmp(ra.usage.pss_bytes.value_or(0), rb.usage.pss_bytes.value_or(0));
                    case kColPriv:    return cmp(ra.usage.private_bytes().value_or(0), rb.usage.private_bytes().value_or(0));
                    case kColSwap:    return cmp(ra.usage.swap_bytes.value_or(0), rb.usage.swap_bytes.value_or(0));
                    case kColPerms:   return cmp(peelf::format_protection(ra.protection),
                                                 peelf::format_protection(rb.protection));
                    case kColKind:    return cmp(peelf::to_string(ra.kind), peelf::to_string(rb.kind));
                    case kColOwner:   return cmp(ra.usage.owner_tid.value_or(0), rb.usage.owner_tid.value_or(0));
                    case kColFileOff: {
                        const bool a_has = (ra.file_offset != 0 || !ra.pathname.empty());
                        const bool b_has = (rb.file_offset != 0 || !rb.pathname.empty());
                        if (a_has != b_has) {
                            return a_has;
                        }
                        return cmp(ra.file_offset, rb.file_offset);
                    }
                    case kColPath:    return cmp(sanitize_single_line_control_chars(ra.pathname),
                                                 sanitize_single_line_control_chars(rb.pathname));
                    default:          return cmp(ra.start_address, rb.start_address);
                }
            });
        }

        ImGuiListClipper clipper;
        clipper.Begin(clamp_imgui_clipper_count(visible.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const std::size_t i = visible[static_cast<std::size_t>(row)];
                const peelf::MemoryRegion& reg = regions[i];
                const std::string safe_pathname = sanitize_single_line_control_chars(reg.pathname);

                std::array<char, 40> start_hex{};
                std::snprintf(start_hex.data(), start_hex.size(), "0x%016" PRIX64, reg.start_address);
                const std::string_view kind_str = peelf::to_string(reg.kind);
                const bool is_selected =
                    (active_region && *active_region == i) ||
                    (selection_.kind == SelectionKind::MemoryRegion &&
                     selection_.object_index == static_cast<std::uint64_t>(i));

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(i));
                if (ImGui::Selectable(start_hex.data(),
                                      is_selected,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (on_region_activated_) {
                        on_region_activated_(i, true);
                    }
                }
                if (ImGui::BeginPopupContextItem("MemMapRowCtx")) {
                    if (ImGui::MenuItem("Inspect (with Module Symbols if applicable)")) {
                        if (on_region_activated_) {
                            on_region_activated_(i, true);
                        }
                    }
                    if (ImGui::MenuItem("Inspect Standalone Region Window Only")) {
                        if (on_region_activated_) {
                            on_region_activated_(i, false);
                        }
                    }
                    ImGui::Separator();
                    const bool has_backing_file =
                        !safe_pathname.empty() && safe_pathname.front() != '[';
                    const InspectableEntity reg_entity{
                        .va = reg.start_address,
                        .file_offset = has_backing_file
                            ? std::optional<std::uint64_t>(reg.file_offset)
                            : std::nullopt,
                        .size = reg.size(),
                        .symbol_or_label = !safe_pathname.empty()
                            ? safe_pathname
                            : std::string("<anonymous>"),
                        .module_name = has_backing_file ? safe_pathname : std::string{},
                        .extra_json_fields = {
                            {"end_va", std::format("0x{:X}", reg.end_address)},
                            {"permissions", peelf::format_protection(reg.protection)},
                            {"region_kind", std::string(kind_str)},
                        },
                    };
                    (void)draw_inspectable_entity_context_menu_items(
                        reg_entity, model_, pending_ctx_action);
                    ImGui::EndPopup();
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::Text("0x%016" PRIX64, reg.end_address);

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_size_short(reg.size()).c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_opt_bytes(reg.usage.rss_bytes).c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_opt_bytes(reg.usage.pss_bytes).c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_opt_bytes(reg.usage.private_bytes()).c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_opt_bytes(reg.usage.swap_bytes).c_str());

                ImGui::TableNextColumn();
                const std::string perms = peelf::format_protection(reg.protection);
                ImGui::TextColored(protection_color(reg.protection), "%s", perms.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(kind_str.data(), kind_str.data() + kind_str.size());

                ImGui::TableNextColumn();
                const std::string attr = format_attribution_badge(reg);
                if (!attr.empty()) {
                    ImGui::TextUnformatted(attr.c_str());
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                if (reg.file_offset != 0 || !reg.pathname.empty()) {
                    ImGui::Text("0x%" PRIX64, reg.file_offset);
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                if (!safe_pathname.empty()) {
                    ImGui::TextUnformatted(safe_pathname.c_str());
                } else if (reg.usage.is_reserved_only) {
                    ImGui::TextDisabled("<reserved>");
                } else {
                    ImGui::TextDisabled("<anonymous>");
                }
            }
        }

        ImGui::EndTable();
    }
    if (pending_ctx_action.has_value() && on_context_action_) {
        on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
    }
}

} // namespace viewer
