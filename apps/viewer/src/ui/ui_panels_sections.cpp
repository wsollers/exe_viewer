#include "panel_helpers.hpp"
#include "ui_panels.hpp"

#include <peelf/macho_image.hpp>

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {
namespace {

enum class SectionSortCol : ImGuiID {
    Name = 0,
    Va = 1,
    VirtSize = 2,
    FileOffset = 3,
    RawSize = 4,
    Perm = 5,
};

[[nodiscard]] std::string format_perm_rwx(bool readable, bool writable, bool executable) {
    std::string perms(3u, '-');
    if (readable) {
        perms[0] = 'R';
    }
    if (writable) {
        perms[1] = 'W';
    }
    if (executable) {
        perms[2] = 'X';
    }
    return perms;
}

[[nodiscard]] std::uint8_t perm_sort_rank(bool readable, bool writable, bool executable) noexcept {
    return static_cast<std::uint8_t>(
        (readable ? 1u : 0u) | (writable ? 2u : 0u) | (executable ? 4u : 0u));
}

void draw_permissions_cell(bool readable, bool writable, bool executable) {
    const std::string perms = format_perm_rwx(readable, writable, executable);
    if (writable && executable) {
        ImGui::TextColored(ImVec4(0.86f, 0.20f, 0.20f, 1.0f), "%s", perms.c_str());
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Writable + Executable (W^X violation)");
        }
    } else {
        ImGui::TextUnformatted(perms.c_str());
    }
}

[[nodiscard]] int icase_cmp(std::string_view a, std::string_view b) noexcept {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0u; i < n; ++i) {
        const int ca = std::tolower(static_cast<unsigned char>(a[i]));
        const int cb = std::tolower(static_cast<unsigned char>(b[i]));
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (a.size() != b.size()) {
        return a.size() < b.size() ? -1 : 1;
    }
    const int exact = a.compare(b);
    return exact < 0 ? -1 : (exact > 0 ? 1 : 0);
}

[[nodiscard]] std::string segment_display_name(
    const peelf::IBinaryImage& img, std::size_t seg_idx, const peelf::Segment& seg) {
    if (seg_idx < img.macho_segments().size() && !img.macho_segments()[seg_idx].name.empty()) {
        return img.macho_segments()[seg_idx].name;
    }
    switch (seg.type) {
        case 0u: return "PT_NULL";
        case 1u: return "PT_LOAD";
        case 2u: return "PT_DYNAMIC";
        case 3u: return "PT_INTERP";
        case 4u: return "PT_NOTE";
        case 6u: return "PT_PHDR";
        case 7u: return "PT_TLS";
        case 0x6474e550u: return "PT_GNU_EH_FRAME";
        case 0x6474e551u: return "PT_GNU_STACK";
        case 0x6474e552u: return "PT_GNU_RELRO";
        case 0x6474e553u: return "PT_GNU_PROPERTY";
        default: return std::format("0x{:X}", seg.type);
    }
}

} // namespace

SectionsPanel::SectionsPanel(BinaryModel& model)
    : UiPanel("Sections")
    , model_(model) {
    filter_buf_[0] = '\0';
}

void SectionsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr || (img->sections().empty() && img->segments().empty())) {
        ImGui::TextDisabled("No sections.");
        return;
    }

    const bool is_64 = img->is_64bit();
    const float va_col_width = is_64 ? 148.0f : 88.0f;

    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##SectionsFilter", "Filter name, VA, or perm...", filter_buf_, sizeof(filter_buf_));
    const std::string_view filter(filter_buf_);

    const auto sections = img->sections();
    std::vector<std::size_t> matched_sections;
    matched_sections.reserve(sections.size());
    for (std::size_t i = 0u; i < sections.size(); ++i) {
        const peelf::Section& sec = sections[i];
        if (!filter.empty()) {
            const std::string va_hex = format_va(sec.virtual_address, is_64);
            const std::string perms = format_perm_rwx(sec.readable, sec.writable, sec.executable);
            if (!icontains(sec.name, filter) &&
                !icontains(va_hex, filter) &&
                !icontains(perms, filter)) {
                continue;
            }
        }
        matched_sections.push_back(i);
    }

    const auto segments = img->segments();
    std::vector<std::size_t> matched_segments;
    matched_segments.reserve(segments.size());
    for (std::size_t i = 0u; i < segments.size(); ++i) {
        const peelf::Segment& seg = segments[i];
        const std::string seg_name = segment_display_name(*img, i, seg);
        if (!filter.empty()) {
            const std::string va_hex = format_va(seg.virtual_address, is_64);
            const std::string perms = format_perm_rwx(seg.readable, seg.writable, seg.executable);
            if (!icontains(seg_name, filter) &&
                !icontains(va_hex, filter) &&
                !icontains(perms, filter)) {
                continue;
            }
        }
        matched_segments.push_back(i);
    }

    ImGui::SameLine();
    if (segments.empty()) {
        ImGui::TextDisabled("%zu/%zu sections", matched_sections.size(), sections.size());
    } else {
        ImGui::TextDisabled("%zu/%zu sections | %zu/%zu segments",
                            matched_sections.size(),
                            sections.size(),
                            matched_segments.size(),
                            segments.size());
    }
    ImGui::Separator();

    std::optional<PendingEntityContextAction> pending_ctx_action;
    const float total_avail_y = ImGui::GetContentRegionAvail().y;
    const ImVec2 sections_table_size = segments.empty()
        ? ImVec2(0.0f, 0.0f)
        : ImVec2(0.0f, std::max(110.0f, total_avail_y * 0.58f));

    if (!sections.empty() &&
        ImGui::BeginTable("SectionsTable", 6, kDenseReTableFlags, sections_table_size)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(SectionSortCol::Name));
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, va_col_width, static_cast<ImGuiID>(SectionSortCol::Va));
        ImGui::TableSetupColumn("Virt Size", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::VirtSize));
        ImGui::TableSetupColumn("File Offset", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::FileOffset));
        ImGui::TableSetupColumn("Raw Size", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::RawSize));
        ImGui::TableSetupColumn("Perm", ImGuiTableColumnFlags_WidthFixed, 48.0f, static_cast<ImGuiID>(SectionSortCol::Perm));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiID sort_col = static_cast<ImGuiID>(SectionSortCol::Va);
        bool ascending = true;
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs();
            specs != nullptr && specs->SpecsCount > 0 && specs->Specs != nullptr) {
            sort_col = specs->Specs[0].ColumnUserID;
            ascending = specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
            specs->SpecsDirty = false;
        }

        std::ranges::sort(matched_sections, [&](std::size_t ia, std::size_t ib) {
            const peelf::Section& a = sections[ia];
            const peelf::Section& b = sections[ib];
            int cmp = 0;
            switch (static_cast<SectionSortCol>(sort_col)) {
                case SectionSortCol::Name:
                    cmp = icase_cmp(a.name, b.name);
                    break;
                case SectionSortCol::Va:
                    cmp = a.virtual_address < b.virtual_address ? -1 : (a.virtual_address > b.virtual_address ? 1 : 0);
                    break;
                case SectionSortCol::VirtSize:
                    cmp = a.virtual_size < b.virtual_size ? -1 : (a.virtual_size > b.virtual_size ? 1 : 0);
                    break;
                case SectionSortCol::FileOffset:
                    cmp = a.file_offset < b.file_offset ? -1 : (a.file_offset > b.file_offset ? 1 : 0);
                    break;
                case SectionSortCol::RawSize:
                    cmp = a.file_size < b.file_size ? -1 : (a.file_size > b.file_size ? 1 : 0);
                    break;
                case SectionSortCol::Perm: {
                    const std::uint8_t pa = perm_sort_rank(a.readable, a.writable, a.executable);
                    const std::uint8_t pb = perm_sort_rank(b.readable, b.writable, b.executable);
                    cmp = pa < pb ? -1 : (pa > pb ? 1 : 0);
                    break;
                }
            }
            if (cmp != 0) {
                return ascending ? (cmp < 0) : (cmp > 0);
            }
            return ia < ib;
        });

        ImGuiListClipper clipper;
        clipper.Begin(clamp_imgui_clipper_count(matched_sections.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const std::size_t section_index = matched_sections[static_cast<std::size_t>(row)];
                const peelf::Section& s = sections[section_index];
                const std::uint64_t range_size = s.file_size != 0u ? s.file_size : s.virtual_size;
                const bool can_navigate =
                    (s.file_size != 0u || s.virtual_size != 0u) &&
                    range_size <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max());

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(section_index));
                const std::string safe_name = s.name.empty()
                    ? std::string{"<unnamed>"}
                    : sanitize_single_line_control_chars(s.name);
                if (ImGui::Selectable(safe_name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (can_navigate && on_section_activated_) {
                        on_section_activated_(s, section_index);
                    }
                }
                draw_inspectable_entity_context_menu(
                    "SectionRowCtx",
                    model_,
                    pending_ctx_action,
                    [&]() -> InspectableEntity {
                        const bool static_img = model_has_static_image(model_);
                        return InspectableEntity{
                            .va = s.virtual_address != 0u
                                ? std::optional<std::uint64_t>(s.virtual_address)
                                : std::nullopt,
                            .file_offset = (static_img && s.file_size != 0u)
                                ? std::optional<std::uint64_t>(s.file_offset)
                                : std::nullopt,
                            .size = range_size,
                            .symbol_or_label = s.name,
                            .module_name = model_.file_info().path,
                            .extra_json_fields = {
                                {"kind", "section"},
                                {"permissions", format_perm_rwx(s.readable, s.writable, s.executable)},
                            },
                        };
                    });
                ImGui::PopID();

                ImGui::TableNextColumn();
                const std::string va_str = format_va(s.virtual_address, is_64);
                ImGui::TextUnformatted(va_str.c_str());

                ImGui::TableNextColumn();
                const std::string vsz_str = format_file_offset(s.virtual_size);
                ImGui::TextUnformatted(vsz_str.c_str());
                if (ImGui::IsItemHovered()) {
                    const std::string vsz_human = format_compact_bytes(s.virtual_size);
                    ImGui::SetTooltip("%s (%llu bytes)",
                                      vsz_human.c_str(),
                                      static_cast<unsigned long long>(s.virtual_size));
                }

                ImGui::TableNextColumn();
                const std::string foff_str = format_file_offset(s.file_offset);
                ImGui::TextUnformatted(foff_str.c_str());

                ImGui::TableNextColumn();
                const std::string rsz_str = format_file_offset(s.file_size);
                ImGui::TextUnformatted(rsz_str.c_str());
                if (ImGui::IsItemHovered()) {
                    const std::string rsz_human = format_compact_bytes(s.file_size);
                    ImGui::SetTooltip("%s (%llu bytes)",
                                      rsz_human.c_str(),
                                      static_cast<unsigned long long>(s.file_size));
                }

                ImGui::TableNextColumn();
                draw_permissions_cell(s.readable, s.writable, s.executable);
            }
        }
        ImGui::EndTable();
    }

    if (!segments.empty()) {
        ImGui::SeparatorText("Segments");
        if (ImGui::BeginTable("SegmentsTable", 6, kDenseReTableFlags)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(SectionSortCol::Name));
            ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, va_col_width, static_cast<ImGuiID>(SectionSortCol::Va));
            ImGui::TableSetupColumn("Virt Size", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::VirtSize));
            ImGui::TableSetupColumn("File Offset", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::FileOffset));
            ImGui::TableSetupColumn("Raw Size", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SectionSortCol::RawSize));
            ImGui::TableSetupColumn("Perm", ImGuiTableColumnFlags_WidthFixed, 48.0f, static_cast<ImGuiID>(SectionSortCol::Perm));
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            ImGuiID seg_sort_col = static_cast<ImGuiID>(SectionSortCol::Va);
            bool seg_ascending = true;
            if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs();
                specs != nullptr && specs->SpecsCount > 0 && specs->Specs != nullptr) {
                seg_sort_col = specs->Specs[0].ColumnUserID;
                seg_ascending = specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
                specs->SpecsDirty = false;
            }

            std::ranges::sort(matched_segments, [&](std::size_t ia, std::size_t ib) {
                const peelf::Segment& a = segments[ia];
                const peelf::Segment& b = segments[ib];
                int cmp = 0;
                switch (static_cast<SectionSortCol>(seg_sort_col)) {
                    case SectionSortCol::Name: {
                        const std::string na = segment_display_name(*img, ia, a);
                        const std::string nb = segment_display_name(*img, ib, b);
                        cmp = icase_cmp(na, nb);
                        break;
                    }
                    case SectionSortCol::Va:
                        cmp = a.virtual_address < b.virtual_address ? -1 : (a.virtual_address > b.virtual_address ? 1 : 0);
                        break;
                    case SectionSortCol::VirtSize:
                        cmp = a.virtual_size < b.virtual_size ? -1 : (a.virtual_size > b.virtual_size ? 1 : 0);
                        break;
                    case SectionSortCol::FileOffset:
                        cmp = a.file_offset < b.file_offset ? -1 : (a.file_offset > b.file_offset ? 1 : 0);
                        break;
                    case SectionSortCol::RawSize:
                        cmp = a.file_size < b.file_size ? -1 : (a.file_size > b.file_size ? 1 : 0);
                        break;
                    case SectionSortCol::Perm: {
                        const std::uint8_t pa = perm_sort_rank(a.readable, a.writable, a.executable);
                        const std::uint8_t pb = perm_sort_rank(b.readable, b.writable, b.executable);
                        cmp = pa < pb ? -1 : (pa > pb ? 1 : 0);
                        break;
                    }
                }
                if (cmp != 0) {
                    return seg_ascending ? (cmp < 0) : (cmp > 0);
                }
                return ia < ib;
            });

            ImGuiListClipper clipper;
            clipper.Begin(clamp_imgui_clipper_count(matched_segments.size()));
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const std::size_t seg_idx = matched_segments[static_cast<std::size_t>(row)];
                    const peelf::Segment& seg = segments[seg_idx];
                    const std::string seg_name = sanitize_single_line_control_chars(
                        segment_display_name(*img, seg_idx, seg));

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(seg_name.c_str());

                    ImGui::TableNextColumn();
                    const std::string va_str = format_va(seg.virtual_address, is_64);
                    ImGui::TextUnformatted(va_str.c_str());

                    ImGui::TableNextColumn();
                    const std::string vsz_str = format_file_offset(seg.virtual_size);
                    ImGui::TextUnformatted(vsz_str.c_str());

                    ImGui::TableNextColumn();
                    const std::string foff_str = format_file_offset(seg.file_offset);
                    ImGui::TextUnformatted(foff_str.c_str());

                    ImGui::TableNextColumn();
                    const std::string rsz_str = format_file_offset(seg.file_size);
                    ImGui::TextUnformatted(rsz_str.c_str());

                    ImGui::TableNextColumn();
                    draw_permissions_cell(seg.readable, seg.writable, seg.executable);
                }
            }
            ImGui::EndTable();
        }
    }

    if (pending_ctx_action.has_value() && on_context_action_) {
        on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
    }
}

} // namespace viewer
