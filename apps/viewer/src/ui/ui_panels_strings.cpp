#include "ui_panels_strings.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {
namespace {

enum StringSortColumnId : ImGuiID {
    kColAddress = 1,
    kColSection = 2,
    kColEncoding = 3,
    kColLength = 4,
    kColXRefs = 5,
    kColString = 6,
};

[[nodiscard]] bool icontains_str(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(
               haystack.begin(),
               haystack.end(),
               needle.begin(),
               needle.end(),
               [](char a, char b) {
                   return std::tolower(static_cast<unsigned char>(a)) ==
                          std::tolower(static_cast<unsigned char>(b));
               }) != haystack.end();
}

[[nodiscard]] bool matches_encoding_filter(StringEncoding enc, int filter_idx) noexcept {
    switch (filter_idx) {
    case 1: return enc == StringEncoding::Ascii;
    case 2: return enc == StringEncoding::Utf8;
    case 3: return enc == StringEncoding::Utf16Le;
    case 4: return enc == StringEncoding::Utf16Be;
    default: return true;
    }
}

[[nodiscard]] ImVec4 encoding_badge_color(StringEncoding enc) noexcept {
    switch (enc) {
    case StringEncoding::Ascii:   return ImVec4(0.75f, 0.82f, 0.90f, 1.0f);
    case StringEncoding::Utf8:    return ImVec4(0.45f, 0.88f, 0.65f, 1.0f);
    case StringEncoding::Utf16Le: return ImVec4(0.95f, 0.78f, 0.38f, 1.0f);
    case StringEncoding::Utf16Be: return ImVec4(0.92f, 0.58f, 0.86f, 1.0f);
    }
    return ImVec4(0.75f, 0.82f, 0.90f, 1.0f);
}

[[nodiscard]] int icompare_sv(std::string_view a, std::string_view b) noexcept {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const int ca = std::tolower(static_cast<unsigned char>(a[i]));
        const int cb = std::tolower(static_cast<unsigned char>(b[i]));
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (a.size() == b.size()) {
        return 0;
    }
    return a.size() < b.size() ? -1 : 1;
}

} // namespace

StringsPanel::StringsPanel(BinaryModel& model,
                           StringsIndex& strings,
                           const ReferenceIndex& references,
                           const AnnotationStore& annotations,
                           ViewerSelection& selection)
    : UiPanel("Strings")
    , model_(model)
    , strings_(strings)
    , references_(references)
    , annotations_(annotations)
    , selection_(selection) {}

void StringsPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to browse strings.");
        return;
    }

    const auto sections = strings_.sections_or_regions();
    if (section_filter_ > static_cast<int>(sections.size())) {
        section_filter_ = 0;
    }

    // Filter bar
    ImGui::SetNextItemWidth(210.0f);
    ImGui::InputTextWithHint("##StrFilter", "Filter text, VA, or section...", filter_, sizeof(filter_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(115.0f);
    ImGui::Combo("##StrEncoding",
                 &encoding_filter_,
                 "All Encodings\0ASCII\0UTF-8\0UTF-16LE\0UTF-16BE\0");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(145.0f);
    const char* current_sec_label =
        (section_filter_ == 0 || static_cast<std::size_t>(section_filter_ - 1) >= sections.size())
            ? "All Sections/Regions"
            : sections[static_cast<std::size_t>(section_filter_ - 1)].c_str();
    if (ImGui::BeginCombo("##StrSection", current_sec_label)) {
        if (ImGui::Selectable("All Sections/Regions", section_filter_ == 0)) {
            section_filter_ = 0;
        }
        for (std::size_t idx = 0; idx < sections.size(); ++idx) {
            const bool sel = (section_filter_ == static_cast<int>(idx + 1));
            if (ImGui::Selectable(sections[idx].c_str(), sel)) {
                section_filter_ = static_cast<int>(idx + 1);
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SetNextItemWidth(82.0f);
    if (ImGui::InputInt("Min len", &min_length_, 1, 4)) {
        min_length_ = std::clamp(min_length_, 2, 256);
        if (static_cast<std::size_t>(min_length_) < strings_.min_length() && on_rebuild_) {
            on_rebuild_(static_cast<std::size_t>(min_length_), scan_all_live_regions_);
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Referenced only (xrefs > 0)", &referenced_only_);
    if (model_.is_live_process()) {
        ImGui::SameLine();
        if (ImGui::Checkbox("All live regions", &scan_all_live_regions_) && on_rebuild_) {
            on_rebuild_(requested_min_length(), scan_all_live_regions_);
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Rescan") && on_rebuild_) {
        on_rebuild_(requested_min_length(), scan_all_live_regions_);
    }

    const auto entries = strings_.entries();
    const std::string_view query(filter_);
    const std::string_view required_section =
        (section_filter_ > 0 && static_cast<std::size_t>(section_filter_ - 1) < sections.size())
            ? std::string_view(sections[static_cast<std::size_t>(section_filter_ - 1)])
            : std::string_view{};
    const auto min_chars = static_cast<std::size_t>(std::max(min_length_, 1));

    std::vector<std::size_t> visible_indices;
    visible_indices.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const ExtractedString& s = entries[i];
        if (s.char_length < min_chars) continue;
        if (referenced_only_ && s.xref_count == 0) continue;
        if (!matches_encoding_filter(s.encoding, encoding_filter_)) continue;
        if (!required_section.empty() && s.section_or_region_name != required_section) continue;

        if (!query.empty()) {
            std::array<char, 32> va_hex{};
            std::snprintf(va_hex.data(), va_hex.size(), "0x%" PRIX64, s.virtual_address);
            if (!icontains_str(s.preview, query) &&
                !icontains_str(s.section_or_region_name, query) &&
                !icontains_str(va_hex.data(), query)) {
                continue;
            }
        }
        visible_indices.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu strings%s",
                        visible_indices.size(),
                        entries.size(),
                        strings_.incomplete() ? " (budget-capped)" : "");
    if (references_.is_scanning()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.45f, 0.82f, 0.96f, 1.0f),
                           "| XRefs scanning %.0f%%...",
                           references_.coverage_percent());
    } else if (references_.incomplete()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| XRefs %.0f%% coverage", references_.coverage_percent());
    }
    ImGui::Separator();

    const float avail_h = ImGui::GetContentRegionAvail().y;
    const float top_table_h = std::max(140.0f, avail_h * 0.60f);

    if (ImGui::BeginTable("StringsCatalogTable",
                          6,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_Sortable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, top_table_h))) {
        ImGui::TableSetupColumn("Address",
                                ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed,
                                128.0f,
                                kColAddress);
        ImGui::TableSetupColumn("Section/Region", ImGuiTableColumnFlags_WidthFixed, 108.0f, kColSection);
        ImGui::TableSetupColumn("Encoding", ImGuiTableColumnFlags_WidthFixed, 72.0f, kColEncoding);
        ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 48.0f, kColLength);
        ImGui::TableSetupColumn("XRefs", ImGuiTableColumnFlags_WidthFixed, 52.0f, kColXRefs);
        ImGui::TableSetupColumn("String", ImGuiTableColumnFlags_WidthStretch, 1.0f, kColString);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs();
            sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& spec = sort_specs->Specs[0];
            const bool asc = (spec.SortDirection != ImGuiSortDirection_Descending);
            std::ranges::sort(visible_indices, [&](std::size_t lhs_idx, std::size_t rhs_idx) {
                const ExtractedString& a = entries[lhs_idx];
                const ExtractedString& b = entries[rhs_idx];
                int cmp = 0;
                switch (spec.ColumnUserID) {
                case kColSection:
                    cmp = icompare_sv(a.section_or_region_name, b.section_or_region_name);
                    break;
                case kColEncoding:
                    cmp = static_cast<int>(a.encoding) - static_cast<int>(b.encoding);
                    break;
                case kColLength:
                    cmp = (a.char_length == b.char_length) ? 0 : (a.char_length < b.char_length ? -1 : 1);
                    break;
                case kColXRefs:
                    cmp = (a.xref_count == b.xref_count) ? 0 : (a.xref_count < b.xref_count ? -1 : 1);
                    break;
                case kColString:
                    cmp = icompare_sv(a.preview, b.preview);
                    break;
                case kColAddress:
                default:
                    cmp = (a.virtual_address == b.virtual_address)
                        ? 0
                        : (a.virtual_address < b.virtual_address ? -1 : 1);
                    break;
                }
                if (cmp == 0) {
                    return a.virtual_address < b.virtual_address;
                }
                return asc ? (cmp < 0) : (cmp > 0);
            });
            sort_specs->SpecsDirty = false;
        }

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible_indices.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const ExtractedString& s = entries[visible_indices[static_cast<std::size_t>(row)]];
                const bool is_selected =
                    (selected_string_va_ && *selected_string_va_ == s.virtual_address) ||
                    (selection_.virtual_address &&
                     *selection_.virtual_address >= s.virtual_address &&
                     (*selection_.virtual_address - s.virtual_address) < std::max<std::size_t>(s.byte_length, 1u));

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(row);
                std::array<char, 32> addr_buf{};
                std::snprintf(addr_buf.data(), addr_buf.size(), "0x%016" PRIX64, s.virtual_address);
                if (ImGui::Selectable(addr_buf.data(),
                                      is_selected,
                                      ImGuiSelectableFlags_SpanAllColumns)) {
                    selected_string_va_ = s.virtual_address;
                    selected_referrer_va_.reset();
                    if (on_string_selected_) {
                        on_string_selected_(s);
                    }
                }
                if (ImGui::IsItemHovered() && s.preview.size() > 80u) {
                    ImGui::SetTooltip("VA: 0x%" PRIX64 " (%zu bytes, %zu chars)\n%s",
                                      s.virtual_address,
                                      s.byte_length,
                                      s.char_length,
                                      format_single_line_string_preview(s.preview, 512).c_str());
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(
                    s.section_or_region_name.empty() ? "-" : s.section_or_region_name.c_str());

                ImGui::TableNextColumn();
                const std::string_view enc_sv = viewer::to_string(s.encoding);
                ImGui::TextColored(encoding_badge_color(s.encoding),
                                   "%.*s",
                                   static_cast<int>(enc_sv.size()),
                                   enc_sv.data());

                ImGui::TableNextColumn();
                ImGui::Text("%zu", s.char_length);

                ImGui::TableNextColumn();
                if (s.xref_count > 0) {
                    ImGui::TextColored(ImVec4(0.42f, 0.90f, 0.56f, 1.0f), "%zu", s.xref_count);
                } else {
                    ImGui::TextDisabled("0");
                }

                ImGui::TableNextColumn();
                const std::string one_line = format_single_line_string_preview(s.preview, 240);
                ImGui::TextUnformatted(one_line.c_str());
            }
        }
        ImGui::EndTable();
    }

    // Bottom split pane: Referencing Functions & Instructions
    ImGui::Separator();
    const ExtractedString* active_string = nullptr;
    if (selected_string_va_) {
        active_string = strings_.find_containing(*selected_string_va_);
    } else if (selection_.virtual_address) {
        active_string = strings_.find_containing(*selection_.virtual_address);
    }

    if (active_string == nullptr) {
        ImGui::TextDisabled("Referencing Functions & Instructions — select a string above to inspect xrefs.");
        return;
    }

    ImGui::Text("Referencing Functions & Instructions for 0x%" PRIX64 " (%zu xref%s)",
                active_string->virtual_address,
                active_string->xref_count,
                active_string->xref_count == 1u ? "" : "s");
    ImGui::SameLine();
    ImGui::TextDisabled("| Click: Disasm + Open Views  |  Double-click: Decompile");

    if (active_string->referrers.empty()) {
        ImGui::TextDisabled(
            "%s",
            references_.incomplete()
                ? "No incoming references found in scanned code yet (use References > Scan Full Binary for 100% coverage)."
                : "No incoming code/data references found for this string.");
        return;
    }

    if (ImGui::BeginTable("StringReferrersTable",
                          5,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch, 0.34f);
        ImGui::TableSetupColumn("Instruction VA", ImGuiTableColumnFlags_WidthFixed, 128.0f);
        ImGui::TableSetupColumn("Span", ImGuiTableColumnFlags_WidthFixed, 54.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 0.44f);
        ImGui::TableSetupColumn("Jump To", ImGuiTableColumnFlags_WidthFixed, 152.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (std::size_t r_idx = 0; r_idx < active_string->referrers.size(); ++r_idx) {
            const StringReferrer& ref = active_string->referrers[r_idx];
            const bool ref_sel = selected_referrer_va_ && *selected_referrer_va_ == ref.instruction_address;

            std::string fn_display = ref.function_name;
            if (ref.function_address) {
                if (const auto* note = annotations_.find(*ref.function_address);
                    note != nullptr && !note->name.empty()) {
                    fn_display = note->name;
                }
                const std::uint64_t delta = ref.instruction_address >= *ref.function_address
                    ? (ref.instruction_address - *ref.function_address)
                    : 0u;
                if (delta > 0 && !fn_display.empty()) {
                    fn_display = std::format("{}+0x{:X}", fn_display, delta);
                }
            }
            if (fn_display.empty()) {
                fn_display = std::format("<code @ 0x{:X}>", ref.instruction_address);
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(r_idx));
            if (ImGui::Selectable(fn_display.c_str(),
                                  ref_sel,
                                  ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_referrer_va_ = ref.instruction_address;
                if (on_referrer_activated_) {
                    const auto target_view = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
                        ? StringReferrerTargetView::Decompile
                        : StringReferrerTargetView::SyncAllOpen;
                    on_referrer_activated_(ref, target_view);
                }
            }

            ImGui::TableNextColumn();
            ImGui::Text("0x%016" PRIX64, ref.instruction_address);

            ImGui::TableNextColumn();
            const std::uint64_t interior_off = ref.target_address >= active_string->virtual_address
                ? (ref.target_address - active_string->virtual_address)
                : 0u;
            if (interior_off == 0) {
                ImGui::TextDisabled("+0x0");
            } else {
                ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.38f, 1.0f), "+0x%" PRIX64, interior_off);
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(ref.instruction_text.c_str());

            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Disasm")) {
                selected_referrer_va_ = ref.instruction_address;
                if (on_referrer_activated_) {
                    on_referrer_activated_(ref, StringReferrerTargetView::Disassembly);
                }
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Decomp")) {
                selected_referrer_va_ = ref.instruction_address;
                if (on_referrer_activated_) {
                    on_referrer_activated_(ref, StringReferrerTargetView::Decompile);
                }
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Graph")) {
                selected_referrer_va_ = ref.instruction_address;
                if (on_referrer_activated_) {
                    on_referrer_activated_(ref, StringReferrerTargetView::FlowGraph);
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

} // namespace viewer
