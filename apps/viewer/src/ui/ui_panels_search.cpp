#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <string>

namespace viewer {
namespace {

[[nodiscard]] std::string format_hit_bytes(const std::vector<std::uint8_t>& bytes) {
    std::string out;
    const std::size_t limit = std::min<std::size_t>(bytes.size(), 16u);
    for (std::size_t i = 0; i < limit; ++i) {
        std::array<char, 4> b{};
        std::snprintf(b.data(), b.size(), "%02X", bytes[i]);
        if (!out.empty()) {
            out += ' ';
        }
        out += b.data();
    }
    if (bytes.size() > limit) {
        out += " ...";
    }
    return out;
}

} // namespace

MemorySearchPanel::MemorySearchPanel(BinaryModel& model)
    : UiPanel("Memory Search")
    , model_(model) {}

void MemorySearchPanel::run_search() {
    error_message_.clear();

    peelf::MemorySearchQuery query;
    switch (scope_idx_) {
        case 0: query.scope = peelf::SearchScope::Heap; break;
        case 1: query.scope = peelf::SearchScope::SelectedRegion; break;
        case 2: query.scope = peelf::SearchScope::ActiveModule; break;
        default: query.scope = peelf::SearchScope::AllReadable; break;
    }

    static constexpr std::array<peelf::SearchValueKind, 13> kKinds = {
        peelf::SearchValueKind::HexPattern,
        peelf::SearchValueKind::Int8,
        peelf::SearchValueKind::UInt8,
        peelf::SearchValueKind::Int16,
        peelf::SearchValueKind::UInt16,
        peelf::SearchValueKind::Int32,
        peelf::SearchValueKind::UInt32,
        peelf::SearchValueKind::Int64,
        peelf::SearchValueKind::UInt64,
        peelf::SearchValueKind::Float32,
        peelf::SearchValueKind::Float64,
        peelf::SearchValueKind::Utf8Text,
        peelf::SearchValueKind::Utf16Text,
    };
    const std::size_t kidx = static_cast<std::size_t>(
        std::clamp(kind_idx_, 0, static_cast<int>(kKinds.size() - 1)));
    query.kind = kKinds[kidx];

    if (endian_mode_ == 1) {
        query.endianness = peelf::Endianness::Little;
    } else if (endian_mode_ == 2) {
        query.endianness = peelf::Endianness::Big;
    } else {
        query.endianness = model_.endianness();
    }

    static constexpr std::array<std::size_t, 4> kAligns = {1u, 2u, 4u, 8u};
    query.alignment = kAligns[static_cast<std::size_t>(std::clamp(align_idx_, 0, 3))];
    query.case_sensitive = case_sensitive_;
    query.max_results = static_cast<std::size_t>(std::clamp(max_results_, 1, 100000));
    query.query_text = query_buf_;

    auto res = model_.search_memory(query);
    if (!res) {
        error_message_ = res.error().message;
        last_report_.reset();
        return;
    }
    last_report_ = std::move(*res);
}

void MemorySearchPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to search heaps and memory.");
        return;
    }

    const bool is_live = model_.is_live_process();
    if (is_live) {
        static constexpr std::array<const char*, 4> kScopeItems = {
            "Heap (default)",
            "Selected Region",
            "Active Module",
            "All Readable Memory",
        };
        ImGui::SetNextItemWidth(175.0f);
        ImGui::Combo("Scope",
                     &scope_idx_,
                     kScopeItems.data(),
                     static_cast<int>(kScopeItems.size()));
    } else {
        ImGui::TextDisabled("Scope: Static Binary Image");
    }

    static constexpr std::array<const char*, 13> kKindItems = {
        "Hex Pattern (e.g. 48 8B ?? 10)",
        "Int8 (signed)",
        "UInt8 (unsigned)",
        "Int16",
        "UInt16",
        "Int32",
        "UInt32",
        "Int64",
        "UInt64",
        "Float32",
        "Float64",
        "Text (UTF-8 / ASCII)",
        "Text (UTF-16)",
    };
    ImGui::SetNextItemWidth(175.0f);
    ImGui::Combo("Value Type",
                 &kind_idx_,
                 kKindItems.data(),
                 static_cast<int>(kKindItems.size()));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(155.0f);
    const std::string auto_endian_label = std::string("Target Auto (") +
                                          std::string(peelf::to_string(model_.endianness())) + ")";
    const std::array<const char*, 3> endian_items = {
        auto_endian_label.c_str(),
        "Little-Endian",
        "Big-Endian",
    };
    ImGui::Combo("Endianness",
                 &endian_mode_,
                 endian_items.data(),
                 static_cast<int>(endian_items.size()));

    static constexpr std::array<const char*, 4> kAlignItems = {
        "1 byte",
        "2 bytes",
        "4 bytes",
        "8 bytes",
    };
    ImGui::SetNextItemWidth(90.0f);
    ImGui::Combo("Align",
                 &align_idx_,
                 kAlignItems.data(),
                 static_cast<int>(kAlignItems.size()));
    ImGui::SameLine();
    ImGui::Checkbox("Case-sensitive", &case_sensitive_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(95.0f);
    ImGui::InputInt("Max hits", &max_results_, 0, 0);

    ImGui::SetNextItemWidth(std::max(140.0f, ImGui::GetContentRegionAvail().x - 84.0f));
    const bool enter_pressed = ImGui::InputTextWithHint(
        "##SearchQuery",
        kind_idx_ == 0 ? "Hex bytes / wildcards, e.g. DE AD ?? EF"
                       : (kind_idx_ >= 11 ? "Text string to find..." : "Numeric value (dec or 0x hex)..."),
        query_buf_,
        sizeof(query_buf_),
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Search", ImVec2(76.0f, 0.0f)) || enter_pressed) {
        run_search();
    }

    if (!error_message_.empty()) {
        ImGui::TextColored(ImVec4(0.98f, 0.46f, 0.44f, 1.0f), "%s", error_message_.c_str());
    }

    if (!last_report_) {
        return;
    }

    ImGui::TextDisabled("Hits: %zu%s  |  Scanned %zu region(s), %" PRIu64 " bytes  |  %s",
                        last_report_->hits.size(),
                        last_report_->truncated ? " (truncated)" : "",
                        last_report_->regions_scanned,
                        last_report_->bytes_scanned,
                        last_report_->status.detail.c_str());
    ImGui::Separator();

    if (ImGui::BeginTable("SearchHitsTable",
                          4,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 134.0f);
        ImGui::TableSetupColumn("Region / Section", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Matched Bytes", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Decoded Preview", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(last_report_->hits.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const peelf::MemorySearchHit& hit = last_report_->hits[static_cast<std::size_t>(row)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(row);
                std::array<char, 32> abuf{};
                std::snprintf(abuf.data(), abuf.size(), "0x%016" PRIX64, hit.address);
                if (ImGui::Selectable(abuf.data(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (on_address_activated_) {
                        on_address_activated_(hit.address, std::max<std::size_t>(1u, hit.matched_bytes.size()));
                    }
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(hit.region_label.empty() ? "-" : hit.region_label.c_str());

                ImGui::TableNextColumn();
                const std::string hex_str = format_hit_bytes(hit.matched_bytes);
                ImGui::TextUnformatted(hex_str.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(hit.decoded_preview.c_str());
            }
        }
        ImGui::EndTable();
    }
}

} // namespace viewer
