#include "panel_helpers.hpp"
#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {
namespace {

enum class ExportSortCol : ImGuiID {
    Name = 0,
    Ordinal = 1,
    Address = 2,
    Forwarder = 3,
};

[[nodiscard]] int icase_cmp_exports(std::string_view a, std::string_view b) noexcept {
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

} // namespace

ExportsPanel::ExportsPanel(BinaryModel& model)
    : UiPanel("Exports")
    , model_(model) {
    filter_buf_[0] = '\0';
}

void ExportsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr || img->exports().empty()) {
        ImGui::TextDisabled("No exports.");
        return;
    }

    const bool is_64 = img->is_64bit();
    const float va_col_width = is_64 ? 148.0f : 92.0f;

    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##ExportsFilter", "Filter name, ordinal, VA, or forwarder...", filter_buf_, sizeof(filter_buf_));
    const std::string_view filter(filter_buf_);

    const auto exports = img->exports();
    std::vector<std::size_t> matched;
    matched.reserve(exports.size());
    for (std::size_t i = 0u; i < exports.size(); ++i) {
        const peelf::ExportEntry& entry = exports[i];
        if (!filter.empty()) {
            const std::string ord_str = std::to_string(entry.ordinal);
            const std::string addr_str =
                entry.virtual_address != 0u ? format_va(entry.virtual_address, is_64) : std::string{};
            if (!icontains(entry.name, filter) &&
                !icontains(entry.forwarder, filter) &&
                !icontains(ord_str, filter) &&
                (addr_str.empty() || !icontains(addr_str, filter))) {
                continue;
            }
        }
        matched.push_back(i);
    }

    ImGui::SameLine();
    ImGui::TextDisabled("%zu/%zu exports", matched.size(), exports.size());

    std::optional<PendingEntityContextAction> pending_ctx_action;
    ImGui::Separator();
    if (ImGui::BeginTable("UnifiedExportsTable", 4, kDenseReTableFlags)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(ExportSortCol::Name));
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 68.0f, static_cast<ImGuiID>(ExportSortCol::Ordinal));
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, va_col_width, static_cast<ImGuiID>(ExportSortCol::Address));
        ImGui::TableSetupColumn("Forwarder", ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(ExportSortCol::Forwarder));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiID sort_col = static_cast<ImGuiID>(ExportSortCol::Name);
        bool ascending = true;
        bool has_active_sort = false;
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs();
            specs != nullptr && specs->SpecsCount > 0 && specs->Specs != nullptr) {
            sort_col = specs->Specs[0].ColumnUserID;
            ascending = specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
            has_active_sort = specs->Specs[0].SortDirection != ImGuiSortDirection_None;
            specs->SpecsDirty = false;
        }

        if (has_active_sort) {
            std::ranges::sort(matched, [&](std::size_t ia, std::size_t ib) {
                const peelf::ExportEntry& a = exports[ia];
                const peelf::ExportEntry& b = exports[ib];
                int cmp = 0;
                switch (static_cast<ExportSortCol>(sort_col)) {
                    case ExportSortCol::Name:
                        if (a.name.empty() != b.name.empty()) {
                            return !a.name.empty();
                        }
                        cmp = icase_cmp_exports(a.name, b.name);
                        break;
                    case ExportSortCol::Ordinal:
                        cmp = a.ordinal < b.ordinal ? -1 : (a.ordinal > b.ordinal ? 1 : 0);
                        break;
                    case ExportSortCol::Address: {
                        const bool a_has = a.virtual_address != 0u;
                        const bool b_has = b.virtual_address != 0u;
                        if (a_has != b_has) {
                            return a_has;
                        }
                        cmp = a.virtual_address < b.virtual_address
                            ? -1
                            : (a.virtual_address > b.virtual_address ? 1 : 0);
                        break;
                    }
                    case ExportSortCol::Forwarder:
                        if (a.forwarder.empty() != b.forwarder.empty()) {
                            return !a.forwarder.empty();
                        }
                        cmp = icase_cmp_exports(a.forwarder, b.forwarder);
                        break;
                }
                if (cmp != 0) {
                    return ascending ? (cmp < 0) : (cmp > 0);
                }
                return ia < ib;
            });
        }

        ImGuiListClipper clipper;
        clipper.Begin(clamp_imgui_clipper_count(matched.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const std::size_t row_id = matched[static_cast<std::size_t>(row)];
                const peelf::ExportEntry& entry = exports[row_id];
                const std::string safe_name = entry.name.empty()
                    ? std::string{"<unnamed>"}
                    : sanitize_single_line_control_chars(entry.name);

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(row_id));
                if (ImGui::Selectable(safe_name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (on_export_activated_) {
                        on_export_activated_(entry, row_id);
                    }
                }
                draw_inspectable_entity_context_menu(
                    "ExportRowCtx",
                    model_,
                    pending_ctx_action,
                    [&]() -> InspectableEntity {
                        const std::optional<std::uint64_t> exp_va =
                            entry.virtual_address != 0u
                                ? std::optional<std::uint64_t>(entry.virtual_address)
                                : std::nullopt;
                        const bool static_img = model_has_static_image(model_);
                        return InspectableEntity{
                            .va = exp_va,
                            .file_offset = (exp_va.has_value() && static_img)
                                ? img->virtual_address_to_file_offset(*exp_va)
                                : std::nullopt,
                            .size = 1u,
                            .symbol_or_label = entry.name,
                            .module_name = model_.file_info().path,
                            .extra_json_fields = {
                                {"kind", "export"},
                                {"ordinal", std::to_string(entry.ordinal)},
                                {"forwarder", entry.forwarder},
                            },
                        };
                    });
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::Text("%u", entry.ordinal);

                ImGui::TableNextColumn();
                if (entry.virtual_address == 0u) {
                    ImGui::TextDisabled("-");
                } else {
                    const std::string va_str = format_va(entry.virtual_address, is_64);
                    ImGui::TextUnformatted(va_str.c_str());
                }

                ImGui::TableNextColumn();
                if (entry.forwarder.empty()) {
                    ImGui::TextDisabled("-");
                } else {
                    const std::string safe_fwd = sanitize_single_line_control_chars(entry.forwarder);
                    ImGui::TextUnformatted(safe_fwd.c_str());
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
