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

enum class ImportSortCol : ImGuiID {
    Library = 0,
    Symbol = 1,
    Kind = 2,
    Address = 3,
};

[[nodiscard]] int icase_cmp_imports(std::string_view a, std::string_view b) noexcept {
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

[[nodiscard]] std::string format_import_symbol(const peelf::ImportEntry& entry) {
    return entry.import_by_ordinal ? ("#" + std::to_string(entry.ordinal)) : entry.name;
}

} // namespace

ImportsPanel::ImportsPanel(BinaryModel& model)
    : UiPanel("Imports")
    , model_(model) {
    filter_buf_[0] = '\0';
}

void ImportsPanel::draw_contents() {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr || img->imports().empty()) {
        ImGui::TextDisabled("No imports.");
        return;
    }

    const bool is_64 = img->is_64bit();
    const float va_col_width = is_64 ? 148.0f : 92.0f;

    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##ImportsFilter", "Filter library, symbol, or VA...", filter_buf_, sizeof(filter_buf_));
    const std::string_view filter(filter_buf_);

    const auto imports = img->imports();
    std::vector<std::size_t> matched;
    matched.reserve(imports.size());
    for (std::size_t i = 0u; i < imports.size(); ++i) {
        const peelf::ImportEntry& entry = imports[i];
        if (!filter.empty()) {
            const std::string symbol_name = format_import_symbol(entry);
            const std::string_view kind_str = entry.delay_load ? "Delay" : "Import";
            const std::string addr_str = entry.address != 0u ? format_va(entry.address, is_64) : std::string{};
            if (!icontains(entry.library, filter) &&
                !icontains(symbol_name, filter) &&
                !icontains(kind_str, filter) &&
                (addr_str.empty() || !icontains(addr_str, filter))) {
                continue;
            }
        }
        matched.push_back(i);
    }

    ImGui::SameLine();
    ImGui::TextDisabled("%zu/%zu imports", matched.size(), imports.size());

    std::optional<PendingEntityContextAction> pending_ctx_action;
    ImGui::Separator();
    if (ImGui::BeginTable("UnifiedImportsTable", 4, kDenseReTableFlags)) {
        ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(ImportSortCol::Library));
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(ImportSortCol::Symbol));
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 64.0f, static_cast<ImGuiID>(ImportSortCol::Kind));
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, va_col_width, static_cast<ImGuiID>(ImportSortCol::Address));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiID sort_col = static_cast<ImGuiID>(ImportSortCol::Library);
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
                const peelf::ImportEntry& a = imports[ia];
                const peelf::ImportEntry& b = imports[ib];
                int cmp = 0;
                switch (static_cast<ImportSortCol>(sort_col)) {
                    case ImportSortCol::Library:
                        cmp = icase_cmp_imports(a.library, b.library);
                        if (cmp == 0) {
                            cmp = icase_cmp_imports(format_import_symbol(a), format_import_symbol(b));
                        }
                        break;
                    case ImportSortCol::Symbol:
                        cmp = icase_cmp_imports(format_import_symbol(a), format_import_symbol(b));
                        break;
                    case ImportSortCol::Kind:
                        cmp = (a.delay_load == b.delay_load) ? 0 : (a.delay_load ? 1 : -1);
                        break;
                    case ImportSortCol::Address: {
                        const bool a_has = a.address != 0u;
                        const bool b_has = b.address != 0u;
                        if (a_has != b_has) {
                            return a_has;
                        }
                        cmp = a.address < b.address ? -1 : (a.address > b.address ? 1 : 0);
                        break;
                    }
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
                const peelf::ImportEntry& entry = imports[row_id];
                const std::string symbol_name = format_import_symbol(entry);
                const std::string safe_lib = entry.library.empty()
                    ? std::string{"<default>"}
                    : sanitize_single_line_control_chars(entry.library);
                const std::string safe_sym = symbol_name.empty()
                    ? std::string{"-"}
                    : sanitize_single_line_control_chars(symbol_name);

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(row_id));
                if (ImGui::Selectable(safe_lib.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (on_import_activated_) {
                        on_import_activated_(entry, row_id);
                    }
                }
                draw_inspectable_entity_context_menu(
                    "ImportRowCtx",
                    model_,
                    pending_ctx_action,
                    [&]() -> InspectableEntity {
                        const std::optional<std::uint64_t> imp_va =
                            entry.address != 0u ? std::optional<std::uint64_t>(entry.address) : std::nullopt;
                        const bool static_img = model_has_static_image(model_);
                        return InspectableEntity{
                            .va = imp_va,
                            .file_offset = (imp_va.has_value() && static_img)
                                ? img->virtual_address_to_file_offset(*imp_va)
                                : std::nullopt,
                            .size = is_64 ? 8u : 4u,
                            .symbol_or_label = symbol_name,
                            .module_name = entry.library,
                            .extra_json_fields = {
                                {"kind", entry.delay_load ? "delay_import" : "import"},
                                {"ordinal", std::to_string(entry.ordinal)},
                            },
                        };
                    });
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(safe_sym.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.delay_load ? "Delay" : "Import");

                ImGui::TableNextColumn();
                if (entry.address == 0u) {
                    ImGui::TextDisabled("-");
                } else {
                    const std::string va_str = format_va(entry.address, is_64);
                    ImGui::TextUnformatted(va_str.c_str());
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
