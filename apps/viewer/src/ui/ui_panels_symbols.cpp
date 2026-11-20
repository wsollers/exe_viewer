#include "panel_helpers.hpp"
#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {
namespace {

enum class SymbolSortCol : ImGuiID {
    Name = 0,
    Address = 1,
    Size = 2,
};

[[nodiscard]] int icase_cmp_symbols(std::string_view a, std::string_view b) noexcept {
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

SymbolsPanel::SymbolsPanel(const SymbolIndex& index, const ViewerSelection& selection, BinaryModel& model)
    : UiPanel("Functions & Names")
    , index_(index)
    , model_(model)
    , selection_(selection) {
    filter_buf_[0] = '\0';
}

void SymbolsPanel::draw_contents() {
    if (library_filter_file_ != model_.file_info().path) {
        library_filter_file_ = model_.file_info().path;
        library_filter_.clear();
    }
    if (index_.empty()) {
        ImGui::TextDisabled("No symbols.");
        return;
    }

    const bool is_64 = model_.image() == nullptr || model_.image()->is_64bit();
    const float va_col_width = is_64 ? 148.0f : 92.0f;

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##Filter", "Filter functions, names, or VA...", filter_buf_, sizeof(filter_buf_));
    const auto libraries = index_.libraries();
    if (!library_filter_.empty() && std::ranges::find(libraries, library_filter_) == libraries.end()) {
        library_filter_.clear();
    }
    ImGui::SetNextItemWidth(-ImGui::CalcTextSize("Library").x - ImGui::GetStyle().ItemInnerSpacing.x);
    if (ImGui::BeginCombo("Library", library_filter_.c_str())) {
        if (ImGui::Selectable("##AllLibraries", library_filter_.empty())) {
            library_filter_.clear();
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("All libraries (no filtering)");
        }
        for (const auto& library : libraries) {
            if (ImGui::Selectable(library.c_str(), library_filter_ == library)) {
                library_filter_ = library;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::Checkbox("Functions only", &functions_only_);
    ImGui::SameLine();
    bool demangle = model_.demangle_symbols();
    if (ImGui::Checkbox("Demangle symbols", &demangle)) {
        model_.set_demangle_symbols(demangle);
        if (on_demangle_changed_) {
            on_demangle_changed_(demangle);
        }
    }

    const std::string_view filter(filter_buf_);
    const bool has_filter = !filter.empty();
    const auto records = index_.records();
    std::optional<std::size_t> selected_index;
    for (std::size_t i = 0u; i < records.size(); ++i) {
        if (selection_.label == records[i].name &&
            selection_.virtual_address == records[i].virtual_address) {
            selected_index = i;
            break;
        }
    }
    if (!selected_index) {
        last_scrolled_selected_.reset();
    }

    std::vector<std::size_t> matches;
    matches.reserve(records.size());
    for (std::size_t i = 0u; i < records.size(); ++i) {
        const SymbolRecord& sym = records[i];
        if (!library_filter_.empty() && sym.library != library_filter_) {
            continue;
        }
        if (functions_only_ && sym.source != SymbolSource::Import &&
            !(model_.image() != nullptr && symbol_has_code(*model_.image(), sym))) {
            continue;
        }
        if (has_filter) {
            const bool name_hit =
                icontains(sym.name, filter) ||
                (!sym.raw_name.empty() && icontains(sym.raw_name, filter)) ||
                (!sym.demangled_name.empty() && icontains(sym.demangled_name, filter)) ||
                (display_name_resolver_ && icontains(display_name_resolver_(sym), filter)) ||
                (sym.virtual_address.has_value() &&
                 icontains(format_va(*sym.virtual_address, is_64), filter));
            if (!name_hit) {
                continue;
            }
        }
        matches.push_back(i);
    }

    ImGui::TextDisabled("%zu/%zu symbols", matches.size(), records.size());
    ImGui::Separator();

    if (ImGui::BeginTable("SymbolsTable",
                          3,
                          kDenseReTableFlags | ImGuiTableFlags_ScrollX)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 16.0f, static_cast<ImGuiID>(SymbolSortCol::Name));
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, va_col_width, static_cast<ImGuiID>(SymbolSortCol::Address));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 92.0f, static_cast<ImGuiID>(SymbolSortCol::Size));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiID sort_col = static_cast<ImGuiID>(SymbolSortCol::Address);
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
            std::ranges::sort(matches, [&](std::size_t ia, std::size_t ib) {
                const SymbolRecord& a = records[ia];
                const SymbolRecord& b = records[ib];
                int cmp = 0;
                switch (static_cast<SymbolSortCol>(sort_col)) {
                    case SymbolSortCol::Name: {
                        const std::string& na = a.display_name(demangle);
                        const std::string& nb = b.display_name(demangle);
                        cmp = icase_cmp_symbols(na, nb);
                        break;
                    }
                    case SymbolSortCol::Address: {
                        const bool a_has = a.virtual_address.has_value();
                        const bool b_has = b.virtual_address.has_value();
                        if (a_has != b_has) {
                            return a_has;
                        }
                        if (a_has) {
                            cmp = *a.virtual_address < *b.virtual_address
                                ? -1
                                : (*a.virtual_address > *b.virtual_address ? 1 : 0);
                        }
                        break;
                    }
                    case SymbolSortCol::Size:
                        cmp = a.size < b.size ? -1 : (a.size > b.size ? 1 : 0);
                        break;
                }
                if (cmp != 0) {
                    return ascending ? (cmp < 0) : (cmp > 0);
                }
                return ia < ib;
            });
        }

        std::optional<int> selected_row;
        if (selected_index.has_value()) {
            for (std::size_t idx = 0u; idx < matches.size(); ++idx) {
                if (matches[idx] == *selected_index &&
                    idx < static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                    selected_row = static_cast<int>(idx);
                    break;
                }
            }
        }

        std::optional<PendingEntityContextAction> pending_ctx_action;
        ImGuiListClipper clipper;
        clipper.Begin(clamp_imgui_clipper_count(matches.size()));
        if (selected_row && last_scrolled_selected_ != selected_index) {
            clipper.IncludeItemByIndex(*selected_row);
        }
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto row_id = matches[static_cast<std::size_t>(row)];
                const auto& symbol = records[row_id];

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(row_id));
                const std::string resolved_name = display_name_resolver_
                    ? display_name_resolver_(symbol)
                    : symbol.display_name(demangle);
                const std::string safe_name = resolved_name.empty()
                    ? std::string{"<unnamed>"}
                    : sanitize_single_line_control_chars(resolved_name);
                const bool selected =
                    selection_.label == symbol.name &&
                    selection_.virtual_address == symbol.virtual_address;
                if (ImGui::Selectable(safe_name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (on_symbol_activated_) {
                        on_symbol_activated_(symbol, row_id);
                    }
                }
                draw_inspectable_entity_context_menu(
                    "SymbolRowCtx",
                    model_,
                    pending_ctx_action,
                    [&]() -> InspectableEntity {
                        const bool static_img = model_has_static_image(model_);
                        const char* src_kind = "image_symbol";
                        switch (symbol.source) {
                            case SymbolSource::DebugSymbol: src_kind = "debug_symbol"; break;
                            case SymbolSource::Import:      src_kind = "import"; break;
                            case SymbolSource::Export:      src_kind = "export"; break;
                            case SymbolSource::EntryPoint:  src_kind = "entry_point"; break;
                            case SymbolSource::ImageSymbol: break;
                        }
                        return InspectableEntity{
                            .va = symbol.virtual_address,
                            .file_offset = static_img ? symbol.file_offset : std::nullopt,
                            .size = symbol.size,
                            .symbol_or_label = resolved_name,
                            .module_name = !symbol.library.empty() ? symbol.library : model_.file_info().path,
                            .extra_json_fields = {
                                {"raw_name", !symbol.raw_name.empty() ? symbol.raw_name : symbol.name},
                                {"source", src_kind},
                            },
                        };
                    });
                if (ImGui::IsItemHovered()) {
                    const std::string& raw = !symbol.raw_name.empty() ? symbol.raw_name : symbol.name;
                    const SourceLineMapping* src = symbol.virtual_address
                        ? model_.find_source_line(*symbol.virtual_address, 16)
                        : nullptr;
                    if (resolved_name != raw && src != nullptr) {
                        ImGui::SetTooltip("Raw symbol: %s\nSource: %s:%u",
                                          raw.c_str(), src->file_path.c_str(), src->line);
                    } else if (resolved_name != raw) {
                        ImGui::SetTooltip("Raw symbol: %s", raw.c_str());
                    } else if (src != nullptr) {
                        ImGui::SetTooltip("Source: %s:%u", src->file_path.c_str(), src->line);
                    }
                }
                if (selected && last_scrolled_selected_ != row_id) {
                    ImGui::SetScrollHereY(0.5f);
                    last_scrolled_selected_ = row_id;
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                if (symbol.virtual_address.has_value()) {
                    const std::string va_str = format_va(*symbol.virtual_address, is_64);
                    ImGui::TextUnformatted(va_str.c_str());
                } else {
                    ImGui::TextDisabled("Unmapped");
                }

                ImGui::TableNextColumn();
                const std::string sz_str = format_file_offset(symbol.size);
                ImGui::TextUnformatted(sz_str.c_str());
                const char* source = "Embedded";
                switch (symbol.source) {
                    case SymbolSource::DebugSymbol: source = "Debug Info (PDB/DWARF)"; break;
                    case SymbolSource::Import: source = "Import"; break;
                    case SymbolSource::Export: source = "Export"; break;
                    case SymbolSource::EntryPoint: source = "Entry point"; break;
                    case SymbolSource::ImageSymbol: break;
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Source: %s", source);
                }
            }
        }

        ImGui::EndTable();
        if (pending_ctx_action.has_value() && on_context_action_) {
            on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
        }
    }
}

} // namespace viewer
