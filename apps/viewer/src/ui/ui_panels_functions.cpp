#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <string_view>

namespace viewer {
namespace {

[[nodiscard]] bool icontains_fn(std::string_view haystack, std::string_view needle) noexcept {
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

[[nodiscard]] bool matches_origin_filter(FunctionOrigin origin, int filter_idx) noexcept {
    switch (filter_idx) {
        case 1: return origin == FunctionOrigin::SymbolTable ||
                       origin == FunctionOrigin::DebugInfo;
        case 2: return origin == FunctionOrigin::PeRuntimePdata;
        case 3: return origin == FunctionOrigin::ExportedEntry ||
                       origin == FunctionOrigin::EntryPoint;
        case 4: return origin == FunctionOrigin::InitFiniOrTlsCallback;
        case 5: return origin == FunctionOrigin::CallTargetDiscovery;
        default: return true;
    }
}

} // namespace

FunctionsPanel::FunctionsPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Functions")
    , model_(model)
    , selection_(selection) {}

void FunctionsPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to browse functions.");
        return;
    }

    const auto& all_entries = model_.function_index().entries();
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##FnFilter", "Filter function name or VA...", filter_buf_, sizeof(filter_buf_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(155.0f);
    ImGui::Combo("##FnOrigin",
                 &origin_filter_,
                 "All Origins\0Symbols / Debug\0Unwind (.pdata/.eh_frame)\0Exports / Entry\0Callbacks (TLS/Init)\0Call Targets\0");
    ImGui::SameLine();
    bool demangle = model_.demangle_symbols();
    if (ImGui::Checkbox("Demangle", &demangle)) {
        model_.set_demangle_symbols(demangle);
        if (on_demangle_changed_) {
            on_demangle_changed_(demangle);
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu total)", all_entries.size());

    if (all_entries.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("No functions discovered for the current selection. Select an executable module or load debug symbols.");
        return;
    }

    const std::string_view filter(filter_buf_);
    std::vector<std::size_t> visible_indices;
    visible_indices.reserve(all_entries.size());
    for (std::size_t i = 0; i < all_entries.size(); ++i) {
        const FunctionEntry& fn = all_entries[i];
        if (!matches_origin_filter(fn.origin, origin_filter_)) {
            continue;
        }
        std::array<char, 32> va_hex{};
        std::snprintf(va_hex.data(), va_hex.size(), "0x%" PRIX64, fn.virtual_address);
        if (!filter.empty() &&
            !icontains_fn(fn.name, filter) &&
            (fn.demangled_name.empty() || !icontains_fn(fn.demangled_name, filter)) &&
            !icontains_fn(fn.section_name, filter) &&
            !icontains_fn(va_hex.data(), filter)) {
            continue;
        }
        visible_indices.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu function(s)  |  Click: Disassemble  |  Double-click: Decompile (F5)",
                        visible_indices.size());
    ImGui::Separator();

    if (ImGui::BeginTable("FunctionsTable",
                          5,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 132.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Origin", ImGuiTableColumnFlags_WidthStretch, 0.30f);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 86.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible_indices.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const FunctionEntry& fn = all_entries[visible_indices[static_cast<std::size_t>(row)]];
                const bool is_sel = selection_.virtual_address.has_value() &&
                                    *selection_.virtual_address >= fn.virtual_address &&
                                    (*selection_.virtual_address == fn.virtual_address ||
                                     (fn.size != 0 && (*selection_.virtual_address - fn.virtual_address) < fn.size));

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(row);
                std::array<char, 32> addr_buf{};
                std::snprintf(addr_buf.data(), addr_buf.size(), "0x%016" PRIX64, fn.virtual_address);
                if (ImGui::Selectable(addr_buf.data(),
                                      is_sel,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                    const bool want_decompile = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
                    if (on_function_activated_) {
                        on_function_activated_(fn.virtual_address, want_decompile);
                    }
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                const std::string& disp_name = fn.display_name(demangle);
                ImGui::TextUnformatted(disp_name.c_str());
                if (ImGui::IsItemHovered()) {
                    const std::string& raw = !fn.raw_name.empty() ? fn.raw_name : fn.name;
                    const SourceLineMapping* src = model_.find_source_line(fn.virtual_address, 16);
                    if (disp_name != raw && src != nullptr) {
                        ImGui::SetTooltip("Raw symbol: %s\nSource: %s:%u",
                                          raw.c_str(), src->file_path.c_str(), src->line);
                    } else if (disp_name != raw) {
                        ImGui::SetTooltip("Raw symbol: %s", raw.c_str());
                    } else if (src != nullptr) {
                        ImGui::SetTooltip("Source: %s:%u", src->file_path.c_str(), src->line);
                    }
                }

                ImGui::TableNextColumn();
                if (fn.size != 0) {
                    ImGui::Text("0x%" PRIX64, fn.size);
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                const std::string_view origin_sv = viewer::to_string(fn.origin);
                ImGui::TextDisabled("%.*s", static_cast<int>(origin_sv.size()), origin_sv.data());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(fn.section_name.empty() ? "-" : fn.section_name.c_str());
            }
        }
        ImGui::EndTable();
    }
}

} // namespace viewer
