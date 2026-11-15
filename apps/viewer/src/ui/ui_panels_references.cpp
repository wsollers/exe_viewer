#include "ui_panels_references.hpp"
#include <algorithm>
#include <cstdio>
#include <format>

namespace viewer {
ReferencesPanel::ReferencesPanel(const ReferenceIndex& index, AnnotationStore& annotations,
    const SymbolIndex& symbols, const ViewerSelection& selection)
    : UiPanel("References & Notes"), index_(index), annotations_(annotations), symbols_(symbols), selection_(selection) {}

void ReferencesPanel::draw_contents() {
    if (ImGui::Button("Refresh references") && rebuild_) rebuild_();
    ImGui::SameLine();
    ImGui::Text("%zu refs | %zu bytes scanned%s", index_.records().size(), index_.scanned_bytes(),
        index_.incomplete() ? " | Partial coverage" : "");
    ImGui::TextDisabled("Static executable-section scan; register-dependent targets are unresolved.");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##reference_filter", "Search addresses, symbols, strings, names or comments...", filter_, sizeof(filter_));
    ImGui::RadioButton("All", &direction_, 0); ImGui::SameLine();
    ImGui::RadioButton("To selection", &direction_, 1); ImGui::SameLine();
    ImGui::RadioButton("From selection", &direction_, 2);

    const auto describe = [&](std::uint64_t address) {
        auto text = std::format("{:X}", address);
        if (const auto* note = annotations_.find(address); note && !note->name.empty()) text += "  " + note->name;
        else if (const auto* symbol = symbols_.find_containing_address(address)) text += "  " + symbol->name;
        return text;
    };
    if (ImGui::CollapsingHeader("Names & comments", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Session only: annotations are cleared when another binary is loaded.");
        if (editing_address_ != selection_.virtual_address || annotation_revision_ != annotations_.revision()) {
            editing_address_ = selection_.virtual_address;
            annotation_revision_ = annotations_.revision();
            const auto* note = editing_address_ ? annotations_.find(*editing_address_) : nullptr;
            std::snprintf(name_, sizeof(name_), "%s", note ? note->name.c_str() : "");
            std::snprintf(comment_, sizeof(comment_), "%s", note ? note->comment.c_str() : "");
        }
        ImGui::BeginDisabled(!editing_address_);
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##user_name", "Name for selected address", name_, sizeof(name_));
        ImGui::InputTextMultiline("##user_comment", comment_, sizeof(comment_), ImVec2(-1, ImGui::GetTextLineHeight() * 3));
        if (ImGui::Button("Save annotation") && editing_address_) annotations_.set(*editing_address_, name_, comment_);
        ImGui::SameLine();
        if (ImGui::Button("Clear annotation") && editing_address_) {
            annotations_.set(*editing_address_, {}, {}); name_[0] = 0; comment_[0] = 0;
        }
        ImGui::EndDisabled();
        if (ImGui::TreeNode("Saved annotations")) {
            for (const auto& [address, note] : annotations_.records()) {
                const auto label = describe(address) + "  " + note.comment;
                if (!symbol_name_matches(label, filter_)) continue;
                if (ImGui::Selectable(label.c_str()) && navigate_) navigate_(address);
            }
            ImGui::TreePop();
        }
    }
    ImGui::Separator();
    if (!ImGui::BeginTable("reference_results", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupColumn("Kind"); ImGui::TableSetupColumn("Source (click to inspect)");
    ImGui::TableSetupColumn("Target (click to follow)"); ImGui::TableSetupColumn("Instruction / string");
    ImGui::TableHeadersRow();
    std::optional<std::uint64_t> next;
    std::vector<const Reference*> matches;
    for (const auto& ref : index_.records()) {
        const auto address = direction_ == 1 ? ref.target : ref.source;
        if (direction_ && (!selection_.virtual_address || address < *selection_.virtual_address ||
            address - *selection_.virtual_address >= std::max<std::uint64_t>(selection_.size, 1))) continue;
        const auto source = describe(ref.source), target = describe(ref.target);
        const auto* source_note = annotations_.find(ref.source);
        const auto* target_note = annotations_.find(ref.target);
        const auto search = source + " " + target + " " + ref.instruction + " " + ref.string_preview + " " +
            (source_note ? source_note->comment : "") + " " + (target_note ? target_note->comment : "");
        if (!symbol_name_matches(search, filter_)) continue;
        matches.push_back(&ref);
    }
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(matches.size()));
    while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const auto& ref = *matches[static_cast<std::size_t>(row)];
        const auto source = describe(ref.source), target = describe(ref.target);
        ImGui::PushID(row); ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(reference_kind_name(ref.kind).data());
        ImGui::TableNextColumn(); if (ImGui::Selectable((source + "##source").c_str())) next = ref.source;
        ImGui::TableNextColumn(); if (ImGui::Selectable((target + "##target").c_str())) next = ref.target;
        ImGui::TableNextColumn(); ImGui::TextUnformatted((ref.string_preview.empty() ? ref.instruction : ref.string_preview).c_str());
        ImGui::PopID();
    }
    ImGui::EndTable();
    if (next && navigate_) navigate_(*next);
}
} // namespace viewer
