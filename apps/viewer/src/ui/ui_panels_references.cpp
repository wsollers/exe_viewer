#include "ui_panels_references.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <format>

namespace viewer {
ReferencesPanel::ReferencesPanel(const ReferenceIndex& index, AnnotationStore& annotations,
    const SymbolIndex& symbols, const ViewerSelection& selection)
    : UiPanel("References & Notes"), index_(index), annotations_(annotations), symbols_(symbols), selection_(selection) {}

void ReferencesPanel::draw_contents() {
    if (ImGui::Button("Refresh references") && rebuild_) rebuild_();
    const bool scanning = index_.is_scanning() || (scanner_ && scanner_->is_scanning());
    const bool paused = scanner_ && scanner_->is_paused();
    const bool can_resume = scanner_ && scanner_->has_resumable_work();

    if (scanning && pause_) {
        ImGui::SameLine();
        if (ImGui::Button("Pause")) pause_();
    } else if (paused && can_resume && resume_) {
        ImGui::SameLine();
        if (ImGui::Button("Resume")) resume_();
    }
    if ((index_.incomplete() || can_resume) && scan_full_) {
        ImGui::SameLine();
        if (ImGui::Button("Scan Full Binary")) scan_full_();
    }

    ImGui::SameLine();
    ImGui::Text("%zu refs | %.1f%% (%zu / %zu bytes)%s%s",
        index_.records().size(),
        index_.coverage_percent(),
        index_.scanned_bytes(),
        index_.total_executable_bytes(),
        scanning ? " | Scanning..." : (paused ? " | Paused" : ""),
        (!scanning && index_.incomplete()) ? " | Partial budget" : "");

    if (scanning || paused || index_.incomplete()) {
        const float fraction = static_cast<float>(std::clamp(index_.coverage_percent() / 100.0, 0.0, 1.0));
        const std::string overlay = std::format("{:.1f}% executable coverage", index_.coverage_percent());
        ImGui::ProgressBar(fraction, ImVec2(-1.0f, 0.0f), overlay.c_str());
    }

    ImGui::TextDisabled("Executable scan recovers direct branches/calls, guarded jump tables, and IAT/GOT pointer slots.");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##reference_filter", "Search addresses, symbols, strings, evidence, names or comments...", filter_, sizeof(filter_));
    ImGui::RadioButton("All", &direction_, 0); ImGui::SameLine();
    ImGui::RadioButton("To selection", &direction_, 1); ImGui::SameLine();
    ImGui::RadioButton("From selection", &direction_, 2); ImGui::SameLine();
    ImGui::SetNextItemWidth(190.0f);
    static constexpr std::array<const char*, 5> kConfidenceItems = {
        "All confidences",
        "Direct",
        "IndirectTable",
        "IndirectPointerSlot",
        "HeuristicConstant",
    };
    ImGui::Combo("##confidence_filter",
                 &confidence_filter_,
                 kConfidenceItems.data(),
                 static_cast<int>(kConfidenceItems.size()));

    const auto describe = [&](std::uint64_t address) {
        auto text = std::format("{:X}", address);
        if (const auto* note = annotations_.find(address); note && !note->name.empty()) text += "  " + note->name;
        else if (const auto* symbol = symbols_.find_containing_address(address)) text += "  " + symbol->name;
        return text;
    };

    if (model_ != nullptr && ImGui::CollapsingHeader("Bookmarks (Ctrl+B)", ImGuiTreeNodeFlags_DefaultOpen)) {
        const bool has_va = selection_.virtual_address.has_value();
        const bool has_off = selection_.file_offset.has_value();
        const bool can_bookmark = has_va || has_off;
        const bool bm_is_off = !has_va && has_off;
        const std::uint64_t bm_addr = has_va ? *selection_.virtual_address : selection_.file_offset.value_or(0);
        const std::optional<std::pair<std::uint64_t, bool>> active_key =
            can_bookmark ? std::optional<std::pair<std::uint64_t, bool>>{{bm_addr, bm_is_off}} : std::nullopt;

        if (editing_bookmark_key_ != active_key || bookmark_revision_ != model_->bookmark_revision()) {
            editing_bookmark_key_ = active_key;
            bookmark_revision_ = model_->bookmark_revision();
            const Bookmark* existing =
                active_key ? model_->find_bookmark(active_key->first, active_key->second) : nullptr;
            if (existing != nullptr) {
                std::snprintf(bm_label_, sizeof(bm_label_), "%s", existing->label.c_str());
                std::snprintf(bm_category_, sizeof(bm_category_), "%s", existing->category.c_str());
                std::snprintf(bm_note_, sizeof(bm_note_), "%s", existing->note.c_str());
            } else {
                const std::string fallback = !selection_.label.empty()
                                                 ? selection_.label
                                                 : (has_va ? describe(bm_addr) : std::format("off_{:X}", bm_addr));
                std::snprintf(bm_label_, sizeof(bm_label_), "%s", fallback.c_str());
                bm_category_[0] = '\0';
                bm_note_[0] = '\0';
            }
        }

        ImGui::BeginDisabled(!can_bookmark);
        ImGui::SetNextItemWidth(220.0f);
        ImGui::InputTextWithHint("##bm_label", "Bookmark label", bm_label_, sizeof(bm_label_));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(140.0f);
        ImGui::InputTextWithHint("##bm_category", "Category (e.g. Entry, Crypto)", bm_category_, sizeof(bm_category_));
        ImGui::SameLine();
        if (ImGui::Button("Save Bookmark") && can_bookmark) {
            model_->add_or_update_bookmark(Bookmark{
                .address = bm_addr,
                .is_file_offset = bm_is_off,
                .label = bm_label_,
                .category = bm_category_,
                .note = bm_note_,
            });
        }
        ImGui::SameLine();
        if (ImGui::Button("Remove Bookmark") && can_bookmark) {
            model_->remove_bookmark_at(bm_addr, bm_is_off);
        }
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##bm_note", "Optional bookmark note...", bm_note_, sizeof(bm_note_));
        ImGui::EndDisabled();

        const auto bookmarks = model_->bookmarks();
        if (!bookmarks.empty() &&
            ImGui::BeginTable("bookmarks_table",
                              5,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Label");
            ImGui::TableSetupColumn("Note");
            ImGui::TableSetupColumn("##Del", ImGuiTableColumnFlags_WidthFixed, 34.0f);
            ImGui::TableHeadersRow();

            std::optional<std::size_t> erase_idx;
            std::optional<Bookmark> jump_bm;
            for (std::size_t i = 0; i < bookmarks.size(); ++i) {
                const Bookmark& bm = bookmarks[i];
                const std::string addr_str = bm.is_file_offset
                                                 ? std::format("off+0x{:X}", bm.address)
                                                 : std::format("0x{:X}", bm.address);
                const std::string search_blob =
                    addr_str + " " + bm.category + " " + bm.label + " " + bm.note;
                if (!symbol_name_matches(search_blob, filter_)) continue;

                ImGui::PushID(static_cast<int>(i));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (ImGui::Selectable((addr_str + "##bmaddr").c_str())) {
                    jump_bm = bm;
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(bm.category.empty() ? "-" : bm.category.c_str());
                ImGui::TableNextColumn();
                if (ImGui::Selectable(((bm.label.empty() ? "<unnamed>" : bm.label) + "##bmlbl").c_str())) {
                    jump_bm = bm;
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(bm.note.c_str());
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("X")) {
                    erase_idx = i;
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
            if (erase_idx) {
                model_->remove_bookmark_index(*erase_idx);
            }
            if (jump_bm) {
                if (jump_bm->is_file_offset) {
                    if (navigate_offset_) navigate_offset_(jump_bm->address);
                } else if (navigate_) {
                    navigate_(jump_bm->address);
                }
            }
        } else if (bookmarks.empty()) {
            ImGui::TextDisabled("No bookmarks saved yet (press Ctrl+B to bookmark the current selection).");
        }
    }

    if (ImGui::CollapsingHeader("Names & comments", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Saved in .peproj v2 sessions and crash-recovery journals.");
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
    if (!ImGui::BeginTable("reference_results", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 68.0f);
    ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 130.0f);
    ImGui::TableSetupColumn("Source (click to inspect)");
    ImGui::TableSetupColumn("Target (click to follow)");
    ImGui::TableSetupColumn("Evidence / Instruction");
    ImGui::TableHeadersRow();

    const auto confidence_matches = [&](ReferenceConfidence conf) noexcept {
        switch (confidence_filter_) {
        case 1: return conf == ReferenceConfidence::Direct;
        case 2: return conf == ReferenceConfidence::IndirectTable;
        case 3: return conf == ReferenceConfidence::IndirectPointerSlot;
        case 4: return conf == ReferenceConfidence::HeuristicConstant;
        default: return true;
        }
    };

    const auto consider_ref = [&](const Reference& ref, std::vector<const Reference*>& out) {
        if (!confidence_matches(ref.confidence)) return;
        const auto source = describe(ref.source), target = describe(ref.target);
        const auto* source_note = annotations_.find(ref.source);
        const auto* target_note = annotations_.find(ref.target);
        const auto search = source + " " + target + " " + ref.instruction + " " + ref.string_preview + " " +
            ref.evidence + " " + std::string(reference_confidence_name(ref.confidence)) + " " +
            (source_note ? source_note->comment : "") + " " + (target_note ? target_note->comment : "");
        if (!symbol_name_matches(search, filter_)) return;
        out.push_back(&ref);
    };

    std::optional<std::uint64_t> next;
    std::vector<const Reference*> matches;
    if (direction_ == 1) {
        if (selection_.virtual_address) {
            const auto candidates = index_.incoming(*selection_.virtual_address, std::max<std::uint64_t>(selection_.size, 1));
            matches.reserve(candidates.size());
            for (const Reference* ref : candidates) consider_ref(*ref, matches);
        }
    } else if (direction_ == 2) {
        if (selection_.virtual_address) {
            const auto candidates = index_.outgoing(*selection_.virtual_address, std::max<std::uint64_t>(selection_.size, 1));
            matches.reserve(candidates.size());
            for (const Reference* ref : candidates) consider_ref(*ref, matches);
        }
    } else {
        for (const auto& ref : index_.records()) {
            consider_ref(ref, matches);
        }
    }

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(matches.size()));
    while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const auto& ref = *matches[static_cast<std::size_t>(row)];
        const auto source = describe(ref.source), target = describe(ref.target);
        ImGui::PushID(row); ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(reference_kind_name(ref.kind).data());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(reference_confidence_name(ref.confidence).data());
        ImGui::TableNextColumn(); if (ImGui::Selectable((source + "##source").c_str())) next = ref.source;
        ImGui::TableNextColumn(); if (ImGui::Selectable((target + "##target").c_str())) next = ref.target;
        ImGui::TableNextColumn();
        const std::string detail = !ref.string_preview.empty()
            ? (ref.evidence.empty() ? ref.string_preview : (ref.evidence + " | \"" + ref.string_preview + "\""))
            : (!ref.evidence.empty() ? (ref.evidence + " | " + ref.instruction) : ref.instruction);
        ImGui::TextUnformatted(detail.c_str());
        if (ImGui::IsItemHovered() && (!ref.evidence.empty() || !ref.instruction.empty())) {
            ImGui::BeginTooltip();
            if (!ref.evidence.empty()) ImGui::Text("Evidence: %s", ref.evidence.c_str());
            if (!ref.instruction.empty()) ImGui::Text("Instruction: %s", ref.instruction.c_str());
            if (!ref.string_preview.empty()) ImGui::Text("String: %s", ref.string_preview.c_str());
            ImGui::EndTooltip();
        }
        ImGui::PopID();
    }
    ImGui::EndTable();
    if (next && navigate_) navigate_(*next);
}
} // namespace viewe
