#include "ui_panels.hpp"
#include "tools/shellcode_converter.hpp"

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

#include <imgui.h>

namespace viewer {
namespace {

[[nodiscard]] std::string format_bytes(const std::vector<std::uint8_t>& bytes) {
    constexpr std::size_t max_visible = 8;
    std::string output;
    const std::size_t count = std::min(max_visible, bytes.size());
    for (std::size_t i = 0; i < count; ++i) {
        std::array<char, 4> buffer{};
        std::snprintf(buffer.data(), buffer.size(), "%02X", bytes[i]);
        if (!output.empty()) {
            output += ' ';
        }
        output += buffer.data();
    }
    if (bytes.size() > max_visible) {
        output += " ...";
    }
    return output;
}

} // namespace

PatchSetPanel::PatchSetPanel(BinaryModel& model, ViewerSelection& selection)
    : UiPanel("Patch Set"), model_(model), selection_(selection) {}

void PatchSetPanel::draw_contents() {
    ImGui::TextDisabled("Preview a fixed-size replacement at the selected file offset.");
    ImGui::SetNextItemWidth(-1);
    if (ImGui::InputTextWithHint("##patch_bytes", "Replacement bytes, e.g. 90 90", replacement_, sizeof(replacement_))) preview_.reset();
    if (ImGui::Button("Preview replacement")) {
        auto parsed = parse_hex_shellcode(replacement_);
        if (!parsed.success || parsed.bytes.empty() || !selection_.file_offset || !symbols_) {
            status_ = "Select file bytes and enter a valid hexadecimal replacement."; preview_.reset();
        } else {
            auto result = preview_patch(model_, *symbols_, *selection_.file_offset, parsed.bytes, thumb_ && *thumb_);
            if (result) { preview_ = std::move(*result); status_ = "Preview ready; source file remains unchanged."; }
            else { status_ = result.error().message; preview_.reset(); }
        }
    }
    if (preview_) {
        ImGui::Text("Preview offset: 0x%llX | %zu bytes", static_cast<unsigned long long>(preview_->offset), preview_->replacement.size());
        ImGui::TextWrapped("%s", preview_->boundary.c_str());
        if (ImGui::BeginTable("patch_comparison", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Before (current effective code)"); ImGui::TableSetupColumn("After replacement"); ImGui::TableHeadersRow();
            ImGui::TableNextRow();
            for (const auto* graph : {&preview_->before, &preview_->after}) {
                ImGui::TableNextColumn();
                ImGui::Text("%zu blocks/nodes | %zu flow edges", graph->nodes.size(), graph->edges.size());
                ImGui::BeginChild(graph == &preview_->before ? "before_code" : "after_code", ImVec2(0, 210), false, ImGuiWindowFlags_HorizontalScrollbar);
                for (const auto& node : graph->nodes) {
                    ImGui::TextDisabled("%s", node.label.c_str());
                    for (const auto& instruction : node.instructions)
                        ImGui::Text("%llX  %s %s", static_cast<unsigned long long>(instruction.address), instruction.mnemonic.c_str(), instruction.operands.c_str());
                }
                for (const auto& edge : graph->edges) ImGui::TextDisabled("%s -> %s (%s)", edge.from_node_id.c_str(), edge.to_node_id.c_str(), edge.label.c_str());
                ImGui::EndChild();
            }
            ImGui::EndTable();
        }
        ImGui::BeginDisabled(preview_->revision != model_.edit_revision());
        if (ImGui::Button("Apply reviewed replacement")) {
            auto result = apply_preview(model_, *preview_); status_ = result ? "Replacement staged. Undo is available." : result.error().message;
            preview_.reset();
        }
        ImGui::EndDisabled();
        if (preview_ && preview_->revision != model_.edit_revision()) ImGui::TextDisabled("Bytes changed; preview again before applying.");
    }
    ImGui::Separator();
    const auto* editable = model_.editable_image();
    ImGui::BeginDisabled(!editable || !editable->can_undo());
    if (ImGui::Button("Undo")) {
        const auto result = model_.undo_patch();
        status_ = result ? "Patch undone." : result.error().message;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!editable || !editable->can_redo());
    if (ImGui::Button("Redo")) {
        const auto result = model_.redo_patch();
        status_ = result ? "Patch redone." : result.error().message;
    }
    ImGui::EndDisabled();
    ImGui::TextDisabled("Export with File > Save Patched As...");
    if (!status_.empty()) ImGui::TextUnformatted(status_.c_str());
    const std::vector<peelf::PatchInterval> patches = model_.changed_intervals();
    if (patches.empty()) {
        ImGui::TextDisabled("No staged patches.");
        return;
    }

    ImGui::TextDisabled("%zu staged range%s", patches.size(), patches.size() == 1 ? "" : "s");
    ImGui::Separator();

    if (ImGui::BeginTable("PatchSetTable",
                          5,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthStretch, 0.5f);
        ImGui::TableSetupColumn("Patched", ImGuiTableColumnFlags_WidthStretch, 0.5f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < patches.size(); ++i) {
            const peelf::PatchInterval& patch = patches[i];
            const ViewerSelection patch_selection =
                selection_from_patch_interval(patch, static_cast<std::uint64_t>(i));
            const bool selected = selection_.kind == SelectionKind::Patch &&
                                  selection_.object_index == static_cast<std::uint64_t>(i) &&
                                  selection_.file_offset == patch.offset;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            std::array<char, 32> label{};
            std::snprintf(label.data(), label.size(), "0x%08" PRIX64, patch.offset);
            if (ImGui::Selectable(label.data(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                selection_ = patch_selection;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::Text("%zu", patch.patched.size());

            ImGui::TableNextColumn();
            const std::string original = format_bytes(patch.original);
            ImGui::TextUnformatted(original.c_str());

            ImGui::TableNextColumn();
            const std::string patched = format_bytes(patch.patched);
            ImGui::TextUnformatted(patched.c_str());
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::SmallButton("Revert")) {
                const auto result = model_.apply_patch_bytes(patch.offset, patch.original, "Revert patch range");
                status_ = result ? "Range restored; Undo can recover it." : result.error().message;
            }
            ImGui::PopID();
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
