#include "ui_panels.hpp"
#include "tools/shellcode_converter.hpp"

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <format>
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
    const bool is_live = model_.is_live_process();

    // Action toolbar
    if (ImGui::SmallButton("Undo")) {
        auto res = model_.undo_patch();
        status_message_ = res ? "Undid last staged patch." : ("Undo failed: " + res.error().message);
        if (res && on_patch_mutated_) {
            on_patch_mutated_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Redo")) {
        auto res = model_.redo_patch();
        status_message_ = res ? "Redid staged patch." : ("Redo failed: " + res.error().message);
        if (res && on_patch_mutated_) {
            on_patch_mutated_();
        }
    }

    if (is_live) {
        const auto staged_live = model_.staged_live_patches();
        const auto committed_live = model_.committed_live_patches();

        ImGui::SameLine();
        ImGui::BeginDisabled(staged_live.empty());
        if (ImGui::SmallButton("Commit to RAM")) {
            auto committed = model_.commit_patches_to_process(
                peelf::MemoryWriteOptions{.allow_protection_override = override_protection_});
            if (committed) {
                status_message_ = std::format("Committed {} patch range(s) to live process RAM.", *committed);
                if (on_patch_mutated_) {
                    on_patch_mutated_();
                }
            } else {
                status_message_ = "Commit failed: " + committed.error().message;
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Discard Staged")) {
            model_.discard_staged_patches();
            status_message_ = "Discarded all staged patches.";
            if (on_patch_mutated_) {
                on_patch_mutated_();
            }
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::BeginDisabled(committed_live.empty());
        if (ImGui::SmallButton("Revert All RAM")) {
            auto reverted = model_.revert_committed_patches(
                peelf::MemoryWriteOptions{.allow_protection_override = override_protection_});
            if (reverted) {
                status_message_ = std::format("Reverted {} committed patch range(s) in process RAM.", *reverted);
                if (on_patch_mutated_) {
                    on_patch_mutated_();
                }
            } else {
                status_message_ = "Revert failed: " + reverted.error().message;
            }
        }
        ImGui::EndDisabled();

        ImGui::Checkbox("Override RX protection on commit/revert", &override_protection_);

        if (!status_message_.empty()) {
            ImGui::TextWrapped("%s", status_message_.c_str());
        }

        ImGui::SeparatorText(std::format("Staged Patches ({})", staged_live.size()).c_str());
        if (staged_live.empty()) {
            ImGui::TextDisabled("No staged patches. Edit bytes in Hex View or Shellcode, then click 'Commit to RAM'.");
        } else if (ImGui::BeginTable("LiveStagedPatchTable",
                                     4,
                                     ImGuiTableFlags_Borders |
                                         ImGuiTableFlags_RowBg |
                                         ImGuiTableFlags_Resizable |
                                         ImGuiTableFlags_ScrollY,
                                     ImVec2(0.0f, committed_live.empty() ? 0.0f : 150.0f))) {
            ImGui::TableSetupColumn("Live VA", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 58.0f);
            ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthStretch, 0.5f);
            ImGui::TableSetupColumn("Staged", ImGuiTableColumnFlags_WidthStretch, 0.5f);
            ImGui::TableHeadersRow();

            for (std::size_t i = 0; i < staged_live.size(); ++i) {
                const peelf::PatchInterval& patch = staged_live[i];
                const ViewerSelection patch_sel = selection_from_live_patch_interval(
                    patch,
                    static_cast<std::uint64_t>(i),
                    model_.virtual_address_to_offset(patch.offset),
                    "Staged");
                const bool selected = selection_.kind == SelectionKind::Patch &&
                                      selection_.virtual_address == patch.offset;

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(i));
                std::array<char, 32> label{};
                std::snprintf(label.data(), label.size(), "0x%016" PRIX64, patch.offset);
                if (ImGui::Selectable(label.data(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    selection_ = patch_sel;
                    if (on_patch_activated_) {
                        on_patch_activated_(patch_sel);
                    }
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::Text("%zu", patch.patched.size());

                ImGui::TableNextColumn();
                const std::string orig = format_bytes(patch.original);
                ImGui::TextUnformatted(orig.c_str());

                ImGui::TableNextColumn();
                const std::string pat = format_bytes(patch.patched);
                ImGui::TextColored(ImVec4(1.0f, 0.78f, 0.25f, 1.0f), "%s", pat.c_str());
            }
            ImGui::EndTable();
        }

        if (!committed_live.empty()) {
            ImGui::SeparatorText(std::format("Committed in RAM ({})", committed_live.size()).c_str());
            if (ImGui::BeginTable("LiveCommittedPatchTable",
                                  5,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Live VA", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 52.0f);
                ImGui::TableSetupColumn("Original RAM", ImGuiTableColumnFlags_WidthStretch, 0.45f);
                ImGui::TableSetupColumn("Committed", ImGuiTableColumnFlags_WidthStretch, 0.45f);
                ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 62.0f);
                ImGui::TableHeadersRow();

                for (std::size_t i = 0; i < committed_live.size(); ++i) {
                    const peelf::PatchInterval& patch = committed_live[i];
                    const ViewerSelection patch_sel = selection_from_live_patch_interval(
                        patch,
                        static_cast<std::uint64_t>(i),
                        model_.virtual_address_to_offset(patch.offset),
                        "Committed");
                    const bool selected = selection_.kind == SelectionKind::Patch &&
                                          selection_.virtual_address == patch.offset;

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(100000 + i));
                    std::array<char, 32> label{};
                    std::snprintf(label.data(), label.size(), "0x%016" PRIX64, patch.offset);
                    if (ImGui::Selectable(label.data(), selected)) {
                        selection_ = patch_sel;
                        if (on_patch_activated_) {
                            on_patch_activated_(patch_sel);
                        }
                    }

                    ImGui::TableNextColumn();
                    ImGui::Text("%zu", patch.patched.size());

                    ImGui::TableNextColumn();
                    const std::string orig = format_bytes(patch.original);
                    ImGui::TextUnformatted(orig.c_str());

                    ImGui::TableNextColumn();
                    const std::string pat = format_bytes(patch.patched);
                    ImGui::TextColored(ImVec4(0.35f, 0.92f, 0.55f, 1.0f), "%s", pat.c_str());

                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Revert")) {
                        auto rev = model_.revert_committed_patch_at(
                            patch.offset,
                            static_cast<std::uint64_t>(patch.patched.size()),
                            peelf::MemoryWriteOptions{.allow_protection_override = override_protection_});
                        status_message_ = rev
                            ? std::format("Reverted RAM patch at 0x{:X}.", patch.offset)
                            : ("Revert failed: " + rev.error().message);
                        if (rev && on_patch_mutated_) {
                            on_patch_mutated_();
                        }
                    }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
        return;
    }

    if (!status_message_.empty()) {
        ImGui::TextWrapped("%s", status_message_.c_str());
    }

    if (!is_live) {
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
    }
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
                if (on_patch_activated_) {
                    on_patch_activated_(patch_selection);
                }
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
