#include "ui_panels.hpp"

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
    const std::vector<peelf::PatchInterval> patches = model_.changed_intervals();
    if (patches.empty()) {
        ImGui::TextDisabled("No staged patches.");
        return;
    }

    ImGui::TextDisabled("%zu staged range%s", patches.size(), patches.size() == 1 ? "" : "s");
    ImGui::Separator();

    if (ImGui::BeginTable("PatchSetTable",
                          4,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthStretch, 0.5f);
        ImGui::TableSetupColumn("Patched", ImGuiTableColumnFlags_WidthStretch, 0.5f);
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
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
