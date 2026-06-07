//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>
#include <cstdio>

namespace viewer {

HexViewPanel::HexViewPanel(BinaryModel& model)
    : UiPanel("Hex View"), model_(model)
{}

void HexViewPanel::draw_contents() {
    const auto& bytes = model_.bytes();
    if (bytes.empty()) {
        ImGui::TextUnformatted("No data loaded.");
        return;
    }

    ImGui::BeginChild("HexScroll", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);

    const size_t total = bytes.size();
    const size_t row_bytes = bytes_per_row_;
    const size_t rows = (total + row_bytes - 1) / row_bytes;

    ImGuiListClipper clipper;
    clipper.Begin((int)rows);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            size_t start = row * row_bytes;
            size_t end = std::min(start + row_bytes, total);

            char addr[32];
            std::snprintf(addr, sizeof(addr), "%08zx: ", start);
            ImGui::TextUnformatted(addr);
            ImGui::SameLine();

            float hex_start = ImGui::GetCursorPosX();

            for (size_t i = start; i < end; ++i) {
                // The "##<offset>" suffix isn't displayed but makes each cell's
                // ImGui ID unique; without it, repeated byte values (e.g. many
                // 0x00s) collide and ImGui reports a duplicate ID.
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%02X##%zu", bytes[i], i);

                bool selected = (i == selected_offset_);
                if (ImGui::Selectable(buf, selected, ImGuiSelectableFlags_AllowDoubleClick)) {
                    selected_offset_ = i;
                    if (on_byte_activated_) {
                        on_byte_activated_(i);
                    }
                }

                if (i + 1 < end)
                    ImGui::SameLine(0.0f, 4.0f);
            }

            float ascii_start = hex_start + ImGui::CalcTextSize("00 ").x * row_bytes + 20.0f;
            ImGui::SameLine(ascii_start);

            for (size_t i = start; i < end; ++i) {
                unsigned char c = bytes[i];
                char ch = (c >= 32 && c < 127) ? (char)c : '.';
                ImGui::TextUnformatted(&ch, &ch + 1);
                if (i + 1 < end)
                    ImGui::SameLine(0.0f, 0.0f);
            }
        }
    }
    clipper.End();

    ImGui::EndChild();
}

} // namespace viewer