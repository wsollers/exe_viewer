//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

#include <algorithm>
#include <cstdio>
#include <vector>
#include <format>
#include "tools/shellcode_converter.hpp"

namespace viewer {

HexViewPanel::HexViewPanel(BinaryModel& model)
    : UiPanel("Hex View"), model_(model)
{}

void HexViewPanel::navigate_to_range(std::size_t file_offset, std::size_t size) {
    const auto& bytes = model_.bytes();
    if (bytes.empty() || file_offset >= bytes.size()) {
        selected_offset_ = 0;
        highlighted_offset_ = 0;
        highlighted_size_ = 0;
        pending_scroll_offset_.reset();
        return;
    }

    selected_offset_ = file_offset;
    highlighted_offset_ = file_offset;
    highlighted_size_ = std::min(size, bytes.size() - file_offset);
    pending_scroll_offset_ = file_offset;
}

void HexViewPanel::draw_contents() {
    const auto& bytes = model_.bytes();
    if (bytes.empty()) {
        ImGui::TextUnformatted("No data loaded.");
        return;
    }

    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputScalar("Offset (hex)", ImGuiDataType_U64, &goto_offset_, nullptr, nullptr, "%llX", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Go")) {
        if (goto_offset_ < bytes.size()) {
            navigate_to_range(static_cast<std::size_t>(goto_offset_), 1);
            if (on_byte_activated_) on_byte_activated_(selected_offset_);
            edit_status_.clear();
        } else edit_status_ = "Offset is outside the file.";
    }
    ImGui::InputTextWithHint("Replacement", "Hex bytes, e.g. 00 FF", edit_bytes_, sizeof(edit_bytes_));
    ImGui::SameLine();
    if (ImGui::Button("Apply bytes")) {
        const auto parsed = parse_hex_shellcode(edit_bytes_);
        if (!parsed.success || parsed.bytes.empty()) edit_status_ = "Enter valid hex bytes.";
        else {
            const auto applied = model_.apply_patch_bytes(selected_offset_, parsed.bytes, "Hex editor replacement");
            edit_status_ = applied ? std::format("Applied {} bytes.", parsed.bytes.size()) : applied.error().message;
            if (applied && on_byte_activated_) on_byte_activated_(selected_offset_);
        }
    }
    ImGui::TextDisabled("Selected offset: 0x%llX", static_cast<unsigned long long>(selected_offset_));
    if (!edit_status_.empty()) ImGui::TextUnformatted(edit_status_.c_str());
    ImGui::Separator();
    ImGui::BeginChild("HexScroll", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);

    const size_t total = bytes.size();
    const size_t row_bytes = bytes_per_row_;
    const size_t rows = (total + row_bytes - 1) / row_bytes;

    if (pending_scroll_offset_) {
        const std::size_t row = *pending_scroll_offset_ / row_bytes;
        ImGui::SetScrollY(static_cast<float>(row) * ImGui::GetTextLineHeightWithSpacing());
        pending_scroll_offset_.reset();
    }

    ImGuiListClipper clipper;
    clipper.Begin((int)rows);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            size_t start = row * row_bytes;
            size_t end = std::min(start + row_bytes, total);
            std::vector<std::uint8_t> row_data;
            if (auto effective = model_.read_effective_bytes(start, end - start)) {
                row_data = std::move(*effective);
            } else {
                row_data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(start),
                                bytes.begin() + static_cast<std::ptrdiff_t>(end));
            }

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
                std::snprintf(buf, sizeof(buf), "%02X##%zu", row_data[i - start], i);

                const bool in_highlight =
                    highlighted_size_ != 0 &&
                    i >= highlighted_offset_ &&
                    i - highlighted_offset_ < highlighted_size_;
                bool selected = (i == selected_offset_) || in_highlight;
                if (ImGui::Selectable(buf, selected, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(ImGui::CalcTextSize("FF").x, 0))) {
                    selected_offset_ = i;
                    highlighted_offset_ = i;
                    highlighted_size_ = 1;
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
                unsigned char c = row_data[i - start];
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
