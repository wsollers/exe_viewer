#include "ui_panels.hpp"
#include "tools/shellcode_converter.hpp"
#include <imgui.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>
#include <format>
#include "tools/shellcode_converter.hpp"
#include "navigation/byte_range.hpp"

namespace viewer {

HexViewPanel::HexViewPanel(BinaryModel& model)
    : UiPanel("Hex View"), model_(model)
{}

void HexViewPanel::clear_selection() noexcept {
    mapped_ranges_.clear();
    selected_offset_ = 0;
    highlighted_offset_ = 0;
    highlighted_size_ = 0;
    pending_scroll_offset_.reset();
    edit_status_.clear();
}

void HexViewPanel::navigate_to_range(std::size_t file_offset, std::size_t size) {
    mapped_ranges_.clear();
    const std::uint64_t total64 = model_.view_size();
    if (total64 == 0 || file_offset >= total64) {
        clear_selection();
        return;
    }

    const std::uint64_t avail64 = total64 - static_cast<std::uint64_t>(file_offset);
    const std::size_t avail = avail64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())
                                  ? std::numeric_limits<std::size_t>::max()
                                  : static_cast<std::size_t>(avail64);
    selected_offset_ = file_offset;
    highlighted_offset_ = file_offset;
    highlighted_size_ = std::min(size, avail);
    pending_scroll_offset_ = file_offset;
    goto_offset_ = file_offset;
}

void HexViewPanel::navigate_to_ranges(std::span<const ByteRange> ranges) {
    if (ranges.empty()) { clear_selection(); return; }
    navigate_to_range(ranges.front().offset,ranges.front().size);
    for (const auto& range : ranges)
        if (range.offset<model_.view_size() && range.size && range.size<=model_.view_size()-range.offset)
            mapped_ranges_.push_back(range);
}

void HexViewPanel::draw_contents() {
    const std::uint64_t total64 = model_.view_size();
    if (total64 == 0) {
        ImGui::TextUnformatted("No data loaded.");
        return;
    }

    // Clamp displayed clipper rows to ImGui int range while keeping 64-bit offsets safe.
    const std::uint64_t row_bytes64 = static_cast<std::uint64_t>(bytes_per_row_);
    const std::uint64_t max_rows64 = static_cast<std::uint64_t>(std::numeric_limits<int>::max() - 1);
    const std::uint64_t capped_total64 = std::min(total64, max_rows64 * row_bytes64);
    const std::size_t total = static_cast<std::size_t>(capped_total64);
    const std::size_t row_bytes = bytes_per_row_;
    const int rows = static_cast<int>((capped_total64 + row_bytes64 - 1u) / row_bytes64);
    const bool is_live = model_.is_live_process();
    const std::uint64_t base_va = model_.view_base_address();
    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputScalar("Offset (hex)", ImGuiDataType_U64, &goto_offset_, nullptr, nullptr, "%" PRIX64, ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Go")) {
        if (goto_offset_ < total64) {
            navigate_to_range(static_cast<std::size_t>(goto_offset_), 1);
            if (on_byte_activated_) on_byte_activated_(highlighted_offset_, highlighted_size_);
            edit_status_.clear();
        } else edit_status_ = "Offset is outside the file.";
    }
    if (!is_live) {
        ImGui::SetNextItemWidth(std::max(100.0f, ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Apply bytes").x - 28.0f));
        ImGui::InputTextWithHint("##Replacement", "Replacement hex bytes, e.g. 00 FF", edit_bytes_, sizeof(edit_bytes_));
        ImGui::SameLine();
        ImGui::BeginDisabled(highlighted_size_ == 0 || mapped_ranges_.size() > 1);
        if (ImGui::Button("Apply bytes")) {
            const auto parsed = parse_hex_shellcode(edit_bytes_);
            if (!parsed.success || parsed.bytes.empty()) edit_status_ = "Enter valid hex bytes.";
            else {
                if (highlighted_size_ > 1 && parsed.bytes.size() != highlighted_size_) {
                    edit_status_ = "Replacement length must match the selected range.";
                } else {
                    const auto applied = model_.apply_patch_bytes(highlighted_offset_, parsed.bytes, "Hex editor replacement");
                    edit_status_ = applied ? std::format("Applied {} bytes.", parsed.bytes.size()) : applied.error().message;
                    if (applied) {
                        highlighted_size_ = parsed.bytes.size();
                        if (on_byte_activated_) on_byte_activated_(highlighted_offset_, highlighted_size_);
                    }
                }
            }
        }
        ImGui::EndDisabled();
        if (mapped_ranges_.size() > 1) {
            ImGui::TextDisabled("%zu mapped instruction ranges. Select a contiguous range to edit.", mapped_ranges_.size());
        }
    }
    if (ImGui::Button(mapped_ranges_.size()>1 ? "Copy primary range" : "Copy hex")) {
        const auto selected = model_.read_effective_bytes(highlighted_offset_, highlighted_size_);
        if (selected) {
            std::string text;
            for (const auto byte : *selected) text += std::format("{:02X} ", byte);
            ImGui::SetClipboardText(text.c_str());
        } else edit_status_ = selected.error().message;
    }
    if (on_apply_structure_) {
        ImGui::SameLine();
        if (ImGui::Button("Apply Structure...")) {
            const std::uint64_t addr = is_live
                ? (base_va + static_cast<std::uint64_t>(selected_offset_))
                : static_cast<std::uint64_t>(selected_offset_);
            on_apply_structure_(addr, !is_live);
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("0x%" PRIX64 " | %zu bytes", static_cast<std::uint64_t>(selected_offset_), highlighted_size_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Shift-click a byte to extend the selection.");
    if (!edit_status_.empty()) ImGui::TextUnformatted(edit_status_.c_str());
    ImGui::Separator();

    if (is_live) {
        ImGui::TextDisabled("Live Window (Read-Only): 0x%016" PRIX64 " .. 0x%016" PRIX64,
                            base_va,
                            base_va + total64);
    } else {
        ImGui::TextDisabled("Static File: %" PRIu64 " bytes  (right-click byte to stage patch)",
                            total64);
    }

    ImGui::BeginChild("HexScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows), ImGui::GetTextLineHeightWithSpacing());
    if (pending_scroll_offset_)
        clipper.IncludeItemByIndex(static_cast<int>(*pending_scroll_offset_ / row_bytes));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::size_t start = static_cast<std::size_t>(row) * row_bytes;
            const std::size_t end = std::min(start + row_bytes, total);
            const std::size_t len = end - start;

            std::vector<std::uint8_t> row_data(len, 0u);
            std::vector<std::uint8_t> row_valid(len, 0u);
            if (auto sample = model_.read_window_sample(start, len)) {
                row_data = std::move(sample->bytes);
                row_valid = std::move(sample->valid);
            }

            char addr[40];
            if (is_live) {
                std::snprintf(addr, sizeof(addr), "%016" PRIX64 ": ", base_va + start);
            } else {
                std::snprintf(addr, sizeof(addr), "%08zx: ", start);
            }
            ImGui::TextUnformatted(addr);
            ImGui::SameLine();

            const float hex_start = ImGui::GetCursorPosX();

            for (std::size_t i = start; i < end; ++i) {
                const std::size_t k = i - start;
                const bool valid = k < row_valid.size() && row_valid[k] != 0;
                const BytePatchState patch_state = model_.byte_patch_state_at_offset(i);

                char buf[32];
                if (valid) {
                    std::snprintf(buf, sizeof(buf), "%02X##%zu", row_data[k], i);
                } else {
                    std::snprintf(buf, sizeof(buf), "??##%zu", i);
                }

                const bool in_highlight = std::ranges::any_of(mapped_ranges_,[i](const ByteRange& range){ return i>=range.offset && i-range.offset<range.size; }) || (
                    highlighted_size_ != 0 &&
                    i >= highlighted_offset_ &&
                    i - highlighted_offset_ < highlighted_size_);
                bool selected = (i == selected_offset_) || in_highlight;
                int pushed_colors = 0;
                if (!valid) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.48f, 1.0f));
                    ++pushed_colors;
                } else if (patch_state == BytePatchState::Staged) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.78f, 0.25f, 1.0f));
                    ++pushed_colors;
                } else if (patch_state == BytePatchState::Committed) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.92f, 0.55f, 1.0f));
                    ++pushed_colors;
                }

                if (ImGui::Selectable(buf, selected, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(ImGui::CalcTextSize("FF").x, 0))) {
                    mapped_ranges_.clear();
                    if (ImGui::GetIO().KeyShift) {
                        if (const auto range = selected_byte_range(selected_offset_, i, total)) {
                            highlighted_offset_ = range->offset;
                            highlighted_size_ = range->size;
                        }
                    } else {
                        selected_offset_ = i;
                        highlighted_offset_ = i;
                        highlighted_size_ = 1;
                    }
                    if (on_byte_activated_) {
                        on_byte_activated_(highlighted_offset_, highlighted_size_);
                    }
                    if (!is_live && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && valid) {
                        quick_patch_offset_ = i;
                        std::snprintf(quick_patch_buf_, sizeof(quick_patch_buf_), "%02X", row_data[k]);
                        quick_patch_status_.clear();
                        ImGui::OpenPopup("HexQuickPatchPopup");
                    }
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected_offset_ = i;
                    highlighted_offset_ = i;
                    highlighted_size_ = 1;
                    quick_patch_offset_ = i;
                    if (valid) {
                        std::snprintf(quick_patch_buf_, sizeof(quick_patch_buf_), "%02X", row_data[k]);
                    } else {
                        quick_patch_buf_[0] = '\0';
                    }
                    quick_patch_status_.clear();
                    ImGui::OpenPopup("HexQuickPatchPopup");
                }

                if (pushed_colors > 0) {
                    ImGui::PopStyleColor(pushed_colors);
                }

                if (i + 1 < end) {
                    ImGui::SameLine(0.0f, 4.0f);
                }
            }

            const float ascii_start =
                hex_start + ImGui::CalcTextSize("00 ").x * static_cast<float>(row_bytes) + 20.0f;
            ImGui::SameLine(ascii_start);

            for (std::size_t i = start; i < end; ++i) {
                const std::size_t k = i - start;
                const bool valid = k < row_valid.size() && row_valid[k] != 0;
                char ch = '?';
                if (valid) {
                    const unsigned char c = row_data[k];
                    ch = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
                }
                if (!valid) {
                    ImGui::TextDisabled("?");
                } else {
                    ImGui::TextUnformatted(&ch, &ch + 1);
                }
                if (i + 1 < end) {
                    ImGui::SameLine(0.0f, 0.0f);
                }
            }
            if (pending_scroll_offset_ && *pending_scroll_offset_ / row_bytes == static_cast<std::size_t>(row)) {
                ImGui::SetScrollHereY(0.5f);
                pending_scroll_offset_.reset();
            }
        }
    }
    clipper.End();

    if (ImGui::BeginPopup("HexQuickPatchPopup")) {
        const std::uint64_t display_addr = is_live ? (base_va + quick_patch_offset_) : quick_patch_offset_;
        if (on_apply_structure_) {
            const std::string apply_lbl = std::format(
                "Apply Structure at {} 0x{:X}...", is_live ? "VA" : "offset", display_addr);
            if (ImGui::MenuItem(apply_lbl.c_str())) {
                on_apply_structure_(display_addr, !is_live);
                ImGui::CloseCurrentPopup();
            }
            if (!is_live) {
                ImGui::Separator();
            }
        }
        if (!is_live) {
            ImGui::Text("Stage hex bytes at offset 0x%" PRIX64, display_addr);
            ImGui::InputTextWithHint("##QuickHexBytes", "e.g. 90 90 or C3", quick_patch_buf_, sizeof(quick_patch_buf_));
            if (ImGui::Button("Stage Patch")) {
                const ShellcodeParseResult parsed = parse_hex_shellcode(quick_patch_buf_);
                if (!parsed.success || parsed.bytes.empty()) {
                    quick_patch_status_ = parsed.diagnostic;
                } else {
                    auto res = model_.apply_patch_bytes(quick_patch_offset_, parsed.bytes, "hex view inline patch");
                    if (res) {
                        if (on_bytes_patched_) {
                            on_bytes_patched_(quick_patch_offset_);
                        }
                        ImGui::CloseCurrentPopup();
                    } else {
                        quick_patch_status_ = res.error().message;
                    }
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                ImGui::CloseCurrentPopup();
            }
            if (!quick_patch_status_.empty()) {
                ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", quick_patch_status_.c_str());
            }
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

} // namespace viewer
