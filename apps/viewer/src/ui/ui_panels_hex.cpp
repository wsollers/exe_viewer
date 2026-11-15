#include "ui_panels.hpp"
#include "tools/shellcode_converter.hpp"
#include <imgui.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

namespace viewer {

HexViewPanel::HexViewPanel(BinaryModel& model)
    : UiPanel("Hex View"), model_(model)
{}

void HexViewPanel::navigate_to_range(std::size_t file_offset, std::size_t size) {
    const std::uint64_t total64 = model_.view_size();
    if (total64 == 0 || static_cast<std::uint64_t>(file_offset) >= total64) {
        selected_offset_ = 0;
        highlighted_offset_ = 0;
        highlighted_size_ = 0;
        pending_scroll_offset_.reset();
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

    if (is_live) {
        ImGui::TextDisabled("Live Window: 0x%016" PRIX64 " .. 0x%016" PRIX64 "  (double-click/right-click byte to stage patch)",
                            base_va,
                            base_va + total64);
    } else {
        ImGui::TextDisabled("Static File: %llu bytes  (right-click byte to stage patch)",
                            static_cast<unsigned long long>(total64));
    }

    ImGui::BeginChild("HexScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (pending_scroll_offset_) {
        const std::size_t row = *pending_scroll_offset_ / row_bytes;
        ImGui::SetScrollY(static_cast<float>(static_cast<double>(row) *
                                             static_cast<double>(ImGui::GetTextLineHeightWithSpacing())));
        pending_scroll_offset_.reset();
    }

    ImGuiListClipper clipper;
    clipper.Begin(rows);
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

                const bool in_highlight =
                    highlighted_size_ != 0 &&
                    i >= highlighted_offset_ &&
                    i - highlighted_offset_ < highlighted_size_;
                const bool selected = (i == selected_offset_) || in_highlight;

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

                if (ImGui::Selectable(buf, selected, ImGuiSelectableFlags_AllowDoubleClick)) {
                    selected_offset_ = i;
                    highlighted_offset_ = i;
                    highlighted_size_ = 1;
                    if (on_byte_activated_) {
                        on_byte_activated_(i);
                    }
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && valid) {
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
        }
    }
    clipper.End();

    if (ImGui::BeginPopup("HexQuickPatchPopup")) {
        const std::uint64_t display_addr = is_live ? (base_va + quick_patch_offset_) : quick_patch_offset_;
        ImGui::Text("Stage hex bytes at %s 0x%" PRIX64,
                    is_live ? "VA" : "offset",
                    display_addr);
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
        if (is_live) {
            ImGui::TextDisabled("Staged edits apply to live RAM when you click 'Commit to RAM'.");
        }
        if (!quick_patch_status_.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", quick_patch_status_.c_str());
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

} // namespace viewer
