#include "ui_panels.hpp"
#include "navigation/byte_range.hpp"
#include "tools/shellcode_converter.hpp"
#include <imgui.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <format>
#include <limits>
#include <string>
#include <vector>

namespace viewer {
namespace {

[[nodiscard]] constexpr std::uint64_t saturating_add_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return b > std::numeric_limits<std::uint64_t>::max() - a
               ? std::numeric_limits<std::uint64_t>::max()
               : (a + b);
}

[[nodiscard]] constexpr char printable_ascii_preview(std::uint8_t byte) noexcept {
    return (byte >= 32u && byte < 127u) ? static_cast<char>(byte) : '.';
}

} // namespace

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
    unavailable_reason_.clear();
}

void HexViewPanel::set_unavailable_reason(std::string reason) {
    mapped_ranges_.clear();
    highlighted_size_ = 0;
    pending_scroll_offset_.reset();
    unavailable_reason_ = std::move(reason);
}

void HexViewPanel::navigate_to_range(std::uint64_t file_offset, std::uint64_t size) {
    mapped_ranges_.clear();
    const std::uint64_t total64 = model_.view_size();
    if (total64 == 0 || file_offset >= total64) {
        clear_selection();
        if (total64 > 0 && size > 0) {
            unavailable_reason_ = std::format(
                "Offset +0x{:X} ({} bytes) is outside the file-backed range (0x{:X} bytes).",
                file_offset,
                size,
                total64);
        }
        return;
    }

    unavailable_reason_.clear();
    const std::uint64_t avail64 = total64 - file_offset;
    selected_offset_ = file_offset;
    highlighted_offset_ = file_offset;
    highlighted_size_ = std::min(size, avail64);
    pending_scroll_offset_ = file_offset;
    goto_offset_ = file_offset;
}

void HexViewPanel::navigate_to_ranges(std::span<const ByteRange> ranges) {
    if (ranges.empty()) { clear_selection(); return; }
    navigate_to_range(ranges.front().offset, ranges.front().size);
    const std::uint64_t total64 = model_.view_size();
    for (const auto& range : ranges) {
        if (range.offset < total64 && range.size != 0 && range.size <= total64 - range.offset) {
            mapped_ranges_.push_back(range);
        }
    }
}

void HexViewPanel::draw_contents() {
    const std::uint64_t total64 = model_.view_size();
    if (total64 == 0) {
        if (!unavailable_reason_.empty()) {
            ImGui::TextColored(ImVec4(0.95f, 0.76f, 0.35f, 1.0f),
                               "(Hex Not Available — virtual/unmapped range)");
            ImGui::TextWrapped("%s", unavailable_reason_.c_str());
        } else {
            ImGui::TextUnformatted("No data loaded.");
        }
        return;
    }

    // Clamp displayed clipper rows to ImGui int range while keeping 64-bit offsets safe.
    const std::uint64_t row_bytes64 = std::max<std::uint64_t>(1u, static_cast<std::uint64_t>(bytes_per_row_));
    const std::size_t row_bytes = static_cast<std::size_t>(row_bytes64);
    const std::uint64_t max_rows64 = static_cast<std::uint64_t>(std::numeric_limits<int>::max() - 1);
    const std::uint64_t capped_total64 = std::min(total64, max_rows64 * row_bytes64);
    const int rows = static_cast<int>((capped_total64 + (row_bytes64 - 1u)) / row_bytes64);
    const bool is_live = model_.is_live_process();
    const std::uint64_t base_va = model_.view_base_address();

    // Address column display mode selector (File Offset / RVA / VA)
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Addr:");
    ImGui::SameLine(0.0f, 4.0f);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 7.2f);
    {
        const char* const addr_mode_labels[] = {"File Offset", "RVA", "VA"};
        int ui_mode_idx = (address_mode_ == AddressDisplayMode::FileOffset)
            ? 0
            : (address_mode_ == AddressDisplayMode::RelativeVirtualAddress ? 1 : 2);
        if (ImGui::Combo("##HexAddrMode", &ui_mode_idx, addr_mode_labels, 3)) {
            address_mode_ = (ui_mode_idx == 0)
                ? AddressDisplayMode::FileOffset
                : (ui_mode_idx == 1 ? AddressDisplayMode::RelativeVirtualAddress
                                    : AddressDisplayMode::VirtualAddress);
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Address column mode (gracefully falls back to +Offset outside mapped sections)");
        }
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0f);
    const char* const goto_label =
        address_mode_ == AddressDisplayMode::VirtualAddress
            ? "VA (hex)"
            : (address_mode_ == AddressDisplayMode::RelativeVirtualAddress ? "RVA (hex)" : "Offset (hex)");
    ImGui::InputScalar(goto_label, ImGuiDataType_U64, &goto_offset_, nullptr, nullptr, "%" PRIX64, ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Go")) {
        std::optional<std::uint64_t> resolved_off;
        if (address_mode_ == AddressDisplayMode::VirtualAddress) {
            resolved_off = model_.virtual_address_to_offset(goto_offset_);
        } else if (address_mode_ == AddressDisplayMode::RelativeVirtualAddress) {
            const std::uint64_t img_base =
                model_.image() != nullptr ? model_.image()->image_base() : base_va;
            if (goto_offset_ <= std::numeric_limits<std::uint64_t>::max() - img_base) {
                resolved_off = model_.virtual_address_to_offset(img_base + goto_offset_);
            }
        } else if (goto_offset_ < total64) {
            resolved_off = goto_offset_;
        }

        if (resolved_off.has_value() && *resolved_off < total64) {
            navigate_to_range(*resolved_off, 1);
            if (on_byte_activated_) on_byte_activated_(highlighted_offset_, highlighted_size_);
            edit_status_.clear();
        } else {
            edit_status_ = "Target address/offset is unmapped or outside the file.";
        }
    }
    if (!is_live) {
        ImGui::SetNextItemWidth(std::max(100.0f, ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Apply bytes").x - 28.0f));
        ImGui::InputTextWithHint("##Replacement", "Replacement hex bytes, e.g. 00 FF", edit_bytes_, sizeof(edit_bytes_));
        ImGui::SameLine();
        ImGui::BeginDisabled(!unavailable_reason_.empty() || highlighted_size_ == 0 || mapped_ranges_.size() > 1);
        if (ImGui::Button("Apply bytes")) {
            const auto parsed = parse_hex_shellcode(edit_bytes_);
            if (!parsed.success || parsed.bytes.empty()) edit_status_ = "Enter valid hex bytes.";
            else {
                if (highlighted_size_ > 1 && static_cast<std::uint64_t>(parsed.bytes.size()) != highlighted_size_) {
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
    ImGui::BeginDisabled(!unavailable_reason_.empty() || highlighted_size_ == 0);
    if (ImGui::Button(mapped_ranges_.size() > 1 ? "Copy primary range" : "Copy hex")) {
        constexpr std::uint64_t kMaxCopyBytes = 16u * 1024u * 1024u;
        const auto copy_len = static_cast<std::size_t>(
            std::min<std::uint64_t>(highlighted_size_,
                                    std::min<std::uint64_t>(kMaxCopyBytes,
                                                            std::numeric_limits<std::size_t>::max())));
        const auto selected = model_.read_effective_bytes(highlighted_offset_, copy_len);
        if (selected) {
            std::string text;
            for (const auto byte : *selected) text += std::format("{:02X} ", byte);
            ImGui::SetClipboardText(text.c_str());
        } else edit_status_ = selected.error().message;
    }
    ImGui::EndDisabled();
    if (on_apply_structure_) {
        ImGui::SameLine();
        if (ImGui::Button("Apply Structure...")) {
            const std::uint64_t addr = is_live
                ? saturating_add_u64(base_va, selected_offset_)
                : selected_offset_;
            on_apply_structure_(addr, !is_live);
        }
    }
    ImGui::SameLine();
    if (unavailable_reason_.empty()) {
        ImGui::TextDisabled("0x%" PRIX64 " | %" PRIu64 " bytes", selected_offset_, highlighted_size_);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Shift-click a byte to extend the selection.");
    } else {
        ImGui::TextColored(ImVec4(0.95f, 0.76f, 0.35f, 1.0f), "(virtual / unmapped selection)");
    }
    if (!edit_status_.empty()) ImGui::TextUnformatted(edit_status_.c_str());
    ImGui::Separator();

    if (is_live) {
        ImGui::TextDisabled("Live Window (Read-Only): 0x%016" PRIX64 " .. 0x%016" PRIX64,
                            base_va,
                            saturating_add_u64(base_va, total64));
    } else {
        ImGui::TextDisabled("Static File: %" PRIu64 " bytes  (right-click byte to stage patch; amber=Staged, emerald=Committed)",
                            total64);
    }

    ImGui::BeginChild("HexScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (!unavailable_reason_.empty()) {
        const ImVec2 avail = ImGui::GetContentRegionAvail();
        const char* const banner = "(Hex Not Available — virtual/unmapped range)";
        const ImVec2 banner_sz = ImGui::CalcTextSize(banner);
        const float top_pad = std::max(18.0f, (avail.y - 96.0f) * 0.42f);
        ImGui::Dummy(ImVec2(1.0f, top_pad));
        ImGui::SetCursorPosX(std::max(12.0f, (avail.x - banner_sz.x) * 0.5f));
        ImGui::TextColored(ImVec4(0.96f, 0.78f, 0.36f, 1.0f), "%s", banner);

        const float wrap_w = std::min(560.0f, std::max(220.0f, avail.x - 40.0f));
        const ImVec2 detail_sz = ImGui::CalcTextSize(unavailable_reason_.c_str(), nullptr, false, wrap_w);
        ImGui::SetCursorPosX(std::max(12.0f, (avail.x - std::min(wrap_w, detail_sz.x)) * 0.5f));
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap_w);
        ImGui::TextDisabled("%s", unavailable_reason_.c_str());
        ImGui::PopTextWrapPos();

        ImGui::Spacing();
        const char* const btn_lbl = "Return to Backed Hex View";
        const float btn_w = ImGui::CalcTextSize(btn_lbl).x + ImGui::GetStyle().FramePadding.x * 2.0f;
        ImGui::SetCursorPosX(std::max(12.0f, (avail.x - btn_w) * 0.5f));
        if (ImGui::Button(btn_lbl)) {
            unavailable_reason_.clear();
        }
        ImGui::EndChild();
        return;
    }

    const AddressDisplayMode effective_addr_mode =
        (is_live && address_mode_ == AddressDisplayMode::FileOffset)
            ? AddressDisplayMode::VirtualAddress
            : address_mode_;

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 cell_size(ImGui::CalcTextSize("FF").x, ImGui::GetTextLineHeight());

    ImGuiListClipper clipper;
    clipper.Begin(rows, ImGui::GetTextLineHeightWithSpacing());
    if (pending_scroll_offset_) {
        const std::uint64_t target_row64 = *pending_scroll_offset_ / row_bytes64;
        if (target_row64 < static_cast<std::uint64_t>(rows)) {
            clipper.IncludeItemByIndex(static_cast<int>(target_row64));
        } else {
            pending_scroll_offset_.reset();
        }
    }
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::uint64_t start = static_cast<std::uint64_t>(row) * row_bytes64;
            const std::uint64_t end = std::min(start + row_bytes64, capped_total64);
            const auto len = static_cast<std::size_t>(end - start);

            std::vector<std::uint8_t> row_data(len, 0u);
            std::vector<std::uint8_t> row_valid(len, 0u);
            if (auto sample = model_.read_window_sample(start, len)) {
                row_data = std::move(sample->bytes);
                row_valid = std::move(sample->valid);
            }

            const std::string addr_col =
                format_hex_row_address(effective_addr_mode, start, model_) + ": ";
            ImGui::TextUnformatted(addr_col.c_str());
            ImGui::SameLine();

            const float hex_start = ImGui::GetCursorPosX();

            for (std::uint64_t i = start; i < end; ++i) {
                const auto k = static_cast<std::size_t>(i - start);
                const bool valid = k < row_valid.size() && row_valid[k] != 0;
                const BytePatchState patch_state = model_.byte_patch_state_at_offset(i);

                char hex_text[4];
                char buf[32];
                if (valid) {
                    std::snprintf(hex_text, sizeof(hex_text), "%02X", row_data[k]);
                    std::snprintf(buf, sizeof(buf), "%02X##%" PRIx64, row_data[k], i);
                } else {
                    std::snprintf(hex_text, sizeof(hex_text), "??");
                    std::snprintf(buf, sizeof(buf), "??##%" PRIx64, i);
                }

                const ImVec2 cell_min = ImGui::GetCursorScreenPos();
                const ImVec2 cell_max(cell_min.x + cell_size.x + 2.0f, cell_min.y + cell_size.y + 1.0f);
                if (valid && patch_state == BytePatchState::Staged) {
                    draw_list->AddRectFilled(
                        ImVec2(cell_min.x - 1.5f, cell_min.y - 0.5f),
                        cell_max,
                        IM_COL32(235, 165, 30, 62),
                        2.0f);
                    draw_list->AddRect(
                        ImVec2(cell_min.x - 1.5f, cell_min.y - 0.5f),
                        cell_max,
                        IM_COL32(255, 196, 62, 150),
                        2.0f);
                } else if (valid && patch_state == BytePatchState::Committed) {
                    draw_list->AddRectFilled(
                        ImVec2(cell_min.x - 1.5f, cell_min.y - 0.5f),
                        cell_max,
                        IM_COL32(36, 188, 108, 54),
                        2.0f);
                    draw_list->AddRect(
                        ImVec2(cell_min.x - 1.5f, cell_min.y - 0.5f),
                        cell_max,
                        IM_COL32(72, 228, 140, 140),
                        2.0f);
                }

                const bool in_highlight =
                    std::ranges::any_of(mapped_ranges_, [i](const ByteRange& range) {
                        return i >= range.offset && i - range.offset < range.size;
                    }) ||
                    (highlighted_size_ != 0 &&
                     i >= highlighted_offset_ &&
                     i - highlighted_offset_ < highlighted_size_);
                const bool selected = (i == selected_offset_) || in_highlight;
                int pushed_colors = 0;
                if (!valid) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.48f, 1.0f));
                    ++pushed_colors;
                } else if (patch_state == BytePatchState::Staged) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.86f, 0.30f, 1.0f));
                    ++pushed_colors;
                } else if (patch_state == BytePatchState::Committed) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.42f, 0.96f, 0.62f, 1.0f));
                    ++pushed_colors;
                }

                if (ImGui::Selectable(buf, selected, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(cell_size.x, 0))) {
                    mapped_ranges_.clear();
                    if (ImGui::GetIO().KeyShift) {
                        if (const auto range = selected_byte_range(selected_offset_, i, capped_total64)) {
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

                // Bold weight accent overdraw for Staged patch bytes
                if (valid && patch_state == BytePatchState::Staged) {
                    draw_list->AddText(
                        ImVec2(cell_min.x + 0.65f, cell_min.y),
                        IM_COL32(255, 224, 96, 210),
                        hex_text);
                }

                if (valid && patch_state != BytePatchState::Unchanged && ImGui::IsItemHovered()) {
                    const std::uint8_t patched_val = row_data[k];
                    const std::uint8_t orig_val = model_.original_byte_at_offset(i).value_or(patched_val);
                    const auto va_opt = model_.offset_to_virtual_address(i);
                    const std::uint64_t img_base =
                        model_.image() != nullptr ? model_.image()->image_base() : base_va;

                    ImGui::BeginTooltip();
                    if (patch_state == BytePatchState::Staged) {
                        ImGui::TextColored(ImVec4(1.0f, 0.84f, 0.28f, 1.0f), "Staged Patch Byte");
                    } else {
                        ImGui::TextColored(ImVec4(0.42f, 0.96f, 0.62f, 1.0f), "Committed Patch Byte");
                    }
                    ImGui::Separator();
                    ImGui::Text("Original byte (0x%02X) -> Patched byte (0x%02X)", orig_val, patched_val);
                    ImGui::Text("ASCII: '%c' -> '%c'",
                                printable_ascii_preview(orig_val),
                                printable_ascii_preview(patched_val));
                    if (va_opt.has_value()) {
                        if (*va_opt >= img_base) {
                            ImGui::TextDisabled("VA: 0x%" PRIX64 "  |  RVA: +0x%" PRIX64 "  |  Offset: +0x%" PRIX64,
                                                *va_opt,
                                                *va_opt - img_base,
                                                i);
                        } else {
                            ImGui::TextDisabled("VA: 0x%" PRIX64 "  |  Offset: +0x%" PRIX64,
                                                *va_opt,
                                                i);
                        }
                    } else {
                        ImGui::TextDisabled("File Offset: +0x%" PRIX64 " (unmapped header/overlay)", i);
                    }
                    ImGui::EndTooltip();
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

            for (std::uint64_t i = start; i < end; ++i) {
                const auto k = static_cast<std::size_t>(i - start);
                const bool valid = k < row_valid.size() && row_valid[k] != 0;
                const BytePatchState patch_state = model_.byte_patch_state_at_offset(i);
                char ch = '?';
                if (valid) {
                    ch = printable_ascii_preview(row_data[k]);
                }
                if (!valid) {
                    ImGui::TextDisabled("?");
                } else if (patch_state == BytePatchState::Staged) {
                    ImGui::TextColored(ImVec4(1.0f, 0.84f, 0.28f, 1.0f), "%c", ch);
                } else if (patch_state == BytePatchState::Committed) {
                    ImGui::TextColored(ImVec4(0.42f, 0.96f, 0.62f, 1.0f), "%c", ch);
                } else {
                    ImGui::TextUnformatted(&ch, &ch + 1);
                }
                if (i + 1 < end) {
                    ImGui::SameLine(0.0f, 0.0f);
                }
            }
            if (pending_scroll_offset_ &&
                (*pending_scroll_offset_ / row_bytes64) == static_cast<std::uint64_t>(row)) {
                ImGui::SetScrollHereY(0.5f);
                pending_scroll_offset_.reset();
            }
        }
    }
    clipper.End();

    if (ImGui::BeginPopup("HexQuickPatchPopup")) {
        const std::uint64_t display_addr =
            is_live ? saturating_add_u64(base_va, quick_patch_offset_) : quick_patch_offset_;
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
