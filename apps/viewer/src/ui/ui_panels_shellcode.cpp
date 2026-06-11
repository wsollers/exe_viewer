#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <span>

#include "tools/shellcode_converter.hpp"

namespace viewer {

ShellcodeScratchPanel::ShellcodeScratchPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Shellcode"), model_(model), selection_(selection)
{
    diagnostic_ = "Paste hex bytes or shellcode text.";
}

void ShellcodeScratchPanel::rebuild_output() {
    output_bytes_.clear();
    hex_view_.clear();

    if (assembly_mode_) {
        diagnostic_ = "Assembly input requires an assembler backend. Keystone integration is tracked in P6-23.";
        return;
    }

    const ShellcodeParseResult parsed = parse_hex_shellcode(input_buf_);
    output_bytes_ = parsed.bytes;
    diagnostic_ = parsed.diagnostic;
    if (parsed.success) {
        hex_view_ = format_shellcode_hex_view(std::span<const std::uint8_t>(output_bytes_.data(), output_bytes_.size()));
    }
}

void ShellcodeScratchPanel::draw_hex_output() const {
    if (hex_view_.empty()) {
        ImGui::TextDisabled("%s", diagnostic_.c_str());
        return;
    }

    ImGui::TextDisabled("%zu bytes", output_bytes_.size());
    ImGui::Separator();
    ImGui::TextUnformatted(hex_view_.c_str());
}

std::optional<std::uint64_t> ShellcodeScratchPanel::selected_file_offset() const {
    if (selection_.file_offset) {
        return selection_.file_offset;
    }
    const peelf::IBinaryImage* image = model_.image();
    if (image != nullptr && selection_.virtual_address) {
        return image->virtual_address_to_file_offset(*selection_.virtual_address);
    }
    return std::nullopt;
}

void ShellcodeScratchPanel::apply_to_selection() {
    if (output_bytes_.empty()) {
        diagnostic_ = "No bytes to apply.";
        return;
    }

    const std::optional<std::uint64_t> offset = selected_file_offset();
    if (!offset) {
        diagnostic_ = "Select file-backed bytes before applying shellcode.";
        return;
    }

    const std::string label = selection_.label.empty()
        ? "shellcode scratch patch"
        : std::format("shellcode scratch patch: {}", selection_.label);
    auto applied = model_.apply_patch_bytes(*offset, output_bytes_, label);
    if (!applied) {
        diagnostic_ = std::format("Patch failed: {}", applied.error().message);
        return;
    }

    diagnostic_ = std::format("Applied {} bytes at file offset 0x{:X}.", output_bytes_.size(), *offset);
}

void ShellcodeScratchPanel::draw_contents() {
    if (assembly_mode_ != last_assembly_mode_) {
        last_assembly_mode_ = assembly_mode_;
        rebuild_output();
    }

    if (ImGui::BeginTable("ShellcodeScratchLayout", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("Hex", ImGuiTableColumnFlags_WidthStretch, 0.48f);
        ImGui::TableSetupColumn("Input", ImGuiTableColumnFlags_WidthStretch, 0.52f);

        ImGui::TableNextColumn();
        ImGui::TextUnformatted("Hex View");
        ImGui::BeginChild("ShellcodeHexOutput", ImVec2(0.0f, 0.0f), true, ImGuiWindowFlags_HorizontalScrollbar);
        draw_hex_output();
        ImGui::EndChild();

        ImGui::TableNextColumn();
        if (ImGui::Checkbox("Assembly input", &assembly_mode_)) {
            rebuild_output();
        }
        ImGui::SameLine();
        if (ImGui::Button("Apply")) {
            apply_to_selection();
        }
        ImGui::SameLine();
        if (ImGui::Button("Undo")) {
            auto undone = model_.undo_patch();
            diagnostic_ = undone ? "Undid last patch." : std::format("Undo failed: {}", undone.error().message);
        }
        ImGui::SameLine();
        if (ImGui::Button("Redo")) {
            auto redone = model_.redo_patch();
            diagnostic_ = redone ? "Redid last patch." : std::format("Redo failed: {}", redone.error().message);
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            input_buf_[0] = '\0';
            rebuild_output();
        }

        ImGui::TextDisabled("%s", assembly_mode_ ? "Assembly -> hex" : "Hex/shellcode -> hex");
        ImGui::SameLine();
        ImGui::TextDisabled("Dirty ranges: %zu", model_.changed_intervals().size());
        ImGui::BeginChild("ShellcodeInputChild", ImVec2(0.0f, 0.0f), true);
        const ImVec2 available = ImGui::GetContentRegionAvail();
        if (ImGui::InputTextMultiline("##ShellcodeInput",
                                      input_buf_,
                                      sizeof(input_buf_),
                                      ImVec2(std::max(available.x, 100.0f), std::max(available.y, 100.0f)),
                                      ImGuiInputTextFlags_AllowTabInput)) {
            rebuild_output();
        }
        ImGui::EndChild();

        ImGui::EndTable();
    }
}

} // namespace viewer
