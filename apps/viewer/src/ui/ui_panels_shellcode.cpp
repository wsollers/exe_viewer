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
    if (selection_.virtual_address) {
        return model_.virtual_address_to_offset(*selection_.virtual_address);
    }
    return std::nullopt;
}

void ShellcodeScratchPanel::apply_to_selection() {
    if (output_bytes_.empty()) {
        diagnostic_ = "No bytes to apply.";
        return;
    }

    const std::string label = selection_.label.empty()
        ? "shellcode scratch patch"
        : std::format("shellcode scratch patch: {}", selection_.label);

    if (model_.is_live_process()) {
        std::optional<std::uint64_t> target_va = selection_.virtual_address;
        if (!target_va && selection_.file_offset) {
            target_va = model_.offset_to_virtual_address(*selection_.file_offset);
        }
        if (!target_va) {
            diagnostic_ = "Select a live memory address, symbol, section, or byte before staging shellcode.";
            return;
        }
        auto staged = model_.stage_patch_at_va(*target_va, output_bytes_, label);
        if (!staged) {
            diagnostic_ = std::format("Stage failed: {}", staged.error().message);
            return;
        }
        diagnostic_ = std::format(
            "Staged {} bytes at live VA 0x{:X} (overlay active; click 'Commit to RAM' to write to process).",
            output_bytes_.size(),
            *target_va);
        if (on_patch_changed_) {
            on_patch_changed_();
        }
        return;
    }

    const std::optional<std::uint64_t> offset = selected_file_offset();
    if (!offset) {
        diagnostic_ = "Select file-backed bytes before applying shellcode.";
        return;
    }

    auto applied = model_.apply_patch_bytes(*offset, output_bytes_, label);
    if (!applied) {
        diagnostic_ = std::format("Patch failed: {}", applied.error().message);
        return;
    }

    diagnostic_ = std::format("Staged {} bytes at file offset 0x{:X}.", output_bytes_.size(), *offset);
    if (on_patch_changed_) {
        on_patch_changed_();
    }
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
        if (ImGui::Button(model_.is_live_process() ? "Stage" : "Apply")) {
            apply_to_selection();
        }
        ImGui::SameLine();
        if (ImGui::Button("Undo")) {
            auto undone = model_.undo_patch();
            diagnostic_ = undone ? "Undid last patch." : std::format("Undo failed: {}", undone.error().message);
            if (undone && on_patch_changed_) {
                on_patch_changed_();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Redo")) {
            auto redone = model_.redo_patch();
            diagnostic_ = redone ? "Redid last patch." : std::format("Redo failed: {}", redone.error().message);
            if (redone && on_patch_changed_) {
                on_patch_changed_();
            }
        }
        if (model_.is_live_process()) {
            ImGui::SameLine();
            const bool has_staged = !model_.staged_live_patches().empty();
            ImGui::BeginDisabled(!has_staged);
            if (ImGui::Button("Commit to RAM")) {
                auto committed = model_.commit_patches_to_process(
                    peelf::MemoryWriteOptions{.allow_protection_override = override_protection_});
                diagnostic_ = committed
                    ? std::format("Committed {} patch range(s) to live process RAM.", *committed)
                    : std::format("Commit failed: {}", committed.error().message);
                if (committed && on_patch_changed_) {
                    on_patch_changed_();
                }
            }
            ImGui::EndDisabled();
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            input_buf_[0] = '\0';
            rebuild_output();
        }

        ImGui::TextDisabled("%s", assembly_mode_ ? "Assembly -> hex" : "Hex/shellcode -> hex");
        ImGui::SameLine();
        if (model_.is_live_process()) {
            ImGui::TextDisabled("Staged: %zu | Committed: %zu",
                                model_.staged_live_patches().size(),
                                model_.committed_live_patches().size());
        } else {
            ImGui::TextDisabled("Dirty ranges: %zu", model_.changed_intervals().size());
        }
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
