#include "ui_panels.hpp"

#include <imgui.h>
#include <peelf/assembler.hpp>

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <format>
#include <span>
#include <sstream>

#include "analysis/patch_preview.hpp"
#include "tools/shellcode_converter.hpp"

namespace viewer {

ShellcodeScratchPanel::ShellcodeScratchPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Shellcode"), model_(model), selection_(selection) {}

std::uint64_t ShellcodeScratchPanel::effective_base_address() const {
    if (selection_.virtual_address.has_value()) {
        return *selection_.virtual_address;
    }
    if (const auto off = selected_file_offset(); off.has_value()) {
        if (const auto va = model_.offset_to_virtual_address(*off); va.has_value()) {
            return *va;
        }
        return *off;
    }
    return 0;
}

ShellcodeTargetConfig ShellcodeScratchPanel::current_target_config() const {
    ShellcodeTargetConfig cfg{};
    cfg.thumb = model_.analysis_thumb_mode();
    cfg.base_va = effective_base_address();
    cfg.assembly_mode = assembly_mode_;
    if (model_.image() != nullptr) {
        cfg.architecture = model_.image()->architecture();
        cfg.endianness = model_.image()->endianness();
        cfg.is_64bit = model_.image()->is_64bit();
    } else if (model_.architecture() != peelf::Architecture::Unknown) {
        cfg.architecture = model_.architecture();
        cfg.endianness = model_.endianness();
        cfg.is_64bit = (cfg.architecture == peelf::Architecture::X86_64 ||
                        cfg.architecture == peelf::Architecture::ARM64 ||
                        cfg.architecture == peelf::Architecture::MIPS64 ||
                        cfg.architecture == peelf::Architecture::PowerPC64 ||
                        cfg.architecture == peelf::Architecture::RISCV64);
    }
    return cfg;
}

void ShellcodeScratchPanel::rebuild_output() {
    scratch_cache_.rebuild(current_target_config(), input_buf_);
}

void ShellcodeScratchPanel::draw_hex_output() const {
    if (scratch_cache_.hex_view().empty()) {
        ImGui::TextDisabled("%s", scratch_cache_.diagnostic().c_str());
        return;
    }

    ImGui::TextDisabled("%s", scratch_cache_.diagnostic().c_str());
    ImGui::Separator();
    ImGui::TextUnformatted(scratch_cache_.hex_view().c_str());
    if (!scratch_cache_.roundtrip_disasm_view().empty()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextDisabled("Capstone Round-Trip Disassembly:");
        ImGui::TextUnformatted(scratch_cache_.roundtrip_disasm_view().c_str());
    }
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
    if (model_.is_live_process()) {
        scratch_cache_.set_diagnostic(
            "Attached live processes are strictly read-only; target process memory is never modified.");
        return;
    }

    scratch_cache_.sync_target(current_target_config(), input_buf_);
    const std::span<const std::uint8_t> bytes = scratch_cache_.output_bytes();
    if (bytes.empty()) {
        scratch_cache_.set_diagnostic("No bytes to apply.");
        return;
    }

    const std::string label = selection_.label.empty()
        ? (assembly_mode_ ? "assembly scratch patch" : "shellcode scratch patch")
        : std::format("{}: {}",
                      assembly_mode_ ? "assembly scratch patch" : "shellcode scratch patch",
                      selection_.label);

    const std::optional<std::uint64_t> offset = selected_file_offset();
    if (!offset) {
        scratch_cache_.set_diagnostic("Select file-backed bytes before applying shellcode.");
        return;
    }

    auto applied = model_.apply_patch_bytes(*offset, bytes, label);
    if (!applied) {
        scratch_cache_.set_diagnostic(std::format("Patch failed: {}", applied.error().message));
        return;
    }

    model_.record_patch_metadata(
        *offset,
        label,
        assembly_mode_ ? std::optional<std::string>(input_buf_) : std::nullopt);
    scratch_cache_.set_diagnostic(
        std::format("Staged {} bytes at file offset 0x{:X}.", bytes.size(), *offset));
    if (on_patch_changed_) {
        on_patch_changed_();
    }
}

void ShellcodeScratchPanel::draw_contents() {
    scratch_cache_.sync_target(current_target_config(), input_buf_);

    if (model_.is_live_process()) {
        ImGui::TextColored(
            ImVec4(0.45f, 0.85f, 1.0f, 1.0f),
            "Read-Only Live Mode: Assembly/hex conversion works as a scratchpad, but patching live process memory is disabled.");
    }

    if (ImGui::BeginTable("ShellcodeScratchLayout", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("Hex", ImGuiTableColumnFlags_WidthStretch, 0.48f);
        ImGui::TableSetupColumn("Input", ImGuiTableColumnFlags_WidthStretch, 0.52f);

        ImGui::TableNextColumn();
        ImGui::TextUnformatted("Encoded Bytes & Round-Trip Disassembly");
        ImGui::BeginChild("ShellcodeHexOutput", ImVec2(0.0f, 0.0f), true, ImGuiWindowFlags_HorizontalScrollbar);
        draw_hex_output();
        ImGui::EndChild();

        ImGui::TableNextColumn();
        if (ImGui::Checkbox("Assembly input", &assembly_mode_)) {
            rebuild_output();
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(model_.is_live_process() || scratch_cache_.output_bytes().empty());
        if (ImGui::Button("Stage Patch")) {
            apply_to_selection();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(model_.is_live_process());
        if (ImGui::Button("Undo")) {
            auto undone = model_.undo_patch();
            scratch_cache_.set_diagnostic(
                undone ? "Undid last patch."
                       : std::format("Undo failed: {}", undone.error().message));
            if (undone && on_patch_changed_) {
                on_patch_changed_();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Redo")) {
            auto redone = model_.redo_patch();
            scratch_cache_.set_diagnostic(
                redone ? "Redid last patch."
                       : std::format("Redo failed: {}", redone.error().message));
            if (redone && on_patch_changed_) {
                on_patch_changed_();
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            input_buf_[0] = '\0';
            rebuild_output();
        }

        ImGui::TextDisabled(
            "%s (Base VA: 0x%" PRIX64 ")",
            assembly_mode_ ? "Assembly -> machine code" : "Hex/shellcode -> bytes",
            effective_base_address());
        ImGui::SameLine();
        if (model_.is_live_process()) {
            ImGui::TextDisabled("| Live process is read-only");
        } else {
            ImGui::TextDisabled("| Staged ranges: %zu", model_.changed_intervals().size());
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
