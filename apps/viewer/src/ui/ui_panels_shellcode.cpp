#include "ui_panels.hpp"

#include <imgui.h>
#include <peelf/assembler.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <span>
#include <sstream>

#include "analysis/patch_preview.hpp"
#include "tools/shellcode_converter.hpp"

namespace viewer {

ShellcodeScratchPanel::ShellcodeScratchPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Shellcode"), model_(model), selection_(selection)
{
    diagnostic_ = "Paste hex bytes, shellcode escapes, or toggle Assembly input.";
}

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

void ShellcodeScratchPanel::rebuild_output() {
    output_bytes_.clear();
    hex_view_.clear();
    roundtrip_disasm_view_.clear();

    peelf::Architecture arch = peelf::Architecture::X86_64;
    peelf::Endianness endian = peelf::Endianness::Little;
    bool is_64bit = true;
    const bool thumb = model_.analysis_thumb_mode();
    if (model_.image() != nullptr) {
        arch = model_.image()->architecture();
        endian = model_.image()->endianness();
        is_64bit = model_.image()->is_64bit();
    } else if (model_.architecture() != peelf::Architecture::Unknown) {
        arch = model_.architecture();
        endian = model_.endianness();
        is_64bit = (arch == peelf::Architecture::X86_64 ||
                    arch == peelf::Architecture::ARM64 ||
                    arch == peelf::Architecture::MIPS64 ||
                    arch == peelf::Architecture::PowerPC64 ||
                    arch == peelf::Architecture::RISCV64);
    }

    const std::uint64_t base_va = effective_base_address();
    last_base_address_ = base_va;

    if (assembly_mode_) {
        if (input_buf_[0] == '\0') {
            diagnostic_ = std::format(
                "Enter {} assembly instructions (base VA 0x{:X}).",
                peelf::to_string(arch),
                base_va);
            return;
        }
        auto res = peelf::assemble_instructions(arch, endian, is_64bit, thumb, base_va, input_buf_);
        if (!res.has_value()) {
            diagnostic_ = res.error().message;
            return;
        }
        output_bytes_ = std::move(res->bytes);
        diagnostic_ = std::format(
            "Assembled {} instruction(s) -> {} byte(s) via {} @ 0x{:X}",
            res->instruction_spans.size(),
            output_bytes_.size(),
            res->provider_name,
            base_va);
    } else {
        const ShellcodeParseResult parsed = parse_hex_shellcode(input_buf_);
        output_bytes_ = parsed.bytes;
        diagnostic_ = parsed.diagnostic;
        if (!parsed.success) {
            return;
        }
    }

    if (!output_bytes_.empty()) {
        hex_view_ = format_shellcode_hex_view(
            std::span<const std::uint8_t>(output_bytes_.data(), output_bytes_.size()));
        const auto insns = disassemble_patch_bytes(output_bytes_, base_va, arch, endian, thumb);
        if (!insns.empty()) {
            std::ostringstream oss;
            for (const Instruction& inst : insns) {
                oss << std::format("0x{:08X}  {} {}\n",
                                   inst.address,
                                   inst.mnemonic,
                                   inst.operands);
            }
            roundtrip_disasm_view_ = oss.str();
        }
    }
}

void ShellcodeScratchPanel::draw_hex_output() const {
    if (hex_view_.empty()) {
        ImGui::TextDisabled("%s", diagnostic_.c_str());
        return;
    }

    ImGui::TextDisabled("%s", diagnostic_.c_str());
    ImGui::Separator();
    ImGui::TextUnformatted(hex_view_.c_str());
    if (!roundtrip_disasm_view_.empty()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextDisabled("Capstone Round-Trip Disassembly:");
        ImGui::TextUnformatted(roundtrip_disasm_view_.c_str());
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
        diagnostic_ =
            "Attached live processes are strictly read-only; target process memory is never modified.";
        return;
    }

    if (output_bytes_.empty()) {
        diagnostic_ = "No bytes to apply.";
        return;
    }

    const std::string label = selection_.label.empty()
        ? (assembly_mode_ ? "assembly scratch patch" : "shellcode scratch patch")
        : std::format("{}: {}",
                      assembly_mode_ ? "assembly scratch patch" : "shellcode scratch patch",
                      selection_.label);

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

    model_.record_patch_metadata(
        *offset,
        label,
        assembly_mode_ ? std::optional<std::string>(input_buf_) : std::nullopt);
    diagnostic_ = std::format("Staged {} bytes at file offset 0x{:X}.", output_bytes_.size(), *offset);
    if (on_patch_changed_) {
        on_patch_changed_();
    }
}

void ShellcodeScratchPanel::draw_contents() {
    if (assembly_mode_ != last_assembly_mode_ ||
        (assembly_mode_ && effective_base_address() != last_base_address_)) {
        last_assembly_mode_ = assembly_mode_;
        rebuild_output();
    }

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
        ImGui::BeginDisabled(model_.is_live_process() || output_bytes_.empty());
        if (ImGui::Button("Stage Patch")) {
            apply_to_selection();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(model_.is_live_process());
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
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            input_buf_[0] = '\0';
            rebuild_output();
        }

        ImGui::TextDisabled(
            "%s (Base VA: 0x%llX)",
            assembly_mode_ ? "Assembly -> machine code" : "Hex/shellcode -> bytes",
            static_cast<unsigned long long>(effective_base_address()));
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
