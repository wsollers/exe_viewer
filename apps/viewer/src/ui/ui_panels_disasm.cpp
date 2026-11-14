//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>
#include <format>

namespace viewer {

    DisassemblyPanel::DisassemblyPanel(BinaryModel& model, std::vector<Instruction>& instructions)
        : UiPanel("Disassembly"), model_(model), current_instructions_(instructions)
    {}

    void DisassemblyPanel::draw_contents() {

        if (current_instructions_.empty()) {
            ImGui::TextUnformatted("No data loaded.");
            return;
        }

        ImGui::BeginChild("InstructionsScroll", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);

        if (ImGui::BeginTable("Instructions", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
            for (const char* column : {"Address", "Bytes", "Mnemonic", "Operands", "Comment"}) ImGui::TableSetupColumn(column);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(current_instructions_.size()));
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& instruction = current_instructions_[static_cast<std::size_t>(row)];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(std::format("{:016X}", instruction.address).c_str());
                    ImGui::TableNextColumn();
                    std::string bytes;
                    for (auto byte : instruction.bytes) bytes += std::format("{:02X} ", byte);
                    ImGui::TextUnformatted(bytes.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.mnemonic.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.operands.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.comment.c_str());
                }
            }
            ImGui::EndTable();
        }

        ImGui::EndChild();
    }

} // namespace viewer
