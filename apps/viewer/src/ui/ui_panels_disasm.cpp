//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

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

        // Display current instructions
        for (const auto& instruction : current_instructions_) {
            char addr[32];
            std::snprintf(addr, sizeof(addr), "%08" PRIx64 ": ", instruction.address);
            ImGui::TextUnformatted(addr);
            ImGui::SameLine();

            // Construct the full instruction string
            std::string instruction_string = instruction.to_string();

            // Display mnemonic and operands
            ImGui::TextUnformatted(instruction_string.c_str());

            // Optional: Display comment if available
            if (!instruction.comment.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), instruction.comment.c_str());
            }
        }

        ImGui::EndChild();
    }

} // namespace viewer