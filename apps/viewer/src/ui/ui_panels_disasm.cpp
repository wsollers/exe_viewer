//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

namespace viewer {

    DisassemblyPanel::DisassemblyPanel(BinaryModel& model)
        : UiPanel("Disassembly"), model_(model)
    {}

    void DisassemblyPanel::draw_contents() {
        ImGui::TextUnformatted("Disassembly not implemented yet.");
    }

} // namespace viewer