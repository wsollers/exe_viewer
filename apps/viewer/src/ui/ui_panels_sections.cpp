//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

namespace viewer {

    SectionsPanel::SectionsPanel(BinaryModel& model)
        : UiPanel("Sections"), model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void SectionsPanel::draw_contents() {
        const auto& secs = model_.sections();
        if (secs.empty()) {
            ImGui::TextUnformatted("No sections.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "Name...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        ImGui::Separator();
        ImGui::BeginChild("SectionsList", ImVec2(0,0), false);

        ImGui::Columns(4, nullptr, true);
        ImGui::Text("Name"); ImGui::NextColumn();
        ImGui::Text("Address"); ImGui::NextColumn();
        ImGui::Text("Size"); ImGui::NextColumn();
        ImGui::Text("Flags"); ImGui::NextColumn();
        ImGui::Separator();

        for (const auto& s : secs) {
            if (has_filter && s.name.find(filter) == std::string::npos)
                continue;

            ImGui::TextUnformatted(s.name.c_str()); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.address); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.size); ImGui::NextColumn();
            ImGui::Text("0x%08X", s.flags); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer