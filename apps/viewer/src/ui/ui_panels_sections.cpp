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
        const peelf::IBinaryImage* img = model_.image();
        if (!img || img->sections().empty()) {
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
        ImGui::Text("Perm"); ImGui::NextColumn();
        ImGui::Separator();

        for (const auto& s : img->sections()) {
            if (has_filter && s.name.find(filter) == std::string::npos)
                continue;

            // R/W/X permissions (avoid braced-init to dodge /permissive- narrowing).
            char perms[4];
            perms[0] = s.readable   ? 'R' : '-';
            perms[1] = s.writable   ? 'W' : '-';
            perms[2] = s.executable ? 'X' : '-';
            perms[3] = '\0';

            ImGui::TextUnformatted(s.name.c_str()); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.virtual_address); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.virtual_size); ImGui::NextColumn();
            ImGui::TextUnformatted(perms); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer