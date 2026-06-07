//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

namespace viewer {
namespace {

void draw_permissions(bool readable, bool writable, bool executable) {
    char perms[4];
    perms[0] = readable ? 'R' : '-';
    perms[1] = writable ? 'W' : '-';
    perms[2] = executable ? 'X' : '-';
    perms[3] = '\0';
    ImGui::TextUnformatted(perms);
}

} // namespace

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

            ImGui::TextUnformatted(s.name.c_str()); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.virtual_address); ImGui::NextColumn();
            ImGui::Text("0x%llX", (unsigned long long)s.virtual_size); ImGui::NextColumn();
            draw_permissions(s.readable, s.writable, s.executable); ImGui::NextColumn();
        }

        ImGui::Columns(1);

        if (!img->segments().empty()) {
            ImGui::SeparatorText("Segments");
            ImGui::Columns(5, nullptr, true);
            ImGui::Text("Type"); ImGui::NextColumn();
            ImGui::Text("Address"); ImGui::NextColumn();
            ImGui::Text("Mem Size"); ImGui::NextColumn();
            ImGui::Text("File Off"); ImGui::NextColumn();
            ImGui::Text("Perm"); ImGui::NextColumn();
            ImGui::Separator();

            for (const auto& segment : img->segments()) {
                ImGui::Text("0x%X", segment.type); ImGui::NextColumn();
                ImGui::Text("0x%llX", (unsigned long long)segment.virtual_address); ImGui::NextColumn();
                ImGui::Text("0x%llX", (unsigned long long)segment.virtual_size); ImGui::NextColumn();
                ImGui::Text("0x%llX", (unsigned long long)segment.file_offset); ImGui::NextColumn();
                draw_permissions(segment.readable, segment.writable, segment.executable); ImGui::NextColumn();
            }
            ImGui::Columns(1);
        }

        ImGui::EndChild();
    }

} // namespace viewer
