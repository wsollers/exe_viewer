#include "ui_panels.hpp"
#include <imgui.h>
#include "model/pe_model.hpp"

namespace viewer {

    PeHeadersPanel::PeHeadersPanel(BinaryModel& model)
        : UiPanel("PE Headers")
        , model_(model)
    {}

    void PeHeadersPanel::draw_contents() {
        const PeModel* pe = model_.pe();
        if (!pe) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        ImGui::Text("Machine: 0x%04X", pe->machine);
        ImGui::Text("Sections: %u", pe->num_sections);
        ImGui::Text("Timestamp: 0x%08X", pe->timestamp);
        ImGui::Text("ImageBase: 0x%llX",
                    static_cast<unsigned long long>(pe->image_base));
        ImGui::Text("EntryPoint RVA: 0x%08X", pe->entry_point_rva);
        ImGui::Text("SizeOfImage: 0x%08X", pe->size_of_image);
        ImGui::Text("PE32+: %s", pe->is_pe32_plus ? "yes" : "no");

        ImGui::Separator();
        if (ImGui::CollapsingHeader("Data Directories", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Columns(3, nullptr, true);
            ImGui::Text("Name"); ImGui::NextColumn();
            ImGui::Text("RVA"); ImGui::NextColumn();
            ImGui::Text("Size"); ImGui::NextColumn();
            ImGui::Separator();

            for (const auto& dd : pe->data_directories) {
                ImGui::TextUnformatted(dd.name.c_str()); ImGui::NextColumn();
                ImGui::Text("0x%08X", dd.rva); ImGui::NextColumn();
                ImGui::Text("0x%08X", dd.size); ImGui::NextColumn();
            }
            ImGui::Columns(1);
        }
    }

} // namespace viewer