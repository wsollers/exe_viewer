#include "ui_panels.hpp"
#include <imgui.h>
#include <cinttypes>

namespace viewer {

    PeHeadersPanel::PeHeadersPanel(BinaryModel& model)
        : UiPanel("PE Headers")
        , model_(model)
    {}

    void PeHeadersPanel::draw_contents() {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || img->format() != peelf::Format::PE || img->pe_header() == nullptr) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        const peelf::PeHeader& pe = *img->pe_header();
        ImGui::Text("Machine: 0x%04X", static_cast<unsigned int>(pe.machine));
        ImGui::Text("Sections: %u", static_cast<unsigned int>(pe.number_of_sections));
        ImGui::Text("Timestamp: 0x%08X", pe.time_date_stamp);
        ImGui::Text("ImageBase: 0x%" PRIX64, img->image_base());
        ImGui::Text("EntryPoint RVA: 0x%08X", pe.entry_point_rva);
        ImGui::Text("SizeOfImage: 0x%08X", pe.size_of_image);
        ImGui::Text("Subsystem: 0x%04X", static_cast<unsigned int>(pe.subsystem));
        ImGui::Text("DllCharacteristics: 0x%04X", static_cast<unsigned int>(pe.dll_characteristics));
        ImGui::Text("PE32+: %s", img->is_64bit() ? "yes" : "no");

        ImGui::Separator();
        const auto data_dirs = img->pe_data_directories();
        if (!data_dirs.empty() && ImGui::CollapsingHeader("Data Directories", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Columns(3, nullptr, true);
            ImGui::Text("Name"); ImGui::NextColumn();
            ImGui::Text("RVA"); ImGui::NextColumn();
            ImGui::Text("Size"); ImGui::NextColumn();
            ImGui::Separator();

            for (const auto& dd : data_dirs) {
                ImGui::TextUnformatted(dd.name.c_str()); ImGui::NextColumn();
                ImGui::Text("0x%08X", dd.rva); ImGui::NextColumn();
                ImGui::Text("0x%08X", dd.size); ImGui::NextColumn();
            }
            ImGui::Columns(1);
        }
    }

} // namespace viewer