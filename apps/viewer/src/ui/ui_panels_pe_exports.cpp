#include "ui_panels.hpp"
#include <imgui.h>

#include <string>

namespace viewer {

    PeExportsPanel::PeExportsPanel(BinaryModel& model)
        : UiPanel("PE Exports")
        , model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void PeExportsPanel::draw_contents() {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || img->format() != peelf::Format::PE) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "Export name...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        ImGui::Separator();
        ImGui::BeginChild("PEExportsList", ImVec2(0, 0), false);

        ImGui::Columns(3, nullptr, true);
        ImGui::Text("Ordinal"); ImGui::NextColumn();
        ImGui::Text("RVA"); ImGui::NextColumn();
        ImGui::Text("Name"); ImGui::NextColumn();
        ImGui::Separator();

        const std::uint64_t base = img->image_base();
        for (const auto& e : img->exports()) {
            const std::string display_name =
                !e.forwarder.empty()
                    ? (e.name + " -> " + e.forwarder)
                    : e.name;
            if (has_filter) {
                if (display_name.find(filter) == std::string::npos) continue;
            }

            const std::uint64_t rva = e.virtual_address >= base ? (e.virtual_address - base) : e.virtual_address;
            ImGui::Text("%u", static_cast<unsigned int>(e.ordinal)); ImGui::NextColumn();
            ImGui::Text("0x%08X", static_cast<unsigned int>(rva)); ImGui::NextColumn();
            ImGui::TextUnformatted(display_name.c_str()); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer
