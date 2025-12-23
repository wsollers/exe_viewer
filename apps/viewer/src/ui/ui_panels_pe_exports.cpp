#include "ui_panels.hpp"
#include <imgui.h>
#include "model/pe_model.hpp"

namespace viewer {

    PeExportsPanel::PeExportsPanel(BinaryModel& model)
        : UiPanel("PE Exports")
        , model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void PeExportsPanel::draw_contents() {
        const PeModel* pe = model_.pe();
        if (!pe) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "Export name...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        ImGui::Separator();
        ImGui::BeginChild("ExportsList", ImVec2(0, 0), false);

        ImGui::Columns(3, nullptr, true);
        ImGui::Text("Ordinal"); ImGui::NextColumn();
        ImGui::Text("RVA"); ImGui::NextColumn();
        ImGui::Text("Name"); ImGui::NextColumn();
        ImGui::Separator();

        for (const auto& e : pe->exports) {
            if (has_filter) {
                if (e.name.find(filter) == std::string::npos) continue;
            }

            ImGui::Text("%u", e.ordinal); ImGui::NextColumn();
            ImGui::Text("0x%08X", e.rva); ImGui::NextColumn();
            ImGui::TextUnformatted(e.name.c_str()); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer