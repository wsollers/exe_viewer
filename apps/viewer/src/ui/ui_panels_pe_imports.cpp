#include "ui_panels.hpp"
#include <imgui.h>
#include "model/pe_model.hpp"

namespace viewer {

    PeImportsPanel::PeImportsPanel(BinaryModel& model)
        : UiPanel("PE Imports")
        , model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void PeImportsPanel::draw_contents() {
        const PeModel* pe = model_.pe();
        if (!pe) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "DLL or function...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        ImGui::Separator();
        ImGui::BeginChild("ImportsList", ImVec2(0, 0), false);

        ImGui::Columns(3, nullptr, true);
        ImGui::Text("DLL"); ImGui::NextColumn();
        ImGui::Text("Function"); ImGui::NextColumn();
        ImGui::Text("Address"); ImGui::NextColumn();
        ImGui::Separator();

        for (const auto& imp : pe->imports) {
            if (has_filter) {
                if (imp.dll.find(filter) == std::string::npos &&
                    imp.function.find(filter) == std::string::npos) {
                    continue;
                    }
            }

            ImGui::TextUnformatted(imp.dll.c_str()); ImGui::NextColumn();
            ImGui::TextUnformatted(imp.function.c_str()); ImGui::NextColumn();
            ImGui::Text("0x%llX",
                        static_cast<unsigned long long>(imp.address)); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer