#include "ui_panels.hpp"
#include <imgui.h>

#include <string>

namespace viewer {

    PeImportsPanel::PeImportsPanel(BinaryModel& model)
        : UiPanel("PE Imports")
        , model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void PeImportsPanel::draw_contents() {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || img->format() != peelf::Format::PE) {
            ImGui::TextUnformatted("No PE file loaded.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "DLL or function...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        ImGui::Separator();
        ImGui::BeginChild("PEImportsList", ImVec2(0, 0), false);

        ImGui::Columns(3, nullptr, true);
        ImGui::Text("DLL"); ImGui::NextColumn();
        ImGui::Text("Function"); ImGui::NextColumn();
        ImGui::Text("Address"); ImGui::NextColumn();
        ImGui::Separator();

        for (const auto& imp : img->imports()) {
            const std::string func_display =
                !imp.name.empty()
                    ? imp.name
                    : ((imp.import_by_ordinal || imp.ordinal != 0u)
                           ? ("Ordinal#" + std::to_string(imp.ordinal))
                           : "<unnamed>");
            if (has_filter) {
                if (imp.library.find(filter) == std::string::npos &&
                    func_display.find(filter) == std::string::npos) {
                    continue;
                }
            }

            ImGui::TextUnformatted(imp.library.c_str()); ImGui::NextColumn();
            ImGui::TextUnformatted(func_display.c_str()); ImGui::NextColumn();
            ImGui::Text("0x%llX",
                        static_cast<unsigned long long>(imp.address)); ImGui::NextColumn();
        }

        ImGui::Columns(1);
        ImGui::EndChild();
    }

} // namespace viewer
