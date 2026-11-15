#pragma once

#include "../model/binary_model.hpp"
#include "ui_panel.hpp"

#include <array>

namespace viewer {

class ProcessInternalsPanel : public UiPanel {
public:
    explicit ProcessInternalsPanel(BinaryModel& model);

protected:
    void draw_contents() override;

private:
    void draw_handles_tab(const peelf::ProcessInternalsSnapshot& snap);
    void draw_sockets_tab(const peelf::ProcessInternalsSnapshot& snap);
    void draw_security_tab(const peelf::ProcessInternalsSnapshot& snap);

    BinaryModel& model_;
    std::array<char, 160> handle_filter_{};
    int handle_kind_filter_{0};
    std::array<char, 160> socket_filter_{};
    std::array<char, 160> cap_filter_{};
};

}  // namespace viewer
