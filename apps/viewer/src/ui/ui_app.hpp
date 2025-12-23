#pragma once

#include <functional>

#include "model/binary_model.hpp"
#include "ui_panels.hpp"

namespace viewer {

    class UiApp {
    public:
        explicit UiApp(BinaryModel& model);

        void render(); // call each frame from Application::render_ui()

        void set_open_file_callback(std::function<void()> cb) { on_open_file_ = std::move(cb); }

        LogPanel& log_panel() { return log_panel_; }


    private:
        BinaryModel& model_;

        FilePanel       file_panel_;
        SectionsPanel   sections_panel_;
        HexViewPanel    hex_panel_;
        DisassemblyPanel disasm_panel_;
        LogPanel        log_panel_;
        PeHeadersPanel  pe_headers_panel_;
        PeImportsPanel  pe_imports_panel_;
        PeExportsPanel  pe_exports_panel_;

        std::function<void()> on_open_file_;

        bool show_demo_window_ = false;

        void render_main_menu();
        void render_dockspace();

    };

} // namespace viewer