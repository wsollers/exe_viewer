#pragma once

#include <functional>

#include "model/binary_model.hpp"
#include "ui_panels.hpp"
#include "dissassembler/dissassembler.hpp"

namespace viewer {

    class UiApp {
    public:
        explicit UiApp(BinaryModel& model);

        void render(); // call each frame from Application::render_ui()

        void set_open_file_callback(std::function<void()> cb) { on_open_file_ = std::move(cb); }

        LogPanel& log_panel() { return log_panel_; }

        bool show_demo_window_ = false;


        void disassemble_at(uint64_t rva, size_t size);

        void disassemble_entry_point(size_t max_size);

        void render_disassembly_panel();

        void on_file_loaded();

        ImVec4 get_mnemonic_color(const std::string &mnemonic) const;

        void disassemble_section(const std::string &section_name, size_t max_size);


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

        viewer::Disassembler disasm_;
        bool file_loaded_;
        PeModel pe_model_;
        std::vector<Instruction> current_instructions_;


        void render_main_menu();
        void render_dockspace();


    };

} // namespace viewer