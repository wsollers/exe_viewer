#include "ui_app.hpp"
#include <imgui.h>

#include "logger.hpp"

namespace viewer {

UiApp::UiApp(BinaryModel& model)
    : model_(model)
    , file_panel_(model)
    , sections_panel_(model)
    , hex_panel_(model)
    , disasm_panel_(model,current_instructions_)
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{}

void UiApp::render() {
    render_main_menu();
    render_dockspace();

    file_panel_.draw();
    sections_panel_.draw();
    hex_panel_.draw();
    disasm_panel_.draw();
    pe_headers_panel_.draw();
    pe_imports_panel_.draw();
    pe_exports_panel_.draw();
    log_panel_.draw();

    disasm_panel_.current_instructions_= current_instructions_;
    render_disassembly_panel();
    if (show_demo_window_)
        ImGui::ShowDemoWindow(&show_demo_window_);
}

void UiApp::render_main_menu() {
    if (!ImGui::BeginMainMenuBar())
        return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) {
            if (on_open_file_) { on_open_file_(); }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) {
            // handled by Application
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);

        {
            bool v = pe_headers_panel_.visible();
            if (ImGui::MenuItem(pe_headers_panel_.name().c_str(), nullptr, &v))
                pe_headers_panel_.set_visible(v);
        }

        {
            bool v = pe_imports_panel_.visible();
            if (ImGui::MenuItem(pe_imports_panel_.name().c_str(), nullptr, &v))
                pe_imports_panel_.set_visible(v);
        }

        {
            bool v = pe_exports_panel_.visible();
            if (ImGui::MenuItem(pe_exports_panel_.name().c_str(), nullptr, &v))
                pe_exports_panel_.set_visible(v);
        }

        ImGui::EndMenu();
    }

    ImGui::EndMainMenuBar();
}

void UiApp::render_dockspace() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("MainDockSpaceHost", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
    ImGuiDockNodeFlags dock_flags =
        ImGuiDockNodeFlags_PassthruCentralNode |
        ImGuiDockNodeFlags_NoDockingInCentralNode;
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dock_flags);

    ImGui::End();
}
    void UiApp::render_disassembly_panel() {
    ImGui::Begin("Disassembly");


    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::Text("No file loaded or disassembler not initialized");
        ImGui::End();
        return;
    }

    // Simple table view
    if (ImGui::BeginTable("DisasmTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto &inst: current_instructions_) {
            ImGui::TableNextRow();

            // Address
            ImGui::TableNextColumn();
            ImGui::Text("%016llX", inst.address);

            // Bytes
            ImGui::TableNextColumn();
            std::string bytes_str;
            for (uint8_t b: inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }
            ImGui::TextDisabled("%s", bytes_str.c_str());

            // Mnemonic (color-coded)
            ImGui::TableNextColumn();
            ImVec4 color = get_mnemonic_color(inst.mnemonic);
            ImGui::TextColored(color, "%s", inst.mnemonic.c_str());

            // Operands
            ImGui::TableNextColumn();
            ImGui::Text("%s", inst.operands.c_str());
        }

        ImGui::EndTable();
                          }

    ImGui::End();
}
    // After loading a PE file
    void UiApp::on_file_loaded() {
        // Get machine type from PE header
        pe_model_ = *model_.pe();
        auto machine = pe_model_.machine;

        auto arch = viewer::architecture_from_machine(machine);
        if (!disasm_.init(arch)) {
            Log().info("Failed to initialize disassembler: %s\n", disasm_.get_error());
            return;
        }

        Log().error("Disassembler initialized for %s\n",
               arch == viewer::Architecture::X86_64
                   ? "x64"
                   : arch == viewer::Architecture::X86_32
                         ? "x86"
                         : arch == viewer::Architecture::ARM64
                               ? "ARM64"
                               : "ARM32");
        file_loaded_ = true;
        // Initialize disassembler for target architecture
            // Disassemble entry point
            disassemble_entry_point(4096);
            Log().error("Dissassembled entry point successfully.\n");

    }




    void UiApp::disassemble_section(const std::string& section_name, size_t max_size) {
        const auto* section = pe_model_.section_by_name(section_name);
        if (!section) {
            fprintf(stderr, "Section '%s' not found\n", section_name.c_str());
            return;
        }

        // Check if section is executable
        if (!(section->characteristics & 0x20000000)) {
            fprintf(stderr, "Warning: Section '%s' is not marked executable\n", section_name.c_str());
        }

        size_t size = std::min(max_size, static_cast<size_t>(section->raw_size));
        const uint8_t* code = pe_model_.data_at_offset(section->raw_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read section data\n");
            return;
        }

        uint64_t va = pe_model_.rva_to_va(section->virtual_address);
        auto instructions = disasm_.disassemble(code, size, va);

        printf("Section: %s (0x%llX - 0x%llX)\n",
               section_name.c_str(), va, va + section->virtual_size);
        printf("----------------------------------------\n");

        for (const auto& inst : instructions) {
            std::string bytes_str;
            for (uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            printf("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }
    void UiApp::disassemble_at(uint64_t rva, size_t size) {
        // Get file offset from RVA
        auto file_offset = pe_model_.rva_to_offset(static_cast<uint32_t>(rva));
        if (!file_offset) {
            fprintf(stderr, "Failed to convert RVA 0x%llX to file offset\n", rva);
            return;
        }

        // Get pointer to code
        const uint8_t* code = pe_model_.data_at_offset(*file_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read %zu bytes at offset 0x%zX\n", size, *file_offset);
            return;
        }

        // Convert RVA to VA for disassembly
        uint64_t va = pe_model_.rva_to_va(static_cast<uint32_t>(rva));

        // Disassemble
        auto instructions = disasm_.disassemble(code, size, va);

        for (const auto& inst : instructions) {
            // Format bytes
            std::string bytes_str;
            for (uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            printf("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }

    void UiApp::disassemble_entry_point(size_t max_size) {
        current_instructions_.clear();
        auto offset = pe_model_.entry_point_offset();
        if (!offset) {
            Log().error("Failed to get entry point offset\n");
            return;
        }

        // Get the section containing the entry point to limit size
        const auto* section = pe_model_.entry_point_section();
        if (section) {
            // Don't read past section end
            size_t section_remaining = section->raw_size -
                (pe_model_.entry_point_rva - section->virtual_address);
            max_size = std::min(max_size, section_remaining);
        }

        const auto code = model_.bytes();
        //const uint8_t* code = pe_model_.data_at_offset(*offset, max_size);
        if (code.size() < 0) {
            Log().error("Failed to read entry point code\n");
            return;
        }

        uint64_t va = pe_model_.entry_point_va();
        current_instructions_ = disasm_.disassemble(code.data(), max_size, va);
        //current_instructions_ = disasm_.disassemble(code, max_size, va);

        Log().error("Entry Point: 0x%llX\n", va);
        printf("----------------------------------------\n");

        for (const auto& inst : current_instructions_) {
            std::string bytes_str;
            for (uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            Log().error("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }

    ImVec4 UiApp::get_mnemonic_color(const std::string& mnemonic) const {
    if (mnemonic.empty()) {
        return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);  // White
    }

    // Branch/control flow - Blue
    if (mnemonic[0] == 'j' ||
        mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" ||
        mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "syscall" || mnemonic == "sysret" ||
        mnemonic == "b" || mnemonic == "bl" || mnemonic == "bx" || mnemonic == "blx" ||
        mnemonic == "cbz" || mnemonic == "cbnz") {
        return ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
    }

    // SIMD/Vector - Green
    if (mnemonic[0] == 'v' ||  // AVX
        mnemonic.find("movap") == 0 || mnemonic.find("movup") == 0 ||
        mnemonic.find("movdq") == 0 || mnemonic.find("movss") == 0 ||
        mnemonic.find("movsd") == 0 || mnemonic.find("addp") == 0 ||
        mnemonic.find("subp") == 0 || mnemonic.find("mulp") == 0 ||
        mnemonic.find("divp") == 0 || mnemonic.find("xmm") != std::string::npos ||
        mnemonic.find("ymm") != std::string::npos ||
        mnemonic.find("zmm") != std::string::npos) {
        return ImVec4(0.5f, 1.0f, 0.5f, 1.0f);
    }

    // NOP/padding - Gray
    if (mnemonic == "nop" || mnemonic == "int3" || mnemonic == "ud2") {
        return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    }

    // Data movement - Light yellow
    if (mnemonic.find("mov") == 0 || mnemonic == "lea" ||
        mnemonic == "push" || mnemonic == "pop" ||
        mnemonic == "xchg" || mnemonic == "ldr" || mnemonic == "str") {
        return ImVec4(1.0f, 1.0f, 0.7f, 1.0f);
    }

    // Arithmetic - Orange
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "mul" ||
        mnemonic == "div" || mnemonic == "inc" || mnemonic == "dec" ||
        mnemonic == "imul" || mnemonic == "idiv" || mnemonic == "neg") {
        return ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
    }

    // Logic/bitwise - Purple
    if (mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "not" || mnemonic == "shl" || mnemonic == "shr" ||
        mnemonic == "sar" || mnemonic == "rol" || mnemonic == "ror" ||
        mnemonic == "test" || mnemonic == "cmp") {
        return ImVec4(0.8f, 0.6f, 1.0f, 1.0f);
    }

    // Compare/test - Cyan
    if (mnemonic == "cmp" || mnemonic == "test" ||
        mnemonic.find("cmp") == 0 || mnemonic.find("test") == 0) {
        return ImVec4(0.4f, 1.0f, 1.0f, 1.0f);
    }

    // Default - White
    return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
}
} // namespace viewer