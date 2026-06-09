#include "ui_app.hpp"
#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

#include "logger.hpp"

namespace viewer {
namespace {

[[nodiscard]] std::optional<viewer::Architecture> disassembler_architecture(peelf::Architecture arch) {
    switch (arch) {
        case peelf::Architecture::X86:       return viewer::Architecture::X86_32;
        case peelf::Architecture::X86_64:    return viewer::Architecture::X86_64;
        case peelf::Architecture::ARM:       return viewer::Architecture::ARM32;
        case peelf::Architecture::ARM64:     return viewer::Architecture::ARM64;
        case peelf::Architecture::MIPS32:    return viewer::Architecture::MIPS32;
        case peelf::Architecture::MIPS64:    return viewer::Architecture::MIPS64;
        case peelf::Architecture::PowerPC:   return viewer::Architecture::PowerPC32;
        case peelf::Architecture::PowerPC64: return viewer::Architecture::PowerPC64;
        case peelf::Architecture::RISCV32:   return viewer::Architecture::RISCV32;
        case peelf::Architecture::RISCV64:   return viewer::Architecture::RISCV64;
        default:                             return std::nullopt;
    }
}

[[nodiscard]] viewer::Endianness disassembler_endianness(peelf::Endianness endianness) {
    return endianness == peelf::Endianness::Big ? viewer::Endianness::Big : viewer::Endianness::Little;
}

} // namespace

UiApp::UiApp(BinaryModel& model)
    : model_(model)
    , file_panel_(model)
    , structure_panel_(structure_tree_, current_selection_)
    , details_panel_(current_selection_)
    , sections_panel_(model)
    , hex_panel_(model)
    , imports_panel_(model)
    , exports_panel_(model)
    , symbols_panel_(model)
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{
    hex_panel_.set_byte_activated_callback([this](std::size_t off) {
        disassemble_at_offset(off);
    });
    sections_panel_.set_section_activated_callback(
        [this](std::size_t file_offset, std::size_t size, std::uint64_t virtual_address) {
            hex_panel_.navigate_to_range(file_offset, size);
            disassemble_at_offset(file_offset, virtual_address);
        });
    symbols_panel_.set_symbol_activated_callback([this](const peelf::Symbol& symbol) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            return;
        }

        const auto file_offset = img->virtual_address_to_file_offset(symbol.virtual_address);
        if (!file_offset) {
            Log().warn("Symbol '{}' at 0x{:X} does not map to file bytes",
                       symbol.name.empty() ? "<unnamed>" : symbol.name,
                       symbol.virtual_address);
            return;
        }
        if (*file_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            symbol.size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            Log().warn("Symbol '{}' range is too large for this platform",
                       symbol.name.empty() ? "<unnamed>" : symbol.name);
            return;
        }

        const std::size_t highlight_size = symbol.size != 0
            ? static_cast<std::size_t>(symbol.size)
            : std::size_t{1};
        hex_panel_.navigate_to_range(static_cast<std::size_t>(*file_offset), highlight_size);
        disassemble_at_offset(static_cast<std::size_t>(*file_offset), symbol.virtual_address);
    });
}

void UiApp::render() {
    render_main_menu();
    render_dockspace();

    file_panel_.draw();
    structure_panel_.draw();
    details_panel_.draw();
    sections_panel_.draw();
    hex_panel_.draw();
    imports_panel_.draw();
    exports_panel_.draw();
    symbols_panel_.draw();
    pe_headers_panel_.draw();
    pe_imports_panel_.draw();
    pe_exports_panel_.draw();
    log_panel_.draw();

    if (show_disassembly_panel_) {
        render_disassembly_panel();
    }
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
        if (ImGui::MenuItem("Reset Layout")) {
            reset_dock_layout_ = true;
        }
        ImGui::Separator();
        ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);

        {
            bool v = file_panel_.visible();
            if (ImGui::MenuItem(file_panel_.name().c_str(), nullptr, &v))
                file_panel_.set_visible(v);
        }

        {
            bool v = structure_panel_.visible();
            if (ImGui::MenuItem(structure_panel_.name().c_str(), nullptr, &v))
                structure_panel_.set_visible(v);
        }

        {
            bool v = details_panel_.visible();
            if (ImGui::MenuItem(details_panel_.name().c_str(), nullptr, &v))
                details_panel_.set_visible(v);
        }

        {
            bool v = sections_panel_.visible();
            if (ImGui::MenuItem(sections_panel_.name().c_str(), nullptr, &v))
                sections_panel_.set_visible(v);
        }

        {
            bool v = hex_panel_.visible();
            if (ImGui::MenuItem(hex_panel_.name().c_str(), nullptr, &v))
                hex_panel_.set_visible(v);
        }

        {
            bool v = imports_panel_.visible();
            if (ImGui::MenuItem(imports_panel_.name().c_str(), nullptr, &v))
                imports_panel_.set_visible(v);
        }

        {
            bool v = exports_panel_.visible();
            if (ImGui::MenuItem(exports_panel_.name().c_str(), nullptr, &v))
                exports_panel_.set_visible(v);
        }

        {
            bool v = symbols_panel_.visible();
            if (ImGui::MenuItem(symbols_panel_.name().c_str(), nullptr, &v))
                symbols_panel_.set_visible(v);
        }

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

        {
            ImGui::MenuItem("Disassembly", nullptr, &show_disassembly_panel_);
        }

        {
            bool v = log_panel_.visible();
            if (ImGui::MenuItem(log_panel_.name().c_str(), nullptr, &v))
                log_panel_.set_visible(v);
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

    const ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
    const ImGuiDockNodeFlags dock_flags = ImGuiDockNodeFlags_None;
    if (reset_dock_layout_ || ImGui::DockBuilderGetNode(dockspace_id) == nullptr) {
        build_default_dock_layout(dockspace_id, viewport->WorkSize);
        reset_dock_layout_ = false;
    }
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dock_flags);

    ImGui::End();
}

void UiApp::build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size) {
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

    ImGuiID main_id = dockspace_id;
    const ImGuiID left_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Left, 0.22f, nullptr, &main_id);
    const ImGuiID right_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Right, 0.24f, nullptr, &main_id);
    const ImGuiID bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.22f, nullptr, &main_id);
    const ImGuiID center_bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.42f, nullptr, &main_id);

    ImGui::DockBuilderDockWindow(structure_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(file_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(sections_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(symbols_panel_.name().c_str(), left_id);

    ImGui::DockBuilderDockWindow(details_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(exports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_headers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_exports_panel_.name().c_str(), right_id);

    ImGui::DockBuilderDockWindow(hex_panel_.name().c_str(), main_id);
    ImGui::DockBuilderDockWindow("Disassembly", center_bottom_id);
    ImGui::DockBuilderDockWindow(log_panel_.name().c_str(), bottom_id);

    ImGui::DockBuilderFinish(dockspace_id);
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
            for (std::uint8_t b: inst.bytes) {
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
    // Called after a file (PE or ELF) is loaded into the model.
    void UiApp::on_file_loaded() {
        const peelf::IBinaryImage* img = model_.image();
        if (!img) {
            file_loaded_ = false;
            structure_tree_.reset();
            current_selection_ = {};
            return;
        }

        structure_tree_ = build_structure_tree(*img);
        current_selection_ = structure_tree_->selection;

        // Map the unified architecture onto the disassembler's enum.
        const std::optional<viewer::Architecture> arch = disassembler_architecture(img->architecture());
        if (!arch) {
            Log().error(std::string("Disassembly is not supported for architecture: ") +
                        std::string(peelf::to_string(img->architecture())));
            file_loaded_ = false;
            current_instructions_.clear();
            return;
        }

        if (!disasm_.init(*arch, disassembler_endianness(img->endianness()))) {
            Log().error(std::string("Failed to initialize disassembler: ") + disasm_.get_error());
            file_loaded_ = false;
            return;
        }
        file_loaded_ = true;
        current_instructions_.clear();

        if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            hex_panel_.navigate_to_range(static_cast<std::size_t>(*entry_offset), 1);
        }

        // PE keeps its entry-point disassembly via the legacy PeModel. ELF
        // entry-point disassembly via the unified image is future work (P4);
        // for now, click a byte in the Hex view to disassemble at that offset.
        if (const PeModel* pe = model_.pe()) {
            pe_model_ = *pe;
            disassemble_entry_point(4096);
        } else if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            disassemble_at_offset(static_cast<std::size_t>(*entry_offset), img->entry_point());
        }
    }




    void UiApp::disassemble_section(const std::string& section_name, std::size_t max_size) {
        const auto* section = pe_model_.section_by_name(section_name);
        if (!section) {
            fprintf(stderr, "Section '%s' not found\n", section_name.c_str());
            return;
        }

        // Check if section is executable
        if (!(section->characteristics & 0x20000000)) {
            fprintf(stderr, "Warning: Section '%s' is not marked executable\n", section_name.c_str());
        }

        std::size_t size = std::min(max_size, static_cast<std::size_t>(section->raw_size));
        const std::uint8_t* code = pe_model_.data_at_offset(section->raw_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read section data\n");
            return;
        }

        std::uint64_t va = pe_model_.rva_to_va(section->virtual_address);
        auto instructions = disasm_.disassemble(code, size, va);

        printf("Section: %s (0x%llX - 0x%llX)\n",
               section_name.c_str(), va, va + section->virtual_size);
        printf("----------------------------------------\n");

        for (const auto& inst : instructions) {
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
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
    void UiApp::disassemble_at(std::uint64_t rva, std::size_t size) {
        // Get file offset from RVA
        auto file_offset = pe_model_.rva_to_offset(static_cast<std::uint32_t>(rva));
        if (!file_offset) {
            fprintf(stderr, "Failed to convert RVA 0x%llX to file offset\n", rva);
            return;
        }

        // Get pointer to code
        const std::uint8_t* code = pe_model_.data_at_offset(*file_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read %zu bytes at offset 0x%zX\n", size, *file_offset);
            return;
        }

        // Convert RVA to VA for disassembly
        std::uint64_t va = pe_model_.rva_to_va(static_cast<std::uint32_t>(rva));

        // Disassemble
        auto instructions = disasm_.disassemble(code, size, va);

        for (const auto& inst : instructions) {
            // Format bytes
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
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

    void UiApp::disassemble_at_offset(std::size_t file_offset) {
        std::uint64_t display_address = file_offset;
        if (const peelf::IBinaryImage* img = model_.image()) {
            if (const auto va = img->file_offset_to_virtual_address(file_offset)) {
                display_address = *va;
            }
        }
        disassemble_at_offset(file_offset, display_address);
    }

    void UiApp::disassemble_at_offset(std::size_t file_offset, std::uint64_t display_address) {
        if (!file_loaded_ || !disasm_.is_initialized()) {
            return;
        }
        const auto& bytes = model_.bytes();
        if (file_offset >= bytes.size()) {
            return;
        }
        constexpr std::size_t kWindow = 256;
        const std::size_t avail = bytes.size() - file_offset;
        const std::size_t size = std::min(kWindow, avail);
        current_instructions_ = disasm_.disassemble(bytes.data() + file_offset, size, display_address);
    }

    void UiApp::disassemble_entry_point(std::size_t max_size) {
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
            const std::uint32_t offset_in_section = pe_model_.entry_point_rva - section->virtual_address;
            if (offset_in_section >= section->raw_size) {
                Log().error("Entry point is outside the section's raw bytes\n");
                return;
            }
            std::size_t section_remaining = static_cast<std::size_t>(section->raw_size - offset_in_section);
            max_size = std::min(max_size, section_remaining);
        }

        const std::uint8_t* code = pe_model_.data_at_offset(*offset, max_size);
        if (!code) {
            Log().error("Failed to read entry point code\n");
            return;
        }

        std::uint64_t va = pe_model_.entry_point_va();
        current_instructions_ = disasm_.disassemble(code, max_size, va);

        Log().error("Entry Point: 0x%llX\n", va);
        printf("----------------------------------------\n");

        for (const auto& inst : current_instructions_) {
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
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
