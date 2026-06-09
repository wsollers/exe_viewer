#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "model/binary_model.hpp"
#include "ui_panels.hpp"
#include "disasm/disassembler.hpp"
#include "graph/call_graph.hpp"
#include "symbols/symbol_index.hpp"
#include "vulkan/vulkan_manager.h"

namespace viewer {

    class UiApp {
    public:
        UiApp(BinaryModel& model, VulkanManager& vulkan);
        ~UiApp();

        void render(); // call each frame from Application::render_ui()

        void set_open_file_callback(std::function<void()> cb) { on_open_file_ = std::move(cb); }
        void set_open_debug_symbols_callback(std::function<void()> cb) { on_open_debug_symbols_ = std::move(cb); }

        LogPanel& log_panel() { return log_panel_; }

        bool show_demo_window_ = false;

        enum class CallGraphSample : std::uint8_t {
            LoadedImage,
            PeStartup,
            ElfStartup
        };

        void disassemble_at(std::uint64_t rva, std::size_t size);

        void disassemble_entry_point(std::size_t max_size);

        void render_disassembly_panel();

        void on_file_loaded();
        void load_debug_symbols(const std::filesystem::path& path);

        ImVec4 get_mnemonic_color(const std::string &mnemonic) const;

        void disassemble_section(const std::string &section_name, std::size_t max_size);

        // Disassemble a window of raw bytes starting at a file offset (used by the
        // Hex view's click-to-disassemble). Format-agnostic.
        void disassemble_at_offset(std::size_t file_offset);
        void disassemble_at_offset(std::size_t file_offset, std::uint64_t display_address);


    private:
        BinaryModel& model_;
        VulkanManager& vulkan_;
        std::optional<StructureNode> structure_tree_;
        SymbolIndex symbol_index_;
        ViewerSelection current_selection_;
        std::optional<ViewerSelection> last_navigation_selection_;

        FilePanel       file_panel_;
        StructureNavigatorPanel structure_panel_;
        SelectionDetailsPanel details_panel_;
        SectionsPanel   sections_panel_;
        HexViewPanel    hex_panel_;
        ImportsPanel    imports_panel_;
        ExportsPanel    exports_panel_;
        SymbolsPanel    symbols_panel_;
        LogPanel        log_panel_;
        PeHeadersPanel  pe_headers_panel_;
        PeImportsPanel  pe_imports_panel_;
        PeExportsPanel  pe_exports_panel_;

        std::function<void()> on_open_file_;
        std::function<void()> on_open_debug_symbols_;

        viewer::Disassembler disasm_;
        bool file_loaded_ = false;
        bool reset_dock_layout_ = false;
        bool show_disassembly_panel_ = true;
        bool show_call_graph_panel_ = false;
        CallGraphSample call_graph_sample_ = CallGraphSample::LoadedImage;
        std::optional<VulkanManager::Texture> call_graph_texture_;
        std::optional<CallGraph> current_call_graph_;
        std::optional<GraphLayout> current_call_graph_layout_;
        std::string call_graph_status_;
        std::filesystem::path loaded_call_graph_bmp_;
        PeModel pe_model_;
        std::vector<Instruction> current_instructions_;


        void render_main_menu();
        void render_dockspace();
        void render_call_graph_panel();
        void load_call_graph_sample(CallGraphSample sample);
        void load_call_graph_from_graph(const CallGraph& graph, const std::filesystem::path& output_name);
        void activate_call_graph_node(const CallGraphNode& node);
        const CallGraphNode* hit_test_call_graph_node(const ImVec2& image_pos,
                                                      const ImVec2& draw_size,
                                                      const ImVec2& mouse_pos) const;
        void build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size);
        void apply_structure_selection_navigation();


    };

} // namespace viewer
