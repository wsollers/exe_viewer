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
#include "ui_panels_references.hpp"
#include "decompile/decompiler.hpp"
#include <future>
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
        void process_deferred_gpu_work();

        void set_open_file_callback(std::function<void()> cb) { on_open_file_ = std::move(cb); }
        void set_open_debug_symbols_callback(std::function<void()> cb) { on_open_debug_symbols_ = std::move(cb); }
        void set_save_patched_as_callback(std::function<void()> cb) { on_save_patched_as_ = std::move(cb); }
        void set_exit_callback(std::function<void()> cb) { on_exit_ = std::move(cb); }
        void set_analysis_file_callback(std::function<void(int)> cb) { on_analysis_file_ = std::move(cb); }
        peelf::Result<void> save_project(const std::filesystem::path&);
        peelf::Result<void> open_project(const std::filesystem::path&);
        peelf::Result<void> save_patch_report(const std::filesystem::path&);
        void set_code_font(ImFont* font) { code_font_ = font; }

        LogPanel& log_panel() { return log_panel_; }

        bool show_demo_window_ = false;

        enum class CallGraphSample : std::uint8_t {
            LoadedImage,
            PeStartup,
            ElfStartup
        };

        struct PendingCallGraphRequest {
            CallGraphSample sample = CallGraphSample::LoadedImage;
            std::uint8_t delay_frames = 0;
        };

        void disassemble_at(std::uint64_t rva, std::size_t size);

        void disassemble_entry_point(std::size_t max_size);

        void render_disassembly_panel();

        void on_file_loaded();
        void load_debug_symbols(const std::filesystem::path& path);
        void navigate_to_address(std::uint64_t address, PreferredView view = PreferredView::Disassembly);

        ImVec4 get_mnemonic_color(const std::string &mnemonic) const;

        void disassemble_section(const std::string &section_name, std::size_t max_size);

        // Disassemble a window of raw bytes starting at a file offset (used by the
        // Hex view's click-to-disassemble). Format-agnostic.
        void disassemble_at_offset(std::size_t file_offset);
        void disassemble_at_offset(std::size_t file_offset, std::uint64_t display_address);


    private:
        ImFont* code_font_ = nullptr; // Owned by the ImGui font atlas.
        bool show_decompiler_ = false;
        bool focus_decompiler_ = false;
        bool binary_ninja_ = false;
        char decompiler_python_[1024] = "python";
        DecompiledUnit decompiled_;
        std::future<DecompiledUnit> decompile_job_;
        std::stop_source decompile_stop_;
        std::uint64_t decompile_revision_ = 0, file_generation_ = 0, decompile_generation_ = 0;
        bool show_about_ = false;
        std::uint64_t jump_address_ = 0;
        bool focus_graph_ = false;
        bool focus_workspace_ = true;
        bool focus_listing_ = false;
        BinaryModel& model_;
        VulkanManager& vulkan_;
        std::optional<StructureNode> structure_tree_;
        SymbolIndex symbol_index_;
        ReferenceIndex reference_index_;
        AnnotationStore annotations_;
        bool references_dirty_ = true;
        bool focus_references_ = false;
        std::uint64_t reference_revision_ = 0;
        std::uint64_t annotation_revision_ = 0;
        bool reference_thumb_mode_ = false;
        ViewerSelection current_selection_;
        std::optional<ViewerSelection> last_navigation_selection_;
        NavigationHistory navigation_history_;
        void navigate_history(bool forward);
        void switch_analysis_view(bool graph);
        [[nodiscard]] std::optional<SymbolRecord> navigation_graph_root(std::uint64_t address) const;

        FilePanel       file_panel_;
        StructureNavigatorPanel structure_panel_;
        SelectionDetailsPanel details_panel_;
        SectionsPanel   sections_panel_;
        HexViewPanel    hex_panel_;
        PatchSetPanel   patch_set_panel_;
        ShellcodeScratchPanel shellcode_panel_;
        ImportsPanel    imports_panel_;
        ExportsPanel    exports_panel_;
        SymbolsPanel    symbols_panel_;
        ReferencesPanel references_panel_;
        LogPanel        log_panel_;
        PeHeadersPanel  pe_headers_panel_;
        PeImportsPanel  pe_imports_panel_;
        PeExportsPanel  pe_exports_panel_;

        std::function<void()> on_open_file_;
        std::function<void()> on_open_debug_symbols_;
        std::function<void()> on_save_patched_as_;
        std::function<void()> on_exit_;
        std::function<void(int)> on_analysis_file_;

        viewer::Disassembler disasm_;
        bool file_loaded_ = false;
        bool thumb_mode_ = false;
        bool reset_dock_layout_ = false;
        std::optional<bool> compact_dock_layout_;
        bool show_disassembly_panel_ = true;
        bool show_call_graph_panel_ = false;
        CallGraphSample call_graph_sample_ = CallGraphSample::LoadedImage;
        std::optional<VulkanManager::Texture> call_graph_texture_;
        std::optional<CallGraph> current_call_graph_;
        std::optional<GraphLayout> current_call_graph_layout_;
        std::optional<SymbolRecord> pending_call_graph_root_;
        std::optional<SymbolRecord> active_graph_root_;
        bool function_cfg_ = true;
        float graph_zoom_ = 1.0f;
        ImVec2 graph_pan_{};
        bool fit_graph_ = false;
        bool center_graph_selection_ = false;
        std::uint64_t graph_revision_ = 0;
        std::uint8_t pending_call_graph_delay_frames_ = 0;
        std::optional<PendingCallGraphRequest> pending_call_graph_request_;
        std::string call_graph_status_;
        char graph_search_[128] = {};
        std::filesystem::path loaded_call_graph_bmp_;
        PeModel pe_model_;
        std::vector<Instruction> current_instructions_;
        struct DisassemblyLocation {
            std::size_t file_offset;
            std::uint64_t address;
        };
        // Keep the requested location even when edited bytes cannot be decoded.
        std::optional<DisassemblyLocation> disassembly_location_;
        std::uint64_t rendered_edit_revision_ = 0;


        void render_main_menu();
        void request_decompile();
        void render_decompiler();
        void rebuild_references();
        void open_references();
        void render_dockspace();
        void render_call_graph_panel();
        void load_call_graph_sample(CallGraphSample sample);
        void queue_call_graph_sample(CallGraphSample sample);
        void load_call_graph_from_graph(CallGraph graph, const std::filesystem::path& output_name);
        void activate_call_graph_node(const CallGraphNode& node);
        const CallGraphNode* hit_test_call_graph_node(const ImVec2& image_pos,
                                                      float graph_scale,
                                                      double graph_min_x,
                                                      double graph_max_y,
                                                      const ImVec2& mouse_pos) const;
        void build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size);
        void apply_structure_selection_navigation();


    };

} // namespace viewer
