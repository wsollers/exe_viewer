#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "analysis/project.hpp"
#include "analysis/strings_index.hpp"
#include "model/binary_model.hpp"
#include "model/recent_binaries.hpp"
#include "ui_panels.hpp"
#include "ui_panels_references.hpp"
#include "ui_panels_strings.hpp"
#include "ui_panels_struct_view.hpp"
#include "ui_panels_process_internals.hpp"
#include "ui_panels_dependencies.hpp"
#include "ui_panels_diff.hpp"
#include "ui_panels_debugger.hpp"
#include "ui_panels_capabilities.hpp"
#include "decompile/decompile_controller.hpp"
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
        peelf::Result<void> open_project(const std::filesystem::path& path,
                                         const std::filesystem::path& relocated_binary = {},
                                         bool allow_modified_binary = false,
                                         bool skip_mismatched_patches = false);
        peelf::Result<void> save_patch_report(const std::filesystem::path&);
        peelf::Result<void> compare_with_binary(const std::filesystem::path& path);
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
        void on_process_attached();
        void load_debug_symbols(const std::filesystem::path& path);
        void navigate_to_address(std::uint64_t address, PreferredView view = PreferredView::Disassembly);

        ImVec4 get_mnemonic_color(const std::string &mnemonic) const;

        void disassemble_section(const std::string &section_name, std::size_t max_size);

        // Disassemble a window of raw bytes starting at a file/window offset (used by
        // Hex view, Symbols, MemMap, and Structure navigation). Format-agnostic.
        void disassemble_at_offset(std::uint64_t file_offset);
        void disassemble_at_offset(std::uint64_t file_offset, std::uint64_t display_address);
        void disassemble_at_offset(std::uint64_t file_offset,
                                   std::uint64_t display_address,
                                   std::size_t max_window_bytes);
        void refresh_disassembly();


    private:
        ImFont* code_font_ = nullptr; // Owned by the ImGui font atlas.
        bool show_decompiler_ = false;
        bool focus_decompiler_ = false;
        int decompiler_provider_ = 0;
        char ghidra_home_[2048] = "";
        char decompiler_java_[2048] = "java";
        int decompiler_timeout_ = 180;
        bool decompiler_thumb_ = false;
        std::filesystem::path decompiler_directory_;
        RecentBinaries recent_binaries_;
        std::filesystem::path recent_binaries_path_;
        std::string decompiler_settings_status_;
        void initialize_decompiler();
        void render_data_types();
        void select_decompiled_line(std::size_t index);
        bool show_data_types_ = true;
        char data_type_filter_[256] = {};
        std::vector<DataTypeRecord> debug_types_;
        std::optional<SymbolRecord> decompiled_root_;
        std::vector<CodeRange> selected_code_ranges_;
        std::optional<std::uint64_t> selected_code_address_;
        std::uint64_t decompile_annotation_revision_ = 0, symbol_revision_ = 0, decompile_symbol_revision_ = 0;
        char decompiler_python_[1024] = "python";
        char decompiler_retdec_[1024] = "retdec-decompiler";
        DecompiledUnit decompiled_;
        DecompileCache decompile_cache_;
        DecompileController decompile_controller_;
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
        AsyncReferenceScanner reference_scanner_;
        StringsIndex strings_index_;
        AnnotationStore annotations_;
        bool references_dirty_ = true;
        bool strings_dirty_ = true;
        bool focus_references_ = false;
        bool focus_strings_ = false;
        bool focus_struct_view_ = false;
        std::uint64_t reference_revision_ = 0;
        std::uint64_t strings_revision_ = 0;
        std::uint64_t annotation_revision_ = 0;
        bool reference_thumb_mode_ = false;
        ViewerSelection current_selection_;
        std::optional<ViewerSelection> last_navigation_selection_;
        NavigationHistory navigation_history_;
        void navigate_history(bool forward);
        void switch_analysis_view(bool graph);
        [[nodiscard]] std::optional<SymbolRecord> navigation_graph_root(std::uint64_t address) const;

        FilePanel       file_panel_;
        MemoryMapPanel  memory_map_panel_;
        StructureNavigatorPanel structure_panel_;
        SelectionDetailsPanel details_panel_;
        SectionsPanel   sections_panel_;
        HexViewPanel    hex_panel_;
        PatchSetPanel   patch_set_panel_;
        ShellcodeScratchPanel shellcode_panel_;
        ImportsPanel    imports_panel_;
        ExportsPanel    exports_panel_;
        SymbolsPanel    symbols_panel_;
        FunctionsPanel  functions_panel_;
        ThreadsAndStackPanel threads_panel_;
        ThreadLocalsPanel thread_locals_panel_;
        MemorySearchPanel memory_search_panel_;
        RuntimeAndFlagsPanel runtime_flags_panel_;
        HandlersPanel   handlers_panel_;
        ReferencesPanel references_panel_;
        StringsPanel    strings_panel_;
        StructureViewPanel struct_view_panel_;
        ProcessInternalsPanel process_internals_panel_;
        DependenciesPanel dependencies_panel_;
        BinaryDiffPanel binary_diff_panel_;
        DebuggerPanel   debugger_panel_;
        CapabilityMatrixPanel capabilities_panel_;
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

        // .peproj v2 relocation, bookmarks, and autosave crash-recovery state
        std::filesystem::path current_project_path_;
        std::uint64_t current_project_saved_ms_ = 0;
        std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t> last_autosave_revisions_{0, 0, 0, 0};
        std::chrono::steady_clock::time_point last_autosave_check_{};
        bool open_relocate_modal_next_frame_ = false;
        std::optional<AnalysisProject> pending_relocation_project_;
        std::filesystem::path pending_relocation_peproj_path_;
        ProjectBinaryResolution pending_relocation_resolution_;
        char relocate_binary_buf_[2048] = {};
        std::string relocate_modal_error_;
        std::optional<AnalysisProject> pending_recovery_project_;
        std::filesystem::path pending_recovery_key_path_;

        // Live process attach modal state
        bool open_attach_modal_next_frame_ = false;
        std::vector<peelf::ProcessInfo> cached_process_list_;
        char process_filter_buf_[128] = {};
        char manual_pid_buf_[32] = {};
        bool process_accessible_only_ = false;
        std::optional<peelf::ProcessId> selected_attach_pid_;
        std::string attach_error_message_;

        // Current disassembly cursor for live refresh
        std::optional<std::uint64_t> last_disasm_offset_;
        std::uint64_t last_disasm_address_ = 0;
        std::size_t last_disasm_window_ = 4096;
        std::string disasm_status_;

        CallGraphSample call_graph_sample_ = CallGraphSample::LoadedImage;
        VulkanManager::UniqueTexture call_graph_texture_;
        std::optional<CallGraph> current_call_graph_;
        std::optional<GraphLayout> current_call_graph_layout_;
        std::optional<GraphLayout> original_call_graph_layout_;
        std::optional<std::string> dragged_graph_card_;
        bool graph_card_moved_ = false;
        ImVec2 graph_card_mouse_{};
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
        std::vector<Instruction> current_instructions_;
        struct DisassemblyLocation {
            std::size_t file_offset;
            std::uint64_t address;
        };
        // Keep the requested location even when edited bytes cannot be decoded.
        std::optional<DisassemblyLocation> disassembly_location_;
        std::uint64_t rendered_edit_revision_ = 0;


        void render_main_menu();
        [[nodiscard]] DecompileValidationStamp current_decompile_stamp() const;
        void request_decompile(bool force_reanalyze = false);
        void clear_decompiler_caches();
        void render_decompiler();
        void rebuild_references();
        void open_references();
        void rebuild_strings();
        void open_strings();
        void open_structure_view(std::string_view type_name = {},
                                 std::optional<std::uint64_t> address = std::nullopt,
                                 bool is_file_offset = false);
        void render_dockspace();
        void render_attach_process_modal();
        void render_relocate_project_modal();
        void render_recovery_banner();
        void toggle_bookmark_at_selection();
        void apply_loaded_project_metadata(const AnalysisProject& project);
        void poll_project_autosave(bool force_now = false);
        void mark_autosave_baseline() noexcept;
        [[nodiscard]] std::filesystem::path active_recovery_key_path() const;
        void open_attach_process_modal();
        void refresh_process_list();
        void sync_live_process_view(bool navigate_to_entry);
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
