#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "disasm/disassembler.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/symbol_index.hpp"
#include "tools/shellcode_converter.hpp"
#include "ui_panel.hpp"
#include "disasm/linear_disassembly.hpp"
#include "ui/logger.hpp"
#include "ui/ui_context_menu.hpp"
#include "analysis/patch_preview.hpp"
#include "navigation/byte_range.hpp"

namespace viewer {

    class FilePanel : public UiPanel {
    public:
        explicit FilePanel(BinaryModel& model);
        void set_attach_requested_callback(std::function<void()> cb) { on_attach_requested_ = std::move(cb); }
        void set_refresh_requested_callback(std::function<void()> cb) { on_refresh_requested_ = std::move(cb); }
        void set_detach_requested_callback(std::function<void()> cb) { on_detach_requested_ = std::move(cb); }
        void set_pause_toggle_callback(std::function<void()> cb) { on_pause_toggle_ = std::move(cb); }
        void set_slice_selected_callback(std::function<void(std::size_t)> cb) {
            on_slice_selected_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        std::function<void()> on_attach_requested_;
        std::function<void()> on_refresh_requested_;
        std::function<void()> on_detach_requested_;
        std::function<void()> on_pause_toggle_;
        std::function<void(std::size_t)> on_slice_selected_;
        EntityContextActionCallback on_context_action_;
    };

    class MemoryMapPanel : public UiPanel {
    public:
        MemoryMapPanel(BinaryModel& model, ViewerSelection& selection);
        void set_attach_requested_callback(std::function<void()> cb) { on_attach_requested_ = std::move(cb); }
        void set_refresh_requested_callback(std::function<void()> cb) { on_refresh_requested_ = std::move(cb); }
        void set_detach_requested_callback(std::function<void()> cb) { on_detach_requested_ = std::move(cb); }
        void set_pause_toggle_callback(std::function<void()> cb) { on_pause_toggle_ = std::move(cb); }
        void set_module_selected_callback(std::function<void(std::size_t)> cb) {
            on_module_selected_ = std::move(cb);
        }
        void set_region_activated_callback(
            std::function<void(std::size_t region_index, bool prefer_module_context)> cb) {
            on_region_activated_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        ViewerSelection& selection_;
        char filter_buf_[128] = {};
        bool filter_exec_only_ = false;
        bool filter_writable_only_ = false;
        bool filter_modules_only_ = false;
        int category_filter_ = -1;     // -1 = all, 0..6 = VMMap category slice
        int footprint_filter_ = -1;    // -1 = all, 0..5 = physical footprint slice
        int protection_filter_ = -1;   // -1 = all, 0..4 = protection slice
        std::function<void()> on_attach_requested_;
        std::function<void()> on_refresh_requested_;
        std::function<void()> on_detach_requested_;
        std::function<void()> on_pause_toggle_;
        std::function<void(std::size_t)> on_module_selected_;
        std::function<void(std::size_t, bool)> on_region_activated_;
        EntityContextActionCallback on_context_action_;
    };

    class StructureNavigatorPanel : public UiPanel {
    public:
        StructureNavigatorPanel(const std::optional<StructureNode>& tree,
                                ViewerSelection& selection,
                                BinaryModel* model = nullptr,
                                NavigationRequestQueue* navigation_queue = nullptr,
                                EntityContextActionCallback on_context_action = {});
        void set_model(BinaryModel* model) noexcept { model_ = model; }
        void set_navigation_queue(NavigationRequestQueue* queue) noexcept { navigation_queue_ = queue; }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        const std::optional<StructureNode>& tree_;
        ViewerSelection& selection_;
        BinaryModel* model_ = nullptr;
        NavigationRequestQueue* navigation_queue_ = nullptr;
        EntityContextActionCallback on_context_action_{};
        char filter_buf_[128] = {};

        void draw_node(const StructureNode& node,
                       bool force_expand,
                       std::optional<ViewerSelection>& pending_activation,
                       std::optional<PendingEntityContextAction>& pending_ctx_action);
    };

    class SelectionDetailsPanel : public UiPanel {
    public:
        explicit SelectionDetailsPanel(const ViewerSelection& selection, const BinaryModel* model = nullptr);
    protected:
        void draw_contents() override;
    private:
        const ViewerSelection& selection_;
        const BinaryModel* model_ = nullptr;
    };

    class SectionsPanel : public UiPanel {
    public:
        explicit SectionsPanel(BinaryModel& model);
        void set_section_activated_callback(
            std::function<void(const peelf::Section& section, std::uint64_t object_index)> cb) {
            on_section_activated_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::Section& section, std::uint64_t object_index)> on_section_activated_;
        EntityContextActionCallback on_context_action_;
    };

    class HexViewPanel : public UiPanel {
    public:
        explicit HexViewPanel(BinaryModel& model);
        // Invoked with the file/window offset of the byte the user clicks.
        void set_byte_activated_callback(std::function<void(std::uint64_t, std::uint64_t)> cb) {
            on_byte_activated_ = std::move(cb);
        }
        void set_bytes_patched_callback(std::function<void(std::uint64_t)> cb) {
            on_bytes_patched_ = std::move(cb);
        }
        void set_apply_structure_callback(std::function<void(std::uint64_t address, bool is_file_offset)> cb) {
            on_apply_structure_ = std::move(cb);
        }
        void navigate_to_range(std::uint64_t file_offset, std::uint64_t size);
        void navigate_to_ranges(std::span<const ByteRange> ranges);
        void clear_selection() noexcept;
        void set_unavailable_reason(std::string reason);
        void clear_unavailable_reason() noexcept { unavailable_reason_.clear(); }
        [[nodiscard]] const std::string& unavailable_reason() const noexcept { return unavailable_reason_; }
        void set_address_display_mode(AddressDisplayMode mode) noexcept { address_mode_ = mode; }
        [[nodiscard]] AddressDisplayMode address_display_mode() const noexcept { return address_mode_; }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        std::uint64_t selected_offset_ = 0;
        std::uint64_t highlighted_offset_ = 0;
        std::uint64_t highlighted_size_ = 0;
        std::vector<ByteRange> mapped_ranges_;
        std::optional<std::uint64_t> pending_scroll_offset_;
        std::size_t bytes_per_row_ = 16;
        std::uint64_t goto_offset_ = 0;
        AddressDisplayMode address_mode_ = AddressDisplayMode::FileOffset;
        std::string unavailable_reason_{};
        char edit_bytes_[4096] = {};
        std::string edit_status_;
        std::function<void(std::uint64_t, std::uint64_t)> on_byte_activated_;
        char quick_patch_buf_[256] = {};
        std::string quick_patch_status_;
        std::uint64_t quick_patch_offset_ = 0;
        std::function<void(std::uint64_t)> on_bytes_patched_;
        std::function<void(std::uint64_t, bool)> on_apply_structure_;
    };

    class ShellcodeScratchPanel : public UiPanel {
    public:
        ShellcodeScratchPanel(BinaryModel& model, const ViewerSelection& selection);
        void set_patch_changed_callback(std::function<void()> cb) { on_patch_changed_ = std::move(cb); }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        const ViewerSelection& selection_;
        bool assembly_mode_ = false;
        char input_buf_[32768] = {};
        ShellcodeScratchCache scratch_cache_;
        std::function<void()> on_patch_changed_;

        [[nodiscard]] ShellcodeTargetConfig current_target_config() const;
        void rebuild_output();
        void draw_hex_output() const;
        void apply_to_selection();
        [[nodiscard]] std::optional<std::uint64_t> selected_file_offset() const;
        [[nodiscard]] std::uint64_t effective_base_address() const;
    };

    class PatchSetPanel : public UiPanel {
    public:
        PatchSetPanel(BinaryModel& model, ViewerSelection& selection);
        void set_analysis_context(const SymbolIndex* symbols, const bool* thumb) { symbols_ = symbols; thumb_ = thumb; }
        void reset_preview() {
            preview_.reset();
            last_asm_target_.reset();
            live_asm_bytes_.clear();
            live_asm_disasm_.clear();
            live_asm_diag_.clear();
            imported_bundle_.reset();
            imported_bundle_preview_.reset();
            bundle_status_.clear();
            replacement_[0] = 0;
            status_.clear();
        }
        void reset_for_new_target();
        void set_patch_activated_callback(std::function<void(const ViewerSelection&)> cb) {
            on_patch_activated_ = std::move(cb);
        }
        void set_patch_mutated_callback(std::function<void()> cb) {
            on_patch_mutated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        void refresh_live_assembly_preview();
        void refresh_imported_bundle_preview();

        BinaryModel& model_;
        ViewerSelection& selection_;
        std::string status_;
        const SymbolIndex* symbols_ = nullptr;
        const bool* thumb_ = nullptr;
        int input_mode_ = 0; // 0 = Hex Bytes, 1 = Assemble Instructions
        bool pad_nops_to_boundary_ = false;
        char replacement_[4096]{};
        char asm_input_[8192]{};
        std::optional<ShellcodeTargetConfig> last_asm_target_;
        std::vector<std::uint8_t> live_asm_bytes_;
        std::vector<Instruction> live_asm_disasm_;
        std::string live_asm_diag_;
        std::optional<PatchPreview> preview_;
        char bundle_path_[1024]{};
        char bundle_name_[256]{};
        char bundle_desc_[512]{};
        bool bundle_allow_hash_mismatch_ = false;
        std::string bundle_status_;
        std::optional<peelf::PatchBundle> imported_bundle_;
        std::optional<peelf::PatchBundlePreview> imported_bundle_preview_;
        std::string loaded_target_path_{};
        std::string status_message_;
        std::function<void(const ViewerSelection&)> on_patch_activated_;
        std::function<void()> on_patch_mutated_;
    };

    class DisassemblyPanel : public UiPanel {
    public:
        explicit DisassemblyPanel(BinaryModel& model, std::vector<Instruction>& instructions);
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
        std::vector<Instruction>& current_instructions_;
    protected:
        void draw_contents() override;


    private:
        BinaryModel& model_;
        EntityContextActionCallback on_context_action_;
    };

    class SymbolsPanel : public UiPanel {
    public:
        SymbolsPanel(const SymbolIndex& index, const ViewerSelection& selection, BinaryModel& model);
        void set_display_name_resolver(std::function<std::string(const SymbolRecord&)> resolver) {
            display_name_resolver_ = std::move(resolver);
        }
        void set_symbol_activated_callback(
            std::function<void(const SymbolRecord& symbol, std::uint64_t object_index)> cb) {
            on_symbol_activated_ = std::move(cb);
        }
        void set_demangle_changed_callback(std::function<void(bool)> cb) {
            on_demangle_changed_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        const SymbolIndex& index_;
        BinaryModel& model_;
        bool functions_only_ = true;
        std::string library_filter_;
        std::string library_filter_file_;
        const ViewerSelection& selection_;
        char filter_buf_[128] = {};
        std::optional<std::uint64_t> last_scrolled_selected_;
        std::function<std::string(const SymbolRecord&)> display_name_resolver_;
        std::function<void(const SymbolRecord& symbol, std::uint64_t object_index)> on_symbol_activated_;
        std::function<void(bool)> on_demangle_changed_;
        EntityContextActionCallback on_context_action_;
    };

    class ImportsPanel : public UiPanel {
    public:
        explicit ImportsPanel(BinaryModel& model);
        void set_import_activated_callback(
            std::function<void(const peelf::ImportEntry& entry, std::uint64_t object_index)> cb) {
            on_import_activated_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::ImportEntry& entry, std::uint64_t object_index)> on_import_activated_;
        EntityContextActionCallback on_context_action_;
    };

    class ExportsPanel : public UiPanel {
    public:
        explicit ExportsPanel(BinaryModel& model);
        void set_export_activated_callback(
            std::function<void(const peelf::ExportEntry& entry, std::uint64_t object_index)> cb) {
            on_export_activated_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::ExportEntry& entry, std::uint64_t object_index)> on_export_activated_;
        EntityContextActionCallback on_context_action_;
    };

    class LogPanel : public UiPanel {
    public:
        using Entry = LogEntry;

        explicit LogPanel(std::size_t capacity = 5000); // ring buffer capacity

        void add(LogLevel level, const std::string& msg);
        [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
        [[nodiscard]] std::vector<LogEntry> snapshot() const;
        void clear() noexcept;

    protected:
        void draw_contents() override;

    private:
        mutable std::mutex mutex_;
        std::vector<Entry> buffer_;
        std::size_t capacity_;
        std::size_t start_ = 0;   // ring buffer head
        std::size_t count_ = 0;   // number of valid entries

        bool auto_scroll_ = true;
    };

    // PE-specific panels
    class PeHeadersPanel : public UiPanel {
    public:
        explicit PeHeadersPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
    };

    class PeImportsPanel : public UiPanel {
    public:
        explicit PeImportsPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
    };

    class PeExportsPanel : public UiPanel {
    public:
        explicit PeExportsPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
    };

    class FunctionsPanel : public UiPanel {
    public:
        FunctionsPanel(BinaryModel& model, const ViewerSelection& selection);
        void set_function_activated_callback(
            std::function<void(std::uint64_t virtual_address, bool decompile)> cb) {
            on_function_activated_ = std::move(cb);
        }
        void set_demangle_changed_callback(std::function<void(bool)> cb) {
            on_demangle_changed_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        const ViewerSelection& selection_;
        char filter_buf_[128] = {};
        int origin_filter_ = 0;
        std::function<void(std::uint64_t, bool)> on_function_activated_;
        std::function<void(bool)> on_demangle_changed_;
    };

    class ThreadsAndStackPanel : public UiPanel {
    public:
        explicit ThreadsAndStackPanel(BinaryModel& model);
        void set_address_activated_callback(
            std::function<void(std::uint64_t virtual_address, PreferredView view, bool decompile)> cb) {
            on_address_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        std::string status_note_;
        std::function<void(std::uint64_t, PreferredView, bool)> on_address_activated_;
    };

    class ThreadLocalsPanel : public UiPanel {
    public:
        explicit ThreadLocalsPanel(BinaryModel& model);
        void set_address_activated_callback(
            std::function<void(std::uint64_t virtual_address, PreferredView view)> cb) {
            on_address_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(std::uint64_t, PreferredView)> on_address_activated_;
    };

    class MemorySearchPanel : public UiPanel {
    public:
        explicit MemorySearchPanel(BinaryModel& model);
        void reset_for_new_target() noexcept {
            last_report_.reset();
            error_message_.clear();
        }
        void set_address_activated_callback(
            std::function<void(std::uint64_t virtual_address, std::size_t size)> cb) {
            on_address_activated_ = std::move(cb);
        }
        void set_offset_activated_callback(
            std::function<void(std::uint64_t file_offset, std::size_t size)> cb) {
            on_offset_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        int scope_idx_ = 0;
        int kind_idx_ = 0;
        int endian_mode_ = 0; // 0 = Target auto, 1 = Little, 2 = Big
        int align_idx_ = 0;   // 0 = 1B, 1 = 2B, 2 = 4B, 3 = 8B
        bool case_sensitive_ = true;
        int max_results_ = 5000;
        char query_buf_[512] = {};
        std::optional<peelf::MemorySearchReport> last_report_;
        std::string error_message_;
        std::function<void(std::uint64_t, std::size_t)> on_address_activated_;
        std::function<void(std::uint64_t, std::size_t)> on_offset_activated_;

        void run_search();
    };

    class RuntimeAndFlagsPanel : public UiPanel {
    public:
        explicit RuntimeAndFlagsPanel(BinaryModel& model);
        void set_address_activated_callback(
            std::function<void(std::uint64_t virtual_address, PreferredView view)> cb) {
            on_address_activated_ = std::move(cb);
        }
        void set_context_action_callback(EntityContextActionCallback cb) {
            on_context_action_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char flags_filter_buf_[128] = {};
        char audit_filter_buf_[128] = {};
        int audit_severity_filter_ = 0; // 0 = All, 1 = Warnings & Errors, 2 = Errors Only
        std::function<void(std::uint64_t, PreferredView)> on_address_activated_;
        EntityContextActionCallback on_context_action_;
    };

    class HandlersPanel : public UiPanel {
    public:
        explicit HandlersPanel(BinaryModel& model);
        void set_address_activated_callback(
            std::function<void(std::uint64_t virtual_address, PreferredView view)> cb) {
            on_address_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        int category_filter_ = 0;
        char filter_buf_[128] = {};
        std::function<void(std::uint64_t, PreferredView)> on_address_activated_;
    };

} // namespace viewer
