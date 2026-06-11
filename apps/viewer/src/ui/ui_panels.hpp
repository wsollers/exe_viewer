#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "disasm/disassembler.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

namespace viewer {

    enum class LogLevel {
        Info,
        Warning,
        Error
    };

    class FilePanel : public UiPanel {
    public:
        explicit FilePanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
    };

    class StructureNavigatorPanel : public UiPanel {
    public:
        StructureNavigatorPanel(const std::optional<StructureNode>& tree, ViewerSelection& selection);
    protected:
        void draw_contents() override;
    private:
        const std::optional<StructureNode>& tree_;
        ViewerSelection& selection_;

        void draw_node(const StructureNode& node);
    };

    class SelectionDetailsPanel : public UiPanel {
    public:
        explicit SelectionDetailsPanel(const ViewerSelection& selection);
    protected:
        void draw_contents() override;
    private:
        const ViewerSelection& selection_;
    };

    class SectionsPanel : public UiPanel {
    public:
        explicit SectionsPanel(BinaryModel& model);
        void set_section_activated_callback(
            std::function<void(const peelf::Section& section, std::uint64_t object_index)> cb) {
            on_section_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::Section& section, std::uint64_t object_index)> on_section_activated_;
    };

    class HexViewPanel : public UiPanel {
    public:
        explicit HexViewPanel(BinaryModel& model);
        // Invoked with the file offset of the byte the user clicks.
        void set_byte_activated_callback(std::function<void(std::size_t)> cb) { on_byte_activated_ = std::move(cb); }
        void navigate_to_range(std::size_t file_offset, std::size_t size);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        std::size_t selected_offset_ = 0;
        std::size_t highlighted_offset_ = 0;
        std::size_t highlighted_size_ = 0;
        std::optional<std::size_t> pending_scroll_offset_;
        std::size_t bytes_per_row_ = 16;
        std::function<void(std::size_t)> on_byte_activated_;
    };

    class ShellcodeScratchPanel : public UiPanel {
    public:
        ShellcodeScratchPanel();
    protected:
        void draw_contents() override;
    private:
        bool assembly_mode_ = false;
        char input_buf_[32768] = {};
        std::vector<std::uint8_t> output_bytes_;
        std::string hex_view_;
        std::string diagnostic_;
        bool last_assembly_mode_ = false;

        void rebuild_output();
        void draw_hex_output() const;
    };

    class DisassemblyPanel : public UiPanel {
    public:
        explicit DisassemblyPanel(BinaryModel& model, std::vector<Instruction>& instructions);
        std::vector<Instruction>& current_instructions_;
    protected:
        void draw_contents() override;


    private:
        BinaryModel& model_;
        std::size_t selected_instr_ = 0;


    };

    class SymbolsPanel : public UiPanel {
    public:
        SymbolsPanel(BinaryModel& model, const ViewerSelection& selection);
        void set_symbol_activated_callback(
            std::function<void(const peelf::Symbol& symbol, std::uint64_t object_index)> cb) {
            on_symbol_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        const ViewerSelection& selection_;
        char filter_buf_[128] = {};
        std::optional<std::uint64_t> last_scrolled_selected_;
        std::function<void(const peelf::Symbol& symbol, std::uint64_t object_index)> on_symbol_activated_;
    };

    class ImportsPanel : public UiPanel {
    public:
        explicit ImportsPanel(BinaryModel& model);
        void set_import_activated_callback(
            std::function<void(const peelf::ImportEntry& entry, std::uint64_t object_index)> cb) {
            on_import_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::ImportEntry& entry, std::uint64_t object_index)> on_import_activated_;
    };

    class ExportsPanel : public UiPanel {
    public:
        explicit ExportsPanel(BinaryModel& model);
        void set_export_activated_callback(
            std::function<void(const peelf::ExportEntry& entry, std::uint64_t object_index)> cb) {
            on_export_activated_ = std::move(cb);
        }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
        std::function<void(const peelf::ExportEntry& entry, std::uint64_t object_index)> on_export_activated_;
    };

    class LogPanel : public UiPanel {
    public:
        explicit LogPanel(std::size_t capacity = 5000); // ring buffer capacity

        void add(LogLevel level, const std::string& msg);

    protected:
        void draw_contents() override;

    private:
        struct Entry {
            std::string timestamp;
            LogLevel level;
            std::string message;
        };

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

} // namespace viewer
