#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "disasm/disassembler.hpp"
#include "model/binary_model.hpp"
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

    class SectionsPanel : public UiPanel {
    public:
        explicit SectionsPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
    };

    class HexViewPanel : public UiPanel {
    public:
        explicit HexViewPanel(BinaryModel& model);
        // Invoked with the file offset of the byte the user clicks.
        void set_byte_activated_callback(std::function<void(std::size_t)> cb) { on_byte_activated_ = std::move(cb); }
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        std::size_t selected_offset_ = 0;
        std::size_t bytes_per_row_ = 16;
        std::function<void(std::size_t)> on_byte_activated_;
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
        explicit SymbolsPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
    };

    class ImportsPanel : public UiPanel {
    public:
        explicit ImportsPanel(BinaryModel& model);
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        char filter_buf_[128] = {};
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
