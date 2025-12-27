#pragma once
#include <complex.h>

#include "ui_panel.hpp"
#include "model/binary_model.hpp"
#include <vector>
#include <string>

#include "dissassembler/dissassembler.hpp"

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
    protected:
        void draw_contents() override;
    private:
        BinaryModel& model_;
        size_t selected_offset_ = 0;
        size_t bytes_per_row_ = 16;
    };

    class DisassemblyPanel : public UiPanel {
    public:
        explicit DisassemblyPanel(BinaryModel& model, std::vector<Instruction>& instructions);
        std::vector<Instruction>& current_instructions_;
    protected:
        void draw_contents() override;


    private:
        BinaryModel& model_;
        size_t selected_instr_ = 0;


    };

    class LogPanel : public UiPanel {
    public:
        explicit LogPanel(size_t capacity = 5000); // ring buffer capacity

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
        size_t capacity_;
        size_t start_ = 0;   // ring buffer head
        size_t count_ = 0;   // number of valid entries

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