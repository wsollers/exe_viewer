#pragma once

#include "analysis/c_type_parser.hpp"
#include "analysis/structure_interpreter.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct ImFont;

namespace viewer {

class StructureViewPanel : public UiPanel {
public:
    StructureViewPanel(BinaryModel& model, const ViewerSelection& selection);

    void set_code_font(ImFont* font) noexcept { code_font_ = font; }
    void open_custom_c_editor() noexcept {
        show_custom_c_editor_ = true;
        focus_custom_c_editor_ = true;
    }

    void set_extra_types_provider(std::function<std::span<const DataTypeRecord>()> provider) {
        extra_types_provider_ = std::move(provider);
    }
    void set_field_selected_callback(
        std::function<void(std::optional<std::uint64_t> window_offset,
                           std::optional<std::uint64_t> virtual_address,
                           std::uint64_t size,
                           std::string label)> cb) {
        on_field_selected_ = std::move(cb);
    }
    void set_pointer_activated_callback(std::function<void(std::uint64_t target_va)> cb) {
        on_pointer_activated_ = std::move(cb);
    }

    /// Programmatically focuses/applies a structure at `address` (used by Data Types & Hex View).
    void apply_structure_at(std::string_view type_name,
                            std::uint64_t address,
                            bool is_file_offset,
                            std::uint32_t count = 1);

    void reset_for_new_binary();

protected:
    void draw_contents() override;

private:
    void ensure_default_type_selected(const StructureCatalog& catalog);
    void sync_custom_c_editor_from_model();
    void draw_custom_c_editor(std::span<const DataTypeRecord> extra_types);
    void reevaluate(const StructureCatalog& catalog);
    void draw_field_rows(std::span<const EvaluatedField> fields,
                         const StructureCatalog& catalog,
                         int depth);

    BinaryModel& model_;
    const ViewerSelection& selection_;
    ImFont* code_font_ = nullptr;

    char type_filter_[128] = {};
    std::string selected_type_name_{};
    std::uint64_t target_address_ = 0;
    bool use_file_offset_ = false;
    bool sync_with_selection_ = false;
    int array_count_ = 1;
    int endian_override_ = 0; // 0 = Auto (Target), 1 = Little, 2 = Big
    int width_override_ = 0;  // 0 = Auto (Target), 1 = 32-bit, 2 = 64-bit
    char binding_label_[128] = {};

    bool show_custom_c_editor_ = false;
    bool focus_custom_c_editor_ = false;
    bool custom_c_editor_dirty_ = false;
    std::string custom_c_buffer_{};
    int custom_c_abi_mode_ = 0; // 0 = Auto from Target, 1 = 64-bit, 2 = 32-bit
    std::vector<CTypeParseDiagnostic> custom_c_diagnostics_{};
    std::string custom_c_status_{};

    std::uint64_t last_synced_selection_addr_ = 0;
    bool last_synced_selection_is_off_ = false;
    std::uint64_t last_eval_revision_ = 0;
    std::uint64_t last_synced_structure_revision_ = 0;
    bool dirty_ = true;

    std::optional<EvaluatedStructure> evaluated_{};
    std::string status_error_{};
    std::string addr_mode_warning_{};
    std::string selected_field_path_{};

    std::function<std::span<const DataTypeRecord>()> extra_types_provider_{};
    std::function<void(std::optional<std::uint64_t>, std::optional<std::uint64_t>, std::uint64_t, std::string)>
        on_field_selected_{};
    std::function<void(std::uint64_t)> on_pointer_activated_{};
};

} // namespace viewer
