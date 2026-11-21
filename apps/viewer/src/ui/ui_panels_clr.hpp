// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <peelf/clr_metadata.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

struct ImFont;

namespace viewer {

class ClrMetadataPanel final : public UiPanel {
public:
    using NavigateOffsetCallback = std::function<void(std::uint64_t file_offset, std::size_t byte_length)>;

    ClrMetadataPanel(BinaryModel& model,
                     ViewerSelection& selection,
                     NavigateOffsetCallback on_navigate_offset);

    void set_code_font(ImFont* font) noexcept { code_font_ = font; }

protected:
    void draw_contents() override;

private:
    enum class MemberRowKind : std::uint8_t {
        TypeDef = 0,
        Field = 1,
        Method = 2,
    };

    struct MemberRow {
        MemberRowKind kind = MemberRowKind::TypeDef;
        std::size_t index = 0;
        std::uint32_t token = 0;
        std::uint32_t rva = 0;
        std::string display_name{};
        std::string detail{};
        std::string search_key{};
    };

    void sync_model_cache(const peelf::ClrMetadata& md);
    void rebuild_filtered_member_rows();
    void select_method_index(std::size_t method_index, const peelf::ClrMetadata& md);

    void render_overview_tab(const peelf::ClrMetadata& md);
    void render_types_and_cil_tab(const peelf::ClrMetadata& md);
    void render_cil_pane(const peelf::ClrMetadata& md);
    void render_pinvoke_tab(const peelf::ClrMetadata& md);
    void render_user_strings_tab(const peelf::ClrMetadata& md);

    BinaryModel& model_;
    ViewerSelection& selection_;
    NavigateOffsetCallback on_navigate_offset_{};
    ImFont* code_font_ = nullptr;

    const peelf::IBinaryImage* cached_image_ptr_ = nullptr;
    std::uint64_t cached_metadata_rva_ = 0;
    std::uint32_t cached_metadata_size_ = 0;
    std::size_t cached_method_count_ = 0;
    std::size_t cached_typedef_count_ = 0;

    std::vector<MemberRow> all_member_rows_{};
    std::vector<std::size_t> filtered_member_indices_{};
    char types_filter_buf_[128] = {};
    bool methods_with_il_only_ = false;
    bool types_filter_dirty_ = true;

    std::optional<std::size_t> selected_method_index_{};
    std::optional<peelf::CilMethodBody> cached_cil_body_{};
    std::string cached_cil_error_{};
    std::optional<std::uint32_t> highlighted_il_offset_{};

    char pinvoke_filter_buf_[128] = {};
    char us_filter_buf_[128] = {};
};

} // namespace viewer
