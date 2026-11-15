#pragma once

#include "../disasm/disassembler.hpp"
#include "../model/binary_model.hpp"
#include "../navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <peelf/binary_diff.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace viewer {

class BinaryDiffPanel : public UiPanel {
public:
    using NavigateCallback = std::function<void(std::uint64_t address, PreferredView view)>;
    using BrowseFileCallback = std::function<void()>;

    BinaryDiffPanel(BinaryModel& model,
                    ViewerSelection& selection,
                    NavigateCallback on_navigate = {},
                    BrowseFileCallback on_browse_file = {});

    [[nodiscard]] peelf::Result<void> compare_with_file(const std::filesystem::path& comparison_path);
    [[nodiscard]] peelf::Result<void> compare_active_live_module_vs_disk();
    void invalidate() noexcept;

protected:
    void draw_contents() override;

private:
    enum class ActiveDiffMode : std::uint8_t {
        None = 0,
        TwoBinaries = 1,
        DiskVsLiveRam = 2,
    };

    void focus_pair_cursor(std::optional<std::uint64_t> lhs_va,
                           std::optional<std::uint64_t> rhs_va,
                           std::optional<std::uint64_t> lhs_file_off,
                           std::optional<std::uint64_t> rhs_file_off,
                           std::size_t window_hint = 256u,
                           bool also_jump_main_view = true);
    void refresh_side_by_side_slices();

    void draw_overview_tab();
    void draw_sections_tab();
    void draw_imports_exports_tab();
    void draw_functions_tab();
    void draw_hunks_tab();
    void draw_side_by_side_tab();

    BinaryModel& model_;
    NavigateCallback on_navigate_;
    BrowseFileCallback on_browse_file_;

    ActiveDiffMode mode_{ActiveDiffMode::None};
    std::array<char, 1024> comparison_path_buf_{};
    std::array<char, 160> filter_buf_{};
    bool changes_only_{true};
    bool include_writable_live_data_{false};
    std::string status_message_{};
    bool switch_to_side_by_side_tab_{false};

    // Cached comparison artifacts so side-by-side hex & disassembly work without re-reading disk
    std::vector<std::uint8_t> lhs_bytes_{};
    std::unique_ptr<peelf::IBinaryImage> lhs_owned_image_{};
    std::vector<std::uint8_t> rhs_bytes_{};
    std::unique_ptr<peelf::IBinaryImage> rhs_owned_image_{};

    std::optional<peelf::BinaryDiffReport> static_report_{};
    std::optional<peelf::LiveModuleIntegrityReport> live_report_{};

    // Synchronized Side-by-Side Hex & Disassembly cursor state
    bool lockstep_scroll_{true};
    std::uint64_t sbs_lhs_va_{0};
    std::uint64_t sbs_rhs_va_{0};
    std::optional<std::uint64_t> sbs_lhs_file_off_{};
    std::optional<std::uint64_t> sbs_rhs_file_off_{};
    std::size_t sbs_window_bytes_{256};
    std::size_t selected_hunk_index_{0};

    std::vector<std::uint8_t> sbs_lhs_slice_{};
    std::vector<std::uint8_t> sbs_rhs_slice_{};
    Disassembler lhs_disasm_{};
    Disassembler rhs_disasm_{};
    std::vector<Instruction> sbs_lhs_insns_{};
    std::vector<Instruction> sbs_rhs_insns_{};
};

} // namespace viewer
