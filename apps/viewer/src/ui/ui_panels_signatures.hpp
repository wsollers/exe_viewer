// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui/ui_context_menu.hpp"
#include "ui_panel.hpp"

#include <peelf/signatures.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct ImFont;

namespace viewer {

class SignaturesPanel final : public UiPanel {
public:
    using NavigateAddressCallback = std::function<void(std::uint64_t address, PreferredView view)>;
    using NavigateOffsetCallback = std::function<void(std::uint64_t file_offset, std::size_t byte_length)>;

    SignaturesPanel(BinaryModel& model,
                    const ReferenceIndex& references,
                    ViewerSelection& selection,
                    NavigateAddressCallback on_navigate_address,
                    NavigateOffsetCallback on_navigate_offset);

    void set_code_font(ImFont* font) noexcept { code_font_ = font; }
    void set_context_action_callback(EntityContextActionCallback cb) {
        on_context_action_ = std::move(cb);
    }

protected:
    void draw_contents() override;

private:
    struct LoadedRulePack {
        std::filesystem::path path{};
        peelf::SignatureRuleSet ruleset{};
    };

    void recompile_inline_rules();
    void run_rule_scan();
    void render_crypto_tab();
    void render_yara_tab();
    void render_pe_rich_tab();

    BinaryModel& model_;
    const ReferenceIndex& references_;
    ViewerSelection& selection_;
    NavigateAddressCallback on_navigate_address_;
    NavigateOffsetCallback on_navigate_offset_;
    EntityContextActionCallback on_context_action_{};
    ImFont* code_font_{nullptr};

    std::uint64_t last_content_generation_{0};
    std::uint64_t last_edit_revision_{0};

    // Crypto & Packer Constants tab state
    std::array<char, 256> crypto_filter_buf_{};
    int crypto_category_filter_{0};
    std::size_t selected_crypto_idx_{static_cast<std::size_t>(-1)};
    std::string crypto_scan_status_{};

    // Rule Scanner (YARA-Lite) tab state
    bool include_builtin_rules_{true};
    bool scan_all_live_regions_{true};
    bool has_scanned_rules_{false};
    std::array<char, 1024> rule_file_path_buf_{};
    std::vector<LoadedRulePack> loaded_rule_files_{};
    std::string rule_file_status_{};
    bool rule_file_status_is_error_{false};

    std::array<char, 16384> inline_rules_buf_{};
    peelf::SignatureRuleParseResult inline_parse_result_{};
    bool inline_rules_compiled_{false};

    std::vector<peelf::SignatureRuleMatch> rule_matches_{};
    std::string rule_scan_status_{};
};

} // namespace viewer
