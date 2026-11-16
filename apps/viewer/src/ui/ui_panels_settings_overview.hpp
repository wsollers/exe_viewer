#pragma once

#include <peelf/executable_settings.hpp>

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace viewer {

class ExecutableSettingsPanel final : public UiPanel {
public:
    using NavigateCallback = std::function<void(std::uint64_t address, PreferredView view)>;

    explicit ExecutableSettingsPanel(BinaryModel& model, NavigateCallback on_navigate = {});

    void set_navigate_callback(NavigateCallback cb) { on_navigate_ = std::move(cb); }

protected:
    void draw_contents() override;

private:
    using DeferredNav = std::optional<std::pair<std::uint64_t, PreferredView>>;

    void draw_snapshot_controls_bar(DeferredNav& pending_nav);
    void draw_snapshot_diff_section(const peelf::SnapshotDiff& diff, DeferredNav& pending_nav);
    void draw_declared_section(const peelf::ExecutableSettingsReport& report);
    void draw_pe_manifest_block(const peelf::DeclaredSettings& decl);
    void draw_pe_version_block(const peelf::DeclaredSettings& decl);
    void draw_pe_clr_block(const peelf::DeclaredSettings& decl);
    void draw_elf_settings_block(const peelf::DeclaredSettings& decl);
    void draw_launch_environment_section(
        const peelf::ExecutableSettingsReport& report,
        std::optional<peelf::EnvironmentRedactionPolicy>& pending_policy);
    void draw_observed_runtime_section(
        const peelf::ExecutableSettingsReport& report,
        DeferredNav& pending_nav);

    BinaryModel& model_;
    NavigateCallback on_navigate_{};
    char filter_buf_[128]{};
    bool show_raw_manifest_xml_{false};
    bool pause_during_snapshot_{false};
    std::size_t diff_before_index_{0u};
    std::size_t diff_after_index_{0u};
    std::string snapshot_status_msg_{};
};

} // namespace viewer
