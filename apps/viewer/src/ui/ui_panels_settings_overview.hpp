#pragma once

#include <peelf/executable_settings.hpp>

#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <cstdint>
#include <functional>

namespace viewer {

class ExecutableSettingsPanel final : public UiPanel {
public:
    using NavigateCallback = std::function<void(std::uint64_t address, PreferredView view)>;

    explicit ExecutableSettingsPanel(BinaryModel& model, NavigateCallback on_navigate = {});

    void set_navigate_callback(NavigateCallback cb) { on_navigate_ = std::move(cb); }

protected:
    void draw_contents() override;

private:
    void draw_declared_section(const peelf::ExecutableSettingsReport& report);
    void draw_pe_manifest_block(const peelf::DeclaredSettings& decl);
    void draw_pe_version_block(const peelf::DeclaredSettings& decl);
    void draw_pe_clr_block(const peelf::DeclaredSettings& decl);
    void draw_elf_settings_block(const peelf::DeclaredSettings& decl);
    void draw_launch_environment_section(const peelf::ExecutableSettingsReport& report);
    void draw_observed_runtime_section(const peelf::ExecutableSettingsReport& report);

    BinaryModel& model_;
    NavigateCallback on_navigate_{};
    char filter_buf_[128]{};
    bool show_raw_manifest_xml_{false};
};

} // namespace viewer
