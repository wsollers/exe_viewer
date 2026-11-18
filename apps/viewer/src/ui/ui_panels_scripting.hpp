#pragma once

#include <peelf/scripting.hpp>

#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "panel_helpers.hpp"
#include "ui_panel.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace viewer {

class ScriptingPanel final : public UiPanel {
public:
    static constexpr std::size_t kStarterTemplateCount = kScriptStarterTemplateCount;

    ScriptingPanel(BinaryModel& model,
                   AnnotationStore& annotations,
                   NavigationRequestQueue& navigation_queue);

    [[nodiscard]] static std::span<const ScriptStarterTemplate> starter_templates() noexcept;

    void load_starter_template(std::size_t index);
    void set_script_text(std::string text);
    [[nodiscard]] std::string_view script_text() const noexcept { return script_buffer_; }
    [[nodiscard]] peelf::ScriptLimits configured_limits() const noexcept;
    [[nodiscard]] bool allow_mutations_requested() const noexcept { return allow_mutations_; }

protected:
    void draw_contents() override;

private:
    void start_execution();
    void draw_toolbar_and_limits(const ScriptMutationEligibility& eligibility);
    void draw_editor(bool is_running);
    void draw_output_and_mutations();

    BinaryModel& model_;
    AnnotationStore& annotations_;
    NavigationRequestQueue& navigation_queue_;

    std::size_t selected_template_index_{0u};
    bool editor_modified_{false};
    std::string script_buffer_{};

    std::uint64_t max_instructions_{peelf::ScriptLimits{}.max_instructions};
    std::uint64_t max_memory_bytes_{peelf::ScriptLimits{}.max_memory_bytes};
    std::uint64_t timeout_ms_{
        static_cast<std::uint64_t>(peelf::ScriptLimits{}.wall_clock_timeout.count())};
    bool allow_mutations_{false};

    std::string launch_error_{};
};

} // namespace viewer
