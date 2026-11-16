#pragma once

#include "../model/binary_model.hpp"
#include "../navigation/viewer_navigation.hpp"
#include "ui_panel.hpp"

#include <peelf/debugger.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace viewer {

class DebuggerPanel : public UiPanel {
public:
    using NavigateCallback = std::function<void(std::uint64_t address, PreferredView view)>;
    using SessionChangedCallback = std::function<void()>;
    using ReadOnlyAttachCallback = std::function<void()>;

    DebuggerPanel(BinaryModel& model,
                  NavigateCallback on_navigate = {},
                  SessionChangedCallback on_session_changed = {},
                  ReadOnlyAttachCallback on_open_readonly_attach = {});

    void open_opt_in_modal();
    void render_opt_in_modal();

protected:
    void draw_contents() override;

private:
    void refresh_modal_process_list();
    void draw_transport_bar();
    void draw_breakpoints_tab();
    void draw_registers_tab();
    void draw_stack_tab();
    void draw_events_tab();

    [[nodiscard]] std::optional<std::uint64_t> parse_address_or_symbol(std::string_view expr) const;

    BinaryModel& model_;
    NavigateCallback on_navigate_;
    SessionChangedCallback on_session_changed_;
    ReadOnlyAttachCallback on_open_readonly_attach_;

    // Opt-in modal state
    bool open_modal_next_frame_{false};
    std::array<char, 1024> launch_exe_buf_{};
    std::array<char, 1024> launch_args_buf_{};
    std::array<char, 1024> launch_cwd_buf_{};
    std::array<char, 128> attach_filter_buf_{};
    std::array<char, 32> manual_pid_buf_{};
    bool attach_accessible_only_{false};
    std::vector<peelf::ProcessInfo> cached_processes_{};
    std::optional<peelf::ProcessId> selected_pid_{};
    std::string modal_error_{};

    // Breakpoint editor state
    std::array<char, 256> bp_expr_buf_{};
    std::array<char, 128> bp_label_buf_{};
    int bp_kind_idx_{0};       // 0=Software, 1=HW Exec, 2=HW Write, 3=HW ReadWrite
    int bp_hw_size_idx_{2};    // 0=1B, 1=2B, 2=4B, 3=8B
    std::string status_msg_{};

    // Opt-in register editor state
    std::array<char, 32> edit_reg_name_buf_{};
    std::array<char, 32> edit_reg_val_buf_{};
    bool pass_signal_on_continue_{false};
};

} // namespace viewer
