#include "ui_panels_debugger.hpp"

#include "logger.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

[[nodiscard]] std::string_view trim_ws(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] bool icontains_ascii(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

[[nodiscard]] std::vector<std::string> split_shell_args(std::string_view raw) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quotes = false;
    char quote_ch = '\0';
    for (std::size_t i = 0; i < raw.size(); ++i) {
        const char c = raw[i];
        if (in_quotes) {
            if (c == '\\' && i + 1 < raw.size() && raw[i + 1] == quote_ch) {
                cur.push_back(raw[++i]);
            } else if (c == quote_ch) {
                in_quotes = false;
            } else {
                cur.push_back(c);
            }
        } else {
            if (c == '"' || c == '\'') {
                in_quotes = true;
                quote_ch = c;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                if (!cur.empty()) {
                    out.push_back(std::move(cur));
                    cur.clear();
                }
            } else {
                cur.push_back(c);
            }
        }
    }
    if (!cur.empty()) {
        out.push_back(std::move(cur));
    }
    return out;
}

[[nodiscard]] ImVec4 state_badge_color(peelf::debugger::DebugSessionState state) noexcept {
    using peelf::debugger::DebugSessionState;
    switch (state) {
        case DebugSessionState::Paused:   return ImVec4(1.00f, 0.78f, 0.25f, 1.0f);
        case DebugSessionState::Running:  return ImVec4(0.35f, 0.92f, 0.55f, 1.0f);
        case DebugSessionState::Detached: return ImVec4(0.65f, 0.72f, 0.80f, 1.0f);
        case DebugSessionState::Exited:   return ImVec4(0.70f, 0.60f, 0.85f, 1.0f);
        case DebugSessionState::Error:    return ImVec4(0.95f, 0.40f, 0.40f, 1.0f);
        case DebugSessionState::Idle:     return ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
    }
    return ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
}

} // namespace

DebuggerPanel::DebuggerPanel(BinaryModel& model,
                             NavigateCallback on_navigate,
                             SessionChangedCallback on_session_changed,
                             ReadOnlyAttachCallback on_open_readonly_attach)
    : UiPanel("Debugger")
    , model_(model)
    , on_navigate_(std::move(on_navigate))
    , on_session_changed_(std::move(on_session_changed))
    , on_open_readonly_attach_(std::move(on_open_readonly_attach)) {}

void DebuggerPanel::open_opt_in_modal() {
    modal_error_.clear();
    if (!model_.is_live_process() && !model_.file_info().path.empty() && launch_exe_buf_[0] == '\0') {
        std::snprintf(launch_exe_buf_.data(), launch_exe_buf_.size(), "%s", model_.file_info().path.c_str());
        const auto parent = std::filesystem::path(model_.file_info().path).parent_path();
        if (!parent.empty()) {
            std::snprintf(launch_cwd_buf_.data(), launch_cwd_buf_.size(), "%s", parent.string().c_str());
        }
    }
    refresh_modal_process_list();
    open_modal_next_frame_ = true;
}

void DebuggerPanel::refresh_modal_process_list() {
    if (auto listed = model_.list_processes(); listed.has_value()) {
        cached_processes_ = std::move(*listed);
    }
}

std::optional<std::uint64_t> DebuggerPanel::parse_address_or_symbol(std::string_view raw) const {
    const std::string_view expr = trim_ws(raw);
    if (expr.empty()) {
        return std::nullopt;
    }

    std::string_view hex_part = expr;
    if (hex_part.starts_with("0x") || hex_part.starts_with("0X")) {
        hex_part.remove_prefix(2);
    }
    if (!hex_part.empty()) {
        std::uint64_t val = 0;
        const auto [ptr, ec] = std::from_chars(hex_part.data(), hex_part.data() + hex_part.size(), val, 16);
        if (ec == std::errc{} && ptr == hex_part.data() + hex_part.size()) {
            return val;
        }
    }

    const bool demangle = model_.demangle_symbols();
    for (const SymbolRecord& sym : model_.symbol_index().records()) {
        if (!sym.virtual_address.has_value()) continue;
        if (sym.name == expr || sym.display_name(demangle) == expr) {
            return *sym.virtual_address;
        }
    }
    for (const SymbolRecord& sym : model_.symbol_index().records()) {
        if (!sym.virtual_address.has_value()) continue;
        if (icontains_ascii(sym.name, expr) || icontains_ascii(sym.display_name(demangle), expr)) {
            return *sym.virtual_address;
        }
    }
    return std::nullopt;
}

void DebuggerPanel::render_opt_in_modal() {
    if (open_modal_next_frame_) {
        ImGui::OpenPopup("Start / Attach Debugger (Opt-In)");
        open_modal_next_frame_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(820.0f, 560.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Start / Attach Debugger (Opt-In)", nullptr)) {
        return;
    }

    bool deferred_session_changed = false;

    // Mode comparison banner explicitly distinguishing Read-Only Attach vs Opt-In Active Debugger
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.17f, 0.22f, 1.0f));
    if (ImGui::BeginChild("##ModeDistinctionBanner", ImVec2(0.0f, 108.0f), ImGuiChildFlags_Borders)) {
        ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.55f, 1.0f),
                           "Read-Only Live Attach (Default — Never Modifies Target)");
        ImGui::TextWrapped(
            "File > Attach to Process (Ctrl+P) opens IProcessSession in strictly non-invasive read-only mode: "
            "zero breakpoint traps, zero register writes, and zero execution interference.");
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.00f, 0.78f, 0.25f, 1.0f),
                           "Active Debugger Session (Opt-In — Uses Breakpoints & Execution Control)");
        ImGui::TextWrapped(
            "Starts an opt-in IDebugSession (ptrace / Win32 Debug API) with software & hardware breakpoints, "
            "single-stepping, and register editing. Original bytes are shadow-filtered in views and restored cleanly on Detach.");
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    if (!modal_error_.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "Error: %s", modal_error_.c_str());
    }

    if (ImGui::BeginTabBar("##OptInDebuggerModalTabs")) {
        if (ImGui::BeginTabItem("Launch Executable (Opt-In)")) {
            ImGui::Spacing();
            ImGui::InputText("Executable Path", launch_exe_buf_.data(), launch_exe_buf_.size());
            ImGui::InputText("Arguments", launch_args_buf_.data(), launch_args_buf_.size());
            ImGui::InputText("Working Directory", launch_cwd_buf_.data(), launch_cwd_buf_.size());
            ImGui::Spacing();

            const bool has_exe = trim_ws(launch_exe_buf_.data()).size() > 0u;
            ImGui::BeginDisabled(!has_exe);
            if (ImGui::Button("Launch Active Debugger (Opt-In)", ImVec2(250.0f, 0.0f))) {
                const std::filesystem::path exe_p(std::string(trim_ws(launch_exe_buf_.data())));
                const std::vector<std::string> args = split_shell_args(launch_args_buf_.data());
                const std::string_view cwd_sv = trim_ws(launch_cwd_buf_.data());
                const std::filesystem::path cwd_p = cwd_sv.empty()
                    ? std::filesystem::path{}
                    : std::filesystem::path(std::string(cwd_sv));
                if (auto res = model_.launch_debug_process(exe_p, args, cwd_p); res.has_value()) {
                    set_visible(true);
                    status_msg_ = std::format("Launched PID {} under opt-in debugger (paused at entry/loader).",
                                              model_.process_session() ? model_.process_session()->pid() : 0u);
                    if (on_session_changed_) on_session_changed_();
                    ImGui::CloseCurrentPopup();
                } else {
                    modal_error_ = res.error().message;
                }
            }
            ImGui::EndDisabled();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Attach to Running PID (Opt-In)")) {
            if (ImGui::Button("Refresh")) {
                refresh_modal_process_list();
            }
            ImGui::SameLine();
            ImGui::SetNextItemWidth(220.0f);
            ImGui::InputTextWithHint("##DbgProcFilter", "Filter PID / name / cmd...",
                                     attach_filter_buf_.data(), attach_filter_buf_.size());
            ImGui::SameLine();
            ImGui::Checkbox("Accessible only", &attach_accessible_only_);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(100.0f);
            ImGui::InputTextWithHint("##DbgManualPid", "PID",
                                     manual_pid_buf_.data(), manual_pid_buf_.size(),
                                     ImGuiInputTextFlags_CharsDecimal);
            ImGui::SameLine();
            if (ImGui::Button("Debug PID")) {
                const std::string_view sv = trim_ws(manual_pid_buf_.data());
                peelf::ProcessId pid = 0;
                const auto [p, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), pid, 10);
                if (ec == std::errc{} && p == sv.data() + sv.size() && pid > 0) {
                    if (auto res = model_.attach_debug_process(pid); res.has_value()) {
                        set_visible(true);
                        status_msg_ = std::format("Attached opt-in debugger to PID {}.", pid);
                        if (on_session_changed_) on_session_changed_();
                        ImGui::CloseCurrentPopup();
                    } else {
                        modal_error_ = res.error().message;
                    }
                } else {
                    modal_error_ = "Enter a valid numeric PID.";
                }
            }

            const std::string_view filter = trim_ws(attach_filter_buf_.data());
            std::optional<peelf::ProcessId> pending_attach_pid;
            if (ImGui::BeginTable("##DbgProcTable", 5,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                                  ImVec2(0.0f, -42.0f))) {
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("User", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                ImGui::TableSetupColumn("Path / Command", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                for (const peelf::ProcessInfo& proc : cached_processes_) {
                    const bool accessible = proc.access == peelf::ProcessAccessStatus::Accessible ||
                                            proc.access == peelf::ProcessAccessStatus::ReadOnly;
                    if (attach_accessible_only_ && !accessible) continue;
                    const std::string pid_s = std::to_string(proc.pid);
                    const std::string exe_s = proc.executable_path.string();
                    if (!filter.empty() &&
                        !icontains_ascii(pid_s, filter) &&
                        !icontains_ascii(proc.name, filter) &&
                        !icontains_ascii(exe_s, filter) &&
                        !icontains_ascii(proc.command_line, filter)) {
                        continue;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    const bool is_sel = selected_pid_.has_value() && *selected_pid_ == proc.pid;
                    ImGui::PushID(static_cast<int>(proc.pid & 0x7FFFFFFFu));
                    if (ImGui::Selectable(pid_s.c_str(), is_sel,
                                          ImGuiSelectableFlags_SpanAllColumns |
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                        selected_pid_ = proc.pid;
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                            pending_attach_pid = proc.pid;
                        }
                    }
                    ImGui::PopID();

                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(proc.name.empty() ? "<unknown>" : proc.name.c_str());
                    ImGui::TableNextColumn();
                    const auto arch_sv = peelf::to_string(proc.architecture);
                    ImGui::TextUnformatted(arch_sv.data(), arch_sv.data() + arch_sv.size());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(proc.user.empty() ? "-" : proc.user.c_str());
                    ImGui::TableNextColumn();
                    const std::string& detail = !exe_s.empty() ? exe_s : proc.command_line;
                    ImGui::TextUnformatted(detail.empty() ? "-" : detail.c_str());
                }
                ImGui::EndTable();
            }

            if (pending_attach_pid.has_value()) {
                if (auto res = model_.attach_debug_process(*pending_attach_pid); res.has_value()) {
                    set_visible(true);
                    status_msg_ = std::format("Attached opt-in debugger to PID {}.", *pending_attach_pid);
                    if (on_session_changed_) on_session_changed_();
                    ImGui::CloseCurrentPopup();
                } else {
                    modal_error_ = res.error().message;
                }
            }

            ImGui::BeginDisabled(!selected_pid_.has_value());
            if (ImGui::Button("Attach Active Debugger (Opt-In)", ImVec2(240.0f, 0.0f)) && selected_pid_) {
                if (auto res = model_.attach_debug_process(*selected_pid_); res.has_value()) {
                    set_visible(true);
                    status_msg_ = std::format("Attached opt-in debugger to PID {}.", *selected_pid_);
                    deferred_session_changed = true;
                    ImGui::CloseCurrentPopup();
                } else {
                    modal_error_ = res.error().message;
                }
            }
            ImGui::EndDisabled();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Connect GDB Remote (Opt-In)")) {
            static constexpr std::array<const char*, 9> kRemoteFallbackArchLabels{
                "Auto (target.xml / RSP negotiation)",
                "x86_64 (Little-Endian)",
                "x86 (32-bit Little-Endian)",
                "ARM64 / AArch64 (Little-Endian)",
                "ARM (32-bit Little-Endian)",
                "RISC-V 64 (Little-Endian)",
                "RISC-V 32 (Little-Endian)",
                "PowerPC64 (Big-Endian)",
                "PowerPC64 ELFv2 (Little-Endian)",
            };
            static constexpr std::array<peelf::Architecture, 9> kRemoteFallbackArchs{
                peelf::Architecture::Unknown,
                peelf::Architecture::X86_64,
                peelf::Architecture::X86,
                peelf::Architecture::ARM64,
                peelf::Architecture::ARM,
                peelf::Architecture::RISCV64,
                peelf::Architecture::RISCV32,
                peelf::Architecture::PowerPC64,
                peelf::Architecture::PowerPC64,
            };
            static constexpr std::array<peelf::Endianness, 9> kRemoteFallbackEndians{
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Little,
                peelf::Endianness::Big,
                peelf::Endianness::Little,
            };

            ImGui::Spacing();
            ImGui::SetNextItemWidth(300.0f);
            ImGui::InputTextWithHint("Endpoint Host",
                                     "127.0.0.1, ::1, localhost, or remote IP...",
                                     remote_host_buf_.data(),
                                     remote_host_buf_.size());
            ImGui::SetNextItemWidth(140.0f);
            if (ImGui::InputInt("TCP Port", &remote_port_, 1, 100)) {
                remote_port_ = std::clamp(remote_port_, 1, 65535);
            }
            ImGui::SameLine();
            ImGui::SetNextItemWidth(140.0f);
            if (ImGui::InputInt("Timeout (ms)", &remote_timeout_ms_, 250, 1000)) {
                remote_timeout_ms_ = std::clamp(remote_timeout_ms_, 250, 60000);
            }
            ImGui::SetNextItemWidth(300.0f);
            ImGui::Combo("Fallback Architecture",
                         &remote_fallback_arch_idx_,
                         kRemoteFallbackArchLabels.data(),
                         static_cast<int>(kRemoteFallbackArchLabels.size()));

            const std::string_view host_sv = trim_ws(remote_host_buf_.data());
            const bool host_valid = !host_sv.empty();
            const bool is_loopback = host_valid && peelf::is_loopback_endpoint_host(host_sv);

            ImGui::Spacing();
            ImGui::Checkbox("Allow unencrypted plaintext RSP TCP connection to non-loopback endpoint",
                            &remote_allow_unencrypted_);
            if (host_valid && !is_loopback) {
                ImGui::TextColored(
                    remote_allow_unencrypted_
                        ? ImVec4(0.95f, 0.78f, 0.30f, 1.0f)
                        : ImVec4(0.95f, 0.45f, 0.45f, 1.0f),
                    "Security notice: '%.*s' is non-loopback; plaintext RSP requires explicit confirmation.",
                    static_cast<int>(host_sv.size()),
                    host_sv.data());
            }
            ImGui::Checkbox(
                "I consent to active target mutation (breakpoints, execution step/continue, register & memory writes)",
                &remote_consent_acknowledged_);

            ImGui::Spacing();
            const bool can_connect_remote =
                host_valid && remote_port_ >= 1 && remote_port_ <= 65535 &&
                (is_loopback || remote_allow_unencrypted_) && remote_consent_acknowledged_;
            ImGui::BeginDisabled(!can_connect_remote);
            if (ImGui::Button("Connect GDB Remote Debugger (Opt-In)", ImVec2(290.0f, 0.0f))) {
                const auto idx = static_cast<std::size_t>(std::clamp(
                    remote_fallback_arch_idx_,
                    0,
                    static_cast<int>(kRemoteFallbackArchLabels.size()) - 1));
                peelf::GdbRemoteOpenOptions opts{};
                opts.endpoint.host = std::string(host_sv);
                opts.endpoint.port = static_cast<std::uint16_t>(std::clamp(remote_port_, 1, 65535));
                const auto timeout_ms = std::chrono::milliseconds{
                    std::clamp(remote_timeout_ms_, 250, 60000)};
                opts.endpoint.connect_timeout = timeout_ms;
                opts.endpoint.io_timeout = timeout_ms;
                opts.endpoint.allow_unencrypted_remote_endpoint = remote_allow_unencrypted_;
                opts.fallback_architecture = kRemoteFallbackArchs[idx];
                opts.fallback_endianness = kRemoteFallbackEndians[idx];
                const peelf::ExplicitDebugConsent consent{
                    .acknowledged_target_mutation = remote_consent_acknowledged_,
                };
                if (auto res = model_.connect_gdb_remote_debug(opts, consent); res.has_value()) {
                    set_visible(true);
                    status_msg_ = std::format("Connected opt-in GDB Remote debugger to {}:{}.",
                                              opts.endpoint.host,
                                              opts.endpoint.port);
                    deferred_session_changed = true;
                    ImGui::CloseCurrentPopup();
                } else {
                    modal_error_ = res.error().message;
                }
            }
            ImGui::EndDisabled();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::Separator();
    if (on_open_readonly_attach_ && ImGui::Button("Use Read-Only Live Attach Instead (Default)")) {
        ImGui::CloseCurrentPopup();
        on_open_readonly_attach_();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(100.0f, 0.0f))) {
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();

    if (deferred_session_changed && on_session_changed_) {
        on_session_changed_();
    }
}

void DebuggerPanel::draw_transport_bar() {
    peelf::debugger::IDebugSession* dbg = model_.debug_session();
    if (ImGui::Button("Start / Attach...")) {
        open_opt_in_modal();
    }

    if (dbg == nullptr) {
        ImGui::SameLine();
        if (model_.is_live_process() && !model_.is_crash_dump()) {
            ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.55f, 1.0f),
                               "[Read-Only Live Attach — Opt-In Debugger Inactive]");
        } else if (model_.is_crash_dump()) {
            ImGui::TextColored(ImVec4(0.85f, 0.65f, 0.35f, 1.0f),
                               "[Offline Crash Dump — Execution Control Unavailable]");
        } else {
            ImGui::TextDisabled("No active debugger session. Click 'Start / Attach...' to opt in.");
        }
        if (!status_msg_.empty()) {
            ImGui::TextDisabled("%s", status_msg_.c_str());
        }
        return;
    }

    const peelf::debugger::DebugStopStatus stop = dbg->stop_status();
    const bool is_paused = stop.state == peelf::debugger::DebugSessionState::Paused;
    const bool is_running = stop.state == peelf::debugger::DebugSessionState::Running;
    const bool is_active = is_paused || is_running;

    ImGui::SameLine();
    ImGui::BeginDisabled(!is_paused);
    if (ImGui::Button("Continue (F5)")) {
        if (auto r = dbg->continue_execution(pass_signal_on_continue_); !r.has_value()) {
            status_msg_ = r.error().message;
        } else {
            status_msg_ = "Resumed debuggee execution.";
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!is_running);
    if (ImGui::Button("Pause")) {
        if (auto r = dbg->pause_execution(); !r.has_value()) {
            status_msg_ = r.error().message;
        } else {
            status_msg_ = "Requested pause...";
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!is_paused);
    if (ImGui::Button("Step Into (F11)")) {
        if (auto r = dbg->step_into(model_.selected_thread_id()); !r.has_value()) {
            status_msg_ = r.error().message;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Over (F10)")) {
        if (auto r = dbg->step_over(model_.selected_thread_id()); !r.has_value()) {
            status_msg_ = r.error().message;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Out (Shift+F11)")) {
        if (auto r = dbg->step_out(model_.selected_thread_id()); !r.has_value()) {
            status_msg_ = r.error().message;
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!is_active);
    if (ImGui::Button("Detach Cleanly")) {
        if (auto r = dbg->detach(); !r.has_value()) {
            model_.refresh_debug_breakpoints();
            status_msg_ = r.error().message;
        } else {
            model_.detach_process();
            status_msg_ = "Disarmed all breakpoints and detached cleanly.";
            if (on_session_changed_) on_session_changed_();
            return;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Terminate")) {
        if (auto r = dbg->terminate(); !r.has_value()) {
            status_msg_ = r.error().message;
        } else {
            model_.detach_process();
            status_msg_ = "Terminated debugged target.";
            if (on_session_changed_) on_session_changed_();
            return;
        }
    }
    ImGui::EndDisabled();

    // Status strip
    const auto state_sv = peelf::debugger::to_string(stop.state);
    ImGui::TextColored(state_badge_color(stop.state), "[%.*s]",
                       static_cast<int>(state_sv.size()), state_sv.data());
    ImGui::SameLine();
    ImGui::Text("PID %u  |  TID %" PRIu64 "  |  IP 0x%" PRIX64,
                model_.process_session() ? model_.process_session()->pid() : 0u,
                static_cast<std::uint64_t>(stop.active_tid),
                stop.instruction_pointer);
    if (stop.instruction_pointer != 0u) {
        const std::string sym = model_.resolve_address_symbol(stop.instruction_pointer);
        if (!sym.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", sym.c_str());
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Jump to IP") && on_navigate_) {
            on_navigate_(stop.instruction_pointer, PreferredView::Disassembly);
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Pass signal/exception", &pass_signal_on_continue_);

    if (stop.last_event.has_value() && !stop.last_event->summary.empty()) {
        ImGui::TextDisabled("Last event: %s", stop.last_event->summary.c_str());
    }
    if (!status_msg_.empty()) {
        ImGui::TextWrapped("%s", status_msg_.c_str());
    }
}

void DebuggerPanel::draw_breakpoints_tab() {
    peelf::debugger::IDebugSession* dbg = model_.debug_session();
    if (dbg == nullptr) {
        ImGui::TextDisabled("Attach or launch an opt-in debugger session to manage breakpoints.");
        return;
    }

    const bool paused = dbg->state() == peelf::debugger::DebugSessionState::Paused;
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##BpAddrSym", "0xVA or symbol name...",
                             bp_expr_buf_.data(), bp_expr_buf_.size());
    ImGui::SameLine();
    static constexpr std::array<const char*, 5> kBreakpointKinds{
        "Software (Trap / Z0)",
        "Hardware Execute (DR / Z1)",
        "Hardware Write (DR / Z2)",
        "Hardware Read/Write (DR / Z4)",
        "Hardware Read (Z3)"
    };
    ImGui::SetNextItemWidth(205.0f);
    ImGui::Combo("##BpKind", &bp_kind_idx_, kBreakpointKinds.data(),
                 static_cast<int>(kBreakpointKinds.size()));

    if (bp_kind_idx_ > 0) {
        ImGui::SameLine();
        static constexpr std::array<const char*, 4> kBreakpointSizes{
            "1 Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes"
        };
        ImGui::SetNextItemWidth(95.0f);
        ImGui::Combo("##BpSize", &bp_hw_size_idx_, kBreakpointSizes.data(),
                     static_cast<int>(kBreakpointSizes.size()));
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0f);
    ImGui::InputTextWithHint("##BpLabel", "Optional label...",
                             bp_label_buf_.data(), bp_label_buf_.size());
    ImGui::SameLine();
    ImGui::BeginDisabled(!paused);
    if (ImGui::Button("Add Breakpoint")) {
        const auto resolved = parse_address_or_symbol(bp_expr_buf_.data());
        if (!resolved.has_value()) {
            status_msg_ = "Could not resolve breakpoint address or symbol.";
        } else {
            std::string label(trim_ws(bp_label_buf_.data()));
            if (label.empty()) {
                label = model_.resolve_address_symbol(*resolved);
            }
            if (bp_kind_idx_ == 0) {
                if (auto r = dbg->add_software_breakpoint(*resolved, std::move(label), model_.analysis_thumb_mode());
                    r.has_value()) {
                    model_.refresh_debug_breakpoints();
                    status_msg_ = std::format("Added software breakpoint #{} at 0x{:X}.", r->id, r->address);
                } else {
                    status_msg_ = r.error().message;
                }
            } else {
                const peelf::debugger::BreakpointKind hw_kind =
                    bp_kind_idx_ == 1 ? peelf::debugger::BreakpointKind::HardwareExecute
                  : bp_kind_idx_ == 2 ? peelf::debugger::BreakpointKind::HardwareWrite
                  : bp_kind_idx_ == 4 ? peelf::debugger::BreakpointKind::HardwareRead
                                      : peelf::debugger::BreakpointKind::HardwareReadWrite;
                constexpr std::array<std::uint8_t, 4> kSizes{1u, 2u, 4u, 8u};
                const std::uint8_t sz = kSizes[static_cast<std::size_t>(std::clamp(bp_hw_size_idx_, 0, 3))];
                const auto r = dbg->add_hardware_breakpoint(*resolved, hw_kind, sz, std::move(label));
                model_.refresh_debug_breakpoints();
                status_msg_ = r.status.detail;
            }
        }
    }
    ImGui::EndDisabled();
    if (!paused) {
        ImGui::SameLine();
        ImGui::TextDisabled("(Pause target to modify breakpoints; F9 toggles at selected Disassembly line)");
    }

    model_.refresh_debug_breakpoints();
    const auto bps = model_.debug_breakpoints();
    std::optional<std::pair<peelf::debugger::BreakpointId, bool>> pending_toggle;
    std::optional<peelf::debugger::BreakpointId> pending_delete;
    std::optional<std::pair<std::uint64_t, PreferredView>> pending_nav;
    if (ImGui::BeginTable("##BreakpointsTable", 8,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 36.0f);
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 42.0f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Symbol / Label", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 48.0f);
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (const peelf::debugger::BreakpointDescriptor& bp : bps) {
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(bp.id));

            ImGui::TableNextColumn();
            bool en = bp.enabled;
            ImGui::BeginDisabled(!paused);
            if (ImGui::Checkbox("##En", &en)) {
                pending_toggle = std::pair{bp.id, en};
            }
            ImGui::EndDisabled();

            ImGui::TableNextColumn();
            ImGui::Text("#%" PRIu64, bp.id);

            ImGui::TableNextColumn();
            const auto kind_sv = peelf::debugger::to_string(bp.kind);
            if (bp.hardware_slot.has_value()) {
                ImGui::Text("%.*s (DR%u)",
                            static_cast<int>(kind_sv.size()), kind_sv.data(),
                            static_cast<unsigned>(*bp.hardware_slot));
            } else {
                ImGui::TextUnformatted(kind_sv.data(), kind_sv.data() + kind_sv.size());
            }

            ImGui::TableNextColumn();
            const std::string addr_s = std::format("0x{:016X}", bp.address);
            if (ImGui::Selectable(addr_s.c_str()) && on_navigate_) {
                pending_nav = std::pair{bp.address, PreferredView::Disassembly};
            }

            ImGui::TableNextColumn();
            const std::string label = !bp.label.empty() ? bp.label : model_.resolve_address_symbol(bp.address);
            ImGui::TextUnformatted(label.empty() ? "-" : label.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%uB", static_cast<unsigned>(bp.byte_size));

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, bp.hit_count);

            ImGui::TableNextColumn();
            ImGui::BeginDisabled(!paused);
            if (ImGui::SmallButton("Delete")) {
                pending_delete = bp.id;
            }
            ImGui::EndDisabled();

            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    if (pending_toggle.has_value()) {
        if (auto r = dbg->set_breakpoint_enabled(pending_toggle->first, pending_toggle->second);
            !r.has_value()) {
            status_msg_ = r.error().message;
        }
        model_.refresh_debug_breakpoints();
    }
    if (pending_delete.has_value()) {
        if (auto r = dbg->remove_breakpoint(*pending_delete); !r.has_value()) {
            status_msg_ = r.error().message;
        }
        model_.refresh_debug_breakpoints();
    }
    if (pending_nav.has_value() && on_navigate_) {
        on_navigate_(pending_nav->first, pending_nav->second);
    }
}

void DebuggerPanel::draw_registers_tab() {
    peelf::debugger::IDebugSession* dbg = model_.debug_session();
    if (!model_.is_live_process()) {
        ImGui::TextDisabled("No live process or debugger session active.");
        return;
    }

    const auto& ctx_fv = model_.selected_thread_context();
    if (!ctx_fv.has_value()) {
        ImGui::TextDisabled("Register context unavailable: %s", ctx_fv.status.detail.c_str());
        return;
    }

    if (dbg != nullptr) {
        const bool paused = dbg->state() == peelf::debugger::DebugSessionState::Paused;
        ImGui::BeginDisabled(!paused);
        ImGui::SetNextItemWidth(95.0f);
        ImGui::InputTextWithHint("##RegName", "Reg (e.g. rax)",
                                 edit_reg_name_buf_.data(), edit_reg_name_buf_.size());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(165.0f);
        ImGui::InputTextWithHint("##RegVal", "Hex value (0x...)",
                                 edit_reg_val_buf_.data(), edit_reg_val_buf_.size());
        ImGui::SameLine();
        if (ImGui::Button("Write Register")) {
            std::string_view val_sv = trim_ws(edit_reg_val_buf_.data());
            if (val_sv.starts_with("0x") || val_sv.starts_with("0X")) {
                val_sv.remove_prefix(2);
            }
            std::uint64_t new_val = 0;
            const auto [ptr, ec] = std::from_chars(val_sv.data(), val_sv.data() + val_sv.size(), new_val, 16);
            if (ec != std::errc{} || ptr != val_sv.data() + val_sv.size() || val_sv.empty()) {
                status_msg_ = "Invalid hex register value.";
            } else {
                const peelf::ThreadId tid = model_.selected_thread_id().value_or(dbg->stop_status().active_tid);
                if (auto r = dbg->write_register(tid, trim_ws(edit_reg_name_buf_.data()), new_val); r.has_value()) {
                    (void)model_.sync_debugger_stop_state();
                    model_.refresh_selected_thread_inspection();
                    status_msg_ = std::format("Updated {} = 0x{:X}.", trim_ws(edit_reg_name_buf_.data()), new_val);
                    if (on_session_changed_) on_session_changed_();
                } else {
                    status_msg_ = r.error().message;
                }
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("Click any register row to pre-fill editor; changed registers highlighted in gold.");
    }

    std::optional<std::pair<std::uint64_t, PreferredView>> pending_nav;
    if (ImGui::BeginTable("##DbgRegistersTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Previous Stop", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Role", ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("Symbol / Pointer Target", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < ctx_fv.value->registers.size(); ++i) {
            const peelf::RegisterValue& rv = ctx_fv.value->registers[i];
            const bool changed = model_.has_debug_register_changed(rv.name, rv.value_u64);
            const auto prev_opt = model_.previous_debug_register_value(rv.name);

            ImGui::TableNextRow();
            if (changed) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                       ImGui::GetColorU32(ImVec4(0.42f, 0.28f, 0.06f, 0.45f)));
            }

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            const ImVec4 name_col = changed
                ? ImVec4(1.00f, 0.82f, 0.25f, 1.0f)
                : ImVec4(0.86f, 0.90f, 0.95f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, name_col);
            if (ImGui::Selectable(rv.name.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                const std::size_t name_len = std::min(edit_reg_name_buf_.size() - 1, rv.name.size());
                std::copy_n(rv.name.data(), name_len, edit_reg_name_buf_.data());
                edit_reg_name_buf_[name_len] = '\0';
                const std::string reg_hex = std::format("0x{:X}", rv.value_u64);
                const std::size_t val_len = std::min(edit_reg_val_buf_.size() - 1, reg_hex.size());
                std::copy_n(reg_hex.data(), val_len, edit_reg_val_buf_.data());
                edit_reg_val_buf_[val_len] = '\0';
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && on_navigate_ && rv.value_u64 != 0u) {
                    pending_nav = std::pair{rv.value_u64, PreferredView::Disassembly};
                }
            }
            ImGui::PopStyleColor();
            ImGui::PopID();

            ImGui::TableNextColumn();
            const std::string val_s = rv.bit_width <= 32
                ? std::format("0x{:08X}", static_cast<std::uint32_t>(rv.value_u64))
                : std::format("0x{:016X}", rv.value_u64);
            if (changed) {
                ImGui::TextColored(ImVec4(1.00f, 0.84f, 0.28f, 1.0f), "%s", val_s.c_str());
            } else {
                ImGui::TextUnformatted(val_s.c_str());
            }

            ImGui::TableNextColumn();
            if (changed && prev_opt.has_value()) {
                ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.30f, 1.0f), "0x%" PRIX64, *prev_opt);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            switch (rv.category) {
                case peelf::RegisterCategory::InstructionPointer:
                    ImGui::TextColored(ImVec4(0.30f, 0.90f, 0.95f, 1.0f), "IP / PC");
                    break;
                case peelf::RegisterCategory::StackPointer:
                    ImGui::TextColored(ImVec4(0.55f, 0.85f, 0.55f, 1.0f), "SP");
                    break;
                case peelf::RegisterCategory::FramePointer:
                    ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.95f, 1.0f), "FP");
                    break;
                default: {
                    const std::string_view cat_sv = peelf::to_string(rv.category);
                    ImGui::TextDisabled("%.*s", static_cast<int>(cat_sv.size()), cat_sv.data());
                    break;
                }
            }

            ImGui::TableNextColumn();
            const std::string sym = model_.resolve_address_symbol(rv.value_u64);
            if (!sym.empty()) {
                ImGui::TextUnformatted(sym.c_str());
            } else {
                ImGui::TextDisabled("-");
            }
        }
        ImGui::EndTable();
    }
    if (pending_nav.has_value() && on_navigate_) {
        on_navigate_(pending_nav->first, pending_nav->second);
    }
}

void DebuggerPanel::draw_stack_tab() {
    if (!model_.is_live_process()) {
        ImGui::TextDisabled("No live process or debugger session active.");
        return;
    }

    const peelf::ThreadStackSnapshot& stack_snap = model_.selected_thread_stack();
    if (!stack_snap.status.detail.empty()) {
        ImGui::TextDisabled("Stack status: %s", stack_snap.status.detail.c_str());
    }
    if (stack_snap.slots.empty()) {
        ImGui::TextDisabled("No readable stack slots available at current SP.");
        return;
    }

    std::optional<std::pair<std::uint64_t, PreferredView>> pending_nav;
    if (ImGui::BeginTable("##DbgStackSlotsTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Stack Address", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 175.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 155.0f);
        ImGui::TableSetupColumn("Role", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Symbol / Annotation", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        const int row_count = stack_snap.slots.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
            ? std::numeric_limits<int>::max()
            : static_cast<int>(stack_snap.slots.size());
        clipper.Begin(row_count);
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const peelf::StackSlotEntry& slot = stack_snap.slots[static_cast<std::size_t>(row)];
                const bool fully_valid = slot.all_bytes_valid();
                const bool is_ret = fully_valid && slot.role == peelf::StackSlotRole::ReturnAddress;

                ImGui::TableNextRow();
                ImGui::PushID(row);

                ImGui::TableNextColumn();
                const std::string addr_s = stack_snap.layout.address_width == peelf::AddressWidth::Bits32
                    ? std::format("0x{:08X}", static_cast<std::uint32_t>(slot.slot_address))
                    : std::format("0x{:016X}", slot.slot_address);
                ImGui::TextUnformatted(addr_s.c_str());

                ImGui::TableNextColumn();
                std::string raw_hex;
                raw_hex.reserve(static_cast<std::size_t>(slot.byte_size) * 3u);
                for (std::size_t b = 0; b < slot.byte_size; ++b) {
                    if (b > 0) raw_hex.push_back(' ');
                    if (slot.is_byte_valid(b)) {
                        raw_hex += std::format("{:02X}", slot.raw_bytes[b]);
                    } else {
                        raw_hex += "??";
                    }
                }
                if (fully_valid) {
                    ImGui::TextDisabled("%s", raw_hex.c_str());
                } else {
                    ImGui::TextColored(ImVec4(0.92f, 0.55f, 0.35f, 1.0f), "%s", raw_hex.c_str());
                }

                ImGui::TableNextColumn();
                const std::string val_s = peelf::format_stack_slot_value(slot, stack_snap.layout);
                if (fully_valid) {
                    if (ImGui::Selectable(val_s.c_str()) && on_navigate_ && slot.value != 0u) {
                        pending_nav = std::pair{
                            slot.value,
                            is_ret ? PreferredView::Disassembly : PreferredView::Hex
                        };
                    }
                } else {
                    ImGui::TextColored(ImVec4(0.92f, 0.55f, 0.35f, 1.0f), "%s", val_s.c_str());
                }

                ImGui::TableNextColumn();
                const std::string_view role_sv = peelf::to_string(slot.role);
                ImGui::TextDisabled("%.*s", static_cast<int>(role_sv.size()), role_sv.data());

                ImGui::TableNextColumn();
                std::string note = slot.resolved_symbol;
                if (!slot.annotation.empty()) {
                    if (!note.empty()) note += " | ";
                    note += slot.annotation;
                }
                ImGui::TextUnformatted(note.empty() ? "-" : note.c_str());

                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (pending_nav.has_value() && on_navigate_) {
        on_navigate_(pending_nav->first, pending_nav->second);
    }
}

void DebuggerPanel::draw_events_tab() {
    peelf::debugger::IDebugSession* dbg = model_.debug_session();
    if (dbg == nullptr) {
        ImGui::TextDisabled("No active opt-in debugger session.");
        return;
    }

    if (ImGui::Button("Clear Events")) {
        dbg->clear_events();
    }

    const std::vector<peelf::debugger::DebugEvent> evs = dbg->events();
    std::optional<std::pair<std::uint64_t, PreferredView>> pending_nav;
    if (ImGui::BeginTable("##DbgEventsTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 52.0f);
        ImGui::TableSetupColumn("Event", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Summary", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (auto it = evs.rbegin(); it != evs.rend(); ++it) {
            const peelf::debugger::DebugEvent& ev = *it;
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(ev.sequence & 0x7FFFFFFFu));

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, ev.sequence);

            ImGui::TableNextColumn();
            const auto ksv = peelf::debugger::to_string(ev.kind);
            ImGui::TextUnformatted(ksv.data(), ksv.data() + ksv.size());

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, static_cast<std::uint64_t>(ev.tid));

            ImGui::TableNextColumn();
            if (ev.address.has_value() && *ev.address != 0u) {
                const std::string as = std::format("0x{:016X}", *ev.address);
                if (ImGui::Selectable(as.c_str()) && on_navigate_) {
                    pending_nav = std::pair{*ev.address, PreferredView::Disassembly};
                }
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(ev.summary.c_str());

            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (pending_nav.has_value() && on_navigate_) {
        on_navigate_(pending_nav->first, pending_nav->second);
    }
}

void DebuggerPanel::draw_contents() {
    draw_transport_bar();
    ImGui::Separator();

    if (ImGui::BeginTabBar("##DebuggerWorkspaceTabs")) {
        if (ImGui::BeginTabItem("Breakpoints")) {
            draw_breakpoints_tab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Registers (Step-Diff Highlighted)")) {
            draw_registers_tab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Stack")) {
            draw_stack_tab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Debug Events")) {
            draw_events_tab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

} // namespace viewer
