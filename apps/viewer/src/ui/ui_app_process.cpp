#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "logger.hpp"

#include <peelf/gdb_remote.hpp>
#include <peelf/process.hpp>

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {
using detail::activate_panel;
using detail::clamp_to_size_t;

[[nodiscard]] std::string_view trim_ascii_ws(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return sv;
}

struct FallbackArchOption {
    const char* label;
    peelf::Architecture arch;
    peelf::Endianness endianness;
};

constexpr std::array<FallbackArchOption, 9> kGdbFallbackArchOptions{{
    {"Auto (target.xml / RSP negotiation)", peelf::Architecture::Unknown, peelf::Endianness::Little},
    {"x86_64 (Little-Endian)", peelf::Architecture::X86_64, peelf::Endianness::Little},
    {"x86 (32-bit Little-Endian)", peelf::Architecture::X86, peelf::Endianness::Little},
    {"ARM64 / AArch64 (Little-Endian)", peelf::Architecture::ARM64, peelf::Endianness::Little},
    {"ARM (32-bit Little-Endian)", peelf::Architecture::ARM, peelf::Endianness::Little},
    {"RISC-V 64 (Little-Endian)", peelf::Architecture::RISCV64, peelf::Endianness::Little},
    {"RISC-V 32 (Little-Endian)", peelf::Architecture::RISCV32, peelf::Endianness::Little},
    {"PowerPC64 (Big-Endian)", peelf::Architecture::PowerPC64, peelf::Endianness::Big},
    {"PowerPC64 ELFv2 (Little-Endian)", peelf::Architecture::PowerPC64, peelf::Endianness::Little},
}};

constexpr std::array<const char*, 9> kGdbFallbackArchLabels{{
    kGdbFallbackArchOptions[0].label,
    kGdbFallbackArchOptions[1].label,
    kGdbFallbackArchOptions[2].label,
    kGdbFallbackArchOptions[3].label,
    kGdbFallbackArchOptions[4].label,
    kGdbFallbackArchOptions[5].label,
    kGdbFallbackArchOptions[6].label,
    kGdbFallbackArchOptions[7].label,
    kGdbFallbackArchOptions[8].label,
}};

[[nodiscard]] bool icontains_filter(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    const auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}
} // namespace

void UiApp::open_attach_process_modal() {
    attach_error_message_.clear();
    refresh_process_list();
    open_attach_modal_next_frame_ = true;
}

void UiApp::refresh_process_list() {
    auto listed = model_.list_processes();
    if (!listed) {
        attach_error_message_ = "Failed to enumerate processes: " + listed.error().message;
        cached_process_list_.clear();
        selected_attach_pid_.reset();
        return;
    }
    cached_process_list_ = std::move(*listed);
    if (selected_attach_pid_.has_value()) {
        const peelf::ProcessId wanted = *selected_attach_pid_;
        const bool still_present = std::ranges::any_of(
            cached_process_list_,
            [this, wanted](const peelf::ProcessInfo& proc) {
                if (proc.pid != wanted) {
                    return false;
                }
                if (!process_accessible_only_) {
                    return true;
                }
                return proc.access == peelf::ProcessAccessStatus::Accessible ||
                       proc.access == peelf::ProcessAccessStatus::ReadOnly;
            });
        if (!still_present) {
            selected_attach_pid_.reset();
        }
    }
}

void UiApp::open_gdb_remote_modal(bool debug_opt_in) {
    gdb_remote_error_message_.clear();
    gdb_remote_modal_debug_mode_ = debug_opt_in;
    if (!debug_opt_in) {
        gdb_remote_consent_acknowledged_ = false;
    }
    open_gdb_remote_modal_next_frame_ = true;
}

void UiApp::render_gdb_remote_modal() {
    const char* popup_title = gdb_remote_modal_debug_mode_
                                  ? "Connect GDB Remote Debugger (Opt-In)"
                                  : "Connect GDB Remote / QEMU (Read-Only)";
    if (open_gdb_remote_modal_next_frame_) {
        ImGui::OpenPopup(popup_title);
        open_gdb_remote_modal_next_frame_ = false;
    }

    bool connected_readonly = false;
    bool connected_debug = false;
    std::optional<bool> switch_to_debug_mode{};

    ImGui::SetNextWindowSize(ImVec2(680.0f, 440.0f), ImGuiCond_FirstUseEver);
    bool modal_open = true;
    if (ImGui::BeginPopupModal(popup_title, &modal_open)) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.17f, 0.22f, 1.0f));
        if (ImGui::BeginChild("##GdbRemoteBanner", ImVec2(0.0f, 92.0f), ImGuiChildFlags_Borders)) {
            if (!gdb_remote_modal_debug_mode_) {
                ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.55f, 1.0f),
                                   "Read-Only GDB Remote / QEMU Inspection (Non-Invasive Default)");
                ImGui::TextWrapped(
                    "Connects an IProcessSession over GDB Remote Serial Protocol (gdbserver, QEMU -s/-g, kgdb, OpenOCD) "
                    "using strictly read-only inspection packets (qSupported, qXfer, qfThreadInfo, g, m). "
                    "Never sends breakpoint (Z), memory-write (M/X), register-write (P/G), or resume/kill packets.");
            } else {
                ImGui::TextColored(ImVec4(1.00f, 0.78f, 0.25f, 1.0f),
                                   "Opt-In GDB Remote Active Debugger (Explicit Mutation Consent Required)");
                ImGui::TextWrapped(
                    "Opens an opt-in IDebugSession over GDB RSP supporting vCont/Hc execution control, Ctrl-C (0x03) pause, "
                    "software & hardware breakpoints/watchpoints (Z0..Z4), register/memory writes (P/G/M), and clean detach (z0..z4 + D).");
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::SetNextItemWidth(320.0f);
        ImGui::InputTextWithHint("Endpoint Host",
                                 "127.0.0.1, ::1, localhost, or remote IP...",
                                 gdb_remote_host_buf_.data(),
                                 gdb_remote_host_buf_.size());

        ImGui::SetNextItemWidth(140.0f);
        if (ImGui::InputInt("TCP Port", &gdb_remote_port_, 1, 100)) {
            gdb_remote_port_ = std::clamp(gdb_remote_port_, 1, 65535);
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth(140.0f);
        if (ImGui::InputInt("Timeout (ms)", &gdb_remote_timeout_ms_, 250, 1000)) {
            gdb_remote_timeout_ms_ = std::clamp(gdb_remote_timeout_ms_, 250, 60000);
        }

        ImGui::SetNextItemWidth(320.0f);
        ImGui::Combo("Fallback Architecture",
                     &gdb_remote_fallback_arch_idx_,
                     kGdbFallbackArchLabels.data(),
                     static_cast<int>(kGdbFallbackArchLabels.size()));
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Used only when the remote stub omits qXfer:features:read:target.xml.");
        }

        const std::string_view host_sv = trim_ascii_ws(gdb_remote_host_buf_.data());
        const bool host_valid = !host_sv.empty();
        const bool is_loopback = host_valid && peelf::is_loopback_endpoint_host(host_sv);

        ImGui::Spacing();
        ImGui::Checkbox("Allow unencrypted plaintext RSP TCP connection to non-loopback endpoint",
                        &gdb_remote_allow_unencrypted_);
        if (host_valid && !is_loopback) {
            ImGui::TextColored(
                gdb_remote_allow_unencrypted_
                    ? ImVec4(0.95f, 0.78f, 0.30f, 1.0f)
                    : ImVec4(0.95f, 0.45f, 0.45f, 1.0f),
                "Security notice: '%.*s' is not loopback; GDB RSP transmits memory & registers unencrypted unless SSH-tunneled.",
                static_cast<int>(host_sv.size()),
                host_sv.data());
        }

        if (gdb_remote_modal_debug_mode_) {
            ImGui::Spacing();
            ImGui::Checkbox(
                "I consent to active target mutation (breakpoints, execution step/continue, register & memory writes)",
                &gdb_remote_consent_acknowledged_);
        }

        if (!gdb_remote_error_message_.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f),
                               "Connection failed: %s",
                               gdb_remote_error_message_.c_str());
        }

        ImGui::Spacing();
        ImGui::Separator();

        const bool unencrypted_ok = is_loopback || gdb_remote_allow_unencrypted_;
        const bool consent_ok = !gdb_remote_modal_debug_mode_ || gdb_remote_consent_acknowledged_;
        const bool can_connect = host_valid && gdb_remote_port_ >= 1 && gdb_remote_port_ <= 65535 &&
                                 unencrypted_ok && consent_ok;

        ImGui::BeginDisabled(!can_connect);
        const char* connect_btn_label = gdb_remote_modal_debug_mode_
                                            ? "Connect Debugger (Opt-In)"
                                            : "Connect Read-Only";
        if (ImGui::Button(connect_btn_label, ImVec2(210.0f, 0.0f))) {
            const std::size_t arch_idx = static_cast<std::size_t>(std::clamp(
                gdb_remote_fallback_arch_idx_,
                0,
                static_cast<int>(kGdbFallbackArchOptions.size()) - 1));
            peelf::GdbRemoteOpenOptions opts{};
            opts.endpoint.host = std::string(host_sv);
            opts.endpoint.port = static_cast<std::uint16_t>(std::clamp(gdb_remote_port_, 1, 65535));
            const auto timeout_ms = std::chrono::milliseconds{
                std::clamp(gdb_remote_timeout_ms_, 250, 60000)};
            opts.endpoint.connect_timeout = timeout_ms;
            opts.endpoint.io_timeout = timeout_ms;
            opts.endpoint.allow_unencrypted_remote_endpoint = gdb_remote_allow_unencrypted_;
            opts.fallback_architecture = kGdbFallbackArchOptions[arch_idx].arch;
            opts.fallback_endianness = kGdbFallbackArchOptions[arch_idx].endianness;

            if (!gdb_remote_modal_debug_mode_) {
                if (auto res = model_.connect_gdb_remote_readonly(opts); res.has_value()) {
                    gdb_remote_error_message_.clear();
                    connected_readonly = true;
                    ImGui::CloseCurrentPopup();
                } else {
                    gdb_remote_error_message_ = res.error().message;
                    Log().error("GDB Remote read-only connect failed: {}", gdb_remote_error_message_);
                }
            } else {
                const peelf::ExplicitDebugConsent consent{
                    .acknowledged_target_mutation = gdb_remote_consent_acknowledged_,
                };
                if (auto res = model_.connect_gdb_remote_debug(opts, consent); res.has_value()) {
                    gdb_remote_error_message_.clear();
                    connected_debug = true;
                    ImGui::CloseCurrentPopup();
                } else {
                    gdb_remote_error_message_ = res.error().message;
                    Log().error("GDB Remote debugger connect failed: {}", gdb_remote_error_message_);
                }
            }
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (!gdb_remote_modal_debug_mode_) {
            if (ImGui::Button("Switch to Opt-In Debugger...")) {
                switch_to_debug_mode = true;
                ImGui::CloseCurrentPopup();
            }
        } else {
            if (ImGui::Button("Use Read-Only Mode Instead")) {
                switch_to_debug_mode = false;
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(100.0f, 0.0f))) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }

    // Deferred UI navigation & panel activation strictly outside ImGui popup scope.
    if (switch_to_debug_mode.has_value()) {
        open_gdb_remote_modal(*switch_to_debug_mode);
    }
    if (connected_readonly) {
        on_process_attached();
        Log().info("Connected read-only GDB remote session");
    } else if (connected_debug) {
        debugger_panel_.set_visible(true);
        activate_panel(debugger_panel_.name().c_str());
        on_process_attached();
        Log().info("Connected opt-in GDB remote debug session");
    }
}

void UiApp::render_attach_process_modal() {
    render_gdb_remote_modal();

    if (open_attach_modal_next_frame_) {
        ImGui::OpenPopup("Attach to Process");
        open_attach_modal_next_frame_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(860.0f, 540.0f), ImGuiCond_FirstUseEver);
    bool modal_open = true;
    if (!ImGui::BeginPopupModal("Attach to Process", &modal_open)) {
        return;
    }

    auto try_attach_pid = [this](peelf::ProcessId pid) {
        auto attached = model_.attach_process(pid);
        if (!attached) {
            attach_error_message_ = std::format("Attach to PID {} failed: {}", pid, attached.error().message);
            Log().error("{}", attach_error_message_);
            return;
        }
        attach_error_message_.clear();
        on_process_attached();
        ImGui::CloseCurrentPopup();
    };

    ImGui::SetNextItemWidth(320.0f);
    ImGui::InputTextWithHint("##ProcSearch",
                             "Filter by PID, name, path, or command line...",
                             process_filter_buf_,
                             sizeof(process_filter_buf_));
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        refresh_process_list();
    }
    ImGui::SameLine();
    if (ImGui::Button("Attach Self")) {
        try_attach_pid(peelf::current_process_id());
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("Accessible only", &process_accessible_only_) &&
        process_accessible_only_ && selected_attach_pid_.has_value()) {
        const peelf::ProcessId wanted = *selected_attach_pid_;
        const bool still_accessible = std::ranges::any_of(
            cached_process_list_,
            [wanted](const peelf::ProcessInfo& proc) {
                return proc.pid == wanted &&
                       (proc.access == peelf::ProcessAccessStatus::Accessible ||
                        proc.access == peelf::ProcessAccessStatus::ReadOnly);
            });
        if (!still_accessible) {
            selected_attach_pid_.reset();
        }
    }

    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputTextWithHint("##ManualPid", "PID...", manual_pid_buf_, sizeof(manual_pid_buf_), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("Attach PID")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(manual_pid_buf_, &end, 10);
        if (end != manual_pid_buf_ && parsed > 0 &&
            parsed <= static_cast<unsigned long long>(std::numeric_limits<peelf::ProcessId>::max())) {
            try_attach_pid(static_cast<peelf::ProcessId>(parsed));
        } else {
            attach_error_message_ = "Enter a valid positive numeric PID.";
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu processes enumerated)", cached_process_list_.size());

    if (!attach_error_message_.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", attach_error_message_.c_str());
    }

    ImGui::Separator();

    const std::string_view filter(process_filter_buf_);
    const float footer_height = ImGui::GetFrameHeightWithSpacing() + 8.0f;
    if (ImGui::BeginTable("AttachProcessTable",
                          6,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -footer_height))) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("User", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Executable / Command Line", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const peelf::ProcessInfo& proc : cached_process_list_) {
            const bool is_accessible = proc.access == peelf::ProcessAccessStatus::Accessible ||
                                       proc.access == peelf::ProcessAccessStatus::ReadOnly;
            if (process_accessible_only_ && !is_accessible) {
                continue;
            }
            const std::string exe_path_str = proc.executable_path.string();
            const std::string pid_str = std::format("{}", proc.pid);
            if (!filter.empty() &&
                !icontains_filter(pid_str, filter) &&
                !icontains_filter(proc.name, filter) &&
                !icontains_filter(exe_path_str, filter) &&
                !icontains_filter(proc.command_line, filter)) {
                continue;
            }

            const bool is_sel = selected_attach_pid_ && *selected_attach_pid_ == proc.pid;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(proc.pid & 0x7FFFFFFFu));
            if (ImGui::Selectable(pid_str.c_str(),
                                  is_sel,
                                  ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_attach_pid_ = proc.pid;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    try_attach_pid(proc.pid);
                }
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(proc.name.empty() ? "<unknown>" : proc.name.c_str());

            ImGui::TableNextColumn();
            const std::string_view arch = peelf::to_string(proc.architecture);
            ImGui::TextUnformatted(arch.data(), arch.data() + arch.size());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(proc.user.empty() ? "-" : proc.user.c_str());

            ImGui::TableNextColumn();
            const std::string_view access_label = peelf::to_string(proc.access);
            ImGui::TextColored(is_accessible ? ImVec4(0.40f, 0.90f, 0.55f, 1.0f)
                                             : ImVec4(0.70f, 0.55f, 0.55f, 1.0f),
                               "%.*s",
                               static_cast<int>(access_label.size()),
                               access_label.data());

            ImGui::TableNextColumn();
            const std::string& detail = !exe_path_str.empty() ? exe_path_str : proc.command_line;
            if (!detail.empty()) {
                ImGui::TextUnformatted(detail.c_str());
            } else {
                ImGui::TextDisabled("-");
            }
        }

        ImGui::EndTable();
    }

    ImGui::BeginDisabled(!selected_attach_pid_.has_value());
    if (ImGui::Button("Attach", ImVec2(110.0f, 0.0f)) && selected_attach_pid_) {
        try_attach_pid(*selected_attach_pid_);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f))) {
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

    void UiApp::sync_live_process_view(bool navigate_to_entry) {
        if (!model_.is_live_process() || model_.process_session() == nullptr) {
            return;
        }

        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
        ++symbol_revision_;
        strings_dirty_ = true;
        references_dirty_ = true;
        const peelf::IProcessSession* sess = model_.process_session();
        structure_tree_ = build_live_process_structure_tree(
            sess->info(),
            model_.process_modules(),
            model_.memory_regions(),
            model_.image(),
            model_.active_module_index());

        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        pending_call_graph_request_.reset();
        call_graph_texture_.reset();

        const peelf::Architecture target_arch = model_.architecture() != peelf::Architecture::Unknown
            ? model_.architecture()
            : sess->info().architecture;
        if (const std::optional<viewer::Architecture> arch = to_disassembler_architecture(target_arch)) {
            file_loaded_ = disasm_.init(*arch, to_disassembler_endianness(model_.endianness()));
        } else {
            file_loaded_ = false;
        }

        if (navigate_to_entry) {
            current_instructions_.clear();
            disasm_status_.clear();
            if (structure_tree_) {
                current_selection_ = structure_tree_->selection;
            }
            const peelf::IBinaryImage* img = model_.image();
            std::uint64_t target_va = 0u;
            if (const auto* dump = model_.crash_dump_summary();
                dump != nullptr && dump->exception.has_value() &&
                dump->exception->instruction_pointer.has_value() &&
                *dump->exception->instruction_pointer != 0u) {
                target_va = *dump->exception->instruction_pointer;
            } else if (img != nullptr && img->entry_point() != 0u) {
                target_va = img->entry_point();
            }
            if (target_va != 0u) {
                if (const auto entry_off = model_.virtual_address_to_offset(target_va)) {
                    hex_panel_.navigate_to_range(clamp_to_size_t(*entry_off), 1);
                    disassemble_at_offset(*entry_off, target_va);
                } else {
                    hex_panel_.navigate_to_range(0, 1);
                    disassemble_at_offset(0, model_.view_base_address());
                }
            } else if (model_.view_size() > 0) {
                hex_panel_.navigate_to_range(0, 1);
                disassemble_at_offset(0, model_.view_base_address());
            }
            last_navigation_selection_ = current_selection_;
            call_graph_sample_ = CallGraphSample::LoadedImage;
            call_graph_status_ = model_.is_crash_dump()
                ? "Opened crash dump. Click Loaded Image or Reload to render the call graph."
                : "Attached to live module. Click Loaded Image or Reload to render the call graph.";
        }
    }

    void UiApp::on_process_attached() {
        if (!model_.is_live_process() || model_.process_session() == nullptr) {
            return;
        }
        reset_target_dependent_state();
        sync_live_process_view(true);
        Log().info("Attached to PID {} ({}): {} regions, {} modules, {} symbols",
                   model_.process_session()->pid(),
                   model_.process_session()->info().name,
                   model_.memory_regions().size(),
                   model_.process_modules().size(),
                   model_.symbol_index().size());
    }

} // namespace viewer
