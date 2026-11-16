#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "logger.hpp"

#include <peelf/process.hpp>

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {
using detail::clamp_to_size_t;

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
        return;
    }
    cached_process_list_ = std::move(*listed);
}

void UiApp::render_attach_process_modal() {
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
    ImGui::Checkbox("Accessible only", &process_accessible_only_);

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
        binary_diff_panel_.invalidate();
        sync_live_process_view(true);
        struct_view_panel_.reset_for_new_binary();
        Log().info("Attached to PID {} ({}): {} regions, {} modules, {} symbols",
                   model_.process_session()->pid(),
                   model_.process_session()->info().name,
                   model_.memory_regions().size(),
                   model_.process_modules().size(),
                   model_.symbol_index().size());
    }

} // namespace viewer
