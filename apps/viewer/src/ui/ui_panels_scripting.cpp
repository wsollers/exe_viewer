#include "ui_panels_scripting.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cfloat>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

constexpr std::uint64_t kMinInstructionQuota = 1'000u;
constexpr std::uint64_t kMaxInstructionQuota = 100'000'000u;
constexpr std::uint64_t kMinMemoryQuotaBytes = 256ull * 1024ull;
constexpr std::uint64_t kMaxMemoryQuotaBytes = 256ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinTimeoutMs = 25u;
constexpr std::uint64_t kMaxTimeoutMs = 300'000u;

int resize_std_string_callback(ImGuiInputTextCallbackData* data) {
    if (data != nullptr && data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* str = static_cast<std::string*>(data->UserData);
        if (str != nullptr) {
            str->resize(static_cast<std::size_t>(data->BufTextLen));
            data->Buf = str->data();
        }
    }
    return 0;
}

[[nodiscard]] std::string format_hex_bytes_short(std::span<const std::uint8_t> bytes,
                                                 std::size_t max_bytes = 8u) {
    std::string out{};
    const std::size_t limit = std::min(bytes.size(), max_bytes);
    for (std::size_t i = 0u; i < limit; ++i) {
        if (i != 0u) {
            out.push_back(' ');
        }
        out += std::format("{:02X}", bytes[i]);
    }
    if (bytes.size() > max_bytes) {
        out += " ...";
    }
    return out;
}

} // namespace

ScriptingPanel::ScriptingPanel(BinaryModel& model,
                               AnnotationStore& annotations,
                               NavigationRequestQueue& navigation_queue)
    : UiPanel("Scripting")
    , model_(model)
    , annotations_(annotations)
    , navigation_queue_(navigation_queue) {
    load_starter_template(0u);
}

std::span<const ScriptStarterTemplate> ScriptingPanel::starter_templates() noexcept {
    return scripting_starter_templates();
}

void ScriptingPanel::load_starter_template(std::size_t index) {
    const auto templates = starter_templates();
    if (index >= templates.size()) {
        return;
    }
    selected_template_index_ = index;
    script_buffer_.assign(templates[index].source);
    editor_modified_ = false;
    launch_error_.clear();
}

void ScriptingPanel::set_script_text(std::string text) {
    script_buffer_ = std::move(text);
    editor_modified_ = true;
}

peelf::ScriptLimits ScriptingPanel::configured_limits() const noexcept {
    peelf::ScriptLimits lim{};
    lim.max_instructions =
        std::clamp(max_instructions_, kMinInstructionQuota, kMaxInstructionQuota);
    lim.max_memory_bytes = static_cast<std::size_t>(
        std::clamp(max_memory_bytes_, kMinMemoryQuotaBytes, kMaxMemoryQuotaBytes));
    lim.wall_clock_timeout = std::chrono::milliseconds(
        std::clamp(timeout_ms_, kMinTimeoutMs, kMaxTimeoutMs));
    return lim;
}

void ScriptingPanel::start_execution() {
    launch_error_.clear();
    const ScriptMutationEligibility elig = model_.script_mutation_eligibility();
    const bool effective_allow = allow_mutations_ && elig.can_mutate_target;

    peelf::ProjectWorkspace seed_ws{};
    for (const auto& [addr, note] : annotations_.records()) {
        if (!note.name.empty()) {
            seed_ws.set_label(addr, note.name);
        }
        if (!note.comment.empty()) {
            seed_ws.set_comment(addr, note.comment);
        }
    }
    for (const Bookmark& bm : model_.bookmarks()) {
        if (!bm.is_file_offset) {
            seed_ws.add_bookmark(bm.address, bm.label);
        }
    }

    if (auto res = model_.start_script_execution(
            script_buffer_,
            configured_limits(),
            effective_allow,
            std::move(seed_ws),
            "=scripting_panel");
        !res.has_value()) {
        launch_error_ = res.error().message;
    }
}

void ScriptingPanel::draw_toolbar_and_limits(const ScriptMutationEligibility& eligibility) {
    const bool is_running = model_.is_script_running();

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Template");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 19.0f);
    const auto templates = starter_templates();
    const char* preview_title = templates[selected_template_index_].title.data();
    if (ImGui::BeginCombo("##ScriptStarterTemplate", preview_title)) {
        for (std::size_t i = 0u; i < templates.size(); ++i) {
            const bool is_selected = (i == selected_template_index_);
            if (ImGui::Selectable(templates[i].title.data(), is_selected)) {
                selected_template_index_ = i;
                if (!editor_modified_) {
                    load_starter_template(i);
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("%.*s",
                                  static_cast<int>(templates[i].summary.size()),
                                  templates[i].summary.data());
            }
            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(is_running);
    if (ImGui::Button("Load Template")) {
        load_starter_template(selected_template_index_);
    }
    ImGui::EndDisabled();

    ImGui::SameLine(0.0f, 16.0f);
    ImGui::BeginDisabled(!model_.has_file() || is_running);
    if (ImGui::Button("Run Script")) {
        start_execution();
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!is_running);
    if (ImGui::Button("Cancel")) {
        model_.cancel_script_execution();
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(is_running || !model_.last_script_outcome().has_value());
    if (ImGui::Button("Clear Output")) {
        model_.clear_last_script_outcome();
        launch_error_.clear();
    }
    ImGui::EndDisabled();

    if (is_running) {
        ImGui::SameLine(0.0f, 12.0f);
        ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.25f, 1.0f),
                           "Running Lua 5.4 script on background worker...");
    }

    // Quota controls row
    ImGui::BeginDisabled(is_running);
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Quotas:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 8.0f);
    if (ImGui::InputScalar("Max Insns", ImGuiDataType_U64, &max_instructions_)) {
        max_instructions_ =
            std::clamp(max_instructions_, kMinInstructionQuota, kMaxInstructionQuota);
    }
    ImGui::SameLine();
    std::uint64_t mem_mib = std::max<std::uint64_t>(1u, max_memory_bytes_ / (1024ull * 1024ull));
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 5.0f);
    if (ImGui::InputScalar("Memory (MiB)", ImGuiDataType_U64, &mem_mib)) {
        mem_mib = std::clamp<std::uint64_t>(mem_mib, 1u, 256u);
        max_memory_bytes_ = mem_mib * 1024ull * 1024ull;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 6.0f);
    if (ImGui::InputScalar("Timeout (ms)", ImGuiDataType_U64, &timeout_ms_)) {
        timeout_ms_ = std::clamp(timeout_ms_, kMinTimeoutMs, kMaxTimeoutMs);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Reset Quotas")) {
        const peelf::ScriptLimits defaults{};
        max_instructions_ = defaults.max_instructions;
        max_memory_bytes_ = defaults.max_memory_bytes;
        timeout_ms_ = static_cast<std::uint64_t>(defaults.wall_clock_timeout.count());
    }
    ImGui::EndDisabled();

    // Explicit opt-in target mutation control + capability reason
    if (!eligibility.can_mutate_target) {
        allow_mutations_ = false;
    }
    ImGui::BeginDisabled(is_running || !eligibility.can_mutate_target);
    ImGui::Checkbox("Allow Target Mutations", &allow_mutations_);
    ImGui::EndDisabled();
    ImGui::SameLine(0.0f, 12.0f);
    if (!eligibility.can_mutate_target) {
        ImGui::TextColored(ImVec4(0.88f, 0.58f, 0.30f, 1.0f),
                           "Read-Only: %s",
                           eligibility.reason.c_str());
    } else if (allow_mutations_) {
        ImGui::TextColored(
            ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
            "Mutations enabled (dry-run unless script explicitly calls peelf.commit()).");
    } else {
        ImGui::TextDisabled(
            "Read-only mode active (enable toggle to allow staging/committing patches & annotations).");
    }

    if (!launch_error_.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f),
                           "Launch error: %s",
                           launch_error_.c_str());
    }
}

void ScriptingPanel::draw_editor(bool is_running) {
    const float avail_h = ImGui::GetContentRegionAvail().y;
    const float editor_h = std::max(ImGui::GetTextLineHeightWithSpacing() * 9.0f, avail_h * 0.46f);

    ImGuiInputTextFlags flags =
        ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize;
    if (is_running) {
        flags |= ImGuiInputTextFlags_ReadOnly;
    }

    if (ImGui::InputTextMultiline("##LuaScriptEditor",
                                  script_buffer_.data(),
                                  script_buffer_.capacity() + 1u,
                                  ImVec2(-FLT_MIN, editor_h),
                                  flags,
                                  resize_std_string_callback,
                                  &script_buffer_)) {
        editor_modified_ = true;
    }
}

void ScriptingPanel::draw_output_and_mutations() {
    const auto& maybe_outcome = model_.last_script_outcome();
    if (!maybe_outcome.has_value()) {
        ImGui::TextDisabled(
            "Run a sandboxed Lua 5.4 script to view peelf.log() output, resource usage, and staged mutations.");
        return;
    }

    const AsyncScriptOutcome& outcome = *maybe_outcome;
    const peelf::ScriptExecutionResult& res = outcome.script_result;

    // Status + telemetry header
    switch (outcome.status) {
        case AsyncScriptStatus::Succeeded: {
            const char* commit_tag = res.committed
                                         ? (outcome.mutations_applied_to_model
                                                ? "Committed"
                                                : "Committed (No Target Mutations)")
                                         : (outcome.allow_mutations_effective
                                                ? "Dry-Run (Rolled Back)"
                                                : "Read-Only OK");
            ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f), "Status: %s", commit_tag);
            break;
        }
        case AsyncScriptStatus::Cancelled:
            ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.25f, 1.0f),
                               "Status: Cancelled (%s)",
                               res.error_message.empty() ? "user stop requested"
                                                         : res.error_message.c_str());
            break;
        case AsyncScriptStatus::StaleDiscarded:
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.25f, 1.0f),
                               "Status: Stale Result Discarded — %s",
                               outcome.apply_diagnostic.c_str());
            break;
        case AsyncScriptStatus::Failed: {
            const std::string_view kind_sv = peelf::to_string(res.error_kind);
            const std::string detail = !outcome.apply_diagnostic.empty()
                                           ? outcome.apply_diagnostic
                                           : res.error_message;
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f),
                               "Status: Failed [%.*s] — %s",
                               static_cast<int>(kind_sv.size()),
                               kind_sv.data(),
                               detail.c_str());
            break;
        }
    }

    ImGui::SameLine(0.0f, 16.0f);
    ImGui::TextDisabled("Insns: %" PRIu64 " | Peak Mem: %.1f KiB | Time: %" PRId64 " ms%s",
                        res.instructions_executed,
                        static_cast<double>(res.peak_memory_bytes) / 1024.0,
                        static_cast<std::int64_t>(res.elapsed.count()),
                        res.output_truncated ? " | [output truncated at quota]" : "");

    const float rem_h = ImGui::GetContentRegionAvail().y;
    const float out_h = std::max(ImGui::GetTextLineHeightWithSpacing() * 4.5f, rem_h * 0.45f);

    std::string display_log = res.output;
    if (!res.ok && !res.error_message.empty()) {
        if (!display_log.empty() && display_log.back() != '\n') {
            display_log.push_back('\n');
        }
        display_log += std::format("[{}] {}", peelf::to_string(res.error_kind), res.error_message);
    }
    ImGui::InputTextMultiline("##LuaScriptOutput",
                              display_log.data(),
                              display_log.size() + 1u,
                              ImVec2(-FLT_MIN, out_h),
                              ImGuiInputTextFlags_ReadOnly);

    const peelf::ScriptExecutionSummary& staged = res.staged_summary;
    const std::size_t total_staged = staged.staged_labels.size() +
                                     staged.staged_comments.size() +
                                     staged.staged_bookmarks.size() +
                                     staged.staged_patches.size();

    ImGui::Text("Staged / Committed Mutations (%zu) — click any row to navigate", total_staged);
    if (total_staged == 0u) {
        ImGui::TextDisabled("No labels, comments, bookmarks, or byte patches were staged.");
        return;
    }

    const char* state_badge =
        (outcome.status == AsyncScriptStatus::Succeeded && res.committed &&
         outcome.mutations_applied_to_model)
            ? "Committed"
            : "Rolled Back (Dry-Run)";

    const ImGuiTableFlags table_flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
                                        ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("##ScriptMutationsTable", 4, table_flags, ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("Address / Offset", ImGuiTableColumnFlags_WidthFixed, 175.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 135.0f);
        ImGui::TableSetupColumn("Details", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        int row_id = 0;

        for (const auto& [va, maybe_label] : staged.staged_labels) {
            ImGui::TableNextRow();
            ImGui::PushID(row_id++);
            ImGui::TableSetColumnIndex(0);
            const std::string addr_str = std::format("0x{:X}", va);
            if (ImGui::Selectable("Label", false, ImGuiSelectableFlags_SpanAllColumns)) {
                navigation_queue_.enqueue_address(va, PreferredView::Disassembly, 1u);
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(addr_str.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(state_badge);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(
                (!maybe_label.has_value() || maybe_label->empty())
                    ? "<cleared label>"
                    : maybe_label->c_str());
            ImGui::PopID();
        }

        for (const auto& [va, maybe_comment] : staged.staged_comments) {
            ImGui::TableNextRow();
            ImGui::PushID(row_id++);
            ImGui::TableSetColumnIndex(0);
            const std::string addr_str = std::format("0x{:X}", va);
            if (ImGui::Selectable("Comment", false, ImGuiSelectableFlags_SpanAllColumns)) {
                navigation_queue_.enqueue_address(va, PreferredView::Disassembly, 1u);
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(addr_str.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(state_badge);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(
                (!maybe_comment.has_value() || maybe_comment->empty())
                    ? "<cleared comment>"
                    : maybe_comment->c_str());
            ImGui::PopID();
        }

        for (const peelf::ScriptBookmark& bm : staged.staged_bookmarks) {
            ImGui::TableNextRow();
            ImGui::PushID(row_id++);
            ImGui::TableSetColumnIndex(0);
            const std::string addr_str = std::format("0x{:X}", bm.virtual_address);
            if (ImGui::Selectable("Bookmark", false, ImGuiSelectableFlags_SpanAllColumns)) {
                navigation_queue_.enqueue_address(
                    bm.virtual_address, PreferredView::Disassembly, 1u);
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(addr_str.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(state_badge);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(bm.label.c_str());
            ImGui::PopID();
        }

        for (const peelf::StagedBytePatch& sp : staged.staged_patches) {
            ImGui::TableNextRow();
            ImGui::PushID(row_id++);
            ImGui::TableSetColumnIndex(0);
            const std::string addr_str =
                std::format("0x{:X} (off 0x{:X})", sp.virtual_address, sp.file_offset);
            const std::size_t patch_len = std::max<std::size_t>(1u, sp.patched_bytes.size());
            if (ImGui::Selectable("Byte Patch", false, ImGuiSelectableFlags_SpanAllColumns)) {
                if (sp.virtual_address != 0u) {
                    navigation_queue_.enqueue_address(
                        sp.virtual_address, PreferredView::Hex, patch_len);
                } else {
                    navigation_queue_.enqueue_offset(sp.file_offset, patch_len);
                }
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(addr_str.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(state_badge);
            ImGui::TableSetColumnIndex(3);
            const std::string detail =
                std::format("{} B: [{}] -> [{}]",
                            sp.patched_bytes.size(),
                            format_hex_bytes_short(sp.original_bytes),
                            format_hex_bytes_short(sp.patched_bytes));
            ImGui::TextUnformatted(detail.c_str());
            ImGui::PopID();
        }

        ImGui::EndTable();
    }
}

void ScriptingPanel::draw_contents() {
    const ScriptMutationEligibility eligibility = model_.script_mutation_eligibility();
    draw_toolbar_and_limits(eligibility);
    ImGui::Separator();
    draw_editor(model_.is_script_running());
    ImGui::Separator();
    draw_output_and_mutations();
}

} // namespace viewer
