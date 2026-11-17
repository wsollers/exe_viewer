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

constexpr std::array<ScriptStarterTemplate, ScriptingPanel::kStarterTemplateCount>
    kStarterTemplates{{
        ScriptStarterTemplate{
            .title = "Inspect Target & Sections",
            .summary = "Read-only summary of target profile, capabilities, and mapped sections.",
            .requires_mutations = false,
            .source =
                "-- Inspect Target & Sections (Read-Only)\n"
                "local info = peelf.target_info()\n"
                "peelf.log(string.format(\"Target: %s | %s | %d-bit | %s | entry=0x%x\",\n"
                "  info.format, info.arch, info.bitness, info.endianness, info.entry_point))\n"
                "local secs = peelf.sections()\n"
                "peelf.log(string.format(\"Sections (%d):\", #secs))\n"
                "for i, s in ipairs(secs) do\n"
                "  local perms = (s.readable and \"R\" or \"-\")\n"
                "             .. (s.writable and \"W\" or \"-\")\n"
                "             .. (s.executable and \"X\" or \"-\")\n"
                "  peelf.log(string.format(\"  [%2d] %-16s va=0x%x size=0x%x file_off=0x%x %s\",\n"
                "    i, s.name, s.virtual_address, s.virtual_size, s.file_offset, perms))\n"
                "end\n"
                "local caps = peelf.capabilities()\n"
                "if caps.StaticPatching then\n"
                "  peelf.log(string.format(\"StaticPatching: %s (can_execute=%s)\",\n"
                "    caps.StaticPatching.state, tostring(caps.StaticPatching.can_execute)))\n"
                "end\n",
        },
        ScriptStarterTemplate{
            .title = "Scan High-Entropy / RWX Sections",
            .summary = "Flags W+X sections and runs peelf.security_audit() rules.",
            .requires_mutations = false,
            .source =
                "-- Scan High-Entropy / RWX Sections & Security Findings (Read-Only)\n"
                "local secs = peelf.sections()\n"
                "local rwx_count = 0\n"
                "for _, s in ipairs(secs) do\n"
                "  if s.writable and s.executable then\n"
                "    rwx_count = rwx_count + 1\n"
                "    peelf.log(string.format(\"[W+X] section '%s' at VA 0x%x (0x%x bytes)\",\n"
                "      s.name, s.virtual_address, s.virtual_size))\n"
                "  end\n"
                "end\n"
                "local audit = peelf.security_audit()\n"
                "peelf.log(string.format(\n"
                "  \"Security Audit (%s): %d error(s), %d warning(s), %d note(s), %d pass(es)\",\n"
                "  audit.format, audit.error_count, audit.warning_count, audit.note_count, audit.pass_count))\n"
                "for _, f in ipairs(audit.findings) do\n"
                "  if f.severity == \"Error\" or f.severity == \"Warning\" then\n"
                "    peelf.log(string.format(\"  [%s] %s (%s): %s\",\n"
                "      f.severity, f.rule_id, f.subject, f.summary))\n"
                "  end\n"
                "end\n"
                "peelf.log(string.format(\"Total W+X sections: %d\", rwx_count))\n",
        },
        ScriptStarterTemplate{
            .title = "Auto-Label Entry & Exports (Dry-Run)",
            .summary =
                "Stages entry/export labels & bookmarks without calling peelf.commit() (dry-run).",
            .requires_mutations = true,
            .source =
                "-- Auto-Label Entry & Exports (Dry-Run)\n"
                "-- Enable 'Allow Target Mutations' above. Because peelf.commit() is omitted,\n"
                "-- staged labels/comments/bookmarks appear in the table below and roll back cleanly.\n"
                "local info = peelf.target_info()\n"
                "assert(info.allow_mutations, \"Enable 'Allow Target Mutations' to stage dry-run annotations\")\n"
                "if info.entry_point ~= 0 then\n"
                "  peelf.set_label(info.entry_point, \"script_entry_point\")\n"
                "  peelf.set_comment(info.entry_point, \"Auto-labeled entry point (dry-run)\")\n"
                "  peelf.add_bookmark(info.entry_point, \"Entry point candidate\")\n"
                "  peelf.log(string.format(\"Staged entry label at 0x%x\", info.entry_point))\n"
                "end\n"
                "local exps = peelf.exports()\n"
                "local limit = math.min(#exps, 32)\n"
                "local count = 0\n"
                "for i = 1, limit do\n"
                "  local e = exps[i]\n"
                "  if e.virtual_address ~= 0 and #e.name > 0 then\n"
                "    peelf.set_label(e.virtual_address, \"exp_\" .. e.name)\n"
                "    peelf.set_comment(e.virtual_address, \"Exported symbol: \" .. e.name)\n"
                "    count = count + 1\n"
                "  end\n"
                "end\n"
                "peelf.log(string.format(\"Dry-run staged %d export annotation(s) (rolled back on exit).\", count))\n",
        },
        ScriptStarterTemplate{
            .title = "Stage NOP Patch + Commit",
            .summary =
                "Disassembles entry point, stages architecture NOP bytes + bookmark, and commits.",
            .requires_mutations = true,
            .source =
                "-- Stage NOP Patch + Commit (Transactional)\n"
                "-- Requires 'Allow Target Mutations' on an editable static binary.\n"
                "local info = peelf.target_info()\n"
                "assert(info.allow_mutations, \"Enable 'Allow Target Mutations' to stage and commit patches\")\n"
                "assert(info.entry_point ~= 0, \"Binary has no non-zero entry_point\")\n"
                "local insns = peelf.disassemble(info.entry_point, 1)\n"
                "assert(#insns >= 1, \"Unable to disassemble first instruction at entry_point\")\n"
                "local first = insns[1]\n"
                "peelf.log(string.format(\"Entry 0x%x: %s (%d byte(s))\", first.address, first.text, first.size))\n"
                "local nop_bytes = {}\n"
                "if info.arch == \"ARM64\" and first.size == 4 then\n"
                "  if info.endianness == \"Big\" then\n"
                "    nop_bytes = { 0xD5, 0x03, 0x20, 0x1F }\n"
                "  else\n"
                "    nop_bytes = { 0x1F, 0x20, 0x03, 0xD5 }\n"
                "  end\n"
                "elseif info.arch == \"x86\" or info.arch == \"x86-64\" then\n"
                "  for i = 1, first.size do nop_bytes[i] = 0x90 end\n"
                "else\n"
                "  error(\"Unsupported architecture for starter NOP template: \" .. info.arch)\n"
                "end\n"
                "peelf.stage_patch(first.address, nop_bytes)\n"
                "peelf.set_comment(first.address, \"NOP-patched via Lua scripting console\")\n"
                "peelf.add_bookmark(first.address, \"Scripted NOP patch\")\n"
                "peelf.commit(\"NOP entry instruction\")\n"
                "peelf.log(\"Committed transactional NOP patch + annotations.\")\n",
        },
    }};

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
    return kStarterTemplates;
}

void ScriptingPanel::load_starter_template(std::size_t index) {
    if (index >= kStarterTemplates.size()) {
        return;
    }
    selected_template_index_ = index;
    script_buffer_.assign(kStarterTemplates[index].source);
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
    const char* preview_title = kStarterTemplates[selected_template_index_].title.data();
    if (ImGui::BeginCombo("##ScriptStarterTemplate", preview_title)) {
        for (std::size_t i = 0u; i < kStarterTemplates.size(); ++i) {
            const bool is_selected = (i == selected_template_index_);
            if (ImGui::Selectable(kStarterTemplates[i].title.data(), is_selected)) {
                selected_template_index_ = i;
                if (!editor_modified_) {
                    load_starter_template(i);
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("%.*s",
                                  static_cast<int>(kStarterTemplates[i].summary.size()),
                                  kStarterTemplates[i].summary.data());
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
