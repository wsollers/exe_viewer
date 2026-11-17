#include "ui_panels.hpp"
#include "ui_panels_capabilities.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <string_view>

namespace viewer {
namespace {

[[nodiscard]] ImVec4 runtime_avail_color(peelf::Availability a) noexcept {
    switch (a) {
        case peelf::Availability::Available:   return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::Availability::Partial:     return ImVec4(1.00f, 0.78f, 0.26f, 1.0f);
        case peelf::Availability::Unavailable: return ImVec4(0.95f, 0.48f, 0.45f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

[[nodiscard]] bool icontains_rt(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    }) != hay.end();
}

void draw_decoded_fields_table(const char* table_id,
                               const std::vector<peelf::DecodedField>& fields,
                               const std::function<void(std::uint64_t, PreferredView)>& on_addr) {
    if (fields.empty()) {
        ImGui::TextDisabled("No structured fields available.");
        return;
    }
    std::optional<std::uint64_t> pending_nav_addr;
    if (ImGui::BeginTable(table_id,
                          4,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 175.0f);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < fields.size(); ++i) {
            const peelf::DecodedField& f = fields[i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(f.name.c_str());

            ImGui::TableNextColumn();
            if (f.offset.has_value()) {
                ImGui::Text("+0x%" PRIX64, *f.offset);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (f.raw_value.has_value() && *f.raw_value >= 0x1000u) {
                if (ImGui::Selectable(f.formatted_value.c_str()) && on_addr) {
                    pending_nav_addr = *f.raw_value;
                }
            } else {
                ImGui::TextUnformatted(f.formatted_value.c_str());
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", f.description.c_str());
        }
        ImGui::EndTable();
    }
    if (pending_nav_addr.has_value() && on_addr) {
        on_addr(*pending_nav_addr, PreferredView::Hex);
    }
}

} // namespace

RuntimeAndFlagsPanel::RuntimeAndFlagsPanel(BinaryModel& model)
    : UiPanel("PEB / TEB & Flags")
    , model_(model) {}

void RuntimeAndFlagsPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to inspect PEB/TEB/auxv runtime blocks and harvested header flags.");
        return;
    }

    if (ImGui::SmallButton("Refresh")) {
        model_.refresh_runtime_and_handlers();
    }
    ImGui::SameLine();
    ui_provenance::draw_capture_stamp_badge("Runtime", model_.runtime_stamp());

    if (ImGui::BeginTabBar("RuntimeAndFlagsTabs")) {
        if (ImGui::BeginTabItem("Security Audit (BinSkim)")) {
            const peelf::SecurityAuditReport& audit = model_.security_audit();
            const std::string_view av = peelf::to_string(audit.status.availability);
            ImGui::TextColored(runtime_avail_color(audit.status.availability),
                               "[%.*s] %s",
                               static_cast<int>(av.size()),
                               av.data(),
                               audit.status.detail.c_str());

            ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "Errors: %zu", audit.error_count);
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.00f, 0.78f, 0.28f, 1.0f), "  Warnings: %zu", audit.warning_count);
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.55f, 0.80f, 1.00f, 1.0f), "  Notes: %zu", audit.note_count);
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.42f, 0.92f, 0.58f, 1.0f), "  Passed: %zu", audit.pass_count);

            static constexpr std::array<const char*, 3> kAuditSeverityItems = {
                "All Rules",
                "Warnings & Errors",
                "Errors Only",
            };
            ImGui::SetNextItemWidth(190.0f);
            ImGui::Combo("Severity##AuditSev",
                         &audit_severity_filter_,
                         kAuditSeverityItems.data(),
                         static_cast<int>(kAuditSeverityItems.size()));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::InputTextWithHint("##AuditFilter",
                                     "Filter rule ID (PE1001, ELF2003, LIVE3001), summary, or evidence...",
                                     audit_filter_buf_,
                                     sizeof(audit_filter_buf_));
            const std::string_view afilter(audit_filter_buf_);

            std::optional<std::uint64_t> pending_audit_nav_va;
            std::optional<PendingEntityContextAction> pending_ctx_action;
            if (ImGui::BeginTable("SecurityAuditTable",
                                  5,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Rule ID", ImGuiTableColumnFlags_WidthFixed, 86.0f);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 78.0f);
                ImGui::TableSetupColumn("Subject / VA", ImGuiTableColumnFlags_WidthFixed, 175.0f);
                ImGui::TableSetupColumn("Finding & Evidence", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Remediation", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                for (std::size_t idx = 0; idx < audit.findings.size(); ++idx) {
                    const peelf::SecurityFinding& f = audit.findings[idx];
                    if (audit_severity_filter_ == 1 &&
                        f.severity != peelf::SecuritySeverity::Warning &&
                        f.severity != peelf::SecuritySeverity::Error) {
                        continue;
                    }
                    if (audit_severity_filter_ == 2 &&
                        f.severity != peelf::SecuritySeverity::Error) {
                        continue;
                    }
                    if (!afilter.empty() &&
                        !icontains_rt(f.rule_id, afilter) &&
                        !icontains_rt(f.rule_name, afilter) &&
                        !icontains_rt(f.subject, afilter) &&
                        !icontains_rt(f.summary, afilter) &&
                        !icontains_rt(f.evidence, afilter)) {
                        continue;
                    }

                    ImVec4 sev_col(0.75f, 0.75f, 0.75f, 1.0f);
                    switch (f.severity) {
                        case peelf::SecuritySeverity::Pass:    sev_col = ImVec4(0.42f, 0.92f, 0.58f, 1.0f); break;
                        case peelf::SecuritySeverity::Note:    sev_col = ImVec4(0.55f, 0.80f, 1.00f, 1.0f); break;
                        case peelf::SecuritySeverity::Warning: sev_col = ImVec4(1.00f, 0.78f, 0.28f, 1.0f); break;
                        case peelf::SecuritySeverity::Error:   sev_col = ImVec4(0.95f, 0.42f, 0.42f, 1.0f); break;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(idx));
                    std::optional<std::uint64_t> nav_va = f.virtual_address;
                    if (!nav_va.has_value() && f.file_offset.has_value()) {
                        nav_va = model_.offset_to_virtual_address(*f.file_offset);
                    }
                    if (ImGui::Selectable(f.rule_id.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                        if (nav_va.has_value() && on_address_activated_) {
                            pending_audit_nav_va = *nav_va;
                        }
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s\n%s", f.rule_name.c_str(), f.evidence.c_str());
                    }
                    draw_inspectable_entity_context_menu(
                        "SecurityFindingCtx",
                        model_,
                        pending_ctx_action,
                        [&]() -> InspectableEntity {
                            const bool static_img = model_has_static_image(model_);
                            std::optional<std::uint64_t> eff_off = f.file_offset;
                            if (!eff_off.has_value() && nav_va.has_value() && static_img) {
                                eff_off = model_.virtual_address_to_offset(*nav_va);
                            }
                            return InspectableEntity{
                                .va = nav_va,
                                .file_offset = static_img ? eff_off : std::nullopt,
                                .size = 1u,
                                .symbol_or_label = f.rule_id + ": " + f.rule_name,
                                .module_name = f.subject,
                                .extra_json_fields = {
                                    {"rule_id", f.rule_id},
                                    {"severity", std::string(peelf::to_string(f.severity))},
                                    {"summary", f.summary},
                                    {"evidence", f.evidence},
                                    {"remediation", f.remediation},
                                },
                            };
                        });
                    ImGui::PopID();

                    ImGui::TableNextColumn();
                    const std::string_view sv = peelf::to_string(f.severity);
                    ImGui::TextColored(sev_col, "%.*s", static_cast<int>(sv.size()), sv.data());

                    ImGui::TableNextColumn();
                    if (f.virtual_address.has_value()) {
                        ImGui::Text("%s (0x%" PRIX64 ")", f.subject.c_str(), *f.virtual_address);
                    } else if (f.file_offset.has_value()) {
                        ImGui::Text("%s (+0x%" PRIX64 ")", f.subject.c_str(), *f.file_offset);
                    } else {
                        ImGui::TextUnformatted(f.subject.c_str());
                    }

                    ImGui::TableNextColumn();
                    ImGui::TextWrapped("%s  [%s]", f.summary.c_str(), f.evidence.c_str());

                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", f.remediation.c_str());
                }
                ImGui::EndTable();
            }
            if (pending_audit_nav_va.has_value() && on_address_activated_) {
                on_address_activated_(*pending_audit_nav_va, PreferredView::Hex);
            }
            if (pending_ctx_action.has_value() && on_context_action_) {
                on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Header & Security Flags")) {
            const peelf::HeaderFlagsReport& hf = model_.header_flags();
            const std::string_view av = peelf::to_string(hf.status.availability);
            ImGui::TextColored(runtime_avail_color(hf.status.availability),
                               "[%.*s] %s",
                               static_cast<int>(av.size()),
                               av.data(),
                               hf.status.detail.c_str());

            ImGui::InputTextWithHint("##FlagFilter",
                                     "Filter flag group, flag name, or description...",
                                     flags_filter_buf_,
                                     sizeof(flags_filter_buf_));
            const std::string_view filter(flags_filter_buf_);

            if (ImGui::BeginTable("HeaderFlagsTable",
                                  4,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Group", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Flag / Characteristic", ImGuiTableColumnFlags_WidthFixed, 210.0f);
                ImGui::TableSetupColumn("Mask", ImGuiTableColumnFlags_WidthFixed, 96.0f);
                ImGui::TableSetupColumn("Meaning", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                for (const peelf::HarvestedFlagItem& item : hf.flags) {
                    if (!filter.empty() &&
                        !icontains_rt(item.category, filter) &&
                        !icontains_rt(item.name, filter) &&
                        !icontains_rt(item.description, filter)) {
                        continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", item.category.c_str());

                    ImGui::TableNextColumn();
                    ImGui::TextColored(item.active ? ImVec4(0.45f, 0.92f, 0.62f, 1.0f)
                                                   : ImVec4(0.65f, 0.65f, 0.68f, 1.0f),
                                       "%s",
                                       item.name.c_str());

                    ImGui::TableNextColumn();
                    ImGui::Text("0x%" PRIX64, item.mask);

                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(item.description.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Process Block (PEB / Linux Runtime)")) {
            const peelf::ProcessEnvironmentSnapshot& peb = model_.process_environment();
            const std::string_view av = peelf::to_string(peb.core_status.availability);
            const char* os_label = peb.os_family == peelf::Format::PE
                ? "Win32 PEB"
                : (peb.os_family == peelf::Format::ELF ? "Linux Process Runtime" : "Process Environment");
            ImGui::TextColored(runtime_avail_color(peb.core_status.availability),
                               "[%.*s] %s  |  %s",
                               static_cast<int>(av.size()),
                               av.data(),
                               os_label,
                               peb.core_status.detail.c_str());

            if (peb.block_address.has_value()) {
                ImGui::Text("Base VA: 0x%016" PRIX64, *peb.block_address);
                ImGui::SameLine();
                if (ImGui::SmallButton("View in Hex") && on_address_activated_) {
                    on_address_activated_(*peb.block_address, PreferredView::Hex);
                }
            }
            ImGui::TextColored(peb.debugger_present ? ImVec4(1.0f, 0.55f, 0.35f, 1.0f)
                                                    : ImVec4(0.40f, 0.90f, 0.58f, 1.0f),
                               "Debugger / Tracer Present: %s%s%s",
                               peb.debugger_present ? "Yes" : "No",
                               peb.debugger_detail.empty() ? "" : "  |  ",
                               peb.debugger_detail.c_str());

            draw_decoded_fields_table("PebFieldsTable", peb.core_fields, on_address_activated_);
            if (!peb.process_parameters.empty() &&
                ImGui::CollapsingHeader("Process Parameters (RTL_USER_PROCESS_PARAMETERS / cmdline & cwd)")) {
                draw_decoded_fields_table("PebParamsTable", peb.process_parameters, on_address_activated_);
            }
            if (!peb.security_and_status_fields.empty() &&
                ImGui::CollapsingHeader("Process Status & Security Posture")) {
                draw_decoded_fields_table("PebSecStatusTable", peb.security_and_status_fields, on_address_activated_);
            }

            if (!peb.loader_modules.empty() &&
                ImGui::CollapsingHeader("Loader Module Chain (PEB_LDR_DATA / r_debug link_map)", ImGuiTreeNodeFlags_DefaultOpen)) {
                std::optional<std::uint64_t> pending_ldr_base_va;
                if (ImGui::BeginTable("LdrModulesTable",
                                      4,
                                      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                                      ImVec2(0.0f, 150.0f))) {
                    ImGui::TableSetupColumn("Base VA", ImGuiTableColumnFlags_WidthFixed, 132.0f);
                    ImGui::TableSetupColumn("Size / Dyn", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                    ImGui::TableSetupColumn("Entry Point", ImGuiTableColumnFlags_WidthFixed, 132.0f);
                    ImGui::TableSetupColumn("Name / Path", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (std::size_t i = 0; i < peb.loader_modules.size(); ++i) {
                        const peelf::RuntimeModuleEntry& m = peb.loader_modules[i];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::PushID(static_cast<int>(i));
                        std::array<char, 32> bbuf{};
                        std::snprintf(bbuf.data(), bbuf.size(), "0x%016" PRIX64, m.base_address);
                        if (ImGui::Selectable(bbuf.data()) && m.base_address != 0 && on_address_activated_) {
                            pending_ldr_base_va = m.base_address;
                        }
                        ImGui::PopID();
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%" PRIX64, m.size_or_dynamic_va);
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%" PRIX64, m.entry_point);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(!m.full_path.empty() ? m.full_path.c_str() : m.name.c_str());
                    }
                    ImGui::EndTable();
                }
                if (pending_ldr_base_va.has_value() && on_address_activated_) {
                    on_address_activated_(*pending_ldr_base_va, PreferredView::Hex);
                }
            }

            if (!peb.auxv_entries.empty() && ImGui::CollapsingHeader("Linux Auxiliary Vector (auxv)")) {
                if (ImGui::BeginTable("AuxvTable",
                                      3,
                                      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                                      ImVec2(0.0f, 160.0f))) {
                    ImGui::TableSetupColumn("Tag", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                    ImGui::TableSetupColumn("Raw Value", ImGuiTableColumnFlags_WidthFixed, 145.0f);
                    ImGui::TableSetupColumn("Decoded", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (const peelf::AuxvEntry& a : peb.auxv_entries) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(a.type_name.c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%" PRIX64, a.value);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(a.formatted_value.c_str());
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Thread Block (TEB / Linux TCB)")) {
            const peelf::ThreadEnvironmentSnapshot& teb = model_.thread_environment();
            const std::string_view av = peelf::to_string(teb.status.availability);
            const char* teb_label = teb.os_family == peelf::Format::PE
                ? "Win32 TEB"
                : (teb.os_family == peelf::Format::ELF ? "Linux Thread / TCB" : "Thread Environment");
            ImGui::TextColored(runtime_avail_color(teb.status.availability),
                               "[%.*s] %s (TID %u)  |  %s",
                               static_cast<int>(av.size()),
                               av.data(),
                               teb_label,
                               teb.tid,
                               teb.status.detail.c_str());

            if (teb.block_address.has_value() && *teb.block_address != 0) {
                ImGui::Text("TEB / TCB Base: 0x%016" PRIX64, *teb.block_address);
                ImGui::SameLine();
                if (ImGui::SmallButton("Inspect in Hex") && on_address_activated_) {
                    on_address_activated_(*teb.block_address, PreferredView::Hex);
                }
            }
            if (teb.stack_base && teb.stack_limit) {
                ImGui::TextDisabled("Stack Bounds: 0x%016" PRIX64 " .. 0x%016" PRIX64,
                                    *teb.stack_limit,
                                    *teb.stack_base);
            }
            draw_decoded_fields_table("TebFieldsTable", teb.fields, on_address_activated_);
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
}

} // namespace viewer
