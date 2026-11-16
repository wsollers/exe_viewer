#include "ui_panels_settings_overview.hpp"

#include "ui_panels_capabilities.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <format>
#include <string>
#include <string_view>

namespace viewer {
namespace {

[[nodiscard]] bool matches_case_insensitive(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    const auto it = std::ranges::search(
        haystack,
        needle,
        [](char a, char b) noexcept {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return !it.empty();
}

void draw_metadata_state_badge(peelf::MetadataFieldState state) {
    ImVec4 col(0.70f, 0.70f, 0.74f, 1.0f);
    switch (state) {
        case peelf::MetadataFieldState::Present:
            col = ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
            break;
        case peelf::MetadataFieldState::Absent:
            col = ImVec4(0.68f, 0.72f, 0.78f, 1.0f);
            break;
        case peelf::MetadataFieldState::Malformed:
            col = ImVec4(1.00f, 0.42f, 0.42f, 1.0f);
            break;
        case peelf::MetadataFieldState::Truncated:
            col = ImVec4(1.00f, 0.76f, 0.28f, 1.0f);
            break;
        case peelf::MetadataFieldState::UnsupportedFormat:
            col = ImVec4(0.55f, 0.58f, 0.64f, 1.0f);
            break;
    }
    const std::string text = std::format("[{}]", peelf::to_string(state));
    ImGui::TextColored(col, "%s", text.c_str());
}

void draw_unavailable_notice(std::string_view section_title,
                             peelf::CaptureAvailability avail,
                             std::string_view note) {
    const ImVec4 col = avail == peelf::CaptureAvailability::Unavailable
                           ? ImVec4(0.72f, 0.74f, 0.80f, 1.0f)
                           : ImVec4(1.00f, 0.76f, 0.28f, 1.0f);
    const std::string status = std::format("[{}] {}", peelf::to_string(avail), section_title);
    ImGui::TextColored(col, "%s", status.c_str());
    if (!note.empty()) {
        ImGui::TextWrapped("%s", std::string(note).c_str());
    }
}

} // namespace

ExecutableSettingsPanel::ExecutableSettingsPanel(BinaryModel& model, NavigateCallback on_navigate)
    : UiPanel("Executable Settings")
    , model_(model)
    , on_navigate_(std::move(on_navigate)) {}

void ExecutableSettingsPanel::draw_contents() {
    if (!model_.has_file() && !model_.is_live_process()) {
        ImGui::TextDisabled("Open a PE/ELF binary, crash dump, or attach to a live process to inspect settings.");
        return;
    }

    DeferredNav pending_nav{};
    std::optional<peelf::EnvironmentRedactionPolicy> pending_policy{};

    // Snapshot & diff controls (and lazy process-internals load) run before binding `report`
    // so mutations to `model_` never invalidate references into `executable_settings()`.
    if (model_.is_live_process()) {
        if (!model_.has_process_internals() &&
            model_.process_session() != nullptr &&
            model_.process_session()->is_alive()) {
            model_.refresh_process_internals();
        }
        draw_snapshot_controls_bar(pending_nav);
        ImGui::Separator();
    }

    const peelf::ExecutableSettingsReport& report = model_.executable_settings();

    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 18.0f);
    ImGui::InputTextWithHint("##settings_filter", "Filter keys / values / libraries...", filter_buf_, sizeof(filter_buf_));
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) {
        filter_buf_[0] = '\0';
    }
    ImGui::SameLine();
    const std::string prof_summary = std::format(
        "{} / {} / {}",
        peelf::to_string(report.target_profile.format),
        peelf::to_string(report.target_profile.architecture),
        peelf::to_string(report.target_profile.backend));
    ImGui::TextDisabled("Target: %s", prof_summary.c_str());

    if (model_.latest_snapshot_diff().has_value()) {
        ImGui::Separator();
        draw_snapshot_diff_section(*model_.latest_snapshot_diff(), pending_nav);
    }

    ImGui::Separator();
    draw_declared_section(report);
    ImGui::Spacing();
    ImGui::Separator();
    draw_launch_environment_section(report, pending_policy);
    ImGui::Spacing();
    ImGui::Separator();
    draw_observed_runtime_section(report, pending_nav);

    if (pending_policy.has_value()) {
        model_.set_environment_redaction_policy(*pending_policy);
    }
    if (pending_nav.has_value() && on_navigate_) {
        on_navigate_(pending_nav->first, pending_nav->second);
    }
}

void ExecutableSettingsPanel::draw_snapshot_controls_bar(DeferredNav& /*pending_nav*/) {
    if (ImGui::Button("Capture Snapshot")) {
        if (auto res = model_.capture_snapshot(pause_during_snapshot_); res.has_value()) {
            const std::size_t idx = *res;
            if (idx >= 1u) {
                diff_before_index_ = idx - 1u;
                diff_after_index_ = idx;
            } else {
                diff_before_index_ = 0u;
                diff_after_index_ = 0u;
            }
            snapshot_status_msg_ = std::format("Captured snapshot #{} (rev {}).",
                                               idx,
                                               model_.captured_snapshots()[idx].snapshot_revision);
        } else {
            snapshot_status_msg_ = std::format("Snapshot failed: {}", res.error().message);
        }
    }

    if (!model_.is_crash_dump()) {
        ImGui::SameLine();
        ImGui::Checkbox("Pause during capture", &pause_during_snapshot_);
    }

    const auto snapshots = model_.captured_snapshots();
    ImGui::SameLine();
    ImGui::TextDisabled("Snapshots: %zu", snapshots.size());

    if (snapshots.size() >= 2u) {
        if (diff_before_index_ >= snapshots.size()) {
            diff_before_index_ = snapshots.size() - 2u;
        }
        if (diff_after_index_ >= snapshots.size()) {
            diff_after_index_ = snapshots.size() - 1u;
        }

        const auto format_snap_label = [&](std::size_t idx) {
            const peelf::ProcessStateSnapshot& s = snapshots[idx];
            return std::format("#{} (rev {}, {})",
                               idx,
                               s.snapshot_revision,
                               s.snapshot_stamp.captured_at_utc.empty()
                                   ? "uninitialized"
                                   : s.snapshot_stamp.captured_at_utc);
        };

        ImGui::Spacing();
        const std::string before_preview = format_snap_label(diff_before_index_);
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14.0f);
        if (ImGui::BeginCombo("Baseline##snap_before", before_preview.c_str())) {
            for (std::size_t i = 0u; i < snapshots.size(); ++i) {
                const std::string lbl = format_snap_label(i);
                const bool selected = (i == diff_before_index_);
                if (ImGui::Selectable(lbl.c_str(), selected)) {
                    diff_before_index_ = i;
                }
            }
            ImGui::EndCombo();
        }

        ImGui::SameLine();
        const std::string after_preview = format_snap_label(diff_after_index_);
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14.0f);
        if (ImGui::BeginCombo("Target##snap_after", after_preview.c_str())) {
            for (std::size_t i = 0u; i < snapshots.size(); ++i) {
                const std::string lbl = format_snap_label(i);
                const bool selected = (i == diff_after_index_);
                if (ImGui::Selectable(lbl.c_str(), selected)) {
                    diff_after_index_ = i;
                }
            }
            ImGui::EndCombo();
        }

        ImGui::SameLine();
        if (ImGui::Button("Diff Snapshots")) {
            if (auto diff_res = model_.diff_snapshots(diff_before_index_, diff_after_index_);
                diff_res.has_value()) {
                snapshot_status_msg_ =
                    std::format("Computed diff #{} -> #{}.", diff_before_index_, diff_after_index_);
            } else {
                snapshot_status_msg_ = std::format("Diff failed: {}", diff_res.error().message);
            }
        }
    } else {
        ImGui::SameLine();
        ImGui::BeginDisabled(true);
        (void)ImGui::Button("Diff Snapshots");
        ImGui::EndDisabled();
    }

    if (!snapshots.empty()) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear Snapshots")) {
            model_.clear_snapshots();
            diff_before_index_ = 0u;
            diff_after_index_ = 0u;
            snapshot_status_msg_ = "Cleared captured snapshots.";
        }
    }

    if (!snapshot_status_msg_.empty()) {
        ImGui::TextDisabled("%s", snapshot_status_msg_.c_str());
    }
}

void ExecutableSettingsPanel::draw_snapshot_diff_section(
    const peelf::SnapshotDiff& diff,
    DeferredNav& pending_nav) {
    if (!ImGui::CollapsingHeader("Snapshot Timeline Diff", ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }

    if (diff.rejected_target_mismatch) {
        ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "%s", diff.summary.c_str());
    } else {
        ImGui::TextUnformatted(diff.summary.c_str());
    }

    for (const peelf::SnapshotUncertainty& unc : diff.uncertainties) {
        ImGui::TextColored(
            ImVec4(1.00f, 0.72f, 0.28f, 1.0f),
            "[Uncertainty: %s / %s] %s",
            std::string(peelf::to_string(unc.domain)).c_str(),
            std::string(peelf::to_string(unc.kind)).c_str(),
            unc.message.c_str());
    }

    if (!diff.modules.empty() && ImGui::TreeNode("Module Deltas")) {
        if (ImGui::BeginTable("##snap_mod_deltas", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("Base VA", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableHeadersRow();
            for (std::size_t i = 0u; i < diff.modules.size(); ++i) {
                const peelf::ModuleDelta& md = diff.modules[i];
                const std::uint64_t target_va =
                    md.after.has_value()
                        ? md.after->base_address
                        : (md.before.has_value() ? md.before->base_address : 0u);
                const std::string mod_name =
                    md.after.has_value()
                        ? md.after->name
                        : (md.before.has_value() ? md.before->name : "<unknown>");
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(std::string(peelf::to_string(md.kind)).c_str());
                ImGui::TableSetColumnIndex(1);
                const std::string va_btn = std::format("0x{:X}##md_va_{}", target_va, i);
                if (target_va != 0u && ImGui::SmallButton(va_btn.c_str())) {
                    pending_nav = std::pair{target_va, PreferredView::Disassembly};
                } else if (target_va == 0u) {
                    ImGui::TextDisabled("0x0");
                }
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(mod_name.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled(
                    "%s%s",
                    md.base_address_reused ? "VA-Reused " : "",
                    md.backing_identity_changed ? "Build-ID-Changed" : "");
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(md.detail.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }

    if (!diff.regions.empty() && ImGui::TreeNode("Memory Region Interval Deltas")) {
        if (ImGui::BeginTable("##snap_reg_deltas", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("Sub-Interval", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableHeadersRow();
            for (std::size_t i = 0u; i < diff.regions.size(); ++i) {
                const peelf::RegionDelta& rd = diff.regions[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(std::string(peelf::to_string(rd.kind)).c_str());
                ImGui::TableSetColumnIndex(1);
                const std::string range_lbl =
                    std::format("[0x{:X}, 0x{:X})##rd_{}", rd.start_address, rd.end_address, i);
                if (rd.start_address != 0u && ImGui::SmallButton(range_lbl.c_str())) {
                    pending_nav = std::pair{
                        rd.start_address,
                        rd.became_executable ? PreferredView::Disassembly : PreferredView::Hex};
                } else {
                    ImGui::Text("[0x%" PRIX64 ", 0x%" PRIX64 ")", rd.start_address, rd.end_address);
                }
                ImGui::TableSetColumnIndex(2);
                if (rd.became_rwx) {
                    ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "RWX! ");
                    ImGui::SameLine();
                }
                ImGui::TextDisabled(
                    "%s%s%s%s",
                    rd.was_split ? "Split " : "",
                    rd.was_merged ? "Merged " : "",
                    rd.va_reused ? "VA-Reused " : "",
                    rd.jit_rw_to_rx ? "RW->RX" : "");
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(rd.detail.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }

    if (!diff.threads.empty() && ImGui::TreeNode("Thread Deltas")) {
        for (std::size_t i = 0u; i < diff.threads.size(); ++i) {
            const peelf::ThreadDelta& td = diff.threads[i];
            ImGui::BulletText("[%s] %s",
                              std::string(peelf::to_string(td.kind)).c_str(),
                              td.detail.c_str());
            if (td.after.has_value() && td.after->info.instruction_pointer.has_value() &&
                *td.after->info.instruction_pointer != 0u) {
                ImGui::SameLine();
                const std::string ip_btn =
                    std::format("Go IP 0x{:X}##td_ip_{}", *td.after->info.instruction_pointer, i);
                if (ImGui::SmallButton(ip_btn.c_str())) {
                    pending_nav =
                        std::pair{*td.after->info.instruction_pointer, PreferredView::Disassembly};
                }
            }
        }
        ImGui::TreePop();
    }

    if (!diff.handles.empty() && ImGui::TreeNode("Handle / FD Deltas")) {
        for (const peelf::HandleDelta& hd : diff.handles) {
            ImGui::BulletText("[%s] %s",
                              std::string(peelf::to_string(hd.kind)).c_str(),
                              hd.detail.c_str());
        }
        ImGui::TreePop();
    }

    if (!diff.sockets.empty() && ImGui::TreeNode("Socket Deltas")) {
        for (const peelf::SocketDelta& sd : diff.sockets) {
            ImGui::BulletText("[%s] %s",
                              std::string(peelf::to_string(sd.kind)).c_str(),
                              sd.detail.c_str());
        }
        ImGui::TreePop();
    }
}

void ExecutableSettingsPanel::draw_declared_section(const peelf::ExecutableSettingsReport& report) {
    if (!ImGui::CollapsingHeader("1. Declared in File (Static Metadata)", ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }

    ui_provenance::draw_provenance_badge(report.declared_in_file.provenance, report.declared_in_file.note);
    ImGui::SameLine();
    ui_provenance::draw_capture_stamp_badge("Declared", report.declared_in_file.stamp);

    if (!report.declared_in_file.has_value()) {
        draw_unavailable_notice(
            "Declared Static Metadata",
            report.declared_in_file.availability,
            report.declared_in_file.note);
        return;
    }

    const peelf::DeclaredSettings& d = *report.declared_in_file.value;
    if (!report.declared_in_file.note.empty() &&
        report.declared_in_file.availability != peelf::CaptureAvailability::Complete) {
        ImGui::TextColored(ImVec4(1.00f, 0.76f, 0.28f, 1.0f),
                           "Notice: %s",
                           report.declared_in_file.note.c_str());
    }

    ImGui::Text("Format: %s (%s, %d-bit %s)  |  Image Base: 0x%" PRIX64 "  |  Entry Point: 0x%" PRIX64,
                std::string(peelf::to_string(d.format)).c_str(),
                std::string(peelf::to_string(d.kind)).c_str(),
                d.is_64bit ? 64 : 32,
                std::string(peelf::to_string(d.endianness)).c_str(),
                d.image_base,
                d.entry_point);
    if (d.entry_point != 0u && on_navigate_) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Jump to Entry##decl_ep")) {
            on_navigate_(d.entry_point, PreferredView::Disassembly);
        }
    }

    if (d.pe_subsystem.has_value()) {
        ImGui::Text("PE Subsystem: %s (%u)  |  Stack Reserve/Commit: 0x%" PRIX64 " / 0x%" PRIX64
                    "  |  Heap Reserve/Commit: 0x%" PRIX64 " / 0x%" PRIX64,
                    d.pe_subsystem_name.c_str(),
                    static_cast<unsigned int>(*d.pe_subsystem),
                    d.pe_stack_reserve.value_or(0u),
                    d.pe_stack_commit.value_or(0u),
                    d.pe_heap_reserve.value_or(0u),
                    d.pe_heap_commit.value_or(0u));
    }

    const std::string_view filter(filter_buf_);
    if (!d.declared_dependencies.empty() && ImGui::TreeNode("Declared Dependencies")) {
        for (const std::string& dep : d.declared_dependencies) {
            if (matches_case_insensitive(dep, filter)) {
                ImGui::BulletText("%s", dep.c_str());
            }
        }
        ImGui::TreePop();
    }

    if (d.format == peelf::Format::PE) {
        draw_pe_manifest_block(d);
        draw_pe_version_block(d);
        draw_pe_clr_block(d);
    } else if (d.format == peelf::Format::ELF) {
        draw_elf_settings_block(d);
    }
}

void ExecutableSettingsPanel::draw_pe_manifest_block(const peelf::DeclaredSettings& d) {
    ImGui::AlignTextToFramePadding();
    const bool open = ImGui::TreeNodeEx("PE Manifest (RT_MANIFEST)", ImGuiTreeNodeFlags_DefaultOpen);
    ImGui::SameLine();
    draw_metadata_state_badge(d.pe_manifest_state);
    if (!open) {
        return;
    }

    if (!d.pe_manifest.has_value()) {
        ImGui::TextDisabled("%s", d.pe_manifest.note.empty() ? "No RT_MANIFEST resource present." : d.pe_manifest.note.c_str());
        ImGui::TreePop();
        return;
    }

    const peelf::PeManifestInfo& m = *d.pe_manifest.value;
    ImGui::Text("Resource ID: %u  |  Language: 0x%04X  |  Encoding: %s  |  Size: %" PRIu32 " bytes",
                m.resource_name_id,
                static_cast<unsigned int>(m.language_id),
                m.encoding.c_str(),
                m.raw_size);
    if (m.data_rva != 0u && on_navigate_) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Inspect Hex##manifest_hex")) {
            on_navigate_(d.image_base + m.data_rva, PreferredView::Hex);
        }
    }

    ImGui::BulletText("UAC Execution Level: %s  |  uiAccess: %s",
                      m.requested_execution_level.empty() ? "<unspecified>" : m.requested_execution_level.c_str(),
                      m.ui_access.has_value() ? (*m.ui_access ? "true" : "false") : "<unspecified>");
    ImGui::BulletText("DPI Aware: %s  |  DPI Awareness: %s",
                      m.dpi_aware.empty() ? "<unspecified>" : m.dpi_aware.c_str(),
                      m.dpi_awareness.empty() ? "<unspecified>" : m.dpi_awareness.c_str());
    ImGui::BulletText("Long Path Aware: %s  |  Heap Type: %s",
                      m.long_path_aware.has_value() ? (*m.long_path_aware ? "true" : "false") : "<unspecified>",
                      m.heap_type.empty() ? "<unspecified>" : m.heap_type.c_str());

    if (m.assembly_identity.has_value()) {
        ImGui::BulletText("Assembly Identity: %s v%s (%s)",
                          m.assembly_identity->name.c_str(),
                          m.assembly_identity->version.c_str(),
                          m.assembly_identity->processor_architecture.empty()
                              ? "any"
                              : m.assembly_identity->processor_architecture.c_str());
    }

    if (!m.supported_os.empty() && ImGui::TreeNode("Supported OS Compatibility GUIDs")) {
        for (const peelf::PeSupportedOsEntry& os : m.supported_os) {
            ImGui::BulletText("%s (%s)", os.friendly_name.c_str(), os.guid.c_str());
        }
        ImGui::TreePop();
    }

    if (!m.dependent_assemblies.empty() && ImGui::TreeNode("Side-by-Side Dependent Assemblies")) {
        for (const peelf::PeAssemblyIdentity& dep : m.dependent_assemblies) {
            ImGui::BulletText("%s v%s [%s] token=%s",
                              dep.name.c_str(),
                              dep.version.c_str(),
                              dep.processor_architecture.empty() ? "*" : dep.processor_architecture.c_str(),
                              dep.public_key_token.empty() ? "none" : dep.public_key_token.c_str());
        }
        ImGui::TreePop();
    }

    for (const std::string& w : m.warnings) {
        ImGui::TextColored(ImVec4(1.00f, 0.72f, 0.28f, 1.0f), "Warning: %s", w.c_str());
    }

    ImGui::Checkbox("Show Raw RT_MANIFEST XML", &show_raw_manifest_xml_);
    if (show_raw_manifest_xml_ && !m.raw_xml.empty()) {
        ImGui::BeginChild("##raw_manifest_xml", ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing() * 8.0f), ImGuiChildFlags_Borders);
        ImGui::TextUnformatted(m.raw_xml.c_str());
        ImGui::EndChild();
    }

    ImGui::TreePop();
}

void ExecutableSettingsPanel::draw_pe_version_block(const peelf::DeclaredSettings& d) {
    ImGui::AlignTextToFramePadding();
    const bool open = ImGui::TreeNodeEx("PE Version Info (RT_VERSION)", ImGuiTreeNodeFlags_DefaultOpen);
    ImGui::SameLine();
    draw_metadata_state_badge(d.pe_version_state);
    if (!open) {
        return;
    }

    if (!d.pe_version.has_value()) {
        ImGui::TextDisabled("%s", d.pe_version.note.empty() ? "No RT_VERSION resource present." : d.pe_version.note.c_str());
        ImGui::TreePop();
        return;
    }

    const peelf::PeVersionInfo& v = *d.pe_version.value;
    if (v.fixed_info.has_value()) {
        const peelf::PeFixedFileInfo& fi = *v.fixed_info;
        ImGui::Text("File Version: %s  |  Product Version: %s  |  OS: %s  |  Type: %s",
                    fi.file_version_string.c_str(),
                    fi.product_version_string.c_str(),
                    fi.decoded_file_os.c_str(),
                    fi.decoded_file_type.c_str());
        if (!fi.decoded_file_flags.empty()) {
            std::string joined;
            for (std::size_t i = 0u; i < fi.decoded_file_flags.size(); ++i) {
                if (i > 0u) joined += " | ";
                joined += fi.decoded_file_flags[i];
            }
            ImGui::TextDisabled("VS_FF_* Flags: %s", joined.c_str());
        }
    }

    const std::string_view filter(filter_buf_);
    for (const peelf::PeStringTableBlock& tbl : v.string_tables) {
        const std::string hdr = std::format(
            "StringTable {} (Lang 0x{:04X}, CodePage {})",
            tbl.language_codepage_hex,
            static_cast<unsigned int>(tbl.language_id),
            static_cast<unsigned int>(tbl.code_page));
        if (ImGui::TreeNodeEx(hdr.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
            if (ImGui::BeginTable("##ver_kv", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthStretch, 0.35f);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.65f);
                ImGui::TableHeadersRow();
                for (const auto& [k, val] : tbl.entries) {
                    if (!matches_case_insensitive(k, filter) && !matches_case_insensitive(val, filter)) {
                        continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(k.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(val.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::TreePop();
        }
    }

    for (const std::string& w : v.warnings) {
        ImGui::TextColored(ImVec4(1.00f, 0.72f, 0.28f, 1.0f), "Warning: %s", w.c_str());
    }

    ImGui::TreePop();
}

void ExecutableSettingsPanel::draw_pe_clr_block(const peelf::DeclaredSettings& d) {
    ImGui::AlignTextToFramePadding();
    const bool open = ImGui::TreeNodeEx("CLR / .NET Metadata (IMAGE_COR20_HEADER)", ImGuiTreeNodeFlags_None);
    ImGui::SameLine();
    draw_metadata_state_badge(d.pe_clr_state);
    if (!open) {
        return;
    }

    if (!d.pe_clr.has_value()) {
        ImGui::TextDisabled("%s", d.pe_clr.note.empty() ? "Native PE binary (no CLR header)." : d.pe_clr.note.c_str());
        ImGui::TreePop();
        return;
    }

    const peelf::PeClrSummary& c = *d.pe_clr.value;
    ImGui::Text("COR20 Header v%u.%u  |  Metadata Runtime: %s  |  EntryPointToken: 0x%08X",
                static_cast<unsigned int>(c.major_runtime_version),
                static_cast<unsigned int>(c.minor_runtime_version),
                c.runtime_version_string.empty() ? "<unknown>" : c.runtime_version_string.c_str(),
                c.entry_point_token_or_rva);
    if (!c.decoded_flags.empty()) {
        std::string flags_txt;
        for (std::size_t i = 0u; i < c.decoded_flags.size(); ++i) {
            if (i > 0u) flags_txt += " | ";
            flags_txt += c.decoded_flags[i];
        }
        ImGui::BulletText("COMIMAGE_FLAGS: %s (0x%08X)", flags_txt.c_str(), c.cor20_flags);
    }
    if (!c.streams.empty() && ImGui::BeginTable("##clr_streams", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Stream");
        ImGui::TableSetupColumn("Offset");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Bounds");
        ImGui::TableHeadersRow();
        for (const peelf::PeClrStreamInfo& st : c.streams) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(st.name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%X", st.offset);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("0x%X", st.size);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(
                st.in_bounds ? ImVec4(0.38f, 0.92f, 0.56f, 1.0f) : ImVec4(1.00f, 0.42f, 0.42f, 1.0f),
                "%s",
                st.in_bounds ? "In-Bounds" : "Truncated");
        }
        ImGui::EndTable();
    }
    for (const std::string& w : c.warnings) {
        ImGui::TextColored(ImVec4(1.00f, 0.72f, 0.28f, 1.0f), "Warning: %s", w.c_str());
    }
    ImGui::TreePop();
}

void ExecutableSettingsPanel::draw_elf_settings_block(const peelf::DeclaredSettings& d) {
    ImGui::AlignTextToFramePadding();
    const bool open = ImGui::TreeNodeEx("ELF Dynamic Linker, Notes & Flags", ImGuiTreeNodeFlags_DefaultOpen);
    ImGui::SameLine();
    draw_metadata_state_badge(d.elf_settings_state);
    if (!open) {
        return;
    }

    if (!d.elf_settings.has_value()) {
        ImGui::TextDisabled("%s", d.elf_settings.note.c_str());
        ImGui::TreePop();
        return;
    }

    const peelf::ElfDeclaredSettings& e = *d.elf_settings.value;
    ImGui::BulletText("PT_INTERP: %s", e.interpreter.has_value() ? e.interpreter->c_str() : "<static / none>");
    ImGui::BulletText("GNU Build-ID: %s", e.build_id_hex.has_value() ? e.build_id_hex->c_str() : "<absent>");
    if (e.abi_tag.has_value()) {
        ImGui::BulletText(".note.ABI-tag: %s (min kernel %s)",
                          e.abi_tag->os_name.c_str(),
                          e.abi_tag->min_kernel.c_str());
    } else {
        ImGui::BulletText(".note.ABI-tag: <absent>");
    }
    if (e.soname.has_value()) {
        ImGui::BulletText("DT_SONAME: %s", e.soname->c_str());
    }
    ImGui::BulletText("Link Flags: PIE=%s  |  BIND_NOW=%s  |  NO_DLOPEN=%s  |  NO_DELETE=%s",
                      e.is_pie ? "yes" : "no",
                      e.bind_now ? "yes" : "no",
                      e.no_dlopen ? "yes" : "no",
                      e.no_delete ? "yes" : "no");

    if (!e.rpath_entries.empty()) {
        ImGui::BulletText("DT_RPATH: %s", e.raw_rpath.c_str());
    }
    if (!e.runpath_entries.empty()) {
        ImGui::BulletText("DT_RUNPATH: %s", e.raw_runpath.c_str());
    }
    for (const std::string& w : e.warnings) {
        ImGui::TextColored(ImVec4(1.00f, 0.72f, 0.28f, 1.0f), "Warning: %s", w.c_str());
    }

    ImGui::TreePop();
}

void ExecutableSettingsPanel::draw_launch_environment_section(
    const peelf::ExecutableSettingsReport& report,
    std::optional<peelf::EnvironmentRedactionPolicy>& pending_policy) {
    if (!ImGui::CollapsingHeader("2. Launch / Current Environment", ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }

    ui_provenance::draw_provenance_badge(report.launch_environment.provenance, report.launch_environment.note);
    ImGui::SameLine();
    ui_provenance::draw_capture_stamp_badge("Launch Env", report.launch_environment.stamp);

    if (!report.launch_environment.has_value()) {
        draw_unavailable_notice(
            "Launch / Current Environment",
            report.launch_environment.availability,
            report.launch_environment.note);
        return;
    }

    const peelf::LaunchEnvironmentSettings& le = *report.launch_environment.value;
    ImGui::Text("Capture Origin: %s",
                std::string(peelf::to_string(le.capture_origin)).c_str());
    if (!report.launch_environment.note.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("(%s)", report.launch_environment.note.c_str());
    }
    ImGui::Text("Executable Path: %s",
                le.executable_path.empty() ? "<unknown>" : le.executable_path.generic_string().c_str());
    ImGui::Text("Current Working Directory: %s",
                le.cwd.has_value() ? le.cwd.value->generic_string().c_str() : le.cwd.note.c_str());
    ImGui::Text("Environment Policy: %s", std::string(peelf::to_string(le.redaction_policy)).c_str());
    ImGui::SameLine();
    bool reveal_unredacted =
        (model_.environment_redaction_policy() ==
         peelf::EnvironmentRedactionPolicy::RevealUnredactedOptIn);
    if (ImGui::Checkbox("Reveal Unredacted Values (Session Opt-In)", &reveal_unredacted)) {
        pending_policy = reveal_unredacted
                             ? peelf::EnvironmentRedactionPolicy::RevealUnredactedOptIn
                             : peelf::EnvironmentRedactionPolicy::RedactSensitiveDefault;
    }

    if (le.argv.has_value() && ImGui::TreeNode("Command-Line Arguments (argv)")) {
        for (std::size_t i = 0u; i < le.argv.value->size(); ++i) {
            ImGui::BulletText("[%zu] %s", i, (*le.argv.value)[i].c_str());
        }
        ImGui::TreePop();
    }

    const std::string_view filter(filter_buf_);
    if (le.environment.has_value() && ImGui::TreeNode("Environment Variables")) {
        if (ImGui::BeginTable("##env_vars", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Variable", ImGuiTableColumnFlags_WidthStretch, 0.32f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.52f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableHeadersRow();
            for (const peelf::EnvironmentVariableEntry& ev : *le.environment.value) {
                if (!matches_case_insensitive(ev.key, filter) &&
                    !matches_case_insensitive(ev.display_value, filter)) {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(ev.key.c_str());
                ImGui::TableSetColumnIndex(1);
                if (ev.redacted) {
                    ImGui::TextColored(ImVec4(0.92f, 0.52f, 0.82f, 1.0f), "%s", ev.display_value.c_str());
                } else {
                    ImGui::TextUnformatted(ev.display_value.c_str());
                }
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%s", std::string(peelf::to_string(ev.availability)).c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }

    if (le.security_profile.has_value() && ImGui::TreeNode("Process Security Profile")) {
        const peelf::ProcessSecurityProfile& sec = *le.security_profile.value;
        if (!sec.user_summary.empty()) {
            ImGui::BulletText("User: %s", sec.user_summary.c_str());
        }
        if (!sec.group_summary.empty()) {
            ImGui::BulletText("Groups: %s", sec.group_summary.c_str());
        }
        if (!sec.integrity_or_lsm_label.empty()) {
            ImGui::BulletText("Integrity / LSM: %s", sec.integrity_or_lsm_label.c_str());
        }
        if (sec.is_elevated.has_value()) {
            ImGui::BulletText("Elevated: %s", *sec.is_elevated ? "Yes" : "No");
        }
        if (sec.no_new_privs.has_value()) {
            ImGui::BulletText("NoNewPrivs: %s", *sec.no_new_privs ? "Enabled" : "Disabled");
        }
        if (!sec.seccomp_mode.empty()) {
            ImGui::BulletText("Seccomp: %s", sec.seccomp_mode.c_str());
        }
        if (!sec.cgroup_summary.empty()) {
            ImGui::BulletText("Cgroup: %s", sec.cgroup_summary.c_str());
        }
        if (sec.cap_eff != 0u || !sec.capabilities.empty()) {
            ImGui::BulletText("Effective Capabilities Mask: 0x%016" PRIX64 " (%zu entries)",
                              sec.cap_eff,
                              sec.capabilities.size());
        }
        if (!sec.mitigations.empty()) {
            ImGui::BulletText("Active Mitigations: %zu policies", sec.mitigations.size());
        }
        ImGui::TreePop();
    }
}

void ExecutableSettingsPanel::draw_observed_runtime_section(
    const peelf::ExecutableSettingsReport& report,
    DeferredNav& pending_nav) {
    if (!ImGui::CollapsingHeader("3. Observed Runtime Configuration", ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }

    ui_provenance::draw_provenance_badge(report.observed_runtime.provenance, report.observed_runtime.note);
    ImGui::SameLine();
    ui_provenance::draw_capture_stamp_badge("Runtime", report.observed_runtime.stamp);

    if (!report.observed_runtime.has_value()) {
        draw_unavailable_notice(
            "Observed Runtime Configuration",
            report.observed_runtime.availability,
            report.observed_runtime.note);
        return;
    }

    const peelf::ObservedRuntimeConfiguration& rt = *report.observed_runtime.value;
    const std::string mod_cnt =
        rt.loaded_modules.has_value()
            ? std::to_string(rt.loaded_modules.value->size())
            : std::string(peelf::to_string(rt.loaded_modules.availability));
    const std::string hnd_cnt =
        rt.open_handles.has_value()
            ? std::to_string(rt.open_handles.value->size())
            : std::string(peelf::to_string(rt.open_handles.availability));
    const std::string sck_cnt =
        rt.sockets.has_value()
            ? std::to_string(rt.sockets.value->size())
            : std::string(peelf::to_string(rt.sockets.availability));
    ImGui::Text("Loaded Modules: %s  |  Open Handles: %s  |  Active Sockets: %s",
                mod_cnt.c_str(),
                hnd_cnt.c_str(),
                sck_cnt.c_str());

    const std::string_view filter(filter_buf_);
    if (rt.declared_vs_loaded.has_value()) {
        const peelf::DeclaredVsLoadedModuleComparison& cmp = *rt.declared_vs_loaded.value;
        ImGui::BulletText("%s", cmp.summary.c_str());
        if (!cmp.missing_declared.empty() && ImGui::TreeNode("Declared Root Imports Not Observed Loaded")) {
            for (const std::string& miss : cmp.missing_declared) {
                if (matches_case_insensitive(miss, filter)) {
                    ImGui::BulletText("%s", miss.c_str());
                }
            }
            ImGui::TreePop();
        }
        if (!cmp.unmatched_loaded.empty() && ImGui::TreeNode("Loaded Modules Not Declared in Root Imports")) {
            ImGui::TextDisabled(
                "%s",
                cmp.runtime_load_proven_by_timeline
                    ? "Includes module(s) proven newly loaded across session snapshots:"
                    : "Note: Presence in memory may reflect transitive dependencies, OS shims, or prior dynamic loads (not asserted as LoadLibrary/dlopen without timeline delta):");
            if (ImGui::BeginTable("##unmatched_mods", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch, 0.25f);
                ImGui::TableSetupColumn("Base VA", ImGuiTableColumnFlags_WidthStretch, 0.18f);
                ImGui::TableSetupColumn("Provenance Note", ImGuiTableColumnFlags_WidthStretch, 0.57f);
                ImGui::TableHeadersRow();
                for (std::size_t i = 0u; i < cmp.unmatched_loaded.size(); ++i) {
                    const peelf::UnmatchedLoadedModule& um = cmp.unmatched_loaded[i];
                    if (!matches_case_insensitive(um.module_name, filter) &&
                        !matches_case_insensitive(um.path.generic_string(), filter)) {
                        continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(um.module_name.c_str());
                    ImGui::TableSetColumnIndex(1);
                    const std::string btn = std::format("0x{:X}##um_va_{}", um.base_address, i);
                    if (um.base_address != 0u && ImGui::SmallButton(btn.c_str())) {
                        pending_nav = std::pair{um.base_address, PreferredView::Disassembly};
                    } else {
                        ImGui::Text("0x%" PRIX64, um.base_address);
                    }
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextWrapped("%s", um.provenance_note.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::TreePop();
        }
    }

    if (rt.loaded_modules.has_value() && ImGui::TreeNode("Loaded Modules")) {
        if (ImGui::BeginTable("##rt_loaded_mods", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("Base VA", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 0.14f);
            ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 0.44f);
            ImGui::TableHeadersRow();
            for (std::size_t i = 0u; i < rt.loaded_modules.value->size(); ++i) {
                const peelf::ModuleInfo& m = (*rt.loaded_modules.value)[i];
                const std::string path_str = m.path.generic_string();
                if (!matches_case_insensitive(m.name, filter) &&
                    !matches_case_insensitive(path_str, filter)) {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(m.name.c_str());
                ImGui::TableSetColumnIndex(1);
                const std::string btn = std::format("0x{:X}##lm_va_{}", m.base_address, i);
                if (m.base_address != 0u && ImGui::SmallButton(btn.c_str())) {
                    pending_nav = std::pair{m.base_address, PreferredView::Disassembly};
                } else {
                    ImGui::Text("0x%" PRIX64, m.base_address);
                }
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("0x%" PRIX64, m.size);
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(path_str.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }

    if (rt.open_handles.has_value() && ImGui::TreeNode("Open Handles / File Descriptors")) {
        if (ImGui::BeginTable("##rt_handles", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("FD / Handle", ImGuiTableColumnFlags_WidthStretch, 0.14f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 0.48f);
            ImGui::TableSetupColumn("Flags / Access", ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableHeadersRow();
            for (const peelf::ProcessHandleEntry& h : *rt.open_handles.value) {
                if (!matches_case_insensitive(h.target, filter) &&
                    !matches_case_insensitive(h.type_name, filter)) {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("0x%" PRIX64, h.handle_or_fd);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(
                    h.type_name.empty()
                        ? std::string(peelf::to_string(h.kind)).c_str()
                        : h.type_name.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(h.target.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", h.access_or_flags.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }

    if (rt.sockets.has_value() && ImGui::TreeNode("Open Sockets")) {
        if (ImGui::BeginTable("##rt_sockets", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthStretch, 0.14f);
            ImGui::TableSetupColumn("Local Endpoint", ImGuiTableColumnFlags_WidthStretch, 0.32f);
            ImGui::TableSetupColumn("Remote Endpoint", ImGuiTableColumnFlags_WidthStretch, 0.32f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableHeadersRow();
            for (const peelf::ProcessSocketEntry& s : *rt.sockets.value) {
                if (!matches_case_insensitive(s.local_endpoint, filter) &&
                    !matches_case_insensitive(s.remote_endpoint, filter) &&
                    !matches_case_insensitive(s.state, filter)) {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(std::string(peelf::to_string(s.protocol)).c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(s.local_endpoint.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(s.remote_endpoint.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(s.state.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }
}

} // namespace viewer
