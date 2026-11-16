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

[[nodiscard]] ImVec4 provenance_tag_color(peelf::ProvenanceTag tag) noexcept {
    switch (tag) {
        case peelf::ProvenanceTag::DiskFile:
            return ImVec4(0.45f, 0.78f, 1.00f, 1.0f);
        case peelf::ProvenanceTag::DebugSymbols:
            return ImVec4(0.76f, 0.58f, 1.00f, 1.0f);
        case peelf::ProvenanceTag::LiveMemory:
            return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::ProvenanceTag::ProcOrOsApi:
            return ImVec4(0.42f, 0.88f, 0.84f, 1.0f);
        case peelf::ProvenanceTag::CrashDump:
            return ImVec4(1.00f, 0.56f, 0.38f, 1.0f);
        case peelf::ProvenanceTag::HeuristicInference:
            return ImVec4(1.00f, 0.78f, 0.28f, 1.0f);
        case peelf::ProvenanceTag::DebuggerShadowed:
            return ImVec4(0.95f, 0.50f, 0.72f, 1.0f);
        case peelf::ProvenanceTag::UserAnnotated:
            return ImVec4(0.62f, 0.90f, 0.42f, 1.0f);
        case peelf::ProvenanceTag::DecompilerSynthesized:
            return ImVec4(0.84f, 0.72f, 0.98f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

[[nodiscard]] ImVec4 capture_avail_color(peelf::CaptureAvailability avail) noexcept {
    switch (avail) {
        case peelf::CaptureAvailability::Complete:
            return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::CaptureAvailability::Partial:
            return ImVec4(1.00f, 0.78f, 0.28f, 1.0f);
        case peelf::CaptureAvailability::Stale:
            return ImVec4(1.00f, 0.58f, 0.24f, 1.0f);
        case peelf::CaptureAvailability::Unavailable:
            return ImVec4(0.70f, 0.70f, 0.74f, 1.0f);
        case peelf::CaptureAvailability::Redacted:
            return ImVec4(0.92f, 0.52f, 0.82f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

[[nodiscard]] ImVec4 support_state_color(peelf::SupportState state) noexcept {
    switch (state) {
        case peelf::SupportState::SupportedValidated:
            return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::SupportState::SupportedExperimental:
            return ImVec4(0.48f, 0.80f, 1.00f, 1.0f);
        case peelf::SupportState::Partial:
            return ImVec4(1.00f, 0.78f, 0.28f, 1.0f);
        case peelf::SupportState::Unsupported:
            return ImVec4(0.95f, 0.45f, 0.45f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

[[nodiscard]] bool icontains_cap(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    }) != hay.end();
}

}  // namespace

namespace ui_provenance {

void draw_provenance_badge(peelf::ProvenanceTag tag, std::string_view detail) {
    const std::string_view name = peelf::to_string(tag);
    ImGui::TextColored(provenance_tag_color(tag),
                       "[%.*s]",
                       static_cast<int>(name.size()),
                       name.data());
    if (!detail.empty() && ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%.*s: %.*s",
                          static_cast<int>(name.size()),
                          name.data(),
                          static_cast<int>(detail.size()),
                          detail.data());
    }
}

void draw_evidence_badges(std::span<const peelf::Evidence> evidence) {
    for (std::size_t i = 0; i < evidence.size(); ++i) {
        if (i > 0u) {
            ImGui::SameLine(0.0f, 4.0f);
            ImGui::TextDisabled("+");
            ImGui::SameLine(0.0f, 4.0f);
        }
        draw_provenance_badge(evidence[i].tag, evidence[i].detail);
    }
}

void draw_capture_stamp_badge(std::string_view collection_label, const peelf::CaptureStamp& stamp) {
    const std::string_view avail = peelf::to_string(stamp.availability);
    if (stamp.snapshot_revision == 0u && stamp.captured_at_utc.empty()) {
        ImGui::TextColored(capture_avail_color(stamp.availability),
                           "[%.*s: %.*s]",
                           static_cast<int>(collection_label.size()),
                           collection_label.data(),
                           static_cast<int>(avail.size()),
                           avail.data());
        return;
    }
    ImGui::TextColored(capture_avail_color(stamp.availability),
                       "[%.*s: %.*s | rev #%" PRIu64 " | %s | %s]",
                       static_cast<int>(collection_label.size()),
                       collection_label.data(),
                       static_cast<int>(avail.size()),
                       avail.data(),
                       stamp.snapshot_revision,
                       stamp.captured_at_utc.empty() ? "-" : stamp.captured_at_utc.c_str(),
                       stamp.target_paused ? "paused" : "running");
}

void draw_backing_identity_banner(const peelf::BackingIdentityMatchResult& match) {
    if (match.summary.empty()) {
        return;
    }
    if (match.has_mismatch()) {
        ImGui::TextColored(ImVec4(1.00f, 0.36f, 0.36f, 1.0f),
                           "[IDENTITY MISMATCH] %s",
                           match.summary.c_str());
    } else if (match.comparable && match.matches) {
        ImGui::TextColored(ImVec4(0.38f, 0.92f, 0.56f, 1.0f),
                           "[IDENTITY VERIFIED] %s (%s)",
                           match.summary.c_str(),
                           match.live_identifier.c_str());
    } else {
        ImGui::TextDisabled("[Identity Unverified] %s", match.summary.c_str());
    }
}

void draw_capability_state_badge(const peelf::Capability& cap) {
    const std::string_view st = peelf::to_string(cap.state);
    ImGui::TextColored(support_state_color(cap.state),
                       "%.*s",
                       static_cast<int>(st.size()),
                       st.data());
    if (ImGui::IsItemHovered() && !cap.reason.empty()) {
        ImGui::SetTooltip("%s", cap.reason.c_str());
    }
}

}  // namespace ui_provenance

CapabilityMatrixPanel::CapabilityMatrixPanel(BinaryModel& model)
    : UiPanel("Target Capabilities")
    , model_(model) {}

void CapabilityMatrixPanel::draw_contents() {
    const peelf::TargetProfile& prof = model_.target_profile();
    const peelf::TargetInstanceId& tid = model_.target_instance_id();
    const peelf::TargetCapabilityMatrix& mat = model_.capability_matrix();

    if (ImGui::CollapsingHeader("Target Profile & Instance Identity", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("TargetProfileTable",
                              2,
                              ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Attribute", ImGuiTableColumnFlags_WidthFixed, 170.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

            const auto row = [](const char* k, std::string_view v) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", k);
                ImGui::TableNextColumn();
                ImGui::Text("%.*s", static_cast<int>(v.size()), v.data());
            };

            row("Format", peelf::to_string(prof.format));
            row("Architecture", peelf::to_string(prof.architecture));
            row("Endianness", peelf::to_string(prof.endianness));
            row("Address Width",
                prof.address_width == peelf::AddressWidth::Bits64 ? "64-bit" : "32-bit");
            row("ABI", peelf::to_string(prof.abi));
            row("Operating System", peelf::to_string(prof.os));
            row("Backend Session", peelf::to_string(prof.backend));

            if (tid.pid != 0u) {
                const std::string pid_str = tid.creation_identity.has_value()
                    ? std::format("{} (creation_id={})", tid.pid, *tid.creation_identity)
                    : std::format("{} (creation_id=unavailable)", tid.pid);
                row("Process Instance", pid_str);
            }
            if (!tid.image_sha256.empty()) {
                row("Image SHA-256", tid.image_sha256);
            }
            if (!tid.build_id_or_pdb_guid.empty()) {
                row("Build ID / PDB GUID", tid.build_id_or_pdb_guid);
            }
            ImGui::EndTable();
        }
        if (model_.is_live_process()) {
            ui_provenance::draw_backing_identity_banner(model_.backing_identity_status());
        }
    }

    if (ImGui::CollapsingHeader("Per-Collection Capture Stamps", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("CollectionStampsTable",
                              5,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Collection", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Availability", ImGuiTableColumnFlags_WidthFixed, 105.0f);
            ImGui::TableSetupColumn("Rev", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Captured At (UTC)", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            const auto stamp_row = [](const char* label, const peelf::CaptureStamp& st) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(label);
                ImGui::TableNextColumn();
                const std::string_view av = peelf::to_string(st.availability);
                ImGui::TextColored(capture_avail_color(st.availability),
                                   "%.*s",
                                   static_cast<int>(av.size()),
                                   av.data());
                ImGui::TableNextColumn();
                if (st.snapshot_revision > 0u) {
                    ImGui::Text("#%" PRIu64, st.snapshot_revision);
                } else {
                    ImGui::TextDisabled("-");
                }
                ImGui::TableNextColumn();
                if (st.snapshot_revision > 0u) {
                    ImGui::TextUnformatted(st.target_paused ? "Paused" : "Running");
                } else {
                    ImGui::TextDisabled("-");
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(
                    st.captured_at_utc.empty() ? "-" : st.captured_at_utc.c_str());
            };

            stamp_row("Static Image", model_.static_image_stamp());
            stamp_row("Memory Map", model_.memory_map_stamp());
            stamp_row("Thread List", model_.threads_stamp());
            stamp_row("Selected Thread", model_.selected_thread_stamp());
            stamp_row("Runtime & Flags", model_.runtime_stamp());
            stamp_row("Process Internals", model_.process_internals_stamp());
            ImGui::EndTable();
        }
    }

    ImGui::Separator();
    ImGui::SetNextItemWidth(185.0f);
    ImGui::Combo("State##CapStateFilter",
                 &state_filter_,
                 "All Operations\0Validated Only\0Experimental / Partial\0Unsupported Only\0");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##CapSearchFilter",
                             "Filter operation or support rationale...",
                             filter_buf_,
                             sizeof(filter_buf_));
    const std::string_view q(filter_buf_);

    if (ImGui::BeginTable("CapabilityMatrixTable",
                          4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Operation", ImGuiTableColumnFlags_WidthFixed, 195.0f);
        ImGui::TableSetupColumn("Validated Support", ImGuiTableColumnFlags_WidthFixed, 155.0f);
        ImGui::TableSetupColumn("Provider Present", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Rationale", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const peelf::Capability& cap : mat.entries()) {
            if (state_filter_ == 1 && cap.state != peelf::SupportState::SupportedValidated) {
                continue;
            }
            if (state_filter_ == 2 &&
                cap.state != peelf::SupportState::SupportedExperimental &&
                cap.state != peelf::SupportState::Partial) {
                continue;
            }
            if (state_filter_ == 3 && cap.state != peelf::SupportState::Unsupported) {
                continue;
            }

            const std::string_view op_name = peelf::to_string(cap.operation);
            if (!icontains_cap(op_name, q) && !icontains_cap(cap.reason, q)) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%.*s", static_cast<int>(op_name.size()), op_name.data());

            ImGui::TableNextColumn();
            ui_provenance::draw_capability_state_badge(cap);

            ImGui::TableNextColumn();
            ImGui::TextColored(cap.provider_available ? ImVec4(0.38f, 0.92f, 0.56f, 1.0f)
                                                      : ImVec4(0.95f, 0.45f, 0.45f, 1.0f),
                               "%s",
                               cap.provider_available ? "Available" : "Missing");

            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", cap.reason.c_str());
        }
        ImGui::EndTable();
    }
}

}  // namespace viewer
