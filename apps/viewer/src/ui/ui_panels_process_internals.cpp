#include "ui_panels_process_internals.hpp"
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

[[nodiscard]] ImVec4 availability_badge_color(peelf::Availability avail) noexcept {
    switch (avail) {
        case peelf::Availability::Available:   return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::Availability::Partial:     return ImVec4(1.00f, 0.78f, 0.26f, 1.0f);
        case peelf::Availability::Unavailable: return ImVec4(0.95f, 0.48f, 0.45f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

void draw_subsystem_banner(const char* label, const peelf::SubsystemStatus& st) {
    const std::string_view tag = peelf::to_string(st.availability);
    ImGui::TextColored(availability_badge_color(st.availability),
                       "[%.*s] %s%s%s%s%s",
                       static_cast<int>(tag.size()),
                       tag.data(),
                       label,
                       st.source.empty() ? "" : " (",
                       st.source.c_str(),
                       st.source.empty() ? "" : "): ",
                       st.detail.c_str());
}

[[nodiscard]] bool icontains_sv(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    }) != hay.end();
}

}  // namespace

ProcessInternalsPanel::ProcessInternalsPanel(BinaryModel& model)
    : UiPanel("Process Internals")
    , model_(model) {}

void ProcessInternalsPanel::draw_contents() {
    if (!model_.is_live_process() || model_.process_session() == nullptr) {
        ImGui::TextDisabled("Not attached to a live process.");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Attach to a running process via File > Attach to Process... to inspect open handles/file "
            "descriptors, correlated TCP/UDP/UNIX sockets, security tokens/capabilities, and OS mitigations.");
        return;
    }

    // Lazy-load on first open for the attached process.
    if (!model_.has_process_internals()) {
        model_.refresh_process_internals();
    }

    const auto& proc_info = model_.process_session()->info();
    if (ImGui::Button("Refresh")) {
        model_.refresh_process_internals();
    }
    ImGui::SameLine();
    ImGui::Text("PID %" PRIu32 " (%s)",
                proc_info.pid,
                proc_info.name.empty() ? "<process>" : proc_info.name.c_str());

    const auto& snap = model_.process_internals();
    if (snap.total_os_handle_count.has_value()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| Total OS Handles/FDs: %" PRIu32, *snap.total_os_handle_count);
    }
    ui_provenance::draw_capture_stamp_badge("Internals", model_.process_internals_stamp());

    ImGui::Separator();

    if (ImGui::BeginTabBar("ProcessInternalsTabs")) {
        if (ImGui::BeginTabItem("Handles / FDs")) {
            draw_handles_tab(snap);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sockets")) {
            draw_sockets_tab(snap);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Security & Mitigations")) {
            draw_security_tab(snap);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void ProcessInternalsPanel::draw_handles_tab(const peelf::ProcessInternalsSnapshot& snap) {
    draw_subsystem_banner("Handles / FDs", snap.handles.status);

    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##HandleFilter", "Filter target / type / flags...",
                             handle_filter_.data(), handle_filter_.size());
    ImGui::SameLine();
    static constexpr const char* kKindItems[] = {
        "All Kinds", "File", "Directory", "Socket", "Pipe",
        "AnonInode", "Device", "Memfd", "Registry", "SyncObject", "Proc/Thread",
    };
    ImGui::SetNextItemWidth(140.0f);
    ImGui::Combo("##HandleKindFilter", &handle_kind_filter_, kKindItems, IM_ARRAYSIZE(kKindItems));

    if (!snap.handles.has_value()) {
        ImGui::TextDisabled("No handle / FD entries available.");
        return;
    }

    const std::string_view q(handle_filter_.data());
    const auto matches_kind = [this](peelf::ProcessHandleKind k) noexcept {
        switch (handle_kind_filter_) {
            case 1:  return k == peelf::ProcessHandleKind::File;
            case 2:  return k == peelf::ProcessHandleKind::Directory;
            case 3:  return k == peelf::ProcessHandleKind::Socket;
            case 4:  return k == peelf::ProcessHandleKind::Pipe;
            case 5:  return k == peelf::ProcessHandleKind::AnonInode;
            case 6:  return k == peelf::ProcessHandleKind::Device;
            case 7:  return k == peelf::ProcessHandleKind::Memfd;
            case 8:  return k == peelf::ProcessHandleKind::KeyOrRegistry;
            case 9:  return k == peelf::ProcessHandleKind::SyncObject;
            case 10: return k == peelf::ProcessHandleKind::ProcessOrThread;
            default: return true;
        }
    };

    if (ImGui::BeginTable("HandlesTable",
                          6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("FD / Handle", ImGuiTableColumnFlags_WidthFixed, 88.0f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 92.0f);
        ImGui::TableSetupColumn("Access / Flags", ImGuiTableColumnFlags_WidthFixed, 175.0f);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 86.0f);
        ImGui::TableSetupColumn("Inode", ImGuiTableColumnFlags_WidthFixed, 86.0f);
        ImGui::TableSetupColumn("Target / Object", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (const auto& h : *snap.handles.value) {
            if (!matches_kind(h.kind)) {
                continue;
            }
            const std::string_view kind_sv = peelf::to_string(h.kind);
            if (!q.empty() && !icontains_sv(h.target, q) && !icontains_sv(h.type_name, q) &&
                !icontains_sv(h.access_or_flags, q) && !icontains_sv(kind_sv, q)) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, h.handle_or_fd);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(h.type_name.empty() ? kind_sv.data() : h.type_name.c_str());

            ImGui::TableNextColumn();
            if (h.access_or_flags.empty()) {
                ImGui::TextDisabled("-");
            } else {
                ImGui::TextUnformatted(h.access_or_flags.c_str());
            }

            ImGui::TableNextColumn();
            if (h.offset.has_value()) {
                ImGui::Text("0x%" PRIX64, *h.offset);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            if (h.inode.has_value()) {
                ImGui::Text("%" PRIu64, *h.inode);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(h.target.empty() ? "-" : h.target.c_str());
        }
        ImGui::EndTable();
    }
}

void ProcessInternalsPanel::draw_sockets_tab(const peelf::ProcessInternalsSnapshot& snap) {
    draw_subsystem_banner("Network & UNIX Sockets", snap.sockets.status);

    ImGui::SetNextItemWidth(260.0f);
    ImGui::InputTextWithHint("##SocketFilter", "Filter endpoint / protocol / state...",
                             socket_filter_.data(), socket_filter_.size());

    if (!snap.sockets.has_value()) {
        ImGui::TextDisabled("No socket telemetry available.");
        return;
    }

    const std::string_view q(socket_filter_.data());
    if (ImGui::BeginTable("SocketsTable",
                          6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 64.0f);
        ImGui::TableSetupColumn("FD", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 115.0f);
        ImGui::TableSetupColumn("Local Endpoint", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Remote Endpoint", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Inode", ImGuiTableColumnFlags_WidthFixed, 86.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (const auto& s : *snap.sockets.value) {
            const std::string_view proto_sv = peelf::to_string(s.protocol);
            if (!q.empty() && !icontains_sv(proto_sv, q) && !icontains_sv(s.local_endpoint, q) &&
                !icontains_sv(s.remote_endpoint, q) && !icontains_sv(s.state, q)) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(proto_sv.data(), proto_sv.data() + proto_sv.size());

            ImGui::TableNextColumn();
            if (s.fd.has_value()) {
                ImGui::Text("%" PRIu64, *s.fd);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.state.c_str());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.local_endpoint.c_str());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.remote_endpoint.c_str());

            ImGui::TableNextColumn();
            if (s.inode != 0) {
                ImGui::Text("%" PRIu64, s.inode);
            } else {
                ImGui::TextDisabled("-");
            }
        }
        ImGui::EndTable();
    }
}

void ProcessInternalsPanel::draw_security_tab(const peelf::ProcessInternalsSnapshot& snap) {
    draw_subsystem_banner("Security & Mitigations", snap.security.status);

    if (!snap.security.has_value()) {
        ImGui::TextDisabled("Security context unavailable.");
        return;
    }

    const auto& sec = *snap.security.value;
    ImGui::Text("User / UID: %s", sec.user_summary.empty() ? "-" : sec.user_summary.c_str());
    if (!sec.group_summary.empty()) {
        ImGui::Text("Groups / GID: %s", sec.group_summary.c_str());
    }
    ImGui::Text("Integrity / LSM: %s",
                sec.integrity_or_lsm_label.empty() ? "-" : sec.integrity_or_lsm_label.c_str());
    if (sec.is_elevated.has_value()) {
        ImGui::SameLine();
        ImGui::TextColored(*sec.is_elevated ? ImVec4(1.0f, 0.72f, 0.28f, 1.0f)
                                            : ImVec4(0.65f, 0.85f, 0.70f, 1.0f),
                           "| Elevated/Root: %s",
                           *sec.is_elevated ? "Yes" : "No");
    }
    if (!sec.cgroup_summary.empty()) {
        ImGui::TextWrapped("Cgroup: %s", sec.cgroup_summary.c_str());
    }

    ImGui::Spacing();
    ImGui::SeparatorText("Mitigations & Sandboxing");
    if (sec.mitigations.empty()) {
        ImGui::TextDisabled("No mitigation records reported.");
    } else if (ImGui::BeginTable("MitigationsTable",
                                 3,
                                 ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Resizable,
                                 ImVec2(0.0f, 120.0f))) {
        ImGui::TableSetupColumn("Policy", ImGuiTableColumnFlags_WidthFixed, 175.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& m : sec.mitigations) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(m.policy.c_str());
            ImGui::TableNextColumn();
            ImGui::TextColored(m.enabled ? ImVec4(0.38f, 0.92f, 0.56f, 1.0f)
                                         : ImVec4(0.82f, 0.82f, 0.82f, 1.0f),
                               "%s",
                               m.state.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(m.detail.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::SeparatorText("Capabilities / Token Privileges");
    ImGui::SetNextItemWidth(240.0f);
    ImGui::InputTextWithHint("##CapFilter", "Filter capability / privilege...",
                             cap_filter_.data(), cap_filter_.size());
    const std::string_view cq(cap_filter_.data());

    if (sec.capabilities.empty()) {
        ImGui::TextDisabled("Zero active capabilities / privileges in token.");
    } else if (ImGui::BeginTable("CapabilitiesTable",
                                 5,
                                 ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Resizable,
                                 ImVec2(0.0f, 150.0f))) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Effective / Enabled", ImGuiTableColumnFlags_WidthFixed, 125.0f);
        ImGui::TableSetupColumn("Permitted", ImGuiTableColumnFlags_WidthFixed, 82.0f);
        ImGui::TableSetupColumn("Inheritable", ImGuiTableColumnFlags_WidthFixed, 85.0f);
        ImGui::TableSetupColumn("Ambient", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableHeadersRow();
        for (const auto& c : sec.capabilities) {
            if (!cq.empty() && !icontains_sv(c.name, cq)) {
                continue;
            }
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(c.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextColored(c.effective ? ImVec4(0.38f, 0.92f, 0.56f, 1.0f)
                                           : ImVec4(0.65f, 0.65f, 0.65f, 1.0f),
                               "%s",
                               c.effective ? "Yes" : "No");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(c.permitted ? "Yes" : "No");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(c.inheritable ? "Yes" : "No");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(c.ambient ? "Yes" : "No");
        }
        ImGui::EndTable();
    }

    if (!sec.namespaces.empty()) {
        ImGui::Spacing();
        ImGui::SeparatorText("Namespaces");
        if (ImGui::BeginTable("NamespacesTable",
                              2,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_Resizable,
                              ImVec2(0.0f, 110.0f))) {
            ImGui::TableSetupColumn("Namespace", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const auto& ns : sec.namespaces) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(ns.ns_type.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(ns.ns_id.c_str());
            }
            ImGui::EndTable();
        }
    }
}

}  // namespace viewer
