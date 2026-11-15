#include "ui_panels.hpp"

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

[[nodiscard]] bool icontains(std::string_view haystack, std::string_view needle) {
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

[[nodiscard]] ImVec4 protection_color(const peelf::MemoryProtection& p) noexcept {
    if (p.executable && p.writable) {
        return ImVec4(1.0f, 0.45f, 0.35f, 1.0f);  // RWX: high-attention coral
    }
    if (p.executable) {
        return ImVec4(0.45f, 0.85f, 1.0f, 1.0f);  // RX: code cyan
    }
    if (p.writable) {
        return ImVec4(0.50f, 0.92f, 0.58f, 1.0f);  // RW: data green
    }
    if (p.readable) {
        return ImVec4(0.82f, 0.84f, 0.90f, 1.0f);  // R--: rodata light gray
    }
    return ImVec4(0.45f, 0.45f, 0.48f, 1.0f);      // ---: guard page dim
}

[[nodiscard]] std::string format_size_short(std::uint64_t bytes) {
    std::array<char, 32> buf{};
    constexpr std::uint64_t kKiB = 1024u;
    constexpr std::uint64_t kMiB = 1024u * 1024u;
    if (bytes >= kMiB && (bytes % kMiB) == 0) {
        std::snprintf(buf.data(), buf.size(), "%" PRIu64 " MiB", bytes / kMiB);
    } else if (bytes >= kKiB && (bytes % kKiB) == 0) {
        std::snprintf(buf.data(), buf.size(), "%" PRIu64 " KiB", bytes / kKiB);
    } else {
        std::snprintf(buf.data(), buf.size(), "0x%" PRIX64, bytes);
    }
    return buf.data();
}

} // namespace

MemoryMapPanel::MemoryMapPanel(BinaryModel& model, ViewerSelection& selection)
    : UiPanel("Memory Map")
    , model_(model)
    , selection_(selection)
{
    filter_buf_[0] = '\0';
}

void MemoryMapPanel::draw_contents() {
    if (!model_.is_live_process()) {
        ImGui::TextDisabled("Not attached to a running process.");
        ImGui::Spacing();
        ImGui::TextWrapped("Attach to a running process (strictly read-only) to explore its virtual memory map, resolve executable paths and symbols, disassemble & decompile live code regions, pause threads, inspect highlighted stack frames & TLS, search heaps, and examine PEB/TEB/auxv & handlers.");
        ImGui::Spacing();
        if (on_attach_requested_ && ImGui::Button("Attach to Process...")) {
            on_attach_requested_();
        }
        return;
    }

    const peelf::IProcessSession* sess = model_.process_session();
    const auto& regions = model_.memory_regions();
    const auto& modules = model_.process_modules();

    if (sess != nullptr) {
        const bool alive = sess->is_alive();
        const bool paused = model_.is_process_suspended();
        ImGui::TextColored(!alive ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f)
                                  : (paused ? ImVec4(1.0f, 0.78f, 0.25f, 1.0f)
                                            : ImVec4(0.35f, 0.90f, 0.55f, 1.0f)),
                           "%s PID %llu: %s (%s, Read-Only)",
                           !alive ? "[EXITED]" : (paused ? "[PAUSED]" : "[LIVE]"),
                           static_cast<unsigned long long>(sess->pid()),
                           sess->info().name.empty() ? "<process>" : sess->info().name.c_str(),
                           std::string(peelf::to_string(sess->info().architecture)).c_str());
    }

    if (ImGui::SmallButton(model_.is_process_suspended() ? "Resume" : "Pause")) {
        if (on_pause_toggle_) {
            on_pause_toggle_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {
        if (on_refresh_requested_) {
            on_refresh_requested_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Attach Other...")) {
        if (on_attach_requested_) {
            on_attach_requested_();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Detach")) {
        if (on_detach_requested_) {
            on_detach_requested_();
        }
        return;
    }

    // Active Module selector combo
    if (!modules.empty()) {
        const std::optional<std::size_t> active_mod = model_.active_module_index();
        std::string preview = "<Standalone Memory Region>";
        if (active_mod && *active_mod < modules.size()) {
            const auto& m = modules[*active_mod];
            const std::string mod_display = m.name.empty() ? m.path.string() : m.name;
            std::array<char, 256> pbuf{};
            std::snprintf(pbuf.data(),
                          pbuf.size(),
                          "%s @ 0x%" PRIX64 " (%s)",
                          mod_display.c_str(),
                          m.base_address,
                          format_size_short(m.size).c_str());
            preview = pbuf.data();
        }

        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::BeginCombo("##ActiveModuleCombo", preview.c_str())) {
            for (std::size_t i = 0; i < modules.size(); ++i) {
                const auto& m = modules[i];
                const std::string mod_display = m.name.empty() ? m.path.string() : m.name;
                std::array<char, 320> item_label{};
                std::snprintf(item_label.data(),
                              item_label.size(),
                              "%s%s @ 0x%" PRIX64 " (%s)##mod%zu",
                              m.is_main_module ? "[main] " : "",
                              mod_display.c_str(),
                              m.base_address,
                              format_size_short(m.size).c_str(),
                              i);
                const bool is_sel = active_mod && *active_mod == i;
                if (ImGui::Selectable(item_label.data(), is_sel)) {
                    if (on_module_selected_) {
                        on_module_selected_(i);
                    }
                }
                if (is_sel) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
    }

    ImGui::InputTextWithHint("Filter", "Address, module, [heap], [stack]...", filter_buf_, sizeof(filter_buf_));
    ImGui::Checkbox("Exec", &filter_exec_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Write", &filter_writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Modules", &filter_modules_only_);
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu regions, %zu modules)", regions.size(), modules.size());

    if (!model_.last_diagnostic().empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.72f, 0.30f, 1.0f),
                           "Note: %s",
                           model_.last_diagnostic().c_str());
    }

    ImGui::Separator();

    const std::string_view filter(filter_buf_);
    const std::optional<std::size_t> active_region = model_.active_region_index();

    if (ImGui::BeginTable("MemMapTable",
                          7,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Start VA", ImGuiTableColumnFlags_WidthFixed, 128.0f);
        ImGui::TableSetupColumn("End VA", ImGuiTableColumnFlags_WidthFixed, 128.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupColumn("Perms", ImGuiTableColumnFlags_WidthFixed, 52.0f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("File Off", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupColumn("Module / Mapping", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < regions.size(); ++i) {
            const peelf::MemoryRegion& reg = regions[i];
            if (filter_exec_only_ && !reg.protection.executable) {
                continue;
            }
            if (filter_writable_only_ && !reg.protection.writable) {
                continue;
            }
            if (filter_modules_only_ &&
                reg.kind != peelf::MemoryRegionKind::Image &&
                reg.kind != peelf::MemoryRegionKind::Vdso) {
                continue;
            }

            std::array<char, 40> start_hex{};
            std::snprintf(start_hex.data(), start_hex.size(), "0x%016" PRIX64, reg.start_address);
            const std::string_view kind_str = peelf::to_string(reg.kind);
            if (!filter.empty() &&
                !icontains(start_hex.data(), filter) &&
                !icontains(reg.pathname, filter) &&
                !icontains(kind_str, filter)) {
                continue;
            }

            const bool is_selected =
                (active_region && *active_region == i) ||
                (selection_.kind == SelectionKind::MemoryRegion &&
                 selection_.object_index == static_cast<std::uint64_t>(i));

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(start_hex.data(),
                                  is_selected,
                                  ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                if (on_region_activated_) {
                    on_region_activated_(i, true);
                }
            }
            if (ImGui::BeginPopupContextItem("MemMapRowCtx")) {
                if (ImGui::MenuItem("Inspect (with Module Symbols if applicable)")) {
                    if (on_region_activated_) {
                        on_region_activated_(i, true);
                    }
                }
                if (ImGui::MenuItem("Inspect Standalone Region Window Only")) {
                    if (on_region_activated_) {
                        on_region_activated_(i, false);
                    }
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::Text("0x%016" PRIX64, reg.end_address);

            ImGui::TableNextColumn();
            const std::string sz_str = format_size_short(reg.size());
            ImGui::TextUnformatted(sz_str.c_str());

            ImGui::TableNextColumn();
            const std::string perms = peelf::format_protection(reg.protection);
            ImGui::TextColored(protection_color(reg.protection), "%s", perms.c_str());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(kind_str.data(), kind_str.data() + kind_str.size());

            ImGui::TableNextColumn();
            if (reg.file_offset != 0 || !reg.pathname.empty()) {
                ImGui::Text("0x%" PRIX64, reg.file_offset);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            if (!reg.pathname.empty()) {
                ImGui::TextUnformatted(reg.pathname.c_str());
            } else {
                ImGui::TextDisabled("<anonymous>");
            }
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
