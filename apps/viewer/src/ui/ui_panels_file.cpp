#include "ui_panels.hpp"
#include "ui_panels_capabilities.hpp"
#include <imgui.h>
#include <cinttypes>
#include <format>

namespace viewer {

    FilePanel::FilePanel(BinaryModel& model)
        : UiPanel("File Info")
        , model_(model)
    {}

    void FilePanel::draw_contents() {
        if (!model_.has_file()) {
            ImGui::TextUnformatted("No file or live process loaded.");
            ImGui::Separator();
            ImGui::TextWrapped("Open a PE/ELF/Mach-O file from disk or attach to a running process to inspect memory and symbols.");
            if (on_attach_requested_ && ImGui::Button("Attach to Process...")) {
                on_attach_requested_();
            }
            return;
        }

        if (model_.is_live_process()) {
            if (const peelf::IProcessSession* sess = model_.process_session()) {
                if (const peelf::CrashDumpSummary* dump = model_.crash_dump_summary(); dump != nullptr) {
                    ImGui::TextColored(ImVec4(1.0f, 0.50f, 0.36f, 1.0f),
                                       "[CRASH DUMP] %s (PID %" PRIu64 ") — %s",
                                       sess->info().name.empty() ? "<dump>" : sess->info().name.c_str(),
                                       static_cast<std::uint64_t>(sess->pid()),
                                       std::string(peelf::to_string(dump->kind)).c_str());
                    if (dump->exception.has_value()) {
                        ImGui::TextColored(ImVec4(1.0f, 0.78f, 0.30f, 1.0f),
                                           "Fault: %s",
                                           dump->exception->description.c_str());
                    }
                    if (!dump->os_summary.empty() || !dump->cpu_summary.empty()) {
                        ImGui::TextDisabled("%s | %s",
                                            dump->os_summary.c_str(),
                                            dump->cpu_summary.c_str());
                    }
                    if (ImGui::SmallButton("Close Dump")) {
                        if (on_detach_requested_) {
                            on_detach_requested_();
                        }
                    }
                } else {
                    const bool paused = model_.is_process_suspended();
                    ImGui::TextColored(paused ? ImVec4(1.0f, 0.78f, 0.25f, 1.0f)
                                              : ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
                                       "%s LIVE PROCESS: %s (PID %" PRIu64 ") [Read-Only]",
                                       paused ? "[PAUSED]" : "[RUNNING]",
                                       sess->info().name.empty() ? "<process>" : sess->info().name.c_str(),
                                       static_cast<std::uint64_t>(sess->pid()));
                    if (ImGui::SmallButton(paused ? "Resume Process" : "Pause Process")) {
                        if (on_pause_toggle_) {
                            on_pause_toggle_();
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Refresh Map")) {
                        if (on_refresh_requested_) {
                            on_refresh_requested_();
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Switch Process...")) {
                        if (on_attach_requested_) {
                            on_attach_requested_();
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Detach")) {
                        if (on_detach_requested_) {
                            on_detach_requested_();
                        }
                    }
                }
                if (model_.resolved_executable_path()) {
                    ImGui::TextDisabled("Backing binary: %s",
                                        model_.resolved_executable_path()->string().c_str());
                }
                ui_provenance::draw_backing_identity_banner(model_.backing_identity_status());
                ui_provenance::draw_capture_stamp_badge("Map", model_.memory_map_stamp());
                ImGui::Separator();
            }
        } else {
            ui_provenance::draw_capture_stamp_badge("StaticFile", model_.static_image_stamp());
            const peelf::BinaryContainerInfo& container = model_.container_info();
            if (container.is_universal_container && !container.slices.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.42f, 0.84f, 0.98f, 1.0f),
                                   "[UNIVERSAL MACH-O] %zu architecture slices",
                                   container.slices.size());

                const auto format_slice_item = [](const peelf::BinarySliceDescriptor& sl) {
                    const std::string_view arch_label =
                        sl.arch_name.empty() ? peelf::to_string(sl.arch) : std::string_view(sl.arch_name);
                    return std::format("#{} — {} ({}-bit {}, off 0x{:X}, {} B)",
                                       sl.slice_index,
                                       arch_label,
                                       sl.bitness,
                                       peelf::to_string(sl.endianness),
                                       sl.container_offset,
                                       sl.slice_size);
                };

                const std::size_t active_idx =
                    model_.active_slice_index() < container.slices.size()
                        ? model_.active_slice_index()
                        : 0u;
                const std::string preview = format_slice_item(container.slices[active_idx]);

                ImGui::AlignTextToFramePadding();
                ImGui::TextDisabled("Active slice:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(-1.0f);
                if (ImGui::BeginCombo("##UniversalSliceSelector", preview.c_str())) {
                    for (std::size_t i = 0u; i < container.slices.size(); ++i) {
                        const bool is_selected = (i == active_idx);
                        const std::string label = format_slice_item(container.slices[i]);
                        if (ImGui::Selectable(label.c_str(), is_selected)) {
                            if (!is_selected && on_slice_selected_) {
                                on_slice_selected_(i);
                            }
                        }
                        if (is_selected) {
                            ImGui::SetItemDefaultFocus();
                        }
                    }
                    ImGui::EndCombo();
                }
            }
            ImGui::Separator();
        }

        const auto& info = model_.file_info();

        if (ImGui::CollapsingHeader("Image properties", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (ImGui::BeginTable("ImageProperties", 2, ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                const auto row = [](const char* label, const std::string& value) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", label);
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(value.c_str());
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", value.c_str());
                };
                row("Path", info.path);
                row("Format", info.format_str);
                row("Architecture", info.arch_str);
                if (!model_.is_live_process() && model_.container_info().is_universal_container &&
                    model_.active_slice_index() < model_.container_info().slices.size()) {
                    const peelf::BinarySliceDescriptor& sl =
                        model_.container_info().slices[model_.active_slice_index()];
                    row("Slice range",
                        std::format("offset 0x{:X} .. 0x{:X} ({} bytes, align 2^{})",
                                    sl.container_offset,
                                    sl.container_offset + sl.slice_size,
                                    sl.slice_size,
                                    sl.align_log2));
                }
                row("Size", std::format("{} bytes", info.size_bytes));
                row("Window base", std::format("0x{:X}", model_.view_base_address()));
                row("Entry point", std::format("0x{:X}", info.entry_point));
                ImGui::EndTable();
            }
        }

        if (!info.flags.empty() && ImGui::CollapsingHeader("Image flags", ImGuiTreeNodeFlags_DefaultOpen)) {
            for (const auto& f : info.flags) {
                ImGui::BulletText("%s", f.c_str());
            }
        }
    }

} // namespace viewer
