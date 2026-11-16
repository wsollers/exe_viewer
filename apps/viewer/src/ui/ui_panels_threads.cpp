#include "ui_panels.hpp"
#include "ui_panels_capabilities.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>

namespace viewer {
namespace {

// Distinct highlight palette for Thread Stack View:
// - Return addresses: Warm Gold / Amber
// - Base / Frame pointers (active & saved chain): Electric Cyan / Teal
constexpr ImVec4 kReturnAddrTextColor(1.00f, 0.80f, 0.24f, 1.00f);
constexpr ImU32 kReturnAddrRowBg = IM_COL32(180, 125, 18, 62);

constexpr ImVec4 kFramePtrTextColor(0.24f, 0.90f, 0.98f, 1.00f);
constexpr ImU32 kFramePtrRowBg = IM_COL32(18, 138, 175, 62);

constexpr ImVec4 kStackPtrTextColor(0.55f, 0.95f, 0.62f, 1.00f);

[[nodiscard]] ImVec4 availability_color(peelf::Availability avail) noexcept {
    switch (avail) {
        case peelf::Availability::Available:   return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::Availability::Partial:     return ImVec4(1.00f, 0.78f, 0.26f, 1.0f);
        case peelf::Availability::Unavailable: return ImVec4(0.95f, 0.48f, 0.45f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

void draw_status_banner(const char* prefix, const peelf::SubsystemStatus& status) {
    const std::string_view tag = peelf::to_string(status.availability);
    ImGui::TextColored(availability_color(status.availability),
                       "[%.*s] %s%s%s",
                       static_cast<int>(tag.size()),
                       tag.data(),
                       prefix,
                       status.detail.empty() ? "" : ": ",
                       status.detail.c_str());
}

[[nodiscard]] std::string format_ptr_width(std::uint64_t val, peelf::AddressWidth width) {
    std::array<char, 32> buf{};
    if (width == peelf::AddressWidth::Bits32) {
        std::snprintf(buf.data(), buf.size(), "0x%08" PRIX32, static_cast<std::uint32_t>(val));
    } else {
        std::snprintf(buf.data(), buf.size(), "0x%016" PRIX64, val);
    }
    return buf.data();
}

[[nodiscard]] bool icontains_tls(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    }) != hay.end();
}

} // namespace

ThreadsAndStackPanel::ThreadsAndStackPanel(BinaryModel& model)
    : UiPanel("Threads & Stack")
    , model_(model) {}

void ThreadsAndStackPanel::draw_contents() {
    if (!model_.is_live_process()) {
        ImGui::TextDisabled("Not attached to a live process.");
        ImGui::Spacing();
        ImGui::TextWrapped("Attach to a running process to pause execution, pick any thread, inspect multi-architecture registers & status flags, and walk the stack with distinct highlights for return addresses vs. base/frame pointers.");
        return;
    }

    if (const peelf::CrashDumpSummary* dump = model_.crash_dump_summary(); dump != nullptr) {
        ImGui::TextColored(ImVec4(1.0f, 0.48f, 0.34f, 1.0f),
                           "[CRASH DUMP] %s",
                           std::string(peelf::to_string(dump->kind)).c_str());
        if (dump->exception.has_value()) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.28f, 1.0f),
                               "| %s",
                               dump->exception->description.c_str());
            if (dump->exception->instruction_pointer.has_value() &&
                *dump->exception->instruction_pointer != 0u &&
                on_address_activated_) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Jump to Faulting IP")) {
                    on_address_activated_(*dump->exception->instruction_pointer,
                                          PreferredView::Disassembly,
                                          false);
                }
            }
        }
        if (ImGui::Button("Refresh Threads & Context")) {
            (void)model_.refresh_threads();
            model_.refresh_selected_thread_inspection();
        }
    } else {
        const bool proc_paused = model_.is_process_suspended();
        if (ImGui::Button(proc_paused ? "Resume Process" : "Pause Process")) {
            const peelf::SubsystemStatus st = proc_paused ? model_.resume_process() : model_.suspend_process();
            status_note_ = st.detail;
        }
        ImGui::SameLine();
        if (ImGui::Button("Refresh Threads & Context")) {
            (void)model_.refresh_threads();
            model_.refresh_selected_thread_inspection();
        }
        ImGui::SameLine();
        ImGui::TextColored(proc_paused ? ImVec4(1.0f, 0.80f, 0.25f, 1.0f)
                                       : ImVec4(0.40f, 0.92f, 0.56f, 1.0f),
                           "%s",
                           proc_paused ? "[PROCESS PAUSED]" : "[PROCESS RUNNING]");
    }

    draw_status_banner("Threads", model_.threads_status());
    ui_provenance::draw_capture_stamp_badge("Threads", model_.threads_stamp());
    if (model_.selected_thread_id().has_value()) {
        ImGui::SameLine();
        ui_provenance::draw_capture_stamp_badge("Context", model_.selected_thread_stamp());
    }
    if (!status_note_.empty()) {
        ImGui::TextWrapped("%s", status_note_.c_str());
    }

    const auto& threads = model_.threads();
    const auto selected_tid = model_.selected_thread_id();
    const peelf::TargetLayout layout = model_.target_layout();

    if (ImGui::BeginTable("ThreadListTable",
                          8,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, 145.0f))) {
        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.28f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 82.0f);
        ImGui::TableSetupColumn("CPU %", ImGuiTableColumnFlags_WidthFixed, 66.0f);
        ImGui::TableSetupColumn("Start Address", ImGuiTableColumnFlags_WidthStretch, 0.34f);
        ImGui::TableSetupColumn("Wait / wchan", ImGuiTableColumnFlags_WidthStretch, 0.26f);
        ImGui::TableSetupColumn("TLS / TEB", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Control", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < threads.size(); ++i) {
            const peelf::ThreadInfo& th = threads[i];
            const bool is_sel = selected_tid && *selected_tid == th.tid;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            std::array<char, 32> tid_buf{};
            std::snprintf(tid_buf.data(), tid_buf.size(), "%" PRIu32, th.tid);
            if (ImGui::Selectable(tid_buf.data(), is_sel)) {
                model_.select_thread(th.tid);
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(th.name.empty() ? "<thread>" : th.name.c_str());

            ImGui::TableNextColumn();
            const std::string_view st_label = peelf::to_string(th.state);
            ImGui::TextUnformatted(st_label.data(), st_label.data() + st_label.size());

            ImGui::TableNextColumn();
            if (th.cpu_percent.has_value()) {
                ImGui::Text("%.1f%%", *th.cpu_percent);
            } else {
                ImGui::TextDisabled("-");
            }
            if (ImGui::IsItemHovered() && (th.user_time_ns.has_value() || th.kernel_time_ns.has_value())) {
                const double user_ms = static_cast<double>(th.user_time_ns.value_or(0)) / 1.0e6;
                const double kern_ms = static_cast<double>(th.kernel_time_ns.value_or(0)) / 1.0e6;
                ImGui::SetTooltip("User: %.2f ms | Kernel: %.2f ms", user_ms, kern_ms);
            }

            ImGui::TableNextColumn();
            if (th.start_address.has_value() && *th.start_address != 0) {
                const std::string start_hex = format_ptr_width(*th.start_address, layout.address_width);
                const std::string sym = model_.resolve_address_symbol(*th.start_address);
                const std::string label = sym.empty() ? start_hex : (sym + " (" + start_hex + ")");
                if (ImGui::SmallButton(label.c_str())) {
                    if (on_address_activated_) {
                        on_address_activated_(*th.start_address, PreferredView::Disassembly, false);
                    }
                }
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            if (!th.wait_channel.empty()) {
                ImGui::TextUnformatted(th.wait_channel.c_str());
            } else if (th.syscall_number.has_value() && *th.syscall_number >= 0) {
                ImGui::Text("syscall #%" PRId64, *th.syscall_number);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            const std::optional<std::uint64_t> tls_or_teb =
                th.teb_address.has_value() ? th.teb_address : th.tls_base;
            if (tls_or_teb.has_value() && *tls_or_teb != 0) {
                const std::string formatted = format_ptr_width(*tls_or_teb, layout.address_width);
                ImGui::TextUnformatted(formatted.c_str());
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            const bool th_stopped = th.state == peelf::ThreadRunState::Stopped;
            if (ImGui::SmallButton(th_stopped ? "Resume" : "Pause")) {
                const peelf::SubsystemStatus tst =
                    th_stopped ? model_.resume_thread(th.tid) : model_.suspend_thread(th.tid);
                status_note_ = tst.detail;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Separator();

    const auto& ctx_fv = model_.selected_thread_context();
    const auto& stack_snap = model_.selected_thread_stack();

    if (ImGui::BeginTabBar("ThreadContextAndStackTabs")) {
        if (ImGui::BeginTabItem("Stack View (Highlighted)")) {
            draw_status_banner("Stack", stack_snap.status);

            // Explicit color legend for return addresses vs. base/frame pointers
            ImGui::TextColored(kReturnAddrTextColor, "[Return Address]");
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::TextColored(kFramePtrTextColor, "[Base / Frame Pointer (FP/BP)]");
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::TextColored(kStackPtrTextColor, "[Stack Top (SP)]");
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::TextDisabled("Endian: %s (%u-bit)",
                                std::string(peelf::to_string(stack_snap.layout.endianness)).c_str(),
                                static_cast<unsigned>(stack_snap.layout.pointer_size() * 8u));

            if (ImGui::BeginTable("StackSlotsTable",
                                  4,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Stack Address", ImGuiTableColumnFlags_WidthFixed, 132.0f);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 138.0f);
                ImGui::TableSetupColumn("Role", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                ImGui::TableSetupColumn("Symbol / Annotation", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(stack_snap.slots.size()));
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const peelf::StackSlotEntry& slot = stack_snap.slots[static_cast<std::size_t>(row)];
                        ImGui::TableNextRow();

                        const bool is_ret = slot.role == peelf::StackSlotRole::ReturnAddress;
                        const bool is_fp = slot.role == peelf::StackSlotRole::ActiveFramePointer ||
                                           slot.role == peelf::StackSlotRole::SavedFramePointer;
                        const bool is_sp = slot.role == peelf::StackSlotRole::StackPointerTop;

                        if (is_ret) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, kReturnAddrRowBg);
                        } else if (is_fp) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, kFramePtrRowBg);
                        }

                        ImGui::TableNextColumn();
                        ImGui::PushID(row);
                        const std::string saddr = format_ptr_width(slot.slot_address, stack_snap.layout.address_width);
                        if (is_sp) {
                            ImGui::TextColored(kStackPtrTextColor, "%s <- SP", saddr.c_str());
                        } else {
                            ImGui::TextUnformatted(saddr.c_str());
                        }

                        ImGui::TableNextColumn();
                        const std::string val_str = format_ptr_width(slot.value, stack_snap.layout.address_width);
                        int pushed = 0;
                        if (is_ret) {
                            ImGui::PushStyleColor(ImGuiCol_Text, kReturnAddrTextColor);
                            ++pushed;
                        } else if (is_fp) {
                            ImGui::PushStyleColor(ImGuiCol_Text, kFramePtrTextColor);
                            ++pushed;
                        }
                        if (ImGui::Selectable(val_str.c_str(),
                                              false,
                                              ImGuiSelectableFlags_AllowDoubleClick)) {
                            if (on_address_activated_) {
                                const PreferredView pv = is_ret ? PreferredView::Disassembly : PreferredView::Hex;
                                const bool want_dec = is_ret && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
                                on_address_activated_(slot.value, pv, want_dec);
                            }
                        }
                        if (pushed > 0) {
                            ImGui::PopStyleColor(pushed);
                        }

                        ImGui::TableNextColumn();
                        const std::string_view role_sv = peelf::to_string(slot.role);
                        if (is_ret) {
                            ImGui::TextColored(kReturnAddrTextColor,
                                               "%.*s",
                                               static_cast<int>(role_sv.size()),
                                               role_sv.data());
                        } else if (is_fp) {
                            ImGui::TextColored(kFramePtrTextColor,
                                               "%.*s",
                                               static_cast<int>(role_sv.size()),
                                               role_sv.data());
                        } else {
                            ImGui::TextDisabled("%.*s", static_cast<int>(role_sv.size()), role_sv.data());
                        }

                        ImGui::TableNextColumn();
                        std::string detail = slot.resolved_symbol;
                        if (!slot.annotation.empty()) {
                            if (!detail.empty()) {
                                detail += "  |  ";
                            }
                            detail += slot.annotation;
                        }
                        if (is_ret) {
                            ImGui::TextColored(kReturnAddrTextColor, "%s", detail.empty() ? "<return target>" : detail.c_str());
                        } else if (is_fp) {
                            ImGui::TextColored(kFramePtrTextColor, "%s", detail.empty() ? "<frame link>" : detail.c_str());
                        } else if (!detail.empty()) {
                            ImGui::TextUnformatted(detail.c_str());
                        } else {
                            ImGui::TextDisabled("-");
                        }
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Call Frames")) {
            draw_status_banner("Unwind", stack_snap.status);
            if (ImGui::BeginTable("CallFramesTable",
                                  6,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 34.0f);
                ImGui::TableSetupColumn("Instruction (PC)", ImGuiTableColumnFlags_WidthFixed, 134.0f);
                ImGui::TableSetupColumn("Stack (SP)", ImGuiTableColumnFlags_WidthFixed, 134.0f);
                ImGui::TableSetupColumn("Frame (FP/BP)", ImGuiTableColumnFlags_WidthFixed, 134.0f);
                ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 105.0f);
                ImGui::TableHeadersRow();

                for (const peelf::StackFrame& fr : stack_snap.frames) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("#%zu", fr.index);

                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(fr.index));
                    const std::string pc_str = format_ptr_width(fr.instruction_pointer, stack_snap.layout.address_width);
                    ImGui::PushStyleColor(ImGuiCol_Text, kReturnAddrTextColor);
                    if (ImGui::Selectable(pc_str.c_str(),
                                          false,
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                        if (on_address_activated_) {
                            on_address_activated_(fr.instruction_pointer,
                                                  PreferredView::Disassembly,
                                                  ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left));
                        }
                    }
                    ImGui::PopStyleColor();
                    ImGui::PopID();

                    ImGui::TableNextColumn();
                    const std::string sp_str = format_ptr_width(fr.stack_pointer, stack_snap.layout.address_width);
                    ImGui::TextUnformatted(sp_str.c_str());

                    ImGui::TableNextColumn();
                    if (fr.frame_pointer != 0) {
                        const std::string fp_str = format_ptr_width(fr.frame_pointer, stack_snap.layout.address_width);
                        ImGui::TextColored(kFramePtrTextColor, "%s", fp_str.c_str());
                    } else {
                        ImGui::TextDisabled("-");
                    }

                    ImGui::TableNextColumn();
                    if (!fr.symbol_name.empty()) {
                        if (fr.symbol_offset != 0) {
                            ImGui::Text("%s+0x%" PRIX64, fr.symbol_name.c_str(), fr.symbol_offset);
                        } else {
                            ImGui::TextUnformatted(fr.symbol_name.c_str());
                        }
                    } else {
                        ImGui::TextUnformatted("<unknown>");
                    }

                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", fr.unwind_method.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Registers & Flags")) {
            draw_status_banner("Registers", ctx_fv.status);
            const peelf::ThreadContext empty_ctx{};
            const peelf::ThreadContext& ctx = ctx_fv.value.has_value() ? *ctx_fv.value : empty_ctx;
            ImGui::TextDisabled("Arch: %s (%u-bit, %s)",
                                std::string(peelf::to_string(ctx.layout.architecture)).c_str(),
                                static_cast<unsigned>(ctx.layout.address_width == peelf::AddressWidth::Bits32 ? 32u : 64u),
                                std::string(peelf::to_string(ctx.layout.endianness)).c_str());

            if (!ctx.decoded_flags.empty()) {
                ImGui::TextDisabled("Flags:");
                for (const peelf::FlagBitInfo& fb : ctx.decoded_flags) {
                    ImGui::SameLine();
                    ImGui::TextColored(fb.set ? ImVec4(0.40f, 0.95f, 0.58f, 1.0f)
                                              : ImVec4(0.52f, 0.54f, 0.58f, 1.0f),
                                       "[%s=%d]",
                                       fb.name.c_str(),
                                       fb.set ? 1 : 0);
                    if (ImGui::IsItemHovered() && !fb.description.empty()) {
                        ImGui::SetTooltip("%s", fb.description.c_str());
                    }
                }
            }

            if (ImGui::BeginTable("RegistersTable",
                                  4,
                                  ImGuiTableFlags_Borders |
                                      ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 86.0f);
                ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 86.0f);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 146.0f);
                ImGui::TableSetupColumn("Resolved Target", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (std::size_t i = 0; i < ctx.registers.size(); ++i) {
                    const peelf::RegisterValue& rv = ctx.registers[i];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(rv.name.c_str());

                    ImGui::TableNextColumn();
                    const std::string_view cat = peelf::to_string(rv.category);
                    ImGui::TextDisabled("%.*s", static_cast<int>(cat.size()), cat.data());

                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(i));
                    std::string vstr = !rv.formatted.empty()
                        ? rv.formatted
                        : format_ptr_width(rv.value_u64, rv.bit_width <= 32 ? peelf::AddressWidth::Bits32 : peelf::AddressWidth::Bits64);
                    if (ImGui::Selectable(vstr.c_str()) && rv.value_u64 != 0 && on_address_activated_) {
                        const PreferredView pv =
                            rv.category == peelf::RegisterCategory::InstructionPointer
                                ? PreferredView::Disassembly
                                : PreferredView::Hex;
                        on_address_activated_(rv.value_u64, pv, false);
                    }
                    ImGui::PopID();

                    ImGui::TableNextColumn();
                    const std::string sym = model_.resolve_address_symbol(rv.value_u64);
                    if (!sym.empty()) {
                        ImGui::TextUnformatted(sym.c_str());
                    } else {
                        ImGui::TextDisabled("-");
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

ThreadLocalsPanel::ThreadLocalsPanel(BinaryModel& model)
    : UiPanel("Thread Locals")
    , model_(model) {}

void ThreadLocalsPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to inspect Thread-Local Storage (TLS).");
        return;
    }

    const peelf::ThreadLocalSnapshot& tls = model_.selected_thread_locals();
    const peelf::TargetLayout layout = model_.target_layout();

    if (model_.is_live_process()) {
        draw_status_banner("Live TLS", tls.status);
        if (ImGui::SmallButton("Refresh TLS")) {
            model_.refresh_selected_thread_inspection();
        }
        ImGui::SameLine();
        if (const auto tid = model_.selected_thread_id()) {
            ImGui::TextDisabled("Selected TID: %u", *tid);
        }
    } else if (const peelf::IBinaryImage* img = model_.image()) {
        // Static file mode: compute static TLS template & variables on demand.
        const std::string static_mod_name = model_.file_info().path.empty()
            ? std::string{}
            : std::filesystem::path(model_.file_info().path).filename().string();
        const peelf::ThreadLocalSnapshot static_tls = peelf::inspect_thread_locals(
            img,
            model_.analysis_image_bytes(),
            nullptr,
            nullptr,
            {},
            static_mod_name);
        draw_status_banner("Static TLS", static_tls.status);
        const std::string_view model_sv = peelf::to_string(static_tls.model);
        ImGui::Text("TLS Model: %.*s  |  Template VA: %s  |  Init: 0x%" PRIX64 "  |  Zero-Fill: 0x%" PRIX64,
                    static_cast<int>(model_sv.size()),
                    model_sv.data(),
                    format_ptr_width(static_tls.template_start_va, layout.address_width).c_str(),
                    static_tls.template_raw_size,
                    static_tls.template_zero_fill_size);
        ImGui::Separator();
        if (static_tls.variables.empty()) {
            ImGui::TextDisabled("No STT_TLS symbols or PE TLS template variables found in this static image.");
            return;
        }
        if (ImGui::BeginTable("StaticTlsVarsTable",
                              4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("TLS Offset", ImGuiTableColumnFlags_WidthFixed, 96.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 68.0f);
            ImGui::TableSetupColumn("Initial Value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const peelf::TlsVariableEntry& v : static_tls.variables) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(v.name.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("0x%" PRIX64, v.template_offset);
                ImGui::TableNextColumn();
                ImGui::Text("%" PRIu64, v.size);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(v.decoded_value.empty() ? "-" : v.decoded_value.c_str());
            }
            ImGui::EndTable();
        }
        return;
    }

    const std::string_view model_sv = peelf::to_string(tls.model);
    const std::string tp_str = tls.thread_pointer.has_value()
        ? format_ptr_width(*tls.thread_pointer, layout.address_width)
        : std::string("-");
    const std::string blk_str = tls.tls_block_address.has_value()
        ? format_ptr_width(*tls.tls_block_address, layout.address_width)
        : std::string("-");
    ImGui::Text("Model: %.*s  |  Thread Ptr: %s  |  Block Base: %s",
                static_cast<int>(model_sv.size()),
                model_sv.data(),
                tp_str.c_str(),
                blk_str.c_str());
    ImGui::TextDisabled("Template VA: %s  |  Init: 0x%" PRIX64 "  |  Zero-Fill: 0x%" PRIX64,
                        tls.template_start_va != 0 ? format_ptr_width(tls.template_start_va, layout.address_width).c_str() : "-",
                        tls.template_raw_size,
                        tls.template_zero_fill_size);

    ImGui::InputTextWithHint("##TlsFilter", "Filter thread-local variable...", filter_buf_, sizeof(filter_buf_));
    const std::string_view filter(filter_buf_);

    if (!tls.variables.empty() &&
        ImGui::BeginTable("LiveTlsVarsTable",
                          5,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, tls.pe_slots.empty() ? 0.0f : 200.0f))) {
        ImGui::TableSetupColumn("Variable", ImGuiTableColumnFlags_WidthStretch, 0.36f);
        ImGui::TableSetupColumn("TLS Off", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Live VA", ImGuiTableColumnFlags_WidthFixed, 134.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 62.0f);
        ImGui::TableSetupColumn("Decoded Value", ImGuiTableColumnFlags_WidthStretch, 0.44f);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < tls.variables.size(); ++i) {
            const peelf::TlsVariableEntry& v = tls.variables[i];
            if (!filter.empty() && !icontains_tls(v.name, filter) && !icontains_tls(v.decoded_value, filter)) {
                continue;
            }
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(v.name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("0x%" PRIX64, v.template_offset);

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (v.live_address.has_value()) {
                const std::string lva = format_ptr_width(*v.live_address, layout.address_width);
                if (ImGui::Selectable(lva.c_str()) && on_address_activated_) {
                    on_address_activated_(*v.live_address, PreferredView::Hex);
                }
            } else {
                ImGui::TextDisabled("<static only>");
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, v.size);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(v.decoded_value.empty() ? "-" : v.decoded_value.c_str());
        }
        ImGui::EndTable();
    } else if (tls.variables.empty()) {
        ImGui::TextDisabled("No thread-local variables discovered for the active module.");
    }

    if (!tls.pe_slots.empty() && ImGui::CollapsingHeader("Win32 TEB TlsSlots / TlsExpansionSlots", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("PeTlsSlotsTable",
                              3,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Slot", ImGuiTableColumnFlags_WidthFixed, 92.0f);
            ImGui::TableSetupColumn("Slot VA", ImGuiTableColumnFlags_WidthFixed, 134.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const peelf::PeTlsSlotEntry& s : tls.pe_slots) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%s[%u]", s.expansion_slot ? "Expansion" : "TlsSlots", s.slot_index);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_ptr_width(s.slot_address, layout.address_width).c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_ptr_width(s.value, layout.address_width).c_str());
            }
            ImGui::EndTable();
        }
    }
}

} // namespace viewer
