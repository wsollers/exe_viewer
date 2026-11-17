//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>
#include <format>

namespace viewer {

    DisassemblyPanel::DisassemblyPanel(BinaryModel& model, std::vector<Instruction>& instructions)
        : UiPanel("Disassembly"), current_instructions_(instructions), model_(model)
    {}

    void DisassemblyPanel::draw_contents() {

        if (current_instructions_.empty()) {
            ImGui::TextUnformatted("No data loaded.");
            return;
        }

        ImGui::BeginChild("InstructionsScroll", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);

        const std::optional<std::uint64_t> active_ip =
            (model_.debug_session() != nullptr &&
             model_.debug_session()->state() == peelf::debugger::DebugSessionState::Paused)
                ? std::optional<std::uint64_t>(model_.debug_session()->stop_status().instruction_pointer)
                : std::nullopt;

        std::optional<PendingEntityContextAction> pending_ctx_action;
        if (ImGui::BeginTable("Instructions", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
            for (const char* column : {"BP", "Address", "Bytes", "Mnemonic", "Operands", "Comment"}) ImGui::TableSetupColumn(column);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(current_instructions_.size()));
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& instruction = current_instructions_[static_cast<std::size_t>(row)];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    const auto* bp = model_.find_breakpoint_at(instruction.address);
                    const bool is_ip = active_ip.has_value() && *active_ip == instruction.address;
                    if (bp != nullptr && bp->enabled) {
                        ImGui::TextColored(ImVec4(0.95f, 0.28f, 0.28f, 1.0f), "●");
                    }
                    if (is_ip) {
                        if (bp != nullptr && bp->enabled) ImGui::SameLine(0.0f, 2.0f);
                        ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.98f, 1.0f), "▶");
                    }
                    ImGui::TableNextColumn();
                    ImGui::PushID(row);
                    const std::string addr_str = std::format("{:016X}", instruction.address);
                    (void)ImGui::Selectable(addr_str.c_str(), false);
                    draw_inspectable_entity_context_menu(
                        "DisasmPanelRowCtx",
                        model_,
                        pending_ctx_action,
                        [&]() -> InspectableEntity {
                            const bool static_img = model_has_static_image(model_);
                            return InspectableEntity{
                                .va = instruction.address,
                                .file_offset = static_img
                                    ? model_.virtual_address_to_offset(instruction.address)
                                    : std::nullopt,
                                .size = instruction.bytes.size(),
                                .symbol_or_label = instruction.to_string(),
                                .module_name = model_.file_info().path,
                                .extra_json_fields = {
                                    {"mnemonic", instruction.mnemonic},
                                    {"operands", instruction.operands},
                                },
                            };
                        });
                    ImGui::PopID();
                    ImGui::TableNextColumn();
                    std::string bytes;
                    for (auto byte : instruction.bytes) bytes += std::format("{:02X} ", byte);
                    ImGui::TextUnformatted(bytes.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.mnemonic.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.operands.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(instruction.comment.c_str());
                }
            }
            ImGui::EndTable();
        }

        ImGui::EndChild();
        if (pending_ctx_action.has_value() && on_context_action_) {
            on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
        }
    }

} // namespace viewer
