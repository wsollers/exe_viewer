//
// Created by wsoll on 12/23/2025.
//
#include "ui_panels.hpp"
#include <imgui.h>

#include <cinttypes>
#include <limits>

namespace viewer {
namespace {

void draw_permissions(bool readable, bool writable, bool executable) {
    char perms[4];
    perms[0] = readable ? 'R' : '-';
    perms[1] = writable ? 'W' : '-';
    perms[2] = executable ? 'X' : '-';
    perms[3] = '\0';
    ImGui::TextUnformatted(perms);
}

} // namespace

    SectionsPanel::SectionsPanel(BinaryModel& model)
        : UiPanel("Sections"), model_(model)
    {
        filter_buf_[0] = '\0';
    }

    void SectionsPanel::draw_contents() {
        const peelf::IBinaryImage* img = model_.image();
        if (!img || img->sections().empty()) {
            ImGui::TextUnformatted("No sections.");
            return;
        }

        ImGui::InputTextWithHint("Filter", "Name...", filter_buf_, sizeof(filter_buf_));
        std::string filter = filter_buf_;
        bool has_filter = !filter.empty();

        std::optional<PendingEntityContextAction> pending_ctx_action;
        ImGui::Separator();
        ImGui::BeginChild("SectionsList", ImVec2(0,0), false);

        ImGui::Columns(4, nullptr, true);
        ImGui::Text("Name"); ImGui::NextColumn();
        ImGui::Text("Address"); ImGui::NextColumn();
        ImGui::Text("Size"); ImGui::NextColumn();
        ImGui::Text("Perm"); ImGui::NextColumn();
        ImGui::Separator();

        std::uint64_t section_index = 0;
        for (const auto& s : img->sections()) {
            if (has_filter && s.name.find(filter) == std::string::npos)
            {
                ++section_index;
                continue;
            }

            const std::uint64_t range_size = s.file_size != 0 ? s.file_size : s.virtual_size;
            const bool can_navigate =
                (s.file_size != 0 || s.virtual_size != 0) &&
                range_size <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max());

            ImGui::PushID(static_cast<int>(section_index));
            if (ImGui::Selectable(s.name.empty() ? "<unnamed>" : s.name.c_str(),
                                  false,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                if (can_navigate && on_section_activated_) {
                    on_section_activated_(s, section_index);
                }
            }
            draw_inspectable_entity_context_menu(
                "SectionRowCtx",
                model_,
                pending_ctx_action,
                [&]() -> InspectableEntity {
                    const bool static_img = model_has_static_image(model_);
                    std::string perms;
                    perms.push_back(s.readable ? 'R' : '-');
                    perms.push_back(s.writable ? 'W' : '-');
                    perms.push_back(s.executable ? 'X' : '-');
                    return InspectableEntity{
                        .va = s.virtual_address != 0
                            ? std::optional<std::uint64_t>(s.virtual_address)
                            : std::nullopt,
                        .file_offset = (static_img && s.file_size != 0)
                            ? std::optional<std::uint64_t>(s.file_offset)
                            : std::nullopt,
                        .size = range_size,
                        .symbol_or_label = s.name,
                        .module_name = model_.file_info().path,
                        .extra_json_fields = {
                            {"kind", "section"},
                            {"permissions", std::move(perms)},
                        },
                    };
                });
            ImGui::PopID();
            ImGui::NextColumn();
            ImGui::Text("0x%" PRIX64, s.virtual_address); ImGui::NextColumn();
            ImGui::Text("0x%" PRIX64, s.virtual_size); ImGui::NextColumn();
            draw_permissions(s.readable, s.writable, s.executable); ImGui::NextColumn();
            ++section_index;
        }

        ImGui::Columns(1);

        if (!img->segments().empty()) {
            ImGui::SeparatorText("Segments");
            ImGui::Columns(5, nullptr, true);
            ImGui::Text("Type"); ImGui::NextColumn();
            ImGui::Text("Address"); ImGui::NextColumn();
            ImGui::Text("Mem Size"); ImGui::NextColumn();
            ImGui::Text("File Off"); ImGui::NextColumn();
            ImGui::Text("Perm"); ImGui::NextColumn();
            ImGui::Separator();

            for (const auto& segment : img->segments()) {
                ImGui::Text("0x%X", segment.type); ImGui::NextColumn();
                ImGui::Text("0x%" PRIX64, segment.virtual_address); ImGui::NextColumn();
                ImGui::Text("0x%" PRIX64, segment.virtual_size); ImGui::NextColumn();
                ImGui::Text("0x%" PRIX64, segment.file_offset); ImGui::NextColumn();
                draw_permissions(segment.readable, segment.writable, segment.executable); ImGui::NextColumn();
            }
            ImGui::Columns(1);
        }

        ImGui::EndChild();
        if (pending_ctx_action.has_value() && on_context_action_) {
            on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
        }
    }

} // namespace viewer
