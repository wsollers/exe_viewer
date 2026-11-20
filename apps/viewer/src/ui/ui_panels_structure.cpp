#include "ui_panels.hpp"
#include "panel_helpers.hpp"
#include "ui_panels_capabilities.hpp"

#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <imgui.h>

namespace viewer {
namespace {

[[nodiscard]] const char* selection_kind_name(SelectionKind kind) {
    switch (kind) {
        case SelectionKind::None:             return "None";
        case SelectionKind::Image:            return "Image";
        case SelectionKind::Header:           return "Header";
        case SelectionKind::Section:          return "Section";
        case SelectionKind::Segment:          return "Segment";
        case SelectionKind::Import:           return "Import";
        case SelectionKind::Export:           return "Export";
        case SelectionKind::Symbol:           return "Symbol";
        case SelectionKind::Relocation:       return "Relocation";
        case SelectionKind::DebugDirectory:   return "Debug Directory";
        case SelectionKind::RuntimeFunction:  return "Runtime Function";
        case SelectionKind::TlsDirectory:     return "TLS Directory";
        case SelectionKind::Certificate:      return "Certificate";
        case SelectionKind::LoadConfig:       return "Load Config";
        case SelectionKind::BoundImport:      return "Bound Import";
        case SelectionKind::ResourceDirectory:return "Resource Directory";
        case SelectionKind::ResourceData:     return "Resource Data";
        case SelectionKind::ClrHeader:        return "CLR Header";
        case SelectionKind::DynamicEntry:     return "Dynamic Entry";
        case SelectionKind::Note:             return "Note";
        case SelectionKind::HashTable:        return "Hash Table";
        case SelectionKind::Interpreter:      return "Interpreter";
        case SelectionKind::Group:            return "Group";
        case SelectionKind::CallGraphNode:    return "Call Graph Node";
        case SelectionKind::Patch:            return "Patch";
        case SelectionKind::ByteRange:        return "Bytes";
        case SelectionKind::Process:          return "Process";
        case SelectionKind::ProcessModule:    return "Process Module";
        case SelectionKind::MemoryRegion:     return "Memory Region";
        case SelectionKind::ProcessThread:    return "Process Thread";
        case SelectionKind::ProcessHandle:    return "Handle / FD";
        case SelectionKind::SecurityFinding:  return "Security Finding";
    }
    return "Unknown";
}

[[nodiscard]] ImVec4 structure_badge_color(SelectionKind kind) noexcept {
    switch (kind) {
        case SelectionKind::Image:
        case SelectionKind::Process:
            return ImVec4(0.45f, 0.84f, 1.00f, 1.0f);
        case SelectionKind::Header:
        case SelectionKind::ClrHeader:
        case SelectionKind::Interpreter:
            return ImVec4(0.76f, 0.72f, 0.98f, 1.0f);
        case SelectionKind::Section:
        case SelectionKind::Segment:
        case SelectionKind::MemoryRegion:
            return ImVec4(0.48f, 0.90f, 0.64f, 1.0f);
        case SelectionKind::Import:
        case SelectionKind::BoundImport:
            return ImVec4(0.98f, 0.74f, 0.38f, 1.0f);
        case SelectionKind::Export:
        case SelectionKind::Symbol:
        case SelectionKind::CallGraphNode:
            return ImVec4(0.96f, 0.86f, 0.42f, 1.0f);
        case SelectionKind::DebugDirectory:
        case SelectionKind::TlsDirectory:
        case SelectionKind::LoadConfig:
        case SelectionKind::Certificate:
        case SelectionKind::DynamicEntry:
        case SelectionKind::Note:
        case SelectionKind::Relocation:
        case SelectionKind::RuntimeFunction:
        case SelectionKind::ResourceDirectory:
        case SelectionKind::ResourceData:
        case SelectionKind::HashTable:
            return ImVec4(0.58f, 0.80f, 0.94f, 1.0f);
        case SelectionKind::ProcessModule:
        case SelectionKind::ProcessThread:
        case SelectionKind::ProcessHandle:
            return ImVec4(0.42f, 0.88f, 0.86f, 1.0f);
        case SelectionKind::SecurityFinding:
        case SelectionKind::Patch:
            return ImVec4(1.00f, 0.52f, 0.46f, 1.0f);
        case SelectionKind::Group:
        case SelectionKind::ByteRange:
        case SelectionKind::None:
            return ImVec4(0.62f, 0.66f, 0.72f, 1.0f);
    }
    return ImVec4(0.62f, 0.66f, 0.72f, 1.0f);
}

[[nodiscard]] bool same_selection(const ViewerSelection& lhs, const ViewerSelection& rhs) {
    return lhs.kind == rhs.kind &&
           lhs.object_index == rhs.object_index &&
           lhs.label == rhs.label;
}

void draw_optional_hex_value(const char* label, const std::optional<std::uint64_t>& value) {
    if (value) {
        ImGui::Text("%s: 0x%016" PRIX64, label, *value);
    } else {
        ImGui::Text("%s: -", label);
    }
}

} // namespace

StructureNavigatorPanel::StructureNavigatorPanel(const std::optional<StructureNode>& tree,
                                                 ViewerSelection& selection,
                                                 BinaryModel* model,
                                                 NavigationRequestQueue* navigation_queue,
                                                 EntityContextActionCallback on_context_action)
    : UiPanel("Structure")
    , tree_(tree)
    , selection_(selection)
    , model_(model)
    , navigation_queue_(navigation_queue)
    , on_context_action_(std::move(on_context_action))
{}

void StructureNavigatorPanel::draw_contents() {
    if (!tree_) {
        ImGui::TextUnformatted("No image loaded.");
        return;
    }

    const std::string_view raw_query(filter_buf_);
    bool has_query = false;
    for (const char ch : raw_query) {
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            has_query = true;
            break;
        }
    }

    std::optional<StructureNode> filtered_tree{};
    std::size_t match_count = 0u;
    if (has_query) {
        match_count = count_structure_tree_matches(*tree_, raw_query);
        filtered_tree = filter_structure_tree(*tree_, raw_query);
    }

    const float clear_width = ImGui::CalcTextSize("Clear").x + ImGui::GetStyle().FramePadding.x * 2.0f + 6.0f;
    const float input_width = ImGui::GetContentRegionAvail().x - (has_query ? clear_width : 0.0f);
    ImGui::SetNextItemWidth(input_width > 80.0f ? input_width : 80.0f);
    ImGui::InputTextWithHint("##StructureFilter",
                             "Filter label, kind, VA, offset...",
                             filter_buf_,
                             sizeof(filter_buf_));
    if (has_query) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear")) {
            std::memset(filter_buf_, 0, sizeof(filter_buf_));
            has_query = false;
            filtered_tree.reset();
            match_count = 0u;
        }
        ImGui::TextDisabled("%zu matching node%s", match_count, match_count == 1u ? "" : "s");
    }
    ImGui::Separator();

    std::optional<ViewerSelection> pending_activation{};
    std::optional<PendingEntityContextAction> pending_ctx_action{};

    ImGui::BeginChild("StructureTree", ImVec2(0.0f, 0.0f), false);
    if (has_query) {
        if (filtered_tree.has_value()) {
            draw_node(*filtered_tree, true, pending_activation, pending_ctx_action);
        } else {
            ImGui::TextDisabled("No structure nodes match \"%s\".", filter_buf_);
        }
    } else {
        draw_node(*tree_, false, pending_activation, pending_ctx_action);
    }
    ImGui::EndChild();

    if (pending_activation.has_value() && navigation_queue_ != nullptr) {
        (void)enqueue_structure_selection_activation(*navigation_queue_, *pending_activation, model_);
    }
    if (pending_ctx_action.has_value() && on_context_action_) {
        on_context_action_(pending_ctx_action->kind, pending_ctx_action->entity);
    }
}

void StructureNavigatorPanel::draw_node(
    const StructureNode& node,
    bool force_expand,
    std::optional<ViewerSelection>& pending_activation,
    std::optional<PendingEntityContextAction>& pending_ctx_action) {
    ImGui::PushID(static_cast<int>(node.selection.kind));
    ImGui::PushID(static_cast<int>(node.selection.object_index & 0x7FFFFFFFu));
    ImGui::PushID(node.selection.label.c_str());

    if (force_expand && !node.children.empty()) {
        ImGui::SetNextItemOpen(true, ImGuiCond_Always);
    }

    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_SpanAvailWidth |
                               ImGuiTreeNodeFlags_AllowOverlap;
    if (node.selection.kind == SelectionKind::Group && !node.children.empty()) {
        flags |= ImGuiTreeNodeFlags_OpenOnDoubleClick;
    }
    if (node.children.empty()) {
        flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    }
    if (same_selection(selection_, node.selection)) {
        flags |= ImGuiTreeNodeFlags_Selected;
    }

    const float text_x = ImGui::GetCursorPosX() + ImGui::GetTreeNodeToLabelSpacing();
    const bool open = ImGui::TreeNodeEx("##node", flags);
    const bool toggled_open = ImGui::IsItemToggledOpen();
    const bool left_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) && !toggled_open;
    const bool double_clicked = ImGui::IsItemHovered() &&
                                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                                !toggled_open;
    const bool enter_pressed = ImGui::IsItemFocused() &&
                               (ImGui::IsKeyPressed(ImGuiKey_Enter) ||
                                ImGui::IsKeyPressed(ImGuiKey_KeypadEnter));

    if (model_ != nullptr &&
        node.selection.kind != SelectionKind::None &&
        node.selection.kind != SelectionKind::Group) {
        draw_inspectable_entity_context_menu(
            "##StructureNodeCtx",
            *model_,
            pending_ctx_action,
            [this, &node]() {
                return build_inspectable_entity_from_selection(node.selection, model_);
            });
    }

    ImGui::SameLine();
    ImGui::SetCursorPosX(text_x);
    const std::string_view badge = structure_node_badge(node.selection.kind);
    if (!badge.empty()) {
        ImGui::TextColored(structure_badge_color(node.selection.kind),
                           "%.*s",
                           static_cast<int>(badge.size()),
                           badge.data());
        ImGui::SameLine(0.0f, 5.0f);
    }
    const std::string clean_label = sanitize_single_line_control_chars(node.selection.label);
    ImGui::TextUnformatted(clean_label.c_str());

    if (left_clicked || double_clicked || enter_pressed) {
        selection_ = node.selection;
    }
    if ((double_clicked || enter_pressed) && node.selection.kind != SelectionKind::Group) {
        pending_activation = node.selection;
    }

    if (open && !node.children.empty()) {
        for (const StructureNode& child : node.children) {
            draw_node(child, force_expand, pending_activation, pending_ctx_action);
        }
        ImGui::TreePop();
    }

    ImGui::PopID();
    ImGui::PopID();
    ImGui::PopID();
}

SelectionDetailsPanel::SelectionDetailsPanel(const ViewerSelection& selection, const BinaryModel* model)
    : UiPanel("Details")
    , selection_(selection)
    , model_(model)
{}

void SelectionDetailsPanel::draw_contents() {
    if (model_ != nullptr && model_->is_crash_dump()) {
        if (const peelf::CrashDumpSummary* dump = model_->crash_dump_summary(); dump != nullptr) {
            ImGui::TextColored(ImVec4(1.0f, 0.48f, 0.34f, 1.0f),
                               "[CRASH DUMP] %s",
                               std::string(peelf::to_string(dump->kind)).c_str());
            if (dump->exception.has_value()) {
                ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.28f, 1.0f),
                                   "%s",
                                   dump->exception->description.c_str());
            }
            ImGui::Separator();
        }
    }

    if (selection_.kind == SelectionKind::None) {
        ImGui::TextUnformatted("No selection.");
        return;
    }

    const std::string_view badge = structure_node_badge(selection_.kind);
    if (!badge.empty()) {
        ImGui::TextColored(structure_badge_color(selection_.kind),
                           "%.*s",
                           static_cast<int>(badge.size()),
                           badge.data());
        ImGui::SameLine(0.0f, 6.0f);
    }
    ImGui::TextWrapped("%s", selection_.label.c_str());
    ImGui::TextDisabled("%s", selection_kind_name(selection_.kind));
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Location", ImGuiTreeNodeFlags_DefaultOpen)) {
        draw_optional_hex_value("File offset", selection_.file_offset);
        draw_optional_hex_value("Virtual address", selection_.virtual_address);
        ImGui::Text("Size: %" PRIu64 " bytes", selection_.size);
    }
    if (model_ != nullptr) {
        const std::vector<DetailPropertyRow> props =
            build_selection_detail_properties(selection_, *model_);
        if (!props.empty() &&
            ImGui::CollapsingHeader("Properties", ImGuiTreeNodeFlags_DefaultOpen)) {
            constexpr ImGuiTableFlags kPropTableFlags =
                ImGuiTableFlags_BordersInnerH |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_Resizable;
            if (ImGui::BeginTable("##SelectionDetailProps", 2, kPropTableFlags)) {
                ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthStretch, 0.38f);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.62f);
                for (const DetailPropertyRow& row : props) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", row.key.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextWrapped("%s", row.value.c_str());
                }
                ImGui::EndTable();
            }
        }
    }
    if (model_ != nullptr && selection_.virtual_address.has_value()) {
        const std::uint64_t va = *selection_.virtual_address;
        const SymbolRecord* sym = model_->symbol_index().find_containing_address(va);
        const SourceLineMapping* src = model_->find_source_line(va, 64);
        if ((sym != nullptr && sym->virtual_address.has_value()) || src != nullptr) {
            if (ImGui::CollapsingHeader("Symbol & Debug Info", ImGuiTreeNodeFlags_DefaultOpen)) {
                if (sym != nullptr && sym->virtual_address.has_value()) {
                    const std::string& raw = !sym->raw_name.empty() ? sym->raw_name : sym->name;
                    const std::string& demangled = sym->display_name(true);
                    const std::uint64_t delta = va - *sym->virtual_address;
                    if (demangled != raw) {
                        ImGui::TextWrapped("Demangled: %s", demangled.c_str());
                        ImGui::TextWrapped("Raw mangled: %s", raw.c_str());
                    } else {
                        ImGui::TextWrapped("Symbol: %s", raw.c_str());
                    }
                    if (delta != 0) {
                        ImGui::Text("Symbol offset: +0x%" PRIX64, delta);
                    }
                    if (!sym->library.empty()) {
                        ImGui::TextWrapped("Unit / Library: %s", sym->library.c_str());
                    }
                    const auto resolved = model_->resolve_symbol_with_provenance(va);
                    if (!resolved.evidence.empty()) {
                        ImGui::TextDisabled("Provenance:");
                        ImGui::SameLine();
                        ui_provenance::draw_evidence_badges(resolved.evidence);
                    }
                    ui_provenance::draw_capture_stamp_badge("SymbolStamp", resolved.stamp);
                    if (!resolved.note.empty()) {
                        ImGui::TextColored(ImVec4(1.00f, 0.72f, 0.28f, 1.0f),
                                           "Note: %s",
                                           resolved.note.c_str());
                    }
                }
                if (src != nullptr) {
                    if (src->column != 0) {
                        ImGui::TextWrapped("Source: %s:%u:%u", src->file_path.c_str(), src->line, src->column);
                    } else {
                        ImGui::TextWrapped("Source: %s:%u", src->file_path.c_str(), src->line);
                    }
                }
            }
        }
    }
}

} // namespace viewer
