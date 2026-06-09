#include "ui_panels.hpp"

#include <cinttypes>
#include <cstdint>

#include <imgui.h>

namespace viewer {
namespace {

[[nodiscard]] const char* selection_kind_name(SelectionKind kind) {
    switch (kind) {
        case SelectionKind::None:           return "None";
        case SelectionKind::Image:          return "Image";
        case SelectionKind::Header:         return "Header";
        case SelectionKind::Section:        return "Section";
        case SelectionKind::Segment:        return "Segment";
        case SelectionKind::Import:         return "Import";
        case SelectionKind::Export:         return "Export";
        case SelectionKind::Symbol:         return "Symbol";
        case SelectionKind::Relocation:     return "Relocation";
        case SelectionKind::DebugDirectory: return "Debug Directory";
        case SelectionKind::RuntimeFunction:return "Runtime Function";
        case SelectionKind::TlsDirectory:   return "TLS Directory";
        case SelectionKind::Certificate:    return "Certificate";
        case SelectionKind::LoadConfig:     return "Load Config";
        case SelectionKind::BoundImport:    return "Bound Import";
        case SelectionKind::ResourceDirectory:return "Resource Directory";
        case SelectionKind::ResourceData:   return "Resource Data";
        case SelectionKind::ClrHeader:      return "CLR Header";
        case SelectionKind::DynamicEntry:   return "Dynamic Entry";
        case SelectionKind::Note:           return "Note";
        case SelectionKind::HashTable:      return "Hash Table";
        case SelectionKind::Interpreter:    return "Interpreter";
        case SelectionKind::Group:          return "Group";
    }
    return "Unknown";
}

[[nodiscard]] const char* preferred_view_name(PreferredView view) {
    switch (view) {
        case PreferredView::Details:     return "Details";
        case PreferredView::Hex:         return "Hex";
        case PreferredView::Disassembly: return "Disassembly";
    }
    return "Details";
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
                                                 ViewerSelection& selection)
    : UiPanel("Structure")
    , tree_(tree)
    , selection_(selection)
{}

void StructureNavigatorPanel::draw_contents() {
    if (!tree_) {
        ImGui::TextUnformatted("No image loaded.");
        return;
    }

    ImGui::BeginChild("StructureTree", ImVec2(0.0f, 0.0f), false);
    draw_node(*tree_);
    ImGui::EndChild();
}

void StructureNavigatorPanel::draw_node(const StructureNode& node) {
    ImGui::PushID(static_cast<const void*>(&node));
    ImGui::PushID(selection_kind_name(node.selection.kind));
    ImGui::PushID(node.selection.label.c_str());

    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_OpenOnDoubleClick |
                               ImGuiTreeNodeFlags_SpanAvailWidth;
    if (node.children.empty()) {
        flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    }
    if (same_selection(selection_, node.selection)) {
        flags |= ImGuiTreeNodeFlags_Selected;
    }

    const bool open = ImGui::TreeNodeEx(node.selection.label.c_str(), flags);
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
        selection_ = node.selection;
    }

    if (open && !node.children.empty()) {
        for (const StructureNode& child : node.children) {
            draw_node(child);
        }
        ImGui::TreePop();
    }

    ImGui::PopID();
    ImGui::PopID();
    ImGui::PopID();
}

SelectionDetailsPanel::SelectionDetailsPanel(const ViewerSelection& selection)
    : UiPanel("Details")
    , selection_(selection)
{}

void SelectionDetailsPanel::draw_contents() {
    if (selection_.kind == SelectionKind::None) {
        ImGui::TextUnformatted("No selection.");
        return;
    }

    ImGui::Text("Kind: %s", selection_kind_name(selection_.kind));
    ImGui::Text("Label: %s", selection_.label.c_str());
    ImGui::Text("Preferred view: %s", preferred_view_name(selection_.preferred_view));
    ImGui::Separator();

    draw_optional_hex_value("File offset", selection_.file_offset);
    draw_optional_hex_value("Virtual address", selection_.virtual_address);
    ImGui::Text("Size: 0x%016" PRIX64, selection_.size);
    ImGui::Text("Object index: %" PRIu64, selection_.object_index);
}

} // namespace viewer
