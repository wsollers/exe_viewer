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
        case SelectionKind::CallGraphNode:  return "Call Graph Node";
        case SelectionKind::Patch:          return "Patch";
        case SelectionKind::ByteRange:      return "Bytes";
        case SelectionKind::Process:        return "Process";
        case SelectionKind::ProcessModule:  return "Process Module";
        case SelectionKind::MemoryRegion:   return "Memory Region";
    }
    return "Unknown";
}

[[nodiscard]] const char* preferred_view_name(PreferredView view) {
    switch (view) {
        case PreferredView::Details:     return "Details";
        case PreferredView::Hex:         return "Hex";
        case PreferredView::Disassembly: return "Disassembly";
        case PreferredView::Graph:       return "Flow Graph";
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

    ImGui::TextWrapped("%s", selection_.label.c_str());
    ImGui::TextDisabled("%s", selection_kind_name(selection_.kind));
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Location", ImGuiTreeNodeFlags_DefaultOpen)) {
        draw_optional_hex_value("File offset", selection_.file_offset);
        draw_optional_hex_value("Virtual address", selection_.virtual_address);
        ImGui::Text("Size: %" PRIu64 " bytes", selection_.size);
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
