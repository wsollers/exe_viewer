#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "graph/call_graph.hpp"
#include "graph/layout_edit.hpp"
#include "logger.hpp"

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {
using detail::clamp_to_size_t;
using detail::same_selection;


struct GraphLayoutBounds {
    double min_x = 0.0;
    double min_y = 0.0;
    double max_x = 0.0;
    double max_y = 0.0;
};

[[nodiscard]] std::string format_graph_hex(std::uint64_t value) {
    return std::format("0x{:X}", value);
}

[[nodiscard]] std::string call_graph_node_display_label(const CallGraphNode& node, bool demangle = true) {
    std::string base_label = node.label.empty() ? node.id : node.label;
    if (demangle && node.symbol && !node.symbol->demangled_name.empty() &&
        (node.label.empty() || node.label == node.symbol->name)) {
        base_label = node.symbol->demangled_name;
    }
    std::string label = base_label;
    if (!node.instructions.empty()) {
        for (const auto& instruction : node.instructions)
            label += std::format("\n{:X}  {:6} {}", instruction.address, instruction.mnemonic, instruction.operands);
        return label;
    }
    if (node.bytes.start.virtual_address) {
        label += "\nVA " + format_graph_hex(*node.bytes.start.virtual_address);
    }
    if (node.bytes.start.file_offset) {
        label += "\nfile " + format_graph_hex(*node.bytes.start.file_offset);
    }
    if (node.symbol && !node.symbol->name.empty() && node.symbol->name != base_label) {
        label += "\n" + node.symbol->name;
    }
    return label;
}

[[nodiscard]] GraphLayoutBounds graph_layout_bounds(const GraphLayout& layout) {
    if (layout.nodes.empty()) {
        return {.min_x = 0.0, .min_y = 0.0, .max_x = layout.width, .max_y = layout.height};
    }

    GraphLayoutBounds bounds{
        .min_x = layout.nodes.front().center_x - layout.nodes.front().width * 0.5,
        .min_y = layout.nodes.front().center_y - layout.nodes.front().height * 0.5,
        .max_x = layout.nodes.front().center_x + layout.nodes.front().width * 0.5,
        .max_y = layout.nodes.front().center_y + layout.nodes.front().height * 0.5,
    };

    for (const GraphLayoutNode& node : layout.nodes) {
        bounds.min_x = std::min(bounds.min_x, node.center_x - node.width * 0.5);
        bounds.min_y = std::min(bounds.min_y, node.center_y - node.height * 0.5);
        bounds.max_x = std::max(bounds.max_x, node.center_x + node.width * 0.5);
        bounds.max_y = std::max(bounds.max_y, node.center_y + node.height * 0.5);
    }
    return bounds;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_binary_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return std::nullopt;
    }

    const std::streamoff end = file.tellg();
    if (end < 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    file.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file) {
            return std::nullopt;
        }
    }
    return bytes;
}

[[nodiscard]] std::optional<std::string> read_text_file(const std::filesystem::path& path) {
    const std::optional<std::vector<std::uint8_t>> bytes = read_binary_file(path);
    if (!bytes) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

[[nodiscard]] const char* graph_bmp_name(UiApp::CallGraphSample sample) {
    switch (sample) {
        case UiApp::CallGraphSample::LoadedImage:
            return "loaded_image_call_graph.bmp";
        case UiApp::CallGraphSample::PeStartup:
            return "pe_x64_startup_to_winmain.bmp";
        case UiApp::CallGraphSample::ElfStartup:
            return "linux_elf_startup_to_main.bmp";
    }
    return "pe_x64_startup_to_winmain.bmp";
}

} // namespace

void UiApp::load_call_graph_sample(CallGraphSample sample) {
    pending_call_graph_request_.reset();
    if (sample == CallGraphSample::LoadedImage) {
        const peelf::IBinaryImage* image = model_.image();
        if (image == nullptr) {
            call_graph_status_ = "No image loaded. Open a PE/ELF file or select a live module.";
            return;
        }
        load_call_graph_from_graph(build_entry_call_graph(*image, model_.symbol_index()), graph_bmp_name(sample));
        call_graph_sample_ = sample;
        return;
    }

    call_graph_status_ = "Sample bitmap rendering is disabled while the Vulkan texture path is isolated.";
    call_graph_sample_ = sample;
}

void UiApp::queue_call_graph_sample(CallGraphSample sample) {
    pending_call_graph_request_ = PendingCallGraphRequest{
        .sample = sample,
        .delay_frames = 1,
    };
    call_graph_sample_ = sample;
    call_graph_status_ = "Queued call graph render";
}

void UiApp::load_call_graph_from_graph(CallGraph graph, const std::filesystem::path& output_name) {
    for (auto& node : graph.nodes) {
        if (node.bytes.start.virtual_address) {
            if (const auto* note = annotations_.find(*node.bytes.start.virtual_address); note && !note->name.empty())
                node.label = note->name;
        }
        for (auto& instruction : node.instructions) {
            if (const auto* note = annotations_.find(instruction.address); note && !note->comment.empty())
                instruction.operands += " ; " + note->comment.substr(0, 160);
            if (instruction.branch_target) {
                if (const auto* note = annotations_.find(*instruction.branch_target); note && !note->name.empty())
                    instruction.operands += " ; " + note->name;
            }
        }
    }
    // Add symbol annotations before layout so node widths include the names.
    for (auto& node : graph.nodes) for (auto& instruction : node.instructions) {
        if (!instruction.branch_target) continue;
        if (const auto* target = symbol_index_.find_containing_address(*instruction.branch_target);
            target && target->virtual_address) {
            const auto delta = *instruction.branch_target - *target->virtual_address;
            instruction.operands += delta ? std::format(" ; {}+0x{:X}", target->name, delta)
                                          : " ; " + target->name;
        }
    }
    current_call_graph_.reset();
    current_call_graph_layout_.reset();
    original_call_graph_layout_.reset();
    dragged_graph_card_.reset();
    const std::filesystem::path plain_path = std::filesystem::temp_directory_path() / (output_name.string() + ".plain");
    const DefaultProcessRunner runner;
    const GraphRenderResult render_result =
        render_graph_with_graphviz(graph, plain_path, GraphRenderFormat::Plain, runner);
    if (!render_result.success) {
        call_graph_status_ = "Graphviz failed to lay out loaded-image graph: " + render_result.diagnostic;
        return;
    }

    const std::optional<std::string> plain_text = read_text_file(plain_path);
    if (!plain_text) {
        call_graph_status_ = "Failed to load rendered graph layout: " + plain_path.string();
        return;
    }

    current_call_graph_layout_ = parse_graphviz_plain_layout(*plain_text);
    if (!current_call_graph_layout_) {
        call_graph_status_ = "Graphviz produced an unreadable graph layout: " + plain_path.string();
        return;
    }

    call_graph_texture_.reset();

    loaded_call_graph_bmp_ = plain_path;
    original_call_graph_layout_ = current_call_graph_layout_;
    current_call_graph_ = std::move(graph);
    center_graph_selection_ = current_selection_.virtual_address.has_value();
    call_graph_status_ = "Loaded graph layout from current image";
}

const CallGraphNode* UiApp::hit_test_call_graph_node(const ImVec2& image_pos,
                                                     float graph_scale,
                                                     double graph_min_x,
                                                     double graph_max_y,
                                                     const ImVec2& mouse_pos) const {
    if (!current_call_graph_ || !current_call_graph_layout_ ||
        current_call_graph_layout_->width <= 0.0 || current_call_graph_layout_->height <= 0.0 ||
        graph_scale <= 0.0f) {
        return nullptr;
    }
    const double graph_x = graph_min_x + static_cast<double>(mouse_pos.x - image_pos.x) / graph_scale;
    const double graph_y = graph_max_y - static_cast<double>(mouse_pos.y - image_pos.y) / graph_scale;

    for (const GraphLayoutNode& layout_node : current_call_graph_layout_->nodes) {
        const double left = layout_node.center_x - layout_node.width * 0.5;
        const double right = layout_node.center_x + layout_node.width * 0.5;
        const double bottom = layout_node.center_y - layout_node.height * 0.5;
        const double top = layout_node.center_y + layout_node.height * 0.5;
        if (graph_x >= left && graph_x <= right && graph_y >= bottom && graph_y <= top) {
            const auto it = std::ranges::find_if(current_call_graph_->nodes, [&](const CallGraphNode& node) {
                return node.id == layout_node.node_id;
            });
            return it == current_call_graph_->nodes.end() ? nullptr : &*it;
        }
    }
    return nullptr;
}

void UiApp::activate_call_graph_node(const CallGraphNode& node) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        return;
    }

    navigation_history_.visit(current_selection_);
    current_selection_ = selection_from_call_graph_node(node, *img);
    current_selection_.preferred_view = PreferredView::Graph;
    current_selection_.graph_root = active_graph_root_;
    std::optional<std::uint64_t> nav_offset = current_selection_.file_offset;
    if (current_selection_.virtual_address) {
        if (const auto model_off = model_.virtual_address_to_offset(*current_selection_.virtual_address)) {
            nav_offset = model_off;
            current_selection_.file_offset = model_off;
        }
    }

    if (nav_offset) {
        const std::uint64_t size = current_selection_.size != 0 ? current_selection_.size : 1u;
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(size));
        const std::uint64_t display_address = current_selection_.virtual_address
            ? *current_selection_.virtual_address
            : *nav_offset;
        disassemble_at_offset(*nav_offset, display_address);
    }
    last_navigation_selection_ = current_selection_;

    if (node.kind == CallGraphNodeKind::BasicBlock) return;
    const SymbolIndex& sym_idx = model_.symbol_index();
    const SymbolRecord* record = nullptr;
    if (node.symbol && !node.symbol->name.empty()) {
        record = sym_idx.find_by_name(node.symbol->name);
    }
    if (!node.label.empty()) {
        if (record == nullptr) {
            record = sym_idx.find_by_name(node.label);
        }
    }
    if (record == nullptr && node.bytes.start.virtual_address) {
        record = sym_idx.find_containing_address(*node.bytes.start.virtual_address);
    }
    if (record != nullptr && record->virtual_address) {
        SymbolRecord resolved = *record;
        if (!resolved.file_offset) {
            resolved.file_offset = model_.virtual_address_to_offset(*resolved.virtual_address);
        }
        if (resolved.file_offset) {
            current_selection_.graph_root = resolved;
            pending_call_graph_root_ = std::move(resolved);
            pending_call_graph_delay_frames_ = 1;
            call_graph_status_ = "Queued fan-out from " + record->name;
        }
    }
}

void UiApp::render_call_graph_panel() {
    ImGui::SetNextWindowSize(ImVec2(900.0f, 420.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Flow Graph", &show_call_graph_panel_)) {
        ImGui::End();
        return;
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_Space)) switch_analysis_view(false);
        if (current_call_graph_ && !current_call_graph_->nodes.empty()) {
            std::vector<const CallGraphNode*> nodes;
            for (const auto& node : current_call_graph_->nodes)
                if (node.bytes.start.virtual_address && node.bytes.start.file_offset) nodes.push_back(&node);
            auto selected = std::ranges::find_if(nodes, [this](const auto* node) {
                return current_selection_.virtual_address && *current_selection_.virtual_address >= *node->bytes.start.virtual_address &&
                    *current_selection_.virtual_address - *node->bytes.start.virtual_address < std::max<std::uint64_t>(1, node->bytes.size);
            });
            if (!nodes.empty() && (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
                auto index = selected == nodes.end() ? std::ptrdiff_t{0} : selected - nodes.begin();
                if (selected != nodes.end()) index += ImGui::IsKeyPressed(ImGuiKey_UpArrow) ? -1 : 1;
                index = std::clamp(index, std::ptrdiff_t{0}, static_cast<std::ptrdiff_t>(nodes.size() - 1));
                activate_call_graph_node(*nodes[static_cast<std::size_t>(index)]);
                center_graph_selection_ = true;
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Enter) && selected != nodes.end()) {
                const auto target = std::ranges::find_if((*selected)->instructions, [](const auto& i) { return i.branch_target.has_value(); });
                if (target != (*selected)->instructions.end()) enqueue_navigation(*target->branch_target, PreferredView::Graph);
            }
        }
    }

    if (ImGui::RadioButton("Control flow", function_cfg_)) {
        function_cfg_ = true; pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Calls", !function_cfg_)) {
        function_cfg_ = false; pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::Button("Image overview")) {
        queue_call_graph_sample(CallGraphSample::LoadedImage);
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload")) {
        if (active_graph_root_) pending_call_graph_root_ = active_graph_root_;
        else queue_call_graph_sample(call_graph_sample_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Fit")) { fit_graph_ = true; graph_pan_ = {}; }
    ImGui::SameLine();
    if (ImGui::Button("100%")) { graph_zoom_ = 1; graph_pan_ = {}; }
    ImGui::SameLine();
    if (ImGui::Button("Reset cards") && original_call_graph_layout_) {
        current_call_graph_layout_ = original_call_graph_layout_;
        dragged_graph_card_.reset(); fit_graph_ = true; graph_pan_ = {};
    }
    ImGui::SameLine();
    ImGui::TextDisabled("Wheel: zoom  |  Middle-drag: pan  |  Drag: move card  |  Click: inspect");

    if (!call_graph_status_.empty()) {
        ImGui::TextUnformatted(call_graph_status_.c_str());
    }
    if (model_.image() != nullptr && reference_index_.total_executable_bytes() > 0) {
        const bool scanning = reference_index_.is_scanning() || reference_scanner_.is_scanning();
        ImGui::TextDisabled("Scan coverage: %.1f%% (%zu / %zu bytes%s)",
            reference_index_.coverage_percent(),
            reference_index_.scanned_bytes(),
            reference_index_.total_executable_bytes(),
            scanning ? ", scanning in background..." : (reference_index_.incomplete() ? ", budget capped" : ""));
        if (!scanning && reference_index_.incomplete()) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Scan Full Binary##cfg_scan_full")) {
                if (reference_scanner_.has_resumable_work()) {
                    reference_scanner_.scan_full(reference_index_);
                }
            }
        }
    }
    if (current_call_graph_ && !current_call_graph_->indirect_recoveries.empty()) {
        const std::string header = std::format(
            "Indirect branch / call recovery ({} resolved)",
            current_call_graph_->indirect_recoveries.size());
        if (ImGui::TreeNode("IndirectRecoveries", "%s", header.c_str())) {
            for (std::size_t idx = 0; idx < current_call_graph_->indirect_recoveries.size(); ++idx) {
                const auto& rec = current_call_graph_->indirect_recoveries[idx];
                ImGui::PushID(static_cast<int>(idx));
                const std::string line = std::format(
                    "0x{:X} [{}] {}",
                    rec.source_address, rec.confidence, rec.evidence);
                if (ImGui::Selectable(line.c_str())) {
                    enqueue_navigation(rec.source_address, PreferredView::Disassembly);
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
    }
    if (!current_call_graph_) ImGui::TextWrapped("Select a function in Functions & Names to explore its calls, or build the loaded-image graph.");

    ImGui::InputTextWithHint("Find node", "Any part of a function name...", graph_search_, sizeof(graph_search_));
    if (current_call_graph_ && current_call_graph_->id != "function_cfg" &&
        ImGui::CollapsingHeader("Callers / Callees (current graph)")) {
        ImGui::BeginChild("CallRelations", ImVec2(0, 160), true);
        for (const auto& root : current_call_graph_->nodes) {
            if (graph_search_[0] && !symbol_name_matches(root.label, graph_search_)) continue;
            ImGui::PushID(root.id.c_str());
            if (ImGui::TreeNode(root.label.c_str())) {
                for (const bool callers : {true, false}) {
                    if (ImGui::TreeNode(callers ? "Callers" : "Callees")) {
                        const auto ids = call_neighbors(*current_call_graph_, root.id, callers);
                        if (ids.empty()) ImGui::TextDisabled("No known calls in this graph");
                        for (const auto& id : ids) {
                            const auto node = std::ranges::find_if(current_call_graph_->nodes,
                                [&](const auto& candidate) { return candidate.id == id; });
                            if (node == current_call_graph_->nodes.end()) continue;
                            ImGui::PushID(id.c_str());
                            const auto label = node->label + (id == root.id ? " (recursive)" : "");
                            if (ImGui::Selectable(label.c_str())) activate_call_graph_node(*node);
                            ImGui::PopID();
                        }
                        ImGui::TreePop();
                    }
                }
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    if (current_call_graph_ && graph_search_[0] != '\0') {
        ImGui::BeginChild("GraphSearchResults", ImVec2(0, 100), true);
        for (const auto& node : current_call_graph_->nodes) {
            if (!symbol_name_matches(node.label, graph_search_) &&
                (!node.symbol || (!symbol_name_matches(node.symbol->name, graph_search_) &&
                                  (node.symbol->demangled_name.empty() ||
                                   !symbol_name_matches(node.symbol->demangled_name, graph_search_))))) continue;
            ImGui::PushID(node.id.c_str());
            const std::string item_label =
                (model_.demangle_symbols() && node.symbol && !node.symbol->demangled_name.empty())
                    ? node.symbol->demangled_name
                    : node.label;
            if (ImGui::Selectable(item_label.c_str())) activate_call_graph_node(node);
            if (ImGui::IsItemHovered() && node.symbol && item_label != node.symbol->name) {
                ImGui::SetTooltip("Raw symbol: %s", node.symbol->name.c_str());
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    const ImVec2 available = ImGui::GetContentRegionAvail();
    const ImVec2 canvas_size(std::max(available.x, 64.0f), std::max(available.y, 64.0f));
    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y))) {
        if (ImGui::GetIO().MouseWheel != 0)
            graph_zoom_ = std::clamp(graph_zoom_ * (1.0f + ImGui::GetIO().MouseWheel * 0.12f), 0.05f, 4.0f);
        if (ImGui::IsMouseDragging(ImGuiMouseButton_Middle)) {
            graph_pan_.x += ImGui::GetIO().MouseDelta.x;
            graph_pan_.y += ImGui::GetIO().MouseDelta.y;
        }
    }
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->PushClipRect(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), true);
    draw_list->AddRectFilled(canvas_pos,
                             ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                             ImGui::GetColorU32(ImGuiCol_ChildBg));

    if (current_call_graph_ && current_call_graph_layout_) {
        const GraphLayoutBounds bounds = graph_layout_bounds(*current_call_graph_layout_);
        const float graph_width = static_cast<float>(std::max(1.0, bounds.max_x - bounds.min_x));
        const float graph_height = static_cast<float>(std::max(1.0, bounds.max_y - bounds.min_y));
        constexpr float kGraphPadding = 32.0f;
        const ImVec2 padded_canvas_size(std::max(1.0f, canvas_size.x - kGraphPadding * 2.0f),
                                        std::max(1.0f, canvas_size.y - kGraphPadding * 2.0f));
        const float native_scale = ImGui::GetFontSize() * 7.2f;
        if (fit_graph_) {
            graph_zoom_ = std::min({padded_canvas_size.x / graph_width,
                                   padded_canvas_size.y / graph_height, native_scale}) / native_scale;
            fit_graph_ = false;
        }
        const float scale = native_scale * graph_zoom_;
        const ImVec2 draw_size(std::max(1.0f, graph_width * scale), std::max(1.0f, graph_height * scale));
        if (center_graph_selection_) {
            for (const auto& node : current_call_graph_->nodes) {
                if (!node.bytes.start.virtual_address || !current_selection_.virtual_address) continue;
                const auto start = *node.bytes.start.virtual_address;
                const auto address = *current_selection_.virtual_address;
                if (address < start || address - start >= std::max<std::uint64_t>(1, node.bytes.size)) continue;
                const auto layout = std::ranges::find_if(current_call_graph_layout_->nodes,
                    [&](const auto& item) { return item.node_id == node.id; });
                if (layout != current_call_graph_layout_->nodes.end()) {
                    graph_pan_.x = draw_size.x * 0.5f - static_cast<float>(layout->center_x - bounds.min_x) * scale;
                    graph_pan_.y = canvas_size.y * 0.5f - kGraphPadding - static_cast<float>(bounds.max_y - layout->center_y) * scale;
                }
                break;
            }
            center_graph_selection_ = false;
        }
        const ImVec2 graph_pos(canvas_pos.x + (canvas_size.x - draw_size.x) * 0.5f + graph_pan_.x,
                               canvas_pos.y + kGraphPadding + graph_pan_.y);

        const auto to_screen = [&](double graph_x, double graph_y) {
            return ImVec2(graph_pos.x + static_cast<float>(graph_x - bounds.min_x) * scale,
                          graph_pos.y + static_cast<float>(bounds.max_y - graph_y) * scale);
        };
        const auto find_layout = [&](std::string_view node_id) -> const GraphLayoutNode* {
            const auto it = std::ranges::find_if(current_call_graph_layout_->nodes, [&](const GraphLayoutNode& node) {
                return node.node_id == node_id;
            });
            return it == current_call_graph_layout_->nodes.end() ? nullptr : &*it;
        };

        for (const CallGraphEdge& edge : current_call_graph_->edges) {
            const GraphLayoutNode* from = find_layout(edge.from_node_id);
            const GraphLayoutNode* to = find_layout(edge.to_node_id);
            if (from == nullptr || to == nullptr) {
                continue;
            }
            const bool cfg = current_call_graph_->id == "function_cfg";
            const auto start = to_screen(from->center_x + (cfg ? 0 : from->width / 2), from->center_y - (cfg ? from->height / 2 : 0));
            const auto end = to_screen(to->center_x - (cfg ? 0 : to->width / 2), to->center_y + (cfg ? to->height / 2 : 0));
            const auto color = ImGui::GetColorU32(edge.kind == CallGraphEdgeKind::ConditionalBranch ? ImGuiCol_PlotLines :
                edge.kind == CallGraphEdgeKind::Fallthrough ? ImGuiCol_PlotHistogramHovered : ImGuiCol_CheckMark);
            const float bend = std::max(24.0f, (cfg ? std::abs(end.y - start.y) : std::abs(end.x - start.x)) * 0.45f);
            draw_list->AddBezierCubic(start, ImVec2(start.x + (cfg ? 0 : bend), start.y + (cfg ? bend : 0)),
                ImVec2(end.x - (cfg ? 0 : bend), end.y - (cfg ? bend : 0)), end, color, 1.8f);
            if (cfg) draw_list->AddTriangleFilled(end, ImVec2(end.x - 5, end.y - 9), ImVec2(end.x + 5, end.y - 9), color);
            else draw_list->AddTriangleFilled(end, ImVec2(end.x - 9, end.y - 5), ImVec2(end.x - 9, end.y + 5), color);
            if (!edge.label.empty()) draw_list->AddText(ImGui::GetFont(), std::max(3.0f, scale / 7.2f),
                ImVec2((start.x + end.x) * 0.5f + 6, (start.y + end.y) * 0.5f), color, edge.label.c_str());
        }

        for (const GraphLayoutNode& layout_node : current_call_graph_layout_->nodes) {
            const auto graph_node = std::ranges::find_if(current_call_graph_->nodes, [&](const CallGraphNode& node) {
                return node.id == layout_node.node_id;
            });
            const std::string label = graph_node == current_call_graph_->nodes.end()
                                          ? layout_node.node_id
                                          : call_graph_node_display_label(*graph_node, model_.demangle_symbols());
            bool selected = false;
            const peelf::IBinaryImage* img = model_.image();
            if (graph_node != current_call_graph_->nodes.end() && img != nullptr) {
                selected = same_selection(current_selection_, selection_from_call_graph_node(*graph_node, *img));
                if (current_selection_.virtual_address && graph_node->bytes.start.virtual_address) {
                    const auto address = *current_selection_.virtual_address;
                    const auto start = *graph_node->bytes.start.virtual_address;
                    selected = address >= start && address - start < std::max<std::uint64_t>(graph_node->bytes.size, 1);
                    if (selected_code_address_ == current_selection_.virtual_address && decompile_revision_ == model_.edit_revision()) {
                        for (const auto& range : selected_code_ranges_)
                            if (range.address >= start && range.address-start < graph_node->bytes.size) selected = true;
                    }
                }
            }
            const ImVec2 top_left = to_screen(layout_node.center_x - layout_node.width * 0.5,
                                              layout_node.center_y + layout_node.height * 0.5);
            const ImVec2 bottom_right = to_screen(layout_node.center_x + layout_node.width * 0.5,
                                                  layout_node.center_y - layout_node.height * 0.5);
            draw_list->AddRectFilled(top_left,
                                     bottom_right,
                                     ImGui::GetColorU32(selected ? ImGuiCol_HeaderActive : ImGuiCol_FrameBg),
                                     4.0f);
            draw_list->AddRect(top_left,
                               bottom_right,
                               ImGui::GetColorU32(selected ? ImGuiCol_CheckMark : ImGuiCol_Border),
                               4.0f,
                               0,
                               selected ? 3.0f : 2.0f);
            const float font_size = std::max(3.0f, scale / 7.2f);
            draw_list->AddRectFilled(top_left, ImVec2(bottom_right.x, top_left.y + font_size + 10), ImGui::GetColorU32(ImGuiCol_Header), 4);
            draw_list->PushClipRect(top_left, bottom_right, true);
            draw_list->AddText(code_font_ ? code_font_ : ImGui::GetFont(), font_size,
                ImVec2(top_left.x + 8, top_left.y + 5), ImGui::GetColorU32(ImGuiCol_Text), label.c_str());
            draw_list->PopClipRect();
        }

        ImGui::SetCursorScreenPos(canvas_pos);
        ImGui::InvisibleButton("CallGraphVectorHitTarget", canvas_size);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            if (const CallGraphNode* node =
                    hit_test_call_graph_node(graph_pos, scale, bounds.min_x, bounds.max_y, ImGui::GetIO().MousePos)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !node->instructions.empty()) {
                    const auto layout = std::ranges::find_if(current_call_graph_layout_->nodes,
                        [&](const auto& item) { return item.node_id == node->id; });
                    if (layout != current_call_graph_layout_->nodes.end()) {
                        const float top = to_screen(layout->center_x, layout->center_y + layout->height * 0.5).y + 5;
                        const auto row = static_cast<int>((ImGui::GetIO().MousePos.y - top) / std::max(3.0f, scale / 7.2f)) - 1;
                        if (row >= 0 && static_cast<std::size_t>(row) < node->instructions.size()) {
                            const auto target = node->instructions[static_cast<std::size_t>(row)].branch_target;
                            if (target) enqueue_navigation(*target, PreferredView::Graph);
                        }
                    }
                } else {
                    dragged_graph_card_ = node->id;
                    graph_card_moved_ = false;
                    graph_card_mouse_ = ImGui::GetIO().MousePos;
                }
            }
        }
        if (dragged_graph_card_) {
            const auto mouse = ImGui::GetIO().MousePos;
            const ImVec2 delta(mouse.x - graph_card_mouse_.x, mouse.y - graph_card_mouse_.y);
            const auto threshold = ImGui::GetIO().MouseDragThreshold;
            if ((graph_card_moved_ || delta.x*delta.x + delta.y*delta.y >= threshold*threshold) &&
                move_graph_card(*current_call_graph_layout_, *dragged_graph_card_, delta.x, delta.y, scale)) {
                graph_card_moved_ = true;
                graph_card_mouse_ = mouse;
                const auto moved_bounds = graph_layout_bounds(*current_call_graph_layout_);
                // Changing the outer bounds must not move the other cards on screen.
                graph_pan_.x += static_cast<float>((moved_bounds.min_x + moved_bounds.max_x - bounds.min_x - bounds.max_x) * 0.5) * scale;
                graph_pan_.y += static_cast<float>(bounds.max_y - moved_bounds.max_y) * scale;
                ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
            }
        }
        if (dragged_graph_card_ && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            if (!graph_card_moved_ && ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
                const auto node = std::ranges::find(current_call_graph_->nodes, *dragged_graph_card_, &CallGraphNode::id);
                if (node != current_call_graph_->nodes.end()) activate_call_graph_node(*node);
            }
            dragged_graph_card_.reset();
        }
    } else if (call_graph_texture_) {
        const float image_width = static_cast<float>(call_graph_texture_->width);
        const float image_height = static_cast<float>(call_graph_texture_->height);
        const float scale = std::min(canvas_size.x / image_width, canvas_size.y / image_height);
        const ImVec2 draw_size(std::max(1.0f, image_width * scale), std::max(1.0f, image_height * scale));
        const ImVec2 image_pos(canvas_pos.x + (canvas_size.x - draw_size.x) * 0.5f,
                               canvas_pos.y + (canvas_size.y - draw_size.y) * 0.5f);
        ImTextureID texture_id = reinterpret_cast<ImTextureID>(call_graph_texture_->descriptor_set);
        draw_list->AddImage(texture_id,
                            image_pos,
                            ImVec2(image_pos.x + draw_size.x, image_pos.y + draw_size.y));
        ImGui::SetCursorScreenPos(image_pos);
        ImGui::InvisibleButton("CallGraphImageHitTarget", draw_size);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            const float image_scale = current_call_graph_layout_ && current_call_graph_layout_->width > 0.0
                                          ? draw_size.x / static_cast<float>(current_call_graph_layout_->width)
                                          : 1.0f;
            if (const CallGraphNode* node = hit_test_call_graph_node(image_pos,
                                                                     image_scale,
                                                                     0.0,
                                                                     current_call_graph_layout_
                                                                         ? current_call_graph_layout_->height
                                                                         : 0.0,
                                                                     ImGui::GetIO().MousePos)) {
                activate_call_graph_node(*node);
            }
        }
    } else {
        const char* message = "No graph rendered yet. Click Loaded Image or Reload.";
        const ImVec2 text_size = ImGui::CalcTextSize(message);
        draw_list->AddText(ImVec2(canvas_pos.x + (canvas_size.x - text_size.x) * 0.5f,
                                  canvas_pos.y + (canvas_size.y - text_size.y) * 0.5f),
                           ImGui::GetColorU32(ImGuiCol_TextDisabled),
                           message);
    }

    draw_list->PopClipRect();
    ImGui::SetCursorScreenPos(canvas_pos);
    if (!call_graph_texture_) {
        ImGui::Dummy(canvas_size);
    } else {
        ImGui::SetCursorScreenPos(ImVec2(canvas_pos.x, canvas_pos.y + canvas_size.y));
    }
    ImGui::End();
}

} // namespace viewer
