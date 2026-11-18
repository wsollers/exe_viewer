#include "ui_app.hpp"
#include "ui_app_internal.hpp"

#include "graph/call_graph.hpp"
#include "graph/call_graph_galaxy.hpp"
#include "graph/layout_edit.hpp"
#include "logger.hpp"
#include "ui/ui_context_menu.hpp"

#include <peelf/byte_viz.hpp>

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
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

class ScopedGraphvizTempDir final {
public:
    ScopedGraphvizTempDir() noexcept = default;
    ~ScopedGraphvizTempDir() noexcept {
        if (!dir_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(dir_, ec);
        }
    }

    ScopedGraphvizTempDir(const ScopedGraphvizTempDir&) = delete;
    ScopedGraphvizTempDir& operator=(const ScopedGraphvizTempDir&) = delete;
    ScopedGraphvizTempDir(ScopedGraphvizTempDir&& other) noexcept
        : dir_(std::move(other.dir_)) {
        other.dir_.clear();
    }
    ScopedGraphvizTempDir& operator=(ScopedGraphvizTempDir&& other) noexcept {
        if (this != &other) {
            if (!dir_.empty()) {
                std::error_code ec;
                std::filesystem::remove_all(dir_, ec);
            }
            dir_ = std::move(other.dir_);
            other.dir_.clear();
        }
        return *this;
    }

    [[nodiscard]] static peelf::Result<ScopedGraphvizTempDir> create() {
        std::error_code ec;
        const std::filesystem::path base = std::filesystem::temp_directory_path(ec);
        if (ec || base.empty()) {
            return peelf::make_error("Unable to resolve temporary directory for Graphviz layout");
        }

        static std::atomic<std::uint64_t> s_seq{0u};
        std::random_device rd;
        for (int attempt = 0; attempt < 16; ++attempt) {
            const auto now_ticks = static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            const std::uint64_t nonce =
                (static_cast<std::uint64_t>(rd()) << 32u) ^ static_cast<std::uint64_t>(rd());
            const std::uint64_t seq = s_seq.fetch_add(1u, std::memory_order_relaxed);
            const std::filesystem::path candidate =
                base / std::format("peelf_gv_{:x}_{:016x}_{:x}", now_ticks, nonce, seq);

            std::error_code mkdir_ec;
            if (std::filesystem::create_directory(candidate, mkdir_ec) && !mkdir_ec) {
                std::error_code perm_ec;
                std::filesystem::permissions(
                    candidate,
                    std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::replace,
                    perm_ec);
                ScopedGraphvizTempDir guard{};
                guard.dir_ = candidate;
                return guard;
            }
        }
        return peelf::make_error("Failed to create unique temporary directory for Graphviz layout");
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return dir_; }

private:
    std::filesystem::path dir_{};
};

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
    loaded_call_graph_bmp_.clear();
    call_galaxy_.cached_unrendered_graph = graph;

    auto temp_dir_res = ScopedGraphvizTempDir::create();
    if (!temp_dir_res.has_value()) {
        call_graph_status_ = temp_dir_res.error().message;
        return;
    }
    const std::filesystem::path stem =
        output_name.filename().empty() ? std::filesystem::path{"layout"} : output_name.filename();
    const std::filesystem::path plain_path = temp_dir_res->path() / (stem.string() + ".plain");
    const DefaultProcessRunner runner;
    const GraphRenderResult render_result =
        render_graph_with_graphviz(graph, plain_path, GraphRenderFormat::Plain, runner);
    if (!render_result.success) {
        call_graph_status_ = "Graphviz failed to lay out loaded-image graph: " + render_result.diagnostic;
        return;
    }

    const std::optional<std::string> plain_text = read_text_file(plain_path);
    if (!plain_text) {
        call_graph_status_ = "Failed to load rendered graph layout";
        return;
    }

    current_call_graph_layout_ = parse_graphviz_plain_layout(*plain_text);
    if (!current_call_graph_layout_) {
        call_graph_status_ = "Graphviz produced an unreadable graph layout";
        return;
    }

    call_graph_texture_.reset();

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
        if (!call_galaxy_.enabled && current_call_graph_ && !current_call_graph_->nodes.empty()) {
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

    if (ImGui::RadioButton("Control flow", !call_galaxy_.enabled && function_cfg_)) {
        call_galaxy_.enabled = false;
        function_cfg_ = true;
        pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Calls", !call_galaxy_.enabled && !function_cfg_)) {
        call_galaxy_.enabled = false;
        function_cfg_ = false;
        pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("GPU Galaxy", call_galaxy_.enabled)) {
        if (!call_galaxy_.enabled) {
            call_galaxy_.enabled = true;
            call_galaxy_.dirty = true;
            call_galaxy_.fit_requested = true;
        }
    }

    if (call_galaxy_.enabled) {
        render_call_galaxy_view();
        ImGui::End();
        return;
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
        const bool graphviz_unavailable =
            !current_call_graph_layout_ &&
            (call_graph_status_.find("Graphviz") != std::string::npos ||
             call_graph_status_.find("Failed") != std::string::npos ||
             call_graph_status_.find("temporary") != std::string::npos);
        if (graphviz_unavailable) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Switch to GPU Galaxy")) {
                call_galaxy_.enabled = true;
                if (active_graph_root_.has_value()) {
                    call_galaxy_.scope = function_cfg_
                                             ? GalaxyScopeMode::ActiveFunctionCfg
                                             : GalaxyScopeMode::ActiveSymbolFanout;
                } else {
                    call_galaxy_.scope = GalaxyScopeMode::WholeBinary;
                }
                call_galaxy_.dirty = true;
                call_galaxy_.fit_requested = true;
                ImGui::End();
                return;
            }
            ImGui::TextDisabled(
                "Tip: Graphviz 'dot' is not required in GPU Galaxy mode (native Barnes-Hut force layout).");
        }
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

namespace {

[[nodiscard]] const char* galaxy_scope_label(std::uint8_t idx) noexcept {
    switch (idx) {
        case 0u: return "Whole-Binary Call Galaxy";
        case 1u: return "Active Function CFG";
        case 2u: return "Active Symbol Fanout";
        default: return "Whole-Binary Call Galaxy";
    }
}

[[nodiscard]] const char* galaxy_color_mode_label(GalaxyColorMode mode) noexcept {
    switch (mode) {
        case GalaxyColorMode::OriginAndSection:  return "Origin / Section";
        case GalaxyColorMode::EntryReachability: return "Entry Reachability";
        case GalaxyColorMode::SecurityFindings:  return "Security Findings";
        case GalaxyColorMode::BinaryDiff:        return "Binary Diff";
        case GalaxyColorMode::CallDegreeHeat:    return "Call Degree Heat";
    }
    return "Origin / Section";
}

[[nodiscard]] bool galaxy_node_matches_search(
    const CallGalaxyNode& node,
    std::string_view query) {
    if (query.empty()) {
        return false;
    }
    if (symbol_name_matches(node.display_name, query) ||
        symbol_name_matches(node.raw_name, query) ||
        symbol_name_matches(node.module_or_section, query)) {
        return true;
    }
    if (node.virtual_address != 0u) {
        const std::string va_hex = std::format("0x{:X}", node.virtual_address);
        if (symbol_name_matches(va_hex, query)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] ImVec4 galaxy_reachability_badge_color(GalaxyReachability reach) noexcept {
    switch (reach) {
        case GalaxyReachability::EntryPoint:
            return ImVec4(0.98f, 0.78f, 0.25f, 1.0f);
        case GalaxyReachability::ReachableFromEntry:
            return ImVec4(0.35f, 0.90f, 0.56f, 1.0f);
        case GalaxyReachability::UnreachableInternal:
            return ImVec4(0.66f, 0.68f, 0.76f, 1.0f);
        case GalaxyReachability::ExternalImport:
            return ImVec4(0.55f, 0.80f, 0.98f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

[[nodiscard]] ImVec4 galaxy_security_badge_color(GalaxySecuritySeverity sev) noexcept {
    switch (sev) {
        case GalaxySecuritySeverity::Error:   return ImVec4(0.98f, 0.34f, 0.34f, 1.0f);
        case GalaxySecuritySeverity::Warning: return ImVec4(0.98f, 0.74f, 0.24f, 1.0f);
        case GalaxySecuritySeverity::Note:    return ImVec4(0.45f, 0.80f, 0.98f, 1.0f);
        case GalaxySecuritySeverity::Pass:    return ImVec4(0.38f, 0.88f, 0.54f, 1.0f);
        case GalaxySecuritySeverity::None:    return ImVec4(0.62f, 0.64f, 0.70f, 1.0f);
    }
    return ImVec4(0.62f, 0.64f, 0.70f, 1.0f);
}

[[nodiscard]] ImVec4 galaxy_diff_badge_color(GalaxyDiffStatus status) noexcept {
    switch (status) {
        case GalaxyDiffStatus::Added:     return ImVec4(0.35f, 0.92f, 0.52f, 1.0f);
        case GalaxyDiffStatus::Modified:  return ImVec4(0.98f, 0.72f, 0.24f, 1.0f);
        case GalaxyDiffStatus::Removed:   return ImVec4(0.98f, 0.36f, 0.36f, 1.0f);
        case GalaxyDiffStatus::Relocated: return ImVec4(0.46f, 0.78f, 0.98f, 1.0f);
        case GalaxyDiffStatus::Unchanged: return ImVec4(0.62f, 0.64f, 0.70f, 1.0f);
    }
    return ImVec4(0.62f, 0.64f, 0.70f, 1.0f);
}

} // namespace

void UiApp::ensure_call_galaxy_worker_started() {
    if (call_galaxy_.worker.joinable()) {
        return;
    }
    call_galaxy_.worker = std::jthread([this](std::stop_token st) {
        call_galaxy_worker_loop(std::move(st));
    });
}

void UiApp::call_galaxy_worker_loop(std::stop_token stop_token) {
    BarnesHutGalaxyLayout local_layout{};
    std::uint64_t active_gen = 0u;
    bool converged = true;

    while (!stop_token.stop_requested()) {
        std::optional<CallGalaxyGraph> seed_graph{};
        BarnesHutLayoutConfig seed_cfg{};
        std::vector<GalaxyPinCommand> pin_cmds{};
        bool do_reheat = false;
        bool do_unpin_all = false;
        bool playing = false;
        std::uint64_t target_gen = 0u;

        {
            std::unique_lock<std::mutex> lock(call_galaxy_.worker_mutex);
            call_galaxy_.worker_cv.wait(lock, stop_token, [&]() {
                const bool has_new_seed = call_galaxy_.pending_seed_graph.has_value();
                const bool has_cmds =
                    !call_galaxy_.pending_pin_commands.empty() ||
                    call_galaxy_.pending_reheat ||
                    call_galaxy_.pending_unpin_all;
                const bool can_step =
                    call_galaxy_.worker_playing && !converged && local_layout.node_count() > 0u;
                return has_new_seed || has_cmds || can_step;
            });
            if (stop_token.stop_requested()) {
                return;
            }

            target_gen = call_galaxy_.worker_generation;
            if (call_galaxy_.pending_seed_graph.has_value()) {
                seed_graph = std::move(call_galaxy_.pending_seed_graph);
                call_galaxy_.pending_seed_graph.reset();
                seed_cfg = call_galaxy_.pending_seed_config;
            }
            pin_cmds.swap(call_galaxy_.pending_pin_commands);
            do_reheat = std::exchange(call_galaxy_.pending_reheat, false);
            do_unpin_all = std::exchange(call_galaxy_.pending_unpin_all, false);
            playing = call_galaxy_.worker_playing;
        }

        if (seed_graph.has_value()) {
            active_gen = target_gen;
            local_layout.reset(*seed_graph, seed_cfg);
            converged = (local_layout.node_count() <= 1u);
        } else if (active_gen != target_gen) {
            converged = true;
            continue;
        }

        bool state_mutated = seed_graph.has_value();
        if (do_unpin_all && local_layout.node_count() > 0u) {
            local_layout.unpin_all();
            local_layout.reheat(0.35f);
            converged = false;
            state_mutated = true;
        }
        for (const GalaxyPinCommand& cmd : pin_cmds) {
            if (cmd.node_index < local_layout.node_count()) {
                if (cmd.pinned) {
                    local_layout.set_node_position(cmd.node_index, cmd.world_x, cmd.world_y);
                }
                local_layout.set_node_pinned(cmd.node_index, cmd.pinned);
                local_layout.reheat(0.18f);
                converged = false;
                state_mutated = true;
            }
        }
        if (do_reheat && local_layout.node_count() > 0u) {
            local_layout.reheat(0.65f);
            converged = false;
            state_mutated = true;
        }

        BarnesHutStepResult step_stats{};
        if (playing && !converged && local_layout.node_count() > 1u) {
            const std::uint32_t batch_iters =
                (local_layout.node_count() > 4096u) ? 2u : 4u;
            step_stats = local_layout.step(batch_iters, stop_token);
            if (stop_token.stop_requested()) {
                return;
            }
            converged = step_stats.converged;
            state_mutated = true;
        } else {
            step_stats.iterations_executed = 0u;
            step_stats.temperature = local_layout.temperature();
            step_stats.converged = converged;
        }

        if (state_mutated) {
            const auto px = local_layout.positions_x();
            const auto py = local_layout.positions_y();
            const auto pm = local_layout.pinned_mask();
            const std::uint32_t tot_iters = local_layout.total_iterations();

            std::scoped_lock lock(call_galaxy_.worker_mutex);
            if (active_gen == call_galaxy_.worker_generation) {
                call_galaxy_.published_pos_x.assign(px.begin(), px.end());
                call_galaxy_.published_pos_y.assign(py.begin(), py.end());
                call_galaxy_.published_pinned.assign(pm.begin(), pm.end());
                call_galaxy_.published_stats = step_stats;
                call_galaxy_.published_total_iterations = tot_iters;
                call_galaxy_.published_converged = converged;
                call_galaxy_.published_generation = active_gen;
                ++call_galaxy_.published_seq;
            }
        }
    }
}

void UiApp::cancel_and_reset_call_galaxy() noexcept {
    if (call_galaxy_.worker.joinable()) {
        call_galaxy_.worker.request_stop();
        call_galaxy_.worker_cv.notify_all();
        call_galaxy_.worker.join();
    }

    {
        std::scoped_lock lock(call_galaxy_.worker_mutex);
        ++call_galaxy_.worker_generation;
        call_galaxy_.pending_seed_graph.reset();
        call_galaxy_.pending_pin_commands.clear();
        call_galaxy_.pending_reheat = false;
        call_galaxy_.pending_unpin_all = false;
        call_galaxy_.published_pos_x.clear();
        call_galaxy_.published_pos_y.clear();
        call_galaxy_.published_pinned.clear();
        call_galaxy_.published_stats = {};
        call_galaxy_.published_total_iterations = 0u;
        call_galaxy_.published_converged = false;
        call_galaxy_.published_seq = 0u;
        call_galaxy_.consumed_seq = 0u;
    }

    call_galaxy_.graph = {};
    call_galaxy_.cached_unrendered_graph.reset();
    call_galaxy_.dirty = true;
    call_galaxy_.fit_requested = true;
    call_galaxy_.was_ref_scanning = false;
    call_galaxy_.ui_pos_x.clear();
    call_galaxy_.ui_pos_y.clear();
    call_galaxy_.ui_pinned.clear();
    call_galaxy_.last_stats = {};
    call_galaxy_.ui_total_iterations = 0u;
    call_galaxy_.layout_converged = false;
    call_galaxy_.hovered_node.reset();
    call_galaxy_.selected_node.reset();
    call_galaxy_.dragged_node.reset();
    call_galaxy_.drag_moved = false;
    call_galaxy_.ego_mask = {};
    call_galaxy_.highlighted_path = {};
    call_galaxy_.trace_status.clear();
    call_galaxy_.context_node.reset();
    call_galaxy_.context_entity = {};
    call_galaxy_.current_batch = {};
    call_galaxy_.needs_gpu_record_this_frame = false;
}

void UiApp::shutdown_call_galaxy() noexcept {
    cancel_and_reset_call_galaxy();
    if (vulkan_.device() != VK_NULL_HANDLE) {
        (void)vkDeviceWaitIdle(vulkan_.device());
    }
    call_galaxy_.edge_pipeline.shutdown();
    call_galaxy_.node_pipeline.shutdown();
    call_galaxy_.edge_ring.shutdown();
    call_galaxy_.node_ring.shutdown();
    call_galaxy_.canvas.shutdown();
    call_galaxy_.canvas_initialized = false;
    call_galaxy_.pipelines_attempted = false;
}

CallGalaxyBuildOptions UiApp::current_call_galaxy_overlay_options(
    std::vector<peelf::ByteVizDiffRange>& diff_scratch) const {
    diff_scratch.clear();
    CallGalaxyBuildOptions opts{};
    const peelf::SecurityAuditReport& sec = model_.security_audit();
    if (!sec.findings.empty()) {
        opts.security_report = &sec;
    }
    if (model_.is_live_process()) {
        if (const auto& live_rep = binary_diff_panel_.active_live_report();
            live_rep.has_value()) {
            diff_scratch = peelf::extract_byte_viz_diff_ranges(*live_rep);
            opts.diff_ranges = diff_scratch;
        }
    } else if (const auto& static_rep = binary_diff_panel_.active_static_report();
               static_rep.has_value()) {
        opts.diff_report = &*static_rep;
        diff_scratch = peelf::extract_byte_viz_diff_ranges(*static_rep, true);
        opts.diff_ranges = diff_scratch;
    }
    return opts;
}

std::optional<CallGraph> UiApp::build_scoped_call_graph_for_galaxy(GalaxyScopeMode scope) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        return std::nullopt;
    }

    std::optional<SymbolRecord> root = active_graph_root_;
    if (!root.has_value() && current_selection_.virtual_address.has_value()) {
        if (const SymbolRecord* sym =
                symbol_index_.find_containing_address(*current_selection_.virtual_address);
            sym != nullptr) {
            root = *sym;
        }
    }
    if (!root.has_value() && img->entry_point() != 0u) {
        if (const SymbolRecord* ep_sym = symbol_index_.find_exact_address(img->entry_point());
            ep_sym != nullptr) {
            root = *ep_sym;
        } else {
            SymbolRecord synth{};
            synth.name = "Entry point";
            synth.virtual_address = img->entry_point();
            synth.file_offset = img->virtual_address_to_file_offset(img->entry_point());
            root = std::move(synth);
        }
    }
    if (!root.has_value() && !model_.function_index().empty()) {
        const FunctionEntry& first_fn = model_.function_index().entries().front();
        SymbolRecord synth{};
        synth.name = first_fn.name;
        synth.raw_name = first_fn.raw_name;
        synth.demangled_name = first_fn.demangled_name;
        synth.virtual_address = first_fn.virtual_address;
        synth.file_offset = first_fn.file_offset;
        synth.size = first_fn.size;
        root = std::move(synth);
    }

    if (!root.has_value() || !root->virtual_address.has_value()) {
        if (call_galaxy_.cached_unrendered_graph.has_value()) {
            return call_galaxy_.cached_unrendered_graph;
        }
        if (current_call_graph_.has_value()) {
            return current_call_graph_;
        }
        return build_entry_call_graph(*img, symbol_index_);
    }

    SymbolRecord root_for_extent = *root;
    if (root->virtual_address.has_value()) {
        root_for_extent.file_offset = img->virtual_address_to_file_offset(*root->virtual_address);
    }

    if (scope == GalaxyScopeMode::ActiveFunctionCfg) {
        const std::size_t analysis_size = static_cast<std::size_t>(model_.analysis_image_size());
        if (root_for_extent.file_offset.has_value() &&
            *root_for_extent.file_offset < analysis_size) {
            if (const auto extent =
                    discover_function_extent(*img, symbol_index_, root_for_extent, analysis_size);
                extent.has_value()) {
                const auto size = static_cast<std::size_t>(extent->size);
                if (const auto bytes = model_.read_virtual_bytes(extent->virtual_address, size);
                    bytes.has_value()) {
                    const auto window_off =
                        model_.virtual_address_to_offset(extent->virtual_address)
                            .value_or(extent->file_offset);
                    const GraphByteReader va_reader =
                        [this](std::uint64_t va, std::size_t len) -> std::vector<std::uint8_t> {
                        auto res = model_.read_virtual_bytes(va, len);
                        return res ? std::move(*res) : std::vector<std::uint8_t>{};
                    };
                    return build_function_cfg_call_graph(
                        *bytes,
                        *root_for_extent.virtual_address,
                        img->architecture(),
                        img->endianness(),
                        static_cast<std::size_t>(window_off),
                        root->name,
                        thumb_mode_,
                        extent->source == FunctionExtentSource::ExecutableRegion ||
                            extent->source == FunctionExtentSource::NextSymbol,
                        va_reader);
                }
            }
        }
    }

    if (model_.is_live_process()) {
        const GraphByteReader reader =
            [this](std::uint64_t offset, std::size_t length) -> std::vector<std::uint8_t> {
            if (const auto va = model_.offset_to_virtual_address(offset); va.has_value()) {
                if (auto vbytes = model_.read_virtual_bytes(*va, length); vbytes.has_value()) {
                    return std::move(*vbytes);
                }
            }
            auto sample = model_.read_window_sample(offset, length);
            if (!sample || sample->bytes.empty()) {
                return {};
            }
            std::size_t readable_prefix = 0u;
            while (readable_prefix < sample->valid.size() && sample->valid[readable_prefix] != 0u) {
                ++readable_prefix;
            }
            sample->bytes.resize(readable_prefix);
            return std::move(sample->bytes);
        };
        return build_symbol_fanout_call_graph(*img, reader, symbol_index_, *root);
    }

    return build_symbol_fanout_call_graph(*img, model_.bytes(), symbol_index_, *root);
}

void UiApp::fit_call_galaxy_camera(float viewport_w, float viewport_h) noexcept {
    call_galaxy_.camera.min_scale = 0.015;
    call_galaxy_.camera.max_scale = 80.0;
    const std::size_t n = call_galaxy_.ui_pos_x.size();
    if (n == 0u || call_galaxy_.ui_pos_y.size() < n ||
        viewport_w <= 1.0f || viewport_h <= 1.0f) {
        call_galaxy_.camera.center_x = 0.0;
        call_galaxy_.camera.center_y = 0.0;
        call_galaxy_.camera.scale_x = 1.0;
        call_galaxy_.camera.scale_y = 1.0;
        return;
    }

    float min_x = call_galaxy_.ui_pos_x[0];
    float max_x = call_galaxy_.ui_pos_x[0];
    float min_y = call_galaxy_.ui_pos_y[0];
    float max_y = call_galaxy_.ui_pos_y[0];
    for (std::size_t i = 1u; i < n; ++i) {
        min_x = std::min(min_x, call_galaxy_.ui_pos_x[i]);
        max_x = std::max(max_x, call_galaxy_.ui_pos_x[i]);
        min_y = std::min(min_y, call_galaxy_.ui_pos_y[i]);
        max_y = std::max(max_y, call_galaxy_.ui_pos_y[i]);
    }
    const double pad = std::max(40.0, 0.12 * std::max(max_x - min_x, max_y - min_y));
    call_galaxy_.camera.fit_bounds(
        static_cast<double>(min_x) - pad,
        static_cast<double>(min_y) - pad,
        static_cast<double>(max_x) + pad,
        static_cast<double>(max_y) + pad,
        static_cast<double>(viewport_w),
        static_cast<double>(viewport_h),
        true);
}

void UiApp::rebuild_call_galaxy_if_needed(float viewport_w, float viewport_h) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        if (!call_galaxy_.graph.empty()) {
            cancel_and_reset_call_galaxy();
        }
        return;
    }

    const bool ref_scanning =
        reference_index_.is_scanning() || reference_scanner_.is_scanning();
    const bool ref_just_finished = call_galaxy_.was_ref_scanning && !ref_scanning;
    call_galaxy_.was_ref_scanning = ref_scanning;

    std::optional<std::uint64_t> desired_root_va{};
    if (call_galaxy_.scope != GalaxyScopeMode::WholeBinary) {
        if (active_graph_root_.has_value() && active_graph_root_->virtual_address.has_value()) {
            desired_root_va = *active_graph_root_->virtual_address;
        } else if (current_selection_.virtual_address.has_value()) {
            desired_root_va = *current_selection_.virtual_address;
        }
    }

    const std::uint64_t cur_diff_rev = binary_diff_panel_.diff_revision();
    const std::size_t cur_sec_count = model_.security_audit().findings.size();

    const bool topology_stale =
        call_galaxy_.dirty ||
        call_galaxy_.built_file_generation != file_generation_ ||
        call_galaxy_.built_scope != call_galaxy_.scope ||
        call_galaxy_.built_edit_revision != model_.edit_revision() ||
        call_galaxy_.built_symbol_revision != symbol_revision_ ||
        (call_galaxy_.scope != GalaxyScopeMode::WholeBinary &&
         call_galaxy_.built_root_va != desired_root_va) ||
        (call_galaxy_.scope == GalaxyScopeMode::WholeBinary &&
         !ref_scanning &&
         call_galaxy_.built_ref_revision != reference_index_.revision()) ||
        ref_just_finished;

    if (!topology_stale) {
        if (call_galaxy_.built_diff_revision != cur_diff_rev ||
            call_galaxy_.built_security_finding_count != cur_sec_count) {
            std::vector<peelf::ByteVizDiffRange> diff_scratch{};
            const CallGalaxyBuildOptions overlay_opts =
                current_call_galaxy_overlay_options(diff_scratch);
            apply_call_galaxy_overlays(call_galaxy_.graph, img, overlay_opts);
            call_galaxy_.built_diff_revision = cur_diff_rev;
            call_galaxy_.built_security_finding_count = cur_sec_count;
        }
        return;
    }

    std::vector<peelf::ByteVizDiffRange> diff_scratch{};
    const CallGalaxyBuildOptions build_opts =
        current_call_galaxy_overlay_options(diff_scratch);

    CallGalaxyGraph rebuilt{};
    if (call_galaxy_.scope == GalaxyScopeMode::WholeBinary) {
        rebuilt = build_whole_binary_call_galaxy(
            *img,
            symbol_index_,
            model_.function_index(),
            reference_index_,
            build_opts);
    } else if (const auto scoped_cg = build_scoped_call_graph_for_galaxy(call_galaxy_.scope);
               scoped_cg.has_value()) {
        rebuilt = build_call_galaxy_from_call_graph(*scoped_cg, build_opts);
    }

    call_galaxy_.dirty = false;
    call_galaxy_.built_file_generation = file_generation_;
    call_galaxy_.built_ref_revision = reference_index_.revision();
    call_galaxy_.built_symbol_revision = symbol_revision_;
    call_galaxy_.built_edit_revision = model_.edit_revision();
    call_galaxy_.built_diff_revision = cur_diff_rev;
    call_galaxy_.built_security_finding_count = cur_sec_count;
    call_galaxy_.built_root_va = desired_root_va;
    call_galaxy_.built_scope = call_galaxy_.scope;

    call_galaxy_.graph = std::move(rebuilt);
    call_galaxy_.hovered_node.reset();
    call_galaxy_.dragged_node.reset();
    call_galaxy_.drag_moved = false;
    call_galaxy_.highlighted_path = {};
    call_galaxy_.trace_status.clear();

    // Preserve selection by virtual address across rebuilds when possible.
    call_galaxy_.selected_node.reset();
    call_galaxy_.ego_mask = {};
    if (current_selection_.virtual_address.has_value()) {
        if (const auto match =
                call_galaxy_.graph.find_node_at_va(*current_selection_.virtual_address);
            match.has_value()) {
            call_galaxy_.selected_node = *match;
            call_galaxy_.ego_mask =
                compute_ego_network_mask(call_galaxy_.graph, *match);
        }
    }

    BarnesHutLayoutConfig lcfg{};
    if (call_galaxy_.scope == GalaxyScopeMode::ActiveFunctionCfg) {
        lcfg.spring_length = 42.0f;
        lcfg.repulsion_strength = 920.0f;
        lcfg.gravity_strength = 0.032f;
    }

    BarnesHutGalaxyLayout initial_seeder{};
    initial_seeder.reset(call_galaxy_.graph, lcfg);
    // Run a tiny synchronous pre-relaxation on small graphs so CFGs look great on frame 1.
    if (call_galaxy_.graph.nodes.size() > 1u && call_galaxy_.graph.nodes.size() <= 256u) {
        call_galaxy_.last_stats = initial_seeder.step(24u);
    } else {
        call_galaxy_.last_stats = {};
    }
    call_galaxy_.ui_total_iterations = initial_seeder.total_iterations();
    const auto sx = initial_seeder.positions_x();
    const auto sy = initial_seeder.positions_y();
    const auto sp = initial_seeder.pinned_mask();
    call_galaxy_.ui_pos_x.assign(sx.begin(), sx.end());
    call_galaxy_.ui_pos_y.assign(sy.begin(), sy.end());
    call_galaxy_.ui_pinned.assign(sp.begin(), sp.end());
    call_galaxy_.layout_converged =
        (call_galaxy_.graph.nodes.size() <= 1u) || call_galaxy_.last_stats.converged;

    if (call_galaxy_.fit_requested) {
        fit_call_galaxy_camera(viewport_w, viewport_h);
        call_galaxy_.fit_requested = false;
    }

    ensure_call_galaxy_worker_started();
    {
        std::scoped_lock lock(call_galaxy_.worker_mutex);
        ++call_galaxy_.worker_generation;
        call_galaxy_.pending_seed_graph = call_galaxy_.graph;
        call_galaxy_.pending_seed_config = lcfg;
        call_galaxy_.pending_pin_commands.clear();
        call_galaxy_.pending_reheat = false;
        call_galaxy_.pending_unpin_all = false;
        call_galaxy_.worker_playing = call_galaxy_.layout_playing;
    }
    call_galaxy_.worker_cv.notify_all();
}

void UiApp::select_call_galaxy_node(std::uint32_t node_index, bool navigate_views) {
    if (node_index >= call_galaxy_.graph.nodes.size()) {
        return;
    }
    call_galaxy_.selected_node = node_index;
    call_galaxy_.ego_mask = compute_ego_network_mask(call_galaxy_.graph, node_index);

    const CallGalaxyNode& node = call_galaxy_.graph.nodes[node_index];
    if (node.virtual_address == 0u) {
        return;
    }

    if (navigate_views) {
        if (ImGui::GetIO().KeyCtrl) {
            InspectableEntity ent{};
            ent.va = node.virtual_address;
            if (const peelf::IBinaryImage* img = model_.image(); img != nullptr) {
                ent.file_offset = img->virtual_address_to_file_offset(node.virtual_address);
            }
            ent.size = node.size_bytes;
            ent.symbol_or_label = node.display_name;
            dispatch_entity_context_action(ContextActionKind::FollowInDecompiler, ent);
            return;
        }
        const PreferredView target_view =
            ImGui::GetIO().KeyAlt ? PreferredView::Hex : PreferredView::Disassembly;
        enqueue_navigation(node.virtual_address, target_view);
        return;
    }

    navigation_history_.visit(current_selection_);
    current_selection_.virtual_address = node.virtual_address;
    current_selection_.size = std::max<std::uint64_t>(node.size_bytes, 1u);
    current_selection_.label = node.display_name;
    current_selection_.preferred_view = PreferredView::Graph;
    if (const auto off = model_.virtual_address_to_offset(node.virtual_address);
        off.has_value()) {
        current_selection_.file_offset = *off;
        hex_panel_.navigate_to_range(
            clamp_to_size_t(*off),
            clamp_to_size_t(current_selection_.size));
        if (node.kind != GalaxyNodeKind::ExternalImport) {
            disassemble_at_offset(*off, node.virtual_address);
        }
    }
    last_navigation_selection_ = current_selection_;
}

void UiApp::render_call_galaxy_view() {
    ImGui::SameLine();
    ImGui::SetNextItemWidth(195.0f);
    const auto cur_scope_idx = static_cast<std::uint8_t>(call_galaxy_.scope);
    if (ImGui::BeginCombo("Scope##GalaxyScope", galaxy_scope_label(cur_scope_idx))) {
        for (std::uint8_t s = 0u; s < 3u; ++s) {
            const bool is_sel = (cur_scope_idx == s);
            if (ImGui::Selectable(galaxy_scope_label(s), is_sel)) {
                const auto next_scope = static_cast<GalaxyScopeMode>(s);
                if (call_galaxy_.scope != next_scope) {
                    call_galaxy_.scope = next_scope;
                    call_galaxy_.dirty = true;
                    call_galaxy_.fit_requested = true;
                }
            }
            if (is_sel) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(165.0f);
    if (ImGui::BeginCombo(
            "Color##GalaxyColor",
            galaxy_color_mode_label(call_galaxy_.color_mode))) {
        constexpr std::array<GalaxyColorMode, 5> kModes = {{
            GalaxyColorMode::OriginAndSection,
            GalaxyColorMode::EntryReachability,
            GalaxyColorMode::SecurityFindings,
            GalaxyColorMode::BinaryDiff,
            GalaxyColorMode::CallDegreeHeat,
        }};
        for (const GalaxyColorMode mode : kModes) {
            const bool is_sel = (call_galaxy_.color_mode == mode);
            if (ImGui::Selectable(galaxy_color_mode_label(mode), is_sel)) {
                call_galaxy_.color_mode = mode;
            }
            if (is_sel) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    if (ImGui::Button(call_galaxy_.layout_playing ? "Pause Layout" : "Play Layout")) {
        call_galaxy_.layout_playing = !call_galaxy_.layout_playing;
        {
            std::scoped_lock lock(call_galaxy_.worker_mutex);
            call_galaxy_.worker_playing = call_galaxy_.layout_playing;
        }
        call_galaxy_.worker_cv.notify_all();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reheat")) {
        call_galaxy_.layout_playing = true;
        call_galaxy_.layout_converged = false;
        {
            std::scoped_lock lock(call_galaxy_.worker_mutex);
            call_galaxy_.worker_playing = true;
            call_galaxy_.pending_reheat = true;
        }
        call_galaxy_.worker_cv.notify_all();
    }
    ImGui::SameLine();
    if (ImGui::Button("Fit##GalaxyFit")) {
        const ImVec2 avail = ImGui::GetContentRegionAvail();
        fit_call_galaxy_camera(std::max(avail.x, 64.0f), std::max(avail.y - 36.0f, 64.0f));
    }
    ImGui::SameLine();
    if (ImGui::Button("Rebuild##GalaxyRebuild")) {
        call_galaxy_.dirty = true;
        call_galaxy_.fit_requested = true;
    }

    const bool has_any_pinned = std::ranges::any_of(
        call_galaxy_.ui_pinned,
        [](std::uint8_t v) noexcept { return v != 0u; });
    if (has_any_pinned) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Unpin All")) {
            std::ranges::fill(call_galaxy_.ui_pinned, std::uint8_t{0u});
            call_galaxy_.layout_playing = true;
            {
                std::scoped_lock lock(call_galaxy_.worker_mutex);
                call_galaxy_.worker_playing = true;
                call_galaxy_.pending_unpin_all = true;
            }
            call_galaxy_.worker_cv.notify_all();
        }
    }

    // Second toolbar row: search, 1-hop spotlight, trace entry -> selected, labels, status.
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint(
        "##GalaxyFindNode",
        "Filter nodes (name or 0xVA)...",
        graph_search_,
        sizeof(graph_search_));
    ImGui::SameLine();
    ImGui::Checkbox("1-Hop Spotlight", &call_galaxy_.ego_spotlight);
    ImGui::SameLine();
    ImGui::Checkbox("Labels", &call_galaxy_.show_labels);

    const bool can_trace =
        call_galaxy_.selected_node.has_value() &&
        *call_galaxy_.selected_node < call_galaxy_.graph.nodes.size() &&
        !call_galaxy_.graph.primary_entry_nodes.empty();
    ImGui::SameLine();
    ImGui::BeginDisabled(!can_trace);
    if (ImGui::Button("Trace Entry -> Selected")) {
        call_galaxy_.highlighted_path = find_shortest_call_path_from_roots(
            call_galaxy_.graph,
            call_galaxy_.graph.primary_entry_nodes,
            *call_galaxy_.selected_node);
        const CallGalaxyNode& dst = call_galaxy_.graph.nodes[*call_galaxy_.selected_node];
        if (!call_galaxy_.highlighted_path.empty()) {
            const CallGalaxyNode& src =
                call_galaxy_.graph.nodes[call_galaxy_.highlighted_path.nodes.front()];
            call_galaxy_.trace_status = std::format(
                "{} -> {} ({} hop{})",
                src.display_name,
                dst.display_name,
                call_galaxy_.highlighted_path.edges.size(),
                call_galaxy_.highlighted_path.edges.size() == 1u ? "" : "s");
        } else {
            call_galaxy_.trace_status = std::format(
                "No directed call path from entry/export roots to {}",
                dst.display_name);
        }
    }
    ImGui::EndDisabled();

    if (!call_galaxy_.highlighted_path.empty() || !call_galaxy_.trace_status.empty()) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear Trace")) {
            call_galaxy_.highlighted_path = {};
            call_galaxy_.trace_status.clear();
        }
    }

    // Status & background reference-scan banner.
    {
        const char* sim_state =
            call_galaxy_.layout_converged
                ? "Converged"
                : (call_galaxy_.layout_playing ? "Barnes-Hut simulating" : "Layout paused");
        ImGui::TextDisabled(
            "%zu nodes  |  %zu edges  |  %s (iter %u, T=%.1f, disp=%.2f)  |  Wheel: zoom  Drag node: pin  Dbl-click: jump  Right-click: menu",
            call_galaxy_.graph.nodes.size(),
            call_galaxy_.graph.edges.size(),
            sim_state,
            call_galaxy_.ui_total_iterations,
            static_cast<double>(call_galaxy_.last_stats.temperature),
            static_cast<double>(call_galaxy_.last_stats.max_displacement));

        if (model_.image() != nullptr && reference_index_.total_executable_bytes() > 0u) {
            const bool scanning = reference_index_.is_scanning() || reference_scanner_.is_scanning();
            if (scanning || reference_index_.incomplete()) {
                ImGui::SameLine();
                ImGui::TextDisabled(
                    "| Xref scan %.1f%%",
                    reference_index_.coverage_percent());
                if (scanning) {
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Refresh Partial##galaxy_ref_now")) {
                        call_galaxy_.dirty = true;
                    }
                } else if (reference_index_.incomplete() &&
                           reference_scanner_.has_resumable_work()) {
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Scan Full Binary##galaxy_scan_full")) {
                        reference_scanner_.scan_full(reference_index_);
                    }
                }
            }
        }
    }

    if (!call_galaxy_.trace_status.empty()) {
        ImGui::TextColored(
            ImVec4(1.0f, 0.84f, 0.28f, 1.0f),
            "Call Trace: %s",
            call_galaxy_.trace_status.c_str());
        if (!call_galaxy_.highlighted_path.empty() &&
            call_galaxy_.highlighted_path.nodes.size() <= 12u) {
            for (std::size_t h = 0u; h < call_galaxy_.highlighted_path.nodes.size(); ++h) {
                const std::uint32_t ni = call_galaxy_.highlighted_path.nodes[h];
                if (ni >= call_galaxy_.graph.nodes.size()) {
                    continue;
                }
                if (h > 0u) {
                    ImGui::SameLine(0.0f, 4.0f);
                    ImGui::TextDisabled("->");
                }
                if (h > 0u) {
                    ImGui::SameLine(0.0f, 4.0f);
                }
                ImGui::PushID(static_cast<int>(h));
                if (ImGui::SmallButton(call_galaxy_.graph.nodes[ni].display_name.c_str())) {
                    select_call_galaxy_node(ni, false);
                    if (ni < call_galaxy_.ui_pos_x.size()) {
                        call_galaxy_.camera.center_x =
                            static_cast<double>(call_galaxy_.ui_pos_x[ni]);
                        call_galaxy_.camera.center_y =
                            static_cast<double>(call_galaxy_.ui_pos_y[ni]);
                    }
                }
                ImGui::PopID();
            }
        }
    }

    // Search match mask & compact jump results list.
    const std::string_view search_sv(graph_search_);
    const bool has_search = !search_sv.empty();
    std::vector<std::uint8_t> search_mask{};
    if (has_search && !call_galaxy_.graph.nodes.empty()) {
        search_mask.assign(call_galaxy_.graph.nodes.size(), 0u);
        std::vector<std::uint32_t> hit_indices{};
        for (const CallGalaxyNode& node : call_galaxy_.graph.nodes) {
            if (galaxy_node_matches_search(node, search_sv)) {
                search_mask[node.node_index] = 1u;
                if (hit_indices.size() < 64u) {
                    hit_indices.push_back(node.node_index);
                }
            }
        }
        if (!hit_indices.empty()) {
            ImGui::BeginChild("GalaxySearchHits", ImVec2(0.0f, 76.0f), true);
            for (const std::uint32_t ni : hit_indices) {
                const CallGalaxyNode& node = call_galaxy_.graph.nodes[ni];
                ImGui::PushID(static_cast<int>(ni));
                const std::string row_label =
                    (node.virtual_address != 0u)
                        ? std::format("0x{:X}  {}", node.virtual_address, node.display_name)
                        : node.display_name;
                if (ImGui::Selectable(row_label.c_str(), call_galaxy_.selected_node == ni)) {
                    select_call_galaxy_node(ni, false);
                    if (ni < call_galaxy_.ui_pos_x.size()) {
                        call_galaxy_.camera.center_x =
                            static_cast<double>(call_galaxy_.ui_pos_x[ni]);
                        call_galaxy_.camera.center_y =
                            static_cast<double>(call_galaxy_.ui_pos_y[ni]);
                    }
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
        }
    }

    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const ImVec2 canvas_size(std::max(avail.x, 64.0f), std::max(avail.y, 64.0f));
    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    const auto req_w = static_cast<std::uint32_t>(std::lround(canvas_size.x));
    const auto req_h = static_cast<std::uint32_t>(std::lround(canvas_size.y));

    rebuild_call_galaxy_if_needed(canvas_size.x, canvas_size.y);

    // Pull latest positions from Barnes-Hut worker (microsecond lock).
    {
        std::scoped_lock lock(call_galaxy_.worker_mutex);
        if (call_galaxy_.published_seq != call_galaxy_.consumed_seq &&
            call_galaxy_.published_generation == call_galaxy_.worker_generation &&
            call_galaxy_.published_pos_x.size() == call_galaxy_.graph.nodes.size()) {
            const std::optional<std::uint32_t> active_drag = call_galaxy_.dragged_node;
            float drag_x = 0.0f;
            float drag_y = 0.0f;
            if (active_drag.has_value() && *active_drag < call_galaxy_.ui_pos_x.size() &&
                call_galaxy_.drag_moved) {
                drag_x = call_galaxy_.ui_pos_x[*active_drag];
                drag_y = call_galaxy_.ui_pos_y[*active_drag];
            }
            call_galaxy_.ui_pos_x = call_galaxy_.published_pos_x;
            call_galaxy_.ui_pos_y = call_galaxy_.published_pos_y;
            call_galaxy_.ui_pinned = call_galaxy_.published_pinned;
            if (active_drag.has_value() && *active_drag < call_galaxy_.ui_pos_x.size() &&
                call_galaxy_.drag_moved) {
                call_galaxy_.ui_pos_x[*active_drag] = drag_x;
                call_galaxy_.ui_pos_y[*active_drag] = drag_y;
                call_galaxy_.ui_pinned[*active_drag] = 1u;
            }
            call_galaxy_.last_stats = call_galaxy_.published_stats;
            call_galaxy_.ui_total_iterations = call_galaxy_.published_total_iterations;
            call_galaxy_.layout_converged = call_galaxy_.published_converged;
            call_galaxy_.consumed_seq = call_galaxy_.published_seq;
        }
    }

    // Lazily initialize Vulkan offscreen canvas, ring buffers, and dual 2D SDF pipelines.
    if (!call_galaxy_.canvas_initialized && vulkan_.device() != VK_NULL_HANDLE) {
        try {
            call_galaxy_.canvas.init(
                vulkan_,
                GpuOffscreenCanvasConfig{
                    .sampler_filter = VK_FILTER_NEAREST,
                    .resize_debounce_frames = 2u,
                });
            call_galaxy_.edge_ring.attach(vulkan_, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT);
            call_galaxy_.node_ring.attach(vulkan_, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT);
            call_galaxy_.canvas_initialized = true;
        } catch (const std::exception& ex) {
            call_galaxy_.gpu_status =
                std::format("Call galaxy GPU canvas fallback: {}", ex.what());
            call_galaxy_.canvas_initialized = false;
        }
    }

    if (call_galaxy_.canvas_initialized) {
        (void)call_galaxy_.canvas.ensure_size(req_w, req_h);
        if (call_galaxy_.canvas.can_use_graphics() &&
            !call_galaxy_.pipelines_attempted) {
            call_galaxy_.pipelines_attempted = true;
            try {
                const std::array<VkVertexInputBindingDescription, 1> bindings = {{
                    VkVertexInputBindingDescription{
                        .binding = 0u,
                        .stride = sizeof(GalaxyEdgeGpuInstance),
                        .inputRate = VK_VERTEX_INPUT_RATE_INSTANCE,
                    },
                }};
                const std::array<VkVertexInputAttributeDescription, 2> attrs = {{
                    VkVertexInputAttributeDescription{
                        .location = 0u,
                        .binding = 0u,
                        .format = VK_FORMAT_R32G32B32A32_SFLOAT,
                        .offset = 0u,
                    },
                    VkVertexInputAttributeDescription{
                        .location = 1u,
                        .binding = 0u,
                        .format = VK_FORMAT_R32G32B32A32_UINT,
                        .offset = 16u,
                    },
                }};
                call_galaxy_.edge_pipeline.init(
                    vulkan_,
                    call_galaxy_.canvas.offscreen_render_pass(),
                    GpuGraphics2DPipelineDesc{
                        .vertex_spirv = shaders::kGalaxyEdgeVertSpirv,
                        .fragment_spirv = shaders::kGalaxyEdgeFragSpirv,
                        .vertex_bindings = bindings,
                        .vertex_attributes = attrs,
                        .push_constant_bytes = sizeof(shaders::CallGalaxyPushConstants),
                        .topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
                        .alpha_blend = true,
                    });
                call_galaxy_.node_pipeline.init(
                    vulkan_,
                    call_galaxy_.canvas.offscreen_render_pass(),
                    GpuGraphics2DPipelineDesc{
                        .vertex_spirv = shaders::kGalaxyNodeVertSpirv,
                        .fragment_spirv = shaders::kGalaxyNodeFragSpirv,
                        .vertex_bindings = bindings,
                        .vertex_attributes = attrs,
                        .push_constant_bytes = sizeof(shaders::CallGalaxyPushConstants),
                        .topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
                        .alpha_blend = true,
                    });
            } catch (const std::exception& ex) {
                call_galaxy_.gpu_status =
                    std::format("Call galaxy CPU RGBA8 fallback active: {}", ex.what());
            }
        }
    }

    const float eff_w =
        (call_galaxy_.canvas_initialized && call_galaxy_.canvas.valid())
            ? static_cast<float>(call_galaxy_.canvas.width())
            : canvas_size.x;
    const float eff_h =
        (call_galaxy_.canvas_initialized && call_galaxy_.canvas.valid())
            ? static_cast<float>(call_galaxy_.canvas.height())
            : canvas_size.y;

    ImGui::SetCursorScreenPos(canvas_pos);
    ImGui::InvisibleButton("CallGalaxyInteractiveCanvas", canvas_size);
    const bool canvas_hovered = ImGui::IsItemHovered();
    const bool canvas_active = ImGui::IsItemActive();
    const ImGuiIO& io = ImGui::GetIO();
    const float local_mx = io.MousePos.x - canvas_pos.x;
    const float local_my = io.MousePos.y - canvas_pos.y;

    if (canvas_hovered && !call_galaxy_.graph.empty()) {
        call_galaxy_.hovered_node = hit_test_galaxy_node(
            call_galaxy_.graph,
            call_galaxy_.ui_pos_x,
            call_galaxy_.ui_pos_y,
            call_galaxy_.camera,
            eff_w,
            eff_h,
            local_mx,
            local_my,
            4.0f);
    } else if (!call_galaxy_.dragged_node.has_value()) {
        call_galaxy_.hovered_node.reset();
    }

    // Cursor-anchored wheel zoom & middle-drag / background left-drag pan.
    if (canvas_hovered && io.MouseWheel != 0.0f) {
        const double factor = std::pow(1.16, static_cast<double>(io.MouseWheel));
        call_galaxy_.camera.zoom_at_screen_pixel(
            static_cast<double>(local_mx),
            static_cast<double>(local_my),
            factor,
            static_cast<double>(eff_w),
            static_cast<double>(eff_h));
    }

    if (canvas_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        if (call_galaxy_.hovered_node.has_value()) {
            call_galaxy_.dragged_node = *call_galaxy_.hovered_node;
            call_galaxy_.drag_moved = false;
            call_galaxy_.drag_start_mouse = io.MousePos;
        } else {
            call_galaxy_.dragged_node.reset();
            call_galaxy_.drag_moved = false;
        }
    }

    if (call_galaxy_.dragged_node.has_value() && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        const std::uint32_t dn = *call_galaxy_.dragged_node;
        const float dx = io.MousePos.x - call_galaxy_.drag_start_mouse.x;
        const float dy = io.MousePos.y - call_galaxy_.drag_start_mouse.y;
        const float thresh = io.MouseDragThreshold;
        if (dn < call_galaxy_.ui_pos_x.size() &&
            (call_galaxy_.drag_moved || (dx * dx + dy * dy) >= (thresh * thresh))) {
            call_galaxy_.drag_moved = true;
            const Vec2d world_pt = call_galaxy_.camera.screen_to_world(
                static_cast<double>(local_mx),
                static_cast<double>(local_my),
                static_cast<double>(eff_w),
                static_cast<double>(eff_h));
            const auto wx = static_cast<float>(world_pt.x);
            const auto wy = static_cast<float>(world_pt.y);
            call_galaxy_.ui_pos_x[dn] = wx;
            call_galaxy_.ui_pos_y[dn] = wy;
            if (dn < call_galaxy_.ui_pinned.size()) {
                call_galaxy_.ui_pinned[dn] = 1u;
            }
            {
                std::scoped_lock lock(call_galaxy_.worker_mutex);
                call_galaxy_.pending_pin_commands.push_back(GalaxyPinCommand{
                    .node_index = dn,
                    .pinned = true,
                    .world_x = wx,
                    .world_y = wy,
                });
            }
            call_galaxy_.worker_cv.notify_all();
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        }
    } else if (call_galaxy_.dragged_node.has_value() &&
               !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        const std::uint32_t dn = *call_galaxy_.dragged_node;
        if (!call_galaxy_.drag_moved && canvas_hovered) {
            select_call_galaxy_node(dn, false);
        }
        call_galaxy_.dragged_node.reset();
        call_galaxy_.drag_moved = false;
    } else if ((canvas_active && ImGui::IsMouseDragging(ImGuiMouseButton_Left) &&
                !call_galaxy_.dragged_node.has_value()) ||
               (canvas_hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle))) {
        call_galaxy_.camera.pan_by_pixels(
            static_cast<double>(io.MouseDelta.x),
            static_cast<double>(io.MouseDelta.y));
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
    }

    if (canvas_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
        call_galaxy_.hovered_node.has_value()) {
        select_call_galaxy_node(*call_galaxy_.hovered_node, true);
    }

    // Right-click universal InspectableEntity context menu.
    if (canvas_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right) &&
        call_galaxy_.hovered_node.has_value() &&
        *call_galaxy_.hovered_node < call_galaxy_.graph.nodes.size()) {
        const std::uint32_t ni = *call_galaxy_.hovered_node;
        select_call_galaxy_node(ni, false);
        const CallGalaxyNode& node = call_galaxy_.graph.nodes[ni];
        InspectableEntity ent{};
        if (node.virtual_address != 0u) {
            ent.va = node.virtual_address;
            if (const peelf::IBinaryImage* img = model_.image(); img != nullptr) {
                ent.file_offset = img->virtual_address_to_file_offset(node.virtual_address);
            }
        }
        ent.size = node.size_bytes;
        ent.symbol_or_label = node.display_name;
        ent.module_name = node.module_or_section;
        ent.extra_json_fields = {
            {"kind", std::string(to_string(node.kind))},
            {"in_degree", std::to_string(node.in_degree)},
            {"out_degree", std::to_string(node.out_degree)},
            {"reachability", std::string(to_string(node.reachability))},
            {"security", std::string(to_string(node.security_severity))},
            {"diff_status", std::string(to_string(node.diff_status))},
        };
        call_galaxy_.context_node = ni;
        call_galaxy_.context_entity = std::move(ent);
        ImGui::OpenPopup("##CallGalaxyNodeCtx");
    }

    std::optional<PendingEntityContextAction> pending_ctx{};
    if (ImGui::BeginPopup("##CallGalaxyNodeCtx")) {
        if (call_galaxy_.context_node.has_value() &&
            *call_galaxy_.context_node < call_galaxy_.graph.nodes.size()) {
            const std::uint32_t cni = *call_galaxy_.context_node;
            const CallGalaxyNode& cnode = call_galaxy_.graph.nodes[cni];
            ImGui::TextUnformatted(cnode.display_name.c_str());
            ImGui::Separator();

            if (call_galaxy_.context_entity.va.has_value() ||
                call_galaxy_.context_entity.file_offset.has_value()) {
                (void)draw_inspectable_entity_context_menu_items(
                    call_galaxy_.context_entity,
                    model_,
                    pending_ctx);
                ImGui::Separator();
            }

            const bool is_pinned =
                (cni < call_galaxy_.ui_pinned.size() && call_galaxy_.ui_pinned[cni] != 0u);
            if (ImGui::MenuItem(is_pinned ? "Unpin Node" : "Pin Node Position")) {
                const bool next_pin = !is_pinned;
                if (cni < call_galaxy_.ui_pinned.size()) {
                    call_galaxy_.ui_pinned[cni] = next_pin ? 1u : 0u;
                }
                const float wx = (cni < call_galaxy_.ui_pos_x.size()) ? call_galaxy_.ui_pos_x[cni] : 0.0f;
                const float wy = (cni < call_galaxy_.ui_pos_y.size()) ? call_galaxy_.ui_pos_y[cni] : 0.0f;
                {
                    std::scoped_lock lock(call_galaxy_.worker_mutex);
                    call_galaxy_.pending_pin_commands.push_back(GalaxyPinCommand{
                        .node_index = cni,
                        .pinned = next_pin,
                        .world_x = wx,
                        .world_y = wy,
                    });
                }
                call_galaxy_.worker_cv.notify_all();
            }

            if (!call_galaxy_.graph.primary_entry_nodes.empty() &&
                ImGui::MenuItem("Trace Entry -> This Node")) {
                call_galaxy_.highlighted_path = find_shortest_call_path_from_roots(
                    call_galaxy_.graph,
                    call_galaxy_.graph.primary_entry_nodes,
                    cni);
                call_galaxy_.trace_status =
                    !call_galaxy_.highlighted_path.empty()
                        ? std::format(
                              "Entry -> {} ({} hops)",
                              cnode.display_name,
                              call_galaxy_.highlighted_path.edges.size())
                        : std::format(
                              "No directed call path from entry roots to {}",
                              cnode.display_name);
            }

            if (cnode.virtual_address != 0u && cnode.kind != GalaxyNodeKind::ExternalImport) {
                if (ImGui::MenuItem("Focus Function CFG in Galaxy")) {
                    SymbolRecord root_rec{};
                    root_rec.name = cnode.display_name;
                    root_rec.raw_name = cnode.raw_name;
                    root_rec.virtual_address = cnode.virtual_address;
                    active_graph_root_ = std::move(root_rec);
                    call_galaxy_.scope = GalaxyScopeMode::ActiveFunctionCfg;
                    call_galaxy_.dirty = true;
                    call_galaxy_.fit_requested = true;
                }
                if (ImGui::MenuItem("Focus Symbol Fanout in Galaxy")) {
                    SymbolRecord root_rec{};
                    root_rec.name = cnode.display_name;
                    root_rec.raw_name = cnode.raw_name;
                    root_rec.virtual_address = cnode.virtual_address;
                    active_graph_root_ = std::move(root_rec);
                    call_galaxy_.scope = GalaxyScopeMode::ActiveSymbolFanout;
                    call_galaxy_.dirty = true;
                    call_galaxy_.fit_requested = true;
                }
            }
        }
        ImGui::EndPopup();
    }
    if (pending_ctx.has_value()) {
        dispatch_entity_context_action(pending_ctx->kind, pending_ctx->entity);
    }

    // Build GPU render batch for this frame.
    const GalaxyEgoMask* active_ego =
        (call_galaxy_.ego_spotlight && call_galaxy_.selected_node.has_value() &&
         call_galaxy_.ego_mask.focus_node == *call_galaxy_.selected_node)
            ? &call_galaxy_.ego_mask
            : nullptr;

    call_galaxy_.current_batch = build_galaxy_render_batch(
        call_galaxy_.graph,
        call_galaxy_.ui_pos_x,
        call_galaxy_.ui_pos_y,
        call_galaxy_.camera,
        GalaxyRenderBuildOptions{
            .viewport_width_px = eff_w,
            .viewport_height_px = eff_h,
            .color_mode = call_galaxy_.color_mode,
            .hovered_node = call_galaxy_.hovered_node.value_or(kInvalidGalaxyNode),
            .selected_node = call_galaxy_.selected_node.value_or(kInvalidGalaxyNode),
            .pinned_mask = call_galaxy_.ui_pinned,
            .ego_mask = active_ego,
            .highlighted_path = call_galaxy_.highlighted_path.empty()
                                    ? nullptr
                                    : &call_galaxy_.highlighted_path,
            .search_match_mask = search_mask,
            .has_active_search = has_search,
            .max_visible_edges = 65'536u,
            .max_labels = call_galaxy_.show_labels ? 48u : 0u,
        });

    if (call_galaxy_.canvas_initialized && call_galaxy_.canvas.valid()) {
        call_galaxy_.pending_push_constants = shaders::CallGalaxyPushConstants{
            .viewport_width = static_cast<float>(call_galaxy_.canvas.width()),
            .viewport_height = static_cast<float>(call_galaxy_.canvas.height()),
            .node_ring_width_px = 1.65f,
            .time_seconds = static_cast<float>(ImGui::GetTime()),
            .hovered_node_index = call_galaxy_.hovered_node.value_or(kInvalidGalaxyNode),
            .selected_node_index = call_galaxy_.selected_node.value_or(kInvalidGalaxyNode),
            .flags = 0u,
            .reserved = 0.0f,
        };
        call_galaxy_.needs_gpu_record_this_frame = true;
    }

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->PushClipRect(
        canvas_pos,
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        true);
    draw_list->AddRectFilled(
        canvas_pos,
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(12, 14, 20, 255));

    if (call_galaxy_.canvas_initialized && call_galaxy_.canvas.valid()) {
        draw_list->AddImage(
            call_galaxy_.canvas.imgui_texture_id(vulkan_.current_frame_index()),
            canvas_pos,
            ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y));
    }

    if (call_galaxy_.graph.empty()) {
        const char* empty_msg =
            (model_.image() == nullptr)
                ? "Open a PE/ELF/Mach-O binary or attach to a process to explore its Call Galaxy."
                : "No functions or call edges discovered in the selected scope yet.";
        const ImVec2 ts = ImGui::CalcTextSize(empty_msg);
        draw_list->AddText(
            ImVec2(canvas_pos.x + (canvas_size.x - ts.x) * 0.5f,
                   canvas_pos.y + (canvas_size.y - ts.y) * 0.5f),
            IM_COL32(156, 162, 178, 255),
            empty_msg);
    } else if (call_galaxy_.show_labels) {
        const float sx_ratio = canvas_size.x / std::max(1.0f, eff_w);
        const float sy_ratio = canvas_size.y / std::max(1.0f, eff_h);
        for (const GalaxyLabelCandidate& lbl : call_galaxy_.current_batch.labels) {
            if (lbl.node_index >= call_galaxy_.graph.nodes.size()) {
                continue;
            }
            const CallGalaxyNode& node = call_galaxy_.graph.nodes[lbl.node_index];
            std::string_view text = node.display_name;
            std::string truncated{};
            if (text.size() > 38u) {
                truncated = std::string(text.substr(0u, 35u)) + "...";
                text = truncated;
            }
            const ImVec2 ts = ImGui::CalcTextSize(text.data(), text.data() + text.size());
            const float lx =
                canvas_pos.x + lbl.screen_x_px * sx_ratio - ts.x * 0.5f;
            const float ly =
                canvas_pos.y + (lbl.screen_y_px + lbl.radius_px + 3.0f) * sy_ratio;

            const bool emph =
                (call_galaxy_.hovered_node == lbl.node_index) ||
                (call_galaxy_.selected_node == lbl.node_index);
            draw_list->AddRectFilled(
                ImVec2(lx - 3.0f, ly - 1.0f),
                ImVec2(lx + ts.x + 3.0f, ly + ts.y + 1.0f),
                emph ? IM_COL32(18, 22, 34, 232) : IM_COL32(12, 15, 24, 188),
                3.0f);
            draw_list->AddText(
                ImVec2(lx, ly),
                emph ? IM_COL32(255, 248, 214, 255) : IM_COL32(224, 230, 242, 238),
                text.data(),
                text.data() + text.size());
        }
    }

    draw_list->PopClipRect();

    // Rich hover tooltip.
    if (canvas_hovered && call_galaxy_.hovered_node.has_value() &&
        *call_galaxy_.hovered_node < call_galaxy_.graph.nodes.size() &&
        !ImGui::IsPopupOpen("##CallGalaxyNodeCtx")) {
        const std::uint32_t ni = *call_galaxy_.hovered_node;
        const CallGalaxyNode& node = call_galaxy_.graph.nodes[ni];
        ImGui::BeginTooltip();
        ImGui::Text("%s", node.display_name.c_str());
        if (!node.raw_name.empty() && node.raw_name != node.display_name) {
            ImGui::TextDisabled("Raw: %s", node.raw_name.c_str());
        }
        ImGui::Separator();
        if (node.virtual_address != 0u) {
            ImGui::Text(
                "VA: 0x%llX  |  Size: %llu B",
                static_cast<unsigned long long>(node.virtual_address),
                static_cast<unsigned long long>(node.size_bytes));
        }
        ImGui::Text(
            "Kind: %.*s  |  %s: %s",
            static_cast<int>(to_string(node.kind).size()),
            to_string(node.kind).data(),
            node.kind == GalaxyNodeKind::ExternalImport ? "Module" : "Section",
            node.module_or_section.empty() ? "-" : node.module_or_section.c_str());
        ImGui::Text(
            "Callers (in): %u  |  Callees (out): %u",
            node.in_degree,
            node.out_degree);
        ImGui::TextColored(
            galaxy_reachability_badge_color(node.reachability),
            "Reachability: %.*s",
            static_cast<int>(to_string(node.reachability).size()),
            to_string(node.reachability).data());
        if (node.security_severity != GalaxySecuritySeverity::None) {
            ImGui::TextColored(
                galaxy_security_badge_color(node.security_severity),
                "Security [%.*s]: %s",
                static_cast<int>(to_string(node.security_severity).size()),
                to_string(node.security_severity).data(),
                node.top_security_finding.c_str());
        }
        if (node.diff_status != GalaxyDiffStatus::Unchanged) {
            ImGui::TextColored(
                galaxy_diff_badge_color(node.diff_status),
                "Binary Diff: %.*s",
                static_cast<int>(to_string(node.diff_status).size()),
                to_string(node.diff_status).data());
        }
        const bool is_pinned =
            (ni < call_galaxy_.ui_pinned.size() && call_galaxy_.ui_pinned[ni] != 0u);
        ImGui::TextDisabled(
            "%sDouble-click: Disassembly (Ctrl: Decompile, Alt: Hex)  |  Right-click: Actions",
            is_pinned ? "[Pinned]  " : "");
        ImGui::EndTooltip();
    }
}

void UiApp::record_call_galaxy_pre_pass(VkCommandBuffer cmd, std::size_t frame_index) {
    if (!call_galaxy_.needs_gpu_record_this_frame) {
        return;
    }
    call_galaxy_.needs_gpu_record_this_frame = false;

    if (!call_galaxy_.canvas_initialized || !call_galaxy_.canvas.valid()) {
        return;
    }

    constexpr ColorFloat4 kClearColor{
        12.0f / 255.0f,
        14.0f / 255.0f,
        20.0f / 255.0f,
        1.0f,
    };

    const std::span<const GalaxyEdgeGpuInstance> edges(call_galaxy_.current_batch.edges);
    const std::span<const GalaxyNodeGpuInstance> nodes(call_galaxy_.current_batch.nodes);
    bool recorded_gpu = false;

    if (call_galaxy_.canvas.can_use_graphics() &&
        call_galaxy_.edge_pipeline.valid() &&
        call_galaxy_.node_pipeline.valid()) {
        try {
            if (!edges.empty()) {
                call_galaxy_.edge_ring.upload<GalaxyEdgeGpuInstance>(frame_index, edges);
            }
            if (!nodes.empty()) {
                call_galaxy_.node_ring.upload<GalaxyNodeGpuInstance>(frame_index, nodes);
            }
            const VkBuffer edge_vb =
                edges.empty() ? VK_NULL_HANDLE : call_galaxy_.edge_ring.buffer(frame_index);
            const VkBuffer node_vb =
                nodes.empty() ? VK_NULL_HANDLE : call_galaxy_.node_ring.buffer(frame_index);

            if ((edges.empty() || edge_vb != VK_NULL_HANDLE) &&
                (nodes.empty() || node_vb != VK_NULL_HANDLE)) {
                call_galaxy_.canvas.record_instanced_render_pass(
                    cmd,
                    frame_index,
                    kClearColor,
                    [&](VkCommandBuffer pass_cmd, VkExtent2D /*extent*/) {
                        const VkDeviceSize zero_offset = 0u;
                        if (!edges.empty()) {
                            vkCmdBindPipeline(
                                pass_cmd,
                                VK_PIPELINE_BIND_POINT_GRAPHICS,
                                call_galaxy_.edge_pipeline.pipeline());
                            vkCmdPushConstants(
                                pass_cmd,
                                call_galaxy_.edge_pipeline.pipeline_layout(),
                                VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT,
                                0u,
                                sizeof(call_galaxy_.pending_push_constants),
                                &call_galaxy_.pending_push_constants);
                            vkCmdBindVertexBuffers(pass_cmd, 0u, 1u, &edge_vb, &zero_offset);
                            vkCmdDraw(
                                pass_cmd,
                                6u,
                                static_cast<std::uint32_t>(edges.size()),
                                0u,
                                0u);
                        }
                        if (!nodes.empty()) {
                            vkCmdBindPipeline(
                                pass_cmd,
                                VK_PIPELINE_BIND_POINT_GRAPHICS,
                                call_galaxy_.node_pipeline.pipeline());
                            vkCmdPushConstants(
                                pass_cmd,
                                call_galaxy_.node_pipeline.pipeline_layout(),
                                VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT,
                                0u,
                                sizeof(call_galaxy_.pending_push_constants),
                                &call_galaxy_.pending_push_constants);
                            vkCmdBindVertexBuffers(pass_cmd, 0u, 1u, &node_vb, &zero_offset);
                            vkCmdDraw(
                                pass_cmd,
                                6u,
                                static_cast<std::uint32_t>(nodes.size()),
                                0u,
                                0u);
                        }
                    });
                recorded_gpu = true;
            }
        } catch (const std::exception&) {
            recorded_gpu = false;
        }
    }

    if (!recorded_gpu) {
        const CallGalaxyRasterConfig rcfg{
            .width = call_galaxy_.canvas.width(),
            .height = call_galaxy_.canvas.height(),
            .clear_rgba8 = pack_galaxy_rgba8(12u, 14u, 20u, 255u),
            .node_ring_width_px = call_galaxy_.pending_push_constants.node_ring_width_px,
        };
        rasterize_call_galaxy_rgba8_into(
            edges,
            nodes,
            rcfg,
            call_galaxy_.cpu_rgba8_scratch);
        call_galaxy_.canvas.record_cpu_rgba8_upload(
            cmd,
            frame_index,
            call_galaxy_.cpu_rgba8_scratch);
    }
}

} // namespace viewer
