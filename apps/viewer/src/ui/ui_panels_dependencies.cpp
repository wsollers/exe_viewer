#include "ui_panels_dependencies.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <format>

namespace viewer {

namespace {

[[nodiscard]] bool icontains_dep(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > hay.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] ImVec4 status_color(peelf::DependencyResolutionStatus st) noexcept {
    switch (st) {
        case peelf::DependencyResolutionStatus::RootModule:
            return ImVec4(0.55f, 0.82f, 1.0f, 1.0f);
        case peelf::DependencyResolutionStatus::ResolvedOnDisk:
            return ImVec4(0.45f, 0.90f, 0.55f, 1.0f);
        case peelf::DependencyResolutionStatus::ResolvedInLiveProcess:
            return ImVec4(0.35f, 0.95f, 0.85f, 1.0f);
        case peelf::DependencyResolutionStatus::VirtualApiSet:
            return ImVec4(0.75f, 0.78f, 0.92f, 1.0f);
        case peelf::DependencyResolutionStatus::ArchitectureMismatch:
            return ImVec4(1.0f, 0.55f, 0.25f, 1.0f);
        case peelf::DependencyResolutionStatus::Unresolved:
            return ImVec4(1.0f, 0.38f, 0.38f, 1.0f);
        case peelf::DependencyResolutionStatus::CycleSkipped:
            return ImVec4(0.95f, 0.82f, 0.35f, 1.0f);
    }
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

[[nodiscard]] ImVec4 symbol_status_color(peelf::ImportedSymbolStatus st) noexcept {
    switch (st) {
        case peelf::ImportedSymbolStatus::BoundExport:
            return ImVec4(0.45f, 0.90f, 0.55f, 1.0f);
        case peelf::ImportedSymbolStatus::BoundForwardedExport:
            return ImVec4(0.45f, 0.85f, 0.95f, 1.0f);
        case peelf::ImportedSymbolStatus::BoundWeakOptional:
            return ImVec4(0.75f, 0.78f, 0.85f, 1.0f);
        case peelf::ImportedSymbolStatus::UnboundMissingExport:
            return ImVec4(1.0f, 0.38f, 0.38f, 1.0f);
        case peelf::ImportedSymbolStatus::UncheckedVirtualApiSet:
            return ImVec4(0.75f, 0.78f, 0.92f, 1.0f);
        case peelf::ImportedSymbolStatus::UncheckedTargetUnavailable:
            return ImVec4(0.95f, 0.75f, 0.35f, 1.0f);
    }
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

} // namespace

DependenciesPanel::DependenciesPanel(BinaryModel& model,
                                     const SymbolIndex& symbol_index,
                                     const ReferenceIndex& reference_index,
                                     ViewerSelection& selection)
    : UiPanel("Dependencies")
    , model_(model)
    , symbol_index_(symbol_index)
    , reference_index_(reference_index)
    , selection_(selection) {}

void DependenciesPanel::rescan() {
    if (!model_.has_file() || model_.image() == nullptr) {
        graph_.reset();
        return;
    }

    peelf::DependencyResolveOptions opts;
    opts.max_depth = static_cast<std::uint32_t>(std::clamp(max_depth_, 1, 16));
    opts.include_default_system_dirs = include_system_dirs_;
    opts.use_env_ld_library_path = use_env_ld_path_;
    opts.search_roots = peelf::parse_search_roots_list(extra_search_roots_.data());

    if (model_.is_live_process()) {
        if (const auto* active = model_.active_module(); active != nullptr && !active->path.empty()) {
            opts.root_path = active->path;
        } else if (model_.resolved_executable_path().has_value()) {
            opts.root_path = *model_.resolved_executable_path();
        }
    } else if (!model_.file_info().path.empty()) {
        opts.root_path = model_.file_info().path;
    }

    graph_ = peelf::build_dependency_graph(*model_.image(), opts, model_.process_session());
    selected_node_id_ = 0;
    selected_edge_index_.reset();
    if (graph_ && !graph_->root_tree.children.empty()) {
        selected_node_id_ = graph_->root_tree.children.front().node_id;
        selected_edge_index_ = graph_->root_tree.children.front().edge_index;
    }
}

bool DependenciesPanel::subtree_matches_filter(const peelf::DependencyTreeItem& item) const {
    if (!graph_ || item.node_id >= graph_->nodes.size()) {
        return false;
    }
    const auto& node = graph_->nodes[item.node_id];
    const std::string_view query(filter_text_.data());

    bool self_issue_ok = true;
    if (issues_only_ && item.depth > 0) {
        bool edge_has_missing_sym = false;
        if (item.edge_index.has_value() && *item.edge_index < graph_->edges.size()) {
            for (const auto& sb : graph_->edges[*item.edge_index].symbol_bindings) {
                if (sb.status == peelf::ImportedSymbolStatus::UnboundMissingExport) {
                    edge_has_missing_sym = true;
                    break;
                }
            }
        }
        self_issue_ok = (item.status == peelf::DependencyResolutionStatus::Unresolved ||
                         item.status == peelf::DependencyResolutionStatus::ArchitectureMismatch ||
                         edge_has_missing_sym ||
                         !node.unresolved_symbols.empty());
    }

    bool self_text_ok = query.empty() ||
                        icontains_dep(item.requested_name, query) ||
                        icontains_dep(node.display_name, query) ||
                        icontains_dep(node.resolved_path.generic_string(), query) ||
                        icontains_dep(node.soname, query);
    if (!self_text_ok && item.edge_index.has_value() && *item.edge_index < graph_->edges.size()) {
        for (const auto& sb : graph_->edges[*item.edge_index].symbol_bindings) {
            if (icontains_dep(sb.name, query)) {
                self_text_ok = true;
                break;
            }
        }
    }

    if (self_issue_ok && self_text_ok && item.depth > 0) {
        return true;
    }
    if (item.depth == 0 && !issues_only_ && self_text_ok) {
        return true;
    }
    for (const auto& child : item.children) {
        if (subtree_matches_filter(child)) {
            return true;
        }
    }
    return item.depth == 0;
}

void DependenciesPanel::draw_tree_item(const peelf::DependencyTreeItem& item,
                                       const std::string& id_prefix) {
    if (!graph_ || item.node_id >= graph_->nodes.size() || !subtree_matches_filter(item)) {
        return;
    }
    const auto& node = graph_->nodes[item.node_id];
    const bool has_visible_children = std::ranges::any_of(
        item.children, [&](const auto& c) { return subtree_matches_filter(c); });

    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_OpenOnDoubleClick |
                               ImGuiTreeNodeFlags_SpanAvailWidth;
    if (!has_visible_children) {
        flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    }
    if (item.depth <= 1) {
        flags |= ImGuiTreeNodeFlags_DefaultOpen;
    }
    const bool selected = (selected_node_id_ == item.node_id &&
                           selected_edge_index_ == item.edge_index);
    if (selected) {
        flags |= ImGuiTreeNodeFlags_Selected;
    }

    std::size_t missing_syms = node.unresolved_symbols.size();
    if (item.edge_index.has_value() && *item.edge_index < graph_->edges.size()) {
        missing_syms = static_cast<std::size_t>(std::ranges::count_if(
            graph_->edges[*item.edge_index].symbol_bindings,
            [](const peelf::ImportedSymbolBinding& b) {
                return b.status == peelf::ImportedSymbolStatus::UnboundMissingExport;
            }));
    }

    std::string label = item.requested_name.empty() ? node.display_name : item.requested_name;
    if (item.edge_kind == peelf::DependencyEdgeKind::DelayLoadImport) {
        label += " [delay-load]";
    } else if (item.edge_kind == peelf::DependencyEdgeKind::ForwardedExport) {
        label += " [forwarder]";
    } else if (item.edge_kind == peelf::DependencyEdgeKind::DynamicLinkerInterp) {
        label += " [PT_INTERP]";
    }
    if (item.is_cycle) {
        label += " [cycle]";
    } else if (item.is_diamond_ref) {
        label += " [shared]";
    }
    if (item.truncated_by_depth) {
        label += " [max-depth]";
    }

    const std::string tree_id = std::format("{}#{}", id_prefix, item.node_id);
    ImGui::PushStyleColor(ImGuiCol_Text, status_color(item.status));
    const bool open = ImGui::TreeNodeEx(
        tree_id.c_str(),
        flags,
        "%s  [%s]%s",
        label.c_str(),
        std::string(peelf::to_string(item.status)).c_str(),
        missing_syms > 0 ? std::format("  (!{} missing sym)", missing_syms).c_str() : "");
    ImGui::PopStyleColor();

    if (ImGui::IsItemClicked()) {
        selected_node_id_ = item.node_id;
        selected_edge_index_ = item.edge_index;
    }

    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Requested: %s", item.requested_name.c_str());
        if (!node.resolved_path.empty()) {
            ImGui::Text("Resolved:  %s", node.resolved_path.string().c_str());
        }
        const std::string& reason =
            (item.edge_index.has_value() && *item.edge_index < graph_->edges.size())
                ? graph_->edges[*item.edge_index].resolution_reason
                : node.resolution_reason;
        ImGui::TextWrapped("Provenance: %s", reason.c_str());
        ImGui::EndTooltip();
    }

    if (open && has_visible_children) {
        for (std::size_t idx = 0; idx < item.children.size(); ++idx) {
            draw_tree_item(item.children[idx], std::format("{}.{}", tree_id, idx));
        }
        ImGui::TreePop();
    }
}

void DependenciesPanel::navigate_to_imported_symbol(const peelf::ImportedSymbolBinding& sym,
                                                    bool prefer_caller) {
    if (model_.image() == nullptr) {
        return;
    }
    const std::uint64_t ptr_sz = model_.image()->is_64bit() ? 8u : 4u;
    std::uint64_t target_va = sym.call_site_va;

    if (target_va == 0 && !sym.name.empty()) {
        for (const std::string& cand : {sym.name, sym.name + "@plt", sym.name + "@got"}) {
            if (const auto* rec = symbol_index_.find_by_name(cand);
                rec != nullptr && rec->virtual_address.has_value()) {
                target_va = *rec->virtual_address;
                break;
            }
        }
    }

    if (prefer_caller && target_va != 0) {
        auto callers = reference_index_.incoming(target_va, ptr_sz);
        if (callers.empty() && !sym.name.empty()) {
            if (const auto* plt_rec = symbol_index_.find_by_name(sym.name + "@plt");
                plt_rec != nullptr && plt_rec->virtual_address.has_value()) {
                callers = reference_index_.incoming(*plt_rec->virtual_address, 16);
            }
        }
        if (!callers.empty()) {
            const std::uint64_t caller_va = callers.front()->source;
            selection_ = ViewerSelection{
                .kind = SelectionKind::ByteRange,
                .label = std::format("Caller of {}", sym.name),
                .file_offset = model_.image()->virtual_address_to_file_offset(caller_va),
                .virtual_address = caller_va,
                .size = 4,
                .object_index = 0,
                .preferred_view = PreferredView::Disassembly,
                .graph_root = std::nullopt,
            };
            return;
        }
    }

    if (target_va != 0) {
        selection_ = ViewerSelection{
            .kind = SelectionKind::Import,
            .label = std::format("Import {}", sym.name),
            .file_offset = model_.image()->virtual_address_to_file_offset(target_va),
            .virtual_address = target_va,
            .size = ptr_sz,
            .object_index = 0,
            .preferred_view = PreferredView::Disassembly,
            .graph_root = std::nullopt,
        };
    }
}

void DependenciesPanel::draw_selected_details() {
    if (!graph_ || selected_node_id_ >= graph_->nodes.size()) {
        ImGui::TextDisabled("Select a library node in the dependency tree.");
        return;
    }

    const auto& node = graph_->nodes[selected_node_id_];
    const peelf::DependencyEdge* edge =
        (selected_edge_index_.has_value() && *selected_edge_index_ < graph_->edges.size())
            ? &graph_->edges[*selected_edge_index_]
            : nullptr;

    ImGui::TextColored(status_color(edge ? edge->resolution_status : node.status),
                       "%s  [%s]",
                       node.display_name.c_str(),
                       std::string(peelf::to_string(edge ? edge->resolution_status : node.status)).c_str());

    if (!node.resolved_path.empty()) {
        ImGui::TextWrapped("Path: %s", node.resolved_path.string().c_str());
    }
    if (node.format != peelf::Format::Unknown) {
        ImGui::Text("Target: %s | %s-bit %s (%s) | Exports: %zu",
                    std::string(peelf::to_string(node.format)).c_str(),
                    node.is_64bit ? "64" : "32",
                    std::string(peelf::to_string(node.architecture)).c_str(),
                    node.endianness == peelf::Endianness::Big ? "Big-Endian" : "Little-Endian",
                    node.export_count);
    }
    if (node.live_base_va.has_value()) {
        ImGui::SameLine();
        ImGui::Text("| Live Base: 0x%llx", static_cast<unsigned long long>(*node.live_base_va));
    }
    if (!node.soname.empty()) {
        ImGui::Text("DT_SONAME: %s", node.soname.c_str());
    }
    if (!node.elf_interpreter.empty()) {
        ImGui::Text("PT_INTERP: %s", node.elf_interpreter.c_str());
    }

    const std::string& reason = edge ? edge->resolution_reason : node.resolution_reason;
    ImGui::TextWrapped("Provenance: %s", reason.c_str());

    const auto& assumptions = edge ? edge->origin_assumptions : node.origin_assumptions;
    if (!assumptions.empty()) {
        ImGui::TextDisabled("Token Expansion:");
        for (const std::string& a : assumptions) {
            ImGui::BulletText("%s", a.c_str());
        }
    }

    const auto& searched = edge ? edge->searched_paths : node.searched_paths;
    if (!searched.empty() && ImGui::TreeNode("Searched Candidate Paths",
                                             "Searched Candidate Paths (%zu)",
                                             searched.size())) {
        for (std::size_t i = 0; i < searched.size(); ++i) {
            ImGui::Text("%zu. %s", i + 1, searched[i].string().c_str());
        }
        ImGui::TreePop();
    }

    ImGui::Separator();

    const std::vector<peelf::ImportedSymbolBinding>& syms =
        edge != nullptr ? edge->symbol_bindings : node.unresolved_symbols;
    ImGui::Text("Imported Symbol Bindings (%zu)", syms.size());
    if (syms.empty()) {
        ImGui::TextDisabled(edge != nullptr
                                ? "No direct symbol bindings attributed to this edge."
                                : "Select a dependency edge to inspect its imported symbols.");
        return;
    }

    const ImGuiTableFlags tflags = ImGuiTableFlags_Borders |
                                   ImGuiTableFlags_RowBg |
                                   ImGuiTableFlags_Resizable |
                                   ImGuiTableFlags_ScrollY |
                                   ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("DepSymbolBindings", 6, tflags, ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch, 2.2f);
        ImGui::TableSetupColumn("Binding Status", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("IAT / GOT VA", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableSetupColumn("Export VA", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableSetupColumn("Notes / Forwarder", ImGuiTableColumnFlags_WidthStretch, 1.8f);
        ImGui::TableSetupColumn("Jump", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableHeadersRow();

        const std::string_view q(filter_text_.data());
        for (std::size_t i = 0; i < syms.size(); ++i) {
            const auto& sym = syms[i];
            if (issues_only_ && sym.status != peelf::ImportedSymbolStatus::UnboundMissingExport) {
                continue;
            }
            if (!q.empty() && !icontains_dep(sym.name, q) && !icontains_dep(sym.forwarded_to, q)) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));

            ImGui::TableSetColumnIndex(0);
            std::string sym_label = sym.name;
            if (sym.delay_load) {
                sym_label += " [delay]";
            }
            if (ImGui::Selectable(sym_label.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                navigate_to_imported_symbol(sym, false);
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(symbol_status_color(sym.status),
                               "%s",
                               std::string(peelf::to_string(sym.status)).c_str());

            ImGui::TableSetColumnIndex(2);
            if (sym.call_site_va != 0) {
                ImGui::Text("0x%llx", static_cast<unsigned long long>(sym.call_site_va));
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableSetColumnIndex(3);
            if (sym.resolved_export_va != 0) {
                ImGui::Text("0x%llx", static_cast<unsigned long long>(sym.resolved_export_va));
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableSetColumnIndex(4);
            if (!sym.forwarded_to.empty()) {
                ImGui::Text("-> %s", sym.forwarded_to.c_str());
            } else if (!sym.note.empty()) {
                ImGui::TextUnformatted(sym.note.c_str());
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableSetColumnIndex(5);
            if (ImGui::SmallButton("Slot")) {
                navigate_to_imported_symbol(sym, false);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Caller")) {
                navigate_to_imported_symbol(sym, true);
            }

            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

void DependenciesPanel::draw_contents() {
    if (!model_.has_file() || model_.image() == nullptr) {
        graph_.reset();
        cached_target_key_.clear();
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a live process to inspect dependencies.");
        return;
    }

    const std::string cur_key = std::format(
        "{}|{}|{}",
        model_.file_info().path,
        model_.is_live_process() ? 1 : 0,
        model_.active_module() ? model_.active_module()->base_address : 0ull);
    if (!graph_.has_value() || cur_key != cached_target_key_) {
        cached_target_key_ = cur_key;
        rescan();
    }

    // Summary KPI strip
    if (graph_.has_value()) {
        const auto& s = graph_->summary;
        ImGui::Text("Direct: %zu  |  Transitive: %zu  |  Resolved: %zu  |  Virtual API-Sets: %zu",
                    s.direct_dependencies,
                    s.transitive_dependencies,
                    s.resolved_count,
                    s.virtual_api_sets);
        ImGui::SameLine();
        ImGui::TextColored(s.missing_libraries > 0 ? ImVec4(1.0f, 0.38f, 0.38f, 1.0f)
                                                   : ImVec4(0.6f, 0.8f, 0.6f, 1.0f),
                           " | Missing Libs: %zu",
                           s.missing_libraries);
        ImGui::SameLine();
        ImGui::TextColored(s.architecture_mismatches > 0 ? ImVec4(1.0f, 0.55f, 0.25f, 1.0f)
                                                         : ImVec4(0.6f, 0.8f, 0.6f, 1.0f),
                           " | Arch Mismatches: %zu",
                           s.architecture_mismatches);
        ImGui::SameLine();
        ImGui::TextColored(s.unresolved_symbols > 0 ? ImVec4(1.0f, 0.38f, 0.38f, 1.0f)
                                                    : ImVec4(0.6f, 0.8f, 0.6f, 1.0f),
                           " | Unresolved Symbols: %zu",
                           s.unresolved_symbols);
    }

    // Search roots & controls
    ImGui::SetNextItemWidth(340.0f);
    ImGui::InputTextWithHint("##DepExtraRoots",
                             "Extra search roots (; or : separated)",
                             extra_search_roots_.data(),
                             extra_search_roots_.size());
    ImGui::SameLine();
    ImGui::Checkbox("System dirs", &include_system_dirs_);
    ImGui::SameLine();
    ImGui::Checkbox("LD_LIBRARY_PATH", &use_env_ld_path_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70.0f);
    ImGui::SliderInt("Depth", &max_depth_, 1, 12);
    ImGui::SameLine();
    if (ImGui::Button("Re-scan")) {
        rescan();
    }

    // Filter bar
    ImGui::SetNextItemWidth(260.0f);
    ImGui::InputTextWithHint("##DepFilter",
                             "Filter library, path, or symbol...",
                             filter_text_.data(),
                             filter_text_.size());
    ImGui::SameLine();
    ImGui::Checkbox("Missing / Issues only", &issues_only_);
    ImGui::Separator();

    if (!graph_.has_value()) {
        return;
    }

    const float avail_w = ImGui::GetContentRegionAvail().x;
    const float left_w = std::max(260.0f, avail_w * 0.40f);
    if (ImGui::BeginChild("DepTreePane", ImVec2(left_w, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeX)) {
        draw_tree_item(graph_->root_tree, "root");
    }
    ImGui::EndChild();

    ImGui::SameLine();

    if (ImGui::BeginChild("DepDetailsPane", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        draw_selected_details();
    }
    ImGui::EndChild();
}

} // namespace viewer
