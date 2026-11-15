#pragma once

#include "../analysis/reference_index.hpp"
#include "../model/binary_model.hpp"
#include "../navigation/viewer_navigation.hpp"
#include "../symbols/symbol_index.hpp"
#include "ui_panel.hpp"

#include <peelf/dependency_tree.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <string>

namespace viewer {

class DependenciesPanel : public UiPanel {
public:
    DependenciesPanel(BinaryModel& model,
                      const SymbolIndex& symbol_index,
                      const ReferenceIndex& reference_index,
                      ViewerSelection& selection);

    void invalidate() noexcept { graph_.reset(); }

protected:
    void draw_contents() override;

private:
    void rescan();
    [[nodiscard]] bool subtree_matches_filter(const peelf::DependencyTreeItem& item) const;
    void draw_tree_item(const peelf::DependencyTreeItem& item, const std::string& id_prefix);
    void draw_selected_details();
    void navigate_to_imported_symbol(const peelf::ImportedSymbolBinding& sym, bool prefer_caller);

    BinaryModel& model_;
    const SymbolIndex& symbol_index_;
    const ReferenceIndex& reference_index_;
    ViewerSelection& selection_;

    std::optional<peelf::DependencyGraph> graph_{};
    std::string cached_target_key_{};
    std::array<char, 512> extra_search_roots_{};
    std::array<char, 160> filter_text_{};
    bool issues_only_{false};
    bool include_system_dirs_{true};
    bool use_env_ld_path_{true};
    int max_depth_{8};

    std::size_t selected_node_id_{0};
    std::optional<std::size_t> selected_edge_index_{};
};

} // namespace viewer
