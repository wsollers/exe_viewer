#pragma once
#include "ui_panel.hpp"
#include "analysis/reference_index.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/symbol_index.hpp"
#include <functional>
#include <optional>

namespace viewer {
class ReferencesPanel final : public UiPanel {
public:
    ReferencesPanel(const ReferenceIndex& index, AnnotationStore& annotations,
        const SymbolIndex& symbols, const ViewerSelection& selection);
    void set_navigate_callback(std::function<void(std::uint64_t)> callback) { navigate_ = std::move(callback); }
    void set_rebuild_callback(std::function<void()> callback) { rebuild_ = std::move(callback); }
protected:
    void draw_contents() override;
private:
    const ReferenceIndex& index_;
    AnnotationStore& annotations_;
    const SymbolIndex& symbols_;
    const ViewerSelection& selection_;
    std::function<void(std::uint64_t)> navigate_;
    std::function<void()> rebuild_;
    std::optional<std::uint64_t> editing_address_;
    std::uint64_t annotation_revision_ = 0;
    char filter_[256]{};
    char name_[256]{};
    char comment_[2048]{};
    int direction_ = 0;
};
} // namespace viewer
