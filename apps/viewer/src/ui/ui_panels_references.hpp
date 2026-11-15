#pragma once
#include "ui_panel.hpp"
#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/symbol_index.hpp"
#include <functional>
#include <optional>

namespace viewer {
class ReferencesPanel final : public UiPanel {
public:
    ReferencesPanel(const ReferenceIndex& index, AnnotationStore& annotations,
        const SymbolIndex& symbols, const ViewerSelection& selection);
    void set_model(BinaryModel* model) noexcept { model_ = model; }
    void set_scanner(const AsyncReferenceScanner* scanner) noexcept { scanner_ = scanner; }
    void set_navigate_callback(std::function<void(std::uint64_t)> callback) { navigate_ = std::move(callback); }
    void set_navigate_offset_callback(std::function<void(std::uint64_t)> callback) {
        navigate_offset_ = std::move(callback);
    }
    void set_rebuild_callback(std::function<void()> callback) { rebuild_ = std::move(callback); }
    void set_pause_callback(std::function<void()> callback) { pause_ = std::move(callback); }
    void set_resume_callback(std::function<void()> callback) { resume_ = std::move(callback); }
    void set_scan_full_callback(std::function<void()> callback) { scan_full_ = std::move(callback); }
protected:
    void draw_contents() override;
private:
    const ReferenceIndex& index_;
    BinaryModel* model_ = nullptr;
    const AsyncReferenceScanner* scanner_ = nullptr;
    AnnotationStore& annotations_;
    const SymbolIndex& symbols_;
    const ViewerSelection& selection_;
    std::function<void(std::uint64_t)> navigate_;
    std::function<void(std::uint64_t)> navigate_offset_;
    std::function<void()> rebuild_;
    std::function<void()> pause_;
    std::function<void()> resume_;
    std::function<void()> scan_full_;
    std::optional<std::uint64_t> editing_address_;
    std::uint64_t annotation_revision_ = 0;
    std::optional<std::pair<std::uint64_t, bool>> editing_bookmark_key_;
    std::uint64_t bookmark_revision_ = 0;
    char filter_[256]{};
    char name_[256]{};
    char comment_[2048]{};
    char bm_label_[256]{};
    char bm_category_[128]{};
    char bm_note_[1024]{};
    int direction_ = 0;
    int confidence_filter_ = 0;
};
} // namespace viewer
