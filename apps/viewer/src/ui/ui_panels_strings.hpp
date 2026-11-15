#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "analysis/reference_index.hpp"
#include "analysis/strings_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/symbol_index.hpp"
#include "ui_panel.hpp"

namespace viewer {

enum class StringReferrerTargetView : std::uint8_t {
    Disassembly,
    Decompile,
    FlowGraph,
    SyncAllOpen,
};

class StringsPanel final : public UiPanel {
public:
    StringsPanel(BinaryModel& model,
                 StringsIndex& strings,
                 const ReferenceIndex& references,
                 const AnnotationStore& annotations,
                 ViewerSelection& selection);

    void set_string_selected_callback(std::function<void(const ExtractedString&)> cb) {
        on_string_selected_ = std::move(cb);
    }
    void set_referrer_activated_callback(
        std::function<void(const StringReferrer&, StringReferrerTargetView)> cb) {
        on_referrer_activated_ = std::move(cb);
    }
    void set_rebuild_callback(std::function<void(std::size_t min_length, bool all_live_regions)> cb) {
        on_rebuild_ = std::move(cb);
    }

    [[nodiscard]] std::size_t requested_min_length() const noexcept {
        return static_cast<std::size_t>(min_length_ > 1 ? min_length_ : 1);
    }
    [[nodiscard]] bool scan_all_live_regions() const noexcept { return scan_all_live_regions_; }

    void reset_selection() noexcept { selected_string_va_.reset(); }

protected:
    void draw_contents() override;

private:
    BinaryModel& model_;
    StringsIndex& strings_;
    const ReferenceIndex& references_;
    const AnnotationStore& annotations_;
    ViewerSelection& selection_;

    std::function<void(const ExtractedString&)> on_string_selected_;
    std::function<void(const StringReferrer&, StringReferrerTargetView)> on_referrer_activated_;
    std::function<void(std::size_t, bool)> on_rebuild_;

    char filter_[256]{};
    int encoding_filter_ = 0;
    int section_filter_ = 0;
    int min_length_ = static_cast<int>(StringScanOptions::kDefaultMinLength);
    bool referenced_only_ = false;
    bool scan_all_live_regions_ = false;
    std::optional<std::uint64_t> selected_string_va_;
    std::optional<std::uint64_t> selected_referrer_va_;
};

} // namespace viewer
