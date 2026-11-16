#pragma once

#include <peelf/capability_matrix.hpp>
#include <peelf/provenance.hpp>

#include "model/binary_model.hpp"
#include "ui_panel.hpp"

#include <span>
#include <string_view>

namespace viewer {

namespace ui_provenance {

void draw_provenance_badge(peelf::ProvenanceTag tag, std::string_view detail = {});
void draw_evidence_badges(std::span<const peelf::Evidence> evidence);
void draw_capture_stamp_badge(std::string_view collection_label, const peelf::CaptureStamp& stamp);
void draw_backing_identity_banner(const peelf::BackingIdentityMatchResult& match);
void draw_capability_state_badge(const peelf::Capability& cap);

}  // namespace ui_provenance

class CapabilityMatrixPanel final : public UiPanel {
public:
    explicit CapabilityMatrixPanel(BinaryModel& model);

protected:
    void draw_contents() override;

private:
    BinaryModel& model_;
    char filter_buf_[128]{};
    int state_filter_{0};  // 0 = All, 1 = Validated, 2 = Experimental/Partial, 3 = Unsupported
};

}  // namespace viewer
