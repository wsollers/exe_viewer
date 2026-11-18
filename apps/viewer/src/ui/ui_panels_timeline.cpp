#include "panel_helpers.hpp"
#include "ui_panels_timeline.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

namespace viewer {
namespace {

constexpr std::array<const char*, 4> kCapacityLabels = {
    "1,024 events",
    "4,096 events",
    "16,384 events",
    "65,536 events",
};

constexpr std::array<std::size_t, 4> kCapacityValues = {
    1024u,
    4096u,
    16384u,
    65536u,
};

struct KindChipSpec {
    peelf::TimelineEventKind kind;
    const char* short_label;
};

constexpr std::array<KindChipSpec, peelf::kTimelineEventKindCount> kKindChipSpecs = {{
    {peelf::TimelineEventKind::DebuggerEvent, "Debugger"},
    {peelf::TimelineEventKind::ModuleDelta, "Module"},
    {peelf::TimelineEventKind::RegionDelta, "Region"},
    {peelf::TimelineEventKind::ThreadDelta, "Thread"},
    {peelf::TimelineEventKind::HandleDelta, "Handle"},
    {peelf::TimelineEventKind::SocketDelta, "Socket"},
    {peelf::TimelineEventKind::SyscallEntry, "Syscall In"},
    {peelf::TimelineEventKind::SyscallExit, "Syscall Out"},
    {peelf::TimelineEventKind::DroppedEvents, "Dropped"},
    {peelf::TimelineEventKind::SamplingGap, "Sampling Gap"},
}};

[[nodiscard]] bool icontains_sv(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    const auto it = std::ranges::search(hay, needle, [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    });
    return !it.empty();
}

[[nodiscard]] ImVec4 event_kind_color(peelf::TimelineEventKind kind) noexcept {
    switch (kind) {
        case peelf::TimelineEventKind::DebuggerEvent:
            return ImVec4(0.35f, 0.78f, 1.00f, 1.00f);
        case peelf::TimelineEventKind::ModuleDelta:
            return ImVec4(0.45f, 0.92f, 0.55f, 1.00f);
        case peelf::TimelineEventKind::RegionDelta:
            return ImVec4(0.72f, 0.62f, 1.00f, 1.00f);
        case peelf::TimelineEventKind::ThreadDelta:
            return ImVec4(0.98f, 0.78f, 0.35f, 1.00f);
        case peelf::TimelineEventKind::HandleDelta:
            return ImVec4(0.92f, 0.62f, 0.42f, 1.00f);
        case peelf::TimelineEventKind::SocketDelta:
            return ImVec4(0.35f, 0.90f, 0.85f, 1.00f);
        case peelf::TimelineEventKind::SyscallEntry:
            return ImVec4(0.82f, 0.85f, 0.42f, 1.00f);
        case peelf::TimelineEventKind::SyscallExit:
            return ImVec4(0.68f, 0.78f, 0.42f, 1.00f);
        case peelf::TimelineEventKind::DroppedEvents:
            return ImVec4(1.00f, 0.40f, 0.40f, 1.00f);
        case peelf::TimelineEventKind::SamplingGap:
            return ImVec4(1.00f, 0.75f, 0.25f, 1.00f);
    }
    return ImVec4(0.80f, 0.80f, 0.80f, 1.00f);
}

[[nodiscard]] ImU32 to_u32_color(const ImVec4& c, float alpha_scale = 1.0f) noexcept {
    ImVec4 scaled = c;
    scaled.w = std::clamp(scaled.w * alpha_scale, 0.0f, 1.0f);
    return ImGui::ColorConvertFloat4ToU32(scaled);
}

[[nodiscard]] ImVec4 support_state_color(peelf::SupportState state, bool active) noexcept {
    switch (state) {
        case peelf::SupportState::SupportedValidated:
            return active ? ImVec4(0.38f, 0.90f, 0.52f, 1.00f)
                          : ImVec4(0.75f, 0.82f, 0.78f, 1.00f);
        case peelf::SupportState::SupportedExperimental:
        case peelf::SupportState::Partial:
            return ImVec4(0.98f, 0.78f, 0.30f, 1.00f);
        case peelf::SupportState::Unsupported:
            return ImVec4(0.68f, 0.68f, 0.72f, 1.00f);
    }
    return ImVec4(0.68f, 0.68f, 0.72f, 1.00f);
}

[[nodiscard]] std::string format_stamp_or_interval(const peelf::TimelineEvent& ev) {
    if (ev.observation_interval.has_value()) {
        const std::uint64_t r0 = ev.observation_interval->earliest.snapshot_revision;
        const std::uint64_t r1 = ev.observation_interval->latest.snapshot_revision;
        const std::uint64_t dur_ns = ev.observation_interval->duration_ns();
        if (dur_ns > 0u) {
            const double dur_ms = static_cast<double>(dur_ns) / 1'000'000.0;
            return std::format("[rev {}..{}] (~{:.2f} ms)", r0, r1, dur_ms);
        }
        return std::format("[rev {}..{}]", r0, r1);
    }
    if (ev.stamp.snapshot_revision != 0u) {
        return std::format("rev {}", ev.stamp.snapshot_revision);
    }
    return "instant";
}

[[nodiscard]] std::string format_lane_title(const peelf::TimelineLane& lane) {
    std::string label = !lane.name.empty()
                            ? std::format("TID {} #{} ({})",
                                          lane.identity.tid,
                                          lane.identity.epoch,
                                          lane.name)
                            : std::format("TID {} #{}",
                                          lane.identity.tid,
                                          lane.identity.epoch);
    if (lane.tid_recycled) {
        label += " [recycled]";
    }
    if (!lane.active) {
        label += " [exited]";
    }
    return label;
}

[[nodiscard]] std::string format_lane_badge(const peelf::TimelineEvent& ev) {
    if (!ev.thread.has_value()) {
        return "Process / Global";
    }
    return std::format("TID {} #{}", ev.thread->tid, ev.thread->epoch);
}

[[nodiscard]] std::size_t preset_index_for_capacity(std::size_t cap) noexcept {
    for (std::size_t i = 0u; i < kCapacityValues.size(); ++i) {
        if (kCapacityValues[i] == cap) {
            return i;
        }
    }
    return 1u;
}

struct TidEpochKey {
    peelf::ThreadId tid{0};
    std::uint64_t epoch{0};
    bool operator==(const TidEpochKey&) const noexcept = default;
};

struct TidEpochKeyHash {
    std::size_t operator()(const TidEpochKey& key) const noexcept {
        const std::size_t h1 = std::hash<peelf::ThreadId>{}(key.tid);
        const std::size_t h2 = std::hash<std::uint64_t>{}(key.epoch);
        return h1 ^ (h2 + 0x9E3779B97F4A7C15ULL + (h1 << 6u) + (h1 >> 2u));
    }
};

} // namespace

ExecutionTimelinePanel::ExecutionTimelinePanel(BinaryModel& model,
                                               NavigateTargetCallback on_navigate)
    : UiPanel("Execution Timeline"),
      model_(model),
      on_navigate_(std::move(on_navigate)) {
    visible_ = false;
    kind_enabled_.fill(true);
}

void ExecutionTimelinePanel::reset_for_new_target() noexcept {
    selected_sequence_.reset();
    pending_navigation_.reset();
    pending_select_tid_.reset();
    lane_filter_.reset();
    global_lane_only_ = false;
    pending_record_snapshot_delta_ = false;
    pending_clear_timeline_ = false;
    pending_capacity_change_.reset();
    status_message_.clear();
}

bool ExecutionTimelinePanel::passes_filter(const peelf::TimelineEvent& ev) const {
    const auto kidx = static_cast<std::size_t>(ev.kind);
    if (kidx < kind_enabled_.size() && !kind_enabled_[kidx]) {
        return false;
    }

    if (global_lane_only_) {
        if (ev.thread.has_value()) {
            return false;
        }
    } else if (lane_filter_.has_value()) {
        if (!ev.thread.has_value() || !ev.thread->same_lane(*lane_filter_)) {
            return false;
        }
    }

    const std::string_view query(text_filter_.data());
    if (!query.empty()) {
        const std::string kind_sv{peelf::to_string(ev.kind)};
        const std::string lane_sv = format_lane_badge(ev);
        bool addr_match = false;
        if (ev.virtual_address.has_value()) {
            const std::string hex_va = std::format("0x{:X}", *ev.virtual_address);
            addr_match = icontains_sv(hex_va, query);
        }
        if (!icontains_sv(ev.summary, query) &&
            !icontains_sv(kind_sv, query) &&
            !icontains_sv(lane_sv, query) &&
            !addr_match) {
            return false;
        }
    }
    return true;
}

const peelf::TimelineEvent* ExecutionTimelinePanel::find_selected_event() const noexcept {
    if (!selected_sequence_.has_value()) {
        return nullptr;
    }
    for (const peelf::TimelineEvent& ev : model_.execution_timeline().events()) {
        if (ev.sequence == *selected_sequence_) {
            return &ev;
        }
    }
    return nullptr;
}

void ExecutionTimelinePanel::dispatch_navigation(
    const peelf::TimelineNavigationTarget& target) {
    if (on_navigate_) {
        on_navigate_(target);
    }
}

void ExecutionTimelinePanel::draw_toolbar_and_banners() {
    const peelf::ExecutionTimeline& timeline = model_.execution_timeline();
    const bool can_capture_live = model_.is_live_process() && !model_.is_crash_dump();

    ImGui::BeginDisabled(!can_capture_live);
    const char* record_btn_label =
        model_.captured_snapshots().empty()
            ? "Capture Baseline Snapshot"
            : "Record Snapshot Delta";
    if (ImGui::Button(record_btn_label)) {
        pending_record_snapshot_delta_ = true;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip(
            "Captures a ProcessStateSnapshot; consecutive captures automatically diff and append "
            "timestamped deltas (plus explicit SamplingGap markers across non-continuous intervals) "
            "into ExecutionTimeline.");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Pause to capture", &pause_during_capture_);
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(timeline.empty() && timeline.total_dropped_events() == 0u);
    if (ImGui::Button("Clear Timeline")) {
        pending_clear_timeline_ = true;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    capacity_preset_idx_ = static_cast<int>(preset_index_for_capacity(timeline.capacity()));
    ImGui::SetNextItemWidth(145.0f);
    if (ImGui::Combo("Ring Capacity",
                     &capacity_preset_idx_,
                     kCapacityLabels.data(),
                     static_cast<int>(kCapacityLabels.size()))) {
        if (capacity_preset_idx_ >= 0 &&
            static_cast<std::size_t>(capacity_preset_idx_) < kCapacityValues.size()) {
            pending_capacity_change_ =
                kCapacityValues[static_cast<std::size_t>(capacity_preset_idx_)];
        }
    }

    ImGui::SameLine();
    std::size_t recycled_lanes = 0u;
    for (const peelf::TimelineLane& lane : timeline.thread_lanes()) {
        if (lane.tid_recycled) {
            ++recycled_lanes;
        }
    }
    ImGui::TextDisabled(
        "| Retained: %zu/%zu  Emitted: %llu  Thread Lanes: %zu%s  Snapshots: %zu",
        timeline.size(),
        timeline.capacity(),
        static_cast<unsigned long long>(timeline.total_emitted_events()),
        timeline.thread_lanes().size(),
        recycled_lanes > 0u ? " (recycled TID separated)" : "",
        model_.captured_snapshots().size());

    if (!status_message_.empty()) {
        ImGui::TextColored(ImVec4(0.65f, 0.85f, 1.0f, 1.0f), "%s", status_message_.c_str());
    }

    // Explicit DroppedEvents visual callout (never silent ring eviction).
    if (timeline.total_dropped_events() > 0u) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.42f, 0.12f, 0.12f, 0.55f));
        if (ImGui::BeginChild("##DroppedCallout", ImVec2(0.0f, 34.0f), ImGuiChildFlags_Borders)) {
            ImGui::TextColored(
                ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
                "RING EVICTION NOTICE: %llu event(s) exceeded bounded capacity (%zu) and are "
                "accounted in explicit DroppedEvents marker(s).",
                static_cast<unsigned long long>(timeline.total_dropped_events()),
                timeline.capacity());
            ImGui::SameLine();
            if (ImGui::SmallButton("Inspect Marker")) {
                for (const peelf::TimelineEvent& ev : timeline.events()) {
                    if (ev.kind == peelf::TimelineEventKind::DroppedEvents) {
                        selected_sequence_ = ev.sequence;
                        break;
                    }
                }
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // Explicit SamplingGap visual callout (honest interval uncertainty).
    if (timeline.sampling_gap_count() > 0u) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.38f, 0.28f, 0.08f, 0.50f));
        if (ImGui::BeginChild("##SamplingGapCallout", ImVec2(0.0f, 34.0f), ImGuiChildFlags_Borders)) {
            ImGui::TextColored(
                ImVec4(1.0f, 0.82f, 0.35f, 1.0f),
                "SAMPLING UNCERTAINTY: %llu SamplingGap marker(s) recorded across non-continuous "
                "snapshot intervals; snapshot deltas carry [earliest, latest] bounds.",
                static_cast<unsigned long long>(timeline.sampling_gap_count()));
            ImGui::SameLine();
            if (ImGui::SmallButton("Inspect Gap")) {
                for (const peelf::TimelineEvent& ev : timeline.events()) {
                    if (ev.kind == peelf::TimelineEventKind::SamplingGap) {
                        selected_sequence_ = ev.sequence;
                        break;
                    }
                }
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

void ExecutionTimelinePanel::draw_sources_strip() {
    const auto descriptors = model_.execution_timeline().source_descriptors();
    if (descriptors.empty()) {
        return;
    }

    ImGui::TextDisabled("Sources:");
    for (std::size_t i = 0u; i < descriptors.size(); ++i) {
        const peelf::TimelineSourceDescriptor& desc = descriptors[i];
        ImGui::SameLine();
        const ImVec4 col = support_state_color(desc.support_state, desc.provider_available);
        const std::string_view state_sv = peelf::to_string(desc.support_state);
        ImGui::TextColored(
            col,
            "[%s: %.*s]",
            desc.name.c_str(),
            static_cast<int>(state_sv.size()),
            state_sv.data());
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            const std::string_view kind_sv = peelf::to_string(desc.kind);
            ImGui::Text("%s (%.*s)", desc.name.c_str(), static_cast<int>(kind_sv.size()), kind_sv.data());
            ImGui::Text("Support: %.*s | Active: %s",
                        static_cast<int>(state_sv.size()),
                        state_sv.data(),
                        desc.provider_available ? "yes" : "no");
            if (!desc.status.detail.empty()) {
                ImGui::TextWrapped("Detail: %s", desc.status.detail.c_str());
            }
            ImGui::EndTooltip();
        }
    }
}

void ExecutionTimelinePanel::draw_filter_bar() {
    const peelf::ExecutionTimeline& timeline = model_.execution_timeline();

    ImGui::TextDisabled("Filter Kinds:");
    ImGui::SameLine();
    if (ImGui::SmallButton("All")) {
        kind_enabled_.fill(true);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("None")) {
        kind_enabled_.fill(false);
    }

    for (const KindChipSpec& spec : kKindChipSpecs) {
        ImGui::SameLine();
        const auto idx = static_cast<std::size_t>(spec.kind);
        const bool enabled = kind_enabled_[idx];
        const std::uint64_t count = timeline.event_kind_count(spec.kind);
        const ImVec4 base_col = event_kind_color(spec.kind);
        const std::string chip_label =
            std::format("{} ({})##chip_{}", spec.short_label, count, idx);

        if (enabled) {
            ImGui::PushStyleColor(
                ImGuiCol_Button,
                ImVec4(base_col.x * 0.45f, base_col.y * 0.45f, base_col.z * 0.45f, 0.85f));
            ImGui::PushStyleColor(
                ImGuiCol_ButtonHovered,
                ImVec4(base_col.x * 0.60f, base_col.y * 0.60f, base_col.z * 0.60f, 0.95f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.18f, 0.20f, 0.60f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.26f, 0.26f, 0.30f, 0.80f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.58f, 1.0f));
        }
        if (ImGui::SmallButton(chip_label.c_str())) {
            kind_enabled_[idx] = !kind_enabled_[idx];
        }
        ImGui::PopStyleColor(3);
    }

    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint(
        "##TimelineSearch",
        "Search summary, TID, 0xVA...",
        text_filter_.data(),
        text_filter_.size());

    ImGui::SameLine();
    std::string active_lane_preview = "All Lanes";
    if (global_lane_only_) {
        active_lane_preview = "Process / Global Only";
    } else if (lane_filter_.has_value()) {
        active_lane_preview =
            std::format("TID {} [epoch #{}]", lane_filter_->tid, lane_filter_->epoch);
    }
    ImGui::SetNextItemWidth(220.0f);
    if (ImGui::BeginCombo("Lane", active_lane_preview.c_str())) {
        const bool all_selected = !global_lane_only_ && !lane_filter_.has_value();
        if (ImGui::Selectable("All Lanes", all_selected)) {
            global_lane_only_ = false;
            lane_filter_.reset();
        }
        if (ImGui::Selectable("Process / Global Only", global_lane_only_)) {
            global_lane_only_ = true;
            lane_filter_.reset();
        }
        for (const peelf::TimelineLane& lane : timeline.thread_lanes()) {
            const bool is_sel =
                !global_lane_only_ &&
                lane_filter_.has_value() &&
                lane.identity.same_lane(*lane_filter_);
            const std::string lbl = format_lane_title(lane);
            if (ImGui::Selectable(lbl.c_str(), is_sel)) {
                global_lane_only_ = false;
                lane_filter_ = lane.identity;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &auto_scroll_table_);
}

void ExecutionTimelinePanel::draw_swimlanes_tab(
    std::span<const peelf::TimelineEvent* const> filtered_events) {
    const peelf::ExecutionTimeline& timeline = model_.execution_timeline();
    if (filtered_events.empty() && timeline.thread_lanes().empty()) {
        ImGui::TextDisabled(
            "No timeline events recorded yet. Attach an active debugger session or click "
            "'Capture Baseline Snapshot' followed by 'Record Snapshot Delta'.");
        return;
    }

    std::uint64_t min_seq = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_seq = 0u;
    for (const peelf::TimelineEvent* ev : filtered_events) {
        min_seq = std::min(min_seq, ev->sequence);
        max_seq = std::max(max_seq, ev->sequence);
    }
    if (min_seq > max_seq) {
        min_seq = 1u;
        max_seq = 1u;
    }
    const std::uint64_t seq_span = (max_seq > min_seq) ? (max_seq - min_seq) : 1u;

    const auto& lanes = timeline.thread_lanes();
    const auto lane_count = lanes.size();
    std::unordered_map<TidEpochKey, std::vector<std::size_t>, TidEpochKeyHash> lanes_by_tid_epoch;
    lanes_by_tid_epoch.reserve(lane_count);
    for (std::size_t li = 0u; li < lane_count; ++li) {
        lanes_by_tid_epoch[TidEpochKey{lanes[li].identity.tid, lanes[li].identity.epoch}]
            .push_back(li);
    }

    std::vector<const peelf::TimelineEvent*> band_events;
    std::vector<const peelf::TimelineEvent*> global_events;
    std::vector<std::vector<const peelf::TimelineEvent*>> lane_events(lane_count);
    for (const peelf::TimelineEvent* ev : filtered_events) {
        if (ev->kind == peelf::TimelineEventKind::DroppedEvents ||
            ev->kind == peelf::TimelineEventKind::SamplingGap) {
            band_events.push_back(ev);
        }
        if (!ev->thread.has_value()) {
            global_events.push_back(ev);
            continue;
        }
        if (const auto it = lanes_by_tid_epoch.find(
                TidEpochKey{ev->thread->tid, ev->thread->epoch});
            it != lanes_by_tid_epoch.end()) {
            for (const std::size_t li : it->second) {
                if (ev->thread->same_lane(lanes[li].identity)) {
                    lane_events[li].push_back(ev);
                }
            }
        }
    }

    constexpr float kLaneRowHeight = 30.0f;
    constexpr float kLabelColWidth = 235.0f;
    constexpr float kTrackPadX = 16.0f;
    const float desired_height = std::clamp(
        static_cast<float>(lane_count + 1u) * (kLaneRowHeight + 4.0f) + 34.0f,
        130.0f,
        290.0f);

    std::optional<std::uint64_t> clicked_seq;
    std::optional<peelf::TimelineNavigationTarget> double_clicked_nav;
    std::optional<peelf::ThreadId> clicked_lane_tid;

    if (ImGui::BeginTable(
            "##SwimlaneTable",
            2,
            ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_BordersOuter |
                ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0.0f, desired_height))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Thread / Global Lane", ImGuiTableColumnFlags_WidthFixed, kLabelColWidth);
        ImGui::TableSetupColumn(
            std::format("Sequence Axis (#{} .. #{})", min_seq, max_seq).c_str(),
            ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        auto render_lane_row = [&](std::string_view lane_title,
                                   const std::optional<peelf::TimelineLane>& lane_meta,
                                   std::span<const peelf::TimelineEvent* const> row_events,
                                   std::size_t row_idx) {
            ImGui::TableNextRow(ImGuiTableRowFlags_None, kLaneRowHeight);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(row_idx));
            if (lane_meta.has_value()) {
                const ImVec4 tid_col = !lane_meta->active
                                           ? ImVec4(0.62f, 0.62f, 0.66f, 1.0f)
                                           : (lane_meta->tid_recycled
                                                  ? ImVec4(1.0f, 0.80f, 0.35f, 1.0f)
                                                  : ImVec4(0.86f, 0.92f, 1.0f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_Text, tid_col);
                if (ImGui::Selectable(lane_title.data(), false, 0, ImVec2(0.0f, kLaneRowHeight - 4.0f)) &&
                    lane_meta->active) {
                    clicked_lane_tid = lane_meta->identity.tid;
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text("TID %llu | Epoch #%llu | Events: %llu",
                                static_cast<unsigned long long>(lane_meta->identity.tid),
                                static_cast<unsigned long long>(lane_meta->identity.epoch),
                                static_cast<unsigned long long>(lane_meta->event_count));
                    if (lane_meta->identity.creation_identity.has_value()) {
                        ImGui::Text("Creation Identity: %llu",
                                    static_cast<unsigned long long>(
                                        *lane_meta->identity.creation_identity));
                    }
                    if (lane_meta->tid_recycled) {
                        ImGui::TextColored(
                            ImVec4(1.0f, 0.80f, 0.35f, 1.0f),
                            "OS TID reused across distinct thread lifetimes (isolated lane)");
                    }
                    ImGui::EndTooltip();
                }
            } else {
                ImGui::TextUnformatted(lane_title.data());
            }

            ImGui::TableSetColumnIndex(1);
            const ImVec2 avail = ImGui::GetContentRegionAvail();
            const float track_w = std::max(avail.x, 80.0f);
            const ImVec2 p0 = ImGui::GetCursorScreenPos();
            const ImVec2 p1(p0.x + track_w, p0.y + kLaneRowHeight - 2.0f);
            ImGui::InvisibleButton("##lane_canvas", ImVec2(track_w, kLaneRowHeight - 2.0f));
            const bool track_hovered = ImGui::IsItemHovered();
            const ImVec2 mouse_pos = ImGui::GetIO().MousePos;

            ImDrawList* dl = ImGui::GetWindowDrawList();
            const float cy = (p0.y + p1.y) * 0.5f;
            const float x_left = p0.x + kTrackPadX;
            const float x_right = std::max(x_left + 1.0f, p1.x - kTrackPadX);
            const float usable_w = x_right - x_left;

            dl->AddLine(ImVec2(x_left, cy), ImVec2(x_right, cy), IM_COL32(90, 96, 110, 140), 1.0f);

            const auto x_for_sequence = [&](std::uint64_t seq) noexcept {
                const float t = (max_seq == min_seq)
                                    ? 0.5f
                                    : static_cast<float>(seq - min_seq) /
                                          static_cast<float>(seq_span);
                return x_left + t * usable_w;
            };

            // Draw global SamplingGap / DroppedEvents vertical callout bands across all lanes.
            for (const peelf::TimelineEvent* ev : band_events) {
                const bool belongs_here =
                    lane_meta.has_value()
                        ? (ev->thread.has_value() && ev->thread->same_lane(lane_meta->identity))
                        : (!ev->thread.has_value());
                const float x = x_for_sequence(ev->sequence);
                const ImU32 band_col =
                    ev->kind == peelf::TimelineEventKind::DroppedEvents
                        ? IM_COL32(255, 85, 85, belongs_here ? 95 : 42)
                        : IM_COL32(255, 195, 65, belongs_here ? 95 : 42);
                dl->AddRectFilled(ImVec2(x - 3.0f, p0.y + 1.0f),
                                  ImVec2(x + 3.0f, p1.y - 1.0f),
                                  band_col,
                                  2.0f);
            }

            const peelf::TimelineEvent* hovered_ev = nullptr;
            float best_hover_dist = 9.0f;

            for (const peelf::TimelineEvent* ev : row_events) {
                const float x = x_for_sequence(ev->sequence);

                const ImVec4 kind_col = event_kind_color(ev->kind);
                const bool is_selected =
                    selected_sequence_.has_value() && *selected_sequence_ == ev->sequence;

                const bool has_uncertain_interval =
                    ev->observation_interval.has_value() &&
                    (ev->observation_interval->duration_ns() > 0u ||
                     ev->observation_interval->latest.snapshot_revision >
                         ev->observation_interval->earliest.snapshot_revision);

                // Uncertainty interval bar for snapshot-derived observations.
                if (has_uncertain_interval) {
                    const float half_bar = std::clamp(usable_w / 36.0f, 6.0f, 18.0f);
                    const float bx0 = std::max(x_left, x - half_bar);
                    const float bx1 = std::min(x_right, x + half_bar);
                    dl->AddRectFilled(ImVec2(bx0, cy - 4.0f),
                                      ImVec2(bx1, cy + 4.0f),
                                      to_u32_color(kind_col, 0.30f),
                                      2.0f);
                }

                const float radius = is_selected ? 6.5f : 4.8f;
                if (ev->observation_interval.has_value()) {
                    // Diamond marker for interval-bounded snapshot delta.
                    const std::array<ImVec2, 4> pts = {{
                        ImVec2(x, cy - radius),
                        ImVec2(x + radius, cy),
                        ImVec2(x, cy + radius),
                        ImVec2(x - radius, cy),
                    }};
                    dl->AddConvexPolyFilled(pts.data(), 4, to_u32_color(kind_col));
                    if (is_selected) {
                        dl->AddPolyline(
                            pts.data(), 4, IM_COL32(255, 255, 255, 240), ImDrawFlags_Closed, 1.8f);
                    }
                } else {
                    // Circle marker for exact point event.
                    dl->AddCircleFilled(ImVec2(x, cy), radius, to_u32_color(kind_col), 14);
                    if (is_selected) {
                        dl->AddCircle(ImVec2(x, cy), radius + 2.0f, IM_COL32(255, 255, 255, 240), 14, 1.8f);
                    }
                }

                if (track_hovered) {
                    const float dx = std::abs(mouse_pos.x - x);
                    const float dy = std::abs(mouse_pos.y - cy);
                    if (dx <= best_hover_dist && dy <= (kLaneRowHeight * 0.5f)) {
                        best_hover_dist = dx;
                        hovered_ev = ev;
                    }
                }
            }

            if (hovered_ev != nullptr) {
                ImGui::BeginTooltip();
                const std::string_view ksv = peelf::to_string(hovered_ev->kind);
                ImGui::Text("#%llu  [%.*s]",
                            static_cast<unsigned long long>(hovered_ev->sequence),
                            static_cast<int>(ksv.size()),
                            ksv.data());
                ImGui::Text("Lane: %s", format_lane_badge(*hovered_ev).c_str());
                ImGui::Text("Timing: %s", format_stamp_or_interval(*hovered_ev).c_str());
                if (hovered_ev->virtual_address.has_value()) {
                    ImGui::Text("Address: 0x%llX",
                                static_cast<unsigned long long>(*hovered_ev->virtual_address));
                }
                ImGui::Separator();
                ImGui::TextWrapped("%s", hovered_ev->summary.c_str());
                ImGui::TextDisabled("Click to inspect | Double-click to navigate");
                ImGui::EndTooltip();

                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    clicked_seq = hovered_ev->sequence;
                }
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    clicked_seq = hovered_ev->sequence;
                    double_clicked_nav =
                        peelf::resolve_timeline_navigation(*hovered_ev);
                }
            }
            ImGui::PopID();
        };

        if (!lane_filter_.has_value()) {
            render_lane_row("Process / Global", std::nullopt, global_events, 0u);
        }

        if (!global_lane_only_) {
            for (std::size_t li = 0u; li < lane_count; ++li) {
                const peelf::TimelineLane& lane = lanes[li];
                if (lane_filter_.has_value() && !lane.identity.same_lane(*lane_filter_)) {
                    continue;
                }
                const std::string title = format_lane_title(lane);
                render_lane_row(title, lane, lane_events[li], li + 1u);
            }
        }

        ImGui::EndTable();
    }

    if (clicked_seq.has_value()) {
        selected_sequence_ = *clicked_seq;
    }
    if (double_clicked_nav.has_value()) {
        pending_navigation_ = std::move(*double_clicked_nav);
    }
    if (clicked_lane_tid.has_value()) {
        pending_select_tid_ = *clicked_lane_tid;
    }
}

void ExecutionTimelinePanel::draw_event_table_tab(
    std::span<const peelf::TimelineEvent* const> filtered_events) {
    if (filtered_events.empty()) {
        ImGui::TextDisabled("No timeline events match the active filters.");
        return;
    }

    std::optional<std::uint64_t> clicked_seq;
    std::optional<peelf::TimelineNavigationTarget> requested_nav;

    constexpr ImGuiTableFlags kFlags =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("##TimelineEventsTable", 6, kFlags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Seq", ImGuiTableColumnFlags_WidthFixed, 64.0f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 118.0f);
        ImGui::TableSetupColumn("Lane", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Stamp / Interval", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 128.0f);
        ImGui::TableSetupColumn("Summary & Navigate", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(clamp_imgui_clipper_count(filtered_events.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const peelf::TimelineEvent& ev =
                    *filtered_events[static_cast<std::size_t>(row)];
                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(ev.sequence & 0x7FFF'FFFFu));

                if (ev.kind == peelf::TimelineEventKind::DroppedEvents) {
                    ImGui::TableSetBgColor(
                        ImGuiTableBgTarget_RowBg0, IM_COL32(110, 28, 28, 120));
                } else if (ev.kind == peelf::TimelineEventKind::SamplingGap) {
                    ImGui::TableSetBgColor(
                        ImGuiTableBgTarget_RowBg0, IM_COL32(105, 78, 20, 120));
                }

                const bool is_selected =
                    selected_sequence_.has_value() && *selected_sequence_ == ev.sequence;

                ImGui::TableSetColumnIndex(0);
                const std::string seq_lbl = std::format("#{}", ev.sequence);
                if (ImGui::Selectable(
                        seq_lbl.c_str(),
                        is_selected,
                        ImGuiSelectableFlags_SpanAllColumns |
                            ImGuiSelectableFlags_AllowOverlap)) {
                    clicked_seq = ev.sequence;
                }
                if (ImGui::IsItemHovered() &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    clicked_seq = ev.sequence;
                    requested_nav = peelf::resolve_timeline_navigation(ev);
                }

                ImGui::TableSetColumnIndex(1);
                const std::string_view ksv = peelf::to_string(ev.kind);
                ImGui::TextColored(
                    event_kind_color(ev.kind),
                    "%.*s",
                    static_cast<int>(ksv.size()),
                    ksv.data());

                ImGui::TableSetColumnIndex(2);
                const std::string lane_txt = format_lane_badge(ev);
                ImGui::TextUnformatted(lane_txt.c_str());

                ImGui::TableSetColumnIndex(3);
                const std::string stamp_txt = format_stamp_or_interval(ev);
                ImGui::TextUnformatted(stamp_txt.c_str());

                ImGui::TableSetColumnIndex(4);
                if (ev.virtual_address.has_value()) {
                    ImGui::Text("0x%llX",
                                static_cast<unsigned long long>(*ev.virtual_address));
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableSetColumnIndex(5);
                if (ImGui::SmallButton("Go")) {
                    clicked_seq = ev.sequence;
                    requested_nav = peelf::resolve_timeline_navigation(ev);
                }
                ImGui::SameLine();
                ImGui::TextUnformatted(ev.summary.c_str());

                ImGui::PopID();
            }
        }

        if (auto_scroll_table_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndTable();
    }

    if (clicked_seq.has_value()) {
        selected_sequence_ = *clicked_seq;
    }
    if (requested_nav.has_value()) {
        pending_navigation_ = std::move(*requested_nav);
    }
}

void ExecutionTimelinePanel::draw_event_inspector(
    const peelf::TimelineEvent* selected_event) {
    ImGui::SeparatorText("Selected Event Inspector");
    if (selected_event == nullptr) {
        ImGui::TextDisabled("Click any marker or table row above to inspect payload provenance and navigate.");
        return;
    }

    const peelf::TimelineEvent& ev = *selected_event;
    const std::string_view ksv = peelf::to_string(ev.kind);
    ImGui::Text("Sequence #%llu  |", static_cast<unsigned long long>(ev.sequence));
    ImGui::SameLine();
    ImGui::TextColored(
        event_kind_color(ev.kind),
        "%.*s",
        static_cast<int>(ksv.size()),
        ksv.data());
    ImGui::SameLine();
    ImGui::Text("|  Lane: %s", format_lane_badge(ev).c_str());

    // Deferred click-to-navigate buttons (Disassembly, Hex, Process Internals, Debugger).
    ImGui::SameLine();
    const bool has_va = ev.virtual_address.has_value() && *ev.virtual_address != 0u;
    ImGui::BeginDisabled(!has_va);
    if (ImGui::SmallButton("Disassembly")) {
        pending_navigation_ =
            peelf::resolve_timeline_navigation(ev, peelf::TimelineTargetPanel::Disassembly);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Hex")) {
        pending_navigation_ =
            peelf::resolve_timeline_navigation(ev, peelf::TimelineTargetPanel::Hex);
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::SmallButton("Process Internals")) {
        pending_navigation_ =
            peelf::resolve_timeline_navigation(ev, peelf::TimelineTargetPanel::ProcessInternals);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Debugger")) {
        pending_navigation_ =
            peelf::resolve_timeline_navigation(ev, peelf::TimelineTargetPanel::Debugger);
    }

    ImGui::TextWrapped("Summary: %s", ev.summary.c_str());

    if (ev.observation_interval.has_value()) {
        const double dur_ms =
            static_cast<double>(ev.observation_interval->duration_ns()) / 1'000'000.0;
        const bool is_uncertain =
            ev.observation_interval->duration_ns() > 0u ||
            ev.observation_interval->latest.snapshot_revision >
                ev.observation_interval->earliest.snapshot_revision;
        ImGui::TextColored(
            ImVec4(0.95f, 0.82f, 0.42f, 1.0f),
            "Observation Interval [earliest..latest]: rev %llu -> rev %llu (span %.3f ms)%s",
            static_cast<unsigned long long>(ev.observation_interval->earliest.snapshot_revision),
            static_cast<unsigned long long>(ev.observation_interval->latest.snapshot_revision),
            dur_ms,
            is_uncertain
                ? " [snapshot-derived interval; exact sub-interval instant unproven]"
                : "");
    } else {
        ImGui::Text(
            "Capture Stamp: rev %llu | mono_ns %llu | unix_ms %llu",
            static_cast<unsigned long long>(ev.stamp.snapshot_revision),
            static_cast<unsigned long long>(ev.stamp.monotonic_ns),
            static_cast<unsigned long long>(ev.stamp.captured_unix_ms));
    }

    if (ev.thread.has_value()) {
        const std::string ci_str =
            ev.thread->creation_identity.has_value()
                ? std::format("{}", *ev.thread->creation_identity)
                : std::string("unproven");
        ImGui::Text(
            "ThreadIdentity: TID %llu | Epoch #%llu | StartIdentity: %s",
            static_cast<unsigned long long>(ev.thread->tid),
            static_cast<unsigned long long>(ev.thread->epoch),
            ci_str.c_str());
    }

    if (ev.virtual_address.has_value()) {
        const std::string resolved = model_.resolve_address_symbol(*ev.virtual_address);
        if (!resolved.empty()) {
            ImGui::Text("Virtual Address: 0x%llX (%s)",
                        static_cast<unsigned long long>(*ev.virtual_address),
                        resolved.c_str());
        } else {
            ImGui::Text("Virtual Address: 0x%llX",
                        static_cast<unsigned long long>(*ev.virtual_address));
        }
    }

    std::visit(
        [](const auto& payload) {
            using T = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                // No additional payload fields.
            } else if constexpr (std::is_same_v<T, peelf::debugger::DebugEvent>) {
                const std::string_view dk = peelf::debugger::to_string(payload.kind);
                ImGui::TextDisabled(
                    "DebugEvent seq=%llu kind=%.*s code=%lld ip=0x%llX",
                    static_cast<unsigned long long>(payload.sequence),
                    static_cast<int>(dk.size()),
                    dk.data(),
                    static_cast<long long>(payload.signal_or_exception_code.value_or(0)),
                    static_cast<unsigned long long>(payload.address.value_or(0u)));
            } else if constexpr (std::is_same_v<T, peelf::ModuleDelta>) {
                const peelf::ModuleInfo* mod =
                    payload.after.has_value()
                        ? &(*payload.after)
                        : (payload.before.has_value() ? &(*payload.before) : nullptr);
                if (mod != nullptr) {
                    ImGui::TextDisabled(
                        "ModuleDelta path=%s base=0x%llX size=0x%llX",
                        mod->path.string().c_str(),
                        static_cast<unsigned long long>(mod->base_address),
                        static_cast<unsigned long long>(mod->size));
                }
            } else if constexpr (std::is_same_v<T, peelf::RegionDelta>) {
                ImGui::TextDisabled(
                    "RegionDelta [0x%llX..0x%llX) size=0x%llX %s",
                    static_cast<unsigned long long>(payload.start_address),
                    static_cast<unsigned long long>(payload.end_address),
                    static_cast<unsigned long long>(payload.size()),
                    payload.detail.c_str());
            } else if constexpr (std::is_same_v<T, peelf::ThreadDelta>) {
                ImGui::TextDisabled(
                    "ThreadDelta tid=%llu tid_reused=%s ip_changed=%s",
                    static_cast<unsigned long long>(payload.tid),
                    payload.tid_reused ? "true" : "false",
                    payload.instruction_pointer_changed ? "true" : "false");
            } else if constexpr (std::is_same_v<T, peelf::HandleDelta>) {
                const peelf::ProcessHandleEntry* h =
                    payload.after.has_value()
                        ? &(*payload.after)
                        : (payload.before.has_value() ? &(*payload.before) : nullptr);
                ImGui::TextDisabled(
                    "HandleDelta handle_or_fd=%llu target=%s",
                    static_cast<unsigned long long>(payload.handle_or_fd),
                    h != nullptr ? h->target.c_str() : payload.detail.c_str());
            } else if constexpr (std::is_same_v<T, peelf::SocketDelta>) {
                const peelf::ProcessSocketEntry* s =
                    payload.after.has_value()
                        ? &(*payload.after)
                        : (payload.before.has_value() ? &(*payload.before) : nullptr);
                if (s != nullptr) {
                    const std::string_view proto_sv = peelf::to_string(s->protocol);
                    ImGui::TextDisabled(
                        "SocketDelta proto=%.*s %s -> %s state=%s",
                        static_cast<int>(proto_sv.size()),
                        proto_sv.data(),
                        s->local_endpoint.c_str(),
                        s->remote_endpoint.c_str(),
                        s->state.c_str());
                }
            } else if constexpr (std::is_same_v<T, peelf::SyscallEventPayload>) {
                ImGui::TextDisabled(
                    "Syscall #%llu (%s) ret=%lld",
                    static_cast<unsigned long long>(payload.syscall_number),
                    payload.name.c_str(),
                    static_cast<long long>(payload.return_value.value_or(0)));
            } else if constexpr (std::is_same_v<T, peelf::DroppedEventsPayload>) {
                ImGui::TextColored(
                    ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
                    "DroppedEvents: %llu event(s) dropped across sequences [%llu..%llu] (%s)",
                    static_cast<unsigned long long>(payload.dropped_count),
                    static_cast<unsigned long long>(payload.first_dropped_sequence),
                    static_cast<unsigned long long>(payload.last_dropped_sequence),
                    payload.reason.c_str());
            } else if constexpr (std::is_same_v<T, peelf::SamplingGapPayload>) {
                ImGui::TextColored(
                    ImVec4(1.0f, 0.82f, 0.35f, 1.0f),
                    "SamplingGap: rev %llu -> rev %llu | unobserved=%llu ns (%s)",
                    static_cast<unsigned long long>(payload.before_revision),
                    static_cast<unsigned long long>(payload.after_revision),
                    static_cast<unsigned long long>(payload.unobserved_monotonic_ns),
                    payload.reason.c_str());
            }
        },
        ev.payload);
}

void ExecutionTimelinePanel::draw_contents() {
    draw_toolbar_and_banners();
    draw_sources_strip();
    ImGui::Separator();
    draw_filter_bar();

    std::vector<const peelf::TimelineEvent*> filtered_events;
    filtered_events.reserve(model_.execution_timeline().size());
    for (const peelf::TimelineEvent& ev : model_.execution_timeline().events()) {
        if (passes_filter(ev)) {
            filtered_events.push_back(&ev);
        }
    }

    if (ImGui::BeginTabBar("##ExecutionTimelineTabs")) {
        if (ImGui::BeginTabItem("Per-Thread Swimlanes")) {
            draw_swimlanes_tab(filtered_events);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Chronological Event Stream")) {
            draw_event_table_tab(filtered_events);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    draw_event_inspector(find_selected_event());

    // Execute deferred actions strictly outside all ImGui table/swimlane loops.
    if (pending_capacity_change_.has_value()) {
        const std::size_t new_cap = *pending_capacity_change_;
        pending_capacity_change_.reset();
        model_.execution_timeline().set_capacity(new_cap);
        status_message_ = std::format("Timeline ring capacity set to {} events.", new_cap);
    }

    if (pending_clear_timeline_) {
        pending_clear_timeline_ = false;
        model_.clear_execution_timeline();
        selected_sequence_.reset();
        lane_filter_.reset();
        status_message_ = "Execution timeline cleared.";
    }

    if (pending_record_snapshot_delta_) {
        pending_record_snapshot_delta_ = false;
        const std::uint64_t seq_before = model_.execution_timeline().next_sequence();
        auto snap_res = model_.record_timeline_snapshot_delta(pause_during_capture_);
        if (!snap_res.has_value()) {
            status_message_ =
                std::format("Snapshot capture failed: {}", snap_res.error().message);
        } else if (*snap_res == 0u) {
            status_message_ = std::format(
                "Captured baseline snapshot #0 ({} thread lane(s) seeded). Capture again to record delta.",
                model_.execution_timeline().thread_lanes().size());
        } else {
            const std::uint64_t added =
                model_.execution_timeline().next_sequence() - seq_before;
            status_message_ = std::format(
                "Captured snapshot #{} and appended {} timeline event(s).",
                *snap_res,
                added);
        }
    }

    if (pending_select_tid_.has_value()) {
        const peelf::ThreadId tid = *pending_select_tid_;
        pending_select_tid_.reset();
        model_.select_thread(tid);
    }

    if (pending_navigation_.has_value()) {
        const peelf::TimelineNavigationTarget nav = std::move(*pending_navigation_);
        pending_navigation_.reset();
        dispatch_navigation(nav);
    }
}

} // namespace viewer
