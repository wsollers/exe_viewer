#include "panel_helpers.hpp"
#include "ui_panels_timeline.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <exception>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace viewer {
namespace {

constexpr std::array<const char*, 6> kCapacityLabels = {
    "1,024 events",
    "4,096 events",
    "16,384 events",
    "65,536 events",
    "262,144 events",
    "1,048,576 events",
};

constexpr std::array<std::size_t, 6> kCapacityValues = {
    1'024u,
    4'096u,
    16'384u,
    65'536u,
    262'144u,
    1'048'576u,
};

constexpr std::array<const char*, 5> kMonitorRateLabels = {
    "Monitor: Off",
    "Monitor: 4 Hz",
    "Monitor: 10 Hz",
    "Monitor: 20 Hz",
    "Monitor: 50 Hz",
};

constexpr std::uint64_t kMinZoomSpanNs = 10ULL; // 10 ns minimum window
constexpr float kRulerHeightPx = 26.0f;
constexpr float kLaneHeightPx = 34.0f;
constexpr float kSparklineSubHeightPx = 16.0f;
constexpr float kLeftHeaderWidthPx = 258.0f;
constexpr float kDragSlopPx = 4.0f;
constexpr double kZoomWheelBase = 1.22;

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

[[nodiscard]] ImVec4 unpack_rgba8_imvec4(std::uint32_t rgba8) noexcept {
    constexpr float kInv255 = 1.0f / 255.0f;
    return ImVec4(
        static_cast<float>(rgba8 & 0xFFu) * kInv255,
        static_cast<float>((rgba8 >> 8u) & 0xFFu) * kInv255,
        static_cast<float>((rgba8 >> 16u) & 0xFFu) * kInv255,
        static_cast<float>((rgba8 >> 24u) & 0xFFu) * kInv255);
}

[[nodiscard]] ImVec4 event_kind_color(peelf::TimelineEventKind kind) noexcept {
    switch (kind) {
        case peelf::TimelineEventKind::DebuggerEvent:
            return ImVec4(0.96f, 0.58f, 0.22f, 1.00f);
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
            return ImVec4(0.78f, 0.52f, 0.96f, 1.00f);
        case peelf::TimelineEventKind::SyscallExit:
            return ImVec4(0.68f, 0.46f, 0.88f, 1.00f);
        case peelf::TimelineEventKind::DroppedEvents:
            return ImVec4(1.00f, 0.36f, 0.36f, 1.00f);
        case peelf::TimelineEventKind::SamplingGap:
            return ImVec4(1.00f, 0.76f, 0.26f, 1.00f);
    }
    return ImVec4(0.80f, 0.80f, 0.80f, 1.00f);
}

[[nodiscard]] ImVec4 thread_state_color(peelf::ThreadSpanState state) noexcept {
    return unpack_rgba8_imvec4(
        peelf::timeline_fill_color_rgba8(peelf::visual_kind_for_thread_state(state), 255u));
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
            return std::format(
                "[rev {}..{}] (~{})",
                r0,
                r1,
                peelf::format_timeline_duration_ns(dur_ns));
        }
        return std::format("[rev {}..{}]", r0, r1);
    }
    if (ev.stamp.snapshot_revision != 0u) {
        return std::format("rev {}", ev.stamp.snapshot_revision);
    }
    if (ev.stamp.monotonic_ns != 0u) {
        return peelf::format_timeline_duration_ns(ev.stamp.monotonic_ns);
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
    for (std::size_t i = kCapacityValues.size(); i > 0u; --i) {
        if (cap >= kCapacityValues[i - 1u]) {
            return i - 1u;
        }
    }
    return 1u;
}

[[nodiscard]] std::chrono::milliseconds interval_for_rate(int rate_idx) noexcept {
    switch (rate_idx) {
        case 1: return std::chrono::milliseconds(250); // 4 Hz
        case 2: return std::chrono::milliseconds(100); // 10 Hz
        case 3: return std::chrono::milliseconds(50);  // 20 Hz
        case 4: return std::chrono::milliseconds(20);  // 50 Hz
        default: return std::chrono::milliseconds(250);
    }
}

[[nodiscard]] std::uint64_t fnv1a_mix(std::uint64_t h, std::uint64_t v) noexcept {
    h ^= v;
    h *= 1099511628211ULL;
    return h;
}

} // namespace

ExecutionTimelinePanel::ExecutionTimelinePanel(BinaryModel& model,
                                               VulkanManager& vulkan,
                                               NavigateTargetCallback on_navigate)
    : UiPanel("Execution Timeline"),
      model_(model),
      vulkan_(vulkan),
      on_navigate_(std::move(on_navigate)) {
    visible_ = false;
    kind_enabled_.fill(true);
}

ExecutionTimelinePanel::~ExecutionTimelinePanel() {
    shutdown();
}

void ExecutionTimelinePanel::stop_monitor_worker() noexcept {
    if (monitor_worker_.joinable()) {
        monitor_worker_.request_stop();
        worker_cv_.notify_all();
        monitor_worker_.join();
    }
    {
        std::scoped_lock lock(worker_mutex_);
        worker_session_.reset();
    }
}

void ExecutionTimelinePanel::cancel_and_reset() noexcept {
    stop_monitor_worker();
    monitor_rate_ = LiveMonitorRate::Off;
    live_monitor_.reset();
    latest_monitor_seq_.store(0u, std::memory_order_release);
    crash_dump_seeded_ = false;
    tracked_pid_ = 0u;
    tracked_session_ptr_ = nullptr;

    cached_monitor_observed_ = peelf::Observed<peelf::LiveThreadMonitorSnapshot>::unavailable(
        peelf::ProvenanceTag::ProcOrOsApi, "Monitor idle");
    viewport_index_.clear();
    current_frame_ = {};
    indexed_timeline_next_seq_ = 0u;
    indexed_timeline_size_ = 0u;
    indexed_lane_count_ = 0u;
    indexed_monitor_seq_ = 0u;
    indexed_filter_sig_ = 0u;
    index_dirty_ = true;

    view_start_ns_ = 0u;
    view_end_ns_ = 1'000'000ULL;
    view_initialized_ = false;
    follow_live_tail_ = true;
    muted_sparkline_lanes_.clear();
    lane_scroll_y_px_ = 0.0f;
    is_panning_ = false;
    pan_exceeded_drag_slop_ = false;
    is_measuring_dt_ = false;
    has_dt_ruler_ = false;

    hovered_hit_id_ = peelf::kInvalidTimelineHitId;
    selected_hit_id_ = peelf::kInvalidTimelineHitId;
    needs_gpu_record_this_frame_ = false;

    selected_sequence_.reset();
    selected_thread_span_.reset();
    pending_navigation_.reset();
    pending_select_tid_.reset();
    lane_filter_.reset();
    global_lane_only_ = false;
    pending_record_snapshot_delta_ = false;
    pending_clear_timeline_ = false;
    pending_capacity_change_.reset();
    status_message_.clear();
}

void ExecutionTimelinePanel::shutdown() noexcept {
    cancel_and_reset();
    if (vulkan_.device() != VK_NULL_HANDLE) {
        (void)vkDeviceWaitIdle(vulkan_.device());
    }
    graphics_pipeline_.shutdown();
    instance_ring_.shutdown();
    canvas_.shutdown();
    canvas_initialized_ = false;
    graphics_pipeline_attempted_ = false;
}

void ExecutionTimelinePanel::ensure_monitor_worker_started() {
    if (monitor_worker_.joinable()) {
        return;
    }
    monitor_worker_ = std::jthread([this](std::stop_token st) {
        monitor_worker_loop(std::move(st));
    });
}

void ExecutionTimelinePanel::monitor_worker_loop(std::stop_token stop_token) {
    while (!stop_token.stop_requested()) {
        std::shared_ptr<peelf::IProcessSession> session_copy{};
        LiveMonitorRate rate = LiveMonitorRate::Off;
        {
            std::unique_lock lock(worker_mutex_);
            worker_cv_.wait(lock, stop_token, [this]() noexcept {
                return monitor_rate_ != LiveMonitorRate::Off && worker_session_ != nullptr;
            });
            if (stop_token.stop_requested()) {
                break;
            }
            session_copy = worker_session_;
            rate = monitor_rate_;
        }

        if (session_copy != nullptr && rate != LiveMonitorRate::Off &&
            !session_copy->is_crash_dump()) {
            const auto sample_res = live_monitor_.sample(*session_copy, stop_token);
            if (sample_res.has_value()) {
                latest_monitor_seq_.store(
                    live_monitor_.sample_sequence(), std::memory_order_release);
            }
        }

        const auto sleep_dur = interval_for_rate(static_cast<int>(rate));
        std::unique_lock lock(worker_mutex_);
        (void)worker_cv_.wait_for(lock, stop_token, sleep_dur, [this, rate]() noexcept {
            return monitor_rate_ != rate || worker_session_ == nullptr;
        });
    }
}

void ExecutionTimelinePanel::sync_target_and_monitor() {
    const peelf::IProcessSession* raw_session = model_.process_session();
    const std::uint32_t current_pid =
        (raw_session != nullptr) ? raw_session->pid() : 0u;

    if (raw_session != tracked_session_ptr_ || current_pid != tracked_pid_) {
        live_monitor_.reset();
        latest_monitor_seq_.store(0u, std::memory_order_release);
        crash_dump_seeded_ = false;
        tracked_session_ptr_ = raw_session;
        tracked_pid_ = current_pid;
        view_initialized_ = false;
        index_dirty_ = true;

        {
            std::scoped_lock lock(worker_mutex_);
            worker_session_ =
                (raw_session != nullptr && !raw_session->is_crash_dump())
                    ? model_.shared_process_session()
                    : nullptr;
            if (worker_session_ == nullptr) {
                monitor_rate_ = LiveMonitorRate::Off;
            }
        }
        worker_cv_.notify_all();
    }

    // Automatically seed thread state spans & stack depths from offline crash dumps.
    if (model_.is_crash_dump() && !crash_dump_seeded_ && raw_session != nullptr) {
        if (auto* dump_session =
                dynamic_cast<peelf::ICrashDumpSession*>(model_.process_session());
            dump_session != nullptr) {
            const auto seed_res = live_monitor_.seed_from_crash_dump(*dump_session);
            if (seed_res.has_value()) {
                latest_monitor_seq_.store(
                    live_monitor_.sample_sequence(), std::memory_order_release);
            }
        }
        crash_dump_seeded_ = true;
        index_dirty_ = true;
    }

    if (monitor_rate_ != LiveMonitorRate::Off && model_.is_live_process() &&
        !model_.is_crash_dump()) {
        {
            std::scoped_lock lock(worker_mutex_);
            worker_session_ = model_.shared_process_session();
        }
        ensure_monitor_worker_started();
        worker_cv_.notify_all();
    }
}

std::uint64_t ExecutionTimelinePanel::compute_filter_signature() const noexcept {
    std::uint64_t h = 14695981039346656037ULL;
    for (std::size_t i = 0u; i < kind_enabled_.size(); ++i) {
        h = fnv1a_mix(h, kind_enabled_[i] ? (i + 1u) : 0u);
    }
    h = fnv1a_mix(h, global_lane_only_ ? 0xA5A5ULL : 0ULL);
    if (lane_filter_.has_value()) {
        h = fnv1a_mix(h, lane_filter_->tid);
        h = fnv1a_mix(h, lane_filter_->epoch);
        h = fnv1a_mix(h, lane_filter_->creation_identity.value_or(0xFFFF'FFFFULL));
    }
    const std::string_view q(text_filter_.data());
    for (const char ch : q) {
        h = fnv1a_mix(h, static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    h = fnv1a_mix(h, muted_sparkline_lanes_.size());
    std::uint64_t muted_xor = 0ULL;
    for (const peelf::ThreadIdentity& id : muted_sparkline_lanes_) {
        muted_xor ^= (static_cast<std::uint64_t>(id.tid) * 0x9E3779B185EBCA87ULL) ^ id.epoch;
    }
    h = fnv1a_mix(h, muted_xor);
    return h;
}

void ExecutionTimelinePanel::fit_view_to_domain() noexcept {
    if (viewport_index_.empty()) {
        view_start_ns_ = 0ULL;
        view_end_ns_ = 1'000'000ULL;
        view_initialized_ = false;
        return;
    }
    const std::uint64_t t0 = viewport_index_.min_time_ns();
    const std::uint64_t t1 = viewport_index_.max_time_ns();
    const std::uint64_t raw_span = (t1 > t0) ? (t1 - t0) : 10'000ULL;
    const std::uint64_t pad = std::max<std::uint64_t>(raw_span / 20ULL, 100ULL);
    view_start_ns_ = (t0 > pad) ? (t0 - pad) : 0ULL;
    if (std::numeric_limits<std::uint64_t>::max() - t1 > pad) {
        view_end_ns_ = t1 + pad;
    } else {
        view_end_ns_ = std::numeric_limits<std::uint64_t>::max();
    }
    if (view_end_ns_ <= view_start_ns_ + kMinZoomSpanNs) {
        view_end_ns_ = view_start_ns_ + 10'000ULL;
    }
    view_initialized_ = true;
}

void ExecutionTimelinePanel::zoom_view_at_ratio(double anchor_ratio, double factor) noexcept {
    if (factor <= 0.0) {
        return;
    }
    const double clamped_ratio = std::clamp(anchor_ratio, 0.0, 1.0);
    const std::uint64_t cur_span =
        (view_end_ns_ > view_start_ns_) ? (view_end_ns_ - view_start_ns_) : kMinZoomSpanNs;
    const double anchor_ns =
        static_cast<double>(view_start_ns_) + clamped_ratio * static_cast<double>(cur_span);

    std::uint64_t max_allowed_span = 3'600'000'000'000ULL; // 1 hour default ceiling
    if (!viewport_index_.empty()) {
        const std::uint64_t dom_span =
            (viewport_index_.max_time_ns() > viewport_index_.min_time_ns())
                ? (viewport_index_.max_time_ns() - viewport_index_.min_time_ns())
                : 1'000'000ULL;
        max_allowed_span = std::max<std::uint64_t>(dom_span * 4ULL, 10'000'000ULL);
    }

    const double desired_span = std::clamp(
        static_cast<double>(cur_span) / factor,
        static_cast<double>(kMinZoomSpanNs),
        static_cast<double>(max_allowed_span));
    const double new_start_f = std::max(0.0, anchor_ns - clamped_ratio * desired_span);
    const auto new_start = static_cast<std::uint64_t>(new_start_f);
    const auto new_span =
        std::max<std::uint64_t>(static_cast<std::uint64_t>(std::llround(desired_span)), kMinZoomSpanNs);

    view_start_ns_ = new_start;
    if (std::numeric_limits<std::uint64_t>::max() - view_start_ns_ > new_span) {
        view_end_ns_ = view_start_ns_ + new_span;
    } else {
        view_end_ns_ = std::numeric_limits<std::uint64_t>::max();
    }
    view_initialized_ = true;
}

void ExecutionTimelinePanel::rebuild_viewport_index_if_needed() {
    const peelf::ExecutionTimeline& timeline = model_.execution_timeline();
    const std::uint64_t cur_next_seq = timeline.next_sequence();
    const std::size_t cur_size = timeline.size();
    const std::size_t cur_lanes = timeline.thread_lanes().size();
    const std::uint64_t cur_mon_seq = latest_monitor_seq_.load(std::memory_order_acquire);
    const std::uint64_t cur_filter_sig = compute_filter_signature();

    const bool data_advanced =
        (cur_next_seq != indexed_timeline_next_seq_) ||
        (cur_mon_seq != indexed_monitor_seq_);

    if (!index_dirty_ &&
        !data_advanced &&
        cur_size == indexed_timeline_size_ &&
        cur_lanes == indexed_lane_count_ &&
        cur_filter_sig == indexed_filter_sig_) {
        return;
    }

    if (cur_mon_seq != indexed_monitor_seq_ || index_dirty_) {
        cached_monitor_observed_ = live_monitor_.snapshot();
    }

    const peelf::LiveThreadMonitorSnapshot* mon_ptr = nullptr;
    peelf::LiveThreadMonitorSnapshot filtered_mon{};
    if (cached_monitor_observed_.has_value()) {
        if (muted_sparkline_lanes_.empty()) {
            mon_ptr = &(*cached_monitor_observed_.value);
        } else {
            filtered_mon = *cached_monitor_observed_.value;
            for (peelf::ThreadMonitorLane& lane : filtered_mon.lanes) {
                if (muted_sparkline_lanes_.contains(lane.identity)) {
                    lane.metrics.clear();
                }
            }
            mon_ptr = &filtered_mon;
        }
    }

    peelf::TimelineBuildOptions opts{};
    opts.include_global_lane = !lane_filter_.has_value();
    opts.filter_thread = global_lane_only_ ? std::optional<peelf::ThreadIdentity>{
                                                 peelf::ThreadIdentity{.tid = 0u, .epoch = ~0ULL}}
                                           : lane_filter_;
    opts.event_filter = [this](const peelf::TimelineEvent& ev) {
        return passes_filter(ev);
    };

    const std::uint64_t prev_max_ns = viewport_index_.max_time_ns();
    viewport_index_.build(timeline, mon_ptr, opts);

    indexed_timeline_next_seq_ = cur_next_seq;
    indexed_timeline_size_ = cur_size;
    indexed_lane_count_ = cur_lanes;
    indexed_monitor_seq_ = cur_mon_seq;
    indexed_filter_sig_ = cur_filter_sig;
    index_dirty_ = false;

    if (!view_initialized_ && !viewport_index_.empty()) {
        fit_view_to_domain();
    } else if (follow_live_tail_ && data_advanced && !viewport_index_.empty()) {
        const std::uint64_t new_max_ns = viewport_index_.max_time_ns();
        if (new_max_ns > prev_max_ns && view_end_ns_ > view_start_ns_) {
            const std::uint64_t window_span = view_end_ns_ - view_start_ns_;
            const std::uint64_t tail_pad = std::max<std::uint64_t>(window_span / 25ULL, 50ULL);
            const std::uint64_t target_end = new_max_ns + tail_pad;
            view_end_ns_ = target_end;
            view_start_ns_ = (target_end > window_span) ? (target_end - window_span) : 0ULL;
        }
    }
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
            ? "Capture Baseline"
            : "Record Delta";
    if (ImGui::Button(record_btn_label)) {
        pending_record_snapshot_delta_ = true;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip(
            "Captures a ProcessStateSnapshot; consecutive captures diff and append "
            "timestamped deltas (plus explicit SamplingGap markers) into ExecutionTimeline.");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Pause", &pause_during_capture_);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Briefly suspend target process while capturing snapshot delta.");
    }

    // Non-intrusive Live Thread Monitor rate selector (`Off`, `4 Hz`, `10 Hz`, `20 Hz`, `50 Hz`).
    ImGui::SameLine();
    int rate_idx = static_cast<int>(monitor_rate_);
    ImGui::SetNextItemWidth(134.0f);
    if (ImGui::Combo("##LiveMonitorRate",
                     &rate_idx,
                     kMonitorRateLabels.data(),
                     static_cast<int>(kMonitorRateLabels.size()))) {
        const auto next_rate = static_cast<LiveMonitorRate>(
            std::clamp(rate_idx, 0, static_cast<int>(kMonitorRateLabels.size()) - 1));
        {
            std::scoped_lock lock(worker_mutex_);
            monitor_rate_ = next_rate;
            worker_session_ =
                (next_rate != LiveMonitorRate::Off) ? model_.shared_process_session() : nullptr;
        }
        if (next_rate != LiveMonitorRate::Off) {
            ensure_monitor_worker_started();
        }
        worker_cv_.notify_all();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip(
            "Non-intrusive background LiveThreadMonitor polling IProcessSession::threads() "
            "and cached stack bounds without stopping or pausing the target process.");
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Checkbox("Sparklines", &show_sparklines_)) {
        // Query-time option; triggers crisp re-layout on next frame.
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
            "Toggle per-lane CPU%% delta & stack-depth sparkline sub-tracks "
            "(individual lanes can also be muted from the left lane header).");
    }

    ImGui::SameLine();
    const bool has_any_data =
        !timeline.empty() || timeline.total_dropped_events() > 0u ||
        latest_monitor_seq_.load(std::memory_order_relaxed) > 0u;
    ImGui::BeginDisabled(!has_any_data);
    if (ImGui::Button("Clear")) {
        pending_clear_timeline_ = true;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    capacity_preset_idx_ = static_cast<int>(preset_index_for_capacity(timeline.capacity()));
    ImGui::SetNextItemWidth(148.0f);
    if (ImGui::Combo("Ring",
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
    const std::uint64_t mon_samples = latest_monitor_seq_.load(std::memory_order_relaxed);
    ImGui::TextDisabled(
        "| Events: %zu/%zu  Samples: %llu  GPU Quads: %zu  Clusters: %zu",
        timeline.size(),
        timeline.capacity(),
        static_cast<unsigned long long>(mon_samples),
        current_frame_.instances.size(),
        current_frame_.coalesced_cluster_count);

    if (!status_message_.empty()) {
        ImGui::TextColored(ImVec4(0.65f, 0.85f, 1.0f, 1.0f), "%s", status_message_.c_str());
    }

    // Explicit DroppedEvents visual callout (never silent ring eviction).
    if (timeline.total_dropped_events() > 0u) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.42f, 0.12f, 0.12f, 0.55f));
        if (ImGui::BeginChild("##DroppedCallout", ImVec2(0.0f, 32.0f), ImGuiChildFlags_Borders)) {
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
                        selected_thread_span_.reset();
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
        if (ImGui::BeginChild("##SamplingGapCallout", ImVec2(0.0f, 32.0f), ImGuiChildFlags_Borders)) {
            ImGui::TextColored(
                ImVec4(1.0f, 0.82f, 0.35f, 1.0f),
                "SAMPLING UNCERTAINTY: %llu SamplingGap marker(s) recorded across non-continuous "
                "snapshot intervals; hatched bands mark unproven sub-intervals.",
                static_cast<unsigned long long>(timeline.sampling_gap_count()));
            ImGui::SameLine();
            if (ImGui::SmallButton("Inspect Gap")) {
                for (const peelf::TimelineEvent& ev : timeline.events()) {
                    if (ev.kind == peelf::TimelineEventKind::SamplingGap) {
                        selected_sequence_ = ev.sequence;
                        selected_thread_span_.reset();
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
    if (descriptors.empty() && !cached_monitor_observed_.has_value()) {
        return;
    }

    ImGui::TextDisabled("Sources:");
    for (const peelf::TimelineSourceDescriptor& desc : descriptors) {
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

    if (cached_monitor_observed_.has_value()) {
        ImGui::SameLine();
        const std::string_view prov_sv =
            peelf::to_string(cached_monitor_observed_.provenance);
        ImGui::TextColored(
            ImVec4(0.35f, 0.90f, 0.65f, 1.0f),
            "[LiveThreadMonitor: %.*s (%zu lanes)]",
            static_cast<int>(prov_sv.size()),
            prov_sv.data(),
            cached_monitor_observed_.value->lanes.size());
    }
}

void ExecutionTimelinePanel::draw_filter_bar() {
    const peelf::ExecutionTimeline& timeline = model_.execution_timeline();

    ImGui::TextDisabled("Kinds:");
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

    ImGui::SetNextItemWidth(205.0f);
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
    ImGui::SetNextItemWidth(200.0f);
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
    if (ImGui::Button("Fit All")) {
        fit_view_to_domain();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Follow Live Tail", &follow_live_tail_);
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll Table", &auto_scroll_table_);
}

void ExecutionTimelinePanel::draw_swimlanes_tab(
    std::span<const peelf::TimelineEvent* const> filtered_events) {
    rebuild_viewport_index_if_needed();

    if (viewport_index_.empty() && filtered_events.empty()) {
        ImGui::TextDisabled(
            "No timeline spans or events recorded yet. Enable 'Monitor: 10..50 Hz' on a live "
            "process, attach the debugger, open a crash dump, or capture a baseline snapshot.");
        return;
    }

    // Viewport navigation & status micro-bar.
    const std::uint64_t visible_span_ns =
        (view_end_ns_ > view_start_ns_) ? (view_end_ns_ - view_start_ns_) : kMinZoomSpanNs;
    const auto rel_start_ns =
        static_cast<std::int64_t>(view_start_ns_) -
        static_cast<std::int64_t>(viewport_index_.origin_ns());
    const std::string start_lbl =
        peelf::format_timeline_offset_ns(rel_start_ns, current_frame_.ruler.major_step_ns);
    const std::string span_lbl = peelf::format_timeline_duration_ns(visible_span_ns);

    ImGui::TextDisabled(
        "Window: %s  (span %s, %s axis)  |  Wheel: Zoom  Drag: Pan  Shift+Drag: dt Ruler  Double-Click: Navigate / Zoom Cluster",
        start_lbl.c_str(),
        span_lbl.c_str(),
        viewport_index_.uses_virtual_sequence_axis() ? "virtual seq" : "monotonic ns");
    if (has_dt_ruler_) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear dt")) {
            has_dt_ruler_ = false;
            is_measuring_dt_ = false;
        }
    }

    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float split_height = std::clamp(avail.y - 135.0f, 180.0f, 520.0f);
    const float right_w = std::max(120.0f, avail.x - kLeftHeaderWidthPx - 6.0f);
    const auto req_canvas_w = static_cast<std::uint32_t>(std::lround(right_w));
    const auto req_canvas_h = static_cast<std::uint32_t>(std::lround(split_height));

    // Lazily initialize Vulkan offscreen canvas & 2D SDF instanced pipeline.
    if (!canvas_initialized_ && vulkan_.device() != VK_NULL_HANDLE) {
        try {
            canvas_.init(
                vulkan_,
                GpuOffscreenCanvasConfig{
                    .sampler_filter = VK_FILTER_NEAREST,
                    .resize_debounce_frames = 2u,
                });
            instance_ring_.attach(vulkan_, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT);
            canvas_initialized_ = true;
        } catch (const std::exception& ex) {
            status_message_ = std::format("Timeline GPU canvas fallback: {}", ex.what());
            canvas_initialized_ = false;
        }
    }

    if (canvas_initialized_) {
        (void)canvas_.ensure_size(req_canvas_w, req_canvas_h);
        if (canvas_.can_use_graphics() && !graphics_pipeline_.valid() &&
            !graphics_pipeline_attempted_) {
            graphics_pipeline_attempted_ = true;
            try {
                const std::array<VkVertexInputBindingDescription, 1> bindings = {{
                    VkVertexInputBindingDescription{
                        .binding = 0u,
                        .stride = sizeof(peelf::TimelineGpuInstance),
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
                graphics_pipeline_.init(
                    vulkan_,
                    canvas_.offscreen_render_pass(),
                    GpuGraphics2DPipelineDesc{
                        .vertex_spirv = shaders::kTimelineSpanVertSpirv,
                        .fragment_spirv = shaders::kTimelineSpanFragSpirv,
                        .vertex_bindings = bindings,
                        .vertex_attributes = attrs,
                        .push_constant_bytes =
                            sizeof(shaders::TimelineViewportPushConstants),
                        .topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
                        .alpha_blend = true,
                    });
            } catch (const std::exception& ex) {
                status_message_ =
                    std::format("Timeline instanced pipeline fallback to CPU RGBA8: {}", ex.what());
            }
        }
    }

    const float effective_w =
        (canvas_initialized_ && canvas_.valid())
            ? static_cast<float>(canvas_.width())
            : right_w;
    const float effective_h =
        (canvas_initialized_ && canvas_.valid())
            ? static_cast<float>(canvas_.height())
            : split_height;

    // Clamp vertical lane scroll before querying frame.
    peelf::TimelineViewportQuery vp_query{};
    vp_query.view_start_ns = view_start_ns_;
    vp_query.view_end_ns = std::max(view_end_ns_, view_start_ns_ + kMinZoomSpanNs);
    vp_query.viewport_width_px = effective_w;
    vp_query.viewport_height_px = effective_h;
    vp_query.ruler_height_px = kRulerHeightPx;
    vp_query.lane_height_px = kLaneHeightPx;
    vp_query.sparkline_height_px = kSparklineSubHeightPx;
    vp_query.lane_scroll_y_px = std::max(0.0f, lane_scroll_y_px_);
    vp_query.min_merge_px = 1.5f;
    vp_query.max_instances = 65'536u;
    vp_query.show_sparklines = show_sparklines_;
    vp_query.emit_ruler_and_separators = true;
    vp_query.selected_event_sequence = selected_sequence_;
    if (selected_thread_span_.has_value()) {
        vp_query.selected_lane = selected_thread_span_->thread;
    }

    current_frame_ = viewport_index_.query(vp_query);
    const float max_scroll_y = std::max(
        0.0f,
        current_frame_.total_lanes_content_height_px -
            std::max(1.0f, effective_h - kRulerHeightPx));
    if (lane_scroll_y_px_ > max_scroll_y) {
        lane_scroll_y_px_ = max_scroll_y;
        vp_query.lane_scroll_y_px = lane_scroll_y_px_;
        current_frame_ = viewport_index_.query(vp_query);
    }

    // Resolve selected hit_id when inspecting a sampled ThreadStateSpan.
    selected_hit_id_ = peelf::kInvalidTimelineHitId;
    if (selected_sequence_.has_value()) {
        for (const peelf::TimelineHitRecord& rec : current_frame_.hit_records) {
            if (rec.event_sequence.has_value() && *rec.event_sequence == *selected_sequence_) {
                selected_hit_id_ = rec.hit_id;
                break;
            }
        }
    } else if (selected_thread_span_.has_value()) {
        for (const peelf::TimelineHitRecord& rec : current_frame_.hit_records) {
            if (rec.kind == peelf::TimelineHitKind::ThreadStateSpan &&
                rec.thread.has_value() &&
                rec.thread->same_lane(selected_thread_span_->thread) &&
                rec.start_ns == selected_thread_span_->span.start_ns &&
                rec.end_ns == selected_thread_span_->span.end_ns) {
                selected_hit_id_ = rec.hit_id;
                break;
            }
        }
    }

    // ========================================================================
    // Left Synchronized Lane Header Column
    // ========================================================================
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.08f, 0.11f, 1.0f));
    if (ImGui::BeginChild(
            "##TracyLaneHeaders",
            ImVec2(kLeftHeaderWidthPx, effective_h),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const ImVec2 hdr_origin = ImGui::GetWindowPos();
        ImDrawList* hdr_dl = ImGui::GetWindowDrawList();
        const ImGuiIO& io = ImGui::GetIO();

        if (ImGui::IsWindowHovered() && std::abs(io.MouseWheel) > 1e-4f) {
            lane_scroll_y_px_ =
                std::clamp(lane_scroll_y_px_ - io.MouseWheel * 28.0f, 0.0f, max_scroll_y);
        }

        // Top-left ruler corner box.
        hdr_dl->AddRectFilled(
            hdr_origin,
            ImVec2(hdr_origin.x + kLeftHeaderWidthPx, hdr_origin.y + kRulerHeightPx),
            IM_COL32(22, 26, 36, 255));
        hdr_dl->AddLine(
            ImVec2(hdr_origin.x, hdr_origin.y + kRulerHeightPx - 1.0f),
            ImVec2(hdr_origin.x + kLeftHeaderWidthPx, hdr_origin.y + kRulerHeightPx - 1.0f),
            IM_COL32(62, 70, 92, 255));
        hdr_dl->AddText(
            ImVec2(hdr_origin.x + 8.0f, hdr_origin.y + 5.0f),
            IM_COL32(188, 198, 222, 255),
            std::format("Lanes ({})", current_frame_.lane_layouts.size()).c_str());

        if (lane_filter_.has_value() || global_lane_only_) {
            ImGui::SetCursorScreenPos(
                ImVec2(hdr_origin.x + kLeftHeaderWidthPx - 64.0f, hdr_origin.y + 3.0f));
            if (ImGui::SmallButton("Show All")) {
                lane_filter_.reset();
                global_lane_only_ = false;
            }
        }

        // Clip lane headers strictly below the ruler row.
        hdr_dl->PushClipRect(
            ImVec2(hdr_origin.x, hdr_origin.y + kRulerHeightPx),
            ImVec2(hdr_origin.x + kLeftHeaderWidthPx, hdr_origin.y + effective_h),
            true);

        for (const peelf::TimelineLaneLayout& lane : current_frame_.lane_layouts) {
            if (lane.y1_px <= kRulerHeightPx || lane.y0_px >= effective_h) {
                continue;
            }
            const float row_y0 = hdr_origin.y + lane.y0_px;
            const float row_y1 = hdr_origin.y + lane.y1_px;
            const float row_h = std::max(1.0f, row_y1 - row_y0);

            const ImU32 bg_col = (lane.lane_index % 2u == 0u)
                                     ? IM_COL32(18, 21, 30, 255)
                                     : IM_COL32(23, 27, 38, 255);
            hdr_dl->AddRectFilled(
                ImVec2(hdr_origin.x, row_y0),
                ImVec2(hdr_origin.x + kLeftHeaderWidthPx, row_y1),
                bg_col);
            hdr_dl->AddLine(
                ImVec2(hdr_origin.x, row_y1 - 1.0f),
                ImVec2(hdr_origin.x + kLeftHeaderWidthPx, row_y1 - 1.0f),
                IM_COL32(46, 52, 68, 255));

            ImGui::PushID(static_cast<int>(lane.lane_index));

            // Per-lane sparkline toggle button on thread lanes when sparklines are enabled.
            if (!lane.is_global_lane && lane.thread.has_value() && show_sparklines_) {
                const bool muted = muted_sparkline_lanes_.contains(*lane.thread);
                ImGui::SetCursorScreenPos(
                    ImVec2(hdr_origin.x + kLeftHeaderWidthPx - 28.0f, row_y0 + 3.0f));
                ImGui::PushStyleColor(
                    ImGuiCol_Text,
                    muted ? ImVec4(0.45f, 0.48f, 0.54f, 1.0f)
                          : ImVec4(0.42f, 0.90f, 0.68f, 1.0f));
                if (ImGui::SmallButton(muted ? "sp-" : "sp+")) {
                    if (muted) {
                        muted_sparkline_lanes_.erase(*lane.thread);
                    } else {
                        muted_sparkline_lanes_.insert(*lane.thread);
                    }
                    index_dirty_ = true;
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Toggle CPU%% & stack-depth sparkline for this thread lane");
                }
            }

            // Interactive lane click hitbox (left portion so it doesn't steal sp+/sp-).
            ImGui::SetCursorScreenPos(ImVec2(hdr_origin.x + 2.0f, row_y0 + 1.0f));
            const float hit_w = (!lane.is_global_lane && show_sparklines_)
                                    ? (kLeftHeaderWidthPx - 34.0f)
                                    : (kLeftHeaderWidthPx - 6.0f);
            if (ImGui::InvisibleButton("##lane_hdr_hit", ImVec2(hit_w, std::max(4.0f, row_h - 2.0f)))) {
                if (io.KeyCtrl) {
                    if (lane.is_global_lane) {
                        global_lane_only_ = !global_lane_only_;
                        lane_filter_.reset();
                    } else if (lane.thread.has_value()) {
                        if (lane_filter_.has_value() && lane_filter_->same_lane(*lane.thread)) {
                            lane_filter_.reset();
                        } else {
                            global_lane_only_ = false;
                            lane_filter_ = *lane.thread;
                        }
                    }
                } else if (lane.thread.has_value() && lane.active) {
                    pending_select_tid_ = lane.thread->tid;
                }
            }
            const bool hdr_hovered = ImGui::IsItemHovered();
            if (hdr_hovered) {
                hdr_dl->AddRectFilled(
                    ImVec2(hdr_origin.x, row_y0),
                    ImVec2(hdr_origin.x + kLeftHeaderWidthPx, row_y1),
                    IM_COL32(255, 255, 255, 16));
            }

            // State indicator bar along left edge.
            ImU32 accent_col = IM_COL32(96, 152, 230, 255);
            if (lane.is_faulting_thread) {
                accent_col = IM_COL32(245, 78, 78, 255);
            } else if (lane.latest_state.has_value()) {
                accent_col = ImGui::ColorConvertFloat4ToU32(
                    thread_state_color(*lane.latest_state));
            }
            hdr_dl->AddRectFilled(
                ImVec2(hdr_origin.x, row_y0 + 1.0f),
                ImVec2(hdr_origin.x + 4.0f, row_y1 - 1.0f),
                accent_col);

            // Primary lane title.
            const ImU32 title_col =
                !lane.active
                    ? IM_COL32(148, 152, 164, 255)
                    : (lane.tid_recycled ? IM_COL32(255, 206, 96, 255)
                                         : IM_COL32(226, 234, 248, 255));
            hdr_dl->AddText(
                ImVec2(hdr_origin.x + 9.0f, row_y0 + 3.0f),
                title_col,
                lane.label.c_str());

            // Secondary telemetry line (live state badge + CPU% + stack depth).
            if (!lane.is_global_lane && row_h >= 28.0f) {
                std::string sub_line{};
                if (lane.latest_state.has_value()) {
                    sub_line = std::string(peelf::to_string(*lane.latest_state));
                } else {
                    sub_line = std::format("{} items", lane.total_item_count);
                }
                if (lane.latest_cpu_ratio > 0.0f || lane.latest_state.has_value()) {
                    sub_line += std::format(" | CPU {:3.0f}%", lane.latest_cpu_ratio * 100.0f);
                }
                if (lane.latest_stack_depth_bytes > 0u) {
                    sub_line += std::format(
                        " | SP {}", format_compact_bytes(lane.latest_stack_depth_bytes));
                }
                hdr_dl->AddText(
                    ImVec2(hdr_origin.x + 9.0f, row_y0 + 17.0f),
                    IM_COL32(146, 164, 192, 255),
                    sub_line.c_str());
            }

            if (hdr_hovered) {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted(lane.label.c_str());
                if (lane.thread.has_value()) {
                    ImGui::Text("TID %llu | Epoch #%llu | Items: %zu",
                                static_cast<unsigned long long>(lane.thread->tid),
                                static_cast<unsigned long long>(lane.thread->epoch),
                                lane.total_item_count);
                    if (lane.latest_state.has_value()) {
                        const std::string_view st_sv = peelf::to_string(*lane.latest_state);
                        ImGui::Text("State: %.*s | CPU: %.1f%%",
                                    static_cast<int>(st_sv.size()),
                                    st_sv.data(),
                                    static_cast<double>(lane.latest_cpu_ratio * 100.0f));
                    }
                    if (lane.high_water_stack_depth_bytes > 0u) {
                        ImGui::Text(
                            "Stack Depth: %s (high-water %s)",
                            format_compact_bytes(lane.latest_stack_depth_bytes).c_str(),
                            format_compact_bytes(lane.high_water_stack_depth_bytes).c_str());
                    }
                    if (lane.is_faulting_thread) {
                        ImGui::TextColored(
                            ImVec4(1.0f, 0.45f, 0.45f, 1.0f),
                            "Faulting / Exception Thread");
                    }
                    if (lane.tid_recycled) {
                        ImGui::TextColored(
                            ImVec4(1.0f, 0.80f, 0.35f, 1.0f),
                            "OS TID reused across distinct thread lifetimes");
                    }
                }
                ImGui::TextDisabled("Click to select thread | Ctrl+Click to solo/filter lane");
                ImGui::EndTooltip();
            }

            ImGui::PopID();
        }

        hdr_dl->PopClipRect();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    // ========================================================================
    // Right GPU-Instanced Offscreen Swimlane Viewport
    // ========================================================================
    ImGui::SameLine();
    const ImVec2 canvas_origin = ImGui::GetCursorScreenPos();
    const ImVec2 canvas_size(effective_w, effective_h);

    if (canvas_initialized_ && canvas_.valid()) {
        ImGui::Image(
            canvas_.imgui_texture_id(vulkan_.current_frame_index()),
            canvas_size);
    } else {
        ImGui::GetWindowDrawList()->AddRectFilled(
            canvas_origin,
            ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y),
            IM_COL32(14, 16, 22, 255));
    }

    ImGui::SetCursorScreenPos(canvas_origin);
    ImGui::InvisibleButton(
        "##TimelineGpuViewportHitBox",
        canvas_size,
        ImGuiButtonFlags_MouseButtonLeft |
            ImGuiButtonFlags_MouseButtonRight |
            ImGuiButtonFlags_MouseButtonMiddle);

    const bool vp_hovered = ImGui::IsItemHovered();
    const bool vp_active = ImGui::IsItemActive();
    const ImGuiIO& io = ImGui::GetIO();
    const float local_mx = io.MousePos.x - canvas_origin.x;
    const float local_my = io.MousePos.y - canvas_origin.y;

    const auto x_to_timestamp_ns = [&](float lx) noexcept -> std::uint64_t {
        const double ratio = std::clamp(
            static_cast<double>(lx) / static_cast<double>(std::max(1.0f, effective_w)),
            0.0,
            1.0);
        const double span_d = static_cast<double>(
            (view_end_ns_ > view_start_ns_) ? (view_end_ns_ - view_start_ns_) : kMinZoomSpanNs);
        const double ts_d = static_cast<double>(view_start_ns_) + ratio * span_d;
        return static_cast<std::uint64_t>(std::max(0.0, ts_d));
    };

    const auto timestamp_to_x_px = [&](std::uint64_t ts_ns) noexcept -> float {
        const double span_d = static_cast<double>(
            (view_end_ns_ > view_start_ns_) ? (view_end_ns_ - view_start_ns_) : kMinZoomSpanNs);
        const double delta_d =
            static_cast<double>(ts_ns) - static_cast<double>(view_start_ns_);
        return static_cast<float>((delta_d / span_d) * static_cast<double>(effective_w));
    };

    // Cursor-anchored wheel zoom (Ctrl/unmodified zooms X time; Alt+wheel scrolls Y lanes).
    if (vp_hovered && std::abs(io.MouseWheel) > 1e-4f) {
        if (io.KeyAlt) {
            lane_scroll_y_px_ =
                std::clamp(lane_scroll_y_px_ - io.MouseWheel * 28.0f, 0.0f, max_scroll_y);
        } else {
            const double anchor_ratio =
                static_cast<double>(local_mx) / static_cast<double>(std::max(1.0f, effective_w));
            const double factor =
                std::pow(kZoomWheelBase, static_cast<double>(io.MouseWheel));
            zoom_view_at_ratio(anchor_ratio, factor);
            if (io.MouseWheel < 0.0f || anchor_ratio < 0.92) {
                follow_live_tail_ = false;
            }
        }
    }

    // Shift + Left-drag: Tracy-style Time Delta Ruler (`dt`).
    if (vp_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && io.KeyShift) {
        is_measuring_dt_ = true;
        has_dt_ruler_ = true;
        dt_start_ns_ = x_to_timestamp_ns(local_mx);
        dt_end_ns_ = dt_start_ns_;
        is_panning_ = false;
    }
    if (is_measuring_dt_) {
        if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            dt_end_ns_ = x_to_timestamp_ns(local_mx);
        } else {
            is_measuring_dt_ = false;
        }
    }

    // Drag pan (Middle-drag or unmodified Left-drag) across X time & Y lanes.
    const bool start_left_pan =
        vp_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !io.KeyShift;
    const bool start_mid_pan =
        vp_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Middle);
    if (start_left_pan || start_mid_pan) {
        is_panning_ = true;
        pan_exceeded_drag_slop_ = false;
        pan_press_x_ = io.MousePos.x;
        pan_press_y_ = io.MousePos.y;
        pan_anchor_start_ns_ = view_start_ns_;
        pan_anchor_end_ns_ = view_end_ns_;
        pan_anchor_scroll_y_ = lane_scroll_y_px_;
    }

    if (is_panning_) {
        const bool still_down =
            ImGui::IsMouseDown(ImGuiMouseButton_Left) ||
            ImGui::IsMouseDown(ImGuiMouseButton_Middle);
        if (still_down && vp_active) {
            const float dx = io.MousePos.x - pan_press_x_;
            const float dy = io.MousePos.y - pan_press_y_;
            if (std::hypot(dx, dy) >= kDragSlopPx) {
                pan_exceeded_drag_slop_ = true;
            }
            if (pan_exceeded_drag_slop_) {
                follow_live_tail_ = false;
                const std::uint64_t anchor_span =
                    (pan_anchor_end_ns_ > pan_anchor_start_ns_)
                        ? (pan_anchor_end_ns_ - pan_anchor_start_ns_)
                        : kMinZoomSpanNs;
                const double ns_per_px =
                    static_cast<double>(anchor_span) /
                    static_cast<double>(std::max(1.0f, effective_w));
                const double shift_ns = -static_cast<double>(dx) * ns_per_px;
                const double new_start_d =
                    std::max(0.0, static_cast<double>(pan_anchor_start_ns_) + shift_ns);
                view_start_ns_ = static_cast<std::uint64_t>(new_start_d);
                view_end_ns_ = view_start_ns_ + anchor_span;
                lane_scroll_y_px_ =
                    std::clamp(pan_anchor_scroll_y_ - dy, 0.0f, max_scroll_y);
            }
        } else {
            is_panning_ = false;
        }
    }

    // Spatial hit-testing (`O(log L + log K_lane)`).
    std::optional<peelf::TimelineHitRecord> hovered_hit{};
    if (vp_hovered && local_my >= kRulerHeightPx && !is_measuring_dt_) {
        hovered_hit = peelf::TimelineViewportIndex::hit_test(
            current_frame_,
            peelf::TimelineHitQuery{
                .x_px = local_mx,
                .y_px = local_my,
                .slop_px = 4.5f,
            });
    }
    hovered_hit_id_ =
        hovered_hit.has_value() ? hovered_hit->hit_id : peelf::kInvalidTimelineHitId;

    // Single-click selection (when not dragging or Shift-measuring).
    if (vp_hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
        !pan_exceeded_drag_slop_ && !io.KeyShift) {
        if (hovered_hit.has_value()) {
            if (hovered_hit->kind == peelf::TimelineHitKind::TimelineEvent &&
                hovered_hit->event_sequence.has_value()) {
                selected_sequence_ = *hovered_hit->event_sequence;
                selected_thread_span_.reset();
            } else if (hovered_hit->kind == peelf::TimelineHitKind::ThreadStateSpan &&
                       hovered_hit->thread.has_value() &&
                       hovered_hit->thread_span.has_value()) {
                selected_sequence_.reset();
                selected_thread_span_ = SelectedThreadSpanState{
                    .thread = *hovered_hit->thread,
                    .span = *hovered_hit->thread_span,
                    .provenance = hovered_hit->provenance,
                };
                pending_select_tid_ = hovered_hit->thread->tid;
            } else if (hovered_hit->kind == peelf::TimelineHitKind::CoalescedCluster &&
                       hovered_hit->cluster.representative_sequence.has_value()) {
                selected_sequence_ = *hovered_hit->cluster.representative_sequence;
                selected_thread_span_.reset();
            }
        } else if (local_my < kRulerHeightPx) {
            has_dt_ruler_ = false;
        }
    }

    // Double-click: zoom into CoalescedCluster OR navigate to Disassembly/Hex/Debugger/Internals!
    if (vp_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
        hovered_hit.has_value()) {
        if (hovered_hit->kind == peelf::TimelineHitKind::CoalescedCluster) {
            const std::uint64_t c0 = hovered_hit->cluster.min_start_ns;
            const std::uint64_t c1 = hovered_hit->cluster.max_end_ns;
            const std::uint64_t c_span =
                std::max<std::uint64_t>((c1 > c0) ? (c1 - c0) : 200ULL, kMinZoomSpanNs);
            const std::uint64_t pad = std::max<std::uint64_t>(c_span / 8ULL, 10ULL);
            view_start_ns_ = (c0 > pad) ? (c0 - pad) : 0ULL;
            view_end_ns_ = c1 + pad;
            follow_live_tail_ = false;
        } else if (hovered_hit->kind == peelf::TimelineHitKind::TimelineEvent &&
                   hovered_hit->event_sequence.has_value()) {
            selected_sequence_ = *hovered_hit->event_sequence;
            selected_thread_span_.reset();
            if (const peelf::TimelineEvent* ev = find_selected_event(); ev != nullptr) {
                pending_navigation_ = peelf::resolve_timeline_navigation(*ev);
            }
        } else if (hovered_hit->kind == peelf::TimelineHitKind::ThreadStateSpan &&
                   hovered_hit->thread_span.has_value()) {
            const peelf::ThreadStateSpan& sp = *hovered_hit->thread_span;
            if (!io.KeyAlt && sp.instruction_pointer.has_value() &&
                *sp.instruction_pointer != 0u) {
                pending_navigation_ = peelf::TimelineNavigationTarget{
                    .primary_panel = peelf::TimelineTargetPanel::Disassembly,
                    .virtual_address = sp.instruction_pointer,
                    .thread = hovered_hit->thread,
                    .description = std::format(
                        "Thread state {} IP 0x{:X}",
                        peelf::to_string(sp.state),
                        *sp.instruction_pointer),
                };
            } else if (sp.stack_pointer.has_value() && *sp.stack_pointer != 0u) {
                pending_navigation_ = peelf::TimelineNavigationTarget{
                    .primary_panel = peelf::TimelineTargetPanel::Hex,
                    .virtual_address = sp.stack_pointer,
                    .thread = hovered_hit->thread,
                    .description = std::format(
                        "Thread state {} SP 0x{:X}",
                        peelf::to_string(sp.state),
                        *sp.stack_pointer),
                };
            }
        }
    }

    // Crisp ImGui text overlay on top of the GPU canvas: major ruler labels + Shift+drag dt ruler.
    ImDrawList* vp_dl = ImGui::GetWindowDrawList();
    vp_dl->PushClipRect(
        canvas_origin,
        ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y),
        true);

    for (const peelf::TimelineRulerTick& tick : current_frame_.ruler.ticks) {
        if (!tick.is_major || tick.label.empty()) {
            continue;
        }
        const float tx = canvas_origin.x + tick.x_px + 4.0f;
        if (tx >= canvas_origin.x - 20.0f && tx <= canvas_origin.x + canvas_size.x - 24.0f) {
            vp_dl->AddText(
                ImVec2(tx, canvas_origin.y + 4.0f),
                IM_COL32(210, 220, 240, 245),
                tick.label.c_str());
        }
    }

    if (has_dt_ruler_) {
        const std::uint64_t lo_ns = std::min(dt_start_ns_, dt_end_ns_);
        const std::uint64_t hi_ns = std::max(dt_start_ns_, dt_end_ns_);
        const std::uint64_t delta_ns = hi_ns - lo_ns;
        const float x0 = canvas_origin.x + timestamp_to_x_px(lo_ns);
        const float x1 = canvas_origin.x + timestamp_to_x_px(hi_ns);

        vp_dl->AddRectFilled(
            ImVec2(x0, canvas_origin.y),
            ImVec2(x1, canvas_origin.y + canvas_size.y),
            IM_COL32(88, 186, 255, 42));
        vp_dl->AddLine(
            ImVec2(x0, canvas_origin.y),
            ImVec2(x0, canvas_origin.y + canvas_size.y),
            IM_COL32(110, 205, 255, 235),
            1.5f);
        vp_dl->AddLine(
            ImVec2(x1, canvas_origin.y),
            ImVec2(x1, canvas_origin.y + canvas_size.y),
            IM_COL32(110, 205, 255, 235),
            1.5f);

        std::string dt_label =
            std::format("dt = {}", peelf::format_timeline_duration_ns(delta_ns));
        if (delta_ns > 0ULL) {
            const double hz = 1.0e9 / static_cast<double>(delta_ns);
            if (hz >= 1.0e6) {
                dt_label += std::format(" ({:.2f} MHz)", hz * 1.0e-6);
            } else if (hz >= 1.0e3) {
                dt_label += std::format(" ({:.2f} kHz)", hz * 1.0e-3);
            } else {
                dt_label += std::format(" ({:.2f} Hz)", hz);
            }
        }
        const ImVec2 txt_sz = ImGui::CalcTextSize(dt_label.c_str());
        const float mid_x = std::clamp(
            (x0 + x1) * 0.5f - txt_sz.x * 0.5f,
            canvas_origin.x + 4.0f,
            std::max(canvas_origin.x + 4.0f, canvas_origin.x + canvas_size.x - txt_sz.x - 12.0f));
        const float badge_y = canvas_origin.y + kRulerHeightPx + 6.0f;
        vp_dl->AddRectFilled(
            ImVec2(mid_x - 5.0f, badge_y - 2.0f),
            ImVec2(mid_x + txt_sz.x + 5.0f, badge_y + txt_sz.y + 2.0f),
            IM_COL32(16, 30, 48, 235),
            4.0f);
        vp_dl->AddRect(
            ImVec2(mid_x - 5.0f, badge_y - 2.0f),
            ImVec2(mid_x + txt_sz.x + 5.0f, badge_y + txt_sz.y + 2.0f),
            IM_COL32(110, 205, 255, 220),
            4.0f);
        vp_dl->AddText(ImVec2(mid_x, badge_y), IM_COL32(235, 246, 255, 255), dt_label.c_str());
    }

    vp_dl->PopClipRect();
    ImGui::PopStyleVar(); // ItemSpacing

    // Rich hover tooltip over hovered GPU span / instant event / coalesced LOD cluster.
    if (vp_hovered && hovered_hit.has_value() && !is_panning_) {
        const peelf::TimelineHitRecord& hit = *hovered_hit;
        ImGui::BeginTooltip();
        const auto rel0 =
            static_cast<std::int64_t>(hit.start_ns) -
            static_cast<std::int64_t>(current_frame_.origin_ns);
        const std::uint64_t dur_ns =
            (hit.end_ns >= hit.start_ns) ? (hit.end_ns - hit.start_ns) : 0ULL;

        if (hit.kind == peelf::TimelineHitKind::CoalescedCluster) {
            const std::string_view dom_sv = peelf::to_string(hit.cluster.dominant_kind);
            ImGui::TextColored(
                unpack_rgba8_imvec4(
                    peelf::timeline_fill_color_rgba8(hit.cluster.dominant_kind, 255u)),
                "Coalesced LOD Cluster (%u items) — Dominant: %.*s",
                hit.cluster.merged_count,
                static_cast<int>(dom_sv.size()),
                dom_sv.data());
            ImGui::Text(
                "Window: %s .. +%s (span %s)",
                peelf::format_timeline_offset_ns(rel0).c_str(),
                peelf::format_timeline_duration_ns(dur_ns).c_str(),
                peelf::format_timeline_duration_ns(dur_ns).c_str());
            if (hit.cluster.max_cpu_ratio > 0.0f) {
                ImGui::Text("Peak CPU: %.1f%%", static_cast<double>(hit.cluster.max_cpu_ratio * 100.0f));
            }
            if (hit.cluster.max_stack_depth_bytes > 0u) {
                ImGui::Text(
                    "Peak Stack Depth: %s",
                    format_compact_bytes(hit.cluster.max_stack_depth_bytes).c_str());
            }
            if (!hit.summary.empty()) {
                ImGui::Separator();
                ImGui::TextWrapped("Representative: %s", hit.summary.c_str());
            }
            ImGui::TextDisabled("Scroll wheel or double-click to zoom into cluster");
        } else if (hit.kind == peelf::TimelineHitKind::ThreadStateSpan &&
                   hit.thread_span.has_value()) {
            const peelf::ThreadStateSpan& sp = *hit.thread_span;
            const std::string_view st_sv = peelf::to_string(sp.state);
            ImGui::TextColored(
                thread_state_color(sp.state),
                "Thread State: %.*s (%u sample%s)",
                static_cast<int>(st_sv.size()),
                st_sv.data(),
                sp.sample_count,
                sp.sample_count == 1u ? "" : "s");
            if (hit.thread.has_value()) {
                ImGui::Text("Lane: TID %llu [epoch #%llu]",
                            static_cast<unsigned long long>(hit.thread->tid),
                            static_cast<unsigned long long>(hit.thread->epoch));
            }
            ImGui::Text(
                "Start: %s | Duration: %s",
                peelf::format_timeline_offset_ns(rel0).c_str(),
                peelf::format_timeline_duration_ns(dur_ns).c_str());
            ImGui::Text("Peak CPU: %.1f%% | Peak Stack: %s",
                        static_cast<double>(sp.peak_cpu_ratio * 100.0f),
                        format_compact_bytes(sp.peak_stack_depth_bytes).c_str());
            if (sp.instruction_pointer.has_value()) {
                const std::string sym =
                    model_.resolve_address_symbol(*sp.instruction_pointer);
                if (!sym.empty()) {
                    ImGui::Text("IP: 0x%llX (%s)",
                                static_cast<unsigned long long>(*sp.instruction_pointer),
                                sym.c_str());
                } else {
                    ImGui::Text("IP: 0x%llX",
                                static_cast<unsigned long long>(*sp.instruction_pointer));
                }
            }
            if (sp.stack_pointer.has_value()) {
                ImGui::Text("SP: 0x%llX",
                            static_cast<unsigned long long>(*sp.stack_pointer));
            }
            if (sp.syscall_number.has_value()) {
                ImGui::Text("Syscall: #%lld", static_cast<long long>(*sp.syscall_number));
            }
            if (!sp.wait_channel.empty()) {
                ImGui::Text("Wait Channel: %s", sp.wait_channel.c_str());
            }
            const std::string_view prov_sv = peelf::to_string(hit.provenance);
            ImGui::TextDisabled(
                "Provenance: %.*s | Double-click -> Disassembly (Alt+Double-click -> Stack Hex)",
                static_cast<int>(prov_sv.size()),
                prov_sv.data());
        } else {
            const std::string_view vis_sv = peelf::to_string(hit.visual_kind);
            ImGui::Text(
                "#%llu  [%.*s]",
                static_cast<unsigned long long>(hit.event_sequence.value_or(0u)),
                static_cast<int>(vis_sv.size()),
                vis_sv.data());
            ImGui::Text(
                "Offset: %s | Span: %s",
                peelf::format_timeline_offset_ns(rel0).c_str(),
                peelf::format_timeline_duration_ns(dur_ns).c_str());
            if (hit.virtual_address.has_value()) {
                const std::string sym =
                    model_.resolve_address_symbol(*hit.virtual_address);
                if (!sym.empty()) {
                    ImGui::Text("Address: 0x%llX (%s)",
                                static_cast<unsigned long long>(*hit.virtual_address),
                                sym.c_str());
                } else {
                    ImGui::Text("Address: 0x%llX",
                                static_cast<unsigned long long>(*hit.virtual_address));
                }
            }
            const std::string_view prov_sv = peelf::to_string(hit.provenance);
            ImGui::TextDisabled("Provenance: %.*s", static_cast<int>(prov_sv.size()), prov_sv.data());
            if (!hit.summary.empty()) {
                ImGui::Separator();
                ImGui::TextWrapped("%s", hit.summary.c_str());
            }
            ImGui::TextDisabled("Click to inspect | Double-click to navigate");
        }
        ImGui::EndTooltip();
    }

    // Arm push constants & pre-pass GPU recording for this frame.
    if (canvas_initialized_ && canvas_.valid()) {
        pending_push_constants_ = shaders::TimelineViewportPushConstants{
            .viewport_width = static_cast<float>(canvas_.width()),
            .viewport_height = static_cast<float>(canvas_.height()),
            .corner_radius_px = 3.0f,
            .border_width_px = 1.0f,
            .hovered_hit_id = hovered_hit_id_,
            .selected_hit_id = selected_hit_id_,
            .hatch_period_px = 8.0f,
            .reserved = 0.0f,
        };
        needs_gpu_record_this_frame_ = true;
    }
}

void ExecutionTimelinePanel::draw_event_table_tab(
    std::span<const peelf::TimelineEvent* const> filtered_events) {
    if (filtered_events.empty()) {
        ImGui::TextDisabled("No timeline events match the active filters.");
        return;
    }

    std::optional<std::uint64_t> clicked_seq{};
    std::optional<peelf::TimelineNavigationTarget> requested_nav{};

    constexpr ImGuiTableFlags kFlags =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("##TimelineEventsTable", 6, kFlags, ImVec2(0.0f, 230.0f))) {
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
        selected_thread_span_.reset();
    }
    if (requested_nav.has_value()) {
        pending_navigation_ = std::move(*requested_nav);
    }
}

void ExecutionTimelinePanel::draw_event_inspector(
    const peelf::TimelineEvent* selected_event) {
    ImGui::SeparatorText("Selected Span / Event Inspector");

    // Inspector mode A: Selected continuous `ThreadStateSpan` from `LiveThreadMonitor`.
    if (selected_event == nullptr && selected_thread_span_.has_value()) {
        const SelectedThreadSpanState& sel = *selected_thread_span_;
        const peelf::ThreadStateSpan& sp = sel.span;
        const std::string_view st_sv = peelf::to_string(sp.state);

        ImGui::Text(
            "Thread Span  |  TID %llu [epoch #%llu]  |",
            static_cast<unsigned long long>(sel.thread.tid),
            static_cast<unsigned long long>(sel.thread.epoch));
        ImGui::SameLine();
        ImGui::TextColored(
            thread_state_color(sp.state),
            "%.*s",
            static_cast<int>(st_sv.size()),
            st_sv.data());

        const bool has_ip = sp.instruction_pointer.has_value() && *sp.instruction_pointer != 0u;
        const bool has_sp = sp.stack_pointer.has_value() && *sp.stack_pointer != 0u;

        ImGui::SameLine();
        ImGui::BeginDisabled(!has_ip);
        if (ImGui::SmallButton("Disassembly (IP)")) {
            pending_navigation_ = peelf::TimelineNavigationTarget{
                .primary_panel = peelf::TimelineTargetPanel::Disassembly,
                .virtual_address = sp.instruction_pointer,
                .thread = sel.thread,
                .description = std::format("Thread TID {} IP 0x{:X}", sel.thread.tid, *sp.instruction_pointer),
            };
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::BeginDisabled(!has_sp);
        if (ImGui::SmallButton("Hex (SP)")) {
            pending_navigation_ = peelf::TimelineNavigationTarget{
                .primary_panel = peelf::TimelineTargetPanel::Hex,
                .virtual_address = sp.stack_pointer,
                .thread = sel.thread,
                .description = std::format("Thread TID {} SP 0x{:X}", sel.thread.tid, *sp.stack_pointer),
            };
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (ImGui::SmallButton("Process Internals")) {
            pending_navigation_ = peelf::TimelineNavigationTarget{
                .primary_panel = peelf::TimelineTargetPanel::ProcessInternals,
                .thread = sel.thread,
                .description = std::format("Thread TID {} Internals", sel.thread.tid),
            };
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Debugger")) {
            pending_navigation_ = peelf::TimelineNavigationTarget{
                .primary_panel = peelf::TimelineTargetPanel::Debugger,
                .virtual_address = sp.instruction_pointer,
                .thread = sel.thread,
                .description = std::format("Thread TID {} Debugger", sel.thread.tid),
            };
        }

        const auto rel0 =
            static_cast<std::int64_t>(sp.start_ns) -
            static_cast<std::int64_t>(viewport_index_.origin_ns());
        ImGui::Text(
            "Interval: %s -> +%s  |  Samples: %u  |  Peak CPU: %.1f%%  |  Peak Stack: %s",
            peelf::format_timeline_offset_ns(rel0).c_str(),
            peelf::format_timeline_duration_ns(sp.duration_ns()).c_str(),
            sp.sample_count,
            static_cast<double>(sp.peak_cpu_ratio * 100.0f),
            format_compact_bytes(sp.peak_stack_depth_bytes).c_str());

        if (has_ip) {
            const std::string sym = model_.resolve_address_symbol(*sp.instruction_pointer);
            ImGui::Text(
                "Instruction Pointer: 0x%llX%s%s",
                static_cast<unsigned long long>(*sp.instruction_pointer),
                sym.empty() ? "" : "  ",
                sym.c_str());
        }
        if (has_sp) {
            ImGui::Text(
                "Stack Pointer: 0x%llX",
                static_cast<unsigned long long>(*sp.stack_pointer));
        }
        if (sp.syscall_number.has_value() || !sp.wait_channel.empty()) {
            ImGui::TextDisabled(
                "Syscall: %s  |  Wait Channel: %s",
                sp.syscall_number.has_value()
                    ? std::format("#{}", *sp.syscall_number).c_str()
                    : "n/a",
                sp.wait_channel.empty() ? "n/a" : sp.wait_channel.c_str());
        }
        return;
    }

    if (selected_event == nullptr) {
        ImGui::TextDisabled(
            "Click any GPU span, instant diamond, or table row above to inspect provenance and navigate.");
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
    sync_target_and_monitor();
    draw_toolbar_and_banners();
    draw_sources_strip();
    ImGui::Separator();
    draw_filter_bar();

    std::vector<const peelf::TimelineEvent*> filtered_events{};
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
        index_dirty_ = true;
        status_message_ = std::format("Timeline ring capacity set to {} events.", new_cap);
    }

    if (pending_clear_timeline_) {
        pending_clear_timeline_ = false;
        model_.clear_execution_timeline();
        live_monitor_.reset();
        latest_monitor_seq_.store(0u, std::memory_order_release);
        crash_dump_seeded_ = false;
        viewport_index_.clear();
        current_frame_ = {};
        index_dirty_ = true;
        view_initialized_ = false;
        selected_sequence_.reset();
        selected_thread_span_.reset();
        lane_filter_.reset();
        has_dt_ruler_ = false;
        status_message_ = "Execution timeline and thread monitor history cleared.";
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
        index_dirty_ = true;
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

void ExecutionTimelinePanel::record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index) {
    if (!needs_gpu_record_this_frame_) {
        return;
    }
    needs_gpu_record_this_frame_ = false;

    if (!canvas_initialized_ || !canvas_.valid()) {
        return;
    }

    constexpr ColorFloat4 kClearColor{
        14.0f / 255.0f,
        16.0f / 255.0f,
        22.0f / 255.0f,
        1.0f,
    };

    const std::span<const peelf::TimelineGpuInstance> instances(current_frame_.instances);
    bool recorded_gpu = false;

    if (canvas_.can_use_graphics() && graphics_pipeline_.valid()) {
        try {
            if (!instances.empty()) {
                instance_ring_.upload<peelf::TimelineGpuInstance>(frame_index, instances);
            }
            const VkBuffer vb = instances.empty() ? VK_NULL_HANDLE : instance_ring_.buffer(frame_index);
            if (instances.empty() || vb != VK_NULL_HANDLE) {
                canvas_.record_instanced_render_pass(
                    cmd,
                    frame_index,
                    kClearColor,
                    [&](VkCommandBuffer pass_cmd, VkExtent2D /*extent*/) {
                        if (instances.empty()) {
                            return;
                        }
                        vkCmdBindPipeline(
                            pass_cmd,
                            VK_PIPELINE_BIND_POINT_GRAPHICS,
                            graphics_pipeline_.pipeline());
                        vkCmdPushConstants(
                            pass_cmd,
                            graphics_pipeline_.pipeline_layout(),
                            VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT,
                            0u,
                            sizeof(pending_push_constants_),
                            &pending_push_constants_);
                        const VkDeviceSize vb_offset = 0u;
                        vkCmdBindVertexBuffers(pass_cmd, 0u, 1u, &vb, &vb_offset);
                        vkCmdDraw(
                            pass_cmd,
                            6u,
                            static_cast<std::uint32_t>(instances.size()),
                            0u,
                            0u);
                    });
                recorded_gpu = true;
            }
        } catch (const std::exception&) {
            recorded_gpu = false;
        }
    }

    if (!recorded_gpu) {
        const peelf::TimelineRasterConfig rcfg{
            .width = canvas_.width(),
            .height = canvas_.height(),
            .clear_rgba8 = peelf::pack_timeline_rgba8(14u, 16u, 22u, 255u),
            .corner_radius_px = pending_push_constants_.corner_radius_px,
            .border_width_px = pending_push_constants_.border_width_px,
            .hatch_period_px = pending_push_constants_.hatch_period_px,
            .hovered_hit_id = pending_push_constants_.hovered_hit_id,
            .selected_hit_id = pending_push_constants_.selected_hit_id,
        };
        peelf::rasterize_timeline_viewport_rgba8_into(instances, rcfg, cpu_rgba8_scratch_);
        canvas_.record_cpu_rgba8_upload(cmd, frame_index, cpu_rgba8_scratch_);
    }
}

} // namespace viewer

