#include <peelf/timeline_viewport.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] constexpr std::uint64_t add_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return (b <= (std::numeric_limits<std::uint64_t>::max() - a))
               ? (a + b)
               : std::numeric_limits<std::uint64_t>::max();
}

[[nodiscard]] constexpr std::uint64_t sub_sat_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? (a - b) : 0ULL;
}

[[nodiscard]] constexpr bool checked_mul_size(
    std::size_t a,
    std::size_t b,
    std::size_t& out) noexcept {
    if (a == 0u || b == 0u) {
        out = 0u;
        return true;
    }
    if (a > (std::numeric_limits<std::size_t>::max() / b)) {
        out = 0u;
        return false;
    }
    out = a * b;
    return true;
}

[[nodiscard]] constexpr std::size_t clamp_ring_capacity(std::size_t requested) noexcept {
    return std::clamp(requested, kMinThreadMonitorRingCapacity, kMaxThreadMonitorRingCapacity);
}

[[nodiscard]] constexpr ThreadSpanState classify_thread_span_state(
    const ThreadInfo& info) noexcept {
    if (info.state == ThreadRunState::Zombie) {
        return ThreadSpanState::Zombie;
    }
    if (info.state == ThreadRunState::Stopped || info.is_suspended) {
        return ThreadSpanState::Stopped;
    }
    if (info.state == ThreadRunState::Waiting) {
        return ThreadSpanState::Waiting;
    }
    if (info.state == ThreadRunState::Sleeping) {
        return ThreadSpanState::Sleeping;
    }
    if (info.syscall_number.has_value() && *info.syscall_number >= 0) {
        return ThreadSpanState::Syscall;
    }
    if (info.state == ThreadRunState::Running) {
        return ThreadSpanState::Running;
    }
    if (!info.wait_channel.empty()) {
        return ThreadSpanState::Waiting;
    }
    return ThreadSpanState::Running;
}

struct ResolvedStackSample {
    bool valid{false};
    std::uint64_t depth_bytes{0};
    std::uint64_t low_address{0};
    std::uint64_t high_address{0};
};

[[nodiscard]] ResolvedStackSample resolve_stack_depth_for_sp(
    std::span<const MemoryRegion> regions,
    std::uint32_t tid,
    std::uint64_t sp) noexcept {
    // Pass 1: match explicit stack region (attributed to `tid` or general stack).
    const MemoryRegion* fallback_stack = nullptr;
    for (const auto& region : regions) {
        if (region.end_address <= region.start_address) {
            continue;
        }
        if (sp < region.start_address || sp > region.end_address) {
            continue;
        }
        const bool is_stack_region =
            region.kind == MemoryRegionKind::Stack ||
            region.usage.owner_tid.has_value() ||
            region.pathname.starts_with("[stack");
        if (!is_stack_region) {
            continue;
        }
        if (region.usage.owner_tid.has_value() && *region.usage.owner_tid == tid) {
            return ResolvedStackSample{
                .valid = true,
                .depth_bytes = sub_sat_u64(region.end_address, sp),
                .low_address = region.start_address,
                .high_address = region.end_address,
            };
        }
        if (fallback_stack == nullptr) {
            fallback_stack = &region;
        }
    }
    if (fallback_stack != nullptr) {
        return ResolvedStackSample{
            .valid = true,
            .depth_bytes = sub_sat_u64(fallback_stack->end_address, sp),
            .low_address = fallback_stack->start_address,
            .high_address = fallback_stack->end_address,
        };
    }

    // Pass 2: match any mapped readable+writable non-reserved region containing SP.
    for (const auto& region : regions) {
        if (region.end_address <= region.start_address || region.usage.is_reserved_only) {
            continue;
        }
        if (!region.protection.readable || !region.protection.writable) {
            continue;
        }
        if (sp >= region.start_address && sp <= region.end_address) {
            return ResolvedStackSample{
                .valid = true,
                .depth_bytes = sub_sat_u64(region.end_address, sp),
                .low_address = region.start_address,
                .high_address = region.end_address,
            };
        }
    }
    return ResolvedStackSample{};
}

[[nodiscard]] double project_time_to_x(
    std::uint64_t ts_ns,
    std::uint64_t view_start_ns,
    std::uint64_t view_span_ns,
    float track_x0_px,
    float track_width_px) noexcept {
    if (view_span_ns == 0ULL || track_width_px <= 0.0f) {
        return static_cast<double>(track_x0_px);
    }
    const double rel_ns =
        (ts_ns >= view_start_ns)
            ? static_cast<double>(ts_ns - view_start_ns)
            : -static_cast<double>(view_start_ns - ts_ns);
    return static_cast<double>(track_x0_px) +
           (rel_ns / static_cast<double>(view_span_ns)) * static_cast<double>(track_width_px);
}

[[nodiscard]] std::uint32_t sparkline_cpu_color_rgba8(
    float cpu_ratio,
    float kernel_share) noexcept {
    const float clamped_cpu = std::clamp(cpu_ratio, 0.0f, 1.0f);
    const float clamped_kern = std::clamp(kernel_share, 0.0f, 1.0f);
    // Blend from cool emerald (low CPU) to warm amber/coral (high CPU / high kernel).
    const float r_f = 64.0f + clamped_cpu * 172.0f + clamped_kern * 18.0f;
    const float g_f = 198.0f - clamped_cpu * 84.0f - clamped_kern * 36.0f;
    const float b_f = 126.0f - clamped_cpu * 56.0f + clamped_kern * 44.0f;
    const auto to_u8 = [](float v) noexcept -> std::uint8_t {
        const float c = std::clamp(v, 0.0f, 255.0f);
        return static_cast<std::uint8_t>(c + 0.5f);
    };
    return pack_timeline_rgba8(to_u8(r_f), to_u8(g_f), to_u8(b_f), 215u);
}

struct UnpackedRgba {
    float r{0.0f};
    float g{0.0f};
    float b{0.0f};
    float a{0.0f};
};

[[nodiscard]] constexpr UnpackedRgba unpack_rgba8(std::uint32_t rgba) noexcept {
    constexpr float inv_255 = 1.0f / 255.0f;
    return UnpackedRgba{
        .r = static_cast<float>(rgba & 0xFFu) * inv_255,
        .g = static_cast<float>((rgba >> 8u) & 0xFFu) * inv_255,
        .b = static_cast<float>((rgba >> 16u) & 0xFFu) * inv_255,
        .a = static_cast<float>((rgba >> 24u) & 0xFFu) * inv_255,
    };
}

[[nodiscard]] constexpr std::uint8_t unit_float_to_u8(float v) noexcept {
    const float c = std::clamp(v, 0.0f, 1.0f);
    return static_cast<std::uint8_t>(c * 255.0f + 0.5f);
}

[[nodiscard]] float sd_rounded_box(
    float dx,
    float dy,
    float hx,
    float hy,
    float radius) noexcept {
    const float r = std::clamp(radius, 0.0f, std::min(hx, hy));
    const float qx = std::abs(dx) - (hx - r);
    const float qy = std::abs(dy) - (hy - r);
    const float ox = std::max(qx, 0.0f);
    const float oy = std::max(qy, 0.0f);
    const float outside = std::sqrt(ox * ox + oy * oy);
    const float inside = std::min(std::max(qx, qy), 0.0f);
    return outside + inside - r;
}

[[nodiscard]] float sd_diamond(
    float dx,
    float dy,
    float hx,
    float hy) noexcept {
    const float rx = std::max(hx, 0.5f);
    const float ry = std::max(hy, 0.5f);
    const float norm = (std::abs(dx) / rx) + (std::abs(dy) / ry) - 1.0f;
    return norm * std::min(rx, ry) * 0.70710678f;
}

} // namespace

// ============================================================================
// LiveThreadMonitor
// ============================================================================

LiveThreadMonitor::LiveThreadMonitor(
    LiveThreadMonitorConfig config,
    ThreadCreationIdentityResolver identity_resolver)
    : config_(config),
      identity_resolver_(std::move(identity_resolver)) {
    config_.max_spans_per_lane = clamp_ring_capacity(config_.max_spans_per_lane);
    config_.max_metrics_per_lane = clamp_ring_capacity(config_.max_metrics_per_lane);
    if (!identity_resolver_) {
        identity_resolver_ = [](std::uint32_t pid, std::uint32_t tid) {
            return query_thread_creation_identity(pid, tid).value_or(0ULL);
        };
    }
}

void LiveThreadMonitor::reset() noexcept {
    std::scoped_lock lock(mutex_);
    tracked_pid_ = 0u;
    sample_sequence_ = 0u;
    first_sample_ns_ = 0u;
    last_sample_ns_ = 0u;
    samples_since_region_refresh_ = 0u;
    seeded_from_crash_dump_ = false;
    region_cache_partial_ = false;
    provenance_ = ProvenanceTag::ProcOrOsApi;
    provider_detail_.clear();
    cached_regions_.clear();
    lanes_.clear();
    tid_trackers_.clear();
}

void LiveThreadMonitor::set_config(LiveThreadMonitorConfig config) {
    config.max_spans_per_lane = clamp_ring_capacity(config.max_spans_per_lane);
    config.max_metrics_per_lane = clamp_ring_capacity(config.max_metrics_per_lane);
    std::scoped_lock lock(mutex_);
    config_ = config;
    for (auto& lane : lanes_) {
        while (lane.spans.size() > config_.max_spans_per_lane) {
            lane.spans.pop_front();
            ++lane.dropped_span_count;
        }
        while (lane.metrics.size() > config_.max_metrics_per_lane) {
            lane.metrics.pop_front();
            ++lane.dropped_metric_count;
        }
    }
}

LiveThreadMonitorConfig LiveThreadMonitor::config() const noexcept {
    std::scoped_lock lock(mutex_);
    return config_;
}

std::uint64_t LiveThreadMonitor::sample_sequence() const noexcept {
    std::scoped_lock lock(mutex_);
    return sample_sequence_;
}

std::size_t LiveThreadMonitor::lane_count() const noexcept {
    std::scoped_lock lock(mutex_);
    return lanes_.size();
}

void LiveThreadMonitor::refresh_cached_regions_locked(
    IProcessSession& session,
    std::span<const ThreadInfo> threads,
    bool force_refresh) {
    const std::uint32_t stride = std::max(1u, config_.region_refresh_stride_samples);
    const bool due = force_refresh || cached_regions_.empty() ||
                     (samples_since_region_refresh_ >= stride);
    if (!due) {
        ++samples_since_region_refresh_;
        return;
    }
    samples_since_region_refresh_ = 0u;
    auto regions_res = session.memory_regions();
    if (!regions_res.has_value()) {
        region_cache_partial_ = true;
        return;
    }
    cached_regions_ = std::move(*regions_res);
    attribute_thread_stacks(cached_regions_, threads, session.pid());
    region_cache_partial_ = false;
}

std::size_t LiveThreadMonitor::resolve_or_create_lane_locked(
    std::uint32_t pid,
    const ThreadInfo& thread_info) {
    const std::uint64_t queried_identity =
        identity_resolver_ ? identity_resolver_(pid, thread_info.tid) : 0ULL;

    for (auto& tracker : tid_trackers_) {
        if (tracker.tid != thread_info.tid) {
            continue;
        }
        bool recycled = false;
        if (queried_identity != 0ULL && tracker.creation_identity != 0ULL) {
            recycled = (queried_identity != tracker.creation_identity);
        } else if (!tracker.currently_alive) {
            recycled = true;
        }

        if (!recycled) {
            if (queried_identity != 0ULL && tracker.creation_identity == 0ULL) {
                tracker.creation_identity = queried_identity;
                lanes_[tracker.lane_index].identity.creation_identity = queried_identity;
            }
            return tracker.lane_index;
        }

        if (tracker.lane_index < lanes_.size()) {
            lanes_[tracker.lane_index].active = false;
        }
        ++tracker.epoch;
        tracker.creation_identity = queried_identity;
        const std::size_t new_index = lanes_.size();
        tracker.lane_index = new_index;

        InternalLane lane{};
        lane.identity = ThreadIdentity{
            .tid = thread_info.tid,
            .creation_identity = (queried_identity != 0ULL)
                                     ? std::optional<std::uint64_t>{queried_identity}
                                     : std::nullopt,
            .epoch = tracker.epoch,
        };
        lane.name = thread_info.name;
        lane.active = true;
        lane.tid_recycled = true;
        lanes_.push_back(std::move(lane));
        return new_index;
    }

    const std::size_t new_index = lanes_.size();
    tid_trackers_.push_back(TidTracker{
        .tid = thread_info.tid,
        .creation_identity = queried_identity,
        .epoch = 1ULL,
        .lane_index = new_index,
        .currently_alive = false,
    });

    InternalLane lane{};
    lane.identity = ThreadIdentity{
        .tid = thread_info.tid,
        .creation_identity = (queried_identity != 0ULL)
                                 ? std::optional<std::uint64_t>{queried_identity}
                                 : std::nullopt,
        .epoch = 1ULL,
    };
    lane.name = thread_info.name;
    lane.active = true;
    lanes_.push_back(std::move(lane));
    return new_index;
}

Result<std::size_t> LiveThreadMonitor::sample(
    IProcessSession& session,
    std::stop_token stop_token,
    std::optional<std::uint64_t> explicit_timestamp_ns) {
    if (stop_token.stop_requested()) {
        return make_error("Thread monitor sample cancelled");
    }

    if (session.is_crash_dump()) {
        if (auto* dump = dynamic_cast<ICrashDumpSession*>(&session); dump != nullptr) {
            return seed_from_crash_dump(*dump, explicit_timestamp_ns);
        }
    }

    auto threads_res = session.threads();
    if (!threads_res.has_value()) {
        return std::unexpected(threads_res.error());
    }
    if (stop_token.stop_requested()) {
        return make_error("Thread monitor sample cancelled");
    }

    const auto& threads = *threads_res;
    const std::uint32_t pid = session.pid();

    std::scoped_lock lock(mutex_);
    if (tracked_pid_ != 0u && tracked_pid_ != pid) {
        tracked_pid_ = 0u;
        sample_sequence_ = 0u;
        first_sample_ns_ = 0u;
        last_sample_ns_ = 0u;
        samples_since_region_refresh_ = 0u;
        seeded_from_crash_dump_ = false;
        cached_regions_.clear();
        lanes_.clear();
        tid_trackers_.clear();
    }
    tracked_pid_ = pid;
    seeded_from_crash_dump_ = session.is_crash_dump();
    provenance_ = session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::ProcOrOsApi;
    provider_detail_ = session.is_crash_dump() ? "Offline crash-dump thread state"
                                               : "Non-intrusive live OS thread & stack sampler";

    const std::uint64_t next_seq = sample_sequence_ + 1ULL;
    const TargetInstanceId target_id{
        .backend = session.is_crash_dump() ? BackendKind::CrashDumpElfCore
                                           : BackendKind::LiveNativeReadOnly,
        .pid = pid,
    };
    std::uint64_t now_ns =
        explicit_timestamp_ns.has_value()
            ? *explicit_timestamp_ns
            : CaptureStamp::capture_now(target_id, next_seq, false).monotonic_ns;
    if (now_ns < last_sample_ns_) {
        now_ns = last_sample_ns_;
    }

    refresh_cached_regions_locked(session, threads, cached_regions_.empty());

    // Check whether any sampled SP missed cached stack regions; if so and we didn't just refresh,
    // refresh once immediately so newly created thread stacks resolve on their first sample.
    if (samples_since_region_refresh_ > 0u) {
        bool any_sp_unmatched = false;
        for (const auto& t : threads) {
            if (t.stack_pointer.has_value() && *t.stack_pointer != 0ULL) {
                const auto probe = resolve_stack_depth_for_sp(cached_regions_, t.tid, *t.stack_pointer);
                if (!probe.valid) {
                    any_sp_unmatched = true;
                    break;
                }
            }
        }
        if (any_sp_unmatched) {
            refresh_cached_regions_locked(session, threads, true);
        }
    }

    std::vector<bool> seen_lane(lanes_.size(), false);

    for (const auto& t : threads) {
        if (stop_token.stop_requested()) {
            return make_error("Thread monitor sample cancelled");
        }

        const std::size_t lane_idx = resolve_or_create_lane_locked(pid, t);
        if (lane_idx >= seen_lane.size()) {
            seen_lane.resize(lanes_.size(), false);
        }
        seen_lane[lane_idx] = true;

        bool was_alive_prev = false;
        for (auto& tracker : tid_trackers_) {
            if (tracker.lane_index == lane_idx) {
                was_alive_prev = tracker.currently_alive;
                tracker.currently_alive = true;
                break;
            }
        }

        auto& lane = lanes_[lane_idx];
        lane.active = true;
        if (!t.name.empty()) {
            lane.name = t.name;
        }

        const ThreadSpanState span_state = classify_thread_span_state(t);

        // Compute CPU% delta and kernel share ratio.
        float cpu_ratio = 0.0f;
        float kernel_share = 0.0f;
        const std::uint64_t wall_delta_ns =
            (lane.last_sample_ns > 0ULL && now_ns > lane.last_sample_ns)
                ? (now_ns - lane.last_sample_ns)
                : 0ULL;

        if (wall_delta_ns > 0ULL &&
            t.user_time_ns.has_value() &&
            lane.prev_user_time_ns.has_value()) {
            const std::uint64_t delta_user = sub_sat_u64(*t.user_time_ns, *lane.prev_user_time_ns);
            const std::uint64_t delta_kernel =
                (t.kernel_time_ns.has_value() && lane.prev_kernel_time_ns.has_value())
                    ? sub_sat_u64(*t.kernel_time_ns, *lane.prev_kernel_time_ns)
                    : 0ULL;
            const std::uint64_t delta_total = add_sat_u64(delta_user, delta_kernel);
            const double raw_cpu =
                static_cast<double>(delta_total) / static_cast<double>(wall_delta_ns);
            if (std::isfinite(raw_cpu)) {
                cpu_ratio = static_cast<float>(std::clamp(raw_cpu, 0.0, 1.0));
            }
            if (delta_total > 0ULL) {
                const double raw_kern =
                    static_cast<double>(delta_kernel) / static_cast<double>(delta_total);
                if (std::isfinite(raw_kern)) {
                    kernel_share = static_cast<float>(std::clamp(raw_kern, 0.0, 1.0));
                }
            }
        } else if (t.cpu_percent.has_value() && std::isfinite(*t.cpu_percent)) {
            cpu_ratio = static_cast<float>(std::clamp(*t.cpu_percent / 100.0, 0.0, 1.0));
        }

        lane.prev_user_time_ns = t.user_time_ns;
        lane.prev_kernel_time_ns = t.kernel_time_ns;

        // Compute stack depth against mapped stack / RW region.
        ResolvedStackSample stack_sample{};
        if (t.stack_pointer.has_value() && *t.stack_pointer != 0ULL) {
            stack_sample = resolve_stack_depth_for_sp(cached_regions_, t.tid, *t.stack_pointer);
            if (stack_sample.valid) {
                lane.stack_low_address = stack_sample.low_address;
                lane.stack_high_address = stack_sample.high_address;
                lane.high_water_stack_depth_bytes =
                    std::max(lane.high_water_stack_depth_bytes, stack_sample.depth_bytes);
            }
        }

        lane.latest_state = span_state;
        lane.latest_cpu_ratio = cpu_ratio;
        lane.latest_kernel_share_ratio = kernel_share;
        lane.latest_stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL;
        lane.latest_instruction_pointer = t.instruction_pointer;
        lane.latest_stack_pointer = t.stack_pointer;
        lane.latest_syscall_number = t.syscall_number;
        lane.latest_wait_channel = t.wait_channel;

        const auto push_span = [&](ThreadStateSpan span) {
            if (lane.spans.size() >= config_.max_spans_per_lane) {
                lane.spans.pop_front();
                ++lane.dropped_span_count;
            }
            lane.spans.push_back(std::move(span));
        };

        const auto make_current_span = [&](std::uint64_t s_ns, std::uint64_t e_ns) {
            return ThreadStateSpan{
                .start_ns = s_ns,
                .end_ns = e_ns,
                .state = span_state,
                .sample_count = 1u,
                .instruction_pointer = t.instruction_pointer,
                .stack_pointer = t.stack_pointer,
                .syscall_number = t.syscall_number,
                .wait_channel = t.wait_channel,
                .peak_cpu_ratio = cpu_ratio,
                .peak_stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL,
            };
        };

        if (lane.spans.empty() || !was_alive_prev) {
            push_span(make_current_span(now_ns, now_ns));
        } else if (config_.sampling_gap_threshold_ns > 0ULL &&
                   wall_delta_ns > config_.sampling_gap_threshold_ns) {
            // Do not stretch the previous state across an unobserved sampling gap.
            push_span(ThreadStateSpan{
                .start_ns = lane.last_sample_ns,
                .end_ns = now_ns,
                .state = ThreadSpanState::SamplingGap,
                .sample_count = 1u,
            });
            push_span(make_current_span(now_ns, now_ns));
        } else {
            auto& prev_span = lane.spans.back();
            if (prev_span.state == span_state) {
                prev_span.end_ns = now_ns;
                if (prev_span.sample_count < std::numeric_limits<std::uint32_t>::max()) {
                    ++prev_span.sample_count;
                }
                prev_span.instruction_pointer = t.instruction_pointer;
                prev_span.stack_pointer = t.stack_pointer;
                prev_span.syscall_number = t.syscall_number;
                prev_span.wait_channel = t.wait_channel;
                prev_span.peak_cpu_ratio = std::max(prev_span.peak_cpu_ratio, cpu_ratio);
                if (stack_sample.valid) {
                    prev_span.peak_stack_depth_bytes =
                        std::max(prev_span.peak_stack_depth_bytes, stack_sample.depth_bytes);
                }
            } else {
                prev_span.end_ns = now_ns;
                push_span(make_current_span(now_ns, now_ns));
            }
        }

        if (lane.metrics.size() >= config_.max_metrics_per_lane) {
            lane.metrics.pop_front();
            ++lane.dropped_metric_count;
        }
        lane.metrics.push_back(ThreadMetricPoint{
            .timestamp_ns = now_ns,
            .cpu_ratio = cpu_ratio,
            .kernel_share_ratio = kernel_share,
            .stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL,
            .stack_depth_valid = stack_sample.valid,
        });

        lane.last_sample_ns = now_ns;
    }

    // Mark lanes whose threads were absent in this sample as exited/inactive.
    for (std::size_t i = 0; i < lanes_.size(); ++i) {
        if (i >= seen_lane.size() || !seen_lane[i]) {
            lanes_[i].active = false;
        }
    }
    for (auto& tracker : tid_trackers_) {
        if (tracker.lane_index >= seen_lane.size() || !seen_lane[tracker.lane_index]) {
            tracker.currently_alive = false;
        }
    }

    sample_sequence_ = next_seq;
    if (first_sample_ns_ == 0ULL) {
        first_sample_ns_ = now_ns;
    }
    last_sample_ns_ = now_ns;
    return threads.size();
}

Result<std::size_t> LiveThreadMonitor::seed_from_crash_dump(
    ICrashDumpSession& dump_session,
    std::optional<std::uint64_t> explicit_timestamp_ns) {
    auto threads_res = dump_session.threads();
    if (!threads_res.has_value()) {
        return std::unexpected(threads_res.error());
    }

    const auto& threads = *threads_res;
    const auto& summary = dump_session.crash_summary();
    const std::optional<std::uint32_t> faulting_tid =
        summary.exception.has_value() ? summary.exception->thread_id : std::nullopt;

    std::scoped_lock lock(mutex_);
    tracked_pid_ = dump_session.pid();
    sample_sequence_ = 1ULL;
    const std::uint64_t start_ns = explicit_timestamp_ns.value_or(1'000'000ULL);
    const std::uint64_t duration_ns = std::max<std::uint64_t>(1'000ULL, config_.crash_dump_span_duration_ns);
    const std::uint64_t end_ns = add_sat_u64(start_ns, duration_ns);
    first_sample_ns_ = start_ns;
    last_sample_ns_ = end_ns;
    seeded_from_crash_dump_ = true;
    provenance_ = ProvenanceTag::CrashDump;
    provider_detail_ = "Offline crash-dump thread & stack seed";
    lanes_.clear();
    tid_trackers_.clear();
    cached_regions_.clear();

    if (auto regions_res = dump_session.memory_regions(); regions_res.has_value()) {
        cached_regions_ = std::move(*regions_res);
        attribute_thread_stacks(cached_regions_, threads, tracked_pid_);
        region_cache_partial_ = false;
    } else {
        region_cache_partial_ = true;
    }

    for (const auto& t : threads) {
        const std::size_t lane_idx = resolve_or_create_lane_locked(tracked_pid_, t);
        for (auto& tracker : tid_trackers_) {
            if (tracker.lane_index == lane_idx) {
                tracker.currently_alive = true;
                break;
            }
        }
        auto& lane = lanes_[lane_idx];
        lane.active = false;
        lane.is_faulting_thread = faulting_tid.has_value() && (*faulting_tid == t.tid);
        if (!t.name.empty()) {
            lane.name = t.name;
        }

        const ThreadSpanState span_state =
            lane.is_faulting_thread ? ThreadSpanState::Stopped : classify_thread_span_state(t);

        ResolvedStackSample stack_sample{};
        if (t.stack_pointer.has_value() && *t.stack_pointer != 0ULL) {
            stack_sample = resolve_stack_depth_for_sp(cached_regions_, t.tid, *t.stack_pointer);
            if (stack_sample.valid) {
                lane.stack_low_address = stack_sample.low_address;
                lane.stack_high_address = stack_sample.high_address;
                lane.high_water_stack_depth_bytes = stack_sample.depth_bytes;
            }
        }

        float cpu_ratio = 0.0f;
        if (t.cpu_percent.has_value() && std::isfinite(*t.cpu_percent)) {
            cpu_ratio = static_cast<float>(std::clamp(*t.cpu_percent / 100.0, 0.0, 1.0));
        }

        lane.latest_state = span_state;
        lane.latest_cpu_ratio = cpu_ratio;
        lane.latest_stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL;
        lane.latest_instruction_pointer = t.instruction_pointer;
        lane.latest_stack_pointer = t.stack_pointer;
        lane.latest_syscall_number = t.syscall_number;
        lane.latest_wait_channel = t.wait_channel;
        lane.last_sample_ns = end_ns;

        lane.spans.push_back(ThreadStateSpan{
            .start_ns = start_ns,
            .end_ns = end_ns,
            .state = span_state,
            .sample_count = 1u,
            .instruction_pointer = t.instruction_pointer,
            .stack_pointer = t.stack_pointer,
            .syscall_number = t.syscall_number,
            .wait_channel = t.wait_channel,
            .peak_cpu_ratio = cpu_ratio,
            .peak_stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL,
        });
        lane.metrics.push_back(ThreadMetricPoint{
            .timestamp_ns = start_ns,
            .cpu_ratio = cpu_ratio,
            .kernel_share_ratio = 0.0f,
            .stack_depth_bytes = stack_sample.valid ? stack_sample.depth_bytes : 0ULL,
            .stack_depth_valid = stack_sample.valid,
        });
    }

    return threads.size();
}

Observed<LiveThreadMonitorSnapshot> LiveThreadMonitor::snapshot() const {
    std::scoped_lock lock(mutex_);
    LiveThreadMonitorSnapshot out{};
    out.pid = tracked_pid_;
    out.sample_sequence = sample_sequence_;
    out.first_sample_ns = first_sample_ns_;
    out.last_sample_ns = last_sample_ns_;
    out.seeded_from_crash_dump = seeded_from_crash_dump_;
    out.lanes.reserve(lanes_.size());

    bool any_dropped = false;
    for (const auto& src : lanes_) {
        ThreadMonitorLane dst{};
        dst.identity = src.identity;
        dst.name = src.name;
        dst.active = src.active;
        dst.tid_recycled = src.tid_recycled;
        dst.is_faulting_thread = src.is_faulting_thread;
        dst.latest_state = src.latest_state;
        dst.latest_cpu_ratio = src.latest_cpu_ratio;
        dst.latest_kernel_share_ratio = src.latest_kernel_share_ratio;
        dst.latest_stack_depth_bytes = src.latest_stack_depth_bytes;
        dst.high_water_stack_depth_bytes = src.high_water_stack_depth_bytes;
        dst.stack_low_address = src.stack_low_address;
        dst.stack_high_address = src.stack_high_address;
        dst.latest_instruction_pointer = src.latest_instruction_pointer;
        dst.latest_stack_pointer = src.latest_stack_pointer;
        dst.latest_syscall_number = src.latest_syscall_number;
        dst.latest_wait_channel = src.latest_wait_channel;
        dst.dropped_span_count = src.dropped_span_count;
        dst.dropped_metric_count = src.dropped_metric_count;
        dst.spans.assign(src.spans.begin(), src.spans.end());
        dst.metrics.assign(src.metrics.begin(), src.metrics.end());
        if (src.dropped_span_count > 0ULL || src.dropped_metric_count > 0ULL) {
            any_dropped = true;
        }
        out.lanes.push_back(std::move(dst));
    }

    CaptureStamp stamp{};
    stamp.target_id = TargetInstanceId{
        .backend = seeded_from_crash_dump_ ? BackendKind::CrashDumpElfCore
                                           : BackendKind::LiveNativeReadOnly,
        .pid = tracked_pid_,
    };
    stamp.snapshot_revision = sample_sequence_;
    stamp.monotonic_ns = last_sample_ns_;

    if (sample_sequence_ == 0ULL) {
        return Observed<LiveThreadMonitorSnapshot>::unavailable(
            ProvenanceTag::ProcOrOsApi,
            "No thread monitor samples captured yet",
            stamp);
    }

    std::vector<Evidence> ev{{Evidence{
        .tag = provenance_,
        .source = std::string(to_string(provenance_)),
        .detail = provider_detail_,
    }}};
    if (region_cache_partial_ || any_dropped) {
        return Observed<LiveThreadMonitorSnapshot>::partial(
            std::move(out),
            provenance_,
            region_cache_partial_
                ? "Memory region map unavailable; stack-depth attribution partial"
                : "Bounded per-lane ring evicted oldest samples",
            stamp,
            std::move(ev));
    }
    return Observed<LiveThreadMonitorSnapshot>::complete(
        std::move(out),
        provenance_,
        stamp,
        std::move(ev));
}

// ============================================================================
// Adaptive Nanosecond Ruler Formatting & Tick Generation
// ============================================================================

std::string format_timeline_duration_ns(std::uint64_t duration_ns) {
    if (duration_ns < 1'000ULL) {
        return std::format("{} ns", duration_ns);
    }
    if (duration_ns < 1'000'000ULL) {
        const double us = static_cast<double>(duration_ns) / 1'000.0;
        if (duration_ns % 1'000ULL == 0ULL) {
            return std::format("{} us", duration_ns / 1'000ULL);
        }
        return std::format("{:.3f} us", us);
    }
    if (duration_ns < 1'000'000'000ULL) {
        const double ms = static_cast<double>(duration_ns) / 1'000'000.0;
        if (duration_ns % 1'000'000ULL == 0ULL) {
            return std::format("{} ms", duration_ns / 1'000'000ULL);
        }
        return std::format("{:.3f} ms", ms);
    }
    if (duration_ns < 60'000'000'000ULL) {
        const double sec = static_cast<double>(duration_ns) / 1'000'000'000.0;
        return std::format("{:.3f} s", sec);
    }
    const std::uint64_t minutes = duration_ns / 60'000'000'000ULL;
    const double rem_sec =
        static_cast<double>(duration_ns % 60'000'000'000ULL) / 1'000'000'000.0;
    return std::format("{}m {:.1f}s", minutes, rem_sec);
}

std::string format_timeline_offset_ns(
    std::int64_t delta_from_origin_ns,
    std::uint64_t step_ns) {
    const char sign = delta_from_origin_ns < 0 ? '-' : '+';
    const std::uint64_t abs_ns =
        delta_from_origin_ns < 0
            ? static_cast<std::uint64_t>(-(delta_from_origin_ns + 1)) + 1ULL
            : static_cast<std::uint64_t>(delta_from_origin_ns);

    if (abs_ns == 0ULL) {
        if (step_ns >= 1'000'000'000ULL) {
            return "+0 s";
        }
        if (step_ns >= 1'000'000ULL) {
            return "+0 ms";
        }
        if (step_ns >= 1'000ULL) {
            return "+0 us";
        }
        return "+0 ns";
    }

    // Choose unit & fractional precision so adjacent ticks separated by `step_ns`
    // always produce distinct labels even when zoomed deeply into a later offset.
    if (abs_ns < 1'000ULL || step_ns < 10ULL) {
        return std::format("{}{} ns", sign, abs_ns);
    }
    if (abs_ns < 1'000'000ULL) {
        if (step_ns >= 1'000ULL && (abs_ns % 1'000ULL == 0ULL)) {
            return std::format("{}{} us", sign, abs_ns / 1'000ULL);
        }
        const double us = static_cast<double>(abs_ns) / 1'000.0;
        if (step_ns >= 100ULL) {
            return std::format("{}{:.1f} us", sign, us);
        }
        return std::format("{}{:.3f} us", sign, us);
    }
    if (abs_ns < 1'000'000'000ULL) {
        if (step_ns >= 1'000'000ULL && (abs_ns % 1'000'000ULL == 0ULL)) {
            return std::format("{}{} ms", sign, abs_ns / 1'000'000ULL);
        }
        const double ms = static_cast<double>(abs_ns) / 1'000'000.0;
        if (step_ns >= 100'000ULL) {
            return std::format("{}{:.1f} ms", sign, ms);
        }
        if (step_ns >= 1'000ULL) {
            return std::format("{}{:.3f} ms", sign, ms);
        }
        return std::format("{}{:.6f} ms", sign, ms);
    }
    if (abs_ns < 60'000'000'000ULL) {
        const double sec = static_cast<double>(abs_ns) / 1'000'000'000.0;
        if (step_ns >= 1'000'000'000ULL && (abs_ns % 1'000'000'000ULL == 0ULL)) {
            return std::format("{}{} s", sign, abs_ns / 1'000'000'000ULL);
        }
        if (step_ns >= 10'000'000ULL) {
            return std::format("{}{:.2f} s", sign, sec);
        }
        if (step_ns >= 100'000ULL) {
            return std::format("{}{:.4f} s", sign, sec);
        }
        return std::format("{}{:.6f} s", sign, sec);
    }

    const std::uint64_t minutes = abs_ns / 60'000'000'000ULL;
    const std::uint64_t rem_ns = abs_ns % 60'000'000'000ULL;
    if (step_ns >= 60'000'000'000ULL && rem_ns == 0ULL) {
        return std::format("{}{}m", sign, minutes);
    }
    const double rem_sec = static_cast<double>(rem_ns) / 1'000'000'000.0;
    if (step_ns >= 1'000'000'000ULL) {
        return std::format("{}{}m {:02}s", sign, minutes, rem_ns / 1'000'000'000ULL);
    }
    return std::format("{}{}m {:.3f}s", sign, minutes, rem_sec);
}

TimelineRulerResult generate_timeline_ruler_ticks(const TimelineRulerConfig& config) {
    TimelineRulerResult out{};
    if (config.track_width_px <= 1.0f || config.view_end_ns <= config.view_start_ns) {
        return out;
    }

    const std::uint64_t view_span_ns = config.view_end_ns - config.view_start_ns;
    const double ns_per_px =
        static_cast<double>(view_span_ns) / static_cast<double>(config.track_width_px);
    const double desired_major_ns =
        std::max(1.0, ns_per_px * static_cast<double>(std::max(24.0f, config.target_major_spacing_px)));

    static constexpr std::array<std::uint64_t, 37> kNiceStepsNs = {
        1ULL,
        2ULL,
        5ULL,
        10ULL,
        20ULL,
        50ULL,
        100ULL,
        200ULL,
        500ULL,
        1'000ULL,
        2'000ULL,
        5'000ULL,
        10'000ULL,
        20'000ULL,
        50'000ULL,
        100'000ULL,
        200'000ULL,
        500'000ULL,
        1'000'000ULL,
        2'000'000ULL,
        5'000'000ULL,
        10'000'000ULL,
        20'000'000ULL,
        50'000'000ULL,
        100'000'000ULL,
        200'000'000ULL,
        500'000'000ULL,
        1'000'000'000ULL,
        2'000'000'000ULL,
        5'000'000'000ULL,
        10'000'000'000ULL,
        15'000'000'000ULL,
        30'000'000'000ULL,
        60'000'000'000ULL,
        120'000'000'000ULL,
        300'000'000'000ULL,
        600'000'000'000ULL,
    };

    std::uint64_t major_step = kNiceStepsNs.back();
    bool found_step = false;
    for (const std::uint64_t candidate : kNiceStepsNs) {
        if (static_cast<double>(candidate) >= desired_major_ns) {
            major_step = candidate;
            found_step = true;
            break;
        }
    }
    if (!found_step) {
        const auto minutes = static_cast<std::uint64_t>(
            std::ceil(desired_major_ns / 60'000'000'000.0));
        major_step = add_sat_u64(0ULL, std::max<std::uint64_t>(10ULL, minutes) * 60'000'000'000ULL);
    }

    std::uint64_t subdiv = 5ULL;
    if (major_step == 2ULL ||
        (major_step >= 20ULL && (major_step / 2ULL) % 10ULL == 0ULL && (major_step / 5ULL) % 10ULL != 0ULL)) {
        subdiv = 4ULL;
    }
    if (major_step == 1ULL) {
        subdiv = 1ULL;
    }
    const std::uint64_t minor_step = std::max<std::uint64_t>(1ULL, major_step / subdiv);
    out.major_step_ns = major_step;
    out.minor_step_ns = minor_step;

    // Align ticks to multiples of `minor_step` relative to `origin_ns`.
    const std::uint64_t Anchor = std::min(config.origin_ns, config.view_start_ns);
    const std::uint64_t offset_from_anchor = sub_sat_u64(config.view_start_ns, Anchor);
    const std::uint64_t first_idx = offset_from_anchor / minor_step;
    std::uint64_t tick_idx = first_idx;

    constexpr std::size_t kMaxTicks = 512u;
    out.ticks.reserve(64u);
    for (std::size_t guard = 0u; guard < kMaxTicks; ++guard, ++tick_idx) {
        std::size_t prod = 0u;
        if (!checked_mul_size(static_cast<std::size_t>(tick_idx),
                              static_cast<std::size_t>(minor_step),
                              prod)) {
            break;
        }
        const std::uint64_t tick_ns = add_sat_u64(Anchor, static_cast<std::uint64_t>(prod));
        if (tick_ns > config.view_end_ns) {
            break;
        }
        if (tick_ns < config.view_start_ns) {
            continue;
        }

        const auto x_px = static_cast<float>(project_time_to_x(
            tick_ns,
            config.view_start_ns,
            view_span_ns,
            config.track_x0_px,
            config.track_width_px));

        const std::uint64_t rel_anchor = sub_sat_u64(tick_ns, Anchor);
        const bool is_major = (rel_anchor % major_step) == 0ULL;

        std::int64_t signed_delta = 0;
        if (tick_ns >= config.origin_ns) {
            const std::uint64_t d = tick_ns - config.origin_ns;
            signed_delta = static_cast<std::int64_t>(
                std::min<std::uint64_t>(d, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())));
        } else {
            const std::uint64_t d = config.origin_ns - tick_ns;
            const auto clamped = std::min<std::uint64_t>(
                d, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
            signed_delta = -static_cast<std::int64_t>(clamped);
        }

        out.ticks.push_back(TimelineRulerTick{
            .timestamp_ns = tick_ns,
            .x_px = x_px,
            .is_major = is_major,
            .label = is_major ? format_timeline_offset_ns(signed_delta, major_step) : std::string{},
        });
    }

    return out;
}

// ============================================================================
// TimelineViewportIndex — Binary Mip Pyramid Construction & Query
// ============================================================================

void TimelineViewportIndex::MipPyramid::build_from_unsorted(std::vector<BaseItem> items) {
    levels.clear();
    if (items.empty()) {
        base_items.clear();
        return;
    }

    std::ranges::sort(items, [](const BaseItem& a, const BaseItem& b) noexcept {
        if (a.start_ns != b.start_ns) {
            return a.start_ns < b.start_ns;
        }
        return a.end_ns < b.end_ns;
    });
    base_items = std::move(items);

    std::vector<MipNode> level0;
    level0.reserve(base_items.size());
    for (std::size_t i = 0; i < base_items.size(); ++i) {
        const auto& item = base_items[i];
        level0.push_back(MipNode{
            .min_start_ns = item.start_ns,
            .max_end_ns = std::max(item.start_ns, item.end_ns),
            .first_base_index = static_cast<std::uint32_t>(i),
            .item_count = 1u,
            .representative_base_index = static_cast<std::uint32_t>(i),
            .dominant_kind = item.visual_kind,
            .max_cpu_ratio = item.cpu_ratio,
            .max_stack_depth_bytes = item.stack_depth_bytes,
            .has_uncertainty = item.is_uncertainty,
        });
    }
    levels.push_back(std::move(level0));

    while (levels.back().size() > 1u) {
        const auto& prev = levels.back();
        std::vector<MipNode> next;
        next.reserve((prev.size() + 1u) / 2u);
        for (std::size_t i = 0; i < prev.size(); i += 2u) {
            if (i + 1u >= prev.size()) {
                next.push_back(prev[i]);
                continue;
            }
            const auto& left = prev[i];
            const auto& right = prev[i + 1u];
            const bool right_wins = right.dominant_kind > left.dominant_kind;
            next.push_back(MipNode{
                .min_start_ns = std::min(left.min_start_ns, right.min_start_ns),
                .max_end_ns = std::max(left.max_end_ns, right.max_end_ns),
                .first_base_index = left.first_base_index,
                .item_count = left.item_count + right.item_count,
                .representative_base_index =
                    right_wins ? right.representative_base_index : left.representative_base_index,
                .dominant_kind = std::max(left.dominant_kind, right.dominant_kind),
                .max_cpu_ratio = std::max(left.max_cpu_ratio, right.max_cpu_ratio),
                .max_stack_depth_bytes = std::max(left.max_stack_depth_bytes, right.max_stack_depth_bytes),
                .has_uncertainty = left.has_uncertainty || right.has_uncertainty,
            });
        }
        levels.push_back(std::move(next));
    }
}

void TimelineViewportIndex::MetricPyramid::build_from_points(
    std::span<const ThreadMetricPoint> src) {
    levels.clear();
    points.assign(src.begin(), src.end());
    if (points.empty()) {
        return;
    }

    std::ranges::sort(points, [](const ThreadMetricPoint& a, const ThreadMetricPoint& b) noexcept {
        return a.timestamp_ns < b.timestamp_ns;
    });

    std::vector<MetricMipNode> level0;
    level0.reserve(points.size());
    for (const auto& pt : points) {
        level0.push_back(MetricMipNode{
            .min_ts_ns = pt.timestamp_ns,
            .max_ts_ns = pt.timestamp_ns,
            .max_cpu_ratio = pt.cpu_ratio,
            .max_kernel_share_ratio = pt.kernel_share_ratio,
            .max_stack_depth_bytes = pt.stack_depth_bytes,
            .any_stack_valid = pt.stack_depth_valid,
        });
    }
    levels.push_back(std::move(level0));

    while (levels.back().size() > 1u) {
        const auto& prev = levels.back();
        std::vector<MetricMipNode> next;
        next.reserve((prev.size() + 1u) / 2u);
        for (std::size_t i = 0; i < prev.size(); i += 2u) {
            if (i + 1u >= prev.size()) {
                next.push_back(prev[i]);
                continue;
            }
            const auto& l = prev[i];
            const auto& r = prev[i + 1u];
            next.push_back(MetricMipNode{
                .min_ts_ns = std::min(l.min_ts_ns, r.min_ts_ns),
                .max_ts_ns = std::max(l.max_ts_ns, r.max_ts_ns),
                .max_cpu_ratio = std::max(l.max_cpu_ratio, r.max_cpu_ratio),
                .max_kernel_share_ratio = std::max(l.max_kernel_share_ratio, r.max_kernel_share_ratio),
                .max_stack_depth_bytes = std::max(l.max_stack_depth_bytes, r.max_stack_depth_bytes),
                .any_stack_valid = l.any_stack_valid || r.any_stack_valid,
            });
        }
        levels.push_back(std::move(next));
    }
}

void TimelineViewportIndex::clear() noexcept {
    lanes_.clear();
    total_indexed_items_ = 0u;
    origin_ns_ = 0ULL;
    min_time_ns_ = 0ULL;
    max_time_ns_ = 0ULL;
    uses_virtual_axis_ = false;
}

void TimelineViewportIndex::build(
    const ExecutionTimeline& timeline,
    const LiveThreadMonitorSnapshot* monitor_snapshot,
    const TimelineBuildOptions& options) {
    clear();

    const std::uint64_t virtual_step_ns =
        std::max<std::uint64_t>(1ULL, options.virtual_sequence_step_ns);

    // Determine whether we have real monotonic timestamps or need virtual sequence fallback.
    std::uint64_t min_nonzero_ns = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_nonzero_ns = 0ULL;
    std::uint64_t min_seq = std::numeric_limits<std::uint64_t>::max();

    const auto& raw_events = timeline.events();
    for (const auto& ev : raw_events) {
        if (options.event_filter && !options.event_filter(ev)) {
            continue;
        }
        min_seq = std::min(min_seq, ev.sequence);
        if (ev.stamp.monotonic_ns > 0ULL) {
            min_nonzero_ns = std::min(min_nonzero_ns, ev.stamp.monotonic_ns);
            max_nonzero_ns = std::max(max_nonzero_ns, ev.stamp.monotonic_ns);
        }
        if (ev.observation_interval.has_value()) {
            if (ev.observation_interval->earliest.monotonic_ns > 0ULL) {
                min_nonzero_ns = std::min(min_nonzero_ns, ev.observation_interval->earliest.monotonic_ns);
                max_nonzero_ns = std::max(max_nonzero_ns, ev.observation_interval->earliest.monotonic_ns);
            }
            if (ev.observation_interval->latest.monotonic_ns > 0ULL) {
                min_nonzero_ns = std::min(min_nonzero_ns, ev.observation_interval->latest.monotonic_ns);
                max_nonzero_ns = std::max(max_nonzero_ns, ev.observation_interval->latest.monotonic_ns);
            }
        }
    }

    if (monitor_snapshot != nullptr) {
        for (const auto& mlane : monitor_snapshot->lanes) {
            for (const auto& sp : mlane.spans) {
                if (sp.start_ns > 0ULL) {
                    min_nonzero_ns = std::min(min_nonzero_ns, sp.start_ns);
                }
                if (sp.end_ns > 0ULL) {
                    max_nonzero_ns = std::max(max_nonzero_ns, sp.end_ns);
                }
            }
        }
    }

    const bool has_real_monotonic = (min_nonzero_ns != std::numeric_limits<std::uint64_t>::max());
    uses_virtual_axis_ = !has_real_monotonic;
    const std::uint64_t seq_anchor =
        (min_seq == std::numeric_limits<std::uint64_t>::max()) ? 1ULL : min_seq;

    struct PendingLaneData {
        IndexedLane meta{};
        std::vector<BaseItem> states{};
        std::vector<BaseItem> events{};
        std::vector<ThreadMetricPoint> metrics{};
    };

    std::vector<PendingLaneData> pending_lanes;

    // Index 0: Global / Process lane (unless filtered out).
    std::optional<std::size_t> global_lane_idx{};
    if (options.include_global_lane && !options.filter_thread.has_value()) {
        global_lane_idx = 0u;
        PendingLaneData g{};
        g.meta.is_global_lane = true;
        g.meta.label = "Process / Global";
        g.meta.active = true;
        pending_lanes.push_back(std::move(g));
    }

    const auto find_or_add_thread_lane =
        [&](const ThreadIdentity& id,
            std::string_view name,
            bool active,
            bool recycled) -> std::optional<std::size_t> {
        if (options.filter_thread.has_value() && !options.filter_thread->same_lane(id)) {
            return std::nullopt;
        }
        for (std::size_t i = 0; i < pending_lanes.size(); ++i) {
            if (!pending_lanes[i].meta.is_global_lane &&
                pending_lanes[i].meta.thread.has_value() &&
                pending_lanes[i].meta.thread->same_lane(id)) {
                if (id.creation_identity.has_value() &&
                    !pending_lanes[i].meta.thread->creation_identity.has_value()) {
                    pending_lanes[i].meta.thread->creation_identity = id.creation_identity;
                }
                pending_lanes[i].meta.tid_recycled =
                    pending_lanes[i].meta.tid_recycled || recycled;
                const bool show_epoch = (id.epoch > 1u) || pending_lanes[i].meta.tid_recycled;
                if (!name.empty() && pending_lanes[i].meta.label.find('(') == std::string::npos) {
                    pending_lanes[i].meta.label =
                        show_epoch
                            ? std::format("TID {}#e{} ({})", id.tid, id.epoch, name)
                            : std::format("TID {} ({})", id.tid, name);
                }
                return i;
            }
        }

        PendingLaneData lane{};
        lane.meta.is_global_lane = false;
        lane.meta.thread = id;
        lane.meta.active = active;
        lane.meta.tid_recycled = recycled;
        const bool show_epoch = (id.epoch > 1u) || recycled;
        if (!name.empty()) {
            lane.meta.label = show_epoch
                                  ? std::format("TID {}#e{} ({})", id.tid, id.epoch, name)
                                  : std::format("TID {} ({})", id.tid, name);
        } else {
            lane.meta.label = show_epoch
                                  ? std::format("TID {}#e{}", id.tid, id.epoch)
                                  : std::format("TID {}", id.tid);
        }
        const std::size_t idx = pending_lanes.size();
        pending_lanes.push_back(std::move(lane));
        return idx;
    };

    // Seed lanes from `ExecutionTimeline::thread_lanes()`.
    for (const auto& tlane : timeline.thread_lanes()) {
        (void)find_or_add_thread_lane(
            tlane.identity, tlane.name, tlane.active, tlane.tid_recycled);
    }

    // Seed lanes + continuous state spans + sparkline metrics from `LiveThreadMonitorSnapshot`.
    if (monitor_snapshot != nullptr) {
        for (const auto& mlane : monitor_snapshot->lanes) {
            const auto lane_idx = find_or_add_thread_lane(
                mlane.identity, mlane.name, mlane.active, mlane.tid_recycled);
            if (!lane_idx.has_value()) {
                continue;
            }
            auto& dst = pending_lanes[*lane_idx];
            dst.meta.active = mlane.active;
            dst.meta.is_faulting_thread = mlane.is_faulting_thread;
            dst.meta.latest_state = mlane.latest_state;
            dst.meta.latest_cpu_ratio = mlane.latest_cpu_ratio;
            dst.meta.latest_stack_depth_bytes = mlane.latest_stack_depth_bytes;
            dst.meta.high_water_stack_depth_bytes = mlane.high_water_stack_depth_bytes;
            dst.metrics = mlane.metrics;

            dst.states.reserve(dst.states.size() + mlane.spans.size());
            for (const auto& sp : mlane.spans) {
                const std::uint64_t s_ns = sp.start_ns;
                const std::uint64_t e_ns = std::max(sp.start_ns, sp.end_ns);
                std::string desc = std::format("Thread {}", to_string(sp.state));
                if (sp.syscall_number.has_value()) {
                    desc += std::format(" (syscall #{})", *sp.syscall_number);
                }
                if (!sp.wait_channel.empty()) {
                    desc += std::format(" [{}]", sp.wait_channel);
                }
                dst.states.push_back(BaseItem{
                    .start_ns = s_ns,
                    .end_ns = e_ns,
                    .visual_kind = visual_kind_for_thread_state(sp.state),
                    .is_thread_state_span = true,
                    .is_uncertainty = (sp.state == ThreadSpanState::SamplingGap),
                    .event_kind = std::nullopt,
                    .event_sequence = std::nullopt,
                    .thread_span = sp,
                    .cpu_ratio = sp.peak_cpu_ratio,
                    .stack_depth_bytes = sp.peak_stack_depth_bytes,
                    .virtual_address = sp.instruction_pointer,
                    .stack_pointer = sp.stack_pointer,
                    .provenance = monitor_snapshot->seeded_from_crash_dump
                                      ? ProvenanceTag::CrashDump
                                      : ProvenanceTag::ProcOrOsApi,
                    .summary = std::move(desc),
                });
            }
        }
    }

    // Ingest discrete & interval events from `ExecutionTimeline::events()`.
    std::uint64_t running_real_anchor_ns = has_real_monotonic ? min_nonzero_ns : 1'000ULL;
    for (const auto& ev : raw_events) {
        if (options.event_filter && !options.event_filter(ev)) {
            continue;
        }

        const bool has_obs_interval =
            ev.observation_interval.has_value() &&
            (ev.observation_interval->duration_ns() > 0ULL ||
             ev.observation_interval->latest.snapshot_revision >
                 ev.observation_interval->earliest.snapshot_revision);
        const bool uncertain =
            is_timeline_uncertainty_marker(ev.kind) ||
            (is_timeline_snapshot_delta(ev.kind) && has_obs_interval);

        std::uint64_t end_ns = 0ULL;
        std::uint64_t start_ns = 0ULL;
        if (ev.stamp.monotonic_ns > 0ULL) {
            end_ns = ev.stamp.monotonic_ns;
            if (ev.observation_interval.has_value() &&
                ev.observation_interval->latest.monotonic_ns > end_ns) {
                end_ns = ev.observation_interval->latest.monotonic_ns;
            }
            running_real_anchor_ns = std::max(running_real_anchor_ns, end_ns);
            if (ev.observation_interval.has_value() &&
                ev.observation_interval->earliest.monotonic_ns > 0ULL &&
                ev.observation_interval->earliest.monotonic_ns <= end_ns) {
                start_ns = ev.observation_interval->earliest.monotonic_ns;
            } else {
                start_ns = end_ns;
            }
        } else if (!has_real_monotonic) {
            const std::uint64_t rel_seq = sub_sat_u64(ev.sequence, seq_anchor);
            end_ns = add_sat_u64(virtual_step_ns, rel_seq * virtual_step_ns);
            start_ns = (uncertain && end_ns > virtual_step_ns)
                           ? (end_ns - virtual_step_ns)
                           : end_ns;
        } else {
            running_real_anchor_ns = add_sat_u64(running_real_anchor_ns, 100ULL);
            end_ns = running_real_anchor_ns;
            start_ns = end_ns;
        }

        std::optional<std::size_t> dst_lane_idx{};
        if (ev.thread.has_value()) {
            dst_lane_idx = find_or_add_thread_lane(*ev.thread, {}, true, false);
        } else {
            dst_lane_idx = global_lane_idx;
        }
        if (!dst_lane_idx.has_value()) {
            continue;
        }

        const TimelineVisualKind vkind = visual_kind_for_timeline_event(ev.kind);

        pending_lanes[*dst_lane_idx].events.push_back(BaseItem{
            .start_ns = start_ns,
            .end_ns = std::max(start_ns, end_ns),
            .visual_kind = vkind,
            .is_thread_state_span = false,
            .is_uncertainty = uncertain,
            .event_kind = ev.kind,
            .event_sequence = ev.sequence,
            .thread_span = {},
            .cpu_ratio = 0.0f,
            .stack_depth_bytes = 0ULL,
            .virtual_address = ev.virtual_address,
            .stack_pointer = std::nullopt,
            .provenance = ev.provenance,
            .summary = ev.summary,
        });
    }

    // Build mip pyramids & compute unified `[min_time_ns_, max_time_ns_]`.
    std::uint64_t global_min_ns = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t global_max_ns = 0ULL;
    std::size_t total_items = 0u;

    lanes_.reserve(pending_lanes.size());
    for (auto& pl : pending_lanes) {
        total_items += pl.states.size() + pl.events.size();
        pl.meta.state_pyramid.build_from_unsorted(std::move(pl.states));
        pl.meta.event_pyramid.build_from_unsorted(std::move(pl.events));
        pl.meta.metric_pyramid.build_from_points(pl.metrics);

        if (!pl.meta.state_pyramid.levels.empty()) {
            const auto& top = pl.meta.state_pyramid.levels.back().front();
            global_min_ns = std::min(global_min_ns, top.min_start_ns);
            global_max_ns = std::max(global_max_ns, top.max_end_ns);
        }
        if (!pl.meta.event_pyramid.levels.empty()) {
            const auto& top = pl.meta.event_pyramid.levels.back().front();
            global_min_ns = std::min(global_min_ns, top.min_start_ns);
            global_max_ns = std::max(global_max_ns, top.max_end_ns);
        }
        lanes_.push_back(std::move(pl.meta));
    }

    total_indexed_items_ = total_items;
    if (global_min_ns == std::numeric_limits<std::uint64_t>::max()) {
        origin_ns_ = 0ULL;
        min_time_ns_ = 0ULL;
        max_time_ns_ = 1'000'000ULL;
    } else {
        origin_ns_ = global_min_ns;
        min_time_ns_ = global_min_ns;
        max_time_ns_ = (global_max_ns > global_min_ns)
                           ? global_max_ns
                           : add_sat_u64(global_min_ns, virtual_step_ns);
    }
}

TimelineViewportFrame TimelineViewportIndex::query(
    const TimelineViewportQuery& params,
    std::stop_token stop_token) const {
    TimelineViewportFrame frame{};
    const float vp_w = std::max(1.0f, params.viewport_width_px);
    const float vp_h = std::max(1.0f, params.viewport_height_px);
    const float ruler_h = params.emit_ruler_and_separators
                              ? std::clamp(params.ruler_height_px, 0.0f, vp_h)
                              : 0.0f;

    std::uint64_t v_start = params.view_start_ns;
    std::uint64_t v_end = params.view_end_ns;
    if (v_end <= v_start) {
        if (max_time_ns_ > min_time_ns_) {
            v_start = min_time_ns_;
            v_end = max_time_ns_;
        } else {
            v_end = add_sat_u64(v_start, 1'000ULL);
        }
    }
    const std::uint64_t view_span_ns = std::max<std::uint64_t>(1ULL, v_end - v_start);

    frame.view_start_ns = v_start;
    frame.view_end_ns = v_end;
    frame.origin_ns = origin_ns_;
    frame.viewport_width_px = vp_w;
    frame.viewport_height_px = vp_h;
    frame.ruler_height_px = ruler_h;

    if (params.max_instances == 0u) {
        return frame;
    }

    frame.ruler = generate_timeline_ruler_ticks(TimelineRulerConfig{
        .view_start_ns = v_start,
        .view_end_ns = v_end,
        .origin_ns = origin_ns_,
        .track_x0_px = 0.0f,
        .track_width_px = vp_w,
        .target_major_spacing_px = 110.0f,
    });

    // Compute per-lane vertical geometry first so we know how many lanes are on-screen.
    const float base_lane_h = std::max(18.0f, params.lane_height_px);
    const float spark_h = params.show_sparklines ? std::max(8.0f, params.sparkline_height_px) : 0.0f;

    frame.lane_layouts.reserve(lanes_.size());
    float cursor_y = ruler_h - std::max(0.0f, params.lane_scroll_y_px);
    float total_content_h = 0.0f;
    std::size_t visible_lane_count = 0u;

    for (std::size_t i = 0; i < lanes_.size(); ++i) {
        const auto& lane = lanes_[i];
        const bool has_spark =
            params.show_sparklines && !lane.is_global_lane && !lane.metric_pyramid.points.empty();
        const float row_h = base_lane_h + (has_spark ? (spark_h + 2.0f) : 0.0f);
        const float y0 = cursor_y;
        const float y1 = cursor_y + row_h;
        cursor_y = y1;
        total_content_h += row_h;

        const float pad_y = 4.0f;
        const float span_y0 = y0 + pad_y;
        const float span_y1 = has_spark ? (y1 - spark_h - 4.0f) : (y1 - pad_y);
        const float sp_y0 = has_spark ? (span_y1 + 2.0f) : y1;
        const float sp_y1 = has_spark ? (y1 - 2.0f) : y1;

        if (y1 >= ruler_h && y0 <= vp_h) {
            ++visible_lane_count;
        }

        frame.lane_layouts.push_back(TimelineLaneLayout{
            .lane_index = i,
            .is_global_lane = lane.is_global_lane,
            .thread = lane.thread,
            .label = lane.label,
            .active = lane.active,
            .tid_recycled = lane.tid_recycled,
            .is_faulting_thread = lane.is_faulting_thread,
            .latest_state = lane.latest_state,
            .latest_cpu_ratio = lane.latest_cpu_ratio,
            .latest_stack_depth_bytes = lane.latest_stack_depth_bytes,
            .high_water_stack_depth_bytes = lane.high_water_stack_depth_bytes,
            .total_item_count =
                lane.state_pyramid.base_items.size() + lane.event_pyramid.base_items.size(),
            .y0_px = y0,
            .y1_px = y1,
            .span_track_y0_px = span_y0,
            .span_track_y1_px = std::max(span_y0 + 6.0f, span_y1),
            .sparkline_y0_px = sp_y0,
            .sparkline_y1_px = sp_y1,
            .hit_begin = 0u,
            .hit_count = 0u,
        });
    }
    frame.total_lanes_content_height_px = total_content_h;

    const std::size_t max_inst = params.max_instances;
    frame.instances.reserve(std::min<std::size_t>(max_inst, 4096u));

    const auto push_instance = [&](const TimelineGpuInstance& inst) noexcept -> bool {
        if (frame.instances.size() >= max_inst) {
            return false;
        }
        frame.instances.push_back(inst);
        return true;
    };

    // Reserve instance headroom so data spans always fit inside `max_instances`!
    const bool allow_chrome =
        params.emit_ruler_and_separators &&
        (max_inst >= (visible_lane_count * 4u + frame.ruler.ticks.size() + 16u));

    if (allow_chrome) {
        // Alternating lane background bands & horizontal separators.
        for (const auto& layout : frame.lane_layouts) {
            if (layout.y1_px < ruler_h || layout.y0_px > vp_h) {
                continue;
            }
            const float cy0 = std::max(layout.y0_px, ruler_h);
            const float cy1 = std::min(layout.y1_px, vp_h);
            if (cy1 <= cy0) {
                continue;
            }
            const bool is_selected_lane =
                params.selected_lane.has_value() &&
                layout.thread.has_value() &&
                (*params.selected_lane == *layout.thread);
            const std::uint32_t bg_col =
                is_selected_lane
                    ? pack_timeline_rgba8(34u, 46u, 68u, 150u)
                    : ((layout.lane_index % 2u == 0u)
                           ? pack_timeline_rgba8(20u, 23u, 31u, 180u)
                           : pack_timeline_rgba8(24u, 28u, 38u, 180u));
            (void)push_instance(TimelineGpuInstance{
                .x0_px = 0.0f,
                .y0_px = cy0,
                .x1_px = vp_w,
                .y1_px = cy1,
                .fill_rgba8 = bg_col,
                .border_rgba8 = bg_col,
                .shape_and_flags = TimelineInstanceFlags::pack(TimelineInstanceShape::FlatRectOrLine),
                .hit_id = kInvalidTimelineHitId,
            });
            if (cy1 < vp_h) {
                (void)push_instance(TimelineGpuInstance{
                    .x0_px = 0.0f,
                    .y0_px = cy1 - 1.0f,
                    .x1_px = vp_w,
                    .y1_px = cy1,
                    .fill_rgba8 = pack_timeline_rgba8(44u, 50u, 64u, 200u),
                    .border_rgba8 = pack_timeline_rgba8(44u, 50u, 64u, 200u),
                    .shape_and_flags = TimelineInstanceFlags::pack(TimelineInstanceShape::FlatRectOrLine),
                    .hit_id = kInvalidTimelineHitId,
                });
            }
        }

        // Vertical grid lines for major ruler ticks across lane area.
        for (const auto& tick : frame.ruler.ticks) {
            if (!tick.is_major) {
                continue;
            }
            (void)push_instance(TimelineGpuInstance{
                .x0_px = tick.x_px,
                .y0_px = ruler_h,
                .x1_px = tick.x_px + 1.0f,
                .y1_px = vp_h,
                .fill_rgba8 = pack_timeline_rgba8(56u, 64u, 82u, 72u),
                .border_rgba8 = pack_timeline_rgba8(56u, 64u, 82u, 72u),
                .shape_and_flags = TimelineInstanceFlags::pack(TimelineInstanceShape::FlatRectOrLine),
                .hit_id = kInvalidTimelineHitId,
            });
        }
    }

    // Compute adaptive `effective_merge_px` so total emitted span instances across
    // all visible lanes smoothly honor `max_instances`.
    const std::size_t remaining_budget =
        max_inst > frame.instances.size() ? (max_inst - frame.instances.size()) : 0u;
    const std::size_t sparkline_reserve =
        (params.show_sparklines && remaining_budget > 128u) ? (remaining_budget / 4u) : 0u;
    const std::size_t span_budget =
        std::max<std::size_t>(1u, remaining_budget - sparkline_reserve);
    const std::size_t lanes_denom = std::max<std::size_t>(1u, visible_lane_count * 2u);
    const std::size_t budget_per_stream = std::max<std::size_t>(1u, span_budget / lanes_denom);
    const float budget_merge_px = vp_w / static_cast<float>(budget_per_stream);
    const float effective_merge_px =
        std::max({0.5f, params.min_merge_px, budget_merge_px});

    struct CandidateNode {
        const MipPyramid* pyramid{nullptr};
        MipNode node{};
        float x0_px{0.0f};
        float x1_px{0.0f};
        bool from_state_pyramid{false};
    };

    struct TraversalFrame {
        std::size_t level{0};
        std::size_t index{0};
    };

    const auto collect_visible_nodes =
        [&](const MipPyramid& pyr,
            bool is_state_pyr,
            std::vector<CandidateNode>& out_nodes) {
        if (pyr.levels.empty()) {
            return;
        }
        std::array<TraversalFrame, 64> stack{};
        std::size_t sp = 0u;
        const std::size_t top_lvl = pyr.levels.size() - 1u;
        for (std::size_t idx = pyr.levels[top_lvl].size(); idx > 0u; --idx) {
            if (sp < stack.size()) {
                stack[sp++] = TraversalFrame{.level = top_lvl, .index = idx - 1u};
            }
        }

        while (sp > 0u) {
            const TraversalFrame cur = stack[--sp];
            const auto& node = pyr.levels[cur.level][cur.index];
            if (node.max_end_ns < v_start || node.min_start_ns > v_end) {
                ++frame.culled_subtree_nodes;
                continue;
            }

            const std::uint64_t clamped_s = std::max(node.min_start_ns, v_start);
            const std::uint64_t clamped_e = std::min(node.max_end_ns, v_end);
            const auto x0 = static_cast<float>(
                project_time_to_x(clamped_s, v_start, view_span_ns, 0.0f, vp_w));
            const auto x1 = static_cast<float>(
                project_time_to_x(clamped_e, v_start, view_span_ns, 0.0f, vp_w));
            const float px_w = std::max(0.0f, x1 - x0);

            if (cur.level == 0u || px_w <= effective_merge_px) {
                out_nodes.push_back(CandidateNode{
                    .pyramid = &pyr,
                    .node = node,
                    .x0_px = x0,
                    .x1_px = x1,
                    .from_state_pyramid = is_state_pyr,
                });
                continue;
            }

            const std::size_t child_lvl = cur.level - 1u;
            const std::size_t left_idx = cur.index * 2u;
            const std::size_t right_idx = left_idx + 1u;
            if (right_idx < pyr.levels[child_lvl].size() && sp < stack.size()) {
                stack[sp++] = TraversalFrame{.level = child_lvl, .index = right_idx};
            }
            if (left_idx < pyr.levels[child_lvl].size() && sp < stack.size()) {
                stack[sp++] = TraversalFrame{.level = child_lvl, .index = left_idx};
            }
        }
    };

    std::vector<CandidateNode> candidates;
    std::vector<CandidateNode> subpixel_pool;

    // Traverse each visible lane.
    for (std::size_t lane_idx = 0; lane_idx < lanes_.size(); ++lane_idx) {
        if (stop_token.stop_requested() || frame.instances.size() >= max_inst) {
            break;
        }
        auto& layout = frame.lane_layouts[lane_idx];
        if (layout.y1_px < ruler_h || layout.y0_px > vp_h) {
            continue;
        }

        const auto& lane = lanes_[lane_idx];
        layout.hit_begin = static_cast<std::uint32_t>(frame.hit_records.size());

        candidates.clear();
        subpixel_pool.clear();
        collect_visible_nodes(lane.state_pyramid, true, candidates);
        collect_visible_nodes(lane.event_pyramid, false, candidates);

        const float track_y0 = layout.span_track_y0_px;
        const float track_y1 = layout.span_track_y1_px;
        const float track_mid_y = 0.5f * (track_y0 + track_y1);
        const float marker_half_h = std::min(7.5f, 0.46f * (track_y1 - track_y0));

        const auto emit_single_base_item = [&](const BaseItem& item, float raw_x0, float raw_x1) {
            if (frame.instances.size() >= max_inst) {
                return;
            }
            const bool is_instant = (!item.is_thread_state_span) && (item.end_ns <= item.start_ns);
            float x0 = raw_x0;
            float x1 = raw_x1;
            float y0 = track_y0;
            float y1 = track_y1;
            TimelineInstanceShape shape = TimelineInstanceShape::RoundedSpan;

            if (is_instant) {
                shape = item.is_uncertainty ? TimelineInstanceShape::HatchedUncertaintyBand
                                            : TimelineInstanceShape::InstantDiamond;
                const float cx = 0.5f * (raw_x0 + raw_x1);
                x0 = cx - marker_half_h;
                x1 = cx + marker_half_h;
                y0 = track_mid_y - marker_half_h;
                y1 = track_mid_y + marker_half_h;
            } else {
                if (item.is_uncertainty) {
                    shape = TimelineInstanceShape::HatchedUncertaintyBand;
                }
                if ((x1 - x0) < 2.5f) {
                    const float cx = 0.5f * (x0 + x1);
                    x0 = cx - 1.25f;
                    x1 = cx + 1.25f;
                }
                if (!item.is_thread_state_span) {
                    y0 = track_y0 + 1.5f;
                    y1 = std::max(y0 + 4.0f, track_y1 - 1.5f);
                }
            }

            const bool is_selected =
                params.selected_event_sequence.has_value() &&
                item.event_sequence.has_value() &&
                (*params.selected_event_sequence == *item.event_sequence);
            std::uint32_t flags = is_selected ? TimelineInstanceFlags::kSelected : 0u;
            if (layout.is_global_lane && item.is_uncertainty) {
                flags |= TimelineInstanceFlags::kGlobalBand;
            }

            const std::uint8_t fill_alpha = item.is_thread_state_span ? 185u : 235u;
            const auto hit_id = static_cast<std::uint32_t>(frame.hit_records.size());
            if (!push_instance(TimelineGpuInstance{
                    .x0_px = x0,
                    .y0_px = y0,
                    .x1_px = x1,
                    .y1_px = y1,
                    .fill_rgba8 = timeline_fill_color_rgba8(item.visual_kind, fill_alpha),
                    .border_rgba8 = timeline_border_color_rgba8(item.visual_kind, 255u),
                    .shape_and_flags = TimelineInstanceFlags::pack(shape, flags),
                    .hit_id = hit_id,
                })) {
                return;
            }

            frame.hit_records.push_back(TimelineHitRecord{
                .hit_id = hit_id,
                .kind = item.is_thread_state_span ? TimelineHitKind::ThreadStateSpan
                                                  : TimelineHitKind::TimelineEvent,
                .lane_index = lane_idx,
                .is_global_lane = layout.is_global_lane,
                .is_foreground_item = !item.is_thread_state_span,
                .thread = layout.thread,
                .x0_px = x0,
                .y0_px = y0,
                .x1_px = x1,
                .y1_px = y1,
                .start_ns = item.start_ns,
                .end_ns = item.end_ns,
                .visual_kind = item.visual_kind,
                .event_kind = item.event_kind,
                .event_sequence = item.event_sequence,
                .thread_span = item.is_thread_state_span
                                   ? std::optional<ThreadStateSpan>(item.thread_span)
                                   : std::nullopt,
                .cluster = {},
                .virtual_address = item.virtual_address,
                .stack_pointer = item.stack_pointer,
                .provenance = item.provenance,
                .summary = item.summary,
            });
        };

        // Pass 1: emit wide individual spans directly (background thread states first,
        // then wide discrete intervals); funnel narrow/multi-item nodes into `subpixel_pool`.
        for (const auto& cand : candidates) {
            const float px_w = cand.x1_px - cand.x0_px;
            if (cand.from_state_pyramid && cand.node.item_count == 1u &&
                px_w >= effective_merge_px) {
                const auto& item = cand.pyramid->base_items[cand.node.representative_base_index];
                emit_single_base_item(item, cand.x0_px, cand.x1_px);
            } else if (!cand.from_state_pyramid && cand.node.item_count == 1u &&
                       px_w >= effective_merge_px) {
                // Defer wide discrete events slightly so they draw on top of background state bars.
                subpixel_pool.push_back(cand);
            } else {
                subpixel_pool.push_back(cand);
            }
        }

        // Sort `subpixel_pool` by screen `x0_px` so adjacent sub-pixel spans & events coalesce cleanly.
        std::ranges::sort(subpixel_pool, [](const CandidateNode& a, const CandidateNode& b) noexcept {
            if (a.x0_px != b.x0_px) {
                return a.x0_px < b.x0_px;
            }
            return a.x1_px < b.x1_px;
        });

        std::size_t idx = 0u;
        while (idx < subpixel_pool.size() && frame.instances.size() < max_inst) {
            const auto& first = subpixel_pool[idx];
            const float first_w = first.x1_px - first.x0_px;
            if (first.node.item_count == 1u && first_w >= effective_merge_px) {
                const auto& item = first.pyramid->base_items[first.node.representative_base_index];
                emit_single_base_item(item, first.x0_px, first.x1_px);
                ++idx;
                continue;
            }

            // Merge adjacent sub-pixel candidates within `effective_merge_px` of `anchor_x0`.
            const float anchor_x0 = first.x0_px;
            float cluster_x0 = first.x0_px;
            float cluster_x1 = first.x1_px;
            std::uint64_t min_s_ns = first.node.min_start_ns;
            std::uint64_t max_e_ns = first.node.max_end_ns;
            std::uint32_t merged_count = first.node.item_count;
            TimelineVisualKind dom_kind = first.node.dominant_kind;
            float max_cpu = first.node.max_cpu_ratio;
            std::uint64_t max_stack = first.node.max_stack_depth_bytes;
            bool any_uncertain = first.node.has_uncertainty;
            const BaseItem* rep_item =
                &first.pyramid->base_items[first.node.representative_base_index];
            bool cluster_selected =
                params.selected_event_sequence.has_value() &&
                rep_item->event_sequence.has_value() &&
                (*params.selected_event_sequence == *rep_item->event_sequence);

            std::size_t next_idx = idx + 1u;
            while (next_idx < subpixel_pool.size()) {
                const auto& nxt = subpixel_pool[next_idx];
                const float nxt_w = nxt.x1_px - nxt.x0_px;
                if (nxt.node.item_count == 1u && nxt_w >= effective_merge_px) {
                    break;
                }
                if ((nxt.x0_px - anchor_x0) > effective_merge_px &&
                    (nxt.x0_px - cluster_x1) > (0.5f * effective_merge_px)) {
                    break;
                }
                if ((nxt.x1_px - anchor_x0) > (2.25f * effective_merge_px)) {
                    break;
                }

                cluster_x0 = std::min(cluster_x0, nxt.x0_px);
                cluster_x1 = std::max(cluster_x1, nxt.x1_px);
                min_s_ns = std::min(min_s_ns, nxt.node.min_start_ns);
                max_e_ns = std::max(max_e_ns, nxt.node.max_end_ns);
                merged_count += nxt.node.item_count;
                max_cpu = std::max(max_cpu, nxt.node.max_cpu_ratio);
                max_stack = std::max(max_stack, nxt.node.max_stack_depth_bytes);
                any_uncertain = any_uncertain || nxt.node.has_uncertainty;

                const BaseItem* nxt_rep =
                    &nxt.pyramid->base_items[nxt.node.representative_base_index];
                if (nxt.node.dominant_kind > dom_kind ||
                    (nxt.node.dominant_kind == dom_kind && !nxt.from_state_pyramid &&
                     rep_item->is_thread_state_span)) {
                    dom_kind = nxt.node.dominant_kind;
                    rep_item = nxt_rep;
                }
                if (params.selected_event_sequence.has_value() &&
                    nxt_rep->event_sequence.has_value() &&
                    (*params.selected_event_sequence == *nxt_rep->event_sequence)) {
                    cluster_selected = true;
                }
                ++next_idx;
            }

            if (merged_count <= 1u) {
                emit_single_base_item(*rep_item, cluster_x0, cluster_x1);
            } else {
                ++frame.coalesced_cluster_count;
                float draw_x0 = cluster_x0;
                float draw_x1 = cluster_x1;
                if ((draw_x1 - draw_x0) < 3.0f) {
                    const float cx = 0.5f * (draw_x0 + draw_x1);
                    draw_x0 = cx - 1.5f;
                    draw_x1 = cx + 1.5f;
                }

                const bool show_hatched =
                    dom_kind == TimelineVisualKind::DroppedEvents ||
                    dom_kind == TimelineVisualKind::SamplingGap;
                const TimelineInstanceShape shape =
                    show_hatched ? TimelineInstanceShape::HatchedUncertaintyBand
                                 : TimelineInstanceShape::RoundedSpan;
                std::uint32_t flags = TimelineInstanceFlags::kCoalescedCluster;
                if (cluster_selected) {
                    flags |= TimelineInstanceFlags::kSelected;
                }

                const auto hit_id = static_cast<std::uint32_t>(frame.hit_records.size());
                if (push_instance(TimelineGpuInstance{
                        .x0_px = draw_x0,
                        .y0_px = track_y0,
                        .x1_px = draw_x1,
                        .y1_px = track_y1,
                        .fill_rgba8 = timeline_fill_color_rgba8(dom_kind, 232u),
                        .border_rgba8 = timeline_border_color_rgba8(dom_kind, 255u),
                        .shape_and_flags = TimelineInstanceFlags::pack(shape, flags),
                        .hit_id = hit_id,
                    })) {
                    CoalescedClusterInfo cinfo{
                        .min_start_ns = min_s_ns,
                        .max_end_ns = max_e_ns,
                        .merged_count = merged_count,
                        .dominant_kind = dom_kind,
                        .max_cpu_ratio = max_cpu,
                        .max_stack_depth_bytes = max_stack,
                        .representative_sequence = rep_item->event_sequence,
                        .representative_va = rep_item->virtual_address,
                    };
                    frame.hit_records.push_back(TimelineHitRecord{
                        .hit_id = hit_id,
                        .kind = TimelineHitKind::CoalescedCluster,
                        .lane_index = lane_idx,
                        .is_global_lane = layout.is_global_lane,
                        .is_foreground_item = true,
                        .thread = layout.thread,
                        .x0_px = draw_x0,
                        .y0_px = track_y0,
                        .x1_px = draw_x1,
                        .y1_px = track_y1,
                        .start_ns = min_s_ns,
                        .end_ns = max_e_ns,
                        .visual_kind = dom_kind,
                        .event_kind = rep_item->event_kind,
                        .event_sequence = rep_item->event_sequence,
                        .thread_span = std::nullopt,
                        .cluster = cinfo,
                        .virtual_address = rep_item->virtual_address,
                        .stack_pointer = rep_item->stack_pointer,
                        .provenance = rep_item->provenance,
                        .summary = std::format(
                            "Coalesced {} items (dominant: {})",
                            merged_count,
                            to_string(dom_kind)),
                    });
                }
            }
            idx = next_idx;
        }

        const std::size_t lane_hit_end = frame.hit_records.size();
        layout.hit_count = static_cast<std::uint32_t>(lane_hit_end - layout.hit_begin);
        // Sort lane hits by center X so `hit_test` can locate candidates quickly.
        auto lane_hits_span = std::span<TimelineHitRecord>(frame.hit_records)
                                  .subspan(layout.hit_begin, layout.hit_count);
        std::ranges::sort(lane_hits_span, [](const TimelineHitRecord& a, const TimelineHitRecord& b) noexcept {
            const float ca = 0.5f * (a.x0_px + a.x1_px);
            const float cb = 0.5f * (b.x0_px + b.x1_px);
            return ca < cb;
        });

        // Emit CPU% & Stack-Depth sparkline columns if enabled and budget remains.
        if (params.show_sparklines &&
            !lane.is_global_lane &&
            !lane.metric_pyramid.points.empty() &&
            layout.sparkline_y1_px > layout.sparkline_y0_px &&
            frame.instances.size() < max_inst) {
            constexpr float kColWidthPx = 4.0f;
            const auto num_cols = static_cast<std::size_t>(
                std::clamp(std::ceil(vp_w / kColWidthPx), 1.0f, 512.0f));
            const auto& pts = lane.metric_pyramid.points;
            const auto first_it = std::ranges::lower_bound(
                pts, v_start, {}, &ThreadMetricPoint::timestamp_ns);
            const std::uint64_t stack_ceil =
                std::max<std::uint64_t>(4096ULL, lane.high_water_stack_depth_bytes);
            const float sp_y0 = layout.sparkline_y0_px;
            const float sp_y1 = layout.sparkline_y1_px;
            const float sp_h = sp_y1 - sp_y0;

            auto it = first_it;
            while (it != pts.end() && it->timestamp_ns <= v_end &&
                   frame.instances.size() < max_inst) {
                const auto x_start = static_cast<float>(
                    project_time_to_x(it->timestamp_ns, v_start, view_span_ns, 0.0f, vp_w));
                const auto col_idx = static_cast<std::size_t>(
                    std::clamp(x_start / kColWidthPx, 0.0f, static_cast<float>(num_cols - 1u)));
                const float col_x0 = static_cast<float>(col_idx) * kColWidthPx;
                const float col_x1 = std::min(vp_w, col_x0 + kColWidthPx - 0.5f);

                float peak_cpu = it->cpu_ratio;
                float peak_kern = it->kernel_share_ratio;
                std::uint64_t peak_stack = it->stack_depth_bytes;
                bool has_stack = it->stack_depth_valid;
                ++it;

                while (it != pts.end() && it->timestamp_ns <= v_end) {
                    const auto nx = static_cast<float>(
                        project_time_to_x(it->timestamp_ns, v_start, view_span_ns, 0.0f, vp_w));
                    if (nx >= (col_x0 + kColWidthPx)) {
                        break;
                    }
                    peak_cpu = std::max(peak_cpu, it->cpu_ratio);
                    peak_kern = std::max(peak_kern, it->kernel_share_ratio);
                    if (it->stack_depth_valid) {
                        peak_stack = std::max(peak_stack, it->stack_depth_bytes);
                        has_stack = true;
                    }
                    ++it;
                }

                if (peak_cpu > 0.005f) {
                    const float bar_h = std::clamp(peak_cpu, 0.08f, 1.0f) * sp_h;
                    const std::uint32_t c_col = sparkline_cpu_color_rgba8(peak_cpu, peak_kern);
                    (void)push_instance(TimelineGpuInstance{
                        .x0_px = col_x0,
                        .y0_px = sp_y1 - bar_h,
                        .x1_px = col_x0 + 0.55f * (col_x1 - col_x0),
                        .y1_px = sp_y1,
                        .fill_rgba8 = c_col,
                        .border_rgba8 = c_col,
                        .shape_and_flags = TimelineInstanceFlags::pack(
                            TimelineInstanceShape::SparklineColumn),
                        .hit_id = kInvalidTimelineHitId,
                    });
                }
                if (has_stack && peak_stack > 0ULL && frame.instances.size() < max_inst) {
                    const float s_ratio = static_cast<float>(std::clamp(
                        static_cast<double>(peak_stack) / static_cast<double>(stack_ceil),
                        0.08,
                        1.0));
                    const float bar_h = s_ratio * sp_h;
                    const std::uint32_t s_col = pack_timeline_rgba8(78u, 196u, 238u, 200u);
                    (void)push_instance(TimelineGpuInstance{
                        .x0_px = col_x0 + 0.55f * (col_x1 - col_x0),
                        .y0_px = sp_y1 - bar_h,
                        .x1_px = col_x1,
                        .y1_px = sp_y1,
                        .fill_rgba8 = s_col,
                        .border_rgba8 = s_col,
                        .shape_and_flags = TimelineInstanceFlags::pack(
                            TimelineInstanceShape::SparklineColumn),
                        .hit_id = kInvalidTimelineHitId,
                    });
                }
            }
        }
    }

    // Emit top time-ruler header bar & tick marks last so scrolled lanes never paint over the ruler.
    if (allow_chrome && ruler_h > 0.0f && frame.instances.size() < max_inst) {
        (void)push_instance(TimelineGpuInstance{
            .x0_px = 0.0f,
            .y0_px = 0.0f,
            .x1_px = vp_w,
            .y1_px = ruler_h,
            .fill_rgba8 = pack_timeline_rgba8(24u, 28u, 38u, 248u),
            .border_rgba8 = pack_timeline_rgba8(68u, 78u, 98u, 255u),
            .shape_and_flags = TimelineInstanceFlags::pack(TimelineInstanceShape::FlatRectOrLine),
            .hit_id = kInvalidTimelineHitId,
        });
        for (const auto& tick : frame.ruler.ticks) {
            if (frame.instances.size() >= max_inst) {
                break;
            }
            const float tick_top = tick.is_major ? (ruler_h * 0.42f) : (ruler_h * 0.72f);
            const std::uint32_t t_col = tick.is_major
                                            ? pack_timeline_rgba8(186u, 198u, 222u, 235u)
                                            : pack_timeline_rgba8(112u, 124u, 148u, 180u);
            (void)push_instance(TimelineGpuInstance{
                .x0_px = tick.x_px,
                .y0_px = tick_top,
                .x1_px = tick.x_px + 1.0f,
                .y1_px = ruler_h,
                .fill_rgba8 = t_col,
                .border_rgba8 = t_col,
                .shape_and_flags = TimelineInstanceFlags::pack(TimelineInstanceShape::FlatRectOrLine),
                .hit_id = kInvalidTimelineHitId,
            });
        }
    }

    return frame;
}

std::optional<std::size_t> TimelineViewportIndex::lane_at_y(
    const TimelineViewportFrame& frame,
    float y_px) noexcept {
    if (y_px < frame.ruler_height_px || frame.lane_layouts.empty()) {
        return std::nullopt;
    }
    const auto it = std::ranges::lower_bound(
        frame.lane_layouts,
        y_px,
        {},
        &TimelineLaneLayout::y1_px);
    if (it == frame.lane_layouts.end()) {
        return std::nullopt;
    }
    if (y_px >= it->y0_px && y_px <= it->y1_px) {
        return it->lane_index;
    }
    return std::nullopt;
}

std::optional<TimelineHitRecord> TimelineViewportIndex::hit_test(
    const TimelineViewportFrame& frame,
    const TimelineHitQuery& cursor) noexcept {
    const auto lane_idx = lane_at_y(frame, cursor.y_px);
    if (!lane_idx.has_value() || *lane_idx >= frame.lane_layouts.size()) {
        return std::nullopt;
    }
    const auto& layout = frame.lane_layouts[*lane_idx];
    if (layout.hit_count == 0u ||
        (static_cast<std::size_t>(layout.hit_begin) + layout.hit_count) > frame.hit_records.size()) {
        return std::nullopt;
    }

    const float slop = std::max(0.0f, cursor.slop_px);
    const auto hits = std::span<const TimelineHitRecord>(frame.hit_records)
                          .subspan(layout.hit_begin, layout.hit_count);

    const TimelineHitRecord* best_fg = nullptr;
    float best_fg_dist = std::numeric_limits<float>::infinity();
    const TimelineHitRecord* best_bg = nullptr;
    float best_bg_dist = std::numeric_limits<float>::infinity();

    for (const auto& h : hits) {
        if (cursor.x_px < (h.x0_px - slop) || cursor.x_px > (h.x1_px + slop)) {
            continue;
        }
        if (cursor.y_px < (h.y0_px - slop) || cursor.y_px > (h.y1_px + slop)) {
            continue;
        }
        const float cx = 0.5f * (h.x0_px + h.x1_px);
        const float dist = std::abs(cursor.x_px - cx);
        if (h.is_foreground_item) {
            if (best_fg == nullptr ||
                h.visual_kind > best_fg->visual_kind ||
                (h.visual_kind == best_fg->visual_kind && dist < best_fg_dist)) {
                best_fg = &h;
                best_fg_dist = dist;
            }
        } else {
            if (best_bg == nullptr || dist < best_bg_dist) {
                best_bg = &h;
                best_bg_dist = dist;
            }
        }
    }

    if (best_fg != nullptr) {
        return *best_fg;
    }
    if (best_bg != nullptr) {
        return *best_bg;
    }
    return std::nullopt;
}

// ============================================================================
// Deterministic CPU Reference Rasterizer (RGBA8)
// ============================================================================

void rasterize_timeline_viewport_rgba8_into(
    std::span<const TimelineGpuInstance> instances,
    const TimelineRasterConfig& config,
    std::vector<std::uint8_t>& out_rgba8,
    std::stop_token stop_token) {
    std::size_t pixel_count = 0u;
    std::size_t byte_count = 0u;
    if (config.width == 0u || config.height == 0u ||
        !checked_mul_size(config.width, config.height, pixel_count) ||
        !checked_mul_size(pixel_count, 4u, byte_count)) {
        out_rgba8.clear();
        return;
    }

    out_rgba8.resize(byte_count);
    const std::uint8_t cr = static_cast<std::uint8_t>(config.clear_rgba8 & 0xFFu);
    const std::uint8_t cg = static_cast<std::uint8_t>((config.clear_rgba8 >> 8u) & 0xFFu);
    const std::uint8_t cb = static_cast<std::uint8_t>((config.clear_rgba8 >> 16u) & 0xFFu);
    const std::uint8_t ca = static_cast<std::uint8_t>((config.clear_rgba8 >> 24u) & 0xFFu);
    for (std::size_t i = 0; i < byte_count; i += 4u) {
        out_rgba8[i + 0u] = cr;
        out_rgba8[i + 1u] = cg;
        out_rgba8[i + 2u] = cb;
        out_rgba8[i + 3u] = ca;
    }

    const float hatch_period = std::max(4.0f, config.hatch_period_px);
    const float border_w = std::max(0.5f, config.border_width_px);

    for (const auto& inst : instances) {
        if (stop_token.stop_requested()) {
            return;
        }
        const float min_x = std::min(inst.x0_px, inst.x1_px);
        const float max_x = std::max(inst.x0_px, inst.x1_px);
        const float min_y = std::min(inst.y0_px, inst.y1_px);
        const float max_y = std::max(inst.y0_px, inst.y1_px);
        if (max_x <= 0.0f || max_y <= 0.0f ||
            min_x >= static_cast<float>(config.width) ||
            min_y >= static_cast<float>(config.height)) {
            continue;
        }

        const int ix0 = std::max(0, static_cast<int>(std::floor(min_x - 1.5f)));
        const int iy0 = std::max(0, static_cast<int>(std::floor(min_y - 1.5f)));
        const int ix1 = std::min(
            static_cast<int>(config.width) - 1,
            static_cast<int>(std::ceil(max_x + 1.5f)));
        const int iy1 = std::min(
            static_cast<int>(config.height) - 1,
            static_cast<int>(std::ceil(max_y + 1.5f)));
        if (ix1 < ix0 || iy1 < iy0) {
            continue;
        }

        const TimelineInstanceShape shape =
            TimelineInstanceFlags::unpack_shape(inst.shape_and_flags);
        const bool is_hovered =
            ((inst.shape_and_flags & TimelineInstanceFlags::kHovered) != 0u) ||
            (inst.hit_id != kInvalidTimelineHitId && inst.hit_id == config.hovered_hit_id);
        const bool is_selected =
            ((inst.shape_and_flags & TimelineInstanceFlags::kSelected) != 0u) ||
            (inst.hit_id != kInvalidTimelineHitId && inst.hit_id == config.selected_hit_id);
        const bool is_cluster =
            (inst.shape_and_flags & TimelineInstanceFlags::kCoalescedCluster) != 0u;

        UnpackedRgba fill = unpack_rgba8(inst.fill_rgba8);
        UnpackedRgba border = unpack_rgba8(inst.border_rgba8);
        if (is_hovered) {
            fill.r = std::min(1.0f, fill.r + 0.14f);
            fill.g = std::min(1.0f, fill.g + 0.14f);
            fill.b = std::min(1.0f, fill.b + 0.14f);
        }
        if (is_selected) {
            fill.r = std::min(1.0f, fill.r + 0.08f);
            fill.g = std::min(1.0f, fill.g + 0.08f);
            fill.b = std::min(1.0f, fill.b + 0.08f);
            border = UnpackedRgba{.r = 1.0f, .g = 0.96f, .b = 0.72f, .a = 1.0f};
        }

        const float cx = 0.5f * (min_x + max_x);
        const float cy = 0.5f * (min_y + max_y);
        const float hx = std::max(0.25f, 0.5f * (max_x - min_x));
        const float hy = std::max(0.25f, 0.5f * (max_y - min_y));

        for (int py = iy0; py <= iy1; ++py) {
            const float sample_y = static_cast<float>(py) + 0.5f;
            for (int px = ix0; px <= ix1; ++px) {
                const float sample_x = static_cast<float>(px) + 0.5f;
                const float dx = sample_x - cx;
                const float dy = sample_y - cy;

                float dist = 0.0f;
                switch (shape) {
                    case TimelineInstanceShape::RoundedSpan:
                        dist = sd_rounded_box(dx, dy, hx, hy, config.corner_radius_px);
                        break;
                    case TimelineInstanceShape::InstantDiamond:
                        dist = sd_diamond(dx, dy, hx, hy);
                        break;
                    case TimelineInstanceShape::HatchedUncertaintyBand:
                        dist = sd_rounded_box(dx, dy, hx, hy, 2.0f);
                        break;
                    case TimelineInstanceShape::SparklineColumn:
                    case TimelineInstanceShape::FlatRectOrLine:
                        dist = std::max(std::abs(dx) - hx, std::abs(dy) - hy);
                        break;
                }

                const float coverage = std::clamp(0.5f - dist, 0.0f, 1.0f);
                if (coverage <= 0.0f) {
                    continue;
                }

                UnpackedRgba src = fill;
                if (shape == TimelineInstanceShape::HatchedUncertaintyBand) {
                    const float phase =
                        std::fmod(std::abs(sample_x + sample_y), hatch_period) / hatch_period;
                    if (phase < 0.45f) {
                        src.a *= 0.38f;
                        src.r *= 0.65f;
                        src.g *= 0.65f;
                        src.b *= 0.65f;
                    }
                }

                if (is_cluster && (sample_y - min_y) <= 2.2f) {
                    src = border;
                }

                if (shape != TimelineInstanceShape::FlatRectOrLine &&
                    shape != TimelineInstanceShape::SparklineColumn) {
                    const float eff_border = is_selected ? (border_w + 0.9f) : border_w;
                    const float border_t = std::clamp(dist + eff_border + 0.5f, 0.0f, 1.0f);
                    src.r = src.r * (1.0f - border_t) + border.r * border_t;
                    src.g = src.g * (1.0f - border_t) + border.g * border_t;
                    src.b = src.b * (1.0f - border_t) + border.b * border_t;
                    src.a = src.a * (1.0f - border_t) + border.a * border_t;
                }

                const float alpha = std::clamp(src.a * coverage, 0.0f, 1.0f);
                if (alpha <= 0.0f) {
                    continue;
                }

                const std::size_t p_off =
                    (static_cast<std::size_t>(py) * config.width + static_cast<std::size_t>(px)) * 4u;
                constexpr float inv_255 = 1.0f / 255.0f;
                const float dr = static_cast<float>(out_rgba8[p_off + 0u]) * inv_255;
                const float dg = static_cast<float>(out_rgba8[p_off + 1u]) * inv_255;
                const float db = static_cast<float>(out_rgba8[p_off + 2u]) * inv_255;
                const float inv_a = 1.0f - alpha;

                out_rgba8[p_off + 0u] = unit_float_to_u8(src.r * alpha + dr * inv_a);
                out_rgba8[p_off + 1u] = unit_float_to_u8(src.g * alpha + dg * inv_a);
                out_rgba8[p_off + 2u] = unit_float_to_u8(src.b * alpha + db * inv_a);
                out_rgba8[p_off + 3u] = 255u;
            }
        }
    }
}

std::vector<std::uint8_t> rasterize_timeline_viewport_rgba8(
    std::span<const TimelineGpuInstance> instances,
    const TimelineRasterConfig& config,
    std::stop_token stop_token) {
    std::vector<std::uint8_t> out;
    rasterize_timeline_viewport_rgba8_into(instances, config, out, std::move(stop_token));
    return out;
}

} // namespace peelf
