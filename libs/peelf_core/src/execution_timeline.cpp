#include <peelf/execution_timeline.hpp>

#include <algorithm>
#include <format>
#include <limits>
#include <utility>

namespace peelf {

namespace {

[[nodiscard]] constexpr std::uint64_t saturating_add_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    if (const auto sum = checked_add_u64(a, b); sum.has_value()) {
        return *sum;
    }
    return std::numeric_limits<std::uint64_t>::max();
}

[[nodiscard]] constexpr bool debug_event_uses_thread_lane(
    debugger::DebugEventKind kind,
    ThreadId tid) noexcept {
    if (tid == 0u) {
        return false;
    }
    switch (kind) {
        case debugger::DebugEventKind::ProcessStarted:
        case debugger::DebugEventKind::ProcessExited:
        case debugger::DebugEventKind::ModuleLoaded:
        case debugger::DebugEventKind::ModuleUnloaded:
            return false;
        case debugger::DebugEventKind::BreakpointHit:
        case debugger::DebugEventKind::SingleStepCompleted:
        case debugger::DebugEventKind::ExceptionOrSignal:
        case debugger::DebugEventKind::ThreadCreated:
        case debugger::DebugEventKind::ThreadExited:
        case debugger::DebugEventKind::DebugOutput:
            return true;
    }
    return false;
}

[[nodiscard]] std::optional<std::uint64_t> extract_thread_snapshot_va(
    const ThreadSnapshot& snap) noexcept {
    if (snap.context.has_value() && snap.context.value->instruction_pointer != 0u) {
        return snap.context.value->instruction_pointer;
    }
    if (snap.info.instruction_pointer.has_value() && *snap.info.instruction_pointer != 0u) {
        return *snap.info.instruction_pointer;
    }
    if (snap.info.start_address.has_value() && *snap.info.start_address != 0u) {
        return *snap.info.start_address;
    }
    return std::nullopt;
}

[[nodiscard]] std::string format_module_delta_summary(const ModuleDelta& delta) {
    if (!delta.detail.empty()) {
        return delta.detail;
    }
    const ModuleInfo* mod = delta.after.has_value()
                                ? &(*delta.after)
                                : (delta.before.has_value() ? &(*delta.before) : nullptr);
    const std::string name = (mod != nullptr && !mod->name.empty()) ? mod->name : "<module>";
    const std::uint64_t base = mod != nullptr ? mod->base_address : 0u;
    return std::format("Module {} {} at 0x{:X}", to_string(delta.kind), name, base);
}

[[nodiscard]] std::string format_region_delta_summary(const RegionDelta& delta) {
    if (!delta.detail.empty()) {
        return delta.detail;
    }
    return std::format(
        "Region {} [0x{:X}, 0x{:X})",
        to_string(delta.kind),
        delta.start_address,
        delta.end_address);
}

[[nodiscard]] std::string format_thread_delta_summary(
    const ThreadDelta& delta,
    const ThreadIdentity& lane_id) {
    if (!delta.detail.empty()) {
        if (lane_id.epoch > 1u) {
            return std::format("{} [epoch #{}]", delta.detail, lane_id.epoch);
        }
        return delta.detail;
    }
    if (lane_id.epoch > 1u) {
        return std::format("TID {} (epoch #{}) {}", delta.tid, lane_id.epoch, to_string(delta.kind));
    }
    return std::format("TID {} {}", delta.tid, to_string(delta.kind));
}

[[nodiscard]] std::string format_handle_delta_summary(const HandleDelta& delta) {
    if (!delta.detail.empty()) {
        return delta.detail;
    }
    const ProcessHandleEntry* h = delta.after.has_value()
                                      ? &(*delta.after)
                                      : (delta.before.has_value() ? &(*delta.before) : nullptr);
    const std::string target = (h != nullptr && !h->target.empty()) ? h->target : "<unnamed>";
    return std::format("Handle/FD {} {}: {}", delta.handle_or_fd, to_string(delta.kind), target);
}

[[nodiscard]] std::string format_socket_delta_summary(const SocketDelta& delta) {
    if (!delta.detail.empty()) {
        return delta.detail;
    }
    const ProcessSocketEntry* s = delta.after.has_value()
                                      ? &(*delta.after)
                                      : (delta.before.has_value() ? &(*delta.before) : nullptr);
    if (s != nullptr) {
        return std::format(
            "{} socket {}: {} -> {} ({})",
            to_string(s->protocol),
            to_string(delta.kind),
            s->local_endpoint,
            s->remote_endpoint,
            s->state);
    }
    return std::format("Socket {}", to_string(delta.kind));
}

[[nodiscard]] bool is_snapshot_interval_non_continuous(
    const SnapshotDiff& diff,
    const SnapshotTimelineIngestOptions& options) noexcept {
    if (diff.has_uncertainties()) {
        return true;
    }
    if (options.target_continuously_paused &&
        diff.before_stamp.target_paused &&
        diff.after_stamp.target_paused) {
        return false;
    }
    if (!diff.before_stamp.target_paused || !diff.after_stamp.target_paused) {
        return true;
    }
    if (diff.after_stamp.monotonic_ns > diff.before_stamp.monotonic_ns ||
        diff.after_stamp.captured_unix_ms > diff.before_stamp.captured_unix_ms) {
        return true;
    }
    if (diff.after_revision > saturating_add_u64(diff.before_revision, 1u)) {
        return true;
    }
    return false;
}

[[nodiscard]] TimelineNavigationTarget resolve_timeline_navigation_default(
    const TimelineEvent& event) {
    TimelineNavigationTarget target{};
    target.thread = event.thread;
    target.virtual_address = event.virtual_address;
    if (event.stamp.snapshot_revision != 0u) {
        target.snapshot_revision = event.stamp.snapshot_revision;
    }

    switch (event.kind) {
        case TimelineEventKind::DebuggerEvent: {
            const auto* dbg = std::get_if<debugger::DebugEvent>(&event.payload);
            if (dbg != nullptr) {
                switch (dbg->kind) {
                    case debugger::DebugEventKind::BreakpointHit:
                    case debugger::DebugEventKind::SingleStepCompleted:
                    case debugger::DebugEventKind::ExceptionOrSignal:
                        if (event.virtual_address.has_value() && *event.virtual_address != 0u) {
                            target.primary_panel = TimelineTargetPanel::Disassembly;
                            target.executable_target = true;
                            target.byte_size = 1u;
                            target.description = std::format(
                                "Navigate Disassembly to 0x{:X} ({})",
                                *event.virtual_address,
                                debugger::to_string(dbg->kind));
                        } else {
                            target.primary_panel = TimelineTargetPanel::Debugger;
                            target.description = std::format(
                                "Inspect {} in Debugger",
                                debugger::to_string(dbg->kind));
                        }
                        return target;

                    case debugger::DebugEventKind::ModuleLoaded:
                    case debugger::DebugEventKind::ModuleUnloaded:
                        if (event.virtual_address.has_value() && *event.virtual_address != 0u) {
                            target.primary_panel = TimelineTargetPanel::Hex;
                            target.byte_size = 64u;
                            target.description = std::format(
                                "Inspect module base 0x{:X} in Hex View",
                                *event.virtual_address);
                        } else {
                            target.primary_panel = TimelineTargetPanel::Debugger;
                            target.description = "Open Debugger module event";
                        }
                        return target;

                    case debugger::DebugEventKind::ProcessStarted:
                    case debugger::DebugEventKind::ThreadCreated:
                    case debugger::DebugEventKind::ThreadExited:
                    case debugger::DebugEventKind::DebugOutput:
                    case debugger::DebugEventKind::ProcessExited:
                        target.primary_panel = TimelineTargetPanel::Debugger;
                        target.description = std::format(
                            "Inspect {} in Debugger",
                            debugger::to_string(dbg->kind));
                        return target;
                }
            }
            target.primary_panel = TimelineTargetPanel::Debugger;
            target.description = "Inspect event in Debugger";
            return target;
        }

        case TimelineEventKind::ModuleDelta: {
            const auto* md = std::get_if<ModuleDelta>(&event.payload);
            if (md != nullptr) {
                const ModuleInfo* mod = md->after.has_value()
                                            ? &(*md->after)
                                            : (md->before.has_value() ? &(*md->before) : nullptr);
                if (mod != nullptr && mod->base_address != 0u) {
                    target.virtual_address = mod->base_address;
                    target.byte_size = mod->size != 0u ? mod->size : 64u;
                    target.primary_panel = TimelineTargetPanel::Hex;
                    target.description = std::format(
                        "Inspect module '{}' at 0x{:X} in Hex View",
                        mod->name,
                        mod->base_address);
                    return target;
                }
            }
            target.primary_panel = TimelineTargetPanel::ExecutableSettings;
            target.description = "Inspect module delta in Executable Settings";
            return target;
        }

        case TimelineEventKind::RegionDelta: {
            const auto* rd = std::get_if<RegionDelta>(&event.payload);
            if (rd != nullptr && rd->start_address != 0u) {
                target.virtual_address = rd->start_address;
                target.byte_size = rd->size() != 0u ? rd->size() : 16u;
                const bool exec_region =
                    rd->became_rwx || rd->became_executable || rd->jit_rw_to_rx ||
                    (rd->after_protection.has_value() && rd->after_protection->executable);
                target.executable_target = exec_region;
                target.primary_panel = exec_region
                                           ? TimelineTargetPanel::Disassembly
                                           : TimelineTargetPanel::Hex;
                target.description = std::format(
                    "Navigate {} to region [0x{:X}, 0x{:X})",
                    to_string(target.primary_panel),
                    rd->start_address,
                    rd->end_address);
                return target;
            }
            target.primary_panel = TimelineTargetPanel::Hex;
            target.description = "Inspect memory region delta";
            return target;
        }

        case TimelineEventKind::ThreadDelta: {
            if (event.virtual_address.has_value() && *event.virtual_address != 0u) {
                target.primary_panel = TimelineTargetPanel::Disassembly;
                target.executable_target = true;
                target.byte_size = 1u;
                target.description = std::format(
                    "Navigate Disassembly to thread PC 0x{:X}",
                    *event.virtual_address);
                return target;
            }
            target.primary_panel = TimelineTargetPanel::Debugger;
            target.description = "Inspect thread state in Debugger";
            return target;
        }

        case TimelineEventKind::HandleDelta:
        case TimelineEventKind::SocketDelta:
            target.primary_panel = TimelineTargetPanel::ProcessInternals;
            target.description = std::format(
                "Open Process Internals ({})",
                to_string(event.kind));
            return target;

        case TimelineEventKind::SyscallEntry:
        case TimelineEventKind::SyscallExit:
            if (event.virtual_address.has_value() && *event.virtual_address != 0u) {
                target.primary_panel = TimelineTargetPanel::Disassembly;
                target.executable_target = true;
                target.byte_size = 1u;
                target.description = std::format(
                    "Navigate Disassembly to syscall site 0x{:X}",
                    *event.virtual_address);
            } else {
                target.primary_panel = TimelineTargetPanel::Debugger;
                target.description = "Inspect syscall event in Debugger";
            }
            return target;

        case TimelineEventKind::SamplingGap:
            target.primary_panel = TimelineTargetPanel::ExecutableSettings;
            target.description = "Inspect snapshot interval uncertainty in Executable Settings";
            return target;

        case TimelineEventKind::DroppedEvents:
            target.primary_panel = TimelineTargetPanel::Debugger;
            target.description = "Inspect dropped-events marker";
            return target;
    }

    return target;
}

}  // namespace

TimelineNavigationTarget resolve_timeline_navigation(
    const TimelineEvent& event,
    std::optional<TimelineTargetPanel> override_panel) {
    TimelineNavigationTarget target = resolve_timeline_navigation_default(event);
    if (override_panel.has_value()) {
        target.primary_panel = *override_panel;
    }
    return target;
}

// ---------------------------------------------------------------------------
// ExecutionTimeline
// ---------------------------------------------------------------------------

ExecutionTimeline::ExecutionTimeline(std::size_t max_events)
    : capacity_(std::max<std::size_t>(kMinCapacity, max_events)) {}

void ExecutionTimeline::set_capacity(std::size_t max_events) {
    capacity_ = std::max<std::size_t>(kMinCapacity, max_events);
    while (events_.size() > capacity_) {
        const CaptureStamp fallback = events_.front().stamp;
        if (events_.front().kind != TimelineEventKind::DroppedEvents) {
            if (events_.size() < 2u) {
                break;
            }
            const TimelineEvent ev1 = std::move(events_.front());
            events_.pop_front();
            const TimelineEvent ev2 = std::move(events_.front());
            events_.pop_front();

            std::uint64_t dropped = 0u;
            if (const auto* d1 = std::get_if<DroppedEventsPayload>(&ev1.payload); d1 != nullptr) {
                dropped = saturating_add_u64(dropped, d1->dropped_count);
            } else {
                dropped = saturating_add_u64(dropped, 1u);
                total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
            }
            if (const auto* d2 = std::get_if<DroppedEventsPayload>(&ev2.payload); d2 != nullptr) {
                dropped = saturating_add_u64(dropped, d2->dropped_count);
            } else {
                dropped = saturating_add_u64(dropped, 1u);
                total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
            }

            const std::uint64_t first_seq =
                std::holds_alternative<DroppedEventsPayload>(ev1.payload)
                    ? std::get<DroppedEventsPayload>(ev1.payload).first_dropped_sequence
                    : ev1.sequence;
            const std::uint64_t last_seq = ev2.sequence;

            TimelineEvent head{};
            head.sequence = last_seq;
            head.kind = TimelineEventKind::DroppedEvents;
            head.stamp = ev2.stamp.has_capture() ? ev2.stamp : fallback;
            head.provenance = ProvenanceTag::ProcOrOsApi;
            head.summary = std::format(
                "Dropped {} oldest timeline event(s) (seq {}..{}) due to capacity limit ({})",
                dropped,
                first_seq,
                last_seq,
                capacity_);
            head.payload = DroppedEventsPayload{
                .dropped_count = dropped,
                .first_dropped_sequence = first_seq,
                .last_dropped_sequence = last_seq,
                .source_name = "ring_buffer",
                .reason = "ExecutionTimeline capacity reached",
            };
            events_.push_front(std::move(head));
        } else {
            if (events_.size() < 2u) {
                break;
            }
            TimelineEvent head = std::move(events_.front());
            events_.pop_front();
            const TimelineEvent evicted = std::move(events_.front());

            auto& drop_payload = std::get<DroppedEventsPayload>(head.payload);
            if (const auto* mid_drop = std::get_if<DroppedEventsPayload>(&evicted.payload);
                mid_drop != nullptr) {
                drop_payload.dropped_count =
                    saturating_add_u64(drop_payload.dropped_count, mid_drop->dropped_count);
                drop_payload.last_dropped_sequence =
                    std::max(evicted.sequence, mid_drop->last_dropped_sequence);
            } else {
                drop_payload.dropped_count = saturating_add_u64(drop_payload.dropped_count, 1u);
                total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
                drop_payload.last_dropped_sequence = evicted.sequence;
            }
            head.sequence = drop_payload.last_dropped_sequence;
            if (evicted.stamp.has_capture()) {
                head.stamp = evicted.stamp;
            }
            head.summary = std::format(
                "Dropped {} oldest timeline event(s) (seq {}..{}) due to capacity limit ({})",
                drop_payload.dropped_count,
                drop_payload.first_dropped_sequence,
                drop_payload.last_dropped_sequence,
                capacity_);
            events_.front() = std::move(head);
        }
    }
}

const TimelineEvent* ExecutionTimeline::find_event(std::uint64_t sequence) const noexcept {
    const auto it = std::ranges::lower_bound(
        events_,
        sequence,
        {},
        &TimelineEvent::sequence);
    if (it != events_.end() && it->sequence == sequence) {
        return &(*it);
    }
    return nullptr;
}

const TimelineLane* ExecutionTimeline::find_lane(const ThreadIdentity& identity) const noexcept {
    for (const TimelineLane& lane : lanes_) {
        if (lane.identity.same_lane(identity)) {
            return &lane;
        }
    }
    return nullptr;
}

std::uint64_t ExecutionTimeline::event_kind_count(TimelineEventKind kind) const noexcept {
    const auto idx = static_cast<std::size_t>(kind);
    return idx < kind_counts_.size() ? kind_counts_[idx] : 0u;
}

void ExecutionTimeline::clear(bool reset_sources) noexcept {
    next_sequence_ = 1u;
    total_emitted_events_ = 0u;
    total_dropped_events_ = 0u;
    sampling_gap_count_ = 0u;
    kind_counts_.fill(0u);
    last_snapshot_after_stamp_.reset();
    events_.clear();
    lanes_.clear();
    tid_states_.clear();
    if (reset_sources) {
        for (const auto& src : sources_) {
            if (src != nullptr) {
                src->reset();
            }
        }
    }
}

void ExecutionTimeline::seed_threads_from_snapshot(const ProcessStateSnapshot& snapshot) {
    if (snapshot.target_id.pid != 0u && target_id_.pid == 0u) {
        target_id_ = snapshot.target_id;
    }
    if (snapshot.snapshot_stamp.has_capture() && !last_snapshot_after_stamp_.has_value()) {
        last_snapshot_after_stamp_ = snapshot.snapshot_stamp;
    }
    if (!snapshot.threads.has_value()) {
        return;
    }
    for (const ThreadSnapshot& ts : *snapshot.threads.value) {
        if (ts.info.tid == 0u) {
            continue;
        }
        const ThreadIdentity id = resolve_thread_for_observation(
            ts.info.tid,
            ts.creation_identity,
            ts.info.name,
            false,
            ts.info.state == ThreadRunState::Zombie);
        (void)id;
    }
}

CaptureStamp ExecutionTimeline::resolve_or_stamp_now(
    std::optional<CaptureStamp> provided,
    bool paused_default) const {
    if (provided.has_value()) {
        return *provided;
    }
    const std::uint64_t rev = saturating_add_u64(total_emitted_events_, 1u);
    return CaptureStamp::capture_now(target_id_, rev, paused_default, CaptureAvailability::Complete);
}

ThreadIdentity ExecutionTimeline::resolve_thread_for_observation(
    ThreadId tid,
    std::optional<std::uint64_t> creation_identity,
    std::string_view thread_name,
    bool force_new_lifetime,
    bool mark_exited_after) {
    ActiveTidState* state_ptr = nullptr;
    for (auto& [tracked_tid, st] : tid_states_) {
        if (tracked_tid == tid) {
            state_ptr = &st;
            break;
        }
    }
    if (state_ptr == nullptr) {
        tid_states_.emplace_back(tid, ActiveTidState{});
        state_ptr = &tid_states_.back().second;
    }

    bool recycled = false;
    if (state_ptr->current_epoch == 0u) {
        state_ptr->current_epoch = 1u;
        state_ptr->creation_identity = creation_identity;
        state_ptr->active = true;
    } else {
        const bool creation_conflict =
            state_ptr->creation_identity.has_value() &&
            creation_identity.has_value() &&
            (*state_ptr->creation_identity != *creation_identity);

        if (force_new_lifetime || !state_ptr->active || creation_conflict) {
            state_ptr->current_epoch = saturating_add_u64(state_ptr->current_epoch, 1u);
            state_ptr->creation_identity = creation_identity;
            state_ptr->active = true;
            recycled = true;
        } else if (!state_ptr->creation_identity.has_value() && creation_identity.has_value()) {
            state_ptr->creation_identity = creation_identity;
        }
    }

    const ThreadIdentity identity{
        .tid = tid,
        .creation_identity = state_ptr->creation_identity,
        .epoch = state_ptr->current_epoch,
    };

    TimelineLane& lane = ensure_lane(identity, thread_name, recycled);
    if (recycled) {
        // Also mark earlier lanes sharing this OS TID as having experienced TID reuse.
        for (TimelineLane& existing : lanes_) {
            if (existing.identity.tid == tid) {
                existing.tid_recycled = true;
                if (existing.identity.epoch < identity.epoch) {
                    existing.active = false;
                }
            }
        }
    }

    if (mark_exited_after) {
        state_ptr->active = false;
        lane.active = false;
    }

    return lane.identity;
}

TimelineLane& ExecutionTimeline::ensure_lane(
    const ThreadIdentity& identity,
    std::string_view thread_name,
    bool recycled_tid) {
    for (TimelineLane& lane : lanes_) {
        if (lane.identity.tid == identity.tid && lane.identity.epoch == identity.epoch) {
            if (!lane.identity.creation_identity.has_value() &&
                identity.creation_identity.has_value()) {
                lane.identity.creation_identity = identity.creation_identity;
            }
            if (!thread_name.empty()) {
                lane.name = std::string(thread_name);
            }
            if (recycled_tid || identity.epoch > 1u) {
                lane.tid_recycled = true;
            }
            return lane;
        }
    }

    lanes_.push_back(TimelineLane{
        .identity = identity,
        .name = std::string(thread_name),
        .active = true,
        .tid_recycled = recycled_tid || (identity.epoch > 1u),
        .event_count = 0u,
        .first_sequence = 0u,
        .last_sequence = 0u,
    });
    return lanes_.back();
}

void ExecutionTimeline::enforce_capacity_before_push(const CaptureStamp& fallback_stamp) {
    if (events_.size() < capacity_) {
        return;
    }

    if (events_.front().kind != TimelineEventKind::DroppedEvents) {
        // Capacity >= 2 guaranteed. Evict the 2 oldest slots and place 1 coalesced
        // DroppedEvents marker at the front so inserting the new event keeps size == capacity_.
        const TimelineEvent ev1 = std::move(events_.front());
        events_.pop_front();
        const TimelineEvent ev2 = std::move(events_.front());
        events_.pop_front();

        std::uint64_t dropped = 0u;
        if (const auto* d1 = std::get_if<DroppedEventsPayload>(&ev1.payload); d1 != nullptr) {
            dropped = saturating_add_u64(dropped, d1->dropped_count);
        } else {
            dropped = saturating_add_u64(dropped, 1u);
            total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
        }
        if (const auto* d2 = std::get_if<DroppedEventsPayload>(&ev2.payload); d2 != nullptr) {
            dropped = saturating_add_u64(dropped, d2->dropped_count);
        } else {
            dropped = saturating_add_u64(dropped, 1u);
            total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
        }

        const std::uint64_t first_seq =
            std::holds_alternative<DroppedEventsPayload>(ev1.payload)
                ? std::get<DroppedEventsPayload>(ev1.payload).first_dropped_sequence
                : ev1.sequence;
        const std::uint64_t last_seq = ev2.sequence;

        TimelineEvent head{};
        head.sequence = last_seq;
        head.kind = TimelineEventKind::DroppedEvents;
        head.stamp = ev2.stamp.has_capture() ? ev2.stamp : fallback_stamp;
        head.provenance = ProvenanceTag::ProcOrOsApi;
        head.summary = std::format(
            "Dropped {} oldest timeline event(s) (seq {}..{}) due to capacity limit ({})",
            dropped,
            first_seq,
            last_seq,
            capacity_);
        head.payload = DroppedEventsPayload{
            .dropped_count = dropped,
            .first_dropped_sequence = first_seq,
            .last_dropped_sequence = last_seq,
            .source_name = "ring_buffer",
            .reason = "ExecutionTimeline capacity reached",
        };
        events_.push_front(std::move(head));
        return;
    }

    // Front is already a DroppedEvents marker: fold events_[1] into it in O(1).
    TimelineEvent head = std::move(events_.front());
    events_.pop_front();
    const TimelineEvent evicted = std::move(events_.front());

    auto& drop_payload = std::get<DroppedEventsPayload>(head.payload);
    if (const auto* mid_drop = std::get_if<DroppedEventsPayload>(&evicted.payload);
        mid_drop != nullptr) {
        drop_payload.dropped_count =
            saturating_add_u64(drop_payload.dropped_count, mid_drop->dropped_count);
        drop_payload.last_dropped_sequence =
            std::max(evicted.sequence, mid_drop->last_dropped_sequence);
    } else {
        drop_payload.dropped_count = saturating_add_u64(drop_payload.dropped_count, 1u);
        total_dropped_events_ = saturating_add_u64(total_dropped_events_, 1u);
        drop_payload.last_dropped_sequence = evicted.sequence;
    }
    head.sequence = drop_payload.last_dropped_sequence;
    if (evicted.stamp.has_capture()) {
        head.stamp = evicted.stamp;
    }
    head.summary = std::format(
        "Dropped {} oldest timeline event(s) (seq {}..{}) due to capacity limit ({})",
        drop_payload.dropped_count,
        drop_payload.first_dropped_sequence,
        drop_payload.last_dropped_sequence,
        capacity_);
    events_.front() = std::move(head);
}

std::uint64_t ExecutionTimeline::append_event(TimelineEvent event) {
    enforce_capacity_before_push(event.stamp);

    const std::uint64_t seq = next_sequence_;
    next_sequence_ = saturating_add_u64(next_sequence_, 1u);
    event.sequence = seq;

    total_emitted_events_ = saturating_add_u64(total_emitted_events_, 1u);
    const auto kind_idx = static_cast<std::size_t>(event.kind);
    if (kind_idx < kind_counts_.size()) {
        kind_counts_[kind_idx] = saturating_add_u64(kind_counts_[kind_idx], 1u);
    }
    if (event.kind == TimelineEventKind::SamplingGap) {
        sampling_gap_count_ = saturating_add_u64(sampling_gap_count_, 1u);
    }

    if (event.thread.has_value()) {
        TimelineLane& lane = ensure_lane(*event.thread, {}, event.thread->epoch > 1u);
        event.thread = lane.identity;
        lane.event_count = saturating_add_u64(lane.event_count, 1u);
        if (lane.first_sequence == 0u) {
            lane.first_sequence = seq;
        }
        lane.last_sequence = seq;
    }

    events_.push_back(std::move(event));
    return seq;
}

std::uint64_t ExecutionTimeline::ingest_debug_event(
    const debugger::DebugEvent& event,
    std::optional<CaptureStamp> stamp,
    std::optional<std::uint64_t> thread_creation_identity,
    std::string_view thread_name) {
    if (event.pid != 0u && target_id_.pid == 0u) {
        target_id_.backend = BackendKind::ActiveDebugger;
        target_id_.pid = event.pid;
    }

    const bool paused_stop =
        event.kind == debugger::DebugEventKind::BreakpointHit ||
        event.kind == debugger::DebugEventKind::SingleStepCompleted ||
        event.kind == debugger::DebugEventKind::ExceptionOrSignal ||
        event.kind == debugger::DebugEventKind::ProcessStarted;
    CaptureStamp resolved_stamp = resolve_or_stamp_now(std::move(stamp), paused_stop);

    std::optional<ThreadIdentity> lane_identity{};
    if (debug_event_uses_thread_lane(event.kind, event.tid)) {
        const bool is_create = (event.kind == debugger::DebugEventKind::ThreadCreated);
        const bool is_exit = (event.kind == debugger::DebugEventKind::ThreadExited);

        // Note: on initial attach or launch, ThreadCreated may arrive for a brand-new TID
        // (`current_epoch == 0` -> epoch 1) or for a TID that was previously active/exited
        // (`force_new_lifetime == true` -> increments epoch).
        lane_identity = resolve_thread_for_observation(
            event.tid,
            thread_creation_identity,
            thread_name,
            is_create,
            is_exit);
    } else if (event.kind == debugger::DebugEventKind::ProcessExited) {
        for (auto& [tracked_tid, st] : tid_states_) {
            (void)tracked_tid;
            st.active = false;
        }
        for (TimelineLane& lane : lanes_) {
            lane.active = false;
        }
    }

    std::string summary = event.summary;
    if (summary.empty()) {
        if (event.address.has_value() && *event.address != 0u) {
            summary = std::format(
                "{} at 0x{:X}",
                debugger::to_string(event.kind),
                *event.address);
        } else {
            summary = std::string(debugger::to_string(event.kind));
        }
    }

    TimelineEvent record{};
    record.kind = TimelineEventKind::DebuggerEvent;
    record.stamp = std::move(resolved_stamp);
    record.thread = lane_identity;
    record.virtual_address = event.address;
    record.provenance = ProvenanceTag::DebuggerShadowed;
    record.summary = std::move(summary);
    record.payload = event;
    return append_event(std::move(record));
}

std::size_t ExecutionTimeline::ingest_snapshot_diff(
    const SnapshotDiff& diff,
    const SnapshotTimelineIngestOptions& options) {
    if (diff.rejected_target_mismatch || !diff.target_identity_matched) {
        return 0u;
    }

    if (target_id_.pid != 0u && diff.after_target_id.pid != 0u &&
        !target_id_.same_instance(diff.after_target_id)) {
        return 0u;
    }
    if (target_id_.pid == 0u && diff.after_target_id.pid != 0u) {
        target_id_ = diff.after_target_id;
    }

    std::size_t emitted = 0u;

    // 1. If there was a prior ingested snapshot and this diff begins strictly later than
    //    that snapshot's end stamp, emit an explicit inter-diff SamplingGap first.
    if (last_snapshot_after_stamp_.has_value()) {
        const CaptureStamp& prev_end = *last_snapshot_after_stamp_;
        const bool skipped_revisions =
            diff.before_revision != 0u &&
            prev_end.snapshot_revision != 0u &&
            diff.before_revision > prev_end.snapshot_revision;
        const bool skipped_time =
            diff.before_stamp.monotonic_ns > prev_end.monotonic_ns;
        if (skipped_revisions || skipped_time) {
            const TimelineInterval skipped_iv{
                .earliest = prev_end,
                .latest = diff.before_stamp,
            };
            TimelineEvent gap_ev{};
            gap_ev.kind = TimelineEventKind::SamplingGap;
            gap_ev.stamp = diff.before_stamp;
            gap_ev.observation_interval = skipped_iv;
            gap_ev.provenance = ProvenanceTag::ProcOrOsApi;
            gap_ev.summary = std::format(
                "Sampling gap between snapshot rev {} and rev {} ({} ms unobserved)",
                prev_end.snapshot_revision,
                diff.before_revision,
                skipped_iv.duration_unix_ms());
            gap_ev.payload = SamplingGapPayload{
                .before_revision = prev_end.snapshot_revision,
                .after_revision = diff.before_revision,
                .unobserved_monotonic_ns = skipped_iv.duration_ns(),
                .unobserved_unix_ms = skipped_iv.duration_unix_ms(),
                .target_executed_unobserved = true,
                .uncertainties = {},
                .reason = "Non-adjacent snapshot baseline created an uncaptured execution gap",
            };
            (void)append_event(std::move(gap_ev));
            ++emitted;
        }
    }

    const TimelineInterval obs_interval{
        .earliest = diff.before_stamp,
        .latest = diff.after_stamp,
    };

    // 2. Emit SamplingGap across [before_stamp, after_stamp] when non-continuous or uncertain.
    if (is_snapshot_interval_non_continuous(diff, options)) {
        TimelineEvent gap_ev{};
        gap_ev.kind = TimelineEventKind::SamplingGap;
        gap_ev.stamp = diff.after_stamp;
        gap_ev.observation_interval = obs_interval;
        gap_ev.provenance = ProvenanceTag::ProcOrOsApi;
        gap_ev.summary = std::format(
            "Sampling gap across snapshot rev {} -> {} ({} ms interval, {} uncertainty note(s))",
            diff.before_revision,
            diff.after_revision,
            obs_interval.duration_unix_ms(),
            diff.uncertainties.size());
        gap_ev.payload = SamplingGapPayload{
            .before_revision = diff.before_revision,
            .after_revision = diff.after_revision,
            .unobserved_monotonic_ns = obs_interval.duration_ns(),
            .unobserved_unix_ms = obs_interval.duration_unix_ms(),
            .target_executed_unobserved = !options.target_continuously_paused,
            .uncertainties = diff.uncertainties,
            .reason = diff.has_uncertainties()
                          ? "Sampled snapshot interval includes partial/unavailable collection uncertainty"
                          : "Target threads executed unobserved between point-in-time snapshots",
        };
        (void)append_event(std::move(gap_ev));
        ++emitted;
    }

    // 3. Emit ModuleDeltas on Process / Global lane.
    for (const ModuleDelta& md : diff.modules) {
        const ModuleInfo* mod = md.after.has_value()
                                    ? &(*md.after)
                                    : (md.before.has_value() ? &(*md.before) : nullptr);
        TimelineEvent ev{};
        ev.kind = TimelineEventKind::ModuleDelta;
        ev.stamp = diff.after_stamp;
        ev.observation_interval = obs_interval;
        if (mod != nullptr && mod->base_address != 0u) {
            ev.virtual_address = mod->base_address;
        }
        ev.provenance = ProvenanceTag::ProcOrOsApi;
        ev.summary = format_module_delta_summary(md);
        ev.payload = md;
        (void)append_event(std::move(ev));
        ++emitted;
    }

    // 4. Emit RegionDeltas on Process / Global lane.
    for (const RegionDelta& rd : diff.regions) {
        TimelineEvent ev{};
        ev.kind = TimelineEventKind::RegionDelta;
        ev.stamp = diff.after_stamp;
        ev.observation_interval = obs_interval;
        if (rd.start_address != 0u) {
            ev.virtual_address = rd.start_address;
        }
        ev.provenance = ProvenanceTag::ProcOrOsApi;
        ev.summary = format_region_delta_summary(rd);
        ev.payload = rd;
        (void)append_event(std::move(ev));
        ++emitted;
    }

    // 5. Emit ThreadDeltas onto distinct ThreadIdentity lanes (exits processed before creations
    //    in diff_process_snapshots so recycled OS TIDs cleanly advance to a new epoch).
    for (const ThreadDelta& td : diff.threads) {
        std::optional<std::uint64_t> ci{};
        std::string tname{};
        std::optional<std::uint64_t> va{};

        if (td.kind == ThreadDeltaKind::Exited) {
            if (td.before.has_value()) {
                ci = td.before->creation_identity;
                tname = td.before->info.name;
                va = extract_thread_snapshot_va(*td.before);
            }
        } else {
            if (td.after.has_value()) {
                ci = td.after->creation_identity;
                tname = td.after->info.name;
                va = extract_thread_snapshot_va(*td.after);
            } else if (td.before.has_value()) {
                ci = td.before->creation_identity;
                tname = td.before->info.name;
                va = extract_thread_snapshot_va(*td.before);
            }
        }

        const bool force_new_lane =
            (td.kind == ThreadDeltaKind::Created) && td.tid_reused;
        const bool mark_exited = (td.kind == ThreadDeltaKind::Exited);

        std::optional<ThreadIdentity> lane_id{};
        if (td.tid != 0u) {
            lane_id = resolve_thread_for_observation(
                td.tid,
                ci,
                tname,
                force_new_lane,
                mark_exited);
        }

        TimelineEvent ev{};
        ev.kind = TimelineEventKind::ThreadDelta;
        ev.stamp = diff.after_stamp;
        ev.observation_interval = obs_interval;
        ev.thread = lane_id;
        ev.virtual_address = va;
        ev.provenance = ProvenanceTag::ProcOrOsApi;
        ev.summary = format_thread_delta_summary(
            td,
            lane_id.value_or(ThreadIdentity{.tid = td.tid}));
        ev.payload = td;
        (void)append_event(std::move(ev));
        ++emitted;
    }

    // 6. Emit HandleDeltas on Process / Global lane.
    for (const HandleDelta& hd : diff.handles) {
        TimelineEvent ev{};
        ev.kind = TimelineEventKind::HandleDelta;
        ev.stamp = diff.after_stamp;
        ev.observation_interval = obs_interval;
        ev.provenance = ProvenanceTag::ProcOrOsApi;
        ev.summary = format_handle_delta_summary(hd);
        ev.payload = hd;
        (void)append_event(std::move(ev));
        ++emitted;
    }

    // 7. Emit SocketDeltas on Process / Global lane.
    for (const SocketDelta& sd : diff.sockets) {
        TimelineEvent ev{};
        ev.kind = TimelineEventKind::SocketDelta;
        ev.stamp = diff.after_stamp;
        ev.observation_interval = obs_interval;
        ev.provenance = ProvenanceTag::ProcOrOsApi;
        ev.summary = format_socket_delta_summary(sd);
        ev.payload = sd;
        (void)append_event(std::move(ev));
        ++emitted;
    }

    if (diff.after_stamp.has_capture() || diff.after_revision != 0u) {
        last_snapshot_after_stamp_ = diff.after_stamp;
    }

    return emitted;
}

std::uint64_t ExecutionTimeline::ingest_syscall_event(
    bool is_exit,
    ThreadId tid,
    SyscallEventPayload payload,
    std::optional<CaptureStamp> stamp,
    std::optional<std::uint64_t> thread_creation_identity,
    std::string_view thread_name) {
    CaptureStamp resolved_stamp = resolve_or_stamp_now(std::move(stamp), true);

    std::optional<ThreadIdentity> lane_id{};
    if (tid != 0u) {
        lane_id = resolve_thread_for_observation(
            tid,
            thread_creation_identity,
            thread_name,
            false,
            false);
    }

    const std::string label = payload.name.empty()
                                  ? std::format("syscall #{}", payload.syscall_number)
                                  : payload.name;
    std::string summary = is_exit
                              ? (payload.return_value.has_value()
                                     ? std::format("{} -> {}", label, *payload.return_value)
                                     : std::format("{} exit", label))
                              : std::format("{} entry", label);

    TimelineEvent ev{};
    ev.kind = is_exit ? TimelineEventKind::SyscallExit : TimelineEventKind::SyscallEntry;
    ev.stamp = std::move(resolved_stamp);
    ev.thread = lane_id;
    ev.virtual_address = payload.instruction_pointer;
    ev.provenance = ProvenanceTag::ProcOrOsApi;
    ev.summary = std::move(summary);
    ev.payload = std::move(payload);
    return append_event(std::move(ev));
}

std::uint64_t ExecutionTimeline::record_dropped_events(
    std::uint64_t dropped_count,
    std::optional<CaptureStamp> stamp,
    std::string_view source_name,
    std::string_view reason) {
    if (dropped_count == 0u) {
        return next_sequence_ > 1u ? (next_sequence_ - 1u) : 0u;
    }

    CaptureStamp resolved_stamp = resolve_or_stamp_now(std::move(stamp), false);
    total_dropped_events_ = saturating_add_u64(total_dropped_events_, dropped_count);

    TimelineEvent ev{};
    ev.kind = TimelineEventKind::DroppedEvents;
    ev.stamp = std::move(resolved_stamp);
    ev.provenance = ProvenanceTag::ProcOrOsApi;
    ev.summary = std::format(
        "Dropped {} event(s) from {}: {}",
        dropped_count,
        source_name.empty() ? "source" : source_name,
        reason);
    ev.payload = DroppedEventsPayload{
        .dropped_count = dropped_count,
        .first_dropped_sequence = next_sequence_,
        .last_dropped_sequence = next_sequence_,
        .source_name = std::string(source_name),
        .reason = std::string(reason),
    };
    return append_event(std::move(ev));
}

void ExecutionTimeline::register_source(std::shared_ptr<ITimelineSource> source) {
    if (source == nullptr) {
        return;
    }
    sources_.push_back(std::move(source));
}

std::vector<TimelineSourceDescriptor> ExecutionTimeline::source_descriptors() const {
    std::vector<TimelineSourceDescriptor> out;
    out.reserve(sources_.size());
    for (const auto& src : sources_) {
        if (src != nullptr) {
            out.push_back(src->descriptor());
        }
    }
    return out;
}

ForgivingValue<std::size_t> ExecutionTimeline::poll_sources() {
    std::size_t total_polled = 0u;
    std::size_t active_sources = 0u;
    std::size_t failed_sources = 0u;
    std::string failure_detail{};

    for (const auto& src : sources_) {
        if (src == nullptr) {
            continue;
        }
        const TimelineSourceDescriptor desc = src->descriptor();
        if (!desc.can_poll()) {
            continue;
        }
        ++active_sources;
        auto res = src->poll(*this);
        if (res.has_value()) {
            if (const auto sum = checked_add_u64(
                    static_cast<std::uint64_t>(total_polled),
                    static_cast<std::uint64_t>(*res));
                sum.has_value() && *sum <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                total_polled = static_cast<std::size_t>(*sum);
            } else {
                total_polled = std::numeric_limits<std::size_t>::max();
            }
        } else {
            ++failed_sources;
            if (!failure_detail.empty()) {
                failure_detail += "; ";
            }
            failure_detail += res.error().message;
        }
    }

    if (active_sources == 0u) {
        return ForgivingValue<std::size_t>{
            .value = std::size_t{0u},
            .status = SubsystemStatus::unavailable(
                "timeline",
                "No supported active timeline sources are currently attached"),
        };
    }
    if (failed_sources > 0u && failed_sources == active_sources) {
        return ForgivingValue<std::size_t>{
            .value = std::nullopt,
            .status = SubsystemStatus::unavailable("timeline", std::move(failure_detail)),
        };
    }
    if (failed_sources > 0u) {
        return ForgivingValue<std::size_t>{
            .value = total_polled,
            .status = SubsystemStatus::partial("timeline", std::move(failure_detail)),
        };
    }
    return ForgivingValue<std::size_t>{
        .value = total_polled,
        .status = SubsystemStatus::available("timeline", "Polled active timeline sources"),
    };
}

// ---------------------------------------------------------------------------
// DebugSessionTimelineSource & UnsupportedTimelineSource
// ---------------------------------------------------------------------------

DebugSessionTimelineSource::DebugSessionTimelineSource(
    std::shared_ptr<debugger::IDebugSession> session,
    TargetInstanceId target_id,
    ThreadCreationIdentityQuery creation_query)
    : session_(std::move(session))
    , target_id_(std::move(target_id))
    , creation_query_(std::move(creation_query)) {}

TimelineSourceDescriptor DebugSessionTimelineSource::descriptor() const {
    if (session_ == nullptr) {
        return TimelineSourceDescriptor{
            .kind = TimelineSourceKind::DebuggerEvents,
            .name = "Debugger Events",
            .support_state = SupportState::SupportedValidated,
            .provider_available = false,
            .provenance = ProvenanceTag::DebuggerShadowed,
            .status = SubsystemStatus::unavailable("debugger", "No active IDebugSession attached"),
        };
    }
    return TimelineSourceDescriptor{
        .kind = TimelineSourceKind::DebuggerEvents,
        .name = "Debugger Events",
        .support_state = SupportState::SupportedValidated,
        .provider_available = true,
        .provenance = ProvenanceTag::DebuggerShadowed,
        .status = SubsystemStatus::available(
            "debugger",
            std::format("Streaming IDebugSession events (state: {})", debugger::to_string(session_->state()))),
    };
}

SupportState DebugSessionTimelineSource::support_state() const noexcept {
    return SupportState::SupportedValidated;
}

Result<std::size_t> DebugSessionTimelineSource::poll(ExecutionTimeline& timeline) {
    if (session_ == nullptr) {
        return make_error("DebugSessionTimelineSource has no attached IDebugSession");
    }

    const std::vector<debugger::DebugEvent> batch = session_->events();
    if (batch.empty()) {
        return std::size_t{0u};
    }

    const bool paused_now = (session_->state() == debugger::DebugSessionState::Paused);
    std::size_t emitted = 0u;

    for (const debugger::DebugEvent& ev : batch) {
        if (ev.sequence != 0u && ev.sequence <= last_polled_sequence_) {
            continue;
        }

        if (ev.sequence > saturating_add_u64(last_polled_sequence_, 1u)) {
            const std::uint64_t lost = ev.sequence - last_polled_sequence_ - 1u;
            const CaptureStamp drop_stamp = CaptureStamp::capture_now(
                target_id_,
                 saturating_add_u64(timeline.total_emitted_events(), 1u),
                paused_now,
                CaptureAvailability::Partial);
            (void)timeline.record_dropped_events(
                lost,
                drop_stamp,
                "IDebugSession",
                "Debugger event ring overflowed between timeline polls");
            ++emitted;
        }

        if (ev.sequence != 0u) {
            last_polled_sequence_ = ev.sequence;
        }

        std::optional<std::uint64_t> creation_id{};
        if (ev.tid != 0u) {
            const ProcessId pid = ev.pid != 0u ? ev.pid : session_->session().pid();
            if (ev.kind == debugger::DebugEventKind::ThreadCreated) {
                if (creation_query_) {
                    creation_id = creation_query_(pid, ev.tid);
                }
                bool updated = false;
                for (auto& [cached_tid, cached_ci] : cached_tid_identities_) {
                    if (cached_tid == ev.tid) {
                        cached_ci = creation_id;
                        updated = true;
                        break;
                    }
                }
                if (!updated) {
                    cached_tid_identities_.emplace_back(ev.tid, creation_id);
                }
            } else {
                bool found = false;
                for (const auto& [cached_tid, cached_ci] : cached_tid_identities_) {
                    if (cached_tid == ev.tid) {
                        creation_id = cached_ci;
                        found = true;
                        break;
                    }
                }
                if (!found && creation_query_ && ev.kind != debugger::DebugEventKind::ThreadExited) {
                    creation_id = creation_query_(pid, ev.tid);
                    cached_tid_identities_.emplace_back(ev.tid, creation_id);
                }
                if (ev.kind == debugger::DebugEventKind::ThreadExited) {
                    std::erase_if(cached_tid_identities_, [&](const auto& kv) noexcept {
                        return kv.first == ev.tid;
                    });
                }
            }
        }

        const CaptureStamp ev_stamp = CaptureStamp::capture_now(
            target_id_,
            saturating_add_u64(timeline.total_emitted_events(), 1u),
            paused_now,
            CaptureAvailability::Complete);
        (void)timeline.ingest_debug_event(ev, ev_stamp, creation_id);
        ++emitted;
    }

    return emitted;
}

void DebugSessionTimelineSource::reset() noexcept {
    last_polled_sequence_ = 0u;
    cached_tid_identities_.clear();
}

UnsupportedTimelineSource::UnsupportedTimelineSource(
    TimelineSourceKind kind,
    std::string name,
    std::string reason)
    : kind_(kind)
    , name_(std::move(name))
    , reason_(std::move(reason)) {}

TimelineSourceDescriptor UnsupportedTimelineSource::descriptor() const {
    return TimelineSourceDescriptor{
        .kind = kind_,
        .name = name_,
        .support_state = SupportState::Unsupported,
        .provider_available = false,
        .provenance = ProvenanceTag::ProcOrOsApi,
        .status = SubsystemStatus::unavailable(name_, reason_),
    };
}

Result<std::size_t> UnsupportedTimelineSource::poll(ExecutionTimeline& /*timeline*/) {
    return make_error(std::format(
        "Timeline source '{}' is unsupported: {}",
        name_,
        reason_));
}

std::shared_ptr<ITimelineSource> create_syscall_timeline_source() {
    return std::make_shared<UnsupportedTimelineSource>(
        TimelineSourceKind::SyscallTrace,
        "Syscall Trace",
        "Kernel syscall entry/exit stop tracing (PTRACE_SYSCALL / seccomp) is not enabled");
}

std::shared_ptr<ITimelineSource> create_etw_timeline_source() {
    return std::make_shared<UnsupportedTimelineSource>(
        TimelineSourceKind::EtwOrKernelTrace,
        "ETW / Kernel Trace",
        "OS kernel event trace provider (ETW / perf_event_open) is not enabled");
}

}  // namespace peelf
