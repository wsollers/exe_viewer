#include "ui/ui_panels_memory_heatmap.hpp"

#include "ui/logger.hpp"
#include "ui/panel_helpers.hpp"

#include <peelf/capability_matrix.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/debugger.hpp>

#include <imgui.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

constexpr std::uint32_t kInvalidCellIndex = 0xFFFF'FFFFu;
constexpr std::uint32_t kDefaultMaxCellsCompact = 65'536u;
constexpr std::uint32_t kDefaultMaxCellsFocused = 131'072u;
constexpr std::size_t kLiveReadBudgetBytesPerTick = 4u * 1024u * 1024u;
constexpr std::size_t kStaticReadBudgetBytesPerTick = 8u * 1024u * 1024u;
constexpr double kZoomWheelBase = 1.18;
constexpr float kMinCanvasHeightPx = 180.0f;
constexpr float kRightClickDragSlopPx = 4.0f;

[[nodiscard]] constexpr std::chrono::milliseconds cadence_interval(
    HeatmapPollCadence cadence) noexcept {
    switch (cadence) {
        case HeatmapPollCadence::Hz10:           return std::chrono::milliseconds{100};
        case HeatmapPollCadence::Hz4:            return std::chrono::milliseconds{250};
        case HeatmapPollCadence::Hz1:            return std::chrono::milliseconds{1000};
        case HeatmapPollCadence::ManualSnapshot: return std::chrono::milliseconds{0};
    }
    return std::chrono::milliseconds{250};
}

[[nodiscard]] constexpr const char* cadence_label(HeatmapPollCadence cadence) noexcept {
    switch (cadence) {
        case HeatmapPollCadence::Hz10:           return "10 Hz (100 ms)";
        case HeatmapPollCadence::Hz4:            return "4 Hz (250 ms)";
        case HeatmapPollCadence::Hz1:            return "1 Hz (1.0 s)";
        case HeatmapPollCadence::ManualSnapshot: return "Manual Snapshot";
    }
    return "4 Hz (250 ms)";
}

[[nodiscard]] constexpr const char* layout_ui_label(
    peelf::MemoryHeatmapLayout layout) noexcept {
    switch (layout) {
        case peelf::MemoryHeatmapLayout::HilbertCurve: return "Hilbert Curve 2D";
        case peelf::MemoryHeatmapLayout::LinearRows:   return "Linear Tile";
    }
    return "Hilbert Curve 2D";
}

[[nodiscard]] constexpr const char* scope_ui_label(peelf::MemoryHeatmapScope scope) noexcept {
    switch (scope) {
        case peelf::MemoryHeatmapScope::CompactAddressSpace:
            return "CompactMapped Address Space";
        case peelf::MemoryHeatmapScope::FocusedRange:
            return "Focused Region / Heap / Module";
    }
    return "CompactMapped Address Space";
}

[[nodiscard]] constexpr const char* color_mode_ui_label(
    peelf::MemoryHeatmapColorMode mode) noexcept {
    switch (mode) {
        case peelf::MemoryHeatmapColorMode::AllocatorAndWriteHeat:
            return "Allocator & Write Heat";
        case peelf::MemoryHeatmapColorMode::CategoryAndResidency:
            return "Region Category & Residency";
        case peelf::MemoryHeatmapColorMode::PermissionsAndRwx:
            return "Permissions & RWX";
        case peelf::MemoryHeatmapColorMode::PageEntropy:
            return "Page Entropy";
    }
    return "Allocator & Write Heat";
}

[[nodiscard]] std::string format_byte_span_compact(std::uint64_t bytes) {
    if (bytes >= (1024ull * 1024ull) && (bytes % (1024ull * 1024ull)) == 0ull) {
        return std::format("{} MiB", bytes / (1024ull * 1024ull));
    }
    if (bytes >= 1024ull && (bytes % 1024ull) == 0ull) {
        return std::format("{} KiB", bytes / 1024ull);
    }
    if (bytes >= (1024ull * 1024ull)) {
        return std::format("{:.1f} MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    }
    if (bytes >= 1024ull) {
        return std::format("{:.1f} KiB", static_cast<double>(bytes) / 1024.0);
    }
    return std::format("{} B", bytes);
}

[[nodiscard]] std::string format_perm_bits(std::uint8_t perms) {
    std::string out;
    out.reserve(12);
    out.push_back((perms & peelf::MemoryCellPermBits::kRead) != 0u ? 'r' : '-');
    out.push_back((perms & peelf::MemoryCellPermBits::kWrite) != 0u ? 'w' : '-');
    out.push_back((perms & peelf::MemoryCellPermBits::kExecute) != 0u ? 'x' : '-');
    out.push_back((perms & peelf::MemoryCellPermBits::kShared) != 0u ? 's' : 'p');
    if ((perms & peelf::MemoryCellPermBits::kGuard) != 0u) {
        out += " [GUARD]";
    }
    if ((perms & peelf::MemoryCellPermBits::kRwxHazard) != 0u) {
        out += " [W^X]";
    }
    return out;
}

[[nodiscard]] ImVec4 provenance_badge_color(
    peelf::ProvenanceTag tag,
    peelf::CaptureAvailability avail) noexcept {
    if (avail == peelf::CaptureAvailability::Unavailable) {
        return ImVec4{0.92f, 0.34f, 0.34f, 1.0f};
    }
    if (avail == peelf::CaptureAvailability::Partial ||
        avail == peelf::CaptureAvailability::Stale ||
        avail == peelf::CaptureAvailability::Redacted) {
        return ImVec4{0.95f, 0.74f, 0.25f, 1.0f};
    }
    switch (tag) {
        case peelf::ProvenanceTag::LiveMemory:    return ImVec4{0.32f, 0.86f, 0.56f, 1.0f};
        case peelf::ProvenanceTag::CrashDump:     return ImVec4{0.94f, 0.60f, 0.28f, 1.0f};
        case peelf::ProvenanceTag::DiskFile:      return ImVec4{0.44f, 0.72f, 0.96f, 1.0f};
        case peelf::ProvenanceTag::UserAnnotated: return ImVec4{0.28f, 0.88f, 0.90f, 1.0f};
        default:                                  return ImVec4{0.72f, 0.76f, 0.82f, 1.0f};
    }
}

} // namespace

MemoryHeatmapPanel::MemoryHeatmapPanel(BinaryModel& model,
                                       VulkanManager& vulkan,
                                       ViewerSelection& selection,
                                       NavigationRequestQueue& nav_queue,
                                       EntityContextActionCallback on_context_action)
    : UiPanel("Memory Heatmap")
    , model_(model)
    , vulkan_(vulkan)
    , selection_(selection)
    , nav_queue_(nav_queue)
    , on_context_action_(std::move(on_context_action)) {
    visible_ = false;
    camera_.min_scale = 0.25;
    camera_.max_scale = 256.0;
}

MemoryHeatmapPanel::~MemoryHeatmapPanel() {
    shutdown();
}

void MemoryHeatmapPanel::ensure_worker_started() {
    if (worker_thread_.joinable()) {
        return;
    }
    worker_thread_ = std::jthread([this](std::stop_token st) { worker_loop(std::move(st)); });
}

void MemoryHeatmapPanel::stop_worker() noexcept {
    if (worker_thread_.joinable()) {
        worker_thread_.request_stop();
        worker_cv_.notify_all();
        try {
            worker_thread_.join();
        } catch (...) {
            // Never propagate exceptions out of noexcept teardown.
        }
    }
    try {
        const std::scoped_lock lock(worker_mutex_);
        pending_job_.reset();
        completed_result_.reset();
        worker_busy_ = false;
    } catch (...) {
    }
}

void MemoryHeatmapPanel::cancel_and_reset() noexcept {
    stop_worker();
    try {
        const std::scoped_lock lock(worker_mutex_);
        ++worker_generation_;
    } catch (...) {
    }
    static_tracker_.reset();
    latest_observed_ = {};
    has_snapshot_ = false;
    hovered_cell_index_.reset();
    selected_cell_index_.reset();
    selected_cell_va_.reset();
    context_cell_index_.reset();
    watchpoint_status_note_.clear();
    focus_options_.clear();
    selected_focus_option_ = 0u;
    dirty_sample_ = true;
    pending_tracker_reset_ = true;
    needs_fit_view_ = true;
    last_fitted_grid_w_ = 0u;
    last_fitted_grid_h_ = 0u;
    needs_gpu_record_this_frame_ = false;
    last_was_live_ = false;
    last_was_crash_dump_ = false;
    last_pid_ = 0;
    last_static_image_ = nullptr;
    last_static_edit_revision_ = 0u;
    last_region_count_ = 0u;
}

void MemoryHeatmapPanel::shutdown() noexcept {
    cancel_and_reset();
    compute_pipeline_.shutdown();
    ssbo_ring_.shutdown();
    canvas_.shutdown();
    canvas_initialized_ = false;
    compute_pipeline_attempted_ = false;
}

void MemoryHeatmapPanel::worker_loop(std::stop_token stop_token) {
    peelf::MemoryHeatmapTracker tracker{};

    while (!stop_token.stop_requested()) {
        std::optional<AsyncSampleJob> job{};
        {
            std::unique_lock lock(worker_mutex_);
            worker_cv_.wait(lock, stop_token, [this] { return pending_job_.has_value(); });
            if (stop_token.stop_requested() || !pending_job_.has_value()) {
                break;
            }
            job = std::move(pending_job_);
            pending_job_.reset();
            worker_busy_ = true;
        }

        if (job->reset_tracker) {
            tracker.reset();
        }

        peelf::Observed<peelf::MemoryHeatmapSnapshot> sampled{};
        if (job->session != nullptr && !stop_token.stop_requested()) {
            try {
                if (auto* dump = dynamic_cast<peelf::ICrashDumpSession*>(job->session.get());
                    dump != nullptr) {
                    sampled = tracker.sample_crash_dump(*dump, job->config);
                } else {
                    sampled = tracker.sample_process(*job->session, job->config);
                }
            } catch (const std::exception& ex) {
                sampled.availability = peelf::CaptureAvailability::Unavailable;
                sampled.note = ex.what();
            } catch (...) {
                sampled.availability = peelf::CaptureAvailability::Unavailable;
                sampled.note = "Unknown exception while sampling process memory";
            }
        }

        {
            const std::scoped_lock lock(worker_mutex_);
            worker_busy_ = false;
            if (!stop_token.stop_requested() && job->generation == worker_generation_) {
                completed_result_ = AsyncSampleResult{
                    .observed = std::move(sampled),
                    .generation = job->generation,
                };
            }
        }
    }
}

void MemoryHeatmapPanel::rebuild_focus_options() {
    std::optional<std::uint64_t> prev_start{};
    if (selected_focus_option_ < focus_options_.size()) {
        prev_start = focus_options_[selected_focus_option_].start_va;
    }

    focus_options_.clear();

    if (selection_.virtual_address.has_value() && *selection_.virtual_address != 0u) {
        const std::uint64_t base = (*selection_.virtual_address) & ~std::uint64_t{0xFFFu};
        const std::uint64_t span = std::max<std::uint64_t>(selection_.size, 256ull * 1024ull);
        const std::uint64_t end_va =
            base <= (UINT64_MAX - span) ? (base + span) : UINT64_MAX;
        if (end_va > base) {
            focus_options_.push_back(FocusTargetOption{
                .label = std::format("Selection @ 0x{:X} ({})",
                                     base,
                                     format_byte_span_compact(end_va - base)),
                .start_va = base,
                .end_va = end_va,
            });
        }
    }

    if (model_.is_live_process()) {
        for (const auto& mod : model_.process_modules()) {
            if (mod.size == 0u || mod.end_address() <= mod.base_address) {
                continue;
            }
            const std::string clean_name = sanitize_single_line_control_chars(
                mod.name.empty() ? "<module>" : mod.name);
            focus_options_.push_back(FocusTargetOption{
                .label = std::format("Module: {} [0x{:X}..0x{:X}] ({})",
                                     clean_name,
                                     mod.base_address,
                                     mod.end_address(),
                                     format_byte_span_compact(mod.size)),
                .start_va = mod.base_address,
                .end_va = mod.end_address(),
            });
        }

        std::size_t added_regions = 0u;
        for (const auto& reg : model_.memory_regions()) {
            if (reg.end_address <= reg.start_address) {
                continue;
            }
            const bool interesting = reg.kind == peelf::MemoryRegionKind::Heap ||
                                     reg.kind == peelf::MemoryRegionKind::Stack ||
                                     (reg.protection.writable && reg.protection.executable) ||
                                     reg.protection.writable;
            if (!interesting) {
                continue;
            }
            std::string tag = std::string(peelf::to_string(reg.kind));
            if (!reg.pathname.empty()) {
                tag = sanitize_single_line_control_chars(reg.pathname);
            } else if (!reg.module_name.empty()) {
                tag = sanitize_single_line_control_chars(reg.module_name);
            }
            focus_options_.push_back(FocusTargetOption{
                .label = std::format("{} [0x{:X}..0x{:X}] ({})",
                                     tag,
                                     reg.start_address,
                                     reg.end_address,
                                     format_byte_span_compact(reg.size())),
                .start_va = reg.start_address,
                .end_va = reg.end_address,
            });
            if (++added_regions >= 48u) {
                break;
            }
        }
    } else if (const peelf::IBinaryImage* img = model_.image(); img != nullptr) {
        for (const auto& sec : img->sections()) {
            const std::uint64_t sz = std::max(sec.virtual_size, sec.file_size);
            if (sz == 0u || sec.virtual_address > (UINT64_MAX - sz)) {
                continue;
            }
            const std::string clean_sec = sanitize_single_line_control_chars(
                sec.name.empty() ? "<section>" : sec.name);
            focus_options_.push_back(FocusTargetOption{
                .label = std::format("Section {} [0x{:X}] ({})",
                                     clean_sec,
                                     sec.virtual_address,
                                     format_byte_span_compact(sz)),
                .start_va = sec.virtual_address,
                .end_va = sec.virtual_address + sz,
            });
        }
    }

    selected_focus_option_ = 0u;
    if (prev_start.has_value()) {
        for (std::size_t i = 0u; i < focus_options_.size(); ++i) {
            if (focus_options_[i].start_va == *prev_start) {
                selected_focus_option_ = i;
                break;
            }
        }
    }
}

peelf::MemoryHeatmapConfig MemoryHeatmapPanel::build_active_config() const {
    peelf::MemoryHeatmapConfig cfg{};
    cfg.layout = layout_mode_;
    cfg.scope = scope_mode_;
    cfg.base_page_bytes = 4096u;
    cfg.max_cells = scope_mode_ == peelf::MemoryHeatmapScope::FocusedRange
                        ? kDefaultMaxCellsFocused
                        : kDefaultMaxCellsCompact;
    cfg.read_budget_bytes_per_tick = model_.is_live_process()
                                         ? kLiveReadBudgetBytesPerTick
                                         : kStaticReadBudgetBytesPerTick;
    cfg.heat_decay_factor = std::clamp(heat_decay_, 0.25f, 0.98f);
    cfg.query_os_pagemap = true;

    if (scope_mode_ == peelf::MemoryHeatmapScope::FocusedRange &&
        selected_focus_option_ < focus_options_.size()) {
        cfg.focus_start_va = focus_options_[selected_focus_option_].start_va;
        cfg.focus_end_va = focus_options_[selected_focus_option_].end_va;
    }
    return cfg;
}

void MemoryHeatmapPanel::sample_static_target_now(bool reset_history) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        latest_observed_ = {};
        has_snapshot_ = false;
        return;
    }
    if (reset_history) {
        static_tracker_.reset();
    }
    latest_observed_ =
        static_tracker_.sample_static_image(*img, model_.editable_image(), build_active_config());
    has_snapshot_ = (latest_observed_.availability != peelf::CaptureAvailability::Unavailable) &&
                    latest_observed_.value.has_value() && !latest_observed_.value->cells.empty();
    last_static_edit_revision_ = model_.edit_revision();
    dirty_sample_ = false;
    pending_tracker_reset_ = false;
    if (selected_cell_va_.has_value() && latest_observed_.value.has_value()) {
        if (const auto idx = latest_observed_.value->find_cell_index_for_va(*selected_cell_va_)) {
            selected_cell_index_ = static_cast<std::uint32_t>(*idx);
        } else {
            selected_cell_index_.reset();
        }
    }
}

void MemoryHeatmapPanel::request_immediate_sample(bool reset_history) {
    dirty_sample_ = true;
    if (reset_history) {
        pending_tracker_reset_ = true;
    }
    last_sample_request_time_ = {};
}

void MemoryHeatmapPanel::sync_target_and_schedule_sampling() {
    const bool is_live = model_.is_live_process();
    const bool is_dump = model_.is_crash_dump();
    const peelf::ProcessId cur_pid =
        (is_live && model_.process_session() != nullptr) ? model_.process_session()->pid() : 0;
    const peelf::IBinaryImage* cur_img = is_live ? nullptr : model_.image();
    const std::size_t cur_regions =
        is_live ? model_.memory_regions().size() : (cur_img != nullptr ? cur_img->sections().size() : 0u);

    if (is_live != last_was_live_ || is_dump != last_was_crash_dump_ || cur_pid != last_pid_ ||
        cur_img != last_static_image_) {
        last_was_live_ = is_live;
        last_was_crash_dump_ = is_dump;
        last_pid_ = cur_pid;
        last_static_image_ = cur_img;
        last_region_count_ = cur_regions;
        rebuild_focus_options();
        dirty_sample_ = true;
        pending_tracker_reset_ = true;
        needs_fit_view_ = true;
        hovered_cell_index_.reset();
        selected_cell_index_.reset();
    } else if (cur_regions != last_region_count_) {
        last_region_count_ = cur_regions;
        rebuild_focus_options();
    }

    if (!is_live) {
        if (cur_img == nullptr) {
            has_snapshot_ = false;
            return;
        }
        if (dirty_sample_ || last_static_edit_revision_ != model_.edit_revision()) {
            sample_static_target_now(pending_tracker_reset_);
        }
        return;
    }

    // Harvest any completed async snapshot from the background worker.
    {
        std::optional<AsyncSampleResult> finished{};
        {
            const std::scoped_lock lock(worker_mutex_);
            if (completed_result_.has_value() &&
                completed_result_->generation == worker_generation_) {
                finished = std::move(completed_result_);
                completed_result_.reset();
            }
        }
        if (finished.has_value()) {
            latest_observed_ = std::move(finished->observed);
            has_snapshot_ =
                (latest_observed_.availability != peelf::CaptureAvailability::Unavailable) &&
                latest_observed_.value.has_value() && !latest_observed_.value->cells.empty();
            if (selected_cell_va_.has_value() && latest_observed_.value.has_value()) {
                if (const auto idx =
                        latest_observed_.value->find_cell_index_for_va(*selected_cell_va_)) {
                    selected_cell_index_ = static_cast<std::uint32_t>(*idx);
                } else {
                    selected_cell_index_.reset();
                }
            }
        }
    }

    const auto session = model_.shared_process_session();
    if (session == nullptr) {
        has_snapshot_ = false;
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto interval = cadence_interval(poll_cadence_);
    const bool timer_due = live_watch_enabled_ && !is_dump &&
                           poll_cadence_ != HeatmapPollCadence::ManualSnapshot &&
                           interval.count() > 0 &&
                           (now - last_sample_request_time_ >= interval);

    if (!dirty_sample_ && !timer_due) {
        return;
    }

    ensure_worker_started();
    {
        const std::scoped_lock lock(worker_mutex_);
        if (worker_busy_ && !dirty_sample_) {
            // Skip overlapping periodic tick if the previous read_memory slice is still running.
            return;
        }
        const bool reset_now = pending_tracker_reset_;
        pending_tracker_reset_ = false;
        dirty_sample_ = false;
        last_sample_request_time_ = now;
        pending_job_ = AsyncSampleJob{
            .session = session,
            .config = build_active_config(),
            .generation = worker_generation_,
            .reset_tracker = reset_now,
        };
    }
    worker_cv_.notify_one();
}

void MemoryHeatmapPanel::fit_camera_to_grid(double canvas_w, double canvas_h) noexcept {
    if (!latest_observed_.value.has_value()) {
        return;
    }
    const auto gw = static_cast<double>(std::max(1u, latest_observed_.value->grid_width));
    const auto gh = static_cast<double>(std::max(1u, latest_observed_.value->grid_height));
    const double pad_x = gw * 0.03;
    const double pad_y = gh * 0.03;
    camera_.fit_bounds(-pad_x,
                       -pad_y,
                       gw + pad_x,
                       gh + pad_y,
                       std::max(canvas_w, 32.0),
                       std::max(canvas_h, 32.0),
                       true);
    needs_fit_view_ = false;
    last_fitted_grid_w_ = latest_observed_.value->grid_width;
    last_fitted_grid_h_ = latest_observed_.value->grid_height;
}

InspectableEntity MemoryHeatmapPanel::build_cell_entity(
    const peelf::MemoryHeatmapCell& cell) const {
    const peelf::HeatmapRegionDescriptor* reg =
        latest_observed_.value.has_value()
            ? latest_observed_.value->find_region_for_va(cell.base_va)
            : nullptr;

    std::string label = std::format(
        "{} @ 0x{:X}", peelf::to_string(cell.category()), cell.base_va);
    std::string mod_name{};
    if (reg != nullptr) {
        mod_name = sanitize_single_line_control_chars(reg->module_name);
        if (!reg->label.empty()) {
            label = std::format("{} ({})",
                                sanitize_single_line_control_chars(reg->label),
                                peelf::to_string(cell.category()));
        }
    }

    InspectableEntity entity{};
    entity.va = cell.base_va;
    entity.file_offset = model_.virtual_address_to_offset(cell.base_va);
    entity.size = std::max<std::uint64_t>(cell.span_bytes(), 1u);
    entity.symbol_or_label = std::move(label);
    entity.module_name = std::move(mod_name);
    entity.extra_json_fields = {
        {"category", std::string(peelf::to_string(cell.category()))},
        {"residency", std::string(peelf::to_string(cell.residency()))},
        {"permissions", format_perm_bits(cell.perms())},
        {"heat_u8", std::to_string(cell.heat_u8())},
        {"mutations_u8", std::to_string(cell.mutation_count_u8())},
        {"entropy_bits_per_byte",
         std::format("{:.2f}", (static_cast<double>(cell.entropy_u8()) / 255.0) * 8.0)},
        {"provenance", std::string(peelf::to_string(latest_observed_.provenance))},
    };
    return entity;
}

void MemoryHeatmapPanel::render_toolbar() {
    // Layout selector
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Layout");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10.5f);
    if (ImGui::BeginCombo("##HeatmapLayout", layout_ui_label(layout_mode_))) {
        for (const auto candidate : {peelf::MemoryHeatmapLayout::HilbertCurve,
                                     peelf::MemoryHeatmapLayout::LinearRows}) {
            const bool selected = (layout_mode_ == candidate);
            if (ImGui::Selectable(layout_ui_label(candidate), selected)) {
                layout_mode_ = candidate;
                needs_fit_view_ = true;
                request_immediate_sample(false);
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    // Scope selector
    ImGui::SameLine();
    ImGui::TextDisabled("Scope");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14.5f);
    if (ImGui::BeginCombo("##HeatmapScope", scope_ui_label(scope_mode_))) {
        for (const auto candidate : {peelf::MemoryHeatmapScope::CompactAddressSpace,
                                     peelf::MemoryHeatmapScope::FocusedRange}) {
            const bool selected = (scope_mode_ == candidate);
            if (ImGui::Selectable(scope_ui_label(candidate), selected)) {
                scope_mode_ = candidate;
                rebuild_focus_options();
                needs_fit_view_ = true;
                request_immediate_sample(false);
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    // Color mode selector
    ImGui::SameLine();
    ImGui::TextDisabled("Color");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 13.5f);
    if (ImGui::BeginCombo("##HeatmapColorMode", color_mode_ui_label(color_mode_))) {
        for (const auto candidate :
             {peelf::MemoryHeatmapColorMode::AllocatorAndWriteHeat,
              peelf::MemoryHeatmapColorMode::CategoryAndResidency,
              peelf::MemoryHeatmapColorMode::PermissionsAndRwx,
              peelf::MemoryHeatmapColorMode::PageEntropy}) {
            const bool selected = (color_mode_ == candidate);
            if (ImGui::Selectable(color_mode_ui_label(candidate), selected)) {
                color_mode_ = candidate;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    if (ImGui::Button("Fit View")) {
        needs_fit_view_ = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Grid", &show_cell_grid_);

    // Second row: Focus target (when FocusedRange) + Live Watch / Poll cadence / Decay / Snapshot
    if (scope_mode_ == peelf::MemoryHeatmapScope::FocusedRange) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("Target");
        ImGui::SameLine();
        if (ImGui::SmallButton("Refresh Ranges")) {
            rebuild_focus_options();
            request_immediate_sample(false);
        }
        ImGui::SameLine();
        const char* preview =
            (selected_focus_option_ < focus_options_.size())
                ? focus_options_[selected_focus_option_].label.c_str()
                : "<no focusable region>";
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 24.0f);
        if (ImGui::BeginCombo("##HeatmapFocusTarget", preview)) {
            for (std::size_t i = 0u; i < focus_options_.size(); ++i) {
                const bool selected = (selected_focus_option_ == i);
                ImGui::PushID(static_cast<int>(i));
                if (ImGui::Selectable(focus_options_[i].label.c_str(), selected)) {
                    selected_focus_option_ = i;
                    needs_fit_view_ = true;
                    request_immediate_sample(false);
                }
                if (selected) {
                    ImGui::SetItemDefaultFocus();
                }
                ImGui::PopID();
            }
            ImGui::EndCombo();
        }
        ImGui::SameLine();
    } else {
        ImGui::AlignTextToFramePadding();
    }

    const bool can_live_poll = model_.is_live_process() && !model_.is_crash_dump();
    ImGui::BeginDisabled(!can_live_poll);
    if (ImGui::Checkbox("Live Watch", &live_watch_enabled_) && live_watch_enabled_) {
        request_immediate_sample(false);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9.5f);
    if (ImGui::BeginCombo("##HeatmapPollRate", cadence_label(poll_cadence_))) {
        for (const auto c : {HeatmapPollCadence::Hz10,
                             HeatmapPollCadence::Hz4,
                             HeatmapPollCadence::Hz1,
                             HeatmapPollCadence::ManualSnapshot}) {
            const bool selected = (poll_cadence_ == c);
            if (ImGui::Selectable(cadence_label(c), selected)) {
                poll_cadence_ = c;
                if (c != HeatmapPollCadence::ManualSnapshot) {
                    request_immediate_sample(false);
                }
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 6.5f);
    ImGui::SliderFloat("Decay", &heat_decay_, 0.50f, 0.97f, "%.2f");
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Snapshot")) {
        request_immediate_sample(false);
    }
}

void MemoryHeatmapPanel::render_summary_strip() const {
    if (!latest_observed_.value.has_value()) {
        return;
    }
    const auto& snap = *latest_observed_.value;
    const auto& st = snap.stats;

    const bool gpu_compute_active = canvas_initialized_ && canvas_.can_use_compute() &&
                                    compute_pipeline_.valid();
    ImGui::TextColored(gpu_compute_active ? ImVec4{0.34f, 0.85f, 0.96f, 1.0f}
                                          : ImVec4{0.82f, 0.78f, 0.45f, 1.0f},
                       "[%s]",
                       gpu_compute_active ? "Vulkan Compute" : "CPU Raster Fallback");

    ImGui::SameLine();
    const ImVec4 prov_col =
        provenance_badge_color(latest_observed_.provenance, latest_observed_.availability);
    const std::string prov_text = std::format(
        "[{}:{}]",
        peelf::to_string(latest_observed_.provenance),
        peelf::to_string(latest_observed_.availability));
    ImGui::TextColored(prov_col, "%s", prov_text.c_str());
    if (ImGui::IsItemHovered() &&
        (!latest_observed_.note.empty() || !st.pagemap_diagnostic.empty())) {
        ImGui::BeginTooltip();
        if (!latest_observed_.note.empty()) {
            ImGui::TextUnformatted(latest_observed_.note.c_str());
        }
        if (!st.pagemap_diagnostic.empty()) {
            ImGui::TextDisabled("OS Pagemap: %s", st.pagemap_diagnostic.c_str());
        }
        ImGui::EndTooltip();
    }

    ImGui::SameLine();
    if (snap.layout == peelf::MemoryHeatmapLayout::HilbertCurve) {
        ImGui::TextDisabled("Order %u (%ux%u) | %zu cells @ %s | Tick #%llu",
                            snap.hilbert_order,
                            snap.grid_width,
                            snap.grid_height,
                            st.active_cell_count,
                            format_byte_span_compact(snap.nominal_cell_bytes).c_str(),
                            static_cast<unsigned long long>(st.tick_sequence));
    } else {
        ImGui::TextDisabled("Tile %ux%u | %zu cells @ %s | Tick #%llu",
                            snap.grid_width,
                            snap.grid_height,
                            st.active_cell_count,
                            format_byte_span_compact(snap.nominal_cell_bytes).c_str(),
                            static_cast<unsigned long long>(st.tick_sequence));
    }

    ImGui::SameLine();
    ImGui::Text("Resident: %zu", st.resident_cell_count);
    if (st.dirty_or_mutated_cell_count > 0u) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4{1.0f, 0.62f, 0.18f, 1.0f},
                           "| Hot/Dirty: %zu",
                           st.dirty_or_mutated_cell_count);
    }
    if (st.rwx_hazard_cell_count > 0u) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4{1.0f, 0.25f, 0.68f, 1.0f},
                           "| W^X: %zu",
                           st.rwx_hazard_cell_count);
    }
    if (st.perm_transition_cell_count > 0u) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4{1.0f, 0.36f, 0.86f, 1.0f},
                           "| RW->RX Flips: %zu",
                           st.perm_transition_cell_count);
    }
    if (!watchpoint_status_note_.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", watchpoint_status_note_.c_str());
    }
}

void MemoryHeatmapPanel::render_hover_tooltip(std::size_t cell_index) const {
    if (!latest_observed_.value.has_value()) {
        return;
    }
    const auto& snap = *latest_observed_.value;
    if (cell_index >= snap.cells.size()) {
        return;
    }
    const peelf::MemoryHeatmapCell& cell = snap.cells[cell_index];
    const peelf::HeatmapRegionDescriptor* reg = snap.find_region_for_va(cell.base_va);
    const std::uint64_t span = cell.span_bytes();
    const std::uint64_t end_va =
        cell.base_va <= (UINT64_MAX - span) ? (cell.base_va + span) : UINT64_MAX;
    const double entropy_bits = (static_cast<double>(cell.entropy_u8()) / 255.0) * 8.0;

    ImGui::BeginTooltip();
    ImGui::Text("VA 0x%llX .. 0x%llX (%s)",
                static_cast<unsigned long long>(cell.base_va),
                static_cast<unsigned long long>(end_va),
                format_byte_span_compact(span).c_str());

    if (reg != nullptr) {
        const std::string clean_label = sanitize_single_line_control_chars(reg->label);
        const std::string clean_mod = sanitize_single_line_control_chars(reg->module_name);
        if (!clean_mod.empty() && clean_mod != clean_label) {
            ImGui::TextDisabled("Region: %s  |  Module: %s",
                                clean_label.empty() ? "<unnamed>" : clean_label.c_str(),
                                clean_mod.c_str());
        } else {
            ImGui::TextDisabled("Region: %s",
                                clean_label.empty() ? "<unnamed>" : clean_label.c_str());
        }
    } else {
        ImGui::TextDisabled("Region: <unmapped gap>");
    }

    ImGui::Separator();
    const auto cat_sv = peelf::to_string(cell.category());
    const auto res_sv = peelf::to_string(cell.residency());
    const std::string perms_str = format_perm_bits(cell.perms());
    ImGui::Text("Category: %.*s   |   Perms: %s",
                static_cast<int>(cat_sv.size()),
                cat_sv.data(),
                perms_str.c_str());
    ImGui::Text("Residency: %.*s   |   Cell #%zu",
                static_cast<int>(res_sv.size()),
                res_sv.data(),
                cell_index);
    ImGui::Text("Write Heat: %u / 255   |   Mutations: %u%s",
                static_cast<unsigned>(cell.heat_u8()),
                static_cast<unsigned>(cell.mutation_count_u8()),
                cell.mutation_count_u8() == 255u ? "+" : "");
    ImGui::Text("Page Entropy: %.2f / 8.00 bits/byte (%u / 255)",
                entropy_bits,
                static_cast<unsigned>(cell.entropy_u8()));

    if (cell.has_perm_transition()) {
        ImGui::TextColored(ImVec4{1.0f, 0.30f, 0.82f, 1.0f},
                           "Protection transition detected across ticks (e.g. RW -> RX JIT)");
    }
    if (cell.is_newly_allocated()) {
        ImGui::TextColored(ImVec4{0.35f, 0.95f, 0.55f, 1.0f},
                           "Newly allocated mapping in latest tick");
    }
    if (cell.category() == peelf::MemoryCellCategory::PatchDirty) {
        ImGui::TextColored(ImVec4{0.25f, 0.92f, 0.95f, 1.0f},
                           "Contains staged PagedBinaryImage byte patch(es)");
    }
    if (cell.has_hot_focus()) {
        ImGui::TextColored(ImVec4{0.96f, 0.88f, 0.32f, 1.0f},
                           "Active instruction / stack / entry-point page");
    }

    const ImVec4 prov_col =
        provenance_badge_color(latest_observed_.provenance, latest_observed_.availability);
    const auto prov_sv = peelf::to_string(latest_observed_.provenance);
    const auto avail_sv = peelf::to_string(latest_observed_.availability);
    ImGui::Separator();
    ImGui::TextColored(prov_col,
                       "Provenance: %.*s (%.*s)",
                       static_cast<int>(prov_sv.size()),
                       prov_sv.data(),
                       static_cast<int>(avail_sv.size()),
                       avail_sv.data());
    if (!snap.stats.pagemap_diagnostic.empty() && !snap.stats.pagemap_available &&
        model_.is_live_process() && !model_.is_crash_dump()) {
        ImGui::TextDisabled("%s", snap.stats.pagemap_diagnostic.c_str());
    }
    ImGui::TextDisabled("Click: Navigate  |  Wheel: Zoom  |  Middle/Right-Drag: Pan  |  Right-Click: Actions");
    ImGui::EndTooltip();
}

void MemoryHeatmapPanel::render_cell_context_popup(
    std::optional<PendingEntityContextAction>& out_pending_ctx) {
    if (!ImGui::BeginPopup("##MemoryHeatmapCellCtx")) {
        return;
    }
    if (!context_cell_index_.has_value() || !latest_observed_.value.has_value()) {
        ImGui::EndPopup();
        return;
    }

    (void)draw_inspectable_entity_context_menu_items(context_entity_, model_, out_pending_ctx);

    ImGui::Separator();
    const peelf::HeatmapRegionDescriptor* reg =
        latest_observed_.value->find_region_for_va(context_cell_.base_va);
    if (reg != nullptr && reg->end_va > reg->start_va) {
        if (ImGui::MenuItem("Focus Heatmap on This Region")) {
            rebuild_focus_options();
            std::optional<std::size_t> match_idx{};
            for (std::size_t i = 0u; i < focus_options_.size(); ++i) {
                if (focus_options_[i].start_va == reg->start_va &&
                    focus_options_[i].end_va == reg->end_va) {
                    match_idx = i;
                    break;
                }
            }
            if (!match_idx.has_value()) {
                focus_options_.push_back(FocusTargetOption{
                    .label = std::format("{} [0x{:X}..0x{:X}] ({})",
                                         sanitize_single_line_control_chars(
                                             reg->label.empty() ? "Region" : reg->label),
                                         reg->start_va,
                                         reg->end_va,
                                         format_byte_span_compact(reg->end_va - reg->start_va)),
                    .start_va = reg->start_va,
                    .end_va = reg->end_va,
                });
                match_idx = focus_options_.size() - 1u;
            }
            selected_focus_option_ = *match_idx;
            scope_mode_ = peelf::MemoryHeatmapScope::FocusedRange;
            needs_fit_view_ = true;
            request_immediate_sample(false);
        }
    }
    if (scope_mode_ == peelf::MemoryHeatmapScope::FocusedRange) {
        if (ImGui::MenuItem("Reset Scope to Compact Mapped Space")) {
            scope_mode_ = peelf::MemoryHeatmapScope::CompactAddressSpace;
            needs_fit_view_ = true;
            request_immediate_sample(false);
        }
    }

    // Hardware watchpoint integration when IDebugSession + HardwareWatchpoints capability are ready.
    ImGui::Separator();
    const peelf::Capability& wp_cap =
        model_.capability_matrix().get(peelf::Operation::HardwareWatchpoints);
    auto* dbg = model_.debug_session();
    const bool dbg_paused =
        dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Paused;
    const bool can_set_watchpoint = dbg_paused && wp_cap.can_execute();

    std::string wp_disabled_reason{};
    if (!can_set_watchpoint) {
        if (dbg == nullptr) {
            wp_disabled_reason =
                "Attach an opt-in Debugger session (Inspect > Start / Attach Debugger) to arm hardware watchpoints.";
        } else if (!dbg_paused) {
            wp_disabled_reason = "Pause the debuggee before arming hardware watchpoints.";
        } else if (!wp_cap.reason.empty()) {
            wp_disabled_reason = wp_cap.reason;
        } else {
            wp_disabled_reason = "Hardware watchpoints are unavailable for this target.";
        }
    }

    if (!can_set_watchpoint) {
        ImGui::BeginDisabled(true);
    }
    if (ImGui::BeginMenu("Set Hardware Watchpoint")) {
        struct WatchSpec {
            const char* label;
            peelf::debugger::BreakpointKind kind;
            std::uint8_t byte_size;
        };
        constexpr std::array<WatchSpec, 5> kSpecs{{
            {"Write Watchpoint (4 bytes)", peelf::debugger::BreakpointKind::HardwareWrite, 4u},
            {"Read/Write Watchpoint (4 bytes)",
             peelf::debugger::BreakpointKind::HardwareReadWrite,
             4u},
            {"Write Watchpoint (8 bytes)", peelf::debugger::BreakpointKind::HardwareWrite, 8u},
            {"Read/Write Watchpoint (8 bytes)",
             peelf::debugger::BreakpointKind::HardwareReadWrite,
             8u},
            {"Execute Breakpoint (1 byte)", peelf::debugger::BreakpointKind::HardwareExecute, 1u},
        }};
        for (const WatchSpec& spec : kSpecs) {
            if (ImGui::MenuItem(spec.label) && dbg != nullptr) {
                const std::uint64_t aligned_va =
                    spec.byte_size > 1u
                        ? (context_cell_.base_va & ~(static_cast<std::uint64_t>(spec.byte_size) - 1u))
                        : context_cell_.base_va;
                auto res = dbg->add_hardware_breakpoint(
                    aligned_va,
                    spec.kind,
                    spec.byte_size,
                    std::format("Heatmap watch @ 0x{:X}", aligned_va));
                model_.refresh_debug_breakpoints();
                if (res.has_value()) {
                    watchpoint_status_note_ =
                        std::format("Armed HW watchpoint #{} @ 0x{:X}", res.value->id, aligned_va);
                    Log().info("{}", watchpoint_status_note_);
                } else {
                    const std::string diag = !res.status.detail.empty()
                                                 ? res.status.detail
                                                 : "Failed to arm hardware watchpoint";
                    watchpoint_status_note_ = diag;
                    Log().warn("Hardware watchpoint @ 0x{:X}: {}", aligned_va, diag);
                }
            }
        }
        ImGui::EndMenu();
    }
    if (!can_set_watchpoint) {
        ImGui::EndDisabled();
        if (!wp_disabled_reason.empty() &&
            ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("%s", wp_disabled_reason.c_str());
        }
    }

    ImGui::EndPopup();
}

void MemoryHeatmapPanel::render_canvas_and_interactions() {
    if (!has_snapshot_ || !latest_observed_.value.has_value() ||
        latest_observed_.value->cells.empty()) {
        ImGui::Spacing();
        if (!model_.has_file() && !model_.is_live_process()) {
            ImGui::TextDisabled(
                "Open a PE/ELF/Mach-O binary, crash dump, or attach to a live process to view its 2D Hilbert memory heatmap.");
        } else if (model_.is_live_process()) {
            ImGui::TextDisabled("Sampling process virtual address space...");
        } else {
            ImGui::TextDisabled("No mapped pages available for the selected scope.");
        }
        return;
    }

    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float canvas_w_f = std::max(avail.x, 64.0f);
    const float canvas_h_f = std::max(avail.y, kMinCanvasHeightPx);
    const auto req_w = static_cast<std::uint32_t>(std::lround(canvas_w_f));
    const auto req_h = static_cast<std::uint32_t>(std::lround(canvas_h_f));

    if (vulkan_.device() == VK_NULL_HANDLE) {
        ImGui::TextDisabled("Vulkan device unavailable.");
        return;
    }

    if (!canvas_initialized_) {
        canvas_.init(vulkan_,
                     GpuOffscreenCanvasConfig{
                         .sampler_filter = VK_FILTER_NEAREST,
                         .resize_debounce_frames = 2u,
                     });
        ssbo_ring_.attach(vulkan_);
        canvas_initialized_ = true;
    }

    (void)canvas_.ensure_size(req_w, req_h);
    if (!canvas_.valid()) {
        ImGui::TextDisabled("Initializing GPU heatmap surface...");
        return;
    }

    const auto disp_w = static_cast<double>(canvas_.width());
    const auto disp_h = static_cast<double>(canvas_.height());
    const auto& snap = *latest_observed_.value;

    if (needs_fit_view_ || last_fitted_grid_w_ != snap.grid_width ||
        last_fitted_grid_h_ != snap.grid_height) {
        fit_camera_to_grid(disp_w, disp_h);
    }

    const ImVec2 canvas_origin = ImGui::GetCursorScreenPos();
    const ImVec2 canvas_size{static_cast<float>(canvas_.width()),
                             static_cast<float>(canvas_.height())};
    const std::size_t frame_idx = vulkan_.current_frame_index();

    ImGui::Image(canvas_.imgui_texture_id(frame_idx), canvas_size);

    // Overlay an InvisibleButton on the exact image rect to capture smooth zoom/pan/click/right-click.
    ImGui::SetCursorScreenPos(canvas_origin);
    ImGui::InvisibleButton(
        "##MemoryHeatmapCanvasHitBox",
        canvas_size,
        ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight |
            ImGuiButtonFlags_MouseButtonMiddle);

    const bool hovered = ImGui::IsItemHovered();
    const ImGuiIO& io = ImGui::GetIO();
    const double local_mx = static_cast<double>(io.MousePos.x - canvas_origin.x);
    const double local_my = static_cast<double>(io.MousePos.y - canvas_origin.y);

    if (hovered && std::abs(io.MouseWheel) > 1e-4f) {
        const double factor = std::pow(kZoomWheelBase, static_cast<double>(io.MouseWheel));
        camera_.zoom_at_screen_pixel(local_mx, local_my, factor, disp_w, disp_h);
    }

    const bool panning_middle =
        ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f);
    const bool panning_right =
        ImGui::IsItemActive() &&
        ImGui::IsMouseDragging(ImGuiMouseButton_Right, kRightClickDragSlopPx);
    const bool panning_shift_left =
        ImGui::IsItemActive() && io.KeyShift && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f);
    if (panning_middle || panning_right || panning_shift_left) {
        camera_.pan_by_pixels(static_cast<double>(io.MouseDelta.x),
                              static_cast<double>(io.MouseDelta.y));
    }

    hovered_cell_index_.reset();
    if (hovered) {
        const Vec2d world_pt = camera_.screen_to_world(local_mx, local_my, disp_w, disp_h);
        if (world_pt.x >= 0.0 && world_pt.y >= 0.0 &&
            world_pt.x < static_cast<double>(snap.grid_width) &&
            world_pt.y < static_cast<double>(snap.grid_height)) {
            const auto cx = static_cast<std::uint32_t>(std::floor(world_pt.x));
            const auto cy = static_cast<std::uint32_t>(std::floor(world_pt.y));
            const std::uint64_t idx = peelf::grid_xy_to_cell_index(
                snap.layout, snap.hilbert_order, snap.grid_width, cx, cy);
            if (idx < snap.cells.size()) {
                hovered_cell_index_ = static_cast<std::uint32_t>(idx);
            }
        }
    }

    // Left-click selects VA and dispatches navigation via NavigationRequestQueue.
    const ImVec2 left_drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left);
    if (hovered && !io.KeyShift && ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
        left_drag.x == 0.0f && left_drag.y == 0.0f) {
        if (hovered_cell_index_.has_value() && *hovered_cell_index_ < snap.cells.size()) {
            const peelf::MemoryHeatmapCell& cell = snap.cells[*hovered_cell_index_];
            selected_cell_index_ = *hovered_cell_index_;
            selected_cell_va_ = cell.base_va;
            if (cell.category() != peelf::MemoryCellCategory::Unmapped) {
                const bool is_exec =
                    (cell.perms() & peelf::MemoryCellPermBits::kExecute) != 0u;
                const PreferredView target_view =
                    is_exec ? PreferredView::Disassembly : PreferredView::Hex;
                nav_queue_.enqueue_address(
                    cell.base_va,
                    target_view,
                    static_cast<std::size_t>(
                        std::min<std::uint64_t>(std::max<std::uint32_t>(cell.span_bytes(), 1u), 64u)),
                    false);
            }
        }
    }

    // Right-click (without drag-panning) opens universal entity context menu + watchpoint submenu.
    const ImVec2 right_drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Right, kRightClickDragSlopPx);
    if (hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right) &&
        right_drag.x == 0.0f && right_drag.y == 0.0f) {
        if (hovered_cell_index_.has_value() && *hovered_cell_index_ < snap.cells.size()) {
            const peelf::MemoryHeatmapCell& cell = snap.cells[*hovered_cell_index_];
            if (cell.category() != peelf::MemoryCellCategory::Unmapped) {
                context_cell_index_ = *hovered_cell_index_;
                context_cell_ = cell;
                context_entity_ = build_cell_entity(cell);
                selected_cell_index_ = *hovered_cell_index_;
                selected_cell_va_ = cell.base_va;
                ImGui::OpenPopup("##MemoryHeatmapCellCtx");
            }
        }
    }

    std::optional<PendingEntityContextAction> pending_ctx{};
    render_cell_context_popup(pending_ctx);
    if (pending_ctx.has_value() && on_context_action_) {
        on_context_action_(pending_ctx->kind, pending_ctx->entity);
    }

    if (hovered && hovered_cell_index_.has_value() &&
        !ImGui::IsPopupOpen("##MemoryHeatmapCellCtx")) {
        render_hover_tooltip(*hovered_cell_index_);
    }

    // Arm pre-pass GPU compute / CPU fallback recording for this frame.
    const auto pulse = static_cast<float>(
        0.5 + 0.5 * std::sin(ImGui::GetTime() * 4.5));
    pending_push_constants_ = shaders::MemoryHeatmapPushConstants{
        .camera = camera_.build_gpu_uniform(disp_w, disp_h),
        .canvas_width = canvas_.width(),
        .canvas_height = canvas_.height(),
        .grid_width = std::max(1u, snap.grid_width),
        .grid_height = std::max(1u, snap.grid_height),
        .hilbert_order = std::max(1u, snap.hilbert_order),
        .active_cell_count = static_cast<std::uint32_t>(snap.cells.size()),
        .layout_mode = static_cast<std::uint32_t>(snap.layout),
        .color_mode = static_cast<std::uint32_t>(color_mode_),
        .hovered_cell = hovered_cell_index_.value_or(kInvalidCellIndex),
        .selected_cell = selected_cell_index_.value_or(kInvalidCellIndex),
        .pulse_phase = pulse,
        .flags = show_cell_grid_ ? 1u : 0u,
    };
    needs_gpu_record_this_frame_ = true;
}

void MemoryHeatmapPanel::draw_contents() {
    sync_target_and_schedule_sampling();
    render_toolbar();
    if (has_snapshot_) {
        render_summary_strip();
    }
    ImGui::Separator();
    render_canvas_and_interactions();
}

void MemoryHeatmapPanel::record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index) {
    if (!needs_gpu_record_this_frame_) {
        return;
    }
    needs_gpu_record_this_frame_ = false;

    if (!canvas_initialized_ || !canvas_.valid() || !has_snapshot_ ||
        !latest_observed_.value.has_value()) {
        return;
    }

    const auto& snap = *latest_observed_.value;

    if (canvas_.can_use_compute()) {
        if (!compute_pipeline_.valid() && !compute_pipeline_attempted_) {
            compute_pipeline_attempted_ = true;
            try {
                compute_pipeline_.init(
                    vulkan_,
                    shaders::kMemoryHeatmapCompSpirv,
                    static_cast<std::uint32_t>(sizeof(shaders::MemoryHeatmapPushConstants)),
                    true);
            } catch (const std::exception& ex) {
                Log().warn(
                    "MemoryHeatmap Vulkan compute pipeline init failed, falling back to CPU rasterizer: {}",
                    ex.what());
            }
        }

        if (compute_pipeline_.valid()) {
            static constexpr std::array<peelf::MemoryHeatmapCell, 1> kDummyCell{{}};
            const std::span<const peelf::MemoryHeatmapCell> cell_span =
                snap.cells.empty() ? std::span<const peelf::MemoryHeatmapCell>{kDummyCell}
                                   : std::span<const peelf::MemoryHeatmapCell>{snap.cells};
            ssbo_ring_.upload(frame_index, cell_span);
            const VkDescriptorBufferInfo ssbo_info = ssbo_ring_.descriptor_info(frame_index);
            canvas_.record_compute_dispatch(
                cmd,
                frame_index,
                compute_pipeline_,
                &ssbo_info,
                std::as_bytes(std::span{&pending_push_constants_, 1}));
            return;
        }
    }

    // Automatic CPU RGBA8 reference rasterizer fallback for minimal Vulkan drivers.
    const peelf::MemoryHeatmapViewport vp{
        .center_x = camera_.center_x,
        .center_y = camera_.center_y,
        .scale_x = camera_.scale_x,
        .scale_y = camera_.scale_y,
        .width_px = canvas_.width(),
        .height_px = canvas_.height(),
        .hovered_cell_index = hovered_cell_index_,
        .selected_cell_index = selected_cell_index_,
    };
    peelf::rasterize_memory_heatmap_rgba8_into(vp, snap, color_mode_, cpu_rgba_scratch_);
    canvas_.record_cpu_rgba8_upload(cmd, frame_index, cpu_rgba_scratch_);
}

} // namespace viewer
