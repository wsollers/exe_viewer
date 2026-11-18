#include "ui/ui_panels_byte_viz.hpp"

#include "ui/logger.hpp"
#include "ui/panel_helpers.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

constexpr std::uint32_t kInvalidIndex = 0xFFFF'FFFFu;
constexpr std::size_t kDefaultMaxTiles = 65'536u;
constexpr std::size_t kDefaultMinTileBytes = 256u;
constexpr std::size_t kStaticMaxReadBudgetBytes = 64u * 1024u * 1024u;
constexpr std::size_t kLiveMaxReadBudgetBytes = 64u * 1024u * 1024u;
constexpr std::size_t kSyncSmallStaticThresholdBytes = 1u * 1024u * 1024u;
constexpr double kZoomWheelBase = 1.18;
constexpr float kMinCanvasHeightPx = 190.0f;
constexpr float kRightClickDragSlopPx = 4.0f;

[[nodiscard]] constexpr const char* viz_mode_ui_label(peelf::ByteVizMode mode) noexcept {
    switch (mode) {
        case peelf::ByteVizMode::EntropyAndByteClass2D: return "2D Entropy & Byte-Class";
        case peelf::ByteVizMode::CantorDustDigram256:   return "256x256 Cantor Digram";
    }
    return "2D Entropy & Byte-Class";
}

[[nodiscard]] constexpr const char* layout_ui_label(peelf::ByteVizLayout layout) noexcept {
    switch (layout) {
        case peelf::ByteVizLayout::HilbertCurve: return "Hilbert Curve 2D";
        case peelf::ByteVizLayout::LinearRows:   return "Linear Strip";
    }
    return "Hilbert Curve 2D";
}

[[nodiscard]] constexpr const char* color_mode_ui_label(peelf::ByteVizColorMode mode) noexcept {
    switch (mode) {
        case peelf::ByteVizColorMode::EntropySpectrum:     return "Entropy Spectrum";
        case peelf::ByteVizColorMode::ByteClassSemantic:   return "Byte-Class Semantic";
        case peelf::ByteVizColorMode::PrintableVsHighBit:  return "Printable vs High-Bit";
        case peelf::ByteVizColorMode::PatchAndDiffOverlay: return "Patch & Diff Overlay";
    }
    return "Entropy Spectrum";
}

[[nodiscard]] std::string format_byte_count_compact(std::uint64_t bytes) {
    if (bytes >= (1024ull * 1024ull) && (bytes % (1024ull * 1024ull)) == 0ull) {
        return std::format("{} MiB", bytes / (1024ull * 1024ull));
    }
    if (bytes >= 1024ull && (bytes % 1024ull) == 0ull) {
        return std::format("{} KiB", bytes / 1024ull);
    }
    if (bytes >= (1024ull * 1024ull)) {
        return std::format("{:.2f} MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    }
    if (bytes >= 1024ull) {
        return std::format("{:.1f} KiB", static_cast<double>(bytes) / 1024.0);
    }
    return std::format("{} B", bytes);
}

[[nodiscard]] std::string format_printable_byte_repr(std::uint8_t b) {
    if (b >= 0x20u && b <= 0x7Eu) {
        if (b == '\'' || b == '\\') {
            return std::format("'\\{:c}'", static_cast<char>(b));
        }
        return std::format("'{:c}'", static_cast<char>(b));
    }
    switch (b) {
        case 0x00u: return "'\\0'";
        case 0x09u: return "'\\t'";
        case 0x0Au: return "'\\n'";
        case 0x0Du: return "'\\r'";
        default:    return "'.'";
    }
}

[[nodiscard]] ImVec4 provenance_badge_color(peelf::ProvenanceTag tag,
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

[[nodiscard]] std::vector<peelf::ByteVizSectionSpan> extract_static_section_spans(
    const peelf::IBinaryImage& image) {
    std::vector<peelf::ByteVizSectionSpan> out{};
    out.reserve(image.sections().size());
    for (const auto& sec : image.sections()) {
        if (sec.file_size == 0u) {
            continue;
        }
        out.push_back(peelf::ByteVizSectionSpan{
            .name = sec.name,
            .start_address = sec.file_offset,
            .size_bytes = sec.file_size,
            .virtual_address = sec.virtual_address != 0u
                                   ? std::optional<std::uint64_t>{sec.virtual_address}
                                   : std::nullopt,
            .file_offset = sec.file_offset,
            .executable = sec.executable,
            .writable = sec.writable,
        });
    }
    return out;
}

} // namespace

ByteEntropyVizPanel::ByteEntropyVizPanel(BinaryModel& model,
                                         VulkanManager& vulkan,
                                         ViewerSelection& selection,
                                         NavigationRequestQueue& nav_queue,
                                         EntityContextActionCallback on_context_action,
                                         DiffOverlayProviderCallback diff_overlay_provider)
    : UiPanel("Entropy & Digram")
    , model_(model)
    , vulkan_(vulkan)
    , selection_(selection)
    , nav_queue_(nav_queue)
    , on_context_action_(std::move(on_context_action))
    , diff_overlay_provider_(std::move(diff_overlay_provider)) {
    visible_ = false;
    camera_.min_scale = 0.20;
    camera_.max_scale = 256.0;
}

ByteEntropyVizPanel::~ByteEntropyVizPanel() {
    shutdown();
}

void ByteEntropyVizPanel::ensure_worker_started() {
    if (worker_thread_.joinable()) {
        return;
    }
    worker_thread_ = std::jthread([this](std::stop_token st) { worker_loop(std::move(st)); });
}

void ByteEntropyVizPanel::stop_worker() noexcept {
    try {
        const std::scoped_lock lock(worker_mutex_);
        (void)active_job_stop_.request_stop();
        pending_job_.reset();
    } catch (...) {
    }
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
        completed_results_.clear();
        worker_busy_ = false;
    } catch (...) {
    }
}

void ByteEntropyVizPanel::cancel_and_reset() noexcept {
    stop_worker();
    try {
        const std::scoped_lock lock(worker_mutex_);
        ++worker_generation_;
    } catch (...) {
    }
    latest_observed_ = {};
    has_snapshot_ = false;
    clear_brush();
    scope_options_.clear();
    selected_scope_index_ = 0u;
    dirty_analysis_ = true;
    needs_fit_view_ = true;
    last_fitted_domain_w_ = 0u;
    last_fitted_domain_h_ = 0u;
    hovered_index_.reset();
    selected_tile_index_.reset();
    selected_tile_addr_.reset();
    selected_cantor_bin_.reset();
    context_index_.reset();
    needs_gpu_record_this_frame_ = false;
    last_was_live_ = false;
    last_was_crash_dump_ = false;
    last_pid_ = 0;
    last_static_image_ = nullptr;
    last_scope_source_count_ = 0u;
    last_edit_revision_ = 0u;
    last_diff_revision_ = 0u;
}

void ByteEntropyVizPanel::shutdown() noexcept {
    cancel_and_reset();
    compute_pipeline_.shutdown();
    ssbo_ring_.shutdown();
    canvas_.shutdown();
    canvas_initialized_ = false;
    compute_pipeline_attempted_ = false;
}

void ByteEntropyVizPanel::clear_brush() noexcept {
    is_brushing_ = false;
    brush_anchor_span_ = {0u, 0u};
    brushed_range_.reset();
    brushed_cantor_observed_.reset();
    viewing_brushed_cantor_ = false;
}

void ByteEntropyVizPanel::worker_loop(std::stop_token thread_stop_token) {
    while (!thread_stop_token.stop_requested()) {
        std::optional<AsyncAnalysisJob> job{};
        std::stop_token job_stop{};
        {
            std::unique_lock lock(worker_mutex_);
            worker_cv_.wait(lock, thread_stop_token, [this] { return pending_job_.has_value(); });
            if (thread_stop_token.stop_requested() || !pending_job_.has_value()) {
                break;
            }
            job = std::move(pending_job_);
            pending_job_.reset();
            active_job_stop_ = std::stop_source{};
            job_stop = active_job_stop_.get_token();
            worker_busy_ = true;
        }

        // Propagate jthread shutdown directly into active_job_stop_ as well.
        std::stop_callback forward_stop(thread_stop_token, [this]() noexcept {
            const std::scoped_lock lock(worker_mutex_);
            (void)active_job_stop_.request_stop();
        });

        AsyncAnalysisResult result{};
        result.kind = job->kind;
        result.generation = job->generation;
        result.brush_range = {job->brush_start, job->brush_end};

        try {
            if (job->kind == AsyncJobKind::FullSnapshot) {
                if (job->is_live) {
                    if (job->session != nullptr) {
                        result.snapshot_observed = peelf::compute_live_region_byte_viz(
                            *job->session,
                            job->live_region,
                            job->config,
                            job->diff_ranges,
                            job->patch_intervals,
                            job_stop);
                    }
                } else if (job->use_owned_effective_bytes) {
                    peelf::ByteVizConfig owned_cfg = job->config;
                    owned_cfg.scope_subrange.reset();
                    result.snapshot_observed = peelf::compute_byte_viz_from_bytes(
                        job->owned_effective_bytes,
                        owned_cfg,
                        job->owned_base_address,
                        false,
                        job->diff_ranges,
                        job->patch_intervals,
                        job->owned_sections,
                        job_stop);
                } else if (job->static_image != nullptr) {
                    result.snapshot_observed = peelf::compute_static_byte_viz(
                        *job->static_image,
                        job->static_raw_bytes,
                        job->config,
                        nullptr,
                        job->diff_ranges,
                        job_stop);
                }
            } else {
                if (job->is_live) {
                    if (job->session != nullptr) {
                        result.brush_cantor_observed = peelf::compute_live_cantor_digram(
                            *job->session,
                            job->live_region,
                            job->brush_start,
                            job->brush_end,
                            job->config.max_read_bytes,
                            job_stop);
                    }
                } else if (job->use_owned_effective_bytes) {
                    result.brush_cantor_observed = peelf::compute_cantor_digram_from_bytes(
                        job->owned_effective_bytes,
                        job->owned_base_address,
                        false,
                        job_stop);
                } else if (job->static_image != nullptr) {
                    result.brush_cantor_observed = peelf::compute_static_cantor_digram(
                        *job->static_image,
                        job->static_raw_bytes,
                        job->brush_start,
                        job->brush_end,
                        nullptr,
                        job_stop);
                }
            }
        } catch (const std::exception& ex) {
            if (job->kind == AsyncJobKind::FullSnapshot) {
                result.snapshot_observed.availability = peelf::CaptureAvailability::Unavailable;
                result.snapshot_observed.note = ex.what();
            } else {
                result.brush_cantor_observed.availability = peelf::CaptureAvailability::Unavailable;
                result.brush_cantor_observed.note = ex.what();
            }
        } catch (...) {
            if (job->kind == AsyncJobKind::FullSnapshot) {
                result.snapshot_observed.availability = peelf::CaptureAvailability::Unavailable;
                result.snapshot_observed.note = "Unknown error during byte-entropy analysis";
            } else {
                result.brush_cantor_observed.availability = peelf::CaptureAvailability::Unavailable;
                result.brush_cantor_observed.note = "Unknown error during Cantor digram analysis";
            }
        }

        {
            const std::scoped_lock lock(worker_mutex_);
            worker_busy_ = false;
            if (!thread_stop_token.stop_requested() && !job_stop.stop_requested() &&
                job->generation == worker_generation_) {
                completed_results_.push_back(std::move(result));
            }
        }
    }
}

void ByteEntropyVizPanel::rebuild_scope_options() {
    std::optional<std::pair<ScopeKind, std::uint64_t>> previous_key{};
    if (selected_scope_index_ < scope_options_.size()) {
        previous_key = {scope_options_[selected_scope_index_].kind,
                        scope_options_[selected_scope_index_].start_address};
    }

    scope_options_.clear();

    if (model_.is_live_process()) {
        // Add mapped process modules first (backed by synthesized MemoryRegion spans), then readable regions.
        for (const auto& reg : model_.memory_regions()) {
            if (reg.end_address <= reg.start_address || !reg.protection.readable) {
                continue;
            }
            std::string tag = std::string(peelf::to_string(reg.kind));
            if (!reg.module_name.empty()) {
                tag = sanitize_single_line_control_chars(reg.module_name);
            } else if (!reg.pathname.empty()) {
                tag = sanitize_single_line_control_chars(reg.pathname);
            }
            const std::string perms = std::format(
                "{}{}{}",
                reg.protection.readable ? 'r' : '-',
                reg.protection.writable ? 'w' : '-',
                reg.protection.executable ? 'x' : '-');
            scope_options_.push_back(ScopeOption{
                .kind = ScopeKind::LiveMemoryRegion,
                .label = std::format("{} [0x{:X}..0x{:X}] {} ({})",
                                     tag,
                                     reg.start_address,
                                     reg.end_address,
                                     perms,
                                     format_byte_count_compact(reg.size())),
                .short_label = tag,
                .start_address = reg.start_address,
                .end_address = reg.end_address,
                .live_region = reg,
            });
            if (scope_options_.size() >= 128u) {
                break;
            }
        }
    } else if (const peelf::IBinaryImage* img = model_.image(); img != nullptr) {
        std::uint64_t whole_start = 0u;
        std::uint64_t whole_end = static_cast<std::uint64_t>(model_.bytes().size());
        if (img->is_universal_slice() && img->container_slice_size() > 0u) {
            whole_start = img->container_slice_offset();
            whole_end = whole_start + img->container_slice_size();
        } else if (const auto* editable = model_.editable_image();
                   editable != nullptr && editable->size() > 0u) {
            whole_end = editable->size();
        }
        if (whole_end > whole_start) {
            scope_options_.push_back(ScopeOption{
                .kind = ScopeKind::WholeStaticBinary,
                .label = std::format("Whole Binary [0x{:X}..0x{:X}] ({})",
                                     whole_start,
                                     whole_end,
                                     format_byte_count_compact(whole_end - whole_start)),
                .short_label = "Whole Binary",
                .start_address = whole_start,
                .end_address = whole_end,
            });
        }

        for (const auto& sec : img->sections()) {
            if (sec.file_size == 0u ||
                sec.file_offset > (std::numeric_limits<std::uint64_t>::max() - sec.file_size)) {
                continue;
            }
            const std::string clean_name = sanitize_single_line_control_chars(
                sec.name.empty() ? "<section>" : sec.name);
            const std::uint64_t end_off = sec.file_offset + sec.file_size;
            scope_options_.push_back(ScopeOption{
                .kind = ScopeKind::StaticSection,
                .label = std::format("Section {} [off 0x{:X}..0x{:X}] ({}){}",
                                     clean_name,
                                     sec.file_offset,
                                     end_off,
                                     format_byte_count_compact(sec.file_size),
                                     sec.executable ? " [exec]" : ""),
                .short_label = clean_name,
                .start_address = sec.file_offset,
                .end_address = end_off,
            });
        }
    }

    selected_scope_index_ = 0u;
    if (previous_key.has_value()) {
        for (std::size_t i = 0u; i < scope_options_.size(); ++i) {
            if (scope_options_[i].kind == previous_key->first &&
                scope_options_[i].start_address == previous_key->second) {
                selected_scope_index_ = i;
                return;
            }
        }
    }

    // For live processes without a prior scope choice, prefer the region containing current selection VA.
    if (model_.is_live_process() && selection_.virtual_address.has_value()) {
        const std::uint64_t sel_va = *selection_.virtual_address;
        for (std::size_t i = 0u; i < scope_options_.size(); ++i) {
            if (sel_va >= scope_options_[i].start_address &&
                sel_va < scope_options_[i].end_address) {
                selected_scope_index_ = i;
                break;
            }
        }
    }
}

void ByteEntropyVizPanel::schedule_full_snapshot_analysis() {
    if (scope_options_.empty() || selected_scope_index_ >= scope_options_.size()) {
        has_snapshot_ = false;
        dirty_analysis_ = false;
        return;
    }

    const ScopeOption& scope = scope_options_[selected_scope_index_];
    const bool is_live = (scope.kind == ScopeKind::LiveMemoryRegion);

    ActiveDiffOverlaySnapshot diff_overlay{};
    if (diff_overlay_provider_) {
        diff_overlay = diff_overlay_provider_(is_live);
    }
    last_diff_revision_ = diff_overlay.revision;
    last_edit_revision_ = model_.edit_revision();

    peelf::ByteVizConfig cfg{};
    cfg.layout = layout_mode_;
    cfg.target_max_tiles = kDefaultMaxTiles;
    cfg.min_tile_bytes = kDefaultMinTileBytes;
    cfg.max_read_bytes = is_live ? kLiveMaxReadBudgetBytes : kStaticMaxReadBudgetBytes;
    cfg.scope_subrange = std::pair<std::uint64_t, std::uint64_t>{
        scope.start_address, scope.end_address};
    cfg.scope_label = scope.short_label;
    cfg.compute_tiles = true;
    cfg.compute_cantor = true;

    const std::uint64_t span_len =
        scope.end_address > scope.start_address ? (scope.end_address - scope.start_address) : 0u;

    // Fast synchronous path for compact static scopes (<= 1 MiB) so byte patching feels instantaneous.
    if (!is_live && model_.image() != nullptr && span_len <= kSyncSmallStaticThresholdBytes) {
        {
            const std::scoped_lock lock(worker_mutex_);
            (void)active_job_stop_.request_stop();
            pending_job_.reset();
            ++worker_generation_;
        }
        latest_observed_ = peelf::compute_static_byte_viz(
            *model_.image(),
            model_.bytes(),
            cfg,
            model_.editable_image(),
            diff_overlay.ranges);
        has_snapshot_ = (latest_observed_.availability != peelf::CaptureAvailability::Unavailable) &&
                        latest_observed_.value.has_value();
        dirty_analysis_ = false;
        if (selected_tile_addr_.has_value() && latest_observed_.value.has_value()) {
            if (const auto idx =
                    latest_observed_.value->find_tile_index_containing(*selected_tile_addr_)) {
                selected_tile_index_ = static_cast<std::uint32_t>(*idx);
            } else {
                selected_tile_index_.reset();
            }
        }
        if (brushed_range_.has_value()) {
            schedule_brush_cantor_analysis(brushed_range_->first, brushed_range_->second);
        }
        return;
    }

    AsyncAnalysisJob job{};
    job.kind = AsyncJobKind::FullSnapshot;
    job.is_live = is_live;
    job.config = std::move(cfg);
    job.diff_ranges = std::move(diff_overlay.ranges);

    if (is_live) {
        job.session = model_.shared_process_session();
        if (job.session == nullptr) {
            has_snapshot_ = false;
            dirty_analysis_ = false;
            return;
        }
        job.live_region = scope.live_region;
    } else {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            has_snapshot_ = false;
            dirty_analysis_ = false;
            return;
        }
        if (!model_.changed_intervals().empty()) {
            // Snapshot effective bytes + staged patch intervals on the UI thread so the background
            // worker never races with PagedBinaryImage's page cache during concurrent hex edits.
            const std::size_t capped_len = static_cast<std::size_t>(
                std::min<std::uint64_t>(span_len, kStaticMaxReadBudgetBytes));
            auto eff = model_.read_effective_bytes(scope.start_address, capped_len);
            if (eff.has_value()) {
                job.use_owned_effective_bytes = true;
                job.owned_effective_bytes = std::move(*eff);
                job.owned_base_address = scope.start_address;
                job.patch_intervals = model_.changed_intervals();
                job.owned_sections = extract_static_section_spans(*img);
                for (auto& dr : job.diff_ranges) {
                    if (dr.is_virtual_address) {
                        if (const auto mapped = img->virtual_address_to_file_offset(dr.offset_or_va)) {
                            dr.offset_or_va = *mapped;
                            dr.is_virtual_address = false;
                        }
                    }
                }
            } else {
                job.static_image = img;
                job.static_raw_bytes = model_.bytes();
            }
        } else {
            job.static_image = img;
            job.static_raw_bytes = model_.bytes();
        }
    }

    ensure_worker_started();
    {
        const std::scoped_lock lock(worker_mutex_);
        (void)active_job_stop_.request_stop();
        ++worker_generation_;
        job.generation = worker_generation_;
        pending_job_ = std::move(job);
    }
    worker_cv_.notify_one();
    dirty_analysis_ = false;
}

void ByteEntropyVizPanel::schedule_brush_cantor_analysis(std::uint64_t brush_start,
                                                         std::uint64_t brush_end) {
    if (brush_end <= brush_start || scope_options_.empty() ||
        selected_scope_index_ >= scope_options_.size()) {
        brushed_cantor_observed_.reset();
        return;
    }

    const ScopeOption& scope = scope_options_[selected_scope_index_];
    const bool is_live = (scope.kind == ScopeKind::LiveMemoryRegion);
    const std::uint64_t span_len = brush_end - brush_start;

    if (!is_live && model_.image() != nullptr && span_len <= kSyncSmallStaticThresholdBytes) {
        brushed_cantor_observed_ = peelf::compute_static_cantor_digram(
            *model_.image(),
            model_.bytes(),
            brush_start,
            brush_end,
            model_.editable_image());
        return;
    }

    AsyncAnalysisJob job{};
    job.kind = AsyncJobKind::BrushCantorOnly;
    job.is_live = is_live;
    job.brush_start = brush_start;
    job.brush_end = brush_end;
    job.config.max_read_bytes = is_live ? kLiveMaxReadBudgetBytes : kStaticMaxReadBudgetBytes;

    if (is_live) {
        job.session = model_.shared_process_session();
        if (job.session == nullptr) {
            return;
        }
        job.live_region = scope.live_region;
    } else if (const peelf::IBinaryImage* img = model_.image(); img != nullptr) {
        if (!model_.changed_intervals().empty()) {
            const std::size_t capped_len = static_cast<std::size_t>(
                std::min<std::uint64_t>(span_len, kStaticMaxReadBudgetBytes));
            if (auto eff = model_.read_effective_bytes(brush_start, capped_len); eff.has_value()) {
                job.use_owned_effective_bytes = true;
                job.owned_effective_bytes = std::move(*eff);
                job.owned_base_address = brush_start;
            } else {
                job.static_image = img;
                job.static_raw_bytes = model_.bytes();
            }
        } else {
            job.static_image = img;
            job.static_raw_bytes = model_.bytes();
        }
    } else {
        return;
    }

    ensure_worker_started();
    {
        const std::scoped_lock lock(worker_mutex_);
        (void)active_job_stop_.request_stop();
        job.generation = worker_generation_;
        pending_job_ = std::move(job);
    }
    worker_cv_.notify_one();
}

void ByteEntropyVizPanel::sync_target_and_schedule_analysis() {
    // Harvest completed worker jobs first.
    {
        std::vector<AsyncAnalysisResult> finished{};
        {
            const std::scoped_lock lock(worker_mutex_);
            if (!completed_results_.empty()) {
                finished.swap(completed_results_);
            }
        }
        for (auto& res : finished) {
            if (res.generation != worker_generation_) {
                continue;
            }
            if (res.kind == AsyncJobKind::FullSnapshot) {
                latest_observed_ = std::move(res.snapshot_observed);
                if (latest_observed_.value.has_value() &&
                    latest_observed_.value->layout != layout_mode_) {
                    latest_observed_.value->relayout(layout_mode_);
                }
                has_snapshot_ =
                    (latest_observed_.availability != peelf::CaptureAvailability::Unavailable) &&
                    latest_observed_.value.has_value();
                if (selected_tile_addr_.has_value() && latest_observed_.value.has_value()) {
                    if (const auto idx =
                            latest_observed_.value->find_tile_index_containing(*selected_tile_addr_)) {
                        selected_tile_index_ = static_cast<std::uint32_t>(*idx);
                    } else {
                        selected_tile_index_.reset();
                    }
                }
            } else if (brushed_range_.has_value() &&
                       brushed_range_->first == res.brush_range.first &&
                       brushed_range_->second == res.brush_range.second) {
                brushed_cantor_observed_ = std::move(res.brush_cantor_observed);
            }
        }
    }

    const bool is_live = model_.is_live_process();
    const bool is_dump = model_.is_crash_dump();
    const peelf::ProcessId cur_pid =
        (is_live && model_.process_session() != nullptr) ? model_.process_session()->pid() : 0;
    const peelf::IBinaryImage* cur_img = is_live ? nullptr : model_.image();
    const std::size_t cur_source_count =
        is_live ? model_.memory_regions().size()
                : (cur_img != nullptr ? cur_img->sections().size() : 0u);

    if (is_live != last_was_live_ || is_dump != last_was_crash_dump_ || cur_pid != last_pid_ ||
        cur_img != last_static_image_) {
        last_was_live_ = is_live;
        last_was_crash_dump_ = is_dump;
        last_pid_ = cur_pid;
        last_static_image_ = cur_img;
        last_scope_source_count_ = cur_source_count;
        clear_brush();
        rebuild_scope_options();
        dirty_analysis_ = true;
        needs_fit_view_ = true;
        hovered_index_.reset();
        selected_tile_index_.reset();
        selected_cantor_bin_.reset();
    } else if (cur_source_count != last_scope_source_count_) {
        last_scope_source_count_ = cur_source_count;
        rebuild_scope_options();
        dirty_analysis_ = true;
    }

    std::uint64_t cur_diff_rev = 0u;
    if (diff_overlay_provider_) {
        cur_diff_rev = diff_overlay_provider_(is_live).revision;
    }
    if (model_.edit_revision() != last_edit_revision_ || cur_diff_rev != last_diff_revision_) {
        dirty_analysis_ = true;
    }

    if (dirty_analysis_) {
        schedule_full_snapshot_analysis();
    }
}

const peelf::CantorDustDigram* ByteEntropyVizPanel::active_cantor_digram() const noexcept {
    if (viewing_brushed_cantor_ && brushed_cantor_observed_.has_value() &&
        brushed_cantor_observed_->value.has_value()) {
        return &(*brushed_cantor_observed_->value);
    }
    if (latest_observed_.value.has_value()) {
        return &latest_observed_.value->cantor;
    }
    return nullptr;
}

void ByteEntropyVizPanel::fit_camera_to_active_domain(double canvas_w, double canvas_h) noexcept {
    std::uint32_t dom_w = 256u;
    std::uint32_t dom_h = 256u;
    if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
        if (!latest_observed_.value.has_value()) {
            return;
        }
        dom_w = std::max(1u, latest_observed_.value->grid_width);
        dom_h = std::max(1u, latest_observed_.value->grid_height);
    }
    const auto gw = static_cast<double>(dom_w);
    const auto gh = static_cast<double>(dom_h);
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
    last_fitted_mode_ = viz_mode_;
    last_fitted_domain_w_ = dom_w;
    last_fitted_domain_h_ = dom_h;
}

void ByteEntropyVizPanel::navigate_to_address_or_offset(std::uint64_t offset_or_va,
                                                        bool addresses_are_virtual,
                                                        bool executable_hint,
                                                        std::size_t highlight_bytes) {
    const std::size_t clamped_hl = std::clamp<std::size_t>(highlight_bytes, 1u, 64u);
    const PreferredView view = executable_hint ? PreferredView::Disassembly : PreferredView::Hex;
    if (addresses_are_virtual) {
        nav_queue_.enqueue_address(offset_or_va, view, clamped_hl, false);
        return;
    }
    if (const auto mapped_va = model_.offset_to_virtual_address(offset_or_va);
        mapped_va.has_value() && executable_hint) {
        nav_queue_.enqueue_address(*mapped_va, PreferredView::Disassembly, clamped_hl, false);
        return;
    }
    nav_queue_.enqueue_offset(offset_or_va, clamped_hl);
}

InspectableEntity ByteEntropyVizPanel::build_tile_entity(const peelf::ByteVizTile& tile) const {
    const bool is_va =
        latest_observed_.value.has_value() && latest_observed_.value->addresses_are_virtual;
    const std::uint64_t addr = tile.base_offset_or_va();
    const peelf::ByteVizSectionSpan* sec =
        latest_observed_.value.has_value() ? latest_observed_.value->find_section_at(addr) : nullptr;

    InspectableEntity entity{};
    if (is_va) {
        entity.va = addr;
        entity.file_offset = model_.virtual_address_to_offset(addr);
    } else {
        entity.file_offset = addr;
        entity.va = model_.offset_to_virtual_address(addr);
    }
    entity.size = std::max<std::uint64_t>(tile.span_bytes(), 1u);

    const std::string cls_str(peelf::to_string(tile.byte_class()));
    if (sec != nullptr && !sec->name.empty()) {
        entity.symbol_or_label = std::format(
            "{} ({}) @ 0x{:X}",
            sanitize_single_line_control_chars(sec->name),
            cls_str,
            addr);
    } else {
        entity.symbol_or_label = std::format("{} @ 0x{:X}", cls_str, addr);
    }
    entity.extra_json_fields = {
        {"byte_class", cls_str},
        {"entropy_bits_per_byte", std::format("{:.3f}", tile.entropy_bits())},
        {"printable_ratio", std::format("{:.3f}", tile.printable_ratio())},
        {"zero_ratio", std::format("{:.3f}", tile.zero_ratio())},
        {"high_bit_ratio", std::format("{:.3f}", tile.high_bit_ratio())},
        {"patch_dirty", tile.is_patch_dirty() ? "true" : "false"},
        {"diff_modified", tile.is_diff_modified() ? "true" : "false"},
        {"diff_added", tile.is_diff_added() ? "true" : "false"},
        {"provenance", std::string(peelf::to_string(latest_observed_.provenance))},
    };
    return entity;
}

InspectableEntity ByteEntropyVizPanel::build_cantor_bin_entity(std::uint8_t first_byte,
                                                               std::uint8_t second_byte) const {
    InspectableEntity entity{};
    const peelf::CantorDustDigram* cantor = active_cantor_digram();
    std::uint32_t count = 0u;
    peelf::CantorPairClass pair_cls = peelf::classify_cantor_pair(first_byte, second_byte);
    if (cantor != nullptr) {
        count = cantor->count_at(first_byte, second_byte);
        if (const auto rep = cantor->first_occurrence_at(first_byte, second_byte)) {
            if (cantor->addresses_are_virtual) {
                entity.va = *rep;
                entity.file_offset = model_.virtual_address_to_offset(*rep);
            } else {
                entity.file_offset = *rep;
                entity.va = model_.offset_to_virtual_address(*rep);
            }
        }
    }
    entity.size = 2u;
    entity.symbol_or_label = std::format(
        "Cantor Pair (0x{:02X}, 0x{:02X})", first_byte, second_byte);
    entity.extra_json_fields = {
        {"pair_hex", std::format("0x{:02X} 0x{:02X}", first_byte, second_byte)},
        {"pair_count", std::to_string(count)},
        {"pair_class", std::string(peelf::to_string(pair_cls))},
    };
    return entity;
}

void ByteEntropyVizPanel::render_toolbar() {
    // Row 1: View Mode | Layout | Color Mode | Fit View | Guides/Grid
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Mode");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 13.5f);
    if (ImGui::BeginCombo("##ByteVizMode", viz_mode_ui_label(viz_mode_))) {
        for (const auto candidate : {peelf::ByteVizMode::EntropyAndByteClass2D,
                                     peelf::ByteVizMode::CantorDustDigram256}) {
            const bool selected = (viz_mode_ == candidate);
            if (ImGui::Selectable(viz_mode_ui_label(candidate), selected)) {
                viz_mode_ = candidate;
                if (candidate == peelf::ByteVizMode::CantorDustDigram256 &&
                    brushed_range_.has_value()) {
                    viewing_brushed_cantor_ = true;
                }
                hovered_index_.reset();
                needs_fit_view_ = true;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    const bool entropy_mode = (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D);
    ImGui::BeginDisabled(!entropy_mode);
    ImGui::TextDisabled("Layout");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10.0f);
    if (ImGui::BeginCombo("##ByteVizLayout", layout_ui_label(layout_mode_))) {
        for (const auto candidate : {peelf::ByteVizLayout::HilbertCurve,
                                     peelf::ByteVizLayout::LinearRows}) {
            const bool selected = (layout_mode_ == candidate);
            if (ImGui::Selectable(layout_ui_label(candidate), selected)) {
                layout_mode_ = candidate;
                if (latest_observed_.value.has_value()) {
                    latest_observed_.value->relayout(layout_mode_);
                }
                needs_fit_view_ = true;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::TextDisabled("Color");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 12.5f);
    if (ImGui::BeginCombo("##ByteVizColor", color_mode_ui_label(color_mode_))) {
        for (const auto candidate : {peelf::ByteVizColorMode::EntropySpectrum,
                                     peelf::ByteVizColorMode::ByteClassSemantic,
                                     peelf::ByteVizColorMode::PrintableVsHighBit,
                                     peelf::ByteVizColorMode::PatchAndDiffOverlay}) {
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
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Fit View")) {
        needs_fit_view_ = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox(entropy_mode ? "Grid" : "Quadrant Guides", &show_guides_);

    // Row 2: Scope selector + Brush inspection actions
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Scope");
    ImGui::SameLine();
    const char* scope_preview =
        (selected_scope_index_ < scope_options_.size())
            ? scope_options_[selected_scope_index_].label.c_str()
            : "<no active target>";
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 23.0f);
    if (ImGui::BeginCombo("##ByteVizScope", scope_preview)) {
        for (std::size_t i = 0u; i < scope_options_.size(); ++i) {
            const bool selected = (selected_scope_index_ == i);
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(scope_options_[i].label.c_str(), selected)) {
                selected_scope_index_ = i;
                clear_brush();
                dirty_analysis_ = true;
                needs_fit_view_ = true;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Re-Analyze")) {
        rebuild_scope_options();
        dirty_analysis_ = true;
    }

    if (brushed_range_.has_value()) {
        ImGui::SameLine();
        ImGui::TextColored(
            ImVec4{0.98f, 0.86f, 0.32f, 1.0f},
            "Brush [0x%llX..0x%llX] (%s)",
            static_cast<unsigned long long>(brushed_range_->first),
            static_cast<unsigned long long>(brushed_range_->second),
            format_byte_count_compact(brushed_range_->second - brushed_range_->first).c_str());

        if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Inspect Brush in Cantor Digram")) {
                viewing_brushed_cantor_ = true;
                if (!brushed_cantor_observed_.has_value()) {
                    schedule_brush_cantor_analysis(brushed_range_->first, brushed_range_->second);
                }
                viz_mode_ = peelf::ByteVizMode::CantorDustDigram256;
                hovered_index_.reset();
                needs_fit_view_ = true;
            }
        } else {
            ImGui::SameLine();
            if (ImGui::SmallButton("Back to 2D Entropy")) {
                viz_mode_ = peelf::ByteVizMode::EntropyAndByteClass2D;
                hovered_index_.reset();
                needs_fit_view_ = true;
            }
        }

        ImGui::SameLine();
        if (ImGui::SmallButton("Clear Brush")) {
            clear_brush();
        }
    } else if (entropy_mode && has_snapshot_) {
        ImGui::SameLine();
        ImGui::TextDisabled("Tip: Shift+Drag to brush a byte range for Cantor inspection");
    }
}

void ByteEntropyVizPanel::render_summary_strip() const {
    if (!latest_observed_.value.has_value()) {
        return;
    }
    const auto& snap = *latest_observed_.value;
    const auto& st = snap.stats;

    const bool gpu_compute_active =
        canvas_initialized_ && canvas_.can_use_compute() && compute_pipeline_.valid();
    ImGui::TextColored(gpu_compute_active ? ImVec4{0.34f, 0.85f, 0.96f, 1.0f}
                                          : ImVec4{0.82f, 0.78f, 0.45f, 1.0f},
                       "[%s]",
                       gpu_compute_active ? "Vulkan Compute" : "CPU Raster Fallback");

    ImGui::SameLine();
    const ImVec4 prov_col =
        provenance_badge_color(latest_observed_.provenance, latest_observed_.availability);
    const std::string prov_badge = std::format(
        "[{}:{}]",
        peelf::to_string(latest_observed_.provenance),
        peelf::to_string(latest_observed_.availability));
    ImGui::TextColored(prov_col, "%s", prov_badge.c_str());
    if (ImGui::IsItemHovered() && !latest_observed_.note.empty()) {
        ImGui::SetTooltip("%s", latest_observed_.note.c_str());
    }

    ImGui::SameLine();
    if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
        ImGui::TextDisabled(
            "%ux%u (%zu tiles @ %s) | Mean H: %.2f b/B | Peak H: %.2f b/B",
            snap.grid_width,
            snap.grid_height,
            snap.tiles.size(),
            format_byte_count_compact(snap.nominal_tile_bytes).c_str(),
            st.mean_entropy_bits,
            st.peak_entropy_bits);
        if (st.high_entropy_tile_count > 0u) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4{0.96f, 0.36f, 0.42f, 1.0f},
                               "| Packed/High-H: %zu",
                               st.high_entropy_tile_count);
        }
        if (st.patch_dirty_tile_count > 0u) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4{0.20f, 0.92f, 0.98f, 1.0f},
                               "| Patched: %zu",
                               st.patch_dirty_tile_count);
        }
        if (st.diff_tile_count > 0u) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4{0.99f, 0.62f, 0.24f, 1.0f},
                               "| Diff: %zu",
                               st.diff_tile_count);
        }
    } else if (const auto* cantor = active_cantor_digram(); cantor != nullptr) {
        ImGui::TextDisabled(
            "256x256 Digram%s | %llu pairs | %u / 65536 occupied bins | Max bin: %u",
            viewing_brushed_cantor_ ? " (Brushed Subrange)" : "",
            static_cast<unsigned long long>(cantor->total_pairs),
            cantor->occupied_bins,
            cantor->max_bin_count);
    }
}

void ByteEntropyVizPanel::render_entropy_hover_tooltip(std::size_t tile_index) const {
    if (!latest_observed_.value.has_value()) {
        return;
    }
    const auto& snap = *latest_observed_.value;
    if (tile_index >= snap.tiles.size()) {
        return;
    }
    const peelf::ByteVizTile& tile = snap.tiles[tile_index];
    const std::uint64_t addr = tile.base_offset_or_va();
    const std::uint64_t end_addr = tile.end_offset_or_va();
    const peelf::ByteVizSectionSpan* sec = snap.find_section_at(addr);

    ImGui::BeginTooltip();
    ImGui::Text("%s 0x%llX .. 0x%llX (%s)",
                snap.addresses_are_virtual ? "VA" : "Offset",
                static_cast<unsigned long long>(addr),
                static_cast<unsigned long long>(end_addr),
                format_byte_count_compact(tile.span_bytes()).c_str());

    if (!snap.addresses_are_virtual) {
        if (const auto mapped_va = model_.offset_to_virtual_address(addr)) {
            ImGui::TextDisabled("Mapped VA: 0x%llX",
                                static_cast<unsigned long long>(*mapped_va));
        }
    }
    if (sec != nullptr) {
        const std::string clean_sec =
            sanitize_single_line_control_chars(sec->name.empty() ? "<unnamed>" : sec->name);
        ImGui::TextDisabled("Section: %s%s",
                            clean_sec.c_str(),
                            sec->executable ? " [executable]" : "");
    } else {
        ImGui::TextDisabled("Section: <header / unmapped overlay>");
    }

    ImGui::Separator();
    const auto cls_sv = peelf::to_string(tile.byte_class());
    ImGui::Text("Byte Class: %.*s   |   Tile #%zu",
                static_cast<int>(cls_sv.size()),
                cls_sv.data(),
                tile_index);
    ImGui::Text("Shannon Entropy: %.2f / 8.00 bits/byte (%u / 255)",
                tile.entropy_bits(),
                static_cast<unsigned>(tile.entropy_u8()));
    ImGui::Text("Printable: %.1f%%   |   Zero (0x00): %.1f%%   |   High-Bit (>=0x80): %.1f%%",
                tile.printable_ratio() * 100.0,
                tile.zero_ratio() * 100.0,
                tile.high_bit_ratio() * 100.0);

    if (tile.is_patch_dirty()) {
        ImGui::TextColored(ImVec4{0.20f, 0.92f, 0.98f, 1.0f},
                           "[PatchDirty] Contains staged byte patch(es)");
    }
    if (tile.is_diff_added()) {
        ImGui::TextColored(ImVec4{0.28f, 0.94f, 0.52f, 1.0f},
                           "[DiffAdded] Added section / byte range in active Binary Diff");
    } else if (tile.is_diff_modified()) {
        ImGui::TextColored(ImVec4{0.99f, 0.62f, 0.24f, 1.0f},
                           "[DiffModified] Modified bytes in active Binary Diff");
    }

    ImGui::Separator();
    ImGui::TextDisabled(
        "Click: Navigate  |  Shift+Drag: Brush Range  |  Wheel: Zoom  |  Middle/Right-Drag: Pan");
    ImGui::EndTooltip();
}

void ByteEntropyVizPanel::render_cantor_hover_tooltip(std::uint32_t bin_index) const {
    const peelf::CantorDustDigram* cantor = active_cantor_digram();
    if (cantor == nullptr ||
        bin_index >= static_cast<std::uint32_t>(peelf::kCantorDigramBinCount)) {
        return;
    }

    const auto bx = static_cast<std::uint8_t>(bin_index & 0xFFu);
    const auto by = static_cast<std::uint8_t>((bin_index >> 8u) & 0xFFu);
    const std::uint32_t count = cantor->count_at(bx, by);
    const double pct =
        cantor->total_pairs > 0u
            ? (100.0 * static_cast<double>(count) / static_cast<double>(cantor->total_pairs))
            : 0.0;
    const peelf::CantorPairClass pair_cls = peelf::classify_cantor_pair(bx, by);
    const std::string repr_x = format_printable_byte_repr(bx);
    const std::string repr_y = format_printable_byte_repr(by);

    ImGui::BeginTooltip();
    ImGui::Text("Digram Pair (0x%02X %s -> 0x%02X %s)",
                static_cast<unsigned>(bx),
                repr_x.c_str(),
                static_cast<unsigned>(by),
                repr_y.c_str());
    const auto cls_sv = peelf::to_string(pair_cls);
    ImGui::Text("Quadrant / Class: %.*s",
                static_cast<int>(cls_sv.size()),
                cls_sv.data());
    ImGui::Separator();
    ImGui::Text("Pair Count: %u   (%.4f%% of %llu total pairs)",
                count,
                pct,
                static_cast<unsigned long long>(cantor->total_pairs));

    if (const auto rep = cantor->first_occurrence_at(bx, by)) {
        ImGui::Text("Representative %s: 0x%llX",
                    cantor->addresses_are_virtual ? "VA" : "Offset",
                    static_cast<unsigned long long>(*rep));
        ImGui::TextDisabled("Click to jump directly to 0x%llX in Hex View",
                            static_cast<unsigned long long>(*rep));
    } else {
        ImGui::TextDisabled("No occurrences of (0x%02X, 0x%02X) in active scope",
                            static_cast<unsigned>(bx),
                            static_cast<unsigned>(by));
    }
    ImGui::EndTooltip();
}

void ByteEntropyVizPanel::render_context_popup(
    std::optional<PendingEntityContextAction>& out_pending_ctx) {
    if (!ImGui::BeginPopup("##ByteEntropyVizCtx")) {
        return;
    }
    if (!context_index_.has_value()) {
        ImGui::EndPopup();
        return;
    }

    const bool has_nav_target =
        context_entity_.va.has_value() || context_entity_.file_offset.has_value();
    if (has_nav_target) {
        (void)draw_inspectable_entity_context_menu_items(
            context_entity_, model_, out_pending_ctx);
        ImGui::Separator();
    }

    if (!context_is_cantor_ && latest_observed_.value.has_value()) {
        const std::uint64_t t_start = context_tile_.base_offset_or_va();
        const std::uint64_t t_end = context_tile_.end_offset_or_va();
        if (t_end > t_start && ImGui::MenuItem("Inspect Tile in Cantor Digram")) {
            brushed_range_ = {t_start, t_end};
            viewing_brushed_cantor_ = true;
            schedule_brush_cantor_analysis(t_start, t_end);
            viz_mode_ = peelf::ByteVizMode::CantorDustDigram256;
            needs_fit_view_ = true;
        }
        if (const auto* sec = latest_observed_.value->find_section_at(t_start);
            sec != nullptr && sec->size_bytes > 0u) {
            const std::string menu_lbl = std::format(
                "Inspect Section '{}' in Cantor Digram",
                sanitize_single_line_control_chars(sec->name.empty() ? "<section>" : sec->name));
            if (ImGui::MenuItem(menu_lbl.c_str())) {
                brushed_range_ = {sec->start_address, sec->end_address()};
                viewing_brushed_cantor_ = true;
                schedule_brush_cantor_analysis(sec->start_address, sec->end_address());
                viz_mode_ = peelf::ByteVizMode::CantorDustDigram256;
                needs_fit_view_ = true;
            }
        }
    }

    if (brushed_range_.has_value() && ImGui::MenuItem("Clear Range Brush")) {
        clear_brush();
    }

    ImGui::EndPopup();
}

void ByteEntropyVizPanel::render_canvas_and_interactions() {
    if (!has_snapshot_ || !latest_observed_.value.has_value()) {
        ImGui::Spacing();
        if (!model_.has_file() && !model_.is_live_process()) {
            ImGui::TextDisabled(
                "Open a PE/ELF/Mach-O binary, crash dump, or attach to a live process to view its 2D Byte-Entropy & Cantor-Dust Digram.");
        } else {
            bool busy = false;
            {
                const std::scoped_lock lock(worker_mutex_);
                busy = worker_busy_ || pending_job_.has_value();
            }
            ImGui::TextDisabled(busy ? "Computing byte-entropy & Cantor-dust digram..."
                                     : "No readable bytes available in the selected scope.");
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
        ImGui::TextDisabled("Initializing GPU visualization surface...");
        return;
    }

    const auto disp_w = static_cast<double>(canvas_.width());
    const auto disp_h = static_cast<double>(canvas_.height());
    const auto& snap = *latest_observed_.value;

    const std::uint32_t dom_w = (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D)
                                    ? std::max(1u, snap.grid_width)
                                    : static_cast<std::uint32_t>(peelf::kCantorDigramAxis);
    const std::uint32_t dom_h = (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D)
                                    ? std::max(1u, snap.grid_height)
                                    : static_cast<std::uint32_t>(peelf::kCantorDigramAxis);

    if (needs_fit_view_ || last_fitted_mode_ != viz_mode_ || last_fitted_domain_w_ != dom_w ||
        last_fitted_domain_h_ != dom_h) {
        fit_camera_to_active_domain(disp_w, disp_h);
    }

    const ImVec2 canvas_origin = ImGui::GetCursorScreenPos();
    const ImVec2 canvas_size{static_cast<float>(canvas_.width()),
                             static_cast<float>(canvas_.height())};
    const std::size_t frame_idx = vulkan_.current_frame_index();

    ImGui::Image(canvas_.imgui_texture_id(frame_idx), canvas_size);

    ImGui::SetCursorScreenPos(canvas_origin);
    ImGui::InvisibleButton(
        "##ByteEntropyVizCanvasHitBox",
        canvas_size,
        ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight |
            ImGuiButtonFlags_MouseButtonMiddle);

    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();
    const ImGuiIO& io = ImGui::GetIO();
    const double local_mx = static_cast<double>(io.MousePos.x - canvas_origin.x);
    const double local_my = static_cast<double>(io.MousePos.y - canvas_origin.y);

    if (hovered && std::abs(io.MouseWheel) > 1e-4f) {
        const double factor = std::pow(kZoomWheelBase, static_cast<double>(io.MouseWheel));
        camera_.zoom_at_screen_pixel(local_mx, local_my, factor, disp_w, disp_h);
    }

    const bool panning_middle =
        active && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f);
    const bool panning_right =
        active && ImGui::IsMouseDragging(ImGuiMouseButton_Right, kRightClickDragSlopPx);
    const bool panning_left_unmodified =
        active && !io.KeyShift && !is_brushing_ &&
        ImGui::IsMouseDragging(ImGuiMouseButton_Left, kRightClickDragSlopPx);
    if (panning_middle || panning_right || panning_left_unmodified) {
        camera_.pan_by_pixels(static_cast<double>(io.MouseDelta.x),
                              static_cast<double>(io.MouseDelta.y));
    }

    // Hit-test world coordinates under cursor (clamped helper for smooth Shift+Drag brushing).
    hovered_index_.reset();
    const Vec2d world_pt = camera_.screen_to_world(local_mx, local_my, disp_w, disp_h);
    if (hovered && world_pt.x >= 0.0 && world_pt.y >= 0.0 &&
        world_pt.x < static_cast<double>(dom_w) &&
        world_pt.y < static_cast<double>(dom_h)) {
        const auto cx = static_cast<std::uint32_t>(std::floor(world_pt.x));
        const auto cy = static_cast<std::uint32_t>(std::floor(world_pt.y));
        if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
            if (const auto idx = snap.grid_coords_to_tile_index(cx, cy)) {
                hovered_index_ = static_cast<std::uint32_t>(*idx);
            }
        } else {
            hovered_index_ = cy * static_cast<std::uint32_t>(peelf::kCantorDigramAxis) + cx;
        }
    }

    // Shift + Left-Drag Range Brush in 2D Entropy mode
    if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D && !snap.tiles.empty()) {
        auto resolve_clamped_tile = [&]() -> const peelf::ByteVizTile* {
            const auto cx = static_cast<std::uint32_t>(
                std::clamp(std::floor(world_pt.x), 0.0, static_cast<double>(dom_w - 1u)));
            const auto cy = static_cast<std::uint32_t>(
                std::clamp(std::floor(world_pt.y), 0.0, static_cast<double>(dom_h - 1u)));
            if (const auto idx = snap.grid_coords_to_tile_index(cx, cy)) {
                return &snap.tiles[*idx];
            }
            return &snap.tiles.back();
        };

        if (hovered && io.KeyShift && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (const peelf::ByteVizTile* t = resolve_clamped_tile(); t != nullptr) {
                is_brushing_ = true;
                brush_anchor_span_ = {t->base_offset_or_va(), t->end_offset_or_va()};
                brushed_range_ = brush_anchor_span_;
                brushed_cantor_observed_.reset();
            }
        }
        if (is_brushing_ && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            if (const peelf::ByteVizTile* t = resolve_clamped_tile(); t != nullptr) {
                const std::uint64_t lo =
                    std::min(brush_anchor_span_.first, t->base_offset_or_va());
                const std::uint64_t hi =
                    std::max(brush_anchor_span_.second, t->end_offset_or_va());
                if (hi > lo) {
                    brushed_range_ = {lo, hi};
                }
            }
        }
        if (is_brushing_ && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
            is_brushing_ = false;
            if (brushed_range_.has_value() && brushed_range_->second > brushed_range_->first) {
                schedule_brush_cantor_analysis(brushed_range_->first, brushed_range_->second);
            }
        }
    }

    // Left-click navigation (when not dragging/brushing)
    const ImVec2 left_drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left, kRightClickDragSlopPx);
    if (hovered && !io.KeyShift && !is_brushing_ &&
        ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
        left_drag.x == 0.0f && left_drag.y == 0.0f && hovered_index_.has_value()) {
        if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
            if (*hovered_index_ < snap.tiles.size()) {
                const peelf::ByteVizTile& tile = snap.tiles[*hovered_index_];
                selected_tile_index_ = *hovered_index_;
                selected_tile_addr_ = tile.base_offset_or_va();
                if (tile.byte_class() != peelf::ByteClass::UnreadableOrEmpty) {
                    navigate_to_address_or_offset(
                        tile.base_offset_or_va(),
                        snap.addresses_are_virtual,
                        tile.is_executable(),
                        static_cast<std::size_t>(std::min<std::uint64_t>(tile.span_bytes(), 64u)));
                }
            }
        } else if (*hovered_index_ < static_cast<std::uint32_t>(peelf::kCantorDigramBinCount)) {
            selected_cantor_bin_ = *hovered_index_;
            if (const peelf::CantorDustDigram* cantor = active_cantor_digram(); cantor != nullptr) {
                const auto bx = static_cast<std::uint8_t>(*hovered_index_ & 0xFFu);
                const auto by = static_cast<std::uint8_t>((*hovered_index_ >> 8u) & 0xFFu);
                if (const auto rep = cantor->first_occurrence_at(bx, by)) {
                    navigate_to_address_or_offset(
                        *rep, cantor->addresses_are_virtual, false, 2u);
                }
            }
        }
    }

    // Right-click universal InspectableEntity context menu
    const ImVec2 right_drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Right, kRightClickDragSlopPx);
    if (hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right) &&
        right_drag.x == 0.0f && right_drag.y == 0.0f && hovered_index_.has_value()) {
        if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D &&
            *hovered_index_ < snap.tiles.size()) {
            const peelf::ByteVizTile& tile = snap.tiles[*hovered_index_];
            if (tile.byte_class() != peelf::ByteClass::UnreadableOrEmpty) {
                context_is_cantor_ = false;
                context_index_ = *hovered_index_;
                context_tile_ = tile;
                context_entity_ = build_tile_entity(tile);
                selected_tile_index_ = *hovered_index_;
                selected_tile_addr_ = tile.base_offset_or_va();
                ImGui::OpenPopup("##ByteEntropyVizCtx");
            }
        } else if (viz_mode_ == peelf::ByteVizMode::CantorDustDigram256 &&
                   *hovered_index_ < static_cast<std::uint32_t>(peelf::kCantorDigramBinCount)) {
            const auto bx = static_cast<std::uint8_t>(*hovered_index_ & 0xFFu);
            const auto by = static_cast<std::uint8_t>((*hovered_index_ >> 8u) & 0xFFu);
            context_is_cantor_ = true;
            context_index_ = *hovered_index_;
            context_entity_ = build_cantor_bin_entity(bx, by);
            selected_cantor_bin_ = *hovered_index_;
            ImGui::OpenPopup("##ByteEntropyVizCtx");
        }
    }

    std::optional<PendingEntityContextAction> pending_ctx{};
    render_context_popup(pending_ctx);
    if (pending_ctx.has_value() && on_context_action_) {
        on_context_action_(pending_ctx->kind, pending_ctx->entity);
    }

    if (hovered && hovered_index_.has_value() && !ImGui::IsPopupOpen("##ByteEntropyVizCtx")) {
        if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
            render_entropy_hover_tooltip(*hovered_index_);
        } else {
            render_cantor_hover_tooltip(*hovered_index_);
        }
    }

    std::uint32_t flags = show_guides_ ? shaders::ByteVizPushFlagBits::kShowGuides : 0u;
    std::uint64_t b_start = 0u;
    std::uint64_t b_end = 0u;
    if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D && brushed_range_.has_value() &&
        brushed_range_->second > brushed_range_->first) {
        flags |= shaders::ByteVizPushFlagBits::kHasBrush;
        b_start = brushed_range_->first;
        b_end = brushed_range_->second;
    }

    const std::uint32_t sel_idx =
        (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D)
            ? selected_tile_index_.value_or(kInvalidIndex)
            : selected_cantor_bin_.value_or(kInvalidIndex);

    pending_push_constants_ = shaders::ByteVizPushConstants{
        .camera = camera_.build_gpu_uniform(disp_w, disp_h),
        .canvas_width = canvas_.width(),
        .canvas_height = canvas_.height(),
        .grid_width = dom_w,
        .grid_height = dom_h,
        .viz_mode = static_cast<std::uint32_t>(viz_mode_),
        .layout_mode = static_cast<std::uint32_t>(snap.layout),
        .color_mode = static_cast<std::uint32_t>(color_mode_),
        .hilbert_order = std::max(1u, snap.hilbert_order),
        .active_count = (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D)
                            ? static_cast<std::uint32_t>(snap.tiles.size())
                            : static_cast<std::uint32_t>(peelf::kCantorDigramBinCount),
        .hovered_index = hovered_index_.value_or(kInvalidIndex),
        .selected_index = sel_idx,
        .flags = flags,
        .brush_start_lo = static_cast<std::uint32_t>(b_start & 0xFFFF'FFFFull),
        .brush_start_hi = static_cast<std::uint32_t>((b_start >> 32u) & 0xFFFF'FFFFull),
        .brush_end_lo = static_cast<std::uint32_t>(b_end & 0xFFFF'FFFFull),
        .brush_end_hi = static_cast<std::uint32_t>((b_end >> 32u) & 0xFFFF'FFFFull),
    };
    needs_gpu_record_this_frame_ = true;
}

void ByteEntropyVizPanel::draw_contents() {
    sync_target_and_schedule_analysis();
    render_toolbar();
    if (has_snapshot_) {
        render_summary_strip();
    }
    ImGui::Separator();
    render_canvas_and_interactions();
}

void ByteEntropyVizPanel::record_pre_pass(VkCommandBuffer cmd, std::size_t frame_index) {
    if (!needs_gpu_record_this_frame_) {
        return;
    }
    needs_gpu_record_this_frame_ = false;

    if (!canvas_initialized_ || !canvas_.valid() || !has_snapshot_ ||
        !latest_observed_.value.has_value()) {
        return;
    }

    const auto& snap = *latest_observed_.value;
    const peelf::CantorDustDigram* cantor = active_cantor_digram();

    if (canvas_.can_use_compute()) {
        if (!compute_pipeline_.valid() && !compute_pipeline_attempted_) {
            compute_pipeline_attempted_ = true;
            try {
                compute_pipeline_.init(
                    vulkan_,
                    shaders::kByteVizCompSpirv,
                    static_cast<std::uint32_t>(sizeof(shaders::ByteVizPushConstants)),
                    true);
            } catch (const std::exception& ex) {
                Log().warn(
                    "ByteEntropyViz Vulkan compute pipeline init failed, falling back to CPU rasterizer: {}",
                    ex.what());
            }
        }

        if (compute_pipeline_.valid()) {
            if (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) {
                static constexpr std::array<peelf::ByteVizTile, 1> kDummyTile{{}};
                const std::span<const peelf::ByteVizTile> tile_span =
                    snap.tiles.empty() ? std::span<const peelf::ByteVizTile>{kDummyTile}
                                       : std::span<const peelf::ByteVizTile>{snap.tiles};
                ssbo_ring_.upload(frame_index, tile_span);
            } else {
                static constexpr std::array<std::uint32_t, 4> kDummyBins{{0u, 0u, 0u, 0u}};
                const std::span<const std::uint32_t> bin_span =
                    (cantor != nullptr && !cantor->packed_gpu_bins.empty())
                        ? std::span<const std::uint32_t>{cantor->packed_gpu_bins}
                        : std::span<const std::uint32_t>{kDummyBins};
                ssbo_ring_.upload(frame_index, bin_span);
            }

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
    const std::optional<std::size_t> sel_opt =
        (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D)
            ? (selected_tile_index_.has_value()
                   ? std::optional<std::size_t>{*selected_tile_index_}
                   : std::nullopt)
            : (selected_cantor_bin_.has_value()
                   ? std::optional<std::size_t>{*selected_cantor_bin_}
                   : std::nullopt);

    const peelf::ByteVizViewport vp{
        .width_px = canvas_.width(),
        .height_px = canvas_.height(),
        .center_x = camera_.center_x,
        .center_y = camera_.center_y,
        .scale_x = camera_.scale_x,
        .scale_y = camera_.scale_y,
        .show_guides_and_grid = show_guides_,
        .brushed_address_range =
            (viz_mode_ == peelf::ByteVizMode::EntropyAndByteClass2D) ? brushed_range_
                                                                     : std::nullopt,
        .hovered_index = hovered_index_.has_value()
                             ? std::optional<std::size_t>{*hovered_index_}
                             : std::nullopt,
        .selected_index = sel_opt,
    };

    if (viz_mode_ == peelf::ByteVizMode::CantorDustDigram256 && cantor != nullptr &&
        cantor != &snap.cantor) {
        peelf::ByteVizSnapshot brushed_view{};
        brushed_view.cantor = *cantor;
        peelf::rasterize_byte_viz_rgba8_into(
            vp, brushed_view, viz_mode_, color_mode_, cpu_rgba_scratch_);
    } else {
        peelf::rasterize_byte_viz_rgba8_into(
            vp, snap, viz_mode_, color_mode_, cpu_rgba_scratch_);
    }
    canvas_.record_cpu_rgba8_upload(cmd, frame_index, cpu_rgba_scratch_);
}

} // namespace viewer
