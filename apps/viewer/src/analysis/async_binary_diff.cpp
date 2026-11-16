#include "async_binary_diff.hpp"

#include <peelf/error.hpp>

#include <algorithm>
#include <format>
#include <fstream>
#include <utility>

namespace viewer {

namespace {

[[nodiscard]] peelf::Result<std::vector<std::uint8_t>> read_all_file_bytes(
    const std::filesystem::path& path,
    std::stop_token stop_token) {
    if (stop_token.stop_requested()) {
        return peelf::make_error("Binary diff cancelled");
    }
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return peelf::make_error(std::format("Cannot open '{}' for comparison", path.string()));
    }
    const auto end_pos = ifs.tellg();
    if (end_pos < 0) {
        return peelf::make_error(std::format("Cannot read file size of '{}'", path.string()));
    }
    const auto total_size = static_cast<std::size_t>(end_pos);
    std::vector<std::uint8_t> data(total_size);
    ifs.seekg(0, std::ios::beg);

    constexpr std::size_t kChunkBytes = 256u * 1024u;
    std::size_t offset = 0u;
    while (offset < total_size) {
        if (stop_token.stop_requested()) {
            return peelf::make_error("Binary diff cancelled");
        }
        const std::size_t to_read = std::min(kChunkBytes, total_size - offset);
        if (!ifs.read(reinterpret_cast<char*>(data.data() + offset),
                      static_cast<std::streamsize>(to_read))) {
            return peelf::make_error(std::format("Failed reading '{}'", path.string()));
        }
        offset += to_read;
    }
    return data;
}

} // namespace

AsyncBinaryDiffer::~AsyncBinaryDiffer() {
    cancel();
    wait_for_idle();
}

void AsyncBinaryDiffer::reset_for_launch(std::string_view initial_stage) {
    cancel();
    if (worker_.joinable()) {
        worker_.join();
    }
    std::scoped_lock lock(mutex_);
    pending_outcome_.reset();
    stage_.assign(initial_stage.begin(), initial_stage.end());
    completed_steps_.store(0u, std::memory_order_relaxed);
    total_steps_.store(1u, std::memory_order_relaxed);
    running_.store(true, std::memory_order_release);
}

void AsyncBinaryDiffer::update_progress(std::string_view stage,
                                        std::size_t completed,
                                        std::size_t total) {
    completed_steps_.store(completed, std::memory_order_relaxed);
    total_steps_.store(std::max<std::size_t>(1u, total), std::memory_order_relaxed);
    std::scoped_lock lock(mutex_);
    stage_.assign(stage.begin(), stage.end());
}

void AsyncBinaryDiffer::publish_outcome(AsyncDiffOutcome outcome) {
    {
        std::scoped_lock lock(mutex_);
        pending_outcome_ = std::move(outcome);
    }
    running_.store(false, std::memory_order_release);
}

void AsyncBinaryDiffer::start_file_diff(std::uint64_t expected_revision,
                                        std::vector<std::uint8_t> primary_bytes,
                                        std::filesystem::path comparison_path,
                                        peelf::BinaryDiffOptions options) {
    reset_for_launch("Loading comparison binary...");

    worker_ = std::jthread(
        [this,
         expected_revision,
         lhs_buf = std::move(primary_bytes),
         rhs_path = std::move(comparison_path),
         opts = std::move(options)](std::stop_token stop_token) mutable {
            AsyncDiffOutcome out{};
            out.kind = AsyncDiffKind::TwoBinaries;
            out.expected_revision = expected_revision;
            out.comparison_path = rhs_path;
            out.lhs_label = opts.lhs_label;
            out.rhs_label = opts.rhs_label;

            auto rhs_loaded = read_all_file_bytes(rhs_path, stop_token);
            if (!rhs_loaded.has_value()) {
                out.status = stop_token.stop_requested() ? AsyncDiffStatus::Cancelled
                                                         : AsyncDiffStatus::Failed;
                out.error_message = rhs_loaded.error().message;
                publish_outcome(std::move(out));
                return;
            }

            if (stop_token.stop_requested()) {
                out.status = AsyncDiffStatus::Cancelled;
                out.error_message = "Binary diff cancelled";
                publish_outcome(std::move(out));
                return;
            }

            update_progress("Parsing primary & comparison images...", 1u, 6u);
            auto lhs_parsed = peelf::parse_image(lhs_buf);
            if (!lhs_parsed.has_value()) {
                out.status = AsyncDiffStatus::Failed;
                out.error_message = lhs_parsed.error().message;
                publish_outcome(std::move(out));
                return;
            }
            auto rhs_parsed = peelf::parse_image(*rhs_loaded);
            if (!rhs_parsed.has_value()) {
                out.status = AsyncDiffStatus::Failed;
                out.error_message = rhs_parsed.error().message;
                publish_outcome(std::move(out));
                return;
            }

            opts.stop_token = stop_token;
            opts.progress_callback = [this](std::size_t completed,
                                            std::size_t total,
                                            std::string_view stage) {
                update_progress(stage, completed, total);
            };

            auto diff = peelf::compare_binaries(**lhs_parsed, lhs_buf, **rhs_parsed, *rhs_loaded, opts);
            if (!diff.has_value()) {
                out.status = stop_token.stop_requested() ? AsyncDiffStatus::Cancelled
                                                         : AsyncDiffStatus::Failed;
                out.error_message = diff.error().message;
                publish_outcome(std::move(out));
                return;
            }

            out.status = AsyncDiffStatus::Succeeded;
            out.lhs_bytes = std::move(lhs_buf);
            out.lhs_image = std::move(*lhs_parsed);
            out.rhs_bytes = std::move(*rhs_loaded);
            out.rhs_image = std::move(*rhs_parsed);
            out.static_report = std::move(*diff);
            publish_outcome(std::move(out));
        });
}

void AsyncBinaryDiffer::start_live_integrity_diff(
    std::uint64_t expected_revision,
    std::filesystem::path disk_path,
    std::shared_ptr<peelf::IProcessSession> session,
    peelf::ModuleInfo live_module,
    peelf::LiveIntegrityDiffOptions options) {
    reset_for_launch("Reading backing on-disk module...");

    worker_ = std::jthread(
        [this,
         expected_revision,
         path = std::move(disk_path),
         sess = std::move(session),
         mod = std::move(live_module),
         opts = std::move(options)](std::stop_token stop_token) mutable {
            AsyncDiffOutcome out{};
            out.kind = AsyncDiffKind::DiskVsLiveRam;
            out.expected_revision = expected_revision;
            out.comparison_path = path;
            out.live_module = mod;

            if (sess == nullptr) {
                out.status = AsyncDiffStatus::Failed;
                out.error_message = "Live process session is unavailable";
                publish_outcome(std::move(out));
                return;
            }

            auto disk_loaded = read_all_file_bytes(path, stop_token);
            if (!disk_loaded.has_value()) {
                out.status = stop_token.stop_requested() ? AsyncDiffStatus::Cancelled
                                                         : AsyncDiffStatus::Failed;
                out.error_message = disk_loaded.error().message;
                publish_outcome(std::move(out));
                return;
            }

            if (stop_token.stop_requested()) {
                out.status = AsyncDiffStatus::Cancelled;
                out.error_message = "Live module integrity diff cancelled";
                publish_outcome(std::move(out));
                return;
            }

            update_progress("Parsing on-disk module...", 1u, 4u);
            auto disk_parsed = peelf::parse_image(*disk_loaded);
            if (!disk_parsed.has_value()) {
                out.status = AsyncDiffStatus::Failed;
                out.error_message = disk_parsed.error().message;
                publish_outcome(std::move(out));
                return;
            }

            opts.stop_token = stop_token;
            opts.progress_callback = [this](std::size_t completed,
                                            std::size_t total,
                                            std::string_view stage) {
                update_progress(stage, completed, total);
            };

            auto live_diff = peelf::compare_module_disk_to_live(
                **disk_parsed, *disk_loaded, *sess, mod, opts);
            if (!live_diff.has_value()) {
                out.status = stop_token.stop_requested() ? AsyncDiffStatus::Cancelled
                                                         : AsyncDiffStatus::Failed;
                out.error_message = live_diff.error().message;
                publish_outcome(std::move(out));
                return;
            }

            out.status = AsyncDiffStatus::Succeeded;
            out.lhs_bytes = std::move(*disk_loaded);
            out.lhs_image = std::move(*disk_parsed);
            out.live_report = std::move(*live_diff);
            publish_outcome(std::move(out));
        });
}

void AsyncBinaryDiffer::cancel() noexcept {
    if (worker_.joinable()) {
        worker_.request_stop();
    }
}

AsyncDiffProgress AsyncBinaryDiffer::progress() const {
    AsyncDiffProgress snap{};
    snap.running = running_.load(std::memory_order_acquire);
    snap.completed_steps = completed_steps_.load(std::memory_order_relaxed);
    snap.total_steps = std::max<std::size_t>(1u, total_steps_.load(std::memory_order_relaxed));
    std::scoped_lock lock(mutex_);
    snap.stage = stage_;
    return snap;
}

std::optional<AsyncDiffOutcome> AsyncBinaryDiffer::poll_completed(std::uint64_t current_revision) {
    if (running_.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    std::optional<AsyncDiffOutcome> finished;
    {
        std::scoped_lock lock(mutex_);
        if (!pending_outcome_.has_value()) {
            return std::nullopt;
        }
        finished = std::move(pending_outcome_);
        pending_outcome_.reset();
    }

    if (worker_.joinable()) {
        worker_.join();
    }

    if (finished->status == AsyncDiffStatus::Succeeded &&
        finished->expected_revision != current_revision) {
        AsyncDiffOutcome stale{};
        stale.status = AsyncDiffStatus::StaleDiscarded;
        stale.kind = finished->kind;
        stale.expected_revision = finished->expected_revision;
        stale.error_message =
            "Discarded stale binary diff result because the active binary or module changed while comparing";
        return stale;
    }
    return finished;
}

void AsyncBinaryDiffer::wait_for_idle() noexcept {
    if (worker_.joinable()) {
        worker_.join();
    }
}

} // namespace viewer
