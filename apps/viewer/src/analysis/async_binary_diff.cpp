#include "async_binary_diff.hpp"

#include <peelf/error.hpp>

#include <algorithm>
#include <exception>
#include <format>
#include <fstream>
#include <new>
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

AsyncBinaryDiffer::~AsyncBinaryDiffer() noexcept {
    cancel();
    wait_for_idle();
}

void AsyncBinaryDiffer::reset_for_launch(AsyncDiffKind kind,
                                         std::uint64_t expected_revision,
                                         std::string_view initial_stage) {
    cancel();
    wait_for_idle();

    AsyncDiffOutcome pre_oom{};
    pre_oom.status = AsyncDiffStatus::Failed;
    pre_oom.kind = kind;
    pre_oom.expected_revision = expected_revision;
    pre_oom.error_message = "Out of memory during binary diff";

    AsyncDiffOutcome pre_unknown{};
    pre_unknown.status = AsyncDiffStatus::Failed;
    pre_unknown.kind = kind;
    pre_unknown.expected_revision = expected_revision;
    pre_unknown.error_message = "Unhandled exception in binary diff worker";

    std::string next_stage(initial_stage);
    next_stage.reserve(128u);

    std::scoped_lock lock(mutex_);
    pending_outcome_.reset();
    oom_outcome_ = std::move(pre_oom);
    unknown_exception_outcome_ = std::move(pre_unknown);
    stage_ = std::move(next_stage);
    completed_steps_.store(0u, std::memory_order_relaxed);
    total_steps_.store(1u, std::memory_order_relaxed);
    running_.store(true, std::memory_order_release);
}

void AsyncBinaryDiffer::rollback_failed_launch() noexcept {
    {
        std::scoped_lock lock(mutex_);
        pending_outcome_.reset();
        stage_.clear();
    }
    completed_steps_.store(0u, std::memory_order_relaxed);
    total_steps_.store(1u, std::memory_order_relaxed);
    running_.store(false, std::memory_order_release);
}

void AsyncBinaryDiffer::update_progress(std::string_view stage,
                                        std::size_t completed,
                                        std::size_t total) {
    completed_steps_.store(completed, std::memory_order_relaxed);
    total_steps_.store(std::max<std::size_t>(1u, total), std::memory_order_relaxed);
    std::scoped_lock lock(mutex_);
    stage_.assign(stage.begin(), stage.end());
}

void AsyncBinaryDiffer::publish_outcome(AsyncDiffOutcome outcome) noexcept {
    {
        std::scoped_lock lock(mutex_);
        pending_outcome_ = std::move(outcome);
    }
    running_.store(false, std::memory_order_release);
}

void AsyncBinaryDiffer::publish_preallocated_failure(bool is_oom, bool stop_requested) noexcept {
    {
        std::scoped_lock lock(mutex_);
        AsyncDiffOutcome& fallback = is_oom ? oom_outcome_ : unknown_exception_outcome_;
        if (stop_requested && !is_oom) {
            fallback.status = AsyncDiffStatus::Cancelled;
        }
        pending_outcome_ = std::move(fallback);
    }
    running_.store(false, std::memory_order_release);
}

void AsyncBinaryDiffer::publish_exception_failure(AsyncDiffKind kind,
                                                  std::uint64_t expected_revision,
                                                  const char* what_msg,
                                                  bool stop_requested) noexcept {
    try {
        AsyncDiffOutcome out{};
        out.status = AsyncDiffStatus::Failed;
        out.kind = kind;
        out.expected_revision = expected_revision;
        out.error_message = (what_msg != nullptr && *what_msg != '\0')
                                ? std::string(what_msg)
                                : std::string("Unhandled std::exception in binary diff worker");
        publish_outcome(std::move(out));
    } catch (...) {
        publish_preallocated_failure(/*is_oom=*/true, stop_requested);
    }
}

void AsyncBinaryDiffer::start_file_diff(std::uint64_t expected_revision,
                                        std::vector<std::uint8_t> primary_bytes,
                                        std::filesystem::path comparison_path,
                                        peelf::BinaryDiffOptions options) {
    reset_for_launch(AsyncDiffKind::TwoBinaries, expected_revision, "Loading comparison binary...");

    struct LaunchRollbackGuard {
        AsyncBinaryDiffer* self;
        bool committed{false};
        explicit LaunchRollbackGuard(AsyncBinaryDiffer* s) noexcept : self(s) {}
        LaunchRollbackGuard(const LaunchRollbackGuard&) = delete;
        LaunchRollbackGuard& operator=(const LaunchRollbackGuard&) = delete;
        ~LaunchRollbackGuard() noexcept {
            if (!committed) {
                self->rollback_failed_launch();
            }
        }
    } launch_guard{this};

    worker_ = std::jthread(
        [this,
         expected_revision,
         lhs_buf = std::move(primary_bytes),
         rhs_path = std::move(comparison_path),
         opts = std::move(options)](std::stop_token stop_token) mutable noexcept {
            try {
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

                auto caller_progress = std::move(opts.progress_callback);
                opts.stop_token = stop_token;
                opts.progress_callback = [this, caller_progress = std::move(caller_progress)](
                                             std::size_t completed,
                                             std::size_t total,
                                             std::string_view stage) {
                    update_progress(stage, completed, total);
                    if (caller_progress) {
                        caller_progress(completed, total, stage);
                    }
                };

                auto diff =
                    peelf::compare_binaries(**lhs_parsed, lhs_buf, **rhs_parsed, *rhs_loaded, opts);
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
            } catch (const std::bad_alloc&) {
                publish_preallocated_failure(/*is_oom=*/true, stop_token.stop_requested());
            } catch (const std::exception& e) {
                publish_exception_failure(AsyncDiffKind::TwoBinaries,
                                          expected_revision,
                                          e.what(),
                                          stop_token.stop_requested());
            } catch (...) {
                publish_preallocated_failure(/*is_oom=*/false, stop_token.stop_requested());
            }
        });
    launch_guard.committed = true;
}

void AsyncBinaryDiffer::start_live_integrity_diff(
    std::uint64_t expected_revision,
    std::filesystem::path disk_path,
    std::shared_ptr<peelf::IProcessSession> session,
    peelf::ModuleInfo live_module,
    peelf::LiveIntegrityDiffOptions options) {
    reset_for_launch(AsyncDiffKind::DiskVsLiveRam,
                     expected_revision,
                     "Reading backing on-disk module...");

    struct LaunchRollbackGuard {
        AsyncBinaryDiffer* self;
        bool committed{false};
        explicit LaunchRollbackGuard(AsyncBinaryDiffer* s) noexcept : self(s) {}
        LaunchRollbackGuard(const LaunchRollbackGuard&) = delete;
        LaunchRollbackGuard& operator=(const LaunchRollbackGuard&) = delete;
        ~LaunchRollbackGuard() noexcept {
            if (!committed) {
                self->rollback_failed_launch();
            }
        }
    } launch_guard{this};

    worker_ = std::jthread(
        [this,
         expected_revision,
         path = std::move(disk_path),
         sess = std::move(session),
         mod = std::move(live_module),
         opts = std::move(options)](std::stop_token stop_token) mutable noexcept {
            try {
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

                auto caller_progress = std::move(opts.progress_callback);
                opts.stop_token = stop_token;
                opts.progress_callback = [this, caller_progress = std::move(caller_progress)](
                                             std::size_t completed,
                                             std::size_t total,
                                             std::string_view stage) {
                    update_progress(stage, completed, total);
                    if (caller_progress) {
                        caller_progress(completed, total, stage);
                    }
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
            } catch (const std::bad_alloc&) {
                publish_preallocated_failure(/*is_oom=*/true, stop_token.stop_requested());
            } catch (const std::exception& e) {
                publish_exception_failure(AsyncDiffKind::DiskVsLiveRam,
                                          expected_revision,
                                          e.what(),
                                          stop_token.stop_requested());
            } catch (...) {
                publish_preallocated_failure(/*is_oom=*/false, stop_token.stop_requested());
            }
        });
    launch_guard.committed = true;
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
        try {
            worker_.join();
        } catch (...) {
        }
    }
}

} // namespace viewer
