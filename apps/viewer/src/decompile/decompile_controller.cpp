#include "decompile/decompile_controller.hpp"

#include "decompile/structured_decompiler.hpp"

#include <exception>
#include <new>
#include <utility>

namespace viewer {

DecompiledUnit execute_decompile_job(const DecompileJobSpec& spec, std::stop_token stop_token) {
    if (stop_token.stop_requested()) {
        return DecompiledUnit{
            .status = DecompileStatus::Cancelled,
            .provider = "Decompiler",
            .diagnostic = "Decompilation cancelled.",
        };
    }

    BackendRunner runner;
    switch (spec.settings.provider) {
        case DecompilerProvider::Ghidra: {
            auto unit = GhidraDecompiler(spec.settings, spec.resources_directory, runner)
                            .decompile(spec.request, stop_token);
            if (unit.status == DecompileStatus::Unavailable && spec.settings.ghidra_home.empty()) {
                auto fallback = StructuredPseudoCDecompiler{}.decompile(spec.request, stop_token);
                if (fallback.status == DecompileStatus::Ready) {
                    fallback.diagnostic =
                        "Ghidra is not configured; decompiled with built-in Structured Pseudo-C.";
                    return fallback;
                }
            }
            return unit;
        }
        case DecompilerProvider::BinaryNinja: {
            DecompilerSettings bn_settings = spec.settings;
            if (bn_settings.binary_ninja_home.empty()) {
                const BinaryNinjaCapabilityStatus discovered = discover_binary_ninja(bn_settings);
                if (discovered.install_found) {
                    bn_settings.binary_ninja_home = discovered.install_directory;
                }
            }
            return BinaryNinjaDecompiler(
                       bn_settings,
                       spec.resources_directory / "bn_decompile.py",
                       runner)
                .decompile(spec.request, stop_token);
        }
        case DecompilerProvider::StructuredPseudoC:
            return StructuredPseudoCDecompiler{}.decompile(spec.request, stop_token);
        case DecompilerProvider::RetDec:
            return RetDecDecompiler(spec.settings.retdec, runner, spec.settings.timeout_seconds)
                .decompile(spec.request, stop_token);
        case DecompilerProvider::AnnotatedCode:
            return AnnotatedCodeDecompiler{}.decompile(spec.request, stop_token);
    }
    return AnnotatedCodeDecompiler{}.decompile(spec.request, stop_token);
}

DecompileController::DecompileController(WorkFn executor)
    : executor_(executor ? std::move(executor) : WorkFn{execute_decompile_job})
    , fatal_worker_oom_unit_{
          .status = DecompileStatus::Failed,
          .provider = "Decompiler",
          .diagnostic = "Out of memory in decompiler worker.",
      }
    , fatal_worker_error_unit_{
          .status = DecompileStatus::Failed,
          .provider = "Decompiler",
          .diagnostic = "Unhandled exception in decompiler worker",
      } {
    struct LaunchRollbackGuard {
        DecompileController* self;
        bool committed{false};
        explicit LaunchRollbackGuard(DecompileController* s) noexcept : self(s) {}
        LaunchRollbackGuard(const LaunchRollbackGuard&) = delete;
        LaunchRollbackGuard& operator=(const LaunchRollbackGuard&) = delete;
        ~LaunchRollbackGuard() noexcept {
            if (!committed) {
                {
                    std::scoped_lock lock(self->mutex_);
                    self->shutting_down_ = true;
                    self->active_sequence_ = 0;
                    self->active_job_stop_ = std::stop_source{std::nostopstate};
                    self->pending_.reset();
                }
                self->cv_.notify_all();
            }
        }
    } launch_guard{this};

    worker_ = std::jthread([this](std::stop_token worker_stop) noexcept {
        try {
            worker_loop(std::move(worker_stop));
        } catch (const std::bad_alloc&) {
            handle_worker_fatal_failure(/*is_oom=*/true, nullptr);
        } catch (const std::exception& e) {
            handle_worker_fatal_failure(/*is_oom=*/false, e.what());
        } catch (...) {
            handle_worker_fatal_failure(/*is_oom=*/false, nullptr);
        }
    });
    launch_guard.committed = true;
}

DecompileController::~DecompileController() noexcept {
    shutdown();
}

std::uint64_t DecompileController::submit(DecompileJobSpec spec) {
    std::stop_source pre_job_stop{};
    DecompiledUnit pre_cancelled{
        .status = DecompileStatus::Cancelled,
        .provider = "Decompiler",
        .diagnostic = "Decompilation cancelled.",
    };
    DecompiledUnit pre_oom{
        .status = DecompileStatus::Failed,
        .provider = "Decompiler",
        .diagnostic = "Out of memory during decompilation.",
    };
    DecompiledUnit pre_unknown{
        .status = DecompileStatus::Failed,
        .provider = "Decompiler",
        .diagnostic = "Unhandled exception in decompiler worker",
    };

    std::uint64_t seq = 0;
    std::stop_source stop_to_request{std::nostopstate};
    {
        std::scoped_lock lock(mutex_);
        seq = ++next_sequence_;
        pending_ = PendingJob{
            .sequence = seq,
            .spec = std::move(spec),
            .job_stop = std::move(pre_job_stop),
            .cancelled_unit = std::move(pre_cancelled),
            .bad_alloc_unit = std::move(pre_oom),
            .unknown_error_unit = std::move(pre_unknown),
        };
        completed_.reset();
        stale_result_discarded_ = false;
        if (active_sequence_ != 0) {
            stop_to_request = active_job_stop_;
        }
    }
    if (stop_to_request.stop_possible()) {
        stop_to_request.request_stop();
    }
    cv_.notify_all();
    return seq;
}

void DecompileController::cancel_current() noexcept {
    std::stop_source stop_to_request{std::nostopstate};
    {
        std::scoped_lock lock(mutex_);
        if (active_sequence_ == 0 && !pending_.has_value()) {
            return;
        }
        stale_result_discarded_ = false;
        user_cancelled_sequence_ = next_sequence_;

        if (pending_.has_value()) {
            DecompileValidationStamp cancelled_stamp = std::move(pending_->spec.stamp);
            const bool thumb = pending_->spec.request.thumb;
            std::optional<SymbolRecord> root = std::move(pending_->spec.root_symbol);
            DecompiledUnit cancelled_unit = std::move(pending_->cancelled_unit);
            pending_.reset();
            completed_ = DecompileJobResult{
                .sequence = next_sequence_,
                .stamp = std::move(cancelled_stamp),
                .cache_key = std::nullopt,
                .root_symbol = std::move(root),
                .thumb = thumb,
                .unit = std::move(cancelled_unit),
            };
        }
        if (active_sequence_ != 0) {
            stop_to_request = active_job_stop_;
        }
    }
    if (stop_to_request.stop_possible()) {
        stop_to_request.request_stop();
    }
    cv_.notify_all();
}

void DecompileController::reset_for_new_target() noexcept {
    std::stop_source stop_to_request{std::nostopstate};
    {
        std::scoped_lock lock(mutex_);
        ++next_sequence_;
        pending_.reset();
        completed_.reset();
        stale_result_discarded_ = false;
        if (active_sequence_ != 0) {
            stop_to_request = active_job_stop_;
        }
    }
    if (stop_to_request.stop_possible()) {
        stop_to_request.request_stop();
    }
    cv_.notify_all();
}

void DecompileController::shutdown() noexcept {
    std::stop_source stop_to_request{std::nostopstate};
    {
        std::scoped_lock lock(mutex_);
        shutting_down_ = true;
        pending_.reset();
        if (active_sequence_ != 0) {
            stop_to_request = active_job_stop_;
        }
    }
    if (stop_to_request.stop_possible()) {
        stop_to_request.request_stop();
    }
    worker_.request_stop();
    cv_.notify_all();
    if (worker_.joinable()) {
        try {
            worker_.join();
        } catch (...) {
        }
    }
}

void DecompileController::wait_for_idle() const {
    std::unique_lock lock(mutex_);
    cv_.wait(lock, [this] {
        return shutting_down_ || (active_sequence_ == 0 && !pending_.has_value());
    });
}

bool DecompileController::is_busy() const noexcept {
    std::scoped_lock lock(mutex_);
    return active_sequence_ != 0 || pending_.has_value();
}

std::uint64_t DecompileController::latest_sequence() const noexcept {
    std::scoped_lock lock(mutex_);
    return next_sequence_;
}

std::optional<DecompileJobResult> DecompileController::poll_completed(
    const DecompileValidationStamp& current_stamp) {
    std::scoped_lock lock(mutex_);
    if (!completed_.has_value()) {
        return std::nullopt;
    }

    DecompileJobResult result = std::move(*completed_);
    completed_.reset();

    if (result.sequence != next_sequence_) {
        return std::nullopt;
    }

    if (!result.stamp.matches(current_stamp)) {
        if (result.stamp.target_identity == current_stamp.target_identity &&
            result.stamp.file_generation == current_stamp.file_generation) {
            stale_result_discarded_ = true;
        }
        return std::nullopt;
    }

    stale_result_discarded_ = false;
    return result;
}

bool DecompileController::consume_stale_discard_notice() noexcept {
    std::scoped_lock lock(mutex_);
    return std::exchange(stale_result_discarded_, false);
}

void DecompileController::worker_loop(std::stop_token worker_stop) {
    while (true) {
        PendingJob job;
        std::stop_token job_stop;
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, worker_stop, [this] {
                return shutting_down_ || pending_.has_value();
            });
            if (shutting_down_ || worker_stop.stop_requested()) {
                active_sequence_ = 0;
                active_job_stop_ = std::stop_source{std::nostopstate};
                lock.unlock();
                cv_.notify_all();
                return;
            }
            job = std::move(*pending_);
            pending_.reset();
            active_sequence_ = job.sequence;
            active_job_stop_ = std::move(job.job_stop);
            job_stop = active_job_stop_.get_token();
        }

        DecompiledUnit unit;
        try {
            unit = executor_(job.spec, job_stop);
        } catch (const std::bad_alloc&) {
            unit = std::move(job.bad_alloc_unit);
        } catch (const std::exception& ex) {
            try {
                const char* what_msg = ex.what();
                unit = DecompiledUnit{
                    .status = DecompileStatus::Failed,
                    .provider = std::move(job.unknown_error_unit.provider),
                    .diagnostic = (what_msg != nullptr && *what_msg != '\0')
                                      ? std::string(what_msg)
                                      : std::move(job.unknown_error_unit.diagnostic),
                };
            } catch (...) {
                unit = std::move(job.bad_alloc_unit);
            }
        } catch (...) {
            unit = std::move(job.unknown_error_unit);
        }

        {
            std::scoped_lock lock(mutex_);
            const bool was_cancelled =
                job_stop.stop_requested() || worker_stop.stop_requested() || shutting_down_;
            if (active_sequence_ == job.sequence) {
                active_sequence_ = 0;
                active_job_stop_ = std::stop_source{std::nostopstate};
            }
            if (!shutting_down_ && !worker_stop.stop_requested() && job.sequence == next_sequence_) {
                if (was_cancelled && unit.status != DecompileStatus::Cancelled) {
                    std::string keep_provider =
                        unit.provider.empty() ? std::move(job.cancelled_unit.provider)
                                              : std::move(unit.provider);
                    unit = std::move(job.cancelled_unit);
                    unit.provider = std::move(keep_provider);
                }
                if (!was_cancelled || user_cancelled_sequence_ == job.sequence) {
                    completed_ = DecompileJobResult{
                        .sequence = job.sequence,
                        .stamp = std::move(job.spec.stamp),
                        .cache_key = std::move(job.spec.cache_key),
                        .root_symbol = std::move(job.spec.root_symbol),
                        .thumb = job.spec.request.thumb,
                        .unit = std::move(unit),
                    };
                }
            }
        }
        cv_.notify_all();
    }
}

void DecompileController::handle_worker_fatal_failure(bool is_oom, const char* what_msg) noexcept {
    {
        std::scoped_lock lock(mutex_);
        if (!shutting_down_ && pending_.has_value()) {
            PendingJob failed_job = std::move(*pending_);
            pending_.reset();
            DecompiledUnit unit = is_oom ? std::move(failed_job.bad_alloc_unit)
                                         : std::move(failed_job.unknown_error_unit);
            if (!is_oom && what_msg != nullptr && *what_msg != '\0') {
                try {
                    unit.diagnostic = what_msg;
                } catch (...) {
                    unit = std::move(fatal_worker_oom_unit_);
                }
            }
            if (failed_job.sequence == next_sequence_) {
                completed_ = DecompileJobResult{
                    .sequence = failed_job.sequence,
                    .stamp = std::move(failed_job.spec.stamp),
                    .cache_key = std::move(failed_job.spec.cache_key),
                    .root_symbol = std::move(failed_job.spec.root_symbol),
                    .thumb = failed_job.spec.request.thumb,
                    .unit = std::move(unit),
                };
            }
        } else if (!shutting_down_ && active_sequence_ != 0 && active_sequence_ == next_sequence_) {
            DecompiledUnit unit = is_oom ? std::move(fatal_worker_oom_unit_)
                                         : std::move(fatal_worker_error_unit_);
            if (!is_oom && what_msg != nullptr && *what_msg != '\0') {
                try {
                    unit.diagnostic = what_msg;
                } catch (...) {
                    unit = std::move(fatal_worker_oom_unit_);
                }
            }
            completed_ = DecompileJobResult{
                .sequence = active_sequence_,
                .unit = std::move(unit),
            };
        }
        active_sequence_ = 0;
        active_job_stop_ = std::stop_source{std::nostopstate};
        pending_.reset();
        shutting_down_ = true;
    }
    cv_.notify_all();
}

} // namespace viewer
