#include "decompile/decompile_controller.hpp"

#include "decompile/structured_decompiler.hpp"

#include <exception>
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
        case DecompilerProvider::BinaryNinja:
            return BinaryNinjaDecompiler(
                       spec.settings.python,
                       spec.resources_directory / "bn_decompile.py",
                       runner)
                .decompile(spec.request, stop_token);
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
    , worker_([this](std::stop_token worker_stop) { worker_loop(std::move(worker_stop)); }) {}

DecompileController::~DecompileController() noexcept {
    shutdown();
}

std::uint64_t DecompileController::submit(DecompileJobSpec spec) {
    std::uint64_t seq = 0;
    {
        std::scoped_lock lock(mutex_);
        seq = ++next_sequence_;
        pending_ = PendingJob{
            .sequence = seq,
            .spec = std::move(spec),
        };
        completed_.reset();
        stale_result_discarded_ = false;
        if (active_sequence_ != 0) {
            active_job_stop_.request_stop();
        }
    }
    cv_.notify_all();
    return seq;
}

void DecompileController::cancel_current() noexcept {
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
            pending_.reset();
            completed_ = DecompileJobResult{
                .sequence = next_sequence_,
                .stamp = std::move(cancelled_stamp),
                .cache_key = std::nullopt,
                .root_symbol = std::move(root),
                .thumb = thumb,
                .unit = DecompiledUnit{
                    .status = DecompileStatus::Cancelled,
                    .provider = "Decompiler",
                    .diagnostic = "Decompilation cancelled.",
                },
            };
        }
        if (active_sequence_ != 0) {
            active_job_stop_.request_stop();
        }
    }
    cv_.notify_all();
}

void DecompileController::reset_for_new_target() noexcept {
    {
        std::scoped_lock lock(mutex_);
        ++next_sequence_;
        pending_.reset();
        completed_.reset();
        stale_result_discarded_ = false;
        if (active_sequence_ != 0) {
            active_job_stop_.request_stop();
        }
    }
    cv_.notify_all();
}

void DecompileController::shutdown() noexcept {
    {
        std::scoped_lock lock(mutex_);
        shutting_down_ = true;
        pending_.reset();
        if (active_sequence_ != 0) {
            active_job_stop_.request_stop();
        }
    }
    worker_.request_stop();
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
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
                lock.unlock();
                cv_.notify_all();
                return;
            }
            job = std::move(*pending_);
            pending_.reset();
            active_sequence_ = job.sequence;
            active_job_stop_ = std::stop_source{};
            job_stop = active_job_stop_.get_token();
        }

        DecompiledUnit unit;
        try {
            unit = executor_(job.spec, job_stop);
        } catch (const std::exception& ex) {
            unit = DecompiledUnit{
                .status = DecompileStatus::Failed,
                .provider = "Decompiler",
                .diagnostic = ex.what(),
            };
        } catch (...) {
            unit = DecompiledUnit{
                .status = DecompileStatus::Failed,
                .provider = "Decompiler",
                .diagnostic = "Unhandled exception in decompiler worker",
            };
        }

        {
            std::scoped_lock lock(mutex_);
            const bool was_cancelled =
                job_stop.stop_requested() || worker_stop.stop_requested() || shutting_down_;
            if (active_sequence_ == job.sequence) {
                active_sequence_ = 0;
            }
            if (!shutting_down_ && !worker_stop.stop_requested() && job.sequence == next_sequence_) {
                if (was_cancelled && unit.status != DecompileStatus::Cancelled) {
                    unit = DecompiledUnit{
                        .status = DecompileStatus::Cancelled,
                        .provider = unit.provider.empty() ? "Decompiler" : std::move(unit.provider),
                        .diagnostic = "Decompilation cancelled.",
                    };
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

} // namespace viewer
