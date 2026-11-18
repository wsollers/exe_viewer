#pragma once

#include "decompile/decompiler.hpp"

#include <compare>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>

namespace viewer {

struct DecompileValidationStamp {
    std::string target_identity{};
    std::uint64_t file_generation = 0;
    std::uint64_t edit_revision = 0;
    std::uint64_t snapshot_revision = 0;

    [[nodiscard]] bool matches(const DecompileValidationStamp& current) const noexcept {
        return target_identity == current.target_identity &&
               file_generation == current.file_generation &&
               edit_revision == current.edit_revision &&
               snapshot_revision == current.snapshot_revision;
    }

    auto operator<=>(const DecompileValidationStamp&) const = default;
};

struct DecompileJobSpec {
    DecompileRequest request{};
    DecompilerSettings settings{};
    std::filesystem::path resources_directory{};
    DecompileValidationStamp stamp{};
    std::optional<DecompileCacheKey> cache_key{};
    std::optional<SymbolRecord> root_symbol{};
};

struct DecompileJobResult {
    std::uint64_t sequence = 0;
    DecompileValidationStamp stamp{};
    std::optional<DecompileCacheKey> cache_key{};
    std::optional<SymbolRecord> root_symbol{};
    bool thumb = false;
    DecompiledUnit unit{};
};

[[nodiscard]] DecompiledUnit execute_decompile_job(const DecompileJobSpec& spec,
                                                   std::stop_token stop_token);

class DecompileController {
public:
    using WorkFn = std::function<DecompiledUnit(const DecompileJobSpec&, std::stop_token)>;

    explicit DecompileController(WorkFn executor = execute_decompile_job);
    ~DecompileController() noexcept;

    DecompileController(const DecompileController&) = delete;
    DecompileController& operator=(const DecompileController&) = delete;
    DecompileController(DecompileController&&) = delete;
    DecompileController& operator=(DecompileController&&) = delete;

    std::uint64_t submit(DecompileJobSpec spec);
    void cancel_current() noexcept;
    void reset_for_new_target() noexcept;
    void shutdown() noexcept;
    void wait_for_idle() const;

    [[nodiscard]] bool is_busy() const noexcept;
    [[nodiscard]] std::uint64_t latest_sequence() const noexcept;
    [[nodiscard]] std::optional<DecompileJobResult> poll_completed(
        const DecompileValidationStamp& current_stamp);
    [[nodiscard]] bool consume_stale_discard_notice() noexcept;

private:
    struct PendingJob {
        std::uint64_t sequence = 0;
        DecompileJobSpec spec{};
        std::stop_source job_stop{std::nostopstate};
        DecompiledUnit cancelled_unit{};
        DecompiledUnit bad_alloc_unit{};
        DecompiledUnit unknown_error_unit{};
    };

    void worker_loop(std::stop_token worker_stop);
    void handle_worker_fatal_failure(bool is_oom, const char* what_msg) noexcept;

    WorkFn executor_;
    mutable std::mutex mutex_;
    mutable std::condition_variable_any cv_;
    std::uint64_t next_sequence_ = 0;
    std::uint64_t active_sequence_ = 0;
    std::uint64_t user_cancelled_sequence_ = 0;
    std::optional<PendingJob> pending_;
    std::optional<DecompileJobResult> completed_;
    DecompiledUnit fatal_worker_oom_unit_{};
    DecompiledUnit fatal_worker_error_unit_{};
    std::stop_source active_job_stop_{std::nostopstate};
    bool shutting_down_ = false;
    bool stale_result_discarded_ = false;
    std::jthread worker_;
};

} // namespace viewer
