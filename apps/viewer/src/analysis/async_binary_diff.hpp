#pragma once

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace viewer {

enum class AsyncDiffStatus : std::uint8_t {
    Succeeded = 0,
    Cancelled = 1,
    Failed = 2,
    StaleDiscarded = 3,
};

enum class AsyncDiffKind : std::uint8_t {
    TwoBinaries = 0,
    DiskVsLiveRam = 1,
};

struct AsyncDiffProgress {
    bool running{false};
    std::size_t completed_steps{0};
    std::size_t total_steps{1};
    std::string stage{};
};

struct AsyncDiffOutcome {
    AsyncDiffStatus status{AsyncDiffStatus::Failed};
    AsyncDiffKind kind{AsyncDiffKind::TwoBinaries};
    std::uint64_t expected_revision{0};
    std::string error_message{};

    std::filesystem::path comparison_path{};
    std::string lhs_label{};
    std::string rhs_label{};
    peelf::ModuleInfo live_module{};

    std::vector<std::uint8_t> lhs_bytes{};
    std::unique_ptr<peelf::IBinaryImage> lhs_image{};
    std::vector<std::uint8_t> rhs_bytes{};
    std::unique_ptr<peelf::IBinaryImage> rhs_image{};

    std::optional<peelf::BinaryDiffReport> static_report{};
    std::optional<peelf::LiveModuleIntegrityReport> live_report{};
};

class AsyncBinaryDiffer {
public:
    AsyncBinaryDiffer() = default;
    ~AsyncBinaryDiffer();

    AsyncBinaryDiffer(const AsyncBinaryDiffer&) = delete;
    AsyncBinaryDiffer& operator=(const AsyncBinaryDiffer&) = delete;

    void start_file_diff(std::uint64_t expected_revision,
                         std::vector<std::uint8_t> primary_bytes,
                         std::filesystem::path comparison_path,
                         peelf::BinaryDiffOptions options = {});

    void start_live_integrity_diff(std::uint64_t expected_revision,
                                   std::filesystem::path disk_path,
                                   std::shared_ptr<peelf::IProcessSession> session,
                                   peelf::ModuleInfo live_module,
                                   peelf::LiveIntegrityDiffOptions options = {});

    void cancel() noexcept;

    [[nodiscard]] bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    [[nodiscard]] AsyncDiffProgress progress() const;

    // Polls for a finished background job. If `current_revision != expected_revision`,
    // returns an outcome with `status == AsyncDiffStatus::StaleDiscarded` and drops
    // the stale comparison artifacts so they are never published onto a newer target.
    [[nodiscard]] std::optional<AsyncDiffOutcome> poll_completed(std::uint64_t current_revision);

    // Blocks until any active worker finishes (primarily for deterministic tests and teardown).
    void wait_for_idle() noexcept;

private:
    void reset_for_launch(std::string_view initial_stage);
    void update_progress(std::string_view stage, std::size_t completed, std::size_t total);
    void publish_outcome(AsyncDiffOutcome outcome);

    mutable std::mutex mutex_{};
    std::atomic<bool> running_{false};
    std::atomic<std::size_t> completed_steps_{0};
    std::atomic<std::size_t> total_steps_{1};
    std::string stage_{};
    std::optional<AsyncDiffOutcome> pending_outcome_{};
    std::jthread worker_{};
};

} // namespace viewer
