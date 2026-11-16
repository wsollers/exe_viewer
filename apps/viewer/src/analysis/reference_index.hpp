#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>

#include "symbols/symbol_index.hpp"

namespace viewer {

enum class ReferenceKind { Call, Branch, Data, AddressConstant };

enum class ReferenceConfidence : std::uint8_t {
    Direct,
    IndirectTable,
    IndirectPointerSlot,
    HeuristicConstant
};

struct Reference {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
    ReferenceKind kind = ReferenceKind::Data;
    std::string instruction;
    std::string string_preview;
    ReferenceConfidence confidence = ReferenceConfidence::Direct;
    std::string evidence;
};

[[nodiscard]] std::string_view reference_kind_name(ReferenceKind kind) noexcept;
[[nodiscard]] std::string_view reference_confidence_name(ReferenceConfidence confidence) noexcept;

struct Annotation { std::string name; std::string comment; };
class AnnotationStore {
public:
    void set(std::uint64_t address, std::string name, std::string comment);
    [[nodiscard]] const Annotation* find(std::uint64_t address) const noexcept;
    [[nodiscard]] const std::map<std::uint64_t, Annotation>& records() const noexcept { return records_; }
    void clear() noexcept { records_.clear(); ++revision_; }
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
private:
    std::map<std::uint64_t, Annotation> records_;
    std::uint64_t revision_ = 0;
};

struct ReferenceScanChunk {
    std::vector<Reference> references;
    std::size_t bytes_scanned = 0;
    bool decode_incomplete = false;
    bool finished = false;
    bool incomplete = false;
};

class ReferenceIndex {
public:
    static constexpr std::size_t kDefaultByteBudget = 4u * 1024u * 1024u;
    static constexpr std::size_t kDefaultChunkBytes = 256u * 1024u;

    // A conservative linear scan of executable file-backed sections, not proof of reachable code.
    [[nodiscard]] static ReferenceIndex build(const peelf::IBinaryImage& image,
        std::span<const std::uint8_t> bytes, bool thumb = false,
        std::size_t byte_budget = kDefaultByteBudget,
        const SymbolIndex* symbols = nullptr);

    // Appends references from one decoded region. Register-dependent targets stay unresolved
    // unless locally proven via a guarded jump table or pointer slot.
    void add_code(std::span<const std::uint8_t> bytes, std::uint64_t address,
        peelf::Architecture architecture, peelf::Endianness endian, bool thumb = false);

    void reset_for_progressive_scan(std::size_t total_executable_bytes, bool scanning = true);
    void append_chunk(ReferenceScanChunk&& chunk);
    void set_scanning(bool scanning) noexcept;
    void mark_failed_incomplete() noexcept;

    [[nodiscard]] std::span<const Reference> records() const noexcept { return records_; }
    [[nodiscard]] std::vector<const Reference*> incoming(std::uint64_t address, std::uint64_t size = 1) const;
    [[nodiscard]] std::vector<const Reference*> outgoing(std::uint64_t address, std::uint64_t size = 1) const;

    [[nodiscard]] std::size_t total_executable_bytes() const noexcept { return total_executable_bytes_; }
    [[nodiscard]] std::size_t scanned_bytes() const noexcept { return scanned_bytes_; }
    [[nodiscard]] double coverage_percent() const noexcept;
    [[nodiscard]] bool is_scanning() const noexcept { return is_scanning_; }
    [[nodiscard]] bool incomplete() const noexcept { return incomplete_; }
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }

private:
    void ensure_lookup_indices() const;

    std::vector<Reference> records_;
    std::size_t total_executable_bytes_ = 0;
    std::size_t scanned_bytes_ = 0;
    bool is_scanning_ = false;
    bool incomplete_ = false;
    std::uint64_t revision_ = 0;

    mutable std::vector<std::pair<std::uint64_t, std::size_t>> by_target_;
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> by_source_;
    mutable bool lookup_dirty_ = false;
};

struct ReferenceScanSnapshot;

// Deterministic, chunked, resumable reference scan job usable synchronously in tests
// or driven on a background std::jthread by AsyncReferenceScanner.
class ReferenceScanJob {
public:
    ReferenceScanJob() = default;
    ReferenceScanJob(const peelf::IBinaryImage& image,
                     std::vector<std::uint8_t> bytes,
                     bool thumb = false,
                     std::size_t byte_budget = ReferenceIndex::kDefaultByteBudget,
                     const SymbolIndex* symbols = nullptr,
                     std::size_t chunk_bytes = ReferenceIndex::kDefaultChunkBytes);

    void set_byte_budget(std::size_t byte_budget) noexcept;
    [[nodiscard]] std::size_t byte_budget() const noexcept { return byte_budget_; }
    [[nodiscard]] std::size_t total_executable_bytes() const noexcept { return total_executable_bytes_; }
    [[nodiscard]] std::size_t scanned_bytes() const noexcept { return scanned_bytes_; }
    [[nodiscard]] bool finished() const noexcept { return finished_; }
    [[nodiscard]] bool incomplete() const noexcept;

    // Advances by at most one chunk (default 256 KiB). Returns std::nullopt if cancelled via stop_token.
    [[nodiscard]] std::optional<ReferenceScanChunk> step(std::stop_token stop = {});

    // Runs chunks into `target` until `byte_budget()` is reached, all executable bytes are scanned,
    // or `stop.stop_requested()` becomes true. Returns true if the scan finished (not cancelled).
    bool run(ReferenceIndex& target, std::stop_token stop = {});

private:
    std::shared_ptr<ReferenceScanSnapshot> snapshot_;
    std::size_t chunk_bytes_ = ReferenceIndex::kDefaultChunkBytes;
    std::size_t byte_budget_ = ReferenceIndex::kDefaultByteBudget;
    std::size_t total_executable_bytes_ = 0;
    std::size_t scanned_bytes_ = 0;
    std::size_t span_index_ = 0;
    std::size_t offset_in_span_ = 0;
    bool decode_incomplete_ = false;
    bool finished_ = true;
};

class AsyncReferenceScanner {
public:
    AsyncReferenceScanner() = default;
    ~AsyncReferenceScanner() noexcept;

    AsyncReferenceScanner(const AsyncReferenceScanner&) = delete;
    AsyncReferenceScanner& operator=(const AsyncReferenceScanner&) = delete;

    void start(ReferenceIndex& target,
               const peelf::IBinaryImage& image,
               std::vector<std::uint8_t> bytes,
               bool thumb = false,
               std::size_t byte_budget = ReferenceIndex::kDefaultByteBudget,
               const SymbolIndex* symbols = nullptr,
               std::size_t chunk_bytes = ReferenceIndex::kDefaultChunkBytes);

    void pause();
    void resume(ReferenceIndex& target);
    void scan_full(ReferenceIndex& target);
    void cancel(ReferenceIndex* target = nullptr) noexcept;

    // Drains completed background chunks into `target` on the caller's thread.
    // Returns the number of chunks merged.
    std::size_t poll(ReferenceIndex& target);

    // Waits for the background worker to become idle (completed, paused, or stopped) and drains into `target`.
    void wait(ReferenceIndex& target);

    [[nodiscard]] bool is_scanning() const noexcept { return active_.load(std::memory_order_acquire) && !paused_.load(std::memory_order_acquire); }
    [[nodiscard]] bool is_paused() const noexcept { return paused_.load(std::memory_order_acquire); }
    [[nodiscard]] bool has_resumable_work() const noexcept;
    [[nodiscard]] bool has_failed() const noexcept;
    [[nodiscard]] std::string last_error() const;

private:
    void worker_loop(std::stop_token stop, std::uint64_t generation);
    void record_worker_failure(std::uint64_t generation, bool is_oom, const char* what_msg) noexcept;

    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    ReferenceScanJob job_;
    std::deque<ReferenceScanChunk> pending_chunks_;
    std::string last_error_;
    std::size_t desired_budget_ = 0;
    std::size_t job_scanned_bytes_ = 0;
    std::size_t job_total_bytes_ = 0;
    bool job_finished_ = true;
    bool worker_failed_ = false;
    bool pending_failure_incomplete_ = false;
    std::uint64_t generation_ = 0;
    std::atomic<bool> active_{false};
    std::atomic<bool> paused_{false};
    std::jthread worker_;
};

} // namespace viewe
