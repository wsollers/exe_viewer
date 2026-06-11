#pragma once

#include "peelf/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace peelf {

struct PatchInterval {
    std::uint64_t offset{};
    std::vector<std::uint8_t> original;
    std::vector<std::uint8_t> patched;

    [[nodiscard]] std::uint64_t end_offset() const noexcept {
        return offset + static_cast<std::uint64_t>(patched.size());
    }
};

struct PatchEdit {
    std::uint64_t offset{};
    std::vector<std::uint8_t> before;
    std::vector<std::uint8_t> after;
    std::string label;
};

struct PendingPatchWrite {
    std::uint64_t offset{};
    std::vector<std::uint8_t> bytes;
};

class PagedBinaryImage;

class PatchTransaction {
public:
    PatchTransaction(PagedBinaryImage& image, std::string label);

    [[nodiscard]] Result<void> write(std::uint64_t offset, std::span<const std::uint8_t> bytes);
    [[nodiscard]] Result<void> commit();
    void rollback() noexcept;

    [[nodiscard]] bool empty() const noexcept { return writes_.empty(); }
    [[nodiscard]] bool committed() const noexcept { return committed_; }

private:
    PagedBinaryImage* image_{};
    std::string label_;
    std::vector<PendingPatchWrite> writes_;
    bool committed_{false};
};

class PagedBinaryImage {
public:
    static constexpr std::uint64_t default_page_size = 4096;

    PagedBinaryImage() = default;

    [[nodiscard]] static Result<PagedBinaryImage> open(std::filesystem::path path,
                                                       std::uint64_t page_size = default_page_size);

    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    [[nodiscard]] std::uint64_t page_size() const noexcept { return page_size_; }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] bool dirty() const noexcept { return !patches_.empty(); }

    [[nodiscard]] Result<std::vector<std::uint8_t>> read_original(std::uint64_t offset,
                                                                  std::uint64_t size) const;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_effective(std::uint64_t offset,
                                                                   std::uint64_t size) const;

    [[nodiscard]] std::vector<PatchInterval> changed_intervals() const;
    [[nodiscard]] std::vector<PatchInterval> changed_intervals(std::uint64_t offset,
                                                               std::uint64_t size) const;

    [[nodiscard]] PatchTransaction begin_transaction(std::string label);
    [[nodiscard]] Result<void> apply_patch(std::uint64_t offset,
                                           std::span<const std::uint8_t> bytes,
                                           std::string label);
    [[nodiscard]] Result<void> undo();
    [[nodiscard]] Result<void> redo();

private:
    friend class PatchTransaction;

    [[nodiscard]] Result<void> validate_range(std::uint64_t offset, std::uint64_t size) const;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_file_range(std::uint64_t offset,
                                                                    std::uint64_t size) const;
    [[nodiscard]] Result<std::vector<std::uint8_t>> load_page(std::uint64_t page_index) const;

    [[nodiscard]] Result<void> apply_replacement_no_history(std::uint64_t offset,
                                                            std::span<const std::uint8_t> bytes);
    [[nodiscard]] Result<void> apply_transaction(std::string label,
                                                 std::span<const PendingPatchWrite> writes);

    std::filesystem::path path_;
    std::uint64_t size_{};
    std::uint64_t page_size_{default_page_size};
    mutable std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> page_cache_;
    std::map<std::uint64_t, PatchInterval> patches_;
    std::vector<PatchEdit> undo_stack_;
    std::vector<PatchEdit> redo_stack_;
};

} // namespace peelf
