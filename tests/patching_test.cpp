#include "peelf/patching.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] std::filesystem::path write_temp_binary(std::vector<std::uint8_t> bytes) {
    static std::atomic<std::uint64_t> counter{0};
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string test_name = info != nullptr ? info->name() : "case";
    const auto nonce = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto path = std::filesystem::temp_directory_path() /
                      std::filesystem::path(std::format(
                          "peelf_patching_{}_{}_{}.bin",
                          test_name,
                          nonce,
                          counter.fetch_add(1, std::memory_order_relaxed)));
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return path;
}

} // namespace

TEST(PagedBinaryImage, ReadsAcrossPageBoundariesFromDisk) {
    std::vector<std::uint8_t> bytes(32);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }

    auto image = peelf::PagedBinaryImage::open(write_temp_binary(bytes), 8);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    auto read = image->read_effective(6, 8);
    ASSERT_TRUE(read.has_value()) << read.error().message;
    ASSERT_EQ(*read, (std::vector<std::uint8_t>{6, 7, 8, 9, 10, 11, 12, 13}));
}

TEST(PagedBinaryImage, AppliesTransactionAcrossPageBoundaryAndUndoRedo) {
    std::vector<std::uint8_t> bytes(32);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }

    auto image = peelf::PagedBinaryImage::open(write_temp_binary(bytes), 8);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    auto tx = image->begin_transaction("patch across page");
    const std::vector<std::uint8_t> patch{0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_TRUE(tx.write(7, patch).has_value());
    ASSERT_TRUE(tx.commit().has_value());

    auto effective = image->read_effective(6, 7);
    ASSERT_TRUE(effective.has_value()) << effective.error().message;
    EXPECT_EQ(*effective, (std::vector<std::uint8_t>{6, 0xAA, 0xBB, 0xCC, 0xDD, 11, 12}));

    auto original = image->read_original(6, 7);
    ASSERT_TRUE(original.has_value()) << original.error().message;
    EXPECT_EQ(*original, (std::vector<std::uint8_t>{6, 7, 8, 9, 10, 11, 12}));

    ASSERT_TRUE(image->undo().has_value());
    auto undone = image->read_effective(6, 7);
    ASSERT_TRUE(undone.has_value()) << undone.error().message;
    EXPECT_EQ(*undone, *original);

    ASSERT_TRUE(image->redo().has_value());
    auto redone = image->read_effective(6, 7);
    ASSERT_TRUE(redone.has_value()) << redone.error().message;
    EXPECT_EQ(*redone, *effective);
}

TEST(PagedBinaryImage, NormalizesOverlappingPatchesAndTracksOriginalBytes) {
    std::vector<std::uint8_t> bytes(32);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }

    auto image = peelf::PagedBinaryImage::open(write_temp_binary(bytes), 8);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    ASSERT_TRUE(image->apply_patch(4, std::vector<std::uint8_t>{0xA0, 0xA1, 0xA2, 0xA3}, "first")
                    .has_value());
    ASSERT_TRUE(image->apply_patch(6, std::vector<std::uint8_t>{0xB0, 0xB1, 0xB2, 0xB3}, "overlap")
                    .has_value());

    auto effective = image->read_effective(4, 6);
    ASSERT_TRUE(effective.has_value()) << effective.error().message;
    EXPECT_EQ(*effective, (std::vector<std::uint8_t>{0xA0, 0xA1, 0xB0, 0xB1, 0xB2, 0xB3}));

    const auto intervals = image->changed_intervals();
    ASSERT_EQ(intervals.size(), 1u);
    EXPECT_EQ(intervals[0].offset, 4u);
    EXPECT_EQ(intervals[0].original, (std::vector<std::uint8_t>{4, 5, 6, 7, 8, 9}));
    EXPECT_EQ(intervals[0].patched, (std::vector<std::uint8_t>{0xA0, 0xA1, 0xB0, 0xB1, 0xB2, 0xB3}));

    ASSERT_TRUE(image->undo().has_value());
    auto after_undo = image->read_effective(4, 6);
    ASSERT_TRUE(after_undo.has_value()) << after_undo.error().message;
    EXPECT_EQ(*after_undo, (std::vector<std::uint8_t>{0xA0, 0xA1, 0xA2, 0xA3, 8, 9}));
}

TEST(PagedBinaryImage, RevertingBytesRemovesCleanIntervals) {
    std::vector<std::uint8_t> bytes(16);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }

    auto image = peelf::PagedBinaryImage::open(write_temp_binary(bytes), 4);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    ASSERT_TRUE(image->apply_patch(4, std::vector<std::uint8_t>{0xFE, 0xED}, "patch").has_value());
    EXPECT_TRUE(image->dirty());

    ASSERT_TRUE(image->apply_patch(4, std::vector<std::uint8_t>{4, 5}, "revert").has_value());
    EXPECT_FALSE(image->dirty());
    EXPECT_TRUE(image->changed_intervals().empty());
}

TEST(PagedBinaryImage, CoalescesAdjacentPatches) {
    std::vector<std::uint8_t> bytes(16);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }

    auto image = peelf::PagedBinaryImage::open(write_temp_binary(bytes), 4);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    ASSERT_TRUE(image->apply_patch(4, std::vector<std::uint8_t>{0xA0, 0xA1}, "left").has_value());
    ASSERT_TRUE(image->apply_patch(6, std::vector<std::uint8_t>{0xB0, 0xB1}, "right").has_value());

    const auto intervals = image->changed_intervals();
    ASSERT_EQ(intervals.size(), 1u);
    EXPECT_EQ(intervals[0].offset, 4u);
    EXPECT_EQ(intervals[0].original, (std::vector<std::uint8_t>{4, 5, 6, 7}));
    EXPECT_EQ(intervals[0].patched, (std::vector<std::uint8_t>{0xA0, 0xA1, 0xB0, 0xB1}));
}

TEST(PagedBinaryImage, WritesEffectiveBytesToNewFileWithoutMutatingOriginal) {
    std::vector<std::uint8_t> bytes(16);
    for (std::uint8_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = i;
    }
    const std::filesystem::path input_path = write_temp_binary(bytes);
    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "peelf_patching_test_output.bin";
    std::filesystem::remove(output_path);

    auto image = peelf::PagedBinaryImage::open(input_path, 4);
    ASSERT_TRUE(image.has_value()) << image.error().message;
    ASSERT_TRUE(image->apply_patch(6, std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC}, "export patch")
                    .has_value());

    ASSERT_TRUE(image->write_effective_to(output_path).has_value());

    auto exported = peelf::PagedBinaryImage::open(output_path, 4);
    ASSERT_TRUE(exported.has_value()) << exported.error().message;
    auto exported_bytes = exported->read_original(0, exported->size());
    ASSERT_TRUE(exported_bytes.has_value()) << exported_bytes.error().message;
    EXPECT_EQ(*exported_bytes,
              (std::vector<std::uint8_t>{0, 1, 2, 3, 4, 5, 0xAA, 0xBB, 0xCC, 9, 10, 11, 12, 13, 14, 15}));

    auto original = image->read_original(6, 3);
    ASSERT_TRUE(original.has_value()) << original.error().message;
    EXPECT_EQ(*original, (std::vector<std::uint8_t>{6, 7, 8}));
}

TEST(PagedBinaryImage, RefusesToOverwriteExistingOutputByDefault) {
    const std::filesystem::path input_path = write_temp_binary({0, 1, 2, 3});
    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "peelf_patching_existing_output.bin";
    {
        std::ofstream file(output_path, std::ios::binary | std::ios::trunc);
        const std::uint8_t marker = 0xFE;
        file.write(reinterpret_cast<const char*>(&marker), 1);
    }

    auto image = peelf::PagedBinaryImage::open(input_path, 4);
    ASSERT_TRUE(image.has_value()) << image.error().message;
    EXPECT_FALSE(image->write_effective_to(output_path).has_value());

    ASSERT_TRUE(image->write_effective_to(output_path, true).has_value());
    auto exported = peelf::PagedBinaryImage::open(output_path, 4);
    ASSERT_TRUE(exported.has_value()) << exported.error().message;
    auto exported_bytes = exported->read_original(0, exported->size());
    ASSERT_TRUE(exported_bytes.has_value()) << exported_bytes.error().message;
    EXPECT_EQ(*exported_bytes, (std::vector<std::uint8_t>{0, 1, 2, 3}));
}

TEST(PagedBinaryImage, SparseAndOverlappingTransactionUndoRedo) {
    const auto path = write_temp_binary({0});
    constexpr std::uint64_t distant = 256ull * 1024 * 1024;
    { std::ofstream file(path, std::ios::binary | std::ios::in | std::ios::out);
      file.seekp(distant); file.put(0); }
    auto image = peelf::PagedBinaryImage::open(path);
    ASSERT_TRUE(image);
    auto tx = image->begin_transaction("sparse overlap");
    ASSERT_TRUE(tx.write(0, std::vector<std::uint8_t>{1, 2}));
    ASSERT_TRUE(tx.write(1, std::vector<std::uint8_t>{3}));
    ASSERT_TRUE(tx.write(distant, std::vector<std::uint8_t>{4}));
    ASSERT_TRUE(tx.commit());
    EXPECT_EQ(*image->read_effective(0, 2), (std::vector<std::uint8_t>{1, 3}));
    EXPECT_EQ(*image->read_effective(distant, 1), (std::vector<std::uint8_t>{4}));
    ASSERT_TRUE(image->undo());
    EXPECT_FALSE(image->dirty());
    ASSERT_TRUE(image->redo());
    EXPECT_EQ(*image->read_effective(0, 2), (std::vector<std::uint8_t>{1, 3}));
    EXPECT_EQ(*image->read_effective(distant, 1), (std::vector<std::uint8_t>{4}));
}

TEST(PagedBinaryImage, FailedCommitRestoresPatchesAndHistory) {
    const auto path = write_temp_binary(std::vector<std::uint8_t>(16384));
    auto image = peelf::PagedBinaryImage::open(path);
    ASSERT_TRUE(image);
    ASSERT_TRUE(image->apply_patch(0, std::vector<std::uint8_t>{7}, "prior"));
    auto tx = image->begin_transaction("will fail");
    ASSERT_TRUE(tx.write(1, std::vector<std::uint8_t>{8}));
    ASSERT_TRUE(tx.write(12288, std::vector<std::uint8_t>{9}));
    std::filesystem::resize_file(path, 4096);
    EXPECT_FALSE(tx.commit());
    EXPECT_FALSE(tx.committed());
    EXPECT_EQ(*image->read_effective(0, 2), (std::vector<std::uint8_t>{7, 0}));
    ASSERT_TRUE(image->undo());
    EXPECT_FALSE(image->dirty());
    EXPECT_FALSE(image->can_undo());
}

TEST(PagedBinaryImage, SameFileSaveAsOverwritePreservesUncachedPagesAndReopensCleanly) {
    constexpr std::uint64_t kPageSize = 64;
    constexpr std::size_t kTotalSize = 8 * static_cast<std::size_t>(kPageSize); // 8 pages
    std::vector<std::uint8_t> initial(kTotalSize);
    for (std::size_t i = 0; i < initial.size(); ++i) {
        initial[i] = static_cast<std::uint8_t>((i * 37u + 0x5Au) & 0xFFu);
    }

    const std::filesystem::path input_path = write_temp_binary(initial);
    {
        auto image = peelf::PagedBinaryImage::open(input_path, kPageSize);
        ASSERT_TRUE(image.has_value()) << image.error().message;

        // Patch only page 0 and page 5; pages 1..4 and 6..7 remain completely uncached in memory.
        const std::vector<std::uint8_t> p0{0xDE, 0xAD, 0xBE, 0xEF};
        const std::vector<std::uint8_t> p5{0xCA, 0xFE};
        ASSERT_TRUE(image->apply_patch(4, p0, "patch page 0").has_value());
        ASSERT_TRUE(image->apply_patch(5 * kPageSize + 10, p5, "patch page 5").has_value());

        std::vector<std::uint8_t> expected = initial;
        std::copy(p0.begin(), p0.end(), expected.begin() + 4);
        std::copy(p5.begin(), p5.end(), expected.begin() + static_cast<std::ptrdiff_t>(5 * kPageSize + 10));

        // Without overwrite=true, same-file save_as must refuse without truncating input_path.
        EXPECT_FALSE(image->save_as(input_path, /*overwrite=*/false).has_value());

        // With overwrite=true, same-file save_as must stage to a sibling temp file, atomically replace
        // input_path without truncating uncached pages, and reopen the backing stream cleanly.
        ASSERT_TRUE(image->save_as(input_path, /*overwrite=*/true).has_value());

        // Existing PagedBinaryImage handle must remain readable across all pages after reopen.
        auto effective_after = image->read_effective(0, image->size());
        ASSERT_TRUE(effective_after.has_value()) << effective_after.error().message;
        EXPECT_EQ(*effective_after, expected);

        // Freshly reopened PagedBinaryImage must observe 100% of uncached pages and patched bytes intact.
        auto reopened = peelf::PagedBinaryImage::open(input_path, kPageSize);
        ASSERT_TRUE(reopened.has_value()) << reopened.error().message;
        EXPECT_FALSE(reopened->dirty());
        auto disk_bytes = reopened->read_original(0, reopened->size());
        ASSERT_TRUE(disk_bytes.has_value()) << disk_bytes.error().message;
        EXPECT_EQ(*disk_bytes, expected);

        // Ensure no leftover temporary sibling files remain.
        const std::string prefix = input_path.filename().string() + ".";
        for (const auto& entry : std::filesystem::directory_iterator(input_path.parent_path())) {
            const std::string fname = entry.path().filename().string();
            EXPECT_FALSE(fname.starts_with(prefix) && fname.ends_with(".tmp"))
                << "Leftover temp file: " << entry.path().string();
        }
    }

    std::error_code ec;
    std::filesystem::remove(input_path, ec);
}

TEST(LiveMemoryPatchSpace, TransactionalRollbackPreservesStateOnReadOrWriteFailure) {
    constexpr std::uint64_t kFaultyBase = 0x1000ull;

    class FaultyLiveSession final : public peelf::IProcessSession {
    public:
        explicit FaultyLiveSession(std::vector<std::uint8_t> ram) : ram_(std::move(ram)) {
            info_.pid = 1234;
            info_.is_64bit = true;
        }

        [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
        [[nodiscard]] bool is_alive() const noexcept override { return true; }
        [[nodiscard]] bool is_read_only() const noexcept override { return false; }

        [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
            return std::vector<peelf::MemoryRegion>{};
        }
        [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
            return std::vector<peelf::ModuleInfo>{};
        }

        [[nodiscard]] peelf::Result<std::size_t> read_memory(
            std::uint64_t address,
            std::span<std::uint8_t> buffer) override {
            if (fail_reads_at.has_value() && address >= *fail_reads_at) {
                return peelf::make_error("simulated read failure");
            }
            if (address < kFaultyBase || (address - kFaultyBase) >= ram_.size()) {
                return peelf::make_error("unmapped");
            }
            const std::size_t off = static_cast<std::size_t>(address - kFaultyBase);
            const std::size_t n = std::min(buffer.size(), ram_.size() - off);
            std::copy_n(ram_.begin() + static_cast<std::ptrdiff_t>(off), n, buffer.begin());
            return n;
        }

        [[nodiscard]] peelf::Result<std::size_t> write_memory(
            std::uint64_t address,
            std::span<const std::uint8_t> buffer,
            peelf::MemoryWriteOptions) override {
            if (fail_writes_at.has_value() && address >= *fail_writes_at) {
                return peelf::make_error("simulated write failure");
            }
            if (address < kFaultyBase || (address - kFaultyBase) + buffer.size() > ram_.size()) {
                return peelf::make_error("unmapped write");
            }
            const std::size_t off = static_cast<std::size_t>(address - kFaultyBase);
            std::copy(buffer.begin(), buffer.end(), ram_.begin() + static_cast<std::ptrdiff_t>(off));
            return buffer.size();
        }

        std::vector<std::uint8_t> ram_;
        std::optional<std::uint64_t> fail_reads_at{};
        std::optional<std::uint64_t> fail_writes_at{};

    private:
        peelf::ProcessInfo info_{};
    };

    FaultyLiveSession session(std::vector<std::uint8_t>(64, 0x11u));
    peelf::LiveMemoryPatchSpace space;

    const std::array<peelf::PendingPatchWrite, 2> writes{{
        {kFaultyBase + 0u, {0xAAu, 0xBBu}},
        {kFaultyBase + 16u, {0xCCu, 0xDDu}},
    }};
    ASSERT_TRUE(space.stage_writes(session, writes, "two-span stage").has_value());
    EXPECT_TRUE(space.can_undo());

    // Simulate transient read failure on second span during undo: undo_stack_ & staged_ must remain intact.
    session.fail_reads_at = kFaultyBase + 16u;
    EXPECT_FALSE(space.undo(session).has_value());
    EXPECT_TRUE(space.can_undo());
    EXPECT_FALSE(space.can_redo());
    session.fail_reads_at.reset();
    EXPECT_EQ(*space.read_effective(session, kFaultyBase, 2u),
              (std::vector<std::uint8_t>{0xAAu, 0xBBu}));

    // Simulate write failure on second span during commit_to_process: first span in RAM must roll back,
    // and staged_ / committed_ must remain consistent.
    session.fail_writes_at = kFaultyBase + 16u;
    EXPECT_FALSE(space.commit_to_process(session).has_value());
    EXPECT_EQ(session.ram_[0], 0x11u);
    EXPECT_EQ(session.ram_[1], 0x11u);
    EXPECT_FALSE(space.has_committed_patches());
    EXPECT_TRUE(space.has_staged_patches());

    // Clear fault and verify commit succeeds cleanly.
    session.fail_writes_at.reset();
    auto committed = space.commit_to_process(session);
    ASSERT_TRUE(committed.has_value()) << committed.error().message;
    EXPECT_EQ(*committed, 4u);
    EXPECT_TRUE(space.has_committed_patches());
    EXPECT_FALSE(space.has_staged_patches());
}
