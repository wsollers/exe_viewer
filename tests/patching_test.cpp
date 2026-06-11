#include "peelf/patching.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

[[nodiscard]] std::filesystem::path write_temp_binary(std::vector<std::uint8_t> bytes) {
    const auto path = std::filesystem::temp_directory_path() /
                      std::filesystem::path("peelf_patching_test.bin");
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
