// Tests for peelf::FileMapping (Phase 0: P0-3 / P0-4).
//
// Covers:
//  - mapping an existing file read-only and reading its bytes
//  - the constructor reporting failure via std::system_error (P0-4)
//  - the non-throwing open() surfacing a std::error_code (P0-4)
//  - move semantics transferring ownership of the mapped data (P0-4 follow-up)

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <system_error>
#include <utility>

#include <mapping/file_mapping.hpp>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

std::filesystem::path fixture_path(const char* name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

using ByteMapping = peelf::FileMapping<std::uint8_t, peelf::NativeFileMappingBackend>;

}  // namespace

TEST(FileMapping, MapsExistingFileReadOnly) {
    const auto path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string();
    }

    ByteMapping map(path, peelf::MapMode::read_only);
    ASSERT_TRUE(map.is_open());
    ASSERT_GE(map.size(), 4u);

    const auto bytes = map.view();
    EXPECT_EQ(bytes[0], 0x7Fu);
    EXPECT_EQ(bytes[1], static_cast<std::uint8_t>('E'));
    EXPECT_EQ(bytes[2], static_cast<std::uint8_t>('L'));
    EXPECT_EQ(bytes[3], static_cast<std::uint8_t>('F'));
}

TEST(FileMapping, ConstructorThrowsOnMissingFile) {
    const auto path = fixture_path("does_not_exist.bin");
    EXPECT_THROW(ByteMapping(path, peelf::MapMode::read_only), std::system_error);
}

TEST(FileMapping, OpenReturnsErrorOnMissingFile) {
    ByteMapping map;
    const std::error_code ec =
        map.open(fixture_path("does_not_exist.bin").string(), peelf::MapMode::read_only);
    EXPECT_TRUE(static_cast<bool>(ec));
    EXPECT_FALSE(map.is_open());
}

TEST(FileMapping, MoveTransfersOwnership) {
    const auto path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string();
    }

    ByteMapping src(path, peelf::MapMode::read_only);
    ASSERT_TRUE(src.is_open());
    const std::size_t original_size = src.size();

    ByteMapping dst(std::move(src));
    EXPECT_TRUE(dst.is_open());
    EXPECT_EQ(dst.size(), original_size);
    // Moved-from object is intentionally inspected: it must release ownership.
    EXPECT_FALSE(src.is_open());
}
