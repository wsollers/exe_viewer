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
#include <fstream>
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

TEST(FileMapping, UnicodePathRoundTrips) {
    const auto path = std::filesystem::temp_directory_path() / std::filesystem::path(u8"peelf_\u65e5\u672c_\u00e9.bin");
    { std::ofstream file(path, std::ios::binary); file << "mapped"; }
    {
        ByteMapping map(path);
        ASSERT_EQ(map.size(), 6u);
        EXPECT_EQ(map.view()[0], 'm');
        const auto utf8 = path.u8string();
        ByteMapping second;
        EXPECT_FALSE(second.open(std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size())));
    }
    std::filesystem::remove(path);
}

namespace {

struct alignas(16) AlignedBlock {
    std::uint64_t lo;
    std::uint64_t hi;
};

struct MisalignedCountingBackend {
    static inline int open_calls = 0;
    static inline int close_calls = 0;
    alignas(16) static inline std::uint8_t backing[64]{};

    static std::error_code open_and_map(MisalignedCountingBackend&,
                                        const std::string& path,
                                        peelf::MapMode,
                                        void** out_ptr,
                                        std::size_t* out_size) noexcept {
        ++open_calls;
        if (path == "zero") {
            *out_ptr = backing;
            *out_size = 0;
            return {};
        }
        *out_ptr = backing + 1;  // Intentionally misaligned for alignof(AlignedBlock) == 16
        *out_size = 32;
        return {};
    }

    static std::error_code flush(MisalignedCountingBackend&, void*, std::size_t) noexcept {
        return {};
    }

    static std::error_code unmap_and_close(MisalignedCountingBackend&,
                                           void* ptr,
                                           std::size_t size) noexcept {
        if (ptr != nullptr || size != 0) {
            ++close_calls;
        }
        return {};
    }
};

}  // namespace

TEST(FileMapping, AlignmentAndZeroSizeFailuresUnmapWithoutLeakingView) {
    MisalignedCountingBackend::open_calls = 0;
    MisalignedCountingBackend::close_calls = 0;

    peelf::FileMapping<AlignedBlock, MisalignedCountingBackend> map;
    const std::error_code ec = map.open("misaligned", peelf::MapMode::read_only);
    EXPECT_EQ(ec, peelf::make_error_code(peelf::MapErrc::invalid_alignment));
    EXPECT_FALSE(map.is_open());
    EXPECT_EQ(MisalignedCountingBackend::open_calls, 1);
    EXPECT_EQ(MisalignedCountingBackend::close_calls, 1);

    const std::error_code zero_ec = map.open("zero", peelf::MapMode::read_only);
    EXPECT_EQ(zero_ec, peelf::make_error_code(peelf::MapErrc::size_zero));
    EXPECT_FALSE(map.is_open());
    EXPECT_EQ(MisalignedCountingBackend::open_calls, 2);
    EXPECT_EQ(MisalignedCountingBackend::close_calls, 2);
}

TEST(FileMapping, EnforcesReadOnlyConstnessAndReadWriteWritableSpan) {
    const auto path = std::filesystem::temp_directory_path() / "peelf_mapping_constness_test.bin";
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write("ABCDEFGH", 8);
    }

    {
        ByteMapping ro_map(path, peelf::MapMode::read_only);
        ASSERT_TRUE(ro_map.is_open());
        EXPECT_EQ(ro_map.mode(), peelf::MapMode::read_only);
        EXPECT_EQ(ro_map.bytes().size(), 8u);
        EXPECT_EQ(ro_map.bytes()[0], static_cast<std::uint8_t>('A'));

        auto denied = ro_map.writable_span();
        EXPECT_FALSE(denied.has_value());
        EXPECT_EQ(ro_map.flush(), peelf::make_error_code(peelf::MapErrc::flush_failed));
    }

    {
        ByteMapping rw_map(path, peelf::MapMode::read_write);
        ASSERT_TRUE(rw_map.is_open());
        EXPECT_EQ(rw_map.mode(), peelf::MapMode::read_write);
        auto writable = rw_map.writable_span();
        ASSERT_TRUE(writable.has_value()) << writable.error().message;
        ASSERT_EQ(writable->size(), 8u);
        (*writable)[0] = static_cast<std::uint8_t>('Z');
        EXPECT_FALSE(static_cast<bool>(rw_map.flush()));
    }

    {
        ByteMapping verify_map(path, peelf::MapMode::read_only);
        ASSERT_EQ(verify_map.bytes().size(), 8u);
        EXPECT_EQ(verify_map.bytes()[0], static_cast<std::uint8_t>('Z'));
    }

    std::filesystem::remove(path);
}
