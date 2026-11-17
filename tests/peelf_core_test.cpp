// Tests for the peelf_core public surface.
//
// Starts with FileKind -> string mapping (peelf::to_string). As the unified
// parser API lands (ToDo.md P1-x), add parse tests for PE/ELF here against the
// fixtures in tests/fixtures/.

#include <gtest/gtest.h>

#include <peelf/endian_reader.hpp>
#include <peelf/peelf.hpp>

#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

static_assert(!std::is_constructible_v<peelf::EndianReader,
                                       std::vector<std::uint8_t>&&,
                                       peelf::TargetLayout>);
static_assert(!std::is_constructible_v<peelf::EndianReader,
                                       const std::vector<std::uint8_t>&&,
                                       peelf::TargetLayout>);
static_assert(!std::is_constructible_v<peelf::EndianReader,
                                       std::vector<std::uint8_t>&&,
                                       peelf::Endianness>);
static_assert(!std::is_constructible_v<peelf::EndianReader,
                                       std::vector<std::uint8_t>&&,
                                       peelf::Endianness,
                                       peelf::AddressWidth>);
static_assert(std::is_constructible_v<peelf::EndianReader,
                                      std::vector<std::uint8_t>&,
                                      peelf::TargetLayout>);
static_assert(std::is_constructible_v<peelf::EndianReader,
                                      const std::vector<std::uint8_t>&,
                                      peelf::TargetLayout>);
static_assert(std::is_constructible_v<peelf::EndianReader,
                                      std::span<const std::uint8_t>,
                                      peelf::TargetLayout>);

TEST(PeelfCore, FileKindToString) {
    EXPECT_EQ(peelf::to_string(peelf::FileKind::ELF), "ELF");
    EXPECT_EQ(peelf::to_string(peelf::FileKind::PE), "PE");
    EXPECT_EQ(peelf::to_string(peelf::FileKind::Unknown), "Unknown");
}

TEST(PeelfCore, CheckedScaleSignedDisplacementAllowsInt64MinBoundary) {
    constexpr auto kInt64Min = std::numeric_limits<std::int64_t>::min();
    static_assert(peelf::checked_scale_signed_displacement(-1, 63u) ==
                  std::optional<std::int64_t>{kInt64Min});

    EXPECT_EQ(peelf::checked_scale_signed_displacement(-1, 63u),
              std::optional<std::int64_t>{kInt64Min});
    EXPECT_EQ(peelf::checked_scale_signed_displacement(-2, 63u), std::nullopt);
    EXPECT_EQ(peelf::checked_scale_signed_displacement(1, 63u), std::nullopt);
    EXPECT_EQ(peelf::checked_scale_signed_displacement(0, 63u),
              std::optional<std::int64_t>{0});
    EXPECT_EQ(peelf::checked_scale_signed_displacement(0, 64u),
              std::optional<std::int64_t>{0});
    EXPECT_EQ(peelf::checked_scale_signed_displacement(-1, 64u), std::nullopt);
}

TEST(PeelfCore, EncodePointerRejects32BitOverflowAndEncodesValidWidths) {
    for (const peelf::Endianness endian : {peelf::Endianness::Little, peelf::Endianness::Big}) {
        const peelf::TargetLayout layout32{
            .architecture = peelf::Architecture::X86,
            .address_width = peelf::AddressWidth::Bits32,
            .endianness = endian,
        };
        const peelf::TargetLayout layout64{
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .endianness = endian,
        };

        const auto overflow_one = peelf::encode_pointer(0x1'0000'0000ULL, layout32);
        EXPECT_FALSE(overflow_one.has_value());

        const auto overflow_max =
            peelf::encode_pointer(std::numeric_limits<std::uint64_t>::max(), layout32);
        EXPECT_FALSE(overflow_max.has_value());

        const auto max32 = peelf::encode_pointer(0xFFFF'FFFFULL, layout32);
        ASSERT_TRUE(max32.has_value()) << max32.error().message;
        ASSERT_EQ(max32->size(), 4u);
        const peelf::EndianReader r32(*max32, layout32);
        const auto decoded32 = r32.read_pointer(0);
        ASSERT_TRUE(decoded32.has_value());
        EXPECT_EQ(*decoded32, 0xFFFF'FFFFULL);

        const auto valid64 = peelf::encode_pointer(0x1'0000'0000ULL, layout64);
        ASSERT_TRUE(valid64.has_value()) << valid64.error().message;
        ASSERT_EQ(valid64->size(), 8u);
        const peelf::EndianReader r64(*valid64, layout64);
        const auto decoded64 = r64.read_pointer(0);
        ASSERT_TRUE(decoded64.has_value());
        EXPECT_EQ(*decoded64, 0x1'0000'0000ULL);
    }
}
