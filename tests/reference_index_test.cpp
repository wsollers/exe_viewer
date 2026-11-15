#include "analysis/reference_index.hpp"
#include <gtest/gtest.h>
#include <array>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>

namespace {
using viewer::ReferenceIndex;
using viewer::ReferenceKind;
constexpr auto x64 = peelf::Architecture::X86_64;
constexpr auto little = peelf::Endianness::Little;
}
TEST(ReferenceIndex, DirectCallAndBranchExcludeRegisterCall) {
    // call 0x1010; call rax; jmp 0x1000
    const std::array<std::uint8_t, 9> bytes{0xE8, 0x0B, 0, 0, 0, 0xFF, 0xD0, 0xEB, 0xF7};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 2);
    EXPECT_EQ(index.records()[0].kind, ReferenceKind::Call);
    EXPECT_EQ(index.records()[0].target, 0x1010);
    EXPECT_EQ(index.records()[1].kind, ReferenceKind::Branch);
    EXPECT_EQ(index.incoming(0x1010).size(), 1);
    EXPECT_EQ(index.outgoing(0x1000, bytes.size()).size(), 2);
    EXPECT_TRUE(index.incoming(std::numeric_limits<std::uint64_t>::max(), 10).empty());
}
TEST(ReferenceIndex, DistinguishesStaticMemoryAndAddressConstants) {
    const std::array<std::uint8_t, 14> bytes{0x48, 0x8D, 0x05, 0x19, 0, 0, 0, 0xB8, 0x20, 0x10, 0, 0, 0x8B, 0};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 2);
    EXPECT_EQ(index.records()[0].target, 0x1020);
    EXPECT_EQ(index.records()[0].kind, ReferenceKind::Data);
    EXPECT_EQ(index.records()[1].target, 0x1020);
    EXPECT_EQ(index.records()[1].kind, ReferenceKind::AddressConstant);
}
TEST(ReferenceIndex, EipRelativeAddressWrapsAt32Bits) {
    const std::array<std::uint8_t, 8> bytes{0x67, 0x48, 0x8D, 0x05, 0x20, 0, 0, 0};
    ReferenceIndex index; index.add_code(bytes, 0xFFFFFFF0ULL, x64, little);
    ASSERT_EQ(index.records().size(), 1);
    EXPECT_EQ(index.records()[0].target, 0x18);
}
TEST(ReferenceIndex, NewPatchInputReplacesOldReferenceTargets) {
    std::array<std::uint8_t, 5> bytes{0xE8, 0x0B, 0, 0, 0};
    ReferenceIndex original; original.add_code(bytes, 0x1000, x64, little);
    bytes[1] = 0x1B;
    ReferenceIndex patched; patched.add_code(bytes, 0x1000, x64, little);
    EXPECT_EQ(original.incoming(0x1010).size(), 1);
    EXPECT_TRUE(patched.incoming(0x1010).empty());
    EXPECT_EQ(patched.incoming(0x1020).size(), 1);
}
TEST(ReferenceIndex, InvalidEncodingRecoveryReportsPartialCoverage) {
    const std::array<std::uint8_t, 6> bytes{0x06, 0xE8, 0, 0, 0, 0};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 1);
    EXPECT_EQ(index.records()[0].source, 0x1001);
    EXPECT_TRUE(index.incomplete());
    ReferenceIndex overflow;
    overflow.add_code(bytes, std::numeric_limits<std::uint64_t>::max() - 1, x64, little);
    EXPECT_TRUE(overflow.incomplete());
    EXPECT_TRUE(overflow.records().empty());
}
TEST(ReferenceIndex, ImageScanHonorsBudgetAndTruncatedInput) {
    std::ifstream file(std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf", std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    auto image = peelf::parse_image(bytes);
    ASSERT_TRUE(image.has_value());
    const auto bounded = ReferenceIndex::build(**image, bytes, false, 1);
    EXPECT_LE(bounded.scanned_bytes(), 1);
    EXPECT_TRUE(bounded.incomplete());
    const auto truncated = ReferenceIndex::build(**image, {});
    EXPECT_TRUE(truncated.records().empty());
    EXPECT_TRUE(truncated.incomplete());
}
TEST(ReferenceIndex, MappedStringReferencesCarrySearchablePreview) {
    std::ifstream file(std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf", std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    auto image = peelf::parse_image(bytes);
    ASSERT_TRUE(image.has_value());
    const auto sections = (*image)->sections();
    const auto code = std::ranges::find_if(sections, [](const auto& section) { return section.executable && section.file_size >= 16; });
    ASSERT_NE(code, sections.end());
    ASSERT_LE(code->file_offset + 16, bytes.size());
    const auto offset = static_cast<std::size_t>(code->file_offset);
    // lea rax,[rip+1] points at a NUL-terminated literal 8 bytes into the region.
    const std::array<std::uint8_t, 7> instruction{0x48, 0x8D, 0x05, 1, 0, 0, 0};
    std::ranges::copy(instruction, bytes.begin() + offset);
    const std::string literal = "hello";
    std::ranges::copy(literal, bytes.begin() + offset + 8);
    bytes[offset + 8 + literal.size()] = 0;
    const auto index = ReferenceIndex::build(**image, bytes);
    const auto refs = index.outgoing(code->virtual_address);
    ASSERT_FALSE(refs.empty());
    EXPECT_EQ(refs.front()->string_preview, literal);
}
TEST(AnnotationStore, RenameCommentAndRemovalAreAddressScoped) {
    viewer::AnnotationStore store;
    store.set(0x1000, "validate_input", "Reject malformed records");
    ASSERT_NE(store.find(0x1000), nullptr);
    EXPECT_EQ(store.find(0x1000)->name, "validate_input");
    store.set(0x1000, "", "Retain comment");
    EXPECT_EQ(store.find(0x1000)->comment, "Retain comment");
    EXPECT_EQ(store.find(0x1001), nullptr);
    store.set(0x1000, "", "");
    EXPECT_TRUE(store.records().empty());
    store.set(1, "name", ""); store.clear();
    EXPECT_TRUE(store.records().empty());
}

TEST(ReferenceIndex, DirectTargetsAcrossSupportedArchitectures) {
    struct Fixture { peelf::Architecture arch; peelf::Endianness endian; std::vector<std::uint8_t> bytes; };
    const std::array fixtures{
        Fixture{peelf::Architecture::X86, little, {0xE8, 0x0B, 0, 0, 0}},
        Fixture{x64, little, {0xE8, 0x0B, 0, 0, 0}},
        Fixture{peelf::Architecture::ARM, little, {0x02, 0, 0, 0xEB}},
        Fixture{peelf::Architecture::ARM64, little, {0x04, 0, 0, 0x94}},
        Fixture{peelf::Architecture::RISCV32, little, {0xEF, 0, 0, 0x01}},
        Fixture{peelf::Architecture::RISCV64, little, {0xEF, 0, 0, 0x01}},
        Fixture{peelf::Architecture::MIPS32, peelf::Endianness::Big, {0x0C, 0, 0x04, 0x04}},
        Fixture{peelf::Architecture::MIPS64, peelf::Endianness::Big, {0x0C, 0, 0x04, 0x04}},
        Fixture{peelf::Architecture::PowerPC, peelf::Endianness::Big, {0x48, 0, 0, 0x11}},
        Fixture{peelf::Architecture::PowerPC64, peelf::Endianness::Big, {0x48, 0, 0, 0x11}}
    };
    for (const auto& fixture : fixtures) {
        SCOPED_TRACE(static_cast<int>(fixture.arch));
        ReferenceIndex index; index.add_code(fixture.bytes, 0x1000, fixture.arch, fixture.endian);
        ASSERT_EQ(index.records().size(), 1);
        EXPECT_EQ(index.records()[0].target, 0x1010);
        EXPECT_EQ(index.records()[0].kind, ReferenceKind::Call);
    }
}

TEST(ReferenceIndex, RiscvZeroDestinationAndPowerPcWithoutLinkAreBranches) {
    const std::array<std::uint8_t, 4> jump{0x6F, 0, 0, 0x01}; // jal x0,+16
    ReferenceIndex riscv; riscv.add_code(jump, 0x1000, peelf::Architecture::RISCV64, little);
    ASSERT_EQ(riscv.records().size(), 1);
    EXPECT_EQ(riscv.records()[0].kind, ReferenceKind::Branch);
    EXPECT_EQ(riscv.records()[0].target, 0x1010);
    const std::array<std::uint8_t, 4> indirect{0x67, 0, 0x05, 0}; // jalr x0,a0,0
    ReferenceIndex unresolved; unresolved.add_code(indirect, 0x1000, peelf::Architecture::RISCV64, little);
    EXPECT_TRUE(unresolved.records().empty());
    const std::array<std::uint8_t, 4> ppc_jump{0x48, 0, 0, 0x10};
    ReferenceIndex ppc; ppc.add_code(ppc_jump, 0x1000, peelf::Architecture::PowerPC, peelf::Endianness::Big);
    ASSERT_EQ(ppc.records().size(), 1);
    EXPECT_EQ(ppc.records()[0].kind, ReferenceKind::Branch);
}
