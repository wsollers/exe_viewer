#include <gtest/gtest.h>

#include "disasm/disassembler.hpp"

#include <array>
#include <cstdint>

TEST(Disassembler, ArmModeSwitchPreservesBigEndianAfterMove) {
    viewer::Disassembler original;
    ASSERT_TRUE(original.init(viewer::Architecture::ARM32, viewer::Endianness::Big));
    viewer::Disassembler disasm(std::move(original));
    ASSERT_TRUE(disasm.set_thumb_mode(true));
    constexpr std::array<std::uint8_t, 2> thumb{0xBF, 0x00};
    const auto decoded = disasm.disassemble(thumb.data(), thumb.size(), 0x1000);
    ASSERT_EQ(decoded.size(), 1u);
    EXPECT_EQ(decoded.front().mnemonic, "nop");
    ASSERT_TRUE(disasm.set_thumb_mode(false));
    constexpr std::array<std::uint8_t, 4> arm{0xE3, 0x20, 0xF0, 0x00};
    const auto restored = disasm.disassemble(arm.data(), arm.size(), 0x1000);
    ASSERT_EQ(restored.size(), 1u);
    EXPECT_EQ(restored.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesX86_32AndRejectsThumbMode) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::X86_32));
    EXPECT_FALSE(disasm.set_thumb_mode(true));
    constexpr std::array<std::uint8_t, 1> code{0x90};
    const auto decoded = disasm.disassemble(code.data(), code.size(), 0x1000);
    ASSERT_EQ(decoded.size(), 1u);
    EXPECT_EQ(decoded.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesX86_64Nop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::X86_64));

    constexpr std::array<std::uint8_t, 1> code{0x90};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x140001000);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x140001000u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DirectCallTargetDoesNotConfuseIndirectCallOrDataImmediate) {
    viewer::Disassembler decoder;
    ASSERT_TRUE(decoder.init(viewer::Architecture::X86_64));
    constexpr std::array<std::uint8_t, 12> code{0xE8,0,0,0,0, 0xFF,0xD0, 0xB8,1,0,0,0};
    const auto decoded = decoder.disassemble(code.data(), code.size(), 0x1000);
    ASSERT_EQ(decoded.size(), 3u);
    ASSERT_TRUE(decoded[0].branch_target);
    EXPECT_EQ(*decoded[0].branch_target, 0x1005u);
    EXPECT_FALSE(decoded[1].branch_target);
    EXPECT_FALSE(decoded[2].branch_target);
}

TEST(Disassembler, Arm64BranchTargetIsAbsolute) {
    viewer::Disassembler decoder;
    ASSERT_TRUE(decoder.init(viewer::Architecture::ARM64));
    constexpr std::array<std::uint8_t, 4> code{1,0,0,0x94};
    const auto decoded = decoder.disassemble(code.data(), code.size(), 0x1000);
    ASSERT_EQ(decoded.size(), 1u);
    ASSERT_TRUE(decoded.front().branch_target);
    EXPECT_EQ(*decoded.front().branch_target, 0x1004u);
}

TEST(Disassembler, RiscVNormalizesRelativeJumpAndRejectsRegisterTarget) {
    for (const auto arch : {viewer::Architecture::RISCV32, viewer::Architecture::RISCV64}) {
        viewer::Disassembler decoder;
        ASSERT_TRUE(decoder.init(arch));
        constexpr std::array<std::uint8_t, 8> code{0xEF,0,0x40,0, 0xE7,0x80,0,0};
        const auto decoded = decoder.disassemble(code.data(), code.size(), 0x1000);
        ASSERT_EQ(decoded.size(), 2u);
        ASSERT_TRUE(decoded[0].branch_target);
        EXPECT_EQ(*decoded[0].branch_target, 0x1004u);
        EXPECT_FALSE(decoded[1].branch_target);
    }
}

TEST(Disassembler, DecodesArm64Nop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::ARM64)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x1F, 0x20, 0x03, 0xD5};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesRiscV32Nop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::RISCV32)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x13, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesRiscV64Nop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::RISCV64)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x13, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesMips32BigEndianNop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::MIPS32, viewer::Endianness::Big)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x00, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesMips64BigEndianNop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::MIPS64, viewer::Endianness::Big)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x00, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesPowerPc32BigEndianNop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::PowerPC32, viewer::Endianness::Big)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x60, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}

TEST(Disassembler, DecodesPowerPc64BigEndianNop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::PowerPC64, viewer::Endianness::Big)) << disasm.get_error();

    constexpr std::array<std::uint8_t, 4> code{0x60, 0x00, 0x00, 0x00};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x400080);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x400080u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
}
