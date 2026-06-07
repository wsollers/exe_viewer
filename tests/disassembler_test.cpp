#include <gtest/gtest.h>

#include "disasm/disassembler.hpp"

#include <array>
#include <cstdint>

TEST(Disassembler, DecodesX86_64Nop) {
    viewer::Disassembler disasm;
    ASSERT_TRUE(disasm.init(viewer::Architecture::X86_64));

    constexpr std::array<std::uint8_t, 1> code{0x90};
    const auto instructions = disasm.disassemble(code.data(), code.size(), 0x140001000);

    ASSERT_EQ(instructions.size(), 1u);
    EXPECT_EQ(instructions.front().address, 0x140001000u);
    EXPECT_EQ(instructions.front().mnemonic, "nop");
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
