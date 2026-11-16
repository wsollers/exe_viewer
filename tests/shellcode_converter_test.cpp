#include "tools/shellcode_converter.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace {

TEST(ShellcodeConverterTest, ParsesEscapedShellcodeBytes) {
    const viewer::ShellcodeParseResult parsed = viewer::parse_hex_shellcode(R"(\x48\x31\xc0\xc3)");

    ASSERT_TRUE(parsed.success) << parsed.diagnostic;
    const std::vector<std::uint8_t> expected{0x48u, 0x31u, 0xC0u, 0xC3u};
    EXPECT_EQ(parsed.bytes, expected);
}

TEST(ShellcodeConverterTest, ParsesCStyleByteArrayWithoutIdentifierNoise) {
    const viewer::ShellcodeParseResult parsed =
        viewer::parse_hex_shellcode("unsigned char sc[] = { 0x48, 0x31, 0xC0, 0xC3 };");

    ASSERT_TRUE(parsed.success) << parsed.diagnostic;
    const std::vector<std::uint8_t> expected{0x48u, 0x31u, 0xC0u, 0xC3u};
    EXPECT_EQ(parsed.bytes, expected);
}

TEST(ShellcodeConverterTest, ParsesDenseAndSpacedHex) {
    const viewer::ShellcodeParseResult parsed = viewer::parse_hex_shellcode("4831c0 c3 90");

    ASSERT_TRUE(parsed.success) << parsed.diagnostic;
    const std::vector<std::uint8_t> expected{0x48u, 0x31u, 0xC0u, 0xC3u, 0x90u};
    EXPECT_EQ(parsed.bytes, expected);
}

TEST(ShellcodeConverterTest, ReportsOddBareHexToken) {
    const viewer::ShellcodeParseResult parsed = viewer::parse_hex_shellcode("48 31 c");

    EXPECT_FALSE(parsed.success);
    EXPECT_TRUE(parsed.bytes.empty());
    EXPECT_NE(parsed.diagnostic.find("Odd-length"), std::string::npos);
}

TEST(ShellcodeConverterTest, FormatsHexViewWithOffsetsAndAscii) {
    const std::vector<std::uint8_t> bytes{0x48u, 0x69u, 0x00u, 0xC3u};

    const std::string view = viewer::format_shellcode_hex_view(bytes, 4);

    EXPECT_EQ(view, "00000000: 48 69 00 C3  Hi..");
}

TEST(ShellcodeScratchCacheTest, InvalidatesStaleMachineBytesWhenArchitectureChanges) {
    viewer::ShellcodeScratchCache cache;
    viewer::ShellcodeTargetConfig x64_cfg{
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .thumb = false,
        .base_va = 0x140001000ULL,
        .assembly_mode = true,
    };

    ASSERT_TRUE(cache.sync_target(x64_cfg, "xor eax, eax\nret"));
    ASSERT_FALSE(cache.output_bytes().empty()) << cache.diagnostic();
    EXPECT_FALSE(cache.hex_view().empty());
    EXPECT_NE(cache.roundtrip_disasm_view().find("0x0000000140001000"), std::string::npos);

    // Repeating sync_target with identical config is a no-op.
    EXPECT_FALSE(cache.sync_target(x64_cfg, "xor eax, eax\nret"));

    // Switching target architecture to ARM64 with x86_64 source in the buffer must
    // immediately clear stale x86_64 machine bytes and disassembly preview.
    viewer::ShellcodeTargetConfig arm64_cfg = x64_cfg;
    arm64_cfg.architecture = peelf::Architecture::ARM64;
    EXPECT_TRUE(cache.sync_target(arm64_cfg, "xor eax, eax\nret"));
    EXPECT_TRUE(cache.output_bytes().empty());
    EXPECT_TRUE(cache.hex_view().empty());
    EXPECT_TRUE(cache.roundtrip_disasm_view().empty());
}

TEST(ShellcodeScratchCacheTest, InvalidatesAndReencodesAcrossBitnessModeAndBaseVaChanges) {
    viewer::ShellcodeScratchCache cache;
    viewer::ShellcodeTargetConfig x64_cfg{
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .thumb = false,
        .base_va = 0x401000ULL,
        .assembly_mode = true,
    };

    cache.rebuild(x64_cfg, "mov rax, 1\nret");
    ASSERT_FALSE(cache.output_bytes().empty()) << cache.diagnostic();

    // Switching to 32-bit x86 must invalidate 64-bit-only `mov rax, 1` bytes.
    viewer::ShellcodeTargetConfig x86_32_cfg{
        .architecture = peelf::Architecture::X86,
        .endianness = peelf::Endianness::Little,
        .is_64bit = false,
        .thumb = false,
        .base_va = 0x401000ULL,
        .assembly_mode = true,
    };
    EXPECT_TRUE(cache.sync_target(x86_32_cfg, "mov rax, 1\nret"));
    EXPECT_TRUE(cache.output_bytes().empty());
    EXPECT_TRUE(cache.roundtrip_disasm_view().empty());

    // Valid x86 instructions re-encode differently in 64-bit (`FF C0 C3`) vs 32-bit (`40 C3`).
    cache.rebuild(x64_cfg, "inc eax\nret");
    const std::vector<std::uint8_t> x64_bytes(cache.output_bytes().begin(),
                                              cache.output_bytes().end());
    ASSERT_FALSE(x64_bytes.empty()) << cache.diagnostic();

    EXPECT_TRUE(cache.sync_target(x86_32_cfg, "inc eax\nret"));
    const std::vector<std::uint8_t> x86_bytes(cache.output_bytes().begin(),
                                              cache.output_bytes().end());
    ASSERT_FALSE(x86_bytes.empty()) << cache.diagnostic();
    EXPECT_NE(x64_bytes, x86_bytes);
    EXPECT_NE(cache.roundtrip_disasm_view().find("0x00401000"), std::string::npos);

    // Changing base_va or endianness in hex mode also invalidates & refreshes roundtrip disassembly.
    viewer::ShellcodeTargetConfig hex_cfg{
        .architecture = peelf::Architecture::ARM,
        .endianness = peelf::Endianness::Little,
        .is_64bit = false,
        .thumb = false,
        .base_va = 0x10000ULL,
        .assembly_mode = false,
    };
    EXPECT_TRUE(cache.sync_target(hex_cfg, "00 f0 20 e3"));
    ASSERT_EQ(cache.output_bytes().size(), 4u);
    const std::string le_disasm = cache.roundtrip_disasm_view();
    EXPECT_NE(le_disasm.find("0x00010000"), std::string::npos);

    hex_cfg.base_va = 0x20000ULL;
    EXPECT_TRUE(cache.sync_target(hex_cfg, "00 f0 20 e3"));
    EXPECT_NE(cache.roundtrip_disasm_view().find("0x00020000"), std::string::npos);

    hex_cfg.endianness = peelf::Endianness::Big;
    EXPECT_TRUE(cache.sync_target(hex_cfg, "00 f0 20 e3"));
    EXPECT_NE(cache.roundtrip_disasm_view(), le_disasm);
}

} // namespace
