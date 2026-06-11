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

} // namespace
