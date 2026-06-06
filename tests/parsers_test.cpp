// Tests for the PE/ELF byte parsers (ToDo.md P0-9).
//
// These exercise the public peelf::parse_*_bytes functions now that they return
// Result<FileInfo> and are declared in <peelf/peelf.hpp>. The ELF success path
// uses the committed hello.elf fixture; error paths use small synthetic buffers.

#include <gtest/gtest.h>

#include <peelf/peelf.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <variant>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

std::filesystem::path fixture_path(const char* name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    const auto size = static_cast<std::size_t>(file.tellg());
    std::vector<std::uint8_t> buf(size);
    file.seekg(0);
    file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
    return buf;
}

}  // namespace

TEST(ElfParser, ParsesHelloFixture) {
    const auto path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string();
    }

    const std::vector<std::uint8_t> bytes = read_all(path);
    ASSERT_GE(bytes.size(), 0x20u);

    const peelf::Result<peelf::FileInfo> result = peelf::parse_elf_bytes(bytes);
    ASSERT_TRUE(result.has_value()) << "parse_elf_bytes failed on the fixture";
    EXPECT_EQ(result->kind, peelf::FileKind::ELF);

    ASSERT_TRUE(std::holds_alternative<ElfSummary>(result->summary));
    const auto& elf = std::get<ElfSummary>(result->summary);
    EXPECT_EQ(elf.ei_class, 2);       // ELFCLASS64
    EXPECT_EQ(elf.ei_data, 1);        // ELFDATA2LSB (little-endian)
    EXPECT_EQ(elf.e_type, 3);         // ET_DYN (PIE executable)
    EXPECT_EQ(elf.e_machine, 0x3E);   // EM_X86_64
}

TEST(ElfParser, RejectsTooSmall) {
    const std::vector<std::uint8_t> tiny(8, 0);
    const auto result = peelf::parse_elf_bytes(tiny);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().message.empty());
}

TEST(PeParser, RejectsMissingMzSignature) {
    // Large enough for a DOS header, but no "MZ" magic.
    const std::vector<std::uint8_t> buf(0x40, 0);
    const auto result = peelf::parse_pe_bytes(buf);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().message.empty());
}

TEST(PeParser, RejectsTooSmall) {
    const std::vector<std::uint8_t> tiny(8, 0);
    const auto result = peelf::parse_pe_bytes(tiny);
    EXPECT_FALSE(result.has_value());
}
