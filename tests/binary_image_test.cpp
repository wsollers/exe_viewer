// Tests for the unified binary-image model (ToDo.md Phase 1: P1-1 .. P1-4).
//
// Covers detect_format, the ELF identity path against the hello.elf fixture
// (exercising 64-bit little-endian x86-64), and a synthetic minimal PE32+ header
// built in-test (so no PE fixture file is required).

#include <gtest/gtest.h>

#include <peelf/binary_image.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
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

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0] = static_cast<std::uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

}  // namespace

TEST(BinaryImage, DetectFormat) {
    const std::vector<std::uint8_t> elf{0x7F, 'E', 'L', 'F'};
    const std::vector<std::uint8_t> pe{'M', 'Z'};
    const std::vector<std::uint8_t> junk{0, 1, 2, 3};
    EXPECT_EQ(peelf::detect_format(elf), peelf::Format::ELF);
    EXPECT_EQ(peelf::detect_format(pe), peelf::Format::PE);
    EXPECT_EQ(peelf::detect_format(junk), peelf::Format::Unknown);
}

TEST(BinaryImage, ParsesElfFixtureIdentity) {
    const auto path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string();
    }

    const std::vector<std::uint8_t> bytes = read_all(path);
    auto result = peelf::parse_image(bytes);
    ASSERT_TRUE(result.has_value()) << "parse_image failed on the ELF fixture";

    const peelf::IBinaryImage& img = **result;
    EXPECT_EQ(img.format(), peelf::Format::ELF);
    EXPECT_EQ(img.architecture(), peelf::Architecture::X86_64);
    EXPECT_TRUE(img.is_64bit());
    EXPECT_EQ(img.endianness(), peelf::Endianness::Little);
    EXPECT_EQ(img.kind(), peelf::ImageKind::SharedLibrary);  // ET_DYN (PIE executable)
    EXPECT_GT(img.entry_point(), 0u);
    EXPECT_FALSE(img.sections().empty());  // sections parsed in Phase 2 (P2-1)
}

TEST(BinaryImage, ParsesElfFixtureSections) {
    const auto path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string();
    }

    const std::vector<std::uint8_t> bytes = read_all(path);
    auto result = peelf::parse_image(bytes);
    ASSERT_TRUE(result.has_value());

    const auto& secs = (**result).sections();
    ASSERT_FALSE(secs.empty());

    bool found_text = false;
    for (const auto& s : secs) {
        if (s.name == ".text") {
            found_text = true;
            EXPECT_TRUE(s.executable);
        }
    }
    EXPECT_TRUE(found_text) << "expected a .text section in hello.elf";
}

TEST(BinaryImage, ParsesSyntheticPe64Identity) {
    std::vector<std::uint8_t> b(0x200, 0);
    b[0] = 'M';
    b[1] = 'Z';

    const std::uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);

    // PE signature
    b[e_lfanew + 0] = 'P';
    b[e_lfanew + 1] = 'E';

    const std::size_t coff = e_lfanew + 4;
    put16(b, coff + 0, 0x8664);    // Machine = AMD64
    put16(b, coff + 16, 0x00F0);   // SizeOfOptionalHeader
    put16(b, coff + 18, 0x0022);   // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE (no DLL)
    put16(b, coff + 2, 1);         // NumberOfSections

    const std::size_t opt = coff + 20;
    put16(b, opt + 0, 0x020B);                 // Magic = PE32+
    put32(b, opt + 16, 0x1000);                // AddressOfEntryPoint (RVA)
    put64(b, opt + 24, 0x140000000ULL);        // ImageBase (PE32+)

    // One section header (".text") immediately after the optional header.
    const std::size_t sect = opt + 0xF0;
    const char* sname = ".text";
    for (std::size_t i = 0; sname[i] != '\0'; ++i) {
        b[sect + i] = static_cast<std::uint8_t>(sname[i]);
    }
    put32(b, sect + 8, 0x0100);        // VirtualSize
    put32(b, sect + 12, 0x1000);       // VirtualAddress (RVA)
    put32(b, sect + 16, 0x0100);       // SizeOfRawData
    put32(b, sect + 20, 0x0400);       // PointerToRawData
    put32(b, sect + 36, 0x60000020);   // CNT_CODE | MEM_EXECUTE | MEM_READ

    auto result = peelf::parse_image(b);
    ASSERT_TRUE(result.has_value()) << "parse_image failed on the synthetic PE";

    const peelf::IBinaryImage& img = **result;
    EXPECT_EQ(img.format(), peelf::Format::PE);
    EXPECT_EQ(img.architecture(), peelf::Architecture::X86_64);
    EXPECT_TRUE(img.is_64bit());
    EXPECT_EQ(img.endianness(), peelf::Endianness::Little);
    EXPECT_EQ(img.kind(), peelf::ImageKind::Executable);
    EXPECT_EQ(img.entry_point(), 0x140000000ULL + 0x1000);

    ASSERT_EQ(img.sections().size(), 1u);
    const auto& sec = img.sections().front();
    EXPECT_EQ(sec.name, ".text");
    EXPECT_EQ(sec.virtual_address, 0x140000000ULL + 0x1000);
    EXPECT_TRUE(sec.executable);
    EXPECT_TRUE(sec.readable);
    EXPECT_FALSE(sec.writable);
}

TEST(BinaryImage, RejectsUnknownFormat) {
    const std::vector<std::uint8_t> junk(64, 0);
    const auto result = peelf::parse_image(junk);
    EXPECT_FALSE(result.has_value());
}
