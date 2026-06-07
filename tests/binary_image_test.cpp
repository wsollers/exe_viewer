// Tests for the unified binary-image model (ToDo.md Phase 1: P1-1 .. P1-4).
//
// Covers detect_format, the ELF identity path against the hello.elf fixture
// (exercising 64-bit little-endian x86-64), and a synthetic minimal PE32+ header
// built in-test (so no PE fixture file is required).

#include <gtest/gtest.h>

#include <peelf/binary_image.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <ranges>
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

struct ExpectedImage {
    const char* name;
    peelf::Format format;
    peelf::Architecture architecture;
    peelf::ImageKind kind;
    peelf::Endianness endianness;
    bool is_64bit;
    std::uint64_t entry_point;
    std::uint64_t text_file_offset;
    std::uint64_t text_virtual_address;
};

struct ExpectedElfHeader {
    const char* name;
    std::uint8_t elf_class;
    peelf::Endianness endianness;
    std::uint16_t machine;
    std::uint64_t program_header_offset;
    std::uint64_t section_header_offset;
    std::uint16_t header_size;
    std::uint16_t program_header_entry_size;
    std::uint16_t section_header_entry_size;
    std::uint16_t section_header_count;
};

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
    EXPECT_EQ(img.elf_header(), nullptr);
    EXPECT_TRUE(img.elf_program_headers().empty());
    EXPECT_TRUE(img.elf_section_headers().empty());
    EXPECT_TRUE(img.elf_symbols().empty());
    EXPECT_TRUE(img.elf_dynamic_entries().empty());

    ASSERT_EQ(img.sections().size(), 1u);
    const auto& sec = img.sections().front();
    EXPECT_EQ(sec.name, ".text");
    EXPECT_EQ(sec.virtual_address, 0x140000000ULL + 0x1000);
    EXPECT_TRUE(sec.executable);
    EXPECT_TRUE(sec.readable);
    EXPECT_FALSE(sec.writable);
}

TEST(BinaryImage, ParsesKnownArchitectureFixtures) {
    constexpr std::array<ExpectedImage, 4> fixtures{{
        {"known-linux-x64.elf", peelf::Format::ELF, peelf::Architecture::X86_64,
         peelf::ImageKind::Executable, peelf::Endianness::Little, true, 0x400080, 0x80, 0x400080},
        {"known-linux-arm64.elf", peelf::Format::ELF, peelf::Architecture::ARM64,
         peelf::ImageKind::Executable, peelf::Endianness::Little, true, 0x400080, 0x80, 0x400080},
        {"known-linux-riscv64.elf", peelf::Format::ELF, peelf::Architecture::RISCV64,
         peelf::ImageKind::Executable, peelf::Endianness::Little, true, 0x400080, 0x80, 0x400080},
        {"known-win-x64.exe", peelf::Format::PE, peelf::Architecture::X86_64,
         peelf::ImageKind::Executable, peelf::Endianness::Little, true, 0x140001000, 0x200, 0x140001000},
    }};

    for (const ExpectedImage& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const peelf::IBinaryImage& img = **result;
        EXPECT_EQ(img.format(), expected.format) << expected.name;
        EXPECT_EQ(img.architecture(), expected.architecture) << expected.name;
        EXPECT_EQ(img.kind(), expected.kind) << expected.name;
        EXPECT_EQ(img.endianness(), expected.endianness) << expected.name;
        EXPECT_EQ(img.is_64bit(), expected.is_64bit) << expected.name;
        EXPECT_EQ(img.entry_point(), expected.entry_point) << expected.name;

        ASSERT_FALSE(img.sections().empty()) << expected.name;
        const auto text = std::ranges::find_if(img.sections(), [](const peelf::Section& section) {
            return section.name == ".text";
        });
        ASSERT_NE(text, img.sections().end()) << expected.name;
        EXPECT_TRUE(text->readable) << expected.name;
        EXPECT_TRUE(text->executable) << expected.name;
        EXPECT_FALSE(text->writable) << expected.name;

        EXPECT_EQ(img.file_offset_to_virtual_address(expected.text_file_offset),
                  std::optional<std::uint64_t>(expected.text_virtual_address)) << expected.name;
        EXPECT_EQ(img.virtual_address_to_file_offset(expected.text_virtual_address),
                  std::optional<std::uint64_t>(expected.text_file_offset)) << expected.name;

        if (expected.format == peelf::Format::ELF) {
            ASSERT_EQ(img.segments().size(), 1u) << expected.name;
            const peelf::Segment& segment = img.segments().front();
            EXPECT_EQ(segment.type, 1u) << expected.name;  // PT_LOAD
            EXPECT_EQ(segment.file_offset, expected.text_file_offset) << expected.name;
            EXPECT_EQ(segment.file_size, 0x10u) << expected.name;
            EXPECT_EQ(segment.virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_EQ(segment.virtual_size, 0x10u) << expected.name;
            EXPECT_TRUE(segment.readable) << expected.name;
            EXPECT_TRUE(segment.executable) << expected.name;
            EXPECT_FALSE(segment.writable) << expected.name;

            const auto start_symbol = std::ranges::find_if(img.symbols(), [](const peelf::Symbol& symbol) {
                return symbol.name == "_start";
            });
            ASSERT_NE(start_symbol, img.symbols().end()) << expected.name;
            EXPECT_EQ(start_symbol->virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_EQ(start_symbol->size, 0x10u) << expected.name;
            EXPECT_EQ(start_symbol->binding, 1u) << expected.name;  // STB_GLOBAL
            EXPECT_EQ(start_symbol->type, 2u) << expected.name;     // STT_FUNC
            EXPECT_EQ(start_symbol->section_index, 1u) << expected.name;
            EXPECT_FALSE(start_symbol->dynamic) << expected.name;

            ASSERT_EQ(img.imports().size(), 1u) << expected.name;
            EXPECT_EQ(img.imports().front().library, "libc.so.6") << expected.name;
            EXPECT_TRUE(img.imports().front().name.empty()) << expected.name;
            EXPECT_TRUE(img.exports().empty()) << expected.name;
        } else {
            EXPECT_TRUE(img.segments().empty()) << expected.name;
            EXPECT_TRUE(img.symbols().empty()) << expected.name;

            ASSERT_EQ(img.imports().size(), 1u) << expected.name;
            const peelf::ImportEntry& imported = img.imports().front();
            EXPECT_EQ(imported.library, "KERNEL32.dll") << expected.name;
            EXPECT_EQ(imported.name, "ExitProcess") << expected.name;
            EXPECT_EQ(imported.address, 0x1400011D0ULL) << expected.name;

            ASSERT_EQ(img.exports().size(), 1u) << expected.name;
            const peelf::ExportEntry& exported = img.exports().front();
            EXPECT_EQ(exported.name, "known_export") << expected.name;
            EXPECT_EQ(exported.ordinal, 1u) << expected.name;
            EXPECT_EQ(exported.virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_TRUE(exported.forwarder.empty()) << expected.name;
        }
    }
}

TEST(BinaryImage, ParsesEndianAndClassCompatibilityFixtures) {
    constexpr std::array<ExpectedImage, 12> fixtures{{
        {"known-linux-x86-elf32-le.elf", peelf::Format::ELF, peelf::Architecture::X86,
         peelf::ImageKind::Executable, peelf::Endianness::Little, false, 0x400080, 0x80, 0x400080},
        {"known-linux-mips-elf32-be.elf", peelf::Format::ELF, peelf::Architecture::MIPS32,
         peelf::ImageKind::Executable, peelf::Endianness::Big, false, 0x400080, 0x80, 0x400080},
        {"known-linux-mips64-elf64-be.elf", peelf::Format::ELF, peelf::Architecture::MIPS64,
         peelf::ImageKind::Executable, peelf::Endianness::Big, true, 0x400080, 0x80, 0x400080},
        {"known-linux-arm-elf32-le.elf", peelf::Format::ELF, peelf::Architecture::ARM,
         peelf::ImageKind::Executable, peelf::Endianness::Little, false, 0x400080, 0x80, 0x400080},
        {"known-linux-arm-elf32-be.elf", peelf::Format::ELF, peelf::Architecture::ARM,
         peelf::ImageKind::Executable, peelf::Endianness::Big, false, 0x400080, 0x80, 0x400080},
        {"known-linux-arm64-elf64-be.elf", peelf::Format::ELF, peelf::Architecture::ARM64,
         peelf::ImageKind::Executable, peelf::Endianness::Big, true, 0x400080, 0x80, 0x400080},
        {"known-linux-riscv32-elf32-le.elf", peelf::Format::ELF, peelf::Architecture::RISCV32,
         peelf::ImageKind::Executable, peelf::Endianness::Little, false, 0x400080, 0x80, 0x400080},
        {"known-linux-riscv32-elf32-be.elf", peelf::Format::ELF, peelf::Architecture::RISCV32,
         peelf::ImageKind::Executable, peelf::Endianness::Big, false, 0x400080, 0x80, 0x400080},
        {"known-linux-riscv64-elf64-be.elf", peelf::Format::ELF, peelf::Architecture::RISCV64,
         peelf::ImageKind::Executable, peelf::Endianness::Big, true, 0x400080, 0x80, 0x400080},
        {"known-linux-ppc-elf32-be.elf", peelf::Format::ELF, peelf::Architecture::PowerPC,
         peelf::ImageKind::Executable, peelf::Endianness::Big, false, 0x400080, 0x80, 0x400080},
        {"known-linux-ppc64-elf64-be.elf", peelf::Format::ELF, peelf::Architecture::PowerPC64,
         peelf::ImageKind::Executable, peelf::Endianness::Big, true, 0x400080, 0x80, 0x400080},
        {"known-win-x86.exe", peelf::Format::PE, peelf::Architecture::X86,
         peelf::ImageKind::Executable, peelf::Endianness::Little, false, 0x401000, 0x200, 0x401000},
    }};

    for (const ExpectedImage& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const peelf::IBinaryImage& img = **result;
        EXPECT_EQ(img.format(), expected.format) << expected.name;
        EXPECT_EQ(img.architecture(), expected.architecture) << expected.name;
        EXPECT_EQ(img.kind(), expected.kind) << expected.name;
        EXPECT_EQ(img.endianness(), expected.endianness) << expected.name;
        EXPECT_EQ(img.is_64bit(), expected.is_64bit) << expected.name;
        EXPECT_EQ(img.entry_point(), expected.entry_point) << expected.name;

        const auto text = std::ranges::find_if(img.sections(), [](const peelf::Section& section) {
            return section.name == ".text";
        });
        ASSERT_NE(text, img.sections().end()) << expected.name;
        EXPECT_EQ(text->file_offset, expected.text_file_offset) << expected.name;
        EXPECT_EQ(text->virtual_address, expected.text_virtual_address) << expected.name;
        EXPECT_TRUE(text->readable) << expected.name;
        EXPECT_TRUE(text->executable) << expected.name;
        EXPECT_FALSE(text->writable) << expected.name;

        EXPECT_EQ(img.file_offset_to_virtual_address(expected.text_file_offset),
                  std::optional<std::uint64_t>(expected.text_virtual_address)) << expected.name;
        EXPECT_EQ(img.virtual_address_to_file_offset(expected.text_virtual_address),
                  std::optional<std::uint64_t>(expected.text_file_offset)) << expected.name;

        if (expected.format == peelf::Format::ELF) {
            ASSERT_EQ(img.segments().size(), 1u) << expected.name;
            EXPECT_EQ(img.segments().front().virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_EQ(img.segments().front().file_offset, expected.text_file_offset) << expected.name;
            EXPECT_TRUE(img.segments().front().readable) << expected.name;
            EXPECT_TRUE(img.segments().front().executable) << expected.name;

            const auto start_symbol = std::ranges::find_if(img.symbols(), [](const peelf::Symbol& symbol) {
                return symbol.name == "_start";
            });
            ASSERT_NE(start_symbol, img.symbols().end()) << expected.name;
            EXPECT_EQ(start_symbol->virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_EQ(start_symbol->size, 0x10u) << expected.name;
            EXPECT_EQ(start_symbol->binding, 1u) << expected.name;
            EXPECT_EQ(start_symbol->type, 2u) << expected.name;
            EXPECT_EQ(start_symbol->section_index, 1u) << expected.name;
            EXPECT_FALSE(start_symbol->dynamic) << expected.name;

            ASSERT_EQ(img.imports().size(), 1u) << expected.name;
            EXPECT_EQ(img.imports().front().library, "libc.so.6") << expected.name;
            EXPECT_TRUE(img.imports().front().name.empty()) << expected.name;
        } else {
            EXPECT_TRUE(img.segments().empty()) << expected.name;
        }
    }
}

TEST(BinaryImage, ParsesElfFileHeaderFieldsAcrossFixtureMatrix) {
    constexpr std::array<ExpectedElfHeader, 14> fixtures{{
        {"known-linux-x64.elf", 2, peelf::Endianness::Little, 62, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-arm64.elf", 2, peelf::Endianness::Little, 183, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-riscv64.elf", 2, peelf::Endianness::Little, 243, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-x86-elf32-le.elf", 1, peelf::Endianness::Little, 3, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-mips-elf32-be.elf", 1, peelf::Endianness::Big, 8, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-mips64-elf64-be.elf", 2, peelf::Endianness::Big, 8, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-arm-elf32-le.elf", 1, peelf::Endianness::Little, 40, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-arm-elf32-be.elf", 1, peelf::Endianness::Big, 40, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-arm64-elf64-be.elf", 2, peelf::Endianness::Big, 183, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-riscv32-elf32-le.elf", 1, peelf::Endianness::Little, 243, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-riscv32-elf32-be.elf", 1, peelf::Endianness::Big, 243, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-riscv64-elf64-be.elf", 2, peelf::Endianness::Big, 243, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
        {"known-linux-ppc-elf32-be.elf", 1, peelf::Endianness::Big, 20, 0x34, 0x180, 0x34, 0x20, 0x28, 7},
        {"known-linux-ppc64-elf64-be.elf", 2, peelf::Endianness::Big, 21, 0x40, 0x180, 0x40, 0x38, 0x40, 7},
    }};

    for (const ExpectedElfHeader& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const peelf::ElfHeader* header = (**result).elf_header();
        ASSERT_NE(header, nullptr) << expected.name;
        EXPECT_EQ(header->elf_class, expected.elf_class) << expected.name;
        EXPECT_EQ(header->data_encoding, expected.endianness == peelf::Endianness::Big ? 2u : 1u) << expected.name;
        EXPECT_EQ(header->ident_version, 1u) << expected.name;
        EXPECT_EQ(header->os_abi, 0u) << expected.name;
        EXPECT_EQ(header->abi_version, 0u) << expected.name;
        EXPECT_EQ(header->type, 2u) << expected.name;
        EXPECT_EQ(header->machine, expected.machine) << expected.name;
        EXPECT_EQ(header->version, 1u) << expected.name;
        EXPECT_EQ(header->entry, 0x400080u) << expected.name;
        EXPECT_EQ(header->program_header_offset, expected.program_header_offset) << expected.name;
        EXPECT_EQ(header->section_header_offset, expected.section_header_offset) << expected.name;
        EXPECT_EQ(header->flags, 0u) << expected.name;
        EXPECT_EQ(header->header_size, expected.header_size) << expected.name;
        EXPECT_EQ(header->program_header_entry_size, expected.program_header_entry_size) << expected.name;
        EXPECT_EQ(header->program_header_count, 1u) << expected.name;
        EXPECT_EQ(header->section_header_entry_size, expected.section_header_entry_size) << expected.name;
        EXPECT_EQ(header->section_header_count, expected.section_header_count) << expected.name;
        EXPECT_EQ(header->section_name_string_table_index, 2u) << expected.name;
    }
}

TEST(BinaryImage, ParsesElfProgramHeadersAcrossFixtureMatrix) {
    constexpr std::array<const char*, 14> fixtures{{
        "known-linux-x64.elf",
        "known-linux-arm64.elf",
        "known-linux-riscv64.elf",
        "known-linux-x86-elf32-le.elf",
        "known-linux-mips-elf32-be.elf",
        "known-linux-mips64-elf64-be.elf",
        "known-linux-arm-elf32-le.elf",
        "known-linux-arm-elf32-be.elf",
        "known-linux-arm64-elf64-be.elf",
        "known-linux-riscv32-elf32-le.elf",
        "known-linux-riscv32-elf32-be.elf",
        "known-linux-riscv64-elf64-be.elf",
        "known-linux-ppc-elf32-be.elf",
        "known-linux-ppc64-elf64-be.elf",
    }};

    for (const char* name : fixtures) {
        const auto path = fixture_path(name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << name;

        const auto& headers = (**result).elf_program_headers();
        ASSERT_EQ(headers.size(), 1u) << name;
        const peelf::ElfProgramHeader& header = headers.front();
        EXPECT_EQ(header.type, 1u) << name;   // PT_LOAD
        EXPECT_EQ(header.flags, 5u) << name;  // PF_R | PF_X
        EXPECT_EQ(header.offset, 0x80u) << name;
        EXPECT_EQ(header.virtual_address, 0x400080u) << name;
        EXPECT_EQ(header.physical_address, 0x400080u) << name;
        EXPECT_EQ(header.file_size, 0x10u) << name;
        EXPECT_EQ(header.memory_size, 0x10u) << name;
        EXPECT_EQ(header.alignment, 0x1000u) << name;

        ASSERT_EQ((**result).segments().size(), 1u) << name;
        const peelf::Segment& segment = (**result).segments().front();
        EXPECT_EQ(segment.type, header.type) << name;
        EXPECT_EQ(segment.file_offset, header.offset) << name;
        EXPECT_EQ(segment.virtual_address, header.virtual_address) << name;
        EXPECT_EQ(segment.file_size, header.file_size) << name;
        EXPECT_EQ(segment.virtual_size, header.memory_size) << name;
    }
}

TEST(BinaryImage, ParsesElfSectionHeadersAcrossFixtureMatrix) {
    constexpr std::array<const char*, 14> fixtures{{
        "known-linux-x64.elf",
        "known-linux-arm64.elf",
        "known-linux-riscv64.elf",
        "known-linux-x86-elf32-le.elf",
        "known-linux-mips-elf32-be.elf",
        "known-linux-mips64-elf64-be.elf",
        "known-linux-arm-elf32-le.elf",
        "known-linux-arm-elf32-be.elf",
        "known-linux-arm64-elf64-be.elf",
        "known-linux-riscv32-elf32-le.elf",
        "known-linux-riscv32-elf32-be.elf",
        "known-linux-riscv64-elf64-be.elf",
        "known-linux-ppc-elf32-be.elf",
        "known-linux-ppc64-elf64-be.elf",
    }};

    for (const char* name : fixtures) {
        const auto path = fixture_path(name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << name;

        const auto& headers = (**result).elf_section_headers();
        ASSERT_GE(headers.size(), 3u) << name;
        EXPECT_EQ(headers.front().name_offset, 0u) << name;
        EXPECT_TRUE(headers.front().name.empty()) << name;
        EXPECT_EQ(headers.front().type, 0u) << name;  // SHT_NULL

        const auto text = std::ranges::find_if(headers, [](const peelf::ElfSectionHeader& section) {
            return section.name == ".text";
        });
        ASSERT_NE(text, headers.end()) << name;
        EXPECT_EQ(text->name_offset, 1u) << name;
        EXPECT_EQ(text->type, 1u) << name;   // SHT_PROGBITS
        EXPECT_EQ(text->flags, 6u) << name;  // SHF_ALLOC | SHF_EXECINSTR
        EXPECT_EQ(text->address, 0x400080u) << name;
        EXPECT_EQ(text->offset, 0x80u) << name;
        EXPECT_EQ(text->size, 0x10u) << name;
        EXPECT_EQ(text->link, 0u) << name;
        EXPECT_EQ(text->info, 0u) << name;
        EXPECT_EQ(text->address_alignment, 0x10u) << name;
        EXPECT_EQ(text->entry_size, 0u) << name;

        const auto shstrtab = std::ranges::find_if(headers, [](const peelf::ElfSectionHeader& section) {
            return section.name == ".shstrtab";
        });
        ASSERT_NE(shstrtab, headers.end()) << name;
        EXPECT_EQ(shstrtab->type, 3u) << name;  // SHT_STRTAB
        EXPECT_EQ(shstrtab->flags, 0u) << name;
        EXPECT_EQ(shstrtab->address, 0u) << name;
        EXPECT_EQ(shstrtab->address_alignment, 1u) << name;

        const auto projected_text = std::ranges::find_if((**result).sections(), [](const peelf::Section& section) {
            return section.name == ".text";
        });
        ASSERT_NE(projected_text, (**result).sections().end()) << name;
        EXPECT_EQ(projected_text->virtual_address, text->address) << name;
        EXPECT_EQ(projected_text->virtual_size, text->size) << name;
        EXPECT_EQ(projected_text->file_offset, text->offset) << name;
        EXPECT_EQ(projected_text->file_size, text->size) << name;
    }
}

TEST(BinaryImage, ParsesRichElfSectionHeaders) {
    constexpr std::array<const char*, 3> fixtures{{
        "known-linux-x64.elf",
        "known-linux-arm64.elf",
        "known-linux-riscv64.elf",
    }};

    for (const char* name : fixtures) {
        const auto path = fixture_path(name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << name;

        const auto& headers = (**result).elf_section_headers();
        ASSERT_EQ(headers.size(), 7u) << name;

        const auto symtab = std::ranges::find_if(headers, [](const peelf::ElfSectionHeader& section) {
            return section.name == ".symtab";
        });
        ASSERT_NE(symtab, headers.end()) << name;
        EXPECT_EQ(symtab->type, 2u) << name;  // SHT_SYMTAB
        EXPECT_EQ(symtab->offset, 0xD8u) << name;
        EXPECT_EQ(symtab->size, 0x30u) << name;
        EXPECT_EQ(symtab->link, 3u) << name;
        EXPECT_EQ(symtab->info, 1u) << name;
        EXPECT_EQ(symtab->address_alignment, 8u) << name;
        EXPECT_EQ(symtab->entry_size, 0x18u) << name;

        const auto dynamic = std::ranges::find_if(headers, [](const peelf::ElfSectionHeader& section) {
            return section.name == ".dynamic";
        });
        ASSERT_NE(dynamic, headers.end()) << name;
        EXPECT_EQ(dynamic->type, 6u) << name;  // SHT_DYNAMIC
        EXPECT_EQ(dynamic->flags, 2u) << name;
        EXPECT_EQ(dynamic->offset, 0x118u) << name;
        EXPECT_EQ(dynamic->size, 0x20u) << name;
        EXPECT_EQ(dynamic->link, 5u) << name;
        EXPECT_EQ(dynamic->address_alignment, 8u) << name;
        EXPECT_EQ(dynamic->entry_size, 0x10u) << name;
    }
}

TEST(BinaryImage, ParsesElfSymbolsAcrossFixtureMatrix) {
    constexpr std::array<const char*, 14> fixtures{{
        "known-linux-x64.elf",
        "known-linux-arm64.elf",
        "known-linux-riscv64.elf",
        "known-linux-x86-elf32-le.elf",
        "known-linux-mips-elf32-be.elf",
        "known-linux-mips64-elf64-be.elf",
        "known-linux-arm-elf32-le.elf",
        "known-linux-arm-elf32-be.elf",
        "known-linux-arm64-elf64-be.elf",
        "known-linux-riscv32-elf32-le.elf",
        "known-linux-riscv32-elf32-be.elf",
        "known-linux-riscv64-elf64-be.elf",
        "known-linux-ppc-elf32-be.elf",
        "known-linux-ppc64-elf64-be.elf",
    }};

    for (const char* name : fixtures) {
        const auto path = fixture_path(name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << name;

        const auto& raw_symbols = (**result).elf_symbols();
        ASSERT_EQ(raw_symbols.size(), 2u) << name;
        EXPECT_TRUE(raw_symbols.front().name.empty()) << name;
        EXPECT_EQ(raw_symbols.front().name_offset, 0u) << name;
        EXPECT_EQ(raw_symbols.front().info, 0u) << name;
        EXPECT_EQ(raw_symbols.front().other, 0u) << name;
        EXPECT_EQ(raw_symbols.front().binding, 0u) << name;
        EXPECT_EQ(raw_symbols.front().type, 0u) << name;
        EXPECT_EQ(raw_symbols.front().visibility, 0u) << name;
        EXPECT_EQ(raw_symbols.front().section_index, 0u) << name;
        EXPECT_EQ(raw_symbols.front().value, 0u) << name;
        EXPECT_EQ(raw_symbols.front().size, 0u) << name;
        EXPECT_FALSE(raw_symbols.front().dynamic) << name;

        const peelf::ElfSymbol& start = raw_symbols.back();
        EXPECT_EQ(start.name, "_start") << name;
        EXPECT_EQ(start.name_offset, 1u) << name;
        EXPECT_EQ(start.info, 0x12u) << name;
        EXPECT_EQ(start.other, 0u) << name;
        EXPECT_EQ(start.binding, 1u) << name;     // STB_GLOBAL
        EXPECT_EQ(start.type, 2u) << name;        // STT_FUNC
        EXPECT_EQ(start.visibility, 0u) << name;  // STV_DEFAULT
        EXPECT_EQ(start.section_index, 1u) << name;
        EXPECT_EQ(start.value, 0x400080u) << name;
        EXPECT_EQ(start.size, 0x10u) << name;
        EXPECT_FALSE(start.dynamic) << name;

        ASSERT_EQ((**result).symbols().size(), 1u) << name;
        const peelf::Symbol& projected = (**result).symbols().front();
        EXPECT_EQ(projected.name, start.name) << name;
        EXPECT_EQ(projected.virtual_address, start.value) << name;
        EXPECT_EQ(projected.size, start.size) << name;
        EXPECT_EQ(projected.binding, start.binding) << name;
        EXPECT_EQ(projected.type, start.type) << name;
        EXPECT_EQ(projected.section_index, start.section_index) << name;
        EXPECT_EQ(projected.dynamic, start.dynamic) << name;
    }
}

TEST(BinaryImage, ParsesElfDynamicEntriesAcrossFixtureMatrix) {
    constexpr std::array<const char*, 14> fixtures{{
        "known-linux-x64.elf",
        "known-linux-arm64.elf",
        "known-linux-riscv64.elf",
        "known-linux-x86-elf32-le.elf",
        "known-linux-mips-elf32-be.elf",
        "known-linux-mips64-elf64-be.elf",
        "known-linux-arm-elf32-le.elf",
        "known-linux-arm-elf32-be.elf",
        "known-linux-arm64-elf64-be.elf",
        "known-linux-riscv32-elf32-le.elf",
        "known-linux-riscv32-elf32-be.elf",
        "known-linux-riscv64-elf64-be.elf",
        "known-linux-ppc-elf32-be.elf",
        "known-linux-ppc64-elf64-be.elf",
    }};

    for (const char* name : fixtures) {
        const auto path = fixture_path(name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << name;

        const auto& dynamic = (**result).elf_dynamic_entries();
        ASSERT_EQ(dynamic.size(), 2u) << name;
        EXPECT_EQ(dynamic[0].tag, 1u) << name;    // DT_NEEDED
        EXPECT_EQ(dynamic[0].value, 1u) << name;  // string-table offset of "libc.so.6"
        EXPECT_EQ(dynamic[0].needed_library, "libc.so.6") << name;
        EXPECT_EQ(dynamic[1].tag, 0u) << name;    // DT_NULL
        EXPECT_EQ(dynamic[1].value, 0u) << name;
        EXPECT_TRUE(dynamic[1].needed_library.empty()) << name;

        ASSERT_EQ((**result).imports().size(), 1u) << name;
        EXPECT_EQ((**result).imports().front().library, dynamic[0].needed_library) << name;
        EXPECT_TRUE((**result).imports().front().name.empty()) << name;
    }
}

TEST(BinaryImage, RejectsTruncatedElfFileHeader) {
    std::vector<std::uint8_t> b(0x20, 0);
    b[0] = 0x7F;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 2;  // ELFCLASS64 requires a 64-byte file header.
    b[5] = 1;
    b[6] = 1;

    const auto result = peelf::parse_image(b);
    EXPECT_FALSE(result.has_value());
}

TEST(BinaryImage, RejectsUnknownFormat) {
    const std::vector<std::uint8_t> junk(64, 0);
    const auto result = peelf::parse_image(junk);
    EXPECT_FALSE(result.has_value());
}

TEST(BinaryImage, RejectsPeWithUnsupportedOptionalMagic) {
    std::vector<std::uint8_t> b(0x200, 0);
    b[0] = 'M';
    b[1] = 'Z';

    const std::uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);
    b[e_lfanew + 0] = 'P';
    b[e_lfanew + 1] = 'E';

    const std::size_t coff = e_lfanew + 4;
    put16(b, coff + 0, 0x8664);
    put16(b, coff + 16, 0x00F0);

    const std::size_t opt = coff + 20;
    put16(b, opt + 0, 0x9999);

    const auto result = peelf::parse_image(b);
    EXPECT_FALSE(result.has_value());
}

TEST(BinaryImage, IgnoresOverflowingElfSectionTable) {
    std::vector<std::uint8_t> b(0x80, 0);
    b[0] = 0x7F;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 2;  // ELFCLASS64
    b[5] = 1;  // little-endian
    b[6] = 1;  // EV_CURRENT
    put16(b, 0x10, 2);
    put16(b, 0x12, 62);
    put32(b, 0x14, 1);
    put64(b, 0x18, 0x400000);
    put64(b, 0x28, 0xFFFF'FFFF'FFFF'FFF0ULL);
    put16(b, 0x34, 0x40);
    put16(b, 0x3A, 0x40);
    put16(b, 0x3C, 2);
    put16(b, 0x3E, 1);

    auto result = peelf::parse_image(b);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE((**result).sections().empty());
}
