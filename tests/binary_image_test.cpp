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
    EXPECT_TRUE(img.pe_base_relocations().empty());
    EXPECT_TRUE(img.pe_debug_directories().empty());
    EXPECT_EQ(img.elf_header(), nullptr);
    EXPECT_TRUE(img.elf_program_headers().empty());
    EXPECT_TRUE(img.elf_section_headers().empty());
    EXPECT_TRUE(img.elf_symbols().empty());
    EXPECT_TRUE(img.elf_dynamic_entries().empty());
    EXPECT_TRUE(img.elf_relocations().empty());
    EXPECT_TRUE(img.elf_notes().empty());
    EXPECT_TRUE(img.elf_sysv_hash_tables().empty());
    EXPECT_TRUE(img.elf_gnu_hash_tables().empty());
    EXPECT_TRUE(img.elf_interpreter().empty());

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
            ASSERT_EQ(img.segments().size(), 3u) << expected.name;
            const auto load_segment = std::ranges::find_if(img.segments(), [](const peelf::Segment& segment) {
                return segment.type == 1;
            });
            ASSERT_NE(load_segment, img.segments().end()) << expected.name;
            const peelf::Segment& segment = *load_segment;
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
            ASSERT_EQ(img.segments().size(), 3u) << expected.name;
            const auto load_segment = std::ranges::find_if(img.segments(), [](const peelf::Segment& segment) {
                return segment.type == 1;
            });
            ASSERT_NE(load_segment, img.segments().end()) << expected.name;
            EXPECT_EQ(load_segment->virtual_address, expected.text_virtual_address) << expected.name;
            EXPECT_EQ(load_segment->file_offset, expected.text_file_offset) << expected.name;
            EXPECT_TRUE(load_segment->readable) << expected.name;
            EXPECT_TRUE(load_segment->executable) << expected.name;

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

TEST(BinaryImage, ParsesPeBaseRelocationsAcrossFixtureMatrix) {
    struct ExpectedRelocation {
        const char* name;
        std::uint16_t type;
        std::uint16_t offset;
        std::uint32_t rva;
        std::uint64_t relocation_section_virtual_address;
        std::uint64_t virtual_address;
        std::uint64_t file_offset;
    };
    constexpr std::array<ExpectedRelocation, 2> fixtures{{
        {"known-win-x86.exe", 3, 0x010, 0x1010, 0x402000, 0x401010, 0x210},
        {"known-win-x64.exe", 10, 0x088, 0x1088, 0x140002000, 0x140001088, 0x288},
    }};

    for (const ExpectedRelocation& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto reloc_section = std::ranges::find_if((**result).sections(), [](const peelf::Section& section) {
            return section.name == ".reloc";
        });
        ASSERT_NE(reloc_section, (**result).sections().end()) << expected.name;
        EXPECT_EQ(reloc_section->virtual_address, expected.relocation_section_virtual_address) << expected.name;
        EXPECT_EQ(reloc_section->virtual_size, 0x0Cu) << expected.name;
        EXPECT_FALSE(reloc_section->executable) << expected.name;
        EXPECT_TRUE(reloc_section->readable) << expected.name;
        EXPECT_FALSE(reloc_section->writable) << expected.name;

        const auto& blocks = (**result).pe_base_relocations();
        ASSERT_EQ(blocks.size(), 1u) << expected.name;
        const peelf::PeBaseRelocationBlock& block = blocks.front();
        EXPECT_EQ(block.page_rva, 0x1000u) << expected.name;
        EXPECT_EQ(block.block_size, 0x0Cu) << expected.name;
        ASSERT_EQ(block.entries.size(), 2u) << expected.name;

        const peelf::PeBaseRelocationEntry& relocation = block.entries.front();
        EXPECT_EQ(relocation.page_rva, block.page_rva) << expected.name;
        EXPECT_EQ(relocation.type, expected.type) << expected.name;
        EXPECT_EQ(relocation.offset, expected.offset) << expected.name;
        EXPECT_EQ(relocation.rva, expected.rva) << expected.name;
        EXPECT_EQ((**result).file_offset_to_virtual_address(expected.file_offset),
                  std::optional<std::uint64_t>(expected.virtual_address)) << expected.name;
        EXPECT_EQ((**result).virtual_address_to_file_offset(expected.virtual_address),
                  std::optional<std::uint64_t>(expected.file_offset)) << expected.name;

        const peelf::PeBaseRelocationEntry& padding = block.entries.back();
        EXPECT_EQ(padding.type, 0u) << expected.name;  // IMAGE_REL_BASED_ABSOLUTE
        EXPECT_EQ(padding.offset, 0u) << expected.name;
        EXPECT_EQ(padding.rva, block.page_rva) << expected.name;
    }
}

TEST(BinaryImage, ParsesPeDebugDirectoriesAcrossFixtureMatrix) {
    struct ExpectedDebug {
        const char* name;
        std::uint32_t time_date_stamp;
        std::uint32_t pointer_to_raw_data;
        std::uint64_t debug_section_virtual_address;
        std::uint32_t codeview_age;
        const char* pdb_path;
        std::uint8_t guid_base;
    };
    constexpr std::array<ExpectedDebug, 2> fixtures{{
        {"known-win-x86.exe", 0x5E2A5A32, 0x41C, 0x403000, 1, "known-win-x86.pdb", 0x10},
        {"known-win-x64.exe", 0x5E2A5A64, 0x51C, 0x140003000, 2, "known-win-x64.pdb", 0x20},
    }};

    for (const ExpectedDebug& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto debug_section = std::ranges::find_if((**result).sections(), [](const peelf::Section& section) {
            return section.name == ".debug";
        });
        ASSERT_NE(debug_section, (**result).sections().end()) << expected.name;
        EXPECT_EQ(debug_section->virtual_address, expected.debug_section_virtual_address) << expected.name;
        EXPECT_EQ(debug_section->virtual_size, 0x80u) << expected.name;
        EXPECT_TRUE(debug_section->readable) << expected.name;
        EXPECT_FALSE(debug_section->writable) << expected.name;
        EXPECT_FALSE(debug_section->executable) << expected.name;

        const auto& debug = (**result).pe_debug_directories();
        ASSERT_EQ(debug.size(), 1u) << expected.name;
        const peelf::PeDebugDirectory& entry = debug.front();
        EXPECT_EQ(entry.characteristics, 0u) << expected.name;
        EXPECT_EQ(entry.time_date_stamp, expected.time_date_stamp) << expected.name;
        EXPECT_EQ(entry.major_version, 0u) << expected.name;
        EXPECT_EQ(entry.minor_version, 0u) << expected.name;
        EXPECT_EQ(entry.type, 2u) << expected.name;  // IMAGE_DEBUG_TYPE_CODEVIEW
        EXPECT_EQ(entry.size_of_data, 0x2Au) << expected.name;
        EXPECT_EQ(entry.address_of_raw_data, 0x301Cu) << expected.name;
        EXPECT_EQ(entry.pointer_to_raw_data, expected.pointer_to_raw_data) << expected.name;
        EXPECT_EQ(entry.codeview_signature, 0x5344'5352u) << expected.name;  // "RSDS"
        EXPECT_EQ(entry.codeview_age, expected.codeview_age) << expected.name;
        EXPECT_EQ(entry.codeview_pdb_path, expected.pdb_path) << expected.name;
        ASSERT_EQ(entry.codeview_guid.size(), 16u) << expected.name;
        for (std::uint8_t i = 0; i < 16; ++i) {
            EXPECT_EQ(entry.codeview_guid[i], static_cast<std::uint8_t>(expected.guid_base + i)) << expected.name;
        }
    }
}

TEST(BinaryImage, ParsesPeTlsDirectoriesAcrossFixtureMatrix) {
    struct ExpectedTls {
        const char* name;
        std::uint64_t raw_data_start_va;
        std::uint64_t raw_data_end_va;
        std::uint64_t address_of_index;
        std::uint64_t address_of_callbacks;
        std::uint32_t size_of_zero_fill;
        std::uint32_t characteristics;
        std::uint64_t callback;
    };
    constexpr std::array<ExpectedTls, 2> fixtures{{
        {"known-win-x86.exe", 0x404010, 0x404018, 0x404020, 0x404030, 4, 0x00300000, 0x401010},
        {"known-win-x64.exe", 0x140004010, 0x140004020, 0x140004030, 0x140004040, 8, 0x00400000, 0x140001088},
    }};

    for (const ExpectedTls& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const peelf::PeTlsDirectory* tls = (**result).pe_tls_directory();
        ASSERT_NE(tls, nullptr) << expected.name;
        EXPECT_EQ(tls->raw_data_start_va, expected.raw_data_start_va) << expected.name;
        EXPECT_EQ(tls->raw_data_end_va, expected.raw_data_end_va) << expected.name;
        EXPECT_EQ(tls->address_of_index, expected.address_of_index) << expected.name;
        EXPECT_EQ(tls->address_of_callbacks, expected.address_of_callbacks) << expected.name;
        EXPECT_EQ(tls->size_of_zero_fill, expected.size_of_zero_fill) << expected.name;
        EXPECT_EQ(tls->characteristics, expected.characteristics) << expected.name;
        ASSERT_EQ(tls->callbacks.size(), 1u) << expected.name;
        EXPECT_EQ(tls->callbacks.front(), expected.callback) << expected.name;
    }
}

TEST(BinaryImage, ParsesPeCertificateTableAcrossFixtureMatrix) {
    struct ExpectedCertificate {
        const char* name;
        std::uint32_t file_offset;
        std::uint32_t length;
        std::uint16_t revision;
        std::uint16_t certificate_type;
        std::uint8_t payload_base;
    };
    constexpr std::array<ExpectedCertificate, 2> fixtures{{
        {"known-win-x86.exe", 0x700, 0x20, 0x0200, 0x0002, 0x30},
        {"known-win-x64.exe", 0x700, 0x20, 0x0200, 0x0002, 0x40},
    }};

    for (const ExpectedCertificate& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto& certs = (**result).pe_certificates();
        ASSERT_EQ(certs.size(), 1u) << expected.name;
        const peelf::PeCertificate& cert = certs.front();
        EXPECT_EQ(cert.file_offset, expected.file_offset) << expected.name;
        EXPECT_EQ(cert.length, expected.length) << expected.name;
        EXPECT_EQ(cert.revision, expected.revision) << expected.name;
        EXPECT_EQ(cert.certificate_type, expected.certificate_type) << expected.name;
        ASSERT_EQ(cert.certificate.size(), expected.length - 8u) << expected.name;
        for (std::uint8_t i = 0; i < cert.certificate.size(); ++i) {
            EXPECT_EQ(cert.certificate[i], static_cast<std::uint8_t>(expected.payload_base + i)) << expected.name;
        }

        EXPECT_EQ((**result).file_offset_to_virtual_address(expected.file_offset), std::nullopt) << expected.name;
    }
}

TEST(BinaryImage, ParsesPeLoadConfigDirectoriesAcrossFixtureMatrix) {
    struct ExpectedLoadConfig {
        const char* name;
        std::uint32_t rva;
        std::uint32_t size;
        std::uint32_t time_date_stamp;
        std::uint16_t major_version;
        std::uint16_t minor_version;
        std::uint32_t global_flags_clear;
        std::uint32_t global_flags_set;
        std::uint64_t critical_section_default_timeout;
        std::uint64_t decommit_free_block_threshold;
        std::uint64_t decommit_total_free_threshold;
        std::uint64_t security_cookie;
        std::uint64_t se_handler_table;
        std::uint64_t se_handler_count;
        std::uint64_t guard_cf_check_function_pointer;
        std::uint64_t guard_cf_dispatch_function_pointer;
        std::uint64_t guard_cf_function_table;
        std::uint64_t guard_cf_function_count;
        std::uint32_t guard_flags;
        std::uint64_t file_offset;
    };
    constexpr std::array<ExpectedLoadConfig, 2> fixtures{{
        {"known-win-x86.exe", 0x4050, 0x5C, 0x6A2A5A32, 1, 2, 0x10, 0x20, 0x30,
         0x1000, 0x2000, 0x405020, 0x405030, 3, 0x405040, 0x405044, 0x405050, 4,
         0x0000'4100, 0x550},
        {"known-win-x64.exe", 0x4050, 0x94, 0x6A2A5A64, 3, 4, 0x30, 0x40, 0x50,
         0x1000'0000, 0x2000'0000, 0x140005020, 0x140005030, 5, 0x140005040,
         0x140005048, 0x140005060, 6, 0x0000'4500, 0x650},
    }};

    for (const ExpectedLoadConfig& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const peelf::PeLoadConfigDirectory* load_config = (**result).pe_load_config_directory();
        ASSERT_NE(load_config, nullptr) << expected.name;
        EXPECT_EQ(load_config->rva, expected.rva) << expected.name;
        EXPECT_EQ(load_config->file_offset, expected.file_offset) << expected.name;
        EXPECT_EQ(load_config->size, expected.size) << expected.name;
        EXPECT_EQ(load_config->time_date_stamp, expected.time_date_stamp) << expected.name;
        EXPECT_EQ(load_config->major_version, expected.major_version) << expected.name;
        EXPECT_EQ(load_config->minor_version, expected.minor_version) << expected.name;
        EXPECT_EQ(load_config->global_flags_clear, expected.global_flags_clear) << expected.name;
        EXPECT_EQ(load_config->global_flags_set, expected.global_flags_set) << expected.name;
        EXPECT_EQ(load_config->critical_section_default_timeout,
                  expected.critical_section_default_timeout) << expected.name;
        EXPECT_EQ(load_config->decommit_free_block_threshold,
                  expected.decommit_free_block_threshold) << expected.name;
        EXPECT_EQ(load_config->decommit_total_free_threshold,
                  expected.decommit_total_free_threshold) << expected.name;
        EXPECT_EQ(load_config->security_cookie, expected.security_cookie) << expected.name;
        EXPECT_EQ(load_config->se_handler_table, expected.se_handler_table) << expected.name;
        EXPECT_EQ(load_config->se_handler_count, expected.se_handler_count) << expected.name;
        EXPECT_EQ(load_config->guard_cf_check_function_pointer,
                  expected.guard_cf_check_function_pointer) << expected.name;
        EXPECT_EQ(load_config->guard_cf_dispatch_function_pointer,
                  expected.guard_cf_dispatch_function_pointer) << expected.name;
        EXPECT_EQ(load_config->guard_cf_function_table, expected.guard_cf_function_table) << expected.name;
        EXPECT_EQ(load_config->guard_cf_function_count, expected.guard_cf_function_count) << expected.name;
        EXPECT_EQ(load_config->guard_flags, expected.guard_flags) << expected.name;
    }
}

TEST(BinaryImage, ParsesPeRuntimeFunctionsAcrossFixtureMatrix) {
    struct ExpectedRuntimeFunction {
        const char* name;
        std::uint32_t begin_address_rva;
        std::uint32_t end_address_rva;
        std::uint32_t unwind_info_rva;
        std::uint64_t file_offset;
        std::uint64_t begin_va;
        std::uint64_t unwind_info_va;
    };
    constexpr std::array<ExpectedRuntimeFunction, 2> fixtures{{
        {"known-win-x86.exe", 0x1000, 0x1010, 0x1090, 0x280, 0x401000, 0x401090},
        {"known-win-x64.exe", 0x1000, 0x1010, 0x1090, 0x280, 0x140001000, 0x140001090},
    }};

    for (const ExpectedRuntimeFunction& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto& runtime_functions = (**result).pe_runtime_functions();
        ASSERT_EQ(runtime_functions.size(), 1u) << expected.name;
        const peelf::PeRuntimeFunction& function = runtime_functions.front();
        EXPECT_EQ(function.begin_address_rva, expected.begin_address_rva) << expected.name;
        EXPECT_EQ(function.end_address_rva, expected.end_address_rva) << expected.name;
        EXPECT_EQ(function.unwind_info_rva, expected.unwind_info_rva) << expected.name;
        EXPECT_EQ(function.file_offset, expected.file_offset) << expected.name;
        EXPECT_EQ((**result).file_offset_to_virtual_address(function.file_offset),
                  std::optional<std::uint64_t>(expected.begin_va + 0x80u)) << expected.name;
        EXPECT_EQ((**result).virtual_address_to_file_offset(expected.begin_va),
                  std::optional<std::uint64_t>(0x200)) << expected.name;
        EXPECT_EQ((**result).virtual_address_to_file_offset(expected.unwind_info_va),
                  std::optional<std::uint64_t>(0x290)) << expected.name;
    }
}

TEST(BinaryImage, ParsesElfFileHeaderFieldsAcrossFixtureMatrix) {
    constexpr std::array<ExpectedElfHeader, 14> fixtures{{
        {"known-linux-x64.elf", 2, peelf::Endianness::Little, 62, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-arm64.elf", 2, peelf::Endianness::Little, 183, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-riscv64.elf", 2, peelf::Endianness::Little, 243, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-x86-elf32-le.elf", 1, peelf::Endianness::Little, 3, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-mips-elf32-be.elf", 1, peelf::Endianness::Big, 8, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-mips64-elf64-be.elf", 2, peelf::Endianness::Big, 8, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-arm-elf32-le.elf", 1, peelf::Endianness::Little, 40, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-arm-elf32-be.elf", 1, peelf::Endianness::Big, 40, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-arm64-elf64-be.elf", 2, peelf::Endianness::Big, 183, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-riscv32-elf32-le.elf", 1, peelf::Endianness::Little, 243, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-riscv32-elf32-be.elf", 1, peelf::Endianness::Big, 243, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-riscv64-elf64-be.elf", 2, peelf::Endianness::Big, 243, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
        {"known-linux-ppc-elf32-be.elf", 1, peelf::Endianness::Big, 20, 0x480, 0x180, 0x34, 0x20, 0x28, 11},
        {"known-linux-ppc64-elf64-be.elf", 2, peelf::Endianness::Big, 21, 0x480, 0x180, 0x40, 0x38, 0x40, 11},
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
        EXPECT_EQ(header->program_header_count, 3u) << expected.name;
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
        ASSERT_EQ(headers.size(), 3u) << name;
        const auto load_header = std::ranges::find_if(headers, [](const peelf::ElfProgramHeader& header) {
            return header.type == 1;
        });
        ASSERT_NE(load_header, headers.end()) << name;
        EXPECT_EQ(load_header->flags, 5u) << name;  // PF_R | PF_X
        EXPECT_EQ(load_header->offset, 0x80u) << name;
        EXPECT_EQ(load_header->virtual_address, 0x400080u) << name;
        EXPECT_EQ(load_header->physical_address, 0x400080u) << name;
        EXPECT_EQ(load_header->file_size, 0x10u) << name;
        EXPECT_EQ(load_header->memory_size, 0x10u) << name;
        EXPECT_EQ(load_header->alignment, 0x1000u) << name;

        const auto interp_header = std::ranges::find_if(headers, [](const peelf::ElfProgramHeader& header) {
            return header.type == 3;
        });
        ASSERT_NE(interp_header, headers.end()) << name;
        EXPECT_EQ(interp_header->flags, 4u) << name;  // PF_R
        EXPECT_EQ(interp_header->offset, 0x540u) << name;
        EXPECT_EQ(interp_header->virtual_address, 0x400540u) << name;
        EXPECT_EQ(interp_header->physical_address, 0x400540u) << name;
        EXPECT_EQ(interp_header->file_size, 0x11u) << name;
        EXPECT_EQ(interp_header->memory_size, 0x11u) << name;
        EXPECT_EQ(interp_header->alignment, 1u) << name;

        const auto note_header = std::ranges::find_if(headers, [](const peelf::ElfProgramHeader& header) {
            return header.type == 4;
        });
        ASSERT_NE(note_header, headers.end()) << name;
        EXPECT_EQ(note_header->flags, 4u) << name;  // PF_R
        EXPECT_EQ(note_header->offset, 0x560u) << name;
        EXPECT_EQ(note_header->virtual_address, 0x400560u) << name;
        EXPECT_EQ(note_header->physical_address, 0x400560u) << name;
        EXPECT_EQ(note_header->file_size, 0x18u) << name;
        EXPECT_EQ(note_header->memory_size, 0x18u) << name;
        EXPECT_EQ(note_header->alignment, 4u) << name;

        ASSERT_EQ((**result).segments().size(), 3u) << name;
        const auto load_segment = std::ranges::find_if((**result).segments(), [](const peelf::Segment& segment) {
            return segment.type == 1;
        });
        ASSERT_NE(load_segment, (**result).segments().end()) << name;
        EXPECT_EQ(load_segment->file_offset, load_header->offset) << name;
        EXPECT_EQ(load_segment->virtual_address, load_header->virtual_address) << name;
        EXPECT_EQ(load_segment->file_size, load_header->file_size) << name;
        EXPECT_EQ(load_segment->virtual_size, load_header->memory_size) << name;
    }
}

TEST(BinaryImage, ParsesElfInterpreterAcrossFixtureMatrix) {
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

        EXPECT_EQ((**result).elf_interpreter(), "/lib/ld-peelf.so") << name;
    }
}

TEST(BinaryImage, ParsesElfNotesAcrossFixtureMatrix) {
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

        const auto& notes = (**result).elf_notes();
        ASSERT_EQ(notes.size(), 2u) << name;
        EXPECT_TRUE(notes[0].from_program_header) << name;
        EXPECT_FALSE(notes[1].from_program_header) << name;
        for (const peelf::ElfNote& note : notes) {
            EXPECT_EQ(note.name, "PEELF") << name;
            EXPECT_EQ(note.type, 1u) << name;
            ASSERT_EQ(note.descriptor.size(), 4u) << name;
            EXPECT_EQ(note.descriptor[0], 0x11u) << name;
            EXPECT_EQ(note.descriptor[1], 0x22u) << name;
            EXPECT_EQ(note.descriptor[2], 0x33u) << name;
            EXPECT_EQ(note.descriptor[3], 0x44u) << name;
        }

        const auto note_section = std::ranges::find_if(
            (**result).elf_section_headers(), [](const peelf::ElfSectionHeader& section) {
                return section.name == ".note.peelf";
            });
        ASSERT_NE(note_section, (**result).elf_section_headers().end()) << name;
        EXPECT_EQ(note_section->type, 7u) << name;  // SHT_NOTE
        EXPECT_EQ(note_section->offset, 0x560u) << name;
        EXPECT_EQ(note_section->size, 0x18u) << name;
        EXPECT_EQ(note_section->address_alignment, 4u) << name;
    }
}

TEST(BinaryImage, ParsesElfHashTablesAcrossFixtureMatrix) {
    struct ExpectedHashFixture {
        const char* name;
        bool is_64bit;
    };
    constexpr std::array<ExpectedHashFixture, 14> fixtures{{
        {"known-linux-x64.elf", true},
        {"known-linux-arm64.elf", true},
        {"known-linux-riscv64.elf", true},
        {"known-linux-x86-elf32-le.elf", false},
        {"known-linux-mips-elf32-be.elf", false},
        {"known-linux-mips64-elf64-be.elf", true},
        {"known-linux-arm-elf32-le.elf", false},
        {"known-linux-arm-elf32-be.elf", false},
        {"known-linux-arm64-elf64-be.elf", true},
        {"known-linux-riscv32-elf32-le.elf", false},
        {"known-linux-riscv32-elf32-be.elf", false},
        {"known-linux-riscv64-elf64-be.elf", true},
        {"known-linux-ppc-elf32-be.elf", false},
        {"known-linux-ppc64-elf64-be.elf", true},
    }};

    for (const ExpectedHashFixture& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto& sysv_tables = (**result).elf_sysv_hash_tables();
        ASSERT_EQ(sysv_tables.size(), 1u) << expected.name;
        const peelf::ElfSysvHashTable& sysv = sysv_tables.front();
        EXPECT_EQ(sysv.section_name, ".hash") << expected.name;
        EXPECT_EQ(sysv.bucket_count, 1u) << expected.name;
        EXPECT_EQ(sysv.chain_count, 2u) << expected.name;
        ASSERT_EQ(sysv.buckets.size(), 1u) << expected.name;
        ASSERT_EQ(sysv.chains.size(), 2u) << expected.name;
        EXPECT_EQ(sysv.buckets[0], 1u) << expected.name;
        EXPECT_EQ(sysv.chains[0], 0u) << expected.name;
        EXPECT_EQ(sysv.chains[1], 0u) << expected.name;

        const auto& gnu_tables = (**result).elf_gnu_hash_tables();
        ASSERT_EQ(gnu_tables.size(), 1u) << expected.name;
        const peelf::ElfGnuHashTable& gnu = gnu_tables.front();
        EXPECT_EQ(gnu.section_name, ".gnu.hash") << expected.name;
        EXPECT_EQ(gnu.bucket_count, 1u) << expected.name;
        EXPECT_EQ(gnu.symbol_offset, 1u) << expected.name;
        EXPECT_EQ(gnu.bloom_word_count, 1u) << expected.name;
        EXPECT_EQ(gnu.bloom_shift, 5u) << expected.name;
        ASSERT_EQ(gnu.bloom.size(), 1u) << expected.name;
        ASSERT_EQ(gnu.buckets.size(), 1u) << expected.name;
        ASSERT_EQ(gnu.chains.size(), 1u) << expected.name;
        EXPECT_EQ(gnu.bloom[0], 1u) << expected.name;
        EXPECT_EQ(gnu.buckets[0], 1u) << expected.name;
        EXPECT_EQ(gnu.chains[0], 1u) << expected.name;

        const auto hash_section = std::ranges::find_if(
            (**result).elf_section_headers(), [](const peelf::ElfSectionHeader& section) {
                return section.name == ".hash";
            });
        ASSERT_NE(hash_section, (**result).elf_section_headers().end()) << expected.name;
        EXPECT_EQ(hash_section->type, 5u) << expected.name;  // SHT_HASH
        EXPECT_EQ(hash_section->offset, 0x580u) << expected.name;
        EXPECT_EQ(hash_section->size, 0x14u) << expected.name;
        EXPECT_EQ(hash_section->link, 4u) << expected.name;
        EXPECT_EQ(hash_section->address_alignment, 4u) << expected.name;
        EXPECT_EQ(hash_section->entry_size, 4u) << expected.name;

        const auto gnu_hash_section = std::ranges::find_if(
            (**result).elf_section_headers(), [](const peelf::ElfSectionHeader& section) {
                return section.name == ".gnu.hash";
            });
        ASSERT_NE(gnu_hash_section, (**result).elf_section_headers().end()) << expected.name;
        EXPECT_EQ(gnu_hash_section->type, 0x6FFF'FFF6u) << expected.name;  // SHT_GNU_HASH
        EXPECT_EQ(gnu_hash_section->offset, 0x5A0u) << expected.name;
        EXPECT_EQ(gnu_hash_section->size, expected.is_64bit ? 0x20u : 0x1Cu) << expected.name;
        EXPECT_EQ(gnu_hash_section->link, 4u) << expected.name;
        EXPECT_EQ(gnu_hash_section->address_alignment, expected.is_64bit ? 8u : 4u) << expected.name;
        EXPECT_EQ(gnu_hash_section->entry_size, 0u) << expected.name;
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
        ASSERT_EQ(headers.size(), 11u) << name;

        const auto symtab = std::ranges::find_if(headers, [](const peelf::ElfSectionHeader& section) {
            return section.name == ".symtab";
        });
        ASSERT_NE(symtab, headers.end()) << name;
        EXPECT_EQ(symtab->type, 2u) << name;  // SHT_SYMTAB
        EXPECT_EQ(symtab->offset, 0x100u) << name;
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
        EXPECT_EQ(dynamic->offset, 0x148u) << name;
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

TEST(BinaryImage, ParsesElfRelocationsAcrossFixtureMatrix) {
    struct ExpectedRelocation {
        const char* name;
        bool is_64bit;
    };
    constexpr std::array<ExpectedRelocation, 14> fixtures{{
        {"known-linux-x64.elf", true},
        {"known-linux-arm64.elf", true},
        {"known-linux-riscv64.elf", true},
        {"known-linux-x86-elf32-le.elf", false},
        {"known-linux-mips-elf32-be.elf", false},
        {"known-linux-mips64-elf64-be.elf", true},
        {"known-linux-arm-elf32-le.elf", false},
        {"known-linux-arm-elf32-be.elf", false},
        {"known-linux-arm64-elf64-be.elf", true},
        {"known-linux-riscv32-elf32-le.elf", false},
        {"known-linux-riscv32-elf32-be.elf", false},
        {"known-linux-riscv64-elf64-be.elf", true},
        {"known-linux-ppc-elf32-be.elf", false},
        {"known-linux-ppc64-elf64-be.elf", true},
    }};

    for (const ExpectedRelocation& expected : fixtures) {
        const auto path = fixture_path(expected.name);
        ASSERT_TRUE(std::filesystem::exists(path)) << "missing fixture: " << path.string();

        const std::vector<std::uint8_t> bytes = read_all(path);
        auto result = peelf::parse_image(bytes);
        ASSERT_TRUE(result.has_value()) << "parse_image failed for " << expected.name;

        const auto& relocations = (**result).elf_relocations();
        ASSERT_EQ(relocations.size(), 1u) << expected.name;

        const peelf::ElfRelocation& relocation = relocations.front();
        EXPECT_EQ(relocation.section_name, expected.is_64bit ? ".rela.dyn" : ".rel.dyn") << expected.name;
        EXPECT_EQ(relocation.offset, expected.is_64bit ? 0x400088u : 0x400084u) << expected.name;
        EXPECT_EQ(relocation.info, expected.is_64bit ? 0x100000008u : 0x101u) << expected.name;
        EXPECT_EQ(relocation.symbol_index, 1u) << expected.name;
        EXPECT_EQ(relocation.type, expected.is_64bit ? 8u : 1u) << expected.name;
        EXPECT_EQ(relocation.has_addend, expected.is_64bit) << expected.name;
        EXPECT_EQ(relocation.addend, expected.is_64bit ? 4 : 0) << expected.name;

        const auto relocation_section = std::ranges::find_if(
            (**result).elf_section_headers(), [&](const peelf::ElfSectionHeader& section) {
                return section.name == relocation.section_name;
            });
        ASSERT_NE(relocation_section, (**result).elf_section_headers().end()) << expected.name;
        EXPECT_EQ(relocation_section->type, expected.is_64bit ? 4u : 9u) << expected.name;
        EXPECT_EQ(relocation_section->link, 4u) << expected.name;
        EXPECT_EQ(relocation_section->info, 1u) << expected.name;
        EXPECT_EQ(relocation_section->entry_size, expected.is_64bit ? 0x18u : 0x08u) << expected.name;
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
