#include <peelf/binary_image.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/dependency_tree.hpp>
#include <peelf/dwarf.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/peelf.hpp>
#include <peelf/security_audit.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

void write_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

void write_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    write_u32_le(buf, off, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
    write_u32_le(buf, off + 4u, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFull));
}

void write_u16_be(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>(v & 0xFFu);
}

void write_u32_be(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>(v & 0xFFu);
}

void append_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

void append_u16_le(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

std::vector<std::uint8_t> make_baseline_pe64() {
    std::vector<std::uint8_t> buf(0x800u, 0u);
    buf[0] = 'M';
    buf[1] = 'Z';
    write_u32_le(buf, 0x3Cu, 0x80u);
    buf[0x80u] = 'P';
    buf[0x81u] = 'E';
    write_u16_le(buf, 0x84u, 0x8664u);
    write_u16_le(buf, 0x86u, 1u);
    write_u16_le(buf, 0x94u, 0xF0u);
    write_u16_le(buf, 0x96u, 0x0022u);

    const std::size_t opt = 0x98u;
    write_u16_le(buf, opt + 0u, 0x020Bu);
    write_u32_le(buf, opt + 16u, 0x1000u);
    write_u64_le(buf, opt + 24u, 0x140000000ull);
    write_u32_le(buf, opt + 32u, 0x1000u);
    write_u32_le(buf, opt + 36u, 0x200u);
    write_u32_le(buf, opt + 56u, 0x3000u);
    write_u32_le(buf, opt + 60u, 0x200u);
    write_u16_le(buf, opt + 70u, 0x0160u);
    write_u32_le(buf, opt + 108u, 16u);

    const std::size_t sh = opt + 0xF0u;
    std::copy_n(".text", 5u, reinterpret_cast<char*>(buf.data() + sh));
    write_u32_le(buf, sh + 8u, 0x600u);
    write_u32_le(buf, sh + 12u, 0x1000u);
    write_u32_le(buf, sh + 16u, 0x600u);
    write_u32_le(buf, sh + 20u, 0x200u);
    write_u32_le(buf, sh + 36u, 0x60000020u);
    return buf;
}

std::vector<std::uint8_t> make_baseline_elf64_le() {
    std::vector<std::uint8_t> buf(0x600u, 0u);
    buf[0] = 0x7Fu;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2u; // ELFCLASS64
    buf[5] = 1u; // ELFDATA2LSB
    buf[6] = 1u; // EV_CURRENT
    write_u16_le(buf, 16u, 3u);     // ET_DYN
    write_u16_le(buf, 18u, 62u);    // EM_X86_64
    write_u32_le(buf, 20u, 1u);     // e_version
    write_u64_le(buf, 24u, 0x1000u);
    write_u64_le(buf, 32u, 64u);    // e_phoff
    write_u64_le(buf, 40u, 0x300u); // e_shoff
    write_u16_le(buf, 52u, 64u);    // e_ehsize
    write_u16_le(buf, 54u, 56u);    // e_phentsize
    write_u16_le(buf, 56u, 1u);     // e_phnum
    write_u16_le(buf, 58u, 64u);    // e_shentsize
    write_u16_le(buf, 60u, 3u);     // e_shnum (NULL, .text, .shstrtab)
    write_u16_le(buf, 62u, 2u);     // e_shstrndx = 2

    // PT_LOAD at 64
    const std::size_t ph = 64u;
    write_u32_le(buf, ph + 0u, 1u); // PT_LOAD
    write_u32_le(buf, ph + 4u, 5u); // PF_R | PF_X
    write_u64_le(buf, ph + 8u, 0u);
    write_u64_le(buf, ph + 16u, 0u);
    write_u64_le(buf, ph + 24u, 0u);
    write_u64_le(buf, ph + 32u, 0x600u);
    write_u64_le(buf, ph + 40u, 0x600u);
    write_u64_le(buf, ph + 48u, 0x1000u);

    // .shstrtab bytes at 0x200: "\0.text\0.shstrtab\0"
    static constexpr std::string_view kShStrTab("\0.text\0.shstrtab\0", 17u);
    std::copy(kShStrTab.begin(),
              kShStrTab.end(),
              reinterpret_cast<char*>(buf.data() + 0x200u));

    // Section 1 (.text) at 0x300 + 64
    const std::size_t sh1 = 0x300u + 64u;
    write_u32_le(buf, sh1 + 0u, 1u);  // ".text"
    write_u32_le(buf, sh1 + 4u, 1u);  // SHT_PROGBITS
    write_u64_le(buf, sh1 + 8u, 6u);  // SHF_ALLOC | SHF_EXECINSTR
    write_u64_le(buf, sh1 + 16u, 0x100u);
    write_u64_le(buf, sh1 + 24u, 0x100u);
    write_u64_le(buf, sh1 + 32u, 0x40u);

    // Section 2 (.shstrtab) at 0x300 + 128
    const std::size_t sh2 = 0x300u + 128u;
    write_u32_le(buf, sh2 + 0u, 7u);  // ".shstrtab"
    write_u32_le(buf, sh2 + 4u, 3u);  // SHT_STRTAB
    write_u64_le(buf, sh2 + 24u, 0x200u);
    write_u64_le(buf, sh2 + 32u, kShStrTab.size());
    return buf;
}

void exercise_all_binary_queries(std::span<const std::uint8_t> bytes) {
    (void)peelf::detect_format(bytes);
    (void)peelf::parse_pe_bytes(bytes);
    (void)peelf::parse_elf_bytes(bytes);

    auto parsed = peelf::parse_image(bytes);
    if (parsed.has_value() && *parsed != nullptr) {
        const peelf::IBinaryImage& img = **parsed;
        (void)img.format();
        (void)img.kind();
        (void)img.architecture();
        (void)img.endianness();
        (void)img.is_64bit();
        (void)img.image_base();
        (void)img.entry_point();
        (void)img.sections();
        (void)img.segments();
        (void)img.symbols();
        (void)img.imports();
        (void)img.exports();
        (void)img.pe_header();
        (void)img.pe_data_directories();
        (void)img.pe_base_relocations();
        (void)img.pe_debug_directories();
        (void)img.pe_tls_directory();
        (void)img.pe_certificates();
        (void)img.pe_load_config_directory();
        (void)img.pe_runtime_functions();
        (void)img.pe_bound_imports();
        (void)img.pe_resource_directory();
        (void)img.pe_resource_data_entries();
        (void)img.pe_clr_header();
        (void)img.elf_header();
        (void)img.elf_program_headers();
        (void)img.elf_section_headers();
        (void)img.elf_symbols();
        (void)img.elf_dynamic_entries();
        (void)img.elf_relocations();
        (void)img.elf_notes();
        (void)img.elf_sysv_hash_tables();
        (void)img.elf_gnu_hash_tables();
        (void)img.elf_interpreter();
        (void)img.file_offset_to_virtual_address(0u);
        (void)img.virtual_address_to_file_offset(img.entry_point());
        (void)peelf::audit_security(img, bytes);
        peelf::DependencyResolveOptions dep_opts{};
        dep_opts.include_default_system_dirs = false;
        (void)peelf::build_dependency_graph(img, dep_opts);
        (void)peelf::parse_dwarf_image(img, bytes);
    }
}

struct HostileBlobCase {
    std::string_view name;
    std::vector<std::uint8_t> bytes;
};

} // namespace

TEST(MalformedInputsMatrix, HostilePeHeadersDirectoriesAndTablesNeverCrashOrOverflow) {
    std::vector<HostileBlobCase> cases;

    // 1. Empty, 1-byte, and truncated MZ headers
    cases.push_back({"empty", {}});
    cases.push_back({"mz_2bytes", {'M', 'Z'}});
    {
        std::vector<std::uint8_t> b(63u, 0u);
        b[0] = 'M';
        b[1] = 'Z';
        cases.push_back({"dos_63_bytes", std::move(b)});
    }

    // 2. e_lfanew wrap-around & out-of-bounds
    for (std::uint32_t bad_lfanew : {0xFFFFFFFFu, 0xFFFFFFF0u, 0x80000000u, 0x00010000u, 0u}) {
        auto b = make_baseline_pe64();
        write_u32_le(b, 0x3Cu, bad_lfanew);
        cases.push_back({"pe_bad_lfanew", std::move(b)});
    }

    // 3. Truncated COFF / Optional header & bad Optional magic / NumberOfRvaAndSizes > 16
    {
        auto b = make_baseline_pe64();
        b.resize(0x98u + 10u);
        cases.push_back({"pe_truncated_optional_header", std::move(b)});
    }
    {
        auto b = make_baseline_pe64();
        write_u16_le(b, 0x98u, 0xDEADu);
        cases.push_back({"pe_unknown_optional_magic", std::move(b)});
    }
    {
        auto b = make_baseline_pe64();
        write_u32_le(b, 0x98u + 108u, 0x40000000u); // huge NumberOfRvaAndSizes
        cases.push_back({"pe_huge_rva_and_sizes", std::move(b)});
    }

    // 4. Section table wrap-around (VirtualAddress + VirtualSize & PointerToRawData + SizeOfRawData)
    {
        auto b = make_baseline_pe64();
        const std::size_t sh = 0x98u + 0xF0u;
        write_u32_le(b, sh + 8u, 0xFFFFFFFFu);  // VirtualSize
        write_u32_le(b, sh + 12u, 0xFFFFF000u); // VirtualAddress
        write_u32_le(b, sh + 16u, 0xFFFFFFFFu); // SizeOfRawData
        write_u32_le(b, sh + 20u, 0xFFFFFF00u); // PointerToRawData
        cases.push_back({"pe_section_bounds_overflow", std::move(b)});
    }

    // 5. Truncated Import table, unterminated DLL/symbol strings, ordinal & delay-load edge cases
    {
        auto b = make_baseline_pe64();
        const std::size_t opt = 0x98u;
        // DataDirectory[1] = Import at RVA 0x1000 (file 0x200)
        write_u32_le(b, opt + 112u + 8u, 0x1000u);
        write_u32_le(b, opt + 112u + 12u, 40u);
        // Import descriptor pointing to ILT @ 0x1100, Name @ 0x15F0 (unterminated through section end)
        write_u32_le(b, 0x200u + 0u, 0x1100u);
        write_u32_le(b, 0x200u + 12u, 0x15F0u);
        write_u32_le(b, 0x200u + 16u, 0x1100u);
        // Fill end of buffer with non-NUL 'A'
        std::fill(b.begin() + 0x7F0u, b.end(), static_cast<std::uint8_t>('A'));
        // ILT entry 0: ordinal import (bit 63 set), entry 1: out-of-bounds Hint/Name RVA
        write_u64_le(b, 0x300u + 0u, (1ull << 63u) | 42ull);
        write_u64_le(b, 0x300u + 8u, 0x99990000ull);
        // Delay-load DataDirectory[13] pointing to truncated descriptor
        write_u32_le(b, opt + 112u + 13u * 8u, 0x15ECu);
        write_u32_le(b, opt + 112u + 13u * 8u + 4u, 64u);
        cases.push_back({"pe_hostile_imports_and_delayload", std::move(b)});
    }

    // 6. Export directory with huge counts & self-forwarding cycle
    {
        auto b = make_baseline_pe64();
        const std::size_t opt = 0x98u;
        write_u32_le(b, opt + 112u + 0u, 0x1000u);
        write_u32_le(b, opt + 112u + 4u, 0x200u);
        // IMAGE_EXPORT_DIRECTORY @ file 0x200 (RVA 0x1000)
        write_u32_le(b, 0x200u + 12u, 0x1080u); // Name RVA
        write_u32_le(b, 0x200u + 16u, 1u);      // Base
        write_u32_le(b, 0x200u + 20u, 0x10000000u); // Huge NumberOfFunctions
        write_u32_le(b, 0x200u + 24u, 0x20000000u); // NumberOfNames > NumberOfFunctions
        write_u32_le(b, 0x200u + 28u, 0x1040u); // AddressOfFunctions (inside export dir -> forwarder!)
        write_u32_le(b, 0x200u + 32u, 0x1050u); // AddressOfNames
        write_u32_le(b, 0x200u + 36u, 0x1060u); // AddressOfNameOrdinals
        write_u32_le(b, 0x240u, 0x1090u);       // Forwarder RVA inside [0x1000, 0x1200)
        std::copy_n("self.Loop", 9u, reinterpret_cast<char*>(b.data() + 0x290u));
        cases.push_back({"pe_export_huge_counts_and_forwarder", std::move(b)});
    }

    // 7. Base relocation block with SizeOfBlock == 0 (infinite-loop trap) and SizeOfBlock == 3
    for (std::uint32_t bad_block_sz : {0u, 3u, 0xFFFFFFFFu}) {
        auto b = make_baseline_pe64();
        const std::size_t opt = 0x98u;
        write_u32_le(b, opt + 112u + 5u * 8u, 0x1000u);
        write_u32_le(b, opt + 112u + 5u * 8u + 4u, 32u);
        write_u32_le(b, 0x200u + 0u, 0x1000u);
        write_u32_le(b, 0x200u + 4u, bad_block_sz);
        cases.push_back({"pe_reloc_bad_block_size", std::move(b)});
    }

    // 8. TLS & LoadConfig directories with out-of-bounds callback/table VAs & truncated CertificateTable
    {
        auto b = make_baseline_pe64();
        const std::size_t opt = 0x98u;
        // TLS [9] @ RVA 0x1000
        write_u32_le(b, opt + 112u + 9u * 8u, 0x1000u);
        write_u32_le(b, opt + 112u + 9u * 8u + 4u, 40u);
        write_u64_le(b, 0x200u + 24u, 0xDEADBEEF0000ull); // unmapped AddressOfCallbacks VA
        // LoadConfig [10] @ RVA 0x1100 (truncated size 12)
        write_u32_le(b, opt + 112u + 10u * 8u, 0x1100u);
        write_u32_le(b, opt + 112u + 10u * 8u + 4u, 12u);
        write_u32_le(b, 0x300u, 0xFFFFu);
        // Security [4] file offset wrap-around
        write_u32_le(b, opt + 112u + 4u * 8u, 0xFFFFFFF0u);
        write_u32_le(b, opt + 112u + 4u * 8u + 4u, 0x100u);
        cases.push_back({"pe_tls_loadconfig_security_oob", std::move(b)});
    }

    for (const auto& tc : cases) {
        SCOPED_TRACE(tc.name);
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(tc.bytes));
    }
}

TEST(MalformedInputsMatrix, ElfExtendedNumberingValidAndTruncatedCases) {
    // Valid extended numbering case (`P1-5`):
    //   e_phnum == PN_XNUM (0xFFFF) -> shdr[0].sh_info = 2
    //   e_shnum == 0                -> shdr[0].sh_size = 3
    //   e_shstrndx == SHN_XINDEX    -> shdr[0].sh_link = 2
    {
        std::vector<std::uint8_t> elf = make_baseline_elf64_le();
        elf.resize(0x800u, 0u);
        // Add a second program header (PT_NOTE) at 64 + 56 = 120
        write_u32_le(elf, 120u + 0u, 4u); // PT_NOTE
        write_u32_le(elf, 120u + 4u, 4u); // PF_R
        write_u64_le(elf, 120u + 8u, 0x240u);
        write_u64_le(elf, 120u + 32u, 0u);

        // Set extended numbering sentinels in ELF header
        write_u16_le(elf, 56u, 0xFFFFu); // PN_XNUM
        write_u16_le(elf, 60u, 0u);      // extended e_shnum
        write_u16_le(elf, 62u, 0xFFFFu); // SHN_XINDEX

        // Populate shdr[0] @ 0x300: sh_size (offset 32) = 3, sh_link (offset 40) = 2, sh_info (offset 44) = 2
        write_u64_le(elf, 0x300u + 32u, 3u);
        write_u32_le(elf, 0x300u + 40u, 2u);
        write_u32_le(elf, 0x300u + 44u, 2u);

        auto parsed = peelf::parse_image(elf);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        const peelf::IBinaryImage& img = **parsed;
        EXPECT_EQ(img.elf_program_headers().size(), 2u);
        ASSERT_EQ(img.elf_section_headers().size(), 3u);
        EXPECT_EQ(img.elf_section_headers()[1].name, ".text");
        EXPECT_EQ(img.elf_section_headers()[2].name, ".shstrtab");
    }

    // Hostile/truncated extended numbering cases
    {
        // e_shnum == 0 but e_shoff points near EOF (truncated shdr[0])
        auto elf = make_baseline_elf64_le();
        write_u16_le(elf, 60u, 0u);
        write_u64_le(elf, 40u, elf.size() - 16u);
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(elf));
    }
    {
        // shdr[0].sh_size = UINT64_MAX overflow
        auto elf = make_baseline_elf64_le();
        write_u16_le(elf, 60u, 0u);
        write_u64_le(elf, 0x300u + 32u, std::numeric_limits<std::uint64_t>::max());
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(elf));
    }
    {
        // SHN_XINDEX with out-of-range shdr[0].sh_link = 99999
        auto elf = make_baseline_elf64_le();
        write_u16_le(elf, 62u, 0xFFFFu);
        write_u32_le(elf, 0x300u + 40u, 99999u);
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(elf));
    }
    {
        // PN_XNUM with huge shdr[0].sh_info = 0x10000000
        auto elf = make_baseline_elf64_le();
        write_u16_le(elf, 56u, 0xFFFFu);
        write_u32_le(elf, 0x300u + 44u, 0x10000000u);
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(elf));
    }
}

TEST(MalformedInputsMatrix, HostileElf32Elf64BeLeAndDwarfNeverCrashOrLoop) {
    std::vector<HostileBlobCase> cases;

    // 1. Truncated ELF ident & invalid class/endianness
    cases.push_back({"elf_4bytes", {0x7Fu, 'E', 'L', 'F'}});
    {
        auto b = make_baseline_elf64_le();
        b[4] = 99u; // bad EI_CLASS
        cases.push_back({"elf_bad_class", std::move(b)});
    }
    {
        auto b = make_baseline_elf64_le();
        b[5] = 99u; // bad EI_DATA
        cases.push_back({"elf_bad_endian", std::move(b)});
    }

    // 2. ELF64 UINT64_MAX e_phoff / e_shoff wrap-around
    {
        auto b = make_baseline_elf64_le();
        write_u64_le(b, 32u, std::numeric_limits<std::uint64_t>::max() - 8u);
        write_u64_le(b, 40u, std::numeric_limits<std::uint64_t>::max() - 8u);
        cases.push_back({"elf64_phoff_shoff_wrap", std::move(b)});
    }

    // 3. ELF32 Big-Endian with truncated program/section tables
    {
        std::vector<std::uint8_t> b(128u, 0u);
        b[0] = 0x7Fu;
        b[1] = 'E';
        b[2] = 'L';
        b[3] = 'F';
        b[4] = 1u; // ELFCLASS32
        b[5] = 2u; // ELFDATA2MSB (Big-Endian)
        b[6] = 1u;
        write_u16_be(b, 16u, 2u);  // ET_EXEC
        write_u16_be(b, 18u, 20u); // EM_PPC
        write_u32_be(b, 20u, 1u);
        write_u32_be(b, 28u, 0xFFFFFFF0u); // e_phoff overflow
        write_u32_be(b, 32u, 0xFFFFFFE0u); // e_shoff overflow
        write_u16_be(b, 40u, 52u);
        write_u16_be(b, 42u, 32u);
        write_u16_be(b, 44u, 4u);
        write_u16_be(b, 46u, 40u);
        write_u16_be(b, 48u, 8u);
        cases.push_back({"elf32_be_overflow_offsets", std::move(b)});
    }

    // 4. Cyclic sh_link & sh_entsize == 0 on SHT_SYMTAB / SHT_DYNAMIC / SHT_RELA
    {
        auto b = make_baseline_elf64_le();
        b.resize(0x900u, 0u);
        write_u16_le(b, 60u, 5u); // 5 sections
        // Section 3: SHT_SYMTAB with sh_entsize == 0 and cyclic sh_link = 4
        const std::size_t sh3 = 0x300u + 3u * 64u;
        write_u32_le(b, sh3 + 4u, 2u); // SHT_SYMTAB
        write_u64_le(b, sh3 + 24u, 0x100u);
        write_u64_le(b, sh3 + 32u, 0x80u);
        write_u32_le(b, sh3 + 40u, 4u); // sh_link -> 4
        write_u64_le(b, sh3 + 56u, 0u); // sh_entsize == 0!
        // Section 4: SHT_DYNAMIC with mismatched sh_entsize == 3 and cyclic sh_link = 3
        const std::size_t sh4 = 0x300u + 4u * 64u;
        write_u32_le(b, sh4 + 4u, 6u); // SHT_DYNAMIC
        write_u64_le(b, sh4 + 24u, 0x100u);
        write_u64_le(b, sh4 + 32u, 0x80u);
        write_u32_le(b, sh4 + 40u, 3u); // sh_link -> 3 (cycle!)
        write_u64_le(b, sh4 + 56u, 3u); // mismatched sh_entsize
        cases.push_back({"elf64_zero_entsize_and_cyclic_shlink", std::move(b)});
    }

    // 5. Unterminated .strtab + out-of-bounds st_name + truncated .dynamic without DT_NULL
    {
        auto b = make_baseline_elf64_le();
        b.resize(0x900u, 0u);
        write_u16_le(b, 60u, 5u);
        // Fill 0x700..0x780 with non-NUL bytes for unterminated .dynstr
        std::fill(b.begin() + 0x700u, b.begin() + 0x780u, static_cast<std::uint8_t>('Z'));
        // Section 3: .dynstr (no NUL terminator!)
        const std::size_t sh3 = 0x300u + 3u * 64u;
        write_u32_le(b, sh3 + 4u, 3u); // SHT_STRTAB
        write_u64_le(b, sh3 + 24u, 0x700u);
        write_u64_le(b, sh3 + 32u, 0x80u);
        // Section 4: .dynsym with st_name = 0x50 (inside non-NUL region) and 0x9999 (OOB)
        const std::size_t sh4 = 0x300u + 4u * 64u;
        write_u32_le(b, sh4 + 4u, 11u); // SHT_DYNSYM
        write_u64_le(b, sh4 + 24u, 0x780u);
        write_u64_le(b, sh4 + 32u, 48u); // 2 Elf64_Sym entries
        write_u32_le(b, sh4 + 40u, 3u);  // sh_link -> .dynstr
        write_u64_le(b, sh4 + 56u, 24u);
        write_u32_le(b, 0x780u + 24u, 0x10u); // entry 1 st_name in non-NUL region
        b[0x780u + 24u + 4u] = 0x12u;         // STB_GLOBAL | STT_FUNC
        cases.push_back({"elf64_unterminated_dynstr_dynsym", std::move(b)});
    }

    for (const auto& tc : cases) {
        SCOPED_TRACE(tc.name);
        EXPECT_NO_FATAL_FAILURE(exercise_all_binary_queries(tc.bytes));
    }

    // 6. DWARF hostile views: truncated LEB128, cyclic DW_AT_type DIEs (A -> B -> A), OOB .debug_str
    {
        peelf::DwarfSectionViews truncated_leb{};
        truncated_leb.debug_abbrev = {0x80u, 0x80u, 0x80u, 0x80u, 0x80u};
        truncated_leb.debug_info = {0x20u, 0x00u, 0x00u, 0x00u, 0x04u, 0x00u};
        EXPECT_NO_FATAL_FAILURE((void)peelf::parse_dwarf_sections(truncated_leb));
    }
    {
        // Construct DWARF v4 CU where DIE @ offset 12 (typedef A) has DW_AT_type -> offset 21 (typedef B)
        // and DIE @ offset 21 (typedef B) has DW_AT_type -> offset 12 (typedef A) + OOB DW_FORM_strp!
        peelf::DwarfSectionViews cyclic{};
        cyclic.debug_str = {'o', 'k', '\0'};
        // Abbrev 1: DW_TAG_compile_unit (0x11), children=1 (0x01), no attrs (0,0)
        // Abbrev 2: DW_TAG_structure_type (0x13), children=1 (0x01), DW_AT_name (0x03) DW_FORM_strp (0x0E), DW_AT_byte_size (0x0B) DW_FORM_data1 (0x0B)
        // Abbrev 3: DW_TAG_member (0x0D), children=0 (0x00), DW_AT_name (0x03) DW_FORM_strp (0x0E), DW_AT_type (0x49) DW_FORM_ref4 (0x13)
        // Abbrev 4: DW_TAG_typedef (0x16), children=0 (0x00), DW_AT_type (0x49) DW_FORM_ref4 (0x13)
        cyclic.debug_abbrev = {
            1u, 0x11u, 1u, 0u, 0u,
            2u, 0x13u, 1u, 0x03u, 0x0Eu, 0x0Bu, 0x0Bu, 0u, 0u,
            3u, 0x0Du, 0u, 0x03u, 0x0Eu, 0x49u, 0x13u, 0u, 0u,
            4u, 0x16u, 0u, 0x49u, 0x13u, 0u, 0u,
            0u};

        std::vector<std::uint8_t> info;
        append_u32_le(info, 0u);  // placeholder unit_length
        append_u16_le(info, 4u);  // DWARF v4
        append_u32_le(info, 0u);  // debug_abbrev_offset
        append_u8(info, 8u);      // address_size = 8
        // offset 11: Abbrev 1 (CU)
        append_u8(info, 1u);
        // offset 12: Abbrev 4 (typedef A -> ref4 = 17)
        const auto off_a = static_cast<std::uint32_t>(info.size());
        append_u8(info, 4u);
        const std::size_t patch_a = info.size();
        append_u32_le(info, 0u);
        // offset 17: Abbrev 4 (typedef B -> ref4 = off_a, cycle!)
        const auto off_b = static_cast<std::uint32_t>(info.size());
        append_u8(info, 4u);
        append_u32_le(info, off_a);
        write_u32_le(info, patch_a, off_b);
        // Abbrev 2: struct with OOB strp (0xDEAD0000) containing member referencing cyclic typedef A
        append_u8(info, 2u);
        append_u32_le(info, 0xDEAD0000u); // OOB .debug_str offset!
        append_u8(info, 8u);              // byte_size = 8
        append_u8(info, 3u);              // member
        append_u32_le(info, 0u);          // name "ok"
        append_u32_le(info, off_a);       // cyclic DW_AT_type!
        append_u8(info, 0u);              // end struct children
        append_u8(info, 0u);              // end CU children
        write_u32_le(info, 0u, static_cast<std::uint32_t>(info.size() - 4u));
        cyclic.debug_info = std::move(info);

        auto res = peelf::parse_dwarf_sections(cyclic);
        // Must terminate cleanly without infinite recursion or OOB read
        EXPECT_TRUE(res.has_value() || !res.error().message.empty());
    }
}

TEST(MalformedInputsMatrix, HostileMinidumpAndElfCoreDumpsNeverCrashOrWrapAround) {
    // 1. Truncated Minidump header & huge NumberOfStreams / out-of-file stream directory RVA
    {
        std::vector<std::uint8_t> mdmp = {'M', 'D', 'M', 'P', 0x93u, 0xA7u};
        EXPECT_FALSE(peelf::open_minidump_bytes(mdmp).has_value());
    }
    {
        std::vector<std::uint8_t> mdmp(64u, 0u);
        std::copy_n("MDMP", 4u, reinterpret_cast<char*>(mdmp.data()));
        write_u32_le(mdmp, 4u, 0x0000A793u);
        write_u32_le(mdmp, 8u, 0x40000000u);  // Huge NumberOfStreams
        write_u32_le(mdmp, 12u, 0xFFFFFFF0u); // Wrap-around StreamDirectoryRva
        EXPECT_FALSE(peelf::open_minidump_bytes(mdmp).has_value());
    }
    // 2. Minidump with out-of-file MemoryListStream / ModuleListStream / ThreadListStream RVA spans
    {
        std::vector<std::uint8_t> mdmp(256u, 0u);
        std::copy_n("MDMP", 4u, reinterpret_cast<char*>(mdmp.data()));
        write_u32_le(mdmp, 4u, 0x0000A793u);
        write_u32_le(mdmp, 8u, 3u);   // 3 streams
        write_u32_le(mdmp, 12u, 32u); // directory @ 32
        // Stream 0: SystemInfoStream (7) @ 128, size 56
        write_u32_le(mdmp, 32u + 0u, 7u);
        write_u32_le(mdmp, 32u + 4u, 56u);
        write_u32_le(mdmp, 32u + 8u, 128u);
        write_u16_le(mdmp, 128u, 9u); // PROCESSOR_ARCHITECTURE_AMD64
        // Stream 1: MemoryListStream (5) claiming 0x10000000 ranges at RVA 200
        write_u32_le(mdmp, 44u + 0u, 5u);
        write_u32_le(mdmp, 44u + 4u, 0xFFFFFF00u);
        write_u32_le(mdmp, 44u + 8u, 200u);
        write_u32_le(mdmp, 200u, 0x10000000u);
        // Stream 2: Memory64ListStream (9) with BaseRva = UINT64_MAX - 4
        write_u32_le(mdmp, 56u + 0u, 9u);
        write_u32_le(mdmp, 56u + 4u, 32u);
        write_u32_le(mdmp, 56u + 8u, 208u);
        write_u64_le(mdmp, 208u, 1u);
        write_u64_le(mdmp, 216u, std::numeric_limits<std::uint64_t>::max() - 4u);
        write_u64_le(mdmp, 224u, 0x400000ull);
        write_u64_le(mdmp, 232u, 0x100000ull);

        auto res = peelf::open_minidump_bytes(mdmp);
        if (res.has_value() && *res != nullptr) {
            (void)(*res)->memory_regions();
            (void)(*res)->modules();
            (void)(*res)->threads();
            std::array<std::uint8_t, 16> scratch{};
            (void)(*res)->read_memory(0x400000ull, scratch);
        }
    }

    // 3. ELF ET_CORE with PT_NOTE namesz=0xFFFFFFFF / descsz=0xFFFFFFFF alignment wrap-around attempt
    //    `(0xFFFFFFFFu + 3u) & ~3u == 0u` would infinite-loop or read OOB without 64-bit bounds math!
    {
        std::vector<std::uint8_t> core(0x300u, 0u);
        core[0] = 0x7Fu;
        core[1] = 'E';
        core[2] = 'L';
        core[3] = 'F';
        core[4] = 2u; // ELF64
        core[5] = 1u; // LE
        core[6] = 1u;
        write_u16_le(core, 16u, 4u);  // ET_CORE
        write_u16_le(core, 18u, 62u); // EM_X86_64
        write_u32_le(core, 20u, 1u);
        write_u64_le(core, 32u, 64u); // e_phoff
        write_u16_le(core, 52u, 64u);
        write_u16_le(core, 54u, 56u);
        write_u16_le(core, 56u, 2u); // 2 program headers: PT_NOTE + truncated PT_LOAD

        // PHDR 0: PT_NOTE @ 0x100, size 0x80
        write_u32_le(core, 64u + 0u, 4u); // PT_NOTE
        write_u64_le(core, 64u + 8u, 0x100u);
        write_u64_le(core, 64u + 32u, 0x80u);

        // PHDR 1: PT_LOAD with p_offset + p_fileszUINT64_MAX wrap-around
        write_u32_le(core, 120u + 0u, 1u); // PT_LOAD
        write_u32_le(core, 120u + 4u, 5u);
        write_u64_le(core, 120u + 8u, 0x200u);
        write_u64_le(core, 120u + 16u, 0x400000ull);
        write_u64_le(core, 120u + 32u, std::numeric_limits<std::uint64_t>::max() - 0x100u);
        write_u64_le(core, 120u + 40u, 0x1000ull);

        // Malformed note header @ 0x100: namesz = 0xFFFFFFFF, descsz = 0xFFFFFFFF, type = NT_PRSTATUS (1)
        write_u32_le(core, 0x100u + 0u, 0xFFFFFFFFu);
        write_u32_le(core, 0x100u + 4u, 0xFFFFFFFFu);
        write_u32_le(core, 0x100u + 8u, 1u);

        auto res = peelf::open_elf_core_bytes(core);
        if (res.has_value() && *res != nullptr) {
            (void)(*res)->memory_regions();
            (void)(*res)->threads();
            std::array<std::uint8_t, 16> scratch{};
            (void)(*res)->read_memory(0x400000ull, scratch);
        }
    }
}

TEST(MalformedInputsMatrix, ProcessMemorySearchSkipsMultiTerabyteShadowAndReservedRegions) {
    class CountingFakeSession final : public peelf::IProcessSession {
    public:
        peelf::ProcessInfo proc_info{.pid = 4242u, .name = "asan_target"};
        std::vector<peelf::MemoryRegion> regs;
        std::vector<std::uint8_t> real_heap{0xDEu, 0xADu, 0xBEu, 0xEFu, 0xCAu, 0xFEu, 0x42u, 0x99u};
        std::size_t read_calls{0};

        [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return proc_info; }
        [[nodiscard]] bool is_alive() const noexcept override { return true; }
        [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
            return regs;
        }
        [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
            return std::vector<peelf::ModuleInfo>{};
        }
        [[nodiscard]] peelf::Result<std::size_t> read_memory(
            std::uint64_t address,
            std::span<std::uint8_t> buffer) override {
            ++read_calls;
            static constexpr std::uint64_t kHeapBase = 0x5020'0000'0000ull;
            if (address >= kHeapBase &&
                (address - kHeapBase) < static_cast<std::uint64_t>(real_heap.size())) {
                const auto off = static_cast<std::size_t>(address - kHeapBase);
                const std::size_t n = std::min(buffer.size(), real_heap.size() - off);
                std::copy_n(real_heap.data() + off, n, buffer.data());
                return n;
            }
            return peelf::make_error("unexpected read from sparse shadow/reserved region");
        }
    };

    CountingFakeSession session;
    // 14 TiB ASan-like sparse shadow mapping (must be skipped!)
    session.regs.push_back(peelf::MemoryRegion{
        .start_address = 0x0200'8FFF'7000ull,
        .end_address = 0x1000'7FFF'8000ull,
        .protection = {.readable = true, .writable = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    });
    // 64 MiB untouched zero-RSS anonymous reservation (must be skipped!)
    peelf::MemoryRegion untouched_anon{
        .start_address = 0x7000'0000'0000ull,
        .end_address = 0x7000'0400'0000ull,
        .protection = {.readable = true, .writable = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    };
    untouched_anon.usage.rss_bytes = 0u;
    untouched_anon.usage.swap_bytes = 0u;
    session.regs.push_back(untouched_anon);

    // Win32 MEM_RESERVE-only region (must be skipped!)
    peelf::MemoryRegion reserved_only{
        .start_address = 0x7100'0000'0000ull,
        .end_address = 0x7100'0010'0000ull,
        .protection = {.readable = true, .writable = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    };
    reserved_only.usage.is_reserved_only = true;
    session.regs.push_back(reserved_only);

    // Real 8-byte heap slab with target needle!
    session.regs.push_back(peelf::MemoryRegion{
        .start_address = 0x5020'0000'0000ull,
        .end_address = 0x5020'0000'0008ull,
        .protection = {.readable = true, .writable = true},
        .kind = peelf::MemoryRegionKind::Heap,
    });

    const peelf::MemorySearchQuery query{
        .scope = peelf::SearchScope::AllReadable,
        .kind = peelf::SearchValueKind::HexPattern,
        .query_text = "DE AD BE EF CA FE",
    };
    const auto report = peelf::search_process_memory(session, session.regs, query);
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->regions_skipped_oversized, 1u);
    EXPECT_EQ(report->regions_scanned, 1u);
    EXPECT_EQ(session.read_calls, 1u);
    ASSERT_EQ(report->hits.size(), 1u);
    EXPECT_EQ(report->hits[0].address, 0x5020'0000'0000ull);
}

