#include "fuzz_targets.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

[[nodiscard]] std::vector<std::uint8_t> to_bytes(std::string_view text) {
    const auto* ptr = reinterpret_cast<const std::uint8_t*>(text.data());
    return {ptr, ptr + text.size()};
}

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return {};
    }
    const auto end_pos = in.tellg();
    if (end_pos <= 0) {
        return {};
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(end_pos));
    in.seekg(0, std::ios::beg);
    in.read(reinterpret_cast<char*>(buf.data()), end_pos);
    if (!in) {
        return {};
    }
    return buf;
}

void run_all_fuzz_targets(std::span<const std::uint8_t> bytes) {
    peelf::fuzz::fuzz_binary_image_one_input(bytes);
    peelf::fuzz::fuzz_debug_formats_one_input(bytes);
    peelf::fuzz::fuzz_crash_dumps_one_input(bytes);
    peelf::fuzz::fuzz_parsers_dsl_one_input(bytes);
}

void append_u16_le(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u32_be(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    append_u32_le(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
    append_u32_le(out, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFull));
}

} // namespace

TEST(FuzzCorpusRegressionTest, EmptyTinyAndOversizedInputsRemainSafe) {
    run_all_fuzz_targets({});

    const std::array<std::uint8_t, 1> single_zero{0u};
    run_all_fuzz_targets(single_zero);

    const std::array<std::uint8_t, 4> all_ff{0xFFu, 0xFFu, 0xFFu, 0xFFu};
    run_all_fuzz_targets(all_ff);

    std::vector<std::uint8_t> oversized(peelf::fuzz::kMaxFuzzInputBytes + 128u, 0xCCu);
    run_all_fuzz_targets(oversized);
}

TEST(FuzzCorpusRegressionTest, CheckedInFixturesAndBinMatrixCorpus) {
    const std::filesystem::path fixtures_dir(PEELF_TEST_FIXTURES_DIR);
    const std::filesystem::path matrix_dir(PEELF_BIN_MATRIX_DIR);

    constexpr std::array<std::string_view, 7> kFixtureNames = {
        "hello.elf",
        "known-linux-x64.elf",
        "known-linux-arm-elf32-be.elf",
        "known-linux-mips64-elf64-be.elf",
        "known-linux-riscv64.elf",
        "known-win-x64.exe",
        "known-win-x86.exe",
    };

    std::size_t loaded_count = 0u;
    for (const std::string_view name : kFixtureNames) {
        const auto bytes = read_file_bytes(fixtures_dir / name);
        ASSERT_FALSE(bytes.empty()) << "Missing fixture: " << name;
        ++loaded_count;
        run_all_fuzz_targets(bytes);

        // Exercise truncated prefix cuts of real binaries.
        for (const std::size_t cut : {1u, 4u, 16u, 64u, 256u}) {
            if (cut < bytes.size()) {
                run_all_fuzz_targets(std::span<const std::uint8_t>(bytes.data(), cut));
            }
        }
    }

    constexpr std::array<std::string_view, 7> kMatrixNames = {
        "elf-linux-x86_64-64-le-callgraph.elf",        "elf-linux-x86_64-64-le-callgraph.debug",
        "elf-linux-arm64-64-le-callgraph.debug",       "elf-linux-mips-32-be-callgraph.debug",
        "elf-linux-ppc64-64-be-callgraph.debug",       "pe-windows-x86_64-64-le-callgraph.dll",
        "pe-windows-x86_64-64-le-callgraph.dll.debug",
    };
    for (const std::string_view name : kMatrixNames) {
        const auto bytes = read_file_bytes(matrix_dir / name);
        ASSERT_FALSE(bytes.empty()) << "Missing bin-matrix artifact: " << name;
        ++loaded_count;
        run_all_fuzz_targets(bytes);
    }

    EXPECT_EQ(loaded_count, kFixtureNames.size() + kMatrixNames.size());
}

TEST(FuzzCorpusRegressionTest, AdversarialBinaryContainerAndRichHeaders) {
    // 1. Universal Mach-O with out-of-bounds + overlapping slice descriptors and zero-cmdsize
    // slice.
    {
        std::vector<std::uint8_t> fat;
        append_u32_be(fat, 0xCAFEBABEu);
        append_u32_be(fat, 2u); // nfat_arch = 2
        // Slice 0: points to offset 64, size 64
        append_u32_be(fat, 0x01000007u); // CPU_TYPE_X86_64
        append_u32_be(fat, 3u);
        append_u32_be(fat, 64u);
        append_u32_be(fat, 64u);
        append_u32_be(fat, 12u);
        // Slice 1: out-of-bounds offset/size near 4 GiB
        append_u32_be(fat, 0x0100000Cu); // CPU_TYPE_ARM64
        append_u32_be(fat, 0u);
        append_u32_be(fat, 0xFFFFFF00u);
        append_u32_be(fat, 0x00001000u);
        append_u32_be(fat, 31u);
        fat.resize(64u, 0u);
        // Thin Mach-O 64 header at offset 64 with ncmds=4, cmdsize=0 (infinite-loop trap if
        // unchecked)
        append_u32_le(fat, 0xFEEDFACFu);
        append_u32_le(fat, 0x01000007u);
        append_u32_le(fat, 3u);
        append_u32_le(fat, 2u);  // MH_EXECUTE
        append_u32_le(fat, 4u);  // ncmds
        append_u32_le(fat, 96u); // sizeofcmds > slice remaining
        append_u32_le(fat, 0u);
        append_u32_le(fat, 0u);
        append_u32_le(fat, 0x19u); // LC_SEGMENT_64
        append_u32_le(fat, 0u);    // cmdsize = 0
        fat.resize(128u, 0u);
        peelf::fuzz::fuzz_binary_image_one_input(fat);
    }

    // 2. Malformed PE with corrupted Rich header + overflowing e_lfanew / section counts.
    {
        std::vector<std::uint8_t> pe(256u, 0u);
        pe[0] = 'M';
        pe[1] = 'Z';
        pe[0x3C] = 0xB0u; // e_lfanew
        // Synthetic Rich marker at 0x90 without DanS and misaligned XOR key
        pe[0x90] = 'R';
        pe[0x91] = 'i';
        pe[0x92] = 'c';
        pe[0x93] = 'h';
        pe[0x94] = 0xAAu;
        pe[0x95] = 0x55u;
        pe[0x96] = 0xAAu;
        pe[0x97] = 0x55u;
        pe[0xB0] = 'P';
        pe[0xB1] = 'E';
        pe[0xB4] = 0x64u;
        pe[0xB5] = 0x86u; // IMAGE_FILE_MACHINE_AMD64
        pe[0xB6] = 0xFFu;
        pe[0xB7] = 0x7Fu; // huge NumberOfSections
        pe[0xC4] = 0xF0u; // SizeOfOptionalHeader
        pe[0xC8] = 0x0Bu;
        pe[0xC9] = 0x02u; // PE32+
        peelf::fuzz::fuzz_binary_image_one_input(pe);
    }

    // 3. Malformed ELF64 with wraparound e_phoff / e_shoff.
    {
        std::vector<std::uint8_t> elf(128u, 0u);
        elf[0] = 0x7Fu;
        elf[1] = 'E';
        elf[2] = 'L';
        elf[3] = 'F';
        elf[4] = 2u; // ELFCLASS64
        elf[5] = 1u; // ELFDATA2LSB
        elf[6] = 1u;
        elf[16] = 3u;    // ET_DYN
        elf[18] = 0x3Eu; // EM_X86_64
        elf[20] = 1u;
        // Set e_phoff and e_shoff near UINT64_MAX
        for (std::size_t off : {32u, 40u}) {
            for (std::size_t b = 0u; b < 8u; ++b) {
                elf[off + b] = 0xFFu;
            }
        }
        elf[54] = 56u;
        elf[56] = 0xFFu;
        elf[57] = 0xFFu;
        peelf::fuzz::fuzz_binary_image_one_input(elf);
    }
}

TEST(FuzzCorpusRegressionTest, AdversarialMsf7DwarfAndDemanglerInputs) {
    // 1. Truncated & invalid MSF 7.00 superblocks.
    {
        static constexpr char kMsfMagic[32] = {
            'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't',  ' ',  'C',    '/', 'C', '+',  '+',  ' ',
            'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1A', 'D', 'S', '\0', '\0', '\0'};
        std::vector<std::uint8_t> msf(reinterpret_cast<const std::uint8_t*>(kMsfMagic),
                                      reinterpret_cast<const std::uint8_t*>(kMsfMagic) + 32u);
        // Truncated right after signature
        peelf::fuzz::fuzz_debug_formats_one_input(msf);

        // Non-power-of-two block size + overflowing num_directory_bytes
        append_u32_le(msf, 513u);        // invalid BlockSize
        append_u32_le(msf, 1u);          // FreeBlockMapBlock
        append_u32_le(msf, 0xFFFFFFFFu); // NumBlocks
        append_u32_le(msf, 0xFFFFFFFFu); // NumDirectoryBytes
        append_u32_le(msf, 0u);
        append_u32_le(msf, 0xFFFFFFFFu); // BlockMapAddr
        peelf::fuzz::fuzz_debug_formats_one_input(msf);

        // Valid 4096 block size but self-referential / truncated directory block map
        std::vector<std::uint8_t> msf_4k(reinterpret_cast<const std::uint8_t*>(kMsfMagic),
                                         reinterpret_cast<const std::uint8_t*>(kMsfMagic) + 32u);
        append_u32_le(msf_4k, 4096u);
        append_u32_le(msf_4k, 1u);
        append_u32_le(msf_4k, 4u);
        append_u32_le(msf_4k, 8192u);
        append_u32_le(msf_4k, 0u);
        append_u32_le(msf_4k, 2u);
        msf_4k.resize(4096u * 3u, 0xFFu);
        peelf::fuzz::fuzz_debug_formats_one_input(msf_4k);
    }

    // 2. Cyclic DWARF abbrev + self-referential DW_AT_type + truncated ULEB128.
    {
        std::vector<std::uint8_t> dwarf_blob;
        // Abbrev: code 1, DW_TAG_pointer_type (0x0f), no children, DW_AT_type (0x49) DW_FORM_ref4
        // (0x13)
        const std::array<std::uint8_t, 12> abbrev_and_info = {
            0x01u, 0x0Fu, 0x00u, 0x49u, 0x13u, 0x00u,
            0x00u, 0x00u, 0x80u, 0x80u, 0x80u, 0x80u, // unterminated LEB128 tail
        };
        dwarf_blob.insert(dwarf_blob.end(), abbrev_and_info.begin(), abbrev_and_info.end());
        // Append DWARF4 CU header with self-referencing DW_FORM_ref4 = 11 (offset of DIE itself)
        append_u32_le(dwarf_blob, 12u); // unit_length
        append_u16_le(dwarf_blob, 4u);  // DWARF v4
        append_u32_le(dwarf_blob, 0u);  // debug_abbrev_offset
        dwarf_blob.push_back(8u);       // address_size
        dwarf_blob.push_back(1u);       // abbrev code 1
        append_u32_le(dwarf_blob, 11u); // self-cycle!
        dwarf_blob.push_back(0u);       // control flags tail
        peelf::fuzz::fuzz_debug_formats_one_input(dwarf_blob);
    }

    // 3. Pathological demangler inputs (deep pointer chains & invalid backreferences).
    {
        std::string deep_itanium = "_Z1f";
        deep_itanium.append(300u, 'P');
        deep_itanium.append("S999_i");
        peelf::fuzz::fuzz_debug_formats_one_input(to_bytes(deep_itanium));

        std::string deep_rust = "_RNvCs123_4core3foo";
        deep_rust.append(256u, 'R');
        deep_rust.append("B0_");
        peelf::fuzz::fuzz_debug_formats_one_input(to_bytes(deep_rust));

        std::string deep_msvc = "?fn@@YA";
        deep_msvc.append(256u, 'P');
        deep_msvc.append("A999@Z");
        peelf::fuzz::fuzz_debug_formats_one_input(to_bytes(deep_msvc));
    }
}

TEST(FuzzCorpusRegressionTest, AdversarialCrashDumpContainers) {
    // 1. Malformed Windows Minidump ("MDMP") with overflowing directory RVA / stream counts.
    {
        std::vector<std::uint8_t> mdmp;
        mdmp.insert(mdmp.end(), {'M', 'D', 'M', 'P'});
        append_u32_le(mdmp, 0x0000A793u); // Version
        append_u32_le(mdmp, 3u);          // NumberOfStreams
        append_u32_le(mdmp, 32u);         // StreamDirectoryRva
        append_u32_le(mdmp, 0u);          // CheckSum
        append_u32_le(mdmp, 0u);          // TimeDateStamp
        append_u64_le(mdmp, 0u);          // Flags
        // Stream 0: SystemInfoStream (7) truncated
        append_u32_le(mdmp, 7u);
        append_u32_le(mdmp, 0xFFFFFF00u); // DataSize overflow
        append_u32_le(mdmp, 80u);         // Rva
        // Stream 1: Memory64ListStream (9) wrapping VA
        append_u32_le(mdmp, 9u);
        append_u32_le(mdmp, 32u);
        append_u32_le(mdmp, 68u);
        // Stream 2: HandleDataStream (12) out-of-bounds
        append_u32_le(mdmp, 12u);
        append_u32_le(mdmp, 4096u);
        append_u32_le(mdmp, 0xFFFFFFF0u);
        mdmp.resize(128u, 0xFFu);
        peelf::fuzz::fuzz_crash_dumps_one_input(mdmp);
    }

    // 2. Malformed ELF64 ET_CORE with PT_NOTE + wraparound PT_LOAD.
    {
        std::vector<std::uint8_t> core(192u, 0u);
        core[0] = 0x7Fu;
        core[1] = 'E';
        core[2] = 'L';
        core[3] = 'F';
        core[4] = 2u; // 64-bit
        core[5] = 1u; // LE
        core[6] = 1u;
        core[16] = 4u;    // ET_CORE
        core[18] = 0x3Eu; // EM_X86_64
        core[20] = 1u;
        core[32] = 64u; // e_phoff = 64
        core[52] = 64u; // e_ehsize = 64
        core[54] = 56u; // e_phentsize = 56
        core[56] = 2u;  // e_phnum = 2
        // Program header 0: PT_NOTE (4) at offset 176, filesz 64 (truncated past EOF)
        core[64] = 4u;
        core[72] = 176u;
        core[96] = 64u;
        // Program header 1: PT_LOAD (1) with p_vaddr = 0xFFFFFFFFFFFFFFF0, p_memsz = 0x100
        core[120] = 1u;
        core[124] = 5u; // PF_R | PF_X
        core[128] = 176u;
        for (std::size_t b = 0u; b < 8u; ++b) {
            core[136u + b] = (b == 0u) ? 0xF0u : 0xFFu;
        }
        core[152] = 16u;
        core[160] = 0u;
        core[161] = 1u; // 0x100
        peelf::fuzz::fuzz_crash_dumps_one_input(core);
    }

    // 3. Malformed Mach-O 64 MH_CORE with truncated LC_THREAD + wraparound LC_SEGMENT_64.
    {
        std::vector<std::uint8_t> mcore;
        append_u32_le(mcore, 0xFEEDFACFu);
        append_u32_le(mcore, 0x01000007u); // X86_64
        append_u32_le(mcore, 3u);
        append_u32_le(mcore, 4u);  // MH_CORE
        append_u32_le(mcore, 2u);  // ncmds = 2
        append_u32_le(mcore, 96u); // sizeofcmds
        append_u32_le(mcore, 0u);
        append_u32_le(mcore, 0u);
        // LC_SEGMENT_64 (0x19), cmdsize = 72, vmaddr near UINT64_MAX
        append_u32_le(mcore, 0x19u);
        append_u32_le(mcore, 72u);
        mcore.resize(mcore.size() + 16u, 'S');
        append_u64_le(mcore, 0xFFFFFFFFFFFFFF00ull); // vmaddr
        append_u64_le(mcore, 0x400ull);              // vmsize (wraps!)
        append_u64_le(mcore, 128ull);                // fileoff
        append_u64_le(mcore, 32ull);                 // filesize
        append_u32_le(mcore, 7u);
        append_u32_le(mcore, 5u);
        append_u32_le(mcore, 0u);
        append_u32_le(mcore, 0u);
        // LC_THREAD (0x04) with bogus count exceeding cmdsize
        append_u32_le(mcore, 0x04u);
        append_u32_le(mcore, 24u);
        append_u32_le(mcore, 4u);          // x86_THREAD_STATE64
        append_u32_le(mcore, 0x3FFFFFFFu); // oversized count in uint32 words
        append_u64_le(mcore, 0xDEADBEEFull);
        mcore.resize(160u, 0x90u);
        peelf::fuzz::fuzz_crash_dumps_one_input(mcore);
    }
}

TEST(FuzzCorpusRegressionTest, AdversarialDslCtypesSignaturesPatchesRegexAndRsp) {
    // 1. Deeply nested & cyclic C struct/union/enum/bitfield declarations.
    {
        std::string deep_c;
        for (int i = 0; i < 40; ++i) {
            deep_c += "struct S" + std::to_string(i) + " { ";
        }
        deep_c += "unsigned int bf : 999; char huge[0x7fffffffffffffffULL]; ";
        for (int i = 39; i >= 0; --i) {
            deep_c += "}; ";
        }
        deep_c += "struct Cycle { struct Cycle self; }; enum E : unsigned long long { A = ~0ULL, B "
                  "}; /* unterminated";
        peelf::fuzz::fuzz_parsers_dsl_one_input(to_bytes(deep_c));
    }

    // 2. Pathological YARA-lite rules.
    {
        constexpr std::string_view kBadRule = R"(
rule AdversarialRule : fuzz pack {
    meta:
        description = "unterminated escapes and huge jumps"
        severity = "error"
    strings:
        $h1 = { 4D 5A [0-99999999] FF ?? ?A ( 01 | 02 | ) }
        $s1 = "abc\xZZ\0def" nocase wide ascii
    condition:
        ((((($h1 and $s1) or any of ($h*)) and filesize < 0xFFFFFFFFFFFFFFFF)))
}
)";
        peelf::fuzz::fuzz_parsers_dsl_one_input(to_bytes(kBadRule));
    }

    // 3. IPS / IPS32 boundary records (including 0x454F46 collision and RLE near 4 GiB).
    {
        std::vector<std::uint8_t> ips = {'P', 'A', 'T', 'C', 'H'};
        // RLE record at 0x454F45 of length 0xFFFF with value 0x90
        ips.insert(ips.end(), {0x45u, 0x4Fu, 0x45u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0x90u});
        ips.insert(ips.end(), {'E', 'O', 'F', 0x00u, 0x10u, 0x00u});
        peelf::fuzz::fuzz_parsers_dsl_one_input(ips);

        std::vector<std::uint8_t> ips32 = {'I', 'P', 'S', '3', '2'};
        // Offset 0xFFFFFFFC + RLE size 0x0010 (crosses 4 GiB boundary)
        ips32.insert(ips32.end(), {0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x10u, 0xCCu});
        ips32.insert(ips32.end(), {'E', 'E', 'O', 'F'});
        peelf::fuzz::fuzz_parsers_dsl_one_input(ips32);
    }

    // 4. Malformed PatchBundle JSON.
    {
        constexpr std::string_view kBadJson =
            R"({"schema_version":1,"name":"\uD800\u0000","expected_size":18446744073709551615,"entries":[{"offset":18446744073709551610,"original_bytes":"909","patched_bytes":"CC"}]})";
        peelf::fuzz::fuzz_parsers_dsl_one_input(to_bytes(kBadJson));
    }

    // 5. Catastrophic-backtracking & malformed regexes (including libFuzzer ReDoS reproducers).
    {
        auto make_parser_dsl_repro = [](std::string_view head, std::string_view haystack) {
            std::vector<std::uint8_t> buf;
            buf.reserve(head.size() + haystack.size() + 3u);
            buf.insert(buf.end(), head.begin(), head.end());
            buf.insert(buf.end(), haystack.begin(), haystack.end());
            // FuzzByteReader consumes from back: flags (u8), lo(split), hi(split).
            buf.push_back(static_cast<std::uint8_t>((head.size() >> 8u) & 0xFFu));
            buf.push_back(static_cast<std::uint8_t>(head.size() & 0xFFu));
            buf.push_back(0x00u);
            return buf;
        };

        const std::string hay_4k(4096u, 'a');
        peelf::fuzz::fuzz_parsers_dsl_one_input(make_parser_dsl_repro(".*.*z", hay_4k));
        peelf::fuzz::fuzz_parsers_dsl_one_input(make_parser_dsl_repro("(a|a)+b", hay_4k));
        peelf::fuzz::fuzz_parsers_dsl_one_input(make_parser_dsl_repro("((a|b))+z", hay_4k));
        peelf::fuzz::fuzz_parsers_dsl_one_input(make_parser_dsl_repro("[^](a+)+[x]", hay_4k));
        peelf::fuzz::fuzz_parsers_dsl_one_input(make_parser_dsl_repro("(?=a+)a+z", hay_4k));
        peelf::fuzz::fuzz_parsers_dsl_one_input(
            make_parser_dsl_repro("\\1[unterminated(abc{0,9999}\\", "abc"));
    }

    // 6. Malformed GDB RSP wire frames, RLE expansion bombs, and cyclic target.xml.
    {
        std::string rsp_rle_bomb;
        for (int i = 0; i < 2048; ++i) {
            rsp_rle_bomb += "0*\x7E";
        }
        rsp_rle_bomb += "}"; // dangling escape byte at EOF
        peelf::fuzz::fuzz_parsers_dsl_one_input(to_bytes(rsp_rle_bomb));

        constexpr std::string_view kCyclicTargetXml = R"(
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <xi:include href="loop.xml"/>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rax" bitsize="64" regnum="0"/>
    <reg name="weird" bitsize="999999" regnum="1"/>
  </feature>
</target>
)";
        peelf::fuzz::fuzz_parsers_dsl_one_input(to_bytes(kCyclicTargetXml));
    }
}
