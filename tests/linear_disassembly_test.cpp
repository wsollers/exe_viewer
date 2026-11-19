#include "disasm/linear_disassembly.hpp"

#include "analysis/reference_index.hpp"
#include "disasm/disassembler.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

[[nodiscard]] std::filesystem::path fixture_path(std::string_view name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

void put16_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
    b[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put32_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

void put64_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

// Builds a valid ELF64 little-endian executable with:
//   - Section 0: NULL
//   - Section 1: .text (SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR) at VA 0x401000, file offset 0x1000
//   - Section 2: .bss  (SHT_NOBITS,   SHF_ALLOC | SHF_WRITE)     at VA 0x500000, file_size = 0, virtual_size = bss_vsize
//   - Section 3: .shstrtab
[[nodiscard]] std::vector<std::uint8_t> build_synthetic_elf64_with_text_and_bss(
    std::uint16_t e_machine,
    std::span<const std::uint8_t> text_bytes,
    std::uint64_t bss_vsize = 0x2000u,
    std::optional<std::uint64_t> inflated_text_sh_size = std::nullopt) {
    constexpr std::size_t kTextFileOff = 0x1000u;
    constexpr std::uint64_t kImageBase = 0x400000u;
    constexpr std::uint64_t kTextVa = 0x401000u;
    constexpr std::uint64_t kBssVa = 0x500000u;

    const std::string shstrtab("\0.text\0.bss\0.shstrtab\0", 22u);
    const std::size_t shstr_off = kTextFileOff + text_bytes.size();
    const std::size_t shdr_off = (shstr_off + shstrtab.size() + 7u) & ~std::size_t{7u};
    constexpr std::size_t kShEntSize = 64u;
    constexpr std::uint16_t kShNum = 4u;
    constexpr std::size_t kPhOff = 64u;
    constexpr std::size_t kPhEntSize = 56u;
    constexpr std::uint16_t kPhNum = 2u;

    std::vector<std::uint8_t> buf(shdr_off + kShEntSize * kShNum, 0u);

    // ELF64 header
    buf[0] = 0x7Fu;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2u; // ELFCLASS64
    buf[5] = 1u; // ELFDATA2LSB
    buf[6] = 1u; // EV_CURRENT
    put16_le(buf, 16u, 2u); // ET_EXEC
    put16_le(buf, 18u, e_machine);
    put32_le(buf, 20u, 1u); // EV_CURRENT
    put64_le(buf, 24u, kTextVa); // e_entry
    put64_le(buf, 32u, kPhOff);
    put64_le(buf, 40u, shdr_off);
    put16_le(buf, 52u, 64u);
    put16_le(buf, 54u, kPhEntSize);
    put16_le(buf, 56u, kPhNum);
    put16_le(buf, 58u, kShEntSize);
    put16_le(buf, 60u, kShNum);
    put16_le(buf, 62u, 3u); // e_shstrndx

    // PT_LOAD 0: headers + .text (R-X)
    put32_le(buf, kPhOff + 0u, 1u); // PT_LOAD
    put32_le(buf, kPhOff + 4u, 5u); // PF_R | PF_X
    put64_le(buf, kPhOff + 8u, 0u);
    put64_le(buf, kPhOff + 16u, kImageBase);
    put64_le(buf, kPhOff + 24u, kImageBase);
    put64_le(buf, kPhOff + 32u, kTextFileOff + text_bytes.size());
    put64_le(buf, kPhOff + 40u, kTextFileOff + text_bytes.size());
    put64_le(buf, kPhOff + 48u, 0x1000u);

    // PT_LOAD 1: .bss (RW-, filesz=0, memsz=bss_vsize)
    const std::size_t ph1 = kPhOff + kPhEntSize;
    put32_le(buf, ph1 + 0u, 1u); // PT_LOAD
    put32_le(buf, ph1 + 4u, 6u); // PF_R | PF_W
    put64_le(buf, ph1 + 8u, shstr_off);
    put64_le(buf, ph1 + 16u, kBssVa);
    put64_le(buf, ph1 + 24u, kBssVa);
    put64_le(buf, ph1 + 32u, 0u);
    put64_le(buf, ph1 + 40u, bss_vsize);
    put64_le(buf, ph1 + 48u, 0x1000u);

    if (!text_bytes.empty()) {
        std::memcpy(buf.data() + kTextFileOff, text_bytes.data(), text_bytes.size());
    }
    std::memcpy(buf.data() + shstr_off, shstrtab.data(), shstrtab.size());

    // Section 1: .text (name offset 1)
    const std::size_t sh1 = shdr_off + kShEntSize * 1u;
    const std::uint64_t recorded_text_size = inflated_text_sh_size.value_or(text_bytes.size());
    put32_le(buf, sh1 + 0u, 1u);  // ".text"
    put32_le(buf, sh1 + 4u, 1u);  // SHT_PROGBITS
    put64_le(buf, sh1 + 8u, 6u);  // SHF_ALLOC | SHF_EXECINSTR
    put64_le(buf, sh1 + 16u, kTextVa);
    put64_le(buf, sh1 + 24u, kTextFileOff);
    put64_le(buf, sh1 + 32u, recorded_text_size);
    put64_le(buf, sh1 + 48u, 16u);

    // Section 2: .bss (name offset 7)
    const std::size_t sh2 = shdr_off + kShEntSize * 2u;
    put32_le(buf, sh2 + 0u, 7u);  // ".bss"
    put32_le(buf, sh2 + 4u, 8u);  // SHT_NOBITS
    put64_le(buf, sh2 + 8u, 3u);  // SHF_WRITE | SHF_ALLOC
    put64_le(buf, sh2 + 16u, kBssVa);
    put64_le(buf, sh2 + 24u, shstr_off);
    put64_le(buf, sh2 + 32u, bss_vsize);
    put64_le(buf, sh2 + 48u, 16u);

    // Section 3: .shstrtab (name offset 12)
    const std::size_t sh3 = shdr_off + kShEntSize * 3u;
    put32_le(buf, sh3 + 0u, 12u); // ".shstrtab"
    put32_le(buf, sh3 + 4u, 3u);  // SHT_STRTAB
    put64_le(buf, sh3 + 24u, shstr_off);
    put64_le(buf, sh3 + 32u, shstrtab.size());
    put64_le(buf, sh3 + 48u, 1u);

    return buf;
}

// Builds a minimal ELF32 ARM little-endian image with .text, .symtab, .strtab, .shstrtab
// containing both an A32 function ($a) and a Thumb function ($t / odd st_value).
[[nodiscard]] std::vector<std::uint8_t> build_synthetic_arm32_mixed_thumb_elf(
    std::span<const std::uint8_t> code_bytes,
    std::uint32_t thumb_offset_in_code,
    bool entry_is_thumb = false) {
    constexpr std::uint32_t kTextVa = 0x00010000u;
    constexpr std::uint32_t kTextOff = 0x200u;

    const std::string strtab("\0$a\0arm_func\0$t\0thumb_func\0", 27u);
    const std::string shstrtab("\0.text\0.symtab\0.strtab\0.shstrtab\0", 33u);

    // 5 Elf32_Sym entries (16 bytes each): NULL, $a, arm_func, $t, thumb_func
    constexpr std::size_t kSymEntSize = 16u;
    constexpr std::size_t kSymCount = 5u;
    std::vector<std::uint8_t> symtab(kSymEntSize * kSymCount, 0u);

    auto write_sym32 = [&](std::size_t idx,
                           std::uint32_t name_off,
                           std::uint32_t value,
                           std::uint32_t size,
                           std::uint8_t info,
                           std::uint16_t shndx) {
        const std::size_t base = idx * kSymEntSize;
        put32_le(symtab, base + 0u, name_off);
        put32_le(symtab, base + 4u, value);
        put32_le(symtab, base + 8u, size);
        symtab[base + 12u] = info;
        put16_le(symtab, base + 14u, shndx);
    };

    // STB_LOCAL=0, STT_NOTYPE=0 -> 0x00; STB_GLOBAL=1, STT_FUNC=2 -> 0x12
    write_sym32(1u, 1u, kTextVa, 0u, 0x00u, 1u); // $a
    write_sym32(2u, 4u, kTextVa, thumb_offset_in_code, 0x12u, 1u); // arm_func
    write_sym32(3u, 13u, kTextVa + thumb_offset_in_code, 0u, 0x00u, 1u); // $t
    write_sym32(4u, 16u, (kTextVa + thumb_offset_in_code) | 1u,
                static_cast<std::uint32_t>(code_bytes.size()) - thumb_offset_in_code,
                0x12u, 1u); // thumb_func (LSB=1 Thumb bit!)

    const std::size_t sym_off = (kTextOff + code_bytes.size() + 3u) & ~std::size_t{3u};
    const std::size_t str_off = sym_off + symtab.size();
    const std::size_t shstr_off = str_off + strtab.size();
    const std::size_t shdr_off = (shstr_off + shstrtab.size() + 3u) & ~std::size_t{3u};

    constexpr std::size_t kShEntSize = 40u;
    constexpr std::uint16_t kShNum = 5u;
    std::vector<std::uint8_t> buf(shdr_off + kShEntSize * kShNum, 0u);

    buf[0] = 0x7Fu;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 1u; // ELFCLASS32
    buf[5] = 1u; // ELFDATA2LSB
    buf[6] = 1u; // EV_CURRENT
    put16_le(buf, 16u, 2u);  // ET_EXEC
    put16_le(buf, 18u, 40u); // EM_ARM
    put32_le(buf, 20u, 1u);
    const std::uint32_t entry_va = entry_is_thumb
        ? ((kTextVa + thumb_offset_in_code) | 1u)
        : kTextVa;
    put32_le(buf, 24u, entry_va);
    put32_le(buf, 28u, 52u); // e_phoff
    put32_le(buf, 32u, static_cast<std::uint32_t>(shdr_off));
    put16_le(buf, 40u, 52u);
    put16_le(buf, 42u, 32u); // e_phentsize
    put16_le(buf, 44u, 1u);  // e_phnum
    put16_le(buf, 46u, kShEntSize);
    put16_le(buf, 48u, kShNum);
    put16_le(buf, 50u, 4u);  // e_shstrndx

    // Elf32_Phdr PT_LOAD
    put32_le(buf, 52u + 0u, 1u); // PT_LOAD
    put32_le(buf, 52u + 4u, kTextOff);
    put32_le(buf, 52u + 8u, kTextVa);
    put32_le(buf, 52u + 12u, kTextVa);
    put32_le(buf, 52u + 16u, static_cast<std::uint32_t>(code_bytes.size()));
    put32_le(buf, 52u + 20u, static_cast<std::uint32_t>(code_bytes.size()));
    put32_le(buf, 52u + 24u, 5u); // PF_R | PF_X
    put32_le(buf, 52u + 28u, 0x1000u);

    std::memcpy(buf.data() + kTextOff, code_bytes.data(), code_bytes.size());
    std::memcpy(buf.data() + sym_off, symtab.data(), symtab.size());
    std::memcpy(buf.data() + str_off, strtab.data(), strtab.size());
    std::memcpy(buf.data() + shstr_off, shstrtab.data(), shstrtab.size());

    // Section 1: .text
    const std::size_t sh1 = shdr_off + kShEntSize * 1u;
    put32_le(buf, sh1 + 0u, 1u);
    put32_le(buf, sh1 + 4u, 1u); // SHT_PROGBITS
    put32_le(buf, sh1 + 8u, 6u); // SHF_ALLOC | SHF_EXECINSTR
    put32_le(buf, sh1 + 12u, kTextVa);
    put32_le(buf, sh1 + 16u, kTextOff);
    put32_le(buf, sh1 + 20u, static_cast<std::uint32_t>(code_bytes.size()));
    put32_le(buf, sh1 + 32u, 4u);

    // Section 2: .symtab
    const std::size_t sh2 = shdr_off + kShEntSize * 2u;
    put32_le(buf, sh2 + 0u, 7u);
    put32_le(buf, sh2 + 4u, 2u); // SHT_SYMTAB
    put32_le(buf, sh2 + 16u, static_cast<std::uint32_t>(sym_off));
    put32_le(buf, sh2 + 20u, static_cast<std::uint32_t>(symtab.size()));
    put32_le(buf, sh2 + 24u, 3u); // sh_link -> .strtab
    put32_le(buf, sh2 + 28u, 2u); // first global index
    put32_le(buf, sh2 + 32u, 4u);
    put32_le(buf, sh2 + 36u, kSymEntSize);

    // Section 3: .strtab
    const std::size_t sh3 = shdr_off + kShEntSize * 3u;
    put32_le(buf, sh3 + 0u, 15u);
    put32_le(buf, sh3 + 4u, 3u); // SHT_STRTAB
    put32_le(buf, sh3 + 16u, static_cast<std::uint32_t>(str_off));
    put32_le(buf, sh3 + 20u, static_cast<std::uint32_t>(strtab.size()));
    put32_le(buf, sh3 + 32u, 1u);

    // Section 4: .shstrtab
    const std::size_t sh4 = shdr_off + kShEntSize * 4u;
    put32_le(buf, sh4 + 0u, 23u);
    put32_le(buf, sh4 + 4u, 3u); // SHT_STRTAB
    put32_le(buf, sh4 + 16u, static_cast<std::uint32_t>(shstr_off));
    put32_le(buf, sh4 + 20u, static_cast<std::uint32_t>(shstrtab.size()));
    put32_le(buf, sh4 + 32u, 1u);

    return buf;
}

// Generates ~72 KiB of variable-length x86-64 instructions that straddle 4 KiB chunk boundaries.
[[nodiscard]] std::vector<std::uint8_t> build_variable_x64_code_stream(std::size_t target_bytes) {
    // 23-byte repeating block (prime length so instructions straddle every power-of-two chunk boundary!):
    //   55                         push rbp            (1B)
    //   48 89 E5                   mov rbp, rsp        (3B)
    //   B8 44 33 22 11             mov eax, 0x11223344 (5B)
    //   48 05 78 56 34 12          add rax, 0x12345678 (6B)
    //   83 F8 07                   cmp eax, 7          (3B)
    //   75 01                      jne +1              (2B)
    //   90                         nop                 (1B)
    //   5D                         pop rbp             (1B)
    //   C3                         ret                 (1B)
    constexpr std::array<std::uint8_t, 23u> kPattern = {
        0x55u,
        0x48u, 0x89u, 0xE5u,
        0xB8u, 0x44u, 0x33u, 0x22u, 0x11u,
        0x48u, 0x05u, 0x78u, 0x56u, 0x34u, 0x12u,
        0x83u, 0xF8u, 0x07u,
        0x75u, 0x01u,
        0x90u,
        0x5Du,
        0xC3u,
    };

    std::vector<std::uint8_t> out;
    out.reserve(target_bytes + kPattern.size());
    while (out.size() < target_bytes) {
        out.insert(out.end(), kPattern.begin(), kPattern.end());
    }
    return out;
}

} // namespace

TEST(LinearDisassemblyViewTest, MultiChunkContinuityMatchesMonolithicDecodeAndEvictsBoundedLru) {
    const std::vector<std::uint8_t> code = build_variable_x64_code_stream(72u * 1024u);
    const std::vector<std::uint8_t> elf = build_synthetic_elf64_with_text_and_bss(62u /* EM_X86_64 */, code);

    peelf_test::ScopedTempDir tmp("linear_disasm_continuity");
    const std::filesystem::path elf_path = tmp.write_bytes("multi_chunk_x64.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));

    // Reference monolithic single-buffer decode across the entire 72 KiB .text
    viewer::Disassembler mono_decoder;
    ASSERT_TRUE(mono_decoder.init(viewer::Architecture::X86_64, viewer::Endianness::Little));
    const std::vector<viewer::Instruction> reference =
        mono_decoder.disassemble(code.data(), code.size(), 0x401000u);
    ASSERT_GT(reference.size(), 15000u);

    // Virtualized view with small 4 KiB chunks and strict 3-chunk LRU capacity
    viewer::LinearDisassemblyOptions cfg{};
    cfg.chunk_target_bytes = 4096u;
    cfg.max_cached_chunks = 3u;

    viewer::LinearDisassemblyView linear(cfg);
    ASSERT_TRUE(linear.sync_with_model(model, false, false));
    ASSERT_EQ(linear.spans().size(), 1u); // .bss (SHT_NOBITS) excluded!
    EXPECT_EQ(linear.spans().front().name, ".text");
    ASSERT_GT(linear.total_chunk_count(), 14u);

    // Decode entire .text range across all chunk boundaries and verify 1:1 instruction continuity
    const std::vector<viewer::Instruction> virtualized =
        linear.decode_address_range(0x401000u, 0x401000u + code.size());

    ASSERT_EQ(virtualized.size(), reference.size());
    for (std::size_t i = 0; i < reference.size(); ++i) {
        ASSERT_EQ(virtualized[i].address, reference[i].address) << "Mismatch at instruction #" << i;
        ASSERT_EQ(virtualized[i].bytes, reference[i].bytes) << "Byte mismatch at instruction #" << i;
        ASSERT_EQ(virtualized[i].mnemonic, reference[i].mnemonic) << "Mnemonic mismatch at instruction #" << i;
    }

    // Verify bounded LRU enforcement & eviction behavior
    EXPECT_LE(linear.cached_chunk_count(), 3u);
    EXPECT_GT(linear.cache_evictions(), 10u);

    // Re-access chunk 0 (evicted earlier) and verify cache miss reload + subsequent cache hit
    const std::size_t hits_before = linear.cache_hits();
    const auto first_inst = linear.find_instruction_at_address(0x401000u);
    ASSERT_TRUE(first_inst.has_value());
    EXPECT_EQ(first_inst->mnemonic, "push");

    const auto first_inst_cached = linear.find_instruction_at_address(0x401000u);
    ASSERT_TRUE(first_inst_cached.has_value());
    EXPECT_GT(linear.cache_hits(), hits_before);
    EXPECT_LE(linear.cached_chunk_count(), 3u);

    // Verify stepped collect_rows across a chunk boundary matches reference slice
    const std::uint64_t boundary_va = linear.chunk_start_address(2u);
    const auto boundary_row = linear.find_row_for_address(boundary_va);
    ASSERT_TRUE(boundary_row.has_value());
    ASSERT_GT(*boundary_row, 8u);
    const std::vector<viewer::Instruction> cross_slice =
        linear.collect_rows(*boundary_row - 5u, 15u);
    ASSERT_EQ(cross_slice.size(), 15u);
    for (std::size_t k = 1u; k < cross_slice.size(); ++k) {
        EXPECT_EQ(cross_slice[k].address,
                  cross_slice[k - 1u].address + cross_slice[k - 1u].bytes.size());
    }
}

TEST(LinearDisassemblyViewTest, AlignsChunksToKnownSymbolBoundariesAndInvalidatesOnPatchRevision) {
    const std::vector<std::uint8_t> code = build_variable_x64_code_stream(24u * 1024u);
    const std::vector<std::uint8_t> elf = build_synthetic_elf64_with_text_and_bss(62u, code);

    peelf_test::ScopedTempDir tmp("linear_disasm_patch_sym");
    const std::filesystem::path elf_path = tmp.write_bytes("sym_patch_x64.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));

    // Inject a known function symbol at instruction boundary 0x401000 + 23 * 180 = 0x40202C (~4140 bytes)
    constexpr std::uint64_t kAlignedSymVa = 0x401000u + 23u * 180u;
    const std::array<viewer::DebugSymbol, 1u> added_syms = {viewer::DebugSymbol{
        .name = "aligned_worker",
        .relative_virtual_address = kAlignedSymVa - 0x400000u,
        .virtual_address = kAlignedSymVa,
        .size = 230u,
        .function = true,
    }};
    model.add_debug_symbols(added_syms);

    viewer::LinearDisassemblyOptions cfg{};
    cfg.chunk_target_bytes = 4096u;
    cfg.max_cached_chunks = 8u;
    viewer::LinearDisassemblyView linear(cfg);
    ASSERT_TRUE(linear.sync_with_model(model, false, false));

    bool aligned_to_sym = false;
    for (std::size_t ci = 0; ci < linear.total_chunk_count(); ++ci) {
        if (linear.chunk_start_address(ci) == kAlignedSymVa) {
            aligned_to_sym = true;
            break;
        }
    }
    EXPECT_TRUE(aligned_to_sym);

    // Populate chunk 0 in cache (`push rbp` = 0x55 at VA 0x401000, file offset 0x1000)
    const auto before_patch = linear.find_instruction_at_address(0x401000u);
    ASSERT_TRUE(before_patch.has_value());
    EXPECT_EQ(before_patch->mnemonic, "push");
    EXPECT_EQ(model.original_byte_at_offset(0x1000u), std::optional<std::uint8_t>{0x55u});

    // Stage 1-byte patch (`int3` = 0xCC) and verify revision-triggered cache invalidation + diff lookup
    const std::array<std::uint8_t, 1u> int3_patch = {0xCCu};
    ASSERT_TRUE(model.apply_patch_bytes(0x1000u, int3_patch, "stage breakpoint patch").has_value());
    EXPECT_EQ(model.byte_patch_state_at_offset(0x1000u), viewer::BytePatchState::Staged);
    EXPECT_EQ(model.original_byte_at_offset(0x1000u), std::optional<std::uint8_t>{0x55u});

    EXPECT_TRUE(linear.sync_with_model(model, false, false)); // invalidated on edit_revision change
    const auto after_patch = linear.find_instruction_at_address(0x401000u);
    ASSERT_TRUE(after_patch.has_value());
    EXPECT_EQ(after_patch->mnemonic, "int3");

    // Undo patch and confirm original instruction returns
    ASSERT_TRUE(model.undo_patch().has_value());
    EXPECT_EQ(model.byte_patch_state_at_offset(0x1000u), viewer::BytePatchState::Unchanged);
    EXPECT_TRUE(linear.sync_with_model(model, false, false));
    const auto restored = linear.find_instruction_at_address(0x401000u);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->mnemonic, "push");
}

TEST(LinearDisassemblyViewTest, BranchArcLayoutAssignsBoundedNonCrossingLanesAndHighlightsSelection) {
    std::vector<viewer::Instruction> rows(12u);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        rows[i].address = 0x401000u + i * 4u;
        rows[i].bytes = {0x90u, 0x90u, 0x90u, 0x90u};
        rows[i].mnemonic = "nop";
        rows[i].flow = viewer::InstructionFlow::Normal;
    }

    // Outer forward conditional branch: row 1 -> row 9 (span 8)
    rows[1].mnemonic = "jne";
    rows[1].operands = "0x401024";
    rows[1].flow = viewer::InstructionFlow::ConditionalBranch;
    rows[1].branch_target = rows[9].address;

    // Inner forward unconditional jump: row 3 -> row 6 (span 3, should get lane 0 < outer lane!)
    rows[3].mnemonic = "jmp";
    rows[3].operands = "0x401018";
    rows[3].flow = viewer::InstructionFlow::Branch;
    rows[3].branch_target = rows[6].address;

    // Backward loop branch: row 8 -> row 2 (upward conditional)
    rows[8].mnemonic = "jb";
    rows[8].operands = "0x401008";
    rows[8].flow = viewer::InstructionFlow::ConditionalBranch;
    rows[8].branch_target = rows[2].address;

    // Direct call (must be ignored by intra-procedure branch arcs)
    rows[4].mnemonic = "call";
    rows[4].operands = "0x402000";
    rows[4].flow = viewer::InstructionFlow::Call;
    rows[4].branch_target = 0x402000u;

    const std::vector<viewer::BranchArc> arcs =
        viewer::compute_branch_arcs(rows, rows[8].address, 6u, nullptr);
    ASSERT_EQ(arcs.size(), 3u);

    const auto find_arc_from = [&](std::size_t src_row) -> const viewer::BranchArc* {
        const auto it = std::ranges::find(arcs, src_row, &viewer::BranchArc::source_row);
        return it != arcs.end() ? &*it : nullptr;
    };

    const viewer::BranchArc* inner_jmp = find_arc_from(3u);
    const viewer::BranchArc* outer_jne = find_arc_from(1u);
    const viewer::BranchArc* loop_jb = find_arc_from(8u);
    ASSERT_NE(inner_jmp, nullptr);
    ASSERT_NE(outer_jne, nullptr);
    ASSERT_NE(loop_jb, nullptr);

    EXPECT_FALSE(inner_jmp->is_conditional);
    EXPECT_FALSE(inner_jmp->is_upward);
    EXPECT_EQ(inner_jmp->target_row, std::optional<std::size_t>{6u});

    EXPECT_TRUE(outer_jne->is_conditional);
    EXPECT_FALSE(outer_jne->is_upward);
    EXPECT_LT(inner_jmp->lane, outer_jne->lane);

    EXPECT_TRUE(loop_jb->is_conditional);
    EXPECT_TRUE(loop_jb->is_upward);
    EXPECT_TRUE(loop_jb->is_selected);
    EXPECT_EQ(loop_jb->target_row, std::optional<std::size_t>{2u});

    // Verify max_lanes cap drops excess overlapping arcs cleanly
    std::vector<viewer::Instruction> crowded(20u);
    for (std::size_t i = 0; i < crowded.size(); ++i) {
        crowded[i].address = 0x500000u + i * 4u;
        crowded[i].bytes = {0x90u, 0x90u, 0x90u, 0x90u};
        crowded[i].mnemonic = "nop";
        crowded[i].flow = viewer::InstructionFlow::Normal;
    }
    for (std::size_t i = 0; i < 8u; ++i) {
        crowded[i].mnemonic = "je";
        crowded[i].flow = viewer::InstructionFlow::ConditionalBranch;
        crowded[i].branch_target = crowded[19u - i].address;
    }
    const std::vector<viewer::BranchArc> capped_arcs =
        viewer::compute_branch_arcs(crowded, std::nullopt, 3u, nullptr);
    EXPECT_EQ(capped_arcs.size(), 3u);
    for (const auto& arc : capped_arcs) {
        EXPECT_LT(arc.lane, 3u);
    }
}

TEST(LinearDisassemblyViewTest, AttachesFunctionHeadersXrefsUserAnnotationsAndCrossPlatformSourceLines) {
    // 2 simple instructions: `push rbp` (0x401000), `mov rbp, rsp` (0x401001), plus caller `call 0x401000` at 0x401010
    std::vector<std::uint8_t> code(32u, 0x90u);
    code[0] = 0x55u;
    code[1] = 0x48u;
    code[2] = 0x89u;
    code[3] = 0xE5u;
    code[4] = 0xC3u;
    // At +0x10 (0x401010): E8 EB FF FF FF -> call 0x401000
    code[16] = 0xE8u;
    code[17] = 0xEBu;
    code[18] = 0xFFu;
    code[19] = 0xFFu;
    code[20] = 0xFFu;
    code[21] = 0xC3u;

    const std::vector<std::uint8_t> elf = build_synthetic_elf64_with_text_and_bss(62u, code);
    peelf_test::ScopedTempDir tmp("linear_disasm_meta");
    const std::filesystem::path elf_path = tmp.write_bytes("meta_x64.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));

    // Attach both Windows PDB-style backslash path and POSIX DWARF slash path
    viewer::DebugSymbolLoadResult dbg{};
    dbg.status = viewer::DebugSymbolLoadStatus::Loaded;
    dbg.symbols.push_back(viewer::DebugSymbol{
        .name = "_Z7computei",
        .relative_virtual_address = 0x1000u,
        .virtual_address = 0x401000u,
        .size = 5u,
        .function = true,
    });
    dbg.symbols.push_back(viewer::DebugSymbol{
        .name = "caller_entry",
        .relative_virtual_address = 0x1010u,
        .virtual_address = 0x401010u,
        .size = 6u,
        .function = true,
    });
    dbg.lines.push_back(viewer::SourceLineMapping{
        .virtual_address = 0x401000u,
        .relative_virtual_address = 0x1000u,
        .file_path = "C:\\work\\project\\src\\engine.cpp",
        .file_name = {},
        .line = 108u,
        .column = 1u,
        .is_stmt = true,
    });
    dbg.lines.push_back(viewer::SourceLineMapping{
        .virtual_address = 0x401010u,
        .relative_virtual_address = 0x1010u,
        .file_path = "/workspace/src/caller.c",
        .file_name = "caller.c",
        .line = 42u,
        .column = 5u,
        .is_stmt = true,
    });
    model.apply_debug_symbol_result(dbg);

    ASSERT_NE(model.image(), nullptr);
    const viewer::SymbolIndex symbols = model.symbol_index();
    const viewer::ReferenceIndex refs = viewer::ReferenceIndex::build(
        *model.image(),
        model.analysis_image_bytes(),
        false,
        viewer::ReferenceIndex::kDefaultByteBudget,
        &symbols);

    viewer::AnnotationStore notes;
    notes.set(0x401001u, "frame_setup", "Establish stack frame");

    viewer::LinearDisassemblyView linear;
    ASSERT_TRUE(linear.sync_with_model(model, false, false));
    const auto inst0 = linear.find_instruction_at_address(0x401000u);
    const auto inst1 = linear.find_instruction_at_address(0x401001u);
    const auto inst_caller = linear.find_instruction_at_address(0x401010u);
    ASSERT_TRUE(inst0.has_value());
    ASSERT_TRUE(inst1.has_value());
    ASSERT_TRUE(inst_caller.has_value());

    const viewer::LinearMetadataContext meta_ctx{
        .symbols = &symbols,
        .functions = &model.function_index(),
        .references = &refs,
        .annotations = &notes,
        .source_lines = model.source_lines(),
        .demangle_symbols = true,
        .max_xref_preview = 3u,
    };

    const viewer::InstructionRowMetadata meta0 =
        viewer::describe_instruction_row(*inst0, meta_ctx, std::nullopt);
    EXPECT_TRUE(meta0.has_header_banner);
    EXPECT_NE(meta0.header_banner.find("compute(int)"), std::string::npos);
    EXPECT_GE(meta0.incoming_xref_count, 1u);
    EXPECT_NE(meta0.xref_summary.find("caller_entry"), std::string::npos);
    EXPECT_EQ(meta0.source_tag, "[engine.cpp:108]");
    EXPECT_TRUE(meta0.is_new_source_line);

    const viewer::InstructionRowMetadata meta1 =
        viewer::describe_instruction_row(*inst1, meta_ctx, inst0->address);
    EXPECT_EQ(meta1.user_label, "frame_setup");
    EXPECT_EQ(meta1.user_comment, "Establish stack frame");

    const viewer::InstructionRowMetadata meta_caller =
        viewer::describe_instruction_row(*inst_caller, meta_ctx, inst1->address);
    EXPECT_EQ(meta_caller.source_tag, "[caller.c:42]");
    EXPECT_TRUE(meta_caller.is_new_source_line);
}

TEST(LinearDisassemblyViewTest, Arm32HonorsMappingSymbolsThumbLsbAndExplicitToolbarToggle) {
    // 8 bytes ARM32 (A32 LE):
    //   0x10000: 2A 00 A0 E3  mov r0, #42
    //   0x10004: 1E FF 2F E1  bx lr
    // Followed by 4 bytes Thumb (T32 LE) at +8 (0x10008):
    //   0x10008: 07 20        movs r0, #7
    //   0x1000A: 70 47        bx lr
    const std::array<std::uint8_t, 12u> mixed_arm_thumb = {
        0x2Au, 0x00u, 0xA0u, 0xE3u,
        0x1Eu, 0xFFu, 0x2Fu, 0xE1u,
        0x07u, 0x20u,
        0x70u, 0x47u,
    };

    const std::vector<std::uint8_t> elf =
        build_synthetic_arm32_mixed_thumb_elf(mixed_arm_thumb, 8u, false);
    peelf_test::ScopedTempDir tmp("linear_disasm_arm_thumb");
    const std::filesystem::path elf_path = tmp.write_bytes("mixed_arm_thumb.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));
    ASSERT_NE(model.image(), nullptr);

    const std::vector<viewer::ArmThumbRangeHint> hints =
        viewer::extract_arm_thumb_hints(*model.image());
    ASSERT_FALSE(hints.empty());

    viewer::LinearDisassemblyView linear;
    ASSERT_TRUE(linear.sync_with_model(model, false, false));
    EXPECT_FALSE(linear.resolve_thumb_at_address(0x10000u));
    EXPECT_TRUE(linear.resolve_thumb_at_address(0x10008u));

    const auto arm_mov = linear.find_instruction_at_address(0x10000u);
    const auto arm_bx = linear.find_instruction_at_address(0x10004u);
    const auto thumb_movs = linear.find_instruction_at_address(0x10008u);
    const auto thumb_bx = linear.find_instruction_at_address(0x1000Au);
    ASSERT_TRUE(arm_mov.has_value());
    ASSERT_TRUE(arm_bx.has_value());
    ASSERT_TRUE(thumb_movs.has_value());
    ASSERT_TRUE(thumb_bx.has_value());

    EXPECT_EQ(arm_mov->bytes.size(), 4u);
    EXPECT_EQ(arm_bx->mnemonic, "bx");
    EXPECT_EQ(thumb_movs->bytes.size(), 2u);
    EXPECT_EQ(thumb_bx->bytes.size(), 2u);
    EXPECT_EQ(thumb_bx->mnemonic, "bx");

    // Odd Thumb symbol VA lookup (0x10009 -> 0x10008)
    const auto via_odd_va = linear.find_instruction_at_address(0x10009u);
    ASSERT_TRUE(via_odd_va.has_value());
    EXPECT_EQ(via_odd_va->address, 0x10008u);

    // Explicit user Thumb toggle forces Thumb across entire span; forcing ARM forces 4-byte A32
    linear.set_thumb_mode(true, true);
    EXPECT_TRUE(linear.thumb_mode());
    EXPECT_TRUE(linear.thumb_mode_forced());
    const auto forced_thumb_at_start = linear.find_instruction_at_address(0x10000u);
    ASSERT_TRUE(forced_thumb_at_start.has_value());
    EXPECT_EQ(forced_thumb_at_start->bytes.size(), 2u);

    linear.set_thumb_mode(false, true);
    const auto forced_arm_at_thumb = linear.find_instruction_at_address(0x10008u);
    ASSERT_TRUE(forced_arm_at_thumb.has_value());
    EXPECT_EQ(forced_arm_at_thumb->bytes.size(), 4u);
}

TEST(LinearDisassemblyViewTest, ClampsInflatedSectionSizeToFileBackingAndHandlesRiscvCompressed) {
    // RV64C + RV64I sequence:
    //   0x0001: c.nop (2B)
    //   0x13 0x05 0xA0 0x02: addi a0, zero, 42 (4B)
    //   0x82 0x80: c.ret (2B)
    const std::array<std::uint8_t, 8u> rv64c_code = {
        0x01u, 0x00u,
        0x13u, 0x05u, 0xA0u, 0x02u,
        0x82u, 0x80u,
    };
    // Inflate .text sh_size to 0x200000 (far larger than actual file) to test strict file clamping
    const std::vector<std::uint8_t> elf = build_synthetic_elf64_with_text_and_bss(
        243u /* EM_RISCV */, rv64c_code, 0x1000u, 0x200000u);

    peelf_test::ScopedTempDir tmp("linear_disasm_rv64_clamp");
    const std::filesystem::path elf_path = tmp.write_bytes("rv64_clamped.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));

    viewer::LinearDisassemblyView linear;
    ASSERT_TRUE(linear.sync_with_model(model, false, false));
    ASSERT_EQ(linear.spans().size(), 1u);
    ASSERT_TRUE(linear.spans().front().file_offset.has_value());
    EXPECT_LE(*linear.spans().front().file_offset + linear.spans().front().byte_size,
              model.view_size());

    const std::vector<viewer::Instruction> insts =
        linear.decode_address_range(0x401000u, 0x401008u);
    ASSERT_EQ(insts.size(), 3u);
    EXPECT_EQ(insts[0].bytes.size(), 2u);
    EXPECT_EQ(insts[1].bytes.size(), 4u);
    EXPECT_EQ(insts[2].bytes.size(), 2u);
}

namespace {

struct MultiArchFixtureCase {
    const char* fixture_name;
    peelf::Architecture expected_arch;
};

class LinearDisassemblyMultiArchTest : public testing::TestWithParam<MultiArchFixtureCase> {};

} // namespace

TEST_P(LinearDisassemblyMultiArchTest, BuildsClampedSpansAndDecodesEntryAcrossAllCpuFamilies) {
    const MultiArchFixtureCase& tc = GetParam();
    const std::filesystem::path path = fixture_path(tc.fixture_name);
    ASSERT_TRUE(std::filesystem::exists(path)) << path.string();

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(path.string()));
    ASSERT_NE(model.image(), nullptr);
    EXPECT_EQ(model.image()->architecture(), tc.expected_arch);

    viewer::LinearDisassemblyView linear;
    ASSERT_TRUE(linear.sync_with_model(model, false, false));
    ASSERT_FALSE(linear.spans().empty());
    EXPECT_GT(linear.total_rows(), 0u);

    for (const auto& span : linear.spans()) {
        EXPECT_GT(span.byte_size, 0u);
        if (span.file_offset.has_value()) {
            EXPECT_LE(*span.file_offset + span.byte_size, model.view_size());
        }
    }

    const std::uint64_t entry_va = model.image()->architecture() == peelf::Architecture::ARM
        ? (model.image()->entry_point() & ~std::uint64_t{1u})
        : model.image()->entry_point();
    const auto entry_inst = linear.find_instruction_at_address(entry_va);
    ASSERT_TRUE(entry_inst.has_value()) << tc.fixture_name;
    EXPECT_EQ(entry_inst->address, entry_va);
    EXPECT_FALSE(entry_inst->bytes.empty());

    const auto entry_row = linear.find_row_for_address(entry_va);
    ASSERT_TRUE(entry_row.has_value());
    const std::vector<viewer::Instruction> window = linear.collect_rows(*entry_row, 8u);
    ASSERT_FALSE(window.empty());
    EXPECT_EQ(window.front().address, entry_va);
}

INSTANTIATE_TEST_SUITE_P(
    AllSevenCpuFamilies,
    LinearDisassemblyMultiArchTest,
    testing::Values(
        MultiArchFixtureCase{"known-linux-x64.elf", peelf::Architecture::X86_64},
        MultiArchFixtureCase{"known-win-x64.exe", peelf::Architecture::X86_64},
        MultiArchFixtureCase{"known-linux-x86-elf32-le.elf", peelf::Architecture::X86},
        MultiArchFixtureCase{"known-win-x86.exe", peelf::Architecture::X86},
        MultiArchFixtureCase{"known-linux-arm-elf32-le.elf", peelf::Architecture::ARM},
        MultiArchFixtureCase{"known-linux-arm-elf32-be.elf", peelf::Architecture::ARM},
        MultiArchFixtureCase{"known-linux-arm64.elf", peelf::Architecture::ARM64},
        MultiArchFixtureCase{"known-linux-riscv64.elf", peelf::Architecture::RISCV64},
        MultiArchFixtureCase{"known-linux-mips-elf32-be.elf", peelf::Architecture::MIPS32},
        MultiArchFixtureCase{"known-linux-mips64-elf64-be.elf", peelf::Architecture::MIPS64},
        MultiArchFixtureCase{"known-linux-ppc-elf32-be.elf", peelf::Architecture::PowerPC},
        MultiArchFixtureCase{"known-linux-ppc64-elf64-be.elf", peelf::Architecture::PowerPC64}),
    [](const testing::TestParamInfo<MultiArchFixtureCase>& info) {
        std::string name(info.param.fixture_name);
        for (char& ch : name) {
            if (!std::isalnum(static_cast<unsigned char>(ch))) {
                ch = '_';
            }
        }
        return name;
    });

TEST(HexAddressAndAvailabilityTest, FormatsOffsetRvaVaWithGracefulFallbackAndDetectsBssWatermark) {
    const std::array<std::uint8_t, 16u> code = {
        0x55u, 0x48u, 0x89u, 0xE5u, 0x90u, 0x90u, 0x5Du, 0xC3u,
        0x90u, 0x90u, 0x90u, 0x90u, 0x90u, 0x90u, 0x90u, 0x90u,
    };
    const std::vector<std::uint8_t> elf =
        build_synthetic_elf64_with_text_and_bss(62u, code, 0x4000u);

    peelf_test::ScopedTempDir tmp("hex_ux_test");
    const std::filesystem::path elf_path = tmp.write_bytes("hex_ux_bss.elf", elf);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_path.string()));
    ASSERT_NE(model.image(), nullptr);

    // Mapped .text offset 0x1004 -> VA 0x0000000000401004, RVA +0x00001004
    EXPECT_EQ(viewer::format_hex_row_address(
                  viewer::AddressDisplayMode::FileOffset, 0x1004u, model),
              "0x00001004");
    EXPECT_EQ(viewer::format_hex_row_address(
                  viewer::AddressDisplayMode::RelativeVirtualAddress, 0x1004u, model),
              "+0x00001004");
    EXPECT_EQ(viewer::format_hex_row_address(
                  viewer::AddressDisplayMode::VirtualAddress, 0x1004u, model),
              "0x0000000000401004");

    // Unmapped section-header table tail offset -> graceful off:0x... fallback in VA and RVA modes!
    const std::uint64_t tail_unmapped_off = model.view_size() - 8u;
    ASSERT_FALSE(model.offset_to_virtual_address(tail_unmapped_off).has_value());
    const std::string fallback_va = viewer::format_hex_row_address(
        viewer::AddressDisplayMode::VirtualAddress, tail_unmapped_off, model);
    const std::string fallback_rva = viewer::format_hex_row_address(
        viewer::AddressDisplayMode::RelativeVirtualAddress, tail_unmapped_off, model);
    EXPECT_TRUE(fallback_va.starts_with("off:0x"));
    EXPECT_EQ(fallback_va, fallback_rva);

    // Verify SHT_NOBITS .bss vs SHT_PROGBITS .text availability watermark transitions
    const peelf::Section* text_sec = nullptr;
    const peelf::Section* bss_sec = nullptr;
    for (const auto& sec : model.image()->sections()) {
        if (sec.name == ".text") {
            text_sec = &sec;
        } else if (sec.name == ".bss") {
            bss_sec = &sec;
        }
    }
    ASSERT_NE(text_sec, nullptr);
    ASSERT_NE(bss_sec, nullptr);

    const viewer::HexAvailabilityStatus bss_status =
        viewer::evaluate_section_hex_availability(*bss_sec, model.view_size());
    EXPECT_FALSE(bss_status.available);
    EXPECT_NE(bss_status.unavailable_reason.find(".bss"), std::string::npos);

    const viewer::HexAvailabilityStatus text_status =
        viewer::evaluate_section_hex_availability(*text_sec, model.view_size());
    EXPECT_TRUE(text_status.available);
    EXPECT_TRUE(text_status.unavailable_reason.empty());

    // Selection-level transitions: virtual-only .bss selection -> unavailable; .text selection -> available
    const viewer::ViewerSelection bss_sel{
        .kind = viewer::SelectionKind::Section,
        .label = ".bss",
        .file_offset = std::nullopt,
        .virtual_address = bss_sec->virtual_address,
        .size = bss_sec->virtual_size,
    };
    const viewer::HexAvailabilityStatus bss_sel_avail =
        viewer::evaluate_hex_selection_availability(model, bss_sel);
    EXPECT_FALSE(bss_sel_avail.available);
    EXPECT_NE(bss_sel_avail.unavailable_reason.find(".bss"), std::string::npos);

    const viewer::ViewerSelection text_sel{
        .kind = viewer::SelectionKind::Section,
        .label = ".text",
        .file_offset = text_sec->file_offset,
        .virtual_address = text_sec->virtual_address,
        .size = text_sec->file_size,
    };
    const viewer::HexAvailabilityStatus text_sel_avail =
        viewer::evaluate_hex_selection_availability(model, text_sel);
    EXPECT_TRUE(text_sel_avail.available);
    EXPECT_TRUE(text_sel_avail.unavailable_reason.empty());
}
