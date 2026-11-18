#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include <gtest/gtest.h>
#include <array>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <thread>

namespace {
using viewer::ReferenceIndex;
using viewer::ReferenceKind;
constexpr auto x64 = peelf::Architecture::X86_64;
constexpr auto little = peelf::Endianness::Little;
}
TEST(ReferenceIndex, DirectCallAndBranchExcludeRegisterCall) {
    // call 0x1010; call rax; jmp 0x1000
    const std::array<std::uint8_t, 9> bytes{0xE8, 0x0B, 0, 0, 0, 0xFF, 0xD0, 0xEB, 0xF7};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 2);
    EXPECT_EQ(index.records()[0].kind, ReferenceKind::Call);
    EXPECT_EQ(index.records()[0].target, 0x1010);
    EXPECT_EQ(index.records()[1].kind, ReferenceKind::Branch);
    EXPECT_EQ(index.incoming(0x1010).size(), 1);
    EXPECT_EQ(index.outgoing(0x1000, bytes.size()).size(), 2);
    EXPECT_TRUE(index.incoming(std::numeric_limits<std::uint64_t>::max(), 10).empty());
}
TEST(ReferenceIndex, DistinguishesStaticMemoryAndAddressConstants) {
    const std::array<std::uint8_t, 14> bytes{0x48, 0x8D, 0x05, 0x19, 0, 0, 0, 0xB8, 0x20, 0x10, 0, 0, 0x8B, 0};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 2);
    EXPECT_EQ(index.records()[0].target, 0x1020);
    EXPECT_EQ(index.records()[0].kind, ReferenceKind::Data);
    EXPECT_EQ(index.records()[1].target, 0x1020);
    EXPECT_EQ(index.records()[1].kind, ReferenceKind::AddressConstant);
}
TEST(ReferenceIndex, EipRelativeAddressWrapsAt32Bits) {
    const std::array<std::uint8_t, 8> bytes{0x67, 0x48, 0x8D, 0x05, 0x20, 0, 0, 0};
    ReferenceIndex index; index.add_code(bytes, 0xFFFFFFF0ULL, x64, little);
    ASSERT_EQ(index.records().size(), 1);
    EXPECT_EQ(index.records()[0].target, 0x18);
}
TEST(ReferenceIndex, NewPatchInputReplacesOldReferenceTargets) {
    std::array<std::uint8_t, 5> bytes{0xE8, 0x0B, 0, 0, 0};
    ReferenceIndex original; original.add_code(bytes, 0x1000, x64, little);
    bytes[1] = 0x1B;
    ReferenceIndex patched; patched.add_code(bytes, 0x1000, x64, little);
    EXPECT_EQ(original.incoming(0x1010).size(), 1);
    EXPECT_TRUE(patched.incoming(0x1010).empty());
    EXPECT_EQ(patched.incoming(0x1020).size(), 1);
}
TEST(ReferenceIndex, InvalidEncodingRecoveryReportsPartialCoverage) {
    const std::array<std::uint8_t, 6> bytes{0x06, 0xE8, 0, 0, 0, 0};
    ReferenceIndex index; index.add_code(bytes, 0x1000, x64, little);
    ASSERT_EQ(index.records().size(), 1);
    EXPECT_EQ(index.records()[0].source, 0x1001);
    EXPECT_TRUE(index.incomplete());
    ReferenceIndex overflow;
    overflow.add_code(bytes, std::numeric_limits<std::uint64_t>::max() - 1, x64, little);
    EXPECT_TRUE(overflow.incomplete());
    EXPECT_TRUE(overflow.records().empty());
}
TEST(ReferenceIndex, ImageScanHonorsBudgetAndTruncatedInput) {
    std::ifstream file(std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf", std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    auto image = peelf::parse_image(bytes);
    ASSERT_TRUE(image.has_value());
    const auto bounded = ReferenceIndex::build(**image, bytes, false, 1);
    EXPECT_LE(bounded.scanned_bytes(), 1);
    EXPECT_TRUE(bounded.incomplete());
    const auto truncated = ReferenceIndex::build(**image, {});
    EXPECT_TRUE(truncated.records().empty());
    EXPECT_TRUE(truncated.incomplete());
}
TEST(ReferenceIndex, MappedStringReferencesCarrySearchablePreview) {
    std::ifstream file(std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf", std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    auto image = peelf::parse_image(bytes);
    ASSERT_TRUE(image.has_value());
    const auto sections = (*image)->sections();
    const auto code = std::ranges::find_if(sections, [](const auto& section) { return section.executable && section.file_size >= 16; });
    ASSERT_NE(code, sections.end());
    ASSERT_LE(code->file_offset + 16, bytes.size());
    const auto offset = static_cast<std::ptrdiff_t>(code->file_offset);
    // lea rax,[rip+1] points at a NUL-terminated literal 8 bytes into the region.
    const std::array<std::uint8_t, 7> instruction{0x48, 0x8D, 0x05, 1, 0, 0, 0};
    std::ranges::copy(instruction, bytes.begin() + offset);
    const std::string literal = "hello";
    std::ranges::copy(literal, bytes.begin() + offset + 8);
    bytes[static_cast<std::size_t>(offset) + 8 + literal.size()] = 0;
    const auto index = ReferenceIndex::build(**image, bytes);
    const auto refs = index.outgoing(code->virtual_address);
    ASSERT_FALSE(refs.empty());
    EXPECT_EQ(refs.front()->string_preview, literal);
}
TEST(AnnotationStore, RenameCommentAndRemovalAreAddressScoped) {
    viewer::AnnotationStore store;
    store.set(0x1000, "validate_input", "Reject malformed records");
    ASSERT_NE(store.find(0x1000), nullptr);
    EXPECT_EQ(store.find(0x1000)->name, "validate_input");
    store.set(0x1000, "", "Retain comment");
    EXPECT_EQ(store.find(0x1000)->comment, "Retain comment");
    EXPECT_EQ(store.find(0x1001), nullptr);
    store.set(0x1000, "", "");
    EXPECT_TRUE(store.records().empty());
    store.set(1, "name", ""); store.clear();
    EXPECT_TRUE(store.records().empty());
}

TEST(ReferenceIndex, DirectTargetsAcrossSupportedArchitectures) {
    struct Fixture { peelf::Architecture arch; peelf::Endianness endian; std::vector<std::uint8_t> bytes; };
    const std::array fixtures{
        Fixture{peelf::Architecture::X86, little, {0xE8, 0x0B, 0, 0, 0}},
        Fixture{x64, little, {0xE8, 0x0B, 0, 0, 0}},
        Fixture{peelf::Architecture::ARM, little, {0x02, 0, 0, 0xEB}},
        Fixture{peelf::Architecture::ARM64, little, {0x04, 0, 0, 0x94}},
        Fixture{peelf::Architecture::RISCV32, little, {0xEF, 0, 0, 0x01}},
        Fixture{peelf::Architecture::RISCV64, little, {0xEF, 0, 0, 0x01}},
        Fixture{peelf::Architecture::MIPS32, peelf::Endianness::Big, {0x0C, 0, 0x04, 0x04}},
        Fixture{peelf::Architecture::MIPS64, peelf::Endianness::Big, {0x0C, 0, 0x04, 0x04}},
        Fixture{peelf::Architecture::PowerPC, peelf::Endianness::Big, {0x48, 0, 0, 0x11}},
        Fixture{peelf::Architecture::PowerPC64, peelf::Endianness::Big, {0x48, 0, 0, 0x11}}
    };
    for (const auto& fixture : fixtures) {
        SCOPED_TRACE(static_cast<int>(fixture.arch));
        ReferenceIndex index; index.add_code(fixture.bytes, 0x1000, fixture.arch, fixture.endian);
        ASSERT_EQ(index.records().size(), 1);
        EXPECT_EQ(index.records()[0].target, 0x1010);
        EXPECT_EQ(index.records()[0].kind, ReferenceKind::Call);
    }
}

TEST(ReferenceIndex, RiscvZeroDestinationAndPowerPcWithoutLinkAreBranches) {
    const std::array<std::uint8_t, 4> jump{0x6F, 0, 0, 0x01}; // jal x0,+16
    ReferenceIndex riscv; riscv.add_code(jump, 0x1000, peelf::Architecture::RISCV64, little);
    ASSERT_EQ(riscv.records().size(), 1);
    EXPECT_EQ(riscv.records()[0].kind, ReferenceKind::Branch);
    EXPECT_EQ(riscv.records()[0].target, 0x1010);
    const std::array<std::uint8_t, 4> indirect{0x67, 0, 0x05, 0}; // jalr x0,a0,0
    ReferenceIndex unresolved; unresolved.add_code(indirect, 0x1000, peelf::Architecture::RISCV64, little);
    EXPECT_TRUE(unresolved.records().empty());
    const std::array<std::uint8_t, 4> ppc_jump{0x48, 0, 0, 0x10};
    ReferenceIndex ppc; ppc.add_code(ppc_jump, 0x1000, peelf::Architecture::PowerPC, peelf::Endianness::Big);
    ASSERT_EQ(ppc.records().size(), 1);
    EXPECT_EQ(ppc.records()[0].kind, ReferenceKind::Branch);
}

namespace {

struct SyntheticElfLayout {
    std::vector<std::uint8_t> bytes;
    std::size_t text_offset = 0;
    std::uint64_t text_va = 0x401000;
    std::size_t rodata_offset = 0;
    std::uint64_t rodata_va = 0;
};

// Builds a minimal valid ELF64 x86-64 little-endian image with PT_LOAD + .text (+ optional .rodata).
[[nodiscard]] SyntheticElfLayout make_synthetic_elf64(std::size_t code_bytes, std::size_t rodata_bytes = 0) {
    constexpr std::size_t kEhdrSize = 64;
    constexpr std::size_t kPhdrSize = 56;
    constexpr std::size_t kShdrSize = 64;
    constexpr std::string_view kShstrtab{"\0.shstrtab\0.text\0.rodata\0", 25};

    const bool has_rodata = rodata_bytes > 0;
    const std::uint16_t phnum = 1;
    const std::uint16_t shnum = has_rodata ? 4 : 3;
    const std::size_t shoff = kEhdrSize + phnum * kPhdrSize;
    const std::size_t shstr_off = shoff + shnum * kShdrSize;
    const std::size_t text_off = (shstr_off + kShstrtab.size() + 15u) & ~std::size_t{15};
    const std::size_t rodata_off = text_off + code_bytes;
    const std::size_t total_size = rodata_off + rodata_bytes;

    SyntheticElfLayout out;
    out.bytes.assign(total_size, 0u);
    out.text_offset = text_off;
    out.text_va = 0x401000ULL;
    out.rodata_offset = rodata_off;
    out.rodata_va = 0x401000ULL + code_bytes;

    auto w16 = [&](std::size_t off, std::uint16_t v) {
        out.bytes[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
        out.bytes[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    };
    auto w32 = [&](std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0; i < 4; ++i) out.bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    };
    auto w64 = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0; i < 8; ++i) out.bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    };

    // Elf64_Ehdr
    out.bytes[0] = 0x7Fu; out.bytes[1] = 'E'; out.bytes[2] = 'L'; out.bytes[3] = 'F';
    out.bytes[4] = 2u; // ELFCLASS64
    out.bytes[5] = 1u; // ELFDATA2LSB
    out.bytes[6] = 1u; // EV_CURRENT
    w16(16, 2u);       // ET_EXEC
    w16(18, 62u);      // EM_X86_64
    w32(20, 1u);       // EV_CURRENT
    w64(24, out.text_va);
    w64(32, kEhdrSize);
    w64(40, shoff);
    w16(52, kEhdrSize);
    w16(54, kPhdrSize);
    w16(56, phnum);
    w16(58, kShdrSize);
    w16(60, shnum);
    w16(62, 1u); // e_shstrndx = 1

    // Single PT_LOAD covering text + rodata
    const std::size_t ph = kEhdrSize;
    w32(ph + 0, 1u); // PT_LOAD
    w32(ph + 4, 5u); // PF_R | PF_X
    w64(ph + 8, text_off);
    w64(ph + 16, out.text_va);
    w64(ph + 24, out.text_va);
    w64(ph + 32, code_bytes + rodata_bytes);
    w64(ph + 40, code_bytes + rodata_bytes);
    w64(ph + 48, 0x1000u);

    std::ranges::copy(kShstrtab, reinterpret_cast<char*>(out.bytes.data() + shstr_off));

    // Shdr[1]: .shstrtab
    const std::size_t sh1 = shoff + 1u * kShdrSize;
    w32(sh1 + 0, 1u);  // ".shstrtab"
    w32(sh1 + 4, 3u);  // SHT_STRTAB
    w64(sh1 + 24, shstr_off);
    w64(sh1 + 32, kShstrtab.size());

    // Shdr[2]: .text
    const std::size_t sh2 = shoff + 2u * kShdrSize;
    w32(sh2 + 0, 11u); // ".text"
    w32(sh2 + 4, 1u);  // SHT_PROGBITS
    w64(sh2 + 8, 6u);  // SHF_ALLOC | SHF_EXECINSTR
    w64(sh2 + 16, out.text_va);
    w64(sh2 + 24, text_off);
    w64(sh2 + 32, code_bytes);

    if (has_rodata) {
        const std::size_t sh3 = shoff + 3u * kShdrSize;
        w32(sh3 + 0, 17u); // ".rodata"
        w32(sh3 + 4, 1u);  // SHT_PROGBITS
        w64(sh3 + 8, 2u);  // SHF_ALLOC
        w64(sh3 + 16, out.rodata_va);
        w64(sh3 + 24, rodata_off);
        w64(sh3 + 32, rodata_bytes);
    }

    std::fill_n(out.bytes.begin() + static_cast<std::ptrdiff_t>(text_off), code_bytes, std::uint8_t{0x90u});
    return out;
}

} // namespace

TEST(ReferenceIndex, ResumableAsyncScannerStreamsBeyondFourMegabyteBudgetAndSupportsStopToken) {
    constexpr std::size_t kFiveMiB = 5u * 1024u * 1024u;
    auto elf = make_synthetic_elf64(kFiveMiB);
    // Fill with 8-byte multi-byte NOPs (0F 1F 84 00 00 00 00 00) so Debug builds decode 5 MiB briskly.
    constexpr std::array<std::uint8_t, 8> kNop8{0x0Fu, 0x1Fu, 0x84u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};
    for (std::size_t off = 0; off + 8u <= kFiveMiB; off += 8u) {
        std::memcpy(elf.bytes.data() + elf.text_offset + off, kNop8.data(), kNop8.size());
    }

    // First call at +0x100 (5-byte call + 3-byte NOP = 8 bytes) -> target 0x401200 (inside initial 4 MiB budget)
    constexpr std::array<std::uint8_t, 8> kCallPlusNop3{0xE8u, 0xFBu, 0x00u, 0x00u, 0x00u, 0x0Fu, 0x1Fu, 0x00u};
    std::memcpy(elf.bytes.data() + elf.text_offset + 0x100u, kCallPlusNop3.data(), kCallPlusNop3.size());

    // Second call at +4 MiB + 0x100 -> target +4 MiB + 0x200 (beyond 4 MiB default budget)
    constexpr std::size_t kLateOffset = 4u * 1024u * 1024u + 0x100u;
    const std::uint64_t late_target = elf.text_va + kLateOffset + 0x100u;
    std::memcpy(elf.bytes.data() + elf.text_offset + kLateOffset, kCallPlusNop3.data(), kCallPlusNop3.size());

    auto parsed = peelf::parse_image(elf.bytes);
    ASSERT_TRUE(parsed.has_value());
    const auto& image = **parsed;

    // Test stop_token cancellation on ReferenceScanJob first.
    {
        std::stop_source stop;
        stop.request_stop();
        viewer::ReferenceScanJob cancelled_job(image, elf.bytes);
        ReferenceIndex cancelled_idx;
        EXPECT_FALSE(cancelled_job.run(cancelled_idx, stop.get_token()));
        EXPECT_EQ(cancelled_idx.scanned_bytes(), 0u);
    }

    ReferenceIndex async_idx;
    viewer::AsyncReferenceScanner scanner;
    scanner.start(async_idx, image, elf.bytes, false, ReferenceIndex::kDefaultByteBudget);
    scanner.wait(async_idx);

    EXPECT_EQ(async_idx.total_executable_bytes(), kFiveMiB);
    EXPECT_EQ(async_idx.scanned_bytes(), ReferenceIndex::kDefaultByteBudget);
    EXPECT_TRUE(async_idx.incomplete());
    EXPECT_NEAR(async_idx.coverage_percent(), 80.0, 0.1);
    EXPECT_TRUE(scanner.has_resumable_work());
    EXPECT_EQ(async_idx.incoming(0x401200).size(), 1u);
    EXPECT_TRUE(async_idx.incoming(late_target).empty());

    // Resume full binary scan without restarting from 0.
    scanner.scan_full(async_idx);
    scanner.wait(async_idx);

    EXPECT_EQ(async_idx.scanned_bytes(), kFiveMiB);
    EXPECT_FALSE(async_idx.incomplete());
    EXPECT_DOUBLE_EQ(async_idx.coverage_percent(), 100.0);
    EXPECT_FALSE(scanner.has_resumable_work());
    EXPECT_EQ(async_idx.incoming(0x401200).size(), 1u);
    ASSERT_EQ(async_idx.incoming(late_target).size(), 1u);
    EXPECT_EQ(async_idx.incoming(late_target)[0]->confidence, viewer::ReferenceConfidence::Direct);
}

TEST(ReferenceIndex, ChunkBoundaryPreservesStraddlingInstructionsAndSortedQueries) {
    auto elf = make_synthetic_elf64(128);
    // Place a 5-byte call at offset 62..67 straddling a 64-byte chunk boundary -> target 0x401000 + 67 + 0x10 = 0x401053
    elf.bytes[elf.text_offset + 62] = 0xE8u;
    elf.bytes[elf.text_offset + 63] = 0x10u;
    elf.bytes[elf.text_offset + 64] = 0x00u;
    elf.bytes[elf.text_offset + 65] = 0x00u;
    elf.bytes[elf.text_offset + 66] = 0x00u;

    auto parsed = peelf::parse_image(elf.bytes);
    ASSERT_TRUE(parsed.has_value());

    viewer::ReferenceScanJob job(**parsed, elf.bytes, false, 128, nullptr, 64);
    ReferenceIndex chunked;
    ASSERT_TRUE(job.run(chunked));
    const ReferenceIndex unchunked = ReferenceIndex::build(**parsed, elf.bytes, false, 128);

    ASSERT_EQ(chunked.records().size(), unchunked.records().size());
    ASSERT_EQ(chunked.records().size(), 1u);
    EXPECT_EQ(chunked.records()[0].source, 0x401000ULL + 62u);
    EXPECT_EQ(chunked.records()[0].target, 0x401053ULL);
    EXPECT_EQ(chunked.incoming(0x401050ULL, 8u).size(), 1u);
    EXPECT_EQ(chunked.outgoing(0x40103CULL, 8u).size(), 1u);
}

TEST(ReferenceIndex, RecoversRipRelativeJumpTablesAndIatIndirectCallsWithConfidenceAndEvidence) {
    // 1) x86-64 RIP-relative i32 jump table in .rodata
    auto switch_elf = make_synthetic_elf64(0x100, 0x40);
    const std::array<std::uint8_t, 33> switch_code{
        0x83, 0xFF, 0x01,
        0x77, 0x1B,
        0x48, 0x8D, 0x0D, 0xF4, 0x00, 0x00, 0x00,
        0x48, 0x63, 0x04, 0xB9,
        0x48, 0x01, 0xC8,
        0xFF, 0xE0,
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
        0x31, 0xC0, 0xC3,
        0x90, 0x90, 0xC3,
    };
    std::ranges::copy(switch_code, switch_elf.bytes.begin() + static_cast<std::ptrdiff_t>(switch_elf.text_offset));
    const auto write_i32 = [&](std::size_t off, std::int32_t val) {
        const auto u = static_cast<std::uint32_t>(val);
        switch_elf.bytes[off + 0] = static_cast<std::uint8_t>(u & 0xFFu);
        switch_elf.bytes[off + 1] = static_cast<std::uint8_t>((u >> 8u) & 0xFFu);
        switch_elf.bytes[off + 2] = static_cast<std::uint8_t>((u >> 16u) & 0xFFu);
        switch_elf.bytes[off + 3] = static_cast<std::uint8_t>((u >> 24u) & 0xFFu);
    };
    write_i32(switch_elf.rodata_offset + 0, static_cast<std::int32_t>(0x401015 - 0x401100));
    write_i32(switch_elf.rodata_offset + 4, static_cast<std::int32_t>(0x40101B - 0x401100));

    auto switch_parsed = peelf::parse_image(switch_elf.bytes);
    ASSERT_TRUE(switch_parsed.has_value());
    const auto switch_refs = ReferenceIndex::build(**switch_parsed, switch_elf.bytes);
    const auto case0_in = switch_refs.incoming(0x401015);
    const auto case1_in = switch_refs.incoming(0x40101B);
    ASSERT_EQ(case0_in.size(), 1u);
    ASSERT_EQ(case1_in.size(), 1u);
    EXPECT_EQ(case0_in[0]->confidence, viewer::ReferenceConfidence::IndirectTable);
    EXPECT_NE(case0_in[0]->evidence.find("RIP-relative i32 jump table"), std::string::npos);

    // 2) PE x64 IAT indirect call: call qword ptr [rip + disp32]
    std::ifstream pe_file(std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe", std::ios::binary);
    std::vector<std::uint8_t> pe_bytes{std::istreambuf_iterator<char>(pe_file), std::istreambuf_iterator<char>()};
    auto pe_img = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(pe_img.has_value());
    ASSERT_FALSE((*pe_img)->imports().empty());
    const auto& imp = (*pe_img)->imports().front();
    const std::uint64_t entry_va = (*pe_img)->entry_point();
    const auto entry_off = (*pe_img)->virtual_address_to_file_offset(entry_va);
    ASSERT_TRUE(entry_off.has_value());
    const std::uint64_t slot_va = imp.address;
    const auto disp32 = static_cast<std::uint32_t>(
        static_cast<std::int32_t>(static_cast<std::int64_t>(slot_va) - static_cast<std::int64_t>(entry_va + 6u)));
    pe_bytes[*entry_off + 0] = 0xFFu;
    pe_bytes[*entry_off + 1] = 0x15u;
    pe_bytes[*entry_off + 2] = static_cast<std::uint8_t>(disp32 & 0xFFu);
    pe_bytes[*entry_off + 3] = static_cast<std::uint8_t>((disp32 >> 8u) & 0xFFu);
    pe_bytes[*entry_off + 4] = static_cast<std::uint8_t>((disp32 >> 16u) & 0xFFu);
    pe_bytes[*entry_off + 5] = static_cast<std::uint8_t>((disp32 >> 24u) & 0xFFu);

    const auto pe_refs = ReferenceIndex::build(**pe_img, pe_bytes);
    const auto slot_in = pe_refs.incoming(slot_va);
    const bool found_iat_call = std::ranges::any_of(slot_in, [&](const viewer::Reference* r) {
        return r->source == entry_va &&
               r->kind == ReferenceKind::Call &&
               r->confidence == viewer::ReferenceConfidence::IndirectPointerSlot &&
               r->evidence.find(imp.name) != std::string::npos;
    });
    EXPECT_TRUE(found_iat_call);
}

TEST(ReferenceIndex, PauseAndCancelWithUnmergedPendingChunksResumeWithoutDroppingChunks) {
    constexpr std::size_t kChunkBytes = 4096u;
    constexpr std::size_t kChunkCount = 16u;
    constexpr std::size_t kTotalCodeBytes = kChunkBytes * kChunkCount;
    // Add an extra 4 KiB target area so every chunk's call lands in valid executable .text.
    auto elf = make_synthetic_elf64(kTotalCodeBytes + 4096u);

    // Place a unique 5-byte `call rel32` inside each of the 16 chunks targeting `callee_base + c * 16`.
    const std::uint64_t callee_base = elf.text_va + kTotalCodeBytes;
    for (std::size_t c = 0; c < kChunkCount; ++c) {
        const std::size_t call_off = c * kChunkBytes + 64u;
        const std::uint64_t call_va = elf.text_va + call_off;
        const std::uint64_t target_va = callee_base + c * 16u;
        const auto rel32 = static_cast<std::uint32_t>(
            static_cast<std::int32_t>(static_cast<std::int64_t>(target_va) - static_cast<std::int64_t>(call_va + 5u)));
        elf.bytes[elf.text_offset + call_off + 0] = 0xE8u;
        elf.bytes[elf.text_offset + call_off + 1] = static_cast<std::uint8_t>(rel32 & 0xFFu);
        elf.bytes[elf.text_offset + call_off + 2] = static_cast<std::uint8_t>((rel32 >> 8u) & 0xFFu);
        elf.bytes[elf.text_offset + call_off + 3] = static_cast<std::uint8_t>((rel32 >> 16u) & 0xFFu);
        elf.bytes[elf.text_offset + call_off + 4] = static_cast<std::uint8_t>((rel32 >> 24u) & 0xFFu);
    }

    auto parsed = peelf::parse_image(elf.bytes);
    ASSERT_TRUE(parsed.has_value());
    const auto& image = **parsed;

    ReferenceIndex idx;
    viewer::AsyncReferenceScanner scanner;
    scanner.start(idx, image, elf.bytes, false, kTotalCodeBytes + 4096u, nullptr, kChunkBytes);

    // Let the background worker enqueue pending chunks without calling `poll(idx)` on the UI thread,
    // then cancel(&idx): un-polled pending chunks are discarded, so `committed_cursor_` MUST roll back
    // `job_` to the last merged cursor (0 bytes) rather than losing those chunks forever!
    for (int spin = 0; spin < 200 && scanner.is_scanning(); ++spin) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    scanner.cancel(&idx);
    EXPECT_EQ(idx.scanned_bytes(), 0u);
    EXPECT_TRUE(scanner.has_resumable_work());

    // Now exercise pause() + poll() + resume() + wait() and verify all 16 chunks are present.
    scanner.resume(idx);
    scanner.pause();
    (void)scanner.poll(idx);
    if (scanner.has_resumable_work()) {
        scanner.resume(idx);
    }
    scanner.wait(idx);

    EXPECT_EQ(idx.scanned_bytes(), kTotalCodeBytes + 4096u);
    EXPECT_FALSE(idx.incomplete());
    for (std::size_t c = 0; c < kChunkCount; ++c) {
        const std::uint64_t target_va = callee_base + c * 16u;
        EXPECT_EQ(idx.incoming(target_va).size(), 1u) << "Missing call from chunk " << c;
    }
}

TEST(ReferenceIndex, JumpTableBackwardScanStopsOnClobbersAndRiscvFunctionIndexChecksAuipcRegisters) {
    const auto write_i32 = [](std::vector<std::uint8_t>& buf, std::size_t off, std::int32_t val) {
        const auto u = static_cast<std::uint32_t>(val);
        buf[off + 0] = static_cast<std::uint8_t>(u & 0xFFu);
        buf[off + 1] = static_cast<std::uint8_t>((u >> 8u) & 0xFFu);
        buf[off + 2] = static_cast<std::uint8_t>((u >> 16u) & 0xFFu);
        buf[off + 3] = static_cast<std::uint8_t>((u >> 24u) & 0xFFu);
    };

    // 1a) Clobbering index register `edi` (`add edi, 1` = 83 C7 01) between `ja` and `movsxd` invalidates bounds!
    {
        auto clobber_idx_elf = make_synthetic_elf64(0x100, 0x40);
        const std::array<std::uint8_t, 36> code_reg_clobber{
            0x83, 0xFF, 0x01,                   // 0x401000: cmp edi, 1
            0x77, 0x1E,                         // 0x401003: ja  0x401023
            0x83, 0xC7, 0x01,                   // 0x401005: add edi, 1  (CLOBBERS edi!)
            0x48, 0x8D, 0x0D, 0xF1, 0x00, 0x00, 0x00, // 0x401008: lea rcx, [rip + 0xF1] -> 0x401100
            0x48, 0x63, 0x04, 0xB9,             // 0x40100F: movsxd rax, dword ptr [rcx + rdi*4]
            0x48, 0x01, 0xC8,                   // 0x401013: add rax, rcx
            0xFF, 0xE0,                         // 0x401016: jmp rax
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, // 0x401018: case 0
            0x31, 0xC0, 0xC3,                   // 0x40101E: case 1
            0x90, 0x90, 0xC3,                   // 0x401021: default
        };
        std::ranges::copy(code_reg_clobber,
                          clobber_idx_elf.bytes.begin() + static_cast<std::ptrdiff_t>(clobber_idx_elf.text_offset));
        write_i32(clobber_idx_elf.bytes, clobber_idx_elf.rodata_offset + 0, static_cast<std::int32_t>(0x401018 - 0x401100));
        write_i32(clobber_idx_elf.bytes, clobber_idx_elf.rodata_offset + 4, static_cast<std::int32_t>(0x40101E - 0x401100));

        const auto parsed = peelf::parse_image(clobber_idx_elf.bytes);
        ASSERT_TRUE(parsed.has_value());
        const auto refs = ReferenceIndex::build(**parsed, clobber_idx_elf.bytes);
        EXPECT_TRUE(refs.incoming(0x401018).empty());
    }

    // 1b) Clobbering flags (`test eax, eax` = 85 C0) between `cmp edi, 1` and `ja` invalidates flag linkage!
    {
        auto clobber_flags_elf = make_synthetic_elf64(0x100, 0x40);
        const std::array<std::uint8_t, 35> code_flag_clobber{
            0x83, 0xFF, 0x01,                   // 0x401000: cmp edi, 1
            0x85, 0xC0,                         // 0x401003: test eax, eax (CLOBBERS EFLAGS!)
            0x77, 0x1B,                         // 0x401005: ja  0x401022
            0x48, 0x8D, 0x0D, 0xF2, 0x00, 0x00, 0x00, // 0x401007: lea rcx, [rip + 0xF2] -> 0x401100
            0x48, 0x63, 0x04, 0xB9,             // 0x40100E: movsxd rax, dword ptr [rcx + rdi*4]
            0x48, 0x01, 0xC8,                   // 0x401012: add rax, rcx
            0xFF, 0xE0,                         // 0x401015: jmp rax
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, // 0x401017: case 0
            0x31, 0xC0, 0xC3,                   // 0x40101D: case 1
            0x90, 0x90, 0xC3,                   // 0x401020: default
        };
        std::ranges::copy(code_flag_clobber,
                          clobber_flags_elf.bytes.begin() + static_cast<std::ptrdiff_t>(clobber_flags_elf.text_offset));
        write_i32(clobber_flags_elf.bytes, clobber_flags_elf.rodata_offset + 0, static_cast<std::int32_t>(0x401017 - 0x401100));
        write_i32(clobber_flags_elf.bytes, clobber_flags_elf.rodata_offset + 4, static_cast<std::int32_t>(0x40101D - 0x401100));

        const auto parsed = peelf::parse_image(clobber_flags_elf.bytes);
        ASSERT_TRUE(parsed.has_value());
        const auto refs = ReferenceIndex::build(**parsed, clobber_flags_elf.bytes);
        EXPECT_TRUE(refs.incoming(0x401017).empty());
    }

    // 2) RISC-V64 FunctionIndex `auipc` + `addi` + `jalr` enforces `rs1 == rd` and invalidates clobbered `rd`!
    {
        auto rv_elf = make_synthetic_elf64(0x100);
        // Set Elf64_Ehdr::e_machine = EM_RISCV (243)
        rv_elf.bytes[18] = 243u;
        rv_elf.bytes[19] = 0u;

        const auto w32_code = [&](std::size_t code_off, std::uint32_t insn) {
            const std::size_t off = rv_elf.text_offset + code_off;
            rv_elf.bytes[off + 0] = static_cast<std::uint8_t>(insn & 0xFFu);
            rv_elf.bytes[off + 1] = static_cast<std::uint8_t>((insn >> 8u) & 0xFFu);
            rv_elf.bytes[off + 2] = static_cast<std::uint8_t>((insn >> 16u) & 0xFFu);
            rv_elf.bytes[off + 3] = static_cast<std::uint8_t>((insn >> 24u) & 0xFFu);
        };
        for (std::size_t off = 0; off + 4u <= 0x100u; off += 4u) {
            w32_code(off, 0x00000013u); // nop (addi x0, x0, 0)
        }

        // Valid: auipc t1, 0 (0x401000) -> addi t1, t1, 0x80 -> jalr ra, 0(t1) => target 0x401080
        w32_code(0x00, 0x00000317u); // auipc t1, 0
        w32_code(0x04, 0x08030313u); // addi  t1, t1, 0x80
        w32_code(0x08, 0x000300E7u); // jalr  ra, 0(t1)

        // Mismatched rs1: auipc t1, 0 (0x40100C) -> jalr ra, 0x90(t2) (t2 != t1 => MUST NOT target 0x40109C!)
        w32_code(0x0C, 0x00000317u); // auipc t1, 0
        w32_code(0x10, 0x090380E7u); // jalr  ra, 0x90(t2)

        // Clobbered rd: auipc t1, 0 (0x401014) -> lui t1, 1 -> jalr ra, 0xA0(t1) (MUST NOT target 0x4010B4!)
        w32_code(0x14, 0x00000317u); // auipc t1, 0
        w32_code(0x18, 0x00001337u); // lui   t1, 1 (clobbers t1)
        w32_code(0x1C, 0x0A0300E7u); // jalr  ra, 0xA0(t1)
        w32_code(0x20, 0x00008067u); // ret

        w32_code(0x80, 0x00008067u); // valid callee at 0x401080
        w32_code(0x9C, 0x00008067u); // unreferenced stub at 0x40109C
        w32_code(0xB4, 0x00008067u); // unreferenced stub at 0x4010B4

        const auto parsed = peelf::parse_image(rv_elf.bytes);
        ASSERT_TRUE(parsed.has_value());
        ASSERT_EQ((*parsed)->architecture(), peelf::Architecture::RISCV64);

        auto sym_idx = viewer::SymbolIndex::build(**parsed);
        const auto fn_idx = viewer::FunctionIndex::discover(**parsed, sym_idx, rv_elf.bytes);
        EXPECT_NE(fn_idx.find_exact(0x401080ULL), nullptr);
        EXPECT_EQ(fn_idx.find_exact(0x40109CULL), nullptr);
        EXPECT_EQ(fn_idx.find_exact(0x4010B4ULL), nullptr);
    }
}

