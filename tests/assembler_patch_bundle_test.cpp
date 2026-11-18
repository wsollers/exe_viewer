#include <peelf/assembler.hpp>
#include <peelf/patch_bundle.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/sha256.hpp>

#include "analysis/patch_preview.hpp"
#include "model/binary_model.hpp"
#include "symbols/symbol_index.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#if defined(__linux__)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

[[nodiscard]] std::filesystem::path fixture_pe64_path() {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe";
}

class DummyReadOnlyLiveSession final : public peelf::IProcessSession {
public:
    DummyReadOnlyLiveSession() {
        info_.pid = 424242;
        info_.name = "readonly_target";
        info_.architecture = peelf::Architecture::X86_64;
        info_.endianness = peelf::Endianness::Little;
        info_.is_64bit = true;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        peelf::MemoryRegion reg;
        reg.start_address = 0x400000;
        reg.end_address = 0x401000;
        reg.protection = {.readable = true, .writable = false, .executable = true, .shared = false};
        reg.kind = peelf::MemoryRegionKind::Image;
        reg.pathname = "/bin/readonly_target";
        return std::vector<peelf::MemoryRegion>{reg};
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        peelf::ModuleInfo mod;
        mod.name = "readonly_target";
        mod.base_address = 0x400000;
        mod.size = 0x1000;
        mod.is_main_module = true;
        return std::vector<peelf::ModuleInfo>{mod};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t /*address*/,
        std::span<std::uint8_t> buffer) override {
        std::fill(buffer.begin(), buffer.end(), 0x90u);
        return buffer.size();
    }

    [[nodiscard]] peelf::Result<std::size_t> write_memory(
        std::uint64_t /*address*/,
        std::span<const std::uint8_t> /*data*/,
        peelf::MemoryWriteOptions /*options*/) override {
        return peelf::make_error("read-only live session");
    }

private:
    peelf::ProcessInfo info_{};
};

} // namespace

#if PEELF_ASMTK_AVAILABLE
TEST(AssemblerProviderTest, AsmTkAssemblesX64MultiLineAndComments) {
    peelf::AsmTkAssemblerProvider provider;
    EXPECT_TRUE(provider.availability().ok());
    EXPECT_TRUE(provider.supports_target(
        peelf::Architecture::X86_64, peelf::Endianness::Little, true, false));
    EXPECT_FALSE(provider.supports_target(
        peelf::Architecture::ARM64, peelf::Endianness::Little, true, false));

    const char* src =
        "; Prologue comment\n"
        "xor eax, eax // zero return value\n"
        "mov eax, 0x2a\n"
        "ret\n";
    auto out = peelf::assemble_instructions(
        peelf::Architecture::X86_64, peelf::Endianness::Little, true, false, 0x140001000ull, src);
    ASSERT_TRUE(out.has_value()) << out.error().message;
    EXPECT_EQ(out->provider_name, "AsmTK");
    ASSERT_EQ(out->instruction_spans.size(), 3u);
    EXPECT_EQ(out->instruction_spans[0].line_number, 2u);
    EXPECT_EQ(out->instruction_spans[1].line_number, 3u);
    EXPECT_EQ(out->instruction_spans[2].line_number, 4u);

    const std::vector<std::uint8_t> expected{0x31u, 0xC0u, 0xB8u, 0x2Au, 0x00u, 0x00u, 0x00u, 0xC3u};
    EXPECT_EQ(out->bytes, expected);
}

TEST(AssemblerProviderTest, AsmTkAssemblesX86_32AndRelativeBranchesAtCustomBaseVa) {
    // 32-bit x86 frame setup
    auto x86_out = peelf::assemble_instructions(
        peelf::Architecture::X86,
        peelf::Endianness::Little,
        false,
        false,
        0x00401000u,
        "push ebp\nmov ebp, esp\npop ebp\nret\n");
    ASSERT_TRUE(x86_out.has_value()) << x86_out.error().message;
    const std::vector<std::uint8_t> expected_x86{0x55u, 0x89u, 0xE5u, 0x5Du, 0xC3u};
    EXPECT_EQ(x86_out->bytes, expected_x86);

    // 64-bit relative call displacement at base VA 0x140001000 -> target 0x140002000
    // Next RIP = 0x140001005, rel32 = +0xFFB (FB 0F 00 00)
    auto call_out = peelf::assemble_instructions(
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        true,
        false,
        0x140001000ull,
        "call 0x140002000\n"
        "loop_head:\n"
        "dec ecx\n"
        "jnz loop_head\n");
    ASSERT_TRUE(call_out.has_value()) << call_out.error().message;
    ASSERT_GE(call_out->bytes.size(), 5u);
    EXPECT_EQ(call_out->bytes[0], 0xE8u);
    EXPECT_EQ(call_out->bytes[1], 0xFBu);
    EXPECT_EQ(call_out->bytes[2], 0x0Fu);
    EXPECT_EQ(call_out->bytes[3], 0x00u);
    EXPECT_EQ(call_out->bytes[4], 0x00u);

    const auto roundtrip = viewer::disassemble_patch_bytes(
        call_out->bytes,
        0x140001000ull,
        peelf::Architecture::X86_64,
        peelf::Endianness::Little,
        false);
    ASSERT_GE(roundtrip.size(), 3u);
    EXPECT_EQ(roundtrip[0].mnemonic, "call");
    ASSERT_TRUE(roundtrip[0].branch_target.has_value());
    EXPECT_EQ(*roundtrip[0].branch_target, 0x140002000ull);
    EXPECT_EQ(roundtrip[2].mnemonic, "jne");
    ASSERT_TRUE(roundtrip[2].branch_target.has_value());
    EXPECT_EQ(*roundtrip[2].branch_target, 0x140001005ull);
}

TEST(AssemblerProviderTest, AsmTkReportsLineNumberedSyntaxAndUnboundLabelDiagnostics) {
    peelf::AsmTkAssemblerProvider provider;

    peelf::AssembleRequest bad_syntax{
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .base_address = 0x401000,
        .source_text = "nop\ninvalid_mnemonic_xyz rax, 1\nret\n",
    };
    auto bad_res = provider.assemble(bad_syntax);
    ASSERT_FALSE(bad_res.has_value());
    EXPECT_NE(bad_res.error().message.find("Line 2"), std::string::npos)
        << bad_res.error().message;

    peelf::AssembleRequest unbound{
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .base_address = 0x401000,
        .source_text = "nop\nret\njmp missing_target_label\n",
    };
    auto unbound_res = provider.assemble(unbound);
    ASSERT_FALSE(unbound_res.has_value());
    EXPECT_NE(unbound_res.error().message.find("missing_target_label"), std::string::npos)
        << unbound_res.error().message;
    EXPECT_NE(unbound_res.error().message.find("Line 3"), std::string::npos)
        << unbound_res.error().message;
}
#endif

TEST(AssemblerProviderTest, LlvmMcTriplesAndShowEncodingParserCoverMultiArchAndErrors) {
    EXPECT_EQ(peelf::llvm_mc_triple_for_target(
                  peelf::Architecture::ARM64, peelf::Endianness::Little, true, false),
              "aarch64-unknown-none-elf");
    EXPECT_EQ(peelf::llvm_mc_triple_for_target(
                  peelf::Architecture::ARM, peelf::Endianness::Little, false, true),
              "thumbv7-unknown-none-eabi");
    EXPECT_EQ(peelf::llvm_mc_triple_for_target(
                  peelf::Architecture::RISCV64, peelf::Endianness::Little, true, false),
              "riscv64-unknown-none-elf");
    EXPECT_EQ(peelf::llvm_mc_triple_for_target(
                  peelf::Architecture::PowerPC64, peelf::Endianness::Big, true, false),
              "powerpc64-unknown-none-elf");
    EXPECT_EQ(peelf::llvm_mc_triple_for_target(
                  peelf::Architecture::MIPS32, peelf::Endianness::Little, false, false),
              "mipsel-unknown-none-elf");

    const char* sample_aarch64 =
        "\t.text\n"
        "\tmov\tx0, #42                 // encoding: [0x40,0x05,0x80,0xd2]\n"
        "\tret                             // encoding: [0xc0,0x03,0x5f,0xd6]\n";
    auto parsed = peelf::parse_llvm_mc_show_encoding_output(sample_aarch64, "", 0x400000);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const std::vector<std::uint8_t> expected_a64{
        0x40u, 0x05u, 0x80u, 0xD2u, 0xC0u, 0x03u, 0x5Fu, 0xD6u};
    EXPECT_EQ(parsed->bytes, expected_a64);
    ASSERT_EQ(parsed->instruction_spans.size(), 2u);
    EXPECT_EQ(parsed->instruction_spans[0].byte_offset, 0u);
    EXPECT_EQ(parsed->instruction_spans[0].byte_size, 4u);
    EXPECT_EQ(parsed->instruction_spans[1].byte_offset, 4u);
    EXPECT_EQ(parsed->instruction_spans[1].byte_size, 4u);

    // Reject unresolved external symbolic fixups cleanly
    const char* with_fixup =
        "\tbl\texternal_sym             // encoding: [A,A,A,0b100101AA]\n"
        "\t                                //   fixup A - offset: 0, value: external_sym, kind: fixup_aarch64_pcrel_call26\n";
    auto fixup_res = peelf::parse_llvm_mc_show_encoding_output(with_fixup, "", 0x400000);
    EXPECT_FALSE(fixup_res.has_value());

    // Parse line:col diagnostics from llvm-mc stderr
    const char* err_stderr = "<stdin>:4:9: error: invalid operand for instruction\n";
    auto err_res = peelf::parse_llvm_mc_show_encoding_output("", err_stderr, 0x400000);
    ASSERT_FALSE(err_res.has_value());
    EXPECT_NE(err_res.error().message.find("Line 4"), std::string::npos) << err_res.error().message;

    // Explicit missing binary reports Unavailable cleanly
    peelf::LlvmMcAssemblerProvider missing_provider("/nonexistent/path/to/llvm-mc-missing");
    EXPECT_FALSE(missing_provider.availability().ok());
    EXPECT_EQ(missing_provider.availability().availability, peelf::Availability::Unavailable);

#if defined(__linux__)
    // Verify safe argv subprocess invocation against a mock llvm-mc executable in /tmp
    peelf_test::ScopedTempDir tmp("peelf_wu11");
    const std::filesystem::path fake_mc = tmp / "fake-llvm-mc";
    {
        std::ofstream script(fake_mc, std::ios::binary | std::ios::trunc);
        script << "#!/bin/sh\n"
               << "if [ \"$1\" = \"--version\" ]; then\n"
               << "  echo 'LLVM version 18.1.8 (mock)'\n"
               << "  exit 0\n"
               << "fi\n"
               << "cat >/dev/null\n"
               << "echo '\taddi a0, zero, 7 # encoding: [0x13,0x05,0x70,0x00]'\n"
               << "echo '\tret              # encoding: [0x67,0x80,0x00,0x00]'\n"
               << "exit 0\n";
    }
    ASSERT_EQ(::chmod(fake_mc.c_str(), 0755), 0);

    peelf::LlvmMcAssemblerProvider mock_provider(fake_mc);
    ASSERT_TRUE(mock_provider.availability().ok()) << mock_provider.availability().detail;
    EXPECT_TRUE(mock_provider.supports_target(
        peelf::Architecture::RISCV64, peelf::Endianness::Little, true, false));

    auto rv_res = mock_provider.assemble(peelf::AssembleRequest{
        .architecture = peelf::Architecture::RISCV64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .base_address = 0x10000,
        .source_text = "addi a0, zero, 7\nret\n",
    });
    ASSERT_TRUE(rv_res.has_value()) << rv_res.error().message;
    const std::vector<std::uint8_t> expected_rv{
        0x13u, 0x05u, 0x70u, 0x00u, 0x67u, 0x80u, 0x00u, 0x00u};
    EXPECT_EQ(rv_res->bytes, expected_rv);
#endif
}

#if PEELF_ASMTK_AVAILABLE
TEST(AssemblyPatchPreviewTest, DetectsOverwrittenInstructionSlackAndSupportsNopPadding) {
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file((std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "hello.elf").string()));
    ASSERT_NE(model.image(), nullptr);
    const auto symbols = viewer::SymbolIndex::build(*model.image());
    const auto entry_off = model.image()->virtual_address_to_file_offset(model.image()->entry_point());
    ASSERT_TRUE(entry_off.has_value());

    // Find an instruction of length >= 2 bytes at or near entry point so a 1-byte `ret` splits it
    const auto entry_bytes = model.read_effective_bytes(*entry_off, 64);
    ASSERT_TRUE(entry_bytes.has_value());
    const auto dis = viewer::disassemble_patch_bytes(
        *entry_bytes,
        model.image()->entry_point(),
        model.image()->architecture(),
        model.image()->endianness(),
        false);
    ASSERT_FALSE(dis.empty());

    std::optional<std::uint64_t> multi_byte_off;
    std::size_t multi_byte_len = 0;
    for (const auto& inst : dis) {
        if (inst.bytes.size() >= 2u) {
            multi_byte_off = model.image()->virtual_address_to_file_offset(inst.address);
            multi_byte_len = inst.bytes.size();
            break;
        }
    }
    ASSERT_TRUE(multi_byte_off.has_value());

    auto unpadded = viewer::preview_assembly_patch(
        model, symbols, *multi_byte_off, "ret\n", false, false);
    ASSERT_TRUE(unpadded.has_value()) << unpadded.error().message;
    EXPECT_EQ(unpadded->replacement, std::vector<std::uint8_t>{0xC3u});
    ASSERT_EQ(unpadded->replacement_disassembly.size(), 1u);
    EXPECT_EQ(unpadded->replacement_disassembly[0].mnemonic, "ret");
    EXPECT_TRUE(unpadded->misaligns_instruction_boundary);
    EXPECT_EQ(unpadded->trailing_slack_bytes, multi_byte_len - 1u);
    EXPECT_FALSE(unpadded->boundary_warning.empty());

    auto padded = viewer::preview_assembly_patch(
        model, symbols, *multi_byte_off, "ret\n", false, true);
    ASSERT_TRUE(padded.has_value()) << padded.error().message;
    EXPECT_EQ(padded->replacement.size(), multi_byte_len);
    EXPECT_FALSE(padded->misaligns_instruction_boundary);
    EXPECT_EQ(padded->trailing_slack_bytes, 0u);

    ASSERT_TRUE(viewer::apply_preview(model, *padded).has_value());
    auto exported = model.export_patch_bundle("Entry early return", "Patched via AsmTK");
    ASSERT_TRUE(exported.has_value()) << exported.error().message;
    ASSERT_EQ(exported->entries.size(), 1u);
    ASSERT_TRUE(exported->entries[0].asm_source.has_value());
    EXPECT_EQ(*exported->entries[0].asm_source, "ret\n");
}
#endif

TEST(PatchBundleTest, JsonRoundTripConflictDetectionAndAtomicTransactionalRollback) {
    peelf_test::ScopedTempDir tmp("peelf_wu11");
    const std::filesystem::path copy_path = tmp / "sample.exe";
    std::filesystem::copy_file(fixture_pe64_path(), copy_path);

    auto img_a = peelf::PagedBinaryImage::open(copy_path);
    ASSERT_TRUE(img_a.has_value()) << img_a.error().message;

    // Stage two disjoint patches on img_a and export a reusable .pepatch.json bundle
    const std::vector<std::uint8_t> p1{0x90u, 0x90u};
    const std::vector<std::uint8_t> p2{0x31u, 0xC0u, 0xC3u};
    ASSERT_TRUE(img_a->apply_patch(0x80u, p1, "NOP header stub").has_value());
    ASSERT_TRUE(img_a->apply_patch(0x200u, p2, "Zero EAX + RET").has_value());

    auto exported = peelf::export_patch_bundle_from_image(
        *img_a, nullptr, "Test Bundle", "Two clean patches");
    ASSERT_TRUE(exported.has_value()) << exported.error().message;
    ASSERT_EQ(exported->entries.size(), 2u);
    exported->entries[1].asm_source = "xor eax, eax\nret";
    exported->target_format = peelf::Format::PE;
    exported->target_arch = peelf::Architecture::X86_64;

    const std::filesystem::path bundle_file = tmp / "test.pepatch.json";
    ASSERT_TRUE(peelf::save_patch_bundle_file(*exported, bundle_file).has_value());

    auto reloaded = peelf::load_patch_bundle_file(bundle_file);
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error().message;
    EXPECT_EQ(reloaded->schema_version, peelf::kPatchBundleSchemaVersion);
    EXPECT_EQ(reloaded->name, "Test Bundle");
    EXPECT_EQ(reloaded->description, "Two clean patches");
    EXPECT_EQ(reloaded->target_format, peelf::Format::PE);
    EXPECT_EQ(reloaded->target_arch, peelf::Architecture::X86_64);
    EXPECT_EQ(reloaded->expected_sha256, exported->expected_sha256);
    EXPECT_EQ(reloaded->expected_size, exported->expected_size);
    ASSERT_EQ(reloaded->entries.size(), 2u);
    EXPECT_EQ(reloaded->entries[1].asm_source, std::optional<std::string>("xor eax, eax\nret"));

    // Preview and apply onto a fresh unpatched PagedBinaryImage: single atomic undoable transaction!
    auto img_b = peelf::PagedBinaryImage::open(copy_path);
    ASSERT_TRUE(img_b.has_value());
    auto clean_preview = peelf::preview_patch_bundle(*reloaded, *img_b);
    ASSERT_TRUE(clean_preview.has_value()) << clean_preview.error().message;
    EXPECT_TRUE(clean_preview->can_apply);
    EXPECT_TRUE(clean_preview->sha256_matches);
    EXPECT_EQ(clean_preview->clean_count, 2u);
    EXPECT_EQ(clean_preview->conflict_count, 0u);

    ASSERT_TRUE(peelf::apply_patch_bundle(*reloaded, *img_b).has_value());
    EXPECT_EQ(img_b->changed_intervals().size(), 2u);
    // Undo once must revert BOTH entries because apply_patch_bundle used a single PatchTransaction!
    ASSERT_TRUE(img_b->undo().has_value());
    EXPECT_TRUE(img_b->changed_intervals().empty());

    // SHA-256 mismatch policy check:
    // Modify expected_sha256 while original_bytes still match -> rejected by default, allowed with override
    peelf::PatchBundle hash_diff = *reloaded;
    hash_diff.expected_sha256 = std::string(64u, '0');
    auto strict_prev = peelf::preview_patch_bundle(hash_diff, *img_b);
    ASSERT_TRUE(strict_prev.has_value());
    EXPECT_FALSE(strict_prev->can_apply);
    EXPECT_FALSE(strict_prev->sha256_matches);
    EXPECT_FALSE(peelf::apply_patch_bundle(hash_diff, *img_b).has_value());
    EXPECT_TRUE(img_b->changed_intervals().empty());

    auto override_prev = peelf::preview_patch_bundle(
        hash_diff, *img_b, {.allow_hash_mismatch_if_original_bytes_match = true});
    ASSERT_TRUE(override_prev.has_value());
    EXPECT_TRUE(override_prev->can_apply);
    EXPECT_TRUE(override_prev->sha256_mismatch_overridden);

    // Original-byte conflict on 2nd entry: even with hash override, preview & apply must reject
    // and leave `img_b` 100% unmodified (all-or-nothing rollback guarantee).
    peelf::PatchBundle byte_conflict = *reloaded;
    byte_conflict.entries[1].original_bytes[0] ^= 0xFFu;
    auto conflict_prev = peelf::preview_patch_bundle(
        byte_conflict, *img_b, {.allow_hash_mismatch_if_original_bytes_match = true});
    ASSERT_TRUE(conflict_prev.has_value());
    EXPECT_FALSE(conflict_prev->can_apply);
    EXPECT_EQ(conflict_prev->clean_count, 1u);
    EXPECT_EQ(conflict_prev->conflict_count, 1u);
    EXPECT_EQ(conflict_prev->entry_previews[0].status, peelf::PatchEntryConflictKind::Clean);
    EXPECT_EQ(conflict_prev->entry_previews[1].status,
              peelf::PatchEntryConflictKind::OriginalBytesMismatch);

    EXPECT_FALSE(peelf::apply_patch_bundle(
                     byte_conflict, *img_b, {.allow_hash_mismatch_if_original_bytes_match = true})
                     .has_value());
    EXPECT_TRUE(img_b->changed_intervals().empty());

    // Overlapping entries within a bundle are flagged and rejected
    peelf::PatchBundle overlapping = *reloaded;
    overlapping.entries[1].offset = overlapping.entries[0].offset + 1u;
    auto overlap_prev = peelf::preview_patch_bundle(overlapping, *img_b);
    ASSERT_TRUE(overlap_prev.has_value());
    EXPECT_FALSE(overlap_prev->can_apply);
    EXPECT_EQ(overlap_prev->entry_previews[0].status, peelf::PatchEntryConflictKind::OverlappingEntry);
}

TEST(PatchBundleTest, StrictlyRejectsReadOnlyLiveProcessSessions) {
    DummyReadOnlyLiveSession live_proc;
    peelf::PatchBundle bundle;
    bundle.name = "Live rejection check";
    bundle.expected_size = 0x1000;
    bundle.entries.push_back(peelf::PatchBundleEntry{
        .offset = 0,
        .original_bytes = {0x90u},
        .patched_bytes = {0xC3u},
    });

    // Core overloads reject live sessions immediately
    EXPECT_FALSE(peelf::apply_patch_bundle(bundle, live_proc).has_value());

    peelf_test::ScopedTempDir tmp("peelf_wu11");
    const std::filesystem::path copy_path = tmp / "sample.exe";
    std::filesystem::copy_file(fixture_pe64_path(), copy_path);
    auto img = peelf::PagedBinaryImage::open(copy_path);
    ASSERT_TRUE(img.has_value());
    EXPECT_FALSE(peelf::preview_patch_bundle(bundle, *img, {}, &live_proc).has_value());
    EXPECT_FALSE(peelf::apply_patch_bundle(bundle, *img, {}, &live_proc).has_value());

    // BinaryModel attached to a live session strictly rejects assembly preview & bundle export/preview/apply
    viewer::BinaryModel live_model;
    ASSERT_TRUE(live_model.attach_session(std::make_unique<DummyReadOnlyLiveSession>()).has_value());
    EXPECT_TRUE(live_model.is_live_process());
    EXPECT_FALSE(live_model.export_patch_bundle().has_value());
    EXPECT_FALSE(live_model.preview_patch_bundle(bundle).has_value());
    EXPECT_FALSE(live_model.apply_patch_bundle(bundle).has_value());
    EXPECT_FALSE(viewer::preview_assembly_patch(
                     live_model, live_model.symbol_index(), 0, "nop\n", false, false)
                     .has_value());
}

TEST(PatchBundleTest, DecodesSurrogatePairsValidatesExpectedSha256AndSweepsNestedOverlaps) {
    peelf_test::ScopedTempDir tmp("peelf_wu11");
    const std::filesystem::path copy_path = tmp / "sample.exe";
    std::filesystem::copy_file(fixture_pe64_path(), copy_path);
    auto img = peelf::PagedBinaryImage::open(copy_path);
    ASSERT_TRUE(img.has_value()) << img.error().message;

    auto base_orig = img->read_original(0u, 64u);
    ASSERT_TRUE(base_orig.has_value());

    // 1. Valid UTF-16 surrogate pairs (`\uD83D\uDE80` -> U+1F680, `\uD834\uDD1E` -> U+1D11E) decode to 4-byte UTF-8,
    //    while lone high/low surrogates are rejected cleanly.
    const std::string valid_sha(64u, 'a');
    const std::string surrogate_json = std::format(
        R"({{"schema_version":1,"name":"Rocket \uD83D\uDE80","description":"Clef \uD834\uDD1E","expected_sha256":"{}","expected_size":0,"entries":[{{"offset":0,"label":"Tag \uD83D\uDE80","original_bytes_hex":"4d5a","patched_bytes_hex":"9090"}}]}})",
        valid_sha);
    auto decoded = peelf::decode_patch_bundle_json(surrogate_json);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().message;
    EXPECT_EQ(decoded->name, "Rocket \xF0\x9F\x9A\x80");
    EXPECT_EQ(decoded->description, "Clef \xF0\x9D\x84\x9E");
    ASSERT_EQ(decoded->entries.size(), 1u);
    EXPECT_EQ(decoded->entries[0].label, "Tag \xF0\x9F\x9A\x80");

    // Lone high surrogate followed by non-surrogate
    const std::string lone_high_json = std::format(
        R"({{"schema_version":1,"name":"Bad \uD83D!","expected_sha256":"{}","expected_size":0,"entries":[]}})",
        valid_sha);
    EXPECT_FALSE(peelf::decode_patch_bundle_json(lone_high_json).has_value());

    // Lone high surrogate followed by BMP \u0041
    const std::string high_bmp_json = std::format(
        R"({{"schema_version":1,"name":"Bad \uD83D\u0041","expected_sha256":"{}","expected_size":0,"entries":[]}})",
        valid_sha);
    EXPECT_FALSE(peelf::decode_patch_bundle_json(high_bmp_json).has_value());

    // Unpaired low surrogate
    const std::string lone_low_json = std::format(
        R"({{"schema_version":1,"name":"Bad \uDE80","expected_sha256":"{}","expected_size":0,"entries":[]}})",
        valid_sha);
    EXPECT_FALSE(peelf::decode_patch_bundle_json(lone_low_json).has_value());

    // 2. Empty or malformed `expected_sha256` rejected in JSON AND rejected by preview/apply unless overridden.
    const std::string empty_sha_json =
        R"({"schema_version":1,"name":"EmptySha","expected_sha256":"","expected_size":0,"entries":[]})";
    EXPECT_FALSE(peelf::decode_patch_bundle_json(empty_sha_json).has_value());

    const std::string malformed_sha_json =
        R"({"schema_version":1,"name":"BadSha","expected_sha256":"not_64_hex_chars","expected_size":0,"entries":[]})";
    EXPECT_FALSE(peelf::decode_patch_bundle_json(malformed_sha_json).has_value());

    peelf::PatchBundle empty_sha_bundle = *decoded;
    empty_sha_bundle.expected_sha256.clear();
    empty_sha_bundle.entries[0].original_bytes = {(*base_orig)[0], (*base_orig)[1]};
    auto empty_prev = peelf::preview_patch_bundle(empty_sha_bundle, *img);
    ASSERT_TRUE(empty_prev.has_value()) << empty_prev.error().message;
    EXPECT_FALSE(empty_prev->sha256_matches);
    EXPECT_FALSE(empty_prev->can_apply);
    EXPECT_FALSE(peelf::apply_patch_bundle(empty_sha_bundle, *img).has_value());

    auto override_empty_prev = peelf::preview_patch_bundle(
        empty_sha_bundle, *img, {.allow_hash_mismatch_if_original_bytes_match = true});
    ASSERT_TRUE(override_empty_prev.has_value());
    EXPECT_TRUE(override_empty_prev->can_apply);
    EXPECT_TRUE(override_empty_prev->sha256_mismatch_overridden);

    // 3. O(N log N) sorted sweep catches nested + non-adjacent overlaps ([0, 16) enclosing [2, 4) and [8, 12))
    //    AND accepts large reverse-sorted disjoint entry sets cleanly.
    peelf::PatchBundle nested_overlap;
    nested_overlap.name = "NestedOverlap";
    nested_overlap.expected_sha256 = empty_prev->actual_sha256;
    nested_overlap.expected_size = img->size();
    nested_overlap.entries = {
        peelf::PatchBundleEntry{
            .offset = 8u,
            .original_bytes = std::vector<std::uint8_t>(base_orig->begin() + 8, base_orig->begin() + 12),
            .patched_bytes = {0x90u, 0x90u, 0x90u, 0x90u},
        },
        peelf::PatchBundleEntry{
            .offset = 0u,
            .original_bytes = std::vector<std::uint8_t>(base_orig->begin(), base_orig->begin() + 16),
            .patched_bytes = std::vector<std::uint8_t>(16u, 0xCCu),
        },
        peelf::PatchBundleEntry{
            .offset = 2u,
            .original_bytes = std::vector<std::uint8_t>(base_orig->begin() + 2, base_orig->begin() + 4),
            .patched_bytes = {0x90u, 0x90u},
        },
    };
    auto nested_prev = peelf::preview_patch_bundle(nested_overlap, *img);
    ASSERT_TRUE(nested_prev.has_value()) << nested_prev.error().message;
    EXPECT_FALSE(nested_prev->can_apply);
    EXPECT_EQ(nested_prev->conflict_count, 3u);
    for (std::size_t i = 0; i < 3u; ++i) {
        EXPECT_EQ(nested_prev->entry_previews[i].status,
                  peelf::PatchEntryConflictKind::OverlappingEntry)
            << "entry " << i;
    }

    const std::size_t max_disjoint = static_cast<std::size_t>(std::min<std::uint64_t>(256u, img->size() / 2u));
    auto full_prefix = img->read_original(0u, static_cast<std::uint64_t>(max_disjoint * 2u));
    ASSERT_TRUE(full_prefix.has_value());
    peelf::PatchBundle disjoint;
    disjoint.name = "DisjointSweep";
    disjoint.expected_sha256 = empty_prev->actual_sha256;
    disjoint.expected_size = img->size();
    for (std::size_t k = max_disjoint; k-- > 0u;) {
        const std::size_t off = k * 2u;
        const std::uint8_t orig = (*full_prefix)[off];
        disjoint.entries.push_back(peelf::PatchBundleEntry{
            .offset = static_cast<std::uint64_t>(off),
            .original_bytes = {orig},
            .patched_bytes = {static_cast<std::uint8_t>(orig ^ 0xFFu)},
        });
    }
    auto disjoint_prev = peelf::preview_patch_bundle(disjoint, *img);
    ASSERT_TRUE(disjoint_prev.has_value()) << disjoint_prev.error().message;
    EXPECT_TRUE(disjoint_prev->can_apply);
    EXPECT_EQ(disjoint_prev->clean_count, max_disjoint);
    EXPECT_EQ(disjoint_prev->conflict_count, 0u);
}

