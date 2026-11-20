#include "model/image_delay_load_descriptor.hpp"
#include "model/pe_characteristics.hpp"
#include "model/pe_machine_types.hpp"
#include "model/pe_optional_image.hpp"
#include "model/pe_subsystem.hpp"
#include "model/section_header_characteristics.hpp"

#include "model/binary_model.hpp"
#include "navigation/byte_range.hpp"
#include "disasm/disassembler.hpp"
#include "peelf/patch_bundle.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

[[nodiscard]] std::filesystem::path fixture_path(const char* name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

} // namespace

namespace {
struct InstructionPatchCase {
    const char* fixture;
    viewer::Architecture architecture;
    viewer::Endianness endian;
    std::vector<std::uint8_t> replacement;
    const char* mnemonic;
};

void PrintTo(const InstructionPatchCase& value, std::ostream* stream) {
    *stream << value.fixture;
}

class InstructionPatchRoundTrip : public testing::TestWithParam<InstructionPatchCase> {};
}

TEST_P(InstructionPatchRoundTrip, DecodeUndoRedoExportReopenPreservesOriginal) {
    const auto& test = GetParam();
    const auto source = fixture_path(test.fixture);
    peelf_test::ScopedTempDir temp_dir("peelf_roundtrip");
    const std::filesystem::path output_path = temp_dir / test.fixture;
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(source.string()));
    const auto original_file = model.bytes();
    ASSERT_NE(model.image(), nullptr);
    const auto address = model.image()->entry_point();
    const auto offset = model.image()->virtual_address_to_file_offset(address);
    ASSERT_TRUE(offset);
    const auto original = model.read_effective_bytes(*offset, test.replacement.size());
    ASSERT_TRUE(original);
    ASSERT_NE(*original, test.replacement);
    viewer::Disassembler decoder;
    ASSERT_TRUE(decoder.init(test.architecture, test.endian)) << decoder.get_error();
    const auto decode = [&](const viewer::BinaryModel& image) {
        const auto bytes = image.read_effective_bytes(*offset, test.replacement.size());
        return bytes ? decoder.disassemble(bytes->data(), bytes->size(), address)
                     : std::vector<viewer::Instruction>{};
    };
    const auto original_instructions = decode(model);
    const auto revision = model.edit_revision();
    ASSERT_TRUE(model.apply_patch_bytes(*offset, test.replacement, "instruction replacement"));
    EXPECT_GT(model.edit_revision(), revision);
    auto patched = decode(model);
    ASSERT_FALSE(patched.empty());
    EXPECT_EQ(patched.front().mnemonic, test.mnemonic);
    EXPECT_EQ(patched.front().bytes, test.replacement);
    EXPECT_EQ(patched.front().address, address);
    ASSERT_TRUE(model.undo_patch());
    const auto undone_bytes = model.read_effective_bytes(*offset, original->size());
    ASSERT_TRUE(undone_bytes);
    EXPECT_EQ(*undone_bytes, *original);
    EXPECT_TRUE(model.changed_intervals().empty());
    const auto undone = decode(model);
    ASSERT_EQ(undone.size(), original_instructions.size());
    if (!undone.empty()) EXPECT_EQ(undone.front().mnemonic, original_instructions.front().mnemonic);
    ASSERT_TRUE(model.redo_patch());
    ASSERT_FALSE(decode(model).empty());
    EXPECT_EQ(decode(model).front().mnemonic, test.mnemonic);
    EXPECT_FALSE(model.save_patched_as(source));
    ASSERT_TRUE(model.save_patched_as(output_path));
    EXPECT_FALSE(model.save_patched_as(output_path));
    viewer::BinaryModel reopened;
    ASSERT_TRUE(reopened.load_file(output_path.string()));
    ASSERT_NE(reopened.image(), nullptr);
    EXPECT_EQ(reopened.image()->architecture(), model.image()->architecture());
    EXPECT_EQ(reopened.image()->entry_point(), address);
    EXPECT_EQ(reopened.image()->virtual_address_to_file_offset(address), offset);
    EXPECT_TRUE(reopened.changed_intervals().empty());
    EXPECT_FALSE(reopened.editable_image()->can_undo());
    const auto exported = decode(reopened);
    ASSERT_FALSE(exported.empty());
    EXPECT_EQ(exported.front().mnemonic, test.mnemonic);
    EXPECT_EQ(exported.front().bytes, test.replacement);
    auto expected_file = original_file;
    std::copy(test.replacement.begin(),
              test.replacement.end(),
              expected_file.begin() + static_cast<std::ptrdiff_t>(*offset));
    EXPECT_EQ(reopened.bytes(), expected_file);
    EXPECT_EQ(model.bytes(), original_file);
    viewer::BinaryModel source_reopened;
    ASSERT_TRUE(source_reopened.load_file(source.string()));
    EXPECT_EQ(source_reopened.bytes(), original_file);
}

using enum viewer::Architecture;
using enum viewer::Endianness;
INSTANTIATE_TEST_SUITE_P(AllCpuFamilies, InstructionPatchRoundTrip, testing::Values(
    InstructionPatchCase{"known-linux-x64.elf", X86_64, Little, {0xCC}, "int3"},
    InstructionPatchCase{"known-linux-x86-elf32-le.elf", X86_32, Little, {0xCC}, "int3"},
    InstructionPatchCase{"known-win-x86.exe", X86_32, Little, {0xC3}, "ret"},
    InstructionPatchCase{"known-win-x64.exe", X86_64, Little, {0xC3}, "ret"},
    InstructionPatchCase{"known-linux-arm-elf32-le.elf", ARM32, Little, {0x1E,0xFF,0x2F,0xE1}, "bx"},
    InstructionPatchCase{"known-linux-arm-elf32-be.elf", ARM32, Big, {0xE1,0x2F,0xFF,0x1E}, "bx"},
    InstructionPatchCase{"known-linux-arm64.elf", ARM64, Little, {0x00,0x00,0x20,0xD4}, "brk"},
    InstructionPatchCase{"known-linux-arm64-elf64-be.elf", ARM64, Big, {0x00,0x00,0x20,0xD4}, "brk"},
    InstructionPatchCase{"known-linux-riscv32-elf32-le.elf", RISCV32, Little, {0x73,0x00,0x10,0x00}, "ebreak"},
    InstructionPatchCase{"known-linux-riscv32-elf32-be.elf", RISCV32, Big, {0x73,0x00,0x10,0x00}, "ebreak"},
    InstructionPatchCase{"known-linux-riscv64.elf", RISCV64, Little, {0x73,0x00,0x10,0x00}, "ebreak"},
    InstructionPatchCase{"known-linux-riscv64-elf64-be.elf", RISCV64, Big, {0x73,0x00,0x10,0x00}, "ebreak"},
    InstructionPatchCase{"known-linux-mips-elf32-be.elf", MIPS32, Big, {0x00,0x00,0x00,0x0D}, "break"},
    InstructionPatchCase{"known-linux-mips64-elf64-be.elf", MIPS64, Big, {0x00,0x00,0x00,0x0D}, "break"},
    InstructionPatchCase{"known-linux-ppc-elf32-be.elf", PowerPC32, Big, {0x4E,0x80,0x00,0x20}, "blr"},
    InstructionPatchCase{"known-linux-ppc64-elf64-be.elf", PowerPC64, Big, {0x4E,0x80,0x00,0x20}, "blr"}
));

#if defined(_WIN32) && defined(PEELF_VIEWER_DEBUG_EXE)
TEST(BinaryModelPatching, ViewerExecutableEntryBytesAreReadableAndDecode) {
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(PEELF_VIEWER_DEBUG_EXE));
    ASSERT_NE(model.image(), nullptr);
    const auto entry = model.image()->entry_point();
    const auto offset = model.image()->virtual_address_to_file_offset(entry);
    ASSERT_TRUE(offset);
    const auto bytes = model.read_effective_bytes(*offset, 16);
    ASSERT_TRUE(bytes);
    viewer::Disassembler decoder;
    ASSERT_TRUE(decoder.init(viewer::Architecture::X86_64));
    const auto instructions = decoder.disassemble(bytes->data(), bytes->size(), entry);
    ASSERT_FALSE(instructions.empty());
    EXPECT_EQ(instructions.front().address, entry);
}
#endif

TEST(HexSelection, IncludesBothEndpointsInEitherDirectionAndRejectsInvalidOffsets) {
    const auto forward = viewer::selected_byte_range(15, 17, 32);
    const auto backward = viewer::selected_byte_range(17, 15, 32);
    ASSERT_TRUE(forward);
    ASSERT_TRUE(backward);
    EXPECT_EQ(forward->offset, 15u);
    EXPECT_EQ(forward->size, 3u);
    EXPECT_EQ(backward->offset, forward->offset);
    EXPECT_EQ(backward->size, forward->size);
    EXPECT_FALSE(viewer::selected_byte_range(0, 0, 0));
    EXPECT_FALSE(viewer::selected_byte_range(0, 32, 32));
    const auto last = viewer::selected_byte_range(31, 31, 32);
    ASSERT_TRUE(last);
    EXPECT_EQ(last->size, 1u);
}

TEST(BinaryModelPatching, RejectsReplacementPastEndWithoutChangingBytes) {
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_FALSE(model.bytes().empty());
    const auto offset = model.bytes().size() - 1;
    const std::vector<std::uint8_t> replacement{0xAA, 0xBB};
    EXPECT_FALSE(model.apply_patch_bytes(offset, replacement, "invalid hex edit").has_value());
    EXPECT_TRUE(model.changed_intervals().empty());
    const auto effective = model.read_effective_bytes(offset, 1);
    ASSERT_TRUE(effective.has_value());
    EXPECT_EQ(effective->front(), model.bytes().back());
}

TEST(BinaryModelPatching, LoadsEditableImageForStaticElf) {
    viewer::BinaryModel model;

    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_NE(model.editable_image(), nullptr);
    EXPECT_FALSE(model.editable_image()->dirty());
}

TEST(BinaryModelPatching, RevertingRangeIsUndoableAndTracksRevision) {
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    const auto revision = model.edit_revision();
    EXPECT_FALSE(model.editable_image()->can_undo());
    const std::vector<std::uint8_t> replacement{0xAA, 0xBB};
    ASSERT_TRUE(model.apply_patch_bytes(4, replacement, "edit"));
    EXPECT_GT(model.edit_revision(), revision);
    EXPECT_TRUE(model.editable_image()->can_undo());
    const auto patches = model.changed_intervals();
    ASSERT_EQ(patches.size(), 1u);
    ASSERT_TRUE(model.apply_patch_bytes(patches.front().offset, patches.front().original, "revert"));
    EXPECT_TRUE(model.changed_intervals().empty());
    const auto reverted_revision = model.edit_revision();
    ASSERT_TRUE(model.undo_patch());
    EXPECT_GT(model.edit_revision(), reverted_revision);
    EXPECT_TRUE(model.editable_image()->can_redo());
    const auto restored = model.read_effective_bytes(4, 2);
    ASSERT_TRUE(restored);
    EXPECT_EQ(*restored, replacement);
    ASSERT_TRUE(model.redo_patch());
    EXPECT_TRUE(model.changed_intervals().empty());
}

TEST(BinaryModelPatching, AppliesPatchWithoutMutatingOriginalBytesVector) {
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_GE(model.bytes().size(), 8u);

    const std::uint8_t original = model.bytes()[4];
    const std::vector<std::uint8_t> replacement{0xAA, 0xBB, 0xCC};
    ASSERT_TRUE(model.apply_patch_bytes(4, replacement, "test patch").has_value());

    auto effective = model.read_effective_bytes(4, replacement.size());
    ASSERT_TRUE(effective.has_value()) << effective.error().message;
    EXPECT_EQ(*effective, replacement);
    EXPECT_EQ(model.bytes()[4], original);

    const auto intervals = model.changed_intervals();
    ASSERT_EQ(intervals.size(), 1u);
    EXPECT_EQ(intervals[0].offset, 4u);

    ASSERT_TRUE(model.undo_patch().has_value());
    auto undone = model.read_effective_bytes(4, replacement.size());
    ASSERT_TRUE(undone.has_value()) << undone.error().message;
    EXPECT_EQ((*undone)[0], original);

    ASSERT_TRUE(model.redo_patch().has_value());
    auto redone = model.read_effective_bytes(4, replacement.size());
    ASSERT_TRUE(redone.has_value()) << redone.error().message;
    EXPECT_EQ(*redone, replacement);
}

TEST(BinaryModelPatching, SavesPatchedImageToNewFile) {
    peelf_test::ScopedTempDir temp_dir("peelf_binary_model_patch");
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_GE(model.bytes().size(), 8u);

    const std::filesystem::path output_path = temp_dir / "peelf_binary_model_patched_output.bin";

    const std::vector<std::uint8_t> replacement{0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_TRUE(model.apply_patch_bytes(4, replacement, "model export patch").has_value());
    ASSERT_TRUE(model.save_patched_as(output_path).has_value());

    std::ifstream file(output_path, std::ios::binary);
    ASSERT_TRUE(file.good());
    std::vector<std::uint8_t> exported(std::istreambuf_iterator<char>(file), {});
    ASSERT_GE(exported.size(), 8u);
    EXPECT_EQ(std::vector<std::uint8_t>(exported.begin() + 4, exported.begin() + 8), replacement);
    EXPECT_NE(std::vector<std::uint8_t>(model.bytes().begin() + 4, model.bytes().begin() + 8), replacement);
}

TEST(PeModelHeaders, SelfContainedConstexprLookupsAndFlags) {
    static_assert(sizeof(pe::ImageDelayLoadDescriptor) == 32u);
    static_assert(pe::get_machine_name(pe::machine::AMD64) != nullptr);
    static_assert(pe::optional_image::magic::is_64bit(pe::optional_image::magic::PE32PLUS));
    static_assert(pe::get_subsystem_info(pe::subsystem::WINDOWS_CUI) != nullptr);
    static_assert(pe::get_section_alignment_bytes(pe::section_flags::ALIGN_16BYTES) == 16u);
    static_assert(pe::is_section_executable(pe::section_flags::MEM_EXECUTE));

    pe::ImageDelayLoadDescriptor desc{};
    desc.Attributes = pe::delay_load_attributes::RVA_BASED;
    desc.DllNameRVA = 0x2000u;
    EXPECT_TRUE(pe::is_valid_delay_load_descriptor(desc));
    EXPECT_TRUE(pe::is_rva_based(desc));

    EXPECT_STREQ(pe::get_machine_name(pe::machine::AMD64), "x64 (AMD64)");
    EXPECT_STREQ(pe::optional_image::magic::get_magic_name(pe::optional_image::magic::PE32PLUS), "PE32+");
    EXPECT_STREQ(pe::get_subsystem_name(pe::subsystem::WINDOWS_CUI), "WINDOWS_CUI");

    const std::string file_flags = pe::get_characteristics_string(
        pe::characteristics::EXECUTABLE_IMAGE | pe::characteristics::LARGE_ADDRESS_AWARE);
    EXPECT_EQ(file_flags, "EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE");

    const std::string dll_flags = pe::optional_image::get_dll_characteristics_string(
        pe::optional_image::dll_characteristics::DYNAMIC_BASE |
        pe::optional_image::dll_characteristics::NX_COMPAT);
    EXPECT_EQ(dll_flags, "DYNAMIC_BASE | NX_COMPAT");

    const std::string sec_desc = pe::get_section_flags_string(
        pe::section_flags::CNT_CODE | pe::section_flags::MEM_EXECUTE |
        pe::section_flags::MEM_READ | pe::section_flags::ALIGN_16BYTES);
    EXPECT_EQ(sec_desc, "CNT_CODE | MEM_EXECUTE | MEM_READ | ALIGN_16BYTES");
    EXPECT_EQ(pe::get_section_flags_string(0u), "NONE");
}

TEST(BinaryModelPatching, NonAllocatingNoexceptIsPatchedTracksApplyUndoRedo) {
    static_assert(noexcept(std::declval<const peelf::PagedBinaryImage&>().is_patched(0u)));
    static_assert(noexcept(std::declval<const viewer::BinaryModel&>().is_byte_patched(0u)));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_NE(model.editable_image(), nullptr);
    ASSERT_GE(model.bytes().size(), 12u);

    EXPECT_FALSE(model.is_byte_patched(4u));
    EXPECT_FALSE(model.editable_image()->is_patched(4u));

    const std::uint8_t orig4 = model.bytes()[4];
    const std::vector<std::uint8_t> replacement{static_cast<std::uint8_t>(orig4 ^ 0xFFu), 0xABu};
    ASSERT_TRUE(model.apply_patch_bytes(4u, replacement, "check is_patched").has_value());

    EXPECT_FALSE(model.is_byte_patched(3u));
    EXPECT_TRUE(model.is_byte_patched(4u));
    EXPECT_EQ(model.editable_image()->is_patched(5u), model.bytes()[5] != 0xABu);
    EXPECT_FALSE(model.is_byte_patched(6u));
    EXPECT_FALSE(model.is_byte_patched(model.bytes().size() + 100u));

    ASSERT_TRUE(model.undo_patch().has_value());
    EXPECT_FALSE(model.is_byte_patched(4u));
    EXPECT_FALSE(model.editable_image()->is_patched(4u));

    ASSERT_TRUE(model.redo_patch().has_value());
    EXPECT_TRUE(model.is_byte_patched(4u));
    EXPECT_TRUE(model.editable_image()->is_patched(4u));
}

TEST(BinaryModelPatching, PreservesPatchNotesAndTimestampsAcrossJsonBundleAndBackwardCompat) {
    peelf_test::ScopedTempDir temp_dir("peelf_bundle_meta");
    const std::filesystem::path elf_src = fixture_path("hello.elf");

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(elf_src.string()));
    ASSERT_GE(model.bytes().size(), 16u);

    const std::vector<std::uint8_t> repl{
        static_cast<std::uint8_t>(model.bytes()[8] ^ 0x55u),
        static_cast<std::uint8_t>(model.bytes()[9] ^ 0xAAu),
    };
    ASSERT_TRUE(model.apply_patch_bytes(8u, repl, "patch header", "analyst ticket #43").has_value());

    const auto ivs = model.changed_intervals();
    ASSERT_EQ(ivs.size(), 1u);
    EXPECT_EQ(ivs[0].note, "analyst ticket #43");
    EXPECT_GT(ivs[0].timestamp_unix_ms, 0);

    const std::filesystem::path bundle_path = temp_dir / "meta.pepatch.json";
    const auto exported = model.export_patch_bundle("meta_bundle", "bundle note");
    ASSERT_TRUE(exported.has_value()) << exported.error().message;
    ASSERT_TRUE(peelf::save_patch_bundle_file(*exported, bundle_path).has_value());

    const auto loaded_bundle = peelf::load_patch_bundle_file(bundle_path);
    ASSERT_TRUE(loaded_bundle.has_value()) << loaded_bundle.error().message;
    EXPECT_EQ(loaded_bundle->description, "bundle note");
    ASSERT_EQ(loaded_bundle->entries.size(), 1u);
    EXPECT_EQ(loaded_bundle->entries[0].note, "analyst ticket #43");
    EXPECT_EQ(loaded_bundle->entries[0].timestamp_unix_ms, ivs[0].timestamp_unix_ms);

    // Apply onto a clean BinaryModel and verify note survives into PagedBinaryImage history!
    viewer::BinaryModel clean_model;
    ASSERT_TRUE(clean_model.load_file(elf_src.string()));
    const auto applied = clean_model.apply_patch_bundle(*loaded_bundle);
    ASSERT_TRUE(applied.has_value()) << applied.error().message;
    ASSERT_EQ(clean_model.changed_intervals().size(), 1u);
    EXPECT_EQ(clean_model.changed_intervals()[0].note, "analyst ticket #43");

    // Legacy v1 JSON without `note` or `timestamp_unix_ms` must still parse cleanly.
    const std::string legacy_json = R"({
  "schema_version": 1,
  "name": "legacy",
  "description": "",
  "target_format": "ELF",
  "target_arch": "x86_64",
  "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "expected_size": 64,
  "entries": [
    {
      "offset": 8,
      "virtual_address": null,
      "label": "legacy entry",
      "asm_source": null,
      "original_bytes_hex": "0000",
      "patched_bytes_hex": "1122"
    }
  ]
})";
    const auto parsed_legacy = peelf::decode_patch_bundle_json(legacy_json);
    ASSERT_TRUE(parsed_legacy.has_value()) << parsed_legacy.error().message;
    ASSERT_EQ(parsed_legacy->entries.size(), 1u);
    EXPECT_EQ(parsed_legacy->entries[0].label, "legacy entry");
    EXPECT_TRUE(parsed_legacy->entries[0].note.empty());
    EXPECT_EQ(parsed_legacy->entries[0].timestamp_unix_ms, 0);
}

TEST(IpsPatchExport, EncodesAndDecodesIpsAndIps32WithEdgeOffsetsChunkingAndRle) {
    peelf_test::ScopedTempDir temp_dir("peelf_ips_export");

    // 1. Standard 24-bit IPS ("PATCH"..."EOF") with span > 0xFFFF (70,000 bytes -> split & coalesced)
    //    plus chunk-boundary avoidance when a >64 KiB span would split right onto 0x454F46 ("EOF")!
    std::vector<std::uint8_t> big_payload(70'000u);
    for (std::size_t i = 0u; i < big_payload.size(); ++i) {
        big_payload[i] = static_cast<std::uint8_t>((i * 7u + 3u) & 0xFFu);
    }
    const std::array<peelf::PatchInterval, 2> ips24_intervals{{
        peelf::PatchInterval{
            .offset = 0x100u,
            .original = std::vector<std::uint8_t>(big_payload.size(), 0u),
            .patched = big_payload,
        },
        peelf::PatchInterval{
            .offset = 0x444F47u, // + 0xFFFF == 0x454F46 ("EOF"), so chunker trims chunk 1 to 0xFFFE!
            .original = std::vector<std::uint8_t>(70'000u, 0u),
            .patched = big_payload,
        },
    }};

    const auto encoded_ips = peelf::encode_ips_patch(ips24_intervals);
    ASSERT_TRUE(encoded_ips.has_value()) << encoded_ips.error().message;
    ASSERT_GE(encoded_ips->size(), 8u);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(encoded_ips->data()), 5u), "PATCH");

    const std::filesystem::path ips_file = temp_dir / "out.ips";
    ASSERT_TRUE(peelf::save_ips_patch_file(ips24_intervals, ips_file).has_value());
    const auto decoded_ips = peelf::load_ips_patch_file(ips_file);
    ASSERT_TRUE(decoded_ips.has_value()) << decoded_ips.error().message;
    ASSERT_EQ(decoded_ips->size(), 2u);
    EXPECT_EQ((*decoded_ips)[0].offset, 0x100u);
    EXPECT_EQ((*decoded_ips)[0].patched, big_payload);
    EXPECT_EQ((*decoded_ips)[1].offset, 0x444F47u);
    EXPECT_EQ((*decoded_ips)[1].patched, big_payload);

    // Exact 0x454F46 ("EOF") start offset promotes cleanly to IPS32 so offset 0x454F46 is preserved bit-exact!
    const std::array<peelf::PatchInterval, 1> eof_offset_iv{{
        peelf::PatchInterval{
            .offset = 0x454F46u,
            .original = {0x00u, 0x00u, 0x00u},
            .patched = {0x90u, 0x90u, 0xC3u},
        },
    }};
    const auto eof_encoded = peelf::encode_ips_patch(eof_offset_iv);
    ASSERT_TRUE(eof_encoded.has_value()) << eof_encoded.error().message;
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(eof_encoded->data()), 5u), "IPS32");
    const auto eof_decoded = peelf::decode_ips_patch(*eof_encoded);
    ASSERT_TRUE(eof_decoded.has_value()) << eof_decoded.error().message;
    ASSERT_EQ(eof_decoded->size(), 1u);
    EXPECT_EQ((*eof_decoded)[0].offset, 0x454F46u);
    EXPECT_EQ((*eof_decoded)[0].patched, (std::vector<std::uint8_t>{0x90u, 0x90u, 0xC3u}));

    // 2. Verify RLE record decoding in standard IPS ("PATCH" + offset 0x000200 + size 0 + rle_len 5 + val 0xCC + "EOF").
    const std::array<std::uint8_t, 17> rle_ips = {
        'P', 'A', 'T', 'C', 'H',
        0x00u, 0x02u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x05u,
        0xCCu,
        'E', 'O', 'F', 0x00u // truncated trailing byte must fail cleanly if malformed
    };
    EXPECT_FALSE(peelf::decode_ips_patch(rle_ips).has_value());
    const auto valid_rle = peelf::decode_ips_patch(std::span<const std::uint8_t>(rle_ips.data(), 16u));
    ASSERT_TRUE(valid_rle.has_value()) << valid_rle.error().message;
    ASSERT_EQ(valid_rle->size(), 1u);
    EXPECT_EQ((*valid_rle)[0].offset, 0x200u);
    EXPECT_EQ((*valid_rle)[0].patched, (std::vector<std::uint8_t>(5u, 0xCCu)));

    // 3. Automatic IPS32 promotion when offset >= 16 MiB (including 0x45454F46 "EEOF" trailer disambiguation!).
    const std::array<peelf::PatchInterval, 2> ips32_intervals{{
        peelf::PatchInterval{
            .offset = 0x0100'0020ULL, // > 16 MiB
            .original = {0x01u, 0x02u},
            .patched = {0xFEu, 0xEDu},
        },
        peelf::PatchInterval{
            .offset = 0x4545'4F46ULL, // ASCII "EEOF"!
            .original = {0x11u, 0x22u},
            .patched = {0xAAu, 0xBBu},
        },
    }};
    const auto encoded_ips32 = peelf::encode_ips_patch(ips32_intervals);
    ASSERT_TRUE(encoded_ips32.has_value()) << encoded_ips32.error().message;
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(encoded_ips32->data()), 5u), "IPS32");

    const auto decoded_ips32 = peelf::decode_ips_patch(*encoded_ips32);
    ASSERT_TRUE(decoded_ips32.has_value()) << decoded_ips32.error().message;
    ASSERT_EQ(decoded_ips32->size(), 2u);
    EXPECT_EQ((*decoded_ips32)[0].offset, 0x0100'0020ULL);
    EXPECT_EQ((*decoded_ips32)[0].patched, (std::vector<std::uint8_t>{0xFEu, 0xEDu}));
    EXPECT_EQ((*decoded_ips32)[1].offset, 0x4545'4F46ULL);
    EXPECT_EQ((*decoded_ips32)[1].patched, (std::vector<std::uint8_t>{0xAAu, 0xBBu}));

    // 4. Offsets >= 4 GiB must fail cleanly.
    const std::array<peelf::PatchInterval, 1> overflow_iv{{
        peelf::PatchInterval{
            .offset = 0x1'0000'0000ULL,
            .original = {0x00u},
            .patched = {0x90u},
        },
    }};
    const auto overflow_res = peelf::encode_ips_patch(overflow_iv);
    ASSERT_FALSE(overflow_res.has_value());
    EXPECT_FALSE(overflow_res.error().message.empty());
}

