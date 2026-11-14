#include "model/binary_model.hpp"
#include "navigation/byte_range.hpp"
#include "disasm/disassembler.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <span>
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

struct TemporaryExport {
    std::filesystem::path path;
    ~TemporaryExport() { std::error_code error; std::filesystem::remove(path, error); }
};
}

TEST_P(InstructionPatchRoundTrip, DecodeUndoRedoExportReopenPreservesOriginal) {
    const auto& test = GetParam();
    const auto source = fixture_path(test.fixture);
    TemporaryExport output{std::filesystem::temp_directory_path() /
        (std::string("peelf-roundtrip-") + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + test.fixture)};
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
    ASSERT_TRUE(model.save_patched_as(output.path));
    EXPECT_FALSE(model.save_patched_as(output.path));
    viewer::BinaryModel reopened;
    ASSERT_TRUE(reopened.load_file(output.path.string()));
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
    std::copy(test.replacement.begin(), test.replacement.end(), expected_file.begin() + *offset);
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
    ASSERT_NE(model.pe(), nullptr);
    ASSERT_NE(model.image(), nullptr);
    const auto entry = model.image()->entry_point();
    const auto offset = model.image()->virtual_address_to_file_offset(entry);
    ASSERT_TRUE(offset);
    ASSERT_NE(model.pe()->data_at_offset(static_cast<std::size_t>(*offset)), nullptr);
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
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_GE(model.bytes().size(), 8u);

    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "peelf_binary_model_patched_output.bin";
    std::filesystem::remove(output_path);

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
