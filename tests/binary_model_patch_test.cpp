#include "model/binary_model.hpp"
#include "navigation/byte_range.hpp"
#include "disasm/disassembler.hpp"

#include <gtest/gtest.h>

#include <cstdint>
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
