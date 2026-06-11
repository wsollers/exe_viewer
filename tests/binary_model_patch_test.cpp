#include "model/binary_model.hpp"

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

TEST(BinaryModelPatching, LoadsEditableImageForStaticElf) {
    viewer::BinaryModel model;

    ASSERT_TRUE(model.load_file(fixture_path("hello.elf").string()));
    ASSERT_NE(model.editable_image(), nullptr);
    EXPECT_FALSE(model.editable_image()->dirty());
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
