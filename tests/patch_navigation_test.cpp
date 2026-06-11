#include "navigation/viewer_navigation.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(PatchNavigation, BuildsHexSelectionFromPatchInterval) {
    const peelf::PatchInterval patch{
        .offset = 0x1234,
        .original = std::vector<std::uint8_t>{0x01, 0x02},
        .patched = std::vector<std::uint8_t>{0x90, 0x90},
    };

    const viewer::ViewerSelection selection = viewer::selection_from_patch_interval(patch, 7);

    EXPECT_EQ(selection.kind, viewer::SelectionKind::Patch);
    ASSERT_TRUE(selection.file_offset.has_value());
    EXPECT_EQ(*selection.file_offset, 0x1234u);
    EXPECT_FALSE(selection.virtual_address.has_value());
    EXPECT_EQ(selection.size, 2u);
    EXPECT_EQ(selection.object_index, 7u);
    EXPECT_EQ(selection.preferred_view, viewer::PreferredView::Hex);
}
