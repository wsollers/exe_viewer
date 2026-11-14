#include <gtest/gtest.h>
#include "ui/theme_resource.hpp"

TEST(ThemeResource, ReadsColorsMetricsAndLastOverride) {
    std::istringstream input("  # comment\nText 1 1 1 1\nText .2 .3 .4 1\nmetric.FrameRounding 4\n");
    const auto theme = viewer::ui::read_theme(input);
    ASSERT_EQ(theme.colors.size(), 1u);
    EXPECT_FLOAT_EQ(theme.colors.at("Text")[0], .2f);
    EXPECT_FLOAT_EQ(theme.metrics.at("FrameRounding"), 4.f);
}

TEST(ThemeResource, RejectsMalformedAndOutOfRangeValues) {
    std::istringstream input("Bad 2 0 0 1\nMissing 1 1\nExtra 1 1 1 1 junk\nNaN nan 0 0 1\nmetric.Negative -1\nmetric.Huge 100\nmetric.Extra 4 junk\nGood 0 0 0 1\n");
    const auto theme = viewer::ui::read_theme(input);
    EXPECT_EQ(theme.colors.size(), 1u);
    EXPECT_TRUE(theme.colors.contains("Good"));
    EXPECT_TRUE(theme.metrics.empty());
}

TEST(ThemeResource, EmptyResourceKeepsDefaultsAvailable) {
    std::istringstream input;
    const auto theme = viewer::ui::read_theme(input);
    EXPECT_TRUE(theme.colors.empty());
    EXPECT_TRUE(theme.metrics.empty());
}
