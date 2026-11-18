#include "model/recent_binaries.hpp"
#include "test_temp_dir.hpp"
#include <gtest/gtest.h>

TEST(RecentBinaries, KeepsFiveMostRecentAndPromotesDuplicates) {
    viewer::RecentBinaries history;
    for (int i=0;i<7;++i) history.remember(std::filesystem::path("binary "+std::to_string(i)+".exe"));
    ASSERT_EQ(history.paths().size(),5);
    EXPECT_EQ(history.paths().front().filename(),"binary 6.exe");
    history.remember("./binary 3.exe");
    ASSERT_EQ(history.paths().size(),5);
    EXPECT_EQ(history.paths().front().filename(),"binary 3.exe");
    EXPECT_EQ(history.paths().back().filename(),"binary 2.exe");
#ifdef _WIN32
    history.remember("BINARY 3.EXE");
    EXPECT_EQ(history.paths().size(),5);
    EXPECT_EQ(history.paths()[1].filename(),"binary 6.exe");
#endif
}
TEST(RecentBinaries, PersistsUtf8PathsAndSeedsOnlyEmptyHistory) {
    peelf_test::ScopedTempDir temp_dir("peelf_recent_binaries");
    const auto storage = temp_dir / "peelf-recent-binaries-test.ini";
    viewer::RecentBinaries history;
    history.load(storage,"debug/peelf_viewer.exe");
    ASSERT_EQ(history.paths().size(),1);
    EXPECT_EQ(history.paths().front().filename(),"peelf_viewer.exe");
    history.remember(std::filesystem::path(u8"folder with spaces/\u03b4.exe"));
    ASSERT_TRUE(history.save(storage));
    viewer::RecentBinaries restored;
    restored.load(storage,"different-seed.exe");
    EXPECT_EQ(restored.paths(),history.paths());
    { std::ofstream broken(storage); broken << "invalid history"; }
    restored.load(storage,"debug/peelf_viewer.exe");
    ASSERT_EQ(restored.paths().size(),1);
    EXPECT_EQ(restored.paths().front().filename(),"peelf_viewer.exe");
}
