#include "model/recent_binaries.hpp"
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
    const auto storage=std::filesystem::temp_directory_path()/"peelf-recent-binaries-test.ini";
    std::filesystem::remove(storage);
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
    std::filesystem::remove(storage);
}
