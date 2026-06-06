// Smoke tests for the peelf_explorer test harness.
//
// Purpose: prove that GoogleTest is wired in, compiles against the project's
// C++23 settings, links, and runs under CTest. As real parsing features land,
// add dedicated test files (e.g. pe_parser_test.cpp, elf_parser_test.cpp);
// this file should stay a minimal harness check.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

std::filesystem::path fixture_path(const char* name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

}  // namespace

// Hello-world: the harness itself runs.
TEST(Smoke, HarnessRuns) {
    EXPECT_EQ(2 + 2, 4);
}

// Sanity check that the fixtures directory was configured and reachable.
TEST(Smoke, FixturesDirectoryConfigured) {
    EXPECT_TRUE(std::filesystem::exists(PEELF_TEST_FIXTURES_DIR))
        << "configured fixtures dir is missing: " << PEELF_TEST_FIXTURES_DIR;
}

// First real fixture check: the committed ELF sample starts with the ELF magic.
// Skips (rather than fails) until tests/fixtures/hello.elf is added, so a fresh
// checkout stays green; becomes a hard assertion once the fixture is present.
TEST(ElfFixture, HasElfMagic) {
    const std::filesystem::path path = fixture_path("hello.elf");
    if (!std::filesystem::exists(path)) {
        GTEST_SKIP() << "fixture not present yet: " << path.string()
                     << " (see tests/fixtures/README.md)";
    }

    std::ifstream file(path, std::ios::binary);
    ASSERT_TRUE(file.good()) << "could not open fixture: " << path.string();

    std::array<unsigned char, 4> magic{};
    file.read(reinterpret_cast<char*>(magic.data()),
              static_cast<std::streamsize>(magic.size()));
    ASSERT_EQ(file.gcount(), static_cast<std::streamsize>(magic.size()));

    EXPECT_EQ(magic[0], 0x7Fu);
    EXPECT_EQ(magic[1], static_cast<unsigned char>('E'));
    EXPECT_EQ(magic[2], static_cast<unsigned char>('L'));
    EXPECT_EQ(magic[3], static_cast<unsigned char>('F'));
}
