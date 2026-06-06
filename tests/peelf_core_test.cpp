// Tests for the peelf_core public surface.
//
// Starts with FileKind -> string mapping (peelf::to_string). As the unified
// parser API lands (ToDo.md P1-x), add parse tests for PE/ELF here against the
// fixtures in tests/fixtures/.

#include <gtest/gtest.h>

#include <peelf/peelf.hpp>

TEST(PeelfCore, FileKindToString) {
    EXPECT_EQ(peelf::to_string(peelf::FileKind::ELF), "ELF");
    EXPECT_EQ(peelf::to_string(peelf::FileKind::PE), "PE");
    EXPECT_EQ(peelf::to_string(peelf::FileKind::Unknown), "Unknown");
}
