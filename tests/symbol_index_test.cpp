#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "symbols/symbol_index.hpp"
#include <peelf/binary_image.hpp>

namespace {

[[nodiscard]] std::vector<std::uint8_t> read_fixture(const std::string& name) {
    const std::filesystem::path path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

[[nodiscard]] std::unique_ptr<peelf::IBinaryImage> parse_fixture(const std::string& name) {
    std::vector<std::uint8_t> bytes = read_fixture(name);
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    EXPECT_TRUE(parsed.has_value()) << name;
    if (!parsed) {
        return {};
    }
    return std::move(*parsed);
}

} // namespace

TEST(SymbolIndex, LoadsElfImageSymbolsAndRuntimeSymbols) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("hello.elf");
    ASSERT_NE(image, nullptr);

    const viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);

    const viewer::SymbolRecord* start = index.find_by_name("_start");
    ASSERT_NE(start, nullptr);
    ASSERT_TRUE(start->virtual_address.has_value());
    EXPECT_EQ(*start->virtual_address, 0x1060u);
    EXPECT_EQ(index.find_containing_address(0x1060), start);

    const viewer::SymbolRecord* main = index.find_by_name("main");
    ASSERT_NE(main, nullptr);
    ASSERT_TRUE(main->virtual_address.has_value());
    EXPECT_EQ(*main->virtual_address, 0x1161u);

    const viewer::SymbolRecord* libc_start = index.find_by_name("__libc_start_main@GLIBC_2.34");
    ASSERT_NE(libc_start, nullptr);
    EXPECT_TRUE(libc_start->external);
}

TEST(SymbolIndex, LoadsPeExportsImportsAndEntryPoint) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);

    const viewer::SymbolRecord* entry = index.find_by_name("Entry Point");
    ASSERT_NE(entry, nullptr);
    ASSERT_TRUE(entry->virtual_address.has_value());
    EXPECT_EQ(*entry->virtual_address, image->entry_point());

    const viewer::SymbolRecord* exported = index.find_by_name("known_export");
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->source, viewer::SymbolSource::Export);
    ASSERT_TRUE(exported->virtual_address.has_value());
    EXPECT_EQ(*exported->virtual_address, image->entry_point());

    const viewer::SymbolRecord* imported = index.find_by_name("KERNEL32.dll!ExitProcess");
    ASSERT_NE(imported, nullptr);
    EXPECT_EQ(imported->source, viewer::SymbolSource::Import);
    EXPECT_TRUE(imported->external);
}
