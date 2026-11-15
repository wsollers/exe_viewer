#include <cstdint>
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "symbols/debug_symbols.hpp"
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

TEST(SymbolIndex, SubstringSearchIsCaseInsensitiveAndHandlesEmptyQueries) {
    EXPECT_TRUE(viewer::symbol_name_matches("HeapAlloc", "alloc"));
    EXPECT_TRUE(viewer::symbol_name_matches("allocate_buffer", "CATE_b"));
    EXPECT_TRUE(viewer::symbol_name_matches("main", ""));
    EXPECT_FALSE(viewer::symbol_name_matches("main", "main_extra"));
    EXPECT_FALSE(viewer::symbol_name_matches("HeapFree", "alloc"));
}

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

TEST(SymbolIndex, FormatsOrdinalImportNames) {
    peelf::ImportEntry entry;
    entry.library = "KERNEL32.dll";
    entry.ordinal = 0x004D;
    entry.import_by_ordinal = true;

    EXPECT_EQ(viewer::import_symbol_name(entry), "KERNEL32.dll!#77");
}

TEST(SymbolIndex, MergesPdbDebugSymbolsAboveParserSymbols) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    viewer::SymbolIndex index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        viewer::DebugSymbol{
            .name = "WinMain",
            .relative_virtual_address = 0x1000,
            .virtual_address = image->entry_point(),
            .size = 0x30,
            .function = true,
        },
    };

    index.add_debug_symbols(*image, symbols);

    const viewer::SymbolRecord* winmain = index.find_by_name("WinMain");
    ASSERT_NE(winmain, nullptr);
    EXPECT_EQ(winmain->source, viewer::SymbolSource::DebugSymbol);
    ASSERT_TRUE(winmain->virtual_address.has_value());
    EXPECT_EQ(*winmain->virtual_address, image->entry_point());
    EXPECT_EQ(index.find_containing_address(image->entry_point()), winmain);
    EXPECT_EQ(winmain->function, true);
    EXPECT_TRUE(viewer::symbol_has_code(*image, *winmain));
}

TEST(SymbolIndex, DataAndUnmappedSymbolsDoNotBecomeCode) {
    const auto image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);
    auto index = viewer::SymbolIndex::build(*image);
    const viewer::DebugSymbol symbols[] = {
        {.name = "data_in_code", .virtual_address = image->entry_point(), .function = false},
        {.name = "unmapped_function", .function = true},
    };
    index.add_debug_symbols(*image, symbols);
    const auto* data = index.find_by_name("data_in_code");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->size, 0u);
    EXPECT_FALSE(viewer::symbol_has_code(*image, *data));
    EXPECT_FALSE(viewer::symbol_has_code(*image, *index.find_by_name("unmapped_function")));
    for (const auto& symbol : index.records())
        if (symbol.source == viewer::SymbolSource::Import)
            EXPECT_FALSE(viewer::symbol_has_code(*image, symbol));
    EXPECT_TRUE(viewer::symbol_has_code(*image, *index.find_by_name("Entry Point")));
}

TEST(DebugSymbols, DiscoversMissingCodeViewPdbAndReportsMissingExplicitPath) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const std::filesystem::path exe_path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe";
    EXPECT_FALSE(viewer::find_local_codeview_pdb(*image, exe_path).has_value());

    const viewer::DebugSymbolLoadResult result =
        viewer::load_pdb_debug_symbols(exe_path.parent_path() / "known-win-x64.pdb", *image);
    EXPECT_EQ(result.status, viewer::DebugSymbolLoadStatus::FileNotFound);
}

TEST(DebugSymbols, RejectsInvalidPdbBeforeDia) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const std::filesystem::path pdb_path = std::filesystem::temp_directory_path() / "peelf_invalid_debug_symbols.pdb";
    {
        std::ofstream out(pdb_path, std::ios::binary);
        ASSERT_TRUE(out) << pdb_path.string();
        out << "not a real pdb";
    }

    const viewer::DebugSymbolLoadResult result = viewer::load_pdb_debug_symbols(pdb_path, *image);
    std::filesystem::remove(pdb_path);

    EXPECT_EQ(result.status, viewer::DebugSymbolLoadStatus::UnsupportedFormat);
}

TEST(DebugSymbols, ConfiguredDiaBackendLoadsBuildPdb) {
#if defined(_WIN32) && defined(PEELF_HAS_DIA) && defined(PEELF_DIA_DLL_PATH)
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const std::array<std::filesystem::path, 4> candidates{
        std::filesystem::current_path() / "Debug" / "peelf_tests.pdb",
        std::filesystem::current_path() / "tests" / "Debug" / "peelf_tests.pdb",
        std::filesystem::current_path().parent_path() / "Debug" / "peelf_tests.pdb",
        std::filesystem::current_path().parent_path() / "tests" / "Debug" / "peelf_tests.pdb",
    };

    std::filesystem::path pdb_path;
    for (const std::filesystem::path& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            pdb_path = candidate;
            break;
        }
    }
    if (pdb_path.empty()) {
        GTEST_SKIP() << "No build-produced peelf_tests.pdb found";
    }

    const viewer::DebugSymbolLoadResult result = viewer::load_pdb_debug_symbols(pdb_path, *image);
    EXPECT_EQ(result.status, viewer::DebugSymbolLoadStatus::Loaded) << result.diagnostic;
    EXPECT_FALSE(result.symbols.empty());
#else
    GTEST_SKIP() << "DIA backend was not configured for this build";
#endif
}

TEST(SymbolIndex, RetainsLibraryMetadataAndListsDistinctLibraries) {
    const auto image=parse_fixture("known-win-x64.exe");
    ASSERT_NE(image,nullptr);
    auto index=viewer::SymbolIndex::build(*image);
    const auto address=image->entry_point();
    const std::array symbols{
        viewer::DebugSymbol{.name="library_function_a",.virtual_address=address,.size=4,.function=true,.library="alpha.lib"},
        viewer::DebugSymbol{.name="library_function_b",.virtual_address=address+4,.size=4,.function=true,.library="alpha.lib"},
        viewer::DebugSymbol{.name="library_function_c",.virtual_address=address+8,.size=4,.function=true,.library="beta.lib"}};
    index.add_debug_symbols(*image,symbols);
    ASSERT_NE(index.find_by_name("library_function_a"),nullptr);
    EXPECT_EQ(index.find_by_name("library_function_a")->library,"alpha.lib");
    const auto libraries=index.libraries();
    EXPECT_EQ(std::ranges::count(libraries,"alpha.lib"),1);
    EXPECT_EQ(std::ranges::count(libraries,"beta.lib"),1);
    EXPECT_EQ(std::ranges::count(libraries,""),0);
    for (const auto& symbol:index.records()) if(symbol.source==viewer::SymbolSource::Import)
        EXPECT_EQ(symbol.library,image->imports()[symbol.source_index].library);
}

TEST(DebugSymbols, ReadsStaticLibraryProvenanceFromFixturePdb) {
#if defined(_WIN32) && defined(PEELF_HAS_DIA)
    std::ifstream file(PEELF_CALLGRAPH_FIXTURE_EXE,std::ios::binary);
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    auto image=peelf::parse_image(bytes); ASSERT_TRUE(image);
    const auto pdb=viewer::load_pdb_debug_symbols(PEELF_CALLGRAPH_FIXTURE_PDB,**image);
    ASSERT_EQ(pdb.status,viewer::DebugSymbolLoadStatus::Loaded)<<pdb.diagnostic;
    EXPECT_TRUE(std::ranges::any_of(pdb.symbols,[](const auto& s){return s.function && !s.library.empty();}));
#else
    GTEST_SKIP()<<"DIA unavailable";
#endif
}
