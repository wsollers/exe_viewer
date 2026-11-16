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

namespace {

void write_u16_le_pdb(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t val) {
    buf[off] = static_cast<std::uint8_t>(val & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
}

void write_u32_le_pdb(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t val) {
    buf[off] = static_cast<std::uint8_t>(val & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((val >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((val >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((val >> 24u) & 0xFFu);
}

void write_u64_le_pdb(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t val) {
    write_u32_le_pdb(buf, off, static_cast<std::uint32_t>(val & 0xFFFFFFFFull));
    write_u32_le_pdb(buf, off + 4u, static_cast<std::uint32_t>((val >> 32u) & 0xFFFFFFFFull));
}

std::vector<std::uint8_t> make_pe64_with_rsds(const std::array<std::uint8_t, 16>& guid,
                                              std::uint32_t age,
                                              std::string_view pdb_name) {
    std::vector<std::uint8_t> buf(0x600u, 0u);
    buf[0] = 'M';
    buf[1] = 'Z';
    write_u32_le_pdb(buf, 0x3Cu, 0x80u);
    buf[0x80u] = 'P';
    buf[0x81u] = 'E';
    write_u16_le_pdb(buf, 0x84u, 0x8664u);
    write_u16_le_pdb(buf, 0x86u, 1u);
    write_u16_le_pdb(buf, 0x94u, 0xF0u);
    write_u16_le_pdb(buf, 0x96u, 0x0022u);

    const std::size_t opt = 0x98u;
    write_u16_le_pdb(buf, opt + 0u, 0x020Bu);
    write_u32_le_pdb(buf, opt + 16u, 0x1000u);
    write_u64_le_pdb(buf, opt + 24u, 0x140000000ull);
    write_u32_le_pdb(buf, opt + 32u, 0x1000u);
    write_u32_le_pdb(buf, opt + 36u, 0x200u);
    write_u32_le_pdb(buf, opt + 56u, 0x2000u);
    write_u32_le_pdb(buf, opt + 60u, 0x200u);
    write_u32_le_pdb(buf, opt + 108u, 16u);
    // DataDirectory[6] = Debug (offset 112 + 6*8 = 160)
    write_u32_le_pdb(buf, opt + 160u, 0x1000u);
    write_u32_le_pdb(buf, opt + 164u, 28u);

    const std::size_t sh = opt + 0xF0u;
    std::copy_n(".rdata", 6u, reinterpret_cast<char*>(buf.data() + sh));
    write_u32_le_pdb(buf, sh + 8u, 0x200u);
    write_u32_le_pdb(buf, sh + 12u, 0x1000u);
    write_u32_le_pdb(buf, sh + 16u, 0x200u);
    write_u32_le_pdb(buf, sh + 20u, 0x200u);
    write_u32_le_pdb(buf, sh + 36u, 0x40000040u);

    // IMAGE_DEBUG_DIRECTORY at file offset 0x200 (RVA 0x1000)
    const std::size_t dbg = 0x200u;
    const auto rsds_len = static_cast<std::uint32_t>(24u + pdb_name.size() + 1u);
    write_u32_le_pdb(buf, dbg + 12u, 2u); // IMAGE_DEBUG_TYPE_CODEVIEW
    write_u32_le_pdb(buf, dbg + 16u, rsds_len);
    write_u32_le_pdb(buf, dbg + 20u, 0x1020u);
    write_u32_le_pdb(buf, dbg + 24u, 0x220u);

    // RSDS record at file offset 0x220
    const std::size_t rsds = 0x220u;
    std::copy_n("RSDS", 4u, reinterpret_cast<char*>(buf.data() + rsds));
    std::copy(guid.begin(), guid.end(), buf.begin() + static_cast<std::ptrdiff_t>(rsds + 4u));
    write_u32_le_pdb(buf, rsds + 20u, age);
    std::copy(pdb_name.begin(),
              pdb_name.end(),
              reinterpret_cast<char*>(buf.data() + rsds + 24u));
    buf[rsds + 24u + pdb_name.size()] = 0u;
    return buf;
}

std::vector<std::uint8_t> make_msf7_pdb(const std::array<std::uint8_t, 16>& guid,
                                        std::uint32_t info_age,
                                        std::uint32_t dbi_age) {
    // 5 blocks of 4096 bytes:
    //   block 0: MSF 7.00 SuperBlock
    //   block 1: BlockMap (points to block 2 for Stream Directory)
    //   block 2: Stream Directory (4 streams: 0=empty, 1=PdbInfo@blk3, 2=empty, 3=DBI@blk4)
    //   block 3: Stream 1 (PdbInfoHeader)
    //   block 4: Stream 3 (DbiStreamHeader)
    constexpr std::size_t kBlockSize = 4096u;
    std::vector<std::uint8_t> pdb(5u * kBlockSize, 0u);
    static constexpr char kMagic[32] = {
        'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ',
        'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1A', 'D', 'S', '\0', '\0', '\0'
    };
    std::copy_n(reinterpret_cast<const std::uint8_t*>(kMagic), 32u, pdb.begin());
    write_u32_le_pdb(pdb, 32u, static_cast<std::uint32_t>(kBlockSize));
    write_u32_le_pdb(pdb, 36u, 1u);   // FreeBlockMapBlock
    write_u32_le_pdb(pdb, 40u, 5u);   // NumBlocks
    write_u32_le_pdb(pdb, 44u, 28u);  // NumDirectoryBytes (4 + 4*4 + 2*4 = 28)
    write_u32_le_pdb(pdb, 52u, 1u);   // BlockMapAddr -> block 1

    // Block 1: directory block list -> [2]
    write_u32_le_pdb(pdb, 1u * kBlockSize, 2u);

    // Block 2: Stream Directory
    const std::size_t dir = 2u * kBlockSize;
    write_u32_le_pdb(pdb, dir + 0u, 4u);    // NumStreams = 4
    write_u32_le_pdb(pdb, dir + 4u, 0u);    // Stream 0 size = 0
    write_u32_le_pdb(pdb, dir + 8u, 28u);   // Stream 1 size = 28 (PdbInfo)
    write_u32_le_pdb(pdb, dir + 12u, 0u);   // Stream 2 size = 0
    write_u32_le_pdb(pdb, dir + 16u, 64u);  // Stream 3 size = 64 (DBI)
    write_u32_le_pdb(pdb, dir + 20u, 3u);   // Stream 1 block -> 3
    write_u32_le_pdb(pdb, dir + 24u, 4u);   // Stream 3 block -> 4

    // Block 3: PdbInfoHeader
    const std::size_t s1 = 3u * kBlockSize;
    write_u32_le_pdb(pdb, s1 + 0u, 20000404u);
    write_u32_le_pdb(pdb, s1 + 4u, 0x65000001u);
    write_u32_le_pdb(pdb, s1 + 8u, info_age);
    std::copy(guid.begin(), guid.end(), pdb.begin() + static_cast<std::ptrdiff_t>(s1 + 12u));

    // Block 4: DbiStreamHeader
    const std::size_t s3 = 4u * kBlockSize;
    write_u32_le_pdb(pdb, s3 + 0u, 0xFFFFFFFFu);
    write_u32_le_pdb(pdb, s3 + 4u, 19990903u);
    write_u32_le_pdb(pdb, s3 + 8u, dbi_age);
    return pdb;
}

} // namespace

TEST(DebugSymbols, LocalCodeViewPdbVerifiesMsf7GuidAndAge) {
    const auto temp_root =
        std::filesystem::temp_directory_path() / "peelf_msf7_pdb_verify_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_root, ec);
    std::filesystem::create_directories(temp_root, ec);

    const std::array<std::uint8_t, 16> guid{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01};
    std::array<std::uint8_t, 16> wrong_guid = guid;
    wrong_guid[15] ^= 0xFFu;

    const auto pe_bytes = make_pe64_with_rsds(guid, 2u, "C:\\build\\sample_app.pdb");
    auto image = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(image.has_value()) << image.error().message;

    const auto exe_path = temp_root / "sample_app.exe";
    const auto pdb_path = temp_root / "sample_app.pdb";

    auto write_file = [](const std::filesystem::path& p, std::span<const std::uint8_t> data) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    };
    write_file(exe_path, pe_bytes);

    // 1. Matching GUID + matching Info/DBI Age -> accepted
    write_file(pdb_path, make_msf7_pdb(guid, 2u, 2u));
    auto matched = viewer::find_local_codeview_pdb(**image, exe_path);
    ASSERT_TRUE(matched.has_value());
    EXPECT_EQ(matched->filename(), "sample_app.pdb");

    // 2. Matching GUID + mspdb bumped PdbInfo.Age=3 while DBI.Age=2 matches RSDS.Age=2 -> accepted
    write_file(pdb_path, make_msf7_pdb(guid, 3u, 2u));
    matched = viewer::find_local_codeview_pdb(**image, exe_path);
    EXPECT_TRUE(matched.has_value());

    // 3. Stale PDB (both Info.Age=1 and DBI.Age=1 mismatch RSDS.Age=2) -> rejected
    write_file(pdb_path, make_msf7_pdb(guid, 1u, 1u));
    EXPECT_FALSE(viewer::find_local_codeview_pdb(**image, exe_path).has_value());

    // 4. Wrong GUID (even with matching Age=2) -> rejected
    write_file(pdb_path, make_msf7_pdb(wrong_guid, 2u, 2u));
    EXPECT_FALSE(viewer::find_local_codeview_pdb(**image, exe_path).has_value());

    std::filesystem::remove_all(temp_root, ec);
}
