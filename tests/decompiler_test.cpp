#include "decompile/decompiler.hpp"
#include <peelf/sha256.hpp>
#include <gtest/gtest.h>
#include <fstream>
#include "model/binary_model.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <thread>
#include "symbols/debug_symbols.hpp"
using namespace viewer;

TEST(Decompiler, MappedRangesAndStructuresRoundTrip) {
    const auto unit=parse_decompiler_output("PEELF_DECOMPILE 3 ready \"C\" 2 0 \"{\" 2 4096 3 4102 5 \"  return count;\" 1 \"Packet\" 16 0 1 8 8 \"weight\" \"double\"");
    ASSERT_EQ(unit.status,viewer::DecompileStatus::Ready);
    EXPECT_FALSE(unit.lines[0].address);
    ASSERT_EQ(unit.lines[1].ranges.size(),2);
    EXPECT_EQ(unit.lines[1].address,4096);
    EXPECT_EQ(unit.lines[1].ranges[1].size,5);
    ASSERT_EQ(unit.types.size(),1);
    EXPECT_TRUE(viewer::type_matches(unit.types[0],"EIGH"));
    EXPECT_TRUE(viewer::type_matches(unit.types[0],"DOUBLE"));
    EXPECT_FALSE(viewer::type_matches(unit.types[0],"missing"));
}
TEST(Decompiler, RejectsInvalidRangesAndLayouts) {
    for (const auto* range : {"-2 1","4096 0","18446744073709551615 2","4096 1048577"})
        EXPECT_EQ(viewer::parse_decompiler_output(std::string("PEELF_DECOMPILE 3 ready \"\" 1 1 ")+range+" \"x\" 0").status,viewer::DecompileStatus::Failed);
    EXPECT_EQ(viewer::parse_decompiler_output("PEELF_DECOMPILE 3 ready \"\" 1 0 \"x\" 1 \"bad\" 4 0 1 3 2 \"field\" \"short\"").status,viewer::DecompileStatus::Failed);
}

using namespace viewer;
TEST(Decompiler, ValidatesProtocolAndAddressMapping) {
    auto unit=parse_decompiler_output("PEELF_DECOMPILE 1\nready \"mapped\"\n2\n4096 \"return 1;\"\n4100 \"}\"\n");
    ASSERT_EQ(unit.status,DecompileStatus::Ready); ASSERT_EQ(unit.lines.size(),2);
    EXPECT_EQ(unit.lines[0].address,4096); EXPECT_EQ(unit.lines[0].text,"return 1;");
    EXPECT_EQ(parse_decompiler_output("bad").status,DecompileStatus::Failed);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 1 ready \"\" 2 1 \"truncated\"").status,DecompileStatus::Failed);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 1 unsupported \"cpu\" 0").status,DecompileStatus::Unsupported);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 1 no_function \"missing\" 0").status,DecompileStatus::NoFunction);
}
TEST(Decompiler, AnnotatedFallbackIsExplicitAndCancellable) {
    DecompileRequest request;
    request.fallback_graph.nodes.push_back({.id="bb0",.label="entry",.instructions={{0x1000,"ret",""}}});
    auto result=AnnotatedCodeDecompiler{}.decompile(request);
    EXPECT_EQ(result.status,DecompileStatus::Ready); EXPECT_NE(result.provider.find("not decompiled"),std::string::npos);
    EXPECT_EQ(result.lines[1].address,0x1000);
    std::stop_source stop; stop.request_stop(); EXPECT_EQ(AnnotatedCodeDecompiler{}.decompile(request,stop.get_token()).status,DecompileStatus::Cancelled);
}
namespace {
class FakeRunner final : public IBackendRunner {
public:
    BackendProcessResult response{};
    std::string output;
    BackendProcessResult run(const std::filesystem::path&,const std::vector<std::string>& args,std::chrono::milliseconds timeout,std::stop_token) const override {
        EXPECT_EQ(timeout,std::chrono::seconds(60)); EXPECT_TRUE(std::filesystem::exists(args[1]));
        if (!output.empty()) { std::ofstream file(args[2]); file<<output; }
        return response;
    }
};
}
TEST(Decompiler, BackendAdapterHandlesTimeoutCancellationUnavailableAndSuccess) {
    const auto bridge=std::filesystem::temp_directory_path()/"peelf-fake-bridge.py"; {std::ofstream file(bridge); file<<"# fixture";}
    FakeRunner runner; DecompileRequest request; request.architecture=peelf::Architecture::X86_64; request.image_bytes={1,2,3};
    BinaryNinjaDecompiler backend("python",bridge,runner);
    runner.response={-1,true,false}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Timeout);
    runner.response={-1,false,true}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Cancelled);
    runner.response={-1,false,false}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Unavailable);
    runner.response={0}; runner.output="PEELF_DECOMPILE 1 ready \"HLIL\" 1 4096 \"return 0;\"";
    EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Ready);
    std::filesystem::remove(bridge);
}

TEST(Decompiler, OptionalMappingsAndMalformedAddresses) {
    const auto unit = parse_decompiler_output("PEELF_DECOMPILE 2 ready \"C\" 2 - \"{\" 4096 \"return 42;\"");
    ASSERT_EQ(unit.status, DecompileStatus::Ready);
    EXPECT_FALSE(unit.lines[0].address);
    EXPECT_EQ(unit.lines[1].address, 4096);
    for (const auto* address : {"-1", "18446744073709551616", "4096junk"})
        EXPECT_EQ(parse_decompiler_output(std::string("PEELF_DECOMPILE 2 ready \"\" 1 ") + address + " \"x\"").status, DecompileStatus::Failed);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 2 timeout \"deadline\" 0").status, DecompileStatus::Timeout);
}

TEST(Decompiler, RealProcessTimeoutCancellationAndArgumentBoundaries) {
    BackendRunner runner;
    auto path=std::filesystem::temp_directory_path()/"peelf space & dollar $ argument.txt";
    auto result=runner.run(PEELF_BACKEND_FIXTURE,{"echo",path.string()},std::chrono::seconds(5),{});
    ASSERT_EQ(result.exit_code,0);
    std::ifstream file(path); const std::string text{std::istreambuf_iterator<char>(file),{}};
    EXPECT_EQ(text,path.string()); file.close(); std::filesystem::remove(path);
    EXPECT_EQ(runner.run(PEELF_BACKEND_FIXTURE,{},std::chrono::seconds(5),{}).exit_code,7);
    result=runner.run(PEELF_BACKEND_FIXTURE,{"sleep"},std::chrono::milliseconds(100),{});
    EXPECT_TRUE(result.timed_out); EXPECT_FALSE(result.cancelled);
    std::stop_source stop;
    std::jthread cancel([&stop]{std::this_thread::sleep_for(std::chrono::milliseconds(100));stop.request_stop();});
    result=runner.run(PEELF_BACKEND_FIXTURE,{"sleep"},std::chrono::seconds(10),stop.get_token());
    EXPECT_TRUE(result.cancelled); EXPECT_FALSE(result.timed_out);
}

TEST(Decompiler, SettingsRoundTripAndValidation) {
    auto path = std::filesystem::temp_directory_path()/"peelf-decompiler-settings-test.ini";
    DecompilerSettings settings; settings.ghidra_home="path with spaces"; settings.java="custom/java"; settings.timeout_seconds=320;
    ASSERT_TRUE(save_decompiler_settings(path,settings));
    auto restored=read_decompiler_settings(path); ASSERT_TRUE(restored);
    EXPECT_EQ(restored->provider,DecompilerProvider::Ghidra); EXPECT_EQ(restored->ghidra_home,settings.ghidra_home);
    EXPECT_EQ(restored->java,settings.java); EXPECT_EQ(restored->timeout_seconds,320);
    { std::ofstream file(path); file << "PEELF_DECOMPILER 1 99 \"\" \"java\" \"python\" 20"; }
    EXPECT_FALSE(read_decompiler_settings(path)); std::filesystem::remove(path);
}

TEST(Decompiler, GhidraAdapterUsesSnapshotAndHandlesFailures) {
    const auto home=std::filesystem::temp_directory_path()/"peelf ghidra adapter test";
    std::filesystem::create_directories(home/"Ghidra/Framework/Utility/lib");
    { std::ofstream file(home/"Ghidra/Framework/Utility/lib/Utility.jar"); }
    { std::ofstream file(home/"PeelfDecompile.java"); }
    struct Runner final : IBackendRunner {
        BackendProcessResult result{0};
        mutable std::filesystem::path workspace;
        BackendProcessResult run(const std::filesystem::path&,const std::vector<std::string>& args,std::chrono::milliseconds timeout,std::stop_token) const override {
            EXPECT_EQ(timeout,std::chrono::seconds(180));
            auto imported=std::ranges::find(args,"-import");
            EXPECT_NE(imported,args.end());
            std::ifstream input(*std::next(imported),std::ios::binary);
            const std::string bytes{std::istreambuf_iterator<char>(input),{}};
            EXPECT_EQ(bytes,"patched snapshot");
            auto script=std::ranges::find(args,"-postScript");
            const auto output=std::filesystem::path(*std::next(script,3)); workspace=output.parent_path();
            { std::ofstream file(output); file<<"PEELF_DECOMPILE 2 ready \"C\" 1 4096 \"return 42;\""; }
            return result;
        }
    } runner;
    DecompilerSettings settings; settings.ghidra_home=home;
    DecompileRequest request; request.architecture=peelf::Architecture::X86_64;
    const std::string bytes="patched snapshot"; request.image_bytes.assign(bytes.begin(),bytes.end());
    GhidraDecompiler backend(settings,home,runner);
    EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Ready);
    EXPECT_FALSE(std::filesystem::exists(runner.workspace));
    runner.result={1}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Failed);
    runner.result={-1,true,false}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Timeout);
    runner.result={-1,false,true}; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Cancelled);
    request.architecture=peelf::Architecture::Unknown; EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Unsupported);
    std::filesystem::remove_all(home);
    EXPECT_EQ(backend.decompile(request).status,DecompileStatus::Unavailable);
}

class GhidraIntegration : public ::testing::TestWithParam<const char*> {};
TEST_P(GhidraIntegration, ProducesMappedCForCpuFixture) {
    auto settings=discover_decompilers({});
    if(settings.ghidra_home.empty()) GTEST_SKIP()<<"Set GHIDRA_INSTALL_DIR and JAVA_HOME for real backend integration";
    BinaryModel model;
    auto path=std::filesystem::path(PEELF_BIN_MATRIX_DIR)/GetParam();
    if(!std::filesystem::exists(path)) path=std::filesystem::path(PEELF_TEST_FIXTURES_DIR)/GetParam();
    ASSERT_TRUE(model.load_file(path.string()));
    const auto symbols=SymbolIndex::build(*model.image());
    const auto* first=symbols.find_by_name("first");
    DecompileRequest request; request.address=first && first->virtual_address ? *first->virtual_address : model.image()->entry_point();
    request.architecture=model.image()->architecture();
    request.image_bytes.assign(model.bytes().begin(),model.bytes().end());
    if (request.architecture == peelf::Architecture::RISCV32) {
        // This parser fixture otherwise terminates with an environment call.
        // Supply a known return-42 function through the effective-byte snapshot.
        const auto offset=model.image()->virtual_address_to_file_offset(request.address);
        ASSERT_TRUE(offset); ASSERT_LE(*offset+8,request.image_bytes.size());
        const std::uint8_t code[]{0x13,0x05,0xA0,0x02,0x67,0x80,0,0};
        std::ranges::copy(code,request.image_bytes.begin()+static_cast<std::ptrdiff_t>(*offset));
    }
    if (std::string_view(GetParam()) == "known-linux-arm-elf32-le.elf") {
        request.thumb = true;
        const auto offset=model.image()->virtual_address_to_file_offset(request.address);
        ASSERT_TRUE(offset); ASSERT_LE(*offset+4,request.image_bytes.size());
        const std::uint8_t code[]{0x2A,0x20,0x70,0x47}; // movs r0,#42; bx lr
        std::ranges::copy(code,request.image_bytes.begin()+static_cast<std::ptrdiff_t>(*offset));
    }
    BackendRunner runner;
    const auto scripts=std::filesystem::path(PEELF_TEST_FIXTURES_DIR).parent_path().parent_path()/"apps/viewer/resources";
    const auto result=GhidraDecompiler(settings,scripts,runner).decompile(request);
    ASSERT_EQ(result.status,DecompileStatus::Ready)<<result.diagnostic;
    ASSERT_FALSE(result.lines.empty());
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.address.has_value();}));
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.text.find("return")!=std::string::npos;}));
    if (request.thumb || request.architecture == peelf::Architecture::RISCV32)
        EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.text.find("0x2a")!=std::string::npos || line.text.find("42")!=std::string::npos;}));
}
INSTANTIATE_TEST_SUITE_P(RealBackend,GhidraIntegration,::testing::Values(
    "elf-linux-x86-32-le-callgraph.elf", "elf-linux-x86_64-64-le-callgraph.elf",
    "elf-linux-arm-32-le-callgraph.elf", "elf-linux-arm64-64-le-callgraph.elf",
    "elf-linux-mips-32-be-callgraph.elf", "elf-linux-mips64-64-be-callgraph.elf",
    "elf-linux-ppc-32-be-callgraph.elf", "elf-linux-ppc64-64-be-callgraph.elf",
    "known-linux-riscv32-elf32-le.elf", "elf-linux-riscv64-64-le-callgraph.elf",
    "pe-windows-x86-32-le-callgraph.dll", "pe-windows-x86_64-64-le-callgraph.dll",
    "known-linux-arm-elf32-le.elf"));

TEST(Decompiler, ContainingFunctionWinsOverInteriorBlock) {
    BinaryModel model;
    ASSERT_TRUE(model.load_file((std::filesystem::path(PEELF_BIN_MATRIX_DIR)/"elf-linux-x86_64-64-le-callgraph.elf").string()));
    auto index=SymbolIndex::build(*model.image());
    const auto* first=index.find_by_name("first");
    ASSERT_NE(first,nullptr); ASSERT_TRUE(first->virtual_address); ASSERT_GT(first->size,1);
    const auto start=*first->virtual_address;
    SymbolRecord block{.name="block",.virtual_address=start+1,.size=1,.function=true};
    auto root=containing_function(*model.image(),index,start+1,block);
    ASSERT_TRUE(root); EXPECT_EQ(root->virtual_address,start); EXPECT_EQ(root->size,first->size);
}

TEST(Decompiler, SymbolManifestPreservesNamesAndPrefersDebugNames) {
    DecompileRequest request; request.address=4096; request.function_size=32;
    request.symbols={{.name="entry",.source=SymbolSource::EntryPoint,.virtual_address=4096},
        {.name="My name",.source=SymbolSource::DebugSymbol,.virtual_address=4096,.size=32,.function=true},
        {.name="external",.virtual_address=8192,.external=true}};
    const auto manifest=encode_decompiler_symbols(request);
    EXPECT_EQ(manifest,"PEELF_SYMBOLS 1\n4096 32\n1\n4096 32 1 4d79206e616d65\n0\n");
}

TEST(Decompiler, PdbStructuresAndRealSymbolAwareFunction) {
    BinaryModel model; ASSERT_TRUE(model.load_file(PEELF_CALLGRAPH_FIXTURE_EXE));
    const auto pdb=load_pdb_debug_symbols(PEELF_CALLGRAPH_FIXTURE_PDB,*model.image());
    if(pdb.status!=DebugSymbolLoadStatus::Loaded) GTEST_SKIP()<<pdb.diagnostic;
    auto type=std::ranges::find_if(pdb.types,[](const auto& t){return t.name.find("DecompilerPacket")!=std::string::npos;});
    ASSERT_NE(type,pdb.types.end()); EXPECT_EQ(type->size,16);
    ASSERT_EQ(type->members.size(),2); EXPECT_TRUE(type_matches(*type,"weight"));
    auto index=SymbolIndex::build(*model.image()); index.add_debug_symbols(*model.image(),pdb.symbols);
    auto first=std::ranges::find_if(index.records(),[](const auto& s){return s.name.find("peelf_fixture::first")!=std::string::npos && s.size>0;});
    ASSERT_NE(first,index.records().end());
    auto root=containing_function(*model.image(),index,*first->virtual_address+1);
    ASSERT_TRUE(root); EXPECT_EQ(root->virtual_address,first->virtual_address);
    auto settings=discover_decompilers({});
    if(settings.ghidra_home.empty()) GTEST_SKIP()<<"Set GHIDRA_INSTALL_DIR for real symbol integration";
    DecompileRequest request; request.address=*root->virtual_address; request.function_size=root->size;
    request.architecture=model.image()->architecture(); request.image_bytes.assign(model.bytes().begin(),model.bytes().end());
    request.symbols.assign(index.records().begin(),index.records().end()); request.types=pdb.types;
    for(auto& symbol:request.symbols) if(symbol.name.find("peelf_fixture::leaf")!=std::string::npos) symbol.name="readable_leaf";
    BackendRunner runner;
    auto scripts=std::filesystem::path(PEELF_TEST_FIXTURES_DIR).parent_path().parent_path()/"apps/viewer/resources";
    auto result=GhidraDecompiler(settings,scripts,runner).decompile(request);
    ASSERT_EQ(result.status,DecompileStatus::Ready)<<result.diagnostic;
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.text.find("readable_leaf")!=std::string::npos;}));
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return !line.ranges.empty();}));
    EXPECT_TRUE(std::ranges::any_of(result.types,[](const auto& t){return t.name.find("DecompilerPacket")!=std::string::npos;}));
}

TEST(Decompiler, ViewerPdbSymbolCollisionsDoNotAbortDecompilation) {
#ifndef PEELF_VIEWER_DEBUG_EXE
    GTEST_SKIP()<<"Viewer build unavailable";
#else
    auto settings=discover_decompilers({});
    if(settings.ghidra_home.empty()) GTEST_SKIP()<<"Set GHIDRA_INSTALL_DIR for real backend integration";
    const auto directory=std::filesystem::path(PEELF_VIEWER_DEBUG_EXE).parent_path();
    BinaryModel model; ASSERT_TRUE(model.load_file((directory/"peelf_viewer.exe").string()));
    const auto pdb=load_pdb_debug_symbols(directory/"peelf_viewer.pdb",*model.image());
    ASSERT_EQ(pdb.status,DebugSymbolLoadStatus::Loaded)<<pdb.diagnostic;
    auto index=SymbolIndex::build(*model.image()); index.add_debug_symbols(*model.image(),pdb.symbols);
    auto target=std::ranges::find_if(index.records(),[](const auto& symbol){return symbol.name=="capture_current_context" && symbol.size>0;});
    ASSERT_NE(target,index.records().end()); ASSERT_TRUE(target->virtual_address);
    DecompileRequest request; request.address=*target->virtual_address; request.function_size=target->size;
    request.architecture=model.image()->architecture(); request.image_bytes.assign(model.bytes().begin(),model.bytes().end());
    request.symbols.assign(index.records().begin(),index.records().end()); request.types=pdb.types;
    BackendRunner runner;
    const auto scripts=std::filesystem::path(PEELF_TEST_FIXTURES_DIR).parent_path().parent_path()/"apps/viewer/resources";
    const auto result=GhidraDecompiler(settings,scripts,runner).decompile(request);
    ASSERT_EQ(result.status,DecompileStatus::Ready)<<result.diagnostic;
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.address.has_value();}));
#endif
}

TEST(Decompiler, BinaryModelContentSha256TracksPatchesAndUndo) {
    BinaryModel model;
    EXPECT_TRUE(model.content_sha256().empty());
    ASSERT_TRUE(model.load_file(PEELF_CALLGRAPH_FIXTURE_EXE));

    const std::string original_sha = model.content_sha256();
    ASSERT_EQ(original_sha.size(), 64u);
    EXPECT_EQ(original_sha, peelf::sha256_hex(model.bytes()));
    // Cached lookup returns identical digest without recomputing mismatch.
    EXPECT_EQ(model.content_sha256(), original_sha);

    ASSERT_GT(model.bytes().size(), 64u);
    const std::uint8_t flipped = static_cast<std::uint8_t>(model.bytes()[64] ^ 0xFFu);
    const std::array<std::uint8_t, 1> patch{flipped};
    ASSERT_TRUE(model.apply_patch_bytes(64, patch, "flip byte").has_value());

    const std::string patched_sha = model.content_sha256();
    EXPECT_NE(patched_sha, original_sha);
    auto effective = model.read_effective_bytes(0, model.bytes().size());
    ASSERT_TRUE(effective.has_value());
    EXPECT_EQ(patched_sha, peelf::sha256_hex(*effective));

    ASSERT_TRUE(model.undo_patch().has_value());
    EXPECT_EQ(model.content_sha256(), original_sha);
}

TEST(Decompiler, DecompileCacheHitInvalidationAndLruEviction) {
    DecompileCache cache(2);

    DecompileRequest req_a;
    req_a.binary_sha256 = std::string(64, 'a');
    req_a.patch_revision = 0;
    req_a.symbol_revision = 1;
    req_a.architecture = peelf::Architecture::X86_64;
    req_a.address = 0x401000;
    req_a.function_size = 64;
    req_a.symbols = {{.name = "func_a", .virtual_address = 0x401000, .size = 64, .function = true}};

    DecompilerSettings settings;
    settings.provider = DecompilerProvider::Ghidra;
    settings.ghidra_home = "/opt/ghidra";

    const auto key_a = make_decompile_cache_key(req_a, settings);
    EXPECT_FALSE(cache.get(key_a).has_value());

    // Non-Ready statuses are never cached.
    DecompiledUnit timeout_unit;
    timeout_unit.status = DecompileStatus::Timeout;
    timeout_unit.provider = "Ghidra";
    timeout_unit.diagnostic = "timed out";
    cache.put(key_a, timeout_unit);
    EXPECT_EQ(cache.size(), 0u);

    DecompiledUnit ready_a;
    ready_a.status = DecompileStatus::Ready;
    ready_a.provider = "Ghidra";
    ready_a.diagnostic = "ok";
    ready_a.lines.push_back(DecompiledLine{0x401000, "int func_a(void)", {}});
    cache.put(key_a, ready_a);
    EXPECT_EQ(cache.size(), 1u);

    auto hit_a = cache.get(key_a);
    ASSERT_TRUE(hit_a.has_value());
    EXPECT_EQ(hit_a->cache_source, DecompileCacheSource::MemoryCacheHit);
    ASSERT_EQ(hit_a->lines.size(), 1u);
    EXPECT_EQ(hit_a->lines[0].text, "int func_a(void)");

    // Patch revision invalidates key.
    auto patched_req = req_a;
    patched_req.patch_revision = 1;
    EXPECT_FALSE(cache.get(make_decompile_cache_key(patched_req, settings)).has_value());

    // Symbol rename invalidates key automatically via symbols_sha256.
    auto renamed_req = req_a;
    renamed_req.symbols[0].name = "renamed_func_a";
    EXPECT_FALSE(cache.get(make_decompile_cache_key(renamed_req, settings)).has_value());

    // Provider/settings change invalidates key.
    auto other_settings = settings;
    other_settings.ghidra_home = "/opt/ghidra-custom";
    EXPECT_FALSE(cache.get(make_decompile_cache_key(req_a, other_settings)).has_value());

    // LRU capacity = 2: insert B, touch A, insert C -> B is evicted, A and C remain.
    auto req_b = req_a;
    req_b.address = 0x401080;
    const auto key_b = make_decompile_cache_key(req_b, settings);
    DecompiledUnit ready_b = ready_a;
    ready_b.lines = {DecompiledLine{0x401080, "int func_b(void)", {}}};
    cache.put(key_b, ready_b);
    EXPECT_TRUE(cache.get(key_a).has_value()); // refresh A as MRU

    auto req_c = req_a;
    req_c.address = 0x401100;
    const auto key_c = make_decompile_cache_key(req_c, settings);
    DecompiledUnit ready_c = ready_a;
    ready_c.lines = {DecompiledLine{0x401100, "int func_c(void)", {}}};
    cache.put(key_c, ready_c);

    EXPECT_EQ(cache.size(), 2u);
    EXPECT_TRUE(cache.get(key_a).has_value());
    EXPECT_FALSE(cache.get(key_b).has_value());
    EXPECT_TRUE(cache.get(key_c).has_value());

    cache.invalidate_function(req_a.binary_sha256, 0x401000);
    EXPECT_FALSE(cache.get(key_a).has_value());
    EXPECT_TRUE(cache.get(key_c).has_value());
}

TEST(Decompiler, GhidraWorkspaceColdImportThenWarmProcessReuseAndInvalidation) {
    struct TempDir {
        std::filesystem::path path;
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    } temp{std::filesystem::temp_directory_path() / "peelf-ghidra-wu02-reuse-test"};
    std::filesystem::remove_all(temp.path);

    const auto ghidra_home = temp.path / "ghidra_install";
    const auto scripts_dir = temp.path / "scripts";
    const auto cache_dir = temp.path / "cache";
    std::filesystem::create_directories(ghidra_home / "Ghidra/Framework/Utility/lib");
    std::filesystem::create_directories(scripts_dir);
    std::ofstream(ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").put('J');
    std::ofstream(scripts_dir / "PeelfDecompile.java").put('/');

    struct InvocationRecord {
        bool had_import = false;
        bool had_process = false;
        bool had_noanalysis = false;
        bool had_delete_project = false;
        bool had_prescript = false;
        std::string post_phase;
        std::filesystem::path project_dir;
        std::string symbols_manifest;
    };

    struct StatefulGhidraRunner final : IBackendRunner {
        mutable std::vector<InvocationRecord> calls;
        BackendProcessResult run(const std::filesystem::path&,
                                 const std::vector<std::string>& args,
                                 std::chrono::milliseconds,
                                 std::stop_token) const override {
            InvocationRecord rec;
            const auto headless = std::ranges::find(args, "ghidra.app.util.headless.AnalyzeHeadless");
            if (headless != args.end() && std::next(headless) != args.end()) {
                rec.project_dir = *std::next(headless);
            }
            rec.had_import = std::ranges::find(args, "-import") != args.end();
            const auto proc_it = std::ranges::find(args, "-process");
            rec.had_process = proc_it != args.end() && std::next(proc_it) != args.end() &&
                              *std::next(proc_it) == "input.bin";
            rec.had_noanalysis = std::ranges::find(args, "-noanalysis") != args.end();
            rec.had_delete_project = std::ranges::find(args, "-deleteProject") != args.end();
            rec.had_prescript = std::ranges::find(args, "-preScript") != args.end();

            const auto post = std::ranges::find(args, "-postScript");
            if (post != args.end() && std::distance(post, args.end()) > 6) {
                rec.post_phase = *std::next(post, 2);
                const std::filesystem::path output(*std::next(post, 3));
                const std::string addr_str = *std::next(post, 4);
                const std::filesystem::path sym_path(*std::next(post, 6));
                std::ifstream sym_in(sym_path, std::ios::binary);
                std::ostringstream ss;
                ss << sym_in.rdbuf();
                rec.symbols_manifest = ss.str();

                if (rec.had_import && !rec.project_dir.empty()) {
                    std::ofstream(rec.project_dir / "analysis.gpr") << "project";
                }
                std::ofstream(output) << "PEELF_DECOMPILE 2 ready \"Ghidra\" 1 " << addr_str
                                      << " \"return 0;\"";
            }
            calls.push_back(std::move(rec));
            return {0};
        }
    } runner;

    DecompilerSettings settings;
    settings.ghidra_home = ghidra_home;
    settings.cache_directory = cache_dir;
    settings.max_cached_workspaces = 3;
    settings.reuse_analysis = true;

    GhidraDecompiler backend(settings, scripts_dir, runner);

    DecompileRequest req;
    req.address = 0x401000;
    req.architecture = peelf::Architecture::X86_64;
    req.image_bytes = {0x7Fu, 'E', 'L', 'F', 0x90u, 0xC3u};
    req.binary_sha256 = peelf::sha256_hex(req.image_bytes);
    req.symbols = {
        {.name = "func_alpha", .virtual_address = 0x401000, .size = 16, .function = true},
        {.name = "func_beta", .virtual_address = 0x401080, .size = 16, .function = true},
    };

    // 1. Cold miss on func_alpha -> uses -import without -deleteProject.
    const auto res1 = backend.decompile(req);
    ASSERT_EQ(res1.status, DecompileStatus::Ready) << res1.diagnostic;
    EXPECT_EQ(res1.cache_source, DecompileCacheSource::FreshAnalysis);
    ASSERT_EQ(runner.calls.size(), 1u);
    EXPECT_TRUE(runner.calls[0].had_import);
    EXPECT_FALSE(runner.calls[0].had_process);
    EXPECT_FALSE(runner.calls[0].had_delete_project);
    EXPECT_TRUE(runner.calls[0].had_prescript);
    EXPECT_EQ(runner.calls[0].post_phase, "export");
    const auto first_project_dir = runner.calls[0].project_dir;
    EXPECT_TRUE(std::filesystem::exists(first_project_dir / "analysis.gpr"));

    // 2. Warm switch to func_beta in same binary -> uses -process input.bin -noanalysis!
    req.address = 0x401080;
    const auto res2 = backend.decompile(req);
    ASSERT_EQ(res2.status, DecompileStatus::Ready) << res2.diagnostic;
    EXPECT_EQ(res2.cache_source, DecompileCacheSource::ReusedWorkspace);
    ASSERT_EQ(runner.calls.size(), 2u);
    EXPECT_FALSE(runner.calls[1].had_import);
    EXPECT_TRUE(runner.calls[1].had_process);
    EXPECT_TRUE(runner.calls[1].had_noanalysis);
    EXPECT_FALSE(runner.calls[1].had_prescript);
    EXPECT_EQ(runner.calls[1].post_phase, "export_warm");
    EXPECT_EQ(runner.calls[1].project_dir, first_project_dir);

    // 3. Symbol rename without byte edits -> warm -process with incremental export_sync!
    req.symbols[1].name = "authenticate_user";
    const auto res3 = backend.decompile(req);
    ASSERT_EQ(res3.status, DecompileStatus::Ready);
    EXPECT_EQ(res3.cache_source, DecompileCacheSource::ReusedWorkspace);
    ASSERT_EQ(runner.calls.size(), 3u);
    EXPECT_FALSE(runner.calls[2].had_import);
    EXPECT_TRUE(runner.calls[2].had_process);
    EXPECT_TRUE(runner.calls[2].had_noanalysis);
    EXPECT_EQ(runner.calls[2].post_phase, "export_sync");
    // Hex encoding of "authenticate_user" appears in symbol manifest.
    EXPECT_NE(runner.calls[2].symbols_manifest.find("61757468656e7469636174655f75736572"),
              std::string::npos);

    // 4. Subsequent function switch with already-synced symbols returns to export_warm.
    req.address = 0x401000;
    const auto res4 = backend.decompile(req);
    ASSERT_EQ(res4.status, DecompileStatus::Ready);
    ASSERT_EQ(runner.calls.size(), 4u);
    EXPECT_EQ(runner.calls[3].post_phase, "export_warm");

    // 5. Byte patch / SHA-256 change invalidates cached project and runs fresh -import.
    req.image_bytes[4] = 0xCCu;
    req.patch_revision = 1;
    req.binary_sha256 = peelf::sha256_hex(req.image_bytes);
    const auto res5 = backend.decompile(req);
    ASSERT_EQ(res5.status, DecompileStatus::Ready);
    EXPECT_EQ(res5.cache_source, DecompileCacheSource::FreshAnalysis);
    ASSERT_EQ(runner.calls.size(), 5u);
    EXPECT_TRUE(runner.calls[4].had_import);
    EXPECT_NE(runner.calls[4].project_dir, first_project_dir);

    // 6. Explicit force_reanalyze rebuilds even an already-warm workspace via -import.
    req.force_reanalyze = true;
    const auto res6 = backend.decompile(req);
    ASSERT_EQ(res6.status, DecompileStatus::Ready);
    EXPECT_EQ(res6.cache_source, DecompileCacheSource::FreshAnalysis);
    ASSERT_EQ(runner.calls.size(), 6u);
    EXPECT_TRUE(runner.calls[5].had_import);
    EXPECT_EQ(runner.calls[5].project_dir, runner.calls[4].project_dir);
}

TEST(Decompiler, GhidraWarmFailureRecoversViaCleanColdReimport) {
    struct TempDir {
        std::filesystem::path path;
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    } temp{std::filesystem::temp_directory_path() / "peelf-ghidra-wu02-recovery-test"};
    std::filesystem::remove_all(temp.path);

    const auto ghidra_home = temp.path / "ghidra_install";
    const auto scripts_dir = temp.path / "scripts";
    const auto cache_dir = temp.path / "cache";
    std::filesystem::create_directories(ghidra_home / "Ghidra/Framework/Utility/lib");
    std::filesystem::create_directories(scripts_dir);
    std::ofstream(ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").put('J');
    std::ofstream(scripts_dir / "PeelfDecompile.java").put('/');

    struct CorruptProcessRunner final : IBackendRunner {
        mutable std::vector<std::string> modes;
        mutable bool fail_warm_process = false;
        BackendProcessResult run(const std::filesystem::path&,
                                 const std::vector<std::string>& args,
                                 std::chrono::milliseconds,
                                 std::stop_token) const override {
            const bool is_import = std::ranges::find(args, "-import") != args.end();
            modes.push_back(is_import ? "import" : "process");
            if (!is_import && fail_warm_process) {
                return {1};
            }
            const auto headless = std::ranges::find(args, "ghidra.app.util.headless.AnalyzeHeadless");
            if (is_import && headless != args.end() && std::next(headless) != args.end()) {
                std::ofstream(std::filesystem::path(*std::next(headless)) / "analysis.gpr") << "ok";
            }
            const auto post = std::ranges::find(args, "-postScript");
            if (post != args.end() && std::distance(post, args.end()) > 4) {
                const std::filesystem::path output(*std::next(post, 3));
                std::ofstream(output) << "PEELF_DECOMPILE 2 ready \"Ghidra\" 1 4096 \"recovered();\"";
            }
            return {0};
        }
    } runner;

    DecompilerSettings settings;
    settings.ghidra_home = ghidra_home;
    settings.cache_directory = cache_dir;
    GhidraDecompiler backend(settings, scripts_dir, runner);

    DecompileRequest req;
    req.address = 4096;
    req.architecture = peelf::Architecture::X86_64;
    req.image_bytes = {1, 2, 3, 4};

    ASSERT_EQ(backend.decompile(req).status, DecompileStatus::Ready);
    ASSERT_EQ(runner.modes, (std::vector<std::string>{"import"}));

    // Corrupt warm run fails -> backend wipes cached workspace and retries cold import once.
    runner.fail_warm_process = true;
    req.address = 4128;
    const auto recovered = backend.decompile(req);
    ASSERT_EQ(recovered.status, DecompileStatus::Ready) << recovered.diagnostic;
    EXPECT_EQ(recovered.cache_source, DecompileCacheSource::FreshAnalysis);
    EXPECT_EQ(runner.modes, (std::vector<std::string>{"import", "process", "import"}));
}

TEST(Decompiler, GhidraWorkspaceLruEvictionAndCacheRootOffMntC) {
    const auto default_root = default_ghidra_cache_directory().generic_string();
    EXPECT_FALSE(default_root.empty());
#ifndef _WIN32
    std::string lowered = default_root;
    std::ranges::transform(lowered, lowered.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    EXPECT_FALSE(lowered == "/mnt/c" || lowered.starts_with("/mnt/c/")) << default_root;
#endif

    struct TempDir {
        std::filesystem::path path;
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    } temp{std::filesystem::temp_directory_path() / "peelf-ghidra-wu02-lru-test"};
    std::filesystem::remove_all(temp.path);

    const auto ghidra_home = temp.path / "ghidra_install";
    const auto scripts_dir = temp.path / "scripts";
    const auto cache_dir = temp.path / "cache";
    std::filesystem::create_directories(ghidra_home / "Ghidra/Framework/Utility/lib");
    std::filesystem::create_directories(scripts_dir);
    std::ofstream(ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").put('J');
    std::ofstream(scripts_dir / "PeelfDecompile.java").put('/');

    struct SimpleRunner final : IBackendRunner {
        mutable std::vector<std::filesystem::path> projects;
        BackendProcessResult run(const std::filesystem::path&,
                                 const std::vector<std::string>& args,
                                 std::chrono::milliseconds,
                                 std::stop_token) const override {
            const auto headless = std::ranges::find(args, "ghidra.app.util.headless.AnalyzeHeadless");
            std::filesystem::path proj;
            if (headless != args.end() && std::next(headless) != args.end()) {
                proj = *std::next(headless);
                projects.push_back(proj);
                if (std::ranges::find(args, "-import") != args.end()) {
                    std::ofstream(proj / "analysis.gpr") << "ok";
                }
            }
            const auto post = std::ranges::find(args, "-postScript");
            if (post != args.end() && std::distance(post, args.end()) > 4) {
                std::ofstream(std::filesystem::path(*std::next(post, 3)))
                    << "PEELF_DECOMPILE 2 ready \"Ghidra\" 1 4096 \"ok();\"";
            }
            return {0};
        }
    } runner;

    DecompilerSettings settings;
    settings.ghidra_home = ghidra_home;
    settings.cache_directory = cache_dir;
    settings.max_cached_workspaces = 2;
    GhidraDecompiler backend(settings, scripts_dir, runner);

    DecompileRequest req1;
    req1.address = 4096;
    req1.architecture = peelf::Architecture::X86_64;
    req1.image_bytes = {1, 0, 0};
    DecompileRequest req2 = req1;
    req2.image_bytes = {2, 0, 0};
    DecompileRequest req3 = req1;
    req3.image_bytes = {3, 0, 0};

    ASSERT_EQ(backend.decompile(req1).status, DecompileStatus::Ready);
    const auto ws1 = runner.projects.back();
    ASSERT_EQ(backend.decompile(req2).status, DecompileStatus::Ready);
    const auto ws2 = runner.projects.back();

    // Touch ws1 via warm reuse so ws2 becomes LRU victim when ws3 arrives.
    req1.address = 4112;
    ASSERT_EQ(backend.decompile(req1).cache_source, DecompileCacheSource::ReusedWorkspace);

    ASSERT_EQ(backend.decompile(req3).status, DecompileStatus::Ready);
    const auto ws3 = runner.projects.back();

    EXPECT_TRUE(std::filesystem::exists(ws1));
    EXPECT_FALSE(std::filesystem::exists(ws2));
    EXPECT_TRUE(std::filesystem::exists(ws3));

    backend.clear_cached_workspaces();
    EXPECT_FALSE(std::filesystem::exists(ws1));
    EXPECT_FALSE(std::filesystem::exists(ws3));
}
