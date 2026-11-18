#include "decompile/decompile_controller.hpp"
#include "decompile/decompiler.hpp"
#include "decompile/structured_decompiler.hpp"
#include <peelf/sha256.hpp>
#include <gtest/gtest.h>
#include <atomic>
#include <condition_variable>
#include <fstream>
#include "model/binary_model.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "symbols/debug_symbols.hpp"
using namespace viewer;

namespace {

[[nodiscard]] unsigned long current_test_pid() noexcept {
#ifdef _WIN32
    return static_cast<unsigned long>(::GetCurrentProcessId());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

[[nodiscard]] std::optional<std::string> read_env_var(const char* name) {
#ifdef _WIN32
    char* buf = nullptr;
    std::size_t len = 0;
    if (_dupenv_s(&buf, &len, name) != 0 || buf == nullptr) {
        return std::nullopt;
    }
    std::string val(buf);
    std::free(buf);
    return val;
#else
    const char* val = std::getenv(name);
    if (val == nullptr) {
        return std::nullopt;
    }
    return std::string(val);
#endif
}

void write_env_var(const char* name, const std::optional<std::string>& value) {
#ifdef _WIN32
    (void)_putenv_s(name, value.has_value() ? value->c_str() : "");
#else
    if (value.has_value()) {
        (void)::setenv(name, value->c_str(), 1);
    } else {
        (void)::unsetenv(name);
    }
#endif
}

[[nodiscard]] std::filesystem::path safe_test_temp_root() {
    std::error_code ec;
    auto base = std::filesystem::temp_directory_path(ec);
#ifndef _WIN32
    std::string generic = base.generic_string();
    std::ranges::transform(generic, generic.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (ec || base.empty() || generic == "/mnt/c" || generic.starts_with("/mnt/c/")) {
        return "/tmp";
    }
#endif
    return base;
}

class IsolatedGhidraCacheEnvironment final : public ::testing::Environment {
public:
    IsolatedGhidraCacheEnvironment()
        : prior_peelf_cache_dir_(read_env_var("PEELF_CACHE_DIR"))
        , isolated_dir_(safe_test_temp_root() / std::format(
              "peelf-decompiler-test-cache-{}-{}",
              current_test_pid(),
              std::chrono::steady_clock::now().time_since_epoch().count())) {
        activate();
    }

    IsolatedGhidraCacheEnvironment(const IsolatedGhidraCacheEnvironment&) = delete;
    IsolatedGhidraCacheEnvironment& operator=(const IsolatedGhidraCacheEnvironment&) = delete;
    IsolatedGhidraCacheEnvironment(IsolatedGhidraCacheEnvironment&&) = delete;
    IsolatedGhidraCacheEnvironment& operator=(IsolatedGhidraCacheEnvironment&&) = delete;

    ~IsolatedGhidraCacheEnvironment() noexcept override {
        cleanup();
    }

    void SetUp() override {
        activate();
    }

    void TearDown() override {
        cleanup();
    }

    [[nodiscard]] const std::filesystem::path& isolated_dir() const noexcept {
        return isolated_dir_;
    }

private:
    void activate() {
        std::error_code ec;
        std::filesystem::create_directories(isolated_dir_, ec);
        std::filesystem::permissions(
            isolated_dir_,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec);
        write_env_var("PEELF_CACHE_DIR", isolated_dir_.string());
        active_ = true;
    }

    void cleanup() noexcept {
        if (!active_) {
            return;
        }
        try {
            write_env_var("PEELF_CACHE_DIR", prior_peelf_cache_dir_);
        } catch (...) {
        }
        std::error_code ec;
        std::filesystem::remove_all(isolated_dir_, ec);
        active_ = false;
    }

    std::optional<std::string> prior_peelf_cache_dir_;
    std::filesystem::path isolated_dir_;
    bool active_ = false;
};

// NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
const auto* const g_isolated_ghidra_cache_env = static_cast<IsolatedGhidraCacheEnvironment*>(
    ::testing::AddGlobalTestEnvironment(new IsolatedGhidraCacheEnvironment()));

} // namespace

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
    DecompilerSettings settings;
    settings.provider = DecompilerProvider::RetDec;
    settings.ghidra_home = "path with spaces";
    settings.java = "custom/java";
    settings.python = "custom/python3";
    settings.retdec = "/opt/retdec custom/bin/retdec-decompiler";
    settings.timeout_seconds = 320;
    settings.cache_directory = "/tmp/peelf cache dir";
    settings.max_cached_workspaces = 7;
    settings.reuse_analysis = false;
    ASSERT_TRUE(save_decompiler_settings(path, settings));
    auto restored = read_decompiler_settings(path);
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->provider, DecompilerProvider::RetDec);
    EXPECT_EQ(restored->ghidra_home, settings.ghidra_home);
    EXPECT_EQ(restored->java, settings.java);
    EXPECT_EQ(restored->python, settings.python);
    EXPECT_EQ(restored->retdec, settings.retdec);
    EXPECT_EQ(restored->timeout_seconds, 320);
    EXPECT_EQ(restored->cache_directory, settings.cache_directory);
    EXPECT_EQ(restored->max_cached_workspaces, 7u);
    EXPECT_FALSE(restored->reuse_analysis);

    // Backward compatibility with legacy v1 settings files (defaults retdec & cache settings).
    {
        std::ofstream file(path, std::ios::trunc);
        file << "PEELF_DECOMPILER 1\n4\n\"/opt/ghidra\"\n\"java\"\n\"python3\"\n240\n";
    }
    auto legacy = read_decompiler_settings(path);
    ASSERT_TRUE(legacy) << legacy.error().message;
    EXPECT_EQ(legacy->provider, DecompilerProvider::RetDec);
    EXPECT_EQ(legacy->ghidra_home, std::filesystem::path("/opt/ghidra"));
    EXPECT_EQ(legacy->retdec, std::filesystem::path("retdec-decompiler"));
    EXPECT_EQ(legacy->timeout_seconds, 240);
    EXPECT_EQ(legacy->max_cached_workspaces, 3u);
    EXPECT_TRUE(legacy->reuse_analysis);

    // Validation rejects out-of-range provider, empty retdec, or invalid cache settings.
    { std::ofstream file(path, std::ios::trunc); file << "PEELF_DECOMPILER 1 99 \"\" \"java\" \"python\" 20"; }
    EXPECT_FALSE(read_decompiler_settings(path));
    { std::ofstream file(path, std::ios::trunc); file << "PEELF_DECOMPILER 2 4 \"\" \"java\" \"python\" \"\" 20 \"\" 3 1"; }
    EXPECT_FALSE(read_decompiler_settings(path));
    { std::ofstream file(path, std::ios::trunc); file << "PEELF_DECOMPILER 2 0 \"\" \"java\" \"python\" \"retdec\" 20 \"\" 0 1"; }
    EXPECT_FALSE(read_decompiler_settings(path));
    std::filesystem::remove(path);
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
        explicit TempDir(std::filesystem::path p) : path(std::move(p)) {}
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;
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
        explicit TempDir(std::filesystem::path p) : path(std::move(p)) {}
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;
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
        explicit TempDir(std::filesystem::path p) : path(std::move(p)) {}
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;
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

TEST(DecompileController, BurstOfRequestsCancelsIntermediatesAndDeliversLatest) {
    std::mutex gate_mutex;
    std::condition_variable_any gate_cv;
    bool first_job_started = false;
    std::vector<std::uint64_t> executed_addresses;

    DecompileController controller(
        [&](const DecompileJobSpec& spec, std::stop_token stop_token) -> DecompiledUnit {
            {
                std::scoped_lock lock(gate_mutex);
                executed_addresses.push_back(spec.request.address);
                if (spec.request.address == 0x1001u) {
                    first_job_started = true;
                    gate_cv.notify_all();
                }
            }
            if (spec.request.address == 0x1001u) {
                std::unique_lock lock(gate_mutex);
                gate_cv.wait_for(lock, stop_token, std::chrono::seconds(5), [] { return false; });
                if (stop_token.stop_requested()) {
                    return DecompiledUnit{
                        .status = DecompileStatus::Cancelled,
                        .provider = "Mock",
                        .diagnostic = "cancelled",
                    };
                }
            }
            DecompiledUnit out;
            out.status = DecompileStatus::Ready;
            out.provider = "Mock";
            out.diagnostic = std::format("fn_0x{:X}", spec.request.address);
            out.lines.push_back({.address = spec.request.address, .text = out.diagnostic});
            return out;
        });

    const DecompileValidationStamp stamp{
        .target_identity = "sha256:abc123",
        .file_generation = 1,
        .edit_revision = 2,
        .snapshot_revision = 3,
    };

    // Submit request #1 and wait until it is actively running on the worker jthread.
    {
        DecompileJobSpec first;
        first.request.address = 0x1001u;
        first.stamp = stamp;
        EXPECT_EQ(controller.submit(std::move(first)), 1u);
    }
    {
        std::unique_lock lock(gate_mutex);
        ASSERT_TRUE(gate_cv.wait_for(lock, std::chrono::seconds(5), [&] { return first_job_started; }));
    }

    // Rapidly submit requests #2..#10 while request #1 is winding down.
    std::uint64_t final_seq = 0;
    for (std::uint64_t idx = 2; idx <= 10; ++idx) {
        DecompileJobSpec spec;
        spec.request.address = 0x1000u + idx;
        spec.stamp = stamp;
        spec.root_symbol = SymbolRecord{
            .name = std::format("sub_{:X}", spec.request.address),
            .virtual_address = spec.request.address,
            .function = true,
        };
        final_seq = controller.submit(std::move(spec));
    }
    EXPECT_EQ(final_seq, 10u);

    controller.wait_for_idle();
    EXPECT_FALSE(controller.is_busy());

    const auto completed = controller.poll_completed(stamp);
    ASSERT_TRUE(completed.has_value());
    EXPECT_EQ(completed->sequence, 10u);
    EXPECT_EQ(completed->unit.status, DecompileStatus::Ready);
    EXPECT_EQ(completed->unit.diagnostic, "fn_0x100A");
    ASSERT_TRUE(completed->root_symbol.has_value());
    EXPECT_EQ(completed->root_symbol->virtual_address, 0x100Au);

    {
        std::scoped_lock lock(gate_mutex);
        ASSERT_GE(executed_addresses.size(), 2u);
        EXPECT_EQ(executed_addresses.front(), 0x1001u);
        EXPECT_EQ(executed_addresses.back(), 0x100Au);
        EXPECT_LT(executed_addresses.size(), 10u);
    }
}

TEST(DecompileController, RejectsStaleCompletionsAcrossTargetEditAndSnapshotRevisions) {
    DecompileController controller(
        [](const DecompileJobSpec& spec, std::stop_token) -> DecompiledUnit {
            DecompiledUnit unit;
            unit.status = DecompileStatus::Ready;
            unit.provider = "Mock";
            unit.diagnostic = std::format("addr=0x{:X}", spec.request.address);
            return unit;
        });

    const DecompileValidationStamp base_stamp{
        .target_identity = "sha256:binA",
        .file_generation = 4,
        .edit_revision = 7,
        .snapshot_revision = 11,
    };

    auto submit_with_base = [&](std::uint64_t va) {
        DecompileJobSpec spec;
        spec.request.address = va;
        spec.stamp = base_stamp;
        (void)controller.submit(std::move(spec));
        controller.wait_for_idle();
    };

    // 1. Target identity mismatch (new binary opened): discarded without same-target stale flag.
    submit_with_base(0x401000u);
    DecompileValidationStamp wrong_target = base_stamp;
    wrong_target.target_identity = "sha256:binB";
    EXPECT_FALSE(controller.poll_completed(wrong_target).has_value());
    EXPECT_FALSE(controller.consume_stale_discard_notice());

    // 2. Edit revision mismatch (bytes patched during decompile): discarded + stale notice set.
    submit_with_base(0x401020u);
    DecompileValidationStamp wrong_edit = base_stamp;
    wrong_edit.edit_revision = 8;
    EXPECT_FALSE(controller.poll_completed(wrong_edit).has_value());
    EXPECT_TRUE(controller.consume_stale_discard_notice());
    EXPECT_FALSE(controller.consume_stale_discard_notice());

    // 3. Snapshot revision mismatch (symbols/annotations edited during decompile): discarded + stale notice set.
    submit_with_base(0x401040u);
    DecompileValidationStamp wrong_snapshot = base_stamp;
    wrong_snapshot.snapshot_revision = 12;
    EXPECT_FALSE(controller.poll_completed(wrong_snapshot).has_value());
    EXPECT_TRUE(controller.consume_stale_discard_notice());

    // 4. Exact match succeeds.
    submit_with_base(0x401060u);
    const auto valid = controller.poll_completed(base_stamp);
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(valid->unit.diagnostic, "addr=0x401060");
    EXPECT_FALSE(controller.consume_stale_discard_notice());
}

TEST(DecompileController, CancelResetAndDestructorWhileBusyJoinCleanly) {
    std::mutex mutex;
    std::condition_variable_any cv;
    bool running = false;

    auto blocking_worker = [&](const DecompileJobSpec&, std::stop_token stop_token) -> DecompiledUnit {
        {
            std::scoped_lock lock(mutex);
            running = true;
            cv.notify_all();
        }
        std::unique_lock lock(mutex);
        cv.wait_for(lock, stop_token, std::chrono::seconds(5), [] { return false; });
        return DecompiledUnit{
            .status = stop_token.stop_requested() ? DecompileStatus::Cancelled : DecompileStatus::Ready,
            .provider = "Mock",
            .diagnostic = stop_token.stop_requested() ? "Cancelled" : "Done",
        };
    };

    const DecompileValidationStamp stamp{
        .target_identity = "sha256:cancel-test",
        .file_generation = 1,
        .edit_revision = 0,
        .snapshot_revision = 0,
    };

    {
        DecompileController controller(blocking_worker);
        DecompileJobSpec spec;
        spec.request.address = 0x5000u;
        spec.stamp = stamp;
        (void)controller.submit(std::move(spec));
        {
            std::unique_lock lock(mutex);
            ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(5), [&] { return running; }));
            running = false;
        }

        controller.cancel_current();
        controller.wait_for_idle();
        const auto cancelled = controller.poll_completed(stamp);
        ASSERT_TRUE(cancelled.has_value());
        EXPECT_EQ(cancelled->unit.status, DecompileStatus::Cancelled);

        // Resetting for a new target cancels in-flight work and drops its output.
        spec = {};
        spec.request.address = 0x5010u;
        spec.stamp = stamp;
        (void)controller.submit(std::move(spec));
        {
            std::unique_lock lock(mutex);
            ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(5), [&] { return running; }));
            running = false;
        }
        controller.reset_for_new_target();
        controller.wait_for_idle();
        EXPECT_FALSE(controller.poll_completed(stamp).has_value());

        // Destroying controller while busy requests stop and joins jthread without hanging.
        spec = {};
        spec.request.address = 0x5020u;
        spec.stamp = stamp;
        (void)controller.submit(std::move(spec));
        {
            std::unique_lock lock(mutex);
            ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(5), [&] { return running; }));
        }
    }
}

TEST(DecompileController, WorkerContainsStdExceptionBadAllocAndUnknownThrows) {
    const DecompileValidationStamp stamp{
        .target_identity = "sha256:exception-boundary-test",
        .file_generation = 1,
        .edit_revision = 0,
        .snapshot_revision = 0,
    };

    DecompileController controller(
        [](const DecompileJobSpec& job, std::stop_token) -> DecompiledUnit {
            if (job.request.address == 0x6001u) {
                throw std::runtime_error("simulated backend runtime_error");
            }
            if (job.request.address == 0x6002u) {
                throw std::bad_alloc{};
            }
            if (job.request.address == 0x6003u) {
                throw 42;
            }
            return DecompiledUnit{
                .status = DecompileStatus::Ready,
                .provider = "Mock",
                .diagnostic = "recovered",
            };
        });

    auto run_job = [&](std::uint64_t address) -> DecompiledUnit {
        DecompileJobSpec spec;
        spec.request.address = address;
        spec.stamp = stamp;
        (void)controller.submit(std::move(spec));
        controller.wait_for_idle();
        const auto res = controller.poll_completed(stamp);
        EXPECT_TRUE(res.has_value());
        return res ? res->unit : DecompiledUnit{};
    };

    const DecompiledUnit err_std = run_job(0x6001u);
    EXPECT_EQ(err_std.status, DecompileStatus::Failed);
    EXPECT_NE(err_std.diagnostic.find("simulated backend runtime_error"), std::string::npos);

    const DecompiledUnit err_oom = run_job(0x6002u);
    EXPECT_EQ(err_oom.status, DecompileStatus::Failed);
    EXPECT_NE(err_oom.diagnostic.find("Out of memory"), std::string::npos);

    const DecompiledUnit err_unknown = run_job(0x6003u);
    EXPECT_EQ(err_unknown.status, DecompileStatus::Failed);
    EXPECT_NE(err_unknown.diagnostic.find("Unhandled exception"), std::string::npos);

    // Controller worker loop survives all three exception classes and still processes normal jobs.
    const DecompiledUnit ok = run_job(0x6004u);
    EXPECT_EQ(ok.status, DecompileStatus::Ready);
    EXPECT_EQ(ok.diagnostic, "recovered");
}

TEST(Decompiler, DecompileCacheZeroCapacityAndLruUpdateConsistency) {
    DecompileRequest base_req;
    base_req.binary_sha256 = std::string(64, 'c');
    base_req.architecture = peelf::Architecture::X86_64;
    base_req.function_size = 32;

    DecompilerSettings settings;
    settings.provider = DecompilerProvider::RetDec;
    settings.retdec = "/opt/retdec-a/retdec-decompiler";

    auto make_key = [&](std::uint64_t addr) {
        auto r = base_req;
        r.address = addr;
        return make_decompile_cache_key(r, settings);
    };
    auto make_ready = [](std::string text) {
        DecompiledUnit u;
        u.status = DecompileStatus::Ready;
        u.provider = "RetDec";
        u.lines.push_back(DecompiledLine{0x1000, std::move(text), {}});
        return u;
    };

    // Zero-capacity construction clamps to minimum capacity 1, evicting older entry post-insert.
    DecompileCache min_cache(0);
    min_cache.put(make_key(0x1000), make_ready("first"));
    EXPECT_EQ(min_cache.size(), 1u);
    min_cache.put(make_key(0x2000), make_ready("second"));
    EXPECT_EQ(min_cache.size(), 1u);
    EXPECT_FALSE(min_cache.get(make_key(0x1000)).has_value());
    EXPECT_TRUE(min_cache.get(make_key(0x2000)).has_value());

    // Capacity-3 LRU consistency across insert, in-place overwrite, get promotion, and eviction.
    DecompileCache cache(3);
    const auto k1 = make_key(0x1000);
    const auto k2 = make_key(0x2000);
    const auto k3 = make_key(0x3000);
    const auto k4 = make_key(0x4000);

    cache.put(k1, make_ready("v1"));
    cache.put(k2, make_ready("v2"));
    cache.put(k3, make_ready("v3"));
    EXPECT_EQ(cache.size(), 3u);

    // Overwriting k1 promotes k1 to MRU, leaving k2 as LRU.
    cache.put(k1, make_ready("v1_updated"));
    EXPECT_EQ(cache.size(), 3u);

    // Inserting k4 evicts k2 (LRU) after inserting k4, keeping k4, k1, k3 intact.
    cache.put(k4, make_ready("v4"));
    EXPECT_EQ(cache.size(), 3u);
    EXPECT_FALSE(cache.get(k2).has_value());
    ASSERT_TRUE(cache.get(k1).has_value());
    EXPECT_EQ(cache.get(k1)->lines[0].text, "v1_updated");
    EXPECT_TRUE(cache.get(k3).has_value());
    EXPECT_TRUE(cache.get(k4).has_value());

    // Changing RetDec executable path produces a distinct cache key fingerprint.
    auto alt_settings = settings;
    alt_settings.retdec = "/opt/retdec-b/retdec-decompiler";
    auto alt_req = base_req;
    alt_req.address = 0x1000;
    EXPECT_FALSE(cache.get(make_decompile_cache_key(alt_req, alt_settings)).has_value());
}

TEST(Decompiler, DefaultGhidraCacheIsIsolatedInTestProcessAndEnforcesPrivatePermissionsAndLock) {
    ASSERT_NE(g_isolated_ghidra_cache_env, nullptr);
    const auto resolved_default = default_ghidra_cache_directory();
    EXPECT_EQ(resolved_default, g_isolated_ghidra_cache_env->isolated_dir() / "ghidra");

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::filesystem::path p) : path(std::move(p)) {}
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;
        ~TempDir() noexcept {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    } temp{safe_test_temp_root() / std::format("peelf-ghidra-fbf05b-perm-{}", current_test_pid())};
    std::filesystem::remove_all(temp.path);

    const auto ghidra_home = temp.path / "ghidra_install";
    const auto scripts_dir = temp.path / "scripts";
    const auto cache_dir = temp.path / "cache";
    std::filesystem::create_directories(ghidra_home / "Ghidra/Framework/Utility/lib");
    std::filesystem::create_directories(scripts_dir);
    std::ofstream(ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").put('J');
    std::ofstream(scripts_dir / "PeelfDecompile.java").put('/');

    struct InspectingRunner final : IBackendRunner {
        mutable std::filesystem::path last_project_dir;
        mutable std::filesystem::path last_scratch_dir;
        mutable std::filesystem::perms scratch_perms = std::filesystem::perms::unknown;
        BackendProcessResult run(const std::filesystem::path&,
                                 const std::vector<std::string>& args,
                                 std::chrono::milliseconds,
                                 std::stop_token) const override {
            const auto headless = std::ranges::find(args, "ghidra.app.util.headless.AnalyzeHeadless");
            if (headless != args.end() && std::next(headless) != args.end()) {
                last_project_dir = *std::next(headless);
                if (std::ranges::find(args, "-import") != args.end() &&
                    std::ranges::find(args, "-deleteProject") == args.end()) {
                    std::ofstream(last_project_dir / "analysis.gpr") << "ok";
                }
            }
            const auto post = std::ranges::find(args, "-postScript");
            if (post != args.end() && std::distance(post, args.end()) > 4) {
                const std::filesystem::path out_file(*std::next(post, 3));
                last_scratch_dir = out_file.parent_path();
                std::error_code ec;
                scratch_perms = std::filesystem::status(last_scratch_dir, ec).permissions();
                std::ofstream(out_file) << "PEELF_DECOMPILE 2 ready \"Ghidra\" 1 4096 \"return 7;\"";
            }
            return {0};
        }
    } runner;

    DecompilerSettings settings;
    settings.ghidra_home = ghidra_home;
    settings.cache_directory = cache_dir;
    settings.reuse_analysis = true;

    DecompileRequest req;
    req.address = 4096;
    req.architecture = peelf::Architecture::X86_64;
    req.image_bytes = {0x90u, 0xC3u};

    GhidraDecompiler backend(settings, scripts_dir, runner);
    ASSERT_EQ(backend.decompile(req).status, DecompileStatus::Ready);
    ASSERT_FALSE(runner.last_project_dir.empty());

#ifndef _WIN32
    constexpr auto kGroupOther =
        std::filesystem::perms::group_all | std::filesystem::perms::others_all;
    EXPECT_EQ(runner.scratch_perms & kGroupOther, std::filesystem::perms::none);
    EXPECT_EQ(runner.scratch_perms & std::filesystem::perms::owner_all,
              std::filesystem::perms::owner_all);

    for (const auto& private_dir : {cache_dir, cache_dir / ".locks", runner.last_project_dir}) {
        std::error_code ec;
        const auto perms = std::filesystem::status(private_dir, ec).permissions();
        ASSERT_FALSE(ec) << private_dir;
        EXPECT_EQ(perms & kGroupOther, std::filesystem::perms::none) << private_dir;
        EXPECT_EQ(perms & std::filesystem::perms::owner_all, std::filesystem::perms::owner_all)
            << private_dir;
    }

    // Hold an external exclusive flock on the workspace lockfile and verify decompile waits
    // cooperatively and honours stop_token cancellation instead of corrupting the .gpr project.
    const auto lock_file =
        cache_dir / ".locks" / (runner.last_project_dir.filename().string() + ".lock");
    ASSERT_TRUE(std::filesystem::exists(lock_file));
    const int ext_fd = ::open(lock_file.c_str(), O_RDWR | O_CLOEXEC);
    ASSERT_GE(ext_fd, 0);
    ASSERT_EQ(::flock(ext_fd, LOCK_EX | LOCK_NB), 0);

    std::stop_source cancel_src;
    std::jthread canceller([&cancel_src] {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        cancel_src.request_stop();
    });
    const auto blocked_unit = backend.decompile(req, cancel_src.get_token());
    EXPECT_EQ(blocked_unit.status, DecompileStatus::Cancelled);
    canceller.join();

    (void)::flock(ext_fd, LOCK_UN);
    (void)::close(ext_fd);

    const auto unblocked_unit = backend.decompile(req);
    EXPECT_EQ(unblocked_unit.status, DecompileStatus::Ready);
    EXPECT_EQ(unblocked_unit.cache_source, DecompileCacheSource::ReusedWorkspace);
#endif
}

TEST(DecompileController, StopCallbackReentryDoesNotDeadlockOnCancelSubmitResetOrShutdown) {
    const DecompileValidationStamp stamp{
        .target_identity = "sha256:stop-reentry-test",
        .file_generation = 1,
        .edit_revision = 0,
        .snapshot_revision = 0,
    };

    std::mutex sync_mutex;
    std::condition_variable sync_cv;
    bool callback_armed = false;
    std::atomic<int> reentry_calls{0};

    std::unique_ptr<DecompileController> controller;
    controller = std::make_unique<DecompileController>(
        [&](const DecompileJobSpec&, std::stop_token stop) -> DecompiledUnit {
            std::stop_callback on_stop(stop, [&] {
                (void)controller->is_busy();
                (void)controller->latest_sequence();
                (void)controller->poll_completed(stamp);
                reentry_calls.fetch_add(1, std::memory_order_relaxed);
            });
            {
                std::scoped_lock lock(sync_mutex);
                callback_armed = true;
            }
            sync_cv.notify_all();
            while (!stop.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            return DecompiledUnit{
                .status = DecompileStatus::Cancelled,
                .provider = "Mock",
                .diagnostic = "stopped",
            };
        });

    auto submit_and_wait_armed = [&](std::uint64_t addr) {
        DecompileJobSpec spec;
        spec.request.address = addr;
        spec.stamp = stamp;
        (void)controller->submit(std::move(spec));
        std::unique_lock lock(sync_mutex);
        ASSERT_TRUE(sync_cv.wait_for(lock, std::chrono::seconds(5), [&] { return callback_armed; }));
        callback_armed = false;
    };

    // 1. cancel_current() invokes stop_callback outside mutex_.
    submit_and_wait_armed(0x7001u);
    controller->cancel_current();
    controller->wait_for_idle();

    // 2. submit() superseding an active job invokes stop_callback outside mutex_.
    submit_and_wait_armed(0x7002u);
    submit_and_wait_armed(0x7003u);

    // 3. reset_for_new_target() invokes stop_callback outside mutex_.
    controller->reset_for_new_target();
    controller->wait_for_idle();

    // 4. shutdown() / destructor invokes stop_callback outside mutex_.
    submit_and_wait_armed(0x7004u);
    controller->shutdown();

    EXPECT_GE(reentry_calls.load(std::memory_order_relaxed), 4);
}

namespace {

[[nodiscard]] std::string join_decompiled_lines(const DecompiledUnit& unit) {
    std::string text;
    for (const auto& line : unit.lines) {
        text += line.text;
        text.push_back('\n');
    }
    return text;
}

} // namespace

TEST(StructuredDecompiler, DeepThousandBlockConditionalChainCompletesWithoutStackOverflow) {
    constexpr std::size_t kChainBlocks = 1000u;
    constexpr std::uint64_t kBaseVa = 0x400000u;
    const std::uint64_t exit_va = kBaseVa + static_cast<std::uint64_t>(kChainBlocks) * 8u;

    CallGraph cfg;
    cfg.id = "function_cfg";
    cfg.architecture = peelf::Architecture::X86_64;
    cfg.nodes.reserve(kChainBlocks + 1u);
    cfg.edges.reserve(kChainBlocks * 2u);

    for (std::size_t i = 0; i < kChainBlocks; ++i) {
        const std::uint64_t va = kBaseVa + static_cast<std::uint64_t>(i) * 8u;
        const std::string id = "bb_" + std::to_string(i);
        const std::string next_id = (i + 1u < kChainBlocks)
                                        ? ("bb_" + std::to_string(i + 1u))
                                        : std::string("bb_exit");
        cfg.nodes.push_back(CallGraphNode{
            .id = id,
            .label = std::format("loc_0x{:x}", va),
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{
                .start = GraphAddress{.virtual_address = va},
                .size = 8u,
            },
            .instructions = {
                GraphInstruction{
                    .address = va,
                    .mnemonic = "cmp",
                    .operands = std::format("edi, {}", i),
                },
                GraphInstruction{
                    .address = va + 4u,
                    .mnemonic = "je",
                    .operands = std::format("0x{:x}", exit_va),
                },
            },
        });
        cfg.edges.push_back(CallGraphEdge{
            .from_node_id = id,
            .to_node_id = "bb_exit",
            .kind = CallGraphEdgeKind::ConditionalBranch,
        });
        cfg.edges.push_back(CallGraphEdge{
            .from_node_id = id,
            .to_node_id = next_id,
            .kind = CallGraphEdgeKind::Fallthrough,
        });
    }

    cfg.nodes.push_back(CallGraphNode{
        .id = "bb_exit",
        .label = std::format("loc_0x{:x}", exit_va),
        .kind = CallGraphNodeKind::BasicBlock,
        .bytes = GraphByteRange{
            .start = GraphAddress{.virtual_address = exit_va},
            .size = 2u,
        },
        .instructions = {
            GraphInstruction{.address = exit_va, .mnemonic = "ret", .operands = ""},
        },
    });

    DecompileRequest req;
    req.address = kBaseVa;
    req.architecture = peelf::Architecture::X86_64;
    req.fallback_graph = std::move(cfg);

    const DecompiledUnit unit = StructuredPseudoCDecompiler{}.decompile(req);
    ASSERT_EQ(unit.status, DecompileStatus::Ready) << unit.diagnostic;
    const std::string code = join_decompiled_lines(unit);
    EXPECT_NE(code.find("goto "), std::string::npos);
    EXPECT_NE(code.find("999"), std::string::npos);
}

TEST(StructuredDecompiler, FlagClobberingAddXorAndCallInvalidateStaleCmp) {
    CallGraph cfg;
    cfg.id = "function_cfg";
    cfg.architecture = peelf::Architecture::X86_64;
    cfg.nodes = {
        CallGraphNode{
            .id = "bb_0",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x1000u}, .size = 16u},
            .instructions = {
                {0x1000u, "cmp", "edi, 42"},
                {0x1003u, "add", "eax, 1"},
                {0x1006u, "je", "0x1030"},
            },
        },
        CallGraphNode{
            .id = "bb_1",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x1010u}, .size = 16u},
            .instructions = {
                {0x1010u, "cmp", "esi, 99"},
                {0x1013u, "xor", "ecx, ebx"},
                {0x1016u, "jne", "0x1030"},
            },
        },
        CallGraphNode{
            .id = "bb_2",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x1020u}, .size = 16u},
            .instructions = {
                {0x1020u, "cmp", "edx, 77"},
                {0x1023u, "call", "0x2000"},
                {0x1028u, "je", "0x1030"},
            },
        },
        CallGraphNode{
            .id = "bb_3",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x102Cu}, .size = 4u},
            .instructions = {
                {0x102Cu, "mov", "eax, 0"},
                {0x102Eu, "ret", ""},
            },
        },
        CallGraphNode{
            .id = "bb_exit",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x1030u}, .size = 2u},
            .instructions = {
                {0x1030u, "ret", ""},
            },
        },
    };
    cfg.edges = {
        {"bb_0", "bb_exit", CallGraphEdgeKind::ConditionalBranch, ""},
        {"bb_0", "bb_1", CallGraphEdgeKind::Fallthrough, ""},
        {"bb_1", "bb_exit", CallGraphEdgeKind::ConditionalBranch, ""},
        {"bb_1", "bb_2", CallGraphEdgeKind::Fallthrough, ""},
        {"bb_2", "bb_exit", CallGraphEdgeKind::ConditionalBranch, ""},
        {"bb_2", "bb_3", CallGraphEdgeKind::Fallthrough, ""},
    };

    DecompileRequest req;
    req.address = 0x1000u;
    req.architecture = peelf::Architecture::X86_64;
    req.fallback_graph = std::move(cfg);

    const DecompiledUnit unit = StructuredPseudoCDecompiler{}.decompile(req);
    ASSERT_EQ(unit.status, DecompileStatus::Ready) << unit.diagnostic;
    const std::string code = join_decompiled_lines(unit);

    // None of the three overwritten cmp immediates (42, 99, 77) may appear in synthesized if(...) conditions.
    EXPECT_EQ(code.find("42"), std::string::npos) << code;
    EXPECT_EQ(code.find("99"), std::string::npos) << code;
    EXPECT_EQ(code.find("77"), std::string::npos) << code;
    EXPECT_NE(code.find("eax += 1"), std::string::npos) << code;
    EXPECT_NE(code.find("if (eax != 0)"), std::string::npos) << code;
    EXPECT_NE(code.find("ecx ^= ebx"), std::string::npos) << code;
    EXPECT_NE(code.find("if (ecx == 0)"), std::string::npos) << code;
    EXPECT_NE(code.find("if (flags != 0)"), std::string::npos) << code;
}

TEST(StructuredDecompiler, SwitchPreservesSelectorAndTruncatedBranchEmitsDiagnosticGoto) {
    // 1. Switch selector recovery: jmp qword ptr [rdi*8 + 0x402000] -> switch (rdi)
    CallGraph sw_cfg;
    sw_cfg.id = "function_cfg";
    sw_cfg.architecture = peelf::Architecture::X86_64;
    sw_cfg.nodes = {
        CallGraphNode{
            .id = "bb_0",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x2000u}, .size = 12u},
            .instructions = {
                {0x2000u, "jmp", "qword ptr [rdi*8 + 0x402000]"},
            },
        },
        CallGraphNode{
            .id = "bb_c0",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x2010u}, .size = 4u},
            .instructions = {{0x2010u, "mov", "eax, 10"}, {0x2013u, "ret", ""}},
        },
        CallGraphNode{
            .id = "bb_c1",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x2020u}, .size = 4u},
            .instructions = {{0x2020u, "mov", "eax, 20"}, {0x2023u, "ret", ""}},
        },
    };
    sw_cfg.edges = {
        {"bb_0", "bb_c0", CallGraphEdgeKind::UnconditionalBranch, "case 0"},
        {"bb_0", "bb_c1", CallGraphEdgeKind::UnconditionalBranch, "case 1"},
    };

    DecompileRequest sw_req;
    sw_req.address = 0x2000u;
    sw_req.architecture = peelf::Architecture::X86_64;
    sw_req.fallback_graph = std::move(sw_cfg);
    const DecompiledUnit sw_unit = StructuredPseudoCDecompiler{}.decompile(sw_req);
    ASSERT_EQ(sw_unit.status, DecompileStatus::Ready) << sw_unit.diagnostic;
    const std::string sw_code = join_decompiled_lines(sw_unit);
    EXPECT_NE(sw_code.find("switch (rdi)"), std::string::npos) << sw_code;
    EXPECT_EQ(sw_code.find("switch (selector)"), std::string::npos) << sw_code;

    // 2. Truncated conditional branch: taken arm exists (0x3020), fallthrough (0x3006) was truncated out.
    CallGraph trunc_cfg;
    trunc_cfg.id = "function_cfg";
    trunc_cfg.architecture = peelf::Architecture::X86_64;
    trunc_cfg.nodes = {
        CallGraphNode{
            .id = "bb_0",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x3000u}, .size = 6u},
            .instructions = {
                {0x3000u, "cmp", "edi, 0"},
                {0x3003u, "je", "0x3020"},
            },
        },
        CallGraphNode{
            .id = "bb_taken",
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = 0x3020u}, .size = 2u},
            .instructions = {
                {0x3020u, "ret", ""},
            },
        },
    };
    trunc_cfg.edges = {
        {"bb_0", "bb_taken", CallGraphEdgeKind::ConditionalBranch, ""},
    };

    DecompileRequest trunc_req;
    trunc_req.address = 0x3000u;
    trunc_req.architecture = peelf::Architecture::X86_64;
    trunc_req.fallback_graph = std::move(trunc_cfg);
    const DecompiledUnit trunc_unit = StructuredPseudoCDecompiler{}.decompile(trunc_req);
    ASSERT_EQ(trunc_unit.status, DecompileStatus::Ready) << trunc_unit.diagnostic;
    const std::string trunc_code = join_decompiled_lines(trunc_unit);
    EXPECT_NE(trunc_code.find("goto block_3020;"), std::string::npos) << trunc_code;
    EXPECT_NE(trunc_code.find("truncated disassembly window"), std::string::npos) << trunc_code;
    EXPECT_NE(trunc_code.find("sub_3006()"), std::string::npos) << trunc_code;
}



