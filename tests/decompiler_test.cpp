#include "decompile/decompiler.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include "model/binary_model.hpp"
#include <algorithm>
#include <thread>

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
    BackendRunner runner;
    const auto scripts=std::filesystem::path(PEELF_TEST_FIXTURES_DIR).parent_path().parent_path()/"apps/viewer/resources";
    const auto result=GhidraDecompiler(settings,scripts,runner).decompile(request);
    ASSERT_EQ(result.status,DecompileStatus::Ready)<<result.diagnostic;
    ASSERT_FALSE(result.lines.empty());
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.address.has_value();}));
    EXPECT_TRUE(std::ranges::any_of(result.lines,[](const auto& line){return line.text.find("return")!=std::string::npos;}));
}
INSTANTIATE_TEST_SUITE_P(RealBackend,GhidraIntegration,::testing::Values(
    "elf-linux-x86-32-le-callgraph.elf", "elf-linux-x86_64-64-le-callgraph.elf",
    "elf-linux-arm-32-le-callgraph.elf", "elf-linux-arm64-64-le-callgraph.elf",
    "elf-linux-mips-32-be-callgraph.elf", "elf-linux-mips64-64-be-callgraph.elf",
    "elf-linux-ppc-32-be-callgraph.elf", "elf-linux-ppc64-64-be-callgraph.elf",
    "known-linux-riscv32-elf32-le.elf", "elf-linux-riscv64-64-le-callgraph.elf",
    "pe-windows-x86-32-le-callgraph.dll", "pe-windows-x86_64-64-le-callgraph.dll"));
