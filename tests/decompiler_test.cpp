#include "decompile/decompiler.hpp"
#include <gtest/gtest.h>
#include <fstream>

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
