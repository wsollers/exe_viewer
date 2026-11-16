#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <peelf/assembler.hpp>

#if PEELF_ASMTK_AVAILABLE
#include <asmjit/x86.h>
#include <asmtk/asmtk.h>
#endif

namespace {

TEST(AssemblerDependencyTest, AsmTkAvailabilityIsReportedAtCompileTime) {
#if PEELF_ASMTK_AVAILABLE
    SUCCEED() << "AsmTK is available";
#else
    GTEST_SKIP() << "AsmTK dependency is disabled";
#endif
}

#if PEELF_ASMTK_AVAILABLE
TEST(AssemblerDependencyTest, AsmTkCanAssembleX64NopRet) {
    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;
    ASSERT_EQ(code.init(env), asmjit::kErrorOk);

    asmjit::x86::Assembler assembler(&code);
    asmtk::AsmParser parser(&assembler);

    const asmjit::Error parse_error = parser.parse("nop\nret\n");
    ASSERT_EQ(parse_error, asmjit::kErrorOk) << asmjit::DebugUtils::error_as_string(parse_error);

    const asmjit::CodeBuffer& buffer = code.text_section()->buffer();
    const std::vector<std::uint8_t> actual(buffer.data(), buffer.data() + buffer.size());
    const std::vector<std::uint8_t> expected{0x90u, 0xC3u};
    EXPECT_EQ(actual, expected);
}
#endif

#ifdef PEELF_BACKEND_FIXTURE
TEST(SubprocessRunnerTest, ServicesConcurrentLargeStdinStdoutAndStderrWithoutDeadlock) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const std::string stdin_payload(512u * 1024u, 'I');
    const std::array<std::string, 1> args{"flood-io"};

    const auto res = peelf::run_argv_process(
        fixture, args, stdin_payload, std::chrono::milliseconds{10000});
    ASSERT_TRUE(res.launched) << res.launch_error;
    EXPECT_FALSE(res.timed_out);
    EXPECT_EQ(res.exit_code, 0);
    EXPECT_EQ(res.stderr_text.size(), 512u * 1024u);
    EXPECT_NE(res.stdout_text.find("STDIN_BYTES=524288"), std::string::npos);
    EXPECT_GT(res.stdout_text.size(), 512u * 1024u);
}

TEST(SubprocessRunnerTest, HandlesEarlyChildExitWithLargeStdinWithoutSigpipe) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    const std::string large_stdin(2u * 1024u * 1024u, 'X');
    const std::array<std::string, 1> args{"early-exit"};

    const auto res = peelf::run_argv_process(
        fixture, args, large_stdin, std::chrono::milliseconds{5000});
    ASSERT_TRUE(res.launched) << res.launch_error;
    EXPECT_FALSE(res.timed_out);
    EXPECT_EQ(res.exit_code, 42);
    EXPECT_EQ(res.stderr_text, "early-err");
}

TEST(SubprocessRunnerTest, TerminatesAndReapsHungChildEvenAfterPipesClose) {
    const std::filesystem::path fixture(PEELF_BACKEND_FIXTURE);
    ASSERT_TRUE(std::filesystem::exists(fixture));

    for (const char* mode : {"sleep", "hang-after-close"}) {
        SCOPED_TRACE(mode);
        const std::array<std::string, 1> args{mode};
        const auto start = std::chrono::steady_clock::now();
        const auto res = peelf::run_argv_process(
            fixture, args, {}, std::chrono::milliseconds{150});
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_TRUE(res.timed_out);
        EXPECT_LT(elapsed.count(), 4000);
        if (std::string(mode) == "hang-after-close") {
            EXPECT_EQ(res.stdout_text, "partial-out");
        }
    }
}
#endif

} // namespace
