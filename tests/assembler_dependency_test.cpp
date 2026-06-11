#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

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

} // namespace
