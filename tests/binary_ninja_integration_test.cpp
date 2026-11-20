#include "decompile/decompiler.hpp"
#include "test_temp_dir.hpp"

#include <peelf/binary_image.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace viewer;

[[nodiscard]] DecompilerSettings host_bn_settings() {
    DecompilerSettings settings{};
    settings.provider = DecompilerProvider::BinaryNinja;
#ifdef PEELF_PYTHON3_EXECUTABLE
    settings.python = PEELF_PYTHON3_EXECUTABLE;
#endif
    const BinaryNinjaCapabilityStatus discovered = discover_binary_ninja(settings);
    if (!discovered.install_directory.empty()) {
        settings.binary_ninja_home = discovered.install_directory;
    }
    settings.timeout_seconds = 120;
    return settings;
}

[[nodiscard]] std::filesystem::path bn_bridge_path() {
    return std::filesystem::path(PEELF_VIEWER_RESOURCES_DIR) / "bn_decompile.py";
}

[[nodiscard]] std::optional<DecompileRequest> build_fixture_request(
    const std::filesystem::path& fixture_path) {
    std::ifstream in(fixture_path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        return std::nullopt;
    }
    const auto parsed = peelf::parse_image(bytes);
    if (!parsed) {
        return std::nullopt;
    }
    const auto& img = *parsed;
    std::optional<std::uint64_t> target_va;
    if (img->entry_point() != 0u) {
        target_va = img->entry_point();
    }
    if (!target_va.has_value()) {
        for (const auto& exp : img->exports()) {
            if (exp.forwarder.empty() && exp.virtual_address != 0u) {
                target_va = exp.virtual_address;
                break;
            }
        }
    }
    if (!target_va.has_value()) {
        for (const auto& sym : img->symbols()) {
            if (sym.virtual_address != 0u) {
                target_va = sym.virtual_address;
                break;
            }
        }
    }
    if (!target_va.has_value()) {
        return std::nullopt;
    }

    DecompileRequest req{};
    req.address = *target_va;
    req.architecture = img->architecture();
    req.endianness = img->endianness();
    req.image_bytes = std::move(bytes);
    return req;
}

TEST(BinaryNinjaIntegration, DiscoveryAndCapabilityProbe) {
    const DecompilerSettings settings = host_bn_settings();
    BackendRunner runner;
    const BinaryNinjaCapabilityStatus caps =
        probe_binary_ninja_capabilities(settings, bn_bridge_path(), runner);
    if (!caps.install_found && !caps.python_api_available) {
        GTEST_SKIP() << "Binary Ninja is not installed on this host: " << caps.status_summary;
    }
    EXPECT_FALSE(caps.status_summary.empty());
    if (caps.edition == BinaryNinjaEdition::Free) {
        EXPECT_FALSE(caps.headless_supported);
        EXPECT_FALSE(check_binary_ninja_architecture_support(caps, peelf::Architecture::ARM64));
    }
}

TEST(BinaryNinjaIntegration, DecompileX64PeAndX64ElfFixtures) {
    const DecompilerSettings settings = host_bn_settings();
    BackendRunner runner;
    const BinaryNinjaCapabilityStatus caps =
        probe_binary_ninja_capabilities(settings, bn_bridge_path(), runner);
    if (!caps.python_api_available || !caps.headless_supported) {
        GTEST_SKIP() << "Headless Binary Ninja license/API unavailable: " << caps.status_summary;
    }

    const std::filesystem::path pe_fixture =
        std::filesystem::exists(std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "pe-windows-x86_64-64-le-callgraph.dll")
            ? (std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "pe-windows-x86_64-64-le-callgraph.dll")
            : (std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe");
    const std::filesystem::path elf_fixture =
        std::filesystem::exists(std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "elf-linux-x86_64-64-le-callgraph.elf")
            ? (std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "elf-linux-x86_64-64-le-callgraph.elf")
            : (std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf");

    const auto pe_req = build_fixture_request(pe_fixture);
    ASSERT_TRUE(pe_req.has_value()) << pe_fixture.string();
    const auto elf_req = build_fixture_request(elf_fixture);
    ASSERT_TRUE(elf_req.has_value()) << elf_fixture.string();

    const BinaryNinjaDecompiler decompiler(settings, bn_bridge_path(), runner, caps);
    const DecompiledUnit pe_unit = decompiler.decompile(*pe_req);
    EXPECT_EQ(pe_unit.status, DecompileStatus::Ready) << pe_unit.diagnostic;
    EXPECT_FALSE(pe_unit.lines.empty());

    const DecompiledUnit elf_unit = decompiler.decompile(*elf_req);
    EXPECT_EQ(elf_unit.status, DecompileStatus::Ready) << elf_unit.diagnostic;
    EXPECT_FALSE(elf_unit.lines.empty());
}

TEST(BinaryNinjaIntegration, UnsupportedArchitectureTimeoutAndBridgeProtocolStability) {
    DecompilerSettings settings = host_bn_settings();
    BackendRunner runner;

    // Unknown architecture always reports Unsupported deterministically.
    DecompileRequest unknown_req{};
    unknown_req.address = 0x1000u;
    unknown_req.architecture = peelf::Architecture::Unknown;
    unknown_req.image_bytes = {0x90, 0xC3};
    const DecompiledUnit unsupported_unit =
        BinaryNinjaDecompiler(settings, bn_bridge_path(), runner).decompile(unknown_req);
    EXPECT_EQ(unsupported_unit.status, DecompileStatus::Unsupported);

    const BinaryNinjaCapabilityStatus caps =
        probe_binary_ninja_capabilities(settings, bn_bridge_path(), runner);
    if (!caps.python_api_available || !caps.headless_supported) {
        GTEST_SKIP() << "Headless Binary Ninja license/API unavailable for live protocol/timeout check: "
                     << caps.status_summary;
    }

    // Verify bn_decompile.py direct CLI output conforms to PEELF_DECOMPILE 3.
    const std::filesystem::path elf_fixture =
        std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-linux-x64.elf";
    const auto elf_req = build_fixture_request(elf_fixture);
    ASSERT_TRUE(elf_req.has_value());

    peelf_test::ScopedTempDir temp("bn_optin_proto");
    const auto out_path = temp.path() / "bn_out.txt";
    std::vector<std::string> args{
        bn_bridge_path().string(),
        elf_fixture.string(),
        out_path.string(),
        std::to_string(elf_req->address),
        "--arch",
        "x86_64",
    };
    if (!settings.binary_ninja_home.empty()) {
        args.emplace_back("--bn-home");
        args.push_back(settings.binary_ninja_home.string());
    }
    const BackendProcessResult proc =
        runner.run(settings.python, args, std::chrono::seconds(60), {});
    ASSERT_EQ(proc.exit_code, 0);
    std::ifstream in(out_path, std::ios::binary);
    const std::string raw{std::istreambuf_iterator<char>(in), {}};
    EXPECT_TRUE(raw.starts_with("PEELF_DECOMPILE 3\n"));
    const DecompiledUnit parsed = parse_decompiler_output(raw);
    EXPECT_EQ(parsed.status, DecompileStatus::Ready) << parsed.diagnostic;
}

}  // namespace
