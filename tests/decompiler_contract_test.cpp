#include "decompile/decompile_controller.hpp"
#include "decompile/decompiler.hpp"
#include "decompile/structured_decompiler.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

using namespace viewer;

void write_text_file(const std::filesystem::path& path, std::string_view content) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.good()) << path.string();
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    ASSERT_TRUE(out.good()) << path.string();
}

void make_executable(const std::filesystem::path& path) {
#ifndef _WIN32
    (void)::chmod(path.c_str(), 0755);
#else
    (void)path;
#endif
}

class ScriptedBackendRunner final : public IBackendRunner {
public:
    using Handler = std::function<BackendProcessResult(
        const std::filesystem::path&,
        const std::vector<std::string>&,
        std::chrono::milliseconds,
        std::stop_token)>;

    explicit ScriptedBackendRunner(Handler handler) : handler_(std::move(handler)) {}

    BackendProcessResult run(const std::filesystem::path& executable,
                             const std::vector<std::string>& arguments,
                             std::chrono::milliseconds timeout,
                             std::stop_token stop) const override {
        last_executable = executable;
        last_arguments = arguments;
        last_timeout = timeout;
        ++call_count;
        return handler_(executable, arguments, timeout, stop);
    }

    mutable std::filesystem::path last_executable{};
    mutable std::vector<std::string> last_arguments{};
    mutable std::chrono::milliseconds last_timeout{0};
    mutable std::size_t call_count{0u};

private:
    Handler handler_;
};

[[nodiscard]] std::filesystem::path create_synthetic_bn_install(
    const std::filesystem::path& dir,
    std::string_view edition_text = {},
    std::string_view version_text = "4.2.6455",
    bool with_python_api = true,
    bool macos_bundle_layout = false) {
    if (macos_bundle_layout) {
        const auto macos_dir = dir / "Binary Ninja.app" / "Contents" / "MacOS";
        const auto res_py = dir / "Binary Ninja.app" / "Contents" / "Resources" / "python" / "binaryninja";
        write_text_file(macos_dir / "binaryninja", "#!/bin/sh\n");
        if (!version_text.empty()) {
            write_text_file(macos_dir / "version.txt", std::string(version_text) + "\n");
        }
        if (!edition_text.empty()) {
            write_text_file(macos_dir / "edition.txt", std::string(edition_text) + "\n");
        }
        if (with_python_api) {
            write_text_file(res_py / "__init__.py", "# synthetic macos bn api\n");
        }
        return dir / "Binary Ninja.app";
    }

    write_text_file(dir / "binaryninja", "#!/bin/sh\n");
    make_executable(dir / "binaryninja");
    if (!version_text.empty()) {
        write_text_file(dir / "version.txt", std::string(version_text) + "\n");
    }
    if (!edition_text.empty()) {
        write_text_file(dir / "edition.txt", std::string(edition_text) + "\n");
    }
    if (with_python_api) {
        write_text_file(dir / "python" / "binaryninja" / "__init__.py", "# synthetic bn api\n");
    }
    return dir;
}

TEST(DecompilerContract, BinaryNinjaSettingsPersistenceAndFingerprint) {
    peelf_test::ScopedTempDir temp("bn_settings_contract");
    const auto ini_path = temp.path() / "decompiler.ini";

    DecompilerSettings settings{};
    settings.provider = DecompilerProvider::BinaryNinja;
    settings.ghidra_home = "/opt/ghidra";
    settings.binary_ninja_home = "/opt/Vector 35/Binary Ninja Commercial";
    settings.java = "java";
    settings.python = "/usr/bin/python3";
    settings.retdec = "retdec-decompiler";
    settings.timeout_seconds = 95;
    settings.cache_directory = temp.path() / "cache";
    settings.max_cached_workspaces = 4u;
    settings.reuse_analysis = true;

    ASSERT_TRUE(save_decompiler_settings(ini_path, settings));
    const auto loaded = read_decompiler_settings(ini_path);
    ASSERT_TRUE(loaded) << loaded.error().message;
    EXPECT_EQ(loaded->provider, DecompilerProvider::BinaryNinja);
    EXPECT_EQ(loaded->binary_ninja_home, settings.binary_ninja_home);
    EXPECT_EQ(loaded->python, settings.python);
    EXPECT_EQ(loaded->timeout_seconds, 95);

    // Unquoted binary_ninja_home=... key-value also parses cleanly.
    write_text_file(
        ini_path,
        "PEELF_DECOMPILER 2\n1\n\"\"\n\"java\"\n\"python3\"\n\"retdec-decompiler\"\n60\n\"\"\n3\n1\n"
        "binary_ninja_home=/opt/binaryninja\n");
    const auto unquoted = read_decompiler_settings(ini_path);
    ASSERT_TRUE(unquoted) << unquoted.error().message;
    EXPECT_EQ(unquoted->binary_ninja_home, std::filesystem::path("/opt/binaryninja"));

    // Legacy v2 file without binary_ninja_home remains valid with empty path.
    write_text_file(
        ini_path,
        "PEELF_DECOMPILER 2\n1\n\"\"\n\"java\"\n\"python3\"\n\"retdec-decompiler\"\n60\n\"\"\n3\n1\n");
    const auto legacy_v2 = read_decompiler_settings(ini_path);
    ASSERT_TRUE(legacy_v2) << legacy_v2.error().message;
    EXPECT_TRUE(legacy_v2->binary_ninja_home.empty());

    // Unknown trailing keys are rejected.
    write_text_file(
        ini_path,
        "PEELF_DECOMPILER 2\n1\n\"\"\n\"java\"\n\"python3\"\n\"retdec-decompiler\"\n60\n\"\"\n3\n1\n"
        "unexpected_key=\"value\"\n");
    EXPECT_FALSE(read_decompiler_settings(ini_path));

    // Fingerprint incorporates binary_ninja_home for BinaryNinja provider.
    DecompilerSettings bn_a = settings;
    DecompilerSettings bn_b = settings;
    bn_b.binary_ninja_home = "/opt/other_binaryninja";
    EXPECT_NE(compute_decompiler_settings_fingerprint(bn_a),
              compute_decompiler_settings_fingerprint(bn_b));

    DecompilerSettings pseudo_a = bn_a;
    DecompilerSettings pseudo_b = bn_b;
    pseudo_a.provider = DecompilerProvider::StructuredPseudoC;
    pseudo_b.provider = DecompilerProvider::StructuredPseudoC;
    EXPECT_EQ(compute_decompiler_settings_fingerprint(pseudo_a),
              compute_decompiler_settings_fingerprint(pseudo_b));
}

TEST(DecompilerContract, BinaryNinjaDiscoveryPriorityAndEditionArchCapabilities) {
    peelf_test::ScopedTempDir temp("bn_discovery_contract");
    const auto explicit_dir = create_synthetic_bn_install(temp.path() / "explicit_bn", "Ultimate", "4.3.1000");
    const auto env_dir = create_synthetic_bn_install(temp.path() / "env_bn", "Commercial", "4.2.2000");
    const auto lastrun_dir = create_synthetic_bn_install(temp.path() / "lastrun_bn", "Personal", "4.1.3000");
    const auto settings_dir = create_synthetic_bn_install(temp.path() / "settings_bn", "", "4.0.4000");
    const auto mac_bundle = create_synthetic_bn_install(
        temp.path() / "mac_root", "Commercial", "4.2.5000", true, true);
    const auto path_dir = create_synthetic_bn_install(temp.path() / "path_bn", "Free", "4.2.6000");

    const auto user_cfg = temp.path() / "user_bn";
    write_text_file(user_cfg / "lastrun", lastrun_dir.string() + "\n");
    write_text_file(
        user_cfg / "settings.json",
        "{\n  \"binaryNinjaHome\": \"" + settings_dir.generic_string() + "\"\n}\n");

    BinaryNinjaDiscoveryEnv env{};
    env.include_system_defaults = false;
    env.bn_install_dir = env_dir;
    env.user_settings_directories = {user_cfg};
    env.standard_install_directories = {mac_bundle};
    env.path_env = path_dir.string();

    // (a) Explicit settings.binary_ninja_home wins over everything.
    DecompilerSettings settings{};
    settings.binary_ninja_home = explicit_dir;
    auto caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_TRUE(caps.python_api_available);
    EXPECT_TRUE(caps.headless_supported);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Ultimate);
    EXPECT_EQ(caps.version, "4.3.1000");
    EXPECT_EQ(caps.install_directory, explicit_dir);

    // (b) BN_INSTALL_DIR wins when settings.binary_ninja_home is empty.
    settings.binary_ninja_home.clear();
    caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Commercial);
    EXPECT_EQ(caps.install_directory, env_dir);

    // (c) lastrun hint wins next and records settings_source.
    env.bn_install_dir.reset();
    caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Personal);
    EXPECT_EQ(caps.install_directory, lastrun_dir);
    EXPECT_EQ(caps.settings_source, user_cfg / "lastrun");

    // (c.2) settings.json hint + license.dat product hint when lastrun is absent.
    std::filesystem::remove(user_cfg / "lastrun");
    write_text_file(
        user_cfg / "license.dat",
        "[{\"product\": \"Binary Ninja Commercial\", \"serial\": \"REDACTED\"}]\n");
    caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Commercial);
    EXPECT_EQ(caps.install_directory, settings_dir);
    EXPECT_EQ(caps.settings_source, user_cfg / "settings.json");

    // (d) Standard install path (including macOS .app bundle layout with ../Resources/python).
    env.user_settings_directories.clear();
    caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_TRUE(caps.python_api_available);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Commercial);
    EXPECT_EQ(caps.version, "4.2.5000");

    // (e) PATH lookup of binaryninja + Free edition capability restrictions.
    env.standard_install_directories.clear();
    caps = discover_binary_ninja(settings, env);
    EXPECT_TRUE(caps.install_found);
    EXPECT_EQ(caps.edition, BinaryNinjaEdition::Free);
    EXPECT_FALSE(caps.headless_supported);
    EXPECT_TRUE(check_binary_ninja_architecture_support(caps, peelf::Architecture::X86));
    EXPECT_TRUE(check_binary_ninja_architecture_support(caps, peelf::Architecture::X86_64));

    // Free edition rejects all non-x86/x64 targets with clear diagnostics.
    constexpr std::array<peelf::Architecture, 8> kNonFreeArches = {
        peelf::Architecture::ARM,
        peelf::Architecture::ARM64,
        peelf::Architecture::MIPS32,
        peelf::Architecture::MIPS64,
        peelf::Architecture::PowerPC,
        peelf::Architecture::PowerPC64,
        peelf::Architecture::RISCV32,
        peelf::Architecture::RISCV64,
    };
    for (const peelf::Architecture arch : kNonFreeArches) {
        const auto arch_res = check_binary_ninja_architecture_support(caps, arch);
        ASSERT_FALSE(arch_res);
        EXPECT_NE(arch_res.error().message.find("Binary Ninja Free"), std::string::npos);
    }

    // Free edition also rejects headless Python batch execution on x86_64.
    const auto headless_res = check_binary_ninja_headless_support(caps, peelf::Architecture::X86_64);
    ASSERT_FALSE(headless_res);
    EXPECT_NE(headless_res.error().message.find("headless"), std::string::npos);

    // Unknown architecture is always rejected.
    EXPECT_FALSE(check_binary_ninja_architecture_support(caps, peelf::Architecture::Unknown));
}

TEST(DecompilerContract, ProtocolV1V2V3MalformedTruncatedOverflowAndValidPayloads) {
    // Valid v3 multi-range HLIL + struct & union DataTypeRecord mapping.
    const std::string valid_v3 =
        "PEELF_DECOMPILE 3\n"
        "ready \"Decompiled with Binary Ninja HLIL\"\n"
        "3\n"
        "0 \"int32_t process_packet(PacketHeader* hdr) {\"\n"
        "2 4096 4 4100 6 \"    if (hdr->magic != 0x504B5400) return -1;\"\n"
        "1 4112 1 \"}\"\n"
        "2\n"
        "\"PacketHeader\" 16 0 2\n"
        "0 4 \"magic\" \"uint32_t\"\n"
        "8 8 \"payload_ptr\" \"void*\"\n"
        "\"PayloadWord\" 8 1 2\n"
        "0 8 \"as_u64\" \"uint64_t\"\n"
        "0 4 \"as_u32\" \"uint32_t\"\n";

    const DecompiledUnit ok_v3 = parse_decompiler_output(valid_v3);
    ASSERT_EQ(ok_v3.status, DecompileStatus::Ready) << ok_v3.diagnostic;
    ASSERT_EQ(ok_v3.lines.size(), 3u);
    EXPECT_FALSE(ok_v3.lines[0].address.has_value());
    EXPECT_TRUE(ok_v3.lines[0].ranges.empty());
    EXPECT_EQ(ok_v3.lines[1].address, 4096u);
    ASSERT_EQ(ok_v3.lines[1].ranges.size(), 2u);
    EXPECT_EQ(ok_v3.lines[1].ranges[0].address, 4096u);
    EXPECT_EQ(ok_v3.lines[1].ranges[0].size, 4u);
    EXPECT_EQ(ok_v3.lines[1].ranges[1].address, 4100u);
    EXPECT_EQ(ok_v3.lines[1].ranges[1].size, 6u);

    ASSERT_EQ(ok_v3.types.size(), 2u);
    EXPECT_EQ(ok_v3.types[0].name, "PacketHeader");
    EXPECT_EQ(ok_v3.types[0].size, 16u);
    EXPECT_FALSE(ok_v3.types[0].is_union);
    ASSERT_EQ(ok_v3.types[0].members.size(), 2u);
    EXPECT_EQ(ok_v3.types[0].members[1].offset, 8u);
    EXPECT_EQ(ok_v3.types[0].members[1].name, "payload_ptr");
    EXPECT_EQ(ok_v3.types[1].name, "PayloadWord");
    EXPECT_TRUE(ok_v3.types[1].is_union);

    // Non-ready v3 statuses parse cleanly with zero lines and zero types.
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 3\nunavailable \"no api\"\n0\n0\n").status,
              DecompileStatus::Unavailable);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 3\nunsupported \"bn free\"\n0\n0\n").status,
              DecompileStatus::Unsupported);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 3\nno_function \"missing\"\n0\n0\n").status,
              DecompileStatus::NoFunction);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 3\ntimeout \"slow\"\n0\n0\n").status,
              DecompileStatus::Timeout);
    EXPECT_EQ(parse_decompiler_output("PEELF_DECOMPILE 3\ncancelled \"stopped\"\n0\n0\n").status,
              DecompileStatus::Cancelled);

    // Malformed, truncated, negative, and overflowing v1/v2/v3 payloads all fail safely.
    const std::array<std::string_view, 16> kBadPayloads = {
        "",
        "{\"json\": \"wrong_protocol\"}",
        "PEELF_DECOMPILE 0\nready \"x\"\n1\n4096 \"ret\"\n",
        "PEELF_DECOMPILE 4\nready \"x\"\n1\n0 \"ret\"\n0\n",
        "PEELF_DECOMPILE 3\nunknown_state \"x\"\n0\n0\n",
        "PEELF_DECOMPILE 3\nready \"empty_ready\"\n0\n0\n",
        "PEELF_DECOMPILE 3\nready \"neg_lines\"\n-1\n0\n",
        "PEELF_DECOMPILE 3\nready \"zero_range_sz\"\n1\n1 4096 0 \"ret\"\n0\n",
        "PEELF_DECOMPILE 3\nready \"huge_range_sz\"\n1\n1 4096 1048577 \"ret\"\n0\n",
        "PEELF_DECOMPILE 3\nready \"u64_wrap_range\"\n1\n1 18446744073709551610 16 \"ret\"\n0\n",
        "PEELF_DECOMPILE 3\nready \"truncated_types\"\n1\n1 4096 4 \"ret\"\n",
        "PEELF_DECOMPILE 3\nready \"bad_union_flag\"\n1\n1 4096 4 \"ret\"\n1\n\"S\" 8 2 0\n",
        "PEELF_DECOMPILE 3\nready \"huge_struct\"\n1\n1 4096 4 \"ret\"\n1\n\"S\" 16777217 0 0\n",
        "PEELF_DECOMPILE 3\nready \"member_past_end\"\n1\n1 4096 4 \"ret\"\n1\n\"S\" 8 0 1\n6 4 \"f\" \"u32\"\n",
        "PEELF_DECOMPILE 3\nready \"neg_member_off\"\n1\n1 4096 4 \"ret\"\n1\n\"S\" 8 0 1\n-1 4 \"f\" \"u32\"\n",
        "PEELF_DECOMPILE 3\nready \"trailing_tokens\"\n1\n1 4096 4 \"ret\"\n0\nextra\n",
    };
    for (const std::string_view bad : kBadPayloads) {
        const auto parsed = parse_decompiler_output(bad);
        EXPECT_EQ(parsed.status, DecompileStatus::Failed) << "Payload unexpectedly succeeded: " << bad;
    }
}

TEST(DecompilerContract, AllBackendsAndControllerContractWithoutExternalTools) {
    peelf_test::ScopedTempDir temp("backend_contract_matrix");
    const auto fake_bridge = temp.path() / "bn_decompile.py";
    write_text_file(fake_bridge, "# fake bridge\n");

    DecompileRequest req{};
    req.address = 0x1000u;
    req.function_size = 8u;
    req.architecture = peelf::Architecture::X86_64;
    // push rbp; mov rbp, rsp; mov eax, 42; pop rbp; ret
    req.image_bytes = {0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3};
    req.symbols.push_back(SymbolRecord{
        .name = "compute_answer",
        .source = SymbolSource::DebugSymbol,
        .virtual_address = 0x1000u,
        .file_offset = 0u,
        .size = 11u,
        .function = true,
    });

    // 1. BinaryNinjaDecompiler contract: Free edition capability rejection + custom timeout/flags + v3 output.
    const auto free_bn_dir = create_synthetic_bn_install(temp.path() / "bn_free", "Free", "4.2.0");
    DecompilerSettings bn_free_settings{};
    bn_free_settings.provider = DecompilerProvider::BinaryNinja;
    bn_free_settings.binary_ninja_home = free_bn_dir;
    bn_free_settings.timeout_seconds = 45;

    ScriptedBackendRunner never_called_runner(
        [](const auto&, const auto&, auto, std::stop_token) -> BackendProcessResult {
            ADD_FAILURE() << "Runner should not execute when pre-flight Free capability check rejects target";
            return {-1, false, false};
        });

    DecompileRequest arm64_req = req;
    arm64_req.architecture = peelf::Architecture::ARM64;
    const auto free_arm64 =
        BinaryNinjaDecompiler(bn_free_settings, fake_bridge, never_called_runner).decompile(arm64_req);
    EXPECT_EQ(free_arm64.status, DecompileStatus::Unsupported);
    EXPECT_NE(free_arm64.diagnostic.find("arm64"), std::string::npos);
    EXPECT_EQ(never_called_runner.call_count, 0u);

    const auto free_x64 =
        BinaryNinjaDecompiler(bn_free_settings, fake_bridge, never_called_runner).decompile(req);
    EXPECT_EQ(free_x64.status, DecompileStatus::Unsupported);
    EXPECT_NE(free_x64.diagnostic.find("Free"), std::string::npos);
    EXPECT_EQ(never_called_runner.call_count, 0u);

    const auto comm_bn_dir = create_synthetic_bn_install(temp.path() / "bn_comm", "Commercial", "4.2.1");
    DecompilerSettings bn_comm_settings = bn_free_settings;
    bn_comm_settings.binary_ninja_home = comm_bn_dir;
    bn_comm_settings.timeout_seconds = 75;

    std::string scripted_bn_payload;
    BackendProcessResult scripted_bn_proc{0, false, false};
    ScriptedBackendRunner bn_runner(
        [&](const std::filesystem::path&,
            const std::vector<std::string>& args,
            std::chrono::milliseconds timeout,
            std::stop_token) -> BackendProcessResult {
            EXPECT_EQ(timeout, std::chrono::seconds(75));
            EXPECT_GE(args.size(), 9u);
            if (args.size() >= 3u && !scripted_bn_payload.empty()) {
                write_text_file(args[2], scripted_bn_payload);
            }
            return scripted_bn_proc;
        });

    BinaryNinjaDecompiler bn_comm(bn_comm_settings, fake_bridge, bn_runner);
    scripted_bn_proc = {-1, true, false};
    EXPECT_EQ(bn_comm.decompile(req).status, DecompileStatus::Timeout);

    scripted_bn_proc = {-1, false, true};
    EXPECT_EQ(bn_comm.decompile(req).status, DecompileStatus::Cancelled);

    scripted_bn_proc = {-1, false, false};
    EXPECT_EQ(bn_comm.decompile(req).status, DecompileStatus::Unavailable);

    scripted_bn_proc = {0, false, false};
    scripted_bn_payload = "PEELF_DECOMPILE 3\nno_function \"No function at VA\"\n0\n0\n";
    EXPECT_EQ(bn_comm.decompile(req).status, DecompileStatus::NoFunction);

    scripted_bn_payload =
        "PEELF_DECOMPILE 3\nready \"HLIL\"\n1\n1 4096 11 \"return 42;\"\n1\n\"Ctx\" 8 0 1\n0 8 \"ptr\" \"void*\"\n";
    const auto bn_ready = bn_comm.decompile(req);
    ASSERT_EQ(bn_ready.status, DecompileStatus::Ready);
    ASSERT_EQ(bn_ready.lines.size(), 1u);
    EXPECT_EQ(bn_ready.lines[0].address, 0x1000u);
    ASSERT_EQ(bn_ready.types.size(), 1u);
    EXPECT_EQ(bn_ready.types[0].name, "Ctx");

    // Non-zero exit code after writing ready payload must be treated as Failed.
    scripted_bn_proc = {1, false, false};
    EXPECT_EQ(bn_comm.decompile(req).status, DecompileStatus::Failed);

    // 2. GhidraDecompiler contract without real Ghidra installed.
    DecompilerSettings ghidra_missing{};
    ghidra_missing.ghidra_home = temp.path() / "missing_ghidra";
    EXPECT_EQ(GhidraDecompiler(ghidra_missing, temp.path(), bn_runner).decompile(req).status,
              DecompileStatus::Unavailable);

    const auto fake_ghidra = temp.path() / "fake_ghidra";
    write_text_file(fake_ghidra / "Ghidra/Framework/Utility/lib/Utility.jar", "jar");
    write_text_file(fake_ghidra / "support/analyzeHeadless", "#!/bin/sh\n");
    write_text_file(fake_ghidra / "support/analyzeHeadless.bat", "@echo off\r\n");
    const auto fake_scripts = temp.path() / "ghidra_scripts";
    write_text_file(fake_scripts / "PeelfDecompile.java", "// stub\n");

    DecompilerSettings ghidra_ok{};
    ghidra_ok.ghidra_home = fake_ghidra;
    ghidra_ok.cache_directory = temp.path() / "ghidra_cache";
    ghidra_ok.timeout_seconds = 30;
    ghidra_ok.reuse_analysis = false;

    ScriptedBackendRunner ghidra_timeout_runner(
        [](const auto&, const auto&, auto, std::stop_token) -> BackendProcessResult {
            return {-1, true, false};
        });
    EXPECT_EQ(GhidraDecompiler(ghidra_ok, fake_scripts, ghidra_timeout_runner).decompile(req).status,
              DecompileStatus::Timeout);

    DecompileRequest unknown_arch_req = req;
    unknown_arch_req.architecture = peelf::Architecture::Unknown;
    EXPECT_EQ(GhidraDecompiler(ghidra_ok, fake_scripts, ghidra_timeout_runner).decompile(unknown_arch_req).status,
              DecompileStatus::Unsupported);

    // 3. RetDecDecompiler contract (missing executable vs fake executable).
    EXPECT_EQ(
        RetDecDecompiler(temp.path() / "nonexistent_retdec", bn_runner, 30).decompile(req).status,
        DecompileStatus::Unavailable);
    EXPECT_EQ(
        RetDecDecompiler(temp.path() / "nonexistent_retdec", bn_runner, 30).decompile(unknown_arch_req).status,
        DecompileStatus::Unsupported);

    const auto fake_retdec = temp.path() / "fake_retdec_bin";
    write_text_file(fake_retdec, "#!/bin/sh\n");
    make_executable(fake_retdec);

    ScriptedBackendRunner retdec_runner(
        [](const std::filesystem::path&,
           const std::vector<std::string>& args,
           std::chrono::milliseconds,
           std::stop_token) -> BackendProcessResult {
            for (std::size_t i = 0; i + 1u < args.size(); ++i) {
                if (args[i] == "-o") {
                    write_text_file(
                        args[i + 1u],
                        "// Address range: 0x1000 - 0x100b\nint64_t compute_answer(void) {\n    return 42;\n}\n");
                }
            }
            return {0, false, false};
        });
    const auto retdec_unit = RetDecDecompiler(fake_retdec, retdec_runner, 30).decompile(req);
    ASSERT_EQ(retdec_unit.status, DecompileStatus::Ready) << retdec_unit.diagnostic;
    EXPECT_FALSE(retdec_unit.lines.empty());
    EXPECT_TRUE(std::ranges::any_of(retdec_unit.lines, [](const DecompiledLine& line) {
        return line.address == std::optional<std::uint64_t>(0x1000u);
    }));

    // 4. Built-in StructuredPseudoCDecompiler & AnnotatedCodeDecompiler contract.
    CallGraph cfg{};
    cfg.id = "fn_1000";
    cfg.label = "compute_answer";
    cfg.architecture = peelf::Architecture::X86_64;
    CallGraphNode block{};
    block.id = "bb_1000";
    block.label = "compute_answer";
    block.kind = CallGraphNodeKind::BasicBlock;
    block.bytes.start.virtual_address = 0x1000u;
    block.bytes.size = 11u;
    block.instructions.push_back(GraphInstruction{
        .address = 0x1004u,
        .mnemonic = "mov",
        .operands = "eax, 0x2a",
    });
    block.instructions.push_back(GraphInstruction{
        .address = 0x100Au,
        .mnemonic = "ret",
        .operands = "",
    });
    cfg.nodes.push_back(std::move(block));
    req.fallback_graph = cfg;

    const auto pseudo_unit = StructuredPseudoCDecompiler{}.decompile(req);
    EXPECT_EQ(pseudo_unit.status, DecompileStatus::Ready);
    EXPECT_FALSE(pseudo_unit.lines.empty());

    const auto annot_unit = AnnotatedCodeDecompiler{}.decompile(req);
    ASSERT_EQ(annot_unit.status, DecompileStatus::Ready);
    EXPECT_TRUE(std::ranges::any_of(annot_unit.lines, [](const DecompiledLine& line) {
        return line.address == std::optional<std::uint64_t>(0x1004u);
    }));

    std::stop_source cancelled_src;
    cancelled_src.request_stop();
    EXPECT_EQ(StructuredPseudoCDecompiler{}.decompile(req, cancelled_src.get_token()).status,
              DecompileStatus::Cancelled);
    EXPECT_EQ(AnnotatedCodeDecompiler{}.decompile(req, cancelled_src.get_token()).status,
              DecompileStatus::Cancelled);

    // 5. DecompileController async completion & unconfigured Ghidra -> StructuredPseudoC fallback.
    DecompileController controller;
    DecompilerSettings unconfigured_ghidra{};
    unconfigured_ghidra.provider = DecompilerProvider::Ghidra;
    const DecompileValidationStamp stamp{
        .target_identity = "contract_bin",
        .file_generation = 1u,
        .edit_revision = 0u,
        .snapshot_revision = 0u,
    };
    const auto job_id = controller.submit(DecompileJobSpec{
        .request = req,
        .settings = unconfigured_ghidra,
        .resources_directory = temp.path(),
        .stamp = stamp,
    });
    EXPECT_GT(job_id, 0u);

    std::optional<DecompileJobResult> harvested;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline && !harvested.has_value()) {
        harvested = controller.poll_completed(stamp);
        if (!harvested.has_value()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    ASSERT_TRUE(harvested.has_value());
    EXPECT_EQ(harvested->unit.status, DecompileStatus::Ready);
}

#ifdef PEELF_PYTHON3_EXECUTABLE
TEST(DecompilerContract, RealPythonBridgeInvocationAgainstMockedBinaryNinjaPackage) {
    peelf_test::ScopedTempDir temp("real_python_bn_bridge");
    const std::filesystem::path bridge_script =
        std::filesystem::path(PEELF_VIEWER_RESOURCES_DIR) / "bn_decompile.py";
    ASSERT_TRUE(std::filesystem::is_regular_file(bridge_script));

    const auto bn_home = create_synthetic_bn_install(temp.path() / "mock_bn", "Commercial", "4.2.8888");
    write_text_file(
        bn_home / "python" / "binaryninja" / "__init__.py",
        "class _Arch:\n"
        "    def __init__(self, name): self.name = name\n"
        "Architecture = [_Arch('x86'), _Arch('x86_64'), _Arch('aarch64'), _Arch('rv64gc')]\n"
        "def core_version(): return '4.2.8888'\n"
        "def core_product(): return 'Binary Ninja Commercial'\n"
        "class _Member:\n"
        "    def __init__(self, offset, width, name, typ):\n"
        "        self.offset = offset; self.width = width; self.name = name; self.type = typ\n"
        "class _Struct:\n"
        "    def __init__(self, width, variant, members):\n"
        "        self.type_class = 'StructureTypeClass'\n"
        "        self.width = width; self.type = variant; self.members = members\n"
        "class _Line:\n"
        "    def __init__(self, addr, text, ll_addrs):\n"
        "        self.address = addr; self._text = text\n"
        "        self.il_instruction = type('IL', (), {'llils': [type('LL', (), {'address': a})() for a in ll_addrs]})()\n"
        "    def __str__(self): return self._text\n"
        "class _Fn:\n"
        "    def __init__(self):\n"
        "        self.name = 'sub_1000'\n"
        "        self.arch = 'x86_64'\n"
        "    @property\n"
        "    def hlil(self):\n"
        "        lines = [\n"
        "            _Line(None, f'int32_t {self.name}(FrameHeader* hdr) {{', []),\n"
        "            _Line(4096, '    return hdr->opcode;', [4096, 4100]),\n"
        "            _Line(4104, '}', [4104]),\n"
        "        ]\n"
        "        return type('HLIL', (), {'root': type('Root', (), {'lines': lines})()})()\n"
        "class _View:\n"
        "    def __init__(self):\n"
        "        self.arch = 'x86_64'\n"
        "        self._fn = _Fn()\n"
        "        self.types = {\n"
        "            'FrameHeader': _Struct(8, 'StructStructureType', [\n"
        "                _Member(0, 4, 'opcode', 'int32_t'),\n"
        "                _Member(4, 4, 'flags', 'uint32_t'),\n"
        "            ]),\n"
        "            'FrameTag': _Struct(4, 'UnionStructureType', [\n"
        "                _Member(0, 4, 'raw', 'uint32_t'),\n"
        "            ]),\n"
        "        }\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *args): pass\n"
        "    def get_instruction_length(self, addr, arch=None): return 4\n"
        "    def get_function_at(self, addr): return self._fn if addr == 4096 else None\n"
        "    def get_functions_containing(self, addr): return [self._fn] if addr == 4096 else []\n"
        "def load(path): return _View()\n");

    BackendRunner real_runner;
    DecompilerSettings settings{};
    settings.provider = DecompilerProvider::BinaryNinja;
    settings.python = PEELF_PYTHON3_EXECUTABLE;
    settings.binary_ninja_home = bn_home;
    settings.timeout_seconds = 30;

    BinaryNinjaDiscoveryEnv env{};
    env.include_system_defaults = false;
    const BinaryNinjaCapabilityStatus probed =
        probe_binary_ninja_capabilities(settings, bridge_script, real_runner, env);
    EXPECT_TRUE(probed.install_found);
    EXPECT_TRUE(probed.python_api_available);
    EXPECT_TRUE(probed.headless_supported);
    EXPECT_EQ(probed.edition, BinaryNinjaEdition::Commercial);
    EXPECT_EQ(probed.version, "4.2.8888");
    EXPECT_NE(std::ranges::find(probed.supported_architectures, peelf::Architecture::X86_64),
              probed.supported_architectures.end());
    EXPECT_NE(std::ranges::find(probed.supported_architectures, peelf::Architecture::ARM64),
              probed.supported_architectures.end());
    EXPECT_NE(std::ranges::find(probed.supported_architectures, peelf::Architecture::RISCV64),
              probed.supported_architectures.end());

    DecompileRequest req{};
    req.address = 4096u;
    req.function_size = 12u;
    req.architecture = peelf::Architecture::X86_64;
    req.image_bytes = {0x90, 0xC3};
    req.symbols.push_back(SymbolRecord{
        .name = "dispatch_frame",
        .source = SymbolSource::DebugSymbol,
        .virtual_address = 4096u,
        .file_offset = 0u,
        .size = 12u,
        .function = true,
    });

    const DecompiledUnit unit =
        BinaryNinjaDecompiler(settings, bridge_script, real_runner, probed).decompile(req);
    ASSERT_EQ(unit.status, DecompileStatus::Ready) << unit.diagnostic;
    ASSERT_EQ(unit.lines.size(), 3u);
    EXPECT_NE(unit.lines[0].text.find("dispatch_frame"), std::string::npos);
    ASSERT_EQ(unit.lines[1].ranges.size(), 1u);
    EXPECT_EQ(unit.lines[1].ranges[0].address, 4096u);
    EXPECT_EQ(unit.lines[1].ranges[0].size, 8u);
    ASSERT_EQ(unit.types.size(), 2u);
    EXPECT_EQ(unit.types[0].name, "FrameHeader");
    EXPECT_FALSE(unit.types[0].is_union);
    EXPECT_EQ(unit.types[1].name, "FrameTag");
    EXPECT_TRUE(unit.types[1].is_union);

    // Verify live probe against a mocked Free installation reports headless_supported=false.
    const auto free_home = create_synthetic_bn_install(temp.path() / "mock_bn_free", "", "4.2.1111");
    write_text_file(
        free_home / "python" / "binaryninja" / "__init__.py",
        "def core_version(): return '4.2.1111'\n"
        "def core_product(): return 'Binary Ninja Free'\n"
        "Architecture = []\n"
        "def load(path): raise RuntimeError('Headless load is not supported in Binary Ninja Free')\n");

    DecompilerSettings free_settings = settings;
    free_settings.binary_ninja_home = free_home;
    const BinaryNinjaCapabilityStatus free_probed =
        probe_binary_ninja_capabilities(free_settings, bridge_script, real_runner, env);
    EXPECT_EQ(free_probed.edition, BinaryNinjaEdition::Free);
    EXPECT_FALSE(free_probed.headless_supported);

    DecompileRequest riscv_req = req;
    riscv_req.architecture = peelf::Architecture::RISCV64;
    const DecompiledUnit free_unit =
        BinaryNinjaDecompiler(free_settings, bridge_script, real_runner, free_probed).decompile(riscv_req);
    EXPECT_EQ(free_unit.status, DecompileStatus::Unsupported);
    EXPECT_NE(free_unit.diagnostic.find("riscv64"), std::string::npos);
}
#endif

}  // namespace
