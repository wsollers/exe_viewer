#include "analysis/c_type_parser.hpp"
#include "analysis/project.hpp"
#include "decompile/decompiler.hpp"
#include "decompile/structured_decompiler.hpp"
#include "symbols/data_types.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

[[nodiscard]] std::string join_decompiled_lines(const viewer::DecompiledUnit& unit) {
    std::string out{};
    for (const auto& line : unit.lines) {
        out += line.text;
        out.push_back('\n');
    }
    return out;
}

void load_known_pe_fixture(viewer::BinaryModel& out) {
    const auto path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe";
    ASSERT_TRUE(out.load_file(path.string()));
    ASSERT_NE(out.image(), nullptr);
}

}  // namespace

TEST(DecompilerOverrides, ValidatesIdentifiersTypesAndStoreLifecycle) {
    EXPECT_TRUE(viewer::is_valid_decompiler_c_identifier("buffer_size"));
    EXPECT_TRUE(viewer::is_valid_decompiler_c_identifier("_ctx2"));
    EXPECT_TRUE(viewer::is_valid_decompiler_c_identifier("payloadPtr"));

    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier(""));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("1leading_digit"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("0x10"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("return"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("int"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("struct"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("sizeof"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("nullptr"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("foo bar"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("foo;bar"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("foo/*inj*/"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier("pkt->field"));
    EXPECT_FALSE(viewer::is_valid_decompiler_c_identifier(
        std::string(viewer::kMaxDecompilerIdentifierLength + 1u, 'a')));

    const auto ok_type = viewer::normalize_decompiler_c_type("  const   struct PacketHeader * ");
    ASSERT_TRUE(ok_type.has_value());
    EXPECT_EQ(*ok_type, "const struct PacketHeader *");

    const auto arr_type = viewer::normalize_decompiler_c_type("uint8_t[16]");
    ASSERT_TRUE(arr_type.has_value());
    EXPECT_EQ(*arr_type, "uint8_t[16]");

    EXPECT_FALSE(viewer::normalize_decompiler_c_type("int x; system(\"sh\")").has_value());
    EXPECT_FALSE(viewer::normalize_decompiler_c_type("int /* bad */").has_value());
    EXPECT_FALSE(viewer::normalize_decompiler_c_type("int // bad").has_value());
    EXPECT_FALSE(viewer::normalize_decompiler_c_type("int { int a }").has_value());
    EXPECT_FALSE(viewer::normalize_decompiler_c_type("uint8_t[16").has_value());
    EXPECT_FALSE(viewer::normalize_decompiler_c_type("int\nchar*").has_value());

    viewer::DecompilerOverrideStore store{};
    EXPECT_EQ(store.revision(), 0u);
    EXPECT_TRUE(store.empty());

    ASSERT_TRUE(store.set_variable_rename(0x140001000u, "stack_var_10", "buffer_size"));
    EXPECT_EQ(store.revision(), 1u);
    ASSERT_TRUE(store.set_variable_type(0x140001000u, "stack_var_10", "size_t"));
    EXPECT_EQ(store.revision(), 2u);
    EXPECT_FALSE(store.set_variable_rename(0x140001000u, "stack_var_10", "while"));
    EXPECT_FALSE(store.set_variable_rename(0x140001000u, "stack_var_10", "9bad"));

    const auto* vov = store.find_variable(0x140001000u, "stack_var_10");
    ASSERT_NE(vov, nullptr);
    EXPECT_EQ(vov->renamed_to, "buffer_size");
    EXPECT_EQ(vov->c_type, "size_t");

    // Resetting rename to original name clears renamed_to while keeping c_type; clearing c_type too prunes empty entries.
    ASSERT_TRUE(store.set_variable_rename(0x140001000u, "stack_var_10", "stack_var_10"));
    vov = store.find_variable(0x140001000u, "stack_var_10");
    ASSERT_NE(vov, nullptr);
    EXPECT_TRUE(vov->renamed_to.empty());
    EXPECT_EQ(vov->c_type, "size_t");

    ASSERT_TRUE(store.set_variable_type(0x140001000u, "stack_var_10", ""));
    EXPECT_EQ(store.find(0x140001000u), nullptr);
    EXPECT_TRUE(store.empty());
}

TEST(DecompilerOverrides, TokenBoundaryRewriterLeavesLiteralsCommentsHexAndMembersIntact) {
    const std::unordered_map<std::string, std::string> renames{
        {"rax", "result_ptr"},
        {"v1", "elem_count"},
        {"r8", "flags_reg"},
    };

    const std::string input =
        "rax = *(uint64_t *)(rax + v1 * 8) + r8 + r8d_other + rax_2 + _rax + 0xdeadbeef + 0x10;\n"
        "logf(\"rax=%p \\\"v1\\\" r8\", rax, pkt->rax, obj.v1, ns::rax, 'v'); /* was rax, v1 */ // rax v1";

    const std::string rewritten = viewer::rewrite_decompiler_c_tokens(input, renames);

    EXPECT_NE(rewritten.find("result_ptr = *(uint64_t *)(result_ptr + elem_count * 8) + flags_reg"),
              std::string::npos);
    EXPECT_NE(rewritten.find("r8d_other + rax_2 + _rax + 0xdeadbeef + 0x10;"), std::string::npos);
    EXPECT_NE(rewritten.find("\"rax=%p \\\"v1\\\" r8\""), std::string::npos);
    EXPECT_NE(rewritten.find("pkt->rax, obj.v1, ns::rax, 'v'"), std::string::npos);
    EXPECT_NE(rewritten.find("/* was rax, v1 */ // rax v1"), std::string::npos);
}

TEST(DecompilerOverrides, StructuredPseudoCDecompilerLowersRenamesCTypesAndReturnType) {
    viewer::CallGraph cfg{};
    cfg.nodes = {
        viewer::CallGraphNode{
            .id = "bb_entry",
            .label = "entry",
            .kind = viewer::CallGraphNodeKind::BasicBlock,
            .bytes = viewer::GraphByteRange{
                .start = viewer::GraphAddress{.virtual_address = 0x140002000u},
                .size = 24u,
            },
            .instructions = {
                {0x140002000u, "push", "rbp"},
                {0x140002001u, "mov", "rbp, rsp"},
                {0x140002004u, "sub", "rsp, 0x20"},
                {0x140002008u, "mov", "qword ptr [rbp - 0x10], rcx"},
                {0x14000200cu, "cmp", "qword ptr [rbp - 0x10], 0"},
                {0x140002011u, "je", "0x140002020"},
            },
        },
        viewer::CallGraphNode{
            .id = "bb_nonnull",
            .label = "loc_2017",
            .kind = viewer::CallGraphNodeKind::BasicBlock,
            .bytes = viewer::GraphByteRange{
                .start = viewer::GraphAddress{.virtual_address = 0x140002017u},
                .size = 9u,
            },
            .instructions = {
                {0x140002017u, "mov", "rax, qword ptr [rbp - 0x10]"},
                {0x14000201bu, "leave", ""},
                {0x14000201cu, "ret", ""},
            },
        },
        viewer::CallGraphNode{
            .id = "bb_null",
            .label = "loc_2020",
            .kind = viewer::CallGraphNodeKind::BasicBlock,
            .bytes = viewer::GraphByteRange{
                .start = viewer::GraphAddress{.virtual_address = 0x140002020u},
                .size = 6u,
            },
            .instructions = {
                {0x140002020u, "xor", "eax, eax"},
                {0x140002022u, "leave", ""},
                {0x140002023u, "ret", ""},
            },
        },
    };
    cfg.edges = {
        {"bb_entry", "bb_null", viewer::CallGraphEdgeKind::ConditionalBranch, "true"},
        {"bb_entry", "bb_nonnull", viewer::CallGraphEdgeKind::Fallthrough, "false"},
        {"bb_nonnull", "exit", viewer::CallGraphEdgeKind::Return, "ret"},
        {"bb_null", "exit", viewer::CallGraphEdgeKind::Return, "ret"},
    };

    viewer::DecompileRequest base_req{};
    base_req.binary_sha256 = std::string(64u, 'a');
    base_req.address = 0x140002000u;
    base_req.architecture = peelf::Architecture::X86_64;
    base_req.fallback_graph = cfg;
    base_req.symbols = {
        viewer::SymbolRecord{
            .name = "parse_packet",
            .virtual_address = 0x140002000u,
            .function = true,
        },
    };

    const viewer::DecompiledUnit baseline = viewer::StructuredPseudoCDecompiler{}.decompile(base_req);
    ASSERT_EQ(baseline.status, viewer::DecompileStatus::Ready);
    const std::string baseline_text = join_decompiled_lines(baseline);
    EXPECT_NE(baseline_text.find("stack_var_10"), std::string::npos);

    viewer::DecompileRequest ov_req = base_req;
    ov_req.function_override = viewer::DecompilerFunctionOverride{
        .function_address = 0x140002000u,
        .return_type = "const char*",
        .signature_override = "(const char* raw_packet, size_t max_len)",
        .variables = {
            viewer::DecompilerVariableOverride{
                .original_name = "stack_var_10",
                .renamed_to = "buffer_ptr",
                .c_type = "const char*",
            },
            viewer::DecompilerVariableOverride{
                .original_name = "rcx",
                .renamed_to = "raw_packet",
                .c_type = "const char*",
            },
            viewer::DecompilerVariableOverride{
                .original_name = "rax",
                .renamed_to = "result_buf",
                .c_type = "const char*",
            },
        },
    };

    const viewer::DecompiledUnit overridden = viewer::StructuredPseudoCDecompiler{}.decompile(ov_req);
    ASSERT_EQ(overridden.status, viewer::DecompileStatus::Ready);
    const std::string text = join_decompiled_lines(overridden);

    EXPECT_NE(text.find("const char* parse_packet(const char* raw_packet, size_t max_len) {"),
              std::string::npos)
        << text;
    EXPECT_NE(text.find("const char* buffer_ptr; /* was stack_var_10 */"), std::string::npos)
        << text;
    EXPECT_NE(text.find("const char* result_buf; /* was rax */"), std::string::npos)
        << text;
    EXPECT_NE(text.find("buffer_ptr = raw_packet;"), std::string::npos) << text;
    EXPECT_NE(text.find("result_buf = buffer_ptr;"), std::string::npos) << text;
    EXPECT_NE(text.find("return result_buf;"), std::string::npos) << text;

    const viewer::DecompilerSettings settings{};
    const auto key_base = viewer::make_decompile_cache_key(base_req, settings);
    const auto key_ov = viewer::make_decompile_cache_key(ov_req, settings);
    EXPECT_NE(key_base, key_ov);
    EXPECT_TRUE(key_base.function_override_sha256.empty());
    EXPECT_EQ(key_ov.function_override_sha256.size(), 64u);
}

TEST(DecompilerOverrides, ExternalBackendPostPassRewritesDeclarationsParametersAndBodySafely) {
    viewer::DecompiledUnit unit{};
    unit.status = viewer::DecompileStatus::Ready;
    unit.provider = "Ghidra";
    unit.lines = {
        {0x401000u, "ulong verify_token(long param_1, uint param_2) {", {}},
        {std::nullopt, "  undefined8 local_18;", {}},
        {0x401004u, "  local_18 = *(undefined8 *)(param_1 + 0x10);", {}},
        {std::nullopt, "  /* local_18 slot from Ghidra */", {}},
        {0x40100cu, "  trace_log(\"local_18=%llx param_1=%p\", local_18, param_1);", {}},
        {0x401014u, "  return local_18 ^ param_2;", {}},
        {std::nullopt, "}", {}},
    };

    const viewer::DecompilerFunctionOverride fn_ov{
        .function_address = 0x401000u,
        .return_type = "const uint8_t*",
        .signature_override = {},
        .variables = {
            {.original_name = "local_18", .renamed_to = "decoded_key", .c_type = "const uint8_t*"},
            {.original_name = "param_1", .renamed_to = "session_ctx", .c_type = "struct Session*"},
            {.original_name = "param_2", .renamed_to = "flags", .c_type = "uint32_t"},
        },
    };

    viewer::apply_decompiler_overrides(unit, fn_ov);
    const std::string joined = join_decompiled_lines(unit);

    EXPECT_EQ(unit.lines[0].text,
              "const uint8_t* verify_token(struct Session* session_ctx, uint32_t flags) {");
    EXPECT_EQ(unit.lines[1].text, "  const uint8_t* decoded_key; /* was local_18 */");
    EXPECT_EQ(unit.lines[2].text, "  decoded_key = *(undefined8 *)(session_ctx + 0x10);");
    EXPECT_EQ(unit.lines[3].text, "  /* local_18 slot from Ghidra */");
    EXPECT_EQ(unit.lines[4].text,
              "  trace_log(\"local_18=%llx param_1=%p\", decoded_key, session_ctx);");
    EXPECT_EQ(unit.lines[5].text, "  return decoded_key ^ flags;");
    (void)joined;
}

TEST(DecompilerOverrides, ProjectEncodeDecodeRoundTripsAndPreservesBackwardCompatibility) {
    viewer::BinaryModel model;
    ASSERT_NO_FATAL_FAILURE(load_known_pe_fixture(model));

    const std::string custom_hdr = "struct PacketHeader { uint32_t magic; uint32_t length; };\n";
    const auto parsed_types = viewer::parse_c_types(custom_hdr);
    ASSERT_TRUE(parsed_types.ok()) << parsed_types.diagnostics.front().message;
    model.set_custom_c_types(custom_hdr, parsed_types.types);

    const std::vector<viewer::DecompilerFunctionOverride> overrides = {
        viewer::DecompilerFunctionOverride{
            .function_address = 0x140001000u,
            .return_type = "const struct PacketHeader*",
            .signature_override = "(const uint8_t* buf, size_t len)",
            .variables = {
                {.original_name = "rcx", .renamed_to = "buf", .c_type = "const uint8_t*"},
                {.original_name = "stack_var_10", .renamed_to = "hdr", .c_type = "struct PacketHeader*"},
            },
        },
        viewer::DecompilerFunctionOverride{
            .function_address = 0x140001200u,
            .return_type = "int32_t",
            .signature_override = {},
            .variables = {
                {.original_name = "local_18", .renamed_to = "decoded_key", .c_type = "uint64_t"},
            },
        },
    };

    peelf_test::ScopedTempDir temp_dir("peelf_wu48_project");
    const std::filesystem::path peproj_path = temp_dir.path() / "wu48_session.peproj";

    const viewer::AnalysisProject proj = viewer::build_analysis_project(
        model,
        peproj_path,
        {},
        {},
        {},
        0u,
        "[Window][Decompiler]\n",
        false,
        overrides);
    ASSERT_EQ(proj.decompiler_overrides, overrides);

    const std::string encoded = viewer::encode_project(proj);
    EXPECT_NE(encoded.find("CUSTOM_C_TYPES 1"), std::string::npos);
    EXPECT_NE(encoded.find("DECOMPILER_OVERRIDES 1"), std::string::npos);

    const auto decoded = viewer::decode_project(encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().message;
    EXPECT_EQ(decoded->custom_c_types_source, custom_hdr);
    EXPECT_EQ(decoded->decompiler_overrides, overrides);

    // Autosave crash-recovery journal round-trip also preserves decompiler_overrides.
    const auto journal_res = viewer::write_recovery_journal(proj, peproj_path, temp_dir.path());
    ASSERT_TRUE(journal_res.has_value()) << journal_res.error().message;
    const auto recovered = viewer::check_newer_recovery_journal(peproj_path, 0u, temp_dir.path());
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->decompiler_overrides, overrides);
    viewer::clear_recovery_journal(peproj_path, temp_dir.path());

    // Backward compatibility: older .peproj v2 without DECOMPILER_OVERRIDES (with CUSTOM_C_TYPES only, and with neither).
    viewer::AnalysisProject legacy_v2_with_types = proj;
    legacy_v2_with_types.decompiler_overrides.clear();
    const std::string encoded_no_ov = viewer::encode_project(legacy_v2_with_types);
    EXPECT_EQ(encoded_no_ov.find("DECOMPILER_OVERRIDES"), std::string::npos);
    const auto decoded_no_ov = viewer::decode_project(encoded_no_ov);
    ASSERT_TRUE(decoded_no_ov.has_value()) << decoded_no_ov.error().message;
    EXPECT_TRUE(decoded_no_ov->decompiler_overrides.empty());
    EXPECT_EQ(decoded_no_ov->custom_c_types_source, custom_hdr);

    viewer::AnalysisProject legacy_v2_plain = legacy_v2_with_types;
    legacy_v2_plain.custom_c_types_source.clear();
    legacy_v2_plain.custom_types.clear();
    const auto decoded_plain = viewer::decode_project(viewer::encode_project(legacy_v2_plain));
    ASSERT_TRUE(decoded_plain.has_value()) << decoded_plain.error().message;
    EXPECT_TRUE(decoded_plain->decompiler_overrides.empty());
    EXPECT_TRUE(decoded_plain->custom_c_types_source.empty());

    // Rejects invalid identifier injected into DECOMPILER_OVERRIDES table.
    viewer::AnalysisProject corrupted = proj;
    corrupted.decompiler_overrides[0].variables[0].renamed_to = "return";
    EXPECT_FALSE(viewer::decode_project(viewer::encode_project(corrupted)).has_value());
}
