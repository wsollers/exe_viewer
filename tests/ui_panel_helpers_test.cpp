#include "analysis/project.hpp"
#include "model/binary_model.hpp"
#include "ui/panel_helpers.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

viewer::BinaryModel load_fixture_pe_model() {
    viewer::BinaryModel result;
    const auto path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe";
    EXPECT_TRUE(result.load_file(path.string()));
    return result;
}

std::optional<viewer::AsyncScriptOutcome> wait_for_script_completion(viewer::BinaryModel& model) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto summary = model.harvest_script_execution(); summary.has_value()) {
            return summary;
        }
        if (!model.is_script_running()) {
            return model.harvest_script_execution();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return std::nullopt;
}

} // namespace

TEST(UiPanelHelpersTest, LaunchTokenizerPreservesEmptyQuotesAndRejectsUnmatchedQuotes) {
    {
        const auto empty_res = viewer::tokenize_launch_arguments("   \t  ");
        ASSERT_TRUE(empty_res.has_value());
        EXPECT_TRUE(empty_res->empty());
    }

    {
        const auto args = viewer::tokenize_launch_arguments(
            R"(--empty-dbl "" --empty-sgl '' --msg "hello world" C:\tools\test.exe \"lit\" "a\"b\\c")");
        ASSERT_TRUE(args.has_value()) << args.error().message;
        const std::vector<std::string> expected{
            "--empty-dbl",
            "",
            "--empty-sgl",
            "",
            "--msg",
            "hello world",
            R"(C:\tools\test.exe)",
            "\"lit\"",
            "a\"b\\c",
        };
        EXPECT_EQ(*args, expected);
    }

    {
        const auto adjacent = viewer::tokenize_launch_arguments(R"(""foo"" ''bar'')");
        ASSERT_TRUE(adjacent.has_value()) << adjacent.error().message;
        const std::vector<std::string> expected{"foo", "bar"};
        EXPECT_EQ(*adjacent, expected);
    }

    {
        const auto bad_dbl = viewer::tokenize_launch_arguments(R"(--flag "unterminated arg)");
        EXPECT_FALSE(bad_dbl.has_value());
        EXPECT_NE(bad_dbl.error().message.find("Unmatched"), std::string::npos);
    }

    {
        const auto bad_sgl = viewer::tokenize_launch_arguments("--flag 'unterminated arg");
        EXPECT_FALSE(bad_sgl.has_value());
        EXPECT_NE(bad_sgl.error().message.find("Unmatched"), std::string::npos);
    }

    {
        const auto bad_esc_quote = viewer::tokenize_launch_arguments(R"(--flag "trailing\)");
        EXPECT_FALSE(bad_esc_quote.has_value());
        EXPECT_NE(bad_esc_quote.error().message.find("Unmatched"), std::string::npos);
    }
}

TEST(UiPanelHelpersTest, BreakpointResolverChecksExactSymbolsBeforeBareHexUnless0xPrefixed) {
    const std::unordered_map<std::string, std::uint64_t> sym_table{
        {"fade", 0x140001010ULL},
        {"dead", 0x140001020ULL},
        {"cafe", 0x140001030ULL},
        {"babe", 0x140001040ULL},
        {"add", 0x140001050ULL},
        {"dec", 0x140001060ULL},
    };

    viewer::SymbolIndex symbols;
    for (const auto& [sym_name, expected_va] : sym_table) {
        symbols.add_discovered_symbol(viewer::SymbolRecord{
            .name = sym_name,
            .raw_name = sym_name,
            .virtual_address = expected_va,
            .size = 16u,
            .function = true,
        });
    }

    for (const auto& [sym_name, expected_va] : sym_table) {
        const auto resolved = viewer::resolve_breakpoint_target(sym_name, symbols);
        ASSERT_TRUE(resolved.has_value()) << sym_name;
        EXPECT_EQ(*resolved, expected_va) << "Symbol '" << sym_name << "' was shadowed by hex parse";
    }

    // Explicit 0x / 0X prefix forces hexadecimal address parsing even when a symbol named "fade" exists.
    const auto explicit_hex = viewer::resolve_breakpoint_target("0xfade", symbols);
    ASSERT_TRUE(explicit_hex.has_value());
    EXPECT_EQ(*explicit_hex, 0xFADEULL);

    const auto explicit_upper_hex = viewer::resolve_breakpoint_target("0XDEAD", symbols);
    ASSERT_TRUE(explicit_upper_hex.has_value());
    EXPECT_EQ(*explicit_upper_hex, 0xDEADULL);

    // Bare hexadecimal strings that do NOT match any symbol still resolve as hex VAs.
    const auto bare_hex = viewer::resolve_breakpoint_target("140002000", symbols);
    ASSERT_TRUE(bare_hex.has_value());
    EXPECT_EQ(*bare_hex, 0x140002000ULL);

    // Non-hex unknown symbol fails cleanly.
    const auto unknown_sym = viewer::resolve_breakpoint_target("nonexistent_func", symbols);
    EXPECT_FALSE(unknown_sym.has_value());
}

TEST(UiPanelHelpersTest, StarterSectionEntropyScriptComputesShannonEntropyAndPreservesBookmarkMeta) {
    auto model = load_fixture_pe_model();

    const auto templates = viewer::scripting_starter_templates();
    ASSERT_EQ(templates.size(), viewer::kScriptStarterTemplateCount);
    const std::string entropy_source(templates[1].source);
    EXPECT_NE(entropy_source.find("math.log"), std::string::npos);

    peelf::ScriptLimits limits{};
    limits.max_instructions = 500'000'000ULL;
    limits.wall_clock_timeout = std::chrono::milliseconds{10000};

    ASSERT_TRUE(model.start_script_execution(
                    entropy_source,
                    limits,
                    /*request_allow_mutations=*/false,
                    peelf::ProjectWorkspace{},
                    "=entropy_template_test")
                    .has_value());

    const auto entropy_run = wait_for_script_completion(model);
    ASSERT_TRUE(entropy_run.has_value());
    EXPECT_EQ(entropy_run->status, viewer::AsyncScriptStatus::Succeeded)
        << entropy_run->script_result.error_message;
    EXPECT_NE(entropy_run->script_result.output.find("entropy="), std::string::npos);
    EXPECT_NE(entropy_run->script_result.output.find("bits/B"), std::string::npos);

    // Seed two existing bookmarks: one with an explicit category and one with an intentionally
    // empty category, then run a mutating script that updates a bookmark and adds a new one.
    const std::uint64_t entry_va = model.image()->entry_point();
    model.add_or_update_bookmark(viewer::Bookmark{
        .address = entry_va,
        .is_file_offset = false,
        .label = "UserEntry",
        .category = "",
        .note = "Keep empty category intact",
    });
    model.add_or_update_bookmark(viewer::Bookmark{
        .address = entry_va + 4u,
        .is_file_offset = false,
        .label = "CryptoCheck",
        .category = "Crypto",
        .note = "Verify constant table",
    });

    peelf::ProjectWorkspace seed_ws{};
    for (const viewer::Bookmark& bm : model.bookmarks()) {
        if (!bm.is_file_offset) {
            seed_ws.add_bookmark(bm.address, bm.label);
        }
    }

    ASSERT_TRUE(model.start_script_execution(
                    "local entry = peelf.target_info().entry_point\n"
                    "peelf.add_bookmark(entry + 8, 'NewScriptBookmark')\n"
                    "peelf.commit('Add bookmark')\n",
                    limits,
                    /*request_allow_mutations=*/true,
                    std::move(seed_ws),
                    "=bookmark_meta_test")
                    .has_value());

    const auto bm_run = wait_for_script_completion(model);
    ASSERT_TRUE(bm_run.has_value());
    EXPECT_EQ(bm_run->status, viewer::AsyncScriptStatus::Succeeded)
        << bm_run->script_result.error_message;

    const viewer::Bookmark* bm_empty_cat = model.find_bookmark(entry_va, false);
    ASSERT_NE(bm_empty_cat, nullptr);
    EXPECT_EQ(bm_empty_cat->category, "");
    EXPECT_EQ(bm_empty_cat->note, "Keep empty category intact");

    const viewer::Bookmark* bm_crypto = model.find_bookmark(entry_va + 4u, false);
    ASSERT_NE(bm_crypto, nullptr);
    EXPECT_EQ(bm_crypto->category, "Crypto");
    EXPECT_EQ(bm_crypto->note, "Verify constant table");

    const viewer::Bookmark* bm_new = model.find_bookmark(entry_va + 8u, false);
    ASSERT_NE(bm_new, nullptr);
    EXPECT_EQ(bm_new->category, "Script");
}

TEST(UiPanelHelpersTest, CrashRecoverySnapshotReplacesBaselinePatchesWithoutSkippingOrDoubleApplying) {
    auto model = load_fixture_pe_model();

    viewer::AnalysisProject baseline;
    baseline.source = model.file_info().path;
    baseline.source_size = model.bytes().size();
    baseline.fingerprint = viewer::binary_fingerprint(model.bytes());
    baseline.source_sha256 = model.content_sha256();

    const std::uint8_t orig0 = model.bytes()[0];
    const std::uint8_t orig4 = model.bytes()[4];
    baseline.patches = {
        peelf::PatchInterval{.offset = 0u, .original = {orig0}, .patched = {static_cast<std::uint8_t>(orig0 ^ 0xFFu)}},
    };
    ASSERT_TRUE(viewer::restore_project_patches(model, baseline));
    ASSERT_EQ(model.changed_intervals().size(), 1u);

    // Recovery journal carries an updated byte at offset 0 AND a second patch at offset 4.
    viewer::AnalysisProject recovery = baseline;
    const std::uint8_t rec0 = static_cast<std::uint8_t>(orig0 ^ 0x55u);
    const std::uint8_t rec4 = static_cast<std::uint8_t>(orig4 ^ 0xAAu);
    recovery.patches = {
        peelf::PatchInterval{.offset = 0u, .original = {orig0}, .patched = {rec0}},
        peelf::PatchInterval{.offset = 4u, .original = {orig4}, .patched = {rec4}},
    };

    const auto applied = viewer::replace_project_patches_from_snapshot(model, recovery);
    ASSERT_TRUE(applied.has_value()) << applied.error().message;
    EXPECT_EQ((*model.read_effective_bytes(0u, 1u))[0], rec0);
    EXPECT_EQ((*model.read_effective_bytes(4u, 1u))[0], rec4);

    // Invalid recovery snapshot does not wipe existing staged patches.
    viewer::AnalysisProject corrupted = baseline;
    corrupted.patches = {
        peelf::PatchInterval{.offset = 0u, .original = {static_cast<std::uint8_t>(orig0 ^ 0x01u)}, .patched = {0x90u}},
    };
    EXPECT_FALSE(viewer::replace_project_patches_from_snapshot(model, corrupted).has_value());
    EXPECT_EQ((*model.read_effective_bytes(0u, 1u))[0], rec0);

    // Recovery snapshot with zero patches (user reverted all edits before crash) clears baseline patches.
    viewer::AnalysisProject reverted = baseline;
    reverted.patches.clear();
    ASSERT_TRUE(viewer::replace_project_patches_from_snapshot(model, reverted).has_value());
    EXPECT_TRUE(model.changed_intervals().empty());
    EXPECT_EQ((*model.read_effective_bytes(0u, 1u))[0], orig0);
}

TEST(UiPanelHelpersTest, ClipperCountControlCharSanitizerAndUtf8PathHelpers) {
    EXPECT_EQ(viewer::clamp_imgui_clipper_count(0u), 0);
    EXPECT_EQ(viewer::clamp_imgui_clipper_count(42u), 42);
    EXPECT_EQ(viewer::clamp_imgui_clipper_count(std::numeric_limits<std::size_t>::max()),
              std::numeric_limits<int>::max());

    EXPECT_EQ(viewer::sanitize_single_line_control_chars("/usr/lib/libc.so.6"),
              "/usr/lib/libc.so.6");
    EXPECT_EQ(viewer::sanitize_single_line_control_chars("/tmp/evil\nspoofed\rrow\t\x7F"),
              "/tmp/evil spoofed row ?");

    const std::string utf8_rel = "パッチ_αβγ_тест.pepatch.json";
    const std::filesystem::path p = viewer::utf8_to_filesystem_path(utf8_rel);
    const auto roundtrip_u8 = p.filename().u8string();
    const std::string roundtrip(roundtrip_u8.begin(), roundtrip_u8.end());
    EXPECT_EQ(roundtrip, utf8_rel);
}
