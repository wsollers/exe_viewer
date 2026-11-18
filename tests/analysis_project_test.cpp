#include "analysis/project.hpp"
#include "analysis/patch_preview.hpp"
#include "test_temp_dir.hpp"
#include <gtest/gtest.h>
#include <filesystem>

namespace {
void load_fixture_model(viewer::BinaryModel& out) {
    ASSERT_TRUE(out.load_file((std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe").string()));
    ASSERT_NE(out.image(), nullptr);
    ASSERT_GE(out.bytes().size(), 8u);
}
viewer::AnalysisProject project_for(const viewer::BinaryModel& source) {
    viewer::AnalysisProject p; p.source=source.file_info().path; p.source_size=source.bytes().size();
    p.fingerprint=viewer::binary_fingerprint(source.bytes()); return p;
}
}
TEST(AnalysisProject, RoundTripPreservesAnnotationsSymbolsHistoryAndLayout) {
    viewer::BinaryModel m; ASSERT_NO_FATAL_FAILURE(load_fixture_model(m)); auto p=project_for(m);
    p.annotations.emplace(0x1000,viewer::Annotation{"a\"b", "line1\nline2\\"});
    p.symbols.push_back({"named",0x1000,0x140001000,22,true}); p.thumb=true;
    p.history.push_back({.kind=viewer::SelectionKind::ByteRange,.label="here",.file_offset=0,.virtual_address=0x1000,.size=1,
        .preferred_view=viewer::PreferredView::Graph,.graph_root=viewer::SymbolRecord{.name="root",.virtual_address=0x1000,.file_offset=0,.size=32}});
    p.layout="[Window][Flow Graph]\nDockId=1\n";
    auto decoded=viewer::decode_project(viewer::encode_project(p)); ASSERT_TRUE(decoded) << decoded.error().message;
    EXPECT_EQ(decoded->annotations.at(0x1000).comment,p.annotations.at(0x1000).comment);
    ASSERT_FALSE(decoded->symbols.empty());
    EXPECT_EQ(decoded->symbols[0].name,"named"); EXPECT_TRUE(decoded->thumb);
    ASSERT_FALSE(decoded->history.empty());
    ASSERT_TRUE(decoded->history[0].graph_root.has_value());
    EXPECT_EQ(decoded->history[0].graph_root->size,32); EXPECT_EQ(decoded->layout,p.layout);
}
TEST(AnalysisProject, PatchRestoreIsOneUndoableTransactionAndValidatesAllRanges) {
    viewer::BinaryModel m; ASSERT_NO_FATAL_FAILURE(load_fixture_model(m)); auto p=project_for(m);
    p.patches={{0,{m.bytes()[0]},{0x12}},{4,{m.bytes()[4]},{0x34}}};
    ASSERT_TRUE(viewer::restore_project_patches(m,p));
    const auto eff = m.read_effective_bytes(0, 1);
    ASSERT_TRUE(eff.has_value()) << eff.error().message;
    ASSERT_FALSE(eff->empty());
    EXPECT_EQ((*eff)[0],0x12);
    ASSERT_TRUE(m.undo_patch()); EXPECT_TRUE(m.changed_intervals().empty());
    p.patches[1].original[0]^=1;
    EXPECT_FALSE(viewer::restore_project_patches(m,p)); EXPECT_TRUE(m.changed_intervals().empty());
    p.fingerprint^=1; EXPECT_FALSE(viewer::restore_project_patches(m,p));
}
TEST(AnalysisProject, RejectsBadVersionTruncationOverlapAndHistoryCursor) {
    viewer::BinaryModel m; ASSERT_NO_FATAL_FAILURE(load_fixture_model(m)); auto p=project_for(m);
    EXPECT_FALSE(viewer::decode_project("PEELF_PROJECT 999"));
    auto encoded=viewer::encode_project(p); EXPECT_FALSE(viewer::decode_project(encoded.substr(0,encoded.size()/2)));
    p.cursor=9; EXPECT_FALSE(viewer::decode_project(viewer::encode_project(p))); p.cursor=0;
    p.patches={{1,{0,0},{1,2}},{2,{0},{1}}}; EXPECT_FALSE(viewer::decode_project(viewer::encode_project(p)));
}
TEST(PatchPreview, DoesNotMutateBeforeApplyAndRejectsStalePreview) {
    viewer::BinaryModel m; ASSERT_NO_FATAL_FAILURE(load_fixture_model(m)); auto symbols=viewer::SymbolIndex::build(*m.image());
    const auto offset=m.image()->virtual_address_to_file_offset(m.image()->entry_point()); ASSERT_TRUE(offset);
    const std::uint8_t replacement=0xC3;
    auto p=viewer::preview_patch(m,symbols,*offset,std::span(&replacement,1)); ASSERT_TRUE(p) << p.error().message;
    EXPECT_TRUE(m.changed_intervals().empty()); ASSERT_FALSE(p->after.nodes.empty());
    ASSERT_TRUE(viewer::apply_preview(m,*p)); EXPECT_FALSE(viewer::apply_preview(m,*p));
    EXPECT_NE(viewer::patch_report(m).find("Replacement: C3"),std::string::npos);
    EXPECT_FALSE(viewer::preview_patch(m,symbols,m.bytes().size(),std::span(&replacement,1)));
}
TEST(AnalysisProject, AtomicFileSaveAndReadRoundTrip) {
    peelf_test::ScopedTempDir temp_dir("peelf_project_roundtrip");
    viewer::BinaryModel m; ASSERT_NO_FATAL_FAILURE(load_fixture_model(m)); auto p=project_for(m);
    auto path = temp_dir / "peelf-project-roundtrip.peproj";
    ASSERT_TRUE(viewer::write_analysis_file(path,viewer::encode_project(p)));
    p.layout="second version"; ASSERT_TRUE(viewer::write_analysis_file(path,viewer::encode_project(p)));
    auto text=viewer::read_project_file(path); ASSERT_TRUE(text); auto restored=viewer::decode_project(*text); ASSERT_TRUE(restored);
    EXPECT_EQ(restored->layout,p.layout);
}

TEST(AnalysisProject, MigratesLegacySchemaV1ToV2Seamlessly) {
    const std::string v1_payload =
        "PEELF_PROJECT 1\n"
        "\"../fixtures/known-win-x64.exe\" 4096 123456789 1\n"
        "1\n"
        "0 \"4d5a\" \"9090\"\n"
        "1\n"
        "4096 \"entry_fn\" \"legacy v1 note\"\n"
        "1\n"
        "\"sym_v1\" 4096 5368713216 16 1\n"
        "1 0\n"
        "2 \"entry\" 1 0 1 5368713216 1 0 2 0 \n"
        "\"[Window][Hex View]\"\n";

    auto migrated = viewer::decode_project(v1_payload);
    ASSERT_TRUE(migrated) << migrated.error().message;
    EXPECT_EQ(migrated->schema_version, viewer::AnalysisProject::kCurrentSchemaVersion);
    EXPECT_TRUE(migrated->migrated_from_v1);
    EXPECT_EQ(migrated->relative_source, "../fixtures/known-win-x64.exe");
    EXPECT_TRUE(migrated->source_sha256.empty());
    EXPECT_TRUE(migrated->bookmarks.empty());
    EXPECT_TRUE(migrated->structure_bindings.empty());
    ASSERT_EQ(migrated->patches.size(), 1u);
    EXPECT_EQ(migrated->annotations.at(4096).name, "entry_fn");
    ASSERT_EQ(migrated->symbols.size(), 1u);
    EXPECT_EQ(migrated->symbols[0].name, "sym_v1");

    const std::string encoded_v2 = viewer::encode_project(*migrated);
    EXPECT_TRUE(encoded_v2.starts_with("PEELF_PROJECT 2\n"));
    auto roundtrip = viewer::decode_project(encoded_v2);
    ASSERT_TRUE(roundtrip) << roundtrip.error().message;
    EXPECT_FALSE(roundtrip->migrated_from_v1);
    EXPECT_EQ(roundtrip->annotations.at(4096).comment, "legacy v1 note");
}

TEST(AnalysisProject, SchemaV2RoundTripsBookmarksStructureBindingsAndSha256) {
    viewer::BinaryModel m;
    ASSERT_NO_FATAL_FAILURE(load_fixture_model(m));
    m.add_or_update_bookmark(viewer::Bookmark{
        .address = 0x140001000,
        .is_file_offset = false,
        .label = "Dispatcher \"Entry\"",
        .category = "ControlFlow",
        .note = "first line\nsecond line",
    });
    m.add_or_update_bookmark(viewer::Bookmark{
        .address = 0x80,
        .is_file_offset = true,
        .label = "PE Signature",
        .category = "Headers",
        .note = "MZ -> PE\\0\\0",
    });
    m.add_applied_structure(viewer::AppliedStructureBinding{
        .address = 0,
        .is_file_offset = true,
        .type_name = "IMAGE_DOS_HEADER",
        .count = 1,
        .label = "DOS Header",
    });
    m.add_applied_structure(viewer::AppliedStructureBinding{
        .address = 0x140000180,
        .is_file_offset = false,
        .type_name = "IMAGE_SECTION_HEADER",
        .count = 4,
        .label = "Section Table",
    });

    std::map<std::uint64_t, viewer::Annotation> notes{
        {0x140001000, viewer::Annotation{"main_entry", "verified"}}
    };
    const auto proj = viewer::build_analysis_project(m, {}, notes, {}, {}, 0, "layout_v2", false);
    EXPECT_EQ(proj.source_sha256.size(), 64u);
    EXPECT_GT(proj.saved_unix_ms, 0u);

    const std::string text = viewer::encode_project(proj);
    EXPECT_TRUE(text.starts_with("PEELF_PROJECT 2\n"));
    auto decoded = viewer::decode_project(text);
    ASSERT_TRUE(decoded) << decoded.error().message;
    EXPECT_EQ(decoded->source_sha256, proj.source_sha256);
    EXPECT_EQ(decoded->saved_unix_ms, proj.saved_unix_ms);
    EXPECT_EQ(decoded->bookmarks, proj.bookmarks);
    EXPECT_EQ(decoded->structure_bindings, proj.structure_bindings);
    EXPECT_EQ(decoded->annotations.at(0x140001000).name, "main_entry");
}

TEST(AnalysisProject, PortableRelativePathResolutionRelocationAndSha256Mismatch) {
    namespace fs = std::filesystem;
    peelf_test::ScopedTempDir temp_dir("peelf_wu09_reloc");
    const fs::path& scratch = temp_dir.path();

    const fs::path ws_a_bin = scratch / "ws_a" / "bin" / "sample.exe";
    const fs::path ws_a_proj = scratch / "ws_a" / "sessions" / "sample.peproj";
    fs::create_directories(ws_a_bin.parent_path());
    fs::create_directories(ws_a_proj.parent_path());
    fs::copy_file(fs::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe", ws_a_bin);

    // Release BinaryModel's file handle before renaming workspace directories on Windows.
    {
        viewer::BinaryModel m;
        ASSERT_TRUE(m.load_file(ws_a_bin.string()));
        const auto proj = viewer::build_analysis_project(m, ws_a_proj);
        EXPECT_EQ(proj.relative_source, "../bin/sample.exe");
        ASSERT_TRUE(viewer::write_analysis_file(ws_a_proj, viewer::encode_project(proj)));
    }

    // Move the entire workspace directory from ws_a -> ws_b so the original absolute path breaks.
    const fs::path ws_b = scratch / "ws_b";
    fs::rename(scratch / "ws_a", ws_b);
    const fs::path ws_b_proj = ws_b / "sessions" / "sample.peproj";
    const fs::path ws_b_bin = ws_b / "bin" / "sample.exe";

    auto loaded_text = viewer::read_project_file(ws_b_proj);
    ASSERT_TRUE(loaded_text);
    auto decoded = viewer::decode_project(*loaded_text);
    ASSERT_TRUE(decoded);

    const auto exact = viewer::resolve_project_binary_path(*decoded, ws_b_proj);
    EXPECT_EQ(exact.status, viewer::ProjectBinaryMatchStatus::ExactMatch);
    EXPECT_TRUE(fs::equivalent(exact.resolved_path, ws_b_bin));
    EXPECT_EQ(exact.actual_sha256, decoded->source_sha256);

    // Move the binary outside the relative tree to trigger RelocationNeeded, then manual relocation.
    const fs::path external_bin = scratch / "relocated" / "moved_sample.exe";
    fs::create_directories(external_bin.parent_path());
    fs::rename(ws_b_bin, external_bin);

    const auto missing = viewer::resolve_project_binary_path(*decoded, ws_b_proj);
    EXPECT_EQ(missing.status, viewer::ProjectBinaryMatchStatus::RelocationNeeded);
    EXPECT_GE(missing.tried_paths.size(), 2u);

    const auto relocated = viewer::resolve_project_binary_path(*decoded, ws_b_proj, external_bin);
    EXPECT_EQ(relocated.status, viewer::ProjectBinaryMatchStatus::ExactMatch);
    EXPECT_TRUE(fs::equivalent(relocated.resolved_path, external_bin));

    // Test SHA-256 enforcement when fingerprint matches but SHA-256 differs,
    // closing the reloaded model before mutating/removing external_bin on Windows.
    {
        viewer::BinaryModel verify_model;
        ASSERT_TRUE(verify_model.load_file(external_bin.string()));
        auto tampered_sha_proj = *decoded;
        tampered_sha_proj.source_sha256 = std::string(64, '0');
        EXPECT_FALSE(viewer::restore_project_patches(verify_model, tampered_sha_proj, false));
        EXPECT_TRUE(viewer::restore_project_patches(verify_model, tampered_sha_proj, true));
    }

    // Mutate one byte in place (preserving file size) and verify SHA-256 mismatch detection.
    {
        std::fstream mut(external_bin, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(mut.is_open());
        mut.seekg(0x40);
        char b = 0;
        mut.read(&b, 1);
        b ^= 0xFF;
        mut.seekp(0x40);
        mut.write(&b, 1);
    }
    const auto mismatch = viewer::resolve_project_binary_path(*decoded, ws_b_proj, external_bin);
    EXPECT_EQ(mismatch.status, viewer::ProjectBinaryMatchStatus::ModifiedMismatch);
    EXPECT_NE(mismatch.actual_sha256, decoded->source_sha256);
}

TEST(AnalysisProject, AutosaveCrashRecoveryJournalLifecycleStaysOffMntC) {
    namespace fs = std::filesystem;
    const fs::path default_rec = viewer::default_project_recovery_directory();
    EXPECT_FALSE(default_rec.generic_string().starts_with("/mnt/c"));

    peelf_test::ScopedTempDir temp_dir("peelf_wu09_recovery");
    const fs::path& rec_dir = temp_dir.path();

    viewer::BinaryModel m;
    ASSERT_NO_FATAL_FAILURE(load_fixture_model(m));
    const fs::path fake_peproj = rec_dir / "session.peproj";
    auto clean_proj = viewer::build_analysis_project(m, fake_peproj);
    const std::uint64_t clean_ms = clean_proj.saved_unix_ms;
    EXPECT_FALSE(viewer::check_newer_recovery_journal(fake_peproj, clean_ms, rec_dir).has_value());

    // Simulate dirty edits saved to the crash-recovery journal after clean save.
    m.add_or_update_bookmark(viewer::Bookmark{
        .address = 0x140001050,
        .is_file_offset = false,
        .label = "Recovered Bookmark",
        .category = "CrashTest",
        .note = "unsaved work",
    });
    auto dirty_proj = viewer::build_analysis_project(m, fake_peproj);
    auto journal_path = viewer::write_recovery_journal(dirty_proj, fake_peproj, rec_dir);
    ASSERT_TRUE(journal_path) << journal_path.error().message;
    EXPECT_TRUE(fs::is_regular_file(*journal_path));

    auto recovered = viewer::check_newer_recovery_journal(fake_peproj, clean_ms, rec_dir);
    ASSERT_TRUE(recovered.has_value());
    ASSERT_EQ(recovered->bookmarks.size(), 1u);
    EXPECT_EQ(recovered->bookmarks[0].label, "Recovered Bookmark");
    EXPECT_GT(recovered->saved_unix_ms, clean_ms);

    // If the project itself was saved AFTER the journal, stale journals are ignored.
    const std::uint64_t newer_save_ms = viewer::next_project_timestamp_ms();
    EXPECT_FALSE(viewer::check_newer_recovery_journal(fake_peproj, newer_save_ms, rec_dir).has_value());

    // Explicit clear removes the journal file.
    viewer::clear_recovery_journal(fake_peproj, rec_dir);
    EXPECT_FALSE(fs::exists(*journal_path));
    EXPECT_FALSE(viewer::check_newer_recovery_journal(fake_peproj, 0, rec_dir).has_value());
}

TEST(AnalysisProject, PrefersSha256MatchingCandidateAndSavesNonDestructively) {
    namespace fs = std::filesystem;
    const fs::path fixture = fs::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe";
    peelf_test::ScopedTempDir temp_dir("peelf_fbf05a_project");
    const fs::path& scratch = temp_dir.path();
    std::error_code ec;

    const fs::path orig_dir = scratch / "orig";
    const fs::path stale_rel_dir = scratch / "workspace" / "bin";
    const fs::path proj_dir = scratch / "workspace" / "sessions";
    const fs::path manual_dir = scratch / "manual_drop";
    ASSERT_TRUE(fs::create_directories(orig_dir, ec));
    ASSERT_TRUE(fs::create_directories(stale_rel_dir, ec));
    ASSERT_TRUE(fs::create_directories(proj_dir, ec));
    ASSERT_TRUE(fs::create_directories(manual_dir, ec));

    const fs::path orig_bin = orig_dir / "known-win-x64.exe";
    const fs::path stale_rel_bin = stale_rel_dir / "known-win-x64.exe";
    const fs::path sibling_match_bin = proj_dir / "known-win-x64.exe";
    const fs::path manual_match_bin = manual_dir / "known-win-x64.exe";
    ASSERT_TRUE(fs::copy_file(fixture, orig_bin, fs::copy_options::overwrite_existing, ec));
    ASSERT_TRUE(fs::copy_file(fixture, stale_rel_bin, fs::copy_options::overwrite_existing, ec));
    ASSERT_TRUE(fs::copy_file(fixture, sibling_match_bin, fs::copy_options::overwrite_existing, ec));
    ASSERT_TRUE(fs::copy_file(fixture, manual_match_bin, fs::copy_options::overwrite_existing, ec));

    viewer::BinaryModel m;
    ASSERT_TRUE(m.load_file(orig_bin.string()));

    const fs::path peproj_path = proj_dir / "session.peproj";
    viewer::AnalysisProject proj = viewer::build_analysis_project(m, peproj_path);
    proj.relative_source = "../bin/known-win-x64.exe";
    proj.layout = "preserved-v1-layout";

    // Mutate BOTH earlier candidates (`orig_bin` and `stale_rel_bin`) while keeping `sibling_match_bin` intact.
    for (const fs::path& mutated : {orig_bin, stale_rel_bin}) {
        std::fstream mut(mutated, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(mut.is_open());
        mut.seekg(0x40);
        char byte_val = 0;
        mut.read(&byte_val, 1);
        byte_val ^= static_cast<char>(0x5Au);
        mut.seekp(0x40);
        mut.write(&byte_val, 1);
    }

    // Resolution must skip the modified earlier candidates and select the SHA-256-matching sibling binary.
    const auto resolved_sibling = viewer::resolve_project_binary_path(proj, peproj_path);
    EXPECT_EQ(resolved_sibling.status, viewer::ProjectBinaryMatchStatus::ExactMatch);
    EXPECT_EQ(fs::weakly_canonical(resolved_sibling.resolved_path, ec),
              fs::weakly_canonical(sibling_match_bin, ec));
    EXPECT_EQ(resolved_sibling.actual_sha256, proj.source_sha256);

    // Passing a directory as `manual_relocated_path` also resolves `manual_dir / filename` with SHA-256 match.
    const auto resolved_manual_dir = viewer::resolve_project_binary_path(proj, peproj_path, manual_dir);
    EXPECT_EQ(resolved_manual_dir.status, viewer::ProjectBinaryMatchStatus::ExactMatch);
    EXPECT_EQ(fs::weakly_canonical(resolved_manual_dir.resolved_path, ec),
              fs::weakly_canonical(manual_match_bin, ec));

    // Non-destructive atomic save: write valid v1, then attempt an oversized (> 64 MiB) save and confirm
    // the existing `.peproj` on disk is completely untouched and zero `.tmp` files remain.
    ASSERT_TRUE(viewer::write_analysis_file(peproj_path, viewer::encode_project(proj)));
    const std::string oversized_payload(viewer::kMaxProjectFileBytes + 1024u, 'X');
    EXPECT_FALSE(viewer::write_analysis_file(peproj_path, oversized_payload));

    const auto preserved_text = viewer::read_project_file(peproj_path);
    ASSERT_TRUE(preserved_text.has_value()) << preserved_text.error().message;
    const auto preserved_proj = viewer::decode_project(*preserved_text);
    ASSERT_TRUE(preserved_proj.has_value()) << preserved_proj.error().message;
    EXPECT_EQ(preserved_proj->layout, "preserved-v1-layout");

    for (const auto& entry : fs::directory_iterator(proj_dir, ec)) {
        EXPECT_EQ(entry.path().filename().string().find(".tmp."), std::string::npos);
    }

    // Also verify `read_project_file` rejects an oversized file on disk before allocating/reading it.
    const fs::path huge_file = scratch / "oversized.peproj";
    {
        std::ofstream out(huge_file, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.is_open());
        out.put('P');
    }
    fs::resize_file(huge_file, viewer::kMaxProjectFileBytes + 1u, ec);
    ASSERT_FALSE(ec);
    EXPECT_FALSE(viewer::read_project_file(huge_file).has_value());
}

