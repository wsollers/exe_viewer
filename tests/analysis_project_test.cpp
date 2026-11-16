#include "analysis/project.hpp"
#include "analysis/patch_preview.hpp"
#include <gtest/gtest.h>
#include <filesystem>

namespace {
viewer::BinaryModel model() {
    viewer::BinaryModel result;
    EXPECT_TRUE(result.load_file((std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe").string()));
    return result;
}
viewer::AnalysisProject project_for(const viewer::BinaryModel& source) {
    viewer::AnalysisProject p; p.source=source.file_info().path; p.source_size=source.bytes().size();
    p.fingerprint=viewer::binary_fingerprint(source.bytes()); return p;
}
}
TEST(AnalysisProject, RoundTripPreservesAnnotationsSymbolsHistoryAndLayout) {
    auto m=model(); auto p=project_for(m);
    p.annotations.emplace(0x1000,viewer::Annotation{"a\"b", "line1\nline2\\"});
    p.symbols.push_back({"named",0x1000,0x140001000,22,true}); p.thumb=true;
    p.history.push_back({.kind=viewer::SelectionKind::ByteRange,.label="here",.file_offset=0,.virtual_address=0x1000,.size=1,
        .preferred_view=viewer::PreferredView::Graph,.graph_root=viewer::SymbolRecord{.name="root",.virtual_address=0x1000,.file_offset=0,.size=32}});
    p.layout="[Window][Flow Graph]\nDockId=1\n";
    auto decoded=viewer::decode_project(viewer::encode_project(p)); ASSERT_TRUE(decoded) << decoded.error().message;
    EXPECT_EQ(decoded->annotations.at(0x1000).comment,p.annotations.at(0x1000).comment);
    EXPECT_EQ(decoded->symbols[0].name,"named"); EXPECT_TRUE(decoded->thumb);
    EXPECT_EQ(decoded->history[0].graph_root->size,32); EXPECT_EQ(decoded->layout,p.layout);
}
TEST(AnalysisProject, PatchRestoreIsOneUndoableTransactionAndValidatesAllRanges) {
    auto m=model(); auto p=project_for(m);
    p.patches={{0,{m.bytes()[0]},{0x12}},{4,{m.bytes()[4]},{0x34}}};
    ASSERT_TRUE(viewer::restore_project_patches(m,p)); EXPECT_EQ((*m.read_effective_bytes(0,1))[0],0x12);
    ASSERT_TRUE(m.undo_patch()); EXPECT_TRUE(m.changed_intervals().empty());
    p.patches[1].original[0]^=1;
    EXPECT_FALSE(viewer::restore_project_patches(m,p)); EXPECT_TRUE(m.changed_intervals().empty());
    p.fingerprint^=1; EXPECT_FALSE(viewer::restore_project_patches(m,p));
}
TEST(AnalysisProject, RejectsBadVersionTruncationOverlapAndHistoryCursor) {
    auto m=model(); auto p=project_for(m);
    EXPECT_FALSE(viewer::decode_project("PEELF_PROJECT 999"));
    auto encoded=viewer::encode_project(p); EXPECT_FALSE(viewer::decode_project(encoded.substr(0,encoded.size()/2)));
    p.cursor=9; EXPECT_FALSE(viewer::decode_project(viewer::encode_project(p))); p.cursor=0;
    p.patches={{1,{0,0},{1,2}},{2,{0},{1}}}; EXPECT_FALSE(viewer::decode_project(viewer::encode_project(p)));
}
TEST(PatchPreview, DoesNotMutateBeforeApplyAndRejectsStalePreview) {
    auto m=model(); auto symbols=viewer::SymbolIndex::build(*m.image());
    const auto offset=m.image()->virtual_address_to_file_offset(m.image()->entry_point()); ASSERT_TRUE(offset);
    const std::uint8_t replacement=0xC3;
    auto p=viewer::preview_patch(m,symbols,*offset,std::span(&replacement,1)); ASSERT_TRUE(p) << p.error().message;
    EXPECT_TRUE(m.changed_intervals().empty()); ASSERT_FALSE(p->after.nodes.empty());
    ASSERT_TRUE(viewer::apply_preview(m,*p)); EXPECT_FALSE(viewer::apply_preview(m,*p));
    EXPECT_NE(viewer::patch_report(m).find("Replacement: C3"),std::string::npos);
    EXPECT_FALSE(viewer::preview_patch(m,symbols,m.bytes().size(),std::span(&replacement,1)));
}
TEST(AnalysisProject, AtomicFileSaveAndReadRoundTrip) {
    auto m=model(); auto p=project_for(m);
    auto path=std::filesystem::temp_directory_path()/"peelf-project-roundtrip.peproj";
    ASSERT_TRUE(viewer::write_analysis_file(path,viewer::encode_project(p)));
    p.layout="second version"; ASSERT_TRUE(viewer::write_analysis_file(path,viewer::encode_project(p)));
    auto text=viewer::read_project_file(path); ASSERT_TRUE(text); auto restored=viewer::decode_project(*text); ASSERT_TRUE(restored);
    EXPECT_EQ(restored->layout,p.layout); std::filesystem::remove(path);
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
    auto m = model();
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
    const fs::path scratch = fs::temp_directory_path() / "peelf-wu09-reloc-test";
    std::error_code ec;
    fs::remove_all(scratch, ec);

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

    fs::remove_all(scratch, ec);
}

TEST(AnalysisProject, AutosaveCrashRecoveryJournalLifecycleStaysOffMntC) {
    namespace fs = std::filesystem;
    const fs::path default_rec = viewer::default_project_recovery_directory();
    EXPECT_FALSE(default_rec.generic_string().starts_with("/mnt/c"));

    const fs::path rec_dir = fs::temp_directory_path() / "peelf-wu09-recovery-test";
    std::error_code ec;
    fs::remove_all(rec_dir, ec);

    auto m = model();
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

    fs::remove_all(rec_dir, ec);
}
