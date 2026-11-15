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
