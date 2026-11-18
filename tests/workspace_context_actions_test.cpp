#include "navigation/viewer_navigation.hpp"
#include "ui/context_actions.hpp"
#include "ui/logger.hpp"
#include "ui/workspace_layout.hpp"

#include <peelf/capability_matrix.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace viewer {
namespace {

[[nodiscard]] bool contains_panel(
    std::span<const WorkspacePanelId> panels,
    WorkspacePanelId needle) noexcept {
    return std::ranges::find(panels, needle) != panels.end();
}

[[nodiscard]] const EvaluatedContextAction* find_action(
    std::span<const EvaluatedContextAction> actions,
    ContextActionKind kind) noexcept {
    const auto it = std::ranges::find_if(
        actions,
        [kind](const EvaluatedContextAction& item) { return item.kind == kind; });
    return it != actions.end() ? &(*it) : nullptr;
}

TEST(WorkspaceLayoutTest, AllFivePresetsPassStructuralValidationAndCopyMoveCleanly) {
    for (const WorkspacePreset preset : kAllWorkspacePresets) {
        const WorkspacePresetSpec spec = build_workspace_preset(preset);
        EXPECT_EQ(spec.preset, preset);
        EXPECT_EQ(spec.schema_version, kWorkspaceLayoutSchemaVersion);
        EXPECT_FALSE(spec.display_name.empty());

        const peelf::Result<void> valid = validate_workspace_preset(spec);
        EXPECT_TRUE(valid.has_value()) << (valid ? "" : valid.error().message);

        WorkspacePresetSpec copied = spec;
        copied.display_name += " (copy)";
        EXPECT_NE(copied.display_name, spec.display_name);
        EXPECT_TRUE(validate_workspace_preset(copied).has_value());

        WorkspacePresetSpec assigned = build_workspace_preset(WorkspacePreset::Minimal);
        assigned = spec;
        EXPECT_EQ(assigned.preset, preset);
        EXPECT_TRUE(validate_workspace_preset(assigned).has_value());

        WorkspacePresetSpec temp = build_workspace_preset(preset);
        const WorkspacePresetSpec moved = std::move(temp);
        EXPECT_TRUE(validate_workspace_preset(moved).has_value());
    }
}

TEST(WorkspaceLayoutTest, PanelWindowNameRoundTripsAcrossAll37Panels) {
    EXPECT_EQ(kWorkspaceLayoutSchemaVersion, 10u);
    EXPECT_EQ(kWorkspacePanelCount, 37u);
    const std::span<const WorkspacePanelId> panels = all_workspace_panels();
    EXPECT_EQ(panels.size(), kWorkspacePanelCount);

    for (std::size_t i = 0; i < panels.size(); ++i) {
        const WorkspacePanelId id = panels[i];
        const std::string_view win_name = workspace_panel_window_name(id);
        ASSERT_FALSE(win_name.empty());

        const std::optional<WorkspacePanelId> parsed = workspace_panel_from_window_name(win_name);
        ASSERT_TRUE(parsed.has_value()) << win_name;
        EXPECT_EQ(*parsed, id);
    }
    EXPECT_FALSE(workspace_panel_from_window_name("NonExistentPanel").has_value());
}

TEST(WorkspaceLayoutTest, PresetsCoverExpectedDomainPanels) {
    {
        const WorkspacePresetSpec sre =
            build_workspace_preset(WorkspacePreset::StaticReverseEngineering);
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::ExecutableSettings));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::Disassembly));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::Decompiler));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::FlowGraph));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::HexView));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::StructureView));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::TargetCapabilities));
        EXPECT_TRUE(contains_panel(sre.visible_panels, WorkspacePanelId::Scripting));
    }
    {
        const WorkspacePresetSpec live =
            build_workspace_preset(WorkspacePreset::LiveProcessAndVmmap);
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::MemoryMap));
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::MemoryHeatmap));
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::ProcessInternals));
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::ExecutionTimeline));
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::ThreadsAndStack));
        EXPECT_TRUE(contains_panel(live.visible_panels, WorkspacePanelId::MemorySearch));
    }
    {
        const WorkspacePresetSpec dbg = build_workspace_preset(WorkspacePreset::Debugger);
        EXPECT_TRUE(contains_panel(dbg.visible_panels, WorkspacePanelId::Debugger));
        EXPECT_TRUE(contains_panel(dbg.visible_panels, WorkspacePanelId::ExecutionTimeline));
        EXPECT_TRUE(contains_panel(dbg.visible_panels, WorkspacePanelId::ThreadsAndStack));
        EXPECT_TRUE(contains_panel(dbg.visible_panels, WorkspacePanelId::Disassembly));
        EXPECT_TRUE(contains_panel(dbg.visible_panels, WorkspacePanelId::HexView));
    }
    {
        const WorkspacePresetSpec diff = build_workspace_preset(WorkspacePreset::BinaryDiff);
        EXPECT_TRUE(contains_panel(diff.visible_panels, WorkspacePanelId::BinaryDiff));
        EXPECT_TRUE(contains_panel(diff.visible_panels, WorkspacePanelId::ExecutableSettings));
        EXPECT_TRUE(contains_panel(diff.visible_panels, WorkspacePanelId::Disassembly));
        EXPECT_TRUE(contains_panel(diff.visible_panels, WorkspacePanelId::HexView));
    }
    {
        const WorkspacePresetSpec minimal = build_workspace_preset(WorkspacePreset::Minimal);
        EXPECT_TRUE(contains_panel(minimal.visible_panels, WorkspacePanelId::Disassembly));
        EXPECT_TRUE(contains_panel(minimal.visible_panels, WorkspacePanelId::HexView));
        EXPECT_FALSE(contains_panel(minimal.visible_panels, WorkspacePanelId::Debugger));
        EXPECT_FALSE(contains_panel(minimal.visible_panels, WorkspacePanelId::BinaryDiff));
    }
}

TEST(WorkspaceLayoutTest, ValidatorEnforcesSplitRatioLeafDuplicatesVisibilityAndActiveTab) {
    // Exact boundary split ratios [0.05, 0.95] succeed.
    for (const float ratio : {kMinDockSplitRatio, kMaxDockSplitRatio}) {
        WorkspacePresetSpec boundary_spec{
            .preset = WorkspacePreset::Minimal,
            .display_name = "Boundary",
            .schema_version = kWorkspaceLayoutSchemaVersion,
            .root = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal,
                ratio,
                DockNodeSpec::make_leaf({WorkspacePanelId::Disassembly}),
                DockNodeSpec::make_leaf({WorkspacePanelId::HexView})),
            .visible_panels = {WorkspacePanelId::Disassembly, WorkspacePanelId::HexView},
        };
        EXPECT_TRUE(validate_workspace_preset(boundary_spec).has_value());
    }

    // Out-of-bounds or NaN split ratios fail.
    for (const float bad_ratio :
         {0.049f, 0.951f, -0.2f, std::numeric_limits<float>::quiet_NaN()}) {
        WorkspacePresetSpec bad_split = build_workspace_preset(WorkspacePreset::Minimal);
        bad_split.root.split_ratio = bad_ratio;
        EXPECT_FALSE(validate_workspace_preset(bad_split).has_value());
    }

    // Empty leaf tab list fails.
    {
        WorkspacePresetSpec empty_leaf{
            .preset = WorkspacePreset::Minimal,
            .display_name = "EmptyLeaf",
            .schema_version = kWorkspaceLayoutSchemaVersion,
            .root = DockNodeSpec::make_leaf({}),
            .visible_panels = {WorkspacePanelId::Disassembly},
        };
        EXPECT_FALSE(validate_workspace_preset(empty_leaf).has_value());
    }

    // Duplicate WorkspacePanelId across leaves fails.
    {
        WorkspacePresetSpec dup_spec{
            .preset = WorkspacePreset::Minimal,
            .display_name = "DuplicatePanel",
            .schema_version = kWorkspaceLayoutSchemaVersion,
            .root = DockNodeSpec::make_split(
                DockSplitAxis::Horizontal,
                0.5f,
                DockNodeSpec::make_leaf({WorkspacePanelId::Disassembly}),
                DockNodeSpec::make_leaf({WorkspacePanelId::Disassembly, WorkspacePanelId::HexView})),
            .visible_panels = {WorkspacePanelId::Disassembly, WorkspacePanelId::HexView},
        };
        EXPECT_FALSE(validate_workspace_preset(dup_spec).has_value());
    }

    // Leaf tab missing from visible_panels fails.
    {
        WorkspacePresetSpec missing_vis = build_workspace_preset(WorkspacePreset::Minimal);
        missing_vis.visible_panels.pop_back();
        EXPECT_FALSE(validate_workspace_preset(missing_vis).has_value());
    }

    // Non-member active_tab fails.
    {
        DockNodeSpec leaf = DockNodeSpec::make_leaf({WorkspacePanelId::Disassembly});
        leaf.active_tab = WorkspacePanelId::Debugger;
        WorkspacePresetSpec bad_active{
            .preset = WorkspacePreset::Minimal,
            .display_name = "BadActiveTab",
            .schema_version = kWorkspaceLayoutSchemaVersion,
            .root = std::move(leaf),
            .visible_panels = {WorkspacePanelId::Disassembly},
        };
        EXPECT_FALSE(validate_workspace_preset(bad_active).has_value());
    }
}

TEST(WorkspaceLayoutTest, SchemaVersionMigrationAndIniMetadataRoundTrip) {
    EXPECT_TRUE(should_migrate_workspace_layout(0u));
    EXPECT_TRUE(should_migrate_workspace_layout(kWorkspaceLayoutSchemaVersion - 1u));
    EXPECT_FALSE(should_migrate_workspace_layout(kWorkspaceLayoutSchemaVersion));
    EXPECT_TRUE(should_migrate_workspace_layout(kWorkspaceLayoutSchemaVersion + 1u));

    const std::string legacy_ini =
        "[Window][Disassembly]\nPos=12,34\nSize=800,600\n\n[Docking][Data]\nDockSpace ID=0x1234\n";
    EXPECT_TRUE(should_migrate_workspace_layout_ini(legacy_ini));
    const PersistedWorkspaceLayoutMetadata legacy_meta =
        parse_workspace_layout_metadata(legacy_ini);
    EXPECT_FALSE(legacy_meta.has_metadata_section);
    EXPECT_EQ(legacy_meta.active_preset, WorkspacePreset::StaticReverseEngineering);

    const std::string old_v7_ini = stamp_workspace_layout_metadata(
        legacy_ini, WorkspacePreset::Debugger, kWorkspaceLayoutSchemaVersion - 1u);
    EXPECT_TRUE(should_migrate_workspace_layout_ini(old_v7_ini));
    const PersistedWorkspaceLayoutMetadata v7_meta = parse_workspace_layout_metadata(old_v7_ini);
    EXPECT_TRUE(v7_meta.has_metadata_section);
    EXPECT_EQ(v7_meta.schema_version, kWorkspaceLayoutSchemaVersion - 1u);
    EXPECT_EQ(v7_meta.active_preset, WorkspacePreset::Debugger);

    const std::string migrated_v8_ini = stamp_workspace_layout_metadata(
        old_v7_ini, v7_meta.active_preset, kWorkspaceLayoutSchemaVersion);
    EXPECT_FALSE(should_migrate_workspace_layout_ini(migrated_v8_ini));
    const PersistedWorkspaceLayoutMetadata v8_meta =
        parse_workspace_layout_metadata(migrated_v8_ini);
    EXPECT_TRUE(v8_meta.has_metadata_section);
    EXPECT_EQ(v8_meta.schema_version, kWorkspaceLayoutSchemaVersion);
    EXPECT_EQ(v8_meta.active_preset, WorkspacePreset::Debugger);
    EXPECT_NE(migrated_v8_ini.find("[Window][Disassembly]"), std::string::npos);
}

TEST(ContextActionsTest, StaticPeElfAndMachOCapabilitiesEnableAnalysisAndDisableDebuggerBreakpoint) {
    const InspectableEntity entity{
        .va = 0x140001000ULL,
        .file_offset = 0x400ULL,
        .size = 16ULL,
        .symbol_or_label = "main",
        .module_name = "sample.bin",
    };

    const std::array<peelf::TargetProfile, 3> static_profiles{{
        peelf::TargetProfile{
            .format = peelf::Format::PE,
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::PeWindows64,
            .os = peelf::OsKind::Windows,
            .backend = peelf::BackendKind::StaticFile,
        },
        peelf::TargetProfile{
            .format = peelf::Format::ELF,
            .architecture = peelf::Architecture::ARM64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::AArch64SysV,
            .os = peelf::OsKind::Linux,
            .backend = peelf::BackendKind::StaticFile,
        },
        peelf::TargetProfile{
            .format = peelf::Format::MachO,
            .architecture = peelf::Architecture::ARM64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::AArch64SysV,
            .os = peelf::OsKind::Unknown,
            .backend = peelf::BackendKind::StaticFile,
        },
    }};

    for (const peelf::TargetProfile& profile : static_profiles) {
        const peelf::TargetCapabilityMatrix caps = peelf::capabilities_for(profile);
        const std::vector<EvaluatedContextAction> actions =
            evaluate_context_actions(entity, caps, /*has_static_image=*/true, /*has_active_debugger=*/false);
        ASSERT_EQ(actions.size(), kContextActionCount);

        for (const ContextActionKind expected_enabled : {
                 ContextActionKind::CopyVirtualAddress,
                 ContextActionKind::CopyFileOffset,
                 ContextActionKind::CopyLabel,
                 ContextActionKind::CopyJsonSummary,
                 ContextActionKind::FollowInHex,
                 ContextActionKind::FollowInDisassembly,
                 ContextActionKind::FollowInDecompiler,
                 ContextActionKind::FollowInStructureView,
                 ContextActionKind::AddBookmark,
             }) {
            const EvaluatedContextAction* act = find_action(actions, expected_enabled);
            ASSERT_NE(act, nullptr);
            EXPECT_TRUE(act->enabled)
                << peelf::to_string(profile.format) << " / " << to_string(expected_enabled)
                << ": " << act->disabled_reason;
            EXPECT_TRUE(act->disabled_reason.empty());
        }

        const EvaluatedContextAction* bp =
            find_action(actions, ContextActionKind::ToggleSoftwareBreakpoint);
        ASSERT_NE(bp, nullptr);
        EXPECT_FALSE(bp->enabled);
        EXPECT_FALSE(bp->disabled_reason.empty());
    }
}

TEST(ContextActionsTest, ReadOnlyLiveProcessAndCrashDumpDisableBreakpointAndMissingFileOffset) {
    const InspectableEntity live_heap_entity{
        .va = 0x7FFF55AA1000ULL,
        .file_offset = std::nullopt,
        .size = 4096ULL,
        .symbol_or_label = "[heap]",
        .module_name = {},
    };

    const std::array<peelf::TargetProfile, 2> readonly_runtime_profiles{{
        peelf::TargetProfile{
            .format = peelf::Format::ELF,
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::GnuLinux,
            .os = peelf::OsKind::Linux,
            .backend = peelf::BackendKind::LiveNativeReadOnly,
        },
        peelf::TargetProfile{
            .format = peelf::Format::PE,
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::PeWindows64,
            .os = peelf::OsKind::Windows,
            .backend = peelf::BackendKind::CrashDumpMinidump,
        },
    }};

    for (const peelf::TargetProfile& profile : readonly_runtime_profiles) {
        const peelf::TargetCapabilityMatrix caps = peelf::capabilities_for(profile);
        const std::vector<EvaluatedContextAction> actions = evaluate_context_actions(
            live_heap_entity,
            caps,
            /*has_static_image=*/false,
            /*has_active_debugger=*/false);

        const EvaluatedContextAction* copy_va =
            find_action(actions, ContextActionKind::CopyVirtualAddress);
        ASSERT_NE(copy_va, nullptr);
        EXPECT_TRUE(copy_va->enabled);

        const EvaluatedContextAction* copy_off =
            find_action(actions, ContextActionKind::CopyFileOffset);
        ASSERT_NE(copy_off, nullptr);
        EXPECT_FALSE(copy_off->enabled);
        EXPECT_FALSE(copy_off->disabled_reason.empty());

        const EvaluatedContextAction* follow_hex =
            find_action(actions, ContextActionKind::FollowInHex);
        ASSERT_NE(follow_hex, nullptr);
        EXPECT_TRUE(follow_hex->enabled);

        const EvaluatedContextAction* follow_disasm =
            find_action(actions, ContextActionKind::FollowInDisassembly);
        ASSERT_NE(follow_disasm, nullptr);
        EXPECT_TRUE(follow_disasm->enabled);

        const EvaluatedContextAction* bp =
            find_action(actions, ContextActionKind::ToggleSoftwareBreakpoint);
        ASSERT_NE(bp, nullptr);
        EXPECT_FALSE(bp->enabled);
        EXPECT_EQ(bp->disabled_reason, caps.get(peelf::Operation::SoftwareBreakpoints).reason);
        EXPECT_FALSE(bp->disabled_reason.empty());
    }
}

TEST(ContextActionsTest, ActiveDebuggerEnablesSoftwareBreakpointOnlyWhenVirtualAddressPresent) {
    const peelf::ProviderFacts dbg_providers{
        .host_os = peelf::OsKind::Linux,
        .host_arch = peelf::Architecture::X86_64,
        .capstone_available = true,
        .asmtk_available = true,
        .native_process_attach_available = true,
        .native_debugger_available = true,
    };
    const peelf::TargetCapabilityMatrix dbg_caps = peelf::capabilities_for(
        peelf::TargetProfile{
            .format = peelf::Format::ELF,
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .abi = peelf::AbiKind::GnuLinux,
            .os = peelf::OsKind::Linux,
            .backend = peelf::BackendKind::ActiveDebugger,
        },
        dbg_providers);

    const InspectableEntity code_entity{
        .va = 0x401120ULL,
        .file_offset = std::nullopt,
        .size = 5ULL,
        .symbol_or_label = "call target",
    };
    const std::vector<EvaluatedContextAction> with_va = evaluate_context_actions(
        code_entity, dbg_caps, /*has_static_image=*/false, /*has_active_debugger=*/true);
    const EvaluatedContextAction* bp_ok =
        find_action(with_va, ContextActionKind::ToggleSoftwareBreakpoint);
    ASSERT_NE(bp_ok, nullptr);
    EXPECT_TRUE(bp_ok->enabled);
    EXPECT_TRUE(bp_ok->disabled_reason.empty());

    const InspectableEntity header_only_entity{
        .va = std::nullopt,
        .file_offset = std::nullopt,
        .size = 0ULL,
        .symbol_or_label = "MACHO4002: Missing Hardened Runtime",
    };
    const std::vector<EvaluatedContextAction> without_va = evaluate_context_actions(
        header_only_entity, dbg_caps, /*has_static_image=*/false, /*has_active_debugger=*/true);
    const EvaluatedContextAction* bp_no_va =
        find_action(without_va, ContextActionKind::ToggleSoftwareBreakpoint);
    ASSERT_NE(bp_no_va, nullptr);
    EXPECT_FALSE(bp_no_va->enabled);
    EXPECT_FALSE(bp_no_va->disabled_reason.empty());
}

TEST(ContextActionsTest, JsonSummaryEscapesSpecialAndControlCharactersPerRfc8259) {
    const InspectableEntity entity{
        .va = 0x1000ULL,
        .file_offset = 0x200ULL,
        .size = 32ULL,
        .symbol_or_label = "fn_\"quoted\"\\slash\nline2\t\x01",
        .module_name = "C:\\bins\\test.exe",
        .extra_json_fields = {
            {"rule\"id", "OLD"},
            {"rule\"id", "PE1001\r\n"},
        },
    };

    const std::string json = format_entity_json_summary(entity);
    EXPECT_NE(json.find("\"va\": \"0x1000\""), std::string::npos);
    EXPECT_NE(json.find("\"file_offset\": \"0x200\""), std::string::npos);
    EXPECT_NE(json.find("\"size\": 32"), std::string::npos);
    EXPECT_NE(
        json.find("\"symbol_or_label\": \"fn_\\\"quoted\\\"\\\\slash\\nline2\\t\\u0001\""),
        std::string::npos);
    EXPECT_NE(json.find("\"module_name\": \"C:\\\\bins\\\\test.exe\""), std::string::npos);
    EXPECT_NE(json.find("\"extra\": {\n    \"rule\\\"id\": \"PE1001\\r\\n\"\n  }"), std::string::npos);
    EXPECT_EQ(json.find("OLD"), std::string::npos);

    const InspectableEntity null_coords_entity{
        .va = std::nullopt,
        .file_offset = std::nullopt,
        .size = 0ULL,
        .symbol_or_label = "\b\f",
    };
    const std::string null_json = format_entity_json_summary(null_coords_entity);
    EXPECT_NE(null_json.find("\"va\": null"), std::string::npos);
    EXPECT_NE(null_json.find("\"file_offset\": null"), std::string::npos);
    EXPECT_NE(null_json.find("\"symbol_or_label\": \"\\b\\f\""), std::string::npos);

    EXPECT_EQ(format_context_copy_payload(ContextActionKind::CopyVirtualAddress, entity), "0x1000");
    EXPECT_EQ(format_context_copy_payload(ContextActionKind::CopyFileOffset, entity), "0x200");
    EXPECT_EQ(
        format_context_copy_payload(ContextActionKind::CopyLabel, entity),
        entity.symbol_or_label);
    EXPECT_EQ(format_context_copy_payload(ContextActionKind::CopyJsonSummary, entity), json);
    EXPECT_FALSE(
        format_context_copy_payload(ContextActionKind::FollowInHex, entity).has_value());
}

TEST(ContextActionsTest, EnqueuesFollowInActionsOntoNavigationRequestQueueWithoutMidLoopMutation) {
    NavigationRequestQueue queue;

    const InspectableEntity va_entity{
        .va = 0x402000ULL,
        .file_offset = 0x1000ULL,
        .size = 24ULL,
        .symbol_or_label = "entry",
    };
    const InspectableEntity offset_only_entity{
        .va = std::nullopt,
        .file_offset = 0x80ULL,
        .size = 64ULL,
        .symbol_or_label = "mach_header_64",
    };

    EXPECT_TRUE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInHex, va_entity, /*has_static_image=*/true));
    EXPECT_TRUE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInDisassembly, va_entity, /*has_static_image=*/true));
    EXPECT_TRUE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInDecompiler, va_entity, /*has_static_image=*/true));
    EXPECT_TRUE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInStructureView, va_entity, /*has_static_image=*/true));
    EXPECT_TRUE(enqueue_context_navigation_action(
        queue,
        ContextActionKind::FollowInStructureView,
        offset_only_entity,
        /*has_static_image=*/true));
    // Live target without static image rejects file-offset-only FollowIn* cleanly.
    EXPECT_FALSE(enqueue_context_navigation_action(
        queue,
        ContextActionKind::FollowInHex,
        offset_only_entity,
        /*has_static_image=*/false));

    std::vector<NavigationRequest> drained;
    queue.drain([&](NavigationRequest& req) { drained.push_back(req); });

    ASSERT_EQ(drained.size(), 5u);

    EXPECT_EQ(drained[0].kind, NavigationRequest::Kind::Address);
    EXPECT_EQ(drained[0].target, 0x402000ULL);
    EXPECT_EQ(drained[0].preferred_view, PreferredView::Hex);
    EXPECT_EQ(drained[0].highlight_size, 24u);
    EXPECT_FALSE(drained[0].request_decompile);
    EXPECT_FALSE(drained[0].open_structure_view);

    EXPECT_EQ(drained[1].kind, NavigationRequest::Kind::Address);
    EXPECT_EQ(drained[1].preferred_view, PreferredView::Disassembly);

    EXPECT_EQ(drained[2].kind, NavigationRequest::Kind::Address);
    EXPECT_EQ(drained[2].preferred_view, PreferredView::Disassembly);
    EXPECT_TRUE(drained[2].request_decompile);

    EXPECT_EQ(drained[3].kind, NavigationRequest::Kind::Address);
    EXPECT_EQ(drained[3].preferred_view, PreferredView::Details);
    EXPECT_TRUE(drained[3].open_structure_view);

    EXPECT_EQ(drained[4].kind, NavigationRequest::Kind::Offset);
    EXPECT_EQ(drained[4].target, 0x80ULL);
    EXPECT_EQ(drained[4].highlight_size, 64u);
    EXPECT_TRUE(drained[4].open_structure_view);
}

TEST(ContextActionsTest, SanitizesInvalidUtf8SequencesWithReplacementEscapeAndRejectsNonNavigableDecompile) {
    // Valid multi-byte UTF-8 ("λ" = CE BB, "🚀" = F0 9F 9A 80) is preserved,
    // while lone continuation (0x80), invalid 0xFF, overlong 0xC0 0xAF,
    // UTF-16 surrogate (ED A0 80), and truncated 3-byte prefix (E2 82) before 'A'
    // are replaced with \uFFFD without swallowing 'A'.
    const std::string mixed_label =
        std::string("ok_\xCE\xBB_\xF0\x9F\x9A\x80_") +
        std::string("\x80", 1u) + "_" +
        std::string("\xFF", 1u) + "_" +
        std::string("\xC0\xAF", 2u) + "_" +
        std::string("\xED\xA0\x80", 3u) + "_" +
        std::string("\xE2\x82" "A", 3u);

    const InspectableEntity entity{
        .va = 0x401000ULL,
        .file_offset = 0x100ULL,
        .size = 4ULL,
        .symbol_or_label = mixed_label,
        .module_name = std::string("mod\xF4\x90\x80\x80.dll", 11u),
    };

    const std::string json = format_entity_json_summary(entity);
    EXPECT_NE(json.find("ok_\xCE\xBB_\xF0\x9F\x9A\x80_\\uFFFD_\\uFFFD_\\uFFFD\\uFFFD_\\uFFFD\\uFFFD\\uFFFD_\\uFFFDA"),
              std::string::npos)
        << json;
    EXPECT_NE(json.find("mod\\uFFFD\\uFFFD\\uFFFD\\uFFFD.dll"), std::string::npos) << json;

    // FollowInDecompiler must reject file-offset-only and unmapped zero-VA entities.
    NavigationRequestQueue queue;
    const InspectableEntity offset_only{
        .va = std::nullopt,
        .file_offset = 0x80ULL,
        .size = 16ULL,
        .symbol_or_label = "dos_header",
    };
    const InspectableEntity zero_unmapped{
        .va = 0ULL,
        .file_offset = std::nullopt,
        .size = 0ULL,
        .symbol_or_label = "undef_sym",
    };
    EXPECT_FALSE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInDecompiler, offset_only, /*has_static_image=*/true));
    EXPECT_FALSE(enqueue_context_navigation_action(
        queue, ContextActionKind::FollowInDecompiler, zero_unmapped, /*has_static_image=*/true));
}

TEST(ContextActionsTest, LoggerHandlesZeroCapacityAndConcurrentSnapshotSafely) {
    Logger& log = Logger::instance();
    const std::size_t prev_cap = log.capacity();

    log.set_capacity(0u);
    EXPECT_EQ(log.capacity(), 0u);
    log.info("dropped safely without modulo-by-zero");
    EXPECT_TRUE(log.snapshot().empty());

    log.set_capacity(64u);
    log.clear();

    std::jthread writer([&log]() {
        for (int i = 0; i < 200; ++i) {
            log.info("worker msg {}", i);
        }
    });
    for (int i = 0; i < 50; ++i) {
        const auto snap = log.snapshot();
        EXPECT_LE(snap.size(), 64u);
        std::size_t visited = 0u;
        log.for_each_entry([&visited](const LogEntry&) noexcept { ++visited; });
        EXPECT_LE(visited, 64u);
    }
    writer.join();

    const auto final_snap = log.snapshot();
    EXPECT_EQ(final_snap.size(), 64u);

    log.clear();
    log.set_capacity(prev_cap > 0u ? prev_cap : 1000u);
}

} // namespace
} // namespace viewer
