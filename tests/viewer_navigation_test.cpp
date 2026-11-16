#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "graph/call_graph.hpp"
#include "navigation/byte_range.hpp"
#include "navigation/viewer_navigation.hpp"
#include <peelf/binary_image.hpp>
#include <peelf/handlers.hpp>
#include <peelf/stack_tls.hpp>

TEST(NavigationHistory, BackForwardAndBranchingPreserveSelections) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection a{.label="a", .file_offset=10, .virtual_address=0x1000, .size=4,
        .preferred_view=viewer::PreferredView::Graph};
    auto b = a; b.virtual_address=0x2000; b.file_offset=20;
    auto c = a; c.virtual_address=0x3000; c.file_offset=30;
    EXPECT_FALSE(history.back());
    history.visit(a); history.visit(b); history.visit(b);
    ASSERT_TRUE(history.can_back());
    const auto previous = history.back();
    ASSERT_TRUE(previous);
    EXPECT_EQ(previous->virtual_address,a.virtual_address);
    EXPECT_EQ(previous->size,4);
    EXPECT_EQ(previous->preferred_view,viewer::PreferredView::Graph);
    EXPECT_FALSE(history.can_back());
    ASSERT_TRUE(history.forward());
    ASSERT_TRUE(history.back());
    history.visit(c);
    EXPECT_FALSE(history.can_forward());
    EXPECT_EQ(history.back()->virtual_address,a.virtual_address);
    history.clear();
    EXPECT_FALSE(history.can_back()); EXPECT_FALSE(history.can_forward());
}

TEST(NavigationHistory, ViewChangesUpdateCurrentEntryAndHistoryIsBounded) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection selection{.file_offset=0, .virtual_address=0, .preferred_view=viewer::PreferredView::Graph};
    history.visit(selection);
    selection.preferred_view=viewer::PreferredView::Disassembly;
    history.visit(selection);
    EXPECT_FALSE(history.can_back());
    for (std::uint64_t i=1; i<300; ++i) {
        selection.file_offset=i; selection.virtual_address=i;
        history.visit(selection);
    }
    int count=0;
    while (history.back()) ++count;
    EXPECT_EQ(count,255);
    history.clear();
    history.visit({});
    EXPECT_FALSE(history.forward()); EXPECT_FALSE(history.back());
}

TEST(NavigationHistory, RetainsUnsymbolizedGraphOriginAcrossViewsAndOtherFunctions) {
    viewer::NavigationHistory history;
    viewer::ViewerSelection block{.file_offset=0x40, .virtual_address=0x1040,
        .preferred_view=viewer::PreferredView::Graph,
        .graph_root=viewer::SymbolRecord{.name="sub_1000", .virtual_address=0x1000, .file_offset=0, .size=0}};
    history.visit(block);
    block.preferred_view=viewer::PreferredView::Disassembly;
    history.visit(block);
    auto callee=block;
    callee.virtual_address=0x2040;
    callee.file_offset=0x1040;
    callee.graph_root=viewer::SymbolRecord{.name="sub_2000", .virtual_address=0x2000, .file_offset=0x1000};
    history.visit(callee);
    const auto restored=history.back();
    ASSERT_TRUE(restored);
    ASSERT_TRUE(restored->graph_root);
    EXPECT_EQ(restored->virtual_address,0x1040);
    EXPECT_EQ(restored->graph_root->virtual_address,0x1000);
    EXPECT_EQ(restored->preferred_view,viewer::PreferredView::Disassembly);
    const auto next=history.forward();
    ASSERT_TRUE(next);
    ASSERT_TRUE(next->graph_root);
    EXPECT_EQ(next->graph_root->virtual_address,0x2000);
}

namespace {

[[nodiscard]] std::vector<std::uint8_t> read_fixture(const std::string& name) {
    const std::filesystem::path path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

[[nodiscard]] std::unique_ptr<peelf::IBinaryImage> parse_fixture(const std::string& name) {
    std::vector<std::uint8_t> bytes = read_fixture(name);
    auto parsed = peelf::parse_image(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    EXPECT_TRUE(parsed.has_value()) << name;
    if (!parsed) {
        return {};
    }
    return std::move(*parsed);
}

[[nodiscard]] const viewer::StructureNode* find_child(const viewer::StructureNode& node,
                                                      const std::string& label) {
    const auto it = std::ranges::find_if(node.children, [&](const viewer::StructureNode& child) {
        return child.selection.label == label;
    });
    return it == node.children.end() ? nullptr : &*it;
}

[[nodiscard]] const viewer::StructureNode* find_kind(const viewer::StructureNode& node,
                                                     viewer::SelectionKind kind) {
    if (node.selection.kind == kind) {
        return &node;
    }
    for (const viewer::StructureNode& child : node.children) {
        if (const viewer::StructureNode* found = find_kind(child, kind)) {
            return found;
        }
    }
    return nullptr;
}

} // namespace

TEST(ViewerNavigation, BuildsElfStructureTreeWithSelectableExecutableSection) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);

    const viewer::StructureNode tree = viewer::build_structure_tree(*image);

    EXPECT_EQ(tree.selection.kind, viewer::SelectionKind::Image);
    EXPECT_EQ(tree.selection.label, "ELF Image");
    ASSERT_TRUE(tree.selection.virtual_address.has_value());
    EXPECT_EQ(*tree.selection.virtual_address, image->entry_point());

    const viewer::StructureNode* headers = find_child(tree, "Headers");
    ASSERT_NE(headers, nullptr);
    EXPECT_NE(find_child(*headers, "ELF File Header"), nullptr);

    const viewer::StructureNode* sections = find_child(tree, "Sections");
    ASSERT_NE(sections, nullptr);
    const viewer::StructureNode* text = find_child(*sections, ".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->selection.kind, viewer::SelectionKind::Section);
    EXPECT_EQ(text->selection.preferred_view, viewer::PreferredView::Disassembly);
    ASSERT_TRUE(text->selection.file_offset.has_value());
    ASSERT_TRUE(text->selection.virtual_address.has_value());
    EXPECT_GT(text->selection.size, 0u);

    EXPECT_NE(find_child(tree, "Segments"), nullptr);
    EXPECT_NE(find_child(tree, "Dynamic Entries"), nullptr);
    EXPECT_NE(find_child(tree, "Relocations"), nullptr);
    EXPECT_NE(find_child(tree, "Notes"), nullptr);
    EXPECT_NE(find_child(tree, "Hash Tables"), nullptr);
    EXPECT_NE(find_kind(tree, viewer::SelectionKind::Symbol), nullptr);
}

TEST(ViewerNavigation, BuildsPeStructureTreeWithRelocationAndDebugSelections) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::StructureNode tree = viewer::build_structure_tree(*image);

    EXPECT_EQ(tree.selection.kind, viewer::SelectionKind::Image);
    EXPECT_EQ(tree.selection.label, "PE Image");

    const viewer::StructureNode* headers = find_child(tree, "Headers");
    ASSERT_NE(headers, nullptr);
    EXPECT_NE(find_child(*headers, "DOS Header"), nullptr);
    EXPECT_NE(find_child(*headers, "PE/COFF Headers"), nullptr);

    const viewer::StructureNode* sections = find_child(tree, "Sections");
    ASSERT_NE(sections, nullptr);
    EXPECT_NE(find_child(*sections, ".text"), nullptr);

    const viewer::StructureNode* imports = find_child(tree, "Imports");
    ASSERT_NE(imports, nullptr);
    EXPECT_NE(find_child(*imports, "USER32.dll!MessageBoxA (delay)"), nullptr);

    const viewer::StructureNode* relocations = find_child(tree, "Base Relocations");
    ASSERT_NE(relocations, nullptr);
    ASSERT_FALSE(relocations->children.empty());
    EXPECT_EQ(relocations->children.front().selection.kind, viewer::SelectionKind::Relocation);
    EXPECT_EQ(relocations->children.front().selection.preferred_view, viewer::PreferredView::Details);
    EXPECT_GT(relocations->children.front().selection.size, 0u);

    const viewer::StructureNode* debug = find_child(tree, "Debug Directories");
    ASSERT_NE(debug, nullptr);
    ASSERT_FALSE(debug->children.empty());
    EXPECT_EQ(debug->children.front().selection.kind, viewer::SelectionKind::DebugDirectory);
    EXPECT_TRUE(debug->children.front().selection.file_offset.has_value());
    EXPECT_GT(debug->children.front().selection.size, 0u);

    const viewer::StructureNode* runtime_functions = find_child(tree, "Runtime Functions");
    ASSERT_NE(runtime_functions, nullptr);
    ASSERT_FALSE(runtime_functions->children.empty());
    EXPECT_EQ(runtime_functions->children.front().selection.kind, viewer::SelectionKind::RuntimeFunction);
    EXPECT_TRUE(runtime_functions->children.front().selection.file_offset.has_value());
    EXPECT_GT(runtime_functions->children.front().selection.size, 0u);

    const viewer::StructureNode* tls = find_child(tree, "TLS Directory");
    ASSERT_NE(tls, nullptr);
    EXPECT_EQ(tls->selection.kind, viewer::SelectionKind::TlsDirectory);
    EXPECT_TRUE(tls->selection.virtual_address.has_value());

    const viewer::StructureNode* certificates = find_child(tree, "Certificates");
    ASSERT_NE(certificates, nullptr);
    ASSERT_FALSE(certificates->children.empty());
    EXPECT_EQ(certificates->children.front().selection.kind, viewer::SelectionKind::Certificate);
    EXPECT_TRUE(certificates->children.front().selection.file_offset.has_value());
    EXPECT_GT(certificates->children.front().selection.size, 0u);

    const viewer::StructureNode* load_config = find_child(tree, "Load Config");
    ASSERT_NE(load_config, nullptr);
    EXPECT_EQ(load_config->selection.kind, viewer::SelectionKind::LoadConfig);
    EXPECT_TRUE(load_config->selection.file_offset.has_value());
    EXPECT_GT(load_config->selection.size, 0u);

    const viewer::StructureNode* bound_imports = find_child(tree, "Bound Imports");
    ASSERT_NE(bound_imports, nullptr);
    ASSERT_FALSE(bound_imports->children.empty());
    EXPECT_EQ(bound_imports->children.front().selection.kind, viewer::SelectionKind::BoundImport);
    EXPECT_TRUE(bound_imports->children.front().selection.file_offset.has_value());
    EXPECT_GT(bound_imports->children.front().selection.size, 0u);

    const viewer::StructureNode* resource = find_child(tree, "Resource Directory");
    ASSERT_NE(resource, nullptr);
    EXPECT_EQ(resource->selection.kind, viewer::SelectionKind::ResourceDirectory);
    EXPECT_TRUE(resource->selection.file_offset.has_value());
    EXPECT_GT(resource->selection.size, 0u);
    ASSERT_FALSE(resource->children.empty());
    EXPECT_EQ(resource->children.front().selection.kind, viewer::SelectionKind::ResourceData);
    EXPECT_TRUE(resource->children.front().selection.file_offset.has_value());
    EXPECT_EQ(resource->children.front().selection.size, 0x10u);

    const viewer::StructureNode* clr = find_child(tree, "CLR Header");
    ASSERT_NE(clr, nullptr);
    EXPECT_EQ(clr->selection.kind, viewer::SelectionKind::ClrHeader);
    EXPECT_TRUE(clr->selection.file_offset.has_value());
    EXPECT_EQ(clr->selection.size, 0x48u);
}

TEST(ViewerNavigation, BuildsSelectionPayloadFromCallGraphFunctionNode) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraphNode node{
        .id = "root",
        .label = "known_export",
        .kind = viewer::CallGraphNodeKind::Function,
        .bytes = viewer::GraphByteRange{
            .start = viewer::GraphAddress{
                .virtual_address = 0x140001000,
            },
            .size = 0x10,
        },
        .symbol = viewer::GraphSymbolRef{
            .name = "known_export",
            .symbol_index = 3,
        },
    };

    const viewer::ViewerSelection selection = viewer::selection_from_call_graph_node(node, *image);

    EXPECT_EQ(selection.kind, viewer::SelectionKind::CallGraphNode);
    EXPECT_EQ(selection.label, "known_export");
    EXPECT_EQ(selection.preferred_view, viewer::PreferredView::Disassembly);
    EXPECT_EQ(selection.object_index, 3u);
    ASSERT_TRUE(selection.virtual_address.has_value());
    EXPECT_EQ(*selection.virtual_address, 0x140001000u);
    ASSERT_TRUE(selection.file_offset.has_value());
    EXPECT_EQ(*selection.file_offset, 0x220u);
    EXPECT_EQ(selection.size, 0x10u);
}

TEST(ViewerNavigation, BuildsDetailsOnlySelectionForUnmappedCallGraphNode) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-win-x64.exe");
    ASSERT_NE(image, nullptr);

    const viewer::CallGraphNode node{
        .id = "imports_summary",
        .label = "Imports",
        .kind = viewer::CallGraphNodeKind::Import,
    };

    const viewer::ViewerSelection selection = viewer::selection_from_call_graph_node(node, *image);

    EXPECT_EQ(selection.kind, viewer::SelectionKind::CallGraphNode);
    EXPECT_EQ(selection.label, "Imports");
    EXPECT_EQ(selection.preferred_view, viewer::PreferredView::Details);
    EXPECT_FALSE(selection.file_offset.has_value());
    EXPECT_FALSE(selection.virtual_address.has_value());
    EXPECT_EQ(selection.size, 0u);
}

TEST(ViewerNavigation, MapsSymbolAndCallGraphSelectionsToSymbolRows) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);
    const auto symbol_it = std::ranges::find_if(image->symbols(), [](const peelf::Symbol& symbol) {
        return !symbol.name.empty() && symbol.virtual_address != 0;
    });
    ASSERT_NE(symbol_it, image->symbols().end());
    const std::uint64_t symbol_index = static_cast<std::uint64_t>(std::distance(image->symbols().begin(), symbol_it));

    const viewer::ViewerSelection symbol_selection{
        .kind = viewer::SelectionKind::Symbol,
        .label = symbol_it->name,
        .object_index = symbol_index,
    };
    EXPECT_EQ(viewer::selected_symbol_index(symbol_selection, *image), symbol_index);

    const viewer::ViewerSelection graph_selection{
        .kind = viewer::SelectionKind::CallGraphNode,
        .label = symbol_it->name,
        .virtual_address = symbol_it->virtual_address,
        .object_index = symbol_index,
    };
    EXPECT_EQ(viewer::selected_symbol_index(graph_selection, *image), symbol_index);
}

TEST(ViewerNavigation, DoesNotMapUnresolvedCallGraphSelectionToFirstSymbol) {
    const std::unique_ptr<peelf::IBinaryImage> image = parse_fixture("known-linux-x64.elf");
    ASSERT_NE(image, nullptr);
    ASSERT_FALSE(image->symbols().empty());

    const viewer::ViewerSelection graph_selection{
        .kind = viewer::SelectionKind::CallGraphNode,
        .label = "Imports",
        .object_index = 0,
    };

    EXPECT_EQ(viewer::selected_symbol_index(graph_selection, *image), std::nullopt);
}

TEST(DeferredNavigationQueue, DrainsFifoOutsideRowIterationAndHandlesReentrantEnqueue) {
    viewer::NavigationRequestQueue queue;
    std::vector<std::uint64_t> active_module_rows{0x401000u, 0x402000u, 0x7FF01000u};
    std::vector<std::string> execution_log;

    // Simulate clicking a cross-module row during an ImGui table loop:
    // backing vector must remain untouched until EndTable() + queue.drain().
    const std::uint64_t* initial_data_ptr = active_module_rows.data();
    for (std::uint64_t va : active_module_rows) {
        if (va == 0x402000u) {
            queue.enqueue_address(va, viewer::PreferredView::Disassembly);
        }
        EXPECT_EQ(active_module_rows.data(), initial_data_ptr);
    }
    EXPECT_FALSE(queue.empty());
    EXPECT_EQ(queue.size(), 1u);

    queue.enqueue_module(2u);

    const std::size_t processed = queue.drain([&](viewer::DeferredNavigationRequest& req) {
        using Kind = viewer::DeferredNavigationRequest::Kind;
        if (req.kind == Kind::Address) {
            execution_log.push_back("addr:" + std::to_string(req.target));
            // Simulate select_live_module() replacing model vectors safely during drain:
            active_module_rows = {0x900000u, 0x900010u, 0x900020u, 0x900030u};
            // Re-entrant enqueue during drain must execute in the subsequent pass:
            queue.enqueue_custom([&]() { execution_log.push_back("followup_custom"); });
        } else if (req.kind == Kind::ModuleIndex) {
            execution_log.push_back("mod:" + std::to_string(req.target));
        } else if (req.kind == Kind::Custom && req.custom_action) {
            req.custom_action();
        }
    });

    EXPECT_EQ(processed, 3u);
    EXPECT_TRUE(queue.empty());
    ASSERT_EQ(execution_log.size(), 3u);
    EXPECT_EQ(execution_log[0], "addr:4202496");
    EXPECT_EQ(execution_log[1], "mod:2");
    EXPECT_EQ(execution_log[2], "followup_custom");
}

TEST(DeferredNavigationQueue, GuardsAgainstRunawayReentrantCycles) {
    viewer::NavigationRequestQueue queue;
    queue.enqueue_offset(0x1000u);
    std::size_t invocations = 0;
    const std::size_t processed = queue.drain([&](viewer::DeferredNavigationRequest& req) {
        ++invocations;
        // Attempt infinite re-enqueue: drain() caps passes to 8 and clears remaining.
        queue.enqueue_offset(req.target + 1u);
    });
    EXPECT_EQ(processed, 8u);
    EXPECT_EQ(invocations, 8u);
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(queue.is_draining());
}

TEST(ByteRange64BitSafety, PreservesOffsetsAbove4GiBAndRejectsOutOfBounds) {
    constexpr std::uint64_t kLargeFileSize = 0x2'8000'0000ULL; // 10 GiB
    const auto range = viewer::selected_byte_range(
        0x2'0000'1000ULL, 0x2'0000'103FULL, kLargeFileSize);
    ASSERT_TRUE(range.has_value());
    EXPECT_EQ(range->offset, 0x2'0000'1000ULL);
    EXPECT_EQ(range->size, 0x40ULL);

    EXPECT_FALSE(viewer::selected_byte_range(
                     kLargeFileSize, 0x2'0000'1000ULL, kLargeFileSize)
                     .has_value());
}

TEST(CheckedHandlerRelocationMath, HandlesSignedBoundsAndRejectsWraparound) {
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x402000ULL, -0x1000LL, true),
              std::optional<std::uint64_t>(0x401000ULL));
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x402000ULL, 0x280LL, true),
              std::optional<std::uint64_t>(0x402280ULL));

    // Negative displacement larger than base must fail instead of wrapping around 2^64.
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x1000ULL, -0x1001LL, true),
              std::nullopt);

    // Positive displacement overflowing UINT64_MAX must fail.
    EXPECT_EQ(peelf::checked_apply_signed_displacement(
                  std::numeric_limits<std::uint64_t>::max() - 3ULL, 4LL, true),
              std::nullopt);

    // INT64_MIN must not trigger signed negation UB:
    constexpr std::int64_t kMinI64 = std::numeric_limits<std::int64_t>::min();
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x7FFF'FFFF'FFFF'FFFFULL, kMinI64, true),
              std::nullopt);
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x8000'0000'0000'0000ULL, kMinI64, true),
              std::optional<std::uint64_t>(0ULL));

    // 32-bit target mode masks/rejects out-of-32-bit range cleanly:
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0x08049000ULL, -0x1000LL, false),
              std::optional<std::uint64_t>(0x08048000ULL));
    EXPECT_EQ(peelf::checked_apply_signed_displacement(0xFFFF'FFF0ULL, 0x20LL, false),
              std::nullopt);
}

namespace {

class PartialStackSession final : public peelf::IProcessSession {
public:
    PartialStackSession() {
        info_.pid = 4242u;
        info_.name = "partial_stack_fixture";
        info_.architecture = peelf::Architecture::X86_64;
        info_.is_64bit = true;
        info_.endianness = peelf::Endianness::Little;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return std::vector<peelf::MemoryRegion>{};
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }
    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address, std::span<std::uint8_t> buffer) override {
        // Simulate page-granular stack validity across 3 pages starting at SP = 0x7FFF00001FF8:
        // - [0x7FFF00001FF8 .. 0x7FFF00001FFB]: 4 readable bytes (EF BE AD DE), short-read at 0x1FFC
        // - [0x7FFF00002000 .. 0x7FFF00002FFF]: completely unreadable guard/hole page
        // - [0x7FFF00003000 .. 0x7FFF00003007]: 8 readable bytes (11 22 33 44 55 66 77 88)
        constexpr std::uint64_t kChunk0Start = 0x7FFF'0000'1FF8ULL;
        constexpr std::array<std::uint8_t, 4> kChunk0 = {0xEFu, 0xBEu, 0xADu, 0xDEu};
        constexpr std::uint64_t kChunk1Start = 0x7FFF'0000'3000ULL;
        constexpr std::array<std::uint8_t, 8> kChunk1 = {
            0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};

        std::size_t copied = 0;
        for (std::size_t i = 0; i < buffer.size(); ++i) {
            const std::uint64_t cur = address + i;
            if (cur >= kChunk0Start && cur < kChunk0Start + kChunk0.size()) {
                buffer[copied++] = kChunk0[static_cast<std::size_t>(cur - kChunk0Start)];
            } else if (cur >= kChunk1Start && cur < kChunk1Start + kChunk1.size()) {
                buffer[copied++] = kChunk1[static_cast<std::size_t>(cur - kChunk1Start)];
            } else {
                break;
            }
        }
        if (copied == 0u) {
            return peelf::make_error("unmapped stack range");
        }
        return copied;
    }

private:
    peelf::ProcessInfo info_{};
};

} // namespace

TEST(StackByteValidity, PreservesPartialAndUnreadableBytesInsteadOfZeroFlattening) {
    PartialStackSession session;
    const peelf::TargetLayout layout = session.target_layout();

    peelf::ThreadContext ctx{};
    ctx.tid = 1001u;
    ctx.layout = layout;
    ctx.stack_pointer = 0x7FFF'0000'1FF8ULL;
    ctx.instruction_pointer = 0x401000ULL;
    ctx.status = peelf::SubsystemStatus::available("test");

    peelf::MemoryRegion stack_region{};
    stack_region.start_address = 0x7FFF'0000'1000ULL;
    stack_region.end_address = 0x7FFF'0000'4000ULL;
    stack_region.kind = peelf::MemoryRegionKind::Stack;
    stack_region.protection.readable = true;
    stack_region.protection.writable = true;

    const std::array<peelf::MemoryRegion, 1> regions = {stack_region};
    const peelf::ThreadStackSnapshot snap = peelf::unwind_and_inspect_stack(
        session, ctx, regions, {}, nullptr, {}, 4u, 516u);

    ASSERT_EQ(snap.slots.size(), 514u);
    // Slot 0 (0x7FFF00001FF8) has low 4 bytes readable (mask 0x0F) and upper 4 bytes unreadable.
    EXPECT_EQ(snap.slots[0].valid_byte_mask, 0x0Fu);
    EXPECT_FALSE(snap.slots[0].all_bytes_valid());
    EXPECT_TRUE(snap.slots[0].any_bytes_valid());
    EXPECT_EQ(peelf::format_stack_slot_value(snap.slots[0], layout), "0x????????DEADBEEF");

    // Slot 1 (0x7FFF00002000) is on the unmapped hole page (mask 0x00):
    // must NOT look like valid 0x0000000000000000!
    EXPECT_EQ(snap.slots[1].valid_byte_mask, 0x00u);
    EXPECT_FALSE(snap.slots[1].any_bytes_valid());
    EXPECT_FALSE(snap.slots[1].points_to_executable);
    EXPECT_FALSE(snap.slots[1].points_to_stack);
    EXPECT_EQ(peelf::format_stack_slot_value(snap.slots[1], layout), "0x????????????????");

    // Slot 513 (0x7FFF00003000) on the next readable page has all 8 bytes valid (mask 0xFF).
    EXPECT_EQ(snap.slots[513].valid_byte_mask, 0xFFu);
    EXPECT_TRUE(snap.slots[513].all_bytes_valid());
    EXPECT_EQ(peelf::format_stack_slot_value(snap.slots[513], layout), "0x8877665544332211");
}
