#include "graph/call_graph_galaxy.hpp"

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "graph/call_graph.hpp"
#include "symbols/symbol_index.hpp"
#include "vulkan/shaders/call_galaxy_spirv.hpp"
#include "vulkan/spirv_validation.hpp"
#include "vulkan/viewport_camera_2d.hpp"

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/byte_viz.hpp>
#include <peelf/security_audit.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

static_assert(sizeof(viewer::GalaxyEdgeGpuInstance) == 32u);
static_assert(alignof(viewer::GalaxyEdgeGpuInstance) == 16u);
static_assert(std::is_trivially_copyable_v<viewer::GalaxyEdgeGpuInstance>);

static_assert(sizeof(viewer::GalaxyNodeGpuInstance) == 32u);
static_assert(alignof(viewer::GalaxyNodeGpuInstance) == 16u);
static_assert(std::is_trivially_copyable_v<viewer::GalaxyNodeGpuInstance>);

static_assert(sizeof(viewer::shaders::CallGalaxyPushConstants) <= 128u);
static_assert(std::is_trivially_copyable_v<viewer::shaders::CallGalaxyPushConstants>);

class SyntheticGalaxyBinaryImage final : public peelf::IBinaryImage {
public:
    SyntheticGalaxyBinaryImage() {
        peelf::Section text_sec{};
        text_sec.name = ".text";
        text_sec.virtual_address = 0x401000ULL;
        text_sec.virtual_size = 0x1000ULL;
        text_sec.file_offset = 0x1000ULL;
        text_sec.file_size = 0x1000ULL;
        text_sec.readable = true;
        text_sec.executable = true;
        sections_.push_back(std::move(text_sec));

        peelf::Section plt_sec{};
        plt_sec.name = ".plt";
        plt_sec.virtual_address = 0x402000ULL;
        plt_sec.virtual_size = 0x200ULL;
        plt_sec.file_offset = 0x2000ULL;
        plt_sec.file_size = 0x200ULL;
        plt_sec.readable = true;
        plt_sec.executable = true;
        sections_.push_back(std::move(plt_sec));

        auto add_fn_sym = [&](std::string name, std::uint64_t va, std::uint64_t sz) {
            peelf::Symbol sym{};
            sym.name = std::move(name);
            sym.virtual_address = va;
            sym.size = sz;
            sym.type = 2u; // STT_FUNC
            symbols_.push_back(std::move(sym));
        };

        // Entry function -> mid_worker -> leaf_helper (plus tail-jump leaf_helper -> tail_sink)
        // Plus an isolated unreachable internal function `dead_code_fn`, and an external import.
        add_fn_sym("_start", 0x401000ULL, 0x40ULL);
        add_fn_sym("_ZN4demo10mid_workerEi", 0x401100ULL, 0x60ULL);
        add_fn_sym("leaf_helper", 0x401200ULL, 0x40ULL);
        add_fn_sym("tail_sink", 0x401300ULL, 0x30ULL);
        add_fn_sym("dead_code_fn", 0x401500ULL, 0x50ULL);

        peelf::ExportEntry exp{};
        exp.name = "_ZN4demo10mid_workerEi";
        exp.ordinal = 1u;
        exp.virtual_address = 0x401100ULL;
        exports_.push_back(std::move(exp));

        peelf::ImportEntry imp{};
        imp.library = "libc.so.6";
        imp.name = "puts";
        imp.address = 0x402010ULL;
        imports_.push_back(std::move(imp));
    }

    [[nodiscard]] peelf::Format format() const noexcept override { return peelf::Format::ELF; }
    [[nodiscard]] peelf::ImageKind kind() const noexcept override {
        return peelf::ImageKind::Executable;
    }
    [[nodiscard]] peelf::Architecture architecture() const noexcept override {
        return peelf::Architecture::X86_64;
    }
    [[nodiscard]] peelf::Endianness endianness() const noexcept override {
        return peelf::Endianness::Little;
    }
    [[nodiscard]] bool is_64bit() const noexcept override { return true; }
    [[nodiscard]] std::uint64_t image_base() const noexcept override { return 0x400000ULL; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return 0x401000ULL; }
    [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override {
        return segments_;
    }
    [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override {
        return imports_;
    }
    [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override {
        return exports_;
    }

    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override {
        for (const peelf::Section& sec : sections_) {
            if (file_offset >= sec.file_offset && file_offset < sec.file_offset + sec.file_size) {
                return sec.virtual_address + (file_offset - sec.file_offset);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t va) const noexcept override {
        for (const peelf::Section& sec : sections_) {
            if (va >= sec.virtual_address && va < sec.virtual_address + sec.virtual_size) {
                return sec.file_offset + (va - sec.virtual_address);
            }
        }
        return std::nullopt;
    }

private:
    std::vector<peelf::Section> sections_{};
    std::vector<peelf::Segment> segments_{};
    std::vector<peelf::Symbol> symbols_{};
    std::vector<peelf::ImportEntry> imports_{};
    std::vector<peelf::ExportEntry> exports_{};
};

[[nodiscard]] const viewer::CallGalaxyNode* find_galaxy_node_by_va(
    const viewer::CallGalaxyGraph& graph,
    std::uint64_t va) noexcept {
    const auto idx = graph.find_node_at_va(va);
    if (!idx.has_value() || *idx >= graph.nodes.size()) {
        return nullptr;
    }
    return &graph.nodes[*idx];
}

[[nodiscard]] bool has_galaxy_edge(
    const viewer::CallGalaxyGraph& graph,
    std::uint32_t src,
    std::uint32_t dst,
    viewer::GalaxyEdgeKind kind) noexcept {
    return std::ranges::any_of(graph.edges, [&](const viewer::CallGalaxyEdge& edge) noexcept {
        return edge.source_node == src && edge.target_node == dst && edge.kind == kind;
    });
}

[[nodiscard]] std::uint32_t read_rgba8_pixel(
    std::span<const std::uint8_t> rgba,
    std::uint32_t width,
    std::uint32_t x,
    std::uint32_t y) noexcept {
    const std::size_t off = (static_cast<std::size_t>(y) * width + x) * 4u;
    if (off + 4u > rgba.size()) {
        return 0u;
    }
    return viewer::pack_galaxy_rgba8(
        rgba[off + 0u],
        rgba[off + 1u],
        rgba[off + 2u],
        rgba[off + 3u]);
}

} // namespace

TEST(CallGraphGalaxy, BuildsWholeBinaryGalaxyWithReachabilitySecurityDiffAndPathQueries) {
    const SyntheticGalaxyBinaryImage image{};
    viewer::SymbolIndex symbols = viewer::SymbolIndex::build(image);
    const viewer::FunctionIndex functions = viewer::FunctionIndex::discover(image, symbols);

    auto make_ref = [](std::uint64_t src, std::uint64_t dst, viewer::ReferenceKind kind) {
        viewer::Reference r{};
        r.source = src;
        r.target = dst;
        r.kind = kind;
        return r;
    };

    viewer::ReferenceIndex references{};
    references.reset_for_progressive_scan(0x1200u, false);
    viewer::ReferenceScanChunk chunk{};
    chunk.bytes_scanned = 0x1200u;
    chunk.finished = true;
    chunk.references = {
        // _start -> mid_worker (two call sites coalesced into weight=2)
        make_ref(0x401008ULL, 0x401100ULL, viewer::ReferenceKind::Call),
        make_ref(0x401020ULL, 0x401100ULL, viewer::ReferenceKind::Call),
        // Intra-function branch inside mid_worker must NOT create a spurious cross-function edge.
        make_ref(0x401110ULL, 0x401130ULL, viewer::ReferenceKind::Branch),
        // Direct call mid_worker -> leaf_helper
        make_ref(0x401124ULL, 0x401200ULL, viewer::ReferenceKind::Call),
        // Tail-jump leaf_helper -> tail_sink (cross-function Branch becomes TailJump)
        make_ref(0x401238ULL, 0x401300ULL, viewer::ReferenceKind::Branch),
        // External import call tail_sink -> puts@IAT
        make_ref(0x401310ULL, 0x402010ULL, viewer::ReferenceKind::Call),
        // Self-recursive call inside dead_code_fn
        make_ref(0x401520ULL, 0x401500ULL, viewer::ReferenceKind::Call),
    };
    references.append_chunk(std::move(chunk));

    peelf::SecurityAuditReport sec_report{};
    {
        peelf::SecurityFinding f1{};
        f1.rule_id = "SEC-101";
        f1.rule_name = "Unsafe format sink";
        f1.severity = peelf::SecuritySeverity::Warning;
        f1.summary = "Potential format issue";
        f1.virtual_address = 0x401210ULL; // inside leaf_helper
        sec_report.findings.push_back(std::move(f1));

        peelf::SecurityFinding f2{};
        f2.rule_id = "SEC-202";
        f2.rule_name = "Stack cookie missing";
        f2.severity = peelf::SecuritySeverity::Error;
        f2.summary = "Critical guard missing";
        f2.file_offset = 0x1218ULL; // maps to 0x401218 inside leaf_helper -> promotes to Error
        sec_report.findings.push_back(std::move(f2));
    }

    peelf::BinaryDiffReport diff_report{};
    {
        peelf::FunctionDiffEntry fd{};
        fd.display_name = "mid_worker";
        fd.raw_lhs_name = "_ZN4demo10mid_workerEi";
        fd.lhs_va = 0x401100ULL;
        fd.rhs_va = 0x401100ULL;
        fd.status = peelf::FunctionMatchKind::Modified;
        diff_report.functions.push_back(std::move(fd));
    }
    peelf::ByteVizDiffRange dr0{};
    dr0.offset_or_va = 0x401510ULL; // inside dead_code_fn
    dr0.size_bytes = 8u;
    dr0.kind = peelf::ByteVizDiffKind::Added;
    dr0.is_virtual_address = true;
    const std::array<peelf::ByteVizDiffRange, 1> diff_ranges{{dr0}};

    viewer::CallGalaxyBuildOptions opts{};
    opts.include_tail_jumps = true;
    opts.security_report = &sec_report;
    opts.diff_report = &diff_report;
    opts.diff_ranges = diff_ranges;

    const viewer::CallGalaxyGraph galaxy =
        viewer::build_whole_binary_call_galaxy(image, symbols, functions, references, opts);

    ASSERT_EQ(galaxy.nodes.size(), 6u);

    const auto* start_node = find_galaxy_node_by_va(galaxy, 0x401000ULL);
    const auto* mid_node = find_galaxy_node_by_va(galaxy, 0x401100ULL);
    const auto* leaf_node = find_galaxy_node_by_va(galaxy, 0x401200ULL);
    const auto* tail_node = find_galaxy_node_by_va(galaxy, 0x401300ULL);
    const auto* dead_node = find_galaxy_node_by_va(galaxy, 0x401500ULL);
    const auto* imp_node = find_galaxy_node_by_va(galaxy, 0x402010ULL);

    ASSERT_NE(start_node, nullptr);
    ASSERT_NE(mid_node, nullptr);
    ASSERT_NE(leaf_node, nullptr);
    ASSERT_NE(tail_node, nullptr);
    ASSERT_NE(dead_node, nullptr);
    ASSERT_NE(imp_node, nullptr);

    EXPECT_EQ(start_node->reachability, viewer::GalaxyReachability::EntryPoint);
    EXPECT_EQ(mid_node->reachability, viewer::GalaxyReachability::ReachableFromEntry);
    EXPECT_EQ(leaf_node->reachability, viewer::GalaxyReachability::ReachableFromEntry);
    EXPECT_EQ(tail_node->reachability, viewer::GalaxyReachability::ReachableFromEntry);
    EXPECT_EQ(imp_node->reachability, viewer::GalaxyReachability::ExternalImport);
    EXPECT_EQ(dead_node->reachability, viewer::GalaxyReachability::UnreachableInternal);

    // Demangled C++ display name on mid_worker.
    EXPECT_NE(mid_node->display_name.find("demo::mid_worker"), std::string::npos);

    // Security & diff overlays.
    EXPECT_EQ(leaf_node->security_finding_count, 2u);
    EXPECT_EQ(leaf_node->security_severity, viewer::GalaxySecuritySeverity::Error);
    EXPECT_NE(leaf_node->top_security_finding.find("SEC-202"), std::string::npos);
    EXPECT_EQ(mid_node->diff_status, viewer::GalaxyDiffStatus::Modified);
    EXPECT_EQ(dead_node->diff_status, viewer::GalaxyDiffStatus::Added);

    // Edge kinds & coalesced weights.
    EXPECT_TRUE(has_galaxy_edge(
        galaxy, start_node->node_index, mid_node->node_index, viewer::GalaxyEdgeKind::Call));
    EXPECT_FALSE(has_galaxy_edge(
        galaxy, mid_node->node_index, mid_node->node_index, viewer::GalaxyEdgeKind::TailJump));
    EXPECT_TRUE(has_galaxy_edge(
        galaxy, mid_node->node_index, leaf_node->node_index, viewer::GalaxyEdgeKind::Call));
    EXPECT_TRUE(has_galaxy_edge(
        galaxy, leaf_node->node_index, tail_node->node_index, viewer::GalaxyEdgeKind::TailJump));
    EXPECT_TRUE(has_galaxy_edge(
        galaxy, tail_node->node_index, imp_node->node_index, viewer::GalaxyEdgeKind::Call));
    EXPECT_TRUE(has_galaxy_edge(
        galaxy, dead_node->node_index, dead_node->node_index, viewer::GalaxyEdgeKind::Call));

    for (const viewer::CallGalaxyEdge& e : galaxy.edges) {
        if (e.source_node == start_node->node_index && e.target_node == mid_node->node_index) {
            EXPECT_EQ(e.weight, 2u);
        }
    }

    // Connected components: main chain (5 nodes) + isolated dead_code_fn (1 node) = 2 components.
    EXPECT_EQ(galaxy.component_count, 2u);
    EXPECT_NE(start_node->component_id, dead_node->component_id);

    // Shortest directed call path: _start -> mid_worker -> leaf_helper -> tail_sink -> puts.
    const viewer::GalaxyCallPath path =
        viewer::find_shortest_call_path(galaxy, start_node->node_index, imp_node->node_index);
    ASSERT_FALSE(path.empty());
    const std::vector<std::uint32_t> expected_path{
        start_node->node_index,
        mid_node->node_index,
        leaf_node->node_index,
        tail_node->node_index,
        imp_node->node_index,
    };
    EXPECT_EQ(path.nodes, expected_path);
    EXPECT_EQ(path.edges.size(), 4u);

    // Unreachable directed path returns empty GalaxyCallPath.
    EXPECT_TRUE(
        viewer::find_shortest_call_path(galaxy, start_node->node_index, dead_node->node_index)
            .empty());

    // 1-hop ego network around mid_worker includes _start (caller), mid_worker (focus), and leaf_helper (callee).
    const viewer::GalaxyEgoMask ego =
        viewer::compute_ego_network_mask(galaxy, mid_node->node_index);
    ASSERT_EQ(ego.node_roles.size(), galaxy.nodes.size());
    EXPECT_EQ(ego.node_roles[start_node->node_index], viewer::GalaxyEgoRole::DirectCaller);
    EXPECT_EQ(ego.node_roles[mid_node->node_index], viewer::GalaxyEgoRole::Focus);
    EXPECT_EQ(ego.node_roles[leaf_node->node_index], viewer::GalaxyEgoRole::DirectCallee);
    EXPECT_EQ(ego.node_roles[tail_node->node_index], viewer::GalaxyEgoRole::None);
    EXPECT_EQ(ego.node_roles[dead_node->node_index], viewer::GalaxyEgoRole::None);
}

TEST(CallGraphGalaxy, BuildsRealFixtureBinaryAndConvertsCfgCallGraph) {
    const std::filesystem::path fixture_path{PEELF_CALLGRAPH_FIXTURE_EXE};
    std::ifstream file(fixture_path, std::ios::binary);
    ASSERT_TRUE(file.good()) << fixture_path.string();
    const std::vector<std::uint8_t> bytes{
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()};

    auto parsed = peelf::parse_image(bytes);
    ASSERT_TRUE(parsed.has_value());
    const peelf::IBinaryImage& img = **parsed;

    viewer::SymbolIndex symbols = viewer::SymbolIndex::build(img);
    const viewer::FunctionIndex functions = viewer::FunctionIndex::discover(img, symbols, bytes);
    const viewer::ReferenceIndex references =
        viewer::ReferenceIndex::build(img, bytes, false, viewer::ReferenceIndex::kDefaultByteBudget, &symbols);

    const viewer::CallGalaxyGraph whole_galaxy =
        viewer::build_whole_binary_call_galaxy(img, symbols, functions, references);
    EXPECT_GE(whole_galaxy.nodes.size(), 4u);
    EXPECT_GE(whole_galaxy.edges.size(), 2u);
    EXPECT_FALSE(whole_galaxy.primary_entry_nodes.empty());

    // Also verify `build_call_galaxy_from_call_graph` on a synthetic multi-block CFG.
    auto make_cfg_node = [](std::string id, std::string label, std::uint64_t va, std::uint64_t sz) {
        viewer::CallGraphNode n{};
        n.id = std::move(id);
        n.label = std::move(label);
        n.kind = viewer::CallGraphNodeKind::BasicBlock;
        n.bytes.start.virtual_address = va;
        n.bytes.size = sz;
        return n;
    };
    auto make_cfg_edge = [](std::string from, std::string to, viewer::CallGraphEdgeKind kind) {
        viewer::CallGraphEdge e{};
        e.from_node_id = std::move(from);
        e.to_node_id = std::move(to);
        e.kind = kind;
        return e;
    };

    viewer::CallGraph cfg{};
    cfg.label = "demo_cfg";
    cfg.nodes = {
        make_cfg_node("bb0", "entry_bb", 0x500000ULL, 16u),
        make_cfg_node("bb1", "then_bb", 0x500010ULL, 12u),
        make_cfg_node("bb2", "else_bb", 0x50001CULL, 12u),
        make_cfg_node("bb3", "merge_bb", 0x500028ULL, 8u),
    };
    cfg.edges = {
        make_cfg_edge("bb0", "bb1", viewer::CallGraphEdgeKind::ConditionalBranch),
        make_cfg_edge("bb0", "bb2", viewer::CallGraphEdgeKind::ConditionalBranch),
        make_cfg_edge("bb1", "bb3", viewer::CallGraphEdgeKind::UnconditionalBranch),
        make_cfg_edge("bb2", "bb3", viewer::CallGraphEdgeKind::Fallthrough),
    };

    const viewer::CallGalaxyGraph cfg_galaxy = viewer::build_call_galaxy_from_call_graph(cfg);
    ASSERT_EQ(cfg_galaxy.nodes.size(), 4u);
    ASSERT_EQ(cfg_galaxy.edges.size(), 4u);
    EXPECT_EQ(cfg_galaxy.nodes[0].reachability, viewer::GalaxyReachability::EntryPoint);
    EXPECT_EQ(cfg_galaxy.nodes[3].reachability, viewer::GalaxyReachability::ReachableFromEntry);
    EXPECT_EQ(cfg_galaxy.nodes[3].in_degree, 2u);
}

TEST(CallGraphGalaxy, BarnesHutSolverIsDeterministicHandlesCoincidentNodesPinningAndCancellation) {
    viewer::CallGalaxyGraph graph{};
    constexpr std::uint32_t kNodeCount = 64u;
    graph.nodes.resize(kNodeCount);
    for (std::uint32_t i = 0u; i < kNodeCount; ++i) {
        graph.nodes[i].node_index = i;
        graph.nodes[i].virtual_address = 0x400000ULL + static_cast<std::uint64_t>(i) * 0x20ULL;
        graph.nodes[i].display_name = "fn_" + std::to_string(i);
        graph.nodes[i].raw_name = graph.nodes[i].display_name;
        if (i > 0u) {
            graph.edges.push_back(viewer::CallGalaxyEdge{
                .source_node = (i - 1u) / 2u,
                .target_node = i,
                .kind = viewer::GalaxyEdgeKind::Call,
                .weight = 1u,
            });
        }
    }
    graph.rebuild_adjacency_and_metrics();

    // 1. Bit-exact determinism across two independent solver instances.
    viewer::BarnesHutGalaxyLayout solver_a{};
    viewer::BarnesHutGalaxyLayout solver_b{};
    solver_a.reset(graph);
    solver_b.reset(graph);

    const viewer::BarnesHutStepResult res_a = solver_a.step(15u);
    const viewer::BarnesHutStepResult res_b = solver_b.step(15u);
    EXPECT_EQ(res_a.iterations_executed, 15u);
    EXPECT_EQ(res_b.iterations_executed, 15u);
    ASSERT_EQ(solver_a.positions_x().size(), kNodeCount);
    EXPECT_TRUE(std::ranges::equal(solver_a.positions_x(), solver_b.positions_x()));
    EXPECT_TRUE(std::ranges::equal(solver_a.positions_y(), solver_b.positions_y()));

    // 2. Coincident-node quadtree depth safety: collapse all 64 nodes onto exact (0, 0).
    for (std::uint32_t i = 0u; i < kNodeCount; ++i) {
        solver_a.set_node_position(i, 0.0f, 0.0f, false);
    }
    solver_a.reheat(80.0f);
    const viewer::BarnesHutStepResult coincident_res = solver_a.step(10u);
    EXPECT_EQ(coincident_res.iterations_executed, 10u);
    EXPECT_FALSE(coincident_res.cancelled);

    bool any_separated = false;
    for (std::uint32_t i = 0u; i < kNodeCount; ++i) {
        const float x = solver_a.positions_x()[i];
        const float y = solver_a.positions_y()[i];
        EXPECT_TRUE(std::isfinite(x));
        EXPECT_TRUE(std::isfinite(y));
        if (std::hypot(x, y) > 1.0e-2f) {
            any_separated = true;
        }
    }
    EXPECT_TRUE(any_separated);

    // 3. Pinned-node invariance.
    solver_a.set_node_position(5u, 321.5f, -654.25f, true);
    EXPECT_TRUE(solver_a.is_node_pinned(5u));
    (void)solver_a.step(12u);
    EXPECT_FLOAT_EQ(solver_a.positions_x()[5u], 321.5f);
    EXPECT_FLOAT_EQ(solver_a.positions_y()[5u], -654.25f);
    solver_a.unpin_all();
    EXPECT_FALSE(solver_a.is_node_pinned(5u));

    // 4. Cooperative std::stop_token cancellation.
    std::stop_source stop_src{};
    stop_src.request_stop();
    const viewer::BarnesHutStepResult cancelled_res = solver_a.step(20u, stop_src.get_token());
    EXPECT_TRUE(cancelled_res.cancelled);
    EXPECT_EQ(cancelled_res.iterations_executed, 0u);
}

TEST(CallGraphGalaxy, ScalesToTenThousandNodesAndThirtyThousandEdges) {
    constexpr std::uint32_t kNumNodes = 10'000u;
    constexpr std::uint32_t kEdgesPerNode = 3u;

    viewer::CallGalaxyGraph large_graph{};
    large_graph.nodes.resize(kNumNodes);
    large_graph.edges.reserve(static_cast<std::size_t>(kNumNodes) * kEdgesPerNode);

    for (std::uint32_t i = 0u; i < kNumNodes; ++i) {
        viewer::CallGalaxyNode& n = large_graph.nodes[i];
        n.node_index = i;
        n.virtual_address = 0x1000'0000ULL + static_cast<std::uint64_t>(i) * 0x40ULL;
        n.section_cluster_id = i % 5u;
        n.reachability = (i == 0u) ? viewer::GalaxyReachability::EntryPoint
                                   : viewer::GalaxyReachability::ReachableFromEntry;

        // Deterministic sparse call topology: tree parent + modular cross-links (30,000 edges).
        const std::uint32_t t1 = (i + 1u) % kNumNodes;
        const std::uint32_t t2 = (i * 7u + 13u) % kNumNodes;
        const std::uint32_t t3 = (i / 4u);
        large_graph.edges.push_back(viewer::CallGalaxyEdge{
            .source_node = i,
            .target_node = t1,
            .kind = viewer::GalaxyEdgeKind::Call,
            .weight = 1u,
        });
        large_graph.edges.push_back(viewer::CallGalaxyEdge{
            .source_node = i,
            .target_node = t2,
            .kind = viewer::GalaxyEdgeKind::Call,
            .weight = 1u,
        });
        large_graph.edges.push_back(viewer::CallGalaxyEdge{
            .source_node = i,
            .target_node = t3,
            .kind = viewer::GalaxyEdgeKind::TailJump,
            .weight = 1u,
        });
    }
    large_graph.primary_entry_nodes.push_back(0u);
    large_graph.rebuild_adjacency_and_metrics();
    ASSERT_EQ(large_graph.edges.size(), 30'000u);

    viewer::BarnesHutGalaxyLayout layout{};
    layout.reset(large_graph);
    const viewer::BarnesHutStepResult step_res = layout.step(2u);
    EXPECT_EQ(step_res.iterations_executed, 2u);
    EXPECT_FALSE(step_res.cancelled);

    const viewer::GalaxyWorldBounds bounds = layout.compute_bounds(0.0f);
    EXPECT_TRUE(std::isfinite(bounds.min_x));
    EXPECT_TRUE(std::isfinite(bounds.max_x));
    EXPECT_TRUE(std::isfinite(bounds.min_y));
    EXPECT_TRUE(std::isfinite(bounds.max_y));
    EXPECT_GT(bounds.width(), 10.0f);
    EXPECT_GT(bounds.height(), 10.0f);
}

TEST(CallGraphGalaxy, ValidatesShadersFrustumCullingHitTestingAndCpuRasterizer) {
    // 1. Validate all 4 precompiled Vulkan 1.0 SPIR-V shaders.
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kGalaxyEdgeVertSpirv));
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kGalaxyEdgeFragSpirv));
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kGalaxyNodeVertSpirv));
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kGalaxyNodeFragSpirv));

    // 2. Build a 3-node graph: two visible nodes connected by an edge, plus one far off-screen node.
    viewer::CallGalaxyGraph graph{};
    graph.nodes.resize(3u);
    for (std::uint32_t i = 0u; i < 3u; ++i) {
        graph.nodes[i].node_index = i;
        graph.nodes[i].virtual_address = 0x401000ULL + static_cast<std::uint64_t>(i) * 0x100ULL;
        graph.nodes[i].display_name = "node_" + std::to_string(i);
        graph.nodes[i].raw_name = graph.nodes[i].display_name;
        graph.nodes[i].reachability = (i == 0u) ? viewer::GalaxyReachability::EntryPoint
                                                : viewer::GalaxyReachability::ReachableFromEntry;
    }
    graph.edges.push_back(viewer::CallGalaxyEdge{
        .source_node = 0u,
        .target_node = 1u,
        .kind = viewer::GalaxyEdgeKind::Call,
        .weight = 2u,
    });
    graph.edges.push_back(viewer::CallGalaxyEdge{
        .source_node = 1u,
        .target_node = 2u,
        .kind = viewer::GalaxyEdgeKind::Call,
        .weight = 1u,
    });
    graph.rebuild_adjacency_and_metrics();

    const std::array<float, 3> world_x{{-40.0f, 40.0f, 50'000.0f}};
    const std::array<float, 3> world_y{{0.0f, 0.0f, 50'000.0f}};
    const std::array<std::uint8_t, 3> pinned{{1u, 0u, 0u}};

    viewer::ViewportCamera2D camera{};
    camera.fit_bounds(-100.0, -100.0, 100.0, 100.0, 256.0, 256.0, true);

    const viewer::GalaxyCallPath call_path = viewer::find_shortest_call_path(graph, 0u, 1u);
    const viewer::GalaxyEgoMask ego_mask = viewer::compute_ego_network_mask(graph, 0u);

    viewer::GalaxyRenderBuildOptions render_opts{};
    render_opts.viewport_width_px = 256.0f;
    render_opts.viewport_height_px = 256.0f;
    render_opts.color_mode = viewer::GalaxyColorMode::EntryReachability;
    render_opts.selected_node = 0u;
    render_opts.hovered_node = 1u;
    render_opts.pinned_mask = pinned;
    render_opts.ego_mask = &ego_mask;
    render_opts.highlighted_path = &call_path;

    const viewer::GalaxyRenderBatch batch =
        viewer::build_galaxy_render_batch(graph, world_x, world_y, camera, render_opts);

    // Off-screen node 2 is frustum-culled; nodes 0 and 1 are emitted.
    EXPECT_EQ(batch.culled_nodes, 1u);
    ASSERT_EQ(batch.nodes.size(), 2u);
    ASSERT_GE(batch.edges.size(), 1u);

    // Cursor hit-test at node 0's screen projection finds node 0, and misses empty corner (4, 4).
    const viewer::Vec2d node0_px = camera.world_to_screen(
        static_cast<double>(world_x[0]),
        static_cast<double>(world_y[0]),
        256.0,
        256.0);
    const auto hit0 = viewer::hit_test_galaxy_node(
        graph,
        world_x,
        world_y,
        camera,
        256.0f,
        256.0f,
        static_cast<float>(node0_px.x),
        static_cast<float>(node0_px.y),
        3.0f);
    ASSERT_TRUE(hit0.has_value());
    EXPECT_EQ(*hit0, 0u);

    const auto miss = viewer::hit_test_galaxy_node(
        graph,
        world_x,
        world_y,
        camera,
        256.0f,
        256.0f,
        4.0f,
        4.0f,
        2.0f);
    EXPECT_FALSE(miss.has_value());

    // 3. Deterministic CPU RGBA8 reference rasterizer produces identical non-blank output.
    const viewer::CallGalaxyRasterConfig rcfg{
        .width = 256u,
        .height = 256u,
        .clear_rgba8 = viewer::pack_galaxy_rgba8(14u, 16u, 22u, 255u),
        .node_ring_width_px = 1.5f,
    };
    const std::vector<std::uint8_t> img_a =
        viewer::rasterize_call_galaxy_rgba8(batch.edges, batch.nodes, rcfg);
    std::vector<std::uint8_t> img_b{};
    viewer::rasterize_call_galaxy_rgba8_into(batch.edges, batch.nodes, rcfg, img_b);

    ASSERT_EQ(img_a.size(), 256u * 256u * 4u);
    EXPECT_EQ(img_a, img_b);

    // Node 0 center, Node 1 center, and the midpoint between them (edge) must differ from clear_rgba8!
    const viewer::Vec2d node1_px = camera.world_to_screen(
        static_cast<double>(world_x[1]),
        static_cast<double>(world_y[1]),
        256.0,
        256.0);
    const auto n0_x = static_cast<std::uint32_t>(std::lround(node0_px.x));
    const auto n0_y = static_cast<std::uint32_t>(std::lround(node0_px.y));
    const auto n1_x = static_cast<std::uint32_t>(std::lround(node1_px.x));
    const auto n1_y = static_cast<std::uint32_t>(std::lround(node1_px.y));
    const std::uint32_t mid_x = (n0_x + n1_x) / 2u;
    const std::uint32_t mid_y = (n0_y + n1_y) / 2u;

    EXPECT_NE(read_rgba8_pixel(img_a, 256u, n0_x, n0_y), rcfg.clear_rgba8);
    EXPECT_NE(read_rgba8_pixel(img_a, 256u, n1_x, n1_y), rcfg.clear_rgba8);
    EXPECT_NE(read_rgba8_pixel(img_a, 256u, mid_x, mid_y), rcfg.clear_rgba8);
    EXPECT_EQ(read_rgba8_pixel(img_a, 256u, 2u, 2u), rcfg.clear_rgba8);
}
