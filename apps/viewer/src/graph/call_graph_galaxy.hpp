#pragma once

// WU-33: Headless Whole-Binary Call-Graph & CFG Force-Layout Galaxy Engine.
//
// Pure C++23, zero Vulkan/ImGui dependencies. Provides:
//   1. Whole-binary call-graph galaxy builder (`build_whole_binary_call_galaxy`)
//      scaling to 10,000+ functions and 50,000+ edges with entry-reachability BFS,
//      security-audit severity attribution, binary-diff overlay attribution, and
//      connected-component / section cluster IDs.
//   2. `CallGraph` -> `CallGalaxyGraph` converter (`build_call_galaxy_from_call_graph`)
//      for GPU rendering of basic-block CFGs and symbol fanout graphs without Graphviz `dot`.
//   3. Deterministic $O(N \log N + E)$ Barnes-Hut quadtree force-directed layout solver
//      (`BarnesHutGalaxyLayout`) with bounded quadtree depth, golden-angle spiral seeding,
//      pinned-node invariance, cooperative `std::stop_token` cancellation, and NaN sanitization.
//   4. 1-hop ego-network masks, shortest directed call-path BFS, cursor hit-testing,
//      `ViewportCamera2D` frustum culling + zoom-adaptive edge decimation, GPU instance
//      structs (`GalaxyEdgeGpuInstance`, `GalaxyNodeGpuInstance`), and deterministic
//      CPU RGBA8 reference rasterization (`rasterize_call_galaxy_rgba8`).

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "graph/call_graph.hpp"
#include "symbols/symbol_index.hpp"
#include "vulkan/viewport_camera_2d.hpp"

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/byte_viz.hpp>
#include <peelf/security_audit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace viewer {

inline constexpr std::uint32_t kInvalidGalaxyNode = 0xFFFF'FFFFu;

enum class GalaxyReachability : std::uint8_t {
    EntryPoint = 0,
    ReachableFromEntry = 1,
    UnreachableInternal = 2,
    ExternalImport = 3,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxyReachability r) noexcept {
    switch (r) {
        case GalaxyReachability::EntryPoint:          return "Entry Point";
        case GalaxyReachability::ReachableFromEntry:  return "Reachable from Entry";
        case GalaxyReachability::UnreachableInternal: return "Unreachable Internal";
        case GalaxyReachability::ExternalImport:      return "External / Import";
    }
    return "Unreachable Internal";
}

enum class GalaxySecuritySeverity : std::uint8_t {
    None = 0,
    Pass = 1,
    Note = 2,
    Warning = 3,
    Error = 4,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxySecuritySeverity s) noexcept {
    switch (s) {
        case GalaxySecuritySeverity::None:    return "None";
        case GalaxySecuritySeverity::Pass:    return "Pass";
        case GalaxySecuritySeverity::Note:    return "Note";
        case GalaxySecuritySeverity::Warning: return "Warning";
        case GalaxySecuritySeverity::Error:   return "Error";
    }
    return "None";
}

enum class GalaxyDiffStatus : std::uint8_t {
    Unchanged = 0,
    Relocated = 1,
    Modified = 2,
    Added = 3,
    Removed = 4,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxyDiffStatus d) noexcept {
    switch (d) {
        case GalaxyDiffStatus::Unchanged: return "Unchanged";
        case GalaxyDiffStatus::Relocated: return "Relocated";
        case GalaxyDiffStatus::Modified:  return "Modified";
        case GalaxyDiffStatus::Added:     return "Added";
        case GalaxyDiffStatus::Removed:   return "Removed";
    }
    return "Unchanged";
}

enum class GalaxyNodeKind : std::uint8_t {
    InternalFunction = 0,
    ExternalImport = 1,
    BasicBlock = 2,
    ExternalTarget = 3,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxyNodeKind k) noexcept {
    switch (k) {
        case GalaxyNodeKind::InternalFunction: return "Function";
        case GalaxyNodeKind::ExternalImport:   return "Import";
        case GalaxyNodeKind::BasicBlock:       return "Basic Block";
        case GalaxyNodeKind::ExternalTarget:   return "External Target";
    }
    return "Function";
}

enum class GalaxyEdgeKind : std::uint8_t {
    Call = 0,
    TailJump = 1,
    ConditionalBranch = 2,
    UnconditionalBranch = 3,
    Fallthrough = 4,
    Return = 5,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxyEdgeKind k) noexcept {
    switch (k) {
        case GalaxyEdgeKind::Call:                return "Call";
        case GalaxyEdgeKind::TailJump:            return "Tail Jump";
        case GalaxyEdgeKind::ConditionalBranch:   return "Cond Branch";
        case GalaxyEdgeKind::UnconditionalBranch: return "Jump";
        case GalaxyEdgeKind::Fallthrough:         return "Fallthrough";
        case GalaxyEdgeKind::Return:              return "Return";
    }
    return "Call";
}

enum class GalaxyColorMode : std::uint8_t {
    OriginAndSection = 0,
    EntryReachability = 1,
    SecurityFindings = 2,
    BinaryDiff = 3,
    CallDegreeHeat = 4,
};

[[nodiscard]] constexpr std::string_view to_string(GalaxyColorMode m) noexcept {
    switch (m) {
        case GalaxyColorMode::OriginAndSection:  return "Origin / Section";
        case GalaxyColorMode::EntryReachability: return "Entry Reachability";
        case GalaxyColorMode::SecurityFindings:  return "Security Findings";
        case GalaxyColorMode::BinaryDiff:        return "Binary Diff";
        case GalaxyColorMode::CallDegreeHeat:    return "Call Degree Heat";
    }
    return "Origin / Section";
}

[[nodiscard]] constexpr std::uint32_t pack_galaxy_rgba8(
    std::uint8_t r,
    std::uint8_t g,
    std::uint8_t b,
    std::uint8_t a = 255u) noexcept {
    return static_cast<std::uint32_t>(r) |
           (static_cast<std::uint32_t>(g) << 8u) |
           (static_cast<std::uint32_t>(b) << 16u) |
           (static_cast<std::uint32_t>(a) << 24u);
}

struct CallGalaxyNode {
    std::uint32_t node_index{0u};
    std::uint64_t virtual_address{0u};
    std::uint64_t size_bytes{0u};
    std::string display_name{};
    std::string raw_name{};
    std::string module_or_section{};
    GalaxyNodeKind kind{GalaxyNodeKind::InternalFunction};
    FunctionOrigin origin{FunctionOrigin::SymbolTable};
    GalaxyReachability reachability{GalaxyReachability::UnreachableInternal};
    GalaxySecuritySeverity security_severity{GalaxySecuritySeverity::None};
    std::uint32_t security_finding_count{0u};
    std::string top_security_finding{};
    GalaxyDiffStatus diff_status{GalaxyDiffStatus::Unchanged};
    std::uint32_t section_cluster_id{0u};
    std::uint32_t component_id{0u};
    std::uint32_t cluster_id{0u};
    std::uint32_t in_degree{0u};
    std::uint32_t out_degree{0u};
    bool is_exported{false};

    [[nodiscard]] constexpr std::uint32_t total_degree() const noexcept {
        return in_degree + out_degree;
    }
};

struct CallGalaxyEdge {
    std::uint32_t source_node{0u};
    std::uint32_t target_node{0u};
    GalaxyEdgeKind kind{GalaxyEdgeKind::Call};
    std::uint32_t weight{1u};
};

struct CallGalaxyBuildOptions {
    const peelf::SecurityAuditReport* security_report{nullptr};
    const peelf::BinaryDiffReport* diff_report{nullptr};
    std::span<const peelf::ByteVizDiffRange> diff_ranges{};
    bool include_tail_jumps{true};
    bool include_unreferenced_imports{false};
    bool treat_exports_as_roots{false};
};

struct CallGalaxyGraph {
    std::vector<CallGalaxyNode> nodes{};
    std::vector<CallGalaxyEdge> edges{};
    std::vector<std::uint32_t> primary_entry_nodes{};
    std::uint32_t component_count{0u};
    std::uint32_t max_total_degree{0u};

    // CSR adjacency tables for O(1) outgoing/incoming edge lookup per node.
    std::vector<std::uint32_t> out_edge_offsets{};
    std::vector<std::uint32_t> out_edge_indices{};
    std::vector<std::uint32_t> in_edge_offsets{};
    std::vector<std::uint32_t> in_edge_indices{};

    [[nodiscard]] bool empty() const noexcept { return nodes.empty(); }

    [[nodiscard]] std::optional<std::uint32_t> find_node_at_va(
        std::uint64_t virtual_address) const noexcept;

    [[nodiscard]] std::span<const std::uint32_t> outgoing_edge_indices(
        std::uint32_t node_index) const noexcept;

    [[nodiscard]] std::span<const std::uint32_t> incoming_edge_indices(
        std::uint32_t node_index) const noexcept;

    void rebuild_adjacency_and_metrics();
};

// Build a whole-binary call-graph galaxy from static/rebased analysis indices.
[[nodiscard]] CallGalaxyGraph build_whole_binary_call_galaxy(
    const peelf::IBinaryImage& image,
    const SymbolIndex& symbols,
    const FunctionIndex& functions,
    const ReferenceIndex& references,
    const CallGalaxyBuildOptions& options = {},
    std::stop_token stop_token = {});

// Convert any `CallGraph` (e.g., function basic-block CFG or symbol call fanout)
// into a `CallGalaxyGraph` for GPU force-layout rendering without Graphviz `dot`.
[[nodiscard]] CallGalaxyGraph build_call_galaxy_from_call_graph(
    const CallGraph& graph,
    const CallGalaxyBuildOptions& options = {});

// Re-apply security/diff overlays in place without rebuilding topology or resetting layout.
void apply_call_galaxy_overlays(
    CallGalaxyGraph& graph,
    const peelf::IBinaryImage* image,
    const CallGalaxyBuildOptions& options);

// ---------------------------------------------------------------------------
// Deterministic Barnes-Hut Quadtree Force-Directed Solver
// ---------------------------------------------------------------------------

struct BarnesHutLayoutConfig {
    float theta{0.75f};
    float repulsion_strength{1800.0f};
    float spring_length{48.0f};
    float spring_stiffness{0.065f};
    float gravity_strength{0.018f};
    float cluster_gravity_strength{0.025f};
    float damping{0.82f};
    float initial_temperature{120.0f};
    float min_temperature{0.25f};
    float cooling_factor{0.975f};
    float softening_distance{2.0f};
    float convergence_threshold{0.08f};
};

struct GalaxyWorldBounds {
    float min_x{0.0f};
    float min_y{0.0f};
    float max_x{0.0f};
    float max_y{0.0f};

    [[nodiscard]] constexpr float width() const noexcept { return max_x - min_x; }
    [[nodiscard]] constexpr float height() const noexcept { return max_y - min_y; }
};

struct BarnesHutStepResult {
    std::uint32_t iterations_executed{0u};
    float max_displacement{0.0f};
    float average_displacement{0.0f};
    float temperature{0.0f};
    bool cancelled{false};
    bool converged{false};
};

class BarnesHutGalaxyLayout {
public:
    static constexpr std::uint32_t kMaxQuadtreeDepth = 24u;

    BarnesHutGalaxyLayout() = default;

    void reset(const CallGalaxyGraph& graph, const BarnesHutLayoutConfig& config = {});

    [[nodiscard]] BarnesHutStepResult step(
        std::uint32_t iterations,
        std::stop_token stop_token = {});

    void reheat(float new_temperature = -1.0f) noexcept;

    void set_node_position(
        std::uint32_t node_index,
        float world_x,
        float world_y,
        bool pin = false) noexcept;

    void set_node_pinned(std::uint32_t node_index, bool pinned) noexcept;
    [[nodiscard]] bool is_node_pinned(std::uint32_t node_index) const noexcept;
    void unpin_all() noexcept;

    [[nodiscard]] std::size_t node_count() const noexcept { return pos_x_.size(); }
    [[nodiscard]] std::uint32_t total_iterations() const noexcept { return total_iterations_; }
    [[nodiscard]] float temperature() const noexcept { return temperature_; }
    [[nodiscard]] const BarnesHutLayoutConfig& config() const noexcept { return config_; }

    [[nodiscard]] std::span<const float> positions_x() const noexcept { return pos_x_; }
    [[nodiscard]] std::span<const float> positions_y() const noexcept { return pos_y_; }
    [[nodiscard]] std::span<const std::uint8_t> pinned_mask() const noexcept { return pinned_; }

    [[nodiscard]] GalaxyWorldBounds compute_bounds(float padding_world = 32.0f) const noexcept;

private:
    static constexpr std::uint32_t kInvalidQuad = 0xFFFF'FFFFu;

    struct CompactEdge {
        std::uint32_t src{0u};
        std::uint32_t dst{0u};
        float weight_scale{1.0f};
        float desired_length{48.0f};
    };

    struct QuadNode {
        float center_x{0.0f};
        float center_y{0.0f};
        float half_size{0.0f};
        float mass{0.0f};
        float com_x{0.0f};
        float com_y{0.0f};
        std::array<std::uint32_t, 4> children{
            kInvalidQuad,
            kInvalidQuad,
            kInvalidQuad,
            kInvalidQuad,
        };
        std::int32_t body_index{-1}; // -1 = empty/internal, >=0 = single body, -2 = coincident leaf
        bool is_internal{false};
    };

    void build_quadtree();
    void insert_body_into_quad(
        std::uint32_t quad_idx,
        std::uint32_t body_idx,
        float bx,
        float by,
        float bmass,
        std::uint32_t depth);

    BarnesHutLayoutConfig config_{};
    std::vector<float> pos_x_{};
    std::vector<float> pos_y_{};
    std::vector<float> vel_x_{};
    std::vector<float> vel_y_{};
    std::vector<float> force_x_{};
    std::vector<float> force_y_{};
    std::vector<float> node_mass_{};
    std::vector<float> inv_degree_damp_{};
    std::vector<std::uint32_t> node_cluster_{};
    std::vector<std::uint8_t> pinned_{};
    std::vector<CompactEdge> edges_{};
    std::uint32_t cluster_count_{0u};

    // Reusable scratch buffers (zero steady-state heap allocations per step).
    std::vector<QuadNode> quad_pool_{};
    std::vector<double> cluster_sum_x_{};
    std::vector<double> cluster_sum_y_{};
    std::vector<std::uint32_t> cluster_counts_{};

    float temperature_{0.0f};
    std::uint32_t total_iterations_{0u};
};

// ---------------------------------------------------------------------------
// Ego-Network, Shortest Path, Hit-Testing, & GPU Instance Generation
// ---------------------------------------------------------------------------

enum class GalaxyEgoRole : std::uint8_t {
    None = 0,
    Focus = 1,
    DirectCaller = 2,
    DirectCallee = 3,
    MutualCallerCallee = 4,
};

struct GalaxyEgoMask {
    std::uint32_t focus_node{kInvalidGalaxyNode};
    std::vector<GalaxyEgoRole> node_roles{};
    std::vector<std::uint8_t> edge_active{};
};

[[nodiscard]] GalaxyEgoMask compute_ego_network_mask(
    const CallGalaxyGraph& graph,
    std::uint32_t focus_node);

struct GalaxyCallPath {
    std::vector<std::uint32_t> nodes{};
    std::vector<std::uint32_t> edges{};

    [[nodiscard]] bool empty() const noexcept { return nodes.empty(); }
};

[[nodiscard]] GalaxyCallPath find_shortest_call_path(
    const CallGalaxyGraph& graph,
    std::uint32_t from_node,
    std::uint32_t to_node);

[[nodiscard]] GalaxyCallPath find_shortest_call_path_from_roots(
    const CallGalaxyGraph& graph,
    std::span<const std::uint32_t> root_nodes,
    std::uint32_t to_node);

[[nodiscard]] float compute_galaxy_node_world_radius(const CallGalaxyNode& node) noexcept;

[[nodiscard]] std::uint32_t compute_galaxy_node_fill_rgba8(
    const CallGalaxyGraph& graph,
    const CallGalaxyNode& node,
    GalaxyColorMode color_mode) noexcept;

[[nodiscard]] std::optional<std::uint32_t> hit_test_galaxy_node(
    const CallGalaxyGraph& graph,
    std::span<const float> world_x,
    std::span<const float> world_y,
    const ViewportCamera2D& camera,
    float viewport_width_px,
    float viewport_height_px,
    float cursor_x_px,
    float cursor_y_px,
    float hit_slop_px = 3.0f) noexcept;

// Edge instance flags encoded in upper 16 bits of `width_q8_and_flags`.
inline constexpr std::uint32_t kGalaxyEdgeFlagHighlighted = 1u << 0u;
inline constexpr std::uint32_t kGalaxyEdgeFlagCallPath    = 1u << 1u;
inline constexpr std::uint32_t kGalaxyEdgeFlagDashed      = 1u << 2u;

// Node instance flags encoded in `GalaxyNodeGpuInstance::flags`.
inline constexpr std::uint32_t kGalaxyNodeFlagHovered     = 1u << 0u;
inline constexpr std::uint32_t kGalaxyNodeFlagSelected    = 1u << 1u;
inline constexpr std::uint32_t kGalaxyNodeFlagPinned      = 1u << 2u;
inline constexpr std::uint32_t kGalaxyNodeFlagOnCallPath  = 1u << 3u;
inline constexpr std::uint32_t kGalaxyNodeFlagSearchMatch = 1u << 4u;
inline constexpr std::uint32_t kGalaxyNodeFlagDimmed      = 1u << 5u;
inline constexpr std::uint32_t kGalaxyNodeFlagEntryPoint  = 1u << 6u;
inline constexpr std::uint32_t kGalaxyNodeFlagExternal    = 1u << 7u;

struct alignas(16) GalaxyEdgeGpuInstance {
    float x0_px{0.0f};
    float y0_px{0.0f};
    float x1_px{0.0f};
    float y1_px{0.0f};
    std::uint32_t color_src_rgba8{0u};
    std::uint32_t color_dst_rgba8{0u};
    std::uint32_t width_q8_and_flags{0u};
    std::uint32_t reserved{0u};
};

static_assert(sizeof(GalaxyEdgeGpuInstance) == 32u);
static_assert(alignof(GalaxyEdgeGpuInstance) == 16u);
static_assert(std::is_trivially_copyable_v<GalaxyEdgeGpuInstance>);

struct alignas(16) GalaxyNodeGpuInstance {
    float cx_px{0.0f};
    float cy_px{0.0f};
    float radius_px{0.0f};
    float halo_px{0.0f};
    std::uint32_t fill_rgba8{0u};
    std::uint32_t ring_rgba8{0u};
    std::uint32_t flags{0u};
    std::uint32_t node_index{0u};
};

static_assert(sizeof(GalaxyNodeGpuInstance) == 32u);
static_assert(alignof(GalaxyNodeGpuInstance) == 16u);
static_assert(std::is_trivially_copyable_v<GalaxyNodeGpuInstance>);

struct GalaxyRenderBuildOptions {
    float viewport_width_px{1280.0f};
    float viewport_height_px{720.0f};
    GalaxyColorMode color_mode{GalaxyColorMode::OriginAndSection};
    std::uint32_t hovered_node{kInvalidGalaxyNode};
    std::uint32_t selected_node{kInvalidGalaxyNode};
    std::span<const std::uint8_t> pinned_mask{};
    const GalaxyEgoMask* ego_mask{nullptr};
    const GalaxyCallPath* highlighted_path{nullptr};
    std::span<const std::uint8_t> search_match_mask{};
    bool has_active_search{false};
    std::size_t max_visible_edges{65'536u};
    std::size_t max_labels{48u};
};

struct GalaxyLabelCandidate {
    std::uint32_t node_index{0u};
    float screen_x_px{0.0f};
    float screen_y_px{0.0f};
    float radius_px{0.0f};
    float priority{0.0f};
};

struct GalaxyRenderBatch {
    std::vector<GalaxyEdgeGpuInstance> edges{};
    std::vector<GalaxyNodeGpuInstance> nodes{};
    std::vector<GalaxyLabelCandidate> labels{};
    std::uint32_t culled_nodes{0u};
    std::uint32_t culled_or_decimated_edges{0u};
};

[[nodiscard]] GalaxyRenderBatch build_galaxy_render_batch(
    const CallGalaxyGraph& graph,
    std::span<const float> world_x,
    std::span<const float> world_y,
    const ViewportCamera2D& camera,
    const GalaxyRenderBuildOptions& options = {});

// ---------------------------------------------------------------------------
// Deterministic CPU Reference Rasterizer (RGBA8)
// ---------------------------------------------------------------------------

struct CallGalaxyRasterConfig {
    std::uint32_t width{0u};
    std::uint32_t height{0u};
    std::uint32_t clear_rgba8{pack_galaxy_rgba8(14u, 16u, 22u, 255u)};
    float node_ring_width_px{1.5f};
};

void rasterize_call_galaxy_rgba8_into(
    std::span<const GalaxyEdgeGpuInstance> edges,
    std::span<const GalaxyNodeGpuInstance> nodes,
    const CallGalaxyRasterConfig& config,
    std::vector<std::uint8_t>& out_rgba8);

[[nodiscard]] std::vector<std::uint8_t> rasterize_call_galaxy_rgba8(
    std::span<const GalaxyEdgeGpuInstance> edges,
    std::span<const GalaxyNodeGpuInstance> nodes,
    const CallGalaxyRasterConfig& config);

} // namespace viewer
