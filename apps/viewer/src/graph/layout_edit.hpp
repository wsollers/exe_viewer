#pragma once
#include "call_graph.hpp"
#include <algorithm>
#include <cmath>

namespace viewer {
// Graphviz coordinates increase upwards; mouse coordinates increase downwards.
inline bool move_graph_card(GraphLayout& layout, std::string_view id,
                            double screen_dx, double screen_dy, double scale) {
    if (!std::isfinite(scale) || scale<=0 || !std::isfinite(screen_dx) || !std::isfinite(screen_dy)) return false;
    const auto node=std::ranges::find(layout.nodes,id,&GraphLayoutNode::node_id);
    if (node==layout.nodes.end()) return false;
    const auto x=node->center_x+screen_dx/scale, y=node->center_y-screen_dy/scale;
    if (!std::isfinite(x) || !std::isfinite(y)) return false;
    node->center_x=x; node->center_y=y;
    return true;
}
}
