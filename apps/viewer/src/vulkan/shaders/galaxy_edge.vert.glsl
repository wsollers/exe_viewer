#version 450
// WU-33: GPU-instanced oriented 2D call-graph edge vertex shader.
//
// Drawn with `vkCmdDraw(cmd, 6, edge_count, 0, 0)` where vertex input
// binding 0 uses `VK_VERTEX_INPUT_RATE_INSTANCE` over `viewer::GalaxyEdgeGpuInstance`
// (`sizeof == 32`, `alignas(16)`).

layout(location = 0) in vec4 in_endpoints_px; // (x0_px, y0_px, x1_px, y1_px)
layout(location = 1) in uvec4 in_style;       // (color_src_rgba8, color_dst_rgba8, width_q8_and_flags, reserved)

layout(push_constant) uniform CallGalaxyPushConstants {
    float viewport_width;
    float viewport_height;
    float node_ring_width_px;
    float time_seconds;
    uint hovered_node_index;
    uint selected_node_index;
    uint flags;
    float reserved;
} pc;

layout(location = 0) out vec2 v_local_px;
layout(location = 1) flat out vec2 v_seg_meta;
layout(location = 2) flat out vec4 v_src_rgba;
layout(location = 3) flat out vec4 v_dst_rgba;
layout(location = 4) flat out uint v_flags;

out gl_PerVertex {
    vec4 gl_Position;
};

vec4 unpack_rgba8(uint c) {
    return vec4(
        float(c & 0xFFu),
        float((c >> 8u) & 0xFFu),
        float((c >> 16u) & 0xFFu),
        float((c >> 24u) & 0xFFu)
    ) * (1.0 / 255.0);
}

void main() {
    vec2 p0 = in_endpoints_px.xy;
    vec2 p1 = in_endpoints_px.zw;
    vec2 delta = p1 - p0;
    float seg_len = length(delta);

    if (seg_len < 0.25) {
        v_local_px = vec2(0.0);
        v_seg_meta = vec2(0.0, 1.0);
        v_src_rgba = vec4(0.0);
        v_dst_rgba = vec4(0.0);
        v_flags = 0u;
        gl_Position = vec4(2.0, 2.0, 0.0, 1.0);
        return;
    }

    vec2 dir = delta / seg_len;
    vec2 nrm = vec2(-dir.y, dir.x);

    float width_px = max(0.85, float(in_style.z & 0xFFFFu) * (1.0 / 256.0));
    uint edge_flags = in_style.z >> 16u;
    float half_ext = width_px * 0.65 + 1.5;

    float along_px = -1.5;
    float perp_px = -half_ext;
    if (gl_VertexIndex == 1 || gl_VertexIndex == 4) {
        along_px = seg_len + 1.5;
        perp_px = -half_ext;
    } else if (gl_VertexIndex == 2 || gl_VertexIndex == 3) {
        along_px = -1.5;
        perp_px = half_ext;
    } else if (gl_VertexIndex == 5) {
        along_px = seg_len + 1.5;
        perp_px = half_ext;
    }

    vec2 pixel_pos = p0 + dir * along_px + nrm * perp_px;

    v_local_px = vec2(along_px, perp_px);
    v_seg_meta = vec2(seg_len, width_px);
    v_src_rgba = unpack_rgba8(in_style.x);
    v_dst_rgba = unpack_rgba8(in_style.y);
    v_flags = edge_flags;

    vec2 vp = max(vec2(pc.viewport_width, pc.viewport_height), vec2(1.0));
    vec2 ndc = (pixel_pos / vp) * 2.0 - 1.0;
    gl_Position = vec4(ndc, 0.0, 1.0);
}
