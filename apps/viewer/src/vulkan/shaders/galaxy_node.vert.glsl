#version 450
// WU-33: GPU-instanced 2D SDF node disc & halo vertex shader.
//
// Drawn with `vkCmdDraw(cmd, 6, node_count, 0, 0)` where vertex input
// binding 0 uses `VK_VERTEX_INPUT_RATE_INSTANCE` over `viewer::GalaxyNodeGpuInstance`
// (`sizeof == 32`, `alignas(16)`).

layout(location = 0) in vec4 in_geom_px; // (cx_px, cy_px, radius_px, halo_px)
layout(location = 1) in uvec4 in_style;  // (fill_rgba8, ring_rgba8, flags, node_index)

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

layout(location = 0) out vec2 v_local_offset_px;
layout(location = 1) flat out vec2 v_radii_px;
layout(location = 2) flat out vec4 v_fill_rgba;
layout(location = 3) flat out vec4 v_ring_rgba;
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
    uint node_flags = in_style.z;
    uint node_idx = in_style.w;

    float radius_px = max(1.5, in_geom_px.z);
    float halo_px = max(0.0, in_geom_px.w);

    if (node_idx != 0xFFFFFFFFu) {
        if (node_idx == pc.hovered_node_index) {
            node_flags |= 1u;
            halo_px = max(halo_px, 9.0);
        }
        if (node_idx == pc.selected_node_index) {
            node_flags |= 2u;
            halo_px = max(halo_px, 8.5);
        }
    }

    float quad_r = radius_px + halo_px + 2.0;
    vec2 offset = vec2(-quad_r, -quad_r);
    if (gl_VertexIndex == 1 || gl_VertexIndex == 4) {
        offset = vec2(quad_r, -quad_r);
    } else if (gl_VertexIndex == 2 || gl_VertexIndex == 3) {
        offset = vec2(-quad_r, quad_r);
    } else if (gl_VertexIndex == 5) {
        offset = vec2(quad_r, quad_r);
    }

    vec2 pixel_pos = in_geom_px.xy + offset;

    v_local_offset_px = offset;
    v_radii_px = vec2(radius_px, halo_px);
    v_fill_rgba = unpack_rgba8(in_style.x);
    v_ring_rgba = unpack_rgba8(in_style.y);
    v_flags = node_flags;

    vec2 vp = max(vec2(pc.viewport_width, pc.viewport_height), vec2(1.0));
    vec2 ndc = (pixel_pos / vp) * 2.0 - 1.0;
    gl_Position = vec4(ndc, 0.0, 1.0);
}
