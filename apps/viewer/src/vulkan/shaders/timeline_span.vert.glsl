#version 450
// WU-32: Tracy-style GPU-instanced 2D timeline span & marker vertex shader.
//
// Drawn with `vkCmdDraw(cmd, 6, instance_count, 0, 0)` where vertex input
// binding 0 uses `VK_VERTEX_INPUT_RATE_INSTANCE` over `peelf::TimelineGpuInstance`
// (`sizeof == 32`, `alignas(16)`).

layout(location = 0) in vec4 in_rect_px; // (x0_px, y0_px, x1_px, y1_px)
layout(location = 1) in uvec4 in_style;  // (fill_rgba8, border_rgba8, shape_and_flags, hit_id)

layout(push_constant) uniform TimelinePushConstants {
    float viewport_width;
    float viewport_height;
    float corner_radius_px;
    float border_width_px;
    uint hovered_hit_id;
    uint selected_hit_id;
    float hatch_period_px;
    float reserved;
} pc;

layout(location = 0) out vec2 v_pixel_pos;
layout(location = 1) flat out vec4 v_rect_px;
layout(location = 2) flat out vec4 v_fill_rgba;
layout(location = 3) flat out vec4 v_border_rgba;
layout(location = 4) flat out uvec2 v_meta;

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
    vec2 min_p = min(in_rect_px.xy, in_rect_px.zw);
    vec2 max_p = max(in_rect_px.xy, in_rect_px.zw);

    // Pad quad bounds by 1.5 px so anti-aliased SDF edges and selection borders never clip.
    const float aa_pad = 1.5;
    vec2 q0 = min_p - vec2(aa_pad);
    vec2 q1 = max_p + vec2(aa_pad);

    vec2 corner = q0;
    if (gl_VertexIndex == 1 || gl_VertexIndex == 4) {
        corner = vec2(q1.x, q0.y);
    } else if (gl_VertexIndex == 2 || gl_VertexIndex == 3) {
        corner = vec2(q0.x, q1.y);
    } else if (gl_VertexIndex == 5) {
        corner = q1;
    }

    uint flags = in_style.z;
    uint hit_id = in_style.w;
    if (hit_id != 0xFFFFFFFFu) {
        if (hit_id == pc.hovered_hit_id) {
            flags |= (1u << 4u);
        }
        if (hit_id == pc.selected_hit_id) {
            flags |= (1u << 5u);
        }
    }

    v_pixel_pos = corner;
    v_rect_px = vec4(min_p, max_p);
    v_fill_rgba = unpack_rgba8(in_style.x);
    v_border_rgba = unpack_rgba8(in_style.y);
    v_meta = uvec2(flags, hit_id);

    vec2 vp = max(vec2(pc.viewport_width, pc.viewport_height), vec2(1.0));
    vec2 ndc = (corner / vp) * 2.0 - 1.0;
    gl_Position = vec4(ndc, 0.0, 1.0);
}
