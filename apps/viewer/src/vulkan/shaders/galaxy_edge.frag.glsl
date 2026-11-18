#version 450
// WU-33: Analytical 2D perpendicular SDF fragment shader for oriented call-graph edges
// with smooth anti-aliasing, source->target directional color/width taper, and dash support.

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

layout(location = 0) in vec2 v_local_px;
layout(location = 1) flat in vec2 v_seg_meta;
layout(location = 2) flat in vec4 v_src_rgba;
layout(location = 3) flat in vec4 v_dst_rgba;
layout(location = 4) flat in uint v_flags;

layout(location = 0) out vec4 out_color;

void main() {
    float seg_len = v_seg_meta.x;
    float width_px = v_seg_meta.y;
    if (seg_len <= 0.0) {
        discard;
    }

    float clamped_x = clamp(v_local_px.x, 0.0, seg_len);
    float t = clamped_x / seg_len;
    float dx_cap = v_local_px.x - clamped_x;
    float dist = length(vec2(dx_cap, v_local_px.y));

    float half_w = max(0.45, width_px * 0.5) * (0.82 + 0.36 * t);
    float coverage = 1.0 - smoothstep(half_w - 0.55, half_w + 0.65, dist);
    if (coverage <= 0.0) {
        discard;
    }

    float dash_mask = 1.0;
    if ((v_flags & 4u) != 0u) {
        float phase = mod(max(clamped_x, 0.0), 10.0);
        dash_mask = (1.0 - smoothstep(5.6, 6.5, phase)) + smoothstep(9.2, 10.0, phase);
        if (dash_mask <= 0.02) {
            discard;
        }
    }

    vec4 col = mix(v_src_rgba, v_dst_rgba, t);
    if ((v_flags & 2u) != 0u) {
        float core = 1.0 - smoothstep(0.0, half_w * 0.55, dist);
        col.rgb = mix(col.rgb, vec3(1.0, 0.99, 0.86), core * 0.45);
    }

    out_color = vec4(col.rgb, clamp(col.a * coverage * dash_mask, 0.0, 1.0));
}
