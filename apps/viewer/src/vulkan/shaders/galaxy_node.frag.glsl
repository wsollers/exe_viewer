#version 450
// WU-33: Analytical 2D SDF fragment shader for call-graph galaxy nodes with
// crisp anti-aliased ring borders, hover/selected/pinned/path radial halos,
// and pinned-node center indicator.

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

layout(location = 0) in vec2 v_local_offset_px;
layout(location = 1) flat in vec2 v_radii_px;
layout(location = 2) flat in vec4 v_fill_rgba;
layout(location = 3) flat in vec4 v_ring_rgba;
layout(location = 4) flat in uint v_flags;

layout(location = 0) out vec4 out_color;

void main() {
    float dist = length(v_local_offset_px);
    float radius_px = v_radii_px.x;
    float halo_px = v_radii_px.y;
    float sdf = dist - radius_px;

    float halo_a = 0.0;
    if (halo_px > 0.25 && sdf < halo_px) {
        float ht = 1.0 - clamp(max(sdf, 0.0) / halo_px, 0.0, 1.0);
        halo_a = v_ring_rgba.a * 0.36 * ht * ht;
    }

    float disc_cov = 1.0 - smoothstep(-0.55, 0.55, sdf);
    if (disc_cov <= 0.0 && halo_a <= 0.002) {
        discard;
    }

    float ring_w = max(0.85, pc.node_ring_width_px);
    if ((v_flags & 3u) != 0u) {
        ring_w += 0.85;
    }

    float ring_mix = smoothstep(-ring_w - 0.45, -ring_w + 0.45, sdf);
    vec4 disc_col = mix(v_fill_rgba, v_ring_rgba, ring_mix);

    if ((v_flags & 1u) != 0u) {
        disc_col.rgb = min(vec3(1.0), disc_col.rgb + vec3(0.10));
    }

    // Subtle crisp inner dot when a node is interactively pinned (`kGalaxyNodeFlagPinned = 4u`).
    if ((v_flags & 4u) != 0u && radius_px >= 4.0) {
        float pin_r = clamp(radius_px * 0.28, 1.1, 3.0);
        float pin_mix = 1.0 - smoothstep(pin_r - 0.45, pin_r + 0.45, dist);
        disc_col = mix(disc_col, vec4(0.92, 0.99, 1.0, 1.0), pin_mix * 0.85);
    }

    float disc_a = clamp(disc_col.a * disc_cov, 0.0, 1.0);
    float out_a = disc_a + halo_a * (1.0 - disc_a);
    if (out_a <= 0.002) {
        discard;
    }

    vec3 premul_rgb = disc_col.rgb * disc_a + v_ring_rgba.rgb * halo_a * (1.0 - disc_a);
    out_color = vec4(premul_rgb / out_a, clamp(out_a, 0.0, 1.0));
}
