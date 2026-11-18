#version 450
// WU-32: Analytical 2D SDF fragment shader for GPU-instanced timeline spans,
// instant diamond markers, diagonal hatched uncertainty bands, sparkline bars,
// anti-aliased 1px borders, and hover/selection highlights.

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

layout(location = 0) in vec2 v_pixel_pos;
layout(location = 1) flat in vec4 v_rect_px;
layout(location = 2) flat in vec4 v_fill_rgba;
layout(location = 3) flat in vec4 v_border_rgba;
layout(location = 4) flat in uvec2 v_meta;

layout(location = 0) out vec4 out_color;

float sd_rounded_box(vec2 p, vec2 half_extents, float radius) {
    float r = clamp(radius, 0.0, min(half_extents.x, half_extents.y));
    vec2 q = abs(p) - (half_extents - vec2(r));
    return length(max(q, vec2(0.0))) + min(max(q.x, q.y), 0.0) - r;
}

float sd_diamond(vec2 p, vec2 half_extents) {
    vec2 r = max(half_extents, vec2(0.5));
    float norm_d = (abs(p.x) / r.x) + (abs(p.y) / r.y) - 1.0;
    return norm_d * min(r.x, r.y) * 0.70710678;
}

void main() {
    uint flags = v_meta.x;
    uint shape = flags & 0xFu;
    bool is_hovered = (flags & (1u << 4u)) != 0u;
    bool is_selected = (flags & (1u << 5u)) != 0u;
    bool is_cluster = (flags & (1u << 6u)) != 0u;

    vec2 center = 0.5 * (v_rect_px.xy + v_rect_px.zw);
    vec2 half_ext = max(0.5 * (v_rect_px.zw - v_rect_px.xy), vec2(0.25));
    vec2 d = v_pixel_pos - center;

    float dist = 0.0;
    if (shape == 0u) {
        dist = sd_rounded_box(d, half_ext, pc.corner_radius_px);
    } else if (shape == 1u) {
        dist = sd_diamond(d, half_ext);
    } else if (shape == 2u) {
        dist = sd_rounded_box(d, half_ext, 2.0);
    } else {
        vec2 q = abs(d) - half_ext;
        dist = max(q.x, q.y);
    }

    float coverage = clamp(0.5 - dist, 0.0, 1.0);
    if (coverage <= 0.0) {
        discard;
    }

    vec4 fill = v_fill_rgba;
    vec4 border = v_border_rgba;
    if (is_hovered) {
        fill.rgb = min(vec3(1.0), fill.rgb + vec3(0.14));
    }
    if (is_selected) {
        border = vec4(1.0, 0.96, 0.72, 1.0);
    }

    vec4 src = fill;
    if (shape == 2u) {
        float period = max(4.0, pc.hatch_period_px);
        float phase = fract(abs(v_pixel_pos.x + v_pixel_pos.y) / period);
        if (phase < 0.45) {
            src.a *= 0.38;
            src.rgb *= 0.65;
        }
    }

    if (is_cluster && (v_pixel_pos.y - v_rect_px.y) <= 2.2) {
        src = border;
    }

    if (shape != 3u && shape != 4u) {
        float bw = max(0.5, pc.border_width_px) + (is_selected ? 0.9 : 0.0);
        float border_t = clamp(dist + bw + 0.5, 0.0, 1.0);
        src = mix(src, border, border_t);
    }

    out_color = vec4(src.rgb, clamp(src.a * coverage, 0.0, 1.0));
}
