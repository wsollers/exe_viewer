#version 450
// WU-30: Live RAM, Dirty-Page, & Allocator Hilbert Heatmap compute shader.
// Precompiled SPIR-V 1.0 words are embedded in memory_heatmap_comp_spirv.hpp
// and validated at compile time via validate_spirv_words(...).

layout(local_size_x = 16, local_size_y = 16, local_size_z = 1) in;

layout(set = 0, binding = 0, rgba8) uniform writeonly image2D u_out_image;

layout(std430, set = 0, binding = 1) readonly buffer CellBuffer {
    uvec4 cells[];
} u_cells;

layout(push_constant) uniform PushConstants {
    vec4 vp_and_scale;   // .xy = viewport_size, .zw = scale_xy (pixels per cell)
    vec4 inv_and_ndc;    // .xy = inv_scale_xy,  .zw = ndc_scale_xy
    vec4 center_hilo;    // .xy = center_x (hi, lo), .zw = center_y (hi, lo)
    uvec4 dims;          // .xy = canvas_size,   .zw = grid_size
    uvec4 modes;         // .x = hilbert_order, .y = active_cells, .z = layout_mode, .w = color_mode
    uvec4 selection;     // .x = hovered_cell,  .y = selected_cell, .z = pulse_bits, .w = flags
} u_pc;

uint hilbert_xy_to_index_u32(uint order, uint x, uint y) {
    uint idx = 0u;
    uint cx = x;
    uint cy = y;
    uint s = (order >= 1u && order <= 16u) ? (1u << (order - 1u)) : 0u;
    while (s > 0u) {
        uint rx = ((cx & s) != 0u) ? 1u : 0u;
        uint ry = ((cy & s) != 0u) ? 1u : 0u;
        uint quad = (3u * rx) ^ ry;
        idx = (idx << 2u) | quad;
        if (ry == 0u) {
            if (rx == 1u) {
                cx = (s - 1u) - (cx & (s - 1u));
                cy = (s - 1u) - (cy & (s - 1u));
            }
            uint tmp = cx;
            cx = cy;
            cy = tmp;
        }
        s >>= 1u;
    }
    return idx;
}

vec3 magma_ramp(float t) {
    float x = clamp(t, 0.0, 1.0);
    vec3 c0 = vec3(0.086, 0.047, 0.180);
    vec3 c1 = vec3(0.451, 0.106, 0.431);
    vec3 c2 = vec3(0.863, 0.298, 0.235);
    vec3 c3 = vec3(0.992, 0.745, 0.235);
    vec3 c4 = vec3(0.996, 0.976, 0.761);
    vec3 a = mix(c0, c1, clamp(x * 4.0, 0.0, 1.0));
    a = mix(a, c2, clamp((x - 0.25) * 4.0, 0.0, 1.0));
    a = mix(a, c3, clamp((x - 0.50) * 4.0, 0.0, 1.0));
    a = mix(a, c4, clamp((x - 0.75) * 4.0, 0.0, 1.0));
    return a;
}

vec3 entropy_ramp(float t) {
    float x = clamp(t, 0.0, 1.0);
    vec3 e0 = vec3(0.110, 0.157, 0.306);
    vec3 e1 = vec3(0.145, 0.525, 0.620);
    vec3 e2 = vec3(0.396, 0.776, 0.420);
    vec3 e3 = vec3(0.976, 0.788, 0.259);
    vec3 a = mix(e0, e1, clamp(x * 3.0, 0.0, 1.0));
    a = mix(a, e2, clamp((x - 0.3333333) * 3.0, 0.0, 1.0));
    a = mix(a, e3, clamp((x - 0.6666667) * 3.0, 0.0, 1.0));
    return a;
}

vec3 category_color(uint cat) {
    vec3 c = vec3(0.118, 0.133, 0.180);
    c = (cat == 1u) ? vec3(0.227, 0.533, 0.878) : c; // ImageCode
    c = (cat == 2u) ? vec3(0.290, 0.698, 0.659) : c; // ImageRoData
    c = (cat == 3u) ? vec3(0.384, 0.620, 0.424) : c; // ImageRwData
    c = (cat == 4u) ? vec3(0.839, 0.557, 0.212) : c; // Heap
    c = (cat == 5u) ? vec3(0.659, 0.408, 0.855) : c; // ThreadStack
    c = (cat == 6u) ? vec3(0.447, 0.502, 0.620) : c; // AnonRw
    c = (cat == 7u) ? vec3(0.329, 0.659, 0.776) : c; // SharedMapped
    c = (cat == 8u) ? vec3(0.698, 0.227, 0.282) : c; // GuardPage
    c = (cat == 9u) ? vec3(0.157, 0.847, 0.894) : c; // PatchDirty
    return c;
}

void main() {
    uvec2 gid = gl_GlobalInvocationID.xy;
    if (gid.x >= u_pc.dims.x || gid.y >= u_pc.dims.y) {
        return;
    }

    float rel_x = ((float(gid.x) + 0.5 - 0.5 * u_pc.vp_and_scale.x) * u_pc.inv_and_ndc.x) + u_pc.center_hilo.y;
    float rel_y = ((float(gid.y) + 0.5 - 0.5 * u_pc.vp_and_scale.y) * u_pc.inv_and_ndc.y) + u_pc.center_hilo.w;
    float wx = u_pc.center_hilo.x + rel_x;
    float wy = u_pc.center_hilo.z + rel_y;

    float fx = floor(wx);
    float fy = floor(wy);
    int ix = int(fx);
    int iy = int(fy);

    vec4 out_rgba = vec4(0.055, 0.063, 0.086, 1.0);
    if (wx >= 0.0 && wy >= 0.0 && ix >= 0 && iy >= 0 &&
        uint(ix) < u_pc.dims.z && uint(iy) < u_pc.dims.w) {
        uint ux = uint(ix);
        uint uy = uint(iy);
        uint cell_idx = (u_pc.modes.z == 0u)
            ? hilbert_xy_to_index_u32(u_pc.modes.x, ux, uy)
            : (uy * u_pc.dims.z + ux);

        vec2 uv = clamp(vec2(wx - fx, wy - fy), vec2(0.0), vec2(1.0));
        float min_px = min(u_pc.vp_and_scale.z, u_pc.vp_and_scale.w);
        float edge_px = min(
            min(uv.x * u_pc.vp_and_scale.z, (1.0 - uv.x) * u_pc.vp_and_scale.z),
            min(uv.y * u_pc.vp_and_scale.w, (1.0 - uv.y) * u_pc.vp_and_scale.w));

        vec3 rgb = vec3(0.086, 0.102, 0.137);
        if (cell_idx < u_pc.modes.y) {
            uvec4 raw = u_cells.cells[cell_idx];
            uint w2 = raw.z;
            uint w3 = raw.w;

            uint perms = (w2 >> 25u) & 0x3Fu;
            bool perm_r = (perms & 0x01u) != 0u;
            bool perm_w = (perms & 0x02u) != 0u;
            bool perm_x = (perms & 0x04u) != 0u;
            bool perm_guard = (perms & 0x10u) != 0u;
            bool perm_rwx = ((perms & 0x20u) != 0u) || (perm_w && perm_x);
            bool perm_flip = ((w2 >> 31u) & 1u) != 0u;

            float heat = float(w3 & 0xFFu) / 255.0;
            float ent = float((w3 >> 8u) & 0xFFu) / 255.0;
            uint cat = (w3 >> 24u) & 0x0Fu;
            uint res = (w3 >> 28u) & 0x03u;
            bool newly_alloc = ((w3 >> 30u) & 1u) != 0u;
            bool hot_focus = ((w3 >> 31u) & 1u) != 0u;

            vec3 cat_rgb = category_color(cat);
            vec3 res_rgb = cat_rgb;
            res_rgb = (res == 2u) ? (cat_rgb * 0.52 + vec3(0.08, 0.04, 0.12)) : res_rgb;
            res_rgb = (res == 3u) ? (cat_rgb * 0.42) : res_rgb;
            res_rgb = (res == 0u) ? (cat_rgb * 0.82) : res_rgb;

            vec3 perm_rgb = vec3(0.216, 0.235, 0.290);
            perm_rgb = perm_r ? vec3(0.275, 0.690, 0.569) : perm_rgb;
            perm_rgb = perm_w ? vec3(0.878, 0.596, 0.227) : perm_rgb;
            perm_rgb = perm_x ? vec3(0.235, 0.569, 0.922) : perm_rgb;
            perm_rgb = perm_guard ? vec3(0.698, 0.227, 0.282) : perm_rgb;
            perm_rgb = perm_rwx ? vec3(0.949, 0.196, 0.471) : perm_rgb;

            vec3 heat_cool = res_rgb * 0.52 + vec3(0.03, 0.04, 0.06);
            vec3 mode0 = mix(heat_cool, magma_ramp(heat), clamp(heat * 1.15, 0.0, 1.0));
            mode0 = newly_alloc ? mix(mode0, vec3(0.30, 0.95, 0.68), 0.32) : mode0;

            vec3 mode1 = mix(res_rgb, magma_ramp(heat), clamp(heat * 0.45, 0.0, 0.45));
            vec3 mode2 = mix(perm_rgb, magma_ramp(heat), clamp(heat * 0.35, 0.0, 0.35));
            vec3 mode3 = entropy_ramp(ent);
            mode3 = (res == 3u) ? (mode3 * 0.45) : mode3;

            rgb = mode0;
            rgb = (u_pc.modes.w == 1u) ? mode1 : rgb;
            rgb = (u_pc.modes.w == 2u) ? mode2 : rgb;
            rgb = (u_pc.modes.w == 3u) ? mode3 : rgb;
            rgb = (cat == 0u && !perm_guard) ? vec3(0.102, 0.118, 0.157) : rgb;

            float pulse = clamp(uintBitsToFloat(u_pc.selection.z), 0.0, 1.0);
            if (cat == 9u && min_px >= 4.0 && uv.x > 0.62 && uv.y < 0.38) {
                rgb = vec3(0.157, 0.949, 1.0);
            }
            if (perm_rwx || perm_flip) {
                vec3 hazard_col = perm_rwx
                    ? mix(vec3(1.0, 0.18, 0.55), vec3(1.0, 0.42, 0.72), pulse)
                    : mix(vec3(1.0, 0.50, 0.14), vec3(1.0, 0.78, 0.25), pulse);
                rgb = (min_px >= 4.0)
                    ? ((edge_px < 1.6) ? hazard_col : rgb)
                    : mix(rgb, hazard_col, 0.60);
            }
            if (hot_focus) {
                rgb = (min_px >= 4.0 && edge_px < 2.2)
                    ? vec3(1.0, 0.96, 0.55)
                    : mix(rgb, vec3(1.0, 0.96, 0.55), 0.42);
            }
        }

        if (((u_pc.selection.w & 1u) != 0u) && min_px >= 6.0) {
            if ((uv.x * u_pc.vp_and_scale.z) < 1.0 || (uv.y * u_pc.vp_and_scale.w) < 1.0) {
                rgb *= 0.68;
            }
        }
        if (cell_idx == u_pc.selection.y) {
            rgb = (min_px >= 4.0 && edge_px < 2.2)
                ? vec3(0.28, 0.95, 1.0)
                : mix(rgb, vec3(0.28, 0.95, 1.0), 0.55);
        } else if (cell_idx == u_pc.selection.x) {
            rgb = (min_px >= 4.0 && edge_px < 1.6)
                ? vec3(0.92, 0.96, 1.0)
                : mix(rgb, vec3(0.92, 0.96, 1.0), 0.30);
        }

        out_rgba = vec4(clamp(rgb, vec3(0.0), vec3(1.0)), 1.0);
    }

    imageStore(u_out_image, ivec2(gid), out_rgba);
}
