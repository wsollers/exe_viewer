#version 450
// WU-31: 2D Binary Byte-Entropy & Cantor-Dust Digram Minimap compute shader.
// Precompiled SPIR-V 1.0 words are embedded in byte_viz_comp_spirv.hpp
// and validated at compile time via validate_spirv_words(...).

layout(local_size_x = 16, local_size_y = 16, local_size_z = 1) in;

layout(set = 0, binding = 0, rgba8) uniform writeonly image2D u_out_image;

layout(std430, set = 0, binding = 1) readonly buffer ByteVizDataBuffer {
    uvec4 words[];
} u_data;

layout(push_constant) uniform PushConstants {
    vec4 vp_and_scale;   // .xy = viewport_size, .zw = scale_xy (pixels per world unit)
    vec4 inv_and_ndc;    // .xy = inv_scale_xy,  .zw = ndc_scale_xy
    vec4 center_hilo;    // .xy = center_x (hi, lo), .zw = center_y (hi, lo)
    uvec4 dims;          // .xy = canvas_size,   .zw = grid_size (or 256x256 in Cantor mode)
    uvec4 modes;         // .x = viz_mode, .y = layout_mode, .z = color_mode, .w = hilbert_order
    uvec4 selection;     // .x = active_count, .y = hovered_idx, .z = selected_idx, .w = flags
    uvec4 brush_bounds;  // .xy = brush_start (lo, hi), .zw = brush_end (lo, hi)
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

uvec2 u64_add_u32(uvec2 a, uint b) {
    uint lo = a.x + b;
    uint carry = (lo < a.x) ? 1u : 0u;
    return uvec2(lo, a.y + carry);
}

bool u64_lt(uvec2 a, uvec2 b) {
    return (a.y < b.y) || ((a.y == b.y) && (a.x < b.x));
}

vec3 entropy_spectrum_ramp(float t) {
    float x = clamp(t, 0.0, 1.0);
    vec3 c0 = vec3(0.094, 0.125, 0.235);
    vec3 c1 = vec3(0.118, 0.459, 0.659);
    vec3 c2 = vec3(0.243, 0.761, 0.525);
    vec3 c3 = vec3(0.961, 0.776, 0.227);
    vec3 c4 = vec3(0.969, 0.259, 0.345);
    vec3 a = mix(c0, c1, clamp(x * 4.0, 0.0, 1.0));
    a = mix(a, c2, clamp((x - 0.25) * 4.0, 0.0, 1.0));
    a = mix(a, c3, clamp((x - 0.50) * 4.0, 0.0, 1.0));
    a = mix(a, c4, clamp((x - 0.75) * 4.0, 0.0, 1.0));
    return a;
}

vec3 byte_class_color(uint cls) {
    vec3 c = vec3(0.110, 0.125, 0.165);                   // 0 UnreadableOrEmpty
    c = (cls == 1u) ? vec3(0.149, 0.188, 0.282) : c;      // 1 AllZeroPadding
    c = (cls == 2u) ? vec3(0.667, 0.329, 0.847) : c;      // 2 TrapOrNopSlide
    c = (cls == 3u) ? vec3(0.243, 0.788, 0.490) : c;      // 3 AsciiText
    c = (cls == 4u) ? vec3(0.196, 0.745, 0.788) : c;      // 4 Utf16LeText
    c = (cls == 5u) ? vec3(0.259, 0.545, 0.922) : c;      // 5 CodeOrStructured
    c = (cls == 6u) ? vec3(0.957, 0.306, 0.376) : c;      // 6 HighEntropyPacked
    return c;
}

vec3 cantor_density_ramp(float t) {
    float x = clamp(t, 0.0, 1.0);
    vec3 c0 = vec3(0.086, 0.114, 0.220);
    vec3 c1 = vec3(0.141, 0.388, 0.686);
    vec3 c2 = vec3(0.196, 0.753, 0.745);
    vec3 c3 = vec3(0.976, 0.831, 0.306);
    vec3 c4 = vec3(1.000, 0.984, 0.882);
    vec3 a = mix(c0, c1, clamp(x * 4.0, 0.0, 1.0));
    a = mix(a, c2, clamp((x - 0.25) * 4.0, 0.0, 1.0));
    a = mix(a, c3, clamp((x - 0.50) * 4.0, 0.0, 1.0));
    a = mix(a, c4, clamp((x - 0.75) * 4.0, 0.0, 1.0));
    return a;
}

vec3 cantor_pair_tint(uint pair_cls) {
    vec3 c = vec3(0.329, 0.447, 0.698);                    // 0 ZeroZero
    c = (pair_cls == 1u) ? vec3(0.259, 0.847, 0.545) : c;  // 1 AsciiAscii
    c = (pair_cls == 2u) ? vec3(0.227, 0.816, 0.863) : c;  // 2 Utf16AsciiZero
    c = (pair_cls == 3u) ? vec3(0.376, 0.569, 0.894) : c;  // 3 ControlOrLow
    c = (pair_cls == 4u) ? vec3(0.933, 0.459, 0.329) : c;  // 4 HighBit
    c = (pair_cls == 5u) ? vec3(0.808, 0.388, 0.922) : c;  // 5 TrapOrNop
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

    bool show_guides = (u_pc.selection.w & 1u) != 0u;
    bool has_brush = (u_pc.selection.w & 2u) != 0u;

    vec4 out_rgba = vec4(0.047, 0.055, 0.078, 1.0);
    if (wx >= 0.0 && wy >= 0.0 && ix >= 0 && iy >= 0 &&
        uint(ix) < u_pc.dims.z && uint(iy) < u_pc.dims.w) {
        uint ux = uint(ix);
        uint uy = uint(iy);
        vec2 uv = clamp(vec2(wx - fx, wy - fy), vec2(0.0), vec2(1.0));
        float min_px = min(u_pc.vp_and_scale.z, u_pc.vp_and_scale.w);
        float edge_px = min(
            min(uv.x * u_pc.vp_and_scale.z, (1.0 - uv.x) * u_pc.vp_and_scale.z),
            min(uv.y * u_pc.vp_and_scale.w, (1.0 - uv.y) * u_pc.vp_and_scale.w));

        if (u_pc.modes.x == 0u) {
            // Mode 0: 2D Entropy & Byte-Class Minimap
            uint tile_idx = (u_pc.modes.y == 0u)
                ? hilbert_xy_to_index_u32(u_pc.modes.w, ux, uy)
                : (uy * u_pc.dims.z + ux);

            vec3 rgb = vec3(0.078, 0.090, 0.125);
            if (tile_idx < u_pc.selection.x) {
                uvec4 raw = u_data.words[tile_idx];
                uint w2 = raw.z;
                uint w3 = raw.w;

                uint mantissa = w2 & 0x000FFFFFu;
                bool page_scale = ((w2 >> 20u) & 1u) != 0u;
                uint span_u32 = page_scale ? (mantissa << 12u) : mantissa;
                uint byte_cls = (w2 >> 21u) & 0x07u;
                uint flags = (w2 >> 24u) & 0xFFu;

                bool patch_dirty = (flags & 0x01u) != 0u;
                bool diff_mod = (flags & 0x02u) != 0u;
                bool diff_add = (flags & 0x04u) != 0u;
                bool sec_start = (flags & 0x08u) != 0u;
                bool exec_tile = (flags & 0x10u) != 0u;

                float ent = float(w3 & 0xFFu) / 255.0;
                float prn = float((w3 >> 8u) & 0xFFu) / 255.0;
                float zro = float((w3 >> 16u) & 0xFFu) / 255.0;
                float hi  = float((w3 >> 24u) & 0xFFu) / 255.0;

                vec3 spec = entropy_spectrum_ramp(ent);
                spec = (byte_cls == 0u) ? vec3(0.102, 0.114, 0.149) : spec;
                spec = (byte_cls == 1u) ? vec3(0.118, 0.153, 0.243) : spec;

                vec3 sem = byte_class_color(byte_cls) * (0.72 + 0.36 * ent);
                sem = (exec_tile && byte_cls == 5u) ? mix(sem, vec3(0.32, 0.66, 1.0), 0.22) : sem;
                sem = (byte_cls == 0u) ? vec3(0.102, 0.114, 0.149) : sem;

                vec3 prn_hi = vec3(
                    0.10 + 0.86 * hi,
                    0.12 + 0.82 * prn,
                    0.16 + 0.56 * zro + 0.20 * (1.0 - max(prn, hi)));
                prn_hi = (byte_cls == 0u) ? vec3(0.102, 0.114, 0.149) : prn_hi;

                vec3 overlay = spec * 0.34 + vec3(0.039, 0.047, 0.067);
                overlay = diff_mod ? vec3(0.988, 0.588, 0.196) : overlay;
                overlay = diff_add ? vec3(0.243, 0.910, 0.478) : overlay;
                overlay = patch_dirty ? vec3(0.157, 0.929, 0.980) : overlay;

                rgb = spec;
                rgb = (u_pc.modes.z == 1u) ? sem : rgb;
                rgb = (u_pc.modes.z == 2u) ? prn_hi : rgb;
                rgb = (u_pc.modes.z == 3u) ? overlay : rgb;

                if (u_pc.modes.z != 3u) {
                    if (patch_dirty) {
                        rgb = (min_px >= 4.0 && uv.x > 0.62 && uv.y < 0.38)
                            ? vec3(0.157, 0.949, 1.0)
                            : mix(rgb, vec3(0.157, 0.949, 1.0), 0.38);
                    } else if (diff_add) {
                        rgb = (min_px >= 4.0 && edge_px < 1.5)
                            ? vec3(0.243, 0.941, 0.502)
                            : mix(rgb, vec3(0.243, 0.941, 0.502), 0.30);
                    } else if (diff_mod) {
                        rgb = (min_px >= 4.0 && edge_px < 1.5)
                            ? vec3(1.0, 0.620, 0.216)
                            : mix(rgb, vec3(1.0, 0.620, 0.216), 0.30);
                    }
                }

                if (sec_start && min_px >= 3.0 && (uv.x * u_pc.vp_and_scale.z) < 1.4) {
                    rgb = mix(rgb, vec3(0.95, 0.97, 1.0), 0.55);
                }

                if (has_brush) {
                    uvec2 brush_s = u_pc.brush_bounds.xy;
                    uvec2 brush_e = u_pc.brush_bounds.zw;
                    uvec2 tile_s = uvec2(raw.x, raw.y);
                    uvec2 tile_e = u64_add_u32(tile_s, max(span_u32, 1u));
                    bool in_brush = u64_lt(brush_s, brush_e) &&
                                    u64_lt(tile_s, brush_e) &&
                                    u64_lt(brush_s, tile_e);
                    if (in_brush) {
                        rgb = (min_px >= 4.0 && edge_px < 1.6)
                            ? vec3(1.0, 0.88, 0.32)
                            : mix(rgb, vec3(1.0, 0.88, 0.32), 0.34);
                    } else {
                        rgb *= 0.52;
                    }
                }
            }

            if (show_guides && min_px >= 6.0) {
                if ((uv.x * u_pc.vp_and_scale.z) < 1.0 || (uv.y * u_pc.vp_and_scale.w) < 1.0) {
                    rgb *= 0.68;
                }
            }
            if (tile_idx == u_pc.selection.z) {
                rgb = (min_px >= 4.0 && edge_px < 2.2)
                    ? vec3(0.28, 0.95, 1.0)
                    : mix(rgb, vec3(0.28, 0.95, 1.0), 0.55);
            } else if (tile_idx == u_pc.selection.y) {
                rgb = (min_px >= 4.0 && edge_px < 1.6)
                    ? vec3(0.92, 0.96, 1.0)
                    : mix(rgb, vec3(0.92, 0.96, 1.0), 0.32);
            }

            out_rgba = vec4(clamp(rgb, vec3(0.0), vec3(1.0)), 1.0);
        } else {
            // Mode 1: 256x256 Cantor-Dust Digram
            uint bin_idx = uy * 256u + ux;
            uint packed_bin = (bin_idx < 65536u)
                ? u_data.words[bin_idx >> 2u][bin_idx & 3u]
                : 0u;
            uint density_u16 = packed_bin & 0xFFFFu;
            uint pair_cls = (packed_bin >> 16u) & 0x0Fu;

            vec3 rgb = vec3(0.055, 0.063, 0.090);
            if (density_u16 > 0u) {
                float dens = float(density_u16) / 65535.0;
                vec3 ramp = cantor_density_ramp(dens);
                vec3 tint = cantor_pair_tint(pair_cls);
                rgb = mix(ramp, tint, 0.20 * (1.0 - 0.55 * dens));
            }

            if (show_guides) {
                float dx_ascii_lo = abs(wx - 32.0) * u_pc.vp_and_scale.z;
                float dx_ascii_hi = abs(wx - 127.0) * u_pc.vp_and_scale.z;
                float dx_high_bit = abs(wx - 128.0) * u_pc.vp_and_scale.z;
                float dy_ascii_lo = abs(wy - 32.0) * u_pc.vp_and_scale.w;
                float dy_ascii_hi = abs(wy - 127.0) * u_pc.vp_and_scale.w;
                float dy_high_bit = abs(wy - 128.0) * u_pc.vp_and_scale.w;

                if (dx_ascii_lo < 0.70 || dx_ascii_hi < 0.70 ||
                    dy_ascii_lo < 0.70 || dy_ascii_hi < 0.70) {
                    rgb = mix(rgb, vec3(0.28, 0.78, 0.56), 0.35);
                }
                if (dx_high_bit < 0.75 || dy_high_bit < 0.75) {
                    rgb = mix(rgb, vec3(0.88, 0.48, 0.34), 0.35);
                }
                if (min_px >= 8.0 &&
                    ((uv.x * u_pc.vp_and_scale.z) < 1.0 || (uv.y * u_pc.vp_and_scale.w) < 1.0)) {
                    rgb *= 0.72;
                }
            }

            if (u_pc.selection.z < 65536u) {
                uint sx = u_pc.selection.z & 0xFFu;
                uint sy = (u_pc.selection.z >> 8u) & 0xFFu;
                if (bin_idx == u_pc.selection.z) {
                    rgb = (min_px >= 4.0 && edge_px < 2.0)
                        ? vec3(0.28, 0.95, 1.0)
                        : mix(rgb, vec3(0.28, 0.95, 1.0), 0.60);
                } else if (ux == sx || uy == sy) {
                    rgb = mix(rgb, vec3(0.28, 0.95, 1.0), 0.16);
                }
            }
            if (u_pc.selection.y < 65536u) {
                uint hx = u_pc.selection.y & 0xFFu;
                uint hy = (u_pc.selection.y >> 8u) & 0xFFu;
                if (bin_idx == u_pc.selection.y) {
                    rgb = (min_px >= 4.0 && edge_px < 1.6)
                        ? vec3(0.95, 0.98, 1.0)
                        : mix(rgb, vec3(0.95, 0.98, 1.0), 0.42);
                } else if (ux == hx || uy == hy) {
                    rgb = mix(rgb, vec3(0.90, 0.94, 1.0), 0.12);
                }
            }

            out_rgba = vec4(clamp(rgb, vec3(0.0), vec3(1.0)), 1.0);
        }
    }

    imageStore(u_out_image, ivec2(gid), out_rgba);
}
