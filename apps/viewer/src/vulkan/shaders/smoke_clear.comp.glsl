#version 450
// WU-29 minimal compute clear smoke shader (SPIR-V 1.0 embedded in spirv_validation.hpp).
layout(local_size_x = 16, local_size_y = 16, local_size_z = 1) in;

layout(set = 0, binding = 0, rgba8) uniform writeonly image2D u_out_image;

layout(push_constant) uniform PushConstants {
    vec4 clear_color;
    uvec2 extent;
} u_pc;

void main() {
    uvec2 gid = gl_GlobalInvocationID.xy;
    if (gid.x < u_pc.extent.x && gid.y < u_pc.extent.y) {
        imageStore(u_out_image, ivec2(gid), u_pc.clear_color);
    }
}
