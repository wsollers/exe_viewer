#version 450
// WU-29 passthrough 2D quad vertex smoke shader (SPIR-V 1.0 embedded in spirv_validation.hpp).
layout(location = 0) in vec2 a_ndc_pos;
layout(location = 1) in vec4 a_color;

layout(location = 0) out vec4 v_color;

out gl_PerVertex {
    vec4 gl_Position;
};

void main() {
    v_color = a_color;
    gl_Position = vec4(a_ndc_pos.x, a_ndc_pos.y, 0.0, 1.0);
}
