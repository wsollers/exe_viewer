#version 450
// WU-29 passthrough 2D quad fragment smoke shader (SPIR-V 1.0 embedded in spirv_validation.hpp).
layout(location = 0) in vec4 v_color;

layout(location = 0) out vec4 out_color;

void main() {
    out_color = v_color;
}
