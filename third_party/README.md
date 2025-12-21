# third_party

This project expects dependencies to be **vendored** here (source checkouts).

## Required
- GLFW: `third_party/glfw`
- Dear ImGui: `third_party/imgui`

## Optional
- Vulkan-Headers: `third_party/Vulkan-Headers`
  (If omitted, the project will try to use headers from your Vulkan SDK / system installation.)

## Bootstrap
Run one of:
- `scripts/bootstrap_deps.sh`
- `scripts/bootstrap_deps.ps1`
