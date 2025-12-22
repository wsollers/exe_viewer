# Third-Party Dependencies

This directory contains vendored third-party dependencies.

## Contents

- **glfw/** - Multi-platform windowing and input library
- **imgui/** - Dear ImGui immediate mode GUI library
- **Vulkan-Headers/** - Vulkan API headers from Khronos
- **Vulkan-Loader/** - Vulkan runtime loader
- **Vulkan-Utility-Libraries/** - Vulkan utility libraries

## Usage

Include the generated CMake file in your project:

`cmake
cmake_minimum_required(VERSION 3.16)
project(MyApp)

include(third_party/dependencies.cmake)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE
    glfw
    imgui
    Vulkan::Vulkan  # or Vulkan::Headers for headers-only
)
`

## Updating

Re-run the vendor script with the `-Clean` flag to update all dependencies:

`powershell
./vendor_dependencies.ps1 -Clean
`

## Generated

This directory was generated on 2025-12-21 18:30:52
