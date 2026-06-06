include(FetchContent)
find_package(Vulkan REQUIRED)
# GLFW
FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.4
        GIT_SHALLOW    TRUE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE  # <-- Add this to each
)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)

# Vulkan-Headers
#FetchContent_Declare(
#        vulkan_headers
#        GIT_REPOSITORY https://github.com/KhronosGroup/Vulkan-Headers.git
#        GIT_TAG        v1.4.335
#        GIT_SHALLOW    TRUE
#        DOWNLOAD_EXTRACT_TIMESTAMP TRUE  # <-- Add this to each
#)

# Dear ImGui
# Pinned to a specific docking-branch commit for reproducibility (ToDo.md P0-2)
# instead of tracking the moving `docking` tip.
#   commit 2af6dd9694288e6befe1edb7ce25510911693c22 (docking, 2026-06-04)
# Verified to contain the Vulkan-backend ImGui_ImplVulkan_InitInfo fields the
# viewer uses (PipelineInfoMain/PipelineInfoForViewports, ApiVersion,
# DescriptorPoolSize, MinAllocationSize, CustomShaderVert/FragCreateInfo).
# To advance the pin: pick a newer docking commit and re-verify those fields in
# backends/imgui_impl_vulkan.h before bumping. GIT_SHALLOW is FALSE because a
# shallow clone cannot reliably check out an arbitrary commit SHA.
FetchContent_Declare(
        imgui_src
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        2af6dd9694288e6befe1edb7ce25510911693c22
        GIT_SHALLOW    FALSE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(glfw imgui_src)

# Build ImGui as a library
add_library(imgui STATIC
        ${imgui_src_SOURCE_DIR}/imgui.cpp
        ${imgui_src_SOURCE_DIR}/imgui_demo.cpp
        ${imgui_src_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_src_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_src_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_src_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_src_SOURCE_DIR}/backends/imgui_impl_vulkan.cpp
)

target_include_directories(imgui PUBLIC
        ${imgui_src_SOURCE_DIR}
        ${imgui_src_SOURCE_DIR}/backends
)

# Native File Dialog Extended
FetchContent_Declare(
        nfd
        GIT_REPOSITORY https://github.com/btzy/nativefiledialog-extended.git
        GIT_TAG        v1.2.1
        GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nfd)

target_link_libraries(imgui PUBLIC glfw Vulkan::Vulkan)

# Capstone
FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG        5.0.6
        GIT_SHALLOW    TRUE
)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)

# Enable only architectures you need
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)      # x86/x64 with SSE/AVX/AVX-512
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)      # ARM32/ARMv7
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)    # ARM64/ARMv8

FetchContent_MakeAvailable(capstone)