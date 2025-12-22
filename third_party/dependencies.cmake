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
FetchContent_Declare(
        imgui_src
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.6
        GIT_SHALLOW    TRUE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE  # <-- Add this to each
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

target_link_libraries(imgui PUBLIC glfw Vulkan::Vulkan)