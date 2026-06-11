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
set(CAPSTONE_MIPS_SUPPORT ON CACHE BOOL "" FORCE)     # MIPS32/MIPS64
set(CAPSTONE_PPC_SUPPORT ON CACHE BOOL "" FORCE)      # PowerPC/PowerPC64
set(CAPSTONE_RISCV_SUPPORT ON CACHE BOOL "" FORCE)    # RISC-V RV32/RV64

FetchContent_MakeAvailable(capstone)

# AsmJit + AsmTK
#
# AsmJit has a normal CMake target (`asmjit::asmjit`). AsmTK's current
# CMakeLists requires a newer CMake than this project, so we fetch its source
# and build the small parser library locally from the same source list it uses.
add_library(peelf_asmtk INTERFACE)
add_library(peelf::asmtk ALIAS peelf_asmtk)

if(PEELF_ENABLE_ASMTK)
        set(PEELF_ASMJIT_TAG "0bd5787b54b575ed94bf32ac452153b34385c514" CACHE STRING "Pinned AsmJit commit")
        set(PEELF_ASMTK_TAG "1261a46fabb0b353be1f52ff77b0245aa9c170f4" CACHE STRING "Pinned AsmTK commit")

        set(ASMJIT_STATIC ON CACHE BOOL "" FORCE)
        set(ASMJIT_TEST OFF CACHE BOOL "" FORCE)
        set(ASMJIT_NO_INSTALL ON CACHE BOOL "" FORCE)
        set(ASMJIT_NO_CUSTOM_FLAGS ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
                asmjit_src
                GIT_REPOSITORY https://github.com/asmjit/asmjit.git
                GIT_TAG        ${PEELF_ASMJIT_TAG}
                GIT_SHALLOW    FALSE
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(asmjit_src)

        FetchContent_Declare(
                asmtk_src
                GIT_REPOSITORY https://github.com/asmjit/asmtk.git
                GIT_TAG        ${PEELF_ASMTK_TAG}
                GIT_SHALLOW    FALSE
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_GetProperties(asmtk_src)
        if(NOT asmtk_src_POPULATED)
                if(POLICY CMP0169)
                        cmake_policy(PUSH)
                        cmake_policy(SET CMP0169 OLD)
                endif()
                FetchContent_Populate(asmtk_src)
                if(POLICY CMP0169)
                        cmake_policy(POP)
                endif()
        endif()

        add_library(asmtk STATIC
                ${asmtk_src_SOURCE_DIR}/src/asmtk/asmtk.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/asmparser.cpp
                ${asmtk_src_SOURCE_DIR}/src/asmtk/asmparser.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/asmtokenizer.cpp
                ${asmtk_src_SOURCE_DIR}/src/asmtk/asmtokenizer.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/elfdefs.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/globals.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/parserutils.h
                ${asmtk_src_SOURCE_DIR}/src/asmtk/strtod.h
        )
        target_compile_features(asmtk PUBLIC cxx_std_17)
        target_compile_definitions(asmtk PUBLIC ASMTK_STATIC)
        target_include_directories(asmtk SYSTEM PUBLIC ${asmtk_src_SOURCE_DIR}/src)
        target_link_libraries(asmtk PUBLIC asmjit::asmjit)
        add_library(asmjit::asmtk ALIAS asmtk)

        target_link_libraries(peelf_asmtk INTERFACE asmjit::asmjit asmjit::asmtk)
        target_compile_definitions(peelf_asmtk INTERFACE PEELF_ASMTK_AVAILABLE=1)
else()
        target_compile_definitions(peelf_asmtk INTERFACE PEELF_ASMTK_AVAILABLE=0)
endif()

# Graphviz
#
# We primarily need Graphviz as a DOT renderer/export target for call-flow and
# control-flow graphs. DOT text emission does not require a dependency, so this
# is deliberately optional: enabling it fetches the upstream source tree and
# exposes a stable project target (`peelf::graphviz`) with source/tool paths for
# future renderer integration. We do not force Graphviz's full build into every
# configure because it is a large project with platform/system-library edges.
set(PEELF_GRAPHVIZ_TAG "13.0.0" CACHE STRING "Graphviz git tag to fetch when PEELF_ENABLE_GRAPHVIZ is ON")
find_program(
        PEELF_GRAPHVIZ_DOT_EXECUTABLE
        NAMES dot
        HINTS
                "$ENV{ProgramFiles}/Graphviz/bin"
                "C:/Program Files/Graphviz/bin"
                "C:/Program Files (x86)/Graphviz/bin"
)

add_library(peelf_graphviz INTERFACE)
add_library(peelf::graphviz ALIAS peelf_graphviz)

if(PEELF_GRAPHVIZ_DOT_EXECUTABLE)
        file(TO_CMAKE_PATH "${PEELF_GRAPHVIZ_DOT_EXECUTABLE}" PEELF_GRAPHVIZ_DOT_EXECUTABLE_CMAKE_PATH)
        target_compile_definitions(peelf_graphviz INTERFACE PEELF_GRAPHVIZ_DOT_AVAILABLE=1)
        target_compile_definitions(peelf_graphviz INTERFACE
                PEELF_GRAPHVIZ_DOT_EXECUTABLE="${PEELF_GRAPHVIZ_DOT_EXECUTABLE_CMAKE_PATH}")
else()
        target_compile_definitions(peelf_graphviz INTERFACE PEELF_GRAPHVIZ_DOT_AVAILABLE=0)
endif()

if(PEELF_ENABLE_GRAPHVIZ)
        FetchContent_Declare(
                graphviz_src
                GIT_REPOSITORY https://gitlab.com/graphviz/graphviz.git
                GIT_TAG        ${PEELF_GRAPHVIZ_TAG}
                GIT_SHALLOW    TRUE
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_GetProperties(graphviz_src)
        if(NOT graphviz_src_POPULATED)
                FetchContent_Populate(graphviz_src)
        endif()
        target_compile_definitions(peelf_graphviz INTERFACE PEELF_GRAPHVIZ_SOURCE_AVAILABLE=1)
        target_compile_definitions(peelf_graphviz INTERFACE
                PEELF_GRAPHVIZ_SOURCE_DIR="$<SHELL_PATH:${graphviz_src_SOURCE_DIR}>")
else()
        target_compile_definitions(peelf_graphviz INTERFACE PEELF_GRAPHVIZ_SOURCE_AVAILABLE=0)
endif()
