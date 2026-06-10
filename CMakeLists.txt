cmake_minimum_required(VERSION 3.25)

project(peelf_explorer
  VERSION 0.0.1
  DESCRIPTION "PE/ELF executable viewer (core parser + Vulkan/GLFW/ImGui GUI)"
  LANGUAGES CXX
)

# Prevent FetchContent from re-running
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
option(PEELF_ENABLE_GRAPHVIZ "Fetch optional Graphviz source and enable Graphviz-backed graph rendering hooks" OFF)
include(third_party/dependencies.cmake)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/ProjectOptions.cmake)  # <-- Add here, once

option(PEELF_BUILD_VIEWER "Build the GUI viewer application" ON)
option(PEELF_BUILD_SHARED "Build peelf_core as a shared library" ON)
option(PEELF_BUILD_TESTS "Build unit tests (GoogleTest)" ON)
option(PEELF_ENABLE_CLANG_TIDY "Run clang-tidy on peelf targets during build (Ninja/Makefile generators only)" OFF)
option(PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST "Register the Docker-backed bin-matrix refresh test with CTest" OFF)

set(PEELF_BIN_MATRIX_DOCKER_IMAGE "exe-viewer-clang" CACHE STRING "Docker image tag used for bin-matrix fixture generation")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)



add_subdirectory(libs/peelf_core)

if(PEELF_BUILD_VIEWER)
  add_subdirectory(apps/viewer)
endif()

# ---------------------------------------------------------------------------
# Unit tests (GoogleTest). Successful test runs are a gating requirement for
# considering any change complete -- see ToDo.md. Run with: ctest --test-dir <build>
# ---------------------------------------------------------------------------
if(PEELF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Cross-architecture fixture matrix.
#
# The checked-in bin-matrix/ artifacts keep normal builds and tests independent
# from Docker. These opt-in helpers rebuild the cross-compiler image, refresh
# bin-matrix/, and can run the focused parser/entry/call-graph matrix test.
# ---------------------------------------------------------------------------
find_program(PEELF_DOCKER_EXE NAMES docker)
if(PEELF_DOCKER_EXE)
    add_custom_target(bin-matrix-docker-image
        COMMAND ${PEELF_DOCKER_EXE} build
                -f ${CMAKE_SOURCE_DIR}/docker/Dockerfile.clang
                -t ${PEELF_BIN_MATRIX_DOCKER_IMAGE}
                ${CMAKE_SOURCE_DIR}
        COMMENT "Building Docker image for cross-architecture bin-matrix generation"
        VERBATIM)

    add_custom_target(generate-bin-matrix
        COMMAND ${PEELF_DOCKER_EXE} run --rm
                -v ${CMAKE_SOURCE_DIR}:/workspace/exe_viewer
                -w /workspace/exe_viewer
                ${PEELF_BIN_MATRIX_DOCKER_IMAGE}
                bash tests/fixtures/build_cross_callgraph_fixtures.sh
        DEPENDS bin-matrix-docker-image
        COMMENT "Generating cross-architecture ELF/debug fixtures into bin-matrix/"
        VERBATIM)

    add_custom_target(test-bin-matrix
        COMMAND ${CMAKE_COMMAND}
                -D BUILD_DIR=${CMAKE_BINARY_DIR}
                -D CONFIG=$<CONFIG>
                -P ${CMAKE_SOURCE_DIR}/cmake/RunBinMatrixTests.cmake
        COMMENT "Refreshing bin-matrix/ and running focused bin-matrix parser/call-graph tests"
        VERBATIM)

    if(PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST)
        add_test(NAME BinMatrix.GenerateAndRunFocusedTests
            COMMAND ${CMAKE_COMMAND}
                    -D BUILD_DIR=${CMAKE_BINARY_DIR}
                    -D CONFIG=$<CONFIG>
                    -P ${CMAKE_SOURCE_DIR}/cmake/RunBinMatrixTests.cmake)
    endif()
elseif(PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST)
    message(FATAL_ERROR "PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST=ON but docker was not found")
endif()

# ---------------------------------------------------------------------------
# Linting (ToDo.md P0-10): opt-in clang-tidy + clang-format helper targets.
# Config lives in .clang-tidy and .clang-format at the repo root.
#
# clang-tidy is applied per-target (NOT via the global CMAKE_CXX_CLANG_TIDY) so
# the FetchContent dependencies are never linted. It requires a Ninja/Makefile
# generator -- the Visual Studio generator ignores CXX_CLANG_TIDY -- so use the
# clang18 presets. This block runs after the targets are defined above.
# ---------------------------------------------------------------------------
if(PEELF_ENABLE_CLANG_TIDY)
    find_program(PEELF_CLANG_TIDY_EXE NAMES clang-tidy)
    if(PEELF_CLANG_TIDY_EXE)
        message(STATUS "clang-tidy enabled: ${PEELF_CLANG_TIDY_EXE}")
        foreach(_tgt peelf_core peelf_viewer peelf_tests)
            if(TARGET ${_tgt})
                set_target_properties(${_tgt} PROPERTIES CXX_CLANG_TIDY "${PEELF_CLANG_TIDY_EXE}")
            endif()
        endforeach()
    else()
        message(WARNING "PEELF_ENABLE_CLANG_TIDY=ON but clang-tidy was not found in PATH")
    endif()
endif()

# clang-format helper targets: `format` (rewrite in place) and `format-check`
# (CI-friendly, fails on diffs, makes no changes). Only our sources are globbed.
find_program(PEELF_CLANG_FORMAT_EXE NAMES clang-format)
if(PEELF_CLANG_FORMAT_EXE)
    file(GLOB_RECURSE PEELF_FORMAT_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/libs/peelf_core/*.cpp
        ${CMAKE_SOURCE_DIR}/libs/peelf_core/*.hpp
        ${CMAKE_SOURCE_DIR}/libs/peelf_core/*.h
        ${CMAKE_SOURCE_DIR}/apps/viewer/*.cpp
        ${CMAKE_SOURCE_DIR}/apps/viewer/*.hpp
        ${CMAKE_SOURCE_DIR}/apps/viewer/*.h
        ${CMAKE_SOURCE_DIR}/tests/*.cpp)
    add_custom_target(format
        COMMAND ${PEELF_CLANG_FORMAT_EXE} -i ${PEELF_FORMAT_SOURCES}
        COMMENT "clang-format: rewriting sources in place"
        VERBATIM)
    add_custom_target(format-check
        COMMAND ${PEELF_CLANG_FORMAT_EXE} --dry-run --Werror ${PEELF_FORMAT_SOURCES}
        COMMENT "clang-format: checking formatting (no changes)"
        VERBATIM)
endif()
