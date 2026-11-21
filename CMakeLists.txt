cmake_minimum_required(VERSION 3.25)

project(peelf_explorer
  VERSION 1.0.0
  DESCRIPTION "PE/ELF executable viewer (core parser + Vulkan/GLFW/ImGui GUI)"
  LANGUAGES C CXX
)

# Prevent FetchContent from re-running
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
option(PEELF_BUILD_VIEWER "Build the viewer launcher" ON)
option(PEELF_BUILD_GUI "Build the optional GUI module" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
option(PEELF_ENABLE_GRAPHVIZ "Fetch optional Graphviz source and enable Graphviz-backed graph rendering hooks" OFF)
option(PEELF_ENABLE_ASMTK "Fetch and build AsmJit plus AsmTK for optional assembly-to-bytes providers" ON)
include(third_party/dependencies.cmake)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_FLAGS MATCHES "-stdlib=libc\\+\\+")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fexperimental-library>)
  add_link_options(-fexperimental-library)
endif()

if(MSVC)
  # Prevent C1041 vc14x.pdb write contention across parallel C/C++ compilations
  # (including FetchContent dependencies built under Ninja/MSBuild).
  add_compile_options(/FS)
endif()

option(PEELF_WARNINGS_AS_ERRORS "Treat warnings as errors on peelf project targets" ON)
option(PEELF_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(PEELF_ENABLE_FUZZERS "Build Clang libFuzzer + ASan + UBSan parser harnesses" OFF)
if(PEELF_ENABLE_FUZZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
    "PEELF_ENABLE_FUZZERS=ON requires a Clang compiler for libFuzzer + SanitizerCoverage instrumentation (detected '${CMAKE_CXX_COMPILER_ID}').")
endif()

include(cmake/ProjectOptions.cmake)  # <-- Add here, once

if(WIN32)
  set(_peelf_default_shared OFF)
else()
  set(_peelf_default_shared ON)
endif()
option(PEELF_BUILD_VIEWER "Build the GUI viewer application" ON)
option(PEELF_BUILD_SHARED "Build peelf_core as a shared library" ${_peelf_default_shared})
option(PEELF_BUILD_TESTS "Build unit tests (GoogleTest)" ON)
option(PEELF_ENABLE_CLANG_TIDY "Run clang-tidy on peelf targets during build (Ninja/Makefile generators only)" OFF)
option(PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST "Register the Docker-backed bin-matrix refresh test with CTest" OFF)
option(PEELF_ENABLE_BINARY_NINJA_SDK "Experimental opt-in check for local Binary Ninja C++ SDK headers/core library (never required)" OFF)
option(PEELF_ENABLE_BINARY_NINJA_TESTS "Register opt-in Binary Ninja integration CTests when Binary Ninja is installed (never required in CI)" OFF)
option(PEELF_INSTALL_DIA_REDIST "Opt-in installation of msdia140.dll alongside Windows viewer runtime (subject to Microsoft DIA redistributable license)" OFF)

if(PEELF_ENABLE_BINARY_NINJA_SDK)
  set(BN_SDK_DIR "" CACHE PATH "Optional path to Vector 35 binaryninja-api C++ SDK checkout")
  set(BN_INSTALL_DIR "" CACHE PATH "Optional path to local Binary Ninja installation containing binaryninjacore")
  find_path(PEELF_BN_SDK_INCLUDE_DIR
    NAMES binaryninjacore.h
    HINTS
      "${BN_SDK_DIR}"
      "$ENV{BN_SDK_DIR}"
    PATH_SUFFIXES include ""
  )
  find_library(PEELF_BN_CORE_LIBRARY
    NAMES binaryninjacore binaryninjacore.1
    HINTS
      "${BN_INSTALL_DIR}"
      "$ENV{BN_INSTALL_DIR}"
      "$ENV{BINARYNINJA_HOME}"
      "/opt/binaryninja"
      "$ENV{HOME}/binaryninja"
      "$ENV{LOCALAPPDATA}/Vector35/BinaryNinja"
      "$ENV{ProgramFiles}/Vector35/BinaryNinja"
      "/Applications/Binary Ninja.app/Contents/MacOS"
  )
  if(PEELF_BN_SDK_INCLUDE_DIR AND PEELF_BN_CORE_LIBRARY)
    set(PEELF_BINARY_NINJA_SDK_FOUND TRUE)
    add_library(peelf_binary_ninja_sdk INTERFACE)
    target_include_directories(peelf_binary_ninja_sdk SYSTEM INTERFACE "${PEELF_BN_SDK_INCLUDE_DIR}")
    target_link_libraries(peelf_binary_ninja_sdk INTERFACE "${PEELF_BN_CORE_LIBRARY}")
    message(STATUS "Binary Ninja C++ SDK detected (opt-in evaluation): headers=${PEELF_BN_SDK_INCLUDE_DIR}, core=${PEELF_BN_CORE_LIBRARY}")
  else()
    set(PEELF_BINARY_NINJA_SDK_FOUND FALSE)
    message(WARNING
      "PEELF_ENABLE_BINARY_NINJA_SDK=ON, but binaryninjacore.h or binaryninjacore library was not found "
      "(set -DBN_SDK_DIR=<binaryninja-api> and -DBN_INSTALL_DIR=<BinaryNinja>). "
      "Continuing with the process-isolated bn_decompile.py Python bridge.")
  endif()
endif()

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

if(PEELF_ENABLE_FUZZERS)
  add_subdirectory(tests/fuzz)
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
    find_program(PEELF_CLANG_TIDY_EXE NAMES clang-tidy-18 clang-tidy)
    if(PEELF_CLANG_TIDY_EXE)
        message(STATUS "clang-tidy enabled: ${PEELF_CLANG_TIDY_EXE}")
        foreach(_tgt peelf_core peelf_gui peelf_viewer)
            if(TARGET ${_tgt})
                set_target_properties(${_tgt} PROPERTIES CXX_CLANG_TIDY "${PEELF_CLANG_TIDY_EXE}")
            endif()
        endforeach()
    else()
        message(WARNING "PEELF_ENABLE_CLANG_TIDY=ON but clang-tidy was not found in PATH")
    endif()
endif()

find_program(PEELF_RUN_CLANG_TIDY_EXE NAMES run-clang-tidy-18 run-clang-tidy)
if(PEELF_RUN_CLANG_TIDY_EXE AND CMAKE_EXPORT_COMPILE_COMMANDS)
    add_custom_target(clang-tidy
        COMMAND ${PEELF_RUN_CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR} -quiet
                libs/peelf_core apps/viewer
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "clang-tidy: checking first-party sources under libs/peelf_core and apps/viewer"
        VERBATIM)
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
        ${CMAKE_SOURCE_DIR}/tests/*.cpp
        ${CMAKE_SOURCE_DIR}/tests/fuzz/*.hpp)
    add_custom_target(format
        COMMAND ${PEELF_CLANG_FORMAT_EXE} -i ${PEELF_FORMAT_SOURCES}
        COMMENT "clang-format: rewriting sources in place"
        VERBATIM)
    add_custom_target(format-check
        COMMAND ${PEELF_CLANG_FORMAT_EXE} --dry-run --Werror ${PEELF_FORMAT_SOURCES}
        COMMENT "clang-format: checking formatting (no changes)"
        VERBATIM)
endif()

# ---------------------------------------------------------------------------
# Installation & CPack portable distribution archives (WU-45).
# ---------------------------------------------------------------------------
install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
  "${CMAKE_CURRENT_SOURCE_DIR}/docs/USER_GUIDE.md"
  "${CMAKE_CURRENT_SOURCE_DIR}/docs/ARCHITECTURE.md"
  DESTINATION "${CMAKE_INSTALL_DOCDIR}"
  COMPONENT runtime
)

set(CPACK_PACKAGE_NAME "peelf-explorer")
set(CPACK_PACKAGE_VENDOR "wsollers")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
if(WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CPACK_SYSTEM_NAME "windows-x64")
  else()
    set(CPACK_SYSTEM_NAME "windows-x86")
  endif()
  set(CPACK_GENERATOR "ZIP")
elseif(APPLE)
  set(CPACK_SYSTEM_NAME "macos-${CMAKE_SYSTEM_PROCESSOR}")
  set(CPACK_GENERATOR "TGZ")
else()
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" _peelf_os_lower)
  set(CPACK_SYSTEM_NAME "${_peelf_os_lower}-${CMAKE_SYSTEM_PROCESSOR}")
  set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
