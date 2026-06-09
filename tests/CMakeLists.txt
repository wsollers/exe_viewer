# Unit tests for peelf_explorer (GoogleTest).
#
# Build is gated by the top-level PEELF_BUILD_TESTS option (ON by default).
# Run from a configured build directory with:
#     ctest --output-on-failure
#
# Per project policy (see ToDo.md), every feature -- current and new -- must be
# covered by tests here, and a green `ctest` run is required before a change is
# considered complete.

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.15.2
  GIT_SHALLOW    TRUE
)

# Keep MSVC from mismatching the C runtime against the rest of the project.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_executable(peelf_tests
  smoke_test.cpp
  file_mapping_test.cpp
  peelf_core_test.cpp
  parsers_test.cpp
  binary_image_test.cpp
  disassembler_test.cpp
  viewer_navigation_test.cpp
  call_graph_test.cpp
  symbol_index_test.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/navigation/viewer_navigation.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/graph/call_graph.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/symbols/symbol_index.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/symbols/debug_symbols.cpp
)

target_compile_features(peelf_tests PRIVATE cxx_std_23)

target_link_libraries(peelf_tests PRIVATE
  peelf::core
  capstone
  peelf::graphviz
  GTest::gtest_main
)

target_include_directories(peelf_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/apps/viewer/src
)

if(MSVC)
  find_path(PEELF_DIA_INCLUDE_DIR dia2.h
    PATHS
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/DIA SDK/include"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK/include"
  )
  find_library(PEELF_DIA_GUIDS_LIBRARY diaguids
    PATHS
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/DIA SDK/lib/amd64"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK/lib/amd64"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/DIA SDK/lib"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK/lib"
  )
  if(PEELF_DIA_INCLUDE_DIR AND PEELF_DIA_GUIDS_LIBRARY)
    target_include_directories(peelf_tests PRIVATE ${PEELF_DIA_INCLUDE_DIR})
    target_link_libraries(peelf_tests PRIVATE ${PEELF_DIA_GUIDS_LIBRARY} ole32 oleaut32)
    target_compile_definitions(peelf_tests PRIVATE PEELF_HAS_DIA=1)
  endif()
endif()

# Absolute path to the test fixtures directory, available to the test code.
target_compile_definitions(peelf_tests PRIVATE
  PEELF_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

# Register every TEST() with CTest so `ctest` discovers and runs them.
gtest_discover_tests(peelf_tests)
