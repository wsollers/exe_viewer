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
)

target_compile_features(peelf_tests PRIVATE cxx_std_23)

target_link_libraries(peelf_tests PRIVATE
  peelf::core
  GTest::gtest_main
)

# Absolute path to the test fixtures directory, available to the test code.
target_compile_definitions(peelf_tests PRIVATE
  PEELF_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

# Register every TEST() with CTest so `ctest` discovers and runs them.
gtest_discover_tests(peelf_tests)
