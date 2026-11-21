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

# Keep MSVC from mismatching the C runtime against the rest of the project,
# and prevent GoogleTest from polluting cmake --install / CPack archives.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_executable(peelf_callgraph_fixture
  fixtures/callgraph_debug_fixture.cpp
)
target_compile_features(peelf_callgraph_fixture PRIVATE cxx_std_23)
if(MSVC)
  target_compile_options(peelf_callgraph_fixture PRIVATE /Od /Ob0 /Zi /FS)
  target_link_options(peelf_callgraph_fixture PRIVATE /DEBUG /INCREMENTAL:NO)
  set(PEELF_CALLGRAPH_FIXTURE_PDB_PATH "$<TARGET_PDB_FILE:peelf_callgraph_fixture>")
else()
  target_compile_options(peelf_callgraph_fixture PRIVATE -O0 -g -fno-inline)
  set(PEELF_CALLGRAPH_FIXTURE_PDB_PATH "")
endif()

add_executable(peelf_tests
  theme_resource_test.cpp
  smoke_test.cpp
  file_mapping_test.cpp
  peelf_core_test.cpp
  sha256_test.cpp
  parsers_test.cpp
  binary_image_test.cpp
  macho_image_test.cpp
  macho_audit_integration_test.cpp
  disassembler_test.cpp
  viewer_navigation_test.cpp
  patch_navigation_test.cpp
  call_graph_test.cpp
  symbol_index_test.cpp
  pdb_parser_test.cpp
  reference_index_test.cpp
  strings_index_test.cpp
  demangle_dwarf_test.cpp
  structure_interpreter_test.cpp
  vmmap_explorer_test.cpp
  process_internals_test.cpp
  analysis_project_test.cpp
  dependency_tree_test.cpp
  binary_diff_test.cpp
  security_headless_test.cpp
  crash_dump_test.cpp
  debugger_test.cpp
  decompiler_test.cpp
  recent_binaries_test.cpp
  shellcode_converter_test.cpp
  subprocess_test.cpp
  assembler_dependency_test.cpp
  assembler_patch_bundle_test.cpp
  patching_test.cpp
  binary_model_patch_test.cpp
  process_memmap_test.cpp
  live_process_self_test.cpp
  multiarch_subsystems_test.cpp
  live_child_inspection_test.cpp
  review_bugs_regression_test.cpp
  malformed_inputs_matrix_test.cpp
  capability_provenance_test.cpp
  executable_settings_test.cpp
  process_snapshot_test.cpp
  execution_timeline_test.cpp
  gdb_remote_rsp_test.cpp
  gdb_remote_debug_test.cpp
  workspace_context_actions_test.cpp
  scripting_test.cpp
  ui_panel_helpers_test.cpp
  vulkan_viewport_test.cpp
  memory_heatmap_test.cpp
  byte_viz_test.cpp
  timeline_viewport_test.cpp
  call_graph_galaxy_test.cpp
  linear_disassembly_test.cpp
  command_palette_test.cpp
  c_type_parser_test.cpp
  signatures_and_crypto_test.cpp
  macho_core_and_dsym_test.cpp
  decompiler_contract_test.cpp
  golden_summary_and_debug_test.cpp
  runtime_paths_and_version_test.cpp
  fuzz_corpus_regression_test.cpp
  fuzz/fuzz_binary_image.cpp
  fuzz/fuzz_debug_formats.cpp
  fuzz/fuzz_crash_dumps.cpp
  fuzz/fuzz_parsers_dsl.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/headless_cli.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/runtime_paths.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/disasm/linear_disassembly.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/vulkan/viewport_camera_2d.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/navigation/viewer_navigation.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/ui/command_palette.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/ui/workspace_layout.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/ui/panel_helpers.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/ui/context_actions.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/ui/logger.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/graph/call_graph_dot.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/graph/call_graph_build.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/graph/call_graph_cfg.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/graph/call_graph_galaxy.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/symbols/symbol_index.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/async_binary_diff.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/function_index.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/reference_index.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/strings_index.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/c_type_parser.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/structure_interpreter.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/patch_preview.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/project.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/decompiler.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/decompile_controller.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/structured_decompiler.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/ghidra_decompiler.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/decompiler_symbols.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/symbols/debug_symbols.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/model/binary_model.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/model/binary_model_live.cpp
  ${CMAKE_SOURCE_DIR}/apps/viewer/src/tools/shellcode_converter.cpp
)

target_compile_features(peelf_tests PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_tests)

target_link_libraries(peelf_tests PRIVATE
  peelf::core
  capstone
  peelf::graphviz
  peelf::asmtk
  GTest::gtest_main
)

target_include_directories(peelf_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/apps/viewer/src
  ${CMAKE_CURRENT_SOURCE_DIR}/fuzz
)

if(MSVC)
  # Keep function pointers equal to PDB function RVAs in the live ASLR self-test.
  # Incremental linking otherwise routes pointers through ILT jump thunks.
  target_link_options(peelf_tests PRIVATE /INCREMENTAL:NO)

  set(_peelf_vs_dia_roots "")
  if(DEFINED ENV{VSINSTALLDIR} AND NOT "$ENV{VSINSTALLDIR}" STREQUAL "")
    list(APPEND _peelf_vs_dia_roots "$ENV{VSINSTALLDIR}")
  endif()
  foreach(_vs_ver IN ITEMS 18 2022)
    foreach(_vs_ed IN ITEMS Enterprise Professional Community BuildTools)
      list(APPEND _peelf_vs_dia_roots "$ENV{ProgramFiles}/Microsoft Visual Studio/${_vs_ver}/${_vs_ed}")
    endforeach()
  endforeach()

  set(_peelf_dia_inc_hints "")
  set(_peelf_dia_lib_hints "")
  set(_peelf_dia_dll_hints "")
  foreach(_root IN LISTS _peelf_vs_dia_roots)
    list(APPEND _peelf_dia_inc_hints "${_root}/DIA SDK/include")
    list(APPEND _peelf_dia_lib_hints "${_root}/DIA SDK/lib/amd64" "${_root}/DIA SDK/lib")
    list(APPEND _peelf_dia_dll_hints "${_root}/DIA SDK/bin/amd64" "${_root}/DIA SDK/bin" "${_root}/Common7/IDE")
  endforeach()

  find_path(PEELF_DIA_INCLUDE_DIR dia2.h PATHS ${_peelf_dia_inc_hints})
  find_library(PEELF_DIA_GUIDS_LIBRARY diaguids PATHS ${_peelf_dia_lib_hints})
  find_file(PEELF_DIA_DLL msdia140.dll PATHS ${_peelf_dia_dll_hints})
  if(PEELF_DIA_INCLUDE_DIR AND PEELF_DIA_GUIDS_LIBRARY)
    target_include_directories(peelf_tests PRIVATE ${PEELF_DIA_INCLUDE_DIR})
    target_link_libraries(peelf_tests PRIVATE ${PEELF_DIA_GUIDS_LIBRARY} ole32 oleaut32)
    target_compile_definitions(peelf_tests PRIVATE PEELF_HAS_DIA=1)
    if(PEELF_DIA_DLL)
      file(TO_CMAKE_PATH "${PEELF_DIA_DLL}" PEELF_DIA_DLL_NORMALIZED)
      target_compile_definitions(peelf_tests PRIVATE PEELF_DIA_DLL_PATH="${PEELF_DIA_DLL_NORMALIZED}")
    endif()
  endif()
endif()

# Absolute path to the test fixtures directory, available to the test code.
target_compile_definitions(peelf_tests PRIVATE
  PEELF_VERSION_STRING="${PROJECT_VERSION}"
  PEELF_INSTALL_LIBDIR="${CMAKE_INSTALL_LIBDIR}"
  PEELF_INSTALL_DATADIR="${CMAKE_INSTALL_DATADIR}"
  PEELF_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  PEELF_BIN_MATRIX_DIR="${CMAKE_SOURCE_DIR}/bin-matrix"
  PEELF_VIEWER_RESOURCES_DIR="${CMAKE_SOURCE_DIR}/apps/viewer/resources"
  PEELF_CALLGRAPH_FIXTURE_EXE="$<TARGET_FILE:peelf_callgraph_fixture>"
  PEELF_CALLGRAPH_FIXTURE_PDB="${PEELF_CALLGRAPH_FIXTURE_PDB_PATH}"
)
if(TARGET peelf_gui)
  target_compile_definitions(peelf_tests PRIVATE
    PEELF_VIEWER_DEBUG_EXE="$<TARGET_FILE:peelf_gui>"
  )
endif()
if(TARGET peelf_gui AND MSVC)
  target_compile_definitions(peelf_tests PRIVATE
    PEELF_VIEWER_DEBUG_PDB="$<TARGET_PDB_FILE:peelf_gui>"
  )
endif()
add_dependencies(peelf_tests peelf_callgraph_fixture)
add_executable(peelf_backend_fixture backend_process_fixture.cpp)
target_compile_features(peelf_backend_fixture PRIVATE cxx_std_23)
add_dependencies(peelf_tests peelf_backend_fixture)
target_compile_definitions(peelf_tests PRIVATE PEELF_BACKEND_FIXTURE="$<TARGET_FILE:peelf_backend_fixture>")

# Register every TEST() with CTest so `ctest` discovers and runs them.
gtest_discover_tests(peelf_tests)
find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  file(TO_CMAKE_PATH "${Python3_EXECUTABLE}" PEELF_PYTHON3_NORMALIZED)
  target_compile_definitions(peelf_tests PRIVATE PEELF_PYTHON3_EXECUTABLE="${PEELF_PYTHON3_NORMALIZED}")
  add_test(NAME Decompiler.PythonBridge
    COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/bn_bridge_test.py)
endif()

if(PEELF_ENABLE_BINARY_NINJA_TESTS)
  add_executable(peelf_binary_ninja_tests
    binary_ninja_integration_test.cpp
    ${CMAKE_SOURCE_DIR}/apps/viewer/src/symbols/symbol_index.cpp
    ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/decompiler.cpp
    ${CMAKE_SOURCE_DIR}/apps/viewer/src/decompile/decompiler_symbols.cpp
  )
  target_compile_features(peelf_binary_ninja_tests PRIVATE cxx_std_23)
  peelf_apply_project_warnings(peelf_binary_ninja_tests)
  target_link_libraries(peelf_binary_ninja_tests PRIVATE
    peelf::core
    GTest::gtest_main
  )
  target_include_directories(peelf_binary_ninja_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/apps/viewer/src
  )
  target_compile_definitions(peelf_binary_ninja_tests PRIVATE
    PEELF_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
    PEELF_BIN_MATRIX_DIR="${CMAKE_SOURCE_DIR}/bin-matrix"
    PEELF_VIEWER_RESOURCES_DIR="${CMAKE_SOURCE_DIR}/apps/viewer/resources"
  )
  if(Python3_Interpreter_FOUND)
    target_compile_definitions(peelf_binary_ninja_tests PRIVATE
      PEELF_PYTHON3_EXECUTABLE="${PEELF_PYTHON3_NORMALIZED}"
    )
  endif()
  if(WIN32 AND PEELF_BUILD_SHARED)
    add_custom_command(TARGET peelf_binary_ninja_tests POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:peelf_core>
        $<TARGET_FILE_DIR:peelf_binary_ninja_tests>
    )
  endif()
  gtest_discover_tests(peelf_binary_ninja_tests PROPERTIES LABELS "binary_ninja_opt_in")
endif()
if(TARGET peelf_viewer)
  target_compile_definitions(peelf_tests PRIVATE
    PEELF_VIEWER_EXECUTABLE_PATH="$<TARGET_FILE:peelf_viewer>"
    PEELF_VIEWER_EXE="$<TARGET_FILE:peelf_viewer>"
  )
  add_dependencies(peelf_tests peelf_viewer)
  if(WIN32 AND PEELF_BUILD_SHARED)
    add_custom_command(TARGET peelf_tests POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:peelf_core>
        $<TARGET_FILE_DIR:peelf_tests>
    )
    set(_peelf_isolated_core_dll_arg "-DCORE_DLL=$<TARGET_FILE:peelf_core>")
  else()
    set(_peelf_isolated_core_dll_arg "")
  endif()
  add_test(NAME Startup.Headless COMMAND $<TARGET_FILE:peelf_viewer> --headless)
  add_test(NAME Startup.Help COMMAND $<TARGET_FILE:peelf_viewer> --help)
  add_test(NAME Startup.Version COMMAND $<TARGET_FILE:peelf_viewer> --version)
  add_test(NAME Headless.FixtureJson
    COMMAND $<TARGET_FILE:peelf_viewer> --headless $<TARGET_FILE:peelf_callgraph_fixture> --format json --output ${CMAKE_CURRENT_BINARY_DIR}/headless_fixture_$<CONFIG>.json)
  add_test(NAME Headless.FixtureSarif
    COMMAND $<TARGET_FILE:peelf_viewer> --headless $<TARGET_FILE:peelf_callgraph_fixture> --format sarif --output ${CMAKE_CURRENT_BINARY_DIR}/headless_fixture_$<CONFIG>.sarif)
  add_test(NAME Startup.WithoutGuiModule COMMAND ${CMAKE_COMMAND}
    -DLAUNCHER=$<TARGET_FILE:peelf_viewer>
    ${_peelf_isolated_core_dll_arg}
    -DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/launcher-isolated-$<CONFIG>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/startup_without_gui.cmake)
  add_test(NAME InstallLayout.Smoke COMMAND ${CMAKE_COMMAND}
    -DBUILD_DIR=${CMAKE_BINARY_DIR}
    -DBUILD_CONFIG=$<CONFIG>
    -DSTAGE_DIR=${CMAKE_CURRENT_BINARY_DIR}/install-smoke-$<CONFIG>
    -DFIXTURE_BIN=${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hello.elf
    -DEXPECT_VERSION=${PROJECT_VERSION}
    -DEXPECT_GUI=$<BOOL:${PEELF_BUILD_GUI}>
    -DEXPECT_SHARED_CORE=$<BOOL:${PEELF_BUILD_SHARED}>
    -DINSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
    -DINSTALL_DATADIR=${CMAKE_INSTALL_DATADIR}
    -DINSTALL_DOCDIR=${CMAKE_INSTALL_DOCDIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/install_layout_smoke.cmake)
endif()
