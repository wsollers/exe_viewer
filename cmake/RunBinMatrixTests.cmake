if(NOT DEFINED BUILD_DIR OR BUILD_DIR STREQUAL "")
    message(FATAL_ERROR "BUILD_DIR is required")
endif()

if(NOT DEFINED CONFIG)
    set(CONFIG "")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${BUILD_DIR}" --target generate-bin-matrix
    RESULT_VARIABLE generate_result
)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "generate-bin-matrix failed with exit code ${generate_result}")
endif()

set(ctest_command
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${BUILD_DIR}"
    --output-on-failure
    -R "^CallGraph\\.BinMatrixFixturesParseEntryAndKnownCallGraphsAcrossArchitectures$"
)
if(NOT CONFIG STREQUAL "")
    list(APPEND ctest_command --build-config "${CONFIG}")
endif()

execute_process(
    COMMAND ${ctest_command}
    RESULT_VARIABLE test_result
)
if(NOT test_result EQUAL 0)
    message(FATAL_ERROR "bin-matrix focused CTest failed with exit code ${test_result}")
endif()
