# A fresh directory proves that the launcher has no load-time GUI dependency.
file(MAKE_DIRECTORY "${TEST_DIR}")
file(COPY "${LAUNCHER}" DESTINATION "${TEST_DIR}")
get_filename_component(name "${LAUNCHER}" NAME)
foreach(argument IN ITEMS "--headless" "")
  execute_process(COMMAND "${TEST_DIR}/${name}" ${argument}
    RESULT_VARIABLE result ERROR_VARIABLE diagnostic TIMEOUT 10)
  if(NOT result STREQUAL "0")
    message(FATAL_ERROR "Isolated launcher failed: ${result}: ${diagnostic}")
  endif()
endforeach()
