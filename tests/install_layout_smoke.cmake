# End-to-end CMake install() layout & relocatable runtime smoke test (WU-45).
foreach(_req IN ITEMS BUILD_DIR STAGE_DIR FIXTURE_BIN EXPECT_VERSION INSTALL_LIBDIR INSTALL_DATADIR INSTALL_DOCDIR)
  if(NOT DEFINED ${_req} OR "${${_req}}" STREQUAL "")
    message(FATAL_ERROR "install_layout_smoke.cmake missing required variable: ${_req}")
  endif()
endforeach()

file(REMOVE_RECURSE "${STAGE_DIR}")

set(_install_cmd "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${STAGE_DIR}")
if(DEFINED BUILD_CONFIG AND NOT "${BUILD_CONFIG}" STREQUAL "")
  list(APPEND _install_cmd --config "${BUILD_CONFIG}")
endif()

execute_process(
  COMMAND ${_install_cmd}
  RESULT_VARIABLE _install_rc
  OUTPUT_VARIABLE _install_out
  ERROR_VARIABLE _install_err
  TIMEOUT 60
)
if(NOT _install_rc STREQUAL "0")
  message(FATAL_ERROR "cmake --install failed (${_install_rc}):\n${_install_out}\n${_install_err}")
endif()

if(WIN32)
  set(_viewer_exe "${STAGE_DIR}/bin/peelf_viewer.exe")
  set(_gui_mod "${STAGE_DIR}/bin/peelf_gui.dll")
  set(_core_mod "${STAGE_DIR}/bin/peelf_core.dll")
  set(_res_dir "${STAGE_DIR}/bin/resources")
elseif(APPLE)
  set(_viewer_exe "${STAGE_DIR}/bin/peelf_viewer")
  set(_gui_mod "${STAGE_DIR}/${INSTALL_LIBDIR}/libpeelf_gui.dylib")
  set(_core_mod "${STAGE_DIR}/${INSTALL_LIBDIR}/libpeelf_core.dylib")
  set(_res_dir "${STAGE_DIR}/${INSTALL_DATADIR}/peelf_explorer/resources")
else()
  set(_viewer_exe "${STAGE_DIR}/bin/peelf_viewer")
  set(_gui_mod "${STAGE_DIR}/${INSTALL_LIBDIR}/libpeelf_gui.so")
  set(_core_mod "${STAGE_DIR}/${INSTALL_LIBDIR}/libpeelf_core.so")
  set(_res_dir "${STAGE_DIR}/${INSTALL_DATADIR}/peelf_explorer/resources")
endif()

if(NOT EXISTS "${_viewer_exe}")
  message(FATAL_ERROR "Installed viewer executable missing: ${_viewer_exe}")
endif()

if(EXPECT_GUI AND NOT EXISTS "${_gui_mod}")
  message(FATAL_ERROR "Installed GUI module missing: ${_gui_mod}")
endif()

if(EXPECT_SHARED_CORE AND NOT EXISTS "${_core_mod}")
  message(FATAL_ERROR "Installed shared core library missing: ${_core_mod}")
endif()

foreach(_res_file IN ITEMS theme.ini bn_decompile.py PeelfDecompile.java viewer.ico splash.png)
  if(NOT EXISTS "${_res_dir}/${_res_file}")
    message(FATAL_ERROR "Installed resource missing: ${_res_dir}/${_res_file}")
  endif()
endforeach()

foreach(_doc_file IN ITEMS README.md LICENSE USER_GUIDE.md ARCHITECTURE.md)
  if(NOT EXISTS "${STAGE_DIR}/${INSTALL_DOCDIR}/${_doc_file}")
    message(FATAL_ERROR "Installed documentation file missing: ${STAGE_DIR}/${INSTALL_DOCDIR}/${_doc_file}")
  endif()
endforeach()

file(GLOB_RECURSE _leaked_third_party
  "${STAGE_DIR}/*gtest*"
  "${STAGE_DIR}/*gmock*"
  "${STAGE_DIR}/*capstone*"
)
if(_leaked_third_party)
  message(FATAL_ERROR "Third-party FetchContent artifacts leaked into install tree: ${_leaked_third_party}")
endif()

# Verify --version output from a neutral working directory without build-tree paths.
execute_process(
  COMMAND "${_viewer_exe}" --version
  WORKING_DIRECTORY "${STAGE_DIR}"
  RESULT_VARIABLE _ver_rc
  OUTPUT_VARIABLE _ver_out
  ERROR_VARIABLE _ver_err
  TIMEOUT 15
)
string(STRIP "${_ver_out}" _ver_out_stripped)
if(NOT _ver_rc STREQUAL "0" OR NOT _ver_out_stripped STREQUAL "peelf_viewer ${EXPECT_VERSION}")
  message(FATAL_ERROR "Installed --version check failed (rc=${_ver_rc}): stdout='${_ver_out_stripped}' stderr='${_ver_err}'")
endif()

# Verify --headless --summary against a lightweight static binary fixture.
execute_process(
  COMMAND "${_viewer_exe}" --headless --summary "${FIXTURE_BIN}"
  WORKING_DIRECTORY "${STAGE_DIR}"
  RESULT_VARIABLE _sum_rc
  OUTPUT_VARIABLE _sum_out
  ERROR_VARIABLE _sum_err
  TIMEOUT 120
)
string(STRIP "${_sum_out}" _sum_out_stripped)
if(NOT _sum_rc STREQUAL "0" OR _sum_out_stripped STREQUAL "")
  message(FATAL_ERROR "Installed --headless --summary failed (rc=${_sum_rc}): stdout='${_sum_out_stripped}' stderr='${_sum_err}'")
endif()

file(REMOVE_RECURSE "${STAGE_DIR}")
