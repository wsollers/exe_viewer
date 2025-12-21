add_library(peelf_core
  src/pe_parser.cpp
  src/elf_parser.cpp
  src/file_reader.cpp
)

add_library(peelf::core ALIAS peelf_core)

target_include_directories(peelf_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(peelf_core PUBLIC cxx_std_23)

include(${CMAKE_SOURCE_DIR}/cmake/ProjectOptions.cmake)
peelf_apply_project_warnings(peelf_core)

if(PEELF_BUILD_SHARED)
  set_target_properties(peelf_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS ON
  )
endif()

target_compile_definitions(peelf_core PUBLIC
  $<$<BOOL:${PEELF_BUILD_SHARED}>:PEELF_CORE_SHARED=1>
)

if(MSVC)
  target_compile_definitions(peelf_core PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
