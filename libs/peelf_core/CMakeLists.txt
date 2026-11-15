add_library(peelf_core
  src/pe/pe_parser.cpp
  src/elf/elf_parser.cpp
  src/file_reader.cpp
  src/sha256.cpp
  src/endian_reader.cpp
  src/binary_image.cpp
  src/binary_diff.cpp
  src/dependency_tree.cpp
  src/demangle.cpp
  src/dwarf.cpp
  src/assembler.cpp
  src/patching.cpp
  src/patch_bundle.cpp
  src/process_common.cpp
  src/process_linux.cpp
  src/process_win32.cpp
  src/process_internals_common.cpp
  src/process_internals_linux.cpp
  src/process_internals_win32.cpp
  src/stack_tls.cpp
  src/memory_search.cpp
  src/runtime_structures.cpp
  src/handlers.cpp
  include/elf/elf_definitions.h
  include/pe/pe_definitions.h
  include/peelf/peelf.hpp
  include/peelf/error.hpp
  include/peelf/sha256.hpp
  include/peelf/forgiving.hpp
  include/peelf/endian_reader.hpp
  include/peelf/binary_image.hpp
  include/peelf/binary_diff.hpp
  include/peelf/dependency_tree.hpp
  include/peelf/demangle.hpp
  include/peelf/dwarf.hpp
  include/peelf/assembler.hpp
  include/peelf/patching.hpp
  include/peelf/patch_bundle.hpp
  include/peelf/process.hpp
  include/peelf/process_internals.hpp
  include/peelf/stack_tls.hpp
  include/peelf/memory_search.hpp
  include/peelf/runtime_structures.hpp
  include/peelf/handlers.hpp
  include/mapping/file_mapping.hpp
  src/mapping/map_errors.cpp
  src/mapping/file_mapping_posix.cpp
  src/mapping/file_mapping_win32.cpp
  include/pe/pe_parser.h
)

add_library(peelf::core ALIAS peelf_core)

target_include_directories(peelf_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(peelf_core PUBLIC cxx_std_23)

target_link_libraries(peelf_core PRIVATE peelf::asmtk)

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

if(WIN32)
  target_link_libraries(peelf_core PRIVATE ws2_32 advapi32)
endif()
