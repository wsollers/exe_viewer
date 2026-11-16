if(PEELF_BUILD_SHARED)
  set(_peelf_core_lib_type SHARED)
else()
  set(_peelf_core_lib_type STATIC)
endif()

file(GLOB_RECURSE PEELF_CORE_ORPHAN_HEADER_CPPS
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/*.cpp"
)
if(PEELF_CORE_ORPHAN_HEADER_CPPS)
  message(FATAL_ERROR
    "Orphan .cpp source files must not reside under libs/peelf_core/include/: ${PEELF_CORE_ORPHAN_HEADER_CPPS}")
endif()

add_library(peelf_core ${_peelf_core_lib_type}
  src/pe/pe_parser.cpp
  src/elf/elf_parser.cpp
  src/file_reader.cpp
  src/sha256.cpp
  src/endian_reader.cpp
  src/image_internal.hpp
  src/image_mapping.cpp
  src/pe_image.cpp
  src/elf_image.cpp
  src/binary_image.cpp
  src/binary_diff.cpp
  src/dependency_tree.cpp
  src/demangle.cpp
  src/dwarf.cpp
  src/subprocess.cpp
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
  src/security_audit.cpp
  src/crash_dump_minidump.cpp
  src/crash_dump_elf_core.cpp
  src/debugger_common.cpp
  src/debugger_linux.cpp
  src/debugger_win32.cpp
  src/provenance.cpp
  src/capability_matrix.cpp
  src/executable_settings.cpp
  src/process_snapshot.cpp
  include/elf/elf_definitions.h
  include/pe/pe_definitions.h
  include/peelf/peelf.hpp
  include/peelf/error.hpp
  include/peelf/sha256.hpp
  include/peelf/forgiving.hpp
  include/peelf/provenance.hpp
  include/peelf/capability_matrix.hpp
  include/peelf/capabilities.hpp
  include/peelf/executable_settings.hpp
  include/peelf/executable_overview.hpp
  include/peelf/process_snapshot.hpp
  include/peelf/endian_reader.hpp
  include/peelf/binary_image.hpp
  include/peelf/binary_diff.hpp
  include/peelf/dependency_tree.hpp
  include/peelf/demangle.hpp
  include/peelf/dwarf.hpp
  include/peelf/subprocess.hpp
  include/peelf/assembler.hpp
  include/peelf/patching.hpp
  include/peelf/patch_bundle.hpp
  include/peelf/process.hpp
  include/peelf/process_internals.hpp
  include/peelf/stack_tls.hpp
  include/peelf/memory_search.hpp
  include/peelf/runtime_structures.hpp
  include/peelf/handlers.hpp
  include/peelf/security_audit.hpp
  include/peelf/crash_dump.hpp
  include/peelf/debugger.hpp
  include/mapping/file_mapping.hpp
  src/mapping/map_errors.cpp
  src/mapping/file_mapping_posix.cpp
  src/mapping/file_mapping_win32.cpp
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

set_target_properties(peelf_core PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)

if(PEELF_BUILD_SHARED)
  set_target_properties(peelf_core PROPERTIES
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
  target_link_libraries(peelf_core PRIVATE ws2_32 advapi32 wintrust crypt32)
endif()
