include(${CMAKE_SOURCE_DIR}/cmake/ProjectOptions.cmake)



# Debug: see what targets exist
if(TARGET Vulkan::Vulkan)
  message(STATUS "Vulkan::Vulkan exists")
endif()
if(TARGET Vulkan::Headers)
  message(STATUS "Vulkan::Headers exists")
endif()
if(TARGET vulkan)
  message(STATUS "vulkan exists")
endif()

add_executable(peelf_viewer
  src/main.cpp
        src/crash/crash_handler.hpp
        src/crash/crash_handler.cpp
        src/application.h
        src/application.cpp
        src/vulkan/vulkan_manager.h
        src/vulkan/vulkan_manager.cpp
        src/model/pe_model.hpp
        src/model/binary_model.hpp
        src/model/pe_parser.cpp
        src/model/pe_parser.hpp
        src/model/binary_model.cpp
        src/ui/ui_panel.hpp
        src/ui/ui_panels.hpp
        src/ui/ui_app.hpp
        src/ui/ui_app.cpp
        src/ui/ui_panels_file.cpp
        src/ui/ui_panels_pe_headers.cpp
        src/ui/ui_panels_pe_imports.cpp
        src/ui/ui_panels_pe_exports.cpp
        src/ui/ui_panels_sections.cpp
        src/ui/ui_panels_structure.cpp
        src/ui/ui_panels_hex.cpp
        src/ui/ui_panels_disasm.cpp
        src/ui/ui_panels_exports.cpp
        src/ui/ui_panels_imports.cpp
        src/ui/ui_panels_symbols.cpp
        src/ui/ui_panels_log.cpp
        src/ui/ui_panels_shellcode.cpp
        src/ui/logger.hpp
        src/ui/logger.cpp
        src/tools/shellcode_converter.hpp
        src/tools/shellcode_converter.cpp
        src/model/pe_machine_types.hpp
        src/model/pe_characteristics.hpp
        src/model/pe_optional_image.hpp
        src/model/pe_subsystem.hpp
        src/model/section_header_characteristics.hpp
        src/model/image_delay_load_descriptor.hpp
        src/navigation/viewer_navigation.hpp
        src/navigation/viewer_navigation.cpp
        src/graph/call_graph.hpp
        src/graph/call_graph.cpp
        src/symbols/symbol_index.hpp
        src/symbols/symbol_index.cpp
        src/symbols/debug_symbols.hpp
        src/symbols/debug_symbols.cpp
        src/disasm/disassembler.hpp
)

target_include_directories(peelf_viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(peelf_viewer PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_viewer)

target_link_libraries(peelf_viewer PRIVATE
        peelf::core
        glfw
        imgui
        Vulkan::Vulkan
        nfd
        capstone
        peelf::graphviz
)

if(MSVC)
  target_link_libraries(peelf_viewer PRIVATE Dbghelp)

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
  find_file(PEELF_DIA_DLL msdia140.dll
    PATHS
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/DIA SDK/bin/amd64"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK/bin/amd64"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/DIA SDK/bin"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK/bin"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/18/Community/Common7/IDE"
      "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/Common7/IDE"
  )
  if(PEELF_DIA_INCLUDE_DIR AND PEELF_DIA_GUIDS_LIBRARY)
    target_include_directories(peelf_viewer PRIVATE ${PEELF_DIA_INCLUDE_DIR})
    target_link_libraries(peelf_viewer PRIVATE ${PEELF_DIA_GUIDS_LIBRARY} ole32 oleaut32)
    target_compile_definitions(peelf_viewer PRIVATE PEELF_HAS_DIA=1)
    if(PEELF_DIA_DLL)
      file(TO_CMAKE_PATH "${PEELF_DIA_DLL}" PEELF_DIA_DLL_NORMALIZED)
      target_compile_definitions(peelf_viewer PRIVATE PEELF_DIA_DLL_PATH="${PEELF_DIA_DLL_NORMALIZED}")
    endif()
  endif()
endif()
