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
  src/launcher.cpp
  src/headless_cli.hpp
  src/headless_cli.cpp
)
target_include_directories(peelf_viewer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
  enable_language(RC)
  target_sources(peelf_viewer PRIVATE resources/branding.rc)
  target_include_directories(peelf_viewer PRIVATE resources)
endif()
target_compile_features(peelf_viewer PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_viewer)
target_link_libraries(peelf_viewer PRIVATE peelf::core ${CMAKE_DL_LIBS})
if(WIN32 AND PEELF_BUILD_SHARED)
  add_custom_command(TARGET peelf_viewer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:peelf_core>
      $<TARGET_FILE_DIR:peelf_viewer>
  )
endif()
if(NOT PEELF_BUILD_GUI)
  return()
endif()
add_library(peelf_gui SHARED
  src/ui/startup_branding.cpp
  src/gui_entry.cpp
        src/crash/crash_handler.hpp
        src/crash/crash_handler.cpp
        src/application.h
        src/application.cpp
        src/vulkan/vulkan_manager.h
        src/vulkan/vulkan_manager.cpp
        src/vulkan/viewport_camera_2d.cpp
        src/vulkan/gpu_offscreen_canvas.cpp
        src/model/binary_model.hpp
        src/model/binary_model_internal.hpp
        src/model/binary_model.cpp
        src/model/binary_model_live.cpp
        src/ui/ui_panel.hpp
        src/ui/ui_panels.hpp
        src/ui/workspace_layout.hpp
        src/ui/workspace_layout.cpp
        src/ui/panel_helpers.hpp
        src/ui/panel_helpers.cpp
        src/ui/context_actions.hpp
        src/ui/context_actions.cpp
        src/ui/ui_context_menu.hpp
        src/ui/ui_context_menu.cpp
        src/ui/ui_app.hpp
        src/ui/ui_app_internal.hpp
        src/ui/ui_app.cpp
        src/ui/ui_app_project.cpp
        src/ui/ui_app_menus_docking.cpp
        src/ui/ui_app_process.cpp
        src/ui/ui_app_graph.cpp
        src/ui/ui_app_navigation.cpp
        src/ui/ui_panels_file.cpp
        src/ui/ui_panels_memmap.cpp
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
        src/ui/ui_panels_functions.cpp
        src/ui/ui_panels_threads.cpp
        src/ui/ui_panels_search.cpp
        src/ui/ui_panels_runtime.cpp
        src/ui/ui_panels_handlers.cpp
        src/ui/ui_panels_references.cpp
        src/ui/ui_panels_strings.hpp
        src/ui/ui_panels_strings.cpp
        src/ui/ui_panels_struct_view.hpp
        src/ui/ui_panels_struct_view.cpp
        src/ui/ui_panels_process_internals.hpp
        src/ui/ui_panels_process_internals.cpp
        src/ui/ui_panels_dependencies.hpp
        src/ui/ui_panels_dependencies.cpp
        src/ui/ui_panels_diff.hpp
        src/ui/ui_panels_diff.cpp
        src/ui/ui_panels_debugger.hpp
        src/ui/ui_panels_debugger.cpp
        src/ui/ui_panels_capabilities.hpp
        src/ui/ui_panels_capabilities.cpp
        src/ui/ui_panels_settings_overview.hpp
        src/ui/ui_panels_settings_overview.cpp
        src/ui/ui_panels_timeline.hpp
        src/ui/ui_panels_timeline.cpp
        src/ui/ui_panels_scripting.hpp
        src/ui/ui_panels_scripting.cpp
        src/ui/ui_panels_memory_heatmap.hpp
        src/ui/ui_panels_memory_heatmap.cpp
        src/vulkan/shaders/memory_heatmap_comp_spirv.hpp
        src/analysis/async_binary_diff.hpp
        src/analysis/async_binary_diff.cpp
        src/analysis/function_index.hpp
        src/analysis/function_index.cpp
        src/analysis/reference_index.cpp
        src/analysis/strings_index.hpp
        src/analysis/strings_index.cpp
        src/analysis/structure_interpreter.hpp
        src/analysis/structure_interpreter.cpp
        src/analysis/patch_preview.cpp
        src/analysis/project.cpp
        src/decompile/decompiler.cpp
        src/decompile/decompile_controller.hpp
        src/decompile/decompile_controller.cpp
        src/decompile/structured_decompiler.hpp
        src/decompile/structured_decompiler.cpp
        src/decompile/ghidra_decompiler.cpp
        src/decompile/decompiler_symbols.cpp
        src/ui/ui_decompile.cpp
        src/ui/ui_panels_log.cpp
        src/ui/ui_panels_shellcode.cpp
        src/ui/ui_panels_patch_set.cpp
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
        src/graph/call_graph_internal.hpp
        src/graph/call_graph_dot.cpp
        src/graph/call_graph_build.cpp
        src/graph/call_graph_cfg.cpp
        src/symbols/symbol_index.hpp
        src/symbols/symbol_index.cpp
        src/symbols/debug_symbols.hpp
        src/symbols/debug_symbols.cpp
        src/disasm/disassembler.hpp
)

target_include_directories(peelf_gui PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(peelf_gui PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_gui)
add_dependencies(peelf_viewer peelf_gui)
add_custom_target(peelf_viewer_resources ALL
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${CMAKE_CURRENT_SOURCE_DIR}/resources" "$<TARGET_FILE_DIR:peelf_gui>/resources")
add_dependencies(peelf_viewer peelf_viewer_resources)

target_link_libraries(peelf_gui PRIVATE
        peelf::core
        glfw
        imgui
        Vulkan::Vulkan
        nfd
        capstone
        peelf::graphviz
        peelf::asmtk
)

if(WIN32)
  target_link_libraries(peelf_gui PRIVATE gdiplus ole32)
endif()

if(MSVC)
  target_link_libraries(peelf_gui PRIVATE Dbghelp)

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
    target_include_directories(peelf_gui PRIVATE ${PEELF_DIA_INCLUDE_DIR})
    target_link_libraries(peelf_gui PRIVATE ${PEELF_DIA_GUIDS_LIBRARY} ole32 oleaut32)
    target_compile_definitions(peelf_gui PRIVATE PEELF_HAS_DIA=1)
    if(PEELF_DIA_DLL)
      file(TO_CMAKE_PATH "${PEELF_DIA_DLL}" PEELF_DIA_DLL_NORMALIZED)
      target_compile_definitions(peelf_gui PRIVATE PEELF_DIA_DLL_PATH="${PEELF_DIA_DLL_NORMALIZED}")
    endif()
  endif()
endif()
