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
        src/application.h
        src/application.cpp
        src/vulkan/vulkan_manager.h
        src/vulkan/vulkan_manager.cpp
        src/gui/gui.h
        src/gui/gui.cpp
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
        src/ui/ui_panels_hex.cpp
        src/ui/ui_panels_disasm.cpp
        src/ui/ui_panels_log.cpp
        src/ui/logger.hpp
        src/ui/logger.cpp
        src/model/pe_machine_types.hpp
        src/model/pe_characteristics.hpp
        src/model/pe_optional_image.hpp
        src/model/pe_subsystem.hpp
        src/model/section_header_characteristics.hpp
        src/model/image_delay_load_descriptor.hpp
        src/dissassembler/dissassembler.hpp
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
)

