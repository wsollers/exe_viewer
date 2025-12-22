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
  src/gui/app_gui.cpp
  src/gui/imgui_impl_stub.cpp
)

target_compile_features(peelf_viewer PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_viewer)

target_link_libraries(peelf_viewer PRIVATE peelf::core
        glfw
        imgui
        Vulkan::Headers
)
