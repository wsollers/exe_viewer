include(${CMAKE_SOURCE_DIR}/cmake/ProjectOptions.cmake)

add_executable(peelf_viewer
  src/main.cpp
  src/gui/app_gui.cpp
  src/gui/imgui_impl_stub.cpp
)

target_compile_features(peelf_viewer PRIVATE cxx_std_23)
peelf_apply_project_warnings(peelf_viewer)

target_link_libraries(peelf_viewer PRIVATE peelf::core)

# ---- third_party: GLFW ----
set(GLFW_DIR "${CMAKE_SOURCE_DIR}/third_party/glfw")
if(EXISTS "${GLFW_DIR}/CMakeLists.txt")
  set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
  set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
  add_subdirectory("${GLFW_DIR}" "${CMAKE_BINARY_DIR}/_deps/glfw-build")
  target_link_libraries(peelf_viewer PRIVATE glfw)
  target_compile_definitions(peelf_viewer PRIVATE PEELF_HAS_GLFW=1)
else()
  message(WARNING "GLFW not found in third_party/glfw. Run scripts/bootstrap_deps.*")
endif()

# ---- third_party: ImGui ----
set(IMGUI_DIR "${CMAKE_SOURCE_DIR}/third_party/imgui")
if(EXISTS "${IMGUI_DIR}/imgui.h")
  target_include_directories(peelf_viewer PRIVATE "${IMGUI_DIR}")
  target_sources(peelf_viewer PRIVATE
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
  )
  target_compile_definitions(peelf_viewer PRIVATE PEELF_HAS_IMGUI=1)
else()
  message(WARNING "ImGui not found in third_party/imgui. Run scripts/bootstrap_deps.*")
endif()

# ---- Vulkan ----
find_package(Vulkan QUIET)
if(Vulkan_FOUND)
  target_link_libraries(peelf_viewer PRIVATE Vulkan::Vulkan)
  target_compile_definitions(peelf_viewer PRIVATE PEELF_HAS_VULKAN=1)
else()
  message(WARNING "Vulkan not found. Install the Vulkan SDK or provide Vulkan in your toolchain.")
endif()
