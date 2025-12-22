cmake_minimum_required(VERSION 3.25)

project(peelf_explorer
  VERSION 0.0.1
  DESCRIPTION "PE/ELF executable viewer (core parser + Vulkan/GLFW/ImGui GUI)"
  LANGUAGES CXX
)

# Prevent FetchContent from re-running
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
include(third_party/dependencies.cmake)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/ProjectOptions.cmake)  # <-- Add here, once

option(PEELF_BUILD_VIEWER "Build the GUI viewer application" ON)
option(PEELF_BUILD_SHARED "Build peelf_core as a shared library" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)



add_subdirectory(libs/peelf_core)

if(PEELF_BUILD_VIEWER)
  add_subdirectory(apps/viewer)
endif()
