set(PEELF_FUZZ_TARGETS
  fuzz_binary_image
  fuzz_debug_formats
  fuzz_crash_dumps
  fuzz_parsers_dsl
)

foreach(fuzz_target IN LISTS PEELF_FUZZ_TARGETS)
  add_executable(${fuzz_target}
    ${fuzz_target}.cpp
  )
  target_compile_definitions(${fuzz_target} PRIVATE PEELF_LIBFUZZER_HARNESS=1)
  target_include_directories(${fuzz_target} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
  )
  target_link_libraries(${fuzz_target} PRIVATE peelf::core)
  peelf_configure_fuzzer_target(${fuzz_target})
endforeach()

# Compile viewer's C struct/union/enum/typedef parser directly into fuzz_parsers_dsl
# without pulling in any Vulkan/GLFW/ImGui GUI library dependencies.
target_sources(fuzz_parsers_dsl PRIVATE
  "${CMAKE_SOURCE_DIR}/apps/viewer/src/analysis/c_type_parser.cpp"
)
target_include_directories(fuzz_parsers_dsl PRIVATE
  "${CMAKE_SOURCE_DIR}/apps/viewer/src"
)
