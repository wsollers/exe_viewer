include(CheckIPOSupported)

function(peelf_apply_project_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /wd4324 /permissive- /Zc:__cplusplus /FS)
    target_compile_definitions(${target} PRIVATE _ENABLE_EXTENDED_ALIGNED_STORAGE)
    if(PEELF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(PEELF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(PEELF_ENABLE_FUZZERS)
      target_compile_options(${target} PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
      )
      get_target_property(_peelf_is_fuzzer ${target} PEELF_IS_FUZZER_TARGET)
      if(NOT _peelf_is_fuzzer)
        target_link_options(${target} PRIVATE
          -fsanitize=fuzzer-no-link,address,undefined
          -fno-omit-frame-pointer
          -fno-sanitize-recover=all
        )
      endif()
    elseif(PEELF_ENABLE_SANITIZERS)
      target_compile_options(${target} PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
      )
      target_link_options(${target} PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
      )
    endif()
  endif()
endfunction()

function(peelf_configure_fuzzer_target target)
  set_target_properties(${target} PROPERTIES PEELF_IS_FUZZER_TARGET TRUE)
  peelf_apply_project_warnings(${target})
  target_link_options(${target} PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all
  )
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_FLAGS MATCHES "-stdlib=libc\\+\\+")
    # Debian/Ubuntu builds libclang_rt.fuzzer-<arch>.a against libstdc++ symbols;
    # pass -Wl,-lstdc++ directly to ld so Clang's -stdlib=libc++ driver keeps it.
    target_link_options(${target} PRIVATE -Wl,-lstdc++)
  endif()
endfunction()

function(peelf_enable_ipo target)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
  if(ipo_supported)
    set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endfunction()
