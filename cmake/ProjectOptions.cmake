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
    if(PEELF_ENABLE_SANITIZERS)
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

function(peelf_enable_ipo target)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
  if(ipo_supported)
    set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endfunction()
