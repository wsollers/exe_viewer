#pragma once

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>

#include <cstddef>
#include <string>
#include <system_error>

namespace peelf {
    enum class MapMode;


    struct Win32FileMappingBackend {
        HANDLE file = INVALID_HANDLE_VALUE;
        HANDLE mapping = nullptr;

        static std::error_code open_and_map(Win32FileMappingBackend& self,
                                            const std::string& path,
                                            MapMode mode,
                                            void** out_ptr,
                                            std::size_t* out_size) noexcept;

        static std::error_code unmap_and_close(Win32FileMappingBackend& self,
                                               void* ptr,
                                               std::size_t size) noexcept;

        static std::error_code flush(Win32FileMappingBackend& self,
                                     void* ptr,
                                     std::size_t size) noexcept;
    };

} // namespace ws::fs

#endif
