#pragma once

#ifndef _WIN32


#include <cstddef>
#include <string>

namespace peelf {

    struct PosixFileMappingBackend {
        int fd = -1;

        static std::error_code open_and_map(PosixFileMappingBackend& self,
                                            const std::string& path,
                                            MapMode mode,
                                            void** out_ptr,
                                            std::size_t* out_size) noexcept;

        static std::error_code unmap_and_close(PosixFileMappingBackend& self,
                                               void* ptr,
                                               std::size_t size) noexcept;

        static std::error_code flush(PosixFileMappingBackend& self,
                                     void* ptr,
                                     std::size_t size) noexcept;
    };

} // namespace ws::fs

#endif
