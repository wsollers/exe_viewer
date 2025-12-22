#ifdef _WIN32

#include <cstdint>

#include "mapping/file_mapping_win32.hpp"
#include "mapping/file_mapping.hpp"
#include "mapping/map_errors.hpp"

namespace peelf {


static std::error_code win32_ec(DWORD e) noexcept {
    return std::error_code(static_cast<int>(e), std::system_category());
}

std::error_code Win32FileMappingBackend::open_and_map(Win32FileMappingBackend& self,
                                                     const std::string& path,
                                                     MapMode mode,
                                                     void** out_ptr,
                                                     std::size_t* out_size) noexcept
{
    *out_ptr = nullptr;
    *out_size = 0;

    const DWORD desiredAccess = (mode == MapMode::read_only)
        ? GENERIC_READ
        : (GENERIC_READ | GENERIC_WRITE);

    HANDLE hFile = ::CreateFileA(
        path.c_str(),
        desiredAccess,
        FILE_SHARE_READ,       // share read; adjust if needed
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return make_error_code(MapErrc::open_failed);

    LARGE_INTEGER liSize{};
    if (!::GetFileSizeEx(hFile, &liSize)) {
        ::CloseHandle(hFile);
        return make_error_code(MapErrc::stat_failed);
    }

    if (liSize.QuadPart <= 0) {
        ::CloseHandle(hFile);
        return make_error_code(MapErrc::size_zero);
    }

    const std::uint64_t size64 = static_cast<std::uint64_t>(liSize.QuadPart);
    if (size64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        ::CloseHandle(hFile);
        return make_error_code(MapErrc::stat_failed);
    }
    const std::size_t size = static_cast<std::size_t>(size64);

    const DWORD protect = (mode == MapMode::read_only) ? PAGE_READONLY : PAGE_READWRITE;
    HANDLE hMap = ::CreateFileMappingA(hFile, nullptr, protect, 0, 0, nullptr);
    if (!hMap) {
        ::CloseHandle(hFile);
        return make_error_code(MapErrc::map_failed);
    }

    const DWORD mapAccess = (mode == MapMode::read_only) ? FILE_MAP_READ : FILE_MAP_WRITE;
    void* ptr = ::MapViewOfFile(hMap, mapAccess, 0, 0, 0);
    if (!ptr) {
        ::CloseHandle(hMap);
        ::CloseHandle(hFile);
        return make_error_code(MapErrc::map_failed);
    }

    self.file = hFile;
    self.mapping = hMap;
    *out_ptr = ptr;
    *out_size = size;
    return {};
}

std::error_code Win32FileMappingBackend::unmap_and_close(Win32FileMappingBackend& self,
                                                        void* ptr,
                                                        std::size_t) noexcept
{
    std::error_code ec{};

    if (ptr) {
        if (!::UnmapViewOfFile(ptr)) {
            ec = make_error_code(MapErrc::unmap_failed);
        }
    }
    if (self.mapping) {
        ::CloseHandle(self.mapping);
        self.mapping = nullptr;
    }
    if (self.file != INVALID_HANDLE_VALUE) {
        ::CloseHandle(self.file);
        self.file = INVALID_HANDLE_VALUE;
    }
    return ec;
}

std::error_code Win32FileMappingBackend::flush(Win32FileMappingBackend&,
                                              void* ptr,
                                              std::size_t size) noexcept
{
    if (!ptr || !size) return {};
    if (!::FlushViewOfFile(ptr, size)) return make_error_code(MapErrc::flush_failed);
    return {};
}

} // namespace ws::fs

#endif
