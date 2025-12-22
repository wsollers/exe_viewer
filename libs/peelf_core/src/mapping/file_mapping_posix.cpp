#ifndef _WIN32

#include "mapping/file_mapping_posix.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace peelf {

static std::error_code posix_ec(int err) noexcept {
    return std::error_code(err, std::generic_category());
}

std::error_code PosixFileMappingBackend::open_and_map(PosixFileMappingBackend& self,
                                                     const std::string& path,
                                                     MapMode mode,
                                                     void** out_ptr,
                                                     std::size_t* out_size) noexcept
{
    *out_ptr = nullptr;
    *out_size = 0;

    const int flags = (mode == MapMode::read_only) ? O_RDONLY : O_RDWR;
    const int fd = ::open(path.c_str(), flags);
    if (fd < 0) return make_error_code(MapErrc::open_failed);

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        ::close(fd);
        return make_error_code(MapErrc::stat_failed);
    }

    if (st.st_size <= 0) {
        ::close(fd);
        return make_error_code(MapErrc::size_zero);
    }

    const std::size_t size = static_cast<std::size_t>(st.st_size);

    const int prot = (mode == MapMode::read_only) ? PROT_READ : (PROT_READ | PROT_WRITE);
    void* ptr = ::mmap(nullptr, size, prot, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        return make_error_code(MapErrc::map_failed);
    }

    self.fd = fd;
    *out_ptr = ptr;
    *out_size = size;
    return {};
}

std::error_code PosixFileMappingBackend::unmap_and_close(PosixFileMappingBackend& self,
                                                        void* ptr,
                                                        std::size_t size) noexcept
{
    std::error_code ec{};

    if (ptr && size) {
        if (::munmap(ptr, size) != 0) {
            ec = make_error_code(MapErrc::unmap_failed);
        }
    }
    if (self.fd >= 0) {
        ::close(self.fd);
        self.fd = -1;
    }
    return ec;
}

std::error_code PosixFileMappingBackend::flush(PosixFileMappingBackend&,
                                              void* ptr,
                                              std::size_t size) noexcept
{
    if (!ptr || !size) return {};
    if (::msync(ptr, size, MS_SYNC) != 0) return make_error_code(MapErrc::flush_failed);
    return {};
}

} // namespace ws::fs

#endif
