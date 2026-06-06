#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <filesystem>

#define NOMINMAX

#include "mapping/map_errors.hpp"

namespace peelf {
    // -------------------------
    // Error handling
    // -------------------------
    enum class MapErrc {
        ok = 0,
        open_failed,
        stat_failed,
        size_zero,
        invalid_alignment,
        map_failed,
        unmap_failed,
        flush_failed,
    };
}
namespace std {
    template <>
    struct is_error_code_enum<peelf::MapErrc> : true_type {};
}
namespace peelf {
    std::error_code make_error_code(MapErrc) noexcept;
// -------------------------
// Mapping mode
// -------------------------
enum class MapMode {
    read_only,
    read_write
};
} // namespace peelf

// -------------------------
// OS backend selection
//
// These includes are at GLOBAL scope on purpose. Each backend header opens its
// own `namespace peelf`, so including it here defines the backend at the correct
// scope (peelf::Win32FileMappingBackend / peelf::PosixFileMappingBackend).
// Including it inside an already-open `namespace peelf` would nest it as
// peelf::peelf::... and leave NativeFileMappingBackend bound to an incomplete
// type. MapMode is defined above so the backend declarations can see it.
// -------------------------
#if defined(_WIN32)
    #include "file_mapping_win32.hpp"  // defines peelf::Win32FileMappingBackend
#else
    #include "file_mapping_posix.hpp"  // defines peelf::PosixFileMappingBackend
#endif

namespace peelf {
#if defined(_WIN32)
    using NativeFileMappingBackend = Win32FileMappingBackend;
#else
    using NativeFileMappingBackend = PosixFileMappingBackend;
#endif

// -------------------------
// FileMapping<T>
// -------------------------
template <class T, class Backend>
class FileMapping {
    static_assert(std::is_trivially_copyable_v<T>,
                  "FileMapping<T>: T must be trivially copyable for safe mmap semantics.");

public:
    using value_type = T;

    FileMapping() = default;

    explicit FileMapping(const std::filesystem::path& path, MapMode mode = MapMode::read_only)
    {
        if (std::error_code ec = open(path.string(), mode); ec) {
            throw std::system_error(ec, "FileMapping: failed to map '" + path.string() + "'");
        }
    }

    ~FileMapping() { close(); }

    FileMapping(const FileMapping&) = delete;
    FileMapping& operator=(const FileMapping&) = delete;

    FileMapping(FileMapping&& other) noexcept { *this = std::move(other); }
    FileMapping& operator=(FileMapping&& other) noexcept
    {
        if (this != &other) {
            close();
            backend_ = std::exchange(other.backend_, {});
            data_ = std::exchange(other.data_, nullptr);
            byte_size_ = std::exchange(other.byte_size_, 0);
            mode_ = other.mode_;
        }
        return *this;
    }

    // Open / close
    std::error_code open(std::string path, MapMode mode = MapMode::read_only)
    {
        close();
        mode_ = mode;

        std::size_t bytes = 0;
        void* ptr = nullptr;

        if (auto ec = Backend::open_and_map(backend_, path, mode, &ptr, &bytes); ec) {
            return ec;
        }

        if (bytes == 0) {
            close();
            return make_error_code(MapErrc::size_zero);
        }

        // Alignment: mmap/CreateFileMapping are page-aligned, but T alignment might exceed that.
        // Typically alignof(T) <= page size; still check for correctness.
        if (reinterpret_cast<std::uintptr_t>(ptr) % alignof(T) != 0) {
            close();
            return make_error_code(MapErrc::invalid_alignment);
        }

        data_ = static_cast<T*>(ptr);
        byte_size_ = bytes;
        return {};
    }

    void close() noexcept
    {
        if (data_) {
            (void)Backend::unmap_and_close(backend_, data_, byte_size_);
            data_ = nullptr;
            byte_size_ = 0;
        } else {
            // still close handles if backend has them
            (void)Backend::unmap_and_close(backend_, nullptr, 0);
            backend_ = {};
        }
    }

    // Accessors
    [[nodiscard]] bool is_open() const noexcept { return data_ != nullptr; }

    [[nodiscard]] std::size_t size_bytes() const noexcept { return byte_size_; }
    [[nodiscard]] std::size_t size() const noexcept { return byte_size_ / sizeof(T); }

    [[nodiscard]] std::span<const T> view() const noexcept
    {
        return {data_, size()};
    }

    [[nodiscard]] std::span<T> view() noexcept
    {
        return {data_, size()};
    }

    // Optional: flush to disk (only meaningful for read_write)
    std::error_code flush() noexcept
    {
        if (!data_) return {};
        return Backend::flush(backend_, data_, byte_size_);
    }

private:
    Backend backend_{};
    T* data_ = nullptr;
    std::size_t byte_size_ = 0;
    MapMode mode_ = MapMode::read_only;
};

} // namespace peelf
