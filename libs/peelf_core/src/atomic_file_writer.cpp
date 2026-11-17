#include "atomic_file_writer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <system_error>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#endif

namespace peelf::detail {
namespace {

constexpr std::size_t kMaxIoChunkBytes = 64u * 1024u * 1024u;
constexpr unsigned int kMaxExclusiveCreateAttempts = 128u;

[[nodiscard]] std::uint64_t current_process_tag() noexcept {
#ifdef _WIN32
    return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

[[nodiscard]] std::uint64_t next_temp_sequence() noexcept {
    static std::atomic<std::uint64_t> s_seq{0};
    return s_seq.fetch_add(1u, std::memory_order_relaxed) + 1u;
}

[[nodiscard]] std::uint64_t steady_ticks() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
}

#ifdef _WIN32
[[nodiscard]] std::string win32_error_message(DWORD code) {
    return std::error_code(static_cast<int>(code), std::system_category()).message();
}
#else
[[nodiscard]] std::string posix_error_message(int err_num) {
    return std::error_code(err_num, std::generic_category()).message();
}
#endif

#ifdef _WIN32
[[nodiscard]] Result<void> write_all_handle(HANDLE handle, std::span<const std::uint8_t> bytes) {
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const std::size_t chunk = std::min<std::size_t>(bytes.size() - offset, kMaxIoChunkBytes);
        DWORD written = 0u;
        if (!::WriteFile(handle,
                         bytes.data() + offset,
                         static_cast<DWORD>(chunk),
                         &written,
                         nullptr) ||
            written == 0u) {
            const DWORD err = ::GetLastError();
            return make_error(std::format("Failed while writing temporary file: {}",
                                          win32_error_message(err)));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}
#else
[[nodiscard]] Result<void> write_all_fd(int fd, std::span<const std::uint8_t> bytes) {
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const std::size_t chunk = std::min<std::size_t>(bytes.size() - offset, kMaxIoChunkBytes);
        const ssize_t n = ::write(fd, bytes.data() + offset, chunk);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int err = errno;
            return make_error(std::format("Failed while writing temporary file: {}",
                                          posix_error_message(err)));
        }
        if (n == 0) {
            return make_error("Short zero-byte write while writing temporary file");
        }
        offset += static_cast<std::size_t>(n);
    }
    return {};
}
#endif

} // namespace

#ifdef _WIN32
AtomicFileWriter::NativeHandle AtomicFileWriter::invalid_native_handle() noexcept {
    return INVALID_HANDLE_VALUE;
}
#endif

AtomicFileWriter::AtomicFileWriter(NativeHandle handle,
                                   std::filesystem::path temp_path,
                                   std::filesystem::path dest_path) noexcept
    : handle_(handle),
      temp_path_(std::move(temp_path)),
      dest_path_(std::move(dest_path)),
      cleanup_needed_(true) {}

AtomicFileWriter::~AtomicFileWriter() noexcept {
    cleanup_noexcept();
}

AtomicFileWriter::AtomicFileWriter(AtomicFileWriter&& other) noexcept
    : handle_(std::exchange(other.handle_, invalid_native_handle())),
      temp_path_(std::move(other.temp_path_)),
      dest_path_(std::move(other.dest_path_)),
      cleanup_needed_(std::exchange(other.cleanup_needed_, false)) {}

AtomicFileWriter& AtomicFileWriter::operator=(AtomicFileWriter&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    cleanup_noexcept();
    handle_ = std::exchange(other.handle_, invalid_native_handle());
    temp_path_ = std::move(other.temp_path_);
    dest_path_ = std::move(other.dest_path_);
    cleanup_needed_ = std::exchange(other.cleanup_needed_, false);
    return *this;
}

void AtomicFileWriter::close_noexcept() noexcept {
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
        (void)::CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (handle_ >= 0) {
        (void)::close(handle_);
        handle_ = -1;
    }
#endif
}

void AtomicFileWriter::cleanup_noexcept() noexcept {
    close_noexcept();
    if (cleanup_needed_ && !temp_path_.empty()) {
#ifdef _WIN32
        (void)::DeleteFileW(temp_path_.c_str());
#else
        (void)::unlink(temp_path_.c_str());
#endif
        cleanup_needed_ = false;
    }
}

Result<AtomicFileWriter> AtomicFileWriter::open(const std::filesystem::path& destination,
                                                bool create_parent_dirs) {
    if (destination.empty() || destination.filename().empty()) {
        return make_error("Output file path is empty");
    }

    const std::filesystem::path parent = destination.parent_path();
    if (create_parent_dirs && !parent.empty()) {
        std::error_code dir_ec;
        std::filesystem::create_directories(parent, dir_ec);
        if (dir_ec) {
            return make_error(std::format("Failed to create output directory '{}': {}",
                                          parent.string(),
                                          dir_ec.message()));
        }
    }

    std::error_code base_ec;
    const std::filesystem::path base_dir =
        parent.empty() ? std::filesystem::current_path(base_ec) : parent;
    if (base_ec) {
        return make_error(std::format("Failed to resolve output directory: {}",
                                      base_ec.message()));
    }

    const std::uint64_t pid = current_process_tag();
    const std::filesystem::path base_name = destination.filename();

#ifndef _WIN32
    mode_t preserved_mode = 0;
    bool has_preserved_mode = false;
    struct stat st {};
    if (::stat(destination.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        preserved_mode = static_cast<mode_t>(st.st_mode & 07777);
        has_preserved_mode = true;
    }
#endif

    for (unsigned int attempt = 0u; attempt < kMaxExclusiveCreateAttempts; ++attempt) {
        const std::uint64_t ticks = steady_ticks();
        const std::uint64_t seq = next_temp_sequence();
        std::filesystem::path candidate = base_dir / base_name;
        candidate += std::format(".{}-{}-{}.tmp", pid, ticks, seq);

#ifdef _WIN32
        HANDLE h = ::CreateFileW(candidate.c_str(),
                                 GENERIC_WRITE,
                                 0u,
                                 nullptr,
                                 CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            return AtomicFileWriter(h, std::move(candidate), destination);
        }
        const DWORD err = ::GetLastError();
        if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
            continue;
        }
        return make_error(std::format("Failed to create temporary file in '{}': {}",
                                      base_dir.string(),
                                      win32_error_message(err)));
#else
        const int fd = ::open(candidate.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                              static_cast<mode_t>(0666));
        if (fd >= 0) {
            if (has_preserved_mode) {
                (void)::fchmod(fd, preserved_mode);
            }
            return AtomicFileWriter(fd, std::move(candidate), destination);
        }
        const int err = errno;
        if (err == EEXIST) {
            continue;
        }
        return make_error(std::format("Failed to create temporary file in '{}': {}",
                                      base_dir.string(),
                                      posix_error_message(err)));
#endif
    }

    return make_error(std::format(
        "Exhausted exclusive temporary file creation attempts in '{}'",
        base_dir.string()));
}

Result<void> AtomicFileWriter::write(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
#ifdef _WIN32
    if (handle_ == INVALID_HANDLE_VALUE) {
        return make_error("Temporary file handle is already closed");
    }
    return write_all_handle(static_cast<HANDLE>(handle_), bytes);
#else
    if (handle_ < 0) {
        return make_error("Temporary file descriptor is already closed");
    }
    return write_all_fd(handle_, bytes);
#endif
}

Result<void> AtomicFileWriter::write_text(std::string_view text) {
    const auto* raw = reinterpret_cast<const std::uint8_t*>(text.data());
    return write(std::span<const std::uint8_t>(raw, text.size()));
}

Result<void> AtomicFileWriter::flush_and_close() {
#ifdef _WIN32
    if (handle_ == INVALID_HANDLE_VALUE) {
        return {};
    }
    HANDLE h = static_cast<HANDLE>(handle_);
    if (!::FlushFileBuffers(h)) {
        const DWORD err = ::GetLastError();
        close_noexcept();
        return make_error(std::format("Failed to flush temporary file '{}': {}",
                                      temp_path_.string(),
                                      win32_error_message(err)));
    }
    handle_ = INVALID_HANDLE_VALUE;
    if (!::CloseHandle(h)) {
        const DWORD err = ::GetLastError();
        return make_error(std::format("Failed to close temporary file '{}': {}",
                                      temp_path_.string(),
                                      win32_error_message(err)));
    }
    return {};
#else
    if (handle_ < 0) {
        return {};
    }
    while (::fsync(handle_) != 0) {
        if (errno == EINTR) {
            continue;
        }
        const int err = errno;
        close_noexcept();
        return make_error(std::format("Failed to fsync temporary file '{}': {}",
                                      temp_path_.string(),
                                      posix_error_message(err)));
    }
    const int fd = std::exchange(handle_, -1);
    if (::close(fd) != 0 && errno != EINTR) {
        const int err = errno;
        return make_error(std::format("Failed to close temporary file '{}': {}",
                                      temp_path_.string(),
                                      posix_error_message(err)));
    }
    return {};
#endif
}

Result<void> AtomicFileWriter::commit(bool overwrite) {
    if (!cleanup_needed_) {
        return make_error("AtomicFileWriter was already committed or cleaned up");
    }
    if (auto flushed = flush_and_close(); !flushed) {
        return flushed;
    }

#ifdef _WIN32
    const DWORD flags = overwrite
                            ? (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
                            : MOVEFILE_WRITE_THROUGH;
    if (!::MoveFileExW(temp_path_.c_str(), dest_path_.c_str(), flags)) {
        const DWORD err = ::GetLastError();
        if (!overwrite && (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)) {
            return make_error(std::format("Output file '{}' already exists",
                                          dest_path_.string()));
        }
        return make_error(std::format("Failed to atomically commit '{}': {}",
                                      dest_path_.string(),
                                      win32_error_message(err)));
    }
    cleanup_needed_ = false;
    return {};
#else
    if (overwrite) {
        if (::rename(temp_path_.c_str(), dest_path_.c_str()) != 0) {
            const int err = errno;
            return make_error(std::format("Failed to atomically replace '{}': {}",
                                          dest_path_.string(),
                                          posix_error_message(err)));
        }
        cleanup_needed_ = false;
        return {};
    }

#if defined(__linux__) && defined(SYS_renameat2)
    constexpr unsigned int kRenameNoReplace = 1u;
    if (::syscall(SYS_renameat2,
                  AT_FDCWD,
                  temp_path_.c_str(),
                  AT_FDCWD,
                  dest_path_.c_str(),
                  kRenameNoReplace) == 0) {
        cleanup_needed_ = false;
        return {};
    }
    const int rename_err = errno;
    if (rename_err == EEXIST) {
        return make_error(std::format("Output file '{}' already exists",
                                      dest_path_.string()));
    }
    if (rename_err != ENOSYS && rename_err != EINVAL && rename_err != EOPNOTSUPP) {
        return make_error(std::format("Failed to publish '{}': {}",
                                      dest_path_.string(),
                                      posix_error_message(rename_err)));
    }
#endif

    if (::link(temp_path_.c_str(), dest_path_.c_str()) == 0) {
        (void)::unlink(temp_path_.c_str());
        cleanup_needed_ = false;
        return {};
    }
    const int link_err = errno;
    if (link_err == EEXIST) {
        return make_error(std::format("Output file '{}' already exists",
                                      dest_path_.string()));
    }
    return make_error(std::format("Failed to publish '{}': {}",
                                  dest_path_.string(),
                                  posix_error_message(link_err)));
#endif
}

Result<void> write_bytes_atomically(const std::filesystem::path& destination,
                                    std::span<const std::uint8_t> bytes,
                                    bool overwrite,
                                    bool create_parent_dirs) {
    auto writer = AtomicFileWriter::open(destination, create_parent_dirs);
    if (!writer) {
        return std::unexpected(writer.error());
    }
    if (auto w = writer->write(bytes); !w) {
        return w;
    }
    return writer->commit(overwrite);
}

Result<void> write_text_atomically(const std::filesystem::path& destination,
                                   std::string_view text,
                                   bool overwrite,
                                   bool create_parent_dirs) {
    const auto* raw = reinterpret_cast<const std::uint8_t*>(text.data());
    return write_bytes_atomically(
        destination,
        std::span<const std::uint8_t>(raw, text.size()),
        overwrite,
        create_parent_dirs);
}

ExclusiveTempFile::ExclusiveTempFile(std::filesystem::path path) noexcept
    : path_(std::move(path)), active_(true) {}

ExclusiveTempFile::~ExclusiveTempFile() noexcept {
    cleanup_noexcept();
}

ExclusiveTempFile::ExclusiveTempFile(ExclusiveTempFile&& other) noexcept
    : path_(std::move(other.path_)),
      active_(std::exchange(other.active_, false)) {}

ExclusiveTempFile& ExclusiveTempFile::operator=(ExclusiveTempFile&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    cleanup_noexcept();
    path_ = std::move(other.path_);
    active_ = std::exchange(other.active_, false);
    return *this;
}

void ExclusiveTempFile::cleanup_noexcept() noexcept {
    if (active_ && !path_.empty()) {
#ifdef _WIN32
        (void)::DeleteFileW(path_.c_str());
#else
        (void)::unlink(path_.c_str());
#endif
        active_ = false;
    }
}

Result<ExclusiveTempFile> ExclusiveTempFile::create(std::string_view prefix,
                                                    std::string_view suffix,
                                                    std::span<const std::uint8_t> bytes) {
    std::filesystem::path temp_dir;
#ifdef _WIN32
    wchar_t dir_buf[MAX_PATH] = {};
    const DWORD dir_len = ::GetTempPathW(MAX_PATH, dir_buf);
    if (dir_len == 0u || dir_len >= MAX_PATH) {
        return make_error("Failed to resolve OS temporary directory");
    }
    temp_dir = std::filesystem::path(dir_buf);
#else
    std::error_code dir_ec;
    temp_dir = std::filesystem::temp_directory_path(dir_ec);
    if (dir_ec || temp_dir.empty()) {
        return make_error("Failed to resolve OS temporary directory");
    }
#endif

    const std::uint64_t pid = current_process_tag();
    for (unsigned int attempt = 0u; attempt < kMaxExclusiveCreateAttempts; ++attempt) {
        const std::uint64_t ticks = steady_ticks();
        const std::uint64_t seq = next_temp_sequence();
        std::filesystem::path candidate =
            temp_dir / std::format("{}{}_{}_{}{}", prefix, pid, ticks, seq, suffix);

#ifdef _WIN32
        HANDLE h = ::CreateFileW(candidate.c_str(),
                                 GENERIC_WRITE,
                                 0u,
                                 nullptr,
                                 CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
                continue;
            }
            return make_error(std::format("Failed to create exclusive temp file: {}",
                                          win32_error_message(err)));
        }

        ExclusiveTempFile guard(std::move(candidate));
        if (auto wr = write_all_handle(h, bytes); !wr) {
            (void)::CloseHandle(h);
            return std::unexpected(wr.error());
        }
        if (!::FlushFileBuffers(h)) {
            const DWORD err = ::GetLastError();
            (void)::CloseHandle(h);
            return make_error(std::format("Failed to flush exclusive temp file: {}",
                                          win32_error_message(err)));
        }
        if (!::CloseHandle(h)) {
            const DWORD err = ::GetLastError();
            return make_error(std::format("Failed to close exclusive temp file: {}",
                                          win32_error_message(err)));
        }
        return guard;
#else
        const int fd = ::open(candidate.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                              static_cast<mode_t>(0600));
        if (fd < 0) {
            const int err = errno;
            if (err == EEXIST) {
                continue;
            }
            return make_error(std::format("Failed to create exclusive temp file: {}",
                                          posix_error_message(err)));
        }

        ExclusiveTempFile guard(std::move(candidate));
        if (auto wr = write_all_fd(fd, bytes); !wr) {
            (void)::close(fd);
            return std::unexpected(wr.error());
        }
        while (::fsync(fd) != 0) {
            if (errno == EINTR) {
                continue;
            }
            const int err = errno;
            (void)::close(fd);
            return make_error(std::format("Failed to fsync exclusive temp file: {}",
                                          posix_error_message(err)));
        }
        if (::close(fd) != 0 && errno != EINTR) {
            const int err = errno;
            return make_error(std::format("Failed to close exclusive temp file: {}",
                                          posix_error_message(err)));
        }
        return guard;
#endif
    }

    return make_error("Exhausted exclusive temporary file creation attempts");
}

} // namespace peelf::detail
