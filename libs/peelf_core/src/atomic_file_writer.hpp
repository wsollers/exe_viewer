#pragma once

#include "peelf/error.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>

namespace peelf::detail {

/// Exclusive sibling temporary file writer with RAII cleanup-on-failure and
/// non-destructive atomic commit (`overwrite` or race-free `noreplace`).
class AtomicFileWriter {
public:
    [[nodiscard]] static Result<AtomicFileWriter> open(
        const std::filesystem::path& destination,
        bool create_parent_dirs = false);

    ~AtomicFileWriter() noexcept;

    AtomicFileWriter(const AtomicFileWriter&) = delete;
    AtomicFileWriter& operator=(const AtomicFileWriter&) = delete;
    AtomicFileWriter(AtomicFileWriter&& other) noexcept;
    AtomicFileWriter& operator=(AtomicFileWriter&& other) noexcept;

    [[nodiscard]] Result<void> write(std::span<const std::uint8_t> bytes);
    [[nodiscard]] Result<void> write_text(std::string_view text);
    [[nodiscard]] Result<void> flush_and_close();
    [[nodiscard]] Result<void> commit(bool overwrite);

    [[nodiscard]] const std::filesystem::path& temp_path() const noexcept { return temp_path_; }

private:
#ifdef _WIN32
    using NativeHandle = void*;
    static NativeHandle invalid_native_handle() noexcept;
#else
    using NativeHandle = int;
    static constexpr NativeHandle invalid_native_handle() noexcept { return -1; }
#endif

    AtomicFileWriter(NativeHandle handle,
                     std::filesystem::path temp_path,
                     std::filesystem::path dest_path) noexcept;

    void close_noexcept() noexcept;
    void cleanup_noexcept() noexcept;

    NativeHandle handle_{invalid_native_handle()};
    std::filesystem::path temp_path_;
    std::filesystem::path dest_path_;
    bool cleanup_needed_{false};
};

[[nodiscard]] Result<void> write_bytes_atomically(
    const std::filesystem::path& destination,
    std::span<const std::uint8_t> bytes,
    bool overwrite,
    bool create_parent_dirs = false);

[[nodiscard]] Result<void> write_text_atomically(
    const std::filesystem::path& destination,
    std::string_view text,
    bool overwrite,
    bool create_parent_dirs = false);

/// Exclusive unique temporary file staged in the OS temporary directory with RAII unlink on destruction.
class ExclusiveTempFile {
public:
    [[nodiscard]] static Result<ExclusiveTempFile> create(
        std::string_view prefix,
        std::string_view suffix,
        std::span<const std::uint8_t> bytes);

    ~ExclusiveTempFile() noexcept;

    ExclusiveTempFile(const ExclusiveTempFile&) = delete;
    ExclusiveTempFile& operator=(const ExclusiveTempFile&) = delete;
    ExclusiveTempFile(ExclusiveTempFile&& other) noexcept;
    ExclusiveTempFile& operator=(ExclusiveTempFile&& other) noexcept;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    explicit ExclusiveTempFile(std::filesystem::path path) noexcept;
    void cleanup_noexcept() noexcept;

    std::filesystem::path path_;
    bool active_{false};
};

} // namespace peelf::detail
