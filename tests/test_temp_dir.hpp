#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace peelf_test {

[[nodiscard]] inline std::uint64_t current_process_id_u64() noexcept {
#if defined(_WIN32)
    return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

class ScopedTempDir {
public:
    explicit ScopedTempDir(std::string_view prefix = "peelf_test") {
        static std::atomic<std::uint64_t> seq{1u};
        std::error_code ec;
        std::filesystem::path base = std::filesystem::temp_directory_path(ec);
        if (ec || base.empty()) {
#if defined(_WIN32)
            base = std::filesystem::current_path(ec);
#else
            base = std::filesystem::path{"/tmp"};
#endif
        }

        const std::uint64_t pid = current_process_id_u64();
        const auto ticks = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        const std::uint64_t id = seq.fetch_add(1u, std::memory_order_relaxed);
        const std::string_view safe_prefix = prefix.empty() ? "peelf_test" : prefix;

        dir_ = base / std::format("{}_{}_{}_{}", safe_prefix, pid, ticks, id);
        std::filesystem::create_directories(dir_, ec);
        std::filesystem::permissions(
            dir_,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    ScopedTempDir(ScopedTempDir&& other) noexcept
        : dir_(std::exchange(other.dir_, std::filesystem::path{})) {}

    ScopedTempDir& operator=(ScopedTempDir&& other) noexcept {
        if (this != &other) {
            cleanup();
            dir_ = std::exchange(other.dir_, std::filesystem::path{});
        }
        return *this;
    }

    ~ScopedTempDir() noexcept {
        cleanup();
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return dir_;
    }

    [[nodiscard]] std::filesystem::path operator/(std::string_view child) const {
        return dir_ / std::filesystem::path{child};
    }

    [[nodiscard]] std::filesystem::path write_bytes(
        std::string_view relative_name,
        std::span<const std::uint8_t> bytes) const {
        const std::filesystem::path target = dir_ / std::filesystem::path{relative_name};
        std::error_code ec;
        if (target.has_parent_path()) {
            std::filesystem::create_directories(target.parent_path(), ec);
        }
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        if (!bytes.empty()) {
            out.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        return target;
    }

private:
    void cleanup() noexcept {
        if (dir_.empty()) {
            return;
        }
        try {
            std::error_code ec;
            std::filesystem::remove_all(dir_, ec);
            if (ec && std::filesystem::exists(dir_, ec)) {
                std::filesystem::permissions(
                    dir_,
                    std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::add,
                    ec);
                for (std::filesystem::recursive_directory_iterator it(
                         dir_,
                         std::filesystem::directory_options::skip_permission_denied,
                         ec);
                     !ec && it != std::filesystem::recursive_directory_iterator{};
                     it.increment(ec)) {
                    std::error_code perm_ec;
                    if (!it->is_symlink(perm_ec)) {
                        std::filesystem::permissions(
                            it->path(),
                            std::filesystem::perms::owner_all,
                            std::filesystem::perm_options::add,
                            perm_ec);
                    }
                }
                ec.clear();
                std::filesystem::remove_all(dir_, ec);
            }
        } catch (...) {
        }
        dir_.clear();
    }

    std::filesystem::path dir_{};
};

} // namespace peelf_test
