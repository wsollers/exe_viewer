#include "runtime_paths.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#ifndef PEELF_INSTALL_LIBDIR
#define PEELF_INSTALL_LIBDIR "lib"
#endif

#ifndef PEELF_INSTALL_DATADIR
#define PEELF_INSTALL_DATADIR "share"
#endif

namespace viewer {
namespace {

void append_unique_normalized(std::vector<std::filesystem::path>& out,
                              const std::filesystem::path& candidate) {
    const std::filesystem::path norm = candidate.lexically_normal();
    if (std::ranges::find(out, norm) == out.end()) {
        out.push_back(norm);
    }
}

[[nodiscard]] bool directory_contains_known_resource(const std::filesystem::path& dir) noexcept {
    static constexpr std::array<std::string_view, 3> kKnownFiles{
        "theme.ini",
        "bn_decompile.py",
        "PeelfDecompile.java",
    };
    for (const std::string_view name : kKnownFiles) {
        std::error_code ec{};
        if (std::filesystem::is_regular_file(dir / name, ec) && !ec) {
            return true;
        }
    }
    return false;
}

} // namespace

std::optional<std::filesystem::path> current_executable_path() {
#ifdef _WIN32
    std::array<wchar_t, 32768> executable{};
    const DWORD length =
        ::GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0u || length >= executable.size()) {
        return std::nullopt;
    }
    return std::filesystem::path(std::wstring_view(executable.data(), length));
#elif defined(__APPLE__)
    std::uint32_t size = 0u;
    (void)_NSGetExecutablePath(nullptr, &size);
    if (size == 0u) {
        return std::nullopt;
    }
    std::string buffer(size, '\0');
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        return std::nullopt;
    }
    std::error_code ec{};
    std::filesystem::path resolved =
        std::filesystem::weakly_canonical(std::filesystem::path(buffer.c_str()), ec);
    if (ec || resolved.empty()) {
        return std::filesystem::path(buffer.c_str());
    }
    return resolved;
#else
    std::error_code ec{};
    std::filesystem::path executable = std::filesystem::canonical("/proc/self/exe", ec);
    if (ec || executable.empty()) {
        return std::nullopt;
    }
    return executable;
#endif
}

std::filesystem::path current_executable_directory() {
    if (const auto exe = current_executable_path(); exe.has_value()) {
        return exe->parent_path();
    }
    std::error_code ec{};
    return std::filesystem::current_path(ec);
}

std::vector<std::filesystem::path> candidate_viewer_resources_directories(
    const std::filesystem::path& executable_dir) {
    std::vector<std::filesystem::path> candidates{};
    candidates.reserve(3u);

    append_unique_normalized(candidates, executable_dir / "resources");

    constexpr std::string_view kConfiguredDataDir = PEELF_INSTALL_DATADIR;
    if (!kConfiguredDataDir.empty()) {
        append_unique_normalized(
            candidates,
            executable_dir / ".." / kConfiguredDataDir / "peelf_explorer" / "resources");
    }
    append_unique_normalized(
        candidates, executable_dir / ".." / "share" / "peelf_explorer" / "resources");

    return candidates;
}

std::filesystem::path resolve_viewer_resources_directory(
    const std::filesystem::path& executable_dir) {
    const std::vector<std::filesystem::path> candidates =
        candidate_viewer_resources_directories(executable_dir);

    for (const std::filesystem::path& dir : candidates) {
        if (directory_contains_known_resource(dir)) {
            return dir;
        }
    }

    for (const std::filesystem::path& dir : candidates) {
        std::error_code ec{};
        if (std::filesystem::is_directory(dir, ec) && !ec) {
            return dir;
        }
    }

    return (executable_dir / "resources").lexically_normal();
}

std::vector<std::filesystem::path> candidate_gui_module_paths(
    const std::filesystem::path& executable_dir,
    std::string_view module_filename) {
    std::vector<std::filesystem::path> candidates{};
    candidates.reserve(4u);

    const std::filesystem::path mod_name(module_filename);
    append_unique_normalized(candidates, executable_dir / mod_name);

    constexpr std::string_view kConfiguredLibDir = PEELF_INSTALL_LIBDIR;
    if (!kConfiguredLibDir.empty()) {
        append_unique_normalized(candidates, executable_dir / ".." / kConfiguredLibDir / mod_name);
    }
    append_unique_normalized(candidates, executable_dir / ".." / "lib" / mod_name);
    append_unique_normalized(candidates, executable_dir / ".." / "lib64" / mod_name);

    return candidates;
}

std::filesystem::path resolve_gui_module_path(
    const std::filesystem::path& executable_dir,
    std::string_view module_filename) {
    const std::vector<std::filesystem::path> candidates =
        candidate_gui_module_paths(executable_dir, module_filename);

    for (const std::filesystem::path& path : candidates) {
        std::error_code ec{};
        if (std::filesystem::is_regular_file(path, ec) && !ec) {
            return path;
        }
    }

    return (executable_dir / std::filesystem::path(module_filename)).lexically_normal();
}

} // namespace viewer
