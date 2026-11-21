#pragma once

#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace viewer {

[[nodiscard]] constexpr std::string_view default_gui_module_filename() noexcept {
#ifdef _WIN32
    return "peelf_gui.dll";
#elif defined(__APPLE__)
    return "libpeelf_gui.dylib";
#else
    return "libpeelf_gui.so";
#endif
}

/// Returns the resolved path of the running executable when available from the OS.
[[nodiscard]] std::optional<std::filesystem::path> current_executable_path();

/// Returns the directory containing the running executable, falling back to the
/// current working directory if the OS executable path cannot be queried.
[[nodiscard]] std::filesystem::path current_executable_directory();

/// Returns candidate viewer resource directories relative to `executable_dir`,
/// ordered from highest to lowest priority (build-tree/bundle `<executable_dir>/resources`
/// followed by GNUInstallDirs `<executable_dir>/../share/peelf_explorer/resources`).
[[nodiscard]] std::vector<std::filesystem::path> candidate_viewer_resources_directories(
    const std::filesystem::path& executable_dir);

/// Resolves the viewer `resources` directory relative to `executable_dir`,
/// supporting both build-tree (`<executable_dir>/resources`) and installed FHS
/// (`<executable_dir>/../share/peelf_explorer/resources`) layouts.
[[nodiscard]] std::filesystem::path resolve_viewer_resources_directory(
    const std::filesystem::path& executable_dir);

/// Returns candidate paths for the dynamically loaded GUI module relative to
/// `executable_dir` (`<executable_dir>/<module>`, `../<libdir>/<module>`,
/// `../lib/<module>`, `../lib64/<module>`).
[[nodiscard]] std::vector<std::filesystem::path> candidate_gui_module_paths(
    const std::filesystem::path& executable_dir,
    std::string_view module_filename = default_gui_module_filename());

/// Resolves the first existing file from `candidate_gui_module_paths`, or returns
/// `<executable_dir>/<module_filename>` when none exist on disk.
[[nodiscard]] std::filesystem::path resolve_gui_module_path(
    const std::filesystem::path& executable_dir,
    std::string_view module_filename = default_gui_module_filename());

} // namespace viewer
