#include <gtest/gtest.h>

#include "headless_cli.hpp"
#include "runtime_paths.hpp"

#include <peelf/peelf.hpp>
#include <peelf/security_audit.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

int current_pid() noexcept {
#ifdef _WIN32
    return _getpid();
#else
    return static_cast<int>(getpid());
#endif
}

class ScopedTempDir {
public:
    explicit ScopedTempDir(std::string_view tag) {
        static std::atomic<unsigned int> counter{0u};
        const unsigned int id = counter.fetch_add(1u, std::memory_order_relaxed);
        std::error_code ec{};
        std::filesystem::path base = std::filesystem::temp_directory_path(ec);
        if (ec || base.empty()) {
            base = std::filesystem::current_path(ec);
        }
        path_ = base / ("peelf_wu45_" + std::string(tag) + "_" +
                        std::to_string(current_pid()) + "_" + std::to_string(id));
        std::filesystem::remove_all(path_, ec);
        std::filesystem::create_directories(path_, ec);
    }

    ~ScopedTempDir() {
        std::error_code ec{};
        std::filesystem::remove_all(path_, ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_{};
};

void touch_file(const std::filesystem::path& file_path, std::string_view contents = "test\n") {
    std::error_code ec{};
    std::filesystem::create_directories(file_path.parent_path(), ec);
    std::ofstream out(file_path, std::ios::binary);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

}  // namespace

TEST(VersionAndRuntimePaths, VersionConstantAndCliOutput) {
    EXPECT_EQ(peelf::kVersionString, "1.0.0");

    for (const std::string_view flag : {"--version", "-V"}) {
        std::ostringstream out{};
        std::ostringstream err{};
        const std::vector<std::string_view> args = {flag};
        const std::optional<int> exit_code =
            viewer::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(exit_code.has_value()) << flag;
        EXPECT_EQ(*exit_code, 0) << flag;
        EXPECT_EQ(out.str(), "peelf_viewer 1.0.0\n") << flag;
        EXPECT_TRUE(err.str().empty()) << flag;
    }

    for (const std::string_view flag : {"--version", "-V"}) {
        std::ostringstream out{};
        std::ostringstream err{};
        const std::vector<std::string_view> args = {flag};
        const std::optional<int> exit_code =
            peelf::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(exit_code.has_value()) << flag;
        EXPECT_EQ(*exit_code, 0) << flag;
        EXPECT_EQ(out.str(), "peelf_viewer 1.0.0\n") << flag;
        EXPECT_TRUE(err.str().empty()) << flag;
    }

    {
        std::ostringstream out{};
        std::ostringstream err{};
        const std::vector<std::string_view> args = {"--help"};
        const std::optional<int> exit_code =
            viewer::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(exit_code.has_value());
        EXPECT_EQ(*exit_code, 0);
        EXPECT_NE(out.str().find("--version"), std::string::npos);
        EXPECT_NE(out.str().find("-V"), std::string::npos);
    }

    const peelf::HeadlessAnalysisReport empty_report{};
    const std::string sarif = peelf::format_headless_report_sarif(empty_report);
    EXPECT_NE(sarif.find("\"version\": \"1.0.0\""), std::string::npos);
}

TEST(VersionAndRuntimePaths, ResolvesViewerResourcesAcrossBuildAndInstallLayouts) {
    ScopedTempDir temp("resources");
    const std::filesystem::path prefix = temp.path();
    const std::filesystem::path bin_dir = prefix / "bin";
    std::error_code ec{};
    std::filesystem::create_directories(bin_dir, ec);

    // Fallback when neither sibling nor FHS share directory exists.
    EXPECT_EQ(viewer::resolve_viewer_resources_directory(bin_dir), bin_dir / "resources");

    // Standard FHS GNUInstallDirs layout (<prefix>/share/peelf_explorer/resources).
    const std::filesystem::path fhs_resources =
        prefix / "share" / "peelf_explorer" / "resources";
    touch_file(fhs_resources / "theme.ini", "Text 1 1 1 1\n");
    EXPECT_EQ(viewer::resolve_viewer_resources_directory(bin_dir),
              fhs_resources.lexically_normal());

    // Build-tree / Windows flat bundle (<exe_dir>/resources) takes precedence when present.
    const std::filesystem::path local_resources = bin_dir / "resources";
    touch_file(local_resources / "bn_decompile.py", "# mock\n");
    EXPECT_EQ(viewer::resolve_viewer_resources_directory(bin_dir),
              local_resources.lexically_normal());
}

TEST(VersionAndRuntimePaths, ResolvesGuiModuleAcrossFlatAndFhsLibLayouts) {
    ScopedTempDir temp("gui_mod");
    const std::filesystem::path prefix = temp.path();
    const std::filesystem::path bin_dir = prefix / "bin";
    std::error_code ec{};
    std::filesystem::create_directories(bin_dir, ec);

    const std::string_view mod_name = viewer::default_gui_module_filename();
    ASSERT_FALSE(mod_name.empty());

    // Fallback when module does not exist anywhere.
    EXPECT_EQ(viewer::resolve_gui_module_path(bin_dir, mod_name), bin_dir / mod_name);

#ifndef _WIN32
    // Standard FHS lib64 layout (<prefix>/lib64/libpeelf_gui.so).
    const std::filesystem::path lib64_mod = prefix / "lib64" / mod_name;
    touch_file(lib64_mod);
    EXPECT_EQ(viewer::resolve_gui_module_path(bin_dir, mod_name),
              lib64_mod.lexically_normal());

    // Standard FHS lib layout (<prefix>/lib/libpeelf_gui.so) precedes lib64 fallback.
    const std::filesystem::path lib_mod = prefix / "lib" / mod_name;
    touch_file(lib_mod);
    EXPECT_EQ(viewer::resolve_gui_module_path(bin_dir, mod_name),
              lib_mod.lexically_normal());
#endif

    // Flat bundle / build-tree (<exe_dir>/<module>) takes highest precedence.
    const std::filesystem::path flat_mod = bin_dir / mod_name;
    touch_file(flat_mod);
    EXPECT_EQ(viewer::resolve_gui_module_path(bin_dir, mod_name),
              flat_mod.lexically_normal());
}

TEST(VersionAndRuntimePaths, CurrentExecutablePathPointsToExistingBinary) {
    const std::optional<std::filesystem::path> exe_path = viewer::current_executable_path();
    ASSERT_TRUE(exe_path.has_value());
    ASSERT_FALSE(exe_path->empty());
    std::error_code ec{};
    EXPECT_TRUE(std::filesystem::is_regular_file(*exe_path, ec));
    EXPECT_FALSE(ec);
}
