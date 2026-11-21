#include "headless_cli.hpp"
#include "runtime_paths.hpp"

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main(int argc, char** argv) {
    std::vector<std::string_view> args;
    if (argc > 1) {
        args.reserve(static_cast<std::size_t>(argc - 1));
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }
    }

    if (const auto cli_exit = viewer::try_run_headless_or_help_cli(args, std::cout, std::cerr);
        cli_exit.has_value()) {
        return *cli_exit;
    }

    const auto executable = viewer::current_executable_path();
    if (!executable.has_value()) {
        std::fputs("GUI location unavailable; headless startup completed.\n", stderr);
        return 0;
    }
    const auto module_path = viewer::resolve_gui_module_path(executable->parent_path());
#ifdef _WIN32
    DWORD previous_error_mode{};
    SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previous_error_mode);
    const auto module = LoadLibraryExW(module_path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    SetThreadErrorMode(previous_error_mode, nullptr);
    const auto run = module ? reinterpret_cast<int(*)()>(GetProcAddress(module, "peelf_run_gui")) : nullptr;
#else
    const auto module = dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    const auto run = module ? reinterpret_cast<int(*)()>(dlsym(module, "peelf_run_gui")) : nullptr;
#endif
    if (!run) {
        std::fputs("GUI unavailable; headless startup completed.\n", stderr);
        return 0;
    }
    return run();
}
