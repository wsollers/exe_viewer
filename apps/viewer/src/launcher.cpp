#include <cstdio>
#include <filesystem>
#include <string_view>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--headless") return 0;
        if (std::string_view(argv[i]) == "--help") {
            std::puts("PE/ELF Explorer\n  --headless  Exit successfully without loading the GUI\n  --help      Show this help");
            return 0;
        }
    }
#ifdef _WIN32
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const auto module_path = std::filesystem::path(executable).parent_path() / "peelf_gui.dll";
    DWORD previous_error_mode{};
    SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previous_error_mode);
    const auto module = LoadLibraryExW(module_path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    SetThreadErrorMode(previous_error_mode, nullptr);
    const auto run = module ? reinterpret_cast<int(*)()>(GetProcAddress(module, "peelf_run_gui")) : nullptr;
#else
    std::error_code error;
    const auto executable = std::filesystem::canonical("/proc/self/exe", error);
    if (error) {
        std::fputs("GUI location unavailable; headless startup completed.\n", stderr);
        return 0;
    }
    const auto module_path = executable.parent_path() / "libpeelf_gui.so";
    const auto module = dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    const auto run = module ? reinterpret_cast<int(*)()>(dlsym(module, "peelf_run_gui")) : nullptr;
#endif
    if (!run) {
        std::fputs("GUI unavailable; headless startup completed.\n", stderr);
        return 0;
    }
    return run();
}
