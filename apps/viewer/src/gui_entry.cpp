#include "application.h"
#include "ui/startup_branding.hpp"
#include "crash/crash_handler.hpp"
#include <cstdio>
#include <exception>
#ifdef _WIN32
#define PEELF_GUI_EXPORT __declspec(dllexport)
#else
#define PEELF_GUI_EXPORT __attribute__((visibility("default")))
#endif

extern "C" PEELF_GUI_EXPORT int peelf_run_gui() {
    viewer::crash::install_crash_handlers();
    viewer::Application app;
    try {
        viewer::StartupSplash splash;
        app.init();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "GUI unavailable: %s; headless startup completed.\n", error.what());
        return 0;
    }
    try {
        app.run();
        app.shutdown();
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Viewer failed: %s\n", error.what());
        return 1;
    }
}
