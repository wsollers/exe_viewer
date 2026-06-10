#include "application.h"
#include "crash/crash_handler.hpp"

int main() {
    viewer::crash::install_crash_handlers();

    viewer::Application app;
    viewer::AppConfig config{};
    config.title = "PE/ELF Viewer";
    config.width = 1280;
    config.height = 720;

    app.init(config);
    app.run();
    app.shutdown();

    return 0;
}
