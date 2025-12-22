#include "application.h"

#include <cstdio>
#include <exception>

int main() {
    viewer::Application app;

    try {
        viewer::AppConfig config{};
        config.title = "PE/ELF Viewer";
        config.width = 1280;
        config.height = 720;

        app.init(config);
        app.run();
        app.shutdown();
    }
    catch (const std::exception& e) {
        fprintf(stderr, "Fatal error: %s\n", e.what());
        return 1;
    }

    return 0;
}