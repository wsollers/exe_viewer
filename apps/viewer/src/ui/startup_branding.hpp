#pragma once
#include <memory>

struct GLFWwindow;
namespace viewer {
// Native startup artwork needs no Vulkan device and remains responsive during init.
class StartupSplash {
public:
    StartupSplash();
    ~StartupSplash();
    StartupSplash(const StartupSplash&) = delete;
    StartupSplash& operator=(const StartupSplash&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void set_window_branding(GLFWwindow* window);
}
