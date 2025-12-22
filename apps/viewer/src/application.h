#pragma once

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include "vulkan/vulkan_manager.h"

#include <memory>
#include <string>

namespace viewer {

    struct AppConfig {
        std::string title = "PE/ELF Viewer";
        uint32_t width = 1280;
        uint32_t height = 720;
    };

    class Application {
    public:
        Application() = default;
        ~Application();

        Application(const Application&) = delete;
        Application& operator=(const Application&) = delete;

        void init(const AppConfig& config = {});
        void run();
        void shutdown();

    private:
        void init_glfw(const AppConfig& config);
        void init_imgui();
        void shutdown_imgui();

        void process_input();
        void render_ui();

        static void glfw_error_callback(int error, const char* description);
        static void glfw_framebuffer_resize_callback(GLFWwindow* window, int width, int height);

        GLFWwindow* window_ = nullptr;
        VulkanManager vulkan_;
        bool running_ = false;
        bool framebuffer_resized_ = false;
    };

} // namespace viewer