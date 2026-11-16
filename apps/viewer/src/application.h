#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include "disasm/disassembler.hpp"
#include "ui/ui_app.hpp"
#include "vulkan/vulkan_manager.h"

namespace viewer {

struct AppConfig {
    std::string title = "PE/ELF Viewer";
    uint32_t width = 1280;
    uint32_t height = 720;
};

class Application {
public:
    Application() = default;
    ~Application() noexcept;

    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;
    Application(Application&&) = delete;
    Application& operator=(Application&&) = delete;

    void init(const AppConfig& config = {});
    void run();
    void shutdown() noexcept;

    void open_file_dialog();
    void open_debug_symbols_dialog();
    void save_patched_as_dialog();
    void analysis_file_dialog(int action);

private:
    class ScopedGlfwSession {
    public:
        ScopedGlfwSession() noexcept = default;
        ~ScopedGlfwSession() noexcept { reset(); }
        ScopedGlfwSession(const ScopedGlfwSession&) = delete;
        ScopedGlfwSession& operator=(const ScopedGlfwSession&) = delete;

        void init();
        void reset() noexcept;
        [[nodiscard]] bool active() const noexcept { return active_; }

    private:
        bool active_ = false;
    };

    struct GlfwWindowDeleter {
        void operator()(GLFWwindow* w) const noexcept {
            if (w != nullptr) {
                glfwDestroyWindow(w);
            }
        }
    };
    using UniqueGlfwWindow = std::unique_ptr<GLFWwindow, GlfwWindowDeleter>;

    class ScopedImGuiSession {
    public:
        ScopedImGuiSession() noexcept = default;
        ~ScopedImGuiSession() noexcept { reset(); }
        ScopedImGuiSession(const ScopedImGuiSession&) = delete;
        ScopedImGuiSession& operator=(const ScopedImGuiSession&) = delete;

        void mark_context_created() noexcept { context_created_ = true; }
        void mark_glfw_initialized() noexcept { glfw_initialized_ = true; }
        void mark_vulkan_initialized() noexcept { vulkan_initialized_ = true; }
        void reset() noexcept;

    private:
        bool context_created_ = false;
        bool glfw_initialized_ = false;
        bool vulkan_initialized_ = false;
    };

    class ScopedNfdSession {
    public:
        ScopedNfdSession() noexcept = default;
        ~ScopedNfdSession() noexcept { reset(); }
        ScopedNfdSession(const ScopedNfdSession&) = delete;
        ScopedNfdSession& operator=(const ScopedNfdSession&) = delete;

        [[nodiscard]] bool init() noexcept;
        void reset() noexcept;
        [[nodiscard]] bool active() const noexcept { return active_; }

    private:
        bool active_ = false;
    };

    class ScopedLoggerAttachment {
    public:
        ScopedLoggerAttachment() noexcept = default;
        ~ScopedLoggerAttachment() noexcept { reset(); }
        ScopedLoggerAttachment(const ScopedLoggerAttachment&) = delete;
        ScopedLoggerAttachment& operator=(const ScopedLoggerAttachment&) = delete;

        void attach(LogPanel* panel) noexcept;
        void reset() noexcept;

    private:
        bool attached_ = false;
    };

    void init_glfw(const AppConfig& config);
    void init_imgui();

    void process_input();
    void render_ui();

    static void glfw_error_callback(int error, const char* description);
    static void glfw_framebuffer_resize_callback(GLFWwindow* window, int width, int height);

    // Ordered so stack unwinding or destruction releases UI & ImGui before Vulkan,
    // window, and GLFW even if init() throws mid-sequence.
    ScopedGlfwSession glfw_;
    UniqueGlfwWindow window_;
    VulkanManager vulkan_;
    BinaryModel model_;
    ScopedImGuiSession imgui_;
    ScopedNfdSession nfd_;
    std::unique_ptr<UiApp> ui_;
    ScopedLoggerAttachment logger_attachment_;
    bool running_ = false;
    bool framebuffer_resized_ = false;
};

} // namespace viewer
