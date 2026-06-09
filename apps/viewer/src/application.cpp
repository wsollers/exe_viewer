#include "application.h"

#include <array>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string_view>

#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>
#include <nfd.h>

#include "vulkan/vulkan_manager.h"
#include "peelf/peelf.hpp"
#include "mapping/file_mapping.hpp"
#include "pe/pe_parser.h"
#include "ui/logger.hpp"
#include "disasm/disassembler.hpp"

namespace viewer {
    namespace {
        constexpr float kUiFontSize = 18.0f;

        std::filesystem::path find_monospace_font() {
#ifdef _WIN32
            constexpr std::array<std::wstring_view, 5> candidates{
                L"CascadiaMono.ttf",
                L"CascadiaCode.ttf",
                L"consola.ttf",
                L"lucon.ttf",
                L"cour.ttf",
            };
            const std::filesystem::path fonts_dir = LR"(C:\Windows\Fonts)";
            for (const std::wstring_view candidate : candidates) {
                std::filesystem::path path = fonts_dir / candidate;
                if (std::filesystem::exists(path)) {
                    return path;
                }
            }
#endif
            return {};
        }
    }

    Application::~Application() {
        if (running_) {
            shutdown();
        }
    }

    void Application::glfw_error_callback(int error, const char *description) {
        fprintf(stderr, "GLFW Error %d: %s\n", error, description);
    }

    void Application::glfw_framebuffer_resize_callback(GLFWwindow *window, int /*width*/, int /*height*/) {
        auto *app = static_cast<Application *>(glfwGetWindowUserPointer(window));
        if (app) {
            app->framebuffer_resized_ = true;
        }
    }

    void Application::init(const AppConfig &config) {
        init_glfw(config);

        VulkanConfig vk_config{};
        vk_config.app_name = config.title.c_str();
        vk_config.width = config.width;
        vk_config.height = config.height;

        vulkan_.init(window_, vk_config);

        // Initialize model/UI
        ui_ = new UiApp(model_, vulkan_);
        ui_->set_open_file_callback([this]() {
            open_file_dialog();
        });
        ui_->set_open_debug_symbols_callback([this]() {
            open_debug_symbols_dialog();
        });
        Logger::instance().init(&ui_->log_panel());

        init_imgui();

        if (NFD_Init() == NFD_OKAY) {
            nfd_initialized_ = true;
        } else {
            Log().error("Failed to initialize native file dialog (NFD)");
        }

        running_ = true;
    }

    void Application::init_glfw(const AppConfig &config) {
        glfwSetErrorCallback(glfw_error_callback);

        if (!glfwInit()) {
            throw std::runtime_error("Failed to initialize GLFW");
        }

        if (!glfwVulkanSupported()) {
            glfwTerminate();
            throw std::runtime_error("Vulkan not supported");
        }

        glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
        glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);

        window_ = glfwCreateWindow(
            static_cast<int>(config.width),
            static_cast<int>(config.height),
            config.title.c_str(),
            nullptr,
            nullptr
        );

        if (!window_) {
            glfwTerminate();
            throw std::runtime_error("Failed to create GLFW window");
        }

        glfwSetWindowUserPointer(window_, this);
        glfwSetFramebufferSizeCallback(window_, glfw_framebuffer_resize_callback);
    }

    void Application::init_imgui() {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();

        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

        const std::filesystem::path font_path = find_monospace_font();
        if (!font_path.empty()) {
            const std::string font_path_string = font_path.string();
            if (io.Fonts->AddFontFromFileTTF(font_path_string.c_str(), kUiFontSize) != nullptr) {
                Log().info("Loaded UI monospace font: {}", font_path.string());
            } else {
                ImFontConfig config{};
                config.SizePixels = kUiFontSize;
                io.Fonts->AddFontDefault(&config);
                Log().warn("Failed to load monospace font {}; using enlarged ImGui default",
                           font_path.string());
            }
        } else {
            ImFontConfig config{};
            config.SizePixels = kUiFontSize;
            io.Fonts->AddFontDefault(&config);
            Log().warn("No system monospace font found; using enlarged ImGui default");
        }

        ImGui::StyleColorsDark();
        ImGui_ImplGlfw_InitForVulkan(window_, true);

        ImGui_ImplVulkan_InitInfo init_info{};
        init_info.ApiVersion = VK_API_VERSION_1_3; // or your app's version
        init_info.Instance = vulkan_.instance();
        init_info.PhysicalDevice = vulkan_.physical_device();
        init_info.Device = vulkan_.device();
        init_info.QueueFamily = vulkan_.graphics_family();
        init_info.Queue = vulkan_.graphics_queue();
        init_info.DescriptorPool = vulkan_.descriptor_pool();
        init_info.DescriptorPoolSize = 0; // use external pool
        init_info.MinImageCount = vulkan_.image_count();
        init_info.ImageCount = vulkan_.image_count();
        init_info.PipelineCache = VK_NULL_HANDLE;

        // --- THIS IS THE CRITICAL PART ---
        // Fill PipelineInfoMain so the backend can create its pipeline.
        init_info.PipelineInfoMain = {};
        init_info.PipelineInfoMain.RenderPass = vulkan_.render_pass();
        init_info.PipelineInfoMain.Subpass = 0;
        init_info.PipelineInfoMain.MSAASamples = VK_SAMPLE_COUNT_1_BIT;

        // For now, mirror main pipeline info for secondary viewports
        init_info.PipelineInfoForViewports = init_info.PipelineInfoMain;

        init_info.UseDynamicRendering = false;
        init_info.Allocator = nullptr;
        init_info.CheckVkResultFn = nullptr;
        init_info.MinAllocationSize = 0;
        init_info.CustomShaderVertCreateInfo = {};
        init_info.CustomShaderFragCreateInfo = {};

        if (!ImGui_ImplVulkan_Init(&init_info)) {
            throw std::runtime_error("ImGui_ImplVulkan_Init failed");
        }

        // --- FONTS ---
        // Your backend version DOES NOT use ImGui_ImplVulkan_CreateFontsTexture(cmd)
        // Instead, it uses the NEW internal upload mechanism:
        //    ImGui_ImplVulkan_CreateFontsTexture(); // <-- NO ARGUMENT VERSION

        // After this, the backend has a valid font texture and descriptor set.
    }

    void Application::shutdown_imgui() {
        ImGui_ImplVulkan_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
    }

    void Application::shutdown() {
        if (!running_) return;

        vulkan_.wait_idle();
        delete ui_;
        ui_ = nullptr;
        shutdown_imgui();
        vulkan_.shutdown();

        if (nfd_initialized_) {
            NFD_Quit();
            nfd_initialized_ = false;
        }

        if (window_) {
            glfwDestroyWindow(window_);
            window_ = nullptr;
        }

        glfwTerminate();
        running_ = false;
    }

    void Application::run() {
        while (!glfwWindowShouldClose(window_)) {
            glfwPollEvents();
            process_input();

            if (framebuffer_resized_) {
                vulkan_.recreate_swapchain(window_);
                framebuffer_resized_ = false;
            }

            // Start frame
            vulkan_.begin_frame();

            // ImGui frame
            ImGui_ImplVulkan_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            render_ui();

            // Render ImGui
            ImGui::Render();
            ImGui_ImplVulkan_RenderDrawData(ImGui::GetDrawData(), vulkan_.current_command_buffer());

            // End frame
            vulkan_.end_frame();
        }
    }

    void Application::process_input() {
        if (glfwGetKey(window_, GLFW_KEY_ESCAPE) == GLFW_PRESS) {
            glfwSetWindowShouldClose(window_, GLFW_TRUE);
        }
    }

    void Application::render_ui() {
        ui_->render();
    }



    void Application::open_file_dialog() {
        if (!nfd_initialized_) {
            Log().error("Cannot open file dialog: NFD not initialized");
            return;
        }

        nfdchar_t *out_path = nullptr;
        nfdfilteritem_t filters[2] = {
            {"Executables", "exe,dll,so,elf"},
            {"All Files", "*"}
        };

        nfdresult_t result = NFD_OpenDialog(&out_path, filters, 2, nullptr);

        if (result == NFD_OKAY) {
            std::string path(out_path);
            NFD_FreePath(out_path);

            if (model_.load_file(path)) {
                Log().info("Loaded file: " + path);
                ui_->on_file_loaded();
            } else {
                Log().error("Did not load file: " + path);
            }
        } else if (result == NFD_ERROR) {
            Log().error(std::string("File dialog error: ") + NFD_GetError());
        }
        // NFD_CANCEL: user cancelled; nothing to do.
    }

    void Application::open_debug_symbols_dialog() {
        if (!nfd_initialized_) {
            Log().error("Cannot open debug symbol dialog: NFD not initialized");
            return;
        }

        if (model_.image() == nullptr) {
            Log().warn("Open an executable before loading debug symbols");
            return;
        }

        nfdchar_t *out_path = nullptr;
        nfdfilteritem_t filters[2] = {
            {"Program Database", "pdb"},
            {"All Files", "*"}
        };

        nfdresult_t result = NFD_OpenDialog(&out_path, filters, 2, nullptr);
        if (result == NFD_OKAY) {
            std::string path(out_path);
            NFD_FreePath(out_path);
            ui_->load_debug_symbols(path);
        } else if (result == NFD_ERROR) {
            Log().error(std::string("Debug symbol dialog error: ") + NFD_GetError());
        }
    }


}
