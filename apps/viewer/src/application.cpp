#include "application.h"

#include <cstdio>
#include <stdexcept>

#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>
#include <nfd.h>

#include "gui/gui.h"
#include "vulkan/vulkan_manager.h"
#include "peelf/peelf.hpp"
#include "mapping/file_mapping.hpp"
#include "pe/pe_parser.h"
#include "ui/logger.hpp"
#include "dissassembler/dissassembler.hpp"

namespace viewer {
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
        ui_ = new UiApp(model_);
        ui_->set_open_file_callback([this]() {
            open_file_dialog();
        });
        Logger::instance().init(&ui_->log_panel());

        init_imgui();

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
        shutdown_imgui();
        vulkan_.shutdown();

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
        NFD_Init();

        nfdchar_t *out_path = nullptr;
        nfdfilteritem_t filters[2] = {
            {"Executables", "exe,dll,so,elf"},
            {"All Files", "*"}
        };

        nfdresult_t result = NFD_OpenDialog(&out_path, filters, 2, nullptr);

        if (result == NFD_OKAY) {
            std::string path(out_path);
            free(out_path);

            if (model_.load_file(path)) {
                // Optional: log success
                Log().info("Loaded file: " + path);
                ui_->on_file_loaded();

            } else {
                Log().error("Did not load file: " + path);
            }
        }
    }


}


