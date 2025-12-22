#include "application.h"

#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>

#include <cstdio>
#include <stdexcept>

#include "application.h"

#include "gui/gui.h"
#include "vulkan/vulkan_manager.h"
#include "peelf/peelf.hpp"
#include "mapping/file_mapping.hpp"
#include "pe/pe_parser.h"


namespace viewer {

Application::~Application() {
    if (running_) {
        shutdown();
    }
}

void Application::glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

void Application::glfw_framebuffer_resize_callback(GLFWwindow* window, int /*width*/, int /*height*/) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (app) {
        app->framebuffer_resized_ = true;
    }
}

void Application::init(const AppConfig& config) {
    init_glfw(config);

    VulkanConfig vk_config{};
    vk_config.app_name = config.title.c_str();
    vk_config.width = config.width;
    vk_config.height = config.height;

    vulkan_.init(window_, vk_config);
    init_imgui();

    running_ = true;
}

void Application::init_glfw(const AppConfig& config) {
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

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForVulkan(window_, true);

    ImGui_ImplVulkan_InitInfo init_info{};
    init_info.ApiVersion        = VK_API_VERSION_1_3; // or your app's version
    init_info.Instance          = vulkan_.instance();
    init_info.PhysicalDevice    = vulkan_.physical_device();
    init_info.Device            = vulkan_.device();
    init_info.QueueFamily       = vulkan_.graphics_family();
    init_info.Queue             = vulkan_.graphics_queue();
    init_info.DescriptorPool    = vulkan_.descriptor_pool();
    init_info.DescriptorPoolSize= 0; // use external pool
    init_info.MinImageCount     = vulkan_.image_count();
    init_info.ImageCount        = vulkan_.image_count();
    init_info.PipelineCache     = VK_NULL_HANDLE;

    // --- THIS IS THE CRITICAL PART ---
    // Fill PipelineInfoMain so the backend can create its pipeline.
    init_info.PipelineInfoMain = {};
    init_info.PipelineInfoMain.RenderPass  = vulkan_.render_pass();
    init_info.PipelineInfoMain.Subpass     = 0;
    init_info.PipelineInfoMain.MSAASamples = VK_SAMPLE_COUNT_1_BIT;

    // For now, mirror main pipeline info for secondary viewports
    init_info.PipelineInfoForViewports = init_info.PipelineInfoMain;

    init_info.UseDynamicRendering = false;
    init_info.Allocator           = nullptr;
    init_info.CheckVkResultFn     = nullptr;
    init_info.MinAllocationSize   = 0;
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
     // Main menu bar
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open", "Ctrl+O")) {
                if (auto path = open_file_dialog()) {
                    load_file(*path);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                glfwSetWindowShouldClose(window_, GLFW_TRUE);
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Demo Window", nullptr, false);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) {
                // TODO: Show about dialog
            }
            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }

    // Main dockspace
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("DockSpace", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);

    ImGui::End();

    // File info panel
    ImGui::Begin("File Info");
    ImGui::Text("No file loaded");
    ImGui::Separator();
    ImGui::Text("Drag and drop a PE or ELF file to analyze");
    ImGui::End();

    // Sections panel
    ImGui::Begin("Sections");
    ImGui::Text("No sections to display");
    ImGui::End();

    // Hex view panel
    ImGui::Begin("Hex View");
    ImGui::Text("No data to display");
    ImGui::End();

    // Demo window for testing
    static bool show_demo = false;
    if (show_demo) {
        ImGui::ShowDemoWindow(&show_demo);
    }
   // Placeholder for GUI rendering code

    Gui gui { window_};
    gui.displayGui();
}
    std::optional<std::string> Application::open_file_dialog() {
    NFD_Init();

    nfdchar_t* out_path = nullptr;
    nfdfilteritem_t filters[2] = {
        { "Executables", "exe,dll,so,elf" },
        { "All Files", "*" }
    };

    nfdresult_t result = NFD_OpenDialog(&out_path, filters, 2, nullptr);

    std::optional<std::string> path;

    if (result == NFD_OKAY) {
        path = std::string(out_path);
        NFD_FreePath(out_path);
    } else if (result == NFD_CANCEL) {
        // User cancelled - not an error
    } else {
        fprintf(stderr, "File dialog error: %s\n", NFD_GetError());
    }

    NFD_Quit();
    return path;
}
    void Application::load_file(const std::string& path) {
    // TODO: Use your peelf_core library to parse the file

    bool file_loaded_ = true;

    printf("Loading file: %s\n", path.c_str());
//
    // Example:
    try {
        std::filesystem::path fileToOpen(path);
        peelf::FileMapping<std::uint8_t, peelf::NativeFileMappingBackend> map(fileToOpen,peelf::MapMode::read_only);

        size_t size = map.size();
        size_t sizeBytes = map.size_bytes();
        const std::span<std::uint8_t> data = map.view();
        auto rc = peelf::parse_pe_bytes(data);
         // Store parsed data...
    } catch (const std::exception& e) {
         fprintf(stderr, "Failed to load file: %s\n", e.what());
        file_loaded_ = false;
    }
}
} // namespace viewer