#include "application.h"
#include "ui/startup_branding.hpp"
#include "ui/theme.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string_view>

#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>
#include <nfd.h>

#include "disasm/disassembler.hpp"
#include "mapping/file_mapping.hpp"
#include "peelf/peelf.hpp"
#include "ui/logger.hpp"
#include "vulkan/vulkan_manager.h"

namespace viewer {
namespace {

[[nodiscard]] std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

constexpr float kUiFontSize = 16.0f;

struct NfdPathDeleter {
    void operator()(nfdchar_t* p) const noexcept {
        if (p != nullptr) {
            NFD_FreePath(p);
        }
    }
};
using UniqueNfdPath = std::unique_ptr<nfdchar_t, NfdPathDeleter>;

void check_imgui_vk_result(VkResult err) {
    if (err == VK_SUCCESS) {
        return;
    }
    if (err < 0) {
        Log().error("ImGui Vulkan error: VkResult={}", static_cast<int>(err));
        throw std::runtime_error("Fatal ImGui Vulkan backend error");
    }
    Log().warn("ImGui Vulkan non-fatal status: VkResult={}", static_cast<int>(err));
}

[[nodiscard]] std::filesystem::path find_monospace_font() {
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

} // namespace

void Application::ScopedGlfwSession::init() {
    reset();
    if (glfwInit() == GLFW_FALSE) {
        throw std::runtime_error("Failed to initialize GLFW");
    }
    active_ = true;
}

void Application::ScopedGlfwSession::reset() noexcept {
    if (active_) {
        glfwTerminate();
        active_ = false;
    }
}

void Application::ScopedImGuiSession::reset() noexcept {
    if (vulkan_initialized_) {
        ImGui_ImplVulkan_Shutdown();
        vulkan_initialized_ = false;
    }
    if (glfw_initialized_) {
        ImGui_ImplGlfw_Shutdown();
        glfw_initialized_ = false;
    }
    if (context_created_) {
        ImGui::DestroyContext();
        context_created_ = false;
    }
}

bool Application::ScopedNfdSession::init() noexcept {
    reset();
    if (NFD_Init() == NFD_OKAY) {
        active_ = true;
    }
    return active_;
}

void Application::ScopedNfdSession::reset() noexcept {
    if (active_) {
        NFD_Quit();
        active_ = false;
    }
}

void Application::ScopedLoggerAttachment::attach(LogPanel* panel) noexcept {
    Logger::instance().init(panel, panel != nullptr ? std::optional<std::size_t>(panel->capacity()) : std::nullopt);
    attached_ = (panel != nullptr);
}

void Application::ScopedLoggerAttachment::reset() noexcept {
    if (attached_) {
        Logger::instance().init(nullptr);
        attached_ = false;
    }
}

Application::~Application() noexcept {
    shutdown();
}

void Application::glfw_error_callback(int error, const char* description) {
    std::fprintf(stderr, "GLFW Error %d: %s\n", error, description != nullptr ? description : "");
}

void Application::glfw_framebuffer_resize_callback(GLFWwindow* window, int /*width*/, int /*height*/) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (app != nullptr) {
        app->framebuffer_resized_ = true;
    }
}

void Application::init(const AppConfig& config) {
    shutdown();

    try {
        init_glfw(config);

        VulkanConfig vk_config{};
        vk_config.app_name = config.title.c_str();
        vk_config.width = config.width;
        vk_config.height = config.height;

        vulkan_.init(window_.get(), vk_config);

        ui_ = std::make_unique<UiApp>(model_, vulkan_);
        ui_->set_exit_callback([this]() { glfwSetWindowShouldClose(window_.get(), GLFW_TRUE); });
        ui_->set_analysis_file_callback([this](int action) { analysis_file_dialog(action); });
        ui_->set_open_file_callback([this]() { open_file_dialog(); });
        ui_->set_open_debug_symbols_callback([this]() { open_debug_symbols_dialog(); });
        ui_->set_save_patched_as_callback([this]() { save_patched_as_dialog(); });
        logger_attachment_.attach(&ui_->log_panel());

        init_imgui();

        if (!nfd_.init()) {
            Log().error("Failed to initialize native file dialog (NFD)");
        }

        running_ = true;
    } catch (...) {
        shutdown();
        throw;
    }
}

void Application::init_glfw(const AppConfig& config) {
    glfwSetErrorCallback(glfw_error_callback);
    glfw_.init();

    if (glfwVulkanSupported() == GLFW_FALSE) {
        throw std::runtime_error("Vulkan not supported");
    }

    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);

    window_.reset(glfwCreateWindow(
        static_cast<int>(config.width),
        static_cast<int>(config.height),
        config.title.c_str(),
        nullptr,
        nullptr));

    if (!window_) {
        throw std::runtime_error("Failed to create GLFW window");
    }

    set_window_branding(window_.get());
    glfwSetWindowUserPointer(window_.get(), this);
    glfwSetFramebufferSizeCallback(window_.get(), glfw_framebuffer_resize_callback);
}

void Application::init_imgui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    imgui_.mark_context_created();
    if (ui_) {
        ui_->register_workspace_settings_handler();
    }

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigDpiScaleFonts = true;

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

    ui_->set_code_font(io.Fonts->Fonts[0]);
#ifdef _WIN32
    const std::filesystem::path ui_font = LR"(C:\Windows\Fonts\segoeui.ttf)";
    if (std::filesystem::exists(ui_font)) {
        if (auto* font = io.Fonts->AddFontFromFileTTF(ui_font.string().c_str(), kUiFontSize)) {
            io.FontDefault = font;
        }
    }
#endif
    float content_scale_x = 1.0f;
    float content_scale_y = 1.0f;
    glfwGetWindowContentScale(window_.get(), &content_scale_x, &content_scale_y);
    ui::load_theme(content_scale_x);
    if (!ImGui_ImplGlfw_InitForVulkan(window_.get(), true)) {
        throw std::runtime_error("ImGui_ImplGlfw_InitForVulkan failed");
    }
    imgui_.mark_glfw_initialized();

    ImGui_ImplVulkan_InitInfo init_info{};
    init_info.ApiVersion = vulkan_.api_version();
    init_info.Instance = vulkan_.instance();
    init_info.PhysicalDevice = vulkan_.physical_device();
    init_info.Device = vulkan_.device();
    init_info.QueueFamily = vulkan_.graphics_family();
    init_info.Queue = vulkan_.graphics_queue();
    init_info.DescriptorPool = vulkan_.descriptor_pool();
    init_info.DescriptorPoolSize = 0; // use external pool
    init_info.MinImageCount = vulkan_.min_image_count();
    init_info.ImageCount = vulkan_.image_count();
    init_info.PipelineCache = VK_NULL_HANDLE;

    init_info.PipelineInfoMain = {};
    init_info.PipelineInfoMain.RenderPass = vulkan_.render_pass();
    init_info.PipelineInfoMain.Subpass = 0;
    init_info.PipelineInfoMain.MSAASamples = VK_SAMPLE_COUNT_1_BIT;

    init_info.PipelineInfoForViewports = init_info.PipelineInfoMain;

    init_info.UseDynamicRendering = false;
    init_info.Allocator = nullptr;
    init_info.CheckVkResultFn = check_imgui_vk_result;
    init_info.MinAllocationSize = 0;
    init_info.CustomShaderVertCreateInfo = {};
    init_info.CustomShaderFragCreateInfo = {};

    if (!ImGui_ImplVulkan_Init(&init_info)) {
        throw std::runtime_error("ImGui_ImplVulkan_Init failed");
    }
    imgui_.mark_vulkan_initialized();
    // Dear ImGui 1.92+ uses ImGuiBackendFlags_RendererHasTextures and uploads
    // ImTextureData font atlases automatically during ImGui_ImplVulkan_RenderDrawData.
}

void Application::shutdown() noexcept {
    vulkan_.wait_idle();
    logger_attachment_.reset();
    ui_.reset();
    nfd_.reset();
    imgui_.reset();
    vulkan_.shutdown();
    window_.reset();
    glfw_.reset();
    running_ = false;
}

void Application::run() {
    while (window_ && !glfwWindowShouldClose(window_.get())) {
        glfwPollEvents();
        process_input();

        if (framebuffer_resized_) {
            vulkan_.recreate_swapchain(window_.get());
            framebuffer_resized_ = false;
        }

        try {
            ui_->process_deferred_gpu_work();
        } catch (const std::exception& e) {
            Log().error("Deferred GPU/UI work failed: {}", e.what());
        } catch (...) {
            Log().error("Deferred GPU/UI work failed with an unknown exception");
        }

        if (!vulkan_.begin_frame()) {
            glfwWaitEventsTimeout(0.01);
            continue;
        }

        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        render_ui();

        ImGui::Render();
        ImGui_ImplVulkan_RenderDrawData(ImGui::GetDrawData(), vulkan_.current_command_buffer());

        vulkan_.end_frame();
    }
}

void Application::process_input() {
    if (glfwGetKey(window_.get(), GLFW_KEY_ESCAPE) == GLFW_PRESS) {
        glfwSetWindowShouldClose(window_.get(), GLFW_TRUE);
    }
}

void Application::render_ui() {
    ui_->render();
}

void Application::open_file_dialog() {
    if (!nfd_.active()) {
        Log().error("Cannot open file dialog: NFD not initialized");
        return;
    }

    nfdchar_t* raw_out_path = nullptr;
    constexpr std::array<nfdfilteritem_t, 3> filters{{
        {"Executables & Crash Dumps", "exe,dll,so,elf,dmp,mdmp,core"},
        {"Crash Dumps (.dmp, .core)", "dmp,mdmp,core"},
        {"All Files", "*"},
    }};

    const nfdresult_t result = NFD_OpenDialog(&raw_out_path, filters.data(), static_cast<nfdfiltersize_t>(filters.size()), nullptr);
    UniqueNfdPath out_path(raw_out_path);

    if (result == NFD_OKAY && out_path) {
        const std::string path(out_path.get());
        out_path.reset();

        if (model_.load_file(path)) {
            Log().info("Loaded file: {}", path);
            ui_->on_file_loaded();
        } else {
            Log().error("Did not load file: {}", path);
        }
    } else if (result == NFD_ERROR) {
        Log().error("File dialog error: {}", NFD_GetError());
    }
}

void Application::open_debug_symbols_dialog() {
    if (!nfd_.active()) {
        Log().error("Cannot open debug symbol dialog: NFD not initialized");
        return;
    }

    if (model_.image() == nullptr) {
        Log().warn("Open an executable before loading debug symbols");
        return;
    }

    nfdchar_t* raw_out_path = nullptr;
    constexpr std::array<nfdfilteritem_t, 2> filters{{
        {"Debug Symbols (PDB / DWARF)", "pdb,debug,dbg,elf,so,dll,exe"},
        {"All Files", "*"},
    }};

    const nfdresult_t result = NFD_OpenDialog(&raw_out_path, filters.data(), static_cast<nfdfiltersize_t>(filters.size()), nullptr);
    UniqueNfdPath out_path(raw_out_path);
    if (result == NFD_OKAY && out_path) {
        const std::string path(out_path.get());
        out_path.reset();
        ui_->load_debug_symbols(utf8_path(path));
    } else if (result == NFD_ERROR) {
        Log().error("Debug symbol dialog error: {}", NFD_GetError());
    }
}

void Application::analysis_file_dialog(int action) {
    if (!nfd_.active()) {
        return;
    }
    nfdchar_t* raw_path = nullptr;
    if (action == 4) {
        constexpr std::array<nfdfilteritem_t, 2> filters{{
            {"Crash Dumps (.dmp, .mdmp, .core)", "dmp,mdmp,core"},
            {"All Files", "*"},
        }};
        if (NFD_OpenDialog(&raw_path, filters.data(), static_cast<nfdfiltersize_t>(filters.size()), nullptr) == NFD_OKAY) {
            UniqueNfdPath guard(raw_path);
            const std::string selected(guard.get());
            guard.reset();
            if (model_.load_file(selected)) {
                Log().info("Loaded crash dump: {}", selected);
                ui_->on_file_loaded();
            } else {
                Log().error("Failed to open crash dump '{}': {}", selected, model_.last_diagnostic());
            }
        }
        return;
    }
    if (action == 3) {
        constexpr std::array<nfdfilteritem_t, 2> filters{{
            {"Executables", "exe,dll,so,elf,bin,sys"},
            {"All Files", "*"},
        }};
        if (NFD_OpenDialog(&raw_path, filters.data(), static_cast<nfdfiltersize_t>(filters.size()), nullptr) == NFD_OKAY) {
            UniqueNfdPath guard(raw_path);
            const std::filesystem::path selected = utf8_path(guard.get());
            guard.reset();
            if (auto cmp = ui_->compare_with_binary(selected); cmp) {
                Log().info("Compared binary against: {}", selected.string());
            } else {
                Log().error("Binary Diff: {}", cmp.error().message);
            }
        }
        return;
    }
    const nfdfilteritem_t filter{
        action == 2 ? "Patch report" : "Analysis project",
        action == 2 ? "txt" : "peproj",
    };
    const nfdresult_t result = action == 0
        ? NFD_OpenDialog(&raw_path, &filter, 1, nullptr)
        : NFD_SaveDialog(&raw_path, &filter, 1, nullptr, nullptr);
    UniqueNfdPath guard(raw_path);
    if (result == NFD_OKAY && guard) {
        const std::filesystem::path selected = utf8_path(guard.get());
        guard.reset();
        auto saved = action == 0
            ? ui_->open_project(selected)
            : action == 1 ? ui_->save_project(selected) : ui_->save_patch_report(selected);
        if (saved) {
            Log().info("{}: {}", action == 0 ? "Project restored" : "Saved", selected.string());
        } else {
            Log().error("Analysis file: {}", saved.error().message);
        }
    } else if (result == NFD_ERROR) {
        Log().error("Analysis file dialog: {}", NFD_GetError());
    }
}

void Application::save_patched_as_dialog() {
    if (!nfd_.active()) {
        Log().error("Cannot open save dialog: NFD not initialized");
        return;
    }

    if (model_.editable_image() == nullptr) {
        Log().warn("Open a static executable before saving patched bytes");
        return;
    }

    if (model_.changed_intervals().empty()) {
        Log().warn("No staged patches to save");
        return;
    }

    nfdchar_t* raw_out_path = nullptr;
    constexpr std::array<nfdfilteritem_t, 2> filters{{
        {"Executables", "exe,dll,so,elf,bin"},
        {"All Files", "*"},
    }};

    const nfdresult_t result = NFD_SaveDialog(
        &raw_out_path, filters.data(), static_cast<nfdfiltersize_t>(filters.size()), nullptr, nullptr);
    UniqueNfdPath out_path(raw_out_path);
    if (result == NFD_OKAY && out_path) {
        const std::string path(out_path.get());
        out_path.reset();
        auto saved = model_.save_patched_as(utf8_path(path));
        if (saved) {
            Log().info("Saved patched image: {}", path);
        } else {
            Log().error("Did not save patched image: {}", saved.error().message);
        }
    } else if (result == NFD_ERROR) {
        Log().error("Save dialog error: {}", NFD_GetError());
    }
}

} // namespace viewer
