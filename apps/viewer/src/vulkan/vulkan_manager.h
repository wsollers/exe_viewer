#pragma once

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include <vector>
#include <stdexcept>
#include <string>

namespace viewer {

struct VulkanConfig {
    const char* app_name = "PE/ELF Viewer";
    uint32_t app_version = VK_MAKE_VERSION(1, 0, 0);
    uint32_t width = 1280;
    uint32_t height = 720;
};

class VulkanManager {
public:
    VulkanManager() = default;
    ~VulkanManager();

    VulkanManager(const VulkanManager&) = delete;
    VulkanManager& operator=(const VulkanManager&) = delete;
    VulkanManager(VulkanManager&&) = delete;
    VulkanManager& operator=(VulkanManager&&) = delete;

    void init(GLFWwindow* window, const VulkanConfig& config = {});
    void shutdown();

    void begin_frame();
    void end_frame();

    void wait_idle();
    void recreate_swapchain(GLFWwindow* window);

    // Accessors for ImGui initialization
    [[nodiscard]] VkInstance instance() const { return instance_; }
    [[nodiscard]] VkPhysicalDevice physical_device() const { return physical_device_; }
    [[nodiscard]] VkDevice device() const { return device_; }
    [[nodiscard]] VkQueue graphics_queue() const { return graphics_queue_; }
    [[nodiscard]] uint32_t graphics_family() const { return graphics_family_; }
    [[nodiscard]] VkRenderPass render_pass() const { return render_pass_; }
    [[nodiscard]] VkDescriptorPool descriptor_pool() const { return descriptor_pool_; }
    [[nodiscard]] uint32_t image_count() const { return static_cast<uint32_t>(swapchain_images_.size()); }
    [[nodiscard]] VkCommandBuffer current_command_buffer() const { return command_buffers_[current_image_index_]; }
    [[nodiscard]] VkExtent2D swapchain_extent() const { return swapchain_extent_; }

private:
    void create_instance(const VulkanConfig& config);
    void create_surface(GLFWwindow* window);
    void select_physical_device();
    void create_logical_device();
    void create_render_pass();
    void create_swapchain(GLFWwindow* window);
    void create_framebuffers();
    void create_command_pool();
    void create_command_buffers();
    void create_descriptor_pool();
    void create_sync_objects();

    void cleanup_swapchain();

    static void check_vk(VkResult result, const char* msg);

    // Vulkan handles
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue graphics_queue_ = VK_NULL_HANDLE;
    VkSurfaceKHR surface_ = VK_NULL_HANDLE;
    VkSwapchainKHR swapchain_ = VK_NULL_HANDLE;
    VkRenderPass render_pass_ = VK_NULL_HANDLE;
    VkCommandPool command_pool_ = VK_NULL_HANDLE;
    VkDescriptorPool descriptor_pool_ = VK_NULL_HANDLE;

    std::vector<VkImage> swapchain_images_;
    std::vector<VkImageView> swapchain_image_views_;
    std::vector<VkFramebuffer> framebuffers_;
    std::vector<VkCommandBuffer> command_buffers_;

    VkFormat swapchain_format_ = VK_FORMAT_B8G8R8A8_SRGB;
    VkExtent2D swapchain_extent_ = {};
    uint32_t graphics_family_ = 0;
    uint32_t current_image_index_ = 0;

    VkSemaphore image_available_semaphore_ = VK_NULL_HANDLE;
    VkSemaphore render_finished_semaphore_ = VK_NULL_HANDLE;
    VkFence in_flight_fence_ = VK_NULL_HANDLE;

    bool initialized_ = false;
};

} // namespace viewer