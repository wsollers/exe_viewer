#pragma once

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include <array>
#include <vector>
#include <stdexcept>
#include <string>
#include <span>
#include <cstdint>

namespace viewer {

struct VulkanConfig {
    const char* app_name = "PE/ELF Viewer";
    uint32_t app_version = VK_MAKE_VERSION(1, 0, 0);
    uint32_t width = 1280;
    uint32_t height = 720;
};

class VulkanManager {
public:
    static constexpr std::size_t kMaxFramesInFlight = 2;

    struct Texture {
        VkImage image = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        VkImageView view = VK_NULL_HANDLE;
        VkDescriptorSet descriptor_set = VK_NULL_HANDLE;
        uint32_t width = 0;
        uint32_t height = 0;
    };

    VulkanManager() = default;
    ~VulkanManager();

    VulkanManager(const VulkanManager&) = delete;
    VulkanManager& operator=(const VulkanManager&) = delete;
    VulkanManager(VulkanManager&&) = delete;
    VulkanManager& operator=(VulkanManager&&) = delete;

    void init(GLFWwindow* window, const VulkanConfig& config = {});
    void shutdown();

    [[nodiscard]] bool begin_frame();
    void end_frame();

    void wait_idle();
    void recreate_swapchain(GLFWwindow* window);
    [[nodiscard]] Texture create_rgba_texture(std::span<const std::uint8_t> pixels,
                                              uint32_t width,
                                              uint32_t height);
    void destroy_texture(Texture& texture);

    // Accessors for ImGui initialization
    [[nodiscard]] uint32_t api_version() const noexcept { return api_version_; }
    [[nodiscard]] VkInstance instance() const noexcept { return instance_; }
    [[nodiscard]] VkPhysicalDevice physical_device() const noexcept { return physical_device_; }
    [[nodiscard]] VkDevice device() const noexcept { return device_; }
    [[nodiscard]] VkQueue graphics_queue() const noexcept { return graphics_queue_; }
    [[nodiscard]] uint32_t graphics_family() const noexcept { return graphics_family_; }
    [[nodiscard]] VkRenderPass render_pass() const noexcept { return render_pass_; }
    [[nodiscard]] VkDescriptorPool descriptor_pool() const noexcept { return descriptor_pool_; }
    [[nodiscard]] uint32_t min_image_count() const noexcept { return min_image_count_; }
    [[nodiscard]] uint32_t image_count() const noexcept { return static_cast<uint32_t>(swapchain_images_.size()); }
    [[nodiscard]] VkCommandBuffer current_command_buffer() const noexcept { return frame_command_buffers_[current_frame_]; }
    [[nodiscard]] VkExtent2D swapchain_extent() const noexcept { return swapchain_extent_; }

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
    [[nodiscard]] uint32_t find_memory_type(uint32_t type_filter, VkMemoryPropertyFlags properties) const;
    [[nodiscard]] VkCommandBuffer begin_one_time_commands() const;
    void end_one_time_commands(VkCommandBuffer command_buffer) const;

    static void check_vk(VkResult result, const char* msg);

    // Vulkan handles
    uint32_t api_version_ = VK_API_VERSION_1_0;
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue graphics_queue_ = VK_NULL_HANDLE;
    VkSurfaceKHR surface_ = VK_NULL_HANDLE;
    uint32_t min_image_count_ = 2;
    VkSwapchainKHR swapchain_ = VK_NULL_HANDLE;
    VkRenderPass render_pass_ = VK_NULL_HANDLE;
    VkCommandPool command_pool_ = VK_NULL_HANDLE;
    std::array<VkCommandPool, kMaxFramesInFlight> frame_command_pools_{};
    std::array<VkCommandBuffer, kMaxFramesInFlight> frame_command_buffers_{};
    VkDescriptorPool descriptor_pool_ = VK_NULL_HANDLE;

    std::vector<VkImage> swapchain_images_;
    std::vector<VkImageView> swapchain_image_views_;
    std::vector<VkFramebuffer> framebuffers_;

    VkFormat swapchain_format_ = VK_FORMAT_B8G8R8A8_SRGB;
    VkExtent2D swapchain_extent_ = {};
    uint32_t graphics_family_ = 0;
    uint32_t current_frame_ = 0;
    uint32_t current_image_index_ = 0;

    std::array<VkSemaphore, kMaxFramesInFlight> image_available_semaphores_{};
    std::vector<VkSemaphore> render_finished_semaphores_;
    std::array<VkFence, kMaxFramesInFlight> in_flight_fences_{};
    std::vector<VkFence> images_in_flight_;
    GLFWwindow* window_ = nullptr;
    bool swapchain_dirty_ = false;

    bool initialized_ = false;
};

} // namespace viewer
