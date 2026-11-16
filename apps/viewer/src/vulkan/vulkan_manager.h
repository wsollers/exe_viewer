#pragma once

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace viewer {

struct VulkanConfig {
    const char* app_name = "PE/ELF Viewer";
    uint32_t app_version = VK_MAKE_VERSION(1, 0, 0);
    uint32_t width = 1280;
    uint32_t height = 720;
};

namespace detail {

class VkInstanceOwner {
public:
    VkInstanceOwner() noexcept = default;
    explicit VkInstanceOwner(VkInstance instance) noexcept : instance_(instance) {}
    ~VkInstanceOwner() noexcept { reset(); }

    VkInstanceOwner(const VkInstanceOwner&) = delete;
    VkInstanceOwner& operator=(const VkInstanceOwner&) = delete;

    VkInstanceOwner(VkInstanceOwner&& other) noexcept
        : instance_(std::exchange(other.instance_, VK_NULL_HANDLE)) {}

    VkInstanceOwner& operator=(VkInstanceOwner&& other) noexcept {
        if (this != &other) {
            reset();
            instance_ = std::exchange(other.instance_, VK_NULL_HANDLE);
        }
        return *this;
    }

    void reset(VkInstance next = VK_NULL_HANDLE) noexcept {
        if (instance_ != VK_NULL_HANDLE) {
            vkDestroyInstance(instance_, nullptr);
        }
        instance_ = next;
    }

    [[nodiscard]] VkInstance get() const noexcept { return instance_; }
    [[nodiscard]] explicit operator bool() const noexcept { return instance_ != VK_NULL_HANDLE; }

private:
    VkInstance instance_ = VK_NULL_HANDLE;
};

class VkSurfaceOwner {
public:
    VkSurfaceOwner() noexcept = default;
    VkSurfaceOwner(VkInstance instance, VkSurfaceKHR surface) noexcept
        : instance_(instance), surface_(surface) {}
    ~VkSurfaceOwner() noexcept { reset(); }

    VkSurfaceOwner(const VkSurfaceOwner&) = delete;
    VkSurfaceOwner& operator=(const VkSurfaceOwner&) = delete;

    VkSurfaceOwner(VkSurfaceOwner&& other) noexcept
        : instance_(std::exchange(other.instance_, VK_NULL_HANDLE))
        , surface_(std::exchange(other.surface_, VK_NULL_HANDLE)) {}

    VkSurfaceOwner& operator=(VkSurfaceOwner&& other) noexcept {
        if (this != &other) {
            reset();
            instance_ = std::exchange(other.instance_, VK_NULL_HANDLE);
            surface_ = std::exchange(other.surface_, VK_NULL_HANDLE);
        }
        return *this;
    }

    void reset(VkInstance instance = VK_NULL_HANDLE, VkSurfaceKHR surface = VK_NULL_HANDLE) noexcept {
        if (instance_ != VK_NULL_HANDLE && surface_ != VK_NULL_HANDLE) {
            vkDestroySurfaceKHR(instance_, surface_, nullptr);
        }
        instance_ = instance;
        surface_ = surface;
    }

    [[nodiscard]] VkSurfaceKHR get() const noexcept { return surface_; }
    [[nodiscard]] explicit operator bool() const noexcept { return surface_ != VK_NULL_HANDLE; }

private:
    VkInstance instance_ = VK_NULL_HANDLE;
    VkSurfaceKHR surface_ = VK_NULL_HANDLE;
};

class VkDeviceOwner {
public:
    VkDeviceOwner() noexcept = default;
    explicit VkDeviceOwner(VkDevice device) noexcept : device_(device) {}
    ~VkDeviceOwner() noexcept { reset(); }

    VkDeviceOwner(const VkDeviceOwner&) = delete;
    VkDeviceOwner& operator=(const VkDeviceOwner&) = delete;

    VkDeviceOwner(VkDeviceOwner&& other) noexcept
        : device_(std::exchange(other.device_, VK_NULL_HANDLE)) {}

    VkDeviceOwner& operator=(VkDeviceOwner&& other) noexcept {
        if (this != &other) {
            reset();
            device_ = std::exchange(other.device_, VK_NULL_HANDLE);
        }
        return *this;
    }

    void reset(VkDevice next = VK_NULL_HANDLE) noexcept {
        if (device_ != VK_NULL_HANDLE) {
            (void)vkDeviceWaitIdle(device_);
            vkDestroyDevice(device_, nullptr);
        }
        device_ = next;
    }

    [[nodiscard]] VkDevice get() const noexcept { return device_; }
    [[nodiscard]] explicit operator bool() const noexcept { return device_ != VK_NULL_HANDLE; }

private:
    VkDevice device_ = VK_NULL_HANDLE;
};

template <typename Handle, typename Deleter>
class ScopedVkDeviceHandle {
public:
    ScopedVkDeviceHandle() noexcept = default;
    ScopedVkDeviceHandle(VkDevice device, Handle handle) noexcept
        : device_(device), handle_(handle) {}
    ~ScopedVkDeviceHandle() noexcept { reset(); }

    ScopedVkDeviceHandle(const ScopedVkDeviceHandle&) = delete;
    ScopedVkDeviceHandle& operator=(const ScopedVkDeviceHandle&) = delete;

    ScopedVkDeviceHandle(ScopedVkDeviceHandle&& other) noexcept
        : device_(std::exchange(other.device_, VK_NULL_HANDLE))
        , handle_(std::exchange(other.handle_, VK_NULL_HANDLE)) {}

    ScopedVkDeviceHandle& operator=(ScopedVkDeviceHandle&& other) noexcept {
        if (this != &other) {
            reset();
            device_ = std::exchange(other.device_, VK_NULL_HANDLE);
            handle_ = std::exchange(other.handle_, VK_NULL_HANDLE);
        }
        return *this;
    }

    void reset(VkDevice device = VK_NULL_HANDLE, Handle handle = VK_NULL_HANDLE) noexcept {
        if (device_ != VK_NULL_HANDLE && handle_ != VK_NULL_HANDLE) {
            Deleter{}(device_, handle_);
        }
        device_ = device;
        handle_ = handle;
    }

    [[nodiscard]] Handle release() noexcept {
        device_ = VK_NULL_HANDLE;
        return std::exchange(handle_, VK_NULL_HANDLE);
    }

    [[nodiscard]] Handle get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept { return handle_ != VK_NULL_HANDLE; }

private:
    VkDevice device_ = VK_NULL_HANDLE;
    Handle handle_ = VK_NULL_HANDLE;
};

struct RenderPassDeleter {
    void operator()(VkDevice d, VkRenderPass h) const noexcept { vkDestroyRenderPass(d, h, nullptr); }
};
struct SwapchainDeleter {
    void operator()(VkDevice d, VkSwapchainKHR h) const noexcept { vkDestroySwapchainKHR(d, h, nullptr); }
};
struct ImageViewDeleter {
    void operator()(VkDevice d, VkImageView h) const noexcept { vkDestroyImageView(d, h, nullptr); }
};
struct FramebufferDeleter {
    void operator()(VkDevice d, VkFramebuffer h) const noexcept { vkDestroyFramebuffer(d, h, nullptr); }
};
struct CommandPoolDeleter {
    void operator()(VkDevice d, VkCommandPool h) const noexcept { vkDestroyCommandPool(d, h, nullptr); }
};
struct DescriptorPoolDeleter {
    void operator()(VkDevice d, VkDescriptorPool h) const noexcept { vkDestroyDescriptorPool(d, h, nullptr); }
};
struct SemaphoreDeleter {
    void operator()(VkDevice d, VkSemaphore h) const noexcept { vkDestroySemaphore(d, h, nullptr); }
};
struct FenceDeleter {
    void operator()(VkDevice d, VkFence h) const noexcept { vkDestroyFence(d, h, nullptr); }
};
struct BufferDeleter {
    void operator()(VkDevice d, VkBuffer h) const noexcept { vkDestroyBuffer(d, h, nullptr); }
};
struct ImageDeleter {
    void operator()(VkDevice d, VkImage h) const noexcept { vkDestroyImage(d, h, nullptr); }
};
struct DeviceMemoryDeleter {
    void operator()(VkDevice d, VkDeviceMemory h) const noexcept { vkFreeMemory(d, h, nullptr); }
};

using UniqueVkRenderPass = ScopedVkDeviceHandle<VkRenderPass, RenderPassDeleter>;
using UniqueVkSwapchain = ScopedVkDeviceHandle<VkSwapchainKHR, SwapchainDeleter>;
using UniqueVkImageView = ScopedVkDeviceHandle<VkImageView, ImageViewDeleter>;
using UniqueVkFramebuffer = ScopedVkDeviceHandle<VkFramebuffer, FramebufferDeleter>;
using UniqueVkCommandPool = ScopedVkDeviceHandle<VkCommandPool, CommandPoolDeleter>;
using UniqueVkDescriptorPool = ScopedVkDeviceHandle<VkDescriptorPool, DescriptorPoolDeleter>;
using UniqueVkSemaphore = ScopedVkDeviceHandle<VkSemaphore, SemaphoreDeleter>;
using UniqueVkFence = ScopedVkDeviceHandle<VkFence, FenceDeleter>;
using UniqueVkBuffer = ScopedVkDeviceHandle<VkBuffer, BufferDeleter>;
using UniqueVkImage = ScopedVkDeviceHandle<VkImage, ImageDeleter>;
using UniqueVkDeviceMemory = ScopedVkDeviceHandle<VkDeviceMemory, DeviceMemoryDeleter>;

} // namespace detail

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

        [[nodiscard]] constexpr bool valid() const noexcept {
            return image != VK_NULL_HANDLE || view != VK_NULL_HANDLE ||
                   memory != VK_NULL_HANDLE || descriptor_set != VK_NULL_HANDLE;
        }
    };

    class UniqueTexture {
    public:
        UniqueTexture() noexcept = default;
        UniqueTexture(VulkanManager* owner, Texture texture) noexcept
            : owner_(owner), texture_(texture) {}
        ~UniqueTexture() noexcept { reset(); }

        UniqueTexture(const UniqueTexture&) = delete;
        UniqueTexture& operator=(const UniqueTexture&) = delete;

        UniqueTexture(UniqueTexture&& other) noexcept
            : owner_(std::exchange(other.owner_, nullptr))
            , texture_(std::exchange(other.texture_, Texture{})) {}

        UniqueTexture& operator=(UniqueTexture&& other) noexcept {
            if (this != &other) {
                reset();
                owner_ = std::exchange(other.owner_, nullptr);
                texture_ = std::exchange(other.texture_, Texture{});
            }
            return *this;
        }

        void reset() noexcept {
            if (owner_ != nullptr && texture_.valid()) {
                owner_->destroy_texture(texture_);
            }
            owner_ = nullptr;
            texture_ = Texture{};
        }

        [[nodiscard]] const Texture& get() const noexcept { return texture_; }
        [[nodiscard]] const Texture* operator->() const noexcept { return &texture_; }
        [[nodiscard]] explicit operator bool() const noexcept { return owner_ != nullptr && texture_.valid(); }

    private:
        VulkanManager* owner_ = nullptr;
        Texture texture_{};
    };

    VulkanManager() = default;
    ~VulkanManager() noexcept;

    VulkanManager(const VulkanManager&) = delete;
    VulkanManager& operator=(const VulkanManager&) = delete;
    VulkanManager(VulkanManager&&) = delete;
    VulkanManager& operator=(VulkanManager&&) = delete;

    void init(GLFWwindow* window, const VulkanConfig& config = {});
    void shutdown() noexcept;

    [[nodiscard]] bool begin_frame();
    void end_frame();

    void wait_idle() noexcept;
    void recreate_swapchain(GLFWwindow* window);
    [[nodiscard]] Texture create_rgba_texture(std::span<const std::uint8_t> pixels,
                                              uint32_t width,
                                              uint32_t height);
    [[nodiscard]] UniqueTexture create_unique_rgba_texture(std::span<const std::uint8_t> pixels,
                                                           uint32_t width,
                                                           uint32_t height);
    void destroy_texture(Texture& texture) noexcept;

    // Accessors for ImGui initialization
    [[nodiscard]] uint32_t api_version() const noexcept { return api_version_; }
    [[nodiscard]] VkInstance instance() const noexcept { return instance_.get(); }
    [[nodiscard]] VkPhysicalDevice physical_device() const noexcept { return physical_device_; }
    [[nodiscard]] VkDevice device() const noexcept { return device_.get(); }
    [[nodiscard]] VkQueue graphics_queue() const noexcept { return graphics_queue_; }
    [[nodiscard]] uint32_t graphics_family() const noexcept { return graphics_family_; }
    [[nodiscard]] VkRenderPass render_pass() const noexcept { return render_pass_.get(); }
    [[nodiscard]] VkDescriptorPool descriptor_pool() const noexcept { return descriptor_pool_.get(); }
    [[nodiscard]] uint32_t min_image_count() const noexcept { return min_image_count_; }
    [[nodiscard]] uint32_t image_count() const noexcept {
        return static_cast<uint32_t>(swapchain_.images.size());
    }
    [[nodiscard]] VkCommandBuffer current_command_buffer() const noexcept {
        return frames_[current_frame_].command_buffer;
    }
    [[nodiscard]] VkExtent2D swapchain_extent() const noexcept { return swapchain_extent_; }

private:
    struct SwapchainState {
        // Declared in dependency order so reverse member destruction destroys
        // framebuffers -> semaphores -> image views -> swapchain.
        detail::UniqueVkSwapchain swapchain;
        std::vector<VkImage> images;
        std::vector<detail::UniqueVkImageView> image_views;
        std::vector<detail::UniqueVkSemaphore> render_finished_semaphores;
        std::vector<detail::UniqueVkFramebuffer> framebuffers;
        std::vector<VkFence> images_in_flight;
    };

    struct FrameSyncSlot {
        detail::UniqueVkCommandPool command_pool;
        VkCommandBuffer command_buffer = VK_NULL_HANDLE;
        detail::UniqueVkSemaphore image_available_semaphore;
        detail::UniqueVkFence in_flight_fence;
    };

    void create_instance(const VulkanConfig& config);
    void create_surface(GLFWwindow* window);
    void select_physical_device();
    void create_logical_device();
    [[nodiscard]] VkSurfaceFormatKHR choose_surface_format() const;
    void create_render_pass();
    void create_swapchain(GLFWwindow* window, VkSurfaceFormatKHR surface_format);
    void create_framebuffers();
    void create_command_pool();
    void create_command_buffers();
    void create_descriptor_pool();
    void create_sync_objects();

    [[nodiscard]] uint32_t find_memory_type(uint32_t type_filter, VkMemoryPropertyFlags properties) const;

    // Vulkan handles ordered in acquisition order so reverse destruction tears down
    // child objects before device, surface, and instance even on partial-init failure.
    uint32_t api_version_ = VK_API_VERSION_1_0;
    detail::VkInstanceOwner instance_;
    detail::VkSurfaceOwner surface_;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    uint32_t graphics_family_ = 0;
    detail::VkDeviceOwner device_;
    VkQueue graphics_queue_ = VK_NULL_HANDLE;

    VkFormat swapchain_format_ = VK_FORMAT_B8G8R8A8_SRGB;
    VkExtent2D swapchain_extent_{};
    uint32_t min_image_count_ = 2;

    detail::UniqueVkRenderPass render_pass_;
    SwapchainState swapchain_;
    detail::UniqueVkCommandPool command_pool_;
    std::array<FrameSyncSlot, kMaxFramesInFlight> frames_{};
    detail::UniqueVkDescriptorPool descriptor_pool_;

    uint32_t current_frame_ = 0;
    uint32_t current_image_index_ = 0;
    GLFWwindow* window_ = nullptr;
    bool swapchain_dirty_ = false;
};

} // namespace viewer
