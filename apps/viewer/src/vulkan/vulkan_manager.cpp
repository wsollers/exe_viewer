#include "vulkan_manager.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

#include <imgui.h>
#include <imgui_impl_vulkan.h>

namespace viewer {
namespace {

void check_vk(VkResult r, const char* msg) {
    if (r != VK_SUCCESS) {
        throw std::runtime_error(msg);
    }
}

class OneTimeCommandScope {
public:
    OneTimeCommandScope(VkDevice device, VkCommandPool pool, VkQueue queue)
        : device_(device), pool_(pool), queue_(queue) {
        VkCommandBufferAllocateInfo alloc_info{};
        alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        alloc_info.commandPool = pool_;
        alloc_info.commandBufferCount = 1;
        check_vk(vkAllocateCommandBuffers(device_, &alloc_info, &cmd_),
                 "vkAllocateCommandBuffers failed for one-time command");

        VkCommandBufferBeginInfo begin_info{};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        if (vkBeginCommandBuffer(cmd_, &begin_info) != VK_SUCCESS) {
            vkFreeCommandBuffers(device_, pool_, 1, &cmd_);
            cmd_ = VK_NULL_HANDLE;
            throw std::runtime_error("vkBeginCommandBuffer failed for one-time command");
        }
    }

    ~OneTimeCommandScope() noexcept {
        if (cmd_ != VK_NULL_HANDLE) {
            vkFreeCommandBuffers(device_, pool_, 1, &cmd_);
        }
    }

    OneTimeCommandScope(const OneTimeCommandScope&) = delete;
    OneTimeCommandScope& operator=(const OneTimeCommandScope&) = delete;

    [[nodiscard]] VkCommandBuffer get() const noexcept { return cmd_; }

    void submit_and_wait() {
        check_vk(vkEndCommandBuffer(cmd_), "vkEndCommandBuffer failed for one-time command");

        VkSubmitInfo submit_info{};
        submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit_info.commandBufferCount = 1;
        submit_info.pCommandBuffers = &cmd_;

        check_vk(vkQueueSubmit(queue_, 1, &submit_info, VK_NULL_HANDLE),
                 "vkQueueSubmit failed for one-time command");
        check_vk(vkQueueWaitIdle(queue_), "vkQueueWaitIdle failed for one-time command");
        vkFreeCommandBuffers(device_, pool_, 1, &cmd_);
        cmd_ = VK_NULL_HANDLE;
    }

private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkCommandPool pool_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    VkCommandBuffer cmd_ = VK_NULL_HANDLE;
};

template <typename Fn>
class RollbackGuard {
public:
    explicit RollbackGuard(Fn fn) noexcept : fn_(std::move(fn)) {}
    ~RollbackGuard() noexcept {
        if (active_) {
            fn_();
        }
    }
    RollbackGuard(const RollbackGuard&) = delete;
    RollbackGuard& operator=(const RollbackGuard&) = delete;

    void disarm() noexcept { active_ = false; }

private:
    Fn fn_;
    bool active_ = true;
};

} // namespace

VulkanManager::~VulkanManager() noexcept {
    shutdown();
}

void VulkanManager::init(GLFWwindow* window, const VulkanConfig& cfg) {
    shutdown();
    RollbackGuard rollback([this]() noexcept { shutdown(); });

    window_ = window;
    create_instance(cfg);
    create_surface(window);
    select_physical_device();
    create_logical_device();

    const VkSurfaceFormatKHR surface_format = choose_surface_format();
    swapchain_format_ = surface_format.format;

    create_render_pass();
    create_swapchain(window, surface_format);
    create_framebuffers();
    create_command_pool();
    create_command_buffers();
    create_descriptor_pool();
    create_sync_objects();

    rollback.disarm();
}

void VulkanManager::shutdown() noexcept {
    wait_idle();

    descriptor_pool_.reset();
    for (FrameSyncSlot& slot : frames_) {
        slot.in_flight_fence.reset();
        slot.image_available_semaphore.reset();
        slot.command_buffer = VK_NULL_HANDLE;
        slot.command_pool.reset();
    }
    command_pool_.reset();
    swapchain_ = SwapchainState{};
    render_pass_.reset();

    graphics_queue_ = VK_NULL_HANDLE;
    device_.reset();
    physical_device_ = VK_NULL_HANDLE;
    graphics_family_ = 0;
    surface_.reset();
    instance_.reset();

    window_ = nullptr;
    current_frame_ = 0;
    current_image_index_ = 0;
    swapchain_dirty_ = false;
}

void VulkanManager::create_instance(const VulkanConfig& cfg) {
    uint32_t ext_count = 0;
    const char** exts = glfwGetRequiredInstanceExtensions(&ext_count);

    api_version_ = VK_API_VERSION_1_0;
    if (auto* enumerate_version = reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
            vkGetInstanceProcAddr(nullptr, "vkEnumerateInstanceVersion"))) {
        uint32_t loader_version = VK_API_VERSION_1_0;
        if (enumerate_version(&loader_version) == VK_SUCCESS &&
            loader_version >= VK_API_VERSION_1_1) {
            api_version_ = VK_API_VERSION_1_1;
        }
    }

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = cfg.app_name;
    app.applicationVersion = cfg.app_version;
    app.apiVersion = api_version_;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    ci.enabledExtensionCount = ext_count;
    ci.ppEnabledExtensionNames = exts;

    VkInstance raw_instance = VK_NULL_HANDLE;
    check_vk(vkCreateInstance(&ci, nullptr, &raw_instance), "vkCreateInstance failed");
    instance_.reset(raw_instance);
}

void VulkanManager::create_surface(GLFWwindow* window) {
    VkSurfaceKHR raw_surface = VK_NULL_HANDLE;
    check_vk(glfwCreateWindowSurface(instance_.get(), window, nullptr, &raw_surface),
             "Failed to create surface");
    surface_.reset(instance_.get(), raw_surface);
}

void VulkanManager::select_physical_device() {
    uint32_t count = 0;
    check_vk(vkEnumeratePhysicalDevices(instance_.get(), &count, nullptr),
             "vkEnumeratePhysicalDevices failed");
    if (count == 0) {
        throw std::runtime_error("No Vulkan devices");
    }

    std::vector<VkPhysicalDevice> devs(count);
    check_vk(vkEnumeratePhysicalDevices(instance_.get(), &count, devs.data()),
             "vkEnumeratePhysicalDevices failed");

    for (VkPhysicalDevice d : devs) {
        uint32_t qcount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(d, &qcount, nullptr);
        std::vector<VkQueueFamilyProperties> qf(qcount);
        vkGetPhysicalDeviceQueueFamilyProperties(d, &qcount, qf.data());

        for (uint32_t i = 0; i < qcount; ++i) {
            VkBool32 present = VK_FALSE;
            check_vk(vkGetPhysicalDeviceSurfaceSupportKHR(d, i, surface_.get(), &present),
                     "vkGetPhysicalDeviceSurfaceSupportKHR failed");
            if ((qf[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0 && present != VK_FALSE) {
                physical_device_ = d;
                graphics_family_ = i;
                return;
            }
        }
    }

    throw std::runtime_error("No suitable GPU found");
}

void VulkanManager::create_logical_device() {
    constexpr float prio = 1.0f;

    VkDeviceQueueCreateInfo q{};
    q.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    q.queueFamilyIndex = graphics_family_;
    q.queueCount = 1;
    q.pQueuePriorities = &prio;

    constexpr std::array<const char*, 1> exts{VK_KHR_SWAPCHAIN_EXTENSION_NAME};

    VkDeviceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    ci.queueCreateInfoCount = 1;
    ci.pQueueCreateInfos = &q;
    ci.enabledExtensionCount = static_cast<uint32_t>(exts.size());
    ci.ppEnabledExtensionNames = exts.data();

    VkDevice raw_device = VK_NULL_HANDLE;
    check_vk(vkCreateDevice(physical_device_, &ci, nullptr, &raw_device),
             "vkCreateDevice failed");
    device_.reset(raw_device);

    vkGetDeviceQueue(device_.get(), graphics_family_, 0, &graphics_queue_);
}

VkSurfaceFormatKHR VulkanManager::choose_surface_format() const {
    uint32_t fcount = 0;
    check_vk(vkGetPhysicalDeviceSurfaceFormatsKHR(physical_device_, surface_.get(), &fcount, nullptr),
             "vkGetPhysicalDeviceSurfaceFormatsKHR failed");
    if (fcount == 0) {
        throw std::runtime_error("Vulkan surface reported zero supported formats");
    }

    std::vector<VkSurfaceFormatKHR> formats(fcount);
    check_vk(vkGetPhysicalDeviceSurfaceFormatsKHR(physical_device_, surface_.get(), &fcount, formats.data()),
             "vkGetPhysicalDeviceSurfaceFormatsKHR failed");

    for (const VkSurfaceFormatKHR& f : formats) {
        if (f.format == VK_FORMAT_B8G8R8A8_UNORM &&
            f.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
            return f;
        }
    }
    return formats.front();
}

void VulkanManager::create_swapchain(GLFWwindow* window, VkSurfaceFormatKHR chosen) {
    swapchain_format_ = chosen.format;

    int w = 0;
    int h = 0;
    glfwGetFramebufferSize(window, &w, &h);
    swapchain_extent_ = {static_cast<uint32_t>(w), static_cast<uint32_t>(h)};

    VkSurfaceCapabilitiesKHR caps{};
    check_vk(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical_device_, surface_.get(), &caps),
             "vkGetPhysicalDeviceSurfaceCapabilitiesKHR failed");

    if (caps.currentExtent.width != std::numeric_limits<uint32_t>::max()) {
        swapchain_extent_ = caps.currentExtent;
    } else {
        swapchain_extent_.width = std::clamp(swapchain_extent_.width, caps.minImageExtent.width, caps.maxImageExtent.width);
        swapchain_extent_.height = std::clamp(swapchain_extent_.height, caps.minImageExtent.height, caps.maxImageExtent.height);
    }

    uint32_t image_count = std::max<uint32_t>(caps.minImageCount + 1u, 2u);
    if (caps.maxImageCount > 0 && image_count > caps.maxImageCount) {
        image_count = caps.maxImageCount;
    }
    min_image_count_ = image_count;

    VkSwapchainCreateInfoKHR ci{};
    ci.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    ci.surface = surface_.get();
    ci.minImageCount = image_count;
    ci.imageFormat = swapchain_format_;
    ci.imageColorSpace = chosen.colorSpace;
    ci.imageExtent = swapchain_extent_;
    ci.imageArrayLayers = 1;
    ci.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    ci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ci.preTransform = caps.currentTransform;
    ci.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    ci.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    ci.clipped = VK_TRUE;

    SwapchainState next_state;

    VkSwapchainKHR raw_swapchain = VK_NULL_HANDLE;
    check_vk(vkCreateSwapchainKHR(device_.get(), &ci, nullptr, &raw_swapchain),
             "vkCreateSwapchain failed");
    next_state.swapchain.reset(device_.get(), raw_swapchain);

    check_vk(vkGetSwapchainImagesKHR(device_.get(), next_state.swapchain.get(), &image_count, nullptr),
             "vkGetSwapchainImagesKHR failed");
    next_state.images.resize(image_count);
    check_vk(vkGetSwapchainImagesKHR(device_.get(), next_state.swapchain.get(), &image_count, next_state.images.data()),
             "vkGetSwapchainImagesKHR failed");
    next_state.images_in_flight.assign(image_count, VK_NULL_HANDLE);

    next_state.render_finished_semaphores.reserve(image_count);
    VkSemaphoreCreateInfo semaphore_info{};
    semaphore_info.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    for (uint32_t i = 0; i < image_count; ++i) {
        VkSemaphore raw_sem = VK_NULL_HANDLE;
        check_vk(vkCreateSemaphore(device_.get(), &semaphore_info, nullptr, &raw_sem),
                 "Failed to create present semaphore");
        next_state.render_finished_semaphores.emplace_back(device_.get(), raw_sem);
    }

    next_state.image_views.reserve(image_count);
    for (uint32_t i = 0; i < image_count; ++i) {
        VkImageViewCreateInfo vi{};
        vi.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        vi.image = next_state.images[i];
        vi.viewType = VK_IMAGE_VIEW_TYPE_2D;
        vi.format = swapchain_format_;
        vi.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        vi.subresourceRange.levelCount = 1;
        vi.subresourceRange.layerCount = 1;

        VkImageView raw_view = VK_NULL_HANDLE;
        check_vk(vkCreateImageView(device_.get(), &vi, nullptr, &raw_view),
                 "vkCreateImageView failed");
        next_state.image_views.emplace_back(device_.get(), raw_view);
    }

    swapchain_ = std::move(next_state);
}

void VulkanManager::create_render_pass() {
    VkAttachmentDescription att{};
    att.format = swapchain_format_;
    att.samples = VK_SAMPLE_COUNT_1_BIT;
    att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    att.finalLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;

    VkAttachmentReference ref{};
    ref.attachment = 0;
    ref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkSubpassDescription sub{};
    sub.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.colorAttachmentCount = 1;
    sub.pColorAttachments = &ref;

    VkSubpassDependency dependency{};
    dependency.srcSubpass = VK_SUBPASS_EXTERNAL;
    dependency.dstSubpass = 0;
    dependency.srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;

    VkRenderPassCreateInfo rp{};
    rp.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp.attachmentCount = 1;
    rp.pAttachments = &att;
    rp.subpassCount = 1;
    rp.pSubpasses = &sub;
    rp.dependencyCount = 1;
    rp.pDependencies = &dependency;

    VkRenderPass raw_rp = VK_NULL_HANDLE;
    check_vk(vkCreateRenderPass(device_.get(), &rp, nullptr, &raw_rp),
             "vkCreateRenderPass failed");
    render_pass_.reset(device_.get(), raw_rp);
}

void VulkanManager::create_framebuffers() {
    swapchain_.framebuffers.clear();
    swapchain_.framebuffers.reserve(swapchain_.image_views.size());

    for (const auto& view : swapchain_.image_views) {
        const VkImageView attachment = view.get();
        VkFramebufferCreateInfo fb{};
        fb.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb.renderPass = render_pass_.get();
        fb.attachmentCount = 1;
        fb.pAttachments = &attachment;
        fb.width = swapchain_extent_.width;
        fb.height = swapchain_extent_.height;
        fb.layers = 1;

        VkFramebuffer raw_fb = VK_NULL_HANDLE;
        check_vk(vkCreateFramebuffer(device_.get(), &fb, nullptr, &raw_fb),
                 "vkCreateFramebuffer failed");
        swapchain_.framebuffers.emplace_back(device_.get(), raw_fb);
    }
}

void VulkanManager::create_command_pool() {
    VkCommandPoolCreateInfo transfer_ci{};
    transfer_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    transfer_ci.queueFamilyIndex = graphics_family_;
    transfer_ci.flags = VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;

    VkCommandPool raw_transfer_pool = VK_NULL_HANDLE;
    check_vk(vkCreateCommandPool(device_.get(), &transfer_ci, nullptr, &raw_transfer_pool),
             "vkCreateCommandPool failed");
    command_pool_.reset(device_.get(), raw_transfer_pool);

    VkCommandPoolCreateInfo frame_ci{};
    frame_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    frame_ci.queueFamilyIndex = graphics_family_;
    frame_ci.flags = 0;

    for (FrameSyncSlot& slot : frames_) {
        VkCommandPool raw_frame_pool = VK_NULL_HANDLE;
        check_vk(vkCreateCommandPool(device_.get(), &frame_ci, nullptr, &raw_frame_pool),
                 "vkCreateCommandPool failed for frame pool");
        slot.command_pool.reset(device_.get(), raw_frame_pool);
    }
}

void VulkanManager::create_command_buffers() {
    for (FrameSyncSlot& slot : frames_) {
        VkCommandBufferAllocateInfo ai{};
        ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool = slot.command_pool.get();
        ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount = 1;

        check_vk(vkAllocateCommandBuffers(device_.get(), &ai, &slot.command_buffer),
                 "vkAllocateCommandBuffers failed");
    }
}

void VulkanManager::create_descriptor_pool() {
    constexpr std::array<VkDescriptorPoolSize, 3> pool_sizes{{
        {VK_DESCRIPTOR_TYPE_SAMPLER, 64},
        {VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 64},
        {VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 64},
    }};

    VkDescriptorPoolCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    ci.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    ci.maxSets = 192;
    ci.poolSizeCount = static_cast<uint32_t>(pool_sizes.size());
    ci.pPoolSizes = pool_sizes.data();

    VkDescriptorPool raw_pool = VK_NULL_HANDLE;
    check_vk(vkCreateDescriptorPool(device_.get(), &ci, nullptr, &raw_pool),
             "vkCreateDescriptorPool failed");
    descriptor_pool_.reset(device_.get(), raw_pool);
}

void VulkanManager::create_sync_objects() {
    VkSemaphoreCreateInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;

    for (FrameSyncSlot& slot : frames_) {
        VkSemaphore raw_sem = VK_NULL_HANDLE;
        check_vk(vkCreateSemaphore(device_.get(), &si, nullptr, &raw_sem),
                 "Failed to create acquire semaphore");
        slot.image_available_semaphore.reset(device_.get(), raw_sem);

        VkFence raw_fence = VK_NULL_HANDLE;
        check_vk(vkCreateFence(device_.get(), &fi, nullptr, &raw_fence),
                 "Failed to create in-flight fence");
        slot.in_flight_fence.reset(device_.get(), raw_fence);
    }
}

uint32_t VulkanManager::find_memory_type(uint32_t type_filter, VkMemoryPropertyFlags properties) const {
    VkPhysicalDeviceMemoryProperties memory_properties{};
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &memory_properties);

    for (uint32_t i = 0; i < memory_properties.memoryTypeCount; ++i) {
        if ((type_filter & (1u << i)) != 0 &&
            (memory_properties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }

    throw std::runtime_error("No suitable Vulkan memory type found");
}

VulkanManager::Texture VulkanManager::create_rgba_texture(std::span<const std::uint8_t> pixels,
                                                          uint32_t width,
                                                          uint32_t height) {
    if (!device_) {
        throw std::runtime_error("Vulkan device is not initialized");
    }
    if (width == 0 || height == 0 || pixels.size() != static_cast<std::size_t>(width) * height * 4u) {
        throw std::runtime_error("Invalid RGBA texture data");
    }

    vkDeviceWaitIdle(device_.get());

    const VkDevice dev = device_.get();
    const VkDeviceSize image_size = static_cast<VkDeviceSize>(pixels.size());

    // Declared so reverse destruction destroys staging_buffer before freeing staging_memory.
    detail::UniqueVkDeviceMemory staging_memory;
    detail::UniqueVkBuffer staging_buffer;
    {
        VkBufferCreateInfo buffer_info{};
        buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        buffer_info.size = image_size;
        buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        VkBuffer raw_staging_buffer = VK_NULL_HANDLE;
        check_vk(vkCreateBuffer(dev, &buffer_info, nullptr, &raw_staging_buffer), "vkCreateBuffer failed");
        staging_buffer.reset(dev, raw_staging_buffer);

        VkMemoryRequirements buffer_requirements{};
        vkGetBufferMemoryRequirements(dev, staging_buffer.get(), &buffer_requirements);

        VkMemoryAllocateInfo buffer_alloc{};
        buffer_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        buffer_alloc.allocationSize = buffer_requirements.size;
        buffer_alloc.memoryTypeIndex = find_memory_type(
            buffer_requirements.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

        VkDeviceMemory raw_staging_memory = VK_NULL_HANDLE;
        check_vk(vkAllocateMemory(dev, &buffer_alloc, nullptr, &raw_staging_memory),
                 "vkAllocateMemory failed for staging texture");
        staging_memory.reset(dev, raw_staging_memory);

        check_vk(vkBindBufferMemory(dev, staging_buffer.get(), staging_memory.get(), 0),
                 "vkBindBufferMemory failed for staging texture");

        void* mapped = nullptr;
        check_vk(vkMapMemory(dev, staging_memory.get(), 0, image_size, 0, &mapped),
                 "vkMapMemory failed for staging texture");
        std::memcpy(mapped, pixels.data(), pixels.size());
        vkUnmapMemory(dev, staging_memory.get());
    }

    // Declared so reverse destruction on exception runs view -> image -> memory.
    detail::UniqueVkDeviceMemory image_memory;
    detail::UniqueVkImage image;
    detail::UniqueVkImageView view;

    VkImageCreateInfo image_info{};
    image_info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    image_info.imageType = VK_IMAGE_TYPE_2D;
    image_info.extent.width = width;
    image_info.extent.height = height;
    image_info.extent.depth = 1;
    image_info.mipLevels = 1;
    image_info.arrayLayers = 1;
    image_info.format = VK_FORMAT_R8G8B8A8_UNORM;
    image_info.tiling = VK_IMAGE_TILING_OPTIMAL;
    image_info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    image_info.usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;
    image_info.samples = VK_SAMPLE_COUNT_1_BIT;
    image_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkImage raw_image = VK_NULL_HANDLE;
    check_vk(vkCreateImage(dev, &image_info, nullptr, &raw_image), "vkCreateImage failed for texture");
    image.reset(dev, raw_image);

    VkMemoryRequirements image_requirements{};
    vkGetImageMemoryRequirements(dev, image.get(), &image_requirements);
    VkMemoryAllocateInfo image_alloc{};
    image_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    image_alloc.allocationSize = image_requirements.size;
    image_alloc.memoryTypeIndex = find_memory_type(
        image_requirements.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);

    VkDeviceMemory raw_image_memory = VK_NULL_HANDLE;
    check_vk(vkAllocateMemory(dev, &image_alloc, nullptr, &raw_image_memory),
             "vkAllocateMemory failed for texture");
    image_memory.reset(dev, raw_image_memory);

    check_vk(vkBindImageMemory(dev, image.get(), image_memory.get(), 0),
             "vkBindImageMemory failed for texture");

    {
        OneTimeCommandScope one_time(dev, command_pool_.get(), graphics_queue_);
        const VkCommandBuffer command_buffer = one_time.get();

        VkImageMemoryBarrier to_transfer{};
        to_transfer.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        to_transfer.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        to_transfer.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        to_transfer.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_transfer.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_transfer.image = image.get();
        to_transfer.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        to_transfer.subresourceRange.levelCount = 1;
        to_transfer.subresourceRange.layerCount = 1;
        to_transfer.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        vkCmdPipelineBarrier(command_buffer,
                             VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,
                             0,
                             0,
                             nullptr,
                             0,
                             nullptr,
                             1,
                             &to_transfer);

        VkBufferImageCopy region{};
        region.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        region.imageSubresource.layerCount = 1;
        region.imageExtent = {width, height, 1};
        vkCmdCopyBufferToImage(command_buffer,
                               staging_buffer.get(),
                               image.get(),
                               VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                               1,
                               &region);

        VkImageMemoryBarrier to_shader{};
        to_shader.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        to_shader.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        to_shader.newLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
        to_shader.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_shader.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_shader.image = image.get();
        to_shader.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        to_shader.subresourceRange.levelCount = 1;
        to_shader.subresourceRange.layerCount = 1;
        to_shader.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        to_shader.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        vkCmdPipelineBarrier(command_buffer,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
                             0,
                             0,
                             nullptr,
                             0,
                             nullptr,
                             1,
                             &to_shader);

        one_time.submit_and_wait();
    }

    // Staging upload finished; release staging buffer then memory explicitly.
    staging_buffer.reset();
    staging_memory.reset();

    VkImageViewCreateInfo view_info{};
    view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view_info.image = image.get();
    view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
    view_info.format = VK_FORMAT_R8G8B8A8_UNORM;
    view_info.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    view_info.subresourceRange.levelCount = 1;
    view_info.subresourceRange.layerCount = 1;

    VkImageView raw_view = VK_NULL_HANDLE;
    check_vk(vkCreateImageView(dev, &view_info, nullptr, &raw_view),
             "vkCreateImageView failed for texture");
    view.reset(dev, raw_view);

    const VkDescriptorSet descriptor_set =
        ImGui_ImplVulkan_AddTexture(view.get(), VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
    if (descriptor_set == VK_NULL_HANDLE) {
        throw std::runtime_error("ImGui_ImplVulkan_AddTexture failed for texture");
    }

    Texture texture{};
    texture.view = view.release();
    texture.image = image.release();
    texture.memory = image_memory.release();
    texture.descriptor_set = descriptor_set;
    texture.width = width;
    texture.height = height;
    return texture;
}

VulkanManager::UniqueTexture VulkanManager::create_unique_rgba_texture(
    std::span<const std::uint8_t> pixels,
    uint32_t width,
    uint32_t height) {
    return UniqueTexture(this, create_rgba_texture(pixels, width, height));
}

void VulkanManager::destroy_texture(Texture& texture) noexcept {
    if (!device_ || !texture.valid()) {
        texture = Texture{};
        return;
    }
    const VkDevice dev = device_.get();
    (void)vkDeviceWaitIdle(dev);

    if (texture.descriptor_set != VK_NULL_HANDLE) {
        ImGui_ImplVulkan_RemoveTexture(texture.descriptor_set);
        texture.descriptor_set = VK_NULL_HANDLE;
    }
    if (texture.view != VK_NULL_HANDLE) {
        vkDestroyImageView(dev, texture.view, nullptr);
        texture.view = VK_NULL_HANDLE;
    }
    if (texture.image != VK_NULL_HANDLE) {
        vkDestroyImage(dev, texture.image, nullptr);
        texture.image = VK_NULL_HANDLE;
    }
    if (texture.memory != VK_NULL_HANDLE) {
        vkFreeMemory(dev, texture.memory, nullptr);
        texture.memory = VK_NULL_HANDLE;
    }
    texture.width = 0;
    texture.height = 0;
}

bool VulkanManager::begin_frame() {
    int width = 0;
    int height = 0;
    glfwGetFramebufferSize(window_, &width, &height);
    if (width == 0 || height == 0) {
        return false;
    }
    if (swapchain_dirty_) {
        recreate_swapchain(window_);
        if (swapchain_dirty_) {
            return false;
        }
    }

    const VkDevice dev = device_.get();
    FrameSyncSlot& frame = frames_[current_frame_];
    const VkFence frame_fence = frame.in_flight_fence.get();

    check_vk(vkWaitForFences(dev, 1, &frame_fence, VK_TRUE, UINT64_MAX),
             "Fence wait failed");

    const VkResult acquired = vkAcquireNextImageKHR(
        dev,
        swapchain_.swapchain.get(),
        UINT64_MAX,
        frame.image_available_semaphore.get(),
        VK_NULL_HANDLE,
        &current_image_index_);
    if (acquired == VK_ERROR_OUT_OF_DATE_KHR) {
        recreate_swapchain(window_);
        return false;
    }
    if (acquired == VK_SUBOPTIMAL_KHR) {
        swapchain_dirty_ = true;
    } else {
        check_vk(acquired, "vkAcquireNextImageKHR failed");
    }

    if (current_image_index_ < swapchain_.images_in_flight.size() &&
        swapchain_.images_in_flight[current_image_index_] != VK_NULL_HANDLE) {
        check_vk(vkWaitForFences(dev, 1, &swapchain_.images_in_flight[current_image_index_], VK_TRUE, UINT64_MAX),
                 "Swapchain image fence wait failed");
    }
    if (current_image_index_ < swapchain_.images_in_flight.size()) {
        swapchain_.images_in_flight[current_image_index_] = frame_fence;
    }

    check_vk(vkResetCommandPool(dev, frame.command_pool.get(), 0),
             "vkResetCommandPool failed");
    const VkCommandBuffer cmd = frame.command_buffer;

    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    check_vk(vkBeginCommandBuffer(cmd, &bi), "vkBeginCommandBuffer failed");

    VkClearValue clear{};
    clear.color = {{0.1f, 0.1f, 0.1f, 1.0f}};

    VkRenderPassBeginInfo rp{};
    rp.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rp.renderPass = render_pass_.get();
    rp.framebuffer = swapchain_.framebuffers[current_image_index_].get();
    rp.renderArea.extent = swapchain_extent_;
    rp.clearValueCount = 1;
    rp.pClearValues = &clear;

    vkCmdBeginRenderPass(cmd, &rp, VK_SUBPASS_CONTENTS_INLINE);
    return true;
}

void VulkanManager::end_frame() {
    const VkDevice dev = device_.get();
    FrameSyncSlot& frame = frames_[current_frame_];
    const VkCommandBuffer cmd = frame.command_buffer;

    vkCmdEndRenderPass(cmd);
    check_vk(vkEndCommandBuffer(cmd), "vkEndCommandBuffer failed");

    const std::array<VkSemaphore, 1> wait{frame.image_available_semaphore.get()};
    const std::array<VkPipelineStageFlags, 1> stages{VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT};
    const std::array<VkSemaphore, 1> signal{
        swapchain_.render_finished_semaphores[current_image_index_].get(),
    };

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = wait.data();
    si.pWaitDstStageMask = stages.data();
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = signal.data();

    const VkFence frame_fence = frame.in_flight_fence.get();
    check_vk(vkResetFences(dev, 1, &frame_fence), "Fence reset failed");
    check_vk(vkQueueSubmit(graphics_queue_, 1, &si, frame_fence),
             "vkQueueSubmit failed");

    const VkSwapchainKHR raw_swapchain = swapchain_.swapchain.get();
    VkPresentInfoKHR pi{};
    pi.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = signal.data();
    pi.swapchainCount = 1;
    pi.pSwapchains = &raw_swapchain;
    pi.pImageIndices = &current_image_index_;

    const VkResult presented = vkQueuePresentKHR(graphics_queue_, &pi);
    if (presented == VK_ERROR_OUT_OF_DATE_KHR || presented == VK_SUBOPTIMAL_KHR || swapchain_dirty_) {
        recreate_swapchain(window_);
    } else {
        check_vk(presented, "vkQueuePresentKHR failed");
    }

    current_frame_ = static_cast<uint32_t>((current_frame_ + 1u) % kMaxFramesInFlight);
}

void VulkanManager::wait_idle() noexcept {
    if (device_) {
        (void)vkDeviceWaitIdle(device_.get());
    }
}

void VulkanManager::recreate_swapchain(GLFWwindow* window) {
    int width = 0;
    int height = 0;
    glfwGetFramebufferSize(window, &width, &height);

    if (width == 0 || height == 0) {
        swapchain_dirty_ = true;
        return;
    }

    wait_idle();

    // Release old swapchain resources before creating the replacement swapchain.
    swapchain_ = SwapchainState{};

    const VkSurfaceFormatKHR surface_format = choose_surface_format();
    create_swapchain(window, surface_format);
    create_framebuffers();
    if (ImGui::GetCurrentContext() != nullptr) {
        ImGui_ImplVulkan_SetMinImageCount(min_image_count_);
    }
    swapchain_dirty_ = false;
}

} // namespace viewer
