#include "vulkan_manager.h"
#include <stdexcept>
#include <vector>
#include <cstdio>

namespace viewer {

static void check(VkResult r, const char* msg) {
    if (r != VK_SUCCESS) throw std::runtime_error(msg);
}

VulkanManager::~VulkanManager() {
    if (initialized_) shutdown();
}

void VulkanManager::init(GLFWwindow* window, const VulkanConfig& cfg) {
    create_instance(cfg);
    create_surface(window);
    select_physical_device();
    create_logical_device();
    create_swapchain(window);      // MUST come before render pass
    create_render_pass();          // uses swapchain_format_
    create_framebuffers();
    create_command_pool();
    create_command_buffers();
    create_descriptor_pool();
    create_sync_objects();
    initialized_ = true;
}

void VulkanManager::shutdown() {
    if (!initialized_) return;
    vkDeviceWaitIdle(device_);

    vkDestroyFence(device_, in_flight_fence_, nullptr);
    vkDestroySemaphore(device_, render_finished_semaphore_, nullptr);
    vkDestroySemaphore(device_, image_available_semaphore_, nullptr);

    vkDestroyDescriptorPool(device_, descriptor_pool_, nullptr);
    vkDestroyCommandPool(device_, command_pool_, nullptr);

    for (auto fb : framebuffers_) vkDestroyFramebuffer(device_, fb, nullptr);
    for (auto iv : swapchain_image_views_) vkDestroyImageView(device_, iv, nullptr);
    vkDestroySwapchainKHR(device_, swapchain_, nullptr);

    vkDestroyRenderPass(device_, render_pass_, nullptr);
    vkDestroyDevice(device_, nullptr);
    vkDestroySurfaceKHR(instance_, surface_, nullptr);
    vkDestroyInstance(instance_, nullptr);

    initialized_ = false;
}

void VulkanManager::create_instance(const VulkanConfig& cfg) {
    uint32_t ext_count = 0;
    const char** exts = glfwGetRequiredInstanceExtensions(&ext_count);

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = cfg.app_name;
    app.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    ci.enabledExtensionCount = ext_count;
    ci.ppEnabledExtensionNames = exts;

    check(vkCreateInstance(&ci, nullptr, &instance_), "vkCreateInstance failed");
}

void VulkanManager::create_surface(GLFWwindow* window) {
    check(glfwCreateWindowSurface(instance_, window, nullptr, &surface_),
          "Failed to create surface");
}

void VulkanManager::select_physical_device() {
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(instance_, &count, nullptr);
    if (count == 0) throw std::runtime_error("No Vulkan devices");

    std::vector<VkPhysicalDevice> devs(count);
    vkEnumeratePhysicalDevices(instance_, &count, devs.data());

    for (auto d : devs) {
        uint32_t qcount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(d, &qcount, nullptr);
        std::vector<VkQueueFamilyProperties> qf(qcount);
        vkGetPhysicalDeviceQueueFamilyProperties(d, &qcount, qf.data());

        for (uint32_t i = 0; i < qcount; i++) {
            VkBool32 present = false;
            vkGetPhysicalDeviceSurfaceSupportKHR(d, i, surface_, &present);
            if ((qf[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) && present) {
                physical_device_ = d;
                graphics_family_ = i;
                return;
            }
        }
    }

    throw std::runtime_error("No suitable GPU found");
}

void VulkanManager::create_logical_device() {
    float prio = 1.0f;

    VkDeviceQueueCreateInfo q{};
    q.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    q.queueFamilyIndex = graphics_family_;
    q.queueCount = 1;
    q.pQueuePriorities = &prio;

    const char* exts[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };

    VkDeviceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    ci.queueCreateInfoCount = 1;
    ci.pQueueCreateInfos = &q;
    ci.enabledExtensionCount = 1;
    ci.ppEnabledExtensionNames = exts;

    check(vkCreateDevice(physical_device_, &ci, nullptr, &device_),
          "vkCreateDevice failed");

    vkGetDeviceQueue(device_, graphics_family_, 0, &graphics_queue_);
}

void VulkanManager::create_swapchain(GLFWwindow* window) {
    // Query surface formats
    uint32_t fcount = 0;
    vkGetPhysicalDeviceSurfaceFormatsKHR(physical_device_, surface_, &fcount, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(fcount);
    vkGetPhysicalDeviceSurfaceFormatsKHR(physical_device_, surface_, &fcount, formats.data());

    VkSurfaceFormatKHR chosen = formats[0];
    for (auto& f : formats) {
        if (f.format == VK_FORMAT_B8G8R8A8_UNORM &&
            f.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
            chosen = f;
            break;
        }
    }

    swapchain_format_ = chosen.format;

    int w, h;
    glfwGetFramebufferSize(window, &w, &h);
    swapchain_extent_ = { (uint32_t)w, (uint32_t)h };

    VkSurfaceCapabilitiesKHR caps{};
    vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical_device_, surface_, &caps);

    uint32_t image_count = caps.minImageCount + 1;
    if (caps.maxImageCount > 0 && image_count > caps.maxImageCount)
        image_count = caps.maxImageCount;

    VkSwapchainCreateInfoKHR ci{};
    ci.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    ci.surface = surface_;
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

    check(vkCreateSwapchainKHR(device_, &ci, nullptr, &swapchain_),
          "vkCreateSwapchain failed");

    vkGetSwapchainImagesKHR(device_, swapchain_, &image_count, nullptr);
    swapchain_images_.resize(image_count);
    vkGetSwapchainImagesKHR(device_, swapchain_, &image_count, swapchain_images_.data());

    swapchain_image_views_.resize(image_count);
    for (uint32_t i = 0; i < image_count; i++) {
        VkImageViewCreateInfo vi{};
        vi.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        vi.image = swapchain_images_[i];
        vi.viewType = VK_IMAGE_VIEW_TYPE_2D;
        vi.format = swapchain_format_;
        vi.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        vi.subresourceRange.levelCount = 1;
        vi.subresourceRange.layerCount = 1;

        check(vkCreateImageView(device_, &vi, nullptr, &swapchain_image_views_[i]),
              "vkCreateImageView failed");
    }
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

    VkRenderPassCreateInfo rp{};
    rp.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp.attachmentCount = 1;
    rp.pAttachments = &att;
    rp.subpassCount = 1;
    rp.pSubpasses = &sub;

    check(vkCreateRenderPass(device_, &rp, nullptr, &render_pass_),
          "vkCreateRenderPass failed");
}

void VulkanManager::create_framebuffers() {
    framebuffers_.resize(swapchain_image_views_.size());

    for (size_t i = 0; i < framebuffers_.size(); i++) {
        VkFramebufferCreateInfo fb{};
        fb.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb.renderPass = render_pass_;
        fb.attachmentCount = 1;
        fb.pAttachments = &swapchain_image_views_[i];
        fb.width = swapchain_extent_.width;
        fb.height = swapchain_extent_.height;
        fb.layers = 1;

        check(vkCreateFramebuffer(device_, &fb, nullptr, &framebuffers_[i]),
              "vkCreateFramebuffer failed");
    }
}

void VulkanManager::create_command_pool() {
    VkCommandPoolCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    ci.queueFamilyIndex = graphics_family_;
    ci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    check(vkCreateCommandPool(device_, &ci, nullptr, &command_pool_),
          "vkCreateCommandPool failed");
}

void VulkanManager::create_command_buffers() {
    command_buffers_.resize(framebuffers_.size());

    VkCommandBufferAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool = command_pool_;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = (uint32_t)command_buffers_.size();

    check(vkAllocateCommandBuffers(device_, &ai, command_buffers_.data()),
          "vkAllocateCommandBuffers failed");
}

void VulkanManager::create_descriptor_pool() {
    VkDescriptorPoolSize ps{};
    ps.type = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    ps.descriptorCount = 100;

    VkDescriptorPoolCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    ci.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    ci.maxSets = 100;
    ci.poolSizeCount = 1;
    ci.pPoolSizes = &ps;

    check(vkCreateDescriptorPool(device_, &ci, nullptr, &descriptor_pool_),
          "vkCreateDescriptorPool failed");
}

void VulkanManager::create_sync_objects() {
    VkSemaphoreCreateInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;

    check(vkCreateSemaphore(device_, &si, nullptr, &image_available_semaphore_),
          "Failed to create semaphore");
    check(vkCreateSemaphore(device_, &si, nullptr, &render_finished_semaphore_),
          "Failed to create semaphore");
    check(vkCreateFence(device_, &fi, nullptr, &in_flight_fence_),
          "Failed to create fence");
}

void VulkanManager::begin_frame() {
    vkWaitForFences(device_, 1, &in_flight_fence_, VK_TRUE, UINT64_MAX);
    vkResetFences(device_, 1, &in_flight_fence_);

    check(vkAcquireNextImageKHR(device_, swapchain_, UINT64_MAX,
                                image_available_semaphore_, VK_NULL_HANDLE,
                                &current_image_index_),
          "vkAcquireNextImageKHR failed");

    VkCommandBuffer cmd = command_buffers_[current_image_index_];
    vkResetCommandBuffer(cmd, 0);

    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    vkBeginCommandBuffer(cmd, &bi);

    VkClearValue clear{};
    clear.color = { 0.1f, 0.1f, 0.1f, 1.0f };

    VkRenderPassBeginInfo rp{};
    rp.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rp.renderPass = render_pass_;
    rp.framebuffer = framebuffers_[current_image_index_];
    rp.renderArea.extent = swapchain_extent_;
    rp.clearValueCount = 1;
    rp.pClearValues = &clear;

    vkCmdBeginRenderPass(cmd, &rp, VK_SUBPASS_CONTENTS_INLINE);
}

void VulkanManager::end_frame() {
    VkCommandBuffer cmd = command_buffers_[current_image_index_];

    vkCmdEndRenderPass(cmd);
    vkEndCommandBuffer(cmd);

    VkSemaphore wait[] = { image_available_semaphore_ };
    VkPipelineStageFlags stages[] = { VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT };
    VkSemaphore signal[] = { render_finished_semaphore_ };

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = wait;
    si.pWaitDstStageMask = stages;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = signal;

    check(vkQueueSubmit(graphics_queue_, 1, &si, in_flight_fence_),
          "vkQueueSubmit failed");

    VkPresentInfoKHR pi{};
    pi.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = signal;
    pi.swapchainCount = 1;
    pi.pSwapchains = &swapchain_;
    pi.pImageIndices = &current_image_index_;

    vkQueuePresentKHR(graphics_queue_, &pi);
}
    void VulkanManager::wait_idle() {
    if (device_) {
        vkDeviceWaitIdle(device_);
    }
}

    void VulkanManager::recreate_swapchain(GLFWwindow* window) {
    int width = 0, height = 0;
    glfwGetFramebufferSize(window, &width, &height);

    // Handle minimized window
    while (width == 0 || height == 0) {
        glfwGetFramebufferSize(window, &width, &height);
        glfwWaitEvents();
    }

    vkDeviceWaitIdle(device_);

    // Destroy old swapchain resources
    for (auto fb : framebuffers_) vkDestroyFramebuffer(device_, fb, nullptr);
    for (auto iv : swapchain_image_views_) vkDestroyImageView(device_, iv, nullptr);
    vkDestroySwapchainKHR(device_, swapchain_, nullptr);

    framebuffers_.clear();
    swapchain_image_views_.clear();
    swapchain_images_.clear();

    // Recreate swapchain + framebuffers
    create_swapchain(window);
    create_framebuffers();
}
} // namespace viewer