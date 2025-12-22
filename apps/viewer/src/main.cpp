#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

static void check_vk(VkResult result, const char* msg) {
    if (result != VK_SUCCESS) {
        fprintf(stderr, "Vulkan error: %s (code: %d)\n", msg, result);
        exit(1);
    }
}

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

// All the Vulkan state
struct VulkanContext {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue graphics_queue = VK_NULL_HANDLE;
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    VkSwapchainKHR swapchain = VK_NULL_HANDLE;
    VkRenderPass render_pass = VK_NULL_HANDLE;
    VkCommandPool command_pool = VK_NULL_HANDLE;
    VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;

    std::vector<VkImage> swapchain_images;
    std::vector<VkImageView> swapchain_image_views;
    std::vector<VkFramebuffer> framebuffers;
    std::vector<VkCommandBuffer> command_buffers;

    VkFormat swapchain_format;
    VkExtent2D swapchain_extent;
    uint32_t graphics_family = 0;

    VkSemaphore image_available_semaphore = VK_NULL_HANDLE;
    VkSemaphore render_finished_semaphore = VK_NULL_HANDLE;
    VkFence in_flight_fence = VK_NULL_HANDLE;
};

void cleanup_swapchain(VulkanContext& ctx) {
    for (auto fb : ctx.framebuffers) vkDestroyFramebuffer(ctx.device, fb, nullptr);
    for (auto iv : ctx.swapchain_image_views) vkDestroyImageView(ctx.device, iv, nullptr);
    if (ctx.swapchain) vkDestroySwapchainKHR(ctx.device, ctx.swapchain, nullptr);
    ctx.framebuffers.clear();
    ctx.swapchain_image_views.clear();
    ctx.swapchain_images.clear();
}

void create_swapchain(VulkanContext& ctx, GLFWwindow* window) {
    VkSurfaceCapabilitiesKHR capabilities;
    vkGetPhysicalDeviceSurfaceCapabilitiesKHR(ctx.physical_device, ctx.surface, &capabilities);

    int width, height;
    glfwGetFramebufferSize(window, &width, &height);

    ctx.swapchain_extent = {
        static_cast<uint32_t>(width),
        static_cast<uint32_t>(height)
    };
    ctx.swapchain_format = VK_FORMAT_B8G8R8A8_SRGB;

    VkSwapchainCreateInfoKHR create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    create_info.surface = ctx.surface;
    create_info.minImageCount = capabilities.minImageCount + 1;
    if (capabilities.maxImageCount > 0 && create_info.minImageCount > capabilities.maxImageCount) {
        create_info.minImageCount = capabilities.maxImageCount;
    }
    create_info.imageFormat = ctx.swapchain_format;
    create_info.imageColorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
    create_info.imageExtent = ctx.swapchain_extent;
    create_info.imageArrayLayers = 1;
    create_info.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    create_info.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    create_info.preTransform = capabilities.currentTransform;
    create_info.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    create_info.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    create_info.clipped = VK_TRUE;

    check_vk(vkCreateSwapchainKHR(ctx.device, &create_info, nullptr, &ctx.swapchain), "Failed to create swapchain");

    uint32_t image_count;
    vkGetSwapchainImagesKHR(ctx.device, ctx.swapchain, &image_count, nullptr);
    ctx.swapchain_images.resize(image_count);
    vkGetSwapchainImagesKHR(ctx.device, ctx.swapchain, &image_count, ctx.swapchain_images.data());

    // Create image views
    ctx.swapchain_image_views.resize(image_count);
    for (uint32_t i = 0; i < image_count; i++) {
        VkImageViewCreateInfo view_info{};
        view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        view_info.image = ctx.swapchain_images[i];
        view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
        view_info.format = ctx.swapchain_format;
        view_info.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        view_info.subresourceRange.baseMipLevel = 0;
        view_info.subresourceRange.levelCount = 1;
        view_info.subresourceRange.baseArrayLayer = 0;
        view_info.subresourceRange.layerCount = 1;
        check_vk(vkCreateImageView(ctx.device, &view_info, nullptr, &ctx.swapchain_image_views[i]), "Failed to create image view");
    }

    // Create framebuffers
    ctx.framebuffers.resize(image_count);
    for (uint32_t i = 0; i < image_count; i++) {
        VkFramebufferCreateInfo fb_info{};
        fb_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb_info.renderPass = ctx.render_pass;
        fb_info.attachmentCount = 1;
        fb_info.pAttachments = &ctx.swapchain_image_views[i];
        fb_info.width = ctx.swapchain_extent.width;
        fb_info.height = ctx.swapchain_extent.height;
        fb_info.layers = 1;
        check_vk(vkCreateFramebuffer(ctx.device, &fb_info, nullptr, &ctx.framebuffers[i]), "Failed to create framebuffer");
    }
}

int main() {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        fprintf(stderr, "Failed to initialize GLFW\n");
        return 1;
    }

    if (!glfwVulkanSupported()) {
        fprintf(stderr, "Vulkan not supported\n");
        glfwTerminate();
        return 1;
    }

    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    GLFWwindow* window = glfwCreateWindow(1280, 720, "PE/ELF Viewer", nullptr, nullptr);
    if (!window) {
        fprintf(stderr, "Failed to create window\n");
        glfwTerminate();
        return 1;
    }

    VulkanContext ctx;

    // Get required extensions
    uint32_t extensions_count = 0;
    const char** glfw_extensions = glfwGetRequiredInstanceExtensions(&extensions_count);

    // Create instance
    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "PE/ELF Viewer";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "No Engine";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo instance_info{};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app_info;
    instance_info.enabledExtensionCount = extensions_count;
    instance_info.ppEnabledExtensionNames = glfw_extensions;

    check_vk(vkCreateInstance(&instance_info, nullptr, &ctx.instance), "Failed to create instance");

    // Create surface
    check_vk(glfwCreateWindowSurface(ctx.instance, window, nullptr, &ctx.surface), "Failed to create surface");

    // Select physical device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(ctx.instance, &device_count, nullptr);
    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(ctx.instance, &device_count, devices.data());
    ctx.physical_device = devices[0];

    // Find graphics queue family
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(ctx.physical_device, &queue_family_count, nullptr);
    std::vector<VkQueueFamilyProperties> queue_families(queue_family_count);
    vkGetPhysicalDeviceQueueFamilyProperties(ctx.physical_device, &queue_family_count, queue_families.data());

    for (uint32_t i = 0; i < queue_family_count; i++) {
        if (queue_families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
            ctx.graphics_family = i;
            break;
        }
    }

    // Create logical device
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info{};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = ctx.graphics_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;

    const char* device_extensions[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
    VkDeviceCreateInfo device_info{};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    device_info.enabledExtensionCount = 1;
    device_info.ppEnabledExtensionNames = device_extensions;

    check_vk(vkCreateDevice(ctx.physical_device, &device_info, nullptr, &ctx.device), "Failed to create device");
    vkGetDeviceQueue(ctx.device, ctx.graphics_family, 0, &ctx.graphics_queue);

    // Create render pass
    VkAttachmentDescription color_attachment{};
    color_attachment.format = VK_FORMAT_B8G8R8A8_SRGB;
    color_attachment.samples = VK_SAMPLE_COUNT_1_BIT;
    color_attachment.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    color_attachment.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    color_attachment.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    color_attachment.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    color_attachment.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    color_attachment.finalLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;

    VkAttachmentReference color_ref{};
    color_ref.attachment = 0;
    color_ref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &color_ref;

    VkSubpassDependency dependency{};
    dependency.srcSubpass = VK_SUBPASS_EXTERNAL;
    dependency.dstSubpass = 0;
    dependency.srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.srcAccessMask = 0;
    dependency.dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;

    VkRenderPassCreateInfo render_pass_info{};
    render_pass_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    render_pass_info.attachmentCount = 1;
    render_pass_info.pAttachments = &color_attachment;
    render_pass_info.subpassCount = 1;
    render_pass_info.pSubpasses = &subpass;
    render_pass_info.dependencyCount = 1;
    render_pass_info.pDependencies = &dependency;

    check_vk(vkCreateRenderPass(ctx.device, &render_pass_info, nullptr, &ctx.render_pass), "Failed to create render pass");

    // Create swapchain
    create_swapchain(ctx, window);

    // Create command pool
    VkCommandPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pool_info.queueFamilyIndex = ctx.graphics_family;
    check_vk(vkCreateCommandPool(ctx.device, &pool_info, nullptr, &ctx.command_pool), "Failed to create command pool");

    // Create command buffers
    ctx.command_buffers.resize(ctx.swapchain_images.size());
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = ctx.command_pool;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = static_cast<uint32_t>(ctx.command_buffers.size());
    check_vk(vkAllocateCommandBuffers(ctx.device, &alloc_info, ctx.command_buffers.data()), "Failed to allocate command buffers");

    // Create descriptor pool for ImGui
    VkDescriptorPoolSize pool_sizes[] = {
        { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1 },
    };
    VkDescriptorPoolCreateInfo desc_pool_info{};
    desc_pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    desc_pool_info.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    desc_pool_info.maxSets = 1;
    desc_pool_info.poolSizeCount = 1;
    desc_pool_info.pPoolSizes = pool_sizes;
    check_vk(vkCreateDescriptorPool(ctx.device, &desc_pool_info, nullptr, &ctx.descriptor_pool), "Failed to create descriptor pool");

    // Create sync objects
    VkSemaphoreCreateInfo sem_info{};
    sem_info.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    VkFenceCreateInfo fence_info{};
    fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fence_info.flags = VK_FENCE_CREATE_SIGNALED_BIT;

    check_vk(vkCreateSemaphore(ctx.device, &sem_info, nullptr, &ctx.image_available_semaphore), "Failed to create semaphore");
    check_vk(vkCreateSemaphore(ctx.device, &sem_info, nullptr, &ctx.render_finished_semaphore), "Failed to create semaphore");
    check_vk(vkCreateFence(ctx.device, &fence_info, nullptr, &ctx.in_flight_fence), "Failed to create fence");

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForVulkan(window, true);

    ImGui_ImplVulkan_InitInfo init_info{};
    init_info.Instance = ctx.instance;
    init_info.PhysicalDevice = ctx.physical_device;
    init_info.Device = ctx.device;
    init_info.QueueFamily = ctx.graphics_family;
    init_info.Queue = ctx.graphics_queue;
    init_info.DescriptorPool = ctx.descriptor_pool;
    init_info.RenderPass = ctx.render_pass;
    init_info.MinImageCount = 2;
    init_info.ImageCount = static_cast<uint32_t>(ctx.swapchain_images.size());
    init_info.MSAASamples = VK_SAMPLE_COUNT_1_BIT;

    ImGui_ImplVulkan_Init(&init_info);

    printf("Window created successfully!\n");

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        if (glfwGetKey(window, GLFW_KEY_ESCAPE) == GLFW_PRESS) {
            glfwSetWindowShouldClose(window, GLFW_TRUE);
        }

        // Wait for previous frame
        vkWaitForFences(ctx.device, 1, &ctx.in_flight_fence, VK_TRUE, UINT64_MAX);
        vkResetFences(ctx.device, 1, &ctx.in_flight_fence);

        // Acquire next image
        uint32_t image_index;
        vkAcquireNextImageKHR(ctx.device, ctx.swapchain, UINT64_MAX, ctx.image_available_semaphore, VK_NULL_HANDLE, &image_index);

        // Start ImGui frame
        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::ShowDemoWindow();

        ImGui::Render();

        // Record command buffer
        VkCommandBuffer cmd = ctx.command_buffers[image_index];
        vkResetCommandBuffer(cmd, 0);

        VkCommandBufferBeginInfo begin_info{};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        vkBeginCommandBuffer(cmd, &begin_info);

        VkClearValue clear_color = {{{0.1f, 0.1f, 0.1f, 1.0f}}};
        VkRenderPassBeginInfo rp_info{};
        rp_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        rp_info.renderPass = ctx.render_pass;
        rp_info.framebuffer = ctx.framebuffers[image_index];
        rp_info.renderArea.extent = ctx.swapchain_extent;
        rp_info.clearValueCount = 1;
        rp_info.pClearValues = &clear_color;

        vkCmdBeginRenderPass(cmd, &rp_info, VK_SUBPASS_CONTENTS_INLINE);
        ImGui_ImplVulkan_RenderDrawData(ImGui::GetDrawData(), cmd);
        vkCmdEndRenderPass(cmd);
        vkEndCommandBuffer(cmd);

        // Submit
        VkSemaphore wait_semaphores[] = { ctx.image_available_semaphore };
        VkPipelineStageFlags wait_stages[] = { VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT };
        VkSemaphore signal_semaphores[] = { ctx.render_finished_semaphore };

        VkSubmitInfo submit_info{};
        submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit_info.waitSemaphoreCount = 1;
        submit_info.pWaitSemaphores = wait_semaphores;
        submit_info.pWaitDstStageMask = wait_stages;
        submit_info.commandBufferCount = 1;
        submit_info.pCommandBuffers = &cmd;
        submit_info.signalSemaphoreCount = 1;
        submit_info.pSignalSemaphores = signal_semaphores;

        check_vk(vkQueueSubmit(ctx.graphics_queue, 1, &submit_info, ctx.in_flight_fence), "Failed to submit");

        // Present
        VkPresentInfoKHR present_info{};
        present_info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
        present_info.waitSemaphoreCount = 1;
        present_info.pWaitSemaphores = signal_semaphores;
        present_info.swapchainCount = 1;
        present_info.pSwapchains = &ctx.swapchain;
        present_info.pImageIndices = &image_index;

        vkQueuePresentKHR(ctx.graphics_queue, &present_info);
    }

    vkDeviceWaitIdle(ctx.device);

    // Cleanup
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    vkDestroyFence(ctx.device, ctx.in_flight_fence, nullptr);
    vkDestroySemaphore(ctx.device, ctx.render_finished_semaphore, nullptr);
    vkDestroySemaphore(ctx.device, ctx.image_available_semaphore, nullptr);
    vkDestroyDescriptorPool(ctx.device, ctx.descriptor_pool, nullptr);
    vkDestroyCommandPool(ctx.device, ctx.command_pool, nullptr);
    cleanup_swapchain(ctx);
    vkDestroyRenderPass(ctx.device, ctx.render_pass, nullptr);
    vkDestroyDevice(ctx.device, nullptr);
    vkDestroySurfaceKHR(ctx.instance, ctx.surface, nullptr);
    vkDestroyInstance(ctx.instance, nullptr);

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}