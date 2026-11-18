#include "vulkan/gpu_offscreen_canvas.hpp"

#include "vulkan/spirv_validation.hpp"

#include <imgui_impl_vulkan.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace viewer {

namespace {

void check_canvas_vk(VkResult result, const char* message) {
    if (result != VK_SUCCESS) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] bool imgui_vulkan_backend_alive() noexcept {
    if (ImGui::GetCurrentContext() == nullptr) {
        return false;
    }
    return ImGui::GetIO().BackendRendererUserData != nullptr;
}

} // namespace

// ============================================================================
// GpuHostRingBuffer
// ============================================================================

GpuHostRingBuffer::BufferAllocation::BufferAllocation(BufferAllocation&& other) noexcept
    : device(std::exchange(other.device, VK_NULL_HANDLE)),
      buffer(std::move(other.buffer)),
      memory(std::move(other.memory)),
      mapped(std::exchange(other.mapped, nullptr)),
      capacity(std::exchange(other.capacity, 0)) {}

GpuHostRingBuffer::BufferAllocation& GpuHostRingBuffer::BufferAllocation::operator=(
    BufferAllocation&& other) noexcept {
    if (this != &other) {
        reset();
        device = std::exchange(other.device, VK_NULL_HANDLE);
        buffer = std::move(other.buffer);
        memory = std::move(other.memory);
        mapped = std::exchange(other.mapped, nullptr);
        capacity = std::exchange(other.capacity, 0);
    }
    return *this;
}

void GpuHostRingBuffer::BufferAllocation::reset() noexcept {
    if (mapped != nullptr && device != VK_NULL_HANDLE && memory) {
        vkUnmapMemory(device, memory.get());
    }
    mapped = nullptr;
    buffer.reset();
    memory.reset();
    device = VK_NULL_HANDLE;
    capacity = 0;
}

GpuHostRingBuffer::GpuHostRingBuffer(VulkanManager& vulkan, VkBufferUsageFlags usage_flags) noexcept
    : vulkan_(&vulkan), usage_flags_(usage_flags) {}

GpuHostRingBuffer::~GpuHostRingBuffer() noexcept {
    shutdown();
}

GpuHostRingBuffer::GpuHostRingBuffer(GpuHostRingBuffer&& other) noexcept
    : vulkan_(std::exchange(other.vulkan_, nullptr)),
      usage_flags_(other.usage_flags_),
      slots_(std::move(other.slots_)),
      last_touched_slot_(
          std::exchange(other.last_touched_slot_, VulkanManager::kMaxFramesInFlight)) {}

GpuHostRingBuffer& GpuHostRingBuffer::operator=(GpuHostRingBuffer&& other) noexcept {
    if (this != &other) {
        shutdown();
        vulkan_ = std::exchange(other.vulkan_, nullptr);
        usage_flags_ = other.usage_flags_;
        slots_ = std::move(other.slots_);
        last_touched_slot_ =
            std::exchange(other.last_touched_slot_, VulkanManager::kMaxFramesInFlight);
    }
    return *this;
}

void GpuHostRingBuffer::attach(VulkanManager& vulkan, VkBufferUsageFlags usage_flags) noexcept {
    if (vulkan_ != &vulkan || usage_flags_ != usage_flags) {
        shutdown();
        vulkan_ = &vulkan;
        usage_flags_ = usage_flags;
    }
}

void GpuHostRingBuffer::shutdown() noexcept {
    bool any_allocated = false;
    for (const auto& slot : slots_) {
        if (slot.active.buffer || !slot.retired.empty()) {
            any_allocated = true;
            break;
        }
    }
    if (any_allocated && vulkan_ != nullptr && vulkan_->device() != VK_NULL_HANDLE) {
        vulkan_->wait_idle();
    }
    for (auto& slot : slots_) {
        slot.retired.clear();
        slot.active.reset();
        slot.uploaded_bytes = 0;
    }
    last_touched_slot_ = VulkanManager::kMaxFramesInFlight;
}

GpuHostRingBuffer::BufferAllocation GpuHostRingBuffer::allocate_buffer(
    std::size_t capacity_bytes) const {
    if (vulkan_ == nullptr || vulkan_->device() == VK_NULL_HANDLE) {
        throw std::runtime_error("GpuHostRingBuffer requires an initialized VulkanManager");
    }
    const VkDevice dev = vulkan_->device();

    VkBufferCreateInfo buf_ci{};
    buf_ci.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_ci.size = static_cast<VkDeviceSize>(capacity_bytes);
    buf_ci.usage = usage_flags_;
    buf_ci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer raw_buf = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateBuffer(dev, &buf_ci, nullptr, &raw_buf),
                    "vkCreateBuffer failed in GpuHostRingBuffer");
    detail::UniqueVkBuffer unique_buf(dev, raw_buf);

    VkMemoryRequirements mem_req{};
    vkGetBufferMemoryRequirements(dev, unique_buf.get(), &mem_req);

    VkMemoryAllocateInfo alloc_ci{};
    alloc_ci.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_ci.allocationSize = mem_req.size;
    alloc_ci.memoryTypeIndex = vulkan_->find_memory_type(
        mem_req.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

    VkDeviceMemory raw_mem = VK_NULL_HANDLE;
    check_canvas_vk(vkAllocateMemory(dev, &alloc_ci, nullptr, &raw_mem),
                    "vkAllocateMemory failed in GpuHostRingBuffer");
    detail::UniqueVkDeviceMemory unique_mem(dev, raw_mem);

    check_canvas_vk(vkBindBufferMemory(dev, unique_buf.get(), unique_mem.get(), 0),
                    "vkBindBufferMemory failed in GpuHostRingBuffer");

    void* mapped_ptr = nullptr;
    check_canvas_vk(
        vkMapMemory(dev, unique_mem.get(), 0, static_cast<VkDeviceSize>(capacity_bytes), 0, &mapped_ptr),
        "vkMapMemory failed in GpuHostRingBuffer");

    BufferAllocation alloc{};
    alloc.device = dev;
    alloc.buffer = std::move(unique_buf);
    alloc.memory = std::move(unique_mem);
    alloc.mapped = mapped_ptr;
    alloc.capacity = static_cast<VkDeviceSize>(capacity_bytes);
    return alloc;
}

void GpuHostRingBuffer::reclaim_retired_on_slot_entry(std::size_t frame_index) noexcept {
    if (last_touched_slot_ != frame_index) {
        // Switching back to frame_index after another frame slot ran guarantees that
        // begin_frame() has waited on frame_index's in-flight fence.
        slots_[frame_index].retired.clear();
        last_touched_slot_ = frame_index;
    }
}

void GpuHostRingBuffer::ensure_capacity(std::size_t frame_index, std::size_t required_bytes) {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        throw std::out_of_range("GpuHostRingBuffer frame_index out of range");
    }
    const std::size_t target_cap =
        next_ring_buffer_capacity_bytes(required_bytes, kMinCapacityBytes);
    if (target_cap == 0u) {
        throw std::length_error("GpuHostRingBuffer requested capacity exceeds maximum");
    }

    reclaim_retired_on_slot_entry(frame_index);
    FrameBufferSlot& slot = slots_[frame_index];
    if (slot.active.buffer && slot.active.capacity >= static_cast<VkDeviceSize>(target_cap)) {
        return;
    }

    BufferAllocation fresh = allocate_buffer(target_cap);
    if (slot.active.buffer) {
        slot.retired.push_back(std::move(slot.active));
    }
    slot.active = std::move(fresh);
}

void GpuHostRingBuffer::upload_bytes(std::size_t frame_index, std::span<const std::byte> bytes) {
    ensure_capacity(frame_index, bytes.size());
    FrameBufferSlot& slot = slots_[frame_index];
    if (!bytes.empty()) {
        std::memcpy(slot.active.mapped, bytes.data(), bytes.size());
    } else if (slot.active.mapped != nullptr && slot.active.capacity >= sizeof(std::uint32_t)) {
        std::memset(slot.active.mapped, 0, sizeof(std::uint32_t));
    }
    slot.uploaded_bytes = static_cast<VkDeviceSize>(bytes.size());
}

VkBuffer GpuHostRingBuffer::buffer(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return slots_[frame_index].active.buffer.get();
}

VkDeviceSize GpuHostRingBuffer::capacity_bytes(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return 0;
    }
    return slots_[frame_index].active.capacity;
}

VkDeviceSize GpuHostRingBuffer::uploaded_bytes(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return 0;
    }
    return slots_[frame_index].uploaded_bytes;
}

VkDescriptorBufferInfo GpuHostRingBuffer::descriptor_info(
    std::size_t frame_index) const noexcept {
    VkDescriptorBufferInfo info{};
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return info;
    }
    const FrameBufferSlot& slot = slots_[frame_index];
    info.buffer = slot.active.buffer.get();
    info.offset = 0;
    const VkDeviceSize fallback_min =
        std::min<VkDeviceSize>(slot.active.capacity, sizeof(std::uint32_t));
    info.range = slot.uploaded_bytes > 0 ? slot.uploaded_bytes : fallback_min;
    return info;
}

// ============================================================================
// GpuComputePipeline
// ============================================================================

GpuComputePipeline::~GpuComputePipeline() noexcept {
    shutdown();
}

GpuComputePipeline::GpuComputePipeline(GpuComputePipeline&& other) noexcept
    : vulkan_(std::exchange(other.vulkan_, nullptr)),
      has_ssbo_binding_(std::exchange(other.has_ssbo_binding_, false)),
      push_constant_bytes_(std::exchange(other.push_constant_bytes_, 0)),
      descriptor_set_layout_(std::move(other.descriptor_set_layout_)),
      pipeline_layout_(std::move(other.pipeline_layout_)),
      pipeline_(std::move(other.pipeline_)),
      descriptor_sets_(std::exchange(other.descriptor_sets_, {})) {}

GpuComputePipeline& GpuComputePipeline::operator=(GpuComputePipeline&& other) noexcept {
    if (this != &other) {
        shutdown();
        vulkan_ = std::exchange(other.vulkan_, nullptr);
        has_ssbo_binding_ = std::exchange(other.has_ssbo_binding_, false);
        push_constant_bytes_ = std::exchange(other.push_constant_bytes_, 0);
        descriptor_set_layout_ = std::move(other.descriptor_set_layout_);
        pipeline_layout_ = std::move(other.pipeline_layout_);
        pipeline_ = std::move(other.pipeline_);
        descriptor_sets_ = std::exchange(other.descriptor_sets_, {});
    }
    return *this;
}

void GpuComputePipeline::init(VulkanManager& vulkan,
                              std::span<const std::uint32_t> compute_spirv,
                              std::uint32_t push_constant_bytes,
                              bool has_ssbo_binding) {
    shutdown();
    if (vulkan.device() == VK_NULL_HANDLE || vulkan.descriptor_pool() == VK_NULL_HANDLE) {
        throw std::runtime_error("GpuComputePipeline::init requires initialized VulkanManager");
    }

    const VkDevice dev = vulkan.device();
    detail::UniqueVkShaderModule shader_mod = vulkan.create_shader_module(compute_spirv);

    std::array<VkDescriptorSetLayoutBinding, 2> bindings{};
    bindings[0].binding = 0;
    bindings[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
    bindings[0].descriptorCount = 1;
    bindings[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    bindings[1].binding = 1;
    bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[1].descriptorCount = 1;
    bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    VkDescriptorSetLayoutCreateInfo dsl_ci{};
    dsl_ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dsl_ci.bindingCount = has_ssbo_binding ? 2u : 1u;
    dsl_ci.pBindings = bindings.data();

    VkDescriptorSetLayout raw_dsl = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateDescriptorSetLayout(dev, &dsl_ci, nullptr, &raw_dsl),
                    "vkCreateDescriptorSetLayout failed in GpuComputePipeline");
    detail::UniqueVkDescriptorSetLayout dsl(dev, raw_dsl);

    VkPushConstantRange pc_range{};
    pc_range.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pc_range.offset = 0;
    pc_range.size = push_constant_bytes;

    const VkDescriptorSetLayout dsl_handle = dsl.get();
    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl_ci.setLayoutCount = 1;
    pl_ci.pSetLayouts = &dsl_handle;
    if (push_constant_bytes > 0u) {
        pl_ci.pushConstantRangeCount = 1;
        pl_ci.pPushConstantRanges = &pc_range;
    }

    VkPipelineLayout raw_pl = VK_NULL_HANDLE;
    check_canvas_vk(vkCreatePipelineLayout(dev, &pl_ci, nullptr, &raw_pl),
                    "vkCreatePipelineLayout failed in GpuComputePipeline");
    detail::UniqueVkPipelineLayout pl(dev, raw_pl);

    VkComputePipelineCreateInfo cp_ci{};
    cp_ci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp_ci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cp_ci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cp_ci.stage.module = shader_mod.get();
    cp_ci.stage.pName = "main";
    cp_ci.layout = pl.get();

    VkPipeline raw_pipe = VK_NULL_HANDLE;
    check_canvas_vk(
        vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cp_ci, nullptr, &raw_pipe),
        "vkCreateComputePipelines failed in GpuComputePipeline");
    detail::UniqueVkPipeline pipe(dev, raw_pipe);

    std::array<VkDescriptorSetLayout, VulkanManager::kMaxFramesInFlight> set_layouts{};
    set_layouts.fill(dsl.get());

    VkDescriptorSetAllocateInfo ds_ai{};
    ds_ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ds_ai.descriptorPool = vulkan.descriptor_pool();
    ds_ai.descriptorSetCount = VulkanManager::kMaxFramesInFlight;
    ds_ai.pSetLayouts = set_layouts.data();

    std::array<VkDescriptorSet, VulkanManager::kMaxFramesInFlight> sets{};
    check_canvas_vk(vkAllocateDescriptorSets(dev, &ds_ai, sets.data()),
                    "vkAllocateDescriptorSets failed in GpuComputePipeline");

    vulkan_ = &vulkan;
    has_ssbo_binding_ = has_ssbo_binding;
    push_constant_bytes_ = push_constant_bytes;
    descriptor_set_layout_ = std::move(dsl);
    pipeline_layout_ = std::move(pl);
    pipeline_ = std::move(pipe);
    descriptor_sets_ = sets;
}

void GpuComputePipeline::shutdown() noexcept {
    if (vulkan_ != nullptr && vulkan_->device() != VK_NULL_HANDLE &&
        vulkan_->descriptor_pool() != VK_NULL_HANDLE &&
        descriptor_sets_[0] != VK_NULL_HANDLE) {
        (void)vkFreeDescriptorSets(vulkan_->device(),
                                   vulkan_->descriptor_pool(),
                                   VulkanManager::kMaxFramesInFlight,
                                   descriptor_sets_.data());
    }
    descriptor_sets_.fill(VK_NULL_HANDLE);
    pipeline_.reset();
    pipeline_layout_.reset();
    descriptor_set_layout_.reset();
    push_constant_bytes_ = 0;
    has_ssbo_binding_ = false;
    vulkan_ = nullptr;
}

VkDescriptorSet GpuComputePipeline::descriptor_set(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return descriptor_sets_[frame_index];
}

// ============================================================================
// GpuGraphics2DPipeline
// ============================================================================

void GpuGraphics2DPipeline::init(VulkanManager& vulkan,
                                 VkRenderPass render_pass,
                                 const GpuGraphics2DPipelineDesc& desc) {
    shutdown();
    if (vulkan.device() == VK_NULL_HANDLE || render_pass == VK_NULL_HANDLE) {
        throw std::runtime_error(
            "GpuGraphics2DPipeline::init requires valid VulkanManager and VkRenderPass");
    }
    const VkDevice dev = vulkan.device();

    detail::UniqueVkShaderModule vert_mod = vulkan.create_shader_module(desc.vertex_spirv);
    detail::UniqueVkShaderModule frag_mod = vulkan.create_shader_module(desc.fragment_spirv);

    VkPushConstantRange pc_range{};
    pc_range.stageFlags = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
    pc_range.offset = 0;
    pc_range.size = desc.push_constant_bytes;

    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl_ci.setLayoutCount = static_cast<uint32_t>(desc.descriptor_set_layouts.size());
    pl_ci.pSetLayouts =
        desc.descriptor_set_layouts.empty() ? nullptr : desc.descriptor_set_layouts.data();
    if (desc.push_constant_bytes > 0u) {
        pl_ci.pushConstantRangeCount = 1;
        pl_ci.pPushConstantRanges = &pc_range;
    }

    VkPipelineLayout raw_pl = VK_NULL_HANDLE;
    check_canvas_vk(vkCreatePipelineLayout(dev, &pl_ci, nullptr, &raw_pl),
                    "vkCreatePipelineLayout failed in GpuGraphics2DPipeline");
    detail::UniqueVkPipelineLayout pl(dev, raw_pl);

    std::array<VkPipelineShaderStageCreateInfo, 2> stages{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vert_mod.get();
    stages[0].pName = "main";

    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = frag_mod.get();
    stages[1].pName = "main";

    VkPipelineVertexInputStateCreateInfo vi_ci{};
    vi_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    vi_ci.vertexBindingDescriptionCount = static_cast<uint32_t>(desc.vertex_bindings.size());
    vi_ci.pVertexBindingDescriptions =
        desc.vertex_bindings.empty() ? nullptr : desc.vertex_bindings.data();
    vi_ci.vertexAttributeDescriptionCount = static_cast<uint32_t>(desc.vertex_attributes.size());
    vi_ci.pVertexAttributeDescriptions =
        desc.vertex_attributes.empty() ? nullptr : desc.vertex_attributes.data();

    VkPipelineInputAssemblyStateCreateInfo ia_ci{};
    ia_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia_ci.topology = desc.topology;
    ia_ci.primitiveRestartEnable = VK_FALSE;

    VkPipelineViewportStateCreateInfo vp_ci{};
    vp_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp_ci.viewportCount = 1;
    vp_ci.scissorCount = 1;

    VkPipelineRasterizationStateCreateInfo rs_ci{};
    rs_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    rs_ci.polygonMode = VK_POLYGON_MODE_FILL;
    rs_ci.cullMode = VK_CULL_MODE_NONE;
    rs_ci.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs_ci.lineWidth = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms_ci{};
    ms_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms_ci.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState cb_att{};
    cb_att.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                            VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
    if (desc.alpha_blend) {
        cb_att.blendEnable = VK_TRUE;
        cb_att.srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA;
        cb_att.dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
        cb_att.colorBlendOp = VK_BLEND_OP_ADD;
        cb_att.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
        cb_att.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
        cb_att.alphaBlendOp = VK_BLEND_OP_ADD;
    } else {
        cb_att.blendEnable = VK_FALSE;
    }

    VkPipelineColorBlendStateCreateInfo cb_ci{};
    cb_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb_ci.attachmentCount = 1;
    cb_ci.pAttachments = &cb_att;

    constexpr std::array<VkDynamicState, 2> dyn_states{{
        VK_DYNAMIC_STATE_VIEWPORT,
        VK_DYNAMIC_STATE_SCISSOR,
    }};
    VkPipelineDynamicStateCreateInfo dyn_ci{};
    dyn_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dyn_ci.dynamicStateCount = static_cast<uint32_t>(dyn_states.size());
    dyn_ci.pDynamicStates = dyn_states.data();

    VkGraphicsPipelineCreateInfo gp_ci{};
    gp_ci.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    gp_ci.stageCount = static_cast<uint32_t>(stages.size());
    gp_ci.pStages = stages.data();
    gp_ci.pVertexInputState = &vi_ci;
    gp_ci.pInputAssemblyState = &ia_ci;
    gp_ci.pViewportState = &vp_ci;
    gp_ci.pRasterizationState = &rs_ci;
    gp_ci.pMultisampleState = &ms_ci;
    gp_ci.pColorBlendState = &cb_ci;
    gp_ci.pDynamicState = &dyn_ci;
    gp_ci.layout = pl.get();
    gp_ci.renderPass = render_pass;
    gp_ci.subpass = 0;

    VkPipeline raw_pipe = VK_NULL_HANDLE;
    check_canvas_vk(
        vkCreateGraphicsPipelines(dev, VK_NULL_HANDLE, 1, &gp_ci, nullptr, &raw_pipe),
        "vkCreateGraphicsPipelines failed in GpuGraphics2DPipeline");

    pipeline_layout_ = std::move(pl);
    pipeline_.reset(dev, raw_pipe);
}

void GpuGraphics2DPipeline::shutdown() noexcept {
    pipeline_.reset();
    pipeline_layout_.reset();
}

// ============================================================================
// GpuOffscreenCanvas
// ============================================================================

GpuOffscreenCanvas::GpuOffscreenCanvas(VulkanManager& vulkan,
                                       const GpuOffscreenCanvasConfig& config) {
    init(vulkan, config);
}

GpuOffscreenCanvas::~GpuOffscreenCanvas() noexcept {
    shutdown();
}

GpuOffscreenCanvas::GpuOffscreenCanvas(GpuOffscreenCanvas&& other) noexcept
    : vulkan_(std::exchange(other.vulkan_, nullptr)),
      config_(other.config_),
      sampler_(std::move(other.sampler_)),
      offscreen_render_pass_(std::move(other.offscreen_render_pass_)),
      slots_(std::move(other.slots_)),
      staging_ring_(std::move(other.staging_ring_)),
      smoke_clear_pipeline_(std::move(other.smoke_clear_pipeline_)),
      width_(std::exchange(other.width_, 0)),
      height_(std::exchange(other.height_, 0)),
      pending_width_(std::exchange(other.pending_width_, 0)),
      pending_height_(std::exchange(other.pending_height_, 0)),
      pending_resize_frames_(std::exchange(other.pending_resize_frames_, 0)),
      offscreen_pass_open_(std::exchange(other.offscreen_pass_open_, false)) {}

GpuOffscreenCanvas& GpuOffscreenCanvas::operator=(GpuOffscreenCanvas&& other) noexcept {
    if (this != &other) {
        shutdown();
        vulkan_ = std::exchange(other.vulkan_, nullptr);
        config_ = other.config_;
        sampler_ = std::move(other.sampler_);
        offscreen_render_pass_ = std::move(other.offscreen_render_pass_);
        slots_ = std::move(other.slots_);
        staging_ring_ = std::move(other.staging_ring_);
        smoke_clear_pipeline_ = std::move(other.smoke_clear_pipeline_);
        width_ = std::exchange(other.width_, 0);
        height_ = std::exchange(other.height_, 0);
        pending_width_ = std::exchange(other.pending_width_, 0);
        pending_height_ = std::exchange(other.pending_height_, 0);
        pending_resize_frames_ = std::exchange(other.pending_resize_frames_, 0);
        offscreen_pass_open_ = std::exchange(other.offscreen_pass_open_, false);
    }
    return *this;
}

void GpuOffscreenCanvas::init(VulkanManager& vulkan, const GpuOffscreenCanvasConfig& config) {
    shutdown();
    if (vulkan.device() == VK_NULL_HANDLE) {
        throw std::runtime_error("GpuOffscreenCanvas::init requires initialized VulkanManager");
    }
    vulkan_ = &vulkan;
    config_ = config;
    staging_ring_.attach(vulkan, VK_BUFFER_USAGE_TRANSFER_SRC_BIT);
    create_sampler();
    if (vulkan_->supports_rgba8_color_attachment()) {
        create_offscreen_render_pass();
    }
}

void GpuOffscreenCanvas::shutdown() noexcept {
    release_images();
    smoke_clear_pipeline_.shutdown();
    staging_ring_.shutdown();
    offscreen_render_pass_.reset();
    sampler_.reset();
    vulkan_ = nullptr;
    width_ = 0;
    height_ = 0;
    pending_width_ = 0;
    pending_height_ = 0;
    pending_resize_frames_ = 0;
    offscreen_pass_open_ = false;
}

void GpuOffscreenCanvas::create_sampler() {
    VkSamplerCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
    ci.magFilter = config_.sampler_filter;
    ci.minFilter = config_.sampler_filter;
    ci.mipmapMode = VK_SAMPLER_MIPMAP_MODE_NEAREST;
    ci.addressModeU = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    ci.addressModeV = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    ci.addressModeW = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    ci.minLod = 0.0f;
    ci.maxLod = 0.0f;

    VkSampler raw_sampler = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateSampler(vulkan_->device(), &ci, nullptr, &raw_sampler),
                    "vkCreateSampler failed in GpuOffscreenCanvas");
    sampler_.reset(vulkan_->device(), raw_sampler);
}

void GpuOffscreenCanvas::create_offscreen_render_pass() {
    VkAttachmentDescription color_att{};
    color_att.format = VK_FORMAT_R8G8B8A8_UNORM;
    color_att.samples = VK_SAMPLE_COUNT_1_BIT;
    color_att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    color_att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    color_att.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    color_att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    color_att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    color_att.finalLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;

    VkAttachmentReference color_ref{};
    color_ref.attachment = 0;
    color_ref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &color_ref;

    std::array<VkSubpassDependency, 2> deps{};
    deps[0].srcSubpass = VK_SUBPASS_EXTERNAL;
    deps[0].dstSubpass = 0;
    deps[0].srcStageMask = VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT;
    deps[0].dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[0].srcAccessMask = VK_ACCESS_SHADER_READ_BIT;
    deps[0].dstAccessMask =
        VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[0].dependencyFlags = VK_DEPENDENCY_BY_REGION_BIT;

    deps[1].srcSubpass = 0;
    deps[1].dstSubpass = VK_SUBPASS_EXTERNAL;
    deps[1].srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[1].dstStageMask = VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT;
    deps[1].srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[1].dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    deps[1].dependencyFlags = VK_DEPENDENCY_BY_REGION_BIT;

    VkRenderPassCreateInfo rp_ci{};
    rp_ci.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp_ci.attachmentCount = 1;
    rp_ci.pAttachments = &color_att;
    rp_ci.subpassCount = 1;
    rp_ci.pSubpasses = &subpass;
    rp_ci.dependencyCount = static_cast<uint32_t>(deps.size());
    rp_ci.pDependencies = deps.data();

    VkRenderPass raw_rp = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateRenderPass(vulkan_->device(), &rp_ci, nullptr, &raw_rp),
                    "vkCreateRenderPass failed in GpuOffscreenCanvas");
    offscreen_render_pass_.reset(vulkan_->device(), raw_rp);
}

void GpuOffscreenCanvas::release_images() noexcept {
    bool any_live = false;
    for (const auto& slot : slots_) {
        if (slot.image || slot.view || slot.framebuffer ||
            slot.imgui_descriptor_set != VK_NULL_HANDLE) {
            any_live = true;
            break;
        }
    }
    if (any_live && vulkan_ != nullptr && vulkan_->device() != VK_NULL_HANDLE) {
        vulkan_->wait_idle();
    }

    const bool can_remove_imgui_tex = imgui_vulkan_backend_alive();
    for (auto& slot : slots_) {
        if (slot.imgui_descriptor_set != VK_NULL_HANDLE) {
            if (can_remove_imgui_tex) {
                ImGui_ImplVulkan_RemoveTexture(slot.imgui_descriptor_set);
            }
            slot.imgui_descriptor_set = VK_NULL_HANDLE;
        }
        slot.framebuffer.reset();
        slot.view.reset();
        slot.image.reset();
        slot.memory.reset();
        slot.current_layout = VK_IMAGE_LAYOUT_UNDEFINED;
    }
    width_ = 0;
    height_ = 0;
}

void GpuOffscreenCanvas::initialize_images_to_shader_read_only() {
    const VkDevice dev = vulkan_->device();

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;
    pool_ci.queueFamilyIndex = vulkan_->graphics_family();

    VkCommandPool raw_pool = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateCommandPool(dev, &pool_ci, nullptr, &raw_pool),
                    "vkCreateCommandPool failed in GpuOffscreenCanvas");
    detail::UniqueVkCommandPool transient_pool(dev, raw_pool);

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = transient_pool.get();
    cb_ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cb_ai.commandBufferCount = 1;

    VkCommandBuffer cmd = VK_NULL_HANDLE;
    check_canvas_vk(vkAllocateCommandBuffers(dev, &cb_ai, &cmd),
                    "vkAllocateCommandBuffers failed in GpuOffscreenCanvas");

    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    check_canvas_vk(vkBeginCommandBuffer(cmd, &bi),
                    "vkBeginCommandBuffer failed in GpuOffscreenCanvas");

    VkImageSubresourceRange subrange{};
    subrange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    subrange.baseMipLevel = 0;
    subrange.levelCount = 1;
    subrange.baseArrayLayer = 0;
    subrange.layerCount = 1;

    const VkClearColorValue zero_clear{{0.0f, 0.0f, 0.0f, 0.0f}};

    for (auto& slot : slots_) {
        VkImageMemoryBarrier to_transfer{};
        to_transfer.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        to_transfer.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        to_transfer.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        to_transfer.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_transfer.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_transfer.image = slot.image.get();
        to_transfer.subresourceRange = subrange;
        to_transfer.srcAccessMask = 0;
        to_transfer.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;

        vkCmdPipelineBarrier(cmd,
                             VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,
                             0,
                             0,
                             nullptr,
                             0,
                             nullptr,
                             1,
                             &to_transfer);

        vkCmdClearColorImage(
            cmd, slot.image.get(), VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &zero_clear, 1, &subrange);

        VkImageMemoryBarrier to_read{};
        to_read.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        to_read.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        to_read.newLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
        to_read.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_read.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        to_read.image = slot.image.get();
        to_read.subresourceRange = subrange;
        to_read.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        to_read.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;

        vkCmdPipelineBarrier(cmd,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
                             0,
                             0,
                             nullptr,
                             0,
                             nullptr,
                             1,
                             &to_read);

        slot.current_layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    }

    check_canvas_vk(vkEndCommandBuffer(cmd), "vkEndCommandBuffer failed in GpuOffscreenCanvas");

    VkFenceCreateInfo fence_ci{};
    fence_ci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence raw_fence = VK_NULL_HANDLE;
    check_canvas_vk(vkCreateFence(dev, &fence_ci, nullptr, &raw_fence),
                    "vkCreateFence failed in GpuOffscreenCanvas");
    detail::UniqueVkFence fence(dev, raw_fence);

    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    check_canvas_vk(vkQueueSubmit(vulkan_->graphics_queue(), 1, &submit, fence.get()),
                    "vkQueueSubmit failed in GpuOffscreenCanvas");
    check_canvas_vk(vkWaitForFences(dev, 1, &raw_fence, VK_TRUE, UINT64_MAX),
                    "vkWaitForFences failed in GpuOffscreenCanvas");
}

void GpuOffscreenCanvas::reallocate_images(std::uint32_t new_width, std::uint32_t new_height) {
    release_images();

    const VkDevice dev = vulkan_->device();
    VkImageUsageFlags usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    if (vulkan_->supports_rgba8_storage_image()) {
        usage |= VK_IMAGE_USAGE_STORAGE_BIT;
    }
    if (vulkan_->supports_rgba8_color_attachment()) {
        usage |= VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    }

    for (auto& slot : slots_) {
        VkImageCreateInfo img_ci{};
        img_ci.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        img_ci.imageType = VK_IMAGE_TYPE_2D;
        img_ci.format = VK_FORMAT_R8G8B8A8_UNORM;
        img_ci.extent = {new_width, new_height, 1u};
        img_ci.mipLevels = 1;
        img_ci.arrayLayers = 1;
        img_ci.samples = VK_SAMPLE_COUNT_1_BIT;
        img_ci.tiling = VK_IMAGE_TILING_OPTIMAL;
        img_ci.usage = usage;
        img_ci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        img_ci.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;

        VkImage raw_img = VK_NULL_HANDLE;
        check_canvas_vk(vkCreateImage(dev, &img_ci, nullptr, &raw_img),
                        "vkCreateImage failed in GpuOffscreenCanvas");
        slot.image.reset(dev, raw_img);

        VkMemoryRequirements mem_req{};
        vkGetImageMemoryRequirements(dev, slot.image.get(), &mem_req);

        VkMemoryAllocateInfo mem_ai{};
        mem_ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mem_ai.allocationSize = mem_req.size;
        mem_ai.memoryTypeIndex = vulkan_->find_memory_type(
            mem_req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);

        VkDeviceMemory raw_mem = VK_NULL_HANDLE;
        check_canvas_vk(vkAllocateMemory(dev, &mem_ai, nullptr, &raw_mem),
                        "vkAllocateMemory failed in GpuOffscreenCanvas");
        slot.memory.reset(dev, raw_mem);

        check_canvas_vk(vkBindImageMemory(dev, slot.image.get(), slot.memory.get(), 0),
                        "vkBindImageMemory failed in GpuOffscreenCanvas");

        VkImageViewCreateInfo view_ci{};
        view_ci.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        view_ci.image = slot.image.get();
        view_ci.viewType = VK_IMAGE_VIEW_TYPE_2D;
        view_ci.format = VK_FORMAT_R8G8B8A8_UNORM;
        view_ci.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        view_ci.subresourceRange.baseMipLevel = 0;
        view_ci.subresourceRange.levelCount = 1;
        view_ci.subresourceRange.baseArrayLayer = 0;
        view_ci.subresourceRange.layerCount = 1;

        VkImageView raw_view = VK_NULL_HANDLE;
        check_canvas_vk(vkCreateImageView(dev, &view_ci, nullptr, &raw_view),
                        "vkCreateImageView failed in GpuOffscreenCanvas");
        slot.view.reset(dev, raw_view);

        if (offscreen_render_pass_) {
            const VkImageView att_view = slot.view.get();
            VkFramebufferCreateInfo fb_ci{};
            fb_ci.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
            fb_ci.renderPass = offscreen_render_pass_.get();
            fb_ci.attachmentCount = 1;
            fb_ci.pAttachments = &att_view;
            fb_ci.width = new_width;
            fb_ci.height = new_height;
            fb_ci.layers = 1;

            VkFramebuffer raw_fb = VK_NULL_HANDLE;
            check_canvas_vk(vkCreateFramebuffer(dev, &fb_ci, nullptr, &raw_fb),
                            "vkCreateFramebuffer failed in GpuOffscreenCanvas");
            slot.framebuffer.reset(dev, raw_fb);
        }

        if (imgui_vulkan_backend_alive()) {
            slot.imgui_descriptor_set = ImGui_ImplVulkan_AddTexture(
                slot.view.get(), VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
            if (slot.imgui_descriptor_set == VK_NULL_HANDLE) {
                release_images();
                throw std::runtime_error(
                    "ImGui_ImplVulkan_AddTexture failed in GpuOffscreenCanvas");
            }
        }
    }

    width_ = new_width;
    height_ = new_height;
    initialize_images_to_shader_read_only();
}

bool GpuOffscreenCanvas::ensure_size(std::uint32_t requested_width,
                                     std::uint32_t requested_height,
                                     bool immediate) {
    if (vulkan_ == nullptr || vulkan_->device() == VK_NULL_HANDLE) {
        throw std::runtime_error("GpuOffscreenCanvas::ensure_size called before init");
    }

    const std::uint32_t clamped_w =
        clamp_offscreen_canvas_dim(requested_width, vulkan_->max_image_dimension_2d());
    const std::uint32_t clamped_h =
        clamp_offscreen_canvas_dim(requested_height, vulkan_->max_image_dimension_2d());

    if (width_ == 0u || height_ == 0u) {
        pending_width_ = clamped_w;
        pending_height_ = clamped_h;
        pending_resize_frames_ = 0u;
        reallocate_images(clamped_w, clamped_h);
        return true;
    }

    if (clamped_w == width_ && clamped_h == height_) {
        pending_width_ = clamped_w;
        pending_height_ = clamped_h;
        pending_resize_frames_ = 0u;
        return false;
    }

    if (immediate || config_.resize_debounce_frames == 0u) {
        pending_width_ = clamped_w;
        pending_height_ = clamped_h;
        pending_resize_frames_ = 0u;
        reallocate_images(clamped_w, clamped_h);
        return true;
    }

    if (clamped_w != pending_width_ || clamped_h != pending_height_) {
        pending_width_ = clamped_w;
        pending_height_ = clamped_h;
        pending_resize_frames_ = 1u;
        return false;
    }

    ++pending_resize_frames_;
    if (pending_resize_frames_ >= config_.resize_debounce_frames) {
        pending_resize_frames_ = 0u;
        reallocate_images(clamped_w, clamped_h);
        return true;
    }
    return false;
}

VkImage GpuOffscreenCanvas::image(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return slots_[frame_index].image.get();
}

VkImageView GpuOffscreenCanvas::image_view(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return slots_[frame_index].view.get();
}

VkFramebuffer GpuOffscreenCanvas::framebuffer(std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return slots_[frame_index].framebuffer.get();
}

VkDescriptorSet GpuOffscreenCanvas::imgui_descriptor_set(
    std::size_t frame_index) const noexcept {
    if (frame_index >= VulkanManager::kMaxFramesInFlight) {
        return VK_NULL_HANDLE;
    }
    return slots_[frame_index].imgui_descriptor_set;
}

ImTextureID GpuOffscreenCanvas::imgui_texture_id(std::size_t frame_index) const noexcept {
    return reinterpret_cast<ImTextureID>(imgui_descriptor_set(frame_index));
}

void GpuOffscreenCanvas::record_compute_dispatch(VkCommandBuffer cmd,
                                                 std::size_t frame_index,
                                                 const GpuComputePipeline& pipeline,
                                                 const VkDescriptorBufferInfo* optional_ssbo,
                                                 std::span<const std::byte> push_constants,
                                                 std::uint32_t group_size_x,
                                                 std::uint32_t group_size_y) {
    if (cmd == VK_NULL_HANDLE || frame_index >= VulkanManager::kMaxFramesInFlight) {
        throw std::out_of_range("Invalid command buffer or frame_index in record_compute_dispatch");
    }
    if (!can_use_compute() || !pipeline.valid() || width_ == 0u || height_ == 0u) {
        throw std::runtime_error("GpuOffscreenCanvas compute dispatch prerequisites not met");
    }
    if (pipeline.has_ssbo_binding() &&
        (optional_ssbo == nullptr || optional_ssbo->buffer == VK_NULL_HANDLE)) {
        throw std::invalid_argument(
            "GpuComputePipeline expects SSBO binding=1, but optional_ssbo is null");
    }

    FrameImageSlot& slot = slots_[frame_index];
    const VkDescriptorSet ds = pipeline.descriptor_set(frame_index);

    VkDescriptorImageInfo img_info{};
    img_info.sampler = VK_NULL_HANDLE;
    img_info.imageView = slot.view.get();
    img_info.imageLayout = VK_IMAGE_LAYOUT_GENERAL;

    std::array<VkWriteDescriptorSet, 2> writes{};
    writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[0].dstSet = ds;
    writes[0].dstBinding = 0;
    writes[0].descriptorCount = 1;
    writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
    writes[0].pImageInfo = &img_info;

    uint32_t write_count = 1u;
    if (pipeline.has_ssbo_binding() && optional_ssbo != nullptr) {
        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = ds;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = optional_ssbo;
        write_count = 2u;
    }

    vkUpdateDescriptorSets(vulkan_->device(), write_count, writes.data(), 0, nullptr);

    VkImageSubresourceRange subrange{};
    subrange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    subrange.baseMipLevel = 0;
    subrange.levelCount = 1;
    subrange.baseArrayLayer = 0;
    subrange.layerCount = 1;

    VkImageMemoryBarrier to_general{};
    to_general.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_general.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    to_general.newLayout = VK_IMAGE_LAYOUT_GENERAL;
    to_general.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_general.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_general.image = slot.image.get();
    to_general.subresourceRange = subrange;
    to_general.srcAccessMask = 0;
    to_general.dstAccessMask = VK_ACCESS_SHADER_WRITE_BIT;

    vkCmdPipelineBarrier(cmd,
                         VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT | VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                         VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0,
                         0,
                         nullptr,
                         0,
                         nullptr,
                         1,
                         &to_general);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline.pipeline());
    vkCmdBindDescriptorSets(
        cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline.pipeline_layout(), 0, 1, &ds, 0, nullptr);

    if (!push_constants.empty() && pipeline.push_constant_bytes() > 0u) {
        const auto push_bytes = static_cast<uint32_t>(
            std::min<std::size_t>(push_constants.size(), pipeline.push_constant_bytes()));
        vkCmdPushConstants(cmd,
                           pipeline.pipeline_layout(),
                           VK_SHADER_STAGE_COMPUTE_BIT,
                           0,
                           push_bytes,
                           push_constants.data());
    }

    const std::uint32_t gx = std::max(group_size_x, 1u);
    const std::uint32_t gy = std::max(group_size_y, 1u);
    const std::uint32_t groups_x = (width_ + gx - 1u) / gx;
    const std::uint32_t groups_y = (height_ + gy - 1u) / gy;
    vkCmdDispatch(cmd, groups_x, groups_y, 1u);

    VkImageMemoryBarrier to_fragment_read{};
    to_fragment_read.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_fragment_read.oldLayout = VK_IMAGE_LAYOUT_GENERAL;
    to_fragment_read.newLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    to_fragment_read.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_fragment_read.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_fragment_read.image = slot.image.get();
    to_fragment_read.subresourceRange = subrange;
    to_fragment_read.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    to_fragment_read.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;

    vkCmdPipelineBarrier(cmd,
                         VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
                         0,
                         0,
                         nullptr,
                         0,
                         nullptr,
                         1,
                         &to_fragment_read);

    slot.current_layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
}

void GpuOffscreenCanvas::record_smoke_clear_compute(VkCommandBuffer cmd,
                                                    std::size_t frame_index,
                                                    ColorFloat4 clear_color) {
    if (!smoke_clear_pipeline_.valid()) {
        smoke_clear_pipeline_.init(*vulkan_,
                                   shaders::kSmokeClearCompSpirv,
                                   sizeof(shaders::SmokeClearPushConstants),
                                   false);
    }
    const shaders::SmokeClearPushConstants pc{
        .clear_color = {clear_color.r, clear_color.g, clear_color.b, clear_color.a},
        .width = width_,
        .height = height_,
    };
    record_compute_dispatch(
        cmd, frame_index, smoke_clear_pipeline_, nullptr, std::as_bytes(std::span{&pc, 1}));
}

void GpuOffscreenCanvas::begin_offscreen_render_pass(VkCommandBuffer cmd,
                                                     std::size_t frame_index,
                                                     ColorFloat4 clear_color) {
    if (cmd == VK_NULL_HANDLE || frame_index >= VulkanManager::kMaxFramesInFlight) {
        throw std::out_of_range(
            "Invalid command buffer or frame_index in begin_offscreen_render_pass");
    }
    if (!can_use_graphics() || width_ == 0u || height_ == 0u ||
        !slots_[frame_index].framebuffer) {
        throw std::runtime_error(
            "GpuOffscreenCanvas graphics render pass prerequisites not met");
    }

    VkClearValue clear_val{};
    clear_val.color = {{clear_color.r, clear_color.g, clear_color.b, clear_color.a}};

    VkRenderPassBeginInfo rp_bi{};
    rp_bi.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rp_bi.renderPass = offscreen_render_pass_.get();
    rp_bi.framebuffer = slots_[frame_index].framebuffer.get();
    rp_bi.renderArea.offset = {0, 0};
    rp_bi.renderArea.extent = {width_, height_};
    rp_bi.clearValueCount = 1;
    rp_bi.pClearValues = &clear_val;

    vkCmdBeginRenderPass(cmd, &rp_bi, VK_SUBPASS_CONTENTS_INLINE);

    VkViewport viewport{};
    viewport.x = 0.0f;
    viewport.y = 0.0f;
    viewport.width = static_cast<float>(width_);
    viewport.height = static_cast<float>(height_);
    viewport.minDepth = 0.0f;
    viewport.maxDepth = 1.0f;
    vkCmdSetViewport(cmd, 0, 1, &viewport);

    VkRect2D scissor{};
    scissor.offset = {0, 0};
    scissor.extent = {width_, height_};
    vkCmdSetScissor(cmd, 0, 1, &scissor);

    offscreen_pass_open_ = true;
}

void GpuOffscreenCanvas::end_offscreen_render_pass(VkCommandBuffer cmd,
                                                   std::size_t frame_index) noexcept {
    if (!offscreen_pass_open_ || cmd == VK_NULL_HANDLE ||
        frame_index >= VulkanManager::kMaxFramesInFlight) {
        return;
    }
    vkCmdEndRenderPass(cmd);
    offscreen_pass_open_ = false;
    slots_[frame_index].current_layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
}

void GpuOffscreenCanvas::record_instanced_render_pass(VkCommandBuffer cmd,
                                                      std::size_t frame_index,
                                                      ColorFloat4 clear_color,
                                                      const OffscreenDrawCallback& draw_fn) {
    begin_offscreen_render_pass(cmd, frame_index, clear_color);
    try {
        if (draw_fn) {
            draw_fn(cmd, VkExtent2D{width_, height_});
        }
    } catch (...) {
        end_offscreen_render_pass(cmd, frame_index);
        throw;
    }
    end_offscreen_render_pass(cmd, frame_index);
}

void GpuOffscreenCanvas::record_cpu_rgba8_upload(VkCommandBuffer cmd,
                                                 std::size_t frame_index,
                                                 std::span<const std::uint8_t> rgba8_pixels) {
    if (cmd == VK_NULL_HANDLE || frame_index >= VulkanManager::kMaxFramesInFlight) {
        throw std::out_of_range("Invalid command buffer or frame_index in record_cpu_rgba8_upload");
    }
    if (width_ == 0u || height_ == 0u || !slots_[frame_index].image) {
        throw std::runtime_error("GpuOffscreenCanvas::record_cpu_rgba8_upload called before size");
    }

    const std::size_t expected_pixels =
        static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_);
    if (expected_pixels > (std::numeric_limits<std::size_t>::max() / 4u) ||
        rgba8_pixels.size() != expected_pixels * 4u) {
        throw std::invalid_argument(
            "GpuOffscreenCanvas::record_cpu_rgba8_upload byte size mismatch");
    }

    staging_ring_.upload(frame_index, rgba8_pixels);
    FrameImageSlot& slot = slots_[frame_index];

    VkImageSubresourceRange subrange{};
    subrange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    subrange.baseMipLevel = 0;
    subrange.levelCount = 1;
    subrange.baseArrayLayer = 0;
    subrange.layerCount = 1;

    VkImageMemoryBarrier to_transfer{};
    to_transfer.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_transfer.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    to_transfer.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_transfer.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.image = slot.image.get();
    to_transfer.subresourceRange = subrange;
    to_transfer.srcAccessMask = 0;
    to_transfer.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;

    vkCmdPipelineBarrier(cmd,
                         VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT | VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT,
                         0,
                         0,
                         nullptr,
                         0,
                         nullptr,
                         1,
                         &to_transfer);

    VkBufferImageCopy copy_region{};
    copy_region.bufferOffset = 0;
    copy_region.bufferRowLength = 0;
    copy_region.bufferImageHeight = 0;
    copy_region.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    copy_region.imageSubresource.mipLevel = 0;
    copy_region.imageSubresource.baseArrayLayer = 0;
    copy_region.imageSubresource.layerCount = 1;
    copy_region.imageOffset = {0, 0, 0};
    copy_region.imageExtent = {width_, height_, 1u};

    vkCmdCopyBufferToImage(cmd,
                           staging_ring_.buffer(frame_index),
                           slot.image.get(),
                           VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                           1,
                           &copy_region);

    VkImageMemoryBarrier to_read{};
    to_read.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_read.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_read.newLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    to_read.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_read.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_read.image = slot.image.get();
    to_read.subresourceRange = subrange;
    to_read.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    to_read.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;

    vkCmdPipelineBarrier(cmd,
                         VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
                         0,
                         0,
                         nullptr,
                         0,
                         nullptr,
                         1,
                         &to_read);

    slot.current_layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
}

} // namespace viewer
