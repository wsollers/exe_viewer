#pragma once

#include "vulkan/viewport_camera_2d.hpp"
#include "vulkan/vulkan_manager.h"

#include <imgui.h>
#include <vulkan/vulkan.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <type_traits>
#include <vector>

namespace viewer {

inline constexpr std::uint32_t kMinOffscreenCanvasDim = 16u;
inline constexpr std::uint32_t kMaxOffscreenCanvasDim = 4096u;
inline constexpr std::uint32_t kDefaultComputeGroupSize2D = 16u;

[[nodiscard]] constexpr std::uint32_t clamp_offscreen_canvas_dim(
    std::uint32_t requested,
    std::uint32_t device_max_dim_2d = kMaxOffscreenCanvasDim) noexcept {
    const std::uint32_t effective_device_max =
        device_max_dim_2d >= kMinOffscreenCanvasDim ? device_max_dim_2d : kMaxOffscreenCanvasDim;
    const std::uint32_t upper = effective_device_max < kMaxOffscreenCanvasDim
                                    ? effective_device_max
                                    : kMaxOffscreenCanvasDim;
    if (requested < kMinOffscreenCanvasDim) {
        return kMinOffscreenCanvasDim;
    }
    if (requested > upper) {
        return upper;
    }
    return requested;
}

[[nodiscard]] constexpr std::size_t next_ring_buffer_capacity_bytes(
    std::size_t required_bytes,
    std::size_t min_capacity_bytes = 256u) noexcept;

// Per-frame-in-flight HOST_VISIBLE | HOST_COHERENT ring buffer supporting SSBO, vertex/instance,
// uniform, and transfer-source usage with zero-stall deferred retirement across frame fences.
class GpuHostRingBuffer {
public:
    static constexpr std::size_t kMinCapacityBytes = 256u;
    static constexpr std::size_t kMaxCapacityBytes = std::size_t{1} << 29; // 512 MiB cap
    static constexpr VkBufferUsageFlags kDefaultUsageFlags =
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_VERTEX_BUFFER_BIT |
        VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;

    GpuHostRingBuffer() = default;
    explicit GpuHostRingBuffer(VulkanManager& vulkan,
                               VkBufferUsageFlags usage_flags = kDefaultUsageFlags) noexcept;
    ~GpuHostRingBuffer() noexcept;

    GpuHostRingBuffer(const GpuHostRingBuffer&) = delete;
    GpuHostRingBuffer& operator=(const GpuHostRingBuffer&) = delete;
    GpuHostRingBuffer(GpuHostRingBuffer&& other) noexcept;
    GpuHostRingBuffer& operator=(GpuHostRingBuffer&& other) noexcept;

    void attach(VulkanManager& vulkan,
                VkBufferUsageFlags usage_flags = kDefaultUsageFlags) noexcept;
    void shutdown() noexcept;

    void ensure_capacity(std::size_t frame_index, std::size_t required_bytes);
    void upload_bytes(std::size_t frame_index, std::span<const std::byte> bytes);

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    void upload(std::size_t frame_index, std::span<const T> elements) {
        upload_bytes(frame_index, std::as_bytes(elements));
    }

    [[nodiscard]] bool valid() const noexcept {
        return vulkan_ != nullptr && vulkan_->device() != VK_NULL_HANDLE;
    }
    [[nodiscard]] VkBuffer buffer(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkDeviceSize capacity_bytes(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkDeviceSize uploaded_bytes(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkDescriptorBufferInfo descriptor_info(std::size_t frame_index) const noexcept;

private:
    struct BufferAllocation {
        VkDevice device = VK_NULL_HANDLE;
        detail::UniqueVkBuffer buffer;
        detail::UniqueVkDeviceMemory memory;
        void* mapped = nullptr;
        VkDeviceSize capacity = 0;

        BufferAllocation() = default;
        ~BufferAllocation() noexcept { reset(); }
        BufferAllocation(const BufferAllocation&) = delete;
        BufferAllocation& operator=(const BufferAllocation&) = delete;
        BufferAllocation(BufferAllocation&& other) noexcept;
        BufferAllocation& operator=(BufferAllocation&& other) noexcept;

        void reset() noexcept;
    };

    struct FrameBufferSlot {
        BufferAllocation active;
        VkDeviceSize uploaded_bytes = 0;
        std::vector<BufferAllocation> retired;
    };

    [[nodiscard]] BufferAllocation allocate_buffer(std::size_t capacity_bytes) const;
    void reclaim_retired_on_slot_entry(std::size_t frame_index) noexcept;

    VulkanManager* vulkan_ = nullptr;
    VkBufferUsageFlags usage_flags_ = kDefaultUsageFlags;
    std::array<FrameBufferSlot, VulkanManager::kMaxFramesInFlight> slots_{};
    std::size_t last_touched_slot_ = VulkanManager::kMaxFramesInFlight;
};

// Reusable compute pipeline wrapper binding binding=0 storage image (rgba8) and optional
// binding=1 SSBO, with per-frame descriptor sets allocated from VulkanManager's pool.
class GpuComputePipeline {
public:
    GpuComputePipeline() = default;
    ~GpuComputePipeline() noexcept;

    GpuComputePipeline(const GpuComputePipeline&) = delete;
    GpuComputePipeline& operator=(const GpuComputePipeline&) = delete;
    GpuComputePipeline(GpuComputePipeline&& other) noexcept;
    GpuComputePipeline& operator=(GpuComputePipeline&& other) noexcept;

    void init(VulkanManager& vulkan,
              std::span<const std::uint32_t> compute_spirv,
              std::uint32_t push_constant_bytes = 0,
              bool has_ssbo_binding = false);
    void shutdown() noexcept;

    [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(pipeline_); }
    [[nodiscard]] bool has_ssbo_binding() const noexcept { return has_ssbo_binding_; }
    [[nodiscard]] std::uint32_t push_constant_bytes() const noexcept {
        return push_constant_bytes_;
    }
    [[nodiscard]] VkPipeline pipeline() const noexcept { return pipeline_.get(); }
    [[nodiscard]] VkPipelineLayout pipeline_layout() const noexcept {
        return pipeline_layout_.get();
    }
    [[nodiscard]] VkDescriptorSet descriptor_set(std::size_t frame_index) const noexcept;

private:
    VulkanManager* vulkan_ = nullptr;
    bool has_ssbo_binding_ = false;
    std::uint32_t push_constant_bytes_ = 0;
    detail::UniqueVkDescriptorSetLayout descriptor_set_layout_;
    detail::UniqueVkPipelineLayout pipeline_layout_;
    detail::UniqueVkPipeline pipeline_;
    std::array<VkDescriptorSet, VulkanManager::kMaxFramesInFlight> descriptor_sets_{};
};

struct GpuGraphics2DPipelineDesc {
    std::span<const std::uint32_t> vertex_spirv{};
    std::span<const std::uint32_t> fragment_spirv{};
    std::span<const VkVertexInputBindingDescription> vertex_bindings{};
    std::span<const VkVertexInputAttributeDescription> vertex_attributes{};
    std::span<const VkDescriptorSetLayout> descriptor_set_layouts{};
    std::uint32_t push_constant_bytes = 0;
    VkPrimitiveTopology topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    bool alpha_blend = true;
};

class GpuGraphics2DPipeline {
public:
    GpuGraphics2DPipeline() = default;
    ~GpuGraphics2DPipeline() = default;

    GpuGraphics2DPipeline(const GpuGraphics2DPipeline&) = delete;
    GpuGraphics2DPipeline& operator=(const GpuGraphics2DPipeline&) = delete;
    GpuGraphics2DPipeline(GpuGraphics2DPipeline&&) noexcept = default;
    GpuGraphics2DPipeline& operator=(GpuGraphics2DPipeline&&) noexcept = default;

    void init(VulkanManager& vulkan,
              VkRenderPass render_pass,
              const GpuGraphics2DPipelineDesc& desc);
    void shutdown() noexcept;

    [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(pipeline_); }
    [[nodiscard]] VkPipeline pipeline() const noexcept { return pipeline_.get(); }
    [[nodiscard]] VkPipelineLayout pipeline_layout() const noexcept {
        return pipeline_layout_.get();
    }

private:
    detail::UniqueVkPipelineLayout pipeline_layout_;
    detail::UniqueVkPipeline pipeline_;
};

struct GpuOffscreenCanvasConfig {
    VkFilter sampler_filter = VK_FILTER_LINEAR;
    std::uint32_t resize_debounce_frames = 2u;
};

// Ring-buffered RGBA8 offscreen canvas supporting compute storage-image dispatches,
// instanced 2D graphics render passes, and CPU RGBA8 staging fallback uploads.
class GpuOffscreenCanvas {
public:
    using OffscreenDrawCallback = std::function<void(VkCommandBuffer, VkExtent2D)>;

    GpuOffscreenCanvas() = default;
    explicit GpuOffscreenCanvas(VulkanManager& vulkan,
                                const GpuOffscreenCanvasConfig& config = {});
    ~GpuOffscreenCanvas() noexcept;

    GpuOffscreenCanvas(const GpuOffscreenCanvas&) = delete;
    GpuOffscreenCanvas& operator=(const GpuOffscreenCanvas&) = delete;
    GpuOffscreenCanvas(GpuOffscreenCanvas&& other) noexcept;
    GpuOffscreenCanvas& operator=(GpuOffscreenCanvas&& other) noexcept;

    void init(VulkanManager& vulkan, const GpuOffscreenCanvasConfig& config = {});
    void shutdown() noexcept;

    // Ensures offscreen images match clamped requested dimensions (debounced across live resize).
    // Safe to call during UI build BEFORE emitting ImGui::Image(imgui_texture_id(frame_index)).
    bool ensure_size(std::uint32_t requested_width,
                     std::uint32_t requested_height,
                     bool immediate = false);

    [[nodiscard]] bool valid() const noexcept {
        return vulkan_ != nullptr && width_ > 0u && height_ > 0u &&
               slots_[0].imgui_descriptor_set != VK_NULL_HANDLE;
    }
    [[nodiscard]] std::uint32_t width() const noexcept { return width_; }
    [[nodiscard]] std::uint32_t height() const noexcept { return height_; }
    [[nodiscard]] VkExtent2D extent() const noexcept { return {width_, height_}; }
    [[nodiscard]] VkRenderPass offscreen_render_pass() const noexcept {
        return offscreen_render_pass_.get();
    }
    [[nodiscard]] VkSampler sampler() const noexcept { return sampler_.get(); }

    [[nodiscard]] bool can_use_compute() const noexcept {
        return vulkan_ != nullptr && vulkan_->supports_compute() &&
               vulkan_->supports_rgba8_storage_image();
    }
    [[nodiscard]] bool can_use_graphics() const noexcept {
        return vulkan_ != nullptr && vulkan_->supports_rgba8_color_attachment() &&
               static_cast<bool>(offscreen_render_pass_);
    }

    [[nodiscard]] VkImage image(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkImageView image_view(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkFramebuffer framebuffer(std::size_t frame_index) const noexcept;
    [[nodiscard]] VkDescriptorSet imgui_descriptor_set(std::size_t frame_index) const noexcept;
    [[nodiscard]] ImTextureID imgui_texture_id(std::size_t frame_index) const noexcept;

    // Mode (a): Compute storage-image dispatch + explicit barrier to SHADER_READ_ONLY_OPTIMAL.
    void record_compute_dispatch(VkCommandBuffer cmd,
                                 std::size_t frame_index,
                                 const GpuComputePipeline& pipeline,
                                 const VkDescriptorBufferInfo* optional_ssbo = nullptr,
                                 std::span<const std::byte> push_constants = {},
                                 std::uint32_t group_size_x = kDefaultComputeGroupSize2D,
                                 std::uint32_t group_size_y = kDefaultComputeGroupSize2D);

    // Built-in compute smoke helper clearing the canvas via embedded kSmokeClearCompSpirv.
    void record_smoke_clear_compute(VkCommandBuffer cmd,
                                    std::size_t frame_index,
                                    ColorFloat4 clear_color);

    // Mode (b): Lightweight offscreen instanced 2D render pass transitioning automatically
    // to VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL via external subpass dependency.
    void begin_offscreen_render_pass(VkCommandBuffer cmd,
                                     std::size_t frame_index,
                                     ColorFloat4 clear_color = {0.06f, 0.07f, 0.09f, 1.0f});
    void end_offscreen_render_pass(VkCommandBuffer cmd, std::size_t frame_index) noexcept;

    void record_instanced_render_pass(VkCommandBuffer cmd,
                                      std::size_t frame_index,
                                      ColorFloat4 clear_color,
                                      const OffscreenDrawCallback& draw_fn);

    // Mode (c): CPU-reference RGBA8 pixel upload via GpuHostRingBuffer + vkCmdCopyBufferToImage.
    void record_cpu_rgba8_upload(VkCommandBuffer cmd,
                                 std::size_t frame_index,
                                 std::span<const std::uint8_t> rgba8_pixels);

private:
    struct FrameImageSlot {
        detail::UniqueVkImage image;
        detail::UniqueVkDeviceMemory memory;
        detail::UniqueVkImageView view;
        detail::UniqueVkFramebuffer framebuffer;
        VkDescriptorSet imgui_descriptor_set = VK_NULL_HANDLE;
        VkImageLayout current_layout = VK_IMAGE_LAYOUT_UNDEFINED;
    };

    void create_sampler();
    void create_offscreen_render_pass();
    void reallocate_images(std::uint32_t new_width, std::uint32_t new_height);
    void release_images() noexcept;
    void initialize_images_to_shader_read_only();

    VulkanManager* vulkan_ = nullptr;
    GpuOffscreenCanvasConfig config_{};
    detail::UniqueVkSampler sampler_;
    detail::UniqueVkRenderPass offscreen_render_pass_;
    std::array<FrameImageSlot, VulkanManager::kMaxFramesInFlight> slots_{};
    GpuHostRingBuffer staging_ring_;
    GpuComputePipeline smoke_clear_pipeline_;

    std::uint32_t width_ = 0;
    std::uint32_t height_ = 0;
    std::uint32_t pending_width_ = 0;
    std::uint32_t pending_height_ = 0;
    std::uint32_t pending_resize_frames_ = 0;
    bool offscreen_pass_open_ = false;
};

constexpr std::size_t next_ring_buffer_capacity_bytes(
    std::size_t required_bytes,
    std::size_t min_capacity_bytes) noexcept {
    const std::size_t floor_cap = min_capacity_bytes > 0u ? min_capacity_bytes : 256u;
    if (required_bytes <= floor_cap) {
        return floor_cap;
    }
    if (required_bytes > GpuHostRingBuffer::kMaxCapacityBytes) {
        return 0u; // signals overflow / exceeding cap
    }
    std::size_t cap = floor_cap;
    while (cap < required_bytes) {
        if (cap > (GpuHostRingBuffer::kMaxCapacityBytes / 2u)) {
            return GpuHostRingBuffer::kMaxCapacityBytes;
        }
        cap *= 2u;
    }
    return cap;
}

} // namespace viewer
