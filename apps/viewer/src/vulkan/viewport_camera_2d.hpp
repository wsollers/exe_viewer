#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace viewer {

struct Vec2d {
    double x = 0.0;
    double y = 0.0;
};

struct Vec2f {
    float x = 0.0f;
    float y = 0.0f;
};

struct WorldRect2D {
    double min_x = 0.0;
    double min_y = 0.0;
    double max_x = 0.0;
    double max_y = 0.0;

    [[nodiscard]] constexpr double width() const noexcept { return max_x - min_x; }
    [[nodiscard]] constexpr double height() const noexcept { return max_y - min_y; }
    [[nodiscard]] constexpr bool contains(double x, double y) const noexcept {
        return x >= min_x && x <= max_x && y >= min_y && y <= max_y;
    }
};

// Camera-relative float32 GPU projection uniform (std140 / std430 / push-constant aligned).
// Subtracting double-precision (world - camera.center) on the CPU before casting to float32
// preserves full 24-bit mantissa precision around the viewport center even at >= 1,000,000x
// zoom over 64-bit virtual addresses or nanosecond execution timelines.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324)
#endif
struct alignas(16) CameraRelativeUniform2D {
    float viewport_width = 1.0f;
    float viewport_height = 1.0f;
    float scale_x = 1.0f;
    float scale_y = 1.0f;
    float inv_scale_x = 1.0f;
    float inv_scale_y = 1.0f;
    float ndc_scale_x = 2.0f;
    float ndc_scale_y = 2.0f;
    // Double-single (hi + lo) decomposition of camera center for compute shaders that
    // reconstruct high-precision world coordinates from pixel coordinates.
    float center_x_hi = 0.0f;
    float center_x_lo = 0.0f;
    float center_y_hi = 0.0f;
    float center_y_lo = 0.0f;

    [[nodiscard]] constexpr Vec2f project_relative_to_screen(float rel_world_x,
                                                             float rel_world_y) const noexcept {
        return Vec2f{
            .x = (0.5f * viewport_width) + (rel_world_x * scale_x),
            .y = (0.5f * viewport_height) + (rel_world_y * scale_y),
        };
    }

    [[nodiscard]] constexpr Vec2f project_relative_to_ndc(float rel_world_x,
                                                          float rel_world_y) const noexcept {
        return Vec2f{
            .x = rel_world_x * ndc_scale_x,
            .y = rel_world_y * ndc_scale_y,
        };
    }

    [[nodiscard]] constexpr Vec2f screen_to_relative_world(float screen_x,
                                                           float screen_y) const noexcept {
        return Vec2f{
            .x = (screen_x - (0.5f * viewport_width)) * inv_scale_x,
            .y = (screen_y - (0.5f * viewport_height)) * inv_scale_y,
        };
    }
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static_assert(sizeof(CameraRelativeUniform2D) == 48,
              "CameraRelativeUniform2D must remain tightly packed for push constants / UBOs");

class ViewportCamera2D {
public:
    static constexpr double kDefaultMinScale = 1.0e-12;
    static constexpr double kDefaultMaxScale = 1.0e9;
    static constexpr double kMaxAbsCoordinate = 1.0e18;

    double center_x = 0.0;
    double center_y = 0.0;
    double scale_x = 1.0;
    double scale_y = 1.0;
    double min_scale = kDefaultMinScale;
    double max_scale = kDefaultMaxScale;

    void sanitize() noexcept;

    [[nodiscard]] Vec2d world_to_screen(double world_x,
                                        double world_y,
                                        double viewport_w,
                                        double viewport_h) const noexcept;

    [[nodiscard]] Vec2d screen_to_world(double screen_x,
                                        double screen_y,
                                        double viewport_w,
                                        double viewport_h) const noexcept;

    [[nodiscard]] WorldRect2D visible_world_rect(double viewport_w,
                                                 double viewport_h) const noexcept;

    void pan_by_pixels(double dx, double dy) noexcept;

    void zoom_at_screen_pixel(double px,
                              double py,
                              double factor,
                              double viewport_w,
                              double viewport_h) noexcept;

    void zoom_axes_at_screen_pixel(double px,
                                   double py,
                                   double factor_x,
                                   double factor_y,
                                   double viewport_w,
                                   double viewport_h) noexcept;

    void fit_bounds(double min_x,
                    double min_y,
                    double max_x,
                    double max_y,
                    double viewport_w,
                    double viewport_h,
                    bool preserve_aspect = true) noexcept;

    // Camera-relative float32 offset (world - center) computed in double precision first.
    [[nodiscard]] Vec2f relative_world_f32(double world_x, double world_y) const noexcept;

    [[nodiscard]] CameraRelativeUniform2D build_gpu_uniform(double viewport_w,
                                                            double viewport_h) const noexcept;

    [[nodiscard]] Vec2f project_world_to_screen_f32(double world_x,
                                                    double world_y,
                                                    double viewport_w,
                                                    double viewport_h) const noexcept;

    // LOD & sub-pixel decimation helpers.
    [[nodiscard]] double world_units_per_pixel_x() const noexcept;
    [[nodiscard]] double world_units_per_pixel_y() const noexcept;
    [[nodiscard]] std::uint32_t compute_lod_level(std::uint32_t max_lod_level = 16u,
                                                  double base_pixels_per_unit = 1.0) const noexcept;

    // Screen-pixel hit-testing helpers (with optional pixel tolerance for thin features).
    [[nodiscard]] bool hit_test_world_rect(double px,
                                           double py,
                                           const WorldRect2D& world_rect,
                                           double viewport_w,
                                           double viewport_h,
                                           double pixel_slop = 0.0) const noexcept;

    [[nodiscard]] bool hit_test_world_point(double px,
                                            double py,
                                            double world_x,
                                            double world_y,
                                            double viewport_w,
                                            double viewport_h,
                                            double radius_pixels = 4.0) const noexcept;
};

struct ColorFloat4 {
    float r = 0.0f;
    float g = 0.0f;
    float b = 0.0f;
    float a = 1.0f;

    [[nodiscard]] constexpr float luminance() const noexcept {
        return (0.2126f * r) + (0.7152f * g) + (0.0722f * b);
    }
};

struct ColorRgba8 {
    std::uint8_t r = 0;
    std::uint8_t g = 0;
    std::uint8_t b = 0;
    std::uint8_t a = 255;

    [[nodiscard]] constexpr bool operator==(const ColorRgba8&) const noexcept = default;

    // Packs into little-endian VK_FORMAT_R8G8B8A8_UNORM / IM_COL32 word (byte 0 = R .. byte 3 = A).
    [[nodiscard]] constexpr std::uint32_t pack_rgba_le() const noexcept {
        return static_cast<std::uint32_t>(r) |
               (static_cast<std::uint32_t>(g) << 8u) |
               (static_cast<std::uint32_t>(b) << 16u) |
               (static_cast<std::uint32_t>(a) << 24u);
    }

    [[nodiscard]] static constexpr ColorRgba8 unpack_rgba_le(std::uint32_t packed) noexcept {
        return ColorRgba8{
            .r = static_cast<std::uint8_t>(packed & 0xFFu),
            .g = static_cast<std::uint8_t>((packed >> 8u) & 0xFFu),
            .b = static_cast<std::uint8_t>((packed >> 16u) & 0xFFu),
            .a = static_cast<std::uint8_t>((packed >> 24u) & 0xFFu),
        };
    }

    [[nodiscard]] constexpr std::array<std::uint8_t, 4> to_bytes() const noexcept {
        return {r, g, b, a};
    }
};

enum class MemoryPermissionCategory : std::uint8_t {
    None = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ReadExecute = 3,
    ReadWriteExecute = 4,
    GuardOrReserved = 5,
};

enum class DiffStatusCategory : std::uint8_t {
    Unchanged = 0,
    Modified = 1,
    Inserted = 2,
    Removed = 3,
    Moved = 4,
};

struct ColorRamp {
    [[nodiscard]] static constexpr float sanitize_unit(float t) noexcept {
        if (!(t >= 0.0f)) {
            return 0.0f;
        }
        if (t > 1.0f) {
            return 1.0f;
        }
        return t;
    }

    [[nodiscard]] static constexpr std::uint8_t float_channel_to_u8(float c) noexcept {
        const float clamped = sanitize_unit(c);
        return static_cast<std::uint8_t>((clamped * 255.0f) + 0.5f);
    }

    [[nodiscard]] static constexpr ColorRgba8 to_rgba8(ColorFloat4 c) noexcept {
        return ColorRgba8{
            .r = float_channel_to_u8(c.r),
            .g = float_channel_to_u8(c.g),
            .b = float_channel_to_u8(c.b),
            .a = float_channel_to_u8(c.a),
        };
    }

    [[nodiscard]] static constexpr ColorFloat4 to_float4(ColorRgba8 c) noexcept {
        constexpr float kInv255 = 1.0f / 255.0f;
        return ColorFloat4{
            .r = static_cast<float>(c.r) * kInv255,
            .g = static_cast<float>(c.g) * kInv255,
            .b = static_cast<float>(c.b) * kInv255,
            .a = static_cast<float>(c.a) * kInv255,
        };
    }

    template <std::size_t N>
        requires(N >= 2)
    [[nodiscard]] static constexpr ColorFloat4 sample_stops(
        const std::array<ColorFloat4, N>& stops,
        float t) noexcept {
        const float u = sanitize_unit(t);
        const float scaled = u * static_cast<float>(N - 1u);
        const auto idx = static_cast<std::size_t>(scaled);
        if (idx >= N - 1u) {
            return stops[N - 1u];
        }
        const float frac = scaled - static_cast<float>(idx);
        const ColorFloat4& a = stops[idx];
        const ColorFloat4& b = stops[idx + 1u];
        return ColorFloat4{
            .r = a.r + ((b.r - a.r) * frac),
            .g = a.g + ((b.g - a.g) * frac),
            .b = a.b + ((b.b - a.b) * frac),
            .a = a.a + ((b.a - a.a) * frac),
        };
    }

    // Perceptually uniform, monotonically brightening Viridis ramp.
    [[nodiscard]] static constexpr ColorFloat4 viridis(float t) noexcept {
        constexpr std::array<ColorFloat4, 9> kStops{{
            {0.2670f, 0.0049f, 0.3294f, 1.0f},
            {0.2826f, 0.1409f, 0.4575f, 1.0f},
            {0.2539f, 0.2653f, 0.5299f, 1.0f},
            {0.2068f, 0.3718f, 0.5531f, 1.0f},
            {0.1636f, 0.4711f, 0.5581f, 1.0f},
            {0.1276f, 0.5669f, 0.5506f, 1.0f},
            {0.2669f, 0.6706f, 0.4408f, 1.0f},
            {0.5857f, 0.8467f, 0.2499f, 1.0f},
            {0.9932f, 0.9062f, 0.1439f, 1.0f},
        }};
        return sample_stops(kStops, t);
    }

    [[nodiscard]] static constexpr ColorRgba8 viridis_rgba8(float t) noexcept {
        return to_rgba8(viridis(t));
    }

    // Perceptually monotonic blackbody / Inferno heat ramp.
    [[nodiscard]] static constexpr ColorFloat4 heat(float t) noexcept {
        constexpr std::array<ColorFloat4, 7> kStops{{
            {0.0500f, 0.0300f, 0.1200f, 1.0f},
            {0.2580f, 0.0390f, 0.4060f, 1.0f},
            {0.5780f, 0.1480f, 0.4040f, 1.0f},
            {0.8650f, 0.3170f, 0.2260f, 1.0f},
            {0.9870f, 0.6450f, 0.0400f, 1.0f},
            {0.9880f, 0.8600f, 0.3600f, 1.0f},
            {0.9880f, 0.9980f, 0.6450f, 1.0f},
        }};
        return sample_stops(kStops, t);
    }

    [[nodiscard]] static constexpr ColorRgba8 heat_rgba8(float t) noexcept {
        return to_rgba8(heat(t));
    }

    // Shannon entropy spectrum for normalized entropy t in [0, 1] (0..8 bits/byte):
    // low/zero padding -> cool deep slate; code/ASCII -> cyan/emerald; packed/encrypted -> bright amber-gold.
    [[nodiscard]] static constexpr ColorFloat4 entropy_spectrum(float t) noexcept {
        constexpr std::array<ColorFloat4, 6> kStops{{
            {0.0900f, 0.1150f, 0.1800f, 1.0f},
            {0.1300f, 0.2900f, 0.4900f, 1.0f},
            {0.1400f, 0.5400f, 0.5800f, 1.0f},
            {0.3100f, 0.7200f, 0.4700f, 1.0f},
            {0.8800f, 0.6800f, 0.2400f, 1.0f},
            {0.9900f, 0.8900f, 0.4800f, 1.0f},
        }};
        return sample_stops(kStops, t);
    }

    [[nodiscard]] static constexpr ColorRgba8 entropy_spectrum_rgba8(float t) noexcept {
        return to_rgba8(entropy_spectrum(t));
    }

    [[nodiscard]] static constexpr float entropy_bits_to_unit(float bits_per_byte) noexcept {
        return sanitize_unit(bits_per_byte * 0.125f);
    }

    [[nodiscard]] static constexpr ColorFloat4 memory_permission(
        MemoryPermissionCategory category) noexcept {
        switch (category) {
            case MemoryPermissionCategory::None:
                return {0.2200f, 0.2350f, 0.2700f, 1.0f};
            case MemoryPermissionCategory::ReadOnly:
                return {0.3100f, 0.5600f, 0.8200f, 1.0f};
            case MemoryPermissionCategory::ReadWrite:
                return {0.2600f, 0.7100f, 0.5200f, 1.0f};
            case MemoryPermissionCategory::ReadExecute:
                return {0.5600f, 0.4600f, 0.8900f, 1.0f};
            case MemoryPermissionCategory::ReadWriteExecute:
                return {0.9500f, 0.3600f, 0.2600f, 1.0f};
            case MemoryPermissionCategory::GuardOrReserved:
                return {0.6200f, 0.5200f, 0.2200f, 1.0f};
        }
        return {0.2200f, 0.2350f, 0.2700f, 1.0f};
    }

    [[nodiscard]] static constexpr ColorRgba8 memory_permission_rgba8(
        MemoryPermissionCategory category) noexcept {
        return to_rgba8(memory_permission(category));
    }

    [[nodiscard]] static constexpr MemoryPermissionCategory classify_rwx(bool readable,
                                                                         bool writable,
                                                                         bool executable) noexcept {
        if (writable && executable) {
            return MemoryPermissionCategory::ReadWriteExecute;
        }
        if (executable) {
            return MemoryPermissionCategory::ReadExecute;
        }
        if (writable) {
            return MemoryPermissionCategory::ReadWrite;
        }
        if (readable) {
            return MemoryPermissionCategory::ReadOnly;
        }
        return MemoryPermissionCategory::None;
    }

    [[nodiscard]] static constexpr ColorFloat4 diff_status(DiffStatusCategory status) noexcept {
        switch (status) {
            case DiffStatusCategory::Unchanged:
                return {0.2400f, 0.2650f, 0.3100f, 1.0f};
            case DiffStatusCategory::Modified:
                return {0.9200f, 0.6700f, 0.2000f, 1.0f};
            case DiffStatusCategory::Inserted:
                return {0.2500f, 0.7600f, 0.4700f, 1.0f};
            case DiffStatusCategory::Removed:
                return {0.9000f, 0.3100f, 0.3300f, 1.0f};
            case DiffStatusCategory::Moved:
                return {0.4200f, 0.6300f, 0.9400f, 1.0f};
        }
        return {0.2400f, 0.2650f, 0.3100f, 1.0f};
    }

    [[nodiscard]] static constexpr ColorRgba8 diff_status_rgba8(
        DiffStatusCategory status) noexcept {
        return to_rgba8(diff_status(status));
    }

    template <std::size_t LutSize = 256u, typename RampFn>
        requires(LutSize >= 2u)
    [[nodiscard]] static constexpr std::array<ColorRgba8, LutSize> bake_lut_rgba8(
        RampFn&& fn) noexcept {
        std::array<ColorRgba8, LutSize> lut{};
        constexpr float denom = static_cast<float>(LutSize - 1u);
        for (std::size_t i = 0; i < LutSize; ++i) {
            lut[i] = to_rgba8(fn(static_cast<float>(i) / denom));
        }
        return lut;
    }
};

struct MemoryPermissionPalette {
    [[nodiscard]] static constexpr ColorFloat4 color(MemoryPermissionCategory category) noexcept {
        return ColorRamp::memory_permission(category);
    }
    [[nodiscard]] static constexpr ColorRgba8 rgba8(MemoryPermissionCategory category) noexcept {
        return ColorRamp::memory_permission_rgba8(category);
    }
    [[nodiscard]] static constexpr ColorRgba8 from_rwx(bool readable,
                                                       bool writable,
                                                       bool executable) noexcept {
        return ColorRamp::memory_permission_rgba8(
            ColorRamp::classify_rwx(readable, writable, executable));
    }
};

struct DiffStatusPalette {
    [[nodiscard]] static constexpr ColorFloat4 color(DiffStatusCategory status) noexcept {
        return ColorRamp::diff_status(status);
    }
    [[nodiscard]] static constexpr ColorRgba8 rgba8(DiffStatusCategory status) noexcept {
        return ColorRamp::diff_status_rgba8(status);
    }
};

} // namespace viewer
