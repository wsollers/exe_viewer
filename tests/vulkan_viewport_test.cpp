#include "vulkan/spirv_validation.hpp"
#include "vulkan/viewport_camera_2d.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace {

using viewer::CameraRelativeUniform2D;
using viewer::ColorFloat4;
using viewer::ColorRamp;
using viewer::ColorRgba8;
using viewer::DiffStatusCategory;
using viewer::DiffStatusPalette;
using viewer::MemoryPermissionCategory;
using viewer::MemoryPermissionPalette;
using viewer::SpirvValidationError;
using viewer::Vec2d;
using viewer::Vec2f;
using viewer::ViewportCamera2D;
using viewer::WorldRect2D;

[[nodiscard]] float relative_luminance(ColorFloat4 c) noexcept {
    return 0.2126f * c.r + 0.7152f * c.g + 0.0722f * c.b;
}

TEST(ViewportCamera2DTest, RoundTripWorldAndScreenCoordinates) {
    ViewportCamera2D cam{};
    cam.center_x = 4096.25;
    cam.center_y = -512.75;
    cam.scale_x = 3.5;
    cam.scale_y = 0.75;

    constexpr double kViewportW = 1280.0;
    constexpr double kViewportH = 720.0;

    constexpr std::array<Vec2d, 5> kSamples{{
        {4096.25, -512.75},
        {0.0, 0.0},
        {-12345.678, 98765.432},
        {140700981886976.0, 2048.5}, // 64-bit x86_64 user-space VA magnitude
        {4210.125, -100.5},
    }};

    for (const Vec2d world : kSamples) {
        const Vec2d screen = cam.world_to_screen(world.x, world.y, kViewportW, kViewportH);
        const Vec2d recovered = cam.screen_to_world(screen.x, screen.y, kViewportW, kViewportH);
        EXPECT_NEAR(recovered.x, world.x, 1e-6);
        EXPECT_NEAR(recovered.y, world.y, 1e-6);
    }

    const Vec2d center_px =
        cam.world_to_screen(cam.center_x, cam.center_y, kViewportW, kViewportH);
    EXPECT_DOUBLE_EQ(center_px.x, kViewportW * 0.5);
    EXPECT_DOUBLE_EQ(center_px.y, kViewportH * 0.5);
}

TEST(ViewportCamera2DTest, CursorAnchoredZoomKeepsWorldPointFixedUnderCursor) {
    ViewportCamera2D cam{};
    cam.center_x = 1500.0;
    cam.center_y = 300.0;
    cam.scale_x = 2.0;
    cam.scale_y = 2.0;
    cam.min_scale = 1e-6;
    cam.max_scale = 1e9;

    constexpr double kViewportW = 1600.0;
    constexpr double kViewportH = 900.0;
    constexpr double kCursorX = 317.25;
    constexpr double kCursorY = 684.5;

    const Vec2d anchor_world =
        cam.screen_to_world(kCursorX, kCursorY, kViewportW, kViewportH);

    for (const double factor : {2.5, 8.0, 125.0, 0.1, 0.025, 4.0}) {
        cam.zoom_at_screen_pixel(kCursorX, kCursorY, factor, kViewportW, kViewportH);
        const Vec2d projected =
            cam.world_to_screen(anchor_world.x, anchor_world.y, kViewportW, kViewportH);
        EXPECT_NEAR(projected.x, kCursorX, 1e-7);
        EXPECT_NEAR(projected.y, kCursorY, 1e-7);
    }

    // Clamp verification at min_scale and max_scale
    cam.zoom_at_screen_pixel(kCursorX, kCursorY, 1e20, kViewportW, kViewportH);
    EXPECT_DOUBLE_EQ(cam.scale_x, cam.max_scale);
    EXPECT_DOUBLE_EQ(cam.scale_y, cam.max_scale);

    cam.zoom_at_screen_pixel(kCursorX, kCursorY, 1e-30, kViewportW, kViewportH);
    EXPECT_DOUBLE_EQ(cam.scale_x, cam.min_scale);
    EXPECT_DOUBLE_EQ(cam.scale_y, cam.min_scale);
}

TEST(ViewportCamera2DTest, DragPanShiftsScreenCoordinatesByExactPixelDelta) {
    ViewportCamera2D cam{};
    cam.center_x = 200.0;
    cam.center_y = -80.0;
    cam.scale_x = 4.0;
    cam.scale_y = 2.0;

    constexpr double kW = 1000.0;
    constexpr double kH = 600.0;
    const Vec2d before = cam.world_to_screen(250.0, -40.0, kW, kH);

    cam.pan_by_pixels(64.0, -30.0);
    const Vec2d after = cam.world_to_screen(250.0, -40.0, kW, kH);
    EXPECT_NEAR(after.x - before.x, 64.0, 1e-9);
    EXPECT_NEAR(after.y - before.y, -30.0, 1e-9);
}

TEST(ViewportCamera2DTest, DeepMillionXZoomCameraRelativeFloat32AvoidsJitter) {
    // 1. Deep 1,000,000x timeline zoom around t = 10,000,000.0s where naive float32 ULP is 1.0
    // world unit (1,000,000 pixels of quantization jitter!), while double ULP is ~1.86e-9.
    constexpr double kTimelineAnchorX = 10'000'000.0;
    constexpr double kTimelineAnchorY = 250'000.0;

    ViewportCamera2D cam{};
    cam.min_scale = 1e-9;
    cam.max_scale = 1e12;
    cam.center_x = kTimelineAnchorX;
    cam.center_y = kTimelineAnchorY;
    cam.scale_x = 1'000'000.0; // 1,000,000x zoom!
    cam.scale_y = 1'000'000.0;

    constexpr double kViewportW = 1920.0;
    constexpr double kViewportH = 1080.0;

    // Two adjacent microsecond events separated by 2.5e-5 world units => 25.0 screen pixels apart.
    const double x0 = kTimelineAnchorX - 1.25e-5;
    const double x1 = kTimelineAnchorX + 1.25e-5;
    const double y0 = kTimelineAnchorY - 0.5e-5;
    const double y1 = kTimelineAnchorY + 0.5e-5;

    // Confirm naive float32 collapses both coordinates to the exact same value:
    EXPECT_EQ(static_cast<float>(x0), static_cast<float>(x1));

    // Camera-relative float32 projection preserves sub-millipixel accuracy:
    const Vec2f p0 = cam.project_world_to_screen_f32(x0, y0, kViewportW, kViewportH);
    const Vec2f p1 = cam.project_world_to_screen_f32(x1, y1, kViewportW, kViewportH);

    EXPECT_NEAR(p1.x - p0.x, 25.0f, 1e-3f);
    EXPECT_NEAR(p1.y - p0.y, 10.0f, 1e-3f);
    EXPECT_NEAR(p0.x, static_cast<float>(kViewportW * 0.5 - 12.5), 1e-3f);
    EXPECT_NEAR(p1.x, static_cast<float>(kViewportW * 0.5 + 12.5), 1e-3f);

    const CameraRelativeUniform2D gpu_u = cam.build_gpu_uniform(kViewportW, kViewportH);
    const Vec2f rel0 = cam.relative_world_f32(x0, y0);
    const Vec2f rel1 = cam.relative_world_f32(x1, y1);
    const Vec2f ndc0 = gpu_u.project_relative_to_ndc(rel0.x, rel0.y);
    const Vec2f ndc1 = gpu_u.project_relative_to_ndc(rel1.x, rel1.y);
    const float expected_ndc_span = 25.0f * (2.0f / static_cast<float>(kViewportW));
    EXPECT_NEAR(ndc1.x - ndc0.x, expected_ndc_span, 1e-6f);

    // 2. High 64-bit user-space virtual address (0x00007FF780000000, naive float32 ULP = 8 MiB!)
    // zoomed to 32 pixels per byte across two 4-byte instructions (128 pixels apart).
    constexpr auto kVaBase = static_cast<double>(0x00007FF780000000ULL);
    cam.center_x = kVaBase;
    cam.scale_x = 32.0;
    const Vec2f va0 = cam.project_world_to_screen_f32(kVaBase, 0.0, kViewportW, kViewportH);
    const Vec2f va1 = cam.project_world_to_screen_f32(kVaBase + 4.0, 0.0, kViewportW, kViewportH);
    EXPECT_NEAR(va1.x - va0.x, 128.0f, 1e-4f);
}

TEST(ViewportCamera2DTest, SanitizesNanInfAndZeroViewportGracefully) {
    ViewportCamera2D cam{};
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();

    cam.center_x = nan;
    cam.center_y = -inf;
    cam.scale_x = -5.0;
    cam.scale_y = inf;
    cam.min_scale = -1.0;
    cam.max_scale = nan;
    cam.sanitize();

    EXPECT_TRUE(std::isfinite(cam.center_x));
    EXPECT_TRUE(std::isfinite(cam.center_y));
    EXPECT_TRUE(std::isfinite(cam.scale_x));
    EXPECT_TRUE(std::isfinite(cam.scale_y));
    EXPECT_GT(cam.scale_x, 0.0);
    EXPECT_GT(cam.scale_y, 0.0);
    EXPECT_LE(cam.min_scale, cam.max_scale);

    // Zero / negative / NaN viewport queries must never return NaN or Inf.
    const Vec2d s0 = cam.world_to_screen(nan, inf, 0.0, -100.0);
    EXPECT_TRUE(std::isfinite(s0.x));
    EXPECT_TRUE(std::isfinite(s0.y));

    const Vec2d w0 = cam.screen_to_world(nan, -inf, 0.0, 0.0);
    EXPECT_TRUE(std::isfinite(w0.x));
    EXPECT_TRUE(std::isfinite(w0.y));

    cam.pan_by_pixels(nan, inf);
    cam.zoom_at_screen_pixel(nan, inf, nan, 0.0, -10.0);
    EXPECT_TRUE(std::isfinite(cam.center_x));
    EXPECT_TRUE(std::isfinite(cam.center_y));
    EXPECT_TRUE(std::isfinite(cam.scale_x));
    EXPECT_TRUE(std::isfinite(cam.scale_y));
}

TEST(ViewportCamera2DTest, FitBoundsCentersAndContainsWorldBounds) {
    ViewportCamera2D cam{};
    constexpr double kViewportW = 1000.0;
    constexpr double kViewportH = 500.0;

    // Intentionally pass reversed min/max to verify canonicalization.
    cam.fit_bounds(300.0, 200.0, 100.0, -50.0, kViewportW, kViewportH, true);

    EXPECT_NEAR(cam.center_x, 200.0, 1e-9);
    EXPECT_NEAR(cam.center_y, 75.0, 1e-9);
    EXPECT_DOUBLE_EQ(cam.scale_x, cam.scale_y);

    const WorldRect2D vis = cam.visible_world_rect(kViewportW, kViewportH);
    EXPECT_LE(vis.min_x, 100.0);
    EXPECT_GE(vis.max_x, 300.0);
    EXPECT_LE(vis.min_y, -50.0);
    EXPECT_GE(vis.max_y, 200.0);

    // Degenerate single-point bounds must also remain finite and well-behaved.
    cam.fit_bounds(42.0, 42.0, 42.0, 42.0, kViewportW, kViewportH);
    EXPECT_NEAR(cam.center_x, 42.0, 1e-9);
    EXPECT_NEAR(cam.center_y, 42.0, 1e-9);
    EXPECT_TRUE(std::isfinite(cam.scale_x));
}

TEST(ViewportCamera2DTest, LodAndPixelHitTestingRespectMinimumPixelRadius) {
    ViewportCamera2D cam{};
    cam.center_x = 500.0;
    cam.center_y = 50.0;
    cam.scale_x = 0.25; // 4 world units per pixel
    cam.scale_y = 1.0;

    EXPECT_EQ(cam.compute_lod_level(16u, 1.0), 2u);

    // Thin 0.5-world-unit event at x=500 is only 0.125 px wide on screen,
    // but pixel_slop = 4.0 makes clicking 3 px away succeed.
    const WorldRect2D thin_event{.min_x = 499.75, .min_y = 40.0, .max_x = 500.25, .max_y = 60.0};
    const Vec2d event_px = cam.world_to_screen(500.0, 50.0, 800.0, 400.0);

    EXPECT_TRUE(
        cam.hit_test_world_rect(event_px.x + 3.0, event_px.y, thin_event, 800.0, 400.0, 4.0));
    EXPECT_FALSE(
        cam.hit_test_world_rect(event_px.x + 8.0, event_px.y, thin_event, 800.0, 400.0, 4.0));
    EXPECT_TRUE(cam.hit_test_world_point(
        event_px.x - 3.0, event_px.y + 3.0, 500.0, 50.0, 800.0, 400.0, 5.0));
    EXPECT_FALSE(cam.hit_test_world_point(
        event_px.x - 6.0, event_px.y, 500.0, 50.0, 800.0, 400.0, 5.0));
}

TEST(ColorRampTest, PerceptualMonotonicityBoundsAndRgba8Packing) {
    float prev_viridis_lum = -1.0f;
    float prev_heat_lum = -1.0f;

    for (int i = 0; i <= 64; ++i) {
        const float t = static_cast<float>(i) / 64.0f;
        const ColorFloat4 v = ColorRamp::viridis(t);
        const ColorFloat4 h = ColorRamp::heat(t);
        const ColorFloat4 e = ColorRamp::entropy_spectrum(t * 8.0f);

        for (const ColorFloat4 c : {v, h, e}) {
            EXPECT_GE(c.r, 0.0f);
            EXPECT_LE(c.r, 1.0f);
            EXPECT_GE(c.g, 0.0f);
            EXPECT_LE(c.g, 1.0f);
            EXPECT_GE(c.b, 0.0f);
            EXPECT_LE(c.b, 1.0f);
            EXPECT_FLOAT_EQ(c.a, 1.0f);
        }

        const float v_lum = relative_luminance(v);
        const float h_lum = relative_luminance(h);
        EXPECT_GE(v_lum + 1e-4f, prev_viridis_lum);
        EXPECT_GE(h_lum + 1e-4f, prev_heat_lum);
        prev_viridis_lum = v_lum;
        prev_heat_lum = h_lum;
    }

    // Out-of-range and NaN clamping
    const ColorRgba8 low = ColorRamp::viridis_rgba8(-10.0f);
    const ColorRgba8 zero = ColorRamp::viridis_rgba8(0.0f);
    const ColorRgba8 nan_c =
        ColorRamp::viridis_rgba8(std::numeric_limits<float>::quiet_NaN());
    const ColorRgba8 high = ColorRamp::viridis_rgba8(99.0f);
    const ColorRgba8 one = ColorRamp::viridis_rgba8(1.0f);
    EXPECT_EQ(low, zero);
    EXPECT_EQ(nan_c, zero);
    EXPECT_EQ(high, one);
    EXPECT_NE(zero, one);

    // Pack / unpack round-trip
    constexpr ColorRgba8 sample{.r = 0x12u, .g = 0x34u, .b = 0xABu, .a = 0xCDu};
    constexpr std::uint32_t packed = sample.pack_rgba_le();
    static_assert(packed == 0xCDAB3412u);
    static_assert(ColorRgba8::unpack_rgba_le(packed) == sample);
    EXPECT_EQ(ColorRgba8::unpack_rgba_le(packed), sample);

    // Categorical palettes & LUT baking
    EXPECT_NE(MemoryPermissionPalette::rgba8(MemoryPermissionCategory::ReadOnly),
              MemoryPermissionPalette::rgba8(MemoryPermissionCategory::ReadWriteExecute));
    EXPECT_EQ(MemoryPermissionPalette::from_rwx(true, true, true),
              MemoryPermissionPalette::rgba8(MemoryPermissionCategory::ReadWriteExecute));
    EXPECT_NE(DiffStatusPalette::rgba8(DiffStatusCategory::Inserted),
              DiffStatusPalette::rgba8(DiffStatusCategory::Removed));

    constexpr auto lut = ColorRamp::bake_lut_rgba8(ColorRamp::viridis);
    EXPECT_EQ(lut.front(), zero);
    EXPECT_EQ(lut.back(), one);
}

TEST(SpirvValidationTest, AcceptsEmbeddedModulesAndRejectsMalformedInputs) {
    // Embedded modules pass both constexpr and runtime inspection
    const auto comp_info = viewer::inspect_spirv_words(viewer::shaders::kSmokeClearCompSpirv);
    EXPECT_TRUE(comp_info.valid);
    EXPECT_EQ(comp_info.error, SpirvValidationError::Ok);
    EXPECT_EQ(comp_info.version_major, 1u);
    EXPECT_EQ(comp_info.version_minor, 0u);
    EXPECT_GT(comp_info.bound, 0u);
    EXPECT_GT(comp_info.instruction_count, 0u);

    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kPassthroughQuadVertSpirv));
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kPassthroughQuadFragSpirv));
    EXPECT_TRUE(viewer::validate_spirv_bytes(
        std::as_bytes(std::span{viewer::shaders::kPassthroughQuadFragSpirv})));

    // 1. Empty span
    EXPECT_EQ(viewer::inspect_spirv_words({}).error, SpirvValidationError::Empty);
    EXPECT_FALSE(viewer::validate_spirv_bytes({}));

    // 2. Truncated header (< 5 words)
    constexpr std::array<std::uint32_t, 4> kTruncated{{0x07230203u, 0x00010000u, 0u, 8u}};
    EXPECT_EQ(viewer::inspect_spirv_words(kTruncated).error,
              SpirvValidationError::TruncatedHeader);

    // 3. Bad magic (including byte-swapped endianness)
    auto bad_magic = viewer::shaders::kPassthroughQuadFragSpirv;
    bad_magic[0] = 0x03022307u;
    EXPECT_EQ(viewer::inspect_spirv_words(bad_magic).error, SpirvValidationError::InvalidMagic);

    // 4. Invalid version word
    auto bad_version = viewer::shaders::kPassthroughQuadFragSpirv;
    bad_version[1] = 0x00020000u;
    EXPECT_EQ(viewer::inspect_spirv_words(bad_version).error,
              SpirvValidationError::InvalidVersion);

    // 5. Zero ID bound
    auto zero_bound = viewer::shaders::kPassthroughQuadFragSpirv;
    zero_bound[3] = 0u;
    EXPECT_EQ(viewer::inspect_spirv_words(zero_bound).error, SpirvValidationError::ZeroBound);

    // 6. Non-zero schema word
    auto bad_schema = viewer::shaders::kPassthroughQuadFragSpirv;
    bad_schema[4] = 1u;
    EXPECT_EQ(viewer::inspect_spirv_words(bad_schema).error, SpirvValidationError::NonZeroSchema);

    // 7. Header-only with 0 instructions
    constexpr std::array<std::uint32_t, 5> kHeaderOnly{{0x07230203u, 0x00010000u, 0u, 4u, 0u}};
    EXPECT_EQ(viewer::inspect_spirv_words(kHeaderOnly).error,
              SpirvValidationError::EmptyInstructionStream);

    // 8. Truncated instruction stream (word_count exceeds remaining words or word_count == 0)
    std::vector<std::uint32_t> truncated_inst(
        viewer::shaders::kPassthroughQuadFragSpirv.begin(),
        viewer::shaders::kPassthroughQuadFragSpirv.end() - 3);
    EXPECT_EQ(viewer::inspect_spirv_words(truncated_inst).error,
              SpirvValidationError::TruncatedInstruction);

    constexpr std::array<std::uint32_t, 6> kZeroWordInst{{
        0x07230203u, 0x00010000u, 0u, 4u, 0u, 0x00000038u,
    }};
    EXPECT_EQ(viewer::inspect_spirv_words(kZeroWordInst).error,
              SpirvValidationError::TruncatedInstruction);

    // 9. Non-4-byte-aligned byte length
    const auto frag_bytes =
        std::as_bytes(std::span{viewer::shaders::kPassthroughQuadFragSpirv});
    EXPECT_EQ(viewer::inspect_spirv_bytes(frag_bytes.subspan(0, frag_bytes.size() - 1)).error,
              SpirvValidationError::UnalignedBytes);
}

} // namespace
