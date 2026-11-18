#include "vulkan/viewport_camera_2d.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace viewer {
namespace {

constexpr double kMinViewportPixels = 1.0;
constexpr double kMaxViewportPixels = 1.0e7;
constexpr double kMinWorldSpan = 1.0e-9;

[[nodiscard]] double sanitize_viewport_dimension(double dim) noexcept {
    if (!std::isfinite(dim) || dim < kMinViewportPixels) {
        return kMinViewportPixels;
    }
    return std::min(dim, kMaxViewportPixels);
}

[[nodiscard]] double sanitize_coordinate(double coord) noexcept {
    if (!std::isfinite(coord)) {
        return 0.0;
    }
    return std::clamp(coord,
                      -ViewportCamera2D::kMaxAbsCoordinate,
                      ViewportCamera2D::kMaxAbsCoordinate);
}

[[nodiscard]] float clamp_finite_f32(double value, float fallback) noexcept {
    if (!std::isfinite(value)) {
        return fallback;
    }
    constexpr double kMaxF32 = static_cast<double>(std::numeric_limits<float>::max()) * 0.5;
    const double clamped = std::clamp(value, -kMaxF32, kMaxF32);
    return static_cast<float>(clamped);
}

struct SanitizedCameraState {
    double center_x = 0.0;
    double center_y = 0.0;
    double scale_x = 1.0;
    double scale_y = 1.0;
    double min_scale = ViewportCamera2D::kDefaultMinScale;
    double max_scale = ViewportCamera2D::kDefaultMaxScale;
};

[[nodiscard]] SanitizedCameraState sanitize_state(const ViewportCamera2D& cam) noexcept {
    SanitizedCameraState s{};
    if (std::isfinite(cam.min_scale) && cam.min_scale > 0.0) {
        s.min_scale = std::min(cam.min_scale, ViewportCamera2D::kDefaultMaxScale);
    }
    if (std::isfinite(cam.max_scale) && cam.max_scale >= s.min_scale) {
        s.max_scale = std::min(cam.max_scale, 1.0e18);
    } else {
        s.max_scale = std::max(s.min_scale, ViewportCamera2D::kDefaultMaxScale);
    }

    s.center_x = sanitize_coordinate(cam.center_x);
    s.center_y = sanitize_coordinate(cam.center_y);

    const double default_scale = std::clamp(1.0, s.min_scale, s.max_scale);
    s.scale_x = (std::isfinite(cam.scale_x) && cam.scale_x > 0.0)
                    ? std::clamp(cam.scale_x, s.min_scale, s.max_scale)
                    : default_scale;
    s.scale_y = (std::isfinite(cam.scale_y) && cam.scale_y > 0.0)
                    ? std::clamp(cam.scale_y, s.min_scale, s.max_scale)
                    : default_scale;
    return s;
}

} // namespace

void ViewportCamera2D::sanitize() noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    min_scale = s.min_scale;
    max_scale = s.max_scale;
    center_x = s.center_x;
    center_y = s.center_y;
    scale_x = s.scale_x;
    scale_y = s.scale_y;
}

Vec2d ViewportCamera2D::world_to_screen(double world_x,
                                        double world_y,
                                        double viewport_w,
                                        double viewport_h) const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);
    const double wx = sanitize_coordinate(world_x);
    const double wy = sanitize_coordinate(world_y);
    return Vec2d{
        .x = (0.5 * w) + ((wx - s.center_x) * s.scale_x),
        .y = (0.5 * h) + ((wy - s.center_y) * s.scale_y),
    };
}

Vec2d ViewportCamera2D::screen_to_world(double screen_x,
                                        double screen_y,
                                        double viewport_w,
                                        double viewport_h) const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);
    const double sx = std::isfinite(screen_x) ? screen_x : (0.5 * w);
    const double sy = std::isfinite(screen_y) ? screen_y : (0.5 * h);
    return Vec2d{
        .x = sanitize_coordinate(s.center_x + ((sx - (0.5 * w)) / s.scale_x)),
        .y = sanitize_coordinate(s.center_y + ((sy - (0.5 * h)) / s.scale_y)),
    };
}

WorldRect2D ViewportCamera2D::visible_world_rect(double viewport_w,
                                                 double viewport_h) const noexcept {
    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);
    const Vec2d top_left = screen_to_world(0.0, 0.0, w, h);
    const Vec2d bottom_right = screen_to_world(w, h, w, h);
    return WorldRect2D{
        .min_x = std::min(top_left.x, bottom_right.x),
        .min_y = std::min(top_left.y, bottom_right.y),
        .max_x = std::max(top_left.x, bottom_right.x),
        .max_y = std::max(top_left.y, bottom_right.y),
    };
}

void ViewportCamera2D::pan_by_pixels(double dx, double dy) noexcept {
    sanitize();
    if (std::isfinite(dx)) {
        center_x = sanitize_coordinate(center_x - (dx / scale_x));
    }
    if (std::isfinite(dy)) {
        center_y = sanitize_coordinate(center_y - (dy / scale_y));
    }
}

void ViewportCamera2D::zoom_at_screen_pixel(double px,
                                            double py,
                                            double factor,
                                            double viewport_w,
                                            double viewport_h) noexcept {
    zoom_axes_at_screen_pixel(px, py, factor, factor, viewport_w, viewport_h);
}

void ViewportCamera2D::zoom_axes_at_screen_pixel(double px,
                                                 double py,
                                                 double factor_x,
                                                 double factor_y,
                                                 double viewport_w,
                                                 double viewport_h) noexcept {
    sanitize();
    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);
    const double anchor_px = std::isfinite(px) ? px : (0.5 * w);
    const double anchor_py = std::isfinite(py) ? py : (0.5 * h);

    const Vec2d anchor_world = screen_to_world(anchor_px, anchor_py, w, h);

    if (std::isfinite(factor_x) && factor_x > 0.0) {
        const double next_sx = scale_x * factor_x;
        scale_x = std::isfinite(next_sx)
                      ? std::clamp(next_sx, min_scale, max_scale)
                      : max_scale;
        center_x = sanitize_coordinate(anchor_world.x - ((anchor_px - (0.5 * w)) / scale_x));
    }

    if (std::isfinite(factor_y) && factor_y > 0.0) {
        const double next_sy = scale_y * factor_y;
        scale_y = std::isfinite(next_sy)
                      ? std::clamp(next_sy, min_scale, max_scale)
                      : max_scale;
        center_y = sanitize_coordinate(anchor_world.y - ((anchor_py - (0.5 * h)) / scale_y));
    }
}

void ViewportCamera2D::fit_bounds(double min_x,
                                  double min_y,
                                  double max_x,
                                  double max_y,
                                  double viewport_w,
                                  double viewport_h,
                                  bool preserve_aspect) noexcept {
    sanitize();
    if (!std::isfinite(min_x) || !std::isfinite(min_y) ||
        !std::isfinite(max_x) || !std::isfinite(max_y)) {
        return;
    }

    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);

    const double lo_x = sanitize_coordinate(std::min(min_x, max_x));
    const double hi_x = sanitize_coordinate(std::max(min_x, max_x));
    const double lo_y = sanitize_coordinate(std::min(min_y, max_y));
    const double hi_y = sanitize_coordinate(std::max(min_y, max_y));

    center_x = sanitize_coordinate((0.5 * lo_x) + (0.5 * hi_x));
    center_y = sanitize_coordinate((0.5 * lo_y) + (0.5 * hi_y));

    const double span_x = std::max(hi_x - lo_x, kMinWorldSpan);
    const double span_y = std::max(hi_y - lo_y, kMinWorldSpan);

    const double fit_sx = std::clamp(w / span_x, min_scale, max_scale);
    const double fit_sy = std::clamp(h / span_y, min_scale, max_scale);

    if (preserve_aspect) {
        const double uniform = std::min(fit_sx, fit_sy);
        scale_x = uniform;
        scale_y = uniform;
    } else {
        scale_x = fit_sx;
        scale_y = fit_sy;
    }
}

Vec2f ViewportCamera2D::relative_world_f32(double world_x, double world_y) const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    const double wx = sanitize_coordinate(world_x);
    const double wy = sanitize_coordinate(world_y);
    return Vec2f{
        .x = clamp_finite_f32(wx - s.center_x, 0.0f),
        .y = clamp_finite_f32(wy - s.center_y, 0.0f),
    };
}

CameraRelativeUniform2D ViewportCamera2D::build_gpu_uniform(double viewport_w,
                                                            double viewport_h) const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    const double w = sanitize_viewport_dimension(viewport_w);
    const double h = sanitize_viewport_dimension(viewport_h);

    const float cx_hi = clamp_finite_f32(s.center_x, 0.0f);
    const float cx_lo = clamp_finite_f32(s.center_x - static_cast<double>(cx_hi), 0.0f);
    const float cy_hi = clamp_finite_f32(s.center_y, 0.0f);
    const float cy_lo = clamp_finite_f32(s.center_y - static_cast<double>(cy_hi), 0.0f);

    return CameraRelativeUniform2D{
        .viewport_width = clamp_finite_f32(w, 1.0f),
        .viewport_height = clamp_finite_f32(h, 1.0f),
        .scale_x = clamp_finite_f32(s.scale_x, 1.0f),
        .scale_y = clamp_finite_f32(s.scale_y, 1.0f),
        .inv_scale_x = clamp_finite_f32(1.0 / s.scale_x, 1.0f),
        .inv_scale_y = clamp_finite_f32(1.0 / s.scale_y, 1.0f),
        .ndc_scale_x = clamp_finite_f32((2.0 * s.scale_x) / w, 2.0f),
        .ndc_scale_y = clamp_finite_f32((2.0 * s.scale_y) / h, 2.0f),
        .center_x_hi = cx_hi,
        .center_x_lo = cx_lo,
        .center_y_hi = cy_hi,
        .center_y_lo = cy_lo,
    };
}

Vec2f ViewportCamera2D::project_world_to_screen_f32(double world_x,
                                                    double world_y,
                                                    double viewport_w,
                                                    double viewport_h) const noexcept {
    const CameraRelativeUniform2D uniform = build_gpu_uniform(viewport_w, viewport_h);
    const Vec2f rel = relative_world_f32(world_x, world_y);
    return uniform.project_relative_to_screen(rel.x, rel.y);
}

double ViewportCamera2D::world_units_per_pixel_x() const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    return 1.0 / s.scale_x;
}

double ViewportCamera2D::world_units_per_pixel_y() const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    return 1.0 / s.scale_y;
}

std::uint32_t ViewportCamera2D::compute_lod_level(std::uint32_t max_lod_level,
                                                  double base_pixels_per_unit) const noexcept {
    const SanitizedCameraState s = sanitize_state(*this);
    const double base_ppu =
        (std::isfinite(base_pixels_per_unit) && base_pixels_per_unit > 0.0)
            ? base_pixels_per_unit
            : 1.0;
    const double min_axis_scale = std::min(s.scale_x, s.scale_y);
    if (min_axis_scale >= base_ppu) {
        return 0u;
    }
    const double ratio = base_ppu / min_axis_scale;
    if (!std::isfinite(ratio) || ratio <= 1.0) {
        return 0u;
    }
    const double lod_f = std::floor(std::log2(ratio));
    if (!std::isfinite(lod_f) || lod_f <= 0.0) {
        return 0u;
    }
    if (lod_f >= static_cast<double>(max_lod_level)) {
        return max_lod_level;
    }
    return static_cast<std::uint32_t>(lod_f);
}

bool ViewportCamera2D::hit_test_world_rect(double px,
                                           double py,
                                           const WorldRect2D& world_rect,
                                           double viewport_w,
                                           double viewport_h,
                                           double pixel_slop) const noexcept {
    if (!std::isfinite(px) || !std::isfinite(py)) {
        return false;
    }
    const double slop = (std::isfinite(pixel_slop) && pixel_slop > 0.0) ? pixel_slop : 0.0;
    const Vec2d s0 = world_to_screen(world_rect.min_x, world_rect.min_y, viewport_w, viewport_h);
    const Vec2d s1 = world_to_screen(world_rect.max_x, world_rect.max_y, viewport_w, viewport_h);
    const double min_sx = std::min(s0.x, s1.x) - slop;
    const double max_sx = std::max(s0.x, s1.x) + slop;
    const double min_sy = std::min(s0.y, s1.y) - slop;
    const double max_sy = std::max(s0.y, s1.y) + slop;
    return px >= min_sx && px <= max_sx && py >= min_sy && py <= max_sy;
}

bool ViewportCamera2D::hit_test_world_point(double px,
                                            double py,
                                            double world_x,
                                            double world_y,
                                            double viewport_w,
                                            double viewport_h,
                                            double radius_pixels) const noexcept {
    if (!std::isfinite(px) || !std::isfinite(py)) {
        return false;
    }
    const double r = (std::isfinite(radius_pixels) && radius_pixels >= 0.0) ? radius_pixels : 0.0;
    const Vec2d screen_pt = world_to_screen(world_x, world_y, viewport_w, viewport_h);
    const double dx = px - screen_pt.x;
    const double dy = py - screen_pt.y;
    return ((dx * dx) + (dy * dy)) <= (r * r);
}

} // namespace viewer
