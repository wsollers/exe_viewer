#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace peelf {

/// Availability state for forgiving static and live-process inspection queries.
/// Subsystems degrade gracefully to Partial or Unavailable with provenance details
/// rather than failing whole-panel snapshots when OS permissions restrict one API.
enum class Availability : std::uint8_t {
    Available,
    Partial,
    Unavailable,
};

[[nodiscard]] constexpr std::string_view to_string(Availability availability) noexcept {
    switch (availability) {
        case Availability::Available:   return "Available";
        case Availability::Partial:     return "Partial";
        case Availability::Unavailable: return "Unavailable";
    }
    return "Unavailable";
}

struct SubsystemStatus {
    Availability availability{Availability::Unavailable};
    std::string source;
    std::string detail;

    [[nodiscard]] static SubsystemStatus available(std::string src = {}, std::string det = {}) {
        return SubsystemStatus{
            .availability = Availability::Available,
            .source = std::move(src),
            .detail = std::move(det),
        };
    }

    [[nodiscard]] static SubsystemStatus partial(std::string src, std::string det) {
        return SubsystemStatus{
            .availability = Availability::Partial,
            .source = std::move(src),
            .detail = std::move(det),
        };
    }

    [[nodiscard]] static SubsystemStatus unavailable(std::string src, std::string det) {
        return SubsystemStatus{
            .availability = Availability::Unavailable,
            .source = std::move(src),
            .detail = std::move(det),
        };
    }

    [[nodiscard]] constexpr bool has_data() const noexcept {
        return availability != Availability::Unavailable;
    }

    [[nodiscard]] constexpr bool is_usable() const noexcept {
        return has_data();
    }

    [[nodiscard]] constexpr bool ok() const noexcept {
        return availability == Availability::Available;
    }

    auto operator<=>(const SubsystemStatus&) const = default;
};

template <typename T>
struct ForgivingValue {
    std::optional<T> value;
    SubsystemStatus status;

    [[nodiscard]] constexpr bool has_value() const noexcept {
        return value.has_value();
    }
};

}  // namespace peelf
