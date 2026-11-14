#pragma once

#include <array>
#include <cmath>
#include <istream>
#include <map>
#include <sstream>
#include <string>

namespace viewer::ui {
struct ThemeResource {
    std::map<std::string, std::array<float, 4>> colors;
    std::map<std::string, float> metrics;
};

// Parse into presentation-only data; invalid lines cannot poison renderer state.
inline ThemeResource read_theme(std::istream& input) {
    ThemeResource result;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream values(line);
        std::string key;
        if (!(values >> key) || key.starts_with('#')) continue;
        if (key.starts_with("metric.")) {
            float value{};
            std::string extra;
            if (values >> value && !(values >> extra) && std::isfinite(value) && value >= 0 && value <= 64)
                result.metrics.insert_or_assign(key.substr(7), value);
            continue;
        }
        std::array<float, 4> color{};
        std::string extra;
        if (!(values >> color[0] >> color[1] >> color[2] >> color[3]) || values >> extra) continue;
        bool valid = true;
        for (const float channel : color)
            valid &= std::isfinite(channel) && channel >= 0 && channel <= 1;
        if (valid) result.colors.insert_or_assign(key, color);
    }
    return result;
}
} // namespace viewer::ui
