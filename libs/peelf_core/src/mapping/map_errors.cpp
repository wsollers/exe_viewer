#include "mapping/map_errors.hpp"

#include <string>

namespace peelf {

    struct MapErrorCategory final : std::error_category {
        const char* name() const noexcept override { return "ws.file_mapping"; }

        std::string message(int c) const override {
            switch (static_cast<MapErrc>(c)) {
                case MapErrc::ok: return "ok";
                case MapErrc::open_failed: return "open failed";
                case MapErrc::stat_failed: return "stat/get size failed";
                case MapErrc::size_zero: return "file size is zero";
                case MapErrc::invalid_alignment: return "mapped address not aligned for T";
                case MapErrc::map_failed: return "map failed";
                case MapErrc::unmap_failed: return "unmap failed";
                case MapErrc::flush_failed: return "flush failed";
            }
            return "unknown mapping error";
        }
    };

    const std::error_category& map_error_category() noexcept {
        static MapErrorCategory cat;
        return cat;
    }

    std::error_code make_error_code(MapErrc e) noexcept {
        return {static_cast<int>(e), map_error_category()};
    }

} // namespace ws::fs
