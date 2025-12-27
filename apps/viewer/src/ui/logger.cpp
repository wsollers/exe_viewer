#include "logger.hpp"

namespace viewer {


    void Logger::info(const std::string& msg) {
        if (!panel_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        panel_->add(LogLevel::Info, msg);
    }

    void Logger::warn(const std::string& msg) {
        if (!panel_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        panel_->add(LogLevel::Warning, msg);
    }

    void Logger::error(const std::string& msg) {
        if (!panel_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        panel_->add(LogLevel::Error, msg);
    }

} // namespace viewer