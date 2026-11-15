#include "logger.hpp"

namespace viewer {


    void Logger::info(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!panel_) return;
        panel_->add(LogLevel::Info, msg);
    }

    void Logger::warn(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!panel_) return;
        panel_->add(LogLevel::Warning, msg);
    }

    void Logger::error(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!panel_) return;
        panel_->add(LogLevel::Error, msg);
    }

} // namespace viewer