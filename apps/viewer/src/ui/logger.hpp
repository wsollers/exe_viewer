#pragma once

#include <string>
#include <mutex>
#include <format>
#include "ui_panels.hpp"

namespace viewer {


    // Forward declaration
    class LogPanel;

    class Logger {
    public:
        static Logger& instance() {
            static Logger logger;
            return logger;
        }

        void init(LogPanel* panel) { panel_ = panel; }

        // String overloads
        void info(const std::string& msg);
        void warn(const std::string& msg);
        void error(const std::string& msg);

        // Variadic template overloads
        template<typename... Args>
        void info(std::format_string<Args...> fmt, Args&&... args) {
            info(std::format(fmt, std::forward<Args>(args)...));
        }

        template<typename... Args>
        void warn(std::format_string<Args...> fmt, Args&&... args) {
            warn(std::format(fmt, std::forward<Args>(args)...));
        }

        template<typename... Args>
        void error(std::format_string<Args...> fmt, Args&&... args) {
            error(std::format(fmt, std::forward<Args>(args)...));
        }

    private:
        Logger() = default;
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        LogPanel* panel_ = nullptr;
        std::mutex mutex_;
    };

    // Convenience macros/functions for global access
    inline Logger& Log() { return Logger::instance(); }

} // namespace viewer