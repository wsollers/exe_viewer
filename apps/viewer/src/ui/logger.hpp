#pragma once
#include <string>
#include <mutex>
#include "ui_panels.hpp"

namespace viewer {

    class Logger {
    public:
        static void init(LogPanel* panel);

        static void info(const std::string& msg);
        static void warn(const std::string& msg);
        static void error(const std::string& msg);

    private:
        static inline LogPanel* panel_ = nullptr;
        static inline std::mutex mutex_;
    };

} // namespace viewer