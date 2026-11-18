#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {

    enum class LogLevel : std::uint8_t {
        Info,
        Warning,
        Error
    };

    struct LogEntry {
        std::string timestamp{};
        LogLevel level{LogLevel::Info};
        std::string message{};
    };

    class LogPanel;

    class Logger {
    public:
        static constexpr std::size_t kDefaultCapacity = 5000;

        static Logger& instance() {
            static Logger logger;
            return logger;
        }

        void init(LogPanel* panel, std::optional<std::size_t> panel_capacity = std::nullopt) noexcept;
        [[nodiscard]] bool is_attached_to(const LogPanel* panel) const noexcept;

        void set_capacity(std::size_t capacity);
        [[nodiscard]] std::size_t capacity() const noexcept;
        void clear() noexcept;

        [[nodiscard]] std::vector<LogEntry> snapshot() const;

        template<typename Fn>
        void for_each_entry(Fn&& fn) const {
            std::scoped_lock lock(mutex_);
            if (capacity_ == 0 || count_ == 0 || buffer_.empty()) {
                return;
            }
            std::size_t idx = (start_ + capacity_ - count_) % capacity_;
            for (std::size_t i = 0; i < count_; ++i) {
                fn(buffer_[idx]);
                idx = (idx + 1) % capacity_;
            }
        }

        void log(LogLevel level, std::string_view msg);

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
        Logger();
        ~Logger() = default;
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;
        Logger(Logger&&) = delete;
        Logger& operator=(Logger&&) = delete;

        void push_locked(LogEntry entry);

        mutable std::mutex mutex_;
        std::vector<LogEntry> buffer_;
        std::size_t capacity_ = kDefaultCapacity;
        std::size_t start_ = 0;
        std::size_t count_ = 0;
        LogPanel* panel_ = nullptr;
    };

    // Convenience function for global access
    inline Logger& Log() { return Logger::instance(); }

} // namespace viewer