#include "logger.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace viewer {
namespace {

[[nodiscard]] std::string format_log_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t raw_time = std::chrono::system_clock::to_time_t(now);

    std::tm local_tm{};
#ifdef _WIN32
    localtime_s(&local_tm, &raw_time);
#else
    localtime_r(&raw_time, &local_tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%H:%M:%S");
    return oss.str();
}

} // namespace

    Logger::Logger() : buffer_(kDefaultCapacity) {}

    void Logger::init(LogPanel* panel, std::optional<std::size_t> panel_capacity) noexcept {
        try {
            std::scoped_lock lock(mutex_);
            panel_ = panel;
            if (panel_ != nullptr && panel_capacity.has_value() && *panel_capacity != capacity_) {
                const std::size_t next_cap = *panel_capacity;
                if (next_cap == 0) {
                    buffer_.clear();
                    capacity_ = 0;
                    start_ = 0;
                    count_ = 0;
                } else {
                    std::vector<LogEntry> next_buf(next_cap);
                    const std::size_t keep = std::min(count_, next_cap);
                    if (keep > 0 && capacity_ > 0 && !buffer_.empty()) {
                        std::size_t idx = (start_ + capacity_ - keep) % capacity_;
                        for (std::size_t i = 0; i < keep; ++i) {
                            next_buf[i] = std::move(buffer_[idx]);
                            idx = (idx + 1) % capacity_;
                        }
                    }
                    buffer_ = std::move(next_buf);
                    capacity_ = next_cap;
                    start_ = keep % capacity_;
                    count_ = keep;
                }
            }
        } catch (...) {
        }
    }

    bool Logger::is_attached_to(const LogPanel* panel) const noexcept {
        std::scoped_lock lock(mutex_);
        return panel != nullptr && panel_ == panel;
    }

    void Logger::set_capacity(std::size_t capacity) {
        std::scoped_lock lock(mutex_);
        if (capacity == 0) {
            buffer_.clear();
            capacity_ = 0;
            start_ = 0;
            count_ = 0;
            return;
        }
        std::vector<LogEntry> next_buf(capacity);
        const std::size_t keep = std::min(count_, capacity);
        if (keep > 0 && capacity_ > 0 && !buffer_.empty()) {
            std::size_t idx = (start_ + capacity_ - keep) % capacity_;
            for (std::size_t i = 0; i < keep; ++i) {
                next_buf[i] = std::move(buffer_[idx]);
                idx = (idx + 1) % capacity_;
            }
        }
        buffer_ = std::move(next_buf);
        capacity_ = capacity;
        start_ = keep % capacity_;
        count_ = keep;
    }

    std::size_t Logger::capacity() const noexcept {
        std::scoped_lock lock(mutex_);
        return capacity_;
    }

    void Logger::clear() noexcept {
        std::scoped_lock lock(mutex_);
        for (LogEntry& entry : buffer_) {
            entry = LogEntry{};
        }
        start_ = 0;
        count_ = 0;
    }

    std::vector<LogEntry> Logger::snapshot() const {
        std::scoped_lock lock(mutex_);
        if (capacity_ == 0 || count_ == 0 || buffer_.empty()) {
            return {};
        }
        std::vector<LogEntry> out;
        out.reserve(count_);
        std::size_t idx = (start_ + capacity_ - count_) % capacity_;
        for (std::size_t i = 0; i < count_; ++i) {
            out.push_back(buffer_[idx]);
            idx = (idx + 1) % capacity_;
        }
        return out;
    }

    void Logger::push_locked(LogEntry entry) {
        if (capacity_ == 0 || buffer_.empty()) {
            return;
        }
        buffer_[start_] = std::move(entry);
        start_ = (start_ + 1) % capacity_;
        if (count_ < capacity_) {
            ++count_;
        }
    }

    void Logger::log(LogLevel level, std::string_view msg) {
        LogEntry entry{
            .timestamp = format_log_timestamp(),
            .level = level,
            .message = std::string(msg),
        };
        std::scoped_lock lock(mutex_);
        push_locked(std::move(entry));
    }

    void Logger::info(const std::string& msg) {
        log(LogLevel::Info, msg);
    }

    void Logger::warn(const std::string& msg) {
        log(LogLevel::Warning, msg);
    }

    void Logger::error(const std::string& msg) {
        log(LogLevel::Error, msg);
    }

} // namespace viewer