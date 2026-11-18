#include "ui_panels.hpp"
#include "logger.hpp"

#include <imgui.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

namespace viewer {
namespace {

    [[nodiscard]] std::string current_timestamp() {
        using namespace std::chrono;

        const auto now = system_clock::now();
        const std::time_t t = system_clock::to_time_t(now);

        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif

        std::ostringstream oss;
        oss << std::put_time(&tm, "%H:%M:%S");
        return oss.str();
    }

} // namespace

    LogPanel::LogPanel(std::size_t capacity)
        : UiPanel("Log"), capacity_(capacity)
    {
        if (capacity_ > 0) {
            buffer_.resize(capacity_);
        }
    }

    void LogPanel::add(LogLevel level, const std::string& msg) {
        if (Logger::instance().is_attached_to(this)) {
            Logger::instance().log(level, msg);
            return;
        }
        if (capacity_ == 0) {
            return;
        }
        Entry e{
            .timestamp = current_timestamp(),
            .level = level,
            .message = msg,
        };

        std::scoped_lock lock(mutex_);
        if (capacity_ == 0 || buffer_.empty()) {
            return;
        }
        buffer_[start_] = std::move(e);
        start_ = (start_ + 1) % capacity_;
        if (count_ < capacity_) {
            ++count_;
        }
    }

    std::vector<LogEntry> LogPanel::snapshot() const {
        if (Logger::instance().is_attached_to(this)) {
            return Logger::instance().snapshot();
        }
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

    void LogPanel::clear() noexcept {
        if (Logger::instance().is_attached_to(this)) {
            Logger::instance().clear();
        }
        std::scoped_lock lock(mutex_);
        for (Entry& entry : buffer_) {
            entry = Entry{};
        }
        start_ = 0;
        count_ = 0;
    }

    void LogPanel::draw_contents() {
        const std::vector<LogEntry> entries = snapshot();

        ImGui::BeginChild("LogScroll", ImVec2(0, 0), false);

        for (const LogEntry& e : entries) {
            ImVec4 color{};
            switch (e.level) {
                case LogLevel::Info:    color = ImGui::GetStyleColorVec4(ImGuiCol_Text); break;
                case LogLevel::Warning: color = ImGui::GetStyleColorVec4(ImGuiCol_PlotHistogram); break;
                case LogLevel::Error:   color = ImGui::GetStyleColorVec4(ImGuiCol_PlotHistogramHovered); break;
            }

            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::Text("[%s] ", e.timestamp.c_str());
            ImGui::SameLine();
            ImGui::TextUnformatted(e.message.c_str());
            ImGui::PopStyleColor();
        }

        if (auto_scroll_) {
            ImGui::SetScrollHereY(1.0f);
        }

        ImGui::EndChild();
    }

} // namespace viewer
