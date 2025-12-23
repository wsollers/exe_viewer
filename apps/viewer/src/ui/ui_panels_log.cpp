#include "ui_panels.hpp"
#include <imgui.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace viewer {

    static std::string current_timestamp() {
        using namespace std::chrono;

        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);

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

    LogPanel::LogPanel(size_t capacity)
        : UiPanel("Log"), capacity_(capacity)
    {
        buffer_.resize(capacity_);
    }

    void LogPanel::add(LogLevel level, const std::string& msg) {
        Entry e;
        e.timestamp = current_timestamp();
        e.level = level;
        e.message = msg;

        buffer_[start_] = std::move(e);
        start_ = (start_ + 1) % capacity_;
        if (count_ < capacity_) count_++;
    }

    void LogPanel::draw_contents() {
        ImGui::BeginChild("LogScroll", ImVec2(0,0), false);

        size_t idx = (start_ + capacity_ - count_) % capacity_;
        for (size_t i = 0; i < count_; ++i) {
            const Entry& e = buffer_[idx];

            ImVec4 color;
            switch (e.level) {
                case LogLevel::Info:    color = ImVec4(0.8f, 0.8f, 0.8f, 1); break;
                case LogLevel::Warning: color = ImVec4(1.0f, 0.8f, 0.2f, 1); break;
                case LogLevel::Error:   color = ImVec4(1.0f, 0.3f, 0.3f, 1); break;
            }

            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::Text("[%s] ", e.timestamp.c_str());
            ImGui::SameLine();
            ImGui::TextUnformatted(e.message.c_str());
            ImGui::PopStyleColor();

            idx = (idx + 1) % capacity_;
        }

        if (auto_scroll_)
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndChild();
    }

} // namespace viewer