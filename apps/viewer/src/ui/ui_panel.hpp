#pragma once
#include <string>
#include <imgui.h>

namespace viewer {

    class UiPanel {
    public:
        explicit UiPanel(std::string name)
            : name_(std::move(name)) {}

        virtual ~UiPanel() = default;

        void draw() {
            if (!visible_) return;
            if (begin()) {
                draw_contents();
                end();
            }
        }

        void set_visible(bool v) { visible_ = v; }
        bool visible() const { return visible_; }
        const std::string& name() const { return name_; }

    protected:
        virtual void draw_contents() = 0;

        virtual bool begin() {
            return ImGui::Begin(name_.c_str(), &visible_);
        }

        virtual void end() {
            ImGui::End();
        }

        bool visible_ = true;
        std::string name_;
    };

} // namespace viewer