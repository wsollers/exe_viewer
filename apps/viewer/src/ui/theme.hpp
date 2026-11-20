#pragma once
#include <imgui.h>
#include "theme_resource.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <cmath>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#define PEELF_THEME_UNDEF_NOMINMAX
#endif
#include <windows.h>
#ifdef PEELF_THEME_UNDEF_NOMINMAX
#undef NOMINMAX
#undef PEELF_THEME_UNDEF_NOMINMAX
#endif
#endif
namespace viewer::ui {
inline void load_theme(float content_scale = 0.0f) {
    const float font_scale = ImGui::GetStyle().FontScaleMain;
    const float font_dpi = ImGui::GetStyle().FontScaleDpi;
    ImGui::GetStyle() = ImGuiStyle{};
    ImGui::GetStyle().FontScaleMain = font_scale;
    ImGui::GetStyle().FontScaleDpi = font_dpi;
    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowPadding = {8, 6};
    style.FramePadding = {5, 2};
    style.ItemSpacing = {6, 3};
    style.CellPadding = {4, 2};
    style.FrameRounding = 2;
    style.TabRounding = 2;
    style.ScrollbarSize = 11;
#ifdef _WIN32
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const auto directory = std::filesystem::path(executable).parent_path();
#else
    std::error_code ec;
    const auto exe_path = std::filesystem::weakly_canonical("/proc/self/exe", ec);
    const auto directory = (ec || exe_path.empty())
                               ? std::filesystem::current_path(ec)
                               : exe_path.parent_path();
#endif
    std::ifstream input(directory / "resources" / "theme.ini");
    const auto resource = read_theme(input);
    for (int i = 0; i < ImGuiCol_COUNT; ++i) {
        if (const auto found = resource.colors.find(ImGui::GetStyleColorName(i)); found != resource.colors.end()) {
            const auto& c = found->second;
            style.Colors[i] = {c[0], c[1], c[2], c[3]};
        }
    }
    auto metric = [&](const char* name, float& target) {
        if (const auto found = resource.metrics.find(name); found != resource.metrics.end()) target = found->second;
    };
    metric("FrameRounding", style.FrameRounding);
    metric("TabRounding", style.TabRounding);
    metric("WindowRounding", style.WindowRounding);
    metric("ScrollbarSize", style.ScrollbarSize);
    metric("WindowPaddingX", style.WindowPadding.x);
    metric("WindowPaddingY", style.WindowPadding.y);
    metric("FramePaddingX", style.FramePadding.x);
    metric("FramePaddingY", style.FramePadding.y);
    metric("ItemSpacingX", style.ItemSpacing.x);
    metric("ItemSpacingY", style.ItemSpacing.y);
    metric("CellPaddingX", style.CellPadding.x);
    metric("CellPaddingY", style.CellPadding.y);
    metric("FrameBorderSize", style.FrameBorderSize);
    metric("ChildBorderSize", style.ChildBorderSize);
    metric("DockingSeparatorSize", style.DockingSeparatorSize);
    const float dpi = content_scale > 0.0f ? content_scale : ImGui::GetMainViewport()->DpiScale;
    style.ScaleAllSizes(dpi > 0.0f ? dpi : 1.0f);
}
}
