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
inline void load_theme() {
    const float font_scale = ImGui::GetStyle().FontScaleMain;
    ImGui::GetStyle() = ImGuiStyle{};
    ImGui::GetStyle().FontScaleMain = font_scale;
    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowPadding = {12,12};
    style.FramePadding = {8,5};
    style.ItemSpacing = {8,7};
    style.CellPadding = {8,4};
    style.FrameRounding = 4;
    style.TabRounding = 4;
    style.ScrollbarSize = 12;
#ifdef _WIN32
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const auto directory = std::filesystem::path(executable).parent_path();
#else
    const auto directory = std::filesystem::canonical("/proc/self/exe").parent_path();
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
    const float dpi = ImGui::GetMainViewport()->DpiScale;
    style.ScaleAllSizes(dpi > 0.0f ? dpi : 1.0f);
}
}
