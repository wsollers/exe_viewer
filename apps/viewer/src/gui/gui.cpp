//
// Created by wsoll on 12/23/2025.
//
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_vulkan.h>

#include <cstdio>
#include <stdexcept>



#include "gui.h"
#include "peelf/peelf.hpp"
#include "mapping/file_mapping.hpp"
#include "pe/pe_parser.h"
#include <nfd.h>


std::optional<std::string> open_file_dialog() {
    NFD_Init();

    nfdchar_t* out_path = nullptr;
    nfdfilteritem_t filters[2] = {
        { "Executables", "exe,dll,so,elf" },
        { "All Files", "*" }
    };

    nfdresult_t result = NFD_OpenDialog(&out_path, filters, 2, nullptr);

    std::optional<std::string> path;

    if (result == NFD_OKAY) {
        path = std::string(out_path);
        NFD_FreePath(out_path);
    } else if (result == NFD_CANCEL) {
        // User cancelled - not an error
    } else {
        fprintf(stderr, "File dialog error: %s\n", NFD_GetError());
    }

    NFD_Quit();
    return path;
}
void load_file(const std::string& path) {


    bool file_loaded_ = true;

    printf("Loading file: %s\n", path.c_str());

    // Example:
    try {
        std::filesystem::path fileToOpen(path);
        peelf::FileMapping<std::uint8_t, peelf::NativeFileMappingBackend> map(fileToOpen,peelf::MapMode::read_only);

        size_t size = map.size();
        size_t sizeBytes = map.size_bytes();
        const std::span<std::uint8_t> data = map.view();
        auto rc = peelf::parse_pe_bytes(data);
        // Store parsed data...
    } catch (const std::exception& e) {
        fprintf(stderr, "Failed to load file: %s\n", e.what());
        file_loaded_ = false;
    }
}


void menubar::render() {
    // Main menu bar
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open", "Ctrl+O")) {
                if (auto path = open_file_dialog()) {
                    load_file(*path);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                //glfwSetWindowShouldClose(window_, GLFW_TRUE);
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Demo Window", nullptr, false);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) {
                // TODO: Show about dialog
            }
            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }

}
