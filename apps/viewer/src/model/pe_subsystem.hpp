//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_PE_SUBSYSTEM_HPP
#define PEELF_EXPLORER_PE_SUBSYSTEM_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace pe {

// Windows subsystem values
namespace subsystem {
    inline constexpr std::uint16_t UNKNOWN                  = 0u;   // Unknown subsystem
    inline constexpr std::uint16_t NATIVE                   = 1u;   // Device drivers and native Windows processes
    inline constexpr std::uint16_t WINDOWS_GUI              = 2u;   // Windows graphical user interface
    inline constexpr std::uint16_t WINDOWS_CUI              = 3u;   // Windows character subsystem (console)
    inline constexpr std::uint16_t OS2_CUI                  = 5u;   // OS/2 character subsystem
    inline constexpr std::uint16_t POSIX_CUI                = 7u;   // POSIX character subsystem
    inline constexpr std::uint16_t NATIVE_WINDOWS           = 8u;   // Native Win9x driver
    inline constexpr std::uint16_t WINDOWS_CE_GUI           = 9u;   // Windows CE
    inline constexpr std::uint16_t EFI_APPLICATION          = 10u;  // EFI application
    inline constexpr std::uint16_t EFI_BOOT_SERVICE_DRIVER  = 11u;  // EFI driver with boot services
    inline constexpr std::uint16_t EFI_RUNTIME_DRIVER       = 12u;  // EFI driver with run-time services
    inline constexpr std::uint16_t EFI_ROM                  = 13u;  // EFI ROM image
    inline constexpr std::uint16_t XBOX                     = 14u;  // Xbox
    inline constexpr std::uint16_t WINDOWS_BOOT_APPLICATION = 16u;  // Windows boot application
} // namespace subsystem

struct SubsystemInfo {
    std::uint16_t value{0};
    const char* name{""};
    const char* description{""};
};

inline constexpr std::array<SubsystemInfo, 14> subsystem_table{{
    { subsystem::UNKNOWN,                  "UNKNOWN",                  "Unknown subsystem" },
    { subsystem::NATIVE,                   "NATIVE",                   "Device drivers and native Windows processes" },
    { subsystem::WINDOWS_GUI,              "WINDOWS_GUI",              "Windows GUI application" },
    { subsystem::WINDOWS_CUI,              "WINDOWS_CUI",              "Windows console application" },
    { subsystem::OS2_CUI,                  "OS2_CUI",                  "OS/2 console application" },
    { subsystem::POSIX_CUI,                "POSIX_CUI",                "POSIX console application" },
    { subsystem::NATIVE_WINDOWS,           "NATIVE_WINDOWS",           "Native Win9x driver" },
    { subsystem::WINDOWS_CE_GUI,           "WINDOWS_CE_GUI",           "Windows CE application" },
    { subsystem::EFI_APPLICATION,          "EFI_APPLICATION",          "EFI application" },
    { subsystem::EFI_BOOT_SERVICE_DRIVER,  "EFI_BOOT_SERVICE_DRIVER",  "EFI boot service driver" },
    { subsystem::EFI_RUNTIME_DRIVER,       "EFI_RUNTIME_DRIVER",       "EFI runtime driver" },
    { subsystem::EFI_ROM,                  "EFI_ROM",                  "EFI ROM image" },
    { subsystem::XBOX,                     "XBOX",                     "Xbox application" },
    { subsystem::WINDOWS_BOOT_APPLICATION, "WINDOWS_BOOT_APPLICATION", "Windows boot application" },
}};

inline constexpr std::size_t subsystem_table_size = subsystem_table.size();

[[nodiscard]] constexpr const char* get_subsystem_name(std::uint16_t value) noexcept {
    switch (value) {
        case subsystem::UNKNOWN:                  return "UNKNOWN";
        case subsystem::NATIVE:                   return "NATIVE";
        case subsystem::WINDOWS_GUI:              return "WINDOWS_GUI";
        case subsystem::WINDOWS_CUI:              return "WINDOWS_CUI";
        case subsystem::OS2_CUI:                  return "OS2_CUI";
        case subsystem::POSIX_CUI:                return "POSIX_CUI";
        case subsystem::NATIVE_WINDOWS:           return "NATIVE_WINDOWS";
        case subsystem::WINDOWS_CE_GUI:           return "WINDOWS_CE_GUI";
        case subsystem::EFI_APPLICATION:          return "EFI_APPLICATION";
        case subsystem::EFI_BOOT_SERVICE_DRIVER:  return "EFI_BOOT_SERVICE_DRIVER";
        case subsystem::EFI_RUNTIME_DRIVER:       return "EFI_RUNTIME_DRIVER";
        case subsystem::EFI_ROM:                  return "EFI_ROM";
        case subsystem::XBOX:                     return "XBOX";
        case subsystem::WINDOWS_BOOT_APPLICATION: return "WINDOWS_BOOT_APPLICATION";
        default:                                  return "UNKNOWN";
    }
}

[[nodiscard]] constexpr const char* get_subsystem_description(std::uint16_t value) noexcept {
    switch (value) {
        case subsystem::UNKNOWN:                  return "Unknown subsystem";
        case subsystem::NATIVE:                   return "Device drivers and native Windows processes";
        case subsystem::WINDOWS_GUI:              return "Windows GUI application";
        case subsystem::WINDOWS_CUI:              return "Windows console application";
        case subsystem::OS2_CUI:                  return "OS/2 console application";
        case subsystem::POSIX_CUI:                return "POSIX console application";
        case subsystem::NATIVE_WINDOWS:           return "Native Win9x driver";
        case subsystem::WINDOWS_CE_GUI:           return "Windows CE application";
        case subsystem::EFI_APPLICATION:          return "EFI application";
        case subsystem::EFI_BOOT_SERVICE_DRIVER:  return "EFI boot service driver";
        case subsystem::EFI_RUNTIME_DRIVER:       return "EFI runtime driver";
        case subsystem::EFI_ROM:                  return "EFI ROM image";
        case subsystem::XBOX:                     return "Xbox application";
        case subsystem::WINDOWS_BOOT_APPLICATION: return "Windows boot application";
        default:                                  return "Unknown subsystem";
    }
}

[[nodiscard]] constexpr const SubsystemInfo* get_subsystem_info(std::uint16_t value) noexcept {
    for (const SubsystemInfo& info : subsystem_table) {
        if (info.value == value) {
            return &info;
        }
    }
    return nullptr;
}

// Helper functions
[[nodiscard]] constexpr bool is_gui(std::uint16_t value) noexcept {
    return value == subsystem::WINDOWS_GUI ||
           value == subsystem::WINDOWS_CE_GUI;
}

[[nodiscard]] constexpr bool is_console(std::uint16_t value) noexcept {
    return value == subsystem::WINDOWS_CUI ||
           value == subsystem::OS2_CUI ||
           value == subsystem::POSIX_CUI;
}

[[nodiscard]] constexpr bool is_driver(std::uint16_t value) noexcept {
    return value == subsystem::NATIVE ||
           value == subsystem::NATIVE_WINDOWS ||
           value == subsystem::EFI_BOOT_SERVICE_DRIVER ||
           value == subsystem::EFI_RUNTIME_DRIVER;
}

[[nodiscard]] constexpr bool is_efi(std::uint16_t value) noexcept {
    return value == subsystem::EFI_APPLICATION ||
           value == subsystem::EFI_BOOT_SERVICE_DRIVER ||
           value == subsystem::EFI_RUNTIME_DRIVER ||
           value == subsystem::EFI_ROM;
}

} // namespace pe
#endif //PEELF_EXPLORER_PE_SUBSYSTEM_HPP