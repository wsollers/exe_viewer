//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_PE_SUBSYSTEM_HPP
#define PEELF_EXPLORER_PE_SUBSYSTEM_HPP
namespace pe {

// Windows subsystem values
namespace subsystem {
    constexpr uint16_t UNKNOWN                  = 0;   // Unknown subsystem
    constexpr uint16_t NATIVE                   = 1;   // Device drivers and native Windows processes
    constexpr uint16_t WINDOWS_GUI              = 2;   // Windows graphical user interface
    constexpr uint16_t WINDOWS_CUI              = 3;   // Windows character subsystem (console)
    constexpr uint16_t OS2_CUI                  = 5;   // OS/2 character subsystem
    constexpr uint16_t POSIX_CUI                = 7;   // POSIX character subsystem
    constexpr uint16_t NATIVE_WINDOWS           = 8;   // Native Win9x driver
    constexpr uint16_t WINDOWS_CE_GUI           = 9;   // Windows CE
    constexpr uint16_t EFI_APPLICATION          = 10;  // EFI application
    constexpr uint16_t EFI_BOOT_SERVICE_DRIVER  = 11;  // EFI driver with boot services
    constexpr uint16_t EFI_RUNTIME_DRIVER       = 12;  // EFI driver with run-time services
    constexpr uint16_t EFI_ROM                  = 13;  // EFI ROM image
    constexpr uint16_t XBOX                     = 14;  // Xbox
    constexpr uint16_t WINDOWS_BOOT_APPLICATION = 16;  // Windows boot application
}

struct SubsystemInfo {
    uint16_t value;
    const char* name;
    const char* description;
};

constexpr SubsystemInfo subsystem_table[] = {
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
};

constexpr size_t subsystem_table_size = sizeof(subsystem_table) / sizeof(subsystem_table[0]);

constexpr const char* get_subsystem_name(uint16_t value) {
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

constexpr const char* get_subsystem_description(uint16_t value) {
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

constexpr const SubsystemInfo* get_subsystem_info(uint16_t value) {
    for (size_t i = 0; i < subsystem_table_size; ++i) {
        if (subsystem_table[i].value == value) {
            return &subsystem_table[i];
        }
    }
    return nullptr;
}

// Helper functions
constexpr bool is_gui(uint16_t value) {
    return value == subsystem::WINDOWS_GUI ||
           value == subsystem::WINDOWS_CE_GUI;
}

constexpr bool is_console(uint16_t value) {
    return value == subsystem::WINDOWS_CUI ||
           value == subsystem::OS2_CUI ||
           value == subsystem::POSIX_CUI;
}

constexpr bool is_driver(uint16_t value) {
    return value == subsystem::NATIVE ||
           value == subsystem::NATIVE_WINDOWS ||
           value == subsystem::EFI_BOOT_SERVICE_DRIVER ||
           value == subsystem::EFI_RUNTIME_DRIVER;
}

constexpr bool is_efi(uint16_t value) {
    return value == subsystem::EFI_APPLICATION ||
           value == subsystem::EFI_BOOT_SERVICE_DRIVER ||
           value == subsystem::EFI_RUNTIME_DRIVER ||
           value == subsystem::EFI_ROM;
}

} // namespace pe
#endif //PEELF_EXPLORER_PE_SUBSYSTEM_HPP