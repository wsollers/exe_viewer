//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP
#define PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP

namespace pe {
namespace optional_image {
    // Optional header magic numbers
    namespace magic {
        constexpr uint16_t PE32      = 0x010B;  // 32-bit executable
        constexpr uint16_t PE32PLUS  = 0x020B;  // 64-bit executable
        constexpr uint16_t ROM       = 0x0107;  // ROM image

        constexpr const char* get_magic_name(uint16_t magic) {
            switch (magic) {
                case magic::PE32:     return "PE32";
                case magic::PE32PLUS: return "PE32+";
                case magic::ROM:      return "ROM";
                default:              return "Unknown";
            }
        }

        constexpr const char* get_magic_description(uint16_t magic) {
            switch (magic) {
                case magic::PE32:     return "32-bit executable";
                case magic::PE32PLUS: return "64-bit executable";
                case magic::ROM:      return "ROM image";
                default:              return "Unknown format";
            }
        }

        constexpr bool is_64bit(uint16_t magic) {
            return magic == magic::PE32PLUS;
        }

        constexpr bool is_32bit(uint16_t magic) {
            return magic == magic::PE32;
        }
    }

    // DLL characteristics flags
    namespace dll_characteristics {
        constexpr uint16_t RESERVED_0001           = 0x0001;  // Reserved, must be zero
        constexpr uint16_t RESERVED_0002           = 0x0002;  // Reserved, must be zero
        constexpr uint16_t RESERVED_0004           = 0x0004;  // Reserved, must be zero
        constexpr uint16_t RESERVED_0008           = 0x0008;  // Reserved, must be zero
        constexpr uint16_t HIGH_ENTROPY_VA         = 0x0020;  // Image can handle high entropy 64-bit virtual address space
        constexpr uint16_t DYNAMIC_BASE            = 0x0040;  // DLL can be relocated at load time (ASLR)
        constexpr uint16_t FORCE_INTEGRITY         = 0x0080;  // Code integrity checks are enforced
        constexpr uint16_t NX_COMPAT               = 0x0100;  // Image is NX compatible (DEP)
        constexpr uint16_t NO_ISOLATION            = 0x0200;  // Isolation aware, but do not isolate the image
        constexpr uint16_t NO_SEH                  = 0x0400;  // Does not use structured exception handling
        constexpr uint16_t NO_BIND                 = 0x0800;  // Do not bind the image
        constexpr uint16_t APPCONTAINER            = 0x1000;  // Image must execute in an AppContainer
        constexpr uint16_t WDM_DRIVER              = 0x2000;  // A WDM driver
        constexpr uint16_t GUARD_CF                = 0x4000;  // Image supports Control Flow Guard
        constexpr uint16_t TERMINAL_SERVER_AWARE   = 0x8000;  // Terminal Server aware
    }

    struct DllCharacteristicInfo {
        uint16_t flag;
        const char* name;
        const char* description;
    };

    constexpr DllCharacteristicInfo dll_characteristics_table[] = {
        { dll_characteristics::HIGH_ENTROPY_VA,       "HIGH_ENTROPY_VA",       "High entropy 64-bit VA space" },
        { dll_characteristics::DYNAMIC_BASE,          "DYNAMIC_BASE",          "ASLR enabled" },
        { dll_characteristics::FORCE_INTEGRITY,       "FORCE_INTEGRITY",       "Code integrity checks enforced" },
        { dll_characteristics::NX_COMPAT,             "NX_COMPAT",             "DEP enabled" },
        { dll_characteristics::NO_ISOLATION,          "NO_ISOLATION",          "Isolation aware, not isolated" },
        { dll_characteristics::NO_SEH,                "NO_SEH",                "No structured exception handling" },
        { dll_characteristics::NO_BIND,               "NO_BIND",               "Do not bind image" },
        { dll_characteristics::APPCONTAINER,          "APPCONTAINER",          "Must run in AppContainer" },
        { dll_characteristics::WDM_DRIVER,            "WDM_DRIVER",            "WDM driver" },
        { dll_characteristics::GUARD_CF,              "GUARD_CF",              "Control Flow Guard enabled" },
        { dll_characteristics::TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE", "Terminal Server aware" },
    };

    constexpr size_t dll_characteristics_table_size = sizeof(dll_characteristics_table) / sizeof(dll_characteristics_table[0]);

    inline std::string get_dll_characteristics_string(uint16_t flags) {
        std::string result;
        for (size_t i = 0; i < dll_characteristics_table_size; ++i) {
            if (flags & dll_characteristics_table[i].flag) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += dll_characteristics_table[i].name;
            }
        }
        return result.empty() ? "NONE" : result;
    }

    template<typename Func>
    void for_each_dll_characteristic(uint16_t flags, Func&& func) {
        for (size_t i = 0; i < dll_characteristics_table_size; ++i) {
            if (flags & dll_characteristics_table[i].flag) {
                func(dll_characteristics_table[i]);
            }
        }
    }

    // Security feature helpers
    constexpr bool has_aslr(uint16_t flags) {
        return flags & dll_characteristics::DYNAMIC_BASE;
    }

    constexpr bool has_dep(uint16_t flags) {
        return flags & dll_characteristics::NX_COMPAT;
    }

    constexpr bool has_cfg(uint16_t flags) {
        return flags & dll_characteristics::GUARD_CF;
    }

    constexpr bool has_high_entropy_aslr(uint16_t flags) {
        return (flags & dll_characteristics::HIGH_ENTROPY_VA) &&
               (flags & dll_characteristics::DYNAMIC_BASE);
    }
}
} // namespace pe



#endif //PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP