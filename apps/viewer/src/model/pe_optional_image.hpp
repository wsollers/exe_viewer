//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP
#define PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pe {
namespace optional_image {
    // Optional header magic numbers
    namespace magic {
        inline constexpr std::uint16_t PE32      = 0x010Bu;  // 32-bit executable
        inline constexpr std::uint16_t PE32PLUS  = 0x020Bu;  // 64-bit executable
        inline constexpr std::uint16_t ROM       = 0x0107u;  // ROM image

        [[nodiscard]] constexpr const char* get_magic_name(std::uint16_t magic_value) noexcept {
            switch (magic_value) {
                case magic::PE32:     return "PE32";
                case magic::PE32PLUS: return "PE32+";
                case magic::ROM:      return "ROM";
                default:              return "Unknown";
            }
        }

        [[nodiscard]] constexpr const char* get_magic_description(std::uint16_t magic_value) noexcept {
            switch (magic_value) {
                case magic::PE32:     return "32-bit executable";
                case magic::PE32PLUS: return "64-bit executable";
                case magic::ROM:      return "ROM image";
                default:              return "Unknown format";
            }
        }

        [[nodiscard]] constexpr bool is_64bit(std::uint16_t magic_value) noexcept {
            return magic_value == magic::PE32PLUS;
        }

        [[nodiscard]] constexpr bool is_32bit(std::uint16_t magic_value) noexcept {
            return magic_value == magic::PE32;
        }
    } // namespace magic

    // DLL characteristics flags
    namespace dll_characteristics {
        inline constexpr std::uint16_t RESERVED_0001           = 0x0001u;  // Reserved, must be zero
        inline constexpr std::uint16_t RESERVED_0002           = 0x0002u;  // Reserved, must be zero
        inline constexpr std::uint16_t RESERVED_0004           = 0x0004u;  // Reserved, must be zero
        inline constexpr std::uint16_t RESERVED_0008           = 0x0008u;  // Reserved, must be zero
        inline constexpr std::uint16_t HIGH_ENTROPY_VA         = 0x0020u;  // Image can handle high entropy 64-bit virtual address space
        inline constexpr std::uint16_t DYNAMIC_BASE            = 0x0040u;  // DLL can be relocated at load time (ASLR)
        inline constexpr std::uint16_t FORCE_INTEGRITY         = 0x0080u;  // Code integrity checks are enforced
        inline constexpr std::uint16_t NX_COMPAT               = 0x0100u;  // Image is NX compatible (DEP)
        inline constexpr std::uint16_t NO_ISOLATION            = 0x0200u;  // Isolation aware, but do not isolate the image
        inline constexpr std::uint16_t NO_SEH                  = 0x0400u;  // Does not use structured exception handling
        inline constexpr std::uint16_t NO_BIND                 = 0x0800u;  // Do not bind the image
        inline constexpr std::uint16_t APPCONTAINER            = 0x1000u;  // Image must execute in an AppContainer
        inline constexpr std::uint16_t WDM_DRIVER              = 0x2000u;  // A WDM driver
        inline constexpr std::uint16_t GUARD_CF                = 0x4000u;  // Image supports Control Flow Guard
        inline constexpr std::uint16_t TERMINAL_SERVER_AWARE   = 0x8000u;  // Terminal Server aware
    } // namespace dll_characteristics

    struct DllCharacteristicInfo {
        std::uint16_t flag{0};
        const char* name{""};
        const char* description{""};
    };

    inline constexpr std::array<DllCharacteristicInfo, 11> dll_characteristics_table{{
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
    }};

    inline constexpr std::size_t dll_characteristics_table_size = dll_characteristics_table.size();

    [[nodiscard]] inline std::string get_dll_characteristics_string(std::uint16_t flags) {
        std::string result{};
        for (const DllCharacteristicInfo& info : dll_characteristics_table) {
            if ((flags & info.flag) != 0u) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += info.name;
            }
        }
        return result.empty() ? std::string("NONE") : result;
    }

    template<typename Func>
    void for_each_dll_characteristic(std::uint16_t flags, Func&& func) {
        for (const DllCharacteristicInfo& info : dll_characteristics_table) {
            if ((flags & info.flag) != 0u) {
                func(info);
            }
        }
    }

    // Security feature helpers
    [[nodiscard]] constexpr bool has_aslr(std::uint16_t flags) noexcept {
        return (flags & dll_characteristics::DYNAMIC_BASE) != 0u;
    }

    [[nodiscard]] constexpr bool has_dep(std::uint16_t flags) noexcept {
        return (flags & dll_characteristics::NX_COMPAT) != 0u;
    }

    [[nodiscard]] constexpr bool has_cfg(std::uint16_t flags) noexcept {
        return (flags & dll_characteristics::GUARD_CF) != 0u;
    }

    [[nodiscard]] constexpr bool has_high_entropy_aslr(std::uint16_t flags) noexcept {
        return (flags & dll_characteristics::HIGH_ENTROPY_VA) != 0u &&
               (flags & dll_characteristics::DYNAMIC_BASE) != 0u;
    }
} // namespace optional_image
} // namespace pe

#endif //PEELF_EXPLORER_PE_OPTIONAL_IMAGE_HPP