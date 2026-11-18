//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_CHARACTERISTICS_HPP
#define PEELF_EXPLORER_PE_CHARACTERISTICS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pe {

// File header characteristics flags
namespace characteristics {
    inline constexpr std::uint16_t RELOCS_STRIPPED         = 0x0001u;  // No base relocations, must load at preferred base
    inline constexpr std::uint16_t EXECUTABLE_IMAGE        = 0x0002u;  // Image is valid and can be run
    inline constexpr std::uint16_t LINE_NUMS_STRIPPED      = 0x0004u;  // COFF line numbers removed (deprecated, should be 0)
    inline constexpr std::uint16_t LOCAL_SYMS_STRIPPED     = 0x0008u;  // COFF symbol table entries removed (deprecated, should be 0)
    inline constexpr std::uint16_t AGGRESSIVE_WS_TRIM      = 0x0010u;  // Aggressively trim working set (obsolete, must be 0)
    inline constexpr std::uint16_t LARGE_ADDRESS_AWARE     = 0x0020u;  // Application can handle > 2GB addresses
    inline constexpr std::uint16_t RESERVED_0040           = 0x0040u;  // Reserved for future use
    inline constexpr std::uint16_t BYTES_REVERSED_LO       = 0x0080u;  // Little endian (deprecated, should be 0)
    inline constexpr std::uint16_t MACHINE_32BIT           = 0x0100u;  // Machine is based on 32-bit architecture
    inline constexpr std::uint16_t DEBUG_STRIPPED          = 0x0200u;  // Debugging information removed from image
    inline constexpr std::uint16_t REMOVABLE_RUN_FROM_SWAP = 0x0400u;  // If on removable media, fully load and copy to swap
    inline constexpr std::uint16_t NET_RUN_FROM_SWAP       = 0x0800u;  // If on network media, fully load and copy to swap
    inline constexpr std::uint16_t SYSTEM                  = 0x1000u;  // Image is a system file, not a user program
    inline constexpr std::uint16_t DLL                     = 0x2000u;  // Image is a DLL
    inline constexpr std::uint16_t UP_SYSTEM_ONLY          = 0x4000u;  // Should only run on uniprocessor machine
    inline constexpr std::uint16_t BYTES_REVERSED_HI       = 0x8000u;  // Big endian (deprecated, should be 0)
} // namespace characteristics

struct CharacteristicInfo {
    std::uint16_t flag{0};
    const char* name{""};
    const char* description{""};
};

inline constexpr std::array<CharacteristicInfo, 15> characteristics_table{{
    { characteristics::RELOCS_STRIPPED,         "RELOCS_STRIPPED",         "No base relocations" },
    { characteristics::EXECUTABLE_IMAGE,        "EXECUTABLE_IMAGE",        "Executable image" },
    { characteristics::LINE_NUMS_STRIPPED,      "LINE_NUMS_STRIPPED",      "Line numbers stripped (deprecated)" },
    { characteristics::LOCAL_SYMS_STRIPPED,     "LOCAL_SYMS_STRIPPED",     "Local symbols stripped (deprecated)" },
    { characteristics::AGGRESSIVE_WS_TRIM,      "AGGRESSIVE_WS_TRIM",      "Aggressively trim working set (obsolete)" },
    { characteristics::LARGE_ADDRESS_AWARE,     "LARGE_ADDRESS_AWARE",     "Can handle > 2GB addresses" },
    { characteristics::BYTES_REVERSED_LO,       "BYTES_REVERSED_LO",       "Little endian (deprecated)" },
    { characteristics::MACHINE_32BIT,           "32BIT_MACHINE",           "32-bit architecture" },
    { characteristics::DEBUG_STRIPPED,          "DEBUG_STRIPPED",          "Debug info stripped" },
    { characteristics::REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP", "Copy to swap if on removable media" },
    { characteristics::NET_RUN_FROM_SWAP,       "NET_RUN_FROM_SWAP",       "Copy to swap if on network media" },
    { characteristics::SYSTEM,                  "SYSTEM",                  "System file" },
    { characteristics::DLL,                     "DLL",                     "Dynamic-link library" },
    { characteristics::UP_SYSTEM_ONLY,          "UP_SYSTEM_ONLY",          "Uniprocessor only" },
    { characteristics::BYTES_REVERSED_HI,       "BYTES_REVERSED_HI",       "Big endian (deprecated)" },
}};

inline constexpr std::size_t characteristics_table_size = characteristics_table.size();

// Helper to get all set flags as a string
[[nodiscard]] inline std::string get_characteristics_string(std::uint16_t flags) {
    std::string result{};
    for (const CharacteristicInfo& info : characteristics_table) {
        if ((flags & info.flag) != 0u) {
            if (!result.empty()) {
                result += " | ";
            }
            result += info.name;
        }
    }
    return result.empty() ? std::string("NONE") : result;
}

// Helper to iterate over set flags
template<typename Func>
void for_each_characteristic(std::uint16_t flags, Func&& func) {
    for (const CharacteristicInfo& info : characteristics_table) {
        if ((flags & info.flag) != 0u) {
            func(info);
        }
    }
}

} // namespace pe
#endif //PEELF_EXPLORER_PE_CHARACTERISTICS_HPP