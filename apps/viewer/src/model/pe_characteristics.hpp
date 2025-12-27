//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_CHARACTERISTICS_HPP
#define PEELF_EXPLORER_PE_CHARACTERISTICS_HPP

namespace pe {

// File header characteristics flags
namespace characteristics {
    constexpr uint16_t RELOCS_STRIPPED         = 0x0001;  // No base relocations, must load at preferred base
    constexpr uint16_t EXECUTABLE_IMAGE        = 0x0002;  // Image is valid and can be run
    constexpr uint16_t LINE_NUMS_STRIPPED      = 0x0004;  // COFF line numbers removed (deprecated, should be 0)
    constexpr uint16_t LOCAL_SYMS_STRIPPED     = 0x0008;  // COFF symbol table entries removed (deprecated, should be 0)
    constexpr uint16_t AGGRESSIVE_WS_TRIM      = 0x0010;  // Aggressively trim working set (obsolete, must be 0)
    constexpr uint16_t LARGE_ADDRESS_AWARE     = 0x0020;  // Application can handle > 2GB addresses
    constexpr uint16_t RESERVED_0040           = 0x0040;  // Reserved for future use
    constexpr uint16_t BYTES_REVERSED_LO       = 0x0080;  // Little endian (deprecated, should be 0)
    constexpr uint16_t MACHINE_32BIT           = 0x0100;  // Machine is based on 32-bit architecture
    constexpr uint16_t DEBUG_STRIPPED          = 0x0200;  // Debugging information removed from image
    constexpr uint16_t REMOVABLE_RUN_FROM_SWAP = 0x0400;  // If on removable media, fully load and copy to swap
    constexpr uint16_t NET_RUN_FROM_SWAP       = 0x0800;  // If on network media, fully load and copy to swap
    constexpr uint16_t SYSTEM                  = 0x1000;  // Image is a system file, not a user program
    constexpr uint16_t DLL                     = 0x2000;  // Image is a DLL
    constexpr uint16_t UP_SYSTEM_ONLY          = 0x4000;  // Should only run on uniprocessor machine
    constexpr uint16_t BYTES_REVERSED_HI       = 0x8000;  // Big endian (deprecated, should be 0)
}

struct CharacteristicInfo {
    uint16_t flag;
    const char* name;
    const char* description;
};

constexpr CharacteristicInfo characteristics_table[] = {
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
};

constexpr size_t characteristics_table_size = sizeof(characteristics_table) / sizeof(characteristics_table[0]);

// Helper to get all set flags as a string
inline std::string get_characteristics_string(uint16_t flags) {
    std::string result;
    for (size_t i = 0; i < characteristics_table_size; ++i) {
        if (flags & characteristics_table[i].flag) {
            if (!result.empty()) {
                result += " | ";
            }
            result += characteristics_table[i].name;
        }
    }
    return result.empty() ? "NONE" : result;
}

// Helper to iterate over set flags
template<typename Func>
void for_each_characteristic(uint16_t flags, Func&& func) {
    for (size_t i = 0; i < characteristics_table_size; ++i) {
        if (flags & characteristics_table[i].flag) {
            func(characteristics_table[i]);
        }
    }
}

} // namespace pe
#endif //PEELF_EXPLORER_PE_CHARACTERISTICS_HPP