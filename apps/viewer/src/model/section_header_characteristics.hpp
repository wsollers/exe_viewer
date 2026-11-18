//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP
#define PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pe {

// Section header characteristics flags
namespace section_flags {
    inline constexpr std::uint32_t RESERVED_0001          = 0x00000001u;  // Reserved for future use
    inline constexpr std::uint32_t RESERVED_0002          = 0x00000002u;  // Reserved for future use
    inline constexpr std::uint32_t RESERVED_0004          = 0x00000004u;  // Reserved for future use
    inline constexpr std::uint32_t TYPE_NO_PAD            = 0x00000008u;  // Section should not be padded (obsolete, use ALIGN_1BYTES)
    inline constexpr std::uint32_t RESERVED_0010          = 0x00000010u;  // Reserved for future use
    inline constexpr std::uint32_t CNT_CODE               = 0x00000020u;  // Section contains executable code
    inline constexpr std::uint32_t CNT_INITIALIZED_DATA   = 0x00000040u;  // Section contains initialized data
    inline constexpr std::uint32_t CNT_UNINITIALIZED_DATA = 0x00000080u;  // Section contains uninitialized data (BSS)
    inline constexpr std::uint32_t LNK_OTHER              = 0x00000100u;  // Reserved for future use
    inline constexpr std::uint32_t LNK_INFO               = 0x00000200u;  // Section contains comments or other info (.drectve)
    inline constexpr std::uint32_t RESERVED_0400          = 0x00000400u;  // Reserved for future use
    inline constexpr std::uint32_t LNK_REMOVE             = 0x00000800u;  // Section will not become part of image (object only)
    inline constexpr std::uint32_t LNK_COMDAT             = 0x00001000u;  // Section contains COMDAT data (object only)
    inline constexpr std::uint32_t GPREL                  = 0x00008000u;  // Section contains data referenced through GP
    inline constexpr std::uint32_t MEM_PURGEABLE          = 0x00020000u;  // Reserved for future use
    inline constexpr std::uint32_t MEM_16BIT              = 0x00020000u;  // Reserved for future use (same as PURGEABLE)
    inline constexpr std::uint32_t MEM_LOCKED             = 0x00040000u;  // Reserved for future use
    inline constexpr std::uint32_t MEM_PRELOAD            = 0x00080000u;  // Reserved for future use

    // Alignment flags (object files only)
    inline constexpr std::uint32_t ALIGN_1BYTES           = 0x00100000u;  // Align data on 1-byte boundary
    inline constexpr std::uint32_t ALIGN_2BYTES           = 0x00200000u;  // Align data on 2-byte boundary
    inline constexpr std::uint32_t ALIGN_4BYTES           = 0x00300000u;  // Align data on 4-byte boundary
    inline constexpr std::uint32_t ALIGN_8BYTES           = 0x00400000u;  // Align data on 8-byte boundary
    inline constexpr std::uint32_t ALIGN_16BYTES          = 0x00500000u;  // Align data on 16-byte boundary
    inline constexpr std::uint32_t ALIGN_32BYTES          = 0x00600000u;  // Align data on 32-byte boundary
    inline constexpr std::uint32_t ALIGN_64BYTES          = 0x00700000u;  // Align data on 64-byte boundary
    inline constexpr std::uint32_t ALIGN_128BYTES         = 0x00800000u;  // Align data on 128-byte boundary
    inline constexpr std::uint32_t ALIGN_256BYTES         = 0x00900000u;  // Align data on 256-byte boundary
    inline constexpr std::uint32_t ALIGN_512BYTES         = 0x00A00000u;  // Align data on 512-byte boundary
    inline constexpr std::uint32_t ALIGN_1024BYTES        = 0x00B00000u;  // Align data on 1024-byte boundary
    inline constexpr std::uint32_t ALIGN_2048BYTES        = 0x00C00000u;  // Align data on 2048-byte boundary
    inline constexpr std::uint32_t ALIGN_4096BYTES        = 0x00D00000u;  // Align data on 4096-byte boundary
    inline constexpr std::uint32_t ALIGN_8192BYTES        = 0x00E00000u;  // Align data on 8192-byte boundary
    inline constexpr std::uint32_t ALIGN_MASK             = 0x00F00000u;  // Mask for alignment value

    inline constexpr std::uint32_t LNK_NRELOC_OVFL        = 0x01000000u;  // Section contains extended relocations
    inline constexpr std::uint32_t MEM_DISCARDABLE        = 0x02000000u;  // Section can be discarded as needed
    inline constexpr std::uint32_t MEM_NOT_CACHED         = 0x04000000u;  // Section cannot be cached
    inline constexpr std::uint32_t MEM_NOT_PAGED          = 0x08000000u;  // Section is not pageable
    inline constexpr std::uint32_t MEM_SHARED             = 0x10000000u;  // Section can be shared in memory
    inline constexpr std::uint32_t MEM_EXECUTE            = 0x20000000u;  // Section can be executed as code
    inline constexpr std::uint32_t MEM_READ               = 0x40000000u;  // Section can be read
    inline constexpr std::uint32_t MEM_WRITE              = 0x80000000u;  // Section can be written to
} // namespace section_flags

struct SectionFlagInfo {
    std::uint32_t flag{0};
    const char* name{""};
    const char* description{""};
};

inline constexpr std::array<SectionFlagInfo, 17> section_flags_table{{
    { section_flags::TYPE_NO_PAD,            "TYPE_NO_PAD",            "No padding (obsolete)" },
    { section_flags::CNT_CODE,               "CNT_CODE",               "Contains executable code" },
    { section_flags::CNT_INITIALIZED_DATA,   "CNT_INITIALIZED_DATA",   "Contains initialized data" },
    { section_flags::CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA", "Contains uninitialized data" },
    { section_flags::LNK_OTHER,              "LNK_OTHER",              "Reserved" },
    { section_flags::LNK_INFO,               "LNK_INFO",               "Contains comments or info" },
    { section_flags::LNK_REMOVE,             "LNK_REMOVE",             "Will not become part of image" },
    { section_flags::LNK_COMDAT,             "LNK_COMDAT",             "Contains COMDAT data" },
    { section_flags::GPREL,                  "GPREL",                  "GP relative data" },
    { section_flags::LNK_NRELOC_OVFL,        "LNK_NRELOC_OVFL",        "Extended relocations" },
    { section_flags::MEM_DISCARDABLE,        "MEM_DISCARDABLE",        "Can be discarded" },
    { section_flags::MEM_NOT_CACHED,         "MEM_NOT_CACHED",         "Cannot be cached" },
    { section_flags::MEM_NOT_PAGED,          "MEM_NOT_PAGED",          "Not pageable" },
    { section_flags::MEM_SHARED,             "MEM_SHARED",             "Can be shared" },
    { section_flags::MEM_EXECUTE,            "MEM_EXECUTE",            "Executable" },
    { section_flags::MEM_READ,               "MEM_READ",               "Readable" },
    { section_flags::MEM_WRITE,              "MEM_WRITE",              "Writable" },
}};

inline constexpr std::size_t section_flags_table_size = section_flags_table.size();

struct AlignmentInfo {
    std::uint32_t flag{0};
    std::uint32_t bytes{0};
    const char* name{""};
};

inline constexpr std::array<AlignmentInfo, 14> alignment_table{{
    { section_flags::ALIGN_1BYTES,    1u,    "ALIGN_1BYTES" },
    { section_flags::ALIGN_2BYTES,    2u,    "ALIGN_2BYTES" },
    { section_flags::ALIGN_4BYTES,    4u,    "ALIGN_4BYTES" },
    { section_flags::ALIGN_8BYTES,    8u,    "ALIGN_8BYTES" },
    { section_flags::ALIGN_16BYTES,   16u,   "ALIGN_16BYTES" },
    { section_flags::ALIGN_32BYTES,   32u,   "ALIGN_32BYTES" },
    { section_flags::ALIGN_64BYTES,   64u,   "ALIGN_64BYTES" },
    { section_flags::ALIGN_128BYTES,  128u,  "ALIGN_128BYTES" },
    { section_flags::ALIGN_256BYTES,  256u,  "ALIGN_256BYTES" },
    { section_flags::ALIGN_512BYTES,  512u,  "ALIGN_512BYTES" },
    { section_flags::ALIGN_1024BYTES, 1024u, "ALIGN_1024BYTES" },
    { section_flags::ALIGN_2048BYTES, 2048u, "ALIGN_2048BYTES" },
    { section_flags::ALIGN_4096BYTES, 4096u, "ALIGN_4096BYTES" },
    { section_flags::ALIGN_8192BYTES, 8192u, "ALIGN_8192BYTES" },
}};

inline constexpr std::size_t alignment_table_size = alignment_table.size();

[[nodiscard]] constexpr const AlignmentInfo* get_section_alignment_info(std::uint32_t flags) noexcept {
    const std::uint32_t align_bits = flags & section_flags::ALIGN_MASK;
    for (const AlignmentInfo& info : alignment_table) {
        if (info.flag == align_bits) {
            return &info;
        }
    }
    return nullptr;
}

[[nodiscard]] constexpr std::uint32_t get_section_alignment_bytes(std::uint32_t flags) noexcept {
    const AlignmentInfo* info = get_section_alignment_info(flags);
    return info != nullptr ? info->bytes : 0u;
}

[[nodiscard]] inline std::string get_section_flags_string(std::uint32_t flags) {
    std::string result{};
    for (const SectionFlagInfo& info : section_flags_table) {
        if ((flags & info.flag) != 0u) {
            if (!result.empty()) {
                result += " | ";
            }
            result += info.name;
        }
    }
    if (const AlignmentInfo* align_info = get_section_alignment_info(flags); align_info != nullptr) {
        if (!result.empty()) {
            result += " | ";
        }
        result += align_info->name;
    }
    return result.empty() ? std::string("NONE") : result;
}

template <typename Func>
void for_each_section_flag(std::uint32_t flags, Func&& func) {
    for (const SectionFlagInfo& info : section_flags_table) {
        if ((flags & info.flag) != 0u) {
            func(info);
        }
    }
}

[[nodiscard]] constexpr bool is_section_executable(std::uint32_t flags) noexcept {
    return (flags & section_flags::MEM_EXECUTE) != 0u;
}

[[nodiscard]] constexpr bool is_section_readable(std::uint32_t flags) noexcept {
    return (flags & section_flags::MEM_READ) != 0u;
}

[[nodiscard]] constexpr bool is_section_writable(std::uint32_t flags) noexcept {
    return (flags & section_flags::MEM_WRITE) != 0u;
}

} // namespace pe
#endif //PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP