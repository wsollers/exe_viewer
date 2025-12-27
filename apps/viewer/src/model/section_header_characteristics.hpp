//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP
#define PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP
namespace pe {

// Section header characteristics flags
namespace section_flags {
    constexpr uint32_t RESERVED_0001          = 0x00000001;  // Reserved for future use
    constexpr uint32_t RESERVED_0002          = 0x00000002;  // Reserved for future use
    constexpr uint32_t RESERVED_0004          = 0x00000004;  // Reserved for future use
    constexpr uint32_t TYPE_NO_PAD            = 0x00000008;  // Section should not be padded (obsolete, use ALIGN_1BYTES)
    constexpr uint32_t RESERVED_0010          = 0x00000010;  // Reserved for future use
    constexpr uint32_t CNT_CODE               = 0x00000020;  // Section contains executable code
    constexpr uint32_t CNT_INITIALIZED_DATA   = 0x00000040;  // Section contains initialized data
    constexpr uint32_t CNT_UNINITIALIZED_DATA = 0x00000080;  // Section contains uninitialized data (BSS)
    constexpr uint32_t LNK_OTHER              = 0x00000100;  // Reserved for future use
    constexpr uint32_t LNK_INFO               = 0x00000200;  // Section contains comments or other info (.drectve)
    constexpr uint32_t RESERVED_0400          = 0x00000400;  // Reserved for future use
    constexpr uint32_t LNK_REMOVE             = 0x00000800;  // Section will not become part of image (object only)
    constexpr uint32_t LNK_COMDAT             = 0x00001000;  // Section contains COMDAT data (object only)
    constexpr uint32_t GPREL                  = 0x00008000;  // Section contains data referenced through GP
    constexpr uint32_t MEM_PURGEABLE          = 0x00020000;  // Reserved for future use
    constexpr uint32_t MEM_16BIT              = 0x00020000;  // Reserved for future use (same as PURGEABLE)
    constexpr uint32_t MEM_LOCKED             = 0x00040000;  // Reserved for future use
    constexpr uint32_t MEM_PRELOAD            = 0x00080000;  // Reserved for future use

    // Alignment flags (object files only)
    constexpr uint32_t ALIGN_1BYTES           = 0x00100000;  // Align data on 1-byte boundary
    constexpr uint32_t ALIGN_2BYTES           = 0x00200000;  // Align data on 2-byte boundary
    constexpr uint32_t ALIGN_4BYTES           = 0x00300000;  // Align data on 4-byte boundary
    constexpr uint32_t ALIGN_8BYTES           = 0x00400000;  // Align data on 8-byte boundary
    constexpr uint32_t ALIGN_16BYTES          = 0x00500000;  // Align data on 16-byte boundary
    constexpr uint32_t ALIGN_32BYTES          = 0x00600000;  // Align data on 32-byte boundary
    constexpr uint32_t ALIGN_64BYTES          = 0x00700000;  // Align data on 64-byte boundary
    constexpr uint32_t ALIGN_128BYTES         = 0x00800000;  // Align data on 128-byte boundary
    constexpr uint32_t ALIGN_256BYTES         = 0x00900000;  // Align data on 256-byte boundary
    constexpr uint32_t ALIGN_512BYTES         = 0x00A00000;  // Align data on 512-byte boundary
    constexpr uint32_t ALIGN_1024BYTES        = 0x00B00000;  // Align data on 1024-byte boundary
    constexpr uint32_t ALIGN_2048BYTES        = 0x00C00000;  // Align data on 2048-byte boundary
    constexpr uint32_t ALIGN_4096BYTES        = 0x00D00000;  // Align data on 4096-byte boundary
    constexpr uint32_t ALIGN_8192BYTES        = 0x00E00000;  // Align data on 8192-byte boundary
    constexpr uint32_t ALIGN_MASK             = 0x00F00000;  // Mask for alignment value

    constexpr uint32_t LNK_NRELOC_OVFL        = 0x01000000;  // Section contains extended relocations
    constexpr uint32_t MEM_DISCARDABLE        = 0x02000000;  // Section can be discarded as needed
    constexpr uint32_t MEM_NOT_CACHED         = 0x04000000;  // Section cannot be cached
    constexpr uint32_t MEM_NOT_PAGED          = 0x08000000;  // Section is not pageable
    constexpr uint32_t MEM_SHARED             = 0x10000000;  // Section can be shared in memory
    constexpr uint32_t MEM_EXECUTE            = 0x20000000;  // Section can be executed as code
    constexpr uint32_t MEM_READ               = 0x40000000;  // Section can be read
    constexpr uint32_t MEM_WRITE              = 0x80000000;  // Section can be written to
}

struct SectionFlagInfo {
    uint32_t flag;
    const char* name;
    const char* description;
};

constexpr SectionFlagInfo section_flags_table[] = {
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
};

constexpr size_t section_flags_table_size = sizeof(section_flags_table) / sizeof(section_flags_table[0]);

struct AlignmentInfo {
    uint32_t flag;
    uint32_t bytes;
    const char* name;
};

constexpr AlignmentInfo alignment_table[] = {
    { section_flags::ALIGN_1BYTES,    1,    "ALIGN_1BYTES" },
    { section_flags::ALIGN_2BYTES,    2,    "ALIGN_2BYTES" },
    { section_flags::ALIGN_4BYTES,    4,    "ALIGN_4BYTES" },
    { section_flags::ALIGN_8BYTES,    8,    "ALIGN_8BYTES" },
    { section_flags::ALIGN_16BYTES,   16,   "ALIGN_16BYTES" },
    { section_flags::ALIGN_32B
#endif //PEELF_EXPLORER_SECTION_HEADER_CHARACTERISTICS_HPP