#include <cstring>  // std::memcpy
#include <algorithm>

#include "pe_parser.hpp"
#include "pe_machine_types.hpp"
#include "pe_characteristics.hpp"
#include "pe_optional_image.hpp"

namespace viewer {

// PE constants
static constexpr std::uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D; // 'MZ'
static constexpr std::uint32_t IMAGE_NT_SIGNATURE  = 0x00004550; // 'PE\0\0'

static constexpr std::uint16_t IMAGE_FILE_MACHINE_I386   = 0x014c;
static constexpr std::uint16_t IMAGE_FILE_MACHINE_AMD64  = 0x8664;

static constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
static constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

static constexpr std::uint16_t IMAGE_FILE_DLL              = 0x2000;
static constexpr std::uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20;

static constexpr std::uint32_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

static constexpr std::uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
static constexpr std::uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

constexpr uint16_t DOS_MAGIC = 0x5A4D;      // "MZ"
constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"

// data structures (packed)
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER_ {
    uint16_t e_magic;       // 0x00: Magic number ("MZ" = 0x5A4D)
    uint16_t e_cblp;        // 0x02: Bytes on last page of file
    uint16_t e_cp;          // 0x04: Pages in file
    uint16_t e_crlc;        // 0x06: Relocations
    uint16_t e_cparhdr;     // 0x08: Size of header in paragraphs
    uint16_t e_minalloc;    // 0x0A: Minimum extra paragraphs needed
    uint16_t e_maxalloc;    // 0x0C: Maximum extra paragraphs needed
    uint16_t e_ss;          // 0x0E: Initial (relative) SS value
    uint16_t e_sp;          // 0x10: Initial SP value
    uint16_t e_csum;        // 0x12: Checksum
    uint16_t e_ip;          // 0x14: Initial IP value
    uint16_t e_cs;          // 0x16: Initial (relative) CS value
    uint16_t e_lfarlc;      // 0x18: File address of relocation table
    uint16_t e_ovno;        // 0x1A: Overlay number
    uint16_t e_res[4];      // 0x1C: Reserved words
    uint16_t e_oemid;       // 0x24: OEM identifier
    uint16_t e_oeminfo;     // 0x26: OEM information
    uint16_t e_res2[10];    // 0x28: Reserved words
    int32_t  e_lfanew;      // 0x3C: File address of PE header
};

struct IMAGE_FILE_HEADER_ {
    std::uint16_t Machine;              // Target CPU type (e.g., x86, x64, ARM)
    std::uint16_t NumberOfSections;     // Number of section table entries
    std::uint32_t TimeDateStamp;        // Seconds since 1970-01-01 00:00:00
    std::uint32_t PointerToSymbolTable; // File offset to COFF symbol table
    std::uint32_t NumberOfSymbols;      // Number of COFF symbol entries
    std::uint16_t SizeOfOptionalHeader; // Size of optional header in bytes
    std::uint16_t Characteristics;      // File attribute flags
};

struct IMAGE_DATA_DIRECTORY_ {
    std::uint32_t VirtualAddress;       // RVA of the table
    std::uint32_t Size;                 // Size of the table in bytes
};

struct IMAGE_OPTIONAL_HEADER32_ {
    std::uint16_t Magic;                       // PE32 (0x10B) or PE32+ (0x20B)
    std::uint8_t  MajorLinkerVersion;          // Linker major version
    std::uint8_t  MinorLinkerVersion;          // Linker minor version
    std::uint32_t SizeOfCode;                  // Sum of all code sections
    std::uint32_t SizeOfInitializedData;       // Sum of all initialized data sections
    std::uint32_t SizeOfUninitializedData;     // Sum of all BSS sections
    std::uint32_t AddressOfEntryPoint;         // RVA of entry point function
    std::uint32_t BaseOfCode;                  // RVA of code section start
    std::uint32_t BaseOfData;                  // RVA of data section start (PE32 only)
    std::uint32_t ImageBase;                   // Preferred load address
    std::uint32_t SectionAlignment;            // Section alignment in memory (bytes)
    std::uint32_t FileAlignment;               // Section alignment on disk (bytes)
    std::uint16_t MajorOperatingSystemVersion; // Required OS major version
    std::uint16_t MinorOperatingSystemVersion; // Required OS minor version
    std::uint16_t MajorImageVersion;           // Image major version (user-defined)
    std::uint16_t MinorImageVersion;           // Image minor version (user-defined)
    std::uint16_t MajorSubsystemVersion;       // Required subsystem major version
    std::uint16_t MinorSubsystemVersion;       // Required subsystem minor version
    std::uint32_t Win32VersionValue;           // Reserved, must be zero
    std::uint32_t SizeOfImage;                 // Total image size in memory (bytes)
    std::uint32_t SizeOfHeaders;               // Size of all headers (bytes)
    std::uint32_t CheckSum;                    // Image checksum (required for drivers)
    std::uint16_t Subsystem;                   // Target subsystem (GUI, CUI, etc.)
    std::uint16_t DllCharacteristics;          // Security flags (ASLR, DEP, CFG, etc.)
    std::uint32_t SizeOfStackReserve;          // Stack reserve size (bytes)
    std::uint32_t SizeOfStackCommit;           // Stack commit size (bytes)
    std::uint32_t SizeOfHeapReserve;           // Heap reserve size (bytes)
    std::uint32_t SizeOfHeapCommit;            // Heap commit size (bytes)
    std::uint32_t LoaderFlags;                 // Reserved, must be zero
    std::uint32_t NumberOfRvaAndSizes;         // Number of data directory entries
    IMAGE_DATA_DIRECTORY_ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64_ {
    std::uint16_t Magic;                       // PE32 (0x10B) or PE32+ (0x20B)
    std::uint8_t  MajorLinkerVersion;          // Linker major version
    std::uint8_t  MinorLinkerVersion;          // Linker minor version
    std::uint32_t SizeOfCode;                  // Sum of all code sections
    std::uint32_t SizeOfInitializedData;       // Sum of all initialized data sections
    std::uint32_t SizeOfUninitializedData;     // Sum of all BSS sections
    std::uint32_t AddressOfEntryPoint;         // RVA of entry point function
    std::uint32_t BaseOfCode;                  // RVA of code section start
    std::uint64_t ImageBase;                   // Preferred load address
    std::uint32_t SectionAlignment;            // Section alignment in memory (bytes)
    std::uint32_t FileAlignment;               // Section alignment on disk (bytes)
    std::uint16_t MajorOperatingSystemVersion; // Required OS major version
    std::uint16_t MinorOperatingSystemVersion; // Required OS minor version
    std::uint16_t MajorImageVersion;           // Image major version (user-defined)
    std::uint16_t MinorImageVersion;           // Image minor version (user-defined)
    std::uint16_t MajorSubsystemVersion;       // Required subsystem major version
    std::uint16_t MinorSubsystemVersion;       // Required subsystem minor version
    std::uint32_t Win32VersionValue;           // Reserved, must be zero
    std::uint32_t SizeOfImage;                 // Total image size in memory (bytes)
    std::uint32_t SizeOfHeaders;               // Size of all headers (bytes)
    std::uint32_t CheckSum;                    // Image checksum (required for drivers)
    std::uint16_t Subsystem;                   // Target subsystem (GUI, CUI, etc.)
    std::uint16_t DllCharacteristics;          // Security flags (ASLR, DEP, CFG, etc.)
    std::uint64_t SizeOfStackReserve;          // Stack reserve size (bytes)
    std::uint64_t SizeOfStackCommit;           // Stack commit size (bytes)
    std::uint64_t SizeOfHeapReserve;           // Heap reserve size (bytes)
    std::uint64_t SizeOfHeapCommit;            // Heap commit size (bytes)
    std::uint32_t LoaderFlags;                 // Reserved, must be zero
    std::uint32_t NumberOfRvaAndSizes;         // Number of data directory entries
    IMAGE_DATA_DIRECTORY_ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_SECTION_HEADER_ {
    char          Name[8];              // Section name (null-padded, not null-terminated if 8 chars)
    std::uint32_t VirtualSize;          // Size in memory (before padding)
    std::uint32_t VirtualAddress;       // RVA of section start
    std::uint32_t SizeOfRawData;        // Size on disk (aligned to FileAlignment)
    std::uint32_t PointerToRawData;     // File offset to section data
    std::uint32_t PointerToRelocations; // File offset to relocations (object files)
    std::uint32_t PointerToLinenumbers; // File offset to line numbers (deprecated)
    std::uint16_t NumberOfRelocations;  // Number of relocation entries
    std::uint16_t NumberOfLinenumbers;  // Number of line number entries (deprecated)
    std::uint32_t Characteristics;      // Section flags (RWX, code, data, etc.)
};

struct IMAGE_IMPORT_DESCRIPTOR_ {
    std::uint32_t OriginalFirstThunk;   // RVA to Import Name Table (INT)
    std::uint32_t TimeDateStamp;        // Timestamp if bound, 0 otherwise
    std::uint32_t ForwarderChain;       // Index of first forwarder reference
    std::uint32_t Name;                 // RVA to DLL name string
    std::uint32_t FirstThunk;           // RVA to Import Address Table (IAT)
};

struct IMAGE_EXPORT_DIRECTORY_ {
    std::uint32_t Characteristics;      // Reserved, must be zero
    std::uint32_t TimeDateStamp;        // Export table creation time
    std::uint16_t MajorVersion;         // User-defined major version
    std::uint16_t MinorVersion;         // User-defined minor version
    std::uint32_t Name;                 // RVA to DLL name string
    std::uint32_t Base;                 // Starting ordinal number
    std::uint32_t NumberOfFunctions;    // Number of entries in EAT
    std::uint32_t NumberOfNames;        // Number of named exports
    std::uint32_t AddressOfFunctions;   // RVA to Export Address Table (EAT)
    std::uint32_t AddressOfNames;       // RVA to Export Name Table
    std::uint32_t AddressOfNameOrdinals;// RVA to ordinal table
};
#pragma pack(pop)

PeParser::PeParser(const std::vector<std::uint8_t>& data, PeModel& out)
    : data_(data), out_(out) {}

template<typename T>
bool PeParser::read(std::uint32_t offset, T& out) const {
    if (offset > data_.size() || data_.size() - offset < sizeof(T))
        return false;
    std::memcpy(&out, data_.data() + offset, sizeof(T));
    return true;
}

PeParseResult PeParser::parse(const std::vector<std::uint8_t>& data, PeModel& out) {
    PeParser parser(data, out);
    std::uint32_t nt_offset = 0;

    if (!parser.parse_dos_header(nt_offset)) return parser.result_;
    if (!parser.parse_nt_headers(nt_offset)) return parser.result_;
    if (!parser.parse_optional_header(nt_offset)) return parser.result_;
    if (!parser.parse_section_headers(nt_offset)) return parser.result_;
    if (!parser.parse_imports()) {}  // non-fatal
    if (!parser.parse_exports()) {}  // non-fatal

    parser.result_.success = true;
    return parser.result_;
}

bool PeParser::parse_dos_header(std::uint32_t& nt_offset) {
    IMAGE_DOS_HEADER_ dos{};
    if (!read(0, dos))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    nt_offset = dos.e_lfanew;
    return true;
}

bool PeParser::parse_nt_headers(std::uint32_t nt_offset) {
    std::uint32_t signature = 0;
    if (!read(nt_offset, signature))
        return false;
    if (signature != IMAGE_NT_SIGNATURE)
        return false;

    IMAGE_FILE_HEADER_ file_hdr{};
    if (!read(nt_offset + 4, file_hdr))
        return false;

    out_.machine = file_hdr.Machine;
    out_.num_sections = file_hdr.NumberOfSections;
    out_.timestamp = file_hdr.TimeDateStamp;

    if (file_hdr.Characteristics & IMAGE_FILE_DLL)
        result_.flags.push_back("DLL");
    if (file_hdr.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        result_.flags.push_back("LargeAddressAware");

    return true;
}

bool PeParser::parse_optional_header(std::uint32_t nt_offset) {
    IMAGE_FILE_HEADER_ file_hdr{};
    if (!read(nt_offset + 4, file_hdr))
        return false;

    std::uint32_t opt_offset = nt_offset + 4 + sizeof(IMAGE_FILE_HEADER_);

    std::uint16_t magic = 0;
    if (!read(opt_offset, magic))
        return false;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32_ opt{};
        if (!read(opt_offset, opt)) return false;

        out_.is_pe32_plus = false;
        out_.image_base = opt.ImageBase;
        out_.entry_point_rva = opt.AddressOfEntryPoint;
        out_.size_of_image = opt.SizeOfImage;
        result_.is_64 = false;
        result_.image_base = opt.ImageBase;
        result_.entry_point_va = opt.ImageBase + opt.AddressOfEntryPoint;

        return parse_data_directories(opt_offset, magic, opt.NumberOfRvaAndSizes);
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64_ opt{};
        if (!read(opt_offset, opt)) return false;

        out_.is_pe32_plus = true;
        out_.image_base = opt.ImageBase;
        out_.entry_point_rva = opt.AddressOfEntryPoint;
        out_.size_of_image = opt.SizeOfImage;
        result_.is_64 = true;
        result_.image_base = opt.ImageBase;
        result_.entry_point_va = opt.ImageBase + opt.AddressOfEntryPoint;

        return parse_data_directories(opt_offset, magic, opt.NumberOfRvaAndSizes);
    }

    return false;
}

bool PeParser::parse_data_directories(std::uint32_t opt_offset,
                                      std::uint16_t magic,
                                      std::uint32_t num_rva_and_sizes) {
    out_.data_directories.clear();

    if (num_rva_and_sizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        num_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    std::uint32_t dir_offset = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        dir_offset = opt_offset + offsetof(IMAGE_OPTIONAL_HEADER32_, DataDirectory);
    } else {
        dir_offset = opt_offset + offsetof(IMAGE_OPTIONAL_HEADER64_, DataDirectory);
    }

    static const char* dir_names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION",
        "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
        "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved"
    };

    for (std::uint32_t i = 0; i < num_rva_and_sizes; ++i) {
        IMAGE_DATA_DIRECTORY_ dir{};
        if (!read(dir_offset + i * sizeof(IMAGE_DATA_DIRECTORY_), dir))
            return false;
        PeDataDirectory dd{};
        dd.name = dir_names[i];
        dd.rva = dir.VirtualAddress;
        dd.size = dir.Size;
        out_.data_directories.push_back(dd);
    }

    return true;
}

bool PeParser::parse_section_headers(std::uint32_t nt_offset) {
    IMAGE_FILE_HEADER_ file_hdr{};
    if (!read(nt_offset + 4, file_hdr))
        return false;

    std::uint32_t opt_offset = nt_offset + 4 + sizeof(IMAGE_FILE_HEADER_);
    std::uint16_t magic = 0;
    if (!read(opt_offset, magic))
        return false;

    std::uint32_t section_table_offset = opt_offset + file_hdr.SizeOfOptionalHeader;

    out_.sections.clear();
    out_.sections.reserve(file_hdr.NumberOfSections);

    for (std::uint32_t i = 0; i < file_hdr.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER_ sh{};
        if (!read(section_table_offset + i * sizeof(IMAGE_SECTION_HEADER_), sh))
            return false;

        PeSectionHeader sec{};
        sec.name = std::string(sh.Name, strnlen(sh.Name, 8));
        sec.virtual_address = sh.VirtualAddress;
        sec.virtual_size = sh.VirtualSize;
        sec.raw_offset = sh.PointerToRawData;
        sec.raw_size = sh.SizeOfRawData;
        sec.characteristics = sh.Characteristics;

        out_.sections.push_back(sec);
    }

    return true;
}

std::uint32_t PeParser::rva_to_file_offset(std::uint32_t rva) const {
    for (const auto& s : out_.sections) {
        std::uint32_t va = s.virtual_address;
        std::uint32_t vs = std::max(s.virtual_size, s.raw_size);
        if (rva >= va && rva < va + vs) {
            std::uint32_t delta = rva - va;
            if (delta < s.raw_size)
                return s.raw_offset + delta;
        }
    }
    return 0;
}

bool PeParser::parse_imports() {
    out_.imports.clear();

    if (out_.data_directories.size() <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return true;

    const auto& dir = out_.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.rva == 0 || dir.size == 0)
        return true;

    std::uint32_t desc_offset = rva_to_file_offset(dir.rva);
    if (desc_offset == 0)
        return false;

    while (true) {
        IMAGE_IMPORT_DESCRIPTOR_ desc{};
        if (!read(desc_offset, desc))
            return false;
        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0)
            break;

        std::uint32_t name_off = rva_to_file_offset(desc.Name);
        if (name_off == 0) break;

        // read DLL name
        std::string dll;
        for (std::uint32_t o = name_off; o < data_.size(); ++o) {
            char c = static_cast<char>(data_[o]);
            if (c == '\0') break;
            dll.push_back(c);
        }

        std::uint32_t oft = rva_to_file_offset(desc.OriginalFirstThunk);
        std::uint32_t ft  = rva_to_file_offset(desc.FirstThunk);

        // 32/64 agnostic thunk parsing
        std::uint32_t thunk_off = oft ? oft : ft;
        if (thunk_off == 0)
            break;

        while (true) {
            if (result_.is_64) {
                std::uint64_t thunk = 0;
                if (!read(thunk_off, thunk))
                    return false;
                if (thunk == 0)
                    break;

                bool is_ordinal = (thunk & (1ull << 63)) != 0;
                if (!is_ordinal) {
                    std::uint32_t hint_name_rva = static_cast<std::uint32_t>(thunk & 0x7FFFFFFF);
                    std::uint32_t hn_off = rva_to_file_offset(hint_name_rva);
                    if (hn_off == 0) break;

                    std::uint16_t hint = 0;
                    if (!read(hn_off, hint))
                        return false;

                    std::string func;
                    for (std::uint32_t o = hn_off + 2; o < data_.size(); ++o) {
                        char c = static_cast<char>(data_[o]);
                        if (c == '\0') break;
                        func.push_back(c);
                    }

                    PeImportEntry e{};
                    e.dll = dll;
                    e.function = func;
                    e.address = result_.image_base + desc.FirstThunk + (thunk_off - (oft ? oft : ft));
                    out_.imports.push_back(std::move(e));
                }
                thunk_off += sizeof(std::uint64_t);
            } else {
                std::uint32_t thunk = 0;
                if (!read(thunk_off, thunk))
                    return false;
                if (thunk == 0)
                    break;

                bool is_ordinal = (thunk & 0x80000000u) != 0;
                if (!is_ordinal) {
                    std::uint32_t hint_name_rva = thunk & 0x7FFFFFFFu;
                    std::uint32_t hn_off = rva_to_file_offset(hint_name_rva);
                    if (hn_off == 0) break;

                    std::uint16_t hint = 0;
                    if (!read(hn_off, hint))
                        return false;

                    std::string func;
                    for (std::uint32_t o = hn_off + 2; o < data_.size(); ++o) {
                        char c = static_cast<char>(data_[o]);
                        if (c == '\0') break;
                        func.push_back(c);
                    }

                    PeImportEntry e{};
                    e.dll = dll;
                    e.function = func;
                    e.address = result_.image_base + desc.FirstThunk + (thunk_off - (oft ? oft : ft));
                    out_.imports.push_back(std::move(e));
                }
                thunk_off += sizeof(std::uint32_t);
            }
        }

        desc_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR_);
    }

    return true;
}

bool PeParser::parse_exports() {
    out_.exports.clear();

    if (out_.data_directories.size() <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return true;

    const auto& dir = out_.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.rva == 0 || dir.size == 0)
        return true;

    std::uint32_t exp_off = rva_to_file_offset(dir.rva);
    if (exp_off == 0)
        return false;

    IMAGE_EXPORT_DIRECTORY_ ed{};
    if (!read(exp_off, ed))
        return false;

    std::uint32_t name_ptrs_off = rva_to_file_offset(ed.AddressOfNames);
    std::uint32_t ordinals_off  = rva_to_file_offset(ed.AddressOfNameOrdinals);
    std::uint32_t func_off      = rva_to_file_offset(ed.AddressOfFunctions);

    if (name_ptrs_off == 0 || ordinals_off == 0 || func_off == 0)
        return false;

    out_.exports.reserve(ed.NumberOfNames);

    for (std::uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        std::uint32_t name_rva = 0;
        if (!read(name_ptrs_off + i * sizeof(std::uint32_t), name_rva))
            return false;

        std::uint16_t ordinal_index = 0;
        if (!read(ordinals_off + i * sizeof(std::uint16_t), ordinal_index))
            return false;

        std::string name;
        std::uint32_t name_off = rva_to_file_offset(name_rva);
        if (name_off == 0) continue;

        for (std::uint32_t o = name_off; o < data_.size(); ++o) {
            char c = static_cast<char>(data_[o]);
            if (c == '\0') break;
            name.push_back(c);
        }

        std::uint32_t func_rva = 0;
        if (!read(func_off + ordinal_index * sizeof(std::uint32_t), func_rva))
            return false;

        PeExportEntry e{};
        e.name = name;
        e.ordinal = ed.Base + ordinal_index;
        e.rva = func_rva;
        out_.exports.push_back(std::move(e));
    }

    return true;
}


    // Calculates the PE checksum (same algorithm as Windows CheckSumMappedFile)
    uint32_t calculate_checksum(const uint8_t* data, size_t size, size_t checksum_offset) {
        uint64_t checksum = 0;

        // Sum all 16-bit words, skipping the checksum field itself
        for (size_t i = 0; i < size; i += 2) {
            // Skip the 4-byte checksum field
            if (i == checksum_offset || i == checksum_offset + 2) {
                continue;
            }

            uint16_t word;
            if (i + 1 < size) {
                word = static_cast<uint16_t>(data[i]) |
                       (static_cast<uint16_t>(data[i + 1]) << 8);
            } else {
                // Odd byte at end
                word = data[i];
            }

            checksum += word;

            // Fold carry bits
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        // Final fold
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

        // Add file size
        return static_cast<uint32_t>(checksum + size);
    }

    // Helper to validate a PE file's checksum
    bool validate_checksum(const uint8_t* data, size_t size) {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER_*>(data);
        if (dos->e_magic != DOS_MAGIC) {
            return false;
        }

        // Get to optional header where checksum lives
        size_t pe_offset = dos->e_lfanew;
        size_t optional_header_offset = pe_offset + 4 + 20;  // Signature + FileHeader
        size_t checksum_offset = optional_header_offset + 64; // CheckSum is at offset 64 in OptionalHeader

        if (checksum_offset + 4 > size) {
            return false;
        }

        uint32_t stored_checksum;
        std::memcpy(&stored_checksum, data + checksum_offset, sizeof(stored_checksum));

        // Zero checksum means not set (valid)
        if (stored_checksum == 0) {
            return true;
        }

        uint32_t calculated = calculate_checksum(data, size, checksum_offset);
        return calculated == stored_checksum;
    }


} // namespace viewer