#include "pe_parser.hpp"
#include <cstring>  // std::memcpy
#include <algorithm>

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

// data structures (packed)
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER_ {
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::uint16_t e_res[4];
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::uint16_t e_res2[10];
    std::uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER_ {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY_ {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32_ {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve;
    std::uint32_t SizeOfStackCommit;
    std::uint32_t SizeOfHeapReserve;
    std::uint32_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64_ {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_SECTION_HEADER_ {
    char          Name[8];
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR_ {
    std::uint32_t OriginalFirstThunk;
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;
    std::uint32_t FirstThunk;
};

struct IMAGE_EXPORT_DIRECTORY_ {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;
    std::uint32_t Base;
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;
    std::uint32_t AddressOfNames;
    std::uint32_t AddressOfNameOrdinals;
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
                                      std::uint16_t num_rva_and_sizes) {
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

} // namespace viewer