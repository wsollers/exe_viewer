#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace viewer {

    struct PeDataDirectory {
        std::string name;
        std::uint32_t rva = 0;
        std::uint32_t size = 0;
    };

    struct PeImportEntry {
        std::string dll;
        std::string function;
        std::uint64_t address = 0;   // IAT VA
    };

    struct PeExportEntry {
        std::string name;
        std::uint32_t ordinal = 0;
        std::uint32_t rva = 0;
    };

    struct PeSectionHeader {
        std::string name;
        std::uint32_t virtual_address = 0;
        std::uint32_t virtual_size = 0;
        std::uint32_t raw_offset = 0;
        std::uint32_t raw_size = 0;
        std::uint32_t characteristics = 0;
    };

    class PeModel {
    public:
        std::uint16_t machine = 0;
        std::uint16_t num_sections = 0;
        std::uint32_t timestamp = 0;
        std::uint64_t image_base = 0;
        std::uint32_t entry_point_rva = 0;
        std::uint32_t size_of_image = 0;
        bool is_pe32_plus = false;

        std::vector<PeDataDirectory> data_directories;
        std::vector<PeSectionHeader> sections;
        std::vector<PeImportEntry> imports;
        std::vector<PeExportEntry> exports;
    };

} // namespace viewer