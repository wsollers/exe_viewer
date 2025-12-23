#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "pe_model.hpp"

namespace viewer {

    struct PeParseResult {
        bool success = false;
        bool is_64 = false;
        std::uint64_t image_base = 0;
        std::uint64_t entry_point_va = 0;
        std::vector<std::string> flags;
    };

    class PeParser {
    public:
        static PeParseResult parse(const std::vector<std::uint8_t>& data, PeModel& out);

    private:
        PeParser(const std::vector<std::uint8_t>& data, PeModel& out);

        const std::vector<std::uint8_t>& data_;
        PeModel& out_;
        PeParseResult result_;

        bool parse_dos_header(std::uint32_t& nt_offset);
        bool parse_nt_headers(std::uint32_t nt_offset);
        bool parse_optional_header(std::uint32_t nt_offset);
        bool parse_section_headers(std::uint32_t nt_offset);
        bool parse_data_directories(std::uint32_t opt_offset, std::uint16_t magic,
                                    std::uint16_t num_rva_and_sizes);
        bool parse_imports();
        bool parse_exports();

        std::uint32_t rva_to_file_offset(std::uint32_t rva) const;

        template<typename T>
        bool read(std::uint32_t offset, T& out) const;
    };

} // namespace viewer