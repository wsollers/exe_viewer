#include "binary_model.hpp"
#include "pe_model.hpp"
#include "pe_parser.hpp"

#include <fstream>

namespace viewer {

    bool BinaryModel::load_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;

        bytes_ = std::vector<std::uint8_t>(
            std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>()
        );

        if (bytes_.size() < 2) {
            format_ = BinaryFormat::None;
            pe_.reset();
            sections_.clear();
            return false;
        }

        // PE magic: MZ
        if (bytes_[0] == 'M' && bytes_[1] == 'Z') {
            return load_pe(path);
        }

        format_ = BinaryFormat::None;
        pe_.reset();
        sections_.clear();
        return false;
    }

    bool BinaryModel::load_pe(const std::string& path) {
        PeModel pe_model;
        PeParseResult result = PeParser::parse(bytes_, pe_model);
        if (!result.success) {
            format_ = BinaryFormat::None;
            pe_.reset();
            sections_.clear();
            return false;
        }

        format_ = BinaryFormat::PE;
        pe_ = std::make_unique<PeModel>(std::move(pe_model));

        file_info_.path = path;
        file_info_.format_str = "PE";
        file_info_.arch_str = result.is_64 ? "x64" : "x86";
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = result.entry_point_va;
        file_info_.flags = result.flags;

        sections_.clear();
        for (const auto& s : pe_->sections) {
            sections_.push_back(SectionInfo{
                .name = s.name,
                .address = result.image_base + s.virtual_address,
                .size = s.virtual_size,
                .flags = s.characteristics
            });
        }

        return true;
    }

} // namespace viewer