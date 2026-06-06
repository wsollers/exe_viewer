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

        // Reset previous state.
        format_ = BinaryFormat::None;
        pe_.reset();
        image_.reset();
        sections_.clear();

        if (bytes_.size() < 2) {
            return false;
        }

        // Unified core image: format-agnostic identity for PE and ELF. Independent
        // of the legacy PE path below (which still feeds the PE-specific panels);
        // this is the migration target (ToDo.md P1-6).
        if (auto parsed = peelf::parse_image(bytes_)) {
            image_ = std::move(*parsed);
        }

        // PE (MZ) -> legacy PE model, which drives the PE-specific panels.
        if (bytes_[0] == 'M' && bytes_[1] == 'Z') {
            return load_pe(path);
        }

        // ELF -> identity from the unified image.
        if (image_ && image_->format() == peelf::Format::ELF) {
            return load_elf(path);
        }

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

    bool BinaryModel::load_elf(const std::string& path) {
        if (!image_ || image_->format() != peelf::Format::ELF) {
            return false;
        }

        format_ = BinaryFormat::ELF;

        file_info_.path = path;
        file_info_.format_str = std::string(peelf::to_string(image_->format()));
        file_info_.arch_str = std::string(peelf::to_string(image_->architecture()));
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = image_->entry_point();

        file_info_.flags.clear();
        file_info_.flags.push_back(std::string(peelf::to_string(image_->kind())));
        file_info_.flags.push_back(image_->is_64bit() ? "64-bit" : "32-bit");
        file_info_.flags.push_back(std::string(peelf::to_string(image_->endianness())));

        // ELF sections are populated in Phase 2 (P2-1); leave empty for now.
        sections_.clear();

        return true;
    }

} // namespace viewer