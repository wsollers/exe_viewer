#include "binary_model.hpp"
#include "pe_model.hpp"
#include "pe_parser.hpp"

#include <peelf/error.hpp>

#include <fstream>
#include <utility>

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
        editable_image_.reset();
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
            const bool loaded = load_pe(path);
            if (loaded) {
                if (auto editable = peelf::PagedBinaryImage::open(path)) {
                    editable_image_ = std::move(*editable);
                }
            }
            return loaded;
        }

        // ELF -> identity from the unified image.
        if (image_ && image_->format() == peelf::Format::ELF) {
            const bool loaded = load_elf(path);
            if (loaded) {
                if (auto editable = peelf::PagedBinaryImage::open(path)) {
                    editable_image_ = std::move(*editable);
                }
            }
            return loaded;
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

        sections_.clear();
        for (const auto& s : image_->sections()) {
            std::uint32_t flags = 0;
            if (s.readable)   flags |= 0x4;
            if (s.writable)   flags |= 0x2;
            if (s.executable) flags |= 0x1;
            sections_.push_back(SectionInfo{
                .name = s.name,
                .address = s.virtual_address,
                .size = s.virtual_size,
                .flags = flags
            });
        }

        return true;
    }

    peelf::Result<std::vector<std::uint8_t>> BinaryModel::read_effective_bytes(std::uint64_t offset,
                                                                               std::uint64_t size) const {
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->read_effective(offset, size);
    }

    peelf::Result<void> BinaryModel::apply_patch_bytes(std::uint64_t offset,
                                                       std::span<const std::uint8_t> bytes,
                                                       std::string label) {
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->apply_patch(offset, bytes, std::move(label));
    }

    peelf::Result<void> BinaryModel::undo_patch() {
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->undo();
    }

    peelf::Result<void> BinaryModel::redo_patch() {
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->redo();
    }

    peelf::Result<void> BinaryModel::save_patched_as(const std::filesystem::path& output_path,
                                                     bool overwrite) const {
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->write_effective_to(output_path, overwrite);
    }

    std::vector<peelf::PatchInterval> BinaryModel::changed_intervals() const {
        if (!editable_image_) {
            return {};
        }
        return editable_image_->changed_intervals();
    }

} // namespace viewer
