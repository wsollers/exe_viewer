#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <memory>
#include "pe_model.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/patching.hpp>

namespace viewer {

    enum class BinaryFormat {
        None,
        PE,
        ELF
    };

    struct SectionInfo {
        std::string name;
        std::uint64_t address;
        std::uint64_t size;
        std::uint32_t flags;
    };

    struct FileInfo {
        std::string path;
        std::string format_str;
        std::string arch_str;
        std::uint64_t size_bytes;
        std::uint64_t entry_point;
        std::vector<std::string> flags;
    };

    class PeModel;
    class ElfModel;

    class BinaryModel {
    public:
        BinaryModel() = default;

        bool load_file(const std::string& path);

        bool has_file() const { return format_ != BinaryFormat::None; }
        BinaryFormat format() const { return format_; }

        const FileInfo& file_info() const { return file_info_; }
        const std::vector<std::uint8_t>& bytes() const { return bytes_; }
        const std::vector<SectionInfo>& sections() const { return sections_; }

        const PeModel* pe() const { return pe_.get(); }

        // Unified core image (format-agnostic identity). Non-null once a PE or ELF
        // file parses; the migration target as panels move onto it (ToDo.md P1-6).
        const peelf::IBinaryImage* image() const { return image_.get(); }
        const peelf::PagedBinaryImage* editable_image() const {
            return editable_image_ ? &*editable_image_ : nullptr;
        }

        peelf::Result<std::vector<std::uint8_t>> read_effective_bytes(std::uint64_t offset,
                                                                      std::uint64_t size) const;
        peelf::Result<void> apply_patch_bytes(std::uint64_t offset,
                                              std::span<const std::uint8_t> bytes,
                                              std::string label);
        peelf::Result<void> undo_patch();
        peelf::Result<void> redo_patch();
        peelf::Result<void> save_patched_as(const std::filesystem::path& output_path,
                                            bool overwrite = false) const;
        std::vector<peelf::PatchInterval> changed_intervals() const;

    private:
        BinaryFormat format_ = BinaryFormat::None;
        FileInfo file_info_;
        std::vector<std::uint8_t> bytes_;
        std::vector<SectionInfo> sections_;
        std::unique_ptr<PeModel> pe_;
        std::unique_ptr<peelf::IBinaryImage> image_;
        std::optional<peelf::PagedBinaryImage> editable_image_;

        bool load_pe(const std::string& path);
        bool load_elf(const std::string& path);
    };

} // namespace viewer
