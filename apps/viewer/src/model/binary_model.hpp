#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "pe_model.hpp"

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

    private:
        BinaryFormat format_ = BinaryFormat::None;
        FileInfo file_info_;
        std::vector<std::uint8_t> bytes_;
        std::vector<SectionInfo> sections_;
        std::unique_ptr<PeModel> pe_;

        bool load_pe(const std::string& path);
    };

} // namespace viewer