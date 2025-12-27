#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <cstring>

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
        std::string forwarder;       // Non-empty if forwarded
        bool is_forwarded = false;
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
        // File header fields
        std::uint16_t machine = 0;
        std::uint16_t num_sections = 0;
        std::uint32_t timestamp = 0;
        std::uint16_t characteristics = 0;

        // Optional header fields
        std::uint64_t image_base = 0;
        std::uint32_t entry_point_rva = 0;
        std::uint32_t size_of_image = 0;
        std::uint32_t size_of_headers = 0;
        std::uint32_t section_alignment = 0;
        std::uint32_t file_alignment = 0;
        std::uint16_t subsystem = 0;
        std::uint16_t dll_characteristics = 0;
        std::uint32_t checksum = 0;
        bool is_pe32_plus = false;

        // Parsed structures
        std::vector<PeDataDirectory> data_directories;
        std::vector<PeSectionHeader> sections;
        std::vector<PeImportEntry> imports;
        std::vector<PeExportEntry> exports;

        // Raw data reference (set by parser)
        const std::uint8_t* raw_data = nullptr;
        std::size_t raw_size = 0;

        // =====================================================================
        // Address Conversion
        // =====================================================================

        // Convert RVA to file offset
        [[nodiscard]] std::optional<std::size_t> rva_to_offset(std::uint32_t rva) const {
            for (const auto& section : sections) {
                std::uint32_t section_end = section.virtual_address +
                    std::max(section.virtual_size, section.raw_size);

                if (rva >= section.virtual_address && rva < section_end) {
                    std::uint32_t offset_in_section = rva - section.virtual_address;

                    // Ensure within raw data bounds
                    if (offset_in_section < section.raw_size) {
                        return section.raw_offset + offset_in_section;
                    }
                    return std::nullopt;  // In virtual padding (uninitialized data)
                }
            }

            // RVA might be in headers (before first section)
            if (!sections.empty() && rva < sections[0].virtual_address) {
                return static_cast<std::size_t>(rva);
            }

            return std::nullopt;
        }

        // Convert file offset to RVA
        [[nodiscard]] std::optional<std::uint32_t> offset_to_rva(std::size_t offset) const {
            for (const auto& section : sections) {
                if (offset >= section.raw_offset &&
                    offset < section.raw_offset + section.raw_size) {
                    std::uint32_t offset_in_section = static_cast<std::uint32_t>(offset - section.raw_offset);
                    return section.virtual_address + offset_in_section;
                }
            }

            // Check if in headers
            std::uint32_t first_section_offset = sections.empty() ?
                static_cast<std::uint32_t>(raw_size) : sections[0].raw_offset;

            if (offset < first_section_offset) {
                return static_cast<std::uint32_t>(offset);
            }

            return std::nullopt;
        }

        // Convert RVA to VA
        [[nodiscard]] std::uint64_t rva_to_va(std::uint32_t rva) const {
            return image_base + rva;
        }

        // Convert VA to RVA
        [[nodiscard]] std::optional<std::uint32_t> va_to_rva(std::uint64_t va) const {
            if (va < image_base) return std::nullopt;

            std::uint64_t rva = va - image_base;
            if (rva > 0xFFFFFFFF) return std::nullopt;

            return static_cast<std::uint32_t>(rva);
        }

        // Convert VA to file offset
        [[nodiscard]] std::optional<std::size_t> va_to_offset(std::uint64_t va) const {
            auto rva = va_to_rva(va);
            if (!rva) return std::nullopt;
            return rva_to_offset(*rva);
        }

        // Convert file offset to VA
        [[nodiscard]] std::optional<std::uint64_t> offset_to_va(std::size_t offset) const {
            auto rva = offset_to_rva(offset);
            if (!rva) return std::nullopt;
            return rva_to_va(*rva);
        }

        // =====================================================================
        // Entry Point
        // =====================================================================

        [[nodiscard]] std::uint64_t entry_point_va() const {
            return rva_to_va(entry_point_rva);
        }

        [[nodiscard]] std::optional<std::size_t> entry_point_offset() const {
            return rva_to_offset(entry_point_rva);
        }

        // =====================================================================
        // Section Utilities
        // =====================================================================

        [[nodiscard]] const PeSectionHeader* section_from_rva(std::uint32_t rva) const {
            for (const auto& section : sections) {
                std::uint32_t section_end = section.virtual_address +
                    std::max(section.virtual_size, section.raw_size);

                if (rva >= section.virtual_address && rva < section_end) {
                    return &section;
                }
            }
            return nullptr;
        }

        [[nodiscard]] const PeSectionHeader* section_from_va(std::uint64_t va) const {
            auto rva = va_to_rva(va);
            if (!rva) return nullptr;
            return section_from_rva(*rva);
        }

        [[nodiscard]] const PeSectionHeader* section_from_offset(std::size_t offset) const {
            for (const auto& section : sections) {
                if (offset >= section.raw_offset &&
                    offset < section.raw_offset + section.raw_size) {
                    return &section;
                }
            }
            return nullptr;
        }

        [[nodiscard]] const PeSectionHeader* section_by_name(const std::string& name) const {
            for (const auto& section : sections) {
                if (section.name == name) {
                    return &section;
                }
            }
            return nullptr;
        }

        [[nodiscard]] const PeSectionHeader* entry_point_section() const {
            return section_from_rva(entry_point_rva);
        }

        [[nodiscard]] const PeSectionHeader* code_section() const {
            // Try to find .text section first
            if (auto* text = section_by_name(".text")) {
                return text;
            }
            // Fall back to first executable section
            for (const auto& section : sections) {
                if (section.characteristics & 0x20000000) {  // IMAGE_SCN_MEM_EXECUTE
                    return &section;
                }
            }
            return nullptr;
        }

        // =====================================================================
        // Data Access
        // =====================================================================

        [[nodiscard]] const std::uint8_t* data_at_offset(std::size_t offset, std::size_t size = 1) const {
            if (!raw_data || offset + size > raw_size) return nullptr;
            return raw_data + offset;
        }

        [[nodiscard]] const std::uint8_t* data_at_rva(std::uint32_t rva, std::size_t size = 1) const {
            auto offset = rva_to_offset(rva);
            if (!offset) return nullptr;
            return data_at_offset(*offset, size);
        }

        [[nodiscard]] const std::uint8_t* data_at_va(std::uint64_t va, std::size_t size = 1) const {
            auto offset = va_to_offset(va);
            if (!offset) return nullptr;
            return data_at_offset(*offset, size);
        }

        template<typename T>
        [[nodiscard]] const T* read_at_offset(std::size_t offset) const {
            if (!raw_data || offset + sizeof(T) > raw_size) return nullptr;
            return reinterpret_cast<const T*>(raw_data + offset);
        }

        template<typename T>
        [[nodiscard]] const T* read_at_rva(std::uint32_t rva) const {
            auto offset = rva_to_offset(rva);
            if (!offset) return nullptr;
            return read_at_offset<T>(*offset);
        }

        template<typename T>
        [[nodiscard]] const T* read_at_va(std::uint64_t va) const {
            auto offset = va_to_offset(va);
            if (!offset) return nullptr;
            return read_at_offset<T>(*offset);
        }

        // Read null-terminated string at offset
        [[nodiscard]] std::string read_string_at_offset(std::size_t offset, std::size_t max_len = 256) const {
            if (!raw_data || offset >= raw_size) return {};

            std::size_t len = 0;
            while (offset + len < raw_size && len < max_len && raw_data[offset + len] != 0) {
                ++len;
            }
            return std::string(reinterpret_cast<const char*>(raw_data + offset), len);
        }

        [[nodiscard]] std::string read_string_at_rva(std::uint32_t rva, std::size_t max_len = 256) const {
            auto offset = rva_to_offset(rva);
            if (!offset) return {};
            return read_string_at_offset(*offset, max_len);
        }

        // =====================================================================
        // Data Directory Access
        // =====================================================================

        [[nodiscard]] const PeDataDirectory* get_directory(const std::string& name) const {
            for (const auto& dir : data_directories) {
                if (dir.name == name && dir.rva != 0 && dir.size != 0) {
                    return &dir;
                }
            }
            return nullptr;
        }

        [[nodiscard]] const PeDataDirectory* get_directory(std::size_t index) const {
            if (index < data_directories.size()) {
                const auto& dir = data_directories[index];
                if (dir.rva != 0 && dir.size != 0) {
                    return &dir;
                }
            }
            return nullptr;
        }

        // =====================================================================
        // File Type Helpers
        // =====================================================================

        [[nodiscard]] bool is_dll() const {
            return characteristics & 0x2000;  // IMAGE_FILE_DLL
        }

        [[nodiscard]] bool is_executable() const {
            return characteristics & 0x0002;  // IMAGE_FILE_EXECUTABLE_IMAGE
        }

        [[nodiscard]] bool is_system_file() const {
            return characteristics & 0x1000;  // IMAGE_FILE_SYSTEM
        }

        [[nodiscard]] bool is_large_address_aware() const {
            return characteristics & 0x0020;  // IMAGE_FILE_LARGE_ADDRESS_AWARE
        }

        // =====================================================================
        // Security Feature Helpers
        // =====================================================================

        [[nodiscard]] bool has_aslr() const {
            return dll_characteristics & 0x0040;  // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        }

        [[nodiscard]] bool has_high_entropy_aslr() const {
            return (dll_characteristics & 0x0020) && has_aslr();  // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        }

        [[nodiscard]] bool has_dep() const {
            return dll_characteristics & 0x0100;  // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        }

        [[nodiscard]] bool has_cfg() const {
            return dll_characteristics & 0x4000;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF
        }

        [[nodiscard]] bool has_seh() const {
            return !(dll_characteristics & 0x0400);  // !IMAGE_DLLCHARACTERISTICS_NO_SEH
        }

        [[nodiscard]] bool is_appcontainer() const {
            return dll_characteristics & 0x1000;  // IMAGE_DLLCHARACTERISTICS_APPCONTAINER
        }

        // =====================================================================
        // Validation
        // =====================================================================

        [[nodiscard]] bool is_valid() const {
            return raw_data != nullptr && raw_size > 0 && image_base != 0;
        }

        [[nodiscard]] bool has_imports() const {
            return !imports.empty();
        }

        [[nodiscard]] bool has_exports() const {
            return !exports.empty();
        }
    };

} // namespace viewer