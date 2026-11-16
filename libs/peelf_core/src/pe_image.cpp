#include "image_internal.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {
namespace {

using detail::align8;
using detail::checked_add_u64;
using detail::fits_range;
using detail::pe_rva_to_file_offset;
using detail::rd16;
using detail::rd32;
using detail::rd64;
using detail::read_c_string;

class PeImage final : public detail::ImageBase {
public:
    [[nodiscard]] const PeHeader* pe_header() const noexcept override {
        return &pe_header_;
    }
    [[nodiscard]] const std::vector<PeDataDirectory>& pe_data_directories() const noexcept override {
        return data_directories_;
    }
    [[nodiscard]] const std::vector<PeBaseRelocationBlock>& pe_base_relocations() const noexcept override {
        return base_relocations_;
    }
    [[nodiscard]] const std::vector<PeDebugDirectory>& pe_debug_directories() const noexcept override {
        return debug_directories_;
    }
    [[nodiscard]] const PeTlsDirectory* pe_tls_directory() const noexcept override {
        return tls_directory_ ? &*tls_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeCertificate>& pe_certificates() const noexcept override {
        return certificates_;
    }
    [[nodiscard]] const PeLoadConfigDirectory* pe_load_config_directory() const noexcept override {
        return load_config_directory_ ? &*load_config_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeRuntimeFunction>& pe_runtime_functions() const noexcept override {
        return runtime_functions_;
    }
    [[nodiscard]] const std::vector<PeBoundImport>& pe_bound_imports() const noexcept override {
        return bound_imports_;
    }
    [[nodiscard]] const PeResourceDirectory* pe_resource_directory() const noexcept override {
        return resource_directory_ ? &*resource_directory_ : nullptr;
    }
    [[nodiscard]] const std::vector<PeResourceDataEntry>& pe_resource_data_entries() const noexcept override {
        return resource_data_entries_;
    }
    [[nodiscard]] const PeClrHeader* pe_clr_header() const noexcept override {
        return clr_header_ ? &*clr_header_ : nullptr;
    }
    [[nodiscard]] static Result<std::unique_ptr<PeImage>> parse(std::span<const std::uint8_t> b);
    void rebase_to_live_base(std::uint64_t live_base) override;

private:
    PeHeader pe_header_;
    std::vector<PeDataDirectory> data_directories_;
    std::vector<PeBaseRelocationBlock> base_relocations_;
    std::vector<PeDebugDirectory> debug_directories_;
    std::optional<PeTlsDirectory> tls_directory_;
    std::vector<PeCertificate> certificates_;
    std::optional<PeLoadConfigDirectory> load_config_directory_;
    std::vector<PeRuntimeFunction> runtime_functions_;
    std::vector<PeBoundImport> bound_imports_;
    std::optional<PeResourceDirectory> resource_directory_;
    std::vector<PeResourceDataEntry> resource_data_entries_;
    std::optional<PeClrHeader> clr_header_;
};

Architecture pe_arch(std::uint16_t machine) noexcept {
    switch (machine) {
        case 0x014c: return Architecture::X86;     // IMAGE_FILE_MACHINE_I386
        case 0x8664: return Architecture::X86_64;  // IMAGE_FILE_MACHINE_AMD64
        case 0x01c0:                               // IMAGE_FILE_MACHINE_ARM
        case 0x01c4: return Architecture::ARM;     // IMAGE_FILE_MACHINE_ARMNT
        case 0xaa64: return Architecture::ARM64;   // IMAGE_FILE_MACHINE_ARM64
        default:     return Architecture::Unknown;
    }
}

void parse_pe_base_relocations(std::span<const std::uint8_t> b,
                               const std::vector<Section>& sections,
                               std::uint64_t image_base,
                               std::uint32_t directory_rva,
                               std::uint32_t directory_size,
                               std::vector<PeBaseRelocationBlock>& relocations_out) {
    if (directory_rva == 0 || directory_size < 8) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = *directory_off + directory_size;
    std::uint64_t cursor = *directory_off;
    while (cursor + 8u <= end) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t page_rva = rd32(b, off + 0x00, false);
        const std::uint32_t block_size = rd32(b, off + 0x04, false);
        if (block_size < 8 || block_size > end - cursor) {
            break;
        }

        PeBaseRelocationBlock block;
        block.page_rva = page_rva;
        block.block_size = block_size;
        const std::uint64_t entry_count = (block_size - 8u) / 2u;
        block.entries.reserve(static_cast<std::size_t>(entry_count));
        std::uint64_t entry_cursor = cursor + 8u;
        for (std::uint64_t i = 0; i < entry_count; ++i, entry_cursor += 2u) {
            const std::uint16_t raw = rd16(b, static_cast<std::size_t>(entry_cursor), false);
            PeBaseRelocationEntry entry;
            entry.page_rva = page_rva;
            entry.type = static_cast<std::uint16_t>(raw >> 12);
            entry.offset = static_cast<std::uint16_t>(raw & 0x0FFFu);
            entry.rva = page_rva + entry.offset;
            block.entries.push_back(entry);
        }
        relocations_out.push_back(std::move(block));
        cursor += block_size;
    }
}

void parse_pe_debug_directories(std::span<const std::uint8_t> b,
                                const std::vector<Section>& sections,
                                std::uint64_t image_base,
                                std::uint32_t directory_rva,
                                std::uint32_t directory_size,
                                std::vector<PeDebugDirectory>& debug_out) {
    if (directory_rva == 0 || directory_size < 0x1C) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    constexpr std::uint64_t kDebugDirectorySize = 0x1C;
    const std::uint64_t count = directory_size / kDebugDirectorySize;
    debug_out.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t entry_off = *directory_off + i * kDebugDirectorySize;
        if (!fits_range(entry_off, kDebugDirectorySize, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t off = static_cast<std::size_t>(entry_off);
        PeDebugDirectory entry;
        entry.characteristics = rd32(b, off + 0x00, false);
        entry.time_date_stamp = rd32(b, off + 0x04, false);
        entry.major_version = rd16(b, off + 0x08, false);
        entry.minor_version = rd16(b, off + 0x0A, false);
        entry.type = rd32(b, off + 0x0C, false);
        entry.size_of_data = rd32(b, off + 0x10, false);
        entry.address_of_raw_data = rd32(b, off + 0x14, false);
        entry.pointer_to_raw_data = rd32(b, off + 0x18, false);

        if (entry.type == 2 && entry.size_of_data >= 24 &&
            fits_range(entry.pointer_to_raw_data, entry.size_of_data, static_cast<std::uint64_t>(b.size()))) {
            const std::uint64_t cv_off64 = entry.pointer_to_raw_data;
            const std::size_t cv = static_cast<std::size_t>(cv_off64);
            entry.codeview_signature = rd32(b, cv + 0x00, false);
            constexpr std::uint32_t kRsds = 0x5344'5352u;
            if (entry.codeview_signature == kRsds) {
                entry.codeview_guid.reserve(16);
                for (std::uint64_t byte_index = 0; byte_index < 16; ++byte_index) {
                    entry.codeview_guid.push_back(b[static_cast<std::size_t>(cv_off64 + 4u + byte_index)]);
                }
                entry.codeview_age = rd32(b, cv + 0x14, false);
                entry.codeview_pdb_path = read_c_string(b, cv_off64 + 0x18, entry.size_of_data - 0x18u);
            }
        }
        debug_out.push_back(std::move(entry));
    }
}

void parse_pe_runtime_functions(std::span<const std::uint8_t> b,
                                const std::vector<Section>& sections,
                                std::uint64_t image_base,
                                std::uint32_t directory_rva,
                                std::uint32_t directory_size,
                                std::vector<PeRuntimeFunction>& runtime_functions_out) {
    if (directory_rva == 0 || directory_size < 12) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    constexpr std::uint64_t kRuntimeFunctionSize = 12;
    const std::uint64_t count = directory_size / kRuntimeFunctionSize;
    runtime_functions_out.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t entry_off = *directory_off + i * kRuntimeFunctionSize;
        if (!fits_range(entry_off, kRuntimeFunctionSize, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t off = static_cast<std::size_t>(entry_off);
        PeRuntimeFunction entry;
        entry.begin_address_rva = rd32(b, off + 0x00, false);
        entry.end_address_rva = rd32(b, off + 0x04, false);
        entry.unwind_info_rva = rd32(b, off + 0x08, false);
        entry.file_offset = entry_off;
        runtime_functions_out.push_back(entry);
    }
}

[[nodiscard]] std::string read_pe_coff_symbol_name(std::span<const std::uint8_t> b,
                                                   std::size_t symbol_offset,
                                                   std::uint64_t string_table_offset,
                                                   std::uint64_t string_table_size) {
    if (rd32(b, symbol_offset, false) == 0) {
        const std::uint32_t name_offset = rd32(b, symbol_offset + 4u, false);
        if (name_offset < 4u || name_offset >= string_table_size) {
            return {};
        }
        return read_c_string(b, string_table_offset + name_offset);
    }

    std::string name;
    for (std::size_t i = 0; i < 8u && b[symbol_offset + i] != 0; ++i) {
        name.push_back(static_cast<char>(b[symbol_offset + i]));
    }
    return name;
}

void parse_pe_coff_symbols(std::span<const std::uint8_t> b,
                           const std::vector<Section>& sections,
                           std::uint32_t symbol_table_offset,
                           std::uint32_t symbol_count,
                           std::vector<Symbol>& symbols_out) {
    constexpr std::uint64_t kSymbolSize = 18;
    if (symbol_table_offset == 0 || symbol_count == 0 ||
        !fits_range(symbol_table_offset, static_cast<std::uint64_t>(symbol_count) * kSymbolSize,
                    static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t string_table_offset =
        static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(symbol_count) * kSymbolSize;
    std::uint64_t string_table_size = 0;
    if (fits_range(string_table_offset, 4, static_cast<std::uint64_t>(b.size()))) {
        string_table_size = rd32(b, static_cast<std::size_t>(string_table_offset), false);
        if (!fits_range(string_table_offset, string_table_size, static_cast<std::uint64_t>(b.size()))) {
            string_table_size = 0;
        }
    }

    const std::size_t original_size = symbols_out.size();
    for (std::uint32_t index = 0; index < symbol_count;) {
        const std::uint64_t symbol_offset64 =
            static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(index) * kSymbolSize;
        const std::size_t symbol_offset = static_cast<std::size_t>(symbol_offset64);
        const std::uint32_t value = rd32(b, symbol_offset + 8u, false);
        const auto section_number = static_cast<std::int16_t>(rd16(b, symbol_offset + 12u, false));
        const std::uint16_t type = rd16(b, symbol_offset + 14u, false);
        const std::uint8_t storage_class = b[symbol_offset + 16u];
        const std::uint8_t auxiliary_count = b[symbol_offset + 17u];

        const bool defined_section = section_number > 0 &&
                                     static_cast<std::size_t>(section_number) <= sections.size();
        constexpr std::uint16_t kFunctionDerivedType = 0x20;
        constexpr std::uint8_t kExternal = 2;
        constexpr std::uint8_t kStatic = 3;
        constexpr std::uint8_t kLabel = 6;
        const bool function = (type & kFunctionDerivedType) != 0;
        const bool useful_storage = storage_class == kExternal || storage_class == kStatic || storage_class == kLabel;

        if (defined_section && function && useful_storage) {
            Symbol symbol;
            symbol.name = read_pe_coff_symbol_name(b, symbol_offset, string_table_offset, string_table_size);
            if (!symbol.name.empty()) {
                const Section& section = sections[static_cast<std::size_t>(section_number - 1)];
                symbol.virtual_address = section.virtual_address + value;
                symbol.binding = storage_class;
                symbol.type = static_cast<std::uint8_t>(type & 0xFFu);
                symbol.section_index = static_cast<std::uint16_t>(section_number);
                symbol.dynamic = false;
                symbols_out.push_back(std::move(symbol));
            }
        }

        index += static_cast<std::uint32_t>(1u + auxiliary_count);
    }

    auto begin = symbols_out.begin() + static_cast<std::ptrdiff_t>(original_size);
    std::ranges::sort(begin, symbols_out.end(), [](const Symbol& lhs, const Symbol& rhs) {
        if (lhs.section_index != rhs.section_index) {
            return lhs.section_index < rhs.section_index;
        }
        return lhs.virtual_address < rhs.virtual_address;
    });

    for (auto it = begin; it != symbols_out.end(); ++it) {
        const auto next = std::find_if(std::next(it), symbols_out.end(), [&](const Symbol& candidate) {
            return candidate.section_index == it->section_index &&
                   candidate.virtual_address > it->virtual_address;
        });
        if (next != symbols_out.end()) {
            it->size = next->virtual_address - it->virtual_address;
        }
    }
}

void parse_pe_bound_imports(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            std::uint32_t directory_rva,
                            std::uint32_t directory_size,
                            std::vector<PeBoundImport>& bound_imports_out) {
    if (directory_rva == 0 || directory_size < 8) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = *directory_off + directory_size;
    for (std::uint64_t cursor = *directory_off; cursor + 8u <= end; cursor += 8u) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        PeBoundImport entry;
        entry.time_date_stamp = rd32(b, off + 0x00, false);
        entry.offset_module_name = rd16(b, off + 0x04, false);
        entry.forwarder_ref_count = rd16(b, off + 0x06, false);
        entry.file_offset = cursor;
        if (entry.time_date_stamp == 0 && entry.offset_module_name == 0 &&
            entry.forwarder_ref_count == 0) {
            break;
        }

        const std::uint64_t name_off = *directory_off + entry.offset_module_name;
        if (name_off < end) {
            entry.module_name = read_c_string(b, name_off, end - name_off);
        }
        bound_imports_out.push_back(std::move(entry));
    }
}

void parse_pe_resource_directory(std::span<const std::uint8_t> b,
                                 const std::vector<Section>& sections,
                                 std::uint64_t image_base,
                                 std::uint32_t directory_rva,
                                 std::uint32_t directory_size,
                                 std::optional<PeResourceDirectory>& resource_out,
                                 std::vector<PeResourceDataEntry>& data_entries_out) {
    if (directory_rva == 0 || directory_size < 16) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, 16, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeResourceDirectory resource;
    resource.rva = directory_rva;
    resource.file_offset = *directory_off;
    resource.characteristics = rd32(b, off + 0x00, false);
    resource.time_date_stamp = rd32(b, off + 0x04, false);
    resource.major_version = rd16(b, off + 0x08, false);
    resource.minor_version = rd16(b, off + 0x0A, false);
    resource.named_entry_count = rd16(b, off + 0x0C, false);
    resource.id_entry_count = rd16(b, off + 0x0E, false);

    const std::uint64_t total_entries = static_cast<std::uint64_t>(resource.named_entry_count) +
                                        static_cast<std::uint64_t>(resource.id_entry_count);
    const std::uint64_t max_entries = directory_size >= 16 ? (directory_size - 16u) / 8u : 0;
    const std::uint64_t parsed_entries = std::min(total_entries, max_entries);
    resource.entries.reserve(static_cast<std::size_t>(parsed_entries));
    for (std::uint64_t i = 0; i < parsed_entries; ++i) {
        const std::uint64_t entry_off = *directory_off + 16u + i * 8u;
        if (!fits_range(entry_off, 8, static_cast<std::uint64_t>(b.size()))) {
            break;
        }
        const std::size_t entry_pos = static_cast<std::size_t>(entry_off);
        PeResourceDirectoryEntry entry;
        entry.name_or_id = rd32(b, entry_pos + 0x00, false);
        entry.offset_to_data_or_directory = rd32(b, entry_pos + 0x04, false);
        entry.name_is_string = (entry.name_or_id & 0x8000'0000u) != 0;
        entry.data_is_directory = (entry.offset_to_data_or_directory & 0x8000'0000u) != 0;
        resource.entries.push_back(entry);
    }

    std::size_t visited_budget = 0u;
    constexpr std::size_t kMaxResourceEntriesVisited = 16384u;
    std::array<std::uint64_t, 4> active_dir_offsets{};

    auto parse_resource_level = [&](auto&& self,
                                    std::uint64_t relative_directory_offset,
                                    std::uint32_t depth,
                                    std::uint32_t type_id,
                                    std::uint32_t name_id,
                                    std::uint32_t language_id) -> void {
        if (depth > 2 || visited_budget >= kMaxResourceEntriesVisited ||
            relative_directory_offset > directory_size ||
            directory_size - relative_directory_offset < 16) {
            return;
        }
        for (std::uint32_t d = 0; d < depth; ++d) {
            if (active_dir_offsets[d] == relative_directory_offset) {
                return;
            }
        }
        active_dir_offsets[depth] = relative_directory_offset;

        const std::uint64_t directory_file_offset = *directory_off + relative_directory_offset;
        if (!fits_range(directory_file_offset, 16, static_cast<std::uint64_t>(b.size()))) {
            return;
        }

        const std::size_t dir = static_cast<std::size_t>(directory_file_offset);
        const std::uint16_t named_count = rd16(b, dir + 0x0C, false);
        const std::uint16_t id_count = rd16(b, dir + 0x0E, false);
        const std::uint64_t entry_count = static_cast<std::uint64_t>(named_count) +
                                          static_cast<std::uint64_t>(id_count);
        for (std::uint64_t i = 0; i < entry_count; ++i) {
            if (visited_budget >= kMaxResourceEntriesVisited) {
                break;
            }
            ++visited_budget;
            const std::uint64_t entry_off = directory_file_offset + 16u + i * 8u;
            if (!fits_range(entry_off, 8, static_cast<std::uint64_t>(b.size()))) {
                break;
            }

            const std::size_t entry_pos = static_cast<std::size_t>(entry_off);
            const std::uint32_t raw_name = rd32(b, entry_pos + 0x00, false);
            const std::uint32_t raw_target = rd32(b, entry_pos + 0x04, false);
            const std::uint32_t id = raw_name & 0x7FFF'FFFFu;
            const std::uint32_t next_type = depth == 0 ? id : type_id;
            const std::uint32_t next_name = depth == 1 ? id : name_id;
            const std::uint32_t next_language = depth == 2 ? id : language_id;

            const std::uint32_t target_offset = raw_target & 0x7FFF'FFFFu;
            if ((raw_target & 0x8000'0000u) != 0) {
                self(self, target_offset, depth + 1u, next_type, next_name, next_language);
                continue;
            }

            if (target_offset > directory_size || directory_size - target_offset < 16) {
                continue;
            }
            const std::uint64_t data_entry_off = *directory_off + target_offset;
            if (!fits_range(data_entry_off, 16, static_cast<std::uint64_t>(b.size()))) {
                continue;
            }

            const std::size_t data = static_cast<std::size_t>(data_entry_off);
            PeResourceDataEntry data_entry;
            data_entry.type_id = next_type;
            data_entry.name_id = next_name;
            data_entry.language_id = next_language;
            data_entry.data_rva = rd32(b, data + 0x00, false);
            data_entry.size = rd32(b, data + 0x04, false);
            data_entry.code_page = rd32(b, data + 0x08, false);
            data_entry.reserved = rd32(b, data + 0x0C, false);
            data_entry.entry_file_offset = data_entry_off;
            if (const auto data_off = pe_rva_to_file_offset(sections, image_base, data_entry.data_rva)) {
                data_entry.data_file_offset = *data_off;
            }
            data_entries_out.push_back(data_entry);
        }
    };

    parse_resource_level(parse_resource_level, 0, 0, 0, 0, 0);

    resource_out = std::move(resource);
}

void parse_pe_tls_directory(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            bool is64,
                            std::uint32_t directory_rva,
                            std::uint32_t directory_size,
                            std::optional<PeTlsDirectory>& tls_out) {
    const std::uint64_t min_size = is64 ? 0x28u : 0x18u;
    if (directory_rva == 0 || directory_size < min_size) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, min_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeTlsDirectory tls;
    if (is64) {
        tls.raw_data_start_va = rd64(b, off + 0x00, false);
        tls.raw_data_end_va = rd64(b, off + 0x08, false);
        tls.address_of_index = rd64(b, off + 0x10, false);
        tls.address_of_callbacks = rd64(b, off + 0x18, false);
        tls.size_of_zero_fill = rd32(b, off + 0x20, false);
        tls.characteristics = rd32(b, off + 0x24, false);
    } else {
        tls.raw_data_start_va = rd32(b, off + 0x00, false);
        tls.raw_data_end_va = rd32(b, off + 0x04, false);
        tls.address_of_index = rd32(b, off + 0x08, false);
        tls.address_of_callbacks = rd32(b, off + 0x0C, false);
        tls.size_of_zero_fill = rd32(b, off + 0x10, false);
        tls.characteristics = rd32(b, off + 0x14, false);
    }

    if (tls.address_of_callbacks != 0 && tls.address_of_callbacks >= image_base) {
        const std::uint64_t callbacks_rva64 = tls.address_of_callbacks - image_base;
        if (callbacks_rva64 <= std::numeric_limits<std::uint32_t>::max()) {
            const auto callbacks_off = pe_rva_to_file_offset(
                sections, image_base, static_cast<std::uint32_t>(callbacks_rva64));
            if (callbacks_off) {
                const std::uint64_t pointer_size = is64 ? 8u : 4u;
                for (std::uint64_t callback_index = 0; callback_index < b.size() / pointer_size; ++callback_index) {
                    const std::uint64_t callback_off = *callbacks_off + callback_index * pointer_size;
                    if (!fits_range(callback_off, pointer_size, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }
                    const std::uint64_t callback_va = is64
                        ? rd64(b, static_cast<std::size_t>(callback_off), false)
                        : static_cast<std::uint64_t>(rd32(b, static_cast<std::size_t>(callback_off), false));
                    if (callback_va == 0) {
                        break;
                    }
                    tls.callbacks.push_back(callback_va);
                }
            }
        }
    }

    tls_out = std::move(tls);
}

void parse_pe_certificates(std::span<const std::uint8_t> b,
                           std::uint32_t directory_file_offset,
                           std::uint32_t directory_size,
                           std::vector<PeCertificate>& certificates_out) {
    if (directory_file_offset == 0 || directory_size < 8) {
        return;
    }
    if (!fits_range(directory_file_offset, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t end = static_cast<std::uint64_t>(directory_file_offset) + directory_size;
    std::uint64_t cursor = directory_file_offset;
    while (cursor + 8u <= end) {
        const std::size_t off = static_cast<std::size_t>(cursor);
        const std::uint32_t length = rd32(b, off + 0x00, false);
        if (length < 8 || length > end - cursor ||
            !fits_range(cursor, length, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        PeCertificate cert;
        cert.file_offset = static_cast<std::uint32_t>(cursor);
        cert.length = length;
        cert.revision = rd16(b, off + 0x04, false);
        cert.certificate_type = rd16(b, off + 0x06, false);
        cert.certificate.reserve(length - 8u);
        for (std::uint64_t i = 0; i < static_cast<std::uint64_t>(length - 8u); ++i) {
            cert.certificate.push_back(b[static_cast<std::size_t>(cursor + 8u + i)]);
        }
        certificates_out.push_back(std::move(cert));

        const std::uint64_t next = align8(cursor + length);
        if (next <= cursor) {
            break;
        }
        cursor = next;
    }
}

void parse_pe_load_config_directory(std::span<const std::uint8_t> b,
                                    const std::vector<Section>& sections,
                                    std::uint64_t image_base,
                                    bool is64,
                                    std::uint32_t directory_rva,
                                    std::uint32_t directory_size,
                                    std::optional<PeLoadConfigDirectory>& load_config_out) {
    const std::uint64_t min_size = is64 ? 0x94u : 0x5Cu;
    if (directory_rva == 0 || directory_size < min_size) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, min_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeLoadConfigDirectory load_config;
    load_config.rva = directory_rva;
    load_config.file_offset = *directory_off;
    load_config.size = rd32(b, off + 0x00, false);
    if (load_config.size < min_size ||
        !fits_range(*directory_off, load_config.size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    load_config.time_date_stamp = rd32(b, off + 0x04, false);
    load_config.major_version = rd16(b, off + 0x08, false);
    load_config.minor_version = rd16(b, off + 0x0A, false);
    load_config.global_flags_clear = rd32(b, off + 0x0C, false);
    load_config.global_flags_set = rd32(b, off + 0x10, false);
    load_config.critical_section_default_timeout = rd32(b, off + 0x14, false);

    if (is64) {
        load_config.decommit_free_block_threshold = rd64(b, off + 0x18, false);
        load_config.decommit_total_free_threshold = rd64(b, off + 0x20, false);
        load_config.lock_prefix_table = rd64(b, off + 0x28, false);
        load_config.maximum_allocation_size = rd64(b, off + 0x30, false);
        load_config.virtual_memory_threshold = rd64(b, off + 0x38, false);
        load_config.process_affinity_mask = rd64(b, off + 0x40, false);
        load_config.process_heap_flags = rd32(b, off + 0x48, false);
        load_config.csd_version = rd16(b, off + 0x4C, false);
        load_config.dependent_load_flags = rd16(b, off + 0x4E, false);
        load_config.edit_list = rd64(b, off + 0x50, false);
        load_config.security_cookie = rd64(b, off + 0x58, false);
        load_config.se_handler_table = rd64(b, off + 0x60, false);
        load_config.se_handler_count = rd64(b, off + 0x68, false);
        load_config.guard_cf_check_function_pointer = rd64(b, off + 0x70, false);
        load_config.guard_cf_dispatch_function_pointer = rd64(b, off + 0x78, false);
        load_config.guard_cf_function_table = rd64(b, off + 0x80, false);
        load_config.guard_cf_function_count = rd64(b, off + 0x88, false);
        load_config.guard_flags = rd32(b, off + 0x90, false);
        if (load_config.size >= 0x118u &&
            fits_range(*directory_off, 0x118u, static_cast<std::uint64_t>(b.size()))) {
            load_config.guard_eh_continuation_table = rd64(b, off + 0x108, false);
            load_config.guard_eh_continuation_count = rd64(b, off + 0x110, false);
        }
    } else {
        load_config.decommit_free_block_threshold = rd32(b, off + 0x18, false);
        load_config.decommit_total_free_threshold = rd32(b, off + 0x1C, false);
        load_config.lock_prefix_table = rd32(b, off + 0x20, false);
        load_config.maximum_allocation_size = rd32(b, off + 0x24, false);
        load_config.virtual_memory_threshold = rd32(b, off + 0x28, false);
        load_config.process_affinity_mask = rd32(b, off + 0x2C, false);
        load_config.process_heap_flags = rd32(b, off + 0x30, false);
        load_config.csd_version = rd16(b, off + 0x34, false);
        load_config.dependent_load_flags = rd16(b, off + 0x36, false);
        load_config.edit_list = rd32(b, off + 0x38, false);
        load_config.security_cookie = rd32(b, off + 0x3C, false);
        load_config.se_handler_table = rd32(b, off + 0x40, false);
        load_config.se_handler_count = rd32(b, off + 0x44, false);
        load_config.guard_cf_check_function_pointer = rd32(b, off + 0x48, false);
        load_config.guard_cf_dispatch_function_pointer = rd32(b, off + 0x4C, false);
        load_config.guard_cf_function_table = rd32(b, off + 0x50, false);
        load_config.guard_cf_function_count = rd32(b, off + 0x54, false);
        load_config.guard_flags = rd32(b, off + 0x58, false);
        if (load_config.size >= 0xACu &&
            fits_range(*directory_off, 0xACu, static_cast<std::uint64_t>(b.size()))) {
            load_config.guard_eh_continuation_table = rd32(b, off + 0xA4, false);
            load_config.guard_eh_continuation_count = rd32(b, off + 0xA8, false);
        }
    }

    load_config_out = load_config;
}

void parse_pe_import_thunks(std::span<const std::uint8_t> b,
                            const std::vector<Section>& sections,
                            std::uint64_t image_base,
                            bool is64,
                            std::string library,
                            std::uint32_t name_table_rva,
                            std::uint32_t address_table_rva,
                            bool delay_load,
                            std::vector<ImportEntry>& imports_out, bool thunk_values_are_va = false) {
    const auto thunk_off = pe_rva_to_file_offset(sections, image_base, name_table_rva);
    if (library.empty() || !thunk_off || address_table_rva == 0) {
        return;
    }

    const std::uint64_t thunk_size = is64 ? 8u : 4u;
    for (std::uint64_t thunk_index = 0; thunk_index < b.size() / thunk_size; ++thunk_index) {
        const std::uint64_t entry_off = *thunk_off + thunk_index * thunk_size;
        if (!fits_range(entry_off, thunk_size, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::uint64_t thunk_value = is64
            ? rd64(b, static_cast<std::size_t>(entry_off), false)
            : static_cast<std::uint64_t>(rd32(b, static_cast<std::size_t>(entry_off), false));
        if (thunk_value == 0) {
            break;
        }

        const std::uint64_t ordinal_mask = is64 ? (1ull << 63) : (1ull << 31);
        if ((thunk_value & ordinal_mask) != 0) {
            ImportEntry entry;
            entry.library = library;
            entry.ordinal = static_cast<std::uint16_t>(thunk_value & 0xFFFFu);
            entry.address = image_base + address_table_rva + thunk_index * thunk_size;
            entry.import_by_ordinal = true;
            entry.delay_load = delay_load;
            imports_out.push_back(std::move(entry));
            continue;
        }

        if (thunk_values_are_va && thunk_value < image_base) continue;
        const auto name_rva = thunk_values_are_va ? thunk_value - image_base : thunk_value;
        if (name_rva > std::numeric_limits<std::uint32_t>::max()) continue;
        const auto hint_name_off = pe_rva_to_file_offset(
            sections, image_base, static_cast<std::uint32_t>(name_rva));
        if (!hint_name_off || !fits_range(*hint_name_off, 2, static_cast<std::uint64_t>(b.size()))) {
            continue;
        }

        ImportEntry entry;
        entry.library = library;
        entry.name = read_c_string(b, *hint_name_off + 2);
        entry.address = image_base + address_table_rva + thunk_index * thunk_size;
        entry.delay_load = delay_load;
        if (!entry.name.empty()) {
            imports_out.push_back(std::move(entry));
        }
    }
}

void parse_pe_delay_load_imports(std::span<const std::uint8_t> b,
                                 const std::vector<Section>& sections,
                                 std::uint64_t image_base,
                                 bool is64,
                                 std::uint32_t directory_rva,
                                 std::uint32_t directory_size,
                                 std::vector<ImportEntry>& imports_out) {
    if (directory_rva == 0 || directory_size < 32) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, directory_size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::uint64_t max_descriptors = directory_size / 32u;
    for (std::uint64_t desc_index = 0; desc_index < max_descriptors; ++desc_index) {
        const std::uint64_t desc_off = *directory_off + desc_index * 32u;
        if (!fits_range(desc_off, 32, static_cast<std::uint64_t>(b.size()))) {
            break;
        }

        const std::size_t desc = static_cast<std::size_t>(desc_off);
        const std::uint32_t attributes = rd32(b, desc + 0x00, false);
        std::uint32_t name_rva = rd32(b, desc + 0x04, false);
        std::uint32_t import_address_table_rva = rd32(b, desc + 0x0C, false);
        std::uint32_t import_name_table_rva = rd32(b, desc + 0x10, false);
        if (attributes == 0 && name_rva == 0 && import_address_table_rva == 0 &&
            import_name_table_rva == 0) {
            break;
        }

        if ((attributes & 1u) == 0) {
            if (name_rva < image_base || import_address_table_rva < image_base ||
                import_name_table_rva < image_base) continue;
            name_rva = static_cast<std::uint32_t>(name_rva - image_base);
            import_address_table_rva = static_cast<std::uint32_t>(import_address_table_rva - image_base);
            import_name_table_rva = static_cast<std::uint32_t>(import_name_table_rva - image_base);
        }
        const auto dll_name_off = pe_rva_to_file_offset(sections, image_base, name_rva);
        const std::string library = dll_name_off ? read_c_string(b, *dll_name_off) : std::string{};
        parse_pe_import_thunks(b, sections, image_base, is64, library, import_name_table_rva,
                               import_address_table_rva, true, imports_out, (attributes & 1u) == 0);
    }
}

void parse_pe_clr_header(std::span<const std::uint8_t> b,
                         const std::vector<Section>& sections,
                         std::uint64_t image_base,
                         std::uint32_t directory_rva,
                         std::uint32_t directory_size,
                         std::optional<PeClrHeader>& clr_out) {
    if (directory_rva == 0 || directory_size < 0x48) {
        return;
    }

    const auto directory_off = pe_rva_to_file_offset(sections, image_base, directory_rva);
    if (!directory_off || !fits_range(*directory_off, 0x48, static_cast<std::uint64_t>(b.size()))) {
        return;
    }

    const std::size_t off = static_cast<std::size_t>(*directory_off);
    PeClrHeader clr;
    clr.rva = directory_rva;
    clr.file_offset = *directory_off;
    clr.size = rd32(b, off + 0x00, false);
    if (clr.size < 0x48 || !fits_range(*directory_off, clr.size, static_cast<std::uint64_t>(b.size()))) {
        return;
    }
    clr.major_runtime_version = rd16(b, off + 0x04, false);
    clr.minor_runtime_version = rd16(b, off + 0x06, false);
    clr.metadata_rva = rd32(b, off + 0x08, false);
    clr.metadata_size = rd32(b, off + 0x0C, false);
    clr.flags = rd32(b, off + 0x10, false);
    clr.entry_point_token_or_rva = rd32(b, off + 0x14, false);
    clr.resources_rva = rd32(b, off + 0x18, false);
    clr.resources_size = rd32(b, off + 0x1C, false);
    clr.strong_name_signature_rva = rd32(b, off + 0x20, false);
    clr.strong_name_signature_size = rd32(b, off + 0x24, false);
    clr.code_manager_table_rva = rd32(b, off + 0x28, false);
    clr.code_manager_table_size = rd32(b, off + 0x2C, false);
    clr.vtable_fixups_rva = rd32(b, off + 0x30, false);
    clr.vtable_fixups_size = rd32(b, off + 0x34, false);
    clr.export_address_table_jumps_rva = rd32(b, off + 0x38, false);
    clr.export_address_table_jumps_size = rd32(b, off + 0x3C, false);
    clr.managed_native_header_rva = rd32(b, off + 0x40, false);
    clr.managed_native_header_size = rd32(b, off + 0x44, false);

    clr_out = clr;
}

Result<std::unique_ptr<PeImage>> PeImage::parse(std::span<const std::uint8_t> b) {
    if (b.size() < 0x40) {
        return make_error("PE: too small for DOS header");
    }
    if (!(b[0] == 'M' && b[1] == 'Z')) {
        return make_error("PE: missing MZ signature");
    }

    const std::uint32_t e_lfanew = rd32(b, 0x3C, false);
    // Need the PE signature (4) + COFF file header (20).
    if (!fits_range(e_lfanew, 4 + 20, static_cast<std::uint64_t>(b.size()))) {
        return make_error("PE: e_lfanew out of range");
    }
    if (!(b[e_lfanew] == 'P' && b[e_lfanew + 1] == 'E' &&
          b[e_lfanew + 2] == 0 && b[e_lfanew + 3] == 0)) {
        return make_error("PE: missing PE signature");
    }

    const std::size_t coff = static_cast<std::size_t>(e_lfanew) + 4;
    const std::uint16_t machine         = rd16(b, coff + 0, false);
    const std::uint32_t symbol_table_offset = rd32(b, coff + 8, false);
    const std::uint32_t symbol_count = rd32(b, coff + 12, false);
    const std::uint16_t size_of_opt     = rd16(b, coff + 16, false);
    const std::uint16_t characteristics = rd16(b, coff + 18, false);

    const std::size_t opt = coff + 20;
    if (size_of_opt < 2 || !fits_range(opt, size_of_opt, static_cast<std::uint64_t>(b.size()))) {
        return make_error("PE: invalid optional header size");
    }

    const std::uint16_t magic = rd16(b, opt + 0, false); // 0x10b = PE32, 0x20b = PE32+
    if (magic != 0x10b && magic != 0x20b) {
        return make_error("PE: unsupported optional header magic");
    }
    const bool is64 = (magic == 0x20b);
    const std::uint16_t min_optional_size = is64 ? 32 : 32;
    if (size_of_opt < min_optional_size) {
        return make_error("PE: optional header too small for identity fields");
    }

    // entry VA = ImageBase + AddressOfEntryPoint.
    // AddressOfEntryPoint: optional-header offset 16 (both PE32 and PE32+).
    // ImageBase: PE32 -> u32 @ offset 28; PE32+ -> u64 @ offset 24.
    std::uint64_t image_base = 0;
    if (is64) {
        image_base = rd64(b, opt + 24, false);
    } else {
        image_base = rd32(b, opt + 28, false);
    }
    const std::uint32_t entry_rva = rd32(b, opt + 16, false);
    const std::uint32_t directory_count = size_of_opt >= (is64 ? 0x70 : 0x60)
        ? rd32(b, opt + (is64 ? 0x6C : 0x5C), false) : 0;
    const std::uint32_t export_dir_rva = (directory_count > 0 && size_of_opt >= (is64 ? 0x78 : 0x68))
                                             ? rd32(b, opt + (is64 ? 0x70 : 0x60), false)
                                             : 0;
    const std::uint32_t export_dir_size = (directory_count > 0 && size_of_opt >= (is64 ? 0x78 : 0x68))
                                              ? rd32(b, opt + (is64 ? 0x74 : 0x64), false)
                                              : 0;
    const std::uint32_t import_dir_rva = (directory_count > 1 && size_of_opt >= (is64 ? 0x80 : 0x70))
                                             ? rd32(b, opt + (is64 ? 0x78 : 0x68), false)
                                             : 0;
    const std::uint32_t import_dir_size = (directory_count > 1 && size_of_opt >= (is64 ? 0x80 : 0x70))
                                              ? rd32(b, opt + (is64 ? 0x7C : 0x6C), false)
                                              : 0;
    const std::uint32_t resource_dir_rva = (directory_count > 2 && size_of_opt >= (is64 ? 0x88 : 0x78))
                                               ? rd32(b, opt + (is64 ? 0x80 : 0x70), false)
                                               : 0;
    const std::uint32_t resource_dir_size = (directory_count > 2 && size_of_opt >= (is64 ? 0x88 : 0x78))
                                                ? rd32(b, opt + (is64 ? 0x84 : 0x74), false)
                                                : 0;
    const std::uint32_t exception_dir_rva = (directory_count > 3 && size_of_opt >= (is64 ? 0x90 : 0x80))
                                                ? rd32(b, opt + (is64 ? 0x88 : 0x78), false)
                                                : 0;
    const std::uint32_t exception_dir_size = (directory_count > 3 && size_of_opt >= (is64 ? 0x90 : 0x80))
                                                 ? rd32(b, opt + (is64 ? 0x8C : 0x7C), false)
                                                 : 0;
    const std::uint32_t certificate_table_file_offset = (directory_count > 4 && size_of_opt >= (is64 ? 0x98 : 0x88))
                                                            ? rd32(b, opt + (is64 ? 0x90 : 0x80), false)
                                                            : 0;
    const std::uint32_t certificate_table_size = (directory_count > 4 && size_of_opt >= (is64 ? 0x98 : 0x88))
                                                     ? rd32(b, opt + (is64 ? 0x94 : 0x84), false)
                                                     : 0;
    const std::uint32_t tls_dir_rva = (directory_count > 9 && size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xB8 : 0xA8), false)
        : 0;
    const std::uint32_t tls_dir_size = (directory_count > 9 && size_of_opt >= (is64 ? 0xC0 : 0xB0))
        ? rd32(b, opt + (is64 ? 0xBC : 0xAC), false)
        : 0;
    const std::uint32_t load_config_dir_rva = (directory_count > 10 && size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC0 : 0xB0), false)
        : 0;
    const std::uint32_t load_config_dir_size = (directory_count > 10 && size_of_opt >= (is64 ? 0xC8 : 0xB8))
        ? rd32(b, opt + (is64 ? 0xC4 : 0xB4), false)
        : 0;
    const std::uint32_t bound_import_dir_rva = (directory_count > 11 && size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xC8 : 0xB8), false)
        : 0;
    const std::uint32_t bound_import_dir_size = (directory_count > 11 && size_of_opt >= (is64 ? 0xD0 : 0xC0))
        ? rd32(b, opt + (is64 ? 0xCC : 0xBC), false)
        : 0;
    const std::uint32_t delay_import_dir_rva = (directory_count > 13 && size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xD8 : 0xC8), false)
        : 0;
    const std::uint32_t delay_import_dir_size = (directory_count > 13 && size_of_opt >= (is64 ? 0xE0 : 0xD0))
        ? rd32(b, opt + (is64 ? 0xDC : 0xCC), false)
        : 0;
    const std::uint32_t clr_dir_rva = (directory_count > 14 && size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE0 : 0xD0), false)
        : 0;
    const std::uint32_t clr_dir_size = (directory_count > 14 && size_of_opt >= (is64 ? 0xE8 : 0xD8))
        ? rd32(b, opt + (is64 ? 0xE4 : 0xD4), false)
        : 0;
    const std::uint32_t base_reloc_dir_rva = (directory_count > 5 && size_of_opt >= (is64 ? 0xA0 : 0x90))
        ? rd32(b, opt + (is64 ? 0x98 : 0x88), false)
        : 0;
    const std::uint32_t base_reloc_dir_size = (directory_count > 5 && size_of_opt >= (is64 ? 0xA0 : 0x90))
                                                  ? rd32(b, opt + (is64 ? 0x9C : 0x8C), false)
                                                  : 0;
    const std::uint32_t debug_dir_rva = (directory_count > 6 && size_of_opt >= (is64 ? 0xA8 : 0x98))
                                            ? rd32(b, opt + (is64 ? 0xA0 : 0x90), false)
                                            : 0;
    const std::uint32_t debug_dir_size = (directory_count > 6 && size_of_opt >= (is64 ? 0xA8 : 0x98))
                                             ? rd32(b, opt + (is64 ? 0xA4 : 0x94), false)
                                             : 0;

    auto img = std::make_unique<PeImage>();
    img->format_ = Format::PE;
    img->endian_ = Endianness::Little;
    img->is_64_  = is64;
    img->image_base_ = image_base;
    img->arch_   = pe_arch(machine);
    // IMAGE_FILE_DLL = 0x2000.
    img->kind_   = (characteristics & 0x2000) ? ImageKind::SharedLibrary : ImageKind::Executable;
    img->entry_  = entry_rva == 0 ? 0 : checked_add_u64(image_base, entry_rva).value_or(0);

    // Sections (P2-1): the section table follows the optional header.
    const std::uint16_t num_sections = rd16(b, coff + 2, false);
    const std::uint32_t time_date_stamp = rd32(b, coff + 4, false);
    img->pe_header_ = PeHeader{
        .machine = machine,
        .number_of_sections = num_sections,
        .time_date_stamp = time_date_stamp,
        .symbol_table_offset = symbol_table_offset,
        .number_of_symbols = symbol_count,
        .optional_header_size = size_of_opt,
        .characteristics = characteristics,
        .optional_magic = magic,
        .entry_point_rva = entry_rva,
        .section_alignment = size_of_opt >= 0x24 ? rd32(b, opt + 0x20, false) : 0u,
        .file_alignment = size_of_opt >= 0x28 ? rd32(b, opt + 0x24, false) : 0u,
        .size_of_image = size_of_opt >= 0x3C ? rd32(b, opt + 0x38, false) : 0u,
        .size_of_headers = size_of_opt >= 0x40 ? rd32(b, opt + 0x3C, false) : 0u,
        .checksum = size_of_opt >= 0x44 ? rd32(b, opt + 0x40, false) : 0u,
        .subsystem = size_of_opt >= 0x46 ? rd16(b, opt + 0x44, false) : std::uint16_t{0},
        .dll_characteristics = size_of_opt >= 0x48 ? rd16(b, opt + 0x46, false) : std::uint16_t{0},
        .stack_reserve = is64 ? (size_of_opt >= 0x50 ? rd64(b, opt + 0x48, false) : 0ull)
                              : (size_of_opt >= 0x4C ? static_cast<std::uint64_t>(rd32(b, opt + 0x48, false)) : 0ull),
        .stack_commit = is64 ? (size_of_opt >= 0x58 ? rd64(b, opt + 0x50, false) : 0ull)
                             : (size_of_opt >= 0x50 ? static_cast<std::uint64_t>(rd32(b, opt + 0x4C, false)) : 0ull),
        .heap_reserve = is64 ? (size_of_opt >= 0x60 ? rd64(b, opt + 0x58, false) : 0ull)
                             : (size_of_opt >= 0x54 ? static_cast<std::uint64_t>(rd32(b, opt + 0x50, false)) : 0ull),
        .heap_commit = is64 ? (size_of_opt >= 0x68 ? rd64(b, opt + 0x60, false) : 0ull)
                            : (size_of_opt >= 0x58 ? static_cast<std::uint64_t>(rd32(b, opt + 0x54, false)) : 0ull),
    };
    {
        static constexpr std::array<std::string_view, 16> kPeDirNames = {
            "Export", "Import", "Resource", "Exception",
            "Security", "BaseReloc", "Debug", "Architecture",
            "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
            "IAT", "DelayImport", "CLRRuntime", "Reserved",
        };
        const std::size_t dd_base_off = opt + (is64 ? 0x70u : 0x60u);
        const std::uint32_t capped_dirs = std::min<std::uint32_t>(directory_count, 16u);
        img->data_directories_.reserve(capped_dirs);
        for (std::uint32_t di = 0u; di < capped_dirs; ++di) {
            const std::size_t entry_off = dd_base_off + static_cast<std::size_t>(di) * 8u;
            if (entry_off + 8u > opt + size_of_opt ||
                !fits_range(entry_off, 8u, static_cast<std::uint64_t>(b.size()))) {
                break;
            }
            img->data_directories_.push_back(PeDataDirectory{
                .index = di,
                .name = std::string(kPeDirNames[di]),
                .rva = rd32(b, entry_off + 0u, false),
                .size = rd32(b, entry_off + 4u, false),
            });
        }
    }
    const std::size_t   sect_table   = opt + size_of_opt;
    constexpr std::size_t kSectHdr = 0x28;  // 40-byte section header
    img->sections_.reserve(num_sections);
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::uint64_t hdr64 = static_cast<std::uint64_t>(sect_table) +
                                    static_cast<std::uint64_t>(i) * kSectHdr;
        if (!fits_range(hdr64, kSectHdr, static_cast<std::uint64_t>(b.size()))) {
            break;  // truncated
        }
        const std::size_t hdr = static_cast<std::size_t>(hdr64);
        std::string name;
        for (std::size_t j = 0; j < 8 && b[hdr + j] != 0; ++j) {
            name.push_back(static_cast<char>(b[hdr + j]));
        }
        const std::uint32_t vsize   = rd32(b, hdr + 8, false);
        const std::uint32_t vaddr   = rd32(b, hdr + 12, false);
        const std::uint32_t rawsize = rd32(b, hdr + 16, false);
        const std::uint32_t rawptr  = rd32(b, hdr + 20, false);
        const std::uint32_t chars   = rd32(b, hdr + 36, false);

        Section sec;
        sec.name            = std::move(name);
        sec.virtual_address = image_base + vaddr;
        sec.virtual_size    = vsize;
        sec.file_offset     = rawptr;
        sec.file_size       = rawsize;
        sec.raw_flags       = chars;
        if (sec.name.starts_with('/')) {
            std::uint32_t name_offset = 0;
            const auto parsed = std::from_chars(sec.name.data() + 1, sec.name.data() + sec.name.size(), name_offset);
            const std::uint64_t strings = static_cast<std::uint64_t>(symbol_table_offset) + static_cast<std::uint64_t>(symbol_count) * 18;
            if (symbol_table_offset != 0 && parsed.ec == std::errc{} && parsed.ptr == sec.name.data() + sec.name.size() &&
                fits_range(strings, 4, b.size())) {
                const auto length = rd32(b, static_cast<std::size_t>(strings), false);
                if (name_offset >= 4 && name_offset < length && fits_range(strings, length, b.size()))
                    sec.name = read_c_string(b, strings + name_offset, length - name_offset);
            }
        }
        sec.executable = (chars & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
        sec.readable   = (chars & 0x40000000u) != 0;  // IMAGE_SCN_MEM_READ
        sec.writable   = (chars & 0x80000000u) != 0;  // IMAGE_SCN_MEM_WRITE
        img->sections_.push_back(std::move(sec));
    }

    parse_pe_coff_symbols(b, img->sections_, symbol_table_offset, symbol_count, img->symbols_);

    parse_pe_base_relocations(b, img->sections_, image_base, base_reloc_dir_rva,
                              base_reloc_dir_size, img->base_relocations_);
    parse_pe_debug_directories(b, img->sections_, image_base, debug_dir_rva,
                               debug_dir_size, img->debug_directories_);
    parse_pe_tls_directory(b, img->sections_, image_base, is64, tls_dir_rva,
                           tls_dir_size, img->tls_directory_);
    parse_pe_certificates(b, certificate_table_file_offset, certificate_table_size,
                          img->certificates_);
    parse_pe_load_config_directory(b, img->sections_, image_base, is64, load_config_dir_rva,
                                   load_config_dir_size, img->load_config_directory_);
    parse_pe_runtime_functions(b, img->sections_, image_base, exception_dir_rva,
                               exception_dir_size, img->runtime_functions_);
    parse_pe_bound_imports(b, img->sections_, image_base, bound_import_dir_rva,
                           bound_import_dir_size, img->bound_imports_);
    parse_pe_resource_directory(b, img->sections_, image_base, resource_dir_rva,
                                resource_dir_size, img->resource_directory_,
                                img->resource_data_entries_);
    parse_pe_clr_header(b, img->sections_, image_base, clr_dir_rva, clr_dir_size,
                        img->clr_header_);

    if (export_dir_rva != 0 && export_dir_size >= 40) {
        const auto export_off = pe_rva_to_file_offset(img->sections_, image_base, export_dir_rva);
        if (export_off && fits_range(*export_off, 40, static_cast<std::uint64_t>(b.size()))) {
            const std::size_t ed = static_cast<std::size_t>(*export_off);
            const std::uint32_t ordinal_base = rd32(b, ed + 16, false);
            const std::uint32_t number_of_functions = rd32(b, ed + 20, false);
            const std::uint32_t number_of_names = rd32(b, ed + 24, false);
            const std::uint32_t functions_rva = rd32(b, ed + 28, false);
            const std::uint32_t names_rva = rd32(b, ed + 32, false);
            const std::uint32_t ordinals_rva = rd32(b, ed + 36, false);

            const auto functions_off = pe_rva_to_file_offset(img->sections_, image_base, functions_rva);
            const auto names_off = pe_rva_to_file_offset(img->sections_, image_base, names_rva);
            const auto ordinals_off = pe_rva_to_file_offset(img->sections_, image_base, ordinals_rva);
            std::vector<bool> named_functions;
            if (functions_off && fits_range(*functions_off, static_cast<std::uint64_t>(number_of_functions) * 4, b.size()))
                named_functions.resize(number_of_functions);
            if (functions_off && names_off && ordinals_off) {
                for (std::uint32_t i = 0; i < number_of_names; ++i) {
                    const std::uint64_t name_ptr_off = *names_off + static_cast<std::uint64_t>(i) * 4;
                    const std::uint64_t ordinal_off = *ordinals_off + static_cast<std::uint64_t>(i) * 2;
                    if (!fits_range(name_ptr_off, 4, static_cast<std::uint64_t>(b.size())) ||
                        !fits_range(ordinal_off, 2, static_cast<std::uint64_t>(b.size()))) {
                        break;
                    }

                    const std::uint32_t name_rva = rd32(b, static_cast<std::size_t>(name_ptr_off), false);
                    const std::uint16_t ordinal_index = rd16(b, static_cast<std::size_t>(ordinal_off), false);
                    if (ordinal_index >= number_of_functions) {
                        continue;
                    }

                    const auto name_off = pe_rva_to_file_offset(img->sections_, image_base, name_rva);
                    const std::uint64_t function_off = *functions_off +
                                                       static_cast<std::uint64_t>(ordinal_index) * 4;
                    if (!name_off ||
                        !fits_range(function_off, 4, static_cast<std::uint64_t>(b.size()))) {
                        continue;
                    }

                    const std::uint32_t function_rva = rd32(b, static_cast<std::size_t>(function_off), false);
                    if (function_rva == 0) continue;
                    ExportEntry entry;
                    entry.name = read_c_string(b, *name_off);
                    entry.ordinal = ordinal_base + ordinal_index;
                    entry.virtual_address = image_base + function_rva;
                    if (function_rva >= export_dir_rva &&
                        static_cast<std::uint64_t>(function_rva) <
                            static_cast<std::uint64_t>(export_dir_rva) + export_dir_size) {
                        if (const auto forwarder_off = pe_rva_to_file_offset(img->sections_, image_base, function_rva)) {
                            entry.forwarder = read_c_string(b, *forwarder_off);
                        }
                    }
                    if (!entry.name.empty()) {
                        if (ordinal_index < named_functions.size()) named_functions[ordinal_index] = true;
                        img->exports_.push_back(std::move(entry));
                    }
                }
            }
            for (std::size_t i = 0; i < named_functions.size(); ++i) {
                if (named_functions[i]) continue;
                const auto rva = rd32(b, static_cast<std::size_t>(*functions_off) + i * 4, false);
                if (rva == 0) continue;
                ExportEntry entry;
                entry.ordinal = ordinal_base + static_cast<std::uint32_t>(i);
                entry.virtual_address = checked_add_u64(image_base, rva).value_or(0);
                if (rva >= export_dir_rva && static_cast<std::uint64_t>(rva) - export_dir_rva < export_dir_size) {
                    if (const auto off = pe_rva_to_file_offset(img->sections_, image_base, rva))
                        entry.forwarder = read_c_string(b, *off);
                }
                img->exports_.push_back(std::move(entry));
            }
        }
    }

    if (import_dir_rva != 0 && import_dir_size >= 20) {
        const auto import_off = pe_rva_to_file_offset(img->sections_, image_base, import_dir_rva);
        if (import_off) {
            const std::uint64_t max_descriptors = import_dir_size / 20;
            for (std::uint64_t desc_index = 0; desc_index < max_descriptors; ++desc_index) {
                const std::uint64_t desc_off = *import_off + desc_index * 20;
                if (!fits_range(desc_off, 20, static_cast<std::uint64_t>(b.size()))) {
                    break;
                }

                const std::size_t desc = static_cast<std::size_t>(desc_off);
                const std::uint32_t original_first_thunk = rd32(b, desc + 0, false);
                const std::uint32_t name_rva = rd32(b, desc + 12, false);
                const std::uint32_t first_thunk = rd32(b, desc + 16, false);
                if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
                    break;
                }

                const auto dll_name_off = pe_rva_to_file_offset(img->sections_, image_base, name_rva);
                const std::string library = dll_name_off ? read_c_string(b, *dll_name_off) : std::string{};
                const std::uint32_t thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
                parse_pe_import_thunks(b, img->sections_, image_base, is64, library, thunk_rva,
                                       first_thunk, false, img->imports_);
            }
        }
    }

    parse_pe_delay_load_imports(b, img->sections_, image_base, is64, delay_import_dir_rva,
                                delay_import_dir_size, img->imports_);
    img->parse_gnu_debuglink_section(b, false);

    return img;
}

void PeImage::rebase_to_live_base(std::uint64_t live_base) {
    const std::uint64_t static_base = image_base_;
    const std::uint64_t bias = live_base - static_base;
    const std::uint64_t entry_rva = entry_ >= static_base ? (entry_ - static_base) : 0;

    image_base_ = live_base;
    entry_ = live_base + entry_rva;
    is_live_mapped_ = true;

    std::uint64_t max_end = 4096;
    for (Section& sec : sections_) {
        const std::uint64_t rva =
            sec.virtual_address >= static_base ? (sec.virtual_address - static_base) : 0;
        sec.virtual_address = live_base + rva;
        sec.file_offset = rva;
        sec.file_size = std::max(sec.virtual_size, sec.file_size);
        max_end = std::max(max_end, sec.file_offset + sec.file_size);
    }
    mapped_span_size_ = max_end;

    for (Symbol& sym : symbols_) {
        if (sym.virtual_address >= static_base && sym.section_index != 0) {
            sym.virtual_address += bias;
        }
    }

    for (ImportEntry& imp : imports_) {
        if (imp.address != 0) {
            imp.address += bias;
        }
    }

    for (ExportEntry& exp : exports_) {
        if (exp.virtual_address != 0) {
            exp.virtual_address += bias;
        }
    }

    for (PeDebugDirectory& dbg : debug_directories_) {
        if (dbg.address_of_raw_data != 0) {
            dbg.pointer_to_raw_data = dbg.address_of_raw_data;
        }
    }

    if (tls_directory_) {
        auto rebase_opt_va = [&](std::uint64_t& va) {
            if (va >= static_base && (va - static_base) < mapped_span_size_) {
                va += bias;
            }
        };
        rebase_opt_va(tls_directory_->raw_data_start_va);
        rebase_opt_va(tls_directory_->raw_data_end_va);
        rebase_opt_va(tls_directory_->address_of_index);
        rebase_opt_va(tls_directory_->address_of_callbacks);
        for (std::uint64_t& cb : tls_directory_->callbacks) {
            rebase_opt_va(cb);
        }
    }

    if (load_config_directory_) {
        load_config_directory_->file_offset = load_config_directory_->rva;
        auto rebase_opt_va = [&](std::uint64_t& va) {
            if (va >= static_base && (va - static_base) < mapped_span_size_) {
                va += bias;
            }
        };
        rebase_opt_va(load_config_directory_->security_cookie);
        rebase_opt_va(load_config_directory_->se_handler_table);
        rebase_opt_va(load_config_directory_->guard_cf_check_function_pointer);
        rebase_opt_va(load_config_directory_->guard_cf_dispatch_function_pointer);
        rebase_opt_va(load_config_directory_->guard_cf_function_table);
        rebase_opt_va(load_config_directory_->guard_eh_continuation_table);
    }

    for (PeRuntimeFunction& rf : runtime_functions_) {
        rf.file_offset = rf.begin_address_rva;
    }

    if (resource_directory_) {
        resource_directory_->file_offset = resource_directory_->rva;
    }

    for (PeResourceDataEntry& rde : resource_data_entries_) {
        rde.data_file_offset = rde.data_rva;
    }

    if (clr_header_) {
        clr_header_->file_offset = clr_header_->rva;
    }
}

} // namespace

namespace detail {

Result<std::unique_ptr<ImageBase>> parse_pe_image_impl(std::span<const std::uint8_t> bytes) {
    auto parsed = PeImage::parse(bytes);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::unique_ptr<ImageBase>(std::move(*parsed));
}

} // namespace detail
} // namespace peelf
