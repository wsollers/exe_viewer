#pragma once

// Unified, format-agnostic view of a parsed binary (ToDo.md Phase 1 / P1-1).
//
// PE and ELF images are parsed into concrete implementations (in binary_image.cpp)
// that callers only ever see through the IBinaryImage interface, obtained from
// parse_image(). This is the spine the GUI model and panels build on.
//
// Phase 1 populates identity (format, kind, architecture, endianness, 64-bit,
// entry point). Sections are filled in Phase 2 (P2-1); symbols/imports/exports
// arrive in Phase 3, at which point this interface grows.

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/error.hpp>

namespace peelf {

enum class Format { Unknown, PE, ELF };
enum class ImageKind { Unknown, Executable, SharedLibrary, Object, Core };
enum class Architecture {
    Unknown,
    X86,
    X86_64,
    ARM,
    ARM64,
    RISCV32,
    RISCV64,
    PowerPC,
    PowerPC64,
    MIPS32,
    MIPS64
};
enum class Endianness { Little, Big };

[[nodiscard]] std::string_view to_string(Format f) noexcept;
[[nodiscard]] std::string_view to_string(ImageKind k) noexcept;
[[nodiscard]] std::string_view to_string(Architecture a) noexcept;
[[nodiscard]] std::string_view to_string(Endianness e) noexcept;

// A section of the image. Populated from Phase 2 (P2-1); Phase-1 identity parsing
// leaves IBinaryImage::sections() empty.
struct Section {
    std::string   name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size    = 0;
    std::uint64_t file_offset     = 0;
    std::uint64_t file_size       = 0;
    bool          readable        = false;
    bool          writable        = false;
    bool          executable      = false;
};

struct Segment {
    std::uint32_t type            = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size    = 0;
    std::uint64_t file_offset     = 0;
    std::uint64_t file_size       = 0;
    bool          readable        = false;
    bool          writable        = false;
    bool          executable      = false;
};

struct Symbol {
    std::string   name;
    std::uint64_t virtual_address = 0;
    std::uint64_t size            = 0;
    std::uint8_t  binding         = 0;
    std::uint8_t  type            = 0;
    std::uint16_t section_index   = 0;
    bool          dynamic         = false;
};

struct ImportEntry {
    std::string   library;
    std::string   name;
    std::uint64_t address = 0;
    bool          delay_load = false;
};

struct PeBoundImport {
    std::uint32_t time_date_stamp = 0;
    std::uint16_t offset_module_name = 0;
    std::uint16_t forwarder_ref_count = 0;
    std::string module_name;
    std::uint64_t file_offset = 0;
};

struct PeResourceDirectoryEntry {
    std::uint32_t name_or_id = 0;
    std::uint32_t offset_to_data_or_directory = 0;
    bool name_is_string = false;
    bool data_is_directory = false;
};

struct PeResourceDirectory {
    std::uint32_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t characteristics = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint16_t named_entry_count = 0;
    std::uint16_t id_entry_count = 0;
    std::vector<PeResourceDirectoryEntry> entries;
};

struct PeResourceDataEntry {
    std::uint32_t type_id = 0;
    std::uint32_t name_id = 0;
    std::uint32_t language_id = 0;
    std::uint32_t data_rva = 0;
    std::uint32_t size = 0;
    std::uint32_t code_page = 0;
    std::uint32_t reserved = 0;
    std::uint64_t entry_file_offset = 0;
    std::uint64_t data_file_offset = 0;
};

struct ExportEntry {
    std::string   name;
    std::uint32_t ordinal = 0;
    std::uint64_t virtual_address = 0;
    std::string   forwarder;
};

struct PeBaseRelocationEntry {
    std::uint32_t page_rva = 0;
    std::uint16_t type = 0;
    std::uint16_t offset = 0;
    std::uint32_t rva = 0;
};

struct PeBaseRelocationBlock {
    std::uint32_t page_rva = 0;
    std::uint32_t block_size = 0;
    std::vector<PeBaseRelocationEntry> entries;
};

struct PeDebugDirectory {
    std::uint32_t characteristics = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t type = 0;
    std::uint32_t size_of_data = 0;
    std::uint32_t address_of_raw_data = 0;
    std::uint32_t pointer_to_raw_data = 0;
    std::uint32_t codeview_signature = 0;
    std::vector<std::uint8_t> codeview_guid;
    std::uint32_t codeview_age = 0;
    std::string codeview_pdb_path;
};

struct PeTlsDirectory {
    std::uint64_t raw_data_start_va = 0;
    std::uint64_t raw_data_end_va = 0;
    std::uint64_t address_of_index = 0;
    std::uint64_t address_of_callbacks = 0;
    std::uint32_t size_of_zero_fill = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint64_t> callbacks;
};

struct PeCertificate {
    std::uint32_t file_offset = 0;
    std::uint32_t length = 0;
    std::uint16_t revision = 0;
    std::uint16_t certificate_type = 0;
    std::vector<std::uint8_t> certificate;
};

struct PeLoadConfigDirectory {
    std::uint32_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t size = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t global_flags_clear = 0;
    std::uint32_t global_flags_set = 0;
    std::uint64_t critical_section_default_timeout = 0;
    std::uint64_t decommit_free_block_threshold = 0;
    std::uint64_t decommit_total_free_threshold = 0;
    std::uint64_t lock_prefix_table = 0;
    std::uint64_t maximum_allocation_size = 0;
    std::uint64_t virtual_memory_threshold = 0;
    std::uint64_t process_affinity_mask = 0;
    std::uint32_t process_heap_flags = 0;
    std::uint16_t csd_version = 0;
    std::uint16_t dependent_load_flags = 0;
    std::uint64_t edit_list = 0;
    std::uint64_t security_cookie = 0;
    std::uint64_t se_handler_table = 0;
    std::uint64_t se_handler_count = 0;
    std::uint64_t guard_cf_check_function_pointer = 0;
    std::uint64_t guard_cf_dispatch_function_pointer = 0;
    std::uint64_t guard_cf_function_table = 0;
    std::uint64_t guard_cf_function_count = 0;
    std::uint32_t guard_flags = 0;
};

struct PeRuntimeFunction {
    std::uint32_t begin_address_rva = 0;
    std::uint32_t end_address_rva = 0;
    std::uint32_t unwind_info_rva = 0;
    std::uint64_t file_offset = 0;
};

struct PeClrHeader {
    std::uint32_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t size = 0;
    std::uint16_t major_runtime_version = 0;
    std::uint16_t minor_runtime_version = 0;
    std::uint32_t metadata_rva = 0;
    std::uint32_t metadata_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t entry_point_token_or_rva = 0;
    std::uint32_t resources_rva = 0;
    std::uint32_t resources_size = 0;
    std::uint32_t strong_name_signature_rva = 0;
    std::uint32_t strong_name_signature_size = 0;
    std::uint32_t code_manager_table_rva = 0;
    std::uint32_t code_manager_table_size = 0;
    std::uint32_t vtable_fixups_rva = 0;
    std::uint32_t vtable_fixups_size = 0;
    std::uint32_t export_address_table_jumps_rva = 0;
    std::uint32_t export_address_table_jumps_size = 0;
    std::uint32_t managed_native_header_rva = 0;
    std::uint32_t managed_native_header_size = 0;
};

struct ElfHeader {
    std::uint8_t  elf_class = 0;
    std::uint8_t  data_encoding = 0;
    std::uint8_t  ident_version = 0;
    std::uint8_t  os_abi = 0;
    std::uint8_t  abi_version = 0;
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint32_t version = 0;
    std::uint64_t entry = 0;
    std::uint64_t program_header_offset = 0;
    std::uint64_t section_header_offset = 0;
    std::uint32_t flags = 0;
    std::uint16_t header_size = 0;
    std::uint16_t program_header_entry_size = 0;
    std::uint16_t program_header_count = 0;
    std::uint16_t section_header_entry_size = 0;
    std::uint16_t section_header_count = 0;
    std::uint16_t section_name_string_table_index = 0;
};

struct ElfProgramHeader {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;
    std::uint64_t alignment = 0;
};

struct ElfSectionHeader {
    std::string   name;
    std::uint32_t name_offset = 0;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t address_alignment = 0;
    std::uint64_t entry_size = 0;
};

struct ElfSymbol {
    std::string   name;
    std::uint32_t name_offset = 0;
    std::uint8_t  info = 0;
    std::uint8_t  other = 0;
    std::uint8_t  binding = 0;
    std::uint8_t  type = 0;
    std::uint8_t  visibility = 0;
    std::uint16_t section_index = 0;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    bool          dynamic = false;
};

struct ElfDynamicEntry {
    std::uint64_t tag = 0;
    std::uint64_t value = 0;
    std::string   needed_library;
};

struct ElfRelocation {
    std::string   section_name;
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::uint64_t symbol_index = 0;
    std::uint64_t type = 0;
    std::int64_t  addend = 0;
    bool          has_addend = false;
};

struct ElfNote {
    std::string name;
    std::uint32_t type = 0;
    std::vector<std::uint8_t> descriptor;
    bool from_program_header = false;
};

struct ElfSysvHashTable {
    std::string section_name;
    std::uint32_t bucket_count = 0;
    std::uint32_t chain_count = 0;
    std::vector<std::uint32_t> buckets;
    std::vector<std::uint32_t> chains;
};

struct ElfGnuHashTable {
    std::string section_name;
    std::uint32_t bucket_count = 0;
    std::uint32_t symbol_offset = 0;
    std::uint32_t bloom_word_count = 0;
    std::uint32_t bloom_shift = 0;
    std::vector<std::uint64_t> bloom;
    std::vector<std::uint32_t> buckets;
    std::vector<std::uint32_t> chains;
};

// Format-agnostic interface over a parsed binary. Concrete PE/ELF types are
// internal to binary_image.cpp; callers obtain one via parse_image().
class IBinaryImage {
public:
    virtual ~IBinaryImage() = default;

    [[nodiscard]] virtual Format        format()       const noexcept = 0;
    [[nodiscard]] virtual ImageKind     kind()         const noexcept = 0;
    [[nodiscard]] virtual Architecture  architecture() const noexcept = 0;
    [[nodiscard]] virtual Endianness    endianness()   const noexcept = 0;
    [[nodiscard]] virtual bool          is_64bit()     const noexcept = 0;
    [[nodiscard]] virtual std::uint64_t image_base()   const noexcept = 0;
    // Entry-point virtual address (ELF e_entry; PE ImageBase + AddressOfEntryPoint).
    [[nodiscard]] virtual std::uint64_t entry_point()  const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Section>& sections() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Segment>& segments() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Symbol>& symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ImportEntry>& imports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ExportEntry>& exports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeBaseRelocationBlock>& pe_base_relocations() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeDebugDirectory>& pe_debug_directories() const noexcept = 0;
    [[nodiscard]] virtual const PeTlsDirectory* pe_tls_directory() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeCertificate>& pe_certificates() const noexcept = 0;
    [[nodiscard]] virtual const PeLoadConfigDirectory* pe_load_config_directory() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeRuntimeFunction>& pe_runtime_functions() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeBoundImport>& pe_bound_imports() const noexcept = 0;
    [[nodiscard]] virtual const PeResourceDirectory* pe_resource_directory() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<PeResourceDataEntry>& pe_resource_data_entries() const noexcept = 0;
    [[nodiscard]] virtual const PeClrHeader* pe_clr_header() const noexcept = 0;
    [[nodiscard]] virtual const ElfHeader* elf_header() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfProgramHeader>& elf_program_headers() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfSectionHeader>& elf_section_headers() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfSymbol>& elf_symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfDynamicEntry>& elf_dynamic_entries() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfRelocation>& elf_relocations() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfNote>& elf_notes() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept = 0;
    [[nodiscard]] virtual std::string_view elf_interpreter() const noexcept = 0;
    [[nodiscard]] virtual std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept = 0;
    [[nodiscard]] virtual std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept = 0;
};

// Detect the container format from the leading magic bytes.
[[nodiscard]] Format detect_format(std::span<const std::uint8_t> bytes) noexcept;

// Parse bytes into a concrete PE/ELF image behind the IBinaryImage interface.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_image(std::span<const std::uint8_t> bytes);

} // namespace peelf
