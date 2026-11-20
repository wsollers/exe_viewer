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

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/error.hpp>

namespace peelf {

enum class Format { Unknown, PE, ELF, MachO };
using BinaryFormat = Format;
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
    std::uint64_t raw_flags       = 0;
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

using SectionInfo = Section;
using SegmentInfo = Segment;
using SymbolInfo  = Symbol;

struct BinarySliceDescriptor {
    std::size_t   slice_index      = 0;
    std::uint32_t cpu_type         = 0;
    std::uint32_t cpu_subtype      = 0;
    Architecture  arch             = Architecture::Unknown;
    std::uint8_t  bitness          = 0;
    Endianness    endianness       = Endianness::Little;
    std::string   arch_name{};
    std::uint64_t container_offset = 0;
    std::uint64_t slice_size       = 0;
    std::uint32_t align_log2       = 0;
};

struct BinaryContainerInfo {
    Format format = Format::Unknown;
    bool is_universal_container = false;
    std::vector<BinarySliceDescriptor> slices{};
};

using UniversalBinaryInfo = BinaryContainerInfo;

struct BinaryOpenOptions {
    std::optional<std::size_t> selected_slice_index{};
    std::string preferred_arch_name{};
    std::optional<Architecture> preferred_architecture{};
};

struct ImportEntry {
    std::string   library;
    std::string   name;
    std::uint16_t ordinal = 0;
    std::uint64_t address = 0;
    bool          import_by_ordinal = false;
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
    std::string name{};
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
    std::uint64_t guard_eh_continuation_table = 0;
    std::uint64_t guard_eh_continuation_count = 0;
};

struct PeDataDirectory {
    std::uint32_t index = 0;
    std::string name{};
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct PeHeader {
    std::uint16_t machine = 0;
    std::uint16_t number_of_sections = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint32_t symbol_table_offset = 0;
    std::uint32_t number_of_symbols = 0;
    std::uint16_t optional_header_size = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t optional_magic = 0;
    std::uint32_t entry_point_rva = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint64_t stack_reserve = 0;
    std::uint64_t stack_commit = 0;
    std::uint64_t heap_reserve = 0;
    std::uint64_t heap_commit = 0;
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
    std::uint32_t effective_program_header_count = 0;
    std::uint32_t effective_section_header_count = 0;
    std::uint32_t effective_shstrndx = 0;
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
    std::string   string_value;
};

struct ElfRelocation {
    std::string   section_name;
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::uint64_t symbol_index = 0;
    std::uint64_t type = 0;
    std::int64_t  addend = 0;
    bool          has_addend = false;
    std::string   symbol_name;
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

struct GnuDebugLink {
    std::string filename;
    std::uint32_t crc32 = 0;
};

struct MachOHeader {
    std::uint32_t magic       = 0;
    std::uint32_t cpu_type    = 0;
    std::uint32_t cpu_subtype = 0;
    std::uint32_t file_type   = 0;
    std::uint32_t ncmds       = 0;
    std::uint32_t sizeofcmds  = 0;
    std::uint32_t flags       = 0;
    std::uint32_t reserved    = 0;
    bool          is_64bit    = false;
    bool          is_arm64e   = false;
    bool          ptrauth_abi = false;
    std::uint8_t  ptrauth_version = 0;

    [[nodiscard]] constexpr bool has_pie() const noexcept {
        return (flags & 0x00200000u) != 0u; // MH_PIE
    }
    [[nodiscard]] constexpr bool allows_stack_execution() const noexcept {
        return (flags & 0x00020000u) != 0u; // MH_ALLOW_STACK_EXECUTION
    }
    [[nodiscard]] constexpr bool has_no_heap_execution() const noexcept {
        return (flags & 0x01000000u) != 0u; // MH_NO_HEAP_EXECUTION
    }
    [[nodiscard]] constexpr bool has_twolevel_namespace() const noexcept {
        return (flags & 0x00000080u) != 0u; // MH_TWOLEVEL
    }
    [[nodiscard]] constexpr bool is_root_safe() const noexcept {
        return (flags & 0x00040000u) != 0u; // MH_ROOT_SAFE
    }
    [[nodiscard]] constexpr bool is_setuid_safe() const noexcept {
        return (flags & 0x00080000u) != 0u; // MH_SETUID_SAFE
    }
    [[nodiscard]] constexpr bool is_app_extension_safe() const noexcept {
        return (flags & 0x02000000u) != 0u; // MH_APP_EXTENSION_SAFE
    }
};

struct MachOLoadCommandInfo {
    std::uint32_t cmd              = 0;
    std::uint32_t cmdsize          = 0;
    std::uint64_t slice_offset     = 0;
    std::uint64_t container_offset = 0;
};

struct MachOSection {
    std::string   section_name;
    std::string   segment_name;
    std::string   full_name;
    std::uint64_t virtual_address   = 0;
    std::uint64_t virtual_size      = 0;
    std::uint64_t file_offset       = 0; // Container-absolute (0 for zero-fill)
    std::uint64_t slice_file_offset = 0; // Raw section offset inside slice
    std::uint64_t file_size         = 0; // 0 for S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL
    std::uint32_t align_log2        = 0;
    std::uint32_t reloff            = 0;
    std::uint32_t nreloc            = 0;
    std::uint32_t flags             = 0;
    std::uint32_t reserved1         = 0;
    std::uint32_t reserved2         = 0;
    std::uint32_t reserved3         = 0;
    bool          readable          = false;
    bool          writable          = false;
    bool          executable        = false;
    bool          is_zerofill       = false;

    [[nodiscard]] constexpr std::uint8_t section_type() const noexcept {
        return static_cast<std::uint8_t>(flags & 0xFFu);
    }
    [[nodiscard]] constexpr std::uint32_t section_attributes() const noexcept {
        return flags & 0xFFFFFF00u;
    }
};

struct MachOSegmentCommand {
    std::string   name;
    std::uint64_t virtual_address   = 0;
    std::uint64_t virtual_size      = 0;
    std::uint64_t file_offset       = 0; // Container-absolute
    std::uint64_t slice_file_offset = 0; // Raw segment fileoff inside slice
    std::uint64_t file_size         = 0;
    std::uint32_t maxprot           = 0;
    std::uint32_t initprot          = 0;
    std::uint32_t nsects            = 0;
    std::uint32_t flags             = 0;
    std::vector<MachOSection> sections{};

    [[nodiscard]] constexpr bool readable() const noexcept { return (initprot & 0x1u) != 0u; }
    [[nodiscard]] constexpr bool writable() const noexcept { return (initprot & 0x2u) != 0u; }
    [[nodiscard]] constexpr bool executable() const noexcept { return (initprot & 0x4u) != 0u; }
    [[nodiscard]] constexpr bool init_is_wx() const noexcept {
        return (initprot & 0x6u) == 0x6u;
    }
    [[nodiscard]] constexpr bool max_is_wx() const noexcept {
        return (maxprot & 0x6u) == 0x6u;
    }
    [[nodiscard]] bool is_pagezero() const noexcept {
        return name == "__PAGEZERO";
    }
};

struct MachODylibDependency {
    std::uint32_t cmd                   = 0;
    std::uint16_t ordinal               = 0; // 1-based ordinal for imported dylibs; 0 for LC_ID_DYLIB
    std::string   name;
    std::uint32_t timestamp             = 0;
    std::uint32_t current_version       = 0;
    std::uint32_t compatibility_version = 0;
    bool          weak                  = false;
    bool          reexport              = false;
    bool          lazy                  = false;
    bool          upward                = false;
};

struct MachORpathEntry {
    std::string   path;
    std::uint64_t slice_offset     = 0;
    std::uint64_t container_offset = 0;
};

struct MachOSymbol {
    std::string   name;
    std::uint32_t string_offset       = 0;
    std::uint8_t  n_type              = 0;
    std::uint8_t  n_sect              = 0;
    std::uint16_t n_desc              = 0;
    std::uint64_t value               = 0;
    std::uint8_t  library_ordinal     = 0;
    std::string   library_name;
    bool          is_stab             = false;
    bool          is_external         = false;
    bool          is_private_external = false;
    bool          is_undefined        = false;
    bool          is_weak_def         = false;
    bool          is_weak_ref         = false;
    bool          is_thumb            = false;
};

struct MachOSymtabInfo {
    bool          present          = false;
    std::uint32_t symoff           = 0;
    std::uint64_t container_symoff = 0;
    std::uint32_t nsyms            = 0;
    std::uint32_t stroff           = 0;
    std::uint64_t container_stroff = 0;
    std::uint32_t strsize          = 0;
};

struct MachODysymtabInfo {
    bool          present                  = false;
    std::uint32_t ilocalsym                = 0;
    std::uint32_t nlocalsym                = 0;
    std::uint32_t iextdefsym               = 0;
    std::uint32_t nextdefsym               = 0;
    std::uint32_t iundefsym                = 0;
    std::uint32_t nundefsym                = 0;
    std::uint32_t indirectsymoff           = 0;
    std::uint64_t container_indirectsymoff = 0;
    std::uint32_t nindirectsyms            = 0;
};

struct MachOBuildToolVersion {
    std::uint32_t tool    = 0;
    std::uint32_t version = 0;
};

struct MachOBuildVersion {
    std::uint32_t cmd                      = 0;
    std::uint32_t platform                 = 0;
    std::uint32_t minos                    = 0;
    std::uint32_t sdk                      = 0;
    bool          from_version_min_command = false;
    std::vector<MachOBuildToolVersion> tools{};
};

struct MachOEncryptionInfo {
    bool          is_64bit           = false;
    std::uint32_t cryptoff           = 0;
    std::uint64_t container_cryptoff = 0;
    std::uint32_t cryptsize          = 0;
    std::uint32_t cryptid            = 0;
    std::uint32_t pad                = 0;

    [[nodiscard]] constexpr bool is_encrypted() const noexcept { return cryptid != 0u; }
};

struct MachOLinkeditRange {
    bool          present          = false;
    std::uint32_t cmd              = 0;
    std::uint32_t slice_offset     = 0;
    std::uint64_t container_offset = 0;
    std::uint32_t size             = 0;
};

struct MachODyldInfoRanges {
    bool               has_dyld_info           = false;
    bool               dyld_info_only          = false;
    std::uint32_t      rebase_off              = 0;
    std::uint64_t      container_rebase_off    = 0;
    std::uint32_t      rebase_size             = 0;
    std::uint32_t      bind_off                = 0;
    std::uint64_t      container_bind_off      = 0;
    std::uint32_t      bind_size               = 0;
    std::uint32_t      weak_bind_off           = 0;
    std::uint64_t      container_weak_bind_off = 0;
    std::uint32_t      weak_bind_size          = 0;
    std::uint32_t      lazy_bind_off           = 0;
    std::uint64_t      container_lazy_bind_off = 0;
    std::uint32_t      lazy_bind_size          = 0;
    std::uint32_t      export_off              = 0;
    std::uint64_t      container_export_off    = 0;
    std::uint32_t      export_size             = 0;
    MachOLinkeditRange exports_trie{};
    MachOLinkeditRange chained_fixups{};
    MachOLinkeditRange function_starts{};
    MachOLinkeditRange data_in_code{};
};

// Structural summary of an embedded `LC_CODE_SIGNATURE` SuperBlob / CodeDirectory.
// Explicitly separates structural blob presence (`superblob_valid` / `has_code_directory` /
// `has_cms_blob`) from OS cryptographic trust-chain verification (`cryptographically_verified`).
struct MachOCodeSignatureInfo {
    bool          present                     = false;
    std::uint32_t slice_offset                = 0;
    std::uint64_t container_offset            = 0;
    std::uint32_t data_size                   = 0;
    bool          superblob_valid             = false;
    std::uint32_t superblob_magic             = 0;
    std::uint32_t superblob_length            = 0;
    std::uint32_t blob_count                  = 0;
    bool          has_code_directory          = false;
    std::uint32_t cd_version                  = 0;
    std::uint32_t cd_flags                    = 0;
    std::uint32_t n_special_slots             = 0;
    std::uint32_t n_code_slots                = 0;
    std::uint32_t code_limit                  = 0;
    std::uint8_t  hash_size                   = 0;
    std::uint8_t  hash_type                   = 0;
    std::uint8_t  platform                    = 0;
    std::uint8_t  page_size_log2              = 0;
    std::string   identifier{};
    std::string   team_id{};
    bool          has_requirements_blob       = false;
    bool          has_entitlements_blob       = false;
    bool          has_der_entitlements_blob   = false;
    bool          has_cms_blob                = false;
    std::uint32_t cms_blob_size               = 0;
    std::uint32_t cms_payload_size            = 0;
    bool          has_nonempty_cms_signature  = false;
    bool          cryptographically_verified  = false;

    [[nodiscard]] constexpr bool is_adhoc() const noexcept {
        return (cd_flags & 0x00000002u) != 0u; // CS_ADHOC
    }
    [[nodiscard]] constexpr bool has_hardened_runtime() const noexcept {
        return (cd_flags & 0x00010000u) != 0u; // CS_RUNTIME
    }
    [[nodiscard]] constexpr bool is_linker_signed() const noexcept {
        return (cd_flags & 0x00020000u) != 0u; // CS_LINKER_SIGNED
    }
};

// Format-agnostic interface over a parsed binary. Concrete PE/ELF/Mach-O types
// sit behind this interface; format-specific accessors carry safe empty defaults
// so subclasses and test mocks need not implement unrelated formats.
class IBinaryImage {
public:
    virtual ~IBinaryImage() = default;

    [[nodiscard]] virtual Format        format()       const noexcept = 0;
    [[nodiscard]] virtual ImageKind     kind()         const noexcept = 0;
    [[nodiscard]] virtual Architecture  architecture() const noexcept = 0;
    [[nodiscard]] virtual Endianness    endianness()   const noexcept = 0;
    [[nodiscard]] virtual bool          is_64bit()     const noexcept = 0;
    [[nodiscard]] virtual std::uint64_t image_base()   const noexcept = 0;
    // Entry-point virtual address (ELF e_entry; PE ImageBase + AddressOfEntryPoint; Mach-O LC_MAIN/LC_UNIXTHREAD).
    [[nodiscard]] virtual std::uint64_t entry_point()  const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Section>& sections() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Segment>& segments() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Symbol>& symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ImportEntry>& imports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ExportEntry>& exports() const noexcept = 0;

    // Container / Universal slice provenance (container-absolute offset discipline).
    [[nodiscard]] virtual bool          is_universal_slice()     const noexcept { return false; }
    [[nodiscard]] virtual std::size_t   container_slice_index()  const noexcept { return 0; }
    [[nodiscard]] virtual std::uint64_t container_slice_offset() const noexcept { return 0; }
    [[nodiscard]] virtual std::uint64_t container_slice_size()   const noexcept { return 0; }
    [[nodiscard]] virtual std::optional<std::uint64_t> slice_relative_offset(
        std::uint64_t container_file_offset) const noexcept;
    [[nodiscard]] virtual std::optional<std::uint64_t> container_file_offset(
        std::uint64_t slice_rel_offset) const noexcept;

    [[nodiscard]] virtual const GnuDebugLink* gnu_debuglink() const noexcept { return nullptr; }

    // PE metadata accessors (safe empty defaults for non-PE images).
    [[nodiscard]] virtual const PeHeader* pe_header() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<PeDataDirectory>& pe_data_directories() const noexcept;
    [[nodiscard]] virtual const std::vector<PeBaseRelocationBlock>& pe_base_relocations() const noexcept;
    [[nodiscard]] virtual const std::vector<PeDebugDirectory>& pe_debug_directories() const noexcept;
    [[nodiscard]] virtual const PeTlsDirectory* pe_tls_directory() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<PeCertificate>& pe_certificates() const noexcept;
    [[nodiscard]] virtual const PeLoadConfigDirectory* pe_load_config_directory() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<PeRuntimeFunction>& pe_runtime_functions() const noexcept;
    [[nodiscard]] virtual const std::vector<PeBoundImport>& pe_bound_imports() const noexcept;
    [[nodiscard]] virtual const PeResourceDirectory* pe_resource_directory() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<PeResourceDataEntry>& pe_resource_data_entries() const noexcept;
    [[nodiscard]] virtual const PeClrHeader* pe_clr_header() const noexcept { return nullptr; }

    // ELF metadata accessors (safe empty defaults for non-ELF images).
    [[nodiscard]] virtual const ElfHeader* elf_header() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<ElfProgramHeader>& elf_program_headers() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfSectionHeader>& elf_section_headers() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfSymbol>& elf_symbols() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfDynamicEntry>& elf_dynamic_entries() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfRelocation>& elf_relocations() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfNote>& elf_notes() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept;
    [[nodiscard]] virtual const std::vector<ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept;
    [[nodiscard]] virtual std::string_view elf_interpreter() const noexcept { return {}; }

    // Mach-O metadata accessors (safe empty defaults for non-Mach-O images).
    [[nodiscard]] virtual const MachOHeader* macho_header() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<MachOLoadCommandInfo>& macho_load_commands() const noexcept;
    [[nodiscard]] virtual const std::vector<MachOSegmentCommand>& macho_segments() const noexcept;
    [[nodiscard]] virtual const std::vector<MachOSection>& macho_sections() const noexcept;
    [[nodiscard]] virtual const std::vector<MachOSymbol>& macho_symbols() const noexcept;
    [[nodiscard]] virtual const MachOSymtabInfo* macho_symtab() const noexcept { return nullptr; }
    [[nodiscard]] virtual const MachODysymtabInfo* macho_dysymtab() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<MachODylibDependency>& macho_dylibs() const noexcept;
    [[nodiscard]] virtual const MachODylibDependency* macho_id_dylib() const noexcept { return nullptr; }
    [[nodiscard]] virtual const std::vector<MachORpathEntry>& macho_rpaths() const noexcept;
    [[nodiscard]] virtual std::string_view macho_dylinker() const noexcept { return {}; }
    [[nodiscard]] virtual std::optional<std::array<std::uint8_t, 16>> macho_uuid() const noexcept {
        return std::nullopt;
    }
    [[nodiscard]] virtual std::string_view macho_uuid_string() const noexcept { return {}; }
    [[nodiscard]] virtual std::optional<std::uint64_t> macho_source_version() const noexcept {
        return std::nullopt;
    }
    [[nodiscard]] virtual const std::vector<MachOBuildVersion>& macho_build_versions() const noexcept;
    [[nodiscard]] virtual const MachOEncryptionInfo* macho_encryption_info() const noexcept {
        return nullptr;
    }
    [[nodiscard]] virtual const MachODyldInfoRanges* macho_dyld_info() const noexcept {
        return nullptr;
    }
    [[nodiscard]] virtual const MachOCodeSignatureInfo* macho_code_signature() const noexcept {
        return nullptr;
    }

    [[nodiscard]] virtual std::span<const std::string> parse_warnings() const noexcept {
        return {};
    }
    [[nodiscard]] virtual std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept = 0;
    [[nodiscard]] virtual std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept = 0;

    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_va(
        std::uint64_t file_offset) const noexcept {
        return file_offset_to_virtual_address(file_offset);
    }
    [[nodiscard]] std::optional<std::uint64_t> va_to_file_offset(
        std::uint64_t virtual_address) const noexcept {
        return virtual_address_to_file_offset(virtual_address);
    }

    [[nodiscard]] virtual Result<std::vector<std::uint8_t>> read_bytes_at_offset(
        std::uint64_t file_offset,
        std::size_t size) const;
    [[nodiscard]] virtual Result<std::vector<std::uint8_t>> read_bytes_at_va(
        std::uint64_t virtual_address,
        std::size_t size) const;
};

// Detect the container format from the leading magic bytes (disambiguating Universal
// Mach-O 0xCAFEBABE containers from Java .class files).
[[nodiscard]] Format detect_format(std::span<const std::uint8_t> bytes) noexcept;

// Inspect a thin binary or Universal Mach-O container and enumerate available slices.
[[nodiscard]] Result<BinaryContainerInfo> inspect_binary_container(
    std::span<const std::uint8_t> bytes);

// Open a thin binary or selected Universal Mach-O slice behind IBinaryImage.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> open_binary_image(
    std::span<const std::uint8_t> bytes,
    const BinaryOpenOptions& options = {});

// Parse bytes into a concrete PE/ELF/Mach-O image behind the IBinaryImage interface.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_image(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_image(
    std::span<const std::uint8_t> bytes,
    const BinaryOpenOptions& options);

// Parse an on-disk PE/ELF file and rebase all virtual addresses and mapped section offsets
// to a live runtime load base (`live_base`), so window offset `off` maps to `live_base + off`.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_rebased_image(
    std::span<const std::uint8_t> file_bytes,
    std::uint64_t live_base);

// Parse an already memory-mapped PE/ELF image snapshot read from `[live_base, live_base + size)`.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_mapped_image(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base);

// Normalize an in-memory mapped PE snapshot so file-layout parsers (such as PeParser/PeImage)
// can inspect headers, sections, exports, and imports directly at their mapped RVA offsets.
[[nodiscard]] std::vector<std::uint8_t> normalize_mapped_pe_for_file_parsers(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base);

} // namespace peelf
