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
};

struct ExportEntry {
    std::string   name;
    std::uint32_t ordinal = 0;
    std::uint64_t virtual_address = 0;
    std::string   forwarder;
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
    // Entry-point virtual address (ELF e_entry; PE ImageBase + AddressOfEntryPoint).
    [[nodiscard]] virtual std::uint64_t entry_point()  const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Section>& sections() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Segment>& segments() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<Symbol>& symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ImportEntry>& imports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ExportEntry>& exports() const noexcept = 0;
    [[nodiscard]] virtual const ElfHeader* elf_header() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfProgramHeader>& elf_program_headers() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfSectionHeader>& elf_section_headers() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfSymbol>& elf_symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfDynamicEntry>& elf_dynamic_entries() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ElfRelocation>& elf_relocations() const noexcept = 0;
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
