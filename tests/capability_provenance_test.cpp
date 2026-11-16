#include "peelf/binary_diff.hpp"
#include "peelf/binary_image.hpp"
#include "peelf/capabilities.hpp"
#include "peelf/capability_matrix.hpp"
#include "peelf/process.hpp"
#include "peelf/provenance.hpp"
#include "peelf/security_audit.hpp"

#include "model/binary_model.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

void write_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 2] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 3] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

void write_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    write_u32_le(buf, off, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
    write_u32_le(buf, off + 4u, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFull));
}

// Builds a valid minimal ELF64 little-endian x86_64 image with optional `.note.gnu.build-id`
// and configurable `EI_OSABI` + exported symbol in `.dynsym`.
[[nodiscard]] std::vector<std::uint8_t> make_synthetic_elf64_with_build_id(
    std::span<const std::uint8_t> build_id,
    std::uint8_t osabi = 0u,
    std::uint8_t code_marker = 0x90u) {
    std::vector<std::uint8_t> img(0x2000u, 0u);

    // ELF64 header at 0x00
    img[0] = 0x7Fu;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 2u;      // ELFCLASS64
    img[5] = 1u;      // ELFDATA2LSB
    img[6] = 1u;      // EV_CURRENT
    img[7] = osabi;   // EI_OSABI
    write_u16_le(img, 16u, 3u);        // ET_DYN
    write_u16_le(img, 18u, 62u);       // EM_X86_64
    write_u32_le(img, 20u, 1u);        // EV_CURRENT
    write_u64_le(img, 24u, 0x1000u);   // e_entry
    write_u64_le(img, 32u, 64u);       // e_phoff
    write_u64_le(img, 40u, 0x1800u);   // e_shoff
    write_u16_le(img, 52u, 64u);       // e_ehsize
    write_u16_le(img, 54u, 56u);       // e_phentsize
    write_u16_le(img, 56u, build_id.empty() ? 2u : 3u);  // e_phnum
    write_u16_le(img, 58u, 64u);       // e_shentsize
    write_u16_le(img, 60u, 6u);        // e_shnum
    write_u16_le(img, 62u, 5u);        // e_shstrndx

    // Program header 0: PT_LOAD covering [0x0, 0x1000) R
    write_u32_le(img, 64u + 0u, 1u);   // PT_LOAD
    write_u32_le(img, 64u + 4u, 4u);   // PF_R
    write_u64_le(img, 64u + 8u, 0u);   // p_offset
    write_u64_le(img, 64u + 16u, 0u);  // p_vaddr
    write_u64_le(img, 64u + 24u, 0u);  // p_paddr
    write_u64_le(img, 64u + 32u, 0x1000u);
    write_u64_le(img, 64u + 40u, 0x1000u);
    write_u64_le(img, 64u + 48u, 0x1000u);

    // Program header 1: PT_LOAD covering [0x1000, 0x1100) R-X (.text)
    const std::size_t ph1 = 64u + 56u;
    write_u32_le(img, ph1 + 0u, 1u);   // PT_LOAD
    write_u32_le(img, ph1 + 4u, 5u);   // PF_R | PF_X
    write_u64_le(img, ph1 + 8u, 0x1000u);
    write_u64_le(img, ph1 + 16u, 0x1000u);
    write_u64_le(img, ph1 + 24u, 0x1000u);
    write_u64_le(img, ph1 + 32u, 0x100u);
    write_u64_le(img, ph1 + 40u, 0x100u);
    write_u64_le(img, ph1 + 48u, 0x1000u);

    // Note payload at 0x200
    std::size_t note_total = 0u;
    if (!build_id.empty()) {
        const std::size_t note_off = 0x200u;
        write_u32_le(img, note_off + 0u, 4u);  // namesz ("GNU\0")
        write_u32_le(img, note_off + 4u, static_cast<std::uint32_t>(build_id.size()));
        write_u32_le(img, note_off + 8u, 3u);  // NT_GNU_BUILD_ID
        img[note_off + 12u] = 'G';
        img[note_off + 13u] = 'N';
        img[note_off + 14u] = 'U';
        img[note_off + 15u] = '\0';
        std::copy(build_id.begin(),
                  build_id.end(),
                  img.begin() + static_cast<std::ptrdiff_t>(note_off + 16u));
        const std::size_t padded_desc = (build_id.size() + 3u) & ~std::size_t{3u};
        note_total = 16u + padded_desc;

        const std::size_t ph2 = 64u + 112u;
        write_u32_le(img, ph2 + 0u, 4u);  // PT_NOTE
        write_u32_le(img, ph2 + 4u, 4u);  // PF_R
        write_u64_le(img, ph2 + 8u, note_off);
        write_u64_le(img, ph2 + 16u, note_off);
        write_u64_le(img, ph2 + 24u, note_off);
        write_u64_le(img, ph2 + 32u, note_total);
        write_u64_le(img, ph2 + 40u, note_total);
        write_u64_le(img, ph2 + 48u, 4u);
    }

    // .dynstr at 0x300
    const std::string dynstr = std::string("\0exported_fn\0", 13u);
    std::memcpy(img.data() + 0x300u, dynstr.data(), dynstr.size());

    // .dynsym at 0x340 (2 entries x 24 bytes: STN_UNDEF + exported_fn)
    const std::size_t sym1 = 0x340u + 24u;
    write_u32_le(img, sym1 + 0u, 1u);       // st_name ("exported_fn")
    img[sym1 + 4u] = 0x12u;                 // STB_GLOBAL | STT_FUNC
    img[sym1 + 5u] = 0u;
    write_u16_le(img, sym1 + 6u, 1u);       // st_shndx (.text = section 1)
    write_u64_le(img, sym1 + 8u, 0x1000u);  // st_value
    write_u64_le(img, sym1 + 16u, 16u);     // st_size

    // .text at 0x1000: push rbp; mov rbp, rsp; marker; call 0x1020; pop rbp; ret
    std::fill(img.begin() + 0x1000u, img.begin() + 0x1040u, static_cast<std::uint8_t>(0x90u));
    img[0x1000u + 0u] = 0x55u;
    img[0x1000u + 1u] = 0x48u;
    img[0x1000u + 2u] = 0x89u;
    img[0x1000u + 3u] = 0xE5u;
    img[0x1000u + 4u] = code_marker;
    img[0x1000u + 5u] = 0xE8u;  // call +0x16 -> 0x1020 (next IP = 0x100A)
    write_u32_le(img, 0x1000u + 6u, 0x16u);
    img[0x1000u + 10u] = 0x5Du;
    img[0x1000u + 11u] = 0xC3u;
    // Unsymbolized second function at 0x1020 for heuristic discovery test
    img[0x1000u + 0x20u] = 0x55u;
    img[0x1000u + 0x21u] = 0x48u;
    img[0x1000u + 0x22u] = 0x89u;
    img[0x1000u + 0x23u] = 0xE5u;
    img[0x1000u + 0x24u] = 0x5Du;
    img[0x1000u + 0x25u] = 0xC3u;

    // .shstrtab at 0x1700
    const char shstr[] =
        "\0.text\0.note.gnu.build-id\0.dynsym\0.dynstr\0.shstrtab\0";
    std::memcpy(img.data() + 0x1700u, shstr, sizeof(shstr) - 1u);

    auto write_shdr = [&](std::size_t idx,
                          std::uint32_t sh_name,
                          std::uint32_t sh_type,
                          std::uint64_t sh_flags,
                          std::uint64_t sh_addr,
                          std::uint64_t sh_offset,
                          std::uint64_t sh_size,
                          std::uint32_t sh_link,
                          std::uint64_t sh_entsize) {
        const std::size_t base = 0x1800u + idx * 64u;
        write_u32_le(img, base + 0u, sh_name);
        write_u32_le(img, base + 4u, sh_type);
        write_u64_le(img, base + 8u, sh_flags);
        write_u64_le(img, base + 16u, sh_addr);
        write_u64_le(img, base + 24u, sh_offset);
        write_u64_le(img, base + 32u, sh_size);
        write_u32_le(img, base + 40u, sh_link);
        write_u64_le(img, base + 48u, 8u);
        write_u64_le(img, base + 56u, sh_entsize);
    };

    // [1] .text (name off 1)
    write_shdr(1u, 1u, 1u /*SHT_PROGBITS*/, 6u /*ALLOC|EXEC*/, 0x1000u, 0x1000u, 0x100u, 0u, 0u);
    // [2] .note.gnu.build-id (name off 7)
    write_shdr(2u, 7u, 7u /*SHT_NOTE*/, 2u /*ALLOC*/, 0x200u, 0x200u, note_total, 0u, 0u);
    // [3] .dynsym (name off 26) -> link to [4] .dynstr
    write_shdr(3u, 26u, 11u /*SHT_DYNSYM*/, 2u /*ALLOC*/, 0x340u, 0x340u, 48u, 4u, 24u);
    // [4] .dynstr (name off 34)
    write_shdr(4u, 34u, 3u /*SHT_STRTAB*/, 2u /*ALLOC*/, 0x300u, 0x300u, dynstr.size(), 0u, 0u);
    // [5] .shstrtab (name off 42)
    write_shdr(5u, 42u, 3u /*SHT_STRTAB*/, 0u, 0u, 0x1700u, sizeof(shstr) - 1u, 0u, 0u);

    return img;
}

// Builds a minimal PE32+ (64-bit) image with a CodeView RSDS PDB70 debug directory entry.
[[nodiscard]] std::vector<std::uint8_t> make_synthetic_pe64_with_rsds(
    std::array<std::uint8_t, 16> pdb_guid,
    std::uint32_t pdb_age,
    std::uint32_t timestamp) {
    std::vector<std::uint8_t> pe(0x1000u, 0u);
    pe[0] = 'M';
    pe[1] = 'Z';
    write_u32_le(pe, 0x3Cu, 0x80u);  // e_lfanew

    // PE\0\0 signature at 0x80
    pe[0x80u] = 'P';
    pe[0x81u] = 'E';
    write_u16_le(pe, 0x84u, 0x8664u);     // IMAGE_FILE_MACHINE_AMD64
    write_u16_le(pe, 0x86u, 2u);          // NumberOfSections = 2 (.text, .rdata)
    write_u32_le(pe, 0x88u, timestamp);   // TimeDateStamp
    write_u16_le(pe, 0x94u, 0xF0u);       // SizeOfOptionalHeader (PE32+)
    write_u16_le(pe, 0x96u, 0x0022u);     // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // OptionalHeader64 at 0x98
    const std::size_t opt = 0x98u;
    write_u16_le(pe, opt + 0u, 0x20Bu);          // PE32+
    write_u32_le(pe, opt + 16u, 0x1000u);        // AddressOfEntryPoint
    write_u64_le(pe, opt + 24u, 0x140000000ull); // ImageBase
    write_u32_le(pe, opt + 32u, 0x1000u);        // SectionAlignment
    write_u32_le(pe, opt + 36u, 0x200u);         // FileAlignment
    write_u32_le(pe, opt + 56u, 0x3000u);        // SizeOfImage
    write_u32_le(pe, opt + 60u, 0x200u);         // SizeOfHeaders
    write_u16_le(pe, opt + 68u, 3u);             // IMAGE_SUBSYSTEM_WINDOWS_CUI
    write_u32_le(pe, opt + 108u, 16u);           // NumberOfRvaAndSizes

    // DataDirectory[6] = Debug Directory (RVA 0x2000, size 28)
    const std::size_t dd_debug = opt + 112u + (6u * 8u);
    write_u32_le(pe, dd_debug + 0u, 0x2000u);
    write_u32_le(pe, dd_debug + 4u, 28u);

    // Section headers at 0x98 + 0xF0 = 0x188
    const std::size_t sh0 = 0x188u;
    std::memcpy(pe.data() + sh0, ".text\0\0\0", 8u);
    write_u32_le(pe, sh0 + 8u, 0x200u);          // VirtualSize
    write_u32_le(pe, sh0 + 12u, 0x1000u);        // VirtualAddress
    write_u32_le(pe, sh0 + 16u, 0x200u);         // SizeOfRawData
    write_u32_le(pe, sh0 + 20u, 0x200u);         // PointerToRawData
    write_u32_le(pe, sh0 + 36u, 0x60000020u);    // CODE | EXECUTE | READ

    const std::size_t sh1 = sh0 + 40u;
    std::memcpy(pe.data() + sh1, ".rdata\0\0", 8u);
    write_u32_le(pe, sh1 + 8u, 0x200u);          // VirtualSize
    write_u32_le(pe, sh1 + 12u, 0x2000u);        // VirtualAddress
    write_u32_le(pe, sh1 + 16u, 0x200u);         // SizeOfRawData
    write_u32_le(pe, sh1 + 20u, 0x400u);         // PointerToRawData
    write_u32_le(pe, sh1 + 36u, 0x40000040u);    // INITIALIZED_DATA | READ

    pe[0x200u] = 0xC3u;  // ret at entry point

    // IMAGE_DEBUG_DIRECTORY at file offset 0x400 (RVA 0x2000)
    const std::size_t dbg = 0x400u;
    write_u32_le(pe, dbg + 4u, timestamp);
    write_u32_le(pe, dbg + 12u, 2u);      // IMAGE_DEBUG_TYPE_CODEVIEW
    write_u32_le(pe, dbg + 16u, 36u);     // SizeOfData
    write_u32_le(pe, dbg + 20u, 0x2040u); // AddressOfRawData
    write_u32_le(pe, dbg + 24u, 0x440u);  // PointerToRawData

    // RSDS CV_INFO_PDB70 at file offset 0x440
    const std::size_t rsds = 0x440u;
    pe[rsds + 0u] = 'R';
    pe[rsds + 1u] = 'S';
    pe[rsds + 2u] = 'D';
    pe[rsds + 3u] = 'S';
    std::copy(pdb_guid.begin(),
              pdb_guid.end(),
              pe.begin() + static_cast<std::ptrdiff_t>(rsds + 4u));
    write_u32_le(pe, rsds + 20u, pdb_age);
    const char pdb_name[] = "app.pdb";
    std::memcpy(pe.data() + rsds + 24u, pdb_name, sizeof(pdb_name));

    return pe;
}

class MockLiveProcessSession final : public peelf::IProcessSession {
public:
    explicit MockLiveProcessSession(peelf::ProcessInfo info)
        : info_(std::move(info)) {}

    void set_mapped_module(std::uint64_t base_va,
                           const std::filesystem::path& disk_path,
                           std::vector<std::uint8_t> mapped_bytes) {
        base_va_ = base_va;
        mapped_ = std::move(mapped_bytes);
        modules_ = {
            peelf::ModuleInfo{
                .name = disk_path.filename().string(),
                .path = disk_path,
                .base_address = base_va_,
                .size = static_cast<std::uint64_t>(mapped_.size()),
                .entry_point = base_va_ + 0x1000u,
                .is_main_module = true,
            },
        };
        regions_ = {
            peelf::MemoryRegion{
                .start_address = base_va_,
                .end_address = base_va_ + 0x1000u,
                .protection = {.readable = true, .writable = false, .executable = false, .shared = false},
                .kind = peelf::MemoryRegionKind::Image,
                .file_offset = 0u,
                .pathname = disk_path.string(),
            },
            peelf::MemoryRegion{
                .start_address = base_va_ + 0x1000u,
                .end_address = base_va_ + static_cast<std::uint64_t>(mapped_.size()),
                .protection = {.readable = true, .writable = false, .executable = true, .shared = false},
                .kind = peelf::MemoryRegionKind::Image,
                .file_offset = 0x1000u,
                .pathname = disk_path.string(),
            },
        };
        threads_ = {
            peelf::ThreadInfo{
                .tid = 9001u,
                .name = "main",
                .state = peelf::ThreadRunState::Running,
                .instruction_pointer = base_va_ + 0x1000u,
            },
        };
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] bool is_suspended() const noexcept override { return suspended_; }

    [[nodiscard]] peelf::Result<void> suspend() override {
        suspended_ = true;
        return {};
    }

    [[nodiscard]] peelf::Result<void> resume() override {
        suspended_ = false;
        return {};
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return modules_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return threads_;
    }

    [[nodiscard]] peelf::ThreadContext thread_context(peelf::ThreadId tid) override {
        peelf::ThreadContext ctx;
        ctx.tid = tid;
        ctx.layout = peelf::TargetLayout::from_arch(
            peelf::Architecture::X86_64, true, peelf::Endianness::Little);
        ctx.instruction_pointer = base_va_ + 0x1004u;
        ctx.stack_pointer = 0x7FFF0000u;
        ctx.frame_pointer = 0x7FFF0010u;
        ctx.registers.push_back(peelf::RegisterValue{
            .name = "RIP",
            .category = peelf::RegisterCategory::InstructionPointer,
            .bit_width = 64u,
            .value_u64 = base_va_ + 0x1004u,
            .raw_bytes = {},
            .formatted = "0x0",
        });
        ctx.status = peelf::SubsystemStatus::available("mock", "Mock thread context");
        return ctx;
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        if (address < base_va_ || address >= base_va_ + mapped_.size()) {
            return peelf::make_error("unmapped mock VA");
        }
        const std::size_t rel = static_cast<std::size_t>(address - base_va_);
        const std::size_t avail = std::min(buffer.size(), mapped_.size() - rel);
        std::memcpy(buffer.data(), mapped_.data() + rel, avail);
        return avail;
    }

private:
    peelf::ProcessInfo info_;
    std::uint64_t base_va_{0};
    std::vector<std::uint8_t> mapped_;
    std::vector<peelf::ModuleInfo> modules_;
    std::vector<peelf::MemoryRegion> regions_;
    std::vector<peelf::ThreadInfo> threads_;
    bool suspended_{false};
};

class ScopedTempDir final {
public:
    ScopedTempDir() {
        path_ = std::filesystem::temp_directory_path() /
                ("peelf_wu21_test_" + std::to_string(
                     std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path_);
    }
    ~ScopedTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

}  // namespace

TEST(CapabilityProvenanceTest, UnknownAndContradictoryProfilesDefaultToUnsupported) {
    const peelf::ProviderFacts facts{
        .host_os = peelf::OsKind::Linux,
        .host_arch = peelf::Architecture::X86_64,
        .capstone_available = true,
        .asmtk_available = true,
        .ghidra_available = true,
        .retdec_available = true,
        .native_process_attach_available = true,
        .native_debugger_available = true,
    };

    // Completely unspecified profile -> every operation is Unsupported.
    const peelf::TargetCapabilityMatrix empty_mat =
        peelf::capabilities_for(peelf::TargetProfile{}, facts);
    for (const peelf::Capability& cap : empty_mat.entries()) {
        EXPECT_EQ(cap.state, peelf::SupportState::Unsupported)
            << peelf::to_string(cap.operation);
    }

    // Contradictory PE + Big-Endian -> Unsupported across the board.
    const peelf::TargetProfile bad_pe{
        .format = peelf::Format::PE,
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Big,
        .address_width = peelf::AddressWidth::Bits64,
        .abi = peelf::AbiKind::PeWindows64,
        .os = peelf::OsKind::Windows,
        .backend = peelf::BackendKind::StaticFile,
    };
    const peelf::TargetCapabilityMatrix bad_pe_mat = peelf::capabilities_for(bad_pe, facts);
    for (const peelf::Capability& cap : bad_pe_mat.entries()) {
        EXPECT_EQ(cap.state, peelf::SupportState::Unsupported);
    }

    // Contradictory X86_64 + 32-bit address width -> Unsupported.
    const peelf::TargetProfile bad_width{
        .format = peelf::Format::ELF,
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .address_width = peelf::AddressWidth::Bits32,
        .abi = peelf::AbiKind::SysV,
        .os = peelf::OsKind::Linux,
        .backend = peelf::BackendKind::StaticFile,
    };
    const peelf::TargetCapabilityMatrix bad_width_mat = peelf::capabilities_for(bad_width, facts);
    for (const peelf::Capability& cap : bad_width_mat.entries()) {
        EXPECT_EQ(cap.state, peelf::SupportState::Unsupported);
    }

    // Bare-metal / generic SysV ELF with EI_OSABI == ELFOSABI_NONE (0) and no Linux note/PT_INTERP
    // must NOT infer OsKind::Linux merely from Format::ELF!
    const std::vector<std::uint8_t> generic_elf = make_synthetic_elf64_with_build_id({}, 0u);
    auto parsed = peelf::parse_image(generic_elf);
    ASSERT_TRUE(parsed.has_value());
    const peelf::TargetProfile derived = peelf::derive_target_profile(
        parsed->get(), nullptr, false, false);
    EXPECT_EQ(derived.format, peelf::Format::ELF);
    EXPECT_EQ(derived.os, peelf::OsKind::Unknown);

    const peelf::TargetCapabilityMatrix generic_elf_mat = peelf::capabilities_for(derived, facts);
    EXPECT_EQ(generic_elf_mat.get(peelf::Operation::ImageParsing).state,
              peelf::SupportState::SupportedValidated);
    EXPECT_EQ(generic_elf_mat.get(peelf::Operation::Disassembly).state,
              peelf::SupportState::SupportedValidated);
    // Live Linux process attach must NOT be claimed on an ELF of unknown OS.
    EXPECT_EQ(generic_elf_mat.get(peelf::Operation::LiveProcessAttach).state,
              peelf::SupportState::Unsupported);
}

TEST(CapabilityProvenanceTest, ValidatedSupportSeparatedFromProviderAvailability) {
    const peelf::TargetProfile win_pe_live{
        .format = peelf::Format::PE,
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .address_width = peelf::AddressWidth::Bits64,
        .abi = peelf::AbiKind::PeWindows64,
        .os = peelf::OsKind::Windows,
        .backend = peelf::BackendKind::LiveNativeReadOnly,
    };

    // Host is Linux without Ghidra/RetDec installed:
    const peelf::ProviderFacts linux_host_no_ext{
        .host_os = peelf::OsKind::Linux,
        .host_arch = peelf::Architecture::X86_64,
        .capstone_available = true,
        .asmtk_available = true,
        .ghidra_available = false,
        .retdec_available = false,
        .native_process_attach_available = true,
        .native_debugger_available = true,
    };

    const peelf::TargetCapabilityMatrix mat_missing =
        peelf::capabilities_for(win_pe_live, linux_host_no_ext);

    // Win64 live process attach IS a validated target capability, even though the Linux host
    // runtime provider cannot attach to a native Win32 process directly.
    const peelf::Capability& live_attach = mat_missing.get(peelf::Operation::LiveProcessAttach);
    EXPECT_EQ(live_attach.state, peelf::SupportState::SupportedValidated);
    EXPECT_FALSE(live_attach.provider_available);
    EXPECT_FALSE(live_attach.is_usable_now());

    // External RetDec decompiler is SupportedExperimental, with provider_available=false until installed.
    const peelf::Capability& ext_dec = mat_missing.get(peelf::Operation::ExternalRetDecDecompile);
    EXPECT_EQ(ext_dec.state, peelf::SupportState::SupportedExperimental);
    EXPECT_FALSE(ext_dec.provider_available);
    EXPECT_FALSE(ext_dec.is_usable_now());

    peelf::ProviderFacts with_retdec = linux_host_no_ext;
    with_retdec.retdec_available = true;
    const peelf::TargetCapabilityMatrix mat_present =
        peelf::capabilities_for(win_pe_live, with_retdec);
    EXPECT_EQ(mat_present.get(peelf::Operation::ExternalRetDecDecompile).state,
              peelf::SupportState::SupportedExperimental);
    EXPECT_TRUE(mat_present.get(peelf::Operation::ExternalRetDecDecompile).provider_available);
    EXPECT_TRUE(mat_present.get(peelf::Operation::ExternalRetDecDecompile).is_usable_now());

    // Syscall/ETW timeline is honestly reported as Unsupported until implemented/enabled.
    EXPECT_EQ(mat_present.get(peelf::Operation::SyscallOrEtwTimeline).state,
              peelf::SupportState::Unsupported);
}

TEST(CapabilityProvenanceTest, TargetInstanceCreationIdentityCatchesPidReuse) {
    // Verify `/proc/<pid>/stat` starttime parser handles spaces and nested parentheses in comm!
    const std::string tricky_stat =
        "4242 (weird (worker) name) S 1 4242 4242 0 -1 4194304 "
        "120 0 0 0 15 3 0 0 20 0 4 0 987654321 12345678 1024\n";
    const auto parsed_ticks = peelf::parse_linux_proc_stat_starttime(tricky_stat);
    ASSERT_TRUE(parsed_ticks.has_value());
    EXPECT_EQ(*parsed_ticks, 987654321ull);

    const peelf::TargetInstanceId first_proc{
        .backend = peelf::BackendKind::LiveNativeReadOnly,
        .pid = 4242u,
        .creation_identity = 100001ull,
    };
    const peelf::TargetInstanceId reused_pid_proc{
        .backend = peelf::BackendKind::LiveNativeReadOnly,
        .pid = 4242u,
        .creation_identity = 999999ull,
    };
    const peelf::TargetInstanceId unknown_creation_proc{
        .backend = peelf::BackendKind::LiveNativeReadOnly,
        .pid = 4242u,
        .creation_identity = std::nullopt,
    };

    EXPECT_TRUE(first_proc.same_instance(first_proc));
    EXPECT_FALSE(first_proc.same_instance(reused_pid_proc));
    EXPECT_FALSE(first_proc.same_instance(unknown_creation_proc));
}

TEST(CapabilityProvenanceTest, BackingImageIdentityDetectsElfBuildIdAndPeRsdsMismatch) {
    // 1. PE RSDS GUID+Age verification
    const std::array<std::uint8_t, 16> guid_a{
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    const std::array<std::uint8_t, 16> guid_b{
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    const auto pe_a = make_synthetic_pe64_with_rsds(guid_a, 1u, 0x65000001u);
    const auto pe_b = make_synthetic_pe64_with_rsds(guid_b, 2u, 0x65000002u);
    auto img_pe_a = peelf::parse_image(pe_a);
    auto img_pe_b = peelf::parse_image(pe_b);
    ASSERT_TRUE(img_pe_a.has_value());
    ASSERT_TRUE(img_pe_b.has_value());

    const peelf::BackingImageIdentity id_pe_a =
        peelf::extract_backing_image_identity(**img_pe_a, pe_a);
    const peelf::BackingImageIdentity id_pe_b =
        peelf::extract_backing_image_identity(**img_pe_b, pe_b);
    EXPECT_FALSE(id_pe_a.codeview_guid_hex.empty());
    EXPECT_TRUE(peelf::verify_backing_image_identity(id_pe_a, id_pe_a).matches);
    const peelf::BackingIdentityMatchResult pe_mismatch =
        peelf::verify_backing_image_identity(id_pe_a, id_pe_b);
    EXPECT_TRUE(pe_mismatch.comparable);
    EXPECT_FALSE(pe_mismatch.matches);
    EXPECT_TRUE(pe_mismatch.has_mismatch());

    // 2. Live ELF module vs rebuilt mismatched on-disk file
    ScopedTempDir tmp;
    const std::array<std::uint8_t, 20> disk_build_id{
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const std::array<std::uint8_t, 20> live_build_id{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x12, 0x34, 0x56, 0x78};

    const std::vector<std::uint8_t> disk_elf =
        make_synthetic_elf64_with_build_id(disk_build_id, 3u /*ELFOSABI_LINUX*/, 0x90u);
    const std::vector<std::uint8_t> live_elf =
        make_synthetic_elf64_with_build_id(live_build_id, 3u /*ELFOSABI_LINUX*/, 0xCCu);

    const std::filesystem::path disk_path = tmp.path() / "rebuilt_target.elf";
    {
        std::ofstream out(disk_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(disk_elf.data()),
                  static_cast<std::streamsize>(disk_elf.size()));
    }

    peelf::ProcessInfo pinfo;
    pinfo.pid = 7777u;
    pinfo.name = "rebuilt_target.elf";
    pinfo.executable_path = disk_path;
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.endianness = peelf::Endianness::Little;

    auto mock_sess = std::make_unique<MockLiveProcessSession>(pinfo);
    constexpr std::uint64_t kLiveBase = 0x7F0000000000ull;
    mock_sess->set_mapped_module(kLiveBase, disk_path, live_elf);

    // `compare_module_disk_to_live` flags Partial status + backing_identity.has_mismatch()
    const auto mods = mock_sess->modules();
    ASSERT_TRUE(mods.has_value());
    auto diff_res = peelf::compare_module_disk_to_live(disk_elf, *mock_sess, (*mods)[0]);
    ASSERT_TRUE(diff_res.has_value());
    EXPECT_TRUE(diff_res->backing_identity.has_mismatch());
    EXPECT_EQ(diff_res->status.availability, peelf::Availability::Partial);
    EXPECT_EQ(diff_res->live_capture_stamp.availability, peelf::CaptureAvailability::Partial);

    // `BinaryModel::attach_session` detects the build-ID mismatch and refuses to silently trust
    // the mismatched on-disk file, exposing `backing_identity_status().has_mismatch() == true`.
    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_session(std::move(mock_sess)).has_value());
    EXPECT_TRUE(model.backing_identity_status().has_mismatch());
    const auto sym_obs = model.resolve_symbol_with_provenance(kLiveBase + 0x1000u);
    ASSERT_TRUE(sym_obs.has_value());
    EXPECT_EQ(sym_obs.stamp.availability, peelf::CaptureAvailability::Partial);
    EXPECT_FALSE(sym_obs.value->backing_identity_verified);
}

TEST(CapabilityProvenanceTest, PerCollectionStampsTrackStaleTransitionsAndMixedEvidence) {
    ScopedTempDir tmp;
    const std::array<std::uint8_t, 20> build_id{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20,
        0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0};
    const std::vector<std::uint8_t> elf_bytes =
        make_synthetic_elf64_with_build_id(build_id, 3u /*ELFOSABI_LINUX*/, 0x90u);

    const std::filesystem::path disk_path = tmp.path() / "matching_target.elf";
    {
        std::ofstream out(disk_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(elf_bytes.data()),
                  static_cast<std::streamsize>(elf_bytes.size()));
    }

    peelf::ProcessInfo pinfo;
    pinfo.pid = 8888u;
    pinfo.name = "matching_target.elf";
    pinfo.executable_path = disk_path;
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.endianness = peelf::Endianness::Little;

    auto mock_sess = std::make_unique<MockLiveProcessSession>(pinfo);
    constexpr std::uint64_t kLiveBase = 0x555555554000ull;
    mock_sess->set_mapped_module(kLiveBase, disk_path, elf_bytes);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_session(std::move(mock_sess)).has_value());
    EXPECT_FALSE(model.backing_identity_status().has_mismatch());
    EXPECT_TRUE(model.backing_identity_status().matches);

    // Collections have distinct revisions and Process Internals starts Unavailable (not faked).
    const std::uint64_t initial_map_rev = model.memory_map_stamp().snapshot_revision;
    const std::uint64_t initial_threads_rev = model.threads_stamp().snapshot_revision;
    const std::uint64_t initial_runtime_rev = model.runtime_stamp().snapshot_revision;
    EXPECT_GT(initial_map_rev, 0u);
    EXPECT_NE(initial_map_rev, initial_threads_rev);
    EXPECT_NE(initial_threads_rev, initial_runtime_rev);
    EXPECT_EQ(model.memory_map_stamp().availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(model.threads_stamp().availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(model.process_internals_stamp().availability,
              peelf::CaptureAvailability::Unavailable);

    // Mixed-source provenance when resolving a symbol on a live module backed by verified disk image:
    // combines `DiskFile` symbol table with `LiveMemory` ASLR rebase!
    const auto live_sym = model.resolve_symbol_with_provenance(kLiveBase + 0x1004u);
    ASSERT_TRUE(live_sym.has_value());
    EXPECT_TRUE(live_sym.is_mixed_source());
    EXPECT_EQ(live_sym.evidence.size(), 2u);
    EXPECT_EQ(live_sym.evidence[0].tag, peelf::ProvenanceTag::DiskFile);
    EXPECT_EQ(live_sym.evidence[1].tag, peelf::ProvenanceTag::LiveMemory);

    // Heuristic function discovery (`sub_...` at 0x1020) carries `HeuristicInference` provenance!
    const auto heur_sym = model.resolve_symbol_with_provenance(kLiveBase + 0x1020u);
    ASSERT_TRUE(heur_sym.has_value());
    EXPECT_TRUE(heur_sym.value->heuristic_discovered);
    ASSERT_FALSE(heur_sym.evidence.empty());
    EXPECT_EQ(heur_sym.evidence[0].tag, peelf::ProvenanceTag::HeuristicInference);

    // Refreshing ONLY threads while unpaused marks older collections (`memory_map`, `runtime`) Stale!
    (void)model.refresh_threads();
    EXPECT_EQ(model.threads_stamp().availability, peelf::CaptureAvailability::Complete);
    EXPECT_GT(model.threads_stamp().snapshot_revision, initial_threads_rev);
    EXPECT_EQ(model.memory_map_stamp().availability, peelf::CaptureAvailability::Stale);
    EXPECT_EQ(model.runtime_stamp().availability, peelf::CaptureAvailability::Stale);

    // Symbol resolution now reflects that the underlying module map stamp is Stale!
    const auto stale_sym = model.resolve_symbol_with_provenance(kLiveBase + 0x1004u);
    EXPECT_EQ(stale_sym.stamp.availability, peelf::CaptureAvailability::Stale);
    EXPECT_FALSE(stale_sym.note.empty());

    // Suspending the process holds execution: refreshing map + threads while paused keeps BOTH Complete!
    ASSERT_TRUE(model.suspend_process().ok());
    ASSERT_TRUE(model.refresh_process_map().has_value());
    (void)model.refresh_threads();
    EXPECT_TRUE(model.memory_map_stamp().target_paused);
    EXPECT_TRUE(model.threads_stamp().target_paused);
    EXPECT_EQ(model.memory_map_stamp().availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(model.threads_stamp().availability, peelf::CaptureAvailability::Complete);

    // Resuming execution invalidates the paused memory_map_stamp_ back to Stale!
    ASSERT_TRUE(model.resume_process().ok());
    EXPECT_EQ(model.memory_map_stamp().availability, peelf::CaptureAvailability::Stale);
}

TEST(CapabilityProvenanceTest, HeadlessReportAndBinaryModelHaveExactCapabilityParity) {
    ScopedTempDir tmp;
    const std::array<std::uint8_t, 20> build_id{
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    const std::vector<std::uint8_t> elf_bytes =
        make_synthetic_elf64_with_build_id(build_id, 3u /*ELFOSABI_LINUX*/, 0x90u);

    const std::filesystem::path bin_path = tmp.path() / "parity_check.elf";
    {
        std::ofstream out(bin_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(elf_bytes.data()),
                  static_cast<std::streamsize>(elf_bytes.size()));
    }

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(bin_path.string()));

    peelf::HeadlessCliOptions opts;
    opts.binary_path = bin_path;
    auto headless = peelf::analyze_binary_headless(opts);
    ASSERT_TRUE(headless.has_value());

    EXPECT_EQ(headless->target_profile, model.target_profile());
    EXPECT_EQ(headless->primary_provenance, peelf::ProvenanceTag::DiskFile);
    EXPECT_EQ(headless->analysis_stamp.availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(headless->analysis_stamp.target_id.build_id_or_pdb_guid,
              model.target_instance_id().build_id_or_pdb_guid);

    for (std::size_t i = 0; i < peelf::kOperationCount; ++i) {
        EXPECT_EQ(headless->capabilities.entries()[i].operation,
                  model.capability_matrix().entries()[i].operation);
        EXPECT_EQ(headless->capabilities.entries()[i].state,
                  model.capability_matrix().entries()[i].state);
        EXPECT_EQ(headless->capabilities.entries()[i].provider_available,
                  model.capability_matrix().entries()[i].provider_available);
    }

    const std::string json = peelf::format_headless_report_json(*headless);
    EXPECT_NE(json.find("\"target_profile\""), std::string::npos);
    EXPECT_NE(json.find("\"provenance\""), std::string::npos);
    EXPECT_NE(json.find("\"capabilities\""), std::string::npos);
    EXPECT_NE(json.find("\"SupportedValidated\""), std::string::npos);
    EXPECT_NE(json.find("\"DiskFile\""), std::string::npos);
}
