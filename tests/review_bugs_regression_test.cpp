#include "analysis/async_binary_diff.hpp"
#include "analysis/function_index.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/debugger.hpp>
#include <peelf/dependency_tree.hpp>
#include <peelf/peelf.hpp>
#include <peelf/security_audit.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace {

void put16_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put32_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void put64_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void put16_be(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>(v & 0xFFu);
}

void put32_be(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> ((3u - i) * 8u)) & 0xFFu);
    }
}

void put64_be(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> ((7u - i) * 8u)) & 0xFFu);
    }
}

std::vector<std::uint8_t> make_minimal_pe64_with_cert(std::uint8_t first_cert_byte,
                                                      std::uint32_t cert_dir_off = 0x600u,
                                                      std::uint32_t cert_dir_size = 16u,
                                                      std::uint32_t cert_dw_length = 16u) {
    std::vector<std::uint8_t> b(0x800u, 0u);
    b[0u] = 'M';
    b[1u] = 'Z';
    put32_le(b, 0x3Cu, 0x80u);

    b[0x80u] = 'P';
    b[0x81u] = 'E';
    put16_le(b, 0x84u, 0x8664u); // AMD64
    put16_le(b, 0x86u, 1u);      // 1 section
    put16_le(b, 0x94u, 0xF0u);   // SizeOfOptionalHeader
    put16_le(b, 0x96u, 0x0022u); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    const std::size_t opt = 0x98u;
    put16_le(b, opt + 0x00u, 0x20Bu); // PE32+
    put32_le(b, opt + 0x10u, 0x1000u);
    put64_le(b, opt + 0x18u, 0x140000000ULL);
    put32_le(b, opt + 0x20u, 0x1000u);
    put32_le(b, opt + 0x24u, 0x200u);
    put32_le(b, opt + 0x38u, 0x2000u);
    put32_le(b, opt + 0x3Cu, 0x200u);
    put16_le(b, opt + 0x44u, 3u);      // CUI
    put16_le(b, opt + 0x46u, 0x0160u); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
    put32_le(b, opt + 0x6Cu, 16u);     // NumberOfRvaAndSizes

    // DataDirectory[4] = Certificate Table (file offset + size)
    put32_le(b, opt + 0x70u + 4u * 8u, cert_dir_off);
    put32_le(b, opt + 0x74u + 4u * 8u, cert_dir_size);

    const std::size_t sh = opt + 0xF0u;
    std::memcpy(&b[sh], ".text\0\0\0", 8u);
    put32_le(b, sh + 8u, 0x200u);
    put32_le(b, sh + 12u, 0x1000u);
    put32_le(b, sh + 16u, 0x200u);
    put32_le(b, sh + 20u, 0x200u);
    put32_le(b, sh + 36u, 0x60000020u);
    b[0x200u] = 0xC3u;

    if (cert_dir_off + 16u <= b.size()) {
        put32_le(b, cert_dir_off + 0u, cert_dw_length);
        put16_le(b, cert_dir_off + 4u, 0x0200u); // WIN_CERT_REVISION_2_0
        put16_le(b, cert_dir_off + 6u, 0x0002u); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        b[cert_dir_off + 8u] = first_cert_byte;
        b[cert_dir_off + 9u] = 0x06u;
    }
    return b;
}

// Builds a completely sectionless (`e_shoff = 0, e_shnum = 0`) 64-bit ELF shared object
// whose dynamic metadata (`DT_NEEDED`, `DT_SYMTAB`, `DT_HASH`, `DT_RELA`) lives solely in `PT_DYNAMIC`.
std::vector<std::uint8_t> make_sectionless_dynamic_elf64() {
    std::vector<std::uint8_t> b(0x2000u, 0u);

    // ELF64 LE header
    b[0u] = 0x7Fu;
    b[1u] = 'E';
    b[2u] = 'L';
    b[3u] = 'F';
    b[4u] = 2u;                  // ELFCLASS64
    b[5u] = 1u;                  // ELFDATA2LSB
    b[6u] = 1u;                  // EV_CURRENT
    put16_le(b, 16u, 3u);        // ET_DYN
    put16_le(b, 18u, 62u);       // EM_X86_64
    put32_le(b, 20u, 1u);        // EV_CURRENT
    put64_le(b, 24u, 0x1000u);   // e_entry
    put64_le(b, 32u, 0x40u);     // e_phoff
    put64_le(b, 40u, 0u);        // e_shoff == 0 (sectionless / sstrip!)
    put16_le(b, 52u, 64u);       // e_ehsize
    put16_le(b, 54u, 56u);       // e_phentsize
    put16_le(b, 56u, 3u);        // e_phnum (PT_LOAD RX, PT_LOAD RW, PT_DYNAMIC)
    put16_le(b, 58u, 0u);        // e_shentsize == 0
    put16_le(b, 60u, 0u);        // e_shnum == 0
    put16_le(b, 62u, 0u);        // e_shstrndx == 0

    auto write_phdr = [&](std::size_t idx, std::uint32_t type, std::uint32_t flags,
                          std::uint64_t off, std::uint64_t vaddr, std::uint64_t sz) {
        const std::size_t ph = 0x40u + idx * 56u;
        put32_le(b, ph + 0u, type);
        put32_le(b, ph + 4u, flags);
        put64_le(b, ph + 8u, off);
        put64_le(b, ph + 16u, vaddr);
        put64_le(b, ph + 24u, vaddr);
        put64_le(b, ph + 32u, sz);
        put64_le(b, ph + 40u, sz);
        put64_le(b, ph + 48u, 0x1000u);
    };

    // PT_LOAD #0: file [0x0000, 0x1200) -> VA [0x0000, 0x1200) RX
    write_phdr(0u, 1u, 5u, 0x0000u, 0x0000u, 0x1200u);
    // PT_LOAD #1: file [0x1200, 0x1800) -> VA [0x2200, 0x2800) RW (note non-zero VA bias 0x1000!)
    write_phdr(1u, 1u, 6u, 0x1200u, 0x2200u, 0x0600u);
    // PT_DYNAMIC: file 0x1200 -> VA 0x2200
    write_phdr(2u, 2u, 6u, 0x1200u, 0x2200u, 0x0200u);

    // Code at 0x1000 (`stripped_api`): mov eax, 7; ret
    b[0x1000u] = 0xB8u;
    put32_le(b, 0x1001u, 7u);
    b[0x1005u] = 0xC3u;

    // .dynstr at file 0x0400 (VA 0x0400)
    std::vector<std::uint8_t> dynstr{0u};
    auto add_dynstr = [&](std::string_view s) -> std::uint32_t {
        const auto off = static_cast<std::uint32_t>(dynstr.size());
        dynstr.insert(dynstr.end(), s.begin(), s.end());
        dynstr.push_back(0u);
        return off;
    };
    const std::uint32_t off_needed = add_dynstr("libcrypto.so.3");
    const std::uint32_t off_soname = add_dynstr("libsectionless.so");
    const std::uint32_t off_rpath = add_dynstr("/opt/peelf/lib");
    const std::uint32_t off_imp_sym = add_dynstr("EVP_sha256");
    const std::uint32_t off_exp_sym = add_dynstr("stripped_api");
    std::memcpy(&b[0x0400u], dynstr.data(), dynstr.size());

    // .dynsym at file 0x0500 (VA 0x0500), 3 symbols * 24 bytes: [0]=UND, [1]=EVP_sha256 (UND), [2]=stripped_api (DEF)
    auto write_sym64 = [&](std::size_t idx, std::uint32_t name, std::uint8_t info,
                           std::uint16_t shndx, std::uint64_t val, std::uint64_t sz) {
        const std::size_t s = 0x0500u + idx * 24u;
        put32_le(b, s + 0u, name);
        b[s + 4u] = info;
        b[s + 5u] = 0u;
        put16_le(b, s + 6u, shndx);
        put64_le(b, s + 8u, val);
        put64_le(b, s + 16u, sz);
    };
    write_sym64(1u, off_imp_sym, 0x12u, 0u, 0u, 0u);          // STB_GLOBAL | STT_FUNC, SHN_UNDEF
    write_sym64(2u, off_exp_sym, 0x12u, 1u, 0x1000u, 6u);     // STB_GLOBAL | STT_FUNC, defined @ 0x1000

    // SysV DT_HASH at file 0x0600 (VA 0x0600): nbucket=1, nchain=3
    put32_le(b, 0x0600u, 1u); // nbucket
    put32_le(b, 0x0604u, 3u); // nchain == 3 dynsyms!
    put32_le(b, 0x0608u, 1u); // bucket[0] = 1
    put32_le(b, 0x060Cu, 0u); // chain[0]
    put32_le(b, 0x0610u, 2u); // chain[1]
    put32_le(b, 0x0614u, 0u); // chain[2]

    // .rela.dyn at file 0x0700 (VA 0x0700): 1 Elf64_Rela (24 bytes) for sym #1 (EVP_sha256), R_X86_64_GLOB_DAT (6)
    put64_le(b, 0x0700u, 0x2500u);                  // r_offset (GOT slot in RW PT_LOAD)
    put64_le(b, 0x0708u, (1ULL << 32u) | 6ULL);     // sym=1, type=R_X86_64_GLOB_DAT
    put64_le(b, 0x0710u, 0u);

    // .dynamic at file 0x1200 (VA 0x2200)
    std::size_t dyn_cursor = 0x1200u;
    auto push_dyn = [&](std::uint64_t tag, std::uint64_t val) {
        put64_le(b, dyn_cursor + 0u, tag);
        put64_le(b, dyn_cursor + 8u, val);
        dyn_cursor += 16u;
    };
    push_dyn(1u, off_needed);  // DT_NEEDED
    push_dyn(14u, off_soname); // DT_SONAME
    push_dyn(15u, off_rpath);  // DT_RPATH
    push_dyn(5u, 0x0400u);     // DT_STRTAB (VA)
    push_dyn(10u, dynstr.size()); // DT_STRSZ
    push_dyn(6u, 0x0500u);     // DT_SYMTAB (VA)
    push_dyn(11u, 24u);        // DT_SYMENT
    push_dyn(4u, 0x0600u);     // DT_HASH (VA)
    push_dyn(7u, 0x0700u);     // DT_RELA (VA)
    push_dyn(8u, 24u);         // DT_RELASZ
    push_dyn(9u, 24u);         // DT_RELAENT
    push_dyn(0u, 0u);          // DT_NULL

    return b;
}

class SlowCancellableMockSession final : public peelf::IProcessSession {
public:
    SlowCancellableMockSession(std::vector<std::uint8_t> image_bytes, std::uint64_t base_va)
        : image_bytes_(std::move(image_bytes)), base_va_(base_va) {
        info_.pid = 9999;
        info_.name = "slow_live_target";
        info_.architecture = peelf::Architecture::X86_64;

        peelf::MemoryRegion reg{};
        reg.start_address = base_va_;
        reg.end_address = base_va_ + std::max<std::size_t>(image_bytes_.size(), 0x2000u);
        reg.protection = {.readable = true, .writable = false, .executable = true, .shared = false};
        reg.kind = peelf::MemoryRegionKind::Image;
        reg.pathname = "/tmp/slow_live_target";
        regions_.push_back(reg);
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }
    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t address,
                                                         std::span<std::uint8_t> buffer) override {
        read_calls_.fetch_add(1u, std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        if (address < base_va_ || address >= base_va_ + 0x2000u) {
            return peelf::make_error("unmapped");
        }
        std::memset(buffer.data(), 0, buffer.size());
        return buffer.size();
    }
    [[nodiscard]] peelf::Result<std::size_t> write_memory(std::uint64_t,
                                                          std::span<const std::uint8_t>,
                                                          peelf::MemoryWriteOptions) override {
        return peelf::make_error("read-only");
    }

    [[nodiscard]] std::size_t read_calls() const noexcept {
        return read_calls_.load(std::memory_order_relaxed);
    }

private:
    peelf::ProcessInfo info_{};
    std::vector<std::uint8_t> image_bytes_{};
    std::uint64_t base_va_{0};
    std::vector<peelf::MemoryRegion> regions_{};
    std::atomic<std::size_t> read_calls_{0};
};

} // namespace

// Bug 1: 32-bit `e_lfanew + 4 + 20` wraparound in `parse_pe_bytes` + big-endian ELF delegation + PeImage data dirs.
TEST(ReviewBugsRegression, PeParserRejectsUint32LfanewOverflowAndUnifiesWithPeAndElfImages) {
    std::vector<std::uint8_t> crafted_mz(256u, 0u);
    crafted_mz[0u] = 'M';
    crafted_mz[1u] = 'Z';
    // 0xFFFFFFF0u + 24u wraps in 32-bit unsigned arithmetic to 0x00000008 (< 256)!
    put32_le(crafted_mz, 0x3Cu, 0xFFFFFFF0u);
    crafted_mz[0xFFFFFFF0u & 0xFFu] = 'P'; // ensure wraparound target inside buffer even has 'P','E'
    crafted_mz[0x08u] = 'P';
    crafted_mz[0x09u] = 'E';

    const auto legacy_pe = peelf::parse_pe_bytes(crafted_mz);
    EXPECT_FALSE(legacy_pe.has_value());
    const auto unified_pe = peelf::parse_image(crafted_mz);
    EXPECT_FALSE(unified_pe.has_value());

    // Valid PE64 exposes full PeHeader + DataDirectories cleanly through both APIs.
    const auto valid_pe_bytes = make_minimal_pe64_with_cert(0x30u);
    const auto summary = peelf::parse_pe_bytes(valid_pe_bytes);
    ASSERT_TRUE(summary.has_value()) << summary.error().message;
    EXPECT_EQ(summary->kind, peelf::FileKind::PE);
    const auto& pe_sum = std::get<PeSummary>(summary->summary);
    EXPECT_EQ(pe_sum.optional_magic, 0x20bu);
    EXPECT_EQ(pe_sum.machine, 0x8664u);

    const auto parsed_pe = peelf::parse_image(valid_pe_bytes);
    ASSERT_TRUE(parsed_pe.has_value()) << parsed_pe.error().message;
    ASSERT_NE((*parsed_pe)->pe_header(), nullptr);
    EXPECT_EQ((*parsed_pe)->image_base(), 0x140000000ULL);
    EXPECT_EQ((*parsed_pe)->pe_header()->entry_point_rva, 0x1000u);
    EXPECT_EQ((*parsed_pe)->pe_header()->section_alignment, 0x1000u);
    EXPECT_EQ((*parsed_pe)->pe_header()->file_alignment, 0x200u);
    ASSERT_EQ((*parsed_pe)->pe_data_directories().size(), 16u);
    EXPECT_EQ((*parsed_pe)->pe_data_directories()[4].name, "Security");
    EXPECT_EQ((*parsed_pe)->pe_data_directories()[4].rva, 0x600u);
    EXPECT_EQ((*parsed_pe)->pe_data_directories()[4].size, 16u);

    // Big-endian 64-bit ELF (`ELFDATA2MSB`) works through `parse_elf_bytes` now that it delegates to `ElfImage::parse`.
    std::vector<std::uint8_t> elf_be(128u, 0u);
    elf_be[0u] = 0x7Fu; elf_be[1u] = 'E'; elf_be[2u] = 'L'; elf_be[3u] = 'F';
    elf_be[4u] = 2u; // ELFCLASS64
    elf_be[5u] = 2u; // ELFDATA2MSB (Big-endian!)
    elf_be[6u] = 1u;
    put16_be(elf_be, 16u, 2u);  // ET_EXEC
    put16_be(elf_be, 18u, 21u); // EM_PPC64
    put32_be(elf_be, 20u, 1u);
    put64_be(elf_be, 24u, 0x10000400ULL);
    put16_be(elf_be, 52u, 64u);

    const auto elf_summary = peelf::parse_elf_bytes(elf_be);
    ASSERT_TRUE(elf_summary.has_value()) << elf_summary.error().message;
    EXPECT_EQ(elf_summary->kind, peelf::FileKind::ELF);
    const auto& elf_sum = std::get<ElfSummary>(elf_summary->summary);
    EXPECT_EQ(elf_sum.ei_class, 2u);
    EXPECT_EQ(elf_sum.ei_data, 2u);
    EXPECT_EQ(elf_sum.e_machine, 21u);
    const auto elf_be_img = peelf::parse_image(elf_be);
    ASSERT_TRUE(elf_be_img.has_value());
    EXPECT_EQ((*elf_be_img)->entry_point(), 0x10000400ULL);
    EXPECT_EQ((*elf_be_img)->endianness(), peelf::Endianness::Big);
}

// Bug 2: Never report `Availability::Available` with zeroed IP/SP on unhandled or truncated Linux NT_PRSTATUS regsets.
TEST(ReviewBugsRegression, LinuxPrstatusDecoderReportsHonestStatusAndDecodesKnownAbis) {
    std::vector<std::uint8_t> fake_ppc_regs(256u, 0xAAu);
    const peelf::TargetLayout ppc_layout{
        .architecture = peelf::Architecture::PowerPC64,
        .address_width = peelf::AddressWidth::Bits64,
        .endianness = peelf::Endianness::Big,
    };
    const peelf::ThreadContext ppc_ctx = peelf::debugger::decode_linux_prstatus_regset(
        777, ppc_layout, fake_ppc_regs);
    EXPECT_EQ(ppc_ctx.status.availability, peelf::Availability::Partial);
    EXPECT_NE(ppc_ctx.status.availability, peelf::Availability::Available);
    EXPECT_EQ(ppc_ctx.instruction_pointer, 0u);
    EXPECT_EQ(ppc_ctx.registers.size(), 1u); // raw blob preserved for diagnostics
    EXPECT_EQ(ppc_ctx.registers[0].name, "nt_prstatus_raw");
    EXPECT_NE(ppc_ctx.status.detail.find("unsupported"), std::string::npos);

    // Truncated AArch64 regset (< 272 bytes) must be Unavailable, never Available.
    std::vector<std::uint8_t> short_arm64(64u, 0x11u);
    const peelf::TargetLayout arm64_layout{
        .architecture = peelf::Architecture::ARM64,
        .address_width = peelf::AddressWidth::Bits64,
        .endianness = peelf::Endianness::Little,
    };
    const peelf::ThreadContext short_ctx = peelf::debugger::decode_linux_prstatus_regset(
        778, arm64_layout, short_arm64);
    EXPECT_EQ(short_ctx.status.availability, peelf::Availability::Unavailable);

    // Full AArch64 regset (34 * 8 = 272 bytes): x29=FP, x30=LR, sp=slot 31, pc=slot 32.
    std::vector<std::uint8_t> arm64_regs(272u, 0u);
    put64_le(arm64_regs, 29u * 8u, 0xFFFF00001000ULL); // x29 (FP)
    put64_le(arm64_regs, 30u * 8u, 0xAAAA00002040ULL); // x30 (LR)
    put64_le(arm64_regs, 31u * 8u, 0xFFFF00000FD0ULL); // sp
    put64_le(arm64_regs, 32u * 8u, 0xAAAA00002008ULL); // pc
    const peelf::ThreadContext arm64_ctx = peelf::debugger::decode_linux_prstatus_regset(
        779, arm64_layout, arm64_regs);
    EXPECT_EQ(arm64_ctx.status.availability, peelf::Availability::Available);
    EXPECT_EQ(arm64_ctx.instruction_pointer, 0xAAAA00002008ULL);
    EXPECT_EQ(arm64_ctx.stack_pointer, 0xFFFF00000FD0ULL);
    EXPECT_EQ(arm64_ctx.frame_pointer, 0xFFFF00001000ULL);
    EXPECT_EQ(arm64_ctx.link_register, 0xAAAA00002040ULL);

    // Full RISC-V 64 regset (32 * 8 = 256 bytes): [0]=pc, [1]=ra, [2]=sp, [8]=s0/fp.
    std::vector<std::uint8_t> rv64_regs(256u, 0u);
    put64_le(rv64_regs, 0u * 8u, 0x0000000000012340ULL); // pc
    put64_le(rv64_regs, 1u * 8u, 0x0000000000012300ULL); // ra
    put64_le(rv64_regs, 2u * 8u, 0x00007FFF00008000ULL); // sp
    put64_le(rv64_regs, 8u * 8u, 0x00007FFF00008040ULL); // s0/fp
    const peelf::TargetLayout rv64_layout{
        .architecture = peelf::Architecture::RISCV64,
        .address_width = peelf::AddressWidth::Bits64,
        .endianness = peelf::Endianness::Little,
    };
    const peelf::ThreadContext rv64_ctx = peelf::debugger::decode_linux_prstatus_regset(
        780, rv64_layout, rv64_regs);
    EXPECT_EQ(rv64_ctx.status.availability, peelf::Availability::Available);
    EXPECT_EQ(rv64_ctx.instruction_pointer, 0x0000000000012340ULL);
    EXPECT_EQ(rv64_ctx.stack_pointer, 0x00007FFF00008000ULL);
    EXPECT_EQ(rv64_ctx.frame_pointer, 0x00007FFF00008040ULL);
    EXPECT_EQ(rv64_ctx.link_register, 0x0000000000012300ULL);
}

// Bug 3 + P1-5: Sectionless static ELF (`e_shoff == 0, e_shnum == 0`) recovers `PT_DYNAMIC` entries,
// imports, exports, relocations, and `DT_NEEDED` dependency tree; ELF extended numbering (`SHN_XINDEX`/`PN_XNUM`) works.
TEST(ReviewBugsRegression, SectionlessStaticElfRecoversDynamicMetadataAndSupportsExtendedNumbering) {
    const auto sectionless = make_sectionless_dynamic_elf64();
    const auto parsed = peelf::parse_image(sectionless);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const peelf::IBinaryImage& img = **parsed;

    EXPECT_TRUE(img.sections().empty());
    EXPECT_FALSE(img.elf_dynamic_entries().empty());

    const bool has_stripped_export = std::ranges::any_of(
        img.exports(),
        [](const peelf::ExportEntry& e) { return e.name == "stripped_api" && e.virtual_address == 0x1000u; });
    EXPECT_TRUE(has_stripped_export);

    const bool has_crypto_needed = std::ranges::any_of(
        img.imports(), [](const peelf::ImportEntry& imp) { return imp.library == "libcrypto.so.3"; });
    const bool has_evp_import = std::ranges::any_of(
        img.imports(), [](const peelf::ImportEntry& imp) { return imp.name == "EVP_sha256"; });
    EXPECT_TRUE(has_crypto_needed);
    EXPECT_TRUE(has_evp_import);
    EXPECT_FALSE(img.elf_relocations().empty());

    peelf::DependencyResolveOptions dep_opts{};
    dep_opts.include_default_system_dirs = false;
    const auto dep_graph = peelf::build_dependency_graph(img, dep_opts);
    ASSERT_EQ(dep_graph.root_tree.children.size(), 1u);
    EXPECT_EQ(dep_graph.root_tree.children[0].requested_name, "libcrypto.so.3");

    // Also verify ELF extended numbering: `e_shnum == 0` -> `shdr[0].sh_size`,
    // `e_shstrndx == SHN_XINDEX (0xFFFF)` -> `shdr[0].sh_link`, `e_phnum == PN_XNUM (0xFFFF)` -> `shdr[0].sh_info`.
    std::vector<std::uint8_t> ext_elf(0x400u, 0u);
    ext_elf[0u] = 0x7Fu; ext_elf[1u] = 'E'; ext_elf[2u] = 'L'; ext_elf[3u] = 'F';
    ext_elf[4u] = 2u; ext_elf[5u] = 1u; ext_elf[6u] = 1u;
    put16_le(ext_elf, 16u, 3u);
    put16_le(ext_elf, 18u, 62u);
    put32_le(ext_elf, 20u, 1u);
    put64_le(ext_elf, 24u, 0x1000u);
    put64_le(ext_elf, 32u, 0x40u);  // e_phoff
    put64_le(ext_elf, 40u, 0x100u); // e_shoff
    put16_le(ext_elf, 52u, 64u);
    put16_le(ext_elf, 54u, 56u);
    put16_le(ext_elf, 56u, 0xFFFFu); // PN_XNUM!
    put16_le(ext_elf, 58u, 64u);
    put16_le(ext_elf, 60u, 0u);      // extended shnum in shdr[0].sh_size!
    put16_le(ext_elf, 62u, 0xFFFFu); // SHN_XINDEX in shdr[0].sh_link!

    // 1 PT_LOAD at 0x40
    put32_le(ext_elf, 0x40u, 1u);
    put32_le(ext_elf, 0x44u, 5u);
    put64_le(ext_elf, 0x48u, 0u);
    put64_le(ext_elf, 0x50u, 0x1000u);
    put64_le(ext_elf, 0x58u, 0x1000u);
    put64_le(ext_elf, 0x60u, 0x200u);
    put64_le(ext_elf, 0x68u, 0x200u);

    // shstrtab at 0x280: "\0.ext_text\0.shstrtab\0"
    const std::string_view shstr("\0.ext_text\0.shstrtab\0", 21u);
    std::memcpy(&ext_elf[0x280u], shstr.data(), shstr.size());

    // shdr[0] @ 0x100: sh_size = 3 sections, sh_link = 2 (shstrtab), sh_info = 1 (phnum)
    put64_le(ext_elf, 0x100u + 32u, 3u); // sh_size -> effective shnum = 3
    put32_le(ext_elf, 0x100u + 40u, 2u); // sh_link -> effective shstrndx = 2
    put32_le(ext_elf, 0x100u + 44u, 1u); // sh_info -> effective phnum = 1

    // shdr[1] @ 0x140: ".ext_text" (offset 1)
    put32_le(ext_elf, 0x140u + 0u, 1u);
    put32_le(ext_elf, 0x140u + 4u, 1u); // SHT_PROGBITS
    put64_le(ext_elf, 0x140u + 8u, 6u); // SHF_ALLOC | SHF_EXECINSTR
    put64_le(ext_elf, 0x140u + 16u, 0x1000u);
    put64_le(ext_elf, 0x140u + 24u, 0x80u);
    put64_le(ext_elf, 0x140u + 32u, 16u);

    // shdr[2] @ 0x180: ".shstrtab" (offset 11)
    put32_le(ext_elf, 0x180u + 0u, 11u);
    put32_le(ext_elf, 0x180u + 4u, 3u); // SHT_STRTAB
    put64_le(ext_elf, 0x180u + 24u, 0x280u);
    put64_le(ext_elf, 0x180u + 32u, shstr.size());

    const auto parsed_ext = peelf::parse_image(ext_elf);
    ASSERT_TRUE(parsed_ext.has_value()) << parsed_ext.error().message;
    ASSERT_EQ((*parsed_ext)->segments().size(), 1u);
    ASSERT_EQ((*parsed_ext)->sections().size(), 3u);
    EXPECT_EQ((*parsed_ext)->sections()[0].file_size, 0u); // SHT_NULL sh_size=3 is extended count, not file bytes!
    EXPECT_EQ((*parsed_ext)->sections()[1].name, ".ext_text");
    EXPECT_EQ((*parsed_ext)->sections()[2].name, ".shstrtab");
}

// Bug 4: `PE1005` never conflates certificate presence with cryptographic validity or publisher trust.
TEST(ReviewBugsRegression, SecurityAuditPe1005RejectsMalformedCertAndNeverMarksUnverifiedPresenceAsPass) {
    auto find_pe1005 = [](const peelf::SecurityAuditReport& r) -> const peelf::SecurityFinding* {
        for (const auto& f : r.findings) {
            if (f.rule_id == "PE1005") return &f;
        }
        return nullptr;
    };

    // 1. Corrupt WIN_CERTIFICATE payload (non-DER tag 0xDE) -> Error on all platforms.
    const auto corrupt_cert = make_minimal_pe64_with_cert(0xDEu);
    const auto parsed_corrupt = peelf::parse_image(corrupt_cert);
    ASSERT_TRUE(parsed_corrupt.has_value());
    const auto audit_corrupt = peelf::audit_security(**parsed_corrupt, corrupt_cert);
    const auto* f_corrupt = find_pe1005(audit_corrupt);
    ASSERT_NE(f_corrupt, nullptr);
    EXPECT_EQ(f_corrupt->severity, peelf::SecuritySeverity::Error);
    EXPECT_NE(f_corrupt->evidence.find("signature_validity=corrupt_structure"), std::string::npos);

    // 2. Out-of-bounds CertificateTable DataDirectory -> Error on all platforms.
    const auto oob_cert = make_minimal_pe64_with_cert(0x30u, 0x7FF0u, 64u, 64u);
    const auto parsed_oob = peelf::parse_image(oob_cert);
    ASSERT_TRUE(parsed_oob.has_value());
    const auto audit_oob = peelf::audit_security(**parsed_oob, oob_cert);
    const auto* f_oob = find_pe1005(audit_oob);
    ASSERT_NE(f_oob, nullptr);
    EXPECT_EQ(f_oob->severity, peelf::SecuritySeverity::Error);

    // 3. Structurally valid ASN.1 DER PKCS#7 WIN_CERTIFICATE -> Note on non-Windows (never Pass!), Error on Windows.
    const auto unverified_cert = make_minimal_pe64_with_cert(0x30u);
    const auto parsed_unverified = peelf::parse_image(unverified_cert);
    ASSERT_TRUE(parsed_unverified.has_value());
    const auto audit_unverified = peelf::audit_security(**parsed_unverified, unverified_cert);
    const auto* f_unverified = find_pe1005(audit_unverified);
    ASSERT_NE(f_unverified, nullptr);
    EXPECT_NE(f_unverified->severity, peelf::SecuritySeverity::Pass);
#ifdef _WIN32
    EXPECT_EQ(f_unverified->severity, peelf::SecuritySeverity::Error);
#else
    EXPECT_EQ(f_unverified->severity, peelf::SecuritySeverity::Note);
    EXPECT_NE(f_unverified->evidence.find("signature_validity=unverified_host"), std::string::npos);
    EXPECT_NE(f_unverified->evidence.find("publisher_trust=unverified_host"), std::string::npos);
#endif
}

// Bug 5: Background `AsyncBinaryDiffer` supports non-blocking execution, stale-revision discard, and prompt `cancel()`.
TEST(ReviewBugsRegression, AsyncBinaryDifferSupportsCompletionRevisionGatingAndCancellation) {
    const auto lhs_pe = make_minimal_pe64_with_cert(0x30u);
    auto rhs_pe = lhs_pe;
    rhs_pe[0x200u] = 0x90u; // mutate entry byte (.text)

    const std::filesystem::path temp_dir =
        std::filesystem::temp_directory_path() /
        ("peelf-async-diff-test-" + std::to_string(
#ifdef _WIN32
             7777
#else
             static_cast<int>(::getpid())
#endif
             ));
    std::error_code ec;
    std::filesystem::create_directories(temp_dir, ec);
    const std::filesystem::path rhs_path = temp_dir / "rhs_modified.exe";
    {
        std::ofstream ofs(rhs_path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(static_cast<bool>(ofs));
        ofs.write(reinterpret_cast<const char*>(rhs_pe.data()),
                  static_cast<std::streamsize>(rhs_pe.size()));
    }

    // 1. Background file diff succeeds when active revision matches.
    {
        viewer::AsyncBinaryDiffer differ;
        peelf::BinaryDiffOptions opts{};
        opts.lhs_label = "lhs.exe";
        opts.rhs_label = "rhs.exe";
        differ.start_file_diff(42u, lhs_pe, rhs_path, opts);
        differ.wait_for_idle();

        const auto done = differ.poll_completed(42u);
        ASSERT_TRUE(done.has_value());
        EXPECT_EQ(done->status, viewer::AsyncDiffStatus::Succeeded);
        ASSERT_TRUE(done->static_report.has_value());
        EXPECT_GE(done->static_report->total_changed_bytes, 1u);
    }

    // 2. Stale revision token discards background diff result instead of publishing onto a newer target.
    {
        viewer::AsyncBinaryDiffer differ;
        differ.start_file_diff(100u, lhs_pe, rhs_path);
        differ.wait_for_idle();

        const auto stale = differ.poll_completed(101u); // active model moved to revision 101!
        ASSERT_TRUE(stale.has_value());
        EXPECT_EQ(stale->status, viewer::AsyncDiffStatus::StaleDiscarded);
        EXPECT_FALSE(stale->static_report.has_value());
    }

    // 3. Mid-flight `cancel()` aborts slow live-module comparison cleanly via `std::stop_token`.
    {
        auto slow_session = std::make_shared<SlowCancellableMockSession>(rhs_pe, 0x140000000ULL);
        peelf::ModuleInfo live_mod{};
        live_mod.name = "rhs_modified.exe";
        live_mod.path = rhs_path;
        live_mod.base_address = 0x140000000ULL;
        live_mod.size = rhs_pe.size();

        viewer::AsyncBinaryDiffer differ;
        differ.start_live_integrity_diff(7u, rhs_path, slow_session, live_mod);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (slow_session->read_calls() == 0u && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        differ.cancel();
        differ.wait_for_idle();

        const auto cancelled = differ.poll_completed(7u);
        ASSERT_TRUE(cancelled.has_value());
        EXPECT_EQ(cancelled->status, viewer::AsyncDiffStatus::Cancelled);
        EXPECT_FALSE(cancelled->live_report.has_value());
    }

    std::filesystem::remove_all(temp_dir, ec);
}

// CA-04 (A01): FunctionIndex::upsert_function uses try_emplace so duplicate-VA merges preserve
// non-SSO symbol/demangled/library/section strings on the incoming candidate.
TEST(ReviewBugsRegression, FunctionIndexDuplicateVaMergePreservesRichFieldsViaTryEmplace) {
    const auto pe_bytes = make_minimal_pe64_with_cert(0x30u);
    auto parsed = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_NE(*parsed, nullptr);

    const std::uint64_t entry_va = (*parsed)->entry_point();
    ASSERT_EQ(entry_va, 0x140001000ULL);

    // SymbolIndex::build seeds "Entry Point" at entry_va first (generic name, lower origin priority).
    viewer::SymbolIndex sym_index = viewer::SymbolIndex::build(**parsed);

    // Append a higher-priority DebugSymbol at the exact same VA with >32-byte strings (exceeding SSO)
    // so moving `candidate` during a failed `.emplace(...)` would empty its strings before merge.
    const std::string mangled_name =
        "_ZN5peelf15ca04_regression37duplicate_va_rich_entry_symbol_targetEii";
    const std::string rich_library =
        "libca04_duplicate_va_rich_debug_origin_module_name.dll";

    viewer::DebugSymbol debug_sym{};
    debug_sym.name = mangled_name;
    debug_sym.library = rich_library;
    debug_sym.virtual_address = entry_va;
    debug_sym.size = 0x18u;
    debug_sym.function = true;
    const viewer::DebugSymbol debug_syms[] = {debug_sym};
    sym_index.add_debug_symbols(**parsed, debug_syms);

    const viewer::FunctionIndex fn_index =
        viewer::FunctionIndex::discover(**parsed, sym_index, pe_bytes);
    const viewer::FunctionEntry* merged = fn_index.find_exact(entry_va);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->origin, viewer::FunctionOrigin::DebugInfo);
    EXPECT_EQ(merged->raw_name, mangled_name);
    EXPECT_FALSE(merged->name.empty());
    EXPECT_NE(merged->name.find("duplicate_va_rich_entry_symbol_target"), std::string::npos);
    EXPECT_FALSE(merged->demangled_name.empty());
    EXPECT_NE(
        merged->demangled_name.find(
            "peelf::ca04_regression::duplicate_va_rich_entry_symbol_target"),
        std::string::npos);
    EXPECT_EQ(merged->library, rich_library);
    EXPECT_EQ(merged->section_name, ".text");
    EXPECT_EQ(merged->size, 0x18u);
}

// CA-04 (A02/A03): AsyncBinaryDiffer worker catches std::exception, std::bad_alloc, and unknown
// exceptions without std::terminate or wait_for_idle() deadlock.
TEST(ReviewBugsRegression, AsyncBinaryDifferWorkerContainsExceptionsWithoutTerminate) {
    const auto lhs_pe = make_minimal_pe64_with_cert(0x30u);
    const std::filesystem::path temp_dir =
        std::filesystem::temp_directory_path() /
        ("peelf-async-diff-exc-test-" + std::to_string(
#ifdef _WIN32
             7778
#else
             static_cast<int>(::getpid())
#endif
             ));
    std::error_code ec;
    std::filesystem::create_directories(temp_dir, ec);
    const std::filesystem::path rhs_path = temp_dir / "rhs.exe";
    {
        std::ofstream ofs(rhs_path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(static_cast<bool>(ofs));
        ofs.write(reinterpret_cast<const char*>(lhs_pe.data()),
                  static_cast<std::streamsize>(lhs_pe.size()));
    }

    // 1. std::runtime_error inside worker progress callback -> structured Failed outcome.
    {
        viewer::AsyncBinaryDiffer differ;
        peelf::BinaryDiffOptions opts{};
        opts.progress_callback = [](std::size_t, std::size_t, std::string_view) {
            throw std::runtime_error("simulated diff callback failure");
        };
        differ.start_file_diff(11u, lhs_pe, rhs_path, opts);
        differ.wait_for_idle();
        EXPECT_FALSE(differ.is_running());

        const auto done = differ.poll_completed(11u);
        ASSERT_TRUE(done.has_value());
        EXPECT_EQ(done->status, viewer::AsyncDiffStatus::Failed);
        EXPECT_NE(done->error_message.find("simulated diff callback failure"), std::string::npos);
    }

    // 2. std::bad_alloc inside worker -> pre-allocated non-allocating OOM outcome.
    {
        viewer::AsyncBinaryDiffer differ;
        peelf::BinaryDiffOptions opts{};
        opts.progress_callback = [](std::size_t, std::size_t, std::string_view) {
            throw std::bad_alloc{};
        };
        differ.start_file_diff(12u, lhs_pe, rhs_path, opts);
        differ.wait_for_idle();
        EXPECT_FALSE(differ.is_running());

        const auto done = differ.poll_completed(12u);
        ASSERT_TRUE(done.has_value());
        EXPECT_EQ(done->status, viewer::AsyncDiffStatus::Failed);
        EXPECT_NE(done->error_message.find("Out of memory"), std::string::npos);
    }

    // 3. Non-standard exception inside live integrity diff worker -> structured Failed outcome.
    {
        auto session = std::make_shared<SlowCancellableMockSession>(lhs_pe, 0x140000000ULL);
        peelf::ModuleInfo live_mod{};
        live_mod.name = "rhs.exe";
        live_mod.path = rhs_path;
        live_mod.base_address = 0x140000000ULL;
        live_mod.size = lhs_pe.size();

        viewer::AsyncBinaryDiffer differ;
        peelf::LiveIntegrityDiffOptions opts{};
        opts.progress_callback = [](std::size_t, std::size_t, std::string_view) {
            throw 99;
        };
        differ.start_live_integrity_diff(13u, rhs_path, session, live_mod, opts);
        differ.wait_for_idle();
        EXPECT_FALSE(differ.is_running());

        const auto done = differ.poll_completed(13u);
        ASSERT_TRUE(done.has_value());
        EXPECT_EQ(done->status, viewer::AsyncDiffStatus::Failed);
        EXPECT_NE(done->error_message.find("Unhandled exception"), std::string::npos);
    }

    std::filesystem::remove_all(temp_dir, ec);
}

