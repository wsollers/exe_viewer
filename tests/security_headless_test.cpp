#include <gtest/gtest.h>

#include "model/binary_model.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/subprocess.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

const peelf::SecurityFinding* find_rule(const peelf::SecurityAuditReport& r, std::string_view rule_id) {
    for (const peelf::SecurityFinding& f : r.findings) {
        if (f.rule_id == rule_id) {
            return &f;
        }
    }
    return nullptr;
}

enum class PeCertFixtureMode : std::uint8_t {
    Unsigned,
    MalformedDummyCert,
};

// Builds a hardened 64-bit PE32+ image satisfying PE1001..PE1004 and PE1006..PE1008,
// with deterministic cross-platform PE1005 behavior for unsigned or dummy-cert fixtures.
std::vector<std::uint8_t> build_hardened_pe64(
    std::uint16_t dll_chars_override = 0x4160u,
    PeCertFixtureMode cert_mode = PeCertFixtureMode::Unsigned) {
    // 0x4160 = HIGH_ENTROPY_VA (0x0020) | DYNAMIC_BASE (0x0040) |
    //          NX_COMPAT (0x0100) | GUARD_CF (0x4000)
    std::vector<std::uint8_t> b(0x1200u, 0u);
    b[0u] = 'M';
    b[1u] = 'Z';
    put32(b, 0x3Cu, 0x80u);

    b[0x80u] = 'P';
    b[0x81u] = 'E';
    put16(b, 0x84u, 0x8664u); // AMD64
    put16(b, 0x86u, 2u);      // .text + .rdata
    put16(b, 0x94u, 0xF0u);   // SizeOfOptionalHeader
    put16(b, 0x96u, 0x0022u); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    const std::size_t opt = 0x98u;
    put16(b, opt + 0x00u, 0x20Bu); // PE32+
    put32(b, opt + 0x10u, 0x1000u);
    put64(b, opt + 0x18u, 0x140000000ull);
    put32(b, opt + 0x20u, 0x1000u);
    put32(b, opt + 0x24u, 0x200u);
    put32(b, opt + 0x38u, 0x4000u); // SizeOfImage
    put32(b, opt + 0x3Cu, 0x400u);  // SizeOfHeaders
    put16(b, opt + 0x46u, dll_chars_override);
    put32(b, opt + 0x6Cu, 16u);     // NumberOfRvaAndSizes

    auto write_sec = [&](std::size_t idx, const char name8[8], std::uint32_t vsize,
                         std::uint32_t rva, std::uint32_t raw_sz, std::uint32_t raw_off,
                         std::uint32_t ch) {
        const std::size_t sh = opt + 0xF0u + idx * 40u;
        std::memcpy(&b[sh], name8, 8u);
        put32(b, sh + 8u, vsize);
        put32(b, sh + 12u, rva);
        put32(b, sh + 16u, raw_sz);
        put32(b, sh + 20u, raw_off);
        put32(b, sh + 36u, ch);
    };

    write_sec(0u, ".text\0\0\0", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u); // RX
    write_sec(1u, ".rdata\0\0", 0x800u, 0x2000u, 0x800u, 0x600u, 0x40000040u); // R

    // .text: ret
    b[0x400u] = 0xC3u;

    // LoadConfig64 @ RVA 0x2000 (file 0x600), size 0xA0
    const std::size_t lc = 0x600u;
    put32(b, lc + 0x00u, 0xA0u);                    // Size
    put64(b, lc + 0x58u, 0x140002500ull);           // SecurityCookie
    put64(b, lc + 0x70u, 0x140002600ull);           // GuardCFCheckFunctionPointer
    put64(b, lc + 0x80u, 0x140002700ull);           // GuardCFFunctionTable
    put64(b, lc + 0x88u, 2ull);                     // GuardCFFunctionCount
    put32(b, lc + 0x90u, 0x00000500u);              // IMAGE_GUARD_CF_INSTRUMENTED | FUNCTION_TABLE_PRESENT

    // DataDirectory[10] = LoadConfig (opt + 0x70 + 10*8 = opt + 0xC0)
    put32(b, opt + 0xC0u, 0x2000u);
    put32(b, opt + 0xC4u, 0xA0u);

    // DebugDirectory @ RVA 0x2200 (file 0x800), 1 entry (28 bytes) -> type 20 (EX_DLLCHARACTERISTICS)
    const std::size_t dbg = 0x800u;
    put32(b, dbg + 12u, 20u);     // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
    put32(b, dbg + 16u, 4u);      // SizeOfData
    put32(b, dbg + 20u, 0x2240u); // AddressOfRawData
    put32(b, dbg + 24u, 0x840u);  // PointerToRawData
    put32(b, 0x840u, 0x0001u);    // IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT

    // DataDirectory[6] = Debug (opt + 0x70 + 6*8 = opt + 0xA0)
    put32(b, opt + 0xA0u, 0x2200u);
    put32(b, opt + 0xA4u, 28u);

    // Embedded string in .rdata @ file 0x880 (RVA 0x2280)
    const std::string_view marker = "PEELF_HEADLESS_MARKER_STRING";
    std::memcpy(&b[0x880u], marker.data(), marker.size());

    if (cert_mode == PeCertFixtureMode::MalformedDummyCert) {
        // CertificateTable @ file offset 0x1000 (DataDirectory[4] uses file offset, not RVA!)
        put32(b, 0x1000u, 16u);     // dwLength
        put16(b, 0x1004u, 0x0200u); // WIN_CERT_REVISION_2_0
        put16(b, 0x1006u, 0x0002u); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        // Non-ASN.1 DER SEQUENCE payload rejected identically across Windows and Linux.
        b[0x1008u] = 0xDEu;
        b[0x1009u] = 0xADu;
        b[0x100Au] = 0xBEu;
        b[0x100Bu] = 0xEFu;
        put32(b, opt + 0x90u, 0x1000u);
        put32(b, opt + 0x94u, 16u);
    }

    return b;
}

// Builds an intentionally vulnerable 32-bit x86 PE32 image triggering PE1001..PE1008 failures.
std::vector<std::uint8_t> build_vulnerable_pe32_x86() {
    std::vector<std::uint8_t> b(0x800u, 0u);
    b[0u] = 'M';
    b[1u] = 'Z';
    put32(b, 0x3Cu, 0x80u);

    b[0x80u] = 'P';
    b[0x81u] = 'E';
    put16(b, 0x84u, 0x014Cu); // IMAGE_FILE_MACHINE_I386
    put16(b, 0x86u, 2u);      // .text (RWX) + .shr (RWS)
    put16(b, 0x94u, 0xE0u);   // SizeOfOptionalHeader (PE32)
    put16(b, 0x96u, 0x0102u); // EXECUTABLE_IMAGE | 32BIT_MACHINE

    const std::size_t opt = 0x98u;
    put16(b, opt + 0x00u, 0x10Bu); // PE32
    put32(b, opt + 0x10u, 0x1000u);
    put32(b, opt + 0x1Cu, 0x00400000u); // ImageBase
    put32(b, opt + 0x20u, 0x1000u);
    put32(b, opt + 0x24u, 0x200u);
    put32(b, opt + 0x38u, 0x3000u);
    put32(b, opt + 0x3Cu, 0x400u);
    // DllCharacteristics @ opt + 0x46: FORCE_INTEGRITY (0x0080) WITHOUT cert, NO ASLR, NO NX, NO NO_SEH!
    put16(b, opt + 0x46u, 0x0080u);
    put32(b, opt + 0x5Cu, 16u); // NumberOfRvaAndSizes (PE32 offset 0x5C)

    auto write_sec = [&](std::size_t idx, const char name8[8], std::uint32_t vsize,
                         std::uint32_t rva, std::uint32_t raw_sz, std::uint32_t raw_off,
                         std::uint32_t ch) {
        const std::size_t sh = opt + 0xE0u + idx * 40u;
        std::memcpy(&b[sh], name8, 8u);
        put32(b, sh + 8u, vsize);
        put32(b, sh + 12u, rva);
        put32(b, sh + 16u, raw_sz);
        put32(b, sh + 20u, raw_off);
        put32(b, sh + 36u, ch);
    };

    // RWX section: IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE = 0xE0000020
    write_sec(0u, ".text\0\0\0", 0x200u, 0x1000u, 0x200u, 0x400u, 0xE0000020u);
    // Writable + Shared section: IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_SHARED | MEM_READ | MEM_WRITE = 0xD0000040
    write_sec(1u, ".shr\0\0\0\0", 0x200u, 0x2000u, 0x200u, 0x600u, 0xD0000040u);
    b[0x400u] = 0xC3u;
    return b;
}

struct ElfSecuritySpec {
    bool pie{true};
    bool exec_stack{false};
    bool has_relro{true};
    bool bind_now{true};
    bool has_canary{true};
    bool has_fortify_chk{true};
    bool has_unfortified_strcpy{false};
    bool rwx_segment{false};
    std::string rpath{};
    std::string runpath{"/usr/lib/myapp"};
    bool emit_empty_rpath{false};
    bool emit_empty_runpath{false};
    bool has_cet_note{true};
    std::uint8_t code_imm{0x2Au};
};

std::vector<std::uint8_t> build_elf64_security_fixture(const ElfSecuritySpec& spec) {
    std::vector<std::uint8_t> dynstr{0};
    std::vector<std::uint8_t> strtab{0};
    std::vector<std::uint8_t> shstrtab{0};

    auto add_str = [](std::vector<std::uint8_t>& tab, std::string_view s) -> std::uint32_t {
        const auto off = static_cast<std::uint32_t>(tab.size());
        tab.insert(tab.end(), s.begin(), s.end());
        tab.push_back(0u);
        return off;
    };

    const std::uint32_t sh_interp_nm = add_str(shstrtab, ".interp");
    const std::uint32_t sh_note_nm = add_str(shstrtab, ".note.gnu.property");
    const std::uint32_t sh_text_nm = add_str(shstrtab, ".text");
    const std::uint32_t sh_rodata_nm = add_str(shstrtab, ".rodata");
    const std::uint32_t sh_dyn_nm = add_str(shstrtab, ".dynamic");
    const std::uint32_t sh_dynstr_nm = add_str(shstrtab, ".dynstr");
    const std::uint32_t sh_symtab_nm = add_str(shstrtab, ".symtab");
    const std::uint32_t sh_strtab_nm = add_str(shstrtab, ".strtab");
    const std::uint32_t sh_shstr_nm = add_str(shstrtab, ".shstrtab");

    const std::string interp_str = "/lib64/ld-linux-x86-64.so.2";
    std::vector<std::uint8_t> interp_bytes(interp_str.begin(), interp_str.end());
    interp_bytes.push_back(0u);

    // .note.gnu.property: namesz=4 ("GNU\0"), descsz=16, type=5 (NT_GNU_PROPERTY_TYPE_0)
    // Property: pr_type=0xC0000002 (X86_FEATURE_1_AND), pr_datasz=4, data=0x03 (IBT|SHSTK), 4-byte pad
    std::vector<std::uint8_t> note_bytes(32u, 0u);
    put32(note_bytes, 0u, 4u);
    put32(note_bytes, 4u, 16u);
    put32(note_bytes, 8u, 5u);
    note_bytes[12u] = 'G';
    note_bytes[13u] = 'N';
    note_bytes[14u] = 'U';
    note_bytes[15u] = 0u;
    put32(note_bytes, 16u, 0xC0000002u);
    put32(note_bytes, 20u, 4u);
    put32(note_bytes, 24u, 0x00000003u); // IBT | SHSTK

    // .text @ VA 0x1000: `mov eax, imm32; ret`
    std::vector<std::uint8_t> text_bytes(64u, 0x90u);
    text_bytes[0u] = 0xB8u;
    put32(text_bytes, 1u, spec.code_imm);
    text_bytes[5u] = 0xC3u;

    // .rodata @ VA 0x2000: printable string for `--include-strings`
    const std::string ro_str = "ELF_HEADLESS_AUDIT_TOKEN_2026";
    std::vector<std::uint8_t> rodata_bytes(ro_str.begin(), ro_str.end());
    rodata_bytes.push_back(0u);

    // .symtab entries: null + `_ZN6Widget4tickEi` (defined func) + optional `__stack_chk_fail`, `__memcpy_chk`, `strcpy`
    std::vector<std::uint8_t> symtab(24u, 0u);
    auto push_sym = [&](std::string_view name, std::uint16_t shndx, std::uint64_t va, std::uint64_t sz) {
        const std::uint32_t noff = add_str(strtab, name);
        const std::size_t base = symtab.size();
        symtab.resize(base + 24u, 0u);
        put32(symtab, base + 0u, noff);
        symtab[base + 4u] = static_cast<std::uint8_t>((1u << 4u) | 2u); // STB_GLOBAL | STT_FUNC
        put16(symtab, base + 6u, shndx);
        put64(symtab, base + 8u, va);
        put64(symtab, base + 16u, sz);
    };
    push_sym("_ZN6Widget4tickEi", 3u, 0x1000u, 6u);
    if (spec.has_canary) {
        push_sym("__stack_chk_fail", 0u, 0u, 0u);
    }
    if (spec.has_fortify_chk) {
        push_sym("__memcpy_chk", 0u, 0u, 0u);
    }
    if (spec.has_unfortified_strcpy) {
        push_sym("strcpy", 0u, 0u, 0u);
    }

    // .dynamic entries
    std::uint32_t rpath_off = 0u;
    std::uint32_t runpath_off = 0u;
    if (!spec.rpath.empty()) rpath_off = add_str(dynstr, spec.rpath);
    if (!spec.runpath.empty()) runpath_off = add_str(dynstr, spec.runpath);

    std::vector<std::uint8_t> dynamic_bytes;
    auto push_dyn = [&](std::uint64_t tag, std::uint64_t val) {
        const std::size_t base = dynamic_bytes.size();
        dynamic_bytes.resize(base + 16u, 0u);
        put64(dynamic_bytes, base + 0u, tag);
        put64(dynamic_bytes, base + 8u, val);
    };

    // Reserve header + up to 6 program headers (0x40 + 6 * 56 = 0x190 -> pad to 0x200)
    std::vector<std::uint8_t> out(0x200u, 0u);
    auto append_aligned = [&](const std::vector<std::uint8_t>& sec) -> std::uint64_t {
        while ((out.size() % 16u) != 0u) out.push_back(0u);
        const auto off = static_cast<std::uint64_t>(out.size());
        out.insert(out.end(), sec.begin(), sec.end());
        return off;
    };

    const std::uint64_t interp_off = append_aligned(interp_bytes);
    const std::uint64_t note_off = spec.has_cet_note ? append_aligned(note_bytes) : 0u;
    const std::uint64_t text_off = append_aligned(text_bytes);
    const std::uint64_t rodata_off = append_aligned(rodata_bytes);
    const std::uint64_t dynstr_off = append_aligned(dynstr);
    const std::uint64_t dynstr_va = 0x2400u;

    push_dyn(5u, dynstr_va);            // DT_STRTAB
    push_dyn(10u, dynstr.size());       // DT_STRSZ
    if (!spec.rpath.empty() || spec.emit_empty_rpath) push_dyn(15u, rpath_off);
    if (!spec.runpath.empty() || spec.emit_empty_runpath) push_dyn(29u, runpath_off);
    std::uint64_t flags_1 = 0u;
    if (spec.pie) flags_1 |= 0x08000000ull;      // DF_1_PIE
    if (spec.bind_now) flags_1 |= 0x00000001ull; // DF_1_NOW
    if (flags_1 != 0u) push_dyn(0x6FFFFFFBull, flags_1);
    if (spec.bind_now) push_dyn(24u, 0u); // DT_BIND_NOW
    push_dyn(0u, 0u);                     // DT_NULL

    const std::uint64_t dyn_off = append_aligned(dynamic_bytes);
    const std::uint64_t symtab_off = append_aligned(symtab);
    const std::uint64_t strtab_off = append_aligned(strtab);
    const std::uint64_t shstr_off = append_aligned(shstrtab);
    while ((out.size() % 16u) != 0u) out.push_back(0u);

    const std::uint64_t shoff = out.size();
    constexpr std::uint16_t kShNum = 10u;
    out.resize(out.size() + kShNum * 64u, 0u);

    // ELF64 header
    out[0u] = 0x7Fu; out[1u] = 'E'; out[2u] = 'L'; out[3u] = 'F';
    out[4u] = 2u; // ELFCLASS64
    out[5u] = 1u; // ELFDATA2LSB
    out[6u] = 1u; // EV_CURRENT
    put16(out, 16u, spec.pie ? 3u : 2u); // ET_DYN vs ET_EXEC
    put16(out, 18u, 62u);                // EM_X86_64
    put32(out, 20u, 1u);
    put64(out, 24u, 0x1000u);            // e_entry
    put64(out, 32u, 0x40u);              // e_phoff
    put64(out, 40u, shoff);              // e_shoff
    put16(out, 52u, 64u);
    put16(out, 54u, 56u);

    std::uint16_t ph_count = 0u;
    auto push_phdr = [&](std::uint32_t p_type, std::uint32_t p_flags, std::uint64_t p_off,
                         std::uint64_t p_vaddr, std::uint64_t p_filesz, std::uint64_t p_memsz) {
        const std::size_t ph = 0x40u + static_cast<std::size_t>(ph_count++) * 56u;
        put32(out, ph + 0u, p_type);
        put32(out, ph + 4u, p_flags);
        put64(out, ph + 8u, p_off);
        put64(out, ph + 16u, p_vaddr);
        put64(out, ph + 24u, p_vaddr);
        put64(out, ph + 32u, p_filesz);
        put64(out, ph + 40u, p_memsz);
        put64(out, ph + 48u, 0x1000u);
    };

    // PT_INTERP
    push_phdr(3u, 4u, interp_off, 0x0300u, interp_bytes.size(), interp_bytes.size());
    // PT_LOAD (.text)
    push_phdr(1u, spec.rwx_segment ? 7u : 5u, text_off, 0x1000u, text_bytes.size(), text_bytes.size());
    // PT_LOAD (.rodata + .dynstr + .dynamic)
    push_phdr(1u, 4u, rodata_off, 0x2000u, rodata_bytes.size(), rodata_bytes.size());
    // PT_DYNAMIC
    push_phdr(2u, 6u, dyn_off, 0x3000u, dynamic_bytes.size(), dynamic_bytes.size());
    // PT_GNU_STACK
    push_phdr(0x6474E551u, spec.exec_stack ? 7u : 6u, 0u, 0u, 0u, 0u);
    // Optional PT_GNU_RELRO
    if (spec.has_relro) {
        push_phdr(0x6474E552u, 4u, dyn_off, 0x3000u, dynamic_bytes.size(), dynamic_bytes.size());
    }

    put16(out, 56u, ph_count);
    put16(out, 58u, 64u);
    put16(out, 60u, kShNum);
    put16(out, 62u, kShNum - 1u);

    auto write_sh = [&](std::size_t idx, std::uint32_t nm, std::uint32_t type, std::uint64_t flags,
                        std::uint64_t addr, std::uint64_t off, std::uint64_t sz,
                        std::uint32_t link = 0u, std::uint32_t info = 0u, std::uint64_t entsz = 0u) {
        const std::size_t sh = static_cast<std::size_t>(shoff) + idx * 64u;
        put32(out, sh + 0u, nm);
        put32(out, sh + 4u, type);
        put64(out, sh + 8u, flags);
        put64(out, sh + 16u, addr);
        put64(out, sh + 24u, off);
        put64(out, sh + 32u, sz);
        put32(out, sh + 40u, link);
        put32(out, sh + 44u, info);
        put64(out, sh + 48u, 8u);
        put64(out, sh + 56u, entsz);
    };

    write_sh(1u, sh_interp_nm, 1u, 0x2u, 0x0300u, interp_off, interp_bytes.size());
    if (spec.has_cet_note) {
        write_sh(2u, sh_note_nm, 7u, 0x2u, 0x0340u, note_off, note_bytes.size()); // SHT_NOTE = 7
    } else {
        write_sh(2u, sh_note_nm, 8u, 0u, 0u, 0u, 0u); // SHT_NOBITS placeholder
    }
    write_sh(3u, sh_text_nm, 1u, spec.rwx_segment ? 0x7u : 0x6u, 0x1000u, text_off, text_bytes.size());
    write_sh(4u, sh_rodata_nm, 1u, 0x2u, 0x2000u, rodata_off, rodata_bytes.size());
    write_sh(5u, sh_dynstr_nm, 3u, 0x2u, dynstr_va, dynstr_off, dynstr.size());
    write_sh(6u, sh_dyn_nm, 6u, 0x3u, 0x3000u, dyn_off, dynamic_bytes.size(), 5u, 0u, 16u);
    write_sh(7u, sh_symtab_nm, 2u, 0u, 0u, symtab_off, symtab.size(), 8u, 1u, 24u);
    write_sh(8u, sh_strtab_nm, 3u, 0u, 0u, strtab_off, strtab.size());
    write_sh(9u, sh_shstr_nm, 3u, 0u, 0u, shstr_off, shstrtab.size());

    return out;
}

class MockSecuritySession final : public peelf::IProcessSession {
public:
    explicit MockSecuritySession(std::vector<peelf::MemoryRegion> regs)
        : regions_(std::move(regs)) {
        info_.pid = 4242;
        info_.name = "audit_target";
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override { return regions_; }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override { return std::vector<peelf::ModuleInfo>{}; }
    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t, std::span<std::uint8_t>) override {
        return peelf::make_error("not needed");
    }
    [[nodiscard]] peelf::Result<std::size_t> write_memory(std::uint64_t,
                                                          std::span<const std::uint8_t>,
                                                          peelf::MemoryWriteOptions) override {
        return peelf::make_error("read-only");
    }

private:
    peelf::ProcessInfo info_{};
    std::vector<peelf::MemoryRegion> regions_{};
};

struct TempTestDir {
    std::filesystem::path dir{};
    explicit TempTestDir(std::string_view prefix) {
        static std::atomic<std::uint64_t> s_seq{0};
        const std::uint64_t seq = s_seq.fetch_add(1u, std::memory_order_relaxed);
#ifdef _WIN32
        const int pid = _getpid();
#else
        const int pid = static_cast<int>(::getpid());
#endif
        dir = std::filesystem::temp_directory_path() /
              (std::string(prefix) + "-" + std::to_string(pid) + "-" + std::to_string(seq));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
    }
    ~TempTestDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    TempTestDir(const TempTestDir&) = delete;
    TempTestDir& operator=(const TempTestDir&) = delete;
    TempTestDir(TempTestDir&&) = delete;
    TempTestDir& operator=(TempTestDir&&) = delete;
};

void write_bytes(const std::filesystem::path& p, std::span<const std::uint8_t> bytes) {
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(static_cast<bool>(ofs));
    ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(static_cast<bool>(ofs));
}

#if defined(PEELF_VIEWER_EXECUTABLE_PATH)
[[nodiscard]] std::filesystem::path configured_viewer_executable_path() {
    return std::filesystem::path{PEELF_VIEWER_EXECUTABLE_PATH};
}

[[nodiscard]] peelf::SubprocessResult run_viewer_subproc(std::span<const std::string> cli_args) {
    return peelf::run_subprocess_bounded(configured_viewer_executable_path(), cli_args);
}
#endif

} // namespace

TEST(SecurityAuditTest, RuleCatalogCoversAll19FormalizedRules) {
    const auto catalog = peelf::security_rule_catalog();
    EXPECT_EQ(catalog.size(), 25u);
    EXPECT_EQ(catalog.front().id, "PE1001");
    EXPECT_EQ(catalog.back().id, "LIVE3003");
}

TEST(SecurityAuditTest, HardenedPe64PassesAllPeRules) {
    const auto raw = build_hardened_pe64();
    auto parsed = peelf::parse_image(raw);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const peelf::SecurityAuditReport audit = peelf::audit_security(**parsed, raw);
    EXPECT_TRUE(audit.status.has_data());
    EXPECT_EQ(audit.error_count, 0u);
    EXPECT_EQ(audit.warning_count, 0u);
    EXPECT_EQ(audit.note_count, 1u);
    EXPECT_EQ(audit.pass_count, 7u);

    for (std::string_view id : {"PE1001", "PE1002", "PE1003", "PE1004", "PE1006", "PE1007", "PE1008"}) {
        const auto* f = find_rule(audit, id);
        ASSERT_NE(f, nullptr) << "Missing rule " << id;
        EXPECT_EQ(f->severity, peelf::SecuritySeverity::Pass) << id << ": " << f->summary << " | " << f->evidence;
    }

    // Unsigned PE without FORCE_INTEGRITY yields identical Note severity on Windows and Linux.
    const auto* pe1005 = find_rule(audit, "PE1005");
    ASSERT_NE(pe1005, nullptr);
    EXPECT_EQ(pe1005->severity, peelf::SecuritySeverity::Note);

    // Malformed dummy certificate yields identical Error severity on Windows and Linux.
    const auto dummy_cert_raw = build_hardened_pe64(0x41E0u, PeCertFixtureMode::MalformedDummyCert);
    auto parsed_dummy = peelf::parse_image(dummy_cert_raw);
    ASSERT_TRUE(parsed_dummy.has_value());
    const auto dummy_audit = peelf::audit_security(**parsed_dummy, dummy_cert_raw);
    const auto* dummy_pe1005 = find_rule(dummy_audit, "PE1005");
    ASSERT_NE(dummy_pe1005, nullptr);
    EXPECT_EQ(dummy_pe1005->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(dummy_audit.error_count, 1u);
    EXPECT_EQ(dummy_audit.warning_count, 0u);
    EXPECT_EQ(dummy_audit.note_count, 0u);
    EXPECT_EQ(dummy_audit.pass_count, 7u);

    // Without HIGH_ENTROPY_VA on 64-bit, PE1001 degrades to Warning (32-bit entropy ASLR) on all hosts.
    const auto low_entropy_raw = build_hardened_pe64(0x4140u); // DYNAMIC_BASE without HIGH_ENTROPY_VA
    auto parsed_low = peelf::parse_image(low_entropy_raw);
    ASSERT_TRUE(parsed_low.has_value());
    const auto low_audit = peelf::audit_security(**parsed_low, low_entropy_raw);
    const auto* pe1001 = find_rule(low_audit, "PE1001");
    ASSERT_NE(pe1001, nullptr);
    EXPECT_EQ(pe1001->severity, peelf::SecuritySeverity::Warning);
    EXPECT_EQ(low_audit.error_count, 0u);
    EXPECT_EQ(low_audit.warning_count, 1u);
    EXPECT_EQ(low_audit.note_count, 1u);
}

TEST(SecurityAuditTest, VulnerablePe32TriggersExpectedRuleViolations) {
    const auto raw = build_vulnerable_pe32_x86();
    auto parsed = peelf::parse_image(raw);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const peelf::SecurityAuditReport audit = peelf::audit_security(**parsed, raw);
    ASSERT_EQ(audit.findings.size(), 8u);

    EXPECT_EQ(find_rule(audit, "PE1001")->severity, peelf::SecuritySeverity::Error);   // No DYNAMIC_BASE
    EXPECT_EQ(find_rule(audit, "PE1002")->severity, peelf::SecuritySeverity::Error);   // No NX_COMPAT
    EXPECT_EQ(find_rule(audit, "PE1003")->severity, peelf::SecuritySeverity::Warning); // No GUARD_CF
    EXPECT_EQ(find_rule(audit, "PE1004")->severity, peelf::SecuritySeverity::Error);   // x86 PE32 missing SafeSEH & NO_SEH
    EXPECT_EQ(find_rule(audit, "PE1005")->severity, peelf::SecuritySeverity::Error);   // FORCE_INTEGRITY=1 with 0 certs
    EXPECT_EQ(find_rule(audit, "PE1006")->severity, peelf::SecuritySeverity::Note);    // Missing CET debug entry

    const auto* pe1007 = find_rule(audit, "PE1007");
    ASSERT_NE(pe1007, nullptr);
    EXPECT_EQ(pe1007->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(pe1007->subject, ".text");
    EXPECT_EQ(pe1007->virtual_address, 0x00401000ull);

    const auto* pe1008 = find_rule(audit, "PE1008");
    ASSERT_NE(pe1008, nullptr);
    EXPECT_EQ(pe1008->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(pe1008->subject, ".shr");
    EXPECT_EQ(pe1008->virtual_address, 0x00402000ull);
}

TEST(SecurityAuditTest, HardenedAndVulnerableElf64CoverAllElfRules) {
    // 1. Hardened PIE ELF64
    const auto hardened_raw = build_elf64_security_fixture(ElfSecuritySpec{});
    auto hardened_img = peelf::parse_image(hardened_raw);
    ASSERT_TRUE(hardened_img.has_value()) << hardened_img.error().message;

    const peelf::SecurityAuditReport clean = peelf::audit_security(**hardened_img, hardened_raw);
    EXPECT_EQ(clean.error_count, 0u);
    EXPECT_EQ(clean.warning_count, 0u);
    EXPECT_EQ(clean.pass_count, 8u);
    for (std::string_view id :
         {"ELF2001", "ELF2002", "ELF2003", "ELF2004", "ELF2005", "ELF2006", "ELF2007", "ELF2008"}) {
        const auto* f = find_rule(clean, id);
        ASSERT_NE(f, nullptr) << id;
        EXPECT_EQ(f->severity, peelf::SecuritySeverity::Pass) << id << ": " << f->summary << " | " << f->evidence;
    }

    // 2. Vulnerable non-PIE ELF64 with RWX stack, Partial RELRO, unfortified strcpy, RWX PT_LOAD, insecure DT_RPATH
    ElfSecuritySpec bad_spec;
    bad_spec.pie = false;
    bad_spec.exec_stack = true;
    bad_spec.has_relro = true;
    bad_spec.bind_now = false; // Partial RELRO
    bad_spec.has_canary = false;
    bad_spec.has_fortify_chk = false;
    bad_spec.has_unfortified_strcpy = true;
    bad_spec.rwx_segment = true;
    bad_spec.rpath = ".:/tmp/untrusted";
    bad_spec.runpath.clear();
    bad_spec.has_cet_note = false;

    const auto bad_raw = build_elf64_security_fixture(bad_spec);
    auto bad_img = peelf::parse_image(bad_raw);
    ASSERT_TRUE(bad_img.has_value()) << bad_img.error().message;

    const peelf::SecurityAuditReport vuln = peelf::audit_security(**bad_img, bad_raw);
    EXPECT_EQ(find_rule(vuln, "ELF2001")->severity, peelf::SecuritySeverity::Error);   // Non-PIE ET_EXEC
    EXPECT_EQ(find_rule(vuln, "ELF2002")->severity, peelf::SecuritySeverity::Error);   // PF_X stack
    EXPECT_EQ(find_rule(vuln, "ELF2003")->severity, peelf::SecuritySeverity::Warning); // Partial RELRO
    EXPECT_EQ(find_rule(vuln, "ELF2004")->severity, peelf::SecuritySeverity::Warning); // No stack canary
    EXPECT_EQ(find_rule(vuln, "ELF2005")->severity, peelf::SecuritySeverity::Warning); // Unfortified strcpy
    EXPECT_EQ(find_rule(vuln, "ELF2006")->severity, peelf::SecuritySeverity::Error);   // RWX PT_LOAD
    EXPECT_EQ(find_rule(vuln, "ELF2007")->severity, peelf::SecuritySeverity::Error);   // '.' & '/tmp' DT_RPATH
    EXPECT_EQ(find_rule(vuln, "ELF2008")->severity, peelf::SecuritySeverity::Note);    // Missing CET GNU property
}

TEST(SecurityAuditTest, LiveProcessRulesDetectRwxUnbackedExecAndDisabledMitigations) {
    // Clean live session (file-backed RX module, vDSO RX exempted, RW stack, Seccomp filter enabled)
    std::vector<peelf::MemoryRegion> clean_regions{
        peelf::MemoryRegion{
            .start_address = 0x555555554000ull,
            .end_address = 0x555555558000ull,
            .protection = {.readable = true, .writable = false, .executable = true, .shared = false},
            .kind = peelf::MemoryRegionKind::Image,
            .pathname = "/usr/bin/app"},
        peelf::MemoryRegion{
            .start_address = 0x7ffff7ffa000ull,
            .end_address = 0x7ffff7ffc000ull,
            .protection = {.readable = true, .writable = false, .executable = true, .shared = false},
            .kind = peelf::MemoryRegionKind::Vdso,
            .pathname = "[vdso]"},
        peelf::MemoryRegion{
            .start_address = 0x7ffffffde000ull,
            .end_address = 0x7ffffffff000ull,
            .protection = {.readable = true, .writable = true, .executable = false, .shared = false},
            .kind = peelf::MemoryRegionKind::Stack,
            .pathname = "[stack]"},
    };
    MockSecuritySession clean_sess(clean_regions);
    peelf::ProcessSecurityProfile clean_prof;
    clean_prof.seccomp_mode = "2 (filter)";
    clean_prof.no_new_privs = true;
    clean_prof.mitigations.push_back({"DEP", "Enabled", true, ""});
    clean_prof.mitigations.push_back({"ASLR", "Enabled", true, ""});

    const auto clean_live = peelf::audit_live_process_security(clean_sess, &clean_prof);
    EXPECT_EQ(find_rule(clean_live, "LIVE3001")->severity, peelf::SecuritySeverity::Pass);
    EXPECT_EQ(find_rule(clean_live, "LIVE3002")->severity, peelf::SecuritySeverity::Pass);
    EXPECT_EQ(find_rule(clean_live, "LIVE3003")->severity, peelf::SecuritySeverity::Pass);

    // Vulnerable live session: RWX stack + unbacked anonymous RX shellcode + disabled DEP
    std::vector<peelf::MemoryRegion> bad_regions = clean_regions;
    bad_regions[2].protection.executable = true; // RWX stack!
    bad_regions.push_back(peelf::MemoryRegion{
        .start_address = 0x7f0000100000ull,
        .end_address = 0x7f0000104000ull,
        .protection = {.readable = true, .writable = false, .executable = true, .shared = false},
        .kind = peelf::MemoryRegionKind::Anonymous,
        .pathname = ""});

    MockSecuritySession bad_sess(bad_regions);
    peelf::ProcessSecurityProfile bad_prof;
    bad_prof.seccomp_mode = "0 (disabled)";
    bad_prof.mitigations.push_back({"DEP (Data Execution Prevention)", "Disabled", false, ""});

    const auto bad_live = peelf::audit_live_process_security(bad_sess, &bad_prof);
    const auto* l3001 = find_rule(bad_live, "LIVE3001");
    ASSERT_NE(l3001, nullptr);
    EXPECT_EQ(l3001->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(l3001->virtual_address, 0x7ffffffde000ull);

    EXPECT_EQ(find_rule(bad_live, "LIVE3002")->severity, peelf::SecuritySeverity::Warning);
    EXPECT_EQ(find_rule(bad_live, "LIVE3003")->severity, peelf::SecuritySeverity::Error);

    // Indeterminate live profile: empty ProcessSecurityProfile (no observed telemetry) must report Note, not Pass!
    peelf::ProcessSecurityProfile empty_prof{};
    const auto empty_live = peelf::audit_live_process_security(clean_sess, &empty_prof);
    const auto* l3003_empty = find_rule(empty_live, "LIVE3003");
    ASSERT_NE(l3003_empty, nullptr);
    EXPECT_EQ(l3003_empty->severity, peelf::SecuritySeverity::Note);
}

TEST(SecurityAuditTest, DetectsEmptyColonRpathCwdHazardAndStrippedPeRelocations) {
    // 1. ELF2007: empty DT_RPATH (""), empty DT_RUNPATH (""), consecutive colons ("::"),
    //    leading colon (":/usr/lib"), and trailing colon ("/usr/lib:") all imply CWD loading!
    {
        ElfSecuritySpec empty_rpath_spec;
        empty_rpath_spec.runpath.clear();
        empty_rpath_spec.emit_empty_rpath = true;
        const auto raw = build_elf64_security_fixture(empty_rpath_spec);
        const auto img = peelf::parse_image(raw);
        ASSERT_TRUE(img.has_value()) << img.error().message;
        const auto report = peelf::audit_security(**img, raw);
        const auto* elf2007 = find_rule(report, "ELF2007");
        ASSERT_NE(elf2007, nullptr);
        EXPECT_EQ(elf2007->severity, peelf::SecuritySeverity::Error);
    }
    {
        ElfSecuritySpec empty_runpath_spec;
        empty_runpath_spec.runpath.clear();
        empty_runpath_spec.emit_empty_runpath = true;
        const auto raw = build_elf64_security_fixture(empty_runpath_spec);
        const auto img = peelf::parse_image(raw);
        ASSERT_TRUE(img.has_value()) << img.error().message;
        const auto report = peelf::audit_security(**img, raw);
        const auto* elf2007 = find_rule(report, "ELF2007");
        ASSERT_NE(elf2007, nullptr);
        EXPECT_EQ(elf2007->severity, peelf::SecuritySeverity::Error);
    }
    for (std::string_view colon_path : {"/usr/lib::/opt/lib", ":/usr/lib", "/usr/lib:"}) {
        ElfSecuritySpec colon_spec;
        colon_spec.rpath = std::string(colon_path);
        colon_spec.runpath.clear();
        const auto raw = build_elf64_security_fixture(colon_spec);
        const auto img = peelf::parse_image(raw);
        ASSERT_TRUE(img.has_value()) << img.error().message;
        const auto report = peelf::audit_security(**img, raw);
        const auto* elf2007 = find_rule(report, "ELF2007");
        ASSERT_NE(elf2007, nullptr) << colon_path;
        EXPECT_EQ(elf2007->severity, peelf::SecuritySeverity::Error) << colon_path;
    }

    // 2. PE1001: setting IMAGE_FILE_RELOCS_STRIPPED (0x0001) on a PE64 image that otherwise has
    //    DYNAMIC_BASE | HIGH_ENTROPY_VA set must fail PE1001 as Error!
    {
        auto stripped_pe = build_hardened_pe64();
        put16(stripped_pe, 0x96u, 0x0023u); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | RELOCS_STRIPPED
        const auto img = peelf::parse_image(stripped_pe);
        ASSERT_TRUE(img.has_value()) << img.error().message;
        const auto report = peelf::audit_security(**img, stripped_pe);
        const auto* pe1001 = find_rule(report, "PE1001");
        ASSERT_NE(pe1001, nullptr);
        EXPECT_EQ(pe1001->severity, peelf::SecuritySeverity::Error);
        EXPECT_EQ(pe1001->subject, "FileHeader.Characteristics");
        EXPECT_EQ(pe1001->file_offset, std::optional<std::uint64_t>(0x96u));
        EXPECT_NE(pe1001->evidence.find("RELOCS_STRIPPED=1"), std::string::npos);
    }
}

TEST(SecurityHeadlessCliTest, JsonSarifComparePolicyGatesAndBinaryModelIntegration) {
    TempTestDir tmp("peelf-wu13-headless");
    const auto hardened_elf = tmp.dir / "hardened_v1.elf";
    ElfSecuritySpec v2_spec;
    v2_spec.code_imm = 0x7Fu; // modify .text function body for `--compare`
    const auto modified_elf = tmp.dir / "hardened_v2.elf";
    const auto hardened_pe = tmp.dir / "hardened_unsigned_x64.exe";
    const auto low_entropy_pe = tmp.dir / "low_entropy_unsigned_x64.exe";
    const auto dummy_cert_pe = tmp.dir / "dummy_cert_x64.exe";
    const auto vuln_pe = tmp.dir / "vulnerable_x86.exe";

    write_bytes(hardened_elf, build_elf64_security_fixture(ElfSecuritySpec{}));
    write_bytes(modified_elf, build_elf64_security_fixture(v2_spec));
    write_bytes(hardened_pe, build_hardened_pe64());
    write_bytes(low_entropy_pe, build_hardened_pe64(0x4140u));
    write_bytes(dummy_cert_pe, build_hardened_pe64(0x41E0u, PeCertFixtureMode::MalformedDummyCert));
    write_bytes(vuln_pe, build_vulnerable_pe32_x86());

    // Verify BinaryModel populates `security_audit()` automatically on file load.
    {
        viewer::BinaryModel model;
        ASSERT_TRUE(model.load_file(hardened_elf.string()));
        EXPECT_TRUE(model.security_audit().status.has_data());
        EXPECT_EQ(model.security_audit().pass_count, 8u);
        EXPECT_EQ(model.security_audit().error_count, 0u);
    }

    // 1. Bare `--headless` (no input file) -> returns 0 cleanly with no output!
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 1> args{"--headless"};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0);
        EXPECT_TRUE(out_ss.str().empty());
        EXPECT_TRUE(err_ss.str().empty());
    }

    // 2. Headless JSON export with `--include-strings`, `--min-string-len`, `--compare`, `--fail-on warning`
    const auto json_path = tmp.dir / "report.json";
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::string p1 = hardened_elf.string();
        const std::string p2 = modified_elf.string();
        const std::string out_p = json_path.string();
        const std::string root_p = tmp.dir.string();
        const std::vector<std::string_view> vec_args{
            "--headless", p1,
            "--compare", p2,
            "--search-root", root_p,
            "--include-strings",
            "--min-string-len", "8",
            "--fail-on", "warning",
            "--output", out_p};
        const auto rc = peelf::try_run_headless_or_help_cli(vec_args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();

        std::ifstream ifs(json_path);
        ASSERT_TRUE(static_cast<bool>(ifs));
        const std::string json_text((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        EXPECT_NE(json_text.find("\"schema_version\": 1"), std::string::npos);
        EXPECT_NE(json_text.find("\"format\": \"ELF\""), std::string::npos);
        EXPECT_NE(json_text.find("\"demangled_name\": \"Widget::tick(int)\""), std::string::npos);
        EXPECT_NE(json_text.find("ELF_HEADLESS_AUDIT_TOKEN_2026"), std::string::npos);
        EXPECT_NE(json_text.find("\"comparison\": {"), std::string::npos);
        EXPECT_NE(json_text.find("\"functions_modified\": 1"), std::string::npos);
        EXPECT_NE(json_text.find("\"rule_id\": \"ELF2001\""), std::string::npos);
    }

    // 3. Headless SARIF 2.1.0 export with `--fail-on error` on vulnerable PE -> returns exit code 2!
    const auto sarif_path = tmp.dir / "vuln.sarif";
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::string vp = vuln_pe.string();
        const std::string sp = sarif_path.string();
        const std::vector<std::string_view> args{
            "--headless", vp, "--format", "sarif", "--fail-on", "error", "--output", sp};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 2) << "Expected policy exit code 2 on error-severity security findings";

        std::ifstream ifs(sarif_path);
        ASSERT_TRUE(static_cast<bool>(ifs));
        const std::string sarif_text((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        EXPECT_NE(sarif_text.find("\"version\": \"2.1.0\""), std::string::npos);
        EXPECT_NE(sarif_text.find("sarif-2.1.0.json"), std::string::npos);
        EXPECT_NE(sarif_text.find("\"ruleId\": \"PE1001\""), std::string::npos);
        EXPECT_NE(sarif_text.find("\"ruleId\": \"PE1007\""), std::string::npos);
        EXPECT_NE(sarif_text.find("\"level\": \"error\""), std::string::npos);
        EXPECT_NE(sarif_text.find("\"sha-256\":"), std::string::npos);
    }

    // 3b. Cross-platform PE policy gates (`--fail-on warning` vs `--fail-on error`)
    //     for unsigned, warning-only, and malformed-cert PE64 images.
    {
        auto run_inproc_gate = [](const std::filesystem::path& bin, std::string_view policy) {
            std::ostringstream out_ss;
            std::ostringstream err_ss;
            const std::string bp = bin.string();
            const std::vector<std::string_view> args{"--headless", bp, "--fail-on", policy};
            const auto rc = peelf::try_run_headless_or_help_cli(args, out_ss, err_ss);
            EXPECT_TRUE(rc.has_value()) << err_ss.str();
            return rc.value_or(-1);
        };

        // Unsigned hardened PE64 has Note-only PE1005 -> exits 0 under both warning and error gates.
        EXPECT_EQ(run_inproc_gate(hardened_pe, "error"), 0);
        EXPECT_EQ(run_inproc_gate(hardened_pe, "warning"), 0);

        // Unsigned low-entropy ASLR PE64 has Warning PE1001 -> exits 0 on error gate, 2 on warning gate.
        EXPECT_EQ(run_inproc_gate(low_entropy_pe, "error"), 0);
        EXPECT_EQ(run_inproc_gate(low_entropy_pe, "warning"), 2);

        // Malformed dummy-cert PE64 has Error PE1005 -> exits 2 under both error and warning gates.
        EXPECT_EQ(run_inproc_gate(dummy_cert_pe, "error"), 2);
        EXPECT_EQ(run_inproc_gate(dummy_cert_pe, "warning"), 2);
    }

    // 4. Invalid file & invalid flag return exit code 1
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::string missing_path = (tmp.dir / "missing_binary.exe").string();
        const std::vector<std::string_view> bad_file{"--headless", missing_path};
        EXPECT_EQ(*peelf::try_run_headless_or_help_cli(bad_file, out_ss, err_ss), 1);

        const std::string p1 = hardened_elf.string();
        const std::vector<std::string_view> bad_flag{"--headless", p1, "--bogus-flag"};
        EXPECT_EQ(*peelf::try_run_headless_or_help_cli(bad_flag, out_ss, err_ss), 1);
    }

#if defined(PEELF_VIEWER_EXECUTABLE_PATH)
    // 5. Cross-platform end-to-end subprocess execution of the exact built `peelf_viewer` binary!
    {
        const std::filesystem::path viewer_exe = configured_viewer_executable_path();
        ASSERT_TRUE(std::filesystem::exists(viewer_exe))
            << "Expected built peelf_viewer at PEELF_VIEWER_EXECUTABLE_PATH: " << viewer_exe.string();

        const std::array<std::string, 1> bare_args{"--headless"};
        const auto bare = run_viewer_subproc(bare_args);
        ASSERT_TRUE(bare.launched) << bare.launch_error;
        EXPECT_FALSE(bare.timed_out);
        EXPECT_EQ(bare.exit_code, 0);
        EXPECT_TRUE(bare.stdout_text.empty());

        const std::array<std::string, 4> ok_json_args{
            "--headless", hardened_elf.string(), "--format", "json"};
        const auto ok_json = run_viewer_subproc(ok_json_args);
        ASSERT_TRUE(ok_json.launched) << ok_json.launch_error;
        EXPECT_FALSE(ok_json.timed_out);
        EXPECT_EQ(ok_json.exit_code, 0) << ok_json.stderr_text;
        EXPECT_NE(ok_json.stdout_text.find("\"security_audit\""), std::string::npos);

        const std::array<std::string, 4> pe_ok_args{
            "--headless", hardened_pe.string(), "--fail-on", "warning"};
        const auto pe_ok = run_viewer_subproc(pe_ok_args);
        ASSERT_TRUE(pe_ok.launched) << pe_ok.launch_error;
        EXPECT_FALSE(pe_ok.timed_out);
        EXPECT_EQ(pe_ok.exit_code, 0) << pe_ok.stderr_text;

        const std::array<std::string, 4> pe_warn_err_gate_args{
            "--headless", low_entropy_pe.string(), "--fail-on", "error"};
        const auto pe_warn_err_gate = run_viewer_subproc(pe_warn_err_gate_args);
        ASSERT_TRUE(pe_warn_err_gate.launched) << pe_warn_err_gate.launch_error;
        EXPECT_FALSE(pe_warn_err_gate.timed_out);
        EXPECT_EQ(pe_warn_err_gate.exit_code, 0) << pe_warn_err_gate.stderr_text;

        const std::array<std::string, 4> pe_warn_gate_args{
            "--headless", low_entropy_pe.string(), "--fail-on", "warning"};
        const auto pe_warn_gate = run_viewer_subproc(pe_warn_gate_args);
        ASSERT_TRUE(pe_warn_gate.launched) << pe_warn_gate.launch_error;
        EXPECT_FALSE(pe_warn_gate.timed_out);
        EXPECT_EQ(pe_warn_gate.exit_code, 2);

        const std::array<std::string, 6> gate_fail_args{
            "--headless", vuln_pe.string(), "--format", "sarif", "--fail-on", "error"};
        const auto gate_fail = run_viewer_subproc(gate_fail_args);
        ASSERT_TRUE(gate_fail.launched) << gate_fail.launch_error;
        EXPECT_FALSE(gate_fail.timed_out);
        EXPECT_EQ(gate_fail.exit_code, 2);
        EXPECT_NE(gate_fail.stdout_text.find("\"version\": \"2.1.0\""), std::string::npos);

        const std::array<std::string, 2> missing_args{
            "--headless", (tmp.dir / "does_not_exist.bin").string()};
        const auto missing = run_viewer_subproc(missing_args);
        ASSERT_TRUE(missing.launched) << missing.launch_error;
        EXPECT_FALSE(missing.timed_out);
        EXPECT_EQ(missing.exit_code, 1);
    }
#endif
}
