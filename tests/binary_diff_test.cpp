#include <gtest/gtest.h>

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

struct ElfFuncDef {
    std::string name{};
    std::uint64_t va{0};
    std::vector<std::uint8_t> code{};
};

std::vector<std::uint8_t> build_elf64_with_functions(
    std::uint64_t text_va,
    const std::vector<ElfFuncDef>& funcs,
    const std::vector<std::string>& extra_section_names = {}) {
    std::vector<std::uint8_t> text_bytes(0x200, 0xCCu);
    for (const ElfFuncDef& fn : funcs) {
        if (fn.va >= text_va) {
            const auto rel = static_cast<std::size_t>(fn.va - text_va);
            if (rel + fn.code.size() > text_bytes.size()) {
                text_bytes.resize(rel + fn.code.size() + 32u, 0xCCu);
            }
            std::copy(fn.code.begin(), fn.code.end(), text_bytes.begin() + static_cast<std::ptrdiff_t>(rel));
        }
    }

    std::vector<std::uint8_t> strtab{0};
    std::vector<std::uint8_t> shstrtab{0};
    auto add_str = [](std::vector<std::uint8_t>& tab, std::string_view s) -> std::uint32_t {
        const auto off = static_cast<std::uint32_t>(tab.size());
        tab.insert(tab.end(), s.begin(), s.end());
        tab.push_back(0);
        return off;
    };

    const std::uint32_t sh_text_nm = add_str(shstrtab, ".text");
    const std::uint32_t sh_rodata_nm = add_str(shstrtab, ".rodata");
    std::vector<std::uint32_t> extra_sh_nms;
    for (const std::string& nm : extra_section_names) {
        extra_sh_nms.push_back(add_str(shstrtab, nm));
    }
    const std::uint32_t sh_symtab_nm = add_str(shstrtab, ".symtab");
    const std::uint32_t sh_strtab_nm = add_str(shstrtab, ".strtab");
    const std::uint32_t sh_shstr_nm = add_str(shstrtab, ".shstrtab");

    std::vector<std::uint8_t> symtab(24u, 0u); // entry 0 = null
    for (const ElfFuncDef& fn : funcs) {
        const std::uint32_t nm_off = fn.name.empty() ? 0u : add_str(strtab, fn.name);
        const std::size_t base = symtab.size();
        symtab.resize(base + 24u, 0u);
        put32(symtab, base + 0u, nm_off);
        symtab[base + 4u] = static_cast<std::uint8_t>((1u << 4u) | 2u); // STB_GLOBAL | STT_FUNC
        put16(symtab, base + 6u, 1u); // .text
        put64(symtab, base + 8u, fn.va);
        put64(symtab, base + 16u, fn.code.size());
    }

    std::vector<std::uint8_t> out(0x200, 0u);
    auto append_aligned = [&](const std::vector<std::uint8_t>& sec) -> std::uint64_t {
        while ((out.size() % 16u) != 0u) out.push_back(0u);
        const auto off = static_cast<std::uint64_t>(out.size());
        out.insert(out.end(), sec.begin(), sec.end());
        return off;
    };

    const std::uint64_t text_off = append_aligned(text_bytes);
    const std::vector<std::uint8_t> rodata_bytes{'v', '1', '-', 'c', 'o', 'n', 's', 't', 0};
    const std::uint64_t rodata_off = append_aligned(rodata_bytes);

    std::vector<std::uint64_t> extra_offs;
    const std::vector<std::uint8_t> extra_payload(24u, 0x42u);
    for (std::size_t i = 0; i < extra_section_names.size(); ++i) {
        extra_offs.push_back(append_aligned(extra_payload));
    }

    const std::uint64_t symtab_off = append_aligned(symtab);
    const std::uint64_t strtab_off = append_aligned(strtab);
    const std::uint64_t shstr_off = append_aligned(shstrtab);
    while ((out.size() % 16u) != 0u) out.push_back(0u);

    const std::uint64_t shoff = out.size();
    const auto shnum = static_cast<std::uint16_t>(6u + extra_section_names.size());
    const auto shstrndx = static_cast<std::uint16_t>(shnum - 1u);
    out.resize(out.size() + static_cast<std::size_t>(shnum) * 64u, 0u);

    out[0] = 0x7Fu;
    out[1] = 'E';
    out[2] = 'L';
    out[3] = 'F';
    out[4] = 2u;
    out[5] = 1u;
    out[6] = 1u;
    put16(out, 0x10u, 3u);  // ET_DYN
    put16(out, 0x12u, 62u); // EM_X86_64
    put32(out, 0x14u, 1u);
    put64(out, 0x18u, funcs.empty() ? text_va : funcs.front().va);
    put64(out, 0x20u, 0x40u);
    put64(out, 0x28u, shoff);
    put16(out, 0x34u, 64u);
    put16(out, 0x36u, 56u);
    put16(out, 0x38u, 3u); // 3 PT_LOAD segments (headers, .text, .rodata)
    put16(out, 0x3Au, 64u);
    put16(out, 0x3Cu, shnum);
    put16(out, 0x3Eu, shstrndx);

    auto write_ph = [&](std::size_t idx, std::uint32_t flags, std::uint64_t off,
                        std::uint64_t vaddr, std::uint64_t sz) {
        const std::size_t p = 0x40u + idx * 56u;
        put32(out, p + 0x00u, 1u); // PT_LOAD
        put32(out, p + 0x04u, flags);
        put64(out, p + 0x08u, off);
        put64(out, p + 0x10u, vaddr);
        put64(out, p + 0x18u, vaddr);
        put64(out, p + 0x20u, sz);
        put64(out, p + 0x28u, sz);
        put64(out, p + 0x30u, 0x1000ull);
    };

    write_ph(0u, 4u, 0u, 0x400000ull, 0x200ull);                        // ELF headers
    write_ph(1u, 5u, text_off, text_va, text_bytes.size());             // .text (RX)
    write_ph(2u, 4u, rodata_off, text_va + 0x2000u, rodata_bytes.size()); // .rodata (R)

    auto write_sh = [&](std::size_t idx, std::uint32_t name, std::uint32_t type,
                        std::uint64_t flags, std::uint64_t addr, std::uint64_t off,
                        std::uint64_t size, std::uint32_t link, std::uint32_t info,
                        std::uint64_t entsize) {
        const std::size_t s = static_cast<std::size_t>(shoff) + idx * 64u;
        put32(out, s + 0x00u, name);
        put32(out, s + 0x04u, type);
        put64(out, s + 0x08u, flags);
        put64(out, s + 0x10u, addr);
        put64(out, s + 0x18u, off);
        put64(out, s + 0x20u, size);
        put32(out, s + 0x28u, link);
        put32(out, s + 0x2Cu, info);
        put64(out, s + 0x30u, 8u);
        put64(out, s + 0x38u, entsize);
    };

    write_sh(1u, sh_text_nm, 1u, 6u, text_va, text_off, text_bytes.size(), 0u, 0u, 0u);
    write_sh(2u, sh_rodata_nm, 1u, 2u, text_va + 0x2000u, rodata_off, rodata_bytes.size(), 0u, 0u, 0u);
    std::size_t next_sh = 3u;
    for (std::size_t i = 0; i < extra_section_names.size(); ++i) {
        write_sh(next_sh++, extra_sh_nms[i], 1u, 2u, text_va + 0x3000u + i * 0x1000u,
                 extra_offs[i], extra_payload.size(), 0u, 0u, 0u);
    }
    const auto strtab_idx = static_cast<std::uint32_t>(next_sh + 1u);
    write_sh(next_sh++, sh_symtab_nm, 2u, 0u, 0u, symtab_off, symtab.size(), strtab_idx, 1u, 24u);
    write_sh(next_sh++, sh_strtab_nm, 3u, 0u, 0u, strtab_off, strtab.size(), 0u, 0u, 0u);
    write_sh(next_sh++, sh_shstr_nm, 3u, 0u, 0u, shstr_off, shstrtab.size(), 0u, 0u, 0u);

    return out;
}

// Synthetic PE64 builder with .text, .rdata (Import + Export tables), .data, and .reloc (`DIR64`)
struct PeDiffTestSpec {
    std::uint64_t image_base{0x140000000ull};
    std::vector<std::string> kernel32_imports{"GetTickCount64", "Sleep"};
    std::vector<std::pair<std::string, std::uint32_t>> exports{{"PluginInit", 0x1000u}};
    std::string forwarder_export_name{};
    std::string forwarder_target{};
    std::uint64_t reloc_target_rva_in_text{0x1002u}; // mov rax, imm64 at .text+0
};

std::vector<std::uint8_t> build_pe64_for_diff(const PeDiffTestSpec& spec) {
    // File layout:
    // 0x000..0x3FF: Headers
    // 0x400..0x5FF: .text   -> RVA 0x1000 (size 0x200)
    // 0x600..0xBFF: .rdata  -> RVA 0x2000 (size 0x600: IAT @ 0x2000, ImportDir @ 0x2080, ExportDir @ 0x2280)
    // 0xC00..0xDFF: .data   -> RVA 0x3000 (size 0x200)
    // 0xE00..0xFFF: .reloc  -> RVA 0x4000 (size 0x200)
    std::vector<std::uint8_t> b(0x1000, 0u);
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3Cu, 0x80u);

    b[0x80u] = 'P';
    b[0x81u] = 'E';
    put16(b, 0x84u, 0x8664u); // AMD64
    put16(b, 0x86u, 4u);      // 4 sections
    put16(b, 0x94u, 0xF0u);   // SizeOfOptionalHeader
    put16(b, 0x96u, 0x2022u); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

    const std::size_t opt = 0x98u;
    put16(b, opt + 0x00u, 0x20Bu); // PE32+
    put32(b, opt + 0x10u, 0x1000u);
    put64(b, opt + 0x18u, spec.image_base);
    put32(b, opt + 0x20u, 0x1000u);
    put32(b, opt + 0x24u, 0x200u);
    put32(b, opt + 0x38u, 0x5000u); // SizeOfImage
    put32(b, opt + 0x3Cu, 0x400u);  // SizeOfHeaders
    put16(b, opt + 0x46u, 0x0160u); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
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

    write_sec(0u, ".text\0\0\0", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
    write_sec(1u, ".rdata\0\0", 0x600u, 0x2000u, 0x600u, 0x600u, 0x40000040u);
    write_sec(2u, ".data\0\0\0", 0x200u, 0x3000u, 0x200u, 0xC00u, 0xC0000040u);
    write_sec(3u, ".reloc\0\0", 0x200u, 0x4000u, 0x200u, 0xE00u, 0x42000040u);

    // Populate .text @ 0x400 (RVA 0x1000): `mov rax, <image_base + 0x3000>; mov eax, [rax]; ret`
    b[0x400u + 0u] = 0x48u;
    b[0x400u + 1u] = 0xB8u; // movabs rax, imm64 (imm64 starts at RVA 0x1002!)
    put64(b, 0x400u + 2u, spec.image_base + 0x3000ull);
    b[0x400u + 10u] = 0x8Bu;
    b[0x400u + 11u] = 0x00u; // mov eax, [rax]
    b[0x400u + 12u] = 0xC3u; // ret

    // Second function @ RVA 0x1040 (file 0x440): `xor eax, eax; ret`
    b[0x440u + 0u] = 0x31u;
    b[0x440u + 1u] = 0xC0u;
    b[0x440u + 2u] = 0xC3u;

    // Populate .data @ 0xC00 (RVA 0x3000)
    put64(b, 0xC00u, 0x1122334455667788ull);

    // Populate Imports in .rdata:
    // IAT @ RVA 0x2000 (file 0x600), INT @ RVA 0x2040 (file 0x640), ImportDesc @ RVA 0x2080 (file 0x680), Strings @ RVA 0x20C0 (file 0x6C0)
    if (!spec.kernel32_imports.empty()) {
        std::uint32_t str_cursor_rva = 0x20C0u;
        auto write_rva_str = [&](std::string_view s) -> std::uint32_t {
            const std::uint32_t rva = str_cursor_rva;
            const std::size_t foff = 0x600u + (rva - 0x2000u);
            std::memcpy(&b[foff], s.data(), s.size());
            b[foff + s.size()] = 0u;
            str_cursor_rva += static_cast<std::uint32_t>(s.size() + 2u) & ~1u;
            return rva;
        };

        const std::uint32_t dll_rva = write_rva_str("KERNEL32.dll");
        for (std::size_t idx = 0; idx < spec.kernel32_imports.size(); ++idx) {
            const std::uint32_t hint_name_rva = str_cursor_rva;
            const std::size_t hn_foff = 0x600u + (hint_name_rva - 0x2000u);
            put16(b, hn_foff, static_cast<std::uint16_t>(idx + 1u));
            const std::string& nm = spec.kernel32_imports[idx];
            std::memcpy(&b[hn_foff + 2u], nm.data(), nm.size());
            b[hn_foff + 2u + nm.size()] = 0u;
            str_cursor_rva += static_cast<std::uint32_t>(2u + nm.size() + 2u) & ~1u;

            put64(b, 0x640u + idx * 8u, hint_name_rva); // OriginalFirstThunk (INT)
            put64(b, 0x600u + idx * 8u, hint_name_rva); // FirstThunk (IAT)
        }
        // IMAGE_IMPORT_DESCRIPTOR @ RVA 0x2080 (file 0x680), followed by zero terminator
        put32(b, 0x680u + 0u, 0x2040u);  // OriginalFirstThunk
        put32(b, 0x680u + 12u, dll_rva); // Name
        put32(b, 0x680u + 16u, 0x2000u); // FirstThunk (IAT)

        // DataDirectory[1] = Import Table (opt + 0x70 + 1*8)
        put32(b, opt + 0x78u, 0x2080u);
        put32(b, opt + 0x7Cu, 40u);
        // DataDirectory[12] = IAT (opt + 0x70 + 12*8)
        put32(b, opt + 0xD0u, 0x2000u);
        put32(b, opt + 0xD4u, static_cast<std::uint32_t>((spec.kernel32_imports.size() + 1u) * 8u));
    }

    // Populate Exports @ RVA 0x2280..0x24FF (file 0x880..0xAFF)
    std::vector<std::pair<std::string, std::uint32_t>> all_exps = spec.exports;
    std::uint32_t exp_str_rva = 0x2380u;
    auto write_exp_str = [&](std::string_view s) -> std::uint32_t {
        const std::uint32_t rva = exp_str_rva;
        const std::size_t foff = 0x600u + (rva - 0x2000u);
        std::memcpy(&b[foff], s.data(), s.size());
        b[foff + s.size()] = 0u;
        exp_str_rva += static_cast<std::uint32_t>(s.size() + 1u);
        return rva;
    };

    if (!spec.forwarder_export_name.empty() && !spec.forwarder_target.empty()) {
        const std::uint32_t fwd_rva = write_exp_str(spec.forwarder_target);
        all_exps.emplace_back(spec.forwarder_export_name, fwd_rva);
    }

    if (!all_exps.empty()) {
        std::ranges::sort(all_exps, [](const auto& a, const auto& c) { return a.first < c.first; });
        const auto cnt = static_cast<std::uint32_t>(all_exps.size());
        const std::uint32_t dll_nm_rva = write_exp_str("test.dll");
        const std::uint32_t eat_rva = 0x22C0u;
        const std::uint32_t names_rva = 0x2300u;
        const std::uint32_t ords_rva = 0x2340u;

        for (std::uint32_t i = 0; i < cnt; ++i) {
            put32(b, 0x600u + (eat_rva - 0x2000u) + i * 4u, all_exps[i].second);
            put32(b, 0x600u + (names_rva - 0x2000u) + i * 4u, write_exp_str(all_exps[i].first));
            put16(b, 0x600u + (ords_rva - 0x2000u) + i * 2u, static_cast<std::uint16_t>(i));
        }

        const std::size_t ed = 0x880u; // RVA 0x2280
        put32(b, ed + 12u, dll_nm_rva);
        put32(b, ed + 16u, 1u); // Base
        put32(b, ed + 20u, cnt);
        put32(b, ed + 24u, cnt);
        put32(b, ed + 28u, eat_rva);
        put32(b, ed + 32u, names_rva);
        put32(b, ed + 36u, ords_rva);

        // DataDirectory[0] = Export Table (RVA 0x2280..0x24FF so forwarder strings lie inside export dir!)
        put32(b, opt + 0x70u, 0x2280u);
        put32(b, opt + 0x74u, 0x280u);
    }

    // Populate Base Relocation Block in .reloc @ 0xE00 (RVA 0x4000)
    if (spec.reloc_target_rva_in_text != 0u) {
        const std::uint32_t page_rva = spec.reloc_target_rva_in_text & ~0xFFFu;
        const auto off12 = static_cast<std::uint16_t>(spec.reloc_target_rva_in_text & 0xFFFu);
        put32(b, 0xE00u + 0u, page_rva);
        put32(b, 0xE00u + 4u, 12u); // 8-byte header + two 2-byte entries
        put16(b, 0xE00u + 8u, static_cast<std::uint16_t>((10u << 12u) | off12)); // IMAGE_REL_BASED_DIR64
        put16(b, 0xE00u + 10u, 0u); // IMAGE_REL_BASED_ABSOLUTE padding

        // DataDirectory[5] = Base Relocation Table (opt + 0x70 + 5*8 = opt + 0x98)
        put32(b, opt + 0x98u, 0x4000u);
        put32(b, opt + 0x9Cu, 12u);
    }

    return b;
}

class MockLiveSession final : public peelf::IProcessSession {
public:
    struct Span {
        peelf::MemoryRegion region{};
        std::vector<std::uint8_t> bytes{};
    };

    explicit MockLiveSession(peelf::ProcessInfo pinfo)
        : info_(std::move(pinfo)) {}

    void add_region(peelf::MemoryRegion reg, std::vector<std::uint8_t> data) {
        spans_.push_back(Span{std::move(reg), std::move(data)});
    }

    void set_modules(std::vector<peelf::ModuleInfo> mods) {
        modules_ = std::move(mods);
    }

    void patch_live_bytes(std::uint64_t va, std::span<const std::uint8_t> patch) {
        for (Span& s : spans_) {
            if (va >= s.region.start_address && va + patch.size() <= s.region.end_address) {
                const auto off = static_cast<std::size_t>(va - s.region.start_address);
                if (off + patch.size() <= s.bytes.size()) {
                    std::copy(patch.begin(), patch.end(), s.bytes.begin() + static_cast<std::ptrdiff_t>(off));
                }
            }
        }
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        std::vector<peelf::MemoryRegion> out;
        for (const Span& s : spans_) out.push_back(s.region);
        return out;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return modules_;
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t address,
                                                         std::span<std::uint8_t> buffer) override {
        for (const Span& s : spans_) {
            if (address >= s.region.start_address && address < s.region.end_address && s.region.protection.readable) {
                const auto rel = static_cast<std::size_t>(address - s.region.start_address);
                if (rel >= s.bytes.size()) return peelf::make_error("past backing bytes");
                const std::size_t take = std::min(buffer.size(), s.bytes.size() - rel);
                std::memcpy(buffer.data(), s.bytes.data() + rel, take);
                return take;
            }
        }
        return peelf::make_error("unmapped");
    }

    [[nodiscard]] peelf::Result<std::size_t> write_memory(std::uint64_t,
                                                          std::span<const std::uint8_t>,
                                                          peelf::MemoryWriteOptions) override {
        return peelf::make_error("read-only");
    }

private:
    peelf::ProcessInfo info_{};
    std::vector<Span> spans_{};
    std::vector<peelf::ModuleInfo> modules_{};
};

} // namespace

TEST(BinaryDiffTest, StaticPeHeaderSectionImportAndExportDiffing) {
    PeDiffTestSpec spec_a;
    spec_a.kernel32_imports = {"GetTickCount64", "Sleep"};
    spec_a.exports = {{"PluginInit", 0x1000u}, {"PluginShutdown", 0x1040u}};
    spec_a.forwarder_export_name = "HeapAllocFwd";
    spec_a.forwarder_target = "NTDLL.RtlAllocateHeap";

    PeDiffTestSpec spec_b = spec_a;
    spec_b.kernel32_imports = {"GetTickCount64", "VirtualQuery"}; // -Sleep, +VirtualQuery
    spec_b.exports = {{"PluginInit", 0x1040u}, {"PluginConfigure", 0x1000u}}; // ~PluginInit RVA, -PluginShutdown, +PluginConfigure
    spec_b.forwarder_target = "KERNELBASE.HeapAlloc"; // ~HeapAllocFwd forwarder

    const auto pe_a = build_pe64_for_diff(spec_a);
    const auto pe_b = build_pe64_for_diff(spec_b);

    const auto diff_res = peelf::compare_binaries(pe_a, pe_b);
    ASSERT_TRUE(diff_res.has_value()) << diff_res.error().message;
    const peelf::BinaryDiffReport& r = *diff_res;

    EXPECT_FALSE(r.header.identical_files);
    EXPECT_TRUE(r.header.format_matches);
    EXPECT_TRUE(r.header.arch_matches);
    EXPECT_TRUE(r.header.bitness_matches);

    // Imports: -Sleep, +VirtualQuery
    EXPECT_EQ(r.imports_added, 1u);
    EXPECT_EQ(r.imports_removed, 1u);

    // Exports: +PluginConfigure, -PluginShutdown, ~PluginInit (RVA), ~HeapAllocFwd (forwarder)
    EXPECT_EQ(r.exports_added, 1u);
    EXPECT_EQ(r.exports_removed, 1u);
    EXPECT_EQ(r.exports_modified, 2u);

    auto rdata_it = std::ranges::find_if(r.sections, [](const peelf::SectionDiffEntry& s) {
        return s.name == ".rdata";
    });
    ASSERT_NE(rdata_it, r.sections.end());
    EXPECT_EQ(rdata_it->status, peelf::DiffChangeKind::Modified);
    EXPECT_GT(rdata_it->changed_byte_count, 0u);

    auto text_it = std::ranges::find_if(r.sections, [](const peelf::SectionDiffEntry& s) {
        return s.name == ".text";
    });
    ASSERT_NE(text_it, r.sections.end());
    EXPECT_EQ(text_it->status, peelf::DiffChangeKind::Unchanged);
}

TEST(BinaryDiffTest, RelocationTolerantFunctionMatchingAcrossShiftedVirtualAddresses) {
    // Build A:
    // - `compute_hash` at 0x401000: uses RIP-relative `lea rcx, [rip + 0x2010]` and `call rel32` to 0x401080
    // - `validate_token` at 0x401040: `push rbp; mov rbp, rsp; mov eax, 7; pop rbp; ret`
    // - `stripped_helper` (anonymous in Build B, shifted VA): `push rbx; xor eax, eax; call ext; pop rbx; ret`
    // - `legacy_only` at 0x4010C0: removed in Build B
    const std::vector<ElfFuncDef> funcs_a{
        ElfFuncDef{
            .name = "_Z12compute_hashPKvm",
            .va = 0x401000ull,
            .code = {
                0x55u,                                           // push rbp
                0x48u, 0x89u, 0xE5u,                             // mov rbp, rsp
                0x48u, 0x8Du, 0x0Du, 0x10u, 0x20u, 0x00u, 0x00u, // lea rcx, [rip + 0x2010]
                0xE8u, 0x70u, 0x00u, 0x00u, 0x00u,               // call 0x401080
                0x5Du,                                           // pop rbp
                0xC3u,                                           // ret
            },
        },
        ElfFuncDef{
            .name = "_Z14validate_tokeni",
            .va = 0x401040ull,
            .code = {
                0x55u, 0x48u, 0x89u, 0xE5u,
                0x89u, 0xF8u,
                0x83u, 0xC0u, 0x07u, // add eax, 7
                0x5Du, 0xC3u,
            },
        },
        ElfFuncDef{
            .name = "renamed_v1_helper",
            .va = 0x401080ull,
            .code = {
                0x53u,                               // push rbx
                0x48u, 0x31u, 0xDBu,                 // xor rbx, rbx
                0xE8u, 0x00u, 0x01u, 0x00u, 0x00u,   // call 0x401189 (next IP = 0x401089)
                0x48u, 0x89u, 0xD8u,                 // mov rax, rbx
                0x5Bu, 0xC3u,
            },
        },
        ElfFuncDef{
            .name = "legacy_only_func",
            .va = 0x4010C0ull,
            .code = {0xB8u, 0xFFu, 0x00u, 0x00u, 0x00u, 0xC3u},
        },
    };

    // Build B shifts functions forward AND changes RIP-relative & CALL rel32 displacements!
    // - `compute_hash` moved to 0x401060 with updated RIP disp32 (`0x1FB0`) and call disp32 (`0x80` -> 0x4010F0) -> MUST be `IdenticalRelocated`!
    // - `validate_token` moved to 0x4010A0 AND changed immediate (`add eax, 0x2A` instead of `7`) -> MUST be `Modified`!
    // - `renamed_v2_helper` moved to 0x4010F0 with updated call disp32 (`0x90` -> 0x401189) -> matched by Pass 2 `NormalizedFingerprint` as `IdenticalRelocated`!
    // - `brand_new_func` added at 0x401130 -> `Added`, plus an extra `.note.build` section!
    const std::vector<ElfFuncDef> funcs_b{
        ElfFuncDef{
            .name = "_Z12compute_hashPKvm",
            .va = 0x401060ull,
            .code = {
                0x55u,
                0x48u, 0x89u, 0xE5u,
                0x48u, 0x8Du, 0x0Du, 0xB0u, 0x1Fu, 0x00u, 0x00u, // shifted RIP disp32!
                0xE8u, 0x80u, 0x00u, 0x00u, 0x00u,               // shifted CALL rel32 -> 0x4010F0!
                0x5Du,
                0xC3u,
            },
        },
        ElfFuncDef{
            .name = "_Z14validate_tokeni",
            .va = 0x4010A0ull,
            .code = {
                0x55u, 0x48u, 0x89u, 0xE5u,
                0x89u, 0xF8u,
                0x83u, 0xC0u, 0x2Au, // genuinely modified logic (`add eax, 42`)!
                0x5Du, 0xC3u,
            },
        },
        ElfFuncDef{
            .name = "renamed_v2_helper",
            .va = 0x4010F0ull,
            .code = {
                0x53u,
                0x48u, 0x31u, 0xDBu,
                0xE8u, 0x90u, 0x00u, 0x00u, 0x00u, // shifted CALL rel32 -> 0x401189!
                0x48u, 0x89u, 0xD8u,
                0x5Bu, 0xC3u,
            },
        },
        ElfFuncDef{
            .name = "brand_new_func",
            .va = 0x401130ull,
            .code = {0xB8u, 0x01u, 0x00u, 0x00u, 0x00u, 0xC3u},
        },
    };

    const auto elf_a = build_elf64_with_functions(0x401000ull, funcs_a);
    const auto elf_b = build_elf64_with_functions(0x401000ull, funcs_b, {".note.build"});

    const auto res = peelf::compare_binaries(elf_a, elf_b);
    ASSERT_TRUE(res.has_value()) << res.error().message;
    const peelf::BinaryDiffReport& r = *res;

    EXPECT_EQ(r.sections_added, 1u);

    auto find_fn = [&](std::string_view substr) -> const peelf::FunctionDiffEntry* {
        for (const auto& f : r.functions) {
            if (f.display_name.find(substr) != std::string::npos ||
                f.raw_lhs_name.find(substr) != std::string::npos ||
                f.raw_rhs_name.find(substr) != std::string::npos) {
                return &f;
            }
        }
        return nullptr;
    };

    const auto* compute_fn = find_fn("compute_hash");
    ASSERT_NE(compute_fn, nullptr);
    EXPECT_EQ(compute_fn->status, peelf::FunctionMatchKind::IdenticalRelocated);
    EXPECT_DOUBLE_EQ(compute_fn->similarity, 1.0);

    const auto* validate_fn = find_fn("validate_token");
    ASSERT_NE(validate_fn, nullptr);
    EXPECT_EQ(validate_fn->status, peelf::FunctionMatchKind::Modified);
    EXPECT_GT(validate_fn->similarity, 0.65);
    EXPECT_LT(validate_fn->similarity, 1.0);

    const auto* helper_fn = find_fn("renamed_v1_helper");
    ASSERT_NE(helper_fn, nullptr);
    EXPECT_EQ(helper_fn->status, peelf::FunctionMatchKind::IdenticalRelocated);
    EXPECT_EQ(helper_fn->match_basis, "NormalizedFingerprint");

    const auto* removed_fn = find_fn("legacy_only_func");
    ASSERT_NE(removed_fn, nullptr);
    EXPECT_EQ(removed_fn->status, peelf::FunctionMatchKind::Removed);

    const auto* added_fn = find_fn("brand_new_func");
    ASSERT_NE(added_fn, nullptr);
    EXPECT_EQ(added_fn->status, peelf::FunctionMatchKind::Added);
}

TEST(BinaryDiffTest, DiskVsLiveRamDistinguishesAslrRelocationsFromInlineAndIatHooks) {
    PeDiffTestSpec spec;
    spec.image_base = 0x140000000ull;
    spec.kernel32_imports = {"GetTickCount64", "Sleep"};
    spec.exports = {{"PluginInit", 0x1000u}, {"TargetRoutine", 0x1040u}};
    spec.reloc_target_rva_in_text = 0x1002u;
    const std::vector<std::uint8_t> disk_pe = build_pe64_for_diff(spec);

    // Map the PE into simulated live process RAM at ASLR base `0x7FF650000000` (ASLR slide = +0x7FF510000000)
    constexpr std::uint64_t kLiveBase = 0x7FF650000000ull;
    constexpr std::uint64_t kKernel32Base = 0x7FF800000000ull;
    constexpr std::uint64_t kEvilDllBase = 0x7FF990000000ull;
    const std::uint64_t bias = kLiveBase - spec.image_base;

    peelf::ProcessInfo pinfo{};
    pinfo.pid = 4242;
    pinfo.name = "target_app.exe";
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.is_64bit = true;

    MockLiveSession session(pinfo);

    // Copy sections into live mapped memory & apply legitimate ASLR relocation + loader IAT resolution + .data mutation
    std::vector<std::uint8_t> live_text(disk_pe.begin() + 0x400, disk_pe.begin() + 0x600);
    // Apply legitimate DIR64 base relocation at .text + 2 (`mov rax, imm64`)
    put64(live_text, 2u, (spec.image_base + 0x3000ull) + bias);

    std::vector<std::uint8_t> live_rdata(disk_pe.begin() + 0x600, disk_pe.begin() + 0xC00);
    // Resolve IAT[0] (`GetTickCount64`) legitimately into `kernel32.dll`
    put64(live_rdata, 0u, kKernel32Base + 0x1230ull);
    // Resolve IAT[1] (`Sleep`) legitimately into `kernelbase.dll` (Windows API forwarding!)
    put64(live_rdata, 8u, kKernel32Base + 0x2480ull);

    std::vector<std::uint8_t> live_data(disk_pe.begin() + 0xC00, disk_pe.begin() + 0xE00);
    // Mutate writable .data at runtime (must NOT trigger hook alerts!)
    put64(live_data, 0u, 0xCAFEBABE12345678ull);

    session.add_region(peelf::MemoryRegion{
        .start_address = kLiveBase + 0x1000ull,
        .end_address = kLiveBase + 0x1200ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "C:\\app\\target_app.exe",
    }, live_text);

    session.add_region(peelf::MemoryRegion{
        .start_address = kLiveBase + 0x2000ull,
        .end_address = kLiveBase + 0x2600ull,
        .protection = {.readable = true, .writable = false, .executable = false},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "C:\\app\\target_app.exe",
    }, live_rdata);

    session.add_region(peelf::MemoryRegion{
        .start_address = kLiveBase + 0x3000ull,
        .end_address = kLiveBase + 0x3200ull,
        .protection = {.readable = true, .writable = true, .executable = false},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "C:\\app\\target_app.exe",
    }, live_data);

    session.add_region(peelf::MemoryRegion{
        .start_address = kKernel32Base,
        .end_address = kKernel32Base + 0x10000ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "C:\\Windows\\System32\\kernel32.dll",
    }, std::vector<std::uint8_t>(64u, 0x90u));

    session.add_region(peelf::MemoryRegion{
        .start_address = kEvilDllBase,
        .end_address = kEvilDllBase + 0x4000ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "C:\\temp\\injected_hook.dll",
    }, std::vector<std::uint8_t>(64u, 0x90u));

    session.set_modules({
        peelf::ModuleInfo{
            .name = "target_app.exe",
            .path = "C:\\app\\target_app.exe",
            .base_address = kLiveBase,
            .size = 0x5000ull,
        },
        peelf::ModuleInfo{
            .name = "kernel32.dll",
            .path = "C:\\Windows\\System32\\kernel32.dll",
            .base_address = kKernel32Base,
            .size = 0x10000ull,
        },
        peelf::ModuleInfo{
            .name = "injected_hook.dll",
            .path = "C:\\temp\\injected_hook.dll",
            .base_address = kEvilDllBase,
            .size = 0x4000ull,
        },
    });

    const peelf::ModuleInfo active_mod{
        .name = "target_app.exe",
        .path = "C:\\app\\target_app.exe",
        .base_address = kLiveBase,
        .size = 0x5000ull,
    };

    // 1. Clean ASLR-relocated image with normal IAT binding + mutated .data => ZERO hooks!
    {
        const auto clean = peelf::compare_module_disk_to_live(disk_pe, session, active_mod);
        ASSERT_TRUE(clean.has_value()) << clean.error().message;
        EXPECT_EQ(clean->normalized_relocation_count, 1u);
        EXPECT_EQ(clean->normalized_loader_slot_count, 2u);
        EXPECT_EQ(clean->inline_code_hook_count, 0u);
        EXPECT_EQ(clean->iat_got_hook_count, 0u);
        EXPECT_GT(clean->writable_data_changed_bytes, 0u);
        EXPECT_TRUE(clean->findings.empty());
    }

    // 2. Inject a 5-byte `E9 rel32` inline detour at `TargetRoutine` (RVA 0x1040) AND hijack `Sleep` IAT slot to `injected_hook.dll`!
    const std::array<std::uint8_t, 5> jmp_detour{0xE9u, 0xBCu, 0xEFu, 0x3Fu, 0x00u};
    session.patch_live_bytes(kLiveBase + 0x1040ull, jmp_detour);

    std::vector<std::uint8_t> hijacked_ptr(8u, 0u);
    put64(hijacked_ptr, 0u, kEvilDllBase + 0x100ull);
    session.patch_live_bytes(kLiveBase + 0x2008ull, hijacked_ptr); // IAT[1] = Sleep

    const auto hooked = peelf::compare_module_disk_to_live(disk_pe, session, active_mod);
    ASSERT_TRUE(hooked.has_value()) << hooked.error().message;
    EXPECT_EQ(hooked->inline_code_hook_count, 1u);
    EXPECT_EQ(hooked->iat_got_hook_count, 1u);
    EXPECT_EQ(hooked->normalized_loader_slot_count, 1u);

    const auto inline_it = std::ranges::find_if(hooked->findings, [](const peelf::ByteDiffHunk& h) {
        return h.classification == peelf::ByteHunkClassification::InlineCodeHook;
    });
    ASSERT_NE(inline_it, hooked->findings.end());
    EXPECT_EQ(inline_it->rhs_va, std::optional<std::uint64_t>(kLiveBase + 0x1040ull));
    EXPECT_NE(inline_it->detail.find("E9"), std::string::npos);

    const auto iat_it = std::ranges::find_if(hooked->findings, [](const peelf::ByteDiffHunk& h) {
        return h.classification == peelf::ByteHunkClassification::IatGotPointerHook;
    });
    ASSERT_NE(iat_it, hooked->findings.end());
    EXPECT_EQ(iat_it->symbol_context, "Sleep");
    EXPECT_NE(iat_it->detail.find("injected_hook.dll"), std::string::npos);
}

TEST(BinaryDiffTest, AdversarialNearUint64MaxRelocAndSecurityCookieRvasDoNotOverflow) {
    class AdversarialImage final : public peelf::IBinaryImage {
    public:
        explicit AdversarialImage(const peelf::IBinaryImage& base) : base_(base) {
            sections_ = base.sections();
            for (peelf::Section& sec : sections_) {
                if (sec.virtual_address >= base.image_base()) {
                    sec.virtual_address -= base.image_base(); // static_base == 0 (PIE-style)
                }
            }
            // Add an adversarial section whose virtual_address + size would wrap 64-bit arithmetic.
            sections_.push_back(peelf::Section{
                .name = ".wrap",
                .virtual_address = 0xFFFF'FFFF'FFFF'FF80ull,
                .virtual_size = 0x200ull,
                .file_offset = 0x400ull,
                .file_size = 0x100ull,
                .readable = true,
                .writable = false,
                .executable = true,
            });

            // Crafted near-UINT64_MAX security_cookie RVA (0xFFFFFFFFFFFFFFFC + 8 wraps to 4).
            load_config_.security_cookie = 0xFFFF'FFFF'FFFF'FFFCull;

            // Crafted PE .reloc entries near 32-bit max and past section end.
            pe_relocs_.push_back(peelf::PeBaseRelocationBlock{
                .page_rva = 0xFFFF'F000u,
                .block_size = 16u,
                .entries = {
                    peelf::PeBaseRelocationEntry{.page_rva = 0xFFFF'F000u, .type = 10u, .offset = 0xFFCu, .rva = 0xFFFF'FFFCu},
                    peelf::PeBaseRelocationEntry{.page_rva = 0x1000u, .type = 10u, .offset = 0x1FCu, .rva = 0x11FCu},
                },
            });

            // Crafted ELF relative & GOT relocations with near-UINT64_MAX offsets and extreme signed addends.
            elf_relocs_ = {
                peelf::ElfRelocation{
                    .section_name = ".rela.dyn",
                    .offset = 0xFFFF'FFFF'FFFF'FFFCull,
                    .info = 8u,
                    .symbol_index = 0u,
                    .type = 8u, // R_X86_64_RELATIVE
                    .addend = std::numeric_limits<std::int64_t>::max(),
                    .has_addend = true,
                    .symbol_name = {},
                },
                peelf::ElfRelocation{
                    .section_name = ".rela.plt",
                    .offset = 0xFFFF'FFFF'FFFF'FFF8ull,
                    .info = 7u,
                    .symbol_index = 1u,
                    .type = 7u, // R_X86_64_JUMP_SLOT
                    .addend = 0,
                    .has_addend = true,
                    .symbol_name = "crafted_got_sym",
                },
                peelf::ElfRelocation{
                    .section_name = ".rela.dyn",
                    .offset = 0x1010ull, // Valid in-bounds R_X86_64_RELATIVE inside .text
                    .info = 8u,
                    .symbol_index = 0u,
                    .type = 8u,
                    .addend = -16,
                    .has_addend = true,
                    .symbol_name = {},
                },
            };

            // Crafted IAT slot at near-UINT64_MAX RVA.
            imports_ = {
                peelf::ImportEntry{
                    .library = "kernel32.dll",
                    .name = "CraftedWrapImport",
                    .ordinal = 0u,
                    .address = 0xFFFF'FFFF'FFFF'FFFCull,
                    .import_by_ordinal = false,
                    .delay_load = false,
                },
            };
        }

        [[nodiscard]] peelf::Format format() const noexcept override { return base_.format(); }
        [[nodiscard]] peelf::ImageKind kind() const noexcept override { return base_.kind(); }
        [[nodiscard]] peelf::Architecture architecture() const noexcept override { return base_.architecture(); }
        [[nodiscard]] peelf::Endianness endianness() const noexcept override { return base_.endianness(); }
        [[nodiscard]] bool is_64bit() const noexcept override { return true; }
        [[nodiscard]] std::uint64_t image_base() const noexcept override { return 0ull; }
        [[nodiscard]] std::uint64_t entry_point() const noexcept override { return 0x1000ull; }
        [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override { return sections_; }
        [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override { return base_.segments(); }
        [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override { return base_.symbols(); }
        [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override { return imports_; }
        [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override { return base_.exports(); }
        [[nodiscard]] const peelf::PeHeader* pe_header() const noexcept override { return base_.pe_header(); }
        [[nodiscard]] const std::vector<peelf::PeDataDirectory>& pe_data_directories() const noexcept override {
            return base_.pe_data_directories();
        }
        [[nodiscard]] const std::vector<peelf::PeBaseRelocationBlock>& pe_base_relocations() const noexcept override {
            return pe_relocs_;
        }
        [[nodiscard]] const std::vector<peelf::PeDebugDirectory>& pe_debug_directories() const noexcept override {
            return base_.pe_debug_directories();
        }
        [[nodiscard]] const peelf::PeTlsDirectory* pe_tls_directory() const noexcept override { return nullptr; }
        [[nodiscard]] const std::vector<peelf::PeCertificate>& pe_certificates() const noexcept override {
            return base_.pe_certificates();
        }
        [[nodiscard]] const peelf::PeLoadConfigDirectory* pe_load_config_directory() const noexcept override {
            return &load_config_;
        }
        [[nodiscard]] const std::vector<peelf::PeRuntimeFunction>& pe_runtime_functions() const noexcept override {
            return base_.pe_runtime_functions();
        }
        [[nodiscard]] const std::vector<peelf::PeBoundImport>& pe_bound_imports() const noexcept override {
            return base_.pe_bound_imports();
        }
        [[nodiscard]] const peelf::PeResourceDirectory* pe_resource_directory() const noexcept override {
            return nullptr;
        }
        [[nodiscard]] const std::vector<peelf::PeResourceDataEntry>& pe_resource_data_entries() const noexcept override {
            return base_.pe_resource_data_entries();
        }
        [[nodiscard]] const peelf::PeClrHeader* pe_clr_header() const noexcept override { return nullptr; }
        [[nodiscard]] const peelf::ElfHeader* elf_header() const noexcept override { return nullptr; }
        [[nodiscard]] const std::vector<peelf::ElfProgramHeader>& elf_program_headers() const noexcept override {
            return base_.elf_program_headers();
        }
        [[nodiscard]] const std::vector<peelf::ElfSectionHeader>& elf_section_headers() const noexcept override {
            return base_.elf_section_headers();
        }
        [[nodiscard]] const std::vector<peelf::ElfSymbol>& elf_symbols() const noexcept override {
            return base_.elf_symbols();
        }
        [[nodiscard]] const std::vector<peelf::ElfDynamicEntry>& elf_dynamic_entries() const noexcept override {
            return base_.elf_dynamic_entries();
        }
        [[nodiscard]] const std::vector<peelf::ElfRelocation>& elf_relocations() const noexcept override {
            return elf_relocs_;
        }
        [[nodiscard]] const std::vector<peelf::ElfNote>& elf_notes() const noexcept override {
            return base_.elf_notes();
        }
        [[nodiscard]] const std::vector<peelf::ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept override {
            return base_.elf_sysv_hash_tables();
        }
        [[nodiscard]] const std::vector<peelf::ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept override {
            return base_.elf_gnu_hash_tables();
        }
        [[nodiscard]] std::string_view elf_interpreter() const noexcept override { return {}; }
        [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
            std::uint64_t file_offset) const noexcept override {
            return base_.file_offset_to_virtual_address(file_offset);
        }
        [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
            std::uint64_t virtual_address) const noexcept override {
            return base_.virtual_address_to_file_offset(virtual_address);
        }

    private:
        const peelf::IBinaryImage& base_;
        std::vector<peelf::Section> sections_{};
        peelf::PeLoadConfigDirectory load_config_{};
        std::vector<peelf::PeBaseRelocationBlock> pe_relocs_{};
        std::vector<peelf::ElfRelocation> elf_relocs_{};
        std::vector<peelf::ImportEntry> imports_{};
    };

    PeDiffTestSpec spec;
    spec.image_base = 0x140000000ull;
    const std::vector<std::uint8_t> disk_pe = build_pe64_for_diff(spec);
    auto parsed = peelf::parse_image(disk_pe);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    AdversarialImage adv(**parsed);

    // High canonical/kernel-style live base >= 0x8000000000000000 exercises signed-addend wrapping safely.
    constexpr std::uint64_t kHighLiveBase = 0x8000'0000'0000'0000ull;
    peelf::ProcessInfo pinfo{};
    pinfo.pid = 9001;
    pinfo.name = "adv.exe";
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.is_64bit = true;

    MockLiveSession session(pinfo);
    std::vector<std::uint8_t> live_text(disk_pe.begin() + 0x400, disk_pe.begin() + 0x600);
    // Apply the one valid in-bounds relative relocation at RVA 0x1010 (offset 0x10 in .text): live_base - 16
    put64(live_text, 0x10u, kHighLiveBase - 16ull);

    session.add_region(peelf::MemoryRegion{
        .start_address = kHighLiveBase + 0x1000ull,
        .end_address = kHighLiveBase + 0x1200ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "adv.exe",
    }, live_text);

    session.add_region(peelf::MemoryRegion{
        .start_address = kHighLiveBase + 0x2000ull,
        .end_address = kHighLiveBase + 0x2600ull,
        .protection = {.readable = true, .writable = false, .executable = false},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "adv.exe",
    }, std::vector<std::uint8_t>(disk_pe.begin() + 0x600, disk_pe.begin() + 0xC00));

    session.add_region(peelf::MemoryRegion{
        .start_address = kHighLiveBase + 0x3000ull,
        .end_address = kHighLiveBase + 0x3200ull,
        .protection = {.readable = true, .writable = true, .executable = false},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "adv.exe",
    }, std::vector<std::uint8_t>(disk_pe.begin() + 0xC00, disk_pe.begin() + 0xE00));

    const peelf::ModuleInfo live_mod{
        .name = "adv.exe",
        .path = "adv.exe",
        .base_address = kHighLiveBase,
        .size = 0x5000ull,
    };
    session.set_modules({live_mod});

    const auto report = peelf::compare_module_disk_to_live(adv, disk_pe, session, live_mod);
    ASSERT_TRUE(report.has_value()) << report.error().message;
    // Only the single valid RVA 0x1010 relocation is applied; all near-UINT64_MAX RVAs are rejected cleanly.
    EXPECT_EQ(report->normalized_relocation_count, 1u);
    EXPECT_EQ(report->inline_code_hook_count, 0u);
    EXPECT_EQ(report->iat_got_hook_count, 0u);

    // Also verify normalize_function_bytes_for_diff handles function VAs near UINT64_MAX without wrapping.
    const std::array<std::uint8_t, 8> near_max_code{0xE8u, 0x10u, 0x00u, 0x00u, 0x00u, 0xEBu, 0x04u, 0xC3u};
    const auto norm = peelf::normalize_function_bytes_for_diff(near_max_code, 0xFFFF'FFFF'FFFF'FFFCull, adv);
    EXPECT_EQ(norm.size(), near_max_code.size());
}

TEST(BinaryDiffTest, UnrelocatedX86CallTargetChangeReportsModifiedAndMergesOverlappingRelocs) {
    // 1. Two x86_64 binaries where `dispatch_request` differs ONLY in its un-relocated
    //    `E8 rel32` displacement (`call fn_a` at 0x401040 vs `call fn_b` at 0x401080) MUST
    //    be classified as `Modified` (NOT `IdenticalRelocated`)!
    const std::vector<ElfFuncDef> funcs_lhs{
        ElfFuncDef{
            .name = "dispatch_request",
            .va = 0x401000ull,
            .code = {
                0x55u,                              // push rbp
                0x48u, 0x89u, 0xE5u,                // mov rbp, rsp
                0xE8u, 0x37u, 0x00u, 0x00u, 0x00u,  // call 0x401040 (`fn_a`, next IP = 0x401009)
                0x5Du,                              // pop rbp
                0xC3u,                              // ret
            },
        },
        ElfFuncDef{
            .name = "fn_a",
            .va = 0x401040ull,
            .code = {0xB8u, 0x01u, 0x00u, 0x00u, 0x00u, 0xC3u}, // mov eax, 1; ret
        },
        ElfFuncDef{
            .name = "fn_b",
            .va = 0x401080ull,
            .code = {0xB8u, 0x02u, 0x00u, 0x00u, 0x00u, 0xC3u}, // mov eax, 2; ret
        },
    };

    std::vector<ElfFuncDef> funcs_rhs = funcs_lhs;
    // Switch `dispatch_request` from `call fn_a` (0x401040) to `call fn_b` (0x401080):
    funcs_rhs[0].code[5] = 0x77u; // 0x401009 + 0x77 = 0x401080 (`fn_b`)

    const auto elf_lhs = build_elf64_with_functions(0x401000ull, funcs_lhs);
    const auto elf_rhs = build_elf64_with_functions(0x401000ull, funcs_rhs);

    const auto diff_res = peelf::compare_binaries(elf_lhs, elf_rhs);
    ASSERT_TRUE(diff_res.has_value()) << diff_res.error().message;

    const auto dispatch_it = std::ranges::find_if(
        diff_res->functions,
        [](const peelf::FunctionDiffEntry& f) { return f.display_name == "dispatch_request"; });
    ASSERT_NE(dispatch_it, diff_res->functions.end());
    EXPECT_EQ(dispatch_it->status, peelf::FunctionMatchKind::Modified);
    EXPECT_LT(dispatch_it->similarity, 1.0);
    EXPECT_EQ(diff_res->functions_modified, 1u);
    EXPECT_EQ(diff_res->functions_relocated, 0u);

    auto parsed_lhs = peelf::parse_image(elf_lhs);
    auto parsed_rhs = peelf::parse_image(elf_rhs);
    ASSERT_TRUE(parsed_lhs.has_value());
    ASSERT_TRUE(parsed_rhs.has_value());
    const auto norm_lhs = peelf::normalize_function_bytes_for_diff(
        funcs_lhs[0].code, 0x401000ull, **parsed_lhs);
    const auto norm_rhs = peelf::normalize_function_bytes_for_diff(
        funcs_rhs[0].code, 0x401000ull, **parsed_rhs);
    EXPECT_NE(norm_lhs, norm_rhs);

    // 2. Overlapping relocation intervals: a wide earlier interval [0x401002, 0x40100A)
    //    overlapping a narrower slightly-later interval [0x401003, 0x401007) MUST be merged
    //    so `std::upper_bound` recognizes that rel32 at [0x401005, 0x401009) is covered!
    class OverlappingRelocImage final : public peelf::IBinaryImage {
    public:
        explicit OverlappingRelocImage(const peelf::IBinaryImage& base) : base_(base) {
            elf_relocs_ = {
                peelf::ElfRelocation{
                    .section_name = ".rela.text",
                    .offset = 0x401003ull,
                    .info = 2u,
                    .symbol_index = 1u,
                    .type = 2u, // 4-byte R_X86_64_PC32 -> [0x401003, 0x401007)
                    .addend = -4,
                    .has_addend = true,
                    .symbol_name = {},
                },
                peelf::ElfRelocation{
                    .section_name = ".rela.text",
                    .offset = 0x401002ull,
                    .info = 1u,
                    .symbol_index = 1u,
                    .type = 1u, // 8-byte R_X86_64_64 -> [0x401002, 0x40100A)
                    .addend = 0,
                    .has_addend = true,
                    .symbol_name = {},
                },
            };
        }
        [[nodiscard]] peelf::Format format() const noexcept override { return base_.format(); }
        [[nodiscard]] peelf::ImageKind kind() const noexcept override { return base_.kind(); }
        [[nodiscard]] peelf::Architecture architecture() const noexcept override { return base_.architecture(); }
        [[nodiscard]] peelf::Endianness endianness() const noexcept override { return base_.endianness(); }
        [[nodiscard]] bool is_64bit() const noexcept override { return base_.is_64bit(); }
        [[nodiscard]] std::uint64_t image_base() const noexcept override { return base_.image_base(); }
        [[nodiscard]] std::uint64_t entry_point() const noexcept override { return base_.entry_point(); }
        [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override { return base_.sections(); }
        [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override { return base_.segments(); }
        [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override { return base_.symbols(); }
        [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override { return base_.imports(); }
        [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override { return base_.exports(); }
        [[nodiscard]] const peelf::PeHeader* pe_header() const noexcept override { return base_.pe_header(); }
        [[nodiscard]] const std::vector<peelf::PeDataDirectory>& pe_data_directories() const noexcept override { return base_.pe_data_directories(); }
        [[nodiscard]] const std::vector<peelf::PeBaseRelocationBlock>& pe_base_relocations() const noexcept override { return base_.pe_base_relocations(); }
        [[nodiscard]] const std::vector<peelf::PeDebugDirectory>& pe_debug_directories() const noexcept override { return base_.pe_debug_directories(); }
        [[nodiscard]] const peelf::PeTlsDirectory* pe_tls_directory() const noexcept override { return base_.pe_tls_directory(); }
        [[nodiscard]] const std::vector<peelf::PeCertificate>& pe_certificates() const noexcept override { return base_.pe_certificates(); }
        [[nodiscard]] const peelf::PeLoadConfigDirectory* pe_load_config_directory() const noexcept override { return base_.pe_load_config_directory(); }
        [[nodiscard]] const std::vector<peelf::PeRuntimeFunction>& pe_runtime_functions() const noexcept override { return base_.pe_runtime_functions(); }
        [[nodiscard]] const std::vector<peelf::PeBoundImport>& pe_bound_imports() const noexcept override { return base_.pe_bound_imports(); }
        [[nodiscard]] const peelf::PeResourceDirectory* pe_resource_directory() const noexcept override { return base_.pe_resource_directory(); }
        [[nodiscard]] const std::vector<peelf::PeResourceDataEntry>& pe_resource_data_entries() const noexcept override { return base_.pe_resource_data_entries(); }
        [[nodiscard]] const peelf::PeClrHeader* pe_clr_header() const noexcept override { return base_.pe_clr_header(); }
        [[nodiscard]] const peelf::ElfHeader* elf_header() const noexcept override { return base_.elf_header(); }
        [[nodiscard]] const std::vector<peelf::ElfProgramHeader>& elf_program_headers() const noexcept override { return base_.elf_program_headers(); }
        [[nodiscard]] const std::vector<peelf::ElfSectionHeader>& elf_section_headers() const noexcept override { return base_.elf_section_headers(); }
        [[nodiscard]] const std::vector<peelf::ElfSymbol>& elf_symbols() const noexcept override { return base_.elf_symbols(); }
        [[nodiscard]] const std::vector<peelf::ElfDynamicEntry>& elf_dynamic_entries() const noexcept override { return base_.elf_dynamic_entries(); }
        [[nodiscard]] const std::vector<peelf::ElfRelocation>& elf_relocations() const noexcept override { return elf_relocs_; }
        [[nodiscard]] const std::vector<peelf::ElfNote>& elf_notes() const noexcept override { return base_.elf_notes(); }
        [[nodiscard]] const std::vector<peelf::ElfSysvHashTable>& elf_sysv_hash_tables() const noexcept override { return base_.elf_sysv_hash_tables(); }
        [[nodiscard]] const std::vector<peelf::ElfGnuHashTable>& elf_gnu_hash_tables() const noexcept override { return base_.elf_gnu_hash_tables(); }
        [[nodiscard]] std::string_view elf_interpreter() const noexcept override { return base_.elf_interpreter(); }
        [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(std::uint64_t o) const noexcept override {
            return base_.file_offset_to_virtual_address(o);
        }
        [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(std::uint64_t v) const noexcept override {
            return base_.virtual_address_to_file_offset(v);
        }

    private:
        const peelf::IBinaryImage& base_;
        std::vector<peelf::ElfRelocation> elf_relocs_{};
    };

    const OverlappingRelocImage overlap_lhs(**parsed_lhs);
    const OverlappingRelocImage overlap_rhs(**parsed_rhs);
    const auto reloc_norm_lhs = peelf::normalize_function_bytes_for_diff(
        funcs_lhs[0].code, 0x401000ull, overlap_lhs);
    const auto reloc_norm_rhs = peelf::normalize_function_bytes_for_diff(
        funcs_rhs[0].code, 0x401000ull, overlap_rhs);
    EXPECT_EQ(reloc_norm_lhs, reloc_norm_rhs);
    EXPECT_EQ(reloc_norm_lhs[5], 0u);
    EXPECT_EQ(reloc_norm_lhs[8], 0u);

    // 3. Bogus explicit `st_size` exceeding `.text` bounds is clamped cleanly, and pre-triggered
    //    `stop_token` cancels cleanly.
    std::vector<std::uint8_t> inflated_sym_elf = elf_lhs;
    // Patch first STT_FUNC symbol's 64-bit `st_size` in `.symtab` (search for `st_value == 0x401000` + `st_size == 11`)
    bool patched_st_size = false;
    for (std::size_t off = 0x200u; off + 16u <= inflated_sym_elf.size(); ++off) {
        if (inflated_sym_elf[off] == 0x00u && inflated_sym_elf[off + 1u] == 0x10u &&
            inflated_sym_elf[off + 2u] == 0x40u && inflated_sym_elf[off + 3u] == 0x00u &&
            inflated_sym_elf[off + 8u] == 11u && inflated_sym_elf[off + 9u] == 0u) {
            put64(inflated_sym_elf, off + 8u, 0x0FFF'FFFFull);
            patched_st_size = true;
            break;
        }
    }
    ASSERT_TRUE(patched_st_size);
    const auto clamped_diff = peelf::compare_binaries(inflated_sym_elf, elf_lhs);
    ASSERT_TRUE(clamped_diff.has_value()) << clamped_diff.error().message;
    for (const auto& fn : clamped_diff->functions) {
        EXPECT_LE(fn.lhs_size, 0x200u);
    }

    std::stop_source stop_src;
    stop_src.request_stop();
    peelf::BinaryDiffOptions cancel_opts;
    cancel_opts.stop_token = stop_src.get_token();
    const auto cancelled = peelf::compare_binaries(elf_lhs, elf_rhs, cancel_opts);
    EXPECT_FALSE(cancelled.has_value());
}

