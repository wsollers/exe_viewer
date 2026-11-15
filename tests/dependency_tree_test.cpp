#include <gtest/gtest.h>

#include <peelf/dependency_tree.hpp>
#include <peelf/process.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
    b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

void write_bytes(const fs::path& path, const std::vector<std::uint8_t>& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.is_open()) << path.string();
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(out.good()) << path.string();
}

struct SynthElfSym {
    std::string name;
    bool defined{false};
    bool weak{false};
    std::uint64_t value{0};
    std::uint64_t reloc_got_va{0};
};

struct SynthElfSpec {
    bool is_64bit{true};
    std::uint16_t e_type{3};      // ET_DYN
    std::uint16_t e_machine{62};  // EM_X86_64 (3 = EM_386)
    std::string interpreter{};
    std::string soname{};
    std::string rpath{};
    std::string runpath{};
    std::vector<std::string> needed{};
    std::vector<SynthElfSym> dynsyms{};
};

std::vector<std::uint8_t> build_synthetic_elf(const SynthElfSpec& spec) {
    if (!spec.is_64bit) {
        // Minimal valid 32-bit ELF header + 1 PT_LOAD for ArchitectureMismatch testing
        std::vector<std::uint8_t> buf(0x200, 0);
        buf[0] = 0x7F;
        buf[1] = 'E';
        buf[2] = 'L';
        buf[3] = 'F';
        buf[4] = 1;  // ELFCLASS32
        buf[5] = 1;  // ELFDATA2LSB
        buf[6] = 1;  // EV_CURRENT
        put16(buf, 0x10, spec.e_type);
        put16(buf, 0x12, spec.e_machine);
        put32(buf, 0x14, 1);
        put32(buf, 0x18, 0x1000);
        put32(buf, 0x1C, 0x34);  // e_phoff
        put16(buf, 0x28, 0x34);  // e_ehsize
        put16(buf, 0x2A, 0x20);  // e_phentsize
        put16(buf, 0x2C, 1);     // e_phnum
        // PT_LOAD
        put32(buf, 0x34 + 0x00, 1);
        put32(buf, 0x34 + 0x04, 0);
        put32(buf, 0x34 + 0x08, 0);
        put32(buf, 0x34 + 0x10, 0x200);
        put32(buf, 0x34 + 0x14, 0x200);
        put32(buf, 0x34 + 0x18, 5);
        put32(buf, 0x34 + 0x1C, 0x1000);
        return buf;
    }

    // Build .shstrtab & .dynstr
    std::vector<std::uint8_t> shstrtab{0};
    auto add_str = [](std::vector<std::uint8_t>& tab, std::string_view s) -> std::uint32_t {
        const auto off = static_cast<std::uint32_t>(tab.size());
        tab.insert(tab.end(), s.begin(), s.end());
        tab.push_back(0);
        return off;
    };

    const std::uint32_t sh_text_nm = add_str(shstrtab, ".text");
    const std::uint32_t sh_dynstr_nm = add_str(shstrtab, ".dynstr");
    const std::uint32_t sh_dynsym_nm = add_str(shstrtab, ".dynsym");
    const std::uint32_t sh_dynamic_nm = add_str(shstrtab, ".dynamic");
    const std::uint32_t sh_rela_nm = add_str(shstrtab, ".rela.plt");
    const std::uint32_t sh_shstr_nm = add_str(shstrtab, ".shstrtab");

    std::vector<std::uint8_t> dynstr{0};
    std::vector<std::uint32_t> needed_offs;
    for (const std::string& lib : spec.needed) {
        needed_offs.push_back(add_str(dynstr, lib));
    }
    const std::uint32_t soname_off = spec.soname.empty() ? 0 : add_str(dynstr, spec.soname);
    const std::uint32_t rpath_off = spec.rpath.empty() ? 0 : add_str(dynstr, spec.rpath);
    const std::uint32_t runpath_off = spec.runpath.empty() ? 0 : add_str(dynstr, spec.runpath);

    // .dynsym (entry 0 = null)
    std::vector<std::uint8_t> dynsym(24, 0);
    std::vector<std::uint8_t> rela;
    for (std::size_t idx = 0; idx < spec.dynsyms.size(); ++idx) {
        const auto& s = spec.dynsyms[idx];
        const std::uint32_t nm_off = add_str(dynstr, s.name);
        const std::size_t base = dynsym.size();
        dynsym.resize(base + 24, 0);
        put32(dynsym, base + 0, nm_off);
        const std::uint8_t bind = s.weak ? 2u : 1u;  // STB_WEAK or STB_GLOBAL
        const std::uint8_t type = 2u;                // STT_FUNC
        dynsym[base + 4] = static_cast<std::uint8_t>((bind << 4) | type);
        dynsym[base + 5] = 0;  // STV_DEFAULT
        put16(dynsym, base + 6, s.defined ? 1u : 0u);  // section 1 (.text) or SHN_UNDEF (0)
        put64(dynsym, base + 8, s.defined ? s.value : 0ull);
        put64(dynsym, base + 16, s.defined ? 16ull : 0ull);

        if (s.reloc_got_va != 0) {
            const std::size_t rbase = rela.size();
            rela.resize(rbase + 24, 0);
            put64(rela, rbase + 0, s.reloc_got_va);
            const std::uint64_t sym_idx = idx + 1;
            put64(rela, rbase + 8, (sym_idx << 32) | 7ull);  // R_X86_64_JUMP_SLOT
            put64(rela, rbase + 16, 0);
        }
    }

    // .dynamic
    std::vector<std::uint8_t> dynamic_sec;
    auto add_dyn = [&](std::uint64_t tag, std::uint64_t val) {
        const std::size_t base = dynamic_sec.size();
        dynamic_sec.resize(base + 16, 0);
        put64(dynamic_sec, base + 0, tag);
        put64(dynamic_sec, base + 8, val);
    };
    for (const std::uint32_t noff : needed_offs) {
        add_dyn(1, noff);  // DT_NEEDED
    }
    if (soname_off != 0) {
        add_dyn(14, soname_off);  // DT_SONAME
    }
    if (rpath_off != 0) {
        add_dyn(15, rpath_off);  // DT_RPATH
    }
    if (runpath_off != 0) {
        add_dyn(29, runpath_off);  // DT_RUNPATH
    }
    add_dyn(0, 0);  // DT_NULL

    // Layout:
    // 0x000: Elf64_Ehdr (64)
    // 0x040: Program headers (2 or 3 * 56)
    // 0x140: PT_INTERP string (optional)
    // 0x200: .text (16 bytes)
    // ... aligned sections + section headers (7 * 64)
    std::vector<std::uint8_t> out(0x200, 0);
    const bool has_interp = !spec.interpreter.empty();
    const std::uint16_t phnum = has_interp ? 3 : 2;

    std::size_t interp_off = 0;
    std::size_t interp_sz = 0;
    if (has_interp) {
        interp_off = 0x140;
        interp_sz = spec.interpreter.size() + 1;
        for (std::size_t i = 0; i < spec.interpreter.size(); ++i) {
            out[interp_off + i] = static_cast<std::uint8_t>(spec.interpreter[i]);
        }
        out[interp_off + spec.interpreter.size()] = 0;
    }

    auto append_aligned = [&](const std::vector<std::uint8_t>& sec) -> std::uint64_t {
        while ((out.size() % 16u) != 0) {
            out.push_back(0);
        }
        const auto off = static_cast<std::uint64_t>(out.size());
        out.insert(out.end(), sec.begin(), sec.end());
        return off;
    };

    const std::vector<std::uint8_t> text_sec(32, 0x90);
    const std::uint64_t text_off = append_aligned(text_sec);
    const std::uint64_t dynstr_off = append_aligned(dynstr);
    const std::uint64_t dynsym_off = append_aligned(dynsym);
    const std::uint64_t dynamic_off = append_aligned(dynamic_sec);
    const std::uint64_t rela_off = append_aligned(rela);
    const std::uint64_t shstr_off = append_aligned(shstrtab);
    while ((out.size() % 16u) != 0) {
        out.push_back(0);
    }
    const std::uint64_t shoff = out.size();
    constexpr std::uint16_t shnum = 7;
    out.resize(out.size() + shnum * 64u, 0);

    // Elf64_Ehdr
    out[0] = 0x7F;
    out[1] = 'E';
    out[2] = 'L';
    out[3] = 'F';
    out[4] = 2;  // ELFCLASS64
    out[5] = 1;  // ELFDATA2LSB
    out[6] = 1;
    put16(out, 0x10, spec.e_type);
    put16(out, 0x12, spec.e_machine);
    put32(out, 0x14, 1);
    put64(out, 0x18, text_off);  // e_entry
    put64(out, 0x20, 0x40);      // e_phoff
    put64(out, 0x28, shoff);     // e_shoff
    put16(out, 0x34, 64);        // e_ehsize
    put16(out, 0x36, 56);        // e_phentsize
    put16(out, 0x38, phnum);     // e_phnum
    put16(out, 0x3A, 64);        // e_shentsize
    put16(out, 0x3C, shnum);     // e_shnum
    put16(out, 0x3E, 6);         // e_shstrndx

    // Program headers
    std::size_t ph = 0x40;
    auto write_ph = [&](std::uint32_t type, std::uint32_t flags,
                        std::uint64_t off, std::uint64_t va, std::uint64_t sz) {
        put32(out, ph + 0x00, type);
        put32(out, ph + 0x04, flags);
        put64(out, ph + 0x08, off);
        put64(out, ph + 0x10, va);
        put64(out, ph + 0x18, va);
        put64(out, ph + 0x20, sz);
        put64(out, ph + 0x28, sz);
        put64(out, ph + 0x30, 0x1000);
        ph += 56;
    };
    write_ph(1, 5, 0, 0, out.size());                         // PT_LOAD
    write_ph(2, 6, dynamic_off, dynamic_off, dynamic_sec.size());  // PT_DYNAMIC
    if (has_interp) {
        write_ph(3, 4, interp_off, interp_off, interp_sz);    // PT_INTERP
    }

    // Section headers: 0=null, 1=.text, 2=.dynstr, 3=.dynsym, 4=.dynamic, 5=.rela.plt, 6=.shstrtab
    auto write_sh = [&](std::size_t idx, std::uint32_t name, std::uint32_t type,
                        std::uint64_t flags, std::uint64_t addr, std::uint64_t off,
                        std::uint64_t size, std::uint32_t link, std::uint64_t entsize) {
        const std::size_t s = static_cast<std::size_t>(shoff) + idx * 64u;
        put32(out, s + 0x00, name);
        put32(out, s + 0x04, type);
        put64(out, s + 0x08, flags);
        put64(out, s + 0x10, addr);
        put64(out, s + 0x18, off);
        put64(out, s + 0x20, size);
        put32(out, s + 0x28, link);
        put64(out, s + 0x30, 8);
        put64(out, s + 0x38, entsize);
    };
    write_sh(1, sh_text_nm, 1, 6, 0x1000, text_off, text_sec.size(), 0, 0);
    write_sh(2, sh_dynstr_nm, 3, 2, dynstr_off, dynstr_off, dynstr.size(), 0, 0);
    write_sh(3, sh_dynsym_nm, 11, 2, dynsym_off, dynsym_off, dynsym.size(), 2, 24);
    write_sh(4, sh_dynamic_nm, 6, 3, dynamic_off, dynamic_off, dynamic_sec.size(), 2, 16);
    write_sh(5, sh_rela_nm, 4, 2, rela_off, rela_off, rela.size(), 3, 24);
    write_sh(6, sh_shstr_nm, 3, 0, 0, shstr_off, shstrtab.size(), 0, 0);

    return out;
}

struct SynthPeExport {
    std::string name{};
    std::uint16_t ordinal{1};  // 1-based ordinal (>= ordinal_base)
    std::uint32_t rva{0x1010};
    std::string forwarder{};
};

struct SynthPeImportDll {
    std::string dll_name;
    bool delay_load{false};
    std::vector<std::pair<std::string, std::uint16_t>> funcs;  // empty name => import by ordinal (.second)
};

std::vector<std::uint8_t> build_synthetic_pe64(
    const std::vector<SynthPeImportDll>& imports,
    const std::vector<SynthPeExport>& exports,
    bool is_dll = true) {
    // 0x000..0x3FF: Headers
    // 0x400..0x13FF: .rdata mapped at RVA 0x2000 (size 0x1000)
    // 0x1400..0x15FF: .text mapped at RVA 0x1000 (size 0x200)
    std::vector<std::uint8_t> b(0x1600, 0);
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3C, 0x80);  // e_lfanew

    b[0x80] = 'P';
    b[0x81] = 'E';
    put16(b, 0x84, 0x8664);  // IMAGE_FILE_MACHINE_AMD64
    put16(b, 0x86, 2);       // 2 sections (.text, .rdata)
    put16(b, 0x94, 0xF0);    // SizeOfOptionalHeader (PE32+)
    put16(b, 0x96, is_dll ? 0x2022 : 0x0022);

    const std::size_t opt = 0x98;
    put16(b, opt + 0x00, 0x20B);  // PE32+
    put32(b, opt + 0x10, 0x1000); // AddressOfEntryPoint
    put64(b, opt + 0x18, 0x140000000ull);
    put32(b, opt + 0x20, 0x1000); // SectionAlignment
    put32(b, opt + 0x24, 0x200);  // FileAlignment
    put32(b, opt + 0x38, 0x4000); // SizeOfImage
    put32(b, opt + 0x3C, 0x400);  // SizeOfHeaders
    put32(b, opt + 0x6C, 16);     // NumberOfRvaAndSizes (PE32+ offset 0x6C)

    // Section 0: .text at RVA 0x1000, raw 0x1400, size 0x200
    const std::size_t sh0 = opt + 0xF0;
    std::memcpy(&b[sh0], ".text\0\0\0", 8);
    put32(b, sh0 + 8, 0x200);
    put32(b, sh0 + 12, 0x1000);
    put32(b, sh0 + 16, 0x200);
    put32(b, sh0 + 20, 0x1400);
    put32(b, sh0 + 36, 0x60000020u);

    // Section 1: .rdata at RVA 0x2000, raw 0x400, size 0x1000
    const std::size_t sh1 = sh0 + 40;
    std::memcpy(&b[sh1], ".rdata\0\0", 8);
    put32(b, sh1 + 8, 0x1000);
    put32(b, sh1 + 12, 0x2000);
    put32(b, sh1 + 16, 0x1000);
    put32(b, sh1 + 20, 0x400);
    put32(b, sh1 + 36, 0x40000040u);

    std::size_t cur = 0x400;
    const auto rva_of = [](std::size_t file_off) -> std::uint32_t {
        return static_cast<std::uint32_t>(0x2000u + (file_off - 0x400u));
    };
    const auto alloc = [&](std::size_t sz, std::size_t align = 8) -> std::size_t {
        while ((cur % align) != 0) {
            ++cur;
        }
        const std::size_t res = cur;
        cur += sz;
        return res;
    };
    const auto alloc_cstr = [&](std::string_view s) -> std::uint32_t {
        const std::size_t off = alloc(s.size() + 1, 1);
        std::memcpy(&b[off], s.data(), s.size());
        b[off + s.size()] = 0;
        return rva_of(off);
    };

    // Standard imports vs Delay-load imports
    std::vector<SynthPeImportDll> std_imps;
    std::vector<SynthPeImportDll> dly_imps;
    for (const auto& imp : imports) {
        if (imp.delay_load) {
            dly_imps.push_back(imp);
        } else {
            std_imps.push_back(imp);
        }
    }

    if (!std_imps.empty()) {
        const std::size_t desc_base = alloc((std_imps.size() + 1) * 20u, 4);
        for (std::size_t i = 0; i < std_imps.size(); ++i) {
            const auto& dll = std_imps[i];
            const std::size_t ilt = alloc((dll.funcs.size() + 1) * 8u, 8);
            const std::size_t iat = alloc((dll.funcs.size() + 1) * 8u, 8);
            for (std::size_t fi = 0; fi < dll.funcs.size(); ++fi) {
                std::uint64_t thunk = 0;
                if (dll.funcs[fi].first.empty()) {
                    thunk = (1ull << 63) | dll.funcs[fi].second;
                } else {
                    const std::size_t hn = alloc(2 + dll.funcs[fi].first.size() + 1, 2);
                    put16(b, hn, 0);
                    std::memcpy(&b[hn + 2], dll.funcs[fi].first.data(), dll.funcs[fi].first.size());
                    thunk = rva_of(hn);
                }
                put64(b, ilt + fi * 8u, thunk);
                put64(b, iat + fi * 8u, thunk);
            }
            const std::uint32_t dll_rva = alloc_cstr(dll.dll_name);
            const std::size_t d = desc_base + i * 20u;
            put32(b, d + 0, rva_of(ilt));
            put32(b, d + 12, dll_rva);
            put32(b, d + 16, rva_of(iat));
        }
        // DataDirectory[1] = Import Table
        put32(b, opt + 0x70 + 1 * 8, rva_of(desc_base));
        put32(b, opt + 0x70 + 1 * 8 + 4, static_cast<std::uint32_t>((std_imps.size() + 1) * 20u));
    }

    if (!dly_imps.empty()) {
        const std::size_t ddesc_base = alloc((dly_imps.size() + 1) * 32u, 4);
        for (std::size_t i = 0; i < dly_imps.size(); ++i) {
            const auto& dll = dly_imps[i];
            const std::size_t int_off = alloc((dll.funcs.size() + 1) * 8u, 8);
            const std::size_t iat_off = alloc((dll.funcs.size() + 1) * 8u, 8);
            for (std::size_t fi = 0; fi < dll.funcs.size(); ++fi) {
                const std::size_t hn = alloc(2 + dll.funcs[fi].first.size() + 1, 2);
                put16(b, hn, 0);
                std::memcpy(&b[hn + 2], dll.funcs[fi].first.data(), dll.funcs[fi].first.size());
                put64(b, int_off + fi * 8u, rva_of(hn));
                put64(b, iat_off + fi * 8u, rva_of(hn));
            }
            const std::uint32_t dll_rva = alloc_cstr(dll.dll_name);
            const std::size_t d = ddesc_base + i * 32u;
            put32(b, d + 0x00, 1u);  // dlattrRva
            put32(b, d + 0x04, dll_rva);
            put32(b, d + 0x0C, rva_of(iat_off));
            put32(b, d + 0x10, rva_of(int_off));
        }
        // DataDirectory[13] = Delay Import Descriptor
        put32(b, opt + 0x70 + 13 * 8, rva_of(ddesc_base));
        put32(b, opt + 0x70 + 13 * 8 + 4, static_cast<std::uint32_t>((dly_imps.size() + 1) * 32u));
    }

    if (!exports.empty()) {
        const std::size_t edata_start = alloc(40, 4);
        std::uint16_t max_ord = 1;
        for (const auto& e : exports) {
            max_ord = std::max(max_ord, e.ordinal);
        }
        const std::size_t num_funcs = max_ord;
        const std::size_t eat_off = alloc(num_funcs * 4u, 4);

        std::vector<std::pair<std::string, std::uint16_t>> named;
        for (const auto& e : exports) {
            const std::size_t slot = static_cast<std::size_t>(e.ordinal - 1);
            if (!e.forwarder.empty()) {
                const std::uint32_t fwd_rva = alloc_cstr(e.forwarder);
                put32(b, eat_off + slot * 4u, fwd_rva);
            } else {
                put32(b, eat_off + slot * 4u, e.rva);
            }
            if (!e.name.empty()) {
                named.emplace_back(e.name, static_cast<std::uint16_t>(slot));
            }
        }
        std::ranges::sort(named, {}, &std::pair<std::string, std::uint16_t>::first);

        const std::size_t enpt_off = alloc(named.size() * 4u, 4);
        const std::size_t eot_off = alloc(named.size() * 2u, 2);
        for (std::size_t i = 0; i < named.size(); ++i) {
            put32(b, enpt_off + i * 4u, alloc_cstr(named[i].first));
            put16(b, eot_off + i * 2u, named[i].second);
        }
        const std::uint32_t mod_name_rva = alloc_cstr("synth.dll");
        const std::size_t edata_end = cur;

        put32(b, edata_start + 12, mod_name_rva);
        put32(b, edata_start + 16, 1u);  // Base ordinal = 1
        put32(b, edata_start + 20, static_cast<std::uint32_t>(num_funcs));
        put32(b, edata_start + 24, static_cast<std::uint32_t>(named.size()));
        put32(b, edata_start + 28, rva_of(eat_off));
        put32(b, edata_start + 32, rva_of(enpt_off));
        put32(b, edata_start + 36, rva_of(eot_off));

        // DataDirectory[0] = Export Table (spanning edata_start..edata_end so forwarder RVAs fall inside!)
        put32(b, opt + 0x70 + 0 * 8, rva_of(edata_start));
        put32(b, opt + 0x70 + 0 * 8 + 4, static_cast<std::uint32_t>(edata_end - edata_start));
    }

    return b;
}

} // namespace

TEST(DependencyTreeTest, ExpandElfDynamicTokensAndParseSearchRoots) {
    std::vector<std::string> assumptions;
    const std::string expanded = peelf::expand_elf_dynamic_tokens(
        "$ORIGIN/../${LIB}/${PLATFORM}/plugins",
        "/opt/myapp/bin",
        "lib64",
        "x86_64",
        &assumptions);
    EXPECT_EQ(expanded, "/opt/myapp/bin/../lib64/x86_64/plugins");
    EXPECT_EQ(assumptions.size(), 3u);

    EXPECT_TRUE(peelf::is_windows_api_set_dll("api-ms-win-crt-runtime-l1-1-0.dll"));
    EXPECT_TRUE(peelf::is_windows_api_set_dll("EXT-MS-WIN-NTUSER-WINDOW-L1-1-0"));
    EXPECT_FALSE(peelf::is_windows_api_set_dll("kernel32.dll"));

    const auto roots = peelf::parse_search_roots_list(" /tmp/a : /tmp/b ; C:\\Windows\\System32 ");
    ASSERT_EQ(roots.size(), 3u);
    EXPECT_EQ(roots[0].generic_string(), "/tmp/a");
    EXPECT_EQ(roots[1].generic_string(), "/tmp/b");
    EXPECT_EQ(roots[2].string(), "C:\\Windows\\System32");
}

TEST(DependencyTreeTest, ElfOriginRunpathDiamondAndMissingDependencyProvenance) {
    const fs::path scratch = fs::temp_directory_path() / "peelf-wu10-elf-diamond";
    std::error_code ec;
    fs::remove_all(scratch, ec);

    const fs::path bin_dir = scratch / "app" / "bin";
    const fs::path lib_dir = scratch / "app" / "lib";

    write_bytes(lib_dir / "libcommon.so", build_synthetic_elf(SynthElfSpec{
        .soname = "libcommon.so",
        .dynsyms = {{.name = "common_fn", .defined = true, .value = 0x3100}},
    }));
    write_bytes(lib_dir / "liba.so", build_synthetic_elf(SynthElfSpec{
        .soname = "liba.so",
        .runpath = "$ORIGIN",
        .needed = {"libcommon.so"},
        .dynsyms = {
            {.name = "fn_a", .defined = true, .value = 0x1100},
            {.name = "common_fn", .defined = false},
        },
    }));
    write_bytes(lib_dir / "libb.so", build_synthetic_elf(SynthElfSpec{
        .soname = "libb.so",
        .runpath = "${ORIGIN}",
        .needed = {"libcommon.so"},
        .dynsyms = {
            {.name = "fn_b", .defined = true, .value = 0x2100},
            {.name = "common_fn", .defined = false},
        },
    }));
    const fs::path main_path = bin_dir / "main.elf";
    write_bytes(main_path, build_synthetic_elf(SynthElfSpec{
        .e_type = 2,
        .runpath = "$ORIGIN/../lib",
        .needed = {"liba.so", "libb.so", "libmissing.so"},
        .dynsyms = {
            {.name = "fn_a", .defined = false, .reloc_got_va = 0x404018},
            {.name = "fn_b", .defined = false, .reloc_got_va = 0x404020},
            {.name = "__gmon_start__", .defined = false, .weak = true},
        },
    }));

    peelf::DependencyResolveOptions opts;
    opts.include_default_system_dirs = false;
    auto graph_res = peelf::build_dependency_graph_from_file(main_path, opts);
    ASSERT_TRUE(graph_res.has_value()) << graph_res.error().message;
    const auto& g = *graph_res;

    // Root + liba + libb + libcommon (deduplicated once in DAG!) + libmissing = 5 nodes
    EXPECT_EQ(g.nodes.size(), 5u);
    EXPECT_EQ(g.summary.direct_dependencies, 3u);
    EXPECT_EQ(g.summary.transitive_dependencies, 1u);
    EXPECT_EQ(g.summary.resolved_count, 3u);
    EXPECT_EQ(g.summary.missing_libraries, 1u);

    // Check diamond marker on second branch in tree
    ASSERT_EQ(g.root_tree.children.size(), 3u);
    ASSERT_EQ(g.root_tree.children[0].children.size(), 1u);
    EXPECT_FALSE(g.root_tree.children[0].children[0].is_diamond_ref);
    ASSERT_EQ(g.root_tree.children[1].children.size(), 1u);
    EXPECT_TRUE(g.root_tree.children[1].children[0].is_diamond_ref);

    // Check missing library provenance & $ORIGIN expansion assumption
    const auto miss_it = std::ranges::find_if(g.edges, [](const peelf::DependencyEdge& e) {
        return e.requested_name == "libmissing.so";
    });
    ASSERT_NE(miss_it, g.edges.end());
    EXPECT_EQ(miss_it->resolution_status, peelf::DependencyResolutionStatus::Unresolved);
    ASSERT_FALSE(miss_it->searched_paths.empty());
    EXPECT_NE(miss_it->searched_paths.front().generic_string().find("libmissing.so"), std::string::npos);
    ASSERT_FALSE(miss_it->origin_assumptions.empty());
    EXPECT_NE(miss_it->origin_assumptions.front().find("$ORIGIN = "), std::string::npos);

    // Check GOT relocation VA + export VA binding for fn_a on liba.so edge
    const auto liba_edge = std::ranges::find_if(g.edges, [](const peelf::DependencyEdge& e) {
        return e.requested_name == "liba.so";
    });
    ASSERT_NE(liba_edge, g.edges.end());
    const auto fn_a_bind = std::ranges::find_if(liba_edge->symbol_bindings, [](const auto& s) {
        return s.name == "fn_a";
    });
    ASSERT_NE(fn_a_bind, liba_edge->symbol_bindings.end());
    EXPECT_EQ(fn_a_bind->status, peelf::ImportedSymbolStatus::BoundExport);
    EXPECT_EQ(fn_a_bind->call_site_va, 0x404018u);
    EXPECT_EQ(fn_a_bind->resolved_export_va, 0x1100u);

    fs::remove_all(scratch, ec);
}

TEST(DependencyTreeTest, ElfCycleGuardAndMissingExportedSymbolDetection) {
    const fs::path scratch = fs::temp_directory_path() / "peelf-wu10-elf-cycle";
    std::error_code ec;
    fs::remove_all(scratch, ec);

    write_bytes(scratch / "libalpha.so", build_synthetic_elf(SynthElfSpec{
        .soname = "libalpha.so",
        .rpath = "$ORIGIN",
        .needed = {"libbeta.so"},
        .dynsyms = {
            {.name = "alpha_exported", .defined = true, .value = 0x1200},
            {.name = "beta_exported", .defined = false},
            {.name = "missing_strong_sym", .defined = false, .reloc_got_va = 0x500010},
            {.name = "optional_weak_sym", .defined = false, .weak = true},
        },
    }));
    write_bytes(scratch / "libbeta.so", build_synthetic_elf(SynthElfSpec{
        .soname = "libbeta.so",
        .rpath = "$ORIGIN",
        .needed = {"libalpha.so"},
        .dynsyms = {
            {.name = "beta_exported", .defined = true, .value = 0x2200},
            {.name = "alpha_exported", .defined = false},
        },
    }));

    peelf::DependencyResolveOptions opts;
    opts.include_default_system_dirs = false;
    auto graph_res = peelf::build_dependency_graph_from_file(scratch / "libalpha.so", opts);
    ASSERT_TRUE(graph_res.has_value()) << graph_res.error().message;
    const auto& g = *graph_res;

    EXPECT_EQ(g.summary.cycle_edges, 1u);
    EXPECT_EQ(g.summary.unresolved_symbols, 1u);

    ASSERT_EQ(g.root_tree.children.size(), 1u);
    ASSERT_EQ(g.root_tree.children[0].children.size(), 1u);
    EXPECT_TRUE(g.root_tree.children[0].children[0].is_cycle);
    EXPECT_EQ(g.root_tree.children[0].children[0].status,
              peelf::DependencyResolutionStatus::CycleSkipped);

    ASSERT_EQ(g.nodes[0].unresolved_symbols.size(), 1u);
    EXPECT_EQ(g.nodes[0].unresolved_symbols[0].name, "missing_strong_sym");
    EXPECT_EQ(g.nodes[0].unresolved_symbols[0].call_site_va, 0x500010u);

    fs::remove_all(scratch, ec);
}

TEST(DependencyTreeTest, DetectsElf32VsElf64ArchitectureMismatch) {
    const fs::path scratch = fs::temp_directory_path() / "peelf-wu10-arch-mismatch";
    std::error_code ec;
    fs::remove_all(scratch, ec);

    // 32-bit X86 library placed on search path for a 64-bit X86_64 binary
    write_bytes(scratch / "lib32" / "libwrong.so", build_synthetic_elf(SynthElfSpec{
        .is_64bit = false,
        .e_type = 3,
        .e_machine = 3,  // EM_386
    }));
    const fs::path main64 = scratch / "app64.elf";
    write_bytes(main64, build_synthetic_elf(SynthElfSpec{
        .is_64bit = true,
        .e_type = 2,
        .e_machine = 62,  // EM_X86_64
        .needed = {"libwrong.so"},
    }));

    peelf::DependencyResolveOptions opts;
    opts.include_default_system_dirs = false;
    opts.search_roots = {scratch / "lib32"};
    auto graph_res = peelf::build_dependency_graph_from_file(main64, opts);
    ASSERT_TRUE(graph_res.has_value()) << graph_res.error().message;
    const auto& g = *graph_res;

    EXPECT_EQ(g.summary.architecture_mismatches, 1u);
    ASSERT_EQ(g.edges.size(), 1u);
    EXPECT_EQ(g.edges[0].resolution_status, peelf::DependencyResolutionStatus::ArchitectureMismatch);
    EXPECT_NE(g.edges[0].resolution_reason.find("Architecture mismatch"), std::string::npos);

    fs::remove_all(scratch, ec);
}

TEST(DependencyTreeTest, PeVirtualApiSetForwardedExportsDelayLoadAndMissingExports) {
    const fs::path scratch = fs::temp_directory_path() / "peelf-wu10-pe-tree";
    std::error_code ec;
    fs::remove_all(scratch, ec);

    write_bytes(scratch / "back.dll", build_synthetic_pe64(
        {},
        {SynthPeExport{.name = "RealImpl", .ordinal = 1, .rva = 0x1040}}));

    write_bytes(scratch / "delaymod.dll", build_synthetic_pe64(
        {},
        {SynthPeExport{.name = "DelayedFn", .ordinal = 1, .rva = 0x1050}}));

    write_bytes(scratch / "front.dll", build_synthetic_pe64(
        {},
        {
            SynthPeExport{.name = "DirectFn", .ordinal = 1, .rva = 0x1010},
            SynthPeExport{.name = "ForwardedFn", .ordinal = 2, .forwarder = "back.RealImpl"},
            SynthPeExport{.name = "", .ordinal = 5, .rva = 0x1060},
        }));

    const fs::path app_exe = scratch / "app.exe";
    write_bytes(app_exe, build_synthetic_pe64(
        {
            SynthPeImportDll{
                .dll_name = "api-ms-win-crt-runtime-l1-1-0.dll",
                .funcs = {{"_initterm", 0}},
            },
            SynthPeImportDll{
                .dll_name = "front.dll",
                .funcs = {
                    {"DirectFn", 0},
                    {"ForwardedFn", 0},
                    {"", 5},  // ordinal #5
                    {"NonExistentExport", 0},
                },
            },
            SynthPeImportDll{
                .dll_name = "delaymod.dll",
                .delay_load = true,
                .funcs = {{"DelayedFn", 0}},
            },
        },
        {},
        false));

    peelf::DependencyResolveOptions opts;
    opts.include_default_system_dirs = false;
    auto graph_res = peelf::build_dependency_graph_from_file(app_exe, opts);
    ASSERT_TRUE(graph_res.has_value()) << graph_res.error().message;
    const auto& g = *graph_res;

    EXPECT_EQ(g.summary.virtual_api_sets, 1u);
    EXPECT_EQ(g.summary.missing_libraries, 0u);
    EXPECT_EQ(g.summary.resolved_count, 3u);  // front.dll, delaymod.dll, transitive back.dll
    EXPECT_EQ(g.summary.unresolved_symbols, 1u);  // NonExistentExport

    const auto front_edge = std::ranges::find_if(g.edges, [](const peelf::DependencyEdge& e) {
        return e.requested_name == "front.dll";
    });
    ASSERT_NE(front_edge, g.edges.end());
    ASSERT_EQ(front_edge->symbol_bindings.size(), 4u);
    EXPECT_EQ(front_edge->symbol_bindings[0].status, peelf::ImportedSymbolStatus::BoundExport);
    EXPECT_EQ(front_edge->symbol_bindings[1].status, peelf::ImportedSymbolStatus::BoundForwardedExport);
    EXPECT_EQ(front_edge->symbol_bindings[1].forwarded_to, "back.RealImpl");
    EXPECT_EQ(front_edge->symbol_bindings[2].status, peelf::ImportedSymbolStatus::BoundExport);
    EXPECT_EQ(front_edge->symbol_bindings[3].status, peelf::ImportedSymbolStatus::UnboundMissingExport);

    const auto delay_edge = std::ranges::find_if(g.edges, [](const peelf::DependencyEdge& e) {
        return e.requested_name == "delaymod.dll";
    });
    ASSERT_NE(delay_edge, g.edges.end());
    EXPECT_EQ(delay_edge->kind, peelf::DependencyEdgeKind::DelayLoadImport);
    ASSERT_EQ(delay_edge->symbol_bindings.size(), 1u);
    EXPECT_EQ(delay_edge->symbol_bindings[0].status, peelf::ImportedSymbolStatus::BoundExport);

    const auto fwd_edge = std::ranges::find_if(g.edges, [](const peelf::DependencyEdge& e) {
        return e.kind == peelf::DependencyEdgeKind::ForwardedExport;
    });
    ASSERT_NE(fwd_edge, g.edges.end());
    EXPECT_EQ(fwd_edge->resolution_status, peelf::DependencyResolutionStatus::ResolvedOnDisk);
    ASSERT_EQ(fwd_edge->symbol_bindings.size(), 1u);
    EXPECT_EQ(fwd_edge->symbol_bindings[0].name, "RealImpl");
    EXPECT_EQ(fwd_edge->symbol_bindings[0].status, peelf::ImportedSymbolStatus::BoundExport);

    fs::remove_all(scratch, ec);
}

#ifdef __linux__
TEST(DependencyTreeTest, LiveProcessDependencyResolutionMarksLoadedModules) {
    auto backend = peelf::create_native_process_backend();
    ASSERT_NE(backend, nullptr);
    auto session = backend->open_process(static_cast<peelf::ProcessId>(::getpid()));
    ASSERT_TRUE(session.has_value()) << session.error().message;

    auto mods = (*session)->modules();
    ASSERT_TRUE(mods.has_value());
    ASSERT_FALSE(mods->empty());

    auto live_img = peelf::load_live_module_image(**session, mods->front());
    ASSERT_TRUE(live_img.has_value()) << live_img.error().message;
    ASSERT_NE(*live_img, nullptr);

    peelf::DependencyResolveOptions opts;
    opts.max_depth = 2;
    opts.root_path = mods->front().path;
    const auto g = peelf::build_dependency_graph(**live_img, opts, session->get());

    EXPECT_GT(g.summary.direct_dependencies, 0u);
    EXPECT_GT(g.summary.resolved_live_count, 0u);
}
#endif
