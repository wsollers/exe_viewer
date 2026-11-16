#include "peelf/binary_image.hpp"
#include "peelf/executable_overview.hpp"
#include "peelf/executable_settings.hpp"
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
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void write_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

void write_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    write_u32_le(buf, off, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
    write_u32_le(buf, off + 4u, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFull));
}

void pad_align4(std::vector<std::uint8_t>& buf) {
    while ((buf.size() & 3u) != 0u) {
        buf.push_back(0u);
    }
}

void append_u16_le(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_utf16le_z(std::vector<std::uint8_t>& buf, std::u16string_view s) {
    for (const char16_t ch : s) {
        append_u16_le(buf, static_cast<std::uint16_t>(ch));
    }
    append_u16_le(buf, 0u);
}

[[nodiscard]] std::vector<std::uint8_t> build_vs_string_node(
    std::u16string_view key,
    std::u16string_view val) {
    std::vector<std::uint8_t> node;
    append_u16_le(node, 0u);  // placeholder wLength
    // wValueLength for String node is WCHAR count including terminating NUL
    append_u16_le(node, static_cast<std::uint16_t>(val.size() + 1u));
    append_u16_le(node, 1u);  // wType = text
    append_utf16le_z(node, key);
    pad_align4(node);
    append_utf16le_z(node, val);
    write_u16_le(node, 0u, static_cast<std::uint16_t>(node.size()));
    return node;
}

[[nodiscard]] std::vector<std::uint8_t> build_vs_string_table(
    std::u16string_view lang_cp_hex,
    std::span<const std::pair<std::u16string_view, std::u16string_view>> entries) {
    std::vector<std::uint8_t> node;
    append_u16_le(node, 0u);
    append_u16_le(node, 0u);
    append_u16_le(node, 1u);
    append_utf16le_z(node, lang_cp_hex);
    pad_align4(node);
    for (const auto& [k, v] : entries) {
        pad_align4(node);
        const std::vector<std::uint8_t> child = build_vs_string_node(k, v);
        node.insert(node.end(), child.begin(), child.end());
    }
    write_u16_le(node, 0u, static_cast<std::uint16_t>(node.size()));
    return node;
}

[[nodiscard]] std::vector<std::uint8_t> build_vs_version_info_blob() {
    std::vector<std::uint8_t> root;
    append_u16_le(root, 0u);    // wLength placeholder
    append_u16_le(root, 52u);   // sizeof(VS_FIXEDFILEINFO)
    append_u16_le(root, 0u);    // wType = binary
    append_utf16le_z(root, u"VS_VERSION_INFO");
    pad_align4(root);

    // VS_FIXEDFILEINFO (52 bytes)
    append_u32_le(root, 0xFEEF04BDu);             // dwSignature
    append_u32_le(root, 0x00010000u);             // dwStrucVersion
    append_u32_le(root, (2u << 16u) | 5u);        // dwFileVersionMS = 2.5
    append_u32_le(root, (104u << 16u) | 9u);      // dwFileVersionLS = 104.9
    append_u32_le(root, (2u << 16u) | 5u);        // dwProductVersionMS = 2.5
    append_u32_le(root, 0u);                      // dwProductVersionLS = 0.0
    append_u32_le(root, 0x3Fu);                   // dwFileFlagsMask
    append_u32_le(root, 0x03u);                   // VS_FF_DEBUG | VS_FF_PRERELEASE
    append_u32_le(root, 0x00040004u);             // VOS_NT_WINDOWS32
    append_u32_le(root, 0x00000001u);             // VFT_APP
    append_u32_le(root, 0u);                      // dwFileSubtype
    append_u32_le(root, 0u);                      // dwFileDateMS
    append_u32_le(root, 0u);                      // dwFileDateLS
    pad_align4(root);

    // StringFileInfo with English (040904B0) and Japanese (041104B0) localized tables
    std::vector<std::uint8_t> sfi;
    append_u16_le(sfi, 0u);
    append_u16_le(sfi, 0u);
    append_u16_le(sfi, 1u);
    append_utf16le_z(sfi, u"StringFileInfo");
    pad_align4(sfi);

    const std::array<std::pair<std::u16string_view, std::u16string_view>, 3> en_entries = {{
        {u"CompanyName", u"Contoso Binary Labs"},
        {u"FileDescription", u"PE/ELF Explorer Test Fixture"},
        {u"OriginalFilename", u"fixture.exe"},
    }};
    const auto en_tbl = build_vs_string_table(u"040904B0", en_entries);
    sfi.insert(sfi.end(), en_tbl.begin(), en_tbl.end());
    pad_align4(sfi);

    // Localized Japanese entry: ProductName = "\u88FD\u54C1" ("製品")
    const std::array<std::pair<std::u16string_view, std::u16string_view>, 2> ja_entries = {{
        {u"ProductName", u"\u88FD\u54C1\u30D3\u30E5\u30FC\u30A2"},
        {u"FileVersion", u"2.5.104.9"},
    }};
    const auto ja_tbl = build_vs_string_table(u"041104B0", ja_entries);
    sfi.insert(sfi.end(), ja_tbl.begin(), ja_tbl.end());
    write_u16_le(sfi, 0u, static_cast<std::uint16_t>(sfi.size()));

    root.insert(root.end(), sfi.begin(), sfi.end());
    pad_align4(root);

    // VarFileInfo -> Translation (0x0409, 1200) and (0x0411, 1200)
    std::vector<std::uint8_t> vfi;
    append_u16_le(vfi, 0u);
    append_u16_le(vfi, 0u);
    append_u16_le(vfi, 1u);
    append_utf16le_z(vfi, u"VarFileInfo");
    pad_align4(vfi);

    std::vector<std::uint8_t> var_node;
    append_u16_le(var_node, 0u);
    append_u16_le(var_node, 8u);  // two 4-byte lang/codepage pairs
    append_u16_le(var_node, 0u);  // binary
    append_utf16le_z(var_node, u"Translation");
    pad_align4(var_node);
    append_u16_le(var_node, 0x0409u);
    append_u16_le(var_node, 1200u);
    append_u16_le(var_node, 0x0411u);
    append_u16_le(var_node, 1200u);
    write_u16_le(var_node, 0u, static_cast<std::uint16_t>(var_node.size()));

    vfi.insert(vfi.end(), var_node.begin(), var_node.end());
    write_u16_le(vfi, 0u, static_cast<std::uint16_t>(vfi.size()));

    root.insert(root.end(), vfi.begin(), vfi.end());
    write_u16_le(root, 0u, static_cast<std::uint16_t>(root.size()));
    return root;
}

// Builds a synthetic PE64 image with `.text`, `.rsrc` (optional RT_VERSION id=16 & RT_MANIFEST id=24),
// and optional `.clr` section (DataDirectory[14] IMAGE_COR20_HEADER + BSJB metadata).
[[nodiscard]] std::vector<std::uint8_t> make_synthetic_pe64_with_metadata(
    std::span<const std::uint8_t> manifest_bytes,
    std::span<const std::uint8_t> version_bytes,
    bool include_clr = false,
    bool truncate_clr_stream = false,
    bool cyclic_resource_dir = false) {
    std::vector<std::uint8_t> pe(0x4000u, 0u);
    pe[0] = 'M';
    pe[1] = 'Z';
    write_u32_le(pe, 0x3Cu, 0x80u);

    const std::uint16_t num_sections = include_clr ? 3u : 2u;
    pe[0x80u] = 'P';
    pe[0x81u] = 'E';
    write_u16_le(pe, 0x84u, 0x8664u);          // AMD64
    write_u16_le(pe, 0x86u, num_sections);
    write_u32_le(pe, 0x88u, 0x65001234u);
    write_u16_le(pe, 0x94u, 0xF0u);            // SizeOfOptionalHeader
    write_u16_le(pe, 0x96u, 0x0022u);          // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    const std::size_t opt = 0x98u;
    write_u16_le(pe, opt + 0u, 0x20Bu);          // PE32+
    write_u32_le(pe, opt + 16u, 0x1000u);        // EntryPoint RVA
    write_u64_le(pe, opt + 24u, 0x140000000ull); // ImageBase
    write_u32_le(pe, opt + 32u, 0x1000u);        // SectionAlignment
    write_u32_le(pe, opt + 36u, 0x200u);         // FileAlignment
    write_u32_le(pe, opt + 56u, 0x5000u);        // SizeOfImage
    write_u32_le(pe, opt + 60u, 0x400u);         // SizeOfHeaders
    write_u16_le(pe, opt + 68u, 2u);             // IMAGE_SUBSYSTEM_WINDOWS_GUI
    write_u64_le(pe, opt + 72u, 0x100000ull);    // StackReserve
    write_u64_le(pe, opt + 80u, 0x4000ull);      // StackCommit
    write_u64_le(pe, opt + 88u, 0x100000ull);    // HeapReserve
    write_u64_le(pe, opt + 96u, 0x2000ull);      // HeapCommit
    write_u32_le(pe, opt + 108u, 16u);           // NumberOfRvaAndSizes

    // Section 0: .text @ RVA 0x1000, file offset 0x400, size 0x200
    const std::size_t sh0 = 0x188u;
    std::memcpy(pe.data() + sh0, ".text\0\0\0", 8u);
    write_u32_le(pe, sh0 + 8u, 0x200u);
    write_u32_le(pe, sh0 + 12u, 0x1000u);
    write_u32_le(pe, sh0 + 16u, 0x200u);
    write_u32_le(pe, sh0 + 20u, 0x400u);
    write_u32_le(pe, sh0 + 36u, 0x60000020u);
    pe[0x400u] = 0xC3u;

    // Section 1: .rsrc @ RVA 0x2000, file offset 0x600, size 0x1800
    const std::size_t sh1 = sh0 + 40u;
    std::memcpy(pe.data() + sh1, ".rsrc\0\0\0", 8u);
    write_u32_le(pe, sh1 + 8u, 0x1800u);
    write_u32_le(pe, sh1 + 12u, 0x2000u);
    write_u32_le(pe, sh1 + 16u, 0x1800u);
    write_u32_le(pe, sh1 + 20u, 0x600u);
    write_u32_le(pe, sh1 + 36u, 0x40000040u);

    const std::size_t rsrc_base = 0x600u;
    const bool has_ver = !version_bytes.empty();
    const bool has_man = !manifest_bytes.empty();
    const std::uint16_t type_count =
        cyclic_resource_dir ? 1u
                            : static_cast<std::uint16_t>((has_ver ? 1u : 0u) + (has_man ? 1u : 0u));

    if (type_count > 0u) {
        // DataDirectory[2] = Resource Table
        const std::size_t dd_rsrc = opt + 112u + (2u * 8u);
        write_u32_le(pe, dd_rsrc + 0u, 0x2000u);
        write_u32_le(pe, dd_rsrc + 4u, 0x1800u);

        write_u16_le(pe, rsrc_base + 14u, type_count);  // NumberOfIdEntries
        if (cyclic_resource_dir) {
            // Self-referential subdirectory pointing back to offset 0!
            write_u32_le(pe, rsrc_base + 16u, 24u);
            write_u32_le(pe, rsrc_base + 20u, 0x80000000u);
        } else {
            std::size_t root_entry_off = rsrc_base + 16u;
            std::size_t next_dir_rel = 0x40u;
            std::size_t next_data_rel = 0x200u;

            auto add_resource = [&](std::uint32_t type_id,
                                    std::uint32_t name_id,
                                    std::uint16_t lang_id,
                                    std::span<const std::uint8_t> payload) {
                // Level 1 entry -> Level 2 dir
                const std::size_t l2_rel = next_dir_rel;
                next_dir_rel += 0x30u;
                write_u32_le(pe, root_entry_off + 0u, type_id);
                write_u32_le(pe, root_entry_off + 4u, 0x80000000u | static_cast<std::uint32_t>(l2_rel));
                root_entry_off += 8u;

                // Level 2 dir -> Level 3 dir
                const std::size_t l3_rel = next_dir_rel;
                next_dir_rel += 0x30u;
                write_u16_le(pe, rsrc_base + l2_rel + 14u, 1u);
                write_u32_le(pe, rsrc_base + l2_rel + 16u, name_id);
                write_u32_le(pe, rsrc_base + l2_rel + 20u, 0x80000000u | static_cast<std::uint32_t>(l3_rel));

                // Level 3 dir -> IMAGE_RESOURCE_DATA_ENTRY
                const std::size_t de_rel = next_dir_rel;
                next_dir_rel += 0x20u;
                write_u16_le(pe, rsrc_base + l3_rel + 14u, 1u);
                write_u32_le(pe, rsrc_base + l3_rel + 16u, lang_id);
                write_u32_le(pe, rsrc_base + l3_rel + 20u, static_cast<std::uint32_t>(de_rel));

                const std::size_t payload_rel = (next_data_rel + 3u) & ~std::size_t{3u};
                next_data_rel = payload_rel + payload.size();
                write_u32_le(pe, rsrc_base + de_rel + 0u, 0x2000u + static_cast<std::uint32_t>(payload_rel));
                write_u32_le(pe, rsrc_base + de_rel + 4u, static_cast<std::uint32_t>(payload.size()));

                std::copy(payload.begin(),
                          payload.end(),
                          pe.begin() + static_cast<std::ptrdiff_t>(rsrc_base + payload_rel));
            };

            if (has_ver) {
                add_resource(16u /*RT_VERSION*/, 1u, 0x0409u, version_bytes);
            }
            if (has_man) {
                add_resource(24u /*RT_MANIFEST*/, 1u, 0x0409u, manifest_bytes);
            }
        }
    }

    if (include_clr) {
        // Section 2: .clr @ RVA 0x4000, file offset 0x2000, size 0x400
        const std::size_t sh2 = sh0 + 80u;
        std::memcpy(pe.data() + sh2, ".clr\0\0\0\0", 8u);
        write_u32_le(pe, sh2 + 8u, 0x400u);
        write_u32_le(pe, sh2 + 12u, 0x4000u);
        write_u32_le(pe, sh2 + 16u, 0x400u);
        write_u32_le(pe, sh2 + 20u, 0x2000u);
        write_u32_le(pe, sh2 + 36u, 0x40000040u);

        // DataDirectory[14] = CLR Runtime Header @ RVA 0x4000, size 72
        const std::size_t dd_clr = opt + 112u + (14u * 8u);
        write_u32_le(pe, dd_clr + 0u, 0x4000u);
        write_u32_le(pe, dd_clr + 4u, 72u);

        const std::size_t cor = 0x2000u;
        write_u32_le(pe, cor + 0u, 72u);           // cb
        write_u16_le(pe, cor + 4u, 2u);            // MajorRuntimeVersion
        write_u16_le(pe, cor + 6u, 5u);            // MinorRuntimeVersion
        write_u32_le(pe, cor + 8u, 0x4080u);       // MetaData RVA
        write_u32_le(pe, cor + 12u, 0x100u);       // MetaData Size
        write_u32_le(pe, cor + 16u, 0x00020003u);  // ILONLY | 32BITREQUIRED | 32BITPREFERRED -> Prefer32Bit + ILOnly
        write_u32_le(pe, cor + 20u, 0x06000001u);  // EntryPointToken

        // BSJB Metadata root at file offset 0x2080 (RVA 0x4080)
        const std::size_t md = 0x2080u;
        write_u32_le(pe, md + 0u, 0x424A5342u);    // "BSJB"
        write_u16_le(pe, md + 4u, 1u);
        write_u16_le(pe, md + 6u, 1u);
        write_u32_le(pe, md + 8u, 0u);
        write_u32_le(pe, md + 12u, 12u);           // version length (4-byte aligned)
        std::memcpy(pe.data() + md + 16u, "v4.0.30319\0\0", 12u);
        write_u16_le(pe, md + 28u, 0u);            // flags
        write_u16_le(pe, md + 30u, 2u);            // 2 streams: #~ and #Strings

        // Stream 0: "#~\0\0" (4 bytes)
        std::size_t st_off = md + 32u;
        write_u32_le(pe, st_off + 0u, 0x60u);
        write_u32_le(pe, st_off + 4u, 0x40u);
        std::memcpy(pe.data() + st_off + 8u, "#~\0\0", 4u);
        st_off += 12u;

        // Stream 1: "#Strings\0\0\0\0" (12 bytes)
        write_u32_le(pe, st_off + 0u, 0xA0u);
        write_u32_le(pe, st_off + 4u, truncate_clr_stream ? 0x200u : 0x40u);
        std::memcpy(pe.data() + st_off + 8u, "#Strings\0\0\0\0", 12u);
    }

    return pe;
}

// Builds a synthetic PIE ELF64 with PT_INTERP, GNU ABI-tag, GNU build-id,
// DT_NEEDED, DT_SONAME, DT_RUNPATH, DT_FLAGS (DF_BIND_NOW), and DT_FLAGS_1 (PIE|NOOPEN|NODELETE).
[[nodiscard]] std::vector<std::uint8_t> make_synthetic_elf64_full_declared() {
    std::vector<std::uint8_t> img(0x3000u, 0u);

    img[0] = 0x7Fu;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 2u;   // ELFCLASS64
    img[5] = 1u;   // ELFDATA2LSB
    img[6] = 1u;   // EV_CURRENT
    img[7] = 3u;   // ELFOSABI_GNU
    write_u16_le(img, 16u, 3u);       // ET_DYN
    write_u16_le(img, 18u, 62u);      // EM_X86_64
    write_u32_le(img, 20u, 1u);
    write_u64_le(img, 24u, 0x1000u);  // e_entry
    write_u64_le(img, 32u, 64u);      // e_phoff
    write_u64_le(img, 40u, 0x2000u);  // e_shoff
    write_u16_le(img, 52u, 64u);      // e_ehsize
    write_u16_le(img, 54u, 56u);      // e_phentsize
    write_u16_le(img, 56u, 5u);       // e_phnum (PT_PHDR/LOAD, PT_LOAD .text, PT_INTERP, PT_NOTE, PT_DYNAMIC)
    write_u16_le(img, 58u, 64u);      // e_shentsize
    write_u16_le(img, 60u, 6u);       // e_shnum
    write_u16_le(img, 62u, 5u);       // e_shstrndx

    auto write_phdr = [&](std::size_t idx,
                          std::uint32_t p_type,
                          std::uint32_t p_flags,
                          std::uint64_t p_off,
                          std::uint64_t p_vaddr,
                          std::uint64_t p_filesz,
                          std::uint64_t p_memsz,
                          std::uint64_t p_align) {
        const std::size_t p = 64u + idx * 56u;
        write_u32_le(img, p + 0u, p_type);
        write_u32_le(img, p + 4u, p_flags);
        write_u64_le(img, p + 8u, p_off);
        write_u64_le(img, p + 16u, p_vaddr);
        write_u64_le(img, p + 24u, p_vaddr);
        write_u64_le(img, p + 32u, p_filesz);
        write_u64_le(img, p + 40u, p_memsz);
        write_u64_le(img, p + 48u, p_align);
    };

    // PT_INTERP at 0x300
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";
    std::memcpy(img.data() + 0x300u, interp, sizeof(interp));

    // PT_NOTE at 0x340: Note 1 = NT_GNU_ABI_TAG (Linux 5.15.0), Note 2 = NT_GNU_BUILD_ID (8 bytes)
    std::size_t npos = 0x340u;
    write_u32_le(img, npos + 0u, 4u);
    write_u32_le(img, npos + 4u, 16u);
    write_u32_le(img, npos + 8u, 1u);  // NT_GNU_ABI_TAG
    std::memcpy(img.data() + npos + 12u, "GNU\0", 4u);
    write_u32_le(img, npos + 16u, 0u);   // OS = Linux
    write_u32_le(img, npos + 20u, 5u);   // major
    write_u32_le(img, npos + 24u, 15u);  // minor
    write_u32_le(img, npos + 28u, 0u);   // patch
    npos += 32u;

    const std::array<std::uint8_t, 8> bid = {0xDEu, 0xADu, 0xBEu, 0xEFu, 0xCAu, 0xFEu, 0xBAu, 0xBEu};
    write_u32_le(img, npos + 0u, 4u);
    write_u32_le(img, npos + 4u, static_cast<std::uint32_t>(bid.size()));
    write_u32_le(img, npos + 8u, 3u);  // NT_GNU_BUILD_ID
    std::memcpy(img.data() + npos + 12u, "GNU\0", 4u);
    std::copy(bid.begin(), bid.end(), img.begin() + static_cast<std::ptrdiff_t>(npos + 16u));
    npos += 24u;
    const std::size_t notes_size = npos - 0x340u;

    // .dynstr at 0x500
    // "\0libc.so.6\0libm.so.6\0libdemo.so.1\0$ORIGIN/../lib:/usr/local/lib\0"
    const char dynstr[] =
        "\0"
        "libc.so.6\0"                      // off 1
        "libm.so.6\0"                      // off 11
        "libdemo.so.1\0"                   // off 21
        "$ORIGIN/../lib:/usr/local/lib\0"; // off 34
    std::memcpy(img.data() + 0x500u, dynstr, sizeof(dynstr) - 1u);

    // .dynamic at 0x600
    std::size_t dpos = 0x600u;
    auto push_dyn = [&](std::uint64_t tag, std::uint64_t val) {
        write_u64_le(img, dpos + 0u, tag);
        write_u64_le(img, dpos + 8u, val);
        dpos += 16u;
    };
    push_dyn(5ull /*DT_STRTAB*/, 0x500ull);
    push_dyn(10ull /*DT_STRSZ*/, sizeof(dynstr) - 1u);
    push_dyn(1ull /*DT_NEEDED*/, 1ull);        // libc.so.6
    push_dyn(1ull /*DT_NEEDED*/, 11ull);       // libm.so.6
    push_dyn(14ull /*DT_SONAME*/, 21ull);      // libdemo.so.1
    push_dyn(29ull /*DT_RUNPATH*/, 34ull);     // $ORIGIN/../lib:/usr/local/lib
    push_dyn(30ull /*DT_FLAGS*/, 0x08ull);     // DF_BIND_NOW
    // DF_1_NOW (0x1) | DF_1_NODELETE (0x8) | DF_1_NOOPEN (0x40) | DF_1_PIE (0x08000000)
    push_dyn(0x6ffffffbull /*DT_FLAGS_1*/, 0x08000049ull);
    push_dyn(0ull /*DT_NULL*/, 0ull);
    const std::size_t dyn_size = dpos - 0x600u;

    img[0x1000u] = 0xC3u;  // ret

    write_phdr(0u, 1u /*PT_LOAD*/, 4u /*PF_R*/, 0u, 0u, 0x1000u, 0x1000u, 0x1000u);
    write_phdr(1u, 1u /*PT_LOAD*/, 5u /*PF_R|PF_X*/, 0x1000u, 0x1000u, 0x100u, 0x100u, 0x1000u);
    write_phdr(2u, 3u /*PT_INTERP*/, 4u /*PF_R*/, 0x300u, 0x300u, sizeof(interp), sizeof(interp), 1u);
    write_phdr(3u, 4u /*PT_NOTE*/, 4u /*PF_R*/, 0x340u, 0x340u, notes_size, notes_size, 4u);
    write_phdr(4u, 2u /*PT_DYNAMIC*/, 6u /*PF_R|PF_W*/, 0x600u, 0x600u, dyn_size, dyn_size, 8u);

    // Section headers at 0x2000
    const char shstr[] = "\0.text\0.note.gnu\0.dynstr\0.dynamic\0.shstrtab\0";
    std::memcpy(img.data() + 0x1F00u, shstr, sizeof(shstr) - 1u);

    auto write_shdr = [&](std::size_t idx,
                          std::uint32_t sh_name,
                          std::uint32_t sh_type,
                          std::uint64_t sh_flags,
                          std::uint64_t sh_addr,
                          std::uint64_t sh_off,
                          std::uint64_t sh_size,
                          std::uint32_t sh_link) {
        const std::size_t s = 0x2000u + idx * 64u;
        write_u32_le(img, s + 0u, sh_name);
        write_u32_le(img, s + 4u, sh_type);
        write_u64_le(img, s + 8u, sh_flags);
        write_u64_le(img, s + 16u, sh_addr);
        write_u64_le(img, s + 24u, sh_off);
        write_u64_le(img, s + 32u, sh_size);
        write_u32_le(img, s + 40u, sh_link);
        write_u64_le(img, s + 48u, 8u);
    };

    write_shdr(1u, 1u, 1u /*SHT_PROGBITS*/, 6u /*ALLOC|EXEC*/, 0x1000u, 0x1000u, 0x100u, 0u);
    write_shdr(2u, 7u, 7u /*SHT_NOTE*/, 2u /*ALLOC*/, 0x340u, 0x340u, notes_size, 0u);
    write_shdr(3u, 17u, 3u /*SHT_STRTAB*/, 2u /*ALLOC*/, 0x500u, 0x500u, sizeof(dynstr) - 1u, 0u);
    write_shdr(4u, 25u, 6u /*SHT_DYNAMIC*/, 3u /*WRITE|ALLOC*/, 0x600u, 0x600u, dyn_size, 3u);
    write_shdr(5u, 34u, 3u /*SHT_STRTAB*/, 0u, 0u, 0x1F00u, sizeof(shstr) - 1u, 0u);

    return img;
}

TEST(ExecutableSettingsTest, ExtractsPeManifestVersionAndClrMetadataCleanly) {
    constexpr std::string_view kManifestXml =
        R"(<?xml version="1.0" encoding="UTF-8" standalone="yes"?>)"
        R"(<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">)"
        R"(  <assemblyIdentity version="2.5.104.9" processorArchitecture="amd64" name="Contoso.Fixture" type="win32"/>)"
        R"(  <dependency><dependentAssembly>)"
        R"(    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df"/>)"
        R"(  </dependentAssembly></dependency>)"
        R"(  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>)"
        R"(    <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>)"
        R"(  </requestedPrivileges></security></trustInfo>)"
        R"(  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>)"
        R"(    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>)"
        R"(    <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>)"
        R"(  </compatibility>)"
        R"(  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>)"
        R"(    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/PM</dpiAware>)"
        R"(    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>)"
        R"(    <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>)"
        R"(    <heapType xmlns="http://schemas.microsoft.com/SMI/2020/WindowsSettings">SegmentHeap</heapType>)"
        R"(  </windowsSettings></application>)"
        R"(</assembly>)";
    // Fix closing tag typo? Notice above `<compatibility>...<application>...</compatibility>` has unclosed `<application>`!
    // Let's make sure the well-formed manifest closes `<application>` properly, and test unclosed tags separately!
    constexpr std::string_view kValidManifestXml =
        R"(<?xml version="1.0" encoding="UTF-8" standalone="yes"?>)"
        R"(<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">)"
        R"(  <assemblyIdentity version="2.5.104.9" processorArchitecture="amd64" name="Contoso.Fixture" type="win32"/>)"
        R"(  <dependency><dependentAssembly>)"
        R"(    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df"/>)"
        R"(  </dependentAssembly></dependency>)"
        R"(  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>)"
        R"(    <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>)"
        R"(  </requestedPrivileges></security></trustInfo>)"
        R"(  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>)"
        R"(    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>)"
        R"(    <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>)"
        R"(  </application></compatibility>)"
        R"(  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>)"
        R"(    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/PM</dpiAware>)"
        R"(    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>)"
        R"(    <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>)"
        R"(    <heapType xmlns="http://schemas.microsoft.com/SMI/2020/WindowsSettings">SegmentHeap</heapType>)"
        R"(  </windowsSettings></application>)"
        R"(</assembly>)";
    (void)kManifestXml;

    const std::vector<std::uint8_t> man_bytes(
        reinterpret_cast<const std::uint8_t*>(kValidManifestXml.data()),
        reinterpret_cast<const std::uint8_t*>(kValidManifestXml.data() + kValidManifestXml.size()));
    const std::vector<std::uint8_t> ver_bytes = build_vs_version_info_blob();
    const std::vector<std::uint8_t> pe = make_synthetic_pe64_with_metadata(man_bytes, ver_bytes, true, false);

    auto parsed = peelf::parse_image(pe);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const peelf::ExecutableSettingsReport report = peelf::extract_executable_settings(**parsed, pe);
    EXPECT_EQ(report.declared_in_file.availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(report.declared_in_file.provenance, peelf::ProvenanceTag::DiskFile);
    ASSERT_TRUE(report.declared_in_file.has_value());

    // Static-only loads MUST mark runtime sections explicitly Unavailable (never silently empty).
    EXPECT_EQ(report.launch_environment.availability, peelf::CaptureAvailability::Unavailable);
    EXPECT_FALSE(report.launch_environment.has_value());
    EXPECT_FALSE(report.launch_environment.note.empty());
    EXPECT_EQ(report.observed_runtime.availability, peelf::CaptureAvailability::Unavailable);
    EXPECT_FALSE(report.observed_runtime.has_value());
    EXPECT_FALSE(report.observed_runtime.note.empty());

    const peelf::DeclaredSettings& decl = *report.declared_in_file.value;
    EXPECT_EQ(decl.pe_subsystem_name, "WindowsGUI");
    EXPECT_EQ(decl.elf_settings_state, peelf::MetadataFieldState::UnsupportedFormat);

    // 1. RT_MANIFEST assertions
    EXPECT_EQ(decl.pe_manifest_state, peelf::MetadataFieldState::Present);
    ASSERT_TRUE(decl.pe_manifest.has_value());
    const peelf::PeManifestInfo& man = *decl.pe_manifest.value;
    EXPECT_EQ(man.requested_execution_level, "requireAdministrator");
    ASSERT_TRUE(man.ui_access.has_value());
    EXPECT_FALSE(*man.ui_access);
    EXPECT_EQ(man.dpi_aware, "true/PM");
    EXPECT_EQ(man.dpi_awareness, "PerMonitorV2");
    ASSERT_TRUE(man.long_path_aware.has_value());
    EXPECT_TRUE(*man.long_path_aware);
    EXPECT_EQ(man.heap_type, "SegmentHeap");
    ASSERT_EQ(man.supported_os.size(), 2u);
    EXPECT_EQ(man.supported_os[0].friendly_name, "Windows 10 / Windows 11 / Server 2016+");
    EXPECT_EQ(man.supported_os[1].friendly_name, "Windows 8.1 / Server 2012 R2");
    ASSERT_TRUE(man.assembly_identity.has_value());
    EXPECT_EQ(man.assembly_identity->name, "Contoso.Fixture");
    ASSERT_EQ(man.dependent_assemblies.size(), 1u);
    EXPECT_EQ(man.dependent_assemblies[0].name, "Microsoft.Windows.Common-Controls");

    // 2. RT_VERSION localized StringFileInfo assertions
    EXPECT_EQ(decl.pe_version_state, peelf::MetadataFieldState::Present);
    ASSERT_TRUE(decl.pe_version.has_value());
    const peelf::PeVersionInfo& ver = *decl.pe_version.value;
    ASSERT_TRUE(ver.fixed_info.has_value());
    EXPECT_EQ(ver.fixed_info->file_version_string, "2.5.104.9");
    EXPECT_EQ(ver.fixed_info->product_version_string, "2.5.0.0");
    EXPECT_EQ(ver.fixed_info->decoded_file_os, "VOS_NT_WINDOWS32");
    EXPECT_EQ(ver.fixed_info->decoded_file_type, "VFT_APP");
    ASSERT_EQ(ver.string_tables.size(), 2u);
    EXPECT_EQ(ver.string_tables[0].language_id, 0x0409u);
    EXPECT_EQ(ver.string_tables[1].language_id, 0x0411u);
    EXPECT_EQ(ver.string_tables[1].entries[0].first, "ProductName");
    // UTF-16 "\u88FD\u54C1\u30D3\u30E5\u30FC\u30A2" -> UTF-8 "製品ビューア"
    EXPECT_EQ(ver.string_tables[1].entries[0].second, "\xE8\xA3\xBD\xE5\x93\x81\xE3\x83\x93\xE3\x83\xA5\xE3\x83\xBC\xE3\x82\xA2");
    ASSERT_EQ(ver.translations.size(), 2u);

    // 3. CLR header & BSJB stream assertions
    EXPECT_EQ(decl.pe_clr_state, peelf::MetadataFieldState::Present);
    ASSERT_TRUE(decl.pe_clr.has_value());
    EXPECT_EQ(decl.pe_clr.value->runtime_version_string, "v4.0.30319");
    ASSERT_EQ(decl.pe_clr.value->streams.size(), 2u);
    EXPECT_EQ(decl.pe_clr.value->streams[0].name, "#~");
    EXPECT_TRUE(decl.pe_clr.value->streams[0].in_bounds);
    EXPECT_EQ(decl.pe_clr.value->streams[1].name, "#Strings");
    EXPECT_TRUE(decl.pe_clr.value->streams[1].in_bounds);
}

TEST(ExecutableSettingsTest, DistinguishesAbsentFromMalformedAndTruncatedMetadata) {
    // Case A: Clean PE with zero resources and zero CLR -> states are `Absent`, overall `Complete`
    const std::vector<std::uint8_t> clean_pe = make_synthetic_pe64_with_metadata({}, {}, false, false);
    auto clean_parsed = peelf::parse_image(clean_pe);
    ASSERT_TRUE(clean_parsed.has_value());
    const peelf::ExecutableSettingsReport clean_rep =
        peelf::extract_executable_settings(**clean_parsed, clean_pe);
    EXPECT_EQ(clean_rep.declared_in_file.availability, peelf::CaptureAvailability::Complete);
    ASSERT_TRUE(clean_rep.declared_in_file.has_value());
    EXPECT_EQ(clean_rep.declared_in_file.value->pe_manifest_state, peelf::MetadataFieldState::Absent);
    EXPECT_EQ(clean_rep.declared_in_file.value->pe_version_state, peelf::MetadataFieldState::Absent);
    EXPECT_EQ(clean_rep.declared_in_file.value->pe_clr_state, peelf::MetadataFieldState::Absent);

    // Case B: Malformed XML with DOCTYPE/XXE attempt + corrupted VS_FIXEDFILEINFO signature + OOB CLR stream
    constexpr std::string_view kDoctypeAndUnclosedXml =
        R"(<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/secret">]>)"
        R"(<assembly><trustInfo><requestedExecutionLevel level="asInvoker"/></assembly>)";
    const std::vector<std::uint8_t> bad_man(
        reinterpret_cast<const std::uint8_t*>(kDoctypeAndUnclosedXml.data()),
        reinterpret_cast<const std::uint8_t*>(kDoctypeAndUnclosedXml.data() + kDoctypeAndUnclosedXml.size()));

    std::vector<std::uint8_t> bad_ver = build_vs_version_info_blob();
    // Corrupt 0xFEEF04BD signature at offset 40 inside VS_VERSION_INFO
    for (std::size_t i = 0u; i + 4u <= bad_ver.size(); ++i) {
        if (bad_ver[i] == 0xBDu && bad_ver[i + 1u] == 0x04u &&
            bad_ver[i + 2u] == 0xEFu && bad_ver[i + 3u] == 0xFEu) {
            bad_ver[i] = 0x00u;
            break;
        }
    }

    const std::vector<std::uint8_t> bad_pe =
        make_synthetic_pe64_with_metadata(bad_man, bad_ver, true, /*truncate_clr_stream=*/true);
    auto bad_parsed = peelf::parse_image(bad_pe);
    ASSERT_TRUE(bad_parsed.has_value());
    const peelf::ExecutableSettingsReport bad_rep =
        peelf::extract_executable_settings(**bad_parsed, bad_pe);

    EXPECT_EQ(bad_rep.declared_in_file.availability, peelf::CaptureAvailability::Partial);
    ASSERT_TRUE(bad_rep.declared_in_file.has_value());
    EXPECT_EQ(bad_rep.declared_in_file.value->pe_manifest_state, peelf::MetadataFieldState::Malformed);
    EXPECT_EQ(bad_rep.declared_in_file.value->pe_version_state, peelf::MetadataFieldState::Malformed);
    EXPECT_EQ(bad_rep.declared_in_file.value->pe_clr_state, peelf::MetadataFieldState::Truncated);
    ASSERT_TRUE(bad_rep.declared_in_file.value->pe_clr.has_value());
    EXPECT_FALSE(bad_rep.declared_in_file.value->pe_clr.value->streams.back().in_bounds);
}

TEST(ExecutableSettingsTest, BoundedAgainstCyclicPeResourceDirectoryAndUtf16Manifest) {
    // 1. Cyclic resource directory MUST NOT hang either `parse_image` or `extract_executable_settings`
    const std::vector<std::uint8_t> cyclic_pe =
        make_synthetic_pe64_with_metadata({}, {}, false, false, /*cyclic_resource_dir=*/true);
    auto parsed_cyclic = peelf::parse_image(cyclic_pe);
    ASSERT_TRUE(parsed_cyclic.has_value());
    const peelf::ExecutableSettingsReport cyclic_rep =
        peelf::extract_executable_settings(**parsed_cyclic, cyclic_pe);
    EXPECT_EQ(cyclic_rep.declared_in_file.availability, peelf::CaptureAvailability::Partial);
    ASSERT_TRUE(cyclic_rep.declared_in_file.has_value());
    EXPECT_EQ(cyclic_rep.declared_in_file.value->pe_manifest_state, peelf::MetadataFieldState::Malformed);

    // 2. UTF-16LE BOM RT_MANIFEST decodes cleanly
    const std::u16string utf16_xml =
        u"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        u"<requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"true\"/>"
        u"</assembly>";
    std::vector<std::uint8_t> utf16_bytes = {0xFFu, 0xFEu};
    for (const char16_t ch : utf16_xml) {
        append_u16_le(utf16_bytes, static_cast<std::uint16_t>(ch));
    }
    const std::vector<std::uint8_t> utf16_pe = make_synthetic_pe64_with_metadata(utf16_bytes, {});
    auto parsed_u16 = peelf::parse_image(utf16_pe);
    ASSERT_TRUE(parsed_u16.has_value());
    const peelf::ExecutableSettingsReport u16_rep =
        peelf::extract_executable_settings(**parsed_u16, utf16_pe);
    ASSERT_TRUE(u16_rep.declared_in_file.has_value());
    EXPECT_EQ(u16_rep.declared_in_file.value->pe_manifest_state, peelf::MetadataFieldState::Present);
    ASSERT_TRUE(u16_rep.declared_in_file.value->pe_manifest.has_value());
    EXPECT_EQ(u16_rep.declared_in_file.value->pe_manifest.value->encoding, "UTF-16LE");
    EXPECT_EQ(u16_rep.declared_in_file.value->pe_manifest.value->requested_execution_level, "highestAvailable");
    EXPECT_EQ(u16_rep.declared_in_file.value->pe_manifest.value->ui_access, std::optional<bool>{true});
}

TEST(ExecutableSettingsTest, ExtractsElfInterpNotesRunpathAndDynamicFlagsWithHeadlessParity) {
    const std::vector<std::uint8_t> elf = make_synthetic_elf64_full_declared();
    auto parsed = peelf::parse_image(elf);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const peelf::ExecutableSettingsReport direct_rep = peelf::extract_executable_settings(**parsed, elf);
    EXPECT_EQ(direct_rep.declared_in_file.availability, peelf::CaptureAvailability::Complete);
    ASSERT_TRUE(direct_rep.declared_in_file.has_value());
    const peelf::DeclaredSettings& decl = *direct_rep.declared_in_file.value;
    EXPECT_EQ(decl.pe_manifest_state, peelf::MetadataFieldState::UnsupportedFormat);
    EXPECT_EQ(decl.elf_settings_state, peelf::MetadataFieldState::Present);
    ASSERT_TRUE(decl.elf_settings.has_value());

    const peelf::ElfDeclaredSettings& e = *decl.elf_settings.value;
    EXPECT_EQ(e.interpreter, std::optional<std::string>{"/lib64/ld-linux-x86-64.so.2"});
    EXPECT_EQ(e.build_id_hex, std::optional<std::string>{"deadbeefcafebabe"});
    ASSERT_TRUE(e.abi_tag.has_value());
    EXPECT_EQ(e.abi_tag->os_name, "Linux");
    EXPECT_EQ(e.abi_tag->min_kernel, "5.15.0");
    EXPECT_EQ(e.soname, std::optional<std::string>{"libdemo.so.1"});
    ASSERT_EQ(e.runpath_entries.size(), 2u);
    EXPECT_EQ(e.runpath_entries[0], "$ORIGIN/../lib");
    EXPECT_EQ(e.runpath_entries[1], "/usr/local/lib");
    ASSERT_EQ(e.needed_libraries.size(), 2u);
    EXPECT_EQ(e.needed_libraries[0], "libc.so.6");
    EXPECT_EQ(e.needed_libraries[1], "libm.so.6");
    EXPECT_TRUE(e.is_pie);
    EXPECT_TRUE(e.bind_now);
    EXPECT_TRUE(e.no_dlopen);
    EXPECT_TRUE(e.no_delete);

    // Verify BinaryModel + Headless CLI parity and deterministic JSON emission
    const std::filesystem::path tmp_path =
        std::filesystem::temp_directory_path() / "peelf_wu22_elf_settings_fixture.so";
    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(static_cast<bool>(ofs));
        ofs.write(reinterpret_cast<const char*>(elf.data()), static_cast<std::streamsize>(elf.size()));
    }

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(tmp_path.string()));
    ASSERT_TRUE(model.executable_settings().declared_in_file.has_value());
    EXPECT_EQ(model.executable_settings().declared_in_file.value->elf_settings.value->build_id_hex,
              e.build_id_hex);
    EXPECT_EQ(model.executable_settings().launch_environment.availability,
              peelf::CaptureAvailability::Unavailable);
    EXPECT_EQ(model.executable_settings().observed_runtime.availability,
              peelf::CaptureAvailability::Unavailable);

    peelf::HeadlessCliOptions cli_opts;
    cli_opts.binary_path = tmp_path;
    auto headless = peelf::analyze_binary_headless(cli_opts);
    std::error_code ec;
    std::filesystem::remove(tmp_path, ec);
    ASSERT_TRUE(headless.has_value()) << headless.error().message;

    const std::string json = peelf::format_headless_report_json(*headless);
    EXPECT_NE(json.find("\"executable_settings\": {"), std::string::npos);
    EXPECT_NE(json.find("\"interpreter\": \"/lib64/ld-linux-x86-64.so.2\""), std::string::npos);
    EXPECT_NE(json.find("\"build_id\": \"deadbeefcafebabe\""), std::string::npos);
    EXPECT_NE(json.find("\"min_kernel\": \"5.15.0\""), std::string::npos);
    EXPECT_NE(json.find("\"is_pie\": true"), std::string::npos);
    EXPECT_NE(json.find("\"no_dlopen\": true"), std::string::npos);
    EXPECT_NE(json.find("\"launch_environment\": {\n      \"availability\": \"Unavailable\""),
              std::string::npos);
    EXPECT_NE(json.find("\"observed_runtime\": {\n      \"availability\": \"Unavailable\""),
              std::string::npos);
}

TEST(ExecutableSettingsTest, DefaultEnvironmentSecretRedactionPolicyGuardsCredentials) {
    const auto secret_entry = peelf::format_environment_variable_entry(
        "GITHUB_TOKEN",
        "ghp_super_secret_token_12345");
    EXPECT_TRUE(secret_entry.redacted);
    EXPECT_EQ(secret_entry.availability, peelf::CaptureAvailability::Redacted);
    EXPECT_EQ(secret_entry.display_value.find("ghp_super_secret"), std::string::npos);

    const auto url_cred = peelf::format_environment_variable_entry(
        "DATABASE_URL",
        "postgres://admin:hunter2@db.internal:5432/prod");
    EXPECT_TRUE(url_cred.redacted);
    EXPECT_EQ(url_cred.availability, peelf::CaptureAvailability::Redacted);
    EXPECT_EQ(url_cred.display_value.find("hunter2"), std::string::npos);

    const auto benign = peelf::format_environment_variable_entry(
        "LANG",
        "en_US.UTF-8");
    EXPECT_FALSE(benign.redacted);
    EXPECT_EQ(benign.availability, peelf::CaptureAvailability::Complete);
    EXPECT_EQ(benign.display_value, "en_US.UTF-8");

    const auto opt_in = peelf::format_environment_variable_entry(
        "GITHUB_TOKEN",
        "ghp_super_secret_token_12345",
        peelf::EnvironmentRedactionPolicy::RevealUnredactedOptIn);
    EXPECT_FALSE(opt_in.redacted);
    EXPECT_EQ(opt_in.display_value, "ghp_super_secret_token_12345");
}

} // namespace
