// SPDX-License-Identifier: BSD-2-Clause
#include <gtest/gtest.h>

#include "headless_cli.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "test_temp_dir.hpp"
#include "ui/panel_helpers.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/clr_metadata.hpp>
#include <peelf/security_audit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (unsigned int i = 0; i < 8u; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu));
    }
}

void put_u16(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put_u32(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

void put_u64(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

void pad_align4(std::vector<std::uint8_t>& out) {
    while ((out.size() % 4u) != 0u) {
        out.push_back(0u);
    }
}

void append_compressed_uint(std::vector<std::uint8_t>& out, std::uint32_t value) {
    if (value <= 0x7Fu) {
        out.push_back(static_cast<std::uint8_t>(value));
    } else if (value <= 0x3FFFu) {
        out.push_back(static_cast<std::uint8_t>(0x80u | ((value >> 8u) & 0x3Fu)));
        out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    } else {
        out.push_back(static_cast<std::uint8_t>(0xC0u | ((value >> 24u) & 0x1Fu)));
        out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    }
}

struct StringsHeapBuilder {
    std::vector<std::uint8_t> bytes{0u};

    std::uint16_t add(std::string_view s) {
        if (s.empty()) {
            return 0u;
        }
        const auto offset = static_cast<std::uint16_t>(bytes.size());
        bytes.insert(bytes.end(), s.begin(), s.end());
        bytes.push_back(0u);
        return offset;
    }

    std::vector<std::uint8_t> finish() const {
        std::vector<std::uint8_t> out = bytes;
        pad_align4(out);
        return out;
    }
};

struct UsHeapBuilder {
    std::vector<std::uint8_t> bytes{0u};

    std::uint32_t add_ascii(std::string_view s) {
        const auto offset = static_cast<std::uint32_t>(bytes.size());
        const auto payload_len = static_cast<std::uint32_t>(s.size() * 2u + 1u);
        append_compressed_uint(bytes, payload_len);
        for (const char ch : s) {
            bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
            bytes.push_back(0u);
        }
        bytes.push_back(0u);
        return 0x70000000u | offset;
    }

    std::vector<std::uint8_t> finish() const {
        std::vector<std::uint8_t> out = bytes;
        pad_align4(out);
        return out;
    }
};

struct BlobHeapBuilder {
    std::vector<std::uint8_t> bytes{0u};

    std::uint16_t add(std::span<const std::uint8_t> blob) {
        const auto offset = static_cast<std::uint16_t>(bytes.size());
        append_compressed_uint(bytes, static_cast<std::uint32_t>(blob.size()));
        bytes.insert(bytes.end(), blob.begin(), blob.end());
        return offset;
    }

    std::vector<std::uint8_t> finish() const {
        std::vector<std::uint8_t> out = bytes;
        pad_align4(out);
        return out;
    }
};

struct SyntheticDotNetLayout {
    std::vector<std::uint8_t> file_bytes{};
    std::uint32_t metadata_file_offset = 0;
    std::uint32_t metadata_size = 0;
    std::uint32_t tables_stream_file_offset = 0;
    std::uint32_t tiny_method_rva = 0x1050u;
    std::uint32_t fat_method_rva = 0x1060u;
    std::uint32_t hello_us_token = 0;
};

// Programmatic minimal .NET PE32 / PE32+ builder with IMAGE_COR20_HEADER, BSJB v4.0.30319,
// #~ (Module, TypeRef, TypeDef, Field, MethodDef, Param, MemberRef, ModuleRef, ImplMap,
// Assembly, AssemblyRef), #Strings, #US, #GUID, #Blob, a Tiny IL method, and a Fat IL method
// with br.s + switch + 0xFE ceq + an EH try/catch clause.
SyntheticDotNetLayout build_synthetic_dotnet_pe(bool pe64 = true,
                                                std::uint64_t extra_valid_mask_bits = 0ULL) {
    StringsHeapBuilder strings;
    const std::uint16_t s_module_name = strings.add("SampleApp.exe");
    const std::uint16_t s_ns_system = strings.add("System");
    const std::uint16_t s_object = strings.add("Object");
    const std::uint16_t s_console = strings.add("Console");
    const std::uint16_t s_exception = strings.add("Exception");
    const std::uint16_t s_lt_module = strings.add("<Module>");
    const std::uint16_t s_ns_sample = strings.add("Sample");
    const std::uint16_t s_program = strings.add("Program");
    const std::uint16_t s_exit_code = strings.add("ExitCode");
    const std::uint16_t s_main = strings.add("Main");
    const std::uint16_t s_dispatch = strings.add("DispatchWithEh");
    const std::uint16_t s_virtual_alloc = strings.add("VirtualAlloc");
    const std::uint16_t s_arg_args = strings.add("args");
    const std::uint16_t s_arg_code = strings.add("code");
    const std::uint16_t s_writeline = strings.add("WriteLine");
    const std::uint16_t s_kernel32 = strings.add("kernel32.dll");
    const std::uint16_t s_asm_name = strings.add("SampleApp");
    const std::uint16_t s_sys_runtime = strings.add("System.Runtime");

    UsHeapBuilder us;
    const std::uint32_t tok_hello = us.add_ascii("Hello from CIL");

    // GUID {11223344-5566-7788-99aa-bbccddeeff00} in mixed-endian ECMA-335 wire order.
    std::vector<std::uint8_t> guid_stream = {
        0x44, 0x33, 0x22, 0x11,
        0x66, 0x55,
        0x88, 0x77,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };

    BlobHeapBuilder blobs;
    // FieldSig: FIELD (0x06), int32 (0x08)
    const std::uint16_t b_field_i32 = blobs.add(std::array<std::uint8_t, 2>{0x06u, 0x08u});
    // MethodDefSig Main: DEFAULT (0x00), 1 param, void (0x01), SZARRAY (0x1D) string (0x0E)
    const std::uint16_t b_sig_main =
        blobs.add(std::array<std::uint8_t, 5>{0x00u, 0x01u, 0x01u, 0x1Du, 0x0Eu});
    // MethodDefSig DispatchWithEh: HASTHIS (0x20), 1 param, int32 (0x08), int32 (0x08)
    const std::uint16_t b_sig_dispatch =
        blobs.add(std::array<std::uint8_t, 4>{0x20u, 0x01u, 0x08u, 0x08u});
    // MethodDefSig VirtualAlloc: DEFAULT (0x00), 4 params, native int (0x18),
    //   (native int 0x18, native uint 0x19, uint32 0x09, uint32 0x09)
    const std::uint16_t b_sig_valloc = blobs.add(
        std::array<std::uint8_t, 7>{0x00u, 0x04u, 0x18u, 0x18u, 0x19u, 0x09u, 0x09u});
    // MemberRefSig WriteLine: DEFAULT (0x00), 1 param, void (0x01), string (0x0E)
    const std::uint16_t b_sig_writeline =
        blobs.add(std::array<std::uint8_t, 4>{0x00u, 0x01u, 0x01u, 0x0Eu});
    const std::uint16_t b_pubkey =
        blobs.add(std::array<std::uint8_t, 4>{0x01u, 0x02u, 0x03u, 0x04u});
    const std::uint16_t b_pkt = blobs.add(
        std::array<std::uint8_t, 8>{0xB7u, 0x7Au, 0x5Cu, 0x56u, 0x19u, 0x34u, 0xE0u, 0x89u});

    // Build #~ stream.
    const std::uint64_t valid_mask =
        (1ULL << 0x00u) | // Module
        (1ULL << 0x01u) | // TypeRef
        (1ULL << 0x02u) | // TypeDef
        (1ULL << 0x04u) | // Field
        (1ULL << 0x06u) | // MethodDef
        (1ULL << 0x08u) | // Param
        (1ULL << 0x0Au) | // MemberRef
        (1ULL << 0x1Au) | // ModuleRef
        (1ULL << 0x1Cu) | // ImplMap
        (1ULL << 0x20u) | // Assembly
        (1ULL << 0x23u) | // AssemblyRef
        extra_valid_mask_bits;

    std::vector<std::uint8_t> tables_stream;
    append_u32(tables_stream, 0u);  // Reserved
    tables_stream.push_back(2u);    // MajorVersion
    tables_stream.push_back(0u);    // MinorVersion
    tables_stream.push_back(0u);    // HeapSizes (all 2-byte indices)
    tables_stream.push_back(1u);    // Reserved
    append_u64(tables_stream, valid_mask);
    append_u64(tables_stream, 0ULL); // Sorted

    // Row counts in ascending table ID order.
    for (unsigned int tid = 0; tid < 64u; ++tid) {
        if (((valid_mask >> tid) & 1ULL) == 0ULL) {
            continue;
        }
        std::uint32_t count = 1u;
        if (tid == 0x01u) count = 3u;      // TypeRef
        else if (tid == 0x02u) count = 2u; // TypeDef
        else if (tid == 0x06u) count = 3u; // MethodDef
        else if (tid == 0x08u) count = 2u; // Param
        append_u32(tables_stream, count);
    }

    // 0x00 Module (1 row)
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, s_module_name);
    append_u16(tables_stream, 1u); // Mvid = GUID #1
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 0u);

    // 0x01 TypeRef (3 rows): ResolutionScope tag 2 = AssemblyRef #1 -> (1 << 2) | 2 = 6
    const std::uint16_t rs_asmref_1 = static_cast<std::uint16_t>((1u << 2u) | 2u);
    append_u16(tables_stream, rs_asmref_1);
    append_u16(tables_stream, s_object);
    append_u16(tables_stream, s_ns_system);

    append_u16(tables_stream, rs_asmref_1);
    append_u16(tables_stream, s_console);
    append_u16(tables_stream, s_ns_system);

    append_u16(tables_stream, rs_asmref_1);
    append_u16(tables_stream, s_exception);
    append_u16(tables_stream, s_ns_system);

    // 0x02 TypeDef (2 rows)
    // Row 1: <Module>
    append_u32(tables_stream, 0u);
    append_u16(tables_stream, s_lt_module);
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 0u);  // Extends = null
    append_u16(tables_stream, 1u);  // FieldList = 1
    append_u16(tables_stream, 1u);  // MethodList = 1
    // Row 2: Sample.Program : System.Object (TypeRef #1 -> TypeDefOrRef (1 << 2) | 1 = 5)
    append_u32(tables_stream, 0x00100001u); // public | auto | class
    append_u16(tables_stream, s_program);
    append_u16(tables_stream, s_ns_sample);
    append_u16(tables_stream, static_cast<std::uint16_t>((1u << 2u) | 1u));
    append_u16(tables_stream, 1u);  // FieldList = 1 (owns Field #1)
    append_u16(tables_stream, 1u);  // MethodList = 1 (owns MethodDef #1..#3)

    // 0x04 Field (1 row)
    append_u16(tables_stream, 0x0016u); // public | static
    append_u16(tables_stream, s_exit_code);
    append_u16(tables_stream, b_field_i32);

    // 0x06 MethodDef (3 rows)
    // Row 1: Main (Tiny IL @ RVA 0x1050)
    append_u32(tables_stream, 0x1050u);
    append_u16(tables_stream, 0x0000u); // IL
    append_u16(tables_stream, 0x0096u); // public | static | hidebysig
    append_u16(tables_stream, s_main);
    append_u16(tables_stream, b_sig_main);
    append_u16(tables_stream, 1u); // ParamList = 1
    // Row 2: DispatchWithEh (Fat IL @ RVA 0x1060)
    append_u32(tables_stream, 0x1060u);
    append_u16(tables_stream, 0x0000u);
    append_u16(tables_stream, 0x0086u); // public | hidebysig
    append_u16(tables_stream, s_dispatch);
    append_u16(tables_stream, b_sig_dispatch);
    append_u16(tables_stream, 2u); // ParamList = 2
    // Row 3: VirtualAlloc (P/Invoke, RVA = 0)
    append_u32(tables_stream, 0u);
    append_u16(tables_stream, 0x0080u); // PreserveSig
    append_u16(tables_stream, 0x2096u); // public | static | pinvokeimpl
    append_u16(tables_stream, s_virtual_alloc);
    append_u16(tables_stream, b_sig_valloc);
    append_u16(tables_stream, 3u); // ParamList = 3 (empty)

    // 0x08 Param (2 rows)
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 1u);
    append_u16(tables_stream, s_arg_args);

    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 1u);
    append_u16(tables_stream, s_arg_code);

    // 0x0A MemberRef (1 row): TypeRef #2 (System.Console) -> MemberRefParent (2 << 3) | 1 = 17
    append_u16(tables_stream, static_cast<std::uint16_t>((2u << 3u) | 1u));
    append_u16(tables_stream, s_writeline);
    append_u16(tables_stream, b_sig_writeline);

    // 0x1A ModuleRef (1 row): kernel32.dll
    append_u16(tables_stream, s_kernel32);

    // 0x1C ImplMap (1 row): MethodDef #3 -> MemberForwarded (3 << 1) | 1 = 7
    append_u16(tables_stream, 0x0142u); // Winapi | SetLastError | Ansi
    append_u16(tables_stream, static_cast<std::uint16_t>((3u << 1u) | 1u));
    append_u16(tables_stream, s_virtual_alloc);
    append_u16(tables_stream, 1u); // ModuleRef #1

    // 0x20 Assembly (1 row)
    append_u32(tables_stream, 0x00008004u); // SHA1
    append_u16(tables_stream, 1u);
    append_u16(tables_stream, 2u);
    append_u16(tables_stream, 3u);
    append_u16(tables_stream, 4u);
    append_u32(tables_stream, 0x0001u); // PublicKey
    append_u16(tables_stream, b_pubkey);
    append_u16(tables_stream, s_asm_name);
    append_u16(tables_stream, 0u); // neutral culture

    // 0x23 AssemblyRef (1 row)
    append_u16(tables_stream, 8u);
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 0u);
    append_u32(tables_stream, 0u);
    append_u16(tables_stream, b_pkt);
    append_u16(tables_stream, s_sys_runtime);
    append_u16(tables_stream, 0u);
    append_u16(tables_stream, 0u);

    pad_align4(tables_stream);
    const std::vector<std::uint8_t> strings_stream = strings.finish();
    const std::vector<std::uint8_t> us_stream = us.finish();
    const std::vector<std::uint8_t> blob_stream = blobs.finish();

    // Build BSJB Metadata Root.
    // Header up to StreamHeaders: 16 bytes + 12-byte version ("v4.0.30319\0\0") + 4 bytes = 32 bytes.
    // StreamHeaders:
    //   "#~"       -> 8 + 4  = 12 bytes
    //   "#Strings" -> 8 + 12 = 20 bytes
    //   "#US"      -> 8 + 4  = 12 bytes
    //   "#GUID"    -> 8 + 8  = 16 bytes
    //   "#Blob"    -> 8 + 8  = 16 bytes
    // Total BSJB header + stream headers = 32 + 76 = 108 (0x6C) bytes.
    const std::uint32_t off_tilde = 0x6Cu;
    const auto off_strings = static_cast<std::uint32_t>(off_tilde + tables_stream.size());
    const auto off_us = static_cast<std::uint32_t>(off_strings + strings_stream.size());
    const auto off_guid = static_cast<std::uint32_t>(off_us + us_stream.size());
    const auto off_blob = static_cast<std::uint32_t>(off_guid + guid_stream.size());

    std::vector<std::uint8_t> bsjb;
    append_u32(bsjb, 0x424A5342u); // "BSJB"
    append_u16(bsjb, 1u);
    append_u16(bsjb, 1u);
    append_u32(bsjb, 0u);
    append_u32(bsjb, 12u);
    const std::string_view ver = "v4.0.30319";
    bsjb.insert(bsjb.end(), ver.begin(), ver.end());
    bsjb.push_back(0u);
    bsjb.push_back(0u);
    append_u16(bsjb, 0u); // Flags
    append_u16(bsjb, 5u); // Streams = 5

    auto append_stream_hdr = [&](std::uint32_t off, std::uint32_t sz, std::string_view name) {
        append_u32(bsjb, off);
        append_u32(bsjb, sz);
        bsjb.insert(bsjb.end(), name.begin(), name.end());
        bsjb.push_back(0u);
        pad_align4(bsjb);
    };
    append_stream_hdr(off_tilde, static_cast<std::uint32_t>(tables_stream.size()), "#~");
    append_stream_hdr(off_strings, static_cast<std::uint32_t>(strings_stream.size()), "#Strings");
    append_stream_hdr(off_us, static_cast<std::uint32_t>(us_stream.size()), "#US");
    append_stream_hdr(off_guid, static_cast<std::uint32_t>(guid_stream.size()), "#GUID");
    append_stream_hdr(off_blob, static_cast<std::uint32_t>(blob_stream.size()), "#Blob");

    bsjb.insert(bsjb.end(), tables_stream.begin(), tables_stream.end());
    bsjb.insert(bsjb.end(), strings_stream.begin(), strings_stream.end());
    bsjb.insert(bsjb.end(), us_stream.begin(), us_stream.end());
    bsjb.insert(bsjb.end(), guid_stream.begin(), guid_stream.end());
    bsjb.insert(bsjb.end(), blob_stream.begin(), blob_stream.end());

    // Assemble full PE image: headers [0..0x400), .text [0x400..0x1C00) @ RVA 0x1000.
    constexpr std::size_t kHeadersSize = 0x400u;
    constexpr std::size_t kTextRawSize = 0x1800u;
    std::vector<std::uint8_t> pe(kHeadersSize + kTextRawSize, 0u);

    pe[0] = 'M';
    pe[1] = 'Z';
    put_u32(pe, 0x3Cu, 0x80u);
    pe[0x80u] = 'P';
    pe[0x81u] = 'E';
    put_u16(pe, 0x84u, pe64 ? 0x8664u : 0x014Cu);
    put_u16(pe, 0x86u, 1u);
    put_u16(pe, 0x94u, pe64 ? 0xF0u : 0xE0u);
    put_u16(pe, 0x96u, pe64 ? 0x0022u : 0x0102u);

    constexpr std::size_t kOptOff = 0x98u;
    std::size_t sec_hdr_off = 0u;
    if (pe64) {
        put_u16(pe, kOptOff + 0x00u, 0x020Bu);
        put_u32(pe, kOptOff + 0x10u, 0x1000u);
        put_u32(pe, kOptOff + 0x14u, 0x1000u);
        put_u64(pe, kOptOff + 0x18u, 0x140000000ULL);
        put_u32(pe, kOptOff + 0x20u, 0x1000u);
        put_u32(pe, kOptOff + 0x24u, 0x200u);
        put_u16(pe, kOptOff + 0x28u, 6u);
        put_u16(pe, kOptOff + 0x30u, 6u);
        put_u32(pe, kOptOff + 0x38u, 0x3000u);
        put_u32(pe, kOptOff + 0x3Cu, static_cast<std::uint32_t>(kHeadersSize));
        put_u16(pe, kOptOff + 0x44u, 3u);
        put_u16(pe, kOptOff + 0x46u, 0x8160u);
        put_u32(pe, kOptOff + 0x6Cu, 16u);
        // DataDirectory[14] = COM_DESCRIPTOR @ RVA 0x1000, size 0x48
        const std::size_t clr_dd_off = kOptOff + 0x70u + 14u * 8u;
        put_u32(pe, clr_dd_off + 0u, 0x1000u);
        put_u32(pe, clr_dd_off + 4u, 0x48u);
        sec_hdr_off = kOptOff + 0xF0u;
    } else {
        put_u16(pe, kOptOff + 0x00u, 0x010Bu);
        put_u32(pe, kOptOff + 0x10u, 0x1000u);
        put_u32(pe, kOptOff + 0x14u, 0x1000u);
        put_u32(pe, kOptOff + 0x18u, 0x1000u);
        put_u32(pe, kOptOff + 0x1Cu, 0x00400000u);
        put_u32(pe, kOptOff + 0x20u, 0x1000u);
        put_u32(pe, kOptOff + 0x24u, 0x200u);
        put_u16(pe, kOptOff + 0x28u, 6u);
        put_u16(pe, kOptOff + 0x30u, 6u);
        put_u32(pe, kOptOff + 0x38u, 0x3000u);
        put_u32(pe, kOptOff + 0x3Cu, static_cast<std::uint32_t>(kHeadersSize));
        put_u16(pe, kOptOff + 0x44u, 3u);
        put_u16(pe, kOptOff + 0x46u, 0x8140u);
        put_u32(pe, kOptOff + 0x5Cu, 16u);
        const std::size_t clr_dd_off = kOptOff + 0x60u + 14u * 8u;
        put_u32(pe, clr_dd_off + 0u, 0x1000u);
        put_u32(pe, clr_dd_off + 4u, 0x48u);
        sec_hdr_off = kOptOff + 0xE0u;
    }

    const std::string_view sec_name = ".text";
    std::copy(sec_name.begin(), sec_name.end(), pe.begin() + static_cast<std::ptrdiff_t>(sec_hdr_off));
    put_u32(pe, sec_hdr_off + 8u, static_cast<std::uint32_t>(kTextRawSize));
    put_u32(pe, sec_hdr_off + 12u, 0x1000u);
    put_u32(pe, sec_hdr_off + 16u, static_cast<std::uint32_t>(kTextRawSize));
    put_u32(pe, sec_hdr_off + 20u, static_cast<std::uint32_t>(kHeadersSize));
    put_u32(pe, sec_hdr_off + 36u, 0x60000020u);

    // Populate .text (file offset 0x400 == RVA 0x1000).
    constexpr std::uint32_t kMetadataRva = 0x1100u;
    const std::size_t cor20_off = kHeadersSize;
    put_u32(pe, cor20_off + 0u, 0x48u);
    put_u16(pe, cor20_off + 4u, 2u);
    put_u16(pe, cor20_off + 6u, 5u);
    put_u32(pe, cor20_off + 8u, kMetadataRva);
    put_u32(pe, cor20_off + 12u, static_cast<std::uint32_t>(bsjb.size()));
    put_u32(pe, cor20_off + 16u, 0x00020009u); // ILONLY | STRONGNAMESIGNED | 32BITPREFERRED
    put_u32(pe, cor20_off + 20u, 0x06000001u); // EntryPointToken = MethodDef #1

    // Tiny IL method @ RVA 0x1050 (file offset 0x450):
    //   ldstr 0x70000001 ; call 0x0A000001 ; ret (11 bytes)
    const std::size_t tiny_off = kHeadersSize + 0x50u;
    pe[tiny_off + 0u] = static_cast<std::uint8_t>((11u << 2u) | 0x02u);
    pe[tiny_off + 1u] = 0x72u; // ldstr
    put_u32(pe, tiny_off + 2u, tok_hello);
    pe[tiny_off + 6u] = 0x28u; // call
    put_u32(pe, tiny_off + 7u, 0x0A000001u);
    pe[tiny_off + 11u] = 0x2Au; // ret

    // Fat IL method @ RVA 0x1060 (file offset 0x460):
    //   IL_0000: br.s +1        -> IL_0003
    //   IL_0002: nop
    //   IL_0003: ldarg.0        (try start)
    //   IL_0004: switch (2) [ +2 -> IL_0013, +5 -> IL_0016 ]
    //   IL_0011: ceq            (0xFE 0x01)
    //   IL_0013: ldc.i4.0
    //   IL_0014: leave.s +3     -> IL_0019 (try end @ IL_0016)
    //   IL_0016: pop            (catch System.Exception handler start)
    //   IL_0017: leave.s +0     -> IL_0019 (handler end @ IL_0019)
    //   IL_0019: ldc.i4.1
    //   IL_001A: ret            (code_size = 0x1B = 27)
    const std::size_t fat_off = kHeadersSize + 0x60u;
    put_u16(pe, fat_off + 0u, 0x301Bu); // FatFormat(3) | MoreSects(8) | InitLocals(0x10) | size=3 dwords
    put_u16(pe, fat_off + 2u, 4u);      // MaxStack = 4
    put_u32(pe, fat_off + 4u, 0x1Bu);   // CodeSize = 27
    put_u32(pe, fat_off + 8u, 0x11000001u);

    const std::array<std::uint8_t, 27> fat_code = {
        0x2Bu, 0x01u,                                     // IL_0000: br.s IL_0003
        0x00u,                                            // IL_0002: nop
        0x02u,                                            // IL_0003: ldarg.0
        0x45u, 0x02u, 0x00u, 0x00u, 0x00u,                // IL_0004: switch N=2
        0x02u, 0x00u, 0x00u, 0x00u,                       //   case 0 -> IL_0013
        0x05u, 0x00u, 0x00u, 0x00u,                       //   case 1 -> IL_0016
        0xFEu, 0x01u,                                     // IL_0011: ceq
        0x16u,                                            // IL_0013: ldc.i4.0
        0xDEu, 0x03u,                                     // IL_0014: leave.s IL_0019
        0x26u,                                            // IL_0016: pop
        0xDEu, 0x00u,                                     // IL_0017: leave.s IL_0019
        0x17u,                                            // IL_0019: ldc.i4.1
        0x2Au,                                            // IL_001A: ret
    };
    std::copy(fat_code.begin(), fat_code.end(), pe.begin() + static_cast<std::ptrdiff_t>(fat_off + 12u));

    // 4-byte aligned Tiny EH section @ fat_off + 12 + 28 = fat_off + 40 (0x488).
    const std::size_t eh_off = fat_off + 40u;
    pe[eh_off + 0u] = 0x01u; // CorILMethod_Sect_EHTable (Tiny)
    pe[eh_off + 1u] = 16u;   // 4 + 12
    put_u16(pe, eh_off + 2u, 0u);
    put_u16(pe, eh_off + 4u, 0x0000u); // Catch
    put_u16(pe, eh_off + 6u, 0x0003u); // TryOffset
    pe[eh_off + 8u] = 0x13u;           // TryLength
    put_u16(pe, eh_off + 9u, 0x0016u); // HandlerOffset
    pe[eh_off + 11u] = 0x03u;          // HandlerLength
    put_u32(pe, eh_off + 12u, 0x01000003u); // TypeRef #3 = System.Exception

    const std::size_t md_file_off = kHeadersSize + (kMetadataRva - 0x1000u);
    std::copy(bsjb.begin(), bsjb.end(), pe.begin() + static_cast<std::ptrdiff_t>(md_file_off));

    return SyntheticDotNetLayout{
        .file_bytes = std::move(pe),
        .metadata_file_offset = static_cast<std::uint32_t>(md_file_off),
        .metadata_size = static_cast<std::uint32_t>(bsjb.size()),
        .tables_stream_file_offset = static_cast<std::uint32_t>(md_file_off + off_tilde),
        .tiny_method_rva = 0x1050u,
        .fat_method_rva = 0x1060u,
        .hello_us_token = tok_hello,
    };
}

} // namespace

TEST(ClrMetadataTest, ParsesSyntheticDotNetPe32AndPe32PlusTablesSignaturesAndPInvoke) {
    for (const bool pe64 : {false, true}) {
        const SyntheticDotNetLayout syn = build_synthetic_dotnet_pe(pe64);
        auto img = peelf::parse_image(syn.file_bytes);
        ASSERT_TRUE(img.has_value()) << img.error().message;
        ASSERT_NE((*img)->pe_clr_header(), nullptr);

        auto parsed = peelf::parse_clr_metadata(**img, syn.file_bytes);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        const peelf::ClrMetadata& md = *parsed;

        EXPECT_EQ(md.runtime_version, "v4.0.30319");
        EXPECT_TRUE(md.compressed_tables);
        EXPECT_NE(md.cor20_flags_summary.find("ILONLY"), std::string::npos);
        EXPECT_NE(md.cor20_flags_summary.find("STRONGNAMESIGNED"), std::string::npos);
        EXPECT_NE(md.cor20_flags_summary.find("32BITPREFERRED"), std::string::npos);
        EXPECT_EQ(md.entry_point_token_or_rva, 0x06000001u);

        ASSERT_TRUE(md.module.has_value());
        EXPECT_EQ(md.module->name, "SampleApp.exe");
        EXPECT_EQ(md.module->mvid_guid, "11223344-5566-7788-99aa-bbccddeeff00");

        ASSERT_TRUE(md.assembly.has_value());
        EXPECT_EQ(md.assembly->name, "SampleApp");
        EXPECT_EQ(md.assembly->version_string(), "1.2.3.4");
        EXPECT_EQ(md.assembly->public_key_hex, "01020304");

        ASSERT_EQ(md.assembly_refs.size(), 1u);
        EXPECT_EQ(md.assembly_refs[0].token, 0x23000001u);
        EXPECT_EQ(md.assembly_refs[0].name, "System.Runtime");
        EXPECT_EQ(md.assembly_refs[0].version_string(), "8.0.0.0");
        EXPECT_EQ(md.assembly_refs[0].public_key_or_token_hex, "b77a5c561934e089");

        ASSERT_EQ(md.type_refs.size(), 3u);
        EXPECT_EQ(md.type_refs[0].full_name(), "System.Object");
        EXPECT_EQ(md.type_refs[0].resolution_scope_summary, "System.Runtime");
        EXPECT_EQ(md.type_refs[1].full_name(), "System.Console");
        EXPECT_EQ(md.type_refs[2].full_name(), "System.Exception");

        ASSERT_EQ(md.type_defs.size(), 2u);
        EXPECT_EQ(md.type_defs[1].token, 0x02000002u);
        EXPECT_EQ(md.type_defs[1].full_name(), "Sample.Program");
        EXPECT_EQ(md.type_defs[1].extends_name, "System.Object");

        ASSERT_EQ(md.fields.size(), 1u);
        EXPECT_EQ(md.fields[0].token, 0x04000001u);
        EXPECT_EQ(md.fields[0].name, "ExitCode");
        EXPECT_EQ(md.fields[0].type_signature, "int32");

        ASSERT_EQ(md.methods.size(), 3u);
        EXPECT_EQ(md.methods[0].full_name(), "Sample.Program::Main");
        EXPECT_EQ(md.methods[0].signature_summary, "void(string[] args)");
        ASSERT_TRUE(md.methods[0].file_offset.has_value());
        EXPECT_EQ(*md.methods[0].file_offset, 0x450u);

        EXPECT_EQ(md.methods[1].full_name(), "Sample.Program::DispatchWithEh");
        EXPECT_EQ(md.methods[1].signature_summary, "int32(int32 code)");
        ASSERT_TRUE(md.methods[1].file_offset.has_value());
        EXPECT_EQ(*md.methods[1].file_offset, 0x460u);

        EXPECT_EQ(md.methods[2].full_name(), "Sample.Program::VirtualAlloc");
        EXPECT_EQ(md.methods[2].rva, 0u);
        EXPECT_FALSE(md.methods[2].file_offset.has_value());
        EXPECT_EQ(md.methods[2].signature_summary, "intptr(intptr, uintptr, uint32, uint32)");

        ASSERT_EQ(md.member_refs.size(), 1u);
        EXPECT_EQ(md.member_refs[0].declaring_parent, "System.Console");
        EXPECT_EQ(md.member_refs[0].name, "WriteLine");
        EXPECT_EQ(md.member_refs[0].signature_summary, "void(string)");

        ASSERT_EQ(md.pinvoke_entries.size(), 1u);
        EXPECT_EQ(md.pinvoke_entries[0].module_name, "kernel32.dll");
        EXPECT_EQ(md.pinvoke_entries[0].entry_point_name, "VirtualAlloc");
        EXPECT_EQ(md.pinvoke_entries[0].method_full_name, "Sample.Program::VirtualAlloc");
        EXPECT_EQ(md.pinvoke_entries[0].method_token, 0x06000003u);

        ASSERT_EQ(md.user_strings.size(), 1u);
        EXPECT_EQ(md.user_strings[0].token, 0x70000001u);
        EXPECT_EQ(md.user_strings[0].value, "Hello from CIL");
    }
}

TEST(ClrMetadataTest, DisassemblesTinyAndFatCilMethodsWithTokenResolutionSwitchAndEhClauses) {
    const SyntheticDotNetLayout syn = build_synthetic_dotnet_pe(true);
    auto img = peelf::parse_image(syn.file_bytes);
    ASSERT_TRUE(img.has_value());
    auto parsed = peelf::parse_clr_metadata(**img, syn.file_bytes);
    ASSERT_TRUE(parsed.has_value());
    const peelf::ClrMetadata& md = *parsed;

    // 1. Tiny IL method: ldstr "Hello from CIL" ; call System.Console::WriteLine ; ret
    auto tiny_cil = peelf::disassemble_cil_method(**img, syn.file_bytes, md, md.methods[0]);
    ASSERT_TRUE(tiny_cil.has_value()) << tiny_cil.error().message;
    EXPECT_FALSE(tiny_cil->is_fat_header);
    EXPECT_EQ(tiny_cil->header_size(), 1u);
    EXPECT_EQ(tiny_cil->max_stack, 8u);
    EXPECT_EQ(tiny_cil->code_size, 11u);
    ASSERT_EQ(tiny_cil->instructions.size(), 3u);

    EXPECT_EQ(tiny_cil->instructions[0].il_offset, 0x0000u);
    EXPECT_EQ(tiny_cil->instructions[0].mnemonic, "ldstr");
    EXPECT_EQ(tiny_cil->instructions[0].referenced_token, std::optional<std::uint32_t>(0x70000001u));
    EXPECT_NE(tiny_cil->instructions[0].operand_text.find("\"Hello from CIL\""), std::string::npos);

    EXPECT_EQ(tiny_cil->instructions[1].il_offset, 0x0005u);
    EXPECT_EQ(tiny_cil->instructions[1].mnemonic, "call");
    EXPECT_EQ(tiny_cil->instructions[1].referenced_token, std::optional<std::uint32_t>(0x0A000001u));
    EXPECT_NE(tiny_cil->instructions[1].operand_text.find("System.Console::WriteLine"),
              std::string::npos);

    EXPECT_EQ(tiny_cil->instructions[2].il_offset, 0x000Au);
    EXPECT_EQ(tiny_cil->instructions[2].mnemonic, "ret");

    // 2. Fat IL method: br.s + switch + 0xFE ceq + Tiny EH catch clause
    auto fat_cil = peelf::disassemble_cil_method(**img, syn.file_bytes, md, md.methods[1]);
    ASSERT_TRUE(fat_cil.has_value()) << fat_cil.error().message;
    EXPECT_TRUE(fat_cil->is_fat_header);
    EXPECT_EQ(fat_cil->header_size(), 12u);
    EXPECT_EQ(fat_cil->max_stack, 4u);
    EXPECT_EQ(fat_cil->code_size, 27u);
    EXPECT_TRUE(fat_cil->init_locals);
    EXPECT_EQ(fat_cil->local_var_sig_tok, 0x11000001u);

    ASSERT_GE(fat_cil->instructions.size(), 9u);
    EXPECT_EQ(fat_cil->instructions[0].mnemonic, "br.s");
    EXPECT_EQ(fat_cil->instructions[0].operand_text, "IL_0003");
    EXPECT_EQ(fat_cil->instructions[0].branch_target_il_offset,
              std::optional<std::uint32_t>(0x0003u));

    EXPECT_EQ(fat_cil->instructions[3].il_offset, 0x0004u);
    EXPECT_EQ(fat_cil->instructions[3].mnemonic, "switch");
    EXPECT_EQ(fat_cil->instructions[3].operand_text, "(IL_0013, IL_0016)");

    EXPECT_EQ(fat_cil->instructions[4].il_offset, 0x0011u);
    EXPECT_EQ(fat_cil->instructions[4].mnemonic, "ceq");

    ASSERT_EQ(fat_cil->eh_clauses.size(), 1u);
    EXPECT_EQ(fat_cil->eh_clauses[0].kind, peelf::CilEhClauseKind::Catch);
    EXPECT_EQ(fat_cil->eh_clauses[0].try_offset, 0x0003u);
    EXPECT_EQ(fat_cil->eh_clauses[0].try_length, 0x0013u);
    EXPECT_EQ(fat_cil->eh_clauses[0].handler_offset, 0x0016u);
    EXPECT_EQ(fat_cil->eh_clauses[0].handler_length, 0x0003u);
    EXPECT_EQ(fat_cil->eh_clauses[0].catch_type_name, "System.Exception");
}

TEST(ClrMetadataTest, DegradesGracefullyOnCorruptMetadataAndTruncatedCilWithoutCrash) {
    const SyntheticDotNetLayout base = build_synthetic_dotnet_pe(true);
    auto base_img = peelf::parse_image(base.file_bytes);
    ASSERT_TRUE(base_img.has_value());

    // 1. Bad BSJB signature fails cleanly.
    {
        std::vector<std::uint8_t> bad_bsjb = base.file_bytes;
        bad_bsjb[base.metadata_file_offset] = 'X';
        auto res = peelf::parse_clr_metadata(**base_img, bad_bsjb);
        EXPECT_FALSE(res.has_value());
    }

    // 2. Unknown high Valid table bit before Assembly/AssemblyRef degrades gracefully without crash.
    {
        const SyntheticDotNetLayout unknown_bit = build_synthetic_dotnet_pe(true, (1ULL << 0x1Eu));
        auto img = peelf::parse_image(unknown_bit.file_bytes);
        ASSERT_TRUE(img.has_value());
        auto res = peelf::parse_clr_metadata(**img, unknown_bit.file_bytes);
        ASSERT_TRUE(res.has_value()) << res.error().message;
        EXPECT_FALSE(res->diagnostics.empty());
        ASSERT_TRUE(res->module.has_value());
        EXPECT_EQ(res->module->name, "SampleApp.exe");
    }

    // 3. Truncated #~ row data records diagnostic without reading out of bounds.
    {
        std::vector<std::uint8_t> trunc_tables = base.file_bytes;
        // Shrink #~ stream size in first StreamHeader (at metadata_file_offset + 32 + 4).
        put_u32(trunc_tables, base.metadata_file_offset + 36u, 60u);
        auto res = peelf::parse_clr_metadata(**base_img, trunc_tables);
        ASSERT_TRUE(res.has_value());
        EXPECT_FALSE(res->diagnostics.empty());
    }

    // 4. Out-of-bounds #Strings / #GUID / #Blob / #US indices do not crash and record diagnostics.
    {
        std::vector<std::uint8_t> oob_heaps = base.file_bytes;
        // Overwrite Module.Name & Module.Mvid (first row after 24B header + 11*4B counts = +68) with 0xFFFF.
        const std::size_t module_row_off = base.tables_stream_file_offset + 24u + 11u * 4u;
        put_u16(oob_heaps, module_row_off + 2u, 0xFFFFu);
        put_u16(oob_heaps, module_row_off + 4u, 0xFFFFu);
        // Also corrupt Field[0].Signature (#Blob index) to 0xFFFF:
        // Module(10B) + TypeRef(3*6B=18B) + TypeDef(2*14B=28B) = +56B -> Field[0] (+4 is Signature).
        put_u16(oob_heaps, module_row_off + 56u + 4u, 0xFFFFu);
        auto res = peelf::parse_clr_metadata(**base_img, oob_heaps);
        ASSERT_TRUE(res.has_value());
        ASSERT_TRUE(res->module.has_value());
        EXPECT_EQ(res->module->name, "<invalid-string>");
        EXPECT_EQ(res->module->mvid_guid, "<invalid-guid>");
        ASSERT_EQ(res->fields.size(), 1u);
        EXPECT_EQ(res->fields[0].type_signature, "...");
        EXPECT_FALSE(res->diagnostics.empty());
    }

    // 5. Truncated switch instruction & invalid Fat EH section chain degrade cleanly.
    {
        auto clean_md = peelf::parse_clr_metadata(**base_img, base.file_bytes);
        ASSERT_TRUE(clean_md.has_value());

        std::vector<std::uint8_t> bad_cil = base.file_bytes;
        const std::size_t fat_off = 0x460u;
        // Set switch target count at IL_0004 (fat_off + 12 + 4 + 1) to 0x40000000 (huge).
        put_u32(bad_cil, fat_off + 17u, 0x40000000u);
        // Set EH section header kind to Fat | MoreSects with huge size exceeding image.
        const std::size_t eh_off = fat_off + 40u;
        bad_cil[eh_off + 0u] = 0xC1u; // EHTable | FatFormat | MoreSects
        bad_cil[eh_off + 1u] = 0xFFu;
        bad_cil[eh_off + 2u] = 0xFFu;
        bad_cil[eh_off + 3u] = 0x7Fu;

        auto dis = peelf::disassemble_cil_method(**base_img, bad_cil, *clean_md, clean_md->methods[1]);
        ASSERT_TRUE(dis.has_value());
        EXPECT_FALSE(dis->diagnostics.empty());
    }
}

TEST(ClrMetadataTest, HeadlessCliClrFlagAndViewerModelPopulateTextJsonCsvAndStructure) {
    const SyntheticDotNetLayout syn = build_synthetic_dotnet_pe(true);
    const peelf_test::ScopedTempDir tmp("clr_headless");
    const std::filesystem::path exe_path = tmp.path() / "SampleApp.exe";
    {
        std::ofstream ofs(exe_path, std::ios::binary);
        ASSERT_TRUE(ofs.good());
        ofs.write(reinterpret_cast<const char*>(syn.file_bytes.data()),
                  static_cast<std::streamsize>(syn.file_bytes.size()));
    }

    const std::string path_arg = exe_path.string();

    // 1. Headless --clr --format text
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 5> args = {
            "--headless", path_arg, "--clr", "--format", "text"};
        const std::optional<int> rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        const std::string text = out_ss.str();
        EXPECT_NE(text.find("[.NET / CLR Metadata]"), std::string::npos);
        EXPECT_NE(text.find("v4.0.30319"), std::string::npos);
        EXPECT_NE(text.find("SampleApp, Version=1.2.3.4"), std::string::npos);
        EXPECT_NE(text.find("System.Runtime (Version=8.0.0.0"), std::string::npos);
        EXPECT_NE(text.find("kernel32.dll!VirtualAlloc"), std::string::npos);
    }

    // 2. Headless --clr --format json
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 5> args = {
            "--headless", path_arg, "--clr", "--format", "json"};
        const std::optional<int> rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        const std::string json = out_ss.str();
        EXPECT_NE(json.find("\"clr\": {"), std::string::npos);
        EXPECT_NE(json.find("\"runtime_version\": \"v4.0.30319\""), std::string::npos);
        EXPECT_NE(json.find("\"type_def_count\": 2"), std::string::npos);
        EXPECT_NE(json.find("\"method_def_count\": 3"), std::string::npos);
        EXPECT_NE(json.find("\"module_name\": \"kernel32.dll\""), std::string::npos);
    }

    // 3. Headless --clr --format csv
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 5> args = {
            "--headless", path_arg, "--clr", "--format", "csv"};
        const std::optional<int> rc = viewer::try_run_headless_or_help_cli(args, out_ss, err_ss);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err_ss.str();
        const std::string csv = out_ss.str();
        EXPECT_NE(csv.find("clr_summary,"), std::string::npos);
        EXPECT_NE(csv.find("clr_assembly_ref,"), std::string::npos);
        EXPECT_NE(csv.find("clr_pinvoke,"), std::string::npos);
        EXPECT_NE(csv.find("VirtualAlloc,kernel32.dll,"), std::string::npos);
    }

    // 4. Viewer BinaryModel + Structure Headers -> "CLR / .NET Metadata" + Details rows
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(path_arg));
    ASSERT_TRUE(model.clr_metadata().has_value());
    EXPECT_EQ(model.clr_metadata()->runtime_version, "v4.0.30319");

    ASSERT_NE(model.image(), nullptr);
    const viewer::StructureNode tree = viewer::build_structure_tree(*model.image());
    const viewer::StructureNode* headers_node = nullptr;
    for (const viewer::StructureNode& child : tree.children) {
        if (child.selection.label == "Headers") {
            headers_node = &child;
            break;
        }
    }
    ASSERT_NE(headers_node, nullptr);
    const viewer::StructureNode* clr_hdr_node = nullptr;
    for (const viewer::StructureNode& child : headers_node->children) {
        if (child.selection.label == "CLR / .NET Metadata") {
            clr_hdr_node = &child;
            break;
        }
    }
    ASSERT_NE(clr_hdr_node, nullptr);
    EXPECT_EQ(clr_hdr_node->selection.kind, viewer::SelectionKind::ClrHeader);

    const auto props = viewer::build_selection_detail_properties(clr_hdr_node->selection, model);
    bool saw_runtime_prop = false;
    bool saw_assembly_prop = false;
    for (const viewer::DetailPropertyRow& row : props) {
        if (row.key == "Metadata Runtime" && row.value.find("v4.0.30319") != std::string::npos) {
            saw_runtime_prop = true;
        }
        if (row.key == "Assembly" && row.value.find("SampleApp v1.2.3.4") != std::string::npos) {
            saw_assembly_prop = true;
        }
    }
    EXPECT_TRUE(saw_runtime_prop);
    EXPECT_TRUE(saw_assembly_prop);
}
