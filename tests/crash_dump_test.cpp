#include <gtest/gtest.h>

#include "model/binary_model.hpp"

#include <peelf/crash_dump.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/runtime_structures.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/stack_tls.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void append_u16_le(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (unsigned i = 0; i < 4u; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu));
    }
}

void append_u64_le(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (unsigned i = 0; i < 8u; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu));
    }
}

void write_u32_le_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    for (unsigned i = 0; i < 4u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void write_u64_le_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    for (unsigned i = 0; i < 8u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void append_u16_be(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void append_u32_be(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (static_cast<unsigned>(i) * 8u)) & 0xFFu));
    }
}

void write_u32_be_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        const auto shift = static_cast<unsigned>((3u - i) * 8u);
        buf[off + i] = static_cast<std::uint8_t>((v >> shift) & 0xFFu);
    }
}

std::uint32_t append_minidump_utf16_string(std::vector<std::uint8_t>& buf, std::string_view ascii) {
    while ((buf.size() % 4u) != 0u) {
        buf.push_back(0u);
    }
    const auto rva = static_cast<std::uint32_t>(buf.size());
    append_u32_le(buf, static_cast<std::uint32_t>(ascii.size() * 2u));
    for (char ch : ascii) {
        append_u16_le(buf, static_cast<std::uint8_t>(ch));
    }
    append_u16_le(buf, 0u);
    return rva;
}

std::vector<std::uint8_t> make_minimal_mapped_pe64(std::uint64_t image_base) {
    std::vector<std::uint8_t> img(0x400u, 0u);
    // DOS header
    img[0] = 'M';
    img[1] = 'Z';
    write_u32_le_at(img, 0x3Cu, 0x80u);

    // PE signature
    img[0x80] = 'P';
    img[0x81] = 'E';
    img[0x82] = 0u;
    img[0x83] = 0u;

    // COFF header (20 bytes @ 0x84)
    img[0x84] = 0x64u;
    img[0x85] = 0x86u; // IMAGE_FILE_MACHINE_AMD64
    img[0x86] = 1u;    // NumberOfSections = 1
    img[0x94] = 0xF0u; // SizeOfOptionalHeader = 240
    img[0x96] = 0x22u; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header PE32+ (@ 0x98)
    const std::size_t opt = 0x98u;
    img[opt + 0] = 0x0Bu;
    img[opt + 1] = 0x02u; // Magic = 0x20B
    write_u32_le_at(img, opt + 16u, 0x200u);      // AddressOfEntryPoint
    write_u32_le_at(img, opt + 20u, 0x200u);      // BaseOfCode
    write_u64_le_at(img, opt + 24u, image_base);  // ImageBase
    write_u32_le_at(img, opt + 32u, 0x1000u);     // SectionAlignment
    write_u32_le_at(img, opt + 36u, 0x200u);      // FileAlignment
    write_u32_le_at(img, opt + 56u, 0x2000u);     // SizeOfImage
    write_u32_le_at(img, opt + 60u, 0x200u);      // SizeOfHeaders
    img[opt + 70u] = 0x60u;
    img[opt + 71u] = 0x01u; // DYNAMIC_BASE | HIGH_ENTROPY_VA | NX_COMPAT
    write_u32_le_at(img, opt + 108u, 16u);        // NumberOfRvaAndSizes

    // Section Header `.text` (@ 0x188, 40 bytes)
    const std::size_t sh = opt + 0xF0u;
    std::memcpy(img.data() + sh, ".text\0\0\0", 8u);
    write_u32_le_at(img, sh + 8u, 0x200u);        // VirtualSize
    write_u32_le_at(img, sh + 12u, 0x200u);       // VirtualAddress (compact test span)
    write_u32_le_at(img, sh + 16u, 0x200u);       // SizeOfRawData
    write_u32_le_at(img, sh + 20u, 0x200u);       // PointerToRawData
    write_u32_le_at(img, sh + 36u, 0x60000020u);  // CNT_CODE | MEM_EXECUTE | MEM_READ

    // Machine instructions at RVA 0x200..0x240
    // 0x200: push rbp; mov rbp, rsp; ...
    const std::array<std::uint8_t, 12> code = {
        0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
        0x48, 0xC7, 0x04, 0x25, 0x00, 0x00, 0xAD, 0xDE // mov qword ptr [0xDEAD0000], ...
    };
    std::copy(code.begin(), code.end(), img.begin() + 0x210u);
    img[0x240u] = 0xC3u; // ret at caller return site
    return img;
}

std::vector<std::uint8_t> build_synthetic_amd64_minidump() {
    constexpr std::uint64_t kImageBase = 0x00007FF610000000ULL;
    constexpr std::uint64_t kCrashRip  = kImageBase + 0x214ULL;
    constexpr std::uint64_t kCallerRet = kImageBase + 0x240ULL;
    constexpr std::uint64_t kStackBase = 0x000000990010F000ULL;
    constexpr std::uint64_t kRsp       = kStackBase + 0x080ULL;
    constexpr std::uint64_t kRbp       = kStackBase + 0x0A0ULL;
    constexpr std::uint64_t kOuterRbp  = kStackBase + 0x0E0ULL;
    constexpr std::uint64_t kTebAddr   = 0x0000009900050000ULL;

    std::vector<std::uint8_t> dmp;
    dmp.reserve(8192u);

    // MINIDUMP_HEADER (32 bytes) + 8 stream directory entries (8 * 12 = 96 bytes)
    constexpr std::uint32_t kStreamCount = 8u;
    append_u32_le(dmp, 0x504D444Du); // "MDMP"
    append_u32_le(dmp, 0x0000A793u); // Version
    append_u32_le(dmp, kStreamCount);
    append_u32_le(dmp, 32u);         // StreamDirectoryRva
    append_u32_le(dmp, 0u);          // CheckSum
    append_u32_le(dmp, 1700000000u); // TimeDateStamp
    append_u64_le(dmp, 0x0002ULL);   // Flags (MiniDumpWithFullMemory)

    const std::size_t dir_base = dmp.size();
    dmp.resize(dir_base + kStreamCount * 12u, 0u);
    auto set_dir = [&](std::uint32_t idx, std::uint32_t type, std::uint32_t size, std::uint32_t rva) {
        const std::size_t off = dir_base + idx * 12u;
        write_u32_le_at(dmp, off + 0u, type);
        write_u32_le_at(dmp, off + 4u, size);
        write_u32_le_at(dmp, off + 8u, rva);
    };

    // Strings first
    const std::uint32_t mod_name_rva = append_minidump_utf16_string(dmp, "C:\\app\\crash_demo.exe");
    const std::uint32_t h_type_rva = append_minidump_utf16_string(dmp, "Event");
    const std::uint32_t h_obj_rva  = append_minidump_utf16_string(dmp, "\\BaseNamedObjects\\CrashReady");

    // AMD64 CONTEXT (1232 bytes)
    while ((dmp.size() % 16u) != 0u) dmp.push_back(0u);
    const auto ctx_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> ctx(1232u, 0u);
    write_u32_le_at(ctx, 48u, 0x0010000Fu); // ContextFlags
    write_u32_le_at(ctx, 68u, 0x00010246u); // EFlags
    write_u64_le_at(ctx, 120u, 0xCAFEBABE12345678ULL); // Rax
    write_u64_le_at(ctx, 128u, 0x1111222233334444ULL); // Rcx
    write_u64_le_at(ctx, 152u, kRsp);                  // Rsp
    write_u64_le_at(ctx, 160u, kRbp);                  // Rbp
    write_u64_le_at(ctx, 248u, kCrashRip);             // Rip
    dmp.insert(dmp.end(), ctx.begin(), ctx.end());

    // Stream 0: SystemInfoStream (type 7, 56 bytes)
    const auto sys_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> sys_info(56u, 0u);
    sys_info[0] = 9u; // PROCESSOR_ARCHITECTURE_AMD64
    sys_info[2] = 6u; // ProcessorLevel
    sys_info[6] = 8u; // NumberOfProcessors
    write_u32_le_at(sys_info, 8u, 2u);     // VER_PLATFORM_WIN32_NT
    write_u32_le_at(sys_info, 12u, 10u);   // MajorVersion
    write_u32_le_at(sys_info, 16u, 0u);    // MinorVersion
    write_u32_le_at(sys_info, 20u, 22631u);// BuildNumber
    dmp.insert(dmp.end(), sys_info.begin(), sys_info.end());
    set_dir(0u, 7u, 56u, sys_rva);

    // Stream 1: MiscInfoStream (type 15, 24 bytes)
    const auto misc_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 24u);
    append_u32_le(dmp, 0x1u);  // MINIDUMP_MISC1_PROCESS_ID
    append_u32_le(dmp, 4242u); // ProcessId
    append_u32_le(dmp, 0u);
    append_u32_le(dmp, 0u);
    append_u32_le(dmp, 0u);
    set_dir(1u, 15u, 24u, misc_rva);

    // Stream 2: ModuleListStream (type 4: u32 count + 108-byte MINIDUMP_MODULE)
    const auto mod_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 1u);
    std::vector<std::uint8_t> mod_ent(108u, 0u);
    write_u64_le_at(mod_ent, 0u, kImageBase);
    write_u32_le_at(mod_ent, 8u, 0x2000u);
    write_u32_le_at(mod_ent, 20u, mod_name_rva);
    dmp.insert(dmp.end(), mod_ent.begin(), mod_ent.end());
    set_dir(2u, 4u, 4u + 108u, mod_rva);

    // Stream 3: MemoryInfoListStream (type 16: 16-byte header + 3 * 48-byte entries)
    const auto meminfo_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 16u);
    append_u32_le(dmp, 48u);
    append_u64_le(dmp, 3u);
    auto append_meminfo = [&](std::uint64_t base, std::uint64_t size, std::uint32_t state,
                              std::uint32_t prot, std::uint32_t type) {
        append_u64_le(dmp, base);
        append_u64_le(dmp, base);
        append_u32_le(dmp, prot);
        append_u32_le(dmp, 0u);
        append_u64_le(dmp, size);
        append_u32_le(dmp, state);
        append_u32_le(dmp, prot);
        append_u32_le(dmp, type);
        append_u32_le(dmp, 0u);
    };
    append_meminfo(kImageBase, 0x2000u, 0x1000u /*MEM_COMMIT*/, 0x20u /*PAGE_EXECUTE_READ*/, 0x1000000u /*MEM_IMAGE*/);
    append_meminfo(kStackBase, 0x1000u, 0x1000u /*MEM_COMMIT*/, 0x04u /*PAGE_READWRITE*/, 0x20000u /*MEM_PRIVATE*/);
    append_meminfo(0x0000009900200000ULL, 0x10000u, 0x2000u /*MEM_RESERVE*/, 0x01u /*PAGE_NOACCESS*/, 0x20000u /*MEM_PRIVATE*/);
    set_dir(3u, 16u, 16u + 3u * 48u, meminfo_rva);

    // Prepare raw memory blobs for Memory64ListStream & Thread stack
    const std::vector<std::uint8_t> pe_blob = make_minimal_mapped_pe64(kImageBase);
    std::vector<std::uint8_t> stack_blob(0x200u, 0u);
    // Frame pointer chain at kRbp: [saved_rbp = kOuterRbp, return_address = kCallerRet]
    write_u64_le_at(stack_blob, static_cast<std::size_t>(kRbp - kStackBase), kOuterRbp);
    write_u64_le_at(stack_blob, static_cast<std::size_t>(kRbp - kStackBase + 8u), kCallerRet);
    write_u64_le_at(stack_blob, static_cast<std::size_t>(kOuterRbp - kStackBase), 0u);

    // Reserve space for Memory64ListStream header (16 + 2 * 16 = 48 bytes)
    const auto mem64_rva = static_cast<std::uint32_t>(dmp.size());
    dmp.resize(dmp.size() + 48u, 0u);
    const auto raw_mem_base_rva = static_cast<std::uint64_t>(dmp.size());
    const auto stack_data_rva = static_cast<std::uint32_t>(raw_mem_base_rva + pe_blob.size());
    dmp.insert(dmp.end(), pe_blob.begin(), pe_blob.end());
    dmp.insert(dmp.end(), stack_blob.begin(), stack_blob.end());

    write_u64_le_at(dmp, mem64_rva + 0u, 2u);
    write_u64_le_at(dmp, mem64_rva + 8u, raw_mem_base_rva);
    write_u64_le_at(dmp, mem64_rva + 16u, kImageBase);
    write_u64_le_at(dmp, mem64_rva + 24u, pe_blob.size());
    write_u64_le_at(dmp, mem64_rva + 32u, kStackBase);
    write_u64_le_at(dmp, mem64_rva + 40u, stack_blob.size());
    set_dir(4u, 9u, 48u, mem64_rva);

    // Stream 5: ThreadListStream (type 3: u32 count + 48-byte MINIDUMP_THREAD)
    const auto thr_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 1u);
    std::vector<std::uint8_t> thr_ent(48u, 0u);
    write_u32_le_at(thr_ent, 0u, 7777u); // ThreadId
    write_u64_le_at(thr_ent, 16u, kTebAddr);
    write_u64_le_at(thr_ent, 24u, kStackBase);
    write_u32_le_at(thr_ent, 32u, static_cast<std::uint32_t>(stack_blob.size()));
    write_u32_le_at(thr_ent, 36u, stack_data_rva);
    write_u32_le_at(thr_ent, 40u, static_cast<std::uint32_t>(ctx.size()));
    write_u32_le_at(thr_ent, 44u, ctx_rva);
    dmp.insert(dmp.end(), thr_ent.begin(), thr_ent.end());
    set_dir(5u, 3u, 4u + 48u, thr_rva);

    // Stream 6: ExceptionStream (type 6: 168 bytes)
    const auto exc_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> exc(168u, 0u);
    write_u32_le_at(exc, 0u, 7777u);               // ThreadId
    write_u32_le_at(exc, 8u, 0xC0000005u);         // EXCEPTION_ACCESS_VIOLATION
    write_u64_le_at(exc, 24u, kCrashRip);          // ExceptionAddress
    write_u32_le_at(exc, 32u, 2u);                 // NumberParameters
    write_u64_le_at(exc, 40u, 1ULL);               // Write fault
    write_u64_le_at(exc, 48u, 0x00000000DEAD0000ULL); // Fault target VA
    write_u32_le_at(exc, 160u, static_cast<std::uint32_t>(ctx.size()));
    write_u32_le_at(exc, 164u, ctx_rva);
    dmp.insert(dmp.end(), exc.begin(), exc.end());
    set_dir(6u, 6u, 168u, exc_rva);

    // Stream 7: HandleDataStream (type 12: 16-byte header + 32-byte descriptor)
    const auto hnd_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 16u);
    append_u32_le(dmp, 32u);
    append_u32_le(dmp, 1u);
    append_u32_le(dmp, 0u);
    std::vector<std::uint8_t> hdesc(32u, 0u);
    write_u64_le_at(hdesc, 0u, 0x1A4ULL);
    write_u32_le_at(hdesc, 8u, h_type_rva);
    write_u32_le_at(hdesc, 12u, h_obj_rva);
    write_u32_le_at(hdesc, 20u, 0x001F0003u);
    dmp.insert(dmp.end(), hdesc.begin(), hdesc.end());
    set_dir(7u, 12u, 16u + 32u, hnd_rva);

    return dmp;
}

std::vector<std::uint8_t> build_synthetic_x86_minidump() {
    std::vector<std::uint8_t> dmp;
    constexpr std::uint32_t kStreamCount = 4u;
    append_u32_le(dmp, 0x504D444Du);
    append_u32_le(dmp, 0x0000A793u);
    append_u32_le(dmp, kStreamCount);
    append_u32_le(dmp, 32u);
    append_u32_le(dmp, 0u);
    append_u32_le(dmp, 1700000100u);
    append_u64_le(dmp, 0u);

    const std::size_t dir_base = dmp.size();
    dmp.resize(dir_base + kStreamCount * 12u, 0u);
    auto set_dir = [&](std::uint32_t idx, std::uint32_t type, std::uint32_t size, std::uint32_t rva) {
        const std::size_t off = dir_base + idx * 12u;
        write_u32_le_at(dmp, off + 0u, type);
        write_u32_le_at(dmp, off + 4u, size);
        write_u32_le_at(dmp, off + 8u, rva);
    };

    // X86 CONTEXT (716 bytes)
    const auto ctx_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> ctx(716u, 0u);
    write_u32_le_at(ctx, 176u, 0x11223344u); // Eax
    write_u32_le_at(ctx, 180u, 0x0019FF20u); // Ebp
    write_u32_le_at(ctx, 184u, 0x00401020u); // Eip
    write_u32_le_at(ctx, 192u, 0x00010202u); // EFlags
    write_u32_le_at(ctx, 196u, 0x0019FF00u); // Esp
    dmp.insert(dmp.end(), ctx.begin(), ctx.end());

    // SystemInfoStream (X86 = 0)
    const auto sys_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> sys_info(56u, 0u);
    sys_info[0] = 0u; // INTEL x86
    sys_info[6] = 4u;
    write_u32_le_at(sys_info, 8u, 2u);
    write_u32_le_at(sys_info, 12u, 10u);
    write_u32_le_at(sys_info, 20u, 19045u);
    dmp.insert(dmp.end(), sys_info.begin(), sys_info.end());
    set_dir(0u, 7u, 56u, sys_rva);

    // Code memory payload
    const auto code_data_rva = static_cast<std::uint32_t>(dmp.size());
    const std::array<std::uint8_t, 16> code_bytes = {
        0x55, 0x89, 0xE5, 0x31, 0xC9, 0xF7, 0xF1, 0xC3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    dmp.insert(dmp.end(), code_bytes.begin(), code_bytes.end());

    // MemoryListStream (type 5: u32 count + 16-byte MINIDUMP_MEMORY_DESCRIPTOR)
    const auto mem_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 1u);
    append_u64_le(dmp, 0x00401020ULL);
    append_u32_le(dmp, static_cast<std::uint32_t>(code_bytes.size()));
    append_u32_le(dmp, code_data_rva);
    set_dir(1u, 5u, 20u, mem_rva);

    // ThreadExListStream (type 8: u32 count + 64-byte MINIDUMP_THREAD_EX)
    const auto thr_rva = static_cast<std::uint32_t>(dmp.size());
    append_u32_le(dmp, 1u);
    std::vector<std::uint8_t> thr_ex(64u, 0u);
    write_u32_le_at(thr_ex, 0u, 1234u);
    write_u64_le_at(thr_ex, 16u, 0x7FFDF000ULL);
    write_u32_le_at(thr_ex, 40u, static_cast<std::uint32_t>(ctx.size()));
    write_u32_le_at(thr_ex, 44u, ctx_rva);
    dmp.insert(dmp.end(), thr_ex.begin(), thr_ex.end());
    set_dir(2u, 8u, 4u + 64u, thr_rva);

    // ExceptionStream (type 6)
    const auto exc_rva = static_cast<std::uint32_t>(dmp.size());
    std::vector<std::uint8_t> exc(168u, 0u);
    write_u32_le_at(exc, 0u, 1234u);
    write_u32_le_at(exc, 8u, 0xC0000094u); // EXCEPTION_INT_DIVIDE_BY_ZERO
    write_u64_le_at(exc, 24u, 0x00401025ULL);
    write_u32_le_at(exc, 160u, static_cast<std::uint32_t>(ctx.size()));
    write_u32_le_at(exc, 164u, ctx_rva);
    dmp.insert(dmp.end(), exc.begin(), exc.end());
    set_dir(3u, 6u, 168u, exc_rva);

    return dmp;
}

void append_elf_note_le(std::vector<std::uint8_t>& notes,
                        std::string_view name,
                        std::uint32_t ntype,
                        std::span<const std::uint8_t> desc) {
    const auto namesz = static_cast<std::uint32_t>(name.size() + 1u);
    append_u32_le(notes, namesz);
    append_u32_le(notes, static_cast<std::uint32_t>(desc.size()));
    append_u32_le(notes, ntype);
    for (char c : name) {
        notes.push_back(static_cast<std::uint8_t>(c));
    }
    notes.push_back(0u);
    while ((notes.size() % 4u) != 0u) {
        notes.push_back(0u);
    }
    notes.insert(notes.end(), desc.begin(), desc.end());
    while ((notes.size() % 4u) != 0u) {
        notes.push_back(0u);
    }
}

std::vector<std::uint8_t> build_synthetic_elf64_le_core() {
    constexpr std::uint64_t kCodeVa   = 0x0000000000400000ULL;
    constexpr std::uint64_t kFaultRip = 0x0000000000400120ULL;
    constexpr std::uint64_t kRetVa    = 0x0000000000400180ULL;
    constexpr std::uint64_t kStackVa  = 0x00007FFFFFFFE000ULL;
    constexpr std::uint64_t kRsp      = kStackVa + 0x100ULL;
    constexpr std::uint64_t kRbp      = kStackVa + 0x120ULL;
    constexpr std::uint64_t kOuterRbp = kStackVa + 0x160ULL;
    constexpr std::uint64_t kRwxVa    = 0x00007F0099000000ULL;

    // Build PT_NOTE payload
    std::vector<std::uint8_t> notes;

    // 1. NT_PRPSINFO (136 bytes on 64-bit Linux)
    std::vector<std::uint8_t> prps(136u, 0u);
    write_u32_le_at(prps, 24u, 9001u); // pr_pid = 136 - 112 = 24
    write_u32_le_at(prps, 28u, 1000u); // pr_ppid
    std::memcpy(prps.data() + 40u, "demo_core", 9u);
    std::memcpy(prps.data() + 56u, "/usr/bin/demo_core --crash-test", 31u);
    append_elf_note_le(notes, "CORE", 3u /*NT_PRPSINFO*/, prps);

    // 2. NT_PRSTATUS for worker thread 9001 (non-faulting) + faulting thread 9002
    auto make_prstatus_x64 = [&](std::uint32_t tid, std::uint16_t sig, std::uint64_t rip,
                                 std::uint64_t rsp, std::uint64_t rbp, std::uint64_t rax) {
        std::vector<std::uint8_t> prs(336u, 0u);
        prs[12] = static_cast<std::uint8_t>(sig & 0xFFu);
        prs[13] = static_cast<std::uint8_t>((sig >> 8u) & 0xFFu);
        write_u32_le_at(prs, 32u, tid);
        // x86_64 user_regs_struct @ +112:
        // [4]=RBP, [10]=RAX, [16]=RIP, [18]=EFLAGS, [19]=RSP, [21]=FS_BASE
        const std::size_t reg = 112u;
        write_u64_le_at(prs, reg + 4u * 8u, rbp);
        write_u64_le_at(prs, reg + 10u * 8u, rax);
        write_u64_le_at(prs, reg + 16u * 8u, rip);
        write_u64_le_at(prs, reg + 18u * 8u, 0x10206ULL);
        write_u64_le_at(prs, reg + 19u * 8u, rsp);
        write_u64_le_at(prs, reg + 21u * 8u, 0x00007F0000000800ULL);
        return prs;
    };
    const auto prs1 = make_prstatus_x64(9001u, 0u, kCodeVa + 0x100u, kRsp + 0x400u, kRbp + 0x400u, 0x1ULL);
    const auto prs2 = make_prstatus_x64(9002u, 11u /*SIGSEGV*/, kFaultRip, kRsp, kRbp, 0xABCDEF0123456789ULL);
    append_elf_note_le(notes, "CORE", 1u /*NT_PRSTATUS*/, prs1);
    append_elf_note_le(notes, "CORE", 1u /*NT_PRSTATUS*/, prs2);

    // 3. NT_AUXV (AT_PHDR=3, AT_ENTRY=9, AT_NULL=0)
    std::vector<std::uint8_t> auxv;
    append_u64_le(auxv, 3ULL);  append_u64_le(auxv, kCodeVa + 64ULL);
    append_u64_le(auxv, 9ULL);  append_u64_le(auxv, kCodeVa + 0x100ULL);
    append_u64_le(auxv, 0ULL);  append_u64_le(auxv, 0ULL);
    append_elf_note_le(notes, "CORE", 6u /*NT_AUXV*/, auxv);

    // 4. NT_FILE (2 entries: /usr/bin/demo_core & /lib/x86_64-linux-gnu/libc.so.6)
    std::vector<std::uint8_t> nt_file;
    append_u64_le(nt_file, 2ULL);      // count
    append_u64_le(nt_file, 4096ULL);   // page_size
    // Entry 0
    append_u64_le(nt_file, kCodeVa);
    append_u64_le(nt_file, kCodeVa + 0x1000ULL);
    append_u64_le(nt_file, 0ULL);
    // Entry 1
    append_u64_le(nt_file, 0x00007F0000100000ULL);
    append_u64_le(nt_file, 0x00007F0000280000ULL);
    append_u64_le(nt_file, 0ULL);
    const std::string_view f0 = "/usr/bin/demo_core";
    const std::string_view f1 = "/lib/x86_64-linux-gnu/libc.so.6";
    nt_file.insert(nt_file.end(), f0.begin(), f0.end()); nt_file.push_back(0u);
    nt_file.insert(nt_file.end(), f1.begin(), f1.end()); nt_file.push_back(0u);
    append_elf_note_le(notes, "CORE", 0x46494C45u /*NT_FILE*/, nt_file);

    // 5. NT_SIGINFO (128 bytes: SIGSEGV=11, si_code=1, si_addr at +16 on 64-bit)
    std::vector<std::uint8_t> siginfo(128u, 0u);
    write_u32_le_at(siginfo, 0u, 11u); // SIGSEGV
    write_u32_le_at(siginfo, 8u, 1u);  // SEGV_MAPERR
    write_u64_le_at(siginfo, 16u, 0x00000000BAD00008ULL);
    append_elf_note_le(notes, "CORE", 0x53494749u /*NT_SIGINFO*/, siginfo);

    // Prepare PT_LOAD payloads
    std::vector<std::uint8_t> code_seg(0x300u, 0x90u);
    // Put x86_64 instructions at kFaultRip (offset 0x120) and kRetVa (offset 0x180)
    code_seg[0x120u] = 0x48u;
    code_seg[0x121u] = 0x8Bu;
    code_seg[0x122u] = 0x00u; // mov rax, [rax]
    code_seg[0x180u] = 0xC3u; // ret

    std::vector<std::uint8_t> stack_seg(0x300u, 0u);
    write_u64_le_at(stack_seg, static_cast<std::size_t>(kRbp - kStackVa), kOuterRbp);
    write_u64_le_at(stack_seg, static_cast<std::size_t>(kRbp - kStackVa + 8u), kRetVa);
    write_u64_le_at(stack_seg, static_cast<std::size_t>(kOuterRbp - kStackVa), 0u);

    std::vector<std::uint8_t> rwx_seg(0x40u, 0xCCu);

    // Assemble ELF64 header (64 bytes) + 4 program headers (4 * 56 = 224 bytes)
    constexpr std::uint16_t kPhNum = 4u; // PT_NOTE + 3 PT_LOAD (RX code, RW stack, RWX jit)
    const std::size_t ph_off = 64u;
    const std::size_t note_off = ph_off + kPhNum * 56u;
    const std::size_t code_off = note_off + notes.size();
    const std::size_t stack_off = code_off + code_seg.size();
    const std::size_t rwx_off = stack_off + stack_seg.size();

    std::vector<std::uint8_t> elf;
    elf.reserve(rwx_off + rwx_seg.size());

    // e_ident (16 bytes)
    elf.insert(elf.end(), {0x7Fu, 'E', 'L', 'F', 2u /*ELFCLASS64*/, 1u /*ELFDATA2LSB*/, 1u, 0u,
                           0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u});
    append_u16_le(elf, 4u);    // e_type = ET_CORE
    append_u16_le(elf, 62u);   // e_machine = EM_X86_64
    append_u32_le(elf, 1u);    // e_version
    append_u64_le(elf, 0u);    // e_entry
    append_u64_le(elf, ph_off);// e_phoff
    append_u64_le(elf, 0u);    // e_shoff
    append_u32_le(elf, 0u);    // e_flags
    append_u16_le(elf, 64u);   // e_ehsize
    append_u16_le(elf, 56u);   // e_phentsize
    append_u16_le(elf, kPhNum);// e_phnum
    append_u16_le(elf, 64u);   // e_shentsize
    append_u16_le(elf, 0u);    // e_shnum
    append_u16_le(elf, 0u);    // e_shstrndx

    auto append_phdr64 = [&](std::uint32_t p_type, std::uint32_t p_flags, std::uint64_t p_offset,
                             std::uint64_t p_vaddr, std::uint64_t p_filesz, std::uint64_t p_memsz) {
        append_u32_le(elf, p_type);
        append_u32_le(elf, p_flags);
        append_u64_le(elf, p_offset);
        append_u64_le(elf, p_vaddr);
        append_u64_le(elf, 0u);
        append_u64_le(elf, p_filesz);
        append_u64_le(elf, p_memsz);
        append_u64_le(elf, 0x1000u);
    };

    append_phdr64(4u /*PT_NOTE*/, 4u, note_off, 0u, notes.size(), notes.size());
    append_phdr64(1u /*PT_LOAD*/, 5u /*PF_R|PF_X*/, code_off, kCodeVa, code_seg.size(), 0x1000u);
    append_phdr64(1u /*PT_LOAD*/, 6u /*PF_R|PF_W*/, stack_off, kStackVa, stack_seg.size(), 0x1000u);
    append_phdr64(1u /*PT_LOAD*/, 7u /*PF_R|PF_W|PF_X*/, rwx_off, kRwxVa, rwx_seg.size(), 0x1000u);

    elf.insert(elf.end(), notes.begin(), notes.end());
    elf.insert(elf.end(), code_seg.begin(), code_seg.end());
    elf.insert(elf.end(), stack_seg.begin(), stack_seg.end());
    elf.insert(elf.end(), rwx_seg.begin(), rwx_seg.end());
    return elf;
}

std::vector<std::uint8_t> build_synthetic_elf32_be_ppc_core() {
    std::vector<std::uint8_t> notes;
    auto append_note_be = [&](std::string_view name, std::uint32_t ntype,
                              std::span<const std::uint8_t> desc) {
        append_u32_be(notes, static_cast<std::uint32_t>(name.size() + 1u));
        append_u32_be(notes, static_cast<std::uint32_t>(desc.size()));
        append_u32_be(notes, ntype);
        for (char c : name) notes.push_back(static_cast<std::uint8_t>(c));
        notes.push_back(0u);
        while ((notes.size() % 4u) != 0u) notes.push_back(0u);
        notes.insert(notes.end(), desc.begin(), desc.end());
        while ((notes.size() % 4u) != 0u) notes.push_back(0u);
    };

    // 32-bit NT_PRPSINFO (124 bytes on PPC32)
    std::vector<std::uint8_t> prps(124u, 0u);
    write_u32_be_at(prps, 12u, 5150u); // 124 - 112 = 12
    write_u32_be_at(prps, 16u, 1u);
    std::memcpy(prps.data() + 28u, "ppc_firmware", 12u);
    append_note_be("CORE", 3u /*NT_PRPSINFO*/, prps);

    // 32-bit NT_PRSTATUS (72-byte header + 48 * 4-byte PPC pt_regs = 264 bytes)
    std::vector<std::uint8_t> prs(264u, 0u);
    prs[12] = 0u;
    prs[13] = 5u; // SIGTRAP (big-endian u16 = 5)
    write_u32_be_at(prs, 24u, 5150u); // pr_pid
    const std::size_t reg = 72u;
    write_u32_be_at(prs, reg + 1u * 4u, 0x7FFF0100u);  // R1 (SP)
    write_u32_be_at(prs, reg + 31u * 4u, 0x7FFF0120u); // R31 (FP)
    write_u32_be_at(prs, reg + 32u * 4u, 0x10000100u); // NIP (PC)
    write_u32_be_at(prs, reg + 36u * 4u, 0x10000080u); // LR
    append_note_be("CORE", 1u /*NT_PRSTATUS*/, prs);

    // Code segment (big-endian PowerPC `trap` = 0x7FE00008 at 0x10000100)
    std::vector<std::uint8_t> code_seg(0x120u, 0u);
    write_u32_be_at(code_seg, 0x100u, 0x7FE00008u);

    const std::size_t ph_off = 52u;
    const std::size_t note_off = ph_off + 2u * 32u;
    const std::size_t code_off = note_off + notes.size();

    std::vector<std::uint8_t> elf;
    elf.insert(elf.end(), {0x7Fu, 'E', 'L', 'F', 1u /*ELFCLASS32*/, 2u /*ELFDATA2MSB*/, 1u, 0u,
                           0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u});
    append_u16_be(elf, 4u);   // ET_CORE
    append_u16_be(elf, 20u);  // EM_PPC
    append_u32_be(elf, 1u);
    append_u32_be(elf, 0u);
    append_u32_be(elf, static_cast<std::uint32_t>(ph_off));
    append_u32_be(elf, 0u);
    append_u32_be(elf, 0u);
    append_u16_be(elf, 52u);
    append_u16_be(elf, 32u);
    append_u16_be(elf, 2u);
    append_u16_be(elf, 40u);
    append_u16_be(elf, 0u);
    append_u16_be(elf, 0u);

    auto append_phdr32_be = [&](std::uint32_t p_type, std::uint32_t p_offset, std::uint32_t p_vaddr,
                                std::uint32_t p_filesz, std::uint32_t p_memsz, std::uint32_t p_flags) {
        append_u32_be(elf, p_type);
        append_u32_be(elf, p_offset);
        append_u32_be(elf, p_vaddr);
        append_u32_be(elf, 0u);
        append_u32_be(elf, p_filesz);
        append_u32_be(elf, p_memsz);
        append_u32_be(elf, p_flags);
        append_u32_be(elf, 0x1000u);
    };

    append_phdr32_be(4u /*PT_NOTE*/, static_cast<std::uint32_t>(note_off), 0u,
                     static_cast<std::uint32_t>(notes.size()), static_cast<std::uint32_t>(notes.size()), 4u);
    append_phdr32_be(1u /*PT_LOAD*/, static_cast<std::uint32_t>(code_off), 0x10000000u,
                     static_cast<std::uint32_t>(code_seg.size()), 0x1000u, 5u /*PF_R|PF_X*/);

    elf.insert(elf.end(), notes.begin(), notes.end());
    elf.insert(elf.end(), code_seg.begin(), code_seg.end());
    return elf;
}

class ScopedTempDumpFile {
public:
    ScopedTempDumpFile(std::string_view filename, const std::vector<std::uint8_t>& bytes) {
        path_ = std::filesystem::temp_directory_path() / filename;
        std::ofstream ofs(path_, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    ScopedTempDumpFile(const ScopedTempDumpFile&) = delete;
    ScopedTempDumpFile& operator=(const ScopedTempDumpFile&) = delete;
    ScopedTempDumpFile(ScopedTempDumpFile&&) = delete;
    ScopedTempDumpFile& operator=(ScopedTempDumpFile&&) = delete;
    ~ScopedTempDumpFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_{};
};

} // namespace

TEST(CrashDumpTest, ParsesAmd64WindowsMinidumpStreamsStackAndHandles) {
    const std::vector<std::uint8_t> dmp = build_synthetic_amd64_minidump();
    EXPECT_TRUE(peelf::is_windows_minidump(dmp));
    EXPECT_TRUE(peelf::is_crash_dump_bytes(dmp));
    EXPECT_FALSE(peelf::is_elf_core_dump(dmp));

    auto opened = peelf::open_crash_dump_bytes(dmp, "crash_demo.dmp");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::ICrashDumpSession& sess = **opened;

    EXPECT_TRUE(sess.is_read_only());
    EXPECT_TRUE(sess.is_crash_dump());
    EXPECT_TRUE(sess.is_alive());
    EXPECT_TRUE(sess.is_suspended());
    EXPECT_EQ(sess.pid(), 4242u);

    const peelf::CrashDumpSummary& cs = sess.crash_summary();
    EXPECT_EQ(cs.kind, peelf::CrashDumpKind::WindowsMinidump);
    EXPECT_EQ(cs.layout.architecture, peelf::Architecture::X86_64);
    EXPECT_EQ(cs.layout.address_width, peelf::AddressWidth::Bits64);
    ASSERT_TRUE(cs.exception.has_value());
    EXPECT_EQ(cs.exception->thread_id, 7777u);
    EXPECT_EQ(cs.exception->fault_code, 0xC0000005u);
    EXPECT_EQ(cs.exception->fault_name, "EXCEPTION_ACCESS_VIOLATION");
    EXPECT_EQ(cs.exception->access_operation, "write");
    EXPECT_EQ(cs.exception->fault_address, 0x00000000DEAD0000ULL);
    EXPECT_EQ(cs.exception->instruction_pointer, 0x00007FF610000214ULL);

    const auto mods = sess.modules();
    ASSERT_TRUE(mods.has_value());
    ASSERT_EQ(mods->size(), 1u);
    EXPECT_EQ((*mods)[0].name, "crash_demo.exe");
    EXPECT_EQ((*mods)[0].base_address, 0x00007FF610000000ULL);

    const auto regs = sess.memory_regions();
    ASSERT_TRUE(regs.has_value());
    EXPECT_GE(regs->size(), 3u);
    const auto sum = sess.memory_summary(*regs);
    ASSERT_TRUE(sum.has_value());
    EXPECT_GT(sum.value->image_bytes, 0u);
    EXPECT_GT(sum.value->reserved_bytes, 0u);

    // Read MZ signature + crashing instruction from Memory64ListStream
    std::array<std::uint8_t, 2> mz{};
    const auto read_mz = sess.read_memory(0x00007FF610000000ULL, mz);
    ASSERT_TRUE(read_mz.has_value());
    EXPECT_EQ(mz[0], 'M');
    EXPECT_EQ(mz[1], 'Z');

    // Thread context + stack unwind highlighting return address & frame pointer
    const auto ths = sess.threads();
    ASSERT_TRUE(ths.has_value());
    ASSERT_EQ(ths->size(), 1u);
    EXPECT_EQ((*ths)[0].tid, 7777u);
    EXPECT_EQ((*ths)[0].tls_base, 0x0000009900050000ULL);

    const peelf::ThreadContext ctx = sess.thread_context(7777u);
    EXPECT_TRUE(ctx.status.has_data());
    EXPECT_EQ(ctx.instruction_pointer, 0x00007FF610000214ULL);
    EXPECT_EQ(ctx.stack_pointer, 0x000000990010F080ULL);
    EXPECT_EQ(ctx.frame_pointer, 0x000000990010F0A0ULL);

    const peelf::ThreadStackSnapshot stk = peelf::unwind_and_inspect_stack(
        sess, ctx, *regs, *mods, nullptr, {});
    EXPECT_GE(stk.frames.size(), 2u);
    bool saw_ret_highlight = false;
    bool saw_fp_highlight = false;
    for (const peelf::StackSlotEntry& slot : stk.slots) {
        if (slot.role == peelf::StackSlotRole::ReturnAddress &&
            slot.value == 0x00007FF610000240ULL) {
            saw_ret_highlight = true;
        }
        if (slot.role == peelf::StackSlotRole::SavedFramePointer ||
            slot.role == peelf::StackSlotRole::ActiveFramePointer) {
            saw_fp_highlight = true;
        }
    }
    EXPECT_TRUE(saw_ret_highlight);
    EXPECT_TRUE(saw_fp_highlight);

    // HandleDataStream surfaces through inspect_process_internals without probing host OS
    const peelf::ProcessInternalsSnapshot internals = peelf::inspect_process_internals(sess);
    ASSERT_TRUE(internals.handles.has_value());
    ASSERT_EQ(internals.handles.value->size(), 1u);
    EXPECT_EQ((*internals.handles.value)[0].type_name, "Event");
    EXPECT_NE((*internals.handles.value)[0].target.find("CrashReady"), std::string::npos);
}

TEST(CrashDumpTest, ParsesX86WindowsMinidump32BitStreams) {
    const std::vector<std::uint8_t> dmp = build_synthetic_x86_minidump();
    auto opened = peelf::open_minidump_bytes(dmp, "x86_div0.dmp");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;

    peelf::ICrashDumpSession& sess = **opened;
    EXPECT_EQ(sess.crash_summary().layout.architecture, peelf::Architecture::X86);
    EXPECT_EQ(sess.crash_summary().layout.address_width, peelf::AddressWidth::Bits32);
    ASSERT_TRUE(sess.crash_summary().exception.has_value());
    EXPECT_EQ(sess.crash_summary().exception->fault_name, "EXCEPTION_INT_DIVIDE_BY_ZERO");

    const peelf::ThreadContext ctx = sess.thread_context(1234u);
    EXPECT_EQ(ctx.instruction_pointer, 0x00401020ULL);
    EXPECT_EQ(ctx.stack_pointer, 0x0019FF00ULL);
    EXPECT_EQ(ctx.frame_pointer, 0x0019FF20ULL);

    std::array<std::uint8_t, 4> code{};
    const auto rd = sess.read_memory(0x00401020ULL, code);
    ASSERT_TRUE(rd.has_value());
    EXPECT_EQ(code[0], 0x55u);
    EXPECT_EQ(code[1], 0x89u);
}

TEST(CrashDumpTest, ParsesElf64CoreDumpNotesAuxvNtFileBinaryModelAndHeadlessJson) {
    const std::vector<std::uint8_t> core = build_synthetic_elf64_le_core();
    EXPECT_TRUE(peelf::is_elf_core_dump(core));
    EXPECT_TRUE(peelf::is_crash_dump_bytes(core));

    ScopedTempDumpFile tmp("synthetic_x64.core", core);

    // 1. Verify BinaryModel::load_file auto-detects ET_CORE before static ELF parser,
    // selects faulting TID 9002, and resolves auxv + stack unwind + LIVE3001 RWX finding!
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(tmp.path().string())) << model.last_diagnostic();
    EXPECT_TRUE(model.is_live_process());
    EXPECT_TRUE(model.is_crash_dump());
    EXPECT_TRUE(model.is_read_only());

    const peelf::CrashDumpSummary* cs = model.crash_dump_summary();
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->kind, peelf::CrashDumpKind::ElfCore);
    EXPECT_EQ(cs->pid, 9001u);
    EXPECT_EQ(cs->parent_pid, 1000u);
    EXPECT_EQ(cs->process_name, "demo_core");
    ASSERT_TRUE(cs->exception.has_value());
    EXPECT_EQ(cs->exception->thread_id, 9002u);
    EXPECT_EQ(cs->exception->fault_code, 11u);
    EXPECT_EQ(cs->exception->fault_name, "SIGSEGV");
    EXPECT_EQ(cs->exception->fault_address, 0x00000000BAD00008ULL);
    EXPECT_EQ(cs->exception->instruction_pointer, 0x0000000000400120ULL);

    // Faulting thread 9002 must be auto-selected over worker thread 9001
    ASSERT_TRUE(model.selected_thread_id().has_value());
    EXPECT_EQ(*model.selected_thread_id(), 9002u);
    EXPECT_GE(model.selected_thread_stack().frames.size(), 2u);

    // NT_FILE produced module entries
    EXPECT_GE(model.process_modules().size(), 2u);

    // NT_AUXV decoded in ProcessEnvironmentSnapshot
    EXPECT_FALSE(model.process_environment().auxv_entries.empty());

    // LIVE3001 detects the RWX PT_LOAD segment in the core dump
    bool saw_live3001 = false;
    for (const peelf::SecurityFinding& f : model.security_audit().findings) {
        if (f.rule_id == "LIVE3001" &&
            (f.severity == peelf::SecuritySeverity::Warning ||
             f.severity == peelf::SecuritySeverity::Error)) {
            saw_live3001 = true;
            break;
        }
    }
    EXPECT_TRUE(saw_live3001);

    // 2. Verify `--headless <dump.core>` JSON & SARIF CLI execution
    std::ostringstream out_json;
    std::ostringstream err_json;
    const std::string path_arg = tmp.path().string();
    const std::array<std::string_view, 3> cli_args = {
        "--headless", path_arg, "--fail-on=warning"
    };
    const auto rc = peelf::try_run_headless_or_help_cli(cli_args, out_json, err_json);
    ASSERT_TRUE(rc.has_value());
    EXPECT_EQ(*rc, 2); // LIVE3001 RWX warning triggers policy gate 2!
    const std::string json = out_json.str();
    EXPECT_NE(json.find("\"kind\": \"CrashDump\""), std::string::npos);
    EXPECT_NE(json.find("\"crash_dump\":"), std::string::npos);
    EXPECT_NE(json.find("\"SIGSEGV\""), std::string::npos);
    EXPECT_NE(json.find("\"demo_core\""), std::string::npos);
    EXPECT_NE(json.find("\"LIVE3001\""), std::string::npos);
}

TEST(CrashDumpTest, ParsesBigEndianElf32PowerPcCoreDump) {
    const std::vector<std::uint8_t> core = build_synthetic_elf32_be_ppc_core();
    EXPECT_TRUE(peelf::is_elf_core_dump(core));

    auto opened = peelf::open_elf_core_bytes(core, "ppc32_be.core");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;

    peelf::ICrashDumpSession& sess = **opened;
    const peelf::CrashDumpSummary& cs = sess.crash_summary();
    EXPECT_EQ(cs.layout.architecture, peelf::Architecture::PowerPC);
    EXPECT_EQ(cs.layout.endianness, peelf::Endianness::Big);
    EXPECT_EQ(cs.layout.address_width, peelf::AddressWidth::Bits32);
    EXPECT_EQ(cs.pid, 5150u);
    EXPECT_EQ(cs.process_name, "ppc_firmware");
    ASSERT_TRUE(cs.exception.has_value());
    EXPECT_EQ(cs.exception->fault_name, "SIGTRAP");
    EXPECT_EQ(cs.exception->instruction_pointer, 0x10000100ULL);

    const peelf::ThreadContext ctx = sess.thread_context(5150u);
    EXPECT_EQ(ctx.layout.endianness, peelf::Endianness::Big);
    EXPECT_EQ(ctx.instruction_pointer, 0x10000100ULL);
    EXPECT_EQ(ctx.stack_pointer, 0x7FFF0100ULL);
    EXPECT_EQ(ctx.link_register, 0x10000080ULL);

    std::array<std::uint8_t, 4> insn{};
    const auto rd = sess.read_memory(0x10000100ULL, insn);
    ASSERT_TRUE(rd.has_value());
    EXPECT_EQ(insn[0], 0x7Fu);
    EXPECT_EQ(insn[1], 0xE0u);
    EXPECT_EQ(insn[2], 0x00u);
    EXPECT_EQ(insn[3], 0x08u);
}

TEST(CrashDumpTest, RejectsOverflowing64BitElfCoreNoteAlignmentAndMarksTruncatedMinidumpPartial) {
    // 1. ELF64 core dump with `namesz = 0xFFFF'FFFE` (which wraps 32-bit `align4` to 0!)
    //    plus overflowing `PT_LOAD` (`vaddr + memsz`) and `NT_FILE` (`page_offset * page_size`).
    {
        std::vector<std::uint8_t> notes;
        // Crafted overflowing note header: namesz = 0xFFFF'FFFE, descsz = 0, type = NT_PRPSINFO (3)
        append_u32_le(notes, 0xFFFF'FFFEu);
        append_u32_le(notes, 0u);
        append_u32_le(notes, 3u);
        // Trailing decoy NT_PRPSINFO note that MUST NOT be parsed after the overflowing note!
        std::vector<std::uint8_t> decoy_prps(136u, 0u);
        write_u32_le_at(decoy_prps, 24u, 4242u);
        std::memcpy(decoy_prps.data() + 40u, "decoy_proc", 10u);
        append_u32_le(notes, 5u);
        append_u32_le(notes, static_cast<std::uint32_t>(decoy_prps.size()));
        append_u32_le(notes, 3u);
        notes.insert(notes.end(), {'C', 'O', 'R', 'E', 0u, 0u, 0u, 0u});
        notes.insert(notes.end(), decoy_prps.begin(), decoy_prps.end());

        // Second PT_NOTE segment with overflowing NT_FILE `page_offset * page_size`
        std::vector<std::uint8_t> notes2;
        std::vector<std::uint8_t> bad_nt_file;
        append_u64_le(bad_nt_file, 1ULL);                        // count = 1
        append_u64_le(bad_nt_file, 4096ULL);                     // page_size = 4096
        append_u64_le(bad_nt_file, 0x400000ULL);                 // start
        append_u64_le(bad_nt_file, 0x401000ULL);                 // end
        append_u64_le(bad_nt_file, 0xFFFF'FFFF'FFFF'FFFFULL);    // page_offset * 4096 overflows!
        const std::string_view bad_path = "/usr/bin/overflow_map";
        bad_nt_file.insert(bad_nt_file.end(), bad_path.begin(), bad_path.end());
        bad_nt_file.push_back(0u);
        append_u32_le(notes2, 5u);
        append_u32_le(notes2, static_cast<std::uint32_t>(bad_nt_file.size()));
        append_u32_le(notes2, 0x46494C45u /*NT_FILE*/);
        notes2.insert(notes2.end(), {'C', 'O', 'R', 'E', 0u, 0u, 0u, 0u});
        notes2.insert(notes2.end(), bad_nt_file.begin(), bad_nt_file.end());
        while ((notes2.size() % 4u) != 0u) {
            notes2.push_back(0u);
        }

        const std::vector<std::uint8_t> valid_seg(0x40u, 0x90u);

        auto build_core_image = [&](const std::vector<std::uint8_t>& first_note_seg,
                                    std::uint64_t pt_load_vaddr) {
            constexpr std::uint16_t kPhNum = 3u;
            const std::size_t ph_off = 64u;
            const std::size_t note1_off = ph_off + kPhNum * 56u;
            const std::size_t note2_off = note1_off + first_note_seg.size();
            const std::size_t seg_off = note2_off + notes2.size();

            std::vector<std::uint8_t> core;
            core.insert(core.end(), {0x7Fu, 'E', 'L', 'F', 2u, 1u, 1u, 0u,
                                     0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u});
            append_u16_le(core, 4u);  // ET_CORE
            append_u16_le(core, 62u); // EM_X86_64
            append_u32_le(core, 1u);
            append_u64_le(core, 0u);
            append_u64_le(core, ph_off);
            append_u64_le(core, 0u);
            append_u32_le(core, 0u);
            append_u16_le(core, 64u);
            append_u16_le(core, 56u);
            append_u16_le(core, kPhNum);
            append_u16_le(core, 64u);
            append_u16_le(core, 0u);
            append_u16_le(core, 0u);

            auto push_ph = [&](std::uint32_t p_type, std::uint64_t off,
                               std::uint64_t vaddr, std::uint64_t filesz, std::uint64_t memsz) {
                append_u32_le(core, p_type);
                append_u32_le(core, 5u);
                append_u64_le(core, off);
                append_u64_le(core, vaddr);
                append_u64_le(core, 0u);
                append_u64_le(core, filesz);
                append_u64_le(core, memsz);
                append_u64_le(core, 0x1000u);
            };
            push_ph(4u /*PT_NOTE*/, note1_off, 0u, first_note_seg.size(), first_note_seg.size());
            push_ph(4u /*PT_NOTE*/, note2_off, 0u, notes2.size(), notes2.size());
            push_ph(1u /*PT_LOAD*/, seg_off, pt_load_vaddr, valid_seg.size(), 0x1000ULL);

            core.insert(core.end(), first_note_seg.begin(), first_note_seg.end());
            core.insert(core.end(), notes2.begin(), notes2.end());
            core.insert(core.end(), valid_seg.begin(), valid_seg.end());
            return core;
        };

        // 1a. 0xFFFF'FFFE PT_NOTE namesz alignment overflow MUST be rejected cleanly
        //     without wrapping 32-bit `align4` to 0 or misparsing the trailing decoy note!
        const auto overflow_note_core = build_core_image(notes, 0x400000ULL);
        const auto overflow_note_res =
            peelf::open_elf_core_bytes(overflow_note_core, "overflow_note.core");
        ASSERT_FALSE(overflow_note_res.has_value());
        EXPECT_NE(overflow_note_res.error().message.find("0xFFFFFFFE"), std::string::npos);

        // 1b. Overflowing PT_LOAD (vaddr + memsz wraps 64-bit) MUST be rejected cleanly!
        const auto bad_load_core = build_core_image(notes2, 0xFFFF'FFFF'FFFF'F800ULL);
        const auto bad_opened = peelf::open_elf_core_bytes(bad_load_core, "overflow_ptload.core");
        ASSERT_FALSE(bad_opened.has_value());

        // 1c. Overflowing NT_FILE (page_ofs * page_size wraps 64-bit) degrades status to Partial:
        const auto nt_file_core = build_core_image(notes2, 0x400000ULL);
        auto opened = peelf::open_elf_core_bytes(nt_file_core, "overflow_ntfile.core");
        ASSERT_TRUE(opened.has_value()) << opened.error().message;
        peelf::ICrashDumpSession& sess = **opened;
        EXPECT_EQ(sess.crash_summary().status.availability, peelf::Availability::Partial);
        EXPECT_FALSE(sess.crash_summary().diagnostics.empty());
        EXPECT_EQ(sess.modules_status().availability, peelf::Availability::Partial);

        const auto regs = sess.memory_regions();
        ASSERT_TRUE(regs.has_value());
        ASSERT_EQ(regs->size(), 1u);
        EXPECT_EQ((*regs)[0].start_address, 0x400000ULL);
    }

    // 2. Minidump with truncated `ModuleListStream` (claims 3 modules, supplies bytes for 2 where
    //    entry 0 overflows `base + size` and entry 1 is valid) -> degrades to `Partial`!
    {
        std::vector<std::uint8_t> dmp(32u + 2u * 12u, 0u); // 32-byte header + 2 directory entries
        std::memcpy(dmp.data(), "MDMP", 4u);
        dmp[4] = 0x93u;
        dmp[5] = 0xA7u;
        write_u32_le_at(dmp, 8u, 2u);   // NumberOfStreams = 2
        write_u32_le_at(dmp, 12u, 32u); // StreamDirectoryRva = 32

        // Stream 0: SystemInfoStream (type = 7, 56 bytes)
        const auto sys_rva = static_cast<std::uint32_t>(dmp.size());
        dmp.resize(sys_rva + 56u, 0u);
        dmp[sys_rva + 0u] = 9u; // PROCESSOR_ARCHITECTURE_AMD64

        // Module name strings
        const std::uint32_t bad_name_rva = append_minidump_utf16_string(dmp, "C:\\wrap.dll");
        const std::uint32_t ok_name_rva = append_minidump_utf16_string(dmp, "C:\\valid.exe");

        // Stream 1: ModuleListStream (type = 4): claims 3 modules, only stores 2 * 108 bytes!
        const auto mod_rva = static_cast<std::uint32_t>(dmp.size());
        append_u32_le(dmp, 3u); // NumberOfModules = 3 (truncated before 3rd entry!)
        const std::size_t m0 = dmp.size();
        dmp.resize(m0 + 2u * 108u, 0u);
        // Entry 0: BaseOfImage + SizeOfImage wraps 64-bit!
        write_u64_le_at(dmp, m0 + 0u, 0xFFFF'FFFF'FFFF'F000ULL);
        write_u32_le_at(dmp, m0 + 8u, 0x2000u);
        write_u32_le_at(dmp, m0 + 20u, bad_name_rva);
        // Entry 1: valid module
        const std::size_t m1 = m0 + 108u;
        write_u64_le_at(dmp, m1 + 0u, 0x00007FF610000000ULL);
        write_u32_le_at(dmp, m1 + 8u, 0x4000u);
        write_u32_le_at(dmp, m1 + 20u, ok_name_rva);
        const auto mod_stream_sz = static_cast<std::uint32_t>(dmp.size() - mod_rva);

        // Populate directory entries at offset 32
        write_u32_le_at(dmp, 32u + 0u, 7u);
        write_u32_le_at(dmp, 32u + 4u, 56u);
        write_u32_le_at(dmp, 32u + 8u, sys_rva);

        write_u32_le_at(dmp, 44u + 0u, 4u);
        write_u32_le_at(dmp, 44u + 4u, mod_stream_sz);
        write_u32_le_at(dmp, 44u + 8u, mod_rva);

        auto opened = peelf::open_minidump_bytes(dmp, "truncated_mods.dmp");
        ASSERT_TRUE(opened.has_value()) << opened.error().message;
        peelf::ICrashDumpSession& sess = **opened;

        const auto mods = sess.modules();
        ASSERT_TRUE(mods.has_value());
        ASSERT_EQ(mods->size(), 1u);
        EXPECT_EQ((*mods)[0].name, "valid.exe");
        EXPECT_EQ(sess.modules_status().availability, peelf::Availability::Partial);
        EXPECT_EQ(sess.crash_summary().status.availability, peelf::Availability::Partial);
        EXPECT_FALSE(sess.crash_summary().diagnostics.empty());

        const peelf::ProcessStateSnapshot snap = peelf::capture_process_snapshot(sess);
        EXPECT_EQ(snap.modules.availability, peelf::CaptureAvailability::Partial);
        EXPECT_EQ(snap.snapshot_stamp.availability, peelf::CaptureAvailability::Partial);
    }
}

