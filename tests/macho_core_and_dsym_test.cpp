#include <gtest/gtest.h>

#include "model/binary_model.hpp"
#include "symbols/debug_symbols.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/dwarf.hpp>
#include <peelf/macho_image.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/stack_tls.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

void append_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

void append_u16_le(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (unsigned i = 0u; i < 4u; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu));
    }
}

void append_u64_le(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (unsigned i = 0u; i < 8u; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu));
    }
}

void append_u32_be(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        buf.push_back(static_cast<std::uint8_t>((v >> static_cast<unsigned>(shift)) & 0xFFu));
    }
}

void write_u32_le_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    for (unsigned i = 0u; i < 4u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void write_u64_le_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    for (unsigned i = 0u; i < 8u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void append_fixed_str16(std::vector<std::uint8_t>& buf, std::string_view s) {
    for (std::size_t i = 0u; i < 16u; ++i) {
        buf.push_back(i < s.size() ? static_cast<std::uint8_t>(s[i]) : 0u);
    }
}

void append_cstr(std::vector<std::uint8_t>& buf, std::string_view s) {
    buf.insert(buf.end(), s.begin(), s.end());
    buf.push_back(0u);
}

class ScopedTempDir {
public:
    explicit ScopedTempDir(std::string_view prefix) {
        static std::atomic<std::uint64_t> counter{0u};
        const std::uint64_t id = counter.fetch_add(1u) + 1u;
#ifdef _WIN32
        const std::filesystem::path root = std::filesystem::temp_directory_path();
#else
        const std::filesystem::path root("/tmp");
#endif
        dir_ = root / std::format("{}_{}", prefix, id);
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
        std::filesystem::create_directories(dir_, ec);
    }

    ~ScopedTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;
    ScopedTempDir(ScopedTempDir&&) = delete;
    ScopedTempDir& operator=(ScopedTempDir&&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return dir_; }

private:
    std::filesystem::path dir_;
};

void write_binary_file(const std::filesystem::path& p, std::span<const std::uint8_t> bytes) {
    std::error_code ec;
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path(), ec);
    }
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.good()) << p.string();
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(out.good()) << p.string();
}

// Synthesize a minimal mapped 64-bit Mach-O `MH_EXECUTE` image (1 page = 0x1000 bytes)
// with `__TEXT,__text` instructions and `LC_MAIN`.
std::vector<std::uint8_t> make_mapped_macho64_execute(std::uint32_t cputype,
                                                      std::uint64_t base_va) {
    std::vector<std::uint8_t> img(0x1000u, 0u);
    std::vector<std::uint8_t> hdr;
    hdr.reserve(256u);

    // mach_header_64 (32 bytes, little-endian magic 0xFEEDFACF)
    append_u32_le(hdr, peelf::macho::kMhMagic64);
    append_u32_le(hdr, cputype);
    append_u32_le(hdr, 0u); // cpusubtype
    append_u32_le(hdr, peelf::macho::kMhExecute);
    append_u32_le(hdr, 2u); // ncmds: LC_SEGMENT_64(__TEXT) + LC_MAIN
    append_u32_le(hdr, 152u + 24u); // sizeofcmds = 176
    append_u32_le(hdr, peelf::macho::kMhPie | peelf::macho::kMhTwoLevel);
    append_u32_le(hdr, 0u); // reserved

    // LC_SEGMENT_64 "__TEXT" (72 bytes) + 1 section_64 "__text" (80 bytes) = 152 bytes
    append_u32_le(hdr, peelf::macho::kLcSegment64);
    append_u32_le(hdr, 152u);
    append_fixed_str16(hdr, "__TEXT");
    append_u64_le(hdr, base_va); // vmaddr
    append_u64_le(hdr, 0x1000u); // vmsize
    append_u64_le(hdr, 0u);      // fileoff
    append_u64_le(hdr, 0x1000u); // filesize
    append_u32_le(hdr, 5u);      // maxprot = R|X
    append_u32_le(hdr, 5u);      // initprot = R|X
    append_u32_le(hdr, 1u);      // nsects = 1
    append_u32_le(hdr, 0u);      // flags

    // section_64 "__text" at RVA 0x200, size 0x100
    append_fixed_str16(hdr, "__text");
    append_fixed_str16(hdr, "__TEXT");
    append_u64_le(hdr, base_va + 0x200u); // addr
    append_u64_le(hdr, 0x100u);           // size
    append_u32_le(hdr, 0x200u);           // offset
    append_u32_le(hdr, 4u);               // align
    append_u32_le(hdr, 0u);               // reloff
    append_u32_le(hdr, 0u);               // nreloc
    append_u32_le(hdr, peelf::macho::kSAttrPureInstructions | peelf::macho::kSAttrSomeInstructions);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);

    // LC_MAIN (24 bytes)
    append_u32_le(hdr, peelf::macho::kLcMain);
    append_u32_le(hdr, 24u);
    append_u64_le(hdr, 0x200u); // entryoff
    append_u64_le(hdr, 0u);     // stacksize

    std::copy(hdr.begin(), hdr.end(), img.begin());

    if (cputype == peelf::macho::kCpuTypeX86_64) {
        // x86_64 prologue + faulting store @ +0x204 + caller ret @ +0x240
        const std::array<std::uint8_t, 12> code{{
            0x55u, 0x48u, 0x89u, 0xE5u,                                     // push rbp; mov rbp, rsp
            0x48u, 0xC7u, 0x04u, 0x25u, 0x10u, 0x00u, 0xADu, 0x0Bu          // mov qword ptr [0xBAD0010], ...
        }};
        std::copy(code.begin(), code.end(), img.begin() + 0x200u);
        img[0x240u] = 0xC3u; // ret
    } else if (cputype == peelf::macho::kCpuTypeArm64) {
        // AArch64 instructions @ +0x200: stp x29, x30, [sp, #-16]!; str x0, [x1]; ret
        write_u32_le_at(img, 0x200u, 0xA9BF7BFDu);
        write_u32_le_at(img, 0x204u, 0xF9000020u);
        write_u32_le_at(img, 0x240u, 0xD65F03C0u);
    }
    return img;
}

// Synthesize a minimal mapped 64-bit Mach-O `MH_DYLIB` header with `LC_ID_DYLIB`.
std::vector<std::uint8_t> make_mapped_macho64_dylib(std::uint32_t cputype,
                                                    std::uint64_t base_va,
                                                    std::string_view install_name) {
    std::vector<std::uint8_t> img(0x1000u, 0u);
    std::vector<std::uint8_t> id_cmd;
    append_u32_le(id_cmd, peelf::macho::kLcIdDylib);
    append_u32_le(id_cmd, 0u); // patched below
    append_u32_le(id_cmd, 24u); // name offset
    append_u32_le(id_cmd, 0u);  // timestamp
    append_u32_le(id_cmd, 0x00010000u); // current_version
    append_u32_le(id_cmd, 0x00010000u); // compat_version
    append_cstr(id_cmd, install_name);
    while ((id_cmd.size() % 8u) != 0u) {
        id_cmd.push_back(0u);
    }
    write_u32_le_at(id_cmd, 4u, static_cast<std::uint32_t>(id_cmd.size()));

    std::vector<std::uint8_t> hdr;
    append_u32_le(hdr, peelf::macho::kMhMagic64);
    append_u32_le(hdr, cputype);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, peelf::macho::kMhDylib);
    append_u32_le(hdr, 2u); // LC_SEGMENT_64 + LC_ID_DYLIB
    append_u32_le(hdr, static_cast<std::uint32_t>(72u + id_cmd.size()));
    append_u32_le(hdr, peelf::macho::kMhTwoLevel);
    append_u32_le(hdr, 0u);

    append_u32_le(hdr, peelf::macho::kLcSegment64);
    append_u32_le(hdr, 72u);
    append_fixed_str16(hdr, "__TEXT");
    append_u64_le(hdr, base_va);
    append_u64_le(hdr, 0x1000u);
    append_u64_le(hdr, 0u);
    append_u64_le(hdr, 0x1000u);
    append_u32_le(hdr, 5u);
    append_u32_le(hdr, 5u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);

    hdr.insert(hdr.end(), id_cmd.begin(), id_cmd.end());
    std::copy(hdr.begin(), hdr.end(), img.begin());
    return img;
}

std::vector<std::uint8_t> build_synthetic_x86_64_macho_core() {
    constexpr std::uint64_t kExeBase   = 0x0000000100000000ULL;
    constexpr std::uint64_t kDylibBase = 0x00007FF812340000ULL;
    constexpr std::uint64_t kDataBase  = 0x0000000100010000ULL;
    constexpr std::uint64_t kRwxBase   = 0x0000000100020000ULL;
    constexpr std::uint64_t kStackBase = 0x00007FF7BFEEF000ULL;

    const std::vector<std::uint8_t> exe_img =
        make_mapped_macho64_execute(peelf::macho::kCpuTypeX86_64, kExeBase);
    const std::vector<std::uint8_t> dylib_img = make_mapped_macho64_dylib(
        peelf::macho::kCpuTypeX86_64, kDylibBase, "/usr/lib/libSystem.B.dylib");

    // Data segment: filesize = 0x40, vmsize = 0x1000 (tail [0x40, 0x1000) is zero-filled!)
    std::vector<std::uint8_t> data_payload(0x40u, 0u);
    const std::string_view marker = "MACHO_CORE_DATA_HEAD";
    std::memcpy(data_payload.data(), marker.data(), marker.size());

    // RWX JIT page to trigger LIVE3001 security finding during `--headless` inspection!
    std::vector<std::uint8_t> rwx_payload(0x100u, 0x90u);

    // Stack segment (0x1000 bytes) with valid x86_64 frame chain
    std::vector<std::uint8_t> stack_payload(0x1000u, 0u);
    constexpr std::uint64_t kRsp      = kStackBase + 0x800ULL;
    constexpr std::uint64_t kRbp      = kStackBase + 0x820ULL;
    constexpr std::uint64_t kOuterRbp = kStackBase + 0x860ULL;
    write_u64_le_at(stack_payload, 0x820u, kOuterRbp);           // saved rbp
    write_u64_le_at(stack_payload, 0x828u, kExeBase + 0x240ULL); // saved return IP

    // LC_UNIXTHREAD: x86_THREAD_STATE64 (flavor=4, count=42 -> 168B) +
    //                x86_EXCEPTION_STATE64 (flavor=6, count=4 -> 16B)
    // Total cmdsize = 8 + (8 + 168) + (8 + 16) = 208 bytes
    std::vector<std::uint8_t> thread_cmd;
    append_u32_le(thread_cmd, peelf::macho::kLcUnixThread);
    append_u32_le(thread_cmd, 208u);
    append_u32_le(thread_cmd, 4u);  // x86_THREAD_STATE64
    append_u32_le(thread_cmd, 42u); // 42 uint32s = 21 uint64s
    const std::array<std::uint64_t, 21> gprs{{
        0x1111222233334444ULL, // rax
        0x2222333344445555ULL, // rbx
        0x3333444455556666ULL, // rcx
        0x4444555566667777ULL, // rdx
        0x000000000BAD0010ULL, // rdi
        0x0000000100010000ULL, // rsi
        kRbp,                  // rbp
        kRsp,                  // rsp
        0x8888000000000008ULL, // r8
        0x9999000000000009ULL, // r9
        0xAAAA00000000000AULL, // r10
        0xBBBB00000000000BULL, // r11
        0xCCCC00000000000CULL, // r12
        0xDDDD00000000000DULL, // r13
        0xEEEE00000000000EULL, // r14
        0xFFFF00000000000FULL, // r15
        kExeBase + 0x204ULL,   // rip
        0x0000000000010246ULL, // rflags (ZF | PF | IF)
        0x2BULL,               // cs
        0x0ULL,                // fs
        0x0ULL,                // gs
    }};
    for (const std::uint64_t v : gprs) {
        append_u64_le(thread_cmd, v);
    }
    append_u32_le(thread_cmd, 6u); // x86_EXCEPTION_STATE64
    append_u32_le(thread_cmd, 4u); // 16 bytes
    append_u16_le(thread_cmd, 14u); // trapno = 14 (#PF Page Fault)
    append_u16_le(thread_cmd, 0u);  // cpu
    append_u32_le(thread_cmd, 0x06u); // err: user write page fault (bit 1 = write)
    append_u64_le(thread_cmd, 0x000000000BAD0010ULL); // faultvaddr

    // 5 LC_SEGMENT_64 (5 * 72 = 360) + 1 LC_UNIXTHREAD (208) = 568 bytes of load commands
    constexpr std::uint32_t kNumCmds = 6u;
    const auto sizeofcmds = static_cast<std::uint32_t>(5u * 72u + thread_cmd.size());
    std::size_t payload_cursor = 0x1000u; // page-aligned start of segment data

    const std::size_t exe_off   = payload_cursor; payload_cursor += exe_img.size();
    const std::size_t dylib_off = payload_cursor; payload_cursor += dylib_img.size();
    const std::size_t data_off  = payload_cursor; payload_cursor += data_payload.size();
    const std::size_t rwx_off   = payload_cursor; payload_cursor += rwx_payload.size();
    const std::size_t stack_off = payload_cursor; payload_cursor += stack_payload.size();

    std::vector<std::uint8_t> core;
    core.reserve(payload_cursor);

    append_u32_le(core, peelf::macho::kMhMagic64);
    append_u32_le(core, peelf::macho::kCpuTypeX86_64);
    append_u32_le(core, 3u); // CPU_SUBTYPE_X86_64_ALL
    append_u32_le(core, peelf::macho::kMhCore);
    append_u32_le(core, kNumCmds);
    append_u32_le(core, sizeofcmds);
    append_u32_le(core, 0u);
    append_u32_le(core, 0u);

    auto emit_seg64 = [&](std::string_view name,
                          std::uint64_t vmaddr,
                          std::uint64_t vmsize,
                          std::uint64_t fileoff,
                          std::uint64_t filesize,
                          std::uint32_t prot) {
        append_u32_le(core, peelf::macho::kLcSegment64);
        append_u32_le(core, 72u);
        append_fixed_str16(core, name);
        append_u64_le(core, vmaddr);
        append_u64_le(core, vmsize);
        append_u64_le(core, fileoff);
        append_u64_le(core, filesize);
        append_u32_le(core, prot);
        append_u32_le(core, prot);
        append_u32_le(core, 0u);
        append_u32_le(core, 0u);
    };

    emit_seg64("seg_exe",   kExeBase,   exe_img.size(),      exe_off,   exe_img.size(),      5u);
    emit_seg64("seg_dylib", kDylibBase, dylib_img.size(),    dylib_off, dylib_img.size(),    5u);
    emit_seg64("seg_data",  kDataBase,  0x1000u,             data_off,  data_payload.size(), 3u);
    emit_seg64("seg_rwx",   kRwxBase,   0x1000u,             rwx_off,   rwx_payload.size(),  7u);
    emit_seg64("seg_stack", kStackBase, stack_payload.size(), stack_off, stack_payload.size(), 3u);
    core.insert(core.end(), thread_cmd.begin(), thread_cmd.end());

    core.resize(0x1000u, 0u);
    core.insert(core.end(), exe_img.begin(), exe_img.end());
    core.insert(core.end(), dylib_img.begin(), dylib_img.end());
    core.insert(core.end(), data_payload.begin(), data_payload.end());
    core.insert(core.end(), rwx_payload.begin(), rwx_payload.end());
    core.insert(core.end(), stack_payload.begin(), stack_payload.end());
    return core;
}

std::vector<std::uint8_t> build_synthetic_arm64_macho_core() {
    constexpr std::uint64_t kExeBase   = 0x0000000102000000ULL;
    constexpr std::uint64_t kStackBase = 0x000000016FDEC000ULL;

    const std::vector<std::uint8_t> exe_img =
        make_mapped_macho64_execute(peelf::macho::kCpuTypeArm64, kExeBase);
    std::vector<std::uint8_t> stack_payload(0x1000u, 0u);
    constexpr std::uint64_t kSp = kStackBase + 0x900ULL;
    constexpr std::uint64_t kFp = kStackBase + 0x910ULL;
    write_u64_le_at(stack_payload, 0x910u, kStackBase + 0x950ULL);
    write_u64_le_at(stack_payload, 0x918u, kExeBase + 0x240ULL);

    // LC_THREAD: ARM_THREAD_STATE64 (flavor=6, count=68 -> 272B) +
    //            ARM_EXCEPTION_STATE64 (flavor=7, count=4 -> 16B)
    // Total cmdsize = 8 + (8 + 272) + (8 + 16) = 312 bytes
    std::vector<std::uint8_t> thread_cmd;
    append_u32_le(thread_cmd, peelf::macho::kLcThread);
    append_u32_le(thread_cmd, 312u);
    append_u32_le(thread_cmd, 6u);  // ARM_THREAD_STATE64
    append_u32_le(thread_cmd, 68u); // 272 bytes
    for (std::uint64_t i = 0u; i <= 28u; ++i) {
        append_u64_le(thread_cmd, 0xA6400000ULL + i); // x0..x28
    }
    append_u64_le(thread_cmd, kFp);                  // fp (x29)
    append_u64_le(thread_cmd, kExeBase + 0x240ULL);  // lr (x30)
    append_u64_le(thread_cmd, kSp);                  // sp
    append_u64_le(thread_cmd, kExeBase + 0x204ULL);  // pc
    append_u32_le(thread_cmd, 0x60000000u);          // cpsr (Z | C)
    append_u32_le(thread_cmd, 0u);                   // pad

    // ARM_EXCEPTION_STATE64: far, esr (EC=0x24 Data Abort lower EL, WnR=1 bit 6), exception=1
    constexpr std::uint32_t kEsr = (0x24u << 26u) | (1u << 6u) | 0x05u;
    append_u32_le(thread_cmd, 7u);
    append_u32_le(thread_cmd, 4u);
    append_u64_le(thread_cmd, 0x00000000DEAD4000ULL); // far
    append_u32_le(thread_cmd, kEsr);                  // esr
    append_u32_le(thread_cmd, 1u);                    // EXC_BAD_ACCESS

    const auto sizeofcmds = static_cast<std::uint32_t>(2u * 72u + thread_cmd.size());
    const std::size_t exe_off   = 0x1000u;
    const std::size_t stack_off = exe_off + exe_img.size();

    std::vector<std::uint8_t> core;
    append_u32_le(core, peelf::macho::kMhMagic64);
    append_u32_le(core, peelf::macho::kCpuTypeArm64);
    append_u32_le(core, 0u);
    append_u32_le(core, peelf::macho::kMhCore);
    append_u32_le(core, 3u);
    append_u32_le(core, sizeofcmds);
    append_u32_le(core, 0u);
    append_u32_le(core, 0u);

    auto emit_seg64 = [&](std::string_view name,
                          std::uint64_t vmaddr,
                          std::uint64_t vmsize,
                          std::uint64_t fileoff,
                          std::uint32_t prot) {
        append_u32_le(core, peelf::macho::kLcSegment64);
        append_u32_le(core, 72u);
        append_fixed_str16(core, name);
        append_u64_le(core, vmaddr);
        append_u64_le(core, vmsize);
        append_u64_le(core, fileoff);
        append_u64_le(core, vmsize);
        append_u32_le(core, prot);
        append_u32_le(core, prot);
        append_u32_le(core, 0u);
        append_u32_le(core, 0u);
    };
    emit_seg64("seg_exe",   kExeBase,   exe_img.size(),       exe_off,   5u);
    emit_seg64("seg_stack", kStackBase, stack_payload.size(), stack_off, 3u);
    core.insert(core.end(), thread_cmd.begin(), thread_cmd.end());

    core.resize(0x1000u, 0u);
    core.insert(core.end(), exe_img.begin(), exe_img.end());
    core.insert(core.end(), stack_payload.begin(), stack_payload.end());
    return core;
}

// Synthesize a stripped 64-bit Mach-O `MH_EXECUTE` on disk with `LC_UUID`.
std::vector<std::uint8_t> build_stripped_macho_executable(
    std::uint32_t cputype,
    const std::array<std::uint8_t, 16>& uuid,
    std::uint64_t text_vmaddr = 0x100000000ULL) {
    std::vector<std::uint8_t> bin(0x2000u, 0u);
    std::vector<std::uint8_t> hdr;

    // ncmds = 4: __PAGEZERO (72), __TEXT + __text (152), LC_UUID (24), LC_MAIN (24) = 272 bytes
    append_u32_le(hdr, peelf::macho::kMhMagic64);
    append_u32_le(hdr, cputype);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, peelf::macho::kMhExecute);
    append_u32_le(hdr, 4u);
    append_u32_le(hdr, 272u);
    append_u32_le(hdr, peelf::macho::kMhPie | peelf::macho::kMhTwoLevel);
    append_u32_le(hdr, 0u);

    // __PAGEZERO
    append_u32_le(hdr, peelf::macho::kLcSegment64);
    append_u32_le(hdr, 72u);
    append_fixed_str16(hdr, "__PAGEZERO");
    append_u64_le(hdr, 0u);
    append_u64_le(hdr, text_vmaddr);
    append_u64_le(hdr, 0u);
    append_u64_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);

    // __TEXT + __text at RVA 0x1000..0x1100
    append_u32_le(hdr, peelf::macho::kLcSegment64);
    append_u32_le(hdr, 152u);
    append_fixed_str16(hdr, "__TEXT");
    append_u64_le(hdr, text_vmaddr);
    append_u64_le(hdr, 0x2000u);
    append_u64_le(hdr, 0u);
    append_u64_le(hdr, 0x2000u);
    append_u32_le(hdr, 5u);
    append_u32_le(hdr, 5u);
    append_u32_le(hdr, 1u);
    append_u32_le(hdr, 0u);

    append_fixed_str16(hdr, "__text");
    append_fixed_str16(hdr, "__TEXT");
    append_u64_le(hdr, text_vmaddr + 0x1000u);
    append_u64_le(hdr, 0x100u);
    append_u32_le(hdr, 0x1000u);
    append_u32_le(hdr, 4u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, peelf::macho::kSAttrPureInstructions | peelf::macho::kSAttrSomeInstructions);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);
    append_u32_le(hdr, 0u);

    // LC_UUID (24 bytes)
    append_u32_le(hdr, peelf::macho::kLcUuid);
    append_u32_le(hdr, 24u);
    hdr.insert(hdr.end(), uuid.begin(), uuid.end());

    // LC_MAIN (24 bytes)
    append_u32_le(hdr, peelf::macho::kLcMain);
    append_u32_le(hdr, 24u);
    append_u64_le(hdr, 0x1000u);
    append_u64_le(hdr, 0u);

    std::copy(hdr.begin(), hdr.end(), bin.begin());
    bin[0x1000u] = 0x55u;
    bin[0x1001u] = 0x48u;
    bin[0x1002u] = 0x89u;
    bin[0x1003u] = 0xE5u;
    bin[0x1004u] = 0xC3u;
    return bin;
}

// Synthesize a Mach-O `MH_DSYM` companion containing `__DWARF` sections:
// `__debug_info`, `__debug_abbrev`, `__debug_str`, `__debug_line`, and 16-char
// truncated `__debug_str_offs` (exercising DWARF v5 `DW_FORM_strx1`)!
std::vector<std::uint8_t> build_macho_dsym_companion(
    std::uint32_t cputype,
    const std::array<std::uint8_t, 16>& uuid,
    std::string_view func_name,
    std::string_view struct_name,
    std::uint64_t text_vmaddr = 0x100000000ULL) {
    // 1. `__debug_str` + `__debug_str_offs` (DWARF v5 string offsets table)
    std::vector<std::uint8_t> debug_str;
    append_u8(debug_str, 0u);
    auto add_str = [&](std::string_view sv) -> std::uint32_t {
        const auto off = static_cast<std::uint32_t>(debug_str.size());
        append_cstr(debug_str, sv);
        return off;
    };
    const std::uint32_t s_cu     = add_str("darwin_engine.cpp");
    const std::uint32_t s_u64    = add_str("uint64_t");
    const std::uint32_t s_u32    = add_str("uint32_t");
    const std::uint32_t s_struct = add_str(struct_name);
    const std::uint32_t s_f0     = add_str("magic_tag");
    const std::uint32_t s_f1     = add_str("session_ptr");
    const std::uint32_t s_fn     = add_str(func_name);

    // DWARF v5 `.debug_str_offsets` / `__debug_str_offs`:
    // 8-byte header (unit_length=4+2+2+4=8? unit_length excludes initial 4B: version=5 (2B), pad=0 (2B) + 1*4B entry = 8B)
    std::vector<std::uint8_t> debug_str_offs;
    append_u32_le(debug_str_offs, 8u); // unit_length = 2 (version) + 2 (padding) + 4 (index 0)
    append_u16_le(debug_str_offs, 5u); // DWARF v5
    append_u16_le(debug_str_offs, 0u); // padding
    append_u32_le(debug_str_offs, s_fn); // strx index 0 -> `func_name`!

    // 2. `__debug_abbrev`
    // 1: DW_TAG_compile_unit (children=yes): DW_AT_str_offsets_base(sec_offset=0x17), DW_AT_name(strp=0x0E)
    // 2: DW_TAG_base_type (no): DW_AT_name(strp), DW_AT_byte_size(data1=0x0B)
    // 3: DW_TAG_structure_type (yes): DW_AT_name(strp), DW_AT_byte_size(data1)
    // 4: DW_TAG_member (no): DW_AT_name(strp), DW_AT_type(ref4=0x13), DW_AT_data_member_location(data1=0x0B)
    // 5: DW_TAG_subprogram (no): DW_AT_name(strx1=0x25), DW_AT_low_pc(addr=0x01), DW_AT_high_pc(data4=0x06), DW_AT_decl_line(data1=0x0B)
    std::vector<std::uint8_t> debug_abbrev;
    auto emit_attr = [&](std::uint8_t attr, std::uint8_t form) {
        append_u8(debug_abbrev, attr);
        append_u8(debug_abbrev, form);
    };
    append_u8(debug_abbrev, 1u); append_u8(debug_abbrev, 0x11u); append_u8(debug_abbrev, 1u);
    emit_attr(0x72u, 0x17u); emit_attr(0x03u, 0x0Eu); emit_attr(0u, 0u);

    append_u8(debug_abbrev, 2u); append_u8(debug_abbrev, 0x24u); append_u8(debug_abbrev, 0u);
    emit_attr(0x03u, 0x0Eu); emit_attr(0x0Bu, 0x0Bu); emit_attr(0u, 0u);

    append_u8(debug_abbrev, 3u); append_u8(debug_abbrev, 0x13u); append_u8(debug_abbrev, 1u);
    emit_attr(0x03u, 0x0Eu); emit_attr(0x0Bu, 0x0Bu); emit_attr(0u, 0u);

    append_u8(debug_abbrev, 4u); append_u8(debug_abbrev, 0x0Du); append_u8(debug_abbrev, 0u);
    emit_attr(0x03u, 0x0Eu); emit_attr(0x49u, 0x13u); emit_attr(0x38u, 0x0Bu); emit_attr(0u, 0u);

    append_u8(debug_abbrev, 5u); append_u8(debug_abbrev, 0x2Eu); append_u8(debug_abbrev, 0u);
    emit_attr(0x03u, 0x25u /*DW_FORM_strx1*/);
    emit_attr(0x11u, 0x01u /*DW_FORM_addr*/);
    emit_attr(0x12u, 0x06u /*DW_FORM_data4*/);
    emit_attr(0x3Bu, 0x0Bu /*DW_FORM_data1*/);
    emit_attr(0u, 0u);
    append_u8(debug_abbrev, 0u);

    // 3. `__debug_info` (DWARF v5 CU)
    std::vector<std::uint8_t> debug_info;
    append_u32_le(debug_info, 0u); // unit_length patched below
    append_u16_le(debug_info, 5u); // version = 5
    append_u8(debug_info, 1u);     // DW_UT_compile
    append_u8(debug_info, 8u);     // address_size = 8
    append_u32_le(debug_info, 0u); // debug_abbrev_offset = 0

    // Root DIE (abbrev 1)
    append_u8(debug_info, 1u);
    append_u32_le(debug_info, 8u); // DW_AT_str_offsets_base = 8 (past 8-byte header)
    append_u32_le(debug_info, s_cu);

    // Base type uint32_t (abbrev 2)
    const auto off_u32 = static_cast<std::uint32_t>(debug_info.size());
    append_u8(debug_info, 2u);
    append_u32_le(debug_info, s_u32);
    append_u8(debug_info, 4u);

    // Base type uint64_t (abbrev 2)
    const auto off_u64 = static_cast<std::uint32_t>(debug_info.size());
    append_u8(debug_info, 2u);
    append_u32_le(debug_info, s_u64);
    append_u8(debug_info, 8u);

    // Struct type (abbrev 3, size 16)
    append_u8(debug_info, 3u);
    append_u32_le(debug_info, s_struct);
    append_u8(debug_info, 16u);
    // Member 0: magic_tag @ +0 (uint32_t)
    append_u8(debug_info, 4u);
    append_u32_le(debug_info, s_f0);
    append_u32_le(debug_info, off_u32);
    append_u8(debug_info, 0u);
    // Member 1: session_ptr @ +8 (uint64_t)
    append_u8(debug_info, 4u);
    append_u32_le(debug_info, s_f1);
    append_u32_le(debug_info, off_u64);
    append_u8(debug_info, 8u);
    append_u8(debug_info, 0u); // end struct children

    // Subprogram (abbrev 5): name via strx1(0) -> `__debug_str_offs`!
    append_u8(debug_info, 5u);
    append_u8(debug_info, 0u); // strx1 index 0
    append_u64_le(debug_info, text_vmaddr + 0x1000u); // low_pc
    append_u32_le(debug_info, 0x40u);                 // high_pc length
    append_u8(debug_info, 42u);                       // decl_line = 42

    append_u8(debug_info, 0u); // end CU children
    write_u32_le_at(debug_info, 0u, static_cast<std::uint32_t>(debug_info.size() - 4u));

    // 4. `__debug_line` (DWARF v4 line table mapping `text_vmaddr + 0x1000` -> `src/darwin_engine.cpp:42`)
    std::vector<std::uint8_t> debug_line;
    append_u32_le(debug_line, 0u); // unit_length patched below
    append_u16_le(debug_line, 4u); // version = 4
    const std::size_t hdr_len_pos = debug_line.size();
    append_u32_le(debug_line, 0u); // header_length patched below
    const std::size_t hdr_start = debug_line.size();
    append_u8(debug_line, 1u);                   // min_inst_length = 1
    append_u8(debug_line, 1u);                   // max_ops_per_inst = 1
    append_u8(debug_line, 1u);                   // default_is_stmt = 1
    append_u8(debug_line, static_cast<std::uint8_t>(-5)); // line_base = -5
    append_u8(debug_line, 14u);                  // line_range = 14
    append_u8(debug_line, 13u);                  // opcode_base = 13
    const std::array<std::uint8_t, 12> std_lens{{0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1}};
    debug_line.insert(debug_line.end(), std_lens.begin(), std_lens.end());
    append_cstr(debug_line, "/Users/dev/project/src");
    append_u8(debug_line, 0u); // end include_directories
    append_cstr(debug_line, "darwin_engine.cpp");
    append_u8(debug_line, 1u); // dir_index = 1
    append_u8(debug_line, 0u); // mtime
    append_u8(debug_line, 0u); // size
    append_u8(debug_line, 0u); // end file_names
    write_u32_le_at(debug_line, hdr_len_pos, static_cast<std::uint32_t>(debug_line.size() - hdr_start));

    // Extended opcode DW_LNE_set_address (len=9, op=2, u64 addr)
    append_u8(debug_line, 0u);
    append_u8(debug_line, 9u);
    append_u8(debug_line, 2u);
    append_u64_le(debug_line, text_vmaddr + 0x1000u);
    // DW_LNS_advance_line (+41 -> line = 1 + 41 = 42)
    append_u8(debug_line, 3u);
    append_u8(debug_line, 41u);
    // DW_LNS_copy
    append_u8(debug_line, 1u);
    // DW_LNS_advance_pc (+4) + DW_LNE_end_sequence
    append_u8(debug_line, 2u);
    append_u8(debug_line, 4u);
    append_u8(debug_line, 0u);
    append_u8(debug_line, 1u);
    append_u8(debug_line, 1u);
    write_u32_le_at(debug_line, 0u, static_cast<std::uint32_t>(debug_line.size() - 4u));

    // Assemble `MH_DSYM` Mach-O with:
    //   - `LC_UUID` (24B)
    //   - `LC_SEGMENT_64` `"__TEXT"` skeleton (72B, vmaddr=text_vmaddr, filesize=0)
    //   - `LC_SEGMENT_64` `"__DWARF"` + 5 `section_64`s (72 + 5*80 = 472B)
    constexpr std::uint32_t kNumDwarfSects = 5u;
    constexpr std::uint32_t kDwarfSegCmdSz = 72u + kNumDwarfSects * 80u;
    constexpr std::uint32_t kSizeOfCmds    = 24u + 72u + kDwarfSegCmdSz;

    std::size_t file_cursor = 0x1000u;
    const std::size_t off_info     = file_cursor; file_cursor += debug_info.size();
    const std::size_t off_abbrev   = file_cursor; file_cursor += debug_abbrev.size();
    const std::size_t off_str      = file_cursor; file_cursor += debug_str.size();
    const std::size_t off_line     = file_cursor; file_cursor += debug_line.size();
    const std::size_t off_str_offs = file_cursor; file_cursor += debug_str_offs.size();
    const std::size_t dwarf_total  = file_cursor - 0x1000u;

    std::vector<std::uint8_t> dsym;
    append_u32_le(dsym, peelf::macho::kMhMagic64);
    append_u32_le(dsym, cputype);
    append_u32_le(dsym, 0u);
    append_u32_le(dsym, peelf::macho::kMhDsym);
    append_u32_le(dsym, 3u);
    append_u32_le(dsym, kSizeOfCmds);
    append_u32_le(dsym, 0u);
    append_u32_le(dsym, 0u);

    // LC_UUID
    append_u32_le(dsym, peelf::macho::kLcUuid);
    append_u32_le(dsym, 24u);
    dsym.insert(dsym.end(), uuid.begin(), uuid.end());

    // LC_SEGMENT_64 "__TEXT" (virtual skeleton, filesize=0, just like `dsymutil`)
    append_u32_le(dsym, peelf::macho::kLcSegment64);
    append_u32_le(dsym, 72u);
    append_fixed_str16(dsym, "__TEXT");
    append_u64_le(dsym, text_vmaddr);
    append_u64_le(dsym, 0x2000u);
    append_u64_le(dsym, 0u);
    append_u64_le(dsym, 0u);
    append_u32_le(dsym, 5u);
    append_u32_le(dsym, 5u);
    append_u32_le(dsym, 0u);
    append_u32_le(dsym, 0u);

    // LC_SEGMENT_64 "__DWARF"
    const std::uint64_t dwarf_vmaddr = text_vmaddr + 0x8000u;
    append_u32_le(dsym, peelf::macho::kLcSegment64);
    append_u32_le(dsym, kDwarfSegCmdSz);
    append_fixed_str16(dsym, "__DWARF");
    append_u64_le(dsym, dwarf_vmaddr);
    append_u64_le(dsym, ((dwarf_total + 0xFFFu) & ~std::size_t{0xFFFu}));
    append_u64_le(dsym, 0x1000u);
    append_u64_le(dsym, dwarf_total);
    append_u32_le(dsym, 3u);
    append_u32_le(dsym, 3u);
    append_u32_le(dsym, kNumDwarfSects);
    append_u32_le(dsym, 0u);

    auto emit_dwarf_sec = [&](std::string_view sectname, std::size_t foff, std::size_t fsz) {
        append_fixed_str16(dsym, sectname);
        append_fixed_str16(dsym, "__DWARF");
        append_u64_le(dsym, dwarf_vmaddr + (foff - 0x1000u));
        append_u64_le(dsym, fsz);
        append_u32_le(dsym, static_cast<std::uint32_t>(foff));
        append_u32_le(dsym, 0u);
        append_u32_le(dsym, 0u);
        append_u32_le(dsym, 0u);
        append_u32_le(dsym, peelf::macho::kSAttrDebug);
        append_u32_le(dsym, 0u);
        append_u32_le(dsym, 0u);
        append_u32_le(dsym, 0u);
    };
    emit_dwarf_sec("__debug_info",     off_info,     debug_info.size());
    emit_dwarf_sec("__debug_abbrev",   off_abbrev,   debug_abbrev.size());
    emit_dwarf_sec("__debug_str",      off_str,      debug_str.size());
    emit_dwarf_sec("__debug_line",     off_line,     debug_line.size());
    emit_dwarf_sec("__debug_str_offs", off_str_offs, debug_str_offs.size()); // 16-char truncated!

    dsym.resize(0x1000u, 0u);
    dsym.insert(dsym.end(), debug_info.begin(), debug_info.end());
    dsym.insert(dsym.end(), debug_abbrev.begin(), debug_abbrev.end());
    dsym.insert(dsym.end(), debug_str.begin(), debug_str.end());
    dsym.insert(dsym.end(), debug_line.begin(), debug_line.end());
    dsym.insert(dsym.end(), debug_str_offs.begin(), debug_str_offs.end());
    return dsym;
}

std::vector<std::uint8_t> pack_universal_macho_2slices(
    std::uint32_t cpu0,
    std::span<const std::uint8_t> slice0,
    std::uint32_t cpu1,
    std::span<const std::uint8_t> slice1) {
    constexpr std::size_t kOff0 = 0x1000u;
    const std::size_t off1 = ((kOff0 + slice0.size() + 0xFFFu) & ~std::size_t{0xFFFu});

    std::vector<std::uint8_t> fat;
    append_u32_be(fat, peelf::macho::kFatMagic);
    append_u32_be(fat, 2u); // nfat_arch = 2

    // fat_arch 0 (20 bytes, big-endian)
    append_u32_be(fat, cpu0);
    append_u32_be(fat, 0u);
    append_u32_be(fat, static_cast<std::uint32_t>(kOff0));
    append_u32_be(fat, static_cast<std::uint32_t>(slice0.size()));
    append_u32_be(fat, 12u);

    // fat_arch 1
    append_u32_be(fat, cpu1);
    append_u32_be(fat, 0u);
    append_u32_be(fat, static_cast<std::uint32_t>(off1));
    append_u32_be(fat, static_cast<std::uint32_t>(slice1.size()));
    append_u32_be(fat, 12u);

    fat.resize(kOff0, 0u);
    fat.insert(fat.end(), slice0.begin(), slice0.end());
    fat.resize(off1, 0u);
    fat.insert(fat.end(), slice1.begin(), slice1.end());
    return fat;
}

}  // namespace

TEST(MachOCoreAndDsymTest, ParsesX8664MachOCoreSegmentsRegistersModulesBinaryModelAndHeadless) {
    const std::vector<std::uint8_t> core = build_synthetic_x86_64_macho_core();
    EXPECT_TRUE(peelf::is_macho_core_dump(core));
    EXPECT_TRUE(peelf::is_crash_dump_bytes(core));

    // Non-core Mach-O and Java `.class` 0xCAFEBABE must NOT be identified as MH_CORE
    const std::vector<std::uint8_t> non_core_exe =
        make_mapped_macho64_execute(peelf::macho::kCpuTypeX86_64, 0x100000000ULL);
    EXPECT_FALSE(peelf::is_macho_core_dump(non_core_exe));
    const std::array<std::uint8_t, 32> java_class{{
        0xCAu, 0xFEu, 0xBAu, 0xBEu, 0x00u, 0x00u, 0x00u, 0x3Du
    }};
    EXPECT_FALSE(peelf::is_macho_core_dump(java_class));

    auto opened = peelf::open_crash_dump_bytes(core, "darwin_crash_app.core");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::ICrashDumpSession& sess = **opened;

    const peelf::CrashDumpSummary& cs = sess.crash_summary();
    EXPECT_EQ(cs.kind, peelf::CrashDumpKind::MachOCore);
    EXPECT_EQ(peelf::to_string(cs.kind), "MachOCore");
    EXPECT_EQ(cs.layout.architecture, peelf::Architecture::X86_64);
    EXPECT_EQ(cs.layout.address_width, peelf::AddressWidth::Bits64);
    EXPECT_EQ(cs.process_name, "darwin_crash_app");

    ASSERT_TRUE(cs.exception.has_value());
    EXPECT_EQ(cs.exception->thread_id, 1u);
    EXPECT_EQ(cs.exception->fault_code, 14u);
    EXPECT_NE(cs.exception->fault_name.find("EXC_BAD_ACCESS"), std::string::npos);
    EXPECT_EQ(cs.exception->access_operation, "write");
    EXPECT_EQ(cs.exception->fault_address, 0x000000000BAD0010ULL);
    EXPECT_EQ(cs.exception->instruction_pointer, 0x0000000100000204ULL);

    // Verify `[file_size, virtual_size)` zero-fill in `read_memory` across `seg_data`
    std::vector<std::uint8_t> span_buf(0x80u, 0xCCu);
    const auto rd = sess.read_memory(0x0000000100010000ULL, span_buf);
    ASSERT_TRUE(rd.has_value()) << rd.error().message;
    EXPECT_EQ(*rd, 0x80u);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(span_buf.data()), 20u),
              "MACHO_CORE_DATA_HEAD");
    for (std::size_t i = 0x40u; i < 0x80u; ++i) {
        EXPECT_EQ(span_buf[i], 0u) << "Expected zero-filled byte at offset " << i;
    }

    // Verify `threads()` and `read_registers(tid)`
    const auto ths = sess.threads();
    ASSERT_TRUE(ths.has_value());
    ASSERT_EQ(ths->size(), 1u);
    EXPECT_EQ((*ths)[0].tid, 1u);
    EXPECT_EQ((*ths)[0].instruction_pointer, 0x0000000100000204ULL);
    EXPECT_EQ((*ths)[0].stack_pointer, 0x00007FF7BFEEF800ULL);

    const peelf::RegisterContext regs = sess.read_registers(1u);
    EXPECT_TRUE(regs.status.has_data());
    EXPECT_EQ(regs.instruction_pointer, 0x0000000100000204ULL);
    EXPECT_EQ(regs.stack_pointer, 0x00007FF7BFEEF800ULL);
    EXPECT_EQ(regs.frame_pointer, 0x00007FF7BFEEF820ULL);
    bool saw_rax = false;
    bool saw_r15 = false;
    for (const peelf::RegisterValue& rv : regs.registers) {
        if (rv.name == "rax" && rv.value_u64 == 0x1111222233334444ULL) {
            saw_rax = true;
        }
        if (rv.name == "r15" && rv.value_u64 == 0xFFFF00000000000FULL) {
            saw_r15 = true;
        }
    }
    EXPECT_TRUE(saw_rax);
    EXPECT_TRUE(saw_r15);

    // Verify recovered mapped Mach-O modules (`MH_EXECUTE` + `MH_DYLIB` `LC_ID_DYLIB`)
    const auto mods = sess.modules();
    ASSERT_TRUE(mods.has_value());
    ASSERT_EQ(mods->size(), 2u);
    EXPECT_TRUE((*mods)[0].is_main_module);
    EXPECT_EQ((*mods)[0].name, "darwin_crash_app");
    EXPECT_EQ((*mods)[0].base_address, 0x0000000100000000ULL);
    EXPECT_EQ((*mods)[1].name, "libSystem.B.dylib");
    EXPECT_EQ((*mods)[1].path.string(), "/usr/lib/libSystem.B.dylib");

    // Verify capability matrix coherence for `MachOCore` / `Darwin`
    const auto regions = sess.memory_regions();
    ASSERT_TRUE(regions.has_value());
    const peelf::TargetProfile profile = peelf::derive_target_profile(nullptr, &sess);
    EXPECT_EQ(profile.backend, peelf::BackendKind::CrashDumpMachOCore);
    EXPECT_EQ(profile.os, peelf::OsKind::Darwin);
    const peelf::TargetCapabilityMatrix caps = peelf::capabilities_for(profile);
    EXPECT_EQ(caps.get(peelf::Operation::SoftwareBreakpoints).state,
              peelf::SupportState::Unsupported);
    EXPECT_EQ(caps.get(peelf::Operation::StaticPatching).state,
              peelf::SupportState::Unsupported);
    EXPECT_TRUE(caps.get(peelf::Operation::StackUnwind).is_supported());

    // Verify `BinaryModel::load_file` and `--headless` JSON output on disk
    ScopedTempDir tmp("peelf_macho_core");
    const std::filesystem::path core_path = tmp.path() / "darwin_crash_app.core";
    write_binary_file(core_path, core);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(core_path.string())) << model.last_diagnostic();
    EXPECT_TRUE(model.is_live_process());
    EXPECT_TRUE(model.is_crash_dump());
    EXPECT_TRUE(model.is_read_only());
    ASSERT_NE(model.crash_dump_summary(), nullptr);
    EXPECT_EQ(model.crash_dump_summary()->kind, peelf::CrashDumpKind::MachOCore);
    ASSERT_TRUE(model.selected_thread_id().has_value());
    EXPECT_EQ(*model.selected_thread_id(), 1u);
    EXPECT_GE(model.selected_thread_stack().frames.size(), 2u);
    EXPECT_EQ(model.process_modules().size(), 2u);

    std::ostringstream out_json;
    std::ostringstream err_json;
    const std::string path_str = core_path.string();
    const std::array<std::string_view, 3> cli_args{{
        "--headless", path_str, "--fail-on=warning"
    }};
    const auto rc = peelf::try_run_headless_or_help_cli(cli_args, out_json, err_json);
    ASSERT_TRUE(rc.has_value());
    EXPECT_EQ(*rc, 2); // RWX segment triggers LIVE3001 warning
    const std::string json = out_json.str();
    EXPECT_NE(json.find("\"kind\": \"CrashDump\""), std::string::npos);
    EXPECT_NE(json.find("\"format\": \"Mach-O\""), std::string::npos);
    EXPECT_NE(json.find("\"EXC_BAD_ACCESS"), std::string::npos);
    EXPECT_NE(json.find("\"LIVE3001\""), std::string::npos);
}

TEST(MachOCoreAndDsymTest, ParsesArm64AndUniversalMachOCoreThreadAndExceptionState) {
    const std::vector<std::uint8_t> arm64_core = build_synthetic_arm64_macho_core();
    EXPECT_TRUE(peelf::is_macho_core_dump(arm64_core));

    auto opened = peelf::open_macho_core_bytes(arm64_core, "ios_arm64.core");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::ICrashDumpSession& sess = **opened;

    const peelf::CrashDumpSummary& cs = sess.crash_summary();
    EXPECT_EQ(cs.kind, peelf::CrashDumpKind::MachOCore);
    EXPECT_EQ(cs.layout.architecture, peelf::Architecture::ARM64);
    ASSERT_TRUE(cs.exception.has_value());
    EXPECT_EQ(cs.exception->fault_address, 0x00000000DEAD4000ULL);
    EXPECT_EQ(cs.exception->access_operation, "write");
    EXPECT_NE(cs.exception->fault_name.find("EXC_BAD_ACCESS"), std::string::npos);

    const peelf::RegisterContext regs = sess.read_registers(1u);
    EXPECT_TRUE(regs.status.has_data());
    EXPECT_EQ(regs.instruction_pointer, 0x0000000102000204ULL);
    EXPECT_EQ(regs.stack_pointer, 0x000000016FDEC900ULL);
    EXPECT_EQ(regs.frame_pointer, 0x000000016FDEC910ULL);
    EXPECT_EQ(regs.link_register, 0x0000000102000240ULL);

    bool saw_x0 = false;
    bool saw_x28 = false;
    bool saw_cpsr = false;
    for (const peelf::RegisterValue& rv : regs.registers) {
        if (rv.name == "x0" && rv.value_u64 == 0xA6400000ULL) {
            saw_x0 = true;
        }
        if (rv.name == "x28" && rv.value_u64 == 0xA640001CULL) {
            saw_x28 = true;
        }
        if (rv.name == "cpsr" && rv.value_u64 == 0x60000000ULL) {
            saw_cpsr = true;
        }
    }
    EXPECT_TRUE(saw_x0);
    EXPECT_TRUE(saw_x28);
    EXPECT_TRUE(saw_cpsr);

    // Universal/FAT container wrapping x86_64 + ARM64 MH_CORE slices
    const std::vector<std::uint8_t> x64_core = build_synthetic_x86_64_macho_core();
    const std::vector<std::uint8_t> fat_core = pack_universal_macho_2slices(
        peelf::macho::kCpuTypeArm64, arm64_core,
        peelf::macho::kCpuTypeX86_64, x64_core);
    EXPECT_TRUE(peelf::is_macho_core_dump(fat_core));
    EXPECT_TRUE(peelf::is_crash_dump_bytes(fat_core));
    auto fat_opened = peelf::open_crash_dump_bytes(fat_core, "universal.core");
    ASSERT_TRUE(fat_opened.has_value()) << fat_opened.error().message;
    EXPECT_EQ((*fat_opened)->crash_summary().kind, peelf::CrashDumpKind::MachOCore);
    EXPECT_EQ((*fat_opened)->crash_summary().layout.architecture, peelf::Architecture::ARM64);
}

TEST(MachOCoreAndDsymTest, HandlesMalformedAndTruncatedMachOCoreInputsSafely) {
    // 1. Truncated load-command table must fail cleanly without UB
    {
        std::vector<std::uint8_t> tiny;
        append_u32_le(tiny, peelf::macho::kMhMagic64);
        append_u32_le(tiny, peelf::macho::kCpuTypeX86_64);
        append_u32_le(tiny, 0u);
        append_u32_le(tiny, peelf::macho::kMhCore);
        append_u32_le(tiny, 4u);
        append_u32_le(tiny, 0x4000u); // exceeds buffer!
        append_u32_le(tiny, 0u);
        append_u32_le(tiny, 0u);

        EXPECT_TRUE(peelf::is_macho_core_dump(tiny));
        const auto res = peelf::open_crash_dump_bytes(tiny, "truncated_hdr.core");
        EXPECT_FALSE(res.has_value());
    }

    // 2. MH_CORE with:
    //    - Segment 0: overflowing `vmaddr + vmsize` (skipped with Partial warning)
    //    - Segment 1: overflowing `fileoff + filesize` (skipped with Partial warning)
    //    - Segment 2: valid readable segment
    //    - Thread 1: truncated `LC_THREAD` state count exceeding `cmdsize`
    //    - Thread 2: unsupported flavor `999`
    {
        std::vector<std::uint8_t> trunc_thread;
        append_u32_le(trunc_thread, peelf::macho::kLcThread);
        append_u32_le(trunc_thread, 24u); // only 16 bytes after cmd header
        append_u32_le(trunc_thread, 4u);  // x86_THREAD_STATE64
        append_u32_le(trunc_thread, 42u); // claims 168 bytes > 8 remaining!
        append_u64_le(trunc_thread, 0xDEADBEEFULL);

        std::vector<std::uint8_t> unsupp_thread;
        append_u32_le(unsupp_thread, peelf::macho::kLcThread);
        append_u32_le(unsupp_thread, 24u);
        append_u32_le(unsupp_thread, 999u); // unsupported flavor
        append_u32_le(unsupp_thread, 2u);   // 8 bytes
        append_u64_le(unsupp_thread, 0x12345678ULL);

        const auto sizeofcmds = static_cast<std::uint32_t>(
            3u * 72u + trunc_thread.size() + unsupp_thread.size());

        std::vector<std::uint8_t> malformed;
        append_u32_le(malformed, peelf::macho::kMhMagic64);
        append_u32_le(malformed, peelf::macho::kCpuTypeX86_64);
        append_u32_le(malformed, 0u);
        append_u32_le(malformed, peelf::macho::kMhCore);
        append_u32_le(malformed, 5u);
        append_u32_le(malformed, sizeofcmds);
        append_u32_le(malformed, 0u);
        append_u32_le(malformed, 0u);

        auto emit_seg = [&](std::uint64_t vmaddr,
                            std::uint64_t vmsize,
                            std::uint64_t fileoff,
                            std::uint64_t filesize) {
            append_u32_le(malformed, peelf::macho::kLcSegment64);
            append_u32_le(malformed, 72u);
            append_fixed_str16(malformed, "seg");
            append_u64_le(malformed, vmaddr);
            append_u64_le(malformed, vmsize);
            append_u64_le(malformed, fileoff);
            append_u64_le(malformed, filesize);
            append_u32_le(malformed, 3u);
            append_u32_le(malformed, 3u);
            append_u32_le(malformed, 0u);
            append_u32_le(malformed, 0u);
        };

        emit_seg(0xFFFF'FFFF'FFFF'F000ULL, 0x4000ULL, 0x400u, 0x10u); // vmaddr+vmsize overflow!
        emit_seg(0x0000000100000000ULL, 0x1000ULL, 0xFFFF'FFFF'FFFF'F800ULL, 0x1000ULL); // fileoff+filesize overflow!
        emit_seg(0x0000000100050000ULL, 0x1000ULL, 0x400u, 0x10u); // valid segment

        malformed.insert(malformed.end(), trunc_thread.begin(), trunc_thread.end());
        malformed.insert(malformed.end(), unsupp_thread.begin(), unsupp_thread.end());
        malformed.resize(0x410u, 0xABu);

        auto opened = peelf::open_macho_core_bytes(malformed, "malformed_partial.core");
        ASSERT_TRUE(opened.has_value()) << opened.error().message;
        peelf::ICrashDumpSession& sess = **opened;

        EXPECT_EQ(sess.crash_summary().status.availability, peelf::Availability::Partial);
        EXPECT_EQ(sess.memory_regions_status().availability, peelf::Availability::Partial);
        EXPECT_EQ(sess.threads_status().availability, peelf::Availability::Partial);
        EXPECT_FALSE(sess.crash_summary().diagnostics.empty());

        const auto regions = sess.memory_regions();
        ASSERT_TRUE(regions.has_value());
        ASSERT_EQ(regions->size(), 1u);
        EXPECT_EQ((*regions)[0].start_address, 0x0000000100050000ULL);

        const auto ths = sess.threads();
        ASSERT_TRUE(ths.has_value());
        ASSERT_EQ(ths->size(), 2u);
        EXPECT_FALSE(sess.read_registers(1u).status.has_data());
        EXPECT_FALSE(sess.read_registers(2u).status.has_data());
    }
}

TEST(MachOCoreAndDsymTest, DiscoversAndLoadsDsymBundlesHydratesDwarfAndRejectsUuidMismatch) {
    constexpr std::array<std::uint8_t, 16> kUuidMatch{{
        0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u, 0x80u,
        0x90u, 0xA0u, 0xB0u, 0xC0u, 0xD0u, 0xE0u, 0xF0u, 0x01u
    }};
    constexpr std::array<std::uint8_t, 16> kUuidMismatch{{
        0xFFu, 0xEEu, 0xDDu, 0xCCu, 0xBBu, 0xAAu, 0x99u, 0x88u,
        0x77u, 0x66u, 0x55u, 0x44u, 0x33u, 0x22u, 0x11u, 0x00u
    }};
    constexpr std::array<std::uint8_t, 16> kUuidArm64{{
        0xA6u, 0x40u, 0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
        0x06u, 0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du
    }};

    const std::vector<std::uint8_t> stripped_exe =
        build_stripped_macho_executable(peelf::macho::kCpuTypeX86_64, kUuidMatch);
    const std::vector<std::uint8_t> matching_dsym = build_macho_dsym_companion(
        peelf::macho::kCpuTypeX86_64, kUuidMatch, "_ZN6darwin10run_engineEv", "DarwinSessionState");
    const std::vector<std::uint8_t> mismatched_dsym = build_macho_dsym_companion(
        peelf::macho::kCpuTypeX86_64, kUuidMismatch, "_ZN6darwin5staleEv", "StaleStruct");

    auto parsed_exe = peelf::parse_image(stripped_exe);
    ASSERT_TRUE(parsed_exe.has_value()) << parsed_exe.error().message;
    EXPECT_FALSE(peelf::has_embedded_dwarf(**parsed_exe));

    auto parsed_dsym = peelf::parse_image(matching_dsym);
    ASSERT_TRUE(parsed_dsym.has_value()) << parsed_dsym.error().message;
    EXPECT_TRUE(peelf::has_embedded_dwarf(**parsed_dsym));

    ScopedTempDir tmp("peelf_dsym_test");
    const std::filesystem::path bin_path = tmp.path() / "DarwinApp";
    const std::filesystem::path bundle_dir = tmp.path() / "DarwinApp.dSYM";
    const std::filesystem::path inner_dwarf =
        bundle_dir / "Contents" / "Resources" / "DWARF" / "DarwinApp";
    write_binary_file(bin_path, stripped_exe);

    // 1. When `.dSYM` has a MISMATCHED `LC_UUID`, `find_separate_debug_file` must ignore it
    //    and `load_debug_symbols_file` must reject it with `BackendError` + UUID diagnostic!
    write_binary_file(inner_dwarf, mismatched_dsym);
    EXPECT_FALSE(peelf::find_separate_debug_file(bin_path, **parsed_exe).has_value());

    const viewer::DebugSymbolLoadResult bad_file_res =
        viewer::load_debug_symbols_file(inner_dwarf, **parsed_exe);
    EXPECT_EQ(bad_file_res.status, viewer::DebugSymbolLoadStatus::BackendError);
    EXPECT_NE(bad_file_res.diagnostic.find("LC_UUID"), std::string::npos);
    EXPECT_NE(bad_file_res.diagnostic.find("10203040-5060-7080-90A0-B0C0D0E0F001"),
              std::string::npos);
    EXPECT_NE(bad_file_res.diagnostic.find("FFEEDDCC-BBAA-9988-7766-554433221100"),
              std::string::npos);

    const viewer::DebugSymbolLoadResult bad_bundle_res =
        viewer::load_debug_symbols_file(bundle_dir, **parsed_exe);
    EXPECT_EQ(bad_bundle_res.status, viewer::DebugSymbolLoadStatus::BackendError);
    EXPECT_NE(bad_bundle_res.diagnostic.find("LC_UUID"), std::string::npos);

    // 2. Replace with matching `LC_UUID` `.dSYM`: verify `find_separate_debug_file` AND
    //    `load_debug_symbols_file` on BOTH inner file and `.dSYM` bundle directory!
    write_binary_file(inner_dwarf, matching_dsym);
    const auto discovered = peelf::find_separate_debug_file(bin_path, **parsed_exe);
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(std::filesystem::weakly_canonical(*discovered),
              std::filesystem::weakly_canonical(inner_dwarf));

    for (const std::filesystem::path& load_target : {inner_dwarf, bundle_dir}) {
        SCOPED_TRACE(load_target.string());
        const viewer::DebugSymbolLoadResult ok =
            viewer::load_debug_symbols_file(load_target, **parsed_exe);
        ASSERT_EQ(ok.status, viewer::DebugSymbolLoadStatus::Loaded) << ok.diagnostic;
        ASSERT_EQ(ok.symbols.size(), 1u);
        EXPECT_EQ(ok.symbols[0].name, "_ZN6darwin10run_engineEv");
        EXPECT_EQ(ok.symbols[0].virtual_address, 0x100001000ULL);
        EXPECT_EQ(ok.symbols[0].relative_virtual_address, 0x1000ULL);
        EXPECT_EQ(ok.symbols[0].size, 0x40ULL);

        ASSERT_EQ(ok.types.size(), 1u);
        EXPECT_EQ(ok.types[0].name, "DarwinSessionState");
        EXPECT_EQ(ok.types[0].size, 16ULL);
        ASSERT_EQ(ok.types[0].members.size(), 2u);
        EXPECT_EQ(ok.types[0].members[0].name, "magic_tag");
        EXPECT_EQ(ok.types[0].members[0].offset, 0ULL);
        EXPECT_EQ(ok.types[0].members[1].name, "session_ptr");
        EXPECT_EQ(ok.types[0].members[1].offset, 8ULL);

        ASSERT_EQ(ok.lines.size(), 1u);
        EXPECT_EQ(ok.lines[0].virtual_address, 0x100001000ULL);
        EXPECT_EQ(ok.lines[0].file_name, "darwin_engine.cpp");
        EXPECT_EQ(ok.lines[0].line, 42u);
    }

    // 3. Verify `BinaryModel::load_file` auto-discovers `<bin>.dSYM` and hydrates symbols/types/lines!
    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(bin_path.string())) << model.last_diagnostic();
    EXPECT_NE(model.symbol_index().find_by_name("_ZN6darwin10run_engineEv"), nullptr);
    EXPECT_NE(model.symbol_index().find_by_name("darwin::run_engine()"), nullptr);
    EXPECT_FALSE(model.debug_types().empty());
    EXPECT_FALSE(model.source_lines().empty());

    // 4. Universal `.dSYM` bundle (ARM64 slice 0 + x86_64 slice 1) picks matching x86_64 slice!
    const std::vector<std::uint8_t> arm64_dsym = build_macho_dsym_companion(
        peelf::macho::kCpuTypeArm64, kUuidArm64, "_ZN6darwin9arm64_symEv", "Arm64State");
    const std::vector<std::uint8_t> universal_dsym = pack_universal_macho_2slices(
        peelf::macho::kCpuTypeArm64, arm64_dsym,
        peelf::macho::kCpuTypeX86_64, matching_dsym);
    write_binary_file(inner_dwarf, universal_dsym);

    const auto uni_discovered = peelf::find_separate_debug_file(bin_path, **parsed_exe);
    ASSERT_TRUE(uni_discovered.has_value());
    const viewer::DebugSymbolLoadResult uni_loaded =
        viewer::load_debug_symbols_file(bundle_dir, **parsed_exe);
    ASSERT_EQ(uni_loaded.status, viewer::DebugSymbolLoadStatus::Loaded) << uni_loaded.diagnostic;
    ASSERT_EQ(uni_loaded.symbols.size(), 1u);
    EXPECT_EQ(uni_loaded.symbols[0].name, "_ZN6darwin10run_engineEv");
}

TEST(MachOCoreAndDsymTest, ParsesX8632MachOCoreSegmentsAndThreadState32) {
    // 32-bit `MH_MAGIC` (`0xFEEDFACE`), `cputype == kCpuTypeX86`, `LC_SEGMENT` (56B) +
    // `LC_THREAD` with `x86_THREAD_STATE32` (flavor=1, count=16 u32s = 64B) and
    // `x86_EXCEPTION_STATE32` (flavor=3, count=3 u32s = 12B).
    std::vector<std::uint8_t> thread_cmd;
    append_u32_le(thread_cmd, peelf::macho::kLcThread);
    append_u32_le(thread_cmd, 8u + (8u + 64u) + (8u + 12u)); // 100 bytes
    append_u32_le(thread_cmd, 1u);  // x86_THREAD_STATE32
    append_u32_le(thread_cmd, 16u); // 16 uint32s
    const std::array<std::uint32_t, 16> regs32{{
        0x11111111u, // eax
        0x22222222u, // ebx
        0x33333333u, // ecx
        0x44444444u, // edx
        0x55555555u, // edi
        0x66666666u, // esi
        0xBFFFE020u, // ebp
        0xBFFFE000u, // esp
        0x23u,       // ss
        0x00010202u, // eflags
        0x00001234u, // eip
        0x1Bu,       // cs
        0x23u,       // ds
        0x23u,       // es
        0x00u,       // fs
        0x00u,       // gs
    }};
    for (const std::uint32_t v : regs32) {
        append_u32_le(thread_cmd, v);
    }
    append_u32_le(thread_cmd, 3u); // x86_EXCEPTION_STATE32
    append_u32_le(thread_cmd, 3u); // 12 bytes
    append_u16_le(thread_cmd, 14u); // trapno = #PF
    append_u16_le(thread_cmd, 0u);  // cpu
    append_u32_le(thread_cmd, 0x04u); // user read page fault
    append_u32_le(thread_cmd, 0xCAFE0004u); // faultvaddr

    std::vector<std::uint8_t> core;
    // mach_header (28 bytes)
    append_u32_le(core, peelf::macho::kMhMagic);
    append_u32_le(core, peelf::macho::kCpuTypeX86);
    append_u32_le(core, 3u);
    append_u32_le(core, peelf::macho::kMhCore);
    append_u32_le(core, 2u);
    append_u32_le(core, static_cast<std::uint32_t>(56u + thread_cmd.size()));
    append_u32_le(core, 0u);

    // LC_SEGMENT (56 bytes)
    append_u32_le(core, peelf::macho::kLcSegment);
    append_u32_le(core, 56u);
    append_fixed_str16(core, "__TEXT");
    append_u32_le(core, 0x00001000u); // vmaddr
    append_u32_le(core, 0x00001000u); // vmsize
    append_u32_le(core, 0x00000400u); // fileoff
    append_u32_le(core, 0x00000100u); // filesize
    append_u32_le(core, 5u);
    append_u32_le(core, 5u);
    append_u32_le(core, 0u);
    append_u32_le(core, 0u);

    core.insert(core.end(), thread_cmd.begin(), thread_cmd.end());
    core.resize(0x500u, 0x90u);

    EXPECT_TRUE(peelf::is_macho_core_dump(core));
    auto opened = peelf::open_crash_dump_bytes(core, "x86_32.core");
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::ICrashDumpSession& sess = **opened;

    EXPECT_EQ(sess.crash_summary().layout.architecture, peelf::Architecture::X86);
    EXPECT_EQ(sess.crash_summary().layout.address_width, peelf::AddressWidth::Bits32);
    ASSERT_TRUE(sess.crash_summary().exception.has_value());
    EXPECT_EQ(sess.crash_summary().exception->fault_address, 0xCAFE0004ULL);
    EXPECT_EQ(sess.crash_summary().exception->access_operation, "read");

    const peelf::RegisterContext regs = sess.read_registers(1u);
    EXPECT_TRUE(regs.status.has_data());
    EXPECT_EQ(regs.instruction_pointer, 0x00001234ULL);
    EXPECT_EQ(regs.stack_pointer, 0xBFFFE000ULL);
    EXPECT_EQ(regs.frame_pointer, 0xBFFFE020ULL);
}

