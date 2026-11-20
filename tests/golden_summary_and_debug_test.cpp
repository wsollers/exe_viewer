// BSD 2-Clause License -- WU-43 Final Roadmap Closure Tests:
//   - P7-2 & P7-8: Deterministic golden summary assertions across PE32, PE32+,
//                  ELF32/ELF64 (x86, x86_64, ARM32, ARM64, RISC-V64, MIPS64 BE, PPC64 BE),
//                  and Mach-O 64 (x86_64, ARM64, and Universal FAT).
//   - P7-11:       Cross-platform MSF 7.00 .pdb (GUID/age match, mismatch rejection,
//                  offline symbol-server-disabled guarantee) and split DWARF
//                  (.gnu_debuglink + .note.gnu.build-id) resolving into
//                  LinearDisassemblyView function headers and call target labels.
//   - §15:         Safe bounded RegexText search (ReDoS/syntax guards + process memory)
//                  and Headless RFC 4180 CSV summary export (--headless --format csv).

#include <peelf/binary_image.hpp>
#include <peelf/dwarf.hpp>
#include <peelf/macho_image.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/pdb.hpp>
#include <peelf/process.hpp>
#include <peelf/security_audit.hpp>

#include "disasm/linear_disassembly.hpp"
#include "model/binary_model.hpp"
#include "symbols/debug_symbols.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

#ifndef PEELF_BIN_MATRIX_DIR
#define PEELF_BIN_MATRIX_DIR "bin-matrix"
#endif

namespace {

[[nodiscard]] std::filesystem::path fixture_path(std::string_view name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

[[nodiscard]] std::filesystem::path bin_matrix_path(std::string_view name) {
    return std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
}

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in.good()) << path.string();
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

class LeWriter {
public:
    void u8(std::uint8_t v) { buf_.push_back(v); }

    void u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    }

    void u32(std::uint32_t v) {
        for (unsigned shift = 0u; shift < 32u; shift += 8u) {
            buf_.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFFu));
        }
    }

    void i32(std::int32_t v) { u32(static_cast<std::uint32_t>(v)); }

    void u64(std::uint64_t v) {
        u32(static_cast<std::uint32_t>(v & 0xFFFF'FFFFULL));
        u32(static_cast<std::uint32_t>((v >> 32u) & 0xFFFF'FFFFULL));
    }

    void u32_be(std::uint32_t v) {
        buf_.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    }

    void bytes(std::span<const std::uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    void cstr(std::string_view sv) {
        buf_.insert(buf_.end(), sv.begin(), sv.end());
        buf_.push_back(0u);
    }

    void fixed_str(std::string_view sv, std::size_t len) {
        for (std::size_t i = 0u; i < len; ++i) {
            buf_.push_back(i < sv.size() ? static_cast<std::uint8_t>(sv[i]) : 0u);
        }
    }

    void align_to(std::size_t alignment, std::uint8_t fill = 0u) {
        if (alignment <= 1u) {
            return;
        }
        const std::size_t rem = buf_.size() % alignment;
        if (rem != 0u) {
            buf_.resize(buf_.size() + (alignment - rem), fill);
        }
    }

    void pad_to(std::size_t target, std::uint8_t fill = 0u) {
        if (buf_.size() < target) {
            buf_.resize(target, fill);
        }
    }

    void put_u16(std::size_t off, std::uint16_t v) {
        buf_[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
        buf_[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    }

    void put_u32(std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0u; i < 4u; ++i) {
            buf_[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
        }
    }

    void put_u64(std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0u; i < 8u; ++i) {
            buf_[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
        }
    }

    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return buf_; }
    [[nodiscard]] std::vector<std::uint8_t> take() noexcept { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_{};
};

// ---------------------------------------------------------------------------
// Synthetic Mach-O 64 (x86_64 & ARM64) + Universal FAT builder for P7-2/P7-8
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::uint8_t> build_golden_macho64_slice(
    std::uint32_t cpu_type,
    std::uint32_t cpu_subtype,
    std::span<const std::uint8_t> code_bytes) {
    using namespace peelf::macho;
    LeWriter w{};

    w.u32(kMhMagic64);
    w.u32(cpu_type);
    w.u32(cpu_subtype);
    w.u32(kMhExecute);
    w.u32(0u); // ncmds
    w.u32(0u); // sizeofcmds
    w.u32(kMhPie | kMhTwoLevel | kMhNoHeapExecution);
    w.u32(0u);

    std::uint32_t ncmds = 0u;
    const std::size_t cmds_start = w.size();

    // 1. __PAGEZERO
    w.u32(kLcSegment64);
    w.u32(72u);
    w.fixed_str("__PAGEZERO", 16u);
    w.u64(0u);
    w.u64(0x100000000ULL);
    w.u64(0u);
    w.u64(0u);
    w.u32(kVmProtNone);
    w.u32(kVmProtNone);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 2. __TEXT with __text @ 0x100000800 (fileoff 0x800)
    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str("__TEXT", 16u);
    w.u64(0x100000000ULL);
    w.u64(0x1000ULL);
    w.u64(0u);
    w.u64(0x1000ULL);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str("__text", 16u);
    w.fixed_str("__TEXT", 16u);
    w.u64(0x100000800ULL);
    w.u64(code_bytes.size());
    w.u32(0x800u);
    w.u32(2u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSAttrSomeInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 3. __DATA with __data @ 0x100001000 (fileoff 0x1000)
    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str("__DATA", 16u);
    w.u64(0x100001000ULL);
    w.u64(0x1000ULL);
    w.u64(0x1000ULL);
    w.u64(0x200ULL);
    w.u32(kVmProtRead | kVmProtWrite);
    w.u32(kVmProtRead | kVmProtWrite);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str("__data", 16u);
    w.fixed_str("__DATA", 16u);
    w.u64(0x100001000ULL);
    w.u64(8u);
    w.u32(0x1000u);
    w.u32(3u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 4. __LINKEDIT @ fileoff 0x1200..0x1400
    w.u32(kLcSegment64);
    w.u32(72u);
    w.fixed_str("__LINKEDIT", 16u);
    w.u64(0x100002000ULL);
    w.u64(0x1000ULL);
    w.u64(0x1200ULL);
    w.u64(0x200ULL);
    w.u32(kVmProtRead);
    w.u32(kVmProtRead);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 5. LC_MAIN -> entryoff 0x800 (VA 0x100000800)
    w.u32(kLcMain);
    w.u32(24u);
    w.u64(0x800ULL);
    w.u64(0u);
    ++ncmds;

    // 6. LC_LOAD_DYLIB (/usr/lib/libSystem.B.dylib)
    {
        const std::size_t cmd_off = w.size();
        w.u32(kLcLoadDylib);
        w.u32(0u);
        w.u32(24u);
        w.u32(2u);
        w.u32(0x00010000u);
        w.u32(0x00010000u);
        w.cstr("/usr/lib/libSystem.B.dylib");
        w.align_to(8u);
        w.put_u32(cmd_off + 4u, static_cast<std::uint32_t>(w.size() - cmd_off));
        ++ncmds;
    }

    // 7. LC_SYMTAB with 1 exported function `_golden_entry` + 1 imported `_puts`
    const std::uint32_t symoff = 0x1200u;
    const std::uint32_t stroff = 0x1220u;
    const std::string strtab("\0_golden_entry\0_puts\0", 21u);
    w.u32(kLcSymtab);
    w.u32(24u);
    w.u32(symoff);
    w.u32(2u);
    w.u32(stroff);
    w.u32(static_cast<std::uint32_t>(strtab.size()));
    ++ncmds;

    const std::size_t cmds_end = w.size();
    w.put_u32(16u, ncmds);
    w.put_u32(20u, static_cast<std::uint32_t>(cmds_end - cmds_start));

    w.pad_to(0x800u, 0u);
    w.bytes(code_bytes);
    w.pad_to(0x1200u, 0u);

    // nlist_64[0]: _golden_entry (N_SECT | N_EXT, sect=1, n_value=0x100000800)
    w.u32(1u);
    w.u8(static_cast<std::uint8_t>(kNSect | kNExt));
    w.u8(1u);
    w.u16(0u);
    w.u64(0x100000800ULL);

    // nlist_64[1]: _puts (N_UNDF | N_EXT, library ordinal = 1 in n_desc high byte)
    w.u32(15u);
    w.u8(static_cast<std::uint8_t>(kNUndf | kNExt));
    w.u8(0u);
    w.u16(0x0100u);
    w.u64(0u);

    w.pad_to(stroff, 0u);
    w.bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(strtab.data()), strtab.size()));
    w.pad_to(0x1400u, 0u);
    return w.take();
}

[[nodiscard]] std::vector<std::uint8_t> build_universal_macho(
    std::span<const std::uint8_t> x64_slice,
    std::span<const std::uint8_t> arm64_slice) {
    using namespace peelf::macho;
    LeWriter fat{};
    fat.u32_be(kFatMagic);
    fat.u32_be(2u);

    constexpr std::uint32_t kSlice0Off = 0x1000u;
    const std::uint32_t kSlice1Off =
        static_cast<std::uint32_t>((kSlice0Off + x64_slice.size() + 0xFFFu) & ~std::size_t{0xFFFu});

    // Slice 0: x86_64
    fat.u32_be(kCpuTypeX86_64);
    fat.u32_be(kCpuSubtypeX86_64All);
    fat.u32_be(kSlice0Off);
    fat.u32_be(static_cast<std::uint32_t>(x64_slice.size()));
    fat.u32_be(12u);

    // Slice 1: ARM64
    fat.u32_be(kCpuTypeArm64);
    fat.u32_be(kCpuSubtypeArm64All);
    fat.u32_be(kSlice1Off);
    fat.u32_be(static_cast<std::uint32_t>(arm64_slice.size()));
    fat.u32_be(12u);

    fat.pad_to(kSlice0Off, 0u);
    fat.bytes(x64_slice);
    fat.pad_to(kSlice1Off, 0u);
    fat.bytes(arm64_slice);
    return fat.take();
}

// ---------------------------------------------------------------------------
// Synthetic MSF 7.00 PDB + PE32+ x86_64 Call Fixture for P7-11
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::uint8_t> make_cv_record(std::uint16_t kind,
                                                       std::span<const std::uint8_t> body) {
    LeWriter rec{};
    rec.u16(0u);
    rec.u16(kind);
    rec.bytes(body);
    rec.align_to(4u, 0u);
    auto out = rec.take();
    out[0] = static_cast<std::uint8_t>((out.size() - 2u) & 0xFFu);
    out[1] = static_cast<std::uint8_t>(((out.size() - 2u) >> 8u) & 0xFFu);
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> build_msf7_pdb_for_pe64(
    const std::array<std::uint8_t, 16>& guid,
    std::uint32_t age) {
    constexpr std::uint32_t kBlockSize = 4096u;

    // Stream 1: PDB Info
    LeWriter info{};
    info.u32(20000404u);
    info.u32(0x66009999u);
    info.u32(age);
    info.bytes(guid);
    info.u32(0u); // cbNames
    info.u32(0u);
    info.u32(0u);
    info.u32(0u);
    info.u32(0u);

    // Stream 2: Minimal empty TPI V80
    LeWriter tpi{};
    tpi.u32(20040203u);
    tpi.u32(56u);
    tpi.u32(0x1000u);
    tpi.u32(0x1000u);
    tpi.u32(0u);
    tpi.u16(0xFFFFu);
    tpi.u16(0xFFFFu);
    tpi.u32(4u);
    tpi.u32(0x3FFFFu);
    for (int i = 0; i < 6; ++i) {
        tpi.u32(0u);
    }

    // Stream 4: Symbol Record Stream (S_PUB32 for pdb_caller @ seg 1 + 0x0, pdb_target_leaf @ seg 1 + 0x20)
    LeWriter sym_records{};
    {
        LeWriter b{};
        b.u32(0x00000002u); // CV_PUBSYMFLAGS_FUNCTION
        b.u32(0x0u);
        b.u16(1u);
        b.cstr("pdb_caller");
        sym_records.bytes(make_cv_record(0x110Eu, b.data()));
    }
    {
        LeWriter b{};
        b.u32(0x00000002u); // CV_PUBSYMFLAGS_FUNCTION
        b.u32(0x20u);
        b.u16(1u);
        b.cstr("pdb_target_leaf");
        sym_records.bytes(make_cv_record(0x110Eu, b.data()));
    }

    // Stream 5: Module stream with S_GPROC32 sizes (pdb_caller = 14 bytes, pdb_target_leaf = 6 bytes)
    LeWriter mod_syms{};
    mod_syms.u32(4u); // CV_SIGNATURE_C13
    {
        LeWriter b{};
        b.u32(0u);
        b.u32(0u);
        b.u32(0u);
        b.u32(14u); // code_len
        b.u32(0u);
        b.u32(14u);
        b.u32(0u);
        b.u32(0x0u);
        b.u16(1u);
        b.u8(0u);
        b.cstr("pdb_caller");
        mod_syms.bytes(make_cv_record(0x1110u, b.data()));
    }
    {
        LeWriter b{};
        b.u32(0u);
        b.u32(0u);
        b.u32(0u);
        b.u32(6u); // code_len
        b.u32(0u);
        b.u32(6u);
        b.u32(0u);
        b.u32(0x20u);
        b.u16(1u);
        b.u8(0u);
        b.cstr("pdb_target_leaf");
        mod_syms.bytes(make_cv_record(0x1110u, b.data()));
    }
    const auto mod_sym_bytes = mod_syms.take();

    // Stream 6: Section Header stream (.text @ RVA 0x1000)
    LeWriter sec_hdr{};
    sec_hdr.fixed_str(".text", 8u);
    sec_hdr.u32(0x200u);
    sec_hdr.u32(0x1000u);
    sec_hdr.u32(0x200u);
    sec_hdr.u32(0x200u);
    sec_hdr.u32(0u);
    sec_hdr.u32(0u);
    sec_hdr.u16(0u);
    sec_hdr.u16(0u);
    sec_hdr.u32(0x60000020u);

    // Stream 3: DBI stream referencing sym_record_stream=4, module stream=5, section_hdr_stream=6
    LeWriter mod_sub{};
    mod_sub.u32(0u);
    for (int i = 0; i < 7; ++i) {
        mod_sub.u32(0u);
    }
    mod_sub.u16(0u);
    mod_sub.u16(5u); // stream 5
    mod_sub.u32(static_cast<std::uint32_t>(mod_sym_bytes.size()));
    mod_sub.u32(0u);
    mod_sub.u32(0u);
    mod_sub.u16(0u);
    mod_sub.u16(0u);
    mod_sub.u32(0u);
    mod_sub.u32(0u);
    mod_sub.u32(0u);
    mod_sub.cstr("main.obj");
    mod_sub.cstr("main.obj");
    mod_sub.align_to(4u, 0u);

    LeWriter opt_dbg{};
    for (int i = 0; i < 11; ++i) {
        opt_dbg.u16(i == 5 ? 6u : 0xFFFFu);
    }

    LeWriter dbi{};
    dbi.i32(-1);
    dbi.u32(19990903u);
    dbi.u32(age);
    dbi.u16(0xFFFFu);
    dbi.u16(0x8E0Bu);
    dbi.u16(0xFFFFu);
    dbi.u16(0u);
    dbi.u16(4u); // SymRecordStream = 4
    dbi.u16(0u);
    dbi.i32(static_cast<std::int32_t>(mod_sub.size()));
    dbi.i32(0);
    dbi.i32(0);
    dbi.i32(0);
    dbi.i32(0);
    dbi.u32(0u);
    dbi.i32(static_cast<std::int32_t>(opt_dbg.size()));
    dbi.i32(0);
    dbi.u16(0u);
    dbi.u16(0x8664u);
    dbi.u32(0u);
    dbi.bytes(mod_sub.data());
    dbi.bytes(opt_dbg.data());

    const std::array<std::vector<std::uint8_t>, 7> streams = {
        std::vector<std::uint8_t>{}, // 0: Old dir
        info.take(),                 // 1: PDB Info
        tpi.take(),                  // 2: TPI
        dbi.take(),                  // 3: DBI
        sym_records.take(),          // 4: SymRecords
        mod_sym_bytes,               // 5: Mod 0
        sec_hdr.take(),              // 6: SectionHdr
    };

    // Blocks: 0=SuperBlock, 1=FPM1, 2=FPM2, 3..8=streams 1..6 (each <= 4096), 9=Dir, 10=BlockMap
    LeWriter dir{};
    dir.u32(static_cast<std::uint32_t>(streams.size()));
    for (const auto& s : streams) {
        dir.u32(static_cast<std::uint32_t>(s.size()));
    }
    std::uint32_t next_blk = 3u;
    std::array<std::uint32_t, 7> assigned_blk{};
    for (std::size_t i = 0u; i < streams.size(); ++i) {
        if (!streams[i].empty()) {
            assigned_blk[i] = next_blk++;
            dir.u32(assigned_blk[i]);
        }
    }
    const std::uint32_t dir_blk = next_blk++;
    const std::uint32_t map_blk = next_blk++;
    const std::uint32_t total_blks = next_blk;
    const auto dir_bytes = dir.take();

    std::vector<std::uint8_t> pdb(static_cast<std::size_t>(total_blks) * kBlockSize, 0u);
    static constexpr std::array<char, 32> kMsfMagic = {
        'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ',
        'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1A', 'D', 'S', '\0', '\0', '\0',
    };
    std::memcpy(pdb.data(), kMsfMagic.data(), kMsfMagic.size());
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (std::size_t b = 0u; b < 4u; ++b) {
            pdb[off + b] = static_cast<std::uint8_t>((v >> (8u * b)) & 0xFFu);
        }
    };
    put32(32u, kBlockSize);
    put32(36u, 1u);
    put32(40u, total_blks);
    put32(44u, static_cast<std::uint32_t>(dir_bytes.size()));
    put32(48u, 0u);
    put32(52u, map_blk);

    for (std::size_t i = 0u; i < streams.size(); ++i) {
        if (!streams[i].empty()) {
            std::memcpy(pdb.data() + static_cast<std::size_t>(assigned_blk[i]) * kBlockSize,
                        streams[i].data(),
                        streams[i].size());
        }
    }
    std::memcpy(pdb.data() + static_cast<std::size_t>(dir_blk) * kBlockSize,
                dir_bytes.data(),
                dir_bytes.size());
    put32(static_cast<std::size_t>(map_blk) * kBlockSize, dir_blk);
    return pdb;
}

[[nodiscard]] std::vector<std::uint8_t> build_stripped_pe64_with_rsds(
    const std::array<std::uint8_t, 16>& guid,
    std::uint32_t age,
    std::string_view rsds_pdb_path) {
    std::vector<std::uint8_t> pe(0x800u, 0u);
    auto put16 = [&](std::size_t off, std::uint16_t v) {
        pe[off] = static_cast<std::uint8_t>(v & 0xFFu);
        pe[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    };
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (std::size_t b = 0u; b < 4u; ++b) {
            pe[off + b] = static_cast<std::uint8_t>((v >> (8u * b)) & 0xFFu);
        }
    };

    pe[0] = 'M';
    pe[1] = 'Z';
    put32(0x3Cu, 0x80u);
    pe[0x80u] = 'P';
    pe[0x81u] = 'E';
    put16(0x84u, 0x8664u); // AMD64
    put16(0x86u, 2u);      // .text + .rdata
    put16(0x94u, 0xF0u);
    put16(0x96u, 0x0022u);

    const std::size_t opt = 0x98u;
    put16(opt + 0u, 0x020Bu);  // PE32+
    put32(opt + 16u, 0x1000u); // EntryPoint = 0x1000 (pdb_caller)
    put32(opt + 24u, 0x40000000u);
    put32(opt + 28u, 0x00000001u); // ImageBase = 0x140000000
    put32(opt + 32u, 0x1000u);
    put32(opt + 36u, 0x200u);
    put16(opt + 70u, 0x0160u); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
    put32(opt + 56u, 0x3000u);
    put32(opt + 60u, 0x200u);
    put32(opt + 108u, 16u);
    put32(opt + 160u, 0x2000u); // Debug directory @ RVA 0x2000
    put32(opt + 164u, 28u);

    const std::size_t sh1 = opt + 0xF0u;
    std::memcpy(pe.data() + sh1, ".text\0\0\0", 8u);
    put32(sh1 + 8u, 0x40u);
    put32(sh1 + 12u, 0x1000u);
    put32(sh1 + 16u, 0x200u);
    put32(sh1 + 20u, 0x200u);
    put32(sh1 + 36u, 0x60000020u);

    const std::size_t sh2 = sh1 + 40u;
    std::memcpy(pe.data() + sh2, ".rdata\0\0", 8u);
    put32(sh2 + 8u, 0x200u);
    put32(sh2 + 12u, 0x2000u);
    put32(sh2 + 16u, 0x200u);
    put32(sh2 + 20u, 0x400u);
    put32(sh2 + 36u, 0x40000040u);

    // .text @ file 0x200 (VA 0x140001000):
    //   0x140001000: 48 83 EC 28          sub rsp, 0x28
    //   0x140001004: E8 17 00 00 00       call 0x140001020 (pdb_target_leaf)
    //   0x140001009: 48 83 C4 28          add rsp, 0x28
    //   0x14000100D: C3                   ret
    //   0x14000100E..0x14000101F: CC padding
    //   0x140001020: B8 2A 00 00 00       mov eax, 42
    //   0x140001025: C3                   ret
    std::fill(pe.begin() + 0x200, pe.begin() + 0x240, 0xCCu);
    const std::array<std::uint8_t, 14> caller_code = {
        0x48u, 0x83u, 0xECu, 0x28u,
        0xE8u, 0x17u, 0x00u, 0x00u, 0x00u,
        0x48u, 0x83u, 0xC4u, 0x28u,
        0xC3u,
    };
    const std::array<std::uint8_t, 6> callee_code = {
        0xB8u, 0x2Au, 0x00u, 0x00u, 0x00u, 0xC3u,
    };
    std::memcpy(pe.data() + 0x200u, caller_code.data(), caller_code.size());
    std::memcpy(pe.data() + 0x220u, callee_code.data(), callee_code.size());

    // IMAGE_DEBUG_DIRECTORY @ file 0x400 (RVA 0x2000) -> RSDS record @ file 0x420 (RVA 0x2020)
    const std::uint32_t cv_len = static_cast<std::uint32_t>(24u + rsds_pdb_path.size() + 1u);
    put32(0x400u + 12u, 2u); // IMAGE_DEBUG_TYPE_CODEVIEW
    put32(0x400u + 16u, cv_len);
    put32(0x400u + 20u, 0x2020u);
    put32(0x400u + 24u, 0x420u);

    std::memcpy(pe.data() + 0x420u, "RSDS", 4u);
    std::memcpy(pe.data() + 0x424u, guid.data(), guid.size());
    put32(0x434u, age);
    std::memcpy(pe.data() + 0x438u, rsds_pdb_path.data(), rsds_pdb_path.size());
    pe[0x438u + rsds_pdb_path.size()] = 0u;
    return pe;
}

// ---------------------------------------------------------------------------
// Synthetic Stripped ELF64 + Split DWARF (.gnu_debuglink + .note.gnu.build-id)
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint32_t gnu_debuglink_crc32(std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFF'FFFFu;
    for (const std::uint8_t b : bytes) {
        crc ^= b;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1u) ^ ((crc & 1u) != 0u ? 0xEDB8'8320u : 0u);
        }
    }
    return ~crc;
}

[[nodiscard]] std::vector<std::uint8_t> build_split_dwarf_elf64(
    std::span<const std::uint8_t> build_id) {
    // Build minimal DWARF v4 .debug_str, .debug_abbrev, .debug_info with 2 subprograms:
    //   - _ZN8dwarf_ns6callerEi @ 0x401000 (size 14)
    //   - _ZN8dwarf_ns11leaf_targetEi @ 0x401020 (size 6)
    LeWriter dstr{};
    dstr.u8(0u);
    const auto s_cu = static_cast<std::uint32_t>(dstr.size());
    dstr.cstr("unit.cpp");
    const auto s_caller_name = static_cast<std::uint32_t>(dstr.size());
    dstr.cstr("caller");
    const auto s_caller_link = static_cast<std::uint32_t>(dstr.size());
    dstr.cstr("_ZN8dwarf_ns6callerEi");
    const auto s_leaf_name = static_cast<std::uint32_t>(dstr.size());
    dstr.cstr("leaf_target");
    const auto s_leaf_link = static_cast<std::uint32_t>(dstr.size());
    dstr.cstr("_ZN8dwarf_ns11leaf_targetEi");

    LeWriter abbrev{};
    // Abbrev 1: DW_TAG_compile_unit (0x11), children=1, DW_AT_name (0x03) DW_FORM_strp (0x0E)
    abbrev.u8(1u); abbrev.u8(0x11u); abbrev.u8(1u);
    abbrev.u8(0x03u); abbrev.u8(0x0Eu);
    abbrev.u8(0u); abbrev.u8(0u);
    // Abbrev 2: DW_TAG_subprogram (0x2E), children=0:
    //   DW_AT_name(0x03)=strp(0x0E), DW_AT_MIPS_linkage_name/linkage_name(0x6E)=strp(0x0E),
    //   DW_AT_low_pc(0x11)=addr(0x01), DW_AT_high_pc(0x12)=data8(0x07)
    abbrev.u8(2u); abbrev.u8(0x2Eu); abbrev.u8(0u);
    abbrev.u8(0x03u); abbrev.u8(0x0Eu);
    abbrev.u8(0x6Eu); abbrev.u8(0x0Eu);
    abbrev.u8(0x11u); abbrev.u8(0x01u);
    abbrev.u8(0x12u); abbrev.u8(0x07u);
    abbrev.u8(0u); abbrev.u8(0u);
    abbrev.u8(0u);

    LeWriter info{};
    info.u32(0u);  // unit_length patched below
    info.u16(4u);  // DWARF v4
    info.u32(0u);  // abbrev_offset = 0
    info.u8(8u);   // addr_size = 8
    info.u8(1u);   // CU
    info.u32(s_cu);
    info.u8(2u);
    info.u32(s_caller_name);
    info.u32(s_caller_link);
    info.u64(0x401000ULL);
    info.u64(14ULL);
    info.u8(2u);
    info.u32(s_leaf_name);
    info.u32(s_leaf_link);
    info.u64(0x401020ULL);
    info.u64(6ULL);
    info.u8(0u); // end CU children
    info.put_u32(0u, static_cast<std::uint32_t>(info.size() - 4u));

    LeWriter note{};
    note.u32(4u); // namesz = "GNU\0"
    note.u32(static_cast<std::uint32_t>(build_id.size()));
    note.u32(3u); // NT_GNU_BUILD_ID
    note.cstr("GNU");
    note.bytes(build_id);
    note.align_to(4u, 0u);

    const std::string shstrtab(
        "\0.note.gnu.build-id\0.debug_info\0.debug_abbrev\0.debug_str\0.shstrtab\0", 67u);

    LeWriter elf{};
    elf.u8(0x7Fu); elf.u8('E'); elf.u8('L'); elf.u8('F');
    elf.u8(2u); elf.u8(1u); elf.u8(1u);
    elf.pad_to(16u, 0u);
    elf.u16(2u);  // ET_EXEC
    elf.u16(62u); // EM_X86_64
    elf.u32(1u);
    elf.u64(0x401000ULL);
    elf.u64(0u);  // e_phoff
    elf.u64(0u);  // e_shoff patched below
    elf.u32(0u);
    elf.u16(64u);
    elf.u16(56u);
    elf.u16(0u);
    elf.u16(64u);
    elf.u16(6u);  // NULL + 5 sections
    elf.u16(5u);  // .shstrtab

    elf.align_to(8u, 0u);
    const auto note_off = elf.size();
    elf.bytes(note.data());

    elf.align_to(8u, 0u);
    const auto info_off = elf.size();
    elf.bytes(info.data());

    elf.align_to(8u, 0u);
    const auto abbrev_off = elf.size();
    elf.bytes(abbrev.data());

    elf.align_to(8u, 0u);
    const auto str_off = elf.size();
    elf.bytes(dstr.data());

    const auto shstr_off = elf.size();
    elf.bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(shstrtab.data()), shstrtab.size()));

    elf.align_to(8u, 0u);
    const auto shoff = elf.size();
    elf.put_u64(40u, shoff);

    auto emit_shdr = [&](std::uint32_t name,
                         std::uint32_t type,
                         std::uint64_t flags,
                         std::uint64_t addr,
                         std::uint64_t off,
                         std::uint64_t sz) {
        elf.u32(name);
        elf.u32(type);
        elf.u64(flags);
        elf.u64(addr);
        elf.u64(off);
        elf.u64(sz);
        elf.u32(0u);
        elf.u32(0u);
        elf.u64(4u);
        elf.u64(0u);
    };

    emit_shdr(0u, 0u, 0u, 0u, 0u, 0u);                                    // 0: NULL
    emit_shdr(1u, 7u, 2u, 0x400200ULL, note_off, note.size());            // 1: .note.gnu.build-id (SHT_NOTE)
    emit_shdr(20u, 1u, 0u, 0u, info_off, info.size());                    // 2: .debug_info
    emit_shdr(32u, 1u, 0u, 0u, abbrev_off, abbrev.size());                // 3: .debug_abbrev
    emit_shdr(46u, 1u, 0u, 0u, str_off, dstr.size());                     // 4: .debug_str
    emit_shdr(57u, 3u, 0u, 0u, shstr_off, shstrtab.size());               // 5: .shstrtab
    return elf.take();
}

[[nodiscard]] std::vector<std::uint8_t> build_stripped_elf64_with_debuglink_and_buildid(
    std::span<const std::uint8_t> build_id,
    std::optional<std::pair<std::string_view, std::uint32_t>> debuglink) {
    // .text @ VA 0x401000, file offset 0x1000:
    //   0x401000: 48 83 EC 08          sub rsp, 8
    //   0x401004: E8 17 00 00 00       call 0x401020 (dwarf_ns::leaf_target(int))
    //   0x401009: 48 83 C4 08          add rsp, 8
    //   0x40100D: C3                   ret
    //   0x401020: B8 07 00 00 00       mov eax, 7
    //   0x401025: C3                   ret
    std::vector<std::uint8_t> text(0x30u, 0x90u);
    const std::array<std::uint8_t, 14> caller = {
        0x48u, 0x83u, 0xECu, 0x08u,
        0xE8u, 0x17u, 0x00u, 0x00u, 0x00u,
        0x48u, 0x83u, 0xC4u, 0x08u,
        0xC3u,
    };
    const std::array<std::uint8_t, 6> leaf = {
        0xB8u, 0x07u, 0x00u, 0x00u, 0x00u, 0xC3u,
    };
    std::memcpy(text.data(), caller.data(), caller.size());
    std::memcpy(text.data() + 0x20u, leaf.data(), leaf.size());

    LeWriter note{};
    note.u32(4u);
    note.u32(static_cast<std::uint32_t>(build_id.size()));
    note.u32(3u); // NT_GNU_BUILD_ID
    note.cstr("GNU");
    note.bytes(build_id);
    note.align_to(4u, 0u);

    LeWriter dbglink{};
    if (debuglink.has_value()) {
        dbglink.cstr(debuglink->first);
        dbglink.align_to(4u, 0u);
        dbglink.u32(debuglink->second);
    }

    const std::string shstrtab(
        "\0.text\0.note.gnu.build-id\0.gnu_debuglink\0.shstrtab\0", 51u);

    LeWriter elf{};
    elf.u8(0x7Fu); elf.u8('E'); elf.u8('L'); elf.u8('F');
    elf.u8(2u); elf.u8(1u); elf.u8(1u);
    elf.pad_to(16u, 0u);
    elf.u16(2u);  // ET_EXEC
    elf.u16(62u); // EM_X86_64
    elf.u32(1u);
    elf.u64(0x401000ULL);
    elf.u64(64u); // e_phoff
    elf.u64(0u);  // e_shoff patched below
    elf.u32(0u);
    elf.u16(64u);
    elf.u16(56u);
    elf.u16(1u);  // 1 PT_LOAD
    elf.u16(64u);
    const std::uint16_t shnum = debuglink.has_value() ? 5u : 4u;
    const std::uint16_t shstrndx = static_cast<std::uint16_t>(shnum - 1u);
    elf.u16(shnum);
    elf.u16(shstrndx);

    // PT_LOAD covering 0..0x1100 at 0x400000 (PF_R | PF_X)
    elf.u32(1u);
    elf.u32(5u);
    elf.u64(0u);
    elf.u64(0x400000ULL);
    elf.u64(0x400000ULL);
    elf.u64(0x1000ULL + text.size());
    elf.u64(0x1000ULL + text.size());
    elf.u64(0x1000ULL);

    elf.pad_to(0x200u, 0u);
    const auto note_off = elf.size();
    elf.bytes(note.data());

    elf.pad_to(0x1000u, 0u);
    const auto text_off = elf.size();
    elf.bytes(text);

    const auto dbglink_off = elf.size();
    if (debuglink.has_value()) {
        elf.bytes(dbglink.data());
    }

    const auto shstr_off = elf.size();
    elf.bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(shstrtab.data()), shstrtab.size()));

    elf.align_to(8u, 0u);
    const auto shoff = elf.size();
    elf.put_u64(40u, shoff);

    auto emit_shdr = [&](std::uint32_t name,
                         std::uint32_t type,
                         std::uint64_t flags,
                         std::uint64_t addr,
                         std::uint64_t off,
                         std::uint64_t sz) {
        elf.u32(name);
        elf.u32(type);
        elf.u64(flags);
        elf.u64(addr);
        elf.u64(off);
        elf.u64(sz);
        elf.u32(0u);
        elf.u32(0u);
        elf.u64(16u);
        elf.u64(0u);
    };

    emit_shdr(0u, 0u, 0u, 0u, 0u, 0u);                              // 0: NULL
    emit_shdr(1u, 1u, 6u, 0x401000ULL, text_off, text.size());      // 1: .text
    emit_shdr(7u, 7u, 2u, 0x400200ULL, note_off, note.size());      // 2: .note.gnu.build-id
    if (debuglink.has_value()) {
        emit_shdr(26u, 1u, 0u, 0u, dbglink_off, dbglink.size());    // 3: .gnu_debuglink
    }
    emit_shdr(41u, 3u, 0u, 0u, shstr_off, shstrtab.size());         // last: .shstrtab
    return elf.take();
}

} // namespace

// ===========================================================================
// P7-2 & P7-8: Deterministic Golden Summary Assertions Across PE/ELF/Mach-O
// ===========================================================================

TEST(GoldenBinarySummary, Pe32AndPe32PlusCanonicalSummariesMatchGoldenExpectations) {
    struct PeGoldenCase {
        std::filesystem::path path;
        peelf::Architecture arch;
        bool is_64bit;
        peelf::ImageKind kind;
        bool expect_exports;
    };

    const std::array<PeGoldenCase, 4> cases = {{
        {bin_matrix_path("pe-windows-x86-32-le-callgraph.dll"),
         peelf::Architecture::X86, false, peelf::ImageKind::SharedLibrary, true},
        {bin_matrix_path("pe-windows-x86_64-64-le-callgraph.dll"),
         peelf::Architecture::X86_64, true, peelf::ImageKind::SharedLibrary, true},
        {fixture_path("known-win-x86.exe"),
         peelf::Architecture::X86, false, peelf::ImageKind::Executable, false},
        {fixture_path("known-win-x64.exe"),
         peelf::Architecture::X86_64, true, peelf::ImageKind::Executable, false},
    }};

    for (const PeGoldenCase& tc : cases) {
        SCOPED_TRACE(tc.path.string());
        const auto raw = read_file_bytes(tc.path);
        ASSERT_FALSE(raw.empty());
        const auto parsed = peelf::parse_image(raw);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        const peelf::IBinaryImage& img = **parsed;

        EXPECT_EQ(img.format(), peelf::Format::PE);
        EXPECT_EQ(img.architecture(), tc.arch);
        EXPECT_EQ(img.endianness(), peelf::Endianness::Little);
        EXPECT_EQ(img.is_64bit(), tc.is_64bit);
        EXPECT_EQ(img.kind(), tc.kind);
        EXPECT_GT(img.image_base(), 0u);
        EXPECT_GT(img.entry_point(), img.image_base());
        EXPECT_FALSE(img.sections().empty());
        EXPECT_TRUE(std::ranges::any_of(img.sections(), [](const peelf::Section& s) {
            return s.name == ".text" && s.executable;
        }));
        if (tc.expect_exports) {
            EXPECT_FALSE(img.exports().empty());
        }

        const auto audit = peelf::audit_security(img, raw);
        EXPECT_FALSE(audit.findings.empty());
        EXPECT_EQ(audit.pass_count + audit.note_count + audit.warning_count + audit.error_count,
                  audit.findings.size());
    }
}

TEST(GoldenBinarySummary, ElfCrossArchitectureMatrixMatchesGoldenSummaryContract) {
    struct ElfGoldenCase {
        const char* so_name;
        peelf::Architecture arch;
        peelf::Endianness endian;
        bool is_64bit;
    };

    const std::array<ElfGoldenCase, 7> cases = {{
        {"elf-linux-x86-32-le-callgraph.so", peelf::Architecture::X86, peelf::Endianness::Little, false},
        {"elf-linux-x86_64-64-le-callgraph.so", peelf::Architecture::X86_64, peelf::Endianness::Little, true},
        {"elf-linux-arm-32-le-callgraph.so", peelf::Architecture::ARM, peelf::Endianness::Little, false},
        {"elf-linux-arm64-64-le-callgraph.so", peelf::Architecture::ARM64, peelf::Endianness::Little, true},
        {"elf-linux-riscv64-64-le-callgraph.so", peelf::Architecture::RISCV64, peelf::Endianness::Little, true},
        {"elf-linux-mips64-64-be-callgraph.so", peelf::Architecture::MIPS64, peelf::Endianness::Big, true},
        {"elf-linux-ppc64-64-be-callgraph.so", peelf::Architecture::PowerPC64, peelf::Endianness::Big, true},
    }};

    for (const ElfGoldenCase& tc : cases) {
        SCOPED_TRACE(tc.so_name);
        const auto path = bin_matrix_path(tc.so_name);
        const auto raw = read_file_bytes(path);
        ASSERT_FALSE(raw.empty());

        const auto parsed = peelf::parse_image(raw);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        const peelf::IBinaryImage& img = **parsed;

        EXPECT_EQ(img.format(), peelf::Format::ELF);
        EXPECT_EQ(img.kind(), peelf::ImageKind::SharedLibrary);
        EXPECT_EQ(img.architecture(), tc.arch);
        EXPECT_EQ(img.endianness(), tc.endian);
        EXPECT_EQ(img.is_64bit(), tc.is_64bit);
        EXPECT_FALSE(img.sections().empty());
        EXPECT_FALSE(img.segments().empty());
        EXPECT_FALSE(img.exports().empty());
        EXPECT_FALSE(img.symbols().empty());

        const auto audit = peelf::audit_security(img, raw);
        EXPECT_FALSE(audit.findings.empty());
        EXPECT_TRUE(std::ranges::any_of(audit.findings, [](const peelf::SecurityFinding& f) {
            return f.rule_id.starts_with("ELF2");
        }));
    }
}

TEST(GoldenBinarySummary, MachO64AndUniversalContainerMatchGoldenSummaryAndSecurityFlags) {
    const std::array<std::uint8_t, 8> x64_code = {
        0x55u, 0x48u, 0x89u, 0xE5u, 0x31u, 0xC0u, 0x5Du, 0xC3u,
    };
    const std::array<std::uint8_t, 8> arm64_code = {
        0x00u, 0x00u, 0x80u, 0xD2u, 0xC0u, 0x03u, 0x5Fu, 0xD6u,
    };

    const auto x64_macho = build_golden_macho64_slice(
        peelf::macho::kCpuTypeX86_64, peelf::macho::kCpuSubtypeX86_64All, x64_code);
    const auto arm64_macho = build_golden_macho64_slice(
        peelf::macho::kCpuTypeArm64, peelf::macho::kCpuSubtypeArm64All, arm64_code);
    const auto universal = build_universal_macho(x64_macho, arm64_macho);

    const auto container = peelf::inspect_binary_container(universal);
    ASSERT_TRUE(container.has_value()) << container.error().message;
    EXPECT_TRUE(container->is_universal_container);
    ASSERT_EQ(container->slices.size(), 2u);
    EXPECT_EQ(container->slices[0].arch, peelf::Architecture::X86_64);
    EXPECT_EQ(container->slices[1].arch, peelf::Architecture::ARM64);

    for (std::size_t idx = 0u; idx < 2u; ++idx) {
        peelf::BinaryOpenOptions opts{};
        opts.selected_slice_index = idx;
        const auto parsed = peelf::parse_image(universal, opts);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        const peelf::IBinaryImage& img = **parsed;

        EXPECT_EQ(img.format(), peelf::Format::MachO);
        EXPECT_EQ(img.kind(), peelf::ImageKind::Executable);
        EXPECT_EQ(img.architecture(),
                  idx == 0u ? peelf::Architecture::X86_64 : peelf::Architecture::ARM64);
        EXPECT_EQ(img.endianness(), peelf::Endianness::Little);
        EXPECT_TRUE(img.is_64bit());
        EXPECT_EQ(img.image_base(), 0x100000000ULL);
        EXPECT_EQ(img.entry_point(), 0x100000800ULL);
        EXPECT_EQ(img.sections().size(), 2u);
        EXPECT_EQ(img.segments().size(), 4u);
        ASSERT_EQ(img.imports().size(), 1u);
        EXPECT_EQ(img.imports()[0].name, "_puts");
        ASSERT_EQ(img.exports().size(), 1u);
        EXPECT_EQ(img.exports()[0].name, "_golden_entry");

        const auto audit = peelf::audit_security(img, universal);
        EXPECT_TRUE(std::ranges::any_of(audit.findings, [](const peelf::SecurityFinding& f) {
            return f.rule_id == "MACHO4001" && f.severity == peelf::SecuritySeverity::Pass;
        }));
    }
}

// ===========================================================================
// P7-11: PDB & Split-DWARF Symbols -> LinearDisassemblyView Headers & Calls
// ===========================================================================

TEST(DebugSymbolDisassemblyIntegration, PdbGuidAgeMatchMismatchOfflineGuaranteeAndDisassemblyLabels) {
    peelf_test::ScopedTempDir tmp("peelf_p7_11_pdb");
    constexpr std::array<std::uint8_t, 16> kExpectedGuid = {
        0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u,
        0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x43u,
    };
    constexpr std::array<std::uint8_t, 16> kWrongGuid = {
        0xFFu, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u,
        0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x00u,
    };
    constexpr std::uint32_t kExpectedAge = 3u;

    const auto exe_path = tmp.write_bytes(
        "target.exe",
        build_stripped_pe64_with_rsds(kExpectedGuid, kExpectedAge, "C:\\build\\out\\target.pdb"));
    const auto matching_pdb_path = tmp.write_bytes(
        "target.pdb", build_msf7_pdb_for_pe64(kExpectedGuid, kExpectedAge));
    const auto wrong_guid_pdb_path = tmp.write_bytes(
        "wrong_guid.pdb", build_msf7_pdb_for_pe64(kWrongGuid, kExpectedAge));
    const auto wrong_age_pdb_path = tmp.write_bytes(
        "wrong_age.pdb", build_msf7_pdb_for_pe64(kExpectedGuid, kExpectedAge + 1u));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(exe_path.string()));
    ASSERT_NE(model.image(), nullptr);

    // 1. GUID mismatch and Age mismatch must be rejected cleanly.
    const auto bad_guid = viewer::load_pdb_debug_symbols(wrong_guid_pdb_path, *model.image());
    EXPECT_EQ(bad_guid.status, viewer::DebugSymbolLoadStatus::BackendError);
    EXPECT_NE(bad_guid.diagnostic.find("GUID"), std::string::npos);

    const auto bad_age = viewer::load_pdb_debug_symbols(wrong_age_pdb_path, *model.image());
    EXPECT_EQ(bad_age.status, viewer::DebugSymbolLoadStatus::BackendError);
    EXPECT_NE(bad_age.diagnostic.find("age"), std::string::npos);

    // 2. Offline guarantee: an HTTP URL or UNC path in RSDS must never make network calls
    //    when no local sibling PDB exists.
    {
        peelf_test::ScopedTempDir isolated("peelf_p7_11_offline");
        const auto remote_exe_path = isolated.write_bytes(
            "remote.exe",
            build_stripped_pe64_with_rsds(
                kExpectedGuid, kExpectedAge, "http://127.0.0.1:1/symbols/remote.pdb"));
        const auto raw = read_file_bytes(remote_exe_path);
        const auto img = peelf::parse_image(raw);
        ASSERT_TRUE(img.has_value());

        const auto t0 = std::chrono::steady_clock::now();
        const auto found = viewer::find_local_codeview_pdb(**img, remote_exe_path);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        EXPECT_FALSE(found.has_value());
        EXPECT_LT(elapsed.count(), 500);
    }

    // 3. Matching sibling PDB auto-discovery + symbol enumeration -> LinearDisassemblyView!
    const auto discovered = viewer::find_local_codeview_pdb(*model.image(), exe_path);
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(discovered->filename(), matching_pdb_path.filename());

    const auto loaded = viewer::load_pdb_debug_symbols(*discovered, *model.image());
    ASSERT_EQ(loaded.status, viewer::DebugSymbolLoadStatus::Loaded) << loaded.diagnostic;
    EXPECT_GE(loaded.symbols.size(), 2u);

    model.apply_debug_symbol_result(loaded);

    viewer::LinearDisassemblyView linear{};
    ASSERT_TRUE(linear.sync_with_model(model, false, false));

    const viewer::LinearMetadataContext ctx{
        .symbols = &model.symbol_index(),
        .functions = &model.function_index(),
        .references = nullptr,
        .annotations = nullptr,
        .source_lines = model.source_lines(),
        .demangle_symbols = true,
    };

    const auto caller_inst = linear.find_instruction_at_address(0x140001000ULL);
    ASSERT_TRUE(caller_inst.has_value());
    const auto caller_meta = viewer::describe_instruction_row(*caller_inst, ctx);
    EXPECT_TRUE(caller_meta.has_header_banner);
    EXPECT_EQ(caller_meta.symbol_name, "pdb_caller");
    EXPECT_NE(caller_meta.header_banner.find("pdb_caller"), std::string::npos);

    const auto call_inst = linear.find_instruction_at_address(0x140001004ULL);
    ASSERT_TRUE(call_inst.has_value());
    EXPECT_EQ(call_inst->flow, viewer::InstructionFlow::Call);
    ASSERT_TRUE(call_inst->branch_target.has_value());
    EXPECT_EQ(*call_inst->branch_target, 0x140001020ULL);
    EXPECT_EQ(model.resolve_address_symbol(*call_inst->branch_target), "pdb_target_leaf");

    const auto callee_inst = linear.find_instruction_at_address(0x140001020ULL);
    ASSERT_TRUE(callee_inst.has_value());
    const auto callee_meta = viewer::describe_instruction_row(*callee_inst, ctx);
    EXPECT_TRUE(callee_meta.has_header_banner);
    EXPECT_EQ(callee_meta.symbol_name, "pdb_target_leaf");
}

TEST(DebugSymbolDisassemblyIntegration, SplitDwarfDebuglinkAndBuildIdResolveDisassemblyHeadersAndCallLabels) {
    peelf_test::ScopedTempDir tmp("peelf_p7_11_dwarf");
    constexpr std::array<std::uint8_t, 8> kBuildId = {
        0xABu, 0xCDu, 0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu,
    };
    const auto debug_elf = build_split_dwarf_elf64(kBuildId);
    const std::uint32_t crc = gnu_debuglink_crc32(debug_elf);

    // 1. `.gnu_debuglink` discovery in `.debug/` subdirectory + CRC32 verification.
    const auto debug_subdir = tmp.path() / ".debug";
    std::filesystem::create_directories(debug_subdir);
    const auto debuglink_target = debug_subdir / "app.elf.debug";
    {
        std::ofstream out(debuglink_target, std::ios::binary);
        out.write(reinterpret_cast<const char*>(debug_elf.data()),
                  static_cast<std::streamsize>(debug_elf.size()));
    }

    const auto stripped_with_link = tmp.write_bytes(
        "app.elf",
        build_stripped_elf64_with_debuglink_and_buildid(
            kBuildId, std::pair<std::string_view, std::uint32_t>{"app.elf.debug", crc}));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(stripped_with_link.string()));
    ASSERT_NE(model.image(), nullptr);

    const auto found_via_link = viewer::find_local_elf_debug_file(*model.image(), stripped_with_link);
    ASSERT_TRUE(found_via_link.has_value());
    EXPECT_EQ(std::filesystem::weakly_canonical(*found_via_link),
              std::filesystem::weakly_canonical(debuglink_target));

    // 2. `.note.gnu.build-id` discovery via `<extra_dir>/.build-id/ab/cd123456789abc.debug`.
    peelf_test::ScopedTempDir buildid_root("peelf_p7_11_buildid");
    const auto buildid_dir = buildid_root.path() / ".build-id" / "ab";
    std::filesystem::create_directories(buildid_dir);
    const auto buildid_debug_path = buildid_dir / "cd123456789abc.debug";
    {
        std::ofstream out(buildid_debug_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(debug_elf.data()),
                  static_cast<std::streamsize>(debug_elf.size()));
    }
    const auto stripped_buildid_only = buildid_root.write_bytes(
        "stripped_only_buildid.elf",
        build_stripped_elf64_with_debuglink_and_buildid(kBuildId, std::nullopt));
    const auto raw_no_link = read_file_bytes(stripped_buildid_only);
    const auto img_no_link = peelf::parse_image(raw_no_link);
    ASSERT_TRUE(img_no_link.has_value());

    const std::array<std::filesystem::path, 1> extra_dirs = {buildid_root.path()};
    const auto found_via_buildid =
        viewer::find_local_elf_debug_file(**img_no_link, stripped_buildid_only, extra_dirs);
    ASSERT_TRUE(found_via_buildid.has_value());
    EXPECT_EQ(std::filesystem::weakly_canonical(*found_via_buildid),
              std::filesystem::weakly_canonical(buildid_debug_path));

    // 3. Load split DWARF into BinaryModel -> verify LinearDisassemblyView headers & call target labels!
    const auto dwarf_res = viewer::load_dwarf_debug_symbols(*found_via_link, *model.image());
    ASSERT_EQ(dwarf_res.status, viewer::DebugSymbolLoadStatus::Loaded) << dwarf_res.diagnostic;
    model.apply_debug_symbol_result(dwarf_res);
    model.set_demangle_symbols(true);

    viewer::LinearDisassemblyView linear{};
    ASSERT_TRUE(linear.sync_with_model(model, false, false));

    const viewer::LinearMetadataContext ctx{
        .symbols = &model.symbol_index(),
        .functions = &model.function_index(),
        .references = nullptr,
        .annotations = nullptr,
        .source_lines = model.source_lines(),
        .demangle_symbols = true,
    };

    const auto caller_inst = linear.find_instruction_at_address(0x401000ULL);
    ASSERT_TRUE(caller_inst.has_value());
    const auto caller_meta = viewer::describe_instruction_row(*caller_inst, ctx);
    EXPECT_TRUE(caller_meta.has_header_banner);
    EXPECT_EQ(caller_meta.symbol_name, "dwarf_ns::caller(int)");

    const auto call_inst = linear.find_instruction_at_address(0x401004ULL);
    ASSERT_TRUE(call_inst.has_value());
    EXPECT_EQ(call_inst->flow, viewer::InstructionFlow::Call);
    ASSERT_TRUE(call_inst->branch_target.has_value());
    EXPECT_EQ(*call_inst->branch_target, 0x401020ULL);
    EXPECT_EQ(model.resolve_address_symbol(*call_inst->branch_target),
              "dwarf_ns::leaf_target(int)");

    model.set_demangle_symbols(false);
    EXPECT_EQ(model.resolve_address_symbol(*call_inst->branch_target),
              "_ZN8dwarf_ns11leaf_targetEi");
}

// ===========================================================================
// §15 Stretches: Bounded Safe Regex Search & Headless CSV Summary Export
// ===========================================================================

TEST(MemorySearchRegex, BoundedRegexMatchesCrossWindowAndRejectsUnsafeOrInvalidPatterns) {
    // Build a 6 KiB buffer (> 2 KiB window size) with NUL-delimited URLs and tokens.
    std::vector<std::uint8_t> hay(6144u, 0u);
    auto place_str = [&](std::size_t off, std::string_view s) {
        std::memcpy(hay.data() + off, s.data(), s.size());
    };
    place_str(64u, "prefix https://api.example.org/v1/status suffix");
    place_str(1900u, "boundary http://edge.internal.local:8080/healthz end"); // crosses 2048-256 overlap!
    place_str(4200u, "UPPER HTTPS://SECURE.EXAMPLE.COM/LOGIN");

    peelf::MemorySearchQuery query{};
    query.kind = peelf::SearchValueKind::RegexText;
    query.query_text = "https?://[A-Za-z0-9.:/_-]+";
    query.case_sensitive = true;

    const auto cs_res = peelf::search_buffer(hay, 0x400000ULL, query);
    ASSERT_TRUE(cs_res.has_value()) << cs_res.error().message;
    ASSERT_EQ(cs_res->hits.size(), 2u);
    EXPECT_EQ(cs_res->hits[0].address, 0x400000ULL + 71u);
    EXPECT_EQ(cs_res->hits[0].decoded_preview, "https://api.example.org/v1/statu...");
    EXPECT_EQ(cs_res->hits[1].address, 0x400000ULL + 1909u);
    EXPECT_EQ(cs_res->hits[1].match_length, 39u);

    // Case-insensitive finds all 3 URLs without duplicating boundary hits.
    query.case_sensitive = false;
    const auto ci_res = peelf::search_buffer(hay, 0x400000ULL, query);
    ASSERT_TRUE(ci_res.has_value()) << ci_res.error().message;
    ASSERT_EQ(ci_res->hits.size(), 3u);
    EXPECT_EQ(ci_res->hits[2].address, 0x400000ULL + 4206u);

    // Also verify `search_process_memory` over a mock live heap region!
    class MockHeapSession final : public peelf::IProcessSession {
    public:
        explicit MockHeapSession(std::vector<std::uint8_t> mem) : mem_(std::move(mem)) {
            info_.pid = 9001u;
            info_.is_64bit = true;
        }
        [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
        [[nodiscard]] bool is_alive() const noexcept override { return true; }
        [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
            return std::vector<peelf::MemoryRegion>{};
        }
        [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
            return std::vector<peelf::ModuleInfo>{};
        }
        [[nodiscard]] peelf::Result<std::size_t> read_memory(
            std::uint64_t address,
            std::span<std::uint8_t> out) override {
            if (address < 0x700000ULL || (address - 0x700000ULL) >= mem_.size()) {
                return peelf::make_error("unmapped");
            }
            const auto off = static_cast<std::size_t>(address - 0x700000ULL);
            const std::size_t n = std::min(out.size(), mem_.size() - off);
            std::copy_n(mem_.data() + off, n, out.data());
            return n;
        }
    private:
        peelf::ProcessInfo info_{};
        std::vector<std::uint8_t> mem_;
    };

    MockHeapSession heap_session(hay);
    peelf::MemoryRegion heap_reg{};
    heap_reg.start_address = 0x700000ULL;
    heap_reg.end_address = 0x700000ULL + hay.size();
    heap_reg.kind = peelf::MemoryRegionKind::Heap;
    heap_reg.protection.readable = true;
    heap_reg.protection.writable = true;

    const std::array<peelf::MemoryRegion, 1> regs = {heap_reg};
    const auto live_res = peelf::search_process_memory(heap_session, regs, query);
    ASSERT_TRUE(live_res.has_value()) << live_res.error().message;
    EXPECT_EQ(live_res->hits.size(), 3u);

    // Adversarial & malformed regexes must return an error without throwing!
    const std::array<std::string, 6> rejected_patterns = {
        "[unterminated",
        "(a+)+$",                       // catastrophic nested quantifier
        "([a-zA-Z0-9_]+)*!",            // nested quantified group
        "(ab)\\1",                      // backreference disallowed
        "a{128}",                       // brace repeat > 64
        std::string(520u, 'x'),         // > 512-byte pattern limit
    };
    for (const std::string& bad : rejected_patterns) {
        SCOPED_TRACE(bad.substr(0u, 48u));
        peelf::MemorySearchQuery bad_q{};
        bad_q.kind = peelf::SearchValueKind::RegexText;
        bad_q.query_text = bad;
        const auto bad_res = peelf::search_buffer(hay, 0u, bad_q);
        ASSERT_FALSE(bad_res.has_value());
        EXPECT_FALSE(bad_res.error().message.empty());
    }
}

TEST(HeadlessCsvExport, EmitsRfc4180CsvForCliAndEscapesSpecialCharacters) {
    const auto so_path = bin_matrix_path("elf-linux-x86_64-64-le-callgraph.so");
    const std::string so_arg = so_path.string();
    const std::array<std::string_view, 4> cli_args = {
        "--headless",
        so_arg,
        "--format",
        "csv",
    };

    std::ostringstream out_stream;
    std::ostringstream err_stream;
    const auto exit_code = peelf::try_run_headless_or_help_cli(cli_args, out_stream, err_stream);
    ASSERT_TRUE(exit_code.has_value());
    EXPECT_EQ(*exit_code, 0) << err_stream.str();

    const std::string csv = out_stream.str();
    ASSERT_FALSE(csv.empty());
    // RFC 4180 requires CRLF line endings and exact header row.
    EXPECT_TRUE(csv.starts_with(
        "record_type,target_path,format,architecture,id_or_name,library_or_category,"
        "severity_or_flags,address_hex,size_bytes,detail\r\n"));
    EXPECT_NE(csv.find("\r\nsummary,"), std::string::npos);
    EXPECT_NE(csv.find("\r\nsection,"), std::string::npos);
    EXPECT_NE(csv.find("\r\nexport,"), std::string::npos);
    EXPECT_NE(csv.find("\r\nfinding,"), std::string::npos);

    // Direct RFC 4180 escaping check with embedded commas, quotes, and newlines.
    peelf::HeadlessAnalysisReport synthetic{};
    synthetic.binary_path = "dir,with,comma/\"quoted\".bin";
    synthetic.sha256 = "deadbeef";
    synthetic.file_size = 128u;
    peelf::SecurityFinding finding{};
    finding.rule_id = "TEST0001";
    finding.domain = peelf::SecurityRuleDomain::ELF;
    finding.severity = peelf::SecuritySeverity::Warning;
    finding.subject = "sec,\"one\"";
    finding.summary = "line1\nline2, comma";
    synthetic.security.findings.push_back(finding);

    const std::string escaped_csv = peelf::format_headless_report_csv(synthetic);
    EXPECT_NE(escaped_csv.find("\"dir,with,comma/\"\"quoted\"\".bin\""), std::string::npos);
    EXPECT_NE(escaped_csv.find("\"sec,\"\"one\"\": line1\nline2, comma\""), std::string::npos);
}
