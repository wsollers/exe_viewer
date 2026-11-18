// Integration & unit tests for WU-26b:
// - Mach-O security audit rules (MACHO4001..MACHO4006) with structural vs cryptographic
//   code-signature provenance separation
// - `--headless --slice <index|arch>` JSON & SARIF 2.1.0 CLI parity
// - Mach-O ExecutableSettings extraction & JSON serialization
// - Mach-O DependencyGraph (@rpath / @loader_path / @executable_path, LC_REEXPORT_DYLIB,
//   and honest macOS dyld shared-cache classification)
// - Thin & Universal Mach-O BinaryDiff slice matching and Mach-O metadata deltas
// - Viewer BinaryModel::select_container_slice Universal container slice switching

#include <gtest/gtest.h>

#include "model/binary_model.hpp"
#include "test_temp_dir.hpp"

#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/dependency_tree.hpp>
#include <peelf/executable_settings.hpp>
#include <peelf/macho_image.hpp>
#include <peelf/provenance.hpp>
#include <peelf/security_audit.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

class ByteWriter {
public:
    explicit ByteWriter(bool big_endian = false) : big_(big_endian) {}

    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return buf_; }
    [[nodiscard]] std::vector<std::uint8_t>& bytes() noexcept { return buf_; }

    void pad_to(std::size_t offset, std::uint8_t fill = 0u) {
        if (buf_.size() < offset) {
            buf_.resize(offset, fill);
        }
    }

    void align_to(std::size_t alignment) {
        if (alignment <= 1u) {
            return;
        }
        const std::size_t rem = buf_.size() % alignment;
        if (rem != 0u) {
            buf_.resize(buf_.size() + (alignment - rem), 0u);
        }
    }

    void u8(std::uint8_t v) { buf_.push_back(v); }

    void u16(std::uint16_t v) {
        const std::size_t off = buf_.size();
        buf_.resize(off + 2u);
        put_u16(off, v);
    }

    void u32(std::uint32_t v) {
        const std::size_t off = buf_.size();
        buf_.resize(off + 4u);
        put_u32(off, v);
    }

    void u64(std::uint64_t v) {
        const std::size_t off = buf_.size();
        buf_.resize(off + 8u);
        put_u64(off, v);
    }

    void u32_be(std::uint32_t v) {
        buf_.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    }

    void fixed_str16(std::string_view sv) {
        const std::size_t n = std::min<std::size_t>(sv.size(), 16u);
        for (std::size_t i = 0u; i < n; ++i) {
            buf_.push_back(static_cast<std::uint8_t>(sv[i]));
        }
        for (std::size_t i = n; i < 16u; ++i) {
            buf_.push_back(0u);
        }
    }

    void raw(std::span<const std::uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    void cstr(std::string_view sv) {
        for (const char c : sv) {
            buf_.push_back(static_cast<std::uint8_t>(c));
        }
        buf_.push_back(0u);
    }

    void put_u16(std::size_t off, std::uint16_t v) {
        if (big_) {
            buf_[off + 0u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
            buf_[off + 1u] = static_cast<std::uint8_t>(v & 0xFFu);
        } else {
            buf_[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
            buf_[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
        }
    }

    void put_u32(std::size_t off, std::uint32_t v) {
        if (big_) {
            buf_[off + 0u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
            buf_[off + 1u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
            buf_[off + 2u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
            buf_[off + 3u] = static_cast<std::uint8_t>(v & 0xFFu);
        } else {
            buf_[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
            buf_[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
            buf_[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
            buf_[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
        }
    }

    void put_u64(std::size_t off, std::uint64_t v) {
        if (big_) {
            put_u32(off + 0u, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFu));
            put_u32(off + 4u, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
        } else {
            put_u32(off + 0u, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
            put_u32(off + 4u, static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFu));
        }
    }

private:
    bool big_{false};
    std::vector<std::uint8_t> buf_{};
};

void write_bytes_to_disk(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(ofs.good()) << "Failed to open " << path.string();
    if (!bytes.empty()) {
        ofs.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    ASSERT_TRUE(ofs.good());
}

void append_dylib_cmd(ByteWriter& w,
                      std::uint32_t cmd,
                      std::string_view path,
                      std::uint32_t current_ver = 0x00010000u,
                      std::uint32_t compat_ver = 0x00010000u) {
    const std::size_t start = w.size();
    w.u32(cmd);
    w.u32(0u);
    w.u32(24u);
    w.u32(2u);
    w.u32(current_ver);
    w.u32(compat_ver);
    w.cstr(path);
    w.align_to(8u);
    w.put_u32(start + 4u, static_cast<std::uint32_t>(w.size() - start));
}

void append_rpath_cmd(ByteWriter& w, std::string_view path) {
    const std::size_t start = w.size();
    w.u32(peelf::macho::kLcRpath);
    w.u32(0u);
    w.u32(12u);
    w.cstr(path);
    w.align_to(8u);
    w.put_u32(start + 4u, static_cast<std::uint32_t>(w.size() - start));
}

void append_dylinker_cmd(ByteWriter& w, std::string_view path) {
    const std::size_t start = w.size();
    w.u32(peelf::macho::kLcLoadDylinker);
    w.u32(0u);
    w.u32(12u);
    w.cstr(path);
    w.align_to(8u);
    w.put_u32(start + 4u, static_cast<std::uint32_t>(w.size() - start));
}

std::vector<std::uint8_t> build_code_signature_blob(std::string_view identifier,
                                                    std::string_view team_id,
                                                    std::uint32_t cd_flags,
                                                    bool include_nonempty_cms) {
    ByteWriter cd(true);
    cd.u32_be(peelf::macho::kCsMagicCodeDirectory);
    cd.u32_be(0u);
    cd.u32_be(0x00020400u);
    cd.u32_be(cd_flags);
    cd.u32_be(0u);
    cd.u32_be(52u);
    cd.u32_be(0u);
    cd.u32_be(1u);
    cd.u32_be(0x1000u);
    cd.u8(32u);
    cd.u8(2u);
    cd.u8(0u);
    cd.u8(12u);
    cd.u32_be(0u);
    cd.u32_be(0u);
    cd.u32_be(0u);
    cd.cstr(identifier);
    if (!team_id.empty()) {
        const auto team_off = static_cast<std::uint32_t>(cd.size());
        cd.cstr(team_id);
        cd.put_u32(48u, team_off);
    }
    const auto hash_off = static_cast<std::uint32_t>(cd.size());
    cd.put_u32(16u, hash_off);
    for (int i = 0; i < 32; ++i) {
        cd.u8(static_cast<std::uint8_t>(0xB0 + i));
    }
    cd.put_u32(4u, static_cast<std::uint32_t>(cd.size()));

    ByteWriter cms(true);
    cms.u32_be(peelf::macho::kCsMagicBlobWrapper);
    cms.u32_be(0u);
    if (include_nonempty_cms) {
        const std::array<std::uint8_t, 6> pkcs7_stub = {0x30u, 0x82u, 0x00u, 0x02u, 0x05u, 0x00u};
        cms.raw(pkcs7_stub);
    }
    cms.put_u32(4u, static_cast<std::uint32_t>(cms.size()));

    ByteWriter sb(true);
    const std::uint32_t idx_end = 12u + 2u * 8u;
    const std::uint32_t cd_pos = idx_end;
    const std::uint32_t cms_pos = cd_pos + static_cast<std::uint32_t>(cd.size());
    const std::uint32_t total = cms_pos + static_cast<std::uint32_t>(cms.size());

    sb.u32_be(peelf::macho::kCsMagicEmbeddedSignature);
    sb.u32_be(total);
    sb.u32_be(2u);
    sb.u32_be(peelf::macho::kCsSlotCodeDirectory);
    sb.u32_be(cd_pos);
    sb.u32_be(peelf::macho::kCsSlotSignatureSlot);
    sb.u32_be(cms_pos);
    sb.raw(cd.bytes());
    sb.raw(cms.bytes());
    return sb.bytes();
}

struct DylibSpec {
    std::uint32_t cmd{peelf::macho::kLcLoadDylib};
    std::string name{};
    std::uint32_t current_ver{0x00010000u};
    std::uint32_t compat_ver{0x00010000u};
};

struct UndefinedSymSpec {
    std::string name{};
    std::uint8_t library_ordinal{1u};
};

struct DefinedSymSpec {
    std::string name{};
    std::uint64_t va{0x100000C00ULL};
    bool exported{true};
};

struct SyntheticMachOSpec {
    std::uint32_t cpu_type{peelf::macho::kCpuTypeArm64};
    std::uint32_t cpu_subtype{
        peelf::macho::kCpuSubtypeArm64e | peelf::macho::kCpuSubtypePtrAuthAbi | (2u << 24u)};
    std::uint32_t file_type{peelf::macho::kMhExecute};
    std::uint32_t flags{
        peelf::macho::kMhPie | peelf::macho::kMhTwoLevel | peelf::macho::kMhNoHeapExecution |
        peelf::macho::kMhDyldLink | peelf::macho::kMhNoUndefs};
    bool include_pagezero{true};
    std::uint64_t pagezero_size{0x100000000ULL};
    bool rwx_data_segment{false};
    bool include_objc_section{true};
    bool include_restrict_section{true};
    std::string dylinker{"/usr/lib/dyld"};
    std::string id_dylib{};
    std::vector<DylibSpec> dylibs{
        DylibSpec{peelf::macho::kLcLoadDylib, "/usr/lib/libSystem.B.dylib", 0x05210000u, 0x00010000u},
    };
    std::vector<std::string> rpaths{"@executable_path/../Frameworks"};
    std::array<std::uint8_t, 16> uuid{
        0xAAu, 0xBBu, 0xCCu, 0xDDu, 0x11u, 0x22u, 0x33u, 0x44u,
        0x55u, 0x66u, 0x77u, 0x88u, 0x99u, 0x00u, 0xEEu, 0xFFu};
    bool include_uuid{true};
    bool include_build_version{true};
    std::uint32_t minos{0x000E0200u}; // 14.2
    std::uint32_t sdk{0x000F0000u};   // 15.0
    bool include_encryption_info{true};
    std::uint32_t cryptid{0u};
    bool include_code_signature{true};
    bool corrupt_code_signature{false};
    std::string cs_identifier{"com.example.hardened"};
    std::string cs_team_id{"TEAM123456"};
    std::uint32_t cs_flags{peelf::macho::kCsRuntime};
    bool cs_nonempty_cms{true};
    std::vector<DefinedSymSpec> defined_symbols{
        DefinedSymSpec{"_main", 0x100000C00ULL, true},
    };
    std::vector<UndefinedSymSpec> undef_symbols{
        UndefinedSymSpec{"___stack_chk_fail", 1u},
        UndefinedSymSpec{"___stack_chk_guard", 1u},
        UndefinedSymSpec{"_objc_release", 1u},
    };
    std::array<std::uint8_t, 8> text_bytes{
        0xFDu, 0x7Bu, 0xBFu, 0xA9u, 0xC0u, 0x03u, 0x5Fu, 0xD6u};
};

std::vector<std::uint8_t> build_synthetic_macho64(const SyntheticMachOSpec& spec) {
    using namespace peelf::macho;
    ByteWriter w(false);

    w.u32(kMhMagic64);
    w.u32(spec.cpu_type);
    w.u32(spec.cpu_subtype);
    w.u32(spec.file_type);
    w.u32(0u);
    w.u32(0u);
    w.u32(spec.flags);
    w.u32(0u);

    std::uint32_t ncmds = 0u;
    const std::size_t cmds_start = w.size();

    if (spec.include_pagezero && spec.file_type == kMhExecute) {
        w.u32(kLcSegment64);
        w.u32(72u);
        w.fixed_str16("__PAGEZERO");
        w.u64(0u);
        w.u64(spec.pagezero_size);
        w.u64(0u);
        w.u64(0u);
        w.u32(kVmProtNone);
        w.u32(kVmProtNone);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // __TEXT with __text @ 0x100000C00 (section index 1)
    {
        w.u32(kLcSegment64);
        w.u32(72u + 80u);
        w.fixed_str16("__TEXT");
        w.u64(0x100000000ULL);
        w.u64(0x1000ULL);
        w.u64(0u);
        w.u64(0x1000ULL);
        w.u32(kVmProtRead | kVmProtExecute);
        w.u32(kVmProtRead | kVmProtExecute);
        w.u32(1u);
        w.u32(0u);

        w.fixed_str16("__text");
        w.fixed_str16("__TEXT");
        w.u64(0x100000C00ULL);
        w.u64(spec.text_bytes.size());
        w.u32(0xC00u);
        w.u32(2u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSAttrPureInstructions | kSAttrSomeInstructions | kSRegular);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // __DATA with __data (+ optional __objc_imageinfo)
    {
        const std::uint32_t nsects = spec.include_objc_section ? 2u : 1u;
        const std::uint32_t data_prot = spec.rwx_data_segment
            ? (kVmProtRead | kVmProtWrite | kVmProtExecute)
            : (kVmProtRead | kVmProtWrite);
        w.u32(kLcSegment64);
        w.u32(72u + nsects * 80u);
        w.fixed_str16("__DATA");
        w.u64(0x100001000ULL);
        w.u64(0x1000ULL);
        w.u64(0x1000ULL);
        w.u64(0x1000ULL);
        w.u32(data_prot);
        w.u32(data_prot);
        w.u32(nsects);
        w.u32(0u);

        w.fixed_str16("__data");
        w.fixed_str16("__DATA");
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

        if (spec.include_objc_section) {
            w.fixed_str16("__objc_imageinfo");
            w.fixed_str16("__DATA");
            w.u64(0x100001010ULL);
            w.u64(8u);
            w.u32(0x1010u);
            w.u32(2u);
            w.u32(0u);
            w.u32(0u);
            w.u32(kSRegular);
            w.u32(0u);
            w.u32(0u);
            w.u32(0u);
        }
        ++ncmds;
    }

    if (spec.include_restrict_section) {
        w.u32(kLcSegment64);
        w.u32(72u + 80u);
        w.fixed_str16("__RESTRICT");
        w.u64(0x100002000ULL);
        w.u64(0x1000ULL);
        w.u64(0u);
        w.u64(0u);
        w.u32(kVmProtNone);
        w.u32(kVmProtNone);
        w.u32(1u);
        w.u32(0u);

        w.fixed_str16("__restrict");
        w.fixed_str16("__RESTRICT");
        w.u64(0x100002000ULL);
        w.u64(0u);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSRegular);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // __LINKEDIT @ file offset 0x2000
    const std::size_t linkedit_off = w.size();
    {
        w.u32(kLcSegment64);
        w.u32(72u);
        w.fixed_str16("__LINKEDIT");
        w.u64(0x100003000ULL);
        w.u64(0x2000ULL);
        w.u64(0x2000ULL);
        w.u64(0u); // patched below
        w.u32(kVmProtRead);
        w.u32(kVmProtRead);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    if (spec.file_type == kMhExecute) {
        w.u32(kLcMain);
        w.u32(24u);
        w.u64(0xC00ULL);
        w.u64(0u);
        ++ncmds;

        if (!spec.dylinker.empty()) {
            append_dylinker_cmd(w, spec.dylinker);
            ++ncmds;
        }
    }

    if (!spec.id_dylib.empty()) {
        append_dylib_cmd(w, kLcIdDylib, spec.id_dylib);
        ++ncmds;
    }

    for (const DylibSpec& dy : spec.dylibs) {
        append_dylib_cmd(w, dy.cmd, dy.name, dy.current_ver, dy.compat_ver);
        ++ncmds;
    }

    for (const std::string& rp : spec.rpaths) {
        append_rpath_cmd(w, rp);
        ++ncmds;
    }

    if (spec.include_uuid) {
        w.u32(kLcUuid);
        w.u32(24u);
        w.raw(spec.uuid);
        ++ncmds;
    }

    if (spec.include_build_version) {
        w.u32(kLcBuildVersion);
        w.u32(32u);
        w.u32(kPlatformMacOS);
        w.u32(spec.minos);
        w.u32(spec.sdk);
        w.u32(1u);
        w.u32(1u); // clang
        w.u32(0x00100000u); // 16.0
        ++ncmds;
    }

    if (spec.include_encryption_info) {
        w.u32(kLcEncryptionInfo64);
        w.u32(24u);
        w.u32(0xC00u);
        w.u32(0x400u);
        w.u32(spec.cryptid);
        w.u32(0u);
        ++ncmds;
    }

    const std::size_t symtab_cmd_off = w.size();
    {
        w.u32(kLcSymtab);
        w.u32(24u);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    const std::size_t codesig_cmd_off = w.size();
    if (spec.include_code_signature) {
        w.u32(kLcCodeSignature);
        w.u32(16u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    const auto sizeofcmds = static_cast<std::uint32_t>(w.size() - cmds_start);
    w.put_u32(16u, ncmds);
    w.put_u32(20u, sizeofcmds);

    // __TEXT,__text @ 0xC00
    w.pad_to(0xC00u);
    w.raw(spec.text_bytes);

    // __DATA,__data @ 0x1000 (+ __objc_imageinfo @ 0x1010)
    w.pad_to(0x1000u);
    const std::array<std::uint8_t, 8> data_bytes = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    w.raw(data_bytes);
    if (spec.include_objc_section) {
        w.pad_to(0x1010u);
        const std::array<std::uint8_t, 8> objc_info = {0u, 0u, 0u, 0u, 0x40u, 0u, 0u, 0u};
        w.raw(objc_info);
    }

    // __LINKEDIT @ 0x2000
    w.pad_to(0x2000u);
    ByteWriter strtab(false);
    strtab.u8(0u);

    struct RawNlist64 {
        std::uint32_t strx{};
        std::uint8_t type{};
        std::uint8_t sect{};
        std::uint16_t desc{};
        std::uint64_t value{};
    };
    std::vector<RawNlist64> nlists;

    for (const DefinedSymSpec& ds : spec.defined_symbols) {
        const auto strx = static_cast<std::uint32_t>(strtab.size());
        strtab.cstr(ds.name);
        nlists.push_back(RawNlist64{
            .strx = strx,
            .type = static_cast<std::uint8_t>(kNSect | (ds.exported ? kNExt : 0u)),
            .sect = 1u,
            .desc = 0u,
            .value = ds.va,
        });
    }

    for (const UndefinedSymSpec& us : spec.undef_symbols) {
        const auto strx = static_cast<std::uint32_t>(strtab.size());
        strtab.cstr(us.name);
        nlists.push_back(RawNlist64{
            .strx = strx,
            .type = static_cast<std::uint8_t>(kNUndf | kNExt),
            .sect = 0u,
            .desc = static_cast<std::uint16_t>(static_cast<std::uint16_t>(us.library_ordinal) << 8u),
            .value = 0u,
        });
    }

    const auto symoff = static_cast<std::uint32_t>(w.size());
    for (const RawNlist64& nl : nlists) {
        w.u32(nl.strx);
        w.u8(nl.type);
        w.u8(nl.sect);
        w.u16(nl.desc);
        w.u64(nl.value);
    }
    const auto stroff = static_cast<std::uint32_t>(w.size());
    w.raw(strtab.bytes());
    w.align_to(16u);

    w.put_u32(symtab_cmd_off + 8u, symoff);
    w.put_u32(symtab_cmd_off + 12u, static_cast<std::uint32_t>(nlists.size()));
    w.put_u32(symtab_cmd_off + 16u, stroff);
    w.put_u32(symtab_cmd_off + 20u, static_cast<std::uint32_t>(strtab.size()));

    if (spec.include_code_signature) {
        const auto cs_off = static_cast<std::uint32_t>(w.size());
        std::vector<std::uint8_t> cs_blob;
        if (spec.corrupt_code_signature) {
            cs_blob = {0xDEu, 0xADu, 0xBEu, 0xEFu, 0x00u, 0x00u, 0x00u, 0x08u};
        } else {
            cs_blob = build_code_signature_blob(
                spec.cs_identifier, spec.cs_team_id, spec.cs_flags, spec.cs_nonempty_cms);
        }
        w.raw(cs_blob);
        w.put_u32(codesig_cmd_off + 8u, cs_off);
        w.put_u32(codesig_cmd_off + 12u, static_cast<std::uint32_t>(cs_blob.size()));
    }

    w.align_to(16u);
    const std::uint64_t linkedit_size = w.size() - 0x2000u;
    w.put_u64(linkedit_off + 32u, std::max<std::uint64_t>(0x1000u, linkedit_size));
    w.put_u64(linkedit_off + 48u, linkedit_size);
    return w.bytes();
}

struct FatSliceInput {
    std::uint32_t cpu_type{};
    std::uint32_t cpu_subtype{};
    std::vector<std::uint8_t> bytes{};
};

std::vector<std::uint8_t> build_universal_fat32(std::span<const FatSliceInput> slices) {
    ByteWriter fat(true);
    fat.u32_be(peelf::macho::kFatMagic);
    fat.u32_be(static_cast<std::uint32_t>(slices.size()));

    const std::size_t arch_table_off = fat.size();
    for (std::size_t i = 0u; i < slices.size(); ++i) {
        fat.u32_be(slices[i].cpu_type);
        fat.u32_be(slices[i].cpu_subtype);
        fat.u32_be(0u); // offset patched below
        fat.u32_be(static_cast<std::uint32_t>(slices[i].bytes.size()));
        fat.u32_be(14u); // 2^14 = 16 KiB alignment
    }

    for (std::size_t i = 0u; i < slices.size(); ++i) {
        fat.align_to(0x4000u);
        const auto off = static_cast<std::uint32_t>(fat.size());
        fat.raw(slices[i].bytes);
        fat.put_u32(arch_table_off + i * 20u + 8u, off);
    }
    return fat.bytes();
}

const peelf::SecurityFinding* find_rule(const peelf::SecurityAuditReport& rep,
                                        std::string_view rule_id) {
    for (const peelf::SecurityFinding& f : rep.findings) {
        if (f.rule_id == rule_id) {
            return &f;
        }
    }
    return nullptr;
}

TEST(MachOAuditIntegrationTest, HardenedArm64eAuditAndUnverifiedOfflineSignatureProvenance) {
    const SyntheticMachOSpec hardened{};
    const std::vector<std::uint8_t> bytes = build_synthetic_macho64(hardened);

    auto img = peelf::open_binary_image(bytes);
    ASSERT_TRUE(img.has_value()) << img.error().message;
    ASSERT_EQ((*img)->format(), peelf::Format::MachO);

    const peelf::SecurityAuditReport audit = peelf::audit_security(**img, bytes);
    EXPECT_EQ(audit.status.availability, peelf::Availability::Available);
    EXPECT_EQ(audit.error_count, 0u);
    EXPECT_EQ(audit.warning_count, 0u);

    // Ensure PE/ELF rules never leak onto Mach-O targets.
    for (const peelf::SecurityFinding& f : audit.findings) {
        EXPECT_TRUE(f.rule_id.starts_with("MACHO"))
            << "Unexpected non-Mach-O finding on Mach-O image: " << f.rule_id;
    }

    const auto* r4001 = find_rule(audit, "MACHO4001");
    const auto* r4002 = find_rule(audit, "MACHO4002");
    const auto* r4003 = find_rule(audit, "MACHO4003");
    const auto* r4004 = find_rule(audit, "MACHO4004");
    const auto* r4005 = find_rule(audit, "MACHO4005");
    const auto* r4006 = find_rule(audit, "MACHO4006");
    ASSERT_NE(r4001, nullptr);
    ASSERT_NE(r4002, nullptr);
    ASSERT_NE(r4003, nullptr);
    ASSERT_NE(r4004, nullptr);
    ASSERT_NE(r4005, nullptr);
    ASSERT_NE(r4006, nullptr);

    EXPECT_EQ(r4001->severity, peelf::SecuritySeverity::Pass) << r4001->summary;
    EXPECT_EQ(r4002->severity, peelf::SecuritySeverity::Pass) << r4002->summary;
    EXPECT_EQ(r4003->severity, peelf::SecuritySeverity::Pass) << r4003->summary;
    // CRITICAL provenance invariant: structural LC_CODE_SIGNATURE + CS_RUNTIME is present,
    // but offline/non-macOS analysis has cryptographically_verified == false -> Note, NOT Pass!
    EXPECT_EQ(r4004->severity, peelf::SecuritySeverity::Note) << r4004->summary;
    EXPECT_NE(r4004->summary.find("unverified"), std::string::npos);
    EXPECT_NE(r4004->evidence.find("cryptographically_verified=false"), std::string::npos);
    EXPECT_EQ(r4005->severity, peelf::SecuritySeverity::Pass) << r4005->summary;
    EXPECT_EQ(r4006->severity, peelf::SecuritySeverity::Pass) << r4006->summary;
}

TEST(MachOAuditIntegrationTest, VulnerableMachOPostureTriggersExpectedSeverities) {
    SyntheticMachOSpec vuln{};
    vuln.cpu_type = peelf::macho::kCpuTypeArm64;
    vuln.cpu_subtype = peelf::macho::kCpuSubtypeArm64All; // plain arm64 (no arm64e PAC)
    vuln.flags = peelf::macho::kMhDyldLink | peelf::macho::kMhAllowStackExecution |
                 peelf::macho::kMhForceFlat; // no MH_PIE, no MH_TWOLEVEL, stack exec enabled
    vuln.include_pagezero = false;
    vuln.rwx_data_segment = true;
    vuln.include_objc_section = true;
    vuln.include_restrict_section = false;
    vuln.undef_symbols = {}; // no ___stack_chk_fail and no _objc_release
    vuln.rpaths = {"/tmp/untrusted_rpath", "../relative/escape"};
    vuln.dylibs = {
        DylibSpec{peelf::macho::kLcLoadDylib, "plugins/relative_hijack.dylib"},
        DylibSpec{peelf::macho::kLcLoadDylib, "@executable_path/../../escape.dylib"},
    };
    vuln.include_code_signature = false;
    vuln.cryptid = 1u; // encrypted segment payload!

    const std::vector<std::uint8_t> bytes = build_synthetic_macho64(vuln);
    auto img = peelf::open_binary_image(bytes);
    ASSERT_TRUE(img.has_value()) << img.error().message;

    const peelf::SecurityAuditReport audit = peelf::audit_security(**img, bytes);
    const auto* r4001 = find_rule(audit, "MACHO4001");
    const auto* r4002 = find_rule(audit, "MACHO4002");
    const auto* r4003 = find_rule(audit, "MACHO4003");
    const auto* r4004 = find_rule(audit, "MACHO4004");
    const auto* r4005 = find_rule(audit, "MACHO4005");
    const auto* r4006 = find_rule(audit, "MACHO4006");
    ASSERT_NE(r4001, nullptr);
    ASSERT_NE(r4002, nullptr);
    ASSERT_NE(r4003, nullptr);
    ASSERT_NE(r4004, nullptr);
    ASSERT_NE(r4005, nullptr);
    ASSERT_NE(r4006, nullptr);

    EXPECT_EQ(r4001->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(r4002->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(r4003->severity, peelf::SecuritySeverity::Warning);
    EXPECT_EQ(r4004->severity, peelf::SecuritySeverity::Warning);
    EXPECT_EQ(r4005->severity, peelf::SecuritySeverity::Error);
    EXPECT_EQ(r4006->severity, peelf::SecuritySeverity::Warning);

    // Corrupt LC_CODE_SIGNATURE must surface MACHO4004 Error.
    SyntheticMachOSpec corrupt_sig = SyntheticMachOSpec{};
    corrupt_sig.corrupt_code_signature = true;
    const std::vector<std::uint8_t> corrupt_bytes = build_synthetic_macho64(corrupt_sig);
    auto corrupt_img = peelf::open_binary_image(corrupt_bytes);
    ASSERT_TRUE(corrupt_img.has_value());
    const peelf::SecurityAuditReport corrupt_audit =
        peelf::audit_security(**corrupt_img, corrupt_bytes);
    const auto* r4004_corrupt = find_rule(corrupt_audit, "MACHO4004");
    ASSERT_NE(r4004_corrupt, nullptr);
    EXPECT_EQ(r4004_corrupt->severity, peelf::SecuritySeverity::Error);
}

TEST(MachOAuditIntegrationTest, HeadlessCliUniversalSliceSelectionJsonAndSarifParity) {
    peelf_test::ScopedTempDir tmp("peelf_wu26b");

    // Build a 3-slice Universal binary:
    //   slice 0: insecure x86_64 (missing MH_PIE / __PAGEZERO -> MACHO4001 Error)
    //   slice 1: plain arm64 (PIE + __PAGEZERO, unsigned -> Warnings, no Errors)
    //   slice 2: hardened signed arm64e (0 Errors, 0 Warnings, MACHO4004 Note)
    SyntheticMachOSpec s0_x64{};
    s0_x64.cpu_type = peelf::macho::kCpuTypeX86_64;
    s0_x64.cpu_subtype = peelf::macho::kCpuSubtypeX86_64All;
    s0_x64.flags = peelf::macho::kMhDyldLink; // missing MH_PIE
    s0_x64.include_pagezero = false;

    SyntheticMachOSpec s1_arm64{};
    s1_arm64.cpu_type = peelf::macho::kCpuTypeArm64;
    s1_arm64.cpu_subtype = peelf::macho::kCpuSubtypeArm64All;
    s1_arm64.include_code_signature = false;

    SyntheticMachOSpec s2_arm64e{};

    const std::array<FatSliceInput, 3> fat_inputs = {
        FatSliceInput{s0_x64.cpu_type, s0_x64.cpu_subtype, build_synthetic_macho64(s0_x64)},
        FatSliceInput{s1_arm64.cpu_type, s1_arm64.cpu_subtype, build_synthetic_macho64(s1_arm64)},
        FatSliceInput{s2_arm64e.cpu_type, s2_arm64e.cpu_subtype, build_synthetic_macho64(s2_arm64e)},
    };
    const std::vector<std::uint8_t> fat_bytes = build_universal_fat32(fat_inputs);
    const std::filesystem::path fat_path = tmp / "universal_app";
    write_bytes_to_disk(fat_path, fat_bytes);
    const std::string fat_arg = fat_path.string();

    // 1. Select slice 0 by numeric index -> fails `--fail-on error` (exit code 2) due to MACHO4001 Error.
    {
        std::ostringstream out;
        std::ostringstream err;
        const std::array<std::string_view, 7> args = {
            "--headless", fat_arg, "--slice", "0", "--format", "json", "--fail-on=error"};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 2) << err.str();
        const std::string json = out.str();
        EXPECT_NE(json.find("\"universal_container\": true"), std::string::npos);
        EXPECT_NE(json.find("\"selected_slice_index\": 0"), std::string::npos);
        EXPECT_NE(json.find("\"MACHO4001\""), std::string::npos);
    }

    // 2. Select exact `"arm64"` (slice 1, NOT slice 2 `"arm64e"`) -> 0 errors, so `--fail-on error` exits 0!
    {
        std::ostringstream out;
        std::ostringstream err;
        const std::array<std::string_view, 6> args = {
            "--headless", fat_arg, "--slice=arm64", "--format", "json", "--fail-on=error"};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err.str();
        const std::string json = out.str();
        EXPECT_NE(json.find("\"selected_slice_index\": 1"), std::string::npos);
        EXPECT_NE(json.find("\"macho_settings\":"), std::string::npos);
        EXPECT_NE(json.find("\"system_shared_cache\":"), std::string::npos);
    }

    // 3. Select `"arm64e"` (slice 2) in SARIF 2.1.0 mode with `--fail-on=warning` -> exits 0!
    {
        std::ostringstream out;
        std::ostringstream err;
        const std::array<std::string_view, 7> args = {
            "--headless", fat_arg, "--slice", "arm64e", "--format", "sarif", "--fail-on=warning"};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(rc.has_value());
        EXPECT_EQ(*rc, 0) << err.str();
        const std::string sarif = out.str();
        EXPECT_NE(sarif.find("\"version\": \"2.1.0\""), std::string::npos);
        EXPECT_NE(sarif.find("\"id\": \"MACHO4004\""), std::string::npos);
        EXPECT_NE(sarif.find("\"selectedSliceIndex\": 2"), std::string::npos);
    }

    // 4. Out-of-range `--slice 99` fails cleanly with non-zero exit code.
    {
        std::ostringstream out;
        std::ostringstream err;
        const std::array<std::string_view, 4> args = {"--headless", fat_arg, "--slice", "99"};
        const auto rc = peelf::try_run_headless_or_help_cli(args, out, err);
        ASSERT_TRUE(rc.has_value());
        EXPECT_NE(*rc, 0);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(MachOAuditIntegrationTest, MachOExecutableSettingsAndProvenanceExtraction) {
    SyntheticMachOSpec spec{};
    spec.rpaths = {"@executable_path/../Frameworks", "@loader_path/Plugins"};
    spec.dylibs = {
        DylibSpec{peelf::macho::kLcLoadDylib, "/usr/lib/libSystem.B.dylib", 0x05210000u, 0x00010000u},
        DylibSpec{peelf::macho::kLcLoadWeakDylib, "@rpath/OptionalKit.dylib", 0x00020100u, 0x00010000u},
    };
    const std::vector<std::uint8_t> bytes = build_synthetic_macho64(spec);
    auto img = peelf::open_binary_image(bytes);
    ASSERT_TRUE(img.has_value()) << img.error().message;

    const peelf::BackingImageIdentity bid = peelf::extract_backing_image_identity(**img, bytes);
    EXPECT_EQ(bid.macho_uuid_hex, "aabbccdd11223344556677889900eeff");
    EXPECT_EQ(bid.primary_identifier(), "uuid:aabbccdd11223344556677889900eeff");

    const peelf::ExecutableSettingsReport settings =
        peelf::extract_executable_settings(**img, bytes);
    ASSERT_TRUE(settings.declared_in_file.value.has_value());
    ASSERT_TRUE(settings.declared_in_file.value->macho_settings.value.has_value());
    const peelf::MachODeclaredSettings& ms =
        *settings.declared_in_file.value->macho_settings.value;

    EXPECT_EQ(ms.file_type_name, "MH_EXECUTE");
    EXPECT_TRUE(ms.is_pie);
    EXPECT_TRUE(ms.two_level_namespace);
    EXPECT_TRUE(ms.no_heap_execution);
    EXPECT_TRUE(ms.is_arm64e_pac);
    EXPECT_EQ(ms.uuid_hex, "AABBCCDD-1122-3344-5566-77889900EEFF");
    EXPECT_EQ(ms.entry_source, "LC_MAIN");
    EXPECT_EQ(ms.dylinker, "/usr/lib/dyld");
    ASSERT_EQ(ms.build_platforms.size(), 1u);
    EXPECT_EQ(ms.build_platforms[0].platform_name, "macOS");
    EXPECT_EQ(ms.build_platforms[0].minos, "14.2");
    EXPECT_EQ(ms.build_platforms[0].sdk, "15.0");
    ASSERT_EQ(ms.rpaths.size(), 2u);
    ASSERT_EQ(ms.dylibs.size(), 2u);
    EXPECT_TRUE(ms.dylibs[1].is_weak);
    EXPECT_TRUE(ms.code_signature.present);
    EXPECT_TRUE(ms.code_signature.hardened_runtime);
    EXPECT_FALSE(ms.code_signature.cryptographically_verified);
    EXPECT_EQ(ms.code_signature.trust_provenance, "unverified_offline_structural_only");

    const std::string json = peelf::format_executable_settings_json(settings);
    EXPECT_NE(json.find("\"macho_settings\":"), std::string::npos);
    EXPECT_NE(json.find("\"cryptographically_verified\": false"), std::string::npos);
    EXPECT_NE(json.find("\"com.example.hardened\""), std::string::npos);
}

TEST(MachOAuditIntegrationTest, MachODependenciesExpandRpathReexportsAndClassifySharedCache) {
    peelf_test::ScopedTempDir tmp("peelf_wu26b");
    const std::filesystem::path macos_dir = tmp.path() / "Sample.app" / "Contents" / "MacOS";
    const std::filesystem::path fw_dir = tmp.path() / "Sample.app" / "Contents" / "Frameworks";

    // 1. SubCore.dylib (thin arm64e dylib exporting `_subcore_api`)
    SyntheticMachOSpec subcore_spec{};
    subcore_spec.file_type = peelf::macho::kMhDylib;
    subcore_spec.id_dylib = "@rpath/SubCore.dylib";
    subcore_spec.dylibs = {};
    subcore_spec.rpaths = {};
    subcore_spec.defined_symbols = {
        DefinedSymSpec{"_subcore_api", 0x100000C00ULL, true},
    };
    subcore_spec.undef_symbols = {};
    write_bytes_to_disk(fw_dir / "SubCore.dylib", build_synthetic_macho64(subcore_spec));

    // 2. HelperKit.dylib (Universal [x86_64, arm64e] dylib exporting `_helper_init`
    //    and re-exporting `@loader_path/SubCore.dylib`)
    SyntheticMachOSpec helper_arm64e{};
    helper_arm64e.file_type = peelf::macho::kMhDylib;
    helper_arm64e.id_dylib = "@rpath/HelperKit.dylib";
    helper_arm64e.rpaths = {};
    helper_arm64e.dylibs = {
        DylibSpec{peelf::macho::kLcReexportDylib, "@loader_path/SubCore.dylib"},
    };
    helper_arm64e.defined_symbols = {
        DefinedSymSpec{"_helper_init", 0x100000C00ULL, true},
    };
    helper_arm64e.undef_symbols = {};

    SyntheticMachOSpec helper_x64 = helper_arm64e;
    helper_x64.cpu_type = peelf::macho::kCpuTypeX86_64;
    helper_x64.cpu_subtype = peelf::macho::kCpuSubtypeX86_64All;

    const std::array<FatSliceInput, 2> helper_slices = {
        FatSliceInput{helper_x64.cpu_type, helper_x64.cpu_subtype, build_synthetic_macho64(helper_x64)},
        FatSliceInput{helper_arm64e.cpu_type, helper_arm64e.cpu_subtype, build_synthetic_macho64(helper_arm64e)},
    };
    write_bytes_to_disk(fw_dir / "HelperKit.dylib", build_universal_fat32(helper_slices));

    // 3. Main executable (arm64e) importing:
    //    ordinal 1: /usr/lib/libSystem.B.dylib (dyld shared cache)
    //    ordinal 2: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (dyld shared cache)
    //    ordinal 3: @rpath/HelperKit.dylib (resolved on disk -> re-exports SubCore.dylib)
    //    ordinal 4: @rpath/MissingPlugin.dylib (genuinely missing!)
    SyntheticMachOSpec app_spec{};
    app_spec.rpaths = {"@executable_path/../Frameworks"};
    app_spec.dylibs = {
        DylibSpec{peelf::macho::kLcLoadDylib, "/usr/lib/libSystem.B.dylib"},
        DylibSpec{peelf::macho::kLcLoadDylib,
                  "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"},
        DylibSpec{peelf::macho::kLcLoadDylib, "@rpath/HelperKit.dylib"},
        DylibSpec{peelf::macho::kLcLoadDylib, "@rpath/MissingPlugin.dylib"},
    };
    app_spec.undef_symbols = {
        UndefinedSymSpec{"___stack_chk_fail", 1u},
        UndefinedSymSpec{"_helper_init", 3u},
        UndefinedSymSpec{"_subcore_api", 3u},
        UndefinedSymSpec{"_missing_entry", 4u},
    };

    const std::vector<std::uint8_t> app_bytes = build_synthetic_macho64(app_spec);
    const std::filesystem::path app_path = macos_dir / "SampleApp";
    write_bytes_to_disk(app_path, app_bytes);

    auto app_img = peelf::open_binary_image(app_bytes);
    ASSERT_TRUE(app_img.has_value());

    peelf::DependencyResolveOptions dep_opts{};
    dep_opts.root_path = app_path;
    const peelf::DependencyGraph graph = peelf::build_dependency_graph(**app_img, dep_opts);

    // System shared-cache paths (/usr/lib/dyld + libSystem + CoreFoundation) must NOT be counted
    // as missing modules on non-macOS/offline hosts; only `@rpath/MissingPlugin.dylib` is missing!
    EXPECT_GE(graph.summary.system_shared_cache, 2u);
    EXPECT_EQ(graph.summary.missing_libraries, 1u);
    EXPECT_GE(graph.summary.resolved_count, 2u); // HelperKit.dylib + SubCore.dylib

    // Verify symbol bindings:
    // - `_helper_init` -> BoundExport
    // - `_subcore_api` -> BoundForwardedExport via LC_REEXPORT_DYLIB to SubCore.dylib
    // - `___stack_chk_fail` -> UncheckedSystemSharedCache
    // - `_missing_entry` -> UncheckedTargetUnavailable
    auto find_sym = [&](std::string_view sym_name) -> const peelf::ImportedSymbolBinding* {
        for (const peelf::DependencyEdge& edge : graph.edges) {
            for (const peelf::ImportedSymbolBinding& b : edge.symbol_bindings) {
                if (b.name == sym_name) {
                    return &b;
                }
            }
        }
        return nullptr;
    };

    const auto* b_helper = find_sym("_helper_init");
    const auto* b_subcore = find_sym("_subcore_api");
    const auto* b_sys = find_sym("___stack_chk_fail");
    const auto* b_missing = find_sym("_missing_entry");
    ASSERT_NE(b_helper, nullptr);
    ASSERT_NE(b_subcore, nullptr);
    ASSERT_NE(b_sys, nullptr);
    ASSERT_NE(b_missing, nullptr);

    EXPECT_EQ(b_helper->status, peelf::ImportedSymbolStatus::BoundExport);
    EXPECT_EQ(b_subcore->status, peelf::ImportedSymbolStatus::BoundForwardedExport);
    EXPECT_NE(b_subcore->forwarded_to.find("SubCore.dylib"), std::string::npos);
    EXPECT_EQ(b_sys->status, peelf::ImportedSymbolStatus::UncheckedSystemSharedCache);
    EXPECT_EQ(b_missing->status, peelf::ImportedSymbolStatus::UncheckedTargetUnavailable);
}

TEST(MachOAuditIntegrationTest, UniversalMachOBinaryDiffMatchesArchitectureSlicesAndMetadata) {
    // Build Universal LHS `[x86_64, arm64e]` and Universal RHS `[arm64e, x86_64]` (reversed order!)
    // where the `arm64e` slice changed UUID, flags, code signature, and `__text` bytes.
    SyntheticMachOSpec x64_spec{};
    x64_spec.cpu_type = peelf::macho::kCpuTypeX86_64;
    x64_spec.cpu_subtype = peelf::macho::kCpuSubtypeX86_64All;

    SyntheticMachOSpec arm64e_v1{};
    arm64e_v1.cs_identifier = "com.example.v1";

    SyntheticMachOSpec arm64e_v2 = arm64e_v1;
    arm64e_v2.uuid[15] ^= 0x5Au;
    arm64e_v2.cs_identifier = "com.example.v2";
    arm64e_v2.cs_flags = peelf::macho::kCsAdhoc; // dropped CS_RUNTIME!
    arm64e_v2.text_bytes = {0xAAu, 0x1Fu, 0x03u, 0xD5u, 0xC0u, 0x03u, 0x5Fu, 0xD6u};

    const std::array<FatSliceInput, 2> lhs_slices = {
        FatSliceInput{x64_spec.cpu_type, x64_spec.cpu_subtype, build_synthetic_macho64(x64_spec)},
        FatSliceInput{arm64e_v1.cpu_type, arm64e_v1.cpu_subtype, build_synthetic_macho64(arm64e_v1)},
    };
    const std::array<FatSliceInput, 2> rhs_slices = {
        FatSliceInput{arm64e_v2.cpu_type, arm64e_v2.cpu_subtype, build_synthetic_macho64(arm64e_v2)},
        FatSliceInput{x64_spec.cpu_type, x64_spec.cpu_subtype, build_synthetic_macho64(x64_spec)},
    };
    const std::vector<std::uint8_t> lhs_fat = build_universal_fat32(lhs_slices);
    const std::vector<std::uint8_t> rhs_fat = build_universal_fat32(rhs_slices);

    peelf::BinaryDiffOptions opts{};
    opts.lhs_slice_index = 1u; // select LHS arm64e slice (#1); RHS should auto-match arm64e (#0)!
    auto pair = peelf::open_matched_diff_images(lhs_fat, rhs_fat, opts);
    ASSERT_TRUE(pair.has_value()) << pair.error().message;
    EXPECT_EQ(pair->lhs_image->container_slice_index(), 1u);
    EXPECT_EQ(pair->rhs_image->container_slice_index(), 0u);
    EXPECT_TRUE(pair->lhs_image->macho_header()->is_arm64e);
    EXPECT_TRUE(pair->rhs_image->macho_header()->is_arm64e);

    auto diff = peelf::compare_binaries(lhs_fat, rhs_fat, opts);
    ASSERT_TRUE(diff.has_value()) << diff.error().message;
    EXPECT_TRUE(diff->header.format_matches);
    EXPECT_TRUE(diff->header.arch_matches);
    EXPECT_GT(diff->sections_modified, 0u);

    auto find_hdr_field = [&](std::string_view name) -> const peelf::MetadataFieldDiff* {
        for (const peelf::MetadataFieldDiff& f : diff->header.fields) {
            if (f.field_name == name) {
                return &f;
            }
        }
        return nullptr;
    };
    const auto* uuid_diff = find_hdr_field("Mach-O UUID");
    const auto* cs_diff = find_hdr_field("Mach-O Code Signature");
    ASSERT_NE(uuid_diff, nullptr);
    ASSERT_NE(cs_diff, nullptr);
    EXPECT_TRUE(uuid_diff->changed);
    EXPECT_TRUE(cs_diff->changed);

    // Thin RHS vs Universal LHS auto-matching (no explicit slice options needed!):
    const std::vector<std::uint8_t> thin_arm64e = build_synthetic_macho64(arm64e_v2);
    auto thin_vs_fat = peelf::open_matched_diff_images(lhs_fat, thin_arm64e);
    ASSERT_TRUE(thin_vs_fat.has_value()) << thin_vs_fat.error().message;
    EXPECT_EQ(thin_vs_fat->lhs_image->container_slice_index(), 1u);
    EXPECT_EQ(thin_vs_fat->lhs_image->architecture(), peelf::Architecture::ARM64);
}

TEST(MachOAuditIntegrationTest, BinaryModelSelectContainerSliceSwitchesUniversalArchitectureCleanly) {
    peelf_test::ScopedTempDir tmp("peelf_wu26b");

    SyntheticMachOSpec x64_slice{};
    x64_slice.cpu_type = peelf::macho::kCpuTypeX86_64;
    x64_slice.cpu_subtype = peelf::macho::kCpuSubtypeX86_64All;
    x64_slice.flags = peelf::macho::kMhDyldLink; // non-PIE x86_64 slice
    x64_slice.include_pagezero = false;
    x64_slice.uuid[0] = 0x11u;

    SyntheticMachOSpec arm64e_slice{};
    arm64e_slice.uuid[0] = 0x22u;

    const std::array<FatSliceInput, 2> slices = {
        FatSliceInput{x64_slice.cpu_type, x64_slice.cpu_subtype, build_synthetic_macho64(x64_slice)},
        FatSliceInput{
            arm64e_slice.cpu_type, arm64e_slice.cpu_subtype, build_synthetic_macho64(arm64e_slice)},
    };
    const std::filesystem::path fat_path = tmp / "viewer_universal_fixture";
    write_bytes_to_disk(fat_path, build_universal_fat32(slices));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(fat_path.string())) << model.last_diagnostic();
    EXPECT_TRUE(model.is_universal_container());
    ASSERT_EQ(model.container_info().slices.size(), 2u);
    EXPECT_EQ(model.active_slice_index(), 0u);
    EXPECT_EQ(model.architecture(), peelf::Architecture::X86_64);

    const auto* r4001_s0 = find_rule(model.security_audit(), "MACHO4001");
    ASSERT_NE(r4001_s0, nullptr);
    EXPECT_EQ(r4001_s0->severity, peelf::SecuritySeverity::Error);

    // Switch to slice #1 (`arm64e`): architecture, UUID, ExecutableSettings, and SecurityAudit all update!
    const std::uint64_t gen_before = model.content_generation();
    ASSERT_TRUE(model.select_container_slice(1u)) << model.last_diagnostic();
    EXPECT_GT(model.content_generation(), gen_before);
    EXPECT_EQ(model.active_slice_index(), 1u);
    EXPECT_EQ(model.architecture(), peelf::Architecture::ARM64);
    ASSERT_NE(model.image(), nullptr);
    ASSERT_NE(model.image()->macho_header(), nullptr);
    EXPECT_TRUE(model.image()->macho_header()->is_arm64e);

    ASSERT_TRUE(model.executable_settings().declared_in_file.value.has_value());
    ASSERT_TRUE(
        model.executable_settings().declared_in_file.value->macho_settings.value.has_value());
    EXPECT_TRUE(
        model.executable_settings().declared_in_file.value->macho_settings.value->is_arm64e_pac);

    const auto* r4001_s1 = find_rule(model.security_audit(), "MACHO4001");
    ASSERT_NE(r4001_s1, nullptr);
    EXPECT_EQ(r4001_s1->severity, peelf::SecuritySeverity::Pass);

    // Out-of-range slice index fails cleanly without corrupting active slice #1.
    EXPECT_FALSE(model.select_container_slice(99u));
    EXPECT_EQ(model.active_slice_index(), 1u);
    EXPECT_EQ(model.architecture(), peelf::Architecture::ARM64);
}

} // namespace
