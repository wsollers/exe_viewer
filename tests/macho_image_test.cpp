// Unit tests for WU-26a: IBinaryImage safe format defaults, cross-endian
// 32/64-bit Mach-O & Universal FAT container parser, Java .class disambiguation,
// container-consistent slice offsets, and adversarial malformed inputs.

#include <gtest/gtest.h>

#include <peelf/binary_image.hpp>
#include <peelf/macho_image.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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

    void resize(std::size_t n, std::uint8_t fill = 0u) { buf_.resize(n, fill); }

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

    void u64_be(std::uint64_t v) {
        u32_be(static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFu));
        u32_be(static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
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
    bool big_ = false;
    std::vector<std::uint8_t> buf_{};
};

// Minimal mock subclass verifying that IBinaryImage format-specific virtuals
// provide safe non-pure defaults without requiring PE/ELF/Mach-O boilerplate.
class MinimalMockBinaryImage final : public peelf::IBinaryImage {
public:
    [[nodiscard]] peelf::Format format() const noexcept override { return peelf::Format::MachO; }
    [[nodiscard]] peelf::ImageKind kind() const noexcept override {
        return peelf::ImageKind::Executable;
    }
    [[nodiscard]] peelf::Architecture architecture() const noexcept override {
        return peelf::Architecture::ARM64;
    }
    [[nodiscard]] peelf::Endianness endianness() const noexcept override {
        return peelf::Endianness::Little;
    }
    [[nodiscard]] bool is_64bit() const noexcept override { return true; }
    [[nodiscard]] std::uint64_t image_base() const noexcept override { return 0x100000000ULL; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return 0x100000400ULL; }
    [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override {
        return segments_;
    }
    [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override {
        return imports_;
    }
    [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override {
        return exports_;
    }
    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t /*file_offset*/) const noexcept override {
        return std::nullopt;
    }
    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t /*virtual_address*/) const noexcept override {
        return std::nullopt;
    }

private:
    std::vector<peelf::Section> sections_{};
    std::vector<peelf::Segment> segments_{};
    std::vector<peelf::Symbol> symbols_{};
    std::vector<peelf::ImportEntry> imports_{};
    std::vector<peelf::ExportEntry> exports_{};
};

void append_dylib_cmd(ByteWriter& w,
                      std::uint32_t cmd,
                      std::string_view path,
                      std::uint32_t current_ver = 0x00010000u,
                      std::uint32_t compat_ver = 0x00010000u) {
    const std::size_t start = w.size();
    w.u32(cmd);
    w.u32(0u); // placeholder cmdsize
    w.u32(24u); // name offset
    w.u32(2u); // timestamp
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

std::vector<std::uint8_t> build_embedded_code_signature(
    std::string_view identifier,
    std::string_view team_id,
    std::uint32_t cd_flags,
    bool include_nonempty_cms) {
    // Build CodeDirectory (big-endian, version 0x20400 so teamOffset @ +48 is present).
    ByteWriter cd(true);
    cd.u32_be(peelf::macho::kCsMagicCodeDirectory);
    cd.u32_be(0u); // length patched below
    cd.u32_be(0x00020400u); // version
    cd.u32_be(cd_flags);
    cd.u32_be(0u); // hashOffset patched below
    cd.u32_be(52u); // identOffset
    cd.u32_be(0u); // nSpecialSlots
    cd.u32_be(1u); // nCodeSlots
    cd.u32_be(0x1000u); // codeLimit
    cd.u8(32u); // SHA-256 hash size
    cd.u8(2u);  // SHA-256 hash type
    cd.u8(0u);  // platform
    cd.u8(12u); // 4 KiB page size (2^12)
    cd.u32_be(0u); // spare2
    cd.u32_be(0u); // scatterOffset
    cd.u32_be(0u); // teamOffset patched below
    cd.cstr(identifier);
    const auto team_off = static_cast<std::uint32_t>(cd.size());
    if (!team_id.empty()) {
        cd.cstr(team_id);
        cd.put_u32(48u, team_off);
    }
    const auto hash_off = static_cast<std::uint32_t>(cd.size());
    cd.put_u32(16u, hash_off);
    for (int i = 0; i < 32; ++i) {
        cd.u8(static_cast<std::uint8_t>(0xA0 + i));
    }
    cd.put_u32(4u, static_cast<std::uint32_t>(cd.size()));

    // Entitlements XML blob.
    ByteWriter ent(true);
    ent.u32_be(peelf::macho::kCsMagicEmbeddedEntitlements);
    ent.u32_be(0u);
    ent.cstr("<plist/>");
    ent.put_u32(4u, static_cast<std::uint32_t>(ent.size()));

    // CMS signature wrapper blob.
    ByteWriter cms(true);
    cms.u32_be(peelf::macho::kCsMagicBlobWrapper);
    cms.u32_be(0u);
    if (include_nonempty_cms) {
        const std::array<std::uint8_t, 6> fake_pkcs7 = {0x30u, 0x82u, 0x00u, 0x02u, 0x05u, 0x00u};
        cms.raw(fake_pkcs7);
    }
    cms.put_u32(4u, static_cast<std::uint32_t>(cms.size()));

    // SuperBlob with 3 slots: CodeDirectory, Entitlements, CMS SignatureSlot.
    ByteWriter sb(true);
    const std::uint32_t idx_end = 12u + 3u * 8u;
    const std::uint32_t cd_pos  = idx_end;
    const std::uint32_t ent_pos = cd_pos + static_cast<std::uint32_t>(cd.size());
    const std::uint32_t cms_pos = ent_pos + static_cast<std::uint32_t>(ent.size());
    const std::uint32_t total   = cms_pos + static_cast<std::uint32_t>(cms.size());

    sb.u32_be(peelf::macho::kCsMagicEmbeddedSignature);
    sb.u32_be(total);
    sb.u32_be(3u);

    sb.u32_be(peelf::macho::kCsSlotCodeDirectory);
    sb.u32_be(cd_pos);
    sb.u32_be(peelf::macho::kCsSlotEntitlements);
    sb.u32_be(ent_pos);
    sb.u32_be(peelf::macho::kCsSlotSignatureSlot);
    sb.u32_be(cms_pos);

    sb.raw(cd.bytes());
    sb.raw(ent.bytes());
    sb.raw(cms.bytes());
    return sb.bytes();
}

std::vector<std::uint8_t> build_full_x86_64_macho() {
    using namespace peelf::macho;
    ByteWriter w(false);

    // mach_header_64 (32 bytes)
    w.u32(kMhMagic64);
    w.u32(kCpuTypeX86_64);
    w.u32(kCpuSubtypeX86_64All);
    w.u32(kMhExecute);
    w.u32(0u); // ncmds patched later
    w.u32(0u); // sizeofcmds patched later
    w.u32(kMhPie | kMhTwoLevel | kMhNoHeapExecution | kMhAppExtensionSafe);
    w.u32(0u);

    std::uint32_t ncmds = 0u;
    const std::size_t cmds_start = w.size();

    // 1. LC_SEGMENT_64 __PAGEZERO
    {
        w.u32(kLcSegment64);
        w.u32(72u);
        w.fixed_str16("__PAGEZERO");
        w.u64(0u);
        w.u64(0x100000000ULL);
        w.u64(0u);
        w.u64(0u);
        w.u32(kVmProtNone);
        w.u32(kVmProtNone);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // 2. LC_SEGMENT_64 __TEXT with 1 section (__TEXT,__text @ 0x100000C00, fileoff 0xC00, size 8)
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

        // section_64 __text
        w.fixed_str16("__text");
        w.fixed_str16("__TEXT");
        w.u64(0x100000C00ULL);
        w.u64(8u);
        w.u32(0xC00u);
        w.u32(4u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSAttrPureInstructions | kSAttrSomeInstructions | kSRegular);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // 3. LC_SEGMENT_64 __DATA with __data (file-backed), __bss (S_ZEROFILL), __huge_bss (S_GB_ZEROFILL)
    {
        w.u32(kLcSegment64);
        w.u32(72u + 3u * 80u);
        w.fixed_str16("__DATA");
        w.u64(0x100001000ULL);
        w.u64(0x100002000ULL);
        w.u64(0x1000ULL);
        w.u64(0x1000ULL);
        w.u32(kVmProtRead | kVmProtWrite);
        w.u32(kVmProtRead | kVmProtWrite);
        w.u32(3u);
        w.u32(0u);

        // __data (4 bytes @ 0x100001000, file offset 0x1000)
        w.fixed_str16("__data");
        w.fixed_str16("__DATA");
        w.u64(0x100001000ULL);
        w.u64(4u);
        w.u32(0x1000u);
        w.u32(2u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSRegular);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);

        // __bss (S_ZEROFILL, 0x100 bytes @ 0x100002000, offset 0)
        w.fixed_str16("__bss");
        w.fixed_str16("__DATA");
        w.u64(0x100002000ULL);
        w.u64(0x100ULL);
        w.u32(0u);
        w.u32(4u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSZeroFill);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);

        // __huge_bss (S_GB_ZEROFILL, 4 GiB @ 0x100003000, offset 0)
        w.fixed_str16("__huge_bss");
        w.fixed_str16("__DATA");
        w.u64(0x100003000ULL);
        w.u64(0x100000000ULL);
        w.u32(0u);
        w.u32(4u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kSGbZeroFill);
        w.u32(0u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // 4. LC_SEGMENT_64 __RESTRICT,__restrict
    {
        w.u32(kLcSegment64);
        w.u32(72u + 80u);
        w.fixed_str16("__RESTRICT");
        w.u64(0x200003000ULL);
        w.u64(0x1000ULL);
        w.u64(0u);
        w.u64(0u);
        w.u32(kVmProtNone);
        w.u32(kVmProtNone);
        w.u32(1u);
        w.u32(0u);

        w.fixed_str16("__restrict");
        w.fixed_str16("__RESTRICT");
        w.u64(0x200003000ULL);
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

    // 5. LC_SEGMENT_64 __LINKEDIT
    const std::size_t linkedit_seg_off = w.size();
    {
        w.u32(kLcSegment64);
        w.u32(72u);
        w.fixed_str16("__LINKEDIT");
        w.u64(0x200004000ULL);
        w.u64(0x2000ULL);
        w.u64(0x2000ULL);
        w.u64(0u); // patched below
        w.u32(kVmProtRead);
        w.u32(kVmProtRead);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // 6. LC_MAIN (entryoff = 0xC00 -> VA 0x100000C00)
    {
        w.u32(kLcMain);
        w.u32(24u);
        w.u64(0xC00ULL);
        w.u64(0u);
        ++ncmds;
    }

    // 7. LC_LOAD_DYLINKER
    append_dylinker_cmd(w, "/usr/lib/dyld");
    ++ncmds;

    // 8. LC_ID_DYLIB (should NOT consume ordinal 1)
    append_dylib_cmd(w, kLcIdDylib, "@rpath/libSelf.dylib");
    ++ncmds;

    // 9..11. Imported dylibs (ordinals 1, 2, 3)
    append_dylib_cmd(w, kLcLoadDylib, "/usr/lib/libSystem.B.dylib", 0x05210000u, 0x00010000u);
    ++ncmds;
    append_dylib_cmd(w, kLcLoadWeakDylib, "@rpath/Optional.framework/Optional");
    ++ncmds;
    append_dylib_cmd(w, kLcReexportDylib, "/usr/lib/libc++.1.dylib");
    ++ncmds;

    // 12..13. LC_RPATH
    append_rpath_cmd(w, "@executable_path/../Frameworks");
    ++ncmds;
    append_rpath_cmd(w, "/opt/vendor/lib");
    ++ncmds;

    // 14. LC_UUID
    {
        w.u32(kLcUuid);
        w.u32(24u);
        const std::array<std::uint8_t, 16> uuid_bytes = {
            0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu,
            0x10u, 0x32u, 0x54u, 0x76u, 0x98u, 0xBAu, 0xDCu, 0xFEu};
        w.raw(uuid_bytes);
        ++ncmds;
    }

    // 15. LC_BUILD_VERSION (macOS 14.2, SDK 14.4, 1 tool: clang 15.0.0)
    {
        w.u32(kLcBuildVersion);
        w.u32(32u);
        w.u32(kPlatformMacOS);
        w.u32(0x000E0200u); // 14.2
        w.u32(0x000E0400u); // 14.4
        w.u32(1u);
        w.u32(1u); // TOOL_CLANG
        w.u32(0x000F0000u); // 15.0
        ++ncmds;
    }

    // 16. LC_SOURCE_VERSION
    {
        w.u32(kLcSourceVersion);
        w.u32(16u);
        w.u64(0x0001000200030004ULL);
        ++ncmds;
    }

    // 17. LC_ENCRYPTION_INFO_64 (unencrypted cryptid=0)
    {
        w.u32(kLcEncryptionInfo64);
        w.u32(24u);
        w.u32(0xC00u);
        w.u32(0x400u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    // 18..19. LC_DYLD_EXPORTS_TRIE & LC_DYLD_CHAINED_FIXUPS
    {
        w.u32(kLcDyldExportsTrie);
        w.u32(16u);
        w.u32(0x2000u);
        w.u32(32u);
        ++ncmds;

        w.u32(kLcDyldChainedFixups);
        w.u32(16u);
        w.u32(0x2020u);
        w.u32(32u);
        ++ncmds;
    }

    // 20. LC_SYMTAB (patched below)
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

    // 21. LC_DYSYMTAB
    {
        w.u32(kLcDysymtab);
        w.u32(80u);
        w.u32(0u); // ilocalsym
        w.u32(1u); // nlocalsym
        w.u32(1u); // iextdefsym
        w.u32(1u); // nextdefsym
        w.u32(2u); // iundefsym
        w.u32(2u); // nundefsym
        for (int i = 0; i < 12; ++i) {
            w.u32(0u);
        }
        ++ncmds;
    }

    // 22. LC_CODE_SIGNATURE (patched below)
    const std::size_t codesig_cmd_off = w.size();
    {
        w.u32(kLcCodeSignature);
        w.u32(16u);
        w.u32(0u);
        w.u32(0u);
        ++ncmds;
    }

    const auto sizeofcmds = static_cast<std::uint32_t>(w.size() - cmds_start);
    w.put_u32(16u, ncmds);
    w.put_u32(20u, sizeofcmds);

    // Emit __TEXT,__text @ 0xC00
    w.pad_to(0xC00u);
    const std::array<std::uint8_t, 8> text_code = {
        0x55u, 0x48u, 0x89u, 0xE5u, 0x31u, 0xC0u, 0x5Du, 0xC3u};
    w.raw(text_code);

    // Emit __DATA,__data @ 0x1000
    w.pad_to(0x1000u);
    const std::array<std::uint8_t, 4> data_bytes = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    w.raw(data_bytes);

    // Emit __LINKEDIT @ 0x2000: exports trie + chained fixups + symtab + strtab + codesig
    w.pad_to(0x2040u);

    // Build string table first so n_strx offsets are known.
    ByteWriter strtab(false);
    strtab.u8(0u);
    const auto str_helper = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_internal_helper");
    const auto str_main = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_main");
    const auto str_printf = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_printf");
    const auto str_opt = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_optional_api");
    strtab.align_to(8u);

    const auto symoff = static_cast<std::uint32_t>(w.size());
    // Symbol 0: private-external defined symbol (_internal_helper) -> NOT in exports()
    w.u32(str_helper);
    w.u8(kNSect | kNExt | kNPext);
    w.u8(1u);
    w.u16(0u);
    w.u64(0x100000C04ULL);

    // Symbol 1: external defined symbol (_main) -> in exports()
    w.u32(str_main);
    w.u8(kNSect | kNExt);
    w.u8(1u);
    w.u16(0u);
    w.u64(0x100000C00ULL);

    // Symbol 2: undefined external (_printf) from ordinal 1 (/usr/lib/libSystem.B.dylib)
    w.u32(str_printf);
    w.u8(kNUndf | kNExt);
    w.u8(0u);
    w.u16(static_cast<std::uint16_t>(1u << 8u));
    w.u64(0u);

    // Symbol 3: weak undefined external (_optional_api) from ordinal 2 (@rpath/Optional.framework/Optional)
    w.u32(str_opt);
    w.u8(kNUndf | kNExt);
    w.u8(0u);
    w.u16(static_cast<std::uint16_t>((2u << 8u) | kNWeakRef));
    w.u64(0u);

    const auto stroff = static_cast<std::uint32_t>(w.size());
    w.raw(strtab.bytes());

    w.put_u32(symtab_cmd_off + 8u, symoff);
    w.put_u32(symtab_cmd_off + 12u, 4u);
    w.put_u32(symtab_cmd_off + 16u, stroff);
    w.put_u32(symtab_cmd_off + 20u, static_cast<std::uint32_t>(strtab.size()));

    w.align_to(16u);
    const auto cs_off = static_cast<std::uint32_t>(w.size());
    const auto cs_blob = build_embedded_code_signature(
        "com.peelf.machotest",
        "TEAM987654",
        kCsAdhoc | kCsRuntime,
        true);
    w.raw(cs_blob);

    w.put_u32(codesig_cmd_off + 8u, cs_off);
    w.put_u32(codesig_cmd_off + 12u, static_cast<std::uint32_t>(cs_blob.size()));

    const auto linkedit_filesz = static_cast<std::uint64_t>(w.size() - 0x2000u);
    w.put_u64(linkedit_seg_off + 48u, linkedit_filesz);

    return w.bytes();
}

std::vector<std::uint8_t> build_arm64e_macho(std::span<const std::uint8_t> code_bytes) {
    using namespace peelf::macho;
    ByteWriter w(false);

    // arm64e subtype 2 with ptrauth ABI bit (0x80000000) and version 1 (0x01000000)
    const std::uint32_t arm64e_subtype = kCpuSubtypePtrAuthAbi | (1u << 24u) | kCpuSubtypeArm64e;
    w.u32(kMhMagic64);
    w.u32(kCpuTypeArm64);
    w.u32(arm64e_subtype);
    w.u32(kMhExecute);
    w.u32(2u); // __TEXT + LC_UNIXTHREAD
    w.u32(0u);
    w.u32(kMhPie | kMhTwoLevel);
    w.u32(0u);

    const std::size_t cmds_start = w.size();

    // LC_SEGMENT_64 __TEXT with __text @ 0x100000400, slice offset 0x400
    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str16("__TEXT");
    w.u64(0x100000000ULL);
    w.u64(0x1000ULL);
    w.u64(0u);
    w.u64(0x800ULL);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u64(0x100000400ULL);
    w.u64(code_bytes.size());
    w.u32(0x400u);
    w.u32(2u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // LC_UNIXTHREAD: ARM_THREAD_STATE64 (flavor=6, count=68 words = 272 bytes)
    // pc is at state_off + 256; encode PAC-authenticated upper bits in bits 48..63.
    w.u32(kLcUnixThread);
    w.u32(16u + 272u);
    w.u32(6u);  // ARM_THREAD_STATE64
    w.u32(68u); // 68 uint32_t words
    for (int reg = 0; reg < 32; ++reg) {
        w.u64(0u); // x0..x28, fp, lr, sp
    }
    w.u64(0x8010000100000400ULL); // PAC-signed entry PC -> strips to 0x100000400
    w.u32(0u); // cpsr
    w.u32(0u); // pad

    w.put_u32(20u, static_cast<std::uint32_t>(w.size() - cmds_start));
    w.pad_to(0x400u);
    w.raw(code_bytes);
    w.pad_to(0x800u);
    return w.bytes();
}

std::vector<std::uint8_t> build_ppc32_be_macho(std::uint32_t entry_va = 0x1200u) {
    using namespace peelf::macho;
    ByteWriter w(true); // big-endian

    // mach_header (28 bytes)
    w.u32(kMhMagic);
    w.u32(kCpuTypePowerPC);
    w.u32(0u);
    w.u32(kMhExecute);
    w.u32(3u); // LC_SEGMENT + LC_VERSION_MIN_MACOSX + LC_UNIXTHREAD
    w.u32(0u);
    w.u32(kMhAllowStackExecution | kMhRootSafe | kMhSetuidSafe);

    const std::size_t cmds_start = w.size();

    // LC_SEGMENT (56 bytes) + 1 section (68 bytes) = 124 bytes
    w.u32(kLcSegment);
    w.u32(56u + 68u);
    w.fixed_str16("__TEXT");
    w.u32(0x1000u);
    w.u32(0x1000u);
    w.u32(0u);
    w.u32(0x400u);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u32(entry_va);
    w.u32(8u);
    w.u32(0x200u);
    w.u32(2u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);

    // LC_VERSION_MIN_MACOSX (10.5.8, SDK 10.6.0)
    w.u32(kLcVersionMinMacosx);
    w.u32(16u);
    w.u32(0x000A0508u);
    w.u32(0x000A0600u);

    // LC_UNIXTHREAD: PPC_THREAD_STATE (flavor=1, count=40 words = 160 bytes), srr0 @ +0
    w.u32(kLcUnixThread);
    w.u32(16u + 160u);
    w.u32(1u);
    w.u32(40u);
    w.u32(entry_va); // srr0
    for (int i = 1; i < 40; ++i) {
        w.u32(0u);
    }

    w.put_u32(20u, static_cast<std::uint32_t>(w.size() - cmds_start));
    w.pad_to(0x200u);
    // PPC instructions: mflr r0 (0x7C0802A6); blr (0x4E800020)
    w.u32(0x7C0802A6u);
    w.u32(0x4E800020u);
    w.pad_to(0x400u);
    return w.bytes();
}

std::vector<std::uint8_t> build_ppc64_be_macho(std::uint64_t entry_va = 0x100001200ULL) {
    using namespace peelf::macho;
    ByteWriter w(true); // big-endian 64-bit

    w.u32(kMhMagic64);
    w.u32(kCpuTypePowerPC64);
    w.u32(0u);
    w.u32(kMhExecute);
    w.u32(2u);
    w.u32(0u);
    w.u32(kMhPie);
    w.u32(0u);

    const std::size_t cmds_start = w.size();

    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str16("__TEXT");
    w.u64(0x100001000ULL);
    w.u64(0x1000ULL);
    w.u64(0u);
    w.u64(0x400ULL);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u64(entry_va);
    w.u64(8ULL);
    w.u32(0x200u);
    w.u32(2u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // LC_UNIXTHREAD: PPC_THREAD_STATE64 (flavor=5, count=76 words = 304 bytes), srr0 @ +0
    w.u32(kLcUnixThread);
    w.u32(16u + 304u);
    w.u32(5u);
    w.u32(76u);
    w.u64(entry_va);
    for (int i = 2; i < 76; ++i) {
        w.u32(0u);
    }

    w.put_u32(20u, static_cast<std::uint32_t>(w.size() - cmds_start));
    w.pad_to(0x200u);
    w.u32(0x60000000u); // nop
    w.u32(0x4E800020u); // blr
    w.pad_to(0x400u);
    return w.bytes();
}

TEST(MachOImageTest, FormatDefaultsAreSafeOnMinimalMock) {
    const MinimalMockBinaryImage mock;
    EXPECT_EQ(peelf::to_string(peelf::BinaryFormat::MachO), "Mach-O");
    EXPECT_EQ(mock.format(), peelf::Format::MachO);
    EXPECT_FALSE(mock.is_universal_slice());
    EXPECT_EQ(mock.container_slice_index(), 0u);
    EXPECT_EQ(mock.container_slice_offset(), 0u);
    EXPECT_EQ(mock.pe_header(), nullptr);
    EXPECT_TRUE(mock.pe_data_directories().empty());
    EXPECT_EQ(mock.elf_header(), nullptr);
    EXPECT_TRUE(mock.elf_program_headers().empty());
    EXPECT_EQ(mock.macho_header(), nullptr);
    EXPECT_TRUE(mock.macho_load_commands().empty());
    EXPECT_TRUE(mock.macho_segments().empty());
    EXPECT_TRUE(mock.macho_sections().empty());
    EXPECT_TRUE(mock.macho_symbols().empty());
    EXPECT_TRUE(mock.macho_dylibs().empty());
    EXPECT_TRUE(mock.macho_rpaths().empty());
    EXPECT_TRUE(mock.macho_build_versions().empty());
    EXPECT_EQ(mock.macho_symtab(), nullptr);
    EXPECT_EQ(mock.macho_dysymtab(), nullptr);
    EXPECT_EQ(mock.macho_code_signature(), nullptr);
    EXPECT_FALSE(mock.read_bytes_at_offset(0u, 4u).has_value());
    EXPECT_FALSE(mock.read_bytes_at_va(0x100000400ULL, 4u).has_value());
}

TEST(MachOImageTest, Thin64LittleEndianX86_64FullMetadataAndZeroFill) {
    const auto raw = build_full_x86_64_macho();
    EXPECT_EQ(peelf::detect_format(raw), peelf::Format::MachO);

    const auto container = peelf::inspect_binary_container(raw);
    ASSERT_TRUE(container.has_value()) << container.error().message;
    EXPECT_EQ(container->format, peelf::Format::MachO);
    EXPECT_FALSE(container->is_universal_container);
    ASSERT_EQ(container->slices.size(), 1u);
    EXPECT_EQ(container->slices[0].arch, peelf::Architecture::X86_64);
    EXPECT_EQ(container->slices[0].bitness, 64u);
    EXPECT_EQ(container->slices[0].endianness, peelf::Endianness::Little);
    EXPECT_EQ(container->slices[0].arch_name, "x86_64");

    const auto parsed = peelf::open_binary_image(raw);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const peelf::IBinaryImage& img = **parsed;

    EXPECT_EQ(img.format(), peelf::Format::MachO);
    EXPECT_EQ(img.kind(), peelf::ImageKind::Executable);
    EXPECT_EQ(img.architecture(), peelf::Architecture::X86_64);
    EXPECT_EQ(img.endianness(), peelf::Endianness::Little);
    EXPECT_TRUE(img.is_64bit());
    EXPECT_EQ(img.image_base(), 0x100000000ULL);
    EXPECT_EQ(img.entry_point(), 0x100000C00ULL);
    EXPECT_TRUE(img.parse_warnings().empty());

    const auto* mh = img.macho_header();
    ASSERT_NE(mh, nullptr);
    EXPECT_TRUE(mh->has_pie());
    EXPECT_TRUE(mh->has_twolevel_namespace());
    EXPECT_TRUE(mh->has_no_heap_execution());
    EXPECT_TRUE(mh->is_app_extension_safe());
    EXPECT_FALSE(mh->allows_stack_execution());

    const auto* macho_img = dynamic_cast<const peelf::MachOImage*>(&img);
    ASSERT_NE(macho_img, nullptr);
    EXPECT_TRUE(macho_img->has_pagezero());
    EXPECT_EQ(macho_img->pagezero_size(), 0x100000000ULL);
    EXPECT_TRUE(macho_img->has_restrict_segment_or_section());
    EXPECT_TRUE(macho_img->entry_uses_lc_main());

    // Dylibs & RPaths (LC_ID_DYLIB is separate and must not shift 1-based ordinals).
    ASSERT_NE(img.macho_id_dylib(), nullptr);
    EXPECT_EQ(img.macho_id_dylib()->name, "@rpath/libSelf.dylib");
    EXPECT_EQ(img.macho_id_dylib()->ordinal, 0u);
    ASSERT_EQ(img.macho_dylibs().size(), 3u);
    EXPECT_EQ(img.macho_dylibs()[0].ordinal, 1u);
    EXPECT_EQ(img.macho_dylibs()[0].name, "/usr/lib/libSystem.B.dylib");
    EXPECT_EQ(img.macho_dylibs()[1].ordinal, 2u);
    EXPECT_TRUE(img.macho_dylibs()[1].weak);
    EXPECT_EQ(img.macho_dylibs()[2].ordinal, 3u);
    EXPECT_TRUE(img.macho_dylibs()[2].reexport);

    ASSERT_EQ(img.macho_rpaths().size(), 2u);
    EXPECT_EQ(img.macho_rpaths()[0].path, "@executable_path/../Frameworks");
    EXPECT_EQ(img.macho_rpaths()[1].path, "/opt/vendor/lib");
    EXPECT_EQ(img.macho_dylinker(), "/usr/lib/dyld");

    // Symbols, Imports, Exports
    ASSERT_EQ(img.imports().size(), 2u);
    EXPECT_EQ(img.imports()[0].name, "_printf");
    EXPECT_EQ(img.imports()[0].library, "/usr/lib/libSystem.B.dylib");
    EXPECT_EQ(img.imports()[1].name, "_optional_api");
    EXPECT_EQ(img.imports()[1].library, "@rpath/Optional.framework/Optional");

    ASSERT_EQ(img.exports().size(), 1u);
    EXPECT_EQ(img.exports()[0].name, "_main");
    EXPECT_EQ(img.exports()[0].virtual_address, 0x100000C00ULL);

    // UUID, Build Version, Encryption Info, Dyld ranges
    EXPECT_EQ(img.macho_uuid_string(), "01234567-89AB-CDEF-1032-547698BADCFE");
    ASSERT_EQ(img.macho_build_versions().size(), 1u);
    EXPECT_EQ(peelf::macho::platform_to_string(img.macho_build_versions()[0].platform), "macOS");
    EXPECT_EQ(peelf::macho::format_packed_version(img.macho_build_versions()[0].minos), "14.2");
    EXPECT_EQ(peelf::macho::format_packed_version(img.macho_build_versions()[0].sdk), "14.4");
    ASSERT_EQ(img.macho_build_versions()[0].tools.size(), 1u);

    ASSERT_NE(img.macho_encryption_info(), nullptr);
    EXPECT_FALSE(img.macho_encryption_info()->is_encrypted());

    ASSERT_NE(img.macho_dyld_info(), nullptr);
    EXPECT_TRUE(img.macho_dyld_info()->exports_trie.present);
    EXPECT_TRUE(img.macho_dyld_info()->chained_fixups.present);

    // Code signature SuperBlob & CodeDirectory (structural presence != cryptographic verification)
    const auto* cs = img.macho_code_signature();
    ASSERT_NE(cs, nullptr);
    EXPECT_TRUE(cs->present);
    EXPECT_TRUE(cs->superblob_valid);
    EXPECT_TRUE(cs->has_code_directory);
    EXPECT_TRUE(cs->is_adhoc());
    EXPECT_TRUE(cs->has_hardened_runtime());
    EXPECT_EQ(cs->identifier, "com.peelf.machotest");
    EXPECT_EQ(cs->team_id, "TEAM987654");
    EXPECT_TRUE(cs->has_entitlements_blob);
    EXPECT_TRUE(cs->has_cms_blob);
    EXPECT_TRUE(cs->has_nonempty_cms_signature);
    EXPECT_FALSE(cs->cryptographically_verified);

    // VA <-> file offset & byte reads (including S_ZEROFILL and 4 GiB S_GB_ZEROFILL)
    EXPECT_EQ(img.va_to_file_offset(0x100000C00ULL), 0xC00u);
    EXPECT_EQ(img.file_offset_to_va(0xC00u), 0x100000C00ULL);
    EXPECT_EQ(img.va_to_file_offset(0x100002000ULL), std::nullopt); // S_ZEROFILL has no file offset
    EXPECT_EQ(img.va_to_file_offset(0x100003000ULL), std::nullopt); // S_GB_ZEROFILL has no file offset
    EXPECT_EQ(img.va_to_file_offset(0x1000ULL), std::nullopt);      // __PAGEZERO is unmapped

    const auto code = img.read_bytes_at_va(0x100000C00ULL, 8u);
    ASSERT_TRUE(code.has_value()) << code.error().message;
    EXPECT_EQ((*code)[0], 0x55u);
    EXPECT_EQ((*code)[7], 0xC3u);

    const auto bss_zero = img.read_bytes_at_va(0x100002000ULL, 32u);
    ASSERT_TRUE(bss_zero.has_value()) << bss_zero.error().message;
    EXPECT_TRUE(std::ranges::all_of(*bss_zero, [](std::uint8_t b) { return b == 0u; }));

    const auto gb_zero = img.read_bytes_at_va(0x180003000ULL, 64u);
    ASSERT_TRUE(gb_zero.has_value()) << gb_zero.error().message;
    EXPECT_EQ(gb_zero->size(), 64u);
    EXPECT_TRUE(std::ranges::all_of(*gb_zero, [](std::uint8_t b) { return b == 0u; }));

    EXPECT_FALSE(img.read_bytes_at_va(0x1000ULL, 4u).has_value());
}

TEST(MachOImageTest, Thin64Arm64ePointerAuthUnixThreadAndOtherIsas) {
    const std::array<std::uint8_t, 8> arm64_insns = {
        0xFDu, 0x7Bu, 0xBFu, 0xA9u, 0xC0u, 0x03u, 0x5Fu, 0xD6u};
    const auto raw = build_arm64e_macho(arm64_insns);

    const auto container = peelf::inspect_binary_container(raw);
    ASSERT_TRUE(container.has_value());
    ASSERT_EQ(container->slices.size(), 1u);
    EXPECT_EQ(container->slices[0].arch, peelf::Architecture::ARM64);
    EXPECT_EQ(container->slices[0].arch_name, "arm64e");

    const auto parsed = peelf::MachOImage::parse(raw);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    EXPECT_TRUE((*parsed)->is_arm64e());
    EXPECT_TRUE((*parsed)->macho_header()->ptrauth_abi);
    EXPECT_EQ((*parsed)->macho_header()->ptrauth_version, 1u);
    EXPECT_TRUE((*parsed)->entry_uses_unixthread());
    EXPECT_EQ((*parsed)->entry_point(), 0x100000400ULL);

    // PAC-tagged pointer normalization on arm64e
    const std::uint64_t pac_tagged_va = 0xABCD000100000400ULL;
    EXPECT_EQ((*parsed)->va_to_file_offset(pac_tagged_va), 0x400u);
    const auto code = (*parsed)->read_bytes_at_va(pac_tagged_va, 4u);
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ((*code)[0], 0xFDu);
    EXPECT_EQ((*code)[3], 0xA9u);

    // Minimal RISC-V 64 and x86 32-bit thin headers
    ByteWriter rv(false);
    rv.u32(peelf::macho::kMhMagic64);
    rv.u32(peelf::macho::kCpuTypeRiscV);
    rv.u32(0u);
    rv.u32(peelf::macho::kMhObject);
    rv.u32(0u);
    rv.u32(0u);
    rv.u32(0u);
    rv.u32(0u);
    const auto rv_img = peelf::parse_image(rv.bytes());
    ASSERT_TRUE(rv_img.has_value());
    EXPECT_EQ((*rv_img)->architecture(), peelf::Architecture::RISCV64);
    EXPECT_EQ((*rv_img)->kind(), peelf::ImageKind::Object);

    ByteWriter x86(false);
    x86.u32(peelf::macho::kMhMagic);
    x86.u32(peelf::macho::kCpuTypeX86);
    x86.u32(3u);
    x86.u32(peelf::macho::kMhDylib);
    x86.u32(0u);
    x86.u32(0u);
    x86.u32(0u);
    const auto x86_img = peelf::parse_image(x86.bytes());
    ASSERT_TRUE(x86_img.has_value());
    EXPECT_EQ((*x86_img)->architecture(), peelf::Architecture::X86);
    EXPECT_FALSE((*x86_img)->is_64bit());
    EXPECT_EQ((*x86_img)->kind(), peelf::ImageKind::SharedLibrary);
}

TEST(MachOImageTest, Thin32BigEndianPowerPCWithUnixThread) {
    const auto raw = build_ppc32_be_macho(0x1200u);
    EXPECT_EQ(peelf::detect_format(raw), peelf::Format::MachO);

    const auto parsed = peelf::parse_image(raw);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const peelf::IBinaryImage& img = **parsed;

    EXPECT_EQ(img.format(), peelf::Format::MachO);
    EXPECT_EQ(img.architecture(), peelf::Architecture::PowerPC);
    EXPECT_EQ(img.endianness(), peelf::Endianness::Big);
    EXPECT_FALSE(img.is_64bit());
    EXPECT_EQ(img.image_base(), 0x1000u);
    EXPECT_EQ(img.entry_point(), 0x1200u);

    ASSERT_NE(img.macho_header(), nullptr);
    EXPECT_TRUE(img.macho_header()->allows_stack_execution());
    EXPECT_TRUE(img.macho_header()->is_root_safe());
    EXPECT_TRUE(img.macho_header()->is_setuid_safe());

    ASSERT_EQ(img.macho_build_versions().size(), 1u);
    EXPECT_TRUE(img.macho_build_versions()[0].from_version_min_command);
    EXPECT_EQ(peelf::macho::format_packed_version(img.macho_build_versions()[0].minos), "10.5.8");

    EXPECT_EQ(img.va_to_file_offset(0x1200u), 0x200u);
    EXPECT_EQ(img.file_offset_to_va(0x200u), 0x1200u);

    const auto insns = img.read_bytes_at_va(0x1200u, 8u);
    ASSERT_TRUE(insns.has_value());
    EXPECT_EQ((*insns)[0], 0x7Cu);
    EXPECT_EQ((*insns)[1], 0x08u);
    EXPECT_EQ((*insns)[2], 0x02u);
    EXPECT_EQ((*insns)[3], 0xA6u);
}

TEST(MachOImageTest, Universal32And64SliceSelectionAndContainerConsistentOffsets) {
    const auto slice0_x86 = build_full_x86_64_macho();
    const std::array<std::uint8_t, 8> arm64_magic_bytes = {
        0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};
    const auto slice1_arm = build_arm64e_macho(arm64_magic_bytes);

    // Build canonical big-endian 32-bit Universal container (0xCAFEBABE):
    // Slice 0 @ 0x1000, Slice 1 @ 0x5000.
    ByteWriter fat32(true);
    fat32.u32_be(peelf::macho::kFatMagic);
    fat32.u32_be(2u);
    // fat_arch[0]: x86_64
    fat32.u32_be(peelf::macho::kCpuTypeX86_64);
    fat32.u32_be(peelf::macho::kCpuSubtypeX86_64All);
    fat32.u32_be(0x1000u);
    fat32.u32_be(static_cast<std::uint32_t>(slice0_x86.size()));
    fat32.u32_be(12u);
    // fat_arch[1]: arm64e
    fat32.u32_be(peelf::macho::kCpuTypeArm64);
    fat32.u32_be(peelf::macho::kCpuSubtypePtrAuthAbi | peelf::macho::kCpuSubtypeArm64e);
    fat32.u32_be(0x5000u);
    fat32.u32_be(static_cast<std::uint32_t>(slice1_arm.size()));
    fat32.u32_be(14u);

    fat32.pad_to(0x1000u);
    fat32.raw(slice0_x86);
    fat32.pad_to(0x5000u);
    fat32.raw(slice1_arm);

    EXPECT_EQ(peelf::detect_format(fat32.bytes()), peelf::Format::MachO);

    const auto info = peelf::inspect_binary_container(fat32.bytes());
    ASSERT_TRUE(info.has_value()) << info.error().message;
    EXPECT_TRUE(info->is_universal_container);
    ASSERT_EQ(info->slices.size(), 2u);
    EXPECT_EQ(info->slices[0].arch_name, "x86_64");
    EXPECT_EQ(info->slices[0].container_offset, 0x1000u);
    EXPECT_EQ(info->slices[1].arch_name, "arm64e");
    EXPECT_EQ(info->slices[1].container_offset, 0x5000u);
    EXPECT_EQ(info->slices[1].align_log2, 14u);

    // Default open selects slice 0 deterministically.
    const auto default_img = peelf::open_binary_image(fat32.bytes());
    ASSERT_TRUE(default_img.has_value());
    EXPECT_TRUE((*default_img)->is_universal_slice());
    EXPECT_EQ((*default_img)->container_slice_index(), 0u);
    EXPECT_EQ((*default_img)->container_slice_offset(), 0x1000u);
    EXPECT_EQ((*default_img)->architecture(), peelf::Architecture::X86_64);
    EXPECT_EQ((*default_img)->va_to_file_offset(0x100000C00ULL), 0x1C00u);

    // Explicit slice 1 selection: container-absolute offset discipline!
    peelf::BinaryOpenOptions opt_slice1{};
    opt_slice1.selected_slice_index = 1u;
    const auto arm_img = peelf::open_binary_image(fat32.bytes(), opt_slice1);
    ASSERT_TRUE(arm_img.has_value()) << arm_img.error().message;
    EXPECT_TRUE((*arm_img)->is_universal_slice());
    EXPECT_EQ((*arm_img)->container_slice_index(), 1u);
    EXPECT_EQ((*arm_img)->container_slice_offset(), 0x5000u);
    EXPECT_EQ((*arm_img)->architecture(), peelf::Architecture::ARM64);

    ASSERT_EQ((*arm_img)->sections().size(), 1u);
    EXPECT_EQ((*arm_img)->sections()[0].file_offset, 0x5400u);
    ASSERT_EQ((*arm_img)->segments().size(), 1u);
    EXPECT_EQ((*arm_img)->segments()[0].file_offset, 0x5000u);

    const auto container_code_off = (*arm_img)->va_to_file_offset(0x100000400ULL);
    ASSERT_EQ(container_code_off, 0x5400u);
    EXPECT_EQ((*arm_img)->file_offset_to_va(0x5400u), 0x100000400ULL);
    EXPECT_EQ((*arm_img)->slice_relative_offset(0x5400u), 0x400u);
    EXPECT_EQ((*arm_img)->container_file_offset(0x400u), 0x5400u);

    // Offsets belonging to slice 0 must be rejected when querying slice 1!
    EXPECT_EQ((*arm_img)->file_offset_to_va(0x1400u), std::nullopt);
    EXPECT_FALSE((*arm_img)->read_bytes_at_offset(0x1400u, 4u).has_value());

    const auto by_off = (*arm_img)->read_bytes_at_offset(*container_code_off, 8u);
    const auto by_va  = (*arm_img)->read_bytes_at_va(0x100000400ULL, 8u);
    ASSERT_TRUE(by_off.has_value());
    ASSERT_TRUE(by_va.has_value());
    EXPECT_EQ(*by_off, *by_va);
    EXPECT_EQ((*by_va)[0], 0x11u);
    EXPECT_EQ((*by_va)[7], 0x88u);

    // Select by preferred_arch_name and verify out-of-range slice index fails cleanly.
    peelf::BinaryOpenOptions opt_by_name{};
    opt_by_name.preferred_arch_name = "arm64e";
    const auto by_name_img = peelf::open_binary_image(fat32.bytes(), opt_by_name);
    ASSERT_TRUE(by_name_img.has_value());
    EXPECT_EQ((*by_name_img)->container_slice_index(), 1u);

    peelf::BinaryOpenOptions opt_oob{};
    opt_oob.selected_slice_index = 2u;
    EXPECT_FALSE(peelf::open_binary_image(fat32.bytes(), opt_oob).has_value());

    // Build 64-bit Universal container (FAT_MAGIC_64 = 0xCAFEBABF) with ppc32 + ppc64 BE slices.
    const auto ppc32 = build_ppc32_be_macho(0x1200u);
    const auto ppc64 = build_ppc64_be_macho(0x100001200ULL);
    ByteWriter fat64(true);
    fat64.u32_be(peelf::macho::kFatMagic64);
    fat64.u32_be(2u);
    // fat_arch_64[0] (32 bytes)
    fat64.u32_be(peelf::macho::kCpuTypePowerPC);
    fat64.u32_be(0u);
    fat64.u64_be(0x1000ULL);
    fat64.u64_be(ppc32.size());
    fat64.u32_be(12u);
    fat64.u32_be(0u);
    // fat_arch_64[1] (32 bytes)
    fat64.u32_be(peelf::macho::kCpuTypePowerPC64);
    fat64.u32_be(0u);
    fat64.u64_be(0x2000ULL);
    fat64.u64_be(ppc64.size());
    fat64.u32_be(12u);
    fat64.u32_be(0u);

    fat64.pad_to(0x1000u);
    fat64.raw(ppc32);
    fat64.pad_to(0x2000u);
    fat64.raw(ppc64);

    const auto info64 = peelf::inspect_binary_container(fat64.bytes());
    ASSERT_TRUE(info64.has_value()) << info64.error().message;
    EXPECT_TRUE(info64->is_universal_container);
    ASSERT_EQ(info64->slices.size(), 2u);
    EXPECT_EQ(info64->slices[0].arch, peelf::Architecture::PowerPC);
    EXPECT_EQ(info64->slices[0].bitness, 32u);
    EXPECT_EQ(info64->slices[1].arch, peelf::Architecture::PowerPC64);
    EXPECT_EQ(info64->slices[1].bitness, 64u);

    const auto ppc64_img = peelf::open_binary_image(fat64.bytes(), opt_slice1);
    ASSERT_TRUE(ppc64_img.has_value()) << ppc64_img.error().message;
    EXPECT_EQ((*ppc64_img)->architecture(), peelf::Architecture::PowerPC64);
    EXPECT_EQ((*ppc64_img)->endianness(), peelf::Endianness::Big);
    EXPECT_EQ((*ppc64_img)->entry_point(), 0x100001200ULL);
    EXPECT_EQ((*ppc64_img)->va_to_file_offset(0x100001200ULL), 0x2200u);
}

TEST(MachOImageTest, RejectsJavaClassFilesSharingCafeBabeMagic) {
    for (const std::uint16_t major_version : {std::uint16_t{45}, std::uint16_t{55}, std::uint16_t{65}}) {
        ByteWriter java_cls(true);
        java_cls.u32_be(0xCAFEBABEu);
        java_cls.u16(0u);            // minor_version
        java_cls.u16(major_version); // Java 1.1 (45), Java 11 (55), Java 21 (65)
        java_cls.u16(16u);           // constant_pool_count
        java_cls.pad_to(256u, 0x01u);

        EXPECT_EQ(peelf::detect_format(java_cls.bytes()), peelf::Format::Unknown);
        const auto inspected = peelf::inspect_binary_container(java_cls.bytes());
        EXPECT_FALSE(inspected.has_value());
        const auto opened = peelf::open_binary_image(java_cls.bytes());
        EXPECT_FALSE(opened.has_value());
    }
}

TEST(MachOImageTest, AdversarialMalformedThinAndUniversalInputsFailOrWarnSafely) {
    using namespace peelf::macho;

    // 1. cmdsize = 0 (infinite-loop hazard if unchecked)
    {
        ByteWriter w(false);
        w.u32(kMhMagic64);
        w.u32(kCpuTypeX86_64);
        w.u32(kCpuSubtypeX86_64All);
        w.u32(kMhExecute);
        w.u32(1u);
        w.u32(16u);
        w.u32(0u);
        w.u32(0u);
        w.u32(kLcMain);
        w.u32(0u); // cmdsize = 0
        w.u64(0u);
        EXPECT_FALSE(peelf::open_binary_image(w.bytes()).has_value());
    }

    // 2. cmdsize exceeding sizeofcmds
    {
        ByteWriter w(false);
        w.u32(kMhMagic64);
        w.u32(kCpuTypeX86_64);
        w.u32(kCpuSubtypeX86_64All);
        w.u32(kMhExecute);
        w.u32(1u);
        w.u32(16u); // sizeofcmds = 16
        w.u32(0u);
        w.u32(0u);
        w.u32(kLcMain);
        w.u32(24u); // cmdsize = 24 > sizeofcmds = 16
        w.pad_to(128u);
        EXPECT_FALSE(peelf::open_binary_image(w.bytes()).has_value());
    }

    // 3. LC_SEGMENT_64 nsects 32-bit multiplication overflow
    {
        ByteWriter w(false);
        w.u32(kMhMagic64);
        w.u32(kCpuTypeX86_64);
        w.u32(kCpuSubtypeX86_64All);
        w.u32(kMhExecute);
        w.u32(1u);
        w.u32(72u);
        w.u32(0u);
        w.u32(0u);

        w.u32(kLcSegment64);
        w.u32(72u);
        w.fixed_str16("__TEXT");
        w.u64(0x100000000ULL);
        w.u64(0x1000ULL);
        w.u64(0u);
        w.u64(72u);
        w.u32(kVmProtRead);
        w.u32(kVmProtRead);
        w.u32(0x03333334u); // 0x03333334 * 80 wraps 32-bit uint32_t!
        w.u32(0u);
        EXPECT_FALSE(peelf::open_binary_image(w.bytes()).has_value());
    }

    // 4. Out-of-bounds LC_SYMTAB stroff/strsize and symoff/nsyms -> safe warning, zero OOB read
    {
        auto damaged = build_full_x86_64_macho();
        // Corrupt LC_SYMTAB stroff/strsize in place: locate kLcSymtab in load commands.
        bool patched_symtab = false;
        for (std::size_t off = 32u; off + 24u <= 0xC00u;) {
            const std::uint32_t cmd = static_cast<std::uint32_t>(damaged[off]) |
                (static_cast<std::uint32_t>(damaged[off + 1u]) << 8u) |
                (static_cast<std::uint32_t>(damaged[off + 2u]) << 16u) |
                (static_cast<std::uint32_t>(damaged[off + 3u]) << 24u);
            const std::uint32_t sz = static_cast<std::uint32_t>(damaged[off + 4u]) |
                (static_cast<std::uint32_t>(damaged[off + 5u]) << 8u) |
                (static_cast<std::uint32_t>(damaged[off + 6u]) << 16u) |
                (static_cast<std::uint32_t>(damaged[off + 7u]) << 24u);
            if (cmd == kLcSymtab) {
                // Set stroff = 0xFFFFFF00, strsize = 0x1000
                damaged[off + 16u] = 0x00u;
                damaged[off + 17u] = 0xFFu;
                damaged[off + 18u] = 0xFFu;
                damaged[off + 19u] = 0xFFu;
                patched_symtab = true;
                break;
            }
            if (sz < 8u) {
                break;
            }
            off += sz;
        }
        ASSERT_TRUE(patched_symtab);
        const auto parsed = peelf::open_binary_image(damaged);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_FALSE((*parsed)->parse_warnings().empty());
        EXPECT_TRUE((*parsed)->imports().empty());
    }

    // 5. Overlapping & out-of-bounds Universal FAT slices
    {
        const auto thin = build_ppc32_be_macho();

        // 5a. Overlapping slices: slice 0 [0x100, +size) and slice 1 [0x180, +size)
        ByteWriter overlap_fat(true);
        overlap_fat.u32_be(kFatMagic);
        overlap_fat.u32_be(2u);
        overlap_fat.u32_be(kCpuTypePowerPC);
        overlap_fat.u32_be(0u);
        overlap_fat.u32_be(0x100u);
        overlap_fat.u32_be(static_cast<std::uint32_t>(thin.size()));
        overlap_fat.u32_be(8u);

        overlap_fat.u32_be(kCpuTypePowerPC);
        overlap_fat.u32_be(0u);
        overlap_fat.u32_be(0x180u);
        overlap_fat.u32_be(static_cast<std::uint32_t>(thin.size()));
        overlap_fat.u32_be(8u);
        overlap_fat.pad_to(0x100u);
        overlap_fat.raw(thin);
        overlap_fat.pad_to(0x180u + thin.size());
        std::copy(thin.begin(), thin.end(), overlap_fat.bytes().begin() + 0x180);

        EXPECT_EQ(peelf::detect_format(overlap_fat.bytes()), peelf::Format::Unknown);
        EXPECT_FALSE(peelf::inspect_binary_container(overlap_fat.bytes()).has_value());
        EXPECT_FALSE(peelf::open_binary_image(overlap_fat.bytes()).has_value());

        // 5b. Out-of-bounds 64-bit FAT slice with uint64 wraparound (0xFFFFFFFFFFFFFF00 + 0x200)
        ByteWriter oob_fat64(true);
        oob_fat64.u32_be(kFatMagic64);
        oob_fat64.u32_be(1u);
        oob_fat64.u32_be(kCpuTypeX86_64);
        oob_fat64.u32_be(kCpuSubtypeX86_64All);
        oob_fat64.u64_be(0xFFFFFFFFFFFFFF00ULL);
        oob_fat64.u64_be(0x200ULL);
        oob_fat64.u32_be(12u);
        oob_fat64.u32_be(0u);
        oob_fat64.pad_to(256u);

        EXPECT_EQ(peelf::detect_format(oob_fat64.bytes()), peelf::Format::Unknown);
        EXPECT_FALSE(peelf::inspect_binary_container(oob_fat64.bytes()).has_value());

        // 5c. Excessive alignment (> 30)
        ByteWriter bad_align(true);
        bad_align.u32_be(kFatMagic);
        bad_align.u32_be(1u);
        bad_align.u32_be(kCpuTypePowerPC);
        bad_align.u32_be(0u);
        bad_align.u32_be(0x100u);
        bad_align.u32_be(static_cast<std::uint32_t>(thin.size()));
        bad_align.u32_be(31u); // align > 30
        bad_align.pad_to(0x100u);
        bad_align.raw(thin);

        EXPECT_EQ(peelf::detect_format(bad_align.bytes()), peelf::Format::Unknown);
        EXPECT_FALSE(peelf::inspect_binary_container(bad_align.bytes()).has_value());

        // 5d. Polyglot Universal slice where outer fat_arch.cputype != inner mach_header.cputype
        ByteWriter mismatched_cpu(true);
        mismatched_cpu.u32_be(kFatMagic);
        mismatched_cpu.u32_be(1u);
        mismatched_cpu.u32_be(kCpuTypeArm64); // claims ARM64, but inner slice is PowerPC
        mismatched_cpu.u32_be(0u);
        mismatched_cpu.u32_be(0x100u);
        mismatched_cpu.u32_be(static_cast<std::uint32_t>(thin.size()));
        mismatched_cpu.u32_be(8u);
        mismatched_cpu.pad_to(0x100u);
        mismatched_cpu.raw(thin);

        EXPECT_EQ(peelf::detect_format(mismatched_cpu.bytes()), peelf::Format::Unknown);
        EXPECT_FALSE(peelf::inspect_binary_container(mismatched_cpu.bytes()).has_value());
        EXPECT_FALSE(peelf::open_binary_image(mismatched_cpu.bytes()).has_value());
    }
}

TEST(MachOImageTest, PreservesAbsAndIndrSymbolsAcrossRebaseAndValidatesCodeDirectoryHashes) {
    using namespace peelf::macho;

    ByteWriter w(false);
    w.u32(kMhMagic64);
    w.u32(kCpuTypeX86_64);
    w.u32(kCpuSubtypeX86_64All);
    w.u32(kMhDylib);
    w.u32(3u); // __TEXT + LC_SYMTAB + LC_CODE_SIGNATURE
    w.u32(0u); // sizeofcmds patched below
    w.u32(kMhPie);
    w.u32(0u);

    const std::size_t cmds_start = w.size();
    // 1. LC_SEGMENT_64 __TEXT with filesize (0x1000) > vmsize (0x800) to also test VA read clamping
    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str16("__TEXT");
    w.u64(0x100000000ULL); // vmaddr
    w.u64(0x800ULL);       // vmsize
    w.u64(0ULL);           // fileoff
    w.u64(0x1000ULL);      // filesize > vmsize
    w.u32(0x5u);           // maxprot
    w.u32(0x5u);           // initprot
    w.u32(1u);             // nsects
    w.u32(0u);
    // __TEXT,__text covering [0x400, 0x410)
    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u64(0x100000400ULL);
    w.u64(0x10ULL);
    w.u32(0x400u);
    w.u32(4u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSAttrSomeInstructions);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // 2. LC_SYMTAB (patched below)
    const std::size_t symtab_cmd_off = w.size();
    w.u32(kLcSymtab);
    w.u32(24u);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // 3. LC_CODE_SIGNATURE (patched below)
    const std::size_t cs_cmd_off = w.size();
    w.u32(kLcCodeSignature);
    w.u32(16u);
    w.u32(0u);
    w.u32(0u);

    w.put_u32(20u, static_cast<std::uint32_t>(w.size() - cmds_start));
    w.pad_to(0x400u);
    w.u8(0xC3u);
    w.pad_to(0x1000u);

    ByteWriter strtab(false);
    strtab.u8(0u);
    const auto str_sect = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_sect_export");
    const auto str_abs = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_abs_constant");
    const auto str_indr = static_cast<std::uint32_t>(strtab.size());
    strtab.cstr("_indr_alias");
    strtab.align_to(8u);

    const auto symoff = static_cast<std::uint32_t>(w.size());
    // N_SECT | N_EXT -> MUST slide on rebase
    w.u32(str_sect);
    w.u8(kNSect | kNExt);
    w.u8(1u);
    w.u16(0u);
    w.u64(0x100000400ULL);
    // N_ABS | N_EXT -> MUST NOT slide on rebase
    w.u32(str_abs);
    w.u8(kNAbs | kNExt);
    w.u8(0u);
    w.u16(0u);
    w.u64(0xFEEDFACEULL);
    // N_INDR | N_EXT -> MUST NOT slide on rebase (value is strtab index)
    w.u32(str_indr);
    w.u8(kNIndr | kNExt);
    w.u8(0u);
    w.u16(0u);
    w.u64(str_sect);

    const auto stroff = static_cast<std::uint32_t>(w.size());
    w.raw(strtab.bytes());
    w.put_u32(symtab_cmd_off + 8u, symoff);
    w.put_u32(symtab_cmd_off + 12u, 3u);
    w.put_u32(symtab_cmd_off + 16u, stroff);
    w.put_u32(symtab_cmd_off + 20u, static_cast<std::uint32_t>(strtab.size()));

    // Malformed CodeDirectory whose declared nCodeSlots * hashSize overflows sub-blob length.
    w.align_to(16u);
    const auto cs_off = static_cast<std::uint32_t>(w.size());
    ByteWriter bad_cs(true);
    bad_cs.u32_be(kCsMagicEmbeddedSignature);
    bad_cs.u32_be(20u + 60u); // SuperBlob length
    bad_cs.u32_be(1u);        // 1 blob
    bad_cs.u32_be(kCsSlotCodeDirectory);
    bad_cs.u32_be(20u);       // CodeDirectory @ +20
    bad_cs.u32_be(kCsMagicCodeDirectory);
    bad_cs.u32_be(60u);       // sub_len = 60
    bad_cs.u32_be(0x20400u);  // version
    bad_cs.u32_be(kCsAdhoc);
    bad_cs.u32_be(56u);       // hashOffset
    bad_cs.u32_be(52u);       // identOffset ("a\0" @ +52)
    bad_cs.u32_be(0u);        // nSpecialSlots
    bad_cs.u32_be(4u);        // nCodeSlots = 4 * 32 = 128 bytes > remaining 4 bytes!
    bad_cs.u32_be(0x800u);    // codeLimit
    bad_cs.u8(32u);           // hashSize
    bad_cs.u8(2u);
    bad_cs.u8(0u);
    bad_cs.u8(12u);
    bad_cs.u32_be(0u);
    bad_cs.u32_be(0u);
    bad_cs.u32_be(0u);
    bad_cs.cstr("a");
    bad_cs.pad_to(80u);
    w.raw(bad_cs.bytes());
    w.put_u32(cs_cmd_off + 8u, cs_off);
    w.put_u32(cs_cmd_off + 12u, static_cast<std::uint32_t>(bad_cs.size()));

    constexpr std::uint64_t kRebasedBase = 0x102000000ULL;
    auto rebased = peelf::parse_rebased_image(w.bytes(), kRebasedBase);
    ASSERT_TRUE(rebased.has_value()) << rebased.error().message;
    const peelf::IBinaryImage& img = **rebased;

    // Segment VA reads stop at vmsize (0x800) even when filesize is 0x1000.
    EXPECT_TRUE(img.read_bytes_at_va(kRebasedBase + 0x7F0u, 0x10u).has_value());
    EXPECT_FALSE(img.read_bytes_at_va(kRebasedBase + 0x7F0u, 0x20u).has_value());

    // Malformed CodeDirectory hashes must NOT leave superblob_valid == true.
    ASSERT_NE(img.macho_code_signature(), nullptr);
    EXPECT_FALSE(img.macho_code_signature()->superblob_valid);
    EXPECT_FALSE(img.macho_code_signature()->has_code_directory);

    const auto find_sym = [&](std::string_view name) -> const peelf::Symbol* {
        const auto it = std::ranges::find_if(img.symbols(), [&](const peelf::Symbol& s) {
            return s.name == name;
        });
        return it != img.symbols().end() ? &*it : nullptr;
    };
    const auto find_exp = [&](std::string_view name) -> const peelf::ExportEntry* {
        const auto it = std::ranges::find_if(img.exports(), [&](const peelf::ExportEntry& e) {
            return e.name == name;
        });
        return it != img.exports().end() ? &*it : nullptr;
    };

    ASSERT_NE(find_sym("_sect_export"), nullptr);
    ASSERT_NE(find_exp("_sect_export"), nullptr);
    EXPECT_EQ(find_sym("_sect_export")->virtual_address, kRebasedBase + 0x400u);
    EXPECT_EQ(find_exp("_sect_export")->virtual_address, kRebasedBase + 0x400u);

    ASSERT_NE(find_sym("_abs_constant"), nullptr);
    ASSERT_NE(find_exp("_abs_constant"), nullptr);
    EXPECT_EQ(find_sym("_abs_constant")->virtual_address, 0xFEEDFACEULL);
    EXPECT_EQ(find_exp("_abs_constant")->virtual_address, 0xFEEDFACEULL);

    ASSERT_NE(find_sym("_indr_alias"), nullptr);
    ASSERT_NE(find_exp("_indr_alias"), nullptr);
    EXPECT_EQ(find_sym("_indr_alias")->virtual_address, str_sect);
    EXPECT_EQ(find_exp("_indr_alias")->virtual_address, str_sect);
}

} // namespace
