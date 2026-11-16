#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "analysis/strings_index.hpp"
#include "symbols/symbol_index.hpp"

namespace {

struct SyntheticElfLayout {
    std::vector<std::uint8_t> bytes;
    std::size_t text_offset = 0;
    std::uint64_t text_va = 0x401000;
    std::size_t rodata_offset = 0;
    std::uint64_t rodata_va = 0;
};

[[nodiscard]] SyntheticElfLayout build_test_elf64(std::span<const std::uint8_t> text_payload,
                                                  std::span<const std::uint8_t> rodata_payload,
                                                  std::span<const peelf::Symbol> func_syms = {}) {
    constexpr std::size_t kEhdrSize = 64;
    constexpr std::size_t kPhdrSize = 56;
    constexpr std::size_t kShdrSize = 64;
    constexpr std::size_t kSymSize = 24;
    constexpr std::string_view kShstrtab{
        "\0.shstrtab\0.text\0.rodata\0.symtab\0.strtab\0", 41};

    std::string strtab("\0", 1);
    struct SymEntry {
        std::uint32_t name_off = 0;
        std::uint64_t value = 0;
        std::uint64_t size = 0;
    };
    std::vector<SymEntry> sym_entries;
    for (const auto& s : func_syms) {
        const auto off = static_cast<std::uint32_t>(strtab.size());
        strtab += s.name;
        strtab.push_back('\0');
        sym_entries.push_back(SymEntry{off, s.virtual_address, s.size});
    }

    const bool has_syms = !sym_entries.empty();
    const std::uint16_t phnum = 1;
    const std::uint16_t shnum = has_syms ? 6 : 4;
    const std::size_t shoff = kEhdrSize + phnum * kPhdrSize;
    const std::size_t shstr_off = shoff + shnum * kShdrSize;
    const std::size_t text_off = (shstr_off + kShstrtab.size() + 15u) & ~std::size_t{15};
    const std::size_t rodata_off = (text_off + text_payload.size() + 15u) & ~std::size_t{15};
    const std::size_t symtab_off = (rodata_off + rodata_payload.size() + 7u) & ~std::size_t{7};
    const std::size_t symtab_bytes = has_syms ? (sym_entries.size() + 1u) * kSymSize : 0u;
    const std::size_t strtab_off = symtab_off + symtab_bytes;
    const std::size_t total_size = strtab_off + (has_syms ? strtab.size() : 0u);

    SyntheticElfLayout out;
    out.bytes.assign(total_size, 0u);
    out.text_offset = text_off;
    out.text_va = 0x400000ULL + text_off;
    out.rodata_offset = rodata_off;
    out.rodata_va = 0x400000ULL + rodata_off;

    auto w16 = [&](std::size_t off, std::uint16_t v) {
        out.bytes[off] = static_cast<std::uint8_t>(v & 0xFFu);
        out.bytes[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    };
    auto w32 = [&](std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0; i < 4; ++i) {
            out.bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };
    auto w64 = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0; i < 8; ++i) {
            out.bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };

    // ELF64 little-endian header
    out.bytes[0] = 0x7Fu; out.bytes[1] = 'E'; out.bytes[2] = 'L'; out.bytes[3] = 'F';
    out.bytes[4] = 2u; out.bytes[5] = 1u; out.bytes[6] = 1u;
    w16(16, 2u);   // ET_EXEC
    w16(18, 62u);  // EM_X86_64
    w32(20, 1u);
    w64(24, out.text_va);
    w64(32, kEhdrSize);
    w64(40, shoff);
    w16(52, kEhdrSize);
    w16(54, kPhdrSize);
    w16(56, phnum);
    w16(58, kShdrSize);
    w16(60, shnum);
    w16(62, 1u);

    // Single PT_LOAD covering [0 .. symtab_off)
    const std::size_t load_span = rodata_off + rodata_payload.size();
    w32(kEhdrSize + 0, 1u);   // PT_LOAD
    w32(kEhdrSize + 4, 5u);   // PF_R | PF_X
    w64(kEhdrSize + 8, 0u);
    w64(kEhdrSize + 16, 0x400000ULL);
    w64(kEhdrSize + 24, 0x400000ULL);
    w64(kEhdrSize + 32, load_span);
    w64(kEhdrSize + 40, load_span);
    w64(kEhdrSize + 48, 0x1000u);

    std::memcpy(out.bytes.data() + shstr_off, kShstrtab.data(), kShstrtab.size());
    if (!text_payload.empty()) {
        std::memcpy(out.bytes.data() + text_off, text_payload.data(), text_payload.size());
    }
    if (!rodata_payload.empty()) {
        std::memcpy(out.bytes.data() + rodata_off, rodata_payload.data(), rodata_payload.size());
    }

    auto write_shdr = [&](std::uint16_t idx,
                          std::uint32_t name,
                          std::uint32_t type,
                          std::uint64_t flags,
                          std::uint64_t addr,
                          std::uint64_t off,
                          std::uint64_t sz,
                          std::uint32_t link = 0,
                          std::uint32_t info = 0,
                          std::uint64_t entsize = 0) {
        const std::size_t b = shoff + idx * kShdrSize;
        w32(b + 0, name);
        w32(b + 4, type);
        w64(b + 8, flags);
        w64(b + 16, addr);
        w64(b + 24, off);
        w64(b + 32, sz);
        w32(b + 40, link);
        w32(b + 44, info);
        w64(b + 48, 16u);
        w64(b + 56, entsize);
    };
    write_shdr(1, 1u, 3u, 0u, 0u, shstr_off, kShstrtab.size());              // .shstrtab
    write_shdr(2, 11u, 1u, 6u, out.text_va, text_off, text_payload.size());  // .text (AX)
    write_shdr(3, 17u, 1u, 2u, out.rodata_va, rodata_off, rodata_payload.size()); // .rodata (A)

    if (has_syms) {
        for (std::size_t i = 0; i < sym_entries.size(); ++i) {
            const std::size_t sb = symtab_off + (i + 1u) * kSymSize;
            w32(sb + 0, sym_entries[i].name_off);
            out.bytes[sb + 4] = static_cast<std::uint8_t>((1u << 4u) | 2u); // STB_GLOBAL | STT_FUNC
            out.bytes[sb + 5] = 0u;
            w16(sb + 6, 2u); // section 2 (.text)
            w64(sb + 8, sym_entries[i].value);
            w64(sb + 16, sym_entries[i].size);
        }
        std::memcpy(out.bytes.data() + strtab_off, strtab.data(), strtab.size());
        write_shdr(4, 25u, 2u, 0u, 0u, symtab_off, symtab_bytes, 5u, 1u, kSymSize); // .symtab
        write_shdr(5, 33u, 3u, 0u, 0u, strtab_off, strtab.size());                  // .strtab
    }

    return out;
}

class MockStringsProcessSession final : public peelf::IProcessSession {
public:
    MockStringsProcessSession(std::vector<peelf::MemoryRegion> regions,
                              std::uint64_t region_base,
                              std::vector<std::uint8_t> backing)
        : regions_(std::move(regions))
        , region_base_(region_base)
        , backing_(std::move(backing)) {}

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t address,
                                                         std::span<std::uint8_t> buffer) override {
        if (address < region_base_) {
            return peelf::make_error("unmapped");
        }
        const std::uint64_t rel = address - region_base_;
        if (rel >= backing_.size()) {
            return peelf::make_error("past end");
        }
        const std::size_t avail = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), backing_.size() - rel));
        std::memcpy(buffer.data(), backing_.data() + rel, avail);
        return avail;
    }

private:
    peelf::ProcessInfo info_{
        .pid = 4242,
        .name = "mock_strings_target",
        .architecture = peelf::Architecture::X86_64,
        .is_64bit = true,
        .access = peelf::ProcessAccessStatus::ReadOnly,
    };
    std::vector<peelf::MemoryRegion> regions_;
    std::uint64_t region_base_ = 0;
    std::vector<std::uint8_t> backing_;
};

void append_cstr(std::vector<std::uint8_t>& buf, std::string_view s) {
    for (char c : s) {
        buf.push_back(static_cast<std::uint8_t>(c));
    }
    buf.push_back(0x00u);
}

void append_utf16le(std::vector<std::uint8_t>& buf, std::u16string_view s) {
    for (char16_t u : s) {
        buf.push_back(static_cast<std::uint8_t>(u & 0xFFu));
        buf.push_back(static_cast<std::uint8_t>((u >> 8u) & 0xFFu));
    }
    buf.push_back(0x00u);
    buf.push_back(0x00u);
}

void append_utf16be(std::vector<std::uint8_t>& buf, std::u16string_view s) {
    for (char16_t u : s) {
        buf.push_back(static_cast<std::uint8_t>((u >> 8u) & 0xFFu));
        buf.push_back(static_cast<std::uint8_t>(u & 0xFFu));
    }
    buf.push_back(0x00u);
    buf.push_back(0x00u);
}

} // namespace

TEST(StringsIndexTest, ExtractsAsciiUtf8Utf16LeAndUtf16BeWithSectionAttribution) {
    std::vector<std::uint8_t> rodata;
    const std::size_t ascii_off = rodata.size();
    append_cstr(rodata, "Hello, Kernel32!\nLine2");
    while (rodata.size() % 4u != 0u) rodata.push_back(0x00u);

    // Valid UTF-8 string ("Café 東京 🚀" = 4 + 1 + 2 + 1 + 6 + 1 + 4 bytes = 15 bytes, 9 code points)
    const std::size_t utf8_off = rodata.size();
    append_cstr(rodata, "Caf\xC3\xA9 \xE6\x9D\xB1\xE4\xBA\xAC \xF0\x9F\x9A\x80");
    while (rodata.size() % 4u != 0u) rodata.push_back(0x00u);

    // UTF-16LE string ("WideRegistryPath" = 16 code points, 32 bytes)
    const std::size_t u16le_off = rodata.size();
    append_utf16le(rodata, u"WideRegistryPath");
    while (rodata.size() % 4u != 0u) rodata.push_back(0x00u);

    // UTF-16BE string ("BigEndianBanner!" = 16 code points, 32 bytes)
    const std::size_t u16be_off = rodata.size();
    append_utf16be(rodata, u"BigEndianBanner!");

    // Also include a short 2-char noise run ("ab") and x86 opcode bytes `C3 90`
    // ("ret; nop") in `.text` to ensure neither pollutes the string catalog.
    std::vector<std::uint8_t> text = {'a', 'b', 0x00, 0xC3, 0x90, 'X', 'Y', 0x00};

    const SyntheticElfLayout elf = build_test_elf64(text, rodata);
    const auto parsed = peelf::parse_image(elf.bytes);
    ASSERT_TRUE(parsed.has_value());

    const viewer::StringsIndex index = viewer::StringsIndex::extract(**parsed, elf.bytes);
    ASSERT_GE(index.size(), 4u);

    const auto* s_ascii = index.find_containing(elf.rodata_va + ascii_off);
    ASSERT_NE(s_ascii, nullptr);
    EXPECT_EQ(s_ascii->encoding, viewer::StringEncoding::Ascii);
    EXPECT_EQ(s_ascii->section_or_region_name, ".rodata");
    EXPECT_EQ(s_ascii->file_offset, elf.rodata_offset + ascii_off);
    EXPECT_EQ(s_ascii->preview, "Hello, Kernel32!\nLine2");
    EXPECT_EQ(viewer::format_single_line_string_preview(s_ascii->preview), "Hello, Kernel32!\\nLine2");

    const auto* s_utf8 = index.find_containing(elf.rodata_va + utf8_off);
    ASSERT_NE(s_utf8, nullptr);
    EXPECT_EQ(s_utf8->encoding, viewer::StringEncoding::Utf8);
    EXPECT_EQ(s_utf8->section_or_region_name, ".rodata");
    EXPECT_EQ(s_utf8->char_length, 9u);
    EXPECT_EQ(s_utf8->preview, "Caf\xC3\xA9 \xE6\x9D\xB1\xE4\xBA\xAC \xF0\x9F\x9A\x80");

    const auto* s_u16le = index.find_containing(elf.rodata_va + u16le_off);
    ASSERT_NE(s_u16le, nullptr);
    EXPECT_EQ(s_u16le->encoding, viewer::StringEncoding::Utf16Le);
    EXPECT_EQ(s_u16le->char_length, 16u);
    EXPECT_EQ(s_u16le->byte_length, 32u);
    EXPECT_EQ(s_u16le->preview, "WideRegistryPath");

    const auto* s_u16be = index.find_containing(elf.rodata_va + u16be_off);
    ASSERT_NE(s_u16be, nullptr);
    EXPECT_EQ(s_u16be->encoding, viewer::StringEncoding::Utf16Be);
    EXPECT_EQ(s_u16be->char_length, 16u);
    EXPECT_EQ(s_u16be->byte_length, 32u);
    EXPECT_EQ(s_u16be->preview, "BigEndianBanner!");

    // Ensure `.text` C3 90 (`ret; nop`) was NOT misclassified as UTF-8 U+00D0.
    EXPECT_EQ(index.find_containing(elf.text_va + 3u), nullptr);
}

TEST(StringsIndexTest, LinksIncomingXrefsIncludingInteriorPointersAndResolvesFunctions) {
    // First compute layout offsets with 0x20 bytes of .text and 0x40 bytes of .rodata,
    // then patch exact RIP-relative `lea` displacements into .text.
    std::vector<std::uint8_t> rodata(0x40, 0x00u);
    const char* s1 = "Prefix:Payload";
    const char* s2 = "UnreferencedText";
    std::memcpy(rodata.data() + 0x00, s1, std::strlen(s1));
    std::memcpy(rodata.data() + 0x20, s2, std::strlen(s2));

    std::vector<std::uint8_t> placeholder_text(0x20, 0x90u);
    const std::array<peelf::Symbol, 2> probe_syms{{
        peelf::Symbol{.name = "fn_alpha", .virtual_address = 0, .size = 0x10},
        peelf::Symbol{.name = "fn_beta",  .virtual_address = 0, .size = 0x10},
    }};
    const SyntheticElfLayout layout_probe = build_test_elf64(placeholder_text, rodata, probe_syms);

    const std::uint64_t fn_alpha_va = layout_probe.text_va;
    const std::uint64_t fn_beta_va = layout_probe.text_va + 0x10u;
    const std::uint64_t s1_va = layout_probe.rodata_va;
    const std::uint64_t s2_va = layout_probe.rodata_va + 0x20u;

    const auto disp_alpha = static_cast<std::int32_t>(s1_va - (fn_alpha_va + 7u));
    const auto disp_beta  = static_cast<std::int32_t>((s1_va + 7u) - (fn_beta_va + 7u));

    std::vector<std::uint8_t> text(0x20, 0x90u);
    // fn_alpha @ +0x00: lea rax, [rip + disp_alpha]; ret
    text[0] = 0x48u; text[1] = 0x8Du; text[2] = 0x05u;
    std::memcpy(text.data() + 3, &disp_alpha, sizeof(disp_alpha));
    text[7] = 0xC3u;
    // fn_beta  @ +0x10: lea rcx, [rip + disp_beta]; ret  (interior pointer +0x7 into "Prefix:Payload")
    text[0x10] = 0x48u; text[0x11] = 0x8Du; text[0x12] = 0x0Du;
    std::memcpy(text.data() + 0x13, &disp_beta, sizeof(disp_beta));
    text[0x17] = 0xC3u;

    const std::array<peelf::Symbol, 2> real_syms{{
        peelf::Symbol{.name = "fn_alpha", .virtual_address = fn_alpha_va, .size = 0x10},
        peelf::Symbol{.name = "fn_beta",  .virtual_address = fn_beta_va,  .size = 0x10},
    }};
    const SyntheticElfLayout elf = build_test_elf64(text, rodata, real_syms);
    const auto parsed = peelf::parse_image(elf.bytes);
    ASSERT_TRUE(parsed.has_value());

    viewer::SymbolIndex sym_index = viewer::SymbolIndex::build(**parsed);
    const viewer::FunctionIndex fn_index = viewer::FunctionIndex::discover(**parsed, sym_index, elf.bytes);

    viewer::StringsIndex strings = viewer::StringsIndex::extract(**parsed, elf.bytes);
    ASSERT_EQ(strings.size(), 2u);

    // Before ReferenceIndex is populated, xrefs are 0; repeat call with unchanged revisions is a no-op.
    viewer::ReferenceIndex empty_refs;
    EXPECT_TRUE(strings.refresh_xrefs(empty_refs, &fn_index, &sym_index, 1u));
    EXPECT_FALSE(strings.refresh_xrefs(empty_refs, &fn_index, &sym_index, 1u));
    const auto* before_s1 = strings.find_containing(s1_va);
    ASSERT_NE(before_s1, nullptr);
    EXPECT_EQ(before_s1->xref_count, 0u);

    // Build ReferenceIndex and verify automatic revision-driven refresh.
    const viewer::ReferenceIndex built_refs = viewer::ReferenceIndex::build(
        **parsed, elf.bytes, false, viewer::ReferenceIndex::kDefaultByteBudget, &sym_index);
    EXPECT_TRUE(strings.refresh_xrefs(built_refs, &fn_index, &sym_index, 1u));
    EXPECT_FALSE(strings.refresh_xrefs(built_refs, &fn_index, &sym_index, 1u));

    const auto* linked_s1 = strings.find_containing(s1_va);
    ASSERT_NE(linked_s1, nullptr);
    EXPECT_EQ(linked_s1->preview, "Prefix:Payload");
    EXPECT_EQ(linked_s1->xref_count, 2u);
    ASSERT_EQ(linked_s1->referrers.size(), 2u);

    EXPECT_EQ(linked_s1->referrers[0].instruction_address, fn_alpha_va);
    EXPECT_EQ(linked_s1->referrers[0].target_address, s1_va);
    EXPECT_EQ(linked_s1->referrers[0].function_address, std::optional<std::uint64_t>(fn_alpha_va));
    EXPECT_EQ(linked_s1->referrers[0].function_name, "fn_alpha");

    EXPECT_EQ(linked_s1->referrers[1].instruction_address, fn_beta_va);
    EXPECT_EQ(linked_s1->referrers[1].target_address, s1_va + 7u);
    EXPECT_EQ(linked_s1->referrers[1].function_address, std::optional<std::uint64_t>(fn_beta_va));
    EXPECT_EQ(linked_s1->referrers[1].function_name, "fn_beta");

    // Interior lookup at s1_va + 7 also resolves to the enclosing string.
    EXPECT_EQ(strings.find_containing(s1_va + 7u), linked_s1);

    const auto* linked_s2 = strings.find_containing(s2_va);
    ASSERT_NE(linked_s2, nullptr);
    EXPECT_EQ(linked_s2->xref_count, 0u);
}

TEST(StringsIndexTest, LiveProcessChunkedExtractionHandlesChunkStraddlingAndCancellation) {
    // Build a 300 KiB live region (> 256 KiB chunk size) with a string straddling
    // the exact 256 KiB boundary (`0x40000 - 8`), verifying it is extracted once
    // in full with no truncated chunk-1 suffix duplicate.
    constexpr std::size_t kRegionSize = 300u * 1024u;
    std::vector<std::uint8_t> backing(kRegionSize, 0x00u);
    const std::string straddle = "BoundaryCrossingStringValue!";
    const std::size_t straddle_off = (256u * 1024u) - 8u;
    std::memcpy(backing.data() + straddle_off, straddle.data(), straddle.size());

    const std::vector<peelf::MemoryRegion> regions{
        peelf::MemoryRegion{
            .start_address = 0x70000000ULL,
            .end_address = 0x70000000ULL + kRegionSize,
            .protection = {.readable = true, .writable = true, .executable = false, .shared = false},
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap]",
        },
        peelf::MemoryRegion{
            .start_address = 0x60000000ULL,
            .end_address = 0x60001000ULL,
            .protection = {.readable = true, .writable = false, .executable = false, .shared = false},
            .kind = peelf::MemoryRegionKind::Image,
            .pathname = "/unreadable/guard",
        },
    };
    MockStringsProcessSession session(regions, 0x70000000ULL, backing);

    viewer::StringScanOptions opts;
    opts.include_all_live_regions = true;
    const viewer::StringsIndex live = viewer::StringsIndex::extract_live(
        session, regions, nullptr, std::nullopt, opts);
    ASSERT_EQ(live.size(), 1u);
    EXPECT_EQ(live.entries()[0].virtual_address, 0x70000000ULL + straddle_off);
    EXPECT_EQ(live.entries()[0].preview, straddle);
    EXPECT_EQ(live.entries()[0].section_or_region_name, "[heap]");

    // Pre-cancelled stop_token stops immediately and marks incomplete().
    std::stop_source stop_src;
    stop_src.request_stop();
    const viewer::StringsIndex cancelled = viewer::StringsIndex::extract_live(
        session, regions, nullptr, std::nullopt, opts, stop_src.get_token());
    EXPECT_EQ(cancelled.size(), 0u);
    EXPECT_TRUE(cancelled.incomplete());
}

TEST(StringsIndexTest, LiveFailedReadConsumesBudgetCapsSyscallsAndMarksIncomplete) {
    class CountingHoleProcessSession final : public peelf::IProcessSession {
    public:
        CountingHoleProcessSession(std::vector<peelf::MemoryRegion> regions,
                                   std::uint64_t readable_page_va,
                                   std::vector<std::uint8_t> readable_page)
            : regions_(std::move(regions)),
              readable_page_va_(readable_page_va),
              readable_page_(std::move(readable_page)) {}

        [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override {
            return info_;
        }
        [[nodiscard]] bool is_alive() const noexcept override {
            return true;
        }
        [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
            return regions_;
        }
        [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
            return std::vector<peelf::ModuleInfo>{};
        }
        [[nodiscard]] peelf::Result<std::size_t> read_memory(
            std::uint64_t address,
            std::span<std::uint8_t> buffer) override {
            ++read_calls;
            if (!readable_page_.empty() &&
                address >= readable_page_va_ &&
                address < readable_page_va_ + readable_page_.size()) {
                const auto off = static_cast<std::size_t>(address - readable_page_va_);
                const std::size_t avail = std::min(buffer.size(), readable_page_.size() - off);
                std::memcpy(buffer.data(), readable_page_.data() + off, avail);
                return avail;
            }
            return peelf::make_error("unreadable page");
        }

        std::size_t read_calls = 0;

    private:
        peelf::ProcessInfo info_{
            .pid = 7777,
            .name = "hole_target",
            .architecture = peelf::Architecture::X86_64,
            .is_64bit = true,
            .access = peelf::ProcessAccessStatus::ReadOnly,
        };
        std::vector<peelf::MemoryRegion> regions_;
        std::uint64_t readable_page_va_ = 0;
        std::vector<std::uint8_t> readable_page_;
    };

    // 1. Unreadable 4 KiB hole followed by a readable 4 KiB page:
    //    must extract the trailing page's string AND set `incomplete() == true`!
    {
        std::vector<std::uint8_t> page2(4096u, 0u);
        const std::string marker = "RecoveredAfterUnreadableGap";
        std::memcpy(page2.data() + 64u, marker.data(), marker.size());

        const std::vector<peelf::MemoryRegion> regions{
            peelf::MemoryRegion{
                .start_address = 0x50000000ULL,
                .end_address = 0x50002000ULL, // 8 KiB: [0x50000000..0x50001000) fails, [0x50001000..0x50002000) succeeds
                .protection = {.readable = true, .writable = true},
                .kind = peelf::MemoryRegionKind::Heap,
                .pathname = "[heap]",
            },
        };
        CountingHoleProcessSession session(regions, 0x50001000ULL, std::move(page2));

        viewer::StringScanOptions opts;
        opts.include_all_live_regions = true;
        opts.chunk_bytes = 4096u;
        const viewer::StringsIndex live = viewer::StringsIndex::extract_live(
            session, regions, nullptr, std::nullopt, opts);
        EXPECT_TRUE(live.incomplete());
        ASSERT_EQ(live.size(), 1u);
        EXPECT_EQ(live.entries()[0].preview, marker);
    }

    // 2. Huge 1 GiB unreadable region:
    //    - Small byte_budget (16 KiB) stops after 4 failed 4 KiB skips!
    //    - Large byte_budget (64 MiB) is bounded by consecutive failed-read cap (<= 64 calls)!
    {
        const std::vector<peelf::MemoryRegion> huge_unreadable{
            peelf::MemoryRegion{
                .start_address = 0x80000000ULL,
                .end_address = 0x80000000ULL + (1ULL << 30u), // 1 GiB
                .protection = {.readable = true},
                .kind = peelf::MemoryRegionKind::Anonymous,
                .pathname = "[sparse]",
            },
        };

        CountingHoleProcessSession small_budget_sess(huge_unreadable, 0ULL, {});
        viewer::StringScanOptions small_opts;
        small_opts.include_all_live_regions = true;
        small_opts.byte_budget = 16u * 1024u;
        const viewer::StringsIndex res_small = viewer::StringsIndex::extract_live(
            small_budget_sess, huge_unreadable, nullptr, std::nullopt, small_opts);
        EXPECT_TRUE(res_small.incomplete());
        EXPECT_EQ(small_budget_sess.read_calls, 4u);

        CountingHoleProcessSession cap_sess(huge_unreadable, 0ULL, {});
        viewer::StringScanOptions big_opts;
        big_opts.include_all_live_regions = true;
        big_opts.byte_budget = 64u * 1024u * 1024u;
        const viewer::StringsIndex res_cap = viewer::StringsIndex::extract_live(
            cap_sess, huge_unreadable, nullptr, std::nullopt, big_opts);
        EXPECT_TRUE(res_cap.incomplete());
        EXPECT_LE(cap_sess.read_calls, 64u);
    }

    // 3. UTF-16LE string containing supplementary surrogate pair U+1F680 decodes to 4-byte UTF-8.
    {
        std::vector<std::uint8_t> rodata;
        append_utf16le(rodata, u"Launch\U0001F680Now");
        const std::array<std::uint8_t, 1> stub_text{0xC3u};
        const SyntheticElfLayout elf = build_test_elf64(stub_text, rodata);
        const auto parsed = peelf::parse_image(elf.bytes);
        ASSERT_TRUE(parsed.has_value());
        const viewer::StringsIndex idx = viewer::StringsIndex::extract(**parsed, elf.bytes);
        const auto* s = idx.find_containing(elf.rodata_va);
        ASSERT_NE(s, nullptr);
        EXPECT_EQ(s->encoding, viewer::StringEncoding::Utf16Le);
        EXPECT_EQ(s->char_length, 10u);
        EXPECT_EQ(s->preview, "Launch\xF0\x9F\x9A\x80Now");
    }
}

