#include <peelf/binary_diff.hpp>
#include <peelf/binary_image.hpp>
#include <peelf/byte_viz.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

#include "test_temp_dir.hpp"
#include "vulkan/shaders/byte_viz_comp_spirv.hpp"
#include "vulkan/spirv_validation.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <numeric>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
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
    for (std::size_t i = 0u; i < 8u; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

[[nodiscard]] std::uint64_t splitmix64(std::uint64_t& state) noexcept {
    std::uint64_t z = (state += 0x9E37'79B9'7F4A'7C15ull);
    z = (z ^ (z >> 30u)) * 0xBF58'476D'1CE4'E5B9ull;
    z = (z ^ (z >> 27u)) * 0x94D0'49BB'1331'11EBull;
    return z ^ (z >> 31u);
}

[[nodiscard]] std::vector<std::uint8_t> make_high_entropy_payload(std::size_t len,
                                                                  std::uint64_t seed = 0xC0FFEEull) {
    std::vector<std::uint8_t> out(len);
    std::uint64_t st = seed;
    for (std::size_t i = 0u; i < len; ++i) {
        out[i] = static_cast<std::uint8_t>(splitmix64(st) & 0xFFu);
    }
    return out;
}

/// Builds a compact valid ELF64 x86_64 image with `.text` (RX), `.rodata` (R), and `.data` (RW).
[[nodiscard]] std::vector<std::uint8_t> build_synthetic_elf64_for_byte_viz() {
    constexpr std::size_t kFileSize = 0x4000u;
    std::vector<std::uint8_t> img(kFileSize, 0u);

    // ELF64 header
    img[0] = 0x7Fu;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 2u; // ELFCLASS64
    img[5] = 1u; // ELFDATA2LSB
    img[6] = 1u; // EV_CURRENT
    write_u16_le(img, 16u, 2u);           // ET_EXEC
    write_u16_le(img, 18u, 62u);          // EM_X86_64
    write_u32_le(img, 20u, 1u);           // EV_CURRENT
    write_u64_le(img, 24u, 0x401000ull);  // e_entry
    write_u64_le(img, 32u, 64ull);        // e_phoff
    write_u64_le(img, 40u, 0x400ull);     // e_shoff
    write_u16_le(img, 52u, 64u);          // e_ehsize
    write_u16_le(img, 54u, 56u);          // e_phentsize
    write_u16_le(img, 56u, 3u);           // e_phnum
    write_u16_le(img, 58u, 64u);          // e_shentsize
    write_u16_le(img, 60u, 5u);           // null, .text, .rodata, .data, .shstrtab
    write_u16_le(img, 62u, 4u);           // e_shstrndx

    auto emit_phdr = [&](std::size_t idx,
                         std::uint32_t flags,
                         std::uint64_t foff,
                         std::uint64_t vaddr,
                         std::uint64_t filesz) {
        const std::size_t base = 64u + idx * 56u;
        write_u32_le(img, base + 0u, 1u); // PT_LOAD
        write_u32_le(img, base + 4u, flags);
        write_u64_le(img, base + 8u, foff);
        write_u64_le(img, base + 16u, vaddr);
        write_u64_le(img, base + 24u, vaddr);
        write_u64_le(img, base + 32u, filesz);
        write_u64_le(img, base + 40u, filesz);
        write_u64_le(img, base + 48u, 0x1000ull);
    };

    emit_phdr(0u, 5u, 0x1000ull, 0x401000ull, 0x1000ull); // RX .text
    emit_phdr(1u, 4u, 0x2000ull, 0x402000ull, 0x1000ull); // R  .rodata
    emit_phdr(2u, 6u, 0x3000ull, 0x403000ull, 0x1000ull); // RW .data

    constexpr std::string_view kShStrTab{"\0.text\0.rodata\0.data\0.shstrtab\0", 31u};
    std::memcpy(img.data() + 0x300u, kShStrTab.data(), kShStrTab.size());

    auto emit_shdr = [&](std::size_t idx,
                         std::uint32_t name_off,
                         std::uint32_t sh_type,
                         std::uint64_t sh_flags,
                         std::uint64_t sh_addr,
                         std::uint64_t sh_off,
                         std::uint64_t sh_size) {
        const std::size_t base = 0x400u + idx * 64u;
        write_u32_le(img, base + 0u, name_off);
        write_u32_le(img, base + 4u, sh_type);
        write_u64_le(img, base + 8u, sh_flags);
        write_u64_le(img, base + 16u, sh_addr);
        write_u64_le(img, base + 24u, sh_off);
        write_u64_le(img, base + 32u, sh_size);
        write_u64_le(img, base + 48u, 16ull);
    };

    emit_shdr(1u, 1u, 1u, 0x6ull, 0x401000ull, 0x1000ull, 0x1000ull);  // .text (AX)
    emit_shdr(2u, 7u, 1u, 0x2ull, 0x402000ull, 0x2000ull, 0x1000ull);  // .rodata (A)
    emit_shdr(3u, 15u, 1u, 0x3ull, 0x403000ull, 0x3000ull, 0x1000ull); // .data (WA)
    emit_shdr(4u, 21u, 3u, 0x0ull, 0ull, 0x300ull, kShStrTab.size());  // .shstrtab

    // `.text`: realistic x86-64 prologue/loop/ret sequence + NOP sled at 0x1800
    constexpr std::array<std::uint8_t, 16> kCodePattern{{
        0x55u, 0x48u, 0x89u, 0xE5u, 0x48u, 0x83u, 0xECu, 0x20u,
        0x89u, 0x7Du, 0xFCu, 0x8Bu, 0x45u, 0xFCu, 0xC9u, 0xC3u,
    }};
    for (std::size_t i = 0u; i < 0x800u; ++i) {
        img[0x1000u + i] = static_cast<std::uint8_t>(
            kCodePattern[i & 15u] ^ static_cast<std::uint8_t>((i >> 4u) & 0x07u));
    }
    std::fill_n(img.data() + 0x1800u, 0x800u, std::uint8_t{0x90u});

    // `.rodata`: ASCII strings in first half, UTF-16LE strings in second half
    constexpr std::string_view kAsciiBanner =
        "PE/ELF Explorer Cantor-Dust & Shannon Entropy Telemetry Strings!\n";
    for (std::size_t i = 0u; i < 0x800u; ++i) {
        img[0x2000u + i] = static_cast<std::uint8_t>(kAsciiBanner[i % kAsciiBanner.size()]);
    }
    constexpr std::string_view kWideSrc = "KernelBase.dll!VirtualProtectEx ";
    for (std::size_t i = 0u; i < 0x400u; ++i) {
        img[0x2800u + i * 2u] = static_cast<std::uint8_t>(kWideSrc[i % kWideSrc.size()]);
        img[0x2800u + i * 2u + 1u] = 0x00u;
    }

    // `.data`: high-entropy packed blob in first half, zero padding in second half
    const auto packed = make_high_entropy_payload(0x800u, 0xBEEF'CAFEull);
    std::memcpy(img.data() + 0x3000u, packed.data(), packed.size());

    return img;
}

class MockByteVizProcessSession final : public peelf::IProcessSession {
public:
    MockByteVizProcessSession() {
        info_.pid = 7777;
        info_.name = "byte_viz_live_target";
        info_.architecture = peelf::Architecture::X86_64;
        info_.is_64bit = true;
        info_.endianness = peelf::Endianness::Little;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return modules_;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return threads_;
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        const std::uint64_t page_base = address & ~std::uint64_t{0xFFFu};
        const auto it = pages_.find(page_base);
        if (it == pages_.end()) {
            return peelf::make_error("guard or unmapped page");
        }
        const std::size_t off = static_cast<std::size_t>(address - page_base);
        if (off >= it->second.size()) {
            return peelf::make_error("offset beyond page");
        }
        const std::size_t n = std::min(buffer.size(), it->second.size() - off);
        std::memcpy(buffer.data(), it->second.data() + off, n);
        return n;
    }

    peelf::ProcessInfo info_{};
    std::vector<peelf::MemoryRegion> regions_{};
    std::vector<peelf::ModuleInfo> modules_{};
    std::vector<peelf::ThreadInfo> threads_{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> pages_{};
};

class MockByteVizCrashSession final : public peelf::ICrashDumpSession {
public:
    MockByteVizCrashSession() {
        info_.pid = 8080;
        info_.name = "crash_target";
        info_.architecture = peelf::Architecture::X86_64;
        info_.is_64bit = true;
        info_.endianness = peelf::Endianness::Little;
        summary_.kind = peelf::CrashDumpKind::ElfCore;
        summary_.pid = 8080;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] const peelf::CrashDumpSummary& crash_summary() const noexcept override {
        return summary_;
    }
    [[nodiscard]] const peelf::ProcessInternalsSnapshot& crash_internals() const noexcept override {
        return internals_;
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return regions_;
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return modules_;
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return threads_;
    }
    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        const std::uint64_t page_base = address & ~std::uint64_t{0xFFFu};
        const auto it = pages_.find(page_base);
        if (it == pages_.end()) {
            return peelf::make_error("page excluded from core dump");
        }
        const std::size_t off = static_cast<std::size_t>(address - page_base);
        const std::size_t n = std::min(buffer.size(), it->second.size() - off);
        std::memcpy(buffer.data(), it->second.data() + off, n);
        return n;
    }

    peelf::ProcessInfo info_{};
    peelf::CrashDumpSummary summary_{};
    peelf::ProcessInternalsSnapshot internals_{};
    std::vector<peelf::MemoryRegion> regions_{};
    std::vector<peelf::ModuleInfo> modules_{};
    std::vector<peelf::ThreadInfo> threads_{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> pages_{};
};

// ---------------------------------------------------------------------------
// 1. Exact Shannon Entropy Math & Quantization
// ---------------------------------------------------------------------------

TEST(ByteVizEntropyMathTest, ExactZeroOneTwoAndEightBitsPerByte) {
    // Empty span -> 0.0 bits/byte.
    EXPECT_DOUBLE_EQ(peelf::compute_shannon_entropy_bits({}), 0.0);
    EXPECT_EQ(peelf::quantize_entropy_u8(0.0), 0u);
    EXPECT_EQ(peelf::quantize_entropy_u8(-1.0), 0u);

    // Constant single-symbol spans -> 0.0 bits/byte.
    const std::vector<std::uint8_t> all_zero(1024u, 0x00u);
    const std::vector<std::uint8_t> all_cc(512u, 0xCCu);
    EXPECT_NEAR(peelf::compute_shannon_entropy_bits(all_zero), 0.0, 1e-12);
    EXPECT_NEAR(peelf::compute_shannon_entropy_bits(all_cc), 0.0, 1e-12);

    // Exact 50/50 two-symbol distribution -> 1.0 bit/byte.
    std::vector<std::uint8_t> two_sym(1024u);
    for (std::size_t i = 0u; i < two_sym.size(); ++i) {
        two_sym[i] = (i & 1u) == 0u ? 0x00u : 0xFFu;
    }
    EXPECT_NEAR(peelf::compute_shannon_entropy_bits(two_sym), 1.0, 1e-12);

    // Exact 4-symbol uniform distribution -> 2.0 bits/byte.
    std::vector<std::uint8_t> four_sym(1024u);
    for (std::size_t i = 0u; i < four_sym.size(); ++i) {
        four_sym[i] = static_cast<std::uint8_t>(i & 3u);
    }
    EXPECT_NEAR(peelf::compute_shannon_entropy_bits(four_sym), 2.0, 1e-12);

    // Exact 256-symbol uniform distribution -> 8.0 bits/byte.
    std::vector<std::uint8_t> uniform_256(4096u);
    for (std::size_t i = 0u; i < uniform_256.size(); ++i) {
        uniform_256[i] = static_cast<std::uint8_t>(i & 0xFFu);
    }
    const double h8 = peelf::compute_shannon_entropy_bits(uniform_256);
    EXPECT_NEAR(h8, 8.0, 1e-12);
    EXPECT_EQ(peelf::quantize_entropy_u8(h8), 255u);
    EXPECT_DOUBLE_EQ(peelf::dequantize_entropy_bits(255u), 8.0);
}

// ---------------------------------------------------------------------------
// 2. ByteClass Classification & 16-Byte Tile Packing
// ---------------------------------------------------------------------------

TEST(ByteVizClassificationTest, ClassifiesZeroNopAsciiUtf16CodeAndHighEntropyPayloads) {
    // 1. All-zero padding
    {
        const std::vector<std::uint8_t> zeros(512u, 0x00u);
        const auto m = peelf::analyze_byte_span(zeros);
        EXPECT_EQ(m.byte_class, peelf::ByteClass::AllZeroPadding);
        EXPECT_EQ(m.zero_u8, 255u);
        EXPECT_EQ(m.entropy_u8, 0u);
    }

    // 2. 0x90 NOP sled & 0xCC INT3 sled
    {
        const std::vector<std::uint8_t> nops(512u, 0x90u);
        const std::vector<std::uint8_t> traps(512u, 0xCCu);
        EXPECT_EQ(peelf::analyze_byte_span(nops).byte_class, peelf::ByteClass::TrapOrNopSlide);
        EXPECT_EQ(peelf::analyze_byte_span(traps).byte_class, peelf::ByteClass::TrapOrNopSlide);
    }

    // 3. Printable ASCII text
    {
        constexpr std::string_view kLine =
            "The quick brown fox jumps over the lazy dog 0123456789!\n";
        std::vector<std::uint8_t> ascii(512u);
        for (std::size_t i = 0u; i < ascii.size(); ++i) {
            ascii[i] = static_cast<std::uint8_t>(kLine[i % kLine.size()]);
        }
        const auto m = peelf::analyze_byte_span(ascii);
        EXPECT_EQ(m.byte_class, peelf::ByteClass::AsciiText);
        EXPECT_EQ(m.printable_u8, 255u);
        EXPECT_EQ(m.zero_u8, 0u);
    }

    // 4. UTF-16LE text
    {
        constexpr std::string_view kText = "Microsoft Windows NT Debugging Symbols ";
        std::vector<std::uint8_t> utf16(512u);
        for (std::size_t i = 0u; i + 1u < utf16.size(); i += 2u) {
            utf16[i] = static_cast<std::uint8_t>(kText[(i / 2u) % kText.size()]);
            utf16[i + 1u] = 0x00u;
        }
        const auto m = peelf::analyze_byte_span(utf16);
        EXPECT_EQ(m.byte_class, peelf::ByteClass::Utf16LeText);
        EXPECT_GT(m.zero_u8, 110u);
    }

    // 5. Structured machine code (moderate entropy, mixed opcodes/zeros/high-bit)
    {
        constexpr std::array<std::uint8_t, 16> kInsns{{
            0x55u, 0x48u, 0x89u, 0xE5u, 0x48u, 0x83u, 0xECu, 0x30u,
            0xE8u, 0x10u, 0x00u, 0x00u, 0x00u, 0x85u, 0xC0u, 0xC3u,
        }};
        std::vector<std::uint8_t> code(512u);
        for (std::size_t i = 0u; i < code.size(); ++i) {
            code[i] = static_cast<std::uint8_t>(
                kInsns[i & 15u] ^ static_cast<std::uint8_t>((i >> 4u) & 0x0Fu));
        }
        const auto m = peelf::analyze_byte_span(code);
        EXPECT_EQ(m.byte_class, peelf::ByteClass::CodeOrStructured);
        EXPECT_GT(m.entropy_bits, 3.0);
        EXPECT_LT(m.entropy_bits, 7.2);
    }

    // 6. High-entropy encrypted / PRNG payload
    {
        const auto prng = make_high_entropy_payload(4096u, 0x1234'5678'9ABC'DEF0ull);
        const auto m = peelf::analyze_byte_span(prng);
        EXPECT_EQ(m.byte_class, peelf::ByteClass::HighEntropyPacked);
        EXPECT_GT(m.entropy_bits, 7.8);
    }

    // 7. 16-byte `ByteVizTile` SSBO layout & page-scaled span round-trip
    static_assert(sizeof(peelf::ByteVizTile) == 16u);
    static_assert(alignof(peelf::ByteVizTile) == 16u);
    const auto tile = peelf::ByteVizTile::pack(
        0x0000'7FF7'ABCD'1000ull,
        16ull * 1024ull * 1024ull, // 16 MiB -> uses 4 KiB page scale
        peelf::ByteClass::HighEntropyPacked,
        248u,
        90u,
        4u,
        128u,
        peelf::ByteVizTileFlagBits::kPatchDirty | peelf::ByteVizTileFlagBits::kExecutable);
    EXPECT_EQ(tile.base_offset_or_va(), 0x0000'7FF7'ABCD'1000ull);
    EXPECT_EQ(tile.span_bytes(), 16ull * 1024ull * 1024ull);
    EXPECT_EQ(tile.byte_class(), peelf::ByteClass::HighEntropyPacked);
    EXPECT_TRUE(tile.is_patch_dirty());
    EXPECT_TRUE(tile.is_executable());
    EXPECT_FALSE(tile.is_diff_modified());
    EXPECT_EQ(tile.entropy_u8(), 248u);
    EXPECT_EQ(tile.printable_u8(), 90u);
    EXPECT_EQ(tile.zero_u8(), 4u);
    EXPECT_EQ(tile.high_bit_u8(), 128u);
}

// ---------------------------------------------------------------------------
// 3. Static PagedBinaryImage PatchDirty & BinaryDiff Attribution + Layouts
// ---------------------------------------------------------------------------

TEST(ByteVizStaticImageTest, AttributesPatchDirtyAndDiffRangesAndSupportsHilbertAndLinearRelayout) {
    peelf_test::ScopedTempDir tmp("peelf_byte_viz_static");
    const std::vector<std::uint8_t> raw_elf = build_synthetic_elf64_for_byte_viz();

    auto img_res = peelf::open_binary_image(raw_elf);
    ASSERT_TRUE(img_res.has_value()) << img_res.error().message;
    auto paged_res = peelf::PagedBinaryImage::open(tmp.write_bytes("sample.elf", raw_elf));
    ASSERT_TRUE(paged_res.has_value()) << paged_res.error().message;

    // Stage a patch in the zero-padded half of `.data` (file offset 0x3A00, 256 bytes of ASCII).
    std::vector<std::uint8_t> staged_ascii(256u, static_cast<std::uint8_t>('A'));
    for (std::size_t i = 0u; i < staged_ascii.size(); ++i) {
        staged_ascii[i] = static_cast<std::uint8_t>('A' + (i % 26u));
    }
    ASSERT_TRUE(paged_res->apply_patch(0x3A00u, staged_ascii, "inject ascii").has_value());

    // Build synthetic diff ranges (one Modified in `.text`, one Added in `.rodata`).
    const std::array<peelf::ByteVizDiffRange, 2> diff_ranges{{
        peelf::ByteVizDiffRange{
            .offset_or_va = 0x1100u,
            .size_bytes = 64u,
            .is_virtual_address = false,
            .kind = peelf::ByteVizDiffKind::Modified,
        },
        peelf::ByteVizDiffRange{
            .offset_or_va = 0x2200u,
            .size_bytes = 64u,
            .is_virtual_address = false,
            .kind = peelf::ByteVizDiffKind::Added,
        },
    }};

    peelf::ByteVizConfig cfg{};
    cfg.layout = peelf::ByteVizLayout::HilbertCurve;
    cfg.min_tile_bytes = 256u;

    const auto obs = peelf::compute_static_byte_viz(
        **img_res, raw_elf, cfg, &(*paged_res), diff_ranges);
    EXPECT_EQ(obs.provenance, peelf::ProvenanceTag::DiskFile);
    EXPECT_EQ(obs.availability, peelf::CaptureAvailability::Complete);
    ASSERT_TRUE(obs.value.has_value());

    auto snap = *obs.value;
    ASSERT_EQ(snap.tiles.size(), 0x4000u / 256u);
    EXPECT_GE(snap.stats.patch_dirty_tile_count, 1u);
    EXPECT_EQ(snap.stats.diff_tile_count, 2u);

    // Patched tile @ 0x3A00 reflects both `is_patch_dirty()` AND the new `AsciiText` bytes!
    const auto patched_idx = snap.find_tile_index_containing(0x3A00u);
    ASSERT_TRUE(patched_idx.has_value());
    EXPECT_TRUE(snap.tiles[*patched_idx].is_patch_dirty());
    EXPECT_EQ(snap.tiles[*patched_idx].byte_class(), peelf::ByteClass::AsciiText);

    // DiffModified tile @ 0x1100 is executable and carries `kDiffModified`.
    const auto mod_idx = snap.find_tile_index_containing(0x1100u);
    ASSERT_TRUE(mod_idx.has_value());
    EXPECT_TRUE(snap.tiles[*mod_idx].is_diff_modified());
    EXPECT_TRUE(snap.tiles[*mod_idx].is_executable());

    // DiffAdded tile @ 0x2200 carries `kDiffAdded`.
    const auto add_idx = snap.find_tile_index_containing(0x2200u);
    ASSERT_TRUE(add_idx.has_value());
    EXPECT_TRUE(snap.tiles[*add_idx].is_diff_added());

    // Section start @ 0x1000 carries `kSectionStart` and resolves `.text`.
    const auto text_start_idx = snap.find_tile_index_containing(0x1000u);
    ASSERT_TRUE(text_start_idx.has_value());
    EXPECT_TRUE(snap.tiles[*text_start_idx].is_section_start());
    const auto* sec = snap.find_section_at(0x1000u);
    ASSERT_NE(sec, nullptr);
    EXPECT_EQ(sec->name, ".text");

    // HilbertCurve and LinearRows coordinate round-trip for every tile.
    for (std::size_t i = 0u; i < snap.tiles.size(); ++i) {
        const auto xy = snap.tile_grid_coords(i);
        EXPECT_EQ(snap.grid_coords_to_tile_index(xy.x, xy.y), i);
    }
    snap.relayout(peelf::ByteVizLayout::LinearRows);
    EXPECT_EQ(snap.layout, peelf::ByteVizLayout::LinearRows);
    for (std::size_t i = 0u; i < snap.tiles.size(); ++i) {
        const auto xy = snap.tile_grid_coords(i);
        EXPECT_EQ(snap.grid_coords_to_tile_index(xy.x, xy.y), i);
    }
}

// ---------------------------------------------------------------------------
// 4. CantorDustDigram256 Conservation, Quadrants, UTF-16 Stripes & Brushing
// ---------------------------------------------------------------------------

TEST(ByteVizCantorDigramTest, ConservesPairCountsDetectsQuadrantsAndResolvesFirstOccurrences) {
    // 0-byte and 1-byte edge cases produce 0 pairs cleanly.
    const std::array<std::uint8_t, 1> single{{0x42u}};
    const auto single_obs = peelf::compute_cantor_digram_from_bytes(single);
    ASSERT_TRUE(single_obs.value.has_value());
    EXPECT_EQ(single_obs.value->total_pairs, 0u);

    // Pure ASCII buffer: N - 1 conservation & 100% ASCII quadrant concentration.
    constexpr std::string_view kAscii = "ELF64_Cantor_Dust_Attractor_Plot_Test_1234567890";
    const std::span<const std::uint8_t> ascii_bytes{
        reinterpret_cast<const std::uint8_t*>(kAscii.data()), kAscii.size()};
    const auto ascii_obs = peelf::compute_cantor_digram_from_bytes(ascii_bytes, 0x2000ull, false);
    ASSERT_TRUE(ascii_obs.value.has_value());
    const auto& ascii_digram = *ascii_obs.value;

    EXPECT_EQ(ascii_digram.total_pairs, kAscii.size() - 1u);
    const std::uint64_t sum_counts = std::accumulate(
        ascii_digram.pair_counts.begin(), ascii_digram.pair_counts.end(), std::uint64_t{0});
    EXPECT_EQ(sum_counts, ascii_digram.total_pairs);
    EXPECT_EQ(ascii_digram.ascii_quadrant_pairs, ascii_digram.total_pairs);
    EXPECT_EQ(ascii_digram.utf16_stripe_pairs, 0u);

    // Representative first-occurrence lookup matches exact byte pair in input!
    const auto first_el = ascii_digram.first_occurrence_at(
        static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'));
    ASSERT_TRUE(first_el.has_value());
    EXPECT_EQ(*first_el, 0x2000ull);

    const auto first_ca = ascii_digram.first_occurrence_at(
        static_cast<std::uint8_t>('C'), static_cast<std::uint8_t>('a'));
    ASSERT_TRUE(first_ca.has_value());
    EXPECT_EQ(*first_ca, 0x2000ull + 6ull);
    EXPECT_FALSE(ascii_digram.first_occurrence_at(0xDEu, 0xADu).has_value());

    // UTF-16LE buffer: 100% `(ascii, 0x00)` / `(0x00, ascii)` stripe concentration.
    std::vector<std::uint8_t> utf16_bytes;
    constexpr std::string_view kWide = "ntdll.dll!NtQueryVirtualMemory";
    for (const char ch : kWide) {
        utf16_bytes.push_back(static_cast<std::uint8_t>(ch));
        utf16_bytes.push_back(0x00u);
    }
    const auto utf16_obs = peelf::compute_cantor_digram_from_bytes(utf16_bytes, 0x5000ull, true);
    ASSERT_TRUE(utf16_obs.value.has_value());
    EXPECT_EQ(utf16_obs.value->total_pairs, utf16_bytes.size() - 1u);
    EXPECT_EQ(utf16_obs.value->utf16_stripe_pairs, utf16_obs.value->total_pairs);
    EXPECT_TRUE(utf16_obs.value->addresses_are_virtual);
    EXPECT_EQ(
        utf16_obs.value->first_occurrence_at(static_cast<std::uint8_t>('n'), 0x00u),
        std::optional<std::uint64_t>{0x5000ull});

    // Brushed subrange recomputation on synthetic ELF64 isolates the NOP sled `[0x1800, 0x2000)`.
    const std::vector<std::uint8_t> raw_elf = build_synthetic_elf64_for_byte_viz();
    auto img_res = peelf::open_binary_image(raw_elf);
    ASSERT_TRUE(img_res.has_value());

    const auto brushed = peelf::compute_static_cantor_digram(
        **img_res, raw_elf, 0x1800ull, 0x2000ull, nullptr);
    ASSERT_TRUE(brushed.value.has_value());
    EXPECT_EQ(brushed.value->total_pairs, 0x800u - 1u);
    EXPECT_EQ(brushed.value->occupied_bins, 1u);
    EXPECT_EQ(brushed.value->count_at(0x90u, 0x90u), 0x800u - 1u);
    EXPECT_EQ(brushed.value->first_occurrence_at(0x90u, 0x90u),
              std::optional<std::uint64_t>{0x1800ull});
    const std::size_t nop_bin = peelf::cantor_bin_index(0x90u, 0x90u);
    EXPECT_EQ(peelf::unpack_cantor_density_u16(brushed.value->packed_gpu_bins[nop_bin]), 65535u);
    EXPECT_EQ(peelf::unpack_cantor_pair_class(brushed.value->packed_gpu_bins[nop_bin]),
              peelf::CantorPairClass::TrapOrNop);
    EXPECT_TRUE(peelf::unpack_cantor_has_occurrence(brushed.value->packed_gpu_bins[nop_bin]));
}

// ---------------------------------------------------------------------------
// 5. Cooperative Cancellation (`std::stop_token`) & Unreadable Live Provenance
// ---------------------------------------------------------------------------

TEST(ByteVizProvenanceAndCancellationTest, HandlesStopTokenAndUnreadableLivePagesCleanly) {
    // 1. Pre-cancelled stop_token exits immediately without hanging.
    std::stop_source stop_src{};
    stop_src.request_stop();

    const std::vector<std::uint8_t> payload = make_high_entropy_payload(65536u);
    const auto cancelled_viz = peelf::compute_byte_viz_from_bytes(
        payload, {}, 0u, false, {}, {}, {}, stop_src.get_token());
    EXPECT_NE(cancelled_viz.availability, peelf::CaptureAvailability::Complete);

    const auto cancelled_cantor = peelf::compute_cantor_digram_from_bytes(
        payload, 0u, false, stop_src.get_token());
    EXPECT_NE(cancelled_cantor.availability, peelf::CaptureAvailability::Complete);

    // 2. Live process session with alternating mapped & guard pages:
    //    Page 0 (0x400000): all 'Z' (readable)
    //    Page 1 (0x401000): unmapped guard gap!
    //    Page 2 (0x402000): all 0xCC (readable)
    //    Page 3 (0x403000): unmapped guard gap!
    MockByteVizProcessSession live{};
    live.pages_[0x400000ull] = std::vector<std::uint8_t>(4096u, static_cast<std::uint8_t>('Z'));
    live.pages_[0x402000ull] = std::vector<std::uint8_t>(4096u, 0xCCu);

    const peelf::MemoryRegion region{
        .start_address = 0x400000ull,
        .end_address = 0x404000ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "partial_live_module",
    };

    peelf::ByteVizConfig cfg{};
    cfg.min_tile_bytes = 4096u;
    const auto live_obs = peelf::compute_live_region_byte_viz(live, region, cfg);
    EXPECT_EQ(live_obs.provenance, peelf::ProvenanceTag::LiveMemory);
    EXPECT_EQ(live_obs.availability, peelf::CaptureAvailability::Partial);
    ASSERT_TRUE(live_obs.value.has_value());

    const auto& snap = *live_obs.value;
    ASSERT_EQ(snap.tiles.size(), 4u);
    EXPECT_EQ(snap.stats.readable_bytes, 8192u);
    EXPECT_EQ(snap.stats.unreadable_bytes, 8192u);
    EXPECT_EQ(snap.stats.unreadable_gap_count, 2u);
    EXPECT_EQ(snap.tiles[0].byte_class(), peelf::ByteClass::AsciiText);
    EXPECT_EQ(snap.tiles[1].byte_class(), peelf::ByteClass::UnreadableOrEmpty);
    EXPECT_EQ(snap.tiles[2].byte_class(), peelf::ByteClass::TrapOrNopSlide);
    EXPECT_EQ(snap.tiles[3].byte_class(), peelf::ByteClass::UnreadableOrEmpty);

    // Crucial invariant: no synthetic cross-gap pair ('Z', 0xCC) may be fabricated across Page 1!
    EXPECT_EQ(snap.cantor.count_at(static_cast<std::uint8_t>('Z'), 0xCCu), 0u);
    EXPECT_EQ(snap.cantor.total_pairs, (4096u - 1u) * 2u);

    // 3. Crash-dump session tags provenance as `ProvenanceTag::CrashDump`.
    MockByteVizCrashSession crash{};
    crash.pages_[0x400000ull] = std::vector<std::uint8_t>(4096u, 0x90u);
    const peelf::MemoryRegion crash_reg{
        .start_address = 0x400000ull,
        .end_address = 0x401000ull,
        .protection = {.readable = true, .writable = false, .executable = true},
        .kind = peelf::MemoryRegionKind::Image,
        .pathname = "crash_text",
    };
    const auto crash_obs = peelf::compute_live_region_byte_viz(crash, crash_reg, cfg);
    EXPECT_EQ(crash_obs.provenance, peelf::ProvenanceTag::CrashDump);
    EXPECT_EQ(crash_obs.availability, peelf::CaptureAvailability::Complete);
}

// ---------------------------------------------------------------------------
// 6. Vulkan SPIR-V Validation & Deterministic CPU Reference RGBA8 Rasterizer
// ---------------------------------------------------------------------------

TEST(ByteVizShaderAndRasterizerTest, ValidatesSpirvAndProducesDeterministicRgba8AcrossModes) {
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kByteVizCompSpirv));
    EXPECT_LE(sizeof(viewer::shaders::ByteVizPushConstants), 128u);

    const std::vector<std::uint8_t> raw_elf = build_synthetic_elf64_for_byte_viz();
    auto img_res = peelf::open_binary_image(raw_elf);
    ASSERT_TRUE(img_res.has_value());

    peelf::ByteVizConfig cfg{};
    cfg.min_tile_bytes = 256u;
    const auto obs = peelf::compute_static_byte_viz(**img_res, raw_elf, cfg);
    ASSERT_TRUE(obs.value.has_value());
    const auto& snap = *obs.value;

    peelf::ByteVizViewport vp{
        .width_px = 96u,
        .height_px = 96u,
        .center_x = static_cast<double>(snap.grid_width) * 0.5,
        .center_y = static_cast<double>(snap.grid_height) * 0.5,
        .scale_x = 8.0,
        .scale_y = 8.0,
        .show_guides_and_grid = true,
        .brushed_address_range = std::pair<std::uint64_t, std::uint64_t>{0x1000ull, 0x2000ull},
        .hovered_index = 4u,
        .selected_index = 16u,
    };

    const std::size_t expected_bytes =
        static_cast<std::size_t>(vp.width_px) * static_cast<std::size_t>(vp.height_px) * 4u;

    std::vector<std::vector<std::uint8_t>> palette_outputs{};
    for (const auto palette : {peelf::ByteVizColorMode::EntropySpectrum,
                               peelf::ByteVizColorMode::ByteClassSemantic,
                               peelf::ByteVizColorMode::PrintableVsHighBit,
                               peelf::ByteVizColorMode::PatchAndDiffOverlay}) {
        const auto img_a = peelf::rasterize_byte_viz_rgba8(
            vp, snap, peelf::ByteVizMode::EntropyAndByteClass2D, palette);
        const auto img_b = peelf::rasterize_byte_viz_rgba8(
            vp, snap, peelf::ByteVizMode::EntropyAndByteClass2D, palette);
        ASSERT_EQ(img_a.size(), expected_bytes);
        EXPECT_EQ(img_a, img_b);
        for (std::size_t px = 3u; px < img_a.size(); px += 4u) {
            EXPECT_EQ(img_a[px], 255u);
        }
        palette_outputs.push_back(img_a);
    }
    // Distinct palettes render distinct visual encodings.
    EXPECT_NE(palette_outputs[0], palette_outputs[1]);
    EXPECT_NE(palette_outputs[1], palette_outputs[2]);

    // Cantor-Dust 256x256 mode: deterministic with & without quadrant guides.
    peelf::ByteVizViewport cantor_vp{
        .width_px = 128u,
        .height_px = 128u,
        .center_x = 128.0,
        .center_y = 128.0,
        .scale_x = 0.5,
        .scale_y = 0.5,
        .show_guides_and_grid = true,
        .hovered_index = peelf::cantor_bin_index(0x90u, 0x90u),
        .selected_index = peelf::cantor_bin_index(static_cast<std::uint8_t>('P'),
                                                  static_cast<std::uint8_t>('E')),
    };
    const auto cantor_guides = peelf::rasterize_byte_viz_rgba8(
        cantor_vp, snap, peelf::ByteVizMode::CantorDustDigram256);
    const auto cantor_guides_repeat = peelf::rasterize_byte_viz_rgba8(
        cantor_vp, snap, peelf::ByteVizMode::CantorDustDigram256);
    ASSERT_EQ(cantor_guides.size(), 128u * 128u * 4u);
    EXPECT_EQ(cantor_guides, cantor_guides_repeat);

    cantor_vp.show_guides_and_grid = false;
    const auto cantor_no_guides = peelf::rasterize_byte_viz_rgba8(
        cantor_vp, snap, peelf::ByteVizMode::CantorDustDigram256);
    EXPECT_NE(cantor_guides, cantor_no_guides);
}

} // namespace
