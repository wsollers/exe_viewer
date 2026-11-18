#include <peelf/binary_image.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/memory_heatmap.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

#include "test_temp_dir.hpp"
#include "vulkan/shaders/memory_heatmap_comp_spirv.hpp"
#include "vulkan/spirv_validation.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

[[nodiscard]] std::uint32_t manhattan_distance(peelf::HilbertCoord2D a,
                                               peelf::HilbertCoord2D b) noexcept {
    const std::uint32_t dx = a.x >= b.x ? (a.x - b.x) : (b.x - a.x);
    const std::uint32_t dy = a.y >= b.y ? (a.y - b.y) : (b.y - a.y);
    return dx + dy;
}

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

/// Builds a compact valid ELF64 x86_64 image with `.text` (RX), `.data` (RW), and `.rwx` (RWX).
[[nodiscard]] std::vector<std::uint8_t> build_synthetic_elf64_with_rwx() {
    constexpr std::size_t kFileSize = 0x5000u;
    std::vector<std::uint8_t> img(kFileSize, 0u);

    // ELF64 header (64 bytes)
    img[0] = 0x7Fu;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 2u; // ELFCLASS64
    img[5] = 1u; // ELFDATA2LSB
    img[6] = 1u; // EV_CURRENT
    write_u16_le(img, 16u, 2u);      // ET_EXEC
    write_u16_le(img, 18u, 62u);     // EM_X86_64
    write_u32_le(img, 20u, 1u);      // EV_CURRENT
    write_u64_le(img, 24u, 0x401000ull); // e_entry
    write_u64_le(img, 32u, 64ull);   // e_phoff
    write_u64_le(img, 40u, 0x400ull); // e_shoff
    write_u16_le(img, 52u, 64u);     // e_ehsize
    write_u16_le(img, 54u, 56u);     // e_phentsize
    write_u16_le(img, 56u, 3u);      // e_phnum
    write_u16_le(img, 58u, 64u);     // e_shentsize
    write_u16_le(img, 60u, 5u);      // e_shnum (null, .text, .data, .rwx, .shstrtab)
    write_u16_le(img, 62u, 4u);      // e_shstrndx

    auto emit_phdr = [&](std::size_t idx,
                         std::uint32_t flags,
                         std::uint64_t foff,
                         std::uint64_t vaddr,
                         std::uint64_t filesz,
                         std::uint64_t memsz) {
        const std::size_t base = 64u + idx * 56u;
        write_u32_le(img, base + 0u, 1u); // PT_LOAD
        write_u32_le(img, base + 4u, flags);
        write_u64_le(img, base + 8u, foff);
        write_u64_le(img, base + 16u, vaddr);
        write_u64_le(img, base + 24u, vaddr);
        write_u64_le(img, base + 32u, filesz);
        write_u64_le(img, base + 40u, memsz);
        write_u64_le(img, base + 48u, 0x1000ull);
    };

    // PF_X=1, PF_W=2, PF_R=4
    emit_phdr(0u, 5u, 0x1000ull, 0x401000ull, 0x1000ull, 0x1000ull); // RX .text
    emit_phdr(1u, 6u, 0x2000ull, 0x402000ull, 0x1000ull, 0x1000ull); // RW .data
    emit_phdr(2u, 7u, 0x3000ull, 0x403000ull, 0x1000ull, 0x1000ull); // RWX .rwx

    // Section header string table at 0x300
    constexpr std::string_view kShStrTab{"\0.text\0.data\0.rwx\0.shstrtab\0", 28u};
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

    // SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4
    emit_shdr(1u, 1u, 1u, 0x6ull, 0x401000ull, 0x1000ull, 0x1000ull);  // .text (AX)
    emit_shdr(2u, 7u, 1u, 0x3ull, 0x402000ull, 0x2000ull, 0x1000ull);  // .data (WA)
    emit_shdr(3u, 13u, 1u, 0x7ull, 0x403000ull, 0x3000ull, 0x1000ull); // .rwx  (WAX)
    emit_shdr(4u, 18u, 3u, 0x0ull, 0ull, 0x300ull, kShStrTab.size());  // .shstrtab

    // Populate non-trivial bytes in .text and .data
    for (std::size_t i = 0u; i < 0x1000u; ++i) {
        img[0x1000u + i] = static_cast<std::uint8_t>((i * 37u + 0x90u) & 0xFFu);
        img[0x2000u + i] = static_cast<std::uint8_t>((i & 0x0Fu) + 0x41u);
        img[0x3000u + i] = 0xCCu;
    }

    return img;
}

class MockLiveProcessSession final : public peelf::IProcessSession {
public:
    MockLiveProcessSession() {
        info_.pid = 4242;
        info_.name = "mock_target";
        info_.architecture = peelf::Architecture::X86_64;
        info_.is_64bit = true;
        info_.endianness = peelf::Endianness::Little;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return alive_; }

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
        const auto it = page_bytes_.find(page_base);
        if (it == page_bytes_.end()) {
            return peelf::make_error("unmapped mock page");
        }
        const std::size_t page_off = static_cast<std::size_t>(address - page_base);
        if (page_off >= it->second.size()) {
            return peelf::make_error("page offset out of range");
        }
        const std::size_t n = std::min(buffer.size(), it->second.size() - page_off);
        std::memcpy(buffer.data(), it->second.data() + page_off, n);
        bytes_read_total_ += n;
        bytes_read_last_tick_ += n;
        return n;
    }

    void set_page_fill(std::uint64_t page_va, std::uint8_t value) {
        page_bytes_[page_va & ~std::uint64_t{0xFFFu}] = std::vector<std::uint8_t>(4096u, value);
    }

    void set_page_high_entropy(std::uint64_t page_va) {
        std::vector<std::uint8_t> data(4096u);
        for (std::size_t i = 0u; i < data.size(); ++i) {
            data[i] = static_cast<std::uint8_t>((i * 131u + (i >> 4u) * 17u) & 0xFFu);
        }
        page_bytes_[page_va & ~std::uint64_t{0xFFFu}] = std::move(data);
    }

    void reset_tick_read_counter() noexcept { bytes_read_last_tick_ = 0u; }
    [[nodiscard]] std::size_t bytes_read_last_tick() const noexcept {
        return bytes_read_last_tick_;
    }

    peelf::ProcessInfo info_{};
    bool alive_{true};
    std::vector<peelf::MemoryRegion> regions_{};
    std::vector<peelf::ModuleInfo> modules_{};
    std::vector<peelf::ThreadInfo> threads_{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> page_bytes_{};
    std::size_t bytes_read_total_{0};
    std::size_t bytes_read_last_tick_{0};
};

class MockCrashDumpSession final : public peelf::ICrashDumpSession {
public:
    MockCrashDumpSession() {
        info_.pid = 9001;
        info_.name = "crashed_app";
        info_.architecture = peelf::Architecture::X86_64;
        info_.is_64bit = true;
        info_.endianness = peelf::Endianness::Little;

        summary_.kind = peelf::CrashDumpKind::ElfCore;
        summary_.pid = 9001;
        summary_.layout = peelf::TargetLayout{
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .endianness = peelf::Endianness::Little,
        };
        summary_.region_count = 2u;
        summary_.exception = peelf::CrashExceptionInfo{
            .thread_id = 77u,
            .fault_code = 11u,
            .fault_name = "SIGSEGV",
            .fault_address = 0xDEAD0000ull,
            .instruction_pointer = 0x500010ull,
        };
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
        const std::uint64_t base = address & ~std::uint64_t{0xFFFu};
        const auto it = pages_.find(base);
        if (it == pages_.end()) {
            return peelf::make_error("page omitted from minidump/core");
        }
        const std::size_t off = static_cast<std::size_t>(address - base);
        if (off >= it->second.size()) {
            return peelf::make_error("offset out of range");
        }
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

TEST(MemoryHeatmapHilbertTest, ExactBijectionAndUnitManhattanLocalityOrders1Through8) {
    for (std::uint32_t order = 1u; order <= 8u; ++order) {
        const std::uint64_t dim = std::uint64_t{1} << order;
        const std::uint64_t total = dim * dim;

        std::vector<std::uint8_t> visited(static_cast<std::size_t>(total), 0u);
        peelf::HilbertCoord2D prev{};

        for (std::uint64_t idx = 0u; idx < total; ++idx) {
            const peelf::HilbertCoord2D xy = peelf::hilbert_index_to_xy(order, idx);
            ASSERT_LT(xy.x, dim) << "order=" << order << " idx=" << idx;
            ASSERT_LT(xy.y, dim) << "order=" << order << " idx=" << idx;

            const std::size_t flat =
                static_cast<std::size_t>(xy.y) * static_cast<std::size_t>(dim) + xy.x;
            EXPECT_EQ(visited[flat], 0u) << "Duplicate Hilbert coordinate at order=" << order;
            visited[flat] = 1u;

            const std::uint64_t roundtrip = peelf::hilbert_xy_to_index(order, xy.x, xy.y);
            ASSERT_EQ(roundtrip, idx) << "order=" << order << " idx=" << idx;

            if (idx > 0u) {
                EXPECT_EQ(manhattan_distance(prev, xy), 1u)
                    << "Consecutive Hilbert indices must be edge-adjacent (order=" << order
                    << ", idx=" << idx << ")";
            }
            prev = xy;
        }
    }
}

TEST(MemoryHeatmapHilbertTest, HighOrder16AndInvalidOrderClamping) {
    // Order 16 supports up to 65536 x 65536 = 4 Gi cells cleanly without overflow.
    constexpr std::array<std::uint64_t, 6> kOrder16Samples{{
        0ull,
        1ull,
        0x1234'5678ull,
        0x7FFF'FFFFull,
        0xDEAD'BEEFull,
        0xFFFF'FFFFull,
    }};
    for (const std::uint64_t idx : kOrder16Samples) {
        const auto xy = peelf::hilbert_index_to_xy(16u, idx);
        EXPECT_LT(xy.x, 65536u);
        EXPECT_LT(xy.y, 65536u);
        EXPECT_EQ(peelf::hilbert_xy_to_index(16u, xy.x, xy.y), idx);
        if (idx + 1ull <= 0xFFFF'FFFFull && idx < 1000ull) {
            const auto next_xy = peelf::hilbert_index_to_xy(16u, idx + 1ull);
            EXPECT_EQ(manhattan_distance(xy, next_xy), 1u);
        }
    }

    // Invalid order 0 rejects cleanly without UB.
    const auto zero_xy = peelf::hilbert_index_to_xy(0u, 99u);
    EXPECT_EQ(zero_xy.x, 0u);
    EXPECT_EQ(zero_xy.y, 0u);
    EXPECT_EQ(peelf::hilbert_xy_to_index(0u, 5u, 7u), 0u);

    // Order > 16 clamps to kMaxHilbertOrder (16).
    const auto clamped_xy = peelf::hilbert_index_to_xy(99u, 0xCAFE'BABEull);
    EXPECT_EQ(peelf::hilbert_xy_to_index(99u, clamped_xy.x, clamped_xy.y), 0xCAFE'BABEull);

    // LinearRows tile mapping round-trips cleanly.
    for (std::uint64_t i = 0u; i < 64u; ++i) {
        const auto tile = peelf::cell_index_to_grid_xy(
            peelf::MemoryHeatmapLayout::LinearRows, 4u, 16u, i);
        EXPECT_EQ(
            peelf::grid_xy_to_cell_index(
                peelf::MemoryHeatmapLayout::LinearRows, 4u, 16u, tile.x, tile.y),
            i);
    }
}

TEST(MemoryHeatmapCellTest, Compact16BytePackingRoundTripsAllFields) {
    static_assert(sizeof(peelf::MemoryHeatmapCell) == 16u);
    static_assert(alignof(peelf::MemoryHeatmapCell) == 16u);

    const auto cell = peelf::MemoryHeatmapCell::pack(
        0x0000'7FF6'1234'5000ull,
        4096u,
        peelf::MemoryCellCategory::Heap,
        peelf::MemoryCellPermBits::kRead | peelf::MemoryCellPermBits::kWrite,
        peelf::MemoryCellResidency::Resident,
        210u,
        177u,
        42u,
        true,
        true,
        true);

    EXPECT_EQ(cell.base_va, 0x0000'7FF6'1234'5000ull);
    EXPECT_EQ(cell.span_bytes(), 4096u);
    EXPECT_EQ(cell.category(), peelf::MemoryCellCategory::Heap);
    EXPECT_EQ(cell.residency(), peelf::MemoryCellResidency::Resident);
    EXPECT_EQ(cell.heat_u8(), 210u);
    EXPECT_EQ(cell.entropy_u8(), 177u);
    EXPECT_EQ(cell.mutation_count_u8(), 42u);
    EXPECT_TRUE(cell.has_perm_transition());
    EXPECT_TRUE(cell.is_newly_allocated());
    EXPECT_TRUE(cell.has_hot_focus());

    // Large bucket span (>= 16 MiB) encodes cleanly via 4 KiB page scale bit.
    peelf::MemoryHeatmapCell bucket = cell;
    bucket.set_span_bytes(64u * 1024u * 1024u);
    EXPECT_EQ(bucket.span_bytes(), 64u * 1024u * 1024u);

    const auto words = bucket.to_uvec4();
    EXPECT_EQ(words[0], 0x1234'5000u);
    EXPECT_EQ(words[1], 0x0000'7FF6u);
}

TEST(MemoryHeatmapStaticTest, AttributesPatchDirtyAndRwxViolationsOnStaticImage) {
    peelf_test::ScopedTempDir tmp("peelf_memory_heatmap");
    const std::vector<std::uint8_t> raw_elf = build_synthetic_elf64_with_rwx();
    auto img_res = peelf::open_binary_image(raw_elf);
    ASSERT_TRUE(img_res.has_value()) << img_res.error().message;

    auto paged_res = peelf::PagedBinaryImage::open(tmp.write_bytes("rwx_sample.elf", raw_elf));
    ASSERT_TRUE(paged_res.has_value()) << paged_res.error().message;

    // Stage a patch in `.data` (file offset 0x2010 -> VA 0x402010).
    const std::array<std::uint8_t, 4> patch_bytes{{0xDEu, 0xADu, 0xBEu, 0xEFu}};
    ASSERT_TRUE(paged_res->apply_patch(0x2010u, patch_bytes, "test patch").has_value());

    peelf::MemoryHeatmapTracker tracker{};
    peelf::MemoryHeatmapConfig cfg{};
    cfg.base_page_bytes = 4096u;

    const auto obs = tracker.sample_static_image(**img_res, &(*paged_res), cfg);
    EXPECT_EQ(obs.provenance, peelf::ProvenanceTag::DiskFile);
    EXPECT_EQ(obs.availability, peelf::CaptureAvailability::Complete);
    ASSERT_TRUE(obs.value.has_value());

    const auto& snap = *obs.value;
    ASSERT_FALSE(snap.cells.empty());
    EXPECT_GE(snap.stats.rwx_hazard_cell_count, 1u);
    EXPECT_GE(snap.stats.dirty_or_mutated_cell_count, 1u);

    // Entry point @ 0x401000 is ImageCode + hot_focus.
    const auto text_idx = snap.find_cell_index_for_va(0x401000ull);
    ASSERT_TRUE(text_idx.has_value());
    EXPECT_EQ(snap.cells[*text_idx].category(), peelf::MemoryCellCategory::ImageCode);
    EXPECT_TRUE(snap.cells[*text_idx].has_hot_focus());

    // Patched `.data` page @ 0x402000 is PatchDirty with full heat_u8 == 255.
    const auto data_idx = snap.find_cell_index_for_va(0x402010ull);
    ASSERT_TRUE(data_idx.has_value());
    EXPECT_EQ(snap.cells[*data_idx].category(), peelf::MemoryCellCategory::PatchDirty);
    EXPECT_EQ(snap.cells[*data_idx].heat_u8(), 255u);
    EXPECT_GE(snap.cells[*data_idx].mutation_count_u8(), 1u);

    // `.rwx` page @ 0x403000 carries kRwxHazard.
    const auto rwx_idx = snap.find_cell_index_for_va(0x403000ull);
    ASSERT_TRUE(rwx_idx.has_value());
    EXPECT_TRUE(snap.cells[*rwx_idx].has_rwx_hazard());
}

TEST(MemoryHeatmapLiveTrackerTest, DetectsAllocationWriteHeatDecayAndRwToRxTransition) {
    MockLiveProcessSession session{};

    const peelf::MemoryProtection rx{.readable = true, .writable = false, .executable = true};
    const peelf::MemoryProtection rw{.readable = true, .writable = true, .executable = false};

    session.modules_.push_back(peelf::ModuleInfo{
        .name = "mock_target",
        .base_address = 0x100000ull,
        .size = 0x2000ull,
        .entry_point = 0x100100ull,
        .format = peelf::Format::ELF,
        .is_main_module = true,
    });
    session.threads_.push_back(peelf::ThreadInfo{
        .tid = 101u,
        .name = "main",
        .instruction_pointer = 0x100100ull,
        .stack_pointer = 0x7FFF0800ull,
    });

    // Tick 1 regions: Code (2 pages), Heap (2 pages), JIT staging (1 page RW), Stack (1 page).
    session.regions_ = {
        peelf::MemoryRegion{
            .start_address = 0x100000ull,
            .end_address = 0x102000ull,
            .protection = rx,
            .kind = peelf::MemoryRegionKind::Image,
            .module_name = "mock_target",
        },
        peelf::MemoryRegion{
            .start_address = 0x200000ull,
            .end_address = 0x202000ull,
            .protection = rw,
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap]",
        },
        peelf::MemoryRegion{
            .start_address = 0x300000ull,
            .end_address = 0x301000ull,
            .protection = rw,
            .kind = peelf::MemoryRegionKind::Anonymous,
            .pathname = "jit_slab",
        },
        peelf::MemoryRegion{
            .start_address = 0x7FFF0000ull,
            .end_address = 0x7FFF1000ull,
            .protection = rw,
            .kind = peelf::MemoryRegionKind::Anonymous, // Attributed to ThreadStack via SP containment!
        },
    };

    session.set_page_fill(0x100000ull, 0x90u);
    session.set_page_fill(0x101000ull, 0xC3u);
    session.set_page_fill(0x200000ull, 0x11u);
    session.set_page_fill(0x201000ull, 0x22u);
    session.set_page_fill(0x300000ull, 0x33u);
    session.set_page_fill(0x7FFF0000ull, 0x44u);

    peelf::MemoryHeatmapTracker tracker{};
    peelf::MemoryHeatmapConfig cfg{};
    cfg.base_page_bytes = 4096u;
    cfg.heat_decay_factor = 0.75f;
    cfg.query_os_pagemap = false;

    // --- Tick 1: Baseline capture ---
    const auto tick1 = tracker.sample_process(session, cfg);
    ASSERT_NE(tick1.availability, peelf::CaptureAvailability::Unavailable);
    ASSERT_TRUE(tick1.value.has_value());
    const auto stack_idx_t1 = tick1.value->find_cell_index_for_va(0x7FFF0800ull);
    ASSERT_TRUE(stack_idx_t1.has_value());
    EXPECT_EQ(tick1.value->cells[*stack_idx_t1].category(),
              peelf::MemoryCellCategory::ThreadStack);

    const auto heap_idx_t1 = tick1.value->find_cell_index_for_va(0x201000ull);
    ASSERT_TRUE(heap_idx_t1.has_value());
    EXPECT_EQ(tick1.value->cells[*heap_idx_t1].category(), peelf::MemoryCellCategory::Heap);
    EXPECT_EQ(tick1.value->cells[*heap_idx_t1].heat_u8(), 0u);

    // --- Tick 2: Mutate heap page 0x201000, flip JIT 0x300000 RW -> RX, allocate new arena 0x400000 ---
    session.set_page_high_entropy(0x201000ull);
    session.regions_[2].protection = rx; // RW -> RX JIT flip!
    session.regions_.insert(
        session.regions_.begin() + 3,
        peelf::MemoryRegion{
            .start_address = 0x400000ull,
            .end_address = 0x401000ull,
            .protection = rw,
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap_arena_2]",
        });
    session.set_page_fill(0x400000ull, 0xAAu);

    const auto tick2 = tracker.sample_process(session, cfg);
    ASSERT_TRUE(tick2.value.has_value());
    EXPECT_EQ(tick2.value->stats.newly_allocated_region_count, 1u);
    EXPECT_GE(tick2.value->stats.perm_transition_cell_count, 1u);

    const auto heap_idx_t2 = tick2.value->find_cell_index_for_va(0x201000ull);
    ASSERT_TRUE(heap_idx_t2.has_value());
    EXPECT_EQ(tick2.value->cells[*heap_idx_t2].heat_u8(), 255u);
    EXPECT_EQ(tick2.value->cells[*heap_idx_t2].mutation_count_u8(), 1u);
    EXPECT_GT(tick2.value->cells[*heap_idx_t2].entropy_u8(), 200u);

    const auto jit_idx_t2 = tick2.value->find_cell_index_for_va(0x300000ull);
    ASSERT_TRUE(jit_idx_t2.has_value());
    EXPECT_TRUE(tick2.value->cells[*jit_idx_t2].has_perm_transition());
    EXPECT_EQ(tick2.value->cells[*jit_idx_t2].heat_u8(), 255u);

    const auto new_idx_t2 = tick2.value->find_cell_index_for_va(0x400000ull);
    ASSERT_TRUE(new_idx_t2.has_value());
    EXPECT_TRUE(tick2.value->cells[*new_idx_t2].is_newly_allocated());
    EXPECT_EQ(tick2.value->cells[*new_idx_t2].heat_u8(), 255u);

    // --- Tick 3 & Tick 4: No new mutations -> exponential afterglow decay ---
    const auto tick3 = tracker.sample_process(session, cfg);
    ASSERT_TRUE(tick3.value.has_value());
    const auto heap_idx_t3 = tick3.value->find_cell_index_for_va(0x201000ull);
    ASSERT_TRUE(heap_idx_t3.has_value());
    const std::uint8_t heat_t3 = tick3.value->cells[*heap_idx_t3].heat_u8();
    EXPECT_GT(heat_t3, 0u);
    EXPECT_LT(heat_t3, 255u);

    const auto tick4 = tracker.sample_process(session, cfg);
    ASSERT_TRUE(tick4.value.has_value());
    const auto heap_idx_t4 = tick4.value->find_cell_index_for_va(0x201000ull);
    ASSERT_TRUE(heap_idx_t4.has_value());
    const std::uint8_t heat_t4 = tick4.value->cells[*heap_idx_t4].heat_u8();
    EXPECT_GT(heat_t4, 0u);
    EXPECT_LT(heat_t4, heat_t3);
}

TEST(MemoryHeatmapLiveTrackerTest, EnforcesPerTickReadBudgetWithRoundRobinProgress) {
    MockLiveProcessSession session{};
    const peelf::MemoryProtection rw{.readable = true, .writable = true, .executable = false};

    // 12 writable heap pages = 48 KiB total.
    constexpr std::uint64_t kHeapBase = 0x500000ull;
    constexpr std::size_t kPageCount = 12u;
    session.regions_.push_back(peelf::MemoryRegion{
        .start_address = kHeapBase,
        .end_address = kHeapBase + kPageCount * 4096ull,
        .protection = rw,
        .kind = peelf::MemoryRegionKind::Heap,
        .pathname = "[heap]",
    });
    for (std::size_t i = 0u; i < kPageCount; ++i) {
        session.set_page_fill(kHeapBase + i * 4096ull, static_cast<std::uint8_t>(i + 1u));
    }

    peelf::MemoryHeatmapTracker tracker{};
    peelf::MemoryHeatmapConfig cfg{};
    cfg.base_page_bytes = 4096u;
    cfg.read_budget_bytes_per_tick = 3u * 4096u; // Strictly cap at 12 KiB (3 pages) per tick!
    cfg.query_os_pagemap = false;

    // Prime all 12 baseline checksums across 4 bounded ticks (3 pages/tick * 4 ticks = 12 pages).
    for (int t = 0; t < 4; ++t) {
        session.reset_tick_read_counter();
        const auto obs = tracker.sample_process(session, cfg);
        ASSERT_TRUE(obs.value.has_value());
        EXPECT_LE(obs.value->stats.bytes_sampled_this_tick, cfg.read_budget_bytes_per_tick);
        EXPECT_LE(session.bytes_read_last_tick(), cfg.read_budget_bytes_per_tick);
    }

    // Mutate page #9 and verify round-robin sampling discovers it within 4 budget-bounded ticks.
    const std::uint64_t target_va = kHeapBase + 9ull * 4096ull;
    session.set_page_fill(target_va, 0xFEu);

    bool detected_spike = false;
    for (int t = 0; t < 4; ++t) {
        session.reset_tick_read_counter();
        const auto obs = tracker.sample_process(session, cfg);
        ASSERT_TRUE(obs.value.has_value());
        EXPECT_LE(obs.value->stats.bytes_sampled_this_tick, cfg.read_budget_bytes_per_tick);
        EXPECT_LE(session.bytes_read_last_tick(), cfg.read_budget_bytes_per_tick);
        const auto idx = obs.value->find_cell_index_for_va(target_va);
        ASSERT_TRUE(idx.has_value());
        if (obs.value->cells[*idx].heat_u8() == 255u) {
            detected_spike = true;
            break;
        }
    }
    EXPECT_TRUE(detected_spike);
}

TEST(MemoryHeatmapCrashDumpTest, HighlightsCrashingThreadPagesAndUncapturedModuleHoles) {
    MockCrashDumpSession dump{};
    dump.modules_.push_back(peelf::ModuleInfo{
        .name = "crashed_app",
        .base_address = 0x500000ull,
        .size = 0x4000ull,
        .entry_point = 0x500000ull,
        .format = peelf::Format::ELF,
        .is_main_module = true,
    });
    dump.modules_.push_back(peelf::ModuleInfo{
        .name = "unbacked_plugin.so",
        .base_address = 0x900000ull,
        .size = 0x2000ull,
        .format = peelf::Format::ELF,
    });
    dump.threads_.push_back(peelf::ThreadInfo{
        .tid = 77u,
        .name = "crasher",
        .instruction_pointer = 0x500010ull,
        .stack_pointer = 0x7FFE0100ull,
    });
    dump.regions_ = {
        peelf::MemoryRegion{
            .start_address = 0x500000ull,
            .end_address = 0x501000ull,
            .protection = {.readable = true, .executable = true},
            .kind = peelf::MemoryRegionKind::Image,
            .module_name = "crashed_app",
        },
        peelf::MemoryRegion{
            .start_address = 0x7FFE0000ull,
            .end_address = 0x7FFE1000ull,
            .protection = {.readable = true, .writable = true},
            .kind = peelf::MemoryRegionKind::Stack,
        },
    };
    dump.pages_[0x500000ull] = std::vector<std::uint8_t>(4096u, 0xCCu);
    dump.pages_[0x7FFE0000ull] = std::vector<std::uint8_t>(4096u, 0x55u);

    peelf::MemoryHeatmapTracker tracker{};
    const auto obs = tracker.sample_crash_dump(dump);
    EXPECT_EQ(obs.provenance, peelf::ProvenanceTag::CrashDump);
    EXPECT_EQ(obs.availability, peelf::CaptureAvailability::Complete);
    ASSERT_TRUE(obs.value.has_value());

    const auto ip_idx = obs.value->find_cell_index_for_va(0x500010ull);
    ASSERT_TRUE(ip_idx.has_value());
    EXPECT_TRUE(obs.value->cells[*ip_idx].has_hot_focus());
    EXPECT_EQ(obs.value->cells[*ip_idx].residency(), peelf::MemoryCellResidency::Resident);

    const auto sp_idx = obs.value->find_cell_index_for_va(0x7FFE0100ull);
    ASSERT_TRUE(sp_idx.has_value());
    EXPECT_EQ(obs.value->cells[*sp_idx].category(), peelf::MemoryCellCategory::ThreadStack);
    EXPECT_TRUE(obs.value->cells[*sp_idx].has_hot_focus());

    // Omitted module hole at 0x900000 is surfaced as ZeroOrUncommitted.
    const auto hole_idx = obs.value->find_cell_index_for_va(0x900000ull);
    ASSERT_TRUE(hole_idx.has_value());
    EXPECT_EQ(obs.value->cells[*hole_idx].residency(),
              peelf::MemoryCellResidency::ZeroOrUncommitted);
}

TEST(MemoryHeatmapRasterAndShaderTest, CpuRasterizerIsDeterministicAndSpirvPassesValidation) {
    // 1. Validate embedded Vulkan compute shader SPIR-V words & push-constant layout.
    EXPECT_TRUE(viewer::validate_spirv_words(viewer::shaders::kMemoryHeatmapCompSpirv));
    const auto spirv_report =
        viewer::inspect_spirv_words(viewer::shaders::kMemoryHeatmapCompSpirv);
    EXPECT_TRUE(spirv_report.valid) << "SPIR-V error=" << static_cast<int>(spirv_report.error);
    EXPECT_GT(spirv_report.instruction_count, 50u);
    EXPECT_EQ(sizeof(viewer::shaders::MemoryHeatmapPushConstants), 96u);

    // 2. Build a multi-category snapshot and verify deterministic RGBA8 output across all modes.
    peelf::MemoryHeatmapSnapshot snap{};
    snap.layout = peelf::MemoryHeatmapLayout::HilbertCurve;
    snap.hilbert_order = 2u;
    snap.grid_width = 4u;
    snap.grid_height = 4u;
    snap.cells = {
        peelf::MemoryHeatmapCell::pack(
            0x1000ull, 4096u, peelf::MemoryCellCategory::ImageCode,
            peelf::MemoryCellPermBits::kRead | peelf::MemoryCellPermBits::kExecute,
            peelf::MemoryCellResidency::Resident, 0u, 180u, 0u, false, false, true),
        peelf::MemoryHeatmapCell::pack(
            0x2000ull, 4096u, peelf::MemoryCellCategory::Heap,
            peelf::MemoryCellPermBits::kRead | peelf::MemoryCellPermBits::kWrite,
            peelf::MemoryCellResidency::Resident, 255u, 220u, 5u),
        peelf::MemoryHeatmapCell::pack(
            0x3000ull, 4096u, peelf::MemoryCellCategory::PatchDirty,
            peelf::MemoryCellPermBits::kRead | peelf::MemoryCellPermBits::kWrite,
            peelf::MemoryCellResidency::Resident, 255u, 140u, 2u),
        peelf::MemoryHeatmapCell::pack(
            0x4000ull, 4096u, peelf::MemoryCellCategory::AnonRw,
            peelf::MemoryCellPermBits::kRead | peelf::MemoryCellPermBits::kWrite |
                peelf::MemoryCellPermBits::kExecute | peelf::MemoryCellPermBits::kRwxHazard,
            peelf::MemoryCellResidency::Resident, 128u, 240u, 1u, true),
    };

    const peelf::MemoryHeatmapViewport vp{
        .center_x = 2.0,
        .center_y = 2.0,
        .scale_x = 16.0,
        .scale_y = 16.0,
        .width_px = 64u,
        .height_px = 64u,
        .hovered_cell_index = 1u,
        .selected_cell_index = 2u,
    };

    for (const auto mode : {peelf::MemoryHeatmapColorMode::AllocatorAndWriteHeat,
                            peelf::MemoryHeatmapColorMode::CategoryAndResidency,
                            peelf::MemoryHeatmapColorMode::PermissionsAndRwx,
                            peelf::MemoryHeatmapColorMode::PageEntropy}) {
        const auto rgba_a = peelf::rasterize_memory_heatmap_rgba8(vp, snap, mode);
        const auto rgba_b = peelf::rasterize_memory_heatmap_rgba8(vp, snap, mode);
        ASSERT_EQ(rgba_a.size(), 64u * 64u * 4u);
        EXPECT_EQ(rgba_a, rgba_b);

        // Verify non-background foreground pixels exist and alpha channel is opaque 255.
        std::size_t bright_pixels = 0u;
        for (std::size_t off = 0u; off < rgba_a.size(); off += 4u) {
            EXPECT_EQ(rgba_a[off + 3u], 255u);
            if (rgba_a[off + 0u] > 40u || rgba_a[off + 1u] > 40u || rgba_a[off + 2u] > 40u) {
                ++bright_pixels;
            }
        }
        EXPECT_GT(bright_pixels, 256u);
    }
}

} // namespace
