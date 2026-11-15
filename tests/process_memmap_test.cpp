#include "peelf/binary_image.hpp"
#include "peelf/patching.hpp"
#include "peelf/process.hpp"

#include "graph/call_graph.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

namespace {

[[nodiscard]] std::filesystem::path fixture_path(std::string_view name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

[[nodiscard]] std::vector<std::uint8_t> read_binary_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file.good()) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

class FakeProcessSession final : public peelf::IProcessSession {
public:
    struct BackingSpan {
        peelf::MemoryRegion region;
        std::vector<std::uint8_t> data;
    };

    explicit FakeProcessSession(peelf::ProcessInfo proc_info)
        : info_(std::move(proc_info)) {}

    void add_mapped_span(peelf::MemoryRegion region, std::vector<std::uint8_t> bytes) {
        spans_.push_back(BackingSpan{
            .region = std::move(region),
            .data = std::move(bytes),
        });
        std::ranges::sort(spans_, [](const BackingSpan& a, const BackingSpan& b) {
            return a.region.start_address < b.region.start_address;
        });
    }

    void add_unbacked_region(peelf::MemoryRegion region) {
        spans_.push_back(BackingSpan{
            .region = std::move(region),
            .data = {},
        });
        std::ranges::sort(spans_, [](const BackingSpan& a, const BackingSpan& b) {
            return a.region.start_address < b.region.start_address;
        });
    }

    void set_modules(std::vector<peelf::ModuleInfo> modules) {
        explicit_modules_ = std::move(modules);
    }

    [[nodiscard]] std::vector<std::uint8_t> raw_ram_slice(std::uint64_t va, std::size_t len) const {
        for (const BackingSpan& span : spans_) {
            if (va >= span.region.start_address &&
                va + len <= span.region.end_address &&
                (va - span.region.start_address) + len <= span.data.size()) {
                const auto rel = static_cast<std::ptrdiff_t>(va - span.region.start_address);
                return {span.data.begin() + rel, span.data.begin() + rel + static_cast<std::ptrdiff_t>(len)};
            }
        }
        return {};
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return alive_; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        if (!alive_) {
            return peelf::make_error("target process exited");
        }
        std::vector<peelf::MemoryRegion> out;
        out.reserve(spans_.size());
        for (const BackingSpan& s : spans_) {
            out.push_back(s.region);
        }
        (void)peelf::derive_modules_from_regions(out, info_.executable_path.string(), this);
        return out;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        if (!alive_) {
            return peelf::make_error("target process exited");
        }
        if (explicit_modules_) {
            return *explicit_modules_;
        }
        auto regs = memory_regions();
        if (!regs) {
            return std::unexpected(regs.error());
        }
        return peelf::derive_modules_from_regions(*regs, info_.executable_path.string(), this);
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t address,
                                                         std::span<std::uint8_t> buffer) override {
        if (!alive_) {
            return peelf::make_error("target process exited");
        }
        if (buffer.empty()) {
            return std::size_t{0};
        }
        for (const BackingSpan& span : spans_) {
            if (!span.region.contains(address)) {
                continue;
            }
            if (!span.region.protection.readable || span.region.protection.guarded || span.data.empty()) {
                return peelf::make_error("region is unreadable or guarded");
            }
            const auto rel = static_cast<std::size_t>(address - span.region.start_address);
            if (rel >= span.data.size()) {
                return peelf::make_error("read past backing data");
            }
            const std::size_t avail = std::min<std::size_t>(buffer.size(), span.data.size() - rel);
            std::memcpy(buffer.data(), span.data.data() + rel, avail);
            return avail;
        }
        return peelf::make_error("unmapped virtual address");
    }

    [[nodiscard]] peelf::Result<std::size_t> write_memory(
        std::uint64_t /*address*/,
        std::span<const std::uint8_t> /*data*/,
        peelf::MemoryWriteOptions /*options*/) override {
        return peelf::make_error("live process session is strictly read-only");
    }

    void set_alive(bool alive) noexcept { alive_ = alive; }

private:
    peelf::ProcessInfo info_;
    bool alive_{true};
    std::vector<BackingSpan> spans_;
    std::optional<std::vector<peelf::ModuleInfo>> explicit_modules_;
};

class FakeProcessBackend final : public peelf::IProcessBackend {
public:
    using SessionFactory = std::function<std::unique_ptr<FakeProcessSession>()>;

    void register_process(peelf::ProcessInfo info, SessionFactory factory) {
        const peelf::ProcessId pid = info.pid;
        processes_.push_back(std::move(info));
        factories_[pid] = std::move(factory);
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ProcessInfo>> list_processes() override {
        return processes_;
    }

    [[nodiscard]] peelf::Result<std::unique_ptr<peelf::IProcessSession>> open_process(
        peelf::ProcessId pid) override {
        const auto it = factories_.find(pid);
        if (it == factories_.end()) {
            return peelf::make_error("PID not found in fake process backend");
        }
        return it->second();
    }

private:
    std::vector<peelf::ProcessInfo> processes_;
    std::map<peelf::ProcessId, SessionFactory> factories_;
};

// Map an ELF image into a FakeProcessSession by PT_LOAD segments at `live_base`.
void map_elf_segments_into_fake_process(FakeProcessSession& session,
                                        const peelf::IBinaryImage& static_elf,
                                        std::span<const std::uint8_t> file_bytes,
                                        std::uint64_t live_base,
                                        const std::string& pathname) {
    const std::uint64_t static_base = static_elf.image_base();
    for (const peelf::Segment& seg : static_elf.segments()) {
        if (seg.type != 1 || (seg.virtual_size == 0 && seg.file_size == 0)) {
            continue;
        }
        const std::uint64_t rva = seg.virtual_address - static_base;
        const std::uint64_t page_rva = rva & ~0xFFFull;
        const std::uint64_t delta = rva - page_rva;
        const std::uint64_t raw_span = std::max(seg.virtual_size, seg.file_size) + delta;
        const std::uint64_t aligned_size = (raw_span + 0xFFFull) & ~0xFFFull;

        std::vector<std::uint8_t> mem(static_cast<std::size_t>(aligned_size), 0);
        const std::uint64_t file_page_off = seg.file_offset >= delta ? (seg.file_offset - delta) : 0;
        if (file_page_off < file_bytes.size()) {
            const std::size_t to_copy = static_cast<std::size_t>(
                std::min<std::uint64_t>(aligned_size, file_bytes.size() - file_page_off));
            std::memcpy(mem.data(), file_bytes.data() + file_page_off, to_copy);
        }

        peelf::MemoryRegion reg;
        reg.start_address = live_base + page_rva;
        reg.end_address = reg.start_address + aligned_size;
        reg.file_offset = file_page_off;
        reg.protection.readable = seg.readable;
        reg.protection.writable = seg.writable;
        reg.protection.executable = seg.executable;
        reg.protection.shared = false;
        reg.kind = peelf::MemoryRegionKind::Image;
        reg.pathname = pathname;
        session.add_mapped_span(std::move(reg), std::move(mem));
    }
}

// Map a PE image into a FakeProcessSession by VirtualAddress sections (true Windows RAM layout)
// at `live_base` (which may differ from the PE's preferred ImageBase, simulating ASLR).
void map_pe_image_into_fake_process(FakeProcessSession& session,
                                    const peelf::IBinaryImage& static_pe,
                                    std::span<const std::uint8_t> file_bytes,
                                    std::uint64_t live_base,
                                    const std::string& pathname) {
    const std::uint64_t static_base = static_pe.image_base();

    // Map PE headers page [0, 0x1000).
    {
        std::vector<std::uint8_t> hdr_page(0x1000, 0);
        const std::size_t hdr_copy = std::min<std::size_t>(0x1000, file_bytes.size());
        std::memcpy(hdr_page.data(), file_bytes.data(), hdr_copy);

        peelf::MemoryRegion hdr_reg;
        hdr_reg.start_address = live_base;
        hdr_reg.end_address = live_base + 0x1000;
        hdr_reg.protection.readable = true;
        hdr_reg.kind = peelf::MemoryRegionKind::Image;
        hdr_reg.pathname = pathname;
        session.add_mapped_span(std::move(hdr_reg), std::move(hdr_page));
    }

    for (const peelf::Section& sec : static_pe.sections()) {
        if (sec.virtual_address < static_base) {
            continue;
        }
        const std::uint64_t rva = sec.virtual_address - static_base;
        const std::uint64_t span_sz =
            ((std::max(sec.virtual_size, sec.file_size) + 0xFFFull) & ~0xFFFull);
        if (span_sz == 0) {
            continue;
        }
        std::vector<std::uint8_t> sec_mem(static_cast<std::size_t>(span_sz), 0);
        if (sec.file_offset < file_bytes.size() && sec.file_size > 0) {
            const std::size_t copy_len = static_cast<std::size_t>(
                std::min<std::uint64_t>({span_sz, sec.file_size, file_bytes.size() - sec.file_offset}));
            std::memcpy(sec_mem.data(), file_bytes.data() + sec.file_offset, copy_len);
        }

        peelf::MemoryRegion sec_reg;
        sec_reg.start_address = live_base + rva;
        sec_reg.end_address = sec_reg.start_address + span_sz;
        sec_reg.protection.readable = sec.readable;
        sec_reg.protection.writable = sec.writable;
        sec_reg.protection.executable = sec.executable;
        sec_reg.kind = peelf::MemoryRegionKind::Image;
        sec_reg.pathname = pathname;
        session.add_mapped_span(std::move(sec_reg), std::move(sec_mem));
    }
}

}  // namespace

TEST(ProcessMapsParser, ParsesLinuxProcMapsAndDerivesModules) {
    constexpr std::string_view kSampleMaps =
        "555555554000-555555555000 r--p 00000000 08:01 131073  /usr/bin/target_app\n"
        "555555555000-555555559000 r-xp 00001000 08:01 131073  /usr/bin/target_app\n"
        "555555559000-55555555a000 r--p 00005000 08:01 131073  /usr/bin/target_app\n"
        "55555555b000-55555555c000 rw-p 00006000 08:01 131073  /usr/bin/target_app\n"
        "55555555c000-55555557d000 rw-p 00000000 00:00 0       [heap]\n"
        "7ffff7c00000-7ffff7c28000 r--p 00000000 08:01 262200  /usr/lib/x86_64-linux-gnu/libc.so.6\n"
        "7ffff7c28000-7ffff7dbd000 r-xp 00028000 08:01 262200  /usr/lib/x86_64-linux-gnu/libc.so.6\n"
        "7ffff7dbd000-7ffff7dbd000 ---p 00000000 00:00 0 \n"
        "7ffff7dd0000-7ffff7dd1000 ---p 00000000 00:00 0 \n"
        "7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0       [vdso]\n"
        "7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0       [stack]\n";

    auto parsed = peelf::parse_proc_maps(kSampleMaps, "/usr/bin/target_app");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    std::vector<peelf::MemoryRegion> regions = std::move(*parsed);
    ASSERT_GE(regions.size(), 9u);

    EXPECT_EQ(regions[0].start_address, 0x555555554000ull);
    EXPECT_EQ(regions[0].protection.to_short_string(), "r--p");
    EXPECT_EQ(regions[1].protection.to_short_string(), "r-xp");
    EXPECT_EQ(regions[4].kind, peelf::MemoryRegionKind::Heap);
    EXPECT_EQ(regions.back().kind, peelf::MemoryRegionKind::Stack);

    const std::vector<peelf::ModuleInfo> modules =
        peelf::derive_modules_from_regions(regions, "/usr/bin/target_app");
    ASSERT_EQ(modules.size(), 3u);

    EXPECT_TRUE(modules[0].is_main_module);
    EXPECT_EQ(modules[0].name, "target_app");
    EXPECT_EQ(modules[0].base_address, 0x555555554000ull);
    EXPECT_EQ(modules[0].size, 0x55555555c000ull - 0x555555554000ull);

    EXPECT_FALSE(modules[1].is_main_module);
    EXPECT_EQ(modules[1].name, "libc.so.6");
    EXPECT_EQ(modules[1].base_address, 0x7ffff7c00000ull);

    EXPECT_FALSE(modules[2].is_main_module);
    EXPECT_EQ(modules[2].name, "[vdso]");
    EXPECT_EQ(modules[2].base_address, 0x7ffff7ffd000ull);
}

TEST(PagedBinaryImageSparse, MultiSpanDisjointTransactionAvoidsBoundingBoxAndUndoesCleanly) {
    // 64 KiB file where two writes in one transaction sit 60 KiB apart.
    std::vector<std::uint8_t> bytes(65536, 0x11);
    const std::filesystem::path tmp =
        std::filesystem::temp_directory_path() / "peelf_sparse_tx_test.bin";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    { // Release the retained input stream before removing the file on Windows.
    auto img = peelf::PagedBinaryImage::open(tmp, 4096);
    ASSERT_TRUE(img.has_value()) << img.error().message;

    auto tx = img->begin_transaction("disjoint writes");
    ASSERT_TRUE(tx.write(16, std::vector<std::uint8_t>{0xAA, 0xBB}).has_value());
    ASSERT_TRUE(tx.write(61440, std::vector<std::uint8_t>{0xCC, 0xDD}).has_value());
    ASSERT_TRUE(tx.commit().has_value());

    EXPECT_EQ(img->changed_intervals().size(), 2u);
    EXPECT_EQ(*img->read_effective(16, 2), (std::vector<std::uint8_t>{0xAA, 0xBB}));
    EXPECT_EQ(*img->read_effective(61440, 2), (std::vector<std::uint8_t>{0xCC, 0xDD}));

    ASSERT_TRUE(img->undo().has_value());
    EXPECT_FALSE(img->dirty());
    EXPECT_EQ(*img->read_effective(16, 2), (std::vector<std::uint8_t>{0x11, 0x11}));
    EXPECT_EQ(*img->read_effective(61440, 2), (std::vector<std::uint8_t>{0x11, 0x11}));

    ASSERT_TRUE(img->redo().has_value());
    EXPECT_EQ(img->changed_intervals().size(), 2u);
    }
    std::filesystem::remove(tmp);
}

TEST(LiveModuleRebasing, RebasesElfWithSymtabAndSupportsPureRamFallback) {
    const std::filesystem::path elf_path = fixture_path("hello.elf");
    const std::vector<std::uint8_t> elf_bytes = read_binary_file(elf_path);
    auto static_img = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(static_img.has_value()) << static_img.error().message;

    constexpr std::uint64_t kLiveBase = 0x0000555555554000ull;
    const std::uint64_t slide = kLiveBase - (*static_img)->image_base();

    peelf::ProcessInfo pinfo;
    pinfo.pid = 4242;
    pinfo.name = "hello.elf";
    pinfo.executable_path = elf_path;
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.is_64bit = true;
    pinfo.access = peelf::ProcessAccessStatus::Accessible;

    FakeProcessSession session(pinfo);
    map_elf_segments_into_fake_process(session, **static_img, elf_bytes, kLiveBase, elf_path.string());

    auto regs = session.memory_regions();
    ASSERT_TRUE(regs.has_value());
    auto mods = session.modules();
    ASSERT_TRUE(mods.has_value());
    ASSERT_EQ(mods->size(), 1u);

    // 1. Hybrid live module load (live RAM + on-disk .symtab/.strtab rebased by ASLR slide).
    auto live_img = peelf::load_live_module_image(session, (*mods)[0], *regs);
    ASSERT_TRUE(live_img.has_value()) << live_img.error().message;
    EXPECT_EQ((*live_img)->image_base(), kLiveBase);
    EXPECT_EQ((*live_img)->entry_point(), (*static_img)->entry_point() + slide);

    const viewer::SymbolIndex live_syms = viewer::SymbolIndex::build(**live_img);
    const viewer::SymbolRecord* main_sym = live_syms.find_by_name("main");
    ASSERT_NE(main_sym, nullptr);
    ASSERT_TRUE(main_sym->virtual_address.has_value());
    EXPECT_EQ(*main_sym->virtual_address, 0x1161ull + slide);
    EXPECT_EQ(live_syms.find_containing_address(0x1161ull + slide), main_sym);

    // 2. Pure RAM-only fallback when the on-disk file is missing (e.g., memfd / deleted binary).
    peelf::ModuleInfo ram_only_mod = (*mods)[0];
    ram_only_mod.path = "/nonexistent_deleted_memfd/hello.elf";
    auto ram_img = peelf::load_live_module_image(session, ram_only_mod, *regs);
    ASSERT_TRUE(ram_img.has_value()) << ram_img.error().message;
    EXPECT_EQ((*ram_img)->format(), peelf::Format::ELF);
    EXPECT_EQ((*ram_img)->image_base(), kLiveBase);
    EXPECT_EQ((*ram_img)->entry_point(), (*static_img)->entry_point() + slide);
    EXPECT_FALSE((*ram_img)->segments().empty());
    EXPECT_FALSE((*ram_img)->sections().empty());
}

TEST(LiveModuleRebasing, RebasesMappedPeExportsImportsAndPdbDebugSymbols) {
    const std::filesystem::path pe_path = fixture_path("known-win-x64.exe");
    const std::vector<std::uint8_t> pe_bytes = read_binary_file(pe_path);
    auto static_pe = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(static_pe.has_value()) << static_pe.error().message;

    const std::uint64_t static_base = (*static_pe)->image_base();
    const std::uint64_t entry_rva = (*static_pe)->entry_point() - static_base;
    constexpr std::uint64_t kLivePeBase = 0x00007FF7A1B20000ull;

    peelf::ProcessInfo pinfo;
    pinfo.pid = 7788;
    pinfo.name = "known-win-x64.exe";
    pinfo.executable_path = pe_path;
    pinfo.architecture = peelf::Architecture::X86_64;
    pinfo.is_64bit = true;
    pinfo.access = peelf::ProcessAccessStatus::Accessible;

    FakeProcessSession session(pinfo);
    map_pe_image_into_fake_process(session, **static_pe, pe_bytes, kLivePeBase, pe_path.string());

    auto regs = session.memory_regions();
    ASSERT_TRUE(regs.has_value());
    auto mods = session.modules();
    ASSERT_TRUE(mods.has_value());
    ASSERT_EQ(mods->size(), 1u);

    // Verify pure RAM-only PE parsing from VirtualAddress-mapped memory!
    peelf::ModuleInfo ram_pe_mod = (*mods)[0];
    ram_pe_mod.path.clear();
    auto ram_pe_img = peelf::load_live_module_image(session, ram_pe_mod, *regs);
    ASSERT_TRUE(ram_pe_img.has_value()) << ram_pe_img.error().message;
    EXPECT_EQ((*ram_pe_img)->format(), peelf::Format::PE);
    EXPECT_EQ((*ram_pe_img)->image_base(), kLivePeBase);
    EXPECT_EQ((*ram_pe_img)->entry_point(), kLivePeBase + entry_rva);

    viewer::SymbolIndex idx = viewer::SymbolIndex::build(**ram_pe_img);
    const viewer::SymbolRecord* exp = idx.find_by_name("known_export");
    ASSERT_NE(exp, nullptr);
    ASSERT_TRUE(exp->virtual_address.has_value());
    EXPECT_EQ(*exp->virtual_address, kLivePeBase + entry_rva);

    const viewer::SymbolRecord* imp = idx.find_by_name("KERNEL32.dll!ExitProcess");
    ASSERT_NE(imp, nullptr);
    EXPECT_TRUE(imp->external);

    // Verify PDB DebugSymbol rebasing to live ASLR base.
    std::vector<viewer::DebugSymbol> pdb_syms{
        viewer::DebugSymbol{
            .name = "WinMain_LivePdb",
            .relative_virtual_address = static_cast<std::uint32_t>(entry_rva),
            .virtual_address = static_base + entry_rva,
            .size = 0x40,
            .function = true,
        },
    };
    const auto rebased_pdb = viewer::rebase_debug_symbols(pdb_syms, kLivePeBase);
    idx.add_debug_symbols(**ram_pe_img, rebased_pdb);

    const viewer::SymbolRecord* pdb_rec = idx.find_containing_address(kLivePeBase + entry_rva + 4);
    ASSERT_NE(pdb_rec, nullptr);
    EXPECT_EQ(pdb_rec->name, "WinMain_LivePdb");
    EXPECT_EQ(pdb_rec->source, viewer::SymbolSource::DebugSymbol);
}

TEST(LiveMemoryTolerantRead, HandlesGuardPagesAndUnmappedHolesGracefully) {
    peelf::ProcessInfo pinfo{.pid = 9001, .name = "guard_test"};
    FakeProcessSession session(pinfo);

    peelf::MemoryRegion page0{
        .start_address = 0x100000,
        .end_address = 0x101000,
        .protection = {.readable = true, .writable = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    };
    peelf::MemoryRegion guard_page{
        .start_address = 0x101000,
        .end_address = 0x102000,
        .protection = {.guarded = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    };
    peelf::MemoryRegion page2{
        .start_address = 0x102000,
        .end_address = 0x103000,
        .protection = {.readable = true},
        .kind = peelf::MemoryRegionKind::Anonymous,
    };

    session.add_mapped_span(page0, std::vector<std::uint8_t>(0x1000, 0x41));
    session.add_unbacked_region(guard_page);
    session.add_mapped_span(page2, std::vector<std::uint8_t>(0x1000, 0x42));

    auto regs = session.memory_regions();
    ASSERT_TRUE(regs.has_value());

    // Read 8 bytes at end of page0 + entire 0x1000 guard page + 8 bytes at start of page2.
    const peelf::MemorySample sample =
        peelf::read_memory_tolerant(session, *regs, 0x100FF8, 8 + 0x1000 + 8);
    ASSERT_EQ(sample.bytes.size(), 0x1010u);
    ASSERT_EQ(sample.valid.size(), 0x1010u);
    EXPECT_EQ(sample.readable_count, 16u);

    for (std::size_t i = 0; i < 8; ++i) {
        EXPECT_EQ(sample.valid[i], 1u);
        EXPECT_EQ(sample.bytes[i], 0x41u);
    }
    for (std::size_t i = 8; i < 8 + 0x1000; ++i) {
        EXPECT_EQ(sample.valid[i], 0u);
        EXPECT_EQ(sample.bytes[i], 0x00u);
    }
    for (std::size_t i = 8 + 0x1000; i < 0x1010; ++i) {
        EXPECT_EQ(sample.valid[i], 1u);
        EXPECT_EQ(sample.bytes[i], 0x42u);
    }
}

TEST(BinaryModelLiveProcess, EnforcesReadOnlyPolicyResolvesCommandLineAndPopulatesStaticMetadata) {
    const std::filesystem::path elf_path = fixture_path("hello.elf");
    const std::vector<std::uint8_t> elf_bytes = read_binary_file(elf_path);
    auto static_img = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(static_img.has_value());

    constexpr std::uint64_t kLiveBase = 0x0000555555554000ull;
    constexpr std::uint64_t kHeapBase = 0x00007FFF10000000ull;  // >46 TiB away from kLiveBase!

    // Deliberately leave `executable_path` empty so `attach_process` must resolve it from `command_line`!
    peelf::ProcessInfo pinfo{
        .pid = 5150,
        .name = "hello.elf",
        .executable_path = {},
        .command_line = "\"" + elf_path.string() + "\" --inspect --port 8080",
        .architecture = peelf::Architecture::X86_64,
        .is_64bit = true,
        .access = peelf::ProcessAccessStatus::ReadOnly,
    };

    FakeProcessSession* raw_session = nullptr;
    auto backend = std::make_shared<FakeProcessBackend>();
    backend->register_process(pinfo, [&]() {
        auto sess = std::make_unique<FakeProcessSession>(pinfo);
        // Map ELF segments WITHOUT pathname on regions so backing path MUST come from command_line!
        map_elf_segments_into_fake_process(*sess, **static_img, elf_bytes, kLiveBase, "");

        peelf::MemoryRegion heap_reg{
            .start_address = kHeapBase,
            .end_address = kHeapBase + 0x2000,
            .protection = {.readable = true, .writable = true},
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap]",
        };
        sess->add_mapped_span(heap_reg, std::vector<std::uint8_t>(0x2000, 0x5A));
        raw_session = sess.get();
        return sess;
    });

    viewer::BinaryModel model;
    model.set_process_backend(backend);

    auto listed = model.list_processes();
    ASSERT_TRUE(listed.has_value());
    ASSERT_EQ(listed->size(), 1u);
    EXPECT_EQ((*listed)[0].pid, 5150u);

    ASSERT_TRUE(model.attach_process(5150).has_value());
    ASSERT_TRUE(model.is_live_process());
    EXPECT_TRUE(model.is_read_only());
    ASSERT_NE(raw_session, nullptr);
    ASSERT_NE(model.image(), nullptr);
    EXPECT_EQ(model.view_base_address(), kLiveBase);

    // Command-line path resolution hydrated non-SHF_ALLOC `.symtab` (`main`) AND FunctionIndex!
    const viewer::SymbolRecord* main_sym = model.symbol_index().find_by_name("main");
    ASSERT_NE(main_sym, nullptr);
    ASSERT_TRUE(main_sym->virtual_address.has_value());
    const std::uint64_t main_va = *main_sym->virtual_address;
    const std::vector<std::uint8_t> orig_main_bytes = raw_session->raw_ram_slice(main_va, 4);
    ASSERT_EQ(orig_main_bytes.size(), 4u);

    EXPECT_FALSE(model.function_index().entries().empty());
    EXPECT_NE(model.function_index().find_containing(main_va), nullptr);
    EXPECT_FALSE(model.header_flags().flags.empty());
    EXPECT_GT(model.analysis_image_size(), 0u);

    // Live virtual read returns exact code bytes at `main_va`.
    auto main_read = model.read_virtual_bytes(main_va, 4);
    ASSERT_TRUE(main_read.has_value()) << main_read.error().message;
    EXPECT_EQ(*main_read, orig_main_bytes);

    // Strictly read-only enforcement: every mutation / patch / commit / revert API must refuse writes!
    EXPECT_FALSE(model.apply_patch_bytes(0, std::vector<std::uint8_t>{0x90}, "blocked byte edit").has_value());
    EXPECT_FALSE(model.apply_patch_bytes(0, std::vector<std::uint8_t>{0x90, 0xC3}, "blocked range edit").has_value());
    EXPECT_FALSE(model.stage_patch_at_va(main_va, std::vector<std::uint8_t>{0x90, 0x90}, "blocked va stage").has_value());
    EXPECT_FALSE(model.commit_patches_to_process().has_value());
    EXPECT_FALSE(model.revert_committed_patches().has_value());
    EXPECT_TRUE(model.changed_intervals().empty());
    EXPECT_EQ(raw_session->raw_ram_slice(main_va, 4), orig_main_bytes);

    // Navigate directly to the heap region via VA and build Structure tree.
    const auto heap_off = model.navigate_to_virtual_address(kHeapBase + 0x20);
    ASSERT_TRUE(heap_off.has_value());
    EXPECT_EQ(model.live_target_kind(), viewer::LiveViewTargetKind::Region);
    EXPECT_EQ(model.view_base_address(), kHeapBase);
    EXPECT_EQ(*heap_off, 0x20u);

    ASSERT_TRUE(model.select_process_module(0).has_value());
    ASSERT_NE(model.process_session(), nullptr);
    const viewer::StructureNode tree = viewer::build_live_process_structure_tree(
        model.process_session()->info(),
        model.process_modules(),
        model.memory_regions(),
        model.image(),
        model.active_module_index());
    EXPECT_EQ(tree.selection.kind, viewer::SelectionKind::Process);
    ASSERT_EQ(tree.children.size(), 3u);
    EXPECT_TRUE(tree.children[0].selection.label.starts_with("Modules ("));
    EXPECT_TRUE(tree.children[1].selection.label.starts_with("Memory Map ("));
    EXPECT_TRUE(tree.children[2].selection.label.starts_with("hello.elf ("));
}

TEST(LiveCallGraph, BuildsSymbolFanoutGraphFromRebasedLiveModuleViaReader) {
#if !defined(PEELF_CALLGRAPH_FIXTURE_EXE)
    GTEST_SKIP() << "callgraph fixture path not configured";
#else
    const std::filesystem::path exe_path = PEELF_CALLGRAPH_FIXTURE_EXE;
    ASSERT_TRUE(std::filesystem::exists(exe_path));
    const std::vector<std::uint8_t> exe_bytes = read_binary_file(exe_path);
    auto static_img = peelf::parse_image(exe_bytes);
    ASSERT_TRUE(static_img.has_value());
    if ((*static_img)->format() != peelf::Format::ELF) {
        GTEST_SKIP() << "ELF live callgraph test runs on ELF callgraph fixture";
    }

    constexpr std::uint64_t kAslrBase = 0x0000560012340000ull;
    peelf::ProcessInfo pinfo{
        .pid = 6060,
        .name = "peelf_callgraph_fixture",
        .executable_path = exe_path,
        .architecture = (*static_img)->architecture(),
        .is_64bit = (*static_img)->is_64bit(),
        .access = peelf::ProcessAccessStatus::Accessible,
    };

    auto sess = std::make_unique<FakeProcessSession>(pinfo);
    map_elf_segments_into_fake_process(*sess, **static_img, exe_bytes, kAslrBase, exe_path.string());

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_session(std::move(sess)).has_value());
    ASSERT_NE(model.image(), nullptr);

    const viewer::SymbolRecord* main_rec = model.symbol_index().find_by_name("main");
    ASSERT_NE(main_rec, nullptr);

    const viewer::GraphByteReader reader = [&model](std::uint64_t offset, std::size_t length) {
        auto sample = model.read_window_sample(offset, length);
        if (!sample) {
            return std::vector<std::uint8_t>{};
        }
        return std::move(sample->bytes);
    };

    const viewer::CallGraph graph = viewer::build_symbol_fanout_call_graph(
        *model.image(), reader, model.symbol_index(), *main_rec);
    EXPECT_GT(graph.nodes.size(), 1u);
    EXPECT_FALSE(graph.edges.empty());
#endif
}
