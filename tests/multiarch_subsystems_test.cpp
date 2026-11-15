#include <gtest/gtest.h>

#include "analysis/function_index.hpp"
#include "decompile/structured_decompiler.hpp"
#include "model/binary_model.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/handlers.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/process.hpp>
#include <peelf/runtime_structures.hpp>
#include <peelf/stack_tls.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

[[nodiscard]] std::filesystem::path fixture_path(std::string_view name) {
    return std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / name;
}

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    EXPECT_TRUE(in.is_open()) << path.string();
    const auto sz = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> out(sz);
    if (sz > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    }
    return out;
}

class SyntheticReadOnlySession final : public peelf::IProcessSession {
public:
    explicit SyntheticReadOnlySession(peelf::ProcessInfo info) : info_(std::move(info)) {}

    void add_region(peelf::MemoryRegion region, std::vector<std::uint8_t> bytes) {
        spans_.push_back({std::move(region), std::move(bytes)});
        std::ranges::sort(spans_, {}, [](const Span& s) { return s.region.start_address; });
    }

    void set_modules(std::vector<peelf::ModuleInfo> modules) { modules_ = std::move(modules); }
    void set_peb(std::uint64_t peb_va) { peb_va_ = peb_va; }
    void set_auxv(std::vector<std::uint8_t> auxv) { auxv_ = std::move(auxv); }
    void set_proc_status(std::string text) { proc_status_ = std::move(text); }
    void set_threads(std::vector<peelf::ThreadInfo> threads) { threads_ = std::move(threads); }
    void set_thread_context(peelf::ThreadId tid, peelf::ThreadContext ctx) {
        contexts_[tid] = std::move(ctx);
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        std::vector<peelf::MemoryRegion> regs;
        regs.reserve(spans_.size());
        for (const Span& s : spans_) {
            regs.push_back(s.region);
        }
        return regs;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return modules_;
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        for (const Span& s : spans_) {
            if (!s.region.contains(address)) {
                continue;
            }
            if (!s.region.protection.readable || s.region.protection.guarded) {
                return peelf::make_error("region is not readable");
            }
            const auto rel = static_cast<std::size_t>(address - s.region.start_address);
            if (rel >= s.bytes.size()) {
                return peelf::make_error("offset outside backing buffer");
            }
            const std::size_t n = std::min<std::size_t>(buffer.size(), s.bytes.size() - rel);
            std::memcpy(buffer.data(), s.bytes.data() + rel, n);
            return n;
        }
        return peelf::make_error("unmapped address");
    }

    [[nodiscard]] peelf::Result<std::size_t> write_memory(
        std::uint64_t /*address*/,
        std::span<const std::uint8_t> /*data*/,
        peelf::MemoryWriteOptions /*options*/) override {
        return peelf::make_error("strictly read-only session");
    }

    [[nodiscard]] peelf::Result<void> suspend() override {
        suspended_ = true;
        return {};
    }
    [[nodiscard]] peelf::Result<void> resume() override {
        suspended_ = false;
        return {};
    }
    [[nodiscard]] bool is_suspended() const noexcept override { return suspended_; }

    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return threads_;
    }

    [[nodiscard]] peelf::ThreadContext thread_context(peelf::ThreadId tid) override {
        const auto it = contexts_.find(tid);
        if (it != contexts_.end()) {
            return it->second;
        }
        return peelf::IProcessSession::thread_context(tid);
    }

    [[nodiscard]] peelf::ForgivingValue<std::uint64_t> process_environment_block_address() override {
        if (peb_va_.has_value()) {
            return {*peb_va_, peelf::SubsystemStatus::available("synthetic", "PEB VA available")};
        }
        return peelf::IProcessSession::process_environment_block_address();
    }

    [[nodiscard]] peelf::ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
        if (!auxv_.empty()) {
            return {auxv_, peelf::SubsystemStatus::available("synthetic", "auxv available")};
        }
        return peelf::IProcessSession::proc_auxv();
    }

    [[nodiscard]] peelf::ForgivingValue<std::string> proc_status_text() override {
        if (!proc_status_.empty()) {
            return {proc_status_, peelf::SubsystemStatus::available("synthetic", "status available")};
        }
        return peelf::IProcessSession::proc_status_text();
    }

private:
    struct Span {
        peelf::MemoryRegion region;
        std::vector<std::uint8_t> bytes;
    };

    peelf::ProcessInfo info_;
    std::vector<Span> spans_;
    std::vector<peelf::ModuleInfo> modules_;
    std::optional<std::uint64_t> peb_va_;
    std::vector<std::uint8_t> auxv_;
    std::string proc_status_;
    std::vector<peelf::ThreadInfo> threads_;
    std::map<peelf::ThreadId, peelf::ThreadContext> contexts_;
    bool suspended_{false};
};

void write_bytes_at(std::vector<std::uint8_t>& dst,
                    std::size_t offset,
                    std::span<const std::uint8_t> src) {
    ASSERT_LE(offset + src.size(), dst.size());
    std::memcpy(dst.data() + offset, src.data(), src.size());
}

}  // namespace

TEST(EndianReaderAndEncoders, RoundTrips32And64BitLittleAndBigEndianPrimitivesAndStrings) {
    for (const peelf::Endianness endian : {peelf::Endianness::Little, peelf::Endianness::Big}) {
        const auto u16_b = peelf::encode_u16(0xCAFEu, endian);
        const auto i32_b = peelf::encode_i32(-123456789, endian);
        const auto u64_b = peelf::encode_u64(0x0123456789ABCDEFull, endian);
        const auto f32_b = peelf::encode_f32(3.25f, endian);
        const auto f64_b = peelf::encode_f64(-1024.5, endian);
        auto u16_str = peelf::encode_utf16("PE/ELF!", endian);
        u16_str.push_back(0);
        u16_str.push_back(0);

        peelf::EndianReader r16(u16_b, endian, peelf::AddressWidth::Bits32);
        ASSERT_TRUE(r16.read_u16(0).has_value());
        EXPECT_EQ(*r16.read_u16(0), 0xCAFEu);

        peelf::EndianReader r32(i32_b, endian, peelf::AddressWidth::Bits32);
        ASSERT_TRUE(r32.read_i32(0).has_value());
        EXPECT_EQ(*r32.read_i32(0), -123456789);
        ASSERT_TRUE(r32.read_pointer(0).has_value());
        EXPECT_EQ(*r32.read_pointer(0), static_cast<std::uint32_t>(-123456789));

        peelf::EndianReader r64(u64_b, endian, peelf::AddressWidth::Bits64);
        ASSERT_TRUE(r64.read_u64(0).has_value());
        EXPECT_EQ(*r64.read_u64(0), 0x0123456789ABCDEFull);
        ASSERT_TRUE(r64.read_pointer(0).has_value());
        EXPECT_EQ(*r64.read_pointer(0), 0x0123456789ABCDEFull);

        peelf::EndianReader rf32(f32_b, endian);
        ASSERT_TRUE(rf32.read_f32(0).has_value());
        EXPECT_FLOAT_EQ(*rf32.read_f32(0), 3.25f);

        peelf::EndianReader rf64(f64_b, endian);
        ASSERT_TRUE(rf64.read_f64(0).has_value());
        EXPECT_DOUBLE_EQ(*rf64.read_f64(0), -1024.5);

        peelf::EndianReader rstr(u16_str, endian);
        auto decoded = rstr.read_utf16_string(0);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(*decoded, "PE/ELF!");

        // Out-of-bounds reads fail cleanly without UB.
        EXPECT_FALSE(r32.read_u64(0).has_value());
        EXPECT_FALSE(r64.read_u16(7).has_value());
    }

    // Verify explicit big-endian byte layout for 0x11223344.
    const auto be32 = peelf::encode_u32(0x11223344u, peelf::Endianness::Big);
    EXPECT_EQ(be32, (std::vector<std::uint8_t>{0x11, 0x22, 0x33, 0x44}));
    const auto le32 = peelf::encode_u32(0x11223344u, peelf::Endianness::Little);
    EXPECT_EQ(le32, (std::vector<std::uint8_t>{0x44, 0x33, 0x22, 0x11}));
}

TEST(CommandLineResolution, ResolvesPosixWindowsNullDelimitedRelativeAndPathExecutables) {
    auto fake_exists = [](const std::filesystem::path& p) {
        const std::string s = p.generic_string();
        return s == "/opt/my service/daemon" ||
               s == "/work/proj/bin/runner" ||
               s == "/usr/local/bin/target_tool" ||
               s == "C:/Program Files/My App/app.exe";
    };

    // 1. NUL-delimited `/proc/<pid>/cmdline`.
    const std::string nul_cmd("/opt/my service/daemon\0--config\0/etc/d.conf\0", 39);
    const auto r1 = peelf::resolve_executable_from_command_line(nul_cmd, {}, {}, false, fake_exists);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->generic_string(), "/opt/my service/daemon");

    // 2. Relative argv[0] resolved against `working_directory`.
    const auto r2 = peelf::resolve_executable_from_command_line(
        "./bin/runner --verbose", "/work/proj", {}, false, fake_exists);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2->lexically_normal().generic_string(), "/work/proj/bin/runner");

    // 3. Bare command resolved via `PATH`.
    const auto r3 = peelf::resolve_executable_from_command_line(
        "target_tool -d", "/tmp", "/bin:/usr/local/bin:/usr/bin", false, fake_exists);
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(r3->generic_string(), "/usr/local/bin/target_tool");

    // 4. Quoted Windows command line with spaces.
    const auto r4 = peelf::resolve_executable_from_command_line(
        "\"C:/Program Files/My App/app.exe\" --flag 1", {}, {}, true, fake_exists);
    ASSERT_TRUE(r4.has_value());
    EXPECT_EQ(r4->generic_string(), "C:/Program Files/My App/app.exe");
}

TEST(EndianMemorySearch, FindsHexWildcardsEndianNumbersAndUnicodeAcrossHeapScope) {
    peelf::ProcessInfo pinfo{
        .pid = 7001,
        .name = "ppc_srv",
        .architecture = peelf::Architecture::PowerPC,
        .endianness = peelf::Endianness::Big,
        .is_64bit = false,
        .access = peelf::ProcessAccessStatus::ReadOnly,
    };
    SyntheticReadOnlySession session(pinfo);

    std::vector<std::uint8_t> code_bytes(0x1000, 0x00);
    // Put a decoy value in Image `.text` to prove `SearchScope::Heap` skips non-heap regions!
    write_bytes_at(code_bytes, 0x40, peelf::encode_u32(0xCAFEBABEu, peelf::Endianness::Big));
    session.add_region(
        peelf::MemoryRegion{
            .start_address = 0x10000000u,
            .end_address = 0x10001000u,
            .protection = {.readable = true, .executable = true},
            .kind = peelf::MemoryRegionKind::Image,
            .pathname = "/usr/bin/ppc_srv",
        },
        std::move(code_bytes));

    std::vector<std::uint8_t> heap_bytes(0x1000, 0x00);
    write_bytes_at(heap_bytes, 0x10, std::array<std::uint8_t, 5>{0xDE, 0xAD, 0x7F, 0xBE, 0xEF});
    write_bytes_at(heap_bytes, 0x40, peelf::encode_u32(0xCAFEBABEu, peelf::Endianness::Big));
    write_bytes_at(heap_bytes, 0x80, peelf::encode_i32(-42000, peelf::Endianness::Little));
    write_bytes_at(heap_bytes, 0xC0, peelf::encode_f64(2718.25, peelf::Endianness::Big));
    const std::string ascii_needle = "HeapSecretToken";
    write_bytes_at(heap_bytes,
                   0x100,
                   std::span<const std::uint8_t>(
                       reinterpret_cast<const std::uint8_t*>(ascii_needle.data()),
                       ascii_needle.size()));
    write_bytes_at(heap_bytes, 0x180, peelf::encode_utf16("WideBigEndian", peelf::Endianness::Big));

    session.add_region(
        peelf::MemoryRegion{
            .start_address = 0x20000000u,
            .end_address = 0x20001000u,
            .protection = {.readable = true, .writable = true},
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap]",
        },
        std::move(heap_bytes));

    const auto regs = *session.memory_regions();

    // 1. Hex wildcard search on Heap.
    auto hex_res = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::HexPattern,
            .query_text = "DE AD ?? BE EF",
        });
    ASSERT_TRUE(hex_res.has_value()) << hex_res.error().message;
    ASSERT_EQ(hex_res->hits.size(), 1u);
    EXPECT_EQ(hex_res->hits[0].address, 0x20000010u);

    // 2. Big-Endian uint32 search on Heap ONLY finds the `[heap]` occurrence, not `.text`!
    auto be_u32 = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::UInt32,
            .query_text = "0xCAFEBABE",
            .endianness = peelf::Endianness::Big,
            .alignment = 4,
        });
    ASSERT_TRUE(be_u32.has_value()) << be_u32.error().message;
    ASSERT_EQ(be_u32->hits.size(), 1u);
    EXPECT_EQ(be_u32->hits[0].address, 0x20000040u);

    // 3. Little-Endian signed int32 search.
    auto le_i32 = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::Int32,
            .query_text = "-42000",
            .endianness = peelf::Endianness::Little,
        });
    ASSERT_TRUE(le_i32.has_value());
    ASSERT_EQ(le_i32->hits.size(), 1u);
    EXPECT_EQ(le_i32->hits[0].address, 0x20000080u);

    // 4. Big-Endian float64 search.
    auto be_f64 = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::Float64,
            .query_text = "2718.25",
            .endianness = peelf::Endianness::Big,
        });
    ASSERT_TRUE(be_f64.has_value());
    ASSERT_EQ(be_f64->hits.size(), 1u);
    EXPECT_EQ(be_f64->hits[0].address, 0x200000C0u);

    // 5. Case-insensitive UTF-8 search.
    auto utf8_ci = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::Utf8Text,
            .query_text = "heapsecrettoken",
            .case_sensitive = false,
        });
    ASSERT_TRUE(utf8_ci.has_value());
    ASSERT_EQ(utf8_ci->hits.size(), 1u);
    EXPECT_EQ(utf8_ci->hits[0].address, 0x20000100u);

    // 6. Big-Endian UTF-16 search.
    auto utf16_be = peelf::search_process_memory(
        session,
        regs,
        peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::Heap,
            .kind = peelf::SearchValueKind::Utf16Text,
            .query_text = "WideBigEndian",
            .endianness = peelf::Endianness::Big,
        });
    ASSERT_TRUE(utf16_be.has_value());
    ASSERT_EQ(utf16_be->hits.size(), 1u);
    EXPECT_EQ(utf16_be->hits[0].address, 0x20000180u);
}

TEST(StackUnwindAndHighlighting, HighlightsReturnAddressesAndFramePointersOn64BitLittleAnd32BitBigEndian) {
    // Case A: 64-bit Little-Endian (x86-64) stack with 2 saved frames.
    {
        peelf::ProcessInfo pinfo{
            .pid = 8001,
            .name = "x64_app",
            .architecture = peelf::Architecture::X86_64,
            .endianness = peelf::Endianness::Little,
            .is_64bit = true,
        };
        SyntheticReadOnlySession sess(pinfo);

        sess.add_region(
            peelf::MemoryRegion{
                .start_address = 0x401000ull,
                .end_address = 0x402000ull,
                .protection = {.readable = true, .executable = true},
                .kind = peelf::MemoryRegionKind::Image,
                .pathname = "/bin/x64_app",
                .module_name = "x64_app",
            },
            std::vector<std::uint8_t>(0x1000, 0x90));

        constexpr std::uint64_t kStackBase = 0x7FFFFFFFE000ull;
        std::vector<std::uint8_t> stack_mem(0x1000, 0);
        // SP = kStackBase + 0x100, RBP = kStackBase + 0x110:
        // [RBP + 0] = saved RBP1 (kStackBase + 0x130), [RBP + 8] = return addr1 (0x401234)
        // [RBP1 + 0] = 0 (end of chain),               [RBP1 + 8] = return addr2 (0x401560)
        write_bytes_at(stack_mem, 0x110, peelf::encode_u64(kStackBase + 0x130ull, peelf::Endianness::Little));
        write_bytes_at(stack_mem, 0x118, peelf::encode_u64(0x401234ull, peelf::Endianness::Little));
        write_bytes_at(stack_mem, 0x130, peelf::encode_u64(0ull, peelf::Endianness::Little));
        write_bytes_at(stack_mem, 0x138, peelf::encode_u64(0x401560ull, peelf::Endianness::Little));

        sess.add_region(
            peelf::MemoryRegion{
                .start_address = kStackBase,
                .end_address = kStackBase + 0x1000ull,
                .protection = {.readable = true, .writable = true},
                .kind = peelf::MemoryRegionKind::Stack,
                .pathname = "[stack]",
            },
            std::move(stack_mem));

        peelf::ThreadContext ctx;
        ctx.tid = 8001;
        ctx.layout = peelf::TargetLayout::from_arch(peelf::Architecture::X86_64, true, peelf::Endianness::Little);
        ctx.instruction_pointer = 0x401100ull;
        ctx.stack_pointer = kStackBase + 0x100ull;
        ctx.frame_pointer = kStackBase + 0x110ull;
        ctx.status = peelf::SubsystemStatus::available("test", "ok");

        const auto regs = *sess.memory_regions();
        const std::vector<peelf::ModuleInfo> mods{
            peelf::ModuleInfo{.name = "x64_app", .base_address = 0x401000ull, .size = 0x1000ull, .is_main_module = true},
        };

        const peelf::ThreadStackSnapshot snap = peelf::unwind_and_inspect_stack(
            sess,
            ctx,
            regs,
            mods,
            nullptr,
            [](std::uint64_t va) -> std::string {
                if (va == 0x401234ull) return "caller_one+0x14";
                if (va == 0x401560ull) return "main+0x30";
                return {};
            });

        EXPECT_TRUE(snap.status.is_usable());
        EXPECT_GE(snap.frames.size(), 3u);

        auto find_slot = [&](std::uint64_t slot_va) -> const peelf::StackSlotEntry* {
            const auto it = std::ranges::find_if(snap.slots, [slot_va](const peelf::StackSlotEntry& s) {
                return s.slot_address == slot_va;
            });
            return it != snap.slots.end() ? &(*it) : nullptr;
        };

        const auto* active_fp = find_slot(kStackBase + 0x110ull);
        const auto* ret1 = find_slot(kStackBase + 0x118ull);
        const auto* saved_fp = find_slot(kStackBase + 0x130ull);
        const auto* ret2 = find_slot(kStackBase + 0x138ull);
        ASSERT_NE(active_fp, nullptr);
        ASSERT_NE(ret1, nullptr);
        ASSERT_NE(saved_fp, nullptr);
        ASSERT_NE(ret2, nullptr);

        // Return addresses and frame pointers MUST carry distinct highlight roles!
        EXPECT_TRUE(active_fp->role == peelf::StackSlotRole::ActiveFramePointer ||
                    active_fp->role == peelf::StackSlotRole::SavedFramePointer);
        EXPECT_EQ(ret1->role, peelf::StackSlotRole::ReturnAddress);
        EXPECT_NE(ret1->role, active_fp->role);
        EXPECT_EQ(saved_fp->role, peelf::StackSlotRole::SavedFramePointer);
        EXPECT_EQ(ret2->role, peelf::StackSlotRole::ReturnAddress);
    }

    // Case B: 32-bit Big-Endian PowerPC SVR4 backchain (`[FP+0] = saved_fp`, `[FP+4] = saved_lr`).
    {
        peelf::ProcessInfo pinfo{
            .pid = 8002,
            .name = "ppc32_app",
            .architecture = peelf::Architecture::PowerPC,
            .endianness = peelf::Endianness::Big,
            .is_64bit = false,
        };
        SyntheticReadOnlySession sess(pinfo);

        sess.add_region(
            peelf::MemoryRegion{
                .start_address = 0x10000000u,
                .end_address = 0x10004000u,
                .protection = {.readable = true, .executable = true},
                .kind = peelf::MemoryRegionKind::Image,
                .pathname = "/bin/ppc32_app",
            },
            std::vector<std::uint8_t>(0x4000, 0x60));

        constexpr std::uint64_t kPpcStack = 0x7FFF0000u;
        std::vector<std::uint8_t> stack_mem(0x400, 0);
        // PowerPC SVR4 ABI: SP/FP = kPpcStack + 0x80 -> backchain to kPpcStack + 0xA0, LR at [next_fp + 4] or [fp + 4].
        write_bytes_at(stack_mem, 0x80, peelf::encode_u32(static_cast<std::uint32_t>(kPpcStack + 0xA0u), peelf::Endianness::Big));
        write_bytes_at(stack_mem, 0x84, peelf::encode_u32(0x10001200u, peelf::Endianness::Big));
        write_bytes_at(stack_mem, 0xA0, peelf::encode_u32(0u, peelf::Endianness::Big));
        write_bytes_at(stack_mem, 0xA4, peelf::encode_u32(0x10001800u, peelf::Endianness::Big));

        sess.add_region(
            peelf::MemoryRegion{
                .start_address = kPpcStack,
                .end_address = kPpcStack + 0x400u,
                .protection = {.readable = true, .writable = true},
                .kind = peelf::MemoryRegionKind::Stack,
                .pathname = "[stack]",
            },
            std::move(stack_mem));

        peelf::ThreadContext ctx;
        ctx.tid = 8002;
        ctx.layout = peelf::TargetLayout::from_arch(peelf::Architecture::PowerPC, false, peelf::Endianness::Big);
        ctx.instruction_pointer = 0x10001050u;
        ctx.stack_pointer = kPpcStack + 0x80u;
        ctx.frame_pointer = kPpcStack + 0x80u;
        ctx.status = peelf::SubsystemStatus::available("test", "ok");

        const auto regs = *sess.memory_regions();
        const peelf::ThreadStackSnapshot snap = peelf::unwind_and_inspect_stack(sess, ctx, regs, {});
        EXPECT_EQ(snap.layout.address_width, peelf::AddressWidth::Bits32);
        EXPECT_EQ(snap.layout.endianness, peelf::Endianness::Big);
        EXPECT_FALSE(snap.slots.empty());
        const bool has_ret = std::ranges::any_of(snap.slots, [](const peelf::StackSlotEntry& s) {
            return s.role == peelf::StackSlotRole::ReturnAddress;
        });
        const bool has_fp = std::ranges::any_of(snap.slots, [](const peelf::StackSlotEntry& s) {
            return s.role == peelf::StackSlotRole::ActiveFramePointer ||
                   s.role == peelf::StackSlotRole::SavedFramePointer;
        });
        EXPECT_TRUE(has_ret);
        EXPECT_TRUE(has_fp);
    }
}

TEST(RuntimeEnvironmentAndHeaderFlags, ParsesPeb64Teb64LinuxAuxvAndHeaderFlagsWithForgivingFallbacks) {
    // 1. Harvest header flags on both PE and ELF fixtures.
    {
        const auto pe_bytes = read_file_bytes(fixture_path("known-win-x64.exe"));
        auto pe_img = peelf::parse_image(pe_bytes);
        ASSERT_TRUE(pe_img.has_value());
        const peelf::HeaderFlagsReport pe_flags = peelf::harvest_header_flags(**pe_img);
        EXPECT_EQ(pe_flags.format, peelf::Format::PE);
        EXPECT_TRUE(pe_flags.status.is_usable());
        EXPECT_FALSE(pe_flags.flags.empty());

        const auto elf_bytes = read_file_bytes(fixture_path("hello.elf"));
        auto elf_img = peelf::parse_image(elf_bytes);
        ASSERT_TRUE(elf_img.has_value());
        const peelf::HeaderFlagsReport elf_flags = peelf::harvest_header_flags(**elf_img);
        EXPECT_EQ(elf_flags.format, peelf::Format::ELF);
        EXPECT_TRUE(elf_flags.status.is_usable());
        EXPECT_FALSE(elf_flags.flags.empty());
    }

    // 2. Synthetic Win64 PEB64 + TEB64 inspection.
    {
        peelf::ProcessInfo pinfo{
            .pid = 9100,
            .name = "win64.exe",
            .architecture = peelf::Architecture::X86_64,
            .endianness = peelf::Endianness::Little,
            .is_64bit = true,
        };
        SyntheticReadOnlySession sess(pinfo);

        constexpr std::uint64_t kPebVa = 0x0000007F00001000ull;
        constexpr std::uint64_t kTebVa = 0x0000007F00002000ull;
        std::vector<std::uint8_t> peb_mem(0x400, 0);
        peb_mem[0x02] = 1;  // BeingDebugged = 1
        write_bytes_at(peb_mem, 0x10, peelf::encode_u64(0x00007FF700000000ull, peelf::Endianness::Little));  // ImageBaseAddress
        sess.add_region(
            peelf::MemoryRegion{
                .start_address = kPebVa,
                .end_address = kPebVa + 0x1000ull,
                .protection = {.readable = true, .writable = true},
                .kind = peelf::MemoryRegionKind::Anonymous,
            },
            std::move(peb_mem));
        sess.set_peb(kPebVa);

        std::vector<std::uint8_t> teb_mem(0x1800, 0);
        // NT_TIB64: [0x08] StackBase, [0x10] StackLimit, [0x30] Self, [0x58] ThreadLocalStoragePointer, [0x60] Peb
        write_bytes_at(teb_mem, 0x08, peelf::encode_u64(0x0000007F00200000ull, peelf::Endianness::Little));
        write_bytes_at(teb_mem, 0x10, peelf::encode_u64(0x0000007F001F0000ull, peelf::Endianness::Little));
        write_bytes_at(teb_mem, 0x30, peelf::encode_u64(kTebVa, peelf::Endianness::Little));
        write_bytes_at(teb_mem, 0x58, peelf::encode_u64(0x0000007F00300000ull, peelf::Endianness::Little));
        write_bytes_at(teb_mem, 0x60, peelf::encode_u64(kPebVa, peelf::Endianness::Little));
        write_bytes_at(teb_mem, 0x68, peelf::encode_u32(5u, peelf::Endianness::Little));  // LastErrorValue = ERROR_ACCESS_DENIED
        sess.add_region(
            peelf::MemoryRegion{
                .start_address = kTebVa,
                .end_address = kTebVa + 0x2000ull,
                .protection = {.readable = true, .writable = true},
                .kind = peelf::MemoryRegionKind::Anonymous,
            },
            std::move(teb_mem));

        const auto pe_bytes = read_file_bytes(fixture_path("known-win-x64.exe"));
        auto pe_img = peelf::parse_image(pe_bytes);
        ASSERT_TRUE(pe_img.has_value());

        const auto regs = *sess.memory_regions();
        const peelf::ProcessEnvironmentSnapshot peb_snap =
            peelf::inspect_process_environment(sess, regs, {}, pe_img->get());
        EXPECT_EQ(peb_snap.os_family, peelf::Format::PE);
        EXPECT_TRUE(peb_snap.debugger_present);
        EXPECT_FALSE(peb_snap.core_fields.empty());

        peelf::ThreadInfo tinfo{.tid = 9101, .name = "main", .teb_address = kTebVa};
        const peelf::ThreadEnvironmentSnapshot teb_snap =
            peelf::inspect_thread_environment(sess, tinfo, nullptr, regs);
        EXPECT_EQ(teb_snap.os_family, peelf::Format::PE);
        ASSERT_TRUE(teb_snap.stack_base.has_value());
        EXPECT_EQ(*teb_snap.stack_base, 0x0000007F00200000ull);
        ASSERT_TRUE(teb_snap.stack_limit.has_value());
        EXPECT_EQ(*teb_snap.stack_limit, 0x0000007F001F0000ull);
    }

    // 3. Synthetic 32-bit Big-Endian Linux auxv + `/proc/<pid>/status` inspection.
    {
        peelf::ProcessInfo pinfo{
            .pid = 9200,
            .name = "mips_be_elf",
            .executable_path = "/bin/mips_be_elf",
            .command_line = "/bin/mips_be_elf --serve",
            .working_directory = "/srv",
            .architecture = peelf::Architecture::MIPS32,
            .endianness = peelf::Endianness::Big,
            .is_64bit = false,
        };
        SyntheticReadOnlySession sess(pinfo);

        std::vector<std::uint8_t> auxv;
        auto push_aux32_be = [&](std::uint32_t tag, std::uint32_t val) {
            const auto tb = peelf::encode_u32(tag, peelf::Endianness::Big);
            const auto vb = peelf::encode_u32(val, peelf::Endianness::Big);
            auxv.insert(auxv.end(), tb.begin(), tb.end());
            auxv.insert(auxv.end(), vb.begin(), vb.end());
        };
        push_aux32_be(6u, 4096u);        // AT_PAGESZ = 4096
        push_aux32_be(9u, 0x00401000u);  // AT_ENTRY = 0x00401000
        push_aux32_be(0u, 0u);           // AT_NULL
        sess.set_auxv(std::move(auxv));
        sess.set_proc_status(
            "Name:\tmips_be_elf\n"
            "TracerPid:\t1337\n"
            "Seccomp:\t2\n"
            "NoNewPrivs:\t1\n"
            "SigPnd:\t0000000000000000\n"
            "SigBlk:\t0000000000000004\n"
            "SigIgn:\t0000000000001000\n"
            "SigCgt:\t0000000000000201\n");

        const peelf::ProcessEnvironmentSnapshot env =
            peelf::inspect_process_environment(sess, {}, {}, nullptr);
        EXPECT_EQ(env.os_family, peelf::Format::ELF);
        EXPECT_TRUE(env.debugger_present);
        EXPECT_FALSE(env.auxv_entries.empty());

        const peelf::HandlersReport hrep =
            peelf::inspect_handlers(nullptr, {}, &sess, {}, {}, nullptr);
        EXPECT_FALSE(hrep.signals.empty());
    }
}

TEST(HandlersSubsystem, Walks32BitSehChainCycleSafelyAndHarvestsStaticPeAndElfHandlers) {
    // 1. Live 32-bit x86 TEB32.ExceptionList SEH chain with intentional cycle at end.
    peelf::ProcessInfo pinfo{
        .pid = 9300,
        .name = "legacy32.exe",
        .architecture = peelf::Architecture::X86,
        .endianness = peelf::Endianness::Little,
        .is_64bit = false,
    };
    SyntheticReadOnlySession sess(pinfo);

    constexpr std::uint64_t kTeb32 = 0x7EFDD000u;
    constexpr std::uint64_t kStack32 = 0x0019F000u;
    std::vector<std::uint8_t> teb32(0x1000, 0);
    // NT_TIB32: [0x00] ExceptionList = kStack32 + 0x20, [0x04] StackBase, [0x08] StackLimit
    write_bytes_at(teb32, 0x00, peelf::encode_u32(static_cast<std::uint32_t>(kStack32 + 0x20u), peelf::Endianness::Little));
    write_bytes_at(teb32, 0x04, peelf::encode_u32(static_cast<std::uint32_t>(kStack32 + 0x1000u), peelf::Endianness::Little));
    write_bytes_at(teb32, 0x08, peelf::encode_u32(static_cast<std::uint32_t>(kStack32), peelf::Endianness::Little));
    sess.add_region(
        peelf::MemoryRegion{
            .start_address = kTeb32,
            .end_address = kTeb32 + 0x1000u,
            .protection = {.readable = true, .writable = true},
            .kind = peelf::MemoryRegionKind::Anonymous,
        },
        std::move(teb32));

    std::vector<std::uint8_t> stack32(0x1000, 0);
    // Record 0 at +0x20 -> Next = +0x40, Handler = 0x00401500
    write_bytes_at(stack32, 0x20, peelf::encode_u32(static_cast<std::uint32_t>(kStack32 + 0x40u), peelf::Endianness::Little));
    write_bytes_at(stack32, 0x24, peelf::encode_u32(0x00401500u, peelf::Endianness::Little));
    // Record 1 at +0x40 -> Next = 0xFFFFFFFF (chain end), Handler = 0x77112233
    write_bytes_at(stack32, 0x40, peelf::encode_u32(0xFFFFFFFFu, peelf::Endianness::Little));
    write_bytes_at(stack32, 0x44, peelf::encode_u32(0x77112233u, peelf::Endianness::Little));
    sess.add_region(
        peelf::MemoryRegion{
            .start_address = kStack32,
            .end_address = kStack32 + 0x1000u,
            .protection = {.readable = true, .writable = true},
            .kind = peelf::MemoryRegionKind::Stack,
            .pathname = "[stack]",
        },
        std::move(stack32));

    peelf::ThreadContext ctx;
    ctx.tid = 9301;
    ctx.layout = peelf::TargetLayout::from_arch(peelf::Architecture::X86, false, peelf::Endianness::Little);
    ctx.teb_address = kTeb32;
    ctx.stack_pointer = kStack32 + 0x10u;
    ctx.status = peelf::SubsystemStatus::available("test", "ok");

    const auto regs = *sess.memory_regions();
    const peelf::HandlersReport seh_rep =
        peelf::inspect_handlers(nullptr, {}, &sess, regs, {}, &ctx);
    const auto seh_count = std::ranges::count_if(seh_rep.entries, [](const peelf::HandlerEntry& e) {
        return e.category == peelf::HandlerCategory::SehChain32;
    });
    EXPECT_EQ(seh_count, 2);

    // 2. Static ELF init/fini & `.eh_frame` handlers on `hello.elf`.
    const auto elf_bytes = read_file_bytes(fixture_path("hello.elf"));
    auto elf_img = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(elf_img.has_value());
    const peelf::HandlersReport elf_hrep =
        peelf::inspect_handlers(elf_img->get(), elf_bytes, nullptr, {}, {}, nullptr);
    EXPECT_FALSE(elf_hrep.entries.empty());
}

TEST(FunctionsAndStructuredDecompiler, DiscoversFunctionsAndDecompilesStructuredPseudoCWithVaMappings) {
    const auto elf_bytes = read_file_bytes(fixture_path("hello.elf"));
    auto elf_img = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(elf_img.has_value());

    viewer::SymbolIndex sym_idx = viewer::SymbolIndex::build(**elf_img);
    const viewer::FunctionIndex fn_idx = viewer::FunctionIndex::discover(**elf_img, sym_idx, elf_bytes);
    ASSERT_FALSE(fn_idx.empty());

    const viewer::SymbolRecord* main_sym = sym_idx.find_by_name("main");
    ASSERT_NE(main_sym, nullptr);
    ASSERT_TRUE(main_sym->virtual_address.has_value());
    const std::uint64_t main_va = *main_sym->virtual_address;
    EXPECT_NE(fn_idx.find_exact(main_va), nullptr);

    viewer::StructuredPseudoCDecompiler decompiler;
    viewer::DecompileRequest req;
    req.address = main_va;
    req.architecture = (*elf_img)->architecture();
    req.image_bytes = elf_bytes;
    req.function_size = main_sym->size > 0 ? main_sym->size : 64;
    const auto sym_recs = sym_idx.records();
    req.symbols.assign(sym_recs.begin(), sym_recs.end());
    const auto main_off = (*elf_img)->virtual_address_to_file_offset(main_va);
    ASSERT_TRUE(main_off.has_value());
    req.fallback_graph = viewer::build_function_cfg_call_graph(
        elf_bytes,
        main_va,
        (*elf_img)->architecture(),
        (*elf_img)->endianness(),
        *main_off,
        "main",
        false,
        true);

    const viewer::DecompiledUnit unit = decompiler.decompile(req);
    ASSERT_EQ(unit.status, viewer::DecompileStatus::Ready) << unit.diagnostic;
    EXPECT_FALSE(unit.lines.empty());
    const bool has_main_sig = std::ranges::any_of(unit.lines, [](const viewer::DecompiledLine& ln) {
        return ln.text.find("main(") != std::string::npos;
    });
    EXPECT_TRUE(has_main_sig);
    const bool has_mapped_va = std::ranges::any_of(unit.lines, [&](const viewer::DecompiledLine& ln) {
        return ln.address.has_value() && *ln.address >= main_va;
    });
    EXPECT_TRUE(has_mapped_va);
}
