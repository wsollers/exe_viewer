#include <gtest/gtest.h>

#if defined(__linux__)

#include "decompile/structured_decompiler.hpp"
#include "model/binary_model.hpp"

#include <peelf/endian_reader.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/process.hpp>
#include <peelf/stack_tls.hpp>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

thread_local std::uint64_t g_child_tls_canary = 0x1122334455667788ull;

struct ChildSharedAnchors {
    std::uint64_t heap_va{0};
    std::uint64_t tls_va{0};
    std::uint64_t middle_fn_va{0};
    std::uint64_t leaf_fn_va{0};
};

extern "C" void peelf_child_atexit_handler() {}
extern "C" void peelf_child_sigusr1_handler(int /*sig*/) {}

#if defined(__clang__) || defined(__GNUC__)
#define PEELF_NOINLINE_FRAME __attribute__((noinline, optnone))
#else
#define PEELF_NOINLINE_FRAME
#endif

extern "C" PEELF_NOINLINE_FRAME int peelf_child_leaf_wait(int ready_write_fd,
                                                          int hold_read_fd,
                                                          const ChildSharedAnchors* anchors) {
    volatile std::uint64_t local_marker = 0xAABBCCDDEEFF0011ull;
    (void)local_marker;

    const ssize_t wr = ::write(ready_write_fd, anchors, sizeof(*anchors));
    (void)wr;

    char token = 0;
    const ssize_t rd = ::read(hold_read_fd, &token, 1);
    return rd == 1 ? static_cast<int>(token) : 0;
}

extern "C" PEELF_NOINLINE_FRAME int peelf_child_middle_frame(int ready_write_fd,
                                                             int hold_read_fd,
                                                             const ChildSharedAnchors* anchors,
                                                             int factor) {
    if (factor > 10) {
        return peelf_child_leaf_wait(ready_write_fd, hold_read_fd, anchors) + factor;
    }
    return factor - 1;
}

extern "C" PEELF_NOINLINE_FRAME int peelf_child_outer_frame(int ready_write_fd,
                                                            int hold_read_fd,
                                                            const ChildSharedAnchors* anchors) {
    return peelf_child_middle_frame(ready_write_fd, hold_read_fd, anchors, 42);
}

struct ScopedChildReaper {
    pid_t pid{-1};
    int hold_write_fd{-1};

    ~ScopedChildReaper() {
        if (hold_write_fd >= 0) {
            const char done = 'Q';
            (void)::write(hold_write_fd, &done, 1);
            ::close(hold_write_fd);
            hold_write_fd = -1;
        }
        if (pid > 0) {
            int status = 0;
            if (::waitpid(pid, &status, WNOHANG) == 0) {
                (void)::kill(pid, SIGCONT);
                (void)::kill(pid, SIGKILL);
                (void)::waitpid(pid, &status, 0);
            }
            pid = -1;
        }
    }
};

}  // namespace

TEST(LiveChildProcessInspection, AttachesReadOnlyPausesUnwindsStackInspectsTlsSearchesHeapAndDecompiles) {
    int ready_pipe[2]{-1, -1};
    int hold_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(ready_pipe), 0);
    ASSERT_EQ(::pipe(hold_pipe), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);

    if (child == 0) {
        ::close(ready_pipe[0]);
        ::close(hold_pipe[1]);

        (void)std::atexit(&peelf_child_atexit_handler);
        (void)std::signal(SIGUSR1, &peelf_child_sigusr1_handler);

        g_child_tls_canary = 0xCAFEBABE55AA1234ull;

        // Allocate a real heap buffer with known hex, endian-encoded numbers, and UTF-8/UTF-16 text.
        auto heap_blob = std::make_unique<std::array<std::uint8_t, 512>>();
        heap_blob->fill(0);
        const std::array<std::uint8_t, 6> magic_hex{0xFE, 0xED, 0xFA, 0xCE, 0x42, 0x99};
        std::memcpy(heap_blob->data() + 0x10, magic_hex.data(), magic_hex.size());

        const auto le_u32 = peelf::encode_u32(0x778899AAu, peelf::Endianness::Little);
        std::memcpy(heap_blob->data() + 0x40, le_u32.data(), le_u32.size());

        const auto be_u32 = peelf::encode_u32(0x13579BDFu, peelf::Endianness::Big);
        std::memcpy(heap_blob->data() + 0x60, be_u32.data(), be_u32.size());

        const std::string tag_utf8 = "LiveChildHeapNeedle_2026";
        std::memcpy(heap_blob->data() + 0x80, tag_utf8.data(), tag_utf8.size());

        const auto tag_utf16_be = peelf::encode_utf16("ChildUtf16BE", peelf::Endianness::Big);
        std::memcpy(heap_blob->data() + 0x100, tag_utf16_be.data(), tag_utf16_be.size());

        ChildSharedAnchors anchors{
            .heap_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(heap_blob->data())),
            .tls_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&g_child_tls_canary)),
            .middle_fn_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&peelf_child_middle_frame)),
            .leaf_fn_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&peelf_child_leaf_wait)),
        };

        const int rc = peelf_child_outer_frame(ready_pipe[1], hold_pipe[0], &anchors);
        ::close(ready_pipe[1]);
        ::close(hold_pipe[0]);
        std::_Exit(rc & 0x7F);
    }

    ::close(ready_pipe[1]);
    ::close(hold_pipe[0]);
    ScopedChildReaper reaper{.pid = child, .hold_write_fd = hold_pipe[1]};

    ChildSharedAnchors anchors{};
    const ssize_t got = ::read(ready_pipe[0], &anchors, sizeof(anchors));
    ::close(ready_pipe[0]);
    ASSERT_EQ(got, static_cast<ssize_t>(sizeof(anchors)));

    viewer::BinaryModel model;
    auto attach_res = model.attach_process(static_cast<peelf::ProcessId>(child));
    ASSERT_TRUE(attach_res.has_value()) << attach_res.error().message;

    // 1. Strictly read-only live mode + static metadata hydration from executable / cmdline!
    EXPECT_TRUE(model.is_live_process());
    EXPECT_TRUE(model.is_read_only());
    ASSERT_NE(model.image(), nullptr);
    EXPECT_FALSE(model.function_index().entries().empty());
    EXPECT_FALSE(model.header_flags().flags.empty());
    EXPECT_FALSE(model.stage_patch_at_va(anchors.heap_va, std::vector<std::uint8_t>{0x00}, "blocked").has_value());
    EXPECT_FALSE(model.commit_patches_to_process().has_value());

    // 2. Pause child process and inspect threads, registers, stack highlights, and TLS!
    const peelf::SubsystemStatus pause_st = model.suspend_process();
    EXPECT_TRUE(pause_st.is_usable()) << pause_st.detail;
    EXPECT_TRUE(model.is_process_suspended());
    EXPECT_FALSE(model.threads().empty());

    const auto& ctx_fv = model.selected_thread_context();
    if (ctx_fv.status.availability == peelf::Availability::Available && ctx_fv.value.has_value()) {
        EXPECT_NE(ctx_fv.value->instruction_pointer, 0u);
        EXPECT_NE(ctx_fv.value->stack_pointer, 0u);
        EXPECT_FALSE(ctx_fv.value->registers.empty());

        const auto& stack_snap = model.selected_thread_stack();
        EXPECT_TRUE(stack_snap.status.is_usable());
        EXPECT_GE(stack_snap.frames.size(), 2u);
        EXPECT_FALSE(stack_snap.slots.empty());

        const bool saw_return_addr = std::ranges::any_of(
            stack_snap.slots,
            [](const peelf::StackSlotEntry& s) {
                return s.role == peelf::StackSlotRole::ReturnAddress;
            });
        EXPECT_TRUE(saw_return_addr);
    } else {
        // Forgiving abstraction guarantee: even if kernel `ptrace_scope` blocks `PTRACE_GETREGSET`,
        // diagnostic status is populated cleanly without failing attach or crashing!
        EXPECT_FALSE(ctx_fv.status.detail.empty());
    }

    // Verify TLS snapshot is usable (either live TLS variable resolution or graceful static template).
    const auto& tls_snap = model.selected_thread_locals();
    EXPECT_TRUE(tls_snap.status.is_usable() || !tls_snap.status.detail.empty());
    auto raw_tls_bytes = model.read_virtual_bytes(anchors.tls_va, sizeof(std::uint64_t));
    if (raw_tls_bytes.has_value()) {
        peelf::EndianReader tr(*raw_tls_bytes, model.endianness(), model.target_layout().address_width);
        ASSERT_TRUE(tr.read_u64(0).has_value());
        EXPECT_EQ(*tr.read_u64(0), 0xCAFEBABE55AA1234ull);
    }

    // 3. Endian-aware Heap / Memory search for hex, LE/BE numbers, UTF-8, and UTF-16BE!
    {
        auto hex_hit = model.search_memory(peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::AllReadable,
            .kind = peelf::SearchValueKind::HexPattern,
            .query_text = "FE ED ?? CE 42 99",
        });
        ASSERT_TRUE(hex_hit.has_value()) << hex_hit.error().message;
        EXPECT_TRUE(std::ranges::any_of(hex_hit->hits, [&](const peelf::MemorySearchHit& h) {
            return h.address == anchors.heap_va + 0x10u;
        }));

        auto be_hit = model.search_memory(peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::AllReadable,
            .kind = peelf::SearchValueKind::UInt32,
            .query_text = "0x13579BDF",
            .endianness = peelf::Endianness::Big,
            .alignment = 4,
        });
        ASSERT_TRUE(be_hit.has_value()) << be_hit.error().message;
        EXPECT_TRUE(std::ranges::any_of(be_hit->hits, [&](const peelf::MemorySearchHit& h) {
            return h.address == anchors.heap_va + 0x60u;
        }));

        auto utf8_hit = model.search_memory(peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::AllReadable,
            .kind = peelf::SearchValueKind::Utf8Text,
            .query_text = "LiveChildHeapNeedle_2026",
        });
        ASSERT_TRUE(utf8_hit.has_value()) << utf8_hit.error().message;
        EXPECT_TRUE(std::ranges::any_of(utf8_hit->hits, [&](const peelf::MemorySearchHit& h) {
            return h.address == anchors.heap_va + 0x80u;
        }));

        auto utf16_hit = model.search_memory(peelf::MemorySearchQuery{
            .scope = peelf::SearchScope::AllReadable,
            .kind = peelf::SearchValueKind::Utf16Text,
            .query_text = "ChildUtf16BE",
            .endianness = peelf::Endianness::Big,
        });
        ASSERT_TRUE(utf16_hit.has_value()) << utf16_hit.error().message;
        EXPECT_TRUE(std::ranges::any_of(utf16_hit->hits, [&](const peelf::MemorySearchHit& h) {
            return h.address == anchors.heap_va + 0x100u;
        }));
    }

    // 4. Inspect Linux Runtime Environment (`auxv`, `status`, `r_debug`) & Handlers (`SIGUSR1` caught)!
    const auto& proc_env = model.process_environment();
    EXPECT_EQ(proc_env.os_family, peelf::Format::ELF);
    EXPECT_FALSE(proc_env.auxv_entries.empty());

    const auto& hrep = model.handlers_report();
    EXPECT_FALSE(hrep.entries.empty());
    const bool sigusr1_caught = std::ranges::any_of(hrep.signals, [](const peelf::SignalDispositionEntry& s) {
        return s.signal_number == SIGUSR1 && s.caught;
    });
    EXPECT_TRUE(sigusr1_caught);

    // 5. Decompile `peelf_child_middle_frame` at its live ASLR VA via `StructuredPseudoCDecompiler`!
    viewer::StructuredPseudoCDecompiler decompiler;
    viewer::DecompileRequest req;
    req.address = anchors.middle_fn_va;
    req.architecture = model.architecture();
    const auto analysis_span = model.analysis_image_bytes();
    req.image_bytes.assign(analysis_span.begin(), analysis_span.end());
    req.function_size = 96;
    const auto sym_recs = model.symbol_index().records();
    req.symbols.assign(sym_recs.begin(), sym_recs.end());
    if (auto fn_bytes = model.read_virtual_bytes(anchors.middle_fn_va, 256)) {
        req.fallback_graph = viewer::build_function_cfg_call_graph(
            *fn_bytes,
            anchors.middle_fn_va,
            model.architecture(),
            model.endianness(),
            0,
            "peelf_child_middle_frame",
            false,
            true);
    }
    const viewer::DecompiledUnit unit = decompiler.decompile(req);
    ASSERT_EQ(unit.status, viewer::DecompileStatus::Ready) << unit.diagnostic;
    EXPECT_FALSE(unit.lines.empty());
    const bool has_fn_header = std::ranges::any_of(unit.lines, [](const viewer::DecompiledLine& ln) {
        return ln.text.find("peelf_child_middle_frame") != std::string::npos;
    });
    EXPECT_TRUE(has_fn_header);

    // 6. Resume and detach cleanly so child exits normally.
    const peelf::SubsystemStatus resume_st = model.resume_process();
    EXPECT_TRUE(resume_st.is_usable()) << resume_st.detail;
    EXPECT_FALSE(model.is_process_suspended());
    model.detach_process();

    const char done = 'K';
    ASSERT_EQ(::write(reaper.hold_write_fd, &done, 1), 1);
    ::close(reaper.hold_write_fd);
    reaper.hold_write_fd = -1;

    int exit_status = 0;
    ASSERT_EQ(::waitpid(child, &exit_status, 0), child);
    reaper.pid = -1;
    EXPECT_TRUE(WIFEXITED(exit_status));
}

#endif  // defined(__linux__)
