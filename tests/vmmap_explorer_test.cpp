#include <gtest/gtest.h>

#include <peelf/process.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

TEST(VmMapExplorerTest, SmapsParserExtractsRssPssDirtySwapLockedVmFlagsAndSpecialOwners) {
    constexpr std::string_view kSmaps = R"(555555554000-555555558000 r-xp 00000000 08:01 1001   /usr/bin/target_app
Size:                 16 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  12 kB
Pss:                   6 kB
Shared_Clean:          8 kB
Shared_Dirty:          0 kB
Private_Clean:         4 kB
Private_Dirty:         0 kB
Swap:                  0 kB
Locked:                4 kB
VmFlags: rd ex mr mw me dw sd
555555760000-555555780000 rw-p 00000000 00:00 0      [heap]
Size:                128 kB
Rss:                  64 kB
Pss:                  64 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        64 kB
Swap:                 16 kB
Locked:                0 kB
VmFlags: rd wr mr mw me ac sd
7fff00000000-7fff00001000 ---p 00000000 00:00 0
Size:                  4 kB
Rss:                   0 kB
Pss:                   0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: mr mw me
7fff00001000-7fff00801000 rw-p 00000000 00:00 0      [stack:4242]
Size:               8192 kB
Rss:                  32 kB
Pss:                  32 kB
Private_Clean:         0 kB
Private_Dirty:        32 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: rd wr mr mw me ac sd
7fff10000000-7fff10004000 rwxp 00000000 00:00 0
Size:                 16 kB
Rss:                  16 kB
Pss:                  16 kB
Private_Clean:         0 kB
Private_Dirty:        16 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: rd wr ex mr mw me ac
7fffffffe000-800000000000 r-xp 00000000 00:00 0      [vdso]
Size:                  8 kB
Rss:                   8 kB
Pss:                   2 kB
Shared_Clean:          8 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: rd ex mr mw me de sd
)";

    auto parsed = peelf::parse_proc_smaps(kSmaps, "/usr/bin/target_app");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), 6u);

    const auto& regs = *parsed;
    EXPECT_EQ(regs[0].kind, peelf::MemoryRegionKind::Image);
    EXPECT_EQ(regs[0].size(), 16ull * 1024ull);
    EXPECT_EQ(regs[0].usage.rss_bytes, 12ull * 1024ull);
    EXPECT_EQ(regs[0].usage.pss_bytes, 6ull * 1024ull);
    EXPECT_EQ(regs[0].usage.shared_clean_bytes, 8ull * 1024ull);
    EXPECT_EQ(regs[0].usage.private_clean_bytes, 4ull * 1024ull);
    EXPECT_EQ(regs[0].usage.locked_bytes, 4ull * 1024ull);
    EXPECT_EQ(regs[0].usage.vm_flags, "rd ex mr mw me dw sd");

    EXPECT_EQ(regs[1].kind, peelf::MemoryRegionKind::Heap);
    EXPECT_EQ(regs[1].usage.heap_id, 0u);
    EXPECT_EQ(regs[1].usage.private_dirty_bytes, 64ull * 1024ull);
    EXPECT_EQ(regs[1].usage.swap_bytes, 16ull * 1024ull);

    // PROT_NONE guard/reservation page
    EXPECT_TRUE(regs[2].usage.is_reserved_only);
    EXPECT_EQ(regs[2].usage.committed_bytes, 0u);

    // Explicit [stack:4242] mapping
    EXPECT_EQ(regs[3].kind, peelf::MemoryRegionKind::Stack);
    EXPECT_EQ(regs[3].usage.owner_tid, 4242u);

    // Summary aggregation
    const peelf::ProcessMemorySummary sum = peelf::summarize_process_memory(regs);
    EXPECT_EQ(sum.total_virtual_bytes, (16ull + 128 + 4 + 8192 + 16 + 8) * 1024ull);
    EXPECT_EQ(sum.reserved_only_bytes, 4ull * 1024ull);
    EXPECT_EQ(sum.committed_bytes, (16ull + 128 + 8192 + 16 + 8) * 1024ull);
    EXPECT_EQ(sum.rss_bytes, (12ull + 64 + 0 + 32 + 16 + 8) * 1024ull);
    EXPECT_EQ(sum.pss_bytes, (6ull + 64 + 0 + 32 + 16 + 2) * 1024ull);
    EXPECT_EQ(sum.private_dirty_bytes, (64ull + 32 + 16) * 1024ull);
    EXPECT_EQ(sum.private_clean_bytes, 4ull * 1024ull);
    EXPECT_EQ(sum.shared_clean_bytes, (8ull + 8) * 1024ull);
    EXPECT_EQ(sum.swap_bytes, 16ull * 1024ull);
    EXPECT_EQ(sum.locked_bytes, 4ull * 1024ull);
    EXPECT_EQ(sum.rwx_region_count, 1u);
    EXPECT_EQ(sum.rwx_bytes, 16ull * 1024ull);
    EXPECT_EQ(sum.image_bytes, 16ull * 1024ull);
    EXPECT_EQ(sum.heap_bytes, 128ull * 1024ull);
    EXPECT_EQ(sum.stack_bytes, 8192ull * 1024ull);
    EXPECT_EQ(sum.anonymous_bytes, 16ull * 1024ull);
    EXPECT_EQ(sum.vdso_bytes, 8ull * 1024ull);
}

TEST(VmMapExplorerTest, ThreadStackAttributionAndSmapsRollupFallback) {
    constexpr std::string_view kMapsOnly = R"(7f0000000000-7f0000001000 ---p 00000000 00:00 0
7f0000001000-7f0000801000 rw-p 00000000 00:00 0
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0   [stack]
)";

    auto parsed = peelf::parse_proc_maps(kMapsOnly);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 3u);

    std::vector<peelf::ThreadInfo> threads{
        peelf::ThreadInfo{.tid = 1000, .stack_pointer = 0x7fffffffe400ull},
        peelf::ThreadInfo{.tid = 1007, .stack_pointer = 0x7f00007ff200ull},
    };
    peelf::attribute_thread_stacks(*parsed, threads, 1000u);

    // Guard page preceding worker stack gets attributed to TID 1007 while staying reserved.
    EXPECT_TRUE((*parsed)[0].usage.is_reserved_only);
    EXPECT_EQ((*parsed)[0].usage.owner_tid, 1007u);

    // Anonymous rw-p containing worker SP becomes Stack owned by TID 1007.
    EXPECT_EQ((*parsed)[1].kind, peelf::MemoryRegionKind::Stack);
    EXPECT_EQ((*parsed)[1].usage.owner_tid, 1007u);

    // Main [stack] becomes owned by main TID 1000.
    EXPECT_EQ((*parsed)[2].kind, peelf::MemoryRegionKind::Stack);
    EXPECT_EQ((*parsed)[2].usage.owner_tid, 1000u);

    // Without smaps, RSS/PSS are nullopt until smaps_rollup enriches them.
    const peelf::ProcessMemorySummary raw_sum = peelf::summarize_process_memory(*parsed);
    EXPECT_FALSE(raw_sum.rss_bytes.has_value());

    constexpr std::string_view kRollup = R"(555555554000-7ffffffff000 ---p 00000000 00:00 0  [rollup]
Rss:                 512 kB
Pss:                 384 kB
Private_Dirty:       256 kB
Swap:                  8 kB
)";
    const peelf::ProcessMemorySummary rollup_sum =
        peelf::summarize_process_memory(*parsed, kRollup);
    EXPECT_EQ(rollup_sum.rss_bytes, 512ull * 1024ull);
    EXPECT_EQ(rollup_sum.pss_bytes, 384ull * 1024ull);
    EXPECT_EQ(rollup_sum.private_dirty_bytes, 256ull * 1024ull);
    EXPECT_EQ(rollup_sum.swap_bytes, 8ull * 1024ull);
}

TEST(VmMapExplorerTest, AddressSpaceClustersCollapseCanonicalHoles) {
    std::vector<peelf::MemoryRegion> regs{
        peelf::MemoryRegion{.start_address = 0x0000555555554000ull, .end_address = 0x0000555555560000ull},
        peelf::MemoryRegion{.start_address = 0x0000555555760000ull, .end_address = 0x0000555555790000ull},
        peelf::MemoryRegion{.start_address = 0x00007ffff7c00000ull, .end_address = 0x00007ffff7e00000ull},
        peelf::MemoryRegion{.start_address = 0x00007ffffffde000ull, .end_address = 0x00007ffffffff000ull},
    };

    const auto clusters = peelf::build_address_space_clusters(regs, 64ull * 1024ull * 1024ull);
    ASSERT_EQ(clusters.size(), 3u);

    EXPECT_EQ(clusters[0].region_indices.size(), 2u);
    EXPECT_EQ(clusters[0].start_address, 0x0000555555554000ull);
    EXPECT_EQ(clusters[0].end_address, 0x0000555555790000ull);

    EXPECT_EQ(clusters[1].region_indices.size(), 1u);
    EXPECT_EQ(clusters[1].preceding_gap_bytes, 0x00007ffff7c00000ull - 0x0000555555790000ull);

    EXPECT_EQ(clusters[2].region_indices.size(), 1u);
    EXPECT_EQ(clusters[2].preceding_gap_bytes, 0x00007ffffffde000ull - 0x00007ffff7e00000ull);
}

#ifdef __linux__
TEST(VmMapExplorerTest, LiveSelfSmapsAndWorkerStackAttribution) {
    std::mutex mu;
    std::condition_variable cv;
    bool ready = false;
    bool finish = false;
    peelf::ThreadId worker_tid = 0;
    volatile std::uint64_t stack_anchor = 0;

    struct ScopedWorkerGuard {
        std::mutex& mu;
        std::condition_variable& cv;
        bool& finish;
        std::jthread worker;

        ScopedWorkerGuard(std::mutex& m, std::condition_variable& c, bool& f, std::jthread w) noexcept
            : mu(m), cv(c), finish(f), worker(std::move(w)) {}
        ScopedWorkerGuard(const ScopedWorkerGuard&) = delete;
        ScopedWorkerGuard& operator=(const ScopedWorkerGuard&) = delete;
        ScopedWorkerGuard(ScopedWorkerGuard&&) = delete;
        ScopedWorkerGuard& operator=(ScopedWorkerGuard&&) = delete;

        ~ScopedWorkerGuard() noexcept {
            if (worker.joinable()) {
                {
                    std::lock_guard<std::mutex> lk(mu);
                    finish = true;
                }
                cv.notify_all();
                worker.join();
            }
        }
    };

    ScopedWorkerGuard worker_guard(mu, cv, finish, std::jthread([&]() {
        volatile std::uint64_t local_var = 0xDEADBEEFCAFEBABEull;
        stack_anchor = reinterpret_cast<std::uint64_t>(const_cast<std::uint64_t*>(&local_var));
        const long tid = ::syscall(SYS_gettid);
        {
            std::lock_guard<std::mutex> lk(mu);
            worker_tid = tid > 0 ? static_cast<peelf::ThreadId>(tid) : 0u;
            ready = true;
        }
        cv.notify_all();
        std::unique_lock<std::mutex> lk(mu);
        cv.wait_for(lk, std::chrono::seconds(5), [&]() { return finish; });
    }));

    {
        std::unique_lock<std::mutex> lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(5), [&]() { return ready; }));
    }

    auto backend = peelf::create_native_process_backend();
    ASSERT_NE(backend, nullptr);
    auto sess_res = backend->open_process(peelf::current_process_id());
    ASSERT_TRUE(sess_res.has_value()) << sess_res.error().message;
    auto& sess = **sess_res;

    auto regs_res = sess.memory_regions();
    ASSERT_TRUE(regs_res.has_value()) << regs_res.error().message;
    EXPECT_FALSE(regs_res->empty());

    auto sum_fv = sess.memory_summary(*regs_res);
    ASSERT_TRUE(sum_fv.value.has_value());
    EXPECT_GT(sum_fv.value->total_virtual_bytes, 0u);
    EXPECT_GT(sum_fv.value->committed_bytes, 0u);
    EXPECT_TRUE(sum_fv.value->rss_bytes.has_value());
    EXPECT_GT(sum_fv.value->rss_bytes.value_or(0), 0u);
    EXPECT_GT(sum_fv.value->image_bytes, 0u);

    // Find the VMA containing the worker thread's stack variable.
    bool found_worker_vma = false;
    const std::uint64_t target_sp = stack_anchor;
    for (const auto& r : *regs_res) {
        if (r.contains(target_sp)) {
            found_worker_vma = true;
            if (r.usage.owner_tid.has_value() && worker_tid != 0) {
                EXPECT_EQ(*r.usage.owner_tid, worker_tid);
                EXPECT_EQ(r.kind, peelf::MemoryRegionKind::Stack);
            }
            break;
        }
    }
    EXPECT_TRUE(found_worker_vma);
}
#endif

} // namespace
