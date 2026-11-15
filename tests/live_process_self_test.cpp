#include "peelf/process.hpp"

#include "model/binary_model.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#if defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

extern "C" {

#if defined(_MSC_VER)
__declspec(noinline) int peelf_live_self_target_fn(int x) {
    return (x * 3) + 17;
}
#else
__attribute__((noinline, used, visibility("default"))) int peelf_live_self_target_fn(int x) {
    asm volatile("" : "+r"(x));
    return (x * 3) + 17;
}
#endif

}  // extern "C"

TEST(LiveSelfProcess, EnumeratesProcessesAndAttachesToSelfWithLiveSymbolsAndPatching) {
    // Keep the target symbol live against linker GC.
    ASSERT_EQ(peelf_live_self_target_fn(5), 32);

    auto backend = peelf::create_native_process_backend();
    ASSERT_NE(backend, nullptr);

    const peelf::ProcessId self_pid = peelf::current_process_id();
    ASSERT_GT(self_pid, 0u);

    auto processes = backend->list_processes();
    ASSERT_TRUE(processes.has_value()) << processes.error().message;
    EXPECT_FALSE(processes->empty());
    const auto self_it = std::ranges::find_if(*processes, [self_pid](const peelf::ProcessInfo& p) {
        return p.pid == self_pid;
    });
    ASSERT_NE(self_it, processes->end()) << "current_process_id() must appear in list_processes()";

    viewer::BinaryModel model;
    model.set_process_backend(backend);
    auto attached = model.attach_process(self_pid);
    ASSERT_TRUE(attached.has_value()) << attached.error().message;

    EXPECT_TRUE(model.is_live_process());
    EXPECT_FALSE(model.memory_regions().empty());
    EXPECT_FALSE(model.process_modules().empty());
    ASSERT_NE(model.active_module(), nullptr);
    EXPECT_TRUE(model.active_module()->is_main_module);
    ASSERT_NE(model.image(), nullptr);

    // Verify live symbol resolution on the running test binary matches real ASLR function pointer!
    const auto fn_va = reinterpret_cast<std::uintptr_t>(&peelf_live_self_target_fn);
    const viewer::SymbolRecord* sym = model.symbol_index().find_by_name("peelf_live_self_target_fn");
    if (sym != nullptr && sym->virtual_address.has_value()) {
        EXPECT_EQ(*sym->virtual_address, static_cast<std::uint64_t>(fn_va));
    }

    // Read live machine code bytes of `peelf_live_self_target_fn` through BinaryModel and compare!
    const auto fn_off = model.virtual_address_to_offset(static_cast<std::uint64_t>(fn_va));
    ASSERT_TRUE(fn_off.has_value());
    auto fn_sample = model.read_window_sample(*fn_off, 16);
    ASSERT_TRUE(fn_sample.has_value()) << fn_sample.error().message;
    ASSERT_EQ(fn_sample->readable_count, 16u);
    std::array<std::uint8_t, 16> direct_code{};
    std::memcpy(direct_code.data(), reinterpret_cast<const void*>(fn_va), direct_code.size());
    EXPECT_EQ(std::vector<std::uint8_t>(direct_code.begin(), direct_code.end()), fn_sample->bytes);

    // Stage -> Commit -> Revert a live RAM patch on an in-process buffer!
    alignas(64) std::array<std::uint8_t, 32> live_buffer{};
    for (std::size_t i = 0; i < live_buffer.size(); ++i) {
        live_buffer[i] = static_cast<std::uint8_t>(0x30u + i);
    }
    const std::array<std::uint8_t, 32> original_snapshot = live_buffer;
    const auto buf_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(live_buffer.data()));

    // Refresh map so stack/heap region containing `live_buffer` is guaranteed visible.
    ASSERT_TRUE(model.refresh_process_map().has_value());
    const auto buf_off = model.navigate_to_virtual_address(buf_va);
    ASSERT_TRUE(buf_off.has_value());

    const std::vector<std::uint8_t> staged_bytes{0xCA, 0xFE, 0xBA, 0xBE, 0x42, 0x99};
    ASSERT_TRUE(model.stage_patch_at_va(buf_va + 4, staged_bytes, "live self buffer patch").has_value());

    // 1. While staged, actual live RAM buffer MUST remain unmodified!
    auto snapshot_live_ram = [&live_buffer]() {
        std::array<std::uint8_t, 32> out{};
        const volatile std::uint8_t* vp = live_buffer.data();
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = vp[i];
        }
        return out;
    };
    std::array<std::uint8_t, 32> observed_ram = snapshot_live_ram();
    EXPECT_EQ(observed_ram, original_snapshot);

    // 2. BinaryModel effective read MUST show the staged overlay!
    auto effective_staged = model.read_effective_bytes(*buf_off + 4, staged_bytes.size());
    ASSERT_TRUE(effective_staged.has_value()) << effective_staged.error().message;
    EXPECT_EQ(*effective_staged, staged_bytes);

    // 3. Explicit Commit to RAM mutates the live buffer in process memory!
    auto committed = model.commit_patches_to_process();
    ASSERT_TRUE(committed.has_value()) << committed.error().message;
    EXPECT_EQ(*committed, staged_bytes.size());

    observed_ram = snapshot_live_ram();
    EXPECT_NE(observed_ram, original_snapshot);
    for (std::size_t i = 0; i < staged_bytes.size(); ++i) {
        EXPECT_EQ(observed_ram[4 + i], staged_bytes[i]);
    }

    // 4. Reverting committed patches restores the exact original bytes in live RAM!
    auto reverted = model.revert_committed_patches();
    ASSERT_TRUE(reverted.has_value()) << reverted.error().message;
    EXPECT_EQ(*reverted, staged_bytes.size());

    observed_ram = snapshot_live_ram();
    EXPECT_EQ(observed_ram, original_snapshot);
}

#if defined(__linux__)
TEST(LiveSelfProcess, PatchesAndRevertsReadExecutePageViaProcMemCowFallback) {
    const long page_sz = ::sysconf(_SC_PAGESIZE);
    ASSERT_GT(page_sz, 0);

    void* page = ::mmap(nullptr,
                        static_cast<std::size_t>(page_sz),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);
    ASSERT_NE(page, MAP_FAILED);

    auto* bytes = static_cast<std::uint8_t*>(page);
    // Populate with x86_64/generic NOP sled + RET bytes, then seal as RX (`r-xp`).
    std::memset(bytes, 0x90, 16);
    bytes[16] = 0xC3;
    ASSERT_EQ(::mprotect(page, static_cast<std::size_t>(page_sz), PROT_READ | PROT_EXEC), 0);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_process(peelf::current_process_id()).has_value());

    const auto rx_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(page));
    ASSERT_TRUE(model.navigate_to_virtual_address(rx_va).has_value());

    const std::vector<std::uint8_t> rx_patch{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    ASSERT_TRUE(model.stage_patch_at_va(rx_va, rx_patch, "rx cow patch").has_value());
    EXPECT_EQ(bytes[0], 0x90u);  // Still untouched before commit!

    auto commit_res =
        model.commit_patches_to_process(peelf::MemoryWriteOptions{.allow_protection_override = true});
    if (commit_res.has_value()) {
        for (std::size_t i = 0; i < rx_patch.size(); ++i) {
            EXPECT_EQ(reinterpret_cast<const volatile std::uint8_t*>(page)[i], rx_patch[i]);
        }
        auto rev_res = model.revert_committed_patches();
        ASSERT_TRUE(rev_res.has_value()) << rev_res.error().message;
        EXPECT_EQ(reinterpret_cast<const volatile std::uint8_t*>(page)[0], 0x90u);
    }

    ::munmap(page, static_cast<std::size_t>(page_sz));
}
#endif
