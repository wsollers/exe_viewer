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

TEST(LiveSelfProcess, EnumeratesProcessesAndAttachesToSelfReadOnlyWithStaticMetadataAndSymbols) {
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
    EXPECT_TRUE(model.is_read_only());
    EXPECT_FALSE(model.memory_regions().empty());
    EXPECT_FALSE(model.process_modules().empty());
    ASSERT_NE(model.active_module(), nullptr);
    EXPECT_TRUE(model.active_module()->is_main_module);
    ASSERT_NE(model.image(), nullptr);
    EXPECT_FALSE(model.function_index().entries().empty());
    EXPECT_FALSE(model.header_flags().flags.empty());

    // Verify live symbol resolution on the running test binary matches real ASLR function pointer!
    const auto fn_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&peelf_live_self_target_fn));
    const viewer::SymbolRecord* sym = model.symbol_index().find_by_name("peelf_live_self_target_fn");
    if (sym != nullptr && sym->virtual_address.has_value()) {
        EXPECT_EQ(*sym->virtual_address, fn_va);
    }

    // Read live machine code bytes of `peelf_live_self_target_fn` through BinaryModel and compare!
    auto fn_bytes = model.read_virtual_bytes(fn_va, 16);
    ASSERT_TRUE(fn_bytes.has_value()) << fn_bytes.error().message;
    ASSERT_EQ(fn_bytes->size(), 16u);
    std::array<std::uint8_t, 16> direct_code{};
    std::memcpy(direct_code.data(), reinterpret_cast<const void*>(fn_va), direct_code.size());
    EXPECT_EQ(std::vector<std::uint8_t>(direct_code.begin(), direct_code.end()), *fn_bytes);

    // Verify live memory reads on an in-process buffer AND strict rejection of any live write!
    alignas(64) std::array<std::uint8_t, 32> live_buffer{};
    for (std::size_t i = 0; i < live_buffer.size(); ++i) {
        live_buffer[i] = static_cast<std::uint8_t>(0x30u + i);
    }
    const std::array<std::uint8_t, 32> original_snapshot = live_buffer;
    const auto buf_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(live_buffer.data()));

    ASSERT_TRUE(model.refresh_process_map().has_value());
    const auto buf_off = model.navigate_to_virtual_address(buf_va);
    ASSERT_TRUE(buf_off.has_value());

    auto buf_read = model.read_effective_bytes(*buf_off, live_buffer.size());
    ASSERT_TRUE(buf_read.has_value()) << buf_read.error().message;
    EXPECT_EQ(*buf_read, std::vector<std::uint8_t>(original_snapshot.begin(), original_snapshot.end()));

    // All write / stage / commit APIs must fail in live mode without touching `live_buffer`.
    EXPECT_FALSE(model.stage_patch_at_va(buf_va, std::vector<std::uint8_t>{0xDE, 0xAD}, "blocked").has_value());
    EXPECT_FALSE(model.apply_patch_bytes(*buf_off, std::vector<std::uint8_t>{0xFF}, "blocked").has_value());
    EXPECT_FALSE(model.commit_patches_to_process().has_value());
    EXPECT_EQ(live_buffer, original_snapshot);
}

#if defined(__linux__)
TEST(LiveSelfProcess, ReadsAnonymousReadExecuteRegionAndEnforcesReadOnly) {
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
    std::memset(bytes, 0x90, 16);
    bytes[16] = 0xC3;
    ASSERT_EQ(::mprotect(page, static_cast<std::size_t>(page_sz), PROT_READ | PROT_EXEC), 0);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_process(peelf::current_process_id()).has_value());

    const auto rx_va = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(page));
    ASSERT_TRUE(model.navigate_to_virtual_address(rx_va).has_value());

    auto code = model.read_virtual_bytes(rx_va, 17);
    ASSERT_TRUE(code.has_value()) << code.error().message;
    ASSERT_EQ(code->size(), 17u);
    EXPECT_EQ((*code)[0], 0x90u);
    EXPECT_EQ((*code)[16], 0xC3u);

    EXPECT_FALSE(model.stage_patch_at_va(rx_va, std::vector<std::uint8_t>{0xCC}, "blocked").has_value());
    EXPECT_EQ(reinterpret_cast<const volatile std::uint8_t*>(page)[0], 0x90u);

    ::munmap(page, static_cast<std::size_t>(page_sz));
}
#endif
