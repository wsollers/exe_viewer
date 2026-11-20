#include "peelf/process.hpp"

#include "model/binary_model.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#if defined(__linux__)
#include <csignal>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

    EXPECT_TRUE(self_it->thread_count.has_value());
    if (self_it->thread_count.has_value()) {
        EXPECT_GE(*self_it->thread_count, 1u);
    }
    EXPECT_TRUE(self_it->working_set_bytes.has_value());
    if (self_it->working_set_bytes.has_value()) {
        EXPECT_GT(*self_it->working_set_bytes, 0u);
    }
    EXPECT_TRUE(self_it->cpu_time_ns.has_value());
    EXPECT_TRUE(self_it->handle_count.has_value());
    if (self_it->handle_count.has_value()) {
        EXPECT_GE(*self_it->handle_count, 3u);
    }
    EXPECT_FALSE(self_it->integrity_level.empty());
#if defined(__linux__)
    EXPECT_TRUE(self_it->integrity_level.starts_with("user") ||
                self_it->integrity_level.starts_with("root"))
        << self_it->integrity_level;
#endif

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

TEST(LiveSelfProcess, RejectsForeignThreadIdAndPreservesPreExistingJobControlStop) {
    int hold_pipe[2]{-1, -1};
    int ready_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(hold_pipe), 0);
    ASSERT_EQ(::pipe(ready_pipe), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::close(hold_pipe[1]);
        ::close(ready_pipe[0]);
#ifdef PR_SET_PTRACER
        (void)::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
        const char r = 'R';
        (void)::write(ready_pipe[1], &r, 1);
        ::close(ready_pipe[1]);

        char ch = 0;
        (void)::read(hold_pipe[0], &ch, 1);
        ::close(hold_pipe[0]);
        ::_exit(0);
    }

    ::close(hold_pipe[0]);
    ::close(ready_pipe[1]);

    struct ScopedHelperChild {
        pid_t pid{-1};
        int hold_fd{-1};

        ScopedHelperChild(pid_t p, int fd) noexcept : pid(p), hold_fd(fd) {}
        ScopedHelperChild(const ScopedHelperChild&) = delete;
        ScopedHelperChild& operator=(const ScopedHelperChild&) = delete;
        ScopedHelperChild(ScopedHelperChild&&) = delete;
        ScopedHelperChild& operator=(ScopedHelperChild&&) = delete;

        ~ScopedHelperChild() {
            if (hold_fd >= 0) {
                ::close(hold_fd);
            }
            if (pid > 0) {
                (void)::kill(pid, SIGCONT);
                (void)::kill(pid, SIGKILL);
                int st = 0;
                (void)::waitpid(pid, &st, 0);
            }
        }
    } guard{child, hold_pipe[1]};

    char ready_ch = 0;
    ASSERT_EQ(::read(ready_pipe[0], &ready_ch, 1), 1);
    ::close(ready_pipe[0]);

    auto backend = peelf::create_native_process_backend();
    auto opened = backend->open_process(static_cast<peelf::ProcessId>(child));
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    peelf::IProcessSession& sess = **opened;

    // Our own thread ID is a real OS TID, but does NOT belong to `child` (`pid_`):
    const auto foreign_tid = static_cast<peelf::ThreadId>(::syscall(SYS_gettid));
    ASSERT_NE(foreign_tid, static_cast<peelf::ThreadId>(child));

    const auto bad_suspend = sess.suspend_thread(foreign_tid);
    ASSERT_FALSE(bad_suspend.has_value());
    EXPECT_NE(bad_suspend.error().message.find("not found in target process"), std::string::npos)
        << bad_suspend.error().message;

    const auto bad_resume = sess.resume_thread(foreign_tid);
    ASSERT_FALSE(bad_resume.has_value());
    EXPECT_NE(bad_resume.error().message.find("not found in target process"), std::string::npos)
        << bad_resume.error().message;

    const peelf::ThreadContext bad_ctx = sess.thread_context(foreign_tid);
    EXPECT_FALSE(bad_ctx.status.ok());

    // Place `child` into job-control stop ('T') BEFORE pause/suspend, then verify
    // suspend() + resume() does NOT send SIGCONT to wake it prematurely.
    ASSERT_EQ(::kill(child, SIGSTOP), 0);
    int stop_st = 0;
    ASSERT_EQ(::waitpid(child, &stop_st, WUNTRACED), child);
    ASSERT_TRUE(WIFSTOPPED(stop_st));

    if (auto sr = sess.suspend(); sr.has_value()) {
        ASSERT_TRUE(sess.resume().has_value());
        int cont_st = 0;
        EXPECT_EQ(::waitpid(child, &cont_st, WNOHANG | WCONTINUED), 0);
    }

    ASSERT_EQ(::kill(child, SIGCONT), 0);
    ::close(guard.hold_fd);
    guard.hold_fd = -1;
    int exit_st = 0;
    ASSERT_EQ(::waitpid(child, &exit_st, 0), child);
    guard.pid = -1;
    EXPECT_TRUE(WIFEXITED(exit_st));
}
#endif
