#include "fuzz_targets.hpp"

#include <peelf/crash_dump.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

namespace peelf::fuzz {

void fuzz_crash_dumps_one_input(std::span<const std::uint8_t> data) noexcept {
    if (data.size() > kMaxFuzzInputBytes) {
        return;
    }

    std::uint64_t acc = 0u;
    acc ^= is_windows_minidump(data) ? 1u : 0u;
    acc ^= is_elf_core_dump(data) ? 2u : 0u;
    acc ^= is_macho_core_dump(data) ? 4u : 0u;
    acc ^= is_crash_dump_bytes(data) ? 8u : 0u;

    std::vector<std::uint8_t> owned(data.begin(), data.end());
    auto opened = open_crash_dump_bytes(std::move(owned), "<fuzz-crash-dump>");
    if (!opened.has_value() || *opened == nullptr) {
        sink_u64(acc);
        return;
    }

    ICrashDumpSession& session = **opened;
    const auto& summary = session.crash_summary();
    acc ^= static_cast<std::uint64_t>(summary.kind);
    acc ^= summary.diagnostics.size();
    acc ^=
        summary.module_count ^ summary.thread_count ^ summary.region_count ^ summary.handle_count;
    if (summary.exception.has_value()) {
        acc ^= summary.exception->instruction_pointer.value_or(0u);
        acc ^= summary.exception->fault_address.value_or(0u);
    }

    const auto& internals = session.crash_internals();
    acc ^= internals.handles.value ? internals.handles.value->size() : 0u;
    acc ^= internals.sockets.value ? internals.sockets.value->size() : 0u;

    const auto inspected = inspect_process_internals(session);
    acc ^= inspected.handles.value ? inspected.handles.value->size() : 0u;

    std::array<std::uint8_t, 64> scratch{};
    if (const auto regions = session.memory_regions(); regions.has_value()) {
        acc ^= regions->size();
        const auto mem_sum = session.memory_summary(*regions);
        if (mem_sum.value.has_value()) {
            acc ^= mem_sum.value->total_virtual_bytes ^ mem_sum.value->committed_bytes;
        }

        const std::size_t max_regions = std::min<std::size_t>(regions->size(), 16u);
        for (std::size_t i = 0u; i < max_regions; ++i) {
            const auto& reg = (*regions)[i];
            acc ^= reg.start_address ^ reg.end_address;
            if (const auto rd = session.read_memory(reg.start_address, scratch); rd.has_value()) {
                acc ^= *rd;
            }
            if (reg.size() > 16u) {
                const std::uint64_t tail_addr = reg.end_address - 16u;
                (void)session.read_memory(tail_addr, scratch);
            }
        }

        if (summary.exception.has_value() && summary.exception->instruction_pointer.has_value()) {
            const auto sample = read_memory_tolerant(session, *regions,
                                                     *summary.exception->instruction_pointer, 64u);
            acc ^= sample.bytes.size();
        }
    }

    if (const auto mods = session.modules(); mods.has_value()) {
        acc ^= mods->size();
        if (!mods->empty()) {
            acc ^= mods->front().base_address ^ mods->front().name.size();
        }
    }

    if (const auto thds = session.threads(); thds.has_value()) {
        acc ^= thds->size();
        const std::size_t max_threads = std::min<std::size_t>(thds->size(), 8u);
        for (std::size_t i = 0u; i < max_threads; ++i) {
            const auto ctx = session.thread_context((*thds)[i].tid);
            acc ^= ctx.registers.size();
        }
    }

    if (const auto auxv = session.proc_auxv(); auxv.value.has_value()) {
        acc ^= auxv.value->size();
    }
    if (const auto status_txt = session.proc_status_text(); status_txt.value.has_value()) {
        acc ^= status_txt.value->size();
    }
    if (const auto env = session.environment_variables(); env.value.has_value()) {
        acc ^= env.value->size();
    }
    if (const auto peb = session.process_environment_block_address(); peb.value.has_value()) {
        acc ^= *peb.value;
    }

    // Boundary out-of-range / wraparound read probes.
    (void)session.read_memory(0u, scratch);
    (void)session.read_memory(std::numeric_limits<std::uint64_t>::max() - 31u, scratch);

    sink_u64(acc);
}

} // namespace peelf::fuzz

#ifdef PEELF_LIBFUZZER_HARNESS
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > peelf::fuzz::kMaxFuzzInputBytes) {
        return 0;
    }
    const std::span<const std::uint8_t> bytes = (data != nullptr)
                                                    ? std::span<const std::uint8_t>(data, size)
                                                    : std::span<const std::uint8_t>{};
    peelf::fuzz::fuzz_crash_dumps_one_input(bytes);
    return 0;
}
#endif
