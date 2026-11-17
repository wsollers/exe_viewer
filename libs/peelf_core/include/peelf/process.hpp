#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

using ProcessId = std::uint32_t;

enum class ProcessAccessStatus : std::uint8_t {
    Accessible,
    ReadOnly,
    AccessDenied,
    Exited,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(ProcessAccessStatus status) noexcept {
    switch (status) {
        case ProcessAccessStatus::Accessible:   return "Accessible";
        case ProcessAccessStatus::ReadOnly:     return "ReadOnly";
        case ProcessAccessStatus::AccessDenied: return "AccessDenied";
        case ProcessAccessStatus::Exited:       return "Exited";
        case ProcessAccessStatus::Unknown:      return "Unknown";
    }
    return "Unknown";
}

struct ProcessInfo {
    ProcessId pid{0};
    ProcessId parent_pid{0};
    std::string name{};
    std::filesystem::path executable_path{};
    std::string command_line{};
    std::filesystem::path working_directory{};
    std::string user{};
    std::optional<std::uint32_t> uid{};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Little};
    bool is_64bit{true};
    ProcessAccessStatus access{ProcessAccessStatus::Unknown};

    auto operator<=>(const ProcessInfo&) const = default;
};

using ThreadId = std::uint32_t;

enum class ThreadRunState : std::uint8_t {
    Running,
    Sleeping,
    Stopped,
    Waiting,
    Zombie,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(ThreadRunState state) noexcept {
    switch (state) {
        case ThreadRunState::Running:  return "Running";
        case ThreadRunState::Sleeping: return "Sleeping";
        case ThreadRunState::Stopped:  return "Stopped";
        case ThreadRunState::Waiting:  return "Waiting";
        case ThreadRunState::Zombie:   return "Zombie";
        case ThreadRunState::Unknown:  return "Unknown";
    }
    return "Unknown";
}

struct ThreadInfo {
    ThreadId tid{0};
    std::string name{};
    ThreadRunState state{ThreadRunState::Unknown};
    bool is_suspended{false};
    std::optional<std::uint64_t> instruction_pointer{};
    std::optional<std::uint64_t> stack_pointer{};
    std::optional<std::uint64_t> start_address{};
    std::optional<std::uint64_t> tls_base{};
    std::optional<std::uint64_t> teb_address{};
    std::optional<std::int64_t> syscall_number{};
    std::string wait_channel{};
    std::optional<std::uint64_t> user_time_ns{};
    std::optional<std::uint64_t> kernel_time_ns{};
    std::optional<double> cpu_percent{};
    SubsystemStatus status{};
};

enum class RegisterCategory : std::uint8_t {
    General,
    InstructionPointer,
    StackPointer,
    FramePointer,
    Flags,
    SegmentOrTls,
    FloatingPoint,
    Vector,
    System,
};

[[nodiscard]] constexpr std::string_view to_string(RegisterCategory cat) noexcept {
    switch (cat) {
        case RegisterCategory::General:            return "GPR";
        case RegisterCategory::InstructionPointer: return "IP/PC";
        case RegisterCategory::StackPointer:       return "SP";
        case RegisterCategory::FramePointer:       return "FP/BP";
        case RegisterCategory::Flags:              return "Flags";
        case RegisterCategory::SegmentOrTls:       return "Seg/TLS";
        case RegisterCategory::FloatingPoint:      return "FPU";
        case RegisterCategory::Vector:             return "SIMD";
        case RegisterCategory::System:             return "System";
    }
    return "GPR";
}

struct FlagBitInfo {
    std::string name;
    std::uint8_t bit{0};
    bool set{false};
    std::string description;
};

struct RegisterValue {
    std::string name;
    RegisterCategory category{RegisterCategory::General};
    std::uint16_t bit_width{64};
    std::uint64_t value_u64{0};
    std::vector<std::uint8_t> raw_bytes;
    std::string formatted;
};

struct ThreadContext {
    ThreadId tid{0};
    TargetLayout layout{};
    std::uint64_t instruction_pointer{0};
    std::uint64_t stack_pointer{0};
    std::uint64_t frame_pointer{0};
    std::optional<std::uint64_t> link_register;
    std::optional<std::uint64_t> tls_pointer;
    std::optional<std::uint64_t> teb_address;
    std::optional<std::uint64_t> flags_value;
    std::vector<FlagBitInfo> decoded_flags;
    std::vector<RegisterValue> registers;
    SubsystemStatus status{};
};

struct MemoryProtection {
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool shared{false};
    bool guarded{false};

    [[nodiscard]] std::string to_short_string() const {
        std::string out(4, '-');
        if (readable) {
            out[0] = 'r';
        }
        if (writable) {
            out[1] = 'w';
        }
        if (executable) {
            out[2] = 'x';
        }
        out[3] = shared ? 's' : 'p';
        if (guarded) {
            out += "+g";
        }
        return out;
    }

    auto operator<=>(const MemoryProtection&) const = default;
};

[[nodiscard]] inline std::string format_protection(const MemoryProtection& protection) {
    return protection.to_short_string();
}

enum class MemoryRegionKind : std::uint8_t {
    Image,
    Heap,
    Stack,
    Vdso,
    MappedFile,
    Anonymous,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryRegionKind kind) noexcept {
    switch (kind) {
        case MemoryRegionKind::Image:      return "Image";
        case MemoryRegionKind::Heap:       return "Heap";
        case MemoryRegionKind::Stack:      return "Stack";
        case MemoryRegionKind::Vdso:       return "vDSO/Kernel";
        case MemoryRegionKind::MappedFile: return "Mapped File";
        case MemoryRegionKind::Anonymous:  return "Anonymous";
        case MemoryRegionKind::Unknown:    return "Unknown";
    }
    return "Unknown";
}

struct MemoryRegionUsage {
    std::optional<std::uint64_t> committed_bytes{};
    std::optional<std::uint64_t> rss_bytes{};  ///< Resident Set Size (Linux) / Working Set (Win32)
    std::optional<std::uint64_t> pss_bytes{};  ///< Proportional Set Size (Linux smaps)
    std::optional<std::uint64_t> private_clean_bytes{};
    std::optional<std::uint64_t> private_dirty_bytes{};
    std::optional<std::uint64_t> shared_clean_bytes{};
    std::optional<std::uint64_t> shared_dirty_bytes{};
    std::optional<std::uint64_t> swap_bytes{};
    std::optional<std::uint64_t> locked_bytes{};
    std::optional<std::uint64_t> allocation_base{};
    bool is_reserved_only{false};
    std::optional<ThreadId> owner_tid{};
    std::optional<std::uint32_t> heap_id{};
    std::string vm_flags{};

    [[nodiscard]] constexpr std::optional<std::uint64_t> working_set_bytes() const noexcept {
        return rss_bytes;
    }

    [[nodiscard]] constexpr std::optional<std::uint64_t> private_bytes() const noexcept {
        if (!private_clean_bytes.has_value() && !private_dirty_bytes.has_value()) {
            return std::nullopt;
        }
        return private_clean_bytes.value_or(0) + private_dirty_bytes.value_or(0);
    }

    [[nodiscard]] constexpr std::optional<std::uint64_t> shared_bytes() const noexcept {
        if (!shared_clean_bytes.has_value() && !shared_dirty_bytes.has_value()) {
            return std::nullopt;
        }
        return shared_clean_bytes.value_or(0) + shared_dirty_bytes.value_or(0);
    }

    auto operator<=>(const MemoryRegionUsage&) const = default;
};

struct MemoryRegion {
    std::uint64_t start_address{0};
    std::uint64_t end_address{0};
    MemoryProtection protection{};
    MemoryRegionKind kind{MemoryRegionKind::Anonymous};
    std::uint64_t file_offset{0};
    std::string pathname{};
    std::string module_name{};
    MemoryRegionUsage usage{};

    [[nodiscard]] constexpr std::uint64_t size() const noexcept {
        return end_address >= start_address ? (end_address - start_address) : 0;
    }

    [[nodiscard]] constexpr bool contains(std::uint64_t address) const noexcept {
        return end_address > start_address && address >= start_address &&
               (address - start_address) < (end_address - start_address);
    }

    auto operator<=>(const MemoryRegion&) const = default;
};

struct ProcessMemorySummary {
    // Overall virtual & physical KPIs
    std::uint64_t total_virtual_bytes{0};
    std::uint64_t committed_bytes{0};
    std::uint64_t reserved_only_bytes{0};
    std::optional<std::uint64_t> rss_bytes{};
    std::optional<std::uint64_t> pss_bytes{};
    std::optional<std::uint64_t> private_clean_bytes{};
    std::optional<std::uint64_t> private_dirty_bytes{};
    std::optional<std::uint64_t> shared_clean_bytes{};
    std::optional<std::uint64_t> shared_dirty_bytes{};
    std::optional<std::uint64_t> swap_bytes{};
    std::optional<std::uint64_t> locked_bytes{};

    // Category / Type breakdown (virtual bytes)
    std::uint64_t image_bytes{0};
    std::uint64_t heap_bytes{0};
    std::uint64_t stack_bytes{0};
    std::uint64_t mapped_file_bytes{0};
    std::uint64_t anonymous_bytes{0};
    std::uint64_t vdso_bytes{0};
    std::uint64_t reserved_bytes{0};

    // Protection breakdown (virtual bytes)
    std::uint64_t rx_bytes{0};
    std::uint64_t readonly_bytes{0};
    std::uint64_t rw_bytes{0};
    std::uint64_t rwx_bytes{0};
    std::uint64_t noaccess_or_guard_bytes{0};
    std::size_t rwx_region_count{0};

    [[nodiscard]] constexpr std::optional<std::uint64_t> shared_bytes() const noexcept {
        if (!shared_clean_bytes.has_value() && !shared_dirty_bytes.has_value()) {
            return std::nullopt;
        }
        return shared_clean_bytes.value_or(0) + shared_dirty_bytes.value_or(0);
    }

    [[nodiscard]] constexpr std::uint64_t unresident_committed_bytes() const noexcept {
        const std::uint64_t res = rss_bytes.value_or(0);
        return committed_bytes > res ? (committed_bytes - res) : 0;
    }

    auto operator<=>(const ProcessMemorySummary&) const = default;
};

/// Contiguous or near-contiguous cluster of virtual memory mappings separated by collapsed
/// multi-MiB / multi-TiB canonical address-space holes for the VMMap visual VA strip.
struct AddressSpaceCluster {
    std::uint64_t start_address{0};
    std::uint64_t end_address{0};
    std::uint64_t preceding_gap_bytes{0};
    std::vector<std::size_t> region_indices{};

    [[nodiscard]] constexpr std::uint64_t span_bytes() const noexcept {
        return end_address >= start_address ? (end_address - start_address) : 0;
    }
};

struct ModuleInfo {
    std::string name{};
    std::filesystem::path path{};
    std::uint64_t base_address{0};
    std::uint64_t size{0};
    std::uint64_t entry_point{0};
    Format format{Format::Unknown};
    bool is_main_module{false};

    [[nodiscard]] constexpr std::uint64_t end_address() const noexcept {
        return size <= (std::numeric_limits<std::uint64_t>::max() - base_address)
                   ? (base_address + size)
                   : std::numeric_limits<std::uint64_t>::max();
    }

    [[nodiscard]] constexpr bool contains(std::uint64_t address) const noexcept {
        return size > 0 && address >= base_address && (address - base_address) < size;
    }

    auto operator<=>(const ModuleInfo&) const = default;
};

struct MemoryWriteOptions {
    bool allow_protection_override{true};
};

struct MemorySample {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> valid;
    std::size_t readable_count{0};
};

class IProcessSession {
public:
    virtual ~IProcessSession() = default;

    [[nodiscard]] virtual const ProcessInfo& info() const noexcept = 0;
    [[nodiscard]] ProcessId pid() const noexcept { return info().pid; }
    [[nodiscard]] virtual bool is_alive() const noexcept = 0;
    [[nodiscard]] virtual bool is_read_only() const noexcept { return true; }
    [[nodiscard]] virtual bool is_crash_dump() const noexcept { return false; }
    [[nodiscard]] virtual TargetLayout target_layout() const noexcept {
        return TargetLayout::from_arch(info().architecture, info().is_64bit, info().endianness);
    }

    [[nodiscard]] virtual Result<std::vector<MemoryRegion>> memory_regions() = 0;
    [[nodiscard]] virtual Result<std::vector<ModuleInfo>> modules() = 0;
    [[nodiscard]] virtual Result<std::size_t> read_memory(std::uint64_t address,
                                                          std::span<std::uint8_t> buffer) = 0;

    [[nodiscard]] virtual SubsystemStatus memory_regions_status() const {
        return SubsystemStatus::available("session");
    }
    [[nodiscard]] virtual SubsystemStatus modules_status() const {
        return SubsystemStatus::available("session");
    }
    [[nodiscard]] virtual SubsystemStatus threads_status() const {
        return SubsystemStatus::available("session");
    }

    /// Live process inspection is strictly read-only (`is_read_only() == true`).
    /// Retained only as a retired error-returning stub so existing `LiveMemoryPatchSpace`
    /// error-handling contracts and fake test doubles fail closed without modifying target RAM.
    [[nodiscard]] virtual Result<std::size_t> write_memory(std::uint64_t /*address*/,
                                                           std::span<const std::uint8_t> /*data*/,
                                                           MemoryWriteOptions /*options*/ = {}) {
        return make_error("live process inspection is strictly read-only; target memory is never modified");
    }

    [[nodiscard]] virtual Result<void> suspend() {
        return make_error("process suspend is not supported by this session");
    }
    [[nodiscard]] virtual Result<void> resume() {
        return make_error("process resume is not supported by this session");
    }
    [[nodiscard]] virtual bool is_suspended() const noexcept { return false; }

    [[nodiscard]] virtual Result<std::vector<ThreadInfo>> threads() {
        return std::vector<ThreadInfo>{};
    }
    [[nodiscard]] virtual Result<void> suspend_thread(ThreadId /*tid*/) {
        return make_error("thread suspend is not supported by this session");
    }
    [[nodiscard]] virtual Result<void> resume_thread(ThreadId /*tid*/) {
        return make_error("thread resume is not supported by this session");
    }
    [[nodiscard]] virtual ThreadContext thread_context(ThreadId tid) {
        ThreadContext ctx;
        ctx.tid = tid;
        ctx.layout = target_layout();
        ctx.status = SubsystemStatus::unavailable("session", "thread context is not supported");
        return ctx;
    }

    [[nodiscard]] virtual ForgivingValue<std::vector<std::uint8_t>> proc_auxv() {
        return {std::nullopt, SubsystemStatus::unavailable("procfs", "auxv not available")};
    }
    [[nodiscard]] virtual ForgivingValue<std::string> proc_status_text() {
        return {std::nullopt, SubsystemStatus::unavailable("procfs", "proc status not available")};
    }
    [[nodiscard]] virtual ForgivingValue<std::vector<std::string>> environment_variables() {
        return {std::nullopt, SubsystemStatus::unavailable("os", "environment not available")};
    }
    [[nodiscard]] virtual ForgivingValue<std::uint64_t> process_environment_block_address() {
        return {std::nullopt, SubsystemStatus::unavailable("os", "PEB address not available")};
    }

    /// Aggregate VMMap-style virtual/physical memory telemetry across `regions` (or freshly
    /// queried `memory_regions()` when `regions` is empty).
    [[nodiscard]] virtual ForgivingValue<ProcessMemorySummary> memory_summary(
        std::span<const MemoryRegion> regions = {});
};

/// RAII helper that pauses a running process session on construction (unless already paused)
/// and automatically resumes it when leaving scope so an inspected process is never left frozen.
class ScopedProcessPause {
public:
    explicit ScopedProcessPause(IProcessSession& session) : session_(&session) {
        if (!session_->is_suspended()) {
            auto res = session_->suspend();
            if (res) {
                owns_pause_ = true;
            } else {
                error_ = res.error();
            }
        }
    }

    ScopedProcessPause(const ScopedProcessPause&) = delete;
    ScopedProcessPause& operator=(const ScopedProcessPause&) = delete;

    ScopedProcessPause(ScopedProcessPause&& other) noexcept
        : session_(other.session_),
          owns_pause_(other.owns_pause_),
          error_(std::move(other.error_)) {
        other.session_ = nullptr;
        other.owns_pause_ = false;
    }

    ScopedProcessPause& operator=(ScopedProcessPause&& other) noexcept {
        if (this != &other) {
            release();
            session_ = other.session_;
            owns_pause_ = other.owns_pause_;
            error_ = std::move(other.error_);
            other.session_ = nullptr;
            other.owns_pause_ = false;
        }
        return *this;
    }

    ~ScopedProcessPause() noexcept { release(); }

    [[nodiscard]] bool paused_by_guard() const noexcept { return owns_pause_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }

    void release() noexcept {
        if (session_ != nullptr && owns_pause_) {
            owns_pause_ = false;
            try {
                (void)session_->resume();
            } catch (...) {
            }
        }
    }

private:
    IProcessSession* session_{nullptr};
    bool owns_pause_{false};
    std::optional<Error> error_;
};

class IProcessBackend {
public:
    virtual ~IProcessBackend() = default;

    [[nodiscard]] virtual Result<std::vector<ProcessInfo>> list_processes() = 0;
    [[nodiscard]] virtual Result<std::unique_ptr<IProcessSession>> open_process(ProcessId pid) = 0;
};

[[nodiscard]] std::shared_ptr<IProcessBackend> create_native_process_backend();
[[nodiscard]] ProcessId current_process_id() noexcept;

[[nodiscard]] std::string strip_deleted_proc_suffix(std::string_view pathname);

/// Split a command line (`argv` string or NUL-delimited `/proc/<pid>/cmdline`) into tokens,
/// honoring Windows (`"..."`) or POSIX quoting/escaping rules.
[[nodiscard]] std::vector<std::string> split_command_line_args(
    std::string_view command_line,
    bool windows_rules = false);

/// Resolve the backing executable file path from a process's command line (`argv[0]`),
/// handling NUL-delimited `/proc/<pid>/cmdline`, quoted Windows/POSIX paths with spaces,
/// relative paths against `working_directory`, and bare command names via `env_path`.
[[nodiscard]] std::optional<std::filesystem::path> resolve_executable_from_command_line(
    std::string_view command_line,
    const std::filesystem::path& working_directory = {},
    std::string_view env_path = {},
    bool windows_rules = false,
    std::function<bool(const std::filesystem::path&)> file_exists_fn = {});

/// Parse Linux `/proc/<pid>/maps` text into structured virtual memory regions.
[[nodiscard]] Result<std::vector<MemoryRegion>> parse_proc_maps(
    std::string_view maps_text,
    std::string_view main_exe_path = {});

/// Parse Linux `/proc/<pid>/smaps` text in a single pass, populating per-region RSS, PSS,
/// Private/Shared Clean/Dirty, Swap, Locked, VmFlags, `[stack:<tid>]` owner_tid, and `[heap]`.
[[nodiscard]] Result<std::vector<MemoryRegion>> parse_proc_smaps(
    std::string_view smaps_text,
    std::string_view main_exe_path = {});

/// Cross-reference thread stack pointers (and main thread `[stack]`) onto `regions`, setting
/// `MemoryRegionKind::Stack` and `usage.owner_tid` for thread stack mappings.
void attribute_thread_stacks(std::vector<MemoryRegion>& regions,
                             std::span<const ThreadInfo> threads,
                             std::optional<ThreadId> main_tid = std::nullopt);

/// Aggregate per-category, per-protection, and physical-footprint totals across `regions`,
/// optionally enriching physical totals from Linux `/proc/<pid>/smaps_rollup` text.
[[nodiscard]] ProcessMemorySummary summarize_process_memory(
    std::span<const MemoryRegion> regions,
    std::string_view smaps_rollup_text = {});

/// Group sorted/unsorted memory regions into visual VA clusters while collapsing gaps >=
/// `gap_collapse_threshold` (default 64 MiB) so multi-TiB canonical holes don't dwarf mappings.
[[nodiscard]] std::vector<AddressSpaceCluster> build_address_space_clusters(
    std::span<const MemoryRegion> regions,
    std::uint64_t gap_collapse_threshold = 64ull * 1024ull * 1024ull);

/// Group mapped file/image regions into loaded PE/ELF modules and annotate `regions` in place
/// with `MemoryRegionKind::Image` and `module_name` where matched.
[[nodiscard]] std::vector<ModuleInfo> derive_modules_from_regions(
    std::vector<MemoryRegion>& regions,
    std::string_view main_exe_path = {},
    IProcessSession* probe_session = nullptr);

/// Read `[address, address + size)` across region/page boundaries, zero-filling unreadable or
/// unmapped holes and setting `valid[i] = 1` for every successfully read byte.
[[nodiscard]] MemorySample read_memory_tolerant(IProcessSession& session,
                                                std::span<const MemoryRegion> regions,
                                                std::uint64_t address,
                                                std::size_t size);

/// Build a live-rebased `IBinaryImage` for `module` in `session`, combining live process memory
/// with on-disk PE/ELF metadata (such as unmapped ELF `.symtab`/`.strtab` and PE directories)
/// when `module.path` is readable on disk, or parsing directly from live RAM otherwise.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> load_live_module_image(
    IProcessSession& session,
    const ModuleInfo& module,
    std::span<const MemoryRegion> regions = {});

}  // namespace peelf
