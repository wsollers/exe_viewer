#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
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
    std::optional<std::uint64_t> tls_base{};
    std::optional<std::uint64_t> teb_address{};
    std::optional<std::int64_t> syscall_number{};
    std::string wait_channel{};
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

struct MemoryRegion {
    std::uint64_t start_address{0};
    std::uint64_t end_address{0};
    MemoryProtection protection{};
    MemoryRegionKind kind{MemoryRegionKind::Anonymous};
    std::uint64_t file_offset{0};
    std::string pathname{};
    std::string module_name{};

    [[nodiscard]] constexpr std::uint64_t size() const noexcept {
        return end_address >= start_address ? (end_address - start_address) : 0;
    }

    [[nodiscard]] constexpr bool contains(std::uint64_t address) const noexcept {
        return address >= start_address && address < end_address;
    }

    auto operator<=>(const MemoryRegion&) const = default;
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
        return base_address + size;
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
    [[nodiscard]] virtual TargetLayout target_layout() const noexcept {
        return TargetLayout::from_arch(info().architecture, info().is_64bit, info().endianness);
    }

    [[nodiscard]] virtual Result<std::vector<MemoryRegion>> memory_regions() = 0;
    [[nodiscard]] virtual Result<std::vector<ModuleInfo>> modules() = 0;
    [[nodiscard]] virtual Result<std::size_t> read_memory(std::uint64_t address,
                                                          std::span<std::uint8_t> buffer) = 0;
    [[nodiscard]] virtual Result<std::size_t> write_memory(std::uint64_t address,
                                                           std::span<const std::uint8_t> data,
                                                           MemoryWriteOptions options = {}) = 0;

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

    ~ScopedProcessPause() { release(); }

    [[nodiscard]] bool paused_by_guard() const noexcept { return owns_pause_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }

    void release() noexcept {
        if (session_ != nullptr && owns_pause_) {
            (void)session_->resume();
            owns_pause_ = false;
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
