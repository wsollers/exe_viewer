#pragma once

#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class CrashDumpKind : std::uint8_t {
    WindowsMinidump = 0,
    ElfCore = 1,
};

[[nodiscard]] constexpr std::string_view to_string(CrashDumpKind kind) noexcept {
    switch (kind) {
        case CrashDumpKind::WindowsMinidump: return "WindowsMinidump";
        case CrashDumpKind::ElfCore:         return "ElfCore";
    }
    return "WindowsMinidump";
}

struct CrashExceptionInfo {
    std::optional<ThreadId> thread_id{};
    std::uint64_t fault_code{0};
    std::optional<std::int64_t> fault_subcode{};
    std::string fault_name{};
    std::optional<std::uint64_t> fault_address{};
    std::optional<std::uint64_t> instruction_pointer{};
    std::string access_operation{};  ///< e.g. "read", "write", "execute", or signal code name
    std::string description{};
};

struct CrashDumpSummary {
    CrashDumpKind kind{CrashDumpKind::WindowsMinidump};
    std::filesystem::path dump_path{};
    std::string sha256{};
    std::uint64_t file_size{0};
    std::string os_summary{};
    std::string cpu_summary{};
    TargetLayout layout{};
    ProcessId pid{0};
    ProcessId parent_pid{0};
    std::string process_name{};
    std::string command_line{};
    std::uint32_t timestamp_unix{0};
    std::optional<CrashExceptionInfo> exception{};
    std::size_t module_count{0};
    std::size_t thread_count{0};
    std::size_t region_count{0};
    std::size_t handle_count{0};
    SubsystemStatus status{SubsystemStatus::available("crash_dump")};
    std::vector<std::string> diagnostics{};
};

/// Strictly read-only `IProcessSession` adapter backed by an offline Windows Minidump (`.dmp`)
/// or Linux ELF Core Dump (`ET_CORE`), allowing every live-process inspection panel (`Memory Map`,
/// `Threads & Stack`, `Thread Locals`, `Memory Search`, `PEB / TEB & Flags`, `Handlers`,
/// `Process Internals`, `Structure View`, `Disassembly`, and `Decompile`) to operate offline.
class ICrashDumpSession : public IProcessSession {
public:
    ~ICrashDumpSession() override = default;

    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] bool is_read_only() const noexcept override { return true; }
    [[nodiscard]] bool is_crash_dump() const noexcept override { return true; }
    [[nodiscard]] bool is_suspended() const noexcept override { return true; }

    [[nodiscard]] virtual const CrashDumpSummary& crash_summary() const noexcept = 0;
    [[nodiscard]] virtual const ProcessInternalsSnapshot& crash_internals() const noexcept = 0;
};

/// Returns true if `bytes` begins with a valid Windows `"MDMP"` (`0x504D444D`) Minidump header.
[[nodiscard]] bool is_windows_minidump(std::span<const std::uint8_t> bytes) noexcept;

/// Returns true if `bytes` begins with a 32/64-bit LE/BE ELF header whose `e_type == ET_CORE` (`4`).
[[nodiscard]] bool is_elf_core_dump(std::span<const std::uint8_t> bytes) noexcept;

/// Returns true if `bytes` is either a Windows Minidump or an ELF `ET_CORE` crash dump.
[[nodiscard]] inline bool is_crash_dump_bytes(std::span<const std::uint8_t> bytes) noexcept {
    return is_windows_minidump(bytes) || is_elf_core_dump(bytes);
}

/// Maps a Win32 / NTSTATUS exception code (e.g. `0xC0000005`) to its symbolic name.
[[nodiscard]] std::string_view windows_exception_code_name(std::uint32_t code) noexcept;

/// Maps a POSIX / Linux signal number (e.g. `11` -> `"SIGSEGV"`) to its symbolic name.
[[nodiscard]] std::string_view posix_signal_name(std::int32_t signo) noexcept;

/// Opens an in-memory Windows Minidump (`.dmp`) buffer as an offline `ICrashDumpSession`.
[[nodiscard]] Result<std::unique_ptr<ICrashDumpSession>> open_minidump_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path = {});

/// Opens an in-memory Linux ELF `ET_CORE` buffer as an offline `ICrashDumpSession`.
[[nodiscard]] Result<std::unique_ptr<ICrashDumpSession>> open_elf_core_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path = {});

/// Auto-detects `"MDMP"` vs. ELF `ET_CORE` and opens `bytes` as an offline `ICrashDumpSession`.
[[nodiscard]] Result<std::unique_ptr<ICrashDumpSession>> open_crash_dump_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path = {});

/// Reads `path` from disk and opens it as an offline `ICrashDumpSession`.
[[nodiscard]] Result<std::unique_ptr<ICrashDumpSession>> open_crash_dump_file(
    const std::filesystem::path& path);

}  // namespace peelf
