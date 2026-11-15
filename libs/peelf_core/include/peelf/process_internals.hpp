#pragma once

#include "peelf/forgiving.hpp"
#include "peelf/process.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace peelf {

enum class ProcessHandleKind : std::uint8_t {
    File,
    Directory,
    Socket,
    Pipe,
    AnonInode,
    Device,
    Memfd,
    KeyOrRegistry,
    SyncObject,
    ProcessOrThread,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(ProcessHandleKind kind) noexcept {
    switch (kind) {
        case ProcessHandleKind::File:            return "File";
        case ProcessHandleKind::Directory:       return "Directory";
        case ProcessHandleKind::Socket:          return "Socket";
        case ProcessHandleKind::Pipe:            return "Pipe";
        case ProcessHandleKind::AnonInode:       return "AnonInode";
        case ProcessHandleKind::Device:          return "Device";
        case ProcessHandleKind::Memfd:           return "Memfd";
        case ProcessHandleKind::KeyOrRegistry:   return "Registry";
        case ProcessHandleKind::SyncObject:      return "SyncObject";
        case ProcessHandleKind::ProcessOrThread: return "Proc/Thread";
        case ProcessHandleKind::Unknown:         return "Unknown";
    }
    return "Unknown";
}

struct ProcessHandleEntry {
    std::uint64_t handle_or_fd{0};
    ProcessHandleKind kind{ProcessHandleKind::Unknown};
    std::string type_name{};
    std::string target{};
    std::string access_or_flags{};
    std::optional<std::uint64_t> offset{};
    std::optional<std::uint64_t> inode{};
    std::optional<std::int32_t> mount_id{};

    auto operator<=>(const ProcessHandleEntry&) const = default;
};

enum class SocketProtocol : std::uint8_t {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
    Unix,
};

[[nodiscard]] constexpr std::string_view to_string(SocketProtocol proto) noexcept {
    switch (proto) {
        case SocketProtocol::Tcp4: return "TCP";
        case SocketProtocol::Tcp6: return "TCP6";
        case SocketProtocol::Udp4: return "UDP";
        case SocketProtocol::Udp6: return "UDP6";
        case SocketProtocol::Unix: return "UNIX";
    }
    return "TCP";
}

struct ProcessSocketEntry {
    SocketProtocol protocol{SocketProtocol::Tcp4};
    std::optional<std::uint64_t> fd{};
    std::uint64_t inode{0};
    std::string local_endpoint{};
    std::string remote_endpoint{};
    std::string state{};

    auto operator<=>(const ProcessSocketEntry&) const = default;
};

struct SecurityCapabilityEntry {
    std::string name{};
    std::uint32_t id{0};
    bool effective{false};
    bool permitted{false};
    bool inheritable{false};
    bool ambient{false};

    auto operator<=>(const SecurityCapabilityEntry&) const = default;
};

struct ProcessMitigationEntry {
    std::string policy{};
    std::string state{};
    bool enabled{false};
    std::string detail{};

    auto operator<=>(const ProcessMitigationEntry&) const = default;
};

struct ProcessNamespaceEntry {
    std::string ns_type{};
    std::string ns_id{};

    auto operator<=>(const ProcessNamespaceEntry&) const = default;
};

struct ProcessSecurityProfile {
    std::string user_summary{};
    std::string group_summary{};
    std::string integrity_or_lsm_label{};
    std::optional<bool> is_elevated{};
    std::optional<bool> no_new_privs{};
    std::string seccomp_mode{};
    std::string cgroup_summary{};

    std::uint64_t cap_inh{0};
    std::uint64_t cap_prm{0};
    std::uint64_t cap_eff{0};
    std::uint64_t cap_bnd{0};
    std::uint64_t cap_amb{0};

    std::vector<SecurityCapabilityEntry> capabilities{};
    std::vector<ProcessMitigationEntry> mitigations{};
    std::vector<ProcessNamespaceEntry> namespaces{};
};

struct ProcessInternalsSnapshot {
    ForgivingValue<std::vector<ProcessHandleEntry>> handles{};
    ForgivingValue<std::vector<ProcessSocketEntry>> sockets{};
    ForgivingValue<ProcessSecurityProfile> security{};
    std::optional<std::uint32_t> total_os_handle_count{};
};

struct LinuxFdInfo {
    std::optional<std::uint64_t> pos{};
    std::optional<std::uint64_t> raw_flags{};
    std::optional<std::int32_t> mnt_id{};
    std::optional<std::uint64_t> ino{};
};

struct LinuxTaskStatSample {
    char state_char{'?'};
    std::uint64_t utime_ticks{0};
    std::uint64_t stime_ticks{0};
    std::optional<std::uint64_t> kstkesp{};
    std::optional<std::uint64_t> kstkeip{};
    bool valid{false};
};

/// Stateful per-thread CPU % delta calculator across consecutive thread snapshots.
class ThreadCpuTracker {
public:
    void reset() noexcept { previous_.clear(); }

    /// Update `threads` in place with `cpu_percent` using `wall_time_ns` (defaults to steady_clock).
    void update(std::span<ThreadInfo> threads,
                std::optional<std::uint64_t> wall_time_ns = std::nullopt);

private:
    struct Sample {
        std::uint64_t wall_ns{0};
        std::uint64_t total_cpu_ns{0};
    };
    std::unordered_map<ThreadId, Sample> previous_{};
};

// Cross-platform testable parsers & decoders for Linux procfs telemetry.
[[nodiscard]] LinuxFdInfo parse_linux_fdinfo(std::string_view fdinfo_text);
[[nodiscard]] std::string decode_linux_open_flags(std::uint64_t raw_flags);
[[nodiscard]] ProcessHandleEntry build_linux_fd_entry(std::uint64_t fd,
                                                      std::string_view readlink_target,
                                                      std::string_view fdinfo_text,
                                                      bool target_is_directory = false);

[[nodiscard]] std::vector<ProcessSocketEntry> parse_linux_proc_net_inet(std::string_view text,
                                                                        SocketProtocol proto);
[[nodiscard]] std::vector<ProcessSocketEntry> parse_linux_proc_net_unix(std::string_view text);
[[nodiscard]] std::vector<ProcessSocketEntry> correlate_linux_process_sockets(
    std::span<const ProcessHandleEntry> handles,
    std::span<const ProcessSocketEntry> net_entries);

[[nodiscard]] std::string_view linux_capability_name(std::uint32_t cap_bit) noexcept;
[[nodiscard]] std::vector<std::string> decode_linux_capability_mask(std::uint64_t mask);
[[nodiscard]] ProcessSecurityProfile parse_linux_security_status(
    std::string_view proc_status_text,
    std::string_view lsm_attr_current = {},
    std::string_view cgroup_text = {},
    std::span<const ProcessNamespaceEntry> namespaces = {});

[[nodiscard]] LinuxTaskStatSample parse_linux_task_stat_sample(std::string_view stat_text) noexcept;

/// Read-only, forgiving user-mode inspection of open handles/FDs, network sockets, and
/// security/mitigation profile for `session`.
[[nodiscard]] ProcessInternalsSnapshot inspect_process_internals(IProcessSession& session);

}  // namespace peelf
