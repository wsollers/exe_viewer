#include "peelf/process_internals.hpp"
#include "peelf/crash_dump.hpp"

#if defined(__linux__)

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {
namespace {

constexpr std::size_t kMaxEnumeratedFds = 4096;

[[nodiscard]] bool read_proc_file(const std::string& path, std::string& out) {
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        return false;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    out = oss.str();
    return true;
}

[[nodiscard]] std::string read_symlink_str(const std::string& path) {
    std::array<char, 4096> buf{};
    const ssize_t len = ::readlink(path.c_str(), buf.data(), buf.size() - 1);
    if (len <= 0) {
        return {};
    }
    return std::string(buf.data(), static_cast<std::size_t>(len));
}

}  // namespace

ProcessInternalsSnapshot inspect_process_internals(IProcessSession& session) {
    if (session.is_crash_dump()) {
        if (const auto* dump = dynamic_cast<const ICrashDumpSession*>(&session)) {
            return dump->crash_internals();
        }
        ProcessInternalsSnapshot snap{};
        snap.handles.status = SubsystemStatus::unavailable("crash_dump", "No handle stream in crash dump");
        snap.sockets.status = SubsystemStatus::unavailable("crash_dump", "Live sockets not captured in crash dump");
        snap.security.status = SubsystemStatus::unavailable("crash_dump", "Live token/seccomp not captured in crash dump");
        return snap;
    }

    ProcessInternalsSnapshot snap{};
    const ProcessId pid = session.pid();
    const std::string proc_root = "/proc/" + std::to_string(pid);

    // 1. Open file descriptors (/proc/<pid>/fd + /proc/<pid>/fdinfo/<fd>)
    {
        const std::string fd_dir_path = proc_root + "/fd";
        DIR* dir = ::opendir(fd_dir_path.c_str());
        if (dir == nullptr) {
            snap.handles.status = SubsystemStatus::unavailable(
                "/proc/<pid>/fd", "unable to open fd directory (permission denied or exited)");
        } else {
            std::vector<ProcessHandleEntry> handles;
            std::uint32_t total_seen = 0;
            bool capped = false;
            bool any_partial = false;

            while (dirent* ent = ::readdir(dir)) {
                const std::string_view name(ent->d_name);
                if (name == "." || name == "..") {
                    continue;
                }
                std::uint64_t fd_num = 0;
                const auto [ptr, ec] =
                    std::from_chars(name.data(), name.data() + name.size(), fd_num, 10);
                if (ec != std::errc{} || ptr != name.data() + name.size()) {
                    continue;
                }
                ++total_seen;
                if (handles.size() >= kMaxEnumeratedFds) {
                    capped = true;
                    continue;
                }

                const std::string link_path = fd_dir_path + "/" + std::string(name);
                const std::string target = read_symlink_str(link_path);
                if (target.empty()) {
                    any_partial = true;
                    continue;
                }

                bool is_dir = false;
                struct stat st{};
                if (target.starts_with('/') && ::stat(link_path.c_str(), &st) == 0) {
                    is_dir = S_ISDIR(st.st_mode);
                }

                std::string fdinfo_text;
                const std::string fdinfo_path = proc_root + "/fdinfo/" + std::string(name);
                if (!read_proc_file(fdinfo_path, fdinfo_text)) {
                    any_partial = true;
                }

                handles.push_back(build_linux_fd_entry(fd_num, target, fdinfo_text, is_dir));
            }
            ::closedir(dir);

            std::ranges::sort(handles, {}, &ProcessHandleEntry::handle_or_fd);
            snap.total_os_handle_count = total_seen;
            const std::size_t count = handles.size();
            snap.handles.value = std::move(handles);
            if (capped) {
                snap.handles.status = SubsystemStatus::partial(
                    "/proc/<pid>/fd",
                    "enumerated first " + std::to_string(kMaxEnumeratedFds) + " of " +
                        std::to_string(total_seen) + " open FDs");
            } else if (any_partial) {
                snap.handles.status = SubsystemStatus::partial(
                    "/proc/<pid>/fd+fdinfo",
                    "enumerated " + std::to_string(count) +
                        " FDs (some transient FDs closed or fdinfo restricted)");
            } else {
                snap.handles.status = SubsystemStatus::available(
                    "/proc/<pid>/fd+fdinfo",
                    std::to_string(count) + " open file descriptors");
            }
        }
    }

    // 2. Network sockets (/proc/<pid>/net/{tcp,tcp6,udp,udp6,unix} correlated with socket:[ino] FDs)
    if (!snap.handles.has_value()) {
        snap.sockets.status = SubsystemStatus::unavailable(
            "/proc/<pid>/net/*",
            "socket FD correlation unavailable because /proc/<pid>/fd could not be read");
    } else {
        std::vector<ProcessSocketEntry> all_net;
        struct NetSource {
            const char* rel_path;
            SocketProtocol proto;
            bool is_unix;
        };
        static constexpr std::array<NetSource, 5> kSources{{
            {"/net/tcp", SocketProtocol::Tcp4, false},
            {"/net/tcp6", SocketProtocol::Tcp6, false},
            {"/net/udp", SocketProtocol::Udp4, false},
            {"/net/udp6", SocketProtocol::Udp6, false},
            {"/net/unix", SocketProtocol::Unix, true},
        }};

        std::size_t readable_tables = 0;
        for (const auto& src : kSources) {
            std::string content;
            if (!read_proc_file(proc_root + src.rel_path, content)) {
                continue;
            }
            ++readable_tables;
            auto parsed = src.is_unix ? parse_linux_proc_net_unix(content)
                                      : parse_linux_proc_net_inet(content, src.proto);
            all_net.insert(all_net.end(),
                           std::make_move_iterator(parsed.begin()),
                           std::make_move_iterator(parsed.end()));
        }

        if (readable_tables == 0) {
            snap.sockets.status = SubsystemStatus::unavailable(
                "/proc/<pid>/net", "unable to read network tables");
        } else {
            auto matched = correlate_linux_process_sockets(*snap.handles.value, all_net);
            const std::size_t sock_count = matched.size();
            snap.sockets.value = std::move(matched);
            if (readable_tables < kSources.size()) {
                snap.sockets.status = SubsystemStatus::partial(
                    "/proc/<pid>/net",
                    std::to_string(sock_count) +
                        " process sockets matched (some /proc/net tables unavailable)");
            } else {
                snap.sockets.status = SubsystemStatus::available(
                    "/proc/<pid>/net",
                    std::to_string(sock_count) + " open sockets correlated");
            }
        }
    }

    // 3. Security context, capabilities, seccomp, LSM, cgroup, namespaces
    {
        std::string status_text;
        if (!read_proc_file(proc_root + "/status", status_text)) {
            snap.security.status = SubsystemStatus::unavailable(
                "/proc/<pid>/status", "unable to read process status");
        } else {
            std::string lsm_text;
            const bool has_lsm = read_proc_file(proc_root + "/attr/current", lsm_text);
            std::string cgroup_text;
            (void)read_proc_file(proc_root + "/cgroup", cgroup_text);

            std::vector<ProcessNamespaceEntry> ns_entries;
            static constexpr std::array<const char*, 8> kNsNames{{
                "mnt", "pid", "net", "uts", "ipc", "user", "cgroup", "time",
            }};
            for (const char* ns_name : kNsNames) {
                const std::string link = read_symlink_str(proc_root + "/ns/" + ns_name);
                if (!link.empty()) {
                    ns_entries.push_back(ProcessNamespaceEntry{
                        .ns_type = ns_name,
                        .ns_id = link,
                    });
                }
            }

            snap.security.value = parse_linux_security_status(
                status_text, lsm_text, cgroup_text, ns_entries);

            if (!has_lsm && ns_entries.empty()) {
                snap.security.status = SubsystemStatus::partial(
                    "/proc/<pid>/status",
                    "UID/GID, capabilities & seccomp read; LSM/namespaces restricted");
            } else {
                snap.security.status = SubsystemStatus::available(
                    "/proc/<pid>/status+attr+ns",
                    "Linux security profile, capabilities, seccomp & namespaces read");
            }
        }
    }

    return snap;
}

}  // namespace peelf

#endif  // defined(__linux__)
