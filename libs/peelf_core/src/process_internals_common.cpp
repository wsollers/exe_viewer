#include "peelf/process_internals.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cinttypes>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] std::string_view trim_ws(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' ||
                           sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' ||
                           sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] std::vector<std::string_view> split_ws(std::string_view sv) {
    std::vector<std::string_view> out;
    out.reserve(16);
    while (!sv.empty()) {
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' ||
                               sv.front() == '\r' || sv.front() == '\n')) {
            sv.remove_prefix(1);
        }
        if (sv.empty()) {
            break;
        }
        std::size_t n = 0;
        while (n < sv.size() && sv[n] != ' ' && sv[n] != '\t' &&
               sv[n] != '\r' && sv[n] != '\n') {
            ++n;
        }
        out.push_back(sv.substr(0, n));
        sv.remove_prefix(n);
    }
    return out;
}

template <typename IntT>
[[nodiscard]] std::optional<IntT> parse_int(std::string_view sv, int base = 10) noexcept {
    sv = trim_ws(sv);
    if (sv.empty()) {
        return std::nullopt;
    }
    IntT val{};
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), val, base);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return std::nullopt;
    }
    return val;
}

[[nodiscard]] std::optional<std::uint64_t> extract_bracketed_inode(std::string_view target,
                                                                   std::string_view prefix) noexcept {
    if (!target.starts_with(prefix)) {
        return std::nullopt;
    }
    target.remove_prefix(prefix.size());
    if (target.empty() || target.back() != ']') {
        return std::nullopt;
    }
    target.remove_suffix(1);
    return parse_int<std::uint64_t>(target, 10);
}

[[nodiscard]] std::string format_ipv6_bytes(const std::array<std::uint8_t, 16>& b) {
    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < 8; ++i) {
        groups[i] = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(b[i * 2]) << 8u) |
            static_cast<std::uint16_t>(b[i * 2 + 1]));
    }

    // Find longest run of >= 2 zero groups (RFC 5952).
    std::size_t best_start = 8;
    std::size_t best_len = 0;
    std::size_t cur_start = 0;
    std::size_t cur_len = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        if (groups[i] == 0) {
            if (cur_len == 0) {
                cur_start = i;
            }
            ++cur_len;
            if (cur_len >= 2 && cur_len > best_len) {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }

    std::string out = "[";
    for (std::size_t i = 0; i < 8;) {
        if (i == best_start) {
            out += "::";
            i += best_len;
            continue;
        }
        if (i > 0 && i != best_start + best_len) {
            out.push_back(':');
        }
        out += std::format("{:x}", static_cast<unsigned>(groups[i]));
        ++i;
    }
    out.push_back(']');
    return out;
}

[[nodiscard]] std::optional<std::string> decode_proc_net_endpoint(std::string_view token,
                                                                  bool is_ipv6) {
    const std::size_t colon = token.find(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view addr_hex = token.substr(0, colon);
    const std::string_view port_hex = token.substr(colon + 1);
    const auto port = parse_int<std::uint16_t>(port_hex, 16);
    if (!port.has_value()) {
        return std::nullopt;
    }

    if (!is_ipv6) {
        if (addr_hex.size() != 8) {
            return std::nullopt;
        }
        const auto w = parse_int<std::uint32_t>(addr_hex, 16);
        if (!w.has_value()) {
            return std::nullopt;
        }
        return std::format("{}.{}.{}.{}:{}",
                           static_cast<unsigned>(*w & 0xFFu),
                           static_cast<unsigned>((*w >> 8u) & 0xFFu),
                           static_cast<unsigned>((*w >> 16u) & 0xFFu),
                           static_cast<unsigned>((*w >> 24u) & 0xFFu),
                           static_cast<unsigned>(*port));
    }

    if (addr_hex.size() != 32) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 16> bytes{};
    for (std::size_t word = 0; word < 4; ++word) {
        const auto w = parse_int<std::uint32_t>(addr_hex.substr(word * 8, 8), 16);
        if (!w.has_value()) {
            return std::nullopt;
        }
        bytes[word * 4 + 0] = static_cast<std::uint8_t>(*w & 0xFFu);
        bytes[word * 4 + 1] = static_cast<std::uint8_t>((*w >> 8u) & 0xFFu);
        bytes[word * 4 + 2] = static_cast<std::uint8_t>((*w >> 16u) & 0xFFu);
        bytes[word * 4 + 3] = static_cast<std::uint8_t>((*w >> 24u) & 0xFFu);
    }

    return std::format("{}:{}", format_ipv6_bytes(bytes), static_cast<unsigned>(*port));
}

[[nodiscard]] std::string decode_linux_tcp_state(std::uint32_t st, bool is_udp) {
    if (is_udp) {
        if (st == 0x01u) {
            return "ESTABLISHED";
        }
        if (st == 0x07u) {
            return "UNCONNECTED";
        }
    }
    switch (st) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        case 0x0C: return "NEW_SYN_RECV";
        default:   return "UNKNOWN";
    }
}

}  // namespace

LinuxFdInfo parse_linux_fdinfo(std::string_view fdinfo_text) {
    LinuxFdInfo info{};
    while (!fdinfo_text.empty()) {
        const std::size_t nl = fdinfo_text.find('\n');
        const std::string_view line =
            (nl == std::string_view::npos) ? fdinfo_text : fdinfo_text.substr(0, nl);
        if (nl == std::string_view::npos) {
            fdinfo_text = {};
        } else {
            fdinfo_text.remove_prefix(nl + 1);
        }

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        const std::string_view key = trim_ws(line.substr(0, colon));
        const std::string_view val = trim_ws(line.substr(colon + 1));
        if (key == "pos") {
            info.pos = parse_int<std::uint64_t>(val, 10);
        } else if (key == "flags") {
            // Linux /proc/<pid>/fdinfo/<fd> prints open flags in octal.
            info.raw_flags = parse_int<std::uint64_t>(val, 8);
        } else if (key == "mnt_id") {
            info.mnt_id = parse_int<std::int32_t>(val, 10);
        } else if (key == "ino") {
            info.ino = parse_int<std::uint64_t>(val, 10);
        }
    }
    return info;
}

std::string decode_linux_open_flags(std::uint64_t raw_flags) {
    std::string out;
    switch (raw_flags & 03ULL) {
        case 0ULL: out = "O_RDONLY"; break;
        case 1ULL: out = "O_WRONLY"; break;
        case 2ULL: out = "O_RDWR"; break;
        default:   out = "O_ACCMODE?"; break;
    }

    struct FlagDef {
        std::uint64_t bit;
        std::string_view name;
    };
    // Generic Linux octal flag definitions (x86/x86_64/riscv/generic ABI).
    static constexpr std::array<FlagDef, 10> kFlags{{
        {00000100ULL, "O_CREAT"},
        {00002000ULL, "O_APPEND"},
        {00004000ULL, "O_NONBLOCK"},
        {00010000ULL, "O_DSYNC"},
        {00040000ULL, "O_DIRECT"},
        {00200000ULL, "O_DIRECTORY"},
        {00400000ULL, "O_NOFOLLOW"},
        {01000000ULL, "O_NOATIME"},
        {02000000ULL, "O_CLOEXEC"},
        {010000000ULL, "O_PATH"},
    }};

    for (const auto& f : kFlags) {
        if ((raw_flags & f.bit) != 0) {
            out += '|';
            out += f.name;
        }
    }
    return out;
}

ProcessHandleEntry build_linux_fd_entry(std::uint64_t fd,
                                        std::string_view readlink_target,
                                        std::string_view fdinfo_text,
                                        bool target_is_directory) {
    ProcessHandleEntry entry{};
    entry.handle_or_fd = fd;
    entry.target = std::string(trim_ws(readlink_target));

    const LinuxFdInfo info = parse_linux_fdinfo(fdinfo_text);
    entry.offset = info.pos;
    entry.mount_id = info.mnt_id;
    entry.inode = info.ino;
    if (info.raw_flags.has_value()) {
        entry.access_or_flags = decode_linux_open_flags(*info.raw_flags);
    }

    const std::string_view tgt = entry.target;
    if (const auto sock_ino = extract_bracketed_inode(tgt, "socket:[")) {
        entry.kind = ProcessHandleKind::Socket;
        entry.type_name = "Socket";
        if (!entry.inode.has_value()) {
            entry.inode = *sock_ino;
        }
    } else if (const auto pipe_ino = extract_bracketed_inode(tgt, "pipe:[")) {
        entry.kind = ProcessHandleKind::Pipe;
        entry.type_name = "Pipe";
        if (!entry.inode.has_value()) {
            entry.inode = *pipe_ino;
        }
    } else if (tgt.starts_with("anon_inode:")) {
        entry.kind = ProcessHandleKind::AnonInode;
        entry.type_name = "AnonInode";
    } else if (tgt.starts_with("/memfd:")) {
        entry.kind = ProcessHandleKind::Memfd;
        entry.type_name = "Memfd";
    } else if (tgt.starts_with("/dev/")) {
        entry.kind = ProcessHandleKind::Device;
        entry.type_name = "Device";
    } else if (target_is_directory ||
               (info.raw_flags.has_value() && ((*info.raw_flags & 00200000ULL) != 0))) {
        entry.kind = ProcessHandleKind::Directory;
        entry.type_name = "Directory";
    } else if (!tgt.empty()) {
        entry.kind = ProcessHandleKind::File;
        entry.type_name = "File";
    } else {
        entry.kind = ProcessHandleKind::Unknown;
        entry.type_name = "Unknown";
    }

    return entry;
}

std::vector<ProcessSocketEntry> parse_linux_proc_net_inet(std::string_view text,
                                                          SocketProtocol proto) {
    std::vector<ProcessSocketEntry> out;
    const bool is_ipv6 = (proto == SocketProtocol::Tcp6 || proto == SocketProtocol::Udp6);
    const bool is_udp = (proto == SocketProtocol::Udp4 || proto == SocketProtocol::Udp6);

    bool first_line = true;
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        const std::string_view line =
            (nl == std::string_view::npos) ? text : text.substr(0, nl);
        if (nl == std::string_view::npos) {
            text = {};
        } else {
            text.remove_prefix(nl + 1);
        }

        const auto cols = split_ws(line);
        if (cols.empty()) {
            continue;
        }
        if (first_line) {
            first_line = false;
            if (cols[0] == "sl") {
                continue;
            }
        }
        // Columns: sl(0) local_address(1) rem_address(2) st(3) tx:rx(4) tr:tm(5)
        //          retrnsmt(6) uid(7) timeout(8) inode(9) ...
        if (cols.size() < 10) {
            continue;
        }
        const auto local_ep = decode_proc_net_endpoint(cols[1], is_ipv6);
        const auto remote_ep = decode_proc_net_endpoint(cols[2], is_ipv6);
        const auto st = parse_int<std::uint32_t>(cols[3], 16);
        const auto ino = parse_int<std::uint64_t>(cols[9], 10);
        if (!local_ep.has_value() || !remote_ep.has_value() || !st.has_value() ||
            !ino.has_value() || *ino == 0) {
            continue;
        }

        ProcessSocketEntry entry{};
        entry.protocol = proto;
        entry.inode = *ino;
        entry.local_endpoint = *local_ep;
        entry.remote_endpoint = *remote_ep;
        entry.state = decode_linux_tcp_state(*st, is_udp);
        out.push_back(std::move(entry));
    }
    return out;
}

std::vector<ProcessSocketEntry> parse_linux_proc_net_unix(std::string_view text) {
    std::vector<ProcessSocketEntry> out;
    bool first_line = true;
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        const std::string_view line =
            (nl == std::string_view::npos) ? text : text.substr(0, nl);
        if (nl == std::string_view::npos) {
            text = {};
        } else {
            text.remove_prefix(nl + 1);
        }

        const auto cols = split_ws(line);
        if (cols.empty()) {
            continue;
        }
        if (first_line) {
            first_line = false;
            if (cols[0] == "Num") {
                continue;
            }
        }
        // Columns: Num(0) RefCount(1) Protocol(2) Flags(3) Type(4) St(5) Inode(6) [Path(7)]
        if (cols.size() < 7) {
            continue;
        }
        const auto st = parse_int<std::uint32_t>(cols[5], 16);
        const auto ino = parse_int<std::uint64_t>(cols[6], 10);
        if (!ino.has_value() || *ino == 0) {
            continue;
        }

        ProcessSocketEntry entry{};
        entry.protocol = SocketProtocol::Unix;
        entry.inode = *ino;
        entry.local_endpoint = (cols.size() >= 8) ? std::string(cols[7]) : std::string("<unnamed>");
        entry.remote_endpoint = "-";
        switch (st.value_or(0)) {
            case 0x01: entry.state = "UNCONNECTED"; break;
            case 0x02: entry.state = "CONNECTING"; break;
            case 0x03: entry.state = "CONNECTED"; break;
            case 0x04: entry.state = "DISCONNECTING"; break;
            default:   entry.state = "UNIX"; break;
        }
        if (const auto flags = parse_int<std::uint32_t>(cols[3], 16);
            flags.has_value() && (*flags & 0x10000u) != 0) {
            entry.state = "LISTEN";
        }
        out.push_back(std::move(entry));
    }
    return out;
}

std::vector<ProcessSocketEntry> correlate_linux_process_sockets(
    std::span<const ProcessHandleEntry> handles,
    std::span<const ProcessSocketEntry> net_entries) {
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> inode_to_fds;
    for (const auto& h : handles) {
        if (h.kind == ProcessHandleKind::Socket && h.inode.has_value() && *h.inode != 0) {
            inode_to_fds[*h.inode].push_back(h.handle_or_fd);
        }
    }

    std::vector<ProcessSocketEntry> matched;
    for (const auto& sock : net_entries) {
        const auto it = inode_to_fds.find(sock.inode);
        if (it == inode_to_fds.end()) {
            continue;
        }
        for (const std::uint64_t fd : it->second) {
            ProcessSocketEntry copy = sock;
            copy.fd = fd;
            matched.push_back(std::move(copy));
        }
    }

    std::ranges::sort(matched, [](const ProcessSocketEntry& a, const ProcessSocketEntry& b) {
        const std::uint64_t fa = a.fd.value_or(UINT64_MAX);
        const std::uint64_t fb = b.fd.value_or(UINT64_MAX);
        if (fa != fb) {
            return fa < fb;
        }
        return a.inode < b.inode;
    });
    return matched;
}

std::string_view linux_capability_name(std::uint32_t cap_bit) noexcept {
    static constexpr std::array<std::string_view, 41> kCapNames{{
        "CAP_CHOWN",              // 0
        "CAP_DAC_OVERRIDE",       // 1
        "CAP_DAC_READ_SEARCH",    // 2
        "CAP_FOWNER",             // 3
        "CAP_FSETID",             // 4
        "CAP_KILL",               // 5
        "CAP_SETGID",             // 6
        "CAP_SETUID",             // 7
        "CAP_SETPCAP",            // 8
        "CAP_LINUX_IMMUTABLE",    // 9
        "CAP_NET_BIND_SERVICE",   // 10
        "CAP_NET_BROADCAST",      // 11
        "CAP_NET_ADMIN",          // 12
        "CAP_NET_RAW",            // 13
        "CAP_IPC_LOCK",           // 14
        "CAP_IPC_OWNER",          // 15
        "CAP_SYS_MODULE",         // 16
        "CAP_SYS_RAWIO",          // 17
        "CAP_SYS_CHROOT",         // 18
        "CAP_SYS_PTRACE",         // 19
        "CAP_SYS_PACCT",          // 20
        "CAP_SYS_ADMIN",          // 21
        "CAP_SYS_BOOT",           // 22
        "CAP_SYS_NICE",           // 23
        "CAP_SYS_RESOURCE",       // 24
        "CAP_SYS_TIME",           // 25
        "CAP_SYS_TTY_CONFIG",     // 26
        "CAP_MKNOD",              // 27
        "CAP_LEASE",              // 28
        "CAP_AUDIT_WRITE",        // 29
        "CAP_AUDIT_CONTROL",      // 30
        "CAP_SETFCAP",            // 31
        "CAP_MAC_OVERRIDE",       // 32
        "CAP_MAC_ADMIN",          // 33
        "CAP_SYSLOG",             // 34
        "CAP_WAKE_ALARM",         // 35
        "CAP_BLOCK_SUSPEND",      // 36
        "CAP_AUDIT_READ",         // 37
        "CAP_PERFMON",            // 38
        "CAP_BPF",                // 39
        "CAP_CHECKPOINT_RESTORE", // 40
    }};
    if (cap_bit < kCapNames.size()) {
        return kCapNames[cap_bit];
    }
    return {};
}

std::vector<std::string> decode_linux_capability_mask(std::uint64_t mask) {
    std::vector<std::string> out;
    for (std::uint32_t bit = 0; bit < 64; ++bit) {
        if (((mask >> bit) & 1ULL) == 0) {
            continue;
        }
        const std::string_view known = linux_capability_name(bit);
        if (!known.empty()) {
            out.emplace_back(known);
        } else {
            out.push_back("CAP_" + std::to_string(bit));
        }
    }
    return out;
}

ProcessSecurityProfile parse_linux_security_status(
    std::string_view proc_status_text,
    std::string_view lsm_attr_current,
    std::string_view cgroup_text,
    std::span<const ProcessNamespaceEntry> namespaces) {
    ProcessSecurityProfile prof{};
    std::string groups_line;

    while (!proc_status_text.empty()) {
        const std::size_t nl = proc_status_text.find('\n');
        const std::string_view line =
            (nl == std::string_view::npos) ? proc_status_text : proc_status_text.substr(0, nl);
        if (nl == std::string_view::npos) {
            proc_status_text = {};
        } else {
            proc_status_text.remove_prefix(nl + 1);
        }

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        const std::string_view key = trim_ws(line.substr(0, colon));
        const std::string_view val = trim_ws(line.substr(colon + 1));

        if (key == "Uid") {
            const auto cols = split_ws(val);
            if (cols.size() >= 4) {
                prof.user_summary = std::string("real=") + std::string(cols[0]) +
                                    " eff=" + std::string(cols[1]) +
                                    " saved=" + std::string(cols[2]) +
                                    " fs=" + std::string(cols[3]);
                if (const auto euid = parse_int<std::uint32_t>(cols[1], 10)) {
                    prof.is_elevated = (*euid == 0);
                }
            } else {
                prof.user_summary = std::string(val);
            }
        } else if (key == "Gid") {
            const auto cols = split_ws(val);
            if (cols.size() >= 4) {
                prof.group_summary = std::string("real=") + std::string(cols[0]) +
                                     " eff=" + std::string(cols[1]) +
                                     " saved=" + std::string(cols[2]) +
                                     " fs=" + std::string(cols[3]);
            } else {
                prof.group_summary = std::string(val);
            }
        } else if (key == "Groups") {
            groups_line = std::string(val);
        } else if (key == "NoNewPrivs") {
            if (const auto nnp = parse_int<int>(val, 10)) {
                prof.no_new_privs = (*nnp != 0);
            }
        } else if (key == "Seccomp") {
            if (const auto sc = parse_int<int>(val, 10)) {
                switch (*sc) {
                    case 0:  prof.seccomp_mode = "Disabled (0)"; break;
                    case 1:  prof.seccomp_mode = "Strict (1)"; break;
                    case 2:  prof.seccomp_mode = "Filter / BPF (2)"; break;
                    default: prof.seccomp_mode = "Mode " + std::to_string(*sc); break;
                }
            }
        } else if (key == "CapInh") {
            prof.cap_inh = parse_int<std::uint64_t>(val, 16).value_or(0);
        } else if (key == "CapPrm") {
            prof.cap_prm = parse_int<std::uint64_t>(val, 16).value_or(0);
        } else if (key == "CapEff") {
            prof.cap_eff = parse_int<std::uint64_t>(val, 16).value_or(0);
        } else if (key == "CapBnd") {
            prof.cap_bnd = parse_int<std::uint64_t>(val, 16).value_or(0);
        } else if (key == "CapAmb") {
            prof.cap_amb = parse_int<std::uint64_t>(val, 16).value_or(0);
        }
    }

    if (!groups_line.empty()) {
        if (!prof.group_summary.empty()) {
            prof.group_summary += " | groups=[" + groups_line + "]";
        } else {
            prof.group_summary = "groups=[" + groups_line + "]";
        }
    }

    const std::string_view lsm = trim_ws(lsm_attr_current);
    prof.integrity_or_lsm_label = lsm.empty() ? std::string("unconfined") : std::string(lsm);

    const std::string_view cg = trim_ws(cgroup_text);
    if (!cg.empty()) {
        // Keep concise single-line cgroup summary.
        std::string flat(cg);
        std::ranges::replace(flat, '\n', ';');
        std::ranges::replace(flat, '\r', ' ');
        prof.cgroup_summary = std::move(flat);
    }

    const std::uint64_t union_caps = prof.cap_eff | prof.cap_prm | prof.cap_inh | prof.cap_amb;
    for (std::uint32_t bit = 0; bit < 64; ++bit) {
        if (((union_caps >> bit) & 1ULL) == 0) {
            continue;
        }
        SecurityCapabilityEntry cap{};
        cap.id = bit;
        const std::string_view known = linux_capability_name(bit);
        cap.name = known.empty() ? ("CAP_" + std::to_string(bit)) : std::string(known);
        cap.effective = ((prof.cap_eff >> bit) & 1ULL) != 0;
        cap.permitted = ((prof.cap_prm >> bit) & 1ULL) != 0;
        cap.inheritable = ((prof.cap_inh >> bit) & 1ULL) != 0;
        cap.ambient = ((prof.cap_amb >> bit) & 1ULL) != 0;
        prof.capabilities.push_back(std::move(cap));
    }

    if (!prof.seccomp_mode.empty()) {
        const bool active = !prof.seccomp_mode.starts_with("Disabled");
        prof.mitigations.push_back(ProcessMitigationEntry{
            .policy = "Seccomp",
            .state = prof.seccomp_mode,
            .enabled = active,
            .detail = active ? "System-call sandboxing active" : "Unfiltered syscalls",
        });
    }
    if (prof.no_new_privs.has_value()) {
        prof.mitigations.push_back(ProcessMitigationEntry{
            .policy = "NoNewPrivs",
            .state = *prof.no_new_privs ? "Enabled" : "Disabled",
            .enabled = *prof.no_new_privs,
            .detail = *prof.no_new_privs ? "execve cannot grant elevated privileges"
                                         : "Standard privilege inheritance",
        });
    }
    prof.mitigations.push_back(ProcessMitigationEntry{
        .policy = "LSM (AppArmor / SELinux)",
        .state = prof.integrity_or_lsm_label,
        .enabled = (prof.integrity_or_lsm_label != "unconfined"),
        .detail = "Linux Security Module label (/proc/<pid>/attr/current)",
    });

    prof.namespaces.assign(namespaces.begin(), namespaces.end());
    return prof;
}

LinuxTaskStatSample parse_linux_task_stat_sample(std::string_view stat_text) noexcept {
    LinuxTaskStatSample out{};
    const std::size_t rparen = stat_text.rfind(')');
    if (rparen == std::string_view::npos || (rparen + 2) >= stat_text.size()) {
        return out;
    }
    std::string_view rest = stat_text.substr(rparen + 2);
    std::array<std::string_view, 32> fields{};
    std::size_t count = 0;
    while (!rest.empty() && count < fields.size()) {
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t' ||
                                 rest.front() == '\n' || rest.front() == '\r')) {
            rest.remove_prefix(1);
        }
        if (rest.empty()) {
            break;
        }
        std::size_t len = 0;
        while (len < rest.size() && rest[len] != ' ' && rest[len] != '\t' &&
               rest[len] != '\n' && rest[len] != '\r') {
            ++len;
        }
        fields[count++] = rest.substr(0, len);
        rest.remove_prefix(len);
    }

    if (count == 0 || fields[0].empty()) {
        return out;
    }
    out.state_char = fields[0][0];
    out.valid = true;

    // After "(comm)", index 0 is field 3 (state):
    //   index 11 -> field 14 (utime)
    //   index 12 -> field 15 (stime)
    //   index 26 -> field 29 (kstkesp)
    //   index 27 -> field 30 (kstkeip)
    if (count > 11) {
        out.utime_ticks = parse_int<std::uint64_t>(fields[11], 10).value_or(0);
    }
    if (count > 12) {
        out.stime_ticks = parse_int<std::uint64_t>(fields[12], 10).value_or(0);
    }
    if (count > 26) {
        if (const auto esp = parse_int<std::uint64_t>(fields[26], 10);
            esp.has_value() && *esp != 0) {
            out.kstkesp = *esp;
        }
    }
    if (count > 27) {
        if (const auto eip = parse_int<std::uint64_t>(fields[27], 10);
            eip.has_value() && *eip != 0) {
            out.kstkeip = *eip;
        }
    }
    return out;
}

void ThreadCpuTracker::update(std::span<ThreadInfo> threads,
                              std::optional<std::uint64_t> wall_time_ns) {
    const std::uint64_t now_ns = wall_time_ns.value_or(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count()));

    std::unordered_map<ThreadId, Sample> next;
    next.reserve(threads.size());

    for (auto& th : threads) {
        if (!th.user_time_ns.has_value() && !th.kernel_time_ns.has_value()) {
            th.cpu_percent.reset();
            continue;
        }
        const std::uint64_t total_cpu =
            th.user_time_ns.value_or(0) + th.kernel_time_ns.value_or(0);

        if (const auto it = previous_.find(th.tid); it != previous_.end()) {
            const Sample& prev = it->second;
            if (now_ns > prev.wall_ns && total_cpu >= prev.total_cpu_ns) {
                const double dt_wall = static_cast<double>(now_ns - prev.wall_ns);
                const double dt_cpu = static_cast<double>(total_cpu - prev.total_cpu_ns);
                th.cpu_percent = std::clamp((dt_cpu * 100.0) / dt_wall, 0.0, 10000.0);
            } else {
                th.cpu_percent = 0.0;
            }
        } else {
            th.cpu_percent = 0.0;
        }

        next.emplace(th.tid, Sample{.wall_ns = now_ns, .total_cpu_ns = total_cpu});
    }

    previous_ = std::move(next);
}

}  // namespace peelf
