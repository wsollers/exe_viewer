#include "peelf/process_internals.hpp"
#include "peelf/crash_dump.hpp"
#include "peelf/gdb_remote.hpp"

#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {
namespace {

constexpr std::size_t kMaxWin32HandlesPerProcess = 4096;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004L);
constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kObjectTypeInformationClass = 2;

struct UnicodeStringCompat {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct ObjectTypeInformationCompat {
    UnicodeStringCompat TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    BYTE Reserved[128];
};

struct SystemHandleTableEntryInfoExCompat {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SystemHandleInformationExCompat {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleTableEntryInfoExCompat Handles[1];
};

using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObjectFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using GetExtendedTcpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
using GetExtendedUdpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);

struct ScopedHandle {
    HANDLE h{nullptr};
    ScopedHandle() noexcept = default;
    explicit ScopedHandle(HANDLE in) noexcept : h(in) {}
    ~ScopedHandle() noexcept { reset(); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept : h(std::exchange(other.h, nullptr)) {}
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.h, nullptr));
        }
        return *this;
    }
    [[nodiscard]] bool valid() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    void reset(HANDLE next = nullptr) noexcept {
        if (valid()) {
            ::CloseHandle(h);
        }
        h = next;
    }
};

class ScopedModule {
public:
    ScopedModule() noexcept = default;
    explicit ScopedModule(HMODULE mod) noexcept : mod_(mod) {}
    ~ScopedModule() noexcept { reset(); }
    ScopedModule(const ScopedModule&) = delete;
    ScopedModule& operator=(const ScopedModule&) = delete;
    ScopedModule(ScopedModule&& other) noexcept : mod_(std::exchange(other.mod_, nullptr)) {}
    ScopedModule& operator=(ScopedModule&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.mod_, nullptr));
        }
        return *this;
    }
    [[nodiscard]] HMODULE get() const noexcept { return mod_; }
    [[nodiscard]] explicit operator bool() const noexcept { return mod_ != nullptr; }
    void reset(HMODULE next = nullptr) noexcept {
        if (mod_ != nullptr) {
            ::FreeLibrary(mod_);
        }
        mod_ = next;
    }

private:
    HMODULE mod_{nullptr};
};

class ScopedLocalMem {
public:
    ScopedLocalMem() noexcept = default;
    explicit ScopedLocalMem(HLOCAL ptr) noexcept : ptr_(ptr) {}
    ~ScopedLocalMem() noexcept { reset(); }
    ScopedLocalMem(const ScopedLocalMem&) = delete;
    ScopedLocalMem& operator=(const ScopedLocalMem&) = delete;
    ScopedLocalMem(ScopedLocalMem&& other) noexcept : ptr_(std::exchange(other.ptr_, nullptr)) {}
    ScopedLocalMem& operator=(ScopedLocalMem&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.ptr_, nullptr));
        }
        return *this;
    }
    void reset(HLOCAL next = nullptr) noexcept {
        if (ptr_ != nullptr) {
            ::LocalFree(ptr_);
        }
        ptr_ = next;
    }

private:
    HLOCAL ptr_{nullptr};
};

[[nodiscard]] std::string wide_to_utf8_len(const wchar_t* wstr, int wlen) {
    if (wstr == nullptr || wlen <= 0) {
        return {};
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, out.data(), needed, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::string wide_to_utf8_z(const wchar_t* wstr) {
    if (wstr == nullptr || *wstr == L'\0') {
        return {};
    }
    return wide_to_utf8_len(wstr, static_cast<int>(::wcslen(wstr)));
}

[[nodiscard]] ProcessHandleKind classify_win32_handle_type(std::string_view type_name) noexcept {
    if (type_name == "File") {
        return ProcessHandleKind::File;
    }
    if (type_name == "Directory") {
        return ProcessHandleKind::Directory;
    }
    if (type_name == "Key") {
        return ProcessHandleKind::KeyOrRegistry;
    }
    if (type_name == "Process" || type_name == "Thread" || type_name == "Job") {
        return ProcessHandleKind::ProcessOrThread;
    }
    if (type_name == "Event" || type_name == "Mutant" || type_name == "Semaphore" ||
        type_name == "Timer" || type_name == "WaitCompletionPacket" ||
        type_name == "IoCompletion" || type_name == "ALPC Port") {
        return ProcessHandleKind::SyncObject;
    }
    if (type_name == "Section") {
        return ProcessHandleKind::Memfd;
    }
    return ProcessHandleKind::Unknown;
}

[[nodiscard]] std::string format_win32_ipv4(DWORD net_order_ip, DWORD net_order_port) {
    IN_ADDR addr{};
    addr.S_un.S_addr = net_order_ip;
    std::array<char, INET_ADDRSTRLEN> ip_buf{};
    const std::string_view ip_str =
        ::inet_ntop(AF_INET, &addr, ip_buf.data(), ip_buf.size()) != nullptr
            ? std::string_view(ip_buf.data())
            : std::string_view("0.0.0.0");
    const unsigned port = ::ntohs(static_cast<u_short>(net_order_port));
    return std::format("{}:{}", ip_str, port);
}

[[nodiscard]] std::string format_win32_ipv6(const UCHAR ip6[16], DWORD net_order_port) {
    IN6_ADDR addr{};
    std::copy_n(ip6, 16, addr.u.Byte);
    std::array<char, INET6_ADDRSTRLEN> ip_buf{};
    const std::string_view ip_str =
        ::inet_ntop(AF_INET6, &addr, ip_buf.data(), ip_buf.size()) != nullptr
            ? std::string_view(ip_buf.data())
            : std::string_view("::");
    const unsigned port = ::ntohs(static_cast<u_short>(net_order_port));
    return std::format("[{}]:{}", ip_str, port);
}

[[nodiscard]] std::string win32_tcp_state_name(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RECV";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
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
    if (const auto* remote = dynamic_cast<const IGdbRemoteSession*>(&session); remote != nullptr) {
        return remote->process_internals();
    }

    ProcessInternalsSnapshot snap{};
    const DWORD pid = static_cast<DWORD>(session.pid());

    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto nt_query_sys = ntdll != nullptr
        ? reinterpret_cast<NtQuerySystemInformationFn>(
              reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQuerySystemInformation")))
        : nullptr;
    const auto nt_query_obj = ntdll != nullptr
        ? reinterpret_cast<NtQueryObjectFn>(
              reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQueryObject")))
        : nullptr;

    ScopedHandle proc_dup(::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        pid));
    ScopedHandle proc_query(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));

    if (proc_query.valid()) {
        DWORD hcount = 0;
        if (::GetProcessHandleCount(proc_query.h, &hcount) != FALSE) {
            snap.total_os_handle_count = static_cast<std::uint32_t>(hcount);
        }
    }

    // 1. Open Handles (NtQuerySystemInformation(SystemExtendedHandleInformation))
    if (nt_query_sys == nullptr) {
        snap.handles.status =
            SubsystemStatus::unavailable("NtQuerySystemInformation", "ntdll export unavailable");
    } else {
        ULONG buf_size = 1u << 20;  // 1 MiB initial buffer
        std::vector<std::uint8_t> buffer(buf_size);
        LONG status = 0;
        for (int attempt = 0; attempt < 8; ++attempt) {
            ULONG ret_len = 0;
            status = nt_query_sys(
                kSystemExtendedHandleInformation, buffer.data(), buf_size, &ret_len);
            if (status != kStatusInfoLengthMismatch) {
                break;
            }
            buf_size = (std::max)(buf_size * 2u, ret_len + 65536u);
            if (buf_size > (256u << 20)) {
                break;
            }
            buffer.resize(buf_size);
        }

        if (status < 0) {
            snap.handles.status = SubsystemStatus::unavailable(
                "SystemExtendedHandleInformation", "NtQuerySystemInformation failed");
        } else {
            const auto* table =
                reinterpret_cast<const SystemHandleInformationExCompat*>(buffer.data());
            std::vector<ProcessHandleEntry> entries;
            bool capped = false;

            for (ULONG_PTR i = 0; i < table->NumberOfHandles; ++i) {
                const auto& raw = table->Handles[i];
                if (raw.UniqueProcessId != static_cast<ULONG_PTR>(pid)) {
                    continue;
                }
                if (entries.size() >= kMaxWin32HandlesPerProcess) {
                    capped = true;
                    break;
                }

                ProcessHandleEntry entry{};
                entry.handle_or_fd = static_cast<std::uint64_t>(raw.HandleValue);
                entry.access_or_flags =
                    std::format("0x{:08X}", static_cast<std::uint32_t>(raw.GrantedAccess));

                if (proc_dup.valid() && nt_query_obj != nullptr) {
                    HANDLE dup = nullptr;
                    if (::DuplicateHandle(proc_dup.h,
                                          reinterpret_cast<HANDLE>(raw.HandleValue),
                                          ::GetCurrentProcess(),
                                          &dup,
                                          0,
                                          FALSE,
                                          DUPLICATE_SAME_ACCESS) != FALSE) {
                        ScopedHandle dup_guard(dup);
                        std::array<std::uint8_t, 1024> type_buf{};
                        ULONG ret = 0;
                        if (nt_query_obj(dup_guard.h,
                                         kObjectTypeInformationClass,
                                         type_buf.data(),
                                         static_cast<ULONG>(type_buf.size()),
                                         &ret) >= 0) {
                            const auto* ti = reinterpret_cast<const ObjectTypeInformationCompat*>(
                                type_buf.data());
                            entry.type_name = wide_to_utf8_len(
                                ti->TypeName.Buffer,
                                static_cast<int>(ti->TypeName.Length / sizeof(wchar_t)));
                            entry.kind = classify_win32_handle_type(entry.type_name);
                        }

                        // Deadlock-safe: NEVER query names on FILE_TYPE_PIPE / FILE_TYPE_CHAR.
                        if (entry.kind == ProcessHandleKind::File) {
                            const DWORD ftype = ::GetFileType(dup_guard.h);
                            if (ftype == FILE_TYPE_DISK) {
                                std::array<wchar_t, 512> path_buf{};
                                const DWORD n = ::GetFinalPathNameByHandleW(
                                    dup_guard.h,
                                    path_buf.data(),
                                    static_cast<DWORD>(path_buf.size()),
                                    VOLUME_NAME_DOS);
                                if (n > 0 && n < path_buf.size()) {
                                    entry.target = wide_to_utf8_len(path_buf.data(),
                                                                    static_cast<int>(n));
                                }
                            } else if (ftype == FILE_TYPE_PIPE) {
                                entry.kind = ProcessHandleKind::Pipe;
                                entry.target = "<pipe/socket handle>";
                            } else if (ftype == FILE_TYPE_CHAR) {
                                entry.kind = ProcessHandleKind::Device;
                                entry.target = "<char device>";
                            }
                        }
                    }
                }
                if (entry.type_name.empty()) {
                    entry.type_name = "Type#" + std::to_string(raw.ObjectTypeIndex);
                }
                entries.push_back(std::move(entry));
            }

            const std::size_t h_count = entries.size();
            snap.handles.value = std::move(entries);
            if (!proc_dup.valid() || capped) {
                snap.handles.status = SubsystemStatus::partial(
                    "SystemExtendedHandleInformation",
                    std::to_string(h_count) +
                        " handles enumerated (PROCESS_DUP_HANDLE restricted or capped)");
            } else {
                snap.handles.status = SubsystemStatus::available(
                    "SystemExtendedHandleInformation",
                    std::to_string(h_count) + " handles inspected");
            }
        }
    }

    // 2. Network Sockets (iphlpapi.dll GetExtendedTcpTable / GetExtendedUdpTable)
    {
        const ScopedModule iphlp(::LoadLibraryW(L"iphlpapi.dll"));
        const auto get_tcp = iphlp
            ? reinterpret_cast<GetExtendedTcpTableFn>(
                  reinterpret_cast<void*>(::GetProcAddress(iphlp.get(), "GetExtendedTcpTable")))
            : nullptr;
        const auto get_udp = iphlp
            ? reinterpret_cast<GetExtendedUdpTableFn>(
                  reinterpret_cast<void*>(::GetProcAddress(iphlp.get(), "GetExtendedUdpTable")))
            : nullptr;

        if (get_tcp == nullptr || get_udp == nullptr) {
            snap.sockets.status = SubsystemStatus::unavailable(
                "iphlpapi", "GetExtendedTcpTable/GetExtendedUdpTable unavailable");
        } else {
            std::vector<ProcessSocketEntry> socks;

            // TCPv4
            {
                DWORD sz = 0;
                (void)get_tcp(nullptr, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (sz > 0) {
                    std::vector<std::uint8_t> buf(sz);
                    if (get_tcp(buf.data(), &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
                        NO_ERROR) {
                        const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
                        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                            const auto& r = tbl->table[i];
                            if (r.dwOwningPid == pid) {
                                socks.push_back(ProcessSocketEntry{
                                    .protocol = SocketProtocol::Tcp4,
                                    .local_endpoint = format_win32_ipv4(r.dwLocalAddr, r.dwLocalPort),
                                    .remote_endpoint = format_win32_ipv4(r.dwRemoteAddr, r.dwRemotePort),
                                    .state = win32_tcp_state_name(r.dwState),
                                });
                            }
                        }
                    }
                }
            }
            // TCPv6
            {
                DWORD sz = 0;
                (void)get_tcp(nullptr, &sz, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                if (sz > 0) {
                    std::vector<std::uint8_t> buf(sz);
                    if (get_tcp(buf.data(), &sz, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) ==
                        NO_ERROR) {
                        const auto* tbl = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                            const auto& r = tbl->table[i];
                            if (r.dwOwningPid == pid) {
                                socks.push_back(ProcessSocketEntry{
                                    .protocol = SocketProtocol::Tcp6,
                                    .local_endpoint = format_win32_ipv6(r.ucLocalAddr, r.dwLocalPort),
                                    .remote_endpoint = format_win32_ipv6(r.ucRemoteAddr, r.dwRemotePort),
                                    .state = win32_tcp_state_name(r.dwState),
                                });
                            }
                        }
                    }
                }
            }
            // UDPv4
            {
                DWORD sz = 0;
                (void)get_udp(nullptr, &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
                if (sz > 0) {
                    std::vector<std::uint8_t> buf(sz);
                    if (get_udp(buf.data(), &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) ==
                        NO_ERROR) {
                        const auto* tbl = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
                        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                            const auto& r = tbl->table[i];
                            if (r.dwOwningPid == pid) {
                                socks.push_back(ProcessSocketEntry{
                                    .protocol = SocketProtocol::Udp4,
                                    .local_endpoint = format_win32_ipv4(r.dwLocalAddr, r.dwLocalPort),
                                    .remote_endpoint = "*:*",
                                    .state = "UNCONNECTED",
                                });
                            }
                        }
                    }
                }
            }
            // UDPv6
            {
                DWORD sz = 0;
                (void)get_udp(nullptr, &sz, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                if (sz > 0) {
                    std::vector<std::uint8_t> buf(sz);
                    if (get_udp(buf.data(), &sz, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) ==
                        NO_ERROR) {
                        const auto* tbl = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
                        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                            const auto& r = tbl->table[i];
                            if (r.dwOwningPid == pid) {
                                socks.push_back(ProcessSocketEntry{
                                    .protocol = SocketProtocol::Udp6,
                                    .local_endpoint = format_win32_ipv6(r.ucLocalAddr, r.dwLocalPort),
                                    .remote_endpoint = "*:*",
                                    .state = "UNCONNECTED",
                                });
                            }
                        }
                    }
                }
            }

            const std::size_t s_count = socks.size();
            snap.sockets.value = std::move(socks);
            snap.sockets.status = SubsystemStatus::available(
                "iphlpapi", std::to_string(s_count) + " TCP/UDP endpoints");
        }
    }

    // 3. Security Token, Integrity, Privileges & Mitigations
    if (!proc_query.valid()) {
        snap.security.status = SubsystemStatus::unavailable(
            "OpenProcess", "PROCESS_QUERY_LIMITED_INFORMATION denied");
    } else {
        ProcessSecurityProfile prof{};
        HANDLE raw_tok = nullptr;
        const bool has_token = (::OpenProcessToken(proc_query.h, TOKEN_QUERY, &raw_tok) != FALSE);
        ScopedHandle tok(raw_tok);

        if (tok.valid()) {
            // TokenUser
            DWORD len = 0;
            (void)::GetTokenInformation(tok.h, TokenUser, nullptr, 0, &len);
            if (len > 0) {
                std::vector<std::uint8_t> buf(len);
                if (::GetTokenInformation(tok.h, TokenUser, buf.data(), len, &len) != FALSE) {
                    const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
                    LPWSTR sid_str = nullptr;
                    std::string sid_utf8;
                    if (::ConvertSidToStringSidW(tu->User.Sid, &sid_str) != FALSE && sid_str != nullptr) {
                        const ScopedLocalMem sid_guard(sid_str);
                        sid_utf8 = wide_to_utf8_z(sid_str);
                    }
                    std::array<wchar_t, 256> name_buf{};
                    std::array<wchar_t, 256> dom_buf{};
                    DWORD name_cch = static_cast<DWORD>(name_buf.size());
                    DWORD dom_cch = static_cast<DWORD>(dom_buf.size());
                    SID_NAME_USE use = SidTypeUnknown;
                    if (::LookupAccountSidW(nullptr,
                                            tu->User.Sid,
                                            name_buf.data(),
                                            &name_cch,
                                            dom_buf.data(),
                                            &dom_cch,
                                            &use) != FALSE) {
                        prof.user_summary = wide_to_utf8_z(dom_buf.data()) + "\\" +
                                            wide_to_utf8_z(name_buf.data()) + " (" + sid_utf8 + ")";
                    } else {
                        prof.user_summary = sid_utf8;
                    }
                }
            }

            // TokenIntegrityLevel
            len = 0;
            (void)::GetTokenInformation(tok.h, TokenIntegrityLevel, nullptr, 0, &len);
            if (len > 0) {
                std::vector<std::uint8_t> buf(len);
                if (::GetTokenInformation(tok.h, TokenIntegrityLevel, buf.data(), len, &len) != FALSE) {
                    const auto* til = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buf.data());
                    const UCHAR count = *::GetSidSubAuthorityCount(til->Label.Sid);
                    if (count > 0) {
                        const DWORD rid = *::GetSidSubAuthority(til->Label.Sid, count - 1u);
                        if (rid < SECURITY_MANDATORY_LOW_RID) {
                            prof.integrity_or_lsm_label = "Untrusted";
                        } else if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
                            prof.integrity_or_lsm_label = "Low";
                        } else if (rid < SECURITY_MANDATORY_HIGH_RID) {
                            prof.integrity_or_lsm_label = "Medium";
                        } else if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
                            prof.integrity_or_lsm_label = "High";
                        } else {
                            prof.integrity_or_lsm_label = "System";
                        }
                    }
                }
            }

            // TokenElevation
            TOKEN_ELEVATION elev{};
            len = sizeof(elev);
            if (::GetTokenInformation(tok.h, TokenElevation, &elev, sizeof(elev), &len) != FALSE) {
                prof.is_elevated = (elev.TokenIsElevated != 0);
            }

            // TokenPrivileges
            len = 0;
            (void)::GetTokenInformation(tok.h, TokenPrivileges, nullptr, 0, &len);
            if (len > 0) {
                std::vector<std::uint8_t> buf(len);
                if (::GetTokenInformation(tok.h, TokenPrivileges, buf.data(), len, &len) != FALSE) {
                    const auto* privs = reinterpret_cast<const TOKEN_PRIVILEGES*>(buf.data());
                    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
                        LUID luid = privs->Privileges[i].Luid;
                        const DWORD attr = privs->Privileges[i].Attributes;
                        std::array<wchar_t, 256> pbuf{};
                        DWORD pcch = static_cast<DWORD>(pbuf.size());
                        if (::LookupPrivilegeNameW(nullptr, &luid, pbuf.data(), &pcch) != FALSE) {
                            prof.capabilities.push_back(SecurityCapabilityEntry{
                                .name = wide_to_utf8_len(pbuf.data(), static_cast<int>(pcch)),
                                .id = static_cast<std::uint32_t>(luid.LowPart),
                                .effective = (attr & SE_PRIVILEGE_ENABLED) != 0,
                                .permitted = true,
                                .inheritable = (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0,
                            });
                        }
                    }
                }
            }
        }

        // Process Mitigations
        PROCESS_MITIGATION_DEP_POLICY dep{};
        if (::GetProcessMitigationPolicy(proc_query.h, ProcessDEPPolicy, &dep, sizeof(dep)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "DEP",
                .state = dep.Enable ? (dep.Permanent ? "Enabled (Permanent)" : "Enabled") : "Disabled",
                .enabled = (dep.Enable != 0),
                .detail = "Data Execution Prevention",
            });
        }
        PROCESS_MITIGATION_ASLR_POLICY aslr{};
        if (::GetProcessMitigationPolicy(proc_query.h, ProcessASLRPolicy, &aslr, sizeof(aslr)) != FALSE) {
            const bool on = aslr.EnableBottomUpRandomization || aslr.EnableHighEntropy;
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "ASLR",
                .state = aslr.EnableHighEntropy ? "High-Entropy ASLR"
                                                : (on ? "Bottom-Up ASLR" : "Disabled"),
                .enabled = on,
                .detail = aslr.EnableForceRelocateImages ? "Force-relocate images" : "Standard relocation",
            });
        }
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "CFG",
                .state = cfg.EnableControlFlowGuard ? "Enabled" : "Disabled",
                .enabled = (cfg.EnableControlFlowGuard != 0),
                .detail = cfg.StrictMode ? "Strict Control Flow Guard" : "Control Flow Guard",
            });
        }
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyncode{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessDynamicCodePolicy, &dyncode, sizeof(dyncode)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "DynamicCode",
                .state = dyncode.ProhibitDynamicCode ? "Prohibited (ACG)" : "Allowed",
                .enabled = (dyncode.ProhibitDynamicCode != 0),
                .detail = "Arbitrary Code Guard",
            });
        }
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessExtensionPointDisablePolicy, &ext, sizeof(ext)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "ExtensionPointDisable",
                .state = ext.DisableExtensionPoints ? "Disabled (Hardened)" : "Allowed",
                .enabled = (ext.DisableExtensionPoints != 0),
                .detail = "AppInit_DLLs / global hooks",
            });
        }
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessSignaturePolicy, &sig, sizeof(sig)) != FALSE) {
            const bool on = sig.MicrosoftSignedOnly || sig.StoreSignedOnly;
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "BinarySignature",
                .state = sig.MicrosoftSignedOnly ? "Microsoft Signed Only"
                                                 : (sig.StoreSignedOnly ? "Store Signed Only" : "Unrestricted"),
                .enabled = on,
                .detail = "DLL code-signing policy",
            });
        }
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY shc{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessStrictHandleCheckPolicy, &shc, sizeof(shc)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "StrictHandleCheck",
                .state = shc.RaiseExceptionOnInvalidHandleReference ? "Strict" : "Standard",
                .enabled = (shc.RaiseExceptionOnInvalidHandleReference != 0),
                .detail = "Invalid handle exception enforcement",
            });
        }
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY scd{};
        if (::GetProcessMitigationPolicy(
                proc_query.h, ProcessSystemCallDisablePolicy, &scd, sizeof(scd)) != FALSE) {
            prof.mitigations.push_back(ProcessMitigationEntry{
                .policy = "SystemCallDisable",
                .state = scd.DisallowWin32kSystemCalls ? "Win32k Disallowed" : "Allowed",
                .enabled = (scd.DisallowWin32kSystemCalls != 0),
                .detail = "Win32k syscall surface lock",
            });
        }

        snap.security.value = std::move(prof);
        snap.security.status = has_token
            ? SubsystemStatus::available("Token+Mitigations", "Win32 token, integrity, privileges & mitigations read")
            : SubsystemStatus::partial("Mitigations", "OpenProcessToken denied; mitigations read");
    }

    return snap;
}

}  // namespace peelf

#elif !defined(__linux__)

namespace peelf {

ProcessInternalsSnapshot inspect_process_internals(IProcessSession&) {
    ProcessInternalsSnapshot snap{};
    snap.handles.status =
        SubsystemStatus::unavailable("unsupported", "process internals unavailable on this OS");
    snap.sockets.status =
        SubsystemStatus::unavailable("unsupported", "socket inspection unavailable on this OS");
    snap.security.status =
        SubsystemStatus::unavailable("unsupported", "security profile unavailable on this OS");
    return snap;
}

}  // namespace peelf

#endif
