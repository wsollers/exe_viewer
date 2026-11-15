#include <gtest/gtest.h>

#include "model/binary_model.hpp"
#include "peelf/process.hpp"
#include "peelf/process_internals.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

TEST(ProcessInternalsTest, ParsesLinuxFdInfoAndClassifiesOpenHandles) {
    constexpr std::string_view kFileFdInfo =
        "pos:\t4096\n"
        "flags:\t02002002\n"
        "mnt_id:\t31\n"
        "ino:\t987654\n";

    const peelf::LinuxFdInfo info = peelf::parse_linux_fdinfo(kFileFdInfo);
    ASSERT_TRUE(info.pos.has_value());
    EXPECT_EQ(*info.pos, 4096u);
    ASSERT_TRUE(info.raw_flags.has_value());
    EXPECT_EQ(*info.raw_flags, 02002002ULL);
    ASSERT_TRUE(info.mnt_id.has_value());
    EXPECT_EQ(*info.mnt_id, 31);
    ASSERT_TRUE(info.ino.has_value());
    EXPECT_EQ(*info.ino, 987654u);

    const peelf::ProcessHandleEntry file_h =
        peelf::build_linux_fd_entry(3, "/var/log/app.log", kFileFdInfo, false);
    EXPECT_EQ(file_h.handle_or_fd, 3u);
    EXPECT_EQ(file_h.kind, peelf::ProcessHandleKind::File);
    EXPECT_EQ(file_h.access_or_flags, "O_RDWR|O_APPEND|O_CLOEXEC");
    EXPECT_EQ(file_h.offset, 4096u);
    EXPECT_EQ(file_h.inode, 987654u);

    const peelf::ProcessHandleEntry sock_h =
        peelf::build_linux_fd_entry(7, "socket:[445566]", "pos:\t0\nflags:\t02004002\n", false);
    EXPECT_EQ(sock_h.kind, peelf::ProcessHandleKind::Socket);
    EXPECT_EQ(sock_h.inode, 445566u);
    EXPECT_EQ(sock_h.access_or_flags, "O_RDWR|O_NONBLOCK|O_CLOEXEC");

    const peelf::ProcessHandleEntry pipe_h =
        peelf::build_linux_fd_entry(8, "pipe:[112233]", "pos:\t0\nflags:\t00\n", false);
    EXPECT_EQ(pipe_h.kind, peelf::ProcessHandleKind::Pipe);
    EXPECT_EQ(pipe_h.inode, 112233u);
    EXPECT_EQ(pipe_h.access_or_flags, "O_RDONLY");

    const peelf::ProcessHandleEntry anon_h =
        peelf::build_linux_fd_entry(9, "anon_inode:[eventpoll]", "pos:\t0\nflags:\t02000002\n", false);
    EXPECT_EQ(anon_h.kind, peelf::ProcessHandleKind::AnonInode);

    const peelf::ProcessHandleEntry memfd_h =
        peelf::build_linux_fd_entry(10, "/memfd:jit-cache (deleted)", "pos:\t0\nflags:\t02\n", false);
    EXPECT_EQ(memfd_h.kind, peelf::ProcessHandleKind::Memfd);

    const peelf::ProcessHandleEntry dev_h =
        peelf::build_linux_fd_entry(11, "/dev/null", "pos:\t0\nflags:\t01\n", false);
    EXPECT_EQ(dev_h.kind, peelf::ProcessHandleKind::Device);
    EXPECT_EQ(dev_h.access_or_flags, "O_WRONLY");

    const peelf::ProcessHandleEntry dir_h =
        peelf::build_linux_fd_entry(12, "/etc", "pos:\t0\nflags:\t02200000\n", true);
    EXPECT_EQ(dir_h.kind, peelf::ProcessHandleKind::Directory);
    EXPECT_NE(dir_h.access_or_flags.find("O_DIRECTORY"), std::string::npos);
}

TEST(ProcessInternalsTest, ParsesProcNetTcpUdpUnixAndCorrelatesFds) {
    constexpr std::string_view kProcNetTcp =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 445566 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100000A:D1CE 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 999999 1 0000000000000000 20 4 30 10 -1\n";

    constexpr std::string_view kProcNetTcp6 =
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 445567 1 0000000000000000 100 0 0 10 0\n";

    constexpr std::string_view kProcNetUdp =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
        "   5: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 445568 2 0000000000000000 0\n";

    constexpr std::string_view kProcNetUnix =
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 445569 /tmp/peelf_test.sock\n";

    auto tcp4 = peelf::parse_linux_proc_net_inet(kProcNetTcp, peelf::SocketProtocol::Tcp4);
    ASSERT_EQ(tcp4.size(), 2u);
    EXPECT_EQ(tcp4[0].local_endpoint, "127.0.0.1:8080");
    EXPECT_EQ(tcp4[0].remote_endpoint, "0.0.0.0:0");
    EXPECT_EQ(tcp4[0].state, "LISTEN");
    EXPECT_EQ(tcp4[0].inode, 445566u);
    EXPECT_EQ(tcp4[1].local_endpoint, "10.0.0.1:53710");
    EXPECT_EQ(tcp4[1].remote_endpoint, "8.8.8.8:443");
    EXPECT_EQ(tcp4[1].state, "ESTABLISHED");

    auto tcp6 = peelf::parse_linux_proc_net_inet(kProcNetTcp6, peelf::SocketProtocol::Tcp6);
    ASSERT_EQ(tcp6.size(), 1u);
    EXPECT_EQ(tcp6[0].local_endpoint, "[::1]:443");
    EXPECT_EQ(tcp6[0].remote_endpoint, "[::]:0");
    EXPECT_EQ(tcp6[0].state, "LISTEN");
    EXPECT_EQ(tcp6[0].inode, 445567u);

    auto udp4 = peelf::parse_linux_proc_net_inet(kProcNetUdp, peelf::SocketProtocol::Udp4);
    ASSERT_EQ(udp4.size(), 1u);
    EXPECT_EQ(udp4[0].local_endpoint, "0.0.0.0:5353");
    EXPECT_EQ(udp4[0].state, "UNCONNECTED");

    auto unix_s = peelf::parse_linux_proc_net_unix(kProcNetUnix);
    ASSERT_EQ(unix_s.size(), 1u);
    EXPECT_EQ(unix_s[0].local_endpoint, "/tmp/peelf_test.sock");
    EXPECT_EQ(unix_s[0].state, "LISTEN");
    EXPECT_EQ(unix_s[0].inode, 445569u);

    std::vector<peelf::ProcessSocketEntry> combined;
    combined.insert(combined.end(), tcp4.begin(), tcp4.end());
    combined.insert(combined.end(), tcp6.begin(), tcp6.end());
    combined.insert(combined.end(), udp4.begin(), udp4.end());
    combined.insert(combined.end(), unix_s.begin(), unix_s.end());

    const std::vector<peelf::ProcessHandleEntry> handles{
        peelf::build_linux_fd_entry(4, "socket:[445566]", "", false),
        peelf::build_linux_fd_entry(5, "socket:[445567]", "", false),
        peelf::build_linux_fd_entry(6, "socket:[445569]", "", false),
    };

    const auto correlated = peelf::correlate_linux_process_sockets(handles, combined);
    ASSERT_EQ(correlated.size(), 3u);
    EXPECT_EQ(correlated[0].fd, 4u);
    EXPECT_EQ(correlated[0].local_endpoint, "127.0.0.1:8080");
    EXPECT_EQ(correlated[1].fd, 5u);
    EXPECT_EQ(correlated[1].local_endpoint, "[::1]:443");
    EXPECT_EQ(correlated[2].fd, 6u);
    EXPECT_EQ(correlated[2].local_endpoint, "/tmp/peelf_test.sock");
}

TEST(ProcessInternalsTest, DecodesLinuxCapabilitiesSeccompAndSecurityStatus) {
    // CAP_NET_BIND_SERVICE (10), CAP_NET_ADMIN (12), CAP_SYS_PTRACE (19), CAP_BPF (39)
    const std::uint64_t mask =
        (1ULL << 10u) | (1ULL << 12u) | (1ULL << 19u) | (1ULL << 39u);
    const auto names = peelf::decode_linux_capability_mask(mask);
    ASSERT_EQ(names.size(), 4u);
    EXPECT_EQ(names[0], "CAP_NET_BIND_SERVICE");
    EXPECT_EQ(names[1], "CAP_NET_ADMIN");
    EXPECT_EQ(names[2], "CAP_SYS_PTRACE");
    EXPECT_EQ(names[3], "CAP_BPF");

    constexpr std::string_view kStatus =
        "Name:\tworker\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\n"
        "Groups:\t4 24 27 1000\n"
        "NoNewPrivs:\t1\n"
        "Seccomp:\t2\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000008000081400\n"
        "CapEff:\t0000000000080400\n"
        "CapBnd:\t000001ffffffffff\n"
        "CapAmb:\t0000000000000000\n";

    const std::vector<peelf::ProcessNamespaceEntry> ns{
        {.ns_type = "pid", .ns_id = "pid:[4026531836]"},
        {.ns_type = "net", .ns_id = "net:[4026531992]"},
    };
    const auto prof = peelf::parse_linux_security_status(
        kStatus, "docker-default (enforce)\n", "0::/user.slice\n", ns);

    EXPECT_EQ(prof.user_summary, "real=1000 eff=1000 saved=1000 fs=1000");
    ASSERT_TRUE(prof.is_elevated.has_value());
    EXPECT_FALSE(*prof.is_elevated);
    ASSERT_TRUE(prof.no_new_privs.has_value());
    EXPECT_TRUE(*prof.no_new_privs);
    EXPECT_EQ(prof.seccomp_mode, "Filter / BPF (2)");
    EXPECT_EQ(prof.integrity_or_lsm_label, "docker-default (enforce)");
    EXPECT_EQ(prof.namespaces.size(), 2u);
    ASSERT_EQ(prof.capabilities.size(), 4u);

    const auto ptrace_it = std::ranges::find_if(prof.capabilities, [](const auto& c) {
        return c.name == "CAP_SYS_PTRACE";
    });
    ASSERT_NE(ptrace_it, prof.capabilities.end());
    EXPECT_TRUE(ptrace_it->effective);
    EXPECT_TRUE(ptrace_it->permitted);

    const auto bpf_it = std::ranges::find_if(prof.capabilities, [](const auto& c) {
        return c.name == "CAP_BPF";
    });
    ASSERT_NE(bpf_it, prof.capabilities.end());
    EXPECT_FALSE(bpf_it->effective);
    EXPECT_TRUE(bpf_it->permitted);
}

TEST(ProcessInternalsTest, ParsesTaskStatTimesAndComputesThreadCpuDeltas) {
    // comm contains spaces and ')' to verify rfind(')') safety!
    constexpr std::string_view kStat =
        "4242 (pool (worker) 1) S 4200 4200 4200 0 -1 4194368 120 0 0 0 "
        "150 50 0 0 20 0 4 0 98765 12345678 500 18446744073709551615 "
        "0 0 0 140728898420736 94123456789012 0 0 0 0 0 0 0 17 2 0 0 0 0 0";

    const auto sample = peelf::parse_linux_task_stat_sample(kStat);
    ASSERT_TRUE(sample.valid);
    EXPECT_EQ(sample.state_char, 'S');
    EXPECT_EQ(sample.utime_ticks, 150u);
    EXPECT_EQ(sample.stime_ticks, 50u);
    EXPECT_EQ(sample.kstkesp, 140728898420736ULL);
    EXPECT_EQ(sample.kstkeip, 94123456789012ULL);

    peelf::ThreadCpuTracker tracker;
    std::vector<peelf::ThreadInfo> snap1{
        peelf::ThreadInfo{
            .tid = 4242,
            .user_time_ns = 100'000'000ULL,
            .kernel_time_ns = 50'000'000ULL,
        },
    };
    tracker.update(snap1, 1'000'000'000ULL);
    ASSERT_TRUE(snap1[0].cpu_percent.has_value());
    EXPECT_DOUBLE_EQ(*snap1[0].cpu_percent, 0.0);

    // 250 ms CPU elapsed over 500 ms wall time -> 50.0%
    std::vector<peelf::ThreadInfo> snap2{
        peelf::ThreadInfo{
            .tid = 4242,
            .user_time_ns = 300'000'000ULL,
            .kernel_time_ns = 100'000'000ULL,
        },
    };
    tracker.update(snap2, 1'500'000'000ULL);
    ASSERT_TRUE(snap2[0].cpu_percent.has_value());
    EXPECT_NEAR(*snap2[0].cpu_percent, 50.0, 1e-6);
}

#if defined(__linux__)
TEST(ProcessInternalsTest, LiveForkChildHandlesSocketsSecurityAndThreadTelemetry) {
    int ready_pipe[2]{-1, -1};
    int hold_pipe[2]{-1, -1};
    ASSERT_EQ(::pipe(ready_pipe), 0);
    ASSERT_EQ(::pipe(hold_pipe), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);

    if (child == 0) {
        ::close(ready_pipe[0]);
        ::close(hold_pipe[1]);

        const int listen_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        std::uint16_t bound_port = 0;
        if (listen_fd >= 0) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(0);
            if (::bind(listen_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0 &&
                ::listen(listen_fd, 1) == 0) {
                socklen_t alen = sizeof(addr);
                if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &alen) == 0) {
                    bound_port = ntohs(addr.sin_port);
                }
            }
        }

        const int devnull_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        (void)::write(ready_pipe[1], &bound_port, sizeof(bound_port));
        ::close(ready_pipe[1]);

        char ch = 0;
        (void)::read(hold_pipe[0], &ch, 1);

        if (devnull_fd >= 0) {
            ::close(devnull_fd);
        }
        if (listen_fd >= 0) {
            ::close(listen_fd);
        }
        ::close(hold_pipe[0]);
        _exit(0);
    }

    ::close(ready_pipe[1]);
    ::close(hold_pipe[0]);

    std::uint16_t child_port = 0;
    ASSERT_EQ(::read(ready_pipe[0], &child_port, sizeof(child_port)),
              static_cast<ssize_t>(sizeof(child_port)));
    ::close(ready_pipe[0]);

    struct ChildGuard {
        pid_t pid;
        int wake_fd;
        ~ChildGuard() {
            if (wake_fd >= 0) {
                char done = 'x';
                (void)::write(wake_fd, &done, 1);
                ::close(wake_fd);
            }
            int status = 0;
            (void)::waitpid(pid, &status, 0);
        }
    } guard{child, hold_pipe[1]};

    viewer::BinaryModel model;
    ASSERT_TRUE(model.attach_process(static_cast<peelf::ProcessId>(child)).has_value());
    EXPECT_FALSE(model.has_process_internals());  // Strictly lazy until requested!

    model.refresh_process_internals();
    EXPECT_TRUE(model.has_process_internals());
    const auto& snap = model.process_internals();

    ASSERT_TRUE(snap.handles.has_value());
    EXPECT_TRUE(snap.handles.status.has_data());
    const bool has_pipe = std::ranges::any_of(*snap.handles.value, [](const auto& h) {
        return h.kind == peelf::ProcessHandleKind::Pipe;
    });
    const bool has_devnull = std::ranges::any_of(*snap.handles.value, [](const auto& h) {
        return h.kind == peelf::ProcessHandleKind::Device && h.target == "/dev/null";
    });
    EXPECT_TRUE(has_pipe);
    EXPECT_TRUE(has_devnull);

    if (child_port != 0) {
        ASSERT_TRUE(snap.sockets.has_value());
        const std::string expected_ep = "127.0.0.1:" + std::to_string(child_port);
        const auto sock_it = std::ranges::find_if(*snap.sockets.value, [&](const auto& s) {
            return s.protocol == peelf::SocketProtocol::Tcp4 &&
                   s.local_endpoint == expected_ep &&
                   s.state == "LISTEN";
        });
        ASSERT_NE(sock_it, snap.sockets.value->end());
        EXPECT_TRUE(sock_it->fd.has_value());
    }

    ASSERT_TRUE(snap.security.has_value());
    EXPECT_FALSE(snap.security.value->user_summary.empty());
    EXPECT_FALSE(snap.security.value->mitigations.empty());

    ASSERT_FALSE(model.threads().empty());
    const auto& main_th = model.threads().front();
    EXPECT_TRUE(main_th.user_time_ns.has_value());
    EXPECT_TRUE(main_th.kernel_time_ns.has_value());
    EXPECT_TRUE(main_th.cpu_percent.has_value());
    EXPECT_TRUE(main_th.start_address.has_value());
}
#endif

}  // namespace
