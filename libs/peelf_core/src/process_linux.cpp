#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdint>

#ifdef __linux__

#include "peelf/process.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <unordered_map>

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

namespace peelf {
namespace {

[[nodiscard]] Architecture elf_machine_to_arch(std::uint16_t machine, bool is_64) noexcept {
    switch (machine) {
        case 3:   return Architecture::X86;
        case 62:  return Architecture::X86_64;
        case 40:  return Architecture::ARM;
        case 183: return Architecture::ARM64;
        case 8:   return is_64 ? Architecture::MIPS64 : Architecture::MIPS32;
        case 20:  return Architecture::PowerPC;
        case 21:  return Architecture::PowerPC64;
        case 243: return is_64 ? Architecture::RISCV64 : Architecture::RISCV32;
        default:  return Architecture::Unknown;
    }
}

[[nodiscard]] Architecture host_architecture() noexcept {
#if defined(__x86_64__)
    return Architecture::X86_64;
#elif defined(__i386__)
    return Architecture::X86;
#elif defined(__aarch64__)
    return Architecture::ARM64;
#elif defined(__arm__)
    return Architecture::ARM;
#elif defined(__riscv) && (__riscv_xlen == 64)
    return Architecture::RISCV64;
#else
    return Architecture::Unknown;
#endif
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

[[nodiscard]] std::string lookup_username(std::uint32_t uid,
                                          std::unordered_map<std::uint32_t, std::string>& cache) {
    if (const auto it = cache.find(uid); it != cache.end()) {
        return it->second;
    }
    std::array<char, 1024> buf{};
    struct passwd pwd{};
    struct passwd* result = nullptr;
    std::string name;
    if (::getpwuid_r(static_cast<uid_t>(uid), &pwd, buf.data(), buf.size(), &result) == 0 &&
        result != nullptr && result->pw_name != nullptr) {
        name = result->pw_name;
    } else {
        name = std::to_string(uid);
    }
    cache.emplace(uid, name);
    return name;
}

void detect_exe_arch(const std::filesystem::path& exe_link,
                     Architecture& out_arch,
                     bool& out_is64) {
    out_arch = host_architecture();
    out_is64 = sizeof(void*) == 8;

    std::ifstream in(exe_link, std::ios::binary);
    std::array<std::uint8_t, 64> hdr{};
    if (!in.read(reinterpret_cast<char*>(hdr.data()), static_cast<std::streamsize>(hdr.size())) &&
        in.gcount() < 20) {
        return;
    }
    const auto got = static_cast<std::size_t>(in.gcount());
    const auto fmt = detect_format(std::span<const std::uint8_t>(hdr.data(), got));
    if (fmt == Format::ELF && got >= 20) {
        out_is64 = hdr[4] == 2;
        const bool le = hdr[5] != 2;
        const std::uint16_t machine =
            le ? static_cast<std::uint16_t>(hdr[18] | (hdr[19] << 8))
               : static_cast<std::uint16_t>((hdr[18] << 8) | hdr[19]);
        out_arch = elf_machine_to_arch(machine, out_is64);
    } else if (fmt == Format::PE && got >= 0x40) {
        const std::uint32_t lfanew =
            static_cast<std::uint32_t>(hdr[0x3C]) |
            (static_cast<std::uint32_t>(hdr[0x3D]) << 8) |
            (static_cast<std::uint32_t>(hdr[0x3E]) << 16) |
            (static_cast<std::uint32_t>(hdr[0x3F]) << 24);
        if (static_cast<std::size_t>(lfanew) + 6 <= got) {
            const std::uint16_t machine = static_cast<std::uint16_t>(
                hdr[lfanew + 4] | (hdr[lfanew + 5] << 8));
            if (machine == 0x8664) {
                out_arch = Architecture::X86_64;
                out_is64 = true;
            } else if (machine == 0x014c) {
                out_arch = Architecture::X86;
                out_is64 = false;
            } else if (machine == 0xaa64) {
                out_arch = Architecture::ARM64;
                out_is64 = true;
            }
        }
    }
}

[[nodiscard]] ProcessInfo inspect_linux_process(
    ProcessId pid,
    std::unordered_map<std::uint32_t, std::string>& user_cache) {
    ProcessInfo info;
    info.pid = pid;

    const std::filesystem::path proc_dir = std::filesystem::path("/proc") / std::to_string(pid);

    std::string comm = read_text_file(proc_dir / "comm");
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
        comm.pop_back();
    }
    info.name = std::move(comm);

    std::string cmdline = read_text_file(proc_dir / "cmdline");
    if (!cmdline.empty()) {
        for (char& ch : cmdline) {
            if (ch == '\0') {
                ch = ' ';
            }
        }
        while (!cmdline.empty() && cmdline.back() == ' ') {
            cmdline.pop_back();
        }
        info.command_line = std::move(cmdline);
    }

    std::array<char, 4096> link_buf{};
    const std::string exe_link = (proc_dir / "exe").string();
    const ssize_t link_len = ::readlink(exe_link.c_str(), link_buf.data(), link_buf.size() - 1);
    if (link_len > 0) {
        const std::string_view raw_target(link_buf.data(), static_cast<std::size_t>(link_len));
        info.executable_path = std::filesystem::path(strip_deleted_proc_suffix(raw_target));
        if (info.name.empty()) {
            info.name = info.executable_path.filename().string();
        }
    }

    const std::string status = read_text_file(proc_dir / "status");
    std::istringstream status_stream(status);
    std::string line;
    while (std::getline(status_stream, line)) {
        if (line.starts_with("Name:") && info.name.empty()) {
            std::size_t pos = 5;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
                ++pos;
            }
            info.name = line.substr(pos);
        } else if (line.starts_with("PPid:")) {
            std::size_t pos = 5;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
                ++pos;
            }
            std::uint32_t ppid = 0;
            std::from_chars(line.data() + pos, line.data() + line.size(), ppid);
            info.parent_pid = ppid;
        } else if (line.starts_with("Uid:")) {
            std::size_t pos = 4;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
                ++pos;
            }
            std::uint32_t ruid = 0;
            const auto [ptr, ec] =
                std::from_chars(line.data() + pos, line.data() + line.size(), ruid);
            (void)ptr;
            if (ec == std::errc{}) {
                info.uid = ruid;
                info.user = lookup_username(ruid, user_cache);
            }
        }
    }

    detect_exe_arch(proc_dir / "exe", info.architecture, info.is_64bit);

    const std::string maps_path = (proc_dir / "maps").string();
    const int maps_fd = ::open(maps_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (maps_fd >= 0) {
        ::close(maps_fd);
        const std::string mem_path = (proc_dir / "mem").string();
        const int mem_rw_fd = ::open(mem_path.c_str(), O_RDWR | O_CLOEXEC);
        if (mem_rw_fd >= 0) {
            ::close(mem_rw_fd);
            info.access = ProcessAccessStatus::Accessible;
        } else {
            const int mem_ro_fd = ::open(mem_path.c_str(), O_RDONLY | O_CLOEXEC);
            if (mem_ro_fd >= 0) {
                ::close(mem_ro_fd);
                info.access = ProcessAccessStatus::ReadOnly;
            } else if (errno == ESRCH) {
                info.access = ProcessAccessStatus::Exited;
            } else {
                info.access = ProcessAccessStatus::AccessDenied;
            }
        }
    } else if (errno == ESRCH || errno == ENOENT) {
        info.access = ProcessAccessStatus::Exited;
    } else {
        info.access = ProcessAccessStatus::AccessDenied;
    }

    return info;
}

class LinuxProcessSession final : public IProcessSession {
public:
    explicit LinuxProcessSession(ProcessInfo info) : info_(std::move(info)) {}

    ~LinuxProcessSession() override {
        if (mem_read_fd_ >= 0) {
            ::close(mem_read_fd_);
            mem_read_fd_ = -1;
        }
    }

    LinuxProcessSession(const LinuxProcessSession&) = delete;
    LinuxProcessSession& operator=(const LinuxProcessSession&) = delete;

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return info_; }

    [[nodiscard]] bool is_alive() const noexcept override {
        if (::kill(static_cast<pid_t>(info_.pid), 0) == 0) {
            return true;
        }
        return errno == EPERM;
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        const std::filesystem::path maps_path =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "maps";
        std::ifstream in(maps_path);
        if (!in) {
            return make_error("failed to open /proc/<pid>/maps (permission denied or process exited)");
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = parse_proc_maps(ss.str(), info_.executable_path.string());
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        (void)derive_modules_from_regions(*parsed, info_.executable_path.string(), this);
        return parsed;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        const std::filesystem::path maps_path =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "maps";
        std::ifstream in(maps_path);
        if (!in) {
            return make_error("failed to open /proc/<pid>/maps");
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = parse_proc_maps(ss.str(), info_.executable_path.string());
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        return derive_modules_from_regions(*parsed, info_.executable_path.string(), this);
    }

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        if (address <= static_cast<std::uint64_t>(std::numeric_limits<std::uintptr_t>::max())) {
            struct iovec local_iov{};
            local_iov.iov_base = buffer.data();
            local_iov.iov_len = buffer.size();

            struct iovec remote_iov{};
            remote_iov.iov_base =
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
            remote_iov.iov_len = buffer.size();

            const ssize_t n =
                ::process_vm_readv(static_cast<pid_t>(info_.pid), &local_iov, 1, &remote_iov, 1, 0);
            if (n > 0) {
                return static_cast<std::size_t>(n);
            }
        }

        // Fallback to /proc/<pid>/mem pread (works across self/child and seccomp-filtered containers).
        if (address > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return make_error("virtual address is outside readable /proc/<pid>/mem range");
        }
        const int fd = ensure_mem_read_fd();
        if (fd < 0) {
            return make_error("failed to open /proc/<pid>/mem for reading");
        }

        const ssize_t got =
            ::pread(fd, buffer.data(), buffer.size(), static_cast<off_t>(address));
        if (got <= 0) {
            return make_error(std::string("failed to read process memory: ") +
                              std::strerror(errno));
        }
        return static_cast<std::size_t>(got);
    }

    [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t address,
                                                   std::span<const std::uint8_t> data,
                                                   MemoryWriteOptions options) override {
        if (data.empty()) {
            return std::size_t{0};
        }

        std::size_t written = 0;
        if (address <= static_cast<std::uint64_t>(std::numeric_limits<std::uintptr_t>::max())) {
            struct iovec local_iov{};
            local_iov.iov_base = const_cast<std::uint8_t*>(data.data());
            local_iov.iov_len = data.size();

            struct iovec remote_iov{};
            remote_iov.iov_base =
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
            remote_iov.iov_len = data.size();

            const ssize_t n = ::process_vm_writev(
                static_cast<pid_t>(info_.pid), &local_iov, 1, &remote_iov, 1, 0);
            if (n > 0) {
                written = static_cast<std::size_t>(n);
                if (written == data.size()) {
                    return written;
                }
            } else if (errno == EFAULT && !options.allow_protection_override) {
                return make_error(
                    "target memory region is write-protected and protection override is disabled");
            }
        }

        if (!options.allow_protection_override) {
            // Check if region is non-writable before using /proc/<pid>/mem FOLL_FORCE.
            if (auto regs = memory_regions()) {
                for (const MemoryRegion& reg : *regs) {
                    if (reg.contains(address + written) && !reg.protection.writable) {
                        return make_error(
                            "target memory page is not writable and protection override is disabled");
                    }
                }
            }
        }

        if (address > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) -
                          static_cast<std::uint64_t>(data.size())) {
            return make_error("virtual address overflows /proc/<pid>/mem write range");
        }

        const std::string mem_path =
            (std::filesystem::path("/proc") / std::to_string(info_.pid) / "mem").string();
        int fd = ::open(mem_path.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            fd = ::open(mem_path.c_str(), O_RDWR | O_CLOEXEC);
        }
        if (fd < 0) {
            if (written > 0) {
                return written;
            }
            return make_error(std::string("failed to open /proc/<pid>/mem for writing: ") +
                              std::strerror(errno));
        }

        while (written < data.size()) {
            const ssize_t n = ::pwrite(fd,
                                       data.data() + written,
                                       data.size() - written,
                                       static_cast<off_t>(address + written));
            if (n <= 0) {
                const int saved_err = errno;
                ::close(fd);
                if (written > 0) {
                    return written;
                }
                return make_error(std::string("failed to write process memory: ") +
                                  std::strerror(saved_err));
            }
            written += static_cast<std::size_t>(n);
        }

        ::close(fd);
        return written;
    }

private:
    int ensure_mem_read_fd() {
        if (mem_read_fd_ >= 0) {
            return mem_read_fd_;
        }
        const std::string mem_path =
            (std::filesystem::path("/proc") / std::to_string(info_.pid) / "mem").string();
        mem_read_fd_ = ::open(mem_path.c_str(), O_RDONLY | O_CLOEXEC);
        return mem_read_fd_;
    }

    ProcessInfo info_;
    int mem_read_fd_{-1};
};

class LinuxProcessBackend final : public IProcessBackend {
public:
    Result<std::vector<ProcessInfo>> list_processes() override {
        std::error_code ec;
        std::vector<ProcessInfo> processes;
        std::unordered_map<std::uint32_t, std::string> user_cache;

        for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_directory(ec) || ec) {
                ec.clear();
                continue;
            }
            const std::string fname = entry.path().filename().string();
            if (fname.empty() || !std::ranges::all_of(fname, [](unsigned char c) {
                    return std::isdigit(c) != 0;
                })) {
                continue;
            }
            ProcessId pid = 0;
            const auto [ptr, parse_ec] =
                std::from_chars(fname.data(), fname.data() + fname.size(), pid);
            if (parse_ec != std::errc{} || ptr != fname.data() + fname.size() || pid == 0) {
                continue;
            }

            ProcessInfo info = inspect_linux_process(pid, user_cache);
            if (info.access != ProcessAccessStatus::Exited) {
                processes.push_back(std::move(info));
            }
        }

        std::ranges::sort(processes, [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.pid < b.pid;
        });
        return processes;
    }

    Result<std::unique_ptr<IProcessSession>> open_process(ProcessId pid) override {
        if (pid == 0) {
            return make_error("invalid PID 0");
        }
        std::unordered_map<std::uint32_t, std::string> user_cache;
        ProcessInfo info = inspect_linux_process(pid, user_cache);
        if (info.access == ProcessAccessStatus::Exited) {
            return make_error("process does not exist or has exited");
        }
        if (info.access == ProcessAccessStatus::AccessDenied) {
            return make_error("permission denied opening process (check UID or ptrace_scope)");
        }
        return std::make_unique<LinuxProcessSession>(std::move(info));
    }
};

}  // namespace

std::shared_ptr<IProcessBackend> create_native_process_backend() {
    return std::make_shared<LinuxProcessBackend>();
}

}  // namespace peelf

#endif  // __linux__
