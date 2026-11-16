#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdint>

#ifdef __linux__

#include "peelf/endian_reader.hpp"
#include "peelf/process.hpp"
#include "peelf/process_internals.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <asm/prctl.h>
#endif

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
#elif defined(__riscv) && (__riscv_xlen == 32)
    return Architecture::RISCV32;
#elif defined(__powerpc64__)
    return Architecture::PowerPC64;
#elif defined(__powerpc__)
    return Architecture::PowerPC;
#elif defined(__mips64)
    return Architecture::MIPS64;
#elif defined(__mips__)
    return Architecture::MIPS32;
#else
    return Architecture::Unknown;
#endif
}

[[nodiscard]] constexpr Endianness host_endianness() noexcept {
    return std::endian::native == std::endian::big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] ThreadId current_thread_id() noexcept {
    const long tid = ::syscall(SYS_gettid);
    return tid > 0 ? static_cast<ThreadId>(tid) : 0u;
}

struct ProcReadResult {
    std::vector<std::uint8_t> bytes;
    int err{0};
    bool ok{false};
};

[[nodiscard]] ProcReadResult read_proc_binary(const std::filesystem::path& path,
                                              std::size_t max_bytes = 1024u * 1024u) {
    ProcReadResult res;
    const std::string pstr = path.string();
    const int fd = ::open(pstr.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        res.err = errno;
        return res;
    }

    std::array<std::uint8_t, 4096> chunk{};
    while (res.bytes.size() < max_bytes) {
        const std::size_t to_read = std::min(chunk.size(), max_bytes - res.bytes.size());
        const ssize_t got = ::read(fd, chunk.data(), to_read);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            res.err = errno;
            ::close(fd);
            return res;
        }
        if (got == 0) {
            break;
        }
        res.bytes.insert(res.bytes.end(),
                         chunk.begin(),
                         chunk.begin() + static_cast<std::ptrdiff_t>(got));
    }

    ::close(fd);
    res.ok = true;
    return res;
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
    const ProcReadResult raw = read_proc_binary(path, 256u * 1024u);
    if (!raw.ok) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(raw.bytes.data()), raw.bytes.size());
}

[[nodiscard]] std::optional<std::filesystem::path> read_proc_symlink(
    const std::filesystem::path& link_path) {
    std::array<char, 4096> link_buf{};
    const std::string link_str = link_path.string();
    const ssize_t link_len = ::readlink(link_str.c_str(), link_buf.data(), link_buf.size() - 1);
    if (link_len <= 0) {
        return std::nullopt;
    }
    const std::string_view raw_target(link_buf.data(), static_cast<std::size_t>(link_len));
    return std::filesystem::path(strip_deleted_proc_suffix(raw_target));
}

[[nodiscard]] std::string format_display_cmdline(std::string_view raw_cmdline) {
    if (raw_cmdline.empty()) {
        return {};
    }
    const std::vector<std::string> tokens = split_command_line_args(raw_cmdline, false);
    if (tokens.empty()) {
        return {};
    }
    if (tokens.size() == 1) {
        const std::string& single = tokens.front();
        if (single.find_first_of(" \t\"'\\") == std::string::npos) {
            return single;
        }
        // Quote single argv[0] containing whitespace only if raw_cmdline had NUL terminator.
        std::string_view trimmed = raw_cmdline;
        while (!trimmed.empty() && trimmed.back() == '\0') {
            trimmed.remove_suffix(1);
        }
        if (trimmed == single && single.find(' ') != std::string::npos) {
            return "\"" + single + "\"";
        }
    }

    std::string out;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) {
            out.push_back(' ');
        }
        const std::string& tok = tokens[i];
        if (tok.empty()) {
            out += "\"\"";
        } else if (tok.find_first_of(" \t\"") != std::string::npos) {
            out.push_back('"');
            for (const char ch : tok) {
                if (ch == '"' || ch == '\\') {
                    out.push_back('\\');
                }
                out.push_back(ch);
            }
            out.push_back('"');
        } else {
            out += tok;
        }
    }
    return out;
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

[[nodiscard]] bool detect_exe_arch_from_file(const std::filesystem::path& exe_path,
                                             Architecture& out_arch,
                                             bool& out_is64,
                                             Endianness& out_endian) {
    const std::string pstr = exe_path.string();
    const int fd = ::open(pstr.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    std::array<std::uint8_t, 512> hdr{};
    const ssize_t n = ::read(fd, hdr.data(), hdr.size());
    ::close(fd);
    if (n < 20) {
        return false;
    }

    const auto got = static_cast<std::size_t>(n);
    const std::span<const std::uint8_t> span(hdr.data(), got);
    const Format fmt = detect_format(span);
    if (fmt == Format::ELF && got >= 20) {
        out_is64 = (hdr[4] == 2);
        out_endian = (hdr[5] == 2) ? Endianness::Big : Endianness::Little;
        const EndianReader reader(span, out_endian, out_is64 ? AddressWidth::Bits64 : AddressWidth::Bits32);
        if (const auto machine = reader.read_u16(18)) {
            out_arch = elf_machine_to_arch(*machine, out_is64);
            return true;
        }
    } else if (fmt == Format::PE && got >= 0x40) {
        out_endian = Endianness::Little;
        const EndianReader reader(span, Endianness::Little, AddressWidth::Bits64);
        if (const auto lfanew = reader.read_u32(0x3C)) {
            const auto pe_off = static_cast<std::size_t>(*lfanew);
            if (const auto machine = reader.read_u16(pe_off + 4u)) {
                if (*machine == 0x8664u) {
                    out_arch = Architecture::X86_64;
                    out_is64 = true;
                    return true;
                }
                if (*machine == 0x014cu) {
                    out_arch = Architecture::X86;
                    out_is64 = false;
                    return true;
                }
                if (*machine == 0xaa64u) {
                    out_arch = Architecture::ARM64;
                    out_is64 = true;
                    return true;
                }
                if (*machine == 0x01c4u || *machine == 0x01c0u) {
                    out_arch = Architecture::ARM;
                    out_is64 = false;
                    return true;
                }
            }
        }
    }
    return false;
}

[[nodiscard]] ProcessInfo inspect_linux_process(
    ProcessId pid,
    std::unordered_map<std::uint32_t, std::string>& user_cache) {
    ProcessInfo info;
    info.pid = pid;
    info.architecture = host_architecture();
    info.is_64bit = (sizeof(void*) == 8);
    info.endianness = host_endianness();

    const std::filesystem::path proc_dir = std::filesystem::path("/proc") / std::to_string(pid);

    std::string comm = read_text_file(proc_dir / "comm");
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
        comm.pop_back();
    }
    info.name = std::move(comm);

    if (const auto cwd = read_proc_symlink(proc_dir / "cwd")) {
        info.working_directory = *cwd;
    }

    const std::string raw_cmdline = read_text_file(proc_dir / "cmdline");
    if (!raw_cmdline.empty()) {
        info.command_line = format_display_cmdline(raw_cmdline);
    }

    if (const auto exe = read_proc_symlink(proc_dir / "exe")) {
        info.executable_path = *exe;
    } else if (!raw_cmdline.empty()) {
        if (const auto resolved =
                resolve_executable_from_command_line(raw_cmdline, info.working_directory)) {
            info.executable_path = *resolved;
        }
    }

    if (info.name.empty() && !info.executable_path.empty()) {
        info.name = info.executable_path.filename().string();
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

    if (!detect_exe_arch_from_file(
            proc_dir / "exe", info.architecture, info.is_64bit, info.endianness) &&
        !info.executable_path.empty()) {
        (void)detect_exe_arch_from_file(
            info.executable_path, info.architecture, info.is_64bit, info.endianness);
    }

    // Strictly read-only access check: never open /proc/<pid>/mem with O_RDWR or O_WRONLY.
    const std::string maps_path = (proc_dir / "maps").string();
    const int maps_fd = ::open(maps_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (maps_fd >= 0) {
        ::close(maps_fd);
        info.access = ProcessAccessStatus::ReadOnly;
    } else if (errno == ESRCH || errno == ENOENT) {
        info.access = ProcessAccessStatus::Exited;
    } else {
        info.access = ProcessAccessStatus::AccessDenied;
    }

    return info;
}

[[nodiscard]] ThreadRunState decode_proc_stat_state(char state_ch) noexcept {
    switch (state_ch) {
        case 'R': return ThreadRunState::Running;
        case 'S':
        case 'I': return ThreadRunState::Sleeping;
        case 'D': return ThreadRunState::Waiting;
        case 'T':
        case 't': return ThreadRunState::Stopped;
        case 'Z':
        case 'X':
        case 'x': return ThreadRunState::Zombie;
        default:  return ThreadRunState::Unknown;
    }
}

struct ProcTaskStatInfo {
    char state_char{'?'};
    std::optional<std::uint64_t> kstkesp;
    std::optional<std::uint64_t> kstkeip;
    bool valid{false};
};

[[nodiscard]] ProcTaskStatInfo parse_proc_task_stat(std::string_view stat_text) {
    ProcTaskStatInfo out;
    const std::size_t rparen = stat_text.rfind(')');
    if (rparen == std::string_view::npos || (rparen + 2) >= stat_text.size()) {
        return out;
    }
    std::string_view rest = stat_text.substr(rparen + 2);
    std::vector<std::string_view> fields;
    fields.reserve(32);
    while (!rest.empty()) {
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
        fields.push_back(rest.substr(0, len));
        rest.remove_prefix(len);
    }

    if (fields.empty() || fields[0].empty()) {
        return out;
    }
    out.state_char = fields[0][0];
    out.valid = true;

    // Field index 26 after "(comm)" is stat field 29 (kstkesp), 27 is stat field 30 (kstkeip).
    if (fields.size() > 26) {
        std::uint64_t esp = 0;
        const auto [p, ec] =
            std::from_chars(fields[26].data(), fields[26].data() + fields[26].size(), esp, 10);
        (void)p;
        if (ec == std::errc{} && esp != 0) {
            out.kstkesp = esp;
        }
    }
    if (fields.size() > 27) {
        std::uint64_t eip = 0;
        const auto [p, ec] =
            std::from_chars(fields[27].data(), fields[27].data() + fields[27].size(), eip, 10);
        (void)p;
        if (ec == std::errc{} && eip != 0) {
            out.kstkeip = eip;
        }
    }
    return out;
}

struct ProcSyscallSnapshot {
    std::optional<std::int64_t> syscall_nr;
    std::optional<std::uint64_t> stack_pointer;
    std::optional<std::uint64_t> instruction_pointer;
    bool parsed{false};
};

[[nodiscard]] std::optional<std::uint64_t> parse_hex_prefixed_u64(std::string_view tok) noexcept {
    if (tok.starts_with("0x") || tok.starts_with("0X")) {
        tok.remove_prefix(2);
    }
    if (tok.empty()) {
        return std::nullopt;
    }
    std::uint64_t val = 0;
    const auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), val, 16);
    if (ec != std::errc{} || ptr != tok.data() + tok.size()) {
        return std::nullopt;
    }
    return val;
}

[[nodiscard]] ProcSyscallSnapshot parse_proc_task_syscall(std::string_view text) {
    ProcSyscallSnapshot snap;
    std::vector<std::string_view> tokens;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t' ||
                                     text[pos] == '\r' || text[pos] == '\n')) {
            ++pos;
        }
        if (pos >= text.size()) {
            break;
        }
        const std::size_t start = pos;
        while (pos < text.size() && text[pos] != ' ' && text[pos] != '\t' &&
               text[pos] != '\r' && text[pos] != '\n') {
            ++pos;
        }
        tokens.push_back(text.substr(start, pos - start));
    }

    if (tokens.size() < 3) {
        return snap;
    }

    std::int64_t sys_nr = -1;
    const auto [p, ec] =
        std::from_chars(tokens[0].data(), tokens[0].data() + tokens[0].size(), sys_nr, 10);
    if (ec != std::errc{} || p != tokens[0].data() + tokens[0].size()) {
        return snap;
    }
    if (sys_nr >= 0) {
        snap.syscall_nr = sys_nr;
    }

    if (const auto sp = parse_hex_prefixed_u64(tokens[tokens.size() - 2]); sp && *sp != 0) {
        snap.stack_pointer = *sp;
    }
    if (const auto pc = parse_hex_prefixed_u64(tokens[tokens.size() - 1]); pc && *pc != 0) {
        snap.instruction_pointer = *pc;
    }
    snap.parsed = snap.stack_pointer.has_value() || snap.instruction_pointer.has_value();
    return snap;
}

[[nodiscard]] RegisterValue make_reg_u64(std::string name,
                                         RegisterCategory cat,
                                         std::uint64_t val,
                                         Endianness endian) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 64,
        .value_u64 = val,
        .raw_bytes = encode_u64(val, endian),
        .formatted = std::format("0x{:016x}", val),
    };
}

[[nodiscard]] RegisterValue make_reg_u32(std::string name,
                                         RegisterCategory cat,
                                         std::uint32_t val,
                                         Endianness endian) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 32,
        .value_u64 = val,
        .raw_bytes = encode_u32(val, endian),
        .formatted = std::format("0x{:08x}", val),
    };
}

[[nodiscard]] RegisterValue make_reg_u16(std::string name,
                                         RegisterCategory cat,
                                         std::uint16_t val,
                                         Endianness endian) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 16,
        .value_u64 = val,
        .raw_bytes = encode_u16(val, endian),
        .formatted = std::format("0x{:04x}", val),
    };
}

[[nodiscard]] RegisterValue make_reg_vec(std::string name,
                                         RegisterCategory cat,
                                         std::span<const std::uint8_t> bytes) {
    std::string hex = "0x";
    for (std::size_t i = bytes.size(); i > 0; --i) {
        hex += std::format("{:02x}", bytes[i - 1]);
    }
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = static_cast<std::uint16_t>(bytes.size() * 8u),
        .value_u64 = 0,
        .raw_bytes = std::vector<std::uint8_t>(bytes.begin(), bytes.end()),
        .formatted = std::move(hex),
    };
}

[[nodiscard]] std::vector<FlagBitInfo> decode_x86_flags(std::uint64_t flags) {
    struct Spec {
        const char* name;
        std::uint8_t bit;
        const char* desc;
    };
    static constexpr std::array<Spec, 9> kSpecs{{
        {"CF", 0, "Carry Flag"},
        {"PF", 2, "Parity Flag"},
        {"AF", 4, "Auxiliary Carry Flag"},
        {"ZF", 6, "Zero Flag"},
        {"SF", 7, "Sign Flag"},
        {"TF", 8, "Trap Flag"},
        {"IF", 9, "Interrupt Enable Flag"},
        {"DF", 10, "Direction Flag"},
        {"OF", 11, "Overflow Flag"},
    }};
    std::vector<FlagBitInfo> out;
    out.reserve(kSpecs.size());
    for (const Spec& s : kSpecs) {
        out.push_back(FlagBitInfo{
            .name = s.name,
            .bit = s.bit,
            .set = ((flags >> s.bit) & 1ull) != 0,
            .description = s.desc,
        });
    }
    return out;
}

[[nodiscard]] std::vector<FlagBitInfo> decode_arm_nzcv_flags(std::uint64_t flags,
                                                             bool include_thumb) {
    std::vector<FlagBitInfo> out{
        {"N", 31, ((flags >> 31u) & 1ull) != 0, "Negative Condition Flag"},
        {"Z", 30, ((flags >> 30u) & 1ull) != 0, "Zero Condition Flag"},
        {"C", 29, ((flags >> 29u) & 1ull) != 0, "Carry Condition Flag"},
        {"V", 28, ((flags >> 28u) & 1ull) != 0, "Overflow Condition Flag"},
    };
    if (include_thumb) {
        out.push_back({"T", 5, ((flags >> 5u) & 1ull) != 0, "Thumb Execution State"});
    }
    return out;
}

[[nodiscard]] bool decode_prstatus_regset(std::span<const std::uint8_t> reg_bytes,
                                          std::span<const std::uint8_t> fp_bytes,
                                          std::span<const std::uint8_t> tls_bytes,
                                          ThreadContext& ctx) {
    const TargetLayout layout = ctx.layout;
    const Endianness endian = layout.endianness;
    const EndianReader reader(reg_bytes, layout);

    // Handle 32-bit x86 regset even if inspected on an x86_64 host.
    if ((layout.architecture == Architecture::X86_64 && reg_bytes.size() >= 216u)) {
        struct RegSpec {
            const char* name;
            std::size_t idx;
            RegisterCategory cat;
        };
        // Display in canonical architectural order while indexing exact Linux user_regs_struct offsets.
        static constexpr std::array<RegSpec, 25> kX64Regs{{
            {"rax", 10, RegisterCategory::General},
            {"rbx", 5, RegisterCategory::General},
            {"rcx", 11, RegisterCategory::General},
            {"rdx", 12, RegisterCategory::General},
            {"rsi", 13, RegisterCategory::General},
            {"rdi", 14, RegisterCategory::General},
            {"rbp", 4, RegisterCategory::FramePointer},
            {"rsp", 19, RegisterCategory::StackPointer},
            {"r8", 9, RegisterCategory::General},
            {"r9", 8, RegisterCategory::General},
            {"r10", 7, RegisterCategory::General},
            {"r11", 6, RegisterCategory::General},
            {"r12", 3, RegisterCategory::General},
            {"r13", 2, RegisterCategory::General},
            {"r14", 1, RegisterCategory::General},
            {"r15", 0, RegisterCategory::General},
            {"rip", 16, RegisterCategory::InstructionPointer},
            {"rflags", 18, RegisterCategory::Flags},
            {"fs_base", 21, RegisterCategory::SegmentOrTls},
            {"gs_base", 22, RegisterCategory::SegmentOrTls},
            {"cs", 17, RegisterCategory::SegmentOrTls},
            {"ss", 20, RegisterCategory::SegmentOrTls},
            {"ds", 23, RegisterCategory::SegmentOrTls},
            {"es", 24, RegisterCategory::SegmentOrTls},
            {"orig_rax", 15, RegisterCategory::System},
        }};

        for (const RegSpec& spec : kX64Regs) {
            const auto v = reader.read_u64(spec.idx * 8u);
            if (!v) {
                continue;
            }
            ctx.registers.push_back(make_reg_u64(spec.name, spec.cat, *v, endian));
        }

        ctx.instruction_pointer = reader.read_u64(16u * 8u).value_or(0);
        ctx.stack_pointer = reader.read_u64(19u * 8u).value_or(0);
        ctx.frame_pointer = reader.read_u64(4u * 8u).value_or(0);
        const std::uint64_t rflags = reader.read_u64(18u * 8u).value_or(0);
        ctx.flags_value = rflags;
        ctx.decoded_flags = decode_x86_flags(rflags);
        if (const auto fs_base = reader.read_u64(21u * 8u); fs_base && *fs_base != 0) {
            ctx.tls_pointer = *fs_base;
        }

        if (fp_bytes.size() >= 512u) {
            const EndianReader fpr(fp_bytes, layout);
            if (const auto fcw = fpr.read_u16(0)) {
                ctx.registers.push_back(make_reg_u16("fcw", RegisterCategory::FloatingPoint, *fcw, endian));
            }
            if (const auto fsw = fpr.read_u16(2)) {
                ctx.registers.push_back(make_reg_u16("fsw", RegisterCategory::FloatingPoint, *fsw, endian));
            }
            if (const auto mxcsr = fpr.read_u32(24)) {
                ctx.registers.push_back(
                    make_reg_u32("mxcsr", RegisterCategory::FloatingPoint, *mxcsr, endian));
            }
            for (std::size_t xmm = 0; xmm < 16u; ++xmm) {
                const std::size_t off = 160u + xmm * 16u;
                if (off + 16u <= fp_bytes.size()) {
                    ctx.registers.push_back(make_reg_vec(
                        std::format("xmm{}", xmm), RegisterCategory::Vector, fp_bytes.subspan(off, 16u)));
                }
            }
        }
        return true;
    }

    if ((layout.architecture == Architecture::X86 ||
         (layout.architecture == Architecture::X86_64 && reg_bytes.size() == 68u)) &&
        reg_bytes.size() >= 68u) {
        const EndianReader r32(reg_bytes, endian, AddressWidth::Bits32);
        struct RegSpec32 {
            const char* name;
            std::size_t idx;
            RegisterCategory cat;
        };
        static constexpr std::array<RegSpec32, 16> kX86Regs{{
            {"eax", 6, RegisterCategory::General},
            {"ebx", 0, RegisterCategory::General},
            {"ecx", 1, RegisterCategory::General},
            {"edx", 2, RegisterCategory::General},
            {"esi", 3, RegisterCategory::General},
            {"edi", 4, RegisterCategory::General},
            {"ebp", 5, RegisterCategory::FramePointer},
            {"esp", 15, RegisterCategory::StackPointer},
            {"eip", 12, RegisterCategory::InstructionPointer},
            {"eflags", 14, RegisterCategory::Flags},
            {"cs", 13, RegisterCategory::SegmentOrTls},
            {"ss", 16, RegisterCategory::SegmentOrTls},
            {"ds", 7, RegisterCategory::SegmentOrTls},
            {"es", 8, RegisterCategory::SegmentOrTls},
            {"fs", 9, RegisterCategory::SegmentOrTls},
            {"gs", 10, RegisterCategory::SegmentOrTls},
        }};
        for (const RegSpec32& spec : kX86Regs) {
            if (const auto v = r32.read_u32(spec.idx * 4u)) {
                ctx.registers.push_back(make_reg_u32(spec.name, spec.cat, *v, endian));
            }
        }
        ctx.instruction_pointer = r32.read_u32(12u * 4u).value_or(0);
        ctx.stack_pointer = r32.read_u32(15u * 4u).value_or(0);
        ctx.frame_pointer = r32.read_u32(5u * 4u).value_or(0);
        const std::uint32_t eflags = r32.read_u32(14u * 4u).value_or(0);
        ctx.flags_value = eflags;
        ctx.decoded_flags = decode_x86_flags(eflags);

        const std::uint32_t xgs = r32.read_u32(10u * 4u).value_or(0);
        const std::uint32_t gs_entry = xgs >> 3u;
        if (tls_bytes.size() >= 16u) {
            const EndianReader tls_r(tls_bytes, endian, AddressWidth::Bits32);
            for (std::size_t off = 0; off + 16u <= tls_bytes.size(); off += 16u) {
                const std::uint32_t entry_num = tls_r.read_u32(off).value_or(0xFFFFu);
                const std::uint32_t base_addr = tls_r.read_u32(off + 4u).value_or(0);
                if (base_addr != 0 && (entry_num == gs_entry || !ctx.tls_pointer.has_value())) {
                    ctx.tls_pointer = base_addr;
                    if (entry_num == gs_entry) {
                        break;
                    }
                }
            }
        }
        return true;
    }

    if (layout.architecture == Architecture::ARM64 && reg_bytes.size() >= 272u) {
        for (std::size_t i = 0; i < 29u; ++i) {
            if (const auto v = reader.read_u64(i * 8u)) {
                ctx.registers.push_back(
                    make_reg_u64(std::format("x{}", i), RegisterCategory::General, *v, endian));
            }
        }
        const std::uint64_t x29 = reader.read_u64(29u * 8u).value_or(0);
        const std::uint64_t x30 = reader.read_u64(30u * 8u).value_or(0);
        const std::uint64_t sp = reader.read_u64(31u * 8u).value_or(0);
        const std::uint64_t pc = reader.read_u64(32u * 8u).value_or(0);
        const std::uint64_t pstate = reader.read_u64(33u * 8u).value_or(0);

        ctx.registers.push_back(make_reg_u64("x29", RegisterCategory::FramePointer, x29, endian));
        ctx.registers.push_back(make_reg_u64("x30", RegisterCategory::General, x30, endian));
        ctx.registers.push_back(make_reg_u64("sp", RegisterCategory::StackPointer, sp, endian));
        ctx.registers.push_back(make_reg_u64("pc", RegisterCategory::InstructionPointer, pc, endian));
        ctx.registers.push_back(make_reg_u64("pstate", RegisterCategory::Flags, pstate, endian));

        ctx.frame_pointer = x29;
        ctx.link_register = x30;
        ctx.stack_pointer = sp;
        ctx.instruction_pointer = pc;
        ctx.flags_value = pstate;
        ctx.decoded_flags = decode_arm_nzcv_flags(pstate, false);

        if (tls_bytes.size() >= 8u) {
            const EndianReader tr(tls_bytes, layout);
            if (const auto tp = tr.read_u64(0); tp && *tp != 0) {
                ctx.tls_pointer = *tp;
                ctx.registers.push_back(
                    make_reg_u64("tpidr_el0", RegisterCategory::SegmentOrTls, *tp, endian));
            }
        }
        return true;
    }

    if (layout.architecture == Architecture::ARM && reg_bytes.size() >= 68u) {
        const EndianReader r32(reg_bytes, endian, AddressWidth::Bits32);
        for (std::size_t i = 0; i <= 10u; ++i) {
            if (const auto v = r32.read_u32(i * 4u)) {
                ctx.registers.push_back(
                    make_reg_u32(std::format("r{}", i), RegisterCategory::General, *v, endian));
            }
        }
        const std::uint32_t fp = r32.read_u32(11u * 4u).value_or(0);
        const std::uint32_t ip = r32.read_u32(12u * 4u).value_or(0);
        const std::uint32_t sp = r32.read_u32(13u * 4u).value_or(0);
        const std::uint32_t lr = r32.read_u32(14u * 4u).value_or(0);
        const std::uint32_t pc = r32.read_u32(15u * 4u).value_or(0);
        const std::uint32_t cpsr = r32.read_u32(16u * 4u).value_or(0);

        ctx.registers.push_back(make_reg_u32("fp", RegisterCategory::FramePointer, fp, endian));
        ctx.registers.push_back(make_reg_u32("ip", RegisterCategory::General, ip, endian));
        ctx.registers.push_back(make_reg_u32("sp", RegisterCategory::StackPointer, sp, endian));
        ctx.registers.push_back(make_reg_u32("lr", RegisterCategory::General, lr, endian));
        ctx.registers.push_back(make_reg_u32("pc", RegisterCategory::InstructionPointer, pc, endian));
        ctx.registers.push_back(make_reg_u32("cpsr", RegisterCategory::Flags, cpsr, endian));

        ctx.frame_pointer = fp;
        ctx.stack_pointer = sp;
        ctx.link_register = lr;
        ctx.instruction_pointer = pc;
        ctx.flags_value = cpsr;
        ctx.decoded_flags = decode_arm_nzcv_flags(cpsr, true);

        if (tls_bytes.size() >= 4u) {
            const EndianReader tr(tls_bytes, endian, AddressWidth::Bits32);
            if (const auto tp = tr.read_u32(0); tp && *tp != 0) {
                ctx.tls_pointer = *tp;
                ctx.registers.push_back(make_reg_u32("tp", RegisterCategory::SegmentOrTls, *tp, endian));
            }
        }
        return true;
    }

    if ((layout.architecture == Architecture::RISCV64 ||
         layout.architecture == Architecture::RISCV32) &&
        reg_bytes.size() >= 32u * layout.pointer_size()) {
        static constexpr std::array<const char*, 32> kRvNames{{
            "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
            "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
            "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
        }};
        const std::size_t psize = layout.pointer_size();
        for (std::size_t i = 0; i < 32u; ++i) {
            const auto val = reader.read_pointer(i * psize);
            if (!val) {
                continue;
            }
            RegisterCategory cat = RegisterCategory::General;
            if (i == 0) {
                cat = RegisterCategory::InstructionPointer;
                ctx.instruction_pointer = *val;
            } else if (i == 1) {
                ctx.link_register = *val;
            } else if (i == 2) {
                cat = RegisterCategory::StackPointer;
                ctx.stack_pointer = *val;
            } else if (i == 4) {
                cat = RegisterCategory::SegmentOrTls;
                if (*val != 0) {
                    ctx.tls_pointer = *val;
                }
            } else if (i == 8) {
                cat = RegisterCategory::FramePointer;
                ctx.frame_pointer = *val;
            }
            ctx.registers.push_back(layout.is_64bit()
                                        ? make_reg_u64(kRvNames[i], cat, *val, endian)
                                        : make_reg_u32(kRvNames[i],
                                                       cat,
                                                       static_cast<std::uint32_t>(*val),
                                                       endian));
        }
        return true;
    }

    if ((layout.architecture == Architecture::PowerPC64 ||
         layout.architecture == Architecture::PowerPC) &&
        reg_bytes.size() >= 37u * layout.pointer_size()) {
        const std::size_t psize = layout.pointer_size();
        for (std::size_t i = 0; i < 32u; ++i) {
            const auto val = reader.read_pointer(i * psize);
            if (!val) {
                continue;
            }
            RegisterCategory cat = RegisterCategory::General;
            if (i == 1) {
                cat = RegisterCategory::StackPointer;
                ctx.stack_pointer = *val;
                ctx.frame_pointer = *val;
            } else if ((layout.is_64bit() && i == 13) || (!layout.is_64bit() && i == 2)) {
                cat = RegisterCategory::SegmentOrTls;
                if (*val != 0) {
                    ctx.tls_pointer = *val;
                }
            } else if (i == 31) {
                cat = RegisterCategory::FramePointer;
            }
            const std::string rname = std::format("r{}", i);
            ctx.registers.push_back(
                layout.is_64bit()
                    ? make_reg_u64(rname, cat, *val, endian)
                    : make_reg_u32(rname, cat, static_cast<std::uint32_t>(*val), endian));
        }
        if (const auto nip = reader.read_pointer(32u * psize)) {
            ctx.instruction_pointer = *nip;
            ctx.registers.push_back(
                layout.is_64bit()
                    ? make_reg_u64("nip", RegisterCategory::InstructionPointer, *nip, endian)
                    : make_reg_u32("nip",
                                   RegisterCategory::InstructionPointer,
                                   static_cast<std::uint32_t>(*nip),
                                   endian));
        }
        if (const auto msr = reader.read_pointer(33u * psize)) {
            ctx.flags_value = *msr;
            ctx.registers.push_back(
                layout.is_64bit()
                    ? make_reg_u64("msr", RegisterCategory::Flags, *msr, endian)
                    : make_reg_u32("msr", RegisterCategory::Flags, static_cast<std::uint32_t>(*msr), endian));
        }
        if (const auto lr = reader.read_pointer(36u * psize)) {
            ctx.link_register = *lr;
            ctx.registers.push_back(
                layout.is_64bit()
                    ? make_reg_u64("lr", RegisterCategory::General, *lr, endian)
                    : make_reg_u32("lr", RegisterCategory::General, static_cast<std::uint32_t>(*lr), endian));
        }
        return true;
    }

    if ((layout.architecture == Architecture::MIPS64 ||
         layout.architecture == Architecture::MIPS32) &&
        reg_bytes.size() >= 38u * layout.pointer_size()) {
        const std::size_t psize = layout.pointer_size();
        const std::size_t total_slots = reg_bytes.size() / psize;
        const std::size_t base_idx = (total_slots >= 45u) ? 6u : 0u;
        for (std::size_t i = 0; i < 32u && (base_idx + i) < total_slots; ++i) {
            const auto val = reader.read_pointer((base_idx + i) * psize);
            if (!val) {
                continue;
            }
            RegisterCategory cat = RegisterCategory::General;
            if (i == 29) {
                cat = RegisterCategory::StackPointer;
                ctx.stack_pointer = *val;
            } else if (i == 30) {
                cat = RegisterCategory::FramePointer;
                ctx.frame_pointer = *val;
            } else if (i == 31) {
                ctx.link_register = *val;
            }
            const std::string rname = std::format("r{}", i);
            ctx.registers.push_back(
                layout.is_64bit()
                    ? make_reg_u64(rname, cat, *val, endian)
                    : make_reg_u32(rname, cat, static_cast<std::uint32_t>(*val), endian));
        }
        const std::size_t epc_idx = base_idx + 34u;
        if (epc_idx < total_slots) {
            if (const auto epc = reader.read_pointer(epc_idx * psize)) {
                ctx.instruction_pointer = *epc;
                ctx.registers.push_back(
                    layout.is_64bit()
                        ? make_reg_u64("epc", RegisterCategory::InstructionPointer, *epc, endian)
                        : make_reg_u32("epc",
                                       RegisterCategory::InstructionPointer,
                                       static_cast<std::uint32_t>(*epc),
                                       endian));
            }
        }
        return true;
    }

    return false;
}

class LinuxProcessSession final : public IProcessSession {
public:
    explicit LinuxProcessSession(ProcessInfo info) : info_(std::move(info)) {}

    ~LinuxProcessSession() noexcept override {
        if (suspended_ || !suspended_tids_.empty() || process_sigstopped_) {
            try {
                (void)resume();
            } catch (...) {
            }
        }
        if (mem_read_fd_ >= 0) {
            ::close(mem_read_fd_);
            mem_read_fd_ = -1;
        }
    }

    LinuxProcessSession(const LinuxProcessSession&) = delete;
    LinuxProcessSession& operator=(const LinuxProcessSession&) = delete;

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_read_only() const noexcept override { return true; }

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
        const std::filesystem::path proc_dir =
            std::filesystem::path("/proc") / std::to_string(info_.pid);

        Result<std::vector<MemoryRegion>> parsed = make_error("uninitialized");
        const ProcReadResult smaps_raw = read_proc_binary(proc_dir / "smaps", 32u * 1024u * 1024u);
        if (smaps_raw.ok && !smaps_raw.bytes.empty()) {
            const std::string_view smaps_text(
                reinterpret_cast<const char*>(smaps_raw.bytes.data()), smaps_raw.bytes.size());
            parsed = parse_proc_smaps(smaps_text, info_.executable_path.string());
            if (parsed) {
                last_memmap_status_ = SubsystemStatus::available(
                    "/proc/<pid>/smaps",
                    std::to_string(parsed->size()) + " regions with RSS/PSS telemetry");
            }
        }

        if (!parsed) {
            const std::string maps_text = read_text_file(proc_dir / "maps");
            if (maps_text.empty()) {
                return make_error(
                    "failed to open /proc/<pid>/maps (permission denied or process exited)");
            }
            parsed = parse_proc_maps(maps_text, info_.executable_path.string());
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            last_memmap_status_ = SubsystemStatus::partial(
                "/proc/<pid>/maps",
                "/proc/<pid>/smaps unreadable; physical RSS/PSS unavailable");
        }

        (void)derive_modules_from_regions(*parsed, info_.executable_path.string(), this);
        if (auto tlist = threads()) {
            attribute_thread_stacks(*parsed, *tlist, static_cast<ThreadId>(info_.pid));
        } else {
            attribute_thread_stacks(*parsed, {}, static_cast<ThreadId>(info_.pid));
        }
        return parsed;
    }

    [[nodiscard]] ForgivingValue<ProcessMemorySummary> memory_summary(
        std::span<const MemoryRegion> regions) override {
        std::vector<MemoryRegion> owned;
        if (regions.empty()) {
            auto fetched = memory_regions();
            if (!fetched) {
                return {std::nullopt,
                        SubsystemStatus::unavailable("/proc/<pid>/maps", fetched.error().message)};
            }
            owned = std::move(*fetched);
            regions = owned;
        }
        const std::filesystem::path rollup_path =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "smaps_rollup";
        std::string rollup_text;
        const ProcReadResult rollup_raw = read_proc_binary(rollup_path, 64u * 1024u);
        if (rollup_raw.ok && !rollup_raw.bytes.empty()) {
            rollup_text.assign(reinterpret_cast<const char*>(rollup_raw.bytes.data()),
                               rollup_raw.bytes.size());
        }
        ProcessMemorySummary sum = summarize_process_memory(regions, rollup_text);
        SubsystemStatus st = last_memmap_status_;
        if (st.source.empty()) {
            st = sum.rss_bytes.has_value()
                     ? SubsystemStatus::available("/proc/<pid>/smaps", "RSS/PSS telemetry")
                     : SubsystemStatus::partial("/proc/<pid>/maps",
                                                "physical RSS/PSS unavailable");
        } else if (st.availability == Availability::Partial && sum.rss_bytes.has_value()) {
            st = SubsystemStatus::partial(
                "/proc/<pid>/smaps_rollup",
                "aggregate RSS/PSS available via smaps_rollup; per-region smaps unavailable");
        }
        return {std::move(sum), std::move(st)};
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        const std::filesystem::path maps_path =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "maps";
        const std::string maps_text = read_text_file(maps_path);
        if (maps_text.empty()) {
            return make_error("failed to open /proc/<pid>/maps");
        }
        auto parsed = parse_proc_maps(maps_text, info_.executable_path.string());
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

        // Strictly read-only fallback via /proc/<pid>/mem pread (O_RDONLY | O_CLOEXEC).
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

    [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t /*address*/,
                                                   std::span<const std::uint8_t> /*data*/,
                                                   MemoryWriteOptions /*options*/) override {
        return make_error("live process inspection is strictly read-only");
    }

    [[nodiscard]] bool is_suspended() const noexcept override { return suspended_; }

    [[nodiscard]] Result<void> suspend() override {
        if (info_.pid == current_process_id()) {
            return make_error("cannot suspend the inspector process itself");
        }
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        if (suspended_) {
            return {};
        }

        std::string last_err = "no threads found in /proc/<pid>/task";
        std::size_t stopped_count = 0;

        // Two passes catch threads spawned concurrently while the initial set is seizing.
        for (int pass = 0; pass < 2; ++pass) {
            const std::vector<ThreadId> tids = list_task_tids();
            if (tids.empty() && pass == 0) {
                return make_error(last_err);
            }
            // Pre-reserve contiguous tracking capacity before invoking ptrace/tgkill so recording
            // a stopped thread can never fail with std::bad_alloc.
            suspended_tids_.reserve(suspended_tids_.size() + tids.size());

            bool added_in_pass = false;
            for (const ThreadId tid : tids) {
                if (has_suspended_tid(tid)) {
                    continue;
                }
                auto res = stop_single_thread(tid);
                if (res) {
                    ++stopped_count;
                    added_in_pass = true;
                } else {
                    last_err = res.error().message;
                }
            }
            if (!added_in_pass) {
                break;
            }
        }

        if (stopped_count == 0 && suspended_tids_.empty()) {
            return make_error("failed to suspend process: " + last_err);
        }
        suspended_ = !suspended_tids_.empty();
        return {};
    }

    [[nodiscard]] Result<void> resume() override {
        std::size_t write_idx = 0;
        std::size_t failed_count = 0;
        std::string detail;

        for (std::size_t i = 0; i < suspended_tids_.size(); ++i) {
            const SuspendedThreadEntry entry = suspended_tids_[i];
            if (auto r = resume_single_entry(entry); !r.has_value()) {
                suspended_tids_[write_idx++] = entry;
                ++failed_count;
                if (detail.empty()) {
                    detail = std::format("TID {}: {}", entry.tid, r.error().message);
                } else {
                    detail += std::format("; TID {}: {}", entry.tid, r.error().message);
                }
            }
        }
        suspended_tids_.resize(write_idx);

        if (process_sigstopped_) {
            const bool any_sigstop_left = std::ranges::any_of(
                suspended_tids_, [](const SuspendedThreadEntry& e) {
                    return e.mechanism == StopMechanism::SigStop;
                });
            if (::kill(static_cast<pid_t>(info_.pid), SIGCONT) == 0 ||
                (errno == ESRCH && !is_alive())) {
                process_sigstopped_ = any_sigstop_left;
            } else {
                const int err = errno;
                ++failed_count;
                const std::string msg =
                    std::format("PID {}: kill(SIGCONT) failed: {}", info_.pid, std::strerror(err));
                if (detail.empty()) {
                    detail = msg;
                } else {
                    detail += "; " + msg;
                }
            }
        }

        suspended_ = !suspended_tids_.empty() || process_sigstopped_;
        if (failed_count > 0) {
            return make_error(
                std::format("failed to resume {} target(s): {}", failed_count, detail));
        }
        return {};
    }

    [[nodiscard]] Result<void> suspend_thread(ThreadId tid) override {
        if (info_.pid == current_process_id()) {
            return make_error("cannot suspend the inspector process itself");
        }
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        return stop_single_thread(tid);
    }

    [[nodiscard]] Result<void> resume_thread(ThreadId tid) override {
        const auto it = find_suspended_tid(tid);
        if (it == suspended_tids_.end()) {
            return {};
        }
        const StopMechanism mech = it->mechanism;
        if (auto r = resume_single_entry(*it); !r.has_value()) {
            return r;
        }
        if (mech == StopMechanism::PtraceSeize) {
            suspended_tids_.erase(it);
        } else {
            if (process_sigstopped_) {
                if (::kill(static_cast<pid_t>(info_.pid), SIGCONT) == 0 ||
                    (errno == ESRCH && !is_alive())) {
                    process_sigstopped_ = false;
                } else {
                    const int err = errno;
                    return make_error(
                        std::format("kill(SIGCONT) failed: {}", std::strerror(err)));
                }
            }
            std::erase_if(suspended_tids_, [](const SuspendedThreadEntry& e) {
                return e.mechanism == StopMechanism::SigStop;
            });
        }
        suspended_ = !suspended_tids_.empty() || process_sigstopped_;
        return {};
    }

    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        const std::vector<ThreadId> tids = list_task_tids();
        if (tids.empty()) {
            return make_error("failed to enumerate /proc/<pid>/task");
        }

        const std::filesystem::path task_root =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "task";
        const bool is_self_proc = (info_.pid == current_process_id());
        const ThreadId self_tid = is_self_proc ? current_thread_id() : 0u;
        const long clk_tck_raw = ::sysconf(_SC_CLK_TCK);
        const std::uint64_t clk_tck = clk_tck_raw > 0 ? static_cast<std::uint64_t>(clk_tck_raw) : 100u;

        std::optional<std::uint64_t> auxv_entry{};
        {
            std::ifstream aux_ifs(std::filesystem::path("/proc") / std::to_string(info_.pid) / "auxv",
                                  std::ios::in | std::ios::binary);
            if (aux_ifs.is_open()) {
                std::vector<std::uint8_t> aux_bytes((std::istreambuf_iterator<char>(aux_ifs)),
                                                    std::istreambuf_iterator<char>());
                const TargetLayout tl = target_layout();
                const std::size_t word_sz = (tl.address_width == AddressWidth::Bits64) ? 8u : 4u;
                const EndianReader rd(aux_bytes, tl.endianness, tl.address_width);
                for (std::size_t off = 0; off + 2 * word_sz <= aux_bytes.size(); off += 2 * word_sz) {
                    const auto tag = rd.read_pointer(off);
                    const auto val = rd.read_pointer(off + word_sz);
                    if (!tag.has_value() || !val.has_value() || *tag == 0) {
                        break;
                    }
                    if (*tag == 9u && *val != 0) {  // AT_ENTRY
                        auxv_entry = *val;
                        break;
                    }
                }
            }
        }

        std::vector<ThreadInfo> out;
        out.reserve(tids.size());
        for (const ThreadId tid : tids) {
            ThreadInfo ti;
            ti.tid = tid;
            const std::filesystem::path tdir = task_root / std::to_string(tid);

            std::string comm = read_text_file(tdir / "comm");
            while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
                comm.pop_back();
            }
            ti.name = std::move(comm);

            const LinuxTaskStatSample stat_sample =
                parse_linux_task_stat_sample(read_text_file(tdir / "stat"));
            if (stat_sample.valid) {
                ti.state = decode_proc_stat_state(stat_sample.state_char);
                ti.is_suspended = (stat_sample.state_char == 'T' || stat_sample.state_char == 't' ||
                                   has_suspended_tid(tid) || suspended_);
                ti.stack_pointer = stat_sample.kstkesp;
                ti.instruction_pointer = stat_sample.kstkeip;
                ti.user_time_ns = (stat_sample.utime_ticks * 1'000'000'000ULL) / clk_tck;
                ti.kernel_time_ns = (stat_sample.stime_ticks * 1'000'000'000ULL) / clk_tck;
            }
            if (static_cast<ProcessId>(tid) == info_.pid && auxv_entry.has_value()) {
                ti.start_address = auxv_entry;
            }

            std::string wchan = read_text_file(tdir / "wchan");
            while (!wchan.empty() && (wchan.back() == '\n' || wchan.back() == '\r' ||
                                      wchan.back() == ' ' || wchan.back() == '\0')) {
                wchan.pop_back();
            }
            if (!wchan.empty() && wchan != "0") {
                ti.wait_channel = std::move(wchan);
            }

            const ProcSyscallSnapshot sys_snap =
                parse_proc_task_syscall(read_text_file(tdir / "syscall"));
            if (sys_snap.syscall_nr.has_value()) {
                ti.syscall_number = sys_snap.syscall_nr;
            }
            if (sys_snap.stack_pointer.has_value()) {
                ti.stack_pointer = sys_snap.stack_pointer;
            }
            if (sys_snap.instruction_pointer.has_value()) {
                ti.instruction_pointer = sys_snap.instruction_pointer;
            }

            // If this thread is already ptrace-stopped by this session, enrich exact IP/SP/TLS.
            if (const auto stop_it = find_suspended_tid(tid);
                stop_it != suspended_tids_.end() &&
                stop_it->mechanism == StopMechanism::PtraceSeize) {
                ThreadContext stopped_ctx;
                stopped_ctx.tid = tid;
                stopped_ctx.layout = target_layout();
                if (capture_ptrace_regsets(tid, stopped_ctx)) {
                    if (stopped_ctx.instruction_pointer != 0) {
                        ti.instruction_pointer = stopped_ctx.instruction_pointer;
                    }
                    if (stopped_ctx.stack_pointer != 0) {
                        ti.stack_pointer = stopped_ctx.stack_pointer;
                    }
                    ti.tls_base = stopped_ctx.tls_pointer;
                }
            } else if (is_self_proc && tid == self_tid) {
                std::uint64_t sp_anchor = 0;
                ti.stack_pointer =
                    static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&sp_anchor));
                ti.instruction_pointer = static_cast<std::uint64_t>(
                    reinterpret_cast<std::uintptr_t>(__builtin_return_address(0)));
#if defined(__x86_64__)
                unsigned long fs_val = 0;
                if (::syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_val) == 0 && fs_val != 0) {
                    ti.tls_base = static_cast<std::uint64_t>(fs_val);
                }
#elif defined(__aarch64__) || defined(__riscv)
                if (const void* tp = __builtin_thread_pointer(); tp != nullptr) {
                    ti.tls_base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(tp));
                }
#endif
            }

            if (ti.instruction_pointer.has_value() && ti.stack_pointer.has_value()) {
                ti.status = SubsystemStatus::available(
                    "/proc/<pid>/task", "thread state and instruction/stack pointers available");
            } else if (stat_sample.valid) {
                ti.status = SubsystemStatus::partial(
                    "/proc/<pid>/task",
                    "thread state available; pause process or enable ptrace for exact live registers");
            } else {
                ti.status = SubsystemStatus::unavailable(
                    "/proc/<pid>/task", "thread exited or /proc/<pid>/task/<tid>/stat unreadable");
            }

            out.push_back(std::move(ti));
        }

        return out;
    }

    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        ThreadContext ctx;
        ctx.tid = tid;
        ctx.layout = target_layout();

        if (!is_alive()) {
            ctx.status = SubsystemStatus::unavailable("process", "target process has exited");
            return ctx;
        }

        // Cooperative self-thread snapshot when inspecting our own process (ptrace cannot attach to self).
        if (info_.pid == current_process_id()) {
            if (tid == current_thread_id()) {
                populate_self_calling_thread_context(ctx);
                return ctx;
            }
            populate_procfs_fallback_context(
                tid,
                ctx,
                "same-process thread (Linux forbids ptrace within the same thread group); "
                "recovered available pointers from /proc/self/task");
            return ctx;
        }

        // Tier 1: Thread is already ptrace-seized by this session.
        if (const auto it = find_suspended_tid(tid);
            it != suspended_tids_.end() && it->mechanism == StopMechanism::PtraceSeize) {
            if (capture_ptrace_regsets(tid, ctx)) {
                ctx.status = SubsystemStatus::available("ptrace(NT_PRSTATUS)", "full register set");
                return ctx;
            }
        }

        // Tier 2: Transient PTRACE_SEIZE + PTRACE_INTERRUPT + PTRACE_GETREGSET + RAII PTRACE_DETACH.
        std::string ptrace_reason = "ptrace unavailable";
        if (::ptrace(PTRACE_SEIZE, static_cast<pid_t>(tid), nullptr, nullptr) == 0) {
            struct ScopedDetach {
                pid_t target_tid;
                ~ScopedDetach() { (void)::ptrace(PTRACE_DETACH, target_tid, nullptr, nullptr); }
            } detach_guard{static_cast<pid_t>(tid)};

            if (::ptrace(PTRACE_INTERRUPT, static_cast<pid_t>(tid), nullptr, nullptr) == 0 &&
                wait_for_ptrace_stop(tid, 250)) {
                if (capture_ptrace_regsets(tid, ctx)) {
                    ctx.status = SubsystemStatus::available(
                        "ptrace(NT_PRSTATUS)", "captured register snapshot via transient seize");
                    return ctx;
                }
                ptrace_reason = "PTRACE_GETREGSET failed for target architecture";
            } else {
                ptrace_reason = std::string("PTRACE_INTERRUPT failed: ") + std::strerror(errno);
            }
        } else {
            const int saved_err = errno;
            if (saved_err == EPERM || saved_err == EACCES) {
                ptrace_reason =
                    "ptrace denied (check /proc/sys/kernel/yama/ptrace_scope or CAP_SYS_PTRACE)";
            } else {
                ptrace_reason = std::string("PTRACE_SEIZE failed: ") + std::strerror(saved_err);
            }
        }

        // Tier 3: Forgiving fallback to /proc/<pid>/task/<tid>/syscall + stat.
        populate_procfs_fallback_context(tid, ctx, ptrace_reason);
        return ctx;
    }

    [[nodiscard]] ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
        const std::filesystem::path p =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "auxv";
        ProcReadResult r = read_proc_binary(p, 64u * 1024u);
        if (!r.ok) {
            return {std::nullopt,
                    SubsystemStatus::unavailable("/proc/<pid>/auxv", std::strerror(r.err))};
        }
        if (r.bytes.empty()) {
            return {std::move(r.bytes),
                    SubsystemStatus::partial("/proc/<pid>/auxv", "auxv readable but empty")};
        }
        const std::string det = std::to_string(r.bytes.size()) + " bytes";
        return {std::move(r.bytes), SubsystemStatus::available("/proc/<pid>/auxv", det)};
    }

    [[nodiscard]] ForgivingValue<std::string> proc_status_text() override {
        const std::filesystem::path p =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "status";
        const ProcReadResult r = read_proc_binary(p, 256u * 1024u);
        if (!r.ok) {
            return {std::nullopt,
                    SubsystemStatus::unavailable("/proc/<pid>/status", std::strerror(r.err))};
        }
        std::string text(reinterpret_cast<const char*>(r.bytes.data()), r.bytes.size());
        return {std::move(text),
                SubsystemStatus::available("/proc/<pid>/status",
                                           std::to_string(r.bytes.size()) + " bytes")};
    }

    [[nodiscard]] ForgivingValue<std::vector<std::string>> environment_variables() override {
        const std::filesystem::path p =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "environ";
        const ProcReadResult r = read_proc_binary(p, 256u * 1024u);
        if (!r.ok) {
            return {std::nullopt,
                    SubsystemStatus::unavailable("/proc/<pid>/environ", std::strerror(r.err))};
        }

        constexpr std::size_t kMaxEnvEntries = 512u;
        std::vector<std::string> entries;
        std::size_t start = 0;
        bool truncated = false;
        const std::string_view raw(reinterpret_cast<const char*>(r.bytes.data()), r.bytes.size());
        while (start < raw.size()) {
            const std::size_t nul = raw.find('\0', start);
            const std::string_view item =
                (nul == std::string_view::npos) ? raw.substr(start) : raw.substr(start, nul - start);
            if (!item.empty()) {
                if (entries.size() >= kMaxEnvEntries) {
                    truncated = true;
                    break;
                }
                entries.emplace_back(item);
            }
            if (nul == std::string_view::npos) {
                break;
            }
            start = nul + 1;
        }

        if (truncated) {
            return {std::move(entries),
                    SubsystemStatus::partial("/proc/<pid>/environ",
                                             "capped at 512 environment variables")};
        }
        const std::string det = std::to_string(entries.size()) + " entries";
        return {std::move(entries), SubsystemStatus::available("/proc/<pid>/environ", det)};
    }

private:
    enum class StopMechanism : std::uint8_t {
        PtraceSeize,
        SigStop,
    };

    SubsystemStatus last_memmap_status_{};

    int ensure_mem_read_fd() {
        if (mem_read_fd_ >= 0) {
            return mem_read_fd_;
        }
        const std::string mem_path =
            (std::filesystem::path("/proc") / std::to_string(info_.pid) / "mem").string();
        mem_read_fd_ = ::open(mem_path.c_str(), O_RDONLY | O_CLOEXEC);
        return mem_read_fd_;
    }

    [[nodiscard]] std::vector<ThreadId> list_task_tids() const {
        std::error_code ec;
        std::vector<ThreadId> tids;
        const std::filesystem::path task_dir =
            std::filesystem::path("/proc") / std::to_string(info_.pid) / "task";
        for (const auto& entry : std::filesystem::directory_iterator(task_dir, ec)) {
            if (ec) {
                break;
            }
            const std::string name = entry.path().filename().string();
            ThreadId tid = 0;
            const auto [ptr, parse_ec] =
                std::from_chars(name.data(), name.data() + name.size(), tid, 10);
            if (parse_ec == std::errc{} && ptr == name.data() + name.size() && tid > 0) {
                tids.push_back(tid);
            }
        }
        std::ranges::sort(tids);
        return tids;
    }

    [[nodiscard]] static bool wait_for_ptrace_stop(ThreadId tid, int timeout_ms) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            int wstatus = 0;
            const pid_t w = ::waitpid(static_cast<pid_t>(tid), &wstatus, __WALL | WNOHANG);
            if (w == static_cast<pid_t>(tid)) {
                return WIFSTOPPED(wstatus);
            }
            if (w < 0 && errno != EINTR) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    }

    void wait_for_proc_stop_state(ThreadId tid, int timeout_ms) const {
        const std::filesystem::path stat_path = std::filesystem::path("/proc") /
                                                std::to_string(info_.pid) / "task" /
                                                std::to_string(tid) / "stat";
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            const ProcTaskStatInfo st = parse_proc_task_stat(read_text_file(stat_path));
            if (!st.valid || st.state_char == 'T' || st.state_char == 't' || st.state_char == 'Z') {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    struct SuspendedThreadEntry {
        ThreadId tid{0};
        StopMechanism mechanism{StopMechanism::PtraceSeize};
    };

    [[nodiscard]] std::vector<SuspendedThreadEntry>::iterator find_suspended_tid(
        ThreadId tid) noexcept {
        return std::ranges::find(suspended_tids_, tid, &SuspendedThreadEntry::tid);
    }

    [[nodiscard]] std::vector<SuspendedThreadEntry>::const_iterator find_suspended_tid(
        ThreadId tid) const noexcept {
        return std::ranges::find(suspended_tids_, tid, &SuspendedThreadEntry::tid);
    }

    [[nodiscard]] bool has_suspended_tid(ThreadId tid) const noexcept {
        return find_suspended_tid(tid) != suspended_tids_.end();
    }

    [[nodiscard]] bool is_thread_still_present(ThreadId tid) const {
        const std::filesystem::path stat_path = std::filesystem::path("/proc") /
                                                std::to_string(info_.pid) / "task" /
                                                std::to_string(tid) / "stat";
        const ProcTaskStatInfo st = parse_proc_task_stat(read_text_file(stat_path));
        if (!st.valid) {
            return false;
        }
        return st.state_char != 'Z' && st.state_char != 'X' && st.state_char != 'x';
    }

    [[nodiscard]] Result<void> resume_single_entry(const SuspendedThreadEntry& entry) {
        if (entry.mechanism == StopMechanism::PtraceSeize) {
            if (::ptrace(PTRACE_DETACH, static_cast<pid_t>(entry.tid), nullptr, nullptr) == 0) {
                return {};
            }
            const int err = errno;
            if (err == ESRCH && !is_thread_still_present(entry.tid)) {
                return {};
            }
            return make_error(
                std::format("ptrace(PTRACE_DETACH) failed: {}", std::strerror(err)));
        }

        if (::syscall(
                SYS_tgkill, static_cast<pid_t>(info_.pid), static_cast<pid_t>(entry.tid), SIGCONT) ==
            0) {
            return {};
        }
        const int err = errno;
        if (err == ESRCH && !is_thread_still_present(entry.tid)) {
            return {};
        }
        return make_error(std::format("tgkill(SIGCONT) failed: {}", std::strerror(err)));
    }

    [[nodiscard]] Result<void> stop_single_thread(ThreadId tid) {
        if (has_suspended_tid(tid)) {
            return {};
        }

        // Pre-reserve contiguous capacity BEFORE OS ptrace/tgkill so tracking push_back cannot throw.
        suspended_tids_.reserve(suspended_tids_.size() + 1u);

        if (::ptrace(PTRACE_SEIZE, static_cast<pid_t>(tid), nullptr, nullptr) == 0) {
            if (::ptrace(PTRACE_INTERRUPT, static_cast<pid_t>(tid), nullptr, nullptr) == 0 &&
                wait_for_ptrace_stop(tid, 250)) {
                suspended_tids_.push_back(SuspendedThreadEntry{tid, StopMechanism::PtraceSeize});
                return {};
            }
            (void)::ptrace(PTRACE_DETACH, static_cast<pid_t>(tid), nullptr, nullptr);
        } else if (errno == ESRCH) {
            return make_error("thread has already exited");
        }

        // Fallback to SIGSTOP when ptrace is restricted (e.g. yama/ptrace_scope >= 1).
        if (::syscall(SYS_tgkill, static_cast<pid_t>(info_.pid), static_cast<pid_t>(tid), SIGSTOP) ==
                0 ||
            ::kill(static_cast<pid_t>(info_.pid), SIGSTOP) == 0) {
            wait_for_proc_stop_state(tid, 250);
            suspended_tids_.push_back(SuspendedThreadEntry{tid, StopMechanism::SigStop});
            process_sigstopped_ = true;
            return {};
        }

        return make_error(std::string("failed to stop thread: ") + std::strerror(errno));
    }

    [[nodiscard]] static std::vector<std::uint8_t> fetch_regset_note(ThreadId tid,
                                                                     std::uintptr_t note_type,
                                                                     std::size_t max_size) {
        std::vector<std::uint8_t> buf(max_size, 0);
        struct iovec iov{};
        iov.iov_base = buf.data();
        iov.iov_len = buf.size();
        if (::ptrace(PTRACE_GETREGSET,
                     static_cast<pid_t>(tid),
                     reinterpret_cast<void*>(note_type),
                     &iov) != 0 ||
            iov.iov_len == 0) {
            return {};
        }
        buf.resize(iov.iov_len);
        return buf;
    }

    [[nodiscard]] bool capture_ptrace_regsets(ThreadId tid, ThreadContext& ctx) const {
        constexpr std::uintptr_t kNtPrStatus = 1u;
        constexpr std::uintptr_t kNtFpRegset = 2u;
        constexpr std::uintptr_t kNt386Tls = 0x200u;
        constexpr std::uintptr_t kNtArmTls = 0x401u;

        const std::vector<std::uint8_t> gprs = fetch_regset_note(tid, kNtPrStatus, 1024u);
        if (gprs.empty()) {
            return false;
        }
        const std::vector<std::uint8_t> fprs = fetch_regset_note(tid, kNtFpRegset, 1024u);
        std::vector<std::uint8_t> tls_note;
        if (ctx.layout.architecture == Architecture::ARM64 ||
            ctx.layout.architecture == Architecture::ARM) {
            tls_note = fetch_regset_note(tid, kNtArmTls, 32u);
        } else if (ctx.layout.architecture == Architecture::X86 || gprs.size() == 68u) {
            tls_note = fetch_regset_note(tid, kNt386Tls, 256u);
        }

        if (!decode_prstatus_regset(gprs, fprs, tls_note, ctx)) {
            return false;
        }
        return true;
    }

    void populate_self_calling_thread_context(ThreadContext& ctx) const {
        std::uint64_t sp_anchor = 0;
        const auto sp_val =
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&sp_anchor));
        const auto fp_val = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0)));
        const auto ip_val = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(__builtin_return_address(0)));

        ctx.instruction_pointer = ip_val;
        ctx.stack_pointer = sp_val;
        ctx.frame_pointer = fp_val;

        const Endianness endian = ctx.layout.endianness;
        const bool is64 = ctx.layout.is_64bit();
        const auto push_ptr_reg = [&](const char* name, RegisterCategory cat, std::uint64_t v) {
            ctx.registers.push_back(
                is64 ? make_reg_u64(name, cat, v, endian)
                     : make_reg_u32(name, cat, static_cast<std::uint32_t>(v), endian));
        };

        if (ctx.layout.architecture == Architecture::X86_64) {
            push_ptr_reg("rip", RegisterCategory::InstructionPointer, ip_val);
            push_ptr_reg("rsp", RegisterCategory::StackPointer, sp_val);
            push_ptr_reg("rbp", RegisterCategory::FramePointer, fp_val);
#if defined(__x86_64__)
            unsigned long fs_val = 0;
            if (::syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_val) == 0 && fs_val != 0) {
                ctx.tls_pointer = static_cast<std::uint64_t>(fs_val);
                push_ptr_reg("fs_base", RegisterCategory::SegmentOrTls, *ctx.tls_pointer);
            }
#endif
        } else {
            push_ptr_reg("pc", RegisterCategory::InstructionPointer, ip_val);
            push_ptr_reg("sp", RegisterCategory::StackPointer, sp_val);
            push_ptr_reg("fp", RegisterCategory::FramePointer, fp_val);
#if defined(__aarch64__) || defined(__riscv)
            if (const void* tp = __builtin_thread_pointer(); tp != nullptr) {
                ctx.tls_pointer = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(tp));
                push_ptr_reg("tp", RegisterCategory::SegmentOrTls, *ctx.tls_pointer);
            }
#endif
        }

        ctx.status = SubsystemStatus::partial(
            "self-cooperative",
            "inspector self-thread snapshot (ptrace skipped on self; live IP/SP/FP/TLS captured)");
    }

    void populate_procfs_fallback_context(ThreadId tid,
                                          ThreadContext& ctx,
                                          std::string_view reason) const {
        const std::filesystem::path tdir = std::filesystem::path("/proc") /
                                           std::to_string(info_.pid) / "task" /
                                           std::to_string(tid);
        const ProcTaskStatInfo stat_info = parse_proc_task_stat(read_text_file(tdir / "stat"));
        const ProcSyscallSnapshot sys_snap =
            parse_proc_task_syscall(read_text_file(tdir / "syscall"));

        const std::optional<std::uint64_t> ip =
            sys_snap.instruction_pointer ? sys_snap.instruction_pointer : stat_info.kstkeip;
        const std::optional<std::uint64_t> sp =
            sys_snap.stack_pointer ? sys_snap.stack_pointer : stat_info.kstkesp;

        const Endianness endian = ctx.layout.endianness;
        const bool is64 = ctx.layout.is_64bit();
        const char* ip_name = (ctx.layout.architecture == Architecture::X86_64)
                                  ? "rip"
                                  : (ctx.layout.architecture == Architecture::X86 ? "eip" : "pc");
        const char* sp_name = (ctx.layout.architecture == Architecture::X86_64)
                                  ? "rsp"
                                  : (ctx.layout.architecture == Architecture::X86 ? "esp" : "sp");

        if (ip.has_value()) {
            ctx.instruction_pointer = *ip;
            ctx.registers.push_back(
                is64 ? make_reg_u64(ip_name, RegisterCategory::InstructionPointer, *ip, endian)
                     : make_reg_u32(ip_name,
                                    RegisterCategory::InstructionPointer,
                                    static_cast<std::uint32_t>(*ip),
                                    endian));
        }
        if (sp.has_value()) {
            ctx.stack_pointer = *sp;
            ctx.registers.push_back(
                is64 ? make_reg_u64(sp_name, RegisterCategory::StackPointer, *sp, endian)
                     : make_reg_u32(sp_name,
                                    RegisterCategory::StackPointer,
                                    static_cast<std::uint32_t>(*sp),
                                    endian));
        }

        if (ip.has_value() || sp.has_value()) {
            ctx.status = SubsystemStatus::partial(
                "/proc/<pid>/task/<tid>/syscall",
                std::string(reason) + "; recovered partial IP/SP from procfs");
        } else {
            ctx.status = SubsystemStatus::unavailable(
                "ptrace+procfs",
                std::string(reason) + " and /proc/<pid>/task/<tid>/syscall unavailable");
        }
    }

    ProcessInfo info_;
    int mem_read_fd_{-1};
    std::vector<SuspendedThreadEntry> suspended_tids_;
    bool process_sigstopped_{false};
    bool suspended_{false};
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
