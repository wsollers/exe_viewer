#include "decompiler.hpp"
#include <peelf/sha256.hpp>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace viewer {
DecompiledUnit AnnotatedCodeDecompiler::decompile(const DecompileRequest& request, std::stop_token stop) const {
    DecompiledUnit unit{DecompileStatus::Ready,"Annotated code (not decompiled)","Instruction semantics are not lifted to C. Select Ghidra or Binary Ninja for decompilation."};
    for (const auto& node : request.fallback_graph.nodes) {
        if (stop.stop_requested()) { unit.status=DecompileStatus::Cancelled; unit.lines.clear(); return unit; }
        if (node.instructions.empty()) continue;
        unit.lines.push_back({node.bytes.start.virtual_address,node.label + ":"});
        for (const auto& instruction : node.instructions)
            unit.lines.push_back({instruction.address, std::format("    {} {}",instruction.mnemonic,instruction.operands)});
        for (const auto& edge : request.fallback_graph.edges) if (edge.from_node_id == node.id)
            unit.lines.push_back({std::nullopt,"    // " + edge.label + " -> " + edge.to_node_id});
    }
    if (unit.lines.empty()) { unit.status=DecompileStatus::NoFunction; unit.diagnostic="No decoded function is available"; }
    return unit;
}
DecompiledUnit parse_decompiler_output(std::string_view text) {
    DecompiledUnit unit; unit.provider="Binary Ninja HLIL";
    if (text.size()>4*1024*1024) { unit.diagnostic="Backend output exceeds 4 MiB"; return unit; }
    std::istringstream in{std::string(text)}; std::string magic,status; int version = 0;
    const auto read_unsigned = [&in](std::uint64_t& value) {
        std::string token;
        if (!(in >> token)) return false;
        const auto [end, error] = std::from_chars(token.data(), token.data()+token.size(), value);
        return error == std::errc{} && end == token.data()+token.size();
    };
    if (!(in>>magic>>version>>status>>std::quoted(unit.diagnostic)) || magic!="PEELF_DECOMPILE" || version<1 || version>3) { unit.diagnostic="Malformed backend response"; return unit; }
    if (status=="unavailable") unit.status=DecompileStatus::Unavailable;
    else if (status=="unsupported") unit.status=DecompileStatus::Unsupported;
    else if (status=="no_function") unit.status=DecompileStatus::NoFunction;
    else if (status=="failed") unit.status=DecompileStatus::Failed;
    else if (status=="ready") unit.status=DecompileStatus::Ready;
    else if (status=="timeout") unit.status=DecompileStatus::Timeout;
    else if (status=="cancelled") unit.status=DecompileStatus::Cancelled;
    else { unit.diagnostic="Unknown backend status"; return unit; }
    std::uint64_t count_u64 = 0;
    if (!read_unsigned(count_u64) || count_u64>100000u) { unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend line count"; return unit; }
    const auto count = static_cast<std::size_t>(count_u64);
    for (std::size_t i=0;i<count;++i) {
        if (version == 3) {
            DecompiledLine line; std::uint64_t ranges_u64=0;
            if (!read_unsigned(ranges_u64) || ranges_u64>4096u) return {DecompileStatus::Failed,unit.provider,"Invalid code range count"};
            const auto ranges = static_cast<std::size_t>(ranges_u64);
            for (std::size_t r=0;r<ranges;++r) {
                CodeRange range;
                if (!read_unsigned(range.address) || !read_unsigned(range.size) || !range.size || range.size>1048576 ||
                    range.address>std::numeric_limits<std::uint64_t>::max()-range.size)
                    return {DecompileStatus::Failed,unit.provider,"Invalid code byte range"};
                line.ranges.push_back(range);
            }
            if (!(in>>std::quoted(line.text))) return {DecompileStatus::Failed,unit.provider,"Truncated code line"};
            if (!line.ranges.empty()) line.address=line.ranges.front().address;
            unit.lines.push_back(std::move(line)); continue;
        }
        std::string address, line;
        if (!(in>>address>>std::quoted(line))) { unit.status=DecompileStatus::Failed; unit.diagnostic="Truncated backend lines"; unit.lines.clear(); return unit; }
        std::optional<std::uint64_t> mapped;
        if (address != "-" || version != 2) {
            std::uint64_t value{};
            const auto [end, error] = std::from_chars(address.data(), address.data()+address.size(), value);
            if (error != std::errc{} || end != address.data()+address.size()) {
                unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend address"; unit.lines.clear(); return unit;
            }
            mapped = value;
        }
        unit.lines.push_back({mapped,std::move(line)});
    }
    if (version == 3) {
        std::uint64_t types_u64=0;
        if (!read_unsigned(types_u64) || types_u64>10000u) return {DecompileStatus::Failed,unit.provider,"Invalid structure count"};
        const auto types = static_cast<std::size_t>(types_u64);
        for (std::size_t t=0;t<types;++t) {
            DataTypeRecord type;
            std::uint64_t is_union_u64 = 0;
            std::uint64_t members_u64 = 0;
            if (!(in>>std::quoted(type.name)) || type.name.empty() ||
                !read_unsigned(type.size) || !read_unsigned(is_union_u64) || !read_unsigned(members_u64) ||
                is_union_u64>1u || members_u64>4096u || type.size>16777216u)
                return {DecompileStatus::Failed,unit.provider,"Invalid structure record"};
            type.is_union = (is_union_u64 != 0u);
            const auto members = static_cast<std::size_t>(members_u64);
            for (std::size_t m=0;m<members;++m) {
                DataMember member;
                if (!read_unsigned(member.offset) || !read_unsigned(member.size) ||
                    !(in>>std::quoted(member.name)>>std::quoted(member.type)) ||
                    member.offset>type.size || member.size>type.size-member.offset)
                    return {DecompileStatus::Failed,unit.provider,"Invalid structure member"};
                type.members.push_back(std::move(member));
            }
            unit.types.push_back(std::move(type));
        }
    }
    in>>std::ws;
    if (!in.eof() || (unit.status==DecompileStatus::Ready && unit.lines.empty())) { unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend response"; unit.lines.clear(); }
    return unit;
}
BackendProcessResult BackendRunner::run(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout,std::stop_token stop) const {
    if(stop.stop_requested()) return {-1,false,true};
#ifdef _WIN32
    auto quote=[](const std::wstring& value) {
        std::wstring output=L"\""; std::size_t slashes=0;
        for(auto c:value) { if(c==L'\\') { ++slashes; continue; } output.append(slashes*(c==L'"'?2:1),L'\\'); slashes=0; if(c==L'"') output+=L'\\'; output+=c; }
        output.append(slashes*2,L'\\'); output+=L'"'; return output;
    };
    auto command=quote(executable.wstring());
    for(const auto& arg:arguments) { command+=L' '; command+=quote(std::filesystem::path(arg).wstring()); }
    STARTUPINFOW startup{}; startup.cb=sizeof(startup); PROCESS_INFORMATION process{};
    struct ScopedWinHandle {
        HANDLE h{nullptr};
        ScopedWinHandle() noexcept = default;
        explicit ScopedWinHandle(HANDLE in) noexcept : h(in) {}
        ~ScopedWinHandle() noexcept { reset(); }
        ScopedWinHandle(const ScopedWinHandle&) = delete;
        ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
        [[nodiscard]] bool valid() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
        void reset(HANDLE next = nullptr) noexcept {
            if (valid()) { CloseHandle(h); }
            h = next;
        }
    };
    ScopedWinHandle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) return {};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { return {}; }
    if(!CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW | CREATE_SUSPENDED,nullptr,nullptr,&startup,&process)) { return {}; }
    ScopedWinHandle proc_handle(process.hProcess);
    ScopedWinHandle thread_handle(process.hThread);
    if (!AssignProcessToJobObject(job.h, proc_handle.h) || ResumeThread(thread_handle.h) == static_cast<DWORD>(-1)) {
        TerminateProcess(proc_handle.h, 1); return {};
    }
    thread_handle.reset();
    auto deadline=std::chrono::steady_clock::now()+timeout; BackendProcessResult result;
    while(WaitForSingleObject(proc_handle.h,25)==WAIT_TIMEOUT) {
        if(stop.stop_requested() || std::chrono::steady_clock::now()>=deadline) {
            result.cancelled=stop.stop_requested(); result.timed_out=!result.cancelled;
            TerminateJobObject(job.h,1); WaitForSingleObject(proc_handle.h,5000); return result;
        }
    }
    DWORD exit=1; GetExitCodeProcess(proc_handle.h,&exit); result.exit_code=static_cast<int>(exit); return result;
#else
    std::vector<std::string> owned{executable.string()}; owned.insert(owned.end(),arguments.begin(),arguments.end());
    std::vector<char*> argv; for(auto& s:owned) argv.push_back(s.data()); argv.push_back(nullptr);
    const auto pid=fork(); if(pid<0) return {};
    if(pid==0) { setpgid(0,0); execvp(argv[0],argv.data()); _exit(127); }
    setpgid(pid,pid);
    auto deadline=std::chrono::steady_clock::now()+timeout; int status=0;
    for (;;) {
        const auto waited = waitpid(pid,&status,WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) { kill(-pid,SIGKILL); return {}; }
        if(stop.stop_requested() || std::chrono::steady_clock::now()>=deadline) {
            kill(-pid,SIGKILL);
            while (waitpid(pid,&status,0) < 0 && errno == EINTR) {}
            return {-1,!stop.stop_requested(),stop.stop_requested()};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    kill(-pid,SIGKILL);
    return {WIFEXITED(status)?WEXITSTATUS(status):-1};
#endif
}
namespace {

[[nodiscard]] std::string read_env_string(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t size = 0;
    _dupenv_s(&value, &size, name);
    std::string result = value ? value : "";
    std::free(value);
    return result;
#else
    const auto* value = std::getenv(name);
    return value ? std::string(value) : std::string{};
#endif
}

[[nodiscard]] bool is_wsl_c_mount_path(const std::filesystem::path& path) {
    std::string generic = path.generic_string();
    std::ranges::transform(generic, generic.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return generic == "/mnt/c" || generic.starts_with("/mnt/c/");
}

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out(sv);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
}

[[nodiscard]] std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] std::string read_bounded_text(const std::filesystem::path& path,
                                            std::uintmax_t max_bytes) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        return {};
    }
    const auto fsize = std::filesystem::file_size(path, ec);
    if (ec || fsize == 0u || fsize > max_bytes) {
        return {};
    }
    std::ifstream file(path, std::ios::binary);
    std::string text(static_cast<std::size_t>(fsize), '\0');
    if (!file.read(text.data(), static_cast<std::streamsize>(fsize))) {
        return {};
    }
    return text;
}

[[nodiscard]] std::optional<std::string> extract_json_string_field(std::string_view json,
                                                                   std::string_view key) {
    const std::string needle = std::format("\"{}\"", key);
    std::size_t pos = 0;
    while ((pos = json.find(needle, pos)) != std::string_view::npos) {
        pos += needle.size();
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
            ++pos;
        }
        if (pos >= json.size() || json[pos] != ':') {
            continue;
        }
        ++pos;
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
            ++pos;
        }
        if (pos >= json.size() || json[pos] != '"') {
            continue;
        }
        ++pos;
        std::string value;
        bool escaped = false;
        for (; pos < json.size(); ++pos) {
            const char ch = json[pos];
            if (escaped) {
                switch (ch) {
                    case '"':  value.push_back('"'); break;
                    case '\\': value.push_back('\\'); break;
                    case '/':  value.push_back('/'); break;
                    case 'n':  value.push_back('\n'); break;
                    case 'r':  value.push_back('\r'); break;
                    case 't':  value.push_back('\t'); break;
                    default:   value.push_back(ch); break;
                }
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                return value;
            }
            value.push_back(ch);
        }
        break;
    }
    return std::nullopt;
}

[[nodiscard]] BinaryNinjaEdition parse_edition_hint(std::string_view text) noexcept {
    const std::string lower = to_lower_ascii(trim_ascii(text));
    if (lower.empty()) {
        return BinaryNinjaEdition::Unknown;
    }
    if (lower.contains("ultimate")) {
        return BinaryNinjaEdition::Ultimate;
    }
    if (lower.contains("headless")) {
        return BinaryNinjaEdition::Headless;
    }
    if (lower.contains("commercial") || lower.contains("enterprise")) {
        return BinaryNinjaEdition::Commercial;
    }
    if (lower.contains("personal") || lower.contains("non-commercial") || lower.contains("student")) {
        return BinaryNinjaEdition::Personal;
    }
    if (lower.contains("free") || lower.contains("demo")) {
        return BinaryNinjaEdition::Free;
    }
    return BinaryNinjaEdition::Unknown;
}

[[nodiscard]] std::optional<peelf::Architecture> map_bn_arch_name(std::string_view name) noexcept {
    const std::string lower = to_lower_ascii(trim_ascii(name));
    if (lower == "x86_64" || lower == "x64" || lower == "amd64") {
        return peelf::Architecture::X86_64;
    }
    if (lower == "x86" || lower == "i386" || lower == "ia32") {
        return peelf::Architecture::X86;
    }
    if (lower == "aarch64" || lower == "arm64" || lower == "arm64e") {
        return peelf::Architecture::ARM64;
    }
    if (lower == "armv7" || lower == "armv7eb" || lower == "thumb2" ||
        lower == "thumb2eb" || lower == "arm" || lower == "arm32") {
        return peelf::Architecture::ARM;
    }
    if (lower == "rv64gc" || lower == "riscv64") {
        return peelf::Architecture::RISCV64;
    }
    if (lower == "rv32gc" || lower == "riscv32") {
        return peelf::Architecture::RISCV32;
    }
    if (lower == "mips64" || lower == "mipsel64") {
        return peelf::Architecture::MIPS64;
    }
    if (lower == "mips32" || lower == "mipsel32") {
        return peelf::Architecture::MIPS32;
    }
    if (lower == "ppc64" || lower == "ppc64_le" || lower == "powerpc64") {
        return peelf::Architecture::PowerPC64;
    }
    if (lower == "ppc" || lower == "ppc_le" || lower == "ppc32" || lower == "powerpc") {
        return peelf::Architecture::PowerPC;
    }
    return std::nullopt;
}

[[nodiscard]] std::string_view architecture_cli_name(peelf::Architecture arch) noexcept {
    switch (arch) {
        case peelf::Architecture::X86:       return "x86";
        case peelf::Architecture::X86_64:    return "x86_64";
        case peelf::Architecture::ARM:       return "arm32";
        case peelf::Architecture::ARM64:     return "arm64";
        case peelf::Architecture::MIPS32:    return "mips32";
        case peelf::Architecture::MIPS64:    return "mips64";
        case peelf::Architecture::PowerPC:   return "ppc32";
        case peelf::Architecture::PowerPC64: return "ppc64";
        case peelf::Architecture::RISCV32:   return "riscv32";
        case peelf::Architecture::RISCV64:   return "riscv64";
        case peelf::Architecture::Unknown:   return "unknown";
    }
    return "unknown";
}

struct InspectedBnInstall {
    bool found = false;
    bool python_api = false;
    std::filesystem::path install_dir{};
    std::filesystem::path python_dir{};
};

[[nodiscard]] InspectedBnInstall inspect_bn_install_candidate(const std::filesystem::path& raw_path) {
    if (raw_path.empty()) {
        return {};
    }
    std::error_code ec;
    std::filesystem::path candidate = raw_path;
    if (std::filesystem::is_regular_file(candidate, ec)) {
        candidate = candidate.parent_path();
    }
    if (!std::filesystem::is_directory(candidate, ec)) {
        return {};
    }

    // Handle macOS .app bundle root directly (e.g., /Applications/Binary Ninja.app).
    if (std::filesystem::is_directory(candidate / "Contents" / "MacOS", ec)) {
        candidate = candidate / "Contents" / "MacOS";
    }
    // Handle user pointing directly at <bn_install>/python.
    if (std::filesystem::is_regular_file(candidate / "binaryninja" / "__init__.py", ec)) {
        InspectedBnInstall info;
        info.found = true;
        info.python_api = true;
        info.python_dir = candidate;
        info.install_dir = candidate.parent_path().empty() ? candidate : candidate.parent_path();
        return info;
    }

    const bool has_binary_or_core =
        std::filesystem::is_regular_file(candidate / "binaryninja", ec) ||
        std::filesystem::is_regular_file(candidate / "binaryninja.exe", ec) ||
        std::filesystem::is_regular_file(candidate / "libbinaryninjacore.so", ec) ||
        std::filesystem::is_regular_file(candidate / "libbinaryninjacore.so.1", ec) ||
        std::filesystem::is_regular_file(candidate / "binaryninjacore.dll", ec) ||
        std::filesystem::is_regular_file(candidate / "libbinaryninjacore.dylib", ec);

    std::filesystem::path py_dir;
    for (const auto& py_cand : {
             candidate / "python",
             candidate.parent_path() / "Resources" / "python",
             candidate / "Contents" / "Resources" / "python",
         }) {
        if (!py_cand.empty() &&
            std::filesystem::is_regular_file(py_cand / "binaryninja" / "__init__.py", ec)) {
            py_dir = py_cand;
            break;
        }
    }

    if (!has_binary_or_core && py_dir.empty()) {
        return {};
    }

    InspectedBnInstall info;
    info.found = true;
    info.install_dir = candidate;
    info.python_api = !py_dir.empty();
    info.python_dir = std::move(py_dir);
    return info;
}

[[nodiscard]] std::vector<peelf::Architecture> default_licensed_bn_architectures() {
    return {
        peelf::Architecture::X86,
        peelf::Architecture::X86_64,
        peelf::Architecture::ARM,
        peelf::Architecture::ARM64,
        peelf::Architecture::MIPS32,
        peelf::Architecture::MIPS64,
        peelf::Architecture::PowerPC,
        peelf::Architecture::PowerPC64,
        peelf::Architecture::RISCV32,
        peelf::Architecture::RISCV64,
    };
}

[[nodiscard]] std::string summarize_bn_capabilities(const BinaryNinjaCapabilityStatus& caps) {
    if (!caps.install_found && !caps.python_api_available) {
        return "Binary Ninja not detected. Set Binary Ninja Home, BN_INSTALL_DIR, or configure Python with the binaryninja API.";
    }
    const std::string ver_suffix = caps.version.empty() ? std::string{} : std::format(" {}", caps.version);
    const std::string loc_suffix =
        caps.install_directory.empty() ? std::string{}
                                       : std::format(" at {}", caps.install_directory.string());
    if (caps.edition == BinaryNinjaEdition::Free) {
        return std::format(
            "Binary Ninja Free{}{} — interactive x86/x64 edition only; headless Python batch API and ARM64/ARM32/MIPS/PowerPC/RISC-V require Personal, Commercial, or Ultimate.",
            ver_suffix,
            loc_suffix);
    }
    if (!caps.python_api_available) {
        return std::format("Binary Ninja{}{} — installation found, but Python API directory is missing.",
                           ver_suffix,
                           loc_suffix);
    }
    if (!caps.headless_supported) {
        return std::format(
            "Binary Ninja ({}){}{} — Python API found, but headless batch analysis is unavailable for this license/edition.",
            to_string(caps.edition),
            ver_suffix,
            loc_suffix);
    }
    if (caps.edition == BinaryNinjaEdition::Unknown) {
        return std::format(
            "Binary Ninja{}{} — Python API available (click Probe to verify license edition and architecture plugins).",
            ver_suffix,
            loc_suffix);
    }
    return std::format(
        "Binary Ninja {}{}{} — headless Python API ready ({} architectures).",
        to_string(caps.edition),
        ver_suffix,
        loc_suffix,
        caps.supported_architectures.size());
}

}  // namespace

std::filesystem::path safe_decompiler_scratch_directory() {
#ifndef _WIN32
    std::error_code ec;
    auto tmp = std::filesystem::temp_directory_path(ec);
    if (!ec && !tmp.empty() && !is_wsl_c_mount_path(tmp)) {
        return tmp;
    }
    return "/tmp";
#else
    return std::filesystem::temp_directory_path();
#endif
}

BinaryNinjaCapabilityStatus discover_binary_ninja(
    const DecompilerSettings& settings,
    const BinaryNinjaDiscoveryEnv& env) {
    BinaryNinjaCapabilityStatus caps{};

    std::vector<std::filesystem::path> user_dirs = env.user_settings_directories;
    if (env.include_system_defaults) {
        if (const std::string appdata = read_env_string("APPDATA"); !appdata.empty()) {
            user_dirs.push_back(std::filesystem::path(appdata) / "Binary Ninja");
        }
        std::string home = read_env_string("HOME");
        if (home.empty()) {
            home = read_env_string("USERPROFILE");
        }
        if (!home.empty()) {
            const std::filesystem::path home_path(home);
            user_dirs.push_back(home_path / ".binaryninja");
            user_dirs.push_back(home_path / "Library" / "Application Support" / "Binary Ninja");
        }
    }

    InspectedBnInstall match{};
    const auto try_candidate = [&match, &caps](const std::filesystem::path& cand,
                                               const std::filesystem::path& source = {}) {
        if (match.found || cand.empty()) {
            return;
        }
        auto inspected = inspect_bn_install_candidate(cand);
        if (inspected.found) {
            match = std::move(inspected);
            if (!source.empty()) {
                caps.settings_source = source;
            }
        }
    };

    // (a) Explicit settings.binary_ninja_home
    try_candidate(settings.binary_ninja_home);

    // (b) BN_INSTALL_DIR / BINARYNINJA_HOME
    if (env.bn_install_dir.has_value()) {
        try_candidate(*env.bn_install_dir);
    } else if (env.include_system_defaults) {
        try_candidate(read_env_string("BN_INSTALL_DIR"));
    }
    if (env.binaryninja_home.has_value()) {
        try_candidate(*env.binaryninja_home);
    } else if (env.include_system_defaults) {
        try_candidate(read_env_string("BINARYNINJA_HOME"));
    }

    // (c) BN user settings: lastrun and settings.json
    for (const auto& u_dir : user_dirs) {
        if (match.found) {
            break;
        }
        const std::filesystem::path lastrun_path = u_dir / "lastrun";
        if (const std::string lastrun_text = read_bounded_text(lastrun_path, 64u * 1024u);
            !lastrun_text.empty()) {
            std::istringstream lines(lastrun_text);
            std::string raw_line;
            while (std::getline(lines, raw_line)) {
                std::string_view sv = trim_ascii(raw_line);
                if (sv.size() >= 2u && sv.front() == '"' && sv.back() == '"') {
                    sv.remove_prefix(1);
                    sv.remove_suffix(1);
                }
                if (!sv.empty()) {
                    try_candidate(std::filesystem::path(sv), lastrun_path);
                    break;
                }
            }
        }
        if (match.found) {
            break;
        }
        const std::filesystem::path settings_json_path = u_dir / "settings.json";
        if (const std::string json_text = read_bounded_text(settings_json_path, 1024u * 1024u);
            !json_text.empty()) {
            for (const std::string_view key : {"binaryNinjaHome", "installDirectory", "lastRun"}) {
                if (const auto hint = extract_json_string_field(json_text, key); hint.has_value()) {
                    try_candidate(std::filesystem::path(*hint), settings_json_path);
                    if (match.found) {
                        break;
                    }
                }
            }
        }
    }

    // (d) Standard install paths
    std::vector<std::filesystem::path> std_dirs = env.standard_install_directories;
    if (env.include_system_defaults) {
        if (const std::string local_app = read_env_string("LOCALAPPDATA"); !local_app.empty()) {
            std_dirs.push_back(std::filesystem::path(local_app) / "Vector35" / "BinaryNinja");
        }
        if (const std::string prog_files = read_env_string("ProgramFiles"); !prog_files.empty()) {
            std_dirs.push_back(std::filesystem::path(prog_files) / "Vector35" / "BinaryNinja");
        }
        std_dirs.emplace_back("/opt/binaryninja");
        std::string home = read_env_string("HOME");
        if (home.empty()) {
            home = read_env_string("USERPROFILE");
        }
        if (!home.empty()) {
            std_dirs.push_back(std::filesystem::path(home) / "binaryninja");
        }
        std_dirs.emplace_back("/Applications/Binary Ninja.app/Contents/MacOS");
    }
    for (const auto& std_dir : std_dirs) {
        if (match.found) {
            break;
        }
        try_candidate(std_dir);
    }

    // (e) PATH lookup of binaryninja / binaryninja.exe
    if (!match.found) {
        std::string path_val;
        if (env.path_env.has_value()) {
            path_val = *env.path_env;
        } else if (env.include_system_defaults) {
            path_val = read_env_string("PATH");
        }
#ifdef _WIN32
        constexpr char kPathSep = ';';
#else
        constexpr char kPathSep = ':';
#endif
        std::size_t start = 0;
        while (start <= path_val.size() && !match.found) {
            const std::size_t sep = path_val.find(kPathSep, start);
            const std::string_view token =
                sep == std::string::npos
                    ? std::string_view(path_val).substr(start)
                    : std::string_view(path_val).substr(start, sep - start);
            start = (sep == std::string::npos) ? (path_val.size() + 1u) : (sep + 1u);
            const std::string_view trimmed = trim_ascii(token);
            if (trimmed.empty()) {
                continue;
            }
            const std::filesystem::path dir_path(trimmed);
            std::error_code ec;
            for (const auto* exe_name : {"binaryninja", "binaryninja.exe"}) {
                const std::filesystem::path exe_path = dir_path / exe_name;
                if (!std::filesystem::is_regular_file(exe_path, ec)) {
                    continue;
                }
                const auto resolved = std::filesystem::weakly_canonical(exe_path, ec);
                if (!ec && !resolved.empty()) {
                    try_candidate(resolved.parent_path());
                }
                try_candidate(dir_path);
                if (match.found) {
                    break;
                }
            }
        }
    }

    if (match.found) {
        caps.install_found = true;
        caps.python_api_available = match.python_api;
        caps.install_directory = std::move(match.install_dir);
        caps.python_api_directory = std::move(match.python_dir);

        // Read non-sensitive version metadata if present.
        for (const auto& ver_file : {
                 caps.install_directory / "version.txt",
                 caps.install_directory / "build.txt",
             }) {
            if (const std::string ver_raw = read_bounded_text(ver_file, 16u * 1024u);
                !ver_raw.empty()) {
                const std::string_view first_line =
                    trim_ascii(std::string_view(ver_raw).substr(0, ver_raw.find('\n')));
                if (!first_line.empty()) {
                    caps.version = std::string(first_line);
                    break;
                }
            }
        }
        if (caps.version.empty() && !caps.python_api_directory.empty()) {
            const std::string py_ver = read_bounded_text(
                caps.python_api_directory / "binaryninja" / "_version.py", 32u * 1024u);
            if (const auto q1 = py_ver.find('"'); q1 != std::string::npos) {
                if (const auto q2 = py_ver.find('"', q1 + 1u); q2 != std::string::npos && q2 > q1 + 1u) {
                    caps.version = py_ver.substr(q1 + 1u, q2 - q1 - 1u);
                }
            }
        }

        // Read non-sensitive product/edition hints (never storing license keys or serials).
        for (const auto& ed_file : {
                 caps.install_directory / "edition.txt",
                 caps.install_directory / "product.txt",
             }) {
            if (const std::string ed_raw = read_bounded_text(ed_file, 16u * 1024u); !ed_raw.empty()) {
                caps.edition = parse_edition_hint(ed_raw);
                if (caps.edition != BinaryNinjaEdition::Unknown) {
                    break;
                }
            }
        }
        if (caps.edition == BinaryNinjaEdition::Unknown) {
            if (const std::string inst_lic =
                    read_bounded_text(caps.install_directory / "license.dat", 256u * 1024u);
                !inst_lic.empty()) {
                if (const auto prod = extract_json_string_field(inst_lic, "product"); prod.has_value()) {
                    caps.edition = parse_edition_hint(*prod);
                }
            }
        }
    }

    // Also inspect user settings directories for product/edition hints.
    for (const auto& u_dir : user_dirs) {
        if (caps.edition != BinaryNinjaEdition::Unknown) {
            break;
        }
        const std::filesystem::path lic_path = u_dir / "license.dat";
        if (const std::string lic_text = read_bounded_text(lic_path, 256u * 1024u); !lic_text.empty()) {
            if (const auto prod = extract_json_string_field(lic_text, "product"); prod.has_value()) {
                caps.edition = parse_edition_hint(*prod);
                if (caps.edition != BinaryNinjaEdition::Unknown && caps.settings_source.empty()) {
                    caps.settings_source = lic_path;
                    break;
                }
            }
        }
        const std::filesystem::path settings_json_path = u_dir / "settings.json";
        if (const std::string json_text = read_bounded_text(settings_json_path, 1024u * 1024u);
            !json_text.empty()) {
            for (const std::string_view key : {"edition", "product", "licenseEdition"}) {
                if (const auto val = extract_json_string_field(json_text, key); val.has_value()) {
                    caps.edition = parse_edition_hint(*val);
                    if (caps.edition != BinaryNinjaEdition::Unknown) {
                        if (caps.settings_source.empty()) {
                            caps.settings_source = settings_json_path;
                        }
                        break;
                    }
                }
            }
        }
    }

    if (caps.install_found && caps.edition == BinaryNinjaEdition::Unknown) {
        caps.edition = parse_edition_hint(caps.install_directory.filename().string());
    }

    if (caps.edition == BinaryNinjaEdition::Free) {
        caps.headless_supported = false;
        caps.supported_architectures = {
            peelf::Architecture::X86,
            peelf::Architecture::X86_64,
        };
    } else if (caps.edition == BinaryNinjaEdition::Personal ||
               caps.edition == BinaryNinjaEdition::Commercial ||
               caps.edition == BinaryNinjaEdition::Ultimate ||
               caps.edition == BinaryNinjaEdition::Headless) {
        caps.headless_supported = caps.python_api_available;
        if (caps.install_found || caps.python_api_available) {
            caps.supported_architectures = default_licensed_bn_architectures();
        }
    } else {
        caps.headless_supported = caps.python_api_available;
    }

    caps.status_summary = summarize_bn_capabilities(caps);
    return caps;
}

BinaryNinjaCapabilityStatus probe_binary_ninja_capabilities(
    const DecompilerSettings& settings,
    const std::filesystem::path& bridge_script,
    const IBackendRunner& runner,
    const BinaryNinjaDiscoveryEnv& env,
    std::stop_token stop) {
    BinaryNinjaCapabilityStatus caps = discover_binary_ninja(settings, env);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(bridge_script, ec)) {
        caps.status_summary = "Binary Ninja bridge script (bn_decompile.py) is missing.";
        return caps;
    }

    static std::atomic<std::uint64_t> probe_serial{0u};
    const std::filesystem::path scratch =
        safe_decompiler_scratch_directory() /
        std::format("peelf-bn-probe-{}-{}",
                    std::chrono::steady_clock::now().time_since_epoch().count(),
                    ++probe_serial);
    if (!std::filesystem::create_directory(scratch, ec)) {
        caps.status_summary = "Cannot create scratch workspace for Binary Ninja probe.";
        return caps;
    }
    std::filesystem::permissions(
        scratch,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec);
    struct ScopedDir {
        std::filesystem::path path;
        explicit ScopedDir(std::filesystem::path p) noexcept : path(std::move(p)) {}
        ScopedDir(const ScopedDir&) = delete;
        ScopedDir& operator=(const ScopedDir&) = delete;
        ~ScopedDir() noexcept {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } guard{scratch};

    const std::filesystem::path probe_out = scratch / "probe.txt";
    std::vector<std::string> args{
        bridge_script.string(),
        "--probe",
        probe_out.string(),
    };
    const std::filesystem::path effective_home =
        !settings.binary_ninja_home.empty() ? settings.binary_ninja_home : caps.install_directory;
    if (!effective_home.empty()) {
        args.emplace_back("--bn-home");
        args.push_back(effective_home.string());
    }

    const int timeout_sec = std::clamp(settings.timeout_seconds, 5, 60);
    const BackendProcessResult proc =
        runner.run(settings.python, args, std::chrono::seconds(timeout_sec), stop);
    if (proc.cancelled) {
        caps.status_summary = "Binary Ninja capability probe cancelled.";
        return caps;
    }
    if (proc.timed_out) {
        caps.status_summary = std::format("Binary Ninja capability probe timed out after {}s.", timeout_sec);
        return caps;
    }

    const std::string probe_text = read_bounded_text(probe_out, 256u * 1024u);
    if (probe_text.empty()) {
        caps.python_api_available = false;
        caps.headless_supported = false;
        caps.status_summary = std::format(
            "Could not run Python interpreter '{}' for Binary Ninja probe.",
            settings.python.string());
        return caps;
    }

    std::istringstream in(probe_text);
    std::string magic;
    int proto_ver = 0;
    int api_avail = 0;
    int headless_ok = 0;
    std::string edition_str;
    std::string version_str;
    std::string py_dir_str;
    std::size_t arch_count = 0;
    if (!(in >> magic >> proto_ver >> api_avail >> headless_ok >>
          std::quoted(edition_str) >> std::quoted(version_str) >>
          std::quoted(py_dir_str) >> arch_count) ||
        magic != "PEELF_BN_PROBE" || proto_ver != 1 || arch_count > 512u) {
        caps.status_summary = "Malformed Binary Ninja probe response.";
        return caps;
    }

    std::vector<peelf::Architecture> probed_arches;
    for (std::size_t i = 0; i < arch_count; ++i) {
        std::string arch_token;
        if (!(in >> std::quoted(arch_token))) {
            caps.status_summary = "Truncated Binary Ninja probe architecture list.";
            return caps;
        }
        if (const auto mapped = map_bn_arch_name(arch_token); mapped.has_value()) {
            if (std::ranges::find(probed_arches, *mapped) == probed_arches.end()) {
                probed_arches.push_back(*mapped);
            }
        }
    }
    std::string diagnostic;
    (void)(in >> std::quoted(diagnostic));

    caps.python_api_available = (api_avail != 0);
    caps.headless_supported = (headless_ok != 0);
    if (const auto parsed_ed = parse_edition_hint(edition_str);
        parsed_ed != BinaryNinjaEdition::Unknown) {
        caps.edition = parsed_ed;
    }
    if (caps.edition == BinaryNinjaEdition::Free) {
        caps.headless_supported = false;
    }
    if (!version_str.empty()) {
        caps.version = std::move(version_str);
    }
    if (!py_dir_str.empty()) {
        caps.python_api_directory = py_dir_str;
        if (!caps.install_found) {
            const auto inferred = inspect_bn_install_candidate(caps.python_api_directory);
            if (inferred.found) {
                caps.install_found = true;
                caps.install_directory = inferred.install_dir;
            }
        }
    }
    if (!probed_arches.empty()) {
        caps.supported_architectures = std::move(probed_arches);
    } else if (caps.edition == BinaryNinjaEdition::Free) {
        caps.supported_architectures = {peelf::Architecture::X86, peelf::Architecture::X86_64};
    }

    if (!caps.python_api_available && !diagnostic.empty()) {
        caps.status_summary = std::move(diagnostic);
    } else if (!caps.headless_supported && !diagnostic.empty() &&
               caps.edition != BinaryNinjaEdition::Free) {
        caps.status_summary = std::move(diagnostic);
    } else {
        caps.status_summary = summarize_bn_capabilities(caps);
    }
    return caps;
}

peelf::Result<void> check_binary_ninja_architecture_support(
    const BinaryNinjaCapabilityStatus& caps,
    peelf::Architecture arch) {
    if (arch == peelf::Architecture::Unknown) {
        return peelf::make_error(
            "Architecture 'unknown' is not supported by Binary Ninja.");
    }
    if (caps.edition == BinaryNinjaEdition::Free &&
        arch != peelf::Architecture::X86 &&
        arch != peelf::Architecture::X86_64) {
        return peelf::make_error(std::format(
            "Architecture '{}' is not supported on Binary Ninja Free (x86/x64-only interactive edition). "
            "ARM64/ARM32/MIPS/PowerPC/RISC-V require Binary Ninja Personal, Commercial, or Ultimate, "
            "or use Structured Pseudo-C / Ghidra.",
            architecture_cli_name(arch)));
    }
    if (!caps.supported_architectures.empty() &&
        std::ranges::find(caps.supported_architectures, arch) == caps.supported_architectures.end()) {
        return peelf::make_error(std::format(
            "Architecture '{}' is not supported by the detected Binary Ninja installation (edition: {}).",
            architecture_cli_name(arch),
            to_string(caps.edition)));
    }
    return {};
}

peelf::Result<void> check_binary_ninja_headless_support(
    const BinaryNinjaCapabilityStatus& caps,
    peelf::Architecture arch) {
    if (const auto arch_ok = check_binary_ninja_architecture_support(caps, arch); !arch_ok) {
        return arch_ok;
    }
    if (caps.edition == BinaryNinjaEdition::Free) {
        return peelf::make_error(
            "Binary Ninja Free is an interactive x86/x64 edition and does not support the headless Python batch API. "
            "Configure Binary Ninja Personal, Commercial, Ultimate, or Headless, or use Structured Pseudo-C / Ghidra.");
    }
    if ((caps.install_found || caps.python_api_available) && !caps.headless_supported) {
        return peelf::make_error(std::format(
            "Binary Ninja headless Python batch API is unavailable (edition: {}). {}",
            to_string(caps.edition),
            caps.status_summary));
    }
    return {};
}

DecompiledUnit BinaryNinjaDecompiler::decompile(const DecompileRequest& request,std::stop_token stop) const {
    auto failure=[](DecompileStatus status,std::string message) { return DecompiledUnit{status,"Binary Ninja HLIL",std::move(message)}; };
    if (stop.stop_requested()) return failure(DecompileStatus::Cancelled,"Decompilation cancelled");
    if (!std::filesystem::is_regular_file(bridge_)) return failure(DecompileStatus::Unavailable,"Binary Ninja bridge resource is missing");
    if (request.architecture==peelf::Architecture::Unknown) return failure(DecompileStatus::Unsupported,"Unknown architecture");
    if (request.image_bytes.empty()) return failure(DecompileStatus::Failed,"Empty binary snapshot");
    if (timeout_seconds_ < 5 || timeout_seconds_ > 3600) {
        return failure(DecompileStatus::Failed,"Decompiler timeout must be between 5 and 3600 seconds");
    }

    if (capabilities_.has_value()) {
        if (const auto ok = check_binary_ninja_headless_support(*capabilities_, request.architecture); !ok) {
            return failure(DecompileStatus::Unsupported, ok.error().message);
        }
    } else if (!binary_ninja_home_.empty()) {
        DecompilerSettings scoped{};
        scoped.binary_ninja_home = binary_ninja_home_;
        BinaryNinjaDiscoveryEnv scoped_env{};
        scoped_env.include_system_defaults = false;
        const BinaryNinjaCapabilityStatus static_caps = discover_binary_ninja(scoped, scoped_env);
        if (!static_caps.install_found) {
            return failure(
                DecompileStatus::Unavailable,
                std::format("Binary Ninja installation not found at '{}'.", binary_ninja_home_.string()));
        }
        if (const auto ok = check_binary_ninja_headless_support(static_caps, request.architecture); !ok) {
            return failure(DecompileStatus::Unsupported, ok.error().message);
        }
    }

    static std::atomic<std::uint64_t> serial{};
    auto directory=safe_decompiler_scratch_directory()/std::format("peelf-decompile-{}-{}",std::chrono::steady_clock::now().time_since_epoch().count(),++serial);
    std::error_code ec; if(!std::filesystem::create_directory(directory,ec)) return failure(DecompileStatus::Failed,"Cannot create backend workspace");
    std::filesystem::permissions(
        directory,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec);
    struct Cleanup {
        std::filesystem::path path;
        explicit Cleanup(std::filesystem::path p) noexcept : path(std::move(p)) {}
        Cleanup(const Cleanup&) = delete;
        Cleanup& operator=(const Cleanup&) = delete;
        ~Cleanup() noexcept { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    } cleanup{directory};
    const auto input=directory/"input.bin", output=directory/"output.txt", symbols=directory/"symbols.txt";
    { std::ofstream file(input,std::ios::binary); file.write(reinterpret_cast<const char*>(request.image_bytes.data()),static_cast<std::streamsize>(request.image_bytes.size())); if(!file) return failure(DecompileStatus::Failed,"Cannot write analysis snapshot"); }
    { std::ofstream sym_file(symbols,std::ios::binary); sym_file<<encode_decompiler_symbols(request); if(!sym_file) return failure(DecompileStatus::Failed,"Cannot write symbol metadata"); }

    std::vector<std::string> args{
        bridge_.string(),
        input.string(),
        output.string(),
        std::to_string(request.address),
        "--arch",
        std::string(architecture_cli_name(request.architecture)),
        "--symbols",
        symbols.string(),
    };
    if (!binary_ninja_home_.empty()) {
        args.emplace_back("--bn-home");
        args.push_back(binary_ninja_home_.string());
    }

    const auto process=runner_.run(python_,args,std::chrono::seconds(timeout_seconds_),stop);
    if(process.cancelled) return failure(DecompileStatus::Cancelled,"Decompilation cancelled");
    if(process.timed_out) return failure(DecompileStatus::Timeout,std::format("Backend exceeded {}-second deadline", timeout_seconds_));
    if(!std::filesystem::exists(output)) return failure(DecompileStatus::Unavailable,"Could not run Python bridge. Configure Python with the Binary Ninja API installed.");
    const auto size=std::filesystem::file_size(output,ec);
    if(ec || size>4*1024*1024) return failure(DecompileStatus::Failed,"Invalid backend output size");
    std::ifstream file(output,std::ios::binary); std::string text(static_cast<std::size_t>(size),'\0');
    if(!file.read(text.data(),static_cast<std::streamsize>(size))) return failure(DecompileStatus::Failed,"Cannot read backend output");
    auto unit = parse_decompiler_output(text);
    if (process.exit_code != 0 && unit.status == DecompileStatus::Ready) {
        return failure(DecompileStatus::Failed, "Binary Ninja bridge exited abnormally after writing output");
    }
    if (unit.status == DecompileStatus::Ready &&
        request.function_override.has_value() &&
        !request.function_override->empty()) {
        apply_decompiler_overrides(unit, *request.function_override);
    }
    return unit;
}

namespace {

[[nodiscard]] std::string format_c_typed_variable_decl(
    std::string_view c_type,
    std::string_view var_name) {
    c_type = trim_ascii(c_type);
    const std::size_t bracket = c_type.find('[');
    if (bracket != std::string_view::npos && bracket > 0u) {
        const std::string_view base_type = trim_ascii(c_type.substr(0, bracket));
        const std::string_view array_suffix = c_type.substr(bracket);
        return std::format("{} {}{}", base_type, var_name, array_suffix);
    }
    return std::format("{} {}", c_type, var_name);
}

[[nodiscard]] bool is_non_type_statement_keyword(std::string_view word) noexcept {
    return word == "return" || word == "goto" || word == "case" || word == "else" ||
           word == "delete" || word == "sizeof" || word == "throw" || word == "co_return" ||
           word == "if" || word == "while" || word == "for" || word == "switch" || word == "do";
}

[[nodiscard]] bool is_member_or_tag_context(std::string_view code, std::size_t tok_start) noexcept {
    std::size_t back = tok_start;
    while (back > 0u && (code[back - 1u] == ' ' || code[back - 1u] == '\t')) {
        --back;
    }
    if (back >= 1u && code[back - 1u] == '.') {
        const bool is_ellipsis =
            back >= 3u && code[back - 2u] == '.' && code[back - 3u] == '.';
        if (!is_ellipsis) {
            return true;
        }
    }
    if (back >= 2u && code[back - 2u] == '-' && code[back - 1u] == '>') {
        return true;
    }
    if (back >= 2u && code[back - 2u] == ':' && code[back - 1u] == ':') {
        return true;
    }
    if (back < tok_start && back > 0u && detail::is_override_ident_cont(code[back - 1u])) {
        std::size_t kw_start = back;
        while (kw_start > 0u && detail::is_override_ident_cont(code[kw_start - 1u])) {
            --kw_start;
        }
        const std::string_view prev_word = code.substr(kw_start, back - kw_start);
        if (prev_word == "struct" || prev_word == "union" || prev_word == "enum") {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string rewrite_single_parameter_decl(
    std::string_view param,
    const std::unordered_map<std::string_view, const DecompilerVariableOverride*>& var_map,
    const std::unordered_map<std::string, std::string>& rename_map) {
    const std::string_view trimmed = trim_ascii(param);
    if (trimmed.empty() || trimmed == "void" || trimmed == "...") {
        return std::string(trimmed);
    }

    std::size_t end_pos = trimmed.size();
    std::string_view array_suffix{};
    if (trimmed.back() == ']') {
        const std::size_t open_br = trimmed.rfind('[');
        if (open_br != std::string_view::npos) {
            array_suffix = trimmed.substr(open_br);
            end_pos = open_br;
            while (end_pos > 0u && (trimmed[end_pos - 1u] == ' ' || trimmed[end_pos - 1u] == '\t')) {
                --end_pos;
            }
        }
    }
    std::size_t name_start = end_pos;
    while (name_start > 0u && detail::is_override_ident_cont(trimmed[name_start - 1u])) {
        --name_start;
    }
    if (name_start < end_pos && detail::is_override_ident_start(trimmed[name_start])) {
        const std::string_view param_name = trimmed.substr(name_start, end_pos - name_start);
        const std::string_view prefix_type = trim_ascii(trimmed.substr(0, name_start));
        if (!prefix_type.empty()) {
            if (const auto it = var_map.find(param_name); it != var_map.end()) {
                const DecompilerVariableOverride* ov = it->second;
                const std::string_view eff_name =
                    !ov->renamed_to.empty() ? std::string_view(ov->renamed_to) : param_name;
                if (!ov->c_type.empty()) {
                    return format_c_typed_variable_decl(ov->c_type, eff_name);
                }
                return std::format("{} {}{}", prefix_type, eff_name, array_suffix);
            }
        }
    }
    return rewrite_decompiler_c_tokens(trimmed, rename_map);
}

[[nodiscard]] bool try_rewrite_function_header_line(
    std::string& line,
    const DecompilerFunctionOverride& ov,
    const std::unordered_map<std::string_view, const DecompilerVariableOverride*>& var_map,
    const std::unordered_map<std::string, std::string>& rename_map) {
    std::size_t indent_len = 0u;
    while (indent_len < line.size() && (line[indent_len] == ' ' || line[indent_len] == '\t')) {
        ++indent_len;
    }
    const std::string indent = line.substr(0, indent_len);
    const std::string_view rest = std::string_view(line).substr(indent_len);
    const std::size_t open_paren = rest.find('(');
    if (open_paren == std::string_view::npos || open_paren == 0u) {
        return false;
    }

    int depth = 0;
    std::size_t close_paren = std::string_view::npos;
    for (std::size_t i = open_paren; i < rest.size(); ++i) {
        if (rest[i] == '(') {
            ++depth;
        } else if (rest[i] == ')') {
            --depth;
            if (depth == 0) {
                close_paren = i;
                break;
            }
        }
    }
    if (close_paren == std::string_view::npos) {
        return false;
    }

    const std::string tail_after_params(rest.substr(close_paren + 1u));
    if (!ov.signature_override.empty() && ov.signature_override.front() != '(') {
        line = std::format("{}{}{}", indent, ov.signature_override, tail_after_params);
        return true;
    }

    std::size_t fn_end = open_paren;
    while (fn_end > 0u && (rest[fn_end - 1u] == ' ' || rest[fn_end - 1u] == '\t')) {
        --fn_end;
    }
    std::size_t fn_start = fn_end;
    while (fn_start > 0u &&
           (detail::is_override_ident_cont(rest[fn_start - 1u]) ||
            rest[fn_start - 1u] == ':' || rest[fn_start - 1u] == '~')) {
        --fn_start;
    }
    if (fn_start == fn_end) {
        return false;
    }
    const std::string_view func_name = rest.substr(fn_start, fn_end - fn_start);
    const std::string_view old_ret = trim_ascii(rest.substr(0, fn_start));
    const std::string_view eff_ret =
        !ov.return_type.empty() ? std::string_view(ov.return_type) : old_ret;

    std::string param_list_str;
    if (!ov.signature_override.empty() && ov.signature_override.front() == '(') {
        param_list_str = ov.signature_override;
    } else {
        const std::string_view raw_params =
            rest.substr(open_paren + 1u, close_paren - open_paren - 1u);
        std::string rebuilt;
        std::size_t start = 0u;
        int p_depth = 0;
        bool first = true;
        for (std::size_t i = 0u; i <= raw_params.size(); ++i) {
            const bool at_end = (i == raw_params.size());
            if (!at_end) {
                if (raw_params[i] == '(' || raw_params[i] == '[' || raw_params[i] == '<') {
                    ++p_depth;
                } else if (raw_params[i] == ')' || raw_params[i] == ']' || raw_params[i] == '>') {
                    --p_depth;
                }
            }
            if (at_end || (raw_params[i] == ',' && p_depth == 0)) {
                const std::string_view part = raw_params.substr(start, i - start);
                if (!first) {
                    rebuilt.append(", ");
                }
                first = false;
                rebuilt.append(rewrite_single_parameter_decl(part, var_map, rename_map));
                start = i + 1u;
            }
        }
        param_list_str = std::format("({})", rebuilt);
    }

    if (eff_ret.empty()) {
        line = std::format("{}{}{}{}", indent, func_name, param_list_str, tail_after_params);
    } else {
        line = std::format("{}{} {}{}{}", indent, eff_ret, func_name, param_list_str, tail_after_params);
    }
    return true;
}

[[nodiscard]] bool try_rewrite_local_decl_line(
    std::string& line,
    const std::unordered_map<std::string_view, const DecompilerVariableOverride*>& var_map,
    const std::unordered_map<std::string, std::string>& rename_map) {
    std::size_t indent_len = 0u;
    while (indent_len < line.size() && (line[indent_len] == ' ' || line[indent_len] == '\t')) {
        ++indent_len;
    }
    const std::string indent = line.substr(0, indent_len);
    const std::string_view body = std::string_view(line).substr(indent_len);
    if (body.empty() || body.starts_with("//") || body.starts_with("/*") || body.starts_with('#')) {
        return false;
    }

    std::size_t semi_pos = std::string_view::npos;
    std::size_t eq_pos = std::string_view::npos;
    bool in_str = false;
    bool in_chr = false;
    int paren_depth = 0;
    for (std::size_t i = 0u; i < body.size(); ++i) {
        const char ch = body[i];
        if (in_str) {
            if (ch == '\\' && i + 1u < body.size()) {
                ++i;
            } else if (ch == '"') {
                in_str = false;
            }
            continue;
        }
        if (in_chr) {
            if (ch == '\\' && i + 1u < body.size()) {
                ++i;
            } else if (ch == '\'') {
                in_chr = false;
            }
            continue;
        }
        if (ch == '"') {
            in_str = true;
            continue;
        }
        if (ch == '\'') {
            in_chr = true;
            continue;
        }
        if (ch == '/' && i + 1u < body.size() && (body[i + 1u] == '/' || body[i + 1u] == '*')) {
            break;
        }
        if (ch == '(') {
            ++paren_depth;
        } else if (ch == ')') {
            --paren_depth;
        } else if (ch == '=' && paren_depth == 0 && eq_pos == std::string_view::npos) {
            if (i + 1u < body.size() && body[i + 1u] == '=') {
                ++i;
                continue;
            }
            if (i > 0u && (body[i - 1u] == '!' || body[i - 1u] == '<' || body[i - 1u] == '>' ||
                           body[i - 1u] == '+' || body[i - 1u] == '-' || body[i - 1u] == '*' ||
                           body[i - 1u] == '/' || body[i - 1u] == '%' || body[i - 1u] == '&' ||
                           body[i - 1u] == '|' || body[i - 1u] == '^')) {
                continue;
            }
            eq_pos = i;
        } else if (ch == ';' && paren_depth == 0) {
            semi_pos = i;
            break;
        }
    }
    if (semi_pos == std::string_view::npos) {
        return false;
    }

    const std::size_t lhs_end = (eq_pos != std::string_view::npos && eq_pos < semi_pos) ? eq_pos : semi_pos;
    std::string_view lhs = trim_ascii(body.substr(0, lhs_end));
    if (lhs.empty()) {
        return false;
    }
    for (char ch : lhs) {
        if (ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == ',') {
            return false;
        }
    }

    std::string_view array_suffix{};
    if (lhs.back() == ']') {
        const std::size_t open_br = lhs.rfind('[');
        if (open_br == std::string_view::npos) {
            return false;
        }
        array_suffix = lhs.substr(open_br);
        lhs = trim_ascii(lhs.substr(0, open_br));
    }

    std::size_t name_start = lhs.size();
    while (name_start > 0u && detail::is_override_ident_cont(lhs[name_start - 1u])) {
        --name_start;
    }
    if (name_start == lhs.size() || !detail::is_override_ident_start(lhs[name_start])) {
        return false;
    }

    const std::string_view var_name = lhs.substr(name_start);
    const std::string_view type_part = trim_ascii(lhs.substr(0, name_start));
    if (type_part.empty()) {
        return false;
    }

    bool type_has_ident = false;
    std::size_t first_word_end = 0u;
    while (first_word_end < type_part.size() && detail::is_override_ident_cont(type_part[first_word_end])) {
        type_has_ident = true;
        ++first_word_end;
    }
    if (!type_has_ident) {
        return false;
    }
    const std::string_view first_word = type_part.substr(0, first_word_end);
    if (is_non_type_statement_keyword(first_word)) {
        return false;
    }

    const auto it = var_map.find(var_name);
    if (it == var_map.end()) {
        return false;
    }
    const DecompilerVariableOverride* ov = it->second;
    const std::string_view eff_name =
        !ov->renamed_to.empty() ? std::string_view(ov->renamed_to) : var_name;

    std::string decl_lhs;
    if (!ov->c_type.empty()) {
        if (ov->c_type.find('[') != std::string::npos || array_suffix.empty()) {
            decl_lhs = format_c_typed_variable_decl(ov->c_type, eff_name);
        } else {
            decl_lhs = std::format("{} {}{}", ov->c_type, eff_name, array_suffix);
        }
    } else {
        decl_lhs = std::format("{} {}{}", type_part, eff_name, array_suffix);
    }

    std::string init_part;
    if (eq_pos != std::string_view::npos && eq_pos < semi_pos) {
        const std::string_view raw_init = trim_ascii(body.substr(eq_pos + 1u, semi_pos - eq_pos - 1u));
        init_part = std::format(" = {}", rewrite_decompiler_c_tokens(raw_init, rename_map));
    }

    const std::string_view trailing = body.substr(semi_pos + 1u);
    std::string was_comment;
    if (eff_name != var_name && trailing.find("was ") == std::string_view::npos) {
        was_comment = std::format(" /* was {} */", var_name);
    }
    line = std::format("{}{}{};{}{}", indent, decl_lhs, init_part, was_comment, trailing);
    return true;
}

} // namespace

std::string rewrite_decompiler_c_tokens(
    std::string_view code,
    const std::unordered_map<std::string, std::string>& rename_map,
    bool& in_block_comment) {
    if (code.empty()) {
        return {};
    }

    if (!in_block_comment) {
        const std::string_view trimmed_line = trim_ascii(code);
        if (trimmed_line.starts_with('#')) {
            return std::string(code);
        }
    }

    std::string out;
    out.reserve(code.size() + 16u);
    std::size_t i = 0u;
    while (i < code.size()) {
        if (in_block_comment) {
            const std::size_t close_pos = code.find("*/", i);
            if (close_pos == std::string_view::npos) {
                out.append(code.substr(i));
                return out;
            }
            out.append(code.substr(i, close_pos + 2u - i));
            i = close_pos + 2u;
            in_block_comment = false;
            continue;
        }

        const char ch = code[i];
        if (ch == '/' && i + 1u < code.size()) {
            if (code[i + 1u] == '*') {
                out.append("/*");
                i += 2u;
                in_block_comment = true;
                continue;
            }
            if (code[i + 1u] == '/') {
                const std::size_t nl = code.find('\n', i + 2u);
                if (nl == std::string_view::npos) {
                    out.append(code.substr(i));
                    return out;
                }
                out.append(code.substr(i, nl - i));
                i = nl;
                continue;
            }
        }

        if (ch == '"' || ch == '\'') {
            const char quote = ch;
            out.push_back(quote);
            ++i;
            while (i < code.size()) {
                if (code[i] == '\\' && i + 1u < code.size()) {
                    out.push_back(code[i]);
                    out.push_back(code[i + 1u]);
                    i += 2u;
                } else if (code[i] == quote) {
                    out.push_back(quote);
                    ++i;
                    break;
                } else {
                    out.push_back(code[i]);
                    ++i;
                }
            }
            continue;
        }

        if ((ch >= '0' && ch <= '9') ||
            (ch == '.' && i + 1u < code.size() && code[i + 1u] >= '0' && code[i + 1u] <= '9')) {
            out.push_back(ch);
            ++i;
            while (i < code.size()) {
                const char nc = code[i];
                if ((nc == 'e' || nc == 'E' || nc == 'p' || nc == 'P') &&
                    i + 1u < code.size() && (code[i + 1u] == '+' || code[i + 1u] == '-')) {
                    out.push_back(nc);
                    out.push_back(code[i + 1u]);
                    i += 2u;
                } else if (detail::is_override_ident_cont(nc) || nc == '.') {
                    out.push_back(nc);
                    ++i;
                } else {
                    break;
                }
            }
            continue;
        }

        if (detail::is_override_ident_start(ch)) {
            const std::size_t start = i;
            ++i;
            while (i < code.size() && detail::is_override_ident_cont(code[i])) {
                ++i;
            }
            const std::string_view ident = code.substr(start, i - start);
            if (!rename_map.empty() && !is_member_or_tag_context(code, start)) {
                if (const auto it = rename_map.find(std::string(ident));
                    it != rename_map.end() && !it->second.empty()) {
                    out.append(it->second);
                    continue;
                }
            }
            out.append(ident);
            continue;
        }

        out.push_back(ch);
        ++i;
    }
    return out;
}

std::string rewrite_decompiler_c_tokens(
    std::string_view code,
    const std::unordered_map<std::string, std::string>& rename_map) {
    bool in_block_comment = false;
    return rewrite_decompiler_c_tokens(code, rename_map, in_block_comment);
}

void apply_decompiler_overrides(
    DecompiledUnit& unit,
    const DecompilerFunctionOverride& override_spec) {
    if (unit.status != DecompileStatus::Ready || override_spec.empty() || unit.lines.empty()) {
        return;
    }

    std::unordered_map<std::string, std::string> rename_map;
    std::unordered_map<std::string_view, const DecompilerVariableOverride*> var_map;
    rename_map.reserve(override_spec.variables.size());
    var_map.reserve(override_spec.variables.size());
    for (const DecompilerVariableOverride& v : override_spec.variables) {
        var_map.emplace(v.original_name, &v);
        if (!v.renamed_to.empty() && v.renamed_to != v.original_name) {
            rename_map.emplace(v.original_name, v.renamed_to);
        }
    }

    bool header_handled = false;
    bool in_block_comment = false;
    for (DecompiledLine& line : unit.lines) {
        if (!header_handled && !in_block_comment) {
            const std::string_view trimmed = trim_ascii(line.text);
            if (!trimmed.empty() && !trimmed.starts_with("//") &&
                !trimmed.starts_with("/*") && !trimmed.starts_with('#') &&
                trimmed.find('(') != std::string_view::npos &&
                trimmed.find(';') == std::string_view::npos) {
                if (try_rewrite_function_header_line(line.text, override_spec, var_map, rename_map)) {
                    header_handled = true;
                    continue;
                }
            }
        }
        if (!in_block_comment && header_handled &&
            try_rewrite_local_decl_line(line.text, var_map, rename_map)) {
            continue;
        }
        line.text = rewrite_decompiler_c_tokens(line.text, rename_map, in_block_comment);
    }
}

std::string compute_decompiler_override_digest(
    const std::optional<DecompilerFunctionOverride>& override_spec) {
    if (!override_spec.has_value() || override_spec->empty()) {
        return {};
    }
    peelf::Sha256Hasher hasher;
    const auto feed = [&hasher](std::string_view sv) {
        hasher.update(sv);
        hasher.update(std::string_view{"\0", 1});
    };
    feed(std::to_string(override_spec->function_address));
    feed(override_spec->return_type);
    feed(override_spec->signature_override);
    std::vector<const DecompilerVariableOverride*> sorted_vars;
    sorted_vars.reserve(override_spec->variables.size());
    for (const auto& v : override_spec->variables) {
        sorted_vars.push_back(&v);
    }
    std::ranges::sort(sorted_vars, [](const auto* a, const auto* b) {
        return a->original_name < b->original_name;
    });
    for (const auto* v : sorted_vars) {
        feed(v->original_name);
        feed(v->renamed_to);
        feed(v->c_type);
    }
    return hasher.finalize_hex();
}

std::string compute_decompiler_settings_fingerprint(const DecompilerSettings& settings) {
    peelf::Sha256Hasher hasher;
    const auto feed = [&hasher](std::string_view sv) {
        hasher.update(sv);
        hasher.update(std::string_view{"\0", 1});
    };
    feed(std::to_string(static_cast<int>(settings.provider)));
    switch (settings.provider) {
        case DecompilerProvider::Ghidra:
            feed(settings.ghidra_home.string());
            feed(settings.java.string());
            break;
        case DecompilerProvider::BinaryNinja:
            feed(settings.python.string());
            feed(settings.binary_ninja_home.string());
            break;
        case DecompilerProvider::RetDec:
            feed(settings.retdec.string());
            break;
        case DecompilerProvider::AnnotatedCode:
        case DecompilerProvider::StructuredPseudoC:
            break;
    }
    return hasher.finalize_hex();
}

DecompileCacheKey make_decompile_cache_key(const DecompileRequest& request,
                                           const DecompilerSettings& settings) {
    std::string sha = request.binary_sha256;
    if (sha.empty() && !request.image_bytes.empty()) {
        sha = peelf::sha256_hex(request.image_bytes);
    }
    return DecompileCacheKey{
        .binary_sha256 = std::move(sha),
        .patch_revision = request.patch_revision,
        .symbol_revision = request.symbol_revision,
        .symbols_sha256 = compute_decompiler_symbols_digest(request.symbols, request.types),
        .function_override_sha256 = compute_decompiler_override_digest(request.function_override),
        .provider = settings.provider,
        .settings_fingerprint = compute_decompiler_settings_fingerprint(settings),
        .architecture = request.architecture,
        .endianness = request.endianness,
        .thumb = request.thumb,
        .function_address = request.address,
        .function_size = request.function_size,
    };
}

std::optional<DecompiledUnit> DecompileCache::get(const DecompileCacheKey& key) const {
    if (key.binary_sha256.empty()) {
        return std::nullopt;
    }
    std::scoped_lock lock(mutex_);
    const auto it = index_.find(key);
    if (it == index_.end()) {
        return std::nullopt;
    }
    lru_.splice(lru_.begin(), lru_, it->second);
    DecompiledUnit copy = it->second->unit;
    copy.cache_source = DecompileCacheSource::MemoryCacheHit;
    return copy;
}

void DecompileCache::put(const DecompileCacheKey& key, DecompiledUnit unit) {
    if (key.binary_sha256.empty() || unit.status != DecompileStatus::Ready) {
        return;
    }
    std::scoped_lock lock(mutex_);
    if (const auto it = index_.find(key); it != index_.end()) {
        it->second->unit = std::move(unit);
        lru_.splice(lru_.begin(), lru_, it->second);
        return;
    }
    if (max_entries_ == 0u) {
        return;
    }

    lru_.push_front(Entry{.key = key, .unit = std::move(unit)});
    struct LruInsertRollback {
        std::list<Entry>& list;
        bool committed{false};
        explicit LruInsertRollback(std::list<Entry>& l) noexcept : list(l) {}
        LruInsertRollback(const LruInsertRollback&) = delete;
        LruInsertRollback& operator=(const LruInsertRollback&) = delete;
        ~LruInsertRollback() noexcept {
            if (!committed) {
                list.pop_front();
            }
        }
    } rollback{lru_};

    index_.try_emplace(lru_.front().key, lru_.begin());
    rollback.committed = true;

    while (lru_.size() > max_entries_) {
        index_.erase(lru_.back().key);
        lru_.pop_back();
    }
}

void DecompileCache::invalidate_function(std::string_view binary_sha256,
                                         std::uint64_t function_address) {
    std::scoped_lock lock(mutex_);
    for (auto it = lru_.begin(); it != lru_.end();) {
        if (it->key.binary_sha256 == binary_sha256 &&
            it->key.function_address == function_address) {
            index_.erase(it->key);
            it = lru_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecompileCache::invalidate_binary(std::string_view binary_sha256) {
    std::scoped_lock lock(mutex_);
    for (auto it = lru_.begin(); it != lru_.end();) {
        if (it->key.binary_sha256 == binary_sha256) {
            index_.erase(it->key);
            it = lru_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecompileCache::clear() {
    std::scoped_lock lock(mutex_);
    index_.clear();
    lru_.clear();
}

std::size_t DecompileCache::size() const {
    std::scoped_lock lock(mutex_);
    return lru_.size();
}
}
