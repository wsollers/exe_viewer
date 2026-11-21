#include "decompiler.hpp"
#include "analysis/project.hpp"
#include <peelf/sha256.hpp>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <format>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace viewer {
namespace {
bool installation(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path / "Ghidra/Framework/Utility/lib/Utility.jar", ec);
}
std::filesystem::path environment(const char* name) {
#ifdef _WIN32
    char* value = nullptr; std::size_t size = 0;
    _dupenv_s(&value, &size, name);
    const std::filesystem::path result = value ? value : "";
    std::free(value); return result;
#else
    const auto* value = std::getenv(name);
    return value ? value : "";
#endif
}

bool is_wsl_windows_c_mount(const std::filesystem::path& path) {
    std::string generic = path.generic_string();
    std::ranges::transform(generic, generic.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return generic == "/mnt/c" || generic.starts_with("/mnt/c/");
}

std::filesystem::path safe_scratch_base_directory() {
    return safe_decompiler_scratch_directory();
}

[[nodiscard]] unsigned long current_process_id() noexcept {
#ifdef _WIN32
    return static_cast<unsigned long>(::GetCurrentProcessId());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

[[nodiscard]] bool ensure_private_directory(const std::filesystem::path& dir) noexcept {
    if (dir.empty()) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (!std::filesystem::is_directory(dir, ec)) {
        return false;
    }
    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec);
    return true;
}

enum class LockAcquireOutcome : std::uint8_t {
    Acquired,
    Cancelled,
    TimedOut,
    Failed,
};

class ScopedWorkspaceFileLock {
public:
    ScopedWorkspaceFileLock() noexcept = default;
    ~ScopedWorkspaceFileLock() noexcept {
        release();
    }

    ScopedWorkspaceFileLock(const ScopedWorkspaceFileLock&) = delete;
    ScopedWorkspaceFileLock& operator=(const ScopedWorkspaceFileLock&) = delete;

    ScopedWorkspaceFileLock(ScopedWorkspaceFileLock&& other) noexcept
#ifdef _WIN32
        : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE))
        , locked_(std::exchange(other.locked_, false))
#else
        : fd_(std::exchange(other.fd_, -1))
        , locked_(std::exchange(other.locked_, false))
#endif
    {
    }

    ScopedWorkspaceFileLock& operator=(ScopedWorkspaceFileLock&& other) noexcept {
        if (this != &other) {
            release();
#ifdef _WIN32
            handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
#else
            fd_ = std::exchange(other.fd_, -1);
#endif
            locked_ = std::exchange(other.locked_, false);
        }
        return *this;
    }

    [[nodiscard]] static std::optional<ScopedWorkspaceFileLock> try_acquire(
        const std::filesystem::path& lock_path) noexcept {
        ScopedWorkspaceFileLock guard;
        if (!guard.open_file(lock_path)) {
            return std::nullopt;
        }
        if (!guard.try_lock_once()) {
            return std::nullopt;
        }
        return guard;
    }

    [[nodiscard]] static std::pair<LockAcquireOutcome, ScopedWorkspaceFileLock> acquire(
        const std::filesystem::path& lock_path,
        std::chrono::milliseconds timeout,
        std::stop_token stop) {
        ScopedWorkspaceFileLock guard;
        if (stop.stop_requested()) {
            return {LockAcquireOutcome::Cancelled, ScopedWorkspaceFileLock{}};
        }
        if (!guard.open_file(lock_path)) {
            return {LockAcquireOutcome::Failed, ScopedWorkspaceFileLock{}};
        }

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (true) {
            if (guard.try_lock_once()) {
                return {LockAcquireOutcome::Acquired, std::move(guard)};
            }
            if (stop.stop_requested()) {
                return {LockAcquireOutcome::Cancelled, ScopedWorkspaceFileLock{}};
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return {LockAcquireOutcome::TimedOut, ScopedWorkspaceFileLock{}};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void release() noexcept {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) {
            if (locked_) {
                OVERLAPPED ov{};
                (void)::UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &ov);
                locked_ = false;
            }
            (void)::CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (fd_ >= 0) {
            if (locked_) {
                (void)::flock(fd_, LOCK_UN);
                locked_ = false;
            }
            (void)::close(fd_);
            fd_ = -1;
        }
#endif
    }

private:
    [[nodiscard]] bool open_file(const std::filesystem::path& lock_path) noexcept {
#ifdef _WIN32
        handle_ = ::CreateFileW(
            lock_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        return handle_ != INVALID_HANDLE_VALUE;
#else
        do {
            fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
        } while (fd_ < 0 && errno == EINTR);
        if (fd_ >= 0) {
            (void)::fchmod(fd_, S_IRUSR | S_IWUSR);
        }
        return fd_ >= 0;
#endif
    }

    [[nodiscard]] bool try_lock_once() noexcept {
#ifdef _WIN32
        OVERLAPPED ov{};
        if (::LockFileEx(handle_,
                         LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                         0,
                         MAXDWORD,
                         MAXDWORD,
                         &ov) != 0) {
            locked_ = true;
            return true;
        }
        return false;
#else
        int rc = 0;
        do {
            rc = ::flock(fd_, LOCK_EX | LOCK_NB);
        } while (rc != 0 && errno == EINTR);
        if (rc == 0) {
            locked_ = true;
            return true;
        }
        return false;
#endif
    }

#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
    bool locked_ = false;
};

[[nodiscard]] std::filesystem::path workspace_lock_path(
    const std::filesystem::path& cache_root,
    std::string_view ws_dir_name) {
    return cache_root / ".locks" / (std::string(ws_dir_name) + ".lock");
}

std::mutex& ghidra_workspace_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::atomic<std::uint64_t>& workspace_lru_clock() {
    static std::atomic<std::uint64_t> clock{0};
    return clock;
}

void write_stamp_file(const std::filesystem::path& path, std::string_view content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_stamp_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void touch_workspace_lru(const std::filesystem::path& project_dir) {
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    const std::uint64_t seq = ++workspace_lru_clock();
    write_stamp_file(project_dir / ".peelf_last_used", std::format("{} {}\n", now_ns, seq));
}

std::pair<long long, std::uint64_t> read_workspace_lru_order(const std::filesystem::path& project_dir) {
    std::istringstream in(read_stamp_file(project_dir / ".peelf_last_used"));
    long long ts = 0;
    std::uint64_t seq = 0;
    if (in >> ts >> seq) {
        return {ts, seq};
    }
    std::error_code ec;
    const auto ftime = std::filesystem::last_write_time(project_dir, ec);
    if (!ec) {
        return {static_cast<long long>(ftime.time_since_epoch().count()), 0u};
    }
    return {0, 0u};
}

void prune_ghidra_workspaces(const std::filesystem::path& cache_root,
                             std::size_t max_keep,
                             const std::filesystem::path& protected_dir) {
    const std::size_t limit = std::max<std::size_t>(1, max_keep);
    std::error_code ec;
    struct Candidate {
        std::filesystem::path path;
        std::pair<long long, std::uint64_t> order;
    };
    std::vector<Candidate> workspaces;
    for (const auto& entry : std::filesystem::directory_iterator(cache_root, ec)) {
        if (!entry.is_directory(ec)) continue;
        const std::string name = entry.path().filename().string();
        if (!name.starts_with("ws-")) continue;
        workspaces.push_back(Candidate{
            .path = entry.path(),
            .order = read_workspace_lru_order(entry.path()),
        });
    }
    if (workspaces.size() <= limit) {
        return;
    }
    std::ranges::sort(workspaces, [](const Candidate& a, const Candidate& b) {
        return a.order < b.order;
    });
    std::size_t remaining = workspaces.size();
    (void)ensure_private_directory(cache_root / ".locks");
    for (const auto& ws : workspaces) {
        if (remaining <= limit) break;
        if (ws.path == protected_dir) continue;
        const std::string ws_name = ws.path.filename().string();
        auto ws_lock = ScopedWorkspaceFileLock::try_acquire(workspace_lock_path(cache_root, ws_name));
        if (!ws_lock.has_value()) {
            continue;
        }
        std::filesystem::remove_all(ws.path, ec);
        --remaining;
    }
}
}

std::filesystem::path default_ghidra_cache_directory() {
#ifndef _WIN32
    if (const auto custom = environment("PEELF_CACHE_DIR");
        !custom.empty() && !is_wsl_windows_c_mount(custom)) {
        return custom / "ghidra";
    }
    if (const auto xdg = environment("XDG_CACHE_HOME");
        !xdg.empty() && !is_wsl_windows_c_mount(xdg)) {
        return xdg / "peelf_viewer" / "ghidra";
    }
    return std::filesystem::path("/tmp") /
           std::format("peelf_viewer-ghidra-{}", static_cast<unsigned long>(::geteuid()));
#else
    if (const auto custom = environment("PEELF_CACHE_DIR"); !custom.empty()) {
        return custom / "ghidra";
    }
    if (const auto local_app_data = environment("LOCALAPPDATA"); !local_app_data.empty()) {
        return local_app_data / "peelf_viewer" / "ghidra";
    }
    return std::filesystem::temp_directory_path() / "peelf_viewer-ghidra";
#endif
}

void clear_ghidra_workspace_cache(const std::filesystem::path& cache_root) {
    if (cache_root.empty()) return;
    std::scoped_lock lock(ghidra_workspace_mutex());
    std::error_code ec;
    if (!std::filesystem::exists(cache_root, ec)) return;
    const bool locks_ready = ensure_private_directory(cache_root / ".locks");
    for (const auto& entry : std::filesystem::directory_iterator(cache_root, ec)) {
        if (!entry.is_directory(ec)) continue;
        const std::string name = entry.path().filename().string();
        if (name.starts_with("ws-")) {
            std::optional<ScopedWorkspaceFileLock> ws_lock;
            if (locks_ready) {
                ws_lock = ScopedWorkspaceFileLock::try_acquire(workspace_lock_path(cache_root, name));
                if (!ws_lock.has_value()) {
                    continue;
                }
            }
            std::filesystem::remove_all(entry.path(), ec);
        }
    }
}
DecompilerSettings discover_decompilers(const std::filesystem::path& directory) {
    DecompilerSettings settings;
    settings.ghidra_home = environment("GHIDRA_INSTALL_DIR");
    if (settings.ghidra_home.empty()) {
        for (auto parent = directory; !parent.empty(); parent = parent.parent_path()) {
            for (const auto& base : {parent / "tools", parent / "out/tools"}) {
                std::error_code ec;
                for (const auto& entry : std::filesystem::directory_iterator(base, ec)) {
                    if (installation(entry.path()) && entry.path() > settings.ghidra_home)
                        settings.ghidra_home = entry.path();
                }
            }
            if (!settings.ghidra_home.empty() || parent == parent.parent_path()) break;
        }
    }
    if (auto home = environment("JAVA_HOME"); !home.empty()) {
#ifdef _WIN32
        settings.java = home / "bin/java.exe";
#else
        settings.java = home / "bin/java";
#endif
    }
    const BinaryNinjaCapabilityStatus bn_caps = discover_binary_ninja(settings);
    if (bn_caps.install_found) {
        settings.binary_ninja_home = bn_caps.install_directory;
    }
    return settings;
}
peelf::Result<DecompilerSettings> read_decompiler_settings(const std::filesystem::path& path) {
    auto text = read_project_file(path);
    if (!text) return std::unexpected(text.error());
    std::istringstream in(*text);
    std::string magic, home, java, python;
    int version = 0, provider = -1;
    DecompilerSettings settings;
    if (!(in >> magic >> version >> provider)) {
        return peelf::make_error("Invalid decompiler settings");
    }
    if (magic != "PEELF_DECOMPILER" || (version != 1 && version != 2) || provider < 0 || provider > 4) {
        return peelf::make_error("Invalid decompiler settings");
    }
    if (version == 1) {
        if (!(in >> std::quoted(home) >> std::quoted(java) >> std::quoted(python) >> settings.timeout_seconds) ||
            java.empty() || python.empty() || settings.timeout_seconds < 10 || settings.timeout_seconds > 3600) {
            return peelf::make_error("Invalid decompiler settings");
        }
        in >> std::ws;
        if (!in.eof()) return peelf::make_error("Unexpected trailing decompiler settings");
        settings.provider = static_cast<DecompilerProvider>(provider);
        settings.ghidra_home = home;
        settings.java = java;
        settings.python = python;
        return settings;
    }

    std::string retdec, cache_dir;
    std::size_t max_cached_workspaces = 0;
    int reuse_analysis = -1;
    if (!(in >> std::quoted(home) >> std::quoted(java) >> std::quoted(python) >> std::quoted(retdec)
             >> settings.timeout_seconds >> std::quoted(cache_dir) >> max_cached_workspaces >> reuse_analysis) ||
        java.empty() || python.empty() || retdec.empty() ||
        settings.timeout_seconds < 10 || settings.timeout_seconds > 3600 ||
        max_cached_workspaces < 1u || max_cached_workspaces > 1024u ||
        (reuse_analysis != 0 && reuse_analysis != 1)) {
        return peelf::make_error("Invalid decompiler settings");
    }
    in >> std::ws;
    while (in.peek() != std::char_traits<char>::eof()) {
        std::string key;
        if (!std::getline(in, key, '=') || key != "binary_ninja_home") {
            return peelf::make_error("Unexpected trailing decompiler settings");
        }
        std::string bn_home;
        if (in.peek() == '"') {
            if (!(in >> std::quoted(bn_home))) {
                return peelf::make_error("Invalid decompiler settings");
            }
        } else {
            std::getline(in, bn_home);
            if (!bn_home.empty() && bn_home.back() == '\r') {
                bn_home.pop_back();
            }
        }
        settings.binary_ninja_home = bn_home;
        in >> std::ws;
    }

    settings.provider = static_cast<DecompilerProvider>(provider);
    settings.ghidra_home = home;
    settings.java = java;
    settings.python = python;
    settings.retdec = retdec;
    settings.cache_directory = cache_dir;
    settings.max_cached_workspaces = max_cached_workspaces;
    settings.reuse_analysis = (reuse_analysis != 0);
    return settings;
}
peelf::Result<void> save_decompiler_settings(const std::filesystem::path& path, const DecompilerSettings& settings) {
    std::ostringstream out;
    out << "PEELF_DECOMPILER 2\n"
        << static_cast<int>(settings.provider) << '\n'
        << std::quoted(settings.ghidra_home.string()) << '\n'
        << std::quoted(settings.java.string()) << '\n'
        << std::quoted(settings.python.string()) << '\n'
        << std::quoted(settings.retdec.string()) << '\n'
        << settings.timeout_seconds << '\n'
        << std::quoted(settings.cache_directory.string()) << '\n'
        << settings.max_cached_workspaces << '\n'
        << (settings.reuse_analysis ? 1 : 0) << '\n'
        << "binary_ninja_home=" << std::quoted(settings.binary_ninja_home.string()) << '\n';
    return write_analysis_file(path, out.str());
}
std::filesystem::path GhidraDecompiler::effective_cache_directory() const {
    return !settings_.cache_directory.empty() ? settings_.cache_directory
                                              : default_ghidra_cache_directory();
}

void GhidraDecompiler::clear_cached_workspaces() const {
    clear_ghidra_workspace_cache(effective_cache_directory());
}

DecompiledUnit GhidraDecompiler::decompile(const DecompileRequest& request, std::stop_token stop) const {
    auto failure = [](DecompileStatus status, std::string message) {
        DecompiledUnit unit;
        unit.status = status;
        unit.provider = "Ghidra";
        unit.diagnostic = std::move(message);
        return unit;
    };
    if (stop.stop_requested()) return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    if (!installation(settings_.ghidra_home))
        return failure(DecompileStatus::Unavailable, "Set the Ghidra installation directory (containing Ghidra and support folders).");
    if (!std::filesystem::is_regular_file(scripts_ / "PeelfDecompile.java"))
        return failure(DecompileStatus::Unavailable, "Ghidra bridge resource is missing");
    if (request.architecture == peelf::Architecture::Unknown)
        return failure(DecompileStatus::Unsupported, "Unknown CPU architecture");
    if (request.image_bytes.empty())
        return failure(DecompileStatus::Failed, "Empty binary snapshot");
    if (settings_.timeout_seconds < 10 || settings_.timeout_seconds > 3600)
        return failure(DecompileStatus::Failed, "Timeout must be between 10 and 3600 seconds");

    static std::atomic<std::uint64_t> serial{};
    const auto scratch_dir = safe_scratch_base_directory() / std::format(
        "peelf-ghidra-run-{}-{}-{}",
        current_process_id(),
        std::chrono::steady_clock::now().time_since_epoch().count(),
        ++serial);
    std::error_code ec;
    if (!ensure_private_directory(scratch_dir))
        return failure(DecompileStatus::Failed, "Cannot create Ghidra workspace");
    struct Workspace {
        std::filesystem::path path;
        explicit Workspace(std::filesystem::path p) : path(std::move(p)) {}
        Workspace(const Workspace&) = delete;
        Workspace& operator=(const Workspace&) = delete;
        Workspace(Workspace&&) = delete;
        Workspace& operator=(Workspace&&) = delete;
        ~Workspace() noexcept {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } scratch_cleanup{scratch_dir};

    const auto output = scratch_dir / "result.txt";
    const auto metadata = scratch_dir / "symbols.txt";
    {
        std::ofstream file(metadata, std::ios::binary);
        file << encode_decompiler_symbols(request);
        file.close();
        if (!file) return failure(DecompileStatus::Failed, "Cannot write symbol snapshot");
    }

    const auto run_and_parse = [&](const std::vector<std::string>& args)
        -> std::pair<BackendProcessResult, DecompiledUnit> {
        std::error_code rm_ec;
        std::filesystem::remove(output, rm_ec);
        const auto result = runner_.run(
            settings_.java, args, std::chrono::seconds(settings_.timeout_seconds), stop);
        if (result.cancelled)
            return {result, failure(DecompileStatus::Cancelled, "Decompilation cancelled")};
        if (result.timed_out)
            return {result, failure(DecompileStatus::Timeout,
                                    "Ghidra exceeded the configured deadline; increase the timeout for large binaries.")};
        std::error_code stat_ec;
        if (!std::filesystem::is_regular_file(output, stat_ec)) {
            return {result, failure(
                result.exit_code < 0 ? DecompileStatus::Unavailable : DecompileStatus::Failed,
                std::format("Ghidra produced no result (exit {}). Check the Java executable and Ghidra/JDK compatibility. Ghidra 12.2 requires JDK 25.",
                            result.exit_code))};
        }
        const auto size = std::filesystem::file_size(output, stat_ec);
        if (stat_ec || size > 4 * 1024 * 1024)
            return {result, failure(DecompileStatus::Failed, "Ghidra output exceeds 4 MiB")};
        std::ifstream file(output, std::ios::binary);
        std::string text(static_cast<std::size_t>(size), '\0');
        if (!file.read(text.data(), static_cast<std::streamsize>(size)))
            return {result, failure(DecompileStatus::Failed, "Cannot read Ghidra output")};
        auto unit = parse_decompiler_output(text);
        unit.provider = "Ghidra";
        if (result.exit_code != 0 && unit.status == DecompileStatus::Ready)
            return {result, failure(DecompileStatus::Failed, "Ghidra exited unsuccessfully; output discarded")};
        if (unit.status == DecompileStatus::Ready &&
            request.function_override.has_value() &&
            !request.function_override->empty()) {
            apply_decompiler_overrides(unit, *request.function_override);
        }
        return {result, std::move(unit)};
    };

    const auto build_common_jvm_prefix = [&](const std::filesystem::path& project_dir) {
        return std::vector<std::string>{
            "-Xmx2G", "-Xshare:off", "-Djava.awt.headless=true",
            "-Djava.system.class.loader=ghidra.GhidraClassLoader", "-Dfile.encoding=UTF8",
            "-Duser.language=en", "-Duser.country=US", "--enable-native-access=ALL-UNNAMED",
            "-cp", (settings_.ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").string(),
            "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
            project_dir.string(), "analysis"};
    };

    if (!settings_.reuse_analysis) {
        const auto input = scratch_dir / "input.bin";
        {
            std::ofstream file(input, std::ios::binary);
            file.write(reinterpret_cast<const char*>(request.image_bytes.data()),
                       static_cast<std::streamsize>(request.image_bytes.size()));
            file.close();
            if (!file) return failure(DecompileStatus::Failed, "Cannot write binary snapshot");
        }
        auto args = build_common_jvm_prefix(scratch_dir);
        const std::vector<std::string> tail{
            "-import", input.string(), "-scriptPath", scripts_.string(),
            "-preScript", "PeelfDecompile.java", "prepare", output.string(),
            std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
            "-postScript", "PeelfDecompile.java", "export", output.string(),
            std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
            "-analysisTimeoutPerFile", std::to_string(settings_.timeout_seconds),
            "-max-cpu", "2", "-deleteProject"};
        args.insert(args.end(), tail.begin(), tail.end());
        auto [proc, unit] = run_and_parse(args);
        unit.cache_source = DecompileCacheSource::FreshAnalysis;
        return unit;
    }

    const std::string binary_sha = !request.binary_sha256.empty()
                                       ? request.binary_sha256
                                       : peelf::sha256_hex(request.image_bytes);
    const std::string symbols_sha =
        compute_decompiler_symbols_digest(request.symbols, request.types);
    const std::string ws_material = std::format(
        "peelf-ghidra-ws-v1|{}|{}|{}|{}|{}",
        binary_sha,
        request.patch_revision,
        static_cast<int>(request.architecture),
        static_cast<int>(request.endianness),
        settings_.ghidra_home.string());
    const std::string ws_id = peelf::sha256_hex(ws_material).substr(0, 24);

    const std::filesystem::path cache_root = effective_cache_directory();
    std::scoped_lock lock(ghidra_workspace_mutex());
    if (cache_root.parent_path().filename() == "peelf_viewer") {
        (void)ensure_private_directory(cache_root.parent_path());
    }
    if (!ensure_private_directory(cache_root) ||
        !ensure_private_directory(cache_root / ".locks")) {
        return failure(DecompileStatus::Failed, "Cannot create Ghidra cache directory");
    }

    const std::string ws_dir_name = "ws-" + ws_id;
    auto [lock_outcome, ws_file_lock] = ScopedWorkspaceFileLock::acquire(
        workspace_lock_path(cache_root, ws_dir_name),
        std::chrono::seconds(settings_.timeout_seconds),
        stop);
    if (lock_outcome == LockAcquireOutcome::Cancelled) {
        return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    }
    if (lock_outcome == LockAcquireOutcome::TimedOut) {
        return failure(DecompileStatus::Timeout,
                       "Timed out waiting for concurrent Ghidra workspace lock.");
    }
    if (lock_outcome != LockAcquireOutcome::Acquired) {
        return failure(DecompileStatus::Failed, "Cannot acquire Ghidra workspace lock");
    }

    const std::filesystem::path project_dir = cache_root / ws_dir_name;
    const std::filesystem::path gpr_file = project_dir / "analysis.gpr";
    const std::filesystem::path stamp_file = project_dir / ".peelf_complete";
    const std::filesystem::path input = project_dir / "input.bin";

    if (request.force_reanalyze) {
        std::filesystem::remove_all(project_dir, ec);
    }

    const bool warm_ready =
        std::filesystem::is_regular_file(gpr_file, ec) &&
        std::filesystem::is_regular_file(stamp_file, ec) &&
        std::filesystem::is_regular_file(input, ec);

    if (warm_ready) {
        std::filesystem::permissions(
            project_dir,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec);
        const std::string applied_symbols_sha = read_stamp_file(stamp_file);
        const bool symbols_changed = (applied_symbols_sha != symbols_sha);
        const std::string warm_phase = symbols_changed ? "export_sync" : "export_warm";

        auto warm_args = build_common_jvm_prefix(project_dir);
        const std::vector<std::string> warm_tail{
            "-process", "input.bin", "-noanalysis",
            "-scriptPath", scripts_.string(),
            "-postScript", "PeelfDecompile.java", warm_phase,
            output.string(), std::to_string(request.address),
            request.thumb ? "true" : "false", metadata.string(),
            "-max-cpu", "2"};
        warm_args.insert(warm_args.end(), warm_tail.begin(), warm_tail.end());

        auto [warm_proc, warm_unit] = run_and_parse(warm_args);
        if (warm_proc.cancelled || warm_proc.timed_out) {
            return warm_unit;
        }
        if (warm_proc.exit_code == 0 &&
            (warm_unit.status == DecompileStatus::Ready ||
             warm_unit.status == DecompileStatus::NoFunction ||
             warm_unit.status == DecompileStatus::Unsupported)) {
            if (symbols_changed) {
                write_stamp_file(stamp_file, symbols_sha);
            }
            touch_workspace_lru(project_dir);
            warm_unit.cache_source = DecompileCacheSource::ReusedWorkspace;
            return warm_unit;
        }

        // Warm `-process` failed (e.g. stale lock or corrupted project); reset and retry cold once.
        std::filesystem::remove_all(project_dir, ec);
    }

    std::filesystem::remove_all(project_dir, ec);
    if (!ensure_private_directory(project_dir)) {
        return failure(DecompileStatus::Failed, "Cannot create Ghidra project workspace");
    }
    {
        std::ofstream file(input, std::ios::binary);
        file.write(reinterpret_cast<const char*>(request.image_bytes.data()),
                   static_cast<std::streamsize>(request.image_bytes.size()));
        file.close();
        if (!file) {
            std::filesystem::remove_all(project_dir, ec);
            return failure(DecompileStatus::Failed, "Cannot write binary snapshot");
        }
    }

    auto cold_args = build_common_jvm_prefix(project_dir);
    const std::vector<std::string> cold_tail{
        "-import", input.string(), "-scriptPath", scripts_.string(),
        "-preScript", "PeelfDecompile.java", "prepare", output.string(),
        std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
        "-postScript", "PeelfDecompile.java", "export", output.string(),
        std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
        "-analysisTimeoutPerFile", std::to_string(settings_.timeout_seconds),
        "-max-cpu", "2"};
    cold_args.insert(cold_args.end(), cold_tail.begin(), cold_tail.end());

    auto [cold_proc, cold_unit] = run_and_parse(cold_args);
    const bool persisted_ok =
        cold_proc.exit_code == 0 &&
        (cold_unit.status == DecompileStatus::Ready ||
         cold_unit.status == DecompileStatus::NoFunction) &&
        std::filesystem::is_regular_file(gpr_file, ec);

    if (persisted_ok) {
        write_stamp_file(stamp_file, symbols_sha);
        touch_workspace_lru(project_dir);
        prune_ghidra_workspaces(cache_root, settings_.max_cached_workspaces, project_dir);
    } else {
        std::filesystem::remove_all(project_dir, ec);
    }
    cold_unit.cache_source = DecompileCacheSource::FreshAnalysis;
    return cold_unit;
}
}
