#include "peelf/process.hpp"
#include "peelf/provenance.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <unordered_map>
#include <utility>

#ifdef __linux__
#include <unistd.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace peelf {
namespace {

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex_u64(std::string_view token) noexcept {
    if (token.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (ec != std::errc{} || ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::uint64_t> parse_dec_u64(std::string_view token) noexcept {
    if (token.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 10);
    if (ec != std::errc{} || ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    return value;
}

void annotate_special_pathname_usage(MemoryRegion& region) {
    if (region.pathname == "[heap]") {
        region.usage.heap_id = 0u;
    } else if (region.pathname.starts_with("[heap:") && region.pathname.back() == ']') {
        const std::string_view inner(region.pathname.data() + 6, region.pathname.size() - 7);
        if (const auto hid = parse_dec_u64(inner);
            hid && *hid <= std::numeric_limits<std::uint32_t>::max()) {
            region.usage.heap_id = static_cast<std::uint32_t>(*hid);
        }
    } else if (region.pathname.starts_with("[stack:") && region.pathname.back() == ']') {
        const std::string_view inner(region.pathname.data() + 7, region.pathname.size() - 8);
        if (const auto tid = parse_dec_u64(inner);
            tid && *tid <= std::numeric_limits<ThreadId>::max()) {
            region.usage.owner_tid = static_cast<ThreadId>(*tid);
            region.kind = MemoryRegionKind::Stack;
        }
    }

    const bool is_anon_like = region.pathname.empty() || region.pathname.starts_with("[anon");
    const bool no_access_private = !region.protection.readable && !region.protection.writable &&
                                   !region.protection.executable && !region.protection.shared;
    if (is_anon_like && no_access_private) {
        region.usage.is_reserved_only = true;
        region.usage.committed_bytes = 0;
    } else {
        region.usage.committed_bytes = region.size();
    }
}

[[nodiscard]] std::string_view next_whitespace_token(std::string_view& rest) noexcept {
    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
        rest.remove_prefix(1);
    }
    std::size_t pos = 0;
    while (pos < rest.size() && rest[pos] != ' ' && rest[pos] != '\t') {
        ++pos;
    }
    const std::string_view tok = rest.substr(0, pos);
    rest.remove_prefix(pos);
    return tok;
}

[[nodiscard]] bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool looks_like_binary_module_filename(std::string_view filename) noexcept {
    if (filename.empty()) {
        return false;
    }
    if (filename.find(".so.") != std::string_view::npos) {
        return true;
    }
    const auto dot = filename.rfind('.');
    if (dot != std::string_view::npos) {
        const std::string_view ext = filename.substr(dot);
        if (iequals_ascii(ext, ".so") || iequals_ascii(ext, ".dll") ||
            iequals_ascii(ext, ".exe") || iequals_ascii(ext, ".elf") ||
            iequals_ascii(ext, ".pyd") || iequals_ascii(ext, ".drv") ||
            iequals_ascii(ext, ".ocx") || iequals_ascii(ext, ".sys")) {
            return true;
        }
    }
    return filename.starts_with("ld-linux") || filename.starts_with("ld-musl");
}

[[nodiscard]] std::string basename_from_path(std::string_view path_str) {
    const auto slash = path_str.find_last_of("/\\");
    if (slash == std::string_view::npos) {
        return std::string(path_str);
    }
    return std::string(path_str.substr(slash + 1));
}

[[nodiscard]] MemoryRegionKind classify_initial_region_kind(std::string_view pathname,
                                                            std::string_view clean_main_exe) {
    if (pathname.empty() || pathname.starts_with("[anon")) {
        return MemoryRegionKind::Anonymous;
    }
    if (pathname == "[heap]" || pathname.starts_with("[heap:")) {
        return MemoryRegionKind::Heap;
    }
    if (pathname == "[stack]" || pathname.starts_with("[stack:")) {
        return MemoryRegionKind::Stack;
    }
    if (pathname == "[vdso]" || pathname == "[vvar]" || pathname == "[vsyscall]" ||
        pathname.starts_with("[vvar")) {
        return MemoryRegionKind::Vdso;
    }
    if (pathname.front() == '[') {
        return MemoryRegionKind::Anonymous;
    }
    const std::string clean = strip_deleted_proc_suffix(pathname);
    if (!clean_main_exe.empty() && clean == clean_main_exe) {
        return MemoryRegionKind::Image;
    }
    return MemoryRegionKind::MappedFile;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> try_read_disk_file(
    const std::filesystem::path& path,
    std::size_t max_bytes = 256ull * 1024ull * 1024ull) {
    std::error_code ec;
    if (path.empty() || !std::filesystem::is_regular_file(path, ec) || ec) {
        return std::nullopt;
    }
    const auto file_sz = std::filesystem::file_size(path, ec);
    if (ec || file_sz == 0 || file_sz > max_bytes) {
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(file_sz));
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (in.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return std::nullopt;
    }
    return bytes;
}

void probe_module_format_and_entry(ModuleInfo& mod, IProcessSession* probe_session) {
    if (probe_session != nullptr) {
        std::array<std::uint8_t, 512> header{};
        auto read_res = probe_session->read_memory(mod.base_address, header);
        if (read_res && *read_res >= 4) {
            const auto span = std::span<const std::uint8_t>(header.data(), *read_res);
            mod.format = detect_format(span);
            if (mod.format == Format::ELF && *read_res >= 64) {
                const bool is_64 = header[4] == 2;
                const bool le = header[5] != 2;
                const auto rd16 = [&](std::size_t off) -> std::uint16_t {
                    return le ? static_cast<std::uint16_t>(header[off] | (header[off + 1] << 8))
                              : static_cast<std::uint16_t>((header[off] << 8) | header[off + 1]);
                };
                const auto rd32 = [&](std::size_t off) -> std::uint32_t {
                    std::uint32_t v = 0;
                    for (std::size_t i = 0; i < 4; ++i) {
                        const std::size_t idx = le ? (off + i) : (off + 3 - i);
                        v |= static_cast<std::uint32_t>(header[idx]) << (8 * i);
                    }
                    return v;
                };
                const auto rd64 = [&](std::size_t off) -> std::uint64_t {
                    std::uint64_t v = 0;
                    for (std::size_t i = 0; i < 8; ++i) {
                        const std::size_t idx = le ? (off + i) : (off + 7 - i);
                        v |= static_cast<std::uint64_t>(header[idx]) << (8 * i);
                    }
                    return v;
                };
                const std::uint16_t e_type = rd16(16);
                const std::uint64_t e_entry = is_64 ? rd64(24) : static_cast<std::uint64_t>(rd32(24));
                if (e_entry != 0) {
                    if (e_type == 3 && e_entry < mod.size) {
                        mod.entry_point = mod.base_address + e_entry;
                    } else {
                        mod.entry_point = e_entry;
                    }
                }
            } else if (mod.format == Format::PE && *read_res >= 0x40) {
                const std::uint32_t lfanew =
                    static_cast<std::uint32_t>(header[0x3C]) |
                    (static_cast<std::uint32_t>(header[0x3D]) << 8) |
                    (static_cast<std::uint32_t>(header[0x3E]) << 16) |
                    (static_cast<std::uint32_t>(header[0x3F]) << 24);
                if (static_cast<std::size_t>(lfanew) + 44 <= *read_res &&
                    header[lfanew] == 'P' && header[lfanew + 1] == 'E' &&
                    header[lfanew + 2] == 0 && header[lfanew + 3] == 0) {
                    const std::size_t opt = static_cast<std::size_t>(lfanew) + 24;
                    const std::uint32_t entry_rva =
                        static_cast<std::uint32_t>(header[opt + 16]) |
                        (static_cast<std::uint32_t>(header[opt + 17]) << 8) |
                        (static_cast<std::uint32_t>(header[opt + 18]) << 16) |
                        (static_cast<std::uint32_t>(header[opt + 19]) << 24);
                    if (entry_rva != 0) {
                        mod.entry_point = mod.base_address + entry_rva;
                    }
                }
            }
        }
    }

    if (mod.format == Format::Unknown && !mod.path.empty()) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(mod.path, ec) && !ec) {
            std::ifstream in(mod.path, std::ios::binary);
            std::array<std::uint8_t, 4> magic{};
            if (in.read(reinterpret_cast<char*>(magic.data()), 4)) {
                mod.format = detect_format(magic);
            }
        }
    }
}

}  // namespace

ProcessId current_process_id() noexcept {
#ifdef __linux__
    return static_cast<ProcessId>(::getpid());
#elif defined(_WIN32)
    return static_cast<ProcessId>(::GetCurrentProcessId());
#else
    return 0;
#endif
}

std::string strip_deleted_proc_suffix(std::string_view pathname) {
    constexpr std::string_view kDeleted = " (deleted)";
    if (pathname.ends_with(kDeleted)) {
        pathname.remove_suffix(kDeleted.size());
    }
    return std::string(pathname);
}

namespace {

[[nodiscard]] constexpr bool is_cmd_whitespace(char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

[[nodiscard]] bool has_windows_drive_prefix(std::string_view s) noexcept {
    return s.size() >= 3 && std::isalpha(static_cast<unsigned char>(s[0])) != 0 && s[1] == ':' &&
           (s[2] == '\\' || s[2] == '/');
}

[[nodiscard]] bool is_explicit_absolute_path(std::string_view s, bool windows_rules) {
    if (s.empty()) {
        return false;
    }
    if (s.front() == '/') {
        return true;
    }
    if (windows_rules) {
        if (has_windows_drive_prefix(s) || s.starts_with("\\\\") || s.front() == '\\') {
            return true;
        }
    }
    return std::filesystem::path(s).is_absolute();
}

[[nodiscard]] bool contains_path_separator(std::string_view s, bool windows_rules) noexcept {
    if (s.find('/') != std::string_view::npos) {
        return true;
    }
    if (windows_rules && s.find('\\') != std::string_view::npos) {
        return true;
    }
    return false;
}

[[nodiscard]] bool uses_windows_style_separators(std::string_view s) noexcept {
    return has_windows_drive_prefix(s) || s.starts_with("\\\\") ||
           (s.find('\\') != std::string_view::npos && !s.starts_with('/'));
}

[[nodiscard]] std::string normalize_windows_path_string(std::string_view raw) {
    std::string prefix;
    std::size_t idx = 0;
    bool rooted = false;

    if (raw.size() >= 2 &&
        ((raw[0] == '\\' && raw[1] == '\\') || (raw[0] == '/' && raw[1] == '/'))) {
        prefix = "\\\\";
        idx = 2;
        rooted = true;
        // Preserve \\server\share UNC root components so ".." cannot climb past share root.
        int unc_parts = 0;
        while (idx < raw.size() && unc_parts < 2) {
            while (idx < raw.size() && (raw[idx] == '\\' || raw[idx] == '/')) {
                ++idx;
            }
            const std::size_t start = idx;
            while (idx < raw.size() && raw[idx] != '\\' && raw[idx] != '/') {
                ++idx;
            }
            if (idx > start) {
                if (unc_parts > 0) {
                    prefix.push_back('\\');
                }
                prefix.append(raw.substr(start, idx - start));
                ++unc_parts;
            }
        }
        prefix.push_back('\\');
    } else if (has_windows_drive_prefix(raw)) {
        prefix.push_back(raw[0]);
        prefix.push_back(':');
        prefix.push_back('\\');
        idx = 3;
        rooted = true;
    } else if (!raw.empty() && (raw[0] == '\\' || raw[0] == '/')) {
        prefix = "\\";
        idx = 1;
        rooted = true;
    }

    std::vector<std::string_view> stack;
    while (idx < raw.size()) {
        while (idx < raw.size() && (raw[idx] == '\\' || raw[idx] == '/')) {
            ++idx;
        }
        const std::size_t start = idx;
        while (idx < raw.size() && raw[idx] != '\\' && raw[idx] != '/') {
            ++idx;
        }
        if (idx == start) {
            break;
        }
        const std::string_view part = raw.substr(start, idx - start);
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            if (!stack.empty() && stack.back() != "..") {
                stack.pop_back();
            } else if (!rooted) {
                stack.push_back(part);
            }
            continue;
        }
        stack.push_back(part);
    }

    std::string out = prefix;
    for (std::size_t i = 0; i < stack.size(); ++i) {
        if (i > 0) {
            out.push_back('\\');
        }
        out.append(stack[i]);
    }
    if (out.empty()) {
        return ".";
    }
    return out;
}

[[nodiscard]] std::filesystem::path normalize_candidate_path(std::string_view raw,
                                                             bool windows_rules) {
    if (windows_rules && uses_windows_style_separators(raw)) {
        return std::filesystem::path(normalize_windows_path_string(raw));
    }
    return std::filesystem::path(raw).lexically_normal();
}

[[nodiscard]] std::filesystem::path join_and_normalize_candidate(
    const std::filesystem::path& base,
    std::string_view rel,
    bool windows_rules) {
    const std::string base_str = base.string();
    if (windows_rules && (uses_windows_style_separators(base_str) ||
                          uses_windows_style_separators(rel))) {
        std::string combined = base_str;
        if (!combined.empty() && combined.back() != '\\' && combined.back() != '/') {
            combined.push_back('\\');
        }
        combined.append(rel);
        return std::filesystem::path(normalize_windows_path_string(combined));
    }
    return (base / std::filesystem::path(rel)).lexically_normal();
}

[[nodiscard]] bool has_windows_exec_extension(std::string_view path_str) noexcept {
    const std::size_t sep = path_str.find_last_of("/\\");
    const std::string_view fname =
        (sep == std::string_view::npos) ? path_str : path_str.substr(sep + 1);
    const std::size_t dot = fname.rfind('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    const std::string_view ext = fname.substr(dot);
    return iequals_ascii(ext, ".exe") || iequals_ascii(ext, ".com") ||
           iequals_ascii(ext, ".bat") || iequals_ascii(ext, ".cmd");
}

}  // namespace

std::vector<std::string> split_command_line_args(std::string_view command_line,
                                                 bool windows_rules) {
    std::vector<std::string> args;
    if (command_line.empty()) {
        return args;
    }

    if (command_line.find('\0') != std::string_view::npos) {
        std::string_view trimmed = command_line;
        while (!trimmed.empty() && trimmed.back() == '\0') {
            trimmed.remove_suffix(1);
        }
        if (trimmed.empty()) {
            return args;
        }
        if (trimmed.find('\0') != std::string_view::npos) {
            std::size_t pos = 0;
            while (pos <= trimmed.size()) {
                const std::size_t nul = trimmed.find('\0', pos);
                if (nul == std::string_view::npos) {
                    args.emplace_back(trimmed.substr(pos));
                    break;
                }
                args.emplace_back(trimmed.substr(pos, nul - pos));
                pos = nul + 1;
            }
            while (!args.empty() && args.back().empty()) {
                args.pop_back();
            }
            return args;
        }
        // Only 1 NUL-free string exists (e.g., setproctitle or single C-string buffer);
        // fall through and parse it with quoting rules.
        command_line = trimmed;
    }

    if (windows_rules) {
        std::size_t i = 0;
        while (i < command_line.size()) {
            while (i < command_line.size() && is_cmd_whitespace(command_line[i])) {
                ++i;
            }
            if (i >= command_line.size()) {
                break;
            }

            std::string current;
            bool in_quotes = false;
            bool has_token = false;

            while (i < command_line.size()) {
                if (!in_quotes && is_cmd_whitespace(command_line[i])) {
                    break;
                }
                if (command_line[i] == '\\') {
                    std::size_t backslashes = 0;
                    while (i < command_line.size() && command_line[i] == '\\') {
                        ++backslashes;
                        ++i;
                    }
                    if (i < command_line.size() && command_line[i] == '"') {
                        current.append(backslashes / 2u, '\\');
                        has_token = true;
                        if ((backslashes % 2u) == 0) {
                            if (in_quotes && (i + 1) < command_line.size() &&
                                command_line[i + 1] == '"') {
                                current.push_back('"');
                                i += 2;
                            } else {
                                in_quotes = !in_quotes;
                                ++i;
                            }
                        } else {
                            current.push_back('"');
                            ++i;
                        }
                    } else {
                        current.append(backslashes, '\\');
                        has_token = true;
                    }
                } else if (command_line[i] == '"') {
                    has_token = true;
                    if (in_quotes && (i + 1) < command_line.size() && command_line[i + 1] == '"') {
                        current.push_back('"');
                        i += 2;
                    } else {
                        in_quotes = !in_quotes;
                        ++i;
                    }
                } else {
                    current.push_back(command_line[i]);
                    has_token = true;
                    ++i;
                }
            }

            if (has_token) {
                args.push_back(std::move(current));
            }
        }
        return args;
    }

    // POSIX quoting/escaping rules.
    std::size_t i = 0;
    while (i < command_line.size()) {
        while (i < command_line.size() && is_cmd_whitespace(command_line[i])) {
            ++i;
        }
        if (i >= command_line.size()) {
            break;
        }

        std::string current;
        bool in_single = false;
        bool in_double = false;
        bool has_token = false;

        while (i < command_line.size()) {
            const char ch = command_line[i];
            if (in_single) {
                if (ch == '\'') {
                    in_single = false;
                } else {
                    current.push_back(ch);
                }
                ++i;
                continue;
            }
            if (in_double) {
                if (ch == '"') {
                    in_double = false;
                    ++i;
                } else if (ch == '\\' && (i + 1) < command_line.size()) {
                    const char next = command_line[i + 1];
                    if (next == '"' || next == '\\' || next == '$' || next == '`') {
                        current.push_back(next);
                        i += 2;
                    } else {
                        current.push_back(ch);
                        ++i;
                    }
                } else {
                    current.push_back(ch);
                    ++i;
                }
                continue;
            }

            if (is_cmd_whitespace(ch)) {
                break;
            }
            if (ch == '\'') {
                in_single = true;
                has_token = true;
                ++i;
            } else if (ch == '"') {
                in_double = true;
                has_token = true;
                ++i;
            } else if (ch == '\\') {
                has_token = true;
                if ((i + 1) < command_line.size()) {
                    current.push_back(command_line[i + 1]);
                    i += 2;
                } else {
                    ++i;
                }
            } else {
                current.push_back(ch);
                has_token = true;
                ++i;
            }
        }

        if (has_token) {
            args.push_back(std::move(current));
        }
    }
    return args;
}

std::optional<std::filesystem::path> resolve_executable_from_command_line(
    std::string_view command_line,
    const std::filesystem::path& working_directory,
    std::string_view env_path,
    bool windows_rules,
    std::function<bool(const std::filesystem::path&)> file_exists_fn) {
    if (command_line.empty()) {
        return std::nullopt;
    }

    const bool using_default_exists = !static_cast<bool>(file_exists_fn);
    if (!file_exists_fn) {
        file_exists_fn = [](const std::filesystem::path& p) -> bool {
            std::error_code ec;
            return !p.empty() && std::filesystem::is_regular_file(p, ec) && !ec;
        };
    }

    std::string sys_path_storage;
    std::string_view effective_env_path = env_path;
    if (effective_env_path.empty() && using_default_exists) {
#ifdef _WIN32
        char* raw_env = nullptr;
        std::size_t raw_len = 0;
        if (_dupenv_s(&raw_env, &raw_len, "PATH") == 0 && raw_env != nullptr) {
            sys_path_storage.assign(raw_env);
            std::free(raw_env);
            effective_env_path = sys_path_storage;
        }
#else
        if (const char* raw_env = std::getenv("PATH"); raw_env != nullptr) {
            sys_path_storage = raw_env;
            effective_env_path = sys_path_storage;
        }
#endif
    }

    const auto probe_path_with_extensions =
        [&](const std::filesystem::path& candidate) -> std::optional<std::filesystem::path> {
        if (candidate.empty()) {
            return std::nullopt;
        }
        if (file_exists_fn(candidate)) {
            return candidate;
        }
        const std::string cand_str = candidate.string();
        if (windows_rules && !has_windows_exec_extension(cand_str)) {
            const std::filesystem::path with_exe(cand_str + ".exe");
            if (file_exists_fn(with_exe)) {
                return with_exe;
            }
            const std::filesystem::path with_com(cand_str + ".com");
            if (file_exists_fn(with_com)) {
                return with_com;
            }
        }
        return std::nullopt;
    };

    const auto resolve_argv0 =
        [&](std::string_view raw_tok) -> std::optional<std::filesystem::path> {
        std::string_view tok = trim_ascii(raw_tok);
        if (tok.size() >= 2 &&
            ((tok.front() == '"' && tok.back() == '"') ||
             (tok.front() == '\'' && tok.back() == '\''))) {
            tok = tok.substr(1, tok.size() - 2);
        }
        if (tok.empty()) {
            return std::nullopt;
        }

        // 1. Direct path if argv[0] is absolute (or drive letter / UNC / root).
        if (is_explicit_absolute_path(tok, windows_rules)) {
            if (auto direct = probe_path_with_extensions(std::filesystem::path(tok))) {
                return direct;
            }
            const std::filesystem::path norm = normalize_candidate_path(tok, windows_rules);
            if (norm.string() != tok) {
                if (auto norm_hit = probe_path_with_extensions(norm)) {
                    return norm_hit;
                }
            }
            return std::nullopt;
        }

        // 2. Relative path containing '/' or '\' resolved against working_directory.
        if (contains_path_separator(tok, windows_rules)) {
            if (!working_directory.empty()) {
                const std::filesystem::path joined =
                    join_and_normalize_candidate(working_directory, tok, windows_rules);
                if (auto rel_hit = probe_path_with_extensions(joined)) {
                    return rel_hit;
                }
            } else {
                const std::filesystem::path norm = normalize_candidate_path(tok, windows_rules);
                if (auto rel_hit = probe_path_with_extensions(norm)) {
                    return rel_hit;
                }
            }
            return std::nullopt;
        }

        // 3. Bare command name searched across env_path.
        if (!effective_env_path.empty()) {
            const char delim = windows_rules ? ';' : ':';
            std::size_t start = 0;
            while (start <= effective_env_path.size()) {
                const std::size_t next = effective_env_path.find(delim, start);
                std::string_view dir_entry =
                    (next == std::string_view::npos)
                        ? effective_env_path.substr(start)
                        : effective_env_path.substr(start, next - start);
                dir_entry = trim_ascii(dir_entry);
                if (windows_rules && dir_entry.size() >= 2 &&
                    dir_entry.front() == '"' && dir_entry.back() == '"') {
                    dir_entry = dir_entry.substr(1, dir_entry.size() - 2);
                }
                if (!dir_entry.empty()) {
                    const std::filesystem::path joined = join_and_normalize_candidate(
                        std::filesystem::path(dir_entry), tok, windows_rules);
                    if (auto path_hit = probe_path_with_extensions(joined)) {
                        return path_hit;
                    }
                }
                if (next == std::string_view::npos) {
                    break;
                }
                start = next + 1;
            }
        }

        return std::nullopt;
    };

    const std::vector<std::string> tokens = split_command_line_args(command_line, windows_rules);
    if (tokens.empty()) {
        return std::nullopt;
    }

    if (auto resolved = resolve_argv0(tokens.front())) {
        return resolved;
    }

    // Handle unquoted paths containing spaces (e.g. "C:\Program Files\App\foo.exe --arg"
    // or single NUL-terminated "/opt/My App/daemon\0").
    std::string_view raw_trimmed = command_line;
    while (!raw_trimmed.empty() && raw_trimmed.back() == '\0') {
        raw_trimmed.remove_suffix(1);
    }
    raw_trimmed = trim_ascii(raw_trimmed);
    if (!raw_trimmed.empty() && raw_trimmed.find('\0') == std::string_view::npos &&
        raw_trimmed.front() != '"' && raw_trimmed.front() != '\'') {
        std::vector<std::string_view> space_prefixes;
        for (std::size_t i = 0; i < raw_trimmed.size(); ++i) {
            if (is_cmd_whitespace(raw_trimmed[i])) {
                const std::string_view prefix = trim_ascii(raw_trimmed.substr(0, i));
                if (!prefix.empty() && prefix != tokens.front()) {
                    space_prefixes.push_back(prefix);
                }
                while (i + 1 < raw_trimmed.size() && is_cmd_whitespace(raw_trimmed[i + 1])) {
                    ++i;
                }
            }
        }
        if (raw_trimmed != tokens.front()) {
            space_prefixes.push_back(raw_trimmed);
        }

        if (windows_rules) {
            // Prioritize prefixes explicitly ending in .exe/.com first.
            for (const std::string_view prefix : space_prefixes) {
                if (has_windows_exec_extension(prefix)) {
                    if (auto hit = resolve_argv0(prefix)) {
                        return hit;
                    }
                }
            }
        }
        for (const std::string_view prefix : space_prefixes) {
            if (is_explicit_absolute_path(prefix, windows_rules) ||
                contains_path_separator(prefix, windows_rules)) {
                if (auto hit = resolve_argv0(prefix)) {
                    return hit;
                }
            }
        }
    }

    // Fallback for Unix login shells where argv[0] has a leading '-' (e.g. "-bash", "-/bin/zsh").
    if (!windows_rules && tokens.front().size() > 1 && tokens.front().front() == '-') {
        if (auto login_hit = resolve_argv0( std::string_view(tokens.front()).substr(1))) {
            return login_hit;
        }
    }

    return std::nullopt;
}

Result<std::vector<MemoryRegion>> parse_proc_maps(std::string_view maps_text,
                                                  std::string_view main_exe_path) {
    const std::string clean_main = strip_deleted_proc_suffix(trim_ascii(main_exe_path));
    std::vector<MemoryRegion> regions;

    std::size_t pos = 0;
    while (pos < maps_text.size()) {
        const std::size_t nl = maps_text.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? maps_text.substr(pos) : maps_text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? maps_text.size() : (nl + 1);

        line = trim_ascii(line);
        if (line.empty()) {
            continue;
        }

        std::string_view cursor = line;
        const std::string_view range_tok = next_whitespace_token(cursor);
        const std::string_view perms_tok = next_whitespace_token(cursor);
        const std::string_view offset_tok = next_whitespace_token(cursor);
        const std::string_view dev_tok = next_whitespace_token(cursor);
        const std::string_view inode_tok = next_whitespace_token(cursor);
        (void)dev_tok;
        (void)inode_tok;

        const std::size_t dash = range_tok.find('-');
        if (dash == std::string_view::npos || perms_tok.size() < 4 || offset_tok.empty()) {
            return make_error("malformed /proc/maps entry");
        }

        const auto start = parse_hex_u64(range_tok.substr(0, dash));
        const auto end = parse_hex_u64(range_tok.substr(dash + 1));
        const auto file_off = parse_hex_u64(offset_tok);
        if (!start || !end || !file_off || *end < *start) {
            return make_error("invalid address or offset in /proc/maps entry");
        }

        const std::string_view path_view = trim_ascii(cursor);

        MemoryRegion region;
        region.start_address = *start;
        region.end_address = *end;
        region.protection.readable = perms_tok[0] == 'r';
        region.protection.writable = perms_tok[1] == 'w';
        region.protection.executable = perms_tok[2] == 'x';
        region.protection.shared = perms_tok[3] == 's';
        region.file_offset = *file_off;
        region.pathname = std::string(path_view);
        region.kind = classify_initial_region_kind(region.pathname, clean_main);
        annotate_special_pathname_usage(region);

        regions.push_back(std::move(region));
    }

    return regions;
}

Result<std::vector<MemoryRegion>> parse_proc_smaps(std::string_view smaps_text,
                                                   std::string_view main_exe_path) {
    const std::string clean_main = strip_deleted_proc_suffix(trim_ascii(main_exe_path));
    std::vector<MemoryRegion> regions;

    std::size_t pos = 0;
    while (pos < smaps_text.size()) {
        const std::size_t nl = smaps_text.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? smaps_text.substr(pos) : smaps_text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? smaps_text.size() : (nl + 1);

        line = trim_ascii(line);
        if (line.empty()) {
            continue;
        }

        std::string_view probe = line;
        const std::string_view first_tok = next_whitespace_token(probe);

        // Metric / flag detail line belonging to the most recent VMA header (e.g. "Rss: 16 kB").
        if (first_tok.ends_with(':')) {
            if (regions.empty()) {
                continue;
            }
            MemoryRegion& cur = regions.back();
            const std::string_view key = first_tok.substr(0, first_tok.size() - 1);
            if (key == "VmFlags") {
                cur.usage.vm_flags = std::string(trim_ascii(probe));
                continue;
            }
            const std::string_view val_tok = next_whitespace_token(probe);
            const auto kb = parse_dec_u64(val_tok);
            if (!kb) {
                continue;
            }
            const std::uint64_t bytes = *kb * 1024ull;
            if (key == "Rss") {
                cur.usage.rss_bytes = bytes;
                if (bytes > 0 && cur.usage.is_reserved_only) {
                    cur.usage.is_reserved_only = false;
                    cur.usage.committed_bytes = cur.size();
                }
            } else if (key == "Pss") {
                cur.usage.pss_bytes = bytes;
            } else if (key == "Shared_Clean") {
                cur.usage.shared_clean_bytes = bytes;
            } else if (key == "Shared_Dirty") {
                cur.usage.shared_dirty_bytes = bytes;
            } else if (key == "Private_Clean") {
                cur.usage.private_clean_bytes = bytes;
            } else if (key == "Private_Dirty") {
                cur.usage.private_dirty_bytes = bytes;
            } else if (key == "Swap") {
                cur.usage.swap_bytes = bytes;
                if (bytes > 0 && cur.usage.is_reserved_only) {
                    cur.usage.is_reserved_only = false;
                    cur.usage.committed_bytes = cur.size();
                }
            } else if (key == "Locked") {
                cur.usage.locked_bytes = bytes;
            }
            continue;
        }

        const std::string_view perms_tok = next_whitespace_token(probe);
        const std::string_view offset_tok = next_whitespace_token(probe);
        const std::string_view dev_tok = next_whitespace_token(probe);
        const std::string_view inode_tok = next_whitespace_token(probe);
        (void)dev_tok;
        (void)inode_tok;

        const std::size_t dash = first_tok.find('-');
        if (dash == std::string_view::npos || perms_tok.size() < 4 || offset_tok.empty()) {
            return make_error("malformed /proc/smaps VMA header entry");
        }

        const auto start = parse_hex_u64(first_tok.substr(0, dash));
        const auto end = parse_hex_u64(first_tok.substr(dash + 1));
        const auto file_off = parse_hex_u64(offset_tok);
        if (!start || !end || !file_off || *end < *start) {
            return make_error("invalid address or offset in /proc/smaps entry");
        }

        MemoryRegion region;
        region.start_address = *start;
        region.end_address = *end;
        region.protection.readable = perms_tok[0] == 'r';
        region.protection.writable = perms_tok[1] == 'w';
        region.protection.executable = perms_tok[2] == 'x';
        region.protection.shared = perms_tok[3] == 's';
        region.file_offset = *file_off;
        region.pathname = std::string(trim_ascii(probe));
        region.kind = classify_initial_region_kind(region.pathname, clean_main);
        annotate_special_pathname_usage(region);

        regions.push_back(std::move(region));
    }

    return regions;
}

void attribute_thread_stacks(std::vector<MemoryRegion>& regions,
                             std::span<const ThreadInfo> threads,
                             std::optional<ThreadId> main_tid) {
    if (main_tid.has_value()) {
        for (MemoryRegion& reg : regions) {
            if (reg.pathname == "[stack]" && !reg.usage.owner_tid.has_value()) {
                reg.kind = MemoryRegionKind::Stack;
                reg.usage.owner_tid = *main_tid;
            }
        }
    }

    for (const ThreadInfo& t : threads) {
        if (t.tid == 0) {
            continue;
        }
        bool already_owned = false;
        for (const MemoryRegion& reg : regions) {
            if (reg.usage.owner_tid == t.tid && !reg.usage.is_reserved_only) {
                already_owned = true;
                break;
            }
        }
        if (already_owned || !t.stack_pointer.has_value() || *t.stack_pointer == 0) {
            continue;
        }
        const std::uint64_t sp = *t.stack_pointer;
        for (std::size_t i = 0; i < regions.size(); ++i) {
            MemoryRegion& reg = regions[i];
            if (!reg.contains(sp)) {
                continue;
            }
            if (reg.kind == MemoryRegionKind::Anonymous || reg.kind == MemoryRegionKind::Stack) {
                reg.kind = MemoryRegionKind::Stack;
                reg.usage.owner_tid = t.tid;
                // Attribute an immediately preceding anonymous guard/reserved page if adjacent.
                if (i > 0 && regions[i - 1].end_address == reg.start_address &&
                    regions[i - 1].usage.is_reserved_only &&
                    !regions[i - 1].usage.owner_tid.has_value()) {
                    regions[i - 1].usage.owner_tid = t.tid;
                }
            }
            break;
        }
    }
}

ProcessMemorySummary summarize_process_memory(std::span<const MemoryRegion> regions,
                                              std::string_view smaps_rollup_text) {
    ProcessMemorySummary sum{};

    std::uint64_t rss_acc = 0;
    std::uint64_t pss_acc = 0;
    std::uint64_t priv_clean_acc = 0;
    std::uint64_t priv_dirty_acc = 0;
    std::uint64_t sh_clean_acc = 0;
    std::uint64_t sh_dirty_acc = 0;
    std::uint64_t swap_acc = 0;
    std::uint64_t locked_acc = 0;

    bool has_rss = false;
    bool has_pss = false;
    bool has_priv_clean = false;
    bool has_priv_dirty = false;
    bool has_sh_clean = false;
    bool has_sh_dirty = false;
    bool has_swap = false;
    bool has_locked = false;

    for (const MemoryRegion& reg : regions) {
        const std::uint64_t sz = reg.size();
        sum.total_virtual_bytes += sz;

        if (reg.usage.is_reserved_only) {
            sum.reserved_only_bytes += sz;
            sum.reserved_bytes += sz;
        } else {
            const std::uint64_t comm = reg.usage.committed_bytes.value_or(sz);
            sum.committed_bytes += comm;
            if (sz > comm) {
                sum.reserved_only_bytes += (sz - comm);
                sum.reserved_bytes += (sz - comm);
            }

            switch (reg.kind) {
                case MemoryRegionKind::Image:
                    sum.image_bytes += comm;
                    break;
                case MemoryRegionKind::Heap:
                    sum.heap_bytes += comm;
                    break;
                case MemoryRegionKind::Stack:
                    sum.stack_bytes += comm;
                    break;
                case MemoryRegionKind::MappedFile:
                    sum.mapped_file_bytes += comm;
                    break;
                case MemoryRegionKind::Vdso:
                    sum.vdso_bytes += comm;
                    break;
                case MemoryRegionKind::Anonymous:
                case MemoryRegionKind::Unknown:
                    sum.anonymous_bytes += comm;
                    break;
            }
        }

        if (reg.protection.guarded ||
            (!reg.protection.readable && !reg.protection.writable && !reg.protection.executable)) {
            sum.noaccess_or_guard_bytes += sz;
        } else if (reg.protection.readable && reg.protection.writable && reg.protection.executable) {
            sum.rwx_bytes += sz;
            ++sum.rwx_region_count;
        } else if (reg.protection.executable) {
            sum.rx_bytes += sz;
            if (reg.protection.writable) {
                // w+x without r is equally dangerous W^X violation.
                ++sum.rwx_region_count;
            }
        } else if (reg.protection.writable) {
            sum.rw_bytes += sz;
        } else {
            sum.readonly_bytes += sz;
        }

        if (reg.usage.rss_bytes.has_value()) {
            rss_acc += *reg.usage.rss_bytes;
            has_rss = true;
        }
        if (reg.usage.pss_bytes.has_value()) {
            pss_acc += *reg.usage.pss_bytes;
            has_pss = true;
        }
        if (reg.usage.private_clean_bytes.has_value()) {
            priv_clean_acc += *reg.usage.private_clean_bytes;
            has_priv_clean = true;
        }
        if (reg.usage.private_dirty_bytes.has_value()) {
            priv_dirty_acc += *reg.usage.private_dirty_bytes;
            has_priv_dirty = true;
        }
        if (reg.usage.shared_clean_bytes.has_value()) {
            sh_clean_acc += *reg.usage.shared_clean_bytes;
            has_sh_clean = true;
        }
        if (reg.usage.shared_dirty_bytes.has_value()) {
            sh_dirty_acc += *reg.usage.shared_dirty_bytes;
            has_sh_dirty = true;
        }
        if (reg.usage.swap_bytes.has_value()) {
            swap_acc += *reg.usage.swap_bytes;
            has_swap = true;
        }
        if (reg.usage.locked_bytes.has_value()) {
            locked_acc += *reg.usage.locked_bytes;
            has_locked = true;
        }
    }

    if (has_rss) {
        sum.rss_bytes = rss_acc;
    }
    if (has_pss) {
        sum.pss_bytes = pss_acc;
    }
    if (has_priv_clean) {
        sum.private_clean_bytes = priv_clean_acc;
    }
    if (has_priv_dirty) {
        sum.private_dirty_bytes = priv_dirty_acc;
    }
    if (has_sh_clean) {
        sum.shared_clean_bytes = sh_clean_acc;
    }
    if (has_sh_dirty) {
        sum.shared_dirty_bytes = sh_dirty_acc;
    }
    if (has_swap) {
        sum.swap_bytes = swap_acc;
    }
    if (has_locked) {
        sum.locked_bytes = locked_acc;
    }

    if (!smaps_rollup_text.empty()) {
        std::size_t pos = 0;
        while (pos < smaps_rollup_text.size()) {
            const std::size_t nl = smaps_rollup_text.find('\n', pos);
            std::string_view line = (nl == std::string_view::npos)
                                        ? smaps_rollup_text.substr(pos)
                                        : smaps_rollup_text.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? smaps_rollup_text.size() : (nl + 1);
            line = trim_ascii(line);
            std::string_view cur = line;
            const std::string_view tok = next_whitespace_token(cur);
            if (!tok.ends_with(':')) {
                continue;
            }
            const std::string_view key = tok.substr(0, tok.size() - 1);
            const auto kb = parse_dec_u64(next_whitespace_token(cur));
            if (!kb) {
                continue;
            }
            const std::uint64_t bytes = *kb * 1024ull;
            if (key == "Rss" && !sum.rss_bytes.has_value()) {
                sum.rss_bytes = bytes;
            } else if (key == "Pss" && !sum.pss_bytes.has_value()) {
                sum.pss_bytes = bytes;
            } else if (key == "Private_Clean" && !sum.private_clean_bytes.has_value()) {
                sum.private_clean_bytes = bytes;
            } else if (key == "Private_Dirty" && !sum.private_dirty_bytes.has_value()) {
                sum.private_dirty_bytes = bytes;
            } else if (key == "Shared_Clean" && !sum.shared_clean_bytes.has_value()) {
                sum.shared_clean_bytes = bytes;
            } else if (key == "Shared_Dirty" && !sum.shared_dirty_bytes.has_value()) {
                sum.shared_dirty_bytes = bytes;
            } else if (key == "Swap" && !sum.swap_bytes.has_value()) {
                sum.swap_bytes = bytes;
            } else if (key == "Locked" && !sum.locked_bytes.has_value()) {
                sum.locked_bytes = bytes;
            }
        }
    }

    return sum;
}

std::vector<AddressSpaceCluster> build_address_space_clusters(
    std::span<const MemoryRegion> regions,
    std::uint64_t gap_collapse_threshold) {
    std::vector<AddressSpaceCluster> clusters;
    if (regions.empty()) {
        return clusters;
    }

    std::vector<std::size_t> order(regions.size());
    for (std::size_t i = 0; i < regions.size(); ++i) {
        order[i] = i;
    }
    std::ranges::sort(order, [&](std::size_t a, std::size_t b) {
        if (regions[a].start_address != regions[b].start_address) {
            return regions[a].start_address < regions[b].start_address;
        }
        return regions[a].end_address < regions[b].end_address;
    });

    const std::size_t first_idx = order.front();
    AddressSpaceCluster current;
    current.start_address = regions[first_idx].start_address;
    current.end_address = regions[first_idx].end_address;
    current.preceding_gap_bytes = regions[first_idx].start_address;
    current.region_indices.push_back(first_idx);

    for (std::size_t k = 1; k < order.size(); ++k) {
        const std::size_t idx = order[k];
        const MemoryRegion& reg = regions[idx];
        const std::uint64_t gap =
            reg.start_address > current.end_address ? (reg.start_address - current.end_address) : 0;
        if (gap >= gap_collapse_threshold) {
            clusters.push_back(std::move(current));
            current = AddressSpaceCluster{};
            current.start_address = reg.start_address;
            current.end_address = reg.end_address;
            current.preceding_gap_bytes = gap;
            current.region_indices.push_back(idx);
        } else {
            current.end_address = std::max(current.end_address, reg.end_address);
            current.region_indices.push_back(idx);
        }
    }

    clusters.push_back(std::move(current));
    return clusters;
}

ForgivingValue<ProcessMemorySummary> IProcessSession::memory_summary(
    std::span<const MemoryRegion> regions) {
    std::vector<MemoryRegion> owned;
    if (regions.empty()) {
        auto fetched = memory_regions();
        if (!fetched) {
            return {std::nullopt, SubsystemStatus::unavailable("vmmap", fetched.error().message)};
        }
        owned = std::move(*fetched);
        regions = owned;
    }
    ProcessMemorySummary summary = summarize_process_memory(regions);
    const SubsystemStatus st = summary.rss_bytes.has_value()
                                   ? SubsystemStatus::available("vmmap", "physical RSS telemetry")
                                   : SubsystemStatus::partial(
                                         "vmmap",
                                         "physical RSS/PSS unavailable; showing virtual map only");
    return {std::move(summary), st};
}

std::vector<ModuleInfo> derive_modules_from_regions(std::vector<MemoryRegion>& regions,
                                                    std::string_view main_exe_path,
                                                    IProcessSession* probe_session) {
    const std::string clean_main = strip_deleted_proc_suffix(trim_ascii(main_exe_path));

    struct Group {
        std::string clean_path;
        std::vector<std::size_t> region_indices;
        bool has_exec{false};
        bool is_vdso{false};
    };

    std::vector<Group> groups;
    std::unordered_map<std::string, std::size_t> group_by_path;

    for (std::size_t i = 0; i < regions.size(); ++i) {
        const MemoryRegion& reg = regions[i];
        if (reg.pathname.empty()) {
            continue;
        }
        if (reg.pathname == "[vdso]") {
            Group g;
            g.clean_path = "[vdso]";
            g.region_indices.push_back(i);
            g.has_exec = reg.protection.executable;
            g.is_vdso = true;
            groups.push_back(std::move(g));
            continue;
        }
        if (reg.pathname.front() == '[' || reg.pathname.starts_with("/dev/")) {
            continue;
        }

        const std::string clean = strip_deleted_proc_suffix(reg.pathname);
        auto [it, inserted] = group_by_path.emplace(clean, groups.size());
        if (inserted) {
            Group g;
            g.clean_path = clean;
            groups.push_back(std::move(g));
        }
        Group& grp = groups[it->second];
        grp.region_indices.push_back(i);
        if (reg.protection.executable) {
            grp.has_exec = true;
        }
    }

    std::vector<ModuleInfo> modules;
    for (const Group& grp : groups) {
        if (grp.region_indices.empty()) {
            continue;
        }

        if (grp.is_vdso) {
            const MemoryRegion& vdso_reg = regions[grp.region_indices.front()];
            bool magic_ok = false;
            if (probe_session != nullptr && vdso_reg.protection.readable) {
                std::array<std::uint8_t, 4> magic{};
                auto res = probe_session->read_memory(vdso_reg.start_address, magic);
                magic_ok = res && *res == 4 && detect_format(magic) == Format::ELF;
            }
            if (!magic_ok && !grp.has_exec) {
                continue;
            }
            ModuleInfo mod;
            mod.name = "[vdso]";
            mod.base_address = vdso_reg.start_address;
            mod.size = vdso_reg.size();
            mod.format = Format::ELF;
            probe_module_format_and_entry(mod, probe_session);
            regions[grp.region_indices.front()].module_name = mod.name;
            modules.push_back(std::move(mod));
            continue;
        }

        const std::string short_name = basename_from_path(grp.clean_path);
        const bool is_main = !clean_main.empty() && grp.clean_path == clean_main;
        bool is_module = is_main || grp.has_exec || looks_like_binary_module_filename(short_name);

        const std::uint64_t first_start = regions[grp.region_indices.front()].start_address;
        if (!is_module && probe_session != nullptr &&
            regions[grp.region_indices.front()].protection.readable) {
            std::array<std::uint8_t, 4> magic{};
            auto res = probe_session->read_memory(first_start, magic);
            if (res && *res == 4 && detect_format(magic) != Format::Unknown) {
                is_module = true;
            }
        }

        if (!is_module) {
            continue;
        }

        std::uint64_t min_addr = first_start;
        std::uint64_t max_addr = regions[grp.region_indices.front()].end_address;
        for (const std::size_t idx : grp.region_indices) {
            min_addr = std::min(min_addr, regions[idx].start_address);
            max_addr = std::max(max_addr, regions[idx].end_address);
            regions[idx].kind = MemoryRegionKind::Image;
            regions[idx].module_name = short_name;
        }

        // Include immediately adjacent anonymous rw-p zero-fill (.bss) tail if present.
        const std::size_t last_idx = grp.region_indices.back();
        if (last_idx + 1 < regions.size()) {
            MemoryRegion& tail = regions[last_idx + 1];
            if (tail.pathname.empty() && tail.start_address == max_addr &&
                tail.protection.readable && tail.protection.writable && !tail.protection.executable) {
                max_addr = tail.end_address;
                tail.module_name = short_name;
            }
        }

        ModuleInfo mod;
        mod.name = short_name;
        mod.path = std::filesystem::path(grp.clean_path);
        mod.base_address = min_addr;
        mod.size = max_addr >= min_addr ? (max_addr - min_addr) : 0;
        mod.is_main_module = is_main;
        probe_module_format_and_entry(mod, probe_session);
        modules.push_back(std::move(mod));
    }

    if (!modules.empty() &&
        std::ranges::none_of(modules, [](const ModuleInfo& m) { return m.is_main_module; })) {
        // Fallback: mark the first non-vdso executable image (lowest non-library or first image)
        // when /proc/<pid>/exe was unreadable.
        for (ModuleInfo& mod : modules) {
            if (mod.name != "[vdso]" && !looks_like_binary_module_filename(mod.name)) {
                mod.is_main_module = true;
                break;
            }
        }
    }

    std::ranges::sort(modules, [](const ModuleInfo& lhs, const ModuleInfo& rhs) {
        if (lhs.is_main_module != rhs.is_main_module) {
            return lhs.is_main_module;
        }
        return lhs.base_address < rhs.base_address;
    });

    return modules;
}

MemorySample read_memory_tolerant(IProcessSession& session,
                                  std::span<const MemoryRegion> regions,
                                  std::uint64_t address,
                                  std::size_t size) {
    MemorySample sample;
    sample.bytes.assign(size, 0);
    sample.valid.assign(size, 0);
    if (size == 0) {
        return sample;
    }

    constexpr std::size_t kMaxChunk = 65536;
    constexpr std::uint64_t kPageSize = 4096;

    const auto read_chunk_with_page_fallback = [&](std::size_t rel_offset, std::size_t len) {
        const std::uint64_t chunk_va = address + static_cast<std::uint64_t>(rel_offset);
        auto out_span = std::span<std::uint8_t>(sample.bytes.data() + rel_offset, len);
        auto fast = session.read_memory(chunk_va, out_span);
        if (fast && *fast == len) {
            std::fill_n(sample.valid.data() + rel_offset, len, static_cast<std::uint8_t>(1));
            sample.readable_count += len;
            return;
        }

        std::size_t cursor = 0;
        if (fast && *fast > 0 && *fast < len) {
            std::fill_n(sample.valid.data() + rel_offset, *fast, static_cast<std::uint8_t>(1));
            sample.readable_count += *fast;
            cursor = *fast;
        }

        while (cursor < len) {
            const std::uint64_t page_va = chunk_va + static_cast<std::uint64_t>(cursor);
            const std::uint64_t page_rem = kPageSize - (page_va % kPageSize);
            const std::size_t step = static_cast<std::size_t>(
                std::min<std::uint64_t>(page_rem, static_cast<std::uint64_t>(len - cursor)));
            auto page_span =
                std::span<std::uint8_t>(sample.bytes.data() + rel_offset + cursor, step);
            auto page_res = session.read_memory(page_va, page_span);
            if (page_res && *page_res > 0) {
                const std::size_t got = std::min(*page_res, step);
                std::fill_n(sample.valid.data() + rel_offset + cursor,
                            got,
                            static_cast<std::uint8_t>(1));
                sample.readable_count += got;
                if (got < step) {
                    std::fill_n(sample.bytes.data() + rel_offset + cursor + got,
                                step - got,
                                static_cast<std::uint8_t>(0));
                }
            } else {
                std::fill_n(sample.bytes.data() + rel_offset + cursor,
                            step,
                            static_cast<std::uint8_t>(0));
            }
            cursor += step;
        }
    };

    if (regions.empty()) {
        std::size_t offset = 0;
        while (offset < size) {
            const std::size_t step = std::min(kMaxChunk, size - offset);
            read_chunk_with_page_fallback(offset, step);
            offset += step;
        }
        return sample;
    }

    const std::uint64_t end_address =
        (address > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(size))
            ? std::numeric_limits<std::uint64_t>::max()
            : (address + static_cast<std::uint64_t>(size));

    for (const MemoryRegion& reg : regions) {
        if (reg.end_address <= address || reg.start_address >= end_address) {
            continue;
        }
        if (!reg.protection.readable || reg.protection.guarded) {
            continue;
        }
        const std::uint64_t overlap_begin = std::max(address, reg.start_address);
        const std::uint64_t overlap_end = std::min(end_address, reg.end_address);
        std::size_t rel = static_cast<std::size_t>(overlap_begin - address);
        std::size_t rem = static_cast<std::size_t>(overlap_end - overlap_begin);
        while (rem > 0) {
            const std::size_t step = std::min(kMaxChunk, rem);
            read_chunk_with_page_fallback(rel, step);
            rel += step;
            rem -= step;
        }
    }

    return sample;
}

Result<std::unique_ptr<IBinaryImage>> load_live_module_image(
    IProcessSession& session,
    const ModuleInfo& module,
    std::span<const MemoryRegion> regions) {
    if (module.base_address == 0 && module.size == 0) {
        return make_error("invalid module base address and size");
    }

    // Prefer on-disk backing PE/ELF when readable so unmapped sections (such as ELF
    // .symtab/.strtab) and original import lookup tables are preserved and rebased to
    // the module's live runtime base.
    std::optional<std::vector<std::uint8_t>> disk_bytes = try_read_disk_file(module.path);
    if (!disk_bytes && module.is_main_module) {
        const ProcessInfo& proc_info = session.info();
        if (!proc_info.executable_path.empty() && proc_info.executable_path != module.path) {
            disk_bytes = try_read_disk_file(proc_info.executable_path);
        }
        if (!disk_bytes && !proc_info.command_line.empty()) {
            const bool win_rules =
#ifdef _WIN32
                true;
#else
                (module.format == Format::PE &&
                 uses_windows_style_separators(proc_info.command_line));
#endif
            if (const auto resolved = resolve_executable_from_command_line(
                    proc_info.command_line, proc_info.working_directory, {}, win_rules)) {
                disk_bytes = try_read_disk_file(*resolved);
            }
        }
    }
    if (disk_bytes) {
        auto rebased = parse_rebased_image(*disk_bytes, module.base_address);
        if (rebased) {
            const BackingIdentityMatchResult id_check = verify_live_module_backing_identity(
                **rebased,
                *disk_bytes,
                session,
                module,
                regions);
            // Only use the on-disk backing file when it does not contradict the in-memory
            // module's build identity (.note.gnu.build-id / RSDS GUID+Age / PE TimeDateStamp).
            if (!id_check.has_mismatch()) {
                return rebased;
            }
        }
    }

    constexpr std::uint64_t kMaxSnapshotBytes = 64ull * 1024ull * 1024ull;
    constexpr std::uint64_t kDefaultProbeSize = 64ull * 1024ull;
    const std::size_t snapshot_size = static_cast<std::size_t>(
        std::min<std::uint64_t>(module.size > 0 ? module.size : kDefaultProbeSize, kMaxSnapshotBytes));

    MemorySample sample =
        read_memory_tolerant(session, regions, module.base_address, snapshot_size);
    if (sample.readable_count == 0) {
        return make_error("failed to read mapped module bytes from process memory");
    }

    return parse_mapped_image(sample.bytes, module.base_address);
}

#if !defined(__linux__) && !defined(_WIN32)
namespace {
class UnsupportedProcessBackend final : public IProcessBackend {
public:
    Result<std::vector<ProcessInfo>> list_processes() override {
        return make_error("live process exploration is not supported on this platform");
    }
    Result<std::unique_ptr<IProcessSession>> open_process(ProcessId) override {
        return make_error("live process exploration is not supported on this platform");
    }
};
}  // namespace

std::shared_ptr<IProcessBackend> create_native_process_backend() {
    return std::make_shared<UnsupportedProcessBackend>();
}
#endif

}  // namespace peelf
