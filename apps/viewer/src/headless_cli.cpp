#include "headless_cli.hpp"
#include "graph/call_graph_internal.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/demangle.hpp>
#include <peelf/subprocess.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/sha256.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef PEELF_VERSION_STRING
#define PEELF_VERSION_STRING "1.0.0"
#endif

namespace viewer {
namespace {

constexpr std::size_t kMaxProjectFileBytes = 64u * 1024u * 1024u;
constexpr std::size_t kMaxProjectItems = 100'000u;

[[nodiscard]] std::string lower_ascii(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

void append_json_escaped(std::string& out, std::string_view text) {
    out.push_back('"');
    for (const char raw_ch : text) {
        const auto c = static_cast<unsigned char>(raw_ch);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20u) {
                    out += std::format("\\u{:04x}", static_cast<unsigned int>(c));
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

[[nodiscard]] std::string encode_hex_lower(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string out{};
    out.reserve(bytes.size() * 2u);
    for (const std::uint8_t b : bytes) {
        out.push_back(kDigits[static_cast<std::size_t>(b >> 4u)]);
        out.push_back(kDigits[static_cast<std::size_t>(b & 0x0Fu)]);
    }
    return out;
}

[[nodiscard]] bool decode_hex_bytes(std::string_view text, std::vector<std::uint8_t>& out) {
    if ((text.size() % 2u) != 0u) {
        return false;
    }
    auto nibble = [](char c) noexcept -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return (c - 'a') + 10;
        if (c >= 'A' && c <= 'F') return (c - 'A') + 10;
        return -1;
    };
    out.clear();
    out.reserve(text.size() / 2u);
    for (std::size_t i = 0u; i < text.size(); i += 2u) {
        const int hi = nibble(text[i]);
        const int lo = nibble(text[i + 1u]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((hi * 16) + lo));
    }
    return true;
}

[[nodiscard]] std::uint64_t fnv1a_fingerprint(std::span<const std::uint8_t> bytes) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const std::uint8_t b : bytes) {
        hash ^= b;
        hash *= 1099511628211ULL;
    }
    return hash;
}

[[nodiscard]] bool normalize_sha256_hex(std::string& value) noexcept {
    if (value.empty()) {
        return true;
    }
    if (value.size() != 64u) {
        return false;
    }
    for (char& ch : value) {
        const auto uch = static_cast<unsigned char>(ch);
        if (std::isxdigit(uch) == 0) {
            return false;
        }
        ch = static_cast<char>(std::tolower(uch));
    }
    return true;
}

[[nodiscard]] peelf::Result<std::vector<std::uint8_t>> read_binary_file(
    const std::filesystem::path& path,
    std::optional<std::size_t> max_bytes = std::nullopt,
    std::string_view max_bytes_message = "File exceeds maximum allowed size") {
    if (max_bytes.has_value()) {
        std::error_code fs_ec{};
        if (!std::filesystem::is_regular_file(path, fs_ec) || fs_ec) {
            return peelf::make_error(std::format("Failed to open file '{}'", path.string()));
        }
        const std::uintmax_t disk_size = std::filesystem::file_size(path, fs_ec);
        if (fs_ec) {
            return peelf::make_error(
                std::format("Failed to determine file size of '{}'", path.string()));
        }
        if (disk_size > static_cast<std::uintmax_t>(*max_bytes)) {
            return peelf::make_error(std::string(max_bytes_message));
        }
    }

    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return peelf::make_error(std::format("Failed to open file '{}'", path.string()));
    }
    const auto end_pos = ifs.tellg();
    if (end_pos < 0) {
        return peelf::make_error(
            std::format("Failed to determine file size of '{}'", path.string()));
    }
    const auto uend_pos = static_cast<std::uintmax_t>(end_pos);
    if (max_bytes.has_value() && uend_pos > static_cast<std::uintmax_t>(*max_bytes)) {
        return peelf::make_error(std::string(max_bytes_message));
    }
    if (uend_pos > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        return peelf::make_error(
            std::format("File '{}' is too large to fit in memory", path.string()));
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(uend_pos));
    ifs.seekg(0, std::ios::beg);
    if (!data.empty() &&
        !ifs.read(reinterpret_cast<char*>(data.data()),
                  static_cast<std::streamsize>(data.size()))) {
        return peelf::make_error(std::format("Failed while reading '{}'", path.string()));
    }
    return data;
}

[[nodiscard]] peelf::Result<void> write_text_file_atomically(
    const std::filesystem::path& output_path,
    std::string_view content) {
    if (output_path.empty() || output_path.filename().empty()) {
        return peelf::make_error("Invalid output file path");
    }

    std::error_code ec{};
    const std::filesystem::path parent = output_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return peelf::make_error(std::format(
                "Failed to create parent directory '{}': {}",
                parent.string(),
                ec.message()));
        }
    }

    std::error_code base_ec{};
    const std::filesystem::path base_dir =
        parent.empty() ? std::filesystem::current_path(base_ec) : parent;
    if (base_ec) {
        return peelf::make_error(std::format(
            "Failed to resolve output directory for '{}': {}",
            output_path.string(),
            base_ec.message()));
    }

    struct TempFileGuard {
        std::filesystem::path temp_path{};
#ifdef _WIN32
        HANDLE handle{INVALID_HANDLE_VALUE};
#else
        int fd{-1};
#endif
        bool committed{false};

        TempFileGuard() = default;
        TempFileGuard(const TempFileGuard&) = delete;
        TempFileGuard& operator=(const TempFileGuard&) = delete;
        TempFileGuard(TempFileGuard&&) = delete;
        TempFileGuard& operator=(TempFileGuard&&) = delete;

        ~TempFileGuard() noexcept {
#ifdef _WIN32
            if (handle != INVALID_HANDLE_VALUE) {
                (void)::CloseHandle(handle);
                handle = INVALID_HANDLE_VALUE;
            }
            if (!committed && !temp_path.empty()) {
                (void)::DeleteFileW(temp_path.c_str());
            }
#else
            if (fd >= 0) {
                (void)::close(fd);
                fd = -1;
            }
            if (!committed && !temp_path.empty()) {
                (void)::unlink(temp_path.c_str());
            }
#endif
        }
    };

    static std::atomic<std::uint64_t> tmp_counter{0u};
    const std::uint64_t pid =
#ifdef _WIN32
        static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
        static_cast<std::uint64_t>(::getpid());
#endif

    TempFileGuard guard{};
#ifndef _WIN32
    mode_t preserved_mode = 0666;
    bool has_preserved_mode = false;
    struct stat existing_st {};
    if (::stat(output_path.c_str(), &existing_st) == 0 && S_ISREG(existing_st.st_mode)) {
        preserved_mode = static_cast<mode_t>(existing_st.st_mode & 07777);
        has_preserved_mode = true;
    }
#endif

    constexpr std::uint32_t kMaxCreateAttempts = 128u;
    bool opened = false;
    for (std::uint32_t attempt = 0u; attempt < kMaxCreateAttempts; ++attempt) {
        std::filesystem::path candidate = base_dir / output_path.filename();
        candidate += std::format(".{}-{}-{}.tmp",
                                 pid,
                                 std::chrono::steady_clock::now().time_since_epoch().count(),
                                 tmp_counter.fetch_add(1u, std::memory_order_relaxed) + 1u);
#ifdef _WIN32
        const HANDLE h = ::CreateFileW(
            candidate.c_str(),
            GENERIC_WRITE,
            0u,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            guard.temp_path = std::move(candidate);
            guard.handle = h;
            opened = true;
            break;
        }
        const DWORD last_err = ::GetLastError();
        if (last_err == ERROR_FILE_EXISTS || last_err == ERROR_ALREADY_EXISTS) {
            continue;
        }
        return peelf::make_error(
            std::format("Failed to open temporary output file '{}'", candidate.string()));
#else
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        int fd = -1;
        do {
            fd = ::open(candidate.c_str(), flags, 0666);
        } while (fd < 0 && errno == EINTR);
        if (fd >= 0) {
            if (has_preserved_mode) {
                (void)::fchmod(fd, preserved_mode);
            }
            guard.temp_path = std::move(candidate);
            guard.fd = fd;
            opened = true;
            break;
        }
        if (errno == EEXIST) {
            continue;
        }
        return peelf::make_error(
            std::format("Failed to open temporary output file '{}'", candidate.string()));
#endif
    }

    if (!opened) {
        return peelf::make_error(std::format(
            "Failed to create unique temporary output file for '{}'", output_path.string()));
    }

#ifdef _WIN32
    std::size_t offset = 0u;
    while (offset < content.size()) {
        const std::size_t remaining = content.size() - offset;
        const auto chunk =
            static_cast<DWORD>(std::min<std::size_t>(remaining, 64u * 1024u * 1024u));
        DWORD written = 0u;
        if (!::WriteFile(guard.handle, content.data() + offset, chunk, &written, nullptr) ||
            written == 0u) {
            return peelf::make_error(std::format(
                "Failed while writing temporary output file '{}'", guard.temp_path.string()));
        }
        offset += static_cast<std::size_t>(written);
    }
    if (!::FlushFileBuffers(guard.handle)) {
        return peelf::make_error(std::format(
            "Failed to flush temporary output file '{}'", guard.temp_path.string()));
    }
    const HANDLE closing = guard.handle;
    guard.handle = INVALID_HANDLE_VALUE;
    if (!::CloseHandle(closing)) {
        return peelf::make_error(std::format(
            "Failed to close temporary output file '{}'", guard.temp_path.string()));
    }
    if (!::MoveFileExW(guard.temp_path.c_str(),
                       output_path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return peelf::make_error(
            std::format("Failed to commit output file '{}'", output_path.string()));
    }
#else
    std::size_t offset = 0u;
    while (offset < content.size()) {
        const std::size_t remaining = content.size() - offset;
        const std::size_t chunk = std::min<std::size_t>(remaining, 64u * 1024u * 1024u);
        const ssize_t written = ::write(guard.fd, content.data() + offset, chunk);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return peelf::make_error(std::format(
                "Failed while writing temporary output file '{}'", guard.temp_path.string()));
        }
        if (written == 0) {
            return peelf::make_error(std::format(
                "Failed while writing temporary output file '{}'", guard.temp_path.string()));
        }
        offset += static_cast<std::size_t>(written);
    }
    while (::fsync(guard.fd) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return peelf::make_error(std::format(
            "Failed to flush temporary output file '{}'", guard.temp_path.string()));
    }
    const int closing = guard.fd;
    guard.fd = -1;
    if (::close(closing) != 0 && errno != EINTR) {
        return peelf::make_error(std::format(
            "Failed to close temporary output file '{}'", guard.temp_path.string()));
    }
    if (::rename(guard.temp_path.c_str(), output_path.c_str()) != 0) {
        return peelf::make_error(
            std::format("Failed to commit output file '{}'", output_path.string()));
    }
#endif

    guard.committed = true;
    return {};
}

[[nodiscard]] peelf::Result<peelf::BinaryOpenOptions> parse_slice_selector_options(
    const std::optional<std::string>& slice_selector) {
    peelf::BinaryOpenOptions open_opts{};
    if (!slice_selector.has_value()) {
        return open_opts;
    }
    const std::string_view sel = *slice_selector;
    if (sel.empty()) {
        return peelf::make_error("--slice selector must not be empty");
    }
    bool all_digits = true;
    for (const char ch : sel) {
        if (ch < '0' || ch > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        std::size_t idx = 0u;
        const auto [ptr, ec] = std::from_chars(sel.data(), sel.data() + sel.size(), idx);
        if (ec != std::errc{} || ptr != sel.data() + sel.size()) {
            return peelf::make_error(std::format("Invalid numeric --slice index '{}'", sel));
        }
        open_opts.selected_slice_index = idx;
    } else {
        open_opts.preferred_arch_name = std::string(sel);
    }
    return open_opts;
}

// Lightweight `PEELF_PROJECT 2` reader/writer compatible with `viewer::decode_project`
// without pulling GUI/viewer-only headers into `peelf_viewer`.
struct HeadlessProjectData {
    struct SavedSymbol {
        std::string name{};
        std::uint64_t rva{0u};
        std::uint64_t va{0u};
        std::uint64_t size{0u};
        bool is_function{false};
    };
    struct SavedStructBinding {
        std::uint64_t address{0u};
        bool is_file_offset{false};
        std::string type_name{};
        std::uint32_t count{1u};
        std::string label{};
    };
    struct SavedOffsetBookmark {
        std::uint64_t offset{0u};
        std::string label{};
        std::string category{};
        std::string note{};
    };
    struct SavedVaBookmarkMeta {
        std::string category{};
        std::string note{};
    };

    std::uint64_t source_size{0u};
    std::uint64_t fingerprint{0u};
    std::string source_sha256{};
    bool thumb{false};
    std::vector<peelf::PatchInterval> patches{};
    peelf::ProjectWorkspace workspace{};
    std::vector<SavedOffsetBookmark> preserved_offset_bookmarks{};
    std::map<std::uint64_t, SavedVaBookmarkMeta> preserved_va_bookmark_meta{};
    std::vector<SavedSymbol> symbols{};
    std::vector<SavedStructBinding> structure_bindings{};
    std::string raw_history_and_layout{"0 0\n\"\"\n"};
};

[[nodiscard]] peelf::Result<HeadlessProjectData> load_headless_peproj(
    const std::filesystem::path& peproj_path,
    std::span<const std::uint8_t> target_binary_bytes,
    bool allow_modified_binary) {
    auto bytes = read_binary_file(
        peproj_path, kMaxProjectFileBytes, "Project exceeds 64 MiB limit");
    if (!bytes.has_value()) {
        return std::unexpected(bytes.error());
    }

    const std::string text(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    std::istringstream in{text};

    std::string magic{};
    int version = 0;
    if (!(in >> magic >> version) || magic != "PEELF_PROJECT" || (version != 1 && version != 2)) {
        return peelf::make_error(
            std::format("Invalid or unsupported project file '{}'", peproj_path.string()));
    }

    HeadlessProjectData out{};
    std::uint64_t proj_source_size = 0u;
    if (version == 1) {
        std::string src{};
        std::uint64_t fp = 0u;
        int thumb = 0;
        if (!(in >> std::quoted(src) >> proj_source_size >> fp >> thumb) ||
            (thumb != 0 && thumb != 1)) {
            return peelf::make_error("Malformed PEELF_PROJECT v1 header");
        }
        out.source_size = proj_source_size;
        out.fingerprint = fp;
        out.thumb = (thumb != 0);
    } else {
        std::string src{};
        std::string rel_src{};
        std::string sha{};
        std::uint64_t fp = 0u;
        int thumb = 0;
        std::uint64_t saved_ms = 0u;
        if (!(in >> std::quoted(src) >> std::quoted(rel_src) >> std::quoted(sha) >>
              proj_source_size >> fp >> thumb >> saved_ms) ||
            (thumb != 0 && thumb != 1) || !normalize_sha256_hex(sha)) {
            return peelf::make_error("Malformed PEELF_PROJECT v2 header");
        }
        out.source_size = proj_source_size;
        out.fingerprint = fp;
        out.source_sha256 = std::move(sha);
        out.thumb = (thumb != 0);
    }

    const auto expected_source_size = static_cast<std::uint64_t>(target_binary_bytes.size());
    if (!allow_modified_binary) {
        if (proj_source_size != expected_source_size) {
            return peelf::make_error(std::format(
                "Project '{}' source size ({}) does not match target binary size ({})",
                peproj_path.string(),
                proj_source_size,
                expected_source_size));
        }
        if (!out.source_sha256.empty()) {
            const std::string actual_sha256 = peelf::sha256_hex(target_binary_bytes);
            if (actual_sha256 != out.source_sha256) {
                return peelf::make_error(std::format(
                    "Project '{}' source SHA-256 ({}) does not match target binary SHA-256 ({})",
                    peproj_path.string(),
                    out.source_sha256,
                    actual_sha256));
            }
        }
        if (out.fingerprint != 0u && fnv1a_fingerprint(target_binary_bytes) != out.fingerprint) {
            return peelf::make_error(std::format(
                "Project '{}' source fingerprint does not match target binary",
                peproj_path.string()));
        }
    }

    std::size_t patch_count = 0u;
    if (!(in >> patch_count) || patch_count > kMaxProjectItems) {
        return peelf::make_error("Invalid patch table in project file");
    }
    std::uint64_t prev_end = 0u;
    for (std::size_t i = 0u; i < patch_count; ++i) {
        peelf::PatchInterval iv{};
        std::string orig_hex{};
        std::string patched_hex{};
        if (!(in >> iv.offset >> std::quoted(orig_hex) >> std::quoted(patched_hex)) ||
            !decode_hex_bytes(orig_hex, iv.original) ||
            !decode_hex_bytes(patched_hex, iv.patched) ||
            iv.patched.empty() || iv.original.size() != iv.patched.size() ||
            iv.offset < prev_end || iv.offset > proj_source_size ||
            iv.patched.size() > proj_source_size - iv.offset) {
            return peelf::make_error("Invalid patch entry in project file");
        }
        if (iv.offset > expected_source_size ||
            iv.patched.size() > expected_source_size - iv.offset) {
            return peelf::make_error(std::format(
                "Project '{}' patch interval at offset 0x{:x} exceeds target binary bounds",
                peproj_path.string(),
                iv.offset));
        }
        if (!allow_modified_binary &&
            !std::ranges::equal(
                iv.original,
                target_binary_bytes.subspan(static_cast<std::size_t>(iv.offset),
                                            iv.original.size()))) {
            return peelf::make_error(std::format(
                "Project '{}' saved patch original bytes at offset 0x{:x} do not match target binary",
                peproj_path.string(),
                iv.offset));
        }
        prev_end = iv.end_offset();
        out.patches.push_back(std::move(iv));
    }

    std::size_t note_count = 0u;
    if (!(in >> note_count) || note_count > kMaxProjectItems) {
        return peelf::make_error("Invalid annotation table in project file");
    }
    for (std::size_t i = 0u; i < note_count; ++i) {
        std::uint64_t addr = 0u;
        std::string name{};
        std::string comment{};
        if (!(in >> addr >> std::quoted(name) >> std::quoted(comment))) {
            return peelf::make_error("Invalid annotation entry in project file");
        }
        if (!name.empty()) {
            out.workspace.set_label(addr, std::move(name));
        }
        if (!comment.empty()) {
            out.workspace.set_comment(addr, std::move(comment));
        }
    }

    std::size_t sym_count = 0u;
    if (!(in >> sym_count) || sym_count > kMaxProjectItems) {
        return peelf::make_error("Invalid symbol table in project file");
    }
    for (std::size_t i = 0u; i < sym_count; ++i) {
        HeadlessProjectData::SavedSymbol sym{};
        int fn = 0;
        if (!(in >> std::quoted(sym.name) >> sym.rva >> sym.va >> sym.size >> fn) ||
            (fn != 0 && fn != 1)) {
            return peelf::make_error("Invalid symbol entry in project file");
        }
        sym.is_function = (fn != 0);
        out.symbols.push_back(std::move(sym));
    }

    if (version == 2) {
        std::size_t bm_count = 0u;
        if (!(in >> bm_count) || bm_count > kMaxProjectItems) {
            return peelf::make_error("Invalid bookmark table in project file");
        }
        for (std::size_t i = 0u; i < bm_count; ++i) {
            std::uint64_t bm_addr = 0u;
            int is_off = 0;
            std::string bm_label{};
            std::string bm_cat{};
            std::string bm_note{};
            if (!(in >> bm_addr >> is_off >> std::quoted(bm_label) >>
                  std::quoted(bm_cat) >> std::quoted(bm_note)) ||
                (is_off != 0 && is_off != 1)) {
                return peelf::make_error("Invalid bookmark entry in project file");
            }
            if (is_off != 0) {
                out.preserved_offset_bookmarks.push_back(HeadlessProjectData::SavedOffsetBookmark{
                    .offset = bm_addr,
                    .label = std::move(bm_label),
                    .category = std::move(bm_cat),
                    .note = std::move(bm_note),
                });
            } else {
                out.preserved_va_bookmark_meta[bm_addr] = HeadlessProjectData::SavedVaBookmarkMeta{
                    .category = std::move(bm_cat),
                    .note = std::move(bm_note),
                };
                out.workspace.add_bookmark(bm_addr, std::move(bm_label));
            }
        }

        std::size_t sb_count = 0u;
        if (!(in >> sb_count) || sb_count > kMaxProjectItems) {
            return peelf::make_error("Invalid structure binding table in project file");
        }
        for (std::size_t i = 0u; i < sb_count; ++i) {
            HeadlessProjectData::SavedStructBinding sb{};
            int is_off = 0;
            if (!(in >> sb.address >> is_off >> std::quoted(sb.type_name) >>
                  sb.count >> std::quoted(sb.label)) ||
                (is_off != 0 && is_off != 1) || sb.type_name.empty() || sb.count == 0u) {
                return peelf::make_error("Invalid structure binding entry in project file");
            }
            sb.is_file_offset = (is_off != 0);
            out.structure_bindings.push_back(std::move(sb));
        }
    }

    in >> std::ws;
    std::string tail((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (!tail.empty()) {
        if (tail.back() != '\n') {
            tail.push_back('\n');
        }
        out.raw_history_and_layout = std::move(tail);
    }

    return out;
}

[[nodiscard]] std::string encode_headless_peproj(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& peproj_path,
    std::span<const std::uint8_t> raw_binary_bytes,
    const HeadlessProjectData& data) {
    std::error_code ec{};
    const std::filesystem::path abs_src = std::filesystem::absolute(binary_path, ec);
    const std::string source_str = (!ec && !abs_src.empty())
                                       ? abs_src.string()
                                       : binary_path.string();
    std::string rel_source_str{};
    if (!peproj_path.empty() && !abs_src.empty()) {
        const std::filesystem::path base_dir =
            std::filesystem::absolute(peproj_path, ec).parent_path();
        if (!ec && !base_dir.empty()) {
            const std::filesystem::path rel = std::filesystem::proximate(abs_src, base_dir, ec);
            if (!ec && !rel.empty()) {
                rel_source_str = rel.generic_string();
            }
        }
    }

    const std::string sha256 = peelf::sha256_hex(raw_binary_bytes);
    const std::uint64_t fp = fnv1a_fingerprint(raw_binary_bytes);
    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    const auto& ws_labels = data.workspace.labels();
    const auto& ws_comments = data.workspace.comments();
    const std::span<const peelf::ScriptBookmark> ws_bookmarks = data.workspace.bookmarks();

    std::set<std::uint64_t> note_addrs{};
    for (const auto& [addr, name] : ws_labels) {
        if (!name.empty()) {
            note_addrs.insert(addr);
        }
    }
    for (const auto& [addr, comment] : ws_comments) {
        if (!comment.empty()) {
            note_addrs.insert(addr);
        }
    }

    std::ostringstream out{};
    out << "PEELF_PROJECT 2\n"
        << std::quoted(source_str) << ' '
        << std::quoted(rel_source_str) << ' '
        << std::quoted(sha256) << ' '
        << raw_binary_bytes.size() << ' '
        << fp << ' '
        << (data.thumb ? 1 : 0) << ' '
        << now_ms << '\n';

    out << data.patches.size() << '\n';
    for (const peelf::PatchInterval& iv : data.patches) {
        out << iv.offset << ' '
            << std::quoted(encode_hex_lower(iv.original)) << ' '
            << std::quoted(encode_hex_lower(iv.patched)) << '\n';
    }

    out << note_addrs.size() << '\n';
    for (const std::uint64_t addr : note_addrs) {
        const auto lbl_it = ws_labels.find(addr);
        const auto cmt_it = ws_comments.find(addr);
        const std::string_view name =
            (lbl_it != ws_labels.end()) ? std::string_view{lbl_it->second} : "";
        const std::string_view comment =
            (cmt_it != ws_comments.end()) ? std::string_view{cmt_it->second} : "";
        out << addr << ' ' << std::quoted(name) << ' ' << std::quoted(comment) << '\n';
    }

    out << data.symbols.size() << '\n';
    for (const auto& sym : data.symbols) {
        out << std::quoted(sym.name) << ' '
            << sym.rva << ' '
            << sym.va << ' '
            << sym.size << ' '
            << (sym.is_function ? 1 : 0) << '\n';
    }

    out << (data.preserved_offset_bookmarks.size() + ws_bookmarks.size()) << '\n';
    for (const auto& obm : data.preserved_offset_bookmarks) {
        out << obm.offset << " 1 "
            << std::quoted(obm.label) << ' '
            << std::quoted(obm.category) << ' '
            << std::quoted(obm.note) << '\n';
    }
    for (const peelf::ScriptBookmark& bm : ws_bookmarks) {
        const auto meta_it = data.preserved_va_bookmark_meta.find(bm.virtual_address);
        const std::string_view category =
            (meta_it != data.preserved_va_bookmark_meta.end())
                ? std::string_view{meta_it->second.category}
                : std::string_view{"Script"};
        const std::string_view note =
            (meta_it != data.preserved_va_bookmark_meta.end())
                ? std::string_view{meta_it->second.note}
                : std::string_view{};
        out << bm.virtual_address << " 0 "
            << std::quoted(bm.label) << ' '
            << std::quoted(category) << ' '
            << std::quoted(note) << '\n';
    }

    out << data.structure_bindings.size() << '\n';
    for (const auto& sb : data.structure_bindings) {
        const std::uint32_t count = (sb.count == 0u) ? 1u : sb.count;
        out << sb.address << ' '
            << (sb.is_file_offset ? 1 : 0) << ' '
            << std::quoted(sb.type_name) << ' '
            << count << ' '
            << std::quoted(sb.label) << '\n';
    }

    out << data.raw_history_and_layout;
    return out.str();
}

void print_help_usage(std::ostream& stdout_stream) {
    stdout_stream
        << "PE/ELF Explorer\n"
        << "Usage:\n"
        << "  peelf_viewer                                  Launch Vulkan/ImGui desktop viewer\n"
        << "  peelf_viewer --headless                       Smoke check without loading GUI (exits 0)\n"
        << "  peelf_viewer --headless <binary> [options]    Run headless static, security, or Lua inspection\n"
        << "\nHeadless Inspection Options:\n"
        << "  --slice <index|arch>         Select Universal Mach-O slice by 0-based index or arch name\n"
        << "  --compare <other_binary>     Include static binary & relocation-tolerant function diff\n"
        << "  --format <json|sarif|csv|text>\n"
        << "                               Output format (default: json for audit, text for --script)\n"
        << "  --output <path>              Write report atomically to <path> (default: stdout)\n"
        << "  --search-root <dir>          Extra dependency search directory (repeatable)\n"
        << "  --rules <path>               Evaluate custom YARA-lite rule file (repeatable)\n"
        << "  --no-builtin-rules           Disable built-in YARA-lite starter rule pack\n"
        << "  --include-strings            Include extracted printable ASCII/UTF-16 strings\n"
        << "  --min-string-len <N>         Minimum character length for extracted strings (default: 4)\n"
        << "  --clr                        Include .NET / CLR ECMA-335 metadata, AssemblyRefs & P/Invoke imports\n"
        << "  --fail-on <none|error|warning>\n"
        << "                               CI policy gate (exit 2 on security findings or missing deps)\n"
        << "\nHeadless Code-Flow Graph Options (--graph):\n"
        << "  --graph <entry|fanout|cfg>   Export entry call graph, symbol fan-out, or function CFG\n"
        << "  --symbol <name-or-va>        Target function name (demangled, mangled, substring) or hex VA (0x...)\n"
        << "  --graph-depth <N>            Call-graph traversal depth for entry/fanout (default: 3)\n"
        << "  --graph-max-nodes <N>        Maximum nodes emitted in exported graph (default: 64)\n"
        << "  --graph-format <dot|svg|png|json>\n"
        << "                               Graph export format (default: from --output ext, svg with --output, dot to stdout)\n"
        << "\nHeadless Lua Scripting Options (--script):\n"
        << "  --script <file.lua>          Execute sandboxed Lua 5.4 script against <binary> (read-only default)\n"
        << "  --script-allow-mutations     Allow script to stage/commit patches, labels, comments & bookmarks\n"
        << "  --allow-modified-binary      Allow loading a .peproj whose source SHA-256 differs from <binary>\n"
        << "  --output-binary <out_path>   Write patched binary atomically when script calls peelf.commit()\n"
        << "  --project <workspace.peproj> Load/save PEELF_PROJECT v2 annotations, bookmarks & byte patches\n"
        << "  --script-max-instructions <N> Override Lua VM instruction quota (default: 1000000)\n"
        << "  --script-timeout-ms <ms>     Override Lua script wall-clock timeout in ms (default: 5000)\n"
        << "  -V, --version                Print version (peelf_viewer " PEELF_VERSION_STRING ") and exit 0\n"
        << "  -h, --help                   Show this help\n";
}

} // namespace

peelf::Result<HeadlessScriptRunReport> run_headless_script(
    const HeadlessScriptCliOptions& options) {
    if (options.binary_path.empty()) {
        return peelf::make_error("No input binary path specified for --script");
    }
    if (options.script_path.empty()) {
        return peelf::make_error("No Lua script path specified for --script");
    }
    if (options.limits.wall_clock_timeout <= std::chrono::milliseconds::zero()) {
        return peelf::make_error("Lua script wall-clock timeout must be positive");
    }

    auto script_bytes = read_binary_file(options.script_path);
    if (!script_bytes.has_value()) {
        return peelf::make_error(
            std::format("Failed to open Lua script '{}': {}",
                        options.script_path.string(),
                        script_bytes.error().message));
    }
    const std::string script_source(
        reinterpret_cast<const char*>(script_bytes->data()), script_bytes->size());
    const std::string chunk_name = "@" + options.script_path.filename().string();

    auto raw_bytes = read_binary_file(options.binary_path);
    if (!raw_bytes.has_value()) {
        return std::unexpected(raw_bytes.error());
    }

    HeadlessScriptRunReport report{};
    report.binary_path = options.binary_path;
    report.script_path = options.script_path;
    report.allow_mutations = options.allow_mutations;

    // Offline crash dump support (strictly read-only).
    if (peelf::is_crash_dump_bytes(*raw_bytes)) {
        if (options.output_binary_path.has_value() || options.project_path.has_value()) {
            return peelf::make_error(
                "--output-binary and --project are only supported for static binary images");
        }
        auto dump = peelf::open_crash_dump_bytes(std::move(*raw_bytes), options.binary_path);
        if (!dump.has_value()) {
            return std::unexpected(dump.error());
        }
        std::unique_ptr<peelf::IBinaryImage> hydrated{};
        const auto regs = (*dump)->memory_regions();
        const auto mods = (*dump)->modules();
        if (regs.has_value() && mods.has_value() && !mods->empty()) {
            if (auto mod_img = peelf::load_live_module_image(**dump, (*mods)[0], *regs);
                mod_img.has_value()) {
                hydrated = std::move(*mod_img);
            }
        }
        peelf::ScriptContext ctx{};
        ctx.image = hydrated.get();
        ctx.live_session = dump->get();
        ctx.crash_dump = dump->get();
        ctx.allow_mutations = false;
        ctx.is_read_only = true;
        report.execution = peelf::execute_lua_script(
            script_source, ctx, options.limits, {}, chunk_name);
        return report;
    }

    auto open_opts = parse_slice_selector_options(options.slice_selector);
    if (!open_opts.has_value()) {
        return std::unexpected(open_opts.error());
    }

    HeadlessProjectData proj_data{};
    std::error_code fs_ec{};
    if (options.project_path.has_value() &&
        std::filesystem::exists(*options.project_path, fs_ec) && !fs_ec) {
        auto loaded_proj = load_headless_peproj(
            *options.project_path, *raw_bytes, options.allow_modified_binary);
        if (!loaded_proj.has_value()) {
            return std::unexpected(loaded_proj.error());
        }
        proj_data = std::move(*loaded_proj);
    }

    std::vector<std::uint8_t> effective_initial_bytes = *raw_bytes;
    for (const peelf::PatchInterval& iv : proj_data.patches) {
        if (iv.offset <= effective_initial_bytes.size() &&
            iv.patched.size() <= effective_initial_bytes.size() - iv.offset) {
            std::copy(iv.patched.begin(),
                      iv.patched.end(),
                      effective_initial_bytes.begin() + static_cast<std::ptrdiff_t>(iv.offset));
        }
    }

    peelf::BinaryContainerInfo cinfo{};
    if (auto inspected = peelf::inspect_binary_container(effective_initial_bytes);
        inspected.has_value()) {
        cinfo = std::move(*inspected);
    }

    auto parsed_image = peelf::open_binary_image(effective_initial_bytes, *open_opts);
    if (!parsed_image.has_value()) {
        return peelf::make_error(std::format(
            "Failed to parse '{}': {}",
            options.binary_path.string(),
            parsed_image.error().message));
    }

    report.selected_slice_index = (*parsed_image)->container_slice_index();
    if (report.selected_slice_index < cinfo.slices.size()) {
        report.selected_slice_arch = cinfo.slices[report.selected_slice_index].arch_name;
    } else {
        report.selected_slice_arch =
            std::string(peelf::to_string((*parsed_image)->architecture()));
    }

    std::optional<peelf::PagedBinaryImage> paged_img{};
    if (options.allow_mutations || !proj_data.patches.empty()) {
        auto opened_paged = peelf::PagedBinaryImage::open(options.binary_path);
        if (!opened_paged.has_value()) {
            return peelf::make_error(std::format(
                "Failed to open paged image for '{}': {}",
                options.binary_path.string(),
                opened_paged.error().message));
        }
        if (opened_paged->size() != raw_bytes->size()) {
            return peelf::make_error(std::format(
                "Target binary '{}' changed size on disk before script execution",
                options.binary_path.string()));
        }
        if (!proj_data.patches.empty()) {
            auto seed_tx = opened_paged->begin_transaction("Seed project patches");
            for (const peelf::PatchInterval& iv : proj_data.patches) {
                if (!options.allow_modified_binary) {
                    auto orig_disk = opened_paged->read_original(iv.offset, iv.original.size());
                    if (!orig_disk.has_value()) {
                        return std::unexpected(orig_disk.error());
                    }
                    if (!std::ranges::equal(*orig_disk, iv.original)) {
                        return peelf::make_error(std::format(
                            "Saved patch original bytes at offset 0x{:x} do not match target binary",
                            iv.offset));
                    }
                }
                if (auto wr = seed_tx.write(iv.offset, iv.patched); !wr.has_value()) {
                    return std::unexpected(wr.error());
                }
            }
            if (auto cm = seed_tx.commit(); !cm.has_value()) {
                return std::unexpected(cm.error());
            }
        }
        paged_img = std::move(*opened_paged);
    }

    peelf::ScriptContext ctx{};
    ctx.image = parsed_image->get();
    ctx.raw_bytes = effective_initial_bytes;
    ctx.paged_image = (options.allow_mutations && paged_img.has_value())
                          ? &*paged_img
                          : nullptr;
    ctx.workspace = &proj_data.workspace;
    ctx.allow_mutations = options.allow_mutations;
    ctx.is_read_only = !options.allow_mutations;

    report.execution = peelf::execute_lua_script(
        script_source, ctx, options.limits, {}, chunk_name);

    if (options.allow_mutations && report.execution.ok && report.execution.committed) {
        if (options.output_binary_path.has_value()) {
            if (!paged_img.has_value()) {
                return peelf::make_error("Internal error: missing editable image for --output-binary");
            }
            if (auto wr = paged_img->write_effective_to(*options.output_binary_path, true);
                !wr.has_value()) {
                return peelf::make_error(std::format(
                    "Failed to write patched binary '{}': {}",
                    options.output_binary_path->string(),
                    wr.error().message));
            }
            report.output_binary_written = true;
        }
        if (options.project_path.has_value()) {
            if (paged_img.has_value()) {
                proj_data.patches = paged_img->changed_intervals();
            }
            const std::string encoded = encode_headless_peproj(
                options.binary_path,
                *options.project_path,
                *raw_bytes,
                proj_data);
            if (encoded.size() > kMaxProjectFileBytes) {
                return peelf::make_error("Project exceeds 64 MiB limit");
            }
            if (auto wr = write_text_file_atomically(*options.project_path, encoded);
                !wr.has_value()) {
                return std::unexpected(wr.error());
            }
            report.project_written = true;
        }
    }

    return report;
}

std::string format_headless_script_report_text(const HeadlessScriptRunReport& report) {
    const peelf::ScriptExecutionResult& res = report.execution;
    std::string out{};
    out.reserve(res.output.size() + 512u);

    if (!res.output.empty()) {
        out += res.output;
        if (out.back() != '\n') {
            out.push_back('\n');
        }
    }

    const std::string_view mode_str =
        !report.allow_mutations
            ? "read-only"
            : (res.committed ? "committed" : "dry-run");
    out += std::format(
        "[script] target={} slice={} ({}) status={} mode={} insns={} peak_mem_bytes={} elapsed_ms={}\n",
        report.binary_path.generic_string(),
        report.selected_slice_index,
        report.selected_slice_arch,
        res.ok ? "OK" : std::string(peelf::to_string(res.error_kind)),
        mode_str,
        res.instructions_executed,
        res.peak_memory_bytes,
        res.elapsed.count());

    const auto& staged = res.staged_summary;
    if (!staged.staged_patches.empty() || !staged.staged_labels.empty() ||
        !staged.staged_comments.empty() || !staged.staged_bookmarks.empty()) {
        out += std::format(
            "[script] mutations: patches={} labels={} comments={} bookmarks={} (committed={})\n",
            staged.staged_patches.size(),
            staged.staged_labels.size(),
            staged.staged_comments.size(),
            staged.staged_bookmarks.size(),
            res.committed ? "true" : "false");
    }
    if (!res.ok && !res.error_message.empty()) {
        out += std::format("[script] error [{}]: {}\n",
                           peelf::to_string(res.error_kind),
                           res.error_message);
    }
    return out;
}

std::string format_headless_script_report_json(const HeadlessScriptRunReport& report) {
    const peelf::ScriptExecutionResult& res = report.execution;
    const peelf::ScriptExecutionSummary& staged = res.staged_summary;
    std::string out{};
    out.reserve(res.output.size() + 1024u);

    auto key = [&out](std::string_view k) {
        append_json_escaped(out, k);
        out += ": ";
    };

    out += "{\n";
    out += "  "; key("binary_path"); append_json_escaped(out, report.binary_path.generic_string()); out += ",\n";
    out += "  "; key("script_path"); append_json_escaped(out, report.script_path.generic_string()); out += ",\n";
    out += std::format("  \"selected_slice_index\": {},\n", report.selected_slice_index);
    out += "  "; key("selected_slice_arch"); append_json_escaped(out, report.selected_slice_arch); out += ",\n";
    out += std::format("  \"ok\": {},\n", res.ok ? "true" : "false");
    out += "  "; key("error_kind"); append_json_escaped(out, peelf::to_string(res.error_kind)); out += ",\n";
    out += "  "; key("error_message"); append_json_escaped(out, res.error_message); out += ",\n";
    out += std::format("  \"allow_mutations\": {},\n", report.allow_mutations ? "true" : "false");
    out += std::format("  \"committed\": {},\n", res.committed ? "true" : "false");
    out += std::format("  \"output_binary_written\": {},\n", report.output_binary_written ? "true" : "false");
    out += std::format("  \"project_written\": {},\n", report.project_written ? "true" : "false");
    out += "  "; key("output"); append_json_escaped(out, res.output); out += ",\n";
    out += std::format("  \"output_truncated\": {},\n", res.output_truncated ? "true" : "false");
    out += std::format("  \"instructions_executed\": {},\n", res.instructions_executed);
    out += std::format("  \"peak_memory_bytes\": {},\n", res.peak_memory_bytes);
    out += std::format("  \"elapsed_ms\": {},\n", res.elapsed.count());

    out += "  \"staged_summary\": {\n";
    out += "    \"patches\": [";
    for (std::size_t i = 0u; i < staged.staged_patches.size(); ++i) {
        const peelf::StagedBytePatch& sp = staged.staged_patches[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += std::format("      {{ \"virtual_address\": {}, \"file_offset\": {}, ",
                           sp.virtual_address,
                           sp.file_offset);
        key("original_hex"); append_json_escaped(out, encode_hex_lower(sp.original_bytes)); out += ", ";
        key("patched_hex"); append_json_escaped(out, encode_hex_lower(sp.patched_bytes));
        out += " }";
    }
    if (!staged.staged_patches.empty()) out += "\n    ";
    out += "],\n";

    out += "    \"labels\": [";
    std::size_t idx = 0u;
    for (const auto& [va, maybe_lbl] : staged.staged_labels) {
        out += (idx++ == 0u) ? "\n" : ",\n";
        out += std::format("      {{ \"virtual_address\": {}, ", va);
        key("label");
        if (maybe_lbl.has_value()) {
            append_json_escaped(out, *maybe_lbl);
        } else {
            out += "null";
        }
        out += " }";
    }
    if (!staged.staged_labels.empty()) out += "\n    ";
    out += "],\n";

    out += "    \"comments\": [";
    idx = 0u;
    for (const auto& [va, maybe_cmt] : staged.staged_comments) {
        out += (idx++ == 0u) ? "\n" : ",\n";
        out += std::format("      {{ \"virtual_address\": {}, ", va);
        key("comment");
        if (maybe_cmt.has_value()) {
            append_json_escaped(out, *maybe_cmt);
        } else {
            out += "null";
        }
        out += " }";
    }
    if (!staged.staged_comments.empty()) out += "\n    ";
    out += "],\n";

    out += "    \"bookmarks\": [";
    for (std::size_t i = 0u; i < staged.staged_bookmarks.size(); ++i) {
        const peelf::ScriptBookmark& bm = staged.staged_bookmarks[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += std::format("      {{ \"virtual_address\": {}, ", bm.virtual_address);
        key("label"); append_json_escaped(out, bm.label);
        out += " }";
    }
    if (!staged.staged_bookmarks.empty()) out += "\n    ";
    out += "]\n";
    out += "  }\n";
    out += "}\n";
    return out;
}


// ---------------------------------------------------------------------------
// Headless Code-Flow Graph Export (--graph entry|fanout|cfg)
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] std::string_view node_kind_json_name(CallGraphNodeKind kind) noexcept {
    switch (kind) {
        case CallGraphNodeKind::Function:    return "function";
        case CallGraphNodeKind::BasicBlock:  return "basic_block";
        case CallGraphNodeKind::Instruction: return "instruction";
        case CallGraphNodeKind::Import:      return "import";
        case CallGraphNodeKind::External:    return "external";
        case CallGraphNodeKind::Unknown:     return "unknown";
    }
    return "unknown";
}

[[nodiscard]] std::string_view edge_kind_json_name(CallGraphEdgeKind kind) noexcept {
    switch (kind) {
        case CallGraphEdgeKind::Call:                return "call";
        case CallGraphEdgeKind::ConditionalBranch:   return "conditional_branch";
        case CallGraphEdgeKind::UnconditionalBranch: return "unconditional_branch";
        case CallGraphEdgeKind::Fallthrough:         return "fallthrough";
        case CallGraphEdgeKind::Return:              return "return";
        case CallGraphEdgeKind::DataReference:       return "data_reference";
        case CallGraphEdgeKind::Unknown:             return "unknown";
    }
    return "unknown";
}

[[nodiscard]] std::optional<HeadlessGraphKind> parse_headless_graph_kind(std::string_view raw) noexcept {
    const std::string low = lower_ascii(raw);
    if (low == "entry") return HeadlessGraphKind::Entry;
    if (low == "fanout" || low == "fan-out") return HeadlessGraphKind::Fanout;
    if (low == "cfg") return HeadlessGraphKind::Cfg;
    return std::nullopt;
}

[[nodiscard]] std::optional<HeadlessGraphFormat> parse_headless_graph_format(std::string_view raw) noexcept {
    const std::string low = lower_ascii(raw);
    if (low == "dot" || low == "gv") return HeadlessGraphFormat::Dot;
    if (low == "svg") return HeadlessGraphFormat::Svg;
    if (low == "png") return HeadlessGraphFormat::Png;
    if (low == "json") return HeadlessGraphFormat::Json;
    return std::nullopt;
}

[[nodiscard]] std::string_view strip_elf_symbol_version(std::string_view sym) noexcept {
    if (sym.empty() || sym.front() == '?') {
        return sym;
    }
    const std::size_t at = sym.find('@');
    if (at != std::string_view::npos && at > 0u) {
        return sym.substr(0u, at);
    }
    return sym;
}

struct DemangledNameParts {
    std::string qualified{};
    std::string unqualified{};
};

[[nodiscard]] DemangledNameParts split_demangled_function_parts(std::string_view text) {
    std::string_view work = strip_elf_symbol_version(text);
    int angle_depth = 0;
    std::size_t paren_pos = std::string_view::npos;
    for (std::size_t i = 0u; i < work.size(); ++i) {
        const char ch = work[i];
        if (ch == '<') {
            ++angle_depth;
        } else if (ch == '>' && angle_depth > 0) {
            --angle_depth;
        } else if (ch == '(' && angle_depth == 0) {
            paren_pos = i;
            break;
        }
    }
    if (paren_pos != std::string_view::npos) {
        work = work.substr(0u, paren_pos);
    }
    while (!work.empty() && std::isspace(static_cast<unsigned char>(work.back())) != 0) {
        work.remove_suffix(1u);
    }
    angle_depth = 0;
    std::size_t last_space = std::string_view::npos;
    for (std::size_t i = 0u; i < work.size(); ++i) {
        const char ch = work[i];
        if (ch == '<') {
            ++angle_depth;
        } else if (ch == '>' && angle_depth > 0) {
            --angle_depth;
        } else if ((std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == '*' || ch == '&') &&
                   angle_depth == 0) {
            if (work.substr(0u, i).ends_with("operator")) {
                continue;
            }
            last_space = i;
        }
    }
    if (last_space != std::string_view::npos && (last_space + 1u) < work.size()) {
        work = work.substr(last_space + 1u);
    }

    std::string qualified(work);
    angle_depth = 0;
    std::size_t tmpl_pos = std::string::npos;
    for (std::size_t i = 0u; i < qualified.size(); ++i) {
        if (qualified[i] == '<') {
            if (angle_depth == 0) tmpl_pos = i;
            ++angle_depth;
        } else if (qualified[i] == '>' && angle_depth > 0) {
            --angle_depth;
        }
    }
    std::string qualified_no_tmpl =
        (tmpl_pos != std::string::npos && tmpl_pos > 0u) ? qualified.substr(0u, tmpl_pos) : qualified;

    std::string unqualified = qualified_no_tmpl;
    if (const std::size_t sep = unqualified.rfind("::"); sep != std::string::npos) {
        unqualified = unqualified.substr(sep + 2u);
    }
    return DemangledNameParts{
        .qualified = std::move(qualified_no_tmpl),
        .unqualified = std::move(unqualified),
    };
}

[[nodiscard]] int score_symbol_record(
    const peelf::IBinaryImage& image,
    const SymbolRecord& rec) noexcept {
    int score = 0;
    if (symbol_has_code(image, rec)) score += 100;
    if (!rec.external && rec.source != SymbolSource::Import) score += 40;
    if (rec.function.value_or(false)) score += 20;
    if (rec.size > 0u) score += 15;
    if (!rec.demangled_name.empty()) score += 5;
    if (!rec.dynamic) score += 3;
    return score;
}

[[nodiscard]] SymbolRecord enrich_symbol_display(const SymbolRecord& rec) {
    SymbolRecord copy = rec;
    if (copy.demangled_name.empty() && !copy.raw_name.empty()) {
        copy.demangled_name = peelf::demangle_symbol(copy.raw_name).demangled;
    } else if (copy.demangled_name.empty() && !copy.name.empty()) {
        copy.demangled_name = peelf::demangle_symbol(copy.name).demangled;
    }
    if (!copy.demangled_name.empty()) {
        copy.name = copy.demangled_name;
    }
    return copy;
}

[[nodiscard]] std::vector<SymbolRecord> deduplicate_candidates_by_va(
    const peelf::IBinaryImage& image,
    const std::vector<const SymbolRecord*>& matches) {
    std::vector<SymbolRecord> out{};
    std::map<std::string, std::size_t> key_to_idx{};
    for (const SymbolRecord* ptr : matches) {
        if (ptr == nullptr) continue;
        const std::string key =
            (ptr->virtual_address.has_value() && *ptr->virtual_address != 0u)
                ? std::format("va:{:X}", *ptr->virtual_address)
                : std::format("sym:{}", !ptr->raw_name.empty() ? ptr->raw_name : ptr->name);
        const auto it = key_to_idx.find(key);
        if (it == key_to_idx.end()) {
            key_to_idx.emplace(key, out.size());
            out.push_back(enrich_symbol_display(*ptr));
        } else {
            SymbolRecord& existing = out[it->second];
            if (score_symbol_record(image, *ptr) > score_symbol_record(image, existing)) {
                SymbolRecord best = enrich_symbol_display(*ptr);
                if (best.size == 0u && existing.size > 0u) best.size = existing.size;
                existing = std::move(best);
            } else if (existing.size == 0u && ptr->size > 0u) {
                existing.size = ptr->size;
            }
        }
    }
    return out;
}

[[nodiscard]] bool address_in_executable_region(
    const peelf::IBinaryImage& image,
    std::uint64_t file_offset) noexcept {
    for (const auto& sec : image.sections()) {
        if (sec.executable && file_offset >= sec.file_offset &&
            (file_offset - sec.file_offset) < sec.file_size) {
            return true;
        }
    }
    for (const auto& seg : image.segments()) {
        if (seg.executable && file_offset >= seg.file_offset &&
            (file_offset - seg.file_offset) < seg.file_size) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string format_ambiguous_candidates(
    std::string_view query,
    const std::vector<SymbolRecord>& candidates) {
    std::string msg = std::format("Ambiguous --symbol '{}' matches {} functions: ",
                                  query,
                                  candidates.size());
    const std::size_t limit = std::min<std::size_t>(candidates.size(), 6u);
    for (std::size_t i = 0u; i < limit; ++i) {
        if (i > 0u) msg += ", ";
        const SymbolRecord& c = candidates[i];
        if (c.virtual_address.has_value()) {
            msg += std::format("'{}' (0x{:X})", c.display_name(true), *c.virtual_address);
        } else {
            msg += std::format("'{}'", c.display_name(true));
        }
    }
    if (candidates.size() > limit) {
        msg += ", ...";
    }
    return msg;
}
[[nodiscard]] peelf::Result<SymbolRecord> resolve_headless_graph_symbol(
    const peelf::IBinaryImage& image,
    const SymbolIndex& symbol_index,
    std::string_view query,
    bool require_code,
    const std::filesystem::path& binary_path) {
    if (query.empty()) {
        return peelf::make_error("--symbol must not be empty");
    }

    if (query.starts_with("0x") || query.starts_with("0X")) {
        const std::string_view hex_digits = query.substr(2u);
        std::uint64_t va = 0u;
        const auto [ptr, ec] =
            std::from_chars(hex_digits.data(), hex_digits.data() + hex_digits.size(), va, 16);
        if (hex_digits.empty() || ec != std::errc{} || ptr != hex_digits.data() + hex_digits.size()) {
            return peelf::make_error(std::format("Invalid hex address for --symbol: '{}'", query));
        }
        std::vector<const SymbolRecord*> exact_va{};
        for (const SymbolRecord& rec : symbol_index.records()) {
            if (rec.virtual_address.has_value() && *rec.virtual_address == va) {
                exact_va.push_back(&rec);
            }
        }
        if (!exact_va.empty()) {
            auto dedup = deduplicate_candidates_by_va(image, exact_va);
            return dedup.front();
        }
        if (const SymbolRecord* containing = symbol_index.find_containing_address(va)) {
            if (containing->virtual_address.has_value() && *containing->virtual_address == va) {
                return enrich_symbol_display(*containing);
            }
        }
        if (const auto mapped = image.virtual_address_to_file_offset(va);
            mapped.has_value() && address_in_executable_region(image, *mapped)) {
            const std::string synth_name = std::format("sub_{:X}", va);
            return SymbolRecord{
                .name = synth_name,
                .raw_name = synth_name,
                .demangled_name = {},
                .source = SymbolSource::ImageSymbol,
                .source_index = 0u,
                .virtual_address = va,
                .file_offset = *mapped,
                .size = 0u,
                .function = true,
            };
        }
        if (const SymbolRecord* containing = symbol_index.find_containing_address(va)) {
            return enrich_symbol_display(*containing);
        }
        return peelf::make_error(std::format(
            "Address 0x{:X} does not map to a symbol or executable region in '{}'",
            va,
            binary_path.string()));
    }

    const auto filter_preferred = [&](const std::vector<const SymbolRecord*>& raw) {
        std::vector<const SymbolRecord*> code_only{};
        for (const SymbolRecord* r : raw) {
            if (r != nullptr && symbol_has_code(image, *r)) {
                code_only.push_back(r);
            }
        }
        if (!code_only.empty()) {
            return deduplicate_candidates_by_va(image, code_only);
        }
        if (require_code) {
            return std::vector<SymbolRecord>{};
        }
        return deduplicate_candidates_by_va(image, raw);
    };

    {
        std::vector<const SymbolRecord*> exact{};
        for (const SymbolRecord& rec : symbol_index.records()) {
            const std::string_view raw = !rec.raw_name.empty() ? std::string_view{rec.raw_name}
                                                               : std::string_view{rec.name};
            const std::string demangled = !rec.demangled_name.empty()
                                              ? rec.demangled_name
                                              : peelf::demangle_symbol(raw).demangled;
            if (rec.name == query || rec.raw_name == query ||
                strip_elf_symbol_version(rec.name) == query ||
                strip_elf_symbol_version(raw) == query ||
                (!demangled.empty() && demangled == query)) {
                exact.push_back(&rec);
            }
        }
        auto preferred = filter_preferred(exact);
        if (preferred.size() == 1u) {
            return preferred.front();
        }
        if (preferred.size() > 1u) {
            std::ranges::sort(preferred, [&](const SymbolRecord& a, const SymbolRecord& b) {
                return score_symbol_record(image, a) > score_symbol_record(image, b);
            });
            return preferred.front();
        }
        if (!exact.empty() && require_code) {
            return peelf::make_error(std::format(
                "Symbol '{}' in '{}' is an external/non-code symbol without a function body",
                query,
                binary_path.string()));
        }
    }

    {
        std::vector<const SymbolRecord*> base_matches{};
        for (const SymbolRecord& rec : symbol_index.records()) {
            const std::string_view raw = !rec.raw_name.empty() ? std::string_view{rec.raw_name}
                                                               : std::string_view{rec.name};
            const std::string demangled = !rec.demangled_name.empty()
                                              ? rec.demangled_name
                                              : peelf::demangle_symbol(raw).demangled;
            const std::string_view target_str =
                !demangled.empty() ? std::string_view{demangled} : std::string_view{rec.name};
            const DemangledNameParts parts = split_demangled_function_parts(target_str);
            if (parts.qualified == query || parts.unqualified == query) {
                base_matches.push_back(&rec);
            }
        }
        auto preferred = filter_preferred(base_matches);
        if (preferred.size() == 1u) {
            return preferred.front();
        }
        if (preferred.size() > 1u) {
            return peelf::make_error(format_ambiguous_candidates(query, preferred));
        }
    }

    {
        std::vector<const SymbolRecord*> sub_matches{};
        for (const SymbolRecord& rec : symbol_index.records()) {
            const std::string_view raw = !rec.raw_name.empty() ? std::string_view{rec.raw_name}
                                                               : std::string_view{rec.name};
            const std::string demangled = !rec.demangled_name.empty()
                                              ? rec.demangled_name
                                              : peelf::demangle_symbol(raw).demangled;
            if (symbol_name_matches(rec.name, query) ||
                (!rec.raw_name.empty() && symbol_name_matches(rec.raw_name, query)) ||
                (!demangled.empty() && symbol_name_matches(demangled, query))) {
                sub_matches.push_back(&rec);
            }
        }
        auto preferred = filter_preferred(sub_matches);
        if (preferred.size() == 1u) {
            return preferred.front();
        }
        if (preferred.size() > 1u) {
            return peelf::make_error(format_ambiguous_candidates(query, preferred));
        }
    }

    return peelf::make_error(std::format(
        "Symbol '{}' not found in '{}'", query, binary_path.string()));
}

void hydrate_symbol_index_with_debug_info(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const std::filesystem::path& binary_path,
    SymbolIndex& symbol_index) {
    if (image.format() == peelf::Format::ELF) {
        DebugSymbolLoadResult dwarf =
            load_dwarf_debug_symbols_from_image(image, raw_bytes, image, binary_path.string());
        if (dwarf.status != DebugSymbolLoadStatus::Loaded) {
            if (const auto ext_dbg = find_local_elf_debug_file(image, binary_path)) {
                dwarf = load_dwarf_debug_symbols(*ext_dbg, image);
            }
        }
        if (dwarf.status == DebugSymbolLoadStatus::Loaded && !dwarf.symbols.empty()) {
            symbol_index.add_debug_symbols(image, dwarf.symbols);
        }
    } else if (image.format() == peelf::Format::PE) {
        if (const auto pdb = find_local_codeview_pdb(image, binary_path)) {
            const DebugSymbolLoadResult dbg = load_pdb_debug_symbols(*pdb, image);
            if (dbg.status == DebugSymbolLoadStatus::Loaded && !dbg.symbols.empty()) {
                symbol_index.add_debug_symbols(image, dbg.symbols);
            }
        }
    }
}

[[nodiscard]] std::string canonical_node_key(const CallGraphNode& node) {
    if (node.symbol.has_value() && !node.symbol->name.empty() &&
        (node.kind == CallGraphNodeKind::External || node.kind == CallGraphNodeKind::Import)) {
        return "ext:" + std::string(strip_elf_symbol_version(node.symbol->name));
    }
    if (node.bytes.start.virtual_address.has_value() && *node.bytes.start.virtual_address != 0u) {
        return std::format("va:{:X}", *node.bytes.start.virtual_address);
    }
    if (node.symbol.has_value() && !node.symbol->name.empty()) {
        return "sym:" + node.symbol->name;
    }
    return "lbl:" + node.label;
}

[[nodiscard]] CallGraphNode make_symbol_graph_node(
    const SymbolRecord& sym,
    std::string id) {
    const SymbolRecord enriched = enrich_symbol_display(sym);
    const bool external = enriched.external || enriched.source == SymbolSource::Import;
    return CallGraphNode{
        .id = std::move(id),
        .label = enriched.display_name(true),
        .kind = external ? CallGraphNodeKind::Import : CallGraphNodeKind::Function,
        .bytes = GraphByteRange{
            .start = GraphAddress{
                .virtual_address = enriched.virtual_address,
                .file_offset = enriched.file_offset,
            },
            .size = enriched.size,
        },
        .symbol = GraphSymbolRef{
            .name = !enriched.raw_name.empty() ? enriched.raw_name : enriched.name,
            .demangled_name = enriched.demangled_name,
            .symbol_index = enriched.source_index,
            .dynamic = enriched.dynamic,
        },
    };
}

void add_unique_edge(CallGraph& graph, CallGraphEdge edge) {
    const bool exists = std::ranges::any_of(graph.edges, [&](const CallGraphEdge& e) {
        return e.from_node_id == edge.from_node_id &&
               e.to_node_id == edge.to_node_id &&
               e.kind == edge.kind &&
               e.label == edge.label;
    });
    if (!exists) {
        graph.edges.push_back(std::move(edge));
    }
}

void trim_graph_to_max_nodes(CallGraph& graph, std::size_t max_nodes) {
    if (graph.nodes.size() <= max_nodes) {
        return;
    }
    graph.nodes.resize(max_nodes);
    std::set<std::string> keep{};
    for (const CallGraphNode& n : graph.nodes) {
        keep.insert(n.id);
    }
    std::erase_if(graph.edges, [&](const CallGraphEdge& e) {
        return !keep.contains(e.from_node_id) || !keep.contains(e.to_node_id);
    });
}
void expand_callees_bfs(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const SymbolIndex& symbol_index,
    CallGraph& graph,
    std::map<std::string, std::string>& key_to_node_id,
    std::deque<std::tuple<std::string, SymbolRecord, std::size_t>>& queue,
    std::size_t max_depth,
    std::size_t max_nodes) {
    std::set<std::string> expanded_node_ids{};
    std::size_t next_id = 0u;

    while (!queue.empty()) {
        auto [from_id, cur_sym, cur_depth] = std::move(queue.front());
        queue.pop_front();
        if (cur_depth >= max_depth || !expanded_node_ids.insert(from_id).second) {
            continue;
        }
        if (!symbol_has_code(image, cur_sym)) {
            continue;
        }

        const CallGraph step =
            build_symbol_fanout_call_graph(image, raw_bytes, symbol_index, cur_sym);
        std::map<std::string, const CallGraphNode*> step_nodes{};
        for (const CallGraphNode& n : step.nodes) {
            step_nodes.emplace(n.id, &n);
        }

        for (const CallGraphEdge& e : step.edges) {
            if (e.from_node_id != "root" || e.to_node_id == "no_calls") {
                continue;
            }
            const auto nit = step_nodes.find(e.to_node_id);
            if (nit == step_nodes.end()) {
                continue;
            }
            CallGraphNode cand = *nit->second;
            if (cand.symbol.has_value() && !cand.symbol->demangled_name.empty()) {
                cand.label = cand.symbol->demangled_name;
            } else if (cand.symbol.has_value() && !cand.symbol->name.empty()) {
                const std::string dem = peelf::demangle_symbol(cand.symbol->name).demangled;
                if (!dem.empty()) {
                    cand.symbol->demangled_name = dem;
                    cand.label = dem;
                }
            }

            const std::string key = canonical_node_key(cand);
            std::string target_id{};
            if (const auto kit = key_to_node_id.find(key); kit != key_to_node_id.end()) {
                target_id = kit->second;
            } else {
                if (graph.nodes.size() >= max_nodes) {
                    continue;
                }
                target_id = std::format("fn_{}", next_id++);
                cand.id = target_id;
                key_to_node_id.emplace(key, target_id);
                graph.nodes.push_back(std::move(cand));
            }

            add_unique_edge(graph, CallGraphEdge{
                .from_node_id = from_id,
                .to_node_id = target_id,
                .kind = e.kind,
                .label = e.label,
            });

            if ((cur_depth + 1u) < max_depth) {
                const CallGraphNode& placed = *std::ranges::find_if(
                    graph.nodes, [&](const CallGraphNode& n) { return n.id == target_id; });
                if (placed.bytes.start.virtual_address.has_value()) {
                    const std::uint64_t callee_va = *placed.bytes.start.virtual_address;
                    std::vector<const SymbolRecord*> va_recs{};
                    for (const SymbolRecord& r : symbol_index.records()) {
                        if (r.virtual_address.has_value() && *r.virtual_address == callee_va &&
                            symbol_has_code(image, r)) {
                            va_recs.push_back(&r);
                        }
                    }
                    auto best = deduplicate_candidates_by_va(image, va_recs);
                    if (!best.empty()) {
                        queue.emplace_back(target_id, std::move(best.front()), cur_depth + 1u);
                    }
                }
            }
        }
    }
}

[[nodiscard]] std::optional<std::filesystem::path> find_executable_in_path(
    std::string_view exe_name) {
    if (exe_name.empty()) {
        return std::nullopt;
    }
    const std::filesystem::path direct(exe_name);
    std::error_code ec{};
    if (direct.has_parent_path() || direct.is_absolute()) {
        if (std::filesystem::is_regular_file(direct, ec) && !ec) {
            return direct;
        }
        return std::nullopt;
    }

    const char* raw_path = std::getenv("PATH");
    if (raw_path != nullptr && *raw_path != '\0') {
#ifdef _WIN32
        constexpr char kPathSep = ';';
#else
        constexpr char kPathSep = ':';
#endif
        std::string_view rem(raw_path);
        while (!rem.empty()) {
            const std::size_t pos = rem.find(kPathSep);
            const std::string_view dir =
                (pos == std::string_view::npos) ? rem : rem.substr(0u, pos);
            if (!dir.empty()) {
                std::filesystem::path cand = std::filesystem::path(dir) / direct;
                if (std::filesystem::is_regular_file(cand, ec) && !ec) {
                    return cand;
                }
#ifdef _WIN32
                if (!cand.has_extension()) {
                    std::filesystem::path cand_exe = cand;
                    cand_exe += ".exe";
                    if (std::filesystem::is_regular_file(cand_exe, ec) && !ec) {
                        return cand_exe;
                    }
                }
#endif
            }
            if (pos == std::string_view::npos) {
                break;
            }
            rem.remove_prefix(pos + 1u);
        }
    }

#if defined(PEELF_GRAPHVIZ_DOT_AVAILABLE) && PEELF_GRAPHVIZ_DOT_AVAILABLE
    const std::filesystem::path baked(PEELF_GRAPHVIZ_DOT_EXECUTABLE);
    if (std::filesystem::is_regular_file(baked, ec) && !ec) {
        return baked;
    }
#endif
    return std::nullopt;
}

class HeadlessDotProcessRunner final : public IProcessRunner {
public:
    explicit HeadlessDotProcessRunner(std::filesystem::path resolved_dot)
        : resolved_dot_(std::move(resolved_dot)) {}

    [[nodiscard]] GraphRenderResult run(
        std::string_view /*executable*/,
        std::span<const std::string> arguments) const override {
        peelf::SubprocessOptions opts{};
        opts.timeout = std::chrono::milliseconds{30000};
        opts.search_path = false;
        const peelf::SubprocessResult sub =
            peelf::run_subprocess_bounded(resolved_dot_, arguments, opts);
        if (sub.timed_out) {
            return GraphRenderResult{
                .success = false,
                .exit_code = -1,
                .diagnostic = "Graphviz 'dot' timed out",
            };
        }
        if (!sub.launched) {
            return GraphRenderResult{
                .success = false,
                .exit_code = -1,
                .diagnostic = sub.launch_error.empty()
                                  ? "Failed to launch Graphviz 'dot'"
                                  : sub.launch_error,
            };
        }
        if (sub.exit_code != 0) {
            std::string diag = sub.stderr_text;
            while (!diag.empty() && (diag.back() == '\n' || diag.back() == '\r')) {
                diag.pop_back();
            }
            return GraphRenderResult{
                .success = false,
                .exit_code = static_cast<std::int32_t>(sub.exit_code),
                .diagnostic = diag.empty() ? "Graphviz 'dot' exited with error" : std::move(diag),
            };
        }
        return GraphRenderResult{.success = true, .exit_code = 0, .diagnostic = {}};
    }

private:
    std::filesystem::path resolved_dot_{};
};

} // namespace

HeadlessGraphFormat resolve_headless_graph_format(const HeadlessOptions& options) noexcept {
    if (options.graph_format.has_value()) {
        return *options.graph_format;
    }
    if (options.output_path.has_value()) {
        std::string ext = lower_ascii(options.output_path->extension().string());
        if (ext == ".dot" || ext == ".gv") return HeadlessGraphFormat::Dot;
        if (ext == ".svg") return HeadlessGraphFormat::Svg;
        if (ext == ".png") return HeadlessGraphFormat::Png;
        if (ext == ".json") return HeadlessGraphFormat::Json;
        return HeadlessGraphFormat::Svg;
    }
    return HeadlessGraphFormat::Dot;
}
peelf::Result<HeadlessGraphRunReport> build_headless_graph(const HeadlessOptions& options) {
    if (options.binary_path.empty()) {
        return peelf::make_error("No input binary path specified for --graph");
    }
    if (options.graph_depth == 0u) {
        return peelf::make_error("--graph-depth must be at least 1");
    }
    if (options.graph_max_nodes == 0u) {
        return peelf::make_error("--graph-max-nodes must be at least 1");
    }
    if ((options.graph_kind == HeadlessGraphKind::Fanout ||
         options.graph_kind == HeadlessGraphKind::Cfg) &&
        (!options.symbol.has_value() || options.symbol->empty())) {
        return peelf::make_error(std::format(
            "--symbol <name-or-va> is required for --graph {}",
            to_string(options.graph_kind)));
    }

    auto raw_bytes = read_binary_file(options.binary_path);
    if (!raw_bytes.has_value()) {
        return std::unexpected(raw_bytes.error());
    }
    auto open_opts = parse_slice_selector_options(options.slice_selector);
    if (!open_opts.has_value()) {
        return std::unexpected(open_opts.error());
    }
    auto parsed_image = peelf::open_binary_image(*raw_bytes, *open_opts);
    if (!parsed_image.has_value()) {
        return peelf::make_error(std::format(
            "Failed to parse '{}': {}",
            options.binary_path.string(),
            parsed_image.error().message));
    }
    const peelf::IBinaryImage& image = **parsed_image;

    SymbolIndex symbol_index = SymbolIndex::build(image);
    hydrate_symbol_index_with_debug_info(image, *raw_bytes, options.binary_path, symbol_index);

    HeadlessGraphRunReport report{};
    report.kind = options.graph_kind;

    if (options.graph_kind == HeadlessGraphKind::Entry) {
        CallGraph graph = build_entry_call_graph(image, symbol_index);
        report.root = detail::format_hex(image.entry_point());
        for (const CallGraphNode& n : graph.nodes) {
            if (n.id == "user_entry" || n.id == "entry_symbol") {
                report.root = n.label.empty() ? n.id : n.label;
                if (n.id == "user_entry") break;
            }
        }

        if (options.graph_depth > 1u && graph.nodes.size() < options.graph_max_nodes) {
            std::map<std::string, std::string> key_to_id{};
            std::deque<std::tuple<std::string, SymbolRecord, std::size_t>> queue{};
            for (const CallGraphNode& n : graph.nodes) {
                key_to_id.emplace(canonical_node_key(n), n.id);
            }
            for (const CallGraphNode& n : graph.nodes) {
                if ((n.id == "user_entry" || n.id == "entry_symbol") &&
                    n.bytes.start.virtual_address.has_value()) {
                    const std::uint64_t va = *n.bytes.start.virtual_address;
                    std::vector<const SymbolRecord*> recs{};
                    for (const SymbolRecord& r : symbol_index.records()) {
                        if (r.virtual_address.has_value() && *r.virtual_address == va &&
                            symbol_has_code(image, r)) {
                            recs.push_back(&r);
                        }
                    }
                    auto best = deduplicate_candidates_by_va(image, recs);
                    if (!best.empty()) {
                        queue.emplace_back(n.id, std::move(best.front()), 0u);
                    }
                }
            }
            expand_callees_bfs(
                image,
                *raw_bytes,
                symbol_index,
                graph,
                key_to_id,
                queue,
                options.graph_depth,
                options.graph_max_nodes);
        }
        trim_graph_to_max_nodes(graph, options.graph_max_nodes);
        report.graph = std::move(graph);
        return report;
    }

    if (options.graph_kind == HeadlessGraphKind::Fanout) {
        auto root_sym = resolve_headless_graph_symbol(
            image, symbol_index, *options.symbol, false, options.binary_path);
        if (!root_sym.has_value()) {
            return std::unexpected(root_sym.error());
        }
        const std::string root_label = root_sym->display_name(true);
        report.root = root_label;

        CallGraph graph{};
        graph.id = "symbol_fanout";
        graph.label = root_label + " fan-out";
        graph.architecture = image.architecture();
        graph.endianness = image.endianness();

        CallGraphNode root_node = make_symbol_graph_node(*root_sym, "root");
        std::map<std::string, std::string> key_to_id{};
        key_to_id.emplace(canonical_node_key(root_node), "root");
        graph.nodes.push_back(std::move(root_node));

        if (root_sym->virtual_address.has_value() && graph.nodes.size() < options.graph_max_nodes) {
            const std::uint64_t target_va = *root_sym->virtual_address;
            std::vector<const SymbolRecord*> code_ptrs{};
            code_ptrs.reserve(symbol_index.records().size());
            for (const SymbolRecord& r : symbol_index.records()) {
                if (r.virtual_address.has_value() && *r.virtual_address != target_va &&
                    symbol_has_code(image, r) && r.size <= 32768u) {
                    code_ptrs.push_back(&r);
                }
            }
            auto candidates = deduplicate_candidates_by_va(image, code_ptrs);
            std::ranges::sort(candidates, [&](const SymbolRecord& a, const SymbolRecord& b) {
                const std::uint64_t va_a = a.virtual_address.value_or(0u);
                const std::uint64_t va_b = b.virtual_address.value_or(0u);
                const std::uint64_t da = (va_a > target_va) ? (va_a - target_va) : (target_va - va_a);
                const std::uint64_t db = (va_b > target_va) ? (va_b - target_va) : (target_va - va_b);
                return da < db;
            });
            const std::size_t max_scan = std::min<std::size_t>(candidates.size(), 256u);
            std::size_t caller_idx = 0u;
            for (std::size_t i = 0u; i < max_scan && graph.nodes.size() < options.graph_max_nodes; ++i) {
                const SymbolRecord& cand = candidates[i];
                const CallGraph cand_fanout =
                    build_symbol_fanout_call_graph(image, *raw_bytes, symbol_index, cand);
                bool calls_root = false;
                for (const CallGraphNode& n : cand_fanout.nodes) {
                    if (n.id != "root" && n.bytes.start.virtual_address.has_value() &&
                        *n.bytes.start.virtual_address == target_va) {
                        calls_root = true;
                        break;
                    }
                }
                if (calls_root) {
                    CallGraphNode caller_node =
                        make_symbol_graph_node(cand, std::format("caller_{}", caller_idx++));
                    const std::string ckey = canonical_node_key(caller_node);
                    std::string cid{};
                    if (const auto it = key_to_id.find(ckey); it != key_to_id.end()) {
                        cid = it->second;
                    } else {
                        cid = caller_node.id;
                        key_to_id.emplace(ckey, cid);
                        graph.nodes.push_back(std::move(caller_node));
                    }
                    add_unique_edge(graph, CallGraphEdge{
                        .from_node_id = cid,
                        .to_node_id = "root",
                        .kind = CallGraphEdgeKind::Call,
                        .label = "caller",
                    });
                }
            }
        }

        std::deque<std::tuple<std::string, SymbolRecord, std::size_t>> queue{};
        queue.emplace_back("root", *root_sym, 0u);
        expand_callees_bfs(
            image,
            *raw_bytes,
            symbol_index,
            graph,
            key_to_id,
            queue,
            options.graph_depth,
            options.graph_max_nodes);

        trim_graph_to_max_nodes(graph, options.graph_max_nodes);
        report.graph = std::move(graph);
        return report;
    }

    auto root_sym = resolve_headless_graph_symbol(
        image, symbol_index, *options.symbol, true, options.binary_path);
    if (!root_sym.has_value()) {
        return std::unexpected(root_sym.error());
    }
    const std::string root_label = root_sym->display_name(true);
    report.root = root_label;

    const auto extent =
        discover_function_extent(image, symbol_index, *root_sym, raw_bytes->size(), 65536u);
    if (!extent.has_value() || extent->size == 0u ||
        extent->file_offset >= raw_bytes->size()) {
        return peelf::make_error(std::format(
            "Unable to discover mapped executable bytes for symbol '{}' in '{}'",
            root_label,
            options.binary_path.string()));
    }

    const std::size_t slice_len = std::min<std::size_t>(
        static_cast<std::size_t>(extent->size),
        raw_bytes->size() - static_cast<std::size_t>(extent->file_offset));
    const std::span<const std::uint8_t> fn_bytes(
        raw_bytes->data() + static_cast<std::ptrdiff_t>(extent->file_offset),
        slice_len);

    const GraphByteReader va_reader = [&](std::uint64_t va, std::size_t size) {
        const auto off = image.virtual_address_to_file_offset(va);
        if (!off.has_value() || *off >= raw_bytes->size() || size == 0u) {
            return std::vector<std::uint8_t>{};
        }
        const std::size_t avail = std::min<std::size_t>(
            size, raw_bytes->size() - static_cast<std::size_t>(*off));
        return std::vector<std::uint8_t>(
            raw_bytes->begin() + static_cast<std::ptrdiff_t>(*off),
            raw_bytes->begin() + static_cast<std::ptrdiff_t>(*off + avail));
    };

    const bool thumb = image.architecture() == peelf::Architecture::ARM &&
                       root_sym->virtual_address.has_value() &&
                       ((*root_sym->virtual_address & 1ULL) != 0ULL);

    CallGraph cfg = build_function_cfg_call_graph(
        fn_bytes,
        extent->virtual_address,
        image.architecture(),
        image.endianness(),
        extent->file_offset,
        root_label,
        thumb,
        false,
        va_reader);

    trim_graph_to_max_nodes(cfg, options.graph_max_nodes);

    std::map<std::string, std::string> callee_key_to_id{};
    std::vector<CallGraphNode> extra_callees{};
    std::size_t callee_counter = 0u;

    for (CallGraphNode& bb : cfg.nodes) {
        if (bb.kind != CallGraphNodeKind::BasicBlock) {
            continue;
        }
        for (GraphInstruction& ins : bb.instructions) {
            const bool is_call =
                ins.mnemonic == "call" || ins.mnemonic == "bl" ||
                ins.mnemonic == "blx" || ins.mnemonic == "jal" || ins.mnemonic == "bal";
            if (!is_call || !ins.branch_target.has_value()) {
                continue;
            }
            const SymbolRecord* target_sym = resolve_call_target_for_address(
                image, *raw_bytes, symbol_index, *ins.branch_target);
            if (target_sym == nullptr) {
                continue;
            }
            const SymbolRecord enriched = enrich_symbol_display(*target_sym);
            const std::string sym_disp = enriched.display_name(true);
            if (!sym_disp.empty()) {
                ins.operands += " ; " + sym_disp;
            }
            CallGraphNode callee_node =
                make_symbol_graph_node(enriched, std::format("call_{}", callee_counter));
            const std::string ckey = canonical_node_key(callee_node);
            std::string cid{};
            if (const auto it = callee_key_to_id.find(ckey); it != callee_key_to_id.end()) {
                cid = it->second;
            } else if ((cfg.nodes.size() + extra_callees.size()) < options.graph_max_nodes) {
                cid = std::format("call_{}", callee_counter++);
                callee_node.id = cid;
                callee_key_to_id.emplace(ckey, cid);
                extra_callees.push_back(std::move(callee_node));
            }
            if (!cid.empty()) {
                add_unique_edge(cfg, CallGraphEdge{
                    .from_node_id = bb.id,
                    .to_node_id = cid,
                    .kind = CallGraphEdgeKind::Call,
                    .label = "call",
                });
            }
        }
    }
    for (CallGraphNode& c : extra_callees) {
        cfg.nodes.push_back(std::move(c));
    }

    report.graph = std::move(cfg);
    return report;
}
std::string format_headless_graph_json(
    HeadlessGraphKind kind,
    std::string_view root,
    const CallGraph& graph) {
    std::string out{};
    out.reserve(1024u + graph.nodes.size() * 256u + graph.edges.size() * 128u);

    auto key = [&out](std::string_view k) {
        append_json_escaped(out, k);
        out += ": ";
    };

    out += "{\n";
    out += "  "; key("kind"); append_json_escaped(out, to_string(kind)); out += ",\n";
    out += "  "; key("root"); append_json_escaped(out, root); out += ",\n";
    out += "  "; key("graph_id"); append_json_escaped(out, graph.id); out += ",\n";
    out += "  "; key("label"); append_json_escaped(out, graph.label); out += ",\n";
    out += "  "; key("architecture"); append_json_escaped(out, peelf::to_string(graph.architecture)); out += ",\n";

    out += "  \"nodes\": [";
    for (std::size_t i = 0u; i < graph.nodes.size(); ++i) {
        const CallGraphNode& node = graph.nodes[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    {\n";
        out += "      "; key("id"); append_json_escaped(out, node.id); out += ",\n";
        out += "      "; key("label"); append_json_escaped(out, node.label); out += ",\n";
        out += "      "; key("kind"); append_json_escaped(out, node_kind_json_name(node.kind)); out += ",\n";
        out += "      "; key("virtual_address");
        if (node.bytes.start.virtual_address.has_value()) {
            append_json_escaped(out, detail::format_hex(*node.bytes.start.virtual_address));
        } else {
            out += "null";
        }
        out += ",\n";
        out += "      "; key("file_offset");
        if (node.bytes.start.file_offset.has_value()) {
            append_json_escaped(out, detail::format_hex(*node.bytes.start.file_offset));
        } else {
            out += "null";
        }
        out += ",\n";
        out += std::format("      \"size\": {},\n", node.bytes.size);
        out += "      "; key("symbol");
        if (node.symbol.has_value() && !node.symbol->name.empty()) {
            append_json_escaped(out, node.symbol->name);
        } else {
            out += "null";
        }
        out += ",\n";
        out += std::format("      \"instruction_count\": {},\n", node.instruction_count);
        out += "      \"instructions\": [";
        for (std::size_t j = 0u; j < node.instructions.size(); ++j) {
            const GraphInstruction& ins = node.instructions[j];
            out += (j == 0u) ? "\n" : ",\n";
            out += "        { ";
            key("address"); append_json_escaped(out, detail::format_hex(ins.address)); out += ", ";
            key("mnemonic"); append_json_escaped(out, ins.mnemonic); out += ", ";
            key("operands"); append_json_escaped(out, ins.operands); out += ", ";
            key("branch_target");
            if (ins.branch_target.has_value()) {
                append_json_escaped(out, detail::format_hex(*ins.branch_target));
            } else {
                out += "null";
            }
            out += " }";
        }
        if (!node.instructions.empty()) {
            out += "\n      ";
        }
        out += "]\n";
        out += "    }";
    }
    if (!graph.nodes.empty()) {
        out += "\n  ";
    }
    out += "],\n";

    out += "  \"edges\": [";
    for (std::size_t i = 0u; i < graph.edges.size(); ++i) {
        const CallGraphEdge& edge = graph.edges[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("from"); append_json_escaped(out, edge.from_node_id); out += ", ";
        key("to"); append_json_escaped(out, edge.to_node_id); out += ", ";
        key("kind"); append_json_escaped(out, edge_kind_json_name(edge.kind)); out += ", ";
        key("label"); append_json_escaped(out, edge.label);
        out += " }";
    }
    if (!graph.edges.empty()) {
        out += "\n  ";
    }
    out += "]\n";
    out += "}\n";
    return out;
}

peelf::Result<void> export_headless_graph(
    const HeadlessOptions& options,
    std::ostream& stdout_stream,
    const IProcessRunner* runner_override) {
    const HeadlessGraphFormat fmt = resolve_headless_graph_format(options);

    std::optional<HeadlessDotProcessRunner> default_dot_runner{};
    const IProcessRunner* active_runner = runner_override;
    if ((fmt == HeadlessGraphFormat::Svg || fmt == HeadlessGraphFormat::Png) &&
        active_runner == nullptr) {
        const char* env_dot = std::getenv("PEELF_DOT_EXECUTABLE");
        const std::string_view dot_query =
            (env_dot != nullptr && *env_dot != '\0') ? std::string_view{env_dot}
                                                     : std::string_view{"dot"};
        auto resolved_dot = find_executable_in_path(dot_query);
        if (!resolved_dot.has_value()) {
            return peelf::make_error(std::format(
                "Graphviz 'dot' executable ('{}') is not available; install Graphviz or use --graph-format dot|json",
                dot_query));
        }
        default_dot_runner.emplace(std::move(*resolved_dot));
        active_runner = &*default_dot_runner;
    }

    auto built = build_headless_graph(options);
    if (!built.has_value()) {
        return std::unexpected(built.error());
    }

    if (fmt == HeadlessGraphFormat::Dot || fmt == HeadlessGraphFormat::Json) {
        const std::string payload =
            (fmt == HeadlessGraphFormat::Dot)
                ? to_dot(built->graph)
                : format_headless_graph_json(built->kind, built->root, built->graph);
        if (options.output_path.has_value()) {
            return write_text_file_atomically(*options.output_path, payload);
        }
        stdout_stream << payload;
        stdout_stream.flush();
        return {};
    }

    const GraphRenderFormat gv_fmt =
        (fmt == HeadlessGraphFormat::Png) ? GraphRenderFormat::Png : GraphRenderFormat::Svg;

    std::error_code fs_ec{};
    const bool stream_to_stdout = !options.output_path.has_value();
    std::filesystem::path target_path{};
    if (options.output_path.has_value()) {
        target_path = *options.output_path;
        const std::filesystem::path parent = target_path.parent_path();
        if (!parent.empty()) {
            std::filesystem::create_directories(parent, fs_ec);
            if (fs_ec) {
                return peelf::make_error(std::format(
                    "Failed to create parent directory '{}': {}",
                    parent.string(),
                    fs_ec.message()));
            }
        }
    } else {
        static std::atomic<std::uint64_t> seq{0u};
        const std::filesystem::path cwd = std::filesystem::current_path(fs_ec);
        if (fs_ec) {
            return peelf::make_error("Failed to determine working directory for Graphviz output");
        }
        target_path = cwd / std::format(
            ".peelf_graph_{}_{}.{}",
            std::chrono::steady_clock::now().time_since_epoch().count(),
            seq.fetch_add(1u, std::memory_order_relaxed) + 1u,
            to_string(fmt));
    }

    const std::filesystem::path sidecar_dot = target_path.string() + ".dot";
    const GraphRenderResult rendered =
        render_graph_with_graphviz(built->graph, target_path, gv_fmt, *active_runner);
    std::filesystem::remove(sidecar_dot, fs_ec);

    if (!rendered.success) {
        if (stream_to_stdout) {
            std::filesystem::remove(target_path, fs_ec);
        }
        return peelf::make_error(std::format(
            "Graphviz '{}' rendering failed: {}",
            to_string(fmt),
            rendered.diagnostic.empty() ? "unknown error" : rendered.diagnostic));
    }

    if (stream_to_stdout) {
        auto rendered_bytes = read_binary_file(target_path);
        std::filesystem::remove(target_path, fs_ec);
        if (!rendered_bytes.has_value()) {
            return std::unexpected(rendered_bytes.error());
        }
        stdout_stream.write(
            reinterpret_cast<const char*>(rendered_bytes->data()),
            static_cast<std::streamsize>(rendered_bytes->size()));
        stdout_stream.flush();
    }
    return {};
}

std::optional<int> try_run_headless_or_help_cli(
    std::span<const std::string_view> args,
    std::ostream& stdout_stream,
    std::ostream& stderr_stream) {
    bool headless = false;
    bool help = false;
    bool version = false;
    bool has_script_flag = false;
    bool has_graph_flag = false;

    for (const std::string_view arg : args) {
        if (arg == "--headless") {
            headless = true;
        } else if (arg == "--help" || arg == "-h") {
            help = true;
        } else if (arg == "--version" || arg == "-V") {
            version = true;
        } else if (arg == "--script" || arg.starts_with("--script=") ||
                   arg == "--script-allow-mutations" ||
                   arg.starts_with("--script-allow-mutations=") ||
                   arg == "--allow-modified-binary" ||
                   arg.starts_with("--allow-modified-binary=") ||
                   arg == "--output-binary" || arg.starts_with("--output-binary=") ||
                   arg == "--project" || arg.starts_with("--project=") ||
                   arg == "--script-max-instructions" || arg.starts_with("--script-max-instructions=") ||
                   arg == "--script-timeout-ms" || arg.starts_with("--script-timeout-ms=")) {
            has_script_flag = true;
        } else if (arg == "--graph" || arg.starts_with("--graph=") ||
                   arg == "--symbol" || arg.starts_with("--symbol=") ||
                   arg == "--function" || arg.starts_with("--function=") ||
                   arg == "--graph-depth" || arg.starts_with("--graph-depth=") ||
                   arg == "--graph-max-nodes" || arg.starts_with("--graph-max-nodes=") ||
                   arg == "--graph-format" || arg.starts_with("--graph-format=")) {
            has_graph_flag = true;
        }
    }

    if (help) {
        print_help_usage(stdout_stream);
        return 0;
    }

    if (version) {
        stdout_stream << "peelf_viewer " << PEELF_VERSION_STRING << '\n';
        stdout_stream.flush();
        return 0;
    }

    if (!headless) {
        if (has_script_flag) {
            stderr_stream << "Error: --script options require --headless\n";
            return 1;
        }
        if (has_graph_flag) {
            stderr_stream << "Error: --graph options require --headless\n";
            return 1;
        }
        return std::nullopt;
    }

    if (has_script_flag && has_graph_flag) {
        stderr_stream << "Error: --graph and --script options cannot be combined\n";
        return 1;
    }

    if (has_graph_flag) {
        HeadlessOptions gopts{};
        bool has_positional_binary = false;
        bool saw_graph_kind = false;

        for (std::size_t i = 0u; i < args.size(); ++i) {
            const std::string_view raw_arg = args[i];
            if (raw_arg == "--headless") {
                continue;
            }
            std::string_view flag = raw_arg;
            std::optional<std::string_view> inline_val{};
            if (raw_arg.starts_with("--")) {
                if (const std::size_t eq = raw_arg.find('='); eq != std::string_view::npos) {
                    flag = raw_arg.substr(0u, eq);
                    inline_val = raw_arg.substr(eq + 1u);
                }
            }

            auto require_next = [&](std::string_view name) -> std::optional<std::string_view> {
                if (inline_val.has_value()) {
                    return *inline_val;
                }
                if ((i + 1u) >= args.size()) {
                    stderr_stream << "Error: missing value after " << name << "\n";
                    return std::nullopt;
                }
                return args[++i];
            };

            if (flag == "--graph") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                auto parsed_kind = parse_headless_graph_kind(*val);
                if (!parsed_kind.has_value()) {
                    stderr_stream << "Error: unsupported --graph '" << *val
                                  << "' (expected entry, fanout, or cfg)\n";
                    return 1;
                }
                gopts.graph_kind = *parsed_kind;
                saw_graph_kind = true;
            } else if (flag == "--symbol" || flag == "--function") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                if (val->empty()) {
                    stderr_stream << "Error: " << flag << " requires a symbol name or hex VA\n";
                    return 1;
                }
                gopts.symbol = std::string(*val);
            } else if (flag == "--graph-depth") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                if (val->starts_with('-')) {
                    stderr_stream << "Error: invalid --graph-depth '" << *val
                                  << "' (expected positive integer)\n";
                    return 1;
                }
                std::size_t parsed = 0u;
                const auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), parsed);
                if (ec != std::errc{} || ptr != val->data() + val->size() || parsed == 0u || parsed > 64u) {
                    stderr_stream << "Error: invalid --graph-depth '" << *val
                                  << "' (expected integer in 1..64)\n";
                    return 1;
                }
                gopts.graph_depth = parsed;
            } else if (flag == "--graph-max-nodes") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                if (val->starts_with('-')) {
                    stderr_stream << "Error: invalid --graph-max-nodes '" << *val
                                  << "' (expected positive integer)\n";
                    return 1;
                }
                std::size_t parsed = 0u;
                const auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), parsed);
                if (ec != std::errc{} || ptr != val->data() + val->size() || parsed == 0u || parsed > 8192u) {
                    stderr_stream << "Error: invalid --graph-max-nodes '" << *val
                                  << "' (expected integer in 1..8192)\n";
                    return 1;
                }
                gopts.graph_max_nodes = parsed;
            } else if (flag == "--graph-format" || flag == "--format") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                auto parsed_fmt = parse_headless_graph_format(*val);
                if (!parsed_fmt.has_value()) {
                    stderr_stream << "Error: unsupported " << flag << " '" << *val
                                  << "' (expected dot, svg, png, or json)\n";
                    return 1;
                }
                gopts.graph_format = *parsed_fmt;
            } else if (flag == "--slice") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                if (val->empty()) {
                    stderr_stream << "Error: --slice requires a slice index or architecture name\n";
                    return 1;
                }
                gopts.slice_selector = std::string(*val);
            } else if (flag == "--output") {
                auto val = require_next(flag);
                if (!val.has_value()) return 1;
                if (val->empty()) {
                    stderr_stream << "Error: --output requires a file path\n";
                    return 1;
                }
                gopts.output_path = std::filesystem::path(*val);
            } else if (flag.starts_with('-')) {
                stderr_stream << "Error: unknown or incompatible --graph option '" << flag << "'\n";
                return 1;
            } else if (!has_positional_binary) {
                gopts.binary_path = std::filesystem::path(raw_arg);
                has_positional_binary = true;
            } else {
                stderr_stream << "Error: unexpected extra positional argument '" << raw_arg << "'\n";
                return 1;
            }
        }

        if (!saw_graph_kind) {
            stderr_stream << "Error: --graph <entry|fanout|cfg> is required when using graph options\n";
            return 1;
        }
        if (!has_positional_binary) {
            stderr_stream << "Error: missing target <binary> path for --headless --graph\n";
            return 1;
        }

        if (auto res = export_headless_graph(gopts, stdout_stream); !res.has_value()) {
            stderr_stream << "Error: " << res.error().message << "\n";
            return 1;
        }
        return 0;
    }

    if (!has_script_flag) {
        return peelf::try_run_headless_or_help_cli(args, stdout_stream, stderr_stream);
    }

    HeadlessScriptCliOptions opts{};
    bool has_positional_binary = false;
    bool saw_script_path = false;

    for (std::size_t i = 0u; i < args.size(); ++i) {
        const std::string_view raw_arg = args[i];
        if (raw_arg == "--headless") {
            continue;
        }

        std::string_view flag = raw_arg;
        std::optional<std::string_view> inline_val{};
        if (raw_arg.starts_with("--")) {
            if (const std::size_t eq = raw_arg.find('='); eq != std::string_view::npos) {
                flag = raw_arg.substr(0u, eq);
                inline_val = raw_arg.substr(eq + 1u);
            }
        }

        auto require_next = [&](std::string_view name) -> std::optional<std::string_view> {
            if (inline_val.has_value()) {
                return *inline_val;
            }
            if ((i + 1u) >= args.size()) {
                stderr_stream << "Error: missing value after " << name << "\n";
                return std::nullopt;
            }
            return args[++i];
        };

        if (flag == "--script") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --script requires a non-empty .lua path\n";
                return 1;
            }
            opts.script_path = std::filesystem::path(*val);
            saw_script_path = true;
        } else if (flag == "--slice") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --slice requires a slice index or architecture name\n";
                return 1;
            }
            opts.slice_selector = std::string(*val);
        } else if (flag == "--script-allow-mutations") {
            if (inline_val.has_value()) {
                stderr_stream << "Error: --script-allow-mutations does not take a value\n";
                return 1;
            }
            opts.allow_mutations = true;
        } else if (flag == "--allow-modified-binary") {
            if (inline_val.has_value()) {
                stderr_stream << "Error: --allow-modified-binary does not take a value\n";
                return 1;
            }
            opts.allow_modified_binary = true;
        } else if (flag == "--output-binary") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --output-binary requires a file path\n";
                return 1;
            }
            opts.output_binary_path = std::filesystem::path(*val);
        } else if (flag == "--project") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --project requires a .peproj file path\n";
                return 1;
            }
            opts.project_path = std::filesystem::path(*val);
        } else if (flag == "--output") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            opts.output_report_path = std::filesystem::path(*val);
        } else if (flag == "--format") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            const std::string low = lower_ascii(*val);
            if (low == "text") {
                opts.format = HeadlessScriptOutputFormat::Text;
            } else if (low == "json") {
                opts.format = HeadlessScriptOutputFormat::Json;
            } else {
                stderr_stream << "Error: unsupported --format '" << *val
                              << "' for --script (expected text or json)\n";
                return 1;
            }
        } else if (flag == "--script-max-instructions") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            std::uint64_t parsed = 0u;
            const auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), parsed);
            if (ec != std::errc{} || ptr != val->data() + val->size() || parsed == 0u) {
                stderr_stream << "Error: invalid --script-max-instructions '" << *val
                              << "' (expected positive integer)\n";
                return 1;
            }
            opts.limits.max_instructions = parsed;
        } else if (flag == "--script-timeout-ms") {
            auto val = require_next(flag);
            if (!val.has_value()) return 1;
            if (val->starts_with('-')) {
                stderr_stream << "Error: invalid --script-timeout-ms '" << *val
                              << "' (expected positive integer)\n";
                return 1;
            }
            std::uint64_t parsed = 0u;
            const auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), parsed);
            constexpr auto kMaxTimeoutMs =
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
            if (ec != std::errc{} || ptr != val->data() + val->size() || parsed == 0u ||
                parsed > kMaxTimeoutMs) {
                stderr_stream << "Error: invalid --script-timeout-ms '" << *val
                              << "' (expected positive integer <= " << kMaxTimeoutMs << ")\n";
                return 1;
            }
            opts.limits.wall_clock_timeout =
                std::chrono::milliseconds(static_cast<std::int64_t>(parsed));
        } else if (flag.starts_with('-')) {
            stderr_stream << "Error: unknown or incompatible --script option '" << flag << "'\n";
            return 1;
        } else if (!has_positional_binary) {
            opts.binary_path = std::filesystem::path(raw_arg);
            has_positional_binary = true;
        } else {
            stderr_stream << "Error: unexpected extra positional argument '" << raw_arg << "'\n";
            return 1;
        }
    }

    if (!saw_script_path) {
        stderr_stream << "Error: --script <file.lua> is required when using script options\n";
        return 1;
    }
    if (!has_positional_binary) {
        stderr_stream << "Error: missing target <binary> path for --headless --script\n";
        return 1;
    }

    auto run_res = run_headless_script(opts);
    if (!run_res.has_value()) {
        stderr_stream << "Error: " << run_res.error().message << "\n";
        return 1;
    }

    const std::string formatted =
        (opts.format == HeadlessScriptOutputFormat::Json)
            ? format_headless_script_report_json(*run_res)
            : format_headless_script_report_text(*run_res);

    if (opts.output_report_path.has_value()) {
        if (auto wr = write_text_file_atomically(*opts.output_report_path, formatted);
            !wr.has_value()) {
            stderr_stream << "Error: " << wr.error().message << "\n";
            return 1;
        }
    } else {
        stdout_stream << formatted;
    }

    if (!run_res->execution.ok) {
        stderr_stream << "Script failed ["
                      << peelf::to_string(run_res->execution.error_kind)
                      << "]: " << run_res->execution.error_message << "\n";
        return 1;
    }

    return 0;
}

} // namespace viewer
