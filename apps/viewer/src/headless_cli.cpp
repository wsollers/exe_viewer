#include "headless_cli.hpp"

#include <peelf/binary_image.hpp>
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
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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
        << "  --fail-on <none|error|warning>\n"
        << "                               CI policy gate (exit 2 on security findings or missing deps)\n"
        << "\nHeadless Lua Scripting Options (--script):\n"
        << "  --script <file.lua>          Execute sandboxed Lua 5.4 script against <binary> (read-only default)\n"
        << "  --script-allow-mutations     Allow script to stage/commit patches, labels, comments & bookmarks\n"
        << "  --allow-modified-binary      Allow loading a .peproj whose source SHA-256 differs from <binary>\n"
        << "  --output-binary <out_path>   Write patched binary atomically when script calls peelf.commit()\n"
        << "  --project <workspace.peproj> Load/save PEELF_PROJECT v2 annotations, bookmarks & byte patches\n"
        << "  --script-max-instructions <N> Override Lua VM instruction quota (default: 1000000)\n"
        << "  --script-timeout-ms <ms>     Override Lua script wall-clock timeout in ms (default: 5000)\n"
        << "  --help                       Show this help\n";
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

std::optional<int> try_run_headless_or_help_cli(
    std::span<const std::string_view> args,
    std::ostream& stdout_stream,
    std::ostream& stderr_stream) {
    bool headless = false;
    bool help = false;
    bool has_script_flag = false;

    for (const std::string_view arg : args) {
        if (arg == "--headless") {
            headless = true;
        } else if (arg == "--help" || arg == "-h") {
            help = true;
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
        }
    }

    if (help) {
        print_help_usage(stdout_stream);
        return 0;
    }

    if (!headless) {
        if (has_script_flag) {
            stderr_stream << "Error: --script options require --headless\n";
            return 1;
        }
        return std::nullopt;
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
