#include "project.hpp"

#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace viewer {
namespace {

constexpr std::size_t max_file = 64 * 1024 * 1024;
constexpr std::size_t max_items = 100000;

void optional_address(std::ostream& out, std::optional<std::uint64_t> value) {
    out << value.has_value() << ' ' << value.value_or(0) << ' ';
}

bool optional_address(std::istream& in, std::optional<std::uint64_t>& value) {
    int present = 0;
    std::uint64_t address = 0;
    if (!(in >> present >> address) || (present != 0 && present != 1)) return false;
    value = present ? std::optional{address} : std::nullopt;
    return true;
}

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        result += digits[b >> 4];
        result += digits[b & 15];
    }
    return result;
}

bool unhex(std::string_view text, std::vector<std::uint8_t>& bytes) {
    if (text.size() % 2) return false;
    auto digit = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int a = digit(text[i]);
        const int b = digit(text[i + 1]);
        if (a < 0 || b < 0) return false;
        bytes.push_back(static_cast<std::uint8_t>(a * 16 + b));
    }
    return true;
}

bool normalize_sha256_hex(std::string& value) {
    if (value.empty()) return true;
    if (value.size() != 64) return false;
    for (char& ch : value) {
        const auto uch = static_cast<unsigned char>(ch);
        if (!std::isxdigit(uch)) return false;
        ch = static_cast<char>(std::tolower(uch));
    }
    return true;
}

std::string lowercase_ascii(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::filesystem::path env_path(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t size = 0;
    _dupenv_s(&value, &size, name);
    const std::filesystem::path result = value ? value : "";
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value ? value : "";
#endif
}

bool is_wsl_windows_c_mount(const std::filesystem::path& path) {
    const std::string generic = lowercase_ascii(path.generic_string());
    return generic == "/mnt/c" || generic.starts_with("/mnt/c/");
}

void write_history(std::ostream& out, std::span<const ViewerSelection> history, std::size_t cursor) {
    out << history.size() << ' ' << cursor << '\n';
    for (const auto& s : history) {
        out << static_cast<unsigned>(s.kind) << ' ' << std::quoted(s.label) << ' ';
        optional_address(out, s.file_offset);
        optional_address(out, s.virtual_address);
        out << s.size << ' ' << s.object_index << ' '
            << static_cast<unsigned>(s.preferred_view) << ' ' << s.graph_root.has_value() << ' ';
        if (s.graph_root) {
            const auto& r = *s.graph_root;
            out << std::quoted(r.name) << ' ';
            optional_address(out, r.virtual_address);
            optional_address(out, r.file_offset);
            out << r.size << ' ';
        }
        out << '\n';
    }
}

bool read_patches_annotations_symbols(std::istream& in, AnalysisProject& p) {
    std::size_t count = 0;
    if (!(in >> count) || count > max_items) return false;
    std::uint64_t end = 0;
    for (std::size_t i = 0; i < count; ++i) {
        peelf::PatchInterval patch;
        std::string a;
        std::string b;
        if (!(in >> patch.offset >> std::quoted(a) >> std::quoted(b)) ||
            !unhex(a, patch.original) || !unhex(b, patch.patched) ||
            patch.patched.empty() || patch.original.size() != patch.patched.size() ||
            patch.offset < end || patch.offset > p.source_size ||
            patch.patched.size() > p.source_size - patch.offset) {
            return false;
        }
        end = patch.end_offset();
        p.patches.push_back(std::move(patch));
    }
    if (!(in >> count) || count > max_items) return false;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint64_t address = 0;
        Annotation note;
        if (!(in >> address >> std::quoted(note.name) >> std::quoted(note.comment)) ||
            !p.annotations.emplace(address, std::move(note)).second) {
            return false;
        }
    }
    if (!(in >> count) || count > max_items) return false;
    for (std::size_t i = 0; i < count; ++i) {
        DebugSymbol s;
        int function = 0;
        if (!(in >> std::quoted(s.name) >> s.relative_virtual_address >> s.virtual_address >> s.size >> function) ||
            function < 0 || function > 1) {
            return false;
        }
        s.function = function != 0;
        p.symbols.push_back(std::move(s));
    }
    return true;
}

bool read_history_and_layout(std::istream& in, AnalysisProject& p) {
    std::size_t count = 0;
    if (!(in >> count >> p.cursor) || count > 256 || (count ? p.cursor >= count : p.cursor != 0)) {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
        ViewerSelection s;
        unsigned kind = 0;
        unsigned view = 0;
        int root = 0;
        if (!(in >> kind >> std::quoted(s.label)) ||
            kind > static_cast<unsigned>(SelectionKind::Group) ||
            !optional_address(in, s.file_offset) ||
            !optional_address(in, s.virtual_address) ||
            !(in >> s.size >> s.object_index >> view >> root) ||
            view > static_cast<unsigned>(PreferredView::Graph) || root < 0 || root > 1) {
            return false;
        }
        if (s.file_offset && (*s.file_offset > p.source_size || s.size > p.source_size - *s.file_offset)) {
            return false;
        }
        s.kind = static_cast<SelectionKind>(kind);
        s.preferred_view = static_cast<PreferredView>(view);
        if (root) {
            SymbolRecord r;
            if (!(in >> std::quoted(r.name)) ||
                !optional_address(in, r.virtual_address) ||
                !optional_address(in, r.file_offset) ||
                !(in >> r.size)) {
                return false;
            }
            s.graph_root = std::move(r);
        }
        p.history.push_back(std::move(s));
    }
    if (!(in >> std::quoted(p.layout))) return false;
    in >> std::ws;
    return in.eof();
}

void add_unique_candidate(std::vector<std::filesystem::path>& candidates,
                          const std::filesystem::path& path) {
    if (path.empty()) return;
    const auto norm = path.lexically_normal();
    for (const auto& existing : candidates) {
        if (existing.lexically_normal() == norm) return;
    }
    candidates.push_back(norm);
}

std::string sanitize_stem(std::string_view raw) {
    std::string out;
    out.reserve(std::min<std::size_t>(raw.size(), 48));
    for (char ch : raw) {
        if (out.size() >= 48) break;
        const auto uch = static_cast<unsigned char>(ch);
        if (std::isalnum(uch) || ch == '-' || ch == '_') {
            out.push_back(ch);
        } else {
            out.push_back('_');
        }
    }
    return out.empty() ? "project" : out;
}

} // namespace

std::uint64_t binary_fingerprint(std::span<const std::uint8_t> bytes) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for (auto b : bytes) {
        hash ^= b;
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::uint64_t next_project_timestamp_ms() noexcept {
    static std::atomic<std::uint64_t> last_ms{0};
    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    std::uint64_t prev = last_ms.load(std::memory_order_relaxed);
    while (true) {
        const std::uint64_t candidate = std::max<std::uint64_t>(now_ms, prev + 1);
        if (last_ms.compare_exchange_weak(prev, candidate, std::memory_order_relaxed)) {
            return candidate;
        }
    }
}

AnalysisProject build_analysis_project(const BinaryModel& model,
                                       const std::filesystem::path& peproj_path,
                                       const std::map<std::uint64_t, Annotation>& annotations,
                                       std::span<const DebugSymbol> symbols,
                                       std::span<const ViewerSelection> history,
                                       std::size_t cursor,
                                       std::string layout,
                                       bool thumb) {
    AnalysisProject p;
    p.schema_version = AnalysisProject::kCurrentSchemaVersion;
    std::error_code ec;
    const std::filesystem::path raw_src(model.file_info().path);
    const std::filesystem::path abs_src = raw_src.empty()
                                              ? std::filesystem::path{}
                                              : std::filesystem::absolute(raw_src, ec);
    p.source = (!ec && !abs_src.empty()) ? abs_src.string() : model.file_info().path;

    if (!peproj_path.empty() && !abs_src.empty()) {
        const std::filesystem::path base_dir =
            std::filesystem::absolute(peproj_path, ec).parent_path();
        if (!ec && !base_dir.empty()) {
            const auto rel = std::filesystem::proximate(abs_src, base_dir, ec);
            if (!ec && !rel.empty()) {
                p.relative_source = rel.generic_string();
            }
        }
    }

    p.source_size = model.bytes().size();
    p.fingerprint = binary_fingerprint(model.bytes());
    p.source_sha256 = peelf::sha256_hex(model.bytes());
    p.saved_unix_ms = next_project_timestamp_ms();
    p.patches = model.changed_intervals();
    p.annotations = annotations;
    p.symbols.assign(symbols.begin(), symbols.end());
    p.bookmarks.assign(model.bookmarks().begin(), model.bookmarks().end());
    p.structure_bindings.assign(model.applied_structures().begin(), model.applied_structures().end());
    p.history.assign(history.begin(), history.end());
    p.cursor = p.history.empty() ? 0 : std::min(cursor, p.history.size() - 1);
    p.layout = std::move(layout);
    p.thumb = thumb;
    return p;
}

std::string encode_project(const AnalysisProject& p) {
    std::string sha = p.source_sha256;
    if (!normalize_sha256_hex(sha)) {
        sha.clear();
    }
    std::ostringstream out;
    out << "PEELF_PROJECT " << AnalysisProject::kCurrentSchemaVersion << '\n'
        << std::quoted(p.source) << ' '
        << std::quoted(p.relative_source) << ' '
        << std::quoted(sha) << ' '
        << p.source_size << ' '
        << p.fingerprint << ' '
        << p.thumb << ' '
        << p.saved_unix_ms << '\n';

    out << p.patches.size() << '\n';
    for (const auto& patch : p.patches) {
        out << patch.offset << ' ' << std::quoted(hex(patch.original)) << ' '
            << std::quoted(hex(patch.patched)) << '\n';
    }

    out << p.annotations.size() << '\n';
    for (const auto& [address, note] : p.annotations) {
        out << address << ' ' << std::quoted(note.name) << ' ' << std::quoted(note.comment) << '\n';
    }

    out << p.symbols.size() << '\n';
    for (const auto& s : p.symbols) {
        out << std::quoted(s.name) << ' ' << s.relative_virtual_address << ' '
            << s.virtual_address << ' ' << s.size << ' ' << s.function << '\n';
    }

    out << p.bookmarks.size() << '\n';
    for (const auto& bm : p.bookmarks) {
        out << bm.address << ' ' << bm.is_file_offset << ' '
            << std::quoted(bm.label) << ' ' << std::quoted(bm.category) << ' '
            << std::quoted(bm.note) << '\n';
    }

    out << p.structure_bindings.size() << '\n';
    for (const auto& sb : p.structure_bindings) {
        const std::uint32_t count = sb.count == 0 ? 1u : sb.count;
        out << sb.address << ' ' << sb.is_file_offset << ' '
            << std::quoted(sb.type_name) << ' ' << count << ' '
            << std::quoted(sb.label) << '\n';
    }

    write_history(out, p.history, p.cursor);
    out << std::quoted(p.layout) << '\n';
    return out.str();
}

peelf::Result<AnalysisProject> decode_project(std::string_view text) {
    if (text.size() > max_file) return peelf::make_error("Project exceeds 64 MiB limit");
    std::istringstream in{std::string(text)};
    AnalysisProject p;
    std::string magic;
    int version = 0;
    auto invalid = [] { return peelf::make_error("Invalid or unsupported analysis project"); };

    if (!(in >> magic >> version) || magic != "PEELF_PROJECT" || (version != 1 && version != 2)) {
        return invalid();
    }

    if (version == 1) {
        int thumb = 0;
        if (!(in >> std::quoted(p.source) >> p.source_size >> p.fingerprint >> thumb) ||
            thumb < 0 || thumb > 1 || p.source.empty()) {
            return invalid();
        }
        p.schema_version = AnalysisProject::kCurrentSchemaVersion;
        p.migrated_from_v1 = true;
        p.thumb = thumb != 0;
        const std::filesystem::path src_path(p.source);
        if (src_path.is_relative()) {
            p.relative_source = src_path.generic_string();
        }
        if (!read_patches_annotations_symbols(in, p)) return invalid();
        if (!read_history_and_layout(in, p)) return invalid();
        return p;
    }

    int thumb = 0;
    if (!(in >> std::quoted(p.source) >> std::quoted(p.relative_source) >>
          std::quoted(p.source_sha256) >> p.source_size >> p.fingerprint >> thumb >>
          p.saved_unix_ms) ||
        thumb < 0 || thumb > 1 || (p.source.empty() && p.relative_source.empty()) ||
        !normalize_sha256_hex(p.source_sha256)) {
        return invalid();
    }
    if (p.source.empty()) {
        p.source = p.relative_source;
    }
    p.schema_version = AnalysisProject::kCurrentSchemaVersion;
    p.migrated_from_v1 = false;
    p.thumb = thumb != 0;

    if (!read_patches_annotations_symbols(in, p)) return invalid();

    std::size_t bm_count = 0;
    if (!(in >> bm_count) || bm_count > max_items) return invalid();
    for (std::size_t i = 0; i < bm_count; ++i) {
        Bookmark bm;
        int is_off = 0;
        if (!(in >> bm.address >> is_off >> std::quoted(bm.label) >>
              std::quoted(bm.category) >> std::quoted(bm.note)) ||
            (is_off != 0 && is_off != 1)) {
            return invalid();
        }
        bm.is_file_offset = (is_off != 0);
        p.bookmarks.push_back(std::move(bm));
    }

    std::size_t sb_count = 0;
    if (!(in >> sb_count) || sb_count > max_items) return invalid();
    for (std::size_t i = 0; i < sb_count; ++i) {
        AppliedStructureBinding sb;
        int is_off = 0;
        if (!(in >> sb.address >> is_off >> std::quoted(sb.type_name) >>
              sb.count >> std::quoted(sb.label)) ||
            (is_off != 0 && is_off != 1) || sb.type_name.empty() || sb.count == 0) {
            return invalid();
        }
        sb.is_file_offset = (is_off != 0);
        p.structure_bindings.push_back(std::move(sb));
    }

    if (!read_history_and_layout(in, p)) return invalid();
    return p;
}

ProjectBinaryResolution resolve_project_binary_path(
    const AnalysisProject& project,
    const std::filesystem::path& peproj_path,
    const std::filesystem::path& manual_relocated_path) {
    ProjectBinaryResolution res;
    const std::filesystem::path base_dir = peproj_path.parent_path();

    if (!manual_relocated_path.empty()) {
        add_unique_candidate(res.tried_paths, manual_relocated_path);
    } else {
        if (!project.relative_source.empty()) {
            const std::filesystem::path rel(project.relative_source);
            add_unique_candidate(res.tried_paths,
                                 (!base_dir.empty() && rel.is_relative()) ? (base_dir / rel) : rel);
        }
        if (!project.source.empty()) {
            const std::filesystem::path src(project.source);
            add_unique_candidate(res.tried_paths,
                                 (!base_dir.empty() && src.is_relative()) ? (base_dir / src) : src);
        }
    }

    std::error_code ec;
    for (const auto& cand : res.tried_paths) {
        if (std::filesystem::is_regular_file(cand, ec)) {
            res.resolved_path = cand;
            break;
        }
    }

    if (res.resolved_path.empty()) {
        res.status = ProjectBinaryMatchStatus::RelocationNeeded;
        std::string list;
        for (std::size_t i = 0; i < res.tried_paths.size(); ++i) {
            if (i > 0) list += ", ";
            list += res.tried_paths[i].string();
        }
        res.diagnostic = list.empty()
                             ? "Project does not specify a valid target binary path"
                             : std::format("Target binary not found (searched: {})", list);
        return res;
    }

    std::ifstream in(res.resolved_path, std::ios::binary);
    if (!in) {
        res.status = ProjectBinaryMatchStatus::ReadError;
        res.diagnostic = std::format("Cannot open target binary: {}", res.resolved_path.string());
        return res;
    }

    peelf::Sha256Hasher hasher;
    std::uint64_t fp = 14695981039346656037ULL;
    std::uint64_t total_bytes = 0;
    std::array<std::uint8_t, 65536> buf{};
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto got = static_cast<std::size_t>(in.gcount());
        if (got == 0) break;
        const auto chunk = std::span<const std::uint8_t>(buf.data(), got);
        hasher.update(chunk);
        for (auto b : chunk) {
            fp ^= b;
            fp *= 1099511628211ULL;
        }
        total_bytes += got;
    }
    if (!in.eof() && in.fail()) {
        res.status = ProjectBinaryMatchStatus::ReadError;
        res.diagnostic = std::format("Read failure while verifying binary: {}", res.resolved_path.string());
        return res;
    }

    res.actual_size = total_bytes;
    res.actual_sha256 = hasher.finalize_hex();
    res.actual_fingerprint = fp;

    const bool size_ok = (res.actual_size == project.source_size);
    const std::string expected_sha = lowercase_ascii(project.source_sha256);
    const bool sha_ok = expected_sha.empty() || (res.actual_sha256 == expected_sha);
    const bool fp_ok = (project.fingerprint == 0) || (res.actual_fingerprint == project.fingerprint);

    if (size_ok && sha_ok && (expected_sha.empty() ? fp_ok : true)) {
        res.status = ProjectBinaryMatchStatus::ExactMatch;
        res.diagnostic = "Target binary verified (exact SHA-256 & size match)";
    } else {
        res.status = ProjectBinaryMatchStatus::ModifiedMismatch;
        if (!size_ok) {
            res.diagnostic = std::format(
                "Target binary size changed (expected {} bytes, found {} bytes)",
                project.source_size,
                res.actual_size);
        } else if (!expected_sha.empty() && !sha_ok) {
            res.diagnostic = std::format(
                "Target binary SHA-256 mismatch (expected {}..., found {}...)",
                expected_sha.substr(0, 16),
                res.actual_sha256.substr(0, 16));
        } else {
            res.diagnostic = "Target binary fingerprint differs from saved project";
        }
    }
    return res;
}

peelf::Result<void> restore_project_patches(BinaryModel& model,
                                            const AnalysisProject& p,
                                            bool allow_modified_binary) {
    if (!allow_modified_binary) {
        if (model.bytes().size() != p.source_size ||
            binary_fingerprint(model.bytes()) != p.fingerprint) {
            return peelf::make_error("Source binary differs from the saved project");
        }
        if (!p.source_sha256.empty() &&
            peelf::sha256_hex(model.bytes()) != lowercase_ascii(p.source_sha256)) {
            return peelf::make_error("Source binary SHA-256 differs from the saved project");
        }
    }
    if (!model.changed_intervals().empty()) {
        return peelf::make_error("Restore requires an unmodified source model");
    }
    for (const auto& patch : p.patches) {
        if (patch.offset > model.bytes().size() ||
            patch.original.size() > model.bytes().size() - patch.offset ||
            patch.original.size() != patch.patched.size() ||
            !std::ranges::equal(
                patch.original,
                std::span(model.bytes()).subspan(static_cast<std::size_t>(patch.offset),
                                                 patch.original.size()))) {
            return peelf::make_error("Saved patch original bytes do not match source");
        }
    }
    if (p.patches.empty()) {
        return {};
    }
    return model.apply_patch_set(p.patches);
}

peelf::Result<std::string> read_project_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return peelf::make_error("Cannot open project");
    const auto size = in.tellg();
    if (size < 0 || size > static_cast<std::streamoff>(max_file)) {
        return peelf::make_error("Project exceeds size limit");
    }
    std::string text(static_cast<std::size_t>(size), '\0');
    in.seekg(0);
    if (size > 0 && !in.read(text.data(), size)) {
        return peelf::make_error("Cannot read project");
    }
    return text;
}

peelf::Result<void> write_analysis_file(const std::filesystem::path& path, std::string_view text) {
    static std::atomic<std::uint64_t> tmp_counter{0};
    std::error_code dir_ec;
    if (path.has_parent_path() && !path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), dir_ec);
    }
    auto tmp = path;
    tmp += std::format(".tmp-{}-{}",
                       std::chrono::steady_clock::now().time_since_epoch().count(),
                       ++tmp_counter);
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return peelf::make_error("Cannot create analysis file");
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.flush();
        out.close();
        if (!out) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            return peelf::make_error("Cannot write analysis file");
        }
    }
    std::error_code ec;
#ifdef _WIN32
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ec = std::error_code(static_cast<int>(GetLastError()), std::system_category());
    }
#else
    std::filesystem::rename(tmp, path, ec);
#endif
    if (ec) {
        std::error_code rm_ec;
        std::filesystem::remove(tmp, rm_ec);
        return peelf::make_error("Cannot replace analysis file");
    }
    return {};
}

std::filesystem::path default_project_recovery_directory() {
#ifndef _WIN32
    if (const auto custom = env_path("PEELF_CACHE_DIR");
        !custom.empty() && !is_wsl_windows_c_mount(custom)) {
        return custom / "recovery";
    }
    if (const auto xdg = env_path("XDG_CACHE_HOME");
        !xdg.empty() && !is_wsl_windows_c_mount(xdg)) {
        return xdg / "peelf_viewer" / "recovery";
    }
    return std::filesystem::path("/tmp") /
           std::format("peelf_viewer-recovery-{}", static_cast<unsigned long>(::geteuid()));
#else
    if (const auto custom = env_path("PEELF_CACHE_DIR"); !custom.empty()) {
        return custom / "recovery";
    }
    if (const auto local_app = env_path("LOCALAPPDATA"); !local_app.empty()) {
        return local_app / "peelf_viewer" / "recovery";
    }
    return std::filesystem::temp_directory_path() / "peelf_viewer-recovery";
#endif
}

std::filesystem::path project_recovery_journal_path(
    const std::filesystem::path& key_path,
    const std::filesystem::path& recovery_dir) {
    std::error_code ec;
    const auto abs_key = key_path.empty() ? std::filesystem::path("untitled")
                                          : std::filesystem::absolute(key_path, ec).lexically_normal();
    const std::string key_utf8 = (!ec ? abs_key : key_path).generic_string();
    const std::string digest = peelf::sha256_hex(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(key_utf8.data()),
                                      key_utf8.size()));
    const std::string stem = sanitize_stem(key_path.stem().string());
    const std::filesystem::path base =
        recovery_dir.empty() ? default_project_recovery_directory() : recovery_dir;
    return base / std::format("{}-{}.peproj.autosave", stem, digest.substr(0, 16));
}

peelf::Result<std::filesystem::path> write_recovery_journal(
    const AnalysisProject& project,
    const std::filesystem::path& key_path,
    const std::filesystem::path& recovery_dir) {
    if (is_wsl_windows_c_mount(recovery_dir)) {
        return peelf::make_error("Recovery directory must not reside on /mnt/c");
    }
    AnalysisProject stamped = project;
    stamped.saved_unix_ms = std::max(stamped.saved_unix_ms, next_project_timestamp_ms());
    const auto journal_path = project_recovery_journal_path(key_path, recovery_dir);
    if (auto res = write_analysis_file(journal_path, encode_project(stamped)); !res) {
        return std::unexpected(res.error());
    }
    return journal_path;
}

std::optional<AnalysisProject> check_newer_recovery_journal(
    const std::filesystem::path& key_path,
    std::uint64_t baseline_saved_unix_ms,
    const std::filesystem::path& recovery_dir) {
    const auto journal_path = project_recovery_journal_path(key_path, recovery_dir);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(journal_path, ec)) {
        return std::nullopt;
    }
    auto text = read_project_file(journal_path);
    if (!text) return std::nullopt;
    auto decoded = decode_project(*text);
    if (!decoded) return std::nullopt;
    if (baseline_saved_unix_ms != 0 && decoded->saved_unix_ms <= baseline_saved_unix_ms) {
        return std::nullopt;
    }
    return *decoded;
}

void clear_recovery_journal(const std::filesystem::path& key_path,
                            const std::filesystem::path& recovery_dir) noexcept {
    std::error_code ec;
    std::filesystem::remove(project_recovery_journal_path(key_path, recovery_dir), ec);
}

} // namespace viewer
