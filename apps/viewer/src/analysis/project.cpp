#include "project.hpp"

#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

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
    if (text.size() > kMaxProjectFileBytes) return peelf::make_error("Project exceeds 64 MiB limit");
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
    std::string expected_sha = lowercase_ascii(project.source_sha256);
    if (!normalize_sha256_hex(expected_sha)) {
        expected_sha.clear();
    }

    std::filesystem::path target_filename = std::filesystem::path(project.source).filename();
    if (target_filename.empty() && !project.relative_source.empty()) {
        target_filename = std::filesystem::path(project.relative_source).filename();
    }

    std::error_code dir_ec;
    if (!manual_relocated_path.empty()) {
        if (std::filesystem::is_directory(manual_relocated_path, dir_ec) && !dir_ec) {
            if (!target_filename.empty()) {
                add_unique_candidate(res.tried_paths, manual_relocated_path / target_filename);
            }
            if (!expected_sha.empty()) {
                std::size_t scanned_entries = 0;
                for (std::filesystem::directory_iterator it(manual_relocated_path, dir_ec), end;
                     !dir_ec && it != end && scanned_entries < 256u;
                     it.increment(dir_ec), ++scanned_entries) {
                    std::error_code entry_ec;
                    if (!it->is_regular_file(entry_ec) || entry_ec) continue;
                    if (project.source_size != 0) {
                        const auto entry_sz = it->file_size(entry_ec);
                        if (entry_ec || entry_sz != project.source_size) continue;
                    }
                    add_unique_candidate(res.tried_paths, it->path());
                }
            }
        } else {
            add_unique_candidate(res.tried_paths, manual_relocated_path);
        }
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
        if (!base_dir.empty() && !target_filename.empty()) {
            add_unique_candidate(res.tried_paths, base_dir / target_filename);
        }
    }

    auto evaluate_candidate = [&](const std::filesystem::path& cand) -> ProjectBinaryResolution {
        ProjectBinaryResolution eval;
        eval.resolved_path = cand;

        std::ifstream in(cand, std::ios::binary);
        if (!in) {
            eval.status = ProjectBinaryMatchStatus::ReadError;
            eval.diagnostic = std::format("Cannot open target binary: {}", cand.string());
            return eval;
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
            for (const auto b : chunk) {
                fp ^= b;
                fp *= 1099511628211ULL;
            }
            total_bytes += got;
        }
        if (!in.eof() && in.fail()) {
            eval.status = ProjectBinaryMatchStatus::ReadError;
            eval.diagnostic = std::format("Read failure while verifying binary: {}", cand.string());
            return eval;
        }

        eval.actual_size = total_bytes;
        eval.actual_sha256 = hasher.finalize_hex();
        eval.actual_fingerprint = fp;

        const bool size_ok = (project.source_size == 0 && !expected_sha.empty())
                                 ? true
                                 : (eval.actual_size == project.source_size);
        const bool sha_ok = expected_sha.empty() || (eval.actual_sha256 == expected_sha);
        const bool fp_ok = (project.fingerprint == 0) || (eval.actual_fingerprint == project.fingerprint);

        if (size_ok && sha_ok && (expected_sha.empty() ? fp_ok : true)) {
            eval.status = ProjectBinaryMatchStatus::ExactMatch;
            eval.diagnostic = "Target binary verified (exact SHA-256 & size match)";
        } else {
            eval.status = ProjectBinaryMatchStatus::ModifiedMismatch;
            if (!size_ok) {
                eval.diagnostic = std::format(
                    "Target binary size changed (expected {} bytes, found {} bytes)",
                    project.source_size,
                    eval.actual_size);
            } else if (!expected_sha.empty() && !sha_ok) {
                eval.diagnostic = std::format(
                    "Target binary SHA-256 mismatch (expected {}..., found {}...)",
                    expected_sha.substr(0, 16),
                    eval.actual_sha256.substr(0, 16));
            } else {
                eval.diagnostic = "Target binary fingerprint differs from saved project";
            }
        }
        return eval;
    };

    std::optional<ProjectBinaryResolution> first_sha_match;
    std::optional<ProjectBinaryResolution> first_modified;
    std::optional<ProjectBinaryResolution> first_read_error;

    for (const auto& cand : res.tried_paths) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(cand, ec) || ec) {
            continue;
        }
        ProjectBinaryResolution eval = evaluate_candidate(cand);
        if (eval.status == ProjectBinaryMatchStatus::ExactMatch) {
            eval.tried_paths = std::move(res.tried_paths);
            return eval;
        }
        if (!expected_sha.empty() && eval.actual_sha256 == expected_sha && !first_sha_match.has_value()) {
            first_sha_match = std::move(eval);
            continue;
        }
        if (eval.status == ProjectBinaryMatchStatus::ModifiedMismatch) {
            if (!first_modified.has_value()) {
                first_modified = std::move(eval);
            }
        } else if (!first_read_error.has_value()) {
            first_read_error = std::move(eval);
        }
    }

    if (first_sha_match.has_value()) {
        first_sha_match->tried_paths = std::move(res.tried_paths);
        return *first_sha_match;
    }
    if (first_modified.has_value()) {
        first_modified->tried_paths = std::move(res.tried_paths);
        return *first_modified;
    }
    if (first_read_error.has_value()) {
        first_read_error->tried_paths = std::move(res.tried_paths);
        return *first_read_error;
    }

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
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        return peelf::make_error("Cannot open project");
    }
    const std::uintmax_t disk_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return peelf::make_error("Cannot open project");
    }
    if (disk_size > kMaxProjectFileBytes) {
        return peelf::make_error("Project exceeds 64 MiB limit");
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return peelf::make_error("Cannot open project");
    }
    std::string text;
    text.reserve(static_cast<std::size_t>(disk_size));
    std::array<char, 65536> buf{};
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const auto got = static_cast<std::size_t>(in.gcount());
        if (got == 0) break;
        if (got > kMaxProjectFileBytes - text.size()) {
            return peelf::make_error("Project exceeds 64 MiB limit");
        }
        text.append(buf.data(), got);
    }
    if (!in.eof() && in.fail()) {
        return peelf::make_error("Cannot read project");
    }
    return text;
}

peelf::Result<void> write_analysis_file(const std::filesystem::path& path, std::string_view text) {
    if (path.empty() || path.filename().empty()) {
        return peelf::make_error("Invalid analysis file path");
    }
    if (text.size() > kMaxProjectFileBytes) {
        return peelf::make_error("Project exceeds 64 MiB limit");
    }

    const std::filesystem::path parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code dir_ec;
        std::filesystem::create_directories(parent, dir_ec);
        if (dir_ec) {
            return peelf::make_error("Cannot create analysis directory");
        }
    }

    std::error_code base_ec;
    const std::filesystem::path base_dir =
        parent.empty() ? std::filesystem::current_path(base_ec) : parent;
    if (base_ec) {
        return peelf::make_error("Cannot resolve analysis directory");
    }

    struct TempFileGuard {
        std::filesystem::path temp_path;
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

    static std::atomic<std::uint64_t> tmp_counter{0};
    const std::uint64_t pid =
#ifdef _WIN32
        static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
        static_cast<std::uint64_t>(::getpid());
#endif

    TempFileGuard guard;
#ifndef _WIN32
    mode_t preserved_mode = 0666;
    bool has_preserved_mode = false;
    struct stat existing_st {};
    if (::stat(path.c_str(), &existing_st) == 0 && S_ISREG(existing_st.st_mode)) {
        preserved_mode = static_cast<mode_t>(existing_st.st_mode & 07777);
        has_preserved_mode = true;
    }
#endif

    constexpr std::uint32_t kMaxCreateAttempts = 128;
    bool opened = false;
    for (std::uint32_t attempt = 0; attempt < kMaxCreateAttempts; ++attempt) {
        std::filesystem::path candidate = base_dir / path.filename();
        candidate += std::format(".{}-{}-{}.tmp",
                                 pid,
                                 std::chrono::steady_clock::now().time_since_epoch().count(),
                                 tmp_counter.fetch_add(1, std::memory_order_relaxed) + 1u);
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
        return peelf::make_error("Cannot create analysis file");
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
        return peelf::make_error("Cannot create analysis file");
#endif
    }

    if (!opened) {
        return peelf::make_error("Cannot create unique temporary analysis file");
    }

#ifdef _WIN32
    std::size_t offset = 0;
    while (offset < text.size()) {
        const std::size_t remaining = text.size() - offset;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 64u * 1024u * 1024u));
        DWORD written = 0;
        if (!::WriteFile(guard.handle, text.data() + offset, chunk, &written, nullptr) || written == 0) {
            return peelf::make_error("Cannot write analysis file");
        }
        offset += static_cast<std::size_t>(written);
    }
    if (!::FlushFileBuffers(guard.handle)) {
        return peelf::make_error("Cannot flush analysis file");
    }
    const HANDLE closing = guard.handle;
    guard.handle = INVALID_HANDLE_VALUE;
    if (!::CloseHandle(closing)) {
        return peelf::make_error("Cannot close analysis file");
    }
    if (!::MoveFileExW(guard.temp_path.c_str(),
                       path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return peelf::make_error("Cannot replace analysis file");
    }
#else
    std::size_t offset = 0;
    while (offset < text.size()) {
        const std::size_t remaining = text.size() - offset;
        const std::size_t chunk = std::min<std::size_t>(remaining, 64u * 1024u * 1024u);
        const ssize_t written = ::write(guard.fd, text.data() + offset, chunk);
        if (written < 0) {
            if (errno == EINTR) continue;
            return peelf::make_error("Cannot write analysis file");
        }
        if (written == 0) {
            return peelf::make_error("Cannot write analysis file");
        }
        offset += static_cast<std::size_t>(written);
    }
    while (::fsync(guard.fd) != 0) {
        if (errno == EINTR) continue;
        return peelf::make_error("Cannot flush analysis file");
    }
    const int closing = guard.fd;
    guard.fd = -1;
    if (::close(closing) != 0 && errno != EINTR) {
        return peelf::make_error("Cannot close analysis file");
    }
    if (::rename(guard.temp_path.c_str(), path.c_str()) != 0) {
        return peelf::make_error("Cannot replace analysis file");
    }
#endif

    guard.committed = true;
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
    auto journal_path = project_recovery_journal_path(key_path, recovery_dir);
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
    if (!std::filesystem::is_regular_file(journal_path, ec) || ec) {
        return std::nullopt;
    }
    const std::uintmax_t journal_size = std::filesystem::file_size(journal_path, ec);
    if (ec || journal_size > kMaxProjectFileBytes) {
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
                            const std::filesystem::path& recovery_dir) {
    std::error_code ec;
    std::filesystem::remove(project_recovery_journal_path(key_path, recovery_dir), ec);
}

} // namespace viewer
