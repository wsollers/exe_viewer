#include "project.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace viewer {
namespace {
constexpr std::size_t max_file = 64 * 1024 * 1024, max_items = 100000;
void optional_address(std::ostream& out, std::optional<std::uint64_t> value) { out << value.has_value() << ' ' << value.value_or(0) << ' '; }
bool optional_address(std::istream& in, std::optional<std::uint64_t>& value) {
    int present; std::uint64_t address;
    if (!(in >> present >> address) || (present != 0 && present != 1)) return false;
    value = present ? std::optional{address} : std::nullopt; return true;
}
std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef"; std::string result; result.reserve(bytes.size() * 2);
    for (auto b : bytes) { result += digits[b >> 4]; result += digits[b & 15]; } return result;
}
bool unhex(std::string_view text, std::vector<std::uint8_t>& bytes) {
    if (text.size() % 2) return false;
    auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (std::size_t i = 0; i < text.size(); i += 2) { int a = digit(text[i]), b = digit(text[i+1]); if (a < 0 || b < 0) return false; bytes.push_back(static_cast<std::uint8_t>(a * 16 + b)); }
    return true;
}
}
std::uint64_t binary_fingerprint(std::span<const std::uint8_t> bytes) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for (auto b : bytes) { hash ^= b; hash *= 1099511628211ULL; } return hash;
}
std::string encode_project(const AnalysisProject& p) {
    std::ostringstream out;
    out << "PEELF_PROJECT 1\n" << std::quoted(p.source) << ' ' << p.source_size << ' ' << p.fingerprint << ' ' << p.thumb << '\n';
    out << p.patches.size() << '\n';
    for (auto& patch : p.patches) out << patch.offset << ' ' << std::quoted(hex(patch.original)) << ' ' << std::quoted(hex(patch.patched)) << '\n';
    out << p.annotations.size() << '\n';
    for (auto& [address, note] : p.annotations) out << address << ' ' << std::quoted(note.name) << ' ' << std::quoted(note.comment) << '\n';
    out << p.symbols.size() << '\n';
    for (auto& s : p.symbols) out << std::quoted(s.name) << ' ' << s.relative_virtual_address << ' ' << s.virtual_address << ' ' << s.size << ' ' << s.function << '\n';
    out << p.history.size() << ' ' << p.cursor << '\n';
    for (auto& s : p.history) {
        out << static_cast<unsigned>(s.kind) << ' ' << std::quoted(s.label) << ' '; optional_address(out, s.file_offset); optional_address(out, s.virtual_address);
        out << s.size << ' ' << s.object_index << ' ' << static_cast<unsigned>(s.preferred_view) << ' ' << s.graph_root.has_value() << ' ';
        if (s.graph_root) { auto& r = *s.graph_root; out << std::quoted(r.name) << ' '; optional_address(out,r.virtual_address); optional_address(out,r.file_offset); out << r.size << ' '; }
        out << '\n';
    }
    out << std::quoted(p.layout) << '\n'; return out.str();
}
peelf::Result<AnalysisProject> decode_project(std::string_view text) {
    if (text.size() > max_file) return peelf::make_error("Project exceeds 64 MiB limit");
    std::istringstream in{std::string(text)}; AnalysisProject p; std::string magic; int version, thumb;
    auto invalid = [] { return peelf::make_error("Invalid or unsupported analysis project"); };
    if (!(in >> magic >> version) || magic != "PEELF_PROJECT" || version != 1 ||
        !(in >> std::quoted(p.source) >> p.source_size >> p.fingerprint >> thumb) || thumb < 0 || thumb > 1 || p.source.empty()) return invalid();
    p.thumb = thumb != 0; std::size_t count;
    if (!(in >> count) || count > max_items) return invalid();
    std::uint64_t end = 0;
    for (std::size_t i = 0; i < count; ++i) {
        peelf::PatchInterval patch; std::string a,b;
        if (!(in >> patch.offset >> std::quoted(a) >> std::quoted(b)) || !unhex(a,patch.original) || !unhex(b,patch.patched) ||
            patch.patched.empty() || patch.original.size() != patch.patched.size() || patch.offset < end || patch.offset > p.source_size ||
            patch.patched.size() > p.source_size - patch.offset) return invalid();
        end = patch.end_offset(); p.patches.push_back(std::move(patch));
    }
    if (!(in >> count) || count > max_items) return invalid();
    for (std::size_t i=0;i<count;++i) { std::uint64_t address; Annotation note; if (!(in >> address >> std::quoted(note.name) >> std::quoted(note.comment)) || !p.annotations.emplace(address,std::move(note)).second) return invalid(); }
    if (!(in >> count) || count > max_items) return invalid();
    for (std::size_t i=0;i<count;++i) { DebugSymbol s; int function; if (!(in >> std::quoted(s.name) >> s.relative_virtual_address >> s.virtual_address >> s.size >> function) || function<0 || function>1) return invalid(); s.function=function!=0; p.symbols.push_back(std::move(s)); }
    if (!(in >> count >> p.cursor) || count > 256 || (count ? p.cursor >= count : p.cursor != 0)) return invalid();
    for (std::size_t i=0;i<count;++i) {
        ViewerSelection s; unsigned kind,view; int root;
        if (!(in >> kind >> std::quoted(s.label)) || kind > static_cast<unsigned>(SelectionKind::Group) || !optional_address(in,s.file_offset) || !optional_address(in,s.virtual_address) ||
            !(in >> s.size >> s.object_index >> view >> root) || view > static_cast<unsigned>(PreferredView::Graph) || root<0 || root>1) return invalid();
        if (s.file_offset && (*s.file_offset > p.source_size || s.size > p.source_size - *s.file_offset)) return invalid();
        s.kind=static_cast<SelectionKind>(kind); s.preferred_view=static_cast<PreferredView>(view);
        if (root) { SymbolRecord r; if (!(in >> std::quoted(r.name)) || !optional_address(in,r.virtual_address) || !optional_address(in,r.file_offset) || !(in >> r.size)) return invalid(); s.graph_root=std::move(r); }
        p.history.push_back(std::move(s));
    }
    if (!(in >> std::quoted(p.layout))) return invalid();
    in >> std::ws; if (!in.eof()) return invalid(); return p;
}
peelf::Result<void> restore_project_patches(BinaryModel& model, const AnalysisProject& p) {
    if (model.bytes().size() != p.source_size || binary_fingerprint(model.bytes()) != p.fingerprint) return peelf::make_error("Source binary differs from the saved project");
    if (!model.changed_intervals().empty()) return peelf::make_error("Restore requires an unmodified source model");
    for (const auto& patch : p.patches) {
        if (patch.offset > model.bytes().size() || patch.original.size() > model.bytes().size() - patch.offset || patch.original.size() != patch.patched.size() ||
            !std::ranges::equal(patch.original, std::span(model.bytes()).subspan(static_cast<std::size_t>(patch.offset),patch.original.size()))) return peelf::make_error("Saved patch original bytes do not match source");
    }
    return model.apply_patch_set(p.patches);
}
peelf::Result<std::string> read_project_file(const std::filesystem::path& path) {
    std::ifstream in(path,std::ios::binary|std::ios::ate); if (!in) return peelf::make_error("Cannot open project");
    const auto size=in.tellg(); if (size<0 || size>static_cast<std::streamoff>(max_file)) return peelf::make_error("Project exceeds size limit");
    std::string text(static_cast<std::size_t>(size),'\0'); in.seekg(0); if (!in.read(text.data(),size)) return peelf::make_error("Cannot read project"); return text;
}
peelf::Result<void> write_analysis_file(const std::filesystem::path& path,std::string_view text) {
    auto tmp=path; tmp += ".tmp-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    { std::ofstream out(tmp,std::ios::binary|std::ios::trunc); if (!out) return peelf::make_error("Cannot create analysis file"); out.write(text.data(),static_cast<std::streamsize>(text.size())); out.close(); if (!out) { std::error_code ec; std::filesystem::remove(tmp,ec); return peelf::make_error("Cannot write analysis file"); } }
    std::error_code ec;
#ifdef _WIN32
    if (!MoveFileExW(tmp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) ec=std::error_code(GetLastError(),std::system_category());
#else
    std::filesystem::rename(tmp,path,ec);
#endif
    if (ec) { std::filesystem::remove(tmp,ec); return peelf::make_error("Cannot replace analysis file"); } return {};
}
}
