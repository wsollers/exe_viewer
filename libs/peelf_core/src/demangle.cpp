#include <peelf/demangle.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if __has_include(<cxxabi.h>)
#include <cxxabi.h>
#define PEELF_HAS_CXXABI_DEMANGLE 1
#else
#define PEELF_HAS_CXXABI_DEMANGLE 0
#endif

namespace peelf {
namespace {

constexpr std::size_t kMaxMangledInputLength = 8192;
constexpr std::size_t kMaxDemangledOutputLength = 16384;
constexpr std::size_t kMaxDemangleDepth = 64;

[[nodiscard]] bool is_ascii_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool is_lower_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

[[nodiscard]] std::uint32_t hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<std::uint32_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint32_t>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F') return static_cast<std::uint32_t>(10 + (c - 'A'));
    return 0xFFu;
}

void append_utf8_cp(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7Fu) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FFu) {
        out.push_back(static_cast<char>(0xC0u | (cp >> 6u)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0xFFFFu) {
        out.push_back(static_cast<char>(0xE0u | (cp >> 12u)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6u) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0x10FFFFu) {
        out.push_back(static_cast<char>(0xF0u | (cp >> 18u)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12u) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6u) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
}

struct SplitSymbolWrapper {
    std::string_view prefix{};
    std::string_view core{};
    std::string_view suffix{};
};

[[nodiscard]] SplitSymbolWrapper split_wrappers(std::string_view raw) noexcept {
    SplitSymbolWrapper res;
    res.core = raw;

    // Optional PE/ELF import library prefix (`KERNEL32.dll!Sym` or `libstdc++.so.6!_ZN...`).
    if (const std::size_t bang = res.core.find('!');
        bang != std::string_view::npos && bang > 0 && bang + 1 < res.core.size()) {
        // Avoid splitting operator!= inside already-demangled strings.
        if (res.core[bang + 1] != '=') {
            res.prefix = res.core.substr(0, bang + 1);
            res.core = res.core.substr(bang + 1);
        }
    }

    // Optional ELF PLT / symbol-version suffix (`@plt`, `@GLIBC_2.34`, `@@GLIBCXX_3.4`).
    // Never strip `@` from MSVC mangled names (`?...`).
    if (!res.core.empty() && res.core.front() != '?') {
        if (const std::size_t at = res.core.find('@'); at != std::string_view::npos && at > 0) {
            res.suffix = res.core.substr(at);
            res.core = res.core.substr(0, at);
        }
    }

    return res;
}

// ============================================================================
// Rust Legacy (`_ZN...17h<16hex>E` / `$LT$` escapes)
// ============================================================================

[[nodiscard]] bool has_rust_legacy_escape(std::string_view s) noexcept {
    return s.find("$LT$") != std::string_view::npos ||
           s.find("$GT$") != std::string_view::npos ||
           s.find("$LP$") != std::string_view::npos ||
           s.find("$RP$") != std::string_view::npos ||
           s.find("$SP$") != std::string_view::npos ||
           s.find("$BP$") != std::string_view::npos ||
           s.find("$RF$") != std::string_view::npos ||
           s.find("$C$") != std::string_view::npos ||
           s.find("$u") != std::string_view::npos ||
           s.find("..") != std::string_view::npos;
}

[[nodiscard]] bool has_rust_legacy_hash_tail(std::string_view s) noexcept {
    // `_ZN...17h<16 lower-hex>E`
    if (s.size() < 24 || s.back() != 'E') {
        return false;
    }
    const std::size_t hash_tag = s.size() - 1 - 19; // "17h" (3) + 16 hex = 19
    if (s.substr(hash_tag, 3) != "17h") {
        return false;
    }
    for (std::size_t i = hash_tag + 3; i + 1 < s.size(); ++i) {
        if (!is_lower_hex(s[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<std::string> unescape_rust_legacy_segment(
    std::string_view seg,
    std::size_t& remaining_budget) {
    std::string out;
    out.reserve(std::min(seg.size(), remaining_budget));
    const auto append_checked = [&](std::string_view piece) noexcept -> bool {
        if (piece.size() > remaining_budget) {
            return false;
        }
        remaining_budget -= piece.size();
        out.append(piece);
        return true;
    };
    const auto push_checked = [&](char ch) noexcept -> bool {
        if (remaining_budget == 0) {
            return false;
        }
        --remaining_budget;
        out.push_back(ch);
        return true;
    };

    std::size_t i = 0;
    if (seg.starts_with('_') && seg.size() > 1 && seg[1] == '$') {
        i = 1; // Leading `_$` escape marker in Rust legacy identifiers
    }
    while (i < seg.size()) {
        if (i + 1 < seg.size() && seg[i] == '.' && seg[i + 1] == '.') {
            if (!append_checked("::")) return std::nullopt;
            i += 2;
            continue;
        }
        if (seg[i] == '$') {
            const std::size_t close = seg.find('$', i + 1);
            if (close != std::string_view::npos) {
                const std::string_view tok = seg.substr(i + 1, close - i - 1);
                if (tok == "SP") { if (!push_checked('@')) return std::nullopt; i = close + 1; continue; }
                if (tok == "BP") { if (!push_checked('*')) return std::nullopt; i = close + 1; continue; }
                if (tok == "RF") { if (!push_checked('&')) return std::nullopt; i = close + 1; continue; }
                if (tok == "LT") { if (!push_checked('<')) return std::nullopt; i = close + 1; continue; }
                if (tok == "GT") { if (!push_checked('>')) return std::nullopt; i = close + 1; continue; }
                if (tok == "LP") { if (!push_checked('(')) return std::nullopt; i = close + 1; continue; }
                if (tok == "RP") { if (!push_checked(')')) return std::nullopt; i = close + 1; continue; }
                if (tok == "C")  { if (!append_checked(", ")) return std::nullopt; i = close + 1; continue; }
                if (tok.size() >= 2 && tok.size() <= 7 && tok[0] == 'u') {
                    std::uint32_t cp = 0;
                    bool ok = true;
                    for (std::size_t k = 1; k < tok.size(); ++k) {
                        const std::uint32_t hv = hex_value(tok[k]);
                        if (hv > 0xFu) { ok = false; break; }
                        cp = (cp << 4u) | hv;
                    }
                    if (ok && cp <= 0x10FFFFu && !(cp >= 0xD800u && cp <= 0xDFFFu)) {
                        std::string utf8_piece;
                        append_utf8_cp(utf8_piece, cp);
                        if (!append_checked(utf8_piece)) return std::nullopt;
                        i = close + 1;
                        continue;
                    }
                }
            }
        }
        if (!push_checked(seg[i])) return std::nullopt;
        ++i;
    }
    return out;
}

[[nodiscard]] std::optional<std::string> try_demangle_rust_legacy(std::string_view s) {
    std::string_view body = s;
    if (body.starts_with("__ZN")) {
        body.remove_prefix(4);
    } else if (body.starts_with("_ZN")) {
        body.remove_prefix(3);
    } else {
        return std::nullopt;
    }
    if (body.empty() || body.back() != 'E') {
        return std::nullopt;
    }
    if (!has_rust_legacy_hash_tail(s) && !has_rust_legacy_escape(body)) {
        return std::nullopt;
    }
    body.remove_suffix(1); // drop 'E'

    std::vector<std::string_view> raw_parts;
    std::size_t pos = 0;
    while (pos < body.size()) {
        if (!is_ascii_digit(body[pos]) || (body[pos] == '0' && pos + 1 < body.size() && is_ascii_digit(body[pos + 1]))) {
            return std::nullopt;
        }
        std::size_t len = 0;
        while (pos < body.size() && is_ascii_digit(body[pos])) {
            const auto d = static_cast<std::size_t>(body[pos] - '0');
            if (len > body.size()) {
                return std::nullopt;
            }
            len = len * 10u + d;
            if (len > body.size()) {
                return std::nullopt;
            }
            ++pos;
        }
        if (len == 0 || pos + len > body.size()) {
            return std::nullopt;
        }
        raw_parts.push_back(body.substr(pos, len));
        pos += len;
    }
    if (raw_parts.empty()) {
        return std::nullopt;
    }

    // Strip trailing `h<16 lower-hex>` crate/monomorphization hash segment if present.
    if (raw_parts.size() >= 2 && raw_parts.back().size() == 17 && raw_parts.back()[0] == 'h') {
        bool all_hex = true;
        for (std::size_t k = 1; k < 17; ++k) {
            if (!is_lower_hex(raw_parts.back()[k])) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            raw_parts.pop_back();
        }
    }

    std::size_t remaining_budget = kMaxDemangledOutputLength;
    std::string result;
    for (std::size_t i = 0; i < raw_parts.size(); ++i) {
        if (i > 0) {
            if (remaining_budget < 2u) {
                return std::nullopt;
            }
            remaining_budget -= 2u;
            result += "::";
        }
        auto seg = unescape_rust_legacy_segment(raw_parts[i], remaining_budget);
        if (!seg) {
            return std::nullopt;
        }
        result += *seg;
        if (result.size() > kMaxDemangledOutputLength) {
            return std::nullopt;
        }
    }
    return result;
}

// ============================================================================
// Rust v0 (`_R...` / RFC 2603)
// ============================================================================

class RustV0Parser {
public:
    explicit RustV0Parser(std::string_view body) noexcept : s_(body) {}

    [[nodiscard]] std::optional<std::string> parse_symbol() {
        // Optional encoding version number after `_R`
        if (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
            return std::nullopt; // Future unknown encoding version
        }
        auto path = parse_path(0);
        if (!path || out_overflow_) {
            return std::nullopt;
        }
        // Optional instantiating crate after root path (not printed in concise form)
        if (pos_ < s_.size() && s_[pos_] != '.') {
            const std::size_t saved = pos_;
            if (!parse_path(0)) {
                if (out_overflow_) {
                    return std::nullopt;
                }
                pos_ = saved;
            }
        }
        // Optional vendor suffix `.llvm.1234`
        std::string suffix;
        if (pos_ < s_.size() && s_[pos_] == '.') {
            const std::string_view vendor = s_.substr(pos_ + 1);
            if (!consume_budget(vendor.size() + 3u)) {
                return std::nullopt;
            }
            suffix = std::string(" (") + std::string(vendor) + ")";
            pos_ = s_.size();
        }
        if (pos_ != s_.size() || out_overflow_) {
            return std::nullopt;
        }
        std::string out = *path + suffix;
        if (!check_len(out)) {
            return std::nullopt;
        }
        return out;
    }

private:
    std::string_view s_;
    std::size_t pos_ = 0;
    std::size_t budget_used_ = 0;
    bool out_overflow_ = false;

    [[nodiscard]] bool consume_budget(std::size_t bytes) noexcept {
        if (out_overflow_ || bytes > kMaxDemangledOutputLength - budget_used_) {
            out_overflow_ = true;
            return false;
        }
        budget_used_ += bytes;
        return true;
    }

    [[nodiscard]] bool check_len(std::string_view piece) noexcept {
        if (out_overflow_ || piece.size() > kMaxDemangledOutputLength) {
            out_overflow_ = true;
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<std::uint64_t> parse_decimal() noexcept {
        if (pos_ >= s_.size() || !is_ascii_digit(s_[pos_])) {
            return std::nullopt;
        }
        if (s_[pos_] == '0') {
            ++pos_;
            return std::uint64_t{0};
        }
        std::uint64_t v = 0;
        while (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
            const auto d = static_cast<std::uint64_t>(s_[pos_] - '0');
            if (v > (UINT64_MAX - d) / 10ULL) {
                return std::nullopt;
            }
            v = v * 10ULL + d;
            ++pos_;
        }
        return v;
    }

    [[nodiscard]] std::optional<std::uint64_t> parse_base62() noexcept {
        if (pos_ >= s_.size()) {
            return std::nullopt;
        }
        if (s_[pos_] == '_') {
            ++pos_;
            return std::uint64_t{0};
        }
        std::uint64_t v = 0;
        const std::size_t start = pos_;
        while (pos_ < s_.size() && s_[pos_] != '_') {
            const char c = s_[pos_];
            std::uint64_t digit = 0;
            if (c >= '0' && c <= '9') digit = static_cast<std::uint64_t>(c - '0');
            else if (c >= 'a' && c <= 'z') digit = static_cast<std::uint64_t>(10 + (c - 'a'));
            else if (c >= 'A' && c <= 'Z') digit = static_cast<std::uint64_t>(36 + (c - 'A'));
            else return std::nullopt;
            if (v > (UINT64_MAX - digit) / 62ULL) {
                return std::nullopt;
            }
            v = v * 62ULL + digit;
            ++pos_;
        }
        if (pos_ == start || pos_ >= s_.size() || s_[pos_] != '_') {
            return std::nullopt;
        }
        ++pos_;
        return v + 1ULL;
    }

    [[nodiscard]] std::optional<std::uint64_t> parse_opt_disambiguator() noexcept {
        if (pos_ < s_.size() && s_[pos_] == 's') {
            ++pos_;
            return parse_base62();
        }
        return std::uint64_t{0};
    }

    [[nodiscard]] std::optional<std::string> parse_ident() {
        if (out_overflow_) {
            return std::nullopt;
        }
        bool is_punycode = false;
        if (pos_ < s_.size() && s_[pos_] == 'u') {
            is_punycode = true;
            ++pos_;
        }
        const auto len = parse_decimal();
        if (!len) {
            return std::nullopt;
        }
        if (pos_ < s_.size() && s_[pos_] == '_') {
            ++pos_;
        }
        if (*len > s_.size() - pos_) {
            return std::nullopt;
        }
        const auto ident_len = static_cast<std::size_t>(*len);
        if (!consume_budget(ident_len)) {
            return std::nullopt;
        }
        const std::string_view raw = s_.substr(pos_, ident_len);
        pos_ += ident_len;
        (void)is_punycode;
        return std::string(raw);
    }

    [[nodiscard]] std::optional<std::string> parse_lifetime() {
        if (out_overflow_ || pos_ >= s_.size() || s_[pos_] != 'L') {
            return std::nullopt;
        }
        ++pos_;
        const auto idx = parse_base62();
        if (!idx) {
            return std::nullopt;
        }
        std::string out = (*idx == 0) ? std::string("'_") : (std::string("'l") + std::to_string(*idx));
        if (!consume_budget(out.size())) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<std::string> parse_const(std::size_t depth) {
        if (out_overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) {
            return std::nullopt;
        }
        if (s_[pos_] == 'B') {
            if (!consume_budget(1u)) {
                return std::nullopt;
            }
            ++pos_;
            const std::size_t backref_origin = pos_ - 1;
            const auto target = parse_base62();
            if (!target || *target >= backref_origin) {
                return std::nullopt;
            }
            const std::size_t saved = pos_;
            pos_ = static_cast<std::size_t>(*target);
            auto res = parse_const(depth + 1);
            pos_ = saved;
            if (!res || !check_len(*res)) {
                return std::nullopt;
            }
            return res;
        }
        if (s_[pos_] == 'p') {
            if (!consume_budget(1u)) {
                return std::nullopt;
            }
            ++pos_;
            return std::string("_");
        }
        // Primitive const `<type><opt-neg><hex>_`
        const std::size_t saved_ty = pos_;
        auto ty = parse_type(depth + 1);
        if (!ty) {
            pos_ = saved_ty;
            return std::nullopt;
        }
        bool neg = false;
        if (pos_ < s_.size() && s_[pos_] == 'n') {
            neg = true;
            ++pos_;
        }
        std::uint64_t val = 0;
        const std::size_t hex_start = pos_;
        while (pos_ < s_.size() && s_[pos_] != '_') {
            const std::uint32_t hv = hex_value(s_[pos_]);
            if (hv > 0xFu) {
                return std::nullopt;
            }
            val = (val << 4u) | hv;
            ++pos_;
        }
        if (pos_ >= s_.size() || s_[pos_] != '_') {
            return std::nullopt;
        }
        ++pos_;
        (void)hex_start;
        std::string rendered = (*ty == "bool")
            ? (val == 0 ? std::string("false") : std::string("true"))
            : ((neg ? std::string("-") : std::string{}) + std::to_string(val));
        if (!consume_budget(rendered.size())) {
            return std::nullopt;
        }
        return rendered;
    }

    [[nodiscard]] std::optional<std::string> parse_generic_arg(std::size_t depth) {
        if (out_overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) {
            return std::nullopt;
        }
        if (s_[pos_] == 'L') {
            return parse_lifetime();
        }
        if (s_[pos_] == 'K') {
            ++pos_;
            return parse_const(depth + 1);
        }
        return parse_type(depth + 1);
    }

    [[nodiscard]] std::optional<std::string> parse_path(std::size_t depth) {
        if (out_overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) {
            return std::nullopt;
        }
        const char tag = s_[pos_++];
        switch (tag) {
        case 'C': {
            if (!parse_opt_disambiguator()) return std::nullopt;
            return parse_ident();
        }
        case 'M': {
            // Inherent impl: `M <impl-path> <type>`
            if (!parse_opt_disambiguator()) return std::nullopt;
            if (!parse_path(depth + 1)) return std::nullopt;
            auto ty = parse_type(depth + 1);
            if (!ty || !consume_budget(2u)) return std::nullopt;
            std::string combined = "<" + *ty + ">";
            if (!check_len(combined)) return std::nullopt;
            return combined;
        }
        case 'X': {
            // Trait impl: `X <impl-path> <type> <trait-path>`
            if (!parse_opt_disambiguator()) return std::nullopt;
            if (!parse_path(depth + 1)) return std::nullopt;
            auto ty = parse_type(depth + 1);
            auto tr = parse_path(depth + 1);
            if (!ty || !tr || !consume_budget(6u)) return std::nullopt;
            std::string combined = "<" + *ty + " as " + *tr + ">";
            if (!check_len(combined)) return std::nullopt;
            return combined;
        }
        case 'Y': {
            auto ty = parse_type(depth + 1);
            auto tr = parse_path(depth + 1);
            if (!ty || !tr || !consume_budget(6u)) return std::nullopt;
            std::string combined = "<" + *ty + " as " + *tr + ">";
            if (!check_len(combined)) return std::nullopt;
            return combined;
        }
        case 'N': {
            if (pos_ >= s_.size()) return std::nullopt;
            const char ns = s_[pos_++];
            auto parent = parse_path(depth + 1);
            if (!parent) return std::nullopt;
            const auto disambig = parse_opt_disambiguator();
            if (!disambig) return std::nullopt;
            auto ident = parse_ident();
            if (!ident) return std::nullopt;

            std::string seg;
            std::size_t extra_wrapper = 0;
            if (ns == 'C') {
                if (ident->empty()) {
                    seg = "{closure#" + std::to_string(*disambig) + "}";
                    extra_wrapper = seg.size();
                } else {
                    seg = "{closure:" + *ident + "}";
                    extra_wrapper = 10u;
                }
            } else if (ns == 'S') {
                if (ident->empty()) {
                    seg = "{shim}";
                    extra_wrapper = 6u;
                } else {
                    seg = "{" + *ident + "}";
                    extra_wrapper = 2u;
                }
            } else {
                seg = *ident;
            }
            const std::size_t sep_bytes = seg.empty() ? 0u : 2u;
            if (!consume_budget(extra_wrapper + sep_bytes)) return std::nullopt;
            std::string combined = seg.empty() ? *parent : (*parent + "::" + seg);
            if (!check_len(combined)) return std::nullopt;
            return combined;
        }
        case 'I': {
            const bool is_value_path =
                (pos_ + 1 < s_.size() && s_[pos_] == 'N' &&
                 (s_[pos_ + 1] == 'v' || s_[pos_ + 1] == 'C' || s_[pos_ + 1] == 'S'));
            auto base = parse_path(depth + 1);
            if (!base) return std::nullopt;
            std::string args;
            bool first = true;
            while (pos_ < s_.size() && s_[pos_] != 'E') {
                auto arg = parse_generic_arg(depth + 1);
                if (!arg) return std::nullopt;
                if (!first) {
                    if (!consume_budget(2u)) return std::nullopt;
                    args += ", ";
                }
                first = false;
                args += *arg;
                if (!check_len(args)) return std::nullopt;
            }
            if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
            ++pos_;
            if (!consume_budget(is_value_path ? 4u : 2u)) return std::nullopt;
            std::string combined = *base + (is_value_path ? "::<" : "<") + args + ">";
            if (!check_len(combined)) return std::nullopt;
            return combined;
        }
        case 'B': {
            if (!consume_budget(1u)) {
                return std::nullopt;
            }
            const std::size_t backref_origin = pos_ - 1;
            const auto target = parse_base62();
            if (!target || *target >= backref_origin) {
                return std::nullopt;
            }
            const std::size_t saved = pos_;
            pos_ = static_cast<std::size_t>(*target);
            auto res = parse_path(depth + 1);
            pos_ = saved;
            if (!res || !check_len(*res)) {
                return std::nullopt;
            }
            return res;
        }
        default:
            return std::nullopt;
        }
    }

    [[nodiscard]] std::optional<std::string> emit_primitive(std::string_view lit) {
        if (!consume_budget(lit.size())) {
            return std::nullopt;
        }
        return std::string(lit);
    }

    [[nodiscard]] std::optional<std::string> parse_type(std::size_t depth) {
        if (out_overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) {
            return std::nullopt;
        }
        const char tag = s_[pos_++];
        switch (tag) {
        case 'a': return emit_primitive("i8");
        case 'b': return emit_primitive("bool");
        case 'c': return emit_primitive("char");
        case 'd': return emit_primitive("f64");
        case 'e': return emit_primitive("str");
        case 'f': return emit_primitive("f32");
        case 'h': return emit_primitive("u8");
        case 'i': return emit_primitive("isize");
        case 'j': return emit_primitive("usize");
        case 'l': return emit_primitive("i32");
        case 'm': return emit_primitive("u32");
        case 'n': return emit_primitive("i128");
        case 'o': return emit_primitive("u128");
        case 'p': return emit_primitive("_");
        case 's': return emit_primitive("i16");
        case 't': return emit_primitive("u16");
        case 'u': return emit_primitive("()");
        case 'v': return emit_primitive("...");
        case 'x': return emit_primitive("i64");
        case 'y': return emit_primitive("u64");
        case 'z': return emit_primitive("!");
        case 'R':
        case 'Q': {
            std::string lt;
            if (pos_ < s_.size() && s_[pos_] == 'L') {
                auto parsed_lt = parse_lifetime();
                if (!parsed_lt) return std::nullopt;
                if (*parsed_lt != "'_") {
                    if (!consume_budget(1u)) return std::nullopt;
                    lt = *parsed_lt + " ";
                }
            }
            auto inner = parse_type(depth + 1);
            if (!inner) return std::nullopt;
            if (!consume_budget(tag == 'Q' ? 5u : 1u)) return std::nullopt;
            std::string out = std::string("&") + lt + (tag == 'Q' ? "mut " : "") + *inner;
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'P':
        case 'O': {
            auto inner = parse_type(depth + 1);
            if (!inner) return std::nullopt;
            if (!consume_budget(tag == 'O' ? 5u : 7u)) return std::nullopt;
            std::string out = std::string(tag == 'O' ? "*mut " : "*const ") + *inner;
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'S': {
            auto inner = parse_type(depth + 1);
            if (!inner || !consume_budget(2u)) return std::nullopt;
            std::string out = "[" + *inner + "]";
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'A': {
            auto inner = parse_type(depth + 1);
            auto len = parse_const(depth + 1);
            if (!inner || !len || !consume_budget(4u)) return std::nullopt;
            std::string out = "[" + *inner + "; " + *len + "]";
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'T': {
            std::string elems;
            std::size_t count = 0;
            while (pos_ < s_.size() && s_[pos_] != 'E') {
                auto elem = parse_type(depth + 1);
                if (!elem) return std::nullopt;
                if (count > 0) {
                    if (!consume_budget(2u)) return std::nullopt;
                    elems += ", ";
                }
                elems += *elem;
                ++count;
                if (!check_len(elems)) return std::nullopt;
            }
            if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
            ++pos_;
            if (count == 1) {
                if (!consume_budget(1u)) return std::nullopt;
                elems += ",";
            }
            if (!consume_budget(2u)) return std::nullopt;
            std::string out = "(" + elems + ")";
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'F': {
            // Binder + unsafe + ABI + params + E + return
            if (pos_ < s_.size() && s_[pos_] == 'G') {
                ++pos_;
                if (!parse_base62()) return std::nullopt;
            }
            std::string prefix;
            if (pos_ < s_.size() && s_[pos_] == 'U') {
                if (!consume_budget(7u)) return std::nullopt;
                prefix += "unsafe ";
                ++pos_;
            }
            if (pos_ < s_.size() && s_[pos_] == 'K') {
                ++pos_;
                if (pos_ < s_.size() && s_[pos_] == 'C') {
                    if (!consume_budget(11u)) return std::nullopt;
                    ++pos_;
                    prefix += "extern \"C\" ";
                } else {
                    auto abi = parse_ident();
                    if (!abi || !consume_budget(10u)) return std::nullopt;
                    prefix += "extern \"" + *abi + "\" ";
                }
            }
            std::string params;
            bool first = true;
            while (pos_ < s_.size() && s_[pos_] != 'E') {
                auto p = parse_type(depth + 1);
                if (!p) return std::nullopt;
                if (!first) {
                    if (!consume_budget(2u)) return std::nullopt;
                    params += ", ";
                }
                first = false;
                params += *p;
                if (!check_len(params)) return std::nullopt;
            }
            if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
            ++pos_;
            auto ret = parse_type(depth + 1);
            if (!ret || !consume_budget(4u)) return std::nullopt;
            std::string out = prefix + "fn(" + params + ")";
            if (*ret != "()") {
                if (!consume_budget(4u)) return std::nullopt;
                out += " -> " + *ret;
            }
            if (!check_len(out)) return std::nullopt;
            return out;
        }
        case 'B': {
            if (!consume_budget(1u)) {
                return std::nullopt;
            }
            const std::size_t backref_origin = pos_ - 1;
            const auto target = parse_base62();
            if (!target || *target >= backref_origin) {
                return std::nullopt;
            }
            const std::size_t saved = pos_;
            pos_ = static_cast<std::size_t>(*target);
            auto res = parse_type(depth + 1);
            pos_ = saved;
            if (!res || !check_len(*res)) {
                return std::nullopt;
            }
            return res;
        }
        default:
            --pos_;
            return parse_path(depth + 1);
        }
    }
};

// ============================================================================
// Portable In-Tree Itanium C++ ABI Demangler (`_Z...` / `__Z...`)
// ============================================================================

class ItaniumPortableParser {
public:
    explicit ItaniumPortableParser(std::string_view s) noexcept : s_(s) {}

    [[nodiscard]] std::optional<std::string> parse() {
        if (s_.starts_with("__Z")) {
            pos_ = 3;
        } else if (s_.starts_with("_Z")) {
            pos_ = 2;
        } else {
            return std::nullopt;
        }

        if (pos_ >= s_.size()) {
            return std::nullopt;
        }

        // Special tables / typeinfo / vtable / guard variables
        if (s_[pos_] == 'T') {
            ++pos_;
            if (pos_ >= s_.size()) return std::nullopt;
            const char tk = s_[pos_++];
            std::string_view label;
            switch (tk) {
            case 'V': label = "vtable for "; break;
            case 'T': label = "VTT for "; break;
            case 'I': label = "typeinfo for "; break;
            case 'S': label = "typeinfo name for "; break;
            default: return std::nullopt;
            }
            auto ty = parse_type(0);
            if (!ty || overflow_ || pos_ != s_.size()) return std::nullopt;
            std::string out = std::string(label) + *ty;
            if (out.size() > kMaxDemangledOutputLength) return std::nullopt;
            return out;
        }
        if (s_.substr(pos_, 2) == "GV") {
            pos_ += 2;
            auto nm = parse_name(0, nullptr);
            if (!nm || overflow_ || pos_ != s_.size()) return std::nullopt;
            std::string out = "guard variable for " + *nm;
            if (out.size() > kMaxDemangledOutputLength) return std::nullopt;
            return out;
        }

        bool has_return_type = false;
        auto name_info = parse_name(0, &has_return_type);
        if (!name_info || overflow_) {
            return std::nullopt;
        }
        if (pos_ == s_.size()) {
            return *name_info;
        }

        // Bare function encoding: [return_type when template function] + param types
        std::string ret_prefix;
        if (has_return_type) {
            auto ret = parse_type(0);
            if (!ret || overflow_) return std::nullopt;
            ret_prefix = *ret + " ";
        }

        std::string params;
        bool first = true;
        while (pos_ < s_.size()) {
            auto p = parse_type(0);
            if (!p || overflow_) return std::nullopt;
            if (*p == "void" && first && pos_ == s_.size()) {
                break;
            }
            if (!first) params += ", ";
            first = false;
            params += *p;
            if (params.size() > kMaxDemangledOutputLength) {
                overflow_ = true;
                return std::nullopt;
            }
        }
        std::string out = ret_prefix + *name_info + "(" + params + ")" + trailing_cv_ref_;
        if (out.size() > kMaxDemangledOutputLength) {
            return std::nullopt;
        }
        return out;
    }

private:
    std::string_view s_;
    std::size_t pos_ = 0;
    std::vector<std::string> subs_;
    std::vector<std::string> tparams_;
    std::string trailing_cv_ref_;
    std::size_t budget_used_ = 0;
    bool overflow_ = false;

    [[nodiscard]] bool consume_budget(std::size_t bytes) noexcept {
        constexpr std::size_t kMaxExpansionBudget = kMaxDemangledOutputLength * 2u;
        if (overflow_ || bytes > kMaxExpansionBudget - budget_used_) {
            overflow_ = true;
            return false;
        }
        budget_used_ += bytes;
        return true;
    }

    void record_sub(std::string val) {
        if (subs_.size() < 256 && val.size() <= kMaxDemangledOutputLength) {
            subs_.push_back(std::move(val));
        }
    }

    [[nodiscard]] std::optional<std::size_t> parse_length() noexcept {
        if (pos_ >= s_.size() || !is_ascii_digit(s_[pos_])) {
            return std::nullopt;
        }
        std::size_t v = 0;
        while (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
            const auto d = static_cast<std::size_t>(s_[pos_] - '0');
            if (v > s_.size()) return std::nullopt;
            v = v * 10u + d;
            if (v > s_.size()) return std::nullopt;
            ++pos_;
        }
        return v;
    }

    [[nodiscard]] std::optional<std::string> parse_source_name() {
        const auto len = parse_length();
        if (!len || *len == 0 || pos_ + *len > s_.size() || !consume_budget(*len)) {
            return std::nullopt;
        }
        std::string out(s_.substr(pos_, *len));
        pos_ += *len;
        return out;
    }

    [[nodiscard]] std::optional<std::string> parse_operator_name(std::size_t depth) {
        if (overflow_ || depth > kMaxDemangleDepth || pos_ + 2 > s_.size()) return std::nullopt;
        const std::string_view op = s_.substr(pos_, 2);
        pos_ += 2;
        if (op == "nw") return std::string("operator new");
        if (op == "na") return std::string("operator new[]");
        if (op == "dl") return std::string("operator delete");
        if (op == "da") return std::string("operator delete[]");
        if (op == "ng") return std::string("operator-");
        if (op == "ad") return std::string("operator&");
        if (op == "de") return std::string("operator*");
        if (op == "co") return std::string("operator~");
        if (op == "pl") return std::string("operator+");
        if (op == "mi") return std::string("operator-");
        if (op == "ml") return std::string("operator*");
        if (op == "dv") return std::string("operator/");
        if (op == "rm") return std::string("operator%");
        if (op == "an") return std::string("operator&");
        if (op == "or") return std::string("operator|");
        if (op == "eo") return std::string("operator^");
        if (op == "aS") return std::string("operator=");
        if (op == "pL") return std::string("operator+=");
        if (op == "mI") return std::string("operator-=");
        if (op == "mL") return std::string("operator*=");
        if (op == "dV") return std::string("operator/=");
        if (op == "lS") return std::string("operator<<=");
        if (op == "rS") return std::string("operator>>=");
        if (op == "ls") return std::string("operator<<");
        if (op == "rs") return std::string("operator>>");
        if (op == "eq") return std::string("operator==");
        if (op == "ne") return std::string("operator!=");
        if (op == "lt") return std::string("operator<");
        if (op == "gt") return std::string("operator>");
        if (op == "le") return std::string("operator<=");
        if (op == "ge") return std::string("operator>=");
        if (op == "ss") return std::string("operator<=>");
        if (op == "nt") return std::string("operator!");
        if (op == "aa") return std::string("operator&&");
        if (op == "oo") return std::string("operator||");
        if (op == "pp") return std::string("operator++");
        if (op == "mm") return std::string("operator--");
        if (op == "cm") return std::string("operator,");
        if (op == "pm") return std::string("operator->*");
        if (op == "pt") return std::string("operator->");
        if (op == "cl") return std::string("operator()");
        if (op == "ix") return std::string("operator[]");
        if (op == "cv") {
            auto ty = parse_type(depth + 1);
            if (!ty) return std::nullopt;
            return "operator " + *ty;
        }
        pos_ -= 2;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string> parse_substitution() {
        if (overflow_ || pos_ >= s_.size() || s_[pos_] != 'S') return std::nullopt;
        ++pos_;
        if (pos_ >= s_.size()) return std::nullopt;
        const char c = s_[pos_];
        if (c == 't') { ++pos_; return consume_budget(3u) ? std::optional<std::string>("std") : std::nullopt; }
        if (c == 'a') { ++pos_; return consume_budget(14u) ? std::optional<std::string>("std::allocator") : std::nullopt; }
        if (c == 'b') { ++pos_; return consume_budget(17u) ? std::optional<std::string>("std::basic_string") : std::nullopt; }
        if (c == 's') { ++pos_; return consume_budget(11u) ? std::optional<std::string>("std::string") : std::nullopt; }
        if (c == 'i') { ++pos_; return consume_budget(12u) ? std::optional<std::string>("std::istream") : std::nullopt; }
        if (c == 'o') { ++pos_; return consume_budget(12u) ? std::optional<std::string>("std::ostream") : std::nullopt; }
        if (c == 'd') { ++pos_; return consume_budget(13u) ? std::optional<std::string>("std::iostream") : std::nullopt; }
        if (c == '_') {
            ++pos_;
            if (subs_.empty() || !consume_budget(subs_[0].size())) return std::nullopt;
            return subs_[0];
        }
        std::size_t idx = 0;
        while (pos_ < s_.size() && s_[pos_] != '_') {
            const char ch = s_[pos_++];
            std::size_t d = 0;
            if (ch >= '0' && ch <= '9') d = static_cast<std::size_t>(ch - '0');
            else if (ch >= 'A' && ch <= 'Z') d = static_cast<std::size_t>(10 + (ch - 'A'));
            else return std::nullopt;
            if (idx > subs_.size()) return std::nullopt;
            idx = idx * 36u + d;
        }
        if (pos_ >= s_.size() || s_[pos_] != '_') return std::nullopt;
        ++pos_;
        ++idx;
        if (idx >= subs_.size() || !consume_budget(subs_[idx].size())) return std::nullopt;
        return subs_[idx];
    }

    [[nodiscard]] std::optional<std::string> parse_template_args(std::size_t depth, bool record_tparams) {
        if (depth > kMaxDemangleDepth || pos_ >= s_.size() || s_[pos_] != 'I') {
            return std::nullopt;
        }
        ++pos_;
        std::string args;
        std::vector<std::string> collected;
        bool first = true;
        while (pos_ < s_.size() && s_[pos_] != 'E') {
            std::optional<std::string> arg;
            if (s_[pos_] == 'L') {
                ++pos_;
                auto lit_ty = parse_type(depth + 1);
                if (!lit_ty) return std::nullopt;
                bool neg = false;
                if (pos_ < s_.size() && s_[pos_] == 'n') { neg = true; ++pos_; }
                std::string digits;
                while (pos_ < s_.size() && s_[pos_] != 'E') {
                    digits.push_back(s_[pos_++]);
                }
                if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
                ++pos_;
                if (*lit_ty == "bool") {
                    arg = (digits == "0") ? std::string("false") : std::string("true");
                } else {
                    arg = (neg ? std::string("-") : std::string{}) + digits;
                }
            } else if (s_[pos_] == 'J') {
                // Parameter pack `J...E`
                ++pos_;
                while (pos_ < s_.size() && s_[pos_] != 'E') {
                    auto pack_elem = parse_type(depth + 1);
                    if (!pack_elem) return std::nullopt;
                    if (!first) args += ", ";
                    first = false;
                    args += *pack_elem;
                    collected.push_back(*pack_elem);
                }
                if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
                ++pos_;
                continue;
            } else {
                arg = parse_type(depth + 1);
            }
            if (!arg) return std::nullopt;
            if (!first) args += ", ";
            first = false;
            args += *arg;
            collected.push_back(*arg);
            if (args.size() > kMaxDemangledOutputLength) {
                overflow_ = true;
                return std::nullopt;
            }
        }
        if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
        ++pos_;
        if (record_tparams) {
            tparams_ = std::move(collected);
        }
        return "<" + args + ">";
    }

    [[nodiscard]] std::optional<std::string> parse_name(std::size_t depth, bool* out_is_template_fn) {
        if (depth > kMaxDemangleDepth || pos_ >= s_.size()) return std::nullopt;

        if (s_[pos_] == 'N') {
            ++pos_;
            std::string cv;
            while (pos_ < s_.size() && (s_[pos_] == 'r' || s_[pos_] == 'V' || s_[pos_] == 'K')) {
                if (s_[pos_] == 'K') cv += " const";
                else if (s_[pos_] == 'V') cv += " volatile";
                ++pos_;
            }
            if (pos_ < s_.size() && (s_[pos_] == 'R' || s_[pos_] == 'O')) {
                cv += (s_[pos_] == 'O') ? " &&" : " &";
                ++pos_;
            }
            if (depth == 0) {
                trailing_cv_ref_ = cv;
            }

            std::string current;
            std::string last_unqualified;
            bool last_was_template = false;
            while (pos_ < s_.size() && s_[pos_] != 'E') {
                std::optional<std::string> part;
                last_was_template = false;
                if (s_[pos_] == 'S') {
                    part = parse_substitution();
                    if (part) last_unqualified = *part;
                } else if (s_[pos_] == 'T') {
                    ++pos_;
                    std::size_t tidx = 0;
                    if (pos_ < s_.size() && s_[pos_] == '_') {
                        ++pos_;
                    } else {
                        while (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
                            if (tidx > tparams_.size()) return std::nullopt;
                            tidx = tidx * 10u + static_cast<std::size_t>(s_[pos_++] - '0');
                        }
                        if (pos_ >= s_.size() || s_[pos_] != '_') return std::nullopt;
                        ++pos_;
                        ++tidx;
                    }
                    if (tidx >= tparams_.size() || !consume_budget(tparams_[tidx].size())) return std::nullopt;
                    part = tparams_[tidx];
                } else if (s_[pos_] == 'C' && pos_ + 1 < s_.size() &&
                           (s_[pos_ + 1] >= '1' && s_[pos_ + 1] <= '5')) {
                    pos_ += 2;
                    part = last_unqualified;
                } else if (s_[pos_] == 'D' && pos_ + 1 < s_.size() &&
                           (s_[pos_ + 1] >= '0' && s_[pos_ + 1] <= '5')) {
                    pos_ += 2;
                    part = "~" + last_unqualified;
                } else if (s_.substr(pos_, 2) == "St") {
                    pos_ += 2;
                    part = std::string("std");
                    last_unqualified = "std";
                } else if (is_ascii_digit(s_[pos_])) {
                    part = parse_source_name();
                    if (part) last_unqualified = *part;
                } else {
                    part = parse_operator_name(depth + 1);
                }

                if (!part) return std::nullopt;

                // ABI tags `B<source-name>`
                while (pos_ < s_.size() && s_[pos_] == 'B') {
                    ++pos_;
                    auto tag = parse_source_name();
                    if (!tag) return std::nullopt;
                    *part += "[abi:" + *tag + "]";
                }

                current = current.empty() ? *part : (current + "::" + *part);
                if (pos_ < s_.size() && s_[pos_] != 'E' && s_[pos_] != 'I') {
                    record_sub(current);
                }

                if (pos_ < s_.size() && s_[pos_] == 'I') {
                    auto targs = parse_template_args(depth + 1, depth == 0);
                    if (!targs) return std::nullopt;
                    current += *targs;
                    last_was_template = true;
                    if (pos_ < s_.size() && s_[pos_] != 'E') {
                        record_sub(current);
                    }
                }
                if (current.size() > kMaxDemangledOutputLength) {
                    overflow_ = true;
                    return std::nullopt;
                }
            }
            if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
            ++pos_;
            if (out_is_template_fn != nullptr) {
                *out_is_template_fn = last_was_template;
            }
            return current;
        }

        // Unscoped `St` prefix (`_ZSt4cout`, `_ZSt4moveIRiE...`)
        std::string prefix;
        if (s_.substr(pos_, 2) == "St") {
            pos_ += 2;
            prefix = "std::";
        } else if (s_[pos_] == 'S') {
            auto sub = parse_substitution();
            if (!sub) return std::nullopt;
            prefix = *sub + "::";
        }

        std::optional<std::string> base;
        if (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
            base = parse_source_name();
        } else {
            base = parse_operator_name(depth + 1);
        }
        if (!base) return std::nullopt;

        while (pos_ < s_.size() && s_[pos_] == 'B') {
            ++pos_;
            auto tag = parse_source_name();
            if (!tag) return std::nullopt;
            *base += "[abi:" + *tag + "]";
        }

        std::string full = prefix + *base;
        bool is_tmpl = false;
        if (pos_ < s_.size() && s_[pos_] == 'I') {
            record_sub(full);
            auto targs = parse_template_args(depth + 1, depth == 0);
            if (!targs) return std::nullopt;
            full += *targs;
            is_tmpl = true;
        }
        if (out_is_template_fn != nullptr) {
            *out_is_template_fn = is_tmpl;
        }
        return full;
    }

    [[nodiscard]] std::optional<std::string> parse_type(std::size_t depth) {
        if (depth > kMaxDemangleDepth || pos_ >= s_.size()) return std::nullopt;

        const char c = s_[pos_];
        switch (c) {
        case 'v': ++pos_; return std::string("void");
        case 'w': ++pos_; return std::string("wchar_t");
        case 'b': ++pos_; return std::string("bool");
        case 'c': ++pos_; return std::string("char");
        case 'a': ++pos_; return std::string("signed char");
        case 'h': ++pos_; return std::string("unsigned char");
        case 's': ++pos_; return std::string("short");
        case 't': ++pos_; return std::string("unsigned short");
        case 'i': ++pos_; return std::string("int");
        case 'j': ++pos_; return std::string("unsigned int");
        case 'l': ++pos_; return std::string("long");
        case 'm': ++pos_; return std::string("unsigned long");
        case 'x': ++pos_; return std::string("long long");
        case 'y': ++pos_; return std::string("unsigned long long");
        case 'n': ++pos_; return std::string("__int128");
        case 'o': ++pos_; return std::string("unsigned __int128");
        case 'f': ++pos_; return std::string("float");
        case 'd': ++pos_; return std::string("double");
        case 'e': ++pos_; return std::string("long double");
        case 'z': ++pos_; return std::string("...");
        case 'D': {
            if (pos_ + 1 >= s_.size()) return std::nullopt;
            const char d2 = s_[pos_ + 1];
            pos_ += 2;
            if (d2 == 'a') return std::string("auto");
            if (d2 == 'c') return std::string("decltype(auto)");
            if (d2 == 'n') return std::string("std::nullptr_t");
            if (d2 == 'i') return std::string("char32_t");
            if (d2 == 's') return std::string("char16_t");
            if (d2 == 'u') return std::string("char8_t");
            pos_ -= 2;
            return std::nullopt;
        }
        case 'K':
        case 'V':
        case 'r': {
            std::string quals;
            while (pos_ < s_.size() && (s_[pos_] == 'r' || s_[pos_] == 'V' || s_[pos_] == 'K')) {
                if (s_[pos_] == 'K') quals += " const";
                else if (s_[pos_] == 'V') quals += " volatile";
                ++pos_;
            }
            auto inner = parse_type(depth + 1);
            if (!inner) return std::nullopt;
            std::string res = *inner + quals;
            record_sub(res);
            return res;
        }
        case 'P':
        case 'R':
        case 'O': {
            ++pos_;
            auto inner = parse_type(depth + 1);
            if (!inner) return std::nullopt;
            const char* suf = (c == 'P') ? "*" : (c == 'R' ? "&" : "&&");
            std::string res = *inner + suf;
            record_sub(res);
            return res;
        }
        case 'F': {
            ++pos_;
            auto ret = parse_type(depth + 1);
            if (!ret) return std::nullopt;
            std::string params;
            bool first = true;
            while (pos_ < s_.size() && s_[pos_] != 'E') {
                auto p = parse_type(depth + 1);
                if (!p) return std::nullopt;
                if (*p == "void" && first && pos_ < s_.size() && s_[pos_] == 'E') break;
                if (!first) params += ", ";
                first = false;
                params += *p;
                if (params.size() > kMaxDemangledOutputLength) {
                    overflow_ = true;
                    return std::nullopt;
                }
            }
            if (pos_ >= s_.size() || s_[pos_] != 'E') return std::nullopt;
            ++pos_;
            std::string res = *ret + " (" + params + ")";
            if (res.size() > kMaxDemangledOutputLength) {
                overflow_ = true;
                return std::nullopt;
            }
            record_sub(res);
            return res;
        }
        case 'T': {
            ++pos_;
            std::size_t tidx = 0;
            if (pos_ < s_.size() && s_[pos_] == '_') {
                ++pos_;
            } else {
                while (pos_ < s_.size() && is_ascii_digit(s_[pos_])) {
                    const auto d = static_cast<std::size_t>(s_[pos_++] - '0');
                    if (tidx > tparams_.size()) return std::nullopt;
                    tidx = tidx * 10u + d;
                }
                if (pos_ >= s_.size() || s_[pos_] != '_') return std::nullopt;
                ++pos_;
                ++tidx;
            }
            if (tidx >= tparams_.size() || !consume_budget(tparams_[tidx].size())) return std::nullopt;
            record_sub(tparams_[tidx]);
            return tparams_[tidx];
        }
        case 'S': {
            if (pos_ + 1 < s_.size() && s_[pos_ + 1] != 't') {
                auto sub = parse_substitution();
                if (!sub) return std::nullopt;
                if (pos_ < s_.size() && s_[pos_] == 'I') {
                    auto targs = parse_template_args(depth + 1, false);
                    if (!targs) return std::nullopt;
                    std::string res = *sub + *targs;
                    record_sub(res);
                    return res;
                }
                return sub;
            }
            auto nm = parse_name(depth + 1, nullptr);
            if (nm) record_sub(*nm);
            return nm;
        }
        default: {
            auto nm = parse_name(depth + 1, nullptr);
            if (nm) record_sub(*nm);
            return nm;
        }
        }
    }
};

// ============================================================================
// Deterministic In-Tree MSVC C++ Demangler (`?...`)
// ============================================================================

class MsvcDemangler {
public:
    explicit MsvcDemangler(std::string_view s) noexcept : s_(s) {}

    [[nodiscard]] std::optional<std::string> parse() {
        if (s_.size() < 2 || s_[0] != '?') {
            return std::nullopt;
        }
        pos_ = 1;

        // String literal `??_C@...`
        if (s_.substr(pos_, 3) == "?_C") {
            return std::string("`string'");
        }

        auto qname = parse_qualified_symbol_name(0);
        if (!qname || overflow_) {
            return std::nullopt;
        }

        if (qname->is_special_table) {
            return qname->full_name;
        }

        if (pos_ >= s_.size()) {
            return qname->full_name;
        }

        const char kind = s_[pos_++];
        // Data / static member variable (`0` private static, `1` protected static, `2` public static, `3` global, `4` guard)
        if (kind >= '0' && kind <= '4') {
            std::string prefix;
            if (kind == '0') prefix = "private: static ";
            else if (kind == '1') prefix = "protected: static ";
            else if (kind == '2') prefix = "public: static ";
            auto var_ty = parse_type(0, false);
            if (!var_ty) return qname->full_name;
            std::string cv = parse_cv_qualifiers();
            return prefix + *var_ty + cv + " " + qname->full_name;
        }
        // vftable / vbtable (`6` / `7`)
        if (kind == '6' || kind == '7') {
            return "const " + qname->full_name;
        }

        // Function encoding
        std::string access_prefix;
        bool is_member = true;
        bool is_static_member = false;
        switch (kind) {
        case 'A': case 'B': access_prefix = "private: "; break;
        case 'C': case 'D': access_prefix = "private: static "; is_static_member = true; break;
        case 'E': case 'F': access_prefix = "private: virtual "; break;
        case 'I': case 'J': access_prefix = "protected: "; break;
        case 'K': case 'L': access_prefix = "protected: static "; is_static_member = true; break;
        case 'M': case 'N': access_prefix = "protected: virtual "; break;
        case 'Q': case 'R': access_prefix = "public: "; break;
        case 'S': case 'T': access_prefix = "public: static "; is_static_member = true; break;
        case 'U': case 'V': access_prefix = "public: virtual "; break;
        case 'Y': case 'Z': is_member = false; break;
        default:
            return qname->full_name;
        }

        std::string this_cv;
        if (is_member && !is_static_member) {
            // Skip 64-bit pointer marker `E` if present
            if (pos_ < s_.size() && s_[pos_] == 'E') {
                ++pos_;
            }
            this_cv = parse_cv_qualifiers();
        }

        const std::string_view cc = parse_calling_convention();
        if (cc.empty()) {
            return qname->full_name;
        }

        // Return type (`@` means none for constructors/destructors)
        std::string ret_str;
        if (pos_ < s_.size() && s_[pos_] == '@') {
            ++pos_;
        } else {
            // Optional return-type storage qualifier `?A` / `?B` / `?C` / `?D`
            std::string ret_cv;
            if (pos_ < s_.size() && s_[pos_] == '?') {
                ++pos_;
                ret_cv = parse_cv_qualifiers();
            }
            auto rty = parse_type(0, false);
            if (!rty) {
                return qname->full_name;
            }
            if (qname->is_conversion_op) {
                qname->full_name += *rty + ret_cv;
            } else {
                ret_str = *rty + ret_cv + " ";
            }
        }

        // Parameter types up to `@Z` or `XZ` (void) or `ZZ` (...)
        std::string params;
        if (pos_ < s_.size() && s_[pos_] == 'X') {
            ++pos_;
            params = "void";
        } else {
            bool first = true;
            std::size_t param_guard = 0;
            while (pos_ < s_.size() && s_[pos_] != '@' && s_[pos_] != 'Z' && param_guard++ < 64) {
                auto pty = parse_type(0, true);
                if (!pty || overflow_) break;
                if (!first) params += ", ";
                first = false;
                params += *pty;
            }
            if (pos_ < s_.size() && s_[pos_] == '@') {
                ++pos_;
            }
            if (pos_ < s_.size() && s_[pos_] == 'Z' && !params.empty()) {
                // Normal parameter list terminator `Z`; check if another `Z` follows for varargs
                ++pos_;
                if (pos_ < s_.size() && s_[pos_] == 'Z') {
                    params += ", ...";
                    ++pos_;
                }
            }
        }

        std::string result = access_prefix + ret_str + std::string(cc) + " " +
                             qname->full_name + "(" + params + ")" + this_cv;
        if (result.size() > kMaxDemangledOutputLength) {
            return std::nullopt;
        }
        return result;
    }

private:
    struct QualifiedName {
        std::string full_name{};
        bool is_ctor_or_dtor = false;
        bool is_conversion_op = false;
        bool is_special_table = false;
    };

    std::string_view s_;
    std::size_t pos_ = 0;
    std::vector<std::string> name_backrefs_;
    std::vector<std::string> type_backrefs_;
    std::size_t budget_used_ = 0;
    bool overflow_ = false;

    [[nodiscard]] bool consume_budget(std::size_t bytes) noexcept {
        constexpr std::size_t kMaxExpansionBudget = kMaxDemangledOutputLength * 2u;
        if (overflow_ || bytes > kMaxExpansionBudget - budget_used_) {
            overflow_ = true;
            return false;
        }
        budget_used_ += bytes;
        return true;
    }

    [[nodiscard]] bool check_len(std::string_view piece) noexcept {
        if (overflow_ || piece.size() > kMaxDemangledOutputLength) {
            overflow_ = true;
            return false;
        }
        return true;
    }

    void add_name_backref(std::string_view name) {
        if (!name.empty() && name_backrefs_.size() < 10 && name.size() <= kMaxDemangledOutputLength) {
            name_backrefs_.emplace_back(name);
        }
    }

    void add_type_backref(std::string_view ty) {
        if (!ty.empty() && type_backrefs_.size() < 10 && ty.size() <= kMaxDemangledOutputLength) {
            type_backrefs_.emplace_back(ty);
        }
    }

    [[nodiscard]] std::string parse_cv_qualifiers() {
        if (pos_ >= s_.size()) return {};
        const char c = s_[pos_++];
        switch (c) {
        case 'A': return {};
        case 'B': case 'J': return " const";
        case 'C': case 'K': return " volatile";
        case 'D': case 'L': return " const volatile";
        default:
            --pos_;
            return {};
        }
    }

    [[nodiscard]] std::string_view parse_calling_convention() noexcept {
        if (pos_ >= s_.size()) return {};
        const char c = s_[pos_++];
        switch (c) {
        case 'A': case 'B': return "__cdecl";
        case 'C': case 'D': return "__pascal";
        case 'E': case 'F': return "__thiscall";
        case 'G': case 'H': return "__stdcall";
        case 'I': case 'J': return "__fastcall";
        case 'M': case 'N': return "__clrcall";
        case 'Q': case 'R': return "__vectorcall";
        default:
            --pos_;
            return {};
        }
    }

    [[nodiscard]] std::optional<std::string> parse_source_fragment(std::size_t depth, bool record_backref) {
        if (overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) return std::nullopt;
        if (is_ascii_digit(s_[pos_])) {
            const auto idx = static_cast<std::size_t>(s_[pos_++] - '0');
            if (idx >= name_backrefs_.size() || !consume_budget(name_backrefs_[idx].size())) {
                return std::nullopt;
            }
            return name_backrefs_[idx];
        }
        if (s_.substr(pos_, 2) == "?$") {
            return parse_template_name(depth + 1, record_backref);
        }
        const std::size_t at = s_.find('@', pos_);
        if (at == std::string_view::npos || at == pos_) {
            return std::nullopt;
        }
        const std::string_view frag = s_.substr(pos_, at - pos_);
        if (!consume_budget(frag.size())) {
            return std::nullopt;
        }
        pos_ = at + 1;
        if (record_backref) {
            add_name_backref(frag);
        }
        return std::string(frag);
    }

    [[nodiscard]] std::optional<std::string> parse_template_name(std::size_t depth, bool record_outer_backref) {
        if (overflow_ || depth > kMaxDemangleDepth || s_.substr(pos_, 2) != "?$") {
            return std::nullopt;
        }
        pos_ += 2;

        // MSVC templates use isolated name & type backref tables inside `?$Name@Args@`!
        auto saved_names = std::move(name_backrefs_);
        auto saved_types = std::move(type_backrefs_);
        name_backrefs_.clear();
        type_backrefs_.clear();

        auto base = parse_source_fragment(depth + 1, true);
        if (!base) {
            name_backrefs_ = std::move(saved_names);
            type_backrefs_ = std::move(saved_types);
            return std::nullopt;
        }

        std::string args;
        bool first = true;
        while (pos_ < s_.size() && s_[pos_] != '@') {
            std::optional<std::string> arg;
            if (s_[pos_] == '$' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '0') {
                // Integer template parameter `$0<encoded-int>`
                pos_ += 2;
                arg = parse_encoded_integer();
            } else if (s_.substr(pos_, 3) == "$$V" || s_.substr(pos_, 3) == "$$Z") {
                pos_ += 3;
                continue;
            } else {
                arg = parse_type(depth + 1, false);
            }
            if (!arg) {
                name_backrefs_ = std::move(saved_names);
                type_backrefs_ = std::move(saved_types);
                return std::nullopt;
            }
            if (!first) args += ", ";
            first = false;
            args += *arg;
            if (!check_len(args)) {
                name_backrefs_ = std::move(saved_names);
                type_backrefs_ = std::move(saved_types);
                return std::nullopt;
            }
        }
        if (pos_ >= s_.size() || s_[pos_] != '@') {
            name_backrefs_ = std::move(saved_names);
            type_backrefs_ = std::move(saved_types);
            return std::nullopt;
        }
        ++pos_;

        name_backrefs_ = std::move(saved_names);
        type_backrefs_ = std::move(saved_types);

        std::string inst = *base + "<" + args + ">";
        if (!check_len(inst)) {
            return std::nullopt;
        }
        if (record_outer_backref) {
            add_name_backref(inst);
        }
        return inst;
    }

    [[nodiscard]] std::optional<std::string> parse_encoded_integer() {
        if (pos_ >= s_.size()) return std::nullopt;
        bool neg = false;
        if (s_[pos_] == '?') {
            neg = true;
            ++pos_;
        }
        if (pos_ >= s_.size()) return std::nullopt;
        if (s_[pos_] >= '0' && s_[pos_] <= '9') {
            const int v = (s_[pos_++] - '0') + 1;
            return (neg ? std::string("-") : std::string{}) + std::to_string(v);
        }
        std::uint64_t val = 0;
        while (pos_ < s_.size() && s_[pos_] != '@') {
            const char c = s_[pos_++];
            if (c < 'A' || c > 'P') return std::nullopt;
            val = (val << 4u) | static_cast<std::uint64_t>(c - 'A');
        }
        if (pos_ >= s_.size() || s_[pos_] != '@') return std::nullopt;
        ++pos_;
        return (neg ? std::string("-") : std::string{}) + std::to_string(val);
    }

    [[nodiscard]] std::optional<std::string> parse_scope_chain(std::size_t depth) {
        if (overflow_ || depth > kMaxDemangleDepth) return std::nullopt;
        std::vector<std::string> scopes;
        while (pos_ < s_.size() && s_[pos_] != '@') {
            if (s_.substr(pos_, 2) == "?A") {
                // Anonymous namespace `?A0x...`@
                const std::size_t at = s_.find('@', pos_ + 2);
                if (at == std::string_view::npos || !consume_budget(21u)) return std::nullopt;
                pos_ = at + 1;
                scopes.emplace_back("`anonymous namespace'");
                continue;
            }
            auto sc = parse_source_fragment(depth + 1, true);
            if (!sc) return std::nullopt;
            scopes.push_back(std::move(*sc));
            if (scopes.size() > 64) return std::nullopt;
        }
        if (pos_ >= s_.size() || s_[pos_] != '@') return std::nullopt;
        ++pos_; // consume `@` ending scope list

        std::string joined;
        for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
            if (!joined.empty()) joined += "::";
            joined += *it;
            if (!check_len(joined)) return std::nullopt;
        }
        return joined;
    }

    [[nodiscard]] std::optional<QualifiedName> parse_qualified_symbol_name(std::size_t depth) {
        if (depth > kMaxDemangleDepth || pos_ >= s_.size()) return std::nullopt;

        QualifiedName res;
        std::string unqualified;
        enum class SpecialOp { None, Ctor, Dtor, Vftable, Vbtable, RttiTypeDesc, RttiBCD, RttiBCA, RttiCHD, RttiCOL };
        SpecialOp special = SpecialOp::None;

        if (s_[pos_] == '?') {
            ++pos_;
            if (pos_ >= s_.size()) return std::nullopt;
            if (s_[pos_] == '$') {
                --pos_; // restore `?$...`
                auto tmpl = parse_template_name(depth + 1, true);
                if (!tmpl) return std::nullopt;
                unqualified = std::move(*tmpl);
            } else if (s_[pos_] == '_') {
                ++pos_;
                if (pos_ >= s_.size()) return std::nullopt;
                const char ext = s_[pos_++];
                switch (ext) {
                case '0': unqualified = "operator/="; break;
                case '1': unqualified = "operator%="; break;
                case '2': unqualified = "operator>>="; break;
                case '3': unqualified = "operator<<="; break;
                case '4': unqualified = "operator&="; break;
                case '5': unqualified = "operator|="; break;
                case '6': unqualified = "operator^="; break;
                case '7': special = SpecialOp::Vftable; unqualified = "`vftable'"; break;
                case '8': special = SpecialOp::Vbtable; unqualified = "`vbtable'"; break;
                case 'E': unqualified = "`vector deleting destructor'"; break;
                case 'G': unqualified = "`scalar deleting destructor'"; break;
                case 'U': unqualified = "operator new[]"; break;
                case 'V': unqualified = "operator delete[]"; break;
                case 'R': {
                    if (pos_ >= s_.size()) return std::nullopt;
                    const char rk = s_[pos_++];
                    if (rk == '0') {
                        // `??_R0?AVFoo@@@8`
                        if (pos_ < s_.size() && s_[pos_] == '?') {
                            ++pos_;
                            (void)parse_cv_qualifiers();
                        }
                        auto rtti_ty = parse_type(depth + 1, false);
                        if (!rtti_ty) return std::nullopt;
                        res.full_name = *rtti_ty + " `RTTI Type Descriptor'";
                        res.is_special_table = true;
                        return res;
                    }
                    if (rk == '1') { special = SpecialOp::RttiBCD; unqualified = "`RTTI Base Class Descriptor'"; break; }
                    if (rk == '2') { special = SpecialOp::RttiBCA; unqualified = "`RTTI Base Class Array'"; break; }
                    if (rk == '3') { special = SpecialOp::RttiCHD; unqualified = "`RTTI Class Hierarchy Descriptor'"; break; }
                    if (rk == '4') { special = SpecialOp::RttiCOL; unqualified = "`RTTI Complete Object Locator'"; break; }
                    return std::nullopt;
                }
                default:
                    return std::nullopt;
                }
            } else {
                const char op = s_[pos_++];
                switch (op) {
                case '0': special = SpecialOp::Ctor; res.is_ctor_or_dtor = true; break;
                case '1': special = SpecialOp::Dtor; res.is_ctor_or_dtor = true; break;
                case '2': unqualified = "operator new"; break;
                case '3': unqualified = "operator delete"; break;
                case '4': unqualified = "operator="; break;
                case '5': unqualified = "operator>>"; break;
                case '6': unqualified = "operator<<"; break;
                case '7': unqualified = "operator!"; break;
                case '8': unqualified = "operator=="; break;
                case '9': unqualified = "operator!="; break;
                case 'A': unqualified = "operator[]"; break;
                case 'B': unqualified = "operator "; res.is_conversion_op = true; break;
                case 'C': unqualified = "operator->"; break;
                case 'D': unqualified = "operator*"; break;
                case 'E': unqualified = "operator++"; break;
                case 'F': unqualified = "operator--"; break;
                case 'G': unqualified = "operator-"; break;
                case 'H': unqualified = "operator+"; break;
                case 'I': unqualified = "operator&"; break;
                case 'J': unqualified = "operator->*"; break;
                case 'K': unqualified = "operator/"; break;
                case 'L': unqualified = "operator%"; break;
                case 'M': unqualified = "operator<"; break;
                case 'N': unqualified = "operator<="; break;
                case 'O': unqualified = "operator>"; break;
                case 'P': unqualified = "operator>="; break;
                case 'Q': unqualified = "operator,"; break;
                case 'R': unqualified = "operator()"; break;
                case 'S': unqualified = "operator~"; break;
                case 'T': unqualified = "operator^"; break;
                case 'U': unqualified = "operator|"; break;
                case 'V': unqualified = "operator&&"; break;
                case 'W': unqualified = "operator||"; break;
                case 'X': unqualified = "operator*="; break;
                case 'Y': unqualified = "operator+="; break;
                case 'Z': unqualified = "operator-="; break;
                default:
                    return std::nullopt;
                }
            }
        } else {
            auto frag = parse_source_fragment(depth + 1, true);
            if (!frag) return std::nullopt;
            unqualified = std::move(*frag);
        }

        auto scope = parse_scope_chain(depth + 1);
        if (!scope) return std::nullopt;

        auto strip_template_args = [](std::string_view s) -> std::string {
            const std::size_t lt = s.find('<');
            return std::string(lt == std::string_view::npos ? s : s.substr(0, lt));
        };
        auto innermost_scope = [](std::string_view sc) -> std::string {
            // Find last `::` at angle-bracket depth 0
            int angle = 0;
            std::size_t last_sep = std::string_view::npos;
            for (std::size_t i = 0; i + 1 < sc.size(); ++i) {
                if (sc[i] == '<') ++angle;
                else if (sc[i] == '>' && angle > 0) --angle;
                else if (angle == 0 && sc[i] == ':' && sc[i + 1] == ':') last_sep = i;
            }
            return std::string(last_sep == std::string_view::npos ? sc : sc.substr(last_sep + 2));
        };

        if (special == SpecialOp::Ctor) {
            unqualified = strip_template_args(innermost_scope(*scope));
        } else if (special == SpecialOp::Dtor) {
            unqualified = "~" + strip_template_args(innermost_scope(*scope));
        } else if (special == SpecialOp::Vftable || special == SpecialOp::Vbtable ||
                   special == SpecialOp::RttiBCA || special == SpecialOp::RttiCHD ||
                   special == SpecialOp::RttiCOL || special == SpecialOp::RttiBCD) {
            res.is_special_table = true;
            const std::string prefix = (special == SpecialOp::Vftable || special == SpecialOp::Vbtable ||
                                        special == SpecialOp::RttiCOL)
                ? "const "
                : "";
            res.full_name = prefix + (scope->empty() ? unqualified : (*scope + "::" + unqualified));
            if (!check_len(res.full_name)) return std::nullopt;
            return res;
        }

        res.full_name = scope->empty() ? unqualified : (*scope + "::" + unqualified);
        if (!check_len(res.full_name)) return std::nullopt;
        return res;
    }

    [[nodiscard]] std::optional<std::string> parse_type(std::size_t depth, bool record_param_backref) {
        if (overflow_ || depth > kMaxDemangleDepth || pos_ >= s_.size()) return std::nullopt;

        if (is_ascii_digit(s_[pos_])) {
            const auto idx = static_cast<std::size_t>(s_[pos_++] - '0');
            if (idx >= type_backrefs_.size() || !consume_budget(type_backrefs_[idx].size())) {
                return std::nullopt;
            }
            return type_backrefs_[idx];
        }

        const char c = s_[pos_++];
        std::optional<std::string> out;
        bool eligible_for_backref = false;

        switch (c) {
        case 'X': out = std::string("void"); break;
        case 'C': out = std::string("signed char"); break;
        case 'D': out = std::string("char"); break;
        case 'E': out = std::string("unsigned char"); break;
        case 'F': out = std::string("short"); break;
        case 'G': out = std::string("unsigned short"); break;
        case 'H': out = std::string("int"); break;
        case 'I': out = std::string("unsigned int"); break;
        case 'J': out = std::string("long"); break;
        case 'K': out = std::string("unsigned long"); break;
        case 'M': out = std::string("float"); break;
        case 'N': out = std::string("double"); break;
        case 'O': out = std::string("long double"); break;
        case 'Z': out = std::string("..."); break;
        case '_': {
            if (pos_ >= s_.size()) return std::nullopt;
            const char ext = s_[pos_++];
            eligible_for_backref = true;
            switch (ext) {
            case 'N': out = std::string("bool"); eligible_for_backref = false; break;
            case 'J': out = std::string("__int64"); break;
            case 'K': out = std::string("unsigned __int64"); break;
            case 'I': out = std::string("__int128"); break;
            case 'L': out = std::string("unsigned __int128"); break;
            case 'W': out = std::string("wchar_t"); break;
            case 'S': out = std::string("char16_t"); break;
            case 'U': out = std::string("char32_t"); break;
            case 'Q': out = std::string("char8_t"); break;
            default: return std::nullopt;
            }
            break;
        }
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'A':
        case 'B': {
            eligible_for_backref = true;
            const bool is_ref = (c == 'A' || c == 'B');
            const std::string outer_ptr_cv =
                (c == 'Q' || c == 'B') ? " const" :
                (c == 'R') ? " volatile" :
                (c == 'S') ? " const volatile" : "";
            if (pos_ < s_.size() && s_[pos_] == 'E') {
                ++pos_; // x64 64-bit pointer modifier
            }
            // Function pointer `P6<cc><ret><params>@Z`
            if (!is_ref && pos_ < s_.size() && s_[pos_] == '6') {
                ++pos_;
                const auto cc = parse_calling_convention();
                auto ret = parse_type(depth + 1, false);
                if (!ret) return std::nullopt;
                std::string fparams;
                if (pos_ < s_.size() && s_[pos_] == 'X') {
                    ++pos_;
                    fparams = "void";
                } else {
                    bool first = true;
                    while (pos_ < s_.size() && s_[pos_] != '@' && s_[pos_] != 'Z') {
                        auto fp = parse_type(depth + 1, false);
                        if (!fp) return std::nullopt;
                        if (!first) fparams += ", ";
                        first = false;
                        fparams += *fp;
                        if (!check_len(fparams)) return std::nullopt;
                    }
                    if (pos_ < s_.size() && s_[pos_] == '@') ++pos_;
                }
                if (pos_ < s_.size() && s_[pos_] == 'Z') ++pos_;
                out = *ret + " (" + std::string(cc) + " *" + outer_ptr_cv + ")(" + fparams + ")";
                if (!check_len(*out)) return std::nullopt;
                break;
            }
            const std::string pointee_cv = parse_cv_qualifiers();
            auto pointee = parse_type(depth + 1, false);
            if (!pointee) return std::nullopt;
            out = *pointee + pointee_cv + (is_ref ? " &" : (" *" + outer_ptr_cv));
            if (!check_len(*out)) return std::nullopt;
            break;
        }
        case '$': {
            if (pos_ >= s_.size()) return std::nullopt;
            if (s_[pos_] == '$') {
                ++pos_;
                if (pos_ >= s_.size()) return std::nullopt;
                const char m2 = s_[pos_++];
                if (m2 == 'Q' || m2 == 'R') {
                    // Rvalue reference `$$Q[E]<cv><type>`
                    eligible_for_backref = true;
                    if (pos_ < s_.size() && s_[pos_] == 'E') ++pos_;
                    const std::string rcv = parse_cv_qualifiers();
                    auto inner = parse_type(depth + 1, false);
                    if (!inner) return std::nullopt;
                    out = *inner + rcv + " &&";
                    if (!check_len(*out)) return std::nullopt;
                    break;
                }
                if (m2 == 'T') {
                    out = std::string("std::nullptr_t");
                    break;
                }
                if (m2 == 'C') {
                    const std::string cv = parse_cv_qualifiers();
                    auto inner = parse_type(depth + 1, false);
                    if (!inner) return std::nullopt;
                    out = *inner + cv;
                    if (!check_len(*out)) return std::nullopt;
                    break;
                }
            }
            return std::nullopt;
        }
        case 'U':
        case 'V':
        case 'T':
        case 'W': {
            eligible_for_backref = true;
            if (c == 'W' && pos_ < s_.size()) {
                ++pos_; // underlying enum type code (e.g. `4` = int)
            }
            auto frag = parse_source_fragment(depth + 1, true);
            if (!frag) return std::nullopt;
            auto sc = parse_scope_chain(depth + 1);
            if (!sc) return std::nullopt;
            out = sc->empty() ? *frag : (*sc + "::" + *frag);
            if (!check_len(*out)) return std::nullopt;
            break;
        }
        default:
            return std::nullopt;
        }

        if (out && record_param_backref && eligible_for_backref) {
            add_type_backref(*out);
        }
        return out;
    }
};

} // namespace

DemangleResult demangle_itanium_portable(std::string_view mangled) {
    if (mangled.empty() || mangled.size() > kMaxMangledInputLength) {
        return DemangleResult{.demangled = std::string(mangled), .scheme = ManglingScheme::None, .succeeded = false};
    }
    ItaniumPortableParser parser(mangled);
    if (auto parsed = parser.parse(); parsed && *parsed != mangled) {
        return DemangleResult{
            .demangled = std::move(*parsed),
            .scheme = ManglingScheme::Itanium,
            .succeeded = true,
        };
    }
    return DemangleResult{.demangled = std::string(mangled), .scheme = ManglingScheme::None, .succeeded = false};
}

DemangleResult demangle_symbol(std::string_view raw_name) {
    if (raw_name.empty() || raw_name.size() > kMaxMangledInputLength) {
        return DemangleResult{
            .demangled = std::string(raw_name),
            .scheme = ManglingScheme::None,
            .succeeded = false,
        };
    }

    const SplitSymbolWrapper parts = split_wrappers(raw_name);
    const std::string_view core = parts.core;
    if (core.empty()) {
        return DemangleResult{
            .demangled = std::string(raw_name),
            .scheme = ManglingScheme::None,
            .succeeded = false,
        };
    }

    const auto wrap = [&](std::string inner, ManglingScheme scheme) -> DemangleResult {
        const std::size_t total_len = parts.prefix.size() + inner.size() + parts.suffix.size();
        if (total_len > kMaxDemangledOutputLength) {
            return DemangleResult{
                .demangled = std::string(raw_name),
                .scheme = ManglingScheme::None,
                .succeeded = false,
            };
        }
        std::string full;
        full.reserve(total_len);
        full.append(parts.prefix);
        full.append(inner);
        full.append(parts.suffix);
        return DemangleResult{
            .demangled = std::move(full),
            .scheme = scheme,
            .succeeded = true,
        };
    };

    // 1. Rust v0 (`_R...` / `__R...`)
    if (core.starts_with("_R") || core.starts_with("__R")) {
        const std::string_view body = core.starts_with("__R") ? core.substr(3) : core.substr(2);
        RustV0Parser rv0(body);
        if (auto res = rv0.parse_symbol()) {
            return wrap(std::move(*res), ManglingScheme::RustV0);
        }
    }

    // 2. Rust Legacy (`_ZN...17h<16hex>E` or `$LT$`/`..` escapes)
    if (core.starts_with("_ZN") || core.starts_with("__ZN")) {
        if (auto rleg = try_demangle_rust_legacy(core)) {
            return wrap(std::move(*rleg), ManglingScheme::RustLegacy);
        }
    }

    // 3. Itanium C++ ABI (`_Z...` / `__Z...` / `_GLOBAL__sub_I_...`)
    if (core.starts_with("_GLOBAL__sub_I_") && core.size() > 15) {
        const std::string_view tail = core.substr(15);
        return wrap("(global constructors keyed to " + std::string(tail) + ")", ManglingScheme::Itanium);
    }
    if (core.starts_with("_Z") || core.starts_with("__Z")) {
#if PEELF_HAS_CXXABI_DEMANGLE
        const std::string_view cxa_in = core.starts_with("__Z") ? core.substr(1) : core;
        // Reject pathological length-prefix claims before invoking libstdc++/libc++ __cxa_demangle.
        const std::string null_terminated(cxa_in);
        int status = -1;
        std::unique_ptr<char, decltype(&std::free)> buf(
            abi::__cxa_demangle(null_terminated.c_str(), nullptr, nullptr, &status),
            &std::free);
        if (status == 0 && buf != nullptr) {
            std::string out(buf.get());
            if (!out.empty() && out != core && out.size() <= kMaxDemangledOutputLength) {
                return wrap(std::move(out), ManglingScheme::Itanium);
            }
        }
#endif
        if (auto fallback = demangle_itanium_portable(core); fallback.succeeded) {
            return wrap(std::move(fallback.demangled), ManglingScheme::Itanium);
        }
    }

    // 4. MSVC C++ (`?...`)
    if (core.starts_with('?')) {
        MsvcDemangler msvc(core);
        if (auto parsed = msvc.parse(); parsed && *parsed != core) {
            return wrap(std::move(*parsed), ManglingScheme::Msvc);
        }
    }

    return DemangleResult{
        .demangled = std::string(raw_name),
        .scheme = ManglingScheme::None,
        .succeeded = false,
    };
}

std::string demangle_or_raw(std::string_view raw_name) {
    DemangleResult res = demangle_symbol(raw_name);
    return std::move(res.demangled);
}

} // namespace peelf
