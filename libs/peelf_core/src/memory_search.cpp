#include <peelf/memory_search.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

namespace {

constexpr std::size_t kMaxPreviewBytes = 32u;
constexpr std::size_t kDefaultChunkBytes = 256u * 1024u;
constexpr std::size_t kFallbackPageBytes = 4096u;

[[nodiscard]] std::string_view trim_ascii_ws(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

[[nodiscard]] constexpr std::uint8_t ascii_lower_byte(std::uint8_t ch) noexcept {
    if (ch >= static_cast<std::uint8_t>('A') && ch <= static_cast<std::uint8_t>('Z')) {
        return static_cast<std::uint8_t>(ch + (static_cast<std::uint8_t>('a') - static_cast<std::uint8_t>('A')));
    }
    return ch;
}

[[nodiscard]] constexpr std::uint16_t ascii_lower_u16(std::uint16_t cu) noexcept {
    if (cu >= static_cast<std::uint16_t>('A') && cu <= static_cast<std::uint16_t>('Z')) {
        return static_cast<std::uint16_t>(cu + (static_cast<std::uint16_t>('a') - static_cast<std::uint16_t>('A')));
    }
    return cu;
}

[[nodiscard]] bool iequals_ascii(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (ascii_lower_byte(static_cast<std::uint8_t>(lhs[i])) !=
            ascii_lower_byte(static_cast<std::uint8_t>(rhs[i]))) {
            return false;
        }
    }
    return true;
}

struct ParsedNibble {
    std::uint8_t value{0};
    std::uint8_t mask{0};
    bool ok{false};
};

[[nodiscard]] constexpr ParsedNibble parse_hex_or_wildcard_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return ParsedNibble{static_cast<std::uint8_t>(c - '0'), 0x0Fu, true};
    }
    if (c >= 'a' && c <= 'f') {
        return ParsedNibble{static_cast<std::uint8_t>(10 + (c - 'a')), 0x0Fu, true};
    }
    if (c >= 'A' && c <= 'F') {
        return ParsedNibble{static_cast<std::uint8_t>(10 + (c - 'A')), 0x0Fu, true};
    }
    if (c == '?' || c == '*') {
        return ParsedNibble{0x00u, 0x00u, true};
    }
    return ParsedNibble{0u, 0u, false};
}

[[nodiscard]] std::vector<WildcardByte> exact_bytes_to_pattern(
    std::span<const std::uint8_t> encoded) {
    std::vector<WildcardByte> out;
    out.reserve(encoded.size());
    for (const std::uint8_t b : encoded) {
        out.push_back(WildcardByte{.value = b, .mask = 0xFFu});
    }
    return out;
}

[[nodiscard]] Result<std::vector<WildcardByte>> parse_hex_pattern(std::string_view text) {
    std::vector<WildcardByte> pattern;
    std::size_t pos = 0;

    while (pos < text.size()) {
        while (pos < text.size() &&
               (std::isspace(static_cast<unsigned char>(text[pos])) != 0 || text[pos] == ',')) {
            ++pos;
        }
        if (pos >= text.size()) {
            break;
        }

        const std::size_t start = pos;
        while (pos < text.size() &&
               std::isspace(static_cast<unsigned char>(text[pos])) == 0 &&
               text[pos] != ',') {
            ++pos;
        }

        std::string_view token = text.substr(start, pos - start);
        if (token == "*") {
            pattern.push_back(WildcardByte{.value = 0x00u, .mask = 0x00u});
            continue;
        }

        if (token.size() >= 2u && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
            token.remove_prefix(2);
            if (token.empty()) {
                return make_error("invalid empty hex prefix '0x' in pattern");
            }
        }

        if ((token.size() % 2u) != 0u) {
            return make_error("hex pattern contains an odd nibble count");
        }

        for (std::size_t i = 0; i < token.size(); i += 2u) {
            const ParsedNibble hi = parse_hex_or_wildcard_nibble(token[i]);
            const ParsedNibble lo = parse_hex_or_wildcard_nibble(token[i + 1u]);
            if (!hi.ok || !lo.ok) {
                return make_error("invalid character in hex search pattern");
            }
            const auto value = static_cast<std::uint8_t>((hi.value << 4u) | lo.value);
            const auto mask = static_cast<std::uint8_t>((hi.mask << 4u) | lo.mask);
            pattern.push_back(WildcardByte{.value = value, .mask = mask});
        }
    }

    if (pattern.empty()) {
        return make_error("hex search pattern contains no bytes");
    }
    return pattern;
}

struct ParsedMagnitude {
    bool negative{false};
    std::uint64_t magnitude{0};
};

[[nodiscard]] Result<ParsedMagnitude> parse_integer_magnitude(std::string_view raw_text) {
    std::string_view s = trim_ascii_ws(raw_text);
    if (s.empty()) {
        return make_error("integer search query is empty");
    }

    bool negative = false;
    if (s.front() == '-') {
        negative = true;
        s.remove_prefix(1);
    } else if (s.front() == '+') {
        s.remove_prefix(1);
    }

    if (s.empty()) {
        return make_error("integer search query is missing digits");
    }

    int base = 10;
    if (s.size() >= 2u && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s.remove_prefix(2);
        if (s.empty()) {
            return make_error("hex integer search query is missing digits after 0x");
        }
    }

    const unsigned char first = static_cast<unsigned char>(s.front());
    const bool valid_first =
        (base == 16) ? (std::isxdigit(first) != 0) : (std::isdigit(first) != 0);
    if (!valid_first) {
        return make_error("invalid digit in integer search query");
    }

    std::uint64_t mag = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), mag, base);
    if (ec == std::errc::result_out_of_range) {
        return make_error("integer search value overflows 64-bit range");
    }
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        return make_error("invalid integer search value");
    }

    return ParsedMagnitude{.negative = negative, .magnitude = mag};
}

[[nodiscard]] Result<std::uint64_t> parse_unsigned_bounded(std::string_view text,
                                                           std::uint64_t max_val) {
    const auto parsed = parse_integer_magnitude(text);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (parsed->negative && parsed->magnitude != 0u) {
        return make_error("negative value is out of range for unsigned integer search");
    }
    if (parsed->magnitude > max_val) {
        return make_error("unsigned integer value is out of range for target width");
    }
    return parsed->magnitude;
}

[[nodiscard]] Result<std::int64_t> parse_signed_bounded(std::string_view text,
                                                        std::uint64_t pos_max,
                                                        std::uint64_t neg_max) {
    const auto parsed = parse_integer_magnitude(text);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (parsed->negative) {
        if (parsed->magnitude > neg_max) {
            return make_error("signed integer value underflows target width");
        }
        if (parsed->magnitude == 0x8000'0000'0000'0000ull) {
            return std::numeric_limits<std::int64_t>::min();
        }
        return -static_cast<std::int64_t>(parsed->magnitude);
    }
    if (parsed->magnitude > pos_max) {
        return make_error("signed integer value overflows target width");
    }
    return static_cast<std::int64_t>(parsed->magnitude);
}

struct ExplicitSpecialFloat {
    bool is_explicit_nan{false};
    bool is_explicit_inf{false};
};

[[nodiscard]] ExplicitSpecialFloat classify_explicit_float_token(std::string_view trimmed) noexcept {
    std::string_view core = trimmed;
    if (!core.empty() && (core.front() == '+' || core.front() == '-')) {
        core.remove_prefix(1);
    }
    ExplicitSpecialFloat out{};
    out.is_explicit_nan = iequals_ascii(core, "nan");
    out.is_explicit_inf = iequals_ascii(core, "inf") || iequals_ascii(core, "infinity");
    return out;
}

[[nodiscard]] Result<float> parse_float32_value(std::string_view raw_text) {
    const std::string_view trimmed = trim_ascii_ws(raw_text);
    if (trimmed.empty()) {
        return make_error("float32 search query is empty");
    }
    const ExplicitSpecialFloat special = classify_explicit_float_token(trimmed);
    const std::string owned(trimmed);
    char* end_ptr = nullptr;
    errno = 0;
    const float val = std::strtof(owned.c_str(), &end_ptr);
    const int saved_errno = errno;

    if (end_ptr != owned.c_str() + owned.size()) {
        return make_error("invalid trailing characters in float32 search query");
    }
    if (std::isnan(val) && !special.is_explicit_nan) {
        return make_error("NaN float32 value requires explicit 'nan' token");
    }
    if ((std::isinf(val) || (saved_errno == ERANGE && val != 0.0f)) && !special.is_explicit_inf) {
        return make_error("float32 value overflows IEEE-754 single precision");
    }
    return val;
}

[[nodiscard]] Result<double> parse_float64_value(std::string_view raw_text) {
    const std::string_view trimmed = trim_ascii_ws(raw_text);
    if (trimmed.empty()) {
        return make_error("float64 search query is empty");
    }
    const ExplicitSpecialFloat special = classify_explicit_float_token(trimmed);
    const std::string owned(trimmed);
    char* end_ptr = nullptr;
    errno = 0;
    const double val = std::strtod(owned.c_str(), &end_ptr);
    const int saved_errno = errno;

    if (end_ptr != owned.c_str() + owned.size()) {
        return make_error("invalid trailing characters in float64 search query");
    }
    if (std::isnan(val) && !special.is_explicit_nan) {
        return make_error("NaN float64 value requires explicit 'nan' token");
    }
    if ((std::isinf(val) || (saved_errno == ERANGE && val != 0.0)) && !special.is_explicit_inf) {
        return make_error("float64 value overflows IEEE-754 double precision");
    }
    return val;
}

[[nodiscard]] std::string format_hex_bytes_preview(std::span<const std::uint8_t> bytes,
                                                   bool has_more) {
    static constexpr std::array<char, 16> kHex = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    std::string out;
    out.reserve(bytes.size() * 3u + 4u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0u) {
            out.push_back(' ');
        }
        const std::uint8_t b = bytes[i];
        out.push_back(kHex[static_cast<std::size_t>((b >> 4u) & 0x0Fu)]);
        out.push_back(kHex[static_cast<std::size_t>(b & 0x0Fu)]);
    }
    if (has_more) {
        out += " ...";
    }
    return out;
}

[[nodiscard]] std::string sanitize_utf8_preview(std::span<const std::uint8_t> bytes,
                                                bool has_more) {
    std::string out;
    out.reserve(bytes.size() + 4u);
    for (const std::uint8_t ch : bytes) {
        if (ch >= 0x20u && ch != 0x7Fu) {
            out.push_back(static_cast<char>(ch));
        } else if (ch == static_cast<std::uint8_t>('\t')) {
            out += "\\t";
        } else if (ch == static_cast<std::uint8_t>('\n')) {
            out += "\\n";
        } else if (ch == static_cast<std::uint8_t>('\r')) {
            out += "\\r";
        } else {
            out.push_back('.');
        }
    }
    if (has_more) {
        out += "...";
    }
    return out;
}

[[nodiscard]] std::string format_decoded_preview(std::span<const std::uint8_t> full_match,
                                                 const MemorySearchQuery& query) {
    const std::size_t capped_len = std::min(full_match.size(), kMaxPreviewBytes);
    const auto capped = full_match.subspan(0, capped_len);
    const bool has_more = full_match.size() > kMaxPreviewBytes;
    const EndianReader reader(full_match, query.endianness);

    switch (query.kind) {
        case SearchValueKind::HexPattern:
            return format_hex_bytes_preview(capped, has_more);
        case SearchValueKind::Int8: {
            const auto v = reader.read_i8(0);
            return v ? std::to_string(static_cast<int>(*v))
                     : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::UInt8: {
            const auto v = reader.read_u8(0);
            return v ? std::to_string(static_cast<unsigned int>(*v))
                     : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::Int16: {
            const auto v = reader.read_i16(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::UInt16: {
            const auto v = reader.read_u16(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::Int32: {
            const auto v = reader.read_i32(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::UInt32: {
            const auto v = reader.read_u32(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::Int64: {
            const auto v = reader.read_i64(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::UInt64: {
            const auto v = reader.read_u64(0);
            return v ? std::to_string(*v) : format_hex_bytes_preview(capped, has_more);
        }
        case SearchValueKind::Float32: {
            const auto v = reader.read_f32(0);
            if (!v) {
                return format_hex_bytes_preview(capped, has_more);
            }
            return std::format("{:.7g}", static_cast<double>(*v));
        }
        case SearchValueKind::Float64: {
            const auto v = reader.read_f64(0);
            if (!v) {
                return format_hex_bytes_preview(capped, has_more);
            }
            return std::format("{:.15g}", *v);
        }
        case SearchValueKind::Utf8Text:
            return sanitize_utf8_preview(capped, has_more);
        case SearchValueKind::Utf16Text: {
            const std::size_t max_units = std::min<std::size_t>(full_match.size() / 2u, 64u);
            const auto decoded = reader.read_utf16_string(0, max_units);
            if (!decoded) {
                return format_hex_bytes_preview(capped, has_more);
            }
            std::string out = *decoded;
            if ((full_match.size() / 2u) > max_units) {
                out += "...";
            }
            return out;
        }
    }
    return format_hex_bytes_preview(capped, has_more);
}

struct CompiledScanner {
    std::vector<WildcardByte> pattern;
    std::vector<std::uint8_t> folded_utf8;
    std::vector<std::uint16_t> folded_utf16;
    Endianness endianness{Endianness::Little};
    bool utf8_case_insensitive{false};
    bool utf16_case_insensitive{false};

    [[nodiscard]] std::size_t match_length() const noexcept { return pattern.size(); }

    [[nodiscard]] bool matches_at(std::span<const std::uint8_t> hay,
                                  std::size_t offset) const noexcept {
        if (utf8_case_insensitive) {
            const std::uint8_t* ptr = hay.data() + offset;
            for (std::size_t i = 0; i < folded_utf8.size(); ++i) {
                if (ascii_lower_byte(ptr[i]) != folded_utf8[i]) {
                    return false;
                }
            }
            return true;
        }

        if (utf16_case_insensitive) {
            const EndianReader reader(hay.subspan(offset, pattern.size()), endianness);
            for (std::size_t i = 0; i < folded_utf16.size(); ++i) {
                const auto cu = reader.read_u16(i * 2u);
                if (!cu || ascii_lower_u16(*cu) != folded_utf16[i]) {
                    return false;
                }
            }
            return true;
        }

        const std::uint8_t* ptr = hay.data() + offset;
        if (!pattern[0].matches(ptr[0])) {
            return false;
        }
        for (std::size_t i = 1u; i < pattern.size(); ++i) {
            if (!pattern[i].matches(ptr[i])) {
                return false;
            }
        }
        return true;
    }
};

[[nodiscard]] Result<CompiledScanner> build_compiled_scanner(const MemorySearchQuery& query) {
    auto pat_res = compile_search_pattern(query);
    if (!pat_res) {
        return std::unexpected(pat_res.error());
    }

    CompiledScanner scanner;
    scanner.pattern = std::move(*pat_res);
    scanner.endianness = query.endianness;

    if (!query.case_sensitive && query.kind == SearchValueKind::Utf8Text) {
        scanner.utf8_case_insensitive = true;
        scanner.folded_utf8.reserve(query.query_text.size());
        for (const char ch : query.query_text) {
            scanner.folded_utf8.push_back(ascii_lower_byte(static_cast<std::uint8_t>(ch)));
        }
    } else if (!query.case_sensitive && query.kind == SearchValueKind::Utf16Text) {
        scanner.utf16_case_insensitive = true;
        const std::vector<std::uint8_t> raw_u16 = encode_utf16(query.query_text, query.endianness);
        const EndianReader reader(raw_u16, query.endianness);
        const std::size_t unit_count = raw_u16.size() / 2u;
        scanner.folded_utf16.reserve(unit_count);
        for (std::size_t i = 0; i < unit_count; ++i) {
            const auto cu = reader.read_u16(i * 2u);
            scanner.folded_utf16.push_back(cu ? ascii_lower_u16(*cu) : 0u);
        }
    }

    return scanner;
}

void scan_window_into_report(std::span<const std::uint8_t> window,
                             std::uint64_t window_base_va,
                             std::uint64_t view_base_va,
                             std::uint64_t align_origin_va,
                             const MemorySearchQuery& query,
                             const CompiledScanner& scanner,
                             std::string_view region_label,
                             MemoryRegionKind region_kind,
                             MemorySearchReport& report) {
    const std::size_t pat_len = scanner.match_length();
    if (pat_len == 0u || window.size() < pat_len) {
        return;
    }

    const std::size_t alignment = std::max<std::size_t>(1u, query.alignment);
    const auto align_u64 = static_cast<std::uint64_t>(alignment);
    const std::uint64_t rel_origin = window_base_va - align_origin_va;
    const auto rem = static_cast<std::size_t>(rel_origin % align_u64);
    const std::size_t first_off = (rem == 0u) ? 0u : (alignment - rem);
    const std::size_t limit = window.size() - pat_len;

    for (std::size_t off = first_off; off <= limit; off += alignment) {
        if (!scanner.matches_at(window, off)) {
            continue;
        }
        if (report.hits.size() >= query.max_results) {
            report.truncated = true;
            return;
        }

        const std::uint64_t hit_va = window_base_va + static_cast<std::uint64_t>(off);
        const auto full_match = window.subspan(off, pat_len);
        const std::size_t preview_bytes = std::min(pat_len, kMaxPreviewBytes);

        MemorySearchHit hit;
        hit.address = hit_va;
        hit.view_offset = (hit_va >= view_base_va) ? (hit_va - view_base_va) : 0u;
        hit.match_length = pat_len;
        hit.region_kind = region_kind;
        hit.region_label = std::string(region_label);
        hit.matched_bytes.assign(full_match.begin(),
                                 full_match.begin() + static_cast<std::ptrdiff_t>(preview_bytes));
        hit.decoded_preview = format_decoded_preview(full_match, query);
        report.hits.push_back(std::move(hit));
    }
}

[[nodiscard]] std::string region_display_label(const MemoryRegion& reg) {
    if (!reg.module_name.empty()) {
        return reg.module_name;
    }
    if (!reg.pathname.empty()) {
        return reg.pathname;
    }
    return std::string(to_string(reg.kind));
}

[[nodiscard]] bool is_heap_candidate(const MemoryRegion& reg) noexcept {
    if (!reg.protection.readable || reg.protection.guarded ||
        reg.usage.is_reserved_only || reg.size() == 0u) {
        return false;
    }
    if (reg.kind == MemoryRegionKind::Heap) {
        return true;
    }
    return reg.kind == MemoryRegionKind::Anonymous &&
           reg.protection.readable &&
           reg.protection.writable &&
           !reg.protection.executable;
}

[[nodiscard]] bool is_untouched_large_anonymous_reservation(const MemoryRegion& reg) noexcept {
    static constexpr std::uint64_t kLargeAnonThreshold = 16ull * 1024ull * 1024ull;
    if (reg.kind != MemoryRegionKind::Anonymous || reg.size() < kLargeAnonThreshold) {
        return false;
    }
    if (!reg.usage.rss_bytes.has_value()) {
        return false;
    }
    return *reg.usage.rss_bytes == 0u && reg.usage.swap_bytes.value_or(0u) == 0u;
}

}  // namespace

Result<std::vector<WildcardByte>> compile_search_pattern(const MemorySearchQuery& query) {
    if (query.query_text.empty()) {
        return make_error("search query text must not be empty");
    }

    switch (query.kind) {
        case SearchValueKind::HexPattern:
            return parse_hex_pattern(query.query_text);

        case SearchValueKind::Int8: {
            const auto v = parse_signed_bounded(query.query_text, 0x7Full, 0x80ull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_i8(static_cast<std::int8_t>(*v)));
        }

        case SearchValueKind::UInt8: {
            const auto v = parse_unsigned_bounded(query.query_text, 0xFFull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_u8(static_cast<std::uint8_t>(*v)));
        }

        case SearchValueKind::Int16: {
            const auto v = parse_signed_bounded(query.query_text, 0x7FFFull, 0x8000ull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(
                encode_i16(static_cast<std::int16_t>(*v), query.endianness));
        }

        case SearchValueKind::UInt16: {
            const auto v = parse_unsigned_bounded(query.query_text, 0xFFFFull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(
                encode_u16(static_cast<std::uint16_t>(*v), query.endianness));
        }

        case SearchValueKind::Int32: {
            const auto v = parse_signed_bounded(query.query_text, 0x7FFF'FFFFull, 0x8000'0000ull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(
                encode_i32(static_cast<std::int32_t>(*v), query.endianness));
        }

        case SearchValueKind::UInt32: {
            const auto v = parse_unsigned_bounded(query.query_text, 0xFFFF'FFFFull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(
                encode_u32(static_cast<std::uint32_t>(*v), query.endianness));
        }

        case SearchValueKind::Int64: {
            const auto v = parse_signed_bounded(
                query.query_text, 0x7FFF'FFFF'FFFF'FFFFull, 0x8000'0000'0000'0000ull);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_i64(*v, query.endianness));
        }

        case SearchValueKind::UInt64: {
            const auto v = parse_unsigned_bounded(
                query.query_text, std::numeric_limits<std::uint64_t>::max());
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_u64(*v, query.endianness));
        }

        case SearchValueKind::Float32: {
            const auto v = parse_float32_value(query.query_text);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_f32(*v, query.endianness));
        }

        case SearchValueKind::Float64: {
            const auto v = parse_float64_value(query.query_text);
            if (!v) {
                return std::unexpected(v.error());
            }
            return exact_bytes_to_pattern(encode_f64(*v, query.endianness));
        }

        case SearchValueKind::Utf8Text: {
            std::vector<WildcardByte> out;
            out.reserve(query.query_text.size());
            for (const char ch : query.query_text) {
                const auto b = static_cast<std::uint8_t>(ch);
                const bool is_ascii_alpha =
                    (b >= static_cast<std::uint8_t>('A') && b <= static_cast<std::uint8_t>('Z')) ||
                    (b >= static_cast<std::uint8_t>('a') && b <= static_cast<std::uint8_t>('z'));
                if (!query.case_sensitive && is_ascii_alpha) {
                    out.push_back(WildcardByte{
                        .value = static_cast<std::uint8_t>(b & 0xDFu),
                        .mask = 0xDFu,
                    });
                } else {
                    out.push_back(WildcardByte{.value = b, .mask = 0xFFu});
                }
            }
            return out;
        }

        case SearchValueKind::Utf16Text: {
            const std::vector<std::uint8_t> encoded =
                encode_utf16(query.query_text, query.endianness);
            if (encoded.empty()) {
                return make_error("UTF-16 search query produced no code units");
            }
            if (query.case_sensitive) {
                return exact_bytes_to_pattern(encoded);
            }

            std::vector<WildcardByte> out;
            out.reserve(encoded.size());
            const EndianReader reader(encoded, query.endianness);
            const std::size_t units = encoded.size() / 2u;
            for (std::size_t i = 0; i < units; ++i) {
                const auto cu = reader.read_u16(i * 2u);
                const std::uint16_t u = cu ? *cu : 0u;
                const bool is_ascii_alpha =
                    (u >= static_cast<std::uint16_t>('A') && u <= static_cast<std::uint16_t>('Z')) ||
                    (u >= static_cast<std::uint16_t>('a') && u <= static_cast<std::uint16_t>('z'));
                if (is_ascii_alpha) {
                    const WildcardByte alpha_byte{
                        .value = static_cast<std::uint8_t>(u & 0xDFu),
                        .mask = 0xDFu,
                    };
                    const WildcardByte zero_byte{.value = 0x00u, .mask = 0xFFu};
                    if (query.endianness == Endianness::Little) {
                        out.push_back(alpha_byte);
                        out.push_back(zero_byte);
                    } else {
                        out.push_back(zero_byte);
                        out.push_back(alpha_byte);
                    }
                } else {
                    out.push_back(WildcardByte{.value = encoded[i * 2u], .mask = 0xFFu});
                    out.push_back(WildcardByte{.value = encoded[i * 2u + 1u], .mask = 0xFFu});
                }
            }
            return out;
        }
    }

    return make_error("unsupported search value kind");
}

Result<MemorySearchReport> search_buffer(std::span<const std::uint8_t> buffer,
                                         std::uint64_t base_address,
                                         const MemorySearchQuery& query,
                                         std::string_view region_label,
                                         MemoryRegionKind kind) {
    const auto scanner_res = build_compiled_scanner(query);
    if (!scanner_res) {
        return std::unexpected(scanner_res.error());
    }

    MemorySearchReport report;
    report.regions_scanned = 1u;
    report.bytes_scanned = static_cast<std::uint64_t>(buffer.size());

    scan_window_into_report(buffer,
                            base_address,
                            base_address,
                            base_address,
                            query,
                            *scanner_res,
                            region_label,
                            kind,
                            report);

    report.status = SubsystemStatus::available(
        "buffer_search",
        report.truncated ? "search stopped at max_results limit" : "buffer scan complete");
    return report;
}

Result<MemorySearchReport> search_process_memory(IProcessSession& session,
                                                 std::span<const MemoryRegion> regions,
                                                 const MemorySearchQuery& query,
                                                 std::optional<MemoryRegion> selected_region,
                                                 std::optional<ModuleInfo> active_module) {
    const auto scanner_res = build_compiled_scanner(query);
    if (!scanner_res) {
        return std::unexpected(scanner_res.error());
    }

    std::vector<MemoryRegion> candidates;
    std::optional<std::uint64_t> active_module_base;

    MemorySearchReport report;

    switch (query.scope) {
        case SearchScope::Heap:
            for (const MemoryRegion& reg : regions) {
                if (!is_heap_candidate(reg) || is_untouched_large_anonymous_reservation(reg)) {
                    continue;
                }
                if (query.max_region_bytes > 0u && reg.size() > query.max_region_bytes) {
                    ++report.regions_skipped_oversized;
                    continue;
                }
                candidates.push_back(reg);
            }
            break;

        case SearchScope::SelectedRegion:
            if (!selected_region.has_value()) {
                return make_error("selected region is required for SelectedRegion search scope");
            }
            if (selected_region->protection.readable &&
                !selected_region->protection.guarded &&
                !selected_region->usage.is_reserved_only &&
                selected_region->size() > 0u) {
                candidates.push_back(*selected_region);
            }
            break;

        case SearchScope::ActiveModule: {
            if (!active_module.has_value() || active_module->size == 0u) {
                return make_error("active module is required for ActiveModule search scope");
            }
            const std::uint64_t mod_start = active_module->base_address;
            const std::uint64_t mod_end = active_module->end_address();
            active_module_base = mod_start;

            for (const MemoryRegion& reg : regions) {
                if (!reg.protection.readable || reg.protection.guarded ||
                    reg.usage.is_reserved_only || reg.size() == 0u) {
                    continue;
                }
                const std::uint64_t clamped_start = std::max(reg.start_address, mod_start);
                const std::uint64_t clamped_end = std::min(reg.end_address, mod_end);
                if (clamped_end > clamped_start) {
                    MemoryRegion slice = reg;
                    slice.start_address = clamped_start;
                    slice.end_address = clamped_end;
                    if (slice.module_name.empty()) {
                        slice.module_name = active_module->name;
                    }
                    candidates.push_back(std::move(slice));
                }
            }
            break;
        }

        case SearchScope::AllReadable:
            for (const MemoryRegion& reg : regions) {
                if (!reg.protection.readable || reg.protection.guarded ||
                    reg.usage.is_reserved_only || reg.size() == 0u ||
                    is_untouched_large_anonymous_reservation(reg)) {
                    continue;
                }
                if (query.max_region_bytes > 0u && reg.size() > query.max_region_bytes) {
                    ++report.regions_skipped_oversized;
                    continue;
                }
                candidates.push_back(reg);
            }
            break;
    }

    if (candidates.empty()) {
        report.status = SubsystemStatus::available(
            "process_memory_search",
            "no readable non-guarded regions matched the selected search scope");
        return report;
    }

    const std::size_t pat_len = scanner_res->match_length();
    const std::size_t overlap = (pat_len > 0u) ? (pat_len - 1u) : 0u;
    const std::size_t chunk_cap = std::max(kDefaultChunkBytes, pat_len * 2u);

    std::vector<std::uint8_t> read_buf(chunk_cap);
    std::vector<std::uint8_t> carry;
    std::vector<std::uint8_t> work;
    carry.reserve(overlap);
    work.reserve(overlap + chunk_cap);

    bool had_read_failure = false;

    for (const MemoryRegion& reg : candidates) {
        if (report.truncated) {
            break;
        }

        const std::string label = region_display_label(reg);
        const std::uint64_t view_base = active_module_base.value_or(reg.start_address);
        const std::uint64_t align_origin = reg.start_address;

        carry.clear();
        bool region_read_any = false;

        const auto process_contiguous_span = [&](std::uint64_t chunk_va,
                                                 std::span<const std::uint8_t> fresh) {
            region_read_any = true;
            report.bytes_scanned += static_cast<std::uint64_t>(fresh.size());

            const std::uint64_t window_base_va =
                chunk_va - static_cast<std::uint64_t>(carry.size());
            work.clear();
            work.insert(work.end(), carry.begin(), carry.end());
            work.insert(work.end(), fresh.begin(), fresh.end());

            scan_window_into_report(work,
                                    window_base_va,
                                    view_base,
                                    align_origin,
                                    query,
                                    *scanner_res,
                                    label,
                                    reg.kind,
                                    report);

            if (overlap > 0u) {
                const std::size_t keep = std::min(overlap, work.size());
                const auto tail_start =
                    work.end() - static_cast<std::ptrdiff_t>(keep);
                carry.assign(tail_start, work.end());
            } else {
                carry.clear();
            }
        };

        std::uint64_t cursor = reg.start_address;
        while (cursor < reg.end_address && !report.truncated) {
            if (query.max_total_bytes > 0u && report.bytes_scanned >= query.max_total_bytes) {
                report.truncated = true;
                break;
            }
            const std::uint64_t rem_budget =
                (query.max_total_bytes > 0u) ? (query.max_total_bytes - report.bytes_scanned)
                                             : (reg.end_address - cursor);
            const std::uint64_t rem_bytes = std::min(reg.end_address - cursor, rem_budget);
            const auto req_size = static_cast<std::size_t>(
                std::min<std::uint64_t>(static_cast<std::uint64_t>(chunk_cap), rem_bytes));

            auto fast = session.read_memory(cursor, std::span<std::uint8_t>(read_buf.data(), req_size));
            if (fast && *fast > 0u) {
                const std::size_t got = std::min(*fast, req_size);
                process_contiguous_span(
                    cursor, std::span<const std::uint8_t>(read_buf.data(), got));
                cursor += static_cast<std::uint64_t>(got);

                if (got < req_size && !report.truncated) {
                    // Probe the remaining span page-by-page so unreadable holes do not abort the region.
                    const std::uint64_t fallback_end =
                        cursor + static_cast<std::uint64_t>(req_size - got);
                    while (cursor < fallback_end && !report.truncated) {
                        const auto step = static_cast<std::size_t>(std::min<std::uint64_t>(
                            static_cast<std::uint64_t>(kFallbackPageBytes),
                            fallback_end - cursor));
                        auto page_res = session.read_memory(
                            cursor, std::span<std::uint8_t>(read_buf.data(), step));
                        if (page_res && *page_res > 0u) {
                            const std::size_t page_got = std::min(*page_res, step);
                            process_contiguous_span(
                                cursor,
                                std::span<const std::uint8_t>(read_buf.data(), page_got));
                            if (page_got < step) {
                                had_read_failure = true;
                                carry.clear();
                            }
                        } else {
                            had_read_failure = true;
                            carry.clear();
                        }
                        cursor += static_cast<std::uint64_t>(step);
                    }
                }
                continue;
            }

            had_read_failure = true;
            if (req_size > kFallbackPageBytes) {
                const std::uint64_t fallback_end = cursor + static_cast<std::uint64_t>(req_size);
                while (cursor < fallback_end && !report.truncated) {
                    const auto step = static_cast<std::size_t>(std::min<std::uint64_t>(
                        static_cast<std::uint64_t>(kFallbackPageBytes),
                        fallback_end - cursor));
                    auto page_res = session.read_memory(
                        cursor, std::span<std::uint8_t>(read_buf.data(), step));
                    if (page_res && *page_res > 0u) {
                        const std::size_t page_got = std::min(*page_res, step);
                        process_contiguous_span(
                            cursor, std::span<const std::uint8_t>(read_buf.data(), page_got));
                        if (page_got < step) {
                            carry.clear();
                        }
                    } else {
                        carry.clear();
                    }
                    cursor += static_cast<std::uint64_t>(step);
                }
            } else {
                carry.clear();
                cursor += static_cast<std::uint64_t>(req_size);
            }
        }

        if (region_read_any) {
            ++report.regions_scanned;
        }
    }

    if (had_read_failure) {
        if (report.regions_scanned == 0u && report.bytes_scanned == 0u) {
            report.status = SubsystemStatus::unavailable(
                "process_memory_search",
                "failed to read candidate process memory regions");
        } else {
            report.status = SubsystemStatus::partial(
                "process_memory_search",
                "some memory regions or pages could not be read");
        }
    } else {
        report.status = SubsystemStatus::available(
            "process_memory_search",
            report.truncated ? "search stopped at max_results limit" : "memory scan complete");
    }

    return report;
}

}  // namespace peelf
