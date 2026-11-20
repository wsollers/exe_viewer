#include <peelf/patch_bundle.hpp>

#include "atomic_file_writer.hpp"

#include <peelf/sha256.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace peelf {

namespace {

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out(sv);
    for (char& ch : out) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return out;
}

[[nodiscard]] bool is_valid_sha256_hex(std::string_view sv) noexcept {
    if (sv.size() != 64u) {
        return false;
    }
    for (const char ch : sv) {
        if (!std::isxdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string format_to_json_token(Format fmt) {
    switch (fmt) {
        case Format::PE:      return "PE";
        case Format::ELF:     return "ELF";
        case Format::MachO:   return "MachO";
        case Format::Unknown: return "Unknown";
    }
    return "Unknown";
}

[[nodiscard]] Format parse_format_token(std::string_view s) {
    const std::string low = to_lower_ascii(s);
    if (low == "pe") return Format::PE;
    if (low == "elf") return Format::ELF;
    if (low == "macho" || low == "mach-o") return Format::MachO;
    return Format::Unknown;
}

[[nodiscard]] Architecture parse_arch_token(std::string_view s) {
    const std::string low = to_lower_ascii(s);
    if (low == "x86") return Architecture::X86;
    if (low == "x86-64" || low == "x86_64" || low == "amd64") return Architecture::X86_64;
    if (low == "arm" || low == "arm32") return Architecture::ARM;
    if (low == "arm64" || low == "aarch64") return Architecture::ARM64;
    if (low == "riscv32" || low == "risc-v 32") return Architecture::RISCV32;
    if (low == "riscv64" || low == "risc-v 64") return Architecture::RISCV64;
    if (low == "powerpc" || low == "ppc32" || low == "powerpc32") return Architecture::PowerPC;
    if (low == "powerpc64" || low == "ppc64" || low == "powerpc 64") return Architecture::PowerPC64;
    if (low == "mips32" || low == "mips") return Architecture::MIPS32;
    if (low == "mips64") return Architecture::MIPS64;
    return Architecture::Unknown;
}

void append_json_escaped(std::ostringstream& os, std::string_view sv) {
    os << '"';
    for (const char raw_ch : sv) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        switch (ch) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b";  break;
            case '\f': os << "\\f";  break;
            case '\n': os << "\\n";  break;
            case '\r': os << "\\r";  break;
            case '\t': os << "\\t";  break;
            default:
                if (ch < 0x20u) {
                    os << std::format("\\u{:04x}", static_cast<unsigned int>(ch));
                } else {
                    os << static_cast<char>(ch);
                }
                break;
        }
    }
    os << '"';
}

// ---------------------------------------------------------------------------
// Minimal strict RFC 8259 JSON DOM parser for `.pepatch.json`
// ---------------------------------------------------------------------------

struct JsonValue {
    using Object = std::map<std::string, JsonValue, std::less<>>;
    using Array = std::vector<JsonValue>;

    std::variant<std::monostate, bool, std::uint64_t, std::int64_t, std::string, Array, Object> data{};

    [[nodiscard]] bool is_null() const noexcept { return std::holds_alternative<std::monostate>(data); }
    [[nodiscard]] const Object* as_object() const noexcept { return std::get_if<Object>(&data); }
    [[nodiscard]] const Array* as_array() const noexcept { return std::get_if<Array>(&data); }
    [[nodiscard]] const std::string* as_string() const noexcept { return std::get_if<std::string>(&data); }

    [[nodiscard]] std::optional<std::uint64_t> as_u64() const noexcept {
        if (const auto* u = std::get_if<std::uint64_t>(&data)) {
            return *u;
        }
        if (const auto* i = std::get_if<std::int64_t>(&data); i != nullptr && *i >= 0) {
            return static_cast<std::uint64_t>(*i);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::int64_t> as_i64() const noexcept {
        if (const auto* i = std::get_if<std::int64_t>(&data)) {
            return *i;
        }
        if (const auto* u = std::get_if<std::uint64_t>(&data);
            u != nullptr &&
            *u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return static_cast<std::int64_t>(*u);
        }
        return std::nullopt;
    }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view text) : text_(text) {}

    [[nodiscard]] Result<JsonValue> parse_document() {
        skip_ws();
        auto val = parse_value(0);
        if (!val.has_value()) {
            return val;
        }
        skip_ws();
        if (pos_ != text_.size()) {
            return make_error(std::format("Unexpected trailing JSON content at byte {}", pos_));
        }
        return val;
    }

private:
    static constexpr std::uint32_t kMaxDepth = 32u;

    void skip_ws() noexcept {
        while (pos_ < text_.size()) {
            const char ch = text_[pos_];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    [[nodiscard]] Result<JsonValue> parse_value(std::uint32_t depth) {
        if (depth > kMaxDepth) {
            return make_error("JSON nesting depth exceeded maximum");
        }
        skip_ws();
        if (pos_ >= text_.size()) {
            return make_error("Unexpected end of JSON input");
        }
        const char ch = text_[pos_];
        if (ch == '{') return parse_object(depth + 1u);
        if (ch == '[') return parse_array(depth + 1u);
        if (ch == '"') {
            auto s = parse_string();
            if (!s.has_value()) return std::unexpected(s.error());
            return JsonValue{.data = std::move(*s)};
        }
        if (ch == 't') {
            if (text_.substr(pos_).starts_with("true")) {
                pos_ += 4u;
                return JsonValue{.data = true};
            }
            return make_error("Invalid JSON literal starting with 't'");
        }
        if (ch == 'f') {
            if (text_.substr(pos_).starts_with("false")) {
                pos_ += 5u;
                return JsonValue{.data = false};
            }
            return make_error("Invalid JSON literal starting with 'f'");
        }
        if (ch == 'n') {
            if (text_.substr(pos_).starts_with("null")) {
                pos_ += 4u;
                return JsonValue{.data = std::monostate{}};
            }
            return make_error("Invalid JSON literal starting with 'n'");
        }
        if (ch == '-' || (ch >= '0' && ch <= '9')) {
            return parse_number();
        }
        return make_error(std::format("Unexpected character '{}' at JSON offset {}", ch, pos_));
    }

    [[nodiscard]] Result<std::string> parse_string() {
        if (pos_ >= text_.size() || text_[pos_] != '"') {
            return make_error("Expected '\"' at start of JSON string");
        }
        ++pos_;
        std::string out;
        while (pos_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            if (ch == '"') {
                return out;
            }
            if (ch < 0x20u) {
                return make_error("Unescaped control character in JSON string");
            }
            if (ch != '\\') {
                out.push_back(static_cast<char>(ch));
                continue;
            }
            if (pos_ >= text_.size()) {
                return make_error("Unterminated escape sequence in JSON string");
            }
            const char esc = text_[pos_++];
            switch (esc) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    auto parse_hex4 = [this]() -> Result<std::uint32_t> {
                        if (pos_ + 4u > text_.size()) {
                            return make_error("Incomplete \\uXXXX escape in JSON string");
                        }
                        std::uint32_t unit = 0;
                        for (std::size_t i = 0; i < 4u; ++i) {
                            const char hc = text_[pos_++];
                            unit <<= 4u;
                            if (hc >= '0' && hc <= '9') {
                                unit |= static_cast<std::uint32_t>(hc - '0');
                            } else if (hc >= 'a' && hc <= 'f') {
                                unit |= static_cast<std::uint32_t>(10 + (hc - 'a'));
                            } else if (hc >= 'A' && hc <= 'F') {
                                unit |= static_cast<std::uint32_t>(10 + (hc - 'A'));
                            } else {
                                return make_error("Invalid hex digit in \\uXXXX JSON escape");
                            }
                        }
                        return unit;
                    };

                    const auto first = parse_hex4();
                    if (!first) {
                        return std::unexpected(first.error());
                    }
                    std::uint32_t codepoint = *first;
                    if (codepoint >= 0xD800u && codepoint <= 0xDBFFu) {
                        if (pos_ + 2u > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1u] != 'u') {
                            return make_error("Unpaired UTF-16 high surrogate in JSON string");
                        }
                        pos_ += 2u;
                        const auto low = parse_hex4();
                        if (!low) {
                            return std::unexpected(low.error());
                        }
                        if (*low < 0xDC00u || *low > 0xDFFFu) {
                            return make_error("Invalid UTF-16 low surrogate following high surrogate in JSON string");
                        }
                        codepoint = 0x10000u + (((codepoint - 0xD800u) << 10u) | (*low - 0xDC00u));
                    } else if (codepoint >= 0xDC00u && codepoint <= 0xDFFFu) {
                        return make_error("Unpaired UTF-16 low surrogate in JSON string");
                    }

                    if (codepoint <= 0x7Fu) {
                        out.push_back(static_cast<char>(codepoint));
                    } else if (codepoint <= 0x7FFu) {
                        out.push_back(static_cast<char>(0xC0u | ((codepoint >> 6u) & 0x1Fu)));
                        out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
                    } else if (codepoint <= 0xFFFFu) {
                        out.push_back(static_cast<char>(0xE0u | ((codepoint >> 12u) & 0x0Fu)));
                        out.push_back(static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3Fu)));
                        out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
                    } else {
                        out.push_back(static_cast<char>(0xF0u | ((codepoint >> 18u) & 0x07u)));
                        out.push_back(static_cast<char>(0x80u | ((codepoint >> 12u) & 0x3Fu)));
                        out.push_back(static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3Fu)));
                        out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
                    }
                    break;
                }
                default:
                    return make_error(std::format("Invalid JSON escape '\\{}'", esc));
            }
        }
        return make_error("Unterminated JSON string");
    }

    [[nodiscard]] Result<JsonValue> parse_number() {
        const std::size_t start = pos_;
        const bool negative = (text_[pos_] == '-');
        if (negative) {
            ++pos_;
        }
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            return make_error("Invalid JSON number");
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
            return make_error("Floating-point numbers are not valid for integer patch bundle fields");
        }
        const std::string_view token = text_.substr(start, pos_ - start);
        if (negative) {
            std::int64_t val = 0;
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), val);
            if (ec != std::errc{} || ptr != token.data() + token.size()) {
                return make_error(std::format("JSON integer out of range: '{}'", token));
            }
            return JsonValue{.data = val};
        }
        std::uint64_t uval = 0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), uval);
        if (ec != std::errc{} || ptr != token.data() + token.size()) {
            return make_error(std::format("JSON unsigned integer out of range: '{}'", token));
        }
        return JsonValue{.data = uval};
    }

    [[nodiscard]] Result<JsonValue> parse_array(std::uint32_t depth) {
        ++pos_; // '['
        JsonValue::Array arr;
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            ++pos_;
            return JsonValue{.data = std::move(arr)};
        }
        for (;;) {
            auto elem = parse_value(depth);
            if (!elem.has_value()) {
                return elem;
            }
            arr.push_back(std::move(*elem));
            skip_ws();
            if (pos_ >= text_.size()) {
                return make_error("Unterminated JSON array");
            }
            if (text_[pos_] == ']') {
                ++pos_;
                return JsonValue{.data = std::move(arr)};
            }
            if (text_[pos_] != ',') {
                return make_error("Expected ',' or ']' in JSON array");
            }
            ++pos_;
        }
    }

    [[nodiscard]] Result<JsonValue> parse_object(std::uint32_t depth) {
        ++pos_; // '{'
        JsonValue::Object obj;
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            ++pos_;
            return JsonValue{.data = std::move(obj)};
        }
        for (;;) {
            skip_ws();
            auto key = parse_string();
            if (!key.has_value()) {
                return std::unexpected(key.error());
            }
            skip_ws();
            if (pos_ >= text_.size() || text_[pos_] != ':') {
                return make_error("Expected ':' after JSON object key");
            }
            ++pos_;
            auto val = parse_value(depth);
            if (!val.has_value()) {
                return val;
            }
            obj[*key] = std::move(*val);
            skip_ws();
            if (pos_ >= text_.size()) {
                return make_error("Unterminated JSON object");
            }
            if (text_[pos_] == '}') {
                ++pos_;
                return JsonValue{.data = std::move(obj)};
            }
            if (text_[pos_] != ',') {
                return make_error("Expected ',' or '}' in JSON object");
            }
            ++pos_;
        }
    }

    std::string_view text_{};
    std::size_t pos_{0};
};

[[nodiscard]] const JsonValue* find_field(const JsonValue::Object& obj, std::string_view key) noexcept {
    const auto it = obj.find(key);
    return it == obj.end() ? nullptr : &it->second;
}

} // namespace

std::string bytes_to_hex_string(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (std::uint8_t b : bytes) {
        out += std::format("{:02x}", b);
    }
    return out;
}

Result<std::vector<std::uint8_t>> hex_string_to_bytes(std::string_view hex) {
    std::string compact;
    compact.reserve(hex.size());
    for (std::size_t i = 0; i < hex.size(); ++i) {
        const char ch = hex[i];
        if (std::isspace(static_cast<unsigned char>(ch)) || ch == '_' || ch == '-') {
            continue;
        }
        if (ch == '0' && i + 1u < hex.size() && (hex[i + 1u] == 'x' || hex[i + 1u] == 'X')) {
            ++i;
            continue;
        }
        compact.push_back(ch);
    }
    if ((compact.size() % 2u) != 0u) {
        return make_error("Hex byte string must contain an even number of hex digits");
    }

    std::vector<std::uint8_t> out;
    out.reserve(compact.size() / 2u);
    for (std::size_t i = 0; i < compact.size(); i += 2u) {
        const auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        const int hi = nibble(compact[i]);
        const int lo = nibble(compact[i + 1u]);
        if (hi < 0 || lo < 0) {
            return make_error(std::format("Invalid hex byte '{}{}'", compact[i], compact[i + 1u]));
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

Result<std::string> compute_paged_image_original_sha256(const PagedBinaryImage& image) {
    Sha256Hasher hasher;
    constexpr std::uint64_t kChunkSize = 64u * 1024u;
    std::uint64_t offset = 0;
    const std::uint64_t total = image.size();
    while (offset < total) {
        const std::uint64_t chunk = std::min(kChunkSize, total - offset);
        auto bytes = image.read_original(offset, chunk);
        if (!bytes.has_value()) {
            return std::unexpected(bytes.error());
        }
        hasher.update(*bytes);
        offset += chunk;
    }
    return hasher.finalize_hex();
}

Result<PatchBundle> export_patch_bundle_from_image(
    const PagedBinaryImage& editable,
    const IBinaryImage* parsed_image,
    std::string name,
    std::string description) {
    auto sha = compute_paged_image_original_sha256(editable);
    if (!sha.has_value()) {
        return std::unexpected(sha.error());
    }

    PatchBundle bundle;
    bundle.schema_version = kPatchBundleSchemaVersion;
    bundle.name = !name.empty() ? std::move(name) : editable.path().filename().string();
    bundle.description = std::move(description);
    bundle.target_format = parsed_image != nullptr ? parsed_image->format() : Format::Unknown;
    bundle.target_arch = parsed_image != nullptr ? parsed_image->architecture() : Architecture::Unknown;
    bundle.expected_sha256 = std::move(*sha);
    bundle.expected_size = editable.size();

    const std::vector<PatchInterval> intervals = editable.changed_intervals();
    bundle.entries.reserve(intervals.size());
    for (std::size_t i = 0; i < intervals.size(); ++i) {
        const PatchInterval& iv = intervals[i];
        PatchBundleEntry entry;
        entry.offset = iv.offset;
        if (parsed_image != nullptr) {
            entry.virtual_address = parsed_image->file_offset_to_virtual_address(iv.offset);
        }
        entry.label = std::format("Patch #{} @ {:#x}", i + 1u, iv.offset);
        entry.original_bytes = iv.original;
        entry.patched_bytes = iv.patched;
        entry.timestamp_unix_ms = iv.timestamp_unix_ms;
        entry.note = iv.note;
        bundle.entries.push_back(std::move(entry));
    }
    return bundle;
}

std::string encode_patch_bundle_json(const PatchBundle& bundle) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"schema_version\": " << bundle.schema_version << ",\n";
    os << "  \"name\": ";
    append_json_escaped(os, bundle.name);
    os << ",\n  \"description\": ";
    append_json_escaped(os, bundle.description);
    os << ",\n  \"target_format\": ";
    append_json_escaped(os, format_to_json_token(bundle.target_format));
    os << ",\n  \"target_arch\": ";
    append_json_escaped(os, to_string(bundle.target_arch));
    os << ",\n  \"expected_sha256\": ";
    append_json_escaped(os, to_lower_ascii(bundle.expected_sha256));
    os << ",\n  \"expected_size\": " << bundle.expected_size << ",\n";
    os << "  \"entries\": [";
    for (std::size_t i = 0; i < bundle.entries.size(); ++i) {
        const PatchBundleEntry& e = bundle.entries[i];
        os << (i == 0 ? "\n" : ",\n");
        os << "    {\n";
        os << "      \"offset\": " << e.offset << ",\n";
        if (e.virtual_address.has_value()) {
            os << "      \"virtual_address\": " << *e.virtual_address << ",\n";
        } else {
            os << "      \"virtual_address\": null,\n";
        }
        os << "      \"label\": ";
        append_json_escaped(os, e.label);
        os << ",\n      \"note\": ";
        append_json_escaped(os, e.note);
        os << ",\n      \"timestamp_unix_ms\": " << e.timestamp_unix_ms;
        os << ",\n      \"asm_source\": ";
        if (e.asm_source.has_value()) {
            append_json_escaped(os, *e.asm_source);
        } else {
            os << "null";
        }
        os << ",\n      \"original_bytes_hex\": ";
        append_json_escaped(os, bytes_to_hex_string(e.original_bytes));
        os << ",\n      \"patched_bytes_hex\": ";
        append_json_escaped(os, bytes_to_hex_string(e.patched_bytes));
        os << "\n    }";
    }
    if (!bundle.entries.empty()) {
        os << "\n  ";
    }
    os << "]\n}\n";
    return os.str();
}

Result<PatchBundle> decode_patch_bundle_json(std::string_view json_text) {
    JsonParser parser(json_text);
    auto root_res = parser.parse_document();
    if (!root_res.has_value()) {
        return std::unexpected(root_res.error());
    }
    const auto* obj = root_res->as_object();
    if (obj == nullptr) {
        return make_error("Patch bundle root JSON value must be an object");
    }

    PatchBundle bundle;
    if (const JsonValue* sv = find_field(*obj, "schema_version")) {
        const auto ver = sv->as_u64();
        if (!ver.has_value() || *ver == 0 || *ver > kPatchBundleSchemaVersion) {
            return make_error("Unsupported or invalid patch bundle schema_version");
        }
        bundle.schema_version = static_cast<std::uint32_t>(*ver);
    } else {
        return make_error("Patch bundle JSON is missing required field 'schema_version'");
    }

    if (const JsonValue* v = find_field(*obj, "name")) {
        if (const auto* s = v->as_string()) bundle.name = *s;
    }
    if (const JsonValue* v = find_field(*obj, "description")) {
        if (const auto* s = v->as_string()) bundle.description = *s;
    }
    if (const JsonValue* v = find_field(*obj, "target_format")) {
        if (const auto* s = v->as_string()) bundle.target_format = parse_format_token(*s);
    }
    if (const JsonValue* v = find_field(*obj, "target_arch")) {
        if (const auto* s = v->as_string()) bundle.target_arch = parse_arch_token(*s);
    }

    if (const JsonValue* v = find_field(*obj, "expected_sha256")) {
        const auto* s = v->as_string();
        if (s == nullptr || !is_valid_sha256_hex(*s)) {
            return make_error("'expected_sha256' must be a 64-character SHA-256 hex string");
        }
        bundle.expected_sha256 = to_lower_ascii(*s);
    } else {
        return make_error("Patch bundle JSON is missing required field 'expected_sha256'");
    }

    if (const JsonValue* v = find_field(*obj, "expected_size")) {
        const auto sz = v->as_u64();
        if (!sz.has_value()) {
            return make_error("'expected_size' must be a non-negative integer");
        }
        bundle.expected_size = *sz;
    } else {
        return make_error("Patch bundle JSON is missing required field 'expected_size'");
    }

    const JsonValue* entries_val = find_field(*obj, "entries");
    if (entries_val == nullptr || entries_val->as_array() == nullptr) {
        return make_error("Patch bundle JSON is missing required 'entries' array");
    }

    const auto& arr = *entries_val->as_array();
    bundle.entries.reserve(arr.size());
    for (std::size_t i = 0; i < arr.size(); ++i) {
        const auto* eobj = arr[i].as_object();
        if (eobj == nullptr) {
            return make_error(std::format("Patch bundle entry [{}] must be a JSON object", i));
        }

        PatchBundleEntry entry;
        const JsonValue* off_val = find_field(*eobj, "offset");
        if (off_val == nullptr || !off_val->as_u64().has_value()) {
            return make_error(std::format("Entry [{}] is missing valid integer 'offset'", i));
        }
        entry.offset = *off_val->as_u64();

        if (const JsonValue* va_val = find_field(*eobj, "virtual_address");
            va_val != nullptr && !va_val->is_null()) {
            const auto va = va_val->as_u64();
            if (!va.has_value()) {
                return make_error(std::format("Entry [{}] has invalid 'virtual_address'", i));
            }
            entry.virtual_address = *va;
        }

        if (const JsonValue* lbl = find_field(*eobj, "label")) {
            if (const auto* s = lbl->as_string()) entry.label = *s;
        }

        if (const JsonValue* note_val = find_field(*eobj, "note");
            note_val != nullptr && !note_val->is_null()) {
            const auto* s = note_val->as_string();
            if (s == nullptr) {
                return make_error(std::format("Entry [{}] 'note' must be string or null", i));
            }
            entry.note = *s;
        }

        if (const JsonValue* ts_val = find_field(*eobj, "timestamp_unix_ms");
            ts_val != nullptr && !ts_val->is_null()) {
            const auto ts = ts_val->as_i64();
            if (!ts.has_value()) {
                return make_error(std::format("Entry [{}] has invalid 'timestamp_unix_ms'", i));
            }
            entry.timestamp_unix_ms = *ts;
        }

        if (const JsonValue* asm_val = find_field(*eobj, "asm_source");
            asm_val != nullptr && !asm_val->is_null()) {
            const auto* s = asm_val->as_string();
            if (s == nullptr) {
                return make_error(std::format("Entry [{}] 'asm_source' must be string or null", i));
            }
            entry.asm_source = *s;
        }

        const JsonValue* orig_val = find_field(*eobj, "original_bytes_hex");
        const JsonValue* patch_val = find_field(*eobj, "patched_bytes_hex");
        if (orig_val == nullptr || orig_val->as_string() == nullptr ||
            patch_val == nullptr || patch_val->as_string() == nullptr) {
            return make_error(std::format(
                "Entry [{}] must contain string 'original_bytes_hex' and 'patched_bytes_hex'", i));
        }

        auto orig_bytes = hex_string_to_bytes(*orig_val->as_string());
        if (!orig_bytes.has_value()) {
            return make_error(std::format("Entry [{}] original_bytes_hex: {}",
                                          i, orig_bytes.error().message));
        }
        auto patched_bytes = hex_string_to_bytes(*patch_val->as_string());
        if (!patched_bytes.has_value()) {
            return make_error(std::format("Entry [{}] patched_bytes_hex: {}",
                                          i, patched_bytes.error().message));
        }
        entry.original_bytes = std::move(*orig_bytes);
        entry.patched_bytes = std::move(*patched_bytes);
        bundle.entries.push_back(std::move(entry));
    }

    return bundle;
}

Result<void> save_patch_bundle_file(const PatchBundle& bundle,
                                    const std::filesystem::path& path) {
    if (path.empty()) {
        return make_error("Patch bundle output path is empty");
    }
    const std::string encoded = encode_patch_bundle_json(bundle);
    return detail::write_text_atomically(path, encoded, true, true);
}

Result<PatchBundle> load_patch_bundle_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return make_error(std::format("Failed to open patch bundle '{}'", path.string()));
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (!in.good() && !in.eof()) {
        return make_error(std::format("Failed reading patch bundle '{}'", path.string()));
    }
    return decode_patch_bundle_json(ss.str());
}

Result<PatchBundlePreview> preview_patch_bundle(
    const PatchBundle& bundle,
    const PagedBinaryImage& target,
    const PatchBundleApplyOptions& options,
    const IProcessSession* live_session) {
    if (live_session != nullptr) {
        return make_error(
            "Live process sessions are strictly read-only; patch bundles cannot be previewed or applied to live memory");
    }

    auto sha_res = compute_paged_image_original_sha256(target);
    if (!sha_res.has_value()) {
        return std::unexpected(sha_res.error());
    }

    PatchBundlePreview preview;
    preview.actual_sha256 = to_lower_ascii(*sha_res);
    preview.actual_size = target.size();
    preview.size_matches = (bundle.expected_size == 0) || (bundle.expected_size == preview.actual_size);
    const bool valid_expected_sha256 = is_valid_sha256_hex(bundle.expected_sha256);
    preview.sha256_matches =
        valid_expected_sha256 && (to_lower_ascii(bundle.expected_sha256) == preview.actual_sha256);

    preview.entry_previews.reserve(bundle.entries.size());

    // Precompute pairwise overlaps among valid in-bounds entries in O(N log N).
    struct IndexedRange {
        std::uint64_t start{0};
        std::uint64_t end{0};
        std::size_t entry_index{0};
    };
    std::vector<IndexedRange> sorted_ranges;
    sorted_ranges.reserve(bundle.entries.size());
    for (std::size_t i = 0; i < bundle.entries.size(); ++i) {
        const PatchBundleEntry& e = bundle.entries[i];
        const auto sz = static_cast<std::uint64_t>(e.patched_bytes.size());
        if (sz == 0u || e.original_bytes.size() != e.patched_bytes.size()) {
            continue;
        }
        if (e.offset > target.size() || sz > target.size() - e.offset) {
            continue;
        }
        sorted_ranges.push_back(IndexedRange{
            .start = e.offset,
            .end = e.offset + sz,
            .entry_index = i,
        });
    }
    std::sort(sorted_ranges.begin(),
              sorted_ranges.end(),
              [](const IndexedRange& a, const IndexedRange& b) noexcept {
                  if (a.start != b.start) return a.start < b.start;
                  if (a.end != b.end) return a.end < b.end;
                  return a.entry_index < b.entry_index;
              });

    std::vector<std::optional<std::size_t>> overlap_peer(bundle.entries.size());
    if (!sorted_ranges.empty()) {
        std::size_t max_end_pos = 0u;
        for (std::size_t k = 1u; k < sorted_ranges.size(); ++k) {
            const IndexedRange& active = sorted_ranges[max_end_pos];
            const IndexedRange& cur = sorted_ranges[k];
            if (cur.start < active.end) {
                if (!overlap_peer[cur.entry_index].has_value()) {
                    overlap_peer[cur.entry_index] = active.entry_index;
                }
                if (!overlap_peer[active.entry_index].has_value()) {
                    overlap_peer[active.entry_index] = cur.entry_index;
                }
            }
            if (cur.end > active.end) {
                max_end_pos = k;
            }
        }
    }

    for (std::size_t i = 0; i < bundle.entries.size(); ++i) {
        const PatchBundleEntry& e = bundle.entries[i];
        PatchBundleEntryPreview ep;
        ep.entry_index = i;
        ep.offset = e.offset;
        ep.virtual_address = e.virtual_address;
        ep.size = static_cast<std::uint64_t>(e.patched_bytes.size());
        ep.label = e.label.empty() ? std::format("Entry #{}", i + 1u) : e.label;

        if (e.patched_bytes.empty() || e.original_bytes.size() != e.patched_bytes.size()) {
            ep.status = PatchEntryConflictKind::InvalidEntrySize;
            ep.detail = std::format(
                "Invalid fixed-size patch entry (original {} B vs patched {} B)",
                e.original_bytes.size(), e.patched_bytes.size());
            ++preview.conflict_count;
            preview.entry_previews.push_back(std::move(ep));
            continue;
        }

        if (e.offset > target.size() || ep.size > target.size() - e.offset) {
            ep.status = PatchEntryConflictKind::OutOfBounds;
            ep.detail = std::format(
                "Patch range [{:#x}, {:#x}) exceeds target size {:#x}",
                e.offset, e.offset + ep.size, target.size());
            ++preview.conflict_count;
            preview.entry_previews.push_back(std::move(ep));
            continue;
        }

        const std::optional<std::size_t> overlap_idx = overlap_peer[i];
        if (overlap_idx.has_value()) {
            ep.status = PatchEntryConflictKind::OverlappingEntry;
            ep.detail = std::format("Overlaps with bundle entry [{}] at {:#x}",
                                    *overlap_idx, bundle.entries[*overlap_idx].offset);
            ++preview.conflict_count;
            preview.entry_previews.push_back(std::move(ep));
            continue;
        }

        auto orig_res = target.read_original(e.offset, ep.size);
        auto eff_res = target.read_effective(e.offset, ep.size);
        if (!orig_res.has_value() || !eff_res.has_value()) {
            ep.status = PatchEntryConflictKind::OutOfBounds;
            ep.detail = !orig_res.has_value() ? orig_res.error().message : eff_res.error().message;
            ++preview.conflict_count;
            preview.entry_previews.push_back(std::move(ep));
            continue;
        }
        ep.actual_original_bytes = std::move(*orig_res);
        ep.actual_effective_bytes = std::move(*eff_res);

        if (ep.actual_effective_bytes == e.original_bytes) {
            ep.status = PatchEntryConflictKind::Clean;
            ep.detail = "Original bytes match target";
            ++preview.clean_count;
        } else if (ep.actual_effective_bytes == e.patched_bytes &&
                   ep.actual_original_bytes == e.original_bytes) {
            ep.status = PatchEntryConflictKind::AlreadyApplied;
            ep.detail = "Patched bytes are already staged at this offset";
            if (options.allow_already_applied_entries) {
                ++preview.clean_count;
            } else {
                ++preview.conflict_count;
            }
        } else {
            ep.status = PatchEntryConflictKind::OriginalBytesMismatch;
            ep.detail = std::format(
                "Expected original [{}], found [{}]",
                bytes_to_hex_string(e.original_bytes),
                bytes_to_hex_string(ep.actual_effective_bytes));
            ++preview.conflict_count;
        }

        preview.entry_previews.push_back(std::move(ep));
    }

    if (bundle.entries.empty()) {
        preview.can_apply = false;
        preview.summary = "Patch bundle contains 0 patch entries";
        return preview;
    }

    const bool identity_ok = preview.sha256_matches && preview.size_matches;
    if (!identity_ok && options.allow_hash_mismatch_if_original_bytes_match &&
        preview.conflict_count == 0) {
        preview.sha256_mismatch_overridden = true;
        preview.can_apply = true;
        preview.summary = std::format(
            "Ready with override: {} clean entry(ies); target SHA-256/size differs from bundle expectation, but all original byte spans match",
            preview.clean_count);
        return preview;
    }

    if (!preview.sha256_matches) {
        preview.can_apply = false;
        preview.summary = !valid_expected_sha256
                              ? std::format(
                                    "Invalid or missing target SHA-256 in patch bundle ('{}'); {} clean, {} conflict(s)",
                                    bundle.expected_sha256,
                                    preview.clean_count,
                                    preview.conflict_count)
                              : std::format(
                                    "Target SHA-256 mismatch (expected {}, actual {}); {} clean, {} conflict(s)",
                                    bundle.expected_sha256,
                                    preview.actual_sha256,
                                    preview.clean_count,
                                    preview.conflict_count);
        return preview;
    }
    if (!preview.size_matches) {
        preview.can_apply = false;
        preview.summary = std::format(
            "Target file size mismatch (expected {} B, actual {} B)",
            bundle.expected_size,
            preview.actual_size);
        return preview;
    }
    if (preview.conflict_count > 0) {
        preview.can_apply = false;
        preview.summary = std::format(
            "Patch bundle has {} conflict(s) and {} clean entry(ies); resolve conflicts before applying",
            preview.conflict_count,
            preview.clean_count);
        return preview;
    }

    preview.can_apply = true;
    preview.summary = std::format(
        "Ready: {} clean patch entry(ies) verified against target SHA-256",
        preview.clean_count);
    return preview;
}

Result<void> apply_patch_bundle(
    const PatchBundle& bundle,
    PagedBinaryImage& target,
    const PatchBundleApplyOptions& options,
    const IProcessSession* live_session) {
    auto preview = preview_patch_bundle(bundle, target, options, live_session);
    if (!preview.has_value()) {
        return std::unexpected(preview.error());
    }
    if (!preview->can_apply) {
        return make_error(preview->summary);
    }

    const std::string tx_label = !options.transaction_label.empty()
                                     ? options.transaction_label
                                     : (!bundle.name.empty()
                                            ? std::format("Apply patch bundle '{}'", bundle.name)
                                            : "Apply patch bundle");
    const std::string tx_note = !options.transaction_note.empty()
                                    ? options.transaction_note
                                    : bundle.description;

    PatchTransaction tx = target.begin_transaction(tx_label, tx_note);
    for (const PatchBundleEntry& entry : bundle.entries) {
        auto w = tx.write(entry.offset, entry.patched_bytes, entry.note);
        if (!w.has_value()) {
            tx.rollback();
            return std::unexpected(w.error());
        }
    }
    auto committed = tx.commit();
    if (!committed.has_value()) {
        tx.rollback();
        return committed;
    }
    return {};
}

Result<void> apply_patch_bundle(const PatchBundle& /*bundle*/,
                                IProcessSession& /*live_session*/) {
    return make_error(
        "Live process sessions are strictly read-only; patch bundles cannot be applied to live memory");
}

Result<std::vector<std::uint8_t>> encode_ips_patch(std::span<const PatchInterval> intervals) {
    constexpr std::uint64_t kIps24Limit = 0x1000000ULL;
    constexpr std::uint64_t kIps32Limit = 0x100000000ULL;
    constexpr std::uint64_t kIpsEofOffset = 0x454F46ULL;     // "EOF"
    constexpr std::uint64_t kIps32EeofOffset = 0x45454F46ULL; // "EEOF"
    constexpr std::size_t kMaxChunkLen = 0xFFFFu;

    struct CoalescedRun {
        std::uint64_t offset{0};
        std::vector<std::uint8_t> bytes{};
    };

    std::vector<CoalescedRun> sorted_runs;
    sorted_runs.reserve(intervals.size());
    for (std::size_t i = 0; i < intervals.size(); ++i) {
        const PatchInterval& iv = intervals[i];
        const auto sz = static_cast<std::uint64_t>(iv.patched.size());
        if (iv.offset >= kIps32Limit || sz > kIps32Limit - iv.offset) {
            return make_error(std::format(
                "IPS/IPS32 patch interval [{}] at {:#x} (+{} B) exceeds 4 GiB limit",
                i, iv.offset, sz));
        }
        if (iv.patched.empty()) {
            continue;
        }
        sorted_runs.push_back(CoalescedRun{
            .offset = iv.offset,
            .bytes = iv.patched,
        });
    }

    std::sort(sorted_runs.begin(),
              sorted_runs.end(),
              [](const CoalescedRun& a, const CoalescedRun& b) noexcept {
                  return a.offset < b.offset;
              });

    std::vector<CoalescedRun> merged;
    merged.reserve(sorted_runs.size());
    for (CoalescedRun& cur : sorted_runs) {
        if (!merged.empty()) {
            CoalescedRun& prev = merged.back();
            const std::uint64_t prev_end =
                prev.offset + static_cast<std::uint64_t>(prev.bytes.size());
            if (cur.offset < prev_end) {
                return make_error(std::format(
                    "IPS/IPS32 patch intervals overlap at offset {:#x}", cur.offset));
            }
            if (cur.offset == prev_end) {
                prev.bytes.insert(prev.bytes.end(), cur.bytes.begin(), cur.bytes.end());
                continue;
            }
        }
        merged.push_back(std::move(cur));
    }

    bool use_ips32 = false;
    for (const CoalescedRun& run : merged) {
        const std::uint64_t run_end =
            run.offset + static_cast<std::uint64_t>(run.bytes.size());
        if (run.offset >= kIps24Limit || run_end > kIps24Limit ||
            run.offset == kIpsEofOffset) {
            use_ips32 = true;
            break;
        }
    }

    std::vector<std::uint8_t> out;
    if (use_ips32) {
        out.insert(out.end(), {'I', 'P', 'S', '3', '2'});
    } else {
        out.insert(out.end(), {'P', 'A', 'T', 'C', 'H'});
    }

    const std::uint64_t marker_collision_offset =
        use_ips32 ? kIps32EeofOffset : kIpsEofOffset;

    for (const CoalescedRun& run : merged) {
        std::size_t pos = 0;
        while (pos < run.bytes.size()) {
            const std::uint64_t chunk_offset = run.offset + static_cast<std::uint64_t>(pos);
            const std::size_t remaining = run.bytes.size() - pos;
            std::size_t chunk_len = std::min<std::size_t>(remaining, kMaxChunkLen);
            if (remaining > chunk_len &&
                (chunk_offset + static_cast<std::uint64_t>(chunk_len)) == marker_collision_offset &&
                chunk_len > 1u) {
                --chunk_len;
            }

            if (use_ips32) {
                out.push_back(static_cast<std::uint8_t>((chunk_offset >> 24u) & 0xFFu));
                out.push_back(static_cast<std::uint8_t>((chunk_offset >> 16u) & 0xFFu));
                out.push_back(static_cast<std::uint8_t>((chunk_offset >> 8u) & 0xFFu));
                out.push_back(static_cast<std::uint8_t>(chunk_offset & 0xFFu));
            } else {
                out.push_back(static_cast<std::uint8_t>((chunk_offset >> 16u) & 0xFFu));
                out.push_back(static_cast<std::uint8_t>((chunk_offset >> 8u) & 0xFFu));
                out.push_back(static_cast<std::uint8_t>(chunk_offset & 0xFFu));
            }

            out.push_back(static_cast<std::uint8_t>((chunk_len >> 8u) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>(chunk_len & 0xFFu));
            out.insert(out.end(),
                       run.bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                       run.bytes.begin() + static_cast<std::ptrdiff_t>(pos + chunk_len));
            pos += chunk_len;
        }
    }

    if (use_ips32) {
        out.insert(out.end(), {'E', 'E', 'O', 'F'});
    } else {
        out.insert(out.end(), {'E', 'O', 'F'});
    }
    return out;
}

Result<std::vector<PatchInterval>> decode_ips_patch(std::span<const std::uint8_t> ips_bytes) {
    if (ips_bytes.size() < 8u) {
        return make_error("IPS/IPS32 patch stream is truncated (< 8 bytes)");
    }

    bool is_ips32 = false;
    if (ips_bytes[0] == 'P' && ips_bytes[1] == 'A' && ips_bytes[2] == 'T' &&
        ips_bytes[3] == 'C' && ips_bytes[4] == 'H') {
        is_ips32 = false;
    } else if (ips_bytes[0] == 'I' && ips_bytes[1] == 'P' && ips_bytes[2] == 'S' &&
               ips_bytes[3] == '3' && ips_bytes[4] == '2') {
        is_ips32 = true;
    } else {
        return make_error("Unrecognized IPS header (expected 'PATCH' or 'IPS32')");
    }

    const std::size_t offset_width = is_ips32 ? 4u : 3u;
    const std::size_t trailer_len = is_ips32 ? 4u : 3u;
    constexpr std::uint64_t kIps32Limit = 0x100000000ULL;

    std::size_t pos = 5u;
    bool saw_trailer = false;
    std::vector<PatchInterval> raw_chunks;

    while (pos < ips_bytes.size()) {
        const std::size_t rem = ips_bytes.size() - pos;
        const bool matches_trailer =
            is_ips32
                ? (rem >= 4u && ips_bytes[pos] == 'E' && ips_bytes[pos + 1u] == 'E' &&
                   ips_bytes[pos + 2u] == 'O' && ips_bytes[pos + 3u] == 'F')
                : (rem >= 3u && ips_bytes[pos] == 'E' && ips_bytes[pos + 1u] == 'O' &&
                   ips_bytes[pos + 2u] == 'F');

        // A valid record + trailer requires at least offset_width + 2 + 1 + trailer_len
        // (9 bytes for IPS, 11 bytes for IPS32), whereas the EOF trailer (with or without
        // optional target truncation length) leaves trailer_len or 2 * trailer_len bytes.
        if (matches_trailer && (rem == trailer_len || rem == trailer_len * 2u)) {
            saw_trailer = true;
            pos = ips_bytes.size();
            break;
        }

        if (rem < offset_width + 2u) {
            return make_error("Truncated IPS/IPS32 record header before trailer");
        }

        std::uint64_t rec_offset = 0;
        if (is_ips32) {
            rec_offset = (static_cast<std::uint64_t>(ips_bytes[pos]) << 24u) |
                         (static_cast<std::uint64_t>(ips_bytes[pos + 1u]) << 16u) |
                         (static_cast<std::uint64_t>(ips_bytes[pos + 2u]) << 8u) |
                         static_cast<std::uint64_t>(ips_bytes[pos + 3u]);
        } else {
            rec_offset = (static_cast<std::uint64_t>(ips_bytes[pos]) << 16u) |
                         (static_cast<std::uint64_t>(ips_bytes[pos + 1u]) << 8u) |
                         static_cast<std::uint64_t>(ips_bytes[pos + 2u]);
        }
        pos += offset_width;

        const std::size_t rec_len =
            (static_cast<std::size_t>(ips_bytes[pos]) << 8u) |
            static_cast<std::size_t>(ips_bytes[pos + 1u]);
        pos += 2u;

        PatchInterval chunk;
        chunk.offset = rec_offset;
        if (rec_len == 0u) {
            // RLE chunk: 16-bit big-endian repeat count + 1-byte fill value.
            if (ips_bytes.size() - pos < 3u) {
                return make_error("Truncated IPS/IPS32 RLE record payload");
            }
            const std::size_t rle_count =
                (static_cast<std::size_t>(ips_bytes[pos]) << 8u) |
                static_cast<std::size_t>(ips_bytes[pos + 1u]);
            const std::uint8_t fill_byte = ips_bytes[pos + 2u];
            pos += 3u;
            if (rle_count == 0u) {
                return make_error("Invalid zero-length IPS/IPS32 RLE record");
            }
            if (rec_offset >= kIps32Limit || rle_count > kIps32Limit - rec_offset) {
                return make_error("Decoded IPS/IPS32 RLE record exceeds 4 GiB limit");
            }
            chunk.patched.assign(rle_count, fill_byte);
        } else {
            if (ips_bytes.size() - pos < rec_len) {
                return make_error("Truncated IPS/IPS32 literal record payload");
            }
            if (rec_offset >= kIps32Limit || rec_len > kIps32Limit - rec_offset) {
                return make_error("Decoded IPS/IPS32 record exceeds 4 GiB limit");
            }
            chunk.patched.assign(ips_bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                                 ips_bytes.begin() + static_cast<std::ptrdiff_t>(pos + rec_len));
            pos += rec_len;
        }
        raw_chunks.push_back(std::move(chunk));
    }

    if (!saw_trailer) {
        return make_error(is_ips32 ? "Missing 'EEOF' trailer in IPS32 patch"
                                   : "Missing 'EOF' trailer in IPS patch");
    }

    std::sort(raw_chunks.begin(),
              raw_chunks.end(),
              [](const PatchInterval& a, const PatchInterval& b) noexcept {
                  return a.offset < b.offset;
              });

    std::vector<PatchInterval> coalesced;
    coalesced.reserve(raw_chunks.size());
    for (PatchInterval& cur : raw_chunks) {
        if (!coalesced.empty()) {
            PatchInterval& prev = coalesced.back();
            if (cur.offset < prev.end_offset()) {
                return make_error(std::format(
                    "Overlapping IPS/IPS32 records at offset {:#x}", cur.offset));
            }
            if (cur.offset == prev.end_offset()) {
                prev.patched.insert(prev.patched.end(), cur.patched.begin(), cur.patched.end());
                continue;
            }
        }
        coalesced.push_back(std::move(cur));
    }
    return coalesced;
}

Result<void> save_ips_patch_file(std::span<const PatchInterval> intervals,
                                 const std::filesystem::path& path) {
    if (path.empty()) {
        return make_error("IPS patch output path is empty");
    }
    auto encoded = encode_ips_patch(intervals);
    if (!encoded.has_value()) {
        return std::unexpected(encoded.error());
    }
    return detail::write_bytes_atomically(path, *encoded, true, true);
}

Result<std::vector<PatchInterval>> load_ips_patch_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return make_error(std::format("Failed to open IPS patch '{}'", path.string()));
    }
    const auto end_pos = in.tellg();
    if (end_pos < 0) {
        return make_error(std::format("Failed to query IPS patch size '{}'", path.string()));
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(end_pos));
    in.seekg(0, std::ios::beg);
    if (!buf.empty()) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() != static_cast<std::streamsize>(buf.size())) {
            return make_error(std::format("Failed reading IPS patch '{}'", path.string()));
        }
    }
    return decode_ips_patch(buf);
}

} // namespace peelf
