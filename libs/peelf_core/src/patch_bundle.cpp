#include <peelf/patch_bundle.hpp>

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
                    if (pos_ + 4u > text_.size()) {
                        return make_error("Incomplete \\uXXXX escape in JSON string");
                    }
                    unsigned int code = 0;
                    for (std::size_t i = 0; i < 4u; ++i) {
                        const char hc = text_[pos_++];
                        code <<= 4u;
                        if (hc >= '0' && hc <= '9') code |= static_cast<unsigned int>(hc - '0');
                        else if (hc >= 'a' && hc <= 'f') code |= static_cast<unsigned int>(10 + (hc - 'a'));
                        else if (hc >= 'A' && hc <= 'F') code |= static_cast<unsigned int>(10 + (hc - 'A'));
                        else return make_error("Invalid hex digit in \\uXXXX JSON escape");
                    }
                    if (code <= 0x7Fu) {
                        out.push_back(static_cast<char>(code));
                    } else if (code <= 0x7FFu) {
                        out.push_back(static_cast<char>(0xC0u | ((code >> 6u) & 0x1Fu)));
                        out.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
                    } else {
                        out.push_back(static_cast<char>(0xE0u | ((code >> 12u) & 0x0Fu)));
                        out.push_back(static_cast<char>(0x80u | ((code >> 6u) & 0x3Fu)));
                        out.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
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
        if (s == nullptr) {
            return make_error("'expected_sha256' must be a hex string");
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
    std::error_code ec;
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
    }

    std::filesystem::path tmp_path = path;
    tmp_path += ".tmp";

    const std::string encoded = encode_patch_bundle_json(bundle);
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return make_error(std::format("Failed to open '{}' for writing", tmp_path.string()));
        }
        out.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
        out.flush();
        if (!out) {
            out.close();
            std::filesystem::remove(tmp_path, ec);
            return make_error(std::format("Failed to write patch bundle '{}'", tmp_path.string()));
        }
    }

    std::filesystem::rename(tmp_path, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path, ec);
            return make_error(std::format("Failed to finalize patch bundle '{}'", path.string()));
        }
    }
    return {};
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
    preview.sha256_matches = bundle.expected_sha256.empty() ||
                             (to_lower_ascii(bundle.expected_sha256) == preview.actual_sha256);

    preview.entry_previews.reserve(bundle.entries.size());

    // Detect pairwise overlaps among valid-sized entries
    auto ranges_overlap = [](std::uint64_t a_off, std::uint64_t a_sz,
                             std::uint64_t b_off, std::uint64_t b_sz) noexcept -> bool {
        if (a_sz == 0 || b_sz == 0) return false;
        const std::uint64_t a_end = a_off + a_sz;
        const std::uint64_t b_end = b_off + b_sz;
        return a_off < b_end && b_off < a_end;
    };

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

        std::optional<std::size_t> overlap_idx;
        for (std::size_t j = 0; j < bundle.entries.size(); ++j) {
            if (j == i || bundle.entries[j].patched_bytes.empty() ||
                bundle.entries[j].original_bytes.size() != bundle.entries[j].patched_bytes.size()) {
                continue;
            }
            if (ranges_overlap(e.offset, ep.size,
                               bundle.entries[j].offset,
                               static_cast<std::uint64_t>(bundle.entries[j].patched_bytes.size()))) {
                overlap_idx = j;
                break;
            }
        }
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
        preview.summary = std::format(
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

    PatchTransaction tx = target.begin_transaction(tx_label);
    for (const PatchBundleEntry& entry : bundle.entries) {
        auto w = tx.write(entry.offset, entry.patched_bytes);
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

} // namespace peelf
