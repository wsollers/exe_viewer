#pragma once
#include "symbol_index.hpp"

#include <algorithm>
#include <map>

namespace viewer {
struct DataEnumEnumerator {
    std::string name{};
    std::int64_t value = 0;

    auto operator<=>(const DataEnumEnumerator&) const = default;
};

struct DataMember {
    std::string name, type;
    std::uint64_t offset{}, size{};
    std::uint8_t bit_width = 0;
    std::uint8_t bit_offset = 0;

    auto operator<=>(const DataMember&) const = default;
};

struct DataTypeRecord {
    std::string name;
    std::uint64_t size{};
    bool is_union = false;
    std::vector<DataMember> members{};
    bool is_enum = false;
    bool is_enum_signed = true;
    bool is_custom_c = false;
    std::string underlying_type{};
    std::vector<DataEnumEnumerator> enum_constants{};
    std::vector<std::string> aliases{};

    auto operator<=>(const DataTypeRecord&) const = default;
};

struct AppliedStructureBinding {
    std::uint64_t address = 0;
    bool is_file_offset = false;
    std::string type_name{};
    std::uint32_t count = 1;
    std::string label{};

    auto operator<=>(const AppliedStructureBinding&) const = default;
};

struct Bookmark {
    std::uint64_t address = 0;
    bool is_file_offset = false;
    std::string label{};
    std::string category{};
    std::string note{};

    auto operator<=>(const Bookmark&) const = default;
};

struct DecompilerVariableOverride {
    std::string original_name{};
    std::string renamed_to{};
    std::string c_type{};

    auto operator<=>(const DecompilerVariableOverride&) const = default;
};

struct DecompilerFunctionOverride {
    std::uint64_t function_address = 0;
    std::string return_type{};
    std::string signature_override{};
    std::vector<DecompilerVariableOverride> variables{};

    [[nodiscard]] bool empty() const noexcept {
        return return_type.empty() && signature_override.empty() && variables.empty();
    }

    auto operator<=>(const DecompilerFunctionOverride&) const = default;
};

namespace detail {

[[nodiscard]] inline std::string_view trim_override_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t')) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] inline constexpr bool is_override_ident_start(char ch) noexcept {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_';
}

[[nodiscard]] inline constexpr bool is_override_ident_cont(char ch) noexcept {
    return is_override_ident_start(ch) || (ch >= '0' && ch <= '9');
}

[[nodiscard]] inline bool is_c_or_cpp_keyword(std::string_view token) noexcept {
    static constexpr std::string_view kKeywords[] = {
        "_Alignas",       "_Alignof",      "_Atomic",        "_BitInt",
        "_Bool",          "_Complex",      "_Decimal128",    "_Decimal32",
        "_Decimal64",     "_Generic",      "_Imaginary",     "_Noreturn",
        "_Static_assert", "_Thread_local", "alignas",        "alignof",
        "and",            "and_eq",        "asm",            "auto",
        "bitand",         "bitor",         "bool",           "break",
        "case",           "catch",         "char",           "char16_t",
        "char32_t",       "char8_t",       "class",          "compl",
        "concept",        "const",         "const_cast",     "consteval",
        "constexpr",      "constinit",     "continue",       "co_await",
        "co_return",      "co_yield",      "decltype",       "default",
        "delete",         "do",            "double",         "dynamic_cast",
        "else",           "enum",          "explicit",       "export",
        "extern",         "false",         "float",          "for",
        "friend",         "goto",          "if",             "inline",
        "int",            "long",          "mutable",        "namespace",
        "new",            "noexcept",      "not",            "not_eq",
        "nullptr",        "operator",      "or",             "or_eq",
        "private",        "protected",     "public",         "register",
        "reinterpret_cast", "requires",    "restrict",       "return",
        "short",          "signed",        "sizeof",         "static",
        "static_assert",  "static_cast",   "struct",         "switch",
        "template",       "this",          "thread_local",   "throw",
        "true",           "try",           "typedef",        "typeid",
        "typename",       "typeof",        "typeof_unqual",  "union",
        "unsigned",       "using",         "virtual",        "void",
        "volatile",       "wchar_t",       "while",          "xor",
        "xor_eq",
    };
    for (const std::string_view kw : kKeywords) {
        if (token == kw) {
            return true;
        }
    }
    return false;
}

} // namespace detail

inline constexpr std::size_t kMaxDecompilerIdentifierLength = 128u;
inline constexpr std::size_t kMaxDecompilerTypeLength = 128u;
inline constexpr std::size_t kMaxDecompilerSignatureLength = 256u;

[[nodiscard]] inline bool is_valid_decompiler_original_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxDecompilerIdentifierLength) {
        return false;
    }
    if (!detail::is_override_ident_start(name.front())) {
        return false;
    }
    for (std::size_t i = 1; i < name.size(); ++i) {
        if (!detail::is_override_ident_cont(name[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool is_valid_decompiler_c_identifier(std::string_view name) noexcept {
    return is_valid_decompiler_original_name(name) && !detail::is_c_or_cpp_keyword(name);
}

[[nodiscard]] inline std::optional<std::string> normalize_decompiler_c_type(std::string_view raw) {
    for (char ch : raw) {
        const auto uch = static_cast<unsigned char>(ch);
        if ((uch < 0x20u && ch != '\t') || uch >= 0x7Fu) {
            return std::nullopt;
        }
    }
    raw = detail::trim_override_ascii(raw);
    if (raw.empty()) {
        return std::string{};
    }

    std::string out;
    out.reserve(std::min<std::size_t>(raw.size(), kMaxDecompilerTypeLength));
    bool prev_space = false;
    bool has_ident_char = false;
    int square_depth = 0;
    int angle_depth = 0;

    for (std::size_t i = 0; i < raw.size(); ++i) {
        const char ch = raw[i];
        if (ch == ' ' || ch == '\t') {
            if (!prev_space && !out.empty()) {
                out.push_back(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        if (detail::is_override_ident_start(ch)) {
            has_ident_char = true;
            out.push_back(ch);
        } else if (ch >= '0' && ch <= '9') {
            if (out.empty()) {
                return std::nullopt;
            }
            out.push_back(ch);
        } else if (ch == '*' || ch == '&') {
            if (!has_ident_char) {
                return std::nullopt;
            }
            out.push_back(ch);
        } else if (ch == '[') {
            if (!has_ident_char) {
                return std::nullopt;
            }
            ++square_depth;
            out.push_back(ch);
        } else if (ch == ']') {
            if (square_depth <= 0) {
                return std::nullopt;
            }
            --square_depth;
            out.push_back(ch);
        } else if (ch == '<') {
            if (!has_ident_char) {
                return std::nullopt;
            }
            ++angle_depth;
            out.push_back(ch);
        } else if (ch == '>') {
            if (angle_depth <= 0) {
                return std::nullopt;
            }
            --angle_depth;
            out.push_back(ch);
        } else if (ch == ':') {
            if (i + 1u < raw.size() && raw[i + 1u] == ':') {
                out.append("::");
                ++i;
            } else {
                return std::nullopt;
            }
        } else if (ch == ',') {
            if (angle_depth <= 0) {
                return std::nullopt;
            }
            out.push_back(ch);
        } else {
            return std::nullopt;
        }

        if (out.size() > kMaxDecompilerTypeLength) {
            return std::nullopt;
        }
    }

    if (!has_ident_char || square_depth != 0 || angle_depth != 0) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] inline std::optional<std::string> normalize_decompiler_signature_override(
    std::string_view raw) {
    for (char ch : raw) {
        const auto uch = static_cast<unsigned char>(ch);
        if ((uch < 0x20u && ch != '\t') || uch >= 0x7Fu) {
            return std::nullopt;
        }
    }
    raw = detail::trim_override_ascii(raw);
    if (raw.empty()) {
        return std::string{};
    }

    std::string out;
    out.reserve(std::min<std::size_t>(raw.size(), kMaxDecompilerSignatureLength));
    bool prev_space = false;
    int paren_depth = 0;
    int square_depth = 0;
    bool saw_open_paren = false;

    for (std::size_t i = 0; i < raw.size(); ++i) {
        const char ch = raw[i];
        if (ch == ' ' || ch == '\t') {
            if (!prev_space && !out.empty()) {
                out.push_back(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        if (detail::is_override_ident_cont(ch) || ch == '*' || ch == '&' || ch == ',' || ch == '.') {
            out.push_back(ch);
        } else if (ch == ':') {
            if (i + 1u < raw.size() && raw[i + 1u] == ':') {
                out.append("::");
                ++i;
            } else {
                return std::nullopt;
            }
        } else if (ch == '(') {
            saw_open_paren = true;
            ++paren_depth;
            out.push_back(ch);
        } else if (ch == ')') {
            if (paren_depth <= 0) {
                return std::nullopt;
            }
            --paren_depth;
            out.push_back(ch);
        } else if (ch == '[') {
            ++square_depth;
            out.push_back(ch);
        } else if (ch == ']') {
            if (square_depth <= 0) {
                return std::nullopt;
            }
            --square_depth;
            out.push_back(ch);
        } else {
            return std::nullopt;
        }

        if (out.size() > kMaxDecompilerSignatureLength) {
            return std::nullopt;
        }
    }

    if (!saw_open_paren || paren_depth != 0 || square_depth != 0) {
        return std::nullopt;
    }
    return out;
}

class DecompilerOverrideStore {
public:
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
    [[nodiscard]] bool empty() const noexcept { return overrides_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return overrides_.size(); }

    [[nodiscard]] const std::map<std::uint64_t, DecompilerFunctionOverride>& records() const noexcept {
        return overrides_;
    }

    [[nodiscard]] std::vector<DecompilerFunctionOverride> to_vector() const {
        std::vector<DecompilerFunctionOverride> out;
        out.reserve(overrides_.size());
        for (const auto& [addr, fn_ov] : overrides_) {
            (void)addr;
            if (!fn_ov.empty()) {
                out.push_back(fn_ov);
            }
        }
        return out;
    }

    void clear() noexcept {
        if (!overrides_.empty()) {
            overrides_.clear();
            ++revision_;
        }
    }

    [[nodiscard]] const DecompilerFunctionOverride* find(std::uint64_t function_address) const noexcept {
        const auto it = overrides_.find(function_address);
        return it != overrides_.end() ? &it->second : nullptr;
    }

    [[nodiscard]] const DecompilerVariableOverride* find_variable(
        std::uint64_t function_address,
        std::string_view original_name) const noexcept {
        const auto* fn = find(function_address);
        if (fn == nullptr) {
            return nullptr;
        }
        for (const auto& var : fn->variables) {
            if (var.original_name == original_name) {
                return &var;
            }
        }
        return nullptr;
    }

    [[nodiscard]] peelf::Result<void> set_variable_override(
        std::uint64_t function_address,
        std::string_view original_name,
        std::string_view renamed_to,
        std::string_view c_type) {
        original_name = detail::trim_override_ascii(original_name);
        renamed_to = detail::trim_override_ascii(renamed_to);
        if (!is_valid_decompiler_original_name(original_name)) {
            return peelf::make_error("Invalid variable target identifier");
        }
        if (renamed_to == original_name) {
            renamed_to = {};
        }
        if (!renamed_to.empty() && !is_valid_decompiler_c_identifier(renamed_to)) {
            return peelf::make_error(
                "Invalid C identifier (use [A-Za-z_][A-Za-z0-9_]* and avoid C/C++ keywords)");
        }
        const auto norm_type = normalize_decompiler_c_type(c_type);
        if (!norm_type.has_value()) {
            return peelf::make_error("Invalid C type expression");
        }

        auto& fn = overrides_[function_address];
        fn.function_address = function_address;
        if (!renamed_to.empty()) {
            for (const auto& existing : fn.variables) {
                if (existing.original_name != original_name) {
                    const std::string_view effective =
                        existing.renamed_to.empty() ? std::string_view(existing.original_name)
                                                    : std::string_view(existing.renamed_to);
                    if (effective == renamed_to) {
                        return peelf::make_error("Another variable in this function already uses that name");
                    }
                }
            }
        }

        for (auto it = fn.variables.begin(); it != fn.variables.end(); ++it) {
            if (it->original_name == original_name) {
                if (renamed_to.empty() && norm_type->empty()) {
                    fn.variables.erase(it);
                    prune_if_empty(function_address);
                    ++revision_;
                    return {};
                }
                if (it->renamed_to == renamed_to && it->c_type == *norm_type) {
                    return {};
                }
                it->renamed_to = std::string(renamed_to);
                it->c_type = *norm_type;
                ++revision_;
                return {};
            }
        }

        if (renamed_to.empty() && norm_type->empty()) {
            prune_if_empty(function_address);
            return {};
        }

        fn.variables.push_back(DecompilerVariableOverride{
            .original_name = std::string(original_name),
            .renamed_to = std::string(renamed_to),
            .c_type = *norm_type,
        });
        ++revision_;
        return {};
    }

    [[nodiscard]] peelf::Result<void> set_variable_rename(
        std::uint64_t function_address,
        std::string_view original_name,
        std::string_view renamed_to) {
        const auto* existing = find_variable(function_address, detail::trim_override_ascii(original_name));
        const std::string keep_type = existing != nullptr ? existing->c_type : std::string{};
        return set_variable_override(function_address, original_name, renamed_to, keep_type);
    }

    [[nodiscard]] peelf::Result<void> set_variable_type(
        std::uint64_t function_address,
        std::string_view original_name,
        std::string_view c_type) {
        const auto* existing = find_variable(function_address, detail::trim_override_ascii(original_name));
        const std::string keep_rename = existing != nullptr ? existing->renamed_to : std::string{};
        return set_variable_override(function_address, original_name, keep_rename, c_type);
    }

    bool remove_variable(std::uint64_t function_address, std::string_view original_name) {
        const auto it = overrides_.find(function_address);
        if (it == overrides_.end()) {
            return false;
        }
        auto& vars = it->second.variables;
        for (auto vit = vars.begin(); vit != vars.end(); ++vit) {
            if (vit->original_name == original_name) {
                vars.erase(vit);
                prune_if_empty(function_address);
                ++revision_;
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] peelf::Result<void> set_function_prototype(
        std::uint64_t function_address,
        std::string_view return_type,
        std::string_view signature_override = {}) {
        const auto norm_ret = normalize_decompiler_c_type(return_type);
        if (!norm_ret.has_value()) {
            return peelf::make_error("Invalid function return C type");
        }
        const auto norm_sig = normalize_decompiler_signature_override(signature_override);
        if (!norm_sig.has_value()) {
            return peelf::make_error("Invalid function prototype/signature override");
        }

        auto& fn = overrides_[function_address];
        fn.function_address = function_address;
        if (fn.return_type == *norm_ret && fn.signature_override == *norm_sig) {
            prune_if_empty(function_address);
            return {};
        }
        fn.return_type = *norm_ret;
        fn.signature_override = *norm_sig;
        prune_if_empty(function_address);
        ++revision_;
        return {};
    }

    bool clear_function(std::uint64_t function_address) {
        if (overrides_.erase(function_address) > 0u) {
            ++revision_;
            return true;
        }
        return false;
    }

    void restore(std::span<const DecompilerFunctionOverride> items) {
        overrides_.clear();
        for (const DecompilerFunctionOverride& raw_fn : items) {
            if (!raw_fn.return_type.empty() || !raw_fn.signature_override.empty()) {
                (void)set_function_prototype(
                    raw_fn.function_address,
                    raw_fn.return_type,
                    raw_fn.signature_override);
            }
            for (const DecompilerVariableOverride& v : raw_fn.variables) {
                (void)set_variable_override(
                    raw_fn.function_address,
                    v.original_name,
                    v.renamed_to,
                    v.c_type);
            }
        }
        ++revision_;
    }

private:
    void prune_if_empty(std::uint64_t function_address) noexcept {
        const auto it = overrides_.find(function_address);
        if (it != overrides_.end() && it->second.empty()) {
            overrides_.erase(it);
        }
    }

    std::map<std::uint64_t, DecompilerFunctionOverride> overrides_{};
    std::uint64_t revision_ = 0;
};
[[nodiscard]] inline bool type_matches(const DataTypeRecord& type, std::string_view query) {
    if (symbol_name_matches(type.name, query)) return true;
    for (const auto& alias : type.aliases)
        if (symbol_name_matches(alias, query)) return true;
    for (const auto& member : type.members)
        if (symbol_name_matches(member.name, query) || symbol_name_matches(member.type, query)) return true;
    for (const auto& ec : type.enum_constants)
        if (symbol_name_matches(ec.name, query)) return true;
    return false;
}
}
