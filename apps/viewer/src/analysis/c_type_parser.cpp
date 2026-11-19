#include "analysis/c_type_parser.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <peelf/endian_reader.hpp>

namespace viewer {

std::string CTypeParseResult::format_diagnostics() const {
    std::ostringstream out;
    for (std::size_t i = 0; i < diagnostics.size(); ++i) {
        if (i > 0) {
            out << '\n';
        }
        const CTypeParseDiagnostic& d = diagnostics[i];
        out << (d.severity == CTypeDiagnosticSeverity::Error ? "error" : "warning")
            << " (" << d.line << ':' << d.column << "): " << d.message;
    }
    return out.str();
}

std::string_view default_custom_c_types_template() noexcept {
    return R"(// Define custom C structs, unions, enums, and typedefs for Structure View:
enum PacketFlags : uint32_t {
    PKT_NONE      = 0,
    PKT_ENCRYPTED = 1 << 0,
    PKT_COMPRESSED = 1 << 1,
    PKT_URGENT    = 1 << 4,
};

#pragma pack(push, 1)
typedef struct _PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t payload_len;
    PacketFlags flags;
    void* next_packet;
} PacketHeader;
#pragma pack(pop)
)";
}

namespace {

// ============================================================================
// Pure ASCII classification helpers (avoids locale & signed-char pitfalls)
// ============================================================================

[[nodiscard]] constexpr bool is_ascii_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] constexpr bool is_ascii_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

[[nodiscard]] constexpr bool is_ascii_hex(char c) noexcept {
    return is_ascii_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

[[nodiscard]] constexpr bool is_ascii_ident_start(char c) noexcept {
    return is_ascii_alpha(c) || c == '_' || c == '$';
}

[[nodiscard]] constexpr bool is_ascii_ident_cont(char c) noexcept {
    return is_ascii_ident_start(c) || is_ascii_digit(c);
}

[[nodiscard]] constexpr char ascii_to_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] constexpr bool is_power_of_two_u64(std::uint64_t v) noexcept {
    return v != 0u && (v & (v - 1u)) == 0u;
}

[[nodiscard]] std::optional<std::uint64_t> checked_align_up(std::uint64_t value,
                                                            std::uint64_t align) noexcept {
    if (align <= 1u) {
        return value;
    }
    const std::uint64_t rem = value % align;
    if (rem == 0u) {
        return value;
    }
    return peelf::checked_add_u64(value, align - rem);
}

// ============================================================================
// Lexer & Preprocessor Directives
// ============================================================================

enum class TokenKind : std::uint8_t {
    Eof = 0,
    Identifier,
    Number,
    CharLiteral,
    LBrace,      // {
    RBrace,      // }
    LParen,      // (
    RParen,      // )
    LBracket,    // [
    RBracket,    // ]
    Semicolon,   // ;
    Comma,       // ,
    Colon,       // :
    Question,    // ?
    Star,        // *
    Plus,        // +
    Minus,       // -
    Slash,       // /
    Percent,     // %
    Amp,         // &
    Pipe,        // |
    Caret,       // ^
    Tilde,       // ~
    Bang,        // !
    Assign,      // =
    Less,        // <
    Greater,     // >
    LShift,      // <<
    RShift,      // >>
    LessEq,      // <=
    GreaterEq,   // >=
    EqEq,        // ==
    NotEq,       // !=
    AmpAmp,      // &&
    PipePipe,    // ||
    Ellipsis,    // ...
    PragmaPackSet,
    PragmaPackPush,
    PragmaPackPop,
};

struct Token {
    TokenKind kind = TokenKind::Eof;
    std::string text{};
    std::uint32_t line = 1;
    std::uint32_t column = 1;
    std::uint64_t pragma_pack_val = 0;
    bool pragma_has_val = false;
};

class Lexer {
public:
    Lexer(std::string_view src, std::vector<CTypeParseDiagnostic>& diags)
        : src_(src), diags_(diags) {}

    [[nodiscard]] std::vector<Token> tokenize() {
        std::vector<Token> raw_tokens;
        raw_tokens.reserve(src_.size() / 4u + 8u);

        while (pos_ < src_.size()) {
            const char c = src_[pos_];

            // Whitespace
            if (c == ' ' || c == '\t' || c == '\v' || c == '\f') {
                advance();
                continue;
            }
            if (c == '\r' || c == '\n') {
                consume_newline();
                at_line_start_ = true;
                continue;
            }
            if (c == '\\' && (peek(1) == '\n' || (peek(1) == '\r' && peek(2) == '\n'))) {
                advance();
                consume_newline();
                continue;
            }

            // Line comment `//`
            if (c == '/' && peek(1) == '/') {
                advance(2);
                while (pos_ < src_.size() && src_[pos_] != '\r' && src_[pos_] != '\n') {
                    if (src_[pos_] == '\\' &&
                        (peek(1) == '\n' || (peek(1) == '\r' && peek(2) == '\n'))) {
                        advance();
                        consume_newline();
                        continue;
                    }
                    advance();
                }
                continue;
            }

            // Block comment `/* ... */`
            if (c == '/' && peek(1) == '*') {
                const std::uint32_t start_line = line_;
                const std::uint32_t start_col = col_;
                advance(2);
                bool closed = false;
                while (pos_ < src_.size()) {
                    if (src_[pos_] == '*' && peek(1) == '/') {
                        advance(2);
                        closed = true;
                        break;
                    }
                    if (src_[pos_] == '\r' || src_[pos_] == '\n') {
                        consume_newline();
                    } else {
                        advance();
                    }
                }
                if (!closed) {
                    emit_error(start_line, start_col, "Unclosed block comment '/*'");
                    break;
                }
                continue;
            }

            // Preprocessor directive `#...` at logical line start
            if (c == '#' && at_line_start_) {
                at_line_start_ = false;
                lex_preprocessor_directive(raw_tokens);
                continue;
            }

            at_line_start_ = false;
            if (!lex_single_token(raw_tokens, false)) {
                break;
            }
        }

        raw_tokens.push_back(Token{
            .kind = TokenKind::Eof,
            .text = {},
            .line = line_,
            .column = col_,
        });
        return raw_tokens;
    }

private:
    std::string_view src_;
    std::vector<CTypeParseDiagnostic>& diags_;
    std::size_t pos_ = 0;
    std::uint32_t line_ = 1;
    std::uint32_t col_ = 1;
    bool at_line_start_ = true;
    std::unordered_map<std::string, std::vector<Token>> macros_{};

    [[nodiscard]] char peek(std::size_t ahead = 0) const noexcept {
        return (pos_ + ahead < src_.size()) ? src_[pos_ + ahead] : '\0';
    }

    void advance(std::size_t count = 1) noexcept {
        for (std::size_t i = 0; i < count && pos_ < src_.size(); ++i) {
            ++pos_;
            ++col_;
        }
    }

    void consume_newline() noexcept {
        if (pos_ < src_.size() && src_[pos_] == '\r') {
            ++pos_;
        }
        if (pos_ < src_.size() && src_[pos_] == '\n') {
            ++pos_;
        }
        ++line_;
        col_ = 1;
    }

    void emit_error(std::uint32_t line, std::uint32_t col, std::string msg) {
        diags_.push_back(CTypeParseDiagnostic{
            .line = line,
            .column = col,
            .severity = CTypeDiagnosticSeverity::Error,
            .message = std::move(msg),
        });
    }

    void emit_warning(std::uint32_t line, std::uint32_t col, std::string msg) {
        diags_.push_back(CTypeParseDiagnostic{
            .line = line,
            .column = col,
            .severity = CTypeDiagnosticSeverity::Warning,
            .message = std::move(msg),
        });
    }

    void expand_identifier_or_push(const Token& ident_tok,
                                   std::vector<Token>& out,
                                   std::size_t depth) {
        if (depth < 16u) {
            if (const auto it = macros_.find(ident_tok.text); it != macros_.end()) {
                for (Token rep : it->second) {
                    rep.line = ident_tok.line;
                    rep.column = ident_tok.column;
                    if (rep.kind == TokenKind::Identifier && rep.text != ident_tok.text) {
                        expand_identifier_or_push(rep, out, depth + 1u);
                    } else {
                        out.push_back(std::move(rep));
                    }
                }
                return;
            }
        }
        out.push_back(ident_tok);
    }

    [[nodiscard]] bool lex_single_token(std::vector<Token>& out, bool in_directive) {
        const std::uint32_t tok_line = line_;
        const std::uint32_t tok_col = col_;
        const char c = src_[pos_];

        // Wide/UTF char literal prefix `L'...'`, `u'...'`, `U'...'`, `u8'...'`
        if ((c == 'L' || c == 'u' || c == 'U') && peek(1) == '\'') {
            advance();
            return lex_char_literal(out, tok_line, tok_col);
        }
        if (c == 'u' && peek(1) == '8' && peek(2) == '\'') {
            advance(2);
            return lex_char_literal(out, tok_line, tok_col);
        }
        if (c == '\'') {
            return lex_char_literal(out, tok_line, tok_col);
        }

        // String literal (not valid in constant exprs, skip or diagnose if seen outside `#include`)
        if (c == '"') {
            emit_error(tok_line, tok_col, "Unexpected string literal in C type declaration");
            advance();
            while (pos_ < src_.size() && src_[pos_] != '"' && src_[pos_] != '\n' &&
                   src_[pos_] != '\r') {
                if (src_[pos_] == '\\' && pos_ + 1 < src_.size()) {
                    advance(2);
                } else {
                    advance();
                }
            }
            if (pos_ < src_.size() && src_[pos_] == '"') {
                advance();
            }
            return true;
        }

        // Identifier
        if (is_ascii_ident_start(c)) {
            const std::size_t start = pos_;
            while (pos_ < src_.size() && is_ascii_ident_cont(src_[pos_])) {
                advance();
            }
            Token tok{
                .kind = TokenKind::Identifier,
                .text = std::string(src_.substr(start, pos_ - start)),
                .line = tok_line,
                .column = tok_col,
            };
            if (in_directive) {
                out.push_back(std::move(tok));
            } else {
                expand_identifier_or_push(tok, out, 0u);
            }
            return true;
        }

        // Number literal
        if (is_ascii_digit(c)) {
            const std::size_t start = pos_;
            while (pos_ < src_.size() &&
                   (is_ascii_ident_cont(src_[pos_]) || src_[pos_] == '\'')) {
                advance();
            }
            std::string num_str;
            num_str.reserve(pos_ - start);
            for (std::size_t i = start; i < pos_; ++i) {
                if (src_[i] != '\'') {
                    num_str.push_back(src_[i]);
                }
            }
            out.push_back(Token{
                .kind = TokenKind::Number,
                .text = std::move(num_str),
                .line = tok_line,
                .column = tok_col,
            });
            return true;
        }

        // Multi-character operators
        if (c == '.' && peek(1) == '.' && peek(2) == '.') {
            advance(3);
            out.push_back(Token{.kind = TokenKind::Ellipsis, .text = "...", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '<' && peek(1) == '<') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::LShift, .text = "<<", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '>' && peek(1) == '>') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::RShift, .text = ">>", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '<' && peek(1) == '=') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::LessEq, .text = "<=", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '>' && peek(1) == '=') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::GreaterEq, .text = ">=", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '=' && peek(1) == '=') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::EqEq, .text = "==", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '!' && peek(1) == '=') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::NotEq, .text = "!=", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '&' && peek(1) == '&') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::AmpAmp, .text = "&&", .line = tok_line, .column = tok_col});
            return true;
        }
        if (c == '|' && peek(1) == '|') {
            advance(2);
            out.push_back(Token{.kind = TokenKind::PipePipe, .text = "||", .line = tok_line, .column = tok_col});
            return true;
        }

        // Single-character punctuation
        TokenKind single = TokenKind::Eof;
        switch (c) {
            case '{': single = TokenKind::LBrace; break;
            case '}': single = TokenKind::RBrace; break;
            case '(': single = TokenKind::LParen; break;
            case ')': single = TokenKind::RParen; break;
            case '[': single = TokenKind::LBracket; break;
            case ']': single = TokenKind::RBracket; break;
            case ';': single = TokenKind::Semicolon; break;
            case ',': single = TokenKind::Comma; break;
            case ':': single = TokenKind::Colon; break;
            case '?': single = TokenKind::Question; break;
            case '*': single = TokenKind::Star; break;
            case '+': single = TokenKind::Plus; break;
            case '-': single = TokenKind::Minus; break;
            case '/': single = TokenKind::Slash; break;
            case '%': single = TokenKind::Percent; break;
            case '&': single = TokenKind::Amp; break;
            case '|': single = TokenKind::Pipe; break;
            case '^': single = TokenKind::Caret; break;
            case '~': single = TokenKind::Tilde; break;
            case '!': single = TokenKind::Bang; break;
            case '=': single = TokenKind::Assign; break;
            case '<': single = TokenKind::Less; break;
            case '>': single = TokenKind::Greater; break;
            default:
                emit_error(tok_line,
                           tok_col,
                           std::format("Unexpected character '{}' (0x{:02X})",
                                       (c >= 0x20 && c < 0x7F) ? std::string(1, c) : std::string("?"),
                                       static_cast<unsigned char>(c)));
                advance();
                return true;
        }

        advance();
        out.push_back(Token{
            .kind = single,
            .text = std::string(1, c),
            .line = tok_line,
            .column = tok_col,
        });
        return true;
    }

    [[nodiscard]] bool lex_char_literal(std::vector<Token>& out,
                                        std::uint32_t tok_line,
                                        std::uint32_t tok_col) {
        advance(); // consume opening '\''
        std::string decoded;
        bool closed = false;
        while (pos_ < src_.size()) {
            const char ch = src_[pos_];
            if (ch == '\'') {
                advance();
                closed = true;
                break;
            }
            if (ch == '\r' || ch == '\n') {
                break;
            }
            if (ch == '\\') {
                advance();
                if (pos_ >= src_.size()) {
                    break;
                }
                const char esc = src_[pos_];
                advance();
                switch (esc) {
                    case 'n': decoded.push_back('\n'); break;
                    case 'r': decoded.push_back('\r'); break;
                    case 't': decoded.push_back('\t'); break;
                    case 'v': decoded.push_back('\v'); break;
                    case 'b': decoded.push_back('\b'); break;
                    case 'f': decoded.push_back('\f'); break;
                    case 'a': decoded.push_back('\a'); break;
                    case '\\': decoded.push_back('\\'); break;
                    case '\'': decoded.push_back('\''); break;
                    case '"': decoded.push_back('"'); break;
                    case '?': decoded.push_back('?'); break;
                    case 'x': {
                        std::uint32_t hex_val = 0;
                        std::size_t digits = 0;
                        while (pos_ < src_.size() && is_ascii_hex(src_[pos_]) && digits < 2u) {
                            const char hc = src_[pos_];
                            const std::uint32_t nibble =
                                is_ascii_digit(hc)
                                    ? static_cast<std::uint32_t>(hc - '0')
                                    : static_cast<std::uint32_t>(ascii_to_lower(hc) - 'a' + 10);
                            hex_val = (hex_val << 4u) | nibble;
                            advance();
                            ++digits;
                        }
                        if (digits == 0u) {
                            emit_error(tok_line, tok_col, "Invalid '\\x' escape in character literal");
                        }
                        decoded.push_back(static_cast<char>(hex_val & 0xFFu));
                        break;
                    }
                    default:
                        if (esc >= '0' && esc <= '7') {
                            std::uint32_t oct_val = static_cast<std::uint32_t>(esc - '0');
                            std::size_t digits = 1;
                            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '7' &&
                                   digits < 3u) {
                                oct_val = (oct_val << 3u) | static_cast<std::uint32_t>(src_[pos_] - '0');
                                advance();
                                ++digits;
                            }
                            decoded.push_back(static_cast<char>(oct_val & 0xFFu));
                        } else {
                            decoded.push_back(esc);
                        }
                        break;
                }
            } else {
                decoded.push_back(ch);
                advance();
            }
        }

        if (!closed) {
            emit_error(tok_line, tok_col, "Unclosed character literal");
            return false;
        }
        if (decoded.empty()) {
            emit_error(tok_line, tok_col, "Empty character literal");
            return true;
        }
        if (decoded.size() > 8u) {
            emit_error(tok_line, tok_col, "Character literal exceeds 8 bytes");
            return true;
        }
        out.push_back(Token{
            .kind = TokenKind::CharLiteral,
            .text = std::move(decoded),
            .line = tok_line,
            .column = tok_col,
        });
        return true;
    }

    void skip_to_end_of_directive_line() {
        while (pos_ < src_.size()) {
            if (src_[pos_] == '\\' &&
                (peek(1) == '\n' || (peek(1) == '\r' && peek(2) == '\n'))) {
                advance();
                consume_newline();
                continue;
            }
            if (src_[pos_] == '/' && peek(1) == '/') {
                advance(2);
                while (pos_ < src_.size() && src_[pos_] != '\r' && src_[pos_] != '\n') {
                    advance();
                }
                break;
            }
            if (src_[pos_] == '/' && peek(1) == '*') {
                const std::uint32_t sl = line_;
                const std::uint32_t sc = col_;
                advance(2);
                bool closed = false;
                while (pos_ < src_.size()) {
                    if (src_[pos_] == '*' && peek(1) == '/') {
                        advance(2);
                        closed = true;
                        break;
                    }
                    if (src_[pos_] == '\r' || src_[pos_] == '\n') {
                        consume_newline();
                    } else {
                        advance();
                    }
                }
                if (!closed) {
                    emit_error(sl, sc, "Unclosed block comment '/*'");
                }
                continue;
            }
            if (src_[pos_] == '\r' || src_[pos_] == '\n') {
                break;
            }
            advance();
        }
    }

    [[nodiscard]] std::vector<Token> collect_directive_tokens() {
        std::vector<Token> line_toks;
        while (pos_ < src_.size()) {
            const char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\v' || c == '\f') {
                advance();
                continue;
            }
            if (c == '\\' && (peek(1) == '\n' || (peek(1) == '\r' && peek(2) == '\n'))) {
                advance();
                consume_newline();
                continue;
            }
            if (c == '/' && peek(1) == '/') {
                skip_to_end_of_directive_line();
                break;
            }
            if (c == '/' && peek(1) == '*') {
                const std::uint32_t sl = line_;
                const std::uint32_t sc = col_;
                advance(2);
                bool closed = false;
                while (pos_ < src_.size()) {
                    if (src_[pos_] == '*' && peek(1) == '/') {
                        advance(2);
                        closed = true;
                        break;
                    }
                    if (src_[pos_] == '\r' || src_[pos_] == '\n') {
                        consume_newline();
                    } else {
                        advance();
                    }
                }
                if (!closed) {
                    emit_error(sl, sc, "Unclosed block comment '/*'");
                    break;
                }
                continue;
            }
            if (c == '\r' || c == '\n') {
                break;
            }
            if (!lex_single_token(line_toks, true)) {
                break;
            }
        }
        return line_toks;
    }

    [[nodiscard]] static bool parse_pack_alignment(const Token& tok, std::uint64_t& out_val) {
        std::uint64_t v = 0;
        const auto [ptr, ec] =
            std::from_chars(tok.text.data(), tok.text.data() + tok.text.size(), v, 10);
        if (ec != std::errc{} || ptr != tok.text.data() + tok.text.size()) {
            return false;
        }
        if (v != 1u && v != 2u && v != 4u && v != 8u && v != 16u) {
            return false;
        }
        out_val = v;
        return true;
    }

    void lex_preprocessor_directive(std::vector<Token>& out) {
        const std::uint32_t hash_line = line_;
        const std::uint32_t hash_col = col_;
        advance(); // consume '#'

        // Peek first word manually so `#include <stdint.h>` doesn't lex `<stdint.h>` as operators
        while (pos_ < src_.size() && (src_[pos_] == ' ' || src_[pos_] == '\t')) {
            advance();
        }
        if (pos_ >= src_.size() || src_[pos_] == '\r' || src_[pos_] == '\n') {
            return;
        }
        const std::uint32_t kw_line = line_;
        const std::uint32_t kw_col = col_;
        if (!is_ascii_ident_start(src_[pos_])) {
            emit_error(kw_line, kw_col, "Invalid preprocessor directive");
            skip_to_end_of_directive_line();
            return;
        }
        const std::size_t kw_start = pos_;
        while (pos_ < src_.size() && is_ascii_ident_cont(src_[pos_])) {
            advance();
        }
        const std::string_view directive = src_.substr(kw_start, pos_ - kw_start);

        if (directive == "include" || directive == "ifdef" || directive == "ifndef" ||
            directive == "endif" || directive == "if" || directive == "elif" ||
            directive == "else" || directive == "undef") {
            skip_to_end_of_directive_line();
            return;
        }

        if (directive == "define") {
            while (pos_ < src_.size() && (src_[pos_] == ' ' || src_[pos_] == '\t')) {
                advance();
            }
            if (pos_ >= src_.size() || !is_ascii_ident_start(src_[pos_])) {
                emit_error(kw_line, kw_col, "Expected macro name after '#define'");
                skip_to_end_of_directive_line();
                return;
            }
            const std::size_t m_start = pos_;
            while (pos_ < src_.size() && is_ascii_ident_cont(src_[pos_])) {
                advance();
            }
            const std::string macro_name(src_.substr(m_start, pos_ - m_start));
            // Function-like macro `#define FOO(x) ...` (no space before `(`): skip cleanly
            if (pos_ < src_.size() && src_[pos_] == '(') {
                skip_to_end_of_directive_line();
                return;
            }
            std::vector<Token> body = collect_directive_tokens();
            macros_[macro_name] = std::move(body);
            return;
        }

        if (directive == "pragma") {
            const std::vector<Token> args = collect_directive_tokens();
            if (args.empty()) {
                return;
            }
            if (args[0].kind == TokenKind::Identifier && args[0].text == "once") {
                return;
            }
            if (args[0].kind == TokenKind::Identifier && args[0].text == "pack") {
                if (args.size() < 3u || args[1].kind != TokenKind::LParen ||
                    args.back().kind != TokenKind::RParen) {
                    emit_error(args[0].line, args[0].column, "Malformed '#pragma pack(...)' directive");
                    return;
                }
                // `#pragma pack()`
                if (args.size() == 3u) {
                    out.push_back(Token{
                        .kind = TokenKind::PragmaPackSet,
                        .text = "pack()",
                        .line = hash_line,
                        .column = hash_col,
                        .pragma_pack_val = 0,
                        .pragma_has_val = true,
                    });
                    return;
                }
                // `#pragma pack(N)`
                if (args.size() == 4u && args[2].kind == TokenKind::Number) {
                    std::uint64_t pack_val = 0;
                    if (!parse_pack_alignment(args[2], pack_val)) {
                        emit_error(args[2].line,
                                   args[2].column,
                                   std::format("Invalid '#pragma pack({})' value (expected 1, 2, 4, 8, or 16)",
                                               args[2].text));
                        return;
                    }
                    out.push_back(Token{
                        .kind = TokenKind::PragmaPackSet,
                        .text = "pack(N)",
                        .line = hash_line,
                        .column = hash_col,
                        .pragma_pack_val = pack_val,
                        .pragma_has_val = true,
                    });
                    return;
                }
                // `#pragma pack(push)` or `#pragma pack(push, N)` or `#pragma pack(push, id, N)`
                if (args[2].kind == TokenKind::Identifier && args[2].text == "push") {
                    if (args.size() == 4u) {
                        out.push_back(Token{
                            .kind = TokenKind::PragmaPackPush,
                            .text = "pack(push)",
                            .line = hash_line,
                            .column = hash_col,
                            .pragma_pack_val = 0,
                            .pragma_has_val = false,
                        });
                        return;
                    }
                    if (args.size() == 6u && args[3].kind == TokenKind::Comma &&
                        args[4].kind == TokenKind::Number) {
                        std::uint64_t pack_val = 0;
                        if (!parse_pack_alignment(args[4], pack_val)) {
                            emit_error(args[4].line,
                                       args[4].column,
                                       std::format("Invalid '#pragma pack(push, {})' value (expected 1, 2, 4, 8, or 16)",
                                                   args[4].text));
                            return;
                        }
                        out.push_back(Token{
                            .kind = TokenKind::PragmaPackPush,
                            .text = "pack(push,N)",
                            .line = hash_line,
                            .column = hash_col,
                            .pragma_pack_val = pack_val,
                            .pragma_has_val = true,
                        });
                        return;
                    }
                    if (args.size() == 6u && args[3].kind == TokenKind::Comma &&
                        args[4].kind == TokenKind::Identifier) {
                        out.push_back(Token{
                            .kind = TokenKind::PragmaPackPush,
                            .text = "pack(push,id)",
                            .line = hash_line,
                            .column = hash_col,
                            .pragma_pack_val = 0,
                            .pragma_has_val = false,
                        });
                        return;
                    }
                    if (args.size() == 8u && args[3].kind == TokenKind::Comma &&
                        args[4].kind == TokenKind::Identifier &&
                        args[5].kind == TokenKind::Comma &&
                        args[6].kind == TokenKind::Number) {
                        std::uint64_t pack_val = 0;
                        if (!parse_pack_alignment(args[6], pack_val)) {
                            emit_error(args[6].line,
                                       args[6].column,
                                       std::format("Invalid '#pragma pack(push, ..., {})' value (expected 1, 2, 4, 8, or 16)",
                                                   args[6].text));
                            return;
                        }
                        out.push_back(Token{
                            .kind = TokenKind::PragmaPackPush,
                            .text = "pack(push,id,N)",
                            .line = hash_line,
                            .column = hash_col,
                            .pragma_pack_val = pack_val,
                            .pragma_has_val = true,
                        });
                        return;
                    }
                    emit_error(args[2].line, args[2].column, "Malformed '#pragma pack(push, ...)' directive");
                    return;
                }
                // `#pragma pack(pop)` or `#pragma pack(pop, id)`
                if (args[2].kind == TokenKind::Identifier && args[2].text == "pop") {
                    if (args.size() == 4u ||
                        (args.size() == 6u && args[3].kind == TokenKind::Comma &&
                         args[4].kind == TokenKind::Identifier)) {
                        out.push_back(Token{
                            .kind = TokenKind::PragmaPackPop,
                            .text = "pack(pop)",
                            .line = hash_line,
                            .column = hash_col,
                        });
                        return;
                    }
                    emit_error(args[2].line, args[2].column, "Malformed '#pragma pack(pop, ...)' directive");
                    return;
                }
                emit_error(args[0].line, args[0].column, "Unsupported '#pragma pack(...)' arguments");
            }
            return;
        }

        emit_warning(kw_line, kw_col, std::format("Ignored preprocessor directive '#{}'", directive));
        skip_to_end_of_directive_line();
    }
};

// ============================================================================
// Parser & ABI Layout Engine
// ============================================================================

struct AttrSpec {
    bool packed = false;
    std::uint64_t explicit_align = 0;
};

struct ConstVal {
    std::uint64_t bits = 0;
    bool is_unsigned = false;

    [[nodiscard]] std::int64_t as_signed() const noexcept {
        return static_cast<std::int64_t>(bits);
    }
};

enum class ResolvedCategory : std::uint8_t {
    Void = 0,
    Integer,
    Float,
    Pointer,
    Array,
    StructOrUnion,
    Enum,
};

struct TypeInfo {
    ResolvedCategory category = ResolvedCategory::Integer;
    std::string type_name{};
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;
    bool is_signed = false;
    bool is_complete = true;
    bool is_anonymous_inline_agg = false;
    DataTypeRecord inline_anon_record{};
};

struct DeclaratorSuffix {
    bool is_array = false;
    std::uint64_t array_count = 0;
    bool is_func_params = false;
    std::string func_params_str{};
};

struct ParsedDeclarator {
    std::string name{};
    std::uint32_t name_line = 1;
    std::uint32_t name_col = 1;
    std::size_t outer_pointer_count = 0;
    std::vector<std::uint8_t> outer_ptr_size_overrides{};
    std::size_t inner_pointer_count = 0; // e.g. `(*fn)` has inner_pointer_count = 1
    std::vector<DeclaratorSuffix> inner_suffixes{};
    std::vector<DeclaratorSuffix> outer_suffixes{};
    bool has_bitfield = false;
    std::uint64_t bitfield_width = 0;
    std::uint32_t bitfield_line = 1;
    std::uint32_t bitfield_col = 1;
    AttrSpec attrs{};
};

class CTypeParser {
public:
    CTypeParser(std::vector<Token> tokens, const CTypeParseOptions& opts, CTypeParseResult& result)
        : tokens_(std::move(tokens)), opts_(opts), res_(result) {
        register_builtin_types();
        register_external_types();
    }

    void parse_translation_unit() {
        while (!is_eof()) {
            consume_pragmas();
            if (is_eof()) {
                break;
            }
            if (match(TokenKind::Semicolon)) {
                continue;
            }
            if (!parse_top_level_declaration()) {
                synchronize_top_level();
            }
        }
    }

private:
    struct RegisteredType {
        TypeInfo info{};
        std::size_t record_index = std::numeric_limits<std::size_t>::max();
    };

    std::vector<Token> tokens_;
    std::size_t idx_ = 0;
    CTypeParseOptions opts_;
    CTypeParseResult& res_;

    std::uint64_t active_pack_ = 0;
    std::vector<std::uint64_t> pack_stack_{};

    std::unordered_map<std::string, RegisteredType> typedef_map_{};
    std::unordered_map<std::string, RegisteredType> tag_map_{}; // struct/union/enum tags
    std::unordered_map<std::string, std::vector<std::string>> pending_tag_aliases_{};
    std::unordered_set<std::string> in_progress_tags_{};
    std::uint32_t anon_counter_ = 0;

    [[nodiscard]] std::uint64_t pointer_size() const noexcept {
        return static_cast<std::uint64_t>(opts_.layout.pointer_size());
    }

    [[nodiscard]] std::uint64_t long_size() const noexcept {
        if (pointer_size() == 4u) {
            return 4u;
        }
        return (opts_.long_model == CLongModel::LP64) ? 8u : 4u;
    }

    [[nodiscard]] std::uint64_t wchar_size() const noexcept {
        return (pointer_size() == 8u && opts_.long_model == CLongModel::LP64) ? 4u : 2u;
    }

    void register_scalar_alias(std::string name,
                               std::string canonical,
                               ResolvedCategory cat,
                               std::uint64_t sz,
                               bool is_signed) {
        typedef_map_[std::move(name)] = RegisteredType{
            .info = TypeInfo{
                .category = cat,
                .type_name = std::move(canonical),
                .size = sz,
                .alignment = std::max<std::uint64_t>(1u, sz),
                .is_signed = is_signed,
                .is_complete = (cat != ResolvedCategory::Void),
            },
        };
    }

    void register_pointer_alias(std::string name, std::string target_ptr_expr) {
        const std::uint64_t ps = pointer_size();
        typedef_map_[std::move(name)] = RegisteredType{
            .info = TypeInfo{
                .category = ResolvedCategory::Pointer,
                .type_name = std::move(target_ptr_expr),
                .size = ps,
                .alignment = ps,
                .is_signed = false,
                .is_complete = true,
            },
        };
    }

    void register_builtin_types() {
        const std::uint64_t ps = pointer_size();
        const std::uint64_t ls = long_size();
        const std::uint64_t ws = wchar_size();

        // Standard stdint / C / C++ fixed-width aliases
        register_scalar_alias("bool", "bool", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("_Bool", "bool", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("int8_t", "int8_t", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("uint8_t", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("__int8", "int8_t", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("int16_t", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("uint16_t", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("__int16", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("char16_t", "char16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("int32_t", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("uint32_t", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("__int32", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("char32_t", "char32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("int64_t", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("uint64_t", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("__int64", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("wchar_t", "wchar_t", ResolvedCategory::Integer, ws, false);

        // Pointer-sized POSIX / C aliases
        register_scalar_alias("size_t", "size_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("ssize_t", "ssize_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("uintptr_t", "uintptr_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("intptr_t", "intptr_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("ptrdiff_t", "ptrdiff_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("off_t", "int64_t", ResolvedCategory::Integer, ls == 8 ? 8 : 4, true);

        // Rust / kernel shorthand aliases often used by reverse engineers
        register_scalar_alias("u8", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("i8", "int8_t", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("s8", "int8_t", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("u16", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("i16", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("s16", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("u32", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("i32", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("s32", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("u64", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("i64", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("s64", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("usize", "size_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("isize", "ssize_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("u_char", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("u_short", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("u_int", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("u_long", ls == 8 ? "uint64_t" : "uint32_t", ResolvedCategory::Integer, ls, false);
        register_scalar_alias("uchar", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("ushort", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("uint", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("ulong", ls == 8 ? "uint64_t" : "uint32_t", ResolvedCategory::Integer, ls, false);

        // Win32 / NT SDK aliases (always Win32 widths even when inspecting PE or cross-ABI)
        register_scalar_alias("VOID", "void", ResolvedCategory::Void, 0, false);
        register_scalar_alias("BYTE", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("UCHAR", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("CHAR", "char", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("CCHAR", "char", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("BOOLEAN", "bool", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("INT8", "int8_t", ResolvedCategory::Integer, 1, true);
        register_scalar_alias("UINT8", "uint8_t", ResolvedCategory::Integer, 1, false);
        register_scalar_alias("WORD", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("USHORT", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("SHORT", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("WCHAR", "wchar_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("INT16", "int16_t", ResolvedCategory::Integer, 2, true);
        register_scalar_alias("UINT16", "uint16_t", ResolvedCategory::Integer, 2, false);
        register_scalar_alias("DWORD", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("ULONG", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("LONG", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("UINT", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("INT", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("BOOL", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("INT32", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("UINT32", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("DWORD32", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("ULONG32", "uint32_t", ResolvedCategory::Integer, 4, false);
        register_scalar_alias("LONG32", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("HRESULT", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("NTSTATUS", "int32_t", ResolvedCategory::Integer, 4, true);
        register_scalar_alias("QWORD", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("ULONGLONG", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("LONGLONG", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("DWORDLONG", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("DWORD64", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("ULONG64", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("LONG64", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("INT64", "int64_t", ResolvedCategory::Integer, 8, true);
        register_scalar_alias("UINT64", "uint64_t", ResolvedCategory::Integer, 8, false);
        register_scalar_alias("ULONG_PTR", "uintptr_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("DWORD_PTR", "uintptr_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("UINT_PTR", "uintptr_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("LONG_PTR", "intptr_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("INT_PTR", "intptr_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("SIZE_T", "size_t", ResolvedCategory::Integer, ps, false);
        register_scalar_alias("SSIZE_T", "ssize_t", ResolvedCategory::Integer, ps, true);
        register_scalar_alias("KAFFINITY", "uintptr_t", ResolvedCategory::Integer, ps, false);

        register_pointer_alias("PVOID", "void*");
        register_pointer_alias("LPVOID", "void*");
        register_pointer_alias("LPCVOID", "void*");
        register_pointer_alias("HANDLE", "void*");
        register_pointer_alias("HMODULE", "void*");
        register_pointer_alias("HINSTANCE", "void*");
        register_pointer_alias("HWND", "void*");
        register_pointer_alias("HKEY", "void*");
        register_pointer_alias("FARPROC", "void (*)()");
        register_pointer_alias("LPSTR", "char*");
        register_pointer_alias("PSTR", "char*");
        register_pointer_alias("LPCSTR", "char*");
        register_pointer_alias("PCSTR", "char*");
        register_pointer_alias("PCHAR", "char*");
        register_pointer_alias("LPWSTR", "wchar_t*");
        register_pointer_alias("PWSTR", "wchar_t*");
        register_pointer_alias("LPCWSTR", "wchar_t*");
        register_pointer_alias("PCWSTR", "wchar_t*");
        register_pointer_alias("PWCHAR", "wchar_t*");
        register_pointer_alias("PBYTE", "uint8_t*");
        register_pointer_alias("LPBYTE", "uint8_t*");
        register_pointer_alias("PUCHAR", "uint8_t*");
        register_pointer_alias("PWORD", "uint16_t*");
        register_pointer_alias("LPWORD", "uint16_t*");
        register_pointer_alias("PDWORD", "uint32_t*");
        register_pointer_alias("LPDWORD", "uint32_t*");
        register_pointer_alias("PULONG", "uint32_t*");
    }

    void register_external_types() {
        for (const DataTypeRecord& ext : opts_.external_types) {
            if (ext.name.empty()) {
                continue;
            }
            const std::uint64_t align =
                ext.size >= 8u ? 8u : (ext.size >= 4u ? 4u : (ext.size >= 2u ? 2u : 1u));
            RegisteredType reg{
                .info = TypeInfo{
                    .category = ext.is_enum ? ResolvedCategory::Enum
                                            : ResolvedCategory::StructOrUnion,
                    .type_name = ext.name,
                    .size = ext.size,
                    .alignment = align,
                    .is_signed = ext.is_enum ? ext.is_enum_signed : false,
                    .is_complete = true,
                },
            };
            tag_map_.emplace(ext.name, reg);
            typedef_map_.emplace(ext.name, reg);
            for (const std::string& al : ext.aliases) {
                if (!al.empty()) {
                    typedef_map_.emplace(al, reg);
                }
            }
            for (const DataEnumEnumerator& ec : ext.enum_constants) {
                res_.enum_constants.emplace(ec.name, ec.value);
            }
        }
    }

    // ------------------------------------------------------------------------
    // Token navigation & pragma execution
    // ------------------------------------------------------------------------

    void consume_pragmas() {
        while (idx_ < tokens_.size()) {
            const Token& t = tokens_[idx_];
            if (t.kind == TokenKind::PragmaPackSet) {
                active_pack_ = t.pragma_pack_val;
                ++idx_;
            } else if (t.kind == TokenKind::PragmaPackPush) {
                if (pack_stack_.size() < 256u) {
                    pack_stack_.push_back(active_pack_);
                }
                if (t.pragma_has_val) {
                    active_pack_ = t.pragma_pack_val;
                }
                ++idx_;
            } else if (t.kind == TokenKind::PragmaPackPop) {
                if (pack_stack_.empty()) {
                    active_pack_ = 0;
                    emit_warning(t, "'#pragma pack(pop)' with empty pack stack; resetting alignment to default");
                } else {
                    active_pack_ = pack_stack_.back();
                    pack_stack_.pop_back();
                }
                ++idx_;
            } else {
                break;
            }
        }
    }

    [[nodiscard]] const Token& cur() {
        consume_pragmas();
        return tokens_[std::min(idx_, tokens_.size() - 1u)];
    }

    [[nodiscard]] const Token& peek_tok(std::size_t ahead = 1) {
        consume_pragmas();
        std::size_t p = idx_;
        std::size_t rem = ahead;
        while (p < tokens_.size() - 1u && rem > 0u) {
            ++p;
            const TokenKind k = tokens_[p].kind;
            if (k == TokenKind::PragmaPackSet || k == TokenKind::PragmaPackPush ||
                k == TokenKind::PragmaPackPop) {
                continue;
            }
            --rem;
        }
        return tokens_[std::min(p, tokens_.size() - 1u)];
    }

    [[nodiscard]] bool is_eof() { return cur().kind == TokenKind::Eof; }

    Token advance_tok() {
        const Token t = cur();
        if (idx_ < tokens_.size() - 1u) {
            ++idx_;
        }
        return t;
    }

    [[nodiscard]] bool check(TokenKind k) { return cur().kind == k; }

    [[nodiscard]] bool check_kw(std::string_view kw) {
        const Token& t = cur();
        return t.kind == TokenKind::Identifier && t.text == kw;
    }

    bool match(TokenKind k) {
        if (check(k)) {
            advance_tok();
            return true;
        }
        return false;
    }

    bool match_kw(std::string_view kw) {
        if (check_kw(kw)) {
            advance_tok();
            return true;
        }
        return false;
    }

    void emit_error(const Token& t, std::string msg) {
        res_.diagnostics.push_back(CTypeParseDiagnostic{
            .line = t.line,
            .column = t.column,
            .severity = CTypeDiagnosticSeverity::Error,
            .message = std::move(msg),
        });
    }

    void emit_error(std::uint32_t line, std::uint32_t col, std::string msg) {
        res_.diagnostics.push_back(CTypeParseDiagnostic{
            .line = line,
            .column = col,
            .severity = CTypeDiagnosticSeverity::Error,
            .message = std::move(msg),
        });
    }

    void emit_warning(const Token& t, std::string msg) {
        res_.diagnostics.push_back(CTypeParseDiagnostic{
            .line = t.line,
            .column = t.column,
            .severity = CTypeDiagnosticSeverity::Warning,
            .message = std::move(msg),
        });
    }

    void synchronize_top_level() {
        int brace_depth = 0;
        while (!is_eof()) {
            const Token t = advance_tok();
            if (t.kind == TokenKind::LBrace) {
                ++brace_depth;
            } else if (t.kind == TokenKind::RBrace) {
                if (brace_depth > 0) {
                    --brace_depth;
                }
                if (brace_depth == 0 && match(TokenKind::Semicolon)) {
                    return;
                }
            } else if (t.kind == TokenKind::Semicolon && brace_depth == 0) {
                return;
            }
        }
    }

    void synchronize_member() {
        int brace_depth = 0;
        while (!is_eof()) {
            if (brace_depth == 0 && check(TokenKind::RBrace)) {
                return;
            }
            const Token t = advance_tok();
            if (t.kind == TokenKind::LBrace) {
                ++brace_depth;
            } else if (t.kind == TokenKind::RBrace) {
                if (brace_depth > 0) {
                    --brace_depth;
                }
            } else if (t.kind == TokenKind::Semicolon && brace_depth == 0) {
                return;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Qualifiers, Calling Conventions, and Attributes
    // ------------------------------------------------------------------------

    [[nodiscard]] static bool is_cv_qualifier(std::string_view s) noexcept {
        return s == "const" || s == "__const" || s == "__const__" ||
               s == "volatile" || s == "__volatile" || s == "__volatile__" ||
               s == "restrict" || s == "__restrict" || s == "__restrict__" ||
               s == "_Atomic" || s == "__unaligned" || s == "_Nonnull" || s == "_Nullable";
    }

    [[nodiscard]] static bool is_calling_convention(std::string_view s) noexcept {
        return s == "__cdecl" || s == "_cdecl" || s == "__stdcall" || s == "_stdcall" ||
               s == "__fastcall" || s == "_fastcall" || s == "__vectorcall" ||
               s == "__thiscall" || s == "WINAPI" || s == "CALLBACK" ||
               s == "NTAPI" || s == "APIENTRY" || s == "STDMETHODCALLTYPE";
    }

    [[nodiscard]] static bool is_primitive_specifier_kw(std::string_view s) noexcept {
        return s == "void" || s == "char" || s == "short" || s == "int" || s == "long" ||
               s == "signed" || s == "__signed" || s == "__signed__" ||
               s == "unsigned" || s == "float" || s == "double" ||
               s == "bool" || s == "_Bool";
    }

    [[nodiscard]] bool is_known_type_start() {
        const Token& t = cur();
        if (t.kind != TokenKind::Identifier) {
            return false;
        }
        const std::string_view s = t.text;
        if (s == "struct" || s == "union" || s == "enum" || is_primitive_specifier_kw(s) ||
            is_cv_qualifier(s) || s == "__attribute__" || s == "__attribute" ||
            s == "__declspec" || s == "alignas" || s == "_Alignas") {
            return true;
        }
        return typedef_map_.contains(t.text) || tag_map_.contains(t.text);
    }

    void skip_balanced_parens() {
        if (!match(TokenKind::LParen)) {
            return;
        }
        int depth = 1;
        while (!is_eof() && depth > 0) {
            const Token t = advance_tok();
            if (t.kind == TokenKind::LParen) {
                ++depth;
            } else if (t.kind == TokenKind::RParen) {
                --depth;
            }
        }
    }

    bool parse_attributes(AttrSpec& out) {
        while (!is_eof()) {
            if (check_kw("__attribute__") || check_kw("__attribute")) {
                const Token attr_tok = advance_tok();
                if (!match(TokenKind::LParen) || !match(TokenKind::LParen)) {
                    emit_error(attr_tok, "Expected '((' after '__attribute__'");
                    return false;
                }
                while (!is_eof() && !check(TokenKind::RParen)) {
                    if (match(TokenKind::Comma)) {
                        continue;
                    }
                    if (!check(TokenKind::Identifier)) {
                        emit_error(cur(), "Expected attribute name inside '__attribute__((...))'");
                        return false;
                    }
                    const Token item = advance_tok();
                    if (item.text == "packed" || item.text == "__packed__") {
                        out.packed = true;
                    } else if (item.text == "aligned" || item.text == "__aligned__") {
                        if (match(TokenKind::LParen)) {
                            const Token align_tok = cur();
                            const auto val = parse_constant_expr(0);
                            if (!val.has_value()) {
                                return false;
                            }
                            if (!match(TokenKind::RParen)) {
                                emit_error(cur(), "Expected ')' after aligned(...) expression");
                                return false;
                            }
                            if ((!val->is_unsigned && val->as_signed() <= 0) ||
                                !is_power_of_two_u64(val->bits) || val->bits > 65536u) {
                                emit_error(align_tok,
                                           "Alignment value must be a power of two between 1 and 65536");
                                return false;
                            }
                            out.explicit_align = std::max(out.explicit_align, val->bits);
                        } else {
                            out.explicit_align = std::max<std::uint64_t>(out.explicit_align, 16u);
                        }
                    } else if (check(TokenKind::LParen)) {
                        skip_balanced_parens();
                    }
                }
                if (!match(TokenKind::RParen) || !match(TokenKind::RParen)) {
                    emit_error(cur(), "Expected '))' to close '__attribute__'");
                    return false;
                }
                continue;
            }

            if (check_kw("__declspec")) {
                const Token ds_tok = advance_tok();
                if (!match(TokenKind::LParen)) {
                    emit_error(ds_tok, "Expected '(' after '__declspec'");
                    return false;
                }
                while (!is_eof() && !check(TokenKind::RParen)) {
                    if (match(TokenKind::Comma)) {
                        continue;
                    }
                    if (!check(TokenKind::Identifier)) {
                        emit_error(cur(), "Expected modifier inside '__declspec(...)'");
                        return false;
                    }
                    const Token mod = advance_tok();
                    if (mod.text == "align") {
                        if (!match(TokenKind::LParen)) {
                            emit_error(cur(), "Expected '(' after '__declspec(align'");
                            return false;
                        }
                        const Token align_tok = cur();
                        const auto val = parse_constant_expr(0);
                        if (!val.has_value()) {
                            return false;
                        }
                        if (!match(TokenKind::RParen)) {
                            emit_error(cur(), "Expected ')' after '__declspec(align(...'");
                            return false;
                        }
                        if ((!val->is_unsigned && val->as_signed() <= 0) ||
                            !is_power_of_two_u64(val->bits) || val->bits > 65536u) {
                            emit_error(align_tok,
                                       "Alignment value must be a power of two between 1 and 65536");
                            return false;
                        }
                        out.explicit_align = std::max(out.explicit_align, val->bits);
                    } else if (check(TokenKind::LParen)) {
                        skip_balanced_parens();
                    }
                }
                if (!match(TokenKind::RParen)) {
                    emit_error(cur(), "Expected ')' after '__declspec(...)'");
                    return false;
                }
                continue;
            }

            if (check_kw("alignas") || check_kw("_Alignas")) {
                const Token al_tok = advance_tok();
                if (!match(TokenKind::LParen)) {
                    emit_error(al_tok, "Expected '(' after 'alignas'");
                    return false;
                }
                const Token arg_tok = cur();
                std::uint64_t align_val = 0;
                if (is_known_type_start()) {
                    const auto ti = parse_abstract_type_name(0);
                    if (!ti.has_value()) {
                        return false;
                    }
                    align_val = ti->alignment;
                } else {
                    const auto val = parse_constant_expr(0);
                    if (!val.has_value()) {
                        return false;
                    }
                    if (!val->is_unsigned && val->as_signed() <= 0) {
                        emit_error(arg_tok, "Alignment value must be positive");
                        return false;
                    }
                    align_val = val->bits;
                }
                if (!match(TokenKind::RParen)) {
                    emit_error(cur(), "Expected ')' after 'alignas(...)'");
                    return false;
                }
                if (!is_power_of_two_u64(align_val) || align_val > 65536u) {
                    emit_error(arg_tok,
                               "Alignment value must be a power of two between 1 and 65536");
                    return false;
                }
                out.explicit_align = std::max(out.explicit_align, align_val);
                continue;
            }

            break;
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // Checked 64-Bit Constant Integer Expression Evaluator
    // ------------------------------------------------------------------------

    [[nodiscard]] std::optional<ConstVal> parse_constant_expr(std::size_t depth) {
        if (depth > 64u) {
            emit_error(cur(), "Maximum constant expression nesting depth exceeded");
            return std::nullopt;
        }
        return parse_ternary(depth + 1u);
    }

    [[nodiscard]] std::optional<ConstVal> parse_ternary(std::size_t depth) {
        auto cond = parse_logical_or(depth);
        if (!cond.has_value()) {
            return std::nullopt;
        }
        if (match(TokenKind::Question)) {
            const auto t_val = parse_constant_expr(depth + 1u);
            if (!t_val.has_value()) {
                return std::nullopt;
            }
            if (!match(TokenKind::Colon)) {
                emit_error(cur(), "Expected ':' in ternary conditional expression");
                return std::nullopt;
            }
            const auto f_val = parse_ternary(depth + 1u);
            if (!f_val.has_value()) {
                return std::nullopt;
            }
            const bool is_u = t_val->is_unsigned || f_val->is_unsigned;
            ConstVal chosen = (cond->bits != 0u) ? *t_val : *f_val;
            chosen.is_unsigned = is_u;
            return chosen;
        }
        return cond;
    }

    [[nodiscard]] std::optional<ConstVal> parse_logical_or(std::size_t depth) {
        auto lhs = parse_logical_and(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (match(TokenKind::PipePipe)) {
            const auto rhs = parse_logical_and(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            lhs = ConstVal{
                .bits = (lhs->bits != 0u || rhs->bits != 0u) ? 1u : 0u,
                .is_unsigned = false,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_logical_and(std::size_t depth) {
        auto lhs = parse_bit_or(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (match(TokenKind::AmpAmp)) {
            const auto rhs = parse_bit_or(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            lhs = ConstVal{
                .bits = (lhs->bits != 0u && rhs->bits != 0u) ? 1u : 0u,
                .is_unsigned = false,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_bit_or(std::size_t depth) {
        auto lhs = parse_bit_xor(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (match(TokenKind::Pipe)) {
            const auto rhs = parse_bit_xor(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            lhs = ConstVal{
                .bits = lhs->bits | rhs->bits,
                .is_unsigned = lhs->is_unsigned || rhs->is_unsigned,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_bit_xor(std::size_t depth) {
        auto lhs = parse_bit_and(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (match(TokenKind::Caret)) {
            const auto rhs = parse_bit_and(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            lhs = ConstVal{
                .bits = lhs->bits ^ rhs->bits,
                .is_unsigned = lhs->is_unsigned || rhs->is_unsigned,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_bit_and(std::size_t depth) {
        auto lhs = parse_equality(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (match(TokenKind::Amp)) {
            const auto rhs = parse_equality(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            lhs = ConstVal{
                .bits = lhs->bits & rhs->bits,
                .is_unsigned = lhs->is_unsigned || rhs->is_unsigned,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_equality(std::size_t depth) {
        auto lhs = parse_relational(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (check(TokenKind::EqEq) || check(TokenKind::NotEq)) {
            const Token op = advance_tok();
            const auto rhs = parse_relational(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            const bool eq = (lhs->bits == rhs->bits);
            lhs = ConstVal{
                .bits = ((op.kind == TokenKind::EqEq) ? eq : !eq) ? 1u : 0u,
                .is_unsigned = false,
            };
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_relational(std::size_t depth) {
        auto lhs = parse_shift(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (check(TokenKind::Less) || check(TokenKind::LessEq) ||
               check(TokenKind::Greater) || check(TokenKind::GreaterEq)) {
            const Token op = advance_tok();
            const auto rhs = parse_shift(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            const bool cmp_u = lhs->is_unsigned || rhs->is_unsigned;
            bool res_b = false;
            if (cmp_u) {
                if (op.kind == TokenKind::Less) res_b = lhs->bits < rhs->bits;
                else if (op.kind == TokenKind::LessEq) res_b = lhs->bits <= rhs->bits;
                else if (op.kind == TokenKind::Greater) res_b = lhs->bits > rhs->bits;
                else res_b = lhs->bits >= rhs->bits;
            } else {
                const std::int64_t a = lhs->as_signed();
                const std::int64_t b = rhs->as_signed();
                if (op.kind == TokenKind::Less) res_b = a < b;
                else if (op.kind == TokenKind::LessEq) res_b = a <= b;
                else if (op.kind == TokenKind::Greater) res_b = a > b;
                else res_b = a >= b;
            }
            lhs = ConstVal{.bits = res_b ? 1u : 0u, .is_unsigned = false};
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_shift(std::size_t depth) {
        auto lhs = parse_additive(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (check(TokenKind::LShift) || check(TokenKind::RShift)) {
            const Token op = advance_tok();
            const auto rhs = parse_additive(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            if (!rhs->is_unsigned && rhs->as_signed() < 0) {
                emit_error(op, "Negative shift count in constant expression");
                return std::nullopt;
            }
            if (rhs->bits >= 64u) {
                emit_error(op, "Shift count >= 64 overflows 64-bit constant expression");
                return std::nullopt;
            }
            const std::uint32_t sh = static_cast<std::uint32_t>(rhs->bits);
            if (op.kind == TokenKind::LShift) {
                if (lhs->is_unsigned) {
                    if (sh > 0u && (lhs->bits >> (64u - sh)) != 0u) {
                        emit_error(op, "Left shift overflows 64-bit unsigned constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = lhs->bits << sh, .is_unsigned = true};
                } else {
                    if (lhs->as_signed() < 0) {
                        emit_error(op, "Left shift of negative value in constant expression");
                        return std::nullopt;
                    }
                    const std::uint64_t max_signed =
                        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
                    if (lhs->bits > (max_signed >> sh)) {
                        emit_error(op, "Signed left shift overflows 64-bit integer range");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = lhs->bits << sh, .is_unsigned = false};
                }
            } else {
                if (lhs->is_unsigned || lhs->as_signed() >= 0) {
                    lhs = ConstVal{.bits = lhs->bits >> sh, .is_unsigned = lhs->is_unsigned};
                } else {
                    // Portable arithmetic right shift on negative 64-bit two's complement without UB
                    const std::uint64_t shifted = lhs->bits >> sh;
                    const std::uint64_t fill =
                        (sh == 0u) ? 0u : (~std::uint64_t{0} << (64u - sh));
                    lhs = ConstVal{.bits = shifted | fill, .is_unsigned = false};
                }
            }
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_additive(std::size_t depth) {
        auto lhs = parse_multiplicative(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (check(TokenKind::Plus) || check(TokenKind::Minus)) {
            const Token op = advance_tok();
            const auto rhs = parse_multiplicative(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            const bool is_u = lhs->is_unsigned || rhs->is_unsigned;
            if (is_u) {
                if (op.kind == TokenKind::Plus) {
                    const auto sum = peelf::checked_add_u64(lhs->bits, rhs->bits);
                    if (!sum.has_value()) {
                        emit_error(op, "Unsigned integer addition overflow in constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = *sum, .is_unsigned = true};
                } else {
                    if (lhs->bits < rhs->bits) {
                        emit_error(op, "Unsigned integer subtraction underflow in constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = lhs->bits - rhs->bits, .is_unsigned = true};
                }
            } else {
                const std::int64_t a = lhs->as_signed();
                const std::int64_t b = rhs->as_signed();
                if (op.kind == TokenKind::Plus) {
                    if ((b > 0 && a > std::numeric_limits<std::int64_t>::max() - b) ||
                        (b < 0 && a < std::numeric_limits<std::int64_t>::min() - b)) {
                        emit_error(op, "Signed integer addition overflow in constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = static_cast<std::uint64_t>(a + b), .is_unsigned = false};
                } else {
                    if ((b < 0 && a > std::numeric_limits<std::int64_t>::max() + b) ||
                        (b > 0 && a < std::numeric_limits<std::int64_t>::min() + b)) {
                        emit_error(op, "Signed integer subtraction overflow in constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = static_cast<std::uint64_t>(a - b), .is_unsigned = false};
                }
            }
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_multiplicative(std::size_t depth) {
        auto lhs = parse_unary(depth);
        if (!lhs.has_value()) {
            return std::nullopt;
        }
        while (check(TokenKind::Star) || check(TokenKind::Slash) || check(TokenKind::Percent)) {
            const Token op = advance_tok();
            const auto rhs = parse_unary(depth);
            if (!rhs.has_value()) {
                return std::nullopt;
            }
            const bool is_u = lhs->is_unsigned || rhs->is_unsigned;
            if (op.kind == TokenKind::Star) {
                if (is_u) {
                    const auto prod = peelf::checked_mul_u64(lhs->bits, rhs->bits);
                    if (!prod.has_value()) {
                        emit_error(op, "Integer multiplication overflow in constant expression");
                        return std::nullopt;
                    }
                    lhs = ConstVal{.bits = *prod, .is_unsigned = true};
                } else {
                    const std::int64_t a = lhs->as_signed();
                    const std::int64_t b = rhs->as_signed();
                    if (a == 0 || b == 0) {
                        lhs = ConstVal{.bits = 0u, .is_unsigned = false};
                    } else {
                        const std::uint64_t mag_a =
                            (a < 0) ? (std::uint64_t{0} - static_cast<std::uint64_t>(a))
                                    : static_cast<std::uint64_t>(a);
                        const std::uint64_t mag_b =
                            (b < 0) ? (std::uint64_t{0} - static_cast<std::uint64_t>(b))
                                    : static_cast<std::uint64_t>(b);
                        const auto mag_prod = peelf::checked_mul_u64(mag_a, mag_b);
                        const bool neg = (a < 0) != (b < 0);
                        const std::uint64_t max_mag =
                            neg ? (static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1u)
                                : static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
                        if (!mag_prod.has_value() || *mag_prod > max_mag) {
                            emit_error(op, "Signed integer multiplication overflow in constant expression");
                            return std::nullopt;
                        }
                        const std::uint64_t res_bits = neg ? (std::uint64_t{0} - *mag_prod) : *mag_prod;
                        lhs = ConstVal{.bits = res_bits, .is_unsigned = false};
                    }
                }
            } else {
                if (rhs->bits == 0u) {
                    emit_error(op, "Division or modulo by zero in constant expression");
                    return std::nullopt;
                }
                if (is_u) {
                    const std::uint64_t r = (op.kind == TokenKind::Slash)
                                                ? (lhs->bits / rhs->bits)
                                                : (lhs->bits % rhs->bits);
                    lhs = ConstVal{.bits = r, .is_unsigned = true};
                } else {
                    const std::int64_t a = lhs->as_signed();
                    const std::int64_t b = rhs->as_signed();
                    if (a == std::numeric_limits<std::int64_t>::min() && b == -1) {
                        emit_error(op, "Signed integer division overflow (INT64_MIN / -1)");
                        return std::nullopt;
                    }
                    const std::int64_t r = (op.kind == TokenKind::Slash) ? (a / b) : (a % b);
                    lhs = ConstVal{.bits = static_cast<std::uint64_t>(r), .is_unsigned = false};
                }
            }
        }
        return lhs;
    }

    [[nodiscard]] std::optional<ConstVal> parse_unary(std::size_t depth) {
        if (depth > 64u) {
            emit_error(cur(), "Maximum constant expression nesting depth exceeded");
            return std::nullopt;
        }
        if (match(TokenKind::Plus)) {
            return parse_unary(depth + 1u);
        }
        if (check(TokenKind::Minus)) {
            const Token op = advance_tok();
            const auto v = parse_unary(depth + 1u);
            if (!v.has_value()) {
                return std::nullopt;
            }
            // Allow `-9223372036854775808` where the literal parsed as 0x8000000000000000u
            if (v->bits == 0x8000000000000000ULL && v->is_unsigned) {
                return ConstVal{.bits = 0x8000000000000000ULL, .is_unsigned = false};
            }
            if (!v->is_unsigned && v->as_signed() == std::numeric_limits<std::int64_t>::min()) {
                emit_error(op, "Signed integer negation overflow in constant expression");
                return std::nullopt;
            }
            return ConstVal{
                .bits = std::uint64_t{0} - v->bits,
                .is_unsigned = v->is_unsigned,
            };
        }
        if (match(TokenKind::Tilde)) {
            const auto v = parse_unary(depth + 1u);
            if (!v.has_value()) {
                return std::nullopt;
            }
            return ConstVal{.bits = ~v->bits, .is_unsigned = v->is_unsigned};
        }
        if (match(TokenKind::Bang)) {
            const auto v = parse_unary(depth + 1u);
            if (!v.has_value()) {
                return std::nullopt;
            }
            return ConstVal{.bits = (v->bits == 0u) ? 1u : 0u, .is_unsigned = false};
        }
        if (check_kw("sizeof")) {
            const Token sz_tok = advance_tok();
            if (check(TokenKind::LParen)) {
                const std::size_t saved_idx = idx_;
                advance_tok(); // '('
                if (is_known_type_start()) {
                    const Token type_tok = cur();
                    const auto ti = parse_abstract_type_name(depth + 1u);
                    if (!ti.has_value()) {
                        return std::nullopt;
                    }
                    if (!match(TokenKind::RParen)) {
                        emit_error(cur(), "Expected ')' after 'sizeof(type)'");
                        return std::nullopt;
                    }
                    if (!ti->is_complete || ti->category == ResolvedCategory::Void) {
                        emit_error(type_tok,
                                   std::format("Cannot apply 'sizeof' to incomplete or void type '{}'",
                                               ti->type_name));
                        return std::nullopt;
                    }
                    return ConstVal{.bits = ti->size, .is_unsigned = true};
                }
                idx_ = saved_idx;
            }
            // `sizeof (expr)` or `sizeof unary_expr`
            const auto expr_v = parse_unary(depth + 1u);
            if (!expr_v.has_value()) {
                emit_error(sz_tok, "Invalid operand to 'sizeof'");
                return std::nullopt;
            }
            return ConstVal{.bits = expr_v->is_unsigned ? 8u : 4u, .is_unsigned = true};
        }
        if (check_kw("alignof") || check_kw("_Alignof") || check_kw("__alignof__") ||
            check_kw("__alignof")) {
            const Token al_tok = advance_tok();
            if (!match(TokenKind::LParen)) {
                emit_error(al_tok, "Expected '(' after 'alignof'");
                return std::nullopt;
            }
            const auto ti = parse_abstract_type_name(depth + 1u);
            if (!ti.has_value()) {
                return std::nullopt;
            }
            if (!match(TokenKind::RParen)) {
                emit_error(cur(), "Expected ')' after 'alignof(type)'");
                return std::nullopt;
            }
            return ConstVal{.bits = ti->alignment, .is_unsigned = true};
        }

        // C-style cast `(int)expr` or parenthesized `(expr)`
        if (check(TokenKind::LParen)) {
            const std::size_t saved_idx = idx_;
            advance_tok(); // '('
            if (is_known_type_start()) {
                const auto cast_ti = parse_abstract_type_name(depth + 1u);
                if (cast_ti.has_value() && match(TokenKind::RParen)) {
                    const auto inner = parse_unary(depth + 1u);
                    if (!inner.has_value()) {
                        return std::nullopt;
                    }
                    if (cast_ti->category == ResolvedCategory::Integer ||
                        cast_ti->category == ResolvedCategory::Enum ||
                        cast_ti->category == ResolvedCategory::Pointer) {
                        const std::uint32_t bits_w =
                            static_cast<std::uint32_t>(std::min<std::uint64_t>(cast_ti->size * 8u, 64u));
                        if (bits_w > 0u && bits_w < 64u) {
                            const std::uint64_t mask = (std::uint64_t{1} << bits_w) - 1u;
                            std::uint64_t trunc = inner->bits & mask;
                            if (cast_ti->is_signed &&
                                (trunc & (std::uint64_t{1} << (bits_w - 1u))) != 0u) {
                                trunc |= ~mask;
                            }
                            return ConstVal{.bits = trunc, .is_unsigned = !cast_ti->is_signed};
                        }
                        return ConstVal{.bits = inner->bits, .is_unsigned = !cast_ti->is_signed};
                    }
                    return inner;
                }
            }
            idx_ = saved_idx;
            advance_tok(); // '('
            const auto v = parse_constant_expr(depth + 1u);
            if (!v.has_value()) {
                return std::nullopt;
            }
            if (!match(TokenKind::RParen)) {
                emit_error(cur(), "Expected ')' in constant expression");
                return std::nullopt;
            }
            return v;
        }

        return parse_primary();
    }

    [[nodiscard]] std::optional<ConstVal> parse_primary() {
        const Token t = cur();
        if (t.kind == TokenKind::Number) {
            advance_tok();
            return parse_number_literal(t);
        }
        if (t.kind == TokenKind::CharLiteral) {
            advance_tok();
            std::uint64_t v = 0;
            for (const char ch : t.text) {
                v = (v << 8u) | static_cast<unsigned char>(ch);
            }
            return ConstVal{.bits = v, .is_unsigned = false};
        }
        if (t.kind == TokenKind::Identifier) {
            advance_tok();
            if (t.text == "true" || t.text == "TRUE") {
                return ConstVal{.bits = 1u, .is_unsigned = false};
            }
            if (t.text == "false" || t.text == "FALSE") {
                return ConstVal{.bits = 0u, .is_unsigned = false};
            }
            if (const auto it = res_.enum_constants.find(t.text);
                it != res_.enum_constants.end()) {
                return ConstVal{
                    .bits = static_cast<std::uint64_t>(it->second),
                    .is_unsigned = false,
                };
            }
            emit_error(t, std::format("Unknown identifier '{}' in constant expression", t.text));
            return std::nullopt;
        }
        emit_error(t, std::format("Expected constant expression, found '{}'",
                                  t.text.empty() ? "<eof>" : t.text));
        return std::nullopt;
    }

    [[nodiscard]] std::optional<ConstVal> parse_number_literal(const Token& t) {
        std::string_view s = t.text;
        bool suffix_unsigned = false;
        // Strip valid integer suffixes: u/U, l/L, ll/LL, z/Z
        bool seen_u = false;
        int l_count = 0;
        bool seen_z = false;
        while (!s.empty()) {
            const char back = ascii_to_lower(s.back());
            if (back == 'u' && !seen_u) {
                seen_u = true;
                suffix_unsigned = true;
                s.remove_suffix(1u);
            } else if (back == 'l' && l_count < 2) {
                ++l_count;
                s.remove_suffix(1u);
            } else if (back == 'z' && !seen_z) {
                seen_z = true;
                s.remove_suffix(1u);
            } else {
                break;
            }
        }

        int base = 10;
        if (s.starts_with("0x") || s.starts_with("0X")) {
            base = 16;
            s.remove_prefix(2u);
        } else if (s.starts_with("0b") || s.starts_with("0B")) {
            base = 2;
            s.remove_prefix(2u);
        } else if (s.size() > 1u && s.front() == '0') {
            base = 8;
            s.remove_prefix(1u);
        }

        if (s.empty()) {
            emit_error(t, std::format("Malformed integer literal '{}'", t.text));
            return std::nullopt;
        }

        std::uint64_t val = 0;
        const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val, base);
        if (ec == std::errc::result_out_of_range) {
            emit_error(t, std::format("Integer literal '{}' overflows 64-bit integer range", t.text));
            return std::nullopt;
        }
        if (ec != std::errc{} || ptr != s.data() + s.size()) {
            emit_error(t, std::format("Invalid integer literal '{}'", t.text));
            return std::nullopt;
        }

        const bool exceeds_i64 =
            val > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        return ConstVal{
            .bits = val,
            .is_unsigned = suffix_unsigned || exceeds_i64,
        };
    }

    // ------------------------------------------------------------------------
    // Type Specifier & Tag Parsing
    // ------------------------------------------------------------------------

    [[nodiscard]] std::optional<TypeInfo> parse_abstract_type_name(std::size_t nesting_depth) {
        AttrSpec attrs{};
        if (!parse_attributes(attrs)) {
            return std::nullopt;
        }
        auto base = parse_base_type_specifier(nesting_depth, "");
        if (!base.has_value()) {
            return std::nullopt;
        }
        ParsedDeclarator decl{};
        if (!parse_declarator(decl, true, nesting_depth)) {
            return std::nullopt;
        }
        return apply_declarator_to_type(*base, decl, cur());
    }

    [[nodiscard]] std::optional<TypeInfo> parse_base_type_specifier(
        std::size_t nesting_depth,
        std::string_view enclosing_record_name) {
        if (nesting_depth > kMaxTypeNestingDepth) {
            emit_error(cur(), "Maximum struct/union/type nesting depth exceeded");
            return std::nullopt;
        }

        while (cur().kind == TokenKind::Identifier &&
               (is_cv_qualifier(cur().text) || is_calling_convention(cur().text))) {
            advance_tok();
        }

        const Token start_tok = cur();
        if (check_kw("struct") || check_kw("union")) {
            return parse_struct_or_union_specifier(nesting_depth, enclosing_record_name);
        }
        if (check_kw("enum")) {
            return parse_enum_specifier(nesting_depth);
        }

        // Multi-word C primitive specifiers (`unsigned long int`, `long long`, `signed char`, etc.)
        if (cur().kind == TokenKind::Identifier && is_primitive_specifier_kw(cur().text)) {
            bool seen_signed = false;
            bool seen_unsigned = false;
            bool seen_void = false;
            bool seen_bool = false;
            bool seen_char = false;
            bool seen_short = false;
            bool seen_int = false;
            int long_cnt = 0;
            bool seen_float = false;
            bool seen_double = false;

            while (cur().kind == TokenKind::Identifier) {
                const std::string_view w = cur().text;
                if (is_cv_qualifier(w) || is_calling_convention(w)) {
                    advance_tok();
                    continue;
                }
                if (w == "signed" || w == "__signed" || w == "__signed__") {
                    seen_signed = true;
                } else if (w == "unsigned") {
                    seen_unsigned = true;
                } else if (w == "void") {
                    seen_void = true;
                } else if (w == "bool" || w == "_Bool") {
                    seen_bool = true;
                } else if (w == "char") {
                    seen_char = true;
                } else if (w == "short") {
                    seen_short = true;
                } else if (w == "int") {
                    seen_int = true;
                } else if (w == "long") {
                    ++long_cnt;
                } else if (w == "float") {
                    seen_float = true;
                } else if (w == "double") {
                    seen_double = true;
                } else {
                    break;
                }
                advance_tok();
            }

            if (seen_signed && seen_unsigned) {
                emit_error(start_tok, "Cannot combine 'signed' and 'unsigned' in type specifier");
                return std::nullopt;
            }
            if (seen_void) {
                if (seen_signed || seen_unsigned || seen_short || seen_int || long_cnt > 0 ||
                    seen_char || seen_float || seen_double || seen_bool) {
                    emit_error(start_tok, "Invalid type specifier combination with 'void'");
                    return std::nullopt;
                }
                return TypeInfo{
                    .category = ResolvedCategory::Void,
                    .type_name = "void",
                    .size = 0,
                    .alignment = 1,
                    .is_signed = false,
                    .is_complete = false,
                };
            }
            if (seen_bool) {
                return TypeInfo{
                    .category = ResolvedCategory::Integer,
                    .type_name = "bool",
                    .size = 1,
                    .alignment = 1,
                    .is_signed = false,
                    .is_complete = true,
                };
            }
            if (seen_float) {
                if (seen_double || seen_signed || seen_unsigned || seen_short || long_cnt > 0) {
                    emit_error(start_tok, "Invalid type specifier combination with 'float'");
                    return std::nullopt;
                }
                return TypeInfo{
                    .category = ResolvedCategory::Float,
                    .type_name = "float",
                    .size = 4,
                    .alignment = 4,
                    .is_signed = true,
                    .is_complete = true,
                };
            }
            if (seen_double) {
                const bool is_ld = (long_cnt == 1);
                const std::uint64_t ld_sz =
                    (is_ld && pointer_size() == 8u && opts_.long_model == CLongModel::LP64) ? 16u : 8u;
                return TypeInfo{
                    .category = ResolvedCategory::Float,
                    .type_name = is_ld ? "long double" : "double",
                    .size = ld_sz,
                    .alignment = ld_sz,
                    .is_signed = true,
                    .is_complete = true,
                };
            }
            if (seen_char) {
                if (seen_short || seen_int || long_cnt > 0) {
                    emit_error(start_tok, "Invalid type specifier combination with 'char'");
                    return std::nullopt;
                }
                return TypeInfo{
                    .category = ResolvedCategory::Integer,
                    .type_name = seen_unsigned ? "uint8_t" : (seen_signed ? "int8_t" : "char"),
                    .size = 1,
                    .alignment = 1,
                    .is_signed = !seen_unsigned,
                    .is_complete = true,
                };
            }
            if (seen_short) {
                if (long_cnt > 0) {
                    emit_error(start_tok, "Cannot combine 'short' and 'long'");
                    return std::nullopt;
                }
                return TypeInfo{
                    .category = ResolvedCategory::Integer,
                    .type_name = seen_unsigned ? "uint16_t" : "int16_t",
                    .size = 2,
                    .alignment = 2,
                    .is_signed = !seen_unsigned,
                    .is_complete = true,
                };
            }
            if (long_cnt >= 2) {
                if (long_cnt > 2) {
                    emit_error(start_tok, "Too many 'long' specifiers");
                    return std::nullopt;
                }
                return TypeInfo{
                    .category = ResolvedCategory::Integer,
                    .type_name = seen_unsigned ? "uint64_t" : "int64_t",
                    .size = 8,
                    .alignment = 8,
                    .is_signed = !seen_unsigned,
                    .is_complete = true,
                };
            }
            if (long_cnt == 1) {
                const std::uint64_t ls = long_size();
                return TypeInfo{
                    .category = ResolvedCategory::Integer,
                    .type_name = seen_unsigned ? (ls == 8u ? "uint64_t" : "uint32_t")
                                               : (ls == 8u ? "int64_t" : "int32_t"),
                    .size = ls,
                    .alignment = ls,
                    .is_signed = !seen_unsigned,
                    .is_complete = true,
                };
            }
            (void)seen_int;
            return TypeInfo{
                .category = ResolvedCategory::Integer,
                .type_name = seen_unsigned ? "uint32_t" : "int32_t",
                .size = 4,
                .alignment = 4,
                .is_signed = !seen_unsigned,
                .is_complete = true,
            };
        }

        // Known typedef or C++ tag name
        if (cur().kind == TokenKind::Identifier) {
            const Token id_tok = advance_tok();
            while (cur().kind == TokenKind::Identifier && is_cv_qualifier(cur().text)) {
                advance_tok();
            }
            if (const auto it = typedef_map_.find(id_tok.text); it != typedef_map_.end()) {
                return resolve_latest_tag_state(it->second.info);
            }
            if (const auto tag_it = tag_map_.find(id_tok.text); tag_it != tag_map_.end()) {
                return tag_it->second.info;
            }
            emit_error(id_tok, std::format("Unknown type name '{}'", id_tok.text));
            return std::nullopt;
        }

        emit_error(start_tok,
                   std::format("Expected type specifier, found '{}'",
                               start_tok.text.empty() ? "<eof>" : start_tok.text));
        return std::nullopt;
    }

    [[nodiscard]] TypeInfo resolve_latest_tag_state(const TypeInfo& ti) const {
        if (ti.category == ResolvedCategory::StructOrUnion && !ti.is_complete) {
            if (const auto it = tag_map_.find(ti.type_name); it != tag_map_.end()) {
                return it->second.info;
            }
        }
        return ti;
    }

    // ------------------------------------------------------------------------
    // `enum` Specifier Parsing
    // ------------------------------------------------------------------------

    [[nodiscard]] std::optional<TypeInfo> parse_enum_specifier(std::size_t nesting_depth) {
        const Token enum_kw = advance_tok(); // consume `enum`
        AttrSpec enum_attrs{};
        if (!parse_attributes(enum_attrs)) {
            return std::nullopt;
        }
        if (!match_kw("class")) {
            (void)match_kw("struct"); // tolerate `enum class` / `enum struct`
        }

        std::string tag_name;
        if (check(TokenKind::Identifier)) {
            tag_name = advance_tok().text;
        }

        // Optional `: underlying_type`
        std::optional<TypeInfo> explicit_underlying;
        if (match(TokenKind::Colon)) {
            const Token ut_tok = cur();
            explicit_underlying = parse_base_type_specifier(nesting_depth + 1u, "");
            if (!explicit_underlying.has_value()) {
                return std::nullopt;
            }
            if (explicit_underlying->category != ResolvedCategory::Integer ||
                explicit_underlying->size == 0u || explicit_underlying->size > 8u) {
                emit_error(ut_tok, "Enum underlying type must be an integer type");
                return std::nullopt;
            }
        }

        // Enum reference without `{ ... }`
        if (!check(TokenKind::LBrace)) {
            if (tag_name.empty()) {
                emit_error(enum_kw, "Expected enum tag name or '{' after 'enum'");
                return std::nullopt;
            }
            if (const auto it = tag_map_.find(tag_name); it != tag_map_.end()) {
                return it->second.info;
            }
            // Forward-declared enum with explicit or default 4-byte underlying type
            const std::uint64_t sz = explicit_underlying ? explicit_underlying->size : 4u;
            const bool is_sgn = explicit_underlying ? explicit_underlying->is_signed : true;
            TypeInfo fwd_enum{
                .category = ResolvedCategory::Enum,
                .type_name = tag_name,
                .size = sz,
                .alignment = sz,
                .is_signed = is_sgn,
                .is_complete = true,
            };
            tag_map_[tag_name] = RegisteredType{.info = fwd_enum};
            return fwd_enum;
        }

        advance_tok(); // consume `{`
        DataTypeRecord rec{};
        rec.name = tag_name.empty() ? std::format("__anon_enum_{}", ++anon_counter_) : tag_name;
        rec.is_enum = true;
        rec.is_custom_c = true;

        std::int64_t next_signed_val = 0;
        bool next_overflowed = false;
        bool needs_64bit = false;
        bool has_negative = false;
        bool needs_unsigned_64 = false;

        while (!is_eof() && !check(TokenKind::RBrace)) {
            if (!check(TokenKind::Identifier)) {
                emit_error(cur(), "Expected enumerator identifier inside 'enum { ... }'");
                return std::nullopt;
            }
            const Token item_tok = advance_tok();
            AttrSpec item_attrs{};
            if (!parse_attributes(item_attrs)) {
                return std::nullopt;
            }

            std::int64_t item_val = 0;
            if (match(TokenKind::Assign)) {
                const auto cv = parse_constant_expr(0);
                if (!cv.has_value()) {
                    return std::nullopt;
                }
                item_val = cv->as_signed();
                if (cv->is_unsigned &&
                    cv->bits > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                    needs_64bit = true;
                    needs_unsigned_64 = true;
                }
                next_overflowed = (item_val == std::numeric_limits<std::int64_t>::max());
                if (!next_overflowed) {
                    next_signed_val = item_val + 1;
                }
            } else {
                if (next_overflowed) {
                    emit_error(item_tok, "Implicit enumerator value overflows 64-bit signed integer");
                    return std::nullopt;
                }
                item_val = next_signed_val;
                next_overflowed = (item_val == std::numeric_limits<std::int64_t>::max());
                if (!next_overflowed) {
                    next_signed_val = item_val + 1;
                }
            }

            if (item_val < 0) {
                has_negative = true;
                if (item_val < std::numeric_limits<std::int32_t>::min()) {
                    needs_64bit = true;
                }
            } else if (static_cast<std::uint64_t>(item_val) >
                       static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
                needs_64bit = true;
            }

            res_.enum_constants[item_tok.text] = item_val;
            rec.enum_constants.push_back(DataEnumEnumerator{
                .name = item_tok.text,
                .value = item_val,
            });

            if (!match(TokenKind::Comma)) {
                break;
            }
        }

        if (!match(TokenKind::RBrace)) {
            emit_error(cur(), "Expected '}' to close enum definition");
            return std::nullopt;
        }
        if (!parse_attributes(enum_attrs)) {
            return std::nullopt;
        }

        if (explicit_underlying.has_value()) {
            rec.size = explicit_underlying->size;
            rec.is_enum_signed = explicit_underlying->is_signed;
            rec.underlying_type = explicit_underlying->type_name;
        } else {
            rec.size = needs_64bit ? 8u : 4u;
            rec.is_enum_signed = has_negative || !needs_unsigned_64;
            rec.underlying_type =
                rec.size == 8u ? (rec.is_enum_signed ? "int64_t" : "uint64_t")
                               : (rec.is_enum_signed ? "int32_t" : "uint32_t");
        }

        std::uint64_t align = rec.size;
        if (enum_attrs.packed) {
            align = 1u;
        } else if (active_pack_ > 0u) {
            align = std::min(align, active_pack_);
        }
        if (enum_attrs.explicit_align > 0u) {
            align = std::max(align, enum_attrs.explicit_align);
        }

        TypeInfo ti{
            .category = ResolvedCategory::Enum,
            .type_name = rec.name,
            .size = rec.size,
            .alignment = std::max<std::uint64_t>(1u, align),
            .is_signed = rec.is_enum_signed,
            .is_complete = true,
        };

        if (!tag_name.empty()) {
            if (const auto pend_it = pending_tag_aliases_.find(tag_name);
                pend_it != pending_tag_aliases_.end()) {
                for (const std::string& al : pend_it->second) {
                    if (al != rec.name &&
                        std::ranges::find(rec.aliases, al) == rec.aliases.end()) {
                        rec.aliases.push_back(al);
                    }
                }
                pending_tag_aliases_.erase(pend_it);
            }
            const std::size_t rec_idx = res_.types.size();
            const std::vector<std::string> known_aliases = rec.aliases;
            res_.types.push_back(std::move(rec));
            RegisteredType reg{.info = ti, .record_index = rec_idx};
            tag_map_[tag_name] = reg;
            typedef_map_.emplace(tag_name, reg);
            for (const std::string& al : known_aliases) {
                typedef_map_[al] = reg;
            }
        } else {
            ti.is_anonymous_inline_agg = true;
            ti.inline_anon_record = std::move(rec);
        }
        return ti;
    }

    // ------------------------------------------------------------------------
    // `struct` / `union` Specifier & Layout Computation
    // ------------------------------------------------------------------------

    [[nodiscard]] std::optional<TypeInfo> parse_struct_or_union_specifier(
        std::size_t nesting_depth,
        std::string_view enclosing_record_name) {
        const Token kw_tok = advance_tok(); // `struct` or `union`
        const bool is_union = (kw_tok.text == "union");

        AttrSpec record_attrs{};
        if (!parse_attributes(record_attrs)) {
            return std::nullopt;
        }

        std::string tag_name;
        if (check(TokenKind::Identifier)) {
            tag_name = advance_tok().text;
        }
        if (!parse_attributes(record_attrs)) {
            return std::nullopt;
        }

        // Tag reference or forward declaration (`struct Node` without `{`)
        if (!check(TokenKind::LBrace)) {
            if (tag_name.empty()) {
                emit_error(kw_tok, std::format("Expected tag name or '{{' after '{}'", kw_tok.text));
                return std::nullopt;
            }
            if (const auto it = tag_map_.find(tag_name); it != tag_map_.end()) {
                return it->second.info;
            }
            TypeInfo incomplete{
                .category = ResolvedCategory::StructOrUnion,
                .type_name = tag_name,
                .size = 0,
                .alignment = 1,
                .is_signed = false,
                .is_complete = false,
            };
            tag_map_.emplace(tag_name, RegisteredType{.info = incomplete});
            return incomplete;
        }

        if (nesting_depth >= kMaxTypeNestingDepth) {
            emit_error(kw_tok, "Maximum struct/union nesting depth exceeded");
            return std::nullopt;
        }

        if (!tag_name.empty()) {
            if (in_progress_tags_.contains(tag_name)) {
                emit_error(kw_tok,
                           std::format("Recursive redefinition of '{}' while incomplete", tag_name));
                return std::nullopt;
            }
            in_progress_tags_.insert(tag_name);
            if (!tag_map_.contains(tag_name)) {
                tag_map_.emplace(tag_name, RegisteredType{
                    .info = TypeInfo{
                        .category = ResolvedCategory::StructOrUnion,
                        .type_name = tag_name,
                        .size = 0,
                        .alignment = 1,
                        .is_signed = false,
                        .is_complete = false,
                    },
                });
            }
        }

        const Token lbrace_tok = advance_tok(); // `{`
        const std::string working_name =
            !tag_name.empty()
                ? tag_name
                : (!enclosing_record_name.empty()
                       ? std::format("{}::__anon_{}_{}",
                                     enclosing_record_name,
                                     is_union ? "union" : "struct",
                                     ++anon_counter_)
                       : std::format("__anon_{}_{}",
                                     is_union ? "union" : "struct",
                                     ++anon_counter_));

        DataTypeRecord rec{};
        rec.name = working_name;
        rec.is_union = is_union;
        rec.is_custom_c = true;

        std::uint64_t current_offset = 0;
        std::uint64_t max_union_size = 0;
        std::uint64_t record_max_align = 1;

        // Bitfield storage unit state (for structs)
        bool bf_active = false;
        std::uint64_t bf_unit_offset = 0;
        std::uint64_t bf_unit_size = 0;
        std::uint32_t bf_bits_used = 0;

        std::unordered_set<std::string> seen_member_names;
        bool body_ok = true;

        while (!is_eof() && !check(TokenKind::RBrace)) {
            if (match(TokenKind::Semicolon)) {
                continue;
            }
            const std::uint64_t member_pack =
                record_attrs.packed ? 1u : active_pack_;

            AttrSpec leading_attrs{};
            if (!parse_attributes(leading_attrs)) {
                body_ok = false;
                break;
            }

            const Token member_start = cur();
            auto base_opt = parse_base_type_specifier(nesting_depth + 1u, working_name);
            if (!base_opt.has_value()) {
                body_ok = false;
                synchronize_member();
                continue;
            }
            TypeInfo base = *base_opt;

            // C11 anonymous inner `struct { ... };` or `union { ... };` (no declarator before `;`)
            if (check(TokenKind::Semicolon) && base.is_anonymous_inline_agg &&
                base.category == ResolvedCategory::StructOrUnion) {
                advance_tok(); // `;`
                bf_active = false;

                std::uint64_t anon_align = base.alignment;
                if (leading_attrs.packed) {
                    anon_align = 1u;
                } else if (member_pack > 0u) {
                    anon_align = std::min(anon_align, member_pack);
                }
                if (leading_attrs.explicit_align > 0u) {
                    anon_align = std::max(anon_align, leading_attrs.explicit_align);
                }
                record_max_align = std::max(record_max_align, anon_align);

                std::uint64_t base_off = 0;
                if (!is_union) {
                    const auto aligned = checked_align_up(current_offset, anon_align);
                    if (!aligned.has_value()) {
                        emit_error(member_start, "Struct size overflow while aligning anonymous record");
                        body_ok = false;
                        break;
                    }
                    base_off = *aligned;
                    const auto next_off = peelf::checked_add_u64(base_off, base.size);
                    if (!next_off.has_value()) {
                        emit_error(member_start, "Struct size overflow in anonymous record");
                        body_ok = false;
                        break;
                    }
                    current_offset = *next_off;
                } else {
                    max_union_size = std::max(max_union_size, base.size);
                }

                for (DataMember promoted : base.inline_anon_record.members) {
                    if (!promoted.name.empty() && !seen_member_names.insert(promoted.name).second) {
                        emit_error(member_start,
                                   std::format("Duplicate member name '{}' in '{}'",
                                               promoted.name,
                                               working_name));
                        body_ok = false;
                    }
                    promoted.offset += base_off;
                    rec.members.push_back(std::move(promoted));
                }
                continue;
            }

            // Anonymous enum inside struct (`enum { X = 1 };`) defines constants only
            if (check(TokenKind::Semicolon) && base.category == ResolvedCategory::Enum) {
                advance_tok();
                continue;
            }

            // One or more declarators (`uint32_t a, *b, c[16];`)
            bool first_decl = true;
            while (first_decl || match(TokenKind::Comma)) {
                first_decl = false;
                ParsedDeclarator decl{};
                decl.attrs = leading_attrs;
                if (!parse_declarator(decl, false, nesting_depth + 1u)) {
                    body_ok = false;
                    synchronize_member();
                    break;
                }
                if (!parse_attributes(decl.attrs)) {
                    body_ok = false;
                    break;
                }

                // If `struct { ... } header;` had an anonymous inline aggregate, materialize a named child record
                TypeInfo member_base = base;
                if (member_base.is_anonymous_inline_agg) {
                    DataTypeRecord nested_rec = member_base.inline_anon_record;
                    const std::string synth_name =
                        !decl.name.empty()
                            ? std::format("{}::{}", working_name, decl.name)
                            : std::format("{}::__anon_{}", working_name, ++anon_counter_);
                    nested_rec.name = synth_name;
                    member_base.type_name = synth_name;
                    member_base.is_anonymous_inline_agg = false;
                    const std::size_t nested_idx = res_.types.size();
                    res_.types.push_back(std::move(nested_rec));
                    RegisteredType nreg{.info = member_base, .record_index = nested_idx};
                    tag_map_[synth_name] = nreg;
                    typedef_map_[synth_name] = nreg;
                    // Reuse synthesized record if multi-declarator `struct { ... } a, b;`
                    base = member_base;
                }

                if (decl.has_bitfield) {
                    if (decl.outer_pointer_count > 0u || decl.inner_pointer_count > 0u ||
                        !decl.outer_suffixes.empty() || !decl.inner_suffixes.empty() ||
                        (member_base.category != ResolvedCategory::Integer &&
                         member_base.category != ResolvedCategory::Enum)) {
                        emit_error(decl.bitfield_line,
                                   decl.bitfield_col,
                                   "Bitfield must have scalar integer or enum type");
                        body_ok = false;
                        break;
                    }
                    const std::uint64_t unit_bytes =
                        member_base.size > 0u ? member_base.size : 4u;
                    const std::uint64_t unit_bits = unit_bytes * 8u;
                    if (decl.bitfield_width == 0u && !decl.name.empty()) {
                        emit_error(decl.bitfield_line,
                                   decl.bitfield_col,
                                   std::format("Named bitfield '{}' cannot have zero width", decl.name));
                        body_ok = false;
                        break;
                    }
                    if (decl.bitfield_width > unit_bits) {
                        emit_error(decl.bitfield_line,
                                   decl.bitfield_col,
                                   std::format("Bitfield width ({}) exceeds storage unit width ({} bits)",
                                               decl.bitfield_width,
                                               unit_bits));
                        body_ok = false;
                        break;
                    }

                    std::uint64_t bf_align = member_base.alignment;
                    if (decl.attrs.packed) {
                        bf_align = 1u;
                    } else if (member_pack > 0u) {
                        bf_align = std::min(bf_align, member_pack);
                    }
                    if (decl.attrs.explicit_align > 0u) {
                        bf_align = std::max(bf_align, decl.attrs.explicit_align);
                    }

                    if (decl.bitfield_width == 0u) {
                        bf_active = false;
                        if (!is_union) {
                            const auto aligned = checked_align_up(current_offset, bf_align);
                            if (!aligned.has_value()) {
                                emit_error(decl.bitfield_line, decl.bitfield_col, "Struct offset overflow");
                                body_ok = false;
                                break;
                            }
                            current_offset = *aligned;
                        }
                        continue;
                    }

                    if (is_union) {
                        record_max_align = std::max(record_max_align, bf_align);
                        max_union_size = std::max(max_union_size, unit_bytes);
                        if (!decl.name.empty()) {
                            if (!seen_member_names.insert(decl.name).second) {
                                emit_error(decl.name_line,
                                           decl.name_col,
                                           std::format("Duplicate member name '{}'", decl.name));
                                body_ok = false;
                                break;
                            }
                            rec.members.push_back(DataMember{
                                .name = decl.name,
                                .type = member_base.type_name,
                                .offset = 0,
                                .size = unit_bytes,
                                .bit_width = static_cast<std::uint8_t>(decl.bitfield_width),
                                .bit_offset = 0,
                            });
                        }
                    } else {
                        const bool can_share =
                            bf_active && bf_unit_size == unit_bytes &&
                            (bf_bits_used + static_cast<std::uint32_t>(decl.bitfield_width) <=
                             static_cast<std::uint32_t>(unit_bits));
                        if (!can_share) {
                            const auto aligned = checked_align_up(current_offset, bf_align);
                            const auto next_off =
                                aligned ? peelf::checked_add_u64(*aligned, unit_bytes) : std::nullopt;
                            if (!next_off.has_value()) {
                                emit_error(decl.bitfield_line, decl.bitfield_col, "Struct offset overflow");
                                body_ok = false;
                                break;
                            }
                            bf_active = true;
                            bf_unit_offset = *aligned;
                            bf_unit_size = unit_bytes;
                            bf_bits_used = 0;
                            current_offset = *next_off;
                            record_max_align = std::max(record_max_align, bf_align);
                        }
                        const std::uint8_t bit_off = static_cast<std::uint8_t>(bf_bits_used);
                        bf_bits_used += static_cast<std::uint32_t>(decl.bitfield_width);
                        if (!decl.name.empty()) {
                            if (!seen_member_names.insert(decl.name).second) {
                                emit_error(decl.name_line,
                                           decl.name_col,
                                           std::format("Duplicate member name '{}'", decl.name));
                                body_ok = false;
                                break;
                            }
                            rec.members.push_back(DataMember{
                                .name = decl.name,
                                .type = member_base.type_name,
                                .offset = bf_unit_offset,
                                .size = bf_unit_size,
                                .bit_width = static_cast<std::uint8_t>(decl.bitfield_width),
                                .bit_offset = bit_off,
                            });
                        }
                    }
                    continue;
                }

                bf_active = false;
                if (decl.name.empty()) {
                    emit_error(member_start, "Expected field name in struct/union member declaration");
                    body_ok = false;
                    break;
                }

                const Token err_loc{
                    .kind = TokenKind::Identifier,
                    .text = decl.name,
                    .line = decl.name_line,
                    .column = decl.name_col,
                };
                const auto resolved_opt = apply_declarator_to_type(member_base, decl, err_loc);
                if (!resolved_opt.has_value()) {
                    body_ok = false;
                    break;
                }
                const TypeInfo& field_ti = *resolved_opt;
                if (!field_ti.is_complete || field_ti.category == ResolvedCategory::Void) {
                    if (in_progress_tags_.contains(field_ti.type_name)) {
                        emit_error(err_loc,
                                   std::format("Cyclic by-value containment of incomplete type '{}'",
                                               field_ti.type_name));
                    } else {
                        emit_error(err_loc,
                                   std::format("Field '{}' has incomplete or void type '{}'",
                                               decl.name,
                                               field_ti.type_name));
                    }
                    body_ok = false;
                    break;
                }

                if (!seen_member_names.insert(decl.name).second) {
                    emit_error(err_loc,
                               std::format("Duplicate member name '{}' in '{}'",
                                           decl.name,
                                           working_name));
                    body_ok = false;
                    break;
                }

                std::uint64_t fld_align = std::max<std::uint64_t>(1u, field_ti.alignment);
                if (decl.attrs.packed) {
                    fld_align = 1u;
                } else if (member_pack > 0u) {
                    fld_align = std::min(fld_align, member_pack);
                }
                if (decl.attrs.explicit_align > 0u) {
                    fld_align = std::max(fld_align, decl.attrs.explicit_align);
                }
                record_max_align = std::max(record_max_align, fld_align);

                std::uint64_t fld_offset = 0;
                if (!is_union) {
                    const auto aligned = checked_align_up(current_offset, fld_align);
                    const auto next_off =
                        aligned ? peelf::checked_add_u64(*aligned, field_ti.size) : std::nullopt;
                    if (!next_off.has_value()) {
                        emit_error(err_loc, "Struct size overflows 64-bit address range");
                        body_ok = false;
                        break;
                    }
                    fld_offset = *aligned;
                    current_offset = *next_off;
                } else {
                    max_union_size = std::max(max_union_size, field_ti.size);
                }

                rec.members.push_back(DataMember{
                    .name = decl.name,
                    .type = field_ti.type_name,
                    .offset = fld_offset,
                    .size = field_ti.size,
                });
            }

            if (!body_ok) {
                synchronize_member();
                continue;
            }
            if (!match(TokenKind::Semicolon)) {
                emit_error(cur(), "Expected ';' after struct/union member declaration");
                body_ok = false;
                synchronize_member();
            }
        }

        if (!tag_name.empty()) {
            in_progress_tags_.erase(tag_name);
        }

        if (!match(TokenKind::RBrace)) {
            emit_error(lbrace_tok, "Unclosed '{' in struct/union definition");
            return std::nullopt;
        }
        if (!parse_attributes(record_attrs)) {
            return std::nullopt;
        }
        if (!body_ok) {
            return std::nullopt;
        }

        if (record_attrs.packed && record_attrs.explicit_align == 0u) {
            record_max_align = 1u;
        }
        if (record_attrs.explicit_align > 0u) {
            record_max_align = std::max(record_max_align, record_attrs.explicit_align);
        }

        const std::uint64_t raw_size = is_union ? max_union_size : current_offset;
        const auto final_size_opt =
            (raw_size == 0u) ? std::optional<std::uint64_t>{0u}
                             : checked_align_up(raw_size, record_max_align);
        if (!final_size_opt.has_value()) {
            emit_error(kw_tok, "Struct/union tail padding overflows 64-bit size");
            return std::nullopt;
        }
        rec.size = *final_size_opt;

        TypeInfo ti{
            .category = ResolvedCategory::StructOrUnion,
            .type_name = rec.name,
            .size = rec.size,
            .alignment = record_max_align,
            .is_signed = false,
            .is_complete = true,
        };

        if (!tag_name.empty()) {
            if (const auto pend_it = pending_tag_aliases_.find(tag_name);
                pend_it != pending_tag_aliases_.end()) {
                for (const std::string& al : pend_it->second) {
                    if (al != rec.name &&
                        std::ranges::find(rec.aliases, al) == rec.aliases.end()) {
                        rec.aliases.push_back(al);
                    }
                }
                pending_tag_aliases_.erase(pend_it);
            }
            const std::size_t rec_idx = res_.types.size();
            const std::vector<std::string> known_aliases = rec.aliases;
            res_.types.push_back(std::move(rec));
            RegisteredType reg{.info = ti, .record_index = rec_idx};
            tag_map_[tag_name] = reg;
            typedef_map_.emplace(tag_name, reg);
            for (const std::string& al : known_aliases) {
                typedef_map_[al] = reg;
            }
        } else {
            ti.is_anonymous_inline_agg = true;
            ti.inline_anon_record = std::move(rec);
        }
        return ti;
    }

    // ------------------------------------------------------------------------
    // Declarator Parsing (Pointers, Multi-Dim Arrays, Function Pointers, Bitfields)
    // ------------------------------------------------------------------------

    bool consume_pointer_prefix(std::size_t& ptr_count,
                                std::vector<std::uint8_t>* overrides = nullptr) {
        while (match(TokenKind::Star)) {
            ++ptr_count;
            std::uint8_t ptr_override = 0;
            while (cur().kind == TokenKind::Identifier) {
                const std::string_view q = cur().text;
                if (is_cv_qualifier(q) || is_calling_convention(q)) {
                    advance_tok();
                } else if (q == "__ptr32") {
                    ptr_override = 4;
                    advance_tok();
                } else if (q == "__ptr64") {
                    ptr_override = 8;
                    advance_tok();
                } else {
                    break;
                }
            }
            if (overrides != nullptr) {
                overrides->push_back(ptr_override);
            }
        }
        while (cur().kind == TokenKind::Identifier && is_calling_convention(cur().text)) {
            advance_tok();
        }
        return true;
    }

    bool parse_declarator_suffixes(std::vector<DeclaratorSuffix>& suffixes,
                                   std::size_t nesting_depth) {
        while (!is_eof()) {
            if (check(TokenKind::LBracket)) {
                const Token lb = advance_tok();
                if (check(TokenKind::RBracket)) {
                    emit_error(lb, "Flexible or unsized array '[]' is not allowed; specify a positive constant bound");
                    return false;
                }
                const Token bound_tok = cur();
                const auto cnt = parse_constant_expr(0);
                if (!cnt.has_value()) {
                    return false;
                }
                if (!match(TokenKind::RBracket)) {
                    emit_error(cur(), "Expected ']' after array bound expression");
                    return false;
                }
                if ((!cnt->is_unsigned && cnt->as_signed() <= 0) || cnt->bits == 0u) {
                    emit_error(bound_tok, "Array bound must be strictly positive (> 0)");
                    return false;
                }
                suffixes.push_back(DeclaratorSuffix{
                    .is_array = true,
                    .array_count = cnt->bits,
                });
                continue;
            }

            if (check(TokenKind::LParen)) {
                advance_tok(); // `(`
                std::string params_str;
                int paren_depth = 1;
                bool prev_ident = false;
                while (!is_eof() && paren_depth > 0) {
                    const Token pt = advance_tok();
                    if (pt.kind == TokenKind::LParen) {
                        ++paren_depth;
                        params_str.push_back('(');
                        prev_ident = false;
                    } else if (pt.kind == TokenKind::RParen) {
                        --paren_depth;
                        if (paren_depth > 0) {
                            params_str.push_back(')');
                        }
                        prev_ident = false;
                    } else if (pt.kind == TokenKind::Comma && paren_depth == 1) {
                        params_str += ", ";
                        prev_ident = false;
                    } else {
                        const bool cur_ident =
                            (pt.kind == TokenKind::Identifier || pt.kind == TokenKind::Number);
                        if (prev_ident && cur_ident) {
                            params_str.push_back(' ');
                        }
                        params_str += pt.text;
                        prev_ident = cur_ident;
                    }
                }
                if (paren_depth != 0) {
                    emit_error(cur(), "Unclosed '(' in function parameter list");
                    return false;
                }
                (void)nesting_depth;
                suffixes.push_back(DeclaratorSuffix{
                    .is_func_params = true,
                    .func_params_str = std::move(params_str),
                });
                continue;
            }

            break;
        }
        return true;
    }

    bool parse_declarator(ParsedDeclarator& out,
                          bool allow_abstract,
                          std::size_t nesting_depth) {
        if (!parse_attributes(out.attrs)) {
            return false;
        }
        consume_pointer_prefix(out.outer_pointer_count, &out.outer_ptr_size_overrides);
        if (!parse_attributes(out.attrs)) {
            return false;
        }

        // Parenthesized inner declarator, e.g. `(*callback)(int, void*)` or `(*arr[4])(int)`
        if (check(TokenKind::LParen) && !is_abstract_func_param_list()) {
            advance_tok(); // `(`
            while (cur().kind == TokenKind::Identifier && is_calling_convention(cur().text)) {
                advance_tok();
            }
            consume_pointer_prefix(out.inner_pointer_count);
            if (check(TokenKind::Identifier)) {
                const Token id = advance_tok();
                out.name = id.text;
                out.name_line = id.line;
                out.name_col = id.column;
            }
            if (!parse_declarator_suffixes(out.inner_suffixes, nesting_depth)) {
                return false;
            }
            if (!match(TokenKind::RParen)) {
                emit_error(cur(), "Expected ')' in parenthesized declarator");
                return false;
            }
        } else if (check(TokenKind::Identifier)) {
            const Token id = advance_tok();
            out.name = id.text;
            out.name_line = id.line;
            out.name_col = id.column;
        } else if (!allow_abstract && !check(TokenKind::Colon)) {
            emit_error(cur(), "Expected declarator identifier");
            return false;
        }

        if (!parse_declarator_suffixes(out.outer_suffixes, nesting_depth)) {
            return false;
        }

        if (!allow_abstract && check(TokenKind::Colon)) {
            const Token colon_tok = advance_tok();
            out.has_bitfield = true;
            out.bitfield_line = colon_tok.line;
            out.bitfield_col = colon_tok.column;
            const auto w = parse_constant_expr(0);
            if (!w.has_value()) {
                return false;
            }
            if (!w->is_unsigned && w->as_signed() < 0) {
                emit_error(colon_tok, "Bitfield width cannot be negative");
                return false;
            }
            out.bitfield_width = w->bits;
        }

        return true;
    }

    [[nodiscard]] bool is_abstract_func_param_list() {
        // Distinguish `void (*)(int)` (inner declarator starts with `*` or calling conv)
        // from `void (int)` (abstract parameter list starting with a type or `)`)
        const Token& next = peek_tok(1);
        if (next.kind == TokenKind::RParen || next.kind == TokenKind::Ellipsis) {
            return true;
        }
        if (next.kind == TokenKind::Star || next.kind == TokenKind::LParen) {
            return false;
        }
        if (next.kind == TokenKind::Identifier) {
            if (is_calling_convention(next.text)) {
                return false;
            }
            if (is_primitive_specifier_kw(next.text) || next.text == "struct" ||
                next.text == "union" || next.text == "enum" || is_cv_qualifier(next.text) ||
                typedef_map_.contains(next.text) || tag_map_.contains(next.text)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::optional<TypeInfo> apply_declarator_to_type(
        const TypeInfo& base_in,
        const ParsedDeclarator& decl,
        const Token& err_tok) {
        TypeInfo cur_ti = resolve_latest_tag_state(base_in);
        const std::uint64_t ps = pointer_size();

        // 1. Apply outer pointers `T*`, `T**`, ...
        for (std::size_t i = 0; i < decl.outer_pointer_count; ++i) {
            const std::uint64_t p_sz =
                (i < decl.outer_ptr_size_overrides.size() && decl.outer_ptr_size_overrides[i] != 0u)
                    ? static_cast<std::uint64_t>(decl.outer_ptr_size_overrides[i])
                    : ps;
            cur_ti = TypeInfo{
                .category = ResolvedCategory::Pointer,
                .type_name = cur_ti.type_name + "*",
                .size = p_sz,
                .alignment = p_sz,
                .is_signed = false,
                .is_complete = true,
            };
        }

        // 2. Check if this is a function pointer `ret (*name)(params)` or `ret (*arr[N])(params)`
        const bool has_outer_func =
            !decl.outer_suffixes.empty() && decl.outer_suffixes.front().is_func_params;
        if (has_outer_func) {
            if (decl.inner_pointer_count == 0u) {
                emit_error(err_tok,
                           std::format("Declaration '{}' has function type; use '(*{})({}...)' for a function pointer",
                                       decl.name,
                                       decl.name,
                                       decl.outer_suffixes.front().func_params_str));
                return std::nullopt;
            }
            std::string fn_ptr_type = std::format(
                "{} (*)({})", cur_ti.type_name, decl.outer_suffixes.front().func_params_str);
            for (std::size_t p = 1; p < decl.inner_pointer_count; ++p) {
                fn_ptr_type += "*";
            }
            cur_ti = TypeInfo{
                .category = ResolvedCategory::Pointer,
                .type_name = std::move(fn_ptr_type),
                .size = ps,
                .alignment = ps,
                .is_signed = false,
                .is_complete = true,
            };
            // Apply any inner array suffixes (e.g. `void (*handlers[4])(int)`)
            for (const DeclaratorSuffix& sfx : decl.inner_suffixes) {
                if (sfx.is_array) {
                    const auto arr_sz = peelf::checked_mul_u64(cur_ti.size, sfx.array_count);
                    if (!arr_sz.has_value()) {
                        emit_error(err_tok, "Array size overflows 64-bit integer range");
                        return std::nullopt;
                    }
                    cur_ti = TypeInfo{
                        .category = ResolvedCategory::Array,
                        .type_name = std::format("{}[{}]", cur_ti.type_name, sfx.array_count),
                        .size = *arr_sz,
                        .alignment = cur_ti.alignment,
                        .is_signed = false,
                        .is_complete = true,
                    };
                }
            }
            return cur_ti;
        }

        // Non-function parenthesized pointers `int (*p)` or `int (*p)[4]`
        for (std::size_t p = 0; p < decl.inner_pointer_count; ++p) {
            cur_ti = TypeInfo{
                .category = ResolvedCategory::Pointer,
                .type_name = cur_ti.type_name + "*",
                .size = ps,
                .alignment = ps,
                .is_signed = false,
                .is_complete = true,
            };
        }

        // Apply array suffixes (handle typedef-of-array cleanly so `Byte16 x[4]` -> `uint8_t[4][16]`)
        const auto apply_array_dim = [&](std::uint64_t count) -> bool {
            if (!cur_ti.is_complete || cur_ti.category == ResolvedCategory::Void) {
                emit_error(err_tok,
                           std::format("Array element type '{}' is incomplete or void",
                                       cur_ti.type_name));
                return false;
            }
            const auto arr_sz = peelf::checked_mul_u64(cur_ti.size, count);
            if (!arr_sz.has_value()) {
                emit_error(err_tok, "Array total byte size overflows 64-bit integer range");
                return false;
            }
            std::string new_name;
            const std::size_t bracket_pos = find_top_level_bracket(cur_ti.type_name);
            if (bracket_pos != std::string::npos) {
                new_name = std::format("{}[{}]{}",
                                       std::string_view(cur_ti.type_name).substr(0, bracket_pos),
                                       count,
                                       std::string_view(cur_ti.type_name).substr(bracket_pos));
            } else {
                new_name = std::format("{}[{}]", cur_ti.type_name, count);
            }
            cur_ti = TypeInfo{
                .category = ResolvedCategory::Array,
                .type_name = std::move(new_name),
                .size = *arr_sz,
                .alignment = cur_ti.alignment,
                .is_signed = false,
                .is_complete = true,
            };
            return true;
        };

        // In C `uint8_t a[4][16]` has outer_suffixes `[4]` then `[16]`.
        // Build dimensions from innermost (`[16]`) to outermost (`[4]`) so `new_name` is `uint8_t[4][16]`.
        std::vector<std::uint64_t> dims;
        for (const DeclaratorSuffix& sfx : decl.inner_suffixes) {
            if (sfx.is_func_params) {
                emit_error(err_tok, "Function declaration is not a valid data type");
                return std::nullopt;
            }
            if (sfx.is_array) {
                dims.push_back(sfx.array_count);
            }
        }
        for (const DeclaratorSuffix& sfx : decl.outer_suffixes) {
            if (sfx.is_func_params) {
                emit_error(err_tok, "Function declaration is not a valid data type");
                return std::nullopt;
            }
            if (sfx.is_array) {
                dims.push_back(sfx.array_count);
            }
        }
        for (std::size_t i = dims.size(); i > 0u; --i) {
            if (!apply_array_dim(dims[i - 1u])) {
                return std::nullopt;
            }
        }

        return cur_ti;
    }

    [[nodiscard]] static std::size_t find_top_level_bracket(std::string_view type_str) noexcept {
        int paren = 0;
        for (std::size_t i = 0; i < type_str.size(); ++i) {
            if (type_str[i] == '(') {
                ++paren;
            } else if (type_str[i] == ')' && paren > 0) {
                --paren;
            } else if (type_str[i] == '[' && paren == 0) {
                return i;
            }
        }
        return std::string::npos;
    }

    // ------------------------------------------------------------------------
    // Top-Level Declarations (`typedef`, `struct`, `union`, `enum`)
    // ------------------------------------------------------------------------

    bool parse_top_level_declaration() {
        AttrSpec decl_attrs{};
        if (!parse_attributes(decl_attrs)) {
            return false;
        }

        if (match_kw("typedef")) {
            return parse_typedef_declaration(decl_attrs);
        }

        // Ignore `extern` / `static` if someone pasted a variable prototype or function prototype,
        // or parse standalone `struct Foo { ... };` / `union Bar { ... };` / `enum Baz { ... };`
        const Token start = cur();
        auto base_opt = parse_base_type_specifier(0, "");
        if (!base_opt.has_value()) {
            return false;
        }

        if (match(TokenKind::Semicolon)) {
            return true;
        }

        // Top-level variable / prototype declaration after a struct/type: skip declarators cleanly to `;`
        bool first = true;
        while (first || match(TokenKind::Comma)) {
            first = false;
            ParsedDeclarator unused_decl{};
            if (!parse_declarator(unused_decl, true, 0)) {
                return false;
            }
            AttrSpec unused_attrs{};
            if (!parse_attributes(unused_attrs)) {
                return false;
            }
        }
        if (!match(TokenKind::Semicolon)) {
            emit_error(start, "Expected ';' after top-level declaration");
            return false;
        }
        return true;
    }

    bool parse_typedef_declaration(const AttrSpec& leading_attrs) {
        AttrSpec attrs = leading_attrs;
        if (!parse_attributes(attrs)) {
            return false;
        }
        const Token base_tok = cur();
        auto base_opt = parse_base_type_specifier(0, "");
        if (!base_opt.has_value()) {
            return false;
        }
        TypeInfo base = *base_opt;

        std::vector<ParsedDeclarator> decls;
        bool first = true;
        while (first || match(TokenKind::Comma)) {
            first = false;
            ParsedDeclarator d{};
            if (!parse_declarator(d, false, 0)) {
                return false;
            }
            if (!parse_attributes(d.attrs)) {
                return false;
            }
            if (d.name.empty()) {
                emit_error(base_tok, "Expected alias identifier in 'typedef' declaration");
                return false;
            }
            if (d.has_bitfield) {
                emit_error(d.bitfield_line, d.bitfield_col, "'typedef' cannot declare a bitfield");
                return false;
            }
            decls.push_back(std::move(d));
        }

        if (!match(TokenKind::Semicolon)) {
            emit_error(cur(), "Expected ';' after 'typedef' declaration");
            return false;
        }

        // Determine if there is a plain (non-pointer, non-array, non-func) alias for an inline aggregate/enum
        const auto is_plain_alias = [](const ParsedDeclarator& d) noexcept {
            return d.outer_pointer_count == 0u && d.inner_pointer_count == 0u &&
                   d.outer_suffixes.empty() && d.inner_suffixes.empty();
        };

        if (base.is_anonymous_inline_agg) {
            std::string chosen_name;
            for (const ParsedDeclarator& d : decls) {
                if (is_plain_alias(d)) {
                    chosen_name = d.name;
                    break;
                }
            }
            if (chosen_name.empty()) {
                chosen_name = decls.front().name + "_t";
            }

            DataTypeRecord rec = std::move(base.inline_anon_record);
            rec.name = chosen_name;
            for (const ParsedDeclarator& d : decls) {
                if (is_plain_alias(d) && d.name != chosen_name) {
                    rec.aliases.push_back(d.name);
                }
            }

            base.type_name = chosen_name;
            base.is_anonymous_inline_agg = false;
            const std::size_t rec_idx = res_.types.size();
            res_.types.push_back(std::move(rec));
            RegisteredType reg{.info = base, .record_index = rec_idx};
            tag_map_[chosen_name] = reg;
            typedef_map_[chosen_name] = reg;
        } else if (base.category == ResolvedCategory::StructOrUnion ||
                   base.category == ResolvedCategory::Enum) {
            // Tagged `typedef struct _NODE { ... } NODE, *PNODE;` or forward `typedef struct _NODE NODE;`
            if (const auto tag_it = tag_map_.find(base.type_name); tag_it != tag_map_.end()) {
                if (tag_it->second.record_index < res_.types.size()) {
                    DataTypeRecord& rec = res_.types[tag_it->second.record_index];
                    for (const ParsedDeclarator& d : decls) {
                        if (!is_plain_alias(d) || d.name == rec.name) {
                            continue;
                        }
                        if (rec.name.starts_with('_') && !d.name.starts_with('_')) {
                            const std::string old_tag = rec.name;
                            rec.name = d.name;
                            if (std::ranges::find(rec.aliases, old_tag) == rec.aliases.end()) {
                                rec.aliases.push_back(old_tag);
                            }
                            base.type_name = rec.name;
                            tag_it->second.info.type_name = rec.name;
                        } else if (std::ranges::find(rec.aliases, d.name) == rec.aliases.end()) {
                            rec.aliases.push_back(d.name);
                        }
                    }
                } else {
                    auto& pend = pending_tag_aliases_[base.type_name];
                    for (const ParsedDeclarator& d : decls) {
                        if (is_plain_alias(d) && d.name != base.type_name &&
                            std::ranges::find(pend, d.name) == pend.end()) {
                            pend.push_back(d.name);
                        }
                    }
                }
            }
        }

        for (const ParsedDeclarator& d : decls) {
            const Token err_tok{
                .kind = TokenKind::Identifier,
                .text = d.name,
                .line = d.name_line,
                .column = d.name_col,
            };
            auto resolved_opt = apply_declarator_to_type(base, d, err_tok);
            if (!resolved_opt.has_value()) {
                return false;
            }
            if (d.attrs.explicit_align > 0u) {
                resolved_opt->alignment = std::max(resolved_opt->alignment, d.attrs.explicit_align);
            }
            typedef_map_[d.name] = RegisteredType{.info = *resolved_opt};
            res_.typedefs.push_back(CTypeAliasInfo{
                .alias = d.name,
                .target_type = resolved_opt->type_name,
                .size = resolved_opt->size,
                .alignment = resolved_opt->alignment,
            });
        }
        return true;
    }
};

} // namespace

CTypeParseResult parse_c_types(std::string_view source, const CTypeParseOptions& options) {
    CTypeParseResult result;
    if (source.size() > kMaxCTypeSourceBytes) {
        result.diagnostics.push_back(CTypeParseDiagnostic{
            .line = 1,
            .column = 1,
            .severity = CTypeDiagnosticSeverity::Error,
            .message = std::format("C type source exceeds maximum size ({} bytes)",
                                   kMaxCTypeSourceBytes),
        });
        return result;
    }

    Lexer lexer(source, result.diagnostics);
    std::vector<Token> tokens = lexer.tokenize();
    if (result.has_errors()) {
        return result;
    }

    CTypeParser parser(std::move(tokens), options, result);
    parser.parse_translation_unit();
    return result;
}

CTypeParseResult parse_c_types(std::string_view source, const peelf::TargetLayout& layout) {
    return parse_c_types(source, CTypeParseOptions{.layout = layout});
}

} // namespace viewer
