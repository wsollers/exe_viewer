#include "ui/command_palette.hpp"

#include <peelf/debugger.hpp>
#include <peelf/demangle.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {

[[nodiscard]] constexpr unsigned char to_uchar(char c) noexcept {
    return static_cast<unsigned char>(c);
}

[[nodiscard]] constexpr bool is_ascii_space(char c) noexcept {
    const unsigned char u = to_uchar(c);
    return u == ' ' || u == '\t' || u == '\r' || u == '\n';
}

[[nodiscard]] constexpr bool is_ascii_upper(char c) noexcept {
    const unsigned char u = to_uchar(c);
    return u >= 'A' && u <= 'Z';
}

[[nodiscard]] constexpr bool is_ascii_lower(char c) noexcept {
    const unsigned char u = to_uchar(c);
    return u >= 'a' && u <= 'z';
}

[[nodiscard]] constexpr bool is_ascii_alpha(char c) noexcept {
    return is_ascii_upper(c) || is_ascii_lower(c);
}

[[nodiscard]] constexpr bool is_ascii_digit(char c) noexcept {
    const unsigned char u = to_uchar(c);
    return u >= '0' && u <= '9';
}

[[nodiscard]] constexpr bool is_ascii_hex(char c) noexcept {
    const unsigned char u = to_uchar(c);
    return is_ascii_digit(c) || (u >= 'a' && u <= 'f') || (u >= 'A' && u <= 'F');
}

[[nodiscard]] constexpr bool is_ascii_alnum(char c) noexcept {
    return is_ascii_alpha(c) || is_ascii_digit(c);
}

[[nodiscard]] constexpr char ascii_lower(char c) noexcept {
    const unsigned char u = to_uchar(c);
    if (u >= 'A' && u <= 'Z') {
        return static_cast<char>(u - 'A' + 'a');
    }
    return c;
}

[[nodiscard]] constexpr std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && is_ascii_space(sv.front())) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && is_ascii_space(sv.back())) {
        sv.remove_suffix(1);
    }
    return sv;
}

[[nodiscard]] constexpr std::string_view trim_leading_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && is_ascii_space(sv.front())) {
        sv.remove_prefix(1);
    }
    return sv;
}

[[nodiscard]] constexpr bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr bool istarts_with_ascii(
    std::string_view text,
    std::string_view prefix) noexcept {
    return text.size() >= prefix.size() && iequals_ascii(text.substr(0, prefix.size()), prefix);
}

[[nodiscard]] constexpr bool is_separator_char(char c) noexcept {
    switch (c) {
        case ' ':
        case '\t':
        case '_':
        case '-':
        case '.':
        case '/':
        case '\\':
        case ':':
        case '!':
        case ',':
        case '(':
        case ')':
        case '<':
        case '>':
        case '[':
        case ']':
        case '&':
        case '*':
            return true;
        default:
            return false;
    }
}

[[nodiscard]] constexpr bool is_word_boundary(std::string_view s, std::size_t idx) noexcept {
    if (idx >= s.size()) {
        return false;
    }
    if (idx == 0u) {
        return true;
    }
    const char prev = s[idx - 1u];
    const char curr = s[idx];
    if (is_separator_char(prev) && !is_separator_char(curr)) {
        return true;
    }
    if (is_ascii_lower(prev) && is_ascii_upper(curr)) {
        return true;
    }
    if (is_ascii_upper(prev) && is_ascii_upper(curr) &&
        (idx + 1u < s.size()) && is_ascii_lower(s[idx + 1u])) {
        return true;
    }
    if (is_ascii_alnum(prev) && is_ascii_alnum(curr) &&
        (is_ascii_alpha(prev) != is_ascii_alpha(curr))) {
        return true;
    }
    return false;
}

void populate_fuzzy_spans(
    std::span<const std::uint16_t> positions,
    int score,
    FuzzyMatchResult* out_match) noexcept {
    if (out_match == nullptr) {
        return;
    }
    *out_match = FuzzyMatchResult{};
    out_match->score = score;
    const std::size_t count = std::min(positions.size(), kMaxFuzzyMatchedIndices);
    out_match->matched_count = static_cast<std::uint8_t>(count);
    for (std::size_t i = 0; i < count; ++i) {
        out_match->matched_indices[i] = positions[i];
    }

    std::uint8_t span_idx = 0u;
    std::size_t i = 0u;
    while (i < count && span_idx < kMaxFuzzyMatchSpans) {
        const std::uint16_t start = positions[i];
        std::uint16_t len = 1u;
        while ((i + 1u) < count &&
               positions[i + 1u] == static_cast<std::uint16_t>(positions[i] + 1u)) {
            ++len;
            ++i;
        }
        out_match->spans[span_idx] = FuzzyMatchSpan{.offset = start, .length = len};
        ++span_idx;
        ++i;
    }
    out_match->span_count = span_idx;
}

// Attempts to match `query` where every word is entered at a true word boundary and
// characters within each word are contiguous (allowing at most 1 intra-word stem skip
// across a multi-word acronym, e.g. `"memhm"` -> `"Memory Heatmap"`).
[[nodiscard]] bool match_word_boundary_acronym(
    std::string_view query,
    std::string_view candidate,
    std::array<std::uint16_t, kMaxFuzzyMatchedIndices>& out_pos,
    int& out_jumps,
    int& out_intra_skips) noexcept {
    const std::size_t m = query.size();
    const std::size_t n = std::min<std::size_t>(candidate.size(), 256u);
    if (m == 0u || m > kMaxFuzzyMatchedIndices || m > n) {
        return false;
    }

    struct Frame {
        std::uint16_t q_idx = 0u;
        std::uint16_t c_idx = 0u;
        int jumps = 0;
        int intra_skips = 0;
    };
    std::array<Frame, 192> stack{};
    std::size_t sp = 0u;

    // Seed in reverse order so earlier boundaries are explored first.
    for (std::size_t j = n; j > 0u; --j) {
        const std::size_t idx = j - 1u;
        if (idx + m <= n &&
            is_word_boundary(candidate, idx) &&
            ascii_lower(candidate[idx]) == ascii_lower(query[0])) {
            if (sp < stack.size()) {
                stack[sp++] = Frame{
                    .q_idx = 0u,
                    .c_idx = static_cast<std::uint16_t>(idx),
                    .jumps = 0,
                    .intra_skips = 0,
                };
            }
        }
    }

    std::size_t steps = 0u;
    constexpr std::size_t kMaxSteps = 640u;
    while (sp > 0u && steps < kMaxSteps) {
        ++steps;
        const Frame cur = stack[--sp];
        out_pos[cur.q_idx] = cur.c_idx;
        if (static_cast<std::size_t>(cur.q_idx) + 1u == m) {
            if (cur.jumps >= 1) {
                out_jumps = cur.jumps;
                out_intra_skips = cur.intra_skips;
                return true;
            }
            continue;
        }

        const std::uint16_t next_q = static_cast<std::uint16_t>(cur.q_idx + 1u);
        const char want = ascii_lower(query[next_q]);
        const std::size_t rem = m - static_cast<std::size_t>(next_q);

        // Lowest priority (pushed first onto LIFO stack): at most 1 intra-word stem skip
        // within the current boundary-anchored word for multi-word queries (`m >= 4`,
        // e.g. `"memhm"` -> `"Memory Heatmap"`).
        if (m >= 4u && cur.jumps >= 1 && cur.intra_skips == 0) {
            std::size_t word_end = static_cast<std::size_t>(cur.c_idx) + 1u;
            while (word_end < n && !is_separator_char(candidate[word_end]) &&
                   !is_word_boundary(candidate, word_end)) {
                ++word_end;
            }
            for (std::size_t j = word_end; j > static_cast<std::size_t>(cur.c_idx) + 2u; --j) {
                const std::size_t idx = j - 1u;
                if (idx + rem <= n && ascii_lower(candidate[idx]) == want && sp < stack.size()) {
                    stack[sp++] = Frame{
                        .q_idx = next_q,
                        .c_idx = static_cast<std::uint16_t>(idx),
                        .jumps = cur.jumps,
                        .intra_skips = cur.intra_skips + 1,
                    };
                }
            }
        }

        // Medium priority: jump to a subsequent word boundary.
        for (std::size_t j = n; j > static_cast<std::size_t>(cur.c_idx) + 1u; --j) {
            const std::size_t idx = j - 1u;
            if (idx + rem <= n &&
                is_word_boundary(candidate, idx) &&
                ascii_lower(candidate[idx]) == want) {
                if (sp < stack.size()) {
                    stack[sp++] = Frame{
                        .q_idx = next_q,
                        .c_idx = static_cast<std::uint16_t>(idx),
                        .jumps = cur.jumps + 1,
                        .intra_skips = cur.intra_skips,
                    };
                }
            }
        }

        // Highest priority (popped first): contiguous character in current word.
        const std::size_t adj = static_cast<std::size_t>(cur.c_idx) + 1u;
        if (adj + rem <= n && !is_separator_char(candidate[adj]) &&
            ascii_lower(candidate[adj]) == want) {
            if (sp < stack.size()) {
                stack[sp++] = Frame{
                    .q_idx = next_q,
                    .c_idx = static_cast<std::uint16_t>(adj),
                    .jumps = cur.jumps,
                    .intra_skips = cur.intra_skips,
                };
            }
        }
    }
    return false;
}

[[nodiscard]] std::optional<std::size_t> find_best_substring(
    std::string_view query,
    std::string_view candidate,
    bool& out_at_boundary) noexcept {
    out_at_boundary = false;
    if (query.empty() || query.size() > candidate.size()) {
        return std::nullopt;
    }
    const std::size_t limit = candidate.size() - query.size();
    std::optional<std::size_t> first_any{};
    for (std::size_t pos = 0u; pos <= limit; ++pos) {
        if (iequals_ascii(candidate.substr(pos, query.size()), query)) {
            if (is_word_boundary(candidate, pos)) {
                out_at_boundary = true;
                return pos;
            }
            if (!first_any.has_value()) {
                first_any = pos;
            }
        }
    }
    return first_any;
}

} // namespace

std::optional<int> fuzzy_match_score(
    std::string_view query,
    std::string_view candidate,
    FuzzyMatchResult* out_match) noexcept {
    if (query.empty()) {
        if (out_match != nullptr) {
            *out_match = FuzzyMatchResult{.score = 0};
        }
        return 0;
    }
    if (query.size() > candidate.size()) {
        return std::nullopt;
    }

    // Fast inline O(N) subsequence pre-filter (avoids helper call overhead in debug builds).
    {
        std::size_t qi = 0u;
        unsigned char want = static_cast<unsigned char>(query[0]);
        if (want >= 'A' && want <= 'Z') {
            want = static_cast<unsigned char>(want + ('a' - 'A'));
        }
        for (const char raw_ch : candidate) {
            unsigned char ch = static_cast<unsigned char>(raw_ch);
            if (ch >= 'A' && ch <= 'Z') {
                ch = static_cast<unsigned char>(ch + ('a' - 'A'));
            }
            if (ch == want) {
                ++qi;
                if (qi == query.size()) {
                    break;
                }
                want = static_cast<unsigned char>(query[qi]);
                if (want >= 'A' && want <= 'Z') {
                    want = static_cast<unsigned char>(want + ('a' - 'A'));
                }
            }
        }
        if (qi < query.size()) {
            return std::nullopt;
        }
    }

    std::array<std::uint16_t, kMaxFuzzyMatchedIndices> positions{};
    const std::size_t recorded_m = std::min(query.size(), kMaxFuzzyMatchedIndices);

    // Tier 1: Exact match (10000)
    if (query.size() == candidate.size() && iequals_ascii(query, candidate)) {
        for (std::size_t i = 0; i < recorded_m; ++i) {
            positions[i] = static_cast<std::uint16_t>(i);
        }
        constexpr int score = 10000;
        populate_fuzzy_spans(std::span(positions.data(), recorded_m), score, out_match);
        return score;
    }

    // Tier 2: Prefix match (~7550..8060)
    if (istarts_with_ascii(candidate, query)) {
        for (std::size_t i = 0; i < recorded_m; ++i) {
            positions[i] = static_cast<std::uint16_t>(i);
        }
        const int tail_penalty =
            std::min(450, static_cast<int>(candidate.size() - query.size()) * 3);
        const int boundary_end_bonus =
            (is_separator_char(candidate[query.size()]) ||
             is_word_boundary(candidate, query.size()))
                ? 60
                : 0;
        const int score = 8000 - tail_penalty + boundary_end_bonus;
        populate_fuzzy_spans(std::span(positions.data(), recorded_m), score, out_match);
        return score;
    }

    // Tier 3: Word-boundary acronym / multi-word prefix (~5300..6250)
    int acronym_jumps = 0;
    int intra_skips = 0;
    if (query.size() <= kMaxFuzzyMatchedIndices &&
        match_word_boundary_acronym(query, candidate, positions, acronym_jumps, intra_skips)) {
        const int start_bonus = (positions[0] == 0u) ? 250 : 0;
        const int span_width =
            static_cast<int>(positions[recorded_m - 1u] - positions[0]) + 1;
        const int density_penalty =
            std::min(300, std::max(0, span_width - static_cast<int>(recorded_m)) * 4);
        const int tail_penalty =
            std::min(200, static_cast<int>(candidate.size() - query.size()) * 2);
        const int skip_penalty = intra_skips * 140;
        const int score = 6000 + start_bonus - density_penalty - tail_penalty - skip_penalty;
        populate_fuzzy_spans(std::span(positions.data(), recorded_m), score, out_match);
        return score;
    }

    // Tier 4: Contiguous substring (~3500..4600)
    bool substr_at_boundary = false;
    if (const auto sub_pos = find_best_substring(query, candidate, substr_at_boundary);
        sub_pos.has_value()) {
        for (std::size_t i = 0; i < recorded_m; ++i) {
            const std::size_t idx = *sub_pos + i;
            positions[i] = static_cast<std::uint16_t>(
                std::min<std::size_t>(idx, std::numeric_limits<std::uint16_t>::max()));
        }
        const int base = substr_at_boundary ? 4600 : 4000;
        const int offset_penalty = std::min(300, static_cast<int>(*sub_pos) * 4);
        const int tail_penalty =
            std::min(200, static_cast<int>(candidate.size() - query.size()) * 2);
        const int score = base - offset_penalty - tail_penalty;
        populate_fuzzy_spans(std::span(positions.data(), recorded_m), score, out_match);
        return score;
    }

    // Tier 5: General subsequence alignment (~100..3500)
    constexpr std::size_t kMaxDpM = 48u;
    constexpr std::size_t kMaxDpN = 192u;
    if (query.size() <= kMaxDpM && candidate.size() <= kMaxDpN) {
        const std::size_t m = query.size();
        const std::size_t n = candidate.size();
        constexpr int kNegInf = -1000000;

        std::array<int, kMaxDpN> prev_dp{};
        std::array<int, kMaxDpN> curr_dp{};
        prev_dp.fill(kNegInf);
        curr_dp.fill(kNegInf);

        // Backpointer table storing previous matched column for each (i, j).
        std::array<std::array<std::uint8_t, kMaxDpN>, kMaxDpM> parent{};

        for (std::size_t j = 0u; j < n; ++j) {
            if (ascii_lower(candidate[j]) == ascii_lower(query[0])) {
                int s = 40 - static_cast<int>(j) * 3;
                if (j == 0u) {
                    s += 55;
                } else if (is_word_boundary(candidate, j)) {
                    s += 38;
                }
                prev_dp[j] = s;
            }
        }

        for (std::size_t i = 1u; i < m; ++i) {
            curr_dp.fill(kNegInf);
            const char q_low = ascii_lower(query[i]);

            int best_gap_val = kNegInf;
            std::size_t best_gap_col = 0u;

            for (std::size_t j = i; j < n; ++j) {
                const std::size_t prev_col = j - 1u;
                if (prev_dp[prev_col] > kNegInf) {
                    const int candidate_gap = prev_dp[prev_col] + static_cast<int>(prev_col) * 2;
                    if (candidate_gap > best_gap_val) {
                        best_gap_val = candidate_gap;
                        best_gap_col = prev_col;
                    }
                }

                if (ascii_lower(candidate[j]) != q_low || best_gap_val == kNegInf) {
                    continue;
                }

                int best_here = best_gap_val - static_cast<int>(j - 1u) * 2 + 40;
                std::size_t chosen_prev = best_gap_col;

                // Consecutive bonus if `j - 1` matched `i - 1`.
                if (prev_dp[prev_col] > kNegInf) {
                    const int consec = prev_dp[prev_col] + 40 + 32;
                    if (consec >= best_here) {
                        best_here = consec;
                        chosen_prev = prev_col;
                    }
                }

                if (is_word_boundary(candidate, j)) {
                    best_here += 36;
                }

                curr_dp[j] = best_here;
                parent[i][j] = static_cast<std::uint8_t>(chosen_prev);
            }
            prev_dp = curr_dp;
        }

        int best_final = kNegInf;
        std::size_t best_end = 0u;
        for (std::size_t j = m - 1u; j < n; ++j) {
            if (prev_dp[j] > best_final) {
                best_final = prev_dp[j];
                best_end = j;
            }
        }

        if (best_final > kNegInf) {
            std::size_t col = best_end;
            for (std::size_t rev = 0u; rev < m; ++rev) {
                const std::size_t idx = m - 1u - rev;
                positions[idx] = static_cast<std::uint16_t>(col);
                if (idx > 0u) {
                    col = parent[idx][col];
                }
            }
            const int tail_penalty =
                std::min(150, static_cast<int>(n - m));
            const int score = std::clamp(1500 + best_final - tail_penalty, 100, 3500);
            populate_fuzzy_spans(std::span(positions.data(), m), score, out_match);
            return score;
        }
    }

    // Fallback linear subsequence scorer for very long inputs.
    std::size_t qi = 0u;
    int raw = 1400;
    std::size_t prev_match = 0u;
    for (std::size_t j = 0u; j < candidate.size() && qi < query.size(); ++j) {
        if (ascii_lower(candidate[j]) == ascii_lower(query[qi])) {
            if (qi < kMaxFuzzyMatchedIndices) {
                positions[qi] = static_cast<std::uint16_t>(
                    std::min<std::size_t>(j, std::numeric_limits<std::uint16_t>::max()));
            }
            if (is_word_boundary(candidate, j)) {
                raw += 25;
            }
            if (qi > 0u && j == prev_match + 1u) {
                raw += 20;
            } else if (qi > 0u) {
                raw -= std::min(40, static_cast<int>(j - prev_match - 1u));
            }
            prev_match = j;
            ++qi;
        }
    }
    const int score = std::clamp(raw, 50, 3000);
    populate_fuzzy_spans(std::span(positions.data(), recorded_m), score, out_match);
    return score;
}

// ---------------------------------------------------------------------------
// Rich Address & Symbol Expression Evaluator
// ---------------------------------------------------------------------------

AddressExpressionContext make_address_expression_context(
    const BinaryModel& model,
    const SymbolIndex* ui_symbols,
    const AnnotationStore* annotations) noexcept {
    AddressExpressionContext ctx{};
    ctx.image = model.image();
    if (ctx.image != nullptr) {
        ctx.image_base = ctx.image->image_base();
        ctx.entry_point = ctx.image->entry_point();
        ctx.sections = ctx.image->sections();
    }
    if (!model.is_live_process() && !model.bytes().empty()) {
        ctx.file_size = static_cast<std::uint64_t>(model.bytes().size());
    }
    ctx.modules = model.process_modules();
    if (!ctx.image_base.has_value() && !ctx.modules.empty()) {
        ctx.image_base = ctx.modules.front().base_address;
        if (ctx.modules.front().entry_point != 0u) {
            ctx.entry_point = ctx.modules.front().entry_point;
        }
    }

    if (const auto& tctx = model.selected_thread_context(); tctx.has_value()) {
        ctx.instruction_pointer = tctx.value->instruction_pointer;
        ctx.stack_pointer = tctx.value->stack_pointer;
        if (tctx.value->frame_pointer != 0u) {
            ctx.frame_pointer = tctx.value->frame_pointer;
        }
        ctx.registers = tctx.value->registers;
    }
    if (const auto* dbg = model.debug_session();
        dbg != nullptr && dbg->state() == peelf::debugger::DebugSessionState::Paused) {
        const std::uint64_t stop_ip = dbg->stop_status().instruction_pointer;
        if (stop_ip != 0u || !ctx.instruction_pointer.has_value()) {
            ctx.instruction_pointer = stop_ip;
        }
    }

    ctx.functions = &model.function_index();
    ctx.symbols = (ui_symbols != nullptr) ? ui_symbols : &model.symbol_index();
    ctx.annotations = annotations;
    ctx.bookmarks = model.bookmarks();
    return ctx;
}

namespace {

enum class EvalValueKind : std::uint8_t {
    Scalar = 0,
    VirtualAddress,
    FileOffset,
};

struct EvalValue {
    std::uint64_t value = 0u;
    EvalValueKind kind = EvalValueKind::Scalar;
    std::string origin_label{};
};

[[nodiscard]] std::optional<std::uint64_t> effective_image_base(
    const AddressExpressionContext& ctx) noexcept {
    if (ctx.image_base.has_value()) {
        return ctx.image_base;
    }
    if (ctx.image != nullptr) {
        return ctx.image->image_base();
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> effective_entry_point(
    const AddressExpressionContext& ctx) noexcept {
    if (ctx.entry_point.has_value()) {
        return ctx.entry_point;
    }
    if (ctx.image != nullptr) {
        return ctx.image->entry_point();
    }
    return std::nullopt;
}

[[nodiscard]] std::span<const peelf::Section> effective_sections(
    const AddressExpressionContext& ctx) noexcept {
    if (!ctx.sections.empty()) {
        return ctx.sections;
    }
    if (ctx.image != nullptr) {
        return ctx.image->sections();
    }
    return {};
}

// Strips trailing `(...)` parameter list and leading return-type tokens from a demangled
// C++/Rust function signature, e.g. `void ns::Widget::run(int) const` -> `ns::Widget::run`.
[[nodiscard]] std::string_view strip_demangled_signature(std::string_view sig) noexcept {
    sig = trim_ascii(sig);
    if (sig.empty()) {
        return sig;
    }

    // Strip trailing qualifiers after closing `)` if signature ends with `(...) [const/noexcept]`.
    int angle_depth = 0;
    int paren_depth = 0;
    std::size_t param_open = std::string_view::npos;
    for (std::size_t i = 0u; i < sig.size(); ++i) {
        const char ch = sig[i];
        if (ch == '<' && paren_depth == 0) {
            ++angle_depth;
        } else if (ch == '>' && paren_depth == 0 && angle_depth > 0) {
            --angle_depth;
        } else if (ch == '(' && angle_depth == 0) {
            if (paren_depth == 0) {
                param_open = i;
            }
            ++paren_depth;
        } else if (ch == ')' && angle_depth == 0 && paren_depth > 0) {
            --paren_depth;
        }
    }
    if (param_open != std::string_view::npos && param_open > 0u) {
        sig = trim_ascii(sig.substr(0, param_open));
    }

    // Strip leading return type when outside `<...>`, e.g. `void ns::Widget::run` -> `ns::Widget::run`.
    angle_depth = 0;
    std::size_t last_space_outside = std::string_view::npos;
    for (std::size_t i = 0u; i < sig.size(); ++i) {
        const char ch = sig[i];
        if (ch == '<') {
            ++angle_depth;
        } else if (ch == '>' && angle_depth > 0) {
            --angle_depth;
        } else if (angle_depth == 0 && is_ascii_space(ch)) {
            last_space_outside = i;
        }
    }
    if (last_space_outside != std::string_view::npos && last_space_outside + 1u < sig.size()) {
        const std::string_view tail = trim_ascii(sig.substr(last_space_outside + 1u));
        if (!tail.empty()) {
            sig = tail;
        }
    }
    return sig;
}

[[nodiscard]] std::string_view strip_module_bang(std::string_view name) noexcept {
    const std::size_t bang = name.find('!');
    if (bang != std::string_view::npos && bang + 1u < name.size()) {
        return name.substr(bang + 1u);
    }
    return name;
}

[[nodiscard]] std::string_view strip_elf_version_or_plt(std::string_view name) noexcept {
    const std::size_t at = name.find('@');
    if (at != std::string_view::npos && at > 0u) {
        return name.substr(0, at);
    }
    return name;
}

[[nodiscard]] bool symbol_matches_token(
    std::string_view token,
    std::string_view primary_name,
    std::string_view raw_name,
    std::string_view demangled_name,
    bool case_insensitive) noexcept {
    const auto eq = [case_insensitive](std::string_view a, std::string_view b) noexcept {
        if (a.empty() || b.empty()) {
            return false;
        }
        return case_insensitive ? iequals_ascii(a, b) : (a == b);
    };

    for (const std::string_view candidate : {primary_name, raw_name, demangled_name}) {
        if (candidate.empty()) {
            continue;
        }
        if (eq(token, candidate)) {
            return true;
        }
        const std::string_view no_bang = strip_module_bang(candidate);
        if (eq(token, no_bang)) {
            return true;
        }
        const std::string_view no_ver = strip_elf_version_or_plt(no_bang);
        if (eq(token, no_ver)) {
            return true;
        }
        const std::string_view stripped_sig = strip_demangled_signature(no_ver);
        if (eq(token, stripped_sig)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] peelf::Result<std::uint64_t> parse_checked_uint64(
    std::string_view digits,
    int base,
    std::string_view original_token) {
    if (digits.empty()) {
        return peelf::make_error(
            std::format("Invalid numeric literal '{}'", original_token));
    }
    // Strip optional '_' digit separators if present.
    std::array<char, 64> clean{};
    std::size_t len = 0u;
    for (const char ch : digits) {
        if (ch == '_') {
            continue;
        }
        if (len >= clean.size()) {
            return peelf::make_error(
                std::format("Numeric literal '{}' overflows 64-bit unsigned range", original_token));
        }
        clean[len++] = ch;
    }
    if (len == 0u) {
        return peelf::make_error(
            std::format("Invalid numeric literal '{}'", original_token));
    }

    std::uint64_t value = 0u;
    const auto [ptr, ec] = std::from_chars(clean.data(), clean.data() + len, value, base);
    if (ec == std::errc::result_out_of_range) {
        return peelf::make_error(
            std::format("Numeric literal '{}' overflows 64-bit unsigned range", original_token));
    }
    if (ec != std::errc{} || ptr != clean.data() + len) {
        return peelf::make_error(
            std::format("Invalid numeric literal '{}'", original_token));
    }
    return value;
}

[[nodiscard]] std::optional<peelf::Result<EvalValue>> try_parse_numeric_literal(
    std::string_view token) {
    if (token.empty()) {
        return std::nullopt;
    }

    // 0x... / 0X...
    if (token.size() >= 2u && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
        auto parsed = parse_checked_uint64(token.substr(2), 16, token);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        return EvalValue{.value = *parsed, .kind = EvalValueKind::Scalar};
    }

    // 140001000h / 0FFh (starts with decimal digit, ends with h/H)
    if (token.size() >= 2u && is_ascii_digit(token.front()) &&
        (token.back() == 'h' || token.back() == 'H')) {
        const std::string_view body = token.substr(0, token.size() - 1u);
        bool all_hex = true;
        for (const char ch : body) {
            if (!is_ascii_hex(ch) && ch != '_') {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            auto parsed = parse_checked_uint64(body, 16, token);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            return EvalValue{.value = *parsed, .kind = EvalValueKind::Scalar};
        }
    }

    // Decimal literal: starts with 0..9 and contains only decimal digits / '_'
    if (is_ascii_digit(token.front())) {
        bool all_dec = true;
        for (const char ch : token) {
            if (!is_ascii_digit(ch) && ch != '_') {
                all_dec = false;
                break;
            }
        }
        if (all_dec) {
            auto parsed = parse_checked_uint64(token, 10, token);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            return EvalValue{.value = *parsed, .kind = EvalValueKind::Scalar};
        }
    }

    return std::nullopt;
}

[[nodiscard]] peelf::Result<EvalValue> resolve_named_or_literal_atom(
    std::string_view raw_atom,
    bool quoted,
    const AddressExpressionContext& ctx) {
    const std::string_view token = quoted ? raw_atom : trim_ascii(raw_atom);
    if (token.empty()) {
        return peelf::make_error("Empty operand in address expression");
    }

    if (!quoted) {
        // 1. Built-in `$` / named register & image tokens
        if (iequals_ascii(token, "$entry") || iequals_ascii(token, "entry")) {
            const auto ep = effective_entry_point(ctx);
            if (!ep.has_value()) {
                return peelf::make_error("Entry point is unavailable in the current target");
            }
            return EvalValue{
                .value = *ep,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = "entry",
            };
        }
        if (iequals_ascii(token, "$base") || iequals_ascii(token, "image_base") ||
            iequals_ascii(token, "$image_base")) {
            const auto base = effective_image_base(ctx);
            if (!base.has_value()) {
                return peelf::make_error("Image base is unavailable in the current target");
            }
            return EvalValue{
                .value = *base,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = "image_base",
            };
        }
        if (iequals_ascii(token, "$pc") || iequals_ascii(token, "$ip")) {
            if (!ctx.instruction_pointer.has_value()) {
                return peelf::make_error(
                    std::format("Register '{}' requires an active thread or debugger context", token));
            }
            return EvalValue{
                .value = *ctx.instruction_pointer,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = std::string(token),
            };
        }
        if (iequals_ascii(token, "$sp")) {
            if (!ctx.stack_pointer.has_value()) {
                return peelf::make_error(
                    "Register '$sp' requires an active thread or debugger context");
            }
            return EvalValue{
                .value = *ctx.stack_pointer,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = "$sp",
            };
        }
        if (iequals_ascii(token, "$fp") || iequals_ascii(token, "$bp")) {
            if (!ctx.frame_pointer.has_value()) {
                return peelf::make_error(
                    std::format("Register '{}' requires an active thread or debugger context", token));
            }
            return EvalValue{
                .value = *ctx.frame_pointer,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = std::string(token),
            };
        }

        // Named general-purpose registers from ThreadContext when prefixed with '$'
        if (token.front() == '$' && token.size() > 1u) {
            const std::string_view reg_name = token.substr(1);
            for (const auto& reg : ctx.registers) {
                if (iequals_ascii(reg.name, reg_name)) {
                    return EvalValue{
                        .value = reg.value_u64,
                        .kind = EvalValueKind::VirtualAddress,
                        .origin_label = std::format("${}", reg.name),
                    };
                }
            }

            // Hex literal `$401000`
            bool all_hex = true;
            for (const char ch : reg_name) {
                if (!is_ascii_hex(ch) && ch != '_') {
                    all_hex = false;
                    break;
                }
            }
            if (all_hex) {
                auto parsed = parse_checked_uint64(reg_name, 16, token);
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                return EvalValue{.value = *parsed, .kind = EvalValueKind::Scalar};
            }
            return peelf::make_error(
                std::format("Unknown register or invalid '$' hex token '{}'", token));
        }

        // 2. Numeric literals (`0x...`, `...h`, decimal `4096`)
        if (auto lit = try_parse_numeric_literal(token); lit.has_value()) {
            return std::move(*lit);
        }
    }

    // 3. Sections (`.text`, `.rdata`, `__TEXT,__text`)
    const auto sections = effective_sections(ctx);
    for (const bool ci : {false, true}) {
        for (const auto& sec : sections) {
            const bool match = ci ? iequals_ascii(sec.name, token) : (sec.name == token);
            if (match) {
                if (sec.virtual_address != 0u || sec.virtual_size != 0u) {
                    return EvalValue{
                        .value = sec.virtual_address,
                        .kind = EvalValueKind::VirtualAddress,
                        .origin_label = sec.name,
                    };
                }
                return EvalValue{
                    .value = sec.file_offset,
                    .kind = EvalValueKind::FileOffset,
                    .origin_label = sec.name,
                };
            }
        }
    }

    // 4. Process Modules (`kernel32.dll`, `libc.so.6`)
    for (const bool ci : {false, true}) {
        for (const auto& mod : ctx.modules) {
            const std::string filename = mod.path.empty()
                                             ? std::string{}
                                             : mod.path.filename().string();
            const bool match_name = ci ? iequals_ascii(mod.name, token) : (mod.name == token);
            const bool match_file = !filename.empty() &&
                                    (ci ? iequals_ascii(filename, token) : (filename == token));
            if (match_name || match_file) {
                return EvalValue{
                    .value = mod.base_address,
                    .kind = EvalValueKind::VirtualAddress,
                    .origin_label = mod.name.empty() ? filename : mod.name,
                };
            }
        }
    }

    // 5. User AnnotationStore labels
    if (ctx.annotations != nullptr) {
        for (const bool ci : {false, true}) {
            for (const auto& [addr, note] : ctx.annotations->records()) {
                if (note.name.empty()) {
                    continue;
                }
                if (ci ? iequals_ascii(note.name, token) : (note.name == token)) {
                    return EvalValue{
                        .value = addr,
                        .kind = EvalValueKind::VirtualAddress,
                        .origin_label = note.name,
                    };
                }
            }
        }
    }

    // 6. User Bookmarks
    for (const bool ci : {false, true}) {
        for (const auto& bm : ctx.bookmarks) {
            if (bm.label.empty()) {
                continue;
            }
            if (ci ? iequals_ascii(bm.label, token) : (bm.label == token)) {
                return EvalValue{
                    .value = bm.address,
                    .kind = bm.is_file_offset ? EvalValueKind::FileOffset
                                              : EvalValueKind::VirtualAddress,
                    .origin_label = bm.label,
                };
            }
        }
    }

    // 7. FunctionIndex & SymbolIndex (exact case first, then case-insensitive; raw + demangled)
    for (const bool ci : {false, true}) {
        if (ctx.functions != nullptr) {
            for (const auto& fn : ctx.functions->entries()) {
                if (symbol_matches_token(
                        token, fn.name, fn.raw_name, fn.demangled_name, ci)) {
                    return EvalValue{
                        .value = fn.virtual_address,
                        .kind = EvalValueKind::VirtualAddress,
                        .origin_label = std::string(fn.display_name(true)),
                    };
                }
            }
        }
        if (ctx.symbols != nullptr) {
            for (const auto& sym : ctx.symbols->records()) {
                std::string synth_demangled{};
                std::string_view demangled_sv = sym.demangled_name;
                const std::string_view raw_sv =
                    sym.raw_name.empty() ? std::string_view(sym.name) : std::string_view(sym.raw_name);
                if (demangled_sv.empty() &&
                    (raw_sv.starts_with("_Z") || raw_sv.starts_with("_R") || raw_sv.starts_with("?"))) {
                    const auto dm = peelf::demangle_symbol(raw_sv);
                    if (dm.succeeded) {
                        synth_demangled = dm.demangled;
                        demangled_sv = synth_demangled;
                    }
                }
                if (symbol_matches_token(token, sym.name, raw_sv, demangled_sv, ci)) {
                    if (sym.virtual_address.has_value()) {
                        return EvalValue{
                            .value = *sym.virtual_address,
                            .kind = EvalValueKind::VirtualAddress,
                            .origin_label = !demangled_sv.empty()
                                                ? std::string(demangled_sv)
                                                : sym.name,
                        };
                    }
                    if (sym.file_offset.has_value()) {
                        return EvalValue{
                            .value = *sym.file_offset,
                            .kind = EvalValueKind::FileOffset,
                            .origin_label = sym.name,
                        };
                    }
                }
            }
        }
    }

    // Distinguish malformed numeric literals from unknown identifiers for clearer diagnostics.
    if (!quoted && is_ascii_digit(token.front())) {
        return peelf::make_error(std::format("Invalid numeric literal '{}'", token));
    }
    return peelf::make_error(
        std::format("Unknown symbol, section, bookmark, or token '{}'", token));
}

class ExpressionParser {
public:
    ExpressionParser(std::string_view input, const AddressExpressionContext& ctx) noexcept
        : input_(input), ctx_(ctx) {}

    [[nodiscard]] peelf::Result<EvalValue> parse() {
        skip_ws();
        if (eof()) {
            return peelf::make_error("Address expression is empty");
        }
        // Optional single leading ':' from palette GoTo prefix (`:0x140001000`),
        // preserving C++ global scope `::symbol`.
        if (peek() == ':' && (pos_ + 1u >= input_.size() || input_[pos_ + 1u] != ':')) {
            ++pos_;
            skip_ws();
            if (eof()) {
                return peelf::make_error("Expected address expression after ':'");
            }
        }

        auto result = parse_expr(0u);
        if (!result) {
            return result;
        }
        skip_ws();
        if (!eof()) {
            return peelf::make_error(
                std::format("Unexpected trailing token '{}' in address expression",
                            input_.substr(pos_)));
        }
        return result;
    }

private:
    static constexpr std::size_t kMaxParenDepth = 64u;

    void skip_ws() noexcept {
        while (pos_ < input_.size() && is_ascii_space(input_[pos_])) {
            ++pos_;
        }
    }

    [[nodiscard]] bool eof() const noexcept { return pos_ >= input_.size(); }
    [[nodiscard]] char peek() const noexcept { return pos_ < input_.size() ? input_[pos_] : '\0'; }

    [[nodiscard]] bool consume_prefix_keyword(std::string_view kw) noexcept {
        if (input_.size() - pos_ <= kw.size()) {
            return false;
        }
        if (!istarts_with_ascii(input_.substr(pos_), kw)) {
            return false;
        }
        // Ensure `ns::Widget` (`::`) is never mistaken for a single-colon prefix.
        const std::size_t after = pos_ + kw.size();
        if (kw.back() == ':' && after < input_.size() && input_[after] == ':') {
            return false;
        }
        pos_ = after;
        return true;
    }

    [[nodiscard]] peelf::Result<EvalValue> parse_expr(std::size_t depth) {
        if (depth > kMaxParenDepth) {
            return peelf::make_error("Address expression exceeds maximum parenthesis nesting depth");
        }
        auto lhs = parse_primary(depth);
        if (!lhs) {
            return lhs;
        }

        while (true) {
            skip_ws();
            if (eof()) {
                break;
            }
            const char op = peek();
            if (op != '+' && op != '-') {
                break;
            }
            ++pos_;
            auto rhs = parse_primary(depth);
            if (!rhs) {
                return rhs;
            }
            auto combined = apply_binary_op(op, *lhs, *rhs);
            if (!combined) {
                return combined;
            }
            lhs = std::move(combined);
        }
        return lhs;
    }

    [[nodiscard]] static peelf::Result<EvalValue> apply_binary_op(
        char op,
        const EvalValue& lhs,
        const EvalValue& rhs) {
        std::uint64_t out_val = 0u;
        if (op == '+') {
            if (rhs.value > std::numeric_limits<std::uint64_t>::max() - lhs.value) {
                return peelf::make_error("Address expression overflow in '+'");
            }
            out_val = lhs.value + rhs.value;
        } else {
            if (rhs.value > lhs.value) {
                return peelf::make_error("Address expression underflow in '-'");
            }
            out_val = lhs.value - rhs.value;
        }

        EvalValueKind kind = lhs.kind;
        if (op == '+') {
            if (lhs.kind == EvalValueKind::FileOffset && rhs.kind == EvalValueKind::FileOffset) {
                return peelf::make_error("Cannot add two file offsets together");
            }
            if (lhs.kind == EvalValueKind::Scalar) {
                kind = rhs.kind;
            }
        } else {
            if (lhs.kind == rhs.kind && lhs.kind != EvalValueKind::Scalar) {
                kind = EvalValueKind::Scalar;
            }
        }

        std::string label = lhs.origin_label;
        if (label.empty() && !rhs.origin_label.empty() && op == '+') {
            label = rhs.origin_label;
        }
        return EvalValue{
            .value = out_val,
            .kind = kind,
            .origin_label = std::move(label),
        };
    }

    [[nodiscard]] peelf::Result<EvalValue> parse_primary(std::size_t depth) {
        skip_ws();
        if (eof()) {
            return peelf::make_error("Unexpected end of address expression");
        }

        const char lead = peek();
        if (lead == '+') {
            ++pos_;
            return parse_primary(depth + 1u);
        }
        if (lead == '-') {
            return peelf::make_error(
                "Unary '-' underflows unsigned 64-bit address arithmetic");
        }
        if (lead == ')') {
            return peelf::make_error("Unexpected ')' in address expression");
        }
        if (lead == '(') {
            ++pos_;
            auto inner = parse_expr(depth + 1u);
            if (!inner) {
                return inner;
            }
            skip_ws();
            if (peek() != ')') {
                return peelf::make_error("Missing closing ')' in address expression");
            }
            ++pos_;
            return inner;
        }

        // Explicit address-space prefixes (`va:`, `rva:`, `off:`, `offset:`, `file:`)
        if (consume_prefix_keyword("va:")) {
            auto val = parse_primary(depth + 1u);
            if (!val) {
                return val;
            }
            val->kind = EvalValueKind::VirtualAddress;
            return val;
        }
        if (consume_prefix_keyword("rva:")) {
            const auto base = effective_image_base(ctx_);
            if (!base.has_value()) {
                return peelf::make_error(
                    "Prefix 'rva:' requires a loaded image or module base address");
            }
            auto val = parse_primary(depth + 1u);
            if (!val) {
                return val;
            }
            if (val->value > std::numeric_limits<std::uint64_t>::max() - *base) {
                return peelf::make_error("RVA expression overflows 64-bit address space");
            }
            return EvalValue{
                .value = *base + val->value,
                .kind = EvalValueKind::VirtualAddress,
                .origin_label = val->origin_label.empty()
                                    ? std::format("image_base+0x{:X}", val->value)
                                    : val->origin_label,
            };
        }
        if (consume_prefix_keyword("offset:") || consume_prefix_keyword("off:") ||
            consume_prefix_keyword("file:")) {
            auto val = parse_primary(depth + 1u);
            if (!val) {
                return val;
            }
            val->kind = EvalValueKind::FileOffset;
            return val;
        }

        // Quoted identifier (`"..."` or `` `...` ``)
        if (lead == '"' || lead == '`') {
            const char quote = lead;
            ++pos_;
            const std::size_t start = pos_;
            while (pos_ < input_.size() && input_[pos_] != quote) {
                ++pos_;
            }
            if (pos_ >= input_.size()) {
                return peelf::make_error(
                    std::format("Unclosed {} in address expression", quote));
            }
            const std::string_view body = input_.substr(start, pos_ - start);
            ++pos_;
            return resolve_named_or_literal_atom(body, true, ctx_);
        }

        // Unquoted operand: scan up to top-level `+`, `-`, `)` while balancing `<...>`
        // template arguments and attached `(...)` C++ parameter lists.
        const std::size_t start = pos_;
        int angle_depth = 0;
        int sig_paren_depth = 0;
        bool prev_was_ws = false;
        while (pos_ < input_.size()) {
            const char ch = input_[pos_];
            if (sig_paren_depth > 0) {
                if (ch == '(') {
                    ++sig_paren_depth;
                } else if (ch == ')') {
                    --sig_paren_depth;
                }
                prev_was_ws = is_ascii_space(ch);
                ++pos_;
                continue;
            }
            if (angle_depth > 0) {
                if (ch == '<') {
                    ++angle_depth;
                } else if (ch == '>') {
                    --angle_depth;
                }
                prev_was_ws = is_ascii_space(ch);
                ++pos_;
                continue;
            }

            if (ch == '+' || ch == '-' || ch == ')') {
                break;
            }
            if (ch == '(') {
                if (pos_ > start && !prev_was_ws) {
                    // Attached C++ signature parameter list, e.g. `ns::Widget::run(int)`
                    ++sig_paren_depth;
                    prev_was_ws = false;
                    ++pos_;
                    continue;
                }
                break;
            }
            if (ch == '<') {
                ++angle_depth;
                prev_was_ws = false;
                ++pos_;
                continue;
            }
            prev_was_ws = is_ascii_space(ch);
            ++pos_;
        }

        if (angle_depth != 0) {
            return peelf::make_error("Unclosed '<' in symbol template arguments");
        }
        if (sig_paren_depth != 0) {
            return peelf::make_error("Unclosed '(' in symbol signature");
        }

        const std::string_view raw_slice = trim_ascii(input_.substr(start, pos_ - start));
        return resolve_named_or_literal_atom(raw_slice, false, ctx_);
    }

    std::string_view input_{};
    const AddressExpressionContext& ctx_;
    std::size_t pos_ = 0u;
};

} // namespace

peelf::Result<ResolvedAddressExpression> evaluate_address_expression(
    std::string_view expression,
    const AddressExpressionContext& context) {
    ExpressionParser parser(expression, context);
    auto evaluated = parser.parse();
    if (!evaluated) {
        return std::unexpected(evaluated.error());
    }

    ResolvedAddressExpression resolved{};
    resolved.matched_symbol_or_section = evaluated->origin_label;

    if (evaluated->kind == EvalValueKind::FileOffset) {
        const std::uint64_t off = evaluated->value;
        if (context.file_size.has_value() && off >= *context.file_size) {
            return peelf::make_error(std::format(
                "File offset 0x{:X} exceeds file size (0x{:X} bytes)",
                off,
                *context.file_size));
        }
        resolved.file_offset = off;
        if (context.image != nullptr) {
            resolved.virtual_address = context.image->file_offset_to_virtual_address(off);
        }
        resolved.is_file_offset_only = !resolved.virtual_address.has_value();
        if (resolved.virtual_address.has_value()) {
            resolved.canonical_summary = std::format(
                "VA 0x{:X} (off 0x{:X})",
                *resolved.virtual_address,
                off);
        } else {
            resolved.canonical_summary = std::format("File offset 0x{:X} (unmapped)", off);
        }
    } else {
        const std::uint64_t va = evaluated->value;
        resolved.virtual_address = va;
        if (context.image != nullptr) {
            resolved.file_offset = context.image->virtual_address_to_file_offset(va);
        }
        resolved.is_file_offset_only = false;
        if (resolved.file_offset.has_value()) {
            resolved.canonical_summary =
                std::format("VA 0x{:X} (off 0x{:X})", va, *resolved.file_offset);
        } else {
            resolved.canonical_summary = std::format("VA 0x{:X}", va);
        }
    }

    if (!resolved.matched_symbol_or_section.empty()) {
        resolved.canonical_summary += std::format(" [{}]", resolved.matched_symbol_or_section);
    }
    return resolved;
}

// ---------------------------------------------------------------------------
// Unified Command Palette Engine
// ---------------------------------------------------------------------------

ParsedPaletteQuery parse_palette_query(std::string_view raw_query) noexcept {
    const std::string_view trimmed = trim_ascii(raw_query);
    if (trimmed.empty()) {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Omni,
            .filter = {},
            .raw_trimmed = {},
        };
    }

    if (trimmed.front() == '>') {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Commands,
            .filter = trim_leading_ascii(trimmed.substr(1)),
            .raw_trimmed = trimmed,
        };
    }
    if (trimmed.front() == '@') {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Symbols,
            .filter = trim_leading_ascii(trimmed.substr(1)),
            .raw_trimmed = trimmed,
        };
    }
    if (trimmed.front() == '#') {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Strings,
            .filter = trim_leading_ascii(trimmed.substr(1)),
            .raw_trimmed = trimmed,
        };
    }
    if (trimmed.front() == ':' && (trimmed.size() < 2u || trimmed[1] != ':')) {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::GoToAddress,
            .filter = trim_leading_ascii(trimmed.substr(1)),
            .raw_trimmed = trimmed,
        };
    }
    if (istarts_with_ascii(trimmed, "struct:")) {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Types,
            .filter = trim_leading_ascii(trimmed.substr(7)),
            .raw_trimmed = trimmed,
        };
    }
    if (istarts_with_ascii(trimmed, "type:")) {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::Types,
            .filter = trim_leading_ascii(trimmed.substr(5)),
            .raw_trimmed = trimmed,
        };
    }
    if (trimmed.front() == '?' || trimmed.front() == '*') {
        return ParsedPaletteQuery{
            .mode = PalettePrefixMode::BookmarksAndRules,
            .filter = trim_leading_ascii(trimmed.substr(1)),
            .raw_trimmed = trimmed,
        };
    }

    return ParsedPaletteQuery{
        .mode = PalettePrefixMode::Omni,
        .filter = trimmed,
        .raw_trimmed = trimmed,
    };
}

std::optional<DeferredNavigationRequest> build_palette_navigation_request(
    const PaletteAction& action) noexcept {
    switch (action.kind) {
        case PaletteActionKind::NavigateAddress:
            return DeferredNavigationRequest{
                .kind = DeferredNavigationRequest::Kind::Address,
                .target = action.target_address,
                .preferred_view = action.preferred_view,
                .highlight_size = action.highlight_size,
                .request_decompile = action.request_decompile,
            };
        case PaletteActionKind::NavigateFileOffset:
            return DeferredNavigationRequest{
                .kind = DeferredNavigationRequest::Kind::Offset,
                .target = action.target_address,
                .preferred_view = action.preferred_view,
                .highlight_size = action.highlight_size,
                .request_decompile = action.request_decompile,
            };
        default:
            return std::nullopt;
    }
}

PaletteDataSources make_palette_data_sources(
    const BinaryModel& model,
    const SymbolIndex* ui_symbols,
    const AnnotationStore* annotations,
    const StringsIndex* strings,
    std::span<const DataTypeRecord> ui_debug_types,
    std::span<const DataTypeRecord> secondary_types) noexcept {
    PaletteDataSources src{};
    src.expr_context = make_address_expression_context(model, ui_symbols, annotations);
    src.functions = &model.function_index();
    src.symbols = (ui_symbols != nullptr) ? ui_symbols : &model.symbol_index();
    src.annotations = annotations;
    src.strings = strings;
    src.custom_types = model.custom_types();
    src.debug_types = !ui_debug_types.empty()
                          ? ui_debug_types
                          : std::span<const DataTypeRecord>(model.debug_types());
    src.secondary_types = secondary_types;
    src.bookmarks = model.bookmarks();
    src.security_audit = &model.security_audit();
    src.demangle_symbols = model.demangle_symbols();
    src.has_file = model.has_file();
    src.is_live_process = model.is_live_process();
    return src;
}

namespace {

struct BuiltinCommandSpec {
    PaletteCommandId id = PaletteCommandId::OpenBinary;
    std::string_view item_id{};
    std::string_view title{};
    std::string_view subtitle{};
    std::string_view shortcut{};
    std::string_view keywords{};
    bool requires_file = false;
};

constexpr std::array<BuiltinCommandSpec, 15> kBuiltinCommands{{
    {PaletteCommandId::OpenBinary,
     "cmd:open_binary",
     "Open Binary...",
     "Open a PE, ELF, or Mach-O executable or shared library",
     "Ctrl+O",
     "file load executable dll so dylib",
     false},
    {PaletteCommandId::AttachToProcess,
     "cmd:attach_process",
     "Attach to Process...",
     "Attach to a running local process (read-only by default)",
     "Ctrl+P",
     "live pid memory inspect",
     false},
    {PaletteCommandId::ConnectGdbRemote,
     "cmd:connect_gdb_remote",
     "Connect GDB Remote...",
     "Connect to a gdbserver or QEMU RSP stub",
     "",
     "qemu rsp remote target stub",
     false},
    {PaletteCommandId::OpenCrashDump,
     "cmd:open_crash_dump",
     "Open Crash Dump...",
     "Inspect a Windows Minidump (.dmp) or Linux ELF core dump",
     "",
     "minidump core dump postmortem",
     false},
    {PaletteCommandId::OpenDebugSymbols,
     "cmd:open_debug_symbols",
     "Open Debug Symbols...",
     "Load external PDB or DWARF debug symbol information",
     "",
     "pdb dwarf dsym symbols types",
     true},
    {PaletteCommandId::SaveProject,
     "cmd:save_project",
     "Save Project...",
     "Save annotations, bookmarks, patches, and layout to .peproj",
     "",
     "peproj analysis project export",
     true},
    {PaletteCommandId::SavePatchedAs,
     "cmd:save_patched_as",
     "Save Patched As...",
     "Write patched binary bytes to a new output file",
     "Ctrl+Shift+S",
     "write patched binary export",
     true},
    {PaletteCommandId::DecompileCurrentFunction,
     "cmd:decompile_current",
     "Decompile Current Function",
     "Run structured / Ghidra decompiler on the active selection",
     "F5",
     "pseudocode clift decompiler",
     true},
    {PaletteCommandId::ScanFullReferences,
     "cmd:scan_full_references",
     "Scan Full References",
     "Scan code & data sections for cross-references (xrefs)",
     "X",
     "xrefs cross references callrefs",
     true},
    {PaletteCommandId::ToggleDemangleSymbols,
     "cmd:toggle_demangle",
     "Toggle Demangle Symbols",
     "Switch between demangled C++/Rust signatures and raw mangled names",
     "",
     "itanium msvc rust mangled",
     false},
    {PaletteCommandId::SwitchFlowGraphGalaxy,
     "cmd:switch_flow_galaxy",
     "Switch Flow Graph / GPU Galaxy",
     "Toggle between control-flow / call graph and GPU Barnes-Hut Call Galaxy",
     "",
     "cfg callgraph barnes hut gpu galaxy",
     false},
    {PaletteCommandId::ResetWorkspaceLayout,
     "cmd:reset_workspace_layout",
     "Reset Current Workspace Layout",
     "Restore default dock splits and tabs for the active workspace preset",
     "",
     "dock layout restore default",
     false},
    {PaletteCommandId::GoToEntryPoint,
     "cmd:goto_entry_point",
     "Go to Entry Point",
     "Jump to the loaded binary entry point in Disassembly",
     "",
     "g2ep entry _start main",
     true},
    {PaletteCommandId::GoToAddressPrompt,
     "cmd:goto_address",
     "Go to Address / Expression...",
     "Evaluate an address, RVA, file offset, or symbol expression",
     "G",
     "g2va goto virtual address rva offset expression",
     false},
    {PaletteCommandId::DefineCustomCTypes,
     "cmd:define_custom_c_types",
     "Define / Import Custom C Types...",
     "Author or paste C struct, union, enum, and typedef declarations in Structure View",
     "",
     "c header struct union enum typedef pragma pack custom types",
     false},
}};

[[nodiscard]] constexpr std::string_view panel_id_slug(WorkspacePanelId panel) noexcept {
    switch (panel) {
        case WorkspacePanelId::FileInfo:           return "panel:file_info";
        case WorkspacePanelId::MemoryMap:          return "panel:memory_map";
        case WorkspacePanelId::MemoryHeatmap:      return "panel:memory_heatmap";
        case WorkspacePanelId::ByteEntropyViz:     return "panel:byte_entropy_viz";
        case WorkspacePanelId::Structure:          return "panel:structure";
        case WorkspacePanelId::Details:            return "panel:details";
        case WorkspacePanelId::Sections:           return "panel:sections";
        case WorkspacePanelId::HexView:            return "panel:hex_view";
        case WorkspacePanelId::PatchSet:           return "panel:patch_set";
        case WorkspacePanelId::Shellcode:          return "panel:shellcode";
        case WorkspacePanelId::Scripting:          return "panel:scripting";
        case WorkspacePanelId::Imports:            return "panel:imports";
        case WorkspacePanelId::Exports:            return "panel:exports";
        case WorkspacePanelId::Symbols:            return "panel:symbols";
        case WorkspacePanelId::Functions:          return "panel:functions";
        case WorkspacePanelId::ThreadsAndStack:    return "panel:threads_and_stack";
        case WorkspacePanelId::ThreadLocals:       return "panel:thread_locals";
        case WorkspacePanelId::MemorySearch:       return "panel:memory_search";
        case WorkspacePanelId::RuntimeAndFlags:    return "panel:runtime_and_flags";
        case WorkspacePanelId::Handlers:           return "panel:handlers";
        case WorkspacePanelId::DataStructures:     return "panel:data_structures";
        case WorkspacePanelId::ReferencesAndNotes: return "panel:references_and_notes";
        case WorkspacePanelId::Strings:            return "panel:strings";
        case WorkspacePanelId::SignaturesAndCrypto: return "panel:signatures_and_crypto";
        case WorkspacePanelId::StructureView:      return "panel:structure_view";
        case WorkspacePanelId::ProcessInternals:   return "panel:process_internals";
        case WorkspacePanelId::Dependencies:       return "panel:dependencies";
        case WorkspacePanelId::BinaryDiff:         return "panel:binary_diff";
        case WorkspacePanelId::Debugger:           return "panel:debugger";
        case WorkspacePanelId::TargetCapabilities: return "panel:target_capabilities";
        case WorkspacePanelId::ExecutableSettings: return "panel:executable_settings";
        case WorkspacePanelId::ExecutionTimeline:  return "panel:execution_timeline";
        case WorkspacePanelId::Decompiler:         return "panel:decompiler";
        case WorkspacePanelId::PeHeaders:          return "panel:pe_headers";
        case WorkspacePanelId::PeImports:          return "panel:pe_imports";
        case WorkspacePanelId::PeExports:          return "panel:pe_exports";
        case WorkspacePanelId::ClrMetadata:        return "panel:clr_metadata";
        case WorkspacePanelId::Disassembly:        return "panel:disassembly";
        case WorkspacePanelId::FlowGraph:          return "panel:flow_graph";
        case WorkspacePanelId::Log:                return "panel:log";
    }
    return "panel:disassembly";
}

[[nodiscard]] bool looks_like_address_expression(std::string_view q) noexcept {
    q = trim_ascii(q);
    if (q.empty()) {
        return false;
    }
    if (istarts_with_ascii(q, "0x") || istarts_with_ascii(q, "va:") ||
        istarts_with_ascii(q, "rva:") || istarts_with_ascii(q, "off:") ||
        istarts_with_ascii(q, "offset:") || istarts_with_ascii(q, "file:")) {
        return true;
    }
    if (q.front() == '$' || q.front() == '.' || q.front() == '(') {
        return true;
    }
    if (iequals_ascii(q, "entry") || iequals_ascii(q, "image_base")) {
        return true;
    }
    if (q.size() >= 2u && is_ascii_digit(q.front()) && (q.back() == 'h' || q.back() == 'H')) {
        return true;
    }
    bool all_digits = true;
    for (const char ch : q) {
        if (!is_ascii_digit(ch) && ch != '_') {
            all_digits = false;
        }
        if (ch == '+' || ch == '-' || ch == '(' || ch == ')') {
            return true;
        }
    }
    return all_digits;
}

enum class CandidateKind : std::uint8_t {
    Panel = 0,
    Preset,
    Command,
    Function,
    Symbol,
    Annotation,
    String,
    CatalogType,
    CustomCType,
    PrimaryDebugType,
    SecondaryDebugType,
    Bookmark,
    SecurityFinding,
    SecurityCatalogRule,
};

struct CandidateHit {
    CandidateKind kind = CandidateKind::Command;
    std::size_t index = 0u;
    std::uint64_t address_key = 0u;
    int score = 0;
    std::uint64_t mru_seq = 0u;
};

[[nodiscard]] bool candidate_better(const CandidateHit& a, const CandidateHit& b) noexcept {
    if (a.score != b.score) {
        return a.score > b.score;
    }
    if (a.mru_seq != b.mru_seq) {
        return a.mru_seq > b.mru_seq;
    }
    if (a.kind != b.kind) {
        return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    }
    return a.index < b.index;
}

class BoundedHitCollector {
public:
    explicit BoundedHitCollector(std::size_t limit) : limit_(limit) {
        heap_.reserve(std::min<std::size_t>(limit, 256u));
    }

    void push(const CandidateHit& hit) {
        if (limit_ == 0u) {
            return;
        }
        if (heap_.size() < limit_) {
            heap_.push_back(hit);
            std::push_heap(heap_.begin(), heap_.end(), candidate_better);
            return;
        }
        if (candidate_better(hit, heap_.front())) {
            std::pop_heap(heap_.begin(), heap_.end(), candidate_better);
            heap_.back() = hit;
            std::push_heap(heap_.begin(), heap_.end(), candidate_better);
        }
    }

    [[nodiscard]] std::vector<CandidateHit> take_sorted() {
        std::sort_heap(heap_.begin(), heap_.end(), candidate_better);
        return std::move(heap_);
    }

private:
    std::size_t limit_ = 64u;
    std::vector<CandidateHit> heap_{};
};

[[nodiscard]] constexpr std::string_view symbol_source_label(SymbolSource src) noexcept {
    switch (src) {
        case SymbolSource::EntryPoint:  return "Entry Point";
        case SymbolSource::ImageSymbol: return "Image Symbol";
        case SymbolSource::Import:      return "Import";
        case SymbolSource::Export:      return "Export";
        case SymbolSource::DebugSymbol: return "Debug Symbol";
    }
    return "Symbol";
}

[[nodiscard]] std::string format_va_badge(
    std::uint64_t va,
    std::optional<std::uint64_t> image_base) {
    if (image_base.has_value() && va >= *image_base && (va - *image_base) < 0x80000000ULL) {
        return std::format("0x{:X} (+0x{:X})", va, va - *image_base);
    }
    return std::format("0x{:X}", va);
}

[[nodiscard]] PaletteAction make_va_or_offset_action(
    std::optional<std::uint64_t> va,
    std::optional<std::uint64_t> off,
    PreferredView view,
    std::size_t highlight_size = 0u,
    bool decompile = false) noexcept {
    if (va.has_value()) {
        return PaletteAction{
            .kind = PaletteActionKind::NavigateAddress,
            .target_address = *va,
            .preferred_view = view,
            .highlight_size = highlight_size,
            .request_decompile = decompile,
        };
    }
    if (off.has_value()) {
        return PaletteAction{
            .kind = PaletteActionKind::NavigateFileOffset,
            .target_address = *off,
            .preferred_view = view,
            .highlight_size = highlight_size,
            .request_decompile = decompile,
        };
    }
    return PaletteAction{};
}

void append_goto_items(
    const ResolvedAddressExpression& resolved,
    bool emit_all_three_rows,
    std::vector<PaletteItem>& out_items,
    std::size_t max_results) {
    if (out_items.size() >= max_results) {
        return;
    }

    const std::string badge = resolved.virtual_address.has_value()
                                  ? std::format("0x{:X}", *resolved.virtual_address)
                                  : std::format("off 0x{:X}", resolved.file_offset.value_or(0u));

    const PaletteAction hex_act = make_va_or_offset_action(
        resolved.virtual_address, resolved.file_offset, PreferredView::Hex);
    const PaletteAction disasm_act = make_va_or_offset_action(
        resolved.virtual_address, resolved.file_offset, PreferredView::Disassembly);
    const PaletteAction decomp_act = resolved.virtual_address.has_value()
                                         ? make_va_or_offset_action(
                                               resolved.virtual_address,
                                               resolved.file_offset,
                                               PreferredView::Disassembly,
                                               0u,
                                               true)
                                         : PaletteAction{};

    if (resolved.is_file_offset_only) {
        PaletteItem hex_item{};
        hex_item.id = std::format("goto:hex:off:0x{:X}", resolved.file_offset.value_or(0u));
        hex_item.category = PaletteCategory::GoTo;
        hex_item.title = "Jump in Hex View";
        hex_item.subtitle = resolved.canonical_summary;
        hex_item.right_badge = badge;
        hex_item.score = 100000;
        hex_item.pinned = true;
        hex_item.primary_action = hex_act;
        hex_item.secondary_hex_action = hex_act;
        out_items.push_back(std::move(hex_item));

        if (emit_all_three_rows && out_items.size() < max_results) {
            PaletteItem dis_item{};
            dis_item.id = std::format("goto:disasm:off:0x{:X}", resolved.file_offset.value_or(0u));
            dis_item.category = PaletteCategory::GoTo;
            dis_item.title = "Jump in Disassembly";
            dis_item.subtitle = resolved.canonical_summary + " · Disassemble raw file bytes";
            dis_item.right_badge = badge;
            dis_item.score = 99999;
            dis_item.pinned = true;
            dis_item.primary_action = disasm_act;
            dis_item.secondary_hex_action = hex_act;
            out_items.push_back(std::move(dis_item));
        }
        return;
    }

    PaletteItem primary{};
    primary.id = std::format("goto:disasm:0x{:X}", *resolved.virtual_address);
    primary.category = PaletteCategory::GoTo;
    primary.title = "Jump in Disassembly";
    primary.subtitle = resolved.canonical_summary +
                       " · Enter: Disassembly · Shift+Enter: Hex View · Ctrl+Enter: Decompile";
    primary.right_badge = badge;
    primary.score = 100000;
    primary.pinned = true;
    primary.primary_action = disasm_act;
    primary.secondary_hex_action = hex_act;
    primary.tertiary_decompile_action = decomp_act;
    out_items.push_back(std::move(primary));

    if (emit_all_three_rows) {
        if (out_items.size() < max_results) {
            PaletteItem hex_item{};
            hex_item.id = std::format("goto:hex:0x{:X}", *resolved.virtual_address);
            hex_item.category = PaletteCategory::GoTo;
            hex_item.title = "Jump in Hex View";
            hex_item.subtitle = resolved.canonical_summary;
            hex_item.right_badge = badge;
            hex_item.score = 99999;
            hex_item.pinned = true;
            hex_item.primary_action = hex_act;
            hex_item.secondary_hex_action = hex_act;
            hex_item.tertiary_decompile_action = decomp_act;
            out_items.push_back(std::move(hex_item));
        }
        if (out_items.size() < max_results) {
            PaletteItem dec_item{};
            dec_item.id = std::format("goto:decompile:0x{:X}", *resolved.virtual_address);
            dec_item.category = PaletteCategory::GoTo;
            dec_item.title = "Decompile at Address";
            dec_item.subtitle = resolved.canonical_summary;
            dec_item.right_badge = badge;
            dec_item.score = 99998;
            dec_item.pinned = true;
            dec_item.primary_action = decomp_act;
            dec_item.secondary_hex_action = hex_act;
            dec_item.tertiary_decompile_action = decomp_act;
            out_items.push_back(std::move(dec_item));
        }
    }
}

} // namespace

CommandPalette::CommandPalette() = default;

void CommandPalette::record_execution(std::string_view item_id) {
    if (item_id.empty()) {
        return;
    }
    const std::uint64_t seq = next_mru_sequence_++;
    for (auto& entry : mru_entries_) {
        if (entry.id == item_id) {
            entry.sequence = seq;
            return;
        }
    }
    if (mru_entries_.size() >= kMaxMruEntries) {
        auto oldest = std::ranges::min_element(
            mru_entries_, {}, &MruEntry::sequence);
        if (oldest != mru_entries_.end()) {
            oldest->id.assign(item_id);
            oldest->sequence = seq;
            return;
        }
    }
    mru_entries_.push_back(MruEntry{.id = std::string(item_id), .sequence = seq});
}

void CommandPalette::clear_mru() noexcept {
    mru_entries_.clear();
    next_mru_sequence_ = 1u;
}

std::uint64_t CommandPalette::mru_sequence_for(std::string_view item_id) const noexcept {
    for (const auto& entry : mru_entries_) {
        if (entry.id == item_id) {
            return entry.sequence;
        }
    }
    return 0u;
}

int CommandPalette::mru_boost_for(std::string_view item_id) const noexcept {
    const std::uint64_t seq = mru_sequence_for(item_id);
    if (seq == 0u) {
        return 0;
    }
    // Most recent item receives +900, decaying gently by 12 points per newer execution
    // with a minimum boost of +180 for any MRU-tracked item.
    const std::uint64_t age =
        (next_mru_sequence_ > seq + 1u) ? (next_mru_sequence_ - 1u - seq) : 0u;
    const int decay = static_cast<int>(std::min<std::uint64_t>(age, 60u)) * 12;
    return std::max(180, 900 - decay);
}

PaletteQueryResult CommandPalette::query(
    std::string_view raw_query,
    const PaletteDataSources& sources,
    PaletteQueryOptions options) const {
    PaletteQueryResult out{};
    out.parsed_query = parse_palette_query(raw_query);

    const std::size_t max_results = options.max_results;
    if (max_results == 0u) {
        return out;
    }

    const PalettePrefixMode mode = out.parsed_query.mode;
    const std::string_view filter = out.parsed_query.filter;
    const bool has_mru = !mru_entries_.empty();
    const auto image_base = effective_image_base(sources.expr_context);

    // 1. Live Expression Evaluation (`:` mode or expression-like Omni query)
    if (mode == PalettePrefixMode::GoToAddress) {
        if (!filter.empty()) {
            auto eval = evaluate_address_expression(filter, sources.expr_context);
            if (eval.has_value()) {
                out.resolved_expression = *eval;
                append_goto_items(*eval, true, out.items, max_results);
            } else {
                out.expression_error = eval.error().message;
            }
        }
        return out;
    }

    if (mode == PalettePrefixMode::Omni && !filter.empty() &&
        looks_like_address_expression(filter)) {
        if (auto eval = evaluate_address_expression(filter, sources.expr_context);
            eval.has_value()) {
            out.resolved_expression = *eval;
            append_goto_items(*eval, true, out.items, max_results);
            if (out.items.size() >= max_results) {
                return out;
            }
        }
    }

    const std::size_t remaining_budget = max_results - out.items.size();
    BoundedHitCollector collector(remaining_budget);

    const bool include_commands =
        (mode == PalettePrefixMode::Omni || mode == PalettePrefixMode::Commands);
    const bool include_symbols =
        (mode == PalettePrefixMode::Omni || mode == PalettePrefixMode::Symbols);
    const bool include_strings =
        (mode == PalettePrefixMode::Omni || mode == PalettePrefixMode::Strings);
    const bool include_types =
        (mode == PalettePrefixMode::Omni || mode == PalettePrefixMode::Types);
    const bool include_bookmarks_rules =
        (mode == PalettePrefixMode::Omni || mode == PalettePrefixMode::BookmarksAndRules);

    const auto score_with_keywords =
        [filter](std::string_view primary, std::string_view secondary = {}) noexcept
        -> std::optional<int> {
        if (filter.empty()) {
            return 0;
        }
        const auto s1 = fuzzy_match_score(filter, primary, nullptr);
        if (secondary.empty()) {
            return s1;
        }
        const auto s2 = fuzzy_match_score(filter, secondary, nullptr);
        if (s1.has_value() && s2.has_value()) {
            return std::max(*s1, *s2 - 120);
        }
        if (s1.has_value()) {
            return s1;
        }
        if (s2.has_value()) {
            return *s2 - 120;
        }
        return std::nullopt;
    };

    // 2. Commands, Presets & Workspace Panels (`>`)
    if (include_commands) {
        for (std::size_t i = 0u; i < kBuiltinCommands.size(); ++i) {
            const auto& cmd = kBuiltinCommands[i];
            const auto sc = score_with_keywords(cmd.title, cmd.keywords);
            if (!sc.has_value()) {
                continue;
            }
            const int base_bias = filter.empty() ? (120 - static_cast<int>(i)) : 45;
            const int boost = has_mru ? mru_boost_for(cmd.item_id) : 0;
            collector.push(CandidateHit{
                .kind = CandidateKind::Command,
                .index = i,
                .score = *sc + base_bias + boost,
                .mru_seq = has_mru ? mru_sequence_for(cmd.item_id) : 0u,
            });
        }

        for (std::size_t i = 0u; i < kAllWorkspacePresets.size(); ++i) {
            const WorkspacePreset preset = kAllWorkspacePresets[i];
            const std::string_view name = workspace_preset_display_name(preset);
            const std::string_view preset_slug = workspace_preset_id(preset);
            const auto sc = score_with_keywords(name, preset_slug);
            std::optional<int> best = sc;
            if (!best.has_value() && !filter.empty()) {
                if (const auto kw = fuzzy_match_score(filter, "Switch Workspace Preset", nullptr)) {
                    best = *kw - 180;
                }
            }
            if (!best.has_value()) {
                continue;
            }
            std::array<char, 64> id_buf{};
            const auto fmt_res = std::format_to_n(
                id_buf.data(), id_buf.size(), "preset:{}", preset_slug);
            const std::string_view item_id(
                id_buf.data(),
                std::min<std::size_t>(static_cast<std::size_t>(fmt_res.size), id_buf.size()));
            const int base_bias = filter.empty() ? (95 - static_cast<int>(i)) : 35;
            const int boost = has_mru ? mru_boost_for(item_id) : 0;
            collector.push(CandidateHit{
                .kind = CandidateKind::Preset,
                .index = i,
                .score = *best + base_bias + boost,
                .mru_seq = has_mru ? mru_sequence_for(item_id) : 0u,
            });
        }

        const auto panels = all_workspace_panels();
        for (std::size_t i = 0u; i < panels.size(); ++i) {
            const WorkspacePanelId panel = panels[i];
            const std::string_view title = workspace_panel_window_name(panel);
            const std::string_view slug = panel_id_slug(panel);
            auto sc = score_with_keywords(title, slug);
            if (!sc.has_value() && !filter.empty()) {
                if (const auto kw = fuzzy_match_score(filter, "Show Focus Toggle Panel", nullptr)) {
                    sc = *kw - 200;
                }
            }
            if (!sc.has_value()) {
                continue;
            }
            const int base_bias = filter.empty() ? (80 - static_cast<int>(i)) : 40;
            const int boost = has_mru ? mru_boost_for(slug) : 0;
            collector.push(CandidateHit{
                .kind = CandidateKind::Panel,
                .index = i,
                .score = *sc + base_bias + boost,
                .mru_seq = has_mru ? mru_sequence_for(slug) : 0u,
            });
        }
    }

    // 3. Functions, Symbols & Annotations (`@`)
    std::size_t annot_idx = 0u;
    if (include_symbols && sources.annotations != nullptr) {
        for (const auto& [addr, note] : sources.annotations->records()) {
            if (note.name.empty()) {
                ++annot_idx;
                continue;
            }
            const auto sc = score_with_keywords(note.name, note.comment);
            if (sc.has_value()) {
                int boost = 0;
                std::uint64_t seq = 0u;
                if (has_mru) {
                    std::array<char, 48> id_buf{};
                    const auto r = std::format_to_n(id_buf.data(), id_buf.size(), "annot:0x{:X}", addr);
                    const std::string_view id_sv(
                        id_buf.data(),
                        std::min<std::size_t>(static_cast<std::size_t>(r.size), id_buf.size()));
                    boost = mru_boost_for(id_sv);
                    seq = mru_sequence_for(id_sv);
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::Annotation,
                    .index = annot_idx,
                    .address_key = addr,
                    .score = *sc + 35 + boost,
                    .mru_seq = seq,
                });
            }
            ++annot_idx;
        }
    }

    if (include_symbols && sources.functions != nullptr) {
        const auto& fns = sources.functions->entries();
        const std::size_t scan_limit =
            filter.empty() ? std::min<std::size_t>(fns.size(), max_results * 2u) : fns.size();
        for (std::size_t i = 0u; i < scan_limit; ++i) {
            const auto& fn = fns[i];
            const std::string_view disp = fn.display_name(sources.demangle_symbols);
            std::optional<int> best = filter.empty()
                                          ? std::optional<int>(30)
                                          : fuzzy_match_score(filter, disp, nullptr);
            if (!filter.empty() && !fn.raw_name.empty() && fn.raw_name != disp) {
                if (const auto raw_sc = fuzzy_match_score(filter, fn.raw_name, nullptr)) {
                    best = best.has_value() ? std::max(*best, *raw_sc) : raw_sc;
                }
            }
            if (!filter.empty() && !fn.demangled_name.empty() && fn.demangled_name != disp) {
                if (const auto dem_sc = fuzzy_match_score(filter, fn.demangled_name, nullptr)) {
                    best = best.has_value() ? std::max(*best, *dem_sc) : dem_sc;
                }
            }
            if (!best.has_value()) {
                continue;
            }
            int boost = 0;
            std::uint64_t seq = 0u;
            if (has_mru) {
                std::array<char, 48> id_buf{};
                const auto r = std::format_to_n(
                    id_buf.data(), id_buf.size(), "fn:0x{:X}:{}", fn.virtual_address, i);
                const std::string_view id_sv(
                    id_buf.data(),
                    std::min<std::size_t>(static_cast<std::size_t>(r.size), id_buf.size()));
                boost = mru_boost_for(id_sv);
                seq = mru_sequence_for(id_sv);
            }
            collector.push(CandidateHit{
                .kind = CandidateKind::Function,
                .index = i,
                .address_key = fn.virtual_address,
                .score = *best + 25 + boost,
                .mru_seq = seq,
            });
        }
    }

    if (include_symbols && sources.symbols != nullptr) {
        const auto& syms = sources.symbols->records();
        const std::size_t scan_limit =
            filter.empty() ? std::min<std::size_t>(syms.size(), max_results * 2u) : syms.size();
        for (std::size_t i = 0u; i < scan_limit; ++i) {
            const auto& sym = syms[i];
            const std::string_view disp = sym.display_name(sources.demangle_symbols);
            std::optional<int> best = filter.empty()
                                          ? std::optional<int>(20)
                                          : fuzzy_match_score(filter, disp, nullptr);
            if (!filter.empty() && !sym.raw_name.empty() && sym.raw_name != disp) {
                if (const auto raw_sc = fuzzy_match_score(filter, sym.raw_name, nullptr)) {
                    best = best.has_value() ? std::max(*best, *raw_sc) : raw_sc;
                }
            }
            if (!filter.empty() && !sym.demangled_name.empty() && sym.demangled_name != disp) {
                if (const auto dem_sc = fuzzy_match_score(filter, sym.demangled_name, nullptr)) {
                    best = best.has_value() ? std::max(*best, *dem_sc) : dem_sc;
                }
            }
            if (!best.has_value()) {
                continue;
            }
            // Skip duplicate symbol entries already represented identically in FunctionIndex.
            if (sources.functions != nullptr && sym.virtual_address.has_value()) {
                const auto* fn = sources.functions->find_exact(*sym.virtual_address);
                if (fn != nullptr &&
                    (fn->name == sym.name || fn->raw_name == sym.raw_name)) {
                    continue;
                }
            }

            int boost = 0;
            std::uint64_t seq = 0u;
            if (has_mru) {
                std::array<char, 48> id_buf{};
                const auto r = std::format_to_n(
                    id_buf.data(),
                    id_buf.size(),
                    "sym:0x{:X}:{}",
                    sym.virtual_address.value_or(sym.file_offset.value_or(0u)),
                    i);
                const std::string_view id_sv(
                    id_buf.data(),
                    std::min<std::size_t>(static_cast<std::size_t>(r.size), id_buf.size()));
                boost = mru_boost_for(id_sv);
                seq = mru_sequence_for(id_sv);
            }
            collector.push(CandidateHit{
                .kind = CandidateKind::Symbol,
                .index = i,
                .address_key = sym.virtual_address.value_or(0u),
                .score = *best + 20 + boost,
                .mru_seq = seq,
            });
        }
    }

    // 4. Strings (`#`)
    if (include_strings && sources.strings != nullptr) {
        const auto& strs = sources.strings->entries();
        const std::size_t scan_limit =
            filter.empty() ? std::min<std::size_t>(strs.size(), max_results) : strs.size();
        for (std::size_t i = 0u; i < scan_limit; ++i) {
            const auto& st = strs[i];
            std::optional<int> best = filter.empty()
                                          ? std::optional<int>(10)
                                          : fuzzy_match_score(filter, st.preview, nullptr);
            if (!best.has_value() && mode == PalettePrefixMode::Strings && !filter.empty()) {
                best = fuzzy_match_score(filter, to_string(st.encoding), nullptr);
                if (!best.has_value()) {
                    std::array<char, 32> addr_buf{};
                    const std::uint64_t a =
                        (st.virtual_address != 0u) ? st.virtual_address : st.file_offset.value_or(0u);
                    const auto r = std::format_to_n(addr_buf.data(), addr_buf.size(), "0x{:X}", a);
                    const std::string_view asv(
                        addr_buf.data(),
                        std::min<std::size_t>(static_cast<std::size_t>(r.size), addr_buf.size()));
                    best = fuzzy_match_score(filter, asv, nullptr);
                }
            }
            if (!best.has_value()) {
                continue;
            }
            collector.push(CandidateHit{
                .kind = CandidateKind::String,
                .index = i,
                .address_key = (st.virtual_address != 0u) ? st.virtual_address : st.file_offset.value_or(0u),
                .score = *best + 10,
            });
        }
    }

    // 5. Structures & Types (`struct:` / `type:`)
    const std::span<const CatalogTypeEntry> cat_entries =
        (sources.structure_catalog != nullptr)
            ? sources.structure_catalog->entries()
            : std::span<const CatalogTypeEntry>(builtin_structure_catalog());

    const auto has_catalog_type = [cat_entries](std::string_view name) noexcept {
        for (const auto& entry : cat_entries) {
            if (iequals_ascii(entry.record.name, name)) {
                return true;
            }
        }
        return false;
    };

    if (include_types) {
        for (std::size_t i = 0u; i < cat_entries.size(); ++i) {
            const auto& entry = cat_entries[i];
            const auto sc = score_with_keywords(entry.record.name, to_string(entry.origin));
            if (!sc.has_value()) {
                continue;
            }
            int boost = 0;
            std::uint64_t seq = 0u;
            if (has_mru) {
                std::array<char, 96> id_buf{};
                const auto r = std::format_to_n(
                    id_buf.data(), id_buf.size(), "type:{}", entry.record.name);
                const std::string_view id_sv(
                    id_buf.data(),
                    std::min<std::size_t>(static_cast<std::size_t>(r.size), id_buf.size()));
                boost = mru_boost_for(id_sv);
                seq = mru_sequence_for(id_sv);
            }
            collector.push(CandidateHit{
                .kind = CandidateKind::CatalogType,
                .index = i,
                .score = *sc + 22 + boost,
                .mru_seq = seq,
            });
        }

        if (sources.structure_catalog == nullptr) {
            const auto has_custom_type = [&sources](std::string_view name) noexcept {
                for (const auto& ct : sources.custom_types) {
                    if (iequals_ascii(ct.name, name)) {
                        return true;
                    }
                }
                return false;
            };

            for (std::size_t i = 0u; i < sources.custom_types.size(); ++i) {
                const auto& ct = sources.custom_types[i];
                if (ct.name.empty()) {
                    continue;
                }
                std::optional<int> sc = filter.empty()
                    ? std::optional<int>(30)
                    : score_with_keywords(ct.name, "Custom C");
                if (!sc.has_value() && !filter.empty()) {
                    for (const auto& alias : ct.aliases) {
                        if (const auto asc = fuzzy_match_score(filter, alias, nullptr)) {
                            sc = asc;
                            break;
                        }
                    }
                }
                if (!sc.has_value()) {
                    continue;
                }
                int boost = 0;
                std::uint64_t seq = 0u;
                if (has_mru) {
                    std::array<char, 96> id_buf{};
                    const auto r = std::format_to_n(
                        id_buf.data(), id_buf.size(), "type:{}", ct.name);
                    const std::string_view id_sv(
                        id_buf.data(),
                        std::min<std::size_t>(static_cast<std::size_t>(r.size), id_buf.size()));
                    boost = mru_boost_for(id_sv);
                    seq = mru_sequence_for(id_sv);
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::CustomCType,
                    .index = i,
                    .score = *sc + 32 + boost,
                    .mru_seq = seq,
                });
            }
            for (std::size_t i = 0u; i < sources.debug_types.size(); ++i) {
                const auto& dt = sources.debug_types[i];
                if (dt.name.empty() || has_catalog_type(dt.name) || has_custom_type(dt.name)) {
                    continue;
                }
                const auto sc = filter.empty()
                                    ? std::optional<int>(25)
                                    : fuzzy_match_score(filter, dt.name, nullptr);
                if (!sc.has_value()) {
                    continue;
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::PrimaryDebugType,
                    .index = i,
                    .score = *sc + 28,
                });
            }
            for (std::size_t i = 0u; i < sources.secondary_types.size(); ++i) {
                const auto& dt = sources.secondary_types[i];
                if (dt.name.empty() || has_catalog_type(dt.name) || has_custom_type(dt.name)) {
                    continue;
                }
                const auto sc = filter.empty()
                                    ? std::optional<int>(20)
                                    : fuzzy_match_score(filter, dt.name, nullptr);
                if (!sc.has_value()) {
                    continue;
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::SecondaryDebugType,
                    .index = i,
                    .score = *sc + 24,
                });
            }
        }
    }

    // 6. Bookmarks & Security Audit Findings / Rules (`?` / `*`)
    if (include_bookmarks_rules) {
        for (std::size_t i = 0u; i < sources.bookmarks.size(); ++i) {
            const auto& bm = sources.bookmarks[i];
            const auto sc = score_with_keywords(bm.label, bm.note);
            std::optional<int> best = sc;
            if (!best.has_value() && !bm.category.empty()) {
                best = fuzzy_match_score(filter, bm.category, nullptr);
            }
            if (!best.has_value()) {
                continue;
            }
            collector.push(CandidateHit{
                .kind = CandidateKind::Bookmark,
                .index = i,
                .address_key = bm.address,
                .score = *best + 32,
            });
        }

        if (sources.security_audit != nullptr) {
            const auto& findings = sources.security_audit->findings;
            for (std::size_t i = 0u; i < findings.size(); ++i) {
                const auto& f = findings[i];
                auto best = score_with_keywords(f.rule_id, f.rule_name);
                if (!best.has_value() && !filter.empty()) {
                    if (const auto desc_sc = score_with_keywords(f.summary, f.subject)) {
                        best = std::max(50, *desc_sc - 500);
                    }
                }
                if (!best.has_value()) {
                    continue;
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::SecurityFinding,
                    .index = i,
                    .score = *best + 30,
                });
            }
        }

        if (sources.include_rule_catalog_fallback) {
            const auto rules = peelf::security_rule_catalog();
            for (std::size_t i = 0u; i < rules.size(); ++i) {
                const auto& rule = rules[i];
                // Skip catalog fallback if an active finding already covers this rule_id.
                bool covered = false;
                if (sources.security_audit != nullptr) {
                    for (const auto& f : sources.security_audit->findings) {
                        if (f.rule_id == rule.id) {
                            covered = true;
                            break;
                        }
                    }
                }
                if (covered) {
                    continue;
                }
                auto best = score_with_keywords(rule.id, rule.name);
                if (!best.has_value() && !filter.empty()) {
                    if (const auto desc_sc = fuzzy_match_score(filter, rule.short_description, nullptr)) {
                        best = std::max(40, *desc_sc - 600);
                    }
                }
                if (!best.has_value()) {
                    continue;
                }
                collector.push(CandidateHit{
                    .kind = CandidateKind::SecurityCatalogRule,
                    .index = i,
                    .score = *best + 18,
                });
            }
        }
    }

    // 7. Materialize only the top bounded hits into rich PaletteItems + highlight spans.
    const auto winners = collector.take_sorted();
    const auto panels = all_workspace_panels();
    const auto rule_catalog = peelf::security_rule_catalog();

    for (const auto& hit : winners) {
        if (out.items.size() >= max_results) {
            break;
        }

        PaletteItem item{};
        item.score = hit.score;

        switch (hit.kind) {
            case CandidateKind::Command: {
                const auto& spec = kBuiltinCommands[hit.index];
                item.id = std::string(spec.item_id);
                item.category = PaletteCategory::Command;
                item.title = std::string(spec.title);
                item.subtitle = std::string(spec.subtitle);
                item.right_badge = std::string(spec.shortcut);
                item.enabled = !spec.requires_file || sources.has_file;
                if (spec.id == PaletteCommandId::ToggleDemangleSymbols) {
                    item.subtitle = sources.demangle_symbols
                                        ? "Currently ON — switch to raw mangled symbol names"
                                        : "Currently OFF — switch to demangled C++/Rust names";
                } else if (spec.id == PaletteCommandId::SwitchFlowGraphGalaxy) {
                    item.subtitle = sources.flow_galaxy_enabled
                                        ? "Currently GPU Call Galaxy — switch to Flow Graph"
                                        : "Currently Flow Graph — switch to GPU Call Galaxy";
                }
                item.primary_action = PaletteAction{
                    .kind = PaletteActionKind::RunCommand,
                    .command_id = spec.id,
                };
                break;
            }
            case CandidateKind::Preset: {
                const WorkspacePreset preset = kAllWorkspacePresets[hit.index];
                item.id = std::format("preset:{}", workspace_preset_id(preset));
                item.category = PaletteCategory::Preset;
                item.title = std::string(workspace_preset_display_name(preset));
                item.subtitle = (preset == sources.active_preset)
                                    ? "Workspace Preset (Active)"
                                    : "Switch Workspace Layout Preset";
                item.right_badge = (preset == sources.active_preset) ? "Active" : "Preset";
                item.primary_action = PaletteAction{
                    .kind = PaletteActionKind::ApplyWorkspacePreset,
                    .preset = preset,
                };
                break;
            }
            case CandidateKind::Panel: {
                const WorkspacePanelId panel = panels[hit.index];
                const auto panel_idx = static_cast<std::size_t>(panel);
                const bool visible =
                    sources.has_panel_visibility && panel_idx < sources.panel_visibility.size() &&
                    sources.panel_visibility[panel_idx];
                item.id = std::string(panel_id_slug(panel));
                item.category = PaletteCategory::Panel;
                item.title = std::string(workspace_panel_window_name(panel));
                item.subtitle = visible
                                    ? "Workspace Panel (Visible — Enter: Focus · Shift+Enter: Hide)"
                                    : "Workspace Panel (Hidden — Enter: Show & Focus)";
                item.right_badge = visible ? "Visible" : "Panel";
                item.primary_action = PaletteAction{
                    .kind = PaletteActionKind::FocusPanel,
                    .panel_id = panel,
                };
                item.secondary_hex_action = PaletteAction{
                    .kind = PaletteActionKind::TogglePanel,
                    .panel_id = panel,
                };
                break;
            }
            case CandidateKind::Annotation: {
                if (sources.annotations == nullptr) {
                    continue;
                }
                const auto* note = sources.annotations->find(hit.address_key);
                if (note == nullptr) {
                    continue;
                }
                item.id = std::format("annot:0x{:X}", hit.address_key);
                item.category = PaletteCategory::Symbol;
                item.title = note->name;
                item.subtitle = note->comment.empty()
                                    ? "User Annotation Label"
                                    : std::format("User Label — {}", note->comment);
                item.right_badge = format_va_badge(hit.address_key, image_base);
                item.primary_action = make_va_or_offset_action(
                    hit.address_key, std::nullopt, PreferredView::Disassembly);
                item.secondary_hex_action = make_va_or_offset_action(
                    hit.address_key, std::nullopt, PreferredView::Hex);
                item.tertiary_decompile_action = make_va_or_offset_action(
                    hit.address_key, std::nullopt, PreferredView::Disassembly, 0u, true);
                break;
            }
            case CandidateKind::Function: {
                const auto& fn = sources.functions->entries()[hit.index];
                item.id = std::format("fn:0x{:X}:{}", fn.virtual_address, hit.index);
                item.category = PaletteCategory::Function;
                item.title = std::string(fn.display_name(sources.demangle_symbols));
                item.subtitle = std::string(to_string(fn.origin));
                if (!fn.section_name.empty()) {
                    item.subtitle += std::format(" · {}", fn.section_name);
                }
                if (!fn.raw_name.empty() && fn.raw_name != item.title) {
                    item.subtitle += std::format(" · {}", fn.raw_name);
                }
                item.right_badge = format_va_badge(fn.virtual_address, image_base);
                const auto fn_hl = static_cast<std::size_t>(
                    std::min<std::uint64_t>(fn.size, std::numeric_limits<std::size_t>::max()));
                item.primary_action = make_va_or_offset_action(
                    fn.virtual_address, fn.file_offset, PreferredView::Disassembly, fn_hl);
                item.secondary_hex_action = make_va_or_offset_action(
                    fn.virtual_address, fn.file_offset, PreferredView::Hex, fn_hl);
                item.tertiary_decompile_action = make_va_or_offset_action(
                    fn.virtual_address, fn.file_offset, PreferredView::Disassembly, fn_hl, true);
                break;
            }
            case CandidateKind::Symbol: {
                const auto& sym = sources.symbols->records()[hit.index];
                const std::uint64_t key =
                    sym.virtual_address.value_or(sym.file_offset.value_or(0u));
                item.id = std::format("sym:0x{:X}:{}", key, hit.index);
                item.category = PaletteCategory::Symbol;
                item.title = std::string(sym.display_name(sources.demangle_symbols));
                item.subtitle = std::string(symbol_source_label(sym.source));
                if (!sym.library.empty()) {
                    item.subtitle += std::format(" · {}", sym.library);
                }
                if (!sym.raw_name.empty() && sym.raw_name != item.title) {
                    item.subtitle += std::format(" · {}", sym.raw_name);
                }
                item.right_badge = sym.virtual_address.has_value()
                                       ? format_va_badge(*sym.virtual_address, image_base)
                                       : std::format("off 0x{:X}", sym.file_offset.value_or(0u));
                const auto sym_hl = static_cast<std::size_t>(
                    std::min<std::uint64_t>(sym.size, std::numeric_limits<std::size_t>::max()));
                item.primary_action = make_va_or_offset_action(
                    sym.virtual_address, sym.file_offset, PreferredView::Disassembly, sym_hl);
                item.secondary_hex_action = make_va_or_offset_action(
                    sym.virtual_address, sym.file_offset, PreferredView::Hex, sym_hl);
                if (sym.virtual_address.has_value()) {
                    item.tertiary_decompile_action = make_va_or_offset_action(
                        sym.virtual_address, sym.file_offset, PreferredView::Disassembly, sym_hl, true);
                }
                break;
            }
            case CandidateKind::String: {
                const auto& st = sources.strings->entries()[hit.index];
                const std::optional<std::uint64_t> st_va =
                    (st.virtual_address != 0u) ? std::optional<std::uint64_t>(st.virtual_address)
                                               : std::nullopt;
                item.id = std::format("str:0x{:X}:{}", st.file_offset.value_or(st.virtual_address), hit.index);
                item.category = PaletteCategory::String;
                item.title = st.preview;
                item.subtitle = std::format("{}", to_string(st.encoding));
                if (!st.section_or_region_name.empty()) {
                    item.subtitle += std::format(" · {}", st.section_or_region_name);
                }
                if (st.xref_count > 0u) {
                    item.subtitle += std::format(" · {} xrefs", st.xref_count);
                }
                item.right_badge = st_va.has_value()
                                       ? format_va_badge(*st_va, image_base)
                                       : std::format("off 0x{:X}", st.file_offset.value_or(0u));
                item.primary_action = make_va_or_offset_action(
                    st_va,
                    st.file_offset,
                    PreferredView::Hex,
                    st.byte_length);
                item.secondary_hex_action = make_va_or_offset_action(
                    st_va, st.file_offset, PreferredView::Hex, st.byte_length);
                break;
            }
            case CandidateKind::CatalogType:
            case CandidateKind::CustomCType:
            case CandidateKind::PrimaryDebugType:
            case CandidateKind::SecondaryDebugType: {
                const DataTypeRecord* rec = nullptr;
                std::string_view origin_sv = "Debug / User Type";
                if (hit.kind == CandidateKind::CatalogType) {
                    rec = &cat_entries[hit.index].record;
                    origin_sv = to_string(cat_entries[hit.index].origin);
                } else if (hit.kind == CandidateKind::CustomCType) {
                    rec = &sources.custom_types[hit.index];
                    origin_sv = "Custom C";
                } else if (hit.kind == CandidateKind::PrimaryDebugType) {
                    rec = &sources.debug_types[hit.index];
                    origin_sv = "PDB / DWARF Debug Type";
                } else {
                    rec = &sources.secondary_types[hit.index];
                    origin_sv = "Decompiler Type";
                }
                item.id = std::format("type:{}", rec->name);
                item.category = PaletteCategory::Type;
                item.title = rec->name;
                if (rec->is_enum) {
                    item.subtitle = std::format(
                        "enum · {} bytes · {} constants · {}",
                        rec->size,
                        rec->enum_constants.size(),
                        origin_sv);
                } else {
                    item.subtitle = std::format(
                        "{} · {} bytes · {} fields · {}",
                        rec->is_union ? "union" : "struct",
                        rec->size,
                        rec->members.size(),
                        origin_sv);
                }
                item.right_badge = std::format("{} B", rec->size);
                item.primary_action = PaletteAction{
                    .kind = PaletteActionKind::OpenStructureView,
                    .type_name = rec->name,
                };
                break;
            }
            case CandidateKind::Bookmark: {
                const auto& bm = sources.bookmarks[hit.index];
                item.id = std::format(
                    "bm:{}:0x{:X}", bm.is_file_offset ? "off" : "va", bm.address);
                item.category = PaletteCategory::Bookmark;
                item.title = bm.label.empty()
                                 ? std::format("Bookmark @ 0x{:X}", bm.address)
                                 : bm.label;
                item.subtitle = bm.category.empty() ? "Bookmark" : bm.category;
                if (!bm.note.empty()) {
                    item.subtitle += std::format(" — {}", bm.note);
                }
                item.right_badge = bm.is_file_offset
                                       ? std::format("off 0x{:X}", bm.address)
                                       : format_va_badge(bm.address, image_base);
                const std::optional<std::uint64_t> va =
                    bm.is_file_offset ? std::nullopt : std::optional<std::uint64_t>(bm.address);
                const std::optional<std::uint64_t> off =
                    bm.is_file_offset ? std::optional<std::uint64_t>(bm.address) : std::nullopt;
                item.primary_action = make_va_or_offset_action(
                    va, off, bm.is_file_offset ? PreferredView::Hex : PreferredView::Disassembly);
                item.secondary_hex_action =
                    make_va_or_offset_action(va, off, PreferredView::Hex);
                if (va.has_value()) {
                    item.tertiary_decompile_action = make_va_or_offset_action(
                        va, off, PreferredView::Disassembly, 0u, true);
                }
                break;
            }
            case CandidateKind::SecurityFinding: {
                const auto& f = sources.security_audit->findings[hit.index];
                item.id = std::format("rule:{}:{}", f.rule_id, hit.index);
                item.category = PaletteCategory::Rule;
                item.title = std::format("{}: {}", f.rule_id, f.rule_name);
                item.subtitle = std::format(
                    "[{}] {}",
                    peelf::to_string(f.severity),
                    f.summary.empty() ? f.subject : f.summary);
                if (f.virtual_address.has_value()) {
                    item.right_badge = format_va_badge(*f.virtual_address, image_base);
                } else if (f.file_offset.has_value()) {
                    item.right_badge = std::format("off 0x{:X}", *f.file_offset);
                } else {
                    item.right_badge = std::string(peelf::to_string(f.severity));
                }
                if (f.virtual_address.has_value() || f.file_offset.has_value()) {
                    item.primary_action = make_va_or_offset_action(
                        f.virtual_address,
                        f.file_offset,
                        f.virtual_address.has_value() ? PreferredView::Disassembly
                                                      : PreferredView::Hex);
                    item.secondary_hex_action = make_va_or_offset_action(
                        f.virtual_address, f.file_offset, PreferredView::Hex);
                } else {
                    item.primary_action = PaletteAction{
                        .kind = PaletteActionKind::FocusPanel,
                        .panel_id = WorkspacePanelId::FileInfo,
                    };
                }
                break;
            }
            case CandidateKind::SecurityCatalogRule: {
                const auto& rule = rule_catalog[hit.index];
                item.id = std::format("rule_cat:{}", rule.id);
                item.category = PaletteCategory::Rule;
                item.title = std::format("{}: {}", rule.id, rule.name);
                item.subtitle = std::format(
                    "[{}] {}",
                    peelf::to_string(rule.domain),
                    rule.short_description);
                item.right_badge = std::string(peelf::to_string(rule.domain));
                item.primary_action = PaletteAction{
                    .kind = PaletteActionKind::FocusPanel,
                    .panel_id = WorkspacePanelId::FileInfo,
                };
                break;
            }
        }

        if (!filter.empty()) {
            (void)fuzzy_match_score(filter, item.title, &item.title_match);
        }
        out.items.push_back(std::move(item));
    }

    return out;
}

} // namespace viewer
