#include "panel_helpers.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <limits>

namespace viewer {
namespace {

[[nodiscard]] std::string_view trim_ascii_whitespace(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1u);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1u);
    }
    return sv;
}

[[nodiscard]] std::optional<std::uint64_t> parse_strict_hex_u64(
    std::string_view hex_digits) noexcept {
    if (hex_digits.empty() || hex_digits.front() == '+' || hex_digits.front() == '-') {
        return std::nullopt;
    }
    std::uint64_t value = 0u;
    const char* begin = hex_digits.data();
    const char* end = begin + hex_digits.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value, 16);
    if (ec == std::errc{} && ptr == end) {
        return value;
    }
    return std::nullopt;
}

[[nodiscard]] bool contains_ascii_icase(std::string_view haystack,
                                        std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    const auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) noexcept {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

constexpr std::array<ScriptStarterTemplate, kScriptStarterTemplateCount>
    kBuiltinStarterTemplates{{
        ScriptStarterTemplate{
            .title = "Inspect Target & Sections",
            .summary = "Read-only summary of target profile, capabilities, and mapped sections.",
            .requires_mutations = false,
            .source =
                "-- Inspect Target & Sections (Read-Only)\n"
                "local info = peelf.target_info()\n"
                "peelf.log(string.format(\"Target: %s | %s | %d-bit | %s | entry=0x%x\",\n"
                "  info.format, info.arch, info.bitness, info.endianness, info.entry_point))\n"
                "local secs = peelf.sections()\n"
                "peelf.log(string.format(\"Sections (%d):\", #secs))\n"
                "for i, s in ipairs(secs) do\n"
                "  local perms = (s.readable and \"R\" or \"-\")\n"
                "             .. (s.writable and \"W\" or \"-\")\n"
                "             .. (s.executable and \"X\" or \"-\")\n"
                "  peelf.log(string.format(\"  [%2d] %-16s va=0x%x size=0x%x file_off=0x%x %s\",\n"
                "    i, s.name, s.virtual_address, s.virtual_size, s.file_offset, perms))\n"
                "end\n"
                "local caps = peelf.capabilities()\n"
                "if caps.StaticPatching then\n"
                "  peelf.log(string.format(\"StaticPatching: %s (can_execute=%s)\",\n"
                "    caps.StaticPatching.state, tostring(caps.StaticPatching.can_execute)))\n"
                "end\n",
        },
        ScriptStarterTemplate{
            .title = "Section Entropy & RWX Scan",
            .summary =
                "Computes Shannon entropy (bits/byte) over sampled section slices, flags W+X, and runs security audit.",
            .requires_mutations = false,
            .source =
                "-- Section Entropy & RWX Scan (Read-Only)\n"
                "local function shannon_entropy(bytes)\n"
                "  local n = #bytes\n"
                "  if n == 0 then return 0.0 end\n"
                "  local freq = {}\n"
                "  for idx = 1, n do\n"
                "    local b = string.byte(bytes, idx)\n"
                "    freq[b] = (freq[b] or 0) + 1\n"
                "  end\n"
                "  local ent = 0.0\n"
                "  for _, count in pairs(freq) do\n"
                "    local p = count / n\n"
                "    ent = ent - (p * math.log(p, 2))\n"
                "  end\n"
                "  return ent\n"
                "end\n"
                "\n"
                "local secs = peelf.sections()\n"
                "local rwx_count = 0\n"
                "local high_entropy_count = 0\n"
                "for _, s in ipairs(secs) do\n"
                "  local is_rwx = s.writable and s.executable\n"
                "  if is_rwx then rwx_count = rwx_count + 1 end\n"
                "  local backed = s.file_size > 0 and s.file_size or 0\n"
                "  if s.virtual_size > 0 and backed > s.virtual_size then\n"
                "    backed = s.virtual_size\n"
                "  end\n"
                "  local sample_len = math.min(backed, 65536)\n"
                "  local ok, data = false, \"\"\n"
                "  if sample_len > 0 then\n"
                "    ok, data = pcall(peelf.read_bytes, s.virtual_address, sample_len)\n"
                "  end\n"
                "  if ok and #data > 0 then\n"
                "    local ent = shannon_entropy(data)\n"
                "    local hi = ent >= 7.2\n"
                "    if hi then high_entropy_count = high_entropy_count + 1 end\n"
                "    peelf.log(string.format(\n"
                "      \"  %-16s va=0x%x sample=%dB entropy=%.3f bits/B%s%s\",\n"
                "      s.name, s.virtual_address, #data, ent,\n"
                "      hi and \" [HIGH-ENTROPY]\" or \"\",\n"
                "      is_rwx and \" [W+X]\" or \"\"))\n"
                "  else\n"
                "    peelf.log(string.format(\n"
                "      \"  %-16s va=0x%x size=0x%x [unbacked/unreadable]%s\",\n"
                "      s.name, s.virtual_address, s.virtual_size,\n"
                "      is_rwx and \" [W+X]\" or \"\"))\n"
                "  end\n"
                "end\n"
                "local audit = peelf.security_audit()\n"
                "peelf.log(string.format(\n"
                "  \"Security Audit (%s): %d error(s), %d warning(s), %d note(s), %d pass(es)\",\n"
                "  audit.format, audit.error_count, audit.warning_count, audit.note_count, audit.pass_count))\n"
                "for _, f in ipairs(audit.findings) do\n"
                "  if f.severity == \"Error\" or f.severity == \"Warning\" then\n"
                "    peelf.log(string.format(\"  [%s] %s (%s): %s\",\n"
                "      f.severity, f.rule_id, f.subject, f.summary))\n"
                "  end\n"
                "end\n"
                "peelf.log(string.format(\n"
                "  \"Summary: %d high-entropy section(s), %d W+X section(s)\",\n"
                "  high_entropy_count, rwx_count))\n",
        },
        ScriptStarterTemplate{
            .title = "Auto-Label Entry & Exports (Dry-Run)",
            .summary =
                "Stages entry/export labels & bookmarks without calling peelf.commit() (dry-run).",
            .requires_mutations = true,
            .source =
                "-- Auto-Label Entry & Exports (Dry-Run)\n"
                "-- Enable 'Allow Target Mutations' above. Because peelf.commit() is omitted,\n"
                "-- staged labels/comments/bookmarks appear in the table below and roll back cleanly.\n"
                "local info = peelf.target_info()\n"
                "assert(info.allow_mutations, \"Enable 'Allow Target Mutations' to stage dry-run annotations\")\n"
                "if info.entry_point ~= 0 then\n"
                "  peelf.set_label(info.entry_point, \"script_entry_point\")\n"
                "  peelf.set_comment(info.entry_point, \"Auto-labeled entry point (dry-run)\")\n"
                "  peelf.add_bookmark(info.entry_point, \"Entry point candidate\")\n"
                "  peelf.log(string.format(\"Staged entry label at 0x%x\", info.entry_point))\n"
                "end\n"
                "local exps = peelf.exports()\n"
                "local limit = math.min(#exps, 32)\n"
                "local count = 0\n"
                "for i = 1, limit do\n"
                "  local e = exps[i]\n"
                "  if e.virtual_address ~= 0 and #e.name > 0 then\n"
                "    peelf.set_label(e.virtual_address, \"exp_\" .. e.name)\n"
                "    peelf.set_comment(e.virtual_address, \"Exported symbol: \" .. e.name)\n"
                "    count = count + 1\n"
                "  end\n"
                "end\n"
                "peelf.log(string.format(\"Dry-run staged %d export annotation(s) (rolled back on exit).\", count))\n",
        },
        ScriptStarterTemplate{
            .title = "Stage NOP Patch + Commit",
            .summary =
                "Disassembles entry point, stages architecture NOP bytes + bookmark, and commits.",
            .requires_mutations = true,
            .source =
                "-- Stage NOP Patch + Commit (Transactional)\n"
                "-- Requires 'Allow Target Mutations' on an editable static binary.\n"
                "local info = peelf.target_info()\n"
                "assert(info.allow_mutations, \"Enable 'Allow Target Mutations' to stage and commit patches\")\n"
                "assert(info.entry_point ~= 0, \"Binary has no non-zero entry_point\")\n"
                "local insns = peelf.disassemble(info.entry_point, 1)\n"
                "assert(#insns >= 1, \"Unable to disassemble first instruction at entry_point\")\n"
                "local first = insns[1]\n"
                "peelf.log(string.format(\"Entry 0x%x: %s (%d byte(s))\", first.address, first.text, first.size))\n"
                "local nop_bytes = {}\n"
                "if info.arch == \"ARM64\" and first.size == 4 then\n"
                "  if info.endianness == \"Big\" then\n"
                "    nop_bytes = { 0xD5, 0x03, 0x20, 0x1F }\n"
                "  else\n"
                "    nop_bytes = { 0x1F, 0x20, 0x03, 0xD5 }\n"
                "  end\n"
                "elseif info.arch == \"x86\" or info.arch == \"x86-64\" then\n"
                "  for i = 1, first.size do nop_bytes[i] = 0x90 end\n"
                "else\n"
                "  error(\"Unsupported architecture for starter NOP template: \" .. info.arch)\n"
                "end\n"
                "peelf.stage_patch(first.address, nop_bytes)\n"
                "peelf.set_comment(first.address, \"NOP-patched via Lua scripting console\")\n"
                "peelf.add_bookmark(first.address, \"Scripted NOP patch\")\n"
                "peelf.commit(\"NOP entry instruction\")\n"
                "peelf.log(\"Committed transactional NOP patch + annotations.\")\n",
        },
    }};

} // namespace

peelf::Result<std::vector<std::string>> tokenize_launch_arguments(std::string_view raw) {
    std::vector<std::string> args{};
    std::string cur{};
    bool in_token = false;
    bool in_double_quote = false;
    bool in_single_quote = false;

    for (std::size_t i = 0u; i < raw.size(); ++i) {
        const char ch = raw[i];
        if (in_double_quote) {
            if (ch == '"') {
                in_double_quote = false;
                continue;
            }
            if (ch == '\\' && (i + 1u) < raw.size()) {
                const char next = raw[i + 1u];
                if (next == '"' || next == '\\') {
                    cur.push_back(next);
                    ++i;
                    continue;
                }
            } else if (ch == '\\' && (i + 1u) == raw.size()) {
                // Trailing escape right before end of input leaves quote unmatched.
                break;
            }
            cur.push_back(ch);
            continue;
        }

        if (in_single_quote) {
            if (ch == '\'') {
                in_single_quote = false;
                continue;
            }
            cur.push_back(ch);
            continue;
        }

        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            if (in_token) {
                args.push_back(std::move(cur));
                cur.clear();
                in_token = false;
            }
            continue;
        }

        if (ch == '\\' && (i + 1u) < raw.size() &&
            (raw[i + 1u] == '"' || raw[i + 1u] == '\'')) {
            in_token = true;
            cur.push_back(raw[++i]);
            continue;
        }
        if (ch == '"') {
            in_double_quote = true;
            in_token = true;
            continue;
        }
        if (ch == '\'') {
            in_single_quote = true;
            in_token = true;
            continue;
        }

        in_token = true;
        cur.push_back(ch);
    }

    if (in_double_quote) {
        return peelf::make_error("Unmatched double quote (\") in launch arguments");
    }
    if (in_single_quote) {
        return peelf::make_error("Unmatched single quote (') in launch arguments");
    }

    if (in_token) {
        args.push_back(std::move(cur));
    }
    return args;
}

std::optional<std::uint64_t> resolve_breakpoint_target(std::string_view raw,
                                                       const SymbolIndex& symbols,
                                                       bool demangle) {
    const std::string_view expr = trim_ascii_whitespace(raw);
    if (expr.empty()) {
        return std::nullopt;
    }

    // 1. Explicit `0x` / `0X` prefix unambiguously selects hexadecimal parsing.
    if (expr.size() >= 2u && expr[0] == '0' && (expr[1] == 'x' || expr[1] == 'X')) {
        return parse_strict_hex_u64(expr.substr(2u));
    }

    const auto records = symbols.records();

    // 2. Exact symbol lookup BEFORE bare hex so valid hex-letter names
    //    (`fade`, `dead`, `cafe`, `babe`, `add`, `dec`) resolve to symbols first.
    for (const SymbolRecord& sym : records) {
        if (!sym.virtual_address.has_value()) {
            continue;
        }
        if (sym.name == expr || sym.display_name(demangle) == expr ||
            (!sym.raw_name.empty() && sym.raw_name == expr) ||
            (!sym.demangled_name.empty() && sym.demangled_name == expr)) {
            return *sym.virtual_address;
        }
    }

    // 3. Bare hexadecimal virtual address.
    if (const auto hex_va = parse_strict_hex_u64(expr); hex_va.has_value()) {
        return hex_va;
    }

    // 4. Case-insensitive substring symbol fallback.
    for (const SymbolRecord& sym : records) {
        if (!sym.virtual_address.has_value()) {
            continue;
        }
        if (contains_ascii_icase(sym.name, expr) ||
            contains_ascii_icase(sym.display_name(demangle), expr)) {
            return *sym.virtual_address;
        }
    }

    return std::nullopt;
}

std::span<const ScriptStarterTemplate> scripting_starter_templates() noexcept {
    return kBuiltinStarterTemplates;
}

int clamp_imgui_clipper_count(std::size_t count) noexcept {
    constexpr auto kMaxIntAsSize =
        static_cast<std::size_t>(std::numeric_limits<int>::max());
    return static_cast<int>(std::min(count, kMaxIntAsSize));
}

std::string sanitize_single_line_control_chars(std::string_view text) {
    std::string out{};
    out.reserve(text.size());
    for (const char ch : text) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch == '\r' || uch == '\n' || uch == '\t') {
            out.push_back(' ');
        } else if (uch < 0x20u || uch == 0x7Fu) {
            out.push_back('?');
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::filesystem::path utf8_to_filesystem_path(std::string_view utf8_text) {
    std::u8string u8{};
    u8.reserve(utf8_text.size());
    for (const char ch : utf8_text) {
        u8.push_back(static_cast<char8_t>(static_cast<unsigned char>(ch)));
    }
    return std::filesystem::path(std::u8string_view{u8});
}

} // namespace viewer
