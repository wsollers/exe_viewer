#include "panel_helpers.hpp"

#include <peelf/demangle.hpp>
#include <peelf/macho_image.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cmath>
#include <format>
#include <limits>
#include <unordered_map>
#include <utility>

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

namespace {

void add_prop(std::vector<DetailPropertyRow>& rows, std::string key, std::string value) {
    rows.push_back(DetailPropertyRow{
        .key = std::move(key),
        .value = sanitize_single_line_control_chars(value),
    });
}

[[nodiscard]] std::string format_rwx(bool r, bool w, bool x) {
    std::string out = "---";
    if (r) {
        out[0] = 'R';
    }
    if (w) {
        out[1] = 'W';
    }
    if (x) {
        out[2] = 'X';
    }
    return out;
}

[[nodiscard]] std::optional<double> compute_shannon_entropy_for_offset(
    const BinaryModel& model,
    const peelf::IBinaryImage* image,
    std::uint64_t file_offset,
    std::uint64_t raw_size) {
    if (raw_size == 0u) {
        return std::nullopt;
    }
    constexpr std::uint64_t kMaxEntropySampleBytes = 1024u * 1024u;
    const std::uint64_t sample_len = std::min<std::uint64_t>(raw_size, kMaxEntropySampleBytes);

    std::vector<std::uint8_t> data{};
    if (!model.is_live_process()) {
        if (auto eff = model.read_effective_bytes(file_offset, sample_len);
            eff.has_value() && !eff->empty()) {
            data = std::move(*eff);
        }
    }
    if (data.empty() && image != nullptr) {
        if (auto raw = image->read_bytes_at_offset(file_offset, static_cast<std::size_t>(sample_len));
            raw.has_value() && !raw->empty()) {
            data = std::move(*raw);
        }
    }
    if (data.empty()) {
        return std::nullopt;
    }

    std::array<std::size_t, 256u> counts{};
    for (const std::uint8_t b : data) {
        ++counts[b];
    }
    const double inv_total = 1.0 / static_cast<double>(data.size());
    double entropy = 0.0;
    for (const std::size_t c : counts) {
        if (c == 0u) {
            continue;
        }
        const double p = static_cast<double>(c) * inv_total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

[[nodiscard]] std::string format_specific_image_label(const peelf::IBinaryImage& img) {
    switch (img.format()) {
        case peelf::Format::PE:
            return img.is_64bit() ? "PE32+" : "PE32";
        case peelf::Format::ELF:
            return img.is_64bit() ? "ELF64" : "ELF32";
        case peelf::Format::MachO:
            return img.is_64bit() ? "Mach-O 64-bit" : "Mach-O 32-bit";
        case peelf::Format::Unknown:
            return "Unknown";
    }
    return "Unknown";
}

[[nodiscard]] std::string pe_subsystem_name(std::uint16_t subsystem) {
    switch (subsystem) {
        case 1u:  return "Native (0x0001)";
        case 2u:  return "Windows GUI (0x0002)";
        case 3u:  return "Windows CUI (0x0003)";
        case 5u:  return "OS/2 CUI (0x0005)";
        case 7u:  return "POSIX CUI (0x0007)";
        case 9u:  return "Windows CE GUI (0x0009)";
        case 10u: return "EFI Application (0x000A)";
        case 11u: return "EFI Boot Service Driver (0x000B)";
        case 12u: return "EFI Runtime Driver (0x000C)";
        case 13u: return "EFI ROM (0x000D)";
        case 14u: return "Xbox (0x000E)";
        case 16u: return "Windows Boot Application (0x0010)";
        default:  return std::format("0x{:04X}", subsystem);
    }
}

[[nodiscard]] std::string format_pe_dll_characteristics(std::uint16_t flags) {
    std::string decoded{};
    auto append_flag = [&](std::uint16_t mask, std::string_view name) {
        if ((flags & mask) != 0u) {
            if (!decoded.empty()) {
                decoded += " | ";
            }
            decoded.append(name);
        }
    };
    append_flag(0x0020u, "HIGH_ENTROPY_VA");
    append_flag(0x0040u, "DYNAMIC_BASE");
    append_flag(0x0080u, "FORCE_INTEGRITY");
    append_flag(0x0100u, "NX_COMPAT");
    append_flag(0x0200u, "NO_ISOLATION");
    append_flag(0x0400u, "NO_SEH");
    append_flag(0x0800u, "NO_BIND");
    append_flag(0x1000u, "APPCONTAINER");
    append_flag(0x4000u, "GUARD_CF");
    append_flag(0x8000u, "TERMINAL_SERVER_AWARE");
    if (decoded.empty()) {
        return std::format("0x{:04X}", flags);
    }
    return std::format("0x{:04X} ({})", flags, decoded);
}

[[nodiscard]] std::string elf_type_name(std::uint16_t e_type) {
    switch (e_type) {
        case 0u: return "ET_NONE (0x0000)";
        case 1u: return "ET_REL (0x0001)";
        case 2u: return "ET_EXEC (0x0002)";
        case 3u: return "ET_DYN (0x0003)";
        case 4u: return "ET_CORE (0x0004)";
        default: return std::format("0x{:04X}", e_type);
    }
}

[[nodiscard]] std::string elf_osabi_name(std::uint8_t os_abi) {
    switch (os_abi) {
        case 0u:  return "UNIX System V (0x00)";
        case 3u:  return "GNU/Linux (0x03)";
        case 6u:  return "Solaris (0x06)";
        case 9u:  return "FreeBSD (0x09)";
        case 12u: return "OpenBSD (0x0C)";
        case 64u: return "ARM EABI (0x40)";
        default:  return std::format("0x{:02X}", os_abi);
    }
}

[[nodiscard]] std::string elf_sht_name(std::uint32_t sh_type) {
    switch (sh_type) {
        case 0u:          return "SHT_NULL";
        case 1u:          return "SHT_PROGBITS";
        case 2u:          return "SHT_SYMTAB";
        case 3u:          return "SHT_STRTAB";
        case 4u:          return "SHT_RELA";
        case 5u:          return "SHT_HASH";
        case 6u:          return "SHT_DYNAMIC";
        case 7u:          return "SHT_NOTE";
        case 8u:          return "SHT_NOBITS";
        case 9u:          return "SHT_REL";
        case 11u:         return "SHT_DYNSYM";
        case 14u:         return "SHT_INIT_ARRAY";
        case 15u:         return "SHT_FINI_ARRAY";
        case 0x6FFFFFF6u: return "SHT_GNU_HASH";
        case 0x6FFFFFFFu: return "SHT_GNU_versym";
        case 0x6FFFFFFEu: return "SHT_GNU_verneed";
        default:          return std::format("0x{:X}", sh_type);
    }
}

[[nodiscard]] std::string elf_pt_name(std::uint32_t p_type) {
    switch (p_type) {
        case 0u:          return "PT_NULL";
        case 1u:          return "PT_LOAD";
        case 2u:          return "PT_DYNAMIC";
        case 3u:          return "PT_INTERP";
        case 4u:          return "PT_NOTE";
        case 6u:          return "PT_PHDR";
        case 7u:          return "PT_TLS";
        case 0x6474E550u: return "PT_GNU_EH_FRAME";
        case 0x6474E551u: return "PT_GNU_STACK";
        case 0x6474E552u: return "PT_GNU_RELRO";
        case 0x6474E553u: return "PT_GNU_PROPERTY";
        default:          return std::format("0x{:X}", p_type);
    }
}

[[nodiscard]] std::string elf_dynamic_tag_name(std::uint64_t tag) {
    switch (tag) {
        case 0u:          return "DT_NULL";
        case 1u:          return "DT_NEEDED";
        case 2u:          return "DT_PLTRELSZ";
        case 3u:          return "DT_PLTGOT";
        case 4u:          return "DT_HASH";
        case 5u:          return "DT_STRTAB";
        case 6u:          return "DT_SYMTAB";
        case 7u:          return "DT_RELA";
        case 10u:         return "DT_STRSZ";
        case 12u:         return "DT_INIT";
        case 13u:         return "DT_FINI";
        case 14u:         return "DT_SONAME";
        case 15u:         return "DT_RPATH";
        case 17u:         return "DT_REL";
        case 20u:         return "DT_PLTREL";
        case 21u:         return "DT_DEBUG";
        case 23u:         return "DT_JMPREL";
        case 24u:         return "DT_BIND_NOW";
        case 25u:         return "DT_INIT_ARRAY";
        case 26u:         return "DT_FINI_ARRAY";
        case 29u:         return "DT_RUNPATH";
        case 30u:         return "DT_FLAGS";
        case 0x6FFFFEF5u: return "DT_GNU_HASH";
        case 0x6FFFFFFBu: return "DT_FLAGS_1";
        default:          return std::format("0x{:X}", tag);
    }
}

[[nodiscard]] std::string macho_filetype_name(std::uint32_t file_type) {
    switch (file_type) {
        case peelf::macho::kMhObject:     return "MH_OBJECT (0x1)";
        case peelf::macho::kMhExecute:    return "MH_EXECUTE (0x2)";
        case peelf::macho::kMhCore:       return "MH_CORE (0x4)";
        case peelf::macho::kMhDylib:      return "MH_DYLIB (0x6)";
        case peelf::macho::kMhDylinker:   return "MH_DYLINKER (0x7)";
        case peelf::macho::kMhBundle:     return "MH_BUNDLE (0x8)";
        case peelf::macho::kMhDsym:       return "MH_DSYM (0xA)";
        case peelf::macho::kMhKextBundle: return "MH_KEXT_BUNDLE (0xB)";
        case peelf::macho::kMhFileset:    return "MH_FILESET (0xC)";
        default:                          return std::format("0x{:X}", file_type);
    }
}

[[nodiscard]] std::string format_macho_flags(std::uint32_t flags) {
    std::string decoded{};
    auto append_flag = [&](std::uint32_t mask, std::string_view name) {
        if ((flags & mask) != 0u) {
            if (!decoded.empty()) {
                decoded += " | ";
            }
            decoded.append(name);
        }
    };
    append_flag(peelf::macho::kMhNoUndefs, "NOUNDEFS");
    append_flag(peelf::macho::kMhDyldLink, "DYLDLINK");
    append_flag(peelf::macho::kMhTwoLevel, "TWOLEVEL");
    append_flag(peelf::macho::kMhPie, "PIE");
    append_flag(peelf::macho::kMhHasTlvDescriptors, "HAS_TLV_DESCRIPTORS");
    append_flag(peelf::macho::kMhAllowStackExecution, "ALLOW_STACK_EXECUTION");
    append_flag(peelf::macho::kMhNoHeapExecution, "NO_HEAP_EXECUTION");
    append_flag(peelf::macho::kMhAppExtensionSafe, "APP_EXTENSION_SAFE");
    if (decoded.empty()) {
        return std::format("0x{:08X}", flags);
    }
    return std::format("0x{:08X} ({})", flags, decoded);
}

[[nodiscard]] std::string pe_debug_type_name(std::uint32_t type) {
    switch (type) {
        case 2u:  return "CodeView (2)";
        case 4u:  return "Misc (4)";
        case 9u:  return "Borland (9)";
        case 12u: return "VC Feature (12)";
        case 13u: return "POGO (13)";
        case 14u: return "ILTCG (14)";
        case 16u: return "Repro / Deterministic (16)";
        case 20u: return "Extended DLL Characteristics (20)";
        default:  return std::format("Type {}", type);
    }
}

[[nodiscard]] std::string symbol_source_name(SymbolSource src) {
    switch (src) {
        case SymbolSource::EntryPoint:  return "Entry Point";
        case SymbolSource::ImageSymbol: return "Image Symbol Table";
        case SymbolSource::Import:      return "Import Table";
        case SymbolSource::Export:      return "Export Table";
        case SymbolSource::DebugSymbol: return "Debug Symbols (PDB/DWARF)";
    }
    return "Image Symbol Table";
}

[[nodiscard]] std::string elf_symbol_binding_name(std::uint8_t binding) {
    switch (binding) {
        case 0u:  return "STB_LOCAL";
        case 1u:  return "STB_GLOBAL";
        case 2u:  return "STB_WEAK";
        case 10u: return "STB_GNU_UNIQUE";
        default:  return std::format("{}", binding);
    }
}

[[nodiscard]] std::string elf_symbol_type_name(std::uint8_t type) {
    switch (type) {
        case 0u:  return "STT_NOTYPE";
        case 1u:  return "STT_OBJECT";
        case 2u:  return "STT_FUNC";
        case 3u:  return "STT_SECTION";
        case 4u:  return "STT_FILE";
        case 6u:  return "STT_TLS";
        case 10u: return "STT_GNU_IFUNC";
        default:  return std::format("{}", type);
    }
}

void append_image_or_header_properties(
    std::vector<DetailPropertyRow>& rows,
    const peelf::IBinaryImage& img,
    const BinaryModel& model) {
    add_prop(rows, "Format", format_specific_image_label(img));
    add_prop(rows, "Image Kind", std::string(peelf::to_string(img.kind())));
    add_prop(rows, "Architecture", std::string(peelf::to_string(img.architecture())));
    add_prop(rows, "Endianness", std::string(peelf::to_string(img.endianness())));
    add_prop(rows, "Image Base", std::format("0x{:X}", img.image_base()));
    add_prop(rows, "Entry VA", std::format("0x{:X}", img.entry_point()));
    add_prop(rows, "Sections", std::format("{}", img.sections().size()));
    add_prop(rows, "Segments", std::format("{}", img.segments().size()));
    add_prop(rows, "Imports", std::format("{}", img.imports().size()));
    add_prop(rows, "Exports", std::format("{}", img.exports().size()));
    add_prop(rows, "Symbols", std::format("{} (indexed: {})",
                                          img.symbols().size(),
                                          model.symbol_index().size()));
    if (!model.is_live_process()) {
        const std::string& sha = model.content_sha256();
        if (!sha.empty()) {
            add_prop(rows, "SHA-256", sha);
        }
    }

    if (const peelf::PeHeader* pe = img.pe_header(); pe != nullptr) {
        add_prop(rows, "Machine", std::format("0x{:04X}", pe->machine));
        add_prop(rows, "Subsystem", pe_subsystem_name(pe->subsystem));
        add_prop(rows, "DLL Characteristics", format_pe_dll_characteristics(pe->dll_characteristics));
        add_prop(rows, "Characteristics", std::format("0x{:04X}", pe->characteristics));
        add_prop(rows, "TimeDateStamp", std::format("0x{:08X}", pe->time_date_stamp));
        add_prop(rows, "SizeOfImage", std::format("0x{:X} ({} bytes)", pe->size_of_image, pe->size_of_image));
        add_prop(rows, "Section / File Alignment",
                 std::format("0x{:X} / 0x{:X}", pe->section_alignment, pe->file_alignment));
    } else if (const peelf::ElfHeader* elf = img.elf_header(); elf != nullptr) {
        add_prop(rows, "ELF Type", elf_type_name(elf->type));
        add_prop(rows, "OS/ABI", std::format("{} (ABI v{})", elf_osabi_name(elf->os_abi), elf->abi_version));
        add_prop(rows, "Flags", std::format("0x{:08X}", elf->flags));
        const std::string_view interp = img.elf_interpreter();
        add_prop(rows, "Interpreter", interp.empty() ? std::string{"-"} : std::string{interp});
        add_prop(rows, "Program Headers",
                 std::format("{} @ 0x{:X}", elf->effective_program_header_count, elf->program_header_offset));
        add_prop(rows, "Section Headers",
                 std::format("{} @ 0x{:X}", elf->effective_section_header_count, elf->section_header_offset));
    } else if (const peelf::MachOHeader* mh = img.macho_header(); mh != nullptr) {
        add_prop(rows, "File Type", macho_filetype_name(mh->file_type));
        add_prop(rows, "Flags", format_macho_flags(mh->flags));
        add_prop(rows, "Load Commands", std::format("{} ({} bytes)", mh->ncmds, mh->sizeofcmds));
        const std::string_view uuid = img.macho_uuid_string();
        if (!uuid.empty()) {
            add_prop(rows, "LC_UUID", std::string(uuid));
        }
        const std::string_view dylinker = img.macho_dylinker();
        if (!dylinker.empty()) {
            add_prop(rows, "Dynamic Linker", std::string(dylinker));
        }
    }
}

} // namespace

std::vector<DetailPropertyRow> build_selection_detail_properties(
    const ViewerSelection& selection,
    const BinaryModel& model) {
    std::vector<DetailPropertyRow> rows{};
    if (selection.kind == SelectionKind::None || selection.kind == SelectionKind::Group) {
        return rows;
    }

    const peelf::IBinaryImage* img = model.image();
    const auto idx = static_cast<std::size_t>(selection.object_index);

    switch (selection.kind) {
        case SelectionKind::Image:
        case SelectionKind::Header: {
            if (img != nullptr) {
                append_image_or_header_properties(rows, *img, model);
            }
            break;
        }
        case SelectionKind::Section: {
            if (img == nullptr || idx >= img->sections().size()) {
                break;
            }
            const peelf::Section& sec = img->sections()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Name", sec.name.empty() ? std::string{"<unnamed>"} : sec.name);
            if (idx < img->elf_section_headers().size()) {
                add_prop(rows, "Type", elf_sht_name(img->elf_section_headers()[idx].type));
            } else if (idx < img->macho_sections().size()) {
                const peelf::MachOSection& ms = img->macho_sections()[idx];
                add_prop(rows, "Segment / Section", std::format("{},{}", ms.segment_name, ms.section_name));
                add_prop(rows, "Type", std::format("0x{:02X}{}", ms.section_type(), ms.is_zerofill ? " (ZeroFill)" : ""));
            } else if (img->format() == peelf::Format::PE) {
                std::string pe_sec_kind{};
                if ((sec.raw_flags & 0x00000020u) != 0u) {
                    pe_sec_kind = "CNT_CODE";
                } else if ((sec.raw_flags & 0x00000040u) != 0u) {
                    pe_sec_kind = "CNT_INITIALIZED_DATA";
                } else if ((sec.raw_flags & 0x00000080u) != 0u) {
                    pe_sec_kind = "CNT_UNINITIALIZED_DATA";
                } else {
                    pe_sec_kind = "PE Section";
                }
                add_prop(rows, "Type", std::move(pe_sec_kind));
            }
            add_prop(rows, "Virtual Address", std::format("0x{:X}", sec.virtual_address));
            if (sec.virtual_address >= img->image_base()) {
                add_prop(rows, "RVA", std::format("0x{:X}", sec.virtual_address - img->image_base()));
            }
            add_prop(rows, "Raw Offset", std::format("0x{:X}", sec.file_offset));
            add_prop(rows, "Virtual Size", std::format("{} bytes (0x{:X})", sec.virtual_size, sec.virtual_size));
            add_prop(rows, "Raw Size", std::format("{} bytes (0x{:X})", sec.file_size, sec.file_size));
            add_prop(rows, "Permissions", format_rwx(sec.readable, sec.writable, sec.executable));
            if (idx < img->elf_section_headers().size()) {
                add_prop(rows, "Alignment",
                         std::format("0x{:X}", img->elf_section_headers()[idx].address_alignment));
            } else if (idx < img->macho_sections().size()) {
                const std::uint32_t align_pow = img->macho_sections()[idx].align_log2;
                const std::uint64_t align_bytes = align_pow < 63u ? (1ULL << align_pow) : 0u;
                add_prop(rows, "Alignment", std::format("0x{:X} (2^{})", align_bytes, align_pow));
            } else if (const peelf::PeHeader* pe = img->pe_header(); pe != nullptr) {
                add_prop(rows, "Alignment", std::format("0x{:X}", pe->section_alignment));
            }
            add_prop(rows, "Characteristics / Flags", std::format("0x{:X}", sec.raw_flags));
            if (const auto ent = compute_shannon_entropy_for_offset(model, img, sec.file_offset, sec.file_size);
                ent.has_value()) {
                add_prop(rows, "Shannon Entropy", std::format("{:.4f} bits/byte", *ent));
            }
            break;
        }
        case SelectionKind::Segment: {
            if (img == nullptr || idx >= img->segments().size()) {
                break;
            }
            const peelf::Segment& seg = img->segments()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            if (idx < img->macho_segments().size()) {
                add_prop(rows, "Name", img->macho_segments()[idx].name);
                add_prop(rows, "Type", std::format("LC_SEGMENT (0x{:X})", seg.type));
            } else {
                add_prop(rows, "Type", elf_pt_name(seg.type));
            }
            add_prop(rows, "Virtual Address", std::format("0x{:X}", seg.virtual_address));
            if (seg.virtual_address >= img->image_base()) {
                add_prop(rows, "RVA", std::format("0x{:X}", seg.virtual_address - img->image_base()));
            }
            add_prop(rows, "Raw Offset", std::format("0x{:X}", seg.file_offset));
            add_prop(rows, "Virtual Size", std::format("{} bytes (0x{:X})", seg.virtual_size, seg.virtual_size));
            add_prop(rows, "Raw Size", std::format("{} bytes (0x{:X})", seg.file_size, seg.file_size));
            add_prop(rows, "Permissions", format_rwx(seg.readable, seg.writable, seg.executable));
            if (idx < img->elf_program_headers().size()) {
                add_prop(rows, "Alignment",
                         std::format("0x{:X}", img->elf_program_headers()[idx].alignment));
                add_prop(rows, "Flags", std::format("0x{:X}", img->elf_program_headers()[idx].flags));
            } else if (idx < img->macho_segments().size()) {
                const peelf::MachOSegmentCommand& ms = img->macho_segments()[idx];
                add_prop(rows, "Init / Max Prot",
                         std::format("0x{:X} / 0x{:X}", ms.initprot, ms.maxprot));
                add_prop(rows, "Flags", std::format("0x{:X}", ms.flags));
            }
            if (const auto ent = compute_shannon_entropy_for_offset(model, img, seg.file_offset, seg.file_size);
                ent.has_value()) {
                add_prop(rows, "Shannon Entropy", std::format("{:.4f} bits/byte", *ent));
            }
            break;
        }
        case SelectionKind::Import: {
            if (img == nullptr || idx >= img->imports().size()) {
                break;
            }
            const peelf::ImportEntry& imp = img->imports()[idx];
            add_prop(rows, "Library / Module", imp.library.empty() ? std::string{"-"} : imp.library);
            const std::string raw_fn =
                imp.import_by_ordinal ? std::format("#{}", imp.ordinal) : imp.name;
            add_prop(rows, "Function (Raw)", raw_fn.empty() ? std::string{"-"} : raw_fn);
            if (!imp.name.empty()) {
                const peelf::DemangleResult dem = peelf::demangle_symbol(imp.name);
                if (dem.succeeded && dem.demangled != imp.name) {
                    add_prop(rows, "Demangled", dem.demangled);
                }
            }
            add_prop(rows, "Ordinal / Hint",
                     std::format("{} ({})", imp.ordinal, imp.import_by_ordinal ? "by ordinal" : "hint / name"));
            add_prop(rows, "Slot / Thunk VA", std::format("0x{:X}", imp.address));
            add_prop(rows, "Binding",
                     imp.delay_load ? "Delay-Load Import"
                                    : (imp.import_by_ordinal ? "Ordinal Import" : "IAT / GOT Slot"));
            add_prop(rows, "Source", "Import Table");
            break;
        }
        case SelectionKind::Export: {
            if (img == nullptr || idx >= img->exports().size()) {
                break;
            }
            const peelf::ExportEntry& exp = img->exports()[idx];
            add_prop(rows, "Name (Raw)", exp.name.empty() ? std::string{"<ordinal-only>"} : exp.name);
            if (!exp.name.empty()) {
                const peelf::DemangleResult dem = peelf::demangle_symbol(exp.name);
                if (dem.succeeded && dem.demangled != exp.name) {
                    add_prop(rows, "Demangled", dem.demangled);
                }
            }
            add_prop(rows, "Ordinal", std::format("{}", exp.ordinal));
            add_prop(rows, "Target VA", std::format("0x{:X}", exp.virtual_address));
            add_prop(rows, "Binding",
                     exp.forwarder.empty() ? "Exported Address" : "Forwarded Export");
            if (!exp.forwarder.empty()) {
                add_prop(rows, "Forwarder", exp.forwarder);
            }
            add_prop(rows, "Source", "Export Table");
            break;
        }
        case SelectionKind::Symbol: {
            const auto rec_idx = selected_symbol_record_index(selection, model.symbol_index());
            const auto records = model.symbol_index().records();
            if (rec_idx.has_value() && *rec_idx < records.size()) {
                const SymbolRecord& rec = records[static_cast<std::size_t>(*rec_idx)];
                const std::string& raw_name = !rec.raw_name.empty() ? rec.raw_name : rec.name;
                add_prop(rows, "Symbol (Raw)", raw_name.empty() ? std::string{"<unnamed>"} : raw_name);
                if (rec.is_demangled()) {
                    add_prop(rows, "Demangled", rec.demangled_name);
                } else if (!raw_name.empty()) {
                    const peelf::DemangleResult dem = peelf::demangle_symbol(raw_name);
                    if (dem.succeeded && dem.demangled != raw_name) {
                        add_prop(rows, "Demangled", dem.demangled);
                    }
                }
                if (!rec.library.empty()) {
                    add_prop(rows, "Library / Module", rec.library);
                }
                if (rec.virtual_address.has_value()) {
                    add_prop(rows, "Target VA", std::format("0x{:X}", *rec.virtual_address));
                }
                if (rec.file_offset.has_value()) {
                    add_prop(rows, "File Offset", std::format("0x{:X}", *rec.file_offset));
                }
                add_prop(rows, "Size", std::format("{} bytes", rec.size));
                add_prop(rows, "Type",
                         rec.function.has_value()
                             ? (*rec.function ? "Function" : "Data / Object")
                             : (rec.external ? "External Symbol" : "Symbol"));
                add_prop(rows, "Binding", rec.dynamic ? "Dynamic" : (rec.external ? "External" : "Static"));
                add_prop(rows, "Source", symbol_source_name(rec.source));
            } else if (img != nullptr && idx < img->symbols().size()) {
                const peelf::Symbol& sym = img->symbols()[idx];
                add_prop(rows, "Symbol (Raw)", sym.name.empty() ? std::string{"<unnamed>"} : sym.name);
                if (!sym.name.empty()) {
                    const peelf::DemangleResult dem = peelf::demangle_symbol(sym.name);
                    if (dem.succeeded && dem.demangled != sym.name) {
                        add_prop(rows, "Demangled", dem.demangled);
                    }
                }
                add_prop(rows, "Target VA", std::format("0x{:X}", sym.virtual_address));
                add_prop(rows, "Size", std::format("{} bytes", sym.size));
                add_prop(rows, "Binding", elf_symbol_binding_name(sym.binding));
                add_prop(rows, "Type", elf_symbol_type_name(sym.type));
                add_prop(rows, "Section Index", std::format("{}", sym.section_index));
                add_prop(rows, "Source", sym.dynamic ? "Dynamic Symbol Table" : "Static Symbol Table");
            }
            break;
        }
        case SelectionKind::DebugDirectory: {
            if (img == nullptr || idx >= img->pe_debug_directories().size()) {
                break;
            }
            const peelf::PeDebugDirectory& dbg = img->pe_debug_directories()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Debug Type", pe_debug_type_name(dbg.type));
            add_prop(rows, "TimeDateStamp", std::format("0x{:08X}", dbg.time_date_stamp));
            add_prop(rows, "Version", std::format("{}.{}", dbg.major_version, dbg.minor_version));
            add_prop(rows, "AddressOfRawData (RVA)", std::format("0x{:X}", dbg.address_of_raw_data));
            add_prop(rows, "PointerToRawData", std::format("0x{:X}", dbg.pointer_to_raw_data));
            add_prop(rows, "SizeOfData", std::format("{} bytes (0x{:X})", dbg.size_of_data, dbg.size_of_data));
            if (!dbg.codeview_pdb_path.empty()) {
                add_prop(rows, "PDB Path", dbg.codeview_pdb_path);
                add_prop(rows, "CodeView Age", std::format("{}", dbg.codeview_age));
            }
            break;
        }
        case SelectionKind::TlsDirectory: {
            if (img == nullptr || img->pe_tls_directory() == nullptr) {
                break;
            }
            const peelf::PeTlsDirectory& tls = *img->pe_tls_directory();
            add_prop(rows, "Raw Data Start VA", std::format("0x{:X}", tls.raw_data_start_va));
            add_prop(rows, "Raw Data End VA", std::format("0x{:X}", tls.raw_data_end_va));
            add_prop(rows, "Address of Index", std::format("0x{:X}", tls.address_of_index));
            add_prop(rows, "Address of Callbacks", std::format("0x{:X}", tls.address_of_callbacks));
            add_prop(rows, "Callback Count", std::format("{}", tls.callbacks.size()));
            add_prop(rows, "Zero Fill Size", std::format("{} bytes", tls.size_of_zero_fill));
            add_prop(rows, "Characteristics", std::format("0x{:08X}", tls.characteristics));
            break;
        }
        case SelectionKind::LoadConfig: {
            if (img == nullptr || img->pe_load_config_directory() == nullptr) {
                break;
            }
            const peelf::PeLoadConfigDirectory& cfg = *img->pe_load_config_directory();
            add_prop(rows, "RVA", std::format("0x{:X}", cfg.rva));
            add_prop(rows, "File Offset", std::format("0x{:X}", cfg.file_offset));
            add_prop(rows, "Structure Size", std::format("{} bytes (0x{:X})", cfg.size, cfg.size));
            add_prop(rows, "Security Cookie VA", std::format("0x{:X}", cfg.security_cookie));
            add_prop(rows, "Guard Flags", std::format("0x{:08X}", cfg.guard_flags));
            add_prop(rows, "CFG Check Function Ptr", std::format("0x{:X}", cfg.guard_cf_check_function_pointer));
            add_prop(rows, "CFG Dispatch Function Ptr", std::format("0x{:X}", cfg.guard_cf_dispatch_function_pointer));
            add_prop(rows, "CFG Function Count", std::format("{}", cfg.guard_cf_function_count));
            add_prop(rows, "SEH Handler Count", std::format("{}", cfg.se_handler_count));
            break;
        }
        case SelectionKind::Certificate: {
            if (img == nullptr || idx >= img->pe_certificates().size()) {
                break;
            }
            const peelf::PeCertificate& cert = img->pe_certificates()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "File Offset", std::format("0x{:X}", cert.file_offset));
            add_prop(rows, "Length", std::format("{} bytes (0x{:X})", cert.length, cert.length));
            add_prop(rows, "Revision", std::format("0x{:04X}", cert.revision));
            add_prop(rows, "Certificate Type",
                     cert.certificate_type == 2u
                         ? "PKCS#7 SignedData (0x0002)"
                         : std::format("0x{:04X}", cert.certificate_type));
            add_prop(rows, "Payload Bytes", std::format("{}", cert.certificate.size()));
            break;
        }
        case SelectionKind::DynamicEntry: {
            if (img == nullptr || idx >= img->elf_dynamic_entries().size()) {
                break;
            }
            const peelf::ElfDynamicEntry& dyn = img->elf_dynamic_entries()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Tag", std::format("{} (0x{:X})", elf_dynamic_tag_name(dyn.tag), dyn.tag));
            add_prop(rows, "Value", std::format("0x{:X}", dyn.value));
            if (!dyn.needed_library.empty()) {
                add_prop(rows, "Needed Library", dyn.needed_library);
            }
            if (!dyn.string_value.empty() && dyn.string_value != dyn.needed_library) {
                add_prop(rows, "String Value", dyn.string_value);
            }
            break;
        }
        case SelectionKind::Note: {
            if (img == nullptr || idx >= img->elf_notes().size()) {
                break;
            }
            const peelf::ElfNote& note = img->elf_notes()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Owner / Name", note.name.empty() ? std::string{"<unnamed>"} : note.name);
            add_prop(rows, "Note Type", std::format("0x{:X}", note.type));
            add_prop(rows, "Origin", note.from_program_header ? "Program Header (PT_NOTE)" : "Section Header (SHT_NOTE)");
            add_prop(rows, "Descriptor Size", std::format("{} bytes", note.descriptor.size()));
            if (!note.descriptor.empty()) {
                const std::size_t preview_n = std::min<std::size_t>(note.descriptor.size(), 32u);
                std::string hex_desc{};
                hex_desc.reserve(preview_n * 2u + 4u);
                for (std::size_t i = 0u; i < preview_n; ++i) {
                    hex_desc += std::format("{:02x}", note.descriptor[i]);
                }
                if (note.descriptor.size() > preview_n) {
                    hex_desc += "...";
                }
                add_prop(rows, "Descriptor Hex", std::move(hex_desc));
            }
            break;
        }
        case SelectionKind::Relocation: {
            if (img == nullptr) {
                break;
            }
            if (img->format() == peelf::Format::PE && idx < img->pe_base_relocations().size()) {
                const peelf::PeBaseRelocationBlock& blk = img->pe_base_relocations()[idx];
                add_prop(rows, "Block Index", std::format("{}", idx));
                add_prop(rows, "Page RVA", std::format("0x{:X}", blk.page_rva));
                add_prop(rows, "Page VA", std::format("0x{:X}", img->image_base() + blk.page_rva));
                add_prop(rows, "Block Size", std::format("{} bytes", blk.block_size));
                add_prop(rows, "Fixup Entries", std::format("{}", blk.entries.size()));
            } else if (idx < img->elf_relocations().size()) {
                const peelf::ElfRelocation& rel = img->elf_relocations()[idx];
                add_prop(rows, "Index", std::format("{}", idx));
                add_prop(rows, "Section", rel.section_name);
                add_prop(rows, "Offset / Target", std::format("0x{:X}", rel.offset));
                add_prop(rows, "Type", std::format("0x{:X}", rel.type));
                add_prop(rows, "Symbol Index", std::format("{}", rel.symbol_index));
                if (!rel.symbol_name.empty()) {
                    add_prop(rows, "Symbol", rel.symbol_name);
                }
                if (rel.has_addend) {
                    add_prop(rows, "Addend", std::format("{}", rel.addend));
                }
            }
            break;
        }
        case SelectionKind::RuntimeFunction: {
            if (img != nullptr && idx < img->pe_runtime_functions().size()) {
                const peelf::PeRuntimeFunction& rf = img->pe_runtime_functions()[idx];
                add_prop(rows, "Index", std::format("{}", idx));
                add_prop(rows, "Begin RVA", std::format("0x{:X}", rf.begin_address_rva));
                add_prop(rows, "End RVA", std::format("0x{:X}", rf.end_address_rva));
                add_prop(rows, "Unwind Info RVA", std::format("0x{:X}", rf.unwind_info_rva));
            }
            break;
        }
        case SelectionKind::BoundImport: {
            if (img != nullptr && idx < img->pe_bound_imports().size()) {
                const peelf::PeBoundImport& bi = img->pe_bound_imports()[idx];
                add_prop(rows, "Module", bi.module_name);
                add_prop(rows, "TimeDateStamp", std::format("0x{:08X}", bi.time_date_stamp));
                add_prop(rows, "Forwarder Refs", std::format("{}", bi.forwarder_ref_count));
            }
            break;
        }
        case SelectionKind::ResourceDirectory: {
            if (img != nullptr && img->pe_resource_directory() != nullptr) {
                const peelf::PeResourceDirectory& dir = *img->pe_resource_directory();
                add_prop(rows, "RVA", std::format("0x{:X}", dir.rva));
                add_prop(rows, "Named Entries", std::format("{}", dir.named_entry_count));
                add_prop(rows, "ID Entries", std::format("{}", dir.id_entry_count));
                add_prop(rows, "Data Leaves", std::format("{}", img->pe_resource_data_entries().size()));
            }
            break;
        }
        case SelectionKind::ResourceData: {
            if (img != nullptr && idx < img->pe_resource_data_entries().size()) {
                const peelf::PeResourceDataEntry& rd = img->pe_resource_data_entries()[idx];
                add_prop(rows, "Type / Name / Lang",
                         std::format("{} / {} / {}", rd.type_id, rd.name_id, rd.language_id));
                add_prop(rows, "Data RVA", std::format("0x{:X}", rd.data_rva));
                add_prop(rows, "Data File Offset", std::format("0x{:X}", rd.data_file_offset));
                add_prop(rows, "Size", std::format("{} bytes", rd.size));
                add_prop(rows, "Code Page", std::format("{}", rd.code_page));
            }
            break;
        }
        case SelectionKind::ClrHeader: {
            if (img != nullptr && img->pe_clr_header() != nullptr) {
                const peelf::PeClrHeader& clr = *img->pe_clr_header();
                add_prop(rows, "Runtime Version",
                         std::format("{}.{}", clr.major_runtime_version, clr.minor_runtime_version));
                add_prop(rows, "Metadata RVA", std::format("0x{:X} ({} bytes)", clr.metadata_rva, clr.metadata_size));
                add_prop(rows, "Flags", std::format("0x{:08X}", clr.flags));
                add_prop(rows, "EntryPointToken", std::format("0x{:08X}", clr.entry_point_token_or_rva));
            }
            break;
        }
        case SelectionKind::HashTable: {
            if (img != nullptr) {
                const auto sysv_n = img->elf_sysv_hash_tables().size();
                if (idx < sysv_n) {
                    const peelf::ElfSysvHashTable& ht = img->elf_sysv_hash_tables()[idx];
                    add_prop(rows, "Kind", "ELF SYSV Hash");
                    add_prop(rows, "Section", ht.section_name);
                    add_prop(rows, "Buckets / Chains", std::format("{} / {}", ht.bucket_count, ht.chain_count));
                } else if (idx - sysv_n < img->elf_gnu_hash_tables().size()) {
                    const peelf::ElfGnuHashTable& gt = img->elf_gnu_hash_tables()[idx - sysv_n];
                    add_prop(rows, "Kind", "ELF GNU Hash");
                    add_prop(rows, "Section", gt.section_name);
                    add_prop(rows, "Buckets / SymOffset", std::format("{} / {}", gt.bucket_count, gt.symbol_offset));
                    add_prop(rows, "Bloom Words", std::format("{} (shift {})", gt.bloom_word_count, gt.bloom_shift));
                }
            }
            break;
        }
        case SelectionKind::Interpreter: {
            if (img != nullptr) {
                add_prop(rows, "Interpreter", std::string(img->elf_interpreter()));
            }
            break;
        }
        case SelectionKind::Process: {
            if (const peelf::IProcessSession* sess = model.process_session(); sess != nullptr) {
                const peelf::ProcessInfo& p = sess->info();
                add_prop(rows, "PID", std::format("{}", p.pid));
                if (p.parent_pid != 0u) {
                    add_prop(rows, "Parent PID", std::format("{}", p.parent_pid));
                }
                add_prop(rows, "Process Name", p.name.empty() ? std::string{"<unknown>"} : p.name);
                add_prop(rows, "Architecture",
                         std::format("{} ({}-bit)", peelf::to_string(p.architecture), p.is_64bit ? 64 : 32));
                add_prop(rows, "Endianness", std::string(peelf::to_string(model.endianness())));
                add_prop(rows, "Access", std::string(peelf::to_string(p.access)));
                const char* backend_str = model.is_crash_dump()
                    ? "Post-Mortem Crash Dump"
                    : (model.is_debug_session() ? "Opt-In Active Debugger" : "Read-Only Live Session");
                add_prop(rows, "Backend", backend_str);
                if (!p.executable_path.empty()) {
                    add_prop(rows, "Executable Path", p.executable_path.string());
                }
                if (!p.command_line.empty()) {
                    add_prop(rows, "Command Line", p.command_line);
                }
                add_prop(rows, "Modules", std::format("{}", model.process_modules().size()));
                add_prop(rows, "Memory Regions", std::format("{}", model.memory_regions().size()));
                add_prop(rows, "Threads", std::format("{}", model.threads().size()));
            }
            break;
        }
        case SelectionKind::ProcessModule: {
            if (idx >= model.process_modules().size()) {
                break;
            }
            const peelf::ModuleInfo& mod = model.process_modules()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Module Name", mod.name.empty() ? std::string{"<unnamed>"} : mod.name);
            add_prop(rows, "Base Address", std::format("0x{:X}", mod.base_address));
            add_prop(rows, "Size", std::format("{} bytes (0x{:X})", mod.size, mod.size));
            add_prop(rows, "End Address", std::format("0x{:X}", mod.base_address + mod.size));
            add_prop(rows, "Active Module",
                     (model.active_module_index().has_value() && *model.active_module_index() == idx) ? "Yes" : "No");
            add_prop(rows, "Path", mod.path.empty() ? std::string{"-"} : mod.path.string());
            break;
        }
        case SelectionKind::MemoryRegion: {
            if (idx >= model.memory_regions().size()) {
                break;
            }
            const peelf::MemoryRegion& reg = model.memory_regions()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Address Range",
                     std::format("0x{:X} - 0x{:X}", reg.start_address, reg.end_address));
            add_prop(rows, "Size", std::format("{} bytes (0x{:X})", reg.size(), reg.size()));
            add_prop(rows, "Protection", peelf::format_protection(reg.protection));
            add_prop(rows, "Region Kind", std::string(peelf::to_string(reg.kind)));
            add_prop(rows, "Backing Offset", std::format("0x{:X}", reg.file_offset));
            add_prop(rows, "Pathname", reg.pathname.empty() ? std::string{"-"} : reg.pathname);
            break;
        }
        case SelectionKind::ProcessThread: {
            if (idx >= model.threads().size()) {
                break;
            }
            const peelf::ThreadInfo& thr = model.threads()[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "TID", std::format("{}", thr.tid));
            if (!thr.name.empty()) {
                add_prop(rows, "Thread Name", thr.name);
            }
            std::string state_str(peelf::to_string(thr.state));
            if (thr.is_suspended) {
                state_str += " (Suspended)";
            }
            add_prop(rows, "State", std::move(state_str));
            add_prop(rows, "Instruction Pointer (PC)",
                     thr.instruction_pointer.has_value()
                         ? std::format("0x{:X}", *thr.instruction_pointer)
                         : std::string{"-"});
            add_prop(rows, "Stack Pointer (SP)",
                     thr.stack_pointer.has_value()
                         ? std::format("0x{:X}", *thr.stack_pointer)
                         : std::string{"-"});
            if (thr.start_address.has_value()) {
                add_prop(rows, "Start Address", std::format("0x{:X}", *thr.start_address));
            }
            if (thr.tls_base.has_value()) {
                add_prop(rows, "TLS Base", std::format("0x{:X}", *thr.tls_base));
            }
            if (thr.teb_address.has_value()) {
                add_prop(rows, "TEB Address", std::format("0x{:X}", *thr.teb_address));
            }
            if (!thr.wait_channel.empty()) {
                add_prop(rows, "Wait Channel", thr.wait_channel);
            }
            break;
        }
        case SelectionKind::ProcessHandle: {
            const auto& handles_opt = model.process_internals().handles.value;
            if (!handles_opt.has_value() || idx >= handles_opt->size()) {
                break;
            }
            const peelf::ProcessHandleEntry& h = (*handles_opt)[idx];
            add_prop(rows, "Index", std::format("{}", idx));
            add_prop(rows, "Handle / FD", std::format("{} (0x{:X})", h.handle_or_fd, h.handle_or_fd));
            add_prop(rows, "Kind", std::string(peelf::to_string(h.kind)));
            if (!h.type_name.empty()) {
                add_prop(rows, "Type Name", h.type_name);
            }
            add_prop(rows, "Target", h.target.empty() ? std::string{"-"} : h.target);
            if (!h.access_or_flags.empty()) {
                add_prop(rows, "Access / Flags", h.access_or_flags);
            }
            if (h.offset.has_value()) {
                add_prop(rows, "File Offset", std::format("0x{:X}", *h.offset));
            }
            if (h.inode.has_value()) {
                add_prop(rows, "Inode", std::format("{}", *h.inode));
            }
            break;
        }
        case SelectionKind::SecurityFinding: {
            const auto& findings = model.security_audit().findings;
            if (idx >= findings.size()) {
                break;
            }
            const peelf::SecurityFinding& f = findings[idx];
            add_prop(rows, "Rule ID", f.rule_id);
            add_prop(rows, "Rule Name", f.rule_name);
            add_prop(rows, "Domain", std::string(peelf::to_string(f.domain)));
            add_prop(rows, "Severity", std::string(peelf::to_string(f.severity)));
            add_prop(rows, "Status", f.severity == peelf::SecuritySeverity::Pass ? "Pass" : "Finding");
            if (!f.subject.empty()) {
                add_prop(rows, "Subject", f.subject);
            }
            if (!f.summary.empty()) {
                add_prop(rows, "Summary", f.summary);
            }
            if (!f.evidence.empty()) {
                add_prop(rows, "Evidence", f.evidence);
            }
            if (!f.remediation.empty()) {
                add_prop(rows, "Remediation", f.remediation);
            }
            break;
        }
        case SelectionKind::CallGraphNode:
        case SelectionKind::Patch:
        case SelectionKind::ByteRange: {
            add_prop(rows, "Kind", std::string(selection_kind_tag(selection.kind)));
            if (selection.virtual_address.has_value()) {
                add_prop(rows, "Virtual Address", std::format("0x{:X}", *selection.virtual_address));
            }
            if (selection.file_offset.has_value()) {
                add_prop(rows, "File Offset", std::format("0x{:X}", *selection.file_offset));
            }
            add_prop(rows, "Size", std::format("{} bytes", selection.size));
            break;
        }
        case SelectionKind::None:
        case SelectionKind::Group:
            break;
    }

    return rows;
}

InspectableEntity build_inspectable_entity_from_selection(
    const ViewerSelection& selection,
    const BinaryModel* model) {
    InspectableEntity entity{
        .va = selection.virtual_address,
        .file_offset = selection.file_offset,
        .size = selection.size,
        .symbol_or_label = selection.label,
        .module_name = {},
        .extra_json_fields = {
            {"kind", std::string(selection_kind_tag(selection.kind))},
            {"badge", std::string(structure_node_badge(selection.kind))},
        },
    };
    if (model != nullptr) {
        if (selection.kind == SelectionKind::Import && model->image() != nullptr) {
            const auto idx = static_cast<std::size_t>(selection.object_index);
            if (idx < model->image()->imports().size()) {
                entity.module_name = model->image()->imports()[idx].library;
            }
        } else if (selection.kind == SelectionKind::ProcessModule) {
            const auto idx = static_cast<std::size_t>(selection.object_index);
            if (idx < model->process_modules().size()) {
                entity.module_name = model->process_modules()[idx].name;
            }
        } else if (const peelf::ModuleInfo* active_mod = model->active_module(); active_mod != nullptr) {
            entity.module_name = active_mod->name;
        } else if (!model->file_info().path.empty()) {
            entity.module_name = utf8_to_filesystem_path(model->file_info().path).filename().string();
        }
    }
    return entity;
}

bool enqueue_structure_selection_activation(
    NavigationRequestQueue& queue,
    const ViewerSelection& selection,
    BinaryModel* model) {
    if (selection.kind == SelectionKind::None || selection.kind == SelectionKind::Group) {
        return false;
    }
    if (selection.kind == SelectionKind::ProcessModule) {
        queue.enqueue_module(static_cast<std::size_t>(selection.object_index));
        return true;
    }
    if (selection.kind == SelectionKind::MemoryRegion) {
        queue.enqueue_memory_region(static_cast<std::size_t>(selection.object_index), true);
        return true;
    }
    if (selection.kind == SelectionKind::ProcessThread) {
        const auto idx = static_cast<std::size_t>(selection.object_index);
        if (model != nullptr) {
            queue.enqueue_custom([model, idx]() {
                if (idx < model->threads().size()) {
                    model->select_thread(model->threads()[idx].tid);
                }
            });
        }
        if (selection.virtual_address.has_value()) {
            const PreferredView view = selection.preferred_view == PreferredView::Details
                ? PreferredView::Disassembly
                : selection.preferred_view;
            queue.enqueue_address(*selection.virtual_address, view, 1u);
        }
        return model != nullptr || selection.virtual_address.has_value();
    }

    const auto highlight_sz =
        static_cast<std::size_t>(std::clamp<std::uint64_t>(selection.size, 1u, 65536u));
    if (selection.virtual_address.has_value()) {
        const PreferredView view = selection.preferred_view == PreferredView::Details
            ? PreferredView::Hex
            : selection.preferred_view;
        queue.enqueue_address(*selection.virtual_address, view, highlight_sz);
        return true;
    }
    if (selection.file_offset.has_value()) {
        if (selection.preferred_view == PreferredView::Disassembly) {
            queue.enqueue(DeferredNavigationRequest{
                .kind = DeferredNavigationRequest::Kind::Offset,
                .target = *selection.file_offset,
                .preferred_view = PreferredView::Disassembly,
                .highlight_size = highlight_sz,
            });
        } else {
            queue.enqueue_offset(*selection.file_offset, highlight_sz);
        }
        return true;
    }
    return false;
}

bool icontains(std::string_view haystack, std::string_view needle) noexcept {
    return contains_ascii_icase(haystack, needle);
}

std::string format_va(std::uint64_t va, bool is_64bit) {
    return is_64bit ? std::format("0x{:016X}", va) : std::format("0x{:08X}", va);
}

std::string format_file_offset(std::uint64_t offset) {
    return offset > 0xFFFFFFFFULL
        ? std::format("0x{:016X}", offset)
        : std::format("0x{:08X}", offset);
}

std::string format_compact_bytes(std::uint64_t bytes) {
    if (bytes < 1024ULL) {
        return std::format("{} B", bytes);
    }
    static constexpr std::array<std::string_view, 6> kUnits{
        "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double scaled = static_cast<double>(bytes) / 1024.0;
    std::size_t unit_idx = 0u;
    while (scaled >= 1023.95 && (unit_idx + 1u) < kUnits.size()) {
        scaled /= 1024.0;
        ++unit_idx;
    }
    if (scaled < 10.0) {
        return std::format("{:.2f} {}", scaled, kUnits[unit_idx]);
    }
    return std::format("{:.1f} {}", scaled, kUnits[unit_idx]);
}

namespace {

[[nodiscard]] int compare_ascii_icase(std::string_view a, std::string_view b) noexcept {
    const std::size_t common = std::min(a.size(), b.size());
    for (std::size_t i = 0u; i < common; ++i) {
        const int ca = std::tolower(static_cast<unsigned char>(a[i]));
        const int cb = std::tolower(static_cast<unsigned char>(b[i]));
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (a.size() != b.size()) {
        return a.size() < b.size() ? -1 : 1;
    }
    const int exact = a.compare(b);
    if (exact < 0) {
        return -1;
    }
    return exact > 0 ? 1 : 0;
}

[[nodiscard]] int compare_nonempty_string_icase(
    std::string_view a, std::string_view b, bool ascending) noexcept {
    if (a.empty() != b.empty()) {
        return a.empty() ? 1 : -1;
    }
    if (a.empty()) {
        return 0;
    }
    const int cmp = compare_ascii_icase(a, b);
    return ascending ? cmp : -cmp;
}

template <typename T>
[[nodiscard]] int compare_optional_value(
    const std::optional<T>& a, const std::optional<T>& b, bool ascending) noexcept {
    if (a.has_value() != b.has_value()) {
        return a.has_value() ? -1 : 1;
    }
    if (!a.has_value()) {
        return 0;
    }
    if (*a < *b) {
        return ascending ? -1 : 1;
    }
    if (*b < *a) {
        return ascending ? 1 : -1;
    }
    return 0;
}

[[nodiscard]] int compare_optional_double(
    const std::optional<double>& a, const std::optional<double>& b, bool ascending) noexcept {
    const bool a_valid = a.has_value() && !std::isnan(*a);
    const bool b_valid = b.has_value() && !std::isnan(*b);
    if (a_valid != b_valid) {
        return a_valid ? -1 : 1;
    }
    if (!a_valid) {
        return 0;
    }
    if (*a < *b) {
        return ascending ? -1 : 1;
    }
    if (*b < *a) {
        return ascending ? 1 : -1;
    }
    return 0;
}

[[nodiscard]] bool process_matches_filter(
    const peelf::ProcessInfo& proc, std::string_view filter) {
    if (filter.empty()) {
        return true;
    }
    if (icontains(proc.name, filter) ||
        icontains(proc.user, filter) ||
        icontains(proc.integrity_level, filter) ||
        icontains(peelf::to_string(proc.architecture), filter) ||
        icontains(proc.command_line, filter)) {
        return true;
    }
    const std::string pid_str = std::to_string(proc.pid);
    if (icontains(pid_str, filter)) {
        return true;
    }
    const std::string ppid_str = std::to_string(proc.parent_pid);
    if (icontains(ppid_str, filter)) {
        return true;
    }
    if (!proc.executable_path.empty()) {
        const std::string exe_str = proc.executable_path.string();
        if (icontains(exe_str, filter)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] int compare_process_column(
    const peelf::ProcessInfo& a,
    const peelf::ProcessInfo& b,
    ProcessSortColumn sort_col,
    bool ascending) {
    switch (sort_col) {
        case ProcessSortColumn::Pid:
            if (a.pid == b.pid) {
                return 0;
            }
            return (a.pid < b.pid) == ascending ? -1 : 1;
        case ProcessSortColumn::ParentPid:
            if (a.parent_pid == b.parent_pid) {
                return 0;
            }
            return (a.parent_pid < b.parent_pid) == ascending ? -1 : 1;
        case ProcessSortColumn::Name:
            return compare_nonempty_string_icase(a.name, b.name, ascending);
        case ProcessSortColumn::Architecture: {
            const bool a_known = a.architecture != peelf::Architecture::Unknown;
            const bool b_known = b.architecture != peelf::Architecture::Unknown;
            if (a_known != b_known) {
                return a_known ? -1 : 1;
            }
            if (!a_known) {
                return 0;
            }
            const int cmp = compare_ascii_icase(
                peelf::to_string(a.architecture), peelf::to_string(b.architecture));
            return ascending ? cmp : -cmp;
        }
        case ProcessSortColumn::User:
            return compare_nonempty_string_icase(a.user, b.user, ascending);
        case ProcessSortColumn::Integrity:
            return compare_nonempty_string_icase(
                a.integrity_level, b.integrity_level, ascending);
        case ProcessSortColumn::Threads:
            return compare_optional_value(a.thread_count, b.thread_count, ascending);
        case ProcessSortColumn::WorkingSet:
            return compare_optional_value(a.working_set_bytes, b.working_set_bytes, ascending);
        case ProcessSortColumn::Handles:
            return compare_optional_value(a.handle_count, b.handle_count, ascending);
        case ProcessSortColumn::CpuPercent:
            return compare_optional_double(a.cpu_percent, b.cpu_percent, ascending);
        case ProcessSortColumn::Access: {
            const auto av = static_cast<std::uint8_t>(a.access);
            const auto bv = static_cast<std::uint8_t>(b.access);
            if (av == bv) {
                return 0;
            }
            return (av < bv) == ascending ? -1 : 1;
        }
        case ProcessSortColumn::Path: {
            const std::string path_a =
                !a.executable_path.empty() ? a.executable_path.string() : a.command_line;
            const std::string path_b =
                !b.executable_path.empty() ? b.executable_path.string() : b.command_line;
            return compare_nonempty_string_icase(path_a, path_b, ascending);
        }
    }
    return 0;
}

} // namespace

std::vector<ProcessInventoryRow> build_process_inventory_view(
    std::span<const peelf::ProcessInfo> processes,
    std::string_view filter,
    bool accessible_only,
    ProcessSortColumn sort_col,
    bool ascending,
    bool tree_hierarchy) {
    std::vector<std::size_t> matched_indices;
    matched_indices.reserve(processes.size());
    for (std::size_t idx = 0u; idx < processes.size(); ++idx) {
        const peelf::ProcessInfo& proc = processes[idx];
        const bool is_accessible =
            proc.access == peelf::ProcessAccessStatus::Accessible ||
            proc.access == peelf::ProcessAccessStatus::ReadOnly;
        if (accessible_only && !is_accessible) {
            continue;
        }
        if (!process_matches_filter(proc, filter)) {
            continue;
        }
        matched_indices.push_back(idx);
    }

    if (matched_indices.empty()) {
        return {};
    }

    std::ranges::sort(matched_indices, [&](std::size_t ia, std::size_t ib) {
        const peelf::ProcessInfo& a = processes[ia];
        const peelf::ProcessInfo& b = processes[ib];
        const int cmp = compare_process_column(a, b, sort_col, ascending);
        if (cmp != 0) {
            return cmp < 0;
        }
        if (a.pid != b.pid) {
            return a.pid < b.pid;
        }
        return ia < ib;
    });

    const std::size_t count = matched_indices.size();
    std::unordered_map<peelf::ProcessId, std::size_t> pid_to_node;
    pid_to_node.reserve(count);
    for (std::size_t node = 0u; node < count; ++node) {
        pid_to_node.try_emplace(processes[matched_indices[node]].pid, node);
    }

    constexpr std::size_t kNoParent = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> parent(count, kNoParent);
    for (std::size_t node = 0u; node < count; ++node) {
        const peelf::ProcessInfo& proc = processes[matched_indices[node]];
        if (proc.parent_pid == 0u || proc.parent_pid == proc.pid) {
            continue;
        }
        const auto it = pid_to_node.find(proc.parent_pid);
        if (it != pid_to_node.end() && it->second != node) {
            parent[node] = it->second;
        }
    }

    if (!tree_hierarchy) {
        std::vector<std::uint8_t> has_child(count, 0u);
        for (std::size_t node = 0u; node < count; ++node) {
            if (parent[node] != kNoParent) {
                has_child[parent[node]] = 1u;
            }
        }
        std::vector<ProcessInventoryRow> rows;
        rows.reserve(count);
        for (std::size_t node = 0u; node < count; ++node) {
            rows.push_back(ProcessInventoryRow{
                .info = &processes[matched_indices[node]],
                .tree_depth = 0u,
                .has_children = has_child[node] != 0u,
            });
        }
        return rows;
    }

    // Break any PPID cycles deterministically at the highest-priority node in the cycle.
    std::vector<std::uint8_t> color(count, 0u);
    std::vector<std::size_t> chain;
    for (std::size_t start = 0u; start < count; ++start) {
        if (color[start] != 0u) {
            continue;
        }
        chain.clear();
        std::size_t cur = start;
        while (cur != kNoParent && color[cur] == 0u) {
            color[cur] = 1u;
            chain.push_back(cur);
            cur = parent[cur];
        }
        if (cur != kNoParent && color[cur] == 1u) {
            const auto cyc_begin = std::ranges::find(chain, cur);
            if (cyc_begin != chain.end()) {
                const std::size_t cycle_root = *std::min_element(cyc_begin, chain.end());
                parent[cycle_root] = kNoParent;
            }
        }
        for (const std::size_t visited : chain) {
            color[visited] = 2u;
        }
    }

    std::vector<std::size_t> roots;
    std::vector<std::vector<std::size_t>> children(count);
    for (std::size_t node = 0u; node < count; ++node) {
        if (parent[node] == kNoParent) {
            roots.push_back(node);
        } else {
            children[parent[node]].push_back(node);
        }
    }

    struct StackFrame {
        std::size_t node = 0u;
        std::size_t depth = 0u;
    };
    std::vector<StackFrame> stack;
    stack.reserve(count);
    for (std::size_t idx = roots.size(); idx > 0u; --idx) {
        stack.push_back(StackFrame{.node = roots[idx - 1u], .depth = 0u});
    }

    std::vector<std::uint8_t> emitted(count, 0u);
    std::vector<ProcessInventoryRow> rows;
    rows.reserve(count);
    while (!stack.empty()) {
        const StackFrame frame = stack.back();
        stack.pop_back();
        if (emitted[frame.node] != 0u) {
            continue;
        }
        emitted[frame.node] = 1u;
        const auto& node_children = children[frame.node];
        rows.push_back(ProcessInventoryRow{
            .info = &processes[matched_indices[frame.node]],
            .tree_depth = frame.depth,
            .has_children = !node_children.empty(),
        });
        for (std::size_t idx = node_children.size(); idx > 0u; --idx) {
            stack.push_back(StackFrame{
                .node = node_children[idx - 1u],
                .depth = frame.depth + 1u,
            });
        }
    }

    return rows;
}

} // namespace viewer
