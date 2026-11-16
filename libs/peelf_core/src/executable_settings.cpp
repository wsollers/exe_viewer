#include <peelf/executable_settings.hpp>

#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
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

constexpr std::size_t kMaxManifestBytes = 1024u * 1024u; // 1 MiB cap
constexpr std::size_t kMaxResourceVisits = 4096u;
constexpr std::uint32_t kPeRtVersion = 16u;
constexpr std::uint32_t kPeRtManifest = 24u;
constexpr std::uint32_t kVsFixedFileInfoSignature = 0xFEEF04BDu;
constexpr std::uint32_t kClrMetadataSignatureBsjb = 0x424A5342u;

[[nodiscard]] constexpr bool fits_range(
    std::uint64_t offset,
    std::uint64_t size,
    std::uint64_t limit) noexcept {
    return offset <= limit && size <= (limit - offset);
}

[[nodiscard]] constexpr std::optional<std::uint64_t> align4_checked(
    std::uint64_t value) noexcept {
    if (value > std::numeric_limits<std::uint64_t>::max() - 3u) {
        return std::nullopt;
    }
    return (value + 3u) & ~std::uint64_t{3u};
}

[[nodiscard]] constexpr std::uint16_t rd16_le(
    std::span<const std::uint8_t> bytes,
    std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[offset]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1u]) << 8u));
}

[[nodiscard]] constexpr std::uint32_t rd32_le(
    std::span<const std::uint8_t> bytes,
    std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
           (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
           (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
}

[[nodiscard]] std::string ascii_lower(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (const char ch : input) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() &&
           (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1u);
    }
    while (!sv.empty() &&
           (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1u);
    }
    return sv;
}

[[nodiscard]] std::string decode_utf16_units_to_utf8(
    std::span<const std::uint8_t> bytes,
    bool big_endian,
    bool stop_at_nul,
    std::vector<std::string>* warnings = nullptr) {
    Utf16DecodeDiagnostics diag{};
    std::string out = decode_utf16_to_utf8(
        bytes,
        big_endian ? Endianness::Big : Endianness::Little,
        stop_at_nul,
        std::numeric_limits<std::size_t>::max(),
        warnings != nullptr ? &diag : nullptr);
    if (warnings != nullptr) {
        if (diag.odd_trailing_byte) {
            warnings->emplace_back("UTF-16 byte span has odd length; trailing odd byte ignored");
        }
        for (std::size_t i = 0u; i < diag.unpaired_high_surrogates; ++i) {
            warnings->emplace_back("Unpaired UTF-16 high surrogate replaced with U+FFFD");
        }
        for (std::size_t i = 0u; i < diag.unpaired_low_surrogates; ++i) {
            warnings->emplace_back("Unpaired UTF-16 low surrogate replaced with U+FFFD");
        }
    }
    return out;
}

[[nodiscard]] std::string pe_subsystem_to_string(std::uint16_t subsystem) {
    switch (subsystem) {
        case 1u:  return "Native";
        case 2u:  return "WindowsGUI";
        case 3u:  return "WindowsCUI";
        case 5u:  return "OS2CUI";
        case 7u:  return "PosixCUI";
        case 8u:  return "NativeWindows";
        case 9u:  return "WindowsCEGUI";
        case 10u: return "EFIApplication";
        case 11u: return "EFIBootServiceDriver";
        case 12u: return "EFIRuntimeDriver";
        case 13u: return "EFIRom";
        case 14u: return "Xbox";
        case 16u: return "WindowsBootApplication";
        default:  return std::format("Subsystem({})", subsystem);
    }
}

// ---------------------------------------------------------------------------
// Bounded PE Resource Directory Walker (Cycle-Safe & ID-Checked)
// ---------------------------------------------------------------------------

struct RawPeResourceLeaf {
    std::uint32_t type_id{0};
    std::uint32_t name_id{0};
    std::uint32_t language_id{0};
    bool type_is_named{false};
    bool name_is_named{false};
    std::uint32_t data_rva{0};
    std::uint32_t size{0};
    std::uint32_t code_page{0};
    std::uint64_t entry_file_offset{0};
    std::optional<std::uint64_t> data_file_offset;
};

struct PeResourceWalkResult {
    bool directory_present{false};
    bool directory_truncated{false};
    bool directory_malformed{false};
    std::uint32_t directory_rva{0};
    std::uint32_t directory_size{0};
    std::optional<std::uint64_t> directory_file_offset;
    std::vector<RawPeResourceLeaf> leaves;
    std::vector<std::string> warnings;
};

[[nodiscard]] PeResourceWalkResult walk_pe_resources_bounded(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes) {
    PeResourceWalkResult res;
    const auto& dirs = image.pe_data_directories();
    if (dirs.size() <= 2u) {
        return res;
    }
    res.directory_rva = dirs[2].rva;
    res.directory_size = dirs[2].size;
    if (res.directory_rva == 0u && res.directory_size == 0u) {
        return res;
    }
    res.directory_present = true;

    if (raw_bytes.empty()) {
        res.directory_truncated = true;
        res.warnings.emplace_back("PE resource directory declared, but raw image bytes are unavailable");
        return res;
    }
    if (res.directory_size < 16u) {
        res.directory_truncated = true;
        res.warnings.emplace_back("PE resource directory size is smaller than 16-byte IMAGE_RESOURCE_DIRECTORY header");
        return res;
    }

    const std::uint64_t base_va = image.image_base();
    if (base_va > std::numeric_limits<std::uint64_t>::max() - res.directory_rva) {
        res.directory_malformed = true;
        res.warnings.emplace_back("PE resource directory RVA overflows image base");
        return res;
    }
    res.directory_file_offset = image.virtual_address_to_file_offset(base_va + res.directory_rva);
    if (!res.directory_file_offset.has_value() ||
        !fits_range(*res.directory_file_offset, 16u, raw_bytes.size())) {
        res.directory_truncated = true;
        res.warnings.emplace_back("PE resource directory RVA does not map to readable image bytes");
        return res;
    }

    const std::uint64_t root_off = *res.directory_file_offset;
    std::size_t visited_steps = 0u;
    bool budget_exceeded = false;
    std::array<std::uint64_t, 8> path_offsets{};

    auto mark_budget_exceeded = [&]() {
        if (!budget_exceeded) {
            budget_exceeded = true;
            res.directory_malformed = true;
            res.warnings.emplace_back(
                "PE resource directory exceeded maximum node/entry traversal budget");
        }
    };

    auto walk = [&](auto&& self,
                    std::uint64_t rel_dir_off,
                    std::uint32_t depth,
                    std::uint32_t type_id,
                    bool type_named,
                    std::uint32_t name_id,
                    bool name_named,
                    std::uint32_t lang_id) -> void {
        if (budget_exceeded) {
            return;
        }
        if (depth > 3u) {
            res.directory_malformed = true;
            res.warnings.emplace_back("PE resource directory exceeds 3-level hierarchy depth");
            return;
        }
        for (std::uint32_t d = 0u; d < depth; ++d) {
            if (path_offsets[d] == rel_dir_off) {
                res.directory_malformed = true;
                res.warnings.emplace_back("Cycle detected in PE resource directory tree");
                return;
            }
        }
        if (visited_steps >= kMaxResourceVisits) {
            mark_budget_exceeded();
            return;
        }
        ++visited_steps;
        path_offsets[depth] = rel_dir_off;

        if (!fits_range(rel_dir_off, 16u, res.directory_size) ||
            !fits_range(root_off, rel_dir_off + 16u, raw_bytes.size())) {
            res.directory_truncated = true;
            res.warnings.emplace_back("Subdirectory offset in PE resource table falls outside declared bounds");
            return;
        }

        const std::size_t dir_pos = static_cast<std::size_t>(root_off + rel_dir_off);
        const std::uint16_t named_count = rd16_le(raw_bytes, dir_pos + 12u);
        const std::uint16_t id_count = rd16_le(raw_bytes, dir_pos + 14u);
        const std::uint64_t total_entries =
            static_cast<std::uint64_t>(named_count) + static_cast<std::uint64_t>(id_count);

        for (std::uint64_t i = 0u; i < total_entries; ++i) {
            if (budget_exceeded) {
                break;
            }
            if (visited_steps >= kMaxResourceVisits) {
                mark_budget_exceeded();
                break;
            }
            ++visited_steps;
            const std::uint64_t rel_entry_off = rel_dir_off + 16u + i * 8u;
            if (!fits_range(rel_entry_off, 8u, res.directory_size) ||
                !fits_range(root_off, rel_entry_off + 8u, raw_bytes.size())) {
                res.directory_truncated = true;
                res.warnings.emplace_back("PE resource directory entry table is truncated");
                break;
            }

            const std::size_t entry_pos = static_cast<std::size_t>(root_off + rel_entry_off);
            const std::uint32_t raw_name = rd32_le(raw_bytes, entry_pos);
            const std::uint32_t raw_target = rd32_le(raw_bytes, entry_pos + 4u);
            const bool is_named = (raw_name & 0x8000'0000u) != 0u;
            const std::uint32_t id_val = raw_name & 0x7FFF'FFFFu;
            const bool target_is_dir = (raw_target & 0x8000'0000u) != 0u;
            const std::uint32_t target_rel = raw_target & 0x7FFF'FFFFu;

            const std::uint32_t next_type = (depth == 0u) ? id_val : type_id;
            const bool next_type_named = (depth == 0u) ? is_named : type_named;
            const std::uint32_t next_name = (depth == 1u) ? id_val : name_id;
            const bool next_name_named = (depth == 1u) ? is_named : name_named;
            const std::uint32_t next_lang = (depth >= 2u) ? id_val : lang_id;

            if (target_is_dir) {
                self(self,
                     target_rel,
                     depth + 1u,
                     next_type,
                     next_type_named,
                     next_name,
                     next_name_named,
                     next_lang);
                continue;
            }

            if (!fits_range(target_rel, 16u, res.directory_size) ||
                !fits_range(root_off, target_rel + 16u, raw_bytes.size())) {
                res.directory_truncated = true;
                res.warnings.emplace_back("IMAGE_RESOURCE_DATA_ENTRY falls outside PE resource bounds");
                continue;
            }

            const std::size_t data_pos = static_cast<std::size_t>(root_off + target_rel);
            RawPeResourceLeaf leaf;
            leaf.type_id = next_type;
            leaf.name_id = next_name;
            leaf.language_id = next_lang;
            leaf.type_is_named = next_type_named;
            leaf.name_is_named = next_name_named;
            leaf.data_rva = rd32_le(raw_bytes, data_pos);
            leaf.size = rd32_le(raw_bytes, data_pos + 4u);
            leaf.code_page = rd32_le(raw_bytes, data_pos + 8u);
            leaf.entry_file_offset = root_off + target_rel;
            if (leaf.data_rva != 0u &&
                base_va <= std::numeric_limits<std::uint64_t>::max() - leaf.data_rva) {
                leaf.data_file_offset = image.virtual_address_to_file_offset(base_va + leaf.data_rva);
            }
            res.leaves.push_back(leaf);
        }
    };

    walk(walk, 0u, 0u, 0u, false, 0u, false, 0u);
    return res;
}

// ---------------------------------------------------------------------------
// PE `RT_MANIFEST` Bounded Non-Networked XML Parser
// ---------------------------------------------------------------------------

[[nodiscard]] std::string_view strip_xml_ns(std::string_view qname) noexcept {
    const std::size_t colon = qname.rfind(':');
    return colon == std::string_view::npos ? qname : qname.substr(colon + 1u);
}

[[nodiscard]] std::string decode_xml_entities(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0u; i < text.size(); ++i) {
        if (text[i] != '&') {
            out.push_back(text[i]);
            continue;
        }
        const std::size_t semi = text.find(';', i + 1u);
        if (semi == std::string_view::npos || semi - i > 12u) {
            out.push_back(text[i]);
            continue;
        }
        const std::string_view ent = text.substr(i + 1u, semi - (i + 1u));
        if (ent == "amp") {
            out.push_back('&');
        } else if (ent == "lt") {
            out.push_back('<');
        } else if (ent == "gt") {
            out.push_back('>');
        } else if (ent == "quot") {
            out.push_back('"');
        } else if (ent == "apos") {
            out.push_back('\'');
        } else if (ent.size() >= 2u && ent[0] == '#') {
            std::uint32_t cp = 0u;
            bool ok = false;
            if (ent[1] == 'x' || ent[1] == 'X') {
                const std::string_view hex = ent.substr(2u);
                const auto [p, ec] = std::from_chars(hex.data(), hex.data() + hex.size(), cp, 16);
                ok = (ec == std::errc{} && p == hex.data() + hex.size());
            } else {
                const std::string_view dec = ent.substr(1u);
                const auto [p, ec] = std::from_chars(dec.data(), dec.data() + dec.size(), cp, 10);
                ok = (ec == std::errc{} && p == dec.data() + dec.size());
            }
            if (ok && cp != 0u) {
                append_utf8_codepoint(out, cp);
            } else {
                out.append(text.substr(i, semi - i + 1u));
            }
        } else {
            out.append(text.substr(i, semi - i + 1u));
        }
        i = semi;
    }
    return out;
}

[[nodiscard]] std::optional<bool> parse_xml_bool(std::string_view val) noexcept {
    const std::string_view trimmed = trim_ascii(val);
    const auto iequals = [](std::string_view a, std::string_view lower_b) noexcept -> bool {
        if (a.size() != lower_b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            const char c = (a[i] >= 'A' && a[i] <= 'Z') ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
            if (c != lower_b[i]) return false;
        }
        return true;
    };
    if (iequals(trimmed, "true") || trimmed == "1" || iequals(trimmed, "yes")) {
        return true;
    }
    if (iequals(trimmed, "false") || trimmed == "0" || iequals(trimmed, "no")) {
        return false;
    }
    return std::nullopt;
}

[[nodiscard]] std::string lookup_supported_os_friendly_name(std::string_view guid_raw) {
    const std::string low = ascii_lower(trim_ascii(guid_raw));
    if (low == "{e2011457-1546-43c5-a5fe-008deee3d3f0}") return "Windows Vista / Server 2008";
    if (low == "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}") return "Windows 7 / Server 2008 R2";
    if (low == "{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}") return "Windows 8 / Server 2012";
    if (low == "{1f676c76-80e1-4239-95bb-83d0f6d0da78}") return "Windows 8.1 / Server 2012 R2";
    if (low == "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}") return "Windows 10 / Windows 11 / Server 2016+";
    return "Unrecognized Compatibility GUID";
}

[[nodiscard]] bool parse_manifest_xml_into(std::string_view xml, PeManifestInfo& info) {
    bool structural_error = false;
    bool saw_root_element = false;
    std::vector<std::string> open_tags;

    auto inside_tag = [&](std::string_view local_name) noexcept -> bool {
        for (const std::string& t : open_tags) {
            if (t == local_name) {
                return true;
            }
        }
        return false;
    };

    std::size_t pos = 0u;
    std::string pending_text;

    auto flush_text_for_current_tag = [&]() {
        if (open_tags.empty()) {
            pending_text.clear();
            return;
        }
        const std::string decoded = decode_xml_entities(trim_ascii(pending_text));
        pending_text.clear();
        if (decoded.empty()) {
            return;
        }
        const std::string& cur = open_tags.back();
        if (cur == "dpiaware") {
            info.dpi_aware = decoded;
        } else if (cur == "dpiawareness") {
            info.dpi_awareness = decoded;
        } else if (cur == "longpathaware") {
            info.long_path_aware = parse_xml_bool(decoded);
        } else if (cur == "heaptype") {
            info.heap_type = decoded;
        } else if (cur == "autoelevate") {
            info.auto_elevate = parse_xml_bool(decoded);
        } else if (cur == "disabletheming") {
            info.disable_theming = parse_xml_bool(decoded);
        } else if (cur == "printerdriverisolation") {
            info.printer_driver_isolation = parse_xml_bool(decoded);
        }
    };

    while (pos < xml.size()) {
        const std::size_t lt = xml.find('<', pos);
        if (lt == std::string_view::npos) {
            pending_text.append(xml.substr(pos));
            break;
        }
        pending_text.append(xml.substr(pos, lt - pos));

        if (lt + 1u >= xml.size()) {
            structural_error = true;
            info.warnings.emplace_back("Trailing '<' at end of RT_MANIFEST XML");
            break;
        }

        // XML Comment <!-- ... -->
        if (xml.substr(lt).starts_with("<!--")) {
            const std::size_t end_comment = xml.find("-->", lt + 4u);
            if (end_comment == std::string_view::npos) {
                structural_error = true;
                info.warnings.emplace_back("Unclosed XML comment in RT_MANIFEST");
                break;
            }
            pos = end_comment + 3u;
            continue;
        }

        // CDATA <![CDATA[ ... ]]>
        if (xml.substr(lt).starts_with("<![CDATA[")) {
            const std::size_t end_cdata = xml.find("]]>", lt + 9u);
            if (end_cdata == std::string_view::npos) {
                structural_error = true;
                info.warnings.emplace_back("Unclosed CDATA section in RT_MANIFEST");
                break;
            }
            pending_text.append(xml.substr(lt + 9u, end_cdata - (lt + 9u)));
            pos = end_cdata + 3u;
            continue;
        }

        // Processing instruction <?xml ... ?>
        if (xml[lt + 1u] == '?') {
            const std::size_t end_pi = xml.find("?>", lt + 2u);
            if (end_pi == std::string_view::npos) {
                structural_error = true;
                info.warnings.emplace_back("Unclosed XML processing instruction in RT_MANIFEST");
                break;
            }
            pos = end_pi + 2u;
            continue;
        }

        // DOCTYPE / ENTITY declaration (explicitly non-networked: skip safely, warn on SYSTEM/PUBLIC)
        if (xml[lt + 1u] == '!') {
            std::size_t scan = lt + 2u;
            int bracket_depth = 0;
            char quote = '\0';
            while (scan < xml.size()) {
                const char c = xml[scan];
                if (quote != '\0') {
                    if (c == quote) quote = '\0';
                } else if (c == '"' || c == '\'') {
                    quote = c;
                } else if (c == '[') {
                    ++bracket_depth;
                } else if (c == ']' && bracket_depth > 0) {
                    --bracket_depth;
                } else if (c == '>' && bracket_depth == 0) {
                    break;
                }
                ++scan;
            }
            if (scan >= xml.size()) {
                structural_error = true;
                info.warnings.emplace_back("Unclosed XML declaration in RT_MANIFEST");
                break;
            }
            const std::string decl_low = ascii_lower(xml.substr(lt, scan - lt + 1u));
            if (decl_low.find("system") != std::string::npos ||
                decl_low.find("public") != std::string::npos ||
                decl_low.find("<!entity") != std::string::npos) {
                info.warnings.emplace_back(
                    "External DTD/ENTITY declaration ignored by non-networked manifest parser");
            }
            pos = scan + 1u;
            continue;
        }

        // Regular opening, closing, or self-closing element tag: find matching '>' outside quotes
        std::size_t gt = lt + 1u;
        char quote = '\0';
        while (gt < xml.size()) {
            const char c = xml[gt];
            if (quote != '\0') {
                if (c == quote) quote = '\0';
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                break;
            } else if (c == '<') {
                structural_error = true;
                info.warnings.emplace_back("Nested '<' inside XML tag in RT_MANIFEST");
                break;
            }
            ++gt;
        }
        if (gt >= xml.size() || xml[gt] != '>') {
            structural_error = true;
            info.warnings.emplace_back("Unclosed XML element tag in RT_MANIFEST");
            break;
        }

        std::string_view inner = trim_ascii(xml.substr(lt + 1u, gt - (lt + 1u)));
        pos = gt + 1u;
        if (inner.empty()) {
            structural_error = true;
            info.warnings.emplace_back("Empty '<>' tag in RT_MANIFEST");
            continue;
        }

        if (inner.front() == '/') {
            flush_text_for_current_tag();
            const std::string close_local = ascii_lower(strip_xml_ns(trim_ascii(inner.substr(1u))));
            if (open_tags.empty() || open_tags.back() != close_local) {
                structural_error = true;
                info.warnings.push_back(
                    std::format("Mismatched closing XML tag '</{}>' in RT_MANIFEST", close_local));
                if (const auto it = std::ranges::find(open_tags, close_local); it != open_tags.end()) {
                    open_tags.erase(it, open_tags.end());
                }
            } else {
                open_tags.pop_back();
            }
            continue;
        }

        pending_text.clear();
        bool self_closing = false;
        if (inner.back() == '/') {
            self_closing = true;
            inner = trim_ascii(inner.substr(0u, inner.size() - 1u));
        }

        std::size_t name_end = 0u;
        while (name_end < inner.size() &&
               inner[name_end] != ' ' && inner[name_end] != '\t' &&
               inner[name_end] != '\r' && inner[name_end] != '\n' &&
               inner[name_end] != '=') {
            ++name_end;
        }
        if (name_end == 0u) {
            structural_error = true;
            info.warnings.emplace_back("Malformed tag name in RT_MANIFEST");
            continue;
        }

        const std::string local_tag = ascii_lower(strip_xml_ns(inner.substr(0u, name_end)));
        saw_root_element = true;

        // Parse attributes
        std::vector<std::pair<std::string, std::string>> attrs;
        std::size_t cur = name_end;
        while (cur < inner.size()) {
            while (cur < inner.size() &&
                   (inner[cur] == ' ' || inner[cur] == '\t' || inner[cur] == '\r' || inner[cur] == '\n')) {
                ++cur;
            }
            if (cur >= inner.size()) break;

            const std::size_t attr_start = cur;
            while (cur < inner.size() &&
                   inner[cur] != '=' && inner[cur] != ' ' &&
                   inner[cur] != '\t' && inner[cur] != '\r' && inner[cur] != '\n') {
                ++cur;
            }
            const std::string attr_name = ascii_lower(strip_xml_ns(inner.substr(attr_start, cur - attr_start)));
            while (cur < inner.size() &&
                   (inner[cur] == ' ' || inner[cur] == '\t' || inner[cur] == '\r' || inner[cur] == '\n')) {
                ++cur;
            }
            if (cur >= inner.size() || inner[cur] != '=') {
                structural_error = true;
                info.warnings.push_back(
                    std::format("Attribute '{}' missing '=' in RT_MANIFEST", attr_name));
                break;
            }
            ++cur;
            while (cur < inner.size() &&
                   (inner[cur] == ' ' || inner[cur] == '\t' || inner[cur] == '\r' || inner[cur] == '\n')) {
                ++cur;
            }
            if (cur >= inner.size() || (inner[cur] != '"' && inner[cur] != '\'')) {
                structural_error = true;
                info.warnings.push_back(
                    std::format("Attribute '{}' missing quoted value in RT_MANIFEST", attr_name));
                break;
            }
            const char q = inner[cur++];
            const std::size_t val_start = cur;
            while (cur < inner.size() && inner[cur] != q) {
                ++cur;
            }
            if (cur >= inner.size()) {
                structural_error = true;
                info.warnings.push_back(
                    std::format("Unclosed attribute value for '{}' in RT_MANIFEST", attr_name));
                break;
            }
            attrs.emplace_back(attr_name, decode_xml_entities(inner.substr(val_start, cur - val_start)));
            ++cur;
        }

        auto get_attr = [&](std::string_view key) -> std::string_view {
            for (const auto& [k, v] : attrs) {
                if (k == key) return v;
            }
            return {};
        };

        if (local_tag == "requestedexecutionlevel") {
            if (const std::string_view lvl = get_attr("level"); !lvl.empty()) {
                info.requested_execution_level = std::string(lvl);
            }
            if (const std::string_view uia = get_attr("uiaccess"); !uia.empty()) {
                info.ui_access = parse_xml_bool(uia);
            }
        } else if (local_tag == "supportedos") {
            if (const std::string_view guid = get_attr("id"); !guid.empty()) {
                info.supported_os.push_back(PeSupportedOsEntry{
                    .guid = std::string(guid),
                    .friendly_name = lookup_supported_os_friendly_name(guid),
                });
            }
        } else if (local_tag == "assemblyidentity") {
            PeAssemblyIdentity ident;
            ident.name = std::string(get_attr("name"));
            ident.version = std::string(get_attr("version"));
            ident.processor_architecture = std::string(get_attr("processorarchitecture"));
            ident.type = std::string(get_attr("type"));
            ident.public_key_token = std::string(get_attr("publickeytoken"));
            ident.language = std::string(get_attr("language"));
            if (inside_tag("dependentassembly") || inside_tag("dependency")) {
                info.dependent_assemblies.push_back(std::move(ident));
            } else if (!info.assembly_identity.has_value()) {
                info.assembly_identity = std::move(ident);
            }
        }

        if (!self_closing) {
            open_tags.push_back(local_tag);
        }
    }

    if (!saw_root_element) {
        structural_error = true;
        info.warnings.emplace_back("RT_MANIFEST payload contains no XML elements");
    }
    if (!open_tags.empty()) {
        structural_error = true;
        info.warnings.push_back(
            std::format("RT_MANIFEST XML ended with {} unclosed element(s) (innermost '<{}>')",
                        open_tags.size(),
                        open_tags.back()));
    }

    return !structural_error;
}

void extract_pe_manifest(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const PeResourceWalkResult& rsrc,
    const CaptureStamp& stamp,
    ProvenanceTag prov_tag,
    MetadataFieldState& state_out,
    Observed<PeManifestInfo>& out) {
    std::vector<const RawPeResourceLeaf*> manifest_leaves;
    for (const RawPeResourceLeaf& leaf : rsrc.leaves) {
        if (!leaf.type_is_named && leaf.type_id == kPeRtManifest) {
            manifest_leaves.push_back(&leaf);
        }
    }

    if (manifest_leaves.empty()) {
        if (rsrc.directory_malformed) {
            state_out = MetadataFieldState::Malformed;
            out = Observed<PeManifestInfo>::unavailable(
                prov_tag,
                rsrc.warnings.empty() ? "Malformed PE resource directory" : rsrc.warnings.front(),
                stamp);
            return;
        }
        if (rsrc.directory_truncated) {
            state_out = MetadataFieldState::Truncated;
            out = Observed<PeManifestInfo>::unavailable(
                prov_tag,
                rsrc.warnings.empty() ? "Truncated PE resource directory" : rsrc.warnings.front(),
                stamp);
            return;
        }
        state_out = MetadataFieldState::Absent;
        out = Observed<PeManifestInfo>::unavailable(
            prov_tag,
            "No RT_MANIFEST (type 24) resource declared in PE image",
            stamp);
        return;
    }

    const RawPeResourceLeaf& leaf = *manifest_leaves.front();
    const std::uint64_t leaf_va = image.image_base() + leaf.data_rva;
    std::vector<Evidence> evidence = {
        Evidence{
            .tag = prov_tag,
            .source = "pe_rt_manifest",
            .detail = std::format("RT_MANIFEST id={} lang=0x{:04X} size={}",
                                  leaf.name_id,
                                  leaf.language_id,
                                  leaf.size),
            .virtual_address = leaf_va,
            .file_offset = leaf.data_file_offset,
        }};

    if (leaf.size == 0u || !leaf.data_file_offset.has_value() ||
        *leaf.data_file_offset >= raw_bytes.size()) {
        state_out = MetadataFieldState::Truncated;
        out = Observed<PeManifestInfo>::unavailable(
            prov_tag,
            "RT_MANIFEST resource entry points outside readable image bytes",
            stamp);
        out.evidence = std::move(evidence);
        return;
    }

    const std::size_t file_off = static_cast<std::size_t>(*leaf.data_file_offset);
    const std::size_t avail = raw_bytes.size() - file_off;
    bool truncated = false;
    PeManifestInfo info;
    info.resource_name_id = leaf.name_id;
    info.language_id = leaf.language_id;
    info.data_rva = leaf.data_rva;
    info.file_offset = *leaf.data_file_offset;
    info.raw_size = leaf.size;

    if (leaf.size > avail) {
        truncated = true;
        info.warnings.push_back(
            std::format("RT_MANIFEST declared size ({} bytes) exceeds available file bytes ({} bytes)",
                        leaf.size,
                        avail));
    }
    if (leaf.size > kMaxManifestBytes) {
        truncated = true;
        info.warnings.push_back(
            std::format("RT_MANIFEST size ({} bytes) exceeds 1 MiB safety cap; capped at {} bytes",
                        leaf.size,
                        kMaxManifestBytes));
    }

    const std::size_t capped_len = std::min<std::size_t>({static_cast<std::size_t>(leaf.size), avail, kMaxManifestBytes});
    std::span<const std::uint8_t> payload = raw_bytes.subspan(file_off, capped_len);

    bool encoding_malformed = false;
    if (payload.size() >= 3u &&
        payload[0] == 0xEFu && payload[1] == 0xBBu && payload[2] == 0xBFu) {
        info.encoding = "UTF-8-BOM";
        payload = payload.subspan(3u);
        while (!payload.empty() && payload.back() == 0u) {
            payload = payload.subspan(0u, payload.size() - 1u);
        }
        info.raw_xml.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    } else if (payload.size() >= 2u && payload[0] == 0xFFu && payload[1] == 0xFEu) {
        info.encoding = "UTF-16LE";
        payload = payload.subspan(2u);
        if ((payload.size() & 1u) != 0u) {
            encoding_malformed = true;
        }
        info.raw_xml = decode_utf16_units_to_utf8(payload, false, false, &info.warnings);
    } else if (payload.size() >= 2u && payload[0] == 0xFEu && payload[1] == 0xFFu) {
        info.encoding = "UTF-16BE";
        payload = payload.subspan(2u);
        if ((payload.size() & 1u) != 0u) {
            encoding_malformed = true;
        }
        info.raw_xml = decode_utf16_units_to_utf8(payload, true, false, &info.warnings);
    } else if (payload.size() >= 4u && payload[0] == 0x3Cu && payload[1] == 0x00u) {
        info.encoding = "UTF-16LE";
        if ((payload.size() & 1u) != 0u) {
            encoding_malformed = true;
        }
        info.raw_xml = decode_utf16_units_to_utf8(payload, false, false, &info.warnings);
    } else if (payload.size() >= 4u && payload[0] == 0x00u && payload[1] == 0x3Cu) {
        info.encoding = "UTF-16BE";
        if ((payload.size() & 1u) != 0u) {
            encoding_malformed = true;
        }
        info.raw_xml = decode_utf16_units_to_utf8(payload, true, false, &info.warnings);
    } else {
        info.encoding = "UTF-8";
        while (!payload.empty() && payload.back() == 0u) {
            payload = payload.subspan(0u, payload.size() - 1u);
        }
        info.raw_xml.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    }

    const bool xml_ok = parse_manifest_xml_into(info.raw_xml, info);
    for (const std::string& w : rsrc.warnings) {
        info.warnings.push_back(w);
    }
    if (truncated || rsrc.directory_truncated) {
        state_out = MetadataFieldState::Truncated;
        const std::string note = info.warnings.empty() ? "Truncated RT_MANIFEST" : info.warnings.front();
        out = Observed<PeManifestInfo>::partial(
            std::move(info), prov_tag, note, stamp, std::move(evidence));
        return;
    }
    if (!xml_ok || encoding_malformed || rsrc.directory_malformed) {
        state_out = MetadataFieldState::Malformed;
        const std::string note = info.warnings.empty() ? "Malformed RT_MANIFEST XML" : info.warnings.front();
        out = Observed<PeManifestInfo>::partial(
            std::move(info), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    state_out = MetadataFieldState::Present;
    out = Observed<PeManifestInfo>::complete(
        std::move(info), prov_tag, stamp, std::move(evidence));
}

// ---------------------------------------------------------------------------
// PE `RT_VERSION` (`VS_VERSIONINFO` + Localized `StringFileInfo`) Parser
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::string> decode_vs_file_flags(std::uint32_t effective_flags) {
    std::vector<std::string> flags;
    if ((effective_flags & 0x00000001u) != 0u) flags.emplace_back("VS_FF_DEBUG");
    if ((effective_flags & 0x00000002u) != 0u) flags.emplace_back("VS_FF_PRERELEASE");
    if ((effective_flags & 0x00000004u) != 0u) flags.emplace_back("VS_FF_PATCHED");
    if ((effective_flags & 0x00000008u) != 0u) flags.emplace_back("VS_FF_PRIVATEBUILD");
    if ((effective_flags & 0x00000010u) != 0u) flags.emplace_back("VS_FF_INFOINFERRED");
    if ((effective_flags & 0x00000020u) != 0u) flags.emplace_back("VS_FF_SPECIALBUILD");
    return flags;
}

[[nodiscard]] std::string decode_vs_file_os(std::uint32_t os) {
    switch (os) {
        case 0x00040004u: return "VOS_NT_WINDOWS32";
        case 0x00040000u: return "VOS_NT";
        case 0x00000004u: return "VOS__WINDOWS32";
        case 0x00010004u: return "VOS_DOS_WINDOWS32";
        case 0x00000000u: return "VOS_UNKNOWN";
        default:          return std::format("0x{:08X}", os);
    }
}

[[nodiscard]] std::string decode_vs_file_type(std::uint32_t ftype) {
    switch (ftype) {
        case 0x00000001u: return "VFT_APP";
        case 0x00000002u: return "VFT_DLL";
        case 0x00000003u: return "VFT_DRV";
        case 0x00000004u: return "VFT_FONT";
        case 0x00000005u: return "VFT_VXD";
        case 0x00000007u: return "VFT_STATIC_LIB";
        default:          return std::format("0x{:08X}", ftype);
    }
}

struct VsNodeHeader {
    std::uint16_t length{0};
    std::uint16_t value_length{0};
    std::uint16_t type{0};
    std::string key;
    std::size_t value_offset{0};
    std::size_t node_end{0};
};

[[nodiscard]] std::optional<VsNodeHeader> read_vs_node_header(
    std::span<const std::uint8_t> buf,
    std::size_t node_off,
    std::size_t parent_end,
    bool& truncated_out,
    bool& malformed_out,
    std::vector<std::string>& warnings) {
    if ((node_off & 3u) != 0u) {
        malformed_out = true;
        warnings.emplace_back("VS_VERSIONINFO node offset is not 4-byte aligned");
        return std::nullopt;
    }
    if (node_off > parent_end || parent_end - node_off < 6u) {
        truncated_out = true;
        warnings.emplace_back("VS_VERSIONINFO node header is truncated (< 6 bytes)");
        return std::nullopt;
    }

    const std::uint16_t w_len = rd16_le(buf, node_off);
    const std::uint16_t w_val_len = rd16_le(buf, node_off + 2u);
    const std::uint16_t w_type = rd16_le(buf, node_off + 4u);

    if (w_len < 6u) {
        malformed_out = true;
        warnings.push_back(std::format("VS_VERSIONINFO node wLength ({}) is invalid (< 6)", w_len));
        return std::nullopt;
    }
    if (static_cast<std::size_t>(w_len) > parent_end - node_off) {
        truncated_out = true;
        warnings.push_back(
            std::format("VS_VERSIONINFO node wLength ({}) exceeds enclosing block ({} bytes remaining)",
                        w_len,
                        parent_end - node_off));
        return std::nullopt;
    }

    const std::size_t node_end = node_off + static_cast<std::size_t>(w_len);
    const std::size_t key_start = node_off + 6u; // Guaranteed 2-byte aligned since node_off is 4-byte aligned
    std::size_t cursor = key_start;
    bool found_nul = false;
    while (cursor + 2u <= node_end) {
        if (rd16_le(buf, cursor) == 0u) {
            found_nul = true;
            break;
        }
        cursor += 2u;
    }
    if (!found_nul) {
        malformed_out = true;
        warnings.emplace_back("Unterminated or misaligned UTF-16 szKey in VS_VERSIONINFO block");
        return std::nullopt;
    }

    VsNodeHeader hdr;
    hdr.length = w_len;
    hdr.value_length = w_val_len;
    hdr.type = w_type;
    hdr.key = decode_utf16_units_to_utf8(
        buf.subspan(key_start, cursor - key_start), false, false, &warnings);
    const auto aligned_val = align4_checked(cursor + 2u);
    if (!aligned_val.has_value() || *aligned_val > node_end) {
        hdr.value_offset = node_end;
    } else {
        hdr.value_offset = static_cast<std::size_t>(*aligned_val);
    }
    hdr.node_end = node_end;
    return hdr;
}

void parse_single_vs_version_resource(
    std::span<const std::uint8_t> buf,
    std::uint32_t resource_lang_id,
    PeVersionInfo& out_info,
    bool& truncated_out,
    bool& malformed_out) {
    const auto root = read_vs_node_header(
        buf, 0u, buf.size(), truncated_out, malformed_out, out_info.warnings);
    if (!root.has_value()) {
        return;
    }
    if (root->key != "VS_VERSION_INFO") {
        malformed_out = true;
        out_info.warnings.push_back(
            std::format("Unexpected VS_VERSIONINFO root key '{}' (expected 'VS_VERSION_INFO')",
                        root->key));
        return;
    }

    std::size_t children_off = root->value_offset;
    if (root->value_length > 0u) {
        if (root->value_length < 52u) {
            malformed_out = true;
            out_info.warnings.push_back(
                std::format("VS_FIXEDFILEINFO value length ({}) is smaller than 52 bytes",
                            root->value_length));
            return;
        }
        if (static_cast<std::size_t>(root->value_length) > root->node_end - root->value_offset) {
            truncated_out = true;
            out_info.warnings.emplace_back("VS_FIXEDFILEINFO extends past VS_VERSION_INFO block");
            return;
        }
        const std::size_t fpos = root->value_offset;
        const std::uint32_t sig = rd32_le(buf, fpos);
        if (sig != kVsFixedFileInfoSignature) {
            malformed_out = true;
            out_info.warnings.push_back(
                std::format("Invalid VS_FIXEDFILEINFO signature 0x{:08X} (expected 0xFEEF04BD)",
                            sig));
            return;
        }

        if (!out_info.fixed_info.has_value()) {
            PeFixedFileInfo fi;
            fi.signature = sig;
            fi.struct_version = rd32_le(buf, fpos + 4u);
            const std::uint32_t fv_ms = rd32_le(buf, fpos + 8u);
            const std::uint32_t fv_ls = rd32_le(buf, fpos + 12u);
            const std::uint32_t pv_ms = rd32_le(buf, fpos + 16u);
            const std::uint32_t pv_ls = rd32_le(buf, fpos + 20u);
            fi.file_version_major = static_cast<std::uint16_t>(fv_ms >> 16u);
            fi.file_version_minor = static_cast<std::uint16_t>(fv_ms & 0xFFFFu);
            fi.file_version_build = static_cast<std::uint16_t>(fv_ls >> 16u);
            fi.file_version_revision = static_cast<std::uint16_t>(fv_ls & 0xFFFFu);
            fi.product_version_major = static_cast<std::uint16_t>(pv_ms >> 16u);
            fi.product_version_minor = static_cast<std::uint16_t>(pv_ms & 0xFFFFu);
            fi.product_version_build = static_cast<std::uint16_t>(pv_ls >> 16u);
            fi.product_version_revision = static_cast<std::uint16_t>(pv_ls & 0xFFFFu);
            fi.file_version_string = std::format("{}.{}.{}.{}",
                                                 fi.file_version_major,
                                                 fi.file_version_minor,
                                                 fi.file_version_build,
                                                 fi.file_version_revision);
            fi.product_version_string = std::format("{}.{}.{}.{}",
                                                    fi.product_version_major,
                                                    fi.product_version_minor,
                                                    fi.product_version_build,
                                                    fi.product_version_revision);
            fi.file_flags_mask = rd32_le(buf, fpos + 24u);
            fi.file_flags = rd32_le(buf, fpos + 28u);
            fi.decoded_file_flags = decode_vs_file_flags(fi.file_flags & fi.file_flags_mask);
            fi.file_os = rd32_le(buf, fpos + 32u);
            fi.decoded_file_os = decode_vs_file_os(fi.file_os);
            fi.file_type = rd32_le(buf, fpos + 36u);
            fi.decoded_file_type = decode_vs_file_type(fi.file_type);
            fi.file_subtype = rd32_le(buf, fpos + 40u);
            out_info.fixed_info = std::move(fi);
        }

        const auto next_aligned = align4_checked(fpos + static_cast<std::size_t>(root->value_length));
        children_off = (next_aligned.has_value() && *next_aligned <= root->node_end)
            ? static_cast<std::size_t>(*next_aligned)
            : root->node_end;
    }

    while (children_off < root->node_end) {
        if (root->node_end - children_off < 6u) {
            break;
        }
        const auto child = read_vs_node_header(
            buf, children_off, root->node_end, truncated_out, malformed_out, out_info.warnings);
        if (!child.has_value()) {
            break;
        }

        if (child->key == "StringFileInfo") {
            std::size_t table_off = child->value_offset;
            while (table_off < child->node_end) {
                if (child->node_end - table_off < 6u) break;
                const auto tbl = read_vs_node_header(
                    buf, table_off, child->node_end, truncated_out, malformed_out, out_info.warnings);
                if (!tbl.has_value()) break;

                PeStringTableBlock block;
                block.language_codepage_hex = tbl->key;
                block.resource_language_id = resource_lang_id;
                if (tbl->key.size() == 8u) {
                    std::uint32_t packed = 0u;
                    const auto [p, ec] = std::from_chars(
                        tbl->key.data(), tbl->key.data() + tbl->key.size(), packed, 16);
                    if (ec == std::errc{} && p == tbl->key.data() + tbl->key.size()) {
                        block.language_id = static_cast<std::uint16_t>(packed >> 16u);
                        block.code_page = static_cast<std::uint16_t>(packed & 0xFFFFu);
                    } else {
                        malformed_out = true;
                        out_info.warnings.push_back(
                            std::format("Non-hex StringTable key '{}' in StringFileInfo", tbl->key));
                    }
                } else {
                    malformed_out = true;
                    out_info.warnings.push_back(
                        std::format("Invalid StringTable key length '{}' (expected 8 hex digits)", tbl->key));
                }

                std::size_t str_off = tbl->value_offset;
                while (str_off < tbl->node_end) {
                    if (tbl->node_end - str_off < 6u) break;
                    const auto kv = read_vs_node_header(
                        buf, str_off, tbl->node_end, truncated_out, malformed_out, out_info.warnings);
                    if (!kv.has_value()) break;

                    std::string val_str;
                    if (kv->value_length > 0u && kv->value_offset < kv->node_end) {
                        const std::size_t rem_bytes = kv->node_end - kv->value_offset;
                        if ((kv->value_offset & 1u) != 0u) {
                            malformed_out = true;
                            out_info.warnings.emplace_back("Misaligned UTF-16 String value in StringTable");
                        } else {
                            const std::size_t requested_bytes =
                                static_cast<std::size_t>(kv->value_length) * 2u;
                            if (requested_bytes > rem_bytes) {
                                // Note: wValueLength in String is WCHAR count; if it exceeds node_end,
                                // record truncation/malformed diagnostic and bound strictly to rem_bytes.
                                malformed_out = true;
                                out_info.warnings.push_back(
                                    std::format("String '{}' wValueLength ({} WCHARs) exceeds block size ({} bytes)",
                                                kv->key,
                                                kv->value_length,
                                                rem_bytes));
                            }
                            const std::size_t bounded_bytes =
                                std::min<std::size_t>(requested_bytes, rem_bytes & ~std::size_t{1u});
                            val_str = decode_utf16_units_to_utf8(
                                buf.subspan(kv->value_offset, bounded_bytes),
                                false,
                                true,
                                &out_info.warnings);
                        }
                    }
                    block.entries.emplace_back(kv->key, std::move(val_str));

                    const auto next_str = align4_checked(kv->node_end);
                    if (!next_str.has_value() || *next_str <= str_off) break;
                    str_off = static_cast<std::size_t>(*next_str);
                }

                out_info.string_tables.push_back(std::move(block));
                const auto next_tbl = align4_checked(tbl->node_end);
                if (!next_tbl.has_value() || *next_tbl <= table_off) break;
                table_off = static_cast<std::size_t>(*next_tbl);
            }
        } else if (child->key == "VarFileInfo") {
            std::size_t var_off = child->value_offset;
            while (var_off < child->node_end) {
                if (child->node_end - var_off < 6u) break;
                const auto var_hdr = read_vs_node_header(
                    buf, var_off, child->node_end, truncated_out, malformed_out, out_info.warnings);
                if (!var_hdr.has_value()) break;

                if (var_hdr->key == "Translation" && var_hdr->value_offset < var_hdr->node_end) {
                    const std::size_t avail =
                        std::min<std::size_t>(var_hdr->value_length, var_hdr->node_end - var_hdr->value_offset);
                    for (std::size_t off = 0u; off + 4u <= avail; off += 4u) {
                        out_info.translations.push_back(PeVarTranslation{
                            .language_id = rd16_le(buf, var_hdr->value_offset + off),
                            .code_page = rd16_le(buf, var_hdr->value_offset + off + 2u),
                        });
                    }
                }

                const auto next_var = align4_checked(var_hdr->node_end);
                if (!next_var.has_value() || *next_var <= var_off) break;
                var_off = static_cast<std::size_t>(*next_var);
            }
        }

        const auto next_child = align4_checked(child->node_end);
        if (!next_child.has_value() || *next_child <= children_off) break;
        children_off = static_cast<std::size_t>(*next_child);
    }
}

void extract_pe_version(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const PeResourceWalkResult& rsrc,
    const CaptureStamp& stamp,
    ProvenanceTag prov_tag,
    MetadataFieldState& state_out,
    Observed<PeVersionInfo>& out) {
    std::vector<const RawPeResourceLeaf*> version_leaves;
    for (const RawPeResourceLeaf& leaf : rsrc.leaves) {
        if (!leaf.type_is_named && leaf.type_id == kPeRtVersion) {
            version_leaves.push_back(&leaf);
        }
    }

    if (version_leaves.empty()) {
        if (rsrc.directory_malformed) {
            state_out = MetadataFieldState::Malformed;
            out = Observed<PeVersionInfo>::unavailable(
                prov_tag,
                rsrc.warnings.empty() ? "Malformed PE resource directory" : rsrc.warnings.front(),
                stamp);
            return;
        }
        if (rsrc.directory_truncated) {
            state_out = MetadataFieldState::Truncated;
            out = Observed<PeVersionInfo>::unavailable(
                prov_tag,
                rsrc.warnings.empty() ? "Truncated PE resource directory" : rsrc.warnings.front(),
                stamp);
            return;
        }
        state_out = MetadataFieldState::Absent;
        out = Observed<PeVersionInfo>::unavailable(
            prov_tag,
            "No RT_VERSION (type 16) resource declared in PE image",
            stamp);
        return;
    }

    PeVersionInfo info;
    std::vector<Evidence> evidence;
    bool any_truncated = false;
    bool any_malformed = false;

    for (std::size_t idx = 0u; idx < version_leaves.size(); ++idx) {
        const RawPeResourceLeaf& leaf = *version_leaves[idx];
        if (idx == 0u) {
            info.data_rva = leaf.data_rva;
            info.file_offset = leaf.data_file_offset.value_or(0u);
            info.raw_size = leaf.size;
        }
        evidence.push_back(Evidence{
            .tag = prov_tag,
            .source = "pe_rt_version",
            .detail = std::format("RT_VERSION id={} lang=0x{:04X} size={}",
                                  leaf.name_id,
                                  leaf.language_id,
                                  leaf.size),
            .virtual_address = image.image_base() + leaf.data_rva,
            .file_offset = leaf.data_file_offset,
        });

        if (leaf.size < 6u || !leaf.data_file_offset.has_value() ||
            *leaf.data_file_offset >= raw_bytes.size()) {
            any_truncated = true;
            info.warnings.emplace_back("RT_VERSION resource entry points outside readable image bytes");
            continue;
        }
        const std::size_t foff = static_cast<std::size_t>(*leaf.data_file_offset);
        const std::size_t avail = raw_bytes.size() - foff;
        if (leaf.size > avail) {
            any_truncated = true;
            info.warnings.push_back(
                std::format("RT_VERSION declared size ({} bytes) exceeds available file bytes ({} bytes)",
                            leaf.size,
                            avail));
            parse_single_vs_version_resource(
                raw_bytes.subspan(foff, avail),
                leaf.language_id,
                info,
                any_truncated,
                any_malformed);
            continue;
        }

        parse_single_vs_version_resource(
            raw_bytes.subspan(foff, leaf.size),
            leaf.language_id,
            info,
            any_truncated,
            any_malformed);
    }

    if (any_truncated) {
        state_out = MetadataFieldState::Truncated;
        const std::string note = info.warnings.empty() ? "Truncated RT_VERSION resource" : info.warnings.front();
        if (info.fixed_info.has_value() || !info.string_tables.empty()) {
            out = Observed<PeVersionInfo>::partial(
                std::move(info), prov_tag, note, stamp, std::move(evidence));
        } else {
            out = Observed<PeVersionInfo>::unavailable(prov_tag, note, stamp);
            out.evidence = std::move(evidence);
        }
        return;
    }
    if (any_malformed) {
        state_out = MetadataFieldState::Malformed;
        const std::string note = info.warnings.empty() ? "Malformed RT_VERSION resource" : info.warnings.front();
        if (info.fixed_info.has_value() || !info.string_tables.empty()) {
            out = Observed<PeVersionInfo>::partial(
                std::move(info), prov_tag, note, stamp, std::move(evidence));
        } else {
            out = Observed<PeVersionInfo>::unavailable(prov_tag, note, stamp);
            out.evidence = std::move(evidence);
        }
        return;
    }

    state_out = MetadataFieldState::Present;
    out = Observed<PeVersionInfo>::complete(
        std::move(info), prov_tag, stamp, std::move(evidence));
}

// ---------------------------------------------------------------------------
// PE CLR (`IMAGE_COR20_HEADER` + Bounded `BSJB` Metadata Root) Extractor
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::string> decode_cor20_flags(std::uint32_t flags) {
    std::vector<std::string> out;
    if ((flags & 0x00000001u) != 0u) out.emplace_back("COMIMAGE_FLAGS_ILONLY");
    if ((flags & 0x00000002u) != 0u) out.emplace_back("COMIMAGE_FLAGS_32BITREQUIRED");
    if ((flags & 0x00000004u) != 0u) out.emplace_back("COMIMAGE_FLAGS_IL_LIBRARY");
    if ((flags & 0x00000008u) != 0u) out.emplace_back("COMIMAGE_FLAGS_STRONGNAMESIGNED");
    if ((flags & 0x00000010u) != 0u) out.emplace_back("COMIMAGE_FLAGS_NATIVE_ENTRYPOINT");
    if ((flags & 0x00010000u) != 0u) out.emplace_back("COMIMAGE_FLAGS_TRACKDEBUGDATA");
    if ((flags & 0x00020000u) != 0u) out.emplace_back("COMIMAGE_FLAGS_32BITPREFERRED");
    return out;
}

void extract_pe_clr(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const CaptureStamp& stamp,
    ProvenanceTag prov_tag,
    MetadataFieldState& state_out,
    Observed<PeClrSummary>& out) {
    const auto& dirs = image.pe_data_directories();
    const bool dir14_declared = (dirs.size() > 14u && (dirs[14].rva != 0u || dirs[14].size != 0u));
    const PeClrHeader* clr = image.pe_clr_header();

    if (!dir14_declared && clr == nullptr) {
        state_out = MetadataFieldState::Absent;
        out = Observed<PeClrSummary>::unavailable(
            prov_tag,
            "No CLR runtime header (Data Directory 14) declared in PE image",
            stamp);
        return;
    }

    if (clr == nullptr) {
        state_out = MetadataFieldState::Truncated;
        std::vector<Evidence> ev;
        if (dirs.size() > 14u) {
            ev.push_back(Evidence{
                .tag = prov_tag,
                .source = "pe_clr_directory",
                .detail = std::format("Data Directory 14 rva=0x{:X} size={} could not be parsed as 72-byte IMAGE_COR20_HEADER",
                                      dirs[14].rva,
                                      dirs[14].size),
                .virtual_address = image.image_base() + dirs[14].rva,
            });
        }
        out = Observed<PeClrSummary>::unavailable(
            prov_tag,
            "Declared CLR Data Directory 14 is truncated or unmapped",
            stamp);
        out.evidence = std::move(ev);
        return;
    }

    PeClrSummary summary;
    summary.header_rva = clr->rva;
    summary.header_file_offset = clr->file_offset;
    summary.header_size = clr->size;
    summary.major_runtime_version = clr->major_runtime_version;
    summary.minor_runtime_version = clr->minor_runtime_version;
    summary.cor20_flags = clr->flags;
    summary.decoded_flags = decode_cor20_flags(clr->flags);
    summary.entry_point_token_or_rva = clr->entry_point_token_or_rva;
    summary.metadata_rva = clr->metadata_rva;
    summary.metadata_size = clr->metadata_size;

    std::vector<Evidence> evidence = {
        Evidence{
            .tag = prov_tag,
            .source = "pe_cor20_header",
            .detail = std::format("IMAGE_COR20_HEADER runtime={}.{} flags=0x{:08X}",
                                  clr->major_runtime_version,
                                  clr->minor_runtime_version,
                                  clr->flags),
            .virtual_address = image.image_base() + clr->rva,
            .file_offset = clr->file_offset,
        }};

    if (clr->metadata_rva == 0u || clr->metadata_size < 16u) {
        state_out = MetadataFieldState::Truncated;
        summary.warnings.emplace_back("CLR header has empty or undersized metadata directory (< 16 bytes)");
        const std::string note = summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary),
            prov_tag,
            note,
            stamp,
            std::move(evidence));
        return;
    }

    if (image.image_base() > std::numeric_limits<std::uint64_t>::max() - clr->metadata_rva) {
        state_out = MetadataFieldState::Malformed;
        summary.warnings.emplace_back("CLR metadata RVA overflows image base");
        const std::string note = summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    const auto meta_off = image.virtual_address_to_file_offset(image.image_base() + clr->metadata_rva);
    if (!meta_off.has_value() || !fits_range(*meta_off, clr->metadata_size, raw_bytes.size())) {
        state_out = MetadataFieldState::Truncated;
        summary.warnings.emplace_back("CLR metadata directory extends outside readable image bytes");
        const std::string note = summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    summary.metadata_file_offset = *meta_off;
    evidence.push_back(Evidence{
        .tag = prov_tag,
        .source = "pe_clr_metadata_root",
        .detail = std::format("CLI metadata root size={} bytes", clr->metadata_size),
        .virtual_address = image.image_base() + clr->metadata_rva,
        .file_offset = *meta_off,
    });

    const std::span<const std::uint8_t> meta = raw_bytes.subspan(
        static_cast<std::size_t>(*meta_off),
        static_cast<std::size_t>(clr->metadata_size));

    const std::uint32_t sig = rd32_le(meta, 0u);
    if (sig != kClrMetadataSignatureBsjb) {
        state_out = MetadataFieldState::Malformed;
        summary.warnings.push_back(
            std::format("Invalid CLI metadata signature 0x{:08X} (expected 0x424A5342 'BSJB')", sig));
        const std::string note = summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }
    summary.metadata_signature_valid = true;

    const std::uint32_t ver_len = rd32_le(meta, 12u);
    const auto aligned_ver_len = align4_checked(ver_len);
    if (!aligned_ver_len.has_value() || !fits_range(16u, *aligned_ver_len + 4u, meta.size())) {
        state_out = MetadataFieldState::Truncated;
        summary.warnings.emplace_back("CLI metadata version string length exceeds declared metadata directory");
        const std::string note = summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    std::size_t ver_actual = 0u;
    while (ver_actual < ver_len && meta[16u + ver_actual] != 0u) {
        ++ver_actual;
    }
    summary.runtime_version_string.assign(
        reinterpret_cast<const char*>(meta.data() + 16u), ver_actual);

    std::size_t cursor = 16u + static_cast<std::size_t>(*aligned_ver_len);
    const std::uint16_t stream_count = rd16_le(meta, cursor + 2u);
    cursor += 4u;

    bool truncated = false;
    bool malformed = false;
    constexpr std::uint16_t kMaxStreams = 64u;
    const std::uint16_t bounded_streams = std::min<std::uint16_t>(stream_count, kMaxStreams);
    if (stream_count > kMaxStreams) {
        malformed = true;
        summary.warnings.push_back(
            std::format("CLI metadata declares {} streams (capped at {})", stream_count, kMaxStreams));
    }

    for (std::uint16_t s = 0u; s < bounded_streams; ++s) {
        if (meta.size() - cursor < 9u) {
            truncated = true;
            summary.warnings.emplace_back("CLI metadata stream directory is truncated");
            break;
        }
        const std::uint32_t s_off = rd32_le(meta, cursor);
        const std::uint32_t s_size = rd32_le(meta, cursor + 4u);
        cursor += 8u;

        const std::size_t name_start = cursor;
        std::size_t name_len = 0u;
        bool found_nul = false;
        while (cursor < meta.size() && name_len < 32u) {
            if (meta[cursor] == 0u) {
                found_nul = true;
                ++cursor;
                break;
            }
            ++cursor;
            ++name_len;
        }
        if (!found_nul) {
            malformed = true;
            summary.warnings.emplace_back("Unterminated stream header name in CLI metadata root");
            break;
        }
        const auto aligned_cursor = align4_checked(cursor);
        if (!aligned_cursor.has_value() || *aligned_cursor > meta.size()) {
            truncated = true;
            summary.warnings.emplace_back("CLI stream header alignment extends past metadata directory");
            break;
        }
        cursor = static_cast<std::size_t>(*aligned_cursor);

        const bool ok_bounds = fits_range(s_off, s_size, meta.size());
        if (!ok_bounds) {
            truncated = true;
            summary.warnings.push_back(
                std::format("CLI stream '{}' (offset=0x{:X}, size=0x{:X}) exceeds metadata directory (0x{:X})",
                            std::string_view(reinterpret_cast<const char*>(meta.data() + name_start), name_len),
                            s_off,
                            s_size,
                            meta.size()));
        }

        summary.streams.push_back(PeClrStreamInfo{
            .name = std::string(reinterpret_cast<const char*>(meta.data() + name_start), name_len),
            .offset = s_off,
            .size = s_size,
            .in_bounds = ok_bounds,
        });
    }

    if (truncated) {
        state_out = MetadataFieldState::Truncated;
        const std::string note = summary.warnings.empty() ? "Truncated PE CLR metadata" : summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }
    if (malformed) {
        state_out = MetadataFieldState::Malformed;
        const std::string note = summary.warnings.empty() ? "Malformed PE CLR metadata" : summary.warnings.front();
        out = Observed<PeClrSummary>::partial(
            std::move(summary), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    state_out = MetadataFieldState::Present;
    out = Observed<PeClrSummary>::complete(
        std::move(summary), prov_tag, stamp, std::move(evidence));
}

// ---------------------------------------------------------------------------
// ELF `ElfDeclaredSettings` Extractor
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::string> split_colon_paths(std::string_view raw) {
    std::vector<std::string> out;
    if (raw.empty()) {
        return out;
    }
    std::size_t start = 0u;
    while (start <= raw.size()) {
        const std::size_t sep = raw.find(':', start);
        if (sep == std::string_view::npos) {
            out.emplace_back(raw.substr(start));
            break;
        }
        out.emplace_back(raw.substr(start, sep - start));
        start = sep + 1u;
    }
    return out;
}

[[nodiscard]] std::string gnu_abi_os_name(std::uint32_t os_id) {
    switch (os_id) {
        case 0u: return "Linux";
        case 1u: return "GNU/Hurd";
        case 2u: return "Solaris";
        case 3u: return "FreeBSD";
        case 4u: return "kNetBSD";
        case 5u: return "Syllable";
        case 6u: return "NaCl";
        default: return std::format("Unknown({})", os_id);
    }
}

[[nodiscard]] std::vector<std::string> decode_elf_dt_flags(std::uint64_t val) {
    std::vector<std::string> out;
    if ((val & 0x00000001ull) != 0u) out.emplace_back("DF_ORIGIN");
    if ((val & 0x00000002ull) != 0u) out.emplace_back("DF_SYMBOLIC");
    if ((val & 0x00000004ull) != 0u) out.emplace_back("DF_TEXTREL");
    if ((val & 0x00000008ull) != 0u) out.emplace_back("DF_BIND_NOW");
    if ((val & 0x00000010ull) != 0u) out.emplace_back("DF_STATIC_TLS");
    return out;
}

[[nodiscard]] std::vector<std::string> decode_elf_dt_flags_1(std::uint64_t val) {
    std::vector<std::string> out;
    if ((val & 0x00000001ull) != 0u) out.emplace_back("DF_1_NOW");
    if ((val & 0x00000002ull) != 0u) out.emplace_back("DF_1_GLOBAL");
    if ((val & 0x00000004ull) != 0u) out.emplace_back("DF_1_GROUP");
    if ((val & 0x00000008ull) != 0u) out.emplace_back("DF_1_NODELETE");
    if ((val & 0x00000010ull) != 0u) out.emplace_back("DF_1_LOADFLTR");
    if ((val & 0x00000020ull) != 0u) out.emplace_back("DF_1_INITFIRST");
    if ((val & 0x00000040ull) != 0u) out.emplace_back("DF_1_NOOPEN");
    if ((val & 0x00000080ull) != 0u) out.emplace_back("DF_1_ORIGIN");
    if ((val & 0x00000100ull) != 0u) out.emplace_back("DF_1_DIRECT");
    if ((val & 0x00000400ull) != 0u) out.emplace_back("DF_1_INTERPOSE");
    if ((val & 0x00000800ull) != 0u) out.emplace_back("DF_1_NODEFLIB");
    if ((val & 0x00001000ull) != 0u) out.emplace_back("DF_1_NODUMP");
    if ((val & 0x08000000ull) != 0u) out.emplace_back("DF_1_PIE");
    if ((val & 0x10000000ull) != 0u) out.emplace_back("DF_1_KMOD");
    if ((val & 0x20000000ull) != 0u) out.emplace_back("DF_1_WEAKFILTER");
    if ((val & 0x40000000ull) != 0u) out.emplace_back("DF_1_NOCOMMON");
    return out;
}

void extract_elf_declared(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const CaptureStamp& stamp,
    ProvenanceTag prov_tag,
    MetadataFieldState& state_out,
    Observed<ElfDeclaredSettings>& out) {
    ElfDeclaredSettings elf;
    std::vector<Evidence> evidence;
    bool truncated = false;
    bool malformed = false;

    for (const std::string& w : image.parse_warnings()) {
        elf.warnings.push_back(w);
        if (w.find("truncated") != std::string::npos || w.find("out of bounds") != std::string::npos) {
            truncated = true;
        } else {
            malformed = true;
        }
    }

    // 1. PT_INTERP check (distinguish absent vs. truncated/unterminated)
    constexpr std::uint32_t kPtInterp = 3u;
    for (const ElfProgramHeader& ph : image.elf_program_headers()) {
        if (ph.type != kPtInterp) continue;
        evidence.push_back(Evidence{
            .tag = prov_tag,
            .source = "elf_pt_interp",
            .detail = std::format("PT_INTERP filesz={}", ph.file_size),
            .virtual_address = ph.virtual_address,
            .file_offset = ph.offset,
        });
        if (ph.file_size == 0u) {
            malformed = true;
            elf.warnings.emplace_back("ELF PT_INTERP program header has zero file_size");
            break;
        }
        if (!raw_bytes.empty()) {
            if (!fits_range(ph.offset, ph.file_size, raw_bytes.size())) {
                truncated = true;
                elf.warnings.emplace_back("ELF PT_INTERP segment extends past end of file");
                break;
            }
            const auto seg = raw_bytes.subspan(
                static_cast<std::size_t>(ph.offset),
                static_cast<std::size_t>(ph.file_size));
            const auto nul_it = std::ranges::find(seg, static_cast<std::uint8_t>(0u));
            if (nul_it == seg.end()) {
                malformed = true;
                elf.warnings.emplace_back("ELF PT_INTERP path is not NUL-terminated within segment bounds");
                elf.interpreter = std::string(reinterpret_cast<const char*>(seg.data()), seg.size());
            } else {
                elf.interpreter = std::string(
                    reinterpret_cast<const char*>(seg.data()),
                    static_cast<std::size_t>(std::distance(seg.begin(), nul_it)));
            }
        } else if (!image.elf_interpreter().empty()) {
            elf.interpreter = std::string(image.elf_interpreter());
        }
        break;
    }

    // Check note section headers for truncation when raw_bytes available
    if (!raw_bytes.empty()) {
        constexpr std::uint32_t kShtNote = 7u;
        for (const ElfSectionHeader& sh : image.elf_section_headers()) {
            if (sh.type == kShtNote && sh.size > 0u &&
                !fits_range(sh.offset, sh.size, raw_bytes.size())) {
                truncated = true;
                elf.warnings.push_back(
                    std::format("ELF note section '{}' (offset=0x{:X}, size=0x{:X}) is truncated",
                                sh.name,
                                sh.offset,
                                sh.size));
            }
        }
    }

    // 2. ELF Notes: `.note.ABI-tag` (GNU type 1) & `.note.gnu.build-id` (GNU type 3)
    const TargetLayout layout = TargetLayout::from_image(image);
    for (const ElfNote& note : image.elf_notes()) {
        if (note.name != "GNU") {
            continue;
        }
        if (note.type == 1u && !elf.abi_tag.has_value()) {
            if (note.descriptor.size() < 16u) {
                truncated = true;
                elf.warnings.push_back(
                    std::format("ELF .note.ABI-tag descriptor is {} bytes (expected >= 16)",
                                note.descriptor.size()));
            } else {
                const EndianReader nr(note.descriptor, layout);
                const auto os_id = nr.read_u32(0u);
                const auto maj = nr.read_u32(4u);
                const auto min = nr.read_u32(8u);
                const auto pat = nr.read_u32(12u);
                if (os_id && maj && min && pat) {
                    ElfAbiTag tag;
                    tag.os_id = *os_id;
                    tag.os_name = gnu_abi_os_name(*os_id);
                    tag.major = *maj;
                    tag.minor = *min;
                    tag.patch = *pat;
                    tag.min_kernel = std::format("{}.{}.{}", *maj, *min, *pat);
                    elf.abi_tag = std::move(tag);
                    evidence.push_back(Evidence{
                        .tag = prov_tag,
                        .source = "elf_note_abi_tag",
                        .detail = std::format("GNU ABI-tag {} {}", elf.abi_tag->os_name, elf.abi_tag->min_kernel),
                    });
                }
            }
        } else if (note.type == 3u && !elf.build_id_hex.has_value()) {
            if (note.descriptor.empty()) {
                malformed = true;
                elf.warnings.emplace_back("ELF .note.gnu.build-id has empty descriptor");
            } else {
                std::string hex;
                hex.reserve(note.descriptor.size() * 2u);
                for (const std::uint8_t b : note.descriptor) {
                    hex += std::format("{:02x}", static_cast<unsigned int>(b));
                }
                elf.build_id_hex = std::move(hex);
                evidence.push_back(Evidence{
                    .tag = prov_tag,
                    .source = "elf_note_build_id",
                    .detail = std::format("GNU Build-ID {}", *elf.build_id_hex),
                });
            }
        }
    }

    // 3. Dynamic Tags (`DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`, `DT_FLAGS`, `DT_FLAGS_1`)
    bool has_dt_bind_now_tag = false;
    for (const ElfDynamicEntry& dyn : image.elf_dynamic_entries()) {
        switch (dyn.tag) {
            case 1ull: // DT_NEEDED
                if (!dyn.needed_library.empty()) {
                    elf.needed_libraries.push_back(dyn.needed_library);
                } else if (!dyn.string_value.empty()) {
                    elf.needed_libraries.push_back(dyn.string_value);
                }
                break;
            case 14ull: // DT_SONAME
                elf.soname = dyn.string_value;
                break;
            case 15ull: // DT_RPATH
                elf.raw_rpath = dyn.string_value;
                elf.rpath_entries = split_colon_paths(dyn.string_value);
                break;
            case 24ull: // DT_BIND_NOW
                has_dt_bind_now_tag = true;
                break;
            case 29ull: // DT_RUNPATH
                elf.raw_runpath = dyn.string_value;
                elf.runpath_entries = split_colon_paths(dyn.string_value);
                break;
            case 30ull: // DT_FLAGS
                elf.dt_flags = dyn.value;
                elf.decoded_dt_flags = decode_elf_dt_flags(dyn.value);
                break;
            case 0x6ffffffbull: // DT_FLAGS_1
                elf.dt_flags_1 = dyn.value;
                elf.decoded_dt_flags_1 = decode_elf_dt_flags_1(dyn.value);
                break;
            default:
                break;
        }
    }

    if (!image.elf_dynamic_entries().empty()) {
        evidence.push_back(Evidence{
            .tag = prov_tag,
            .source = "elf_pt_dynamic",
            .detail = std::format("Parsed {} dynamic tag(s)", image.elf_dynamic_entries().size()),
        });
    }

    const ElfHeader* ehdr = image.elf_header();
    const bool df1_pie = elf.dt_flags_1.has_value() && ((*elf.dt_flags_1 & 0x08000000ull) != 0u);
    const bool et_dyn_exec = (ehdr != nullptr && ehdr->type == 3u && elf.interpreter.has_value());
    elf.is_pie = df1_pie || et_dyn_exec;
    elf.bind_now = has_dt_bind_now_tag ||
                   (elf.dt_flags.has_value() && ((*elf.dt_flags & 0x08ull) != 0u)) ||
                   (elf.dt_flags_1.has_value() && ((*elf.dt_flags_1 & 0x01ull) != 0u));
    elf.no_dlopen = elf.dt_flags_1.has_value() && ((*elf.dt_flags_1 & 0x40ull) != 0u);
    elf.no_delete = elf.dt_flags_1.has_value() && ((*elf.dt_flags_1 & 0x08ull) != 0u);

    if (evidence.empty()) {
        evidence.push_back(Evidence{
            .tag = prov_tag,
            .source = "elf_header",
            .detail = "Static ELF header metadata",
            .file_offset = 0u,
        });
    }

    if (truncated) {
        state_out = MetadataFieldState::Truncated;
        const std::string note = elf.warnings.empty() ? "Truncated ELF declared metadata" : elf.warnings.front();
        out = Observed<ElfDeclaredSettings>::partial(
            std::move(elf), prov_tag, note, stamp, std::move(evidence));
        return;
    }
    if (malformed) {
        state_out = MetadataFieldState::Malformed;
        const std::string note = elf.warnings.empty() ? "Malformed ELF declared metadata" : elf.warnings.front();
        out = Observed<ElfDeclaredSettings>::partial(
            std::move(elf), prov_tag, note, stamp, std::move(evidence));
        return;
    }

    state_out = MetadataFieldState::Present;
    out = Observed<ElfDeclaredSettings>::complete(
        std::move(elf), prov_tag, stamp, std::move(evidence));
}

// ---------------------------------------------------------------------------
// JSON Escaping Helpers
// ---------------------------------------------------------------------------

void append_json_string(std::string& out, std::string_view text) {
    out.push_back('"');
    for (const char raw_ch : text) {
        const auto c = static_cast<unsigned char>(raw_ch);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20u) {
                    out += std::format("\\u{:04x}", static_cast<unsigned int>(c));
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void append_indent(std::string& out, std::size_t spaces) {
    out.append(spaces, ' ');
}

void append_string_array_json(
    std::string& out,
    std::span<const std::string> items) {
    out.push_back('[');
    for (std::size_t i = 0u; i < items.size(); ++i) {
        if (i > 0u) out += ", ";
        append_json_string(out, items[i]);
    }
    out.push_back(']');
}

void append_stamp_json(
    std::string& out,
    const CaptureStamp& stamp,
    std::size_t indent) {
    out += "{\n";
    append_indent(out, indent + 2u);
    out += std::format("\"snapshot_revision\": {},\n", stamp.snapshot_revision);
    append_indent(out, indent + 2u);
    out += "\"captured_at_utc\": ";
    append_json_string(out, stamp.captured_at_utc);
    out += ",\n";
    append_indent(out, indent + 2u);
    out += std::format("\"target_paused\": {},\n", stamp.target_paused ? "true" : "false");
    append_indent(out, indent + 2u);
    out += "\"availability\": ";
    append_json_string(out, to_string(stamp.availability));
    out += "\n";
    append_indent(out, indent);
    out += "}";
}

} // namespace

// ---------------------------------------------------------------------------
// Public API Implementation
// ---------------------------------------------------------------------------

bool is_sensitive_environment_variable(
    std::string_view key,
    std::string_view raw_value) noexcept {
    const std::string_view trimmed_key = trim_ascii(key);
    if (trimmed_key.empty()) {
        return false;
    }

    const auto lower_ch = [](char c) noexcept -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    const auto icontains = [&](std::string_view hay, std::string_view lower_needle) noexcept -> bool {
        if (lower_needle.empty()) return true;
        if (hay.size() < lower_needle.size()) return false;
        const std::size_t limit = hay.size() - lower_needle.size();
        for (std::size_t i = 0; i <= limit; ++i) {
            bool ok = true;
            for (std::size_t j = 0; j < lower_needle.size(); ++j) {
                if (lower_ch(hay[i + j]) != lower_needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    };
    const auto istarts_with = [&](std::string_view hay, std::string_view lower_prefix) noexcept -> bool {
        if (hay.size() < lower_prefix.size()) return false;
        for (std::size_t i = 0; i < lower_prefix.size(); ++i) {
            if (lower_ch(hay[i]) != lower_prefix[i]) return false;
        }
        return true;
    };

    static constexpr std::array<std::string_view, 18> kSensitiveSubstrings = {
        "secret",
        "token",
        "password",
        "passwd",
        "pwd",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "access_key",
        "auth",
        "credential",
        "cookie",
        "session",
        "bearer",
        "conn_str",
        "connection_string",
        "sas_token",
    };

    for (const std::string_view pat : kSensitiveSubstrings) {
        if (icontains(trimmed_key, pat)) {
            return true;
        }
    }

    static constexpr std::array<std::string_view, 6> kSensitivePrefixes = {
        "aws_",
        "azure_",
        "github_",
        "gh_",
        "npm_token",
        "openai_",
    };
    // Conservative security posture: redact AWS_*, AZURE_*, GITHUB_*, GH_* by default per roadmap spec.
    for (const std::string_view pfx : kSensitivePrefixes) {
        if (istarts_with(trimmed_key, pfx)) {
            return true;
        }
    }

    if (!raw_value.empty()) {
        // Credential-bearing URL userinfo `scheme://user:pass@host` or PEM private key header
        if (icontains(raw_value, "-----begin ") &&
            icontains(raw_value, "private key")) {
            return true;
        }
        if (const std::size_t scheme = raw_value.find("://"); scheme != std::string_view::npos) {
            const std::size_t auth_start = scheme + 3u;
            const std::size_t slash = raw_value.find('/', auth_start);
            const std::string_view authority =
                (slash == std::string_view::npos)
                    ? raw_value.substr(auth_start)
                    : raw_value.substr(auth_start, slash - auth_start);
            const std::size_t at = authority.find('@');
            const std::size_t colon = authority.find(':');
            if (at != std::string_view::npos && colon != std::string_view::npos && colon < at) {
                return true;
            }
        }
    }

    return false;
}

EnvironmentVariableEntry format_environment_variable_entry(
    std::string_view key,
    std::string_view raw_value,
    EnvironmentRedactionPolicy policy) {
    EnvironmentVariableEntry entry;
    entry.key = std::string(key);
    entry.raw_length = raw_value.size();

    const bool should_redact =
        policy == EnvironmentRedactionPolicy::RedactAllValues ||
        (policy == EnvironmentRedactionPolicy::RedactSensitiveDefault &&
         is_sensitive_environment_variable(key, raw_value));

    if (should_redact) {
        entry.redacted = true;
        entry.availability = CaptureAvailability::Redacted;
        entry.display_value = std::format("<redacted: {} chars>", raw_value.size());
    } else {
        entry.redacted = false;
        entry.availability = CaptureAvailability::Complete;
        entry.display_value = std::string(raw_value);
    }
    return entry;
}

ExecutableSettingsReport extract_executable_settings(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    const CaptureStamp& static_stamp) {
    ExecutableSettingsReport report;
    report.target_profile = derive_target_profile(&image, nullptr, false, false);

    CaptureStamp eff_stamp = static_stamp;
    if (eff_stamp.snapshot_revision == 0u && eff_stamp.captured_at_utc.empty()) {
        TargetInstanceId tid;
        tid.backend = BackendKind::StaticFile;
        eff_stamp = CaptureStamp::capture_now(tid, 1u, true, CaptureAvailability::Complete);
    }

    const ProvenanceTag prov =
        (eff_stamp.target_id.backend == BackendKind::CrashDumpMinidump ||
         eff_stamp.target_id.backend == BackendKind::CrashDumpElfCore)
            ? ProvenanceTag::CrashDump
            : ((eff_stamp.target_id.backend == BackendKind::LiveNativeReadOnly ||
                eff_stamp.target_id.backend == BackendKind::ActiveDebugger ||
                eff_stamp.target_id.backend == BackendKind::RemoteGdbRsp)
                   ? ProvenanceTag::LiveMemory
                   : ProvenanceTag::DiskFile);

    DeclaredSettings decl;
    decl.format = image.format();
    decl.kind = image.kind();
    decl.architecture = image.architecture();
    decl.endianness = image.endianness();
    decl.is_64bit = image.is_64bit();
    decl.image_base = image.image_base();
    decl.entry_point = image.entry_point();

    // Unique declared library dependencies in deterministic appearance order
    for (const ImportEntry& imp : image.imports()) {
        if (!imp.library.empty() &&
            std::ranges::find(decl.declared_dependencies, imp.library) ==
                decl.declared_dependencies.end()) {
            decl.declared_dependencies.push_back(imp.library);
        }
    }

    if (image.format() == Format::PE) {
        if (const PeHeader* hdr = image.pe_header(); hdr != nullptr) {
            decl.pe_subsystem = hdr->subsystem;
            decl.pe_subsystem_name = pe_subsystem_to_string(hdr->subsystem);
            decl.pe_stack_reserve = hdr->stack_reserve;
            decl.pe_stack_commit = hdr->stack_commit;
            decl.pe_heap_reserve = hdr->heap_reserve;
            decl.pe_heap_commit = hdr->heap_commit;
        }

        const PeResourceWalkResult rsrc = walk_pe_resources_bounded(image, raw_bytes);
        extract_pe_manifest(
            image, raw_bytes, rsrc, eff_stamp, prov, decl.pe_manifest_state, decl.pe_manifest);
        extract_pe_version(
            image, raw_bytes, rsrc, eff_stamp, prov, decl.pe_version_state, decl.pe_version);
        extract_pe_clr(
            image, raw_bytes, eff_stamp, prov, decl.pe_clr_state, decl.pe_clr);

        decl.elf_settings_state = MetadataFieldState::UnsupportedFormat;
        decl.elf_settings = Observed<ElfDeclaredSettings>::unavailable(
            prov, "Target format is PE (ELF dynamic/note metadata not applicable)", eff_stamp);
    } else if (image.format() == Format::ELF) {
        extract_elf_declared(
            image, raw_bytes, eff_stamp, prov, decl.elf_settings_state, decl.elf_settings);
        if (decl.elf_settings.has_value()) {
            for (const std::string& lib : decl.elf_settings.value->needed_libraries) {
                if (std::ranges::find(decl.declared_dependencies, lib) ==
                    decl.declared_dependencies.end()) {
                    decl.declared_dependencies.push_back(lib);
                }
            }
        }

        decl.pe_manifest_state = MetadataFieldState::UnsupportedFormat;
        decl.pe_manifest = Observed<PeManifestInfo>::unavailable(
            prov, "Target format is ELF (PE RT_MANIFEST not applicable)", eff_stamp);
        decl.pe_version_state = MetadataFieldState::UnsupportedFormat;
        decl.pe_version = Observed<PeVersionInfo>::unavailable(
            prov, "Target format is ELF (PE RT_VERSION not applicable)", eff_stamp);
        decl.pe_clr_state = MetadataFieldState::UnsupportedFormat;
        decl.pe_clr = Observed<PeClrSummary>::unavailable(
            prov, "Target format is ELF (PE CLR header not applicable)", eff_stamp);
    }

    const bool any_partial_decl =
        decl.pe_manifest_state == MetadataFieldState::Malformed ||
        decl.pe_manifest_state == MetadataFieldState::Truncated ||
        decl.pe_version_state == MetadataFieldState::Malformed ||
        decl.pe_version_state == MetadataFieldState::Truncated ||
        decl.pe_clr_state == MetadataFieldState::Malformed ||
        decl.pe_clr_state == MetadataFieldState::Truncated ||
        decl.elf_settings_state == MetadataFieldState::Malformed ||
        decl.elf_settings_state == MetadataFieldState::Truncated;

    std::vector<Evidence> decl_ev = {
        Evidence{
            .tag = prov,
            .source = "binary_headers",
            .detail = std::format("{} {} ({})",
                                  to_string(decl.format),
                                  to_string(decl.kind),
                                  to_string(decl.architecture)),
            .file_offset = 0u,
        }};

    if (any_partial_decl) {
        report.declared_in_file = Observed<DeclaredSettings>::partial(
            std::move(decl),
            prov,
            "One or more static metadata blocks are malformed or truncated",
            eff_stamp,
            std::move(decl_ev));
    } else {
        report.declared_in_file = Observed<DeclaredSettings>::complete(
            std::move(decl),
            prov,
            eff_stamp,
            std::move(decl_ev));
    }

    // Static-only loads explicitly mark runtime sections `Unavailable` (never ambiguously blank).
    CaptureStamp runtime_unavail_stamp = eff_stamp;
    runtime_unavail_stamp.availability = CaptureAvailability::Unavailable;

    report.launch_environment = Observed<LaunchEnvironmentSettings>::unavailable(
        ProvenanceTag::ProcOrOsApi,
        "Static binary inspection only; attach to a live process or open a crash dump to observe launch environment",
        runtime_unavail_stamp);

    report.observed_runtime = Observed<ObservedRuntimeConfiguration>::unavailable(
        ProvenanceTag::ProcOrOsApi,
        "Static binary inspection only; attach to a live process or open a crash dump to observe loaded modules, handles, and sockets",
        runtime_unavail_stamp);

    return report;
}

namespace {

[[nodiscard]] constexpr std::string_view strip_deleted_view(std::string_view sv) noexcept {
    constexpr std::string_view kDeletedSuffix = " (deleted)";
    if (sv.ends_with(kDeletedSuffix)) {
        sv.remove_suffix(kDeletedSuffix.size());
    }
    return sv;
}

[[nodiscard]] std::string extract_filename_component(std::string_view raw_path_or_name) {
    const std::string_view cleaned = strip_deleted_view(raw_path_or_name);
    const std::size_t slash = cleaned.find_last_of("/\\");
    const std::string_view base =
        (slash == std::string_view::npos) ? cleaned : cleaned.substr(slash + 1u);
    return std::string(base);
}

[[nodiscard]] std::string normalize_pe_dll_stem(std::string_view name) {
    std::string lower = ascii_lower(extract_filename_component(name));
    if (lower.ends_with(".dll")) {
        lower.resize(lower.size() - 4u);
    }
    return lower;
}

[[nodiscard]] bool pe_declared_matches_loaded(
    std::string_view declared_dll,
    std::string_view loaded_basename) {
    const std::string d_lower = ascii_lower(extract_filename_component(declared_dll));
    const std::string l_lower = ascii_lower(loaded_basename);
    if (d_lower.empty() || l_lower.empty()) {
        return false;
    }
    if (d_lower == l_lower) {
        return true;
    }
    return normalize_pe_dll_stem(d_lower) == normalize_pe_dll_stem(l_lower);
}

[[nodiscard]] bool elf_declared_matches_loaded(
    std::string_view declared_soname,
    std::string_view loaded_basename) noexcept {
    if (declared_soname.empty() || loaded_basename.empty()) {
        return false;
    }
    const std::size_t d_slash = declared_soname.find_last_of("/\\");
    const std::string_view d_base =
        (d_slash == std::string_view::npos) ? declared_soname : declared_soname.substr(d_slash + 1u);
    if (loaded_basename == d_base) {
        return true;
    }
    // Handle symlink-resolved kernel dentry names such as libstdc++.so.6 -> libstdc++.so.6.0.30.
    if (loaded_basename.size() > d_base.size() &&
        loaded_basename.starts_with(d_base) &&
        loaded_basename[d_base.size()] == '.') {
        return true;
    }
    // Handle versioned glibc dentry names such as libc.so.6 -> libc-2.31.so.
    if (const std::size_t so_pos = d_base.find(".so"); so_pos != std::string_view::npos && so_pos > 0u) {
        const std::string_view stem = d_base.substr(0u, so_pos);
        if (loaded_basename.size() > stem.size() + 4u &&
            loaded_basename.starts_with(stem) &&
            loaded_basename[stem.size()] == '-' &&
            loaded_basename.find(".so", stem.size() + 1u) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_main_executable_module(
    const ModuleInfo& mod,
    std::size_t mod_index,
    const std::filesystem::path& main_executable_path,
    Format declared_format) {
    const std::string mod_path_clean =
        std::string(strip_deleted_proc_suffix(mod.path.generic_string()));
    const std::string main_path_clean =
        std::string(strip_deleted_proc_suffix(main_executable_path.generic_string()));
    if (!mod_path_clean.empty() && !main_path_clean.empty()) {
        if (declared_format == Format::PE) {
            if (ascii_lower(mod_path_clean) == ascii_lower(main_path_clean)) {
                return true;
            }
        } else if (mod_path_clean == main_path_clean) {
            return true;
        }
    }

    const std::string mod_base = !mod.path.empty()
                                     ? extract_filename_component(mod.path.generic_string())
                                     : extract_filename_component(mod.name);
    const std::string main_base = extract_filename_component(main_path_clean);
    if (!mod_base.empty() && !main_base.empty()) {
        if (declared_format == Format::PE) {
            if (ascii_lower(mod_base) == ascii_lower(main_base)) {
                return true;
            }
        } else if (mod_base == main_base) {
            return true;
        }
    }

    if (mod_index == 0u && main_base.empty() &&
        declared_format == Format::PE && ascii_lower(mod_base).ends_with(".exe")) {
        return true;
    }
    return false;
}

}  // namespace

EnvironmentVariableEntry parse_and_format_environment_entry(
    std::string_view raw_key_value,
    EnvironmentRedactionPolicy policy) {
    const std::size_t eq = raw_key_value.find('=');
    if (eq == std::string_view::npos) {
        return format_environment_variable_entry(raw_key_value, {}, policy);
    }
    return format_environment_variable_entry(
        raw_key_value.substr(0u, eq),
        raw_key_value.substr(eq + 1u),
        policy);
}

Observed<DeclaredVsLoadedModuleComparison> reconcile_declared_vs_loaded_modules(
    const Observed<DeclaredSettings>& declared_in_file,
    const Observed<std::vector<ModuleInfo>>& loaded_modules,
    const std::filesystem::path& main_executable_path,
    std::span<const std::uint64_t> timeline_proven_dynamic_bases) {
    const ProvenanceTag prov = loaded_modules.provenance;
    if (!loaded_modules.has_value() || loaded_modules.is_unavailable()) {
        CaptureStamp s = loaded_modules.stamp;
        s.availability = CaptureAvailability::Unavailable;
        return Observed<DeclaredVsLoadedModuleComparison>::unavailable(
            prov,
            "Loaded module list unavailable; declared vs loaded module reconciliation skipped.",
            std::move(s));
    }
    if (!declared_in_file.has_value() || declared_in_file.is_unavailable()) {
        CaptureStamp s = loaded_modules.stamp;
        s.availability = CaptureAvailability::Unavailable;
        return Observed<DeclaredVsLoadedModuleComparison>::unavailable(
            prov,
            "Static declared dependency metadata unavailable (disk image not loaded); declared vs loaded reconciliation skipped.",
            std::move(s));
    }

    const DeclaredSettings& decl = *declared_in_file.value;
    const auto& mods = *loaded_modules.value;
    const bool is_pe = (decl.format == Format::PE);

    std::vector<std::string> declared_libs = decl.declared_dependencies;
    const auto push_unique_decl = [&](std::string_view lib) {
        if (lib.empty()) {
            return;
        }
        const bool exists = std::ranges::any_of(declared_libs, [&](const std::string& cur) {
            return is_pe ? (ascii_lower(cur) == ascii_lower(lib)) : (cur == lib);
        });
        if (!exists) {
            declared_libs.emplace_back(lib);
        }
    };

    if (!is_pe && decl.elf_settings.has_value()) {
        for (const std::string& needed : decl.elf_settings.value->needed_libraries) {
            push_unique_decl(needed);
        }
    }

    std::optional<std::string> elf_interp_base{};
    std::optional<std::string> elf_soname{};
    if (!is_pe && decl.elf_settings.has_value()) {
        if (decl.elf_settings.value->interpreter.has_value()) {
            elf_interp_base = extract_filename_component(*decl.elf_settings.value->interpreter);
        }
        if (decl.elf_settings.value->soname.has_value()) {
            elf_soname = *decl.elf_settings.value->soname;
        }
    }

    std::vector<std::string> mod_basenames;
    mod_basenames.reserve(mods.size());
    for (const ModuleInfo& m : mods) {
        const std::string base = !m.path.empty()
                                     ? extract_filename_component(m.path.generic_string())
                                     : extract_filename_component(m.name);
        mod_basenames.push_back(base);
    }

    std::vector<std::uint8_t> mod_accounted(mods.size(), 0u);
    for (std::size_t mi = 0u; mi < mods.size(); ++mi) {
        if (is_main_executable_module(mods[mi], mi, main_executable_path, decl.format)) {
            mod_accounted[mi] = 1u;
            continue;
        }
        if (elf_interp_base.has_value() &&
            elf_declared_matches_loaded(*elf_interp_base, mod_basenames[mi])) {
            mod_accounted[mi] = 1u;
            continue;
        }
        if (elf_soname.has_value() &&
            elf_declared_matches_loaded(*elf_soname, mod_basenames[mi])) {
            mod_accounted[mi] = 1u;
            continue;
        }
    }

    DeclaredVsLoadedModuleComparison cmp{};
    for (const std::string& decl_lib : declared_libs) {
        bool matched_any = false;
        for (std::size_t mi = 0u; mi < mods.size(); ++mi) {
            const bool matches = is_pe
                                     ? pe_declared_matches_loaded(decl_lib, mod_basenames[mi])
                                     : elf_declared_matches_loaded(decl_lib, mod_basenames[mi]);
            if (matches) {
                matched_any = true;
                mod_accounted[mi] = 1u;
            }
        }
        if (matched_any) {
            cmp.matched_declared.push_back(decl_lib);
        } else {
            cmp.missing_declared.push_back(decl_lib);
        }
    }

    bool any_timeline_proven = false;
    for (std::size_t mi = 0u; mi < mods.size(); ++mi) {
        if (mod_accounted[mi] != 0u) {
            continue;
        }
        const ModuleInfo& m = mods[mi];
        const bool proven_dynamic =
            std::ranges::find(timeline_proven_dynamic_bases, m.base_address) !=
            timeline_proven_dynamic_bases.end();
        any_timeline_proven = any_timeline_proven || proven_dynamic;

        UnmatchedLoadedModule um{};
        um.module_name = !m.name.empty() ? m.name : mod_basenames[mi];
        um.path = m.path;
        um.base_address = m.base_address;
        um.provenance_note = proven_dynamic
                                 ? "Observed newly loaded across session snapshots (runtime LoadLibrary/dlopen or late load); not listed in root image declared imports."
                                 : "Loaded in process address space without matching a root executable declared import (may be a transitive dependency, preloaded library, or prior runtime load; not asserted as LoadLibrary/dlopen without snapshot timeline delta).";
        cmp.unmatched_loaded.push_back(std::move(um));
    }

    cmp.runtime_load_proven_by_timeline = any_timeline_proven;
    const bool partial_inputs =
        (loaded_modules.availability != CaptureAvailability::Complete) ||
        (declared_in_file.availability != CaptureAvailability::Complete);

    if (partial_inputs) {
        cmp.summary = std::format(
            "Partial reconciliation: {}/{} root declared dependencies observed loaded ({} not observed in partial capture), {} unmatched loaded module(s).",
            cmp.matched_declared.size(),
            declared_libs.size(),
            cmp.missing_declared.size(),
            cmp.unmatched_loaded.size());
        CaptureStamp s = loaded_modules.stamp;
        s.availability = CaptureAvailability::Partial;
        return Observed<DeclaredVsLoadedModuleComparison>::partial(
            std::move(cmp),
            prov,
            "Loaded module list or static dependency table was partial.",
            std::move(s));
    }

    cmp.summary = std::format(
        "{}/{} root declared dependencies loaded ({} not currently loaded), {} unmatched loaded module(s){}.",
        cmp.matched_declared.size(),
        declared_libs.size(),
        cmp.missing_declared.size(),
        cmp.unmatched_loaded.size(),
        any_timeline_proven ? " (includes timeline-proven runtime load)" : "");

    CaptureStamp s = loaded_modules.stamp;
    s.availability = CaptureAvailability::Complete;
    std::vector<Evidence> ev = {
        Evidence{.tag = declared_in_file.provenance, .source = "declared_dependencies"},
        Evidence{.tag = loaded_modules.provenance, .source = "loaded_modules"},
    };
    return Observed<DeclaredVsLoadedModuleComparison>::complete(
        std::move(cmp), prov, std::move(s), std::move(ev));
}

Observed<LaunchEnvironmentSettings> extract_launch_environment_settings(
    IProcessSession& session,
    const TargetInstanceId& target_id,
    std::uint64_t snapshot_revision,
    const RuntimeSettingsOptions& options,
    const Observed<ProcessSecurityProfile>* pre_captured_security,
    const std::string* fallback_cwd) {
    const bool paused = session.is_suspended() || session.is_crash_dump();
    const ProvenanceTag prov =
        session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::ProcOrOsApi;

    if (!session.is_alive()) {
        const CaptureStamp unavail_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        return Observed<LaunchEnvironmentSettings>::unavailable(
            prov, "Target process is no longer alive.", unavail_stamp);
    }

    LaunchEnvironmentSettings le{};
    if (session.is_crash_dump()) {
        le.capture_origin = EnvironmentCaptureOrigin::CrashDumpState;
    } else if (options.launched_by_session) {
        le.capture_origin = EnvironmentCaptureOrigin::LaunchCaptured;
    } else {
        le.capture_origin = EnvironmentCaptureOrigin::AttachedCurrentState;
    }
    le.redaction_policy = options.redaction_policy;

    const ProcessInfo info = session.info();
    le.executable_path = !options.resolved_executable_path.empty()
                             ? options.resolved_executable_path
                             : info.executable_path;

    // 1. argv
    if (!info.command_line.empty()) {
        const bool windows_cmd_style =
            le.executable_path.generic_string().find(':') != std::string::npos ||
            ascii_lower(le.executable_path.generic_string()).ends_with(".exe");
        std::vector<std::string> args =
            split_command_line_args(info.command_line, windows_cmd_style);
        const CaptureStamp argv_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Complete);
        le.argv = Observed<std::vector<std::string>>::complete(
            std::move(args), prov, argv_stamp);
    } else {
        const CaptureStamp argv_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        le.argv = Observed<std::vector<std::string>>::unavailable(
            prov, "Command-line arguments unavailable for target.", argv_stamp);
    }

    // 2. cwd
    if (!info.working_directory.empty()) {
        const CaptureStamp cwd_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Complete);
        le.cwd = Observed<std::filesystem::path>::complete(
            info.working_directory, prov, cwd_stamp);
    } else if (fallback_cwd != nullptr && !fallback_cwd->empty()) {
        const CaptureStamp cwd_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Complete);
        le.cwd = Observed<std::filesystem::path>::complete(
            std::filesystem::path(*fallback_cwd), ProvenanceTag::LiveMemory, cwd_stamp);
    } else {
        const CaptureStamp cwd_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        le.cwd = Observed<std::filesystem::path>::unavailable(
            prov, "Current working directory unavailable for target.", cwd_stamp);
    }

    // 3. Environment variables (redacted by default unless explicitly opted in)
    ForgivingValue<std::vector<std::string>> raw_env = session.environment_variables();
    if (raw_env.status.has_data() && raw_env.value.has_value()) {
        std::vector<EnvironmentVariableEntry> formatted;
        formatted.reserve(raw_env.value->size());
        std::size_t redacted_count = 0u;
        for (const std::string& kv : *raw_env.value) {
            EnvironmentVariableEntry entry =
                parse_and_format_environment_entry(kv, options.redaction_policy);
            if (entry.redacted) {
                ++redacted_count;
            }
            formatted.push_back(std::move(entry));
        }
        const CaptureAvailability env_avail =
            (raw_env.status.availability == Availability::Partial)
                ? CaptureAvailability::Partial
                : CaptureAvailability::Complete;
        const CaptureStamp env_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, env_avail);
        if (env_avail == CaptureAvailability::Complete) {
            le.environment = Observed<std::vector<EnvironmentVariableEntry>>::complete(
                std::move(formatted), prov, env_stamp);
            if (redacted_count > 0u) {
                le.environment.note = std::format(
                    "{} sensitive environment value(s) redacted under policy {}.",
                    redacted_count,
                    to_string(options.redaction_policy));
            }
        } else {
            le.environment = Observed<std::vector<EnvironmentVariableEntry>>::partial(
                std::move(formatted),
                prov,
                raw_env.status.detail.empty()
                    ? "Environment block partially captured."
                    : raw_env.status.detail,
                env_stamp);
        }
    } else {
        const CaptureStamp env_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        le.environment = Observed<std::vector<EnvironmentVariableEntry>>::unavailable(
            prov,
            raw_env.status.detail.empty()
                ? "Environment block unavailable for target."
                : raw_env.status.detail,
            env_stamp);
    }

    // 4. Security profile
    if (pre_captured_security != nullptr) {
        le.security_profile = *pre_captured_security;
    } else if (options.query_process_internals) {
        ProcessInternalsSnapshot internals = inspect_process_internals(session);
        const CaptureAvailability sec_avail =
            to_capture_availability(internals.security.status.availability);
        const CaptureStamp sec_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, sec_avail);
        le.security_profile = Observed<ProcessSecurityProfile>::from_forgiving(
            std::move(internals.security), prov, sec_stamp);
    } else {
        const CaptureStamp sec_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        le.security_profile = Observed<ProcessSecurityProfile>::unavailable(
            prov, "Security profile query skipped.", sec_stamp);
    }

    const bool any_present =
        !le.argv.is_unavailable() ||
        !le.cwd.is_unavailable() ||
        !le.environment.is_unavailable() ||
        !le.security_profile.is_unavailable();

    const std::string origin_note =
        le.capture_origin == EnvironmentCaptureOrigin::LaunchCaptured
            ? "Captured from debugger-launched target state."
            : (le.capture_origin == EnvironmentCaptureOrigin::CrashDumpState
                   ? "Extracted from post-mortem crash dump state."
                   : "Observed current process state after attach (process cwd/environment may have mutated since initial launch).");

    if (!any_present) {
        const CaptureStamp unavail_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        return Observed<LaunchEnvironmentSettings>::unavailable(
            prov, "Process launch/current environment fields are all unavailable.", unavail_stamp);
    }

    const bool all_complete =
        le.argv.availability == CaptureAvailability::Complete &&
        le.cwd.availability == CaptureAvailability::Complete &&
        le.environment.availability == CaptureAvailability::Complete &&
        le.security_profile.availability == CaptureAvailability::Complete;

    const CaptureStamp overall_stamp = CaptureStamp::capture_now(
        target_id,
        snapshot_revision,
        paused,
        all_complete ? CaptureAvailability::Complete : CaptureAvailability::Partial);

    if (all_complete) {
        auto obs = Observed<LaunchEnvironmentSettings>::complete(
            std::move(le), prov, overall_stamp);
        obs.note = origin_note;
        return obs;
    }
    return Observed<LaunchEnvironmentSettings>::partial(
        std::move(le), prov, origin_note, overall_stamp);
}

void populate_runtime_executable_settings(
    ExecutableSettingsReport& report,
    IProcessSession& session,
    const TargetInstanceId& target_id,
    std::uint64_t snapshot_revision,
    const RuntimeSettingsOptions& options,
    const ProcessInternalsSnapshot* cached_internals,
    const CaptureStamp* cached_internals_stamp,
    std::span<const ModuleInfo> cached_modules,
    const CaptureStamp* cached_modules_stamp,
    const std::string* fallback_cwd) {
    const bool paused = session.is_suspended() || session.is_crash_dump();
    const ProvenanceTag prov =
        session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::ProcOrOsApi;

    std::optional<ProcessInternalsSnapshot> owned_internals{};
    const ProcessInternalsSnapshot* internals_ptr = cached_internals;
    if (internals_ptr == nullptr && options.query_process_internals && session.is_alive()) {
        owned_internals.emplace(inspect_process_internals(session));
        internals_ptr = &*owned_internals;
    }

    Observed<ProcessSecurityProfile> sec_obs{};
    Observed<std::vector<ProcessHandleEntry>> handles_obs{};
    Observed<std::vector<ProcessSocketEntry>> sockets_obs{};

    if (internals_ptr != nullptr) {
        const auto make_stamp = [&](Availability avail) {
            if (cached_internals_stamp != nullptr) {
                CaptureStamp s = *cached_internals_stamp;
                s.availability = to_capture_availability(avail);
                return s;
            }
            return CaptureStamp::capture_now(
                target_id, snapshot_revision, paused, to_capture_availability(avail));
        };
        sec_obs = Observed<ProcessSecurityProfile>::from_forgiving(
            internals_ptr->security, prov, make_stamp(internals_ptr->security.status.availability));
        handles_obs = Observed<std::vector<ProcessHandleEntry>>::from_forgiving(
            internals_ptr->handles, prov, make_stamp(internals_ptr->handles.status.availability));
        sockets_obs = Observed<std::vector<ProcessSocketEntry>>::from_forgiving(
            internals_ptr->sockets, prov, make_stamp(internals_ptr->sockets.status.availability));
    } else {
        const CaptureStamp unavail_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        sec_obs = Observed<ProcessSecurityProfile>::unavailable(
            prov, "Process internals not queried.", unavail_stamp);
        handles_obs = Observed<std::vector<ProcessHandleEntry>>::unavailable(
            prov, "Process handles not queried.", unavail_stamp);
        sockets_obs = Observed<std::vector<ProcessSocketEntry>>::unavailable(
            prov, "Process sockets not queried.", unavail_stamp);
    }

    report.launch_environment = extract_launch_environment_settings(
        session,
        target_id,
        snapshot_revision,
        options,
        &sec_obs,
        fallback_cwd);

    Observed<std::vector<ModuleInfo>> modules_obs{};
    if (cached_modules_stamp != nullptr) {
        std::vector<ModuleInfo> mods_copy(cached_modules.begin(), cached_modules.end());
        CaptureStamp mod_stamp = *cached_modules_stamp;
        if (mod_stamp.availability == CaptureAvailability::Unavailable) {
            modules_obs = Observed<std::vector<ModuleInfo>>::unavailable(
                prov, "Module list unavailable.", mod_stamp);
        } else if (mod_stamp.availability == CaptureAvailability::Partial) {
            modules_obs = Observed<std::vector<ModuleInfo>>::partial(
                std::move(mods_copy), prov, "Module list partially captured.", mod_stamp);
        } else {
            mod_stamp.availability = CaptureAvailability::Complete;
            modules_obs = Observed<std::vector<ModuleInfo>>::complete(
                std::move(mods_copy), prov, mod_stamp);
        }
    } else if (session.is_alive()) {
        if (auto mods_res = session.modules(); mods_res.has_value()) {
            const CaptureStamp mod_stamp = CaptureStamp::capture_now(
                target_id, snapshot_revision, paused, CaptureAvailability::Complete);
            modules_obs = Observed<std::vector<ModuleInfo>>::complete(
                std::move(*mods_res), prov, mod_stamp);
        } else {
            const CaptureStamp mod_stamp = CaptureStamp::capture_now(
                target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
            modules_obs = Observed<std::vector<ModuleInfo>>::unavailable(
                prov, mods_res.error().message, mod_stamp);
        }
    } else {
        const CaptureStamp mod_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        modules_obs = Observed<std::vector<ModuleInfo>>::unavailable(
            prov, "Target process is no longer alive.", mod_stamp);
    }

    const std::filesystem::path main_exe =
        !options.resolved_executable_path.empty()
            ? options.resolved_executable_path
            : session.info().executable_path;

    ObservedRuntimeConfiguration runtime{};
    runtime.loaded_modules = std::move(modules_obs);
    runtime.open_handles = std::move(handles_obs);
    runtime.sockets = std::move(sockets_obs);
    runtime.declared_vs_loaded = reconcile_declared_vs_loaded_modules(
        report.declared_in_file,
        runtime.loaded_modules,
        main_exe,
        options.timeline_proven_dynamic_bases);

    const bool any_rt =
        !runtime.loaded_modules.is_unavailable() ||
        !runtime.open_handles.is_unavailable() ||
        !runtime.sockets.is_unavailable();

    if (!any_rt) {
        const CaptureStamp unavail_stamp = CaptureStamp::capture_now(
            target_id, snapshot_revision, paused, CaptureAvailability::Unavailable);
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::unavailable(
            prov,
            "All runtime collections (modules, handles, sockets) are unavailable.",
            unavail_stamp);
        return;
    }

    const bool all_complete =
        runtime.loaded_modules.availability == CaptureAvailability::Complete &&
        runtime.open_handles.availability == CaptureAvailability::Complete &&
        runtime.sockets.availability == CaptureAvailability::Complete;

    const CaptureStamp rt_stamp = CaptureStamp::capture_now(
        target_id,
        snapshot_revision,
        paused,
        all_complete ? CaptureAvailability::Complete : CaptureAvailability::Partial);

    if (all_complete) {
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::complete(
            std::move(runtime), prov, rt_stamp);
    } else {
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::partial(
            std::move(runtime),
            prov,
            "One or more runtime collections (modules, handles, sockets) are partial or unavailable.",
            rt_stamp);
    }
}

ExecutableSettingsReport extract_executable_settings_for_session(
    const IBinaryImage* image,
    std::span<const std::uint8_t> raw_bytes,
    IProcessSession& session,
    const RuntimeSettingsOptions& options,
    const CaptureStamp& static_stamp) {
    ExecutableSettingsReport report{};
    if (image != nullptr) {
        report = extract_executable_settings(*image, raw_bytes, static_stamp);
    } else {
        const CaptureStamp unavail_static = CaptureStamp::capture_now(
            TargetInstanceId{.backend = BackendKind::StaticFile},
            1u,
            true,
            CaptureAvailability::Unavailable);
        report.declared_in_file = Observed<DeclaredSettings>::unavailable(
            ProvenanceTag::DiskFile,
            "Backing disk executable image unavailable; static declared settings omitted.",
            unavail_static);
    }

    const bool dbg_active = !session.is_read_only() && !session.is_crash_dump();
    report.target_profile = derive_target_profile(image, &session, dbg_active, false);

    TargetInstanceId tid{};
    tid.backend = report.target_profile.backend;
    tid.pid = session.pid();
    if (!session.is_crash_dump() && tid.pid != 0u) {
        tid.creation_identity = query_process_creation_identity(tid.pid);
    }
    if (!tid.creation_identity.has_value()) {
        const auto raw_ptr = reinterpret_cast<std::uintptr_t>(&session);
        tid.session_nonce = raw_ptr != 0u ? static_cast<std::uint64_t>(raw_ptr) : 1u;
    }

    populate_runtime_executable_settings(report, session, tid, 1u, options);
    return report;
}

std::string format_executable_settings_json(
    const ExecutableSettingsReport& report,
    std::size_t base_indent) {
    std::string out;
    out.reserve(8192u);

    const auto line = [&](std::size_t rel_indent, std::string_view text) {
        append_indent(out, base_indent + rel_indent);
        out += text;
        out.push_back('\n');
    };

    out += "{\n";
    line(2u, std::format("\"schema_version\": {},", report.schema_version));

    // 1. declared_in_file
    append_indent(out, base_indent + 2u);
    out += "\"declared_in_file\": {\n";
    line(4u, std::format("\"availability\": \"{}\",", to_string(report.declared_in_file.availability)));
    line(4u, std::format("\"provenance\": \"{}\",", to_string(report.declared_in_file.provenance)));
    append_indent(out, base_indent + 4u);
    out += "\"note\": ";
    append_json_string(out, report.declared_in_file.note);
    out += ",\n";
    append_indent(out, base_indent + 4u);
    out += "\"stamp\": ";
    append_stamp_json(out, report.declared_in_file.stamp, base_indent + 4u);
    out += ",\n";

    if (report.declared_in_file.has_value()) {
        const DeclaredSettings& d = *report.declared_in_file.value;
        line(4u, std::format("\"format\": \"{}\",", to_string(d.format)));
        line(4u, std::format("\"kind\": \"{}\",", to_string(d.kind)));
        line(4u, std::format("\"architecture\": \"{}\",", to_string(d.architecture)));
        line(4u, std::format("\"endianness\": \"{}\",", to_string(d.endianness)));
        line(4u, std::format("\"bits\": {},", d.is_64bit ? 64 : 32));
        line(4u, std::format("\"image_base\": {},", d.image_base));
        line(4u, std::format("\"entry_point\": {},", d.entry_point));

        append_indent(out, base_indent + 4u);
        out += "\"declared_dependencies\": ";
        append_string_array_json(out, d.declared_dependencies);
        out += ",\n";

        if (d.pe_subsystem.has_value()) {
            line(4u, std::format("\"pe_subsystem\": {},", *d.pe_subsystem));
            append_indent(out, base_indent + 4u);
            out += "\"pe_subsystem_name\": ";
            append_json_string(out, d.pe_subsystem_name);
            out += ",\n";
            line(4u, std::format("\"pe_stack_reserve\": {},", d.pe_stack_reserve.value_or(0u)));
            line(4u, std::format("\"pe_stack_commit\": {},", d.pe_stack_commit.value_or(0u)));
            line(4u, std::format("\"pe_heap_reserve\": {},", d.pe_heap_reserve.value_or(0u)));
            line(4u, std::format("\"pe_heap_commit\": {},", d.pe_heap_commit.value_or(0u)));
        }

        // PE Manifest
        append_indent(out, base_indent + 4u);
        out += "\"pe_manifest\": {\n";
        line(6u, std::format("\"state\": \"{}\",", to_string(d.pe_manifest_state)));
        line(6u, std::format("\"availability\": \"{}\",", to_string(d.pe_manifest.availability)));
        append_indent(out, base_indent + 6u);
        out += "\"note\": ";
        append_json_string(out, d.pe_manifest.note);
        if (d.pe_manifest.has_value()) {
            const PeManifestInfo& m = *d.pe_manifest.value;
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"encoding\": ";
            append_json_string(out, m.encoding);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"requested_execution_level\": ";
            append_json_string(out, m.requested_execution_level);
            out += ",\n";
            line(6u, std::format("\"ui_access\": {},",
                                 m.ui_access.has_value() ? (*m.ui_access ? "true" : "false") : "null"));
            append_indent(out, base_indent + 6u);
            out += "\"dpi_aware\": ";
            append_json_string(out, m.dpi_aware);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"dpi_awareness\": ";
            append_json_string(out, m.dpi_awareness);
            out += ",\n";
            line(6u, std::format("\"long_path_aware\": {},",
                                 m.long_path_aware.has_value() ? (*m.long_path_aware ? "true" : "false") : "null"));
            append_indent(out, base_indent + 6u);
            out += "\"heap_type\": ";
            append_json_string(out, m.heap_type);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"supported_os\": [";
            for (std::size_t i = 0u; i < m.supported_os.size(); ++i) {
                if (i > 0u) out += ", ";
                out += "{\"guid\": ";
                append_json_string(out, m.supported_os[i].guid);
                out += ", \"name\": ";
                append_json_string(out, m.supported_os[i].friendly_name);
                out += "}";
            }
            out += "],\n";
            append_indent(out, base_indent + 6u);
            out += "\"dependent_assemblies\": [";
            for (std::size_t i = 0u; i < m.dependent_assemblies.size(); ++i) {
                if (i > 0u) out += ", ";
                out += "{\"name\": ";
                append_json_string(out, m.dependent_assemblies[i].name);
                out += ", \"version\": ";
                append_json_string(out, m.dependent_assemblies[i].version);
                out += ", \"processor_architecture\": ";
                append_json_string(out, m.dependent_assemblies[i].processor_architecture);
                out += "}";
            }
            out += "],\n";
            append_indent(out, base_indent + 6u);
            out += "\"warnings\": ";
            append_string_array_json(out, m.warnings);
        }
        out += "\n";
        line(4u, "},");

        // PE Version
        append_indent(out, base_indent + 4u);
        out += "\"pe_version\": {\n";
        line(6u, std::format("\"state\": \"{}\",", to_string(d.pe_version_state)));
        line(6u, std::format("\"availability\": \"{}\",", to_string(d.pe_version.availability)));
        append_indent(out, base_indent + 6u);
        out += "\"note\": ";
        append_json_string(out, d.pe_version.note);
        if (d.pe_version.has_value()) {
            const PeVersionInfo& v = *d.pe_version.value;
            out += ",\n";
            if (v.fixed_info.has_value()) {
                append_indent(out, base_indent + 6u);
                out += "\"file_version\": ";
                append_json_string(out, v.fixed_info->file_version_string);
                out += ",\n";
                append_indent(out, base_indent + 6u);
                out += "\"product_version\": ";
                append_json_string(out, v.fixed_info->product_version_string);
                out += ",\n";
                append_indent(out, base_indent + 6u);
                out += "\"file_os\": ";
                append_json_string(out, v.fixed_info->decoded_file_os);
                out += ",\n";
                append_indent(out, base_indent + 6u);
                out += "\"file_type\": ";
                append_json_string(out, v.fixed_info->decoded_file_type);
                out += ",\n";
                append_indent(out, base_indent + 6u);
                out += "\"file_flags\": ";
                append_string_array_json(out, v.fixed_info->decoded_file_flags);
                out += ",\n";
            }
            append_indent(out, base_indent + 6u);
            out += "\"string_tables\": [";
            for (std::size_t t = 0u; t < v.string_tables.size(); ++t) {
                if (t > 0u) out += ", ";
                const PeStringTableBlock& blk = v.string_tables[t];
                out += "{\"lang_codepage\": ";
                append_json_string(out, blk.language_codepage_hex);
                out += std::format(", \"language_id\": {}, \"code_page\": {}, \"entries\": {{",
                                   blk.language_id,
                                   blk.code_page);
                for (std::size_t e = 0u; e < blk.entries.size(); ++e) {
                    if (e > 0u) out += ", ";
                    append_json_string(out, blk.entries[e].first);
                    out += ": ";
                    append_json_string(out, blk.entries[e].second);
                }
                out += "}}";
            }
            out += "],\n";
            append_indent(out, base_indent + 6u);
            out += "\"warnings\": ";
            append_string_array_json(out, v.warnings);
        }
        out += "\n";
        line(4u, "},");

        // PE CLR
        append_indent(out, base_indent + 4u);
        out += "\"pe_clr\": {\n";
        line(6u, std::format("\"state\": \"{}\",", to_string(d.pe_clr_state)));
        line(6u, std::format("\"availability\": \"{}\",", to_string(d.pe_clr.availability)));
        append_indent(out, base_indent + 6u);
        out += "\"note\": ";
        append_json_string(out, d.pe_clr.note);
        if (d.pe_clr.has_value()) {
            const PeClrSummary& c = *d.pe_clr.value;
            out += ",\n";
            line(6u, std::format("\"cor20_flags\": {},", c.cor20_flags));
            append_indent(out, base_indent + 6u);
            out += "\"decoded_flags\": ";
            append_string_array_json(out, c.decoded_flags);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"runtime_version\": ";
            append_json_string(out, c.runtime_version_string);
            out += ",\n";
            line(6u, std::format("\"entry_point_token\": {},", c.entry_point_token_or_rva));
            append_indent(out, base_indent + 6u);
            out += "\"streams\": [";
            for (std::size_t i = 0u; i < c.streams.size(); ++i) {
                if (i > 0u) out += ", ";
                out += "{\"name\": ";
                append_json_string(out, c.streams[i].name);
                out += std::format(", \"offset\": {}, \"size\": {}, \"in_bounds\": {}}}",
                                   c.streams[i].offset,
                                   c.streams[i].size,
                                   c.streams[i].in_bounds ? "true" : "false");
            }
            out += "],\n";
            append_indent(out, base_indent + 6u);
            out += "\"warnings\": ";
            append_string_array_json(out, c.warnings);
        }
        out += "\n";
        line(4u, "},");

        // ELF Settings
        append_indent(out, base_indent + 4u);
        out += "\"elf_settings\": {\n";
        line(6u, std::format("\"state\": \"{}\",", to_string(d.elf_settings_state)));
        line(6u, std::format("\"availability\": \"{}\",", to_string(d.elf_settings.availability)));
        append_indent(out, base_indent + 6u);
        out += "\"note\": ";
        append_json_string(out, d.elf_settings.note);
        if (d.elf_settings.has_value()) {
            const ElfDeclaredSettings& e = *d.elf_settings.value;
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"interpreter\": ";
            if (e.interpreter.has_value()) {
                append_json_string(out, *e.interpreter);
            } else {
                out += "null";
            }
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"build_id\": ";
            if (e.build_id_hex.has_value()) {
                append_json_string(out, *e.build_id_hex);
            } else {
                out += "null";
            }
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"abi_tag\": ";
            if (e.abi_tag.has_value()) {
                out += "{\"os\": ";
                append_json_string(out, e.abi_tag->os_name);
                out += ", \"min_kernel\": ";
                append_json_string(out, e.abi_tag->min_kernel);
                out += "}";
            } else {
                out += "null";
            }
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"soname\": ";
            if (e.soname.has_value()) {
                append_json_string(out, *e.soname);
            } else {
                out += "null";
            }
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"rpath\": ";
            append_string_array_json(out, e.rpath_entries);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"runpath\": ";
            append_string_array_json(out, e.runpath_entries);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"dt_flags\": ";
            append_string_array_json(out, e.decoded_dt_flags);
            out += ",\n";
            append_indent(out, base_indent + 6u);
            out += "\"dt_flags_1\": ";
            append_string_array_json(out, e.decoded_dt_flags_1);
            out += ",\n";
            line(6u, std::format("\"is_pie\": {},", e.is_pie ? "true" : "false"));
            line(6u, std::format("\"bind_now\": {},", e.bind_now ? "true" : "false"));
            line(6u, std::format("\"no_dlopen\": {},", e.no_dlopen ? "true" : "false"));
            line(6u, std::format("\"no_delete\": {},", e.no_delete ? "true" : "false"));
            append_indent(out, base_indent + 6u);
            out += "\"warnings\": ";
            append_string_array_json(out, e.warnings);
        }
        out += "\n";
        line(4u, "}");
    } else {
        line(4u, "\"value\": null");
    }
    line(2u, "},");

    // 2. launch_environment
    append_indent(out, base_indent + 2u);
    out += "\"launch_environment\": {\n";
    line(4u, std::format("\"availability\": \"{}\",", to_string(report.launch_environment.availability)));
    line(4u, std::format("\"provenance\": \"{}\",", to_string(report.launch_environment.provenance)));
    append_indent(out, base_indent + 4u);
    out += "\"note\": ";
    append_json_string(out, report.launch_environment.note);
    if (report.launch_environment.has_value()) {
        const LaunchEnvironmentSettings& le = *report.launch_environment.value;
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"capture_origin\": ";
        append_json_string(out, to_string(le.capture_origin));
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"executable_path\": ";
        append_json_string(out, le.executable_path.generic_string());
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"redaction_policy\": ";
        append_json_string(out, to_string(le.redaction_policy));
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"argv\": ";
        if (le.argv.has_value()) {
            append_string_array_json(out, *le.argv.value);
        } else {
            out += "null";
        }
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"cwd\": ";
        if (le.cwd.has_value()) {
            append_json_string(out, le.cwd.value->generic_string());
        } else {
            out += "null";
        }
        out += ",\n";
        append_indent(out, base_indent + 4u);
        out += "\"environment\": [";
        if (le.environment.has_value()) {
            for (std::size_t i = 0u; i < le.environment.value->size(); ++i) {
                if (i > 0u) out += ", ";
                const EnvironmentVariableEntry& ev = (*le.environment.value)[i];
                out += "{\"key\": ";
                append_json_string(out, ev.key);
                out += ", \"value\": ";
                append_json_string(out, ev.display_value);
                out += std::format(", \"redacted\": {}, \"availability\": \"{}\"}}",
                                   ev.redacted ? "true" : "false",
                                   to_string(ev.availability));
            }
        }
        out += "]";
    }
    out += "\n";
    line(2u, "},");

    // 3. observed_runtime
    append_indent(out, base_indent + 2u);
    out += "\"observed_runtime\": {\n";
    line(4u, std::format("\"availability\": \"{}\",", to_string(report.observed_runtime.availability)));
    line(4u, std::format("\"provenance\": \"{}\",", to_string(report.observed_runtime.provenance)));
    append_indent(out, base_indent + 4u);
    out += "\"note\": ";
    append_json_string(out, report.observed_runtime.note);
    if (report.observed_runtime.has_value()) {
        const ObservedRuntimeConfiguration& rt = *report.observed_runtime.value;
        out += ",\n";
        line(4u, std::format("\"loaded_module_count\": {},",
                             rt.loaded_modules.has_value() ? rt.loaded_modules.value->size() : 0u));
        line(4u, std::format("\"open_handle_count\": {},",
                             rt.open_handles.has_value() ? rt.open_handles.value->size() : 0u));
        line(4u, std::format("\"socket_count\": {},",
                             rt.sockets.has_value() ? rt.sockets.value->size() : 0u));
        append_indent(out, base_indent + 4u);
        out += "\"declared_vs_loaded\": ";
        if (rt.declared_vs_loaded.has_value()) {
            const DeclaredVsLoadedModuleComparison& cmp = *rt.declared_vs_loaded.value;
            out += "{\"matched_declared\": ";
            append_string_array_json(out, cmp.matched_declared);
            out += ", \"missing_declared\": ";
            append_string_array_json(out, cmp.missing_declared);
            out += std::format(", \"unmatched_loaded_count\": {}, \"runtime_load_proven_by_timeline\": {}}}",
                               cmp.unmatched_loaded.size(),
                               cmp.runtime_load_proven_by_timeline ? "true" : "false");
        } else {
            out += "null";
        }
    }
    out += "\n";
    line(2u, "}");

    append_indent(out, base_indent);
    out += "}";
    return out;
}

} // namespace peelf
