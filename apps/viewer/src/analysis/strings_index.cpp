#include "analysis/strings_index.hpp"

#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <limits>
#include <set>
#include <utility>

namespace viewer {
namespace {

using peelf::append_utf8_codepoint;

[[nodiscard]] constexpr bool is_graphic_codepoint(std::uint32_t cp) noexcept {
    if (cp <= 0x20u || cp == 0x7Fu) {
        return false;
    }
    if (cp >= 0x80u && cp <= 0xA0u) {
        return false;
    }
    return true;
}

struct DecodedUtf8Char {
    std::uint32_t codepoint = 0;
    std::uint8_t byte_len = 0;
};

[[nodiscard]] std::optional<DecodedUtf8Char> decode_printable_utf8(
    std::span<const std::uint8_t> bytes,
    std::size_t pos) noexcept {
    if (pos >= bytes.size()) {
        return std::nullopt;
    }
    const std::uint8_t b0 = bytes[pos];
    if ((b0 >= 0x20u && b0 <= 0x7Eu) || b0 == '\t' || b0 == '\n' || b0 == '\r') {
        return DecodedUtf8Char{.codepoint = b0, .byte_len = 1};
    }

    if (b0 >= 0xC2u && b0 <= 0xDFu) {
        if (pos + 1u >= bytes.size()) return std::nullopt;
        const std::uint8_t b1 = bytes[pos + 1u];
        if ((b1 & 0xC0u) != 0x80u) return std::nullopt;
        const std::uint32_t cp = ((static_cast<std::uint32_t>(b0 & 0x1Fu) << 6u) |
                                  static_cast<std::uint32_t>(b1 & 0x3Fu));
        if (cp < 0x00A0u) return std::nullopt;
        return DecodedUtf8Char{.codepoint = cp, .byte_len = 2};
    }

    if (b0 >= 0xE0u && b0 <= 0xEFu) {
        if (pos + 2u >= bytes.size()) return std::nullopt;
        const std::uint8_t b1 = bytes[pos + 1u];
        const std::uint8_t b2 = bytes[pos + 2u];
        if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u) return std::nullopt;
        if (b0 == 0xE0u && b1 < 0xA0u) return std::nullopt; // overlong
        if (b0 == 0xEDu && b1 >= 0xA0u) return std::nullopt; // UTF-16 surrogates
        const std::uint32_t cp = ((static_cast<std::uint32_t>(b0 & 0x0Fu) << 12u) |
                                  (static_cast<std::uint32_t>(b1 & 0x3Fu) << 6u) |
                                  static_cast<std::uint32_t>(b2 & 0x3Fu));
        if (cp >= 0xE000u && cp <= 0xF8FFu) return std::nullopt; // Private Use Area
        if (cp == 0xFFFDu || cp == 0xFFFEu || cp == 0xFFFFu) return std::nullopt;
        return DecodedUtf8Char{.codepoint = cp, .byte_len = 3};
    }

    if (b0 >= 0xF0u && b0 <= 0xF4u) {
        if (pos + 3u >= bytes.size()) return std::nullopt;
        const std::uint8_t b1 = bytes[pos + 1u];
        const std::uint8_t b2 = bytes[pos + 2u];
        const std::uint8_t b3 = bytes[pos + 3u];
        if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u || (b3 & 0xC0u) != 0x80u) {
            return std::nullopt;
        }
        if (b0 == 0xF0u && b1 < 0x90u) return std::nullopt; // overlong
        if (b0 == 0xF4u && b1 > 0x8Fu) return std::nullopt; // > U+10FFFF
        const std::uint32_t cp = ((static_cast<std::uint32_t>(b0 & 0x07u) << 18u) |
                                  (static_cast<std::uint32_t>(b1 & 0x3Fu) << 12u) |
                                  (static_cast<std::uint32_t>(b2 & 0x3Fu) << 6u) |
                                  static_cast<std::uint32_t>(b3 & 0x3Fu));
        if (cp >= 0xF0000u || (cp & 0xFFFEu) == 0xFFFEu) return std::nullopt;
        return DecodedUtf8Char{.codepoint = cp, .byte_len = 4};
    }

    return std::nullopt;
}

[[nodiscard]] constexpr std::uint16_t read_u16(const std::uint8_t* p, bool little_endian) noexcept {
    return little_endian
        ? static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                     (static_cast<std::uint16_t>(p[1]) << 8u))
        : static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8u) |
                                     static_cast<std::uint16_t>(p[1]));
}

[[nodiscard]] constexpr bool is_printable_utf16_bmp(std::uint16_t u) noexcept {
    if ((u >= 0x0020u && u <= 0x007Eu) || u == '\t' || u == '\n' || u == '\r') {
        return true;
    }
    if (u >= 0x00A0u && u <= 0x06FFu) return true; // Latin-1/Ext, Greek, Cyrillic, Hebrew, Arabic
    if (u >= 0x2000u && u <= 0x27BFu) return true; // Punctuation, Currency, Symbols, Dingbats
    if (u >= 0x3000u && u <= 0x30FFu) return true; // CJK Punctuation, Hiragana, Katakana
    if (u >= 0x4E00u && u <= 0x9FFFu) return true; // CJK Unified Ideographs
    if (u >= 0xAC00u && u <= 0xD7A3u) return true; // Hangul Syllables
    if (u >= 0xFF01u && u <= 0xFF5Eu) return true; // Fullwidth ASCII
    return false;
}

[[nodiscard]] constexpr int utf16_script_bucket(std::uint32_t cp) noexcept {
    if (cp <= 0x024Fu) return 1; // ASCII / Latin
    if (cp >= 0x0370u && cp <= 0x03FFu) return 2; // Greek
    if (cp >= 0x0400u && cp <= 0x052Fu) return 3; // Cyrillic
    if (cp >= 0x0590u && cp <= 0x06FFu) return 4; // Hebrew / Arabic
    if ((cp >= 0x3000u && cp <= 0x30FFu) ||
        (cp >= 0x4E00u && cp <= 0x9FFFu) ||
        (cp >= 0xFF01u && cp <= 0xFF5Eu)) return 5; // Japanese / Chinese
    if (cp >= 0xAC00u && cp <= 0xD7A3u) return 6; // Korean Hangul
    if (cp >= 0x2000u && cp <= 0x27BFu) return 7; // General symbols
    if (cp >= 0x10000u) return 8; // Supplementary (Emoji / Historic)
    return 9;
}

struct Utf16Candidate {
    std::size_t start_offset = 0;
    std::size_t byte_length = 0;
    std::size_t char_length = 0;
    StringEncoding encoding = StringEncoding::Utf16Le;
    bool nul_terminated = false;
    bool has_bom = false;
    std::string preview{};
};

void scan_utf16_orientation(
    std::span<const std::uint8_t> bytes,
    const std::vector<std::uint8_t>& byte_claimed,
    bool little_endian,
    std::uint64_t base_va,
    const StringScanOptions& options,
    bool is_executable_code,
    std::stop_token stop,
    std::vector<Utf16Candidate>& out_candidates) {
    const std::size_t min_len = std::max<std::size_t>(options.min_length, 1u);
    const std::size_t min_graphic = std::min<std::size_t>(min_len, 2u);
    const StringEncoding enc = little_endian ? StringEncoding::Utf16Le : StringEncoding::Utf16Be;

    for (std::size_t parity = 0; parity < 2u; ++parity) {
        if (stop.stop_requested()) {
            return;
        }
        std::size_t pos = parity;
        std::size_t step_counter = 0;
        while (pos + 2u <= bytes.size()) {
            if ((++step_counter & 0xFFFu) == 0u && stop.stop_requested()) {
                return;
            }
            if (byte_claimed[pos] != 0 || byte_claimed[pos + 1u] != 0) {
                pos += 2u;
                continue;
            }

            bool has_bom = false;
            const std::uint16_t first_u16 = read_u16(bytes.data() + pos, little_endian);
            if (first_u16 == 0xFEFFu && pos + 4u <= bytes.size()) {
                has_bom = true;
                pos += 2u;
            }

            const std::size_t run_start = pos;
            std::size_t char_count = 0;
            std::size_t graphic_count = 0;
            std::size_t wide_ascii_or_latin_count = 0;
            std::size_t surrogate_count = 0;
            int dominant_script = 0;
            bool script_coherent = true;
            std::string preview;

            while (pos + 2u <= bytes.size()) {
                if ((++step_counter & 0xFFFu) == 0u && stop.stop_requested()) {
                    return;
                }
                if (byte_claimed[pos] != 0 || byte_claimed[pos + 1u] != 0) {
                    break;
                }
                const std::uint16_t u0 = read_u16(bytes.data() + pos, little_endian);
                if (u0 == 0x0000u) {
                    break;
                }
                std::uint32_t cp = 0;
                std::size_t unit_bytes = 2u;
                if (u0 >= 0xD800u && u0 <= 0xDBFFu) {
                    if (pos + 4u > bytes.size() ||
                        byte_claimed[pos + 2u] != 0 ||
                        byte_claimed[pos + 3u] != 0) {
                        break;
                    }
                    const std::uint16_t u1 = read_u16(bytes.data() + pos + 2u, little_endian);
                    if (u1 < 0xDC00u || u1 > 0xDFFFu) {
                        break;
                    }
                    cp = 0x10000u + (((static_cast<std::uint32_t>(u0 - 0xD800u)) << 10u) |
                                     static_cast<std::uint32_t>(u1 - 0xDC00u));
                    if (cp >= 0xF0000u || (cp & 0xFFFEu) == 0xFFFEu) {
                        break;
                    }
                    unit_bytes = 4u;
                    ++surrogate_count;
                } else if (u0 >= 0xDC00u && u0 <= 0xDFFFu) {
                    break;
                } else {
                    if (!is_printable_utf16_bmp(u0)) {
                        break;
                    }
                    cp = u0;
                }

                pos += unit_bytes;
                ++char_count;
                if (is_graphic_codepoint(cp)) {
                    ++graphic_count;
                }
                if (cp <= 0x024Fu) {
                    ++wide_ascii_or_latin_count;
                } else {
                    const int bucket = utf16_script_bucket(cp);
                    if (bucket != 7 && bucket != 8) {
                        if (dominant_script == 0) {
                            dominant_script = bucket;
                        } else if (dominant_script != bucket) {
                            script_coherent = false;
                        }
                    }
                }
                if (char_count <= options.max_string_chars) {
                    append_utf8_codepoint(preview, cp);
                }
            }

            if (char_count >= min_len && graphic_count >= min_graphic && pos > run_start) {
                const auto run_va = peelf::checked_add_u64(base_va, run_start);
                const std::size_t run_byte_len = pos - run_start;
                if (run_va.has_value() &&
                    peelf::checked_add_u64(*run_va, run_byte_len - 1u).has_value()) {
                    const bool nul_term = (pos + 2u <= bytes.size() &&
                                           read_u16(bytes.data() + pos, little_endian) == 0x0000u);
                    const bool aligned_va = ((*run_va & 1ULL) == 0ULL);

                    bool accept = false;
                    if (wide_ascii_or_latin_count >= min_len ||
                        wide_ascii_or_latin_count * 2u >= char_count) {
                        // High byte 0x00..0x02 across >= min_len units has negligible false-positive rate.
                        accept = !is_executable_code || wide_ascii_or_latin_count >= min_len;
                    } else if (!is_executable_code) {
                        // Non-Latin Unicode (Cyrillic, CJK, Kana, Hangul, Emoji):
                        // require script coherence plus either BOM, NUL termination, surrogate pair,
                        // or narrow-range script (Greek/Cyrillic/Kana) at 2-byte alignment.
                        const bool narrow_script =
                            (dominant_script == 2 || dominant_script == 3 || dominant_script == 4);
                        accept = script_coherent &&
                                 (has_bom || nul_term || surrogate_count > 0 ||
                                  (narrow_script && (aligned_va || run_start == 0)));
                    }

                    if (accept) {
                        out_candidates.push_back(Utf16Candidate{
                            .start_offset = run_start,
                            .byte_length = run_byte_len,
                            .char_length = char_count,
                            .encoding = enc,
                            .nul_terminated = nul_term,
                            .has_bom = has_bom,
                            .preview = std::move(preview),
                        });
                    }
                }
            }

            if (pos == run_start) {
                pos += 2u;
            }
        }
    }
}

bool extract_slice_into(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_va,
    std::optional<std::uint64_t> base_file_offset,
    std::string_view section_or_region_name,
    peelf::Endianness hint_endian,
    const StringScanOptions& options,
    bool is_executable_code,
    std::stop_token stop,
    std::vector<ExtractedString>& out) {
    if (bytes.empty() || stop.stop_requested()) {
        return false;
    }

    bool va_clamped = false;
    const std::uint64_t max_va_offset = std::numeric_limits<std::uint64_t>::max() - base_va;
    if (static_cast<std::uint64_t>(bytes.size() - 1u) > max_va_offset) {
        bytes = bytes.first(static_cast<std::size_t>(max_va_offset + 1ULL));
        va_clamped = true;
    }

    const std::size_t min_len = std::max<std::size_t>(options.min_length, 1u);
    const std::size_t min_graphic = std::min<std::size_t>(min_len, 2u);
    std::vector<std::uint8_t> byte_claimed(bytes.size(), 0u);

    // 1. Scan single-byte ASCII and multi-byte valid UTF-8 runs.
    std::size_t pos = 0;
    std::size_t iter = 0;
    while (pos < bytes.size()) {
        if ((++iter & 0xFFFu) == 0u && stop.stop_requested()) {
            return va_clamped;
        }
        const auto first = decode_printable_utf8(bytes, pos);
        if (!first) {
            ++pos;
            continue;
        }

        const std::size_t start = pos;
        std::size_t char_count = 0;
        std::size_t graphic_count = 0;
        std::size_t ascii_count = 0;
        std::size_t non_ascii_count = 0;
        std::string preview;

        while (pos < bytes.size()) {
            if ((++iter & 0xFFFu) == 0u && stop.stop_requested()) {
                return va_clamped;
            }
            const auto dec = decode_printable_utf8(bytes, pos);
            if (!dec) {
                break;
            }
            pos += dec->byte_len;
            ++char_count;
            if (is_graphic_codepoint(dec->codepoint)) {
                ++graphic_count;
            }
            if (dec->byte_len == 1u) {
                ++ascii_count;
            } else {
                ++non_ascii_count;
            }
            if (char_count <= options.max_string_chars) {
                append_utf8_codepoint(preview, dec->codepoint);
            }
        }

        if (char_count >= min_len && graphic_count >= min_graphic && pos > start) {
            const bool nul_terminated = (pos < bytes.size() && bytes[pos] == 0x00u);
            // Guard against x86 `ret; nop` (C3 90 = U+00D0) merging onto 3 opcode bytes in .text.
            const bool utf8_plausible = (non_ascii_count == 0u) ||
                                        !is_executable_code ||
                                        non_ascii_count >= 2u ||
                                        ascii_count >= min_len ||
                                        nul_terminated;
            const auto entry_va = peelf::checked_add_u64(base_va, start);
            if (utf8_plausible && entry_va.has_value() &&
                peelf::checked_add_u64(*entry_va, (pos - start) - 1u).has_value()) {
                std::fill(byte_claimed.begin() + static_cast<std::ptrdiff_t>(start),
                          byte_claimed.begin() + static_cast<std::ptrdiff_t>(pos),
                          std::uint8_t{1u});
                out.push_back(ExtractedString{
                    .virtual_address = *entry_va,
                    .file_offset = base_file_offset
                        ? peelf::checked_add_u64(*base_file_offset, start)
                        : std::nullopt,
                    .byte_length = pos - start,
                    .char_length = char_count,
                    .encoding = non_ascii_count > 0u ? StringEncoding::Utf8 : StringEncoding::Ascii,
                    .section_or_region_name = std::string(section_or_region_name),
                    .preview = std::move(preview),
                });
            }
        }
    }

    if (stop.stop_requested()) {
        return va_clamped;
    }

    // 2. Scan UTF-16LE and UTF-16BE runs and resolve shifted LE/BE overlaps.
    std::vector<Utf16Candidate> utf16_candidates;
    scan_utf16_orientation(bytes, byte_claimed, true, base_va, options, is_executable_code, stop, utf16_candidates);
    scan_utf16_orientation(bytes, byte_claimed, false, base_va, options, is_executable_code, stop, utf16_candidates);

    if (utf16_candidates.empty() || stop.stop_requested()) {
        return va_clamped;
    }

    const StringEncoding preferred_enc =
        (hint_endian == peelf::Endianness::Big) ? StringEncoding::Utf16Be : StringEncoding::Utf16Le;

    std::ranges::sort(utf16_candidates, [&](const Utf16Candidate& a, const Utf16Candidate& b) {
        if (a.char_length != b.char_length) return a.char_length > b.char_length;
        if (a.has_bom != b.has_bom) return a.has_bom > b.has_bom;
        if (a.nul_terminated != b.nul_terminated) return a.nul_terminated > b.nul_terminated;
        const auto a_va = peelf::checked_add_u64(base_va, a.start_offset);
        const auto b_va = peelf::checked_add_u64(base_va, b.start_offset);
        const bool a_aligned = a_va.has_value() && ((*a_va & 1ULL) == 0ULL);
        const bool b_aligned = b_va.has_value() && ((*b_va & 1ULL) == 0ULL);
        if (a_aligned != b_aligned) return a_aligned > b_aligned;
        const bool a_native = (a.encoding == preferred_enc);
        const bool b_native = (b.encoding == preferred_enc);
        if (a_native != b_native) return a_native > b_native;
        return a.start_offset < b.start_offset;
    });

    std::vector<std::uint8_t> utf16_claimed(bytes.size(), 0u);
    for (auto& cand : utf16_candidates) {
        if ((++iter & 0xFFFu) == 0u && stop.stop_requested()) {
            return va_clamped;
        }
        bool overlaps = false;
        for (std::size_t k = cand.start_offset; k < cand.start_offset + cand.byte_length; ++k) {
            if (utf16_claimed[k] != 0u) {
                overlaps = true;
                break;
            }
        }
        if (overlaps) {
            continue;
        }
        const auto cand_va = peelf::checked_add_u64(base_va, cand.start_offset);
        if (!cand_va.has_value() || cand.byte_length == 0u ||
            !peelf::checked_add_u64(*cand_va, cand.byte_length - 1u).has_value()) {
            continue;
        }
        std::fill(utf16_claimed.begin() + static_cast<std::ptrdiff_t>(cand.start_offset),
                  utf16_claimed.begin() + static_cast<std::ptrdiff_t>(cand.start_offset + cand.byte_length),
                  std::uint8_t{1u});
        out.push_back(ExtractedString{
            .virtual_address = *cand_va,
            .file_offset = base_file_offset
                ? peelf::checked_add_u64(*base_file_offset, cand.start_offset)
                : std::nullopt,
            .byte_length = cand.byte_length,
            .char_length = cand.char_length,
            .encoding = cand.encoding,
            .section_or_region_name = std::string(section_or_region_name),
            .preview = std::move(cand.preview),
        });
    }
    return va_clamped;
}

void finalize_sorted_strings(std::vector<ExtractedString>& entries) {
    std::ranges::sort(entries, [](const ExtractedString& a, const ExtractedString& b) {
        if (a.virtual_address != b.virtual_address) return a.virtual_address < b.virtual_address;
        if (a.byte_length != b.byte_length) return a.byte_length > b.byte_length;
        return static_cast<std::uint8_t>(a.encoding) < static_cast<std::uint8_t>(b.encoding);
    });
    std::vector<ExtractedString> deduped;
    deduped.reserve(entries.size());
    std::array<std::optional<std::uint64_t>, 4> max_last_by_enc{};
    for (auto& entry : entries) {
        if (entry.byte_length == 0u) {
            continue;
        }
        const auto enc_idx = static_cast<std::size_t>(entry.encoding);
        const std::uint64_t last_va = peelf::checked_add_u64(
            entry.virtual_address,
            entry.byte_length - 1u).value_or(std::numeric_limits<std::uint64_t>::max());
        if (max_last_by_enc[enc_idx].has_value() && last_va <= *max_last_by_enc[enc_idx]) {
            continue;
        }
        max_last_by_enc[enc_idx] = last_va;
        deduped.push_back(std::move(entry));
    }
    entries = std::move(deduped);
}

[[nodiscard]] std::string format_region_name(
    const peelf::MemoryRegion& region,
    const peelf::IBinaryImage* active_image,
    std::optional<std::uint64_t> active_module_base) {
    if (active_image != nullptr) {
        for (const auto& sec : active_image->sections()) {
            const std::uint64_t sec_size = std::max(sec.virtual_size, sec.file_size);
            if (sec_size == 0) continue;
            if (region.start_address >= sec.virtual_address &&
                region.start_address - sec.virtual_address < sec_size) {
                if (!region.pathname.empty()) {
                    const auto slash = region.pathname.find_last_of("/\\");
                    const std::string_view base = slash == std::string::npos
                        ? std::string_view(region.pathname)
                        : std::string_view(region.pathname).substr(slash + 1u);
                    return std::format("{}:{}", base, sec.name);
                }
                return sec.name;
            }
        }
        (void)active_module_base;
    }
    if (!region.pathname.empty()) {
        const auto slash = region.pathname.find_last_of("/\\");
        if (slash != std::string::npos && region.pathname.front() != '[') {
            return region.pathname.substr(slash + 1u);
        }
        return region.pathname;
    }
    return std::string(peelf::to_string(region.kind));
}

[[nodiscard]] bool is_metadata_table_section(std::string_view name) noexcept {
    return name == ".shstrtab" ||
           name == ".strtab" ||
           name == ".symtab" ||
           name == ".dynstr" ||
           name == ".dynsym" ||
           name == ".gnu.hash" ||
           name == ".hash" ||
           name.starts_with(".debug_") ||
           name.starts_with(".zdebug_") ||
           name.starts_with(".rela.") ||
           name.starts_with(".rel.") ||
           name.starts_with(".gnu.version");
}

} // namespace

std::string format_single_line_string_preview(std::string_view utf8_text, std::size_t max_bytes) {
    if (max_bytes == 0u) {
        return utf8_text.empty() ? std::string{} : std::string{"..."};
    }
    std::string out;
    out.reserve(std::min(utf8_text.size(), max_bytes) + 8u);
    bool truncated = false;
    for (std::size_t i = 0; i < utf8_text.size(); ++i) {
        const char ch = utf8_text[i];
        const bool is_escaped = (ch == '\n' || ch == '\r' || ch == '\t');
        const std::size_t add_len = is_escaped ? 2u : 1u;
        if (out.size() + add_len > max_bytes) {
            if ((static_cast<std::uint8_t>(ch) & 0xC0u) == 0x80u) {
                while (!out.empty() &&
                       (static_cast<std::uint8_t>(out.back()) & 0xC0u) == 0x80u) {
                    out.pop_back();
                }
                if (!out.empty() &&
                    (static_cast<std::uint8_t>(out.back()) & 0x80u) != 0u) {
                    out.pop_back();
                }
            }
            truncated = true;
            break;
        }
        switch (ch) {
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:   out.push_back(ch); break;
        }
    }
    if (truncated) {
        out += "...";
    }
    return out;
}

StringsIndex StringsIndex::extract_from_buffer(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_virtual_address,
    std::optional<std::uint64_t> base_file_offset,
    std::string_view section_or_region_name,
    peelf::Endianness hint_endian,
    const StringScanOptions& options,
    bool is_executable_code,
    std::stop_token stop) {
    StringsIndex index;
    index.min_length_ = std::max<std::size_t>(options.min_length, 1u);
    const std::size_t cap = std::min(bytes.size(), options.byte_budget);
    index.incomplete_ = cap < bytes.size();
    if (extract_slice_into(
            bytes.first(cap),
            base_virtual_address,
            base_file_offset,
            section_or_region_name,
            hint_endian,
            options,
            is_executable_code,
            stop,
            index.entries_)) {
        index.incomplete_ = true;
    }
    if (stop.stop_requested()) {
        index.incomplete_ = true;
    }
    finalize_sorted_strings(index.entries_);
    return index;
}

StringsIndex StringsIndex::extract(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> bytes,
    const StringScanOptions& options,
    std::stop_token stop) {
    StringsIndex index;
    index.min_length_ = std::max<std::size_t>(options.min_length, 1u);
    std::size_t remaining_budget = options.byte_budget;

    const auto& sections = image.sections();
    bool scanned_any_section = false;
    for (std::size_t idx = 0; idx < sections.size(); ++idx) {
        if (stop.stop_requested()) {
            index.incomplete_ = true;
            break;
        }
        const auto& sec = sections[idx];
        if (sec.file_size == 0) {
            continue;
        }
        if (!options.include_executable_sections && sec.executable) {
            continue;
        }
        if (!options.include_metadata_sections && is_metadata_table_section(sec.name)) {
            continue;
        }
        scanned_any_section = true;
        if (sec.file_offset >= bytes.size()) {
            index.incomplete_ = true;
            continue;
        }
        if (remaining_budget == 0) {
            index.incomplete_ = true;
            break;
        }
        const std::uint64_t avail = std::min<std::uint64_t>(sec.file_size, bytes.size() - sec.file_offset);
        if (avail < sec.file_size) {
            index.incomplete_ = true;
        }
        const std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(avail, remaining_budget));
        if (take < avail) {
            index.incomplete_ = true;
        }
        const std::string label = sec.name.empty() ? std::format("section_{}", idx) : sec.name;
        const std::uint64_t base_va = sec.virtual_address != 0 ? sec.virtual_address : sec.file_offset;
        if (extract_slice_into(
                bytes.subspan(static_cast<std::size_t>(sec.file_offset), take),
                base_va,
                sec.file_offset,
                label,
                image.endianness(),
                options,
                sec.executable,
                stop,
                index.entries_)) {
            index.incomplete_ = true;
        }
        remaining_budget -= take;
    }

    if (!scanned_any_section) {
        const auto& segments = image.segments();
        for (std::size_t idx = 0; idx < segments.size(); ++idx) {
            if (stop.stop_requested()) {
                index.incomplete_ = true;
                break;
            }
            const auto& seg = segments[idx];
            if (seg.file_size == 0) {
                continue;
            }
            if (!options.include_executable_sections && seg.executable) {
                continue;
            }
            if (seg.file_offset >= bytes.size()) {
                index.incomplete_ = true;
                continue;
            }
            if (remaining_budget == 0) {
                index.incomplete_ = true;
                break;
            }
            const std::uint64_t avail = std::min<std::uint64_t>(seg.file_size, bytes.size() - seg.file_offset);
            if (avail < seg.file_size) {
                index.incomplete_ = true;
            }
            const std::size_t take = static_cast<std::size_t>(
                std::min<std::uint64_t>(avail, remaining_budget));
            if (take < avail) {
                index.incomplete_ = true;
            }
            const std::string label = std::format("PT_LOAD[{}]", idx);
            if (extract_slice_into(
                    bytes.subspan(static_cast<std::size_t>(seg.file_offset), take),
                    seg.virtual_address,
                    seg.file_offset,
                    label,
                    image.endianness(),
                    options,
                    seg.executable,
                    stop,
                    index.entries_)) {
                index.incomplete_ = true;
            }
            remaining_budget -= take;
        }
    }

    if (stop.stop_requested()) {
        index.incomplete_ = true;
    }
    finalize_sorted_strings(index.entries_);
    return index;
}

StringsIndex StringsIndex::extract_live(
    peelf::IProcessSession& session,
    std::span<const peelf::MemoryRegion> regions,
    const peelf::IBinaryImage* active_image,
    std::optional<std::uint64_t> active_module_base,
    const StringScanOptions& options,
    std::stop_token stop) {
    StringsIndex index;
    index.min_length_ = std::max<std::size_t>(options.min_length, 1u);

    std::size_t remaining_budget = options.byte_budget;
    const std::size_t chunk_sz = std::max<std::size_t>(options.chunk_bytes, 4096u);
    constexpr std::size_t kChunkOverlap = 256u;
    constexpr std::size_t kMaxConsecutiveFailedReads = 64u;
    constexpr std::size_t kMaxTotalFailedReads = 256u;
    std::size_t total_failed_reads = 0u;

    const peelf::Endianness endian = active_image != nullptr
        ? active_image->endianness()
        : peelf::Endianness::Little;

    std::vector<std::uint8_t> buffer;
    for (const auto& region : regions) {
        if (stop.stop_requested()) {
            index.incomplete_ = true;
            break;
        }
        if (!region.protection.readable || region.size() == 0) {
            continue;
        }
        if (!options.include_executable_sections && region.protection.executable) {
            continue;
        }
        if (!options.include_all_live_regions &&
            active_module_base.has_value() &&
            active_image != nullptr) {
            // If scoped to an active module, scan regions belonging to that module's path or VA span.
            const std::uint64_t mod_start = *active_module_base;
            std::uint64_t mod_end = mod_start;
            for (const auto& sec : active_image->sections()) {
                const std::uint64_t sec_end = peelf::checked_add_u64(
                    sec.virtual_address,
                    std::max(sec.virtual_size, sec.file_size))
                    .value_or(std::numeric_limits<std::uint64_t>::max());
                mod_end = std::max(mod_end, sec_end);
            }
            for (const auto& seg : active_image->segments()) {
                const std::uint64_t seg_end = peelf::checked_add_u64(
                    seg.virtual_address,
                    std::max(seg.virtual_size, seg.file_size))
                    .value_or(std::numeric_limits<std::uint64_t>::max());
                mod_end = std::max(mod_end, seg_end);
            }
            if (mod_end > mod_start &&
                (region.end_address <= mod_start || region.start_address >= mod_end)) {
                continue;
            }
        }
        if (remaining_budget == 0 || total_failed_reads >= kMaxTotalFailedReads) {
            index.incomplete_ = true;
            break;
        }

        const std::string region_label = format_region_name(region, active_image, active_module_base);
        const std::uint64_t reg_size = region.size();
        std::uint64_t offset = 0;
        std::size_t consecutive_failed_reads = 0u;

        while (offset < reg_size && remaining_budget > 0) {
            if (stop.stop_requested()) {
                index.incomplete_ = true;
                break;
            }
            const auto slice_va_opt = peelf::checked_add_u64(region.start_address, offset);
            if (!slice_va_opt) {
                index.incomplete_ = true;
                break;
            }
            const std::uint64_t slice_va = *slice_va_opt;
            const std::uint64_t to_advance = std::min<std::uint64_t>({
                chunk_sz,
                reg_size - offset,
                remaining_budget,
            });
            const std::uint64_t read_len = std::min<std::uint64_t>(
                reg_size - offset,
                to_advance + kChunkOverlap);
            buffer.resize(static_cast<std::size_t>(read_len));
            auto read_res = session.read_memory(slice_va, buffer);
            if (read_res && *read_res > 0) {
                consecutive_failed_reads = 0u;
                buffer.resize(*read_res);
                const std::optional<std::uint64_t> slice_file_off =
                    active_image != nullptr ? active_image->virtual_address_to_file_offset(slice_va) : std::nullopt;
                if (extract_slice_into(
                        buffer,
                        slice_va,
                        slice_file_off,
                        region_label,
                        endian,
                        options,
                        region.protection.executable,
                        stop,
                        index.entries_)) {
                    index.incomplete_ = true;
                }
                const std::size_t consumed = std::min<std::size_t>(
                    *read_res,
                    static_cast<std::size_t>(to_advance));
                const std::size_t step = std::max<std::size_t>(consumed, 1u);
                offset += step;
                remaining_budget -= std::min(remaining_budget, step);
            } else {
                // Charge unreadable gaps against the byte budget and cap failed reads so
                // sparse or inaccessible VMAs cannot cause unbounded read_memory calls.
                index.incomplete_ = true;
                const std::uint64_t skip = std::min<std::uint64_t>(4096u, reg_size - offset);
                offset += skip;
                const std::size_t budget_charge = static_cast<std::size_t>(
                    std::min<std::uint64_t>(skip, remaining_budget));
                remaining_budget -= budget_charge;
                ++consecutive_failed_reads;
                ++total_failed_reads;
                if (consecutive_failed_reads >= kMaxConsecutiveFailedReads ||
                    total_failed_reads >= kMaxTotalFailedReads) {
                    break;
                }
            }
        }
        if (offset < reg_size) {
            index.incomplete_ = true;
        }
    }

    if (stop.stop_requested()) {
        index.incomplete_ = true;
    }
    finalize_sorted_strings(index.entries_);
    return index;
}

bool StringsIndex::refresh_xrefs(
    const ReferenceIndex& references,
    const FunctionIndex* functions,
    const SymbolIndex* symbols,
    std::uint64_t symbol_revision) {
    if (xrefs_initialized_ &&
        linked_reference_revision_ == references.revision() &&
        linked_symbol_revision_ == symbol_revision) {
        return false;
    }

    for (auto& entry : entries_) {
        entry.referrers.clear();
        const auto incoming = references.incoming(
            entry.virtual_address,
            std::max<std::uint64_t>(entry.byte_length, 1u));
        entry.referrers.reserve(incoming.size());

        for (const Reference* ref : incoming) {
            if (ref == nullptr) continue;
            const bool duplicate = std::ranges::any_of(entry.referrers, [&](const StringReferrer& existing) {
                return existing.instruction_address == ref->source &&
                       existing.target_address == ref->target;
            });
            if (duplicate) {
                continue;
            }

            std::optional<std::uint64_t> fn_va;
            std::string fn_name;
            if (functions != nullptr) {
                if (const FunctionEntry* fn = functions->find_containing(ref->source)) {
                    fn_va = fn->virtual_address;
                    fn_name = fn->name;
                }
            }
            if (!fn_va && symbols != nullptr) {
                if (const SymbolRecord* sym = symbols->find_containing_address(ref->source);
                    sym != nullptr && sym->virtual_address.has_value()) {
                    fn_va = sym->virtual_address;
                    fn_name = sym->name;
                }
            }

            entry.referrers.push_back(StringReferrer{
                .instruction_address = ref->source,
                .target_address = ref->target,
                .function_address = fn_va,
                .function_name = std::move(fn_name),
                .instruction_text = ref->instruction,
                .kind = ref->kind,
                .confidence = ref->confidence,
            });
        }
        entry.xref_count = entry.referrers.size();
    }

    linked_reference_revision_ = references.revision();
    linked_symbol_revision_ = symbol_revision;
    xrefs_initialized_ = true;
    return true;
}

std::vector<std::string> StringsIndex::sections_or_regions() const {
    std::set<std::string> names;
    for (const auto& entry : entries_) {
        if (!entry.section_or_region_name.empty()) {
            names.insert(entry.section_or_region_name);
        }
    }
    return std::vector<std::string>(names.begin(), names.end());
}

const ExtractedString* StringsIndex::find_containing(std::uint64_t virtual_address) const noexcept {
    if (entries_.empty()) {
        return nullptr;
    }
    auto it = std::ranges::upper_bound(
        entries_,
        virtual_address,
        {},
        &ExtractedString::virtual_address);
    if (it == entries_.begin()) {
        return nullptr;
    }
    --it;
    const std::uint64_t len = std::max<std::uint64_t>(it->byte_length, 1u);
    if (virtual_address >= it->virtual_address && (virtual_address - it->virtual_address) < len) {
        return &*it;
    }
    return nullptr;
}

} // namespace viewer
