#include "fuzz_targets.hpp"

#include "analysis/c_type_parser.hpp"

#include <peelf/endian_reader.hpp>
#include <peelf/gdb_remote.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/patch_bundle.hpp>
#include <peelf/signatures.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace peelf::fuzz {

namespace {

void exercise_c_type_parser(std::span<const std::uint8_t> data, std::uint8_t flags) noexcept {
    constexpr std::size_t kMaxCSourceBytes = 32u * 1024u;
    const auto src_span = data.first(std::min(data.size(), kMaxCSourceBytes));
    const auto src = FuzzByteReader::as_string_view(src_span);

    viewer::CTypeParseOptions opts{};
    const bool is_64bit = ((flags & 0x01u) == 0u);
    const Endianness endian = ((flags & 0x02u) != 0u) ? Endianness::Big : Endianness::Little;
    opts.layout = TargetLayout::from_arch(is_64bit ? Architecture::X86_64 : Architecture::X86,
                                          is_64bit, endian);
    switch ((flags >> 2u) & 0x03u) {
    case 0u:
        opts.long_model = viewer::CLongModel::LP64;
        break;
    case 1u:
        opts.long_model = viewer::CLongModel::LLP64;
        break;
    default:
        opts.long_model = viewer::CLongModel::Auto;
        break;
    }

    const auto parsed = viewer::parse_c_types(src, opts);
    sink_u64(parsed.types.size() ^ parsed.typedefs.size() ^ parsed.diagnostics.size() ^
             parsed.format_diagnostics().size());
}

void exercise_signature_rules(std::span<const std::uint8_t> rule_bytes,
                              std::span<const std::uint8_t> haystack) noexcept {
    constexpr std::size_t kMaxRulesBytes = 16u * 1024u;
    constexpr std::size_t kMaxHaystackBytes = 16u * 1024u;
    const auto rules_txt = FuzzByteReader::as_string_view(
        rule_bytes.first(std::min(rule_bytes.size(), kMaxRulesBytes)));
    const auto scan_buf = haystack.first(std::min(haystack.size(), kMaxHaystackBytes));

    const auto parsed = parse_signature_rules(rules_txt, "<fuzz>");
    std::uint64_t acc = parsed.diagnostics.size() ^ parsed.ruleset.size();
    if (!parsed.ruleset.empty()) {
        const auto matches = evaluate_signature_rules(parsed.ruleset, scan_buf, nullptr);
        acc ^= matches.size();
    }
    sink_u64(acc);
}

void exercise_patches(std::span<const std::uint8_t> data) noexcept {
    std::uint64_t acc = 0u;
    if (const auto ips = decode_ips_patch(data); ips.has_value()) {
        acc ^= ips->size();
        if (ips->size() <= 64u) {
            if (const auto reencoded = encode_ips_patch(*ips); reencoded.has_value()) {
                acc ^= reencoded->size();
            }
        }
    }

    constexpr std::size_t kMaxJsonBytes = 32u * 1024u;
    const auto json_txt =
        FuzzByteReader::as_string_view(data.first(std::min(data.size(), kMaxJsonBytes)));
    if (const auto bundle = decode_patch_bundle_json(json_txt); bundle.has_value()) {
        acc ^= bundle->entries.size() ^ bundle->name.size();
    }

    const auto hex_txt =
        FuzzByteReader::as_string_view(data.first(std::min<std::size_t>(data.size(), 512u)));
    if (const auto hex = hex_string_to_bytes(hex_txt); hex.has_value()) {
        acc ^= hex->size();
    }

    sink_u64(acc);
}

void exercise_regex_and_search(std::span<const std::uint8_t> pattern_bytes,
                               std::span<const std::uint8_t> buffer_bytes,
                               std::uint8_t flags) noexcept {
    const auto pat_str = std::string(FuzzByteReader::as_string_view(
        pattern_bytes.first(std::min<std::size_t>(pattern_bytes.size(), 600u))));
    const auto haystack = buffer_bytes.first(std::min<std::size_t>(buffer_bytes.size(), 4096u));

    // Always exercise RegexText validation + bounded search.
    MemorySearchQuery regex_q{};
    regex_q.kind = SearchValueKind::RegexText;
    regex_q.query_text = pat_str;
    regex_q.case_sensitive = ((flags & 0x01u) != 0u);
    regex_q.max_results = 64u;
    if (const auto rep = search_buffer(haystack, 0x1000u, regex_q, "fuzz"); rep.has_value()) {
        sink_u64(rep->hits.size());
    }

    // Also exercise all other search pattern compilers (HexPattern, scalars, UTF-8/UTF-16).
    MemorySearchQuery other_q{};
    constexpr std::array<SearchValueKind, 6> kKinds = {
        SearchValueKind::Utf8Text, SearchValueKind::Utf16Text, SearchValueKind::HexPattern,
        SearchValueKind::Int32,    SearchValueKind::UInt64,    SearchValueKind::Float64,
    };
    other_q.kind = kKinds[flags % kKinds.size()];
    other_q.query_text = pat_str;
    other_q.endianness = ((flags & 0x02u) != 0u) ? Endianness::Big : Endianness::Little;
    other_q.case_sensitive = ((flags & 0x04u) != 0u);
    other_q.alignment = ((flags & 0x08u) != 0u) ? 4u : 1u;
    other_q.max_results = 64u;
    if (const auto compiled = compile_search_pattern(other_q); compiled.has_value()) {
        if (const auto rep = search_buffer(haystack, 0x2000u, other_q, "fuzz"); rep.has_value()) {
            sink_u64(rep->hits.size() ^ compiled->size());
        }
    }
}

void exercise_gdb_rsp(std::span<const std::uint8_t> data, std::uint8_t flags) noexcept {
    constexpr std::size_t kMaxRspBytes = 16u * 1024u;
    const auto rsp_txt =
        FuzzByteReader::as_string_view(data.first(std::min(data.size(), kMaxRspBytes)));
    const auto short_txt = rsp_txt.substr(0u, std::min<std::size_t>(rsp_txt.size(), 512u));

    std::uint64_t acc = compute_rsp_checksum(short_txt);
    acc ^= is_mutating_rsp_packet(short_txt) ? 1u : 0u;
    acc ^= rsp_escape_payload(short_txt).size();
    acc ^= rsp_encode_frame(short_txt).size();

    if (const auto ep = parse_gdb_remote_endpoint(short_txt); ep.has_value()) {
        acc ^= ep->port ^ ep->host.size();
    }
    if (const auto decoded = rsp_decode_wire_payload(rsp_txt, 64u * 1024u); decoded.has_value()) {
        acc ^= decoded->size();
    }

    const auto qsup = parse_qsupported_reply(short_txt);
    acc ^= qsup.packet_size ^ (qsup.qxfer_features_read ? 2u : 0u);

    const auto annex_body = std::string(short_txt);
    std::size_t annex_fetches = 0u;
    if (const auto target_desc = parse_rsp_target_xml(
            rsp_txt,
            [&](std::string_view /*annex_name*/) -> Result<std::string> {
                if (++annex_fetches > 4u) {
                    return make_error("annex fetch budget exhausted");
                }
                return annex_body;
            },
            4u, 8u);
        target_desc.has_value()) {
        acc ^= target_desc->registers.size();
        if (const auto regs = decode_rsp_g_packet(*target_desc, short_txt); regs.has_value()) {
            acc ^= regs->size();
        }
    }

    for (const std::uint32_t bits : {8u, 16u, 32u, 64u, 128u}) {
        RspRegisterSpec spec{};
        spec.name = "r0";
        spec.regnum = 0u;
        spec.bitsize = bits;
        if (const auto reg_val = decode_rsp_register_hex(
                spec, short_txt, ((flags & 0x20u) != 0u) ? Endianness::Big : Endianness::Little);
            reg_val.has_value()) {
            acc ^= reg_val->raw_bytes.size() ^ reg_val->value_u64.value_or(0u);
        }
    }

    if (const auto mmap = parse_rsp_memory_map_xml(rsp_txt); mmap.has_value()) {
        acc ^= mmap->size();
    }
    if (const auto libs = parse_rsp_libraries_xml(rsp_txt); libs.has_value()) {
        acc ^= libs->size();
    }
    if (const auto tid = parse_rsp_thread_id(short_txt); tid.has_value()) {
        acc ^= tid->tid ^ tid->pid;
    }
    bool reached_end = false;
    if (const auto tids = parse_rsp_thread_info_packet(short_txt, reached_end); tids.has_value()) {
        acc ^= tids->size() ^ (reached_end ? 1u : 0u);
    }

    sink_u64(acc);
}

} // namespace

void fuzz_parsers_dsl_one_input(std::span<const std::uint8_t> data) noexcept {
    if (data.size() > kMaxFuzzInputBytes) {
        return;
    }

    FuzzByteReader reader(data);
    const std::uint8_t flags = reader.consume_u8(0u);
    const auto head_slice = reader.consume_sized_slice(std::min<std::size_t>(data.size(), 4096u));
    const auto tail_slice = reader.consume_remaining_bytes();

    // Exercise every parser on both raw `data` (so pure C / JSON / IPS / XML seeds parse
    // directly from offset 0) and split slices (for rule+haystack / regex+buffer pairs).
    exercise_c_type_parser(data, flags);
    exercise_patches(data);
    exercise_gdb_rsp(data, flags);
    exercise_signature_rules(data, tail_slice.empty() ? data : tail_slice);
    exercise_signature_rules(head_slice, tail_slice);
    exercise_regex_and_search(head_slice.empty() ? data : head_slice,
                              tail_slice.empty() ? data : tail_slice, flags);
}

} // namespace peelf::fuzz

#ifdef PEELF_LIBFUZZER_HARNESS
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > peelf::fuzz::kMaxFuzzInputBytes) {
        return 0;
    }
    const std::span<const std::uint8_t> bytes = (data != nullptr)
                                                    ? std::span<const std::uint8_t>(data, size)
                                                    : std::span<const std::uint8_t>{};
    peelf::fuzz::fuzz_parsers_dsl_one_input(bytes);
    return 0;
}
#endif
