#include "fuzz_targets.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/demangle.hpp>
#include <peelf/dwarf.hpp>
#include <peelf/pdb.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace peelf::fuzz {

namespace {

[[nodiscard]] std::vector<std::uint8_t> to_vec(std::span<const std::uint8_t> s) {
    return {s.begin(), s.end()};
}

void exercise_demanglers(std::span<const std::uint8_t> data) noexcept {
    constexpr std::size_t kMaxSymbolBytes = 4096u;
    const auto sym_span = data.first(std::min(data.size(), kMaxSymbolBytes));
    const auto raw_sym = FuzzByteReader::as_string_view(sym_span);

    const auto direct = demangle_symbol(raw_sym);
    std::uint64_t acc = direct.demangled.size() ^ static_cast<std::uint64_t>(direct.scheme);

    // Deterministically exercise Itanium (_Z), Rust v0 (_R), and MSVC (?) prefixes
    // even when random mutations have not yet synthesized the exact prefix bytes.
    const auto short_span = data.first(std::min<std::size_t>(data.size(), 512u));
    const auto body = FuzzByteReader::as_string_view(short_span);
    std::string prefixed;
    prefixed.reserve(body.size() + 3u);

    prefixed.assign("_Z");
    prefixed.append(body);
    acc ^= demangle_symbol(prefixed).demangled.size();

    prefixed.assign("_R");
    prefixed.append(body);
    acc ^= demangle_symbol(prefixed).demangled.size();

    prefixed.assign("?");
    prefixed.append(body);
    acc ^= demangle_symbol(prefixed).demangled.size();

    sink_u64(acc);
}

void exercise_dwarf_slices(std::span<const std::uint8_t> data) noexcept {
    FuzzByteReader reader(data);
    const std::uint8_t flags = reader.consume_u8(0u);
    const std::size_t max_part = std::max<std::size_t>(64u, reader.remaining() / 2u);

    DwarfSectionViews views{};
    views.endian = ((flags & 0x01u) != 0u) ? Endianness::Big : Endianness::Little;
    views.default_address_size = ((flags & 0x02u) != 0u) ? 4u : 8u;
    views.debug_abbrev = to_vec(reader.consume_sized_slice(max_part));
    views.debug_str = to_vec(reader.consume_sized_slice(max_part));
    views.debug_line = to_vec(reader.consume_sized_slice(max_part));
    views.debug_line_str = to_vec(reader.consume_sized_slice(max_part));
    views.debug_str_offsets = to_vec(reader.consume_sized_slice(max_part));
    views.debug_addr = to_vec(reader.consume_sized_slice(max_part));
    views.debug_info = to_vec(reader.consume_remaining_bytes());

    std::uint64_t acc = 0u;
    if (const auto parsed = parse_dwarf_sections(views); parsed.has_value()) {
        acc ^= parsed->functions.size() ^ parsed->types.size() ^ parsed->lines.size();
    }

    // Also flip endianness / address size on the same slices to stress both paths.
    views.endian = (views.endian == Endianness::Little) ? Endianness::Big : Endianness::Little;
    views.default_address_size = (views.default_address_size == 8u) ? 4u : 8u;
    if (const auto flipped = parse_dwarf_sections(views); flipped.has_value()) {
        acc ^= flipped->functions.size() ^ flipped->types.size() ^ flipped->lines.size();
    }

    sink_u64(acc);
}

} // namespace

void fuzz_debug_formats_one_input(std::span<const std::uint8_t> data) noexcept {
    if (data.size() > kMaxFuzzInputBytes) {
        return;
    }

    std::uint64_t acc = has_msf7_signature(data) ? 1u : 0u;
    if (const auto id = read_pdb_identity(data); id.has_value()) {
        acc ^= id->info_age ^ id->signature ^ id->version;
    }
    if (const auto pdb = parse_pdb_bytes(data); pdb.has_value()) {
        acc ^= pdb->symbols.size() ^ pdb->types.size() ^ pdb->enums.size() ^ pdb->lines.size() ^
               pdb->machine;
    }

    exercise_demanglers(data);
    exercise_dwarf_slices(data);

    if (const auto img = parse_image(data); img.has_value() && *img != nullptr) {
        acc ^= has_embedded_dwarf(**img) ? 0x10u : 0u;
        const auto link_info = extract_elf_debug_link_info(**img);
        acc ^= link_info.debuglink_filename.size() ^ link_info.build_id_hex.size();
        if (const auto dwarf_img = parse_dwarf_image(**img, data); dwarf_img.has_value()) {
            acc ^= dwarf_img->functions.size() ^ dwarf_img->types.size() ^ dwarf_img->lines.size();
        }
    }

    sink_u64(acc);
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
    peelf::fuzz::fuzz_debug_formats_one_input(bytes);
    return 0;
}
#endif
