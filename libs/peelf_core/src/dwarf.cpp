#include <peelf/dwarf.hpp>

#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {
namespace {

// DWARF tags
constexpr std::uint64_t kDW_TAG_array_type            = 0x01;
constexpr std::uint64_t kDW_TAG_class_type            = 0x02;
constexpr std::uint64_t kDW_TAG_enumeration_type      = 0x04;
constexpr std::uint64_t kDW_TAG_member                = 0x0d;
constexpr std::uint64_t kDW_TAG_pointer_type          = 0x0f;
constexpr std::uint64_t kDW_TAG_reference_type        = 0x10;
constexpr std::uint64_t kDW_TAG_compile_unit          = 0x11;
constexpr std::uint64_t kDW_TAG_structure_type        = 0x13;
constexpr std::uint64_t kDW_TAG_subroutine_type       = 0x15;
constexpr std::uint64_t kDW_TAG_typedef               = 0x16;
constexpr std::uint64_t kDW_TAG_union_type            = 0x17;
constexpr std::uint64_t kDW_TAG_subrange_type         = 0x21;
constexpr std::uint64_t kDW_TAG_base_type             = 0x24;
constexpr std::uint64_t kDW_TAG_const_type            = 0x26;
constexpr std::uint64_t kDW_TAG_subprogram            = 0x2e;
constexpr std::uint64_t kDW_TAG_volatile_type         = 0x35;
constexpr std::uint64_t kDW_TAG_restrict_type         = 0x37;
constexpr std::uint64_t kDW_TAG_partial_unit          = 0x3c;
constexpr std::uint64_t kDW_TAG_type_unit             = 0x41;
constexpr std::uint64_t kDW_TAG_rvalue_reference_type = 0x42;
constexpr std::uint64_t kDW_TAG_atomic_type           = 0x47;

// DWARF attributes
constexpr std::uint64_t kDW_AT_name                 = 0x03;
constexpr std::uint64_t kDW_AT_byte_size            = 0x0b;
constexpr std::uint64_t kDW_AT_low_pc               = 0x11;
constexpr std::uint64_t kDW_AT_high_pc              = 0x12;
constexpr std::uint64_t kDW_AT_upper_bound          = 0x2f;
constexpr std::uint64_t kDW_AT_abstract_origin      = 0x31;
constexpr std::uint64_t kDW_AT_count                = 0x37;
constexpr std::uint64_t kDW_AT_data_member_location = 0x38;
constexpr std::uint64_t kDW_AT_decl_line            = 0x3b;
constexpr std::uint64_t kDW_AT_declaration          = 0x3c;
constexpr std::uint64_t kDW_AT_specification        = 0x47;
constexpr std::uint64_t kDW_AT_type                 = 0x49;
constexpr std::uint64_t kDW_AT_MIPS_linkage_name    = 0x2007;
constexpr std::uint64_t kDW_AT_linkage_name         = 0x6e;
constexpr std::uint64_t kDW_AT_str_offsets_base     = 0x72;
constexpr std::uint64_t kDW_AT_addr_base            = 0x73;
constexpr std::uint64_t kDW_AT_GNU_addr_base        = 0x2133;

// DWARF forms
constexpr std::uint64_t kDW_FORM_addr           = 0x01;
constexpr std::uint64_t kDW_FORM_block2         = 0x03;
constexpr std::uint64_t kDW_FORM_block4         = 0x04;
constexpr std::uint64_t kDW_FORM_data2          = 0x05;
constexpr std::uint64_t kDW_FORM_data4          = 0x06;
constexpr std::uint64_t kDW_FORM_data8          = 0x07;
constexpr std::uint64_t kDW_FORM_string         = 0x08;
constexpr std::uint64_t kDW_FORM_block          = 0x09;
constexpr std::uint64_t kDW_FORM_block1         = 0x0a;
constexpr std::uint64_t kDW_FORM_data1          = 0x0b;
constexpr std::uint64_t kDW_FORM_flag           = 0x0c;
constexpr std::uint64_t kDW_FORM_sdata          = 0x0d;
constexpr std::uint64_t kDW_FORM_strp           = 0x0e;
constexpr std::uint64_t kDW_FORM_udata          = 0x0f;
constexpr std::uint64_t kDW_FORM_ref_addr       = 0x10;
constexpr std::uint64_t kDW_FORM_ref1           = 0x11;
constexpr std::uint64_t kDW_FORM_ref2           = 0x12;
constexpr std::uint64_t kDW_FORM_ref4           = 0x13;
constexpr std::uint64_t kDW_FORM_ref8           = 0x14;
constexpr std::uint64_t kDW_FORM_ref_udata      = 0x15;
constexpr std::uint64_t kDW_FORM_indirect       = 0x16;
constexpr std::uint64_t kDW_FORM_sec_offset     = 0x17;
constexpr std::uint64_t kDW_FORM_exprloc        = 0x18;
constexpr std::uint64_t kDW_FORM_flag_present   = 0x19;
constexpr std::uint64_t kDW_FORM_strx           = 0x1a;
constexpr std::uint64_t kDW_FORM_addrx          = 0x1b;
constexpr std::uint64_t kDW_FORM_ref_sup4       = 0x1c;
constexpr std::uint64_t kDW_FORM_strp_sup       = 0x1d;
constexpr std::uint64_t kDW_FORM_data16         = 0x1e;
constexpr std::uint64_t kDW_FORM_line_strp      = 0x1f;
constexpr std::uint64_t kDW_FORM_ref_sig8       = 0x20;
constexpr std::uint64_t kDW_FORM_implicit_const = 0x21;
constexpr std::uint64_t kDW_FORM_loclistx       = 0x22;
constexpr std::uint64_t kDW_FORM_rnglistx       = 0x23;
constexpr std::uint64_t kDW_FORM_ref_sup8       = 0x24;
constexpr std::uint64_t kDW_FORM_strx1          = 0x25;
constexpr std::uint64_t kDW_FORM_strx2          = 0x26;
constexpr std::uint64_t kDW_FORM_strx3          = 0x27;
constexpr std::uint64_t kDW_FORM_strx4          = 0x28;
constexpr std::uint64_t kDW_FORM_addrx1         = 0x29;
constexpr std::uint64_t kDW_FORM_addrx2         = 0x2a;
constexpr std::uint64_t kDW_FORM_addrx3         = 0x2b;
constexpr std::uint64_t kDW_FORM_addrx4         = 0x2c;

// DWARF v5 unit types
constexpr std::uint8_t kDW_UT_type          = 0x02;
constexpr std::uint8_t kDW_UT_skeleton      = 0x04;
constexpr std::uint8_t kDW_UT_split_compile = 0x05;
constexpr std::uint8_t kDW_UT_split_type    = 0x06;

// DWARF v5 line content types
constexpr std::uint64_t kDW_LNCT_path            = 0x01;
constexpr std::uint64_t kDW_LNCT_directory_index = 0x02;

// DWARF line standard/extended opcodes
constexpr std::uint8_t kDW_LNS_copy               = 1;
constexpr std::uint8_t kDW_LNS_advance_pc         = 2;
constexpr std::uint8_t kDW_LNS_advance_line       = 3;
constexpr std::uint8_t kDW_LNS_set_file           = 4;
constexpr std::uint8_t kDW_LNS_set_column         = 5;
constexpr std::uint8_t kDW_LNS_negate_stmt        = 6;
constexpr std::uint8_t kDW_LNS_set_basic_block    = 7;
constexpr std::uint8_t kDW_LNS_const_add_pc       = 8;
constexpr std::uint8_t kDW_LNS_fixed_advance_pc   = 9;
constexpr std::uint8_t kDW_LNS_set_prologue_end   = 10;
constexpr std::uint8_t kDW_LNS_set_epilogue_begin = 11;
constexpr std::uint8_t kDW_LNS_set_isa            = 12;

constexpr std::uint8_t kDW_LNE_end_sequence       = 1;
constexpr std::uint8_t kDW_LNE_set_address        = 2;
constexpr std::uint8_t kDW_LNE_define_file        = 3;
constexpr std::uint8_t kDW_LNE_set_discriminator  = 4;

[[nodiscard]] std::optional<std::uint64_t> read_uleb128(std::span<const std::uint8_t> data,
                                                        std::size_t& cursor) noexcept {
    std::uint64_t result = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10u; ++i) {
        if (cursor >= data.size()) {
            return std::nullopt;
        }
        const std::uint8_t byte = data[cursor++];
        if (shift == 63u) {
            if ((byte & 0x80u) != 0u || (byte & 0x7Fu) > 0x01u) {
                return std::nullopt;
            }
            result |= (static_cast<std::uint64_t>(byte & 0x01u) << 63u);
            return result;
        }
        result |= (static_cast<std::uint64_t>(byte & 0x7Fu) << shift);
        if ((byte & 0x80u) == 0u) {
            return result;
        }
        shift += 7u;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::int64_t> read_sleb128(std::span<const std::uint8_t> data,
                                                       std::size_t& cursor) noexcept {
    std::uint64_t result = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10u; ++i) {
        if (cursor >= data.size()) {
            return std::nullopt;
        }
        const std::uint8_t byte = data[cursor++];
        if (shift == 63u) {
            if (byte != 0x00u && byte != 0x7Fu) {
                return std::nullopt;
            }
            result |= (static_cast<std::uint64_t>(byte & 0x01u) << 63u);
            return static_cast<std::int64_t>(result);
        }
        result |= (static_cast<std::uint64_t>(byte & 0x7Fu) << shift);
        shift += 7u;
        if ((byte & 0x80u) == 0u) {
            if (shift < 64u && (byte & 0x40u) != 0u) {
                result |= (~std::uint64_t{0} << shift);
            }
            return static_cast<std::int64_t>(result);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> read_c_string(std::span<const std::uint8_t> data,
                                                       std::size_t& cursor,
                                                       std::size_t max_len = 4096) {
    if (cursor >= data.size()) {
        return std::nullopt;
    }
    const std::size_t start = cursor;
    while (cursor < data.size() && data[cursor] != 0) {
        ++cursor;
    }
    if (cursor >= data.size()) {
        return std::nullopt;
    }
    const std::size_t len = std::min(cursor - start, max_len);
    std::string s(reinterpret_cast<const char*>(data.data() + start), len);
    ++cursor; // consume NUL
    return s;
}

[[nodiscard]] std::string read_str_table(std::span<const std::uint8_t> table, std::uint64_t offset) {
    if (offset >= table.size()) {
        return {};
    }
    std::size_t cursor = static_cast<std::size_t>(offset);
    if (auto s = read_c_string(table, cursor)) {
        return std::move(*s);
    }
    // Truncated string at end of table without NUL: read remaining printable slice safely.
    const std::size_t rem = std::min<std::size_t>(table.size() - static_cast<std::size_t>(offset), 512);
    return std::string(reinterpret_cast<const char*>(table.data() + offset), rem);
}

[[nodiscard]] std::optional<std::uint64_t> read_sized_uint(const EndianReader& reader,
                                                           std::size_t& cursor,
                                                           std::uint8_t byte_width) noexcept {
    switch (byte_width) {
    case 1: {
        const auto v = reader.read_u8(cursor);
        if (!v) return std::nullopt;
        cursor += 1;
        return static_cast<std::uint64_t>(*v);
    }
    case 2: {
        const auto v = reader.read_u16(cursor);
        if (!v) return std::nullopt;
        cursor += 2;
        return static_cast<std::uint64_t>(*v);
    }
    case 3: {
        if (!reader.can_read(cursor, 3)) return std::nullopt;
        const auto sub = reader.bytes().subspan(cursor, 3);
        cursor += 3;
        if (reader.endianness() == Endianness::Little) {
            return static_cast<std::uint64_t>(sub[0]) |
                   (static_cast<std::uint64_t>(sub[1]) << 8u) |
                   (static_cast<std::uint64_t>(sub[2]) << 16u);
        }
        return (static_cast<std::uint64_t>(sub[0]) << 16u) |
               (static_cast<std::uint64_t>(sub[1]) << 8u) |
               static_cast<std::uint64_t>(sub[2]);
    }
    case 4: {
        const auto v = reader.read_u32(cursor);
        if (!v) return std::nullopt;
        cursor += 4;
        return static_cast<std::uint64_t>(*v);
    }
    case 8: {
        const auto v = reader.read_u64(cursor);
        if (!v) return std::nullopt;
        cursor += 8;
        return *v;
    }
    default:
        return std::nullopt;
    }
}

constexpr std::array<std::string_view, 3> kDebugInfoSectionNames{{
    ".debug_info", "__DWARF,__debug_info", "__debug_info"
}};
constexpr std::array<std::string_view, 3> kDebugAbbrevSectionNames{{
    ".debug_abbrev", "__DWARF,__debug_abbrev", "__debug_abbrev"
}};
constexpr std::array<std::string_view, 3> kDebugStrSectionNames{{
    ".debug_str", "__DWARF,__debug_str", "__debug_str"
}};
constexpr std::array<std::string_view, 3> kDebugLineSectionNames{{
    ".debug_line", "__DWARF,__debug_line", "__debug_line"
}};
constexpr std::array<std::string_view, 3> kDebugLineStrSectionNames{{
    ".debug_line_str", "__DWARF,__debug_line_str", "__debug_line_str"
}};
constexpr std::array<std::string_view, 4> kDebugStrOffsetsSectionNames{{
    ".debug_str_offsets", "__DWARF,__debug_str_offs", "__debug_str_offs", "__DWARF,__debug_str_offsets"
}};
constexpr std::array<std::string_view, 3> kDebugAddrSectionNames{{
    ".debug_addr", "__DWARF,__debug_addr", "__debug_addr"
}};

[[nodiscard]] bool matches_any_section_name(
    std::string_view actual_name,
    std::span<const std::string_view> candidates) noexcept {
    for (const std::string_view cand : candidates) {
        if (actual_name == cand) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::vector<std::uint8_t> read_section_bytes(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    std::span<const std::string_view> target_names) {
    constexpr std::uint64_t kMaxDwarfSectionBytes = 128ULL * 1024ULL * 1024ULL;
    for (const auto& sec : image.sections()) {
        if (!matches_any_section_name(sec.name, target_names) || sec.file_size == 0) {
            continue;
        }
        if (sec.file_offset > file_bytes.size()) {
            continue;
        }
        const std::uint64_t avail = static_cast<std::uint64_t>(file_bytes.size()) - sec.file_offset;
        const std::size_t to_read = static_cast<std::size_t>(
            std::min<std::uint64_t>({sec.file_size, avail, kMaxDwarfSectionBytes}));
        if (to_read == 0) {
            continue;
        }
        const auto start = static_cast<std::size_t>(sec.file_offset);
        return {file_bytes.begin() + static_cast<std::ptrdiff_t>(start),
                file_bytes.begin() + static_cast<std::ptrdiff_t>(start + to_read)};
    }
    return {};
}

[[nodiscard]] std::uint64_t infer_static_image_base(const IBinaryImage& image) noexcept {
    if (image.format() == Format::MachO) {
        for (const auto& seg : image.macho_segments()) {
            if (seg.name == "__TEXT") {
                return seg.virtual_address;
            }
        }
        return 0;
    }
    if (image.image_base() != 0) {
        return image.image_base();
    }
    // Fallback for separate `.debug` ELF sidecars whose program headers were stripped (`e_phnum == 0`).
    if (image.format() == Format::ELF && image.elf_header() != nullptr &&
        image.elf_header()->type == 2 && image.segments().empty()) {
        std::uint64_t min_alloc_va = std::numeric_limits<std::uint64_t>::max();
        for (const auto& sec : image.sections()) {
            if (sec.readable && sec.virtual_address != 0) {
                const std::uint64_t candidate = sec.virtual_address >= sec.file_offset
                    ? (sec.virtual_address - sec.file_offset)
                    : (sec.virtual_address & ~std::uint64_t{0xFFFu});
                min_alloc_va = std::min(min_alloc_va, candidate);
            }
        }
        if (min_alloc_va != std::numeric_limits<std::uint64_t>::max()) {
            return min_alloc_va;
        }
    }
    return 0;
}

struct AbbrevAttrSpec {
    std::uint64_t name = 0;
    std::uint64_t form = 0;
    std::int64_t implicit_const = 0;
};

struct AbbrevDecl {
    std::uint64_t code = 0;
    std::uint64_t tag = 0;
    bool has_children = false;
    std::vector<AbbrevAttrSpec> attrs{};
};

using AbbrevTable = std::unordered_map<std::uint64_t, AbbrevDecl>;

[[nodiscard]] AbbrevTable parse_abbrev_table(std::span<const std::uint8_t> debug_abbrev,
                                             std::uint64_t offset) {
    AbbrevTable table;
    if (offset >= debug_abbrev.size()) {
        return table;
    }
    std::size_t cursor = static_cast<std::size_t>(offset);
    while (cursor < debug_abbrev.size()) {
        const auto code = read_uleb128(debug_abbrev, cursor);
        if (!code || *code == 0) {
            break;
        }
        const auto tag = read_uleb128(debug_abbrev, cursor);
        if (!tag || cursor >= debug_abbrev.size()) {
            break;
        }
        const bool has_children = (debug_abbrev[cursor++] != 0);

        AbbrevDecl decl;
        decl.code = *code;
        decl.tag = *tag;
        decl.has_children = has_children;

        while (cursor < debug_abbrev.size()) {
            const auto attr_name = read_uleb128(debug_abbrev, cursor);
            const auto attr_form = read_uleb128(debug_abbrev, cursor);
            if (!attr_name || !attr_form) {
                return table;
            }
            if (*attr_name == 0 && *attr_form == 0) {
                break;
            }
            AbbrevAttrSpec spec{.name = *attr_name, .form = *attr_form, .implicit_const = 0};
            if (*attr_form == kDW_FORM_implicit_const) {
                const auto ic = read_sleb128(debug_abbrev, cursor);
                if (!ic) {
                    return table;
                }
                spec.implicit_const = *ic;
            }
            decl.attrs.push_back(spec);
        }
        const std::uint64_t abbrev_code = decl.code;
        table.try_emplace(abbrev_code, std::move(decl));
    }
    return table;
}

struct CompileUnitContext {
    std::size_t cu_start = 0;
    std::size_t cu_end = 0;
    std::uint16_t version = 4;
    std::uint8_t offset_size = 4;
    std::uint8_t address_size = 8;
    std::uint64_t str_offsets_base = 0;
    std::uint64_t addr_base = 0;
    std::string comp_unit_name{};
};

struct AttrValue {
    enum class Kind : std::uint8_t {
        None,
        Uint,
        Int,
        Address,
        SecOffset,
        DieRef,
        String,
        StrxIndex,
        AddrxIndex,
        Block,
        Flag,
    };
    Kind kind = Kind::None;
    std::uint64_t uval = 0;
    std::int64_t sval = 0;
    std::string str{};
    std::vector<std::uint8_t> block{};
};

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        return std::nullopt;
    }
    return a + b;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_mul_u64(
    std::uint64_t a,
    std::uint64_t b) noexcept {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
        return std::nullopt;
    }
    return a * b;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_entry_offset(
    std::uint64_t base,
    std::uint64_t index,
    std::uint64_t entry_size,
    std::uint64_t section_size) noexcept {
    if (entry_size == 0 || base > section_size) {
        return std::nullopt;
    }
    const std::uint64_t avail = section_size - base;
    if (entry_size > avail) {
        return std::nullopt;
    }
    const std::uint64_t max_entries = avail / entry_size;
    if (index >= max_entries) {
        return std::nullopt;
    }
    return base + index * entry_size;
}

[[nodiscard]] std::string resolve_strx(const DwarfSectionViews& views,
                                       const CompileUnitContext& cu,
                                       std::uint64_t index) {
    const std::uint64_t entry_size = cu.offset_size;
    // In DWARF v5, if `DW_AT_str_offsets_base` was omitted on a single-CU file,
    // header size is 8 bytes (DWARF32) or 16 bytes (DWARF64).
    std::uint64_t base = cu.str_offsets_base;
    if (base == 0 && views.debug_str_offsets.size() >= (cu.offset_size == 8 ? 16u : 8u)) {
        base = (cu.offset_size == 8) ? 16u : 8u;
    }
    const auto pos = checked_entry_offset(
        base, index, entry_size, static_cast<std::uint64_t>(views.debug_str_offsets.size()));
    if (!pos.has_value()) {
        return {};
    }
    EndianReader r(views.debug_str_offsets, views.endian);
    std::size_t cursor = static_cast<std::size_t>(*pos);
    const auto str_off = read_sized_uint(r, cursor, cu.offset_size);
    if (!str_off) {
        return {};
    }
    return read_str_table(views.debug_str, *str_off);
}

[[nodiscard]] std::optional<std::uint64_t> resolve_addrx(const DwarfSectionViews& views,
                                                         const CompileUnitContext& cu,
                                                         std::uint64_t index) noexcept {
    std::uint64_t base = cu.addr_base;
    // DWARF v5 `.debug_addr` has an 8-byte (DWARF32) or 16-byte (DWARF64) header when `addr_base == 0` in v5.
    if (base == 0 && cu.version >= 5 && views.debug_addr.size() >= (cu.offset_size == 8 ? 16u : 8u)) {
        base = (cu.offset_size == 8) ? 16u : 8u;
    }
    const auto pos = checked_entry_offset(
        base, index, cu.address_size, static_cast<std::uint64_t>(views.debug_addr.size()));
    if (!pos.has_value()) {
        return std::nullopt;
    }
    EndianReader r(views.debug_addr, views.endian);
    std::size_t cursor = static_cast<std::size_t>(*pos);
    return read_sized_uint(r, cursor, cu.address_size);
}

[[nodiscard]] std::optional<AttrValue> read_form_value(const DwarfSectionViews& views,
                                                       const EndianReader& info_reader,
                                                       std::size_t& cursor,
                                                       std::size_t limit,
                                                       const CompileUnitContext& cu,
                                                       std::uint64_t form,
                                                       std::int64_t implicit_const) {
    std::span<const std::uint8_t> raw = info_reader.bytes();
    limit = std::min(limit, raw.size());
    if (cursor > limit) {
        return std::nullopt;
    }
    while (form == kDW_FORM_indirect) {
        const auto actual = read_uleb128(raw.subspan(0, limit), cursor);
        if (!actual || cursor > limit) return std::nullopt;
        form = *actual;
    }

    AttrValue val;
    switch (form) {
    case kDW_FORM_addr: {
        const auto v = read_sized_uint(info_reader, cursor, cu.address_size);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Address;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_data1: {
        const auto v = read_sized_uint(info_reader, cursor, 1);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_data2: {
        const auto v = read_sized_uint(info_reader, cursor, 2);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_data4: {
        const auto v = read_sized_uint(info_reader, cursor, 4);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_data8:
    case kDW_FORM_ref_sig8: {
        const auto v = read_sized_uint(info_reader, cursor, 8);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_data16: {
        if (cursor > limit || limit - cursor < 16u) return std::nullopt;
        cursor += 16;
        val.kind = AttrValue::Kind::Uint;
        return val;
    }
    case kDW_FORM_udata:
    case kDW_FORM_loclistx:
    case kDW_FORM_rnglistx: {
        const auto v = read_uleb128(raw, cursor);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *v;
        return val;
    }
    case kDW_FORM_sdata: {
        const auto v = read_sleb128(raw, cursor);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Int;
        val.sval = *v;
        val.uval = static_cast<std::uint64_t>(*v);
        return val;
    }
    case kDW_FORM_implicit_const: {
        val.kind = AttrValue::Kind::Int;
        val.sval = implicit_const;
        val.uval = static_cast<std::uint64_t>(implicit_const);
        return val;
    }
    case kDW_FORM_flag: {
        const auto v = read_sized_uint(info_reader, cursor, 1);
        if (!v || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Flag;
        val.uval = (*v != 0) ? 1 : 0;
        return val;
    }
    case kDW_FORM_flag_present: {
        val.kind = AttrValue::Kind::Flag;
        val.uval = 1;
        return val;
    }
    case kDW_FORM_string: {
        auto s = read_c_string(raw, cursor);
        if (!s || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::String;
        val.str = std::move(*s);
        return val;
    }
    case kDW_FORM_strp:
    case kDW_FORM_strp_sup: {
        const auto off = read_sized_uint(info_reader, cursor, cu.offset_size);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::String;
        val.str = read_str_table(views.debug_str, *off);
        return val;
    }
    case kDW_FORM_line_strp: {
        const auto off = read_sized_uint(info_reader, cursor, cu.offset_size);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::String;
        val.str = read_str_table(views.debug_line_str, *off);
        return val;
    }
    case kDW_FORM_strx:
    case kDW_FORM_strx1:
    case kDW_FORM_strx2:
    case kDW_FORM_strx3:
    case kDW_FORM_strx4: {
        std::optional<std::uint64_t> idx;
        if (form == kDW_FORM_strx) idx = read_uleb128(raw, cursor);
        else if (form == kDW_FORM_strx1) idx = read_sized_uint(info_reader, cursor, 1);
        else if (form == kDW_FORM_strx2) idx = read_sized_uint(info_reader, cursor, 2);
        else if (form == kDW_FORM_strx3) idx = read_sized_uint(info_reader, cursor, 3);
        else idx = read_sized_uint(info_reader, cursor, 4);
        if (!idx || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::StrxIndex;
        val.uval = *idx;
        val.str = resolve_strx(views, cu, *idx);
        return val;
    }
    case kDW_FORM_addrx:
    case kDW_FORM_addrx1:
    case kDW_FORM_addrx2:
    case kDW_FORM_addrx3:
    case kDW_FORM_addrx4: {
        std::optional<std::uint64_t> idx;
        if (form == kDW_FORM_addrx) idx = read_uleb128(raw, cursor);
        else if (form == kDW_FORM_addrx1) idx = read_sized_uint(info_reader, cursor, 1);
        else if (form == kDW_FORM_addrx2) idx = read_sized_uint(info_reader, cursor, 2);
        else if (form == kDW_FORM_addrx3) idx = read_sized_uint(info_reader, cursor, 3);
        else idx = read_sized_uint(info_reader, cursor, 4);
        if (!idx || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::AddrxIndex;
        val.uval = *idx;
        if (const auto resolved = resolve_addrx(views, cu, *idx)) {
            val.kind = AttrValue::Kind::Address;
            val.uval = *resolved;
        }
        return val;
    }
    case kDW_FORM_sec_offset: {
        const auto off = read_sized_uint(info_reader, cursor, cu.offset_size);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::SecOffset;
        val.uval = *off;
        return val;
    }
    case kDW_FORM_ref_addr: {
        const std::uint8_t ref_sz = (cu.version == 2) ? cu.address_size : cu.offset_size;
        const auto off = read_sized_uint(info_reader, cursor, ref_sz);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::DieRef;
        val.uval = *off;
        return val;
    }
    case kDW_FORM_ref1:
    case kDW_FORM_ref2:
    case kDW_FORM_ref4:
    case kDW_FORM_ref8:
    case kDW_FORM_ref_udata: {
        std::optional<std::uint64_t> rel;
        if (form == kDW_FORM_ref1) rel = read_sized_uint(info_reader, cursor, 1);
        else if (form == kDW_FORM_ref2) rel = read_sized_uint(info_reader, cursor, 2);
        else if (form == kDW_FORM_ref4) rel = read_sized_uint(info_reader, cursor, 4);
        else if (form == kDW_FORM_ref8) rel = read_sized_uint(info_reader, cursor, 8);
        else rel = read_uleb128(raw, cursor);
        if (!rel || cursor > limit) return std::nullopt;
        const auto abs_ref = checked_add_u64(static_cast<std::uint64_t>(cu.cu_start), *rel);
        val.kind = AttrValue::Kind::DieRef;
        val.uval = (abs_ref.has_value() && *abs_ref < static_cast<std::uint64_t>(cu.cu_end))
                       ? *abs_ref
                       : std::numeric_limits<std::uint64_t>::max();
        return val;
    }
    case kDW_FORM_ref_sup4: {
        const auto off = read_sized_uint(info_reader, cursor, 4);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *off;
        return val;
    }
    case kDW_FORM_ref_sup8: {
        const auto off = read_sized_uint(info_reader, cursor, 8);
        if (!off || cursor > limit) return std::nullopt;
        val.kind = AttrValue::Kind::Uint;
        val.uval = *off;
        return val;
    }
    case kDW_FORM_block1:
    case kDW_FORM_block2:
    case kDW_FORM_block4:
    case kDW_FORM_block:
    case kDW_FORM_exprloc: {
        std::optional<std::uint64_t> len;
        if (form == kDW_FORM_block1) len = read_sized_uint(info_reader, cursor, 1);
        else if (form == kDW_FORM_block2) len = read_sized_uint(info_reader, cursor, 2);
        else if (form == kDW_FORM_block4) len = read_sized_uint(info_reader, cursor, 4);
        else len = read_uleb128(raw.subspan(0, limit), cursor);
        if (!len || cursor > limit || *len > limit - cursor) return std::nullopt;
        const auto sz = static_cast<std::size_t>(*len);
        val.kind = AttrValue::Kind::Block;
        if (sz <= 256) {
            val.block.assign(raw.begin() + static_cast<std::ptrdiff_t>(cursor),
                             raw.begin() + static_cast<std::ptrdiff_t>(cursor + sz));
        }
        cursor += sz;
        return val;
    }
    default:
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::uint64_t> eval_member_location(const AttrValue& attr) noexcept {
    if (attr.kind == AttrValue::Kind::Uint || attr.kind == AttrValue::Kind::SecOffset) {
        return attr.uval;
    }
    if (attr.kind == AttrValue::Kind::Int && attr.sval >= 0) {
        return static_cast<std::uint64_t>(attr.sval);
    }
    if (attr.kind == AttrValue::Kind::Block && !attr.block.empty()) {
        std::size_t c = 0;
        const std::uint8_t op = attr.block[c++];
        // DW_OP_plus_uconst (0x23) or DW_OP_constu (0x10)
        if (op == 0x23u || op == 0x10u) {
            return read_uleb128(attr.block, c);
        }
        // DW_OP_consts (0x11)
        if (op == 0x11u) {
            const auto sv = read_sleb128(attr.block, c);
            if (sv && *sv >= 0) return static_cast<std::uint64_t>(*sv);
        }
        // DW_OP_lit0..DW_OP_lit31 (0x30..0x4f)
        if (op >= 0x30u && op <= 0x4fu) {
            return static_cast<std::uint64_t>(op - 0x30u);
        }
    }
    return std::nullopt;
}

struct DieNode {
    std::uint64_t offset = 0;
    std::uint64_t tag = 0;
    std::uint8_t address_size = 8;
    std::string comp_unit{};
    std::string name{};
    std::string linkage_name{};
    std::optional<std::uint64_t> byte_size{};
    std::optional<std::uint64_t> type_ref{};
    std::optional<std::uint64_t> spec_ref{};
    std::optional<std::uint64_t> low_pc{};
    std::optional<AttrValue> high_pc{};
    std::optional<std::uint64_t> member_offset{};
    std::optional<std::uint64_t> array_count{};
    std::uint32_t decl_line = 0;
    bool is_declaration = false;
    std::vector<std::uint64_t> child_offsets{};
};

struct ResolvedTypeInfo {
    std::string name{};
    std::uint64_t byte_size = 0;
};

[[nodiscard]] ResolvedTypeInfo resolve_die_type(
    std::optional<std::uint64_t> die_offset,
    const std::unordered_map<std::uint64_t, DieNode>& dies,
    std::uint8_t default_ptr_size,
    unsigned depth = 0) {
    if (!die_offset || depth > 16) {
        return ResolvedTypeInfo{.name = "void", .byte_size = 0};
    }
    const auto it = dies.find(*die_offset);
    if (it == dies.end()) {
        return ResolvedTypeInfo{.name = "unknown", .byte_size = 0};
    }
    const DieNode& d = it->second;
    const std::uint8_t ptr_size = d.address_size != 0 ? d.address_size : default_ptr_size;

    switch (d.tag) {
    case kDW_TAG_base_type:
        return ResolvedTypeInfo{
            .name = d.name.empty() ? "scalar" : d.name,
            .byte_size = d.byte_size.value_or(0),
        };
    case kDW_TAG_typedef: {
        const auto target = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{
            .name = d.name.empty() ? target.name : d.name,
            .byte_size = d.byte_size.value_or(target.byte_size),
        };
    }
    case kDW_TAG_const_type: {
        const auto inner = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{.name = "const " + inner.name, .byte_size = inner.byte_size};
    }
    case kDW_TAG_volatile_type: {
        const auto inner = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{.name = "volatile " + inner.name, .byte_size = inner.byte_size};
    }
    case kDW_TAG_restrict_type:
    case kDW_TAG_atomic_type:
        return resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
    case kDW_TAG_pointer_type: {
        const auto inner = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{
            .name = inner.name + "*",
            .byte_size = d.byte_size.value_or(ptr_size),
        };
    }
    case kDW_TAG_reference_type: {
        const auto inner = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{
            .name = inner.name + "&",
            .byte_size = d.byte_size.value_or(ptr_size),
        };
    }
    case kDW_TAG_rvalue_reference_type: {
        const auto inner = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{
            .name = inner.name + "&&",
            .byte_size = d.byte_size.value_or(ptr_size),
        };
    }
    case kDW_TAG_array_type: {
        const auto elem = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        std::string dims;
        std::optional<std::uint64_t> total_elems = std::uint64_t{1};
        bool has_dim = false;
        for (const std::uint64_t child_off : d.child_offsets) {
            const auto cit = dies.find(child_off);
            if (cit != dies.end() && cit->second.tag == kDW_TAG_subrange_type) {
                if (cit->second.array_count.has_value()) {
                    const std::uint64_t cnt = *cit->second.array_count;
                    dims += "[" + std::to_string(cnt) + "]";
                    total_elems = total_elems.has_value()
                                      ? checked_mul_u64(*total_elems, cnt)
                                      : std::nullopt;
                    has_dim = true;
                } else {
                    dims += "[]";
                }
            }
        }
        if (dims.empty()) dims = "[]";
        const auto computed_sz =
            (has_dim && total_elems.has_value())
                ? checked_mul_u64(elem.byte_size, *total_elems)
                : std::optional<std::uint64_t>{0};
        const std::uint64_t sz = d.byte_size.value_or(computed_sz.value_or(0));
        return ResolvedTypeInfo{.name = elem.name + dims, .byte_size = sz};
    }
    case kDW_TAG_structure_type:
    case kDW_TAG_class_type:
    case kDW_TAG_union_type: {
        const char* kw = (d.tag == kDW_TAG_union_type) ? "union " : (d.tag == kDW_TAG_class_type ? "class " : "struct ");
        const std::string nm = d.name.empty() ? (std::string(kw) + "<anon>") : d.name;
        return ResolvedTypeInfo{.name = nm, .byte_size = d.byte_size.value_or(0)};
    }
    case kDW_TAG_enumeration_type: {
        const std::string nm = d.name.empty() ? "enum <anon>" : ("enum " + d.name);
        return ResolvedTypeInfo{.name = nm, .byte_size = d.byte_size.value_or(4)};
    }
    case kDW_TAG_subroutine_type: {
        const auto ret = resolve_die_type(d.type_ref, dies, ptr_size, depth + 1);
        return ResolvedTypeInfo{.name = ret.name + "()", .byte_size = 0};
    }
    default:
        return ResolvedTypeInfo{
            .name = d.name.empty() ? "unknown" : d.name,
            .byte_size = d.byte_size.value_or(0),
        };
    }
}

void parse_debug_info_units(const DwarfSectionViews& views, DwarfDebugData& out) {
    if (views.debug_info.empty() || views.debug_abbrev.empty()) {
        return;
    }

    EndianReader reader(views.debug_info, views.endian);
    std::unordered_map<std::uint64_t, DieNode> all_dies;
    std::vector<std::uint64_t> die_order;

    std::size_t cursor = 0;
    while (cursor <= views.debug_info.size() && views.debug_info.size() - cursor >= 4u) {
        const std::size_t cu_start = cursor;
        const auto initial_len32 = reader.read_u32(cursor);
        if (!initial_len32 || *initial_len32 == 0) {
            break;
        }
        cursor += 4;
        bool is_dwarf64 = false;
        std::uint64_t unit_len = *initial_len32;
        if (*initial_len32 == 0xFFFF'FFFFu) {
            const auto len64 = reader.read_u64(cursor);
            if (!len64) break;
            cursor += 8;
            is_dwarf64 = true;
            unit_len = *len64;
        }
        if (cursor > views.debug_info.size() || unit_len > views.debug_info.size() - cursor) {
            break;
        }
        const std::size_t cu_end = cursor + static_cast<std::size_t>(unit_len);
        const std::span<const std::uint8_t> cu_bytes =
            std::span<const std::uint8_t>(views.debug_info).first(cu_end);
        const EndianReader cu_reader(cu_bytes, views.endian);

        if (cursor > cu_end || cu_end - cursor < 2u) {
            cursor = cu_end;
            continue;
        }
        const auto version = cu_reader.read_u16(cursor);
        if (!version || *version < 2 || *version > 5) {
            cursor = cu_end;
            continue;
        }
        cursor += 2;

        CompileUnitContext cu;
        cu.cu_start = cu_start;
        cu.cu_end = cu_end;
        cu.version = *version;
        cu.offset_size = is_dwarf64 ? 8 : 4;
        cu.address_size = views.default_address_size;

        std::uint64_t abbrev_offset = 0;
        if (*version >= 5) {
            if (cursor > cu_end || cu_end - cursor < 2u) {
                cursor = cu_end;
                continue;
            }
            const auto unit_type = cu_reader.read_u8(cursor);
            const auto addr_sz = cu_reader.read_u8(cursor + 1);
            if (!unit_type || !addr_sz) {
                cursor = cu_end;
                continue;
            }
            cursor += 2;
            cu.address_size = *addr_sz;
            const auto abbrev_off = read_sized_uint(cu_reader, cursor, cu.offset_size);
            if (!abbrev_off || cursor > cu_end) {
                cursor = cu_end;
                continue;
            }
            abbrev_offset = *abbrev_off;
            if (*unit_type == kDW_UT_skeleton || *unit_type == kDW_UT_split_compile) {
                if (cursor > cu_end || cu_end - cursor < 8u) { cursor = cu_end; continue; }
                cursor += 8;
            } else if (*unit_type == kDW_UT_type || *unit_type == kDW_UT_split_type) {
                if (cursor > cu_end || cu_end - cursor < static_cast<std::size_t>(8u + cu.offset_size)) {
                    cursor = cu_end;
                    continue;
                }
                cursor += 8u + cu.offset_size;
            }
        } else {
            const auto abbrev_off = read_sized_uint(cu_reader, cursor, cu.offset_size);
            if (!abbrev_off || cursor >= cu_end) {
                cursor = cu_end;
                continue;
            }
            abbrev_offset = *abbrev_off;
            const auto addr_sz = cu_reader.read_u8(cursor);
            if (!addr_sz) {
                cursor = cu_end;
                continue;
            }
            cursor += 1;
            cu.address_size = *addr_sz;
        }

        if (cu.address_size != 4 && cu.address_size != 8) {
            cursor = cu_end;
            continue;
        }

        const AbbrevTable abbrevs = parse_abbrev_table(views.debug_abbrev, abbrev_offset);
        if (abbrevs.empty()) {
            cursor = cu_end;
            continue;
        }

        std::vector<std::uint64_t> parent_stack;
        bool is_root_die = true;

        while (cursor < cu_end) {
            const std::uint64_t die_offset = static_cast<std::uint64_t>(cursor);
            const auto abbrev_code = read_uleb128(cu_bytes, cursor);
            if (!abbrev_code || cursor > cu_end) {
                break;
            }
            if (*abbrev_code == 0) {
                if (!parent_stack.empty()) {
                    parent_stack.pop_back();
                }
                continue;
            }

            const auto ait = abbrevs.find(*abbrev_code);
            if (ait == abbrevs.end()) {
                break;
            }
            const AbbrevDecl& decl = ait->second;

            DieNode node;
            node.offset = die_offset;
            node.tag = decl.tag;
            node.address_size = cu.address_size;
            node.comp_unit = cu.comp_unit_name;

            std::optional<std::uint64_t> deferred_root_name_strx;
            std::optional<std::uint64_t> deferred_root_low_pc_addrx;
            std::optional<std::uint64_t> upper_bound;
            bool attrs_ok = true;

            for (const AbbrevAttrSpec& spec : decl.attrs) {
                const auto val = read_form_value(views, cu_reader, cursor, cu_end, cu, spec.form, spec.implicit_const);
                if (!val) {
                    attrs_ok = false;
                    break;
                }

                switch (spec.name) {
                case kDW_AT_str_offsets_base:
                    if (is_root_die && (val->kind == AttrValue::Kind::SecOffset || val->kind == AttrValue::Kind::Uint)) {
                        cu.str_offsets_base = val->uval;
                    }
                    break;
                case kDW_AT_addr_base:
                case kDW_AT_GNU_addr_base:
                    if (is_root_die && (val->kind == AttrValue::Kind::SecOffset || val->kind == AttrValue::Kind::Uint)) {
                        cu.addr_base = val->uval;
                    }
                    break;
                case kDW_AT_name:
                    if (!val->str.empty()) {
                        node.name = val->str;
                    } else if (is_root_die && val->kind == AttrValue::Kind::StrxIndex) {
                        deferred_root_name_strx = val->uval;
                    }
                    break;
                case kDW_AT_linkage_name:
                case kDW_AT_MIPS_linkage_name:
                    if (!val->str.empty()) {
                        node.linkage_name = val->str;
                    }
                    break;
                case kDW_AT_byte_size:
                    if (val->kind == AttrValue::Kind::Uint) node.byte_size = val->uval;
                    else if (val->kind == AttrValue::Kind::Int && val->sval >= 0) node.byte_size = static_cast<std::uint64_t>(val->sval);
                    break;
                case kDW_AT_type:
                    if (val->kind == AttrValue::Kind::DieRef) node.type_ref = val->uval;
                    break;
                case kDW_AT_specification:
                case kDW_AT_abstract_origin:
                    if (val->kind == AttrValue::Kind::DieRef) node.spec_ref = val->uval;
                    break;
                case kDW_AT_low_pc:
                    if (val->kind == AttrValue::Kind::Address) {
                        node.low_pc = val->uval;
                    } else if (is_root_die && val->kind == AttrValue::Kind::AddrxIndex) {
                        deferred_root_low_pc_addrx = val->uval;
                    }
                    break;
                case kDW_AT_high_pc:
                    node.high_pc = *val;
                    break;
                case kDW_AT_data_member_location:
                    node.member_offset = eval_member_location(*val);
                    break;
                case kDW_AT_count:
                    if (val->kind == AttrValue::Kind::Uint) node.array_count = val->uval;
                    else if (val->kind == AttrValue::Kind::Int && val->sval >= 0) node.array_count = static_cast<std::uint64_t>(val->sval);
                    break;
                case kDW_AT_upper_bound:
                    if (val->kind == AttrValue::Kind::Uint) upper_bound = val->uval;
                    else if (val->kind == AttrValue::Kind::Int && val->sval >= 0) upper_bound = static_cast<std::uint64_t>(val->sval);
                    break;
                case kDW_AT_decl_line:
                    if (val->kind == AttrValue::Kind::Uint || (val->kind == AttrValue::Kind::Int && val->sval >= 0)) {
                        node.decl_line = static_cast<std::uint32_t>(val->uval);
                    }
                    break;
                case kDW_AT_declaration:
                    node.is_declaration = (val->uval != 0);
                    break;
                default:
                    break;
                }
            }

            if (!attrs_ok) {
                break;
            }

            if (!node.array_count.has_value() && upper_bound.has_value()) {
                node.array_count = checked_add_u64(*upper_bound, 1u);
            }

            if (is_root_die) {
                if (deferred_root_name_strx.has_value()) {
                    node.name = resolve_strx(views, cu, *deferred_root_name_strx);
                }
                if (deferred_root_low_pc_addrx.has_value()) {
                    node.low_pc = resolve_addrx(views, cu, *deferred_root_low_pc_addrx);
                }
                if (node.tag == kDW_TAG_compile_unit || node.tag == kDW_TAG_partial_unit || node.tag == kDW_TAG_type_unit) {
                    cu.comp_unit_name = node.name;
                    node.comp_unit = cu.comp_unit_name;
                }
                is_root_die = false;
            }

            if (!parent_stack.empty()) {
                if (auto pit = all_dies.find(parent_stack.back()); pit != all_dies.end()) {
                    pit->second.child_offsets.push_back(node.offset);
                }
            }

            if (decl.has_children) {
                parent_stack.push_back(node.offset);
            }

            const std::uint64_t offset = node.offset;
            die_order.push_back(offset);
            all_dies.try_emplace(offset, std::move(node));
        }

        cursor = cu_end;
    }

    // Materialize `DwarfFunctionSymbol` and `DwarfAggregateType` records in DIE order.
    for (const std::uint64_t die_off : die_order) {
        const auto it = all_dies.find(die_off);
        if (it == all_dies.end()) continue;
        const DieNode& d = it->second;

        if (d.tag == kDW_TAG_subprogram && d.low_pc.has_value() && *d.low_pc != 0) {
            std::string name = d.name;
            std::string linkage = d.linkage_name;
            std::uint32_t decl_line = d.decl_line;

            // Follow `DW_AT_specification` / `DW_AT_abstract_origin` up to 4 hops if needed.
            std::optional<std::uint64_t> spec = d.spec_ref;
            for (unsigned hop = 0; hop < 4 && spec.has_value() && (name.empty() || linkage.empty()); ++hop) {
                const auto sit = all_dies.find(*spec);
                if (sit == all_dies.end()) break;
                if (name.empty() && !sit->second.name.empty()) name = sit->second.name;
                if (linkage.empty() && !sit->second.linkage_name.empty()) linkage = sit->second.linkage_name;
                if (decl_line == 0 && sit->second.decl_line != 0) decl_line = sit->second.decl_line;
                spec = sit->second.spec_ref;
            }

            if (name.empty() && linkage.empty()) {
                continue;
            }

            std::uint64_t fn_size = 0;
            if (d.high_pc.has_value()) {
                if (d.high_pc->kind == AttrValue::Kind::Address) {
                    if (d.high_pc->uval >= *d.low_pc) {
                        fn_size = d.high_pc->uval - *d.low_pc;
                    }
                } else if (d.high_pc->kind == AttrValue::Kind::Uint ||
                           (d.high_pc->kind == AttrValue::Kind::Int && d.high_pc->sval >= 0)) {
                    fn_size = d.high_pc->uval;
                }
            }

            DwarfFunctionSymbol fn;
            fn.name = name.empty() ? linkage : name;
            fn.linkage_name = linkage;
            fn.comp_unit = d.comp_unit;
            fn.low_pc = *d.low_pc;
            fn.relative_address = (*d.low_pc >= views.static_image_base)
                ? (*d.low_pc - views.static_image_base)
                : *d.low_pc;
            fn.byte_size = fn_size;
            fn.decl_line = decl_line;
            out.functions.push_back(std::move(fn));
            continue;
        }

        if ((d.tag == kDW_TAG_structure_type || d.tag == kDW_TAG_class_type || d.tag == kDW_TAG_union_type) &&
            !d.is_declaration && !d.name.empty() && d.byte_size.has_value()) {
            DwarfAggregateType agg;
            agg.name = d.name;
            agg.kind = (d.tag == kDW_TAG_union_type)
                ? DwarfAggregateKind::Union
                : (d.tag == kDW_TAG_class_type ? DwarfAggregateKind::Class : DwarfAggregateKind::Struct);
            agg.byte_size = *d.byte_size;

            for (const std::uint64_t child_off : d.child_offsets) {
                const auto cit = all_dies.find(child_off);
                if (cit == all_dies.end() || cit->second.tag != kDW_TAG_member) {
                    continue;
                }
                const DieNode& mem = cit->second;
                const ResolvedTypeInfo mtype = resolve_die_type(mem.type_ref, all_dies, d.address_size);
                DwarfMemberInfo info;
                info.name = mem.name.empty() ? "<anon>" : mem.name;
                info.type_name = mtype.name;
                info.byte_offset = mem.member_offset.value_or(0);
                info.byte_size = mem.byte_size.value_or(mtype.byte_size);
                agg.members.push_back(std::move(info));
            }
            out.types.push_back(std::move(agg));
        }
    }

    // Deduplicate aggregate types by (name, byte_size, member count) while keeping richest definition.
    std::ranges::sort(out.types, [](const DwarfAggregateType& a, const DwarfAggregateType& b) {
        if (a.name != b.name) return a.name < b.name;
        if (a.members.size() != b.members.size()) return a.members.size() > b.members.size();
        return a.byte_size > b.byte_size;
    });
    out.types.erase(
        std::ranges::unique(out.types, [](const DwarfAggregateType& a, const DwarfAggregateType& b) {
            return a.name == b.name && a.byte_size == b.byte_size;
        }).begin(),
        out.types.end());

    // Sort and deduplicate functions by (low_pc, linkage_name, name).
    std::ranges::sort(out.functions, [](const DwarfFunctionSymbol& a, const DwarfFunctionSymbol& b) {
        if (a.low_pc != b.low_pc) return a.low_pc < b.low_pc;
        if (a.byte_size != b.byte_size) return a.byte_size > b.byte_size;
        return a.name < b.name;
    });
    out.functions.erase(
        std::ranges::unique(out.functions, [](const DwarfFunctionSymbol& a, const DwarfFunctionSymbol& b) {
            return a.low_pc == b.low_pc && a.name == b.name;
        }).begin(),
        out.functions.end());
}

struct LineFileEntry {
    std::string path{};
    std::uint64_t dir_index = 0;
};

[[nodiscard]] std::pair<std::string, std::string> compose_line_file_paths(
    std::span<const std::string> directories,
    std::span<const LineFileEntry> files,
    std::uint16_t version,
    std::uint64_t file_index) {
    // DWARF v2..v4 uses 1-based file/directory indices (dir 0 = compilation dir);
    // DWARF v5 uses 0-based file/directory indices!
    std::size_t fidx = 0;
    if (version >= 5) {
        if (file_index < files.size()) {
            fidx = static_cast<std::size_t>(file_index);
        } else if (file_index == 1 && files.size() == 1) {
            fidx = 0;
        } else {
            return {};
        }
    } else {
        if (file_index == 0 || file_index > files.size()) return {};
        fidx = static_cast<std::size_t>(file_index - 1u);
    }

    const LineFileEntry& fe = files[fidx];
    std::string dir;
    if (version >= 5) {
        if (fe.dir_index < directories.size()) {
            dir = directories[static_cast<std::size_t>(fe.dir_index)];
        }
    } else {
        if (fe.dir_index > 0 && fe.dir_index <= directories.size()) {
            dir = directories[static_cast<std::size_t>(fe.dir_index - 1u)];
        }
    }

    std::string full = fe.path;
    const bool is_abs = !fe.path.empty() &&
                        (fe.path[0] == '/' || fe.path[0] == '\\' ||
                         (fe.path.size() > 1 && fe.path[1] == ':'));
    if (!is_abs && !dir.empty()) {
        const char sep = (dir.find('\\') != std::string::npos) ? '\\' : '/';
        if (dir.back() == '/' || dir.back() == '\\') {
            full = dir + fe.path;
        } else {
            full = dir + sep + fe.path;
        }
    }

    const std::size_t slash = full.find_last_of("/\\");
    std::string base = (slash == std::string::npos) ? full : full.substr(slash + 1u);
    return {std::move(full), std::move(base)};
}

void parse_debug_line_units(const DwarfSectionViews& views, DwarfDebugData& out) {
    if (views.debug_line.empty()) {
        return;
    }

    EndianReader reader(views.debug_line, views.endian);
    std::size_t cursor = 0;

    while (cursor <= views.debug_line.size() && views.debug_line.size() - cursor >= 4u) {
        const auto init32 = reader.read_u32(cursor);
        if (!init32 || *init32 == 0) {
            break;
        }
        cursor += 4;
        bool is_dwarf64 = false;
        std::uint64_t unit_len = *init32;
        if (*init32 == 0xFFFF'FFFFu) {
            const auto len64 = reader.read_u64(cursor);
            if (!len64) break;
            cursor += 8;
            is_dwarf64 = true;
            unit_len = *len64;
        }
        if (cursor > views.debug_line.size() || unit_len > views.debug_line.size() - cursor) {
            break;
        }
        const std::size_t unit_end = cursor + static_cast<std::size_t>(unit_len);
        const std::span<const std::uint8_t> unit_bytes =
            std::span<const std::uint8_t>(views.debug_line).first(unit_end);
        const EndianReader unit_reader(unit_bytes, views.endian);

        if (cursor > unit_end || unit_end - cursor < 2u) {
            cursor = unit_end;
            continue;
        }
        const auto version = unit_reader.read_u16(cursor);
        if (!version || *version < 2 || *version > 5) {
            cursor = unit_end;
            continue;
        }
        cursor += 2;

        const std::uint8_t offset_size = is_dwarf64 ? 8 : 4;
        std::uint8_t address_size = views.default_address_size;
        if (*version >= 5) {
            if (cursor > unit_end || unit_end - cursor < 2u) {
                cursor = unit_end;
                continue;
            }
            const auto addr_sz = unit_reader.read_u8(cursor);
            const auto seg_sz = unit_reader.read_u8(cursor + 1);
            if (!addr_sz || !seg_sz) {
                cursor = unit_end;
                continue;
            }
            cursor += 2;
            address_size = *addr_sz;
        }

        const auto header_len = read_sized_uint(unit_reader, cursor, offset_size);
        if (!header_len || cursor > unit_end || *header_len > unit_end - cursor) {
            cursor = unit_end;
            continue;
        }
        const std::size_t program_start = cursor + static_cast<std::size_t>(*header_len);
        const std::span<const std::uint8_t> header_bytes = unit_bytes.subspan(0, program_start);
        const EndianReader header_reader(header_bytes, views.endian);

        const auto min_inst_len = header_reader.read_u8(cursor++);
        std::uint8_t max_ops_per_inst = 1;
        if (*version >= 4) {
            const auto mops = header_reader.read_u8(cursor++);
            if (!mops) { cursor = unit_end; continue; }
            max_ops_per_inst = (*mops == 0) ? 1 : *mops;
        }
        const auto default_is_stmt = header_reader.read_u8(cursor++);
        const auto line_base_u8 = header_reader.read_u8(cursor++);
        const auto line_range = header_reader.read_u8(cursor++);
        const auto opcode_base = header_reader.read_u8(cursor++);
        if (!min_inst_len || !default_is_stmt || !line_base_u8 || !line_range || !opcode_base ||
            *min_inst_len == 0 || *line_range == 0 || *opcode_base == 0) {
            cursor = unit_end;
            continue;
        }
        const auto line_base = static_cast<std::int8_t>(*line_base_u8);

        std::vector<std::uint8_t> std_opcode_lengths(*opcode_base, 0);
        bool opcodes_ok = true;
        for (std::uint8_t i = 1; i < *opcode_base; ++i) {
            const auto n = header_reader.read_u8(cursor++);
            if (!n) { opcodes_ok = false; break; }
            std_opcode_lengths[i] = *n;
        }
        if (!opcodes_ok || cursor > program_start) {
            cursor = unit_end;
            continue;
        }

        std::vector<std::string> directories;
        std::vector<LineFileEntry> files;

        CompileUnitContext line_cu;
        line_cu.version = *version;
        line_cu.offset_size = offset_size;
        line_cu.address_size = address_size;

        if (*version >= 5) {
            // Directory format + entries
            const auto dir_fmt_cnt = header_reader.read_u8(cursor++);
            if (!dir_fmt_cnt) { cursor = unit_end; continue; }
            std::vector<std::pair<std::uint64_t, std::uint64_t>> dir_fmt;
            bool ok = true;
            for (std::uint8_t i = 0; i < *dir_fmt_cnt; ++i) {
                const auto ct = read_uleb128(header_bytes, cursor);
                const auto fm = read_uleb128(header_bytes, cursor);
                if (!ct || !fm) { ok = false; break; }
                dir_fmt.emplace_back(*ct, *fm);
            }
            const auto dir_cnt = ok ? read_uleb128(header_bytes, cursor) : std::nullopt;
            if (!dir_cnt || (*dir_cnt > 0 && dir_fmt.empty()) || *dir_cnt > 65536u) {
                cursor = unit_end;
                continue;
            }
            for (std::uint64_t d = 0; d < *dir_cnt && ok; ++d) {
                std::string dpath;
                for (const auto& [ct, fm] : dir_fmt) {
                    const auto v = read_form_value(views, header_reader, cursor, program_start, line_cu, fm, 0);
                    if (!v) { ok = false; break; }
                    if (ct == kDW_LNCT_path) dpath = v->str;
                }
                directories.push_back(std::move(dpath));
            }

            // File format + entries
            if (!ok) { cursor = unit_end; continue; }
            const auto file_fmt_cnt = header_reader.read_u8(cursor++);
            if (!file_fmt_cnt) { cursor = unit_end; continue; }
            std::vector<std::pair<std::uint64_t, std::uint64_t>> file_fmt;
            for (std::uint8_t i = 0; i < *file_fmt_cnt; ++i) {
                const auto ct = read_uleb128(header_bytes, cursor);
                const auto fm = read_uleb128(header_bytes, cursor);
                if (!ct || !fm) { ok = false; break; }
                file_fmt.emplace_back(*ct, *fm);
            }
            const auto file_cnt = ok ? read_uleb128(header_bytes, cursor) : std::nullopt;
            if (!file_cnt || (*file_cnt > 0 && file_fmt.empty()) || *file_cnt > 262144u) {
                cursor = unit_end;
                continue;
            }
            for (std::uint64_t f = 0; f < *file_cnt && ok; ++f) {
                LineFileEntry fe;
                for (const auto& [ct, fm] : file_fmt) {
                    const auto v = read_form_value(views, header_reader, cursor, program_start, line_cu, fm, 0);
                    if (!v) { ok = false; break; }
                    if (ct == kDW_LNCT_path) fe.path = v->str;
                    else if (ct == kDW_LNCT_directory_index) fe.dir_index = v->uval;
                }
                files.push_back(std::move(fe));
            }
            if (!ok) {
                cursor = unit_end;
                continue;
            }
        } else {
            while (cursor < program_start) {
                const auto d = read_c_string(header_bytes, cursor);
                if (!d || d->empty()) break;
                directories.push_back(*d);
            }
            while (cursor < program_start) {
                const auto fn = read_c_string(header_bytes, cursor);
                if (!fn || fn->empty()) break;
                const auto dir_idx = read_uleb128(header_bytes, cursor);
                const auto mtime = read_uleb128(header_bytes, cursor);
                const auto fsz = read_uleb128(header_bytes, cursor);
                if (!dir_idx || !mtime || !fsz) break;
                files.push_back(LineFileEntry{.path = *fn, .dir_index = *dir_idx});
            }
        }

        // Execute the `.debug_line` bytecode program.
        cursor = program_start;
        struct LineRegs {
            std::uint64_t address = 0;
            std::uint64_t op_index = 0;
            std::uint64_t file = 1;
            std::int64_t line = 1;
            std::uint64_t column = 0;
            bool is_stmt = false;
        };
        const auto reset_regs = [&]() -> LineRegs {
            return LineRegs{
                .address = 0,
                .op_index = 0,
                .file = 1,
                .line = 1,
                .column = 0,
                .is_stmt = (*default_is_stmt != 0),
            };
        };
        LineRegs regs = reset_regs();

        const auto advance_addr = [&](std::uint64_t op_advance) {
            const std::uint64_t total_ops =
                checked_add_u64(regs.op_index, op_advance)
                    .value_or(std::numeric_limits<std::uint64_t>::max());
            const std::uint64_t addr_delta =
                checked_mul_u64(*min_inst_len, total_ops / max_ops_per_inst).value_or(0u);
            regs.address = checked_add_u64(regs.address, addr_delta).value_or(0u);
            regs.op_index = total_ops % max_ops_per_inst;
        };

        const auto advance_line_checked = [&](std::int64_t delta) {
            // Perform addition in unsigned domain to avoid signed integer overflow UB on hostile SLEB128.
            regs.line = static_cast<std::int64_t>(
                static_cast<std::uint64_t>(regs.line) + static_cast<std::uint64_t>(delta));
        };

        const auto emit_row = [&]() {
            if (regs.address == 0 || regs.line <= 0) {
                return;
            }
            auto [full_path, base_name] = compose_line_file_paths(directories, files, *version, regs.file);
            if (full_path.empty() && base_name.empty()) {
                return;
            }
            DwarfLineEntry entry;
            entry.address = regs.address;
            entry.relative_address = (regs.address >= views.static_image_base)
                ? (regs.address - views.static_image_base)
                : regs.address;
            entry.file_path = std::move(full_path);
            entry.file_name = std::move(base_name);
            entry.line = static_cast<std::uint32_t>(regs.line);
            entry.column = static_cast<std::uint32_t>(regs.column);
            entry.is_stmt = regs.is_stmt;
            out.lines.push_back(std::move(entry));
        };

        while (cursor < unit_end) {
            const std::uint8_t op = unit_bytes[cursor++];
            if (op == 0) {
                // Extended opcode
                const auto ext_len = read_uleb128(unit_bytes, cursor);
                if (!ext_len || *ext_len == 0 || cursor > unit_end || *ext_len > unit_end - cursor) {
                    break;
                }
                const std::size_t ext_end = cursor + static_cast<std::size_t>(*ext_len);
                const std::span<const std::uint8_t> ext_bytes = unit_bytes.subspan(0, ext_end);
                const EndianReader ext_reader(ext_bytes, views.endian);
                const std::uint8_t ext_op = ext_bytes[cursor++];
                switch (ext_op) {
                case kDW_LNE_end_sequence:
                    regs = reset_regs();
                    break;
                case kDW_LNE_set_address: {
                    const auto addr = read_sized_uint(ext_reader, cursor, address_size);
                    if (addr && cursor <= ext_end) {
                        regs.address = *addr;
                        regs.op_index = 0;
                    }
                    break;
                }
                case kDW_LNE_define_file: {
                    const auto fn = read_c_string(ext_bytes, cursor);
                    const auto dir_idx = read_uleb128(ext_bytes, cursor);
                    const auto mtime = read_uleb128(ext_bytes, cursor);
                    const auto fsz = read_uleb128(ext_bytes, cursor);
                    if (fn && dir_idx && mtime && fsz && cursor <= ext_end) {
                        files.push_back(LineFileEntry{.path = *fn, .dir_index = *dir_idx});
                    }
                    break;
                }
                case kDW_LNE_set_discriminator:
                    (void)read_uleb128(ext_bytes, cursor);
                    break;
                default:
                    break;
                }
                cursor = ext_end;
            } else if (op < *opcode_base) {
                bool std_ok = true;
                switch (op) {
                case kDW_LNS_copy:
                    emit_row();
                    break;
                case kDW_LNS_advance_pc:
                    if (const auto adv = read_uleb128(unit_bytes, cursor)) {
                        advance_addr(*adv);
                    } else {
                        std_ok = false;
                    }
                    break;
                case kDW_LNS_advance_line:
                    if (const auto dline = read_sleb128(unit_bytes, cursor)) {
                        advance_line_checked(*dline);
                    } else {
                        std_ok = false;
                    }
                    break;
                case kDW_LNS_set_file:
                    if (const auto f = read_uleb128(unit_bytes, cursor)) {
                        regs.file = *f;
                    } else {
                        std_ok = false;
                    }
                    break;
                case kDW_LNS_set_column:
                    if (const auto c = read_uleb128(unit_bytes, cursor)) {
                        regs.column = *c;
                    } else {
                        std_ok = false;
                    }
                    break;
                case kDW_LNS_negate_stmt:
                    regs.is_stmt = !regs.is_stmt;
                    break;
                case kDW_LNS_set_basic_block:
                case kDW_LNS_set_prologue_end:
                case kDW_LNS_set_epilogue_begin:
                    break;
                case kDW_LNS_const_add_pc:
                    advance_addr((255u - *opcode_base) / *line_range);
                    break;
                case kDW_LNS_fixed_advance_pc:
                    if (const auto delta = unit_reader.read_u16(cursor)) {
                        cursor += 2;
                        regs.address = checked_add_u64(regs.address, *delta).value_or(0u);
                        regs.op_index = 0;
                    } else {
                        std_ok = false;
                    }
                    break;
                case kDW_LNS_set_isa:
                    if (!read_uleb128(unit_bytes, cursor)) {
                        std_ok = false;
                    }
                    break;
                default:
                    for (std::uint8_t a = 0; a < std_opcode_lengths[op]; ++a) {
                        if (!read_uleb128(unit_bytes, cursor)) {
                            std_ok = false;
                            break;
                        }
                    }
                    break;
                }
                if (!std_ok) {
                    break;
                }
            } else {
                // Special opcode
                const std::uint8_t adj = static_cast<std::uint8_t>(op - *opcode_base);
                advance_addr(adj / *line_range);
                advance_line_checked(static_cast<std::int64_t>(line_base) +
                                     static_cast<std::int64_t>(adj % *line_range));
                emit_row();
            }
        }

        cursor = unit_end;
    }

    // Sort and deduplicate line rows by address (prefer statement rows on ties).
    std::ranges::sort(out.lines, [](const DwarfLineEntry& a, const DwarfLineEntry& b) {
        if (a.address != b.address) return a.address < b.address;
        if (a.is_stmt != b.is_stmt) return a.is_stmt > b.is_stmt;
        return a.line < b.line;
    });
    out.lines.erase(
        std::ranges::unique(out.lines, [](const DwarfLineEntry& a, const DwarfLineEntry& b) {
            return a.address == b.address;
        }).begin(),
        out.lines.end());
}

[[nodiscard]] std::string bytes_to_lower_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const std::uint8_t b : bytes) {
        out.push_back(kHex[b >> 4u]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

[[nodiscard]] bool file_exists_regular(const std::filesystem::path& p) {
    std::error_code ec;
    return !p.empty() && std::filesystem::is_regular_file(p, ec) && !ec;
}

void append_dsym_bundle_candidates(const std::filesystem::path& dsym_bundle_dir,
                                   const std::filesystem::path& preferred_filename,
                                   std::vector<std::filesystem::path>& out) {
    if (dsym_bundle_dir.empty()) {
        return;
    }
    const std::filesystem::path dwarf_dir = dsym_bundle_dir / "Contents" / "Resources" / "DWARF";
    if (!preferred_filename.empty()) {
        out.push_back(dwarf_dir / preferred_filename);
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(dwarf_dir, ec) || ec) {
        return;
    }
    std::vector<std::filesystem::path> entries;
    for (const auto& entry : std::filesystem::directory_iterator(dwarf_dir, ec)) {
        if (ec) {
            break;
        }
        std::error_code fec;
        if (!entry.is_regular_file(fec) || fec) {
            continue;
        }
        const std::string fname = entry.path().filename().string();
        if (fname.empty() || fname.front() == '.') {
            continue;
        }
        if (!preferred_filename.empty() && entry.path().filename() == preferred_filename) {
            continue;
        }
        entries.push_back(entry.path());
    }
    std::ranges::sort(entries);
    for (auto& p : entries) {
        out.push_back(std::move(p));
    }
}

[[nodiscard]] bool macho_dsym_candidate_matches_image(const std::filesystem::path& cand_path,
                                                      const IBinaryImage& target_image) {
    constexpr std::uintmax_t kMaxDsymFileSize = 512ull * 1024ull * 1024ull;
    std::error_code ec;
    const auto fsize = std::filesystem::file_size(cand_path, ec);
    if (ec || fsize < 28u || fsize > kMaxDsymFileSize) {
        return false;
    }

    std::ifstream file(cand_path, std::ios::binary);
    if (!file) {
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(fsize));
    if (!file.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()))) {
        return false;
    }

    BinaryOpenOptions opts{};
    if (target_image.architecture() != Architecture::Unknown) {
        opts.preferred_architecture = target_image.architecture();
    }
    auto parsed = open_binary_image(bytes, opts);
    if (!parsed) {
        return false;
    }
    if ((*parsed)->format() != Format::MachO || !has_embedded_dwarf(**parsed)) {
        return false;
    }

    const auto expected_uuid = target_image.macho_uuid();
    if (expected_uuid.has_value()) {
        const auto cand_uuid = (*parsed)->macho_uuid();
        if (!cand_uuid.has_value() || *cand_uuid != *expected_uuid) {
            return false;
        }
    }
    return true;
}

} // namespace

ElfDebugLinkInfo extract_elf_debug_link_info(const IBinaryImage& image) {
    ElfDebugLinkInfo info;

    // 1. `.note.gnu.build-id` (`name == "GNU"`, `type == 3`)
    for (const auto& note : image.elf_notes()) {
        if (note.name == "GNU" && note.type == 3 && !note.descriptor.empty()) {
            info.build_id_hex = bytes_to_lower_hex(note.descriptor);
            break;
        }
    }

    // 2. `.gnu_debuglink` (`<filename>\0` + padding to 4-byte boundary + `uint32_t crc32`)
    if (const GnuDebugLink* dlink = image.gnu_debuglink(); dlink != nullptr && !dlink->filename.empty()) {
        info.debuglink_filename = dlink->filename;
        info.debuglink_crc32 = dlink->crc32;
        info.has_debuglink = true;
    }

    return info;
}

std::optional<std::filesystem::path> find_separate_debug_file(
    const std::filesystem::path& binary_path,
    const IBinaryImage& image,
    std::span<const std::filesystem::path> extra_search_dirs) {
    std::error_code ec;
    const auto bin_canon = binary_path.empty()
        ? std::filesystem::path{}
        : std::filesystem::weakly_canonical(binary_path, ec);
    const std::filesystem::path bin_dir = binary_path.parent_path();

    if (image.format() == Format::MachO) {
        std::filesystem::path fname = binary_path.filename();
        if (fname.empty() && image.macho_id_dylib() != nullptr &&
            !image.macho_id_dylib()->name.empty()) {
            fname = std::filesystem::path(image.macho_id_dylib()->name).filename();
        }

        std::vector<std::filesystem::path> dsym_candidates;
        if (!binary_path.empty()) {
            std::filesystem::path direct_bundle = binary_path;
            direct_bundle += ".dSYM";
            append_dsym_bundle_candidates(direct_bundle, fname, dsym_candidates);
        }
        if (!bin_dir.empty() && !fname.empty()) {
            std::filesystem::path sibling_bundle = bin_dir / fname;
            sibling_bundle += ".dSYM";
            append_dsym_bundle_candidates(sibling_bundle, fname, dsym_candidates);
        }
        for (const auto& extra : extra_search_dirs) {
            if (extra.empty()) {
                continue;
            }
            if (!fname.empty()) {
                std::filesystem::path extra_bundle = extra / fname;
                extra_bundle += ".dSYM";
                append_dsym_bundle_candidates(extra_bundle, fname, dsym_candidates);
            }
            append_dsym_bundle_candidates(extra, fname, dsym_candidates);
        }

        std::vector<std::filesystem::path> seen_canon;
        for (const auto& cand : dsym_candidates) {
            if (!file_exists_regular(cand)) {
                continue;
            }
            std::error_code cec;
            const auto cand_canon = std::filesystem::weakly_canonical(cand, cec);
            if (!cec && !bin_canon.empty() && cand_canon == bin_canon) {
                continue;
            }
            if (!cec) {
                if (std::ranges::find(seen_canon, cand_canon) != seen_canon.end()) {
                    continue;
                }
                seen_canon.push_back(cand_canon);
            }
            if (macho_dsym_candidate_matches_image(cand, image)) {
                return cand;
            }
        }
        return std::nullopt;
    }

    const ElfDebugLinkInfo link = extract_elf_debug_link_info(image);

    std::vector<std::filesystem::path> candidates;

    // 1. `.gnu_debuglink` candidates
    if (link.has_debuglink && !link.debuglink_filename.empty()) {
        const std::filesystem::path link_name = std::filesystem::path(link.debuglink_filename).filename();
        if (!bin_dir.empty()) {
            candidates.push_back(bin_dir / link_name);
            candidates.push_back(bin_dir / ".debug" / link_name);
            std::filesystem::path rel = bin_dir.relative_path();
            if (!rel.empty()) {
                candidates.push_back(std::filesystem::path("/usr/lib/debug") / rel / link_name);
            }
        }
        for (const auto& extra : extra_search_dirs) {
            if (!extra.empty()) {
                candidates.push_back(extra / link_name);
                candidates.push_back(extra / ".debug" / link_name);
            }
        }
    }

    // 2. `.note.gnu.build-id` (`/usr/lib/debug/.build-id/xx/yyyy.debug`)
    if (link.build_id_hex.size() >= 4) {
        const std::string prefix = link.build_id_hex.substr(0, 2);
        const std::string rest = link.build_id_hex.substr(2) + ".debug";
        for (const auto& extra : extra_search_dirs) {
            if (!extra.empty()) {
                candidates.push_back(extra / ".build-id" / prefix / rest);
            }
        }
        if (!bin_dir.empty()) {
            candidates.push_back(bin_dir / ".build-id" / prefix / rest);
        }
        candidates.push_back(std::filesystem::path("/usr/lib/debug/.build-id") / prefix / rest);
    }

    // 3. Sibling `<binary>.debug` and `<stem>.debug`
    if (!binary_path.empty()) {
        std::filesystem::path appended = binary_path;
        appended += ".debug";
        candidates.push_back(std::move(appended));

        std::filesystem::path replaced = binary_path;
        replaced.replace_extension(".debug");
        if (replaced != binary_path) {
            candidates.push_back(std::move(replaced));
        }
    }

    for (const auto& cand : candidates) {
        if (!file_exists_regular(cand)) {
            continue;
        }
        if (!bin_canon.empty()) {
            std::error_code cec;
            if (std::filesystem::weakly_canonical(cand, cec) == bin_canon && !cec) {
                continue;
            }
        }
        return cand;
    }

    return std::nullopt;
}

bool has_embedded_dwarf(const IBinaryImage& image) noexcept {
    for (const auto& sec : image.sections()) {
        if (sec.file_size != 0 &&
            (matches_any_section_name(sec.name, kDebugInfoSectionNames) ||
             matches_any_section_name(sec.name, kDebugLineSectionNames))) {
            return true;
        }
    }
    return false;
}

Result<DwarfDebugData> parse_dwarf_sections(const DwarfSectionViews& views) {
    if (views.debug_info.empty() && views.debug_line.empty()) {
        return make_error("DWARF: neither .debug_info nor .debug_line is present");
    }

    DwarfDebugData data;
    data.static_image_base = views.static_image_base;

    parse_debug_info_units(views, data);
    parse_debug_line_units(views, data);
    return data;
}

Result<DwarfDebugData> parse_dwarf_image(const IBinaryImage& image,
                                         std::span<const std::uint8_t> file_bytes) {
    DwarfSectionViews views;
    views.endian = image.endianness();
    views.default_address_size = image.is_64bit() ? 8 : 4;
    views.static_image_base = infer_static_image_base(image);
    views.debug_info = read_section_bytes(image, file_bytes, kDebugInfoSectionNames);
    views.debug_abbrev = read_section_bytes(image, file_bytes, kDebugAbbrevSectionNames);
    views.debug_str = read_section_bytes(image, file_bytes, kDebugStrSectionNames);
    views.debug_line = read_section_bytes(image, file_bytes, kDebugLineSectionNames);
    views.debug_line_str = read_section_bytes(image, file_bytes, kDebugLineStrSectionNames);
    views.debug_str_offsets = read_section_bytes(image, file_bytes, kDebugStrOffsetsSectionNames);
    views.debug_addr = read_section_bytes(image, file_bytes, kDebugAddrSectionNames);

    return parse_dwarf_sections(views);
}

} // namespace peelf
