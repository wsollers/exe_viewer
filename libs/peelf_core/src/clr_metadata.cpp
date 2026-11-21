// SPDX-License-Identifier: BSD-2-Clause
#include <peelf/clr_metadata.hpp>
#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
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

constexpr std::uint32_t kBsjbMagic = 0x424A5342u;
constexpr std::size_t kMaxStreams = 64u;
constexpr std::size_t kMaxVersionBytes = 1024u;
constexpr std::size_t kMaxStringBytes = 4096u;
constexpr std::uint32_t kMaxDecodedRowsPerTable = 200'000u;
constexpr std::size_t kMaxUserStrings = 65'536u;
constexpr std::size_t kMaxSignatureParams = 256u;
constexpr std::size_t kMaxSignatureDepth = 16u;
constexpr std::size_t kMaxDiagnostics = 64u;
constexpr std::size_t kMaxCilInstructions = 100'000u;
constexpr std::uint32_t kMaxCilCodeSize = 4u * 1024u * 1024u;
constexpr std::size_t kMaxEhSections = 64u;
constexpr std::size_t kMaxEhClauses = 4096u;
constexpr std::uint32_t kMaxSwitchTargets = 16'384u;

void push_diagnostic(std::vector<std::string>& diags, std::string msg) {
    if (diags.size() < kMaxDiagnostics) {
        diags.push_back(std::move(msg));
    }
}

[[nodiscard]] std::string hex_encode_upper(std::span<const std::uint8_t> bytes,
                                           std::size_t max_bytes = 64u) {
    const std::size_t count = std::min(bytes.size(), max_bytes);
    std::string out{};
    out.reserve(count * 2u + (bytes.size() > count ? 3u : 0u));
    for (std::size_t i = 0u; i < count; ++i) {
        out += std::format("{:02x}", bytes[i]);
    }
    if (bytes.size() > count) {
        out += "...";
    }
    return out;
}

[[nodiscard]] std::string escape_cil_string(std::string_view raw, std::size_t max_chars = 256u) {
    std::string out{};
    out.reserve(std::min(raw.size(), max_chars) + 8u);
    out.push_back('"');
    std::size_t emitted = 0u;
    for (const char ch : raw) {
        if (emitted >= max_chars) {
            out += "...";
            break;
        }
        const auto uch = static_cast<unsigned char>(ch);
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\0': out += "\\0"; break;
            default:
                if (uch >= 0x20u && uch != 0x7Fu) {
                    out.push_back(ch);
                } else {
                    out += std::format("\\x{:02X}", static_cast<unsigned>(uch));
                }
                break;
        }
        ++emitted;
    }
    out.push_back('"');
    return out;
}

// ECMA-335 II.24.2.4 compressed unsigned integer decoder (`#Blob` and `#US`).
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::size_t>>
decode_compressed_uint(std::span<const std::uint8_t> buf, std::size_t offset) noexcept {
    if (offset >= buf.size()) {
        return std::nullopt;
    }
    const std::uint8_t b0 = buf[offset];
    if ((b0 & 0x80u) == 0u) {
        return std::pair<std::uint32_t, std::size_t>{static_cast<std::uint32_t>(b0 & 0x7Fu), 1u};
    }
    if ((b0 & 0xC0u) == 0x80u) {
        if (offset + 2u > buf.size()) {
            return std::nullopt;
        }
        const std::uint32_t val =
            (static_cast<std::uint32_t>(b0 & 0x3Fu) << 8u) |
            static_cast<std::uint32_t>(buf[offset + 1u]);
        return std::pair<std::uint32_t, std::size_t>{val, 2u};
    }
    if ((b0 & 0xE0u) == 0xC0u) {
        if (offset + 4u > buf.size()) {
            return std::nullopt;
        }
        const std::uint32_t val =
            (static_cast<std::uint32_t>(b0 & 0x1Fu) << 24u) |
            (static_cast<std::uint32_t>(buf[offset + 1u]) << 16u) |
            (static_cast<std::uint32_t>(buf[offset + 2u]) << 8u) |
            static_cast<std::uint32_t>(buf[offset + 3u]);
        return std::pair<std::uint32_t, std::size_t>{val, 4u};
    }
    return std::nullopt;
}

enum class CodedIndexKind : std::uint8_t {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
    HasCustomDebugInformation,
};

struct CodedIndexSpec {
    std::uint8_t tag_bits{0};
    std::span<const std::uint8_t> tables{};
};

constexpr std::array<std::uint8_t, 3> kTablesTypeDefOrRef{{0x02u, 0x01u, 0x1Bu}};
constexpr std::array<std::uint8_t, 3> kTablesHasConstant{{0x04u, 0x08u, 0x17u}};
constexpr std::array<std::uint8_t, 22> kTablesHasCustomAttribute{{
    0x06u, 0x04u, 0x01u, 0x02u, 0x08u, 0x09u, 0x0Au, 0x00u,
    0x0Eu, 0x17u, 0x14u, 0x11u, 0x1Au, 0x1Bu, 0x20u, 0x23u,
    0x26u, 0x27u, 0x28u, 0x2Au, 0x2Cu, 0x2Bu,
}};
constexpr std::array<std::uint8_t, 2> kTablesHasFieldMarshal{{0x04u, 0x08u}};
constexpr std::array<std::uint8_t, 3> kTablesHasDeclSecurity{{0x02u, 0x06u, 0x20u}};
constexpr std::array<std::uint8_t, 5> kTablesMemberRefParent{{0x02u, 0x01u, 0x1Au, 0x06u, 0x1Bu}};
constexpr std::array<std::uint8_t, 2> kTablesHasSemantics{{0x14u, 0x17u}};
constexpr std::array<std::uint8_t, 2> kTablesMethodDefOrRef{{0x06u, 0x0Au}};
constexpr std::array<std::uint8_t, 2> kTablesMemberForwarded{{0x04u, 0x06u}};
constexpr std::array<std::uint8_t, 3> kTablesImplementation{{0x26u, 0x23u, 0x27u}};
constexpr std::array<std::uint8_t, 5> kTablesCustomAttributeType{{0xFFu, 0xFFu, 0x06u, 0x0Au, 0xFFu}};
constexpr std::array<std::uint8_t, 4> kTablesResolutionScope{{0x00u, 0x1Au, 0x23u, 0x01u}};
constexpr std::array<std::uint8_t, 2> kTablesTypeOrMethodDef{{0x02u, 0x06u}};
constexpr std::array<std::uint8_t, 27> kTablesHasCustomDebugInformation{{
    0x06u, 0x04u, 0x01u, 0x02u, 0x08u, 0x09u, 0x0Au, 0x00u,
    0x0Eu, 0x17u, 0x14u, 0x11u, 0x1Au, 0x1Bu, 0x20u, 0x23u,
    0x26u, 0x27u, 0x28u, 0x2Au, 0x2Cu, 0x2Bu, 0x30u, 0x32u,
    0x33u, 0x34u, 0x35u,
}};

[[nodiscard]] CodedIndexSpec coded_index_spec(CodedIndexKind kind) noexcept {
    switch (kind) {
        case CodedIndexKind::TypeDefOrRef:
            return {2u, kTablesTypeDefOrRef};
        case CodedIndexKind::HasConstant:
            return {2u, kTablesHasConstant};
        case CodedIndexKind::HasCustomAttribute:
            return {5u, kTablesHasCustomAttribute};
        case CodedIndexKind::HasFieldMarshal:
            return {1u, kTablesHasFieldMarshal};
        case CodedIndexKind::HasDeclSecurity:
            return {2u, kTablesHasDeclSecurity};
        case CodedIndexKind::MemberRefParent:
            return {3u, kTablesMemberRefParent};
        case CodedIndexKind::HasSemantics:
            return {1u, kTablesHasSemantics};
        case CodedIndexKind::MethodDefOrRef:
            return {1u, kTablesMethodDefOrRef};
        case CodedIndexKind::MemberForwarded:
            return {1u, kTablesMemberForwarded};
        case CodedIndexKind::Implementation:
            return {2u, kTablesImplementation};
        case CodedIndexKind::CustomAttributeType:
            return {3u, kTablesCustomAttributeType};
        case CodedIndexKind::ResolutionScope:
            return {2u, kTablesResolutionScope};
        case CodedIndexKind::TypeOrMethodDef:
            return {1u, kTablesTypeOrMethodDef};
        case CodedIndexKind::HasCustomDebugInformation:
            return {5u, kTablesHasCustomDebugInformation};
    }
    return {2u, kTablesTypeDefOrRef};
}

struct TableLayoutContext {
    std::uint8_t string_index_size{2u};
    std::uint8_t guid_index_size{2u};
    std::uint8_t blob_index_size{2u};
    std::array<std::uint32_t, 64> rows{};

    [[nodiscard]] std::uint32_t simple_index_size(std::uint8_t table_id) const noexcept {
        if (table_id >= rows.size()) {
            return 2u;
        }
        return rows[table_id] < 65'536u ? 2u : 4u;
    }

    [[nodiscard]] std::uint32_t coded_index_size(CodedIndexKind kind) const noexcept {
        const CodedIndexSpec spec = coded_index_spec(kind);
        const std::uint32_t threshold = 1u << (16u - spec.tag_bits);
        for (const std::uint8_t tbl : spec.tables) {
            if (tbl < rows.size() && rows[tbl] >= threshold) {
                return 4u;
            }
        }
        return 2u;
    }

    [[nodiscard]] static std::uint32_t decode_coded_token(CodedIndexKind kind,
                                                          std::uint32_t raw) noexcept {
        if (raw == 0u) {
            return 0u;
        }
        const CodedIndexSpec spec = coded_index_spec(kind);
        const std::uint32_t mask = (1u << spec.tag_bits) - 1u;
        const std::uint32_t tag = raw & mask;
        const std::uint32_t rid = raw >> spec.tag_bits;
        if (rid == 0u || tag >= spec.tables.size()) {
            return 0u;
        }
        const std::uint8_t tbl = spec.tables[tag];
        if (tbl == 0xFFu || rid > 0x00FFFFFFu) {
            return 0u;
        }
        return (static_cast<std::uint32_t>(tbl) << 24u) | rid;
    }
};

// Returns exact row byte stride for ECMA-335 tables `0x00..0x2C` + Portable PDB `0x30..0x37`,
// or `std::nullopt` for unknown/reserved table IDs (`0x2D..0x2F`, `0x38..0x3F`).
[[nodiscard]] std::optional<std::uint32_t> compute_table_row_stride(
    std::uint8_t table_id,
    const TableLayoutContext& ctx) noexcept {
    const std::uint32_t s = ctx.string_index_size;
    const std::uint32_t g = ctx.guid_index_size;
    const std::uint32_t b = ctx.blob_index_size;

    switch (table_id) {
        case 0x00u: // Module: Generation(2) + Name(S) + Mvid(G) + EncId(G) + EncBaseId(G)
            return 2u + s + 3u * g;
        case 0x01u: // TypeRef: ResolutionScope + TypeName(S) + TypeNamespace(S)
            return ctx.coded_index_size(CodedIndexKind::ResolutionScope) + 2u * s;
        case 0x02u: // TypeDef: Flags(4) + Name(S) + Namespace(S) + Extends + FieldList + MethodList
            return 4u + 2u * s + ctx.coded_index_size(CodedIndexKind::TypeDefOrRef) +
                   ctx.simple_index_size(0x04u) + ctx.simple_index_size(0x06u);
        case 0x03u: // FieldPtr
            return ctx.simple_index_size(0x04u);
        case 0x04u: // Field: Flags(2) + Name(S) + Signature(B)
            return 2u + s + b;
        case 0x05u: // MethodPtr
            return ctx.simple_index_size(0x06u);
        case 0x06u: // MethodDef: RVA(4) + ImplFlags(2) + Flags(2) + Name(S) + Signature(B) + ParamList
            return 8u + s + b + ctx.simple_index_size(0x08u);
        case 0x07u: // ParamPtr
            return ctx.simple_index_size(0x08u);
        case 0x08u: // Param: Flags(2) + Sequence(2) + Name(S)
            return 4u + s;
        case 0x09u: // InterfaceImpl: Class(TypeDef) + Interface(TypeDefOrRef)
            return ctx.simple_index_size(0x02u) +
                   ctx.coded_index_size(CodedIndexKind::TypeDefOrRef);
        case 0x0Au: // MemberRef: Class(MemberRefParent) + Name(S) + Signature(B)
            return ctx.coded_index_size(CodedIndexKind::MemberRefParent) + s + b;
        case 0x0Bu: // Constant: Type(1) + Pad(1) + Parent(HasConstant) + Value(B)
            return 2u + ctx.coded_index_size(CodedIndexKind::HasConstant) + b;
        case 0x0Cu: // CustomAttribute: Parent + Type + Value(B)
            return ctx.coded_index_size(CodedIndexKind::HasCustomAttribute) +
                   ctx.coded_index_size(CodedIndexKind::CustomAttributeType) + b;
        case 0x0Du: // FieldMarshal: Parent(HasFieldMarshal) + NativeType(B)
            return ctx.coded_index_size(CodedIndexKind::HasFieldMarshal) + b;
        case 0x0Eu: // DeclSecurity: Action(2) + Parent(HasDeclSecurity) + PermissionSet(B)
            return 2u + ctx.coded_index_size(CodedIndexKind::HasDeclSecurity) + b;
        case 0x0Fu: // ClassLayout: PackingSize(2) + ClassSize(4) + Parent(TypeDef)
            return 6u + ctx.simple_index_size(0x02u);
        case 0x10u: // FieldLayout: Offset(4) + Field
            return 4u + ctx.simple_index_size(0x04u);
        case 0x11u: // StandAloneSig: Signature(B)
            return b;
        case 0x12u: // EventMap: Parent(TypeDef) + EventList(Event)
            return ctx.simple_index_size(0x02u) + ctx.simple_index_size(0x14u);
        case 0x13u: // EventPtr
            return ctx.simple_index_size(0x14u);
        case 0x14u: // Event: EventFlags(2) + Name(S) + EventType(TypeDefOrRef)
            return 2u + s + ctx.coded_index_size(CodedIndexKind::TypeDefOrRef);
        case 0x15u: // PropertyMap: Parent(TypeDef) + PropertyList(Property)
            return ctx.simple_index_size(0x02u) + ctx.simple_index_size(0x17u);
        case 0x16u: // PropertyPtr
            return ctx.simple_index_size(0x17u);
        case 0x17u: // Property: PropFlags(2) + Name(S) + Type(B)
            return 2u + s + b;
        case 0x18u: // MethodSemantics: Semantics(2) + Method(MethodDef) + Association(HasSemantics)
            return 2u + ctx.simple_index_size(0x06u) +
                   ctx.coded_index_size(CodedIndexKind::HasSemantics);
        case 0x19u: // MethodImpl: Class(TypeDef) + MethodBody + MethodDeclaration
            return ctx.simple_index_size(0x02u) +
                   2u * ctx.coded_index_size(CodedIndexKind::MethodDefOrRef);
        case 0x1Au: // ModuleRef: Name(S)
            return s;
        case 0x1Bu: // TypeSpec: Signature(B)
            return b;
        case 0x1Cu: // ImplMap: MappingFlags(2) + MemberForwarded + ImportName(S) + ImportScope(ModuleRef)
            return 2u + ctx.coded_index_size(CodedIndexKind::MemberForwarded) + s +
                   ctx.simple_index_size(0x1Au);
        case 0x1Du: // FieldRVA: RVA(4) + Field
            return 4u + ctx.simple_index_size(0x04u);
        case 0x1Eu: // ENCLog: Token(4) + FuncCode(4)
            return 8u;
        case 0x1Fu: // ENCMap: Token(4)
            return 4u;
        case 0x20u: // Assembly: HashAlgId(4) + Ver(8) + Flags(4) + PublicKey(B) + Name(S) + Culture(S)
            return 16u + b + 2u * s;
        case 0x21u: // AssemblyProcessor: Processor(4)
            return 4u;
        case 0x22u: // AssemblyOS: OSPlatformID(4) + OSMajor(4) + OSMinor(4)
            return 12u;
        case 0x23u: // AssemblyRef: Ver(8) + Flags(4) + PublicKeyOrToken(B) + Name(S) + Culture(S) + HashValue(B)
            return 12u + 2u * b + 2u * s;
        case 0x24u: // AssemblyRefProcessor: Processor(4) + AssemblyRef
            return 4u + ctx.simple_index_size(0x23u);
        case 0x25u: // AssemblyRefOS: OSPlatformID(4) + OSMajor(4) + OSMinor(4) + AssemblyRef
            return 12u + ctx.simple_index_size(0x23u);
        case 0x26u: // File: Flags(4) + Name(S) + HashValue(B)
            return 4u + s + b;
        case 0x27u: // ExportedType: Flags(4) + TypeDefId(4) + Name(S) + Namespace(S) + Implementation
            return 8u + 2u * s + ctx.coded_index_size(CodedIndexKind::Implementation);
        case 0x28u: // ManifestResource: Offset(4) + Flags(4) + Name(S) + Implementation
            return 8u + s + ctx.coded_index_size(CodedIndexKind::Implementation);
        case 0x29u: // NestedClass: NestedClass(TypeDef) + EnclosingClass(TypeDef)
            return 2u * ctx.simple_index_size(0x02u);
        case 0x2Au: // GenericParam: Number(2) + Flags(2) + Owner(TypeOrMethodDef) + Name(S)
            return 4u + ctx.coded_index_size(CodedIndexKind::TypeOrMethodDef) + s;
        case 0x2Bu: // MethodSpec: Method(MethodDefOrRef) + Instantiation(B)
            return ctx.coded_index_size(CodedIndexKind::MethodDefOrRef) + b;
        case 0x2Cu: // GenericParamConstraint: Owner(GenericParam) + Constraint(TypeDefOrRef)
            return ctx.simple_index_size(0x2Au) +
                   ctx.coded_index_size(CodedIndexKind::TypeDefOrRef);

        // Portable PDB Metadata Tables (`0x30..0x37`)
        case 0x30u: // Document: Name(B) + HashAlgorithm(G) + Hash(B) + Language(G)
            return 2u * b + 2u * g;
        case 0x31u: // MethodDebugInformation: Document(0x30) + SequencePoints(B)
            return ctx.simple_index_size(0x30u) + b;
        case 0x32u: // LocalScope: Method(0x06) + ImportScope(0x35) + VarList(0x33) + ConstList(0x34) + Start(4) + Len(4)
            return ctx.simple_index_size(0x06u) + ctx.simple_index_size(0x35u) +
                   ctx.simple_index_size(0x33u) + ctx.simple_index_size(0x34u) + 8u;
        case 0x33u: // LocalVariable: Attributes(2) + Index(2) + Name(S)
            return 4u + s;
        case 0x34u: // LocalConstant: Name(S) + Signature(B)
            return s + b;
        case 0x35u: // ImportScope: Parent(0x35) + Imports(B)
            return ctx.simple_index_size(0x35u) + b;
        case 0x36u: // StateMachineMethod: MoveNextMethod(0x06) + KickoffMethod(0x06)
            return 2u * ctx.simple_index_size(0x06u);
        case 0x37u: // CustomDebugInformation: Parent(HasCustomDebugInformation) + Kind(G) + Value(B)
            return ctx.coded_index_size(CodedIndexKind::HasCustomDebugInformation) + g + b;

        default:
            return std::nullopt;
    }
}

struct HeapView {
    std::span<const std::uint8_t> strings{};
    std::span<const std::uint8_t> us{};
    std::span<const std::uint8_t> guid{};
    std::span<const std::uint8_t> blob{};
    std::vector<std::string>* diagnostics{nullptr};
    bool* degraded{nullptr};

    void mark_degraded(std::string msg) const {
        if (degraded != nullptr) {
            *degraded = true;
        }
        if (diagnostics != nullptr) {
            push_diagnostic(*diagnostics, std::move(msg));
        }
    }

    [[nodiscard]] std::string read_string(std::uint32_t index) const {
        if (index == 0u) {
            return {};
        }
        if (strings.empty() || index >= strings.size()) {
            mark_degraded(std::format("Out-of-bounds #Strings index 0x{:X} (heap size 0x{:X})",
                                      index,
                                      strings.size()));
            return "<invalid-string>";
        }
        const std::size_t max_rem = std::min<std::size_t>(strings.size() - index, kMaxStringBytes);
        std::size_t len = 0u;
        while (len < max_rem && strings[index + len] != 0u) {
            ++len;
        }
        if (index + len >= strings.size() && (len == 0u || strings.back() != 0u)) {
            mark_degraded(std::format("Unterminated #Strings entry at offset 0x{:X}", index));
        }
        return std::string(reinterpret_cast<const char*>(strings.data() + index), len);
    }

    [[nodiscard]] std::string read_guid(std::uint32_t one_based_index) const {
        if (one_based_index == 0u) {
            return {};
        }
        const std::uint64_t byte_off = (static_cast<std::uint64_t>(one_based_index) - 1u) * 16u;
        if (byte_off > guid.size() || guid.size() - static_cast<std::size_t>(byte_off) < 16u) {
            mark_degraded(std::format("Out-of-bounds #GUID index {} (heap size 0x{:X})",
                                      one_based_index,
                                      guid.size()));
            return "<invalid-guid>";
        }
        const auto s = guid.subspan(static_cast<std::size_t>(byte_off), 16u);
        const std::uint32_t d1 =
            static_cast<std::uint32_t>(s[0]) |
            (static_cast<std::uint32_t>(s[1]) << 8u) |
            (static_cast<std::uint32_t>(s[2]) << 16u) |
            (static_cast<std::uint32_t>(s[3]) << 24u);
        const std::uint16_t d2 =
            static_cast<std::uint16_t>(s[4]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(s[5]) << 8u);
        const std::uint16_t d3 =
            static_cast<std::uint16_t>(s[6]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(s[7]) << 8u);
        return std::format(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d1, d2, d3,
            s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]);
    }

    [[nodiscard]] std::optional<std::span<const std::uint8_t>> read_blob(std::uint32_t index) const {
        if (index == 0u) {
            return std::span<const std::uint8_t>{};
        }
        if (blob.empty() || index >= blob.size()) {
            mark_degraded(std::format("Out-of-bounds #Blob index 0x{:X} (heap size 0x{:X})",
                                      index,
                                      blob.size()));
            return std::nullopt;
        }
        const auto len_and_hdr = decode_compressed_uint(blob, index);
        if (!len_and_hdr.has_value()) {
            mark_degraded(std::format("Malformed compressed length in #Blob at 0x{:X}", index));
            return std::nullopt;
        }
        const auto [byte_len, hdr_bytes] = *len_and_hdr;
        const std::size_t payload_off = static_cast<std::size_t>(index) + hdr_bytes;
        if (payload_off > blob.size() || byte_len > blob.size() - payload_off) {
            mark_degraded(std::format("Truncated #Blob entry at 0x{:X} (length {} exceeds heap)",
                                      index,
                                      byte_len));
            return std::nullopt;
        }
        return blob.subspan(payload_off, byte_len);
    }

    [[nodiscard]] std::optional<std::string> read_user_string(std::uint32_t us_offset) const {
        if (us_offset == 0u) {
            return std::string{};
        }
        if (us.empty() || us_offset >= us.size()) {
            mark_degraded(std::format("Out-of-bounds #US offset 0x{:X} (heap size 0x{:X})",
                                      us_offset,
                                      us.size()));
            return std::nullopt;
        }
        const auto len_and_hdr = decode_compressed_uint(us, us_offset);
        if (!len_and_hdr.has_value()) {
            mark_degraded(std::format("Malformed compressed length in #US at 0x{:X}", us_offset));
            return std::nullopt;
        }
        const auto [byte_len, hdr_bytes] = *len_and_hdr;
        const std::size_t payload_off = static_cast<std::size_t>(us_offset) + hdr_bytes;
        if (payload_off > us.size() || byte_len > us.size() - payload_off) {
            mark_degraded(std::format("Truncated #US entry at 0x{:X} (length {} exceeds heap)",
                                      us_offset,
                                      byte_len));
            return std::nullopt;
        }
        if (byte_len == 0u) {
            return std::string{};
        }
        const std::size_t utf16_bytes =
            (byte_len & 1u) != 0u ? static_cast<std::size_t>(byte_len - 1u)
                                  : static_cast<std::size_t>(byte_len);
        return decode_utf16_to_utf8(
            us.subspan(payload_off, utf16_bytes), Endianness::Little, /*stop_at_nul=*/false);
    }
};

struct RowCursor {
    EndianReader reader;
    std::size_t pos{0u};

    [[nodiscard]] std::uint16_t u16() noexcept {
        const auto v = reader.read_u16(pos);
        pos += 2u;
        return v.value_or(0u);
    }

    [[nodiscard]] std::uint32_t u32() noexcept {
        const auto v = reader.read_u32(pos);
        pos += 4u;
        return v.value_or(0u);
    }

    [[nodiscard]] std::uint32_t idx(std::uint32_t width) noexcept {
        return width == 4u ? u32() : static_cast<std::uint32_t>(u16());
    }
};

[[nodiscard]] std::string join_namespace_name(std::string_view ns, std::string_view name) {
    if (ns.empty()) {
        return std::string(name);
    }
    std::string out{};
    out.reserve(ns.size() + 1u + name.size());
    out.append(ns);
    out.push_back('.');
    out.append(name);
    return out;
}

[[nodiscard]] std::string describe_typedef_visibility(std::uint32_t flags) {
    switch (flags & 0x00000007u) {
        case 0x00u: return "internal";
        case 0x01u: return "public";
        case 0x02u: return "nested public";
        case 0x03u: return "nested private";
        case 0x04u: return "nested family";
        case 0x05u: return "nested assembly";
        case 0x06u: return "nested famorassem";
        case 0x07u: return "nested famandassem";
        default:    return "internal";
    }
}

[[nodiscard]] std::string describe_typedef_kind(std::uint32_t flags, std::string_view extends_name) {
    if ((flags & 0x00000020u) != 0u) {
        return "interface";
    }
    if (extends_name == "System.Enum") {
        return "enum";
    }
    if (extends_name == "System.ValueType") {
        return "struct";
    }
    if (extends_name == "System.MulticastDelegate" || extends_name == "System.Delegate") {
        return "delegate";
    }
    if ((flags & 0x00000180u) == 0x00000180u) {
        return "static class";
    }
    if ((flags & 0x00000080u) != 0u) {
        return "abstract class";
    }
    if ((flags & 0x00000100u) != 0u) {
        return "sealed class";
    }
    return "class";
}

[[nodiscard]] std::string describe_field_flags(std::uint16_t flags) {
    std::string out{};
    switch (flags & 0x0007u) {
        case 0x01u: out = "private"; break;
        case 0x02u: out = "famandassem"; break;
        case 0x03u: out = "internal"; break;
        case 0x04u: out = "protected"; break;
        case 0x05u: out = "famorassem"; break;
        case 0x06u: out = "public"; break;
        default:    out = "compilercontrolled"; break;
    }
    if ((flags & 0x0010u) != 0u) out += " static";
    if ((flags & 0x0020u) != 0u) out += " initonly";
    if ((flags & 0x0040u) != 0u) out += " literal";
    return out;
}

[[nodiscard]] std::string describe_method_flags(std::uint16_t flags, std::uint16_t impl_flags) {
    std::string out{};
    switch (flags & 0x0007u) {
        case 0x01u: out = "private"; break;
        case 0x02u: out = "famandassem"; break;
        case 0x03u: out = "internal"; break;
        case 0x04u: out = "protected"; break;
        case 0x05u: out = "famorassem"; break;
        case 0x06u: out = "public"; break;
        default:    out = "compilercontrolled"; break;
    }
    if ((flags & 0x0010u) != 0u) out += " static";
    if ((flags & 0x0020u) != 0u) out += " final";
    if ((flags & 0x0040u) != 0u) out += " virtual";
    if ((flags & 0x0400u) != 0u) out += " abstract";
    if ((flags & 0x2000u) != 0u) out += " pinvokeimpl";
    if ((impl_flags & 0x0003u) == 0x0001u) out += " native";
    if ((impl_flags & 0x0003u) == 0x0003u) out += " runtime";
    if ((impl_flags & 0x1000u) != 0u) out += " internalcall";
    return out;
}

[[nodiscard]] std::string describe_pinvoke_callconv(std::uint16_t mapping_flags) {
    switch (mapping_flags & 0x0700u) {
        case 0x0100u: return "Winapi";
        case 0x0200u: return "Cdecl";
        case 0x0300u: return "StdCall";
        case 0x0400u: return "ThisCall";
        case 0x0500u: return "FastCall";
        default:      return "Default";
    }
}

[[nodiscard]] std::string describe_pinvoke_charset(std::uint16_t mapping_flags) {
    switch (mapping_flags & 0x0006u) {
        case 0x0002u: return "Ansi";
        case 0x0004u: return "Unicode";
        case 0x0006u: return "Auto";
        default:      return "NotSpec";
    }
}

// Resolves `TypeDefOrRefOrSpecEncoded` compressed unsigned integer in ECMA-335 II.23.2.8 blobs.
[[nodiscard]] std::string resolve_sig_type_token(std::uint32_t encoded, const ClrMetadata& md) {
    const std::uint32_t tag = encoded & 0x03u;
    const std::uint32_t rid = encoded >> 2u;
    if (rid == 0u || rid > 0x00FFFFFFu) {
        return std::format("0x{:08X}", encoded);
    }
    std::uint8_t tbl = 0xFFu;
    if (tag == 0u) tbl = 0x02u;
    else if (tag == 1u) tbl = 0x01u;
    else if (tag == 2u) tbl = 0x1Bu;
    if (tbl == 0xFFu) {
        return std::format("0x{:08X}", encoded);
    }
    const std::uint32_t tok = (static_cast<std::uint32_t>(tbl) << 24u) | rid;
    if (const auto name = md.resolve_token(tok); name.has_value()) {
        return *name;
    }
    return std::format("0x{:08X}", tok);
}

struct SignatureReader {
    std::span<const std::uint8_t> bytes{};
    std::size_t pos{0u};
    const ClrMetadata& md;

    [[nodiscard]] std::optional<std::uint8_t> read_byte() noexcept {
        if (pos >= bytes.size()) {
            return std::nullopt;
        }
        return bytes[pos++];
    }

    [[nodiscard]] std::optional<std::uint32_t> read_compressed() noexcept {
        const auto dec = decode_compressed_uint(bytes, pos);
        if (!dec.has_value()) {
            return std::nullopt;
        }
        pos += dec->second;
        return dec->first;
    }

    [[nodiscard]] std::string decode_type(std::size_t depth = 0u) {
        if (depth > kMaxSignatureDepth) {
            return "...";
        }
        // Strip custom modifiers (`CMOD_REQD`, `CMOD_OPT`) and `PINNED`.
        bool is_pinned = false;
        std::size_t mod_steps = 0u;
        while (pos < bytes.size() && mod_steps < 16u) {
            const std::uint8_t peek = bytes[pos];
            if (peek == 0x1Fu || peek == 0x20u) {
                ++pos;
                if (!read_compressed().has_value()) {
                    return "...";
                }
                ++mod_steps;
                continue;
            }
            if (peek == 0x45u) { // ELEMENT_TYPE_PINNED
                ++pos;
                is_pinned = true;
                ++mod_steps;
                continue;
            }
            break;
        }

        const auto elem_opt = read_byte();
        if (!elem_opt.has_value()) {
            return "...";
        }
        std::string base{};
        switch (*elem_opt) {
            case 0x01u: base = "void"; break;
            case 0x02u: base = "bool"; break;
            case 0x03u: base = "char"; break;
            case 0x04u: base = "int8"; break;
            case 0x05u: base = "uint8"; break;
            case 0x06u: base = "int16"; break;
            case 0x07u: base = "uint16"; break;
            case 0x08u: base = "int32"; break;
            case 0x09u: base = "uint32"; break;
            case 0x0Au: base = "int64"; break;
            case 0x0Bu: base = "uint64"; break;
            case 0x0Cu: base = "float32"; break;
            case 0x0Du: base = "float64"; break;
            case 0x0Eu: base = "string"; break;
            case 0x0Fu: { // PTR
                const std::string inner = decode_type(depth + 1u);
                base = inner == "..." ? "..." : (inner + "*");
                break;
            }
            case 0x10u: { // BYREF
                const std::string inner = decode_type(depth + 1u);
                base = inner == "..." ? "..." : (inner + "&");
                break;
            }
            case 0x11u: // VALUETYPE
            case 0x12u: { // CLASS
                const auto encoded = read_compressed();
                if (!encoded.has_value()) {
                    return "...";
                }
                base = resolve_sig_type_token(*encoded, md);
                break;
            }
            case 0x13u: { // VAR (!T)
                const auto num = read_compressed();
                if (!num.has_value()) return "...";
                base = std::format("!{}", *num);
                break;
            }
            case 0x14u: { // ARRAY: Type Rank NumSizes Size* NumLoBounds LoBound*
                const std::string inner = decode_type(depth + 1u);
                const auto rank = read_compressed();
                const auto num_sizes = read_compressed();
                if (!rank.has_value() || !num_sizes.has_value() || *num_sizes > 64u) {
                    return "...";
                }
                for (std::uint32_t i = 0u; i < *num_sizes; ++i) {
                    if (!read_compressed().has_value()) return "...";
                }
                const auto num_lo = read_compressed();
                if (!num_lo.has_value() || *num_lo > 64u) {
                    return "...";
                }
                for (std::uint32_t i = 0u; i < *num_lo; ++i) {
                    if (!read_compressed().has_value()) return "...";
                }
                std::string dims = "[";
                for (std::uint32_t r = 1u; r < std::min<std::uint32_t>(*rank, 16u); ++r) {
                    dims.push_back(',');
                }
                dims.push_back(']');
                base = inner + dims;
                break;
            }
            case 0x15u: { // GENERICINST: (CLASS|VALUETYPE) TypeDefOrRefOrSpecEncoded GenArgCount Type*
                const auto kind_b = read_byte();
                const auto encoded = read_compressed();
                const auto argc = read_compressed();
                if (!kind_b.has_value() || (*kind_b != 0x11u && *kind_b != 0x12u) ||
                    !encoded.has_value() || !argc.has_value() || *argc > 64u) {
                    return "...";
                }
                std::string gname = resolve_sig_type_token(*encoded, md);
                gname.push_back('<');
                for (std::uint32_t i = 0u; i < *argc; ++i) {
                    if (i > 0u) gname += ", ";
                    gname += decode_type(depth + 1u);
                }
                gname.push_back('>');
                base = std::move(gname);
                break;
            }
            case 0x16u: base = "typedbyref"; break;
            case 0x18u: base = "intptr"; break;
            case 0x19u: base = "uintptr"; break;
            case 0x1Bu: { // FNPTR
                const auto cc = read_byte();
                if (!cc.has_value()) return "...";
                if ((*cc & 0x10u) != 0u && !read_compressed().has_value()) return "...";
                const auto pcount = read_compressed();
                if (!pcount.has_value() || *pcount > kMaxSignatureParams) return "...";
                const std::string ret = decode_type(depth + 1u);
                std::string fn = "fnptr " + ret + "(";
                for (std::uint32_t i = 0u; i < *pcount; ++i) {
                    if (i > 0u) fn += ", ";
                    fn += decode_type(depth + 1u);
                }
                fn.push_back(')');
                base = std::move(fn);
                break;
            }
            case 0x1Cu: base = "object"; break;
            case 0x1Du: { // SZARRAY
                const std::string inner = decode_type(depth + 1u);
                base = inner == "..." ? "..." : (inner + "[]");
                break;
            }
            case 0x1Eu: { // MVAR (!!M)
                const auto num = read_compressed();
                if (!num.has_value()) return "...";
                base = std::format("!!{}", *num);
                break;
            }
            case 0x41u: base = "..."; break; // SENTINEL
            default:    base = "..."; break;
        }
        if (is_pinned && base != "...") {
            base += " pinned";
        }
        return base;
    }
};

struct DecodedMethodSig {
    bool is_field{false};
    std::uint32_t generic_arity{0u};
    std::string return_type{"..."};
    std::vector<std::string> param_types{};
};

[[nodiscard]] DecodedMethodSig decode_method_or_member_sig(
    std::span<const std::uint8_t> blob,
    const ClrMetadata& md) {
    DecodedMethodSig out{};
    if (blob.empty()) {
        return out;
    }
    SignatureReader sr{.bytes = blob, .pos = 0u, .md = md};
    const auto cc_opt = sr.read_byte();
    if (!cc_opt.has_value()) {
        return out;
    }
    const std::uint8_t cc = *cc_opt;
    if ((cc & 0x0Fu) == 0x06u) {
        out.is_field = true;
        out.return_type = sr.decode_type(0u);
        return out;
    }
    if ((cc & 0x10u) != 0u) {
        const auto ga = sr.read_compressed();
        if (!ga.has_value()) {
            return out;
        }
        out.generic_arity = *ga;
    }
    const auto param_count_opt = sr.read_compressed();
    if (!param_count_opt.has_value()) {
        return out;
    }
    const std::uint32_t param_count = std::min<std::uint32_t>(
        *param_count_opt, static_cast<std::uint32_t>(kMaxSignatureParams));
    out.return_type = sr.decode_type(0u);
    out.param_types.reserve(param_count);
    for (std::uint32_t i = 0u; i < param_count; ++i) {
        if (sr.pos < sr.bytes.size() && sr.bytes[sr.pos] == 0x41u) {
            ++sr.pos; // vararg SENTINEL before optional vararg types
            out.param_types.emplace_back("...");
        }
        out.param_types.push_back(sr.decode_type(0u));
    }
    return out;
}

[[nodiscard]] std::string format_method_sig_summary(
    std::string_view ret_type,
    std::span<const std::string> param_types,
    std::span<const std::string> param_names = {}) {
    std::string out{};
    out.append(ret_type.empty() ? "..." : ret_type);
    out.push_back('(');
    for (std::size_t i = 0u; i < param_types.size(); ++i) {
        if (i > 0u) {
            out += ", ";
        }
        out += param_types[i];
        if (i < param_names.size() && !param_names[i].empty()) {
            out.push_back(' ');
            out += param_names[i];
        }
    }
    out.push_back(')');
    return out;
}

// ---------------------------------------------------------------------------
// CIL Opcode Descriptors (ECMA-335 Partition III)
// ---------------------------------------------------------------------------

enum class CilOperandKind : std::uint8_t {
    Invalid,
    InlineNone,
    ShortInlineVar,
    InlineVar,
    ShortInlineI_Signed,
    ShortInlineI_Unsigned,
    InlineI,
    InlineI8,
    ShortInlineR,
    InlineR,
    ShortInlineBrTarget,
    InlineBrTarget,
    InlineSwitch,
    InlineMethod,
    InlineField,
    InlineType,
    InlineString,
    InlineSig,
    InlineTok,
};

struct CilOpcodeSpec {
    std::string_view mnemonic{};
    CilOperandKind operand{CilOperandKind::Invalid};
};

[[nodiscard]] constexpr CilOpcodeSpec lookup_single_byte_opcode(std::uint8_t op) noexcept {
    using K = CilOperandKind;
    switch (op) {
        case 0x00u: return {"nop", K::InlineNone};
        case 0x01u: return {"break", K::InlineNone};
        case 0x02u: return {"ldarg.0", K::InlineNone};
        case 0x03u: return {"ldarg.1", K::InlineNone};
        case 0x04u: return {"ldarg.2", K::InlineNone};
        case 0x05u: return {"ldarg.3", K::InlineNone};
        case 0x06u: return {"ldloc.0", K::InlineNone};
        case 0x07u: return {"ldloc.1", K::InlineNone};
        case 0x08u: return {"ldloc.2", K::InlineNone};
        case 0x09u: return {"ldloc.3", K::InlineNone};
        case 0x0Au: return {"stloc.0", K::InlineNone};
        case 0x0Bu: return {"stloc.1", K::InlineNone};
        case 0x0Cu: return {"stloc.2", K::InlineNone};
        case 0x0Du: return {"stloc.3", K::InlineNone};
        case 0x0Eu: return {"ldarg.s", K::ShortInlineVar};
        case 0x0Fu: return {"ldarga.s", K::ShortInlineVar};
        case 0x10u: return {"starg.s", K::ShortInlineVar};
        case 0x11u: return {"ldloc.s", K::ShortInlineVar};
        case 0x12u: return {"ldloca.s", K::ShortInlineVar};
        case 0x13u: return {"stloc.s", K::ShortInlineVar};
        case 0x14u: return {"ldnull", K::InlineNone};
        case 0x15u: return {"ldc.i4.m1", K::InlineNone};
        case 0x16u: return {"ldc.i4.0", K::InlineNone};
        case 0x17u: return {"ldc.i4.1", K::InlineNone};
        case 0x18u: return {"ldc.i4.2", K::InlineNone};
        case 0x19u: return {"ldc.i4.3", K::InlineNone};
        case 0x1Au: return {"ldc.i4.4", K::InlineNone};
        case 0x1Bu: return {"ldc.i4.5", K::InlineNone};
        case 0x1Cu: return {"ldc.i4.6", K::InlineNone};
        case 0x1Du: return {"ldc.i4.7", K::InlineNone};
        case 0x1Eu: return {"ldc.i4.8", K::InlineNone};
        case 0x1Fu: return {"ldc.i4.s", K::ShortInlineI_Signed};
        case 0x20u: return {"ldc.i4", K::InlineI};
        case 0x21u: return {"ldc.i8", K::InlineI8};
        case 0x22u: return {"ldc.r4", K::ShortInlineR};
        case 0x23u: return {"ldc.r8", K::InlineR};
        case 0x25u: return {"dup", K::InlineNone};
        case 0x26u: return {"pop", K::InlineNone};
        case 0x27u: return {"jmp", K::InlineMethod};
        case 0x28u: return {"call", K::InlineMethod};
        case 0x29u: return {"calli", K::InlineSig};
        case 0x2Au: return {"ret", K::InlineNone};
        case 0x2Bu: return {"br.s", K::ShortInlineBrTarget};
        case 0x2Cu: return {"brfalse.s", K::ShortInlineBrTarget};
        case 0x2Du: return {"brtrue.s", K::ShortInlineBrTarget};
        case 0x2Eu: return {"beq.s", K::ShortInlineBrTarget};
        case 0x2Fu: return {"bge.s", K::ShortInlineBrTarget};
        case 0x30u: return {"bgt.s", K::ShortInlineBrTarget};
        case 0x31u: return {"ble.s", K::ShortInlineBrTarget};
        case 0x32u: return {"blt.s", K::ShortInlineBrTarget};
        case 0x33u: return {"bne.un.s", K::ShortInlineBrTarget};
        case 0x34u: return {"bge.un.s", K::ShortInlineBrTarget};
        case 0x35u: return {"bgt.un.s", K::ShortInlineBrTarget};
        case 0x36u: return {"ble.un.s", K::ShortInlineBrTarget};
        case 0x37u: return {"blt.un.s", K::ShortInlineBrTarget};
        case 0x38u: return {"br", K::InlineBrTarget};
        case 0x39u: return {"brfalse", K::InlineBrTarget};
        case 0x3Au: return {"brtrue", K::InlineBrTarget};
        case 0x3Bu: return {"beq", K::InlineBrTarget};
        case 0x3Cu: return {"bge", K::InlineBrTarget};
        case 0x3Du: return {"bgt", K::InlineBrTarget};
        case 0x3Eu: return {"ble", K::InlineBrTarget};
        case 0x3Fu: return {"blt", K::InlineBrTarget};
        case 0x40u: return {"bne.un", K::InlineBrTarget};
        case 0x41u: return {"bge.un", K::InlineBrTarget};
        case 0x42u: return {"bgt.un", K::InlineBrTarget};
        case 0x43u: return {"ble.un", K::InlineBrTarget};
        case 0x44u: return {"blt.un", K::InlineBrTarget};
        case 0x45u: return {"switch", K::InlineSwitch};
        case 0x46u: return {"ldind.i1", K::InlineNone};
        case 0x47u: return {"ldind.u1", K::InlineNone};
        case 0x48u: return {"ldind.i2", K::InlineNone};
        case 0x49u: return {"ldind.u2", K::InlineNone};
        case 0x4Au: return {"ldind.i4", K::InlineNone};
        case 0x4Bu: return {"ldind.u4", K::InlineNone};
        case 0x4Cu: return {"ldind.i8", K::InlineNone};
        case 0x4Du: return {"ldind.i", K::InlineNone};
        case 0x4Eu: return {"ldind.r4", K::InlineNone};
        case 0x4Fu: return {"ldind.r8", K::InlineNone};
        case 0x50u: return {"ldind.ref", K::InlineNone};
        case 0x51u: return {"stind.ref", K::InlineNone};
        case 0x52u: return {"stind.i1", K::InlineNone};
        case 0x53u: return {"stind.i2", K::InlineNone};
        case 0x54u: return {"stind.i4", K::InlineNone};
        case 0x55u: return {"stind.i8", K::InlineNone};
        case 0x56u: return {"stind.r4", K::InlineNone};
        case 0x57u: return {"stind.r8", K::InlineNone};
        case 0x58u: return {"add", K::InlineNone};
        case 0x59u: return {"sub", K::InlineNone};
        case 0x5Au: return {"mul", K::InlineNone};
        case 0x5Bu: return {"div", K::InlineNone};
        case 0x5Cu: return {"div.un", K::InlineNone};
        case 0x5Du: return {"rem", K::InlineNone};
        case 0x5Eu: return {"rem.un", K::InlineNone};
        case 0x5Fu: return {"and", K::InlineNone};
        case 0x60u: return {"or", K::InlineNone};
        case 0x61u: return {"xor", K::InlineNone};
        case 0x62u: return {"shl", K::InlineNone};
        case 0x63u: return {"shr", K::InlineNone};
        case 0x64u: return {"shr.un", K::InlineNone};
        case 0x65u: return {"neg", K::InlineNone};
        case 0x66u: return {"not", K::InlineNone};
        case 0x67u: return {"conv.i1", K::InlineNone};
        case 0x68u: return {"conv.i2", K::InlineNone};
        case 0x69u: return {"conv.i4", K::InlineNone};
        case 0x6Au: return {"conv.i8", K::InlineNone};
        case 0x6Bu: return {"conv.r4", K::InlineNone};
        case 0x6Cu: return {"conv.r8", K::InlineNone};
        case 0x6Du: return {"conv.u4", K::InlineNone};
        case 0x6Eu: return {"conv.u8", K::InlineNone};
        case 0x6Fu: return {"callvirt", K::InlineMethod};
        case 0x70u: return {"cpobj", K::InlineType};
        case 0x71u: return {"ldobj", K::InlineType};
        case 0x72u: return {"ldstr", K::InlineString};
        case 0x73u: return {"newobj", K::InlineMethod};
        case 0x74u: return {"castclass", K::InlineType};
        case 0x75u: return {"isinst", K::InlineType};
        case 0x76u: return {"conv.r.un", K::InlineNone};
        case 0x79u: return {"unbox", K::InlineType};
        case 0x7Au: return {"throw", K::InlineNone};
        case 0x7Bu: return {"ldfld", K::InlineField};
        case 0x7Cu: return {"ldflda", K::InlineField};
        case 0x7Du: return {"stfld", K::InlineField};
        case 0x7Eu: return {"ldsfld", K::InlineField};
        case 0x7Fu: return {"ldsflda", K::InlineField};
        case 0x80u: return {"stsfld", K::InlineField};
        case 0x81u: return {"stobj", K::InlineType};
        case 0x82u: return {"conv.ovf.i1.un", K::InlineNone};
        case 0x83u: return {"conv.ovf.i2.un", K::InlineNone};
        case 0x84u: return {"conv.ovf.i4.un", K::InlineNone};
        case 0x85u: return {"conv.ovf.i8.un", K::InlineNone};
        case 0x86u: return {"conv.ovf.u1.un", K::InlineNone};
        case 0x87u: return {"conv.ovf.u2.un", K::InlineNone};
        case 0x88u: return {"conv.ovf.u4.un", K::InlineNone};
        case 0x89u: return {"conv.ovf.u8.un", K::InlineNone};
        case 0x8Au: return {"conv.ovf.i.un", K::InlineNone};
        case 0x8Bu: return {"conv.ovf.u.un", K::InlineNone};
        case 0x8Cu: return {"box", K::InlineType};
        case 0x8Du: return {"newarr", K::InlineType};
        case 0x8Eu: return {"ldlen", K::InlineNone};
        case 0x8Fu: return {"ldelema", K::InlineType};
        case 0x90u: return {"ldelem.i1", K::InlineNone};
        case 0x91u: return {"ldelem.u1", K::InlineNone};
        case 0x92u: return {"ldelem.i2", K::InlineNone};
        case 0x93u: return {"ldelem.u2", K::InlineNone};
        case 0x94u: return {"ldelem.i4", K::InlineNone};
        case 0x95u: return {"ldelem.u4", K::InlineNone};
        case 0x96u: return {"ldelem.i8", K::InlineNone};
        case 0x97u: return {"ldelem.i", K::InlineNone};
        case 0x98u: return {"ldelem.r4", K::InlineNone};
        case 0x99u: return {"ldelem.r8", K::InlineNone};
        case 0x9Au: return {"ldelem.ref", K::InlineNone};
        case 0x9Bu: return {"stelem.i", K::InlineNone};
        case 0x9Cu: return {"stelem.i1", K::InlineNone};
        case 0x9Du: return {"stelem.i2", K::InlineNone};
        case 0x9Eu: return {"stelem.i4", K::InlineNone};
        case 0x9Fu: return {"stelem.i8", K::InlineNone};
        case 0xA0u: return {"stelem.r4", K::InlineNone};
        case 0xA1u: return {"stelem.r8", K::InlineNone};
        case 0xA2u: return {"stelem.ref", K::InlineNone};
        case 0xA3u: return {"ldelem", K::InlineType};
        case 0xA4u: return {"stelem", K::InlineType};
        case 0xA5u: return {"unbox.any", K::InlineType};
        case 0xB3u: return {"conv.ovf.i1", K::InlineNone};
        case 0xB4u: return {"conv.ovf.u1", K::InlineNone};
        case 0xB5u: return {"conv.ovf.i2", K::InlineNone};
        case 0xB6u: return {"conv.ovf.u2", K::InlineNone};
        case 0xB7u: return {"conv.ovf.i4", K::InlineNone};
        case 0xB8u: return {"conv.ovf.u4", K::InlineNone};
        case 0xB9u: return {"conv.ovf.i8", K::InlineNone};
        case 0xBAu: return {"conv.ovf.u8", K::InlineNone};
        case 0xC2u: return {"refanyval", K::InlineType};
        case 0xC3u: return {"ckfinite", K::InlineNone};
        case 0xC6u: return {"mkrefany", K::InlineType};
        case 0xD0u: return {"ldtoken", K::InlineTok};
        case 0xD1u: return {"conv.u2", K::InlineNone};
        case 0xD2u: return {"conv.u1", K::InlineNone};
        case 0xD3u: return {"conv.i", K::InlineNone};
        case 0xD4u: return {"conv.ovf.i", K::InlineNone};
        case 0xD5u: return {"conv.ovf.u", K::InlineNone};
        case 0xD6u: return {"add.ovf", K::InlineNone};
        case 0xD7u: return {"add.ovf.un", K::InlineNone};
        case 0xD8u: return {"mul.ovf", K::InlineNone};
        case 0xD9u: return {"mul.ovf.un", K::InlineNone};
        case 0xDAu: return {"sub.ovf", K::InlineNone};
        case 0xDBu: return {"sub.ovf.un", K::InlineNone};
        case 0xDCu: return {"endfinally", K::InlineNone};
        case 0xDDu: return {"leave", K::InlineBrTarget};
        case 0xDEu: return {"leave.s", K::ShortInlineBrTarget};
        case 0xDFu: return {"stind.i", K::InlineNone};
        case 0xE0u: return {"conv.u", K::InlineNone};
        default:    return {{}, K::Invalid};
    }
}

[[nodiscard]] constexpr CilOpcodeSpec lookup_fe_opcode(std::uint8_t op2) noexcept {
    using K = CilOperandKind;
    switch (op2) {
        case 0x00u: return {"arglist", K::InlineNone};
        case 0x01u: return {"ceq", K::InlineNone};
        case 0x02u: return {"cgt", K::InlineNone};
        case 0x03u: return {"cgt.un", K::InlineNone};
        case 0x04u: return {"clt", K::InlineNone};
        case 0x05u: return {"clt.un", K::InlineNone};
        case 0x06u: return {"ldftn", K::InlineMethod};
        case 0x07u: return {"ldvirtftn", K::InlineMethod};
        case 0x09u: return {"ldarg", K::InlineVar};
        case 0x0Au: return {"ldarga", K::InlineVar};
        case 0x0Bu: return {"starg", K::InlineVar};
        case 0x0Cu: return {"ldloc", K::InlineVar};
        case 0x0Du: return {"ldloca", K::InlineVar};
        case 0x0Eu: return {"stloc", K::InlineVar};
        case 0x0Fu: return {"localloc", K::InlineNone};
        case 0x11u: return {"endfilter", K::InlineNone};
        case 0x12u: return {"unaligned.", K::ShortInlineI_Unsigned};
        case 0x13u: return {"volatile.", K::InlineNone};
        case 0x14u: return {"tail.", K::InlineNone};
        case 0x15u: return {"initobj", K::InlineType};
        case 0x16u: return {"constrained.", K::InlineType};
        case 0x17u: return {"cpblk", K::InlineNone};
        case 0x18u: return {"initblk", K::InlineNone};
        case 0x19u: return {"no.", K::ShortInlineI_Unsigned};
        case 0x1Au: return {"rethrow", K::InlineNone};
        case 0x1Cu: return {"sizeof", K::InlineType};
        case 0x1Du: return {"refanytype", K::InlineNone};
        case 0x1Eu: return {"readonly.", K::InlineNone};
        default:    return {{}, K::Invalid};
    }
}

[[nodiscard]] std::string format_il_bytes_hex(std::span<const std::uint8_t> bytes) {
    const std::size_t limit = std::min<std::size_t>(bytes.size(), 10u);
    std::string out{};
    out.reserve(limit * 3u + 4u);
    for (std::size_t i = 0u; i < limit; ++i) {
        if (i > 0u) out.push_back(' ');
        out += std::format("{:02X}", bytes[i]);
    }
    if (bytes.size() > limit) {
        out += " ...";
    }
    return out;
}

}  // namespace

std::string format_cor20_flags(std::uint32_t flags) {
    std::vector<std::string_view> names{};
    if ((flags & kCorImageFlagsIlOnly) != 0u) names.emplace_back("ILONLY");
    if ((flags & kCorImageFlags32BitRequired) != 0u) names.emplace_back("32BITREQUIRED");
    if ((flags & kCorImageFlagsIlLibrary) != 0u) names.emplace_back("IL_LIBRARY");
    if ((flags & kCorImageFlagsStrongNameSigned) != 0u) names.emplace_back("STRONGNAMESIGNED");
    if ((flags & kCorImageFlagsNativeEntryPoint) != 0u) names.emplace_back("NATIVE_ENTRYPOINT");
    if ((flags & kCorImageFlagsTrackDebugData) != 0u) names.emplace_back("TRACKDEBUGDATA");
    if ((flags & kCorImageFlags32BitPreferred) != 0u) names.emplace_back("32BITPREFERRED");
    if (names.empty()) {
        return std::format("0x{:08X}", flags);
    }
    std::string out{};
    for (std::size_t i = 0u; i < names.size(); ++i) {
        if (i > 0u) out += " | ";
        out += names[i];
    }
    return out;
}

std::string ClrAssemblyInfo::version_string() const {
    return std::format("{}.{}.{}.{}",
                       major_version,
                       minor_version,
                       build_number,
                       revision_number);
}

std::string ClrAssemblyRef::version_string() const {
    return std::format("{}.{}.{}.{}",
                       major_version,
                       minor_version,
                       build_number,
                       revision_number);
}

std::string ClrTypeRef::full_name() const {
    return join_namespace_name(type_namespace, type_name);
}

std::string ClrTypeDef::full_name() const {
    return join_namespace_name(type_namespace, type_name);
}

std::optional<std::string> ClrMetadata::resolve_token(std::uint32_t token) const {
    const std::uint8_t tbl = static_cast<std::uint8_t>((token >> 24u) & 0xFFu);
    const std::uint32_t rid = token & 0x00FFFFFFu;

    if (tbl == 0x70u) {
        for (const ClrUserString& us_entry : user_strings) {
            if (us_entry.token == token) {
                return escape_cil_string(us_entry.value);
            }
        }
        return std::nullopt;
    }
    if (rid == 0u) {
        return std::nullopt;
    }
    const std::size_t idx = static_cast<std::size_t>(rid - 1u);
    switch (tbl) {
        case 0x00u:
            if (idx == 0u && module.has_value()) {
                return module->name;
            }
            break;
        case 0x01u:
            if (idx < type_refs.size()) {
                return type_refs[idx].full_name();
            }
            break;
        case 0x02u:
            if (idx < type_defs.size()) {
                return type_defs[idx].full_name();
            }
            break;
        case 0x04u:
            if (idx < fields.size()) {
                const ClrFieldDef& f = fields[idx];
                if (!f.owning_type_name.empty()) {
                    return std::format("{}::{}", f.owning_type_name, f.name);
                }
                return f.name;
            }
            break;
        case 0x06u:
            if (idx < methods.size()) {
                const ClrMethodDef& m = methods[idx];
                const std::string qual = !m.owning_type_name.empty()
                                             ? std::format("{}::{}", m.owning_type_name, m.name)
                                             : m.name;
                return !m.signature_summary.empty()
                           ? std::format("{} {}", qual, m.signature_summary)
                           : qual;
            }
            break;
        case 0x0Au:
            if (idx < member_refs.size()) {
                const ClrMemberRef& mr = member_refs[idx];
                const std::string qual = !mr.declaring_parent.empty()
                                             ? std::format("{}::{}", mr.declaring_parent, mr.name)
                                             : mr.name;
                return !mr.signature_summary.empty()
                           ? std::format("{} {}", qual, mr.signature_summary)
                           : qual;
            }
            break;
        case 0x1Au:
            if (idx < module_refs.size()) {
                return module_refs[idx];
            }
            break;
        case 0x1Bu:
            if (idx < type_specs.size() && !type_specs[idx].empty()) {
                return type_specs[idx];
            }
            break;
        case 0x20u:
            if (idx == 0u && assembly.has_value()) {
                return assembly->name;
            }
            break;
        case 0x23u:
            if (idx < assembly_refs.size()) {
                return assembly_refs[idx].name;
            }
            break;
        default:
            break;
    }
    return std::nullopt;
}

Result<ClrMetadata> parse_clr_metadata(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes) {
    if (image.format() != Format::PE) {
        return make_error("Binary image is not a PE executable/library");
    }
    const PeClrHeader* clr = image.pe_clr_header();
    if (clr == nullptr) {
        return make_error("PE image does not contain an IMAGE_COR20_HEADER CLR directory");
    }
    if (clr->metadata_rva == 0u || clr->metadata_size < 16u) {
        return make_error("CLR header specifies an empty or invalid metadata directory");
    }

    const std::uint64_t image_base = image.image_base();
    if (clr->metadata_rva > std::numeric_limits<std::uint64_t>::max() - image_base) {
        return make_error("CLR metadata RVA overflows image base");
    }
    const auto meta_off_opt = image.va_to_file_offset(image_base + clr->metadata_rva);
    if (!meta_off_opt.has_value() || *meta_off_opt >= file_bytes.size()) {
        return make_error("CLR metadata RVA does not map to in-bounds file bytes");
    }

    const auto meta_off = static_cast<std::size_t>(*meta_off_opt);
    const std::size_t avail_meta = file_bytes.size() - meta_off;
    if (avail_meta < 16u) {
        return make_error("Truncated CLR metadata root (< 16 bytes)");
    }

    ClrMetadata out{};
    bool degraded = false;

    out.cor20_major_runtime_version = clr->major_runtime_version;
    out.cor20_minor_runtime_version = clr->minor_runtime_version;
    out.cor20_flags = clr->flags;
    out.cor20_flags_summary = format_cor20_flags(clr->flags);
    out.entry_point_token_or_rva = clr->entry_point_token_or_rva;
    out.il_only = (clr->flags & kCorImageFlagsIlOnly) != 0u;
    out.requires_32bit = (clr->flags & kCorImageFlags32BitRequired) != 0u;
    out.prefers_32bit = (clr->flags & kCorImageFlags32BitPreferred) != 0u;
    out.strong_name_signed = (clr->flags & kCorImageFlagsStrongNameSigned) != 0u;
    out.native_entry_point = (clr->flags & kCorImageFlagsNativeEntryPoint) != 0u;
    out.track_debug_data = (clr->flags & kCorImageFlagsTrackDebugData) != 0u;

    out.metadata_rva = clr->metadata_rva;
    out.metadata_file_offset = *meta_off_opt;
    out.metadata_size = clr->metadata_size;

    std::size_t effective_meta_size = clr->metadata_size;
    if (effective_meta_size > avail_meta) {
        degraded = true;
        push_diagnostic(out.diagnostics,
                        std::format("CLR metadata size (0x{:X}) exceeds file bounds (clamped to 0x{:X})",
                                    clr->metadata_size,
                                    avail_meta));
        effective_meta_size = avail_meta;
    }

    const std::span<const std::uint8_t> meta_bytes = file_bytes.subspan(meta_off, effective_meta_size);
    const EndianReader root_reader(
        meta_bytes,
        TargetLayout{.address_width = AddressWidth::Bits32, .endianness = Endianness::Little});

    const auto sig = root_reader.read_u32(0u);
    if (!sig.has_value() || *sig != kBsjbMagic) {
        return make_error(std::format(
            "Invalid CLR metadata root signature 0x{:08X} (expected BSJB 0x424A5342)",
            sig.value_or(0u)));
    }

    out.md_major_version = root_reader.read_u16(4u).value_or(0u);
    out.md_minor_version = root_reader.read_u16(6u).value_or(0u);
    const std::uint32_t raw_ver_len = root_reader.read_u32(12u).value_or(0u);
    if (raw_ver_len > kMaxVersionBytes) {
        return make_error(std::format("CLR metadata version string length ({}) exceeds safety cap",
                                      raw_ver_len));
    }
    const std::size_t aligned_ver_len = (static_cast<std::size_t>(raw_ver_len) + 3u) & ~std::size_t{3u};
    if (16u + aligned_ver_len + 4u > meta_bytes.size()) {
        return make_error("Truncated CLR BSJB metadata root before stream headers");
    }

    {
        std::size_t str_len = 0u;
        while (str_len < aligned_ver_len && meta_bytes[16u + str_len] != 0u) {
            ++str_len;
        }
        out.runtime_version.assign(
            reinterpret_cast<const char*>(meta_bytes.data() + 16u), str_len);
    }

    std::size_t hdr_cursor = 16u + aligned_ver_len;
    out.md_flags = root_reader.read_u16(hdr_cursor).value_or(0u);
    const std::uint16_t stream_count = root_reader.read_u16(hdr_cursor + 2u).value_or(0u);
    hdr_cursor += 4u;

    if (stream_count > kMaxStreams) {
        return make_error(std::format("CLR metadata stream count ({}) exceeds safety cap ({})",
                                      stream_count,
                                      kMaxStreams));
    }

    std::span<const std::uint8_t> tables_stream{};
    bool saw_tables_stream = false;
    HeapView heaps{
        .diagnostics = &out.diagnostics,
        .degraded = &degraded,
    };

    out.streams.reserve(stream_count);
    for (std::uint16_t si = 0u; si < stream_count; ++si) {
        if (!root_reader.can_read(hdr_cursor, 8u)) {
            degraded = true;
            push_diagnostic(out.diagnostics,
                            std::format("Truncated CLR stream header {} at 0x{:X}", si, hdr_cursor));
            break;
        }
        const std::uint32_t s_off = root_reader.read_u32(hdr_cursor).value_or(0u);
        const std::uint32_t s_size = root_reader.read_u32(hdr_cursor + 4u).value_or(0u);
        hdr_cursor += 8u;

        // Read NUL-terminated ASCII stream name (max 32 chars in ECMA-335), 4-byte aligned.
        std::size_t name_len = 0u;
        bool found_nul = false;
        const std::size_t max_name_scan = std::min<std::size_t>(meta_bytes.size() - hdr_cursor, 32u);
        while (name_len < max_name_scan) {
            if (meta_bytes[hdr_cursor + name_len] == 0u) {
                found_nul = true;
                break;
            }
            ++name_len;
        }
        if (!found_nul) {
            degraded = true;
            push_diagnostic(out.diagnostics,
                            std::format("Unterminated CLR stream name in header {}", si));
            break;
        }
        std::string s_name(reinterpret_cast<const char*>(meta_bytes.data() + hdr_cursor), name_len);
        const std::size_t padded_name_bytes = (name_len + 4u) & ~std::size_t{3u};
        if (padded_name_bytes > meta_bytes.size() - hdr_cursor) {
            degraded = true;
            push_diagnostic(out.diagnostics,
                            std::format("Truncated CLR stream header padding for '{}'", s_name));
            break;
        }
        hdr_cursor += padded_name_bytes;

        out.streams.push_back(ClrStreamHeaderInfo{
            .name = s_name,
            .offset = s_off,
            .size = s_size,
        });

        if (s_off > meta_bytes.size() || s_size > meta_bytes.size() - s_off) {
            degraded = true;
            push_diagnostic(out.diagnostics,
                            std::format("Out-of-bounds CLR stream '{}' (offset=0x{:X}, size=0x{:X})",
                                        s_name,
                                        s_off,
                                        s_size));
            continue;
        }

        const auto slice = meta_bytes.subspan(s_off, s_size);
        if ((s_name == "#~" || s_name == "#-") && !saw_tables_stream) {
            tables_stream = slice;
            saw_tables_stream = true;
            out.compressed_tables = (s_name == "#~");
        } else if (s_name == "#Strings") {
            heaps.strings = slice;
        } else if (s_name == "#US") {
            heaps.us = slice;
        } else if (s_name == "#GUID") {
            heaps.guid = slice;
        } else if (s_name == "#Blob") {
            heaps.blob = slice;
        }
    }

    // Bounded walk of `#US` user string heap (`0x70xxxxxx` tokens).
    if (heaps.us.size() > 1u) {
        std::size_t us_pos = 1u;
        while (us_pos < heaps.us.size() && out.user_strings.size() < kMaxUserStrings) {
            if (us_pos > 0x00FFFFFFu) {
                break;
            }
            const auto dec = decode_compressed_uint(heaps.us, us_pos);
            if (!dec.has_value()) {
                degraded = true;
                push_diagnostic(out.diagnostics,
                                std::format("Malformed #US compressed length at 0x{:X}", us_pos));
                break;
            }
            const auto [byte_len, hdr_bytes] = *dec;
            if (byte_len == 0u) {
                us_pos += hdr_bytes;
                continue;
            }
            const std::size_t payload_off = us_pos + hdr_bytes;
            if (payload_off > heaps.us.size() || byte_len > heaps.us.size() - payload_off) {
                degraded = true;
                push_diagnostic(out.diagnostics,
                                std::format("Truncated #US entry at 0x{:X} (len={})", us_pos, byte_len));
                break;
            }
            const std::size_t utf16_bytes =
                (byte_len & 1u) != 0u ? static_cast<std::size_t>(byte_len - 1u)
                                      : static_cast<std::size_t>(byte_len);
            std::string decoded = decode_utf16_to_utf8(
                heaps.us.subspan(payload_off, utf16_bytes), Endianness::Little, /*stop_at_nul=*/false);
            out.user_strings.push_back(ClrUserString{
                .token = 0x70000000u | static_cast<std::uint32_t>(us_pos),
                .value = std::move(decoded),
            });
            us_pos = payload_off + byte_len;
        }
    }

    if (saw_tables_stream) {
        if (tables_stream.size() < 24u) {
            degraded = true;
            push_diagnostic(out.diagnostics, "Truncated CLR #~/#- metadata tables header (< 24 bytes)");
        } else {
            const EndianReader tbl_reader(
                tables_stream,
                TargetLayout{.address_width = AddressWidth::Bits32, .endianness = Endianness::Little});
            out.heap_sizes = tbl_reader.read_u8(6u).value_or(0u);
            out.valid_tables_mask = tbl_reader.read_u64(8u).value_or(0u);
            out.sorted_tables_mask = tbl_reader.read_u64(16u).value_or(0u);

            const auto pop = static_cast<std::size_t>(std::popcount(out.valid_tables_mask));
            std::size_t rows_header_end = 24u + pop * 4u;
            const bool has_extra_data = (out.heap_sizes & 0x40u) != 0u;
            if (has_extra_data) {
                rows_header_end += 4u;
            }
            if (rows_header_end > tables_stream.size()) {
                degraded = true;
                push_diagnostic(out.diagnostics,
                                "Truncated CLR metadata table row-count array in #~/#- stream");
            } else {
                TableLayoutContext layout_ctx{};
                layout_ctx.string_index_size = (out.heap_sizes & 0x01u) != 0u ? 4u : 2u;
                layout_ctx.guid_index_size   = (out.heap_sizes & 0x02u) != 0u ? 4u : 2u;
                layout_ctx.blob_index_size   = (out.heap_sizes & 0x04u) != 0u ? 4u : 2u;

                std::size_t cnt_off = 24u;
                for (std::uint8_t t = 0u; t < 64u; ++t) {
                    if ((out.valid_tables_mask & (std::uint64_t{1u} << t)) != 0u) {
                        const std::uint32_t rc = tbl_reader.read_u32(cnt_off).value_or(0u);
                        cnt_off += 4u;
                        out.table_row_counts[t] = rc;
                        layout_ctx.rows[t] = rc;
                    }
                }

                struct TableSlice {
                    bool present{false};
                    std::span<const std::uint8_t> bytes{};
                    std::uint32_t stride{0u};
                    std::uint32_t available_rows{0u};
                };
                std::array<TableSlice, 64> slices{};

                std::size_t table_data_off = rows_header_end;
                for (std::uint8_t t = 0u; t < 64u; ++t) {
                    const std::uint32_t rc = layout_ctx.rows[t];
                    if (rc == 0u) {
                        continue;
                    }
                    const auto stride_opt = compute_table_row_stride(t, layout_ctx);
                    if (!stride_opt.has_value() || *stride_opt == 0u) {
                        degraded = true;
                        push_diagnostic(
                            out.diagnostics,
                            std::format("Unsupported CLR metadata table 0x{:02X} ({} row(s)); "
                                        "halting further table layout to avoid misalignment",
                                        t,
                                        rc));
                        break;
                    }
                    const std::uint32_t stride = *stride_opt;
                    const std::size_t rem_bytes = tables_stream.size() - table_data_off;
                    const std::uint64_t needed =
                        static_cast<std::uint64_t>(rc) * static_cast<std::uint64_t>(stride);
                    if (needed > rem_bytes) {
                        const auto fit_rows = static_cast<std::uint32_t>(
                            std::min<std::size_t>(rem_bytes / stride, kMaxDecodedRowsPerTable));
                        degraded = true;
                        push_diagnostic(
                            out.diagnostics,
                            std::format("Truncated CLR metadata table 0x{:02X}: expected {} row(s) "
                                        "({} bytes), only {} complete row(s) fit in #~/#-",
                                        t,
                                        rc,
                                        needed,
                                        fit_rows));
                        slices[t] = TableSlice{
                            .present = fit_rows > 0u,
                            .bytes = tables_stream.subspan(table_data_off,
                                                           static_cast<std::size_t>(fit_rows) * stride),
                            .stride = stride,
                            .available_rows = fit_rows,
                        };
                        break;
                    }

                    const std::uint32_t capped_rows = std::min<std::uint32_t>(rc, kMaxDecodedRowsPerTable);
                    if (capped_rows < rc) {
                        degraded = true;
                        push_diagnostic(
                            out.diagnostics,
                            std::format("Capped CLR metadata table 0x{:02X} at {} rows (total {})",
                                        t,
                                        capped_rows,
                                        rc));
                    }
                    const auto total_table_bytes = static_cast<std::size_t>(needed);
                    slices[t] = TableSlice{
                        .present = true,
                        .bytes = tables_stream.subspan(table_data_off,
                                                       static_cast<std::size_t>(capped_rows) * stride),
                        .stride = stride,
                        .available_rows = capped_rows,
                    };
                    table_data_off += total_table_bytes;
                }

                auto row_cursor = [](const TableSlice& sl, std::uint32_t row_idx) -> RowCursor {
                    const auto row_span =
                        sl.bytes.subspan(static_cast<std::size_t>(row_idx) * sl.stride, sl.stride);
                    return RowCursor{
                        .reader = EndianReader(
                            row_span,
                            TargetLayout{.address_width = AddressWidth::Bits32,
                                         .endianness = Endianness::Little}),
                        .pos = 0u,
                    };
                };

                // 1. Module (`0x00`), Assembly (`0x20`), AssemblyRef (`0x23`), ModuleRef (`0x1A`)
                if (slices[0x00u].present && slices[0x00u].available_rows >= 1u) {
                    RowCursor rc = row_cursor(slices[0x00u], 0u);
                    const std::uint16_t gen = rc.u16();
                    const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                    const std::uint32_t mvid_idx = rc.idx(layout_ctx.guid_index_size);
                    out.module = ClrModuleInfo{
                        .token = 0x00000001u,
                        .generation = gen,
                        .name = heaps.read_string(name_idx),
                        .mvid_guid = heaps.read_guid(mvid_idx),
                    };
                }

                if (slices[0x20u].present && slices[0x20u].available_rows >= 1u) {
                    RowCursor rc = row_cursor(slices[0x20u], 0u);
                    ClrAssemblyInfo asm_info{};
                    asm_info.token = 0x20000001u;
                    asm_info.hash_alg_id = rc.u32();
                    asm_info.major_version = rc.u16();
                    asm_info.minor_version = rc.u16();
                    asm_info.build_number = rc.u16();
                    asm_info.revision_number = rc.u16();
                    asm_info.flags = rc.u32();
                    const std::uint32_t pk_idx = rc.idx(layout_ctx.blob_index_size);
                    const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                    const std::uint32_t cult_idx = rc.idx(layout_ctx.string_index_size);
                    if (const auto pk_blob = heaps.read_blob(pk_idx); pk_blob.has_value()) {
                        asm_info.public_key_hex = hex_encode_upper(*pk_blob);
                    }
                    asm_info.name = heaps.read_string(name_idx);
                    asm_info.culture = heaps.read_string(cult_idx);
                    out.assembly = std::move(asm_info);
                }

                if (slices[0x23u].present) {
                    out.assembly_refs.reserve(slices[0x23u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x23u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x23u], r);
                        ClrAssemblyRef aref{};
                        aref.token = 0x23000000u | (r + 1u);
                        aref.major_version = rc.u16();
                        aref.minor_version = rc.u16();
                        aref.build_number = rc.u16();
                        aref.revision_number = rc.u16();
                        aref.flags = rc.u32();
                        const std::uint32_t pkt_idx = rc.idx(layout_ctx.blob_index_size);
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t cult_idx = rc.idx(layout_ctx.string_index_size);
                        if (const auto pkt_blob = heaps.read_blob(pkt_idx); pkt_blob.has_value()) {
                            aref.public_key_or_token_hex = hex_encode_upper(*pkt_blob);
                        }
                        aref.name = heaps.read_string(name_idx);
                        aref.culture = heaps.read_string(cult_idx);
                        out.assembly_refs.push_back(std::move(aref));
                    }
                }

                if (slices[0x1Au].present) {
                    out.module_refs.reserve(slices[0x1Au].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x1Au].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x1Au], r);
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        out.module_refs.push_back(heaps.read_string(name_idx));
                    }
                }

                // 2. TypeRef (`0x01`) — two passes so nested TypeRef scopes resolve cleanly.
                if (slices[0x01u].present) {
                    const std::uint32_t rs_w = layout_ctx.coded_index_size(CodedIndexKind::ResolutionScope);
                    out.type_refs.reserve(slices[0x01u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x01u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x01u], r);
                        const std::uint32_t raw_rs = rc.idx(rs_w);
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t ns_idx = rc.idx(layout_ctx.string_index_size);
                        out.type_refs.push_back(ClrTypeRef{
                            .token = 0x01000000u | (r + 1u),
                            .resolution_scope_token =
                                TableLayoutContext::decode_coded_token(CodedIndexKind::ResolutionScope, raw_rs),
                            .type_namespace = heaps.read_string(ns_idx),
                            .type_name = heaps.read_string(name_idx),
                        });
                    }
                    for (ClrTypeRef& tr : out.type_refs) {
                        if (tr.resolution_scope_token != 0u) {
                            tr.resolution_scope_summary =
                                out.resolve_token(tr.resolution_scope_token)
                                    .value_or(std::format("0x{:08X}", tr.resolution_scope_token));
                        }
                    }
                }

                // 3. TypeDef (`0x02`) raw ranges + names first so signatures can resolve TypeDef tokens!
                struct RawTypeRanges {
                    std::uint32_t field_list_one_based{1u};
                    std::uint32_t method_list_one_based{1u};
                };
                std::vector<RawTypeRanges> raw_type_ranges{};
                if (slices[0x02u].present) {
                    const std::uint32_t ext_w = layout_ctx.coded_index_size(CodedIndexKind::TypeDefOrRef);
                    const std::uint32_t fld_w = layout_ctx.simple_index_size(0x04u);
                    const std::uint32_t mth_w = layout_ctx.simple_index_size(0x06u);

                    out.type_defs.reserve(slices[0x02u].available_rows);
                    raw_type_ranges.reserve(slices[0x02u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x02u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x02u], r);
                        const std::uint32_t tflags = rc.u32();
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t ns_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t raw_ext = rc.idx(ext_w);
                        const std::uint32_t field_list = rc.idx(fld_w);
                        const std::uint32_t method_list = rc.idx(mth_w);

                        ClrTypeDef td{};
                        td.token = 0x02000000u | (r + 1u);
                        td.flags = tflags;
                        td.visibility_summary = describe_typedef_visibility(tflags);
                        td.type_name = heaps.read_string(name_idx);
                        td.type_namespace = heaps.read_string(ns_idx);
                        td.extends_token =
                            TableLayoutContext::decode_coded_token(CodedIndexKind::TypeDefOrRef, raw_ext);
                        out.type_defs.push_back(std::move(td));
                        raw_type_ranges.push_back(RawTypeRanges{
                            .field_list_one_based = field_list == 0u ? 1u : field_list,
                            .method_list_one_based = method_list == 0u ? 1u : method_list,
                        });
                    }
                }

                // Decode TypeSpec (`0x1B`) blobs now that TypeRef & TypeDef names exist,
                // before resolving TypeDef.Extends and MemberRef.Class!
                if (slices[0x1Bu].present) {
                    out.type_specs.reserve(slices[0x1Bu].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x1Bu].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x1Bu], r);
                        const std::uint32_t sig_idx = rc.idx(layout_ctx.blob_index_size);
                        if (const auto sig_blob = heaps.read_blob(sig_idx);
                            sig_blob.has_value() && !sig_blob->empty()) {
                            SignatureReader sr{.bytes = *sig_blob, .pos = 0u, .md = out};
                            out.type_specs.push_back(sr.decode_type(0u));
                        } else {
                            out.type_specs.emplace_back("...");
                        }
                    }
                }

                // Resolve TypeDef.Extends and TypeDef kind now that all TypeDef, TypeRef & TypeSpec names exist.
                const std::uint32_t total_fields = slices[0x04u].available_rows;
                const std::uint32_t total_methods = slices[0x06u].available_rows;
                for (std::size_t ti = 0u; ti < out.type_defs.size(); ++ti) {
                    ClrTypeDef& td = out.type_defs[ti];
                    if (td.extends_token != 0u) {
                        td.extends_name = out.resolve_token(td.extends_token)
                                              .value_or(std::format("0x{:08X}", td.extends_token));
                    }
                    td.kind_summary = describe_typedef_kind(td.flags, td.extends_name);

                    const std::uint32_t f_start_1 = raw_type_ranges[ti].field_list_one_based;
                    const std::uint32_t f_end_1 =
                        (ti + 1u < raw_type_ranges.size())
                            ? raw_type_ranges[ti + 1u].field_list_one_based
                            : (total_fields + 1u);
                    const std::uint32_t clamped_f_start =
                        std::min<std::uint32_t>(f_start_1 > 0u ? f_start_1 - 1u : 0u, total_fields);
                    const std::uint32_t clamped_f_end =
                        std::clamp<std::uint32_t>(f_end_1 > 0u ? f_end_1 - 1u : 0u,
                                                  clamped_f_start,
                                                  total_fields);
                    td.field_start_index = clamped_f_start;
                    td.field_count = clamped_f_end - clamped_f_start;

                    const std::uint32_t m_start_1 = raw_type_ranges[ti].method_list_one_based;
                    const std::uint32_t m_end_1 =
                        (ti + 1u < raw_type_ranges.size())
                            ? raw_type_ranges[ti + 1u].method_list_one_based
                            : (total_methods + 1u);
                    const std::uint32_t clamped_m_start =
                        std::min<std::uint32_t>(m_start_1 > 0u ? m_start_1 - 1u : 0u, total_methods);
                    const std::uint32_t clamped_m_end =
                        std::clamp<std::uint32_t>(m_end_1 > 0u ? m_end_1 - 1u : 0u,
                                                  clamped_m_start,
                                                  total_methods);
                    td.method_start_index = clamped_m_start;
                    td.method_count = clamped_m_end - clamped_m_start;
                }

                // 4. Param (`0x08`) before MethodDef so parameter names attach directly!
                if (slices[0x08u].present) {
                    out.params.reserve(slices[0x08u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x08u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x08u], r);
                        const std::uint16_t pflags = rc.u16();
                        const std::uint16_t seq = rc.u16();
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        out.params.push_back(ClrParamDef{
                            .token = 0x08000000u | (r + 1u),
                            .flags = pflags,
                            .sequence = seq,
                            .name = heaps.read_string(name_idx),
                        });
                    }
                }

                // 5. Field (`0x04`) + owning TypeDef mapping
                if (slices[0x04u].present) {
                    std::vector<std::uint32_t> field_owner_idx(slices[0x04u].available_rows,
                                                               std::numeric_limits<std::uint32_t>::max());
                    for (std::uint32_t ti = 0u; ti < out.type_defs.size(); ++ti) {
                        const ClrTypeDef& td = out.type_defs[ti];
                        for (std::uint32_t fi = 0u; fi < td.field_count; ++fi) {
                            const std::uint32_t idx = td.field_start_index + fi;
                            if (idx < field_owner_idx.size()) {
                                field_owner_idx[idx] = ti;
                            }
                        }
                    }

                    out.fields.reserve(slices[0x04u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x04u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x04u], r);
                        const std::uint16_t fflags = rc.u16();
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t sig_idx = rc.idx(layout_ctx.blob_index_size);

                        ClrFieldDef fld{};
                        fld.token = 0x04000000u | (r + 1u);
                        if (field_owner_idx[r] < out.type_defs.size()) {
                            const ClrTypeDef& owner = out.type_defs[field_owner_idx[r]];
                            fld.owning_type_token = owner.token;
                            fld.owning_type_name = owner.full_name();
                        }
                        fld.flags = fflags;
                        fld.flags_summary = describe_field_flags(fflags);
                        fld.name = heaps.read_string(name_idx);
                        if (const auto sig_blob = heaps.read_blob(sig_idx);
                            sig_blob.has_value() && !sig_blob->empty()) {
                            const DecodedMethodSig dsig = decode_method_or_member_sig(*sig_blob, out);
                            fld.type_signature = dsig.return_type;
                        } else {
                            fld.type_signature = "...";
                        }
                        out.fields.push_back(std::move(fld));
                    }
                }

                // 6. MethodDef (`0x06`) + owning TypeDef + Param names + MethodDefSig decoding
                if (slices[0x06u].present) {
                    const std::uint32_t prm_w = layout_ctx.simple_index_size(0x08u);
                    const std::uint32_t total_params = static_cast<std::uint32_t>(out.params.size());

                    std::vector<std::uint32_t> method_owner_idx(slices[0x06u].available_rows,
                                                                std::numeric_limits<std::uint32_t>::max());
                    for (std::uint32_t ti = 0u; ti < out.type_defs.size(); ++ti) {
                        const ClrTypeDef& td = out.type_defs[ti];
                        for (std::uint32_t mi = 0u; mi < td.method_count; ++mi) {
                            const std::uint32_t idx = td.method_start_index + mi;
                            if (idx < method_owner_idx.size()) {
                                method_owner_idx[idx] = ti;
                            }
                        }
                    }

                    struct RawMethodRow {
                        std::uint32_t rva{0u};
                        std::uint16_t impl_flags{0u};
                        std::uint16_t flags{0u};
                        std::uint32_t name_idx{0u};
                        std::uint32_t sig_idx{0u};
                        std::uint32_t param_list_1{1u};
                    };
                    std::vector<RawMethodRow> raw_methods{};
                    raw_methods.reserve(slices[0x06u].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x06u].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x06u], r);
                        RawMethodRow rm{};
                        rm.rva = rc.u32();
                        rm.impl_flags = rc.u16();
                        rm.flags = rc.u16();
                        rm.name_idx = rc.idx(layout_ctx.string_index_size);
                        rm.sig_idx = rc.idx(layout_ctx.blob_index_size);
                        const std::uint32_t pl = rc.idx(prm_w);
                        rm.param_list_1 = pl == 0u ? 1u : pl;
                        raw_methods.push_back(rm);
                    }

                    out.methods.reserve(raw_methods.size());
                    for (std::size_t r = 0u; r < raw_methods.size(); ++r) {
                        const RawMethodRow& rm = raw_methods[r];
                        ClrMethodDef mdef{};
                        mdef.token = 0x06000000u | static_cast<std::uint32_t>(r + 1u);
                        if (method_owner_idx[r] < out.type_defs.size()) {
                            const ClrTypeDef& owner = out.type_defs[method_owner_idx[r]];
                            mdef.owning_type_token = owner.token;
                            mdef.owning_type_name = owner.full_name();
                        }
                        mdef.name = heaps.read_string(rm.name_idx);
                        mdef.rva = rm.rva;
                        if (rm.rva != 0u && rm.rva <= std::numeric_limits<std::uint64_t>::max() - image_base) {
                            mdef.file_offset = image.va_to_file_offset(image_base + rm.rva);
                        }
                        mdef.impl_flags = rm.impl_flags;
                        mdef.flags = rm.flags;
                        mdef.flags_summary = describe_method_flags(rm.flags, rm.impl_flags);

                        DecodedMethodSig dsig{};
                        if (const auto sig_blob = heaps.read_blob(rm.sig_idx);
                            sig_blob.has_value() && !sig_blob->empty()) {
                            dsig = decode_method_or_member_sig(*sig_blob, out);
                        }
                        mdef.return_type = dsig.return_type;
                        mdef.parameter_types = std::move(dsig.param_types);
                        mdef.parameter_names.assign(mdef.parameter_types.size(), std::string{});

                        const std::uint32_t p_start =
                            std::min<std::uint32_t>(rm.param_list_1 - 1u, total_params);
                        const std::uint32_t next_pl_1 =
                            (r + 1u < raw_methods.size()) ? raw_methods[r + 1u].param_list_1
                                                          : (total_params + 1u);
                        const std::uint32_t p_end =
                            std::clamp<std::uint32_t>(next_pl_1 - 1u, p_start, total_params);
                        for (std::uint32_t pi = p_start; pi < p_end; ++pi) {
                            const ClrParamDef& pd = out.params[pi];
                            if (pd.sequence >= 1u &&
                                static_cast<std::size_t>(pd.sequence - 1u) < mdef.parameter_names.size()) {
                                mdef.parameter_names[pd.sequence - 1u] = pd.name;
                            }
                        }

                        mdef.signature_summary = format_method_sig_summary(
                            mdef.return_type, mdef.parameter_types, mdef.parameter_names);
                        out.methods.push_back(std::move(mdef));
                    }
                }

                // 7. MemberRef (`0x0A`)
                if (slices[0x0Au].present) {
                    const std::uint32_t mrp_w =
                        layout_ctx.coded_index_size(CodedIndexKind::MemberRefParent);
                    out.member_refs.reserve(slices[0x0Au].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x0Au].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x0Au], r);
                        const std::uint32_t raw_parent = rc.idx(mrp_w);
                        const std::uint32_t name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t sig_idx = rc.idx(layout_ctx.blob_index_size);

                        ClrMemberRef mref{};
                        mref.token = 0x0A000000u | (r + 1u);
                        mref.parent_token = TableLayoutContext::decode_coded_token(
                            CodedIndexKind::MemberRefParent, raw_parent);
                        if (mref.parent_token != 0u) {
                            mref.declaring_parent =
                                out.resolve_token(mref.parent_token)
                                    .value_or(std::format("0x{:08X}", mref.parent_token));
                        }
                        mref.name = heaps.read_string(name_idx);
                        if (const auto sig_blob = heaps.read_blob(sig_idx);
                            sig_blob.has_value() && !sig_blob->empty()) {
                            const DecodedMethodSig dsig = decode_method_or_member_sig(*sig_blob, out);
                            mref.is_field_ref = dsig.is_field;
                            mref.signature_summary =
                                dsig.is_field
                                    ? dsig.return_type
                                    : format_method_sig_summary(dsig.return_type, dsig.param_types);
                        } else {
                            mref.signature_summary = "...";
                        }
                        out.member_refs.push_back(std::move(mref));
                    }
                }

                // 8. ImplMap (`0x1C`) P/Invoke unmanaged DLL imports!
                if (slices[0x1Cu].present) {
                    const std::uint32_t mf_w =
                        layout_ctx.coded_index_size(CodedIndexKind::MemberForwarded);
                    const std::uint32_t mod_w = layout_ctx.simple_index_size(0x1Au);
                    out.pinvoke_entries.reserve(slices[0x1Cu].available_rows);
                    for (std::uint32_t r = 0u; r < slices[0x1Cu].available_rows; ++r) {
                        RowCursor rc = row_cursor(slices[0x1Cu], r);
                        const std::uint16_t mflags = rc.u16();
                        const std::uint32_t raw_mf = rc.idx(mf_w);
                        const std::uint32_t import_name_idx = rc.idx(layout_ctx.string_index_size);
                        const std::uint32_t scope_rid = rc.idx(mod_w);

                        ClrPInvokeEntry pi{};
                        pi.impl_map_token = 0x1C000000u | (r + 1u);
                        pi.mapping_flags = mflags;
                        pi.method_token = TableLayoutContext::decode_coded_token(
                            CodedIndexKind::MemberForwarded, raw_mf);
                        std::string fallback_method_name{};
                        if ((pi.method_token >> 24u) == 0x06u) {
                            const std::uint32_t m_rid = pi.method_token & 0x00FFFFFFu;
                            if (m_rid >= 1u && m_rid <= out.methods.size()) {
                                const ClrMethodDef& md = out.methods[m_rid - 1u];
                                fallback_method_name = md.name;
                                pi.method_full_name = !md.owning_type_name.empty()
                                                          ? std::format("{}::{}", md.owning_type_name, md.name)
                                                          : md.name;
                            }
                        } else if (pi.method_token != 0u) {
                            pi.method_full_name =
                                out.resolve_token(pi.method_token)
                                    .value_or(std::format("0x{:08X}", pi.method_token));
                        }
                        if (scope_rid >= 1u && scope_rid <= out.module_refs.size()) {
                            pi.module_name = out.module_refs[scope_rid - 1u];
                        } else {
                            degraded = true;
                            push_diagnostic(out.diagnostics,
                                            std::format("ImplMap row {} references out-of-bounds ModuleRef {}",
                                                        r + 1u,
                                                        scope_rid));
                            pi.module_name = "<invalid-moduleref>";
                        }
                        pi.entry_point_name = heaps.read_string(import_name_idx);
                        if (pi.entry_point_name.empty()) {
                            pi.entry_point_name = fallback_method_name;
                        }
                        pi.calling_convention = describe_pinvoke_callconv(mflags);
                        pi.char_set = describe_pinvoke_charset(mflags);
                        pi.supports_last_error = (mflags & 0x0040u) != 0u;
                        out.pinvoke_entries.push_back(std::move(pi));
                    }
                }
            }
        }
    }

    if (degraded) {
        out.status = SubsystemStatus::partial(
            "clr_metadata",
            out.diagnostics.empty() ? "CLR metadata parsed with warnings" : out.diagnostics.front());
    } else {
        out.status = SubsystemStatus::available(
            "clr_metadata",
            std::format("Parsed ECMA-335 {} metadata ({} TypeDef(s), {} MethodDef(s), {} P/Invoke(s))",
                        out.runtime_version,
                        out.type_defs.size(),
                        out.methods.size(),
                        out.pinvoke_entries.size()));
    }

    return out;
}

Result<CilMethodBody> disassemble_cil_method(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    const ClrMetadata& metadata,
    const ClrMethodDef& method) {
    return disassemble_cil_method_at_rva(image, file_bytes, metadata, method.rva, method.token);
}

Result<CilMethodBody> disassemble_cil_method_at_rva(
    const IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    const ClrMetadata& metadata,
    std::uint32_t method_rva,
    std::uint32_t method_token) {
    if (method_rva == 0u) {
        return make_error("Method has RVA 0 (abstract, runtime, or P/Invoke method without CIL body)");
    }
    const std::uint64_t image_base = image.image_base();
    if (method_rva > std::numeric_limits<std::uint64_t>::max() - image_base) {
        return make_error("Method RVA overflows image base");
    }
    const auto off_opt = image.va_to_file_offset(image_base + method_rva);
    if (!off_opt.has_value() || *off_opt >= file_bytes.size()) {
        return make_error(std::format("Method RVA 0x{:X} does not map to file bytes", method_rva));
    }

    const auto method_off = static_cast<std::size_t>(*off_opt);
    const std::uint8_t first_byte = file_bytes[method_off];
    const std::uint8_t hdr_format = static_cast<std::uint8_t>(first_byte & 0x03u);

    CilMethodBody body{};
    body.method_token = method_token;
    body.rva = method_rva;
    body.file_offset = *off_opt;

    bool degraded = false;
    std::size_t code_start_off = 0u;

    if (hdr_format == 0x02u) {
        // CorILMethod_TinyFormat (1-byte header)
        body.is_fat_header = false;
        body.raw_flags = hdr_format;
        body.max_stack = 8u;
        body.code_size = static_cast<std::uint32_t>(first_byte >> 2u);
        body.local_var_sig_tok = 0u;
        body.init_locals = false;
        body.has_more_sections = false;
        code_start_off = method_off + 1u;
    } else if (hdr_format == 0x03u) {
        // CorILMethod_FatFormat (12-byte header; size in dwords in upper nibble of u16 flags)
        if (file_bytes.size() - method_off < 12u) {
            return make_error("Truncated Fat CIL method header (< 12 bytes)");
        }
        const EndianReader hr(
            file_bytes.subspan(method_off, 12u),
            TargetLayout{.address_width = AddressWidth::Bits32, .endianness = Endianness::Little});
        const std::uint16_t flags_and_size = hr.read_u16(0u).value_or(0u);
        const std::uint16_t hdr_dwords = static_cast<std::uint16_t>((flags_and_size >> 12u) & 0x0Fu);
        if (hdr_dwords < 3u) {
            return make_error(std::format("Invalid Fat CIL header size ({} dwords; expected >= 3)",
                                          hdr_dwords));
        }
        const std::size_t hdr_bytes = static_cast<std::size_t>(hdr_dwords) * 4u;
        if (hdr_bytes > file_bytes.size() - method_off) {
            return make_error("Fat CIL method header size exceeds file bounds");
        }
        body.is_fat_header = true;
        body.raw_flags = static_cast<std::uint16_t>(flags_and_size & 0x0FFFu);
        body.has_more_sections = (body.raw_flags & 0x0008u) != 0u;
        body.init_locals = (body.raw_flags & 0x0010u) != 0u;
        body.max_stack = hr.read_u16(2u).value_or(0u);
        body.code_size = hr.read_u32(4u).value_or(0u);
        body.local_var_sig_tok = hr.read_u32(8u).value_or(0u);
        if (body.code_size > kMaxCilCodeSize) {
            return make_error(std::format("CIL method code_size (0x{:X}) exceeds safety cap",
                                          body.code_size));
        }
        code_start_off = method_off + hdr_bytes;
    } else {
        return make_error(std::format("Invalid CIL method header format bits 0x{:02X}", first_byte));
    }

    body.code_file_offset = code_start_off;
    std::size_t effective_code_bytes = body.code_size;
    if (code_start_off > file_bytes.size() || effective_code_bytes > file_bytes.size() - code_start_off) {
        degraded = true;
        effective_code_bytes = code_start_off <= file_bytes.size() ? (file_bytes.size() - code_start_off) : 0u;
        push_diagnostic(body.diagnostics,
                        std::format("Truncated CIL code stream (declared {} bytes, {} available)",
                                    body.code_size,
                                    effective_code_bytes));
    }

    const std::span<const std::uint8_t> code = file_bytes.subspan(code_start_off, effective_code_bytes);
    const EndianReader cr(
        code,
        TargetLayout{.address_width = AddressWidth::Bits32, .endianness = Endianness::Little});

    std::size_t pc = 0u;
    while (pc < code.size() && body.instructions.size() < kMaxCilInstructions) {
        const std::size_t insn_start = pc;
        const std::uint8_t b0 = code[pc++];
        CilOpcodeSpec spec{};
        if (b0 == 0xFEu) {
            if (pc >= code.size()) {
                degraded = true;
                push_diagnostic(body.diagnostics,
                                std::format("Truncated 0xFE two-byte CIL opcode at IL_{:04X}", insn_start));
                body.instructions.push_back(CilInstruction{
                    .il_offset = static_cast<std::uint32_t>(insn_start),
                    .size = 1u,
                    .raw_bytes_hex = "FE",
                    .mnemonic = "db",
                    .operand_text = "0xFE /* truncated prefix */",
                });
                break;
            }
            const std::uint8_t b1 = code[pc++];
            spec = lookup_fe_opcode(b1);
        } else {
            spec = lookup_single_byte_opcode(b0);
        }

        if (spec.operand == CilOperandKind::Invalid) {
            degraded = true;
            const std::size_t bad_len = pc - insn_start;
            const std::string hex = format_il_bytes_hex(code.subspan(insn_start, bad_len));
            push_diagnostic(body.diagnostics,
                            std::format("Unknown CIL opcode ({}) at IL_{:04X}", hex, insn_start));
            body.instructions.push_back(CilInstruction{
                .il_offset = static_cast<std::uint32_t>(insn_start),
                .size = static_cast<std::uint32_t>(bad_len),
                .raw_bytes_hex = hex,
                .mnemonic = "<unknown>",
                .operand_text = hex,
            });
            continue;
        }

        CilInstruction insn{};
        insn.il_offset = static_cast<std::uint32_t>(insn_start);
        insn.mnemonic = std::string(spec.mnemonic);

        auto fail_truncated_operand = [&]() {
            degraded = true;
            const std::size_t rem = code.size() - insn_start;
            insn.size = static_cast<std::uint32_t>(rem);
            insn.raw_bytes_hex = format_il_bytes_hex(code.subspan(insn_start, rem));
            insn.operand_text = "<truncated operand>";
            push_diagnostic(body.diagnostics,
                            std::format("Truncated operand for '{}' at IL_{:04X}",
                                        insn.mnemonic,
                                        insn.il_offset));
            body.instructions.push_back(std::move(insn));
            pc = code.size();
        };

        auto format_branch_target = [&](std::int64_t target) -> std::string {
            if (target < 0 || static_cast<std::uint64_t>(target) > body.code_size) {
                degraded = true;
                push_diagnostic(body.diagnostics,
                                std::format("Out-of-range CIL branch target {} at IL_{:04X}",
                                            target,
                                            insn.il_offset));
                return std::format("<invalid IL target {}>", target);
            }
            const auto u_target = static_cast<std::uint32_t>(target);
            insn.branch_target_il_offset = u_target;
            return std::format("IL_{:04X}", u_target);
        };

        auto resolve_token_operand = [&](std::uint32_t tok, bool is_us_string) {
            insn.referenced_token = tok;
            if (is_us_string && (tok >> 24u) == 0x70u) {
                if (const auto resolved = metadata.resolve_token(tok); resolved.has_value()) {
                    insn.operand_text = *resolved;
                    return;
                }
            } else if (const auto resolved = metadata.resolve_token(tok); resolved.has_value()) {
                insn.operand_text = *resolved;
                return;
            }
            insn.operand_text = std::format("0x{:08X}", tok);
        };

        using K = CilOperandKind;
        switch (spec.operand) {
            case K::InlineNone:
                break;
            case K::ShortInlineVar:
            case K::ShortInlineI_Unsigned: {
                if (!cr.can_read(pc, 1u)) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint8_t v = code[pc++];
                insn.operand_text = std::to_string(v);
                break;
            }
            case K::ShortInlineI_Signed: {
                if (!cr.can_read(pc, 1u)) {
                    fail_truncated_operand();
                    continue;
                }
                const auto v = static_cast<std::int8_t>(code[pc++]);
                insn.operand_text = std::to_string(static_cast<int>(v));
                break;
            }
            case K::InlineVar: {
                if (!cr.can_read(pc, 2u)) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint16_t v = cr.read_u16(pc).value_or(0u);
                pc += 2u;
                insn.operand_text = std::to_string(v);
                break;
            }
            case K::InlineI: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const auto v = static_cast<std::int32_t>(cr.read_u32(pc).value_or(0u));
                pc += 4u;
                insn.operand_text = std::to_string(v);
                break;
            }
            case K::InlineI8: {
                if (!cr.can_read(pc, 8u)) {
                    fail_truncated_operand();
                    continue;
                }
                const auto v = static_cast<std::int64_t>(cr.read_u64(pc).value_or(0u));
                pc += 8u;
                insn.operand_text = std::format("0x{:X} ({})", static_cast<std::uint64_t>(v), v);
                break;
            }
            case K::ShortInlineR: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const float f = std::bit_cast<float>(cr.read_u32(pc).value_or(0u));
                pc += 4u;
                insn.operand_text = std::format("{}", f);
                break;
            }
            case K::InlineR: {
                if (!cr.can_read(pc, 8u)) {
                    fail_truncated_operand();
                    continue;
                }
                const double d = std::bit_cast<double>(cr.read_u64(pc).value_or(0u));
                pc += 8u;
                insn.operand_text = std::format("{}", d);
                break;
            }
            case K::ShortInlineBrTarget: {
                if (!cr.can_read(pc, 1u)) {
                    fail_truncated_operand();
                    continue;
                }
                const auto rel = static_cast<std::int8_t>(code[pc++]);
                const std::int64_t target = static_cast<std::int64_t>(pc) + static_cast<std::int64_t>(rel);
                insn.operand_text = format_branch_target(target);
                break;
            }
            case K::InlineBrTarget: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const auto rel = static_cast<std::int32_t>(cr.read_u32(pc).value_or(0u));
                pc += 4u;
                const std::int64_t target = static_cast<std::int64_t>(pc) + static_cast<std::int64_t>(rel);
                insn.operand_text = format_branch_target(target);
                break;
            }
            case K::InlineSwitch: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint32_t count = cr.read_u32(pc).value_or(0u);
                if (count > kMaxSwitchTargets) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint64_t table_bytes = 4ull + static_cast<std::uint64_t>(count) * 4ull;
                if (table_bytes > code.size() - pc) {
                    fail_truncated_operand();
                    continue;
                }
                const std::size_t next_ip = pc + static_cast<std::size_t>(table_bytes);
                pc += 4u;
                std::string targets_txt = "(";
                insn.switch_target_il_offsets.reserve(count);
                for (std::uint32_t si = 0u; si < count; ++si) {
                    const auto rel = static_cast<std::int32_t>(cr.read_u32(pc).value_or(0u));
                    pc += 4u;
                    if (si > 0u) targets_txt += ", ";
                    const std::int64_t target =
                        static_cast<std::int64_t>(next_ip) + static_cast<std::int64_t>(rel);
                    if (target >= 0 && static_cast<std::uint64_t>(target) <= body.code_size) {
                        const auto u_target = static_cast<std::uint32_t>(target);
                        insn.switch_target_il_offsets.push_back(u_target);
                        targets_txt += std::format("IL_{:04X}", u_target);
                    } else {
                        degraded = true;
                        push_diagnostic(body.diagnostics,
                                        std::format("Out-of-range switch target {} at IL_{:04X}",
                                                    target,
                                                    insn.il_offset));
                        targets_txt += std::format("<invalid {}>", target);
                    }
                }
                targets_txt.push_back(')');
                insn.operand_text = std::move(targets_txt);
                break;
            }
            case K::InlineString: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint32_t tok = cr.read_u32(pc).value_or(0u);
                pc += 4u;
                resolve_token_operand(tok, /*is_us_string=*/true);
                break;
            }
            case K::InlineMethod:
            case K::InlineField:
            case K::InlineType:
            case K::InlineSig:
            case K::InlineTok: {
                if (!cr.can_read(pc, 4u)) {
                    fail_truncated_operand();
                    continue;
                }
                const std::uint32_t tok = cr.read_u32(pc).value_or(0u);
                pc += 4u;
                resolve_token_operand(tok, /*is_us_string=*/false);
                break;
            }
            case K::Invalid:
                break;
        }

        const std::size_t insn_len = pc - insn_start;
        insn.size = static_cast<std::uint32_t>(insn_len);
        insn.raw_bytes_hex = format_il_bytes_hex(code.subspan(insn_start, insn_len));
        body.instructions.push_back(std::move(insn));
    }

    // Parse aligned extra method data sections (`CorILMethod_MoreSects` = `0x08`) for EH clauses!
    if (body.has_more_sections && !degraded) {
        const std::uint64_t after_code =
            static_cast<std::uint64_t>(code_start_off) + static_cast<std::uint64_t>(body.code_size);
        const std::uint64_t aligned_first = (after_code + 3ull) & ~std::uint64_t{3ull};
        if (aligned_first >= file_bytes.size() || file_bytes.size() - static_cast<std::size_t>(aligned_first) < 4u) {
            degraded = true;
            push_diagnostic(body.diagnostics, "Truncated Fat CIL extra data section chain after method body");
        } else {
            auto sec_off = static_cast<std::size_t>(aligned_first);
            for (std::size_t sec_idx = 0u; sec_idx < kMaxEhSections; ++sec_idx) {
                if (sec_off > file_bytes.size() || file_bytes.size() - sec_off < 4u) {
                    degraded = true;
                    push_diagnostic(body.diagnostics,
                                    std::format("Truncated CIL extra section header {} at file offset 0x{:X}",
                                                sec_idx,
                                                sec_off));
                    break;
                }
                const std::uint8_t kind = file_bytes[sec_off];
                const std::uint8_t sec_type = static_cast<std::uint8_t>(kind & 0x3Fu);
                const bool fat_sect = (kind & 0x40u) != 0u;
                const bool more_sects = (kind & 0x80u) != 0u;

                if (sec_type != 0x01u && sec_type != 0x02u) {
                    degraded = true;
                    push_diagnostic(body.diagnostics,
                                    std::format("Invalid CIL extra section kind 0x{:02X} at file offset 0x{:X}",
                                                kind,
                                                sec_off));
                    break;
                }

                std::uint32_t data_size = 0u;
                if (fat_sect) {
                    data_size = static_cast<std::uint32_t>(file_bytes[sec_off + 1u]) |
                                (static_cast<std::uint32_t>(file_bytes[sec_off + 2u]) << 8u) |
                                (static_cast<std::uint32_t>(file_bytes[sec_off + 3u]) << 16u);
                } else {
                    data_size = file_bytes[sec_off + 1u];
                }

                if (data_size < 4u || data_size > file_bytes.size() - sec_off) {
                    degraded = true;
                    push_diagnostic(body.diagnostics,
                                    std::format("Invalid or truncated CIL extra section size {} at 0x{:X}",
                                                data_size,
                                                sec_off));
                    break;
                }

                if (sec_type == 0x01u) { // CorILMethod_Sect_EHTable
                    const std::size_t clause_stride = fat_sect ? 24u : 12u;
                    const std::size_t payload_bytes = static_cast<std::size_t>(data_size) - 4u;
                    if (payload_bytes % clause_stride != 0u) {
                        degraded = true;
                        push_diagnostic(body.diagnostics,
                                        "CIL EH section size is not an exact multiple of clause stride");
                    }
                    const std::size_t clause_count =
                        std::min<std::size_t>(payload_bytes / clause_stride, kMaxEhClauses);
                    const EndianReader er(
                        file_bytes.subspan(sec_off + 4u, payload_bytes),
                        TargetLayout{.address_width = AddressWidth::Bits32,
                                     .endianness = Endianness::Little});
                    for (std::size_t ci = 0u; ci < clause_count; ++ci) {
                        const std::size_t coff = ci * clause_stride;
                        CilEhClause cl{};
                        if (fat_sect) {
                            cl.raw_flags = er.read_u32(coff).value_or(0u);
                            cl.try_offset = er.read_u32(coff + 4u).value_or(0u);
                            cl.try_length = er.read_u32(coff + 8u).value_or(0u);
                            cl.handler_offset = er.read_u32(coff + 12u).value_or(0u);
                            cl.handler_length = er.read_u32(coff + 16u).value_or(0u);
                            cl.class_token_or_filter_offset = er.read_u32(coff + 20u).value_or(0u);
                        } else {
                            cl.raw_flags = er.read_u16(coff).value_or(0u);
                            cl.try_offset = er.read_u16(coff + 2u).value_or(0u);
                            cl.try_length = er.read_u8(coff + 4u).value_or(0u);
                            cl.handler_offset = er.read_u16(coff + 5u).value_or(0u);
                            cl.handler_length = er.read_u8(coff + 7u).value_or(0u);
                            cl.class_token_or_filter_offset = er.read_u32(coff + 8u).value_or(0u);
                        }

                        switch (cl.raw_flags & 0x07u) {
                            case 0x00u:
                                cl.kind = CilEhClauseKind::Catch;
                                if (cl.class_token_or_filter_offset != 0u) {
                                    cl.catch_type_name =
                                        metadata.resolve_token(cl.class_token_or_filter_offset)
                                            .value_or(std::format("0x{:08X}", cl.class_token_or_filter_offset));
                                }
                                break;
                            case 0x01u: cl.kind = CilEhClauseKind::Filter; break;
                            case 0x02u: cl.kind = CilEhClauseKind::Finally; break;
                            case 0x04u: cl.kind = CilEhClauseKind::Fault; break;
                            default:    cl.kind = CilEhClauseKind::Unknown; break;
                        }

                        if (static_cast<std::uint64_t>(cl.try_offset) + cl.try_length > body.code_size ||
                            static_cast<std::uint64_t>(cl.handler_offset) + cl.handler_length > body.code_size) {
                            degraded = true;
                            push_diagnostic(body.diagnostics,
                                            std::format("Out-of-bounds EH clause {} range in method 0x{:08X}",
                                                        ci,
                                                        method_token));
                        }
                        body.eh_clauses.push_back(std::move(cl));
                    }
                }

                if (!more_sects) {
                    break;
                }
                const std::uint64_t next_unaligned =
                    static_cast<std::uint64_t>(sec_off) + static_cast<std::uint64_t>(data_size);
                const std::uint64_t next_aligned = (next_unaligned + 3ull) & ~std::uint64_t{3ull};
                if (next_aligned <= sec_off || next_aligned > file_bytes.size()) {
                    degraded = true;
                    push_diagnostic(body.diagnostics, "Invalid next extra section alignment in CIL method");
                    break;
                }
                sec_off = static_cast<std::size_t>(next_aligned);
            }
        }
    }

    if (degraded) {
        body.status = SubsystemStatus::partial(
            "cil_disassembler",
            body.diagnostics.empty() ? "CIL method decoded with warnings" : body.diagnostics.front());
    } else {
        body.status = SubsystemStatus::available(
            "cil_disassembler",
            std::format("Decoded {} CIL instruction(s), {} EH clause(s)",
                        body.instructions.size(),
                        body.eh_clauses.size()));
    }

    return body;
}

}  // namespace peelf
