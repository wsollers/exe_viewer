#include "analysis/structure_interpreter.hpp"

#include "model/binary_model.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <format>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace viewer {
namespace {

[[nodiscard]] std::string trim_ascii(std::string_view sv) {
    std::size_t b = 0;
    while (b < sv.size() && std::isspace(static_cast<unsigned char>(sv[b])) != 0) {
        ++b;
    }
    std::size_t e = sv.size();
    while (e > b && std::isspace(static_cast<unsigned char>(sv[e - 1])) != 0) {
        --e;
    }
    return std::string(sv.substr(b, e - b));
}

[[nodiscard]] bool strip_leading_keyword(std::string& s, std::string_view kw) {
    if (s.size() > kw.size() && s.starts_with(kw) &&
        std::isspace(static_cast<unsigned char>(s[kw.size()])) != 0) {
        s = trim_ascii(std::string_view(s).substr(kw.size() + 1));
        return true;
    }
    return false;
}

[[nodiscard]] bool strip_trailing_keyword(std::string& s, std::string_view kw) {
    if (s.size() > kw.size() && s.ends_with(kw) &&
        std::isspace(static_cast<unsigned char>(s[s.size() - kw.size() - 1])) != 0) {
        s = trim_ascii(std::string_view(s).substr(0, s.size() - kw.size()));
        return true;
    }
    return false;
}

[[nodiscard]] std::string canonical_type_key(std::string_view raw) {
    std::string s = trim_ascii(raw);
    bool changed = true;
    while (changed) {
        changed = false;
        changed |= strip_leading_keyword(s, "const");
        changed |= strip_leading_keyword(s, "volatile");
        changed |= strip_leading_keyword(s, "struct");
        changed |= strip_leading_keyword(s, "class");
        changed |= strip_leading_keyword(s, "union");
        changed |= strip_leading_keyword(s, "enum");
        changed |= strip_trailing_keyword(s, "const");
        changed |= strip_trailing_keyword(s, "volatile");
    }
    return s;
}

struct ParsedTypeExpr {
    enum class Kind : std::uint8_t {
        Base,
        Array,
        Pointer,
    };

    Kind kind = Kind::Base;
    std::string base_name{};
    std::string inner_type{};
    std::uint64_t array_count = 0;
};

[[nodiscard]] ParsedTypeExpr parse_type_expr(std::string_view raw_type) {
    std::string s = trim_ascii(raw_type);
    while (strip_leading_keyword(s, "const") || strip_leading_keyword(s, "volatile")) {
    }
    while (strip_trailing_keyword(s, "const") || strip_trailing_keyword(s, "volatile")) {
    }

    // Fixed-size array suffix `T[N]` (outermost dimension is first `[` if multi-dim, or last `[` —
    // in C `int a[2][4]` is an array of 2 of `int[4]`, so splitting at the first top-level `[` handles both!).
    int angle_depth = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '<') {
            ++angle_depth;
        } else if (s[i] == '>' && angle_depth > 0) {
            --angle_depth;
        } else if (s[i] == '[' && angle_depth == 0) {
            const std::size_t close = s.find(']', i + 1);
            if (close != std::string::npos) {
                const std::string count_str = trim_ascii(std::string_view(s).substr(i + 1, close - i - 1));
                std::uint64_t count = 0;
                bool ok = !count_str.empty();
                if (count_str.starts_with("0x") || count_str.starts_with("0X")) {
                    ok = count_str.size() > 2;
                    for (std::size_t k = 2; k < count_str.size() && ok; ++k) {
                        const char c = count_str[k];
                        std::uint64_t d = 0;
                        if (c >= '0' && c <= '9') d = static_cast<std::uint64_t>(c - '0');
                        else if (c >= 'a' && c <= 'f') d = static_cast<std::uint64_t>(10 + c - 'a');
                        else if (c >= 'A' && c <= 'F') d = static_cast<std::uint64_t>(10 + c - 'A');
                        else ok = false;
                        count = (count << 4u) | d;
                    }
                } else {
                    for (const char c : count_str) {
                        if (c < '0' || c > '9') {
                            ok = false;
                            break;
                        }
                        count = count * 10u + static_cast<std::uint64_t>(c - '0');
                    }
                }
                if (ok) {
                    const std::string elem =
                        trim_ascii(std::string_view(s).substr(0, i)) +
                        trim_ascii(std::string_view(s).substr(close + 1));
                    return ParsedTypeExpr{
                        .kind = ParsedTypeExpr::Kind::Array,
                        .base_name = {},
                        .inner_type = elem,
                        .array_count = count,
                    };
                }
            }
            break;
        }
    }

    // Pointer suffix `T*`
    if (!s.empty() && s.back() == '*') {
        std::string pointee = trim_ascii(std::string_view(s).substr(0, s.size() - 1));
        while (strip_trailing_keyword(pointee, "const") || strip_trailing_keyword(pointee, "volatile")) {
        }
        return ParsedTypeExpr{
            .kind = ParsedTypeExpr::Kind::Pointer,
            .base_name = {},
            .inner_type = pointee.empty() ? "void" : pointee,
            .array_count = 0,
        };
    }

    return ParsedTypeExpr{
        .kind = ParsedTypeExpr::Kind::Base,
        .base_name = canonical_type_key(s),
        .inner_type = {},
        .array_count = 0,
    };
}

enum class ScalarKind : std::uint8_t {
    None,
    Bool,
    Char,
    WChar16,
    WChar32,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    IntPtr,
    UIntPtr,
    Float32,
    Float64,
};

struct ScalarInfo {
    ScalarKind kind = ScalarKind::None;
    std::uint64_t byte_size = 0;
};

[[nodiscard]] std::string ascii_lower(std::string_view sv) {
    std::string out(sv.size(), '\0');
    for (std::size_t i = 0; i < sv.size(); ++i) {
        const auto uc = static_cast<unsigned char>(sv[i]);
        out[i] = static_cast<char>(std::tolower(uc));
    }
    return out;
}

[[nodiscard]] ScalarInfo classify_scalar(std::string_view base_name,
                                         const peelf::TargetLayout& layout,
                                         std::uint64_t declared_size_hint = 0) {
    const std::string low = ascii_lower(canonical_type_key(base_name));
    if (low == "bool" || low == "_bool") {
        return {ScalarKind::Bool, 1};
    }
    if (low == "char") {
        return {ScalarKind::Char, 1};
    }
    if (low == "signed char" || low == "int8_t" || low == "int8" || low == "i8" || low == "sbyte" || low == "__int8") {
        return {ScalarKind::Int8, 1};
    }
    if (low == "unsigned char" || low == "uint8_t" || low == "uint8" || low == "u8" || low == "uchar" ||
        low == "byte" || low == "boolean" || low == "undefined1") {
        return {ScalarKind::UInt8, 1};
    }
    if (low == "wchar_t" || low == "char16_t" || low == "wchar") {
        if (declared_size_hint == 4) {
            return {ScalarKind::WChar32, 4};
        }
        return {ScalarKind::WChar16, 2};
    }
    if (low == "char32_t") {
        return {ScalarKind::WChar32, 4};
    }
    if (low == "short" || low == "short int" || low == "signed short" || low == "int16_t" ||
        low == "int16" || low == "i16" || low == "__int16") {
        return {ScalarKind::Int16, 2};
    }
    if (low == "unsigned short" || low == "unsigned short int" || low == "uint16_t" || low == "uint16" ||
        low == "u16" || low == "ushort" || low == "word" || low == "undefined2" || low == "elf32_half" ||
        low == "elf64_half") {
        return {ScalarKind::UInt16, 2};
    }
    if (low == "int" || low == "signed" || low == "signed int" || low == "int32_t" || low == "int32" ||
        low == "i32" || low == "__int32" || low == "hresult" || low == "ntstatus" || low == "elf32_sword" ||
        low == "elf64_sword") {
        return {ScalarKind::Int32, 4};
    }
    if (low == "unsigned" || low == "unsigned int" || low == "uint32_t" || low == "uint32" ||
        low == "u32" || low == "uint" || low == "dword" || low == "ulong" || low == "undefined4" ||
        low == "elf32_word" || low == "elf64_word" || low == "elf32_addr" || low == "elf32_off") {
        return {ScalarKind::UInt32, 4};
    }
    if (low == "long" || low == "long int" || low == "signed long") {
        if (declared_size_hint == 8) {
            return {ScalarKind::Int64, 8};
        }
        return {ScalarKind::Int32, 4};
    }
    if (low == "unsigned long" || low == "unsigned long int") {
        if (declared_size_hint == 8) {
            return {ScalarKind::UInt64, 8};
        }
        return {ScalarKind::UInt32, 4};
    }
    if (low == "long long" || low == "long long int" || low == "signed long long" || low == "int64_t" ||
        low == "int64" || low == "i64" || low == "__int64" || low == "longlong" || low == "isize" ||
        low == "elf64_sxword") {
        return {ScalarKind::Int64, 8};
    }
    if (low == "unsigned long long" || low == "unsigned long long int" || low == "uint64_t" ||
        low == "uint64" || low == "u64" || low == "ulonglong" || low == "unsigned __int64" ||
        low == "qword" || low == "dword64" || low == "ulong64" || low == "undefined8" ||
        low == "elf64_xword" || low == "elf64_addr" || low == "elf64_off") {
        return {ScalarKind::UInt64, 8};
    }
    if (low == "intptr_t" || low == "ssize_t" || low == "ptrdiff_t" || low == "long_ptr") {
        const std::uint64_t psz = declared_size_hint == 4 || declared_size_hint == 8
                                      ? declared_size_hint
                                      : static_cast<std::uint64_t>(layout.pointer_size());
        return {ScalarKind::IntPtr, psz};
    }
    if (low == "uintptr_t" || low == "size_t" || low == "usize" || low == "ulong_ptr" ||
        low == "dword_ptr" || low == "handle") {
        const std::uint64_t psz = declared_size_hint == 4 || declared_size_hint == 8
                                      ? declared_size_hint
                                      : static_cast<std::uint64_t>(layout.pointer_size());
        return {ScalarKind::UIntPtr, psz};
    }
    if (low == "float" || low == "float32" || low == "f32") {
        return {ScalarKind::Float32, 4};
    }
    if (low == "double" || low == "float64" || low == "f64") {
        return {ScalarKind::Float64, 8};
    }
    return {ScalarKind::None, 0};
}

[[nodiscard]] std::uint64_t compute_type_size(const StructureCatalog& catalog,
                                              std::string_view type_expr,
                                              const peelf::TargetLayout& layout,
                                              std::size_t depth = 0) {
    if (depth > 8) {
        return 0;
    }
    const ParsedTypeExpr parsed = parse_type_expr(type_expr);
    if (parsed.kind == ParsedTypeExpr::Kind::Pointer) {
        return static_cast<std::uint64_t>(layout.pointer_size());
    }
    if (parsed.kind == ParsedTypeExpr::Kind::Array) {
        const std::uint64_t elem_sz = compute_type_size(catalog, parsed.inner_type, layout, depth + 1);
        return elem_sz * parsed.array_count;
    }
    const ScalarInfo sc = classify_scalar(parsed.base_name, layout);
    if (sc.kind != ScalarKind::None) {
        return sc.byte_size;
    }
    if (const DataTypeRecord* rec = catalog.find(parsed.base_name)) {
        return rec->size;
    }
    return 0;
}

[[nodiscard]] std::string escape_ascii_preview(std::span<const std::uint8_t> bytes,
                                               std::span<const std::uint8_t> valid,
                                               bool stop_at_nul,
                                               std::size_t max_chars = 64) {
    std::string out;
    out.reserve(std::min(bytes.size(), max_chars) + 4);
    out.push_back('"');
    std::size_t emitted = 0;
    bool truncated = false;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i < valid.size() && valid[i] == 0) {
            break;
        }
        const std::uint8_t b = bytes[i];
        if (b == 0 && stop_at_nul) {
            break;
        }
        if (emitted >= max_chars) {
            truncated = true;
            break;
        }
        if (b == '\\') {
            out += "\\\\";
        } else if (b == '"') {
            out += "\\\"";
        } else if (b == '\n') {
            out += "\\n";
        } else if (b == '\r') {
            out += "\\r";
        } else if (b == '\t') {
            out += "\\t";
        } else if (b >= 0x20 && b < 0x7F) {
            out.push_back(static_cast<char>(b));
        } else if (b == 0) {
            break;
        } else {
            out += std::format("\\x{:02X}", b);
        }
        ++emitted;
    }
    out.push_back('"');
    if (truncated) {
        out += "...";
    }
    return out;
}

[[nodiscard]] std::string decode_utf16_preview(std::span<const std::uint8_t> bytes,
                                               std::span<const std::uint8_t> valid,
                                               peelf::Endianness endianness,
                                               bool stop_at_nul,
                                               std::size_t max_units = 64) {
    std::string out = "L\"";
    const peelf::EndianReader reader(bytes, endianness);
    std::size_t units = 0;
    bool truncated = false;
    for (std::size_t off = 0; off + 1 < bytes.size(); off += 2) {
        if (off + 1 < valid.size() && (valid[off] == 0 || valid[off + 1] == 0)) {
            break;
        }
        const auto cu_res = reader.read_u16(off);
        if (!cu_res) {
            break;
        }
        const std::uint16_t cu = *cu_res;
        if (cu == 0) {
            if (stop_at_nul) {
                break;
            }
            break;
        }
        if (units >= max_units) {
            truncated = true;
            break;
        }
        if (cu == '\\') {
            out += "\\\\";
        } else if (cu == '"') {
            out += "\\\"";
        } else if (cu == '\n') {
            out += "\\n";
        } else if (cu == '\r') {
            out += "\\r";
        } else if (cu == '\t') {
            out += "\\t";
        } else if (cu >= 0x20 && cu < 0x7F) {
            out.push_back(static_cast<char>(cu));
        } else if (cu < 0x800) {
            out.push_back(static_cast<char>(0xC0u | (cu >> 6u)));
            out.push_back(static_cast<char>(0x80u | (cu & 0x3Fu)));
        } else if (cu >= 0xD800 && cu <= 0xDFFF) {
            out += std::format("\\u{:04X}", cu);
        } else {
            out.push_back(static_cast<char>(0xE0u | (cu >> 12u)));
            out.push_back(static_cast<char>(0x80u | ((cu >> 6u) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cu & 0x3Fu)));
        }
        ++units;
    }
    out.push_back('"');
    if (truncated) {
        out += "...";
    }
    return out;
}

[[nodiscard]] std::string format_raw_hex(const peelf::MemorySample& sample,
                                         std::size_t max_bytes = 16) {
    if (sample.bytes.empty()) {
        return {};
    }
    const std::size_t n = std::min(sample.bytes.size(), max_bytes);
    std::string out;
    out.reserve(n * 3 + 4);
    for (std::size_t i = 0; i < n; ++i) {
        if (i > 0) {
            out.push_back(' ');
        }
        const bool ok = i < sample.valid.size() && sample.valid[i] != 0;
        if (ok) {
            out += std::format("{:02X}", sample.bytes[i]);
        } else {
            out += "??";
        }
    }
    if (sample.bytes.size() > max_bytes) {
        out += " ...";
    }
    return out;
}

[[nodiscard]] peelf::Availability sample_availability(const peelf::MemorySample& sample) noexcept {
    if (sample.bytes.empty()) {
        return peelf::Availability::Available;
    }
    if (sample.readable_count == 0) {
        return peelf::Availability::Unavailable;
    }
    if (sample.readable_count < sample.bytes.size()) {
        return peelf::Availability::Partial;
    }
    return peelf::Availability::Available;
}

[[nodiscard]] peelf::Availability merge_availability(peelf::Availability a,
                                                     peelf::Availability b) noexcept {
    if (a == b) {
        return a;
    }
    return peelf::Availability::Partial;
}

[[nodiscard]] std::vector<CatalogTypeEntry> build_builtin_catalog() {
    std::vector<CatalogTypeEntry> out;
    out.reserve(32);

    auto add = [&](StructureSchemaOrigin origin,
                   std::string name,
                   std::uint64_t size,
                   bool is_union,
                   std::vector<DataMember> members) {
        out.push_back(CatalogTypeEntry{
            .record = DataTypeRecord{
                .name = std::move(name),
                .size = size,
                .is_union = is_union,
                .members = std::move(members),
            },
            .origin = origin,
        });
    };

    // ---------------- PE Format ----------------
    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_DOS_HEADER", 64, false, {
        {"e_magic", "uint16_t", 0x00, 2},
        {"e_cblp", "uint16_t", 0x02, 2},
        {"e_cp", "uint16_t", 0x04, 2},
        {"e_crlc", "uint16_t", 0x06, 2},
        {"e_cparhdr", "uint16_t", 0x08, 2},
        {"e_minalloc", "uint16_t", 0x0A, 2},
        {"e_maxalloc", "uint16_t", 0x0C, 2},
        {"e_ss", "uint16_t", 0x0E, 2},
        {"e_sp", "uint16_t", 0x10, 2},
        {"e_csum", "uint16_t", 0x12, 2},
        {"e_ip", "uint16_t", 0x14, 2},
        {"e_cs", "uint16_t", 0x16, 2},
        {"e_lfarlc", "uint16_t", 0x18, 2},
        {"e_ovno", "uint16_t", 0x1A, 2},
        {"e_res", "uint16_t[4]", 0x1C, 8},
        {"e_oemid", "uint16_t", 0x24, 2},
        {"e_oeminfo", "uint16_t", 0x26, 2},
        {"e_res2", "uint16_t[10]", 0x28, 20},
        {"e_lfanew", "int32_t", 0x3C, 4},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_FILE_HEADER", 20, false, {
        {"Machine", "uint16_t", 0x00, 2},
        {"NumberOfSections", "uint16_t", 0x02, 2},
        {"TimeDateStamp", "uint32_t", 0x04, 4},
        {"PointerToSymbolTable", "uint32_t", 0x08, 4},
        {"NumberOfSymbols", "uint32_t", 0x0C, 4},
        {"SizeOfOptionalHeader", "uint16_t", 0x10, 2},
        {"Characteristics", "uint16_t", 0x12, 2},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_DATA_DIRECTORY", 8, false, {
        {"VirtualAddress", "uint32_t", 0x00, 4},
        {"Size", "uint32_t", 0x04, 4},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_OPTIONAL_HEADER32", 224, false, {
        {"Magic", "uint16_t", 0x00, 2},
        {"MajorLinkerVersion", "uint8_t", 0x02, 1},
        {"MinorLinkerVersion", "uint8_t", 0x03, 1},
        {"SizeOfCode", "uint32_t", 0x04, 4},
        {"SizeOfInitializedData", "uint32_t", 0x08, 4},
        {"SizeOfUninitializedData", "uint32_t", 0x0C, 4},
        {"AddressOfEntryPoint", "uint32_t", 0x10, 4},
        {"BaseOfCode", "uint32_t", 0x14, 4},
        {"BaseOfData", "uint32_t", 0x18, 4},
        {"ImageBase", "uint32_t", 0x1C, 4},
        {"SectionAlignment", "uint32_t", 0x20, 4},
        {"FileAlignment", "uint32_t", 0x24, 4},
        {"MajorOperatingSystemVersion", "uint16_t", 0x28, 2},
        {"MinorOperatingSystemVersion", "uint16_t", 0x2A, 2},
        {"MajorImageVersion", "uint16_t", 0x2C, 2},
        {"MinorImageVersion", "uint16_t", 0x2E, 2},
        {"MajorSubsystemVersion", "uint16_t", 0x30, 2},
        {"MinorSubsystemVersion", "uint16_t", 0x32, 2},
        {"Win32VersionValue", "uint32_t", 0x34, 4},
        {"SizeOfImage", "uint32_t", 0x38, 4},
        {"SizeOfHeaders", "uint32_t", 0x3C, 4},
        {"CheckSum", "uint32_t", 0x40, 4},
        {"Subsystem", "uint16_t", 0x44, 2},
        {"DllCharacteristics", "uint16_t", 0x46, 2},
        {"SizeOfStackReserve", "uint32_t", 0x48, 4},
        {"SizeOfStackCommit", "uint32_t", 0x4C, 4},
        {"SizeOfHeapReserve", "uint32_t", 0x50, 4},
        {"SizeOfHeapCommit", "uint32_t", 0x54, 4},
        {"LoaderFlags", "uint32_t", 0x58, 4},
        {"NumberOfRvaAndSizes", "uint32_t", 0x5C, 4},
        {"DataDirectory", "IMAGE_DATA_DIRECTORY[16]", 0x60, 128},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_OPTIONAL_HEADER64", 240, false, {
        {"Magic", "uint16_t", 0x00, 2},
        {"MajorLinkerVersion", "uint8_t", 0x02, 1},
        {"MinorLinkerVersion", "uint8_t", 0x03, 1},
        {"SizeOfCode", "uint32_t", 0x04, 4},
        {"SizeOfInitializedData", "uint32_t", 0x08, 4},
        {"SizeOfUninitializedData", "uint32_t", 0x0C, 4},
        {"AddressOfEntryPoint", "uint32_t", 0x10, 4},
        {"BaseOfCode", "uint32_t", 0x14, 4},
        {"ImageBase", "uint64_t", 0x18, 8},
        {"SectionAlignment", "uint32_t", 0x20, 4},
        {"FileAlignment", "uint32_t", 0x24, 4},
        {"MajorOperatingSystemVersion", "uint16_t", 0x28, 2},
        {"MinorOperatingSystemVersion", "uint16_t", 0x2A, 2},
        {"MajorImageVersion", "uint16_t", 0x2C, 2},
        {"MinorImageVersion", "uint16_t", 0x2E, 2},
        {"MajorSubsystemVersion", "uint16_t", 0x30, 2},
        {"MinorSubsystemVersion", "uint16_t", 0x32, 2},
        {"Win32VersionValue", "uint32_t", 0x34, 4},
        {"SizeOfImage", "uint32_t", 0x38, 4},
        {"SizeOfHeaders", "uint32_t", 0x3C, 4},
        {"CheckSum", "uint32_t", 0x40, 4},
        {"Subsystem", "uint16_t", 0x44, 2},
        {"DllCharacteristics", "uint16_t", 0x46, 2},
        {"SizeOfStackReserve", "uint64_t", 0x48, 8},
        {"SizeOfStackCommit", "uint64_t", 0x50, 8},
        {"SizeOfHeapReserve", "uint64_t", 0x58, 8},
        {"SizeOfHeapCommit", "uint64_t", 0x60, 8},
        {"LoaderFlags", "uint32_t", 0x68, 4},
        {"NumberOfRvaAndSizes", "uint32_t", 0x6C, 4},
        {"DataDirectory", "IMAGE_DATA_DIRECTORY[16]", 0x70, 128},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_SECTION_HEADER", 40, false, {
        {"Name", "char[8]", 0x00, 8},
        {"VirtualSize", "uint32_t", 0x08, 4},
        {"VirtualAddress", "uint32_t", 0x0C, 4},
        {"SizeOfRawData", "uint32_t", 0x10, 4},
        {"PointerToRawData", "uint32_t", 0x14, 4},
        {"PointerToRelocations", "uint32_t", 0x18, 4},
        {"PointerToLinenumbers", "uint32_t", 0x1C, 4},
        {"NumberOfRelocations", "uint16_t", 0x20, 2},
        {"NumberOfLinenumbers", "uint16_t", 0x22, 2},
        {"Characteristics", "uint32_t", 0x24, 4},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_IMPORT_DESCRIPTOR", 20, false, {
        {"OriginalFirstThunk", "uint32_t", 0x00, 4},
        {"TimeDateStamp", "uint32_t", 0x04, 4},
        {"ForwarderChain", "uint32_t", 0x08, 4},
        {"Name", "uint32_t", 0x0C, 4},
        {"FirstThunk", "uint32_t", 0x10, 4},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_TLS_DIRECTORY32", 24, false, {
        {"StartAddressOfRawData", "void*", 0x00, 4},
        {"EndAddressOfRawData", "void*", 0x04, 4},
        {"AddressOfIndex", "uint32_t*", 0x08, 4},
        {"AddressOfCallBacks", "void*", 0x0C, 4},
        {"SizeOfZeroFill", "uint32_t", 0x10, 4},
        {"Characteristics", "uint32_t", 0x14, 4},
    });

    add(StructureSchemaOrigin::BuiltinPe, "IMAGE_TLS_DIRECTORY64", 40, false, {
        {"StartAddressOfRawData", "void*", 0x00, 8},
        {"EndAddressOfRawData", "void*", 0x08, 8},
        {"AddressOfIndex", "uint32_t*", 0x10, 8},
        {"AddressOfCallBacks", "void*", 0x18, 8},
        {"SizeOfZeroFill", "uint32_t", 0x20, 4},
        {"Characteristics", "uint32_t", 0x24, 4},
    });

    // ---------------- Win32 Runtime ----------------
    add(StructureSchemaOrigin::BuiltinWin32Runtime, "UNICODE_STRING32", 8, false, {
        {"Length", "uint16_t", 0x00, 2},
        {"MaximumLength", "uint16_t", 0x02, 2},
        {"Buffer", "wchar_t*", 0x04, 4},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "UNICODE_STRING64", 16, false, {
        {"Length", "uint16_t", 0x00, 2},
        {"MaximumLength", "uint16_t", 0x02, 2},
        {"Reserved", "uint32_t", 0x04, 4},
        {"Buffer", "wchar_t*", 0x08, 8},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "LIST_ENTRY32", 8, false, {
        {"Flink", "LIST_ENTRY32*", 0x00, 4},
        {"Blink", "LIST_ENTRY32*", 0x04, 4},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "LIST_ENTRY64", 16, false, {
        {"Flink", "LIST_ENTRY64*", 0x00, 8},
        {"Blink", "LIST_ENTRY64*", 0x08, 8},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "NT_TIB32", 28, false, {
        {"ExceptionList", "void*", 0x00, 4},
        {"StackBase", "void*", 0x04, 4},
        {"StackLimit", "void*", 0x08, 4},
        {"SubSystemTib", "void*", 0x0C, 4},
        {"FiberData", "void*", 0x10, 4},
        {"ArbitraryUserPointer", "void*", 0x14, 4},
        {"Self", "NT_TIB32*", 0x18, 4},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "NT_TIB64", 56, false, {
        {"ExceptionList", "void*", 0x00, 8},
        {"StackBase", "void*", 0x08, 8},
        {"StackLimit", "void*", 0x10, 8},
        {"SubSystemTib", "void*", 0x18, 8},
        {"FiberData", "void*", 0x20, 8},
        {"ArbitraryUserPointer", "void*", 0x28, 8},
        {"Self", "NT_TIB64*", 0x30, 8},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "RTL_USER_PROCESS_PARAMETERS64", 0x88, false, {
        {"MaximumLength", "uint32_t", 0x00, 4},
        {"Length", "uint32_t", 0x04, 4},
        {"Flags", "uint32_t", 0x08, 4},
        {"DebugFlags", "uint32_t", 0x0C, 4},
        {"ConsoleHandle", "void*", 0x10, 8},
        {"ConsoleFlags", "uint32_t", 0x18, 4},
        {"StandardInput", "void*", 0x20, 8},
        {"StandardOutput", "void*", 0x28, 8},
        {"StandardError", "void*", 0x30, 8},
        {"CurrentDirectoryPath", "UNICODE_STRING64", 0x38, 16},
        {"CurrentDirectoryHandle", "void*", 0x48, 8},
        {"DllPath", "UNICODE_STRING64", 0x50, 16},
        {"ImagePathName", "UNICODE_STRING64", 0x60, 16},
        {"CommandLine", "UNICODE_STRING64", 0x70, 16},
        {"Environment", "wchar_t*", 0x80, 8},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "PEB32", 0x6C, false, {
        {"InheritedAddressSpace", "uint8_t", 0x00, 1},
        {"ReadImageFileExecOptions", "uint8_t", 0x01, 1},
        {"BeingDebugged", "bool", 0x02, 1},
        {"BitField", "uint8_t", 0x03, 1},
        {"Mutant", "void*", 0x04, 4},
        {"ImageBaseAddress", "void*", 0x08, 4},
        {"Ldr", "void*", 0x0C, 4},
        {"ProcessParameters", "void*", 0x10, 4},
        {"SubSystemData", "void*", 0x14, 4},
        {"ProcessHeap", "void*", 0x18, 4},
        {"FastPebLock", "void*", 0x1C, 4},
        {"AtlThunkSListPtr", "void*", 0x20, 4},
        {"IFEOKey", "void*", 0x24, 4},
        {"CrossProcessFlags", "uint32_t", 0x28, 4},
        {"NtGlobalFlag", "uint32_t", 0x68, 4},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "PEB64", 0x128, false, {
        {"InheritedAddressSpace", "uint8_t", 0x00, 1},
        {"ReadImageFileExecOptions", "uint8_t", 0x01, 1},
        {"BeingDebugged", "bool", 0x02, 1},
        {"BitField", "uint8_t", 0x03, 1},
        {"Mutant", "void*", 0x08, 8},
        {"ImageBaseAddress", "void*", 0x10, 8},
        {"Ldr", "void*", 0x18, 8},
        {"ProcessParameters", "RTL_USER_PROCESS_PARAMETERS64*", 0x20, 8},
        {"SubSystemData", "void*", 0x28, 8},
        {"ProcessHeap", "void*", 0x30, 8},
        {"FastPebLock", "void*", 0x38, 8},
        {"AtlThunkSListPtr", "void*", 0x40, 8},
        {"IFEOKey", "void*", 0x48, 8},
        {"CrossProcessFlags", "uint32_t", 0x50, 4},
        {"NumberOfHeaps", "uint32_t", 0xE8, 4},
        {"MaximumNumberOfHeaps", "uint32_t", 0xEC, 4},
        {"ProcessHeaps", "void*", 0xF0, 8},
        {"NtGlobalFlag", "uint32_t", 0xBC, 4},
        {"OSMajorVersion", "uint32_t", 0x118, 4},
        {"OSMinorVersion", "uint32_t", 0x11C, 4},
        {"OSBuildNumber", "uint16_t", 0x120, 2},
    });
    // Keep PEB64 members sorted strictly by offset for clean table display
    std::ranges::sort(out.back().record.members, {}, &DataMember::offset);

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "TEB32", 0x38, false, {
        {"NtTib", "NT_TIB32", 0x00, 28},
        {"EnvironmentPointer", "void*", 0x1C, 4},
        {"ClientId_UniqueProcess", "uint32_t", 0x20, 4},
        {"ClientId_UniqueThread", "uint32_t", 0x24, 4},
        {"ActiveRpcHandle", "void*", 0x28, 4},
        {"ThreadLocalStoragePointer", "void*", 0x2C, 4},
        {"ProcessEnvironmentBlock", "PEB32*", 0x30, 4},
        {"LastErrorValue", "uint32_t", 0x34, 4},
    });

    add(StructureSchemaOrigin::BuiltinWin32Runtime, "TEB64", 0x70, false, {
        {"NtTib", "NT_TIB64", 0x00, 56},
        {"EnvironmentPointer", "void*", 0x38, 8},
        {"ClientId_UniqueProcess", "uint64_t", 0x40, 8},
        {"ClientId_UniqueThread", "uint64_t", 0x48, 8},
        {"ActiveRpcHandle", "void*", 0x50, 8},
        {"ThreadLocalStoragePointer", "void*", 0x58, 8},
        {"ProcessEnvironmentBlock", "PEB64*", 0x60, 8},
        {"LastErrorValue", "uint32_t", 0x68, 4},
    });

    // ---------------- ELF Format ----------------
    add(StructureSchemaOrigin::BuiltinElf, "Elf32_Ehdr", 52, false, {
        {"e_ident", "uint8_t[16]", 0x00, 16},
        {"e_type", "uint16_t", 0x10, 2},
        {"e_machine", "uint16_t", 0x12, 2},
        {"e_version", "uint32_t", 0x14, 4},
        {"e_entry", "uint32_t", 0x18, 4},
        {"e_phoff", "uint32_t", 0x1C, 4},
        {"e_shoff", "uint32_t", 0x20, 4},
        {"e_flags", "uint32_t", 0x24, 4},
        {"e_ehsize", "uint16_t", 0x28, 2},
        {"e_phentsize", "uint16_t", 0x2A, 2},
        {"e_phnum", "uint16_t", 0x2C, 2},
        {"e_shentsize", "uint16_t", 0x2E, 2},
        {"e_shnum", "uint16_t", 0x30, 2},
        {"e_shstrndx", "uint16_t", 0x32, 2},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf64_Ehdr", 64, false, {
        {"e_ident", "uint8_t[16]", 0x00, 16},
        {"e_type", "uint16_t", 0x10, 2},
        {"e_machine", "uint16_t", 0x12, 2},
        {"e_version", "uint32_t", 0x14, 4},
        {"e_entry", "uint64_t", 0x18, 8},
        {"e_phoff", "uint64_t", 0x20, 8},
        {"e_shoff", "uint64_t", 0x28, 8},
        {"e_flags", "uint32_t", 0x30, 4},
        {"e_ehsize", "uint16_t", 0x34, 2},
        {"e_phentsize", "uint16_t", 0x36, 2},
        {"e_phnum", "uint16_t", 0x38, 2},
        {"e_shentsize", "uint16_t", 0x3A, 2},
        {"e_shnum", "uint16_t", 0x3C, 2},
        {"e_shstrndx", "uint16_t", 0x3E, 2},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf32_Phdr", 32, false, {
        {"p_type", "uint32_t", 0x00, 4},
        {"p_offset", "uint32_t", 0x04, 4},
        {"p_vaddr", "uint32_t", 0x08, 4},
        {"p_paddr", "uint32_t", 0x0C, 4},
        {"p_filesz", "uint32_t", 0x10, 4},
        {"p_memsz", "uint32_t", 0x14, 4},
        {"p_flags", "uint32_t", 0x18, 4},
        {"p_align", "uint32_t", 0x1C, 4},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf64_Phdr", 56, false, {
        {"p_type", "uint32_t", 0x00, 4},
        {"p_flags", "uint32_t", 0x04, 4},
        {"p_offset", "uint64_t", 0x08, 8},
        {"p_vaddr", "uint64_t", 0x10, 8},
        {"p_paddr", "uint64_t", 0x18, 8},
        {"p_filesz", "uint64_t", 0x20, 8},
        {"p_memsz", "uint64_t", 0x28, 8},
        {"p_align", "uint64_t", 0x30, 8},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf32_Shdr", 40, false, {
        {"sh_name", "uint32_t", 0x00, 4},
        {"sh_type", "uint32_t", 0x04, 4},
        {"sh_flags", "uint32_t", 0x08, 4},
        {"sh_addr", "uint32_t", 0x0C, 4},
        {"sh_offset", "uint32_t", 0x10, 4},
        {"sh_size", "uint32_t", 0x14, 4},
        {"sh_link", "uint32_t", 0x18, 4},
        {"sh_info", "uint32_t", 0x1C, 4},
        {"sh_addralign", "uint32_t", 0x20, 4},
        {"sh_entsize", "uint32_t", 0x24, 4},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf64_Shdr", 64, false, {
        {"sh_name", "uint32_t", 0x00, 4},
        {"sh_type", "uint32_t", 0x04, 4},
        {"sh_flags", "uint64_t", 0x08, 8},
        {"sh_addr", "uint64_t", 0x10, 8},
        {"sh_offset", "uint64_t", 0x18, 8},
        {"sh_size", "uint64_t", 0x20, 8},
        {"sh_link", "uint32_t", 0x28, 4},
        {"sh_info", "uint32_t", 0x2C, 4},
        {"sh_addralign", "uint64_t", 0x30, 8},
        {"sh_entsize", "uint64_t", 0x38, 8},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf32_Dyn", 8, false, {
        {"d_tag", "int32_t", 0x00, 4},
        {"d_val", "uint32_t", 0x04, 4},
    });

    add(StructureSchemaOrigin::BuiltinElf, "Elf64_Dyn", 16, false, {
        {"d_tag", "int64_t", 0x00, 8},
        {"d_val", "uint64_t", 0x08, 8},
    });

    // ---------------- Linux Dynamic Linker Runtime ----------------
    add(StructureSchemaOrigin::BuiltinLinuxRuntime, "link_map32", 20, false, {
        {"l_addr", "uint32_t", 0x00, 4},
        {"l_name", "char*", 0x04, 4},
        {"l_ld", "Elf32_Dyn*", 0x08, 4},
        {"l_next", "link_map32*", 0x0C, 4},
        {"l_prev", "link_map32*", 0x10, 4},
    });

    add(StructureSchemaOrigin::BuiltinLinuxRuntime, "link_map64", 40, false, {
        {"l_addr", "uint64_t", 0x00, 8},
        {"l_name", "char*", 0x08, 8},
        {"l_ld", "Elf64_Dyn*", 0x10, 8},
        {"l_next", "link_map64*", 0x18, 8},
        {"l_prev", "link_map64*", 0x20, 8},
    });

    add(StructureSchemaOrigin::BuiltinLinuxRuntime, "r_debug32", 20, false, {
        {"r_version", "int32_t", 0x00, 4},
        {"r_map", "link_map32*", 0x04, 4},
        {"r_brk", "void*", 0x08, 4},
        {"r_state", "int32_t", 0x0C, 4},
        {"r_ldbase", "void*", 0x10, 4},
    });

    add(StructureSchemaOrigin::BuiltinLinuxRuntime, "r_debug64", 40, false, {
        {"r_version", "int32_t", 0x00, 4},
        {"r_map", "link_map64*", 0x08, 8},
        {"r_brk", "void*", 0x10, 8},
        {"r_state", "int32_t", 0x18, 4},
        {"r_ldbase", "void*", 0x20, 8},
    });

    return out;
}

} // namespace

const std::vector<CatalogTypeEntry>& builtin_structure_catalog() {
    static const std::vector<CatalogTypeEntry> kBuiltins = build_builtin_catalog();
    return kBuiltins;
}

void StructureCatalog::add_entry(CatalogTypeEntry entry) {
    if (entry.record.name.empty()) {
        return;
    }
    const std::string key = canonical_type_key(entry.record.name);
    if (key.empty() || by_canonical_name_.contains(key)) {
        return;
    }
    const std::size_t idx = entries_.size();
    entries_.push_back(std::move(entry));
    by_canonical_name_.emplace(key, idx);
    if (entries_.back().record.name != key) {
        by_canonical_name_.emplace(entries_.back().record.name, idx);
    }
}

StructureCatalog StructureCatalog::build(std::span<const DataTypeRecord> primary_user_types,
                                         std::span<const DataTypeRecord> secondary_user_types,
                                         bool include_builtins) {
    StructureCatalog cat;
    const auto& builtins = builtin_structure_catalog();
    cat.entries_.reserve(primary_user_types.size() + secondary_user_types.size() +
                         (include_builtins ? builtins.size() : 0u));

    for (const DataTypeRecord& rec : primary_user_types) {
        cat.add_entry(CatalogTypeEntry{
            .record = rec,
            .origin = StructureSchemaOrigin::UserOrDebug,
        });
    }
    for (const DataTypeRecord& rec : secondary_user_types) {
        cat.add_entry(CatalogTypeEntry{
            .record = rec,
            .origin = StructureSchemaOrigin::UserOrDebug,
        });
    }
    if (include_builtins) {
        for (const CatalogTypeEntry& builtin : builtins) {
            cat.add_entry(builtin);
        }
    }
    return cat;
}

const CatalogTypeEntry* StructureCatalog::find_entry(std::string_view type_name) const {
    const std::string key = canonical_type_key(type_name);
    if (const auto it = by_canonical_name_.find(key); it != by_canonical_name_.end()) {
        return &entries_[it->second];
    }
    return nullptr;
}

const DataTypeRecord* StructureCatalog::find(std::string_view type_name) const {
    if (const CatalogTypeEntry* entry = find_entry(type_name)) {
        return &entry->record;
    }
    return nullptr;
}

// ============================================================================
// Byte Sources
// ============================================================================

peelf::MemorySample SpanStructureByteSource::read_bytes(std::uint64_t address,
                                                        bool is_file_offset,
                                                        std::size_t size) const {
    peelf::MemorySample sample;
    sample.bytes.assign(size, 0u);
    sample.valid.assign(size, 0u);
    if (size == 0) {
        return sample;
    }

    std::uint64_t offset = address;
    if (!is_file_offset) {
        if (address < base_va_) {
            return sample;
        }
        offset = address - base_va_;
    }

    for (std::size_t i = 0; i < size; ++i) {
        if (offset > std::numeric_limits<std::uint64_t>::max() - i) {
            break;
        }
        const std::uint64_t cur = offset + i;
        if (cur >= bytes_.size()) {
            break;
        }
        const auto idx = static_cast<std::size_t>(cur);
        const bool ok = valid_mask_.empty() || (idx < valid_mask_.size() && valid_mask_[idx] != 0);
        if (ok) {
            sample.bytes[i] = bytes_[idx];
            sample.valid[i] = 1u;
            ++sample.readable_count;
        }
    }
    return sample;
}

std::optional<std::uint64_t> SpanStructureByteSource::to_virtual_address(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (!is_file_offset) {
        return address;
    }
    if (address >= bytes_.size()) {
        return std::nullopt;
    }
    return base_va_ + address;
}

std::optional<std::uint64_t> SpanStructureByteSource::to_window_offset(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (is_file_offset) {
        return address < bytes_.size() ? std::optional<std::uint64_t>{address} : std::nullopt;
    }
    if (address < base_va_) {
        return std::nullopt;
    }
    const std::uint64_t off = address - base_va_;
    return off < bytes_.size() ? std::optional<std::uint64_t>{off} : std::nullopt;
}

std::string SpanStructureByteSource::describe_pointer(std::uint64_t target_va) const {
    return annotator_ ? annotator_(target_va) : std::string{};
}

peelf::MemorySample StaticImageStructureByteSource::read_bytes(std::uint64_t address,
                                                               bool is_file_offset,
                                                               std::size_t size) const {
    peelf::MemorySample sample;
    sample.bytes.assign(size, 0u);
    sample.valid.assign(size, 0u);
    if (size == 0) {
        return sample;
    }

    for (std::size_t i = 0; i < size; ++i) {
        if (address > std::numeric_limits<std::uint64_t>::max() - i) {
            break;
        }
        const std::uint64_t cur = address + i;
        if (is_file_offset) {
            if (cur < file_bytes_.size()) {
                sample.bytes[i] = file_bytes_[static_cast<std::size_t>(cur)];
                sample.valid[i] = 1u;
                ++sample.readable_count;
            }
            continue;
        }

        if (const auto foff = image_.virtual_address_to_file_offset(cur); foff && *foff < file_bytes_.size()) {
            sample.bytes[i] = file_bytes_[static_cast<std::size_t>(*foff)];
            sample.valid[i] = 1u;
            ++sample.readable_count;
            continue;
        }

        // Check zero-filled BSS virtual range in sections or segments
        bool in_bss = false;
        const std::uint64_t base = image_.image_base();
        for (const peelf::Section& sec : image_.sections()) {
            const std::uint64_t sec_va =
                (image_.format() == peelf::Format::PE) ? (base + sec.virtual_address) : sec.virtual_address;
            if (cur >= sec_va && cur - sec_va < sec.virtual_size) {
                in_bss = true;
                break;
            }
        }
        if (in_bss) {
            sample.bytes[i] = 0u;
            sample.valid[i] = 1u;
            ++sample.readable_count;
        }
    }
    return sample;
}

std::optional<std::uint64_t> StaticImageStructureByteSource::to_virtual_address(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (!is_file_offset) {
        return address;
    }
    if (auto va = image_.file_offset_to_virtual_address(address)) {
        return *va;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> StaticImageStructureByteSource::to_window_offset(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (is_file_offset) {
        return address < file_bytes_.size() ? std::optional<std::uint64_t>{address} : std::nullopt;
    }
    if (auto foff = image_.virtual_address_to_file_offset(address); foff && *foff < file_bytes_.size()) {
        return *foff;
    }
    return std::nullopt;
}

std::string StaticImageStructureByteSource::describe_pointer(std::uint64_t target_va) const {
    if (annotator_) {
        if (std::string s = annotator_(target_va); !s.empty()) {
            return s;
        }
    }
    const std::uint64_t base = image_.image_base();
    for (const peelf::Section& sec : image_.sections()) {
        const std::uint64_t sec_va =
            (image_.format() == peelf::Format::PE) ? (base + sec.virtual_address) : sec.virtual_address;
        if (target_va >= sec_va && target_va - sec_va < std::max(sec.virtual_size, sec.file_size)) {
            return std::format("{}+0x{:X}", sec.name, target_va - sec_va);
        }
    }
    return {};
}

peelf::MemorySample LiveProcessStructureByteSource::read_bytes(std::uint64_t address,
                                                               bool is_file_offset,
                                                               std::size_t size) const {
    peelf::MemorySample sample;
    sample.bytes.assign(size, 0u);
    sample.valid.assign(size, 0u);
    if (size == 0 || is_file_offset) {
        return sample;
    }

    // Read in page-aligned slices so a struct straddling a readable -> guard page boundary
    // decodes all readable fields cleanly and marks only the unmapped tail as unreadable.
    constexpr std::uint64_t kPageSize = 4096u;
    std::size_t pos = 0;
    while (pos < size) {
        if (address > std::numeric_limits<std::uint64_t>::max() - pos) {
            break;
        }
        const std::uint64_t cur_va = address + pos;
        const std::uint64_t page_rem = kPageSize - (cur_va & (kPageSize - 1u));
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(page_rem, static_cast<std::uint64_t>(size - pos)));

        std::span<std::uint8_t> dst(sample.bytes.data() + pos, chunk);
        if (auto res = session_.read_memory(cur_va, dst); res && *res > 0) {
            const std::size_t got = std::min(*res, chunk);
            for (std::size_t k = 0; k < got; ++k) {
                sample.valid[pos + k] = 1u;
            }
            sample.readable_count += got;
            if (got < chunk) {
                // Fine-grained probe for remaining bytes in this chunk if mock/OS ended mid-page
                for (std::size_t k = got; k < chunk; ++k) {
                    std::uint8_t b = 0;
                    if (auto bres = session_.read_memory(cur_va + k, std::span<std::uint8_t>(&b, 1));
                        bres && *bres == 1) {
                        sample.bytes[pos + k] = b;
                        sample.valid[pos + k] = 1u;
                        ++sample.readable_count;
                    } else {
                        break;
                    }
                }
            }
        } else {
            // Probe byte-by-byte only for small sub-page spans (<= 256 bytes) in case a synthetic
            // test session exposes non-4KiB region boundaries.
            if (chunk <= 256) {
                for (std::size_t k = 0; k < chunk; ++k) {
                    std::uint8_t b = 0;
                    if (auto bres = session_.read_memory(cur_va + k, std::span<std::uint8_t>(&b, 1));
                        bres && *bres == 1) {
                        sample.bytes[pos + k] = b;
                        sample.valid[pos + k] = 1u;
                        ++sample.readable_count;
                    }
                }
            }
        }
        pos += chunk;
    }
    return sample;
}

std::string LiveProcessStructureByteSource::describe_pointer(std::uint64_t target_va) const {
    if (annotator_) {
        if (std::string sym = annotator_(target_va); !sym.empty()) {
            return sym;
        }
    }
    for (const peelf::MemoryRegion& reg : regions_) {
        if (reg.contains(target_va)) {
            const std::string_view label = !reg.module_name.empty()
                                               ? std::string_view(reg.module_name)
                                               : (!reg.pathname.empty()
                                                      ? std::string_view(reg.pathname)
                                                      : peelf::to_string(reg.kind));
            return std::format("{}+0x{:X}", label, target_va - reg.start_address);
        }
    }
    return {};
}

peelf::MemorySample BinaryModelStructureByteSource::read_bytes(std::uint64_t address,
                                                               bool is_file_offset,
                                                               std::size_t size) const {
    peelf::MemorySample sample;
    sample.bytes.assign(size, 0u);
    sample.valid.assign(size, 0u);
    if (size == 0) {
        return sample;
    }

    if (model_.is_live_process()) {
        if (is_file_offset) {
            if (auto s = model_.read_window_sample(address, size)) {
                return std::move(*s);
            }
            return sample;
        }
        // If inside the active window, `read_window_sample` includes staged overlay patches too!
        if (const auto win_off = model_.virtual_address_to_offset(address);
            win_off && *win_off + size <= model_.view_size()) {
            if (auto s = model_.read_window_sample(*win_off, size)) {
                return std::move(*s);
            }
        }
        if (auto* sess = const_cast<BinaryModel&>(model_).process_session()) {
            LiveProcessStructureByteSource live_src(*sess, model_.memory_regions());
            return live_src.read_bytes(address, false, size);
        }
        return sample;
    }

    // Static file mode (honoring staged patches via `read_window_sample` / `read_virtual_bytes`)
    if (is_file_offset) {
        if (auto s = model_.read_window_sample(address, size)) {
            return std::move(*s);
        }
        return sample;
    }

    if (auto vb = model_.read_virtual_bytes(address, size)) {
        sample.bytes = std::move(*vb);
        sample.valid.assign(sample.bytes.size(), 1u);
        sample.readable_count = sample.bytes.size();
        return sample;
    }

    // Partial VA read fallback (e.g., struct crossing end of section)
    for (std::size_t i = 0; i < size; ++i) {
        if (address > std::numeric_limits<std::uint64_t>::max() - i) {
            break;
        }
        if (auto b = model_.read_virtual_bytes(address + i, 1); b && b->size() == 1) {
            sample.bytes[i] = (*b)[0];
            sample.valid[i] = 1u;
            ++sample.readable_count;
        }
    }
    return sample;
}

std::optional<std::uint64_t> BinaryModelStructureByteSource::to_virtual_address(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (!is_file_offset) {
        return address;
    }
    return model_.offset_to_virtual_address(address);
}

std::optional<std::uint64_t> BinaryModelStructureByteSource::to_window_offset(
    std::uint64_t address,
    bool is_file_offset) const noexcept {
    if (is_file_offset) {
        return address < model_.view_size() ? std::optional<std::uint64_t>{address} : std::nullopt;
    }
    return model_.virtual_address_to_offset(address);
}

std::string BinaryModelStructureByteSource::describe_pointer(std::uint64_t target_va) const {
    if (custom_annotator_) {
        if (std::string s = custom_annotator_(target_va); !s.empty()) {
            return s;
        }
    }
    if (std::string sym = model_.resolve_address_symbol(target_va); !sym.empty()) {
        return sym;
    }
    if (model_.is_live_process()) {
        for (const peelf::MemoryRegion& reg : model_.memory_regions()) {
            if (reg.contains(target_va)) {
                const std::string_view label = !reg.module_name.empty()
                                                   ? std::string_view(reg.module_name)
                                                   : (!reg.pathname.empty()
                                                          ? std::string_view(reg.pathname)
                                                          : peelf::to_string(reg.kind));
                return std::format("{}+0x{:X}", label, target_va - reg.start_address);
            }
        }
    } else if (const peelf::IBinaryImage* img = model_.image()) {
        const std::uint64_t base = img->image_base();
        for (const peelf::Section& sec : img->sections()) {
            const std::uint64_t sec_va =
                (img->format() == peelf::Format::PE) ? (base + sec.virtual_address) : sec.virtual_address;
            if (target_va >= sec_va && target_va - sec_va < std::max(sec.virtual_size, sec.file_size)) {
                return std::format("{}+0x{:X}", sec.name, target_va - sec_va);
            }
        }
    }
    return {};
}

// ============================================================================
// Recursive Structure Evaluator
// ============================================================================

namespace {

struct EvalContext {
    const StructureCatalog& catalog;
    const IStructureByteSource& source;
    const StructureEvalOptions& options;
    std::vector<std::string> inline_type_stack{};
    std::set<std::pair<std::uint64_t, std::string>> visited_pointers{};
};

[[nodiscard]] EvaluatedField evaluate_field_impl(EvalContext& ctx,
                                                 std::string name,
                                                 std::string type_expr,
                                                 std::uint64_t address,
                                                 std::uint64_t relative_offset,
                                                 std::uint64_t declared_size,
                                                 bool is_file_offset,
                                                 std::size_t depth,
                                                 std::size_t ptr_depth);

void populate_record_children(EvalContext& ctx,
                              const DataTypeRecord& record,
                                            std::uint64_t base_address,
                                            bool is_file_offset,
                                            std::size_t depth,
                                            std::size_t ptr_depth,
                                            EvaluatedField& out_parent) {
    out_parent.is_aggregate = true;
    if (depth >= ctx.options.max_depth) {
        out_parent.decoded_value = std::format("{} {} (<max depth reached>)",
                                               record.is_union ? "union" : "struct",
                                               record.name);
        return;
    }
    if (std::ranges::find(ctx.inline_type_stack, record.name) != ctx.inline_type_stack.end()) {
        out_parent.decoded_value = std::format("<recursive inline type {}>", record.name);
        return;
    }

    ctx.inline_type_stack.push_back(record.name);
    out_parent.children.reserve(record.members.size());

    bool any_avail = false;
    bool any_unavail = false;
    for (const DataMember& m : record.members) {
        const std::uint64_t member_off = record.is_union ? 0u : m.offset;
        const std::uint64_t member_addr = base_address + member_off;
        const std::uint64_t eff_size = m.size != 0
                                           ? m.size
                                           : compute_type_size(ctx.catalog, m.type, ctx.options.layout);
        EvaluatedField child = evaluate_field_impl(
            ctx,
            m.name,
            m.type,
            member_addr,
            out_parent.relative_offset + member_off,
            eff_size,
            is_file_offset,
            depth + 1,
            ptr_depth);
        if (child.availability == peelf::Availability::Available) {
            any_avail = true;
        } else if (child.availability == peelf::Availability::Unavailable) {
            any_unavail = true;
        } else {
            any_avail = true;
            any_unavail = true;
        }
        out_parent.children.push_back(std::move(child));
    }
    ctx.inline_type_stack.pop_back();

    if (any_avail && any_unavail) {
        out_parent.availability = peelf::Availability::Partial;
    } else if (any_unavail && !any_avail && !record.members.empty()) {
        out_parent.availability = peelf::Availability::Unavailable;
    } else {
        out_parent.availability = peelf::Availability::Available;
    }

    // Build a concise summary preview of the first 2 scalar/pointer fields
    std::string summary = "{ ";
    std::size_t shown = 0;
    for (const EvaluatedField& ch : out_parent.children) {
        if (shown >= 3) {
            summary += ", ...";
            break;
        }
        if (shown > 0) {
            summary += ", ";
        }
        summary += std::format(".{} = {}", ch.name, ch.decoded_value);
        ++shown;
    }
    summary += " }";
    if (out_parent.availability == peelf::Availability::Unavailable) {
        out_parent.decoded_value = "<unreadable>";
    } else {
        out_parent.decoded_value = std::move(summary);
    }
}

[[nodiscard]] EvaluatedField evaluate_field_impl(EvalContext& ctx,
                                                 std::string name,
                                                 std::string type_expr,
                                                 std::uint64_t address,
                                                 std::uint64_t relative_offset,
                                                 std::uint64_t declared_size,
                                                 bool is_file_offset,
                                                 std::size_t depth,
                                                 std::size_t ptr_depth) {
    EvaluatedField field;
    field.name = std::move(name);
    field.type_name = trim_ascii(type_expr);
    field.address = address;
    field.relative_offset = relative_offset;
    field.virtual_address = ctx.source.to_virtual_address(address, is_file_offset);
    field.window_offset = ctx.source.to_window_offset(address, is_file_offset);

    const ParsedTypeExpr parsed = parse_type_expr(field.type_name);
    const peelf::TargetLayout& layout = ctx.options.layout;

    // 1. Pointer `T*`
    if (parsed.kind == ParsedTypeExpr::Kind::Pointer) {
        const std::uint64_t ptr_sz = (declared_size == 4 || declared_size == 8)
                                         ? declared_size
                                         : static_cast<std::uint64_t>(layout.pointer_size());
        field.size = ptr_sz;
        field.is_pointer = true;
        field.pointee_type_name = canonical_type_key(parsed.inner_type);

        const peelf::MemorySample sample =
            ctx.source.read_bytes(address, is_file_offset, static_cast<std::size_t>(ptr_sz));
        field.raw_bytes_hex = format_raw_hex(sample);
        field.availability = sample_availability(sample);

        if (field.availability != peelf::Availability::Available) {
            field.decoded_value = "<unreadable>";
            return field;
        }

        const peelf::EndianReader reader(
            sample.bytes,
            layout.endianness,
            ptr_sz == 8 ? peelf::AddressWidth::Bits64 : peelf::AddressWidth::Bits32);
        const auto ptr_res = reader.read_pointer(0);
        if (!ptr_res) {
            field.decoded_value = "<unreadable>";
            field.availability = peelf::Availability::Unavailable;
            return field;
        }

        const std::uint64_t ptr_val = *ptr_res;
        field.pointer_target_va = ptr_val;
        const std::string hex_ptr = ptr_sz == 8
                                        ? std::format("0x{:016X}", ptr_val)
                                        : std::format("0x{:08X}", ptr_val);
        if (ptr_val == 0) {
            field.decoded_value = hex_ptr + " (nullptr)";
            return field;
        }

        field.pointer_annotation = ctx.source.describe_pointer(ptr_val);
        const std::string low_pointee = ascii_lower(field.pointee_type_name);
        if (low_pointee == "char" || low_pointee == "signed char" || low_pointee == "unsigned char" ||
            low_pointee == "uint8_t") {
            const peelf::MemorySample str_sample = ctx.source.read_bytes(ptr_val, false, 96);
            if (str_sample.readable_count > 0 && str_sample.valid[0] != 0) {
                field.string_preview = escape_ascii_preview(str_sample.bytes, str_sample.valid, true, 64);
            }
        } else if (low_pointee == "wchar_t" || low_pointee == "char16_t" || low_pointee == "wchar") {
            const peelf::MemorySample wstr_sample = ctx.source.read_bytes(ptr_val, false, 160);
            if (wstr_sample.readable_count >= 2 && wstr_sample.valid[0] != 0 && wstr_sample.valid[1] != 0) {
                field.string_preview = decode_utf16_preview(
                    wstr_sample.bytes, wstr_sample.valid, layout.endianness, true, 64);
            }
        }

        std::string text = hex_ptr;
        if (!field.string_preview.empty()) {
            text += " -> " + field.string_preview;
            if (!field.pointer_annotation.empty()) {
                text += " (" + field.pointer_annotation + ")";
            }
        } else if (!field.pointer_annotation.empty()) {
            text += " -> " + field.pointer_annotation;
        }
        field.decoded_value = std::move(text);

        // Optional cycle-guarded 1-hop struct dereference preview
        if (ctx.options.dereference_struct_pointers &&
            ptr_depth < ctx.options.max_pointer_deref_depth &&
            depth + 1 < ctx.options.max_depth) {
            if (const DataTypeRecord* pointee_rec = ctx.catalog.find(field.pointee_type_name)) {
                const auto visit_key = std::make_pair(ptr_val, pointee_rec->name);
                if (!ctx.visited_pointers.contains(visit_key)) {
                    const std::size_t probe_sz =
                        static_cast<std::size_t>(std::min<std::uint64_t>(std::max<std::uint64_t>(pointee_rec->size, 1u), 16u));
                    const peelf::MemorySample probe = ctx.source.read_bytes(ptr_val, false, probe_sz);
                    if (probe.readable_count > 0) {
                        ctx.visited_pointers.insert(visit_key);
                        std::vector<std::string> saved_inline_stack;
                        saved_inline_stack.swap(ctx.inline_type_stack);
                        EvaluatedField deref_node;
                        deref_node.name = "*" + field.name;
                        deref_node.type_name = pointee_rec->name;
                        deref_node.address = ptr_val;
                        deref_node.relative_offset = 0;
                        deref_node.size = pointee_rec->size;
                        deref_node.virtual_address = ptr_val;
                        deref_node.window_offset = ctx.source.to_window_offset(ptr_val, false);
                        deref_node.raw_bytes_hex = format_raw_hex(probe);
                        populate_record_children(
                            ctx, *pointee_rec, ptr_val, false, depth + 1, ptr_depth + 1, deref_node);
                        ctx.inline_type_stack.swap(saved_inline_stack);
                        field.children = std::move(deref_node.children);
                        ctx.visited_pointers.erase(visit_key);
                    }
                }
            }
        }
        return field;
    }

    // 2. Fixed-size array `T[N]`
    if (parsed.kind == ParsedTypeExpr::Kind::Array) {
        std::uint64_t elem_sz = compute_type_size(ctx.catalog, parsed.inner_type, layout);
        if (elem_sz == 0 && parsed.array_count > 0 && declared_size >= parsed.array_count) {
            elem_sz = declared_size / parsed.array_count;
        }
        field.size = declared_size != 0 ? declared_size : (elem_sz * parsed.array_count);
        field.is_aggregate = true;

        const std::size_t preview_bytes =
            static_cast<std::size_t>(std::min<std::uint64_t>(field.size, 256u));
        const peelf::MemorySample sample =
            ctx.source.read_bytes(address, is_file_offset, preview_bytes);
        field.raw_bytes_hex = format_raw_hex(sample);
        field.availability = sample_availability(sample);

        const std::string inner_canon = ascii_lower(canonical_type_key(parsed.inner_type));
        if (inner_canon == "char") {
            if (field.availability == peelf::Availability::Unavailable && field.size > 0) {
                field.decoded_value = "<unreadable>";
            } else {
                field.string_preview = escape_ascii_preview(sample.bytes, sample.valid, true, 64);
                field.decoded_value = field.string_preview;
            }
        } else if (inner_canon == "wchar_t" || inner_canon == "char16_t" || inner_canon == "wchar") {
            if (field.availability == peelf::Availability::Unavailable && field.size > 0) {
                field.decoded_value = "<unreadable>";
            } else {
                field.string_preview = decode_utf16_preview(
                    sample.bytes, sample.valid, layout.endianness, true, 64);
                field.decoded_value = field.string_preview;
            }
        }

        if (depth < ctx.options.max_depth && elem_sz > 0 && parsed.array_count > 0) {
            const std::size_t cap = static_cast<std::size_t>(
                std::min<std::uint64_t>(parsed.array_count, ctx.options.max_array_elements));
            field.children.reserve(cap);
            for (std::size_t idx = 0; idx < cap; ++idx) {
                const std::uint64_t elem_off = static_cast<std::uint64_t>(idx) * elem_sz;
                EvaluatedField elem = evaluate_field_impl(
                    ctx,
                    std::format("[{}]", idx),
                    parsed.inner_type,
                    address + elem_off,
                    relative_offset + elem_off,
                    elem_sz,
                    is_file_offset,
                    depth + 1,
                    ptr_depth);
                field.availability = merge_availability(field.availability, elem.availability);
                field.children.push_back(std::move(elem));
            }
        }

        if (field.decoded_value.empty()) {
            if (field.availability == peelf::Availability::Unavailable && field.size > 0) {
                field.decoded_value = "<unreadable>";
            } else {
                std::string arr_summary = "[";
                const std::size_t show_n = std::min<std::size_t>(field.children.size(), 4u);
                for (std::size_t i = 0; i < show_n; ++i) {
                    if (i > 0) arr_summary += ", ";
                    arr_summary += field.children[i].decoded_value;
                }
                if (parsed.array_count > show_n) {
                    if (show_n > 0) arr_summary += ", ";
                    arr_summary += std::format("... ({} items)", parsed.array_count);
                }
                arr_summary += "]";
                field.decoded_value = std::move(arr_summary);
            }
        }
        return field;
    }

    // 3. Known nested struct / union in catalog
    if (const DataTypeRecord* nested_rec = ctx.catalog.find(parsed.base_name)) {
        field.size = declared_size != 0 ? declared_size : nested_rec->size;
        const std::size_t preview_sz =
            static_cast<std::size_t>(std::min<std::uint64_t>(field.size, 16u));
        const peelf::MemorySample sample =
            ctx.source.read_bytes(address, is_file_offset, preview_sz);
        field.raw_bytes_hex = format_raw_hex(sample);
        populate_record_children(ctx, *nested_rec, address, is_file_offset, depth, ptr_depth, field);
        return field;
    }

    // 4. Scalar primitive
    const ScalarInfo scalar = classify_scalar(parsed.base_name, layout, declared_size);
    if (scalar.kind != ScalarKind::None) {
        field.size = scalar.byte_size;
        const peelf::MemorySample sample =
            ctx.source.read_bytes(address, is_file_offset, static_cast<std::size_t>(field.size));
        field.raw_bytes_hex = format_raw_hex(sample);
        field.availability = sample_availability(sample);
        if (field.availability != peelf::Availability::Available) {
            field.decoded_value = "<unreadable>";
            return field;
        }

        const peelf::EndianReader reader(sample.bytes, layout);
        switch (scalar.kind) {
            case ScalarKind::Bool: {
                const std::uint8_t v = *reader.read_u8(0);
                field.decoded_value =
                    v == 0 ? "false (0)" : (v == 1 ? "true (1)" : std::format("true (0x{:02X})", v));
                break;
            }
            case ScalarKind::Char: {
                const std::uint8_t v = *reader.read_u8(0);
                if (v >= 0x20 && v < 0x7F) {
                    field.decoded_value = std::format("'{}' (0x{:02X})", static_cast<char>(v), v);
                } else {
                    field.decoded_value = std::format("0x{:02X} ({})", v, static_cast<std::int8_t>(v));
                }
                break;
            }
            case ScalarKind::WChar16: {
                const std::uint16_t v = *reader.read_u16(0);
                if (v >= 0x20 && v < 0x7F) {
                    field.decoded_value = std::format("L'{}' (0x{:04X})", static_cast<char>(v), v);
                } else {
                    field.decoded_value = std::format("0x{:04X}", v);
                }
                break;
            }
            case ScalarKind::WChar32: {
                const std::uint32_t v = *reader.read_u32(0);
                field.decoded_value = std::format("U+{:04X}", v);
                break;
            }
            case ScalarKind::Int8: {
                const std::int8_t v = *reader.read_i8(0);
                field.decoded_value = std::format("{} (0x{:02X})", v, static_cast<std::uint8_t>(v));
                break;
            }
            case ScalarKind::UInt8: {
                const std::uint8_t v = *reader.read_u8(0);
                field.decoded_value = std::format("0x{:02X} ({})", v, v);
                break;
            }
            case ScalarKind::Int16: {
                const std::int16_t v = *reader.read_i16(0);
                field.decoded_value = std::format("{} (0x{:04X})", v, static_cast<std::uint16_t>(v));
                break;
            }
            case ScalarKind::UInt16: {
                const std::uint16_t v = *reader.read_u16(0);
                const std::uint8_t lo = sample.bytes[0];
                const std::uint8_t hi = sample.bytes[1];
                if (lo >= 0x20 && lo < 0x7F && hi >= 0x20 && hi < 0x7F) {
                    field.decoded_value = std::format(
                        "0x{:04X} ({}) \"{}{}\"", v, v, static_cast<char>(lo), static_cast<char>(hi));
                } else {
                    field.decoded_value = std::format("0x{:04X} ({})", v, v);
                }
                break;
            }
            case ScalarKind::Int32: {
                const std::int32_t v = *reader.read_i32(0);
                field.decoded_value = std::format("{} (0x{:08X})", v, static_cast<std::uint32_t>(v));
                break;
            }
            case ScalarKind::UInt32: {
                const std::uint32_t v = *reader.read_u32(0);
                field.decoded_value = std::format("0x{:08X} ({})", v, v);
                break;
            }
            case ScalarKind::Int64: {
                const std::int64_t v = *reader.read_i64(0);
                field.decoded_value = std::format("{} (0x{:016X})", v, static_cast<std::uint64_t>(v));
                break;
            }
            case ScalarKind::UInt64: {
                const std::uint64_t v = *reader.read_u64(0);
                field.decoded_value = std::format("0x{:016X} ({})", v, v);
                break;
            }
            case ScalarKind::IntPtr: {
                if (field.size == 8) {
                    const std::int64_t v = *reader.read_i64(0);
                    field.decoded_value = std::format("{} (0x{:016X})", v, static_cast<std::uint64_t>(v));
                } else {
                    const std::int32_t v = *reader.read_i32(0);
                    field.decoded_value = std::format("{} (0x{:08X})", v, static_cast<std::uint32_t>(v));
                }
                break;
            }
            case ScalarKind::UIntPtr: {
                if (field.size == 8) {
                    const std::uint64_t v = *reader.read_u64(0);
                    field.decoded_value = std::format("0x{:016X} ({})", v, v);
                } else {
                    const std::uint32_t v = *reader.read_u32(0);
                    field.decoded_value = std::format("0x{:08X} ({})", v, v);
                }
                break;
            }
            case ScalarKind::Float32: {
                const float v = *reader.read_f32(0);
                field.decoded_value = std::format("{:.6g}", v);
                break;
            }
            case ScalarKind::Float64: {
                const double v = *reader.read_f64(0);
                field.decoded_value = std::format("{:.12g}", v);
                break;
            }
            case ScalarKind::None:
                break;
        }
        return field;
    }

    // 5. Fallback opaque / enum / unknown fixed-size field
    field.size = declared_size;
    const std::size_t read_sz =
        static_cast<std::size_t>(std::min<std::uint64_t>(field.size, 64u));
    const peelf::MemorySample sample = ctx.source.read_bytes(address, is_file_offset, read_sz);
    field.raw_bytes_hex = format_raw_hex(sample);
    field.availability = sample_availability(sample);
    if (field.size == 0) {
        field.decoded_value = "<zero-sized>";
    } else if (field.availability != peelf::Availability::Available) {
        field.decoded_value = "<unreadable>";
    } else {
        const peelf::EndianReader reader(sample.bytes, layout);
        if (field.size == 1) {
            field.decoded_value = std::format("0x{:02X}", *reader.read_u8(0));
        } else if (field.size == 2) {
            field.decoded_value = std::format("0x{:04X}", *reader.read_u16(0));
        } else if (field.size == 4) {
            field.decoded_value = std::format("0x{:08X}", *reader.read_u32(0));
        } else if (field.size == 8) {
            field.decoded_value = std::format("0x{:016X}", *reader.read_u64(0));
        } else {
            field.decoded_value = field.raw_bytes_hex;
        }
    }
    return field;
}

} // namespace

peelf::Result<EvaluatedStructure> evaluate_structure(const StructureCatalog& catalog,
                                                     std::string_view type_name,
                                                     std::uint64_t address,
                                                     bool is_file_offset,
                                                     const IStructureByteSource& source,
                                                     const StructureEvalOptions& options) {
    const CatalogTypeEntry* entry = catalog.find_entry(type_name);
    if (entry == nullptr) {
        return peelf::make_error(std::format("Unknown structure type '{}'", type_name));
    }

    const DataTypeRecord& rec = entry->record;
    const std::uint32_t clamped_count = std::clamp<std::uint32_t>(options.count, 1u, 256u);

    EvaluatedStructure result;
    result.type_name = rec.name;
    result.origin = entry->origin;
    result.base_address = address;
    result.is_file_offset = is_file_offset;
    result.count = clamped_count;
    result.stride = rec.size;
    result.total_size = rec.size * static_cast<std::uint64_t>(clamped_count);
    result.layout = options.layout;

    EvalContext ctx{
        .catalog = catalog,
        .source = source,
        .options = options,
    };

    if (clamped_count == 1) {
        if (const auto root_va = source.to_virtual_address(address, is_file_offset)) {
            ctx.visited_pointers.emplace(*root_va, rec.name);
        }
        EvaluatedField root;
        root.name = rec.name;
        root.type_name = rec.name;
        root.address = address;
        root.relative_offset = 0;
        root.size = rec.size;
        populate_record_children(ctx, rec, address, is_file_offset, 0, 0, root);
        result.availability = root.availability;
        result.fields = std::move(root.children);
        return result;
    }

    result.fields.reserve(clamped_count);
    bool any_avail = false;
    bool any_unavail = false;
    for (std::uint32_t idx = 0; idx < clamped_count; ++idx) {
        const std::uint64_t elem_off = static_cast<std::uint64_t>(idx) * rec.size;
        const std::uint64_t elem_addr = address + elem_off;
        EvaluatedField elem;
        elem.name = std::format("[{}]", idx);
        elem.type_name = rec.name;
        elem.address = elem_addr;
        elem.relative_offset = elem_off;
        elem.size = rec.size;
        elem.virtual_address = source.to_virtual_address(elem_addr, is_file_offset);
        elem.window_offset = source.to_window_offset(elem_addr, is_file_offset);
        const std::size_t preview_sz = static_cast<std::size_t>(std::min<std::uint64_t>(rec.size, 16u));
        elem.raw_bytes_hex = format_raw_hex(source.read_bytes(elem_addr, is_file_offset, preview_sz));
        populate_record_children(ctx, rec, elem_addr, is_file_offset, 0, 0, elem);
        if (elem.availability == peelf::Availability::Available) {
            any_avail = true;
        } else if (elem.availability == peelf::Availability::Unavailable) {
            any_unavail = true;
        } else {
            any_avail = true;
            any_unavail = true;
        }
        result.fields.push_back(std::move(elem));
    }

    if (any_avail && any_unavail) {
        result.availability = peelf::Availability::Partial;
    } else if (any_unavail && !any_avail) {
        result.availability = peelf::Availability::Unavailable;
    } else {
        result.availability = peelf::Availability::Available;
    }
    return result;
}

} // namespace viewer
