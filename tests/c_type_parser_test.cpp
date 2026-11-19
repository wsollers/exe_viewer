#include "analysis/c_type_parser.hpp"
#include "analysis/project.hpp"
#include "analysis/structure_interpreter.hpp"
#include "model/binary_model.hpp"
#include "ui/command_palette.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace viewer;

class InMemoryStructureBytes final : public IStructureByteSource {
public:
    explicit InMemoryStructureBytes(std::uint64_t base_va = 0x10000000ULL)
        : base_va_(base_va) {}

    void map_va(std::uint64_t va, std::vector<std::uint8_t> data) {
        va_blocks_[va] = std::move(data);
    }

    void set_file_bytes(std::vector<std::uint8_t> data) {
        file_bytes_ = std::move(data);
    }

    [[nodiscard]] peelf::MemorySample read_bytes(std::uint64_t address,
                                                 bool is_file_offset,
                                                 std::size_t size) const override {
        peelf::MemorySample sample{};
        sample.bytes.assign(size, 0u);
        sample.valid.assign(size, 0u);
        if (size == 0) {
            return sample;
        }
        if (is_file_offset) {
            for (std::size_t i = 0; i < size; ++i) {
                const std::uint64_t off = address + i;
                if (off >= file_bytes_.size()) {
                    break;
                }
                sample.bytes[i] = file_bytes_[static_cast<std::size_t>(off)];
                sample.valid[i] = 1u;
                ++sample.readable_count;
            }
            return sample;
        }

        for (std::size_t i = 0; i < size; ++i) {
            const std::uint64_t va = address + i;
            for (const auto& [block_va, block] : va_blocks_) {
                if (va >= block_va && va < block_va + block.size()) {
                    sample.bytes[i] = block[static_cast<std::size_t>(va - block_va)];
                    sample.valid[i] = 1u;
                    ++sample.readable_count;
                    break;
                }
            }
        }
        return sample;
    }

    [[nodiscard]] std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept override {
        if (!is_file_offset) {
            return address;
        }
        if (address < file_bytes_.size()) {
            return base_va_ + address;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> to_window_offset(
        std::uint64_t address,
        bool is_file_offset) const noexcept override {
        if (is_file_offset) {
            return address;
        }
        return std::nullopt;
    }

private:
    std::uint64_t base_va_ = 0;
    std::vector<std::uint8_t> file_bytes_;
    std::map<std::uint64_t, std::vector<std::uint8_t>> va_blocks_;
};

const DataTypeRecord* find_record(std::span<const DataTypeRecord> records, std::string_view name) {
    for (const DataTypeRecord& r : records) {
        if (r.name == name) {
            return &r;
        }
        for (const std::string& alias : r.aliases) {
            if (alias == name) {
                return &r;
            }
        }
    }
    return nullptr;
}

const DataMember* find_member(const DataTypeRecord& rec, std::string_view name) {
    for (const DataMember& m : rec.members) {
        if (m.name == name) {
            return &m;
        }
    }
    return nullptr;
}

void write_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

void write_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
}

} // namespace

TEST(CTypeParser,Abi32Vs64PointerFunctionPointerAndLongModels) {
    constexpr std::string_view kSrc = R"c(
        struct AbiProbe {
            uint8_t tag;
            void* ptr;
            unsigned long sys_word;
            int (*callback)(const void*, size_t);
            uintptr_t tail_uptr;
            uint8_t trailing;
        };
    )c";

    // 64-bit Windows LLP64 (8-byte pointers, 4-byte long)
    const CTypeParseResult win64 = parse_c_types(kSrc, CTypeParseOptions{
        .layout = {.address_width = peelf::AddressWidth::Bits64, .endianness = peelf::Endianness::Little},
        .long_model = CLongModel::LLP64,
    });
    ASSERT_TRUE(win64.ok());
    const DataTypeRecord* r_win64 = find_record(win64.types, "AbiProbe");
    ASSERT_NE(r_win64, nullptr);
    EXPECT_EQ(find_member(*r_win64, "tag")->offset, 0u);
    EXPECT_EQ(find_member(*r_win64, "ptr")->offset, 8u);
    EXPECT_EQ(find_member(*r_win64, "ptr")->size, 8u);
    EXPECT_EQ(find_member(*r_win64, "sys_word")->offset, 16u);
    EXPECT_EQ(find_member(*r_win64, "sys_word")->size, 4u);
    EXPECT_EQ(find_member(*r_win64, "callback")->offset, 24u);
    EXPECT_EQ(find_member(*r_win64, "callback")->size, 8u);
    EXPECT_EQ(find_member(*r_win64, "tail_uptr")->offset, 32u);
    EXPECT_EQ(find_member(*r_win64, "trailing")->offset, 40u);
    EXPECT_EQ(r_win64->size, 48u);

    // 64-bit System V LP64 (8-byte pointers, 8-byte long)
    const CTypeParseResult lp64 = parse_c_types(kSrc, CTypeParseOptions{
        .layout = {.address_width = peelf::AddressWidth::Bits64, .endianness = peelf::Endianness::Little},
        .long_model = CLongModel::LP64,
    });
    ASSERT_TRUE(lp64.ok());
    const DataTypeRecord* r_lp64 = find_record(lp64.types, "AbiProbe");
    ASSERT_NE(r_lp64, nullptr);
    EXPECT_EQ(find_member(*r_lp64, "sys_word")->size, 8u);
    EXPECT_EQ(find_member(*r_lp64, "callback")->offset, 24u);
    EXPECT_EQ(r_lp64->size, 48u);

    // 32-bit ILP32 (4-byte pointers, 4-byte long)
    const CTypeParseResult x86 = parse_c_types(kSrc, CTypeParseOptions{
        .layout = {.address_width = peelf::AddressWidth::Bits32, .endianness = peelf::Endianness::Little},
        .long_model = CLongModel::LLP64,
    });
    ASSERT_TRUE(x86.ok());
    const DataTypeRecord* r_x86 = find_record(x86.types, "AbiProbe");
    ASSERT_NE(r_x86, nullptr);
    EXPECT_EQ(find_member(*r_x86, "ptr")->offset, 4u);
    EXPECT_EQ(find_member(*r_x86, "ptr")->size, 4u);
    EXPECT_EQ(find_member(*r_x86, "sys_word")->offset, 8u);
    EXPECT_EQ(find_member(*r_x86, "callback")->offset, 12u);
    EXPECT_EQ(find_member(*r_x86, "callback")->size, 4u);
    EXPECT_EQ(find_member(*r_x86, "tail_uptr")->offset, 16u);
    EXPECT_EQ(find_member(*r_x86, "trailing")->offset, 20u);
    EXPECT_EQ(r_x86->size, 24u);
}

TEST(CTypeParser, PragmaPackPushPopAndAlignmentAttributes) {
    constexpr std::string_view kSrc = R"c(
        #pragma pack(push, 1)
        struct PackedWireHeader {
            uint8_t  magic;
            uint32_t seq;
            uint64_t timestamp;
        };
        #pragma pack(pop)

        struct NaturalHeader {
            uint8_t  magic;
            uint32_t seq;
            uint64_t timestamp;
        };

        struct __attribute__((packed)) AttrPacked {
            uint8_t  a;
            uint64_t b;
        };

        struct __declspec(align(32)) CacheAligned {
            uint32_t x;
        };

        struct FieldAligned {
            uint8_t a;
            alignas(16) uint32_t vec_lane;
        };
    )c";

    const CTypeParseResult res = parse_c_types(kSrc);
    ASSERT_TRUE(res.ok());

    const DataTypeRecord* packed = find_record(res.types, "PackedWireHeader");
    ASSERT_NE(packed, nullptr);
    EXPECT_EQ(packed->size, 13u);
    EXPECT_EQ(find_member(*packed, "seq")->offset, 1u);
    EXPECT_EQ(find_member(*packed, "timestamp")->offset, 5u);

    const DataTypeRecord* natural = find_record(res.types, "NaturalHeader");
    ASSERT_NE(natural, nullptr);
    EXPECT_EQ(natural->size, 16u);
    EXPECT_EQ(find_member(*natural, "seq")->offset, 4u);
    EXPECT_EQ(find_member(*natural, "timestamp")->offset, 8u);

    const DataTypeRecord* attr_packed = find_record(res.types, "AttrPacked");
    ASSERT_NE(attr_packed, nullptr);
    EXPECT_EQ(attr_packed->size, 9u);
    EXPECT_EQ(find_member(*attr_packed, "b")->offset, 1u);

    const DataTypeRecord* cache_aligned = find_record(res.types, "CacheAligned");
    ASSERT_NE(cache_aligned, nullptr);
    EXPECT_EQ(cache_aligned->size, 32u);

    const DataTypeRecord* field_aligned = find_record(res.types, "FieldAligned");
    ASSERT_NE(field_aligned, nullptr);
    EXPECT_EQ(find_member(*field_aligned, "vec_lane")->offset, 16u);
    EXPECT_EQ(field_aligned->size, 32u);
}

TEST(CTypeParser, AnonymousStructsUnionsMultiDeclaratorsArraysAndBitfields) {
    constexpr std::string_view kSrc = R"c(
        typedef struct ComplexPacket {
            uint16_t magic;
            uint16_t flags_a : 4, flags_b : 5, flags_c : 7;
            union {
                struct {
                    uint32_t ipv4_src, ipv4_dst;
                };
                uint64_t combined_id;
            };
            uint8_t matrix[2][3];
            DWORD win_count, *win_ptr;
            WCHAR short_name[4];
        } ComplexPacket_t, *PComplexPacket;
    )c";

    const CTypeParseResult res = parse_c_types(kSrc);
    ASSERT_TRUE(res.ok());

    const DataTypeRecord* pkt = find_record(res.types, "ComplexPacket_t");
    ASSERT_NE(pkt, nullptr);
    EXPECT_EQ(pkt->name, "ComplexPacket");
    ASSERT_FALSE(pkt->aliases.empty());
    EXPECT_EQ(pkt->aliases.front(), "ComplexPacket_t");

    // Bitfields coalesced into a single 2-byte uint16_t storage unit at offset 2
    const DataMember* fa = find_member(*pkt, "flags_a");
    const DataMember* fb = find_member(*pkt, "flags_b");
    const DataMember* fc = find_member(*pkt, "flags_c");
    ASSERT_NE(fa, nullptr);
    ASSERT_NE(fb, nullptr);
    ASSERT_NE(fc, nullptr);
    EXPECT_EQ(fa->offset, 2u);
    EXPECT_EQ(fa->bit_offset, 0u);
    EXPECT_EQ(fa->bit_width, 4u);
    EXPECT_EQ(fb->offset, 2u);
    EXPECT_EQ(fb->bit_offset, 4u);
    EXPECT_EQ(fb->bit_width, 5u);
    EXPECT_EQ(fc->offset, 2u);
    EXPECT_EQ(fc->bit_offset, 9u);
    EXPECT_EQ(fc->bit_width, 7u);

    // Anonymous union aligned to 8 bytes at offset 8
    EXPECT_EQ(find_member(*pkt, "ipv4_src")->offset, 8u);
    EXPECT_EQ(find_member(*pkt, "ipv4_dst")->offset, 12u);
    EXPECT_EQ(find_member(*pkt, "combined_id")->offset, 8u);

    // 2x3 matrix = 6 bytes at offset 16 (row-major 2 rows x 3 cols)
    const DataMember* mat = find_member(*pkt, "matrix");
    ASSERT_NE(mat, nullptr);
    EXPECT_EQ(mat->offset, 16u);
    EXPECT_EQ(mat->size, 6u);
    EXPECT_EQ(mat->type, "uint8_t[2][3]");

    // Evaluate bitfields against live bytes!
    const StructureCatalog catalog = StructureCatalog::build_with_custom(res.types, {}, {}, false);
    ASSERT_NE(catalog.find("ComplexPacket"), nullptr);
    ASSERT_NE(catalog.find("ComplexPacket_t"), nullptr);

    std::vector<std::uint8_t> bytes(pkt->size, 0);
    write_u16_le(bytes, 0, 0xCAFEu);
    // flags_a = 0xA (4b), flags_b = 0x15 (5b -> 21), flags_c = 0x42 (7b -> 66)
    const std::uint16_t packed_bits =
        static_cast<std::uint16_t>(0xAu | (0x15u << 4u) | (0x42u << 9u));
    write_u16_le(bytes, 2, packed_bits);
    write_u32_le(bytes, 8, 0x01020304u);
    write_u32_le(bytes, 12, 0x05060708u);

    InMemoryStructureBytes src;
    src.set_file_bytes(std::move(bytes));

    const auto eval = evaluate_structure(catalog, "ComplexPacket", 0, true, src, StructureEvalOptions{});
    ASSERT_TRUE(eval.has_value()) << eval.error().message;
    EXPECT_EQ(eval->origin, StructureSchemaOrigin::CustomUserC);

    auto find_eval_field = [&](std::string_view fname) -> const EvaluatedField* {
        for (const EvaluatedField& f : eval->fields) {
            if (f.name == fname) {
                return &f;
            }
        }
        return nullptr;
    };

    const EvaluatedField* ef_a = find_eval_field("flags_a");
    const EvaluatedField* ef_b = find_eval_field("flags_b");
    const EvaluatedField* ef_c = find_eval_field("flags_c");
    ASSERT_NE(ef_a, nullptr);
    ASSERT_NE(ef_b, nullptr);
    ASSERT_NE(ef_c, nullptr);
    EXPECT_NE(ef_a->decoded_value.find("(10)"), std::string::npos);
    EXPECT_NE(ef_b->decoded_value.find("(21)"), std::string::npos);
    EXPECT_NE(ef_c->decoded_value.find("(66)"), std::string::npos);
}

TEST(CTypeParser, EnumConstantExpressionsAndSymbolicStructureEvaluation) {
    constexpr std::string_view kSrc = R"c(
        #define BASE_PORT 0x100
        enum ConnState : uint16_t {
            STATE_IDLE   = 0,
            STATE_INIT   = 1,
            STATE_ACTIVE = 2,
            STATE_CLOSED = 0xFF
        };

        typedef enum PacketFlags : uint32_t {
            PKT_NONE = 0,
            PKT_SYN  = (1 << 0),
            PKT_ACK  = (1 << 4),
            PKT_URG  = (1 << 5)
        } PacketFlags;

        struct NetHeader {
            uint16_t    port;
            ConnState   state;
            PacketFlags flags;
            uint8_t     pad[sizeof(PacketFlags) + (BASE_PORT >> 6)];
        };
    )c";

    const CTypeParseResult res = parse_c_types(kSrc);
    ASSERT_TRUE(res.ok());

    const DataTypeRecord* hdr = find_record(res.types, "NetHeader");
    ASSERT_NE(hdr, nullptr);
    // sizeof(PacketFlags) == 4, (0x100 >> 6) == 4 -> pad[8], total size = 2 + 2 + 4 + 8 = 16
    EXPECT_EQ(hdr->size, 16u);

    const StructureCatalog catalog = StructureCatalog::build_with_custom(res.types, {}, {}, false);
    std::vector<std::uint8_t> bytes(16, 0);
    write_u16_le(bytes, 0, 443u);
    write_u16_le(bytes, 2, 2u);           // STATE_ACTIVE
    write_u32_le(bytes, 4, 0x10u | 0x2u); // PKT_ACK | 0x2

    InMemoryStructureBytes src;
    src.set_file_bytes(std::move(bytes));

    const auto eval = evaluate_structure(catalog, "NetHeader", 0, true, src, StructureEvalOptions{});
    ASSERT_TRUE(eval.has_value()) << eval.error().message;
    ASSERT_GE(eval->fields.size(), 3u);

    // Exact enum match: `2 (STATE_ACTIVE)`
    EXPECT_EQ(eval->fields[1].name, "state");
    EXPECT_NE(eval->fields[1].decoded_value.find("STATE_ACTIVE"), std::string::npos);

    // Bitwise flag decomposition + residual hex: `0x00000012 (PKT_ACK | 0x2)`
    EXPECT_EQ(eval->fields[2].name, "flags");
    EXPECT_NE(eval->fields[2].decoded_value.find("PKT_ACK | 0x2"), std::string::npos);

    // Direct root enum evaluation at offset 2
    const auto root_enum = evaluate_structure(catalog, "ConnState", 2, true, src, StructureEvalOptions{});
    ASSERT_TRUE(root_enum.has_value()) << root_enum.error().message;
    ASSERT_EQ(root_enum->fields.size(), 1u);
    EXPECT_NE(root_enum->fields[0].decoded_value.find("STATE_ACTIVE"), std::string::npos);
}

TEST(CTypeParser, SelfReferentialLinkedListEvaluatesPointerChain) {
    constexpr std::string_view kSrc = R"c(
        typedef struct ListNode ListNode;
        struct ListNode {
            ListNode* next;
            PVOID     payload;
            uint32_t  node_id;
            uint32_t  reserved;
        };
    )c";

    const CTypeParseResult res = parse_c_types(kSrc);
    ASSERT_TRUE(res.ok());

    const StructureCatalog catalog = StructureCatalog::build_with_custom(res.types, {}, {}, false);
    InMemoryStructureBytes mem;

    std::vector<std::uint8_t> node1(24, 0);
    write_u64_le(node1, 0, 0x20002000ULL);
    write_u64_le(node1, 8, 0xCAFEBABEULL);
    write_u32_le(node1, 16, 101u);

    std::vector<std::uint8_t> node2(24, 0);
    write_u64_le(node2, 0, 0ULL);
    write_u64_le(node2, 8, 0xDEADBEEFULL);
    write_u32_le(node2, 16, 202u);

    mem.map_va(0x20001000ULL, std::move(node1));
    mem.map_va(0x20002000ULL, std::move(node2));

    StructureEvalOptions opts{};
    opts.layout = {.address_width = peelf::AddressWidth::Bits64, .endianness = peelf::Endianness::Little};
    opts.dereference_struct_pointers = true;
    opts.max_pointer_deref_depth = 2;

    const auto eval = evaluate_structure(catalog, "ListNode", 0x20001000ULL, false, mem, opts);
    ASSERT_TRUE(eval.has_value()) << eval.error().message;
    ASSERT_EQ(eval->fields.size(), 4u);
    EXPECT_TRUE(eval->fields[0].is_pointer);
    EXPECT_EQ(eval->fields[0].pointer_target_va, std::optional<std::uint64_t>(0x20002000ULL));
    ASSERT_EQ(eval->fields[0].children.size(), 4u);
    EXPECT_NE(eval->fields[0].children[2].decoded_value.find("(202)"), std::string::npos);
}

TEST(CTypeParser, ProjectPersistenceAndCommandPaletteRoundTrip) {
    BinaryModel model;
    const auto fixture_path =
        (std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / "known-win-x64.exe").string();
    ASSERT_TRUE(model.load_file(fixture_path));

    const std::uint64_t rev_before = model.structure_binding_revision();
    constexpr std::string_view kCustomSrc = R"c(
        /* Custom IPC frame */
        enum IpcOpcode : uint16_t {
            IPC_PING = 1,
            IPC_EXEC = 2
        };
        #pragma pack(push, 1)
        typedef struct IpcFrame {
            uint32_t  magic;
            IpcOpcode opcode;
            ULONG_PTR token;
        } IpcFrame_t;
        #pragma pack(pop)
    )c";

    const CTypeParseResult compiled =
        model.compile_and_set_custom_c_types(std::string(kCustomSrc), CTypeAbiMode::AutoTarget);
    ASSERT_TRUE(compiled.ok());
    EXPECT_GT(model.structure_binding_revision(), rev_before);
    ASSERT_EQ(model.custom_types().size(), 2u);

    model.add_applied_structure(AppliedStructureBinding{
        .address = 0,
        .is_file_offset = true,
        .type_name = "IpcFrame_t",
        .count = 1,
        .label = "dos_as_ipc",
    });

    // Verify CommandPalette indexes custom C types under `struct:` / `type:` (both tag & alias)
    CommandPalette palette;
    const PaletteDataSources pal_src = make_palette_data_sources(model);
    const PaletteQueryResult qres = palette.query("struct:IpcFrame_t", pal_src);
    ASSERT_FALSE(qres.items.empty());
    EXPECT_EQ(qres.items.front().title, "IpcFrame");
    EXPECT_NE(qres.items.front().subtitle.find("Custom C"), std::string::npos);

    const PaletteQueryResult eqres = palette.query("type:IpcOpcode", pal_src);
    ASSERT_FALSE(eqres.items.empty());
    EXPECT_EQ(eqres.items.front().title, "IpcOpcode");
    EXPECT_NE(eqres.items.front().subtitle.find("enum"), std::string::npos);

    // Encode & decode .peproj v2 with custom C types + structure bindings
    const AnalysisProject proj = build_analysis_project(model);
    const std::string encoded = encode_project(proj);
    EXPECT_NE(encoded.find("CUSTOM_C_TYPES 1"), std::string::npos);

    const auto decoded = decode_project(encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().message;
    EXPECT_EQ(decoded->custom_c_types_source, std::string(kCustomSrc));
    EXPECT_EQ(decoded->custom_c_types_abi, static_cast<std::uint32_t>(CTypeAbiMode::AutoTarget));
    ASSERT_EQ(decoded->custom_types.size(), 2u);
    ASSERT_EQ(decoded->structure_bindings.size(), 1u);
    EXPECT_EQ(decoded->structure_bindings[0].type_name, "IpcFrame_t");

    // Verify .peproj v2 WITHOUT custom C types produces no CUSTOM_C_TYPES block and loads cleanly
    model.clear_custom_c_types();
    EXPECT_TRUE(model.custom_types().empty());
    const AnalysisProject clean_proj = build_analysis_project(model);
    const std::string clean_encoded = encode_project(clean_proj);
    EXPECT_EQ(clean_encoded.find("CUSTOM_C_TYPES"), std::string::npos);
    const auto clean_decoded = decode_project(clean_encoded);
    ASSERT_TRUE(clean_decoded.has_value()) << clean_decoded.error().message;
    EXPECT_TRUE(clean_decoded->custom_types.empty());

    // Malformed trailing extension in .peproj v2 must be rejected cleanly
    EXPECT_FALSE(decode_project(clean_encoded + "CUSTOM_C_TYPES 99 0 \"\" 0\n").has_value());

    // Loading a new binary clears custom C types
    model.set_custom_c_types(std::string(kCustomSrc), decoded->custom_types);
    ASSERT_FALSE(model.custom_types().empty());
    ASSERT_TRUE(model.load_file(fixture_path));
    EXPECT_TRUE(model.custom_types().empty());
}

TEST(CTypeParser, HostileAndMalformedInputsProduceActionableLineColDiagnostics) {
    // 1. Unclosed block comment reports exact opening line/col
    {
        const CTypeParseResult res = parse_c_types("struct Ok { int x; };\n   /* unclosed comment\nint y;");
        EXPECT_FALSE(res.ok());
        ASSERT_FALSE(res.diagnostics.empty());
        EXPECT_EQ(res.diagnostics.front().line, 2u);
        EXPECT_EQ(res.diagnostics.front().column, 4u);
    }

    // 2. Direct & mutual cyclic by-value struct containment rejected cleanly
    {
        const CTypeParseResult direct = parse_c_types("struct Self { struct Self s; };");
        EXPECT_FALSE(direct.ok());
        ASSERT_FALSE(direct.diagnostics.empty());
    }
    {
        constexpr std::string_view kMutual = R"c(
            struct B;
            struct A { struct B b; };
            struct B { struct A a; };
        )c";
        const CTypeParseResult mutual = parse_c_types(kMutual);
        EXPECT_FALSE(mutual.ok());
        ASSERT_FALSE(mutual.diagnostics.empty());
    }

    // 3. Checked 64-bit arithmetic: division by zero, shift out of range, signed multiply overflow
    {
        const CTypeParseResult div0 = parse_c_types("enum BadDiv { A = 100 / 0 };");
        EXPECT_FALSE(div0.ok());
        ASSERT_FALSE(div0.diagnostics.empty());
    }
    {
        const CTypeParseResult mod0 = parse_c_types("enum BadMod { A = 100 % (4 - 4) };");
        EXPECT_FALSE(mod0.ok());
    }
    {
        const CTypeParseResult shift_oob = parse_c_types("enum BadShift { A = 1 << 64 };");
        EXPECT_FALSE(shift_oob.ok());
    }
    {
        const CTypeParseResult shift_neg = parse_c_types("enum BadShiftNeg { A = 1 >> -3 };");
        EXPECT_FALSE(shift_neg.ok());
    }
    {
        const CTypeParseResult mul_ovf =
            parse_c_types("enum BadMul { A = 0x4000000000000000LL * 4 };");
        EXPECT_FALSE(mul_ovf.ok());
    }

    // 4. Zero or negative array bounds rejected
    {
        const CTypeParseResult zero_arr = parse_c_types("struct BadArr { uint8_t data[0]; };");
        EXPECT_FALSE(zero_arr.ok());
    }
    {
        const CTypeParseResult neg_arr = parse_c_types("struct NegArr { uint8_t data[-8]; };");
        EXPECT_FALSE(neg_arr.ok());
    }

    // 5. Excessive nesting depth exceeding kMaxTypeNestingDepth rejected without stack overflow
    {
        std::string deep;
        for (std::size_t i = 0; i < kMaxTypeNestingDepth + 6u; ++i) {
            deep += "struct { ";
        }
        deep += "uint32_t leaf; ";
        for (std::size_t i = 0; i < kMaxTypeNestingDepth + 6u; ++i) {
            deep += "} f" + std::to_string(i) + "; ";
        }
        const CTypeParseResult deep_res = parse_c_types("struct Root { " + deep + "};");
        EXPECT_FALSE(deep_res.ok());
        ASSERT_FALSE(deep_res.diagnostics.empty());
    }
}
