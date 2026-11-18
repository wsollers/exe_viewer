#include "analysis/structure_interpreter.hpp"

#include "model/binary_model.hpp"
#include "peelf/binary_image.hpp"
#include "peelf/process.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef PEELF_BIN_MATRIX_DIR
#define PEELF_BIN_MATRIX_DIR "bin-matrix"
#endif

namespace {

using namespace viewer;

class MockSparseProcessSession final : public peelf::IProcessSession {
public:
    struct MappedPage {
        peelf::MemoryRegion region{};
        std::vector<std::uint8_t> bytes{};
    };

    explicit MockSparseProcessSession(peelf::Architecture arch,
                                      peelf::Endianness endian = peelf::Endianness::Little,
                                      bool is_64 = true) {
        info_.pid = 9001;
        info_.name = "mock_target";
        info_.architecture = arch;
        info_.endianness = endian;
        info_.is_64bit = is_64;
        info_.access = peelf::ProcessAccessStatus::ReadOnly;
    }

    void map_bytes(std::uint64_t start_va,
                   std::vector<std::uint8_t> data,
                   std::string pathname = "[anon]",
                   peelf::MemoryRegionKind kind = peelf::MemoryRegionKind::Anonymous) {
        peelf::MemoryRegion r{};
        r.start_address = start_va;
        r.end_address = start_va + data.size();
        r.protection = peelf::MemoryProtection{
            .readable = true,
            .writable = true,
            .executable = false,
            .shared = false,
            .guarded = false,
        };
        r.kind = kind;
        r.pathname = std::move(pathname);
        pages_.push_back(MappedPage{.region = std::move(r), .bytes = std::move(data)});
    }

    void map_guard_page(std::uint64_t start_va, std::uint64_t size) {
        peelf::MemoryRegion r{};
        r.start_address = start_va;
        r.end_address = start_va + size;
        r.protection = peelf::MemoryProtection{
            .readable = false,
            .writable = false,
            .executable = false,
            .shared = false,
            .guarded = true,
        };
        r.kind = peelf::MemoryRegionKind::Anonymous;
        r.pathname = "[guard]";
        pages_.push_back(MappedPage{.region = std::move(r), .bytes = {}});
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        std::vector<peelf::MemoryRegion> out;
        out.reserve(pages_.size());
        for (const auto& p : pages_) {
            out.push_back(p.region);
        }
        return out;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t address,
                                                         std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        std::size_t copied = 0;
        for (std::size_t i = 0; i < buffer.size(); ++i) {
            const std::uint64_t va = address + i;
            bool ok = false;
            for (const auto& p : pages_) {
                if (p.region.protection.readable && !p.region.protection.guarded &&
                    va >= p.region.start_address && va < p.region.end_address) {
                    const std::size_t off = static_cast<std::size_t>(va - p.region.start_address);
                    if (off < p.bytes.size()) {
                        buffer[i] = p.bytes[off];
                        ok = true;
                    }
                    break;
                }
            }
            if (!ok) {
                break;
            }
            ++copied;
        }
        if (copied == 0) {
            return peelf::make_error("unreadable page");
        }
        return copied;
    }

    [[nodiscard]] peelf::TargetLayout target_layout() const noexcept override {
        return peelf::TargetLayout{
            .architecture = info_.architecture,
            .address_width = info_.is_64bit ? peelf::AddressWidth::Bits64 : peelf::AddressWidth::Bits32,
            .endianness = info_.endianness,
        };
    }

private:
    peelf::ProcessInfo info_{};
    std::vector<MappedPage> pages_{};
};

[[nodiscard]] const EvaluatedField* find_field(std::span<const EvaluatedField> fields,
                                               std::string_view name) {
    for (const auto& f : fields) {
        if (f.name == name) {
            return &f;
        }
    }
    return nullptr;
}

} // namespace

TEST(StructureInterpreterTest, BuiltinSchemaCatalogCoversPeElfWin32AndLinuxRuntimeLayouts) {
    const StructureCatalog catalog = StructureCatalog::build({}, {}, true);
    EXPECT_GE(catalog.entries().size(), 24u);

    constexpr std::array<std::string_view, 22> expected_names = {
        "IMAGE_DOS_HEADER",
        "IMAGE_FILE_HEADER",
        "IMAGE_OPTIONAL_HEADER32",
        "IMAGE_OPTIONAL_HEADER64",
        "IMAGE_SECTION_HEADER",
        "IMAGE_IMPORT_DESCRIPTOR",
        "IMAGE_TLS_DIRECTORY32",
        "IMAGE_TLS_DIRECTORY64",
        "PEB32",
        "PEB64",
        "TEB32",
        "TEB64",
        "RTL_USER_PROCESS_PARAMETERS64",
        "Elf32_Ehdr",
        "Elf64_Ehdr",
        "Elf32_Phdr",
        "Elf64_Phdr",
        "Elf32_Shdr",
        "Elf64_Shdr",
        "Elf32_Dyn",
        "Elf64_Dyn",
        "r_debug64",
    };

    for (const std::string_view name : expected_names) {
        const CatalogTypeEntry* entry = catalog.find_entry(name);
        ASSERT_NE(entry, nullptr) << "Missing built-in schema: " << name;
        EXPECT_TRUE(entry->is_builtin()) << name;
        EXPECT_GT(entry->record.size, 0u) << name;
        EXPECT_FALSE(entry->record.members.empty()) << name;
    }
    EXPECT_NE(catalog.find_entry("r_debug32"), nullptr);
    EXPECT_NE(catalog.find_entry("link_map32"), nullptr);
    EXPECT_NE(catalog.find_entry("link_map64"), nullptr);

    // Loaded debug types take precedence over built-in schemas of the same name.
    DataTypeRecord custom_dos{};
    custom_dos.name = "IMAGE_DOS_HEADER";
    custom_dos.size = 4;
    custom_dos.members.push_back(DataMember{.name = "custom_magic", .type = "uint32_t", .offset = 0, .size = 4});

    const StructureCatalog merged = StructureCatalog::build(std::span{&custom_dos, 1}, {}, true);
    const CatalogTypeEntry* found = merged.find_entry("IMAGE_DOS_HEADER");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->origin, StructureSchemaOrigin::UserOrDebug);
    EXPECT_EQ(found->record.size, 4u);
}

TEST(StructureInterpreterTest, EvaluatesScalarsBigAndLittleEndianAnd32Vs64BitPointers) {
    DataTypeRecord packet{};
    packet.name = "TelemetryPacket";
    packet.size = 32;
    packet.members = {
        {.name = "magic", .type = "uint32_t", .offset = 0, .size = 4},
        {.name = "delta", .type = "int16_t", .offset = 4, .size = 2},
        {.name = "active", .type = "bool", .offset = 6, .size = 1},
        {.name = "tag", .type = "char", .offset = 7, .size = 1},
        {.name = "ratio", .type = "float", .offset = 8, .size = 4},
        {.name = "cookie", .type = "uintptr_t", .offset = 12, .size = 0},
    };

    const StructureCatalog catalog = StructureCatalog::build(std::span{&packet, 1}, {}, false);

    // Big-Endian 32-bit buffer at VA 0x1000
    std::vector<std::uint8_t> be_buf(32, 0u);
    be_buf[0] = 0xDE; be_buf[1] = 0xAD; be_buf[2] = 0xBE; be_buf[3] = 0xEF; // magic = 0xDEADBEEF
    be_buf[4] = 0xFF; be_buf[5] = 0xD6;                                     // delta = -42
    be_buf[6] = 0x01;                                                       // active = true
    be_buf[7] = 'Z';                                                        // tag = 'Z'
    be_buf[8] = 0x40; be_buf[9] = 0x20; be_buf[10] = 0x00; be_buf[11] = 0x00; // ratio = 2.5f (IEEE-754 BE)
    be_buf[12] = 0x12; be_buf[13] = 0x34; be_buf[14] = 0x56; be_buf[15] = 0x78; // 32-bit uintptr_t

    SpanStructureByteSource be_src(be_buf, 0x1000);
    StructureEvalOptions be_opts{
        .layout = peelf::TargetLayout{
            .architecture = peelf::Architecture::MIPS32,
            .address_width = peelf::AddressWidth::Bits32,
            .endianness = peelf::Endianness::Big,
        },
        .count = 1,
    };

    const auto be_eval = evaluate_structure(catalog, "TelemetryPacket", 0x1000, false, be_src, be_opts);
    ASSERT_TRUE(be_eval.has_value()) << be_eval.error().message;
    EXPECT_EQ(be_eval->availability, peelf::Availability::Available);

    const auto* f_magic = find_field(be_eval->fields, "magic");
    ASSERT_NE(f_magic, nullptr);
    EXPECT_NE(f_magic->decoded_value.find("0xDEADBEEF"), std::string::npos);

    const auto* f_delta = find_field(be_eval->fields, "delta");
    ASSERT_NE(f_delta, nullptr);
    EXPECT_NE(f_delta->decoded_value.find("-42"), std::string::npos);

    const auto* f_active = find_field(be_eval->fields, "active");
    ASSERT_NE(f_active, nullptr);
    EXPECT_NE(f_active->decoded_value.find("true"), std::string::npos);

    const auto* f_tag = find_field(be_eval->fields, "tag");
    ASSERT_NE(f_tag, nullptr);
    EXPECT_NE(f_tag->decoded_value.find("'Z'"), std::string::npos);

    const auto* f_ratio = find_field(be_eval->fields, "ratio");
    ASSERT_NE(f_ratio, nullptr);
    EXPECT_NE(f_ratio->decoded_value.find("2.5"), std::string::npos);

    const auto* f_cookie = find_field(be_eval->fields, "cookie");
    ASSERT_NE(f_cookie, nullptr);
    EXPECT_EQ(f_cookie->size, 4u);
    EXPECT_NE(f_cookie->decoded_value.find("0x12345678"), std::string::npos);
}

TEST(StructureInterpreterTest, EvaluatesNestedStructsUnionsFixedArraysAndCyclicPointers) {
    DataTypeRecord inner_union{};
    inner_union.name = "ValueUnion";
    inner_union.is_union = true;
    inner_union.size = 4;
    inner_union.members = {
        {.name = "as_u32", .type = "uint32_t", .offset = 0, .size = 4},
        {.name = "bytes", .type = "uint8_t[4]", .offset = 0, .size = 4},
    };

    DataTypeRecord node{};
    node.name = "ListNode";
    node.size = 24;
    node.members = {
        {.name = "next", .type = "ListNode*", .offset = 0, .size = 8},
        {.name = "name", .type = "const char*", .offset = 8, .size = 8},
        {.name = "wide_tag", .type = "const wchar_t*", .offset = 16, .size = 8},
        {.name = "payload", .type = "ValueUnion", .offset = 20, .size = 4},
    };
    node.size = 28;

    const std::array<DataTypeRecord, 2> defs = {inner_union, node};
    const StructureCatalog catalog = StructureCatalog::build(defs, {}, false);

    // Memory at VA 0x400000:
    // +0x00: ListNode #0 (next -> 0x400020 Node #1, name -> 0x400040 "alpha_node", wide -> 0x400050 L"OK", payload = 0x11223344)
    // +0x20: ListNode #1 (next -> 0x400000 Node #0 circular cycle!, payload = 0x55667788)
    std::vector<std::uint8_t> mem(0x80, 0u);
    const auto write_u64_le = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t b = 0; b < 8; ++b) {
            mem[off + b] = static_cast<std::uint8_t>((v >> (b * 8)) & 0xFFu);
        }
    };
    write_u64_le(0, 0x400020ULL);  // Node #0 -> Node #1
    write_u64_le(8, 0x400040ULL);  // C-string pointer
    write_u64_le(16, 0x400050ULL); // UTF-16LE string pointer
    mem[24] = 0x44; mem[25] = 0x33; mem[26] = 0x22; mem[27] = 0x11;

    write_u64_le(0x20, 0x400000ULL); // Node #1 -> Node #0 (2-node cycle!)
    mem[0x20 + 24] = 0x88; mem[0x20 + 25] = 0x77; mem[0x20 + 26] = 0x66; mem[0x20 + 27] = 0x55;
    // Align payload offset to 24 cleanly:
    DataTypeRecord clean_node = node;
    clean_node.size = 28;
    clean_node.members[3].offset = 24;
    const std::array<DataTypeRecord, 2> clean_defs = {inner_union, clean_node};
    const StructureCatalog clean_cat = StructureCatalog::build(clean_defs, {}, false);

    const char* cstr = "alpha_node";
    std::memcpy(mem.data() + 0x40, cstr, std::strlen(cstr) + 1);
    // UTF-16LE "OK" at +0x50
    mem[0x50] = 'O'; mem[0x51] = 0; mem[0x52] = 'K'; mem[0x53] = 0; mem[0x54] = 0; mem[0x55] = 0;

    SpanStructureByteSource src(
        mem,
        0x400000ULL,
        {},
        [](std::uint64_t va) -> std::string {
            if (va == 0x400000ULL) {
                return "g_head_node";
            }
            if (va == 0x400020ULL) {
                return "g_second_node";
            }
            return {};
        });

    StructureEvalOptions opts{
        .layout = peelf::TargetLayout{
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .endianness = peelf::Endianness::Little,
        },
        .count = 1,
        .max_depth = 6,
        .max_pointer_deref_depth = 3,
        .dereference_struct_pointers = true,
    };

    const auto eval = evaluate_structure(clean_cat, "ListNode", 0x400000ULL, false, src, opts);
    ASSERT_TRUE(eval.has_value()) << eval.error().message;

    const auto* f_next = find_field(eval->fields, "next");
    ASSERT_NE(f_next, nullptr);
    EXPECT_TRUE(f_next->is_pointer);
    ASSERT_TRUE(f_next->pointer_target_va.has_value());
    EXPECT_EQ(*f_next->pointer_target_va, 0x400020ULL);
    EXPECT_EQ(f_next->pointee_type_name, "ListNode");
    EXPECT_NE(f_next->decoded_value.find("g_second_node"), std::string::npos);
    // Node #0 -> Node #1 expands cleanly, and Node #1 -> Node #0 cycle guard terminates!
    ASSERT_FALSE(f_next->children.empty());
    const auto* f_next_next = find_field(f_next->children, "next");
    ASSERT_NE(f_next_next, nullptr);
    EXPECT_TRUE(f_next_next->children.empty());

    const auto* f_name = find_field(eval->fields, "name");
    ASSERT_NE(f_name, nullptr);
    EXPECT_TRUE(f_name->is_pointer);
    EXPECT_NE(f_name->decoded_value.find("\"alpha_node\""), std::string::npos);

    const auto* f_wide = find_field(eval->fields, "wide_tag");
    ASSERT_NE(f_wide, nullptr);
    EXPECT_TRUE(f_wide->is_pointer);
    EXPECT_NE(f_wide->decoded_value.find("L\"OK\""), std::string::npos);

    const auto* f_payload = find_field(eval->fields, "payload");
    ASSERT_NE(f_payload, nullptr);
    ASSERT_EQ(f_payload->children.size(), 2u);
    const auto* u_val = find_field(f_payload->children, "as_u32");
    ASSERT_NE(u_val, nullptr);
    EXPECT_NE(u_val->decoded_value.find("0x11223344"), std::string::npos);
    const auto* u_bytes = find_field(f_payload->children, "bytes");
    ASSERT_NE(u_bytes, nullptr);
    EXPECT_EQ(u_bytes->children.size(), 4u);
}

TEST(StructureInterpreterTest, HandlesPartialAndUnreadableLivePagesGracefully) {
    MockSparseProcessSession session(peelf::Architecture::X86_64, peelf::Endianness::Little, true);
    // Map only 16 bytes at 0x7FFF0000, followed by an unreadable guard page at 0x7FFF0010!
    std::vector<std::uint8_t> header_slice(16, 0u);
    header_slice[0] = 0x7F;
    header_slice[1] = 'E';
    header_slice[2] = 'L';
    header_slice[3] = 'F';
    header_slice[4] = 2; // 64-bit
    header_slice[5] = 1; // little-endian
    header_slice[6] = 1; // EV_CURRENT
    session.map_bytes(0x7FFF0000ULL, header_slice, "/lib/partial.so", peelf::MemoryRegionKind::Image);
    session.map_guard_page(0x7FFF0010ULL, 0x1000);

    const StructureCatalog catalog = StructureCatalog::build({}, {}, true);
    LiveProcessStructureByteSource live_src(session);
    StructureEvalOptions opts{.layout = session.target_layout(), .count = 1};

    // Reading Elf64_Ehdr (64 bytes) across the 16-byte boundary must succeed with Partial availability:
    // e_ident[16] is Available, while e_type..e_shstrndx are <unreadable>!
    const auto partial_eval =
        evaluate_structure(catalog, "Elf64_Ehdr", 0x7FFF0000ULL, false, live_src, opts);
    ASSERT_TRUE(partial_eval.has_value()) << partial_eval.error().message;
    EXPECT_EQ(partial_eval->availability, peelf::Availability::Partial);

    const auto* f_ident = find_field(partial_eval->fields, "e_ident");
    ASSERT_NE(f_ident, nullptr);
    EXPECT_EQ(f_ident->availability, peelf::Availability::Available);

    const auto* f_entry = find_field(partial_eval->fields, "e_entry");
    ASSERT_NE(f_entry, nullptr);
    EXPECT_EQ(f_entry->availability, peelf::Availability::Unavailable);
    EXPECT_EQ(f_entry->decoded_value, "<unreadable>");

    // Reading entirely inside the guard page yields Unavailable without throwing or failing Result.
    const auto unavail_eval =
        evaluate_structure(catalog, "Elf64_Ehdr", 0x7FFF0020ULL, false, live_src, opts);
    ASSERT_TRUE(unavail_eval.has_value());
    EXPECT_EQ(unavail_eval->availability, peelf::Availability::Unavailable);
}

TEST(StructureInterpreterTest, DecodesRealBinMatrixElfAndPeHeadersAndPersistsModelBindings) {
    const std::filesystem::path amd64_bin =
        std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "elf-linux-x86_64-64-le-callgraph.elf";
    const std::filesystem::path mips_be_bin =
        std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "elf-linux-mips-32-be-callgraph.elf";
    const std::filesystem::path pe64_dll =
        std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "pe-windows-x86_64-64-le-callgraph.dll";

    BinaryModel model;
    ASSERT_TRUE(model.load_file(amd64_bin.string()));

    const StructureCatalog catalog = StructureCatalog::build(model.debug_types(), {}, true);
    BinaryModelStructureByteSource src(model);
    StructureEvalOptions opts{.layout = model.target_layout(), .count = 1};

    const auto ehdr64 = evaluate_structure(catalog, "Elf64_Ehdr", 0, true, src, opts);
    ASSERT_TRUE(ehdr64.has_value()) << ehdr64.error().message;
    EXPECT_EQ(ehdr64->availability, peelf::Availability::Available);
    const auto* e_machine64 = find_field(ehdr64->fields, "e_machine");
    ASSERT_NE(e_machine64, nullptr);
    EXPECT_NE(e_machine64->decoded_value.find("62"), std::string::npos); // EM_X86_64 = 62

    // Persist bindings on BinaryModel and verify deduplication + removal
    model.add_applied_structure(AppliedStructureBinding{
        .address = 0,
        .is_file_offset = true,
        .type_name = "Elf64_Ehdr",
        .count = 1,
        .label = "ELF Header",
    });
    model.add_applied_structure(AppliedStructureBinding{
        .address = 64,
        .is_file_offset = true,
        .type_name = "Elf64_Phdr",
        .count = 4,
        .label = "Program Headers",
    });
    // Updating existing binding at (0, true, "Elf64_Ehdr") deduplicates in place
    model.add_applied_structure(AppliedStructureBinding{
        .address = 0,
        .is_file_offset = true,
        .type_name = "Elf64_Ehdr",
        .count = 1,
        .label = "Main ELF Header",
    });
    ASSERT_EQ(model.applied_structures().size(), 2u);
    EXPECT_EQ(model.applied_structures()[0].label, "Main ELF Header");
    model.remove_applied_structure(0);
    ASSERT_EQ(model.applied_structures().size(), 1u);
    EXPECT_EQ(model.applied_structures()[0].type_name, "Elf64_Phdr");

    // Load Big-Endian 32-bit MIPS binary: bindings reset on new file, and Elf32_Ehdr decodes BE!
    ASSERT_TRUE(model.load_file(mips_be_bin.string()));
    EXPECT_TRUE(model.applied_structures().empty());
    EXPECT_EQ(model.target_layout().endianness, peelf::Endianness::Big);
    EXPECT_EQ(model.target_layout().address_width, peelf::AddressWidth::Bits32);

    BinaryModelStructureByteSource mips_src(model);
    StructureEvalOptions mips_opts{.layout = model.target_layout(), .count = 1};
    const auto ehdr32 = evaluate_structure(catalog, "Elf32_Ehdr", 0, true, mips_src, mips_opts);
    ASSERT_TRUE(ehdr32.has_value()) << ehdr32.error().message;
    const auto* e_machine32 = find_field(ehdr32->fields, "e_machine");
    ASSERT_NE(e_machine32, nullptr);
    EXPECT_NE(e_machine32->decoded_value.find("8"), std::string::npos); // EM_MIPS = 8

    // Load PE64 DLL and decode IMAGE_DOS_HEADER (e_magic = 0x5A4D "MZ")
    ASSERT_TRUE(model.load_file(pe64_dll.string()));
    BinaryModelStructureByteSource pe_src(model);
    StructureEvalOptions pe_opts{.layout = model.target_layout(), .count = 1};
    const auto dos = evaluate_structure(catalog, "IMAGE_DOS_HEADER", 0, true, pe_src, pe_opts);
    ASSERT_TRUE(dos.has_value()) << dos.error().message;
    const auto* e_magic = find_field(dos->fields, "e_magic");
    ASSERT_NE(e_magic, nullptr);
    EXPECT_NE(e_magic->decoded_value.find("0x5A4D"), std::string::npos);
}

TEST(StructureInterpreterTest, RejectsOverflowingArrayCountsAndGuardsNearUint64MaxAddresses) {
    DataTypeRecord ovf_2pow64{};
    ovf_2pow64.name = "OverflowArray2Pow64";
    ovf_2pow64.size = 0;
    ovf_2pow64.members = {
        {.name = "header", .type = "uint32_t", .offset = 0, .size = 4},
        {.name = "huge", .type = "uint32_t[18446744073709551616]", .offset = 4, .size = 0},
    };

    DataTypeRecord ovf_byte_mul{};
    ovf_byte_mul.name = "OverflowArrayByteMul";
    ovf_byte_mul.size = 0;
    ovf_byte_mul.members = {
        {.name = "items", .type = "uint64_t[4611686018427387904]", .offset = 0, .size = 0},
    };

    DataTypeRecord huge_stride{};
    huge_stride.name = "HugeStrideStruct";
    huge_stride.size = (std::uint64_t{1} << 60u) + 8ULL;
    huge_stride.members = {
        {.name = "first", .type = "uint64_t", .offset = 0, .size = 8},
    };

    DataTypeRecord pair_u64{};
    pair_u64.name = "PairU64";
    pair_u64.size = 16;
    pair_u64.members = {
        {.name = "first", .type = "uint64_t", .offset = 0, .size = 8},
        {.name = "second", .type = "uint64_t", .offset = 8, .size = 8},
    };

    DataTypeRecord wide_preview{};
    wide_preview.name = "WidePreviewSample";
    wide_preview.size = 12;
    wide_preview.members = {
        {.name = "text", .type = "wchar_t[6]", .offset = 0, .size = 12},
    };

    const std::array<DataTypeRecord, 5> user_types{{
        ovf_2pow64,
        ovf_byte_mul,
        huge_stride,
        pair_u64,
        wide_preview,
    }};
    const StructureCatalog catalog = StructureCatalog::build(user_types, {}, false);

    std::array<std::uint8_t, 64> backing{};
    backing[0] = 0x78u;
    backing[1] = 0x56u;
    backing[2] = 0x34u;
    backing[3] = 0x12u;
    SpanStructureByteSource span_src(backing, /*base_va=*/0ULL);
    StructureEvalOptions opts{};
    opts.layout = peelf::TargetLayout{
        .architecture = peelf::Architecture::X86_64,
        .address_width = peelf::AddressWidth::Bits64,
        .endianness = peelf::Endianness::Little,
    };

    // 1. Array count >= 2^64 must NOT wrap mod 2^64 to 0!
    const auto ovf_count =
        evaluate_structure(catalog, "OverflowArray2Pow64", 0, true, span_src, opts);
    EXPECT_FALSE(ovf_count.has_value());

    // 2. Array element_size * count overflowing uint64_t (8 * 2^62 == 2^65) must be rejected!
    const auto ovf_mul =
        evaluate_structure(catalog, "OverflowArrayByteMul", 0, true, span_src, opts);
    EXPECT_FALSE(ovf_mul.has_value());

    // 3. Top-level `stride * opts.count` multiplication overflow ((2^60 + 8) * 32) must be rejected!
    StructureEvalOptions huge_count_opts = opts;
    huge_count_opts.count = 32u;
    const auto ovf_top_count =
        evaluate_structure(catalog, "HugeStrideStruct", 0, true, span_src, huge_count_opts);
    EXPECT_FALSE(ovf_top_count.has_value());

    // 4. `base_address` near UINT64_MAX (`0xFFFFFFFFFFFFFFF8`):
    //    `first` ([FFF8..FFFF], 8 bytes) fits in uint64_t;
    //    `second` (offset +8 -> wraps to 0x0 if unchecked!) MUST be marked Unavailable and
    //    must NEVER wrap around to read low address 0x0!
    class HighBoundaryByteSource final : public IStructureByteSource {
    public:
        [[nodiscard]] peelf::MemorySample read_bytes(
            std::uint64_t address,
            bool /*is_file_offset*/,
            std::size_t size) const override {
            peelf::MemorySample out;
            out.bytes.assign(size, 0u);
            out.valid.assign(size, 0u);
            for (std::size_t i = 0; i < size; ++i) {
                if (i > std::numeric_limits<std::uint64_t>::max() - address) {
                    break;
                }
                const std::uint64_t cur = address + i;
                if (cur >= 0xFFFF'FFFF'FFFF'FFF8ULL) {
                    out.bytes[i] = 0xAAu;
                    out.valid[i] = 1u;
                    ++out.readable_count;
                } else if (cur < 16ULL) {
                    // Trap bytes at low VA 0x0..0xF to catch any uint64 wraparound!
                    out.bytes[i] = 0xFEu;
                    out.valid[i] = 1u;
                    ++out.readable_count;
                }
            }
            return out;
        }
    };

    HighBoundaryByteSource high_src;
    const auto near_max = evaluate_structure(
        catalog, "PairU64", 0xFFFF'FFFF'FFFF'FFF8ULL, false, high_src, opts);
    ASSERT_TRUE(near_max.has_value()) << near_max.error().message;
    const auto* first_f = find_field(near_max->fields, "first");
    const auto* second_f = find_field(near_max->fields, "second");
    ASSERT_NE(first_f, nullptr);
    ASSERT_NE(second_f, nullptr);
    EXPECT_EQ(first_f->availability, peelf::Availability::Available);
    EXPECT_NE(first_f->decoded_value.find("0xAAAAAAAAAAAAAAAA"), std::string::npos);
    EXPECT_EQ(second_f->availability, peelf::Availability::Unavailable);
    EXPECT_EQ(second_f->decoded_value.find("0xFEFE"), std::string::npos);

    // Also verify SpanStructureByteSource rejects overflowing base+size near UINT64_MAX.
    SpanStructureByteSource high_span_src(backing, 0xFFFF'FFFF'FFFF'FFF8ULL);
    const auto span_near_max = evaluate_structure(
        catalog, "PairU64", 0xFFFF'FFFF'FFFF'FFF8ULL, false, high_span_src, opts);
    ASSERT_TRUE(span_near_max.has_value());
    const auto* span_second = find_field(span_near_max->fields, "second");
    ASSERT_NE(span_second, nullptr);
    EXPECT_EQ(span_second->availability, peelf::Availability::Unavailable);

    // 5. UTF-16 `wchar_t[]` preview decodes valid surrogate pair U+1F680 and replaces lone surrogate with U+FFFD.
    std::vector<std::uint8_t> wide_bytes;
    for (const std::uint16_t cu : {std::uint16_t{0xD83Du},
                                   std::uint16_t{0xDE80u}, // U+1F680 🚀
                                   std::uint16_t{0xD83Du}, // lone high surrogate -> U+FFFD
                                   std::uint16_t{'!'},
                                   std::uint16_t{0u},
                                   std::uint16_t{0u}}) {
        wide_bytes.push_back(static_cast<std::uint8_t>(cu & 0xFFu));
        wide_bytes.push_back(static_cast<std::uint8_t>((cu >> 8u) & 0xFFu));
    }
    SpanStructureByteSource wide_src(wide_bytes, 0ULL);
    const auto wide_res =
        evaluate_structure(catalog, "WidePreviewSample", 0, true, wide_src, opts);
    ASSERT_TRUE(wide_res.has_value()) << wide_res.error().message;
    const auto* text_field = find_field(wide_res->fields, "text");
    ASSERT_NE(text_field, nullptr);
    EXPECT_EQ(text_field->string_preview, "L\"\xF0\x9F\x9A\x80\xEF\xBF\xBD!\"");
}

TEST(StructureInterpreterTest, PeSectionVaAvoidsDoubleImageBaseClampsBssZeroFillAndBoundsArrayCount) {
    // Construct a minimal valid PE32+ (x64) image with:
    //   ImageBase = 0x140000000
    //   Section 0 (".data"): VirtualAddress = 0x2000 (VA = 0x140002000),
    //                        VirtualSize = 16, SizeOfRawData = 8, PointerToRawData = 0x200
    std::vector<std::uint8_t> pe_bytes(0x208u, 0u);
    const auto w16 = [&](std::size_t off, std::uint16_t v) {
        pe_bytes[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
        pe_bytes[off + 1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    };
    const auto w32 = [&](std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0; i < 4u; ++i) {
            pe_bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };
    const auto w64 = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0; i < 8u; ++i) {
            pe_bytes[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };

    // DOS header + PE signature at 0x80
    w16(0x00, 0x5A4Du);
    w32(0x3C, 0x80u);
    pe_bytes[0x80] = 'P';
    pe_bytes[0x81] = 'E';

    // COFF File Header at 0x84 (20 bytes)
    w16(0x84, 0x8664u); // IMAGE_FILE_MACHINE_AMD64
    w16(0x86, 1u);      // NumberOfSections = 1
    w16(0x94, 0xF0u);   // SizeOfOptionalHeader = 240
    w16(0x96, 0x0022u); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // OptionalHeader64 at 0x98 (240 bytes -> ends at 0x188)
    constexpr std::uint64_t kImageBase = 0x140000000ULL;
    constexpr std::uint64_t kDataSectionVa = kImageBase + 0x2000ULL;
    w16(0x98 + 0x00, 0x020Bu); // PE32+
    w32(0x98 + 0x10, 0x2000u); // AddressOfEntryPoint
    w64(0x98 + 0x18, kImageBase);
    w32(0x98 + 0x20, 0x1000u); // SectionAlignment
    w32(0x98 + 0x24, 0x200u);  // FileAlignment
    w16(0x98 + 0x30, 6u);      // MajorSubsystemVersion
    w32(0x98 + 0x38, 0x3000u); // SizeOfImage
    w32(0x98 + 0x3C, 0x200u);  // SizeOfHeaders
    w16(0x98 + 0x44, 3u);      // IMAGE_SUBSYSTEM_WINDOWS_CUI
    w32(0x98 + 0x6C, 16u);     // NumberOfRvaAndSizes

    // Section Header[0] ".data" at 0x188 (40 bytes)
    std::memcpy(pe_bytes.data() + 0x188, ".data", 5u);
    w32(0x188 + 0x08, 16u);         // VirtualSize = 16 (8 file-backed + 8 BSS zero-fill)
    w32(0x188 + 0x0C, 0x2000u);     // VirtualAddress (RVA)
    w32(0x188 + 0x10, 8u);          // SizeOfRawData = 8
    w32(0x188 + 0x14, 0x200u);      // PointerToRawData = 0x200
    w32(0x188 + 0x24, 0xC0000040u); // INITIALIZED_DATA | READ | WRITE

    // Store a pointer to `.data + 4` (`0x140002004`) in the 8 file-backed bytes at file offset 0x200.
    w64(0x200, kDataSectionVa + 4ULL);

    const auto parsed_pe = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(parsed_pe.has_value()) << parsed_pe.error().message;
    ASSERT_EQ((*parsed_pe)->sections().size(), 1u);
    EXPECT_EQ((*parsed_pe)->sections()[0].virtual_address, kDataSectionVa);

    DataTypeRecord pe_probe{};
    pe_probe.name = "PeBssProbe";
    pe_probe.size = 20;
    pe_probe.members = {
        {.name = "ptr", .type = "void*", .offset = 0, .size = 8},
        {.name = "bss_tail", .type = "uint64_t", .offset = 8, .size = 8},
        {.name = "past_virtual_size", .type = "uint32_t", .offset = 16, .size = 4},
    };

    DataTypeRecord capped_arr{};
    capped_arr.name = "DeclaredSizeCappedArray";
    capped_arr.size = 12;
    capped_arr.members = {
        // Declared member byte_size = 12 must clamp uint32_t[100] (stride 4) to 3 elements!
        {.name = "items", .type = "uint32_t[100]", .offset = 0, .size = 12},
    };

    const std::array<DataTypeRecord, 2> defs{{pe_probe, capped_arr}};
    const StructureCatalog catalog = StructureCatalog::build(defs, {}, false);
    StructureEvalOptions opts{
        .layout = peelf::TargetLayout{
            .architecture = peelf::Architecture::X86_64,
            .address_width = peelf::AddressWidth::Bits64,
            .endianness = peelf::Endianness::Little,
        },
        .count = 1,
    };

    // 1. StaticImageStructureByteSource reads PE section VA without double-adding ImageBase,
    //    resolves pointer target ".data+0x4", zero-fills [file_size, virtual_size), and leaves >= virtual_size unreadable.
    StaticImageStructureByteSource static_src(**parsed_pe, pe_bytes);
    EXPECT_EQ(static_src.describe_pointer(kDataSectionVa + 4ULL), ".data+0x4");

    const auto static_eval = evaluate_structure(catalog, "PeBssProbe", kDataSectionVa, false, static_src, opts);
    ASSERT_TRUE(static_eval.has_value()) << static_eval.error().message;
    const auto* f_ptr = find_field(static_eval->fields, "ptr");
    const auto* f_bss = find_field(static_eval->fields, "bss_tail");
    const auto* f_past = find_field(static_eval->fields, "past_virtual_size");
    ASSERT_NE(f_ptr, nullptr);
    ASSERT_NE(f_bss, nullptr);
    ASSERT_NE(f_past, nullptr);
    EXPECT_EQ(f_ptr->availability, peelf::Availability::Available);
    EXPECT_EQ(f_ptr->pointer_target_va, std::optional<std::uint64_t>{kDataSectionVa + 4ULL});
    EXPECT_NE(f_ptr->decoded_value.find(".data+0x4"), std::string::npos);
    EXPECT_EQ(f_bss->availability, peelf::Availability::Available);
    EXPECT_EQ(f_bss->decoded_value, "0x0000000000000000 (0)");
    EXPECT_EQ(f_past->availability, peelf::Availability::Unavailable);
    EXPECT_EQ(f_past->decoded_value, "<unreadable>");

    // 2. Truncated file-backed bytes (< file_size) must NOT be falsely zero-filled as BSS.
    const std::vector<std::uint8_t> truncated_pe(pe_bytes.begin(), pe_bytes.begin() + 0x204);
    StaticImageStructureByteSource trunc_src(**parsed_pe, truncated_pe);
    const peelf::MemorySample trunc_sample = trunc_src.read_bytes(kDataSectionVa, false, 16u);
    ASSERT_EQ(trunc_sample.valid.size(), 16u);
    // [0..4) present in file, [4..8) missing file-backed bytes (invalid!), [8..16) BSS zero-fill (valid!).
    EXPECT_EQ(trunc_sample.valid[0], 1u);
    EXPECT_EQ(trunc_sample.valid[3], 1u);
    EXPECT_EQ(trunc_sample.valid[4], 0u);
    EXPECT_EQ(trunc_sample.valid[7], 0u);
    EXPECT_EQ(trunc_sample.valid[8], 1u);
    EXPECT_EQ(trunc_sample.valid[15], 1u);

    // 3. BinaryModelStructureByteSource also resolves PE pointer descriptions without double ImageBase
    //    and clamps oversized array element_count against declared field byte_size.
    const std::filesystem::path tmp_pe =
        std::filesystem::temp_directory_path() / "peelf-fbf05a-synth-pe64.exe";
    {
        std::ofstream out(tmp_pe, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.is_open());
        out.write(reinterpret_cast<const char*>(pe_bytes.data()),
                  static_cast<std::streamsize>(pe_bytes.size()));
    }
    BinaryModel pe_model;
    ASSERT_TRUE(pe_model.load_file(tmp_pe.string()));
    BinaryModelStructureByteSource model_src(pe_model);
    EXPECT_EQ(model_src.describe_pointer(kDataSectionVa + 4ULL), ".data+0x4");

    const auto arr_eval =
        evaluate_structure(catalog, "DeclaredSizeCappedArray", kDataSectionVa, false, model_src, opts);
    ASSERT_TRUE(arr_eval.has_value()) << arr_eval.error().message;
    const auto* f_items = find_field(arr_eval->fields, "items");
    ASSERT_NE(f_items, nullptr);
    EXPECT_EQ(f_items->children.size(), 3u);

    std::error_code ec;
    std::filesystem::remove(tmp_pe, ec);
}


