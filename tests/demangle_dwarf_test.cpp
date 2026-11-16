#include "peelf/binary_image.hpp"
#include "peelf/demangle.hpp"
#include "peelf/dwarf.hpp"
#include "peelf/process.hpp"

#include "analysis/function_index.hpp"
#include "model/binary_model.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef PEELF_BIN_MATRIX_DIR
#define PEELF_BIN_MATRIX_DIR "bin-matrix"
#endif

namespace {

[[nodiscard]] std::filesystem::path bin_matrix_path(std::string_view name) {
    return std::filesystem::path(PEELF_BIN_MATRIX_DIR) / name;
}

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in.good()) << path.string();
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void append_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

void append_u16_be(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void append_u32_be(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void append_u64_be(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buf.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFFu));
    }
}

void append_cstr(std::vector<std::uint8_t>& buf, std::string_view s) {
    buf.insert(buf.end(), s.begin(), s.end());
    buf.push_back(0);
}

class FakeAslrProcessBackend final : public peelf::IProcessBackend {
public:
    class Session final : public peelf::IProcessSession {
    public:
        Session(peelf::ProcessInfo info,
                std::vector<peelf::MemoryRegion> regions,
                std::vector<peelf::ModuleInfo> modules,
                std::uint64_t base_va,
                std::vector<std::uint8_t> mapped_ram)
            : info_(std::move(info))
            , regions_(std::move(regions))
            , modules_(std::move(modules))
            , base_va_(base_va)
            , mapped_ram_(std::move(mapped_ram)) {}

        [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
        [[nodiscard]] bool is_alive() const noexcept override { return true; }

        [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
            return regions_;
        }

        [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
            return modules_;
        }

        [[nodiscard]] peelf::Result<std::size_t> read_memory(
            std::uint64_t address, std::span<std::uint8_t> buffer) override {
            if (address < base_va_ || address >= base_va_ + mapped_ram_.size()) {
                return peelf::make_error("unmapped address");
            }
            const std::size_t rel = static_cast<std::size_t>(address - base_va_);
            const std::size_t avail = std::min(buffer.size(), mapped_ram_.size() - rel);
            std::copy_n(mapped_ram_.data() + rel, avail, buffer.data());
            return avail;
        }

    private:
        peelf::ProcessInfo info_;
        std::vector<peelf::MemoryRegion> regions_;
        std::vector<peelf::ModuleInfo> modules_;
        std::uint64_t base_va_{0};
        std::vector<std::uint8_t> mapped_ram_;
    };

    explicit FakeAslrProcessBackend(std::shared_ptr<Session> session)
        : session_(std::move(session)) {}

    [[nodiscard]] peelf::Result<std::vector<peelf::ProcessInfo>> list_processes() override {
        return std::vector<peelf::ProcessInfo>{session_->info()};
    }

    [[nodiscard]] peelf::Result<std::unique_ptr<peelf::IProcessSession>> open_process(
        peelf::ProcessId pid) override {
        if (pid != session_->info().pid) {
            return peelf::make_error("unknown pid");
        }
        return std::make_unique<Session>(*session_);
    }

private:
    std::shared_ptr<Session> session_;
};

} // namespace

TEST(DemanglerTest, DemanglesItaniumSymbolsAndPortableFallback) {
    const auto r1 = peelf::demangle_symbol("_ZNK5peelf11BinaryModel14symbol_by_nameESt17basic_string_viewIcSt11char_traitsIcEE");
    EXPECT_EQ(r1.scheme, peelf::ManglingScheme::Itanium);
    EXPECT_NE(r1.demangled.find("peelf::BinaryModel::symbol_by_name"), std::string::npos);

    const auto r2 = peelf::demangle_symbol("_ZN13peelf_fixture4leafEi@plt");
    EXPECT_EQ(r2.scheme, peelf::ManglingScheme::Itanium);
    EXPECT_EQ(r2.demangled, "peelf_fixture::leaf(int)@plt");

    const auto r3 = peelf::demangle_symbol("libc.so.6!_ZN3VecplERKS_");
    EXPECT_EQ(r3.scheme, peelf::ManglingScheme::Itanium);
    EXPECT_TRUE(r3.demangled.starts_with("libc.so.6!Vec::operator+"));

    // Directly exercise the bounded portable Itanium parser too.
    const auto p1 = peelf::demangle_itanium_portable("_ZNK3foo3bar4quuxEiPKc");
    ASSERT_TRUE(p1.succeeded);
    EXPECT_EQ(p1.demangled, "foo::bar::quux(int, char const*) const");

    const auto p2 = peelf::demangle_itanium_portable("_ZTVN5peelf11BinaryModelE");
    ASSERT_TRUE(p2.succeeded);
    EXPECT_EQ(p2.demangled, "vtable for peelf::BinaryModel");

    // Plain C identifiers must remain untouched.
    const auto plain = peelf::demangle_symbol("printf");
    EXPECT_EQ(plain.scheme, peelf::ManglingScheme::None);
    EXPECT_FALSE(plain.succeeded);
    EXPECT_EQ(plain.demangled, "printf");
}

TEST(DemanglerTest, DemanglesRustV0AndLegacySymbols) {
    const auto v0_fn = peelf::demangle_symbol("_RNvNtCs1234_4core3mem4drop");
    EXPECT_EQ(v0_fn.scheme, peelf::ManglingScheme::RustV0);
    EXPECT_TRUE(v0_fn.succeeded);
    EXPECT_EQ(v0_fn.demangled, "core::mem::drop");

    const auto v0_generic = peelf::demangle_symbol("_RINvNtC3std3mem7replacehE");
    EXPECT_EQ(v0_generic.scheme, peelf::ManglingScheme::RustV0);
    EXPECT_TRUE(v0_generic.succeeded);
    EXPECT_EQ(v0_generic.demangled, "std::mem::replace::<u8>");

    const auto v0_type = peelf::demangle_symbol("_RINtNtC5alloc3vec3VechE");
    EXPECT_EQ(v0_type.scheme, peelf::ManglingScheme::RustV0);
    EXPECT_TRUE(v0_type.succeeded);
    EXPECT_EQ(v0_type.demangled, "alloc::vec::Vec<u8>");

    const auto legacy = peelf::demangle_symbol(
        "_ZN4core3fmt9Arguments6new_v117h1234567890abcdefE");
    EXPECT_EQ(legacy.scheme, peelf::ManglingScheme::RustLegacy);
    EXPECT_EQ(legacy.demangled, "core::fmt::Arguments::new_v1");

    const auto legacy_escaped = peelf::demangle_symbol(
        "_ZN68_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..ops..deref..Deref$GT$5deref17habcdef0123456789E");
    EXPECT_EQ(legacy_escaped.scheme, peelf::ManglingScheme::RustLegacy);
    EXPECT_EQ(legacy_escaped.demangled,
              "<alloc::vec::Vec<T> as core::ops::deref::Deref>::deref");

    // Self-referential Rust v0 backref must reject safely without hanging.
    const auto bad_cycle = peelf::demangle_symbol("_RB0_");
    EXPECT_FALSE(bad_cycle.succeeded);
}

TEST(DemanglerTest, DemanglesMsvcCppSymbolsDeterministically) {
    const auto fn = peelf::demangle_symbol("?leaf@peelf_fixture@@YAHH@Z");
    EXPECT_EQ(fn.scheme, peelf::ManglingScheme::Msvc);
    EXPECT_EQ(fn.demangled, "int __cdecl peelf_fixture::leaf(int)");

    const auto method = peelf::demangle_symbol(
        "?read_memory@Session@peelf@@UEBA_K_KPEAE@Z");
    EXPECT_EQ(method.scheme, peelf::ManglingScheme::Msvc);
    EXPECT_EQ(method.demangled,
              "public: virtual unsigned __int64 __cdecl peelf::Session::read_memory(unsigned __int64, unsigned char *) const");

    const auto tmpl = peelf::demangle_symbol("??$clamp@H@std@@YAHHHH@Z");
    EXPECT_EQ(tmpl.scheme, peelf::ManglingScheme::Msvc);
    EXPECT_EQ(tmpl.demangled, "int __cdecl std::clamp<int>(int, int, int)");

    const auto ctor = peelf::demangle_symbol("??0?$Span@E@peelf@@QEAA@PEAE_K@Z");
    EXPECT_EQ(ctor.scheme, peelf::ManglingScheme::Msvc);
    EXPECT_EQ(ctor.demangled, "public: __cdecl peelf::Span<unsigned char>::Span(unsigned char *, unsigned __int64)");

    const auto vtbl = peelf::demangle_symbol("??_7BinaryModel@peelf@@6B@");
    EXPECT_EQ(vtbl.scheme, peelf::ManglingScheme::Msvc);
    EXPECT_EQ(vtbl.demangled, "const peelf::BinaryModel::`vftable'");
}

TEST(DemanglerTest, HandlesMalformedAndAdversarialInputsSafely) {
    const std::array<std::string, 10> malformed = {
        "",
        "_Z",
        "_ZN999999999fooE",
        "_ZN3foo",
        "_R",
        "_RNv999999_foo",
        "?",
        "??",
        "?broken@@",
        std::string(2048, 'P'),
    };
    for (const std::string& input : malformed) {
        const auto res = peelf::demangle_symbol(input);
        // Must never throw or crash; if unrecognized, succeeded is false and raw name is preserved.
        if (res.scheme == peelf::ManglingScheme::None) {
            EXPECT_FALSE(res.succeeded);
            EXPECT_EQ(res.demangled, input);
        }
    }
}

TEST(DemanglerTest, SymbolIndexSupportsRawAndDemangledLookup) {
    const auto raw_bytes = read_file_bytes(bin_matrix_path("elf-linux-x86_64-64-le-callgraph.elf"));
    auto parsed = peelf::parse_image(raw_bytes);
    ASSERT_TRUE(parsed.has_value());

    viewer::SymbolIndex index = viewer::SymbolIndex::build(**parsed);
    const std::vector<viewer::DebugSymbol> extra = {
        viewer::DebugSymbol{
            .name = "?compute@Engine@demo@@QEAAHM@Z",
            .relative_virtual_address = 0x1500,
            .virtual_address = (*parsed)->image_base() + 0x1500,
            .size = 32,
            .function = true,
            .library = {},
        },
    };
    index.add_debug_symbols(**parsed, extra);

    const viewer::SymbolRecord* by_raw = index.find_by_name("?compute@Engine@demo@@QEAAHM@Z");
    ASSERT_NE(by_raw, nullptr);
    EXPECT_EQ(by_raw->raw_name, "?compute@Engine@demo@@QEAAHM@Z");
    EXPECT_EQ(by_raw->demangled_name, "public: int __cdecl demo::Engine::compute(float)");
    EXPECT_EQ(by_raw->display_name(true), "public: int __cdecl demo::Engine::compute(float)");
    EXPECT_EQ(by_raw->display_name(false), "?compute@Engine@demo@@QEAAHM@Z");

    const viewer::SymbolRecord* by_demangled =
        index.find_by_name("public: int __cdecl demo::Engine::compute(float)");
    ASSERT_NE(by_demangled, nullptr);
    EXPECT_EQ(by_demangled, by_raw);
}

TEST(DwarfMatrixTest, DiscoversSidecarsAndParsesFunctionsAndLinesAcrossAllArchitectures) {
    struct MatrixCase {
        const char* binary_file;
        const char* expected_debug_file;
    };
    constexpr std::array<MatrixCase, 20> kCases = {{
        {"elf-linux-x86-32-le-callgraph.elf", "elf-linux-x86-32-le-callgraph.debug"},
        {"elf-linux-x86-32-le-callgraph.so", "elf-linux-x86-32-le-callgraph.so.debug"},
        {"elf-linux-x86_64-64-le-callgraph.elf", "elf-linux-x86_64-64-le-callgraph.debug"},
        {"elf-linux-x86_64-64-le-callgraph.so", "elf-linux-x86_64-64-le-callgraph.so.debug"},
        {"elf-linux-arm-32-le-callgraph.elf", "elf-linux-arm-32-le-callgraph.debug"},
        {"elf-linux-arm-32-le-callgraph.so", "elf-linux-arm-32-le-callgraph.so.debug"},
        {"elf-linux-arm64-64-le-callgraph.elf", "elf-linux-arm64-64-le-callgraph.debug"},
        {"elf-linux-arm64-64-le-callgraph.so", "elf-linux-arm64-64-le-callgraph.so.debug"},
        {"elf-linux-riscv64-64-le-callgraph.elf", "elf-linux-riscv64-64-le-callgraph.debug"},
        {"elf-linux-riscv64-64-le-callgraph.so", "elf-linux-riscv64-64-le-callgraph.so.debug"},
        {"elf-linux-mips-32-be-callgraph.elf", "elf-linux-mips-32-be-callgraph.debug"},
        {"elf-linux-mips-32-be-callgraph.so", "elf-linux-mips-32-be-callgraph.so.debug"},
        {"elf-linux-mips64-64-be-callgraph.elf", "elf-linux-mips64-64-be-callgraph.debug"},
        {"elf-linux-mips64-64-be-callgraph.so", "elf-linux-mips64-64-be-callgraph.so.debug"},
        {"elf-linux-ppc-32-be-callgraph.elf", "elf-linux-ppc-32-be-callgraph.debug"},
        {"elf-linux-ppc-32-be-callgraph.so", "elf-linux-ppc-32-be-callgraph.so.debug"},
        {"elf-linux-ppc64-64-be-callgraph.elf", "elf-linux-ppc64-64-be-callgraph.debug"},
        {"elf-linux-ppc64-64-be-callgraph.so", "elf-linux-ppc64-64-be-callgraph.so.debug"},
        {"pe-windows-x86-32-le-callgraph.dll", "pe-windows-x86-32-le-callgraph.dll.debug"},
        {"pe-windows-x86_64-64-le-callgraph.dll", "pe-windows-x86_64-64-le-callgraph.dll.debug"},
    }};

    for (const MatrixCase& tc : kCases) {
        SCOPED_TRACE(tc.binary_file);
        const std::filesystem::path bin_path = bin_matrix_path(tc.binary_file);
        const std::vector<std::uint8_t> bin_bytes = read_file_bytes(bin_path);
        auto bin_img = peelf::parse_image(bin_bytes);
        ASSERT_TRUE(bin_img.has_value()) << bin_img.error().message;

        const auto link_info = peelf::extract_elf_debug_link_info(**bin_img);
        ASSERT_TRUE(link_info.has_debuglink);
        EXPECT_EQ(link_info.debuglink_filename, tc.expected_debug_file);

        const auto discovered = peelf::find_separate_debug_file(bin_path, **bin_img);
        ASSERT_TRUE(discovered.has_value());
        EXPECT_EQ(discovered->filename().string(), tc.expected_debug_file);

        const auto loaded = viewer::load_debug_symbols_file(*discovered, **bin_img);
        ASSERT_EQ(loaded.status, viewer::DebugSymbolLoadStatus::Loaded) << loaded.diagnostic;
        EXPECT_FALSE(loaded.symbols.empty());
        EXPECT_FALSE(loaded.lines.empty());

        const bool has_leaf = std::ranges::any_of(loaded.symbols, [](const viewer::DebugSymbol& s) {
            return s.name.find("leaf") != std::string::npos;
        });
        const bool has_first = std::ranges::any_of(loaded.symbols, [](const viewer::DebugSymbol& s) {
            return s.name.find("first") != std::string::npos;
        });
        EXPECT_TRUE(has_leaf);
        EXPECT_TRUE(has_first);

        const bool has_valid_line = std::ranges::any_of(loaded.lines, [](const viewer::SourceLineMapping& l) {
            return l.line > 0 && !l.file_name.empty();
        });
        EXPECT_TRUE(has_valid_line);
    }
}

TEST(DwarfReaderTest, ParsesSyntheticBigEndianDwarfV5StructsUnionsAndSubprograms) {
    // Construct a big-endian 64-bit DWARF v5 compilation unit with:
    //   - base types: int32_t (4B), uint64_t (8B)
    //   - typedef: Handle -> uint64_t*
    //   - array: int32_t[4]
    //   - struct Packet (24B): id @ +0 (int32_t), ptr @ +8 (Handle), values @ +16 (int32_t[4])
    //   - union Payload (8B): raw @ +0 (uint64_t), code @ +0 (int32_t)
    //   - subprogram: _ZN4demo7processEP6Packet [0x10400, +0x48)
    std::vector<std::uint8_t> debug_str;
    append_u8(debug_str, 0); // offset 0: ""
    const auto str_off = [&](std::string_view text) -> std::uint32_t {
        const auto pos = static_cast<std::uint32_t>(debug_str.size());
        append_cstr(debug_str, text);
        return pos;
    };
    const std::uint32_t s_cu = str_off("synthetic_unit.cpp");
    const std::uint32_t s_i32 = str_off("int32_t");
    const std::uint32_t s_u64 = str_off("uint64_t");
    const std::uint32_t s_handle = str_off("Handle");
    const std::uint32_t s_packet = str_off("Packet");
    const std::uint32_t s_id = str_off("id");
    const std::uint32_t s_ptr = str_off("ptr");
    const std::uint32_t s_vals = str_off("values");
    const std::uint32_t s_payload = str_off("Payload");
    const std::uint32_t s_raw = str_off("raw");
    const std::uint32_t s_code = str_off("code");
    const std::uint32_t s_fn = str_off("process");
    const std::uint32_t s_link = str_off("_ZN4demo7processEP6Packet");

    // Abbreviations:
    // 1: DW_TAG_compile_unit (children=yes): DW_AT_name (strp)
    // 2: DW_TAG_base_type (no): DW_AT_name (strp), DW_AT_byte_size (data1), DW_AT_encoding (data1)
    // 3: DW_TAG_pointer_type (no): DW_AT_type (ref4), DW_AT_byte_size (data1)
    // 4: DW_TAG_typedef (no): DW_AT_name (strp), DW_AT_type (ref4)
    // 5: DW_TAG_array_type (yes): DW_AT_type (ref4)
    // 6: DW_TAG_subrange_type (no): DW_AT_count (data1)
    // 7: DW_TAG_structure_type (yes): DW_AT_name (strp), DW_AT_byte_size (data1)
    // 8: DW_TAG_member (no): DW_AT_name (strp), DW_AT_type (ref4), DW_AT_data_member_location (data1)
    // 9: DW_TAG_member (no, exprloc): DW_AT_name (strp), DW_AT_type (ref4), DW_AT_data_member_location (exprloc)
    // 10: DW_TAG_union_type (yes): DW_AT_name (strp), DW_AT_byte_size (data1)
    // 11: DW_TAG_subprogram (no): DW_AT_name (strp), DW_AT_linkage_name (strp), DW_AT_low_pc (addr), DW_AT_high_pc (data4)
    std::vector<std::uint8_t> abbrev;
    auto emit_attr = [&](std::uint8_t attr, std::uint8_t form) {
        append_u8(abbrev, attr);
        append_u8(abbrev, form);
    };
    // 1: compile_unit
    append_u8(abbrev, 1); append_u8(abbrev, 0x11); append_u8(abbrev, 1);
    emit_attr(0x03, 0x0E); emit_attr(0, 0);
    // 2: base_type
    append_u8(abbrev, 2); append_u8(abbrev, 0x24); append_u8(abbrev, 0);
    emit_attr(0x03, 0x0E); emit_attr(0x0B, 0x0B); emit_attr(0x3E, 0x0B); emit_attr(0, 0);
    // 3: pointer_type
    append_u8(abbrev, 3); append_u8(abbrev, 0x0F); append_u8(abbrev, 0);
    emit_attr(0x49, 0x13); emit_attr(0x0B, 0x0B); emit_attr(0, 0);
    // 4: typedef
    append_u8(abbrev, 4); append_u8(abbrev, 0x16); append_u8(abbrev, 0);
    emit_attr(0x03, 0x0E); emit_attr(0x49, 0x13); emit_attr(0, 0);
    // 5: array_type
    append_u8(abbrev, 5); append_u8(abbrev, 0x01); append_u8(abbrev, 1);
    emit_attr(0x49, 0x13); emit_attr(0, 0);
    // 6: subrange_type
    append_u8(abbrev, 6); append_u8(abbrev, 0x21); append_u8(abbrev, 0);
    emit_attr(0x37, 0x0B); emit_attr(0, 0);
    // 7: structure_type
    append_u8(abbrev, 7); append_u8(abbrev, 0x13); append_u8(abbrev, 1);
    emit_attr(0x03, 0x0E); emit_attr(0x0B, 0x0B); emit_attr(0, 0);
    // 8: member (data1 offset)
    append_u8(abbrev, 8); append_u8(abbrev, 0x0D); append_u8(abbrev, 0);
    emit_attr(0x03, 0x0E); emit_attr(0x49, 0x13); emit_attr(0x38, 0x0B); emit_attr(0, 0);
    // 9: member (exprloc DW_OP_plus_uconst)
    append_u8(abbrev, 9); append_u8(abbrev, 0x0D); append_u8(abbrev, 0);
    emit_attr(0x03, 0x0E); emit_attr(0x49, 0x13); emit_attr(0x38, 0x18); emit_attr(0, 0);
    // 10: union_type
    append_u8(abbrev, 10); append_u8(abbrev, 0x17); append_u8(abbrev, 1);
    emit_attr(0x03, 0x0E); emit_attr(0x0B, 0x0B); emit_attr(0, 0);
    // 11: subprogram
    append_u8(abbrev, 11); append_u8(abbrev, 0x2E); append_u8(abbrev, 0);
    emit_attr(0x03, 0x0E); emit_attr(0x6E, 0x0E); emit_attr(0x11, 0x01); emit_attr(0x12, 0x06); emit_attr(0, 0);
    append_u8(abbrev, 0);

    // Build .debug_info (DWARF v5 header: unit_length(4), version=5(2), unit_type=DW_UT_compile(1), addr_size=8(1), abbrev_off=0(4))
    std::vector<std::uint8_t> info;
    append_u32_be(info, 0); // placeholder for unit_length
    append_u16_be(info, 5); // DWARF v5
    append_u8(info, 0x01);  // DW_UT_compile
    append_u8(info, 8);     // 64-bit addresses
    append_u32_be(info, 0); // abbrev offset

    // CU DIE (code 1)
    append_u8(info, 1);
    append_u32_be(info, s_cu);

    const auto off_i32 = static_cast<std::uint32_t>(info.size());
    append_u8(info, 2); append_u32_be(info, s_i32); append_u8(info, 4); append_u8(info, 0x05);

    const auto off_u64 = static_cast<std::uint32_t>(info.size());
    append_u8(info, 2); append_u32_be(info, s_u64); append_u8(info, 8); append_u8(info, 0x07);

    const auto off_ptr_u64 = static_cast<std::uint32_t>(info.size());
    append_u8(info, 3); append_u32_be(info, off_u64); append_u8(info, 8);

    const auto off_handle = static_cast<std::uint32_t>(info.size());
    append_u8(info, 4); append_u32_be(info, s_handle); append_u32_be(info, off_ptr_u64);

    const auto off_arr = static_cast<std::uint32_t>(info.size());
    append_u8(info, 5); append_u32_be(info, off_i32);
    append_u8(info, 6); append_u8(info, 4); // subrange count=4
    append_u8(info, 0); // end array children

    // struct Packet (size 32)
    append_u8(info, 7); append_u32_be(info, s_packet); append_u8(info, 32);
    append_u8(info, 8); append_u32_be(info, s_id); append_u32_be(info, off_i32); append_u8(info, 0);
    append_u8(info, 8); append_u32_be(info, s_ptr); append_u32_be(info, off_handle); append_u8(info, 8);
    // exprloc member: length=2, DW_OP_plus_uconst (0x23), uleb(16)
    append_u8(info, 9); append_u32_be(info, s_vals); append_u32_be(info, off_arr);
    append_u8(info, 2); append_u8(info, 0x23); append_u8(info, 16);
    append_u8(info, 0); // end Packet children

    // union Payload (size 8)
    append_u8(info, 10); append_u32_be(info, s_payload); append_u8(info, 8);
    append_u8(info, 8); append_u32_be(info, s_raw); append_u32_be(info, off_u64); append_u8(info, 0);
    append_u8(info, 8); append_u32_be(info, s_code); append_u32_be(info, off_i32); append_u8(info, 0);
    append_u8(info, 0); // end Payload children

    // subprogram _ZN4demo7processEP6Packet
    append_u8(info, 11);
    append_u32_be(info, s_fn);
    append_u32_be(info, s_link);
    append_u64_be(info, 0x0000000000010400ULL);
    append_u32_be(info, 0x48u);

    append_u8(info, 0); // end CU children

    const auto unit_len = static_cast<std::uint32_t>(info.size() - 4u);
    info[0] = static_cast<std::uint8_t>((unit_len >> 24u) & 0xFFu);
    info[1] = static_cast<std::uint8_t>((unit_len >> 16u) & 0xFFu);
    info[2] = static_cast<std::uint8_t>((unit_len >> 8u) & 0xFFu);
    info[3] = static_cast<std::uint8_t>(unit_len & 0xFFu);

    peelf::DwarfSectionViews views{
        .endian = peelf::Endianness::Big,
        .default_address_size = 8,
        .debug_info = std::move(info),
        .debug_abbrev = std::move(abbrev),
        .debug_str = std::move(debug_str),
    };
    const auto parsed = peelf::parse_dwarf_sections(views);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    ASSERT_EQ(parsed->functions.size(), 1u);
    EXPECT_EQ(parsed->functions[0].name, "process");
    EXPECT_EQ(parsed->functions[0].linkage_name, "_ZN4demo7processEP6Packet");
    EXPECT_EQ(parsed->functions[0].low_pc, 0x10400ULL);
    EXPECT_EQ(parsed->functions[0].byte_size, 0x48ULL);

    ASSERT_EQ(parsed->types.size(), 2u);
    const auto packet_it = std::ranges::find(parsed->types, "Packet", &peelf::DwarfAggregateType::name);
    ASSERT_NE(packet_it, parsed->types.end());
    EXPECT_EQ(packet_it->kind, peelf::DwarfAggregateKind::Struct);
    EXPECT_EQ(packet_it->byte_size, 32u);
    ASSERT_EQ(packet_it->members.size(), 3u);
    EXPECT_EQ(packet_it->members[0].name, "id");
    EXPECT_EQ(packet_it->members[0].type_name, "int32_t");
    EXPECT_EQ(packet_it->members[0].byte_offset, 0u);
    EXPECT_EQ(packet_it->members[0].byte_size, 4u);
    EXPECT_EQ(packet_it->members[1].name, "ptr");
    EXPECT_EQ(packet_it->members[1].type_name, "Handle");
    EXPECT_EQ(packet_it->members[1].byte_offset, 8u);
    EXPECT_EQ(packet_it->members[1].byte_size, 8u);
    EXPECT_EQ(packet_it->members[2].name, "values");
    EXPECT_EQ(packet_it->members[2].type_name, "int32_t[4]");
    EXPECT_EQ(packet_it->members[2].byte_offset, 16u);
    EXPECT_EQ(packet_it->members[2].byte_size, 16u);

    const auto payload_it = std::ranges::find(parsed->types, "Payload", &peelf::DwarfAggregateType::name);
    ASSERT_NE(payload_it, parsed->types.end());
    EXPECT_EQ(payload_it->kind, peelf::DwarfAggregateKind::Union);
    EXPECT_EQ(payload_it->byte_size, 8u);
    ASSERT_EQ(payload_it->members.size(), 2u);
}

#if defined(PEELF_CALLGRAPH_FIXTURE_EXE) && !defined(_WIN32)
TEST(DwarfBinaryModelTest, AutoDiscoversEmbeddedCppDwarfTypesDemanglesAndMapsLines) {
    const std::filesystem::path exe_path(PEELF_CALLGRAPH_FIXTURE_EXE);
    ASSERT_TRUE(std::filesystem::exists(exe_path));

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(exe_path.string()));

    // Verify DWARF struct DecompilerPacket was extracted into BinaryModel::debug_types().
    const auto packet_it = std::ranges::find_if(model.debug_types(), [](const viewer::DataTypeRecord& t) {
        return t.name.find("DecompilerPacket") != std::string::npos;
    });
    ASSERT_NE(packet_it, model.debug_types().end());
    EXPECT_GE(packet_it->size, 12u);
    ASSERT_EQ(packet_it->members.size(), 2u);
    EXPECT_EQ(packet_it->members[0].name, "count");
    EXPECT_EQ(packet_it->members[0].offset, 0u);
    EXPECT_EQ(packet_it->members[1].name, "weight");
    EXPECT_EQ(packet_it->members[1].offset, 8u);

    // Verify demangling toggle works on C++ symbols in BinaryModel & SymbolIndex.
    const viewer::SymbolRecord* leaf_sym = model.symbol_index().find_by_name("peelf_fixture::leaf(int)");
    ASSERT_NE(leaf_sym, nullptr);
    ASSERT_TRUE(leaf_sym->virtual_address.has_value());
    const std::uint64_t leaf_va = *leaf_sym->virtual_address;

    model.set_demangle_symbols(true);
    EXPECT_EQ(model.resolve_address_symbol(leaf_va), "peelf_fixture::leaf(int)");

    model.set_demangle_symbols(false);
    EXPECT_EQ(model.resolve_address_symbol(leaf_va), leaf_sym->raw_name);
    model.set_demangle_symbols(true);

    // Verify .debug_line maps leaf_va back to callgraph_debug_fixture.cpp.
    const auto* src_line = model.find_source_line(leaf_va, 32);
    ASSERT_NE(src_line, nullptr);
    EXPECT_NE(src_line->file_name.find("callgraph_debug_fixture.cpp"), std::string::npos);
    EXPECT_GT(src_line->line, 0u);
}
#endif

TEST(DwarfLiveAslrTest, RebasesSidecarDwarfSymbolsAndSourceLinesOntoLiveProcessModule) {
    const std::filesystem::path so_path = bin_matrix_path("elf-linux-x86_64-64-le-callgraph.so");
    const std::vector<std::uint8_t> so_bytes = read_file_bytes(so_path);
    auto disk_img = peelf::parse_image(std::span<const std::uint8_t>(so_bytes));
    ASSERT_TRUE(disk_img.has_value());

    // Simulate mapping only PT_LOAD segments into live RAM at a high ASLR base (stripping all
    // non-SHF_ALLOC sections and sidecar DWARF from RAM).
    constexpr std::uint64_t kLiveBase = 0x00007F44'80000000ULL;
    const std::uint64_t static_base = (*disk_img)->image_base();

    std::uint64_t max_rva = 0x10000;
    for (const peelf::Segment& seg : (*disk_img)->segments()) {
        if (seg.virtual_address >= static_base) {
            max_rva = std::max(max_rva, (seg.virtual_address - static_base) + seg.virtual_size + 0x1000u);
        }
    }
    std::vector<std::uint8_t> mapped_ram(static_cast<std::size_t>(max_rva), 0);
    for (const peelf::Segment& seg : (*disk_img)->segments()) {
        if (seg.file_size == 0 || seg.virtual_address < static_base) {
            continue;
        }
        const std::size_t rva = static_cast<std::size_t>(seg.virtual_address - static_base);
        const std::size_t off = static_cast<std::size_t>(seg.file_offset);
        if (off + seg.file_size <= so_bytes.size() && rva + seg.file_size <= mapped_ram.size()) {
            std::copy_n(so_bytes.data() + off, static_cast<std::size_t>(seg.file_size), mapped_ram.data() + rva);
        }
    }

    peelf::ProcessInfo pinfo{
        .pid = 42424,
        .name = "aslr_host",
        .executable_path = so_path,
        .architecture = peelf::Architecture::X86_64,
        .endianness = peelf::Endianness::Little,
        .is_64bit = true,
        .access = peelf::ProcessAccessStatus::Accessible,
    };
    std::vector<peelf::MemoryRegion> regions = {
        peelf::MemoryRegion{
            .start_address = kLiveBase,
            .end_address = kLiveBase + mapped_ram.size(),
            .protection = {.readable = true, .writable = false, .executable = true},
            .kind = peelf::MemoryRegionKind::Image,
            .file_offset = 0,
            .pathname = so_path.string(),
        },
    };
    std::vector<peelf::ModuleInfo> modules = {
        peelf::ModuleInfo{
            .name = so_path.filename().string(),
            .path = so_path,
            .base_address = kLiveBase,
            .size = mapped_ram.size(),
            .format = peelf::Format::ELF,
            .is_main_module = true,
        },
    };

    auto session = std::make_shared<FakeAslrProcessBackend::Session>(
        std::move(pinfo), std::move(regions), std::move(modules), kLiveBase, std::move(mapped_ram));
    auto backend = std::make_shared<FakeAslrProcessBackend>(session);

    viewer::BinaryModel model;
    model.set_process_backend(backend);
    ASSERT_TRUE(model.attach_process(42424).has_value());
    ASSERT_NE(model.image(), nullptr);
    EXPECT_EQ(model.image()->image_base(), kLiveBase);

    // Sidecar DWARF (.so.debug) must be auto-discovered and rebased to kLiveBase!
    const viewer::SymbolRecord* leaf_sym = model.symbol_index().find_by_name("leaf");
    ASSERT_NE(leaf_sym, nullptr);
    ASSERT_TRUE(leaf_sym->virtual_address.has_value());
    EXPECT_GT(*leaf_sym->virtual_address, kLiveBase);
    EXPECT_LT(*leaf_sym->virtual_address, kLiveBase + 0x20000ULL);

    ASSERT_FALSE(model.source_lines().empty());
    for (const viewer::SourceLineMapping& line : model.source_lines()) {
        EXPECT_GE(line.virtual_address, kLiveBase);
        EXPECT_LT(line.virtual_address, kLiveBase + 0x40000ULL);
    }
}

TEST(DwarfCheckedArithmeticTest, RejectsWrappingStrxAndAddrxIndicesWithoutModuloAliasing) {
    auto push_u16_le = [](std::vector<std::uint8_t>& out, std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    };
    auto push_u32_le = [](std::vector<std::uint8_t>& out, std::uint32_t v) {
        for (int s = 0; s < 32; s += 8) {
            out.push_back(static_cast<std::uint8_t>((v >> s) & 0xFFu));
        }
    };
    auto push_u64_le = [](std::vector<std::uint8_t>& out, std::uint64_t v) {
        for (int s = 0; s < 64; s += 8) {
            out.push_back(static_cast<std::uint8_t>((v >> s) & 0xFFu));
        }
    };
    auto push_uleb = [](std::vector<std::uint8_t>& out, std::uint64_t v) {
        do {
            std::uint8_t byte = static_cast<std::uint8_t>(v & 0x7Fu);
            v >>= 7u;
            if (v != 0) byte |= 0x80u;
            out.push_back(byte);
        } while (v != 0);
    };

    // .debug_str: offset 0 = "valid_fn\0", offset 9 = "wrapped_secret\0"
    std::vector<std::uint8_t> debug_str;
    for (char c : std::string_view{"valid_fn", 9}) debug_str.push_back(static_cast<std::uint8_t>(c));
    for (char c : std::string_view{"wrapped_secret", 15}) debug_str.push_back(static_cast<std::uint8_t>(c));

    // DWARF64 .debug_str_offsets: 16-byte header, entry[0] @ 16 -> 0 ("valid_fn"), entry[1] @ 24 -> 9 ("wrapped_secret")
    std::vector<std::uint8_t> debug_str_offsets(16, 0);
    push_u64_le(debug_str_offsets, 0ull);
    push_u64_le(debug_str_offsets, 9ull);

    // .debug_addr: 16-byte header, entry[0] @ 16 -> 0x401000, entry[1] @ 24 -> 0xDEADBEEFCAFEBABE
    std::vector<std::uint8_t> debug_addr(16, 0);
    push_u64_le(debug_addr, 0x401000ull);
    push_u64_le(debug_addr, 0xDEADBEEFCAFEBABEull);

    // Abbrev table:
    //   [1] DW_TAG_compile_unit, children=yes: DW_AT_str_offsets_base (sec_offset=0x17), DW_AT_addr_base (sec_offset=0x17)
    //   [2] DW_TAG_subprogram, children=no: DW_AT_name (strx=0x1a), DW_AT_low_pc (addrx=0x1b), DW_AT_high_pc (data8=0x07)
    std::vector<std::uint8_t> debug_abbrev;
    push_uleb(debug_abbrev, 1u);
    push_uleb(debug_abbrev, 0x11u); // DW_TAG_compile_unit
    debug_abbrev.push_back(1u);     // DW_CHILDREN_yes
    push_uleb(debug_abbrev, 0x72u); // DW_AT_str_offsets_base
    push_uleb(debug_abbrev, 0x17u); // DW_FORM_sec_offset
    push_uleb(debug_abbrev, 0x73u); // DW_AT_addr_base
    push_uleb(debug_abbrev, 0x17u); // DW_FORM_sec_offset
    debug_abbrev.push_back(0u);
    debug_abbrev.push_back(0u);

    push_uleb(debug_abbrev, 2u);
    push_uleb(debug_abbrev, 0x2eu); // DW_TAG_subprogram
    debug_abbrev.push_back(0u);     // DW_CHILDREN_no
    push_uleb(debug_abbrev, 0x03u); // DW_AT_name
    push_uleb(debug_abbrev, 0x1au); // DW_FORM_strx
    push_uleb(debug_abbrev, 0x11u); // DW_AT_low_pc
    push_uleb(debug_abbrev, 0x1bu); // DW_FORM_addrx
    push_uleb(debug_abbrev, 0x12u); // DW_AT_high_pc
    push_uleb(debug_abbrev, 0x07u); // DW_FORM_data8
    debug_abbrev.push_back(0u);
    debug_abbrev.push_back(0u);
    debug_abbrev.push_back(0u);

    // Craft wrapping index: (2^64 / 8) + 1 = 0x2000000000000001ULL.
    // Unchecked `16 + index * 8` wraps modulo 2^64 to `16 + 8 == 24` (entry[1]!).
    constexpr std::uint64_t kWrappingIndex = (1ull << 61u) + 1ull;
    static_assert(16ull + kWrappingIndex * 8ull == 24ull);

    std::vector<std::uint8_t> cu_body;
    push_u16_le(cu_body, 5u);  // DWARF v5
    cu_body.push_back(0x01u);  // DW_UT_compile
    cu_body.push_back(8u);     // address_size = 8
    push_u64_le(cu_body, 0ull); // abbrev_offset = 0

    // DIE [1] compile_unit: str_offsets_base = 16, addr_base = 16
    push_uleb(cu_body, 1u);
    push_u64_le(cu_body, 16ull);
    push_u64_le(cu_body, 16ull);

    // DIE [2] valid subprogram (index 0 -> "valid_fn" @ 0x401000)
    push_uleb(cu_body, 2u);
    push_uleb(cu_body, 0u);
    push_uleb(cu_body, 0u);
    push_u64_le(cu_body, 0x20ull);

    // DIE [2] hostile subprogram (wrapping index -> must NOT alias entry[1])
    push_uleb(cu_body, 2u);
    push_uleb(cu_body, kWrappingIndex);
    push_uleb(cu_body, kWrappingIndex);
    push_u64_le(cu_body, 0x20ull);

    cu_body.push_back(0u); // end of children

    // DWARF64 unit header: 0xFFFFFFFF + 8-byte length
    std::vector<std::uint8_t> debug_info;
    push_u32_le(debug_info, 0xFFFF'FFFFu);
    push_u64_le(debug_info, static_cast<std::uint64_t>(cu_body.size()));
    debug_info.insert(debug_info.end(), cu_body.begin(), cu_body.end());

    peelf::DwarfSectionViews views{
        .endian = peelf::Endianness::Little,
        .default_address_size = 8,
        .debug_info = debug_info,
        .debug_abbrev = debug_abbrev,
        .debug_str = debug_str,
        .debug_str_offsets = debug_str_offsets,
        .debug_addr = debug_addr,
    };

    const auto parsed_res = peelf::parse_dwarf_sections(views);
    ASSERT_TRUE(parsed_res.has_value()) << parsed_res.error().message;
    ASSERT_EQ(parsed_res->functions.size(), 1u);
    EXPECT_EQ(parsed_res->functions[0].name, "valid_fn");
    EXPECT_EQ(parsed_res->functions[0].low_pc, 0x401000ull);
}
