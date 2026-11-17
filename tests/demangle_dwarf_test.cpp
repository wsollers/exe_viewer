#include "peelf/binary_image.hpp"
#include "peelf/demangle.hpp"
#include "peelf/dwarf.hpp"
#include "peelf/handlers.hpp"
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
    append_cstr(debug_str, "valid_fn");
    append_cstr(debug_str, "wrapped_secret");

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

TEST(DwarfBoundsAndLeb128Test, RejectsTenthByteLeb128OverflowAndTruncatedUnitRecords) {
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

    // 1. 10th-byte ULEB128 overflow (`0x02` in 10th byte = 2^64, which would wrap to 0 if unchecked)
    //    vs valid 10-byte UINT64_MAX (`0xFF x 9, 0x01`) and SLEB128 overflow (`0x80 x 9, 0x01`).
    {
        std::vector<std::uint8_t> debug_str;
        append_cstr(debug_str, "overflow_fn");
        const auto valid_str_off = static_cast<std::uint32_t>(debug_str.size());
        append_cstr(debug_str, "valid_after_bounds");

        // Abbrev [1]: compile_unit (no attrs, children=yes)
        // Abbrev [2]: subprogram: DW_AT_name (strp=0x0E), DW_AT_low_pc (addr=0x01),
        //                         DW_AT_high_pc (udata=0x0F), DW_AT_call_line (sdata=0x0D)
        std::vector<std::uint8_t> abbrev{
            1u, 0x11u, 1u, 0u, 0u,
            2u, 0x2Eu, 0u,
            0x03u, 0x0Eu,
            0x11u, 0x01u,
            0x12u, 0x0Fu,
            0x59u, 0x0Du,
            0u, 0u,
            0u,
        };

        auto make_cu_with_leb = [&](std::span<const std::uint8_t> uleb_bytes,
                                    std::span<const std::uint8_t> sleb_bytes,
                                    std::uint32_t name_off) {
            std::vector<std::uint8_t> body;
            push_u16_le(body, 5u);
            body.push_back(0x01u);
            body.push_back(8u);
            push_u32_le(body, 0u);
            body.push_back(1u); // CU DIE
            body.push_back(2u); // subprogram DIE
            push_u32_le(body, name_off);
            push_u64_le(body, 0x402000ull);
            body.insert(body.end(), uleb_bytes.begin(), uleb_bytes.end());
            body.insert(body.end(), sleb_bytes.begin(), sleb_bytes.end());
            body.push_back(0u);

            std::vector<std::uint8_t> cu;
            push_u32_le(cu, static_cast<std::uint32_t>(body.size()));
            cu.insert(cu.end(), body.begin(), body.end());
            return cu;
        };

        // Overflowing 10th-byte ULEB128 (bit 1 set -> 2^64)
        const std::array<std::uint8_t, 10> bad_uleb{
            0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x02u};
        const std::array<std::uint8_t, 1> zero_sleb{0x00u};

        // Overflowing 10th-byte SLEB128 (positive bit 0 set without sign extension -> +2^63)
        const std::array<std::uint8_t, 2> small_uleb{0x90u, 0x01u};
        const std::array<std::uint8_t, 10> bad_sleb{
            0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x01u};

        // Valid 10-byte SLEB128 INT64_MIN (`0x80 x 9, 0x7F`) with small ULEB128 size
        const std::array<std::uint8_t, 10> min_i64_sleb{
            0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x7Fu};

        std::vector<std::uint8_t> combined_info;
        const auto cu1 = make_cu_with_leb(bad_uleb, zero_sleb, 0u);
        const auto cu2 = make_cu_with_leb(small_uleb, bad_sleb, 0u);
        const auto cu3 = make_cu_with_leb(small_uleb, min_i64_sleb, valid_str_off);
        combined_info.insert(combined_info.end(), cu1.begin(), cu1.end());
        combined_info.insert(combined_info.end(), cu2.begin(), cu2.end());
        combined_info.insert(combined_info.end(), cu3.begin(), cu3.end());

        peelf::DwarfSectionViews views{
            .endian = peelf::Endianness::Little,
            .default_address_size = 8,
            .debug_info = std::move(combined_info),
            .debug_abbrev = std::move(abbrev),
            .debug_str = std::move(debug_str),
        };
        const auto parsed = peelf::parse_dwarf_sections(views);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        // Malformed CUs #1 and #2 must abort cleanly without emitting "overflow_fn",
        // while subsequent valid CU #3 ("valid_after_bounds") still parses!
        ASSERT_EQ(parsed->functions.size(), 1u);
        EXPECT_EQ(parsed->functions[0].name, "valid_after_bounds");
    }

    // 2. Truncated inner unit boundary in .debug_info & .debug_line followed by trailing bytes:
    //    must never wrap `cu_end - cursor` or `unit_end - cursor` to ~size_t{0} and read past the unit.
    {
        std::vector<std::uint8_t> debug_str;
        append_cstr(debug_str, "poison_trailing_fn");

        std::vector<std::uint8_t> abbrev{
            1u, 0x11u, 1u, 0u, 0u,
            2u, 0x2Eu, 0u, 0x03u, 0x0Eu, 0x11u, 0x01u, 0x12u, 0x06u, 0u, 0u,
            0u,
        };

        // Declare unit_length = 9 bytes (ends right inside the first subprogram's DW_AT_name),
        // then append complete valid-looking subprogram bytes immediately after `cu_end`.
        std::vector<std::uint8_t> truncated_info;
        push_u32_le(truncated_info, 9u); // unit_length = 9 -> cu_end = 13
        push_u16_le(truncated_info, 5u);
        truncated_info.push_back(0x01u);
        truncated_info.push_back(8u);
        push_u32_le(truncated_info, 0u);
        truncated_info.push_back(1u); // CU DIE @ offset 12 (last valid byte of CU #1!)
        // Trailing bytes beyond cu_end (not a valid DWARF unit header either):
        truncated_info.push_back(2u);
        push_u32_le(truncated_info, 0u);
        push_u64_le(truncated_info, 0x403000ull);
        push_u32_le(truncated_info, 0x20u);
        truncated_info.push_back(0u);

        // Truncated .debug_line unit where header_length exceeds unit_length:
        std::vector<std::uint8_t> truncated_line;
        push_u32_le(truncated_line, 12u); // unit_end = 16
        push_u16_le(truncated_line, 4u);  // DWARF v4 line table
        push_u32_le(truncated_line, 64u); // header_length = 64 > remaining unit bytes!
        truncated_line.resize(96u, 0x01u);

        peelf::DwarfSectionViews views{
            .endian = peelf::Endianness::Little,
            .default_address_size = 8,
            .debug_info = std::move(truncated_info),
            .debug_abbrev = std::move(abbrev),
            .debug_str = std::move(debug_str),
            .debug_line = std::move(truncated_line),
        };
        const auto parsed = peelf::parse_dwarf_sections(views);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        EXPECT_TRUE(parsed->functions.empty());
        EXPECT_TRUE(parsed->lines.empty());
    }
}

TEST(EhFrameBoundsAndLeb128Test, RejectsTruncatedCieAugmentationAndTenthByteLeb128Overflow) {
    auto put16 = [](std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
        b[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
        b[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    };
    auto put32 = [](std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0; i < 4u; ++i) {
            b[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };
    auto put64 = [](std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0; i < 8u; ++i) {
            b[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };

    auto build_eh_frame_elf = [&](const std::vector<std::uint8_t>& eh_frame) {
        std::vector<std::uint8_t> shstrtab{0};
        auto add_shstr = [&](std::string_view s) {
            const auto pos = static_cast<std::uint32_t>(shstrtab.size());
            shstrtab.insert(shstrtab.end(), s.begin(), s.end());
            shstrtab.push_back(0u);
            return pos;
        };
        const std::uint32_t nm_text = add_shstr(".text");
        const std::uint32_t nm_eh = add_shstr(".eh_frame");
        const std::uint32_t nm_shstr = add_shstr(".shstrtab");

        std::vector<std::uint8_t> elf(0x200u, 0u);
        elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
        elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
        put16(elf, 16u, 3u);  // ET_DYN
        put16(elf, 18u, 62u); // EM_X86_64
        put32(elf, 20u, 1u);
        put64(elf, 24u, 0x1000u);
        put64(elf, 32u, 0x40u);
        put16(elf, 52u, 64u);
        put16(elf, 54u, 56u);
        put16(elf, 56u, 1u);
        put16(elf, 58u, 64u);
        put16(elf, 60u, 4u);
        put16(elf, 62u, 3u);

        const std::uint64_t text_off = 0x200u;
        elf.resize(text_off + 0x40u, 0xC3u);
        while ((elf.size() % 8u) != 0u) elf.push_back(0u);
        const std::uint64_t eh_off = elf.size();
        elf.insert(elf.end(), eh_frame.begin(), eh_frame.end());
        while ((elf.size() % 8u) != 0u) elf.push_back(0u);
        const std::uint64_t shstr_off = elf.size();
        elf.insert(elf.end(), shstrtab.begin(), shstrtab.end());
        while ((elf.size() % 8u) != 0u) elf.push_back(0u);

        const std::uint64_t shoff = elf.size();
        put64(elf, 40u, shoff);
        elf.resize(elf.size() + 4u * 64u, 0u);

        // PT_LOAD covering the text + .eh_frame range
        put32(elf, 0x40u + 0u, 1u);
        put32(elf, 0x40u + 4u, 5u);
        put64(elf, 0x40u + 8u, 0u);
        put64(elf, 0x40u + 16u, 0u);
        put64(elf, 0x40u + 24u, 0u);
        put64(elf, 0x40u + 32u, shstr_off);
        put64(elf, 0x40u + 40u, shstr_off);
        put64(elf, 0x40u + 48u, 0x1000u);

        auto write_sh = [&](std::size_t idx, std::uint32_t nm, std::uint32_t type,
                            std::uint64_t flags, std::uint64_t addr, std::uint64_t off, std::uint64_t sz) {
            const std::size_t sh = static_cast<std::size_t>(shoff) + idx * 64u;
            put32(elf, sh + 0u, nm);
            put32(elf, sh + 4u, type);
            put64(elf, sh + 8u, flags);
            put64(elf, sh + 16u, addr);
            put64(elf, sh + 24u, off);
            put64(elf, sh + 32u, sz);
            put64(elf, sh + 48u, 8u);
        };
        write_sh(1u, nm_text, 1u, 0x6u, text_off, text_off, 0x40u);
        write_sh(2u, nm_eh, 1u, 0x2u, eh_off, eh_off, eh_frame.size());
        write_sh(3u, nm_shstr, 3u, 0u, 0u, shstr_off, shstrtab.size());
        return elf;
    };

    // Case 1: CIE #1 has truncated `aug_len = 2` for `"zP"` where `P` uses `DW_EH_PE_udata8` (0x04),
    //         followed immediately inside the record by `0x1020` (poison handler address!).
    //         CIE #2 has 10th-byte ULEB128 overflow (`0x80 x 9, 0x02`) on `code_align` with a valid-looking
    //         personality `0x1030`. Neither malformed CIE may produce an `ElfEhFramePersonality` entry!
    std::vector<std::uint8_t> eh;
    auto append_record = [&](std::uint32_t cie_id_or_ptr, const std::vector<std::uint8_t>& body) {
        const std::size_t start = eh.size();
        eh.resize(start + 8u, 0u);
        put32(eh, start, static_cast<std::uint32_t>(4u + body.size()));
        put32(eh, start + 4u, cie_id_or_ptr);
        eh.insert(eh.end(), body.begin(), body.end());
    };

    // Malformed CIE #1: aug = "zP\0", code_align=1, data_align=-8(0x78), ret_reg=16,
    // aug_len=2 (only room for encoding byte + 1 byte, NOT 8-byte udata8!), followed by 8-byte 0x208ull.
    {
        std::vector<std::uint8_t> cie1{
            1u,                     // version
            'z', 'P', 0u,           // augmentation
            1u,                     // code_align
            0x78u,                  // data_align (-8)
            16u,                    // return_address_register
            2u,                     // aug_len = 2 (truncated!)
            0x04u,                  // DW_EH_PE_udata8 (needs 8 bytes, exceeds aug_end!)
        };
        const std::size_t p_off = cie1.size();
        cie1.resize(p_off + 8u, 0u);
        put64(cie1, p_off, 0x208ull);
        append_record(0u, cie1);
    }

    // Malformed CIE #2: 10th-byte ULEB128 overflow in code_align (`0x80 x 9, 0x02`)
    {
        std::vector<std::uint8_t> cie2{
            1u,
            'z', 'P', 0u,
            0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x02u, // overflowing ULEB128!
            0x78u,
            16u,
            9u,
            0x04u,
        };
        const std::size_t p_off = cie2.size();
        cie2.resize(p_off + 8u, 0u);
        put64(cie2, p_off, 0x210ull);
        append_record(0u, cie2);
    }

    // Valid CIE #3 + valid FDE #1 + truncated FDE #2 referencing CIE #3 with personality @ 0x220ull
    const auto cie3_offset = static_cast<std::uint32_t>(eh.size());
    {
        std::vector<std::uint8_t> cie3{
            1u,
            'z', 'P', 'L', 'R', 0u,
            1u,
            0x78u,
            16u,
            11u,   // aug_len = 1 (P enc) + 8 (P ptr) + 1 (L enc) + 1 (R enc)
            0x04u, // P = DW_EH_PE_udata8
        };
        const std::size_t p_off = cie3.size();
        cie3.resize(p_off + 8u, 0u);
        put64(cie3, p_off, 0x220ull);
        cie3.push_back(0x04u); // L = DW_EH_PE_udata8
        cie3.push_back(0x04u); // R = DW_EH_PE_udata8
        append_record(0u, cie3);
    }
    {
        // Valid FDE #1 (fde_aug_len = 8, LSDA = 0x228ull)
        const auto fde_id_pos = static_cast<std::uint32_t>(eh.size() + 4u);
        const std::uint32_t cie_ptr = fde_id_pos - cie3_offset;
        std::vector<std::uint8_t> fde(25u, 0u);
        put64(fde, 0u, 0x200ull); // initial_location
        put64(fde, 8u, 0x20ull);  // address_range
        fde[16u] = 8u;            // fde_aug_len = 8
        put64(fde, 17u, 0x228ull);
        append_record(cie_ptr, fde);
    }
    {
        // Malformed FDE #2: fde_aug_len = 2 (truncated for 8-byte udata8 LSDA!), followed by 0x230ull
        const auto fde_id_pos = static_cast<std::uint32_t>(eh.size() + 4u);
        const std::uint32_t cie_ptr = fde_id_pos - cie3_offset;
        std::vector<std::uint8_t> bad_fde(25u, 0u);
        put64(bad_fde, 0u, 0x220ull);
        put64(bad_fde, 8u, 0x10ull);
        bad_fde[16u] = 2u; // truncated fde_aug_len!
        put64(bad_fde, 17u, 0x230ull);
        append_record(cie_ptr, bad_fde);
    }
    // Zero terminator
    eh.resize(eh.size() + 4u, 0u);

    const auto elf_bytes = build_eh_frame_elf(eh);
    const auto img = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(img.has_value()) << img.error().message;

    const peelf::HandlersReport report = peelf::inspect_handlers(img->get(), elf_bytes);
    std::vector<std::uint64_t> personalities;
    for (const auto& entry : report.entries) {
        if (entry.category == peelf::HandlerCategory::ElfEhFramePersonality) {
            personalities.push_back(entry.handler_address);
            EXPECT_NE(entry.lsda_or_data_address, std::optional<std::uint64_t>(0x230ull));
        }
    }
    // Expect exactly CIE #3 + valid FDE #1 (both with personality 0x220); malformed CIE #1 (0x208),
    // malformed CIE #2 (0x210), and truncated FDE #2 (LSDA 0x230) must all be rejected!
    ASSERT_EQ(personalities.size(), 2u);
    EXPECT_EQ(personalities[0], 0x220ull);
    EXPECT_EQ(personalities[1], 0x220ull);
}

TEST(DemangleLimitsTest, CapsDeepMsvcNestedTemplateRecursionAndRustBackrefAmplification) {
    // 1. Shallow nested MSVC template (`?$Outer@V?$Inner@H@@`) succeeds cleanly.
    {
        const peelf::DemangleResult shallow = peelf::demangle_symbol("?fn@?$Outer@V?$Inner@H@@@@YAXXZ");
        EXPECT_TRUE(shallow.succeeded);
        EXPECT_NE(shallow.demangled.find("Outer<"), std::string::npos);
        EXPECT_NE(shallow.demangled.find("Inner<int>"), std::string::npos);
    }

    // 2. Deeply nested MSVC `?$T@...` (> kMaxDemangleDepth = 64) must terminate safely without stack overflow.
    {
        std::string deep = "?fn@";
        constexpr std::size_t kNesting = 160u;
        for (std::size_t i = 0; i < kNesting; ++i) {
            deep += "?$Node@V";
        }
        deep += "Leaf@@";
        for (std::size_t i = 0; i < kNesting; ++i) {
            deep += "@@";
        }
        deep += "YAXXZ";

        const peelf::DemangleResult res = peelf::demangle_symbol(deep);
        EXPECT_FALSE(res.succeeded);
        EXPECT_EQ(peelf::demangle_or_raw(deep), deep);
    }

    // 3. Rust v0 exponential backreference amplification (`B...` doubling path segments 20 times)
    //    must fail cleanly within the shared output budget rather than allocating megabytes/gigabytes.
    {
        auto encode_base62 = [](std::size_t idx) {
            if (idx == 0u) {
                return std::string("B_");
            }
            std::size_t n = idx - 1u;
            std::string digits;
            do {
                const std::size_t rem = n % 62u;
                n /= 62u;
                char ch = '0';
                if (rem < 10u) ch = static_cast<char>('0' + rem);
                else if (rem < 36u) ch = static_cast<char>('a' + (rem - 10u));
                else ch = static_cast<char>('A' + (rem - 36u));
                digits.push_back(ch);
            } while (n > 0u);
            std::ranges::reverse(digits);
            return "B" + digits + "_";
        };

        std::string sym = "_RINtC4core4bomb";
        std::vector<std::size_t> type_offsets;
        type_offsets.push_back(sym.size() - 2u);
        sym += "NtC4core24aaaaaaaaaaaaaaaaaaaaaaaa";
        for (std::size_t level = 0; level < 20u; ++level) {
            const std::size_t prev_off = type_offsets.back();
            type_offsets.push_back(sym.size() - 2u);
            const std::string br = encode_base62(prev_off);
            sym += "INtC4core4pair";
            sym += br;
            sym += br;
            sym += "E";
        }
        sym += "E";

        ASSERT_LT(sym.size(), 512u);
        const peelf::DemangleResult bomb_res = peelf::demangle_symbol(sym);
        EXPECT_FALSE(bomb_res.succeeded);
        EXPECT_LE(bomb_res.demangled.size(), 65536u);
    }
}

