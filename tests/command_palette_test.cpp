#include "ui/command_palette.hpp"

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "analysis/strings_index.hpp"
#include "analysis/structure_interpreter.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/data_types.hpp"
#include "symbols/symbol_index.hpp"
#include "ui/workspace_layout.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>
#include <peelf/security_audit.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace viewer {
namespace {

class SyntheticBinaryImage final : public peelf::IBinaryImage {
public:
    SyntheticBinaryImage() {
        sections_.push_back(peelf::Section{
            .name = ".text",
            .virtual_address = 0x140001000ULL,
            .virtual_size = 0x2000ULL,
            .file_offset = 0x400ULL,
            .file_size = 0x2000ULL,
            .readable = true,
            .writable = false,
            .executable = true,
        });
        sections_.push_back(peelf::Section{
            .name = ".rdata",
            .virtual_address = 0x140003000ULL,
            .virtual_size = 0x1000ULL,
            .file_offset = 0x2400ULL,
            .file_size = 0x1000ULL,
            .readable = true,
            .writable = false,
            .executable = false,
        });
        sections_.push_back(peelf::Section{
            .name = "__TEXT,__text",
            .virtual_address = 0x140005000ULL,
            .virtual_size = 0x800ULL,
            .file_offset = 0x3400ULL,
            .file_size = 0x800ULL,
            .readable = true,
            .writable = false,
            .executable = true,
        });
    }

    [[nodiscard]] peelf::Format format() const noexcept override { return peelf::Format::PE; }
    [[nodiscard]] peelf::ImageKind kind() const noexcept override { return peelf::ImageKind::Executable; }
    [[nodiscard]] peelf::Architecture architecture() const noexcept override {
        return peelf::Architecture::X86_64;
    }
    [[nodiscard]] peelf::Endianness endianness() const noexcept override {
        return peelf::Endianness::Little;
    }
    [[nodiscard]] bool is_64bit() const noexcept override { return true; }
    [[nodiscard]] std::uint64_t image_base() const noexcept override { return 0x140000000ULL; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return 0x140001000ULL; }

    [[nodiscard]] const std::vector<peelf::Section>& sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] const std::vector<peelf::Segment>& segments() const noexcept override {
        return segments_;
    }
    [[nodiscard]] const std::vector<peelf::Symbol>& symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] const std::vector<peelf::ImportEntry>& imports() const noexcept override {
        return imports_;
    }
    [[nodiscard]] const std::vector<peelf::ExportEntry>& exports() const noexcept override {
        return exports_;
    }

    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override {
        for (const auto& sec : sections_) {
            if (file_offset >= sec.file_offset && file_offset < sec.file_offset + sec.file_size) {
                return sec.virtual_address + (file_offset - sec.file_offset);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept override {
        for (const auto& sec : sections_) {
            if (virtual_address >= sec.virtual_address &&
                virtual_address < sec.virtual_address + sec.virtual_size) {
                const std::uint64_t delta = virtual_address - sec.virtual_address;
                if (delta < sec.file_size) {
                    return sec.file_offset + delta;
                }
            }
        }
        return std::nullopt;
    }

private:
    std::vector<peelf::Section> sections_{};
    std::vector<peelf::Segment> segments_{};
    std::vector<peelf::Symbol> symbols_{};
    std::vector<peelf::ImportEntry> imports_{};
    std::vector<peelf::ExportEntry> exports_{};
};

[[nodiscard]] std::vector<std::uint8_t> read_fixture_bytes(const std::string& filename) {
    const std::filesystem::path path = std::filesystem::path(PEELF_TEST_FIXTURES_DIR) / filename;
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file.good()) << path.string();
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

// ---------------------------------------------------------------------------
// 1. Fuzzy Scorer (`fuzzy_match_score`)
// ---------------------------------------------------------------------------

TEST(CommandPaletteFuzzyTest, EnforcesStrictTierOrderingExactPrefixBoundarySubstringSubsequence) {
    const auto exact = fuzzy_match_score("Memory Heatmap", "Memory Heatmap");
    const auto prefix = fuzzy_match_score("Memory Heatmap", "Memory Heatmap Panel");
    const auto boundary = fuzzy_match_score("memhm", "Memory Heatmap");
    const auto substring = fuzzy_match_score("heatmap", "Process Memory Heatmap");
    const auto subseq = fuzzy_match_score("mryhtp", "Memory Heatmap");

    ASSERT_TRUE(exact.has_value());
    ASSERT_TRUE(prefix.has_value());
    ASSERT_TRUE(boundary.has_value());
    ASSERT_TRUE(substring.has_value());
    ASSERT_TRUE(subseq.has_value());

    EXPECT_GT(*exact, *prefix);
    EXPECT_GT(*prefix, *boundary);
    EXPECT_GT(*boundary, *substring);
    EXPECT_GT(*substring, *subseq);

    // Also verify score ordering for identical query `"mem"` across all tiers:
    const auto q_exact = fuzzy_match_score("mem", "Mem");
    const auto q_prefix = fuzzy_match_score("mem", "Memory Heatmap");
    const auto q_boundary = fuzzy_match_score("mem", "Main Execution Map");
    const auto q_word_substr = fuzzy_match_score("mem", "Virtual Memory");
    const auto q_substring = fuzzy_match_score("mem", "InmemBuffer");
    const auto q_subseq = fuzzy_match_score("mem", "Module Enumerator");

    ASSERT_TRUE(q_exact.has_value());
    ASSERT_TRUE(q_prefix.has_value());
    ASSERT_TRUE(q_boundary.has_value());
    ASSERT_TRUE(q_word_substr.has_value());
    ASSERT_TRUE(q_substring.has_value());
    ASSERT_TRUE(q_subseq.has_value());

    EXPECT_GT(*q_exact, *q_prefix);
    EXPECT_GT(*q_prefix, *q_boundary);
    EXPECT_GT(*q_boundary, *q_word_substr);
    EXPECT_GT(*q_word_substr, *q_substring);
    EXPECT_GT(*q_substring, *q_subseq);
}

TEST(CommandPaletteFuzzyTest, SupportsCamelCaseUnderscoreAcronymsCaseInsensitivityAndHighlightSpans) {
    FuzzyMatchResult camel_match{};
    const auto camel_score =
        fuzzy_match_score("g2va", "Go2VirtualAddress", &camel_match);
    ASSERT_TRUE(camel_score.has_value());
    EXPECT_EQ(camel_match.indices().size(), 4u);

    FuzzyMatchResult sub_match{};
    const auto sub_score = fuzzy_match_score("sub_401", "sub_401000", &sub_match);
    ASSERT_TRUE(sub_score.has_value());
    const auto spans = sub_match.highlight_spans();
    ASSERT_EQ(spans.size(), 1u);
    EXPECT_EQ(spans[0].offset, 0u);
    EXPECT_EQ(spans[0].length, 7u);

    FuzzyMatchResult hm_match{};
    const auto lower_score = fuzzy_match_score("memhm", "Memory Heatmap", &hm_match);
    const auto upper_score = fuzzy_match_score("MEMHM", "Memory Heatmap");
    ASSERT_TRUE(lower_score.has_value());
    ASSERT_TRUE(upper_score.has_value());
    EXPECT_EQ(*lower_score, *upper_score);

    // "mem" at [0, 3) and "hm" -> 'H' at [7, 8) + 'm' at [11, 12)
    const auto hm_spans = hm_match.highlight_spans();
    ASSERT_GE(hm_spans.size(), 2u);
    EXPECT_EQ(hm_spans.front().offset, 0u);
    EXPECT_EQ(hm_spans.front().length, 3u);
    for (const auto& sp : hm_spans) {
        EXPECT_GT(sp.length, 0u);
        EXPECT_LE(static_cast<std::size_t>(sp.offset) + sp.length,
                  std::string_view("Memory Heatmap").size());
    }

    // Empty query succeeds with zero score and empty spans; impossible queries fail cleanly.
    FuzzyMatchResult empty_match{};
    const auto empty_score = fuzzy_match_score("", "Memory Heatmap", &empty_match);
    ASSERT_TRUE(empty_score.has_value());
    EXPECT_EQ(*empty_score, 0);
    EXPECT_TRUE(empty_match.indices().empty());
    EXPECT_TRUE(empty_match.highlight_spans().empty());

    EXPECT_FALSE(fuzzy_match_score("zzz", "Memory Heatmap").has_value());
    EXPECT_FALSE(fuzzy_match_score("nonempty", "").has_value());
    EXPECT_FALSE(fuzzy_match_score("longer_than_cand", "short").has_value());
}

// ---------------------------------------------------------------------------
// 2. Address & Symbol Expression Evaluator (`evaluate_address_expression`)
// ---------------------------------------------------------------------------

TEST(CommandPaletteExprTest, EvaluatesLiteralsPrefixesBuiltinsSectionsModulesSymbolsAndParentheses) {
    const SyntheticBinaryImage image{};

    SymbolIndex symbols{};
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "main",
        .raw_name = "main",
        .demangled_name = "main",
        .source = SymbolSource::Export,
        .virtual_address = 0x140001100ULL,
        .file_offset = 0x500ULL,
        .size = 0x80ULL,
    });
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "_ZN2ns6Widget3runEiPPc",
        .raw_name = "_ZN2ns6Widget3runEiPPc",
        .demangled_name = "int ns::Widget::run(int, char**) const",
        .source = SymbolSource::DebugSymbol,
        .virtual_address = 0x140001500ULL,
        .file_offset = 0x900ULL,
        .size = 0x64ULL,
    });
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "_RNvMNtCs123_5alloc3vecINtB2_3VechE4push",
        .raw_name = "_RNvMNtCs123_5alloc3vecINtB2_3VechE4push",
        .demangled_name = "alloc::vec::Vec<u8>::push",
        .source = SymbolSource::ImageSymbol,
        .virtual_address = 0x140001700ULL,
        .file_offset = 0xB00ULL,
        .size = 0x40ULL,
    });
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "KERNEL32.dll!CreateFileW",
        .raw_name = "KERNEL32.dll!CreateFileW",
        .demangled_name = "KERNEL32.dll!CreateFileW",
        .source = SymbolSource::Import,
        .virtual_address = 0x140003100ULL,
        .file_offset = 0x2500ULL,
        .size = 8ULL,
        .library = "KERNEL32.dll",
    });

    AnnotationStore annotations{};
    annotations.set(0x140001900ULL, "decrypt_payload", "XOR loop entry");

    const std::vector<Bookmark> bookmarks{
        Bookmark{
            .address = 0x140001A00ULL,
            .is_file_offset = false,
            .label = "tls_init_hook",
            .category = "Persistence",
            .note = "Suspicious TLS callback",
        },
        Bookmark{
            .address = 0x40ULL,
            .is_file_offset = true,
            .label = "dos_stub_mark",
            .category = "Headers",
            .note = "Unmapped DOS stub",
        },
    };

    const std::vector<peelf::ModuleInfo> modules{
        peelf::ModuleInfo{
            .name = "kernel32.dll",
            .path = "C:\\Windows\\System32\\kernel32.dll",
            .base_address = 0x7FF810000000ULL,
            .size = 0xBC000ULL,
        },
        peelf::ModuleInfo{
            .name = "libc.so.6",
            .path = "/lib/x86_64-linux-gnu/libc.so.6",
            .base_address = 0x7F1234000000ULL,
            .size = 0x1E0000ULL,
        },
    };

    peelf::RegisterValue rax_reg{};
    rax_reg.name = "rax";
    rax_reg.value_u64 = 0x140001234ULL;
    const std::vector<peelf::RegisterValue> extra_regs{rax_reg};

    AddressExpressionContext ctx{};
    ctx.image = &image;
    ctx.file_size = 0x8000ULL;
    ctx.symbols = &symbols;
    ctx.annotations = &annotations;
    ctx.bookmarks = bookmarks;
    ctx.modules = modules;
    ctx.instruction_pointer = 0x140001120ULL;
    ctx.stack_pointer = 0x7FFEFFFFE000ULL;
    ctx.frame_pointer = 0x7FFEFFFFE080ULL;
    ctx.registers = extra_regs;

    // Hex & decimal literals
    {
        const auto r1 = evaluate_address_expression("0x140001000", ctx);
        ASSERT_TRUE(r1.has_value()) << r1.error().message;
        EXPECT_EQ(r1->virtual_address, 0x140001000ULL);
        EXPECT_EQ(r1->file_offset, 0x400ULL);
        EXPECT_FALSE(r1->is_file_offset_only);

        const auto r2 = evaluate_address_expression("140001000h", ctx);
        ASSERT_TRUE(r2.has_value()) << r2.error().message;
        EXPECT_EQ(r2->virtual_address, 0x140001000ULL);

        const auto r3 = evaluate_address_expression("$401000", ctx);
        ASSERT_TRUE(r3.has_value()) << r3.error().message;
        EXPECT_EQ(r3->virtual_address, 0x401000ULL);

        const auto r4 = evaluate_address_expression("4096", ctx);
        ASSERT_TRUE(r4.has_value()) << r4.error().message;
        EXPECT_EQ(r4->virtual_address, 4096ULL);
    }

    // Explicit `va:`, `rva:`, `off:`, `file:` prefixes
    {
        const auto va_res = evaluate_address_expression("va:0x140001040", ctx);
        ASSERT_TRUE(va_res.has_value()) << va_res.error().message;
        EXPECT_EQ(va_res->virtual_address, 0x140001040ULL);
        EXPECT_EQ(va_res->file_offset, 0x440ULL);

        const auto rva_res = evaluate_address_expression("rva:0x1000 + 0x20", ctx);
        ASSERT_TRUE(rva_res.has_value()) << rva_res.error().message;
        EXPECT_EQ(rva_res->virtual_address, 0x140001020ULL);
        EXPECT_EQ(rva_res->file_offset, 0x420ULL);

        const auto mapped_off = evaluate_address_expression("off:0x400 + 0x10", ctx);
        ASSERT_TRUE(mapped_off.has_value()) << mapped_off.error().message;
        EXPECT_EQ(mapped_off->file_offset, 0x410ULL);
        EXPECT_EQ(mapped_off->virtual_address, 0x140001010ULL);
        EXPECT_FALSE(mapped_off->is_file_offset_only);

        const auto unmapped_off = evaluate_address_expression("file:0x40", ctx);
        ASSERT_TRUE(unmapped_off.has_value()) << unmapped_off.error().message;
        EXPECT_EQ(unmapped_off->file_offset, 0x40ULL);
        EXPECT_FALSE(unmapped_off->virtual_address.has_value());
        EXPECT_TRUE(unmapped_off->is_file_offset_only);
    }

    // Built-in tokens (`$entry`, `entry`, `$base`, `image_base`, `$pc`, `$ip`, `$sp`, `$rax`)
    {
        EXPECT_EQ(evaluate_address_expression("$entry + 0x10", ctx)->virtual_address,
                  0x140001010ULL);
        EXPECT_EQ(evaluate_address_expression("entry", ctx)->virtual_address, 0x140001000ULL);
        EXPECT_EQ(evaluate_address_expression("image_base + 0x1050", ctx)->virtual_address,
                  0x140001050ULL);
        EXPECT_EQ(evaluate_address_expression("$base + 0x3000", ctx)->virtual_address,
                  0x140003000ULL);
        EXPECT_EQ(evaluate_address_expression("$pc + 4", ctx)->virtual_address, 0x140001124ULL);
        EXPECT_EQ(evaluate_address_expression("$ip - 0x20", ctx)->virtual_address,
                  0x140001100ULL);
        EXPECT_EQ(evaluate_address_expression("$sp + 0x18", ctx)->virtual_address,
                  0x7FFEFFFFE018ULL);
        EXPECT_EQ(evaluate_address_expression("$rax + 0xC", ctx)->virtual_address,
                  0x140001240ULL);
    }

    // Section & module names
    {
        const auto sec1 = evaluate_address_expression(".text + 0x120", ctx);
        ASSERT_TRUE(sec1.has_value()) << sec1.error().message;
        EXPECT_EQ(sec1->virtual_address, 0x140001120ULL);
        EXPECT_EQ(sec1->file_offset, 0x520ULL);

        const auto sec2 = evaluate_address_expression("__TEXT,__text + 0x40", ctx);
        ASSERT_TRUE(sec2.has_value()) << sec2.error().message;
        EXPECT_EQ(sec2->virtual_address, 0x140005040ULL);

        const auto mod1 = evaluate_address_expression("kernel32.dll + 0x1000", ctx);
        ASSERT_TRUE(mod1.has_value()) << mod1.error().message;
        EXPECT_EQ(mod1->virtual_address, 0x7FF810001000ULL);

        const auto mod2 = evaluate_address_expression("libc.so.6 + 0x80", ctx);
        ASSERT_TRUE(mod2.has_value()) << mod2.error().message;
        EXPECT_EQ(mod2->virtual_address, 0x7F1234000080ULL);
    }

    // Raw & demangled C++/Rust symbols, imports, annotations, bookmarks, and parentheses
    {
        const auto main_off = evaluate_address_expression("main + 0x24", ctx);
        ASSERT_TRUE(main_off.has_value()) << main_off.error().message;
        EXPECT_EQ(main_off->virtual_address, 0x140001124ULL);

        const auto cpp_sym = evaluate_address_expression("ns::Widget::run + 0x10", ctx);
        ASSERT_TRUE(cpp_sym.has_value()) << cpp_sym.error().message;
        EXPECT_EQ(cpp_sym->virtual_address, 0x140001510ULL);

        const auto raw_cpp = evaluate_address_expression("_ZN2ns6Widget3runEiPPc + 8", ctx);
        ASSERT_TRUE(raw_cpp.has_value()) << raw_cpp.error().message;
        EXPECT_EQ(raw_cpp->virtual_address, 0x140001508ULL);

        const auto rust_sym = evaluate_address_expression("alloc::vec::Vec<u8>::push + 0x10", ctx);
        ASSERT_TRUE(rust_sym.has_value()) << rust_sym.error().message;
        EXPECT_EQ(rust_sym->virtual_address, 0x140001710ULL);

        const auto quoted_cpp = evaluate_address_expression(
            "`int ns::Widget::run(int, char**) const` + 0x14", ctx);
        ASSERT_TRUE(quoted_cpp.has_value()) << quoted_cpp.error().message;
        EXPECT_EQ(quoted_cpp->virtual_address, 0x140001514ULL);

        const auto paren_imp = evaluate_address_expression("(CreateFileW + 0x10) - 4", ctx);
        ASSERT_TRUE(paren_imp.has_value()) << paren_imp.error().message;
        EXPECT_EQ(paren_imp->virtual_address, 0x14000310CULL);

        const auto annot = evaluate_address_expression("decrypt_payload + 0x18", ctx);
        ASSERT_TRUE(annot.has_value()) << annot.error().message;
        EXPECT_EQ(annot->virtual_address, 0x140001918ULL);

        const auto bm_va = evaluate_address_expression("tls_init_hook + 4", ctx);
        ASSERT_TRUE(bm_va.has_value()) << bm_va.error().message;
        EXPECT_EQ(bm_va->virtual_address, 0x140001A04ULL);

        const auto bm_off = evaluate_address_expression("dos_stub_mark + 0x10", ctx);
        ASSERT_TRUE(bm_off.has_value()) << bm_off.error().message;
        EXPECT_EQ(bm_off->file_offset, 0x50ULL);
        EXPECT_TRUE(bm_off->is_file_offset_only);
    }
}

TEST(CommandPaletteExprTest, RejectsOverflowUnderflowUnknownSymbolsAndMalformedSyntaxWithoutUB) {
    const SyntheticBinaryImage image{};
    AddressExpressionContext ctx{};
    ctx.image = &image;
    ctx.file_size = 0x4000ULL;

    EXPECT_FALSE(evaluate_address_expression("", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("   ", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("0xFFFFFFFFFFFFFFFF + 1", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("0x1000 - 0x2000", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("-0x10", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("unknown_symbol_xyz + 4", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("(0x1000 + 4", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("0x1000 + 4)", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("$pc", ctx).has_value());
    EXPECT_FALSE(evaluate_address_expression("off:0x5000", ctx).has_value());

    AddressExpressionContext headless_ctx{};
    EXPECT_FALSE(evaluate_address_expression("rva:0x1000", headless_ctx).has_value());
}

// ---------------------------------------------------------------------------
// 3. Unified Command Palette Prefix Modes, MRU & 100k Scalability
// ---------------------------------------------------------------------------

TEST(CommandPaletteCatalogTest, PrefixModesFilterPanelsPresetsCommandsSymbolsStringsTypesAndRules) {
    // Verify prefix parser across every documented shortcut mode
    EXPECT_EQ(parse_palette_query("memhm").mode, PalettePrefixMode::Omni);
    EXPECT_EQ(parse_palette_query(">reset").mode, PalettePrefixMode::Commands);
    EXPECT_EQ(parse_palette_query("> reset").filter, "reset");
    EXPECT_EQ(parse_palette_query("@Widget").mode, PalettePrefixMode::Symbols);
    EXPECT_EQ(parse_palette_query("#http").mode, PalettePrefixMode::Strings);
    EXPECT_EQ(parse_palette_query(":main + 0x20").mode, PalettePrefixMode::GoToAddress);
    EXPECT_EQ(parse_palette_query("struct:IMAGE_DOS").mode, PalettePrefixMode::Types);
    EXPECT_EQ(parse_palette_query("type: CustomHdr").mode, PalettePrefixMode::Types);
    EXPECT_EQ(parse_palette_query("?PE1001").mode, PalettePrefixMode::BookmarksAndRules);
    EXPECT_EQ(parse_palette_query("*tls").mode, PalettePrefixMode::BookmarksAndRules);

    // Build rich data sources using a real fixture image + FunctionIndex + StringsIndex
    const std::vector<std::uint8_t> elf_bytes = read_fixture_bytes("known-linux-x64.elf");
    auto parsed = peelf::parse_image(elf_bytes);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const peelf::IBinaryImage& elf_img = **parsed;

    SymbolIndex symbols = SymbolIndex::build(elf_img);
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "_ZN4core6cipher7decryptEPhm",
        .raw_name = "_ZN4core6cipher7decryptEPhm",
        .demangled_name = "core::cipher::decrypt(unsigned char*, unsigned long)",
        .source = SymbolSource::DebugSymbol,
        .virtual_address = elf_img.entry_point() + 0x40ULL,
        .file_offset = 0x80ULL,
        .size = 0x30ULL,
    });
    FunctionIndex functions = FunctionIndex::discover(elf_img, symbols, elf_bytes);

    AnnotationStore annotations{};
    annotations.set(elf_img.entry_point() + 0x80ULL, "stage2_dispatcher", "Unpacked jump table");

    const std::string_view raw_str_blob =
        "https://telemetry.example.invalid/v1\0SecretApiTokenHeader\0";
    const std::span<const std::uint8_t> str_span(
        reinterpret_cast<const std::uint8_t*>(raw_str_blob.data()), raw_str_blob.size());
    const StringsIndex strings = StringsIndex::extract_from_buffer(
        str_span, 0x402000ULL, 0x2000ULL, ".rodata");

    const std::vector<DataTypeRecord> debug_types{
        DataTypeRecord{
            .name = "CustomPacketHeader",
            .size = 24ULL,
            .is_union = false,
            .members = {
                DataMember{.name = "magic", .type = "uint32_t", .offset = 0, .size = 4},
                DataMember{.name = "payload_len", .type = "uint32_t", .offset = 4, .size = 4},
            },
        },
    };
    const StructureCatalog struct_catalog = StructureCatalog::build(debug_types, {}, true);

    const std::vector<Bookmark> bookmarks{
        Bookmark{
            .address = elf_img.entry_point(),
            .is_file_offset = false,
            .label = "entry_guard_check",
            .category = "Security",
            .note = "Stack cookie check",
        },
    };

    peelf::SecurityAuditReport audit{};
    audit.findings.push_back(peelf::SecurityFinding{
        .rule_id = "PE1001",
        .rule_name = "Dynamic Base (ASLR)",
        .domain = peelf::SecurityRuleDomain::PE,
        .severity = peelf::SecuritySeverity::Warning,
        .subject = "OptionalHeader.DllCharacteristics",
        .summary = "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is clear",
        .virtual_address = elf_img.entry_point(),
    });

    PaletteDataSources sources{};
    sources.expr_context.image = &elf_img;
    sources.expr_context.file_size = elf_bytes.size();
    sources.expr_context.symbols = &symbols;
    sources.expr_context.functions = &functions;
    sources.expr_context.annotations = &annotations;
    sources.expr_context.bookmarks = bookmarks;
    sources.functions = &functions;
    sources.symbols = &symbols;
    sources.annotations = &annotations;
    sources.strings = &strings;
    sources.structure_catalog = &struct_catalog;
    sources.debug_types = debug_types;
    sources.bookmarks = bookmarks;
    sources.security_audit = &audit;
    sources.has_file = true;
    sources.active_preset = WorkspacePreset::StaticReverseEngineering;

    CommandPalette palette{};

    // `>` mode: verify all 38 panels + all 5 presets + all required commands are discoverable!
    {
        const auto all_cmds = palette.query(">", sources, PaletteQueryOptions{.max_results = 128});
        std::unordered_set<WorkspacePanelId> seen_panels{};
        std::unordered_set<WorkspacePreset> seen_presets{};
        std::unordered_set<PaletteCommandId> seen_cmd_ids{};
        for (const auto& item : all_cmds.items) {
            if (item.primary_action.kind == PaletteActionKind::FocusPanel) {
                seen_panels.insert(item.primary_action.panel_id);
            } else if (item.primary_action.kind == PaletteActionKind::ApplyWorkspacePreset) {
                seen_presets.insert(item.primary_action.preset);
            } else if (item.primary_action.kind == PaletteActionKind::RunCommand) {
                seen_cmd_ids.insert(item.primary_action.command_id);
            }
        }
        EXPECT_EQ(seen_panels.size(), kWorkspacePanelCount);
        EXPECT_EQ(seen_presets.size(), kWorkspacePresetCount);
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::ResetWorkspaceLayout));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::OpenBinary));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::AttachToProcess));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::ConnectGdbRemote));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::OpenCrashDump));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::OpenDebugSymbols));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::SaveProject));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::SavePatchedAs));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::DecompileCurrentFunction));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::ScanFullReferences));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::ToggleDemangleSymbols));
        EXPECT_TRUE(seen_cmd_ids.contains(PaletteCommandId::SwitchFlowGraphGalaxy));
    }

    // `@` mode: matches demangled C++ symbols, raw mangled names, and AnnotationStore labels
    {
        const auto sym_demangled = palette.query("@cipher::decrypt", sources);
        ASSERT_FALSE(sym_demangled.items.empty());
        EXPECT_NE(sym_demangled.items.front().title.find("core::cipher::decrypt"), std::string::npos);

        const auto sym_raw = palette.query("@_ZN4core6cipher", sources);
        ASSERT_FALSE(sym_raw.items.empty());
        EXPECT_EQ(sym_raw.items.front().primary_action.target_address,
                  elf_img.entry_point() + 0x40ULL);

        const auto annot_hit = palette.query("@stage2_disp", sources);
        ASSERT_FALSE(annot_hit.items.empty());
        EXPECT_EQ(annot_hit.items.front().title, "stage2_dispatcher");
    }

    // `#` mode: searches extracted strings
    {
        const auto str_res = palette.query("#telemetry.example", sources);
        ASSERT_FALSE(str_res.items.empty());
        EXPECT_EQ(str_res.items.front().category, PaletteCategory::String);
        EXPECT_EQ(str_res.items.front().primary_action.target_address, 0x402000ULL);
    }

    // `type:` & `struct:` modes: searches built-in catalog + loaded debug types
    {
        const auto builtin_type = palette.query("struct:IMAGE_DOS_HEADER", sources);
        ASSERT_FALSE(builtin_type.items.empty());
        EXPECT_EQ(builtin_type.items.front().category, PaletteCategory::Type);
        EXPECT_EQ(builtin_type.items.front().primary_action.kind,
                  PaletteActionKind::OpenStructureView);

        const auto user_type = palette.query("type:CustomPacketHeader", sources);
        ASSERT_FALSE(user_type.items.empty());
        EXPECT_EQ(user_type.items.front().primary_action.type_name, "CustomPacketHeader");
    }

    // `?` and `*` modes: searches Bookmarks + active SecurityFinding + rule catalog (`ELF2001`, `MACHO4001`, `LIVE3001`)
    {
        const auto bm_res = palette.query("*entry_guard", sources);
        ASSERT_FALSE(bm_res.items.empty());
        EXPECT_EQ(bm_res.items.front().category, PaletteCategory::Bookmark);

        const auto pe_rule = palette.query("?PE1001", sources);
        ASSERT_FALSE(pe_rule.items.empty());
        EXPECT_EQ(pe_rule.items.front().category, PaletteCategory::Rule);
        EXPECT_EQ(pe_rule.items.front().primary_action.target_address, elf_img.entry_point());

        for (const std::string_view code : {"?ELF2001", "?MACHO4001", "?LIVE3001"}) {
            const auto cat_rule = palette.query(code, sources);
            ASSERT_FALSE(cat_rule.items.empty()) << code;
            EXPECT_EQ(cat_rule.items.front().category, PaletteCategory::Rule);
        }
    }

    // `:` Go-To mode and omni-expression pinning
    {
        const auto goto_res = palette.query(":$entry + 0x10", sources);
        ASSERT_TRUE(goto_res.resolved_expression.has_value());
        EXPECT_TRUE(goto_res.expression_error.empty());
        ASSERT_EQ(goto_res.items.size(), 3u);
        EXPECT_EQ(goto_res.items[0].title, "Jump in Disassembly");
        EXPECT_EQ(goto_res.items[1].title, "Jump in Hex View");
        EXPECT_EQ(goto_res.items[2].title, "Decompile at Address");
        EXPECT_TRUE(goto_res.items[2].primary_action.request_decompile);

        const auto bad_goto = palette.query(":nonexistent_sym + 4", sources);
        EXPECT_FALSE(bad_goto.resolved_expression.has_value());
        EXPECT_FALSE(bad_goto.expression_error.empty());

        const auto omni_hex = palette.query("0x401000", sources);
        ASSERT_FALSE(omni_hex.items.empty());
        EXPECT_EQ(omni_hex.items.front().category, PaletteCategory::GoTo);
        EXPECT_TRUE(omni_hex.items.front().pinned);
    }

    // Mixed Omni-search acronym + MRU boost verification
    {
        const auto memhm = palette.query("memhm", sources);
        ASSERT_FALSE(memhm.items.empty());
        EXPECT_EQ(memhm.items.front().title, "Memory Heatmap");

        const auto before_mru = palette.query(">binary", sources);
        ASSERT_GE(before_mru.items.size(), 2u);
        // Record execution of the Binary Diff preset (`preset:BinaryDiff`) and verify MRU boost promotes it!
        palette.record_execution("preset:BinaryDiff");
        EXPECT_GT(palette.mru_boost_for("preset:BinaryDiff"), 0);

        const auto after_mru = palette.query(">binary", sources);
        ASSERT_FALSE(after_mru.items.empty());
        EXPECT_EQ(after_mru.items.front().id, "preset:BinaryDiff");

        palette.clear_mru();
        EXPECT_EQ(palette.mru_boost_for("preset:BinaryDiff"), 0);
    }
}

TEST(CommandPaletteScalabilityTest, BoundedRankingHandles100kSymbolsQuicklyWithinTop64Cap) {
    SymbolIndex huge_symbols{};
    for (std::size_t i = 0u; i < 100000u; ++i) {
        std::string sym_name = (i == 98765u)
                                   ? "needle_crypto_aes_gcm_encrypt"
                                   : std::format("sub_autogen_{:06d}", i);
        huge_symbols.add_discovered_symbol(SymbolRecord{
            .name = sym_name,
            .raw_name = sym_name,
            .demangled_name = sym_name,
            .source = SymbolSource::ImageSymbol,
            .virtual_address = 0x140010000ULL + static_cast<std::uint64_t>(i) * 16ULL,
            .file_offset = 0x1000ULL + static_cast<std::uint64_t>(i) * 16ULL,
            .size = 16ULL,
        });
    }

    PaletteDataSources sources{};
    sources.symbols = &huge_symbols;
    sources.expr_context.symbols = &huge_symbols;

    const CommandPalette palette{};
    const auto t0 = std::chrono::steady_clock::now();
    const PaletteQueryResult res = palette.query("@aesgcm", sources);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();

    ASSERT_FALSE(res.items.empty());
    EXPECT_LE(res.items.size(), kDefaultPaletteMaxResults);
    EXPECT_EQ(res.items.front().title, "needle_crypto_aes_gcm_encrypt");
    EXPECT_EQ(res.items.front().primary_action.target_address,
              0x140010000ULL + 98765ULL * 16ULL);

    // Bounded heap scan across 100k symbols stays fast even in unoptimized debug builds.
    EXPECT_LT(elapsed_ms, 500);

    const PaletteQueryResult prefix_res = palette.query("@sub_autogen_0999", sources);
    EXPECT_EQ(prefix_res.items.size(), kDefaultPaletteMaxResults);
}

// ---------------------------------------------------------------------------
// 4. `P7-10` Navigation History & Deferred Queue Integration
// ---------------------------------------------------------------------------

TEST(CommandPaletteNavigationP7_10, RoutesPaletteActionsThroughDeferredQueueAndNavigationHistory) {
    const SyntheticBinaryImage image{};
    SymbolIndex symbols{};
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "main",
        .raw_name = "main",
        .demangled_name = "main",
        .source = SymbolSource::Export,
        .virtual_address = 0x140001100ULL,
        .file_offset = 0x500ULL,
        .size = 0x80ULL,
    });
    symbols.add_discovered_symbol(SymbolRecord{
        .name = "_ZN2ns6Widget3runEv",
        .raw_name = "_ZN2ns6Widget3runEv",
        .demangled_name = "ns::Widget::run()",
        .source = SymbolSource::DebugSymbol,
        .virtual_address = 0x140001500ULL,
        .file_offset = 0x900ULL,
        .size = 0x48ULL,
    });

    const std::string_view str_blob = "LicenseValidationFailed\0";
    const StringsIndex strings = StringsIndex::extract_from_buffer(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(str_blob.data()), str_blob.size()),
        0x140003200ULL,
        0x2600ULL,
        ".rdata");

    PaletteDataSources sources{};
    sources.expr_context.image = &image;
    sources.expr_context.file_size = 0x8000ULL;
    sources.expr_context.symbols = &symbols;
    sources.symbols = &symbols;
    sources.strings = &strings;
    sources.has_file = true;

    CommandPalette palette{};
    NavigationRequestQueue nav_queue{};
    NavigationHistory history{};
    bool decompile_triggered = false;

    ViewerSelection current{
        .kind = SelectionKind::Symbol,
        .label = "entry",
        .file_offset = 0x400ULL,
        .virtual_address = 0x140001000ULL,
        .size = 16ULL,
        .preferred_view = PreferredView::Disassembly,
    };
    history.visit(current);

    const auto drain_into_history = [&]() {
        (void)nav_queue.drain([&](const DeferredNavigationRequest& req) {
            if (req.kind == DeferredNavigationRequest::Kind::Address) {
                current = ViewerSelection{
                    .kind = SelectionKind::ByteRange,
                    .label = std::format("0x{:X}", req.target),
                    .file_offset = image.virtual_address_to_file_offset(req.target),
                    .virtual_address = req.target,
                    .size = req.highlight_size,
                    .preferred_view = req.preferred_view,
                };
                decompile_triggered = req.request_decompile;
                history.visit(current);
            } else if (req.kind == DeferredNavigationRequest::Kind::Offset) {
                current = ViewerSelection{
                    .kind = SelectionKind::ByteRange,
                    .label = std::format("off 0x{:X}", req.target),
                    .file_offset = req.target,
                    .virtual_address = image.file_offset_to_virtual_address(req.target),
                    .size = req.highlight_size,
                    .preferred_view = req.preferred_view,
                };
                decompile_triggered = req.request_decompile;
                history.visit(current);
            }
        });
    };

    // Step 1: `:main + 0x24` -> Enter (`primary_action`: Disassembly @ 0x140001124)
    {
        const auto res = palette.query(":main + 0x24", sources);
        ASSERT_FALSE(res.items.empty());
        const auto nav_req = build_palette_navigation_request(res.items.front().primary_action);
        ASSERT_TRUE(nav_req.has_value());
        nav_queue.enqueue(*nav_req);
        drain_into_history();

        EXPECT_EQ(current.virtual_address, 0x140001124ULL);
        EXPECT_EQ(current.file_offset, 0x524ULL);
        EXPECT_EQ(current.preferred_view, PreferredView::Disassembly);
        EXPECT_FALSE(decompile_triggered);
    }

    // Step 2: `#LicenseValidation` -> Enter (`primary_action`: Hex @ 0x140003200 with string length)
    {
        const auto res = palette.query("#LicenseValidation", sources);
        ASSERT_FALSE(res.items.empty());
        const auto nav_req = build_palette_navigation_request(res.items.front().primary_action);
        ASSERT_TRUE(nav_req.has_value());
        nav_queue.enqueue(*nav_req);
        drain_into_history();

        EXPECT_EQ(current.virtual_address, 0x140003200ULL);
        EXPECT_EQ(current.file_offset, 0x2600ULL);
        EXPECT_EQ(current.preferred_view, PreferredView::Hex);
        EXPECT_GT(current.size, 0u);
    }

    // Step 3: `:file:0x40` -> unmapped file offset (`Kind::Offset`, Hex @ file offset 0x40)
    {
        const auto res = palette.query(":file:0x40", sources);
        ASSERT_FALSE(res.items.empty());
        const auto nav_req = build_palette_navigation_request(res.items.front().primary_action);
        ASSERT_TRUE(nav_req.has_value());
        EXPECT_EQ(nav_req->kind, DeferredNavigationRequest::Kind::Offset);
        nav_queue.enqueue(*nav_req);
        drain_into_history();

        EXPECT_EQ(current.file_offset, 0x40ULL);
        EXPECT_FALSE(current.virtual_address.has_value());
        EXPECT_EQ(current.preferred_view, PreferredView::Hex);
    }

    // Step 4: `@Widget::run` -> Ctrl+Enter (`tertiary_decompile_action` @ 0x140001500)
    {
        const auto res = palette.query("@Widget::run", sources);
        ASSERT_FALSE(res.items.empty());
        ASSERT_NE(res.items.front().tertiary_decompile_action.kind, PaletteActionKind::None);
        const auto nav_req =
            build_palette_navigation_request(res.items.front().tertiary_decompile_action);
        ASSERT_TRUE(nav_req.has_value());
        nav_queue.enqueue(*nav_req);
        drain_into_history();

        EXPECT_EQ(current.virtual_address, 0x140001500ULL);
        EXPECT_TRUE(decompile_triggered);
    }

    // Verify full P7-10 back/forward traversal across all 5 visited locations!
    ASSERT_TRUE(history.can_back());
    const auto back_to_unmapped = history.back();
    ASSERT_TRUE(back_to_unmapped.has_value());
    EXPECT_EQ(back_to_unmapped->file_offset, 0x40ULL);
    EXPECT_FALSE(back_to_unmapped->virtual_address.has_value());

    const auto back_to_string = history.back();
    ASSERT_TRUE(back_to_string.has_value());
    EXPECT_EQ(back_to_string->virtual_address, 0x140003200ULL);
    EXPECT_EQ(back_to_string->preferred_view, PreferredView::Hex);

    const auto back_to_main_plus_24 = history.back();
    ASSERT_TRUE(back_to_main_plus_24.has_value());
    EXPECT_EQ(back_to_main_plus_24->virtual_address, 0x140001124ULL);
    EXPECT_EQ(back_to_main_plus_24->preferred_view, PreferredView::Disassembly);

    const auto back_to_entry = history.back();
    ASSERT_TRUE(back_to_entry.has_value());
    EXPECT_EQ(back_to_entry->virtual_address, 0x140001000ULL);
    EXPECT_FALSE(history.can_back());

    const auto fwd_step = history.forward();
    ASSERT_TRUE(fwd_step.has_value());
    EXPECT_EQ(fwd_step->virtual_address, 0x140001124ULL);
}

} // namespace
} // namespace viewer
