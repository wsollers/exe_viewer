#include "peelf/scripting.hpp"

#include "analysis/project.hpp"
#include "headless_cli.hpp"
#include "model/binary_model.hpp"
#include "peelf/binary_image.hpp"
#include "peelf/capability_matrix.hpp"
#include "peelf/macho_image.hpp"
#include "peelf/patching.hpp"
#include "peelf/process.hpp"
#include "peelf/subprocess.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifndef PEELF_TEST_FIXTURES_DIR
#define PEELF_TEST_FIXTURES_DIR "fixtures"
#endif

#ifndef PEELF_BIN_MATRIX_DIR
#define PEELF_BIN_MATRIX_DIR "../bin-matrix"
#endif

namespace {

class TempFileGuard {
public:
    explicit TempFileGuard(std::span<const std::uint8_t> bytes) {
        static std::atomic<std::uint64_t> counter{0};
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string test_name = info != nullptr ? info->name() : "case";
        const auto nonce = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        path_ = std::filesystem::temp_directory_path() /
                std::filesystem::path(std::format(
                    "peelf_scripting_{}_{}_{}.bin",
                    test_name,
                    nonce,
                    counter.fetch_add(1u, std::memory_order_relaxed)));
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;

    TempFileGuard(TempFileGuard&& other) noexcept : path_(std::move(other.path_)) {
        other.path_.clear();
    }

    TempFileGuard& operator=(TempFileGuard&& other) noexcept {
        if (this != &other) {
            cleanup();
            path_ = std::move(other.path_);
            other.path_.clear();
        }
        return *this;
    }

    ~TempFileGuard() noexcept { cleanup(); }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    void cleanup() noexcept {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }

    std::filesystem::path path_;
};

[[nodiscard]] std::vector<std::uint8_t> read_all_bytes(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    const auto end_pos = file.tellg();
    if (end_pos <= 0) {
        return {};
    }
    const auto size = static_cast<std::size_t>(end_pos);
    std::vector<std::uint8_t> out(size);
    file.seekg(0);
    file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
    return out;
}

class MachOByteWriter {
public:
    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return buf_; }

    void pad_to(std::size_t offset, std::uint8_t fill = 0u) {
        if (buf_.size() < offset) {
            buf_.resize(offset, fill);
        }
    }

    void align_to(std::size_t alignment) {
        if (alignment <= 1u) {
            return;
        }
        const std::size_t rem = buf_.size() % alignment;
        if (rem != 0u) {
            buf_.resize(buf_.size() + (alignment - rem), 0u);
        }
    }

    void u8(std::uint8_t v) { buf_.push_back(v); }

    void u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    }

    void u32(std::uint32_t v) {
        const std::size_t off = buf_.size();
        buf_.resize(off + 4u);
        put_u32(off, v);
    }

    void u64(std::uint64_t v) {
        u32(static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
        u32(static_cast<std::uint32_t>((v >> 32u) & 0xFFFFFFFFULL));
    }

    void put_u32(std::size_t off, std::uint32_t v) {
        buf_[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
        buf_[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
        buf_[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
        buf_[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    }

    void fixed_str16(std::string_view sv) {
        const std::size_t n = std::min<std::size_t>(sv.size(), 16u);
        for (std::size_t i = 0u; i < n; ++i) {
            buf_.push_back(static_cast<std::uint8_t>(sv[i]));
        }
        for (std::size_t i = n; i < 16u; ++i) {
            buf_.push_back(0u);
        }
    }

    void raw(std::span<const std::uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    void cstr(std::string_view sv) {
        for (const char ch : sv) {
            buf_.push_back(static_cast<std::uint8_t>(ch));
        }
        buf_.push_back(0u);
    }

private:
    std::vector<std::uint8_t> buf_{};
};

// Minimal synthetic 64-bit x86_64 Mach-O executable with __TEXT,__text instructions,
// an ASCII string in __TEXT,__cstring, LC_MAIN entry point, and LC_SYMTAB `_main`.
[[nodiscard]] std::vector<std::uint8_t> make_synthetic_x86_64_macho() {
    using namespace peelf::macho;
    MachOByteWriter w;

    // mach_header_64 (32 bytes)
    w.u32(kMhMagic64);
    w.u32(kCpuTypeX86_64);
    w.u32(kCpuSubtypeX86_64All);
    w.u32(kMhExecute);
    w.u32(0u); // ncmds patched later
    w.u32(0u); // sizeofcmds patched later
    w.u32(kMhPie | kMhTwoLevel | kMhNoHeapExecution);
    w.u32(0u);

    std::uint32_t ncmds = 0u;
    const std::size_t cmds_start = w.size();

    // 1. LC_SEGMENT_64 __PAGEZERO
    w.u32(kLcSegment64);
    w.u32(72u);
    w.fixed_str16("__PAGEZERO");
    w.u64(0u);
    w.u64(0x100000000ULL);
    w.u64(0u);
    w.u64(0u);
    w.u32(kVmProtNone);
    w.u32(kVmProtNone);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 2. LC_SEGMENT_64 __TEXT with __text @ 0x100000C00 and __cstring @ 0x100000C20
    w.u32(kLcSegment64);
    w.u32(72u + 2u * 80u);
    w.fixed_str16("__TEXT");
    w.u64(0x100000000ULL);
    w.u64(0x1000ULL);
    w.u64(0u);
    w.u64(0x1000ULL);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(2u);
    w.u32(0u);

    // section_64 __text (8 bytes @ 0x100000C00, file offset 0xC00)
    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u64(0x100000C00ULL);
    w.u64(8u);
    w.u32(0xC00u);
    w.u32(4u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSAttrSomeInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // section_64 __cstring (18 bytes @ 0x100000C20, file offset 0xC20)
    w.fixed_str16("__cstring");
    w.fixed_str16("__TEXT");
    w.u64(0x100000C20ULL);
    w.u64(18u);
    w.u32(0xC20u);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);
    w.u32(0x2u); // S_CSTRING_LITERALS
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);
    ++ncmds;

    // 3. LC_MAIN pointing to entryoff 0xC00 -> VA 0x100000C00
    w.u32(kLcMain);
    w.u32(24u);
    w.u64(0xC00ULL);
    w.u64(0ULL);
    ++ncmds;

    // 4. LC_SYMTAB with 1 defined external symbol `_main` @ 0x100000C00
    w.u32(kLcSymtab);
    w.u32(24u);
    w.u32(0x1000u); // symoff
    w.u32(1u);      // nsyms
    w.u32(0x1010u); // stroff
    w.u32(8u);      // strsize
    ++ncmds;

    const std::size_t cmds_end = w.size();
    w.put_u32(16u, ncmds);
    w.put_u32(20u, static_cast<std::uint32_t>(cmds_end - cmds_start));

    // Populate __text @ 0xC00: push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
    w.pad_to(0xC00u);
    const std::array<std::uint8_t, 8> code = {
        0x55u, 0x48u, 0x89u, 0xE5u, 0x31u, 0xC0u, 0x5Du, 0xC3u};
    w.raw(code);

    // Populate __cstring @ 0xC20
    w.pad_to(0xC20u);
    w.cstr("MachOScriptMarker");

    // Populate nlist_64 @ 0x1000 and string table @ 0x1010
    w.pad_to(0x1000u);
    w.u32(1u);                  // n_strx -> "_main"
    w.u8(kNSect | kNExt);       // n_type
    w.u8(1u);                   // n_sect (1-based -> __text)
    w.u16(0u);                  // n_desc
    w.u64(0x100000C00ULL);      // n_value

    w.pad_to(0x1010u);
    w.u8(0u);
    w.cstr("_main");
    w.align_to(8u);
    return w.bytes();
}

// Read-only mock live process session verifying capability-gated mutation rejection.
class ReadOnlyMockProcessSession final : public peelf::IProcessSession {
public:
    ReadOnlyMockProcessSession() {
        info_.pid = 4242u;
        info_.name = "mock_live";
        info_.architecture = peelf::Architecture::X86_64;
        info_.endianness = peelf::Endianness::Little;
        info_.is_64bit = true;
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return std::vector<peelf::MemoryRegion>{};
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(std::uint64_t /*address*/,
                                                         std::span<std::uint8_t> buffer) override {
        std::fill(buffer.begin(), buffer.end(), std::uint8_t{0x90u});
        return buffer.size();
    }

private:
    peelf::ProcessInfo info_{};
};

struct LoadedStaticFixture {
    std::vector<std::uint8_t> raw_bytes;
    TempFileGuard temp_file;
    std::unique_ptr<peelf::IBinaryImage> image;
    peelf::PagedBinaryImage paged;
    peelf::ProjectWorkspace workspace;

    static void load_from_bytes(std::vector<std::uint8_t> bytes,
                                std::optional<LoadedStaticFixture>& out) {
        TempFileGuard guard(bytes);
        auto parsed = peelf::parse_image(bytes);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
        auto paged_res = peelf::PagedBinaryImage::open(guard.path(), 64u);
        ASSERT_TRUE(paged_res.has_value()) << paged_res.error().message;
        out.emplace(LoadedStaticFixture{
            .raw_bytes = std::move(bytes),
            .temp_file = std::move(guard),
            .image = std::move(*parsed),
            .paged = std::move(*paged_res),
            .workspace = peelf::ProjectWorkspace{},
        });
    }

    [[nodiscard]] peelf::ScriptContext make_context(bool allow_mutations = true) noexcept {
        return peelf::ScriptContext{
            .image = image.get(),
            .raw_bytes = raw_bytes,
            .paged_image = &paged,
            .workspace = &workspace,
            .allow_mutations = allow_mutations,
        };
    }
};

} // namespace

TEST(ScriptingTest, UniqueLuaStateRaiiCleanupHandlesLiveAndNullStates) {
    peelf::UniqueLuaState empty_state{nullptr};
    EXPECT_EQ(empty_state.get(), nullptr);

    auto state = peelf::make_unique_lua_state();
    ASSERT_NE(state.get(), nullptr);
    state.reset();
    EXPECT_EQ(state.get(), nullptr);
}

TEST(ScriptingTest, InspectsElfTargetMetadataSymbolsStringsDisasmAndAudit) {
    const auto elf_path =
        std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "elf-linux-x86_64-64-le-callgraph.so";
    ASSERT_TRUE(std::filesystem::exists(elf_path)) << elf_path.string();

    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(read_all_bytes(elf_path), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    constexpr std::string_view kScript = R"lua(
        local info = peelf.target_info()
        assert(info.format == "ELF", "expected ELF format, got " .. tostring(info.format))
        assert(info.arch == "x86-64", "expected x86-64 arch, got " .. tostring(info.arch))
        assert(info.bitness == 64, "expected 64-bit")
        assert(info.endianness == "little-endian", "expected little-endian")
        assert(info.is_read_only == false, "static file should be mutable")

        local caps = peelf.capabilities()
        assert(caps.ImageParsing ~= nil and caps.ImageParsing.can_execute == true)
        assert(caps.StaticPatching ~= nil and caps.StaticPatching.can_execute == true)
        assert(caps.StackUnwind ~= nil and caps.StackUnwind.can_execute == false)

        local secs = peelf.sections()
        assert(#secs > 0, "expected ELF sections")
        local text_sec = nil
        for _, s in ipairs(secs) do
            if s.name == ".text" then
                text_sec = s
                break
            end
        end
        assert(text_sec ~= nil and text_sec.executable == true, "missing executable .text")

        local segs = peelf.segments()
        assert(#segs > 0, "expected ELF PT_LOAD segments")

        local syms = peelf.symbols()
        local exps = peelf.exports()
        assert(#syms > 0 or #exps > 0, "expected symbols or exports")

        local off = peelf.va_to_offset(text_sec.virtual_address)
        assert(off == text_sec.file_offset, "va_to_offset mismatch")
        local roundtrip_va = peelf.offset_to_va(off)
        assert(roundtrip_va == text_sec.virtual_address, "offset_to_va mismatch")

        local raw = peelf.read_bytes(text_sec.virtual_address, 8)
        assert(#raw == 8, "expected 8 bytes from .text")
        local b0 = peelf.read_u8(text_sec.virtual_address)
        assert(b0 == string.byte(raw, 1), "read_u8 mismatch")
        local u16 = peelf.read_u16(text_sec.virtual_address)
        assert((u16 & 0xFF) == b0, "read_u16 low byte mismatch")
        local u32 = peelf.read_u32(text_sec.virtual_address)
        assert((u32 & 0xFFFF) == u16, "read_u32 low word mismatch")
        local u64 = peelf.read_u64(text_sec.virtual_address)
        assert((u64 & 0xFFFFFFFF) == u32, "read_u64 low dword mismatch")

        local insns = peelf.disassemble(text_sec.virtual_address, 3)
        assert(#insns == 3, "expected 3 disassembled instructions")
        assert(insns[1].address == text_sec.virtual_address)
        assert(#insns[1].mnemonic > 0)
        assert(#insns[1].bytes > 0)

        local strs = peelf.strings(10)
        assert(#strs > 0 and #strs <= 10, "expected bounded extracted strings")

        local audit = peelf.security_audit()
        assert(audit.format == "ELF")
        assert(type(audit.findings) == "table" and #audit.findings > 0)

        print("ELF_OK", info.format, #secs, #insns, #audit.findings)
    )lua";

    const auto res = peelf::execute_lua_script(kScript, ctx);
    ASSERT_TRUE(res.ok) << res.error_message;
    EXPECT_FALSE(res.committed);
    EXPECT_NE(res.output.find("ELF_OK\tELF"), std::string::npos);
}

TEST(ScriptingTest, InspectsPeTargetMetadataExportsDisassemblyAndAudit) {
    const auto pe_path =
        std::filesystem::path(PEELF_BIN_MATRIX_DIR) / "pe-windows-x86_64-64-le-callgraph.dll";
    ASSERT_TRUE(std::filesystem::exists(pe_path)) << pe_path.string();

    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(read_all_bytes(pe_path), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    constexpr std::string_view kScript = R"lua(
        local info = peelf.target_info()
        assert(info.format == "PE")
        assert(info.arch == "x86-64")
        assert(info.bitness == 64)
        assert(info.endianness == "little-endian")
        assert(info.image_base > 0)

        local secs = peelf.sections()
        local text_va = nil
        for _, s in ipairs(secs) do
            if s.executable and s.file_size >= 8 then
                text_va = s.virtual_address
                break
            end
        end
        assert(text_va ~= nil, "expected executable PE section")

        local exps = peelf.exports()
        local imps = peelf.imports()
        assert(type(exps) == "table" and type(imps) == "table")
        assert(#exps > 0, "callgraph DLL should expose exports")

        local raw4 = peelf.read_bytes(text_va, 4)
        assert(#raw4 == 4)
        local u32 = peelf.read_u32(text_va)
        local expected = string.byte(raw4, 1)
            | (string.byte(raw4, 2) << 8)
            | (string.byte(raw4, 3) << 16)
            | (string.byte(raw4, 4) << 24)
        assert(u32 == expected, "PE read_u32 mismatch")

        local insns = peelf.disassemble(text_va, 2)
        assert(#insns == 2 and #insns[1].mnemonic > 0)

        local audit = peelf.security_audit()
        assert(audit.format == "PE")
        assert(#audit.findings > 0)

        peelf.log("PE_OK:" .. tostring(#exps))
    )lua";

    const auto res = peelf::execute_lua_script(kScript, ctx);
    ASSERT_TRUE(res.ok) << res.error_message;
    EXPECT_NE(res.output.find("PE_OK:"), std::string::npos);
}

TEST(ScriptingTest, InspectsMachOTargetMetadataSymbolsStringsDisassemblyAndAudit) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    constexpr std::string_view kScript = R"lua(
        local info = peelf.target_info()
        assert(info.format == "Mach-O")
        assert(info.arch == "x86-64")
        assert(info.bitness == 64)
        assert(info.endianness == "little-endian")
        assert(info.entry_point == 0x100000C00)

        local secs = peelf.sections()
        assert(#secs == 2)
        local syms = peelf.symbols()
        assert(#syms == 1 and syms[1].name == "_main")

        local strs = peelf.strings()
        local found_marker = false
        for _, entry in ipairs(strs) do
            if entry.value == "MachOScriptMarker" then
                found_marker = true
                assert(entry.virtual_address == 0x100000C20)
            end
        end
        assert(found_marker, "expected MachOScriptMarker in extracted strings")

        local insns = peelf.disassemble(info.entry_point, 5)
        assert(#insns == 5)
        assert(insns[1].mnemonic == "push")
        assert(insns[4].mnemonic == "pop")
        assert(insns[5].mnemonic == "ret")

        local audit = peelf.security_audit()
        assert(audit.format == "Mach-O")
        assert(#audit.findings > 0)
        print("MACHO_OK")
    )lua";

    const auto res = peelf::execute_lua_script(kScript, ctx);
    ASSERT_TRUE(res.ok) << res.error_message;
    EXPECT_EQ(res.output, "MACHO_OK\n");
}

TEST(ScriptingTest, HermeticSandboxStripsUnsafeLibrariesAndBlocksBinaryBytecode) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    constexpr std::string_view kSandboxCheck = R"lua(
        assert(io == nil, "io must be stripped")
        assert(os == nil, "os must be stripped")
        assert(debug == nil, "debug must be stripped")
        assert(package == nil, "package must be stripped")
        assert(require == nil, "require must be stripped")
        assert(dofile == nil, "dofile must be stripped")
        assert(loadfile == nil, "loadfile must be stripped")
        assert(warn == nil, "warn must be stripped")

        assert(type(table) == "table")
        assert(type(string) == "table")
        assert(type(math) == "table")
        assert(type(utf8) == "table")

        -- Binary mode and mixed mode in load() must be rejected.
        local fn_b, err_b = load("return 1", "bchunk", "b")
        assert(fn_b == nil and type(err_b) == "string")

        local fn_bt, err_bt = load("return 1", "btchunk", "bt")
        assert(fn_bt == nil and type(err_bt) == "string")

        -- Raw Lua bytecode signature (\x1bLua) passed to load() must be rejected.
        local fn_sig, err_sig = load("\x1bLua\x54\x00\x19\x93\r\n\x1a\n")
        assert(fn_sig == nil and type(err_sig) == "string")

        -- Text-only dynamic load remains supported inside the sandbox.
        local fn_t, err_t = load("return 40 + 2", "tchunk", "t")
        assert(fn_t ~= nil, err_t)
        assert(fn_t() == 42)
        print("SANDBOX_OK")
    )lua";

    const auto ok_res = peelf::execute_lua_script(kSandboxCheck, ctx);
    ASSERT_TRUE(ok_res.ok) << ok_res.error_message;
    EXPECT_EQ(ok_res.output, "SANDBOX_OK\n");

    // Direct top-level binary bytecode chunk (\x1bLua...) must be rejected immediately.
    const std::string raw_bytecode_chunk{"\x1bLua\x54\x00\x19\x93\r\n\x1a\n", 12u};
    const auto bin_res = peelf::execute_lua_script(raw_bytecode_chunk, ctx);
    EXPECT_FALSE(bin_res.ok);
    EXPECT_EQ(bin_res.error_kind, peelf::ScriptErrorKind::SyntaxOrLoadError);
    EXPECT_NE(bin_res.error_message.find("binary"), std::string::npos);
}

TEST(ScriptingTest, EnforcesMaxInstructionsIncludingPcallSwallowAttempts) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    peelf::ScriptLimits limits{};
    limits.max_instructions = 4'000u;

    const auto direct = peelf::execute_lua_script("while true do end", ctx, limits);
    EXPECT_FALSE(direct.ok);
    EXPECT_EQ(direct.error_kind, peelf::ScriptErrorKind::InstructionLimitExceeded);
    EXPECT_GE(direct.instructions_executed, limits.max_instructions);

    // Untrusted script attempting to swallow quota errors via nested pcall/xpcall must still abort.
    constexpr std::string_view kPcallTrap = R"lua(
        while true do
            pcall(function()
                while true do end
            end)
        end
    )lua";
    const auto trapped = peelf::execute_lua_script(kPcallTrap, ctx, limits);
    EXPECT_FALSE(trapped.ok);
    EXPECT_EQ(trapped.error_kind, peelf::ScriptErrorKind::InstructionLimitExceeded);
}

TEST(ScriptingTest, EnforcesMaxMemoryBytesOnAllocationBombCleanly) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    peelf::ScriptLimits limits{};
    limits.max_memory_bytes = 512ULL * 1024ULL; // 512 KiB cap
    limits.max_instructions = 5'000'000u;

    constexpr std::string_view kAllocBomb = R"lua(
        local function blow_up()
            local chunk = string.rep("X", 1024)
            local keep = {}
            while true do
                chunk = chunk .. chunk
                keep[#keep + 1] = chunk
            end
        end
        pcall(blow_up)
        blow_up()
    )lua";

    const auto res = peelf::execute_lua_script(kAllocBomb, ctx, limits);
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.error_kind, peelf::ScriptErrorKind::MemoryLimitExceeded);
    EXPECT_LE(res.peak_memory_bytes, limits.max_memory_bytes);
    EXPECT_FALSE(res.committed);
}

TEST(ScriptingTest, EnforcesCooperativeCancellationAndWallClockTimeout) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    // 1. Cooperative cancellation via std::stop_source from a worker thread.
    {
        std::stop_source stop_src;
        std::jthread stopper([&stop_src]() {
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
            stop_src.request_stop();
        });

        peelf::ScriptLimits limits{};
        limits.max_instructions = 500'000'000ULL;
        limits.wall_clock_timeout = std::chrono::milliseconds{10'000};

        const auto cancelled =
            peelf::execute_lua_script("local x = 0; while true do x = x + 1 end",
                                      ctx,
                                      limits,
                                      stop_src.get_token());
        EXPECT_FALSE(cancelled.ok);
        EXPECT_EQ(cancelled.error_kind, peelf::ScriptErrorKind::Cancelled);
    }

    // 2. Deterministic wall-clock timeout inside instruction hook.
    {
        peelf::ScriptLimits limits{};
        limits.max_instructions = 500'000'000ULL;
        limits.wall_clock_timeout = std::chrono::milliseconds{2};

        const auto timed_out =
            peelf::execute_lua_script("local x = 0; while true do x = x + 1 end", ctx, limits);
        EXPECT_FALSE(timed_out.ok);
        EXPECT_EQ(timed_out.error_kind, peelf::ScriptErrorKind::WallClockTimeout);
    }
}

TEST(ScriptingTest, EnforcesMaxOutputBytesCapAcrossPrintAndLog) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    peelf::ScriptLimits limits{};
    limits.max_output_bytes = 128u;

    constexpr std::string_view kNoisy = R"lua(
        for i = 1, 50 do
            print("line", i, "abcdefghijklmnopqrstuvwxyz")
            peelf.log("more output")
        end
    )lua";

    const auto res = peelf::execute_lua_script(kNoisy, ctx, limits);
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.error_kind, peelf::ScriptErrorKind::OutputLimitExceeded);
    EXPECT_TRUE(res.output_truncated);
    EXPECT_LE(res.output.size(), limits.max_output_bytes);
}

TEST(ScriptingTest, TransactionalReadYourWritesDryRunLeavesHostUntouched) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    constexpr std::string_view kDryRunScript = R"lua(
        local entry = peelf.target_info().entry_point
        assert(peelf.disassemble(entry, 1)[1].mnemonic == "push")

        -- Stage 3-byte patch via binary string (nop; nop; ret) and 2-byte patch via byte table.
        peelf.stage_patch(entry, "\x90\x90\xc3")
        peelf.stage_patch(entry + 4, {0xDE, 0xAD})

        -- Read-your-writes: read_bytes, read_u32, and disassemble immediately see staged overlay!
        local patched = peelf.read_bytes(entry, 6)
        assert(string.byte(patched, 1) == 0x90)
        assert(string.byte(patched, 2) == 0x90)
        assert(string.byte(patched, 3) == 0xC3)
        assert(string.byte(patched, 5) == 0xDE)
        assert(string.byte(patched, 6) == 0xAD)
        assert((peelf.read_u32(entry) & 0xFFFFFF) == 0xC39090)

        local insns = peelf.disassemble(entry, 3)
        assert(insns[1].mnemonic == "nop")
        assert(insns[2].mnemonic == "nop")
        assert(insns[3].mnemonic == "ret")

        -- Stage annotations and verify read-your-writes before commit.
        peelf.set_label(entry, "patched_entry")
        assert(peelf.get_label(entry) == "patched_entry")

        peelf.set_comment(entry, "NOP sled return")
        assert(peelf.get_comment(entry) == "NOP sled return")

        peelf.add_bookmark(entry, "EntryPointHook")
        local bms = peelf.bookmarks()
        assert(#bms == 1 and bms[1].address == entry and bms[1].label == "EntryPointHook")
        -- Intentionally omit peelf.commit(): dry-run only!
    )lua";

    const auto res = peelf::execute_lua_script(kDryRunScript, ctx);
    ASSERT_TRUE(res.ok) << res.error_message;
    EXPECT_FALSE(res.committed);
    ASSERT_EQ(res.staged_summary.staged_patches.size(), 2u);
    EXPECT_EQ(res.staged_summary.staged_patches[0].patched_bytes.size() +
                  res.staged_summary.staged_patches[1].patched_bytes.size(),
              5u);
    EXPECT_EQ(res.staged_summary.staged_labels.size(), 1u);
    EXPECT_EQ(res.staged_summary.staged_comments.size(), 1u);
    EXPECT_EQ(res.staged_summary.staged_bookmarks.size(), 1u);
    EXPECT_TRUE(res.staged_summary.bookmarks_modified);

    // Host PagedBinaryImage and ProjectWorkspace must remain completely untouched!
    EXPECT_FALSE(fixture.paged.dirty());
    EXPECT_TRUE(fixture.workspace.labels().empty());
    EXPECT_TRUE(fixture.workspace.comments().empty());
    EXPECT_TRUE(fixture.workspace.bookmarks().empty());
}

TEST(ScriptingTest, RuntimeErrorOrExplicitRollbackAfterCommitDiscardsMutations) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    fixture.workspace.set_label(0x100000C00ULL, "existing_label");
    auto ctx = fixture.make_context();

    // 1. Runtime error AFTER peelf.commit() must roll back everything at the host boundary.
    constexpr std::string_view kErrorAfterCommit = R"lua(
        local entry = peelf.target_info().entry_point
        peelf.stage_patch(entry, "\x90\xc3")
        peelf.set_label(entry, "should_not_persist")
        peelf.set_comment(entry, "transient")
        peelf.add_bookmark(entry, "transient_bm")
        peelf.commit()
        error("late failure after commit")
    )lua";

    const auto failed = peelf::execute_lua_script(kErrorAfterCommit, ctx);
    EXPECT_FALSE(failed.ok);
    EXPECT_EQ(failed.error_kind, peelf::ScriptErrorKind::RuntimeError);
    EXPECT_FALSE(failed.committed);
    EXPECT_FALSE(fixture.paged.dirty());
    ASSERT_EQ(fixture.workspace.get_label(0x100000C00ULL), std::optional<std::string>{"existing_label"});
    EXPECT_TRUE(fixture.workspace.comments().empty());
    EXPECT_TRUE(fixture.workspace.bookmarks().empty());

    // 2. Explicit peelf.rollback() discards staged overlay & reverts read-your-writes view.
    constexpr std::string_view kRollbackScript = R"lua(
        local entry = peelf.target_info().entry_point
        assert(peelf.get_label(entry) == "existing_label")
        peelf.stage_patch(entry, "\xcc\xcc")
        peelf.set_label(entry, "overwritten")
        peelf.commit()
        peelf.rollback()

        -- After rollback(), read-your-writes sees original host state again!
        assert(peelf.get_label(entry) == "existing_label")
        assert(peelf.read_u8(entry) == 0x55)
    )lua";

    const auto rolled_back = peelf::execute_lua_script(kRollbackScript, ctx);
    ASSERT_TRUE(rolled_back.ok) << rolled_back.error_message;
    EXPECT_FALSE(rolled_back.committed);
    EXPECT_FALSE(fixture.paged.dirty());
    EXPECT_EQ(fixture.workspace.get_label(0x100000C00ULL), std::optional<std::string>{"existing_label"});
}

TEST(ScriptingTest, ExplicitCommitAtomicallyAppliesWorkspaceAndUndoableImagePatches) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    fixture.workspace.set_label(0x100000C04ULL, "obsolete_label");
    auto ctx = fixture.make_context();

    constexpr std::string_view kCommitScript = R"lua(
        local entry = peelf.target_info().entry_point
        peelf.stage_patch(entry, "\x31\xc0\xc3")
        peelf.stage_patch(entry + 3, {0x90})
        peelf.set_label(entry, "fast_return_zero")
        peelf.set_label(entry + 4, "") -- clear existing label
        peelf.set_comment(entry, "xor eax, eax; ret; nop")
        peelf.add_bookmark(entry, "PatchedEntry")
        assert(peelf.commit() == true)
    )lua";

    const auto res = peelf::execute_lua_script(kCommitScript, ctx);
    ASSERT_TRUE(res.ok) << res.error_message;
    EXPECT_TRUE(res.committed);
    ASSERT_EQ(res.staged_summary.staged_patches.size(), 1u);
    EXPECT_EQ(res.staged_summary.staged_patches[0].patched_bytes.size(), 4u);

    // Verify ProjectWorkspace mutations applied.
    EXPECT_EQ(fixture.workspace.get_label(0x100000C00ULL),
              std::optional<std::string>{"fast_return_zero"});
    EXPECT_EQ(fixture.workspace.get_label(0x100000C04ULL), std::nullopt);
    EXPECT_EQ(fixture.workspace.get_comment(0x100000C00ULL),
              std::optional<std::string>{"xor eax, eax; ret; nop"});
    ASSERT_EQ(fixture.workspace.bookmarks().size(), 1u);
    EXPECT_EQ(fixture.workspace.bookmarks()[0].virtual_address, 0x100000C00ULL);
    EXPECT_EQ(fixture.workspace.bookmarks()[0].label, "PatchedEntry");

    // Verify PagedBinaryImage received both staged patches as one atomic undoable transaction.
    EXPECT_TRUE(fixture.paged.dirty());
    const auto effective = fixture.paged.read_effective(0xC00u, 4u);
    ASSERT_TRUE(effective.has_value()) << effective.error().message;
    EXPECT_EQ(*effective, (std::vector<std::uint8_t>{0x31u, 0xC0u, 0xC3u, 0x90u}));

    ASSERT_TRUE(fixture.paged.undo().has_value());
    EXPECT_FALSE(fixture.paged.dirty());
    const auto restored = fixture.paged.read_effective(0xC00u, 4u);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(*restored, (std::vector<std::uint8_t>{0x55u, 0x48u, 0x89u, 0xE5u}));
}

TEST(ScriptingTest, RejectsMutationsOnReadOnlyTargetsAndUnmappedAddresses) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;

    // 1. Explicit allow_mutations == false
    {
        auto ro_ctx = fixture.make_context(/*allow_mutations=*/false);
        const auto info_res = peelf::execute_lua_script(
            "assert(peelf.target_info().is_read_only == true)\n"
            "assert(peelf.capabilities().StaticPatching.can_execute == false)\n",
            ro_ctx);
        ASSERT_TRUE(info_res.ok) << info_res.error_message;

        const auto patch_res = peelf::execute_lua_script(
            "peelf.stage_patch(0x100000C00, '\\x90')", ro_ctx);
        EXPECT_FALSE(patch_res.ok);
        EXPECT_EQ(patch_res.error_kind, peelf::ScriptErrorKind::RuntimeError);

        const auto label_res = peelf::execute_lua_script(
            "peelf.set_label(0x100000C00, 'nope')", ro_ctx);
        EXPECT_FALSE(label_res.ok);
        EXPECT_EQ(label_res.error_kind, peelf::ScriptErrorKind::RuntimeError);
    }

    // 2. Live process target (read-only by TargetCapabilityMatrix even if allow_mutations == true)
    {
        ReadOnlyMockProcessSession mock_proc;
        peelf::ScriptContext live_ctx{
            .image = fixture.image.get(),
            .raw_bytes = fixture.raw_bytes,
            .paged_image = &fixture.paged,
            .workspace = &fixture.workspace,
            .live_session = &mock_proc,
            .allow_mutations = true,
        };

        const auto live_res = peelf::execute_lua_script(
            "assert(peelf.target_info().is_read_only == true)\n"
            "peelf.stage_patch(0x100000C00, '\\x90')\n",
            live_ctx);
        EXPECT_FALSE(live_res.ok);
        EXPECT_EQ(live_res.error_kind, peelf::ScriptErrorKind::RuntimeError);
        EXPECT_FALSE(fixture.paged.dirty());
    }

    // 3. Unmapped virtual address on mutable static target
    {
        auto rw_ctx = fixture.make_context(/*allow_mutations=*/true);
        const auto oob_res = peelf::execute_lua_script(
            "peelf.stage_patch(0xDEADBEEF0000, '\\x90\\x90')", rw_ctx);
        EXPECT_FALSE(oob_res.ok);
        EXPECT_EQ(oob_res.error_kind, peelf::ScriptErrorKind::RuntimeError);
        EXPECT_FALSE(fixture.paged.dirty());
    }
}

TEST(ScriptingTest, SandboxLoadReraisesMemoryQuotaErrorsAndRefusesCommit) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    fixture.workspace.set_label(0x100000C00ULL, "baseline_entry");
    auto ctx = fixture.make_context();

    peelf::ScriptLimits limits{};
    limits.max_memory_bytes = 256u * 1024u;
    limits.max_instructions = 2'000'000ULL;

    // Even when `load(...)` is wrapped inside `pcall(...)`, an OOM / memory-quota failure
    // during `lua_load` MUST re-raise fatally rather than returning `(nil, msg)` that the
    // script could swallow and follow with `peelf.commit()`.
    constexpr std::string_view kLoadOomScript = R"lua(
        local entry = peelf.target_info().entry_point
        peelf.stage_patch(entry, "\x90\xc3")
        peelf.set_label(entry, "should_never_commit")
        local chunk_src = string.rep("local a = 1;\n", 16384)
        local ok, fn, err = pcall(function()
            return load(chunk_src, "oom_chunk", "t")
        end)
        peelf.commit()
    )lua";

    const auto res = peelf::execute_lua_script(kLoadOomScript, ctx, limits);
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.error_kind, peelf::ScriptErrorKind::MemoryLimitExceeded);
    EXPECT_FALSE(res.committed);
    EXPECT_LE(res.peak_memory_bytes, limits.max_memory_bytes);
    EXPECT_FALSE(fixture.paged.dirty());
    EXPECT_EQ(fixture.workspace.get_label(0x100000C00ULL),
              std::optional<std::string>{"baseline_entry"});
}

TEST(ScriptingTest, HostStagedMemoryQuotaEnforcedAtomicallyWithoutTornPatches) {
    // Build a synthetic Mach-O with an 8 KiB __text section so staging thousands of host
    // patch cells exercises host-side `ScriptLimits::max_memory_bytes` accounting.
    std::vector<std::uint8_t> big_macho = make_synthetic_x86_64_macho();
    big_macho.resize(0x4000u, 0x90u);
    // Widen LC_SEGMENT_64 __TEXT vmsize/filesize and __text section size to 0x2000 bytes.
    auto patch_u64_le = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0u; i < 8u; ++i) {
            big_macho[off + i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    };
    // Header (32) + __PAGEZERO (72) = 104 -> __TEXT segment_command_64:
    // vmsize @ +32 (136), filesize @ +48 (152); __text section_64 starts @ 176: size @ +40 (216).
    patch_u64_le(136u, 0x4000ULL);
    patch_u64_le(152u, 0x4000ULL);
    patch_u64_le(216u, 0x2000ULL);

    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(std::move(big_macho), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    auto ctx = fixture.make_context();

    peelf::ScriptLimits limits{};
    limits.max_memory_bytes = 256u * 1024u;
    limits.max_instructions = 2'000'000ULL;

    constexpr std::string_view kHostPatchQuotaScript = R"lua(
        local entry = peelf.target_info().entry_point
        peelf.stage_patch(entry, "\x31\xc0")
        -- 6000 unique staged cells * 48B host node overhead exceeds the 256 KiB total cap;
        -- pcall MUST NOT swallow the fatal MemoryLimitExceeded error or allow commit.
        pcall(function()
            peelf.stage_patch(entry + 2, string.rep("\x90", 6000))
        end)
        peelf.commit()
    )lua";

    const auto res = peelf::execute_lua_script(kHostPatchQuotaScript, ctx, limits);
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.error_kind, peelf::ScriptErrorKind::MemoryLimitExceeded);
    EXPECT_FALSE(res.committed);
    EXPECT_LE(res.peak_memory_bytes, limits.max_memory_bytes);
    EXPECT_FALSE(fixture.paged.dirty());
}

TEST(ScriptingTest, HostCommitIsAllOrNothingAcrossWorkspaceAndPagedBinaryImage) {
    std::optional<LoadedStaticFixture> fixture_opt;
    ASSERT_NO_FATAL_FAILURE(LoadedStaticFixture::load_from_bytes(make_synthetic_x86_64_macho(), fixture_opt));
    ASSERT_TRUE(fixture_opt.has_value());
    auto& fixture = *fixture_opt;
    fixture.workspace.set_label(0x100000C00ULL, "seed_label");
    fixture.workspace.set_comment(0x100000C00ULL, "seed_comment");
    fixture.workspace.add_bookmark(0x100000C04ULL, "SeedBM");

    // 1. Failing PagedBinaryImage patch write/commit (e.g. truncated/undersized PagedBinaryImage)
    // MUST roll back all ProjectWorkspace label/comment/bookmark mutations atomically.
    const std::vector<std::uint8_t> tiny_backing(0x200u, 0u);
    const TempFileGuard tiny_file(tiny_backing);
    auto tiny_paged = peelf::PagedBinaryImage::open(tiny_file.path(), 64u);
    ASSERT_TRUE(tiny_paged.has_value()) << tiny_paged.error().message;

    peelf::ScriptTransaction tx{};
    tx.reset(&fixture.workspace);
    tx.stage_label(0x100000C00ULL, "corrupted_if_not_rolled_back");
    tx.stage_label(0x100000C04ULL, "extra_label");
    tx.stage_comment(0x100000C00ULL, ""); // erase seed comment
    tx.stage_bookmark(0x100000C00ULL, "MutatedBM");
    tx.stage_byte(0xC00u, 0x100000C00ULL, 0x55u, 0xCCu);
    tx.request_commit("atomic_rollback_check");

    const auto failed_patch_commit = tx.apply_to_host(&(*tiny_paged), &fixture.workspace);
    EXPECT_FALSE(failed_patch_commit.has_value());
    EXPECT_FALSE(tiny_paged->dirty());
    EXPECT_EQ(fixture.workspace.get_label(0x100000C00ULL),
              std::optional<std::string>{"seed_label"});
    EXPECT_EQ(fixture.workspace.get_label(0x100000C04ULL), std::nullopt);
    EXPECT_EQ(fixture.workspace.get_comment(0x100000C00ULL),
              std::optional<std::string>{"seed_comment"});
    ASSERT_EQ(fixture.workspace.bookmarks().size(), 1u);
    EXPECT_EQ(fixture.workspace.bookmarks()[0].virtual_address, 0x100000C04ULL);
    EXPECT_EQ(fixture.workspace.bookmarks()[0].label, "SeedBM");

    // 2. Conversely, missing ProjectWorkspace when both patches and annotations are staged
    // MUST NOT leave PagedBinaryImage mutated.
    const auto failed_missing_ws = tx.apply_to_host(&fixture.paged, /*workspace=*/nullptr);
    EXPECT_FALSE(failed_missing_ws.has_value());
    EXPECT_FALSE(fixture.paged.dirty());
}

namespace {

class TempDirGuard {
public:
    TempDirGuard() {
        static std::atomic<std::uint64_t> seq{0u};
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string test_name = info != nullptr ? info->name() : "wu28b";
        const auto nonce = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        dir_ = std::filesystem::temp_directory_path() /
               std::filesystem::path(std::format(
                   "peelf_wu28b_{}_{}_{}",
                   test_name,
                   nonce,
                   seq.fetch_add(1u, std::memory_order_relaxed)));
        std::filesystem::create_directories(dir_);
    }

    TempDirGuard(const TempDirGuard&) = delete;
    TempDirGuard& operator=(const TempDirGuard&) = delete;
    TempDirGuard(TempDirGuard&&) = delete;
    TempDirGuard& operator=(TempDirGuard&&) = delete;

    ~TempDirGuard() noexcept {
        std::error_code ec{};
        std::filesystem::remove_all(dir_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return dir_; }

    [[nodiscard]] std::filesystem::path write_text(std::string_view filename,
                                                   std::string_view contents) const {
        const std::filesystem::path p = dir_ / filename;
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        return p;
    }

    [[nodiscard]] std::filesystem::path write_bytes(std::string_view filename,
                                                    std::span<const std::uint8_t> bytes) const {
        const std::filesystem::path p = dir_ / filename;
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        return p;
    }

private:
    std::filesystem::path dir_{};
};

[[nodiscard]] std::vector<std::uint8_t> make_synthetic_arm64_macho() {
    using namespace peelf::macho;
    MachOByteWriter w;

    // mach_header_64 (32 bytes)
    w.u32(kMhMagic64);
    w.u32(kCpuTypeArm64);
    w.u32(kCpuSubtypeArm64All);
    w.u32(kMhExecute);
    w.u32(2u);
    w.u32(72u + 80u + 24u);
    w.u32(kMhPie | kMhTwoLevel);
    w.u32(0u);

    // 1. LC_SEGMENT_64 __TEXT with __text @ 0x100000400 (file offset 0x400)
    w.u32(kLcSegment64);
    w.u32(72u + 80u);
    w.fixed_str16("__TEXT");
    w.u64(0x100000000ULL);
    w.u64(0x1000ULL);
    w.u64(0u);
    w.u64(0x800ULL);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(kVmProtRead | kVmProtExecute);
    w.u32(1u);
    w.u32(0u);

    w.fixed_str16("__text");
    w.fixed_str16("__TEXT");
    w.u64(0x100000400ULL);
    w.u64(8u);
    w.u32(0x400u);
    w.u32(2u);
    w.u32(0u);
    w.u32(0u);
    w.u32(kSAttrPureInstructions | kSRegular);
    w.u32(0u);
    w.u32(0u);
    w.u32(0u);

    // 2. LC_MAIN -> entryoff 0x400
    w.u32(kLcMain);
    w.u32(24u);
    w.u64(0x400ULL);
    w.u64(0ULL);

    w.pad_to(0x400u);
    // ARM64: mov w0, #7; ret (0x528000E0, 0xD65F03C0)
    const std::array<std::uint8_t, 8> code{
        0xE0u, 0x00u, 0x80u, 0x52u, 0xC0u, 0x03u, 0x5Fu, 0xD6u};
    w.raw(code);
    w.pad_to(0x800u);
    return w.bytes();
}

[[nodiscard]] std::vector<std::uint8_t> make_synthetic_universal_macho() {
    const std::vector<std::uint8_t> slice0_x86 = make_synthetic_x86_64_macho();
    const std::vector<std::uint8_t> slice1_arm = make_synthetic_arm64_macho();

    auto append_be32 = [](std::vector<std::uint8_t>& out, std::uint32_t v) {
        out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    };

    std::vector<std::uint8_t> fat{};
    append_be32(fat, peelf::macho::kFatMagic);
    append_be32(fat, 2u);

    // Slice 0: x86_64 @ 0x1000
    append_be32(fat, peelf::macho::kCpuTypeX86_64);
    append_be32(fat, peelf::macho::kCpuSubtypeX86_64All);
    append_be32(fat, 0x1000u);
    append_be32(fat, static_cast<std::uint32_t>(slice0_x86.size()));
    append_be32(fat, 12u);

    // Slice 1: arm64 @ 0x4000
    append_be32(fat, peelf::macho::kCpuTypeArm64);
    append_be32(fat, peelf::macho::kCpuSubtypeArm64All);
    append_be32(fat, 0x4000u);
    append_be32(fat, static_cast<std::uint32_t>(slice1_arm.size()));
    append_be32(fat, 12u);

    fat.resize(0x1000u, 0u);
    fat.insert(fat.end(), slice0_x86.begin(), slice0_x86.end());
    fat.resize(0x4000u, 0u);
    fat.insert(fat.end(), slice1_arm.begin(), slice1_arm.end());
    return fat;
}

[[nodiscard]] std::optional<viewer::AsyncScriptOutcome> wait_for_script_harvest(
    viewer::BinaryModel& model,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{4000}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto harvested = model.harvest_script_execution(); harvested.has_value()) {
            return harvested;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return std::nullopt;
}

#if defined(PEELF_VIEWER_EXECUTABLE_PATH)
[[nodiscard]] peelf::SubprocessResult run_viewer_cli_subprocess(
    std::span<const std::string> args) {
    return peelf::run_subprocess_bounded(
        std::filesystem::path{PEELF_VIEWER_EXECUTABLE_PATH}, args);
}
#endif

} // namespace

TEST(ScriptingTest, BinaryModelAsyncScriptHarvestsCommittedMutationsAndHonorsDryRun) {
    const TempDirGuard tmp{};
    const std::filesystem::path bin_path =
        tmp.write_bytes("target.macho", make_synthetic_x86_64_macho());

    viewer::BinaryModel model{};
    ASSERT_TRUE(model.load_file(bin_path.string()));
    const auto eligibility = model.script_mutation_eligibility();
    EXPECT_TRUE(eligibility.can_mutate_target) << eligibility.reason;

    // 1. Dry-run script stages mutations without calling peelf.commit(): UI model stays clean.
    {
        peelf::ProjectWorkspace seed_ws{};
        seed_ws.set_label(0x100000C00ULL, "seed_entry");

        constexpr std::string_view kDryRun = R"lua(
            local entry = peelf.target_info().entry_point
            assert(peelf.get_label(entry) == "seed_entry")
            peelf.stage_patch(entry, "\x90\x90\xc3")
            peelf.set_label(entry, "dry_run_label")
            peelf.add_bookmark(entry, "DryRunBM")
            print("dry-run complete")
        )lua";

        auto started = model.start_script_execution(
            std::string{kDryRun}, peelf::ScriptLimits{}, /*request_allow_mutations=*/true, std::move(seed_ws));
        ASSERT_TRUE(started.has_value()) << started.error().message;

        const auto outcome = wait_for_script_harvest(model);
        ASSERT_TRUE(outcome.has_value());
        EXPECT_EQ(outcome->status, viewer::AsyncScriptStatus::Succeeded);
        EXPECT_TRUE(outcome->script_result.ok) << outcome->script_result.error_message;
        EXPECT_FALSE(outcome->script_result.committed);
        EXPECT_FALSE(outcome->mutations_applied_to_model);
        EXPECT_TRUE(model.changed_intervals().empty());
        EXPECT_TRUE(model.bookmarks().empty());
    }

    // 2. Explicit peelf.commit() safely harvests patches & bookmarks onto BinaryModel on UI thread.
    {
        constexpr std::string_view kCommit = R"lua(
            local entry = peelf.target_info().entry_point
            peelf.stage_patch(entry, "\x31\xc0\xc3")
            peelf.set_label(entry, "ui_committed_entry")
            peelf.set_comment(entry, "patched from async worker")
            peelf.add_bookmark(entry, "AsyncScriptBookmark")
            assert(peelf.commit() == true)
            print("committed ok")
        )lua";

        auto started = model.start_script_execution(
            std::string{kCommit}, peelf::ScriptLimits{}, /*request_allow_mutations=*/true);
        ASSERT_TRUE(started.has_value()) << started.error().message;

        const auto outcome = wait_for_script_harvest(model);
        ASSERT_TRUE(outcome.has_value());
        EXPECT_EQ(outcome->status, viewer::AsyncScriptStatus::Succeeded);
        EXPECT_TRUE(outcome->script_result.ok) << outcome->script_result.error_message;
        EXPECT_TRUE(outcome->script_result.committed);
        EXPECT_TRUE(outcome->mutations_applied_to_model) << outcome->apply_diagnostic;

        EXPECT_EQ(model.changed_intervals().size(), 1u);
        const auto patched_bytes = model.read_effective_bytes(0xC00u, 3u);
        ASSERT_TRUE(patched_bytes.has_value());
        EXPECT_EQ(*patched_bytes, (std::vector<std::uint8_t>{0x31u, 0xC0u, 0xC3u}));

        ASSERT_EQ(model.bookmarks().size(), 1u);
        EXPECT_EQ(model.bookmarks()[0].address, 0x100000C00ULL);
        EXPECT_EQ(model.bookmarks()[0].label, "AsyncScriptBookmark");

        // Undo reverts the harvested Lua commit cleanly in one step.
        ASSERT_TRUE(model.undo_patch().has_value());
        EXPECT_TRUE(model.changed_intervals().empty());
    }
}

TEST(ScriptingTest, BinaryModelAsyncScriptSupportsCancellationAndReloadCleanup) {
    const TempDirGuard tmp{};
    const std::filesystem::path bin_path =
        tmp.write_bytes("target.macho", make_synthetic_x86_64_macho());
    const std::filesystem::path bin_path_2 =
        tmp.write_bytes("target2.macho", make_synthetic_arm64_macho());

    viewer::BinaryModel model{};
    ASSERT_TRUE(model.load_file(bin_path.string()));

    peelf::ScriptLimits generous_limits{};
    generous_limits.max_instructions = 500'000'000ULL;
    generous_limits.wall_clock_timeout = std::chrono::milliseconds{10000};

    auto started = model.start_script_execution(
        "local n = 0; while true do n = n + 1 end",
        generous_limits,
        /*request_allow_mutations=*/false);
    ASSERT_TRUE(started.has_value()) << started.error().message;

    // Give worker a moment to enter Lua VM, then cooperatively cancel via stop_source.
    std::this_thread::sleep_for(std::chrono::milliseconds{15});
    model.cancel_script_execution();

    const auto cancelled = wait_for_script_harvest(model);
    ASSERT_TRUE(cancelled.has_value());
    EXPECT_EQ(cancelled->status, viewer::AsyncScriptStatus::Cancelled);
    EXPECT_FALSE(cancelled->script_result.ok);
    EXPECT_EQ(cancelled->script_result.error_kind, peelf::ScriptErrorKind::Cancelled);

    // Concurrent UI edit while script is running invalidates expected_stamp -> StaleDiscarded.
    {
        ASSERT_TRUE(model.start_script_execution(
                        "local entry = peelf.target_info().entry_point\n"
                        "peelf.stage_patch(entry, '\\x90\\x90')\n"
                        "peelf.commit()\n",
                        generous_limits,
                        /*request_allow_mutations=*/true)
                        .has_value());
        const std::array<std::uint8_t, 1> manual_patch{0xCCu};
        ASSERT_TRUE(model.apply_patch_bytes(0xC04u, manual_patch, "Concurrent UI edit").has_value());

        const auto stale = wait_for_script_harvest(model);
        ASSERT_TRUE(stale.has_value());
        EXPECT_EQ(stale->status, viewer::AsyncScriptStatus::StaleDiscarded);
        EXPECT_FALSE(stale->mutations_applied_to_model);
        // Only the manual UI edit at 0xC04 remains; script's 0xC00 patch was discarded.
        ASSERT_EQ(model.changed_intervals().size(), 1u);
        EXPECT_EQ(model.changed_intervals()[0].offset, 0xC04u);
    }

    // Reloading a new target while another script is running cleanly stops & resets state.
    ASSERT_TRUE(model.start_script_execution(
                    "local n = 0; while true do n = n + 1 end",
                    generous_limits,
                    /*request_allow_mutations=*/false)
                    .has_value());
    ASSERT_TRUE(model.load_file(bin_path_2.string()));
    EXPECT_FALSE(model.is_script_running());
    EXPECT_FALSE(model.harvest_script_execution().has_value());
}

TEST(ScriptingTest, ConcurrentAnnotationAndBookmarkEditsInvalidateAsyncScriptAndPreserveMetadata) {
    const TempDirGuard tmp{};
    const std::filesystem::path bin_path =
        tmp.write_bytes("target_annot.macho", make_synthetic_x86_64_macho());

    viewer::BinaryModel model{};
    ASSERT_TRUE(model.load_file(bin_path.string()));

    // Verify add_or_update_bookmark preserves existing category & note unless overridden.
    model.add_or_update_bookmark(viewer::Bookmark{
        .address = 0x100000C00ULL,
        .is_file_offset = false,
        .label = "InitialLabel",
        .category = "Security",
        .note = "Important check",
    });
    model.add_or_update_bookmark(viewer::Bookmark{
        .address = 0x100000C00ULL,
        .is_file_offset = false,
        .label = "RenamedLabel",
        .category = {},
        .note = {},
    });
    ASSERT_EQ(model.bookmarks().size(), 1u);
    EXPECT_EQ(model.bookmarks()[0].label, "RenamedLabel");
    EXPECT_EQ(model.bookmarks()[0].category, "Security");
    EXPECT_EQ(model.bookmarks()[0].note, "Important check");

    peelf::ScriptLimits generous_limits{};
    generous_limits.max_instructions = 500'000'000ULL;
    generous_limits.wall_clock_timeout = std::chrono::milliseconds{10000};

    // 1. Concurrent bookmark mutation during async script execution -> StaleDiscarded.
    {
        ASSERT_TRUE(model.start_script_execution(
                        "local entry = peelf.target_info().entry_point\n"
                        "peelf.add_bookmark(entry + 8, 'ScriptBM')\n"
                        "peelf.commit()\n",
                        generous_limits,
                        /*request_allow_mutations=*/true)
                        .has_value());
        model.add_or_update_bookmark(viewer::Bookmark{
            .address = 0x100000C04ULL,
            .is_file_offset = false,
            .label = "ConcurrentUserBM",
            .category = "User",
            .note = "Concurrent note",
        });

        const auto stale = wait_for_script_harvest(model);
        ASSERT_TRUE(stale.has_value());
        EXPECT_EQ(stale->status, viewer::AsyncScriptStatus::StaleDiscarded);
        EXPECT_FALSE(stale->mutations_applied_to_model);
        ASSERT_EQ(model.bookmarks().size(), 2u);
    }

    // 2. Concurrent UI label/comment edit (bump_annotation_revision) -> StaleDiscarded.
    {
        ASSERT_TRUE(model.start_script_execution(
                        "local entry = peelf.target_info().entry_point\n"
                        "peelf.set_label(entry, 'script_label')\n"
                        "peelf.commit()\n",
                        generous_limits,
                        /*request_allow_mutations=*/true)
                        .has_value());
        model.bump_annotation_revision();

        const auto stale = wait_for_script_harvest(model);
        ASSERT_TRUE(stale.has_value());
        EXPECT_EQ(stale->status, viewer::AsyncScriptStatus::StaleDiscarded);
        EXPECT_FALSE(stale->mutations_applied_to_model);
    }
}

TEST(ScriptingTest, HeadlessCliRejectsMismatchedProjectPreservesBookmarkMetadataAndBoundsTimeout) {
    // 1. --script-timeout-ms rejects <= 0 and > INT64_MAX cleanly.
    {
        std::ostringstream out_ss;
        std::ostringstream err_ss;
        const std::array<std::string_view, 6> zero_args{
            "--headless", "bin", "--script", "s.lua", "--script-timeout-ms", "0"};
        const auto zero_rc = viewer::try_run_headless_or_help_cli(zero_args, out_ss, err_ss);
        ASSERT_TRUE(zero_rc.has_value());
        EXPECT_NE(*zero_rc, 0);
        EXPECT_NE(err_ss.str().find("--script-timeout-ms"), std::string::npos);

        out_ss.str("");
        err_ss.str("");
        const std::array<std::string_view, 6> huge_args{
            "--headless", "bin", "--script", "s.lua", "--script-timeout-ms", "9223372036854775808"};
        const auto huge_rc = viewer::try_run_headless_or_help_cli(huge_args, out_ss, err_ss);
        ASSERT_TRUE(huge_rc.has_value());
        EXPECT_NE(*huge_rc, 0);
        EXPECT_NE(err_ss.str().find("--script-timeout-ms"), std::string::npos);
    }

    // 2. --headless --project rejects mismatched source_sha256 unless --allow-modified-binary,
    //    and preserves existing VA bookmark category/note across script commits.
    const std::vector<std::uint8_t> orig_bytes = make_synthetic_x86_64_macho();
    std::vector<std::uint8_t> modified_bytes = orig_bytes;
    modified_bytes.back() ^= 0xFFu;

    const TempDirGuard tmp{};
    const std::filesystem::path orig_bin = tmp.write_bytes("orig_proj.macho", orig_bytes);
    const std::filesystem::path mod_bin = tmp.write_bytes("mod_proj.macho", modified_bytes);
    const std::filesystem::path peproj_path = tmp.path() / "state.peproj";

    {
        viewer::BinaryModel seed_model;
        ASSERT_TRUE(seed_model.load_file(orig_bin.string()));
        seed_model.add_or_update_bookmark(viewer::Bookmark{
            .address = 0x100000C00ULL,
            .is_file_offset = false,
            .label = "OldEntryBM",
            .category = "Triage",
            .note = "Keep this note",
        });
        const viewer::AnalysisProject proj = viewer::build_analysis_project(seed_model, peproj_path);
        ASSERT_TRUE(viewer::write_analysis_file(peproj_path, viewer::encode_project(proj)).has_value());
    }

    const std::filesystem::path script_path = tmp.write_text(
        "update_bm.lua",
        R"lua(
            local entry = peelf.target_info().entry_point
            peelf.add_bookmark(entry, "UpdatedEntryBM")
            assert(peelf.commit() == true)
        )lua");

    // Mismatched binary without --allow-modified-binary must fail cleanly with SHA-256 mismatch.
    {
        viewer::HeadlessScriptCliOptions opts;
        opts.binary_path = mod_bin;
        opts.script_path = script_path;
        opts.project_path = peproj_path;
        opts.allow_mutations = true;
        const auto mismatched = viewer::run_headless_script(opts);
        ASSERT_FALSE(mismatched.has_value());
        EXPECT_NE(mismatched.error().message.find("SHA-256"), std::string::npos)
            << mismatched.error().message;
    }

    // Matching binary succeeds and preserves VA bookmark category and note in saved .peproj.
    {
        viewer::HeadlessScriptCliOptions opts;
        opts.binary_path = orig_bin;
        opts.script_path = script_path;
        opts.project_path = peproj_path;
        opts.allow_mutations = true;
        const auto ok_report = viewer::run_headless_script(opts);
        ASSERT_TRUE(ok_report.has_value()) << ok_report.error().message;
        EXPECT_TRUE(ok_report->project_written);

        const auto proj_text = viewer::read_project_file(peproj_path);
        ASSERT_TRUE(proj_text.has_value()) << proj_text.error().message;
        const auto decoded = viewer::decode_project(*proj_text);
        ASSERT_TRUE(decoded.has_value()) << decoded.error().message;
        ASSERT_EQ(decoded->bookmarks.size(), 1u);
        EXPECT_EQ(decoded->bookmarks[0].address, 0x100000C00ULL);
        EXPECT_EQ(decoded->bookmarks[0].label, "UpdatedEntryBM");
        EXPECT_EQ(decoded->bookmarks[0].category, "Triage");
        EXPECT_EQ(decoded->bookmarks[0].note, "Keep this note");
    }
}

#if defined(PEELF_VIEWER_EXECUTABLE_PATH)
TEST(ScriptingTest, HeadlessCliScriptSupportsTextJsonSlicesAndQuotaExitCodes) {
    const std::filesystem::path viewer_exe{PEELF_VIEWER_EXECUTABLE_PATH};
    ASSERT_TRUE(std::filesystem::exists(viewer_exe))
        << "Expected built peelf_viewer at " << viewer_exe.string();

    const TempDirGuard tmp{};
    const std::filesystem::path macho_bin =
        tmp.write_bytes("sample.macho", make_synthetic_x86_64_macho());
    const std::filesystem::path fat_bin =
        tmp.write_bytes("universal.macho", make_synthetic_universal_macho());

    const std::filesystem::path inspect_lua = tmp.write_text(
        "inspect.lua",
        R"lua(
            local info = peelf.target_info()
            print(string.format("ARCH=%s ENTRY=0x%X RO=%s",
                info.arch, info.entry_point, tostring(info.is_read_only)))
        )lua");

    // 1. Default text output is read-only and exits 0.
    {
        const std::array<std::string, 4> args{
            "--headless", macho_bin.string(), "--script", inspect_lua.string()};
        const auto res = run_viewer_cli_subprocess(args);
        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_FALSE(res.timed_out);
        EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("ARCH=x86-64 ENTRY=0x100000C00 RO=true"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("status=OK mode=read-only"), std::string::npos);
    }

    // 2. JSON output + Universal Mach-O `--slice arm64` selects slice 1 (ARM64).
    {
        const std::array<std::string, 8> args{
            "--headless", fat_bin.string(),
            "--slice", "arm64",
            "--script", inspect_lua.string(),
            "--format", "json"};
        const auto res = run_viewer_cli_subprocess(args);
        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_FALSE(res.timed_out);
        EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("\"selected_slice_index\": 1"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("ARCH=ARM64 ENTRY=0x100000400 RO=true"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"allow_mutations\": false"), std::string::npos);
    }

    // 3. Attempting mutation without `--script-allow-mutations` fails deterministically (exit 1).
    {
        const std::filesystem::path mut_lua = tmp.write_text(
            "disallow_mut.lua", "peelf.stage_patch(0x100000C00, '\\x90')\n");
        const std::array<std::string, 6> args{
            "--headless", macho_bin.string(), "--script", mut_lua.string(), "--format", "json"};
        const auto res = run_viewer_cli_subprocess(args);
        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_EQ(res.exit_code, 1);
        EXPECT_NE(res.stdout_text.find("\"error_kind\": \"RuntimeError\""), std::string::npos);
    }

    // 4. Syntax error and instruction quota limit return deterministic non-zero exit code (1).
    {
        const std::filesystem::path bad_lua = tmp.write_text("syntax_err.lua", "function broken(\n");
        const std::array<std::string, 6> bad_args{
            "--headless", macho_bin.string(), "--script", bad_lua.string(), "--format", "json"};
        const auto bad_res = run_viewer_cli_subprocess(bad_args);
        ASSERT_TRUE(bad_res.launched) << bad_res.launch_error;
        EXPECT_EQ(bad_res.exit_code, 1);
        EXPECT_NE(bad_res.stdout_text.find("\"error_kind\": \"SyntaxOrLoadError\""),
                  std::string::npos);

        const std::filesystem::path loop_lua =
            tmp.write_text("loop.lua", "local x = 0; while true do x = x + 1 end\n");
        const std::array<std::string, 8> quota_args{
            "--headless", macho_bin.string(),
            "--script", loop_lua.string(),
            "--script-max-instructions", "200",
            "--format", "json"};
        const auto quota_res = run_viewer_cli_subprocess(quota_args);
        ASSERT_TRUE(quota_res.launched) << quota_res.launch_error;
        EXPECT_FALSE(quota_res.timed_out);
        EXPECT_EQ(quota_res.exit_code, 1);
        EXPECT_NE(quota_res.stdout_text.find("\"error_kind\": \"InstructionLimitExceeded\""),
                  std::string::npos);
    }
}

TEST(ScriptingTest, HeadlessCliScriptTransactionalCommitVsDryRunWritesOutputAndProject) {
    const std::vector<std::uint8_t> orig_bytes = make_synthetic_x86_64_macho();
    const TempDirGuard tmp{};
    const std::filesystem::path macho_bin = tmp.write_bytes("orig.macho", orig_bytes);
    const std::filesystem::path dry_out_bin = tmp.path() / "dry_out.macho";
    const std::filesystem::path dry_proj = tmp.path() / "dry.peproj";

    // 1. Dry-run with `--script-allow-mutations` (no peelf.commit()) does NOT write outputs.
    {
        const std::filesystem::path dry_lua = tmp.write_text(
            "dry.lua",
            R"lua(
                local entry = peelf.target_info().entry_point
                peelf.stage_patch(entry, "\x90\x90\xc3")
                peelf.set_label(entry, "dry_label")
                peelf.add_bookmark(entry, "DryBM")
            )lua");
        const std::array<std::string, 11> args{
            "--headless", macho_bin.string(),
            "--script", dry_lua.string(),
            "--script-allow-mutations",
            "--output-binary", dry_out_bin.string(),
            "--project", dry_proj.string(),
            "--format", "json"};
        const auto res = run_viewer_cli_subprocess(args);
        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("\"committed\": false"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"output_binary_written\": false"), std::string::npos);
        EXPECT_FALSE(std::filesystem::exists(dry_out_bin));
        EXPECT_FALSE(std::filesystem::exists(dry_proj));
        EXPECT_EQ(read_all_bytes(macho_bin), orig_bytes);
    }

    // 2. Transactional commit writes patched binary + PEELF_PROJECT v2 workspace atomically.
    const std::filesystem::path committed_bin = tmp.path() / "patched.macho";
    const std::filesystem::path committed_proj = tmp.path() / "workspace.peproj";
    {
        const std::filesystem::path commit_lua = tmp.write_text(
            "commit.lua",
            R"lua(
                local entry = peelf.target_info().entry_point
                peelf.stage_patch(entry, "\x31\xc0\xc3")
                peelf.set_label(entry, "cli_fast_entry")
                peelf.set_comment(entry, "committed via headless --script")
                peelf.add_bookmark(entry, "HeadlessCommitBM")
                assert(peelf.commit() == true)
            )lua");
        const std::array<std::string, 11> args{
            "--headless", macho_bin.string(),
            "--script", commit_lua.string(),
            "--script-allow-mutations",
            "--output-binary", committed_bin.string(),
            "--project", committed_proj.string(),
            "--format", "json"};
        const auto res = run_viewer_cli_subprocess(args);
        ASSERT_TRUE(res.launched) << res.launch_error;
        EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("\"committed\": true"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"output_binary_written\": true"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"project_written\": true"), std::string::npos);

        // Input binary remains untouched; `--output-binary` carries the 3-byte patch @ 0xC00.
        EXPECT_EQ(read_all_bytes(macho_bin), orig_bytes);
        const std::vector<std::uint8_t> out_bytes = read_all_bytes(committed_bin);
        ASSERT_EQ(out_bytes.size(), orig_bytes.size());
        EXPECT_EQ(out_bytes[0xC00u], 0x31u);
        EXPECT_EQ(out_bytes[0xC01u], 0xC0u);
        EXPECT_EQ(out_bytes[0xC02u], 0xC3u);

        // Saved `.peproj` round-trips cleanly through `viewer::decode_project`.
        const auto proj_text = viewer::read_project_file(committed_proj);
        ASSERT_TRUE(proj_text.has_value()) << proj_text.error().message;
        const auto decoded = viewer::decode_project(*proj_text);
        ASSERT_TRUE(decoded.has_value()) << decoded.error().message;
        ASSERT_EQ(decoded->patches.size(), 1u);
        EXPECT_EQ(decoded->patches[0].offset, 0xC00u);
        EXPECT_EQ(decoded->patches[0].patched, (std::vector<std::uint8_t>{0x31u, 0xC0u, 0xC3u}));

        const auto note_it = decoded->annotations.find(0x100000C00ULL);
        ASSERT_NE(note_it, decoded->annotations.end());
        EXPECT_EQ(note_it->second.name, "cli_fast_entry");
        EXPECT_EQ(note_it->second.comment, "committed via headless --script");

        ASSERT_EQ(decoded->bookmarks.size(), 1u);
        EXPECT_EQ(decoded->bookmarks[0].address, 0x100000C00ULL);
        EXPECT_EQ(decoded->bookmarks[0].label, "HeadlessCommitBM");
    }
}
#endif

