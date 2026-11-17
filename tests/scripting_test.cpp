#include "peelf/scripting.hpp"

#include "peelf/binary_image.hpp"
#include "peelf/capability_matrix.hpp"
#include "peelf/macho_image.hpp"
#include "peelf/patching.hpp"
#include "peelf/process.hpp"

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

    ~TempFileGuard() { cleanup(); }

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

    static LoadedStaticFixture from_bytes(std::vector<std::uint8_t> bytes) {
        TempFileGuard guard(bytes);
        auto parsed = peelf::parse_image(bytes);
        EXPECT_TRUE(parsed.has_value());
        auto paged_res = peelf::PagedBinaryImage::open(guard.path(), 64u);
        EXPECT_TRUE(paged_res.has_value()) << paged_res.error().message;
        return LoadedStaticFixture{
            .raw_bytes = std::move(bytes),
            .temp_file = std::move(guard),
            .image = std::move(*parsed),
            .paged = std::move(*paged_res),
            .workspace = peelf::ProjectWorkspace{},
        };
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

    auto fixture = LoadedStaticFixture::from_bytes(read_all_bytes(elf_path));
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

    auto fixture = LoadedStaticFixture::from_bytes(read_all_bytes(pe_path));
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());
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
    auto fixture = LoadedStaticFixture::from_bytes(make_synthetic_x86_64_macho());

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
