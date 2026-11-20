// SPDX-License-Identifier: BSD-2-Clause
#include <gtest/gtest.h>

#include "analysis/function_index.hpp"
#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "ui/command_palette.hpp"
#include "ui/workspace_layout.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/process.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/signatures.hpp>
#include <peelf/subprocess.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

void put16_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off + 0u] = static_cast<std::uint8_t>(v & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put32_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

void put64_le(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8u; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu);
    }
}

void put32_be(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    b[off + 0u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    b[off + 1u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    b[off + 2u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    b[off + 3u] = static_cast<std::uint8_t>(v & 0xFFu);
}

struct RichItemSpec {
    std::uint16_t prod_id{0};
    std::uint16_t build{0};
    std::uint32_t count{0};
};

// Builds a minimal valid 64-bit PE32+ image with an optional synthesized PE Rich header.
std::vector<std::uint8_t> build_pe64_with_rich(
    std::span<const RichItemSpec> rich_items,
    bool tamper_xor_key = false,
    std::size_t rdata_raw_size = 0x1000u) {
    const std::uint32_t e_lfanew = 0xC0u;
    const std::size_t text_off = 0x400u;
    const std::size_t text_sz = 0x200u;
    const std::size_t rdata_off = 0x600u;
    const std::size_t total_sz = rdata_off + rdata_raw_size;

    std::vector<std::uint8_t> b(total_sz, 0u);
    b[0u] = 'M';
    b[1u] = 'Z';
    // Deterministic DOS stub bytes in [0x02..0x3B)
    b[0x02u] = 0x90u;
    b[0x04u] = 0x03u;
    put32_le(b, 0x3Cu, e_lfanew);

    if (!rich_items.empty()) {
        const std::size_t dans_off = 0x50u;
        // Compute standard rotated-left Rich checksum:
        // 1) Sum(rotl(byte[i], i & 31)) for i in [0..dans_off) with e_lfanew [0x3C..0x3F] zeroed.
        std::uint32_t csum = static_cast<std::uint32_t>(dans_off);
        for (std::size_t i = 0; i < dans_off; ++i) {
            if (i >= 0x3Cu && i < 0x40u) {
                continue;
            }
            csum += std::rotl(static_cast<std::uint32_t>(b[i]), static_cast<int>(i & 31u));
        }
        // 2) Sum(rotl(comp_id, count & 31)) for each @comp.id entry.
        for (const RichItemSpec& item : rich_items) {
            const std::uint32_t comp_id =
                (static_cast<std::uint32_t>(item.prod_id) << 16u) | item.build;
            csum += std::rotl(comp_id, static_cast<int>(item.count & 31u));
        }

        const std::uint32_t mask_key = csum;
        // 'DanS' (0x536E6144) + 3 zero DWORDs masked by mask_key
        put32_le(b, dans_off + 0u, 0x536E6144u ^ mask_key);
        put32_le(b, dans_off + 4u, 0u ^ mask_key);
        put32_le(b, dans_off + 8u, 0u ^ mask_key);
        put32_le(b, dans_off + 12u, 0u ^ mask_key);

        std::size_t cur = dans_off + 16u;
        for (const RichItemSpec& item : rich_items) {
            const std::uint32_t comp_id =
                (static_cast<std::uint32_t>(item.prod_id) << 16u) | item.build;
            put32_le(b, cur + 0u, comp_id ^ mask_key);
            put32_le(b, cur + 4u, item.count ^ mask_key);
            cur += 8u;
        }
        // 'Rich' (0x68636952) + stored XOR key
        put32_le(b, cur + 0u, 0x68636952u);
        put32_le(b, cur + 4u, tamper_xor_key ? (mask_key ^ 0x00000001u) : mask_key);
    }

    // PE\0\0 header @ e_lfanew (0xC0)
    b[e_lfanew + 0u] = 'P';
    b[e_lfanew + 1u] = 'E';
    put16_le(b, e_lfanew + 4u, 0x8664u); // AMD64
    put16_le(b, e_lfanew + 6u, 2u);      // .text + .rdata
    put16_le(b, e_lfanew + 20u, 0xF0u);  // SizeOfOptionalHeader
    put16_le(b, e_lfanew + 22u, 0x0022u);

    const std::size_t opt = e_lfanew + 24u;
    put16_le(b, opt + 0x00u, 0x20Bu); // PE32+
    put32_le(b, opt + 0x10u, 0x1000u); // AddressOfEntryPoint
    put64_le(b, opt + 0x18u, 0x140000000ull); // ImageBase
    put32_le(b, opt + 0x20u, 0x1000u); // SectionAlignment
    put32_le(b, opt + 0x24u, 0x200u);  // FileAlignment
    const std::uint32_t aligned_rdata_vsize =
        static_cast<std::uint32_t>(((rdata_raw_size + 0xFFFu) / 0x1000u) * 0x1000u);
    put32_le(b, opt + 0x38u, 0x2000u + aligned_rdata_vsize); // SizeOfImage
    put32_le(b, opt + 0x3Cu, 0x400u);                        // SizeOfHeaders
    put16_le(b, opt + 0x46u, 0x4160u);                       // DllCharacteristics
    put32_le(b, opt + 0x6Cu, 16u);                           // NumberOfRvaAndSizes

    auto write_sec = [&](std::size_t idx,
                         const char name8[8],
                         std::uint32_t vsize,
                         std::uint32_t rva,
                         std::uint32_t raw_sz,
                         std::uint32_t raw_off,
                         std::uint32_t ch) {
        const std::size_t sh = opt + 0xF0u + idx * 40u;
        std::memcpy(&b[sh], name8, 8u);
        put32_le(b, sh + 8u, vsize);
        put32_le(b, sh + 12u, rva);
        put32_le(b, sh + 16u, raw_sz);
        put32_le(b, sh + 20u, raw_off);
        put32_le(b, sh + 36u, ch);
    };

    write_sec(0u,
              ".text\0\0\0",
              static_cast<std::uint32_t>(text_sz),
              0x1000u,
              static_cast<std::uint32_t>(text_sz),
              static_cast<std::uint32_t>(text_off),
              0x60000020u); // RX
    write_sec(1u,
              ".rdata\0\0",
              static_cast<std::uint32_t>(rdata_raw_size),
              0x2000u,
              static_cast<std::uint32_t>(rdata_raw_size),
              static_cast<std::uint32_t>(rdata_off),
              0x40000040u); // R

    b[text_off] = 0xC3u; // ret
    return b;
}

constexpr std::array<std::uint8_t, 256> kAesSbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

std::vector<std::uint8_t> build_crc32_ieee_table_le() {
    std::vector<std::uint8_t> tbl(256u * 4u, 0u);
    for (std::uint32_t i = 0; i < 256u; ++i) {
        std::uint32_t c = i;
        for (int b = 0; b < 8; ++b) {
            c = (c & 1u) != 0u ? (0xEDB88320u ^ (c >> 1u)) : (c >> 1u);
        }
        put32_le(tbl, static_cast<std::size_t>(i) * 4u, c);
    }
    return tbl;
}

class FakeSignatureProcessSession final : public peelf::IProcessSession {
public:
    struct BackedRegion {
        peelf::MemoryRegion region{};
        std::vector<std::uint8_t> data{};
    };

    explicit FakeSignatureProcessSession(std::vector<BackedRegion> regions)
        : regions_(std::move(regions)) {
        info_.pid = 4242u;
        info_.name = "fake_crypto_target";
    }

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_alive() const noexcept override { return true; }
    [[nodiscard]] bool is_read_only() const noexcept override { return true; }

    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        std::vector<peelf::MemoryRegion> out;
        out.reserve(regions_.size());
        for (const BackedRegion& r : regions_) {
            out.push_back(r.region);
        }
        return out;
    }

    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return std::vector<peelf::ModuleInfo>{};
    }

    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        for (const BackedRegion& r : regions_) {
            if (!r.region.protection.readable) {
                continue;
            }
            if (address >= r.region.start_address && address < r.region.end_address) {
                const auto off = static_cast<std::size_t>(address - r.region.start_address);
                if (off >= r.data.size()) {
                    return peelf::make_error("offset outside backed buffer");
                }
                const std::size_t n = std::min(buffer.size(), r.data.size() - off);
                std::memcpy(buffer.data(), r.data.data() + off, n);
                return n;
            }
        }
        return peelf::make_error("unmapped or unreadable");
    }

    [[nodiscard]] peelf::Result<std::size_t> write_memory(
        std::uint64_t,
        std::span<const std::uint8_t>,
        peelf::MemoryWriteOptions) override {
        return peelf::make_error("read-only");
    }

private:
    peelf::ProcessInfo info_{};
    std::vector<BackedRegion> regions_{};
};

struct TempTestDir {
    std::filesystem::path dir{};
    explicit TempTestDir(std::string_view prefix) {
        static std::atomic<std::uint64_t> s_seq{0};
        const std::uint64_t seq = s_seq.fetch_add(1u, std::memory_order_relaxed);
#ifdef _WIN32
        const int pid = _getpid();
#else
        const int pid = static_cast<int>(::getpid());
#endif
        dir = std::filesystem::temp_directory_path() /
              (std::string(prefix) + "-" + std::to_string(pid) + "-" + std::to_string(seq));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
    }
    ~TempTestDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    TempTestDir(const TempTestDir&) = delete;
    TempTestDir& operator=(const TempTestDir&) = delete;
    TempTestDir(TempTestDir&&) = delete;
    TempTestDir& operator=(TempTestDir&&) = delete;
};

void write_binary_file(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(static_cast<bool>(ofs));
    ofs.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(static_cast<bool>(ofs));
}

void write_text_file(const std::filesystem::path& path, std::string_view text) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(static_cast<bool>(ofs));
    ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
    ASSERT_TRUE(static_cast<bool>(ofs));
}

const peelf::CryptoSignatureHit* find_crypto_hit(
    std::span<const peelf::CryptoSignatureHit> hits,
    std::string_view id) {
    for (const peelf::CryptoSignatureHit& h : hits) {
        if (h.id == id) {
            return &h;
        }
    }
    return nullptr;
}

} // namespace

// ===========================================================================
// 1. PE Rich Header Decoder & Checksum Verification
// ===========================================================================

TEST(SignaturesAndCryptoTest, PeRichHeaderValidDecodeAndRotatedChecksum) {
    const std::array<RichItemSpec, 3> items{{
        {.prod_id = 0x0105u, .build = 33808u, .count = 14u}, // MSVC C++ Compiler
        {.prod_id = 0x0103u, .build = 33808u, .count = 2u},  // MASM Assembler
        {.prod_id = 0x0102u, .build = 33808u, .count = 1u},  // MSVC Linker
    }};
    const std::vector<std::uint8_t> pe = build_pe64_with_rich(items, /*tamper_xor_key=*/false);

    const std::optional<peelf::PeRichHeader> rich = peelf::parse_pe_rich_header(pe);
    ASSERT_TRUE(rich.has_value());
    EXPECT_TRUE(rich->checksum_valid) << rich->diagnostic;
    EXPECT_EQ(rich->xor_key, rich->computed_checksum);
    EXPECT_EQ(rich->dans_offset, 0x50u);
    ASSERT_EQ(rich->entries.size(), 3u);

    EXPECT_EQ(rich->entries[0].prod_id, 0x0105u);
    EXPECT_EQ(rich->entries[0].build_number, 33808u);
    EXPECT_EQ(rich->entries[0].use_count, 14u);
    EXPECT_NE(rich->entries[0].tool_category.find("C++"), std::string::npos);

    EXPECT_EQ(rich->entries[1].prod_id, 0x0103u);
    EXPECT_NE(rich->entries[1].tool_category.find("MASM"), std::string::npos);

    EXPECT_EQ(rich->entries[2].prod_id, 0x0102u);
    EXPECT_NE(rich->entries[2].tool_category.find("Linker"), std::string::npos);
}

TEST(SignaturesAndCryptoTest, PeRichHeaderDetectsTamperedEntryAndXorKeyMismatch) {
    const std::array<RichItemSpec, 2> items{{
        {.prod_id = 0x0104u, .build = 33523u, .count = 7u},
        {.prod_id = 0x0102u, .build = 33523u, .count = 1u},
    }};
    std::vector<std::uint8_t> pe = build_pe64_with_rich(items, /*tamper_xor_key=*/false);
    // Tamper one masked @comp.id count word at 0x50 + 16 + 4 without updating xor_key:
    // DanS remains valid under xor_key, but rotated checksum over entries diverges!
    pe[0x50u + 16u + 4u] ^= 0x04u;

    const std::optional<peelf::PeRichHeader> rich = peelf::parse_pe_rich_header(pe);
    ASSERT_TRUE(rich.has_value());
    EXPECT_FALSE(rich->checksum_valid);
    EXPECT_NE(rich->xor_key, rich->computed_checksum);
    EXPECT_EQ(rich->entries.size(), 2u);

    // Tampered trailing XOR key: recovered via DanS zero-padding, flagged invalid with diagnostic.
    const std::vector<std::uint8_t> tampered_key_pe =
        build_pe64_with_rich(items, /*tamper_xor_key=*/true);
    const std::optional<peelf::PeRichHeader> tampered_rich =
        peelf::parse_pe_rich_header(tampered_key_pe);
    ASSERT_TRUE(tampered_rich.has_value());
    EXPECT_FALSE(tampered_rich->checksum_valid);
    EXPECT_FALSE(tampered_rich->diagnostic.empty());
}

TEST(SignaturesAndCryptoTest, PeRichHeaderHandlesAbsentTruncatedAndNonPeSafely) {
    // Richless PE
    const std::vector<std::uint8_t> clean_pe = build_pe64_with_rich({});
    EXPECT_FALSE(peelf::parse_pe_rich_header(clean_pe).has_value());

    // Stubless PE (e_lfanew == 0x40)
    std::vector<std::uint8_t> stubless(0x200u, 0u);
    stubless[0] = 'M';
    stubless[1] = 'Z';
    put32_le(stubless, 0x3Cu, 0x40u);
    stubless[0x40u] = 'P';
    stubless[0x41u] = 'E';
    EXPECT_FALSE(peelf::parse_pe_rich_header(stubless).has_value());

    // Truncated (< 0x40 bytes) & ELF magic
    const std::array<std::uint8_t, 8> tiny{'M', 'Z', 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(peelf::parse_pe_rich_header(tiny).has_value());
    const std::array<std::uint8_t, 64> elf_hdr{0x7Fu, 'E', 'L', 'F'};
    EXPECT_FALSE(peelf::parse_pe_rich_header(elf_hdr).has_value());

    // Corrupted DanS + corrupted pad DWORDs so neither pass can locate a valid Rich block
    const std::array<RichItemSpec, 1> one_item{{{.prod_id = 0x0104u, .build = 30000u, .count = 1u}}};
    std::vector<std::uint8_t> broken_dans =
        build_pe64_with_rich(one_item, /*tamper_xor_key=*/true);
    broken_dans[0x50u + 4u] ^= 0xAAu;
    EXPECT_FALSE(peelf::parse_pe_rich_header(broken_dans).has_value());
}

// ===========================================================================
// 2. Crypto, Hash, Compression, & Packer Constant Detector
// ===========================================================================

TEST(SignaturesAndCryptoTest, DetectsStaticCryptoHashCrcPackerAndHighEntropyConstants) {
    std::vector<std::uint8_t> pe = build_pe64_with_rich({}, false, /*rdata_raw_size=*/0x2000u);
    // .rdata (file offset 0x600 -> RVA 0x2000 -> VA 0x140002000):
    // 1) AES S-Box @ 0x600 (VA 0x140002000)
    std::memcpy(&pe[0x600u], kAesSbox.data(), kAesSbox.size());

    // 2) SHA-256 first 8 round constants (LE DWORDs) @ 0x740 (VA 0x140002140)
    constexpr std::array<std::uint32_t, 8> kSha256K8 = {
        0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
        0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    };
    for (std::size_t i = 0; i < kSha256K8.size(); ++i) {
        put32_le(pe, 0x740u + i * 4u, kSha256K8[i]);
    }
    // Also place Big-Endian SHA-256 constants @ 0x780 to verify BE detection
    for (std::size_t i = 0; i < kSha256K8.size(); ++i) {
        put32_be(pe, 0x780u + i * 4u, kSha256K8[i]);
    }

    // 3) ChaCha20 sigma "expand 32-byte k" @ 0x7C0 (VA 0x1400021C0)
    constexpr std::string_view kChaChaSigma = "expand 32-byte k";
    std::memcpy(&pe[0x7C0u], kChaChaSigma.data(), kChaChaSigma.size());

    // 4) CRC32 IEEE 256-entry lookup table @ 0x800 (VA 0x140002200)
    const std::vector<std::uint8_t> crc_tbl = build_crc32_ieee_table_le();
    std::memcpy(&pe[0x800u], crc_tbl.data(), crc_tbl.size());

    // 5) UPX! magic header @ 0xD00 (VA 0x140002700)
    std::memcpy(&pe[0xD00u], "UPX!", 4u);

    // 6) Zstandard magic 0xFD2FB528 (LE: 28 B5 2F FD) @ 0xD20
    put32_le(pe, 0xD20u, 0xFD2FB528u);

    auto parsed = peelf::parse_image(pe);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const std::vector<peelf::CryptoSignatureHit> hits =
        peelf::scan_crypto_and_packer_constants(pe, parsed->get());

    const auto* aes = find_crypto_hit(hits, "CRYPTO_AES_SBOX");
    ASSERT_NE(aes, nullptr);
    EXPECT_EQ(aes->file_offset, std::optional<std::uint64_t>(0x600u));
    EXPECT_EQ(aes->virtual_address, std::optional<std::uint64_t>(0x140002000ull));
    EXPECT_EQ(aes->section_name, ".rdata");
    EXPECT_EQ(aes->category, "Symmetric Cipher");

    const bool found_sha_le = std::ranges::any_of(hits, [](const peelf::CryptoSignatureHit& h) {
        return h.id == "HASH_SHA256_K" &&
               h.file_offset == std::optional<std::uint64_t>(0x740u) &&
               h.virtual_address == std::optional<std::uint64_t>(0x140002140ull);
    });
    const bool found_sha_be = std::ranges::any_of(hits, [](const peelf::CryptoSignatureHit& h) {
        return h.id == "HASH_SHA256_K" &&
               h.file_offset == std::optional<std::uint64_t>(0x780u) &&
               h.virtual_address == std::optional<std::uint64_t>(0x140002180ull);
    });
    EXPECT_TRUE(found_sha_le);
    EXPECT_TRUE(found_sha_be);

    const auto* chacha = find_crypto_hit(hits, "CRYPTO_CHACHA20_SIGMA");
    ASSERT_NE(chacha, nullptr);
    EXPECT_EQ(chacha->file_offset, std::optional<std::uint64_t>(0x7C0u));
    EXPECT_EQ(chacha->virtual_address, std::optional<std::uint64_t>(0x1400021C0ull));

    const auto* crc = find_crypto_hit(hits, "CHECKSUM_CRC32_IEEE");
    ASSERT_NE(crc, nullptr);
    EXPECT_EQ(crc->file_offset, std::optional<std::uint64_t>(0x800u));
    EXPECT_EQ(crc->virtual_address, std::optional<std::uint64_t>(0x140002200ull));

    const auto* upx_hdr = find_crypto_hit(hits, "PACKER_UPX_MAGIC");
    ASSERT_NE(upx_hdr, nullptr);
    EXPECT_EQ(upx_hdr->file_offset, std::optional<std::uint64_t>(0xD00u));

    const auto* zstd = find_crypto_hit(hits, "COMPRESS_ZSTD_MAGIC");
    ASSERT_NE(zstd, nullptr);
    EXPECT_EQ(zstd->file_offset, std::optional<std::uint64_t>(0xD20u));
}

TEST(SignaturesAndCryptoTest, DetectsUpxSectionAndHighEntropyPackedExecutableSection) {
    // Build a PE64 whose executable section is named "UPX1" and has 4096 bytes of uniform
    // pseudo-random (8.0 bits/byte) packed data.
    std::vector<std::uint8_t> pe(0x2800u, 0u);
    pe[0] = 'M';
    pe[1] = 'Z';
    put32_le(pe, 0x3Cu, 0x80u);
    pe[0x80u] = 'P';
    pe[0x81u] = 'E';
    put16_le(pe, 0x84u, 0x8664u);
    put16_le(pe, 0x86u, 1u);
    put16_le(pe, 0x94u, 0xF0u);
    put16_le(pe, 0x96u, 0x0022u);
    const std::size_t opt = 0x98u;
    put16_le(pe, opt + 0x00u, 0x20Bu);
    put32_le(pe, opt + 0x10u, 0x1000u);
    put64_le(pe, opt + 0x18u, 0x140000000ull);
    put32_le(pe, opt + 0x20u, 0x1000u);
    put32_le(pe, opt + 0x24u, 0x200u);
    put32_le(pe, opt + 0x38u, 0x3000u);
    put32_le(pe, opt + 0x3Cu, 0x400u);
    put32_le(pe, opt + 0x6Cu, 16u);

    const std::size_t sh = opt + 0xF0u;
    std::memcpy(&pe[sh], "UPX1\0\0\0\0", 8u);
    put32_le(pe, sh + 8u, 0x1000u);
    put32_le(pe, sh + 12u, 0x1000u);
    put32_le(pe, sh + 16u, 0x1000u);
    put32_le(pe, sh + 20u, 0x400u);
    put32_le(pe, sh + 36u, 0xE0000020u); // RWX

    // Fill [0x400..0x1400) with uniform byte distribution (each byte 0..255 appears 16 times -> H = 8.0)
    for (std::size_t i = 0; i < 0x1000u; ++i) {
        pe[0x400u + i] = static_cast<std::uint8_t>((i * 73u + 19u) & 0xFFu);
    }
    EXPECT_NEAR(peelf::compute_shannon_entropy(std::span<const std::uint8_t>(&pe[0x400u], 0x1000u)),
                8.0,
                1e-6);

    auto parsed = peelf::parse_image(pe);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    const auto hits = peelf::scan_crypto_and_packer_constants(pe, parsed->get());
    EXPECT_NE(find_crypto_hit(hits, "PACKER_UPX_SECTION"), nullptr);
    const auto* ent = find_crypto_hit(hits, "PACKER_HIGH_ENTROPY_EXEC");
    ASSERT_NE(ent, nullptr);
    EXPECT_EQ(ent->virtual_address, std::optional<std::uint64_t>(0x140001000ull));
    EXPECT_EQ(ent->section_name, "UPX1");
}

TEST(SignaturesAndCryptoTest, ScansLiveProcessReadableRegionsOnly) {
    std::vector<std::uint8_t> readable_buf(0x400u, 0u);
    std::memcpy(&readable_buf[0x80u], kAesSbox.data(), kAesSbox.size());

    std::vector<std::uint8_t> noaccess_buf(0x400u, 0u);
    std::memcpy(&noaccess_buf[0x40u], "expand 32-byte k", 16u);

    std::vector<FakeSignatureProcessSession::BackedRegion> regions{};
    regions.push_back(FakeSignatureProcessSession::BackedRegion{
        .region = peelf::MemoryRegion{
            .start_address = 0x7FF000000000ull,
            .end_address = 0x7FF000000400ull,
            .protection = {.readable = true, .writable = false, .executable = false},
            .kind = peelf::MemoryRegionKind::Heap,
            .pathname = "[heap]",
        },
        .data = std::move(readable_buf),
    });
    regions.push_back(FakeSignatureProcessSession::BackedRegion{
        .region = peelf::MemoryRegion{
            .start_address = 0x7FF000010000ull,
            .end_address = 0x7FF000010400ull,
            .protection = {.readable = false, .writable = false, .executable = false},
            .kind = peelf::MemoryRegionKind::Anonymous,
            .pathname = "[guard]",
        },
        .data = std::move(noaccess_buf),
    });

    FakeSignatureProcessSession session(std::move(regions));
    const auto hits = peelf::scan_crypto_and_packer_constants(session);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].id, "CRYPTO_AES_SBOX");
    EXPECT_FALSE(hits[0].file_offset.has_value());
    EXPECT_EQ(hits[0].virtual_address, std::optional<std::uint64_t>(0x7FF000000080ull));
    EXPECT_EQ(hits[0].section_name, "[heap]");
}

// ===========================================================================
// 3. Clean-Room YARA-Lite Parser, AST Evaluator, & Adversarial Diagnostics
// ===========================================================================

TEST(SignaturesAndCryptoTest, YaraLiteEvaluatesStringsHexWildcardsJumpsAndFullConditionAst) {
    std::vector<std::uint8_t> pe = build_pe64_with_rich({});
    // Place ASCII nocase string @ 0x620 ("SeCrEtToKeN") twice
    std::memcpy(&pe[0x620u], "SeCrEtToKeN", 11u);
    std::memcpy(&pe[0x640u], "secrettoken", 11u);

    // Place UTF-16LE wide string L"WidePayload" @ 0x680
    constexpr std::string_view kWideSrc = "WidePayload";
    for (std::size_t i = 0; i < kWideSrc.size(); ++i) {
        pe[0x680u + i * 2u] = static_cast<std::uint8_t>(kWideSrc[i]);
        pe[0x680u + i * 2u + 1u] = 0u;
    }

    // Place hex stub @ 0x410: 48 8B C4  [3 arbitrary bytes: 90 90 90]  E8 A4
    pe[0x410u] = 0x48u;
    pe[0x411u] = 0x8Bu;
    pe[0x412u] = 0xC4u;
    pe[0x413u] = 0x90u;
    pe[0x414u] = 0x90u;
    pe[0x415u] = 0x90u;
    pe[0x416u] = 0xE8u;
    pe[0x417u] = 0xA4u;

    // Place 256 high-entropy bytes @ 0x900 (each byte 0..255 once -> entropy == 8.0)
    for (std::size_t i = 0; i < 256u; ++i) {
        pe[0x900u + i] = static_cast<std::uint8_t>(i);
    }

    // Place big-endian marker @ 0xA20: DEADBEEF
    put32_be(pe, 0xA20u, 0xDEADBEEFu);

    auto parsed_img = peelf::parse_image(pe);
    ASSERT_TRUE(parsed_img.has_value());

    constexpr std::string_view kRuleText = R"YARA(
rule Complex_YaraLite_Verification : crypto test_tag {
    meta:
        description = "Verifies ascii/wide/nocase, hex wildcards/jumps, and AST intrinsics"
        severity = "error"
        author = "unit_test"
    strings:
        $s_tok = "SecretToken" ascii nocase
        $s_wide = "WidePayload" wide
        $h_stub = { 48 8B ?? [2-4] E8 ?4 }
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        uint32be(0xA20) == 0xDEADBEEF and
        filesize > 1KB and filesize < 1MB and
        entrypoint == 0x400 and
        entropy(0x900, 256) > 7.9 and
        #s_tok >= 2 and
        @s_tok == 0x620 and
        $h_stub at entrypoint + 0x10 and
        2 of ($s*) and
        all of them
}
)YARA";

    const peelf::SignatureRuleParseResult pr =
        peelf::parse_signature_rules(kRuleText, "unit_test.yar");
    ASSERT_TRUE(pr.ok()) << (pr.diagnostics.empty() ? "" : pr.diagnostics.front().message);
    ASSERT_EQ(pr.ruleset.rules.size(), 1u);

    const auto matches = peelf::evaluate_signature_rules(pr.ruleset, pe, parsed_img->get());
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].rule_name, "Complex_YaraLite_Verification");
    EXPECT_EQ(matches[0].severity, "error");
    ASSERT_EQ(matches[0].tags.size(), 2u);
    EXPECT_EQ(matches[0].tags[0], "crypto");
    EXPECT_EQ(matches[0].tags[1], "test_tag");
    EXPECT_GE(matches[0].string_matches.size(), 4u); // 2x $s_tok + 1x $s_wide + 1x $h_stub
}

TEST(SignaturesAndCryptoTest, BuiltinStarterRulesCompileCleanlyWithZeroBenignFalsePositives) {
    const peelf::SignatureRuleSet& builtins = peelf::builtin_signature_rules();
    EXPECT_GE(builtins.rules.size(), 8u);

    // Benign hardened PE64 should trigger zero built-in starter rules.
    const std::vector<std::uint8_t> benign_pe = build_pe64_with_rich({});
    auto parsed = peelf::parse_image(benign_pe);
    ASSERT_TRUE(parsed.has_value());
    const auto benign_matches =
        peelf::evaluate_signature_rules(builtins, benign_pe, parsed->get());
    EXPECT_TRUE(benign_matches.empty());

    // Add classic remote-thread injection API strings -> triggers Suspicious_Process_Injection_APIs.
    std::vector<std::uint8_t> inj_pe = benign_pe;
    std::memcpy(&inj_pe[0x620u], "VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0", 53u);
    const auto inj_matches =
        peelf::evaluate_signature_rules(builtins, inj_pe, parsed->get());
    ASSERT_FALSE(inj_matches.empty());
    const bool found_inj = std::ranges::any_of(inj_matches, [](const peelf::SignatureRuleMatch& m) {
        return m.rule_name == "Suspicious_Process_Injection_APIs";
    });
    EXPECT_TRUE(found_inj);
}

TEST(SignaturesAndCryptoTest, YaraLiteReportsExactLineColDiagnosticsAndRejectsPathologicalJumps) {
    // 1) Undefined identifier on line 6
    constexpr std::string_view kBadIdent =
        "rule Broken_Undefined {\n"
        "  strings:\n"
        "    $a = \"hello\"\n"
        "  condition:\n"
        "    $a and $missing_id\n"
        "}\n";
    const auto r1 = peelf::parse_signature_rules(kBadIdent, "bad1.yar");
    EXPECT_FALSE(r1.ok());
    ASSERT_FALSE(r1.diagnostics.empty());
    EXPECT_EQ(r1.diagnostics.front().line, 5u);
    EXPECT_GT(r1.diagnostics.front().column, 1u);

    // 2) Pathological hex jump [0-99999] > 4096 max bound
    constexpr std::string_view kHugeJump =
        "rule Pathological_Jump {\n"
        "  strings:\n"
        "    $h = { 4D 5A [0-99999] 50 45 }\n"
        "  condition:\n"
        "    $h\n"
        "}\n";
    const auto r2 = peelf::parse_signature_rules(kHugeJump, "bad2.yar");
    EXPECT_FALSE(r2.ok());
    ASSERT_FALSE(r2.diagnostics.empty());
    EXPECT_EQ(r2.diagnostics.front().line, 3u);

    // 3) Inverted hex jump [8-2]
    constexpr std::string_view kInvertedJump =
        "rule Inverted_Jump {\n"
        "  strings:\n"
        "    $h = { 90 [8-2] C3 }\n"
        "  condition:\n"
        "    $h\n"
        "}\n";
    const auto r3 = peelf::parse_signature_rules(kInvertedJump, "bad3.yar");
    EXPECT_FALSE(r3.ok());
    ASSERT_FALSE(r3.diagnostics.empty());
    EXPECT_EQ(r3.diagnostics.front().line, 3u);
}

// ===========================================================================
// 4. BinaryModel XRef-Function Resolution & CommandPalette Wiring
// ===========================================================================

TEST(SignaturesAndCryptoTest, BinaryModelResolvesRdataCryptoHitBackToReferencingFunctionAndPaletteIndexesPanel) {
    // Build a PE64 where:
    // - .text @ 0x140001000 (file 0x400) has `lea rax, [rip + 0xFF9]; ret`:
    //   48 8D 05 F9 0F 00 00 (7 bytes; next RIP = 0x140001007 + 0xFF9 = 0x140002000!)
    //   C3 (ret)
    // - .rdata @ 0x140002000 (file 0x600) holds the AES Rijndael S-Box!
    std::vector<std::uint8_t> pe = build_pe64_with_rich({});
    const std::array<std::uint8_t, 8> lea_ret = {
        0x48u, 0x8Du, 0x05u, 0xF9u, 0x0Fu, 0x00u, 0x00u, 0xC3u,
    };
    std::memcpy(&pe[0x400u], lea_ret.data(), lea_ret.size());
    std::memcpy(&pe[0x600u], kAesSbox.data(), kAesSbox.size());

    TempTestDir tmp("wu38-model");
    const std::filesystem::path bin_path = tmp.dir / "aes_xref.exe";
    write_binary_file(bin_path, pe);

    viewer::BinaryModel model;
    ASSERT_TRUE(model.load_file(bin_path.string())) << model.last_diagnostic();

    EXPECT_FALSE(model.pe_rich_header().has_value());
    ASSERT_FALSE(model.crypto_signatures().empty());
    const auto* aes = find_crypto_hit(model.crypto_signatures(), "CRYPTO_AES_SBOX");
    ASSERT_NE(aes, nullptr);
    ASSERT_EQ(aes->virtual_address, std::optional<std::uint64_t>(0x140002000ull));

    // Populate ReferenceIndex over the loaded image so RIP-relative LEA XRef is indexed.
    ASSERT_NE(model.image(), nullptr);
    const viewer::ReferenceIndex refs = viewer::ReferenceIndex::build(
        *model.image(), model.bytes(), false, viewer::ReferenceIndex::kDefaultByteBudget, &model.symbol_index());

    const auto resolved = model.resolve_hit_referencing_function(
        aes->virtual_address, aes->byte_length, &refs);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_TRUE(resolved->via_xref);
    EXPECT_EQ(resolved->function_va, 0x140001000ull);
    EXPECT_EQ(resolved->code_va, 0x140001000ull);
    EXPECT_FALSE(resolved->display_name.empty());

    // CommandPalette indexes WorkspacePanelId::SignaturesAndCrypto ("Signatures & Crypto").
    viewer::CommandPalette palette;
    const viewer::PaletteDataSources sources = viewer::make_palette_data_sources(model);
    const viewer::PaletteQueryResult results =
        palette.query("Signatures & Crypto", sources, {.max_results = 10u});
    const bool found_panel = std::ranges::any_of(results.items, [](const viewer::PaletteItem& item) {
        return item.primary_action.panel_id == viewer::WorkspacePanelId::SignaturesAndCrypto;
    });
    EXPECT_TRUE(found_panel);
}

// ===========================================================================
// 5. End-to-End Headless CLI (--rules, JSON, SARIF 2.1.0, & Exit Policy)
// ===========================================================================

#if defined(PEELF_VIEWER_EXECUTABLE_PATH)
TEST(SignaturesAndCryptoTest, HeadlessCliRulesFlagEmitsJsonSarifAndEnforcesFailOnPolicy) {
    const std::array<RichItemSpec, 1> rich_items{{
        {.prod_id = 0x0104u, .build = 33808u, .count = 5u},
    }};
    std::vector<std::uint8_t> pe = build_pe64_with_rich(rich_items);
    std::memcpy(&pe[0x600u], kAesSbox.data(), kAesSbox.size());
    std::memcpy(&pe[0x720u], "MALWARE_BEACON_V4", 17u);

    TempTestDir tmp("wu38-headless");
    const std::filesystem::path bin_path = tmp.dir / "sample.exe";
    const std::filesystem::path yar_path = tmp.dir / "beacon.yar";
    write_binary_file(bin_path, pe);

    write_text_file(
        yar_path,
        "rule Detect_Beacon_V4 : c2 implant {\n"
        "  meta:\n"
        "    description = \"Detects synthetic C2 beacon marker\"\n"
        "    severity = \"error\"\n"
        "  strings:\n"
        "    $b = \"MALWARE_BEACON_V4\" ascii\n"
        "  condition:\n"
        "    uint16(0) == 0x5A4D and $b\n"
        "}\n");

    const std::filesystem::path exe_path{PEELF_VIEWER_EXECUTABLE_PATH};

    // 1) JSON output with --rules
    {
        const std::array<std::string, 6> args = {
            "--headless",
            bin_path.string(),
            "--rules",
            yar_path.string(),
            "--format",
            "json",
        };
        const peelf::SubprocessResult res = peelf::run_subprocess_bounded(exe_path, args);
        ASSERT_FALSE(res.timed_out);
        EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("\"pe_rich_header\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"checksum_valid\": true"), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"crypto_signatures\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"CRYPTO_AES_SBOX\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"rule_matches\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"Detect_Beacon_V4\""), std::string::npos);
    }

    // 2) SARIF 2.1.0 output + --fail-on error triggers policy exit code 2
    {
        const std::array<std::string, 9> args = {
            "--headless",
            bin_path.string(),
            "--rules",
            yar_path.string(),
            "--no-builtin-rules",
            "--format",
            "sarif",
            "--fail-on",
            "error",
        };
        const peelf::SubprocessResult res = peelf::run_subprocess_bounded(exe_path, args);
        ASSERT_FALSE(res.timed_out);
        EXPECT_EQ(res.exit_code, 2) << res.stderr_text;
        EXPECT_NE(res.stdout_text.find("\"ruleId\": \"Detect_Beacon_V4\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"level\": \"error\""), std::string::npos);
        EXPECT_NE(res.stdout_text.find("\"offsetFromParent\": 1824"), std::string::npos); // 0x720 == 1824
    }
}
#endif
