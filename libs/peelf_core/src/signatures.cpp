// SPDX-License-Identifier: BSD-2-Clause
#include <peelf/signatures.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] constexpr std::uint16_t read_u16_le(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(buf[off]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(buf[off + 1u]) << 8u));
}

[[nodiscard]] constexpr std::uint16_t read_u16_be(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(buf[off]) << 8u) |
        static_cast<std::uint16_t>(buf[off + 1u]));
}

[[nodiscard]] constexpr std::uint32_t read_u32_le(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return static_cast<std::uint32_t>(buf[off]) |
           (static_cast<std::uint32_t>(buf[off + 1u]) << 8u) |
           (static_cast<std::uint32_t>(buf[off + 2u]) << 16u) |
           (static_cast<std::uint32_t>(buf[off + 3u]) << 24u);
}

[[nodiscard]] constexpr std::uint32_t read_u32_be(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(buf[off]) << 24u) |
           (static_cast<std::uint32_t>(buf[off + 1u]) << 16u) |
           (static_cast<std::uint32_t>(buf[off + 2u]) << 8u) |
           static_cast<std::uint32_t>(buf[off + 3u]);
}

[[nodiscard]] constexpr std::uint64_t read_u64_le(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return static_cast<std::uint64_t>(read_u32_le(buf, off)) |
           (static_cast<std::uint64_t>(read_u32_le(buf, off + 4u)) << 32u);
}

[[nodiscard]] constexpr std::uint64_t read_u64_be(std::span<const std::uint8_t> buf,
                                                  std::size_t off) noexcept {
    return (static_cast<std::uint64_t>(read_u32_be(buf, off)) << 32u) |
           static_cast<std::uint64_t>(read_u32_be(buf, off + 4u));
}

[[nodiscard]] constexpr std::uint8_t ascii_lower_u8(std::uint8_t ch) noexcept {
    if (ch >= static_cast<std::uint8_t>('A') && ch <= static_cast<std::uint8_t>('Z')) {
        return static_cast<std::uint8_t>(ch + (static_cast<std::uint8_t>('a') -
                                               static_cast<std::uint8_t>('A')));
    }
    return ch;
}

[[nodiscard]] constexpr char ascii_lower_char(char ch) noexcept {
    return static_cast<char>(ascii_lower_u8(static_cast<std::uint8_t>(ch)));
}

[[nodiscard]] constexpr bool is_ascii_alpha(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    return (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z');
}

[[nodiscard]] constexpr bool is_ascii_digit(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    return u >= '0' && u <= '9';
}

[[nodiscard]] constexpr bool is_ascii_alnum_or_underscore(char ch) noexcept {
    return is_ascii_alpha(ch) || is_ascii_digit(ch) || ch == '_';
}

[[nodiscard]] constexpr int parse_hex_nibble(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    if (u >= '0' && u <= '9') {
        return static_cast<int>(u - '0');
    }
    if (u >= 'a' && u <= 'f') {
        return static_cast<int>(u - 'a' + 10u);
    }
    if (u >= 'A' && u <= 'F') {
        return static_cast<int>(u - 'A' + 10u);
    }
    return -1;
}

[[nodiscard]] std::string to_lower_ascii(std::string_view text) {
    std::string out{};
    out.reserve(text.size());
    for (const char ch : text) {
        out.push_back(ascii_lower_char(ch));
    }
    return out;
}

[[nodiscard]] std::string normalize_rule_severity(std::string_view raw) {
    const std::string low = to_lower_ascii(raw);
    if (low == "error" || low == "critical" || low == "high") {
        return "error";
    }
    if (low == "note" || low == "info" || low == "informational" || low == "low") {
        return "note";
    }
    return "warning";
}

// ---------------------------------------------------------------------------
// Mathematical / Clean-Room Constant Table Generators (`consteval`)
// ---------------------------------------------------------------------------

[[nodiscard]] consteval std::uint8_t gf256_mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t p = 0u;
    std::uint8_t cur_a = a;
    std::uint8_t cur_b = b;
    for (int bit = 0; bit < 8; ++bit) {
        if ((cur_b & 1u) != 0u) {
            p ^= cur_a;
        }
        const bool hi = (cur_a & 0x80u) != 0u;
        cur_a = static_cast<std::uint8_t>(cur_a << 1u);
        if (hi) {
            cur_a ^= 0x1Bu;
        }
        cur_b = static_cast<std::uint8_t>(cur_b >> 1u);
    }
    return p;
}

[[nodiscard]] consteval std::uint8_t gf256_inv(std::uint8_t x) noexcept {
    if (x == 0u) {
        return 0u;
    }
    // x^254 in GF(2^8)
    std::uint8_t res = 1u;
    std::uint8_t base = x;
    std::uint32_t exp = 254u;
    while (exp > 0u) {
        if ((exp & 1u) != 0u) {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1u;
    }
    return res;
}

[[nodiscard]] consteval std::array<std::uint8_t, 256> make_aes_sbox() noexcept {
    std::array<std::uint8_t, 256> sbox{};
    for (std::size_t i = 0u; i < 256u; ++i) {
        const std::uint8_t inv = gf256_inv(static_cast<std::uint8_t>(i));
        const std::uint8_t s = static_cast<std::uint8_t>(
            inv ^ std::rotl<std::uint8_t>(inv, 1) ^ std::rotl<std::uint8_t>(inv, 2) ^
            std::rotl<std::uint8_t>(inv, 3) ^ std::rotl<std::uint8_t>(inv, 4) ^ 0x63u);
        sbox[i] = s;
    }
    return sbox;
}

[[nodiscard]] consteval std::array<std::uint8_t, 256> make_aes_inv_sbox(
    const std::array<std::uint8_t, 256>& sbox) noexcept {
    std::array<std::uint8_t, 256> inv{};
    for (std::size_t i = 0u; i < 256u; ++i) {
        inv[sbox[i]] = static_cast<std::uint8_t>(i);
    }
    return inv;
}

[[nodiscard]] consteval std::array<std::uint32_t, 256> make_aes_te0(
    const std::array<std::uint8_t, 256>& sbox) noexcept {
    std::array<std::uint32_t, 256> te0{};
    for (std::size_t i = 0u; i < 256u; ++i) {
        const std::uint8_t s = sbox[i];
        const std::uint8_t s2 = gf256_mul(s, 0x02u);
        const std::uint8_t s3 = static_cast<std::uint8_t>(s2 ^ s);
        te0[i] = (static_cast<std::uint32_t>(s2) << 24u) |
                 (static_cast<std::uint32_t>(s) << 16u) |
                 (static_cast<std::uint32_t>(s) << 8u) |
                 static_cast<std::uint32_t>(s3);
    }
    return te0;
}

[[nodiscard]] consteval std::array<std::uint32_t, 256> make_crc32_table(
    std::uint32_t reflected_poly) noexcept {
    std::array<std::uint32_t, 256> tbl{};
    for (std::uint32_t i = 0u; i < 256u; ++i) {
        std::uint32_t c = i;
        for (int bit = 0; bit < 8; ++bit) {
            if ((c & 1u) != 0u) {
                c = (c >> 1u) ^ reflected_poly;
            } else {
                c >>= 1u;
            }
        }
        tbl[i] = c;
    }
    return tbl;
}

constexpr auto kAesSbox = make_aes_sbox();
constexpr auto kAesInvSbox = make_aes_inv_sbox(kAesSbox);
constexpr auto kAesTe0 = make_aes_te0(kAesSbox);
constexpr auto kCrc32IeeeTable = make_crc32_table(0xEDB88320u);
constexpr auto kCrc32CastagnoliTable = make_crc32_table(0x82F63B78u);

static_assert(kAesSbox[0] == 0x63u && kAesSbox[1] == 0x7Cu && kAesSbox[2] == 0x77u &&
              kAesSbox[255] == 0x16u);
static_assert(kAesInvSbox[0] == 0x52u && kAesInvSbox[1] == 0x09u && kAesInvSbox[2] == 0x6Au &&
              kAesInvSbox[255] == 0x7Du);
static_assert(kAesTe0[0] == 0xC66363A5u && kAesTe0[1] == 0xF87C7C84u);
static_assert(kCrc32IeeeTable[0] == 0x00000000u && kCrc32IeeeTable[1] == 0x77073096u &&
              kCrc32IeeeTable[255] == 0x2D02EF8Du);
static_assert(kCrc32CastagnoliTable[0] == 0x00000000u && kCrc32CastagnoliTable[1] == 0xF26B8303u);

// FIPS 46-3 DES Initial Permutation (1-based) and 0-based variant
constexpr std::array<std::uint8_t, 64> kDesIpOneBased{{
    58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
}};

[[nodiscard]] consteval std::array<std::uint8_t, 64> make_des_ip_zero_based() noexcept {
    std::array<std::uint8_t, 64> out{};
    for (std::size_t i = 0u; i < 64u; ++i) {
        out[i] = static_cast<std::uint8_t>(kDesIpOneBased[i] - 1u);
    }
    return out;
}
constexpr auto kDesIpZeroBased = make_des_ip_zero_based();

// FIPS 46-3 DES S-Box S1 (4x16 = 64 bytes)
constexpr std::array<std::uint8_t, 64> kDesS1{{
    14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
    0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
    4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
    15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13,
}};

// Blowfish P-array initial 18 words (hex digits of pi - 3)
constexpr std::array<std::uint32_t, 18> kBlowfishP{{
    0x243F6A88u, 0x85A308D3u, 0x13198A2Eu, 0x03707344u, 0xA4093822u, 0x299F31D0u,
    0x082EFA98u, 0xEC4E6C89u, 0x452821E6u, 0x38D01377u, 0xBE5466CFu, 0x34E90C6Cu,
    0xC0AC29B7u, 0xC97C50DDu, 0x3F84D5B5u, 0xB5470917u, 0x9216D5D9u, 0x8979FB1Bu,
}};

// FIPS 180-4 SHA-256 K round constants (64 x 32-bit)
constexpr std::array<std::uint32_t, 64> kSha256K{{
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
}};

// FIPS 180-4 SHA-512 K round constants (first 16 of 80 x 64-bit, sufficient for 128B prefix + stride)
constexpr std::array<std::uint64_t, 80> kSha512K{{
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
}};

// BLAKE2b / SHA-512 initial chaining state IV (8 x 64-bit)
constexpr std::array<std::uint64_t, 8> kBlake2bSha512Iv{{
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
}};

// MD5 / SHA-1 initial state IV (5 x 32-bit; first 4 shared by MD5 and SHA-1)
constexpr std::array<std::uint32_t, 5> kMd5Sha1Iv{{
    0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u,
}};

// RFC 1951 Deflate length base table (29 entries) and distance base table (30 entries)
constexpr std::array<std::uint16_t, 29> kDeflateLengthBase{{
    3,  4,  5,  6,  7,  8,  9,  10, 11, 13, 15, 17, 19, 23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}};

constexpr std::array<std::uint16_t, 30> kDeflateDistBase{{
    1,    2,    3,    4,    5,    7,    9,    13,   17,   25,
    33,   49,   65,   97,   129,  193,  257,  385,  513,  769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
}};

// ---------------------------------------------------------------------------
// Offset / VA / Section Resolution Helper
// ---------------------------------------------------------------------------

struct ResolvedLocation {
    std::optional<std::uint64_t> file_offset{};
    std::optional<std::uint64_t> virtual_address{};
    std::string section_name{};
};

struct ScanAddressContext {
    const IBinaryImage* image{nullptr};
    std::optional<std::uint64_t> fixed_base_va{};
    std::string fallback_region_name{};
    bool has_file_offsets{true};
};

[[nodiscard]] ResolvedLocation resolve_location_at(const ScanAddressContext& ctx,
                                                   std::size_t local_offset) {
    ResolvedLocation loc{};
    const auto off64 = static_cast<std::uint64_t>(local_offset);
    if (ctx.has_file_offsets) {
        loc.file_offset = off64;
    }
    if (ctx.image != nullptr) {
        loc.virtual_address = ctx.image->file_offset_to_virtual_address(off64);
        for (const Section& sec : ctx.image->sections()) {
            if (sec.file_size > 0u && off64 >= sec.file_offset &&
                (off64 - sec.file_offset) < sec.file_size) {
                loc.section_name = sec.name;
                if (!loc.virtual_address.has_value() && sec.virtual_address != 0u) {
                    loc.virtual_address = sec.virtual_address + (off64 - sec.file_offset);
                }
                break;
            }
        }
        if (loc.section_name.empty()) {
            const std::uint64_t hdr_end = ctx.image->container_slice_offset() + 0x400u;
            if (off64 < hdr_end) {
                loc.section_name = "<headers>";
            } else {
                loc.section_name = "<overlay>";
            }
        }
    } else if (ctx.fixed_base_va.has_value()) {
        loc.virtual_address = *ctx.fixed_base_va + off64;
        loc.section_name = ctx.fallback_region_name;
    } else {
        loc.section_name = ctx.fallback_region_name;
    }
    return loc;
}

[[nodiscard]] std::size_t match_u32_table_run(std::span<const std::uint8_t> bytes,
                                              std::size_t start_off,
                                              std::span<const std::uint32_t> table,
                                              bool big_endian) noexcept {
    std::size_t matched_words = 0u;
    while (matched_words < table.size()) {
        const std::size_t pos = start_off + matched_words * 4u;
        if (pos + 4u > bytes.size()) {
            break;
        }
        const std::uint32_t got = big_endian ? read_u32_be(bytes, pos) : read_u32_le(bytes, pos);
        if (got != table[matched_words]) {
            break;
        }
        ++matched_words;
    }
    return matched_words;
}

[[nodiscard]] std::size_t match_u64_table_run(std::span<const std::uint8_t> bytes,
                                              std::size_t start_off,
                                              std::span<const std::uint64_t> table,
                                              bool big_endian) noexcept {
    std::size_t matched_words = 0u;
    while (matched_words < table.size()) {
        const std::size_t pos = start_off + matched_words * 8u;
        if (pos + 8u > bytes.size()) {
            break;
        }
        const std::uint64_t got = big_endian ? read_u64_be(bytes, pos) : read_u64_le(bytes, pos);
        if (got != table[matched_words]) {
            break;
        }
        ++matched_words;
    }
    return matched_words;
}

[[nodiscard]] bool match_u16_le_exact(std::span<const std::uint8_t> bytes,
                                      std::size_t start_off,
                                      std::span<const std::uint16_t> table) noexcept {
    if (start_off + table.size() * 2u > bytes.size()) {
        return false;
    }
    for (std::size_t i = 0u; i < table.size(); ++i) {
        if (read_u16_le(bytes, start_off + i * 2u) != table[i]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool match_u16_promoted_u32_le_exact(std::span<const std::uint8_t> bytes,
                                                   std::size_t start_off,
                                                   std::span<const std::uint16_t> table) noexcept {
    if (start_off + table.size() * 4u > bytes.size()) {
        return false;
    }
    for (std::size_t i = 0u; i < table.size(); ++i) {
        if (read_u32_le(bytes, start_off + i * 4u) != static_cast<std::uint32_t>(table[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_power_of_two_u32(std::uint32_t v) noexcept {
    return v != 0u && (v & (v - 1u)) == 0u;
}

[[nodiscard]] int confidence_rank(std::string_view conf) noexcept {
    if (conf == "High") {
        return 3;
    }
    if (conf == "Medium") {
        return 2;
    }
    return 1;
}

[[nodiscard]] bool is_section_envelope_hit(std::string_view hit_id) noexcept {
    return hit_id == "PACKER_HIGH_ENTROPY_EXEC" ||
           hit_id == "PACKER_UPX_SECTION" ||
           hit_id == "PACKER_MPRESS_SECTION" ||
           hit_id == "PACKER_ASPACK_SECTION" ||
           hit_id == "PACKER_VMPROTECT_SECTION" ||
           hit_id == "PACKER_THEMIDA_SECTION";
}

void scan_buffer_crypto_and_packers(std::span<const std::uint8_t> raw_bytes,
                                    const ScanAddressContext& ctx,
                                    std::vector<CryptoSignatureHit>& raw_hits) {
    if (raw_bytes.empty()) {
        return;
    }

    auto emit_hit = [&](std::string id,
                        std::string category,
                        std::string algorithm,
                        std::string summary,
                        std::string confidence,
                        std::size_t offset,
                        std::size_t byte_len) {
        ResolvedLocation loc = resolve_location_at(ctx, offset);
        CryptoSignatureHit hit{};
        hit.id = std::move(id);
        hit.category = std::move(category);
        hit.algorithm = std::move(algorithm);
        hit.summary = std::move(summary);
        hit.confidence = std::move(confidence);
        hit.file_offset = loc.file_offset;
        hit.virtual_address = loc.virtual_address;
        hit.byte_length = static_cast<std::uint64_t>(byte_len);
        hit.section_name = std::move(loc.section_name);
        raw_hits.push_back(std::move(hit));
    };

    constexpr std::string_view kChaChaSigma = "expand 32-byte k";
    constexpr std::string_view kSalsaTau = "expand 16-byte k";
    constexpr std::array<std::uint8_t, 6> kXzMagic{{0xFDu, '7', 'z', 'X', 'Z', 0x00u}};
    constexpr std::array<std::uint8_t, 6> k7zMagic{{'7', 'z', 0xBCu, 0xAFu, 0x27u, 0x1Cu}};
    constexpr std::string_view kZlibInflateSig = " inflate 1.";
    constexpr std::string_view kZlibDeflateSig = " deflate 1.";

    // Track covered RC5/RC6 windows and recent TEA delta offsets to avoid noisy duplicates
    std::vector<std::pair<std::size_t, std::size_t>> rc5_windows{};
    std::optional<std::size_t> last_upx_magic_off{};

    // First pass for RC5/RC6 P32 (`0xB7E15163`) paired with Q32 (`0x9E3779B9` or `-Q32 = 0x61C88647`)
    for (std::size_t i = 0u; i + 4u <= raw_bytes.size(); ++i) {
        const std::uint32_t le = read_u32_le(raw_bytes, i);
        const std::uint32_t be = read_u32_be(raw_bytes, i);
        if (le != 0xB7E15163u && be != 0xB7E15163u) {
            continue;
        }
        const bool is_be = (le != 0xB7E15163u);
        const std::size_t win_lo = (i > 64u) ? (i - 64u) : 0u;
        const std::size_t win_hi = std::min<std::size_t>(raw_bytes.size(), i + 68u);
        std::optional<std::size_t> q_pos{};
        for (std::size_t j = win_lo; j + 4u <= win_hi; ++j) {
            if (j == i) {
                continue;
            }
            const std::uint32_t q = is_be ? read_u32_be(raw_bytes, j) : read_u32_le(raw_bytes, j);
            if (q == 0x9E3779B9u || q == 0x61C88647u) {
                q_pos = j;
                break;
            }
        }
        if (q_pos.has_value()) {
            const std::size_t lo = std::min(i, *q_pos);
            const std::size_t hi = std::max(i, *q_pos) + 4u;
            rc5_windows.emplace_back(lo, hi);
            emit_hit("CRYPTO_RC5_RC6_PQ32",
                     "Symmetric Cipher",
                     "RC5 / RC6",
                     std::format("RC5/RC6 key-schedule magic constants P32=0xB7E15163 & Q32=0x9E3779B9 ({})",
                                 is_be ? "BE" : "LE"),
                     "High",
                     lo,
                     hi - lo);
            i = hi - 1u;
        }
    }

    std::optional<std::size_t> last_tea_off{};

    // Main linear constant & table scan
    std::size_t i = 0u;
    while (i < raw_bytes.size()) {
        const std::uint8_t b0 = raw_bytes[i];
        const std::size_t rem = raw_bytes.size() - i;

        // 1. AES S-Box (256 bytes)
        if (b0 == 0x63u && rem >= 256u && raw_bytes[i + 1u] == 0x7Cu &&
            std::memcmp(raw_bytes.data() + i, kAesSbox.data(), 256u) == 0) {
            emit_hit("CRYPTO_AES_SBOX",
                     "Symmetric Cipher",
                     "AES (Rijndael S-Box)",
                     "FIPS 197 256-byte AES Rijndael forward S-Box",
                     "High",
                     i,
                     256u);
            i += 256u;
            continue;
        }

        // 2. AES Inverse S-Box (256 bytes)
        if (b0 == 0x52u && rem >= 256u && raw_bytes[i + 1u] == 0x09u &&
            std::memcmp(raw_bytes.data() + i, kAesInvSbox.data(), 256u) == 0) {
            emit_hit("CRYPTO_AES_INV_SBOX",
                     "Symmetric Cipher",
                     "AES (Inverse S-Box)",
                     "FIPS 197 256-byte AES Rijndael inverse S-Box",
                     "High",
                     i,
                     256u);
            i += 256u;
            continue;
        }

        // 3. AES Te0 T-Table (LE starts with A5 63 63 C6, BE starts with C6 63 63 A5)
        if (rem >= 64u && (b0 == 0xA5u || b0 == 0xC6u)) {
            const bool be = (b0 == 0xC6u);
            const std::size_t words = match_u32_table_run(raw_bytes, i, kAesTe0, be);
            if (words >= 16u) {
                const std::size_t byte_len = words * 4u;
                emit_hit("CRYPTO_AES_TE0",
                         "Symmetric Cipher",
                         "AES (Te0 T-Table)",
                         std::format("AES Rijndael Te0 lookup T-table ({} entries, {})",
                                     words,
                                     be ? "BE" : "LE"),
                         "High",
                         i,
                         byte_len);
                i += byte_len;
                continue;
            }
        }

        // 4. ChaCha20 / Salsa20 16-byte ASCII constants ("expand 32-byte k" / "expand 16-byte k")
        if (b0 == 'e' && rem >= 16u) {
            if (std::memcmp(raw_bytes.data() + i, kChaChaSigma.data(), 16u) == 0) {
                emit_hit("CRYPTO_CHACHA20_SIGMA",
                         "Symmetric Cipher",
                         "ChaCha20 / Salsa20",
                         "ChaCha20/Salsa20 256-bit key constant (\"expand 32-byte k\")",
                         "High",
                         i,
                         16u);
                i += 16u;
                continue;
            }
            if (std::memcmp(raw_bytes.data() + i, kSalsaTau.data(), 16u) == 0) {
                emit_hit("CRYPTO_SALSA20_TAU",
                         "Symmetric Cipher",
                         "ChaCha20 / Salsa20",
                         "Salsa20/ChaCha20 128-bit key constant (\"expand 16-byte k\")",
                         "High",
                         i,
                         16u);
                i += 16u;
                continue;
            }
        }

        // 5. DES Initial Permutation (64 bytes, 1-based or 0-based) & DES S1 (64 bytes)
        if (rem >= 64u) {
            if (b0 == 58u && raw_bytes[i + 1u] == 50u &&
                std::memcmp(raw_bytes.data() + i, kDesIpOneBased.data(), 64u) == 0) {
                emit_hit("CRYPTO_DES_IP",
                         "Symmetric Cipher",
                         "DES / 3DES",
                         "FIPS 46-3 DES 64-byte Initial Permutation table (1-based)",
                         "High",
                         i,
                         64u);
                i += 64u;
                continue;
            }
            if (b0 == 57u && raw_bytes[i + 1u] == 49u &&
                std::memcmp(raw_bytes.data() + i, kDesIpZeroBased.data(), 64u) == 0) {
                emit_hit("CRYPTO_DES_IP",
                         "Symmetric Cipher",
                         "DES / 3DES",
                         "FIPS 46-3 DES 64-byte Initial Permutation table (0-based)",
                         "High",
                         i,
                         64u);
                i += 64u;
                continue;
            }
            if (b0 == 14u && raw_bytes[i + 1u] == 4u && raw_bytes[i + 2u] == 13u &&
                std::memcmp(raw_bytes.data() + i, kDesS1.data(), 64u) == 0) {
                emit_hit("CRYPTO_DES_S1",
                         "Symmetric Cipher",
                         "DES / 3DES",
                         "FIPS 46-3 DES 64-byte S-Box S1 table",
                         "High",
                         i,
                         64u);
                i += 64u;
                continue;
            }
        }

        // 6. Blowfish P-array prefix (`0x243F6A88, 0x85A308D3...`)
        if (rem >= 8u && (b0 == 0x88u || b0 == 0x24u)) {
            const bool be = (b0 == 0x24u);
            const std::size_t words = match_u32_table_run(raw_bytes, i, kBlowfishP, be);
            if (words >= 2u) {
                const std::size_t byte_len = words * 4u;
                emit_hit("CRYPTO_BLOWFISH_P",
                         "Symmetric Cipher",
                         "Blowfish",
                         std::format("Blowfish P-array subkey initialization constants ({} words, {})",
                                     words,
                                     be ? "BE" : "LE"),
                         words >= 4u ? "High" : "Medium",
                         i,
                         byte_len);
                i += byte_len;
                continue;
            }
        }

        // 7. SHA-512 K (check BEFORE SHA-256 K since SHA-512 K[0] upper 32 bits == SHA-256 K[0] in BE)
        if (rem >= 32u && (b0 == 0x22u || b0 == 0x42u)) {
            const bool be = (b0 == 0x42u);
            const std::size_t words = match_u64_table_run(raw_bytes, i, kSha512K, be);
            if (words >= 4u) {
                const std::size_t byte_len = words * 8u;
                emit_hit("HASH_SHA512_K",
                         "Hash / Checksum",
                         "SHA-512 / SHA-384",
                         std::format("FIPS 180-4 SHA-512 64-bit round constants K ({} words, {})",
                                     words,
                                     be ? "BE" : "LE"),
                         "High",
                         i,
                         byte_len);
                i += byte_len;
                continue;
            }
        }

        // 8. SHA-256 K round constants (`0x428A2F98, 0x71374491, ...`)
        if (rem >= 16u && (b0 == 0x98u || b0 == 0x42u)) {
            const bool be = (b0 == 0x42u);
            const std::size_t words = match_u32_table_run(raw_bytes, i, kSha256K, be);
            if (words >= 4u) {
                const std::size_t byte_len = words * 4u;
                emit_hit("HASH_SHA256_K",
                         "Hash / Checksum",
                         "SHA-256 / SHA-224",
                         std::format("FIPS 180-4 SHA-256 32-bit round constants K ({} words, {})",
                                     words,
                                     be ? "BE" : "LE"),
                         "High",
                         i,
                         byte_len);
                i += byte_len;
                continue;
            }
        }

        // 9. BLAKE2b / SHA-512 IV (`0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, ...`)
        if (rem >= 16u && (b0 == 0x08u || b0 == 0x6Au)) {
            const bool be = (b0 == 0x6Au);
            const std::size_t words = match_u64_table_run(raw_bytes, i, kBlake2bSha512Iv, be);
            if (words >= 2u) {
                const std::size_t byte_len = words * 8u;
                emit_hit("HASH_BLAKE2B_SHA512_IV",
                         "Hash / Checksum",
                         "BLAKE2b / SHA-512",
                         std::format("BLAKE2b / SHA-512 64-bit initialization vector IV ({} words, {})",
                                     words,
                                     be ? "BE" : "LE"),
                         words >= 4u ? "High" : "Medium",
                         i,
                         byte_len);
                i += byte_len;
                continue;
            }
        }

        // 10. MD5 / SHA-1 contiguous IV (`0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476` [+ `0xC3D2E1F0`])
        if (rem >= 16u && (b0 == 0x01u || b0 == 0x67u)) {
            const bool be = (b0 == 0x67u);
            const std::size_t words = match_u32_table_run(raw_bytes, i, kMd5Sha1Iv, be);
            if (words >= 4u) {
                const std::size_t byte_len = words * 4u;
                if (words >= 5u) {
                    emit_hit("HASH_SHA1_IV",
                             "Hash / Checksum",
                             "SHA-1",
                             std::format("SHA-1 160-bit initial chaining state IV ({})",
                                         be ? "BE" : "LE"),
                             "High",
                             i,
                             20u);
                } else {
                    emit_hit("HASH_MD5_SHA1_IV",
                             "Hash / Checksum",
                             "MD5 / SHA-1",
                             std::format("MD5 / SHA-1 128-bit initial chaining state IV ({})",
                                         be ? "BE" : "LE"),
                             "High",
                             i,
                             16u);
                }
                i += byte_len;
                continue;
            }
        }

        // 11. CRC-32 IEEE (`0xEDB88320`) & CRC-32C Castagnoli (`0x82F63B78`) 256-entry tables
        // Both tables begin with 0x00000000 followed by entry[1] (0x77073096 or 0xF26B8303)
        if (b0 == 0x00u && rem >= 64u && read_u32_le(raw_bytes, i) == 0u) {
            const std::uint32_t second_le = read_u32_le(raw_bytes, i + 4u);
            const std::uint32_t second_be = read_u32_be(raw_bytes, i + 4u);
            if (second_le == kCrc32IeeeTable[1] || second_be == kCrc32IeeeTable[1]) {
                const bool be = (second_le != kCrc32IeeeTable[1]);
                const std::size_t words = match_u32_table_run(raw_bytes, i, kCrc32IeeeTable, be);
                if (words >= 16u) {
                    const std::size_t byte_len = words * 4u;
                    emit_hit("CHECKSUM_CRC32_IEEE",
                             "Hash / Checksum",
                             "CRC-32 (IEEE 802.3)",
                             std::format("CRC-32 IEEE 0xEDB88320 lookup table ({} entries, {})",
                                         words,
                                         be ? "BE" : "LE"),
                             "High",
                             i,
                             byte_len);
                    i += byte_len;
                    continue;
                }
            }
            if (second_le == kCrc32CastagnoliTable[1] || second_be == kCrc32CastagnoliTable[1]) {
                const bool be = (second_le != kCrc32CastagnoliTable[1]);
                const std::size_t words =
                    match_u32_table_run(raw_bytes, i, kCrc32CastagnoliTable, be);
                if (words >= 16u) {
                    const std::size_t byte_len = words * 4u;
                    emit_hit("CHECKSUM_CRC32C_CASTAGNOLI",
                             "Hash / Checksum",
                             "CRC-32C (Castagnoli)",
                             std::format("CRC-32C Castagnoli 0x82F63B78 lookup table ({} entries, {})",
                                         words,
                                         be ? "BE" : "LE"),
                             "High",
                             i,
                             byte_len);
                    i += byte_len;
                    continue;
                }
            }
        }

        // 12. TEA / XTEA golden-ratio delta `0x9E3779B9` (LE `B9 79 37 9E` / BE `9E 37 79 B9`)
        if (rem >= 4u && (b0 == 0xB9u || b0 == 0x9Eu)) {
            const std::uint32_t le = read_u32_le(raw_bytes, i);
            const std::uint32_t be = read_u32_be(raw_bytes, i);
            if (le == 0x9E3779B9u || be == 0x9E3779B9u) {
                const bool in_rc5 = std::ranges::any_of(
                    rc5_windows,
                    [i](const auto& w) noexcept { return i >= w.first && i < w.second; });
                const bool near_prev_tea =
                    last_tea_off.has_value() && (i - *last_tea_off) < 64u;
                if (!in_rc5 && !near_prev_tea) {
                    const bool is_be = (le != 0x9E3779B9u);
                    // Check if 32-round TEA sum `0xC6EF3720` appears nearby for High confidence
                    const std::size_t s_lo = (i > 128u) ? (i - 128u) : 0u;
                    const std::size_t s_hi = std::min<std::size_t>(raw_bytes.size(), i + 132u);
                    bool has_tea_sum = false;
                    for (std::size_t k = s_lo; k + 4u <= s_hi; ++k) {
                        const std::uint32_t v =
                            is_be ? read_u32_be(raw_bytes, k) : read_u32_le(raw_bytes, k);
                        if (v == 0xC6EF3720u) {
                            has_tea_sum = true;
                            break;
                        }
                    }
                    last_tea_off = i;
                    emit_hit("CRYPTO_TEA_DELTA",
                             "Symmetric Cipher",
                             "TEA / XTEA",
                             std::format("TEA/XTEA key-schedule delta constant 0x9E3779B9 ({})",
                                         is_be ? "BE" : "LE"),
                             has_tea_sum ? "High" : "Medium",
                             i,
                             4u);
                }
            }
        }

        // 13. zlib / deflate RFC 1951 tables & banner
        if (b0 == 0x03u && rem >= 58u) {
            if (match_u16_le_exact(raw_bytes, i, kDeflateLengthBase)) {
                emit_hit("COMPRESS_ZLIB_DEFLATE",
                         "Compression",
                         "zlib / Deflate",
                         "RFC 1951 Deflate length-code base lookup table (29x16-bit)",
                         "High",
                         i,
                         58u);
                i += 58u;
                continue;
            }
            if (rem >= 116u && match_u16_promoted_u32_le_exact(raw_bytes, i, kDeflateLengthBase)) {
                emit_hit("COMPRESS_ZLIB_DEFLATE",
                         "Compression",
                         "zlib / Deflate",
                         "RFC 1951 Deflate length-code base lookup table (29x32-bit)",
                         "High",
                         i,
                         116u);
                i += 116u;
                continue;
            }
        }
        if (b0 == 0x01u && rem >= 60u) {
            if (match_u16_le_exact(raw_bytes, i, kDeflateDistBase)) {
                emit_hit("COMPRESS_ZLIB_DEFLATE",
                         "Compression",
                         "zlib / Deflate",
                         "RFC 1951 Deflate distance-code base lookup table (30x16-bit)",
                         "High",
                         i,
                         60u);
                i += 60u;
                continue;
            }
        }
        if (b0 == ' ' && rem >= 16u) {
            if (std::memcmp(raw_bytes.data() + i, kZlibInflateSig.data(), kZlibInflateSig.size()) == 0 ||
                std::memcmp(raw_bytes.data() + i, kZlibDeflateSig.data(), kZlibDeflateSig.size()) == 0) {
                emit_hit("COMPRESS_ZLIB_BANNER",
                         "Compression",
                         "zlib / Deflate",
                         "Embedded zlib library version banner",
                         "High",
                         i,
                         15u);
                i += 15u;
                continue;
            }
        }

        // 14. LZMA / XZ / 7z headers
        if (b0 == 0xFDu && rem >= 6u &&
            std::memcmp(raw_bytes.data() + i, kXzMagic.data(), 6u) == 0) {
            emit_hit("COMPRESS_LZMA_XZ",
                     "Compression",
                     "XZ / LZMA2",
                     "XZ stream container magic (\\xFD7zXZ\\x00)",
                     "High",
                     i,
                     6u);
            i += 6u;
            continue;
        }
        if (b0 == '7' && rem >= 6u &&
            std::memcmp(raw_bytes.data() + i, k7zMagic.data(), 6u) == 0) {
            emit_hit("COMPRESS_7Z_LZMA",
                     "Compression",
                     "7-Zip / LZMA",
                     "7z archive signature header",
                     "High",
                     i,
                     6u);
            i += 6u;
            continue;
        }
        if (b0 == 0x5Du && rem >= 13u) {
            const std::uint32_t dict_sz = read_u32_le(raw_bytes, i + 1u);
            const std::uint64_t uncomp_sz = read_u64_le(raw_bytes, i + 5u);
            if (is_power_of_two_u32(dict_sz) && dict_sz >= (1u << 16u) && dict_sz <= (1u << 27u) &&
                uncomp_sz == std::numeric_limits<std::uint64_t>::max()) {
                emit_hit("COMPRESS_LZMA_HEADER",
                         "Compression",
                         "LZMA",
                         std::format("LZMA-alone stream properties header (lc=3,lp=0,pb=2, dict={} KiB)",
                                     dict_sz / 1024u),
                         "High",
                         i,
                         13u);
                i += 13u;
                continue;
            }
        }

        // 15. Zstandard frame magic (`0xFD2FB528` LE = `28 B5 2F FD`)
        if (b0 == 0x28u && rem >= 4u && read_u32_le(raw_bytes, i) == 0xFD2FB528u) {
            emit_hit("COMPRESS_ZSTD_MAGIC",
                     "Compression",
                     "Zstandard (zstd)",
                     "Zstandard compressed frame magic (0xFD2FB528)",
                     "High",
                     i,
                     4u);
            i += 4u;
            continue;
        }

        // 16. UPX! packheader magic (`55 50 58 21`)
        if (b0 == 'U' && rem >= 4u && raw_bytes[i + 1u] == 'P' && raw_bytes[i + 2u] == 'X' &&
            raw_bytes[i + 3u] == '!') {
            if (!last_upx_magic_off.has_value() || (i - *last_upx_magic_off) >= 32u) {
                last_upx_magic_off = i;
                emit_hit("PACKER_UPX_MAGIC",
                         "Packer",
                         "UPX",
                         "UPX! packheader signature marker",
                         "High",
                         i,
                         4u);
            }
            i += 4u;
            continue;
        }

        ++i;
    }
}

void scan_image_sections_for_packers(std::span<const std::uint8_t> raw_bytes,
                                     const IBinaryImage& image,
                                     std::vector<CryptoSignatureHit>& raw_hits) {
    for (const Section& sec : image.sections()) {
        const std::string low = to_lower_ascii(sec.name);
        const std::optional<std::uint64_t> sec_off =
            sec.file_offset < raw_bytes.size() ? std::optional<std::uint64_t>(sec.file_offset)
                                               : std::nullopt;
        const std::optional<std::uint64_t> sec_va =
            sec.virtual_address != 0u ? std::optional<std::uint64_t>(sec.virtual_address)
                                      : image.file_offset_to_virtual_address(sec.file_offset);
        const std::uint64_t sec_len = std::max<std::uint64_t>(sec.file_size, sec.virtual_size);

        auto emit_sec_packer = [&](std::string id, std::string algo, std::string summary) {
            CryptoSignatureHit hit{};
            hit.id = std::move(id);
            hit.category = "Packer";
            hit.algorithm = std::move(algo);
            hit.summary = std::move(summary);
            hit.confidence = "High";
            hit.file_offset = sec_off;
            hit.virtual_address = sec_va;
            hit.byte_length = sec_len;
            hit.section_name = sec.name;
            raw_hits.push_back(std::move(hit));
        };

        if (low == "upx0" || low == "upx1" || low == "upx2" || low == ".upx0" ||
            low == ".upx1" || low == ".upx2") {
            emit_sec_packer("PACKER_UPX_SECTION",
                            "UPX",
                            std::format("UPX packer section '{}'", sec.name));
        } else if (low == ".mpress1" || low == ".mpress2" || low == "mpress1" || low == "mpress2") {
            emit_sec_packer("PACKER_MPRESS_SECTION",
                            "MPRESS",
                            std::format("MPRESS packer section '{}'", sec.name));
        } else if (low == ".aspack" || low == "aspack") {
            emit_sec_packer("PACKER_ASPACK_SECTION",
                            "ASPack",
                            std::format("ASPack packer section '{}'", sec.name));
        } else if (low.starts_with(".vmp0") || low.starts_with(".vmp1") || low.starts_with(".vmp2")) {
            emit_sec_packer("PACKER_VMPROTECT_SECTION",
                            "VMProtect",
                            std::format("VMProtect protected section '{}'", sec.name));
        } else if (low == ".themida" || low == "themida" || low == ".winlice") {
            emit_sec_packer("PACKER_THEMIDA_SECTION",
                            "Themida / WinLicense",
                            std::format("Themida/WinLicense protected section '{}'", sec.name));
        }

        // High-entropy packed executable section heuristic (`executable && entropy >= 7.2 && size >= 4096`)
        if (sec.executable && sec.file_size >= 4096u && sec.file_offset < raw_bytes.size()) {
            const std::size_t avail = static_cast<std::size_t>(
                std::min<std::uint64_t>(sec.file_size, raw_bytes.size() - sec.file_offset));
            if (avail >= 4096u) {
                const auto span =
                    raw_bytes.subspan(static_cast<std::size_t>(sec.file_offset), avail);
                const double ent = compute_shannon_entropy(span);
                if (ent >= 7.2) {
                    CryptoSignatureHit hit{};
                    hit.id = "PACKER_HIGH_ENTROPY_EXEC";
                    hit.category = "Packer";
                    hit.algorithm = "High-Entropy Executable Section";
                    hit.summary = std::format(
                        "Executable section '{}' has Shannon entropy {:.2f} bits/byte (>= 7.20, {} bytes)",
                        sec.name,
                        ent,
                        avail);
                    hit.confidence = ent >= 7.6 ? "High" : "Medium";
                    hit.file_offset = sec.file_offset;
                    hit.virtual_address = sec_va;
                    hit.byte_length = static_cast<std::uint64_t>(avail);
                    hit.section_name = sec.name;
                    raw_hits.push_back(std::move(hit));
                }
            }
        }
    }
}

[[nodiscard]] std::vector<CryptoSignatureHit> deduplicate_crypto_hits(
    std::vector<CryptoSignatureHit> hits) {
    if (hits.size() <= 1u) {
        return hits;
    }

    auto primary_pos = [](const CryptoSignatureHit& h) noexcept -> std::uint64_t {
        return h.file_offset.value_or(
            h.virtual_address.value_or(std::numeric_limits<std::uint64_t>::max()));
    };

    std::ranges::sort(hits, [&](const CryptoSignatureHit& a, const CryptoSignatureHit& b) {
        const std::uint64_t pa = primary_pos(a);
        const std::uint64_t pb = primary_pos(b);
        if (pa != pb) {
            return pa < pb;
        }
        const int ca = confidence_rank(a.confidence);
        const int cb = confidence_rank(b.confidence);
        if (ca != cb) {
            return ca > cb;
        }
        if (a.byte_length != b.byte_length) {
            return a.byte_length > b.byte_length;
        }
        return a.id < b.id;
    });

    std::vector<CryptoSignatureHit> deduped{};
    deduped.reserve(hits.size());

    for (CryptoSignatureHit& cand : hits) {
        const bool cand_env = is_section_envelope_hit(cand.id);
        const std::uint64_t c_start = primary_pos(cand);
        const std::uint64_t c_end =
            (c_start <= std::numeric_limits<std::uint64_t>::max() - cand.byte_length)
                ? (c_start + cand.byte_length)
                : std::numeric_limits<std::uint64_t>::max();

        bool redundant = false;
        for (const CryptoSignatureHit& kept : deduped) {
            const std::uint64_t k_start = primary_pos(kept);
            if (cand.id == kept.id && c_start == k_start &&
                cand.virtual_address == kept.virtual_address) {
                redundant = true;
                break;
            }
            const bool kept_env = is_section_envelope_hit(kept.id);
            if (cand_env != kept_env) {
                continue;
            }
            if (!cand_env && cand.category == kept.category && c_start != std::numeric_limits<std::uint64_t>::max()) {
                const std::uint64_t k_end =
                    (k_start <= std::numeric_limits<std::uint64_t>::max() - kept.byte_length)
                        ? (k_start + kept.byte_length)
                        : std::numeric_limits<std::uint64_t>::max();
                // Drop overlapping sub-table hits within the same category
                if (c_start >= k_start && c_end <= k_end &&
                    (cand.id == kept.id || cand.algorithm == kept.algorithm)) {
                    redundant = true;
                    break;
                }
            }
        }
        if (!redundant) {
            deduped.push_back(std::move(cand));
        }
    }
    return deduped;
}

} // namespace

// ---------------------------------------------------------------------------
// A. PE Rich Header Decoder Implementation
// ---------------------------------------------------------------------------

std::string describe_pe_rich_comp_id(std::uint32_t comp_id_dword) {
    const auto build = static_cast<std::uint16_t>(comp_id_dword & 0xFFFFu);
    const auto prod_id = static_cast<std::uint16_t>((comp_id_dword >> 16u) & 0xFFFFu);

    if (prod_id == 0x0000u) {
        return "Unmarked / Imported Object";
    }
    if (prod_id == 0x0001u) {
        return "Import Table Record (Import0)";
    }

    auto vs_era_from_modern_build = [](std::uint16_t b) noexcept -> std::string_view {
        if (b >= 30000u) {
            return "VS 2022";
        }
        if (b >= 27500u) {
            return "VS 2019";
        }
        if (b >= 25000u) {
            return "VS 2017";
        }
        if (b >= 22000u) {
            return "VS 2015";
        }
        return "MSVC 14+";
    };

    // Modern MSVC unified ProdId block (VS 2015 / 2017 / 2019 / 2022: 0x00FF..0x0116)
    if (prod_id >= 0x00FFu && prod_id <= 0x0116u) {
        const std::string_view vs = vs_era_from_modern_build(build);
        switch (prod_id) {
            case 0x00FFu:
            case 0x010Au:
                return std::format("Resource Converter cvtres ({})", vs);
            case 0x0100u:
            case 0x010Bu:
                return std::format("Export Utility ({})", vs);
            case 0x0101u:
            case 0x010Cu:
                return std::format("Import Library Tool ({})", vs);
            case 0x0102u:
            case 0x010Du:
                return std::format("MSVC Linker ({})", vs);
            case 0x0103u:
            case 0x010Eu:
                return std::format("MASM Assembler ({})", vs);
            case 0x0104u:
            case 0x010Fu:
                return std::format("MSVC C Compiler ({})", vs);
            case 0x0105u:
            case 0x0110u:
                return std::format("MSVC C++ Compiler ({})", vs);
            default:
                return std::format("MSVC LTCG / PGO Toolchain ({})", vs);
        }
    }

    if (prod_id >= 0x00DDu && prod_id <= 0x00FEu) {
        return "MSVC Toolchain (VS 2013)";
    }
    if (prod_id >= 0x00C7u && prod_id <= 0x00DCu) {
        return "MSVC Toolchain (VS 2012)";
    }
    if (prod_id >= 0x009Eu && prod_id <= 0x00C6u) {
        return "MSVC Toolchain (VS 2010)";
    }
    if (prod_id >= 0x0095u && prod_id <= 0x009Du) {
        if (prod_id == 0x0097u) return "MSVC Linker (VS 2008)";
        if (prod_id == 0x0098u) return "MASM Assembler (VS 2008)";
        if (prod_id == 0x009Au) return "MSVC C Compiler (VS 2008)";
        if (prod_id == 0x009Bu) return "MSVC C++ Compiler (VS 2008)";
        return "MSVC Toolchain (VS 2008)";
    }
    if (prod_id >= 0x006Du && prod_id <= 0x0094u) {
        return "MSVC Toolchain (VS 2005)";
    }
    if (prod_id >= 0x005Au && prod_id <= 0x006Cu) {
        return "MSVC Toolchain (VS 2003)";
    }
    if (prod_id >= 0x0002u && prod_id <= 0x0059u) {
        return "Legacy MSVC / MASM / Linker (VC6 - VS 2002)";
    }
    return std::format("Microsoft Toolchain (ProdId 0x{:04X})", prod_id);
}

std::optional<PeRichHeader> parse_pe_rich_header(
    std::span<const std::uint8_t> raw_bytes) noexcept {
    try {
        if (raw_bytes.size() < 0x58u) {
            return std::nullopt;
        }
        if (raw_bytes[0] != static_cast<std::uint8_t>('M') ||
            raw_bytes[1] != static_cast<std::uint8_t>('Z')) {
            return std::nullopt;
        }

        const std::uint32_t e_lfanew = read_u32_le(raw_bytes, 0x3Cu);
        // Require room between sizeof(IMAGE_DOS_HEADER) (0x40) and e_lfanew for at least
        // DanS + 3 pad DWORDs + Rich + key (24 bytes => 0x58).
        if (e_lfanew < 0x58u || e_lfanew > 0x100000u) {
            return std::nullopt;
        }
        const auto pe_off = static_cast<std::size_t>(e_lfanew);
        if (pe_off + 4u <= raw_bytes.size()) {
            if (raw_bytes[pe_off] != static_cast<std::uint8_t>('P') ||
                raw_bytes[pe_off + 1u] != static_cast<std::uint8_t>('E') ||
                raw_bytes[pe_off + 2u] != 0u ||
                raw_bytes[pe_off + 3u] != 0u) {
                return std::nullopt;
            }
        }

        const std::size_t search_end = std::min<std::size_t>(pe_off, raw_bytes.size());
        if (search_end < 0x58u) {
            return std::nullopt;
        }

        constexpr std::uint32_t kRichMagicLe = 0x68636952u; // "Rich"
        constexpr std::uint32_t kDansMagicLe = 0x536E6144u; // "DanS"

        std::optional<std::size_t> rich_off{};
        // Scan backwards from search_end - 8 down to 0x50 (prefer 4-byte aligned offsets first)
        for (int aligned_pass = 0; aligned_pass < 2 && !rich_off.has_value(); ++aligned_pass) {
            for (std::size_t pos = search_end - 8u; pos >= 0x50u; --pos) {
                if (aligned_pass == 0 && (pos & 3u) != 0u) {
                    if (pos == 0x50u) break;
                    continue;
                }
                if (read_u32_le(raw_bytes, pos) == kRichMagicLe) {
                    rich_off = pos;
                    break;
                }
                if (pos == 0x50u) {
                    break;
                }
            }
        }

        if (!rich_off.has_value() || *rich_off < 0x50u) {
            return std::nullopt;
        }

        const std::uint32_t stored_xor_key = read_u32_le(raw_bytes, *rich_off + 4u);

        std::optional<std::size_t> dans_off{};
        std::uint32_t unmask_key = stored_xor_key;
        bool mask_mismatch = false;

        // Pass 1: locate exact `DanS ^ stored_xor_key` backwards on 8-byte record boundaries
        for (std::size_t pos = *rich_off - 16u; pos >= 0x40u;) {
            if (((*rich_off - (pos + 16u)) % 8u) == 0u &&
                read_u32_le(raw_bytes, pos) == (kDansMagicLe ^ stored_xor_key)) {
                dans_off = pos;
                break;
            }
            if (pos < 0x44u) {
                break;
            }
            pos -= 4u;
        }

        // Pass 2: if trailing xor_key was tampered in-place, recover DanS via the 3 zero-pad DWORDs
        // (`d1 == d2 == d3 == body_key` and `(d0 ^ d1) == 'DanS'`).
        if (!dans_off.has_value()) {
            for (std::size_t pos = *rich_off - 16u; pos >= 0x40u;) {
                if (((*rich_off - (pos + 16u)) % 8u) == 0u) {
                    const std::uint32_t d0 = read_u32_le(raw_bytes, pos);
                    const std::uint32_t d1 = read_u32_le(raw_bytes, pos + 4u);
                    const std::uint32_t d2 = read_u32_le(raw_bytes, pos + 8u);
                    const std::uint32_t d3 = read_u32_le(raw_bytes, pos + 12u);
                    if (d1 == d2 && d2 == d3 && (d0 ^ d1) == kDansMagicLe) {
                        dans_off = pos;
                        unmask_key = d1;
                        mask_mismatch = true;
                        break;
                    }
                }
                if (pos < 0x44u) {
                    break;
                }
                pos -= 4u;
            }
        }

        if (!dans_off.has_value()) {
            return std::nullopt;
        }

        PeRichHeader header{};
        header.dans_offset = static_cast<std::uint64_t>(*dans_off);
        header.rich_offset = static_cast<std::uint64_t>(*rich_off);
        header.byte_length = static_cast<std::uint64_t>((*rich_off + 8u) - *dans_off);
        header.xor_key = stored_xor_key;

        const std::uint32_t pad0 = read_u32_le(raw_bytes, *dans_off + 4u) ^ unmask_key;
        const std::uint32_t pad1 = read_u32_le(raw_bytes, *dans_off + 8u) ^ unmask_key;
        const std::uint32_t pad2 = read_u32_le(raw_bytes, *dans_off + 12u) ^ unmask_key;
        header.padding_valid = (pad0 == 0u && pad1 == 0u && pad2 == 0u);

        const std::size_t entry_bytes = *rich_off - (*dans_off + 16u);
        header.entries.reserve(entry_bytes / 8u);
        for (std::size_t off = *dans_off + 16u; off + 8u <= *rich_off; off += 8u) {
            const std::uint32_t comp_id = read_u32_le(raw_bytes, off) ^ unmask_key;
            const std::uint32_t count = read_u32_le(raw_bytes, off + 4u) ^ unmask_key;
            PeRichCompIdEntry rec{};
            rec.build_number = static_cast<std::uint16_t>(comp_id & 0xFFFFu);
            rec.prod_id = static_cast<std::uint16_t>((comp_id >> 16u) & 0xFFFFu);
            rec.use_count = count;
            rec.tool_category = describe_pe_rich_comp_id(comp_id);
            rec.file_offset = static_cast<std::uint64_t>(off);
            header.entries.push_back(std::move(rec));
        }

        // Standard Microsoft Rich rotated-left checksum:
        //   dans_offset + sum_{i < dans_offset, i not in [0x3C,0x40)} rotl32(dos[i], i & 31)
        //               + sum_{entry} rotl32(comp_id, use_count & 31)
        std::uint32_t checksum = static_cast<std::uint32_t>(*dans_off);
        for (std::size_t i = 0u; i < *dans_off; ++i) {
            if (i >= 0x3Cu && i < 0x40u) {
                continue; // e_lfanew zeroed
            }
            checksum += std::rotl<std::uint32_t>(
                static_cast<std::uint32_t>(raw_bytes[i]),
                static_cast<int>(i & 31u));
        }
        for (const PeRichCompIdEntry& entry : header.entries) {
            checksum += std::rotl<std::uint32_t>(
                entry.comp_id_dword(),
                static_cast<int>(entry.use_count & 31u));
        }

        header.computed_checksum = checksum;
        header.checksum_valid =
            (checksum == header.xor_key) && header.padding_valid && !mask_mismatch;
        if (!header.checksum_valid) {
            if (mask_mismatch) {
                header.diagnostic = std::format(
                    "Tampered Rich XOR key (stored 0x{:08X}, body masked with 0x{:08X}, expected checksum 0x{:08X})",
                    header.xor_key,
                    unmask_key,
                    header.computed_checksum);
            } else if (!header.padding_valid) {
                header.diagnostic = "Non-zero Rich DanS header padding DWORDs";
            } else {
                header.diagnostic = std::format(
                    "Rich header checksum mismatch (stored 0x{:08X}, computed 0x{:08X})",
                    header.xor_key,
                    header.computed_checksum);
            }
        }
        return header;
    } catch (...) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// B. Shannon Entropy & Crypto / Packer Constant Detector Implementation
// ---------------------------------------------------------------------------

double compute_shannon_entropy(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return 0.0;
    }
    std::array<std::uint64_t, 256> counts{};
    for (const std::uint8_t b : bytes) {
        ++counts[b];
    }
    const double inv_total = 1.0 / static_cast<double>(bytes.size());
    double entropy = 0.0;
    for (const std::uint64_t c : counts) {
        if (c == 0u) {
            continue;
        }
        const double p = static_cast<double>(c) * inv_total;
        entropy -= p * std::log2(p);
    }
    return std::clamp(entropy, 0.0, 8.0);
}

std::vector<CryptoSignatureHit> scan_crypto_and_packer_constants(
    std::span<const std::uint8_t> raw_bytes,
    const IBinaryImage* image) {
    std::vector<CryptoSignatureHit> hits{};
    ScanAddressContext ctx{};
    ctx.image = image;
    ctx.has_file_offsets = true;
    ctx.fallback_region_name = "<raw>";

    scan_buffer_crypto_and_packers(raw_bytes, ctx, hits);
    if (image != nullptr) {
        scan_image_sections_for_packers(raw_bytes, *image, hits);
    }
    return deduplicate_crypto_hits(std::move(hits));
}

std::vector<CryptoSignatureHit> scan_crypto_and_packer_constants(
    IProcessSession& session,
    std::size_t max_bytes_per_region) {
    std::vector<CryptoSignatureHit> hits{};
    const auto regions_res = session.memory_regions();
    if (!regions_res.has_value() || max_bytes_per_region == 0u) {
        return hits;
    }

    constexpr std::size_t kChunkBytes = 256u * 1024u;
    constexpr std::size_t kOverlapBytes = 4096u;
    std::vector<std::uint8_t> chunk_buf(kChunkBytes, 0u);

    for (const MemoryRegion& reg : *regions_res) {
        if (!reg.protection.readable || reg.usage.is_reserved_only || reg.size() == 0u) {
            continue;
        }
        const std::uint64_t total_to_read =
            std::min<std::uint64_t>(reg.size(), static_cast<std::uint64_t>(max_bytes_per_region));
        const std::string reg_label = !reg.module_name.empty()
                                          ? reg.module_name
                                          : (!reg.pathname.empty() ? reg.pathname
                                                                   : std::string(to_string(reg.kind)));

        std::uint64_t cursor = 0u;
        bool checked_exec_entropy = false;
        while (cursor < total_to_read) {
            const auto req = static_cast<std::size_t>(
                std::min<std::uint64_t>(kChunkBytes, total_to_read - cursor));
            const auto rd = session.read_memory(
                reg.start_address + cursor,
                std::span<std::uint8_t>(chunk_buf.data(), req));
            if (!rd.has_value() || *rd == 0u) {
                break;
            }
            const auto valid_span = std::span<const std::uint8_t>(chunk_buf.data(), *rd);

            ScanAddressContext ctx{};
            ctx.image = nullptr;
            ctx.fixed_base_va = reg.start_address + cursor;
            ctx.fallback_region_name = reg_label;
            ctx.has_file_offsets = false;
            scan_buffer_crypto_and_packers(valid_span, ctx, hits);

            if (!checked_exec_entropy && reg.protection.executable && valid_span.size() >= 4096u) {
                checked_exec_entropy = true;
                const double ent = compute_shannon_entropy(valid_span);
                if (ent >= 7.2) {
                    CryptoSignatureHit h{};
                    h.id = "PACKER_HIGH_ENTROPY_EXEC";
                    h.category = "Packer";
                    h.algorithm = "High-Entropy Executable Region";
                    h.summary = std::format(
                        "Executable region '{}' at 0x{:X} has Shannon entropy {:.2f} bits/byte (>= 7.20)",
                        reg_label,
                        reg.start_address,
                        ent);
                    h.confidence = ent >= 7.6 ? "High" : "Medium";
                    h.file_offset = std::nullopt;
                    h.virtual_address = reg.start_address;
                    h.byte_length = static_cast<std::uint64_t>(valid_span.size());
                    h.section_name = reg_label;
                    hits.push_back(std::move(h));
                }
            }

            if (*rd < req || cursor + *rd >= total_to_read) {
                break;
            }
            const std::size_t advance = (*rd > kOverlapBytes) ? (*rd - kOverlapBytes) : *rd;
            cursor += static_cast<std::uint64_t>(advance);
        }
    }

    return deduplicate_crypto_hits(std::move(hits));
}

// ---------------------------------------------------------------------------
// C. Clean-Room YARA-Lite Lexer, Parser, Compiler & Evaluator
// ---------------------------------------------------------------------------

namespace detail {

struct HexMaskedByte {
    std::uint8_t value{0};
    std::uint8_t mask{0xFFu}; // 0xFF exact, 0xF0 high nibble, 0x0F low nibble, 0x00 wildcard ??
};

struct HexJump {
    std::size_t min_skip{0};
    std::size_t max_skip{0};
};

// A hex pattern is represented as `segments[0]`, then `(jumps[k-1], segments[k])` for k >= 1.
struct CompiledHexPattern {
    std::vector<std::vector<HexMaskedByte>> segments{};
    std::vector<HexJump> jumps{};
};

enum class PatternKind : std::uint8_t {
    Text = 0,
    Hex = 1,
};

struct CompiledStringPattern {
    std::string identifier{}; // includes leading '$', e.g. "$a"
    PatternKind kind{PatternKind::Text};
    std::vector<std::uint8_t> raw_text{};
    bool ascii{true};
    bool wide{false};
    bool nocase{false};
    CompiledHexPattern hex{};
};

enum class ExprKind : std::uint8_t {
    BoolLiteral = 0,
    IntLiteral,
    FloatLiteral,
    Filesize,
    Entrypoint,
    StringMatched,     // $id
    StringCount,       // #id
    StringFirstOffset, // @id
    StringAtOffset,    // $id at <expr>
    QuantifiedOf,      // any/all/<K> of them / ($prefix*)
    ReadIntFunc,       // uint8/16/32/16be/32be(off)
    EntropyFunc,       // entropy(off, len)
    UnaryNot,
    UnaryNeg,
    UnaryBitNot,
    BinaryOp,
};

enum class BinaryOpKind : std::uint8_t {
    LogicalOr = 0,
    LogicalAnd,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    BitOr,
    BitXor,
    BitAnd,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
};

enum class ReadIntWidth : std::uint8_t {
    U8 = 0,
    U16Le,
    U32Le,
    U16Be,
    U32Be,
};

enum class QuantifierKind : std::uint8_t {
    Any = 0,
    All,
    None,
    ExactCount,
};

struct ExprNode {
    ExprKind kind{ExprKind::BoolLiteral};
    bool bool_val{false};
    std::uint64_t int_val{0};
    double float_val{0.0};
    std::size_t pattern_index{0};
    QuantifierKind quantifier{QuantifierKind::Any};
    std::uint64_t quantifier_count{0};
    std::vector<std::size_t> target_pattern_indices{};
    ReadIntWidth read_width{ReadIntWidth::U8};
    BinaryOpKind bin_op{BinaryOpKind::LogicalAnd};
    std::unique_ptr<ExprNode> lhs{};
    std::unique_ptr<ExprNode> rhs{};
};

struct CompiledSignatureRuleBody {
    std::vector<CompiledStringPattern> patterns{};
    std::unique_ptr<ExprNode> condition{};
    bool uses_offset_builtins{false};
};

} // namespace detail

void SignatureRuleSet::append(const SignatureRuleSet& other) {
    rules.insert(rules.end(), other.rules.begin(), other.rules.end());
}

namespace {

enum class TokenKind : std::uint8_t {
    EndOfFile = 0,
    Identifier,
    StringId,      // $foo or $
    StringCountId, // #foo
    StringOffId,   // @foo
    StringStarId,  // $foo* or $*
    StringLiteral,
    IntLiteral,
    FloatLiteral,
    HexBlock, // raw text inside `{ ... }`
    Colon,
    Comma,
    Equals,
    EqEq,
    BangEq,
    Less,
    LessEq,
    Greater,
    GreaterEq,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    LParen,
    RParen,
    LBrace,
    RBrace,
};

struct SourceLoc {
    std::uint32_t line{1};
    std::uint32_t column{1};
};

struct Token {
    TokenKind kind{TokenKind::EndOfFile};
    SourceLoc loc{};
    std::string text{};
    std::uint64_t int_val{0};
    double float_val{0.0};
};

class RuleLexer {
public:
    RuleLexer(std::string_view src,
              std::string_view src_name,
              std::vector<SignatureRuleDiagnostic>& diags) noexcept
        : src_(src), src_name_(src_name), diags_(diags) {}

    [[nodiscard]] std::vector<Token> tokenize() {
        std::vector<Token> tokens{};
        bool expect_hex_block = false;
        TokenKind prev_kind = TokenKind::EndOfFile;

        while (!eof()) {
            skip_whitespace_and_comments();
            if (eof()) {
                break;
            }

            const SourceLoc start_loc{line_, col_};
            const char ch = peek();

            // Inside `strings: $h = { ... }`, lex `{ ... }` as a dedicated HexBlock token
            // so hex pairs like `4E` or `E8` are not confused with float exponents or identifiers.
            if (ch == '{' && expect_hex_block) {
                expect_hex_block = false;
                advance(); // consume '{'
                Token tok{};
                tok.kind = TokenKind::HexBlock;
                tok.loc = start_loc;
                const std::size_t content_start = pos_;
                bool closed = false;
                while (!eof()) {
                    if (peek() == '/' && peek_next() == '/') {
                        while (!eof() && peek() != '\n') {
                            advance();
                        }
                        continue;
                    }
                    if (peek() == '/' && peek_next() == '*') {
                        const SourceLoc cmt_loc{line_, col_};
                        advance();
                        advance();
                        bool cmt_closed = false;
                        while (!eof()) {
                            if (peek() == '*' && peek_next() == '/') {
                                advance();
                                advance();
                                cmt_closed = true;
                                break;
                            }
                            advance();
                        }
                        if (!cmt_closed) {
                            report_error(cmt_loc, "Unterminated block comment inside hex pattern");
                            return tokens;
                        }
                        continue;
                    }
                    if (peek() == '}') {
                        tok.text.assign(src_.substr(content_start, pos_ - content_start));
                        advance();
                        closed = true;
                        break;
                    }
                    advance();
                }
                if (!closed) {
                    report_error(start_loc, "Unterminated hex pattern '{ ... }'");
                    return tokens;
                }
                prev_kind = tok.kind;
                tokens.push_back(std::move(tok));
                continue;
            }

            expect_hex_block = false;

            if (ch == '"') {
                Token str_tok = lex_string_literal(start_loc);
                prev_kind = str_tok.kind;
                tokens.push_back(std::move(str_tok));
                continue;
            }

            if (ch == '$' || ch == '#' || ch == '@') {
                advance();
                std::string ident{};
                ident.push_back(ch);
                while (!eof() && is_ascii_alnum_or_underscore(peek())) {
                    ident.push_back(advance());
                }
                Token tok{};
                tok.loc = start_loc;
                if (ch == '$' && !eof() && peek() == '*') {
                    ident.push_back(advance());
                    tok.kind = TokenKind::StringStarId;
                } else if (ch == '$') {
                    tok.kind = TokenKind::StringId;
                } else if (ch == '#') {
                    if (ident.size() == 1u) {
                        report_error(start_loc, "Expected string identifier after '#'");
                    }
                    tok.kind = TokenKind::StringCountId;
                } else {
                    if (ident.size() == 1u) {
                        report_error(start_loc, "Expected string identifier after '@'");
                    }
                    tok.kind = TokenKind::StringOffId;
                }
                tok.text = std::move(ident);
                prev_kind = tok.kind;
                tokens.push_back(std::move(tok));
                continue;
            }

            if (is_ascii_digit(ch)) {
                Token num_tok = lex_number(start_loc);
                prev_kind = num_tok.kind;
                tokens.push_back(std::move(num_tok));
                continue;
            }

            if (is_ascii_alpha(ch) || ch == '_') {
                std::string ident{};
                while (!eof() && is_ascii_alnum_or_underscore(peek())) {
                    ident.push_back(advance());
                }
                Token tok{};
                tok.kind = TokenKind::Identifier;
                tok.loc = start_loc;
                tok.text = std::move(ident);
                prev_kind = tok.kind;
                tokens.push_back(std::move(tok));
                continue;
            }

            // Punctuation & operators
            advance();
            Token tok{};
            tok.loc = start_loc;
            switch (ch) {
                case ':': tok.kind = TokenKind::Colon; tok.text = ":"; break;
                case ',': tok.kind = TokenKind::Comma; tok.text = ","; break;
                case '+': tok.kind = TokenKind::Plus; tok.text = "+"; break;
                case '-': tok.kind = TokenKind::Minus; tok.text = "-"; break;
                case '*': tok.kind = TokenKind::Star; tok.text = "*"; break;
                case '/': tok.kind = TokenKind::Slash; tok.text = "/"; break;
                case '%': tok.kind = TokenKind::Percent; tok.text = "%"; break;
                case '&': tok.kind = TokenKind::Amp; tok.text = "&"; break;
                case '|': tok.kind = TokenKind::Pipe; tok.text = "|"; break;
                case '^': tok.kind = TokenKind::Caret; tok.text = "^"; break;
                case '~': tok.kind = TokenKind::Tilde; tok.text = "~"; break;
                case '(': tok.kind = TokenKind::LParen; tok.text = "("; break;
                case ')': tok.kind = TokenKind::RParen; tok.text = ")"; break;
                case '{': tok.kind = TokenKind::LBrace; tok.text = "{"; break;
                case '}': tok.kind = TokenKind::RBrace; tok.text = "}"; break;
                case '=':
                    if (!eof() && peek() == '=') {
                        advance();
                        tok.kind = TokenKind::EqEq;
                        tok.text = "==";
                    } else {
                        tok.kind = TokenKind::Equals;
                        tok.text = "=";
                        if (prev_kind == TokenKind::StringId) {
                            expect_hex_block = true;
                        }
                    }
                    break;
                case '!':
                    if (!eof() && peek() == '=') {
                        advance();
                        tok.kind = TokenKind::BangEq;
                        tok.text = "!=";
                    } else {
                        report_error(start_loc, "Unexpected '!' (use 'not' for boolean negation or '!=' for inequality)");
                        continue;
                    }
                    break;
                case '<':
                    if (!eof() && peek() == '=') {
                        advance();
                        tok.kind = TokenKind::LessEq;
                        tok.text = "<=";
                    } else {
                        tok.kind = TokenKind::Less;
                        tok.text = "<";
                    }
                    break;
                case '>':
                    if (!eof() && peek() == '=') {
                        advance();
                        tok.kind = TokenKind::GreaterEq;
                        tok.text = ">=";
                    } else {
                        tok.kind = TokenKind::Greater;
                        tok.text = ">";
                    }
                    break;
                default:
                    report_error(start_loc, std::format("Unexpected character '{}'", ch));
                    continue;
            }
            prev_kind = tok.kind;
            tokens.push_back(std::move(tok));
        }

        Token eof_tok{};
        eof_tok.kind = TokenKind::EndOfFile;
        eof_tok.loc = SourceLoc{line_, col_};
        tokens.push_back(std::move(eof_tok));
        return tokens;
    }

private:
    [[nodiscard]] bool eof() const noexcept { return pos_ >= src_.size(); }
    [[nodiscard]] char peek() const noexcept { return eof() ? '\0' : src_[pos_]; }
    [[nodiscard]] char peek_next() const noexcept {
        return (pos_ + 1u < src_.size()) ? src_[pos_ + 1u] : '\0';
    }

    char advance() noexcept {
        const char ch = src_[pos_++];
        if (ch == '\n') {
            ++line_;
            col_ = 1u;
        } else {
            ++col_;
        }
        return ch;
    }

    void report_error(SourceLoc loc, std::string msg) {
        diags_.push_back(SignatureRuleDiagnostic{
            .source_name = std::string(src_name_),
            .line = loc.line,
            .column = loc.column,
            .message = std::move(msg),
        });
    }

    void skip_whitespace_and_comments() {
        while (!eof()) {
            const char ch = peek();
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                advance();
                continue;
            }
            if (ch == '/' && peek_next() == '/') {
                while (!eof() && peek() != '\n') {
                    advance();
                }
                continue;
            }
            if (ch == '/' && peek_next() == '*') {
                const SourceLoc start_loc{line_, col_};
                advance();
                advance();
                bool closed = false;
                while (!eof()) {
                    if (peek() == '*' && peek_next() == '/') {
                        advance();
                        advance();
                        closed = true;
                        break;
                    }
                    advance();
                }
                if (!closed) {
                    report_error(start_loc, "Unterminated '/* ... */' block comment");
                }
                continue;
            }
            break;
        }
    }

    [[nodiscard]] Token lex_string_literal(SourceLoc start_loc) {
        advance(); // consume opening '"'
        Token tok{};
        tok.kind = TokenKind::StringLiteral;
        tok.loc = start_loc;
        std::string decoded{};
        bool closed = false;
        while (!eof()) {
            const char ch = peek();
            if (ch == '\n' || ch == '\r') {
                break;
            }
            advance();
            if (ch == '"') {
                closed = true;
                break;
            }
            if (ch == '\\') {
                if (eof()) {
                    break;
                }
                const SourceLoc esc_loc{line_, col_};
                const char esc = advance();
                switch (esc) {
                    case '"':  decoded.push_back('"'); break;
                    case '\\': decoded.push_back('\\'); break;
                    case 'n':  decoded.push_back('\n'); break;
                    case 'r':  decoded.push_back('\r'); break;
                    case 't':  decoded.push_back('\t'); break;
                    case '0':  decoded.push_back('\0'); break;
                    case 'x': {
                        if (pos_ + 2u > src_.size()) {
                            report_error(esc_loc, "Incomplete \\xHH hex escape in string literal");
                            break;
                        }
                        const int hi = parse_hex_nibble(advance());
                        const int lo = parse_hex_nibble(advance());
                        if (hi < 0 || lo < 0) {
                            report_error(esc_loc, "Invalid hex digit in \\xHH escape");
                        } else {
                            decoded.push_back(static_cast<char>((hi << 4) | lo));
                        }
                        break;
                    }
                    default:
                        report_error(esc_loc, std::format("Unsupported escape sequence '\\{}'", esc));
                        decoded.push_back(esc);
                        break;
                }
            } else {
                decoded.push_back(ch);
            }
        }
        if (!closed) {
            report_error(start_loc, "Unterminated string literal");
        }
        tok.text = std::move(decoded);
        return tok;
    }

    [[nodiscard]] Token lex_number(SourceLoc start_loc) {
        Token tok{};
        tok.loc = start_loc;
        const std::size_t begin = pos_;

        if (peek() == '0' && (peek_next() == 'x' || peek_next() == 'X')) {
            advance();
            advance();
            const std::size_t hex_start = pos_;
            while (!eof() && parse_hex_nibble(peek()) >= 0) {
                advance();
            }
            const std::string_view digits = src_.substr(hex_start, pos_ - hex_start);
            if (digits.empty()) {
                report_error(start_loc, "Expected hexadecimal digits after '0x'");
                tok.kind = TokenKind::IntLiteral;
                return tok;
            }
            std::uint64_t val = 0u;
            const auto [ptr, ec] =
                std::from_chars(digits.data(), digits.data() + digits.size(), val, 16);
            if (ec != std::errc{} || ptr != digits.data() + digits.size()) {
                report_error(start_loc, "Hexadecimal integer literal out of 64-bit range");
            }
            tok.kind = TokenKind::IntLiteral;
            tok.int_val = val;
            tok.text = std::string(src_.substr(begin, pos_ - begin));
            return tok;
        }

        while (!eof() && is_ascii_digit(peek())) {
            advance();
        }

        if (!eof() && peek() == '.' && is_ascii_digit(peek_next())) {
            advance(); // '.'
            while (!eof() && is_ascii_digit(peek())) {
                advance();
            }
            const std::string num_str(src_.substr(begin, pos_ - begin));
            char* end_ptr = nullptr;
            const double fval = std::strtod(num_str.c_str(), &end_ptr);
            tok.kind = TokenKind::FloatLiteral;
            tok.float_val = fval;
            tok.text = num_str;
            return tok;
        }

        const std::string_view dec_digits = src_.substr(begin, pos_ - begin);
        std::uint64_t val = 0u;
        const auto [ptr, ec] =
            std::from_chars(dec_digits.data(), dec_digits.data() + dec_digits.size(), val, 10);
        if (ec != std::errc{} || ptr != dec_digits.data() + dec_digits.size()) {
            report_error(start_loc, "Decimal integer literal out of 64-bit range");
        }

        // Optional YARA `KB` / `MB` unit multiplier suffix
        if (pos_ + 2u <= src_.size()) {
            const std::string_view suf = src_.substr(pos_, 2u);
            if ((suf == "KB" || suf == "MB") &&
                (pos_ + 2u == src_.size() || !is_ascii_alnum_or_underscore(src_[pos_ + 2u]))) {
                const std::uint64_t mult = (suf == "KB") ? 1024ULL : (1024ULL * 1024ULL);
                advance();
                advance();
                if (val > std::numeric_limits<std::uint64_t>::max() / mult) {
                    report_error(start_loc, "Integer literal with KB/MB suffix overflows 64 bits");
                } else {
                    val *= mult;
                }
            }
        }

        tok.kind = TokenKind::IntLiteral;
        tok.int_val = val;
        tok.text = std::string(src_.substr(begin, pos_ - begin));
        return tok;
    }

    std::string_view src_{};
    std::string_view src_name_{};
    std::vector<SignatureRuleDiagnostic>& diags_;
    std::size_t pos_{0};
    std::uint32_t line_{1};
    std::uint32_t col_{1};
};

// Parses the interior of `$h = { 48 8B ?? [2-6] E8 ?4 }` with exact line:column tracking.
[[nodiscard]] std::optional<detail::CompiledHexPattern> parse_hex_block_content(
    const Token& hex_tok,
    std::string_view source_name,
    std::vector<SignatureRuleDiagnostic>& diags) {
    detail::CompiledHexPattern out{};
    out.segments.emplace_back();

    const std::string_view raw = hex_tok.text;
    std::size_t pos = 0u;
    std::uint32_t line = hex_tok.loc.line;
    std::uint32_t col = hex_tok.loc.column + 1u; // right after '{'

    auto adv = [&]() noexcept -> char {
        const char ch = raw[pos++];
        if (ch == '\n') {
            ++line;
            col = 1u;
        } else {
            ++col;
        }
        return ch;
    };

    auto err = [&](SourceLoc loc, std::string msg) {
        diags.push_back(SignatureRuleDiagnostic{
            .source_name = std::string(source_name),
            .line = loc.line,
            .column = loc.column,
            .message = std::move(msg),
        });
    };

    while (pos < raw.size()) {
        const char ch = raw[pos];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            (void)adv();
            continue;
        }
        if (ch == '/' && pos + 1u < raw.size() && raw[pos + 1u] == '/') {
            while (pos < raw.size() && raw[pos] != '\n') {
                (void)adv();
            }
            continue;
        }
        if (ch == '/' && pos + 1u < raw.size() && raw[pos + 1u] == '*') {
            (void)adv();
            (void)adv();
            while (pos + 1u < raw.size()) {
                if (raw[pos] == '*' && raw[pos + 1u] == '/') {
                    (void)adv();
                    (void)adv();
                    break;
                }
                (void)adv();
            }
            continue;
        }

        const SourceLoc item_loc{line, col};
        if (ch == '[') {
            (void)adv(); // '['
            if (out.segments.back().empty()) {
                err(item_loc, "Hex byte jump '[...]' cannot appear at the start of a hex pattern or immediately after another jump");
                return std::nullopt;
            }
            auto skip_ws = [&]() noexcept {
                while (pos < raw.size() && (raw[pos] == ' ' || raw[pos] == '\t')) {
                    (void)adv();
                }
            };
            skip_ws();
            const std::size_t n_start = pos;
            while (pos < raw.size() && is_ascii_digit(raw[pos])) {
                (void)adv();
            }
            const std::string_view n_str = raw.substr(n_start, pos - n_start);
            if (n_str.empty()) {
                err(item_loc, "Expected non-negative lower bound inside hex jump '[N]' or '[N-M]'");
                return std::nullopt;
            }
            std::size_t min_j = 0u;
            const auto [p1, ec1] =
                std::from_chars(n_str.data(), n_str.data() + n_str.size(), min_j, 10);
            if (ec1 != std::errc{} || p1 != n_str.data() + n_str.size()) {
                err(item_loc, "Invalid jump lower bound in hex pattern");
                return std::nullopt;
            }

            std::size_t max_j = min_j;
            skip_ws();
            if (pos < raw.size() && raw[pos] == '-') {
                (void)adv(); // '-'
                skip_ws();
                const std::size_t m_start = pos;
                while (pos < raw.size() && is_ascii_digit(raw[pos])) {
                    (void)adv();
                }
                const std::string_view m_str = raw.substr(m_start, pos - m_start);
                if (m_str.empty()) {
                    err(item_loc, std::format(
                        "Unbounded hex jump is not allowed; specify an upper bound <= {}",
                        kMaxSignatureHexJumpSpan));
                    return std::nullopt;
                }
                const auto [p2, ec2] =
                    std::from_chars(m_str.data(), m_str.data() + m_str.size(), max_j, 10);
                if (ec2 != std::errc{} || p2 != m_str.data() + m_str.size()) {
                    err(item_loc, "Invalid jump upper bound in hex pattern");
                    return std::nullopt;
                }
            }
            skip_ws();
            if (pos >= raw.size() || raw[pos] != ']') {
                err(item_loc, "Expected closing ']' in hex jump specification");
                return std::nullopt;
            }
            (void)adv(); // ']'

            if (max_j < min_j) {
                err(item_loc, std::format("Hex jump upper bound ({}) must be >= lower bound ({})",
                                          max_j,
                                          min_j));
                return std::nullopt;
            }
            if (min_j > kMaxSignatureHexJumpSpan || max_j > kMaxSignatureHexJumpSpan) {
                err(item_loc, std::format(
                    "Hex jump bound [{}-{}] exceeds maximum allowed span ({} bytes)",
                    min_j,
                    max_j,
                    kMaxSignatureHexJumpSpan));
                return std::nullopt;
            }

            out.jumps.push_back(detail::HexJump{.min_skip = min_j, .max_skip = max_j});
            out.segments.emplace_back();
            continue;
        }

        // Expect a pair of hex/wildcard nibbles: `[0-9A-Fa-f?]{2}`
        if (pos + 2u > raw.size()) {
            err(item_loc, "Odd number of hex nibbles in hex pattern");
            return std::nullopt;
        }
        const char c_hi = adv();
        const char c_lo = adv();
        detail::HexMaskedByte mb{};
        mb.value = 0u;
        mb.mask = 0u;

        if (c_hi != '?') {
            const int hi = parse_hex_nibble(c_hi);
            if (hi < 0) {
                err(item_loc, std::format("Invalid hex nibble '{}' in hex pattern", c_hi));
                return std::nullopt;
            }
            mb.value |= static_cast<std::uint8_t>(hi << 4);
            mb.mask |= 0xF0u;
        }
        if (c_lo != '?') {
            const int lo = parse_hex_nibble(c_lo);
            if (lo < 0) {
                err(item_loc, std::format("Invalid hex nibble '{}' in hex pattern", c_lo));
                return std::nullopt;
            }
            mb.value |= static_cast<std::uint8_t>(lo);
            mb.mask |= 0x0Fu;
        }
        out.segments.back().push_back(mb);
    }

    if (out.segments.front().empty()) {
        err(hex_tok.loc, "Hex pattern '{ ... }' must contain at least one byte");
        return std::nullopt;
    }
    if (out.segments.back().empty()) {
        err(hex_tok.loc, "Hex pattern cannot end with a trailing '[...]' jump");
        return std::nullopt;
    }
    return out;
}

class RuleParser {
public:
    RuleParser(std::vector<Token> tokens,
               std::string_view src_name,
               std::vector<SignatureRuleDiagnostic>& diags) noexcept
        : tokens_(std::move(tokens)), src_name_(src_name), diags_(diags) {}

    [[nodiscard]] SignatureRuleSet parse_all() {
        SignatureRuleSet set{};
        while (!at_eof()) {
            if (auto rule = parse_rule()) {
                set.rules.push_back(std::move(*rule));
            } else {
                synchronize_to_next_rule();
            }
        }
        return set;
    }

private:
    [[nodiscard]] const Token& cur() const noexcept { return tokens_[idx_]; }
    [[nodiscard]] bool at_eof() const noexcept { return cur().kind == TokenKind::EndOfFile; }

    const Token& consume() noexcept {
        const Token& t = tokens_[idx_];
        if (idx_ + 1u < tokens_.size()) {
            ++idx_;
        }
        return t;
    }

    [[nodiscard]] bool check_ident(std::string_view kw) const noexcept {
        return cur().kind == TokenKind::Identifier && cur().text == kw;
    }

    void report_error(SourceLoc loc, std::string msg) {
        diags_.push_back(SignatureRuleDiagnostic{
            .source_name = std::string(src_name_),
            .line = loc.line,
            .column = loc.column,
            .message = std::move(msg),
        });
    }

    void synchronize_to_next_rule() {
        while (!at_eof()) {
            if (cur().kind == TokenKind::RBrace) {
                (void)consume();
                return;
            }
            if (check_ident("rule") || check_ident("private") || check_ident("global")) {
                return;
            }
            (void)consume();
        }
    }

    [[nodiscard]] std::optional<SignatureRule> parse_rule() {
        while (check_ident("private") || check_ident("global")) {
            (void)consume();
        }
        if (!check_ident("rule")) {
            report_error(cur().loc, std::format("Expected 'rule' declaration, found '{}'", cur().text));
            (void)consume();
            return std::nullopt;
        }
        (void)consume(); // 'rule'

        if (cur().kind != TokenKind::Identifier) {
            report_error(cur().loc, "Expected rule identifier after 'rule'");
            return std::nullopt;
        }
        SignatureRule rule{};
        rule.name = consume().text;
        rule.source_name = std::string(src_name_);

        if (cur().kind == TokenKind::Colon) {
            (void)consume();
            while (cur().kind == TokenKind::Identifier) {
                rule.tags.push_back(consume().text);
            }
            if (rule.tags.empty()) {
                report_error(cur().loc, "Expected at least one tag identifier after ':'");
                return std::nullopt;
            }
        }

        if (cur().kind != TokenKind::LBrace) {
            report_error(cur().loc, "Expected '{' to open rule body");
            return std::nullopt;
        }
        (void)consume(); // '{'

        auto body = std::make_shared<detail::CompiledSignatureRuleBody>();
        std::unordered_map<std::string, std::size_t> pattern_map{};
        bool saw_condition = false;

        while (!at_eof() && cur().kind != TokenKind::RBrace) {
            if (check_ident("meta")) {
                (void)consume();
                if (cur().kind != TokenKind::Colon) {
                    report_error(cur().loc, "Expected ':' after 'meta'");
                    return std::nullopt;
                }
                (void)consume();
                if (!parse_meta_section(rule)) {
                    return std::nullopt;
                }
            } else if (check_ident("strings")) {
                (void)consume();
                if (cur().kind != TokenKind::Colon) {
                    report_error(cur().loc, "Expected ':' after 'strings'");
                    return std::nullopt;
                }
                (void)consume();
                if (!parse_strings_section(*body, pattern_map)) {
                    return std::nullopt;
                }
            } else if (check_ident("condition")) {
                (void)consume();
                if (cur().kind != TokenKind::Colon) {
                    report_error(cur().loc, "Expected ':' after 'condition'");
                    return std::nullopt;
                }
                (void)consume();
                saw_condition = true;
                active_body_ = body.get();
                active_pattern_map_ = &pattern_map;
                body->condition = parse_expr_or();
                active_body_ = nullptr;
                active_pattern_map_ = nullptr;
                if (!body->condition) {
                    return std::nullopt;
                }
                break;
            } else {
                report_error(cur().loc,
                             std::format("Expected 'meta:', 'strings:', or 'condition:' section, found '{}'",
                                         cur().text));
                return std::nullopt;
            }
        }

        if (!saw_condition || !body->condition) {
            report_error(cur().loc, std::format("Rule '{}' is missing a 'condition:' section", rule.name));
            return std::nullopt;
        }

        if (cur().kind != TokenKind::RBrace) {
            report_error(cur().loc, std::format("Expected '}}' closing rule '{}', found '{}'",
                                                rule.name,
                                                cur().text));
            return std::nullopt;
        }
        (void)consume(); // '}'

        rule.compiled = std::move(body);
        return rule;
    }

    [[nodiscard]] bool parse_meta_section(SignatureRule& rule) {
        while (!at_eof() && cur().kind == TokenKind::Identifier) {
            // Stop when hitting the next section header (`strings:` or `condition:`)
            if ((check_ident("strings") || check_ident("condition") || check_ident("meta")) &&
                idx_ + 1u < tokens_.size() && tokens_[idx_ + 1u].kind == TokenKind::Colon) {
                break;
            }
            const std::string key = consume().text;
            if (cur().kind != TokenKind::Equals) {
                report_error(cur().loc, std::format("Expected '=' after meta key '{}'", key));
                return false;
            }
            (void)consume();

            std::string val_str{};
            if (cur().kind == TokenKind::StringLiteral) {
                val_str = consume().text;
            } else if (cur().kind == TokenKind::IntLiteral) {
                val_str = std::to_string(consume().int_val);
            } else if (check_ident("true") || check_ident("false")) {
                val_str = consume().text;
            } else {
                report_error(cur().loc, std::format("Expected string, integer, or boolean value for meta key '{}'", key));
                return false;
            }

            if (key == "description") {
                rule.description = val_str;
            } else if (key == "severity") {
                rule.severity = normalize_rule_severity(val_str);
            } else if (key == "author") {
                rule.author = val_str;
            }
            rule.metadata.emplace_back(key, std::move(val_str));
        }
        return true;
    }

    [[nodiscard]] bool parse_strings_section(
        detail::CompiledSignatureRuleBody& body,
        std::unordered_map<std::string, std::size_t>& pattern_map) {
        while (!at_eof() && cur().kind == TokenKind::StringId) {
            const Token id_tok = consume();
            std::string pat_id = id_tok.text;
            if (pat_id == "$") {
                pat_id = std::format("$anon_{}", body.patterns.size());
            }
            if (pattern_map.contains(pat_id)) {
                report_error(id_tok.loc, std::format("Duplicate string identifier '{}'", pat_id));
                return false;
            }
            if (cur().kind != TokenKind::Equals) {
                report_error(cur().loc, std::format("Expected '=' after string identifier '{}'", pat_id));
                return false;
            }
            (void)consume(); // '='

            detail::CompiledStringPattern pat{};
            pat.identifier = pat_id;

            if (cur().kind == TokenKind::StringLiteral) {
                const Token str_tok = consume();
                if (str_tok.text.empty()) {
                    report_error(str_tok.loc,
                                 std::format("String pattern '{}' must not be empty", pat_id));
                    return false;
                }
                pat.kind = detail::PatternKind::Text;
                pat.raw_text.assign(
                    reinterpret_cast<const std::uint8_t*>(str_tok.text.data()),
                    reinterpret_cast<const std::uint8_t*>(str_tok.text.data()) + str_tok.text.size());

                bool explicit_ascii = false;
                bool explicit_wide = false;
                while (cur().kind == TokenKind::Identifier) {
                    if ((check_ident("condition") || check_ident("meta") || check_ident("strings")) &&
                        idx_ + 1u < tokens_.size() && tokens_[idx_ + 1u].kind == TokenKind::Colon) {
                        break;
                    }
                    if (check_ident("ascii")) {
                        explicit_ascii = true;
                        (void)consume();
                    } else if (check_ident("wide")) {
                        explicit_wide = true;
                        (void)consume();
                    } else if (check_ident("nocase")) {
                        pat.nocase = true;
                        (void)consume();
                    } else {
                        report_error(cur().loc,
                                     std::format("Unknown string modifier '{}' (expected ascii, wide, or nocase)",
                                                 cur().text));
                        return false;
                    }
                }
                if (explicit_ascii || explicit_wide) {
                    pat.ascii = explicit_ascii;
                    pat.wide = explicit_wide;
                } else {
                    pat.ascii = true;
                    pat.wide = false;
                }
            } else if (cur().kind == TokenKind::HexBlock) {
                const Token hex_tok = consume();
                auto parsed_hex = parse_hex_block_content(hex_tok, src_name_, diags_);
                if (!parsed_hex.has_value()) {
                    return false;
                }
                pat.kind = detail::PatternKind::Hex;
                pat.hex = std::move(*parsed_hex);
            } else {
                report_error(cur().loc,
                             std::format("Expected quoted string or '{{ ... }}' hex pattern for '{}'",
                                         pat_id));
                return false;
            }

            const std::size_t pat_idx = body.patterns.size();
            pattern_map.emplace(pat.identifier, pat_idx);
            body.patterns.push_back(std::move(pat));
        }
        return true;
    }

    // Condition grammar (standard YARA precedence):
    //   expr_or     := expr_and ('or' expr_and)*
    //   expr_and    := expr_not ('and' expr_not)*
    //   expr_not    := 'not' expr_not | expr_cmp
    //   expr_cmp    := expr_bitor (('=='|'!='|'<'|'<='|'>'|'>=') expr_bitor)?
    //   expr_bitor  := expr_bitxor ('|' expr_bitxor)*
    //   expr_bitxor := expr_bitand ('^' expr_bitand)*
    //   expr_bitand := expr_add ('&' expr_add)*
    //   expr_add    := expr_mul (('+'|'-') expr_mul)*
    //   expr_mul    := expr_unary (('*'|'/'|'%') expr_unary)*
    //   expr_unary  := ('-'|'~') expr_unary | expr_primary

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_or() {
        auto lhs = parse_expr_and();
        while (lhs && check_ident("or")) {
            (void)consume();
            auto rhs = parse_expr_and();
            if (!rhs) return nullptr;
            lhs = make_binary(detail::BinaryOpKind::LogicalOr, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_and() {
        auto lhs = parse_expr_not();
        while (lhs && check_ident("and")) {
            (void)consume();
            auto rhs = parse_expr_not();
            if (!rhs) return nullptr;
            lhs = make_binary(detail::BinaryOpKind::LogicalAnd, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_not() {
        if (check_ident("not")) {
            (void)consume();
            auto operand = parse_expr_not();
            if (!operand) return nullptr;
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::UnaryNot;
            node->lhs = std::move(operand);
            return node;
        }
        return parse_expr_cmp();
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_cmp() {
        auto lhs = parse_expr_bitor();
        if (!lhs) return nullptr;

        std::optional<detail::BinaryOpKind> op{};
        switch (cur().kind) {
            case TokenKind::EqEq:      op = detail::BinaryOpKind::Eq; break;
            case TokenKind::BangEq:    op = detail::BinaryOpKind::Ne; break;
            case TokenKind::Less:      op = detail::BinaryOpKind::Lt; break;
            case TokenKind::LessEq:    op = detail::BinaryOpKind::Le; break;
            case TokenKind::Greater:   op = detail::BinaryOpKind::Gt; break;
            case TokenKind::GreaterEq: op = detail::BinaryOpKind::Ge; break;
            default: break;
        }
        if (op.has_value()) {
            (void)consume();
            auto rhs = parse_expr_bitor();
            if (!rhs) return nullptr;
            lhs = make_binary(*op, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_bitor() {
        auto lhs = parse_expr_bitxor();
        while (lhs && cur().kind == TokenKind::Pipe) {
            (void)consume();
            auto rhs = parse_expr_bitxor();
            if (!rhs) return nullptr;
            lhs = make_binary(detail::BinaryOpKind::BitOr, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_bitxor() {
        auto lhs = parse_expr_bitand();
        while (lhs && cur().kind == TokenKind::Caret) {
            (void)consume();
            auto rhs = parse_expr_bitand();
            if (!rhs) return nullptr;
            lhs = make_binary(detail::BinaryOpKind::BitXor, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_bitand() {
        auto lhs = parse_expr_add();
        while (lhs && cur().kind == TokenKind::Amp) {
            (void)consume();
            auto rhs = parse_expr_add();
            if (!rhs) return nullptr;
            lhs = make_binary(detail::BinaryOpKind::BitAnd, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_add() {
        auto lhs = parse_expr_mul();
        while (lhs && (cur().kind == TokenKind::Plus || cur().kind == TokenKind::Minus)) {
            const detail::BinaryOpKind op =
                (consume().kind == TokenKind::Plus) ? detail::BinaryOpKind::Add
                                                    : detail::BinaryOpKind::Sub;
            auto rhs = parse_expr_mul();
            if (!rhs) return nullptr;
            lhs = make_binary(op, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_mul() {
        auto lhs = parse_expr_unary();
        while (lhs && (cur().kind == TokenKind::Star || cur().kind == TokenKind::Slash ||
                       cur().kind == TokenKind::Percent)) {
            const TokenKind tk = consume().kind;
            const detail::BinaryOpKind op =
                (tk == TokenKind::Star)    ? detail::BinaryOpKind::Mul
                : (tk == TokenKind::Slash) ? detail::BinaryOpKind::Div
                                           : detail::BinaryOpKind::Mod;
            auto rhs = parse_expr_unary();
            if (!rhs) return nullptr;
            lhs = make_binary(op, std::move(lhs), std::move(rhs));
        }
        return lhs;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_unary() {
        if (cur().kind == TokenKind::Minus) {
            (void)consume();
            auto sub = parse_expr_unary();
            if (!sub) return nullptr;
            auto n = std::make_unique<detail::ExprNode>();
            n->kind = detail::ExprKind::UnaryNeg;
            n->lhs = std::move(sub);
            return n;
        }
        if (cur().kind == TokenKind::Tilde) {
            (void)consume();
            auto sub = parse_expr_unary();
            if (!sub) return nullptr;
            auto n = std::make_unique<detail::ExprNode>();
            n->kind = detail::ExprKind::UnaryBitNot;
            n->lhs = std::move(sub);
            return n;
        }
        return parse_expr_primary();
    }

    [[nodiscard]] std::optional<std::size_t> resolve_pattern_id(SourceLoc loc,
                                                                std::string_view dollar_id) {
        if (active_pattern_map_ == nullptr) {
            return std::nullopt;
        }
        const auto it = active_pattern_map_->find(std::string(dollar_id));
        if (it == active_pattern_map_->end()) {
            report_error(loc, std::format("Reference to undefined string '{}'", dollar_id));
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_quantified_of(
        SourceLoc loc,
        detail::QuantifierKind qkind,
        std::uint64_t qcount) {
        (void)consume(); // consume 'of'
        std::vector<std::size_t> indices{};

        if (check_ident("them")) {
            (void)consume();
            if (active_body_ == nullptr || active_body_->patterns.empty()) {
                report_error(loc, "'of them' used in a rule with no declared strings");
                return nullptr;
            }
            indices.reserve(active_body_->patterns.size());
            for (std::size_t i = 0u; i < active_body_->patterns.size(); ++i) {
                indices.push_back(i);
            }
        } else if (cur().kind == TokenKind::LParen) {
            (void)consume(); // '('
            while (!at_eof() && cur().kind != TokenKind::RParen) {
                if (cur().kind == TokenKind::StringStarId) {
                    const Token star_tok = consume();
                    // Strip trailing '*' to match prefix (e.g. "$s*" -> "$s", "$*" -> "$")
                    const std::string_view prefix(star_tok.text.data(), star_tok.text.size() - 1u);
                    std::size_t matched_any = 0u;
                    if (active_body_ != nullptr) {
                        for (std::size_t i = 0u; i < active_body_->patterns.size(); ++i) {
                            if (active_body_->patterns[i].identifier.starts_with(prefix)) {
                                if (std::ranges::find(indices, i) == indices.end()) {
                                    indices.push_back(i);
                                }
                                ++matched_any;
                            }
                        }
                    }
                    if (matched_any == 0u) {
                        report_error(star_tok.loc,
                                     std::format("String wildcard '{}' matches no declared strings",
                                                 star_tok.text));
                        return nullptr;
                    }
                } else if (cur().kind == TokenKind::StringId) {
                    const Token id_tok = consume();
                    const auto resolved = resolve_pattern_id(id_tok.loc, id_tok.text);
                    if (!resolved.has_value()) {
                        return nullptr;
                    }
                    if (std::ranges::find(indices, *resolved) == indices.end()) {
                        indices.push_back(*resolved);
                    }
                } else {
                    report_error(cur().loc, "Expected '$prefix*' or '$id' inside 'of (...)' set");
                    return nullptr;
                }

                if (cur().kind == TokenKind::Comma) {
                    (void)consume();
                } else {
                    break;
                }
            }
            if (cur().kind != TokenKind::RParen) {
                report_error(cur().loc, "Expected ')' after string set in 'of (...)' expression");
                return nullptr;
            }
            (void)consume();
        } else {
            report_error(cur().loc, "Expected 'them' or '(...)' after 'of'");
            return nullptr;
        }

        auto node = std::make_unique<detail::ExprNode>();
        node->kind = detail::ExprKind::QuantifiedOf;
        node->quantifier = qkind;
        node->quantifier_count = qcount;
        node->target_pattern_indices = std::move(indices);
        return node;
    }

    [[nodiscard]] std::unique_ptr<detail::ExprNode> parse_expr_primary() {
        const Token& t = cur();

        if (t.kind == TokenKind::LParen) {
            (void)consume();
            auto inner = parse_expr_or();
            if (!inner) return nullptr;
            if (cur().kind != TokenKind::RParen) {
                report_error(cur().loc, "Expected closing ')'");
                return nullptr;
            }
            (void)consume();
            return inner;
        }

        if (t.kind == TokenKind::IntLiteral) {
            const Token num = consume();
            if (check_ident("of")) {
                return parse_quantified_of(
                    num.loc, detail::QuantifierKind::ExactCount, num.int_val);
            }
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::IntLiteral;
            node->int_val = num.int_val;
            return node;
        }

        if (t.kind == TokenKind::FloatLiteral) {
            const Token flt = consume();
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::FloatLiteral;
            node->float_val = flt.float_val;
            return node;
        }

        if (t.kind == TokenKind::StringId) {
            const Token id_tok = consume();
            const auto pat_idx = resolve_pattern_id(id_tok.loc, id_tok.text);
            if (!pat_idx.has_value()) {
                return nullptr;
            }
            if (check_ident("at")) {
                (void)consume();
                if (active_body_ != nullptr) {
                    active_body_->uses_offset_builtins = true;
                }
                auto off_expr = parse_expr_bitor();
                if (!off_expr) return nullptr;
                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::StringAtOffset;
                node->pattern_index = *pat_idx;
                node->lhs = std::move(off_expr);
                return node;
            }
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::StringMatched;
            node->pattern_index = *pat_idx;
            return node;
        }

        if (t.kind == TokenKind::StringCountId) {
            const Token cnt_tok = consume();
            const std::string dollar_id = "$" + cnt_tok.text.substr(1u);
            const auto pat_idx = resolve_pattern_id(cnt_tok.loc, dollar_id);
            if (!pat_idx.has_value()) {
                return nullptr;
            }
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::StringCount;
            node->pattern_index = *pat_idx;
            return node;
        }

        if (t.kind == TokenKind::StringOffId) {
            const Token off_tok = consume();
            const std::string dollar_id = "$" + off_tok.text.substr(1u);
            const auto pat_idx = resolve_pattern_id(off_tok.loc, dollar_id);
            if (!pat_idx.has_value()) {
                return nullptr;
            }
            if (active_body_ != nullptr) {
                active_body_->uses_offset_builtins = true;
            }
            auto node = std::make_unique<detail::ExprNode>();
            node->kind = detail::ExprKind::StringFirstOffset;
            node->pattern_index = *pat_idx;
            return node;
        }

        if (t.kind == TokenKind::Identifier) {
            if (check_ident("true") || check_ident("false")) {
                const bool bv = (consume().text == "true");
                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::BoolLiteral;
                node->bool_val = bv;
                return node;
            }
            if (check_ident("any")) {
                const SourceLoc loc = consume().loc;
                if (!check_ident("of")) {
                    report_error(cur().loc, "Expected 'of' after 'any'");
                    return nullptr;
                }
                return parse_quantified_of(loc, detail::QuantifierKind::Any, 1u);
            }
            if (check_ident("all")) {
                const SourceLoc loc = consume().loc;
                if (!check_ident("of")) {
                    report_error(cur().loc, "Expected 'of' after 'all'");
                    return nullptr;
                }
                return parse_quantified_of(loc, detail::QuantifierKind::All, 0u);
            }
            if (check_ident("none")) {
                const SourceLoc loc = consume().loc;
                if (!check_ident("of")) {
                    report_error(cur().loc, "Expected 'of' after 'none'");
                    return nullptr;
                }
                return parse_quantified_of(loc, detail::QuantifierKind::None, 0u);
            }
            if (check_ident("filesize")) {
                (void)consume();
                if (active_body_ != nullptr) {
                    active_body_->uses_offset_builtins = true;
                }
                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::Filesize;
                return node;
            }
            if (check_ident("entrypoint")) {
                (void)consume();
                if (active_body_ != nullptr) {
                    active_body_->uses_offset_builtins = true;
                }
                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::Entrypoint;
                return node;
            }
            if (check_ident("uint8") || check_ident("uint16") || check_ident("uint32") ||
                check_ident("uint16be") || check_ident("uint32be")) {
                const Token fn_tok = consume();
                if (active_body_ != nullptr) {
                    active_body_->uses_offset_builtins = true;
                }
                if (cur().kind != TokenKind::LParen) {
                    report_error(cur().loc, std::format("Expected '(' after '{}'", fn_tok.text));
                    return nullptr;
                }
                (void)consume();
                auto arg = parse_expr_or();
                if (!arg) return nullptr;
                if (cur().kind != TokenKind::RParen) {
                    report_error(cur().loc, std::format("Expected ')' after '{}' argument", fn_tok.text));
                    return nullptr;
                }
                (void)consume();

                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::ReadIntFunc;
                if (fn_tok.text == "uint8")         node->read_width = detail::ReadIntWidth::U8;
                else if (fn_tok.text == "uint16")   node->read_width = detail::ReadIntWidth::U16Le;
                else if (fn_tok.text == "uint32")   node->read_width = detail::ReadIntWidth::U32Le;
                else if (fn_tok.text == "uint16be") node->read_width = detail::ReadIntWidth::U16Be;
                else                                node->read_width = detail::ReadIntWidth::U32Be;
                node->lhs = std::move(arg);
                return node;
            }
            if (check_ident("entropy")) {
                const Token fn_tok = consume();
                if (active_body_ != nullptr) {
                    active_body_->uses_offset_builtins = true;
                }
                if (cur().kind != TokenKind::LParen) {
                    report_error(cur().loc, "Expected '(' after 'entropy'");
                    return nullptr;
                }
                (void)consume();
                auto off_arg = parse_expr_or();
                if (!off_arg) return nullptr;
                if (cur().kind != TokenKind::Comma) {
                    report_error(cur().loc, "Expected ',' separating entropy(offset, length) arguments");
                    return nullptr;
                }
                (void)consume();
                auto len_arg = parse_expr_or();
                if (!len_arg) return nullptr;
                if (cur().kind != TokenKind::RParen) {
                    report_error(fn_tok.loc, "Expected ')' closing entropy(offset, length)");
                    return nullptr;
                }
                (void)consume();

                auto node = std::make_unique<detail::ExprNode>();
                node->kind = detail::ExprKind::EntropyFunc;
                node->lhs = std::move(off_arg);
                node->rhs = std::move(len_arg);
                return node;
            }

            report_error(t.loc, std::format("Unknown identifier '{}' in condition expression", t.text));
            return nullptr;
        }

        report_error(t.loc, std::format("Unexpected token '{}' in condition expression", t.text));
        return nullptr;
    }

    [[nodiscard]] static std::unique_ptr<detail::ExprNode> make_binary(
        detail::BinaryOpKind op,
        std::unique_ptr<detail::ExprNode> lhs,
        std::unique_ptr<detail::ExprNode> rhs) {
        auto node = std::make_unique<detail::ExprNode>();
        node->kind = detail::ExprKind::BinaryOp;
        node->bin_op = op;
        node->lhs = std::move(lhs);
        node->rhs = std::move(rhs);
        return node;
    }

    std::vector<Token> tokens_{};
    std::string_view src_name_{};
    std::vector<SignatureRuleDiagnostic>& diags_;
    std::size_t idx_{0};
    detail::CompiledSignatureRuleBody* active_body_{nullptr};
    const std::unordered_map<std::string, std::size_t>* active_pattern_map_{nullptr};
};

// ---------------------------------------------------------------------------
// Pattern Scanning & AST Evaluation Engine
// ---------------------------------------------------------------------------

constexpr std::size_t kMaxStoredMatchOffsetsPerPattern = 2048u;
constexpr std::size_t kMaxExportedMatchesPerRule = 64u;

struct PatternRuntimeHit {
    std::size_t offset{0};
    std::size_t length{0};
};

struct PatternEvalState {
    std::uint64_t total_count{0};
    std::optional<std::uint64_t> first_offset{};
    std::vector<PatternRuntimeHit> recorded{};
    bool overflowed_recorded{false};
};

[[nodiscard]] bool match_ascii_at(std::span<const std::uint8_t> bytes,
                                  std::size_t pos,
                                  std::span<const std::uint8_t> needle,
                                  bool nocase) noexcept {
    if (pos + needle.size() > bytes.size()) {
        return false;
    }
    if (!nocase) {
        return std::memcmp(bytes.data() + pos, needle.data(), needle.size()) == 0;
    }
    for (std::size_t i = 0u; i < needle.size(); ++i) {
        if (ascii_lower_u8(bytes[pos + i]) != ascii_lower_u8(needle[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool match_wide_at(std::span<const std::uint8_t> bytes,
                                 std::size_t pos,
                                 std::span<const std::uint8_t> needle,
                                 bool nocase) noexcept {
    const std::size_t wide_len = needle.size() * 2u;
    if (pos + wide_len > bytes.size()) {
        return false;
    }
    for (std::size_t i = 0u; i < needle.size(); ++i) {
        if (bytes[pos + i * 2u + 1u] != 0u) {
            return false;
        }
        const std::uint8_t got = bytes[pos + i * 2u];
        const std::uint8_t exp = needle[i];
        if (nocase) {
            if (ascii_lower_u8(got) != ascii_lower_u8(exp)) {
                return false;
            }
        } else if (got != exp) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool match_hex_segment_at(std::span<const std::uint8_t> bytes,
                                        std::size_t pos,
                                        std::span<const detail::HexMaskedByte> seg) noexcept {
    if (pos + seg.size() > bytes.size()) {
        return false;
    }
    for (std::size_t i = 0u; i < seg.size(); ++i) {
        if ((bytes[pos + i] & seg[i].mask) != seg[i].value) {
            return false;
        }
    }
    return true;
}

// Non-backtracking forward segment state-set matcher for `{ seg0 [min0-max0] seg1 ... }`.
// Returns the shortest matching total byte length starting at `start_pos`, or `nullopt`.
[[nodiscard]] std::optional<std::size_t> match_hex_pattern_at(
    std::span<const std::uint8_t> bytes,
    std::size_t start_pos,
    const detail::CompiledHexPattern& hex) {
    const auto& seg0 = hex.segments.front();
    if (!match_hex_segment_at(bytes, start_pos, seg0)) {
        return std::nullopt;
    }
    if (hex.jumps.empty()) {
        return seg0.size();
    }

    std::vector<std::size_t> current_ends{start_pos + seg0.size()};
    std::vector<std::size_t> next_ends{};

    for (std::size_t j = 0u; j < hex.jumps.size(); ++j) {
        const detail::HexJump jmp = hex.jumps[j];
        const auto& next_seg = hex.segments[j + 1u];
        next_ends.clear();

        for (const std::size_t end_pos : current_ends) {
            if (end_pos + jmp.min_skip + next_seg.size() > bytes.size()) {
                continue;
            }
            const std::size_t lo = end_pos + jmp.min_skip;
            const std::size_t hi = std::min<std::size_t>(
                end_pos + jmp.max_skip,
                bytes.size() - next_seg.size());
            for (std::size_t cand = lo; cand <= hi; ++cand) {
                if (match_hex_segment_at(bytes, cand, next_seg)) {
                    next_ends.push_back(cand + next_seg.size());
                }
            }
        }
        if (next_ends.empty()) {
            return std::nullopt;
        }
        std::ranges::sort(next_ends);
        const auto uniq = std::ranges::unique(next_ends);
        next_ends.erase(uniq.begin(), uniq.end());
        current_ends.swap(next_ends);
    }

    return current_ends.front() - start_pos;
}

[[nodiscard]] bool test_pattern_at_exact_offset(const detail::CompiledStringPattern& pat,
                                                std::span<const std::uint8_t> bytes,
                                                std::size_t offset) {
    if (offset >= bytes.size()) {
        return false;
    }
    if (pat.kind == detail::PatternKind::Text) {
        if (pat.ascii && match_ascii_at(bytes, offset, pat.raw_text, pat.nocase)) {
            return true;
        }
        if (pat.wide && match_wide_at(bytes, offset, pat.raw_text, pat.nocase)) {
            return true;
        }
        return false;
    }
    return match_hex_pattern_at(bytes, offset, pat.hex).has_value();
}

[[nodiscard]] PatternEvalState scan_single_pattern(const detail::CompiledStringPattern& pat,
                                                   std::span<const std::uint8_t> bytes) {
    PatternEvalState st{};
    if (bytes.empty()) {
        return st;
    }

    auto record_hit = [&](std::size_t off, std::size_t len) {
        ++st.total_count;
        if (!st.first_offset.has_value() || off < *st.first_offset) {
            st.first_offset = static_cast<std::uint64_t>(off);
        }
        if (st.recorded.size() < kMaxStoredMatchOffsetsPerPattern) {
            st.recorded.push_back(PatternRuntimeHit{.offset = off, .length = len});
        } else {
            st.overflowed_recorded = true;
        }
    };

    if (pat.kind == detail::PatternKind::Text) {
        if (pat.raw_text.empty()) {
            return st;
        }
        const std::uint8_t first_b = pat.raw_text[0];
        const std::uint8_t first_lo = ascii_lower_u8(first_b);

        if (pat.ascii && !pat.wide && !pat.nocase) {
            // Fast `std::memchr`-accelerated exact ASCII scan
            std::size_t cur = 0u;
            while (cur + pat.raw_text.size() <= bytes.size()) {
                const std::size_t search_len = (bytes.size() - pat.raw_text.size() + 1u) - cur;
                const auto* found = static_cast<const std::uint8_t*>(
                    std::memchr(bytes.data() + cur, first_b, search_len));
                if (found == nullptr) {
                    break;
                }
                const auto idx = static_cast<std::size_t>(found - bytes.data());
                if (std::memcmp(bytes.data() + idx, pat.raw_text.data(), pat.raw_text.size()) == 0) {
                    record_hit(idx, pat.raw_text.size());
                }
                cur = idx + 1u;
            }
            return st;
        }

        for (std::size_t pos = 0u; pos < bytes.size(); ++pos) {
            const std::uint8_t b = bytes[pos];
            const bool first_ok = pat.nocase ? (ascii_lower_u8(b) == first_lo) : (b == first_b);
            if (!first_ok) {
                continue;
            }
            if (pat.ascii && match_ascii_at(bytes, pos, pat.raw_text, pat.nocase)) {
                record_hit(pos, pat.raw_text.size());
            }
            if (pat.wide && match_wide_at(bytes, pos, pat.raw_text, pat.nocase)) {
                record_hit(pos, pat.raw_text.size() * 2u);
            }
        }
        return st;
    }

    // Hex pattern scan: anchor on the first exact (`mask == 0xFF`) byte inside `segments[0]` when present
    const auto& seg0 = pat.hex.segments.front();
    std::optional<std::size_t> anchor_idx{};
    for (std::size_t i = 0u; i < seg0.size(); ++i) {
        if (seg0[i].mask == 0xFFu) {
            anchor_idx = i;
            break;
        }
    }

    if (anchor_idx.has_value()) {
        const std::size_t a_off = *anchor_idx;
        const std::uint8_t a_val = seg0[a_off].value;
        std::size_t cur = a_off;
        while (cur < bytes.size()) {
            const auto* found = static_cast<const std::uint8_t*>(
                std::memchr(bytes.data() + cur, a_val, bytes.size() - cur));
            if (found == nullptr) {
                break;
            }
            const auto anchor_pos = static_cast<std::size_t>(found - bytes.data());
            const std::size_t start_pos = anchor_pos - a_off;
            if (const auto mlen = match_hex_pattern_at(bytes, start_pos, pat.hex)) {
                record_hit(start_pos, *mlen);
            }
            cur = anchor_pos + 1u;
        }
    } else {
        for (std::size_t pos = 0u; pos + seg0.size() <= bytes.size(); ++pos) {
            if (const auto mlen = match_hex_pattern_at(bytes, pos, pat.hex)) {
                record_hit(pos, *mlen);
            }
        }
    }
    return st;
}

enum class EvalScalarKind : std::uint8_t {
    Undefined = 0,
    Bool,
    Int,
    Float,
};

struct EvalScalar {
    EvalScalarKind kind{EvalScalarKind::Undefined};
    bool bool_val{false};
    std::uint64_t int_val{0};
    double float_val{0.0};

    [[nodiscard]] static constexpr EvalScalar undef() noexcept { return EvalScalar{}; }
    [[nodiscard]] static constexpr EvalScalar from_bool(bool b) noexcept {
        return EvalScalar{.kind = EvalScalarKind::Bool, .bool_val = b, .int_val = b ? 1u : 0u};
    }
    [[nodiscard]] static constexpr EvalScalar from_int(std::uint64_t v) noexcept {
        return EvalScalar{.kind = EvalScalarKind::Int, .int_val = v, .float_val = static_cast<double>(v)};
    }
    [[nodiscard]] static constexpr EvalScalar from_float(double d) noexcept {
        return EvalScalar{.kind = EvalScalarKind::Float, .float_val = d};
    }

    [[nodiscard]] constexpr bool to_bool() const noexcept {
        switch (kind) {
            case EvalScalarKind::Undefined: return false;
            case EvalScalarKind::Bool:      return bool_val;
            case EvalScalarKind::Int:       return int_val != 0u;
            case EvalScalarKind::Float:     return float_val != 0.0;
        }
        return false;
    }

    [[nodiscard]] constexpr std::optional<std::uint64_t> to_uint() const noexcept {
        if (kind == EvalScalarKind::Int) {
            return int_val;
        }
        if (kind == EvalScalarKind::Bool) {
            return bool_val ? 1ULL : 0ULL;
        }
        return std::nullopt;
    }

    [[nodiscard]] constexpr std::optional<double> to_double() const noexcept {
        if (kind == EvalScalarKind::Float) {
            return float_val;
        }
        if (kind == EvalScalarKind::Int) {
            return static_cast<double>(int_val);
        }
        if (kind == EvalScalarKind::Bool) {
            return bool_val ? 1.0 : 0.0;
        }
        return std::nullopt;
    }
};

struct RuleEvalContext {
    std::span<const std::uint8_t> bytes{};
    std::optional<std::uint64_t> entrypoint_offset{};
    std::span<const detail::CompiledStringPattern> patterns{};
    std::span<const PatternEvalState> states{};
};

[[nodiscard]] std::optional<std::uint64_t> compute_entrypoint_file_offset(
    std::span<const std::uint8_t> raw_bytes,
    const IBinaryImage* image) noexcept {
    if (image != nullptr && image->entry_point() != 0u) {
        if (const auto off = image->virtual_address_to_file_offset(image->entry_point())) {
            return *off;
        }
        return image->entry_point();
    }
    // Lightweight header fallback when `image == nullptr`
    if (raw_bytes.size() >= 0x40u && raw_bytes[0] == 'M' && raw_bytes[1] == 'Z') {
        const std::uint32_t lfanew = read_u32_le(raw_bytes, 0x3Cu);
        if (static_cast<std::size_t>(lfanew) + 0x2Cu <= raw_bytes.size() &&
            raw_bytes[lfanew] == 'P' && raw_bytes[lfanew + 1u] == 'E') {
            return static_cast<std::uint64_t>(read_u32_le(raw_bytes, static_cast<std::size_t>(lfanew) + 0x28u));
        }
    }
    return std::nullopt;
}

[[nodiscard]] EvalScalar evaluate_ast(const detail::ExprNode& node, const RuleEvalContext& ctx) {
    switch (node.kind) {
        case detail::ExprKind::BoolLiteral:
            return EvalScalar::from_bool(node.bool_val);
        case detail::ExprKind::IntLiteral:
            return EvalScalar::from_int(node.int_val);
        case detail::ExprKind::FloatLiteral:
            return EvalScalar::from_float(node.float_val);
        case detail::ExprKind::Filesize:
            return EvalScalar::from_int(static_cast<std::uint64_t>(ctx.bytes.size()));
        case detail::ExprKind::Entrypoint:
            return ctx.entrypoint_offset.has_value()
                       ? EvalScalar::from_int(*ctx.entrypoint_offset)
                       : EvalScalar::undef();
        case detail::ExprKind::StringMatched:
            return EvalScalar::from_bool(ctx.states[node.pattern_index].total_count > 0u);
        case detail::ExprKind::StringCount:
            return EvalScalar::from_int(ctx.states[node.pattern_index].total_count);
        case detail::ExprKind::StringFirstOffset: {
            const auto& fo = ctx.states[node.pattern_index].first_offset;
            return fo.has_value() ? EvalScalar::from_int(*fo) : EvalScalar::undef();
        }
        case detail::ExprKind::StringAtOffset: {
            const auto target_off = evaluate_ast(*node.lhs, ctx).to_uint();
            if (!target_off.has_value() || *target_off >= ctx.bytes.size()) {
                return EvalScalar::from_bool(false);
            }
            const auto off_sz = static_cast<std::size_t>(*target_off);
            const PatternEvalState& st = ctx.states[node.pattern_index];
            if (!st.overflowed_recorded) {
                const bool found = std::ranges::any_of(
                    st.recorded,
                    [off_sz](const PatternRuntimeHit& h) noexcept { return h.offset == off_sz; });
                return EvalScalar::from_bool(found);
            }
            return EvalScalar::from_bool(
                test_pattern_at_exact_offset(ctx.patterns[node.pattern_index], ctx.bytes, off_sz));
        }
        case detail::ExprKind::QuantifiedOf: {
            std::uint64_t matched_patterns = 0u;
            for (const std::size_t idx : node.target_pattern_indices) {
                if (ctx.states[idx].total_count > 0u) {
                    ++matched_patterns;
                }
            }
            switch (node.quantifier) {
                case detail::QuantifierKind::Any:
                    return EvalScalar::from_bool(matched_patterns >= 1u);
                case detail::QuantifierKind::All:
                    return EvalScalar::from_bool(
                        !node.target_pattern_indices.empty() &&
                        matched_patterns == node.target_pattern_indices.size());
                case detail::QuantifierKind::None:
                    return EvalScalar::from_bool(matched_patterns == 0u);
                case detail::QuantifierKind::ExactCount:
                    return EvalScalar::from_bool(matched_patterns >= node.quantifier_count);
            }
            return EvalScalar::from_bool(false);
        }
        case detail::ExprKind::ReadIntFunc: {
            const auto off = evaluate_ast(*node.lhs, ctx).to_uint();
            if (!off.has_value() || *off >= ctx.bytes.size()) {
                return EvalScalar::undef();
            }
            const auto pos = static_cast<std::size_t>(*off);
            switch (node.read_width) {
                case detail::ReadIntWidth::U8:
                    return EvalScalar::from_int(ctx.bytes[pos]);
                case detail::ReadIntWidth::U16Le:
                    return (pos + 2u <= ctx.bytes.size())
                               ? EvalScalar::from_int(read_u16_le(ctx.bytes, pos))
                               : EvalScalar::undef();
                case detail::ReadIntWidth::U32Le:
                    return (pos + 4u <= ctx.bytes.size())
                               ? EvalScalar::from_int(read_u32_le(ctx.bytes, pos))
                               : EvalScalar::undef();
                case detail::ReadIntWidth::U16Be:
                    return (pos + 2u <= ctx.bytes.size())
                               ? EvalScalar::from_int(read_u16_be(ctx.bytes, pos))
                               : EvalScalar::undef();
                case detail::ReadIntWidth::U32Be:
                    return (pos + 4u <= ctx.bytes.size())
                               ? EvalScalar::from_int(read_u32_be(ctx.bytes, pos))
                               : EvalScalar::undef();
            }
            return EvalScalar::undef();
        }
        case detail::ExprKind::EntropyFunc: {
            const auto off = evaluate_ast(*node.lhs, ctx).to_uint();
            const auto len = evaluate_ast(*node.rhs, ctx).to_uint();
            if (!off.has_value() || !len.has_value() || *len == 0u || *off >= ctx.bytes.size()) {
                return EvalScalar::undef();
            }
            const auto start = static_cast<std::size_t>(*off);
            const auto avail = static_cast<std::size_t>(
                std::min<std::uint64_t>(*len, ctx.bytes.size() - start));
            return EvalScalar::from_float(compute_shannon_entropy(ctx.bytes.subspan(start, avail)));
        }
        case detail::ExprKind::UnaryNot:
            return EvalScalar::from_bool(!evaluate_ast(*node.lhs, ctx).to_bool());
        case detail::ExprKind::UnaryNeg: {
            const EvalScalar v = evaluate_ast(*node.lhs, ctx);
            if (v.kind == EvalScalarKind::Float) {
                return EvalScalar::from_float(-v.float_val);
            }
            if (const auto u = v.to_uint()) {
                return EvalScalar::from_int(0ULL - *u);
            }
            return EvalScalar::undef();
        }
        case detail::ExprKind::UnaryBitNot: {
            if (const auto u = evaluate_ast(*node.lhs, ctx).to_uint()) {
                return EvalScalar::from_int(~(*u));
            }
            return EvalScalar::undef();
        }
        case detail::ExprKind::BinaryOp: {
            if (node.bin_op == detail::BinaryOpKind::LogicalOr) {
                if (evaluate_ast(*node.lhs, ctx).to_bool()) {
                    return EvalScalar::from_bool(true);
                }
                return EvalScalar::from_bool(evaluate_ast(*node.rhs, ctx).to_bool());
            }
            if (node.bin_op == detail::BinaryOpKind::LogicalAnd) {
                if (!evaluate_ast(*node.lhs, ctx).to_bool()) {
                    return EvalScalar::from_bool(false);
                }
                return EvalScalar::from_bool(evaluate_ast(*node.rhs, ctx).to_bool());
            }

            const EvalScalar lv = evaluate_ast(*node.lhs, ctx);
            const EvalScalar rv = evaluate_ast(*node.rhs, ctx);
            if (lv.kind == EvalScalarKind::Undefined || rv.kind == EvalScalarKind::Undefined) {
                // Comparisons with undefined evaluate cleanly to false (per YARA semantics)
                switch (node.bin_op) {
                    case detail::BinaryOpKind::Eq:
                    case detail::BinaryOpKind::Ne:
                    case detail::BinaryOpKind::Lt:
                    case detail::BinaryOpKind::Le:
                    case detail::BinaryOpKind::Gt:
                    case detail::BinaryOpKind::Ge:
                        return EvalScalar::from_bool(false);
                    default:
                        return EvalScalar::undef();
                }
            }

            const bool use_float =
                (lv.kind == EvalScalarKind::Float || rv.kind == EvalScalarKind::Float);
            if (use_float) {
                const double ld = lv.to_double().value_or(0.0);
                const double rd = rv.to_double().value_or(0.0);
                switch (node.bin_op) {
                    case detail::BinaryOpKind::Eq:  return EvalScalar::from_bool(ld == rd);
                    case detail::BinaryOpKind::Ne:  return EvalScalar::from_bool(ld != rd);
                    case detail::BinaryOpKind::Lt:  return EvalScalar::from_bool(ld < rd);
                    case detail::BinaryOpKind::Le:  return EvalScalar::from_bool(ld <= rd);
                    case detail::BinaryOpKind::Gt:  return EvalScalar::from_bool(ld > rd);
                    case detail::BinaryOpKind::Ge:  return EvalScalar::from_bool(ld >= rd);
                    case detail::BinaryOpKind::Add: return EvalScalar::from_float(ld + rd);
                    case detail::BinaryOpKind::Sub: return EvalScalar::from_float(ld - rd);
                    case detail::BinaryOpKind::Mul: return EvalScalar::from_float(ld * rd);
                    case detail::BinaryOpKind::Div:
                        return rd != 0.0 ? EvalScalar::from_float(ld / rd) : EvalScalar::undef();
                    default:
                        return EvalScalar::undef();
                }
            }

            const std::uint64_t lu = lv.to_uint().value_or(0u);
            const std::uint64_t ru = rv.to_uint().value_or(0u);
            switch (node.bin_op) {
                case detail::BinaryOpKind::Eq:     return EvalScalar::from_bool(lu == ru);
                case detail::BinaryOpKind::Ne:     return EvalScalar::from_bool(lu != ru);
                case detail::BinaryOpKind::Lt:     return EvalScalar::from_bool(lu < ru);
                case detail::BinaryOpKind::Le:     return EvalScalar::from_bool(lu <= ru);
                case detail::BinaryOpKind::Gt:     return EvalScalar::from_bool(lu > ru);
                case detail::BinaryOpKind::Ge:     return EvalScalar::from_bool(lu >= ru);
                case detail::BinaryOpKind::BitOr:  return EvalScalar::from_int(lu | ru);
                case detail::BinaryOpKind::BitXor: return EvalScalar::from_int(lu ^ ru);
                case detail::BinaryOpKind::BitAnd: return EvalScalar::from_int(lu & ru);
                case detail::BinaryOpKind::Add:    return EvalScalar::from_int(lu + ru);
                case detail::BinaryOpKind::Sub:    return EvalScalar::from_int(lu - ru);
                case detail::BinaryOpKind::Mul:    return EvalScalar::from_int(lu * ru);
                case detail::BinaryOpKind::Div:
                    return ru != 0u ? EvalScalar::from_int(lu / ru) : EvalScalar::undef();
                case detail::BinaryOpKind::Mod:
                    return ru != 0u ? EvalScalar::from_int(lu % ru) : EvalScalar::undef();
                default:
                    return EvalScalar::undef();
            }
        }
    }
    return EvalScalar::undef();
}

[[nodiscard]] std::string format_match_preview(std::span<const std::uint8_t> bytes,
                                               std::size_t offset,
                                               std::size_t length) {
    if (offset >= bytes.size() || length == 0u) {
        return {};
    }
    const std::size_t capped = std::min<std::size_t>({length, bytes.size() - offset, 32u});
    bool all_printable = true;
    for (std::size_t i = 0u; i < capped; ++i) {
        const std::uint8_t b = bytes[offset + i];
        if (b < 0x20u || b > 0x7Eu) {
            all_printable = false;
            break;
        }
    }
    if (all_printable) {
        std::string out(reinterpret_cast<const char*>(bytes.data() + offset), capped);
        if (length > capped) {
            out += "...";
        }
        return out;
    }
    const std::size_t hex_cap = std::min<std::size_t>(capped, 16u);
    std::string hex_out{};
    hex_out.reserve(hex_cap * 3u + 4u);
    for (std::size_t i = 0u; i < hex_cap; ++i) {
        if (i > 0u) {
            hex_out.push_back(' ');
        }
        hex_out += std::format("{:02X}", bytes[offset + i]);
    }
    if (length > hex_cap) {
        hex_out += " ...";
    }
    return hex_out;
}

[[nodiscard]] std::optional<SignatureRuleMatch> evaluate_single_rule_on_buffer(
    const SignatureRule& rule,
    std::span<const std::uint8_t> raw_bytes,
    const ScanAddressContext& addr_ctx,
    std::optional<std::uint64_t> entrypoint_offset) {
    if (!rule.compiled || !rule.compiled->condition) {
        return std::nullopt;
    }

    const auto& body = *rule.compiled;
    std::vector<PatternEvalState> states{};
    states.reserve(body.patterns.size());
    for (const detail::CompiledStringPattern& pat : body.patterns) {
        states.push_back(scan_single_pattern(pat, raw_bytes));
    }

    const RuleEvalContext eval_ctx{
        .bytes = raw_bytes,
        .entrypoint_offset = entrypoint_offset,
        .patterns = body.patterns,
        .states = states,
    };

    if (!evaluate_ast(*body.condition, eval_ctx).to_bool()) {
        return std::nullopt;
    }

    SignatureRuleMatch match{};
    match.rule_name = rule.name;
    match.tags = rule.tags;
    match.description = rule.description;
    match.severity = rule.severity;
    match.author = rule.author;
    match.source_name = rule.source_name;

    for (std::size_t p = 0u; p < body.patterns.size(); ++p) {
        const PatternEvalState& st = states[p];
        match.total_match_count += st.total_count;
        for (const PatternRuntimeHit& hit : st.recorded) {
            if (match.string_matches.size() >= kMaxExportedMatchesPerRule) {
                break;
            }
            ResolvedLocation loc = resolve_location_at(addr_ctx, hit.offset);
            SignatureStringMatch sm{};
            sm.identifier = body.patterns[p].identifier;
            sm.file_offset = loc.file_offset;
            sm.virtual_address = loc.virtual_address;
            sm.byte_length = static_cast<std::uint64_t>(hit.length);
            sm.section_name = std::move(loc.section_name);
            sm.matched_preview = format_match_preview(raw_bytes, hit.offset, hit.length);
            match.string_matches.push_back(std::move(sm));
        }
    }

    return match;
}

constexpr std::string_view kBuiltinRulesSource = R"YARA(
// Clean-Room Starter Signature Pack (peelf_core, BSD-2-Clause)

rule Packer_UPX_Signature : packer upx {
    meta:
        description = "Detects UPX-packed executable markers and UPX section names"
        severity = "warning"
        author = "peelf_core"
    strings:
        $magic = "UPX!" ascii
        $sec0 = "UPX0" ascii
        $sec1 = "UPX1" ascii
    condition:
        $magic and ($sec0 or $sec1)
}

rule Packer_MPRESS_ASPack_Protector : packer protector {
    meta:
        description = "Detects MPRESS, ASPack, VMProtect, or Themida packer section signatures"
        severity = "warning"
        author = "peelf_core"
    strings:
        $mp1 = ".MPRESS1" ascii
        $mp2 = ".MPRESS2" ascii
        $asp = ".aspack" ascii nocase
        $vmp0 = ".vmp0" ascii nocase
        $vmp1 = ".vmp1" ascii nocase
        $thm = ".themida" ascii nocase
    condition:
        ($mp1 and $mp2) or $asp or ($vmp0 and $vmp1) or $thm
}

rule Embedded_PE_Executable_Payload : embedded pe {
    meta:
        description = "Detects a secondary PE DOS stub embedded in an overlay, resource, or non-PE binary"
        severity = "warning"
        author = "peelf_core"
    strings:
        $dos1 = "This program cannot be run in DOS mode" ascii
        $dos2 = "This program must be run under Win32" ascii
    condition:
        (uint16(0) == 0x5A4D and (#dos1 >= 2 or #dos2 >= 2 or ($dos1 and $dos2))) or
        (uint16(0) != 0x5A4D and ($dos1 or $dos2))
}

rule Embedded_ELF_Image_Payload : embedded elf {
    meta:
        description = "Detects an embedded 32/64-bit ELF image header inside a non-core payload"
        severity = "note"
        author = "peelf_core"
    strings:
        $elf64_le = { 7F 45 4C 46 02 01 01 ?? 00 00 00 00 00 00 00 00 }
        $elf32_le = { 7F 45 4C 46 01 01 01 ?? 00 00 00 00 00 00 00 00 }
    condition:
        (uint32be(0) != 0x7F454C46 and ($elf64_le or $elf32_le)) or
        (uint32be(0) == 0x7F454C46 and uint16(16) != 4 and (#elf64_le >= 2 or #elf32_le >= 2))
}

rule Embedded_MachO_Image_Payload : embedded macho {
    meta:
        description = "Detects a 64-bit x86_64 or ARM64 Mach-O header embedded inside a non-Mach-O container"
        severity = "note"
        author = "peelf_core"
    strings:
        $macho_x64 = { CF FA ED FE 07 00 00 01 }
        $macho_arm64 = { CF FA ED FE 0C 00 00 01 }
    condition:
        uint32be(0) != 0xCFFAEDFE and uint32be(0) != 0xFEEDFACF and
        uint32be(0) != 0xCAFEBABE and uint32be(0) != 0xBEBAFECA and
        ($macho_x64 or $macho_arm64)
}

rule Suspicious_Process_Injection_APIs : injection windows {
    meta:
        description = "Detects remote process memory allocation, write, and remote thread execution API triad"
        severity = "warning"
        author = "peelf_core"
    strings:
        $alloc1 = "VirtualAllocEx" ascii wide
        $alloc2 = "NtMapViewOfSection" ascii wide
        $write1 = "WriteProcessMemory" ascii wide
        $write2 = "NtWriteVirtualMemory" ascii wide
        $exec1 = "CreateRemoteThread" ascii wide
        $exec2 = "QueueUserAPC" ascii wide
        $exec3 = "NtCreateThreadEx" ascii wide
    condition:
        ($alloc1 or $alloc2) and ($write1 or $write2) and ($exec1 or $exec2 or $exec3)
}

rule Suspicious_AntiDebug_Indicators : antidebug evasion {
    meta:
        description = "Detects 3 or more anti-debugging API and kernel-query indicators"
        severity = "note"
        author = "peelf_core"
    strings:
        $s1 = "IsDebuggerPresent" ascii wide
        $s2 = "CheckRemoteDebuggerPresent" ascii wide
        $s3 = "NtQueryInformationProcess" ascii wide
        $s4 = "NtSetInformationThread" ascii wide
        $s5 = "RtlAdjustPrivilege" ascii wide
    condition:
        3 of ($s*)
}

rule Shellcode_PEB_Walk_Stub : shellcode x86 x64 {
    meta:
        description = "Detects x86/x64 TEB/PEB LDR module-walking position-independent shellcode stub"
        severity = "warning"
        author = "peelf_core"
    strings:
        $x64_gs_peb = { 65 48 8B ?? 60 00 00 00 [0-16] 48 8B ?? 18 }
        $x86_fs_peb = { 64 8B ?? 30 00 00 00 [0-16] 8B ?? 0C }
    condition:
        any of them
}

rule Suspicious_Reflective_Or_Memfd_Loader : loader rwx {
    meta:
        description = "Detects reflective DLL loader export or Linux anonymous memfd execution staging"
        severity = "note"
        author = "peelf_core"
    strings:
        $refl = "ReflectiveLoader" ascii wide
        $memfd = "memfd_create" ascii
        $proc_fd = "/proc/self/fd/" ascii
    condition:
        $refl or ($memfd and $proc_fd)
}
)YARA";

} // namespace

SignatureRuleParseResult parse_signature_rules(
    std::string_view source,
    SignatureRuleSourceName source_name) {
    SignatureRuleParseResult res{};
    RuleLexer lexer(source, source_name.value, res.diagnostics);
    std::vector<Token> tokens = lexer.tokenize();
    if (!res.diagnostics.empty()) {
        return res;
    }
    RuleParser parser(std::move(tokens), source_name.value, res.diagnostics);
    res.ruleset = parser.parse_all();
    if (!res.diagnostics.empty()) {
        res.ruleset.rules.clear();
    }
    return res;
}

Result<SignatureRuleParseResult> load_signature_rules_file(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return make_error(std::format("Failed to open signature rule file '{}'", path.string()));
    }
    const auto end_pos = ifs.tellg();
    if (end_pos < 0) {
        return make_error(
            std::format("Failed to determine size of signature rule file '{}'", path.string()));
    }
    std::string content(static_cast<std::size_t>(end_pos), '\0');
    ifs.seekg(0, std::ios::beg);
    if (!content.empty() &&
        !ifs.read(content.data(), static_cast<std::streamsize>(content.size()))) {
        return make_error(std::format("Failed while reading signature rule file '{}'", path.string()));
    }
    const std::string label = path.filename().empty() ? path.string() : path.filename().string();
    return parse_signature_rules(content, SignatureRuleSourceName{label});
}

std::string_view builtin_signature_rules_source() noexcept {
    return kBuiltinRulesSource;
}

const SignatureRuleSet& builtin_signature_rules() {
    static const SignatureRuleSet kCompiledBuiltin = []() {
        SignatureRuleParseResult parsed =
            parse_signature_rules(kBuiltinRulesSource, SignatureRuleSourceName{"<builtin>"});
        return std::move(parsed.ruleset);
    }();
    return kCompiledBuiltin;
}

std::vector<SignatureRuleMatch> evaluate_signature_rules(
    const SignatureRuleSet& ruleset,
    std::span<const std::uint8_t> raw_bytes,
    const IBinaryImage* image) {
    std::vector<SignatureRuleMatch> matches{};
    if (ruleset.empty()) {
        return matches;
    }

    ScanAddressContext addr_ctx{};
    addr_ctx.image = image;
    addr_ctx.has_file_offsets = true;
    addr_ctx.fallback_region_name = "<raw>";
    const auto ep_off = compute_entrypoint_file_offset(raw_bytes, image);

    for (const SignatureRule& rule : ruleset.rules) {
        if (auto m = evaluate_single_rule_on_buffer(rule, raw_bytes, addr_ctx, ep_off)) {
            matches.push_back(std::move(*m));
        }
    }
    return matches;
}

std::vector<SignatureRuleMatch> evaluate_signature_rules(
    const SignatureRuleSet& ruleset,
    IProcessSession& session,
    std::size_t max_bytes_per_region) {
    std::vector<SignatureRuleMatch> matches{};
    if (ruleset.empty() || max_bytes_per_region == 0u) {
        return matches;
    }
    const auto regions_res = session.memory_regions();
    if (!regions_res.has_value()) {
        return matches;
    }

    struct RegionSlice {
        std::uint64_t base_va{0};
        std::string name{};
        std::vector<std::uint8_t> bytes{};
    };

    constexpr std::size_t kMaxRegionRead = 1024u * 1024u;
    std::vector<RegionSlice> readable_slices{};
    for (const MemoryRegion& reg : *regions_res) {
        if (!reg.protection.readable || reg.usage.is_reserved_only || reg.size() == 0u) {
            continue;
        }
        const auto cap = static_cast<std::size_t>(std::min<std::uint64_t>(
            {reg.size(), static_cast<std::uint64_t>(max_bytes_per_region), static_cast<std::uint64_t>(kMaxRegionRead)}));
        std::vector<std::uint8_t> buf(cap, 0u);
        const auto rd = session.read_memory(reg.start_address, buf);
        if (!rd.has_value() || *rd == 0u) {
            continue;
        }
        buf.resize(*rd);
        const std::string reg_label = !reg.module_name.empty()
                                          ? reg.module_name
                                          : (!reg.pathname.empty() ? reg.pathname
                                                                   : std::string(to_string(reg.kind)));
        readable_slices.push_back(RegionSlice{
            .base_va = reg.start_address,
            .name = reg_label,
            .bytes = std::move(buf),
        });
    }

    for (const SignatureRule& rule : ruleset.rules) {
        if (!rule.compiled || !rule.compiled->condition) {
            continue;
        }
        bool rule_matched = false;
        for (const RegionSlice& sl : readable_slices) {
            ScanAddressContext ctx{};
            ctx.fixed_base_va = sl.base_va;
            ctx.fallback_region_name = sl.name;
            ctx.has_file_offsets = false;
            if (auto m = evaluate_single_rule_on_buffer(rule, sl.bytes, ctx, std::nullopt)) {
                matches.push_back(std::move(*m));
                rule_matched = true;
                break;
            }
        }
        if (rule_matched || rule.compiled->uses_offset_builtins || readable_slices.size() <= 1u) {
            continue;
        }

        // Cross-region aggregation for pure multi-string rules (e.g., API strings across mapped pages)
        const auto& body = *rule.compiled;
        std::vector<PatternEvalState> agg_states(body.patterns.size());
        std::vector<SignatureStringMatch> agg_matches{};
        for (const RegionSlice& sl : readable_slices) {
            ScanAddressContext ctx{};
            ctx.fixed_base_va = sl.base_va;
            ctx.fallback_region_name = sl.name;
            ctx.has_file_offsets = false;
            for (std::size_t p = 0u; p < body.patterns.size(); ++p) {
                const PatternEvalState part = scan_single_pattern(body.patterns[p], sl.bytes);
                agg_states[p].total_count += part.total_count;
                if (!agg_states[p].first_offset.has_value() && part.first_offset.has_value()) {
                    agg_states[p].first_offset = sl.base_va + *part.first_offset;
                }
                for (const PatternRuntimeHit& h : part.recorded) {
                    if (agg_matches.size() >= kMaxExportedMatchesPerRule) {
                        break;
                    }
                    SignatureStringMatch sm{};
                    sm.identifier = body.patterns[p].identifier;
                    sm.file_offset = std::nullopt;
                    sm.virtual_address = sl.base_va + static_cast<std::uint64_t>(h.offset);
                    sm.byte_length = static_cast<std::uint64_t>(h.length);
                    sm.section_name = sl.name;
                    sm.matched_preview = format_match_preview(sl.bytes, h.offset, h.length);
                    agg_matches.push_back(std::move(sm));
                }
            }
        }
        const RuleEvalContext eval_ctx{
            .bytes = {},
            .entrypoint_offset = std::nullopt,
            .patterns = body.patterns,
            .states = agg_states,
        };
        if (evaluate_ast(*body.condition, eval_ctx).to_bool()) {
            SignatureRuleMatch m{};
            m.rule_name = rule.name;
            m.tags = rule.tags;
            m.description = rule.description;
            m.severity = rule.severity;
            m.author = rule.author;
            m.source_name = rule.source_name;
            for (const PatternEvalState& st : agg_states) {
                m.total_match_count += st.total_count;
            }
            m.string_matches = std::move(agg_matches);
            matches.push_back(std::move(m));
        }
    }

    return matches;
}

} // namespace peelf
