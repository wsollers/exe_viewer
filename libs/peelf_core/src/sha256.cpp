#include <peelf/sha256.hpp>

#include <algorithm>
#include <bit>
#include <cstring>

namespace peelf {

namespace {

constexpr std::array<std::uint32_t, 8> kInitialState = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

[[nodiscard]] constexpr std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24u) |
           (static_cast<std::uint32_t>(p[1]) << 16u) |
           (static_cast<std::uint32_t>(p[2]) << 8u) |
           static_cast<std::uint32_t>(p[3]);
}

constexpr void store_be32(std::uint8_t* out, std::uint32_t v) noexcept {
    out[0] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    out[3] = static_cast<std::uint8_t>(v & 0xFFu);
}

constexpr void store_be64(std::uint8_t* out, std::uint64_t v) noexcept {
    store_be32(out, static_cast<std::uint32_t>(v >> 32u));
    store_be32(out + 4, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
}

[[nodiscard]] constexpr std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

[[nodiscard]] constexpr std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

[[nodiscard]] constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
    return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
}

[[nodiscard]] constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
    return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
}

[[nodiscard]] constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
    return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3u);
}

[[nodiscard]] constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
    return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10u);
}

}  // namespace

Sha256Hasher::Sha256Hasher() noexcept {
    reset();
}

void Sha256Hasher::reset() noexcept {
    state_ = kInitialState;
    buffer_.fill(0);
    buffer_len_ = 0;
    total_bytes_ = 0;
}

void Sha256Hasher::compress_block(const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4u);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + kRoundConstants[i] + w[i];
        const std::uint32_t t2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256Hasher::update(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return;
    }

    total_bytes_ += static_cast<std::uint64_t>(bytes.size());
    const std::uint8_t* data = bytes.data();
    std::size_t remaining = bytes.size();

    if (buffer_len_ > 0) {
        const std::size_t take = std::min<std::size_t>(64u - buffer_len_, remaining);
        std::memcpy(buffer_.data() + buffer_len_, data, take);
        buffer_len_ += take;
        data += take;
        remaining -= take;
        if (buffer_len_ == 64u) {
            compress_block(buffer_.data());
            buffer_len_ = 0;
        }
    }

    while (remaining >= 64u) {
        compress_block(data);
        data += 64u;
        remaining -= 64u;
    }

    if (remaining > 0) {
        std::memcpy(buffer_.data(), data, remaining);
        buffer_len_ = remaining;
    }
}

void Sha256Hasher::update(std::string_view text) noexcept {
    if (text.empty()) {
        return;
    }
    update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

Sha256Digest Sha256Hasher::finalize() noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8ull;

    buffer_[buffer_len_++] = 0x80u;
    if (buffer_len_ > 56u) {
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_len_), buffer_.end(),
                  std::uint8_t{0});
        compress_block(buffer_.data());
        buffer_len_ = 0;
    }

    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_len_),
              buffer_.begin() + 56, std::uint8_t{0});
    store_be64(buffer_.data() + 56u, bit_length);
    compress_block(buffer_.data());

    Sha256Digest out{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_be32(out.data() + i * 4u, state_[i]);
    }

    reset();
    return out;
}

std::string Sha256Hasher::finalize_hex() {
    return sha256_to_hex(finalize());
}

std::string sha256_to_hex(const Sha256Digest& digest) {
    constexpr std::string_view kHexDigits = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const std::uint8_t byte = digest[i];
        out[i * 2u] = kHexDigits[(byte >> 4u) & 0x0Fu];
        out[i * 2u + 1u] = kHexDigits[byte & 0x0Fu];
    }
    return out;
}

Sha256Digest sha256_bytes(std::span<const std::uint8_t> bytes) noexcept {
    Sha256Hasher hasher;
    hasher.update(bytes);
    return hasher.finalize();
}

Sha256Digest sha256_bytes(std::string_view text) noexcept {
    Sha256Hasher hasher;
    hasher.update(text);
    return hasher.finalize();
}

std::string sha256_hex(std::span<const std::uint8_t> bytes) {
    return sha256_to_hex(sha256_bytes(bytes));
}

std::string sha256_hex(std::string_view text) {
    return sha256_to_hex(sha256_bytes(text));
}

}  // namespace peelf
