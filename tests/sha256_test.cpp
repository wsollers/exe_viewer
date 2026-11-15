#include <gtest/gtest.h>

#include <peelf/sha256.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

TEST(Sha256Test, NistFips180_4Vectors) {
    // Empty input
    EXPECT_EQ(peelf::sha256_hex(std::string_view{}),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Single block ("abc")
    EXPECT_EQ(peelf::sha256_hex("abc"),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Two blocks (448 bits)
    EXPECT_EQ(peelf::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Multi-block (896 bits)
    EXPECT_EQ(peelf::sha256_hex(
                  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                  "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
              "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

TEST(Sha256Test, PaddingBoundariesAndOneMillionAs) {
    // 55 bytes (fits length in same block: 55 + 0x80 + 8 == 64)
    EXPECT_EQ(peelf::sha256_hex(std::string(55, 'a')),
              "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");

    // 56 bytes (spills length into next block)
    EXPECT_EQ(peelf::sha256_hex(std::string(56, 'a')),
              "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");

    // 64 bytes (exact block boundary)
    EXPECT_EQ(peelf::sha256_hex(std::string(64, 'a')),
              "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");

    // NIST 1,000,000 'a' characters streamed across odd chunk sizes
    peelf::Sha256Hasher hasher;
    const std::string chunk(997, 'a');
    std::size_t remaining = 1'000'000;
    while (remaining > 0) {
        const std::size_t n = std::min(remaining, chunk.size());
        hasher.update(std::string_view(chunk.data(), n));
        remaining -= n;
    }
    EXPECT_EQ(hasher.finalize_hex(),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    // Finalize resets state so the same hasher instance is immediately reusable.
    hasher.update("abc");
    EXPECT_EQ(hasher.finalize_hex(),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

}  // namespace
