#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace peelf {

using Sha256Digest = std::array<std::uint8_t, 32>;

/// Incremental FIPS 180-4 SHA-256 hasher with zero external dependencies.
class Sha256Hasher {
public:
    Sha256Hasher() noexcept;

    void reset() noexcept;

    void update(std::span<const std::uint8_t> bytes) noexcept;
    void update(std::string_view text) noexcept;

    /// Finalizes the digest and resets the hasher state for reuse.
    [[nodiscard]] Sha256Digest finalize() noexcept;
    [[nodiscard]] std::string finalize_hex();

private:
    void compress_block(const std::uint8_t* block) noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_len_{0};
    std::uint64_t total_bytes_{0};
};

[[nodiscard]] std::string sha256_to_hex(const Sha256Digest& digest);
[[nodiscard]] Sha256Digest sha256_bytes(std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] Sha256Digest sha256_bytes(std::string_view text) noexcept;
[[nodiscard]] std::string sha256_hex(std::span<const std::uint8_t> bytes);
[[nodiscard]] std::string sha256_hex(std::string_view text);

}  // namespace peelf
