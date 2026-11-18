#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace viewer {

inline constexpr std::uint32_t kSpirvMagicNumber = 0x07230203u;
inline constexpr std::size_t kSpirvHeaderWordCount = 5u;

enum class SpirvValidationError : std::uint8_t {
    Ok = 0,
    Empty,
    UnalignedBytes,
    UnalignedPointer,
    TruncatedHeader,
    InvalidMagic,
    InvalidVersion,
    ZeroBound,
    NonZeroSchema,
    EmptyInstructionStream,
    TruncatedInstruction,
};

struct SpirvValidationResult {
    bool valid = false;
    SpirvValidationError error = SpirvValidationError::Empty;
    std::uint8_t version_major = 0;
    std::uint8_t version_minor = 0;
    std::uint32_t bound = 0;
    std::uint32_t instruction_count = 0;

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return valid; }
};

[[nodiscard]] constexpr SpirvValidationResult inspect_spirv_words(
    std::span<const std::uint32_t> words) noexcept {
    if (words.empty()) {
        return {.valid = false, .error = SpirvValidationError::Empty};
    }

    if (!std::is_constant_evaluated()) {
        const auto addr = reinterpret_cast<std::uintptr_t>(words.data());
        if ((addr % alignof(std::uint32_t)) != 0u) {
            return {.valid = false, .error = SpirvValidationError::UnalignedPointer};
        }
    }

    if (words.size() < kSpirvHeaderWordCount) {
        return {.valid = false, .error = SpirvValidationError::TruncatedHeader};
    }

    if (words[0] != kSpirvMagicNumber) {
        return {.valid = false, .error = SpirvValidationError::InvalidMagic};
    }

    const std::uint32_t version_word = words[1];
    if ((version_word & 0xFF0000FFu) != 0u) {
        return {.valid = false, .error = SpirvValidationError::InvalidVersion};
    }
    const auto major = static_cast<std::uint8_t>((version_word >> 16u) & 0xFFu);
    const auto minor = static_cast<std::uint8_t>((version_word >> 8u) & 0xFFu);
    if (major != 1u || minor > 6u) {
        return {.valid = false, .error = SpirvValidationError::InvalidVersion};
    }

    const std::uint32_t id_bound = words[3];
    if (id_bound == 0u) {
        return {.valid = false, .error = SpirvValidationError::ZeroBound};
    }

    if (words[4] != 0u) {
        return {.valid = false, .error = SpirvValidationError::NonZeroSchema};
    }

    if (words.size() == kSpirvHeaderWordCount) {
        return {.valid = false, .error = SpirvValidationError::EmptyInstructionStream};
    }

    std::size_t cursor = kSpirvHeaderWordCount;
    std::uint32_t instructions = 0u;
    while (cursor < words.size()) {
        const std::uint32_t inst_header = words[cursor];
        const std::uint32_t word_count = inst_header >> 16u;
        if (word_count == 0u || word_count > (words.size() - cursor)) {
            return {.valid = false, .error = SpirvValidationError::TruncatedInstruction};
        }
        cursor += static_cast<std::size_t>(word_count);
        ++instructions;
    }

    return SpirvValidationResult{
        .valid = true,
        .error = SpirvValidationError::Ok,
        .version_major = major,
        .version_minor = minor,
        .bound = id_bound,
        .instruction_count = instructions,
    };
}

[[nodiscard]] constexpr bool validate_spirv_words(
    std::span<const std::uint32_t> words) noexcept {
    return inspect_spirv_words(words).valid;
}

[[nodiscard]] inline SpirvValidationResult inspect_spirv_bytes(
    std::span<const std::byte> bytes) noexcept {
    if (bytes.empty()) {
        return {.valid = false, .error = SpirvValidationError::Empty};
    }
    if ((bytes.size() % sizeof(std::uint32_t)) != 0u) {
        return {.valid = false, .error = SpirvValidationError::UnalignedBytes};
    }
    const auto addr = reinterpret_cast<std::uintptr_t>(bytes.data());
    if ((addr % alignof(std::uint32_t)) != 0u) {
        return {.valid = false, .error = SpirvValidationError::UnalignedPointer};
    }
    const auto* word_ptr = reinterpret_cast<const std::uint32_t*>(bytes.data());
    return inspect_spirv_words(
        std::span<const std::uint32_t>(word_ptr, bytes.size() / sizeof(std::uint32_t)));
}

[[nodiscard]] inline bool validate_spirv_bytes(std::span<const std::byte> bytes) noexcept {
    return inspect_spirv_bytes(bytes).valid;
}

namespace shaders {

struct alignas(16) SmokeClearPushConstants {
    std::array<float, 4> clear_color{0.0f, 0.0f, 0.0f, 1.0f};
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t pad0 = 0;
    std::uint32_t pad1 = 0;
};
static_assert(sizeof(SmokeClearPushConstants) == 32);

// Precompiled SPIR-V 1.0 for apps/viewer/src/vulkan/shaders/smoke_clear.comp.glsl
inline constexpr std::array<std::uint32_t, 237> kSmokeClearCompSpirv{{
    0x07230203u, 0x00010000u, 0x00000000u, 0x0000002bu, 0x00000000u, 0x00020011u,
    0x00000001u, 0x0003000eu, 0x00000000u, 0x00000001u, 0x0006000fu, 0x00000005u,
    0x00000001u, 0x6e69616du, 0x00000000u, 0x00000010u, 0x00060010u, 0x00000001u,
    0x00000011u, 0x00000010u, 0x00000010u, 0x00000001u, 0x00040047u, 0x0000000eu,
    0x00000022u, 0x00000000u, 0x00040047u, 0x0000000eu, 0x00000021u, 0x00000000u,
    0x00030047u, 0x0000000eu, 0x00000019u, 0x00040047u, 0x00000010u, 0x0000000bu,
    0x0000001cu, 0x00030047u, 0x00000011u, 0x00000002u, 0x00050048u, 0x00000011u,
    0x00000000u, 0x00000023u, 0x00000000u, 0x00050048u, 0x00000011u, 0x00000001u,
    0x00000023u, 0x00000010u, 0x00020013u, 0x00000002u, 0x00030021u, 0x00000003u,
    0x00000002u, 0x00040015u, 0x00000004u, 0x00000020u, 0x00000000u, 0x00040015u,
    0x00000005u, 0x00000020u, 0x00000001u, 0x00030016u, 0x00000006u, 0x00000020u,
    0x00020014u, 0x00000007u, 0x00040017u, 0x00000008u, 0x00000004u, 0x00000003u,
    0x00040017u, 0x00000009u, 0x00000004u, 0x00000002u, 0x00040017u, 0x0000000au,
    0x00000005u, 0x00000002u, 0x00040017u, 0x0000000bu, 0x00000006u, 0x00000004u,
    0x00090019u, 0x0000000cu, 0x00000006u, 0x00000001u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000002u, 0x00000004u, 0x00040020u, 0x0000000du, 0x00000000u,
    0x0000000cu, 0x0004003bu, 0x0000000du, 0x0000000eu, 0x00000000u, 0x00040020u,
    0x0000000fu, 0x00000001u, 0x00000008u, 0x0004003bu, 0x0000000fu, 0x00000010u,
    0x00000001u, 0x0004001eu, 0x00000011u, 0x0000000bu, 0x00000009u, 0x00040020u,
    0x00000012u, 0x00000009u, 0x00000011u, 0x0004003bu, 0x00000012u, 0x00000013u,
    0x00000009u, 0x00040020u, 0x00000014u, 0x00000009u, 0x0000000bu, 0x00040020u,
    0x00000015u, 0x00000009u, 0x00000009u, 0x0004002bu, 0x00000005u, 0x00000016u,
    0x00000000u, 0x0004002bu, 0x00000005u, 0x00000017u, 0x00000001u, 0x00050036u,
    0x00000002u, 0x00000001u, 0x00000000u, 0x00000003u, 0x000200f8u, 0x00000018u,
    0x0004003du, 0x00000008u, 0x00000019u, 0x00000010u, 0x00050051u, 0x00000004u,
    0x0000001au, 0x00000019u, 0x00000000u, 0x00050051u, 0x00000004u, 0x0000001bu,
    0x00000019u, 0x00000001u, 0x00050041u, 0x00000015u, 0x0000001cu, 0x00000013u,
    0x00000017u, 0x0004003du, 0x00000009u, 0x0000001du, 0x0000001cu, 0x00050051u,
    0x00000004u, 0x0000001eu, 0x0000001du, 0x00000000u, 0x00050051u, 0x00000004u,
    0x0000001fu, 0x0000001du, 0x00000001u, 0x000500b0u, 0x00000007u, 0x00000020u,
    0x0000001au, 0x0000001eu, 0x000500b0u, 0x00000007u, 0x00000021u, 0x0000001bu,
    0x0000001fu, 0x000500a7u, 0x00000007u, 0x00000022u, 0x00000020u, 0x00000021u,
    0x000300f7u, 0x00000024u, 0x00000000u, 0x000400fau, 0x00000022u, 0x00000023u,
    0x00000024u, 0x000200f8u, 0x00000023u, 0x00050041u, 0x00000014u, 0x00000025u,
    0x00000013u, 0x00000016u, 0x0004003du, 0x0000000bu, 0x00000026u, 0x00000025u,
    0x0004003du, 0x0000000cu, 0x00000027u, 0x0000000eu, 0x0004007cu, 0x00000005u,
    0x00000028u, 0x0000001au, 0x0004007cu, 0x00000005u, 0x00000029u, 0x0000001bu,
    0x00050050u, 0x0000000au, 0x0000002au, 0x00000028u, 0x00000029u, 0x00040063u,
    0x00000027u, 0x0000002au, 0x00000026u, 0x000200f9u, 0x00000024u, 0x000200f8u,
    0x00000024u, 0x000100fdu, 0x00010038u,
}};

// Precompiled SPIR-V 1.0 for apps/viewer/src/vulkan/shaders/passthrough_quad.vert.glsl
inline constexpr std::array<std::uint32_t, 151> kPassthroughQuadVertSpirv{{
    0x07230203u, 0x00010000u, 0x00000000u, 0x0000001bu, 0x00000000u, 0x00020011u,
    0x00000001u, 0x0003000eu, 0x00000000u, 0x00000001u, 0x0009000fu, 0x00000000u,
    0x00000001u, 0x6e69616du, 0x00000000u, 0x00000009u, 0x0000000bu, 0x0000000du,
    0x00000010u, 0x00040047u, 0x00000009u, 0x0000001eu, 0x00000000u, 0x00040047u,
    0x0000000bu, 0x0000001eu, 0x00000001u, 0x00040047u, 0x0000000du, 0x0000001eu,
    0x00000000u, 0x00030047u, 0x0000000eu, 0x00000002u, 0x00050048u, 0x0000000eu,
    0x00000000u, 0x0000000bu, 0x00000000u, 0x00020013u, 0x00000002u, 0x00030021u,
    0x00000003u, 0x00000002u, 0x00030016u, 0x00000004u, 0x00000020u, 0x00040017u,
    0x00000005u, 0x00000004u, 0x00000002u, 0x00040017u, 0x00000006u, 0x00000004u,
    0x00000004u, 0x00040015u, 0x00000007u, 0x00000020u, 0x00000001u, 0x00040020u,
    0x00000008u, 0x00000001u, 0x00000005u, 0x0004003bu, 0x00000008u, 0x00000009u,
    0x00000001u, 0x00040020u, 0x0000000au, 0x00000001u, 0x00000006u, 0x0004003bu,
    0x0000000au, 0x0000000bu, 0x00000001u, 0x00040020u, 0x0000000cu, 0x00000003u,
    0x00000006u, 0x0004003bu, 0x0000000cu, 0x0000000du, 0x00000003u, 0x0003001eu,
    0x0000000eu, 0x00000006u, 0x00040020u, 0x0000000fu, 0x00000003u, 0x0000000eu,
    0x0004003bu, 0x0000000fu, 0x00000010u, 0x00000003u, 0x0004002bu, 0x00000007u,
    0x00000011u, 0x00000000u, 0x0004002bu, 0x00000004u, 0x00000012u, 0x00000000u,
    0x0004002bu, 0x00000004u, 0x00000013u, 0x3f800000u, 0x00050036u, 0x00000002u,
    0x00000001u, 0x00000000u, 0x00000003u, 0x000200f8u, 0x00000014u, 0x0004003du,
    0x00000005u, 0x00000015u, 0x00000009u, 0x0004003du, 0x00000006u, 0x00000016u,
    0x0000000bu, 0x0003003eu, 0x0000000du, 0x00000016u, 0x00050051u, 0x00000004u,
    0x00000017u, 0x00000015u, 0x00000000u, 0x00050051u, 0x00000004u, 0x00000018u,
    0x00000015u, 0x00000001u, 0x00070050u, 0x00000006u, 0x00000019u, 0x00000017u,
    0x00000018u, 0x00000012u, 0x00000013u, 0x00050041u, 0x0000000cu, 0x0000001au,
    0x00000010u, 0x00000011u, 0x0003003eu, 0x0000001au, 0x00000019u, 0x000100fdu,
    0x00010038u,
}};

// Precompiled SPIR-V 1.0 for apps/viewer/src/vulkan/shaders/passthrough_quad.frag.glsl
inline constexpr std::array<std::uint32_t, 72> kPassthroughQuadFragSpirv{{
    0x07230203u, 0x00010000u, 0x00000000u, 0x0000000cu, 0x00000000u, 0x00020011u,
    0x00000001u, 0x0003000eu, 0x00000000u, 0x00000001u, 0x0007000fu, 0x00000004u,
    0x00000001u, 0x6e69616du, 0x00000000u, 0x00000007u, 0x00000009u, 0x00030010u,
    0x00000001u, 0x00000007u, 0x00040047u, 0x00000007u, 0x0000001eu, 0x00000000u,
    0x00040047u, 0x00000009u, 0x0000001eu, 0x00000000u, 0x00020013u, 0x00000002u,
    0x00030021u, 0x00000003u, 0x00000002u, 0x00030016u, 0x00000004u, 0x00000020u,
    0x00040017u, 0x00000005u, 0x00000004u, 0x00000004u, 0x00040020u, 0x00000006u,
    0x00000001u, 0x00000005u, 0x0004003bu, 0x00000006u, 0x00000007u, 0x00000001u,
    0x00040020u, 0x00000008u, 0x00000003u, 0x00000005u, 0x0004003bu, 0x00000008u,
    0x00000009u, 0x00000003u, 0x00050036u, 0x00000002u, 0x00000001u, 0x00000000u,
    0x00000003u, 0x000200f8u, 0x0000000au, 0x0004003du, 0x00000005u, 0x0000000bu,
    0x00000007u, 0x0003003eu, 0x00000009u, 0x0000000bu, 0x000100fdu, 0x00010038u,
}};

static_assert(validate_spirv_words(kSmokeClearCompSpirv),
              "Embedded clear compute SPIR-V smoke shader must pass constexpr validation");
static_assert(validate_spirv_words(kPassthroughQuadVertSpirv),
              "Embedded passthrough quad vertex SPIR-V smoke shader must pass constexpr validation");
static_assert(validate_spirv_words(kPassthroughQuadFragSpirv),
              "Embedded passthrough quad fragment SPIR-V smoke shader must pass constexpr validation");

} // namespace shaders

} // namespace viewer
