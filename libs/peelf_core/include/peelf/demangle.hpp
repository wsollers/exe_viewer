#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace peelf {

enum class ManglingScheme : std::uint8_t {
    None,
    Itanium,
    RustV0,
    RustLegacy,
    Msvc,
};

[[nodiscard]] constexpr std::string_view to_string(ManglingScheme scheme) noexcept {
    switch (scheme) {
    case ManglingScheme::None:       return "None";
    case ManglingScheme::Itanium:    return "Itanium C++";
    case ManglingScheme::RustV0:     return "Rust v0";
    case ManglingScheme::RustLegacy: return "Rust Legacy";
    case ManglingScheme::Msvc:       return "MSVC C++";
    }
    return "None";
}

struct DemangleResult {
    std::string demangled{};
    ManglingScheme scheme = ManglingScheme::None;
    bool succeeded = false;
};

/// Demangles Itanium C++ (`_Z...`), Rust v0 (`_R...`), Rust legacy (`_ZN...17h...E`),
/// and MSVC C++ (`?...`) symbol names with strict input/recursion/output bounds so
/// malformed or adversarial inputs never crash or allocate unbounded memory.
/// Preserves optional `module!` import prefixes and `@plt` / `@VERSION` suffixes.
[[nodiscard]] DemangleResult demangle_symbol(std::string_view raw_name);

/// Convenience wrapper returning the demangled string on success or `raw_name` unchanged.
[[nodiscard]] std::string demangle_or_raw(std::string_view raw_name);

/// Portable in-tree Itanium C++ demangler exposed directly for deterministic cross-platform testing.
[[nodiscard]] DemangleResult demangle_itanium_portable(std::string_view mangled);

} // namespace peelf
