#pragma once

#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

enum class FunctionOrigin : std::uint8_t {
    SymbolTable,
    DebugInfo,
    PeRuntimePdata,
    ExportedEntry,
    InitFiniOrTlsCallback,
    EntryPoint,
    CallTargetDiscovery,
};

[[nodiscard]] constexpr std::string_view to_string(FunctionOrigin origin) noexcept {
    switch (origin) {
        case FunctionOrigin::SymbolTable:           return "Symbol Table";
        case FunctionOrigin::DebugInfo:             return "Debug Info (PDB/DWARF)";
        case FunctionOrigin::PeRuntimePdata:        return "PE .pdata Unwind";
        case FunctionOrigin::ExportedEntry:         return "Export";
        case FunctionOrigin::InitFiniOrTlsCallback: return "Init/Fini/TLS Callback";
        case FunctionOrigin::EntryPoint:            return "Entry Point";
        case FunctionOrigin::CallTargetDiscovery:   return "Call Target Analysis";
    }
    return "Function";
}

struct FunctionEntry {
    std::string name;
    std::string raw_name;
    std::string demangled_name;
    std::uint64_t virtual_address{0};
    std::optional<std::uint64_t> file_offset;
    std::uint64_t size{0};
    FunctionOrigin origin{FunctionOrigin::SymbolTable};
    std::string section_name;
    std::string library;
    bool is_thunk{false};

    [[nodiscard]] const std::string& display_name(bool demangle = true) const noexcept {
        if (demangle && !demangled_name.empty()) {
            return demangled_name;
        }
        return !raw_name.empty() ? raw_name : name;
    }

    [[nodiscard]] bool is_demangled() const noexcept {
        const std::string& raw = !raw_name.empty() ? raw_name : name;
        return !demangled_name.empty() && demangled_name != raw;
    }
};

/// Unified multi-source function discovery index across static files and live-rebased modules.
/// Aggregates symbol tables, PDB/DWARF debug symbols, PE `.pdata` runtime functions, exports,
/// TLS / `.init_array` / `.fini_array` callbacks, entry points, and direct `call`/`bl`/`jal`
/// target discovery, and enriches `SymbolIndex` so navigation, CFG, references, stack unwinding,
/// and decompilation all resolve discovered `sub_<VA>` functions seamlessly.
class FunctionIndex {
public:
    [[nodiscard]] static FunctionIndex discover(
        const peelf::IBinaryImage& image,
        SymbolIndex& symbol_index,
        std::span<const std::uint8_t> image_bytes = {},
        bool thumb_mode = false);

    [[nodiscard]] std::span<const FunctionEntry> entries() const noexcept { return entries_; }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

    [[nodiscard]] const FunctionEntry* find_exact(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] const FunctionEntry* find_containing(std::uint64_t virtual_address) const noexcept;

private:
    std::vector<FunctionEntry> entries_;
};

}  // namespace viewer
