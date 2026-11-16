#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <peelf/binary_image.hpp>

namespace viewer {

enum class SymbolSource : std::uint8_t {
    EntryPoint,
    ImageSymbol,
    Import,
    Export,
    DebugSymbol
};

struct DebugSymbol {
    std::string name{};
    std::uint64_t relative_virtual_address = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t size = 0;
    bool function = false;
    std::string library{};
};

struct SymbolRecord {
    std::string name{};
    std::string raw_name{};
    std::string demangled_name{};
    SymbolSource source = SymbolSource::ImageSymbol;
    std::uint64_t source_index = 0;
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> file_offset{};
    std::uint64_t size = 0;
    bool dynamic = false;
    bool external = false;
    bool heuristic_discovered = false;
    // Known PDB/DWARF classification; other symbol formats use executable section membership.
    std::optional<bool> function{};
    std::string library{};

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

class SymbolIndex {
public:
    [[nodiscard]] static SymbolIndex build(const peelf::IBinaryImage& image);
    void add_debug_symbols(const peelf::IBinaryImage& image, std::span<const DebugSymbol> symbols);
    void add_discovered_symbol(SymbolRecord record);

    [[nodiscard]] std::span<const SymbolRecord> records() const noexcept { return records_; }
    [[nodiscard]] bool empty() const noexcept { return records_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
    [[nodiscard]] std::vector<std::string> libraries() const;

    [[nodiscard]] const SymbolRecord* find_by_name(std::string_view name) const noexcept;
    [[nodiscard]] const SymbolRecord* find_containing_address(std::uint64_t virtual_address) const;
    [[nodiscard]] const SymbolRecord* find_exact_address(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] const SymbolRecord* find_nearest_preceding_address(std::uint64_t virtual_address,
                                                                     std::uint64_t max_distance) const;

private:
    struct AddressSpan {
        std::uint64_t start{0};
        std::uint64_t end{0};
        std::uint64_t max_end_prefix{0};
        std::size_t record_index{0};
    };

    void push_record(SymbolRecord record);
    void ensure_address_spans() const;

    std::vector<SymbolRecord> records_;
    std::unordered_map<std::uint64_t, std::size_t> first_by_exact_va_;
    mutable std::vector<AddressSpan> sorted_spans_;
    mutable bool spans_dirty_{true};
};

[[nodiscard]] std::string import_symbol_name(const peelf::ImportEntry& entry);
[[nodiscard]] bool symbol_has_code(const peelf::IBinaryImage& image, const SymbolRecord& symbol) noexcept;
[[nodiscard]] inline bool symbol_name_matches(std::string_view name, std::string_view query) noexcept {
    const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; };
    if (query.size() > name.size()) return false;
    for (std::size_t i = 0; i <= name.size() - query.size(); ++i) {
        bool matches = true;
        for (std::size_t j = 0; j < query.size(); ++j)
            if (lower(name[i + j]) != lower(query[j])) { matches = false; break; }
        if (matches) return true;
    }
    return false;
}
[[nodiscard]] const char* to_string(SymbolSource source) noexcept;

} // namespace viewer
