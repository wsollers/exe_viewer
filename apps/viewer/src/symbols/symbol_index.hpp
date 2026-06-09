#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>

namespace viewer {

enum class SymbolSource : std::uint8_t {
    EntryPoint,
    ImageSymbol,
    Import,
    Export
};

struct SymbolRecord {
    std::string name;
    SymbolSource source = SymbolSource::ImageSymbol;
    std::uint64_t source_index = 0;
    std::optional<std::uint64_t> virtual_address;
    std::optional<std::uint64_t> file_offset;
    std::uint64_t size = 0;
    bool dynamic = false;
    bool external = false;
};

class SymbolIndex {
public:
    [[nodiscard]] static SymbolIndex build(const peelf::IBinaryImage& image);

    [[nodiscard]] std::span<const SymbolRecord> records() const noexcept { return records_; }
    [[nodiscard]] bool empty() const noexcept { return records_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }

    [[nodiscard]] const SymbolRecord* find_by_name(std::string_view name) const noexcept;
    [[nodiscard]] const SymbolRecord* find_containing_address(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] const SymbolRecord* find_exact_address(std::uint64_t virtual_address) const noexcept;

private:
    std::vector<SymbolRecord> records_;
};

[[nodiscard]] std::string import_symbol_name(const peelf::ImportEntry& entry);

} // namespace viewer
