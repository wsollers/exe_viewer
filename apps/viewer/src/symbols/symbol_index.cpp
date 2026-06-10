#include "symbols/symbol_index.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace viewer {
namespace {

[[nodiscard]] std::uint64_t normalized_size(std::uint64_t size) noexcept {
    return size == 0 ? 1u : size;
}

[[nodiscard]] bool contains_address(const SymbolRecord& record, std::uint64_t virtual_address) noexcept {
    if (!record.virtual_address) {
        return false;
    }
    const std::uint64_t start = *record.virtual_address;
    const std::uint64_t size = normalized_size(record.size);
    if (start > std::numeric_limits<std::uint64_t>::max() - size) {
        return virtual_address == start;
    }
    return virtual_address >= start && virtual_address < start + size;
}

[[nodiscard]] std::uint8_t source_rank(SymbolSource source) noexcept {
    switch (source) {
        case SymbolSource::ImageSymbol:
            return 0;
        case SymbolSource::DebugSymbol:
            return 0;
        case SymbolSource::Export:
            return 1;
        case SymbolSource::EntryPoint:
            return 2;
        case SymbolSource::Import:
            return 3;
    }
    return 4;
}

[[nodiscard]] bool is_better_address_match(const SymbolRecord& candidate, const SymbolRecord& current) noexcept {
    const std::uint8_t candidate_rank = source_rank(candidate.source);
    const std::uint8_t current_rank = source_rank(current.source);
    if (candidate_rank != current_rank) {
        return candidate_rank < current_rank;
    }
    return normalized_size(candidate.size) < normalized_size(current.size);
}

void add_record(std::vector<SymbolRecord>& records, SymbolRecord record) {
    if (record.name.empty()) {
        return;
    }
    records.push_back(std::move(record));
}

} // namespace

std::string import_symbol_name(const peelf::ImportEntry& entry) {
    if (entry.library.empty()) {
        return entry.name.empty() ? "<import>" : entry.name;
    }
    if (entry.name.empty()) {
        return entry.library;
    }
    return entry.library + "!" + entry.name;
}

SymbolIndex SymbolIndex::build(const peelf::IBinaryImage& image) {
    SymbolIndex index;
    index.records_.reserve(1u + image.symbols().size() + image.imports().size() + image.exports().size());

    const std::uint64_t entry = image.entry_point();
    add_record(index.records_, SymbolRecord{
        .name = "Entry Point",
        .source = SymbolSource::EntryPoint,
        .virtual_address = entry,
        .file_offset = image.virtual_address_to_file_offset(entry),
        .size = 1,
    });

    for (std::uint64_t i = 0; i < image.symbols().size(); ++i) {
        const peelf::Symbol& symbol = image.symbols()[static_cast<std::size_t>(i)];
        add_record(index.records_, SymbolRecord{
            .name = symbol.name,
            .source = SymbolSource::ImageSymbol,
            .source_index = i,
            .virtual_address = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                           : std::optional(symbol.virtual_address),
            .file_offset = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                       : image.virtual_address_to_file_offset(symbol.virtual_address),
            .size = symbol.size,
            .dynamic = symbol.dynamic,
            .external = symbol.virtual_address == 0,
        });
    }

    for (std::uint64_t i = 0; i < image.exports().size(); ++i) {
        const peelf::ExportEntry& entry_record = image.exports()[static_cast<std::size_t>(i)];
        add_record(index.records_, SymbolRecord{
            .name = entry_record.name.empty() ? "<export>" : entry_record.name,
            .source = SymbolSource::Export,
            .source_index = i,
            .virtual_address = entry_record.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                                 : std::optional(entry_record.virtual_address),
            .file_offset = entry_record.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                            : image.virtual_address_to_file_offset(entry_record.virtual_address),
            .size = 1,
        });
    }

    for (std::uint64_t i = 0; i < image.imports().size(); ++i) {
        const peelf::ImportEntry& import = image.imports()[static_cast<std::size_t>(i)];
        add_record(index.records_, SymbolRecord{
            .name = import_symbol_name(import),
            .source = SymbolSource::Import,
            .source_index = i,
            .virtual_address = import.address == 0 ? std::optional<std::uint64_t>{} : std::optional(import.address),
            .file_offset = import.address == 0 ? std::optional<std::uint64_t>{}
                                               : image.virtual_address_to_file_offset(import.address),
            .size = image.is_64bit() ? 8u : 4u,
            .dynamic = true,
            .external = true,
        });
    }

    return index;
}

void SymbolIndex::add_debug_symbols(const peelf::IBinaryImage& image, std::span<const DebugSymbol> symbols) {
    records_.reserve(records_.size() + symbols.size());
    for (std::uint64_t i = 0; i < symbols.size(); ++i) {
        const DebugSymbol& symbol = symbols[static_cast<std::size_t>(i)];
        add_record(records_, SymbolRecord{
            .name = symbol.name,
            .source = SymbolSource::DebugSymbol,
            .source_index = i,
            .virtual_address = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                           : std::optional(symbol.virtual_address),
            .file_offset = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                       : image.virtual_address_to_file_offset(symbol.virtual_address),
            .size = symbol.size,
            .dynamic = false,
            .external = symbol.virtual_address == 0,
        });
    }
}

const SymbolRecord* SymbolIndex::find_by_name(std::string_view name) const noexcept {
    const auto it = std::ranges::find_if(records_, [&](const SymbolRecord& record) {
        return record.name == name;
    });
    return it == records_.end() ? nullptr : &*it;
}

const SymbolRecord* SymbolIndex::find_exact_address(std::uint64_t virtual_address) const noexcept {
    const auto it = std::ranges::find_if(records_, [&](const SymbolRecord& record) {
        return record.virtual_address && *record.virtual_address == virtual_address;
    });
    return it == records_.end() ? nullptr : &*it;
}

const SymbolRecord* SymbolIndex::find_containing_address(std::uint64_t virtual_address) const noexcept {
    const SymbolRecord* best = nullptr;
    for (const SymbolRecord& record : records_) {
        if (!contains_address(record, virtual_address)) {
            continue;
        }
        if (best == nullptr || is_better_address_match(record, *best)) {
            best = &record;
        }
    }
    return best;
}

const SymbolRecord* SymbolIndex::find_nearest_preceding_address(std::uint64_t virtual_address,
                                                                std::uint64_t max_distance) const noexcept {
    const SymbolRecord* best = nullptr;
    std::uint64_t best_distance = max_distance + (max_distance == std::numeric_limits<std::uint64_t>::max() ? 0u : 1u);
    for (const SymbolRecord& record : records_) {
        if (!record.virtual_address || *record.virtual_address > virtual_address) {
            continue;
        }
        const std::uint64_t distance = virtual_address - *record.virtual_address;
        if (distance > max_distance) {
            continue;
        }
        if (best == nullptr || distance < best_distance ||
            (distance == best_distance && is_better_address_match(record, *best))) {
            best = &record;
            best_distance = distance;
        }
    }
    return best;
}

} // namespace viewer
