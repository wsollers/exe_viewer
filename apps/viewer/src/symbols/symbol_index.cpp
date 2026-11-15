#include "symbols/symbol_index.hpp"

#include <algorithm>
#include <limits>
#include <string>
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

[[nodiscard]] bool is_elf_mapping_symbol(std::string_view name) noexcept {
    return name.starts_with("$a") || name.starts_with("$d") ||
           name.starts_with("$t") || name.starts_with("$x");
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

[[nodiscard]] const peelf::Section* executable_section_containing(const peelf::IBinaryImage& image,
                                                                  std::uint64_t virtual_address) noexcept {
    for (const peelf::Section& section : image.sections()) {
        if (!section.executable) {
            continue;
        }
        const std::uint64_t mapped_size = section.virtual_size != 0 ? section.virtual_size : section.file_size;
        if (mapped_size == 0) {
            continue;
        }
        if (virtual_address >= section.virtual_address &&
            virtual_address - section.virtual_address < mapped_size) {
            return &section;
        }
    }
    return nullptr;
}

[[nodiscard]] bool section_contains(const peelf::Section& section, std::uint64_t virtual_address) noexcept {
    const std::uint64_t mapped_size = section.virtual_size != 0 ? section.virtual_size : section.file_size;
    return mapped_size != 0 &&
           virtual_address >= section.virtual_address &&
           virtual_address - section.virtual_address < mapped_size;
}

[[nodiscard]] std::uint64_t recover_pe_function_size(const peelf::IBinaryImage& image,
                                                     std::uint64_t virtual_address,
                                                     std::uint64_t fallback_size = 0) noexcept {
    if (image.format() != peelf::Format::PE || virtual_address < image.image_base()) {
        return fallback_size;
    }

    const std::uint64_t rva = virtual_address - image.image_base();
    for (const peelf::PeRuntimeFunction& function : image.pe_runtime_functions()) {
        if (rva >= function.begin_address_rva && rva < function.end_address_rva) {
            return function.end_address_rva - rva;
        }
    }

    for (const peelf::Symbol& symbol : image.symbols()) {
        if (symbol.virtual_address == virtual_address && symbol.size != 0) {
            return symbol.size;
        }
    }

    const peelf::Section* section = executable_section_containing(image, virtual_address);
    if (section == nullptr) {
        return fallback_size;
    }

    std::uint64_t nearest_after = 0;
    for (const peelf::Symbol& symbol : image.symbols()) {
        if (symbol.virtual_address <= virtual_address || !section_contains(*section, symbol.virtual_address)) {
            continue;
        }
        if (nearest_after == 0 || symbol.virtual_address < nearest_after) {
            nearest_after = symbol.virtual_address;
        }
    }
    for (const peelf::ExportEntry& exported : image.exports()) {
        if (exported.virtual_address <= virtual_address || !section_contains(*section, exported.virtual_address)) {
            continue;
        }
        if (nearest_after == 0 || exported.virtual_address < nearest_after) {
            nearest_after = exported.virtual_address;
        }
    }

    return nearest_after > virtual_address ? nearest_after - virtual_address : fallback_size;
}

[[nodiscard]] std::uint64_t exclusive_end(std::uint64_t start, std::uint64_t size) noexcept {
    const std::uint64_t norm = normalized_size(size);
    if (start > std::numeric_limits<std::uint64_t>::max() - norm) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return start + norm;
}

} // namespace

void SymbolIndex::push_record(SymbolRecord record) {
    if (record.name.empty() || is_elf_mapping_symbol(record.name)) {
        return;
    }
    const std::size_t idx = records_.size();
    if (record.virtual_address.has_value()) {
        first_by_exact_va_.try_emplace(*record.virtual_address, idx);
    }
    records_.push_back(std::move(record));
    spans_dirty_ = true;
}

void SymbolIndex::ensure_address_spans() const {
    if (!spans_dirty_) {
        return;
    }
    sorted_spans_.clear();
    sorted_spans_.reserve(records_.size());
    for (std::size_t i = 0; i < records_.size(); ++i) {
        const SymbolRecord& rec = records_[i];
        if (!rec.virtual_address.has_value()) {
            continue;
        }
        const std::uint64_t s = *rec.virtual_address;
        sorted_spans_.push_back(AddressSpan{
            .start = s,
            .end = exclusive_end(s, rec.size),
            .max_end_prefix = 0,
            .record_index = i,
        });
    }
    std::ranges::sort(sorted_spans_, [](const AddressSpan& a, const AddressSpan& b) noexcept {
        if (a.start != b.start) {
            return a.start < b.start;
        }
        return a.record_index < b.record_index;
    });
    std::uint64_t running_max = 0;
    for (AddressSpan& sp : sorted_spans_) {
        if (sp.end > running_max) {
            running_max = sp.end;
        }
        sp.max_end_prefix = running_max;
    }
    spans_dirty_ = false;
}

std::string import_symbol_name(const peelf::ImportEntry& entry) {
    const std::string import_name = entry.import_by_ordinal
        ? "#" + std::to_string(entry.ordinal)
        : entry.name;
    if (entry.library.empty()) {
        return import_name.empty() ? "<import>" : import_name;
    }
    if (import_name.empty()) {
        return entry.library;
    }
    return entry.library + "!" + import_name;
}

bool symbol_has_code(const peelf::IBinaryImage& image, const SymbolRecord& symbol) noexcept {
    if (symbol.source == SymbolSource::Import || !symbol.file_offset || !symbol.virtual_address)
        return false;
    if (symbol.function) return *symbol.function;
    return executable_section_containing(image, *symbol.virtual_address) != nullptr;
}

const char* to_string(SymbolSource source) noexcept {
    switch (source) {
        case SymbolSource::EntryPoint:  return "entry";
        case SymbolSource::ImageSymbol: return "symbol";
        case SymbolSource::Import:      return "import";
        case SymbolSource::Export:      return "export";
        case SymbolSource::DebugSymbol: return "pdb";
    }
    return "symbol";
}

SymbolIndex SymbolIndex::build(const peelf::IBinaryImage& image) {
    SymbolIndex index;
    const std::size_t est = 1u + image.symbols().size() + image.imports().size() + image.exports().size();
    index.records_.reserve(est);
    index.first_by_exact_va_.reserve(est);

    const std::uint64_t entry = image.entry_point();
    index.push_record(SymbolRecord{
        .name = "Entry Point",
        .source = SymbolSource::EntryPoint,
        .virtual_address = entry,
        .file_offset = image.virtual_address_to_file_offset(entry),
        .size = 1,
        .function = std::nullopt,
        .library = {},
    });

    for (std::uint64_t i = 0; i < image.symbols().size(); ++i) {
        const peelf::Symbol& symbol = image.symbols()[static_cast<std::size_t>(i)];
        index.push_record(SymbolRecord{
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
            .function = std::nullopt,
            .library = {},
        });
    }

    for (std::uint64_t i = 0; i < image.exports().size(); ++i) {
        const peelf::ExportEntry& entry_record = image.exports()[static_cast<std::size_t>(i)];
        index.push_record(SymbolRecord{
            .name = entry_record.name.empty() ? "<export>" : entry_record.name,
            .source = SymbolSource::Export,
            .source_index = i,
            .virtual_address = entry_record.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                                 : std::optional(entry_record.virtual_address),
            .file_offset = entry_record.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                            : image.virtual_address_to_file_offset(entry_record.virtual_address),
            .size = entry_record.virtual_address == 0 ? 0 : recover_pe_function_size(image, entry_record.virtual_address),
            .function = std::nullopt,
            .library = {},
        });
    }

    for (std::uint64_t i = 0; i < image.imports().size(); ++i) {
        const peelf::ImportEntry& import = image.imports()[static_cast<std::size_t>(i)];
        index.push_record(SymbolRecord{
            .name = import_symbol_name(import),
            .source = SymbolSource::Import,
            .source_index = i,
            .virtual_address = import.address == 0 ? std::optional<std::uint64_t>{} : std::optional(import.address),
            .file_offset = import.address == 0 ? std::optional<std::uint64_t>{}
                                               : image.virtual_address_to_file_offset(import.address),
            .size = image.is_64bit() ? 8u : 4u,
            .dynamic = true,
            .external = true,
            .function = std::nullopt,
            .library = import.library,
        });
    }

    if (image.format() == peelf::Format::ELF && !image.elf_relocations().empty()) {
        std::vector<const peelf::ElfSymbol*> dynsyms;
        for (const peelf::ElfSymbol& es : image.elf_symbols()) {
            if (es.dynamic) {
                dynsyms.push_back(&es);
            }
        }
        if (!dynsyms.empty()) {
            const std::uint64_t slot_size = image.is_64bit() ? 8u : 4u;
            for (std::uint64_t rel_idx = 0; rel_idx < image.elf_relocations().size(); ++rel_idx) {
                const peelf::ElfRelocation& rel =
                    image.elf_relocations()[static_cast<std::size_t>(rel_idx)];
                if (rel.offset == 0 || rel.symbol_index == 0 ||
                    rel.symbol_index >= dynsyms.size()) {
                    continue;
                }
                const peelf::ElfSymbol& sym = *dynsyms[static_cast<std::size_t>(rel.symbol_index)];
                if (sym.name.empty()) {
                    continue;
                }
                if (index.find_exact_address(rel.offset) != nullptr) {
                    continue;
                }
                index.push_record(SymbolRecord{
                    .name = sym.name,
                    .source = SymbolSource::Import,
                    .source_index = image.imports().size() + rel_idx,
                    .virtual_address = rel.offset,
                    .file_offset = image.virtual_address_to_file_offset(rel.offset),
                    .size = slot_size,
                    .dynamic = true,
                    .external = true,
                    .function = std::nullopt,
                    .library = {},
                });
            }
        }
    }

    return index;
}

void SymbolIndex::add_debug_symbols(const peelf::IBinaryImage& image, std::span<const DebugSymbol> symbols) {
    records_.reserve(records_.size() + symbols.size());
    for (std::uint64_t i = 0; i < symbols.size(); ++i) {
        const DebugSymbol& symbol = symbols[static_cast<std::size_t>(i)];
        push_record(SymbolRecord{
            .name = symbol.name,
            .source = SymbolSource::DebugSymbol,
            .source_index = i,
            .virtual_address = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                           : std::optional(symbol.virtual_address),
            .file_offset = symbol.virtual_address == 0 ? std::optional<std::uint64_t>{}
                                                       : image.virtual_address_to_file_offset(symbol.virtual_address),
            .size = symbol.function && symbol.size == 0 && symbol.virtual_address != 0
                         ? recover_pe_function_size(image, symbol.virtual_address)
                         : symbol.size,
            .dynamic = false,
            .external = symbol.virtual_address == 0,
            .function = symbol.function,
            .library = symbol.library,
        });
    }
}

void SymbolIndex::add_discovered_symbol(SymbolRecord record) {
    if (record.virtual_address && find_exact_address(*record.virtual_address) != nullptr) {
        return;
    }
    push_record(std::move(record));
}

std::vector<std::string> SymbolIndex::libraries() const {
    std::vector<std::string> result;
    for (const auto& record : records_) if (!record.library.empty()) result.push_back(record.library);
    std::ranges::sort(result);
    result.erase(std::ranges::unique(result).begin(), result.end());
    return result;
}

const SymbolRecord* SymbolIndex::find_by_name(std::string_view name) const noexcept {
    const auto it = std::ranges::find_if(records_, [&](const SymbolRecord& record) {
        return record.name == name;
    });
    return it == records_.end() ? nullptr : &*it;
}

const SymbolRecord* SymbolIndex::find_exact_address(std::uint64_t virtual_address) const noexcept {
    const auto it = first_by_exact_va_.find(virtual_address);
    if (it == first_by_exact_va_.end() || it->second >= records_.size()) {
        return nullptr;
    }
    return &records_[it->second];
}

const SymbolRecord* SymbolIndex::find_containing_address(std::uint64_t virtual_address) const noexcept {
    ensure_address_spans();
    if (sorted_spans_.empty()) {
        return nullptr;
    }

    const auto hi = std::ranges::upper_bound(sorted_spans_, virtual_address, {}, &AddressSpan::start);
    std::size_t idx = static_cast<std::size_t>(hi - sorted_spans_.begin());
    std::vector<std::size_t> candidates;
    while (idx > 0) {
        --idx;
        const AddressSpan& sp = sorted_spans_[idx];
        if (sp.max_end_prefix <= virtual_address) {
            break;
        }
        if (contains_address(records_[sp.record_index], virtual_address)) {
            candidates.push_back(sp.record_index);
        }
    }
    if (candidates.empty()) {
        return nullptr;
    }
    std::ranges::sort(candidates);
    const SymbolRecord* best = nullptr;
    for (const std::size_t rec_idx : candidates) {
        const SymbolRecord& record = records_[rec_idx];
        if (best == nullptr || is_better_address_match(record, *best)) {
            best = &record;
        }
    }
    return best;
}

const SymbolRecord* SymbolIndex::find_nearest_preceding_address(std::uint64_t virtual_address,
                                                                std::uint64_t max_distance) const noexcept {
    ensure_address_spans();
    if (sorted_spans_.empty()) {
        return nullptr;
    }

    const auto hi = std::ranges::upper_bound(sorted_spans_, virtual_address, {}, &AddressSpan::start);
    if (hi == sorted_spans_.begin()) {
        return nullptr;
    }

    std::size_t idx = static_cast<std::size_t>(hi - sorted_spans_.begin()) - 1u;
    const std::uint64_t nearest_start = sorted_spans_[idx].start;
    const std::uint64_t best_distance = virtual_address - nearest_start;
    if (best_distance > max_distance) {
        return nullptr;
    }

    std::vector<std::size_t> candidates;
    while (true) {
        if (sorted_spans_[idx].start != nearest_start) {
            break;
        }
        candidates.push_back(sorted_spans_[idx].record_index);
        if (idx == 0) {
            break;
        }
        --idx;
    }
    std::ranges::sort(candidates);
    const SymbolRecord* best = nullptr;
    for (const std::size_t rec_idx : candidates) {
        const SymbolRecord& record = records_[rec_idx];
        if (best == nullptr || is_better_address_match(record, *best)) {
            best = &record;
        }
    }
    return best;
}

} // namespace viewer
