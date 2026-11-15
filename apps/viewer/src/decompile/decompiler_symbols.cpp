#include "decompiler.hpp"
#include <map>
#include <format>
#include <sstream>

namespace viewer {
std::optional<SymbolRecord> containing_function(const peelf::IBinaryImage& image, const SymbolIndex& index,
    std::uint64_t address, const std::optional<SymbolRecord>& fallback) {
    const SymbolRecord* best = nullptr;
    for (const auto& symbol : index.records()) {
        if (!symbol.virtual_address || !symbol_has_code(image,symbol) || symbol.source == SymbolSource::EntryPoint) continue;
        const auto start = *symbol.virtual_address;
        if (address < start || (symbol.size ? address-start >= symbol.size : address != start)) continue;
        if (!best || (symbol.function.value_or(false) && !best->function.value_or(false)) ||
            (symbol.function == best->function && symbol.size > best->size)) best = &symbol;
    }
    if (best) return *best;
    if (image.format() == peelf::Format::PE && image.architecture() == peelf::Architecture::X86_64 && address >= image.image_base()) {
        const auto rva = address-image.image_base();
        for (const auto& runtime : image.pe_runtime_functions()) if (rva >= runtime.begin_address_rva && rva < runtime.end_address_rva) {
            const auto start = image.image_base()+runtime.begin_address_rva;
            return SymbolRecord{.name=std::format("sub_{:X}",start), .virtual_address=start,
                .file_offset=image.virtual_address_to_file_offset(start), .size=runtime.end_address_rva-runtime.begin_address_rva, .function=true};
        }
    }
    if (fallback && fallback->virtual_address && address >= *fallback->virtual_address &&
        (!fallback->size || address-*fallback->virtual_address < fallback->size)) return fallback;
    const auto offset=image.virtual_address_to_file_offset(address);
    if (!offset) return std::nullopt;
    SymbolRecord root{.name=std::format("sub_{:X}",address),.virtual_address=address,.file_offset=offset};
    return symbol_has_code(image,root) ? std::optional(root) : std::nullopt;
}
std::string encode_decompiler_symbols(const DecompileRequest& request) {
    const auto hex=[](std::string_view text) {
        std::string encoded;
        for (unsigned char c : text) encoded += std::format("{:02x}",c);
        return encoded.empty() ? "-" : encoded;
    };
    std::ostringstream out;
    out << "PEELF_SYMBOLS 1\n" << request.address << ' ' << request.function_size << '\n';
    std::map<std::uint64_t,const SymbolRecord*> unique;
    for (const auto& symbol : request.symbols) {
        if (!symbol.virtual_address || symbol.name.empty() || symbol.external) continue;
        auto [it,inserted]=unique.emplace(*symbol.virtual_address,&symbol);
        if (!inserted && (symbol.source == SymbolSource::DebugSymbol || it->second->source == SymbolSource::EntryPoint)) it->second=&symbol;
    }
    out << unique.size() << '\n';
    for (const auto& [address,symbol] : unique)
        out << address << ' ' << symbol->size << ' ' << symbol->function.value_or(false) << ' ' << hex(symbol->name) << '\n';
    out << request.types.size() << '\n';
    for (const auto& type : request.types) {
        out << hex(type.name) << ' ' << type.size << ' ' << type.is_union << ' ' << type.members.size() << '\n';
        for (const auto& member : type.members)
            out << member.offset << ' ' << member.size << ' ' << hex(member.name) << ' ' << hex(member.type) << '\n';
    }
    return out.str();
}
}
