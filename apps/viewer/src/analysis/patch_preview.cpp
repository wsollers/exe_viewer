#include "patch_preview.hpp"
#include <algorithm>
#include <format>
#include <sstream>

namespace viewer {
peelf::Result<PatchPreview> preview_patch(const BinaryModel& model, const SymbolIndex& symbols,
    std::uint64_t offset, std::span<const std::uint8_t> replacement, bool thumb) {
    if (!model.image() || replacement.empty() || offset >= model.bytes().size() ||
        replacement.size() > model.bytes().size() - offset) return peelf::make_error("Replacement is outside the file");
    PatchPreview preview{offset, model.edit_revision(), {replacement.begin(), replacement.end()}};
    const auto& image = *model.image();
    const auto address = image.file_offset_to_virtual_address(offset);
    if (!address) { preview.boundary = "Raw data: no mapped instruction address"; return preview; }
    SymbolRecord root{.name = "Patch preview", .virtual_address = address, .file_offset = offset};
    if (const auto* symbol = symbols.find_containing_address(*address); symbol && symbol_has_code(image, *symbol)) root = *symbol;
    auto extent = discover_function_extent(image, symbols, root, model.bytes().size());
    if (!extent) { preview.boundary = "Data region: instruction preview unavailable"; return preview; }
    if (offset < extent->file_offset || replacement.size() > extent->size ||
        offset - extent->file_offset > extent->size - replacement.size())
        return peelf::make_error("Patch crosses the analyzed function boundary; split the replacement");
    auto bytes = model.read_effective_bytes(extent->file_offset, extent->size);
    if (!bytes) return std::unexpected(bytes.error());
    preview.boundary = std::string(function_extent_source_name(extent->source));
    if (extent->source == FunctionExtentSource::ExecutableRegion)
        preview.boundary += "; instruction alignment is assumed at the selected address";
    preview.before = build_function_cfg_call_graph(*bytes, extent->virtual_address, image.architecture(),
        image.endianness(), extent->file_offset, root.name, thumb, true);
    std::ranges::copy(replacement, bytes->begin() + static_cast<std::ptrdiff_t>(offset - extent->file_offset));
    preview.after = build_function_cfg_call_graph(*bytes, extent->virtual_address, image.architecture(),
        image.endianness(), extent->file_offset, root.name, thumb, true);
    return preview;
}
peelf::Result<void> apply_preview(BinaryModel& model, const PatchPreview& preview) {
    if (model.edit_revision() != preview.revision) return peelf::make_error("Preview is stale; preview the current bytes again");
    return model.apply_patch_bytes(preview.offset, preview.replacement, "Reviewed byte replacement");
}
std::string patch_report(const BinaryModel& model) {
    std::ostringstream out;
    out << "PE/ELF patch change report\nSource: " << model.file_info().path << "\nArchitecture: " << model.file_info().arch_str << "\n";
    for (const auto& patch : model.changed_intervals()) {
        out << std::format("\nOffset: 0x{:X}  Size: {}", patch.offset, patch.patched.size());
        if (model.image()) if (auto va = model.image()->file_offset_to_virtual_address(patch.offset)) out << std::format("  VA: 0x{:X}", *va);
        out << "\nOriginal:";
        for (auto b : patch.original) out << std::format(" {:02X}", b);
        out << "\nReplacement:";
        for (auto b : patch.patched) out << std::format(" {:02X}", b);
        out << '\n';
    }
    return out.str();
}
}
