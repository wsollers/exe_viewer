#include "patch_preview.hpp"

#include <peelf/assembler.hpp>

#include <algorithm>
#include <format>
#include <optional>
#include <sstream>

namespace viewer {

namespace {

[[nodiscard]] std::optional<Architecture> to_disasm_architecture(peelf::Architecture arch) noexcept {
    switch (arch) {
        case peelf::Architecture::X86:       return Architecture::X86_32;
        case peelf::Architecture::X86_64:    return Architecture::X86_64;
        case peelf::Architecture::ARM:       return Architecture::ARM32;
        case peelf::Architecture::ARM64:     return Architecture::ARM64;
        case peelf::Architecture::MIPS32:    return Architecture::MIPS32;
        case peelf::Architecture::MIPS64:    return Architecture::MIPS64;
        case peelf::Architecture::PowerPC:   return Architecture::PowerPC32;
        case peelf::Architecture::PowerPC64: return Architecture::PowerPC64;
        case peelf::Architecture::RISCV32:   return Architecture::RISCV32;
        case peelf::Architecture::RISCV64:   return Architecture::RISCV64;
        case peelf::Architecture::Unknown:   return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] Endianness to_disasm_endianness(peelf::Endianness endian) noexcept {
    return endian == peelf::Endianness::Big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] std::vector<std::uint8_t> nop_pattern_for_target(peelf::Architecture arch,
                                                               peelf::Endianness endian,
                                                               bool thumb) {
    switch (arch) {
        case peelf::Architecture::X86:
        case peelf::Architecture::X86_64:
            return {0x90u};
        case peelf::Architecture::ARM64:
            return endian == peelf::Endianness::Big
                       ? std::vector<std::uint8_t>{0xD5u, 0x03u, 0x20u, 0x1Fu}
                       : std::vector<std::uint8_t>{0x1Fu, 0x20u, 0x03u, 0xD5u};
        case peelf::Architecture::ARM:
            if (thumb) {
                return endian == peelf::Endianness::Big
                           ? std::vector<std::uint8_t>{0xBFu, 0x00u}
                           : std::vector<std::uint8_t>{0x00u, 0xBFu};
            }
            return endian == peelf::Endianness::Big
                       ? std::vector<std::uint8_t>{0xE3u, 0x20u, 0xF0u, 0x00u}
                       : std::vector<std::uint8_t>{0x00u, 0xF0u, 0x20u, 0xE3u};
        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:
            return {0x13u, 0x00u, 0x00u, 0x00u};
        default:
            return {};
    }
}

void analyze_overwritten_boundaries(PatchPreview& preview,
                                    std::span<const Instruction> before_insns) {
    if (!preview.virtual_address.has_value() || preview.replacement.empty()) {
        return;
    }
    const std::uint64_t patch_start = *preview.virtual_address;
    const std::uint64_t patch_end = patch_start + static_cast<std::uint64_t>(preview.replacement.size());

    std::vector<Instruction> overlapped;
    for (const auto& inst : before_insns) {
        const std::uint64_t inst_start = inst.address;
        const std::uint64_t inst_end = inst_start + static_cast<std::uint64_t>(inst.bytes.size());
        if (inst.bytes.empty()) {
            continue;
        }
        if (inst_start < patch_end && patch_start < inst_end) {
            overlapped.push_back(inst);
        }
    }

    std::ranges::sort(overlapped, [](const Instruction& a, const Instruction& b) {
        return a.address < b.address;
    });
    overlapped.erase(std::unique(overlapped.begin(),
                                 overlapped.end(),
                                 [](const Instruction& a, const Instruction& b) {
                                     return a.address == b.address;
                                 }),
                     overlapped.end());

    preview.overwritten_instructions = std::move(overlapped);
    if (preview.overwritten_instructions.empty()) {
        return;
    }

    const Instruction& first = preview.overwritten_instructions.front();
    const Instruction& last = preview.overwritten_instructions.back();
    const std::uint64_t last_end = last.address + static_cast<std::uint64_t>(last.bytes.size());

    std::vector<std::string> warnings;
    if (first.address < patch_start) {
        preview.misaligns_instruction_boundary = true;
        warnings.push_back(std::format(
            "Patch starts {} byte(s) inside instruction at {:#x} ({})",
            patch_start - first.address,
            first.address,
            first.to_string()));
    }
    if (last_end > patch_end) {
        preview.misaligns_instruction_boundary = true;
        preview.trailing_slack_bytes = last_end - patch_end;
        warnings.push_back(std::format(
            "Replacement ({} B) splits instruction at {:#x} ({}), leaving {} trailing slack byte(s); consider NOP padding",
            preview.replacement.size(),
            last.address,
            last.to_string(),
            preview.trailing_slack_bytes));
    }

    if (!warnings.empty()) {
        std::ostringstream oss;
        for (std::size_t i = 0; i < warnings.size(); ++i) {
            if (i > 0) {
                oss << "; ";
            }
            oss << warnings[i];
        }
        preview.boundary_warning = oss.str();
    }
}

} // namespace

std::vector<Instruction> disassemble_patch_bytes(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_address,
    peelf::Architecture arch,
    peelf::Endianness endian,
    bool thumb) {
    if (bytes.empty()) {
        return {};
    }
    const auto dis_arch = to_disasm_architecture(arch);
    if (!dis_arch.has_value()) {
        return {};
    }
    Disassembler dis;
    if (!dis.init(*dis_arch, to_disasm_endianness(endian))) {
        return {};
    }
    if (*dis_arch == Architecture::ARM32) {
        (void)dis.set_thumb_mode(thumb);
    }
    return dis.disassemble(bytes.data(), bytes.size(), base_address);
}

peelf::Result<PatchPreview> preview_patch(const BinaryModel& model, const SymbolIndex& symbols,
    std::uint64_t offset, std::span<const std::uint8_t> replacement, bool thumb) {
    if (model.is_live_process()) {
        return peelf::make_error(
            "Live process inspection is strictly read-only; byte patches cannot be previewed or staged on live processes");
    }
    if (!model.image() || replacement.empty() || offset >= model.bytes().size() ||
        replacement.size() > model.bytes().size() - offset) return peelf::make_error("Replacement is outside the file");

    PatchPreview preview;
    preview.offset = offset;
    preview.revision = model.edit_revision();
    preview.replacement.assign(replacement.begin(), replacement.end());

    if (auto orig = model.read_effective_bytes(offset, replacement.size()); orig.has_value()) {
        preview.original_bytes = std::move(*orig);
    }

    const auto& image = *model.image();
    const auto address = image.file_offset_to_virtual_address(offset);
    preview.virtual_address = address;
    preview.replacement_disassembly = disassemble_patch_bytes(
        replacement,
        address.value_or(offset),
        image.architecture(),
        image.endianness(),
        thumb);

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
    const std::vector<Instruction> before_linear = disassemble_patch_bytes(
        *bytes,
        extent->virtual_address,
        image.architecture(),
        image.endianness(),
        thumb);
    preview.before = build_function_cfg_call_graph(*bytes, extent->virtual_address, image.architecture(),
        image.endianness(), extent->file_offset, root.name, thumb, true);
    std::ranges::copy(replacement, bytes->begin() + static_cast<std::ptrdiff_t>(offset - extent->file_offset));
    preview.after = build_function_cfg_call_graph(*bytes, extent->virtual_address, image.architecture(),
        image.endianness(), extent->file_offset, root.name, thumb, true);

    analyze_overwritten_boundaries(preview, before_linear);
    return preview;
}

peelf::Result<PatchPreview> preview_assembly_patch(
    const BinaryModel& model,
    const SymbolIndex& symbols,
    std::uint64_t offset,
    std::string_view asm_text,
    bool thumb,
    bool pad_nops_to_boundary) {
    if (model.is_live_process()) {
        return peelf::make_error(
            "Live process inspection is strictly read-only; assembly patches cannot be staged on live processes");
    }
    if (!model.image()) {
        return peelf::make_error("No static binary image is loaded");
    }
    if (offset >= model.bytes().size()) {
        return peelf::make_error("Selected patch offset is outside the file");
    }

    const auto& image = *model.image();
    const std::uint64_t base_va = image.file_offset_to_virtual_address(offset).value_or(offset);
    auto assembled = peelf::assemble_instructions(
        image.architecture(),
        image.endianness(),
        image.is_64bit(),
        thumb,
        base_va,
        asm_text);
    if (!assembled.has_value()) {
        return std::unexpected(assembled.error());
    }
    if (assembled->bytes.empty()) {
        return peelf::make_error("Assembly produced 0 encoded bytes");
    }

    std::vector<std::uint8_t> replacement = std::move(assembled->bytes);
    auto preview_res = preview_patch(model, symbols, offset, replacement, thumb);
    if (!preview_res.has_value()) {
        return preview_res;
    }

    if (pad_nops_to_boundary && preview_res->trailing_slack_bytes > 0) {
        const std::vector<std::uint8_t> nop =
            nop_pattern_for_target(image.architecture(), image.endianness(), thumb);
        if (!nop.empty() && (preview_res->trailing_slack_bytes % nop.size()) == 0u) {
            const std::size_t count =
                static_cast<std::size_t>(preview_res->trailing_slack_bytes) / nop.size();
            for (std::size_t i = 0; i < count; ++i) {
                replacement.insert(replacement.end(), nop.begin(), nop.end());
            }
            auto padded = preview_patch(model, symbols, offset, replacement, thumb);
            if (padded.has_value()) {
                preview_res = std::move(padded);
            }
        }
    }

    preview_res->asm_source = std::string(asm_text);
    preview_res->label = std::format("Assembly patch @ {:#x} ({})", base_va, assembled->provider_name);
    return preview_res;
}

peelf::Result<void> apply_preview(BinaryModel& model, const PatchPreview& preview) {
    if (model.is_live_process()) {
        return peelf::make_error("Live process inspection is strictly read-only");
    }
    if (model.edit_revision() != preview.revision) return peelf::make_error("Preview is stale; preview the current bytes again");
    const std::string label = preview.label.empty() ? "Reviewed byte replacement" : preview.label;
    auto applied = model.apply_patch_bytes(preview.offset, preview.replacement, label);
    if (applied.has_value()) {
        model.record_patch_metadata(preview.offset, label, preview.asm_source);
    }
    return applied;
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

} // namespace viewer
