#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "disasm/disassembler.hpp"
#include "graph/call_graph.hpp"
#include "model/binary_model.hpp"

namespace viewer {

struct PatchPreview {
    std::uint64_t offset{};
    std::uint64_t revision{};
    std::vector<std::uint8_t> replacement{};
    CallGraph before{};
    CallGraph after{};
    std::string boundary{};
    std::optional<std::uint64_t> virtual_address{};
    std::vector<std::uint8_t> original_bytes{};
    std::vector<Instruction> replacement_disassembly{};
    std::vector<Instruction> overwritten_instructions{};
    bool misaligns_instruction_boundary{false};
    std::uint64_t trailing_slack_bytes{0};
    std::string boundary_warning{};
    std::optional<std::string> asm_source{};
    std::string label{"Reviewed byte replacement"};
    std::string note{};
};

[[nodiscard]] std::vector<Instruction> disassemble_patch_bytes(
    std::span<const std::uint8_t> bytes,
    std::uint64_t base_address,
    peelf::Architecture arch,
    peelf::Endianness endian,
    bool thumb = false);

[[nodiscard]] peelf::Result<PatchPreview> preview_patch(
    const BinaryModel& model,
    const SymbolIndex& symbols,
    std::uint64_t offset,
    std::span<const std::uint8_t> replacement,
    bool thumb = false);

[[nodiscard]] peelf::Result<PatchPreview> preview_assembly_patch(
    const BinaryModel& model,
    const SymbolIndex& symbols,
    std::uint64_t offset,
    std::string_view asm_text,
    bool thumb = false,
    bool pad_nops_to_boundary = false);

[[nodiscard]] peelf::Result<void> apply_preview(BinaryModel& model, const PatchPreview& preview);
[[nodiscard]] std::string patch_report(const BinaryModel& model);

} // namespace viewer
