#include "disasm/linear_disassembly.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <format>
#include <limits>
#include <numeric>
#include <utility>

namespace viewer {
namespace {

constexpr std::uint64_t kMaxInsnLookaheadBytes = 16u;
constexpr std::uint64_t kMaxLocalOffscreenBranchDistance = 64u * 1024u;
constexpr std::uint64_t kMaxSourceLineDistance = 32u;
constexpr std::uint16_t kPeMachineArmNt = 0x01C4u;
constexpr std::uint8_t kElfSttFunc = 2u;
constexpr std::uint8_t kElfSttGnuIfunc = 10u;

[[nodiscard]] std::string extract_cross_platform_basename(std::string_view full_path) {
    if (full_path.empty()) {
        return {};
    }
    const std::size_t slash_pos = full_path.find_last_of("/\\");
    if (slash_pos == std::string_view::npos) {
        return std::string(full_path);
    }
    if (slash_pos + 1u >= full_path.size()) {
        return std::string(full_path);
    }
    return std::string(full_path.substr(slash_pos + 1u));
}

[[nodiscard]] bool open_capstone_handle(
    ScopedCsHandle& out_handle,
    Architecture arch,
    Endianness endian,
    bool thumb_mode) noexcept {
    out_handle.reset();

    cs_arch cs_architecture{};
    cs_mode cs_mode_flags{};

    switch (arch) {
        case Architecture::X86_32:
            cs_architecture = CS_ARCH_X86;
            cs_mode_flags = CS_MODE_32;
            break;
        case Architecture::X86_64:
            cs_architecture = CS_ARCH_X86;
            cs_mode_flags = CS_MODE_64;
            break;
        case Architecture::ARM32:
            cs_architecture = CS_ARCH_ARM;
            cs_mode_flags = static_cast<cs_mode>(
                (thumb_mode ? CS_MODE_THUMB : CS_MODE_ARM) |
                (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
            break;
        case Architecture::ARM64:
            cs_architecture = CS_ARCH_ARM64;
            cs_mode_flags = static_cast<cs_mode>(
                endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
            break;
        case Architecture::MIPS32:
            cs_architecture = CS_ARCH_MIPS;
            cs_mode_flags = static_cast<cs_mode>(
                CS_MODE_MIPS32 |
                (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
            break;
        case Architecture::MIPS64:
            cs_architecture = CS_ARCH_MIPS;
            cs_mode_flags = static_cast<cs_mode>(
                CS_MODE_MIPS64 |
                (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
            break;
        case Architecture::PowerPC32:
            cs_architecture = CS_ARCH_PPC;
            cs_mode_flags = static_cast<cs_mode>(
                endian == Endianness::Little ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN);
            break;
        case Architecture::PowerPC64:
            cs_architecture = CS_ARCH_PPC;
            cs_mode_flags = static_cast<cs_mode>(
                CS_MODE_64 |
                (endian == Endianness::Little ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN));
            break;
        case Architecture::RISCV32:
            cs_architecture = CS_ARCH_RISCV;
            cs_mode_flags = static_cast<cs_mode>(CS_MODE_RISCV32 | CS_MODE_RISCVC);
            break;
        case Architecture::RISCV64:
            cs_architecture = CS_ARCH_RISCV;
            cs_mode_flags = static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC);
            break;
    }

    if (cs_open(cs_architecture, cs_mode_flags, out_handle.put()) != CS_ERR_OK) {
        return false;
    }
    (void)cs_option(out_handle.get(), CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}

[[nodiscard]] bool switch_arm_thumb_mode(
    csh handle,
    Endianness endian,
    bool thumb_mode) noexcept {
    const auto mode = static_cast<cs_mode>(
        (thumb_mode ? CS_MODE_THUMB : CS_MODE_ARM) |
        (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
    return cs_option(handle, CS_OPT_MODE, mode) == CS_ERR_OK;
}

[[nodiscard]] InstructionFlow classify_instruction_flow(
    Architecture arch,
    const cs_insn& insn) noexcept {
    if (insn.detail == nullptr) {
        return InstructionFlow::Normal;
    }
    const auto has_group = [&insn](std::uint8_t grp) noexcept {
        for (std::uint8_t i = 0; i < insn.detail->groups_count; ++i) {
            if (insn.detail->groups[i] == grp) {
                return true;
            }
        }
        return false;
    };

    const std::string_view m = insn.mnemonic;
    const std::string_view operands = insn.op_str;
    const bool conditional_arm = arch == Architecture::ARM32 &&
        insn.detail->arm.cc != ARM_CC_AL &&
        insn.detail->arm.cc != ARM_CC_INVALID;
    const InstructionFlow return_flow =
        conditional_arm ? InstructionFlow::ConditionalReturn : InstructionFlow::Return;

    if (has_group(CS_GRP_RET) || has_group(CS_GRP_IRET)) {
        return return_flow;
    }
    if (arch == Architecture::ARM32) {
        if ((insn.id == ARM_INS_BX && operands == "lr") ||
            ((insn.id == ARM_INS_POP || insn.id == ARM_INS_LDM) &&
             operands.find("pc") != std::string_view::npos)) {
            return return_flow;
        }
    }
    if ((arch == Architecture::MIPS32 || arch == Architecture::MIPS64) &&
        m == "jr" && (operands == "$ra" || operands == "$31")) {
        return InstructionFlow::Return;
    }
    if ((arch == Architecture::MIPS32 || arch == Architecture::MIPS64) &&
        (insn.id == MIPS_INS_JAL || insn.id == MIPS_INS_JALR ||
         insn.id == MIPS_INS_BAL || insn.id == MIPS_INS_JALX)) {
        return InstructionFlow::Call;
    }
    if ((arch == Architecture::PowerPC32 || arch == Architecture::PowerPC64) && m == "blr") {
        return InstructionFlow::Return;
    }
    if ((arch == Architecture::RISCV32 || arch == Architecture::RISCV64) &&
        (m == "ret" || m == "c.ret" || (m == "jr" && operands == "ra") ||
         (m == "c.jr" && operands == "ra"))) {
        return InstructionFlow::Return;
    }
    if (arch == Architecture::RISCV32 || arch == Architecture::RISCV64) {
        const auto& detail = insn.detail->riscv;
        if (m == "j" || m == "jr" || m == "c.j" || m == "c.jr" ||
            ((insn.id == RISCV_INS_JAL || insn.id == RISCV_INS_JALR) &&
             detail.op_count > 1 &&
             detail.operands[0].type == RISCV_OP_REG &&
             detail.operands[0].reg == RISCV_REG_X0)) {
            return InstructionFlow::Branch;
        }
    }
    if ((arch == Architecture::PowerPC32 || arch == Architecture::PowerPC64) &&
        (insn.id == PPC_INS_BL || insn.id == PPC_INS_BLA ||
         insn.id == PPC_INS_BCTRL || insn.id == PPC_INS_BLRL ||
         insn.id == PPC_INS_BCL || insn.id == PPC_INS_BCLA ||
         insn.id == PPC_INS_BCCTRL || insn.id == PPC_INS_BCLRL)) {
        return InstructionFlow::Call;
    }
    if (has_group(CS_GRP_CALL)) {
        return InstructionFlow::Call;
    }
    if (arch == Architecture::ARM32 && (insn.id == ARM_INS_TBB || insn.id == ARM_INS_TBH)) {
        return InstructionFlow::Branch;
    }
    if (!has_group(CS_GRP_JUMP)) {
        return InstructionFlow::Normal;
    }

    switch (arch) {
        case Architecture::X86_32:
        case Architecture::X86_64:
            return (insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP)
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
        case Architecture::ARM32:
            if (insn.id == ARM_INS_CBZ || insn.id == ARM_INS_CBNZ) {
                return InstructionFlow::ConditionalBranch;
            }
            return (insn.detail->arm.cc == ARM_CC_AL || insn.detail->arm.cc == ARM_CC_INVALID)
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
        case Architecture::ARM64:
            return ((insn.id == ARM64_INS_B &&
                     (insn.detail->arm64.cc == ARM64_CC_AL ||
                      insn.detail->arm64.cc == ARM64_CC_INVALID)) ||
                    insn.id == ARM64_INS_BR)
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
        case Architecture::MIPS32:
        case Architecture::MIPS64:
            return (m == "j" || m == "jr" || m == "b")
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
        case Architecture::PowerPC32:
        case Architecture::PowerPC64:
            return (m == "b" || m == "ba" || m == "bctr")
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
        case Architecture::RISCV32:
        case Architecture::RISCV64:
            return (m == "j" || m == "jr" || m == "jal" || m == "jalr" ||
                    m == "c.j" || m == "c.jr")
                ? InstructionFlow::Branch
                : InstructionFlow::ConditionalBranch;
    }
    return InstructionFlow::Normal;
}

[[nodiscard]] std::optional<std::uint64_t> extract_direct_target(
    Architecture arch,
    const cs_insn& insn,
    InstructionFlow flow) noexcept {
    if (insn.detail == nullptr) {
        return std::nullopt;
    }
    bool is_branch = flow == InstructionFlow::Call ||
                     flow == InstructionFlow::Branch ||
                     flow == InstructionFlow::ConditionalBranch;
    for (std::uint8_t i = 0; i < insn.detail->groups_count; ++i) {
        is_branch |= insn.detail->groups[i] == CS_GRP_CALL ||
                     insn.detail->groups[i] == CS_GRP_JUMP;
    }
    if (!is_branch) {
        return std::nullopt;
    }

    std::optional<std::uint64_t> target{};
    const auto scan_imm = [&target](const auto& detail, auto imm_type) noexcept {
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == imm_type) {
                target = static_cast<std::uint64_t>(detail.operands[i].imm);
            }
        }
    };

    switch (arch) {
        case Architecture::X86_32:
        case Architecture::X86_64:
            scan_imm(insn.detail->x86, X86_OP_IMM);
            break;
        case Architecture::ARM32:
            scan_imm(insn.detail->arm, ARM_OP_IMM);
            break;
        case Architecture::ARM64:
            scan_imm(insn.detail->arm64, ARM64_OP_IMM);
            break;
        case Architecture::MIPS32:
        case Architecture::MIPS64:
            scan_imm(insn.detail->mips, MIPS_OP_IMM);
            break;
        case Architecture::PowerPC32:
        case Architecture::PowerPC64:
            scan_imm(insn.detail->ppc, PPC_OP_IMM);
            break;
        case Architecture::RISCV32:
        case Architecture::RISCV64:
            if (insn.id != RISCV_INS_JALR &&
                insn.id != RISCV_INS_C_JR &&
                insn.id != RISCV_INS_C_JALR) {
                scan_imm(insn.detail->riscv, RISCV_OP_IMM);
                if (target.has_value()) {
                    *target += insn.address;
                    if (arch == Architecture::RISCV32) {
                        *target &= 0xFFFFFFFFULL;
                    }
                }
            }
            break;
    }
    return target;
}

void populate_jump_table_annotation(
    Architecture arch,
    const cs_insn& insn,
    Instruction& out_inst) noexcept {
    if (insn.detail == nullptr ||
        (arch != Architecture::X86_32 && arch != Architecture::X86_64)) {
        return;
    }
    const auto& detail = insn.detail->x86;
    if (insn.id == X86_INS_CMP && detail.op_count == 2 &&
        detail.operands[0].type == X86_OP_REG &&
        detail.operands[1].type == X86_OP_IMM &&
        detail.operands[1].imm >= 0) {
        out_inst.compare_register = detail.operands[0].reg;
        out_inst.compare_bound = static_cast<std::uint64_t>(detail.operands[1].imm);
    }
    if (insn.id != X86_INS_JMP || detail.op_count != 1 ||
        detail.operands[0].type != X86_OP_MEM) {
        return;
    }
    const auto& operand = detail.operands[0];
    const auto& mem = operand.mem;
    if (mem.base != X86_REG_INVALID ||
        mem.index == X86_REG_INVALID ||
        mem.segment != X86_REG_INVALID ||
        mem.disp < 0 ||
        mem.scale != operand.size ||
        (operand.size != 4 && operand.size != 8)) {
        return;
    }
    out_inst.jump_table = AbsoluteJumpTableOperand{
        .address = static_cast<std::uint64_t>(mem.disp),
        .index_register = static_cast<std::uint32_t>(mem.index),
        .entry_size = operand.size,
    };
}

[[nodiscard]] Instruction make_instruction_from_cs(Architecture arch, const cs_insn& insn) {
    Instruction inst{};
    inst.address = insn.address;
    inst.bytes.assign(insn.bytes, insn.bytes + insn.size);
    inst.mnemonic = insn.mnemonic;
    inst.operands = insn.op_str;
    inst.flow = classify_instruction_flow(arch, insn);
    inst.branch_target = extract_direct_target(arch, insn, inst.flow);
    inst.delay_slot = (arch == Architecture::MIPS32 || arch == Architecture::MIPS64) &&
                      inst.flow != InstructionFlow::Normal;
    populate_jump_table_annotation(arch, insn, inst);
    inst.annulled_delay_slot = inst.delay_slot &&
        (inst.mnemonic == "beql" || inst.mnemonic == "bnel" ||
         inst.mnemonic == "blezl" || inst.mnemonic == "bgtzl" ||
         inst.mnemonic == "bltzl" || inst.mnemonic == "bgezl");
    return inst;
}

[[nodiscard]] Instruction make_data_fallback_instruction(
    std::uint64_t address,
    std::span<const std::uint8_t> raw_bytes) {
    Instruction inst{};
    inst.address = address;
    inst.bytes.assign(raw_bytes.begin(), raw_bytes.end());
    inst.mnemonic = ".byte";
    std::string ops;
    for (std::size_t i = 0; i < raw_bytes.size(); ++i) {
        if (i != 0u) {
            ops += ", ";
        }
        ops += std::format("0x{:02X}", raw_bytes[i]);
    }
    inst.operands = std::move(ops);
    inst.flow = InstructionFlow::Normal;
    return inst;
}

[[nodiscard]] std::vector<LinearDisassemblySpan> normalize_spans(
    std::span<const LinearDisassemblySpan> input_spans) {
    std::vector<LinearDisassemblySpan> sorted;
    sorted.reserve(input_spans.size());
    for (const LinearDisassemblySpan& sp : input_spans) {
        if (sp.byte_size == 0u) {
            continue;
        }
        if (sp.byte_size > std::numeric_limits<std::uint64_t>::max() - sp.virtual_address) {
            LinearDisassemblySpan clamped = sp;
            clamped.byte_size = std::numeric_limits<std::uint64_t>::max() - sp.virtual_address;
            if (clamped.byte_size != 0u) {
                sorted.push_back(std::move(clamped));
            }
            continue;
        }
        sorted.push_back(sp);
    }

    std::ranges::sort(sorted, [](const LinearDisassemblySpan& lhs, const LinearDisassemblySpan& rhs) {
        if (lhs.virtual_address != rhs.virtual_address) {
            return lhs.virtual_address < rhs.virtual_address;
        }
        return lhs.byte_size > rhs.byte_size;
    });

    std::vector<LinearDisassemblySpan> deduped;
    deduped.reserve(sorted.size());
    for (LinearDisassemblySpan& sp : sorted) {
        if (deduped.empty()) {
            deduped.push_back(std::move(sp));
            continue;
        }
        const LinearDisassemblySpan& prev = deduped.back();
        const std::uint64_t prev_end = prev.virtual_address + prev.byte_size;
        const std::uint64_t cur_end = sp.virtual_address + sp.byte_size;
        if (cur_end <= prev_end) {
            continue;
        }
        if (sp.virtual_address < prev_end) {
            const std::uint64_t overlap = prev_end - sp.virtual_address;
            sp.virtual_address = prev_end;
            sp.byte_size -= overlap;
            if (sp.file_offset.has_value()) {
                *sp.file_offset += overlap;
            }
        }
        if (sp.byte_size != 0u) {
            deduped.push_back(std::move(sp));
        }
    }
    return deduped;
}

[[nodiscard]] std::vector<std::uint64_t> collect_boundaries(
    const SymbolIndex* symbols,
    const FunctionIndex* functions,
    Architecture arch) {
    std::vector<std::uint64_t> bounds;
    const std::uint64_t mask = (arch == Architecture::ARM32) ? ~std::uint64_t{1} : ~std::uint64_t{0};

    if (functions != nullptr) {
        bounds.reserve(functions->size());
        for (const FunctionEntry& fn : functions->entries()) {
            if (fn.virtual_address != 0u) {
                bounds.push_back(fn.virtual_address & mask);
            }
        }
    }
    if (symbols != nullptr) {
        for (const SymbolRecord& sym : symbols->records()) {
            if (sym.virtual_address.has_value() && *sym.virtual_address != 0u) {
                bounds.push_back(*sym.virtual_address & mask);
            }
        }
    }
    std::ranges::sort(bounds);
    const auto unique_end = std::ranges::unique(bounds).begin();
    bounds.erase(unique_end, bounds.end());
    return bounds;
}

[[nodiscard]] const SourceLineMapping* lookup_source_line(
    std::span<const SourceLineMapping> lines,
    std::uint64_t virtual_address,
    std::uint64_t max_distance) noexcept {
    if (lines.empty() || virtual_address == 0u) {
        return nullptr;
    }
    const auto upper = std::upper_bound(
        lines.begin(),
        lines.end(),
        virtual_address,
        [](std::uint64_t addr, const SourceLineMapping& entry) {
            return addr < entry.virtual_address;
        });
    if (upper == lines.begin()) {
        return nullptr;
    }
    const SourceLineMapping& candidate = *std::prev(upper);
    const std::uint64_t delta = virtual_address - candidate.virtual_address;
    if (delta > max_distance) {
        return nullptr;
    }
    return &candidate;
}

[[nodiscard]] std::string resolve_caller_label(
    std::uint64_t caller_va,
    const LinearMetadataContext& context) {
    if (context.annotations != nullptr) {
        if (const Annotation* ann = context.annotations->find(caller_va);
            ann != nullptr && !ann->name.empty()) {
            return ann->name;
        }
    }
    if (context.functions != nullptr) {
        if (const FunctionEntry* fn = context.functions->find_containing(caller_va);
            fn != nullptr && fn->virtual_address != 0u) {
            const std::uint64_t delta = caller_va - fn->virtual_address;
            const std::string& name = fn->display_name(context.demangle_symbols);
            return delta == 0u ? name : std::format("{}+0x{:X}", name, delta);
        }
    }
    if (context.symbols != nullptr) {
        if (const SymbolRecord* sym = context.symbols->find_containing_address(caller_va);
            sym != nullptr && sym->virtual_address.has_value()) {
            const std::uint64_t delta = caller_va - *sym->virtual_address;
            const std::uint64_t limit = sym->size != 0u ? sym->size : 0x4000u;
            if (delta < limit) {
                const std::string& name = sym->display_name(context.demangle_symbols);
                return delta == 0u ? name : std::format("{}+0x{:X}", name, delta);
            }
        }
    }
    return std::format("0x{:X}", caller_va);
}

} // namespace

std::string format_address_column(
    AddressDisplayMode mode,
    std::uint64_t file_offset,
    const peelf::IBinaryImage* image,
    std::optional<std::uint64_t> explicit_va,
    std::optional<std::uint64_t> explicit_base_va,
    bool is_64bit) {
    if (mode == AddressDisplayMode::FileOffset) {
        return file_offset > 0xFFFFFFFFULL
            ? std::format("0x{:012X}", file_offset)
            : std::format("0x{:08X}", file_offset);
    }

    const std::optional<std::uint64_t> resolved_va = explicit_va.has_value()
        ? explicit_va
        : (image != nullptr ? image->file_offset_to_virtual_address(file_offset) : std::nullopt);

    if (!resolved_va.has_value()) {
        return file_offset > 0xFFFFFFFFULL
            ? std::format("off:0x{:012X}", file_offset)
            : std::format("off:0x{:08X}", file_offset);
    }

    if (mode == AddressDisplayMode::RelativeVirtualAddress) {
        const std::uint64_t base_va = explicit_base_va.has_value()
            ? *explicit_base_va
            : (image != nullptr ? image->image_base() : 0u);
        if (*resolved_va >= base_va) {
            const std::uint64_t rva = *resolved_va - base_va;
            return rva > 0xFFFFFFFFULL
                ? std::format("+0x{:012X}", rva)
                : std::format("+0x{:08X}", rva);
        }
        return std::format("0x{:08X}", *resolved_va);
    }

    const bool wide = (image != nullptr ? image->is_64bit() : is_64bit) ||
                      *resolved_va > 0xFFFFFFFFULL;
    return wide
        ? std::format("0x{:016X}", *resolved_va)
        : std::format("0x{:08X}", *resolved_va);
}

std::string format_hex_row_address(
    AddressDisplayMode mode,
    std::uint64_t window_offset,
    const BinaryModel& model) {
    if (model.is_live_process()) {
        const std::optional<std::uint64_t> live_va = model.offset_to_virtual_address(window_offset);
        std::optional<std::uint64_t> base_va{};
        if (const peelf::ModuleInfo* mod = model.active_module(); mod != nullptr) {
            base_va = mod->base_address;
        } else {
            base_va = model.view_base_address();
        }
        const bool is_64 = model.target_layout().is_64bit();
        if (mode == AddressDisplayMode::FileOffset) {
            if (model.image() != nullptr && live_va.has_value()) {
                std::uint64_t image_va = *live_va;
                if (const peelf::ModuleInfo* mod = model.active_module();
                    mod != nullptr && *live_va >= mod->base_address) {
                    image_va = model.image()->image_base() + (*live_va - mod->base_address);
                }
                if (const auto disk_off = model.image()->virtual_address_to_file_offset(image_va);
                    disk_off.has_value()) {
                    return format_address_column(
                        AddressDisplayMode::FileOffset,
                        *disk_off,
                        model.image(),
                        live_va,
                        base_va,
                        is_64);
                }
            }
            return format_address_column(
                AddressDisplayMode::FileOffset,
                window_offset,
                nullptr,
                live_va,
                base_va,
                is_64);
        }
        return format_address_column(mode, window_offset, model.image(), live_va, base_va, is_64);
    }

    const bool is_64 = model.image() != nullptr ? model.image()->is_64bit()
                                                : model.target_layout().is_64bit();
    return format_address_column(mode, window_offset, model.image(), std::nullopt, std::nullopt, is_64);
}

std::string format_instruction_address(
    AddressDisplayMode mode,
    std::uint64_t instruction_va,
    std::optional<std::uint64_t> file_offset,
    std::uint64_t image_base,
    bool is_64bit) {
    switch (mode) {
        case AddressDisplayMode::VirtualAddress:
            return (is_64bit || instruction_va > 0xFFFFFFFFULL)
                ? std::format("0x{:016X}", instruction_va)
                : std::format("0x{:08X}", instruction_va);
        case AddressDisplayMode::RelativeVirtualAddress:
            if (instruction_va >= image_base) {
                const std::uint64_t rva = instruction_va - image_base;
                return rva > 0xFFFFFFFFULL
                    ? std::format("+0x{:012X}", rva)
                    : std::format("+0x{:08X}", rva);
            }
            return std::format("0x{:08X}", instruction_va);
        case AddressDisplayMode::FileOffset:
            if (file_offset.has_value()) {
                return *file_offset > 0xFFFFFFFFULL
                    ? std::format("0x{:012X}", *file_offset)
                    : std::format("0x{:08X}", *file_offset);
            }
            return std::format("va:0x{:X}", instruction_va);
    }
    return std::format("0x{:016X}", instruction_va);
}

HexAvailabilityStatus evaluate_section_hex_availability(
    const peelf::Section& section,
    std::uint64_t available_file_size) {
    const std::string sec_name = section.name.empty() ? "<unnamed>" : section.name;
    if (section.file_size == 0u) {
        return HexAvailabilityStatus{
            .available = false,
            .unavailable_reason = std::format(
                "Section '{}' (VA 0x{:X}, virtual size 0x{:X}) has zero file-backed bytes "
                "(SHT_NOBITS / virtual-only range).",
                sec_name,
                section.virtual_address,
                section.virtual_size),
        };
    }
    if (section.file_offset >= available_file_size) {
        return HexAvailabilityStatus{
            .available = false,
            .unavailable_reason = std::format(
                "Section '{}' file offset 0x{:X} lies outside file bounds (0x{:X} bytes).",
                sec_name,
                section.file_offset,
                available_file_size),
        };
    }
    return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
}

HexAvailabilityStatus evaluate_hex_selection_availability(
    const BinaryModel& model,
    const ViewerSelection& selection) {
    if (!model.has_file()) {
        return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
    }
    if (selection.kind == SelectionKind::None ||
        selection.kind == SelectionKind::Group ||
        selection.kind == SelectionKind::Process ||
        selection.kind == SelectionKind::ProcessModule ||
        selection.kind == SelectionKind::ProcessHandle) {
        return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
    }

    if (!model.is_live_process()) {
        const peelf::IBinaryImage* img = model.image();
        const std::uint64_t file_size = model.view_size();

        if (selection.kind == SelectionKind::Section && img != nullptr) {
            const auto& sections = img->sections();
            const peelf::Section* matched_sec = nullptr;
            if (selection.object_index < sections.size()) {
                const peelf::Section& candidate =
                    sections[static_cast<std::size_t>(selection.object_index)];
                const bool label_ok = selection.label.empty() || candidate.name == selection.label;
                const bool va_ok = !selection.virtual_address.has_value() ||
                    candidate.virtual_address == *selection.virtual_address;
                if (label_ok && va_ok) {
                    matched_sec = &candidate;
                }
            }
            if (matched_sec == nullptr) {
                for (const peelf::Section& candidate : sections) {
                    const bool label_ok = !selection.label.empty() && candidate.name == selection.label;
                    const bool va_ok = !selection.virtual_address.has_value() ||
                        candidate.virtual_address == *selection.virtual_address;
                    if (label_ok && va_ok) {
                        matched_sec = &candidate;
                        break;
                    }
                }
            }
            if (matched_sec != nullptr) {
                return evaluate_section_hex_availability(*matched_sec, file_size);
            }
        }

        if (selection.file_offset.has_value()) {
            if (*selection.file_offset < file_size) {
                return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
            }
            return HexAvailabilityStatus{
                .available = false,
                .unavailable_reason = std::format(
                    "Selected file offset 0x{:X} is outside file bounds (0x{:X} bytes).",
                    *selection.file_offset,
                    file_size),
            };
        }

        if (selection.virtual_address.has_value()) {
            const std::uint64_t va = *selection.virtual_address;
            if (const auto mapped = model.virtual_address_to_offset(va);
                mapped.has_value() && *mapped < file_size) {
                return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
            }
            if (img != nullptr) {
                for (const peelf::Section& sec : img->sections()) {
                    const std::uint64_t vspan = std::max(sec.virtual_size, sec.file_size);
                    if (vspan != 0u && va >= sec.virtual_address && va - sec.virtual_address < vspan) {
                        if (sec.file_size == 0u || va - sec.virtual_address >= sec.file_size) {
                            const std::string sec_name = sec.name.empty() ? "<unnamed>" : sec.name;
                            return HexAvailabilityStatus{
                                .available = false,
                                .unavailable_reason = std::format(
                                    "Address 0x{:X} in section '{}' is virtual-only / unmapped in file "
                                    "(SHT_NOBITS / zero-fill).",
                                    va,
                                    sec_name),
                            };
                        }
                    }
                }
            }
            return HexAvailabilityStatus{
                .available = false,
                .unavailable_reason = std::format(
                    "Virtual address 0x{:X} is unmapped and has no file-backed bytes.",
                    va),
            };
        }

        if (selection.size > 0u) {
            return HexAvailabilityStatus{
                .available = false,
                .unavailable_reason = "Selected range is virtual-only or unmapped in file.",
            };
        }
        return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
    }

    // Live process / crash dump
    if (selection.kind == SelectionKind::MemoryRegion) {
        const auto& regions = model.memory_regions();
        if (selection.object_index < regions.size()) {
            const peelf::MemoryRegion& reg = regions[static_cast<std::size_t>(selection.object_index)];
            const bool va_ok = !selection.virtual_address.has_value() ||
                reg.contains(*selection.virtual_address) ||
                reg.start_address == *selection.virtual_address;
            if (va_ok && !reg.protection.readable) {
                return HexAvailabilityStatus{
                    .available = false,
                    .unavailable_reason = std::format(
                        "Memory region 0x{:X}-0x{:X} is guard/inaccessible (no read permission).",
                        reg.start_address,
                        reg.end_address),
                };
            }
        }
    }

    if (selection.virtual_address.has_value()) {
        const auto sample = model.read_virtual_bytes(*selection.virtual_address, 1u);
        if (!sample.has_value() || sample->empty()) {
            return HexAvailabilityStatus{
                .available = false,
                .unavailable_reason = std::format(
                    "Virtual address 0x{:X} is unmapped or unreadable in target memory.",
                    *selection.virtual_address),
            };
        }
    }

    return HexAvailabilityStatus{.available = true, .unavailable_reason = {}};
}

std::vector<BranchArc> compute_branch_arcs(
    std::span<const Instruction> window_instructions,
    std::optional<std::uint64_t> selected_va,
    std::size_t max_lanes,
    const FunctionIndex* functions) {
    std::vector<BranchArc> arcs;
    if (window_instructions.empty() || max_lanes == 0u) {
        return arcs;
    }

    const std::uint64_t window_first_va = window_instructions.front().address;
    const std::uint64_t window_last_va = window_instructions.back().address;

    struct CandidateArc {
        BranchArc arc{};
        std::size_t interval_lo = 0;
        std::size_t interval_hi = 0;
    };

    std::vector<CandidateArc> candidates;
    for (std::size_t idx = 0; idx < window_instructions.size(); ++idx) {
        const Instruction& inst = window_instructions[idx];
        if ((inst.flow != InstructionFlow::Branch &&
             inst.flow != InstructionFlow::ConditionalBranch) ||
            !inst.branch_target.has_value()) {
            continue;
        }
        const std::uint64_t target_va = *inst.branch_target;
        if (target_va == inst.address) {
            BranchArc self_arc{};
            self_arc.source_va = inst.address;
            self_arc.target_va = target_va;
            self_arc.source_row = idx;
            self_arc.target_row = idx;
            self_arc.is_conditional = (inst.flow == InstructionFlow::ConditionalBranch);
            self_arc.is_upward = true;
            self_arc.is_selected = selected_va.has_value() && *selected_va == inst.address;
            candidates.push_back(CandidateArc{
                .arc = self_arc,
                .interval_lo = idx,
                .interval_hi = idx,
            });
            continue;
        }

        // Binary search for target_va within window_instructions
        const auto target_it = std::lower_bound(
            window_instructions.begin(),
            window_instructions.end(),
            target_va,
            [](const Instruction& item, std::uint64_t addr) {
                return item.address < addr;
            });

        std::optional<std::size_t> target_row{};
        if (target_it != window_instructions.end()) {
            const std::uint64_t aligned_target = target_va & ~std::uint64_t{1};
            if (target_it->address == target_va || target_it->address == aligned_target) {
                target_row = static_cast<std::size_t>(
                    std::distance(window_instructions.begin(), target_it));
            }
        }
        if (!target_row.has_value() && target_it != window_instructions.begin()) {
            const auto prev_it = std::prev(target_it);
            if (prev_it->address == (target_va & ~std::uint64_t{1})) {
                target_row = static_cast<std::size_t>(
                    std::distance(window_instructions.begin(), prev_it));
            }
        }

        bool offscreen_above = false;
        bool offscreen_below = false;
        if (!target_row.has_value()) {
            bool local_eligible = false;
            if (functions != nullptr) {
                const FunctionEntry* fn = functions->find_containing(inst.address);
                if (fn != nullptr && fn->size != 0u &&
                    target_va >= fn->virtual_address &&
                    target_va - fn->virtual_address < fn->size) {
                    local_eligible = true;
                }
            }
            if (!local_eligible) {
                const std::uint64_t dist = target_va > inst.address
                    ? (target_va - inst.address)
                    : (inst.address - target_va);
                local_eligible = dist <= kMaxLocalOffscreenBranchDistance;
            }
            if (!local_eligible) {
                continue;
            }

            if (target_va < window_first_va) {
                offscreen_above = true;
            } else if (target_va > window_last_va) {
                offscreen_below = true;
            } else {
                continue;
            }
        }

        BranchArc arc{};
        arc.source_va = inst.address;
        arc.target_va = target_va;
        arc.source_row = idx;
        arc.target_row = target_row;
        arc.is_conditional = (inst.flow == InstructionFlow::ConditionalBranch);
        arc.is_upward = target_va < inst.address;
        arc.is_selected = selected_va.has_value() &&
            (*selected_va == inst.address ||
             *selected_va == target_va ||
             *selected_va == (target_va & ~std::uint64_t{1}));
        arc.target_offscreen_above = offscreen_above;
        arc.target_offscreen_below = offscreen_below;

        const std::size_t end_row = target_row.has_value()
            ? *target_row
            : (offscreen_above ? 0u : (window_instructions.size() - 1u));
        candidates.push_back(CandidateArc{
            .arc = arc,
            .interval_lo = std::min(idx, end_row),
            .interval_hi = std::max(idx, end_row),
        });
    }

    if (candidates.empty()) {
        return arcs;
    }

    // Assign shorter inner spans to inner lanes (0, 1, ...) and outer spans to higher lanes,
    // strictly bounded by max_lanes.
    std::vector<std::size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), 0u);
    std::ranges::sort(order, [&candidates](std::size_t a, std::size_t b) {
        const CandidateArc& lhs = candidates[a];
        const CandidateArc& rhs = candidates[b];
        const bool lhs_in_win = lhs.arc.target_row.has_value();
        const bool rhs_in_win = rhs.arc.target_row.has_value();
        if (lhs_in_win != rhs_in_win) {
            return lhs_in_win > rhs_in_win;
        }
        const std::size_t lhs_len = lhs.interval_hi - lhs.interval_lo;
        const std::size_t rhs_len = rhs.interval_hi - rhs.interval_lo;
        if (lhs_len != rhs_len) {
            return lhs_len < rhs_len;
        }
        if (lhs.arc.is_selected != rhs.arc.is_selected) {
            return lhs.arc.is_selected > rhs.arc.is_selected;
        }
        return lhs.arc.source_row < rhs.arc.source_row;
    });

    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lane_intervals(max_lanes);
    arcs.reserve(candidates.size());
    for (const std::size_t idx : order) {
        CandidateArc& cand = candidates[idx];
        std::optional<std::size_t> chosen_lane{};
        for (std::size_t lane = 0; lane < max_lanes; ++lane) {
            bool conflict = false;
            for (const auto& [lo, hi] : lane_intervals[lane]) {
                if (cand.interval_lo <= hi && lo <= cand.interval_hi) {
                    conflict = true;
                    break;
                }
            }
            if (!conflict) {
                chosen_lane = lane;
                break;
            }
        }
        if (!chosen_lane.has_value()) {
            continue;
        }
        cand.arc.lane = *chosen_lane;
        lane_intervals[*chosen_lane].emplace_back(cand.interval_lo, cand.interval_hi);
        arcs.push_back(cand.arc);
    }
    return arcs;
}

InstructionRowMetadata describe_instruction_row(
    const Instruction& instruction,
    const LinearMetadataContext& context,
    std::optional<std::uint64_t> previous_instruction_va) {
    InstructionRowMetadata meta{};
    const std::uint64_t va = instruction.address;

    if (context.annotations != nullptr) {
        if (const Annotation* ann = context.annotations->find(va); ann != nullptr) {
            meta.user_label = ann->name;
            meta.user_comment = ann->comment;
        }
    }

    if (context.functions != nullptr) {
        const FunctionEntry* fn = context.functions->find_exact(va);
        if (fn == nullptr) {
            fn = context.functions->find_exact(va | std::uint64_t{1});
        }
        if (fn != nullptr) {
            meta.has_header_banner = true;
            meta.raw_symbol_name = fn->name;
            meta.symbol_name = !meta.user_label.empty()
                ? meta.user_label
                : fn->display_name(context.demangle_symbols);
            meta.function_size = fn->size;
        }
    }

    if (!meta.has_header_banner && context.symbols != nullptr) {
        if (const SymbolRecord* sym = context.symbols->find_containing_address(va);
            sym != nullptr && sym->virtual_address.has_value() &&
            (*sym->virtual_address == va || (*sym->virtual_address & ~std::uint64_t{1}) == va)) {
            meta.has_header_banner = true;
            meta.raw_symbol_name = sym->name;
            meta.symbol_name = !meta.user_label.empty()
                ? meta.user_label
                : sym->display_name(context.demangle_symbols);
            meta.function_size = sym->size;
        }
    }

    if (meta.has_header_banner) {
        meta.header_banner = meta.function_size != 0u
            ? std::format("=== {} (0x{:X}) ===", meta.symbol_name, meta.function_size)
            : std::format("=== {} ===", meta.symbol_name);
    }

    if (context.references != nullptr) {
        auto refs = context.references->incoming(va);
        if (refs.empty() && (va & 1ULL) == 0ULL) {
            refs = context.references->incoming(va | 1ULL);
        }
        meta.incoming_xref_count = refs.size();
        if (!refs.empty()) {
            const std::size_t preview_limit = std::max<std::size_t>(1u, context.max_xref_preview);
            std::string summary = refs.size() > 1u
                ? std::format("XREFS ({}): ", refs.size())
                : std::string{"XREF: "};
            const std::size_t shown = std::min(refs.size(), preview_limit);
            for (std::size_t i = 0; i < shown; ++i) {
                if (i != 0u) {
                    summary += ", ";
                }
                summary += resolve_caller_label(refs[i]->source, context);
            }
            if (refs.size() > shown) {
                summary += std::format(", +{} more", refs.size() - shown);
            }
            meta.xref_summary = std::move(summary);
        }
    }

    if (!context.source_lines.empty()) {
        const SourceLineMapping* cur_line =
            lookup_source_line(context.source_lines, va, kMaxSourceLineDistance);
        if (cur_line != nullptr && cur_line->line != 0u) {
            meta.has_source_line = true;
            meta.source_full_path = !cur_line->file_path.empty()
                ? cur_line->file_path
                : cur_line->file_name;
            meta.source_file = !cur_line->file_name.empty()
                ? extract_cross_platform_basename(cur_line->file_name)
                : extract_cross_platform_basename(cur_line->file_path);
            meta.source_line = cur_line->line;
            meta.source_column = cur_line->column;
            meta.source_tag = std::format("[{}:{}]", meta.source_file, meta.source_line);

            const SourceLineMapping* prev_line = previous_instruction_va.has_value()
                ? lookup_source_line(context.source_lines, *previous_instruction_va, kMaxSourceLineDistance)
                : nullptr;
            meta.is_new_source_line = prev_line == nullptr ||
                prev_line->line != cur_line->line ||
                prev_line->file_path != cur_line->file_path ||
                prev_line->file_name != cur_line->file_name;
        }
    }

    return meta;
}

std::vector<ArmThumbRangeHint> extract_arm_thumb_hints(const peelf::IBinaryImage& image) {
    std::vector<ArmThumbRangeHint> hints;
    if (image.architecture() != peelf::Architecture::ARM) {
        return hints;
    }

    // PE ARMNT (0x01C4) is exclusively Thumb-2 across executable sections.
    if (image.format() == peelf::Format::PE &&
        image.pe_header() != nullptr &&
        image.pe_header()->machine == kPeMachineArmNt) {
        for (const peelf::Section& sec : image.sections()) {
            const std::uint64_t len = std::max(sec.file_size, sec.virtual_size);
            if (len != 0u) {
                hints.push_back(ArmThumbRangeHint{
                    .start_va = sec.virtual_address & ~std::uint64_t{1},
                    .end_va = (sec.virtual_address & ~std::uint64_t{1}) + len,
                    .thumb = true,
                });
            }
        }
        return hints;
    }

    struct MappingMark {
        std::uint64_t va = 0;
        bool thumb = false;
    };
    std::vector<MappingMark> mapping_marks;

    for (const peelf::ElfSymbol& es : image.elf_symbols()) {
        if (es.value == 0u) {
            continue;
        }
        if (es.name == "$t" || es.name.starts_with("$t.")) {
            mapping_marks.push_back(MappingMark{.va = es.value & ~std::uint64_t{1}, .thumb = true});
            continue;
        }
        if (es.name == "$a" || es.name.starts_with("$a.")) {
            mapping_marks.push_back(MappingMark{.va = es.value & ~std::uint64_t{1}, .thumb = false});
            continue;
        }
        const std::uint8_t stt = es.type != 0u ? es.type : static_cast<std::uint8_t>(es.info & 0x0Fu);
        if (stt == kElfSttFunc || stt == kElfSttGnuIfunc) {
            const bool is_thumb = (es.value & 1ULL) != 0ULL;
            const std::uint64_t start = es.value & ~std::uint64_t{1};
            const std::uint64_t len = es.size != 0u ? es.size : (is_thumb ? 2u : 4u);
            hints.push_back(ArmThumbRangeHint{
                .start_va = start,
                .end_va = start + len,
                .thumb = is_thumb,
            });
        }
    }

    if (!mapping_marks.empty()) {
        std::ranges::sort(mapping_marks, [](const MappingMark& a, const MappingMark& b) {
            return a.va < b.va;
        });
        std::uint64_t max_exec_end = 0u;
        for (const peelf::Section& sec : image.sections()) {
            if (sec.executable) {
                max_exec_end = std::max(
                    max_exec_end,
                    sec.virtual_address + std::max(sec.file_size, sec.virtual_size));
            }
        }
        hints.clear();
        for (std::size_t i = 0; i < mapping_marks.size(); ++i) {
            const std::uint64_t start = mapping_marks[i].va;
            const std::uint64_t end = (i + 1u < mapping_marks.size())
                ? mapping_marks[i + 1u].va
                : std::max(start + 4u, max_exec_end);
            if (end > start) {
                hints.push_back(ArmThumbRangeHint{
                    .start_va = start,
                    .end_va = end,
                    .thumb = mapping_marks[i].thumb,
                });
            }
        }
    }

    for (const peelf::MachOSymbol& ms : image.macho_symbols()) {
        if (ms.value != 0u && ms.is_thumb) {
            const std::uint64_t start = ms.value & ~std::uint64_t{1};
            hints.push_back(ArmThumbRangeHint{
                .start_va = start,
                .end_va = start + 64u,
                .thumb = true,
            });
        }
    }

    for (const peelf::Symbol& sym : image.symbols()) {
        if (sym.virtual_address != 0u && (sym.virtual_address & 1ULL) != 0ULL) {
            const std::uint64_t start = sym.virtual_address & ~std::uint64_t{1};
            const std::uint64_t len = sym.size != 0u ? sym.size : 16u;
            hints.push_back(ArmThumbRangeHint{
                .start_va = start,
                .end_va = start + len,
                .thumb = true,
            });
        }
    }

    if ((image.entry_point() & 1ULL) != 0ULL) {
        const std::uint64_t ep = image.entry_point() & ~std::uint64_t{1};
        hints.push_back(ArmThumbRangeHint{
            .start_va = ep,
            .end_va = ep + 64u,
            .thumb = true,
        });
    }

    std::ranges::sort(hints, [](const ArmThumbRangeHint& lhs, const ArmThumbRangeHint& rhs) {
        if (lhs.start_va != rhs.start_va) {
            return lhs.start_va < rhs.start_va;
        }
        return lhs.end_va < rhs.end_va;
    });
    return hints;
}

LinearDisassemblyView::LinearDisassemblyView(LinearDisassemblyOptions options)
    : options_(options) {
    options_.chunk_target_bytes = std::max<std::size_t>(64u, options_.chunk_target_bytes);
    options_.max_cached_chunks = std::max<std::size_t>(1u, options_.max_cached_chunks);
}

void LinearDisassemblyView::clear() noexcept {
    configured_ = false;
    byte_reader_ = {};
    base_spans_.clear();
    fallback_span_.reset();
    active_spans_.clear();
    symbol_boundaries_.clear();
    arm_hints_.clear();
    chunks_.clear();
    chunk_row_offsets_.clear();
    lru_order_.clear();
    chunk_cache_.clear();
    cache_hits_ = 0;
    cache_misses_ = 0;
    cache_evictions_ = 0;
    synced_model_identity_ = 0;
}

void LinearDisassemblyView::set_options(LinearDisassemblyOptions options) {
    options.chunk_target_bytes = std::max<std::size_t>(64u, options.chunk_target_bytes);
    options.max_cached_chunks = std::max<std::size_t>(1u, options.max_cached_chunks);
    const bool repartition = options.chunk_target_bytes != options_.chunk_target_bytes;
    options_ = options;
    if (!configured_) {
        return;
    }
    if (repartition) {
        rebuild_partitions();
        return;
    }
    while (chunk_cache_.size() > options_.max_cached_chunks && !lru_order_.empty()) {
        const std::size_t victim = lru_order_.back();
        lru_order_.pop_back();
        chunk_cache_.erase(victim);
        ++cache_evictions_;
    }
}

bool LinearDisassemblyView::configure_synthetic(
    Architecture arch,
    Endianness endian,
    std::span<const LinearDisassemblySpan> spans,
    ByteReaderFn reader,
    std::span<const std::uint64_t> symbol_boundaries,
    std::span<const ArmThumbRangeHint> arm_hints,
    LinearDisassemblyRevision revision) {
    clear();
    if (!reader) {
        return false;
    }
    arch_ = arch;
    endian_ = endian;
    revision_ = revision;
    byte_reader_ = std::move(reader);
    base_spans_ = normalize_spans(spans);

    const std::uint64_t mask = (arch_ == Architecture::ARM32) ? ~std::uint64_t{1} : ~std::uint64_t{0};
    symbol_boundaries_.reserve(symbol_boundaries.size());
    for (const std::uint64_t b : symbol_boundaries) {
        symbol_boundaries_.push_back(b & mask);
    }
    std::ranges::sort(symbol_boundaries_);
    const auto uniq = std::ranges::unique(symbol_boundaries_).begin();
    symbol_boundaries_.erase(uniq, symbol_boundaries_.end());

    arm_hints_.assign(arm_hints.begin(), arm_hints.end());
    std::ranges::sort(arm_hints_, [](const ArmThumbRangeHint& lhs, const ArmThumbRangeHint& rhs) {
        return lhs.start_va < rhs.start_va;
    });

    configured_ = true;
    rebuild_partitions();
    return !chunks_.empty();
}

bool LinearDisassemblyView::configure_image(
    const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> file_bytes,
    const SymbolIndex* symbols,
    const FunctionIndex* functions,
    LinearDisassemblyRevision revision) {
    const auto mapped_arch = to_disassembler_architecture(image.architecture());
    if (!mapped_arch.has_value()) {
        clear();
        return false;
    }

    const auto available_size = static_cast<std::uint64_t>(file_bytes.size());
    std::vector<LinearDisassemblySpan> spans;
    for (const peelf::Section& sec : image.sections()) {
        if (!sec.executable || sec.file_size == 0u || sec.file_offset >= available_size) {
            continue;
        }
        const std::uint64_t clamped_file_size =
            std::min(sec.file_size, available_size - sec.file_offset);
        const std::uint64_t span_bytes = sec.virtual_size != 0u
            ? std::min(clamped_file_size, sec.virtual_size)
            : clamped_file_size;
        if (span_bytes == 0u) {
            continue;
        }
        spans.push_back(LinearDisassemblySpan{
            .name = sec.name,
            .virtual_address = sec.virtual_address,
            .file_offset = sec.file_offset,
            .byte_size = span_bytes,
            .executable = true,
            .fallback_data = false,
        });
    }

    if (spans.empty()) {
        for (const peelf::Segment& seg : image.segments()) {
            if (!seg.executable || seg.file_size == 0u || seg.file_offset >= available_size) {
                continue;
            }
            const std::uint64_t clamped_size =
                std::min(seg.file_size, available_size - seg.file_offset);
            if (clamped_size == 0u) {
                continue;
            }
            spans.push_back(LinearDisassemblySpan{
                .name = seg.type == 1u ? "PT_LOAD" : std::format("PT_{}", seg.type),
                .virtual_address = seg.virtual_address,
                .file_offset = seg.file_offset,
                .byte_size = clamped_size,
                .executable = true,
                .fallback_data = false,
            });
        }
    }

    const std::vector<LinearDisassemblySpan> normalized = normalize_spans(spans);
    std::vector<std::uint8_t> owned_bytes(file_bytes.begin(), file_bytes.end());
    auto reader = [normalized, bytes = std::move(owned_bytes)](
                      std::uint64_t va,
                      std::span<std::uint8_t> out) -> std::size_t {
        if (out.empty()) {
            return 0u;
        }
        const auto it = std::upper_bound(
            normalized.begin(),
            normalized.end(),
            va,
            [](std::uint64_t addr, const LinearDisassemblySpan& sp) {
                return addr < sp.virtual_address;
            });
        if (it == normalized.begin()) {
            return 0u;
        }
        const LinearDisassemblySpan& sp = *std::prev(it);
        if (va < sp.virtual_address || va - sp.virtual_address >= sp.byte_size ||
            !sp.file_offset.has_value()) {
            return 0u;
        }
        const std::uint64_t delta = va - sp.virtual_address;
        const std::uint64_t file_off = *sp.file_offset + delta;
        if (file_off >= bytes.size()) {
            return 0u;
        }
        const std::uint64_t max_in_span = sp.byte_size - delta;
        const std::uint64_t max_in_file = static_cast<std::uint64_t>(bytes.size()) - file_off;
        const auto to_copy = static_cast<std::size_t>(
            std::min<std::uint64_t>({static_cast<std::uint64_t>(out.size()), max_in_span, max_in_file}));
        std::copy_n(bytes.data() + static_cast<std::size_t>(file_off), to_copy, out.data());
        return to_copy;
    };

    const std::vector<std::uint64_t> bounds = collect_boundaries(symbols, functions, *mapped_arch);
    const std::vector<ArmThumbRangeHint> hints = extract_arm_thumb_hints(image);
    return configure_synthetic(
        *mapped_arch,
        to_disassembler_endianness(image.endianness()),
        normalized,
        std::move(reader),
        bounds,
        hints,
        revision);
}

bool LinearDisassemblyView::sync_with_model(
    const BinaryModel& model,
    bool thumb_mode,
    bool force_thumb_override) {
    if (!model.has_file()) {
        clear();
        return false;
    }
    const auto mapped_arch = to_disassembler_architecture(model.architecture());
    if (!mapped_arch.has_value()) {
        clear();
        return false;
    }

    const std::uint64_t model_identity =
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&model)) ^
        (model.content_generation() * 0x9E3779B97F4A7C15ULL) ^
        (static_cast<std::uint64_t>(model.active_slice_index()) << 32u) ^
        (model.is_live_process() ? 0xA5A5A5A500000001ULL : 0ULL);

    std::uint64_t snapshot_rev =
        static_cast<std::uint64_t>(model.symbol_index().records().size()) ^
        (static_cast<std::uint64_t>(model.function_index().size()) << 24u);
    if (model.is_live_process()) {
        snapshot_rev ^= (model.memory_map_stamp().snapshot_revision << 8u) ^
                        model.view_base_address() ^
                        (model.view_size() << 4u) ^
                        (model.active_module_index().value_or(0xFFFFu) << 40u) ^
                        (model.active_region_index().value_or(0xFFFFu) << 48u);
    }

    const LinearDisassemblyRevision next_rev{
        .file_generation = model.content_generation(),
        .edit_revision = model.edit_revision(),
        .snapshot_revision = snapshot_rev,
        .thumb_mode = thumb_mode,
        .thumb_mode_forced = force_thumb_override,
    };

    if (configured_ && synced_model_identity_ == model_identity &&
        revision_.snapshot_revision == next_rev.snapshot_revision &&
        revision_.file_generation == next_rev.file_generation) {
        update_revision(next_rev);
        return !chunks_.empty();
    }

    const std::optional<LinearDisassemblySpan> preserved_fallback = fallback_span_;
    std::vector<LinearDisassemblySpan> spans;
    std::vector<ArmThumbRangeHint> hints;

    if (!model.is_live_process()) {
        const peelf::IBinaryImage* img = model.image();
        const std::uint64_t avail = model.view_size();
        if (img != nullptr) {
            hints = extract_arm_thumb_hints(*img);
            for (const peelf::Section& sec : img->sections()) {
                if (!sec.executable || sec.file_size == 0u || sec.file_offset >= avail) {
                    continue;
                }
                const std::uint64_t clamped_file_size = std::min(sec.file_size, avail - sec.file_offset);
                const std::uint64_t span_bytes = sec.virtual_size != 0u
                    ? std::min(clamped_file_size, sec.virtual_size)
                    : clamped_file_size;
                if (span_bytes == 0u) {
                    continue;
                }
                spans.push_back(LinearDisassemblySpan{
                    .name = sec.name,
                    .virtual_address = sec.virtual_address,
                    .file_offset = sec.file_offset,
                    .byte_size = span_bytes,
                    .executable = true,
                    .fallback_data = false,
                });
            }
            if (spans.empty()) {
                for (const peelf::Segment& seg : img->segments()) {
                    if (!seg.executable || seg.file_size == 0u || seg.file_offset >= avail) {
                        continue;
                    }
                    const std::uint64_t clamped_size = std::min(seg.file_size, avail - seg.file_offset);
                    if (clamped_size == 0u) {
                        continue;
                    }
                    spans.push_back(LinearDisassemblySpan{
                        .name = seg.type == 1u ? "PT_LOAD" : std::format("PT_{}", seg.type),
                        .virtual_address = seg.virtual_address,
                        .file_offset = seg.file_offset,
                        .byte_size = clamped_size,
                        .executable = true,
                        .fallback_data = false,
                    });
                }
            }
        }
    } else {
        if (const peelf::IBinaryImage* img = model.image(); img != nullptr) {
            hints = extract_arm_thumb_hints(*img);
        }
        // Prefer active module executable sections if mapped in live window, plus executable regions.
        if (model.live_target_kind() == LiveViewTargetKind::Module && !model.sections().empty()) {
            for (const SectionInfo& sec : model.sections()) {
                if ((sec.flags & 0x1u) == 0u || sec.size == 0u) {
                    continue;
                }
                spans.push_back(LinearDisassemblySpan{
                    .name = sec.name,
                    .virtual_address = sec.address,
                    .file_offset = model.virtual_address_to_offset(sec.address),
                    .byte_size = sec.size,
                    .executable = true,
                    .fallback_data = false,
                });
            }
        }
        if (spans.empty()) {
            for (const peelf::MemoryRegion& reg : model.memory_regions()) {
                if (!reg.protection.executable || !reg.protection.readable || reg.size() == 0u) {
                    continue;
                }
                const std::string reg_label = !reg.module_name.empty()
                    ? reg.module_name
                    : (!reg.pathname.empty() ? reg.pathname : "[exec]");
                spans.push_back(LinearDisassemblySpan{
                    .name = reg_label,
                    .virtual_address = reg.start_address,
                    .file_offset = model.virtual_address_to_offset(reg.start_address),
                    .byte_size = reg.size(),
                    .executable = true,
                    .fallback_data = false,
                });
            }
        }
    }

    const BinaryModel* model_ptr = &model;
    auto reader = [model_ptr](std::uint64_t va, std::span<std::uint8_t> out) -> std::size_t {
        if (out.empty() || model_ptr == nullptr || !model_ptr->has_file()) {
            return 0u;
        }
        if (!model_ptr->is_live_process()) {
            std::optional<std::uint64_t> off = model_ptr->virtual_address_to_offset(va);
            if (!off.has_value() && va < model_ptr->view_size() && model_ptr->image() == nullptr) {
                off = va;
            }
            if (!off.has_value() || *off >= model_ptr->view_size()) {
                return 0u;
            }
            const std::uint64_t avail = model_ptr->view_size() - *off;
            const auto req = static_cast<std::uint64_t>(out.size());
            const std::uint64_t clamped = std::min(req, avail);
            auto bytes = model_ptr->read_effective_bytes(*off, clamped);
            if (!bytes.has_value() || bytes->empty()) {
                return 0u;
            }
            const std::size_t n = std::min(out.size(), bytes->size());
            std::copy_n(bytes->data(), n, out.data());
            return n;
        }

        auto bytes = model_ptr->read_virtual_bytes(va, out.size());
        if (!bytes.has_value() || bytes->empty()) {
            return 0u;
        }
        const std::size_t n = std::min(out.size(), bytes->size());
        std::copy_n(bytes->data(), n, out.data());
        return n;
    };

    const std::vector<std::uint64_t> bounds = collect_boundaries(
        &model.symbol_index(),
        &model.function_index(),
        *mapped_arch);

    (void)configure_synthetic(
        *mapped_arch,
        to_disassembler_endianness(model.endianness()),
        spans,
        std::move(reader),
        bounds,
        hints,
        next_rev);
    synced_model_identity_ = model_identity;
    if (preserved_fallback.has_value() &&
        !contains_executable_address(preserved_fallback->virtual_address)) {
        set_fallback_span(preserved_fallback);
    }
    return !chunks_.empty();
}

void LinearDisassemblyView::set_fallback_span(std::optional<LinearDisassemblySpan> fallback_span) {
    if (fallback_span.has_value() && fallback_span->byte_size == 0u) {
        fallback_span.reset();
    }
    if (fallback_span_.has_value() == fallback_span.has_value()) {
        if (!fallback_span.has_value() ||
            (fallback_span_->virtual_address == fallback_span->virtual_address &&
             fallback_span_->byte_size == fallback_span->byte_size &&
             fallback_span_->file_offset == fallback_span->file_offset)) {
            return;
        }
    }
    fallback_span_ = std::move(fallback_span);
    if (configured_) {
        rebuild_partitions();
    }
}

void LinearDisassemblyView::clear_fallback_span() noexcept {
    if (!fallback_span_.has_value()) {
        return;
    }
    fallback_span_.reset();
    if (configured_) {
        rebuild_partitions();
    }
}

void LinearDisassemblyView::set_thumb_mode(bool enable, bool force_override) {
    if (revision_.thumb_mode == enable && revision_.thumb_mode_forced == force_override) {
        return;
    }
    revision_.thumb_mode = enable;
    revision_.thumb_mode_forced = force_override;
    if (configured_ && arch_ == Architecture::ARM32) {
        invalidate_decoded_cache(true);
    }
}

void LinearDisassemblyView::clear_thumb_mode_override() {
    if (!revision_.thumb_mode_forced) {
        return;
    }
    revision_.thumb_mode_forced = false;
    if (configured_ && arch_ == Architecture::ARM32) {
        invalidate_decoded_cache(true);
    }
}

bool LinearDisassemblyView::resolve_thumb_at_address(std::uint64_t virtual_address) const noexcept {
    if (arch_ != Architecture::ARM32) {
        return false;
    }
    if (revision_.thumb_mode_forced) {
        return revision_.thumb_mode;
    }
    if ((virtual_address & 1ULL) != 0ULL) {
        return true;
    }
    const std::uint64_t aligned = virtual_address & ~std::uint64_t{1};
    const auto upper = std::upper_bound(
        arm_hints_.begin(),
        arm_hints_.end(),
        aligned,
        [](std::uint64_t addr, const ArmThumbRangeHint& hint) {
            return addr < hint.start_va;
        });
    if (upper != arm_hints_.begin()) {
        const ArmThumbRangeHint& cand = *std::prev(upper);
        if (aligned >= cand.start_va && aligned < cand.end_va) {
            return cand.thumb;
        }
    }
    return revision_.thumb_mode;
}

void LinearDisassemblyView::update_revision(LinearDisassemblyRevision revision) {
    if (revision_ == revision) {
        return;
    }
    const bool rebuild_needed =
        revision.file_generation != revision_.file_generation ||
        revision.snapshot_revision != revision_.snapshot_revision;
    revision_ = revision;
    if (!configured_) {
        return;
    }
    if (rebuild_needed) {
        rebuild_partitions();
    } else {
        invalidate_decoded_cache(true);
    }
}

const LinearDisassemblySpan* LinearDisassemblyView::span_for_address(
    std::uint64_t virtual_address) const noexcept {
    const std::uint64_t addr = normalize_lookup_address(virtual_address);
    const auto upper = std::upper_bound(
        active_spans_.begin(),
        active_spans_.end(),
        addr,
        [](std::uint64_t va, const LinearDisassemblySpan& sp) {
            return va < sp.virtual_address;
        });
    if (upper == active_spans_.begin()) {
        return nullptr;
    }
    const LinearDisassemblySpan& cand = *std::prev(upper);
    if (addr >= cand.virtual_address && addr - cand.virtual_address < cand.byte_size) {
        return &cand;
    }
    return nullptr;
}

bool LinearDisassemblyView::contains_executable_address(std::uint64_t virtual_address) const noexcept {
    const std::uint64_t addr = normalize_lookup_address(virtual_address);
    for (const LinearDisassemblySpan& sp : base_spans_) {
        if (addr >= sp.virtual_address && addr - sp.virtual_address < sp.byte_size) {
            return true;
        }
    }
    return false;
}

std::size_t LinearDisassemblyView::total_rows() const noexcept {
    return chunk_row_offsets_.empty() ? 0u : chunk_row_offsets_.back();
}

void LinearDisassemblyView::rebuild_partitions() {
    chunks_.clear();
    chunk_row_offsets_.clear();
    lru_order_.clear();
    chunk_cache_.clear();

    std::vector<LinearDisassemblySpan> merged = base_spans_;
    if (fallback_span_.has_value()) {
        merged.push_back(*fallback_span_);
        merged = normalize_spans(merged);
    }
    active_spans_ = std::move(merged);
    if (active_spans_.empty()) {
        return;
    }

    const auto target_bytes = static_cast<std::uint64_t>(options_.chunk_target_bytes);
    const bool fixed_4byte_isa =
        arch_ == Architecture::ARM64 ||
        arch_ == Architecture::MIPS32 ||
        arch_ == Architecture::MIPS64 ||
        arch_ == Architecture::PowerPC32 ||
        arch_ == Architecture::PowerPC64;

    for (std::size_t s_idx = 0; s_idx < active_spans_.size(); ++s_idx) {
        const LinearDisassemblySpan& span = active_spans_[s_idx];
        const std::uint64_t span_end = span.virtual_address + span.byte_size;
        std::uint64_t cursor = span.virtual_address;

        while (cursor < span_end) {
            const std::uint64_t remaining = span_end - cursor;
            std::uint64_t cut = span_end;

            if (remaining > target_bytes) {
                cut = cursor + target_bytes;
                const std::size_t align = alignment_for_address(cut);
                if (align > 1u) {
                    const std::uint64_t mask = ~static_cast<std::uint64_t>(align - 1u);
                    cut &= mask;
                    if (cut <= cursor) {
                        cut = std::min(span_end, cursor + static_cast<std::uint64_t>(align));
                    }
                }

                // Snap cut to a nearby known function/symbol boundary if available.
                const std::uint64_t window_lo = cursor + (target_bytes / 2u);
                const std::uint64_t window_hi = std::min(span_end, cursor + target_bytes + (target_bytes / 4u));
                const auto sym_it = std::lower_bound(
                    symbol_boundaries_.begin(),
                    symbol_boundaries_.end(),
                    cut);
                if (sym_it != symbol_boundaries_.end() && *sym_it > cursor && *sym_it <= window_hi) {
                    cut = *sym_it;
                } else if (sym_it != symbol_boundaries_.begin()) {
                    const std::uint64_t prev_sym = *std::prev(sym_it);
                    if (prev_sym >= window_lo && prev_sym > cursor) {
                        cut = prev_sym;
                    }
                }
            }

            const bool exact_boundary =
                cursor == span.virtual_address ||
                fixed_4byte_isa ||
                std::ranges::binary_search(symbol_boundaries_, cursor);

            ChunkDescriptor desc{};
            desc.span_index = s_idx;
            desc.start_va = cursor;
            desc.end_va = cut;
            if (exact_boundary) {
                desc.resolved_start_va = cursor;
            }
            desc.row_count = estimated_rows_for_bytes(cut - cursor, cursor);
            desc.exact_row_count = false;
            chunks_.push_back(desc);

            cursor = cut;
        }
    }

    recompute_row_prefix_sums();
}

void LinearDisassemblyView::recompute_row_prefix_sums() noexcept {
    chunk_row_offsets_.resize(chunks_.size() + 1u);
    std::size_t running = 0u;
    for (std::size_t i = 0; i < chunks_.size(); ++i) {
        chunk_row_offsets_[i] = running;
        running += chunks_[i].row_count;
    }
    chunk_row_offsets_[chunks_.size()] = running;
}

void LinearDisassemblyView::invalidate_decoded_cache(bool reset_row_counts) noexcept {
    lru_order_.clear();
    chunk_cache_.clear();

    const bool fixed_4byte_isa =
        arch_ == Architecture::ARM64 ||
        arch_ == Architecture::MIPS32 ||
        arch_ == Architecture::MIPS64 ||
        arch_ == Architecture::PowerPC32 ||
        arch_ == Architecture::PowerPC64;

    if (reset_row_counts) {
        for (ChunkDescriptor& ch : chunks_) {
            const LinearDisassemblySpan& sp = active_spans_[ch.span_index];
            const bool exact_boundary =
                ch.start_va == sp.virtual_address ||
                fixed_4byte_isa ||
                std::ranges::binary_search(symbol_boundaries_, ch.start_va);
            if (!exact_boundary) {
                ch.resolved_start_va.reset();
            } else {
                ch.resolved_start_va = ch.start_va;
            }
            ch.row_count = estimated_rows_for_bytes(ch.end_va - ch.start_va, ch.start_va);
            ch.exact_row_count = false;
        }
        recompute_row_prefix_sums();
    }
}

std::size_t LinearDisassemblyView::estimated_rows_for_bytes(
    std::uint64_t byte_count,
    std::uint64_t start_va) const noexcept {
    if (byte_count == 0u) {
        return 0u;
    }
    std::uint64_t divisor = 4u;
    switch (arch_) {
        case Architecture::X86_32:
        case Architecture::X86_64:
            divisor = 3u;
            break;
        case Architecture::ARM32:
            divisor = resolve_thumb_at_address(start_va) ? 2u : 4u;
            break;
        case Architecture::RISCV32:
        case Architecture::RISCV64:
            divisor = 3u;
            break;
        case Architecture::ARM64:
        case Architecture::MIPS32:
        case Architecture::MIPS64:
        case Architecture::PowerPC32:
        case Architecture::PowerPC64:
            divisor = 4u;
            break;
    }
    const std::uint64_t est = std::max<std::uint64_t>(1u, (byte_count + divisor - 1u) / divisor);
    return static_cast<std::size_t>(
        std::min<std::uint64_t>(est, static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())));
}

std::size_t LinearDisassemblyView::alignment_for_address(std::uint64_t virtual_address) const noexcept {
    switch (arch_) {
        case Architecture::X86_32:
        case Architecture::X86_64:
            return 1u;
        case Architecture::ARM32:
            return resolve_thumb_at_address(virtual_address) ? 2u : 4u;
        case Architecture::RISCV32:
        case Architecture::RISCV64:
            return 2u;
        case Architecture::ARM64:
        case Architecture::MIPS32:
        case Architecture::MIPS64:
        case Architecture::PowerPC32:
        case Architecture::PowerPC64:
            return 4u;
    }
    return 1u;
}

std::uint64_t LinearDisassemblyView::normalize_lookup_address(
    std::uint64_t virtual_address) const noexcept {
    if (arch_ == Architecture::ARM32) {
        return virtual_address & ~std::uint64_t{1};
    }
    return virtual_address;
}

std::optional<std::size_t> LinearDisassemblyView::chunk_index_for_row(
    std::size_t global_row) const noexcept {
    if (chunks_.empty() || chunk_row_offsets_.empty() || global_row >= chunk_row_offsets_.back()) {
        return std::nullopt;
    }
    const auto upper = std::upper_bound(
        chunk_row_offsets_.begin(),
        chunk_row_offsets_.end() - 1,
        global_row);
    if (upper == chunk_row_offsets_.begin()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(chunk_row_offsets_.begin(), std::prev(upper)));
}

std::optional<std::size_t> LinearDisassemblyView::chunk_index_for_address(
    std::uint64_t virtual_address) const noexcept {
    if (chunks_.empty()) {
        return std::nullopt;
    }
    const std::uint64_t addr = normalize_lookup_address(virtual_address);
    const auto upper = std::upper_bound(
        chunks_.begin(),
        chunks_.end(),
        addr,
        [](std::uint64_t va, const ChunkDescriptor& ch) {
            return va < ch.start_va;
        });
    if (upper == chunks_.begin()) {
        return std::nullopt;
    }
    const auto idx = static_cast<std::size_t>(std::distance(chunks_.begin(), std::prev(upper)));
    if (addr >= chunks_[idx].start_va && addr < chunks_[idx].end_va) {
        return idx;
    }
    return std::nullopt;
}

std::uint64_t LinearDisassemblyView::determine_chunk_effective_start(std::size_t chunk_index) {
    const ChunkDescriptor& ch = chunks_[chunk_index];
    if (ch.resolved_start_va.has_value()) {
        return *ch.resolved_start_va;
    }
    if (chunk_index == 0u || chunks_[chunk_index - 1u].span_index != ch.span_index) {
        chunks_[chunk_index].resolved_start_va = ch.start_va;
        return ch.start_va;
    }

    // If the immediately preceding chunk is already cached, its end is known.
    if (const auto prev_it = chunk_cache_.find(chunk_index - 1u); prev_it != chunk_cache_.end()) {
        const auto& prev_insns = prev_it->second.instructions;
        if (!prev_insns.empty()) {
            const Instruction& last = prev_insns.back();
            const std::uint64_t after_last =
                last.address + static_cast<std::uint64_t>(last.bytes.size());
            const std::uint64_t resolved = std::clamp(after_last, ch.start_va, ch.end_va);
            chunks_[chunk_index].resolved_start_va = resolved;
            return resolved;
        }
    }

    // Forward resynchronization from a bounded lookbehind window in the same span.
    const LinearDisassemblySpan& span = active_spans_[ch.span_index];
    const auto lookbehind = static_cast<std::uint64_t>(options_.resync_lookbehind_bytes);
    std::uint64_t resync_va = (ch.start_va - span.virtual_address > lookbehind)
        ? (ch.start_va - lookbehind)
        : span.virtual_address;

    const std::size_t align = alignment_for_address(resync_va);
    if (align > 1u) {
        const std::uint64_t rem = (resync_va - span.virtual_address) % static_cast<std::uint64_t>(align);
        if (rem != 0u) {
            resync_va += static_cast<std::uint64_t>(align) - rem;
        }
    }

    // Snap resync start forward to any known symbol boundary inside [resync_va, ch.start_va].
    const auto sym_upper = std::upper_bound(
        symbol_boundaries_.begin(),
        symbol_boundaries_.end(),
        ch.start_va);
    if (sym_upper != symbol_boundaries_.begin()) {
        const std::uint64_t sym_va = *std::prev(sym_upper);
        if (sym_va >= resync_va && sym_va <= ch.start_va) {
            resync_va = sym_va;
        }
    }

    if (resync_va >= ch.start_va) {
        return ch.start_va;
    }

    std::uint64_t synced_end = ch.start_va;
    (void)decode_range_raw(
        resync_va,
        ch.start_va,
        span.virtual_address + span.byte_size,
        &synced_end);
    return std::clamp(synced_end, ch.start_va, ch.end_va);
}

std::vector<Instruction> LinearDisassemblyView::decode_range_raw(
    std::uint64_t start_va,
    std::uint64_t stop_va,
    std::uint64_t span_end_va,
    std::uint64_t* out_end_va) const {
    std::vector<Instruction> result;
    if (out_end_va != nullptr) {
        *out_end_va = start_va;
    }
    if (!configured_ || !byte_reader_ || start_va >= stop_va || start_va >= span_end_va) {
        return result;
    }

    const std::uint64_t fetch_end = std::min(
        span_end_va,
        stop_va > std::numeric_limits<std::uint64_t>::max() - kMaxInsnLookaheadBytes
            ? std::numeric_limits<std::uint64_t>::max()
            : (stop_va + kMaxInsnLookaheadBytes));
    if (fetch_end <= start_va) {
        return result;
    }

    const auto fetch_len = static_cast<std::size_t>(fetch_end - start_va);
    std::vector<std::uint8_t> buffer(fetch_len, 0u);
    std::size_t total_read = 0u;
    if (byte_reader_) {
        total_read = byte_reader_(start_va, buffer);
    }
    if (total_read == 0u) {
        return result;
    }
    buffer.resize(total_read);

    bool active_thumb = resolve_thumb_at_address(start_va);
    ScopedCsHandle cs_handle;
    if (!open_capstone_handle(cs_handle, arch_, endian_, active_thumb)) {
        return result;
    }
    const ScopedCsInsn cs_inst(cs_malloc(cs_handle.get()), 1u);
    if (!cs_inst) {
        return result;
    }

    const std::uint64_t readable_end_va = start_va + static_cast<std::uint64_t>(total_read);
    const std::uint64_t target_stop_va = std::min(stop_va, readable_end_va);
    result.reserve(estimated_rows_for_bytes(target_stop_va - start_va, start_va));

    std::uint64_t pc = start_va;
    while (pc < target_stop_va) {
        if (arch_ == Architecture::ARM32) {
            const bool want_thumb = resolve_thumb_at_address(pc);
            if (want_thumb != active_thumb) {
                if (switch_arm_thumb_mode(cs_handle.get(), endian_, want_thumb)) {
                    active_thumb = want_thumb;
                }
            }
        }

        const auto buf_offset = static_cast<std::size_t>(pc - start_va);
        const std::uint8_t* code_ptr = buffer.data() + buf_offset;
        std::size_t code_rem = buffer.size() - buf_offset;
        std::uint64_t iter_pc = pc;

        if (cs_disasm_iter(cs_handle.get(), &code_ptr, &code_rem, &iter_pc, cs_inst.get()) &&
            iter_pc > pc) {
            result.push_back(make_instruction_from_cs(arch_, *cs_inst.get()));
            pc = iter_pc;
            continue;
        }

        // Undecodable byte/word (inline literal pool, jump table data, or padding):
        // emit a bounded .byte directive without skipping past symbol boundaries or stop_va.
        std::size_t step = alignment_for_address(pc);
        const auto rem_to_stop = static_cast<std::size_t>(target_stop_va - pc);
        step = std::min(step, rem_to_stop);

        const auto next_sym = std::upper_bound(
            symbol_boundaries_.begin(),
            symbol_boundaries_.end(),
            pc);
        if (next_sym != symbol_boundaries_.end() && *next_sym > pc && *next_sym < target_stop_va) {
            step = std::min(step, static_cast<std::size_t>(*next_sym - pc));
        }
        step = std::max<std::size_t>(1u, std::min(step, buffer.size() - buf_offset));

        result.push_back(make_data_fallback_instruction(
            pc,
            std::span<const std::uint8_t>(buffer.data() + buf_offset, step)));
        pc += static_cast<std::uint64_t>(step);
    }

    if (out_end_va != nullptr) {
        *out_end_va = pc;
    }
    return result;
}

const LinearDisassemblyView::CachedChunk* LinearDisassemblyView::ensure_chunk_decoded(
    std::size_t chunk_index) {
    if (chunk_index >= chunks_.size()) {
        return nullptr;
    }

    if (const auto hit = chunk_cache_.find(chunk_index); hit != chunk_cache_.end()) {
        ++cache_hits_;
        lru_order_.splice(lru_order_.begin(), lru_order_, hit->second.lru_it);
        return &hit->second;
    }

    ++cache_misses_;
    const std::uint64_t effective_start = determine_chunk_effective_start(chunk_index);
    const ChunkDescriptor& ch_snapshot = chunks_[chunk_index];
    const LinearDisassemblySpan& span = active_spans_[ch_snapshot.span_index];
    const std::uint64_t span_end = span.virtual_address + span.byte_size;

    std::uint64_t actual_end_va = effective_start;
    std::vector<Instruction> decoded = decode_range_raw(
        effective_start,
        ch_snapshot.end_va,
        span_end,
        &actual_end_va);

    bool prefix_sums_dirty = false;
    ChunkDescriptor& ch = chunks_[chunk_index];
    if (!ch.exact_row_count || ch.row_count != decoded.size()) {
        ch.row_count = decoded.size();
        ch.exact_row_count = true;
        prefix_sums_dirty = true;
    }

    // Propagate exact instruction end boundary into adjacent chunk of same span.
    if (chunk_index + 1u < chunks_.size() &&
        chunks_[chunk_index + 1u].span_index == ch.span_index) {
        ChunkDescriptor& next_ch = chunks_[chunk_index + 1u];
        const std::uint64_t next_start = std::clamp(actual_end_va, next_ch.start_va, next_ch.end_va);
        next_ch.resolved_start_va = next_start;

        if (const auto next_cached = chunk_cache_.find(chunk_index + 1u);
            next_cached != chunk_cache_.end() &&
            next_cached->second.decoded_start_va != next_start) {
            lru_order_.erase(next_cached->second.lru_it);
            chunk_cache_.erase(next_cached);
            next_ch.exact_row_count = false;
        }
    }

    if (prefix_sums_dirty) {
        recompute_row_prefix_sums();
    }

    while (chunk_cache_.size() >= options_.max_cached_chunks && !lru_order_.empty()) {
        const std::size_t victim = lru_order_.back();
        lru_order_.pop_back();
        chunk_cache_.erase(victim);
        ++cache_evictions_;
    }

    lru_order_.push_front(chunk_index);
    CachedChunk entry{};
    entry.decoded_start_va = effective_start;
    entry.instructions = std::move(decoded);
    entry.lru_it = lru_order_.begin();
    const auto [ins_it, _] = chunk_cache_.emplace(chunk_index, std::move(entry));
    return &ins_it->second;
}

void LinearDisassemblyView::prepare_row_range(std::size_t start_row, std::size_t row_count) {
    if (chunks_.empty() || row_count == 0u || start_row >= total_rows()) {
        return;
    }
    const auto first_chunk = chunk_index_for_row(start_row);
    if (!first_chunk.has_value()) {
        return;
    }
    const std::size_t max_chunks_to_warm = std::min<std::size_t>(
        options_.max_cached_chunks,
        std::max<std::size_t>(2u, (row_count / 64u) + 3u));
    std::size_t warmed = 0u;
    for (std::size_t ci = *first_chunk; ci < chunks_.size() && warmed < max_chunks_to_warm; ++ci) {
        if (chunk_row_offsets_[ci] >= start_row + row_count) {
            break;
        }
        (void)ensure_chunk_decoded(ci);
        ++warmed;
    }
}

const Instruction* LinearDisassemblyView::instruction_at_row(std::size_t global_row) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        const auto ci = chunk_index_for_row(global_row);
        if (!ci.has_value()) {
            return nullptr;
        }
        const CachedChunk* cached = ensure_chunk_decoded(*ci);
        if (cached == nullptr) {
            return nullptr;
        }
        const std::size_t base_row = chunk_row_offsets_[*ci];
        if (global_row >= base_row && global_row - base_row < cached->instructions.size()) {
            return &cached->instructions[global_row - base_row];
        }
    }
    return nullptr;
}

std::vector<Instruction> LinearDisassemblyView::collect_rows(
    std::size_t start_row,
    std::size_t row_count) {
    std::vector<Instruction> out;
    if (row_count == 0u || chunks_.empty()) {
        return out;
    }
    prepare_row_range(start_row, row_count);
    const std::size_t end_row = std::min(total_rows(), start_row + row_count);
    if (end_row <= start_row) {
        return out;
    }
    out.reserve(end_row - start_row);
    for (std::size_t r = start_row; r < end_row; ++r) {
        if (const Instruction* inst = instruction_at_row(r); inst != nullptr) {
            out.push_back(*inst);
        }
    }
    return out;
}

std::optional<std::size_t> LinearDisassemblyView::find_row_for_address(
    std::uint64_t virtual_address) {
    const std::uint64_t addr = normalize_lookup_address(virtual_address);
    const auto ci = chunk_index_for_address(addr);
    if (!ci.has_value()) {
        return std::nullopt;
    }

    // If addr is right near the start of chunk *ci, an instruction starting at the tail of (*ci - 1)
    // may straddle into chunk *ci. Check (*ci - 1) if in the same span and addr - start_va < 16.
    if (*ci > 0u &&
        chunks_[*ci - 1u].span_index == chunks_[*ci].span_index &&
        addr - chunks_[*ci].start_va < kMaxInsnLookaheadBytes) {
        if (const CachedChunk* prev_cached = ensure_chunk_decoded(*ci - 1u);
            prev_cached != nullptr && !prev_cached->instructions.empty()) {
            const Instruction& tail = prev_cached->instructions.back();
            const std::uint64_t tail_end =
                tail.address + static_cast<std::uint64_t>(tail.bytes.size());
            if (addr >= tail.address && addr < tail_end) {
                return chunk_row_offsets_[*ci - 1u] + prev_cached->instructions.size() - 1u;
            }
        }
    }

    const CachedChunk* cached = ensure_chunk_decoded(*ci);
    if (cached == nullptr || cached->instructions.empty()) {
        return std::nullopt;
    }

    const auto& insns = cached->instructions;
    const auto upper = std::upper_bound(
        insns.begin(),
        insns.end(),
        addr,
        [](std::uint64_t target, const Instruction& item) {
            return target < item.address;
        });
    if (upper != insns.begin()) {
        const auto match_it = std::prev(upper);
        const std::uint64_t end_va =
            match_it->address + static_cast<std::uint64_t>(match_it->bytes.size());
        if (addr >= match_it->address && addr < end_va) {
            const auto local_idx = static_cast<std::size_t>(std::distance(insns.begin(), match_it));
            return chunk_row_offsets_[*ci] + local_idx;
        }
    }
    if (upper != insns.end() && upper->address < chunks_[*ci].end_va) {
        const auto local_idx = static_cast<std::size_t>(std::distance(insns.begin(), upper));
        return chunk_row_offsets_[*ci] + local_idx;
    }
    return std::nullopt;
}

std::optional<Instruction> LinearDisassemblyView::find_instruction_at_address(
    std::uint64_t virtual_address) {
    const auto row = find_row_for_address(virtual_address);
    if (!row.has_value()) {
        return std::nullopt;
    }
    const Instruction* inst = instruction_at_row(*row);
    if (inst == nullptr) {
        return std::nullopt;
    }
    return *inst;
}

std::vector<Instruction> LinearDisassemblyView::decode_window_from_address(
    std::uint64_t virtual_address,
    std::size_t max_instructions) {
    if (max_instructions == 0u) {
        return {};
    }
    const auto row = find_row_for_address(virtual_address);
    if (!row.has_value()) {
        return {};
    }
    return collect_rows(*row, max_instructions);
}

std::vector<Instruction> LinearDisassemblyView::decode_address_range(
    std::uint64_t start_va,
    std::uint64_t end_va) {
    std::vector<Instruction> out;
    if (chunks_.empty() || start_va >= end_va) {
        return out;
    }
    const std::uint64_t norm_start = normalize_lookup_address(start_va);
    for (std::size_t ci = 0; ci < chunks_.size(); ++ci) {
        if (chunks_[ci].end_va <= norm_start) {
            continue;
        }
        if (chunks_[ci].start_va >= end_va) {
            break;
        }
        const CachedChunk* cached = ensure_chunk_decoded(ci);
        if (cached == nullptr) {
            continue;
        }
        for (const Instruction& inst : cached->instructions) {
            if (inst.address < norm_start) {
                continue;
            }
            if (inst.address >= end_va) {
                return out;
            }
            out.push_back(inst);
        }
    }
    return out;
}

} // namespace viewer
