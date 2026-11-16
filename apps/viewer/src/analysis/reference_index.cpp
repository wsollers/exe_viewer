#include "reference_index.hpp"
#include "disasm/disassembler.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <format>
#include <functional>
#include <limits>
#include <new>
#include <optional>
#include <capstone/capstone.h>

namespace viewer {

std::string_view reference_kind_name(ReferenceKind kind) noexcept {
    switch (kind) {
    case ReferenceKind::Call: return "Call";
    case ReferenceKind::Branch: return "Branch";
    case ReferenceKind::Data: return "Data";
    case ReferenceKind::AddressConstant: return "Address constant";
    }
    return "Unknown";
}

std::string_view reference_confidence_name(ReferenceConfidence confidence) noexcept {
    switch (confidence) {
    case ReferenceConfidence::Direct: return "Direct";
    case ReferenceConfidence::IndirectTable: return "Indirect table";
    case ReferenceConfidence::IndirectPointerSlot: return "Pointer slot";
    case ReferenceConfidence::HeuristicConstant: return "Heuristic constant";
    }
    return "Unknown";
}

void AnnotationStore::set(std::uint64_t address, std::string name, std::string comment) {
    if (name.empty() && comment.empty()) records_.erase(address);
    else records_.insert_or_assign(address, Annotation{std::move(name), std::move(comment)});
    ++revision_;
}

const Annotation* AnnotationStore::find(std::uint64_t address) const noexcept {
    const auto it = records_.find(address);
    return it == records_.end() ? nullptr : &it->second;
}

struct ExecutableSpan {
    std::uint64_t virtual_address = 0;
    std::size_t byte_offset = 0;
    std::size_t byte_size = 0;
};

struct ReferenceScanSnapshot {
    peelf::Architecture architecture = peelf::Architecture::Unknown;
    peelf::Endianness endianness = peelf::Endianness::Little;
    bool thumb = false;
    bool truncated_input = false;
    std::vector<std::uint8_t> bytes;
    std::vector<peelf::Section> sections;
    std::vector<peelf::Segment> segments;
    std::vector<ExecutableSpan> executable_spans;
    std::map<std::uint64_t, std::string> pointer_slot_symbols;

    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(std::uint64_t va) const noexcept {
        for (const auto& section : sections) {
            if (section.file_size == 0 || va < section.virtual_address) continue;
            const auto delta = va - section.virtual_address;
            const auto mapped_limit = section.virtual_size != 0
                ? std::min(section.file_size, section.virtual_size)
                : section.file_size;
            if (delta < mapped_limit) {
                return section.file_offset + delta;
            }
        }
        for (const auto& segment : segments) {
            if (segment.file_size == 0 || va < segment.virtual_address) continue;
            const auto delta = va - segment.virtual_address;
            if (delta < segment.file_size) {
                return segment.file_offset + delta;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] bool is_mapped_virtual_address(std::uint64_t va) const noexcept {
        if (virtual_address_to_file_offset(va).has_value()) return true;
        for (const auto& section : sections) {
            const auto span = std::max(section.virtual_size, section.file_size);
            if (span != 0 && va >= section.virtual_address && va - section.virtual_address < span) return true;
        }
        for (const auto& segment : segments) {
            const auto span = std::max(segment.virtual_size, segment.file_size);
            if (span != 0 && va >= segment.virtual_address && va - segment.virtual_address < span) return true;
        }
        return pointer_slot_symbols.contains(va);
    }

    [[nodiscard]] bool is_executable_virtual_address(std::uint64_t va) const noexcept {
        const std::uint64_t align_mask =
            (architecture == peelf::Architecture::X86 || architecture == peelf::Architecture::X86_64) ? 0ULL :
            ((architecture == peelf::Architecture::ARM && thumb) ||
             architecture == peelf::Architecture::RISCV32 ||
             architecture == peelf::Architecture::RISCV64) ? 1ULL : 3ULL;
        if ((va & align_mask) != 0) return false;

        for (const auto& span : executable_spans) {
            if (va >= span.virtual_address && va - span.virtual_address < span.byte_size) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool read_virtual_bytes(std::uint64_t va, std::span<std::uint8_t> out) const noexcept {
        const auto off = virtual_address_to_file_offset(va);
        if (!off || *off > bytes.size() || out.size() > bytes.size() - static_cast<std::size_t>(*off)) {
            return false;
        }
        std::memcpy(out.data(), bytes.data() + static_cast<std::size_t>(*off), out.size());
        return true;
    }

    [[nodiscard]] std::optional<std::string> resolve_slot_symbol(std::uint64_t va) const {
        const auto it = pointer_slot_symbols.find(va);
        if (it == pointer_slot_symbols.end()) return std::nullopt;
        return it->second;
    }
};

namespace {

struct Decoder {
    ScopedCsHandle handle;
};

bool open_decoder(Decoder& decoder, peelf::Architecture arch, peelf::Endianness endian, bool thumb) {
    cs_arch target{};
    unsigned mode = endian == peelf::Endianness::Big
        ? static_cast<unsigned>(CS_MODE_BIG_ENDIAN)
        : static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN);
    switch (arch) {
    case peelf::Architecture::X86: target = CS_ARCH_X86; mode = static_cast<unsigned>(CS_MODE_32); break;
    case peelf::Architecture::X86_64: target = CS_ARCH_X86; mode = static_cast<unsigned>(CS_MODE_64); break;
    case peelf::Architecture::ARM:
        target = CS_ARCH_ARM;
        mode |= thumb ? static_cast<unsigned>(CS_MODE_THUMB) : static_cast<unsigned>(CS_MODE_ARM);
        break;
    case peelf::Architecture::ARM64: target = CS_ARCH_ARM64; break;
    case peelf::Architecture::MIPS32: target = CS_ARCH_MIPS; mode |= static_cast<unsigned>(CS_MODE_MIPS32); break;
    case peelf::Architecture::MIPS64: target = CS_ARCH_MIPS; mode |= static_cast<unsigned>(CS_MODE_MIPS64); break;
    case peelf::Architecture::PowerPC: target = CS_ARCH_PPC; break;
    case peelf::Architecture::PowerPC64: target = CS_ARCH_PPC; mode |= static_cast<unsigned>(CS_MODE_64); break;
    case peelf::Architecture::RISCV32:
        target = CS_ARCH_RISCV;
        mode |= static_cast<unsigned>(CS_MODE_RISCV32) | static_cast<unsigned>(CS_MODE_RISCVC);
        break;
    case peelf::Architecture::RISCV64:
        target = CS_ARCH_RISCV;
        mode |= static_cast<unsigned>(CS_MODE_RISCV64) | static_cast<unsigned>(CS_MODE_RISCVC);
        break;
    default: return false;
    }
    return cs_open(target, static_cast<cs_mode>(mode), decoder.handle.put()) == CS_ERR_OK &&
           cs_option(decoder.handle.get(), CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
}

[[nodiscard]] std::size_t arch_alignment(peelf::Architecture arch, bool thumb) noexcept {
    if (arch == peelf::Architecture::X86 || arch == peelf::Architecture::X86_64) return 1;
    if ((arch == peelf::Architecture::ARM && thumb) ||
        arch == peelf::Architecture::RISCV32 ||
        arch == peelf::Architecture::RISCV64) return 2;
    return 4;
}

[[nodiscard]] int norm_x86_gpr(unsigned reg) noexcept {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: return 0;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: return 1;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: return 2;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: return 3;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 4;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 5;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 6;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 7;
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return 8;
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return 9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
    default: return -1;
    }
}

[[nodiscard]] int norm_arm_gpr(int reg) noexcept {
    switch (reg) {
    case ARM_REG_R0: return 0;
    case ARM_REG_R1: return 1;
    case ARM_REG_R2: return 2;
    case ARM_REG_R3: return 3;
    case ARM_REG_R4: return 4;
    case ARM_REG_R5: return 5;
    case ARM_REG_R6: return 6;
    case ARM_REG_R7: return 7;
    case ARM_REG_R8: return 8;
    case ARM_REG_R9: return 9;
    case ARM_REG_R10: return 10;
    case ARM_REG_R11: return 11;
    case ARM_REG_R12: return 12;
    case ARM_REG_SP: return 13;
    case ARM_REG_LR: return 14;
    case ARM_REG_PC: return 15;
    default: return -1;
    }
}

[[nodiscard]] int norm_arm64_gpr(unsigned reg) noexcept {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return static_cast<int>(reg - ARM64_REG_X0);
    if (reg == ARM64_REG_FP) return 29;
    if (reg == ARM64_REG_LR) return 30;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return static_cast<int>(reg - ARM64_REG_W0);
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return 31;
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return 32;
    return -1;
}

[[nodiscard]] std::uint64_t read_uint_endian(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    std::uint64_t v = 0;
    if (endian == peelf::Endianness::Big) {
        for (std::size_t i = 0; i < width; ++i) v = (v << 8u) | p[i];
    } else {
        for (std::size_t i = 0; i < width; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8u);
    }
    return v;
}

[[nodiscard]] std::int64_t read_sint_endian(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    const std::uint64_t u = read_uint_endian(p, width, endian);
    switch (width) {
    case 1: return static_cast<std::int8_t>(u & 0xFFu);
    case 2: return static_cast<std::int16_t>(u & 0xFFFFu);
    case 4: return static_cast<std::int32_t>(u & 0xFFFFFFFFu);
    default: return static_cast<std::int64_t>(u);
    }
}

[[nodiscard]] std::string format_slot_evidence(std::string_view prefix,
                                               std::uint64_t slot_va,
                                               const std::optional<std::string>& symbol_name) {
    if (symbol_name && !symbol_name->empty()) {
        return std::format("{} [0x{:X}] -> {}", prefix, slot_va, *symbol_name);
    }
    return std::format("{} [0x{:X}]", prefix, slot_va);
}

struct RecentInsn {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    bool is_unconditional_stop = false;

    // Bounds comparison & guard
    int cmp_reg = -1;
    std::uint64_t cmp_imm = 0;
    bool has_cmp_imm = false;
    bool is_unsigned_upper_guard = false;
    bool guard_strict_above = true; // true for ja/bhi (count = imm + 1), false for jae/bhs (count = imm)

    // Register-to-register move tracking (dst <- src)
    int mov_dst = -1;
    int mov_src = -1;

    // x86-64 RIP-relative jump-table pieces
    int lea_rip_dst = -1;
    std::uint64_t lea_rip_target = 0;

    int movsxd_dst = -1;
    int movsxd_base = -1;
    int movsxd_index = -1;
    std::int64_t movsxd_disp = 0;

    int add_reg_dst = -1;
    int add_reg_a = -1;
    int add_reg_b = -1;

    // ARM64 ADRP / ADR / table pieces
    int adr_dst = -1;
    std::uint64_t adr_target = 0;
    bool adr_is_page = false;

    int add_imm_dst = -1;
    int add_imm_base = -1;
    std::uint64_t add_imm_val = 0;

    int ptr_slot_dst = -1;
    std::uint64_t ptr_slot_va = 0;

    int table_load_dst = -1;
    int table_load_base = -1;
    int table_load_index = -1;
    std::uint8_t table_entry_bytes = 0;
    bool table_entry_signed = false;

    int arm64_add_dst = -1;
    int arm64_add_anchor = -1;
    int arm64_add_off = -1;
    unsigned arm64_add_shift = 0;
    bool arm64_add_signed_ext = false;
    std::uint8_t arm64_add_ext_bytes = 0;

    int clobbered_reg = -1;
};

using ReadVaFn = std::function<bool(std::uint64_t va, std::span<std::uint8_t> out)>;
using IsExecVaFn = std::function<bool(std::uint64_t va)>;
using ResolveSlotFn = std::function<std::optional<std::string>(std::uint64_t va)>;

[[nodiscard]] std::optional<std::size_t> find_guarded_case_count(const std::deque<RecentInsn>& history,
                                                                 int idx_reg) noexcept {
    if (idx_reg < 0) return std::nullopt;
    int tracked_idx = idx_reg;
    bool saw_guard = false;
    bool strict_above = true;

    for (auto it = history.rbegin(); it != history.rend(); ++it) {
        if (it->is_unconditional_stop) break;
        if (!saw_guard) {
            if (it->is_unsigned_upper_guard) {
                saw_guard = true;
                strict_above = it->guard_strict_above;
                continue;
            }
            if (it->mov_dst == tracked_idx && it->mov_src >= 0) {
                tracked_idx = it->mov_src;
            }
        } else {
            if (it->has_cmp_imm && it->cmp_reg == tracked_idx) {
                const std::uint64_t count = strict_above ? (it->cmp_imm + 1u) : it->cmp_imm;
                if (count >= 1u && count <= 256u) {
                    return static_cast<std::size_t>(count);
                }
                return std::nullopt;
            }
            if (it->mov_dst == tracked_idx && it->mov_src >= 0) {
                tracked_idx = it->mov_src;
            }
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> resolve_arm64_reg_va(
    const std::deque<RecentInsn>& history,
    std::size_t start_from_back,
    int reg) noexcept {
    if (reg < 0) return std::nullopt;
    std::optional<std::uint64_t> pending_add;
    int target_reg = reg;

    std::size_t idx = 0;
    for (auto it = history.rbegin(); it != history.rend(); ++it, ++idx) {
        if (idx < start_from_back) continue;
        if (it->is_unconditional_stop) break;
        if (it->adr_dst == target_reg) {
            return it->adr_target + pending_add.value_or(0ULL);
        }
        if (!pending_add && it->add_imm_dst == target_reg && it->add_imm_base >= 0) {
            pending_add = it->add_imm_val;
            target_reg = it->add_imm_base;
            continue;
        }
        if (it->clobbered_reg == target_reg) {
            break;
        }
    }
    return std::nullopt;
}

struct SliceScanResult {
    std::size_t bytes_consumed = 0;
    bool decode_incomplete = false;
    bool cancelled = false;
};

SliceScanResult scan_code_slice(
    std::span<const std::uint8_t> bytes,
    std::size_t max_consume_bytes,
    std::uint64_t address,
    peelf::Architecture architecture,
    peelf::Endianness endian,
    bool thumb,
    std::deque<RecentInsn>& history,
    std::vector<Reference>& out_records,
    const ReadVaFn& read_va,
    const IsExecVaFn& is_exec_va,
    const ResolveSlotFn& resolve_slot,
    std::stop_token stop = {}) {

    SliceScanResult status{};
    Decoder decoder;
    if (!open_decoder(decoder, architecture, endian, thumb)) {
        status.decode_incomplete = true;
        return status;
    }
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - address) {
        status.decode_incomplete = true;
        return status;
    }
    const ScopedCsInsn instruction(cs_malloc(decoder.handle.get()), 1u);
    if (!instruction) {
        status.decode_incomplete = true;
        return status;
    }

    const auto* data = bytes.data();
    auto remaining = bytes.size();
    auto pc = address;
    const std::size_t alignment = arch_alignment(architecture, thumb);
    std::size_t step_counter = 0;

    while (remaining > 0 && status.bytes_consumed < max_consume_bytes) {
        if ((++step_counter & 0x3FFu) == 0 && stop.stop_requested()) {
            status.cancelled = true;
            break;
        }

        if (!cs_disasm_iter(decoder.handle.get(), &data, &remaining, &pc, instruction.get())) {
            status.decode_incomplete = true;
            history.clear();
            const auto skip = std::min(remaining, alignment);
            data += skip;
            pc += skip;
            remaining -= skip;
            status.bytes_consumed = bytes.size() - remaining;
            continue;
        }
        status.bytes_consumed = bytes.size() - remaining;

        const auto& insn = *instruction.get();
        const auto& detail = *insn.detail;
        bool call = false;
        bool branch = false;
        bool ret = false;
        for (unsigned i = 0; i < detail.groups_count; ++i) {
            call |= detail.groups[i] == CS_GRP_CALL;
            branch |= detail.groups[i] == CS_GRP_JUMP;
            ret |= detail.groups[i] == CS_GRP_RET || detail.groups[i] == CS_GRP_IRET;
        }

        if (architecture == peelf::Architecture::MIPS32 || architecture == peelf::Architecture::MIPS64) {
            call |= insn.id == MIPS_INS_JAL || insn.id == MIPS_INS_JALX || insn.id == MIPS_INS_BAL;
            branch |= insn.id == MIPS_INS_J || insn.id == MIPS_INS_JR;
        }
        if ((architecture == peelf::Architecture::PowerPC || architecture == peelf::Architecture::PowerPC64) &&
            insn.size == 4) {
            std::uint32_t word = 0;
            for (unsigned i = 0; i < 4; ++i) {
                word |= static_cast<std::uint32_t>(insn.bytes[i])
                     << ((endian == peelf::Endianness::Big ? 3 - i : i) * 8);
            }
            const auto opcode = word >> 26;
            if (opcode == 16 || opcode == 18) {
                branch = true;
                call = (word & 1) != 0;
            }
        }
        if (architecture == peelf::Architecture::RISCV32 || architecture == peelf::Architecture::RISCV64) {
            if (insn.id == RISCV_INS_JAL || insn.id == RISCV_INS_JALR) {
                const auto destination = (static_cast<unsigned>(insn.bytes[0]) >> 7) |
                    ((static_cast<unsigned>(insn.bytes[1]) & 0x0F) << 1);
                call = destination != 0;
                branch = true;
            } else if (insn.id == RISCV_INS_C_J || insn.id == RISCV_INS_C_JR) {
                call = false;
                branch = true;
            }
        }
        if (architecture == peelf::Architecture::ARM &&
            (insn.id == ARM_INS_TBB || insn.id == ARM_INS_TBH)) {
            branch = true;
        }

        const std::string insn_text =
            insn.op_str[0] != '\0' ? (std::string(insn.mnemonic) + " " + insn.op_str) : std::string(insn.mnemonic);

        const auto emit = [&](std::uint64_t target,
                              ReferenceKind kind,
                              ReferenceConfidence confidence = ReferenceConfidence::Direct,
                              std::string evidence = {}) {
            for (auto it = out_records.rbegin(); it != out_records.rend() && it->source == insn.address; ++it) {
                if (it->target == target && it->kind == kind) return;
            }
            out_records.push_back(Reference{
                .source = insn.address,
                .target = target,
                .kind = kind,
                .instruction = insn_text,
                .string_preview = {},
                .confidence = confidence,
                .evidence = std::move(evidence),
            });
        };

        RecentInsn recent{
            .address = insn.address,
            .size = insn.size,
        };

        std::optional<std::uint64_t> immediate;
        const auto scan_immediates = [&](const auto& operands, auto immediate_type) {
            for (unsigned i = 0; i < operands.op_count; ++i) {
                if (operands.operands[i].type == immediate_type) {
                    immediate = static_cast<std::uint64_t>(operands.operands[i].imm);
                    if (!call && !branch) {
                        emit(*immediate, ReferenceKind::AddressConstant, ReferenceConfidence::HeuristicConstant);
                    }
                }
            }
        };

        switch (architecture) {
        case peelf::Architecture::X86:
        case peelf::Architecture::X86_64: {
            const auto& x86 = detail.x86;
            scan_immediates(x86, X86_OP_IMM);

            for (unsigned i = 0; i < x86.op_count; ++i) {
                const auto& operand = x86.operands[i];
                if (operand.type != X86_OP_MEM || operand.mem.index != X86_REG_INVALID ||
                    operand.mem.segment != X86_REG_INVALID) {
                    continue;
                }
                if (operand.mem.base == X86_REG_RIP || operand.mem.base == X86_REG_EIP) {
                    std::optional<std::uint64_t> target_opt;
                    if (operand.mem.base == X86_REG_EIP) {
                        target_opt =
                            (insn.address + insn.size + static_cast<std::uint64_t>(operand.mem.disp)) &
                            0xFFFFFFFFULL;
                    } else if (const auto next_pc = peelf::checked_add_u64(insn.address, insn.size)) {
                        target_opt = peelf::checked_apply_signed_displacement(*next_pc, operand.mem.disp);
                    }
                    if (!target_opt.has_value()) {
                        continue;
                    }
                    const std::uint64_t target = *target_opt;
                    if (call || branch) {
                        emit(target,
                             call ? ReferenceKind::Call : ReferenceKind::Branch,
                             ReferenceConfidence::IndirectPointerSlot,
                             format_slot_evidence("RIP-relative pointer slot", target, resolve_slot(target)));
                    } else {
                        emit(target, ReferenceKind::Data, ReferenceConfidence::Direct);
                        if (insn.id == X86_INS_LEA && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG) {
                            recent.lea_rip_dst = norm_x86_gpr(x86.operands[0].reg);
                            recent.lea_rip_target = target;
                        }
                    }
                } else if (operand.mem.base == X86_REG_INVALID) {
                    auto target = static_cast<std::uint64_t>(operand.mem.disp);
                    if (architecture == peelf::Architecture::X86) target &= 0xFFFFFFFFULL;
                    if (call || branch) {
                        emit(target,
                             call ? ReferenceKind::Call : ReferenceKind::Branch,
                             ReferenceConfidence::IndirectPointerSlot,
                             format_slot_evidence("Indirect pointer slot", target, resolve_slot(target)));
                    } else {
                        emit(target, ReferenceKind::Data, ReferenceConfidence::Direct);
                    }
                }
            }

            if (x86.op_count >= 1 && x86.operands[0].type == X86_OP_REG && insn.id != X86_INS_CMP && insn.id != X86_INS_TEST) {
                recent.clobbered_reg = norm_x86_gpr(x86.operands[0].reg);
            }

            if (insn.id == X86_INS_CMP && x86.op_count == 2 &&
                x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM &&
                x86.operands[1].imm >= 0) {
                recent.cmp_reg = norm_x86_gpr(x86.operands[0].reg);
                recent.cmp_imm = static_cast<std::uint64_t>(x86.operands[1].imm);
                recent.has_cmp_imm = recent.cmp_reg >= 0;
            } else if (insn.id == X86_INS_JA || insn.id == X86_INS_JAE) {
                recent.is_unsigned_upper_guard = true;
                recent.guard_strict_above = (insn.id == X86_INS_JA);
            } else if ((insn.id == X86_INS_MOV || insn.id == X86_INS_MOVZX || insn.id == X86_INS_MOVSXD) &&
                       x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG) {
                recent.mov_dst = norm_x86_gpr(x86.operands[0].reg);
                recent.mov_src = norm_x86_gpr(x86.operands[1].reg);
            } else if ((insn.id == X86_INS_MOVSXD || insn.id == X86_INS_MOVSX) &&
                       x86.op_count == 2 && x86.operands[0].type == X86_OP_REG &&
                       x86.operands[1].type == X86_OP_MEM &&
                       x86.operands[1].mem.scale == 4 &&
                       x86.operands[1].mem.base != X86_REG_INVALID &&
                       x86.operands[1].mem.index != X86_REG_INVALID) {
                recent.movsxd_dst = norm_x86_gpr(x86.operands[0].reg);
                recent.movsxd_base = norm_x86_gpr(x86.operands[1].mem.base);
                recent.movsxd_index = norm_x86_gpr(x86.operands[1].mem.index);
                recent.movsxd_disp = x86.operands[1].mem.disp;
            } else if (insn.id == X86_INS_ADD && x86.op_count == 2 &&
                       x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG) {
                recent.add_reg_dst = norm_x86_gpr(x86.operands[0].reg);
                recent.add_reg_a = recent.add_reg_dst;
                recent.add_reg_b = norm_x86_gpr(x86.operands[1].reg);
            } else if (insn.id == X86_INS_LEA && x86.op_count == 2 &&
                       x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_MEM &&
                       x86.operands[1].mem.base != X86_REG_INVALID &&
                       x86.operands[1].mem.index != X86_REG_INVALID &&
                       x86.operands[1].mem.scale == 1 && x86.operands[1].mem.disp == 0) {
                recent.add_reg_dst = norm_x86_gpr(x86.operands[0].reg);
                recent.add_reg_a = norm_x86_gpr(x86.operands[1].mem.base);
                recent.add_reg_b = norm_x86_gpr(x86.operands[1].mem.index);
            }

            // 1) Guarded absolute x86 / x86-64 jump table: jmp [index * (4|8) + table_va]
            if (insn.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_MEM) {
                const auto& mem = x86.operands[0].mem;
                const std::uint8_t entry_size = x86.operands[0].size;
                if (mem.base == X86_REG_INVALID && mem.index != X86_REG_INVALID &&
                    mem.segment == X86_REG_INVALID && mem.disp >= 0 &&
                    (entry_size == 4 || entry_size == 8) && mem.scale == entry_size) {
                    const int idx_reg = norm_x86_gpr(mem.index);
                    if (const auto count = find_guarded_case_count(history, idx_reg)) {
                        const auto table_va = static_cast<std::uint64_t>(mem.disp);
                        std::vector<std::uint8_t> table_bytes(*count * entry_size);
                        if (read_va(table_va, table_bytes)) {
                            std::vector<std::uint64_t> targets;
                            targets.reserve(*count);
                            for (std::size_t c = 0; c < *count; ++c) {
                                const std::uint64_t target =
                                    read_uint_endian(table_bytes.data() + c * entry_size, entry_size, endian);
                                if (!is_exec_va(target)) { targets.clear(); break; }
                                targets.push_back(target);
                            }
                            if (!targets.empty()) {
                                const std::string ev = std::format(
                                    "Guarded absolute u{} jump table @ 0x{:X} ({} cases)",
                                    static_cast<unsigned>(entry_size * 8u), table_va, *count);
                                for (const auto target : targets) {
                                    emit(target, ReferenceKind::Branch, ReferenceConfidence::IndirectTable, ev);
                                }
                            }
                        }
                    }
                }
            }

            // 2) x86-64 RIP-relative signed 32-bit offset jump table:
            //    lea rBase, [rip + table]; movsxd rOff, dword ptr [rBase + rIdx*4]; add/lea rTarget; jmp rTarget
            if (architecture == peelf::Architecture::X86_64 &&
                insn.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_REG) {
                const int jmp_reg = norm_x86_gpr(x86.operands[0].reg);
                int cand_a = -1;
                int cand_b = -1;
                int matched_base = -1;
                int matched_idx = -1;
                std::int64_t table_extra_disp = 0;
                std::size_t movsxd_hist_pos = 0;
                bool found_movsxd = false;

                std::size_t pos = 0;
                for (auto it = history.rbegin(); it != history.rend(); ++it, ++pos) {
                    if (it->is_unconditional_stop) break;
                    if (cand_a < 0) {
                        if (it->add_reg_dst == jmp_reg && it->add_reg_a >= 0 && it->add_reg_b >= 0) {
                            cand_a = it->add_reg_a;
                            cand_b = it->add_reg_b;
                        } else if (it->clobbered_reg == jmp_reg) {
                            break;
                        }
                    } else {
                        if (it->movsxd_dst >= 0 &&
                            ((it->movsxd_dst == cand_a && it->movsxd_base == cand_b) ||
                             (it->movsxd_dst == cand_b && it->movsxd_base == cand_a))) {
                            matched_base = it->movsxd_base;
                            matched_idx = it->movsxd_index;
                            table_extra_disp = it->movsxd_disp;
                            movsxd_hist_pos = pos;
                            found_movsxd = true;
                            break;
                        }
                    }
                }

                if (found_movsxd && matched_base >= 0 && matched_idx >= 0) {
                    std::optional<std::uint64_t> anchor_va;
                    std::size_t p2 = 0;
                    for (auto it = history.rbegin(); it != history.rend(); ++it, ++p2) {
                        if (p2 <= movsxd_hist_pos) continue;
                        if (it->is_unconditional_stop) break;
                        if (it->lea_rip_dst == matched_base) {
                            anchor_va = it->lea_rip_target;
                            break;
                        }
                        if (it->clobbered_reg == matched_base) break;
                    }

                    // Search for bounds guard before or around lea using a sub-history slice up to movsxd
                    std::deque<RecentInsn> prefix;
                    for (std::size_t k = 0; k + movsxd_hist_pos < history.size(); ++k) {
                        prefix.push_back(history[k]);
                    }
                    const auto count = find_guarded_case_count(prefix, matched_idx);
                    if (anchor_va && count) {
                        const auto table_va =
                            peelf::checked_apply_signed_displacement(*anchor_va, table_extra_disp);
                        const auto table_bytes_len = peelf::checked_mul_u64(*count, 4u);
                        if (table_va && table_bytes_len &&
                            *table_bytes_len <= std::numeric_limits<std::size_t>::max()) {
                            std::vector<std::uint8_t> table_bytes(
                                static_cast<std::size_t>(*table_bytes_len));
                            if (read_va(*table_va, table_bytes)) {
                                std::vector<std::uint64_t> targets;
                                targets.reserve(*count);
                                for (std::size_t c = 0; c < *count; ++c) {
                                    const std::int64_t rel =
                                        read_sint_endian(table_bytes.data() + c * 4u, 4u, endian);
                                    const auto target =
                                        peelf::checked_apply_signed_displacement(*anchor_va, rel);
                                    if (!target || !is_exec_va(*target)) {
                                        targets.clear();
                                        break;
                                    }
                                    targets.push_back(*target);
                                }
                                if (!targets.empty()) {
                                    const std::string ev = std::format(
                                        "RIP-relative i32 jump table @ 0x{:X} ({} cases)",
                                        *table_va,
                                        *count);
                                    for (const auto target : targets) {
                                        emit(target,
                                             ReferenceKind::Branch,
                                             ReferenceConfidence::IndirectTable,
                                             ev);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            recent.is_unconditional_stop =
                ret || insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP;
            break;
        }

        case peelf::Architecture::ARM: {
            const auto& arm = detail.arm;
            scan_immediates(arm, ARM_OP_IMM);
            for (unsigned i = 0; i < arm.op_count; ++i) {
                const auto& op = arm.operands[i];
                if (op.type == ARM_OP_MEM && op.mem.base == ARM_REG_PC && op.mem.index == ARM_REG_INVALID) {
                    emit(((insn.address + (thumb ? 4u : 8u)) & ~std::uint64_t{3}) +
                             static_cast<std::uint64_t>(op.mem.disp),
                         ReferenceKind::Data,
                         ReferenceConfidence::Direct);
                }
            }

            if (insn.id == ARM_INS_CMP && arm.op_count == 2 &&
                arm.operands[0].type == ARM_OP_REG && arm.operands[1].type == ARM_OP_IMM &&
                arm.operands[1].imm >= 0) {
                recent.cmp_reg = norm_arm_gpr(arm.operands[0].reg);
                recent.cmp_imm = static_cast<std::uint64_t>(arm.operands[1].imm);
                recent.has_cmp_imm = recent.cmp_reg >= 0;
            } else if (insn.id == ARM_INS_B && (arm.cc == ARM_CC_HI || arm.cc == ARM_CC_HS)) {
                recent.is_unsigned_upper_guard = true;
                recent.guard_strict_above = (arm.cc == ARM_CC_HI);
            } else if (insn.id == ARM_INS_MOV && arm.op_count == 2 &&
                       arm.operands[0].type == ARM_OP_REG && arm.operands[1].type == ARM_OP_REG) {
                recent.mov_dst = norm_arm_gpr(arm.operands[0].reg);
                recent.mov_src = norm_arm_gpr(arm.operands[1].reg);
            }

            if (thumb && (insn.id == ARM_INS_TBB || insn.id == ARM_INS_TBH) &&
                arm.op_count == 1 && arm.operands[0].type == ARM_OP_MEM &&
                arm.operands[0].mem.base == ARM_REG_PC && arm.operands[0].mem.index != ARM_REG_INVALID) {
                const int idx_reg = norm_arm_gpr(arm.operands[0].mem.index);
                if (const auto count = find_guarded_case_count(history, idx_reg)) {
                    const std::size_t entry_size = (insn.id == ARM_INS_TBH) ? 2u : 1u;
                    const std::uint64_t table_va = insn.address + 4u;
                    std::vector<std::uint8_t> table_bytes(*count * entry_size);
                    if (read_va(table_va, table_bytes)) {
                        std::vector<std::uint64_t> targets;
                        targets.reserve(*count);
                        for (std::size_t c = 0; c < *count; ++c) {
                            const std::uint64_t e =
                                read_uint_endian(table_bytes.data() + c * entry_size, entry_size, endian);
                            const std::uint64_t target = (table_va + e * 2u) & ~std::uint64_t{1};
                            if (!is_exec_va(target)) { targets.clear(); break; }
                            targets.push_back(target);
                        }
                        if (!targets.empty()) {
                            const std::string ev = std::format(
                                "Thumb-2 {} jump table @ 0x{:X} ({} cases)",
                                insn.id == ARM_INS_TBH ? "tbh" : "tbb",
                                table_va,
                                *count);
                            for (const auto target : targets) {
                                emit(target, ReferenceKind::Branch, ReferenceConfidence::IndirectTable, ev);
                            }
                        }
                    }
                }
            }

            recent.is_unconditional_stop =
                ret || (branch && !call && (arm.cc == ARM_CC_AL || arm.cc == ARM_CC_INVALID));
            break;
        }

        case peelf::Architecture::ARM64: {
            const auto& a64 = detail.arm64;
            scan_immediates(a64, ARM64_OP_IMM);

            if (a64.op_count >= 1 && a64.operands[0].type == ARM64_OP_REG &&
                insn.id != ARM64_INS_CMP && insn.id != ARM64_INS_CMN && insn.id != ARM64_INS_TST) {
                const int d = norm_arm64_gpr(a64.operands[0].reg);
                if (d != 31) recent.clobbered_reg = d;
            }

            if ((insn.id == ARM64_INS_CMP && a64.op_count >= 2 &&
                 a64.operands[0].type == ARM64_OP_REG && a64.operands[1].type == ARM64_OP_IMM &&
                 a64.operands[1].imm >= 0) ||
                (insn.id == ARM64_INS_SUBS && a64.op_count >= 3 &&
                 norm_arm64_gpr(a64.operands[0].reg) == 31 &&
                 a64.operands[1].type == ARM64_OP_REG && a64.operands[2].type == ARM64_OP_IMM &&
                 a64.operands[2].imm >= 0)) {
                const unsigned reg_op = (insn.id == ARM64_INS_SUBS) ? 1u : 0u;
                const unsigned imm_op = reg_op + 1u;
                const std::uint64_t shift = a64.operands[imm_op].shift.type == ARM64_SFT_LSL
                    ? a64.operands[imm_op].shift.value : 0u;
                if (shift < 64u) {
                    recent.cmp_reg = norm_arm64_gpr(a64.operands[reg_op].reg);
                    recent.cmp_imm = static_cast<std::uint64_t>(a64.operands[imm_op].imm) << shift;
                    recent.has_cmp_imm = recent.cmp_reg >= 0;
                }
            } else if (insn.id == ARM64_INS_B && (a64.cc == ARM64_CC_HI || a64.cc == ARM64_CC_HS)) {
                recent.is_unsigned_upper_guard = true;
                recent.guard_strict_above = (a64.cc == ARM64_CC_HI);
            } else if (insn.id == ARM64_INS_MOV && a64.op_count == 2 &&
                       a64.operands[0].type == ARM64_OP_REG && a64.operands[1].type == ARM64_OP_REG) {
                recent.mov_dst = norm_arm64_gpr(a64.operands[0].reg);
                recent.mov_src = norm_arm64_gpr(a64.operands[1].reg);
            } else if ((insn.id == ARM64_INS_ADR || insn.id == ARM64_INS_ADRP) &&
                       a64.op_count == 2 && a64.operands[0].type == ARM64_OP_REG &&
                       a64.operands[1].type == ARM64_OP_IMM) {
                recent.adr_dst = norm_arm64_gpr(a64.operands[0].reg);
                recent.adr_target = static_cast<std::uint64_t>(a64.operands[1].imm);
                recent.adr_is_page = (insn.id == ARM64_INS_ADRP);
            } else if (insn.id == ARM64_INS_ADD && a64.op_count == 3 &&
                       a64.operands[0].type == ARM64_OP_REG && a64.operands[1].type == ARM64_OP_REG &&
                       a64.operands[2].type == ARM64_OP_IMM && a64.operands[2].imm >= 0) {
                const std::uint64_t shift = a64.operands[2].shift.type == ARM64_SFT_LSL
                    ? a64.operands[2].shift.value : 0u;
                if (shift < 64u) {
                    recent.add_imm_dst = norm_arm64_gpr(a64.operands[0].reg);
                    recent.add_imm_base = norm_arm64_gpr(a64.operands[1].reg);
                    recent.add_imm_val = static_cast<std::uint64_t>(a64.operands[2].imm) << shift;
                    if (recent.add_imm_val != 0) {
                        if (const auto base_va = resolve_arm64_reg_va(history, 0, recent.add_imm_base)) {
                            if (const auto target_va = peelf::checked_add_u64(*base_va, recent.add_imm_val)) {
                                emit(*target_va, ReferenceKind::Data, ReferenceConfidence::Direct);
                            }
                        }
                    }
                }
            } else if (insn.id == ARM64_INS_ADD && a64.op_count == 3 &&
                       a64.operands[0].type == ARM64_OP_REG &&
                       a64.operands[1].type == ARM64_OP_REG &&
                       a64.operands[2].type == ARM64_OP_REG) {
                recent.arm64_add_dst = norm_arm64_gpr(a64.operands[0].reg);
                recent.arm64_add_anchor = norm_arm64_gpr(a64.operands[1].reg);
                recent.arm64_add_off = norm_arm64_gpr(a64.operands[2].reg);
                recent.arm64_add_shift = a64.operands[2].shift.value;
                switch (a64.operands[2].ext) {
                case ARM64_EXT_SXTB: recent.arm64_add_signed_ext = true; recent.arm64_add_ext_bytes = 1; break;
                case ARM64_EXT_SXTH: recent.arm64_add_signed_ext = true; recent.arm64_add_ext_bytes = 2; break;
                case ARM64_EXT_SXTW: recent.arm64_add_signed_ext = true; recent.arm64_add_ext_bytes = 4; break;
                default: break;
                }
            } else if ((insn.id == ARM64_INS_LDR || insn.id == ARM64_INS_LDRB || insn.id == ARM64_INS_LDRSB ||
                        insn.id == ARM64_INS_LDRH || insn.id == ARM64_INS_LDRSH || insn.id == ARM64_INS_LDRSW) &&
                       a64.op_count == 2 && a64.operands[0].type == ARM64_OP_REG &&
                       a64.operands[1].type == ARM64_OP_MEM) {
                const auto& mem = a64.operands[1].mem;
                if (mem.base != ARM64_REG_INVALID && mem.index == ARM64_REG_INVALID && insn.id == ARM64_INS_LDR) {
                    const int base_r = norm_arm64_gpr(mem.base);
                    if (const auto page_va = resolve_arm64_reg_va(history, 0, base_r)) {
                        if (const auto slot_va =
                                peelf::checked_apply_signed_displacement(*page_va, mem.disp)) {
                            recent.ptr_slot_dst = norm_arm64_gpr(a64.operands[0].reg);
                            recent.ptr_slot_va = *slot_va;
                            if (mem.disp != 0) {
                                emit(*slot_va, ReferenceKind::Data, ReferenceConfidence::Direct);
                            }
                        }
                    }
                } else if (mem.base != ARM64_REG_INVALID && mem.index != ARM64_REG_INVALID && mem.disp == 0) {
                    recent.table_load_dst = norm_arm64_gpr(a64.operands[0].reg);
                    recent.table_load_base = norm_arm64_gpr(mem.base);
                    recent.table_load_index = norm_arm64_gpr(mem.index);
                    switch (insn.id) {
                    case ARM64_INS_LDRB: recent.table_entry_bytes = 1; recent.table_entry_signed = false; break;
                    case ARM64_INS_LDRSB: recent.table_entry_bytes = 1; recent.table_entry_signed = true; break;
                    case ARM64_INS_LDRH: recent.table_entry_bytes = 2; recent.table_entry_signed = false; break;
                    case ARM64_INS_LDRSH: recent.table_entry_bytes = 2; recent.table_entry_signed = true; break;
                    case ARM64_INS_LDRSW: recent.table_entry_bytes = 4; recent.table_entry_signed = true; break;
                    case ARM64_INS_LDR:
                        recent.table_entry_bytes =
                            (a64.operands[0].reg >= ARM64_REG_W0 && a64.operands[0].reg <= ARM64_REG_W30) ? 4 : 8;
                        recent.table_entry_signed = false;
                        break;
                    default: break;
                    }
                }
            }

            // ARM64 indirect call / branch: check pointer slot (ADRP+LDR+BLR/BR) and PC-relative jump table (BR)
            if ((insn.id == ARM64_INS_BLR || insn.id == ARM64_INS_BR) &&
                a64.op_count == 1 && a64.operands[0].type == ARM64_OP_REG) {
                const int target_reg = norm_arm64_gpr(a64.operands[0].reg);
                bool resolved_table = false;

                if (insn.id == ARM64_INS_BR) {
                    // Check PC-relative offset jump table: add xTarget, xAnchor, xOff, shift; ldr* xOff, [xBase, xIdx]
                    std::size_t pos = 0;
                    for (auto it = history.rbegin(); it != history.rend(); ++it, ++pos) {
                        if (it->is_unconditional_stop) break;
                        if (it->arm64_add_dst == target_reg) {
                            const int anchor_r = it->arm64_add_anchor;
                            const int off_r = it->arm64_add_off;
                            const unsigned shift = it->arm64_add_shift;
                            const bool add_signed = it->arm64_add_signed_ext;
                            const std::uint8_t add_ext_bytes = it->arm64_add_ext_bytes;

                            std::size_t load_pos = pos + 1u;
                            for (auto lit = std::next(it); lit != history.rend(); ++lit, ++load_pos) {
                                if (lit->is_unconditional_stop) break;
                                if (lit->table_load_dst == off_r && lit->table_entry_bytes != 0 &&
                                    lit->table_entry_bytes <= 4) {
                                    const auto table_va = resolve_arm64_reg_va(history, load_pos + 1u, lit->table_load_base);
                                    const auto anchor_va = (anchor_r == lit->table_load_base)
                                        ? table_va
                                        : resolve_arm64_reg_va(history, pos + 1u, anchor_r);
                                    std::deque<RecentInsn> prefix;
                                    for (std::size_t k = 0; k + load_pos < history.size(); ++k) {
                                        prefix.push_back(history[k]);
                                    }
                                    const auto count = find_guarded_case_count(prefix, lit->table_load_index);
                                    if (table_va && anchor_va && count && shift < 64u) {
                                        const std::size_t esz = lit->table_entry_bytes;
                                        const bool is_signed = lit->table_entry_signed ||
                                            (add_signed && add_ext_bytes == esz);
                                        const auto table_bytes_len = peelf::checked_mul_u64(*count, esz);
                                        if (table_bytes_len &&
                                            *table_bytes_len <= std::numeric_limits<std::size_t>::max()) {
                                            std::vector<std::uint8_t> table_bytes(
                                                static_cast<std::size_t>(*table_bytes_len));
                                            if (read_va(*table_va, table_bytes)) {
                                                std::vector<std::uint64_t> targets;
                                                targets.reserve(*count);
                                                for (std::size_t c = 0; c < *count; ++c) {
                                                    std::optional<std::uint64_t> target_opt;
                                                    if (is_signed) {
                                                        const auto scaled =
                                                            peelf::checked_scale_signed_displacement(
                                                                read_sint_endian(
                                                                    table_bytes.data() + c * esz, esz, endian),
                                                                shift);
                                                        if (scaled.has_value()) {
                                                            target_opt =
                                                                peelf::checked_apply_signed_displacement(
                                                                    *anchor_va, *scaled);
                                                        }
                                                    } else {
                                                        const std::uint64_t uval = read_uint_endian(
                                                            table_bytes.data() + c * esz, esz, endian);
                                                        if (shift == 0u ||
                                                            uval <= (std::numeric_limits<std::uint64_t>::max() >>
                                                                     shift)) {
                                                            target_opt =
                                                                peelf::checked_add_u64(*anchor_va, uval << shift);
                                                        }
                                                    }
                                                    if (!target_opt || (*target_opt & 3ULL) != 0 ||
                                                        !is_exec_va(*target_opt)) {
                                                        targets.clear();
                                                        break;
                                                    }
                                                    targets.push_back(*target_opt);
                                                }
                                                if (!targets.empty()) {
                                                    const std::string ev = std::format(
                                                        "ARM64 jump table @ 0x{:X} ({} cases)", *table_va, *count);
                                                    for (const auto t : targets) {
                                                        emit(t, ReferenceKind::Branch, ReferenceConfidence::IndirectTable, ev);
                                                    }
                                                    resolved_table = true;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                                if (lit->clobbered_reg == off_r) break;
                            }
                            break;
                        }
                        if (it->table_load_dst == target_reg && it->table_entry_bytes == 8) {
                            const auto table_va = resolve_arm64_reg_va(history, pos + 1u, it->table_load_base);
                            std::deque<RecentInsn> prefix;
                            for (std::size_t k = 0; k + pos < history.size(); ++k) prefix.push_back(history[k]);
                            const auto count = find_guarded_case_count(prefix, it->table_load_index);
                            if (table_va && count) {
                                const auto table_bytes_len = peelf::checked_mul_u64(*count, 8u);
                                if (table_bytes_len &&
                                    *table_bytes_len <= std::numeric_limits<std::size_t>::max()) {
                                    std::vector<std::uint8_t> table_bytes(
                                        static_cast<std::size_t>(*table_bytes_len));
                                    if (read_va(*table_va, table_bytes)) {
                                        std::vector<std::uint64_t> targets;
                                        targets.reserve(*count);
                                        for (std::size_t c = 0; c < *count; ++c) {
                                            const std::uint64_t t =
                                                read_uint_endian(table_bytes.data() + c * 8u, 8u, endian);
                                            if ((t & 3ULL) != 0 || !is_exec_va(t)) { targets.clear(); break; }
                                            targets.push_back(t);
                                        }
                                        if (!targets.empty()) {
                                            const std::string ev = std::format(
                                                "ARM64 u64 jump table @ 0x{:X} ({} cases)", *table_va, *count);
                                            for (const auto t : targets) {
                                                emit(t, ReferenceKind::Branch, ReferenceConfidence::IndirectTable, ev);
                                            }
                                            resolved_table = true;
                                        }
                                    }
                                }
                            }
                            break;
                        }
                        if (it->clobbered_reg == target_reg) break;
                    }
                }

                if (!resolved_table) {
                    for (auto it = history.rbegin(); it != history.rend(); ++it) {
                        if (it->is_unconditional_stop) break;
                        if (it->ptr_slot_dst == target_reg) {
                            emit(it->ptr_slot_va,
                                 insn.id == ARM64_INS_BLR ? ReferenceKind::Call : ReferenceKind::Branch,
                                 ReferenceConfidence::IndirectPointerSlot,
                                 format_slot_evidence("ADRP+LDR pointer slot",
                                                      it->ptr_slot_va,
                                                      resolve_slot(it->ptr_slot_va)));
                            break;
                        }
                        if (it->clobbered_reg == target_reg) break;
                    }
                }
            }

            recent.is_unconditional_stop =
                ret || insn.id == ARM64_INS_BR ||
                (insn.id == ARM64_INS_B && (a64.cc == ARM64_CC_AL || a64.cc == ARM64_CC_INVALID));
            break;
        }

        case peelf::Architecture::MIPS32:
        case peelf::Architecture::MIPS64:
            scan_immediates(detail.mips, MIPS_OP_IMM);
            break;

        case peelf::Architecture::PowerPC:
        case peelf::Architecture::PowerPC64:
            if (insn.id != PPC_INS_BCLR && insn.id != PPC_INS_BCLRL &&
                insn.id != PPC_INS_BCCTR && insn.id != PPC_INS_BCCTRL) {
                scan_immediates(detail.ppc, PPC_OP_IMM);
            }
            break;

        case peelf::Architecture::RISCV32:
        case peelf::Architecture::RISCV64:
            if (insn.id != RISCV_INS_JALR && insn.id != RISCV_INS_C_JR && insn.id != RISCV_INS_C_JALR) {
                scan_immediates(detail.riscv, RISCV_OP_IMM);
                if (immediate && (call || branch)) {
                    *immediate += insn.address;
                    if (architecture == peelf::Architecture::RISCV32) *immediate &= 0xFFFFFFFFULL;
                }
            }
            break;

        default:
            break;
        }

        if ((call || branch) && immediate) {
            emit(*immediate, call ? ReferenceKind::Call : ReferenceKind::Branch, ReferenceConfidence::Direct);
        }

        history.push_back(recent);
        if (history.size() > 16u) {
            history.pop_front();
        }
    }

    return status;
}

void finalize_snapshot_references(const ReferenceScanSnapshot& snapshot, std::vector<Reference>& refs) {
    std::erase_if(refs, [&](const Reference& ref) {
        if (ref.kind == ReferenceKind::Data || ref.kind == ReferenceKind::AddressConstant) {
            return !snapshot.virtual_address_to_file_offset(ref.target).has_value();
        }
        if (ref.confidence == ReferenceConfidence::IndirectPointerSlot) {
            return !snapshot.is_mapped_virtual_address(ref.target);
        }
        return false;
    });

    for (auto& ref : refs) {
        if (ref.kind == ReferenceKind::Call || ref.kind == ReferenceKind::Branch) continue;
        const auto offset = snapshot.virtual_address_to_file_offset(ref.target);
        if (!offset || *offset >= snapshot.bytes.size()) continue;
        std::string preview;
        const auto limit = std::min<std::size_t>(snapshot.bytes.size() - static_cast<std::size_t>(*offset), 128u);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto ch = snapshot.bytes[static_cast<std::size_t>(*offset) + i];
            if (!ch) {
                if (preview.size() >= 4u) ref.string_preview = std::move(preview);
                break;
            }
            if (ch < 32 || ch > 126) break;
            preview.push_back(static_cast<char>(ch));
        }
    }
}

std::shared_ptr<ReferenceScanSnapshot> build_scan_snapshot(const peelf::IBinaryImage& image,
                                                           std::vector<std::uint8_t> bytes,
                                                           bool thumb,
                                                           const SymbolIndex* symbols,
                                                           std::size_t& out_total_exec_bytes) {
    auto snap = std::make_shared<ReferenceScanSnapshot>();
    snap->architecture = image.architecture();
    snap->endianness = image.endianness();
    snap->thumb = thumb;
    snap->bytes = std::move(bytes);
    snap->sections = image.sections();
    snap->segments = image.segments();

    for (const auto& imp : image.imports()) {
        if (imp.address == 0) continue;
        std::string label = imp.library;
        if (!imp.name.empty()) {
            if (!label.empty()) label += '!';
            label += imp.name;
        }
        if (!label.empty()) snap->pointer_slot_symbols.emplace(imp.address, std::move(label));
    }
    std::vector<const peelf::ElfSymbol*> dynsyms;
    for (const auto& es : image.elf_symbols()) {
        if (es.dynamic) dynsyms.push_back(&es);
    }
    for (const auto& rel : image.elf_relocations()) {
        if (rel.offset != 0 && rel.symbol_index < dynsyms.size() && !dynsyms[rel.symbol_index]->name.empty()) {
            snap->pointer_slot_symbols.try_emplace(rel.offset, dynsyms[rel.symbol_index]->name);
        }
    }
    if (symbols != nullptr) {
        for (const auto& sym : symbols->records()) {
            if (sym.virtual_address && !sym.name.empty()) {
                snap->pointer_slot_symbols.try_emplace(*sym.virtual_address, sym.name);
            }
        }
    }

    out_total_exec_bytes = 0;
    for (const auto& section : snap->sections) {
        if (!section.executable || section.file_size == 0) continue;
        const auto declared = static_cast<std::size_t>(
            std::min<std::uint64_t>(section.file_size, std::numeric_limits<std::size_t>::max() - out_total_exec_bytes));
        out_total_exec_bytes += declared;
        if (section.file_offset >= snap->bytes.size()) {
            snap->truncated_input = true;
            continue;
        }
        const auto available = std::min<std::uint64_t>(section.file_size, snap->bytes.size() - section.file_offset);
        if (available < section.file_size) {
            snap->truncated_input = true;
        }
        if (available > 0) {
            snap->executable_spans.push_back(ExecutableSpan{
                .virtual_address = section.virtual_address,
                .byte_offset = static_cast<std::size_t>(section.file_offset),
                .byte_size = static_cast<std::size_t>(available),
            });
        }
    }

    if (out_total_exec_bytes == 0 && snap->executable_spans.empty()) {
        for (const auto& segment : snap->segments) {
            if (!segment.executable || segment.file_size == 0) continue;
            const auto declared = static_cast<std::size_t>(
                std::min<std::uint64_t>(segment.file_size, std::numeric_limits<std::size_t>::max() - out_total_exec_bytes));
            out_total_exec_bytes += declared;
            if (segment.file_offset >= snap->bytes.size()) {
                snap->truncated_input = true;
                continue;
            }
            const auto available = std::min<std::uint64_t>(segment.file_size, snap->bytes.size() - segment.file_offset);
            if (available < segment.file_size) {
                snap->truncated_input = true;
            }
            if (available > 0) {
                snap->executable_spans.push_back(ExecutableSpan{
                    .virtual_address = segment.virtual_address,
                    .byte_offset = static_cast<std::size_t>(segment.file_offset),
                    .byte_size = static_cast<std::size_t>(available),
                });
            }
        }
    }

    return snap;
}

} // namespace

void ReferenceIndex::add_code(std::span<const std::uint8_t> bytes,
                              std::uint64_t address,
                              peelf::Architecture architecture,
                              peelf::Endianness endian,
                              bool thumb) {
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - address) {
        incomplete_ = true;
        return;
    }

    total_executable_bytes_ += bytes.size();
    std::deque<RecentInsn> history;

    const ReadVaFn read_va = [bytes, address](std::uint64_t va, std::span<std::uint8_t> out) -> bool {
        if (va < address) return false;
        const auto off = va - address;
        if (off > bytes.size() || out.size() > bytes.size() - static_cast<std::size_t>(off)) return false;
        std::memcpy(out.data(), bytes.data() + static_cast<std::size_t>(off), out.size());
        return true;
    };
    const std::size_t align = arch_alignment(architecture, thumb);
    const IsExecVaFn is_exec_va = [bytes, address, align](std::uint64_t va) -> bool {
        if ((va & (align - 1u)) != 0) return false;
        return va >= address && va - address < bytes.size();
    };
    const ResolveSlotFn resolve_slot = [](std::uint64_t) -> std::optional<std::string> {
        return std::nullopt;
    };

    const auto slice = scan_code_slice(
        bytes, bytes.size(), address, architecture, endian, thumb,
        history, records_, read_va, is_exec_va, resolve_slot);

    scanned_bytes_ += slice.bytes_consumed;
    incomplete_ |= slice.decode_incomplete || (slice.bytes_consumed < bytes.size());
    lookup_dirty_ = true;
    ++revision_;
}

void ReferenceIndex::reset_for_progressive_scan(std::size_t total_executable_bytes, bool scanning) {
    records_.clear();
    by_target_.clear();
    by_source_.clear();
    lookup_dirty_ = false;
    total_executable_bytes_ = total_executable_bytes;
    scanned_bytes_ = 0;
    is_scanning_ = scanning;
    incomplete_ = total_executable_bytes > 0 && scanning;
    ++revision_;
}

void ReferenceIndex::append_chunk(ReferenceScanChunk&& chunk) {
    scanned_bytes_ += chunk.bytes_scanned;
    if (!chunk.references.empty()) {
        records_.insert(records_.end(),
                        std::make_move_iterator(chunk.references.begin()),
                        std::make_move_iterator(chunk.references.end()));
        lookup_dirty_ = true;
    }
    if (chunk.finished) {
        is_scanning_ = false;
        incomplete_ = chunk.incomplete;
    } else {
        incomplete_ = chunk.incomplete || (scanned_bytes_ < total_executable_bytes_);
    }
    ++revision_;
}

void ReferenceIndex::set_scanning(bool scanning) noexcept {
    if (is_scanning_ != scanning) {
        is_scanning_ = scanning;
        ++revision_;
    }
}

void ReferenceIndex::mark_failed_incomplete() noexcept {
    is_scanning_ = false;
    incomplete_ = true;
    ++revision_;
}

double ReferenceIndex::coverage_percent() const noexcept {
    if (total_executable_bytes_ == 0) {
        return incomplete_ ? 0.0 : 100.0;
    }
    const double pct = (100.0 * static_cast<double>(scanned_bytes_)) / static_cast<double>(total_executable_bytes_);
    return std::clamp(pct, 0.0, 100.0);
}

void ReferenceIndex::ensure_lookup_indices() const {
    if (!lookup_dirty_) return;
    by_target_.clear();
    by_source_.clear();
    by_target_.reserve(records_.size());
    by_source_.reserve(records_.size());
    for (std::size_t idx = 0; idx < records_.size(); ++idx) {
        by_target_.emplace_back(records_[idx].target, idx);
        by_source_.emplace_back(records_[idx].source, idx);
    }
    std::ranges::sort(by_target_);
    std::ranges::sort(by_source_);
    lookup_dirty_ = false;
}

std::vector<const Reference*> ReferenceIndex::incoming(std::uint64_t address, std::uint64_t size) const {
    ensure_lookup_indices();
    const std::uint64_t span = std::max<std::uint64_t>(size, 1u);
    auto it = std::ranges::lower_bound(by_target_, std::pair<std::uint64_t, std::size_t>{address, 0u});
    std::vector<std::size_t> matched_indices;
    for (; it != by_target_.end() && (it->first - address) < span; ++it) {
        matched_indices.push_back(it->second);
    }
    if (matched_indices.size() > 1u) {
        std::ranges::sort(matched_indices);
    }
    std::vector<const Reference*> result;
    result.reserve(matched_indices.size());
    for (const std::size_t idx : matched_indices) {
        result.push_back(&records_[idx]);
    }
    return result;
}

std::vector<const Reference*> ReferenceIndex::outgoing(std::uint64_t address, std::uint64_t size) const {
    ensure_lookup_indices();
    const std::uint64_t span = std::max<std::uint64_t>(size, 1u);
    auto it = std::ranges::lower_bound(by_source_, std::pair<std::uint64_t, std::size_t>{address, 0u});
    std::vector<std::size_t> matched_indices;
    for (; it != by_source_.end() && (it->first - address) < span; ++it) {
        matched_indices.push_back(it->second);
    }
    if (matched_indices.size() > 1u) {
        std::ranges::sort(matched_indices);
    }
    std::vector<const Reference*> result;
    result.reserve(matched_indices.size());
    for (const std::size_t idx : matched_indices) {
        result.push_back(&records_[idx]);
    }
    return result;
}

ReferenceIndex ReferenceIndex::build(const peelf::IBinaryImage& image,
                                     std::span<const std::uint8_t> bytes,
                                     bool thumb,
                                     std::size_t byte_budget,
                                     const SymbolIndex* symbols) {
    ReferenceIndex result;
    ReferenceScanJob job(
        image,
        std::vector<std::uint8_t>(bytes.begin(), bytes.end()),
        thumb,
        byte_budget,
        symbols,
        kDefaultChunkBytes);
    job.run(result);
    return result;
}

ReferenceScanJob::ReferenceScanJob(const peelf::IBinaryImage& image,
                                   std::vector<std::uint8_t> bytes,
                                   bool thumb,
                                   std::size_t byte_budget,
                                   const SymbolIndex* symbols,
                                   std::size_t chunk_bytes)
    : chunk_bytes_(std::max<std::size_t>(chunk_bytes, 1u))
    , byte_budget_(byte_budget) {
    snapshot_ = build_scan_snapshot(image, std::move(bytes), thumb, symbols, total_executable_bytes_);
    finished_ = snapshot_->executable_spans.empty() || byte_budget_ == 0;
}

void ReferenceScanJob::set_byte_budget(std::size_t byte_budget) noexcept {
    byte_budget_ = byte_budget;
    if (snapshot_ && span_index_ < snapshot_->executable_spans.size() && scanned_bytes_ < byte_budget_) {
        finished_ = false;
    }
}

bool ReferenceScanJob::incomplete() const noexcept {
    if (!snapshot_) return false;
    return snapshot_->truncated_input || decode_incomplete_ || (scanned_bytes_ < total_executable_bytes_);
}

std::optional<ReferenceScanChunk> ReferenceScanJob::step(std::stop_token stop) {
    if (stop.stop_requested()) {
        return std::nullopt;
    }
    if (!snapshot_ || finished_ || span_index_ >= snapshot_->executable_spans.size() || scanned_bytes_ >= byte_budget_) {
        finished_ = true;
        return ReferenceScanChunk{
            .references = {},
            .bytes_scanned = 0,
            .decode_incomplete = decode_incomplete_,
            .finished = true,
            .incomplete = incomplete(),
        };
    }

    const auto& span = snapshot_->executable_spans[span_index_];
    const std::size_t remaining_in_span = span.byte_size - offset_in_span_;
    const std::size_t remaining_budget = byte_budget_ - scanned_bytes_;
    const std::size_t target_consume = std::min({chunk_bytes_, remaining_in_span, remaining_budget});

    // Provide up to 15 bytes of instruction lookahead within the remaining span & budget
    // so variable-length instructions at 256 KiB chunk boundaries decode intact without exceeding byte_budget_.
    const std::size_t max_allowed = std::min(remaining_in_span, remaining_budget);
    const std::size_t lookahead_cap = std::min(max_allowed, target_consume + 15u);
    const std::span<const std::uint8_t> slice_bytes(
        snapshot_->bytes.data() + span.byte_offset + offset_in_span_,
        lookahead_cap);
    const std::uint64_t slice_va = span.virtual_address + offset_in_span_;

    // Seed small context window from up to 64 preceding bytes in the same span when resuming mid-span
    // so jump-table sequences straddling a 256 KiB chunk boundary still recover cleanly.
    std::deque<RecentInsn> history;
    if (offset_in_span_ > 0) {
        const std::size_t warmup = std::min<std::size_t>(offset_in_span_, 64u);
        const std::size_t align = arch_alignment(snapshot_->architecture, snapshot_->thumb);
        const std::size_t aligned_warmup = (warmup / align) * align;
        if (aligned_warmup > 0) {
            std::vector<Reference> discarded;
            const std::span<const std::uint8_t> warm_bytes(
                snapshot_->bytes.data() + span.byte_offset + (offset_in_span_ - aligned_warmup),
                aligned_warmup);
            (void)scan_code_slice(
                warm_bytes,
                aligned_warmup,
                slice_va - aligned_warmup,
                snapshot_->architecture,
                snapshot_->endianness,
                snapshot_->thumb,
                history,
                discarded,
                [](std::uint64_t, std::span<std::uint8_t>) { return false; },
                [](std::uint64_t) { return false; },
                [](std::uint64_t) -> std::optional<std::string> { return std::nullopt; });
        }
    }

    const ReadVaFn read_va = [snap = snapshot_.get()](std::uint64_t va, std::span<std::uint8_t> out) {
        return snap->read_virtual_bytes(va, out);
    };
    const IsExecVaFn is_exec_va = [snap = snapshot_.get()](std::uint64_t va) {
        return snap->is_executable_virtual_address(va);
    };
    const ResolveSlotFn resolve_slot = [snap = snapshot_.get()](std::uint64_t va) {
        return snap->resolve_slot_symbol(va);
    };

    ReferenceScanChunk chunk{};
    const auto res = scan_code_slice(
        slice_bytes,
        target_consume,
        slice_va,
        snapshot_->architecture,
        snapshot_->endianness,
        snapshot_->thumb,
        history,
        chunk.references,
        read_va,
        is_exec_va,
        resolve_slot,
        stop);

    if (res.cancelled) {
        return std::nullopt;
    }

    finalize_snapshot_references(*snapshot_, chunk.references);

    const std::size_t advance = res.bytes_consumed > 0 ? res.bytes_consumed : target_consume;
    offset_in_span_ += advance;
    scanned_bytes_ += advance;
    decode_incomplete_ |= res.decode_incomplete || (res.bytes_consumed < target_consume);

    if (offset_in_span_ >= span.byte_size) {
        ++span_index_;
        offset_in_span_ = 0;
    }
    if (span_index_ >= snapshot_->executable_spans.size() || scanned_bytes_ >= byte_budget_) {
        finished_ = true;
    }

    chunk.bytes_scanned = advance;
    chunk.decode_incomplete = decode_incomplete_;
    chunk.finished = finished_;
    chunk.incomplete = incomplete();
    return chunk;
}

bool ReferenceScanJob::run(ReferenceIndex& target, std::stop_token stop) {
    if (scanned_bytes_ == 0 && target.records().empty()) {
        target.reset_for_progressive_scan(total_executable_bytes_, true);
    } else {
        target.set_scanning(true);
    }

    if (finished_) {
        ReferenceScanChunk terminal{
            .references = {},
            .bytes_scanned = 0,
            .decode_incomplete = decode_incomplete_,
            .finished = true,
            .incomplete = incomplete(),
        };
        target.append_chunk(std::move(terminal));
        return true;
    }

    while (!finished_) {
        auto chunk = step(stop);
        if (!chunk) {
            target.set_scanning(false);
            return false;
        }
        target.append_chunk(std::move(*chunk));
    }
    return true;
}

AsyncReferenceScanner::~AsyncReferenceScanner() noexcept {
    cancel();
}

void AsyncReferenceScanner::start(ReferenceIndex& target,
                                  const peelf::IBinaryImage& image,
                                  std::vector<std::uint8_t> bytes,
                                  bool thumb,
                                  std::size_t byte_budget,
                                  const SymbolIndex* symbols,
                                  std::size_t chunk_bytes) {
    cancel();

    ReferenceScanJob next_job(image, std::move(bytes), thumb, byte_budget, symbols, chunk_bytes);
    const std::size_t total_exec = next_job.total_executable_bytes();
    const bool already_finished = next_job.finished();
    const bool incomp = next_job.incomplete();

    std::string reserved_error;
    reserved_error.reserve(128u);

    target.reset_for_progressive_scan(total_exec, !already_finished);
    std::uint64_t gen = 0;
    {
        std::scoped_lock lock(mutex_);
        pending_chunks_.clear();
        last_error_ = std::move(reserved_error);
        job_ = std::move(next_job);
        desired_budget_ = byte_budget;
        job_scanned_bytes_ = 0;
        job_total_bytes_ = total_exec;
        job_finished_ = already_finished;
        worker_failed_ = false;
        pending_failure_incomplete_ = false;
        gen = ++generation_;
        paused_.store(false, std::memory_order_release);
        active_.store(!already_finished, std::memory_order_release);
    }

    if (already_finished) {
        ReferenceScanChunk empty_done{
            .references = {},
            .bytes_scanned = 0,
            .decode_incomplete = false,
            .finished = true,
            .incomplete = incomp,
        };
        target.append_chunk(std::move(empty_done));
        return;
    }

    struct LaunchRollbackGuard {
        AsyncReferenceScanner* self;
        ReferenceIndex* target_index;
        bool committed{false};
        ~LaunchRollbackGuard() noexcept {
            if (!committed) {
                {
                    std::scoped_lock lock(self->mutex_);
                    self->job_finished_ = true;
                    self->paused_.store(false, std::memory_order_release);
                    self->active_.store(false, std::memory_order_release);
                }
                target_index->mark_failed_incomplete();
                self->cv_.notify_all();
            }
        }
    } launch_guard{this, &target};

    worker_ = std::jthread([this, gen](std::stop_token stop) noexcept {
        try {
            worker_loop(stop, gen);
        } catch (const std::bad_alloc&) {
            record_worker_failure(gen, /*is_oom=*/true, nullptr);
        } catch (const std::exception& e) {
            record_worker_failure(gen, /*is_oom=*/false, e.what());
        } catch (...) {
            record_worker_failure(gen, /*is_oom=*/false, nullptr);
        }
    });
    launch_guard.committed = true;
}

void AsyncReferenceScanner::pause() {
    {
        std::scoped_lock lock(mutex_);
        if (!active_.load(std::memory_order_acquire)) return;
        paused_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
}

void AsyncReferenceScanner::resume(ReferenceIndex& target) {
    std::string reserved_error;
    reserved_error.reserve(128u);

    std::jthread finished_worker;
    std::uint64_t new_gen = 0;
    bool spawn_worker = false;
    bool woke = false;
    bool prev_paused = false;
    {
        std::scoped_lock lock(mutex_);
        if (!job_finished_ && job_scanned_bytes_ < job_total_bytes_) {
            const bool was_active = active_.load(std::memory_order_acquire);
            prev_paused = paused_.load(std::memory_order_acquire);
            if (last_error_.capacity() < 128u) {
                last_error_ = std::move(reserved_error);
            } else {
                last_error_.clear();
            }
            worker_failed_ = false;
            pending_failure_incomplete_ = false;
            paused_.store(false, std::memory_order_release);
            active_.store(true, std::memory_order_release);
            woke = true;
            if (!was_active) {
                finished_worker = std::move(worker_);
                new_gen = ++generation_;
                spawn_worker = true;
            }
        }
    }

    struct LaunchRollbackGuard {
        AsyncReferenceScanner* self;
        ReferenceIndex* target_index;
        bool restore_paused{false};
        bool armed{false};
        bool committed{false};
        ~LaunchRollbackGuard() noexcept {
            if (armed && !committed) {
                {
                    std::scoped_lock lock(self->mutex_);
                    self->paused_.store(restore_paused, std::memory_order_release);
                    self->active_.store(false, std::memory_order_release);
                }
                target_index->set_scanning(false);
                self->cv_.notify_all();
            }
        }
    } launch_guard{this, &target, prev_paused, spawn_worker, false};

    if (finished_worker.joinable()) {
        finished_worker.request_stop();
        cv_.notify_all();
        finished_worker.join();
    }
    if (spawn_worker) {
        worker_ = std::jthread([this, new_gen](std::stop_token stop) noexcept {
            try {
                worker_loop(stop, new_gen);
            } catch (const std::bad_alloc&) {
                record_worker_failure(new_gen, /*is_oom=*/true, nullptr);
            } catch (const std::exception& e) {
                record_worker_failure(new_gen, /*is_oom=*/false, e.what());
            } catch (...) {
                record_worker_failure(new_gen, /*is_oom=*/false, nullptr);
            }
        });
        launch_guard.committed = true;
    }
    if (woke) {
        target.set_scanning(true);
        cv_.notify_all();
    }
}

void AsyncReferenceScanner::scan_full(ReferenceIndex& target) {
    std::string reserved_error;
    reserved_error.reserve(128u);

    std::jthread finished_worker;
    std::uint64_t new_gen = 0;
    bool spawn_worker = false;
    bool woke = false;
    bool prev_paused = false;
    bool prev_finished = true;
    std::size_t prev_budget = 0;
    {
        std::scoped_lock lock(mutex_);
        prev_budget = desired_budget_;
        prev_finished = job_finished_;
        desired_budget_ = std::numeric_limits<std::size_t>::max();
        if (job_scanned_bytes_ < job_total_bytes_) {
            const bool was_active = active_.load(std::memory_order_acquire);
            prev_paused = paused_.load(std::memory_order_acquire);
            if (last_error_.capacity() < 128u) {
                last_error_ = std::move(reserved_error);
            } else {
                last_error_.clear();
            }
            worker_failed_ = false;
            pending_failure_incomplete_ = false;
            job_finished_ = false;
            paused_.store(false, std::memory_order_release);
            active_.store(true, std::memory_order_release);
            woke = true;
            if (!was_active) {
                finished_worker = std::move(worker_);
                new_gen = ++generation_;
                spawn_worker = true;
            }
        }
    }

    struct LaunchRollbackGuard {
        AsyncReferenceScanner* self;
        ReferenceIndex* target_index;
        std::size_t restore_budget{0};
        bool restore_finished{true};
        bool restore_paused{false};
        bool armed{false};
        bool committed{false};
        ~LaunchRollbackGuard() noexcept {
            if (armed && !committed) {
                {
                    std::scoped_lock lock(self->mutex_);
                    self->desired_budget_ = restore_budget;
                    self->job_finished_ = restore_finished;
                    self->paused_.store(restore_paused, std::memory_order_release);
                    self->active_.store(false, std::memory_order_release);
                }
                target_index->set_scanning(false);
                self->cv_.notify_all();
            }
        }
    } launch_guard{this, &target, prev_budget, prev_finished, prev_paused, spawn_worker, false};

    if (finished_worker.joinable()) {
        finished_worker.request_stop();
        cv_.notify_all();
        finished_worker.join();
    }
    if (spawn_worker) {
        worker_ = std::jthread([this, new_gen](std::stop_token stop) noexcept {
            try {
                worker_loop(stop, new_gen);
            } catch (const std::bad_alloc&) {
                record_worker_failure(new_gen, /*is_oom=*/true, nullptr);
            } catch (const std::exception& e) {
                record_worker_failure(new_gen, /*is_oom=*/false, e.what());
            } catch (...) {
                record_worker_failure(new_gen, /*is_oom=*/false, nullptr);
            }
        });
        launch_guard.committed = true;
    }
    if (woke) {
        target.set_scanning(true);
        cv_.notify_all();
    }
}

void AsyncReferenceScanner::cancel(ReferenceIndex* target) noexcept {
    if (worker_.joinable()) {
        worker_.request_stop();
        cv_.notify_all();
        try {
            worker_.join();
        } catch (...) {
        }
    }
    {
        std::scoped_lock lock(mutex_);
        pending_chunks_.clear();
        pending_failure_incomplete_ = false;
        paused_.store(false, std::memory_order_release);
        active_.store(false, std::memory_order_release);
    }
    if (target != nullptr) {
        target->set_scanning(false);
    }
}

std::size_t AsyncReferenceScanner::poll(ReferenceIndex& target) {
    std::deque<ReferenceScanChunk> ready;
    bool now_paused = false;
    bool now_active = false;
    bool mark_failed = false;
    {
        std::scoped_lock lock(mutex_);
        ready.swap(pending_chunks_);
        mark_failed = std::exchange(pending_failure_incomplete_, false);
        now_paused = paused_.load(std::memory_order_acquire);
        now_active = active_.load(std::memory_order_acquire);
    }
    const std::size_t count = ready.size();
    while (!ready.empty()) {
        target.append_chunk(std::move(ready.front()));
        ready.pop_front();
    }
    if (mark_failed) {
        target.mark_failed_incomplete();
    } else if (now_paused || !now_active) {
        target.set_scanning(false);
    }
    return count;
}

void AsyncReferenceScanner::wait(ReferenceIndex& target) {
    {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] {
            return !active_.load(std::memory_order_acquire) || paused_.load(std::memory_order_acquire);
        });
    }
    poll(target);
}

bool AsyncReferenceScanner::has_resumable_work() const noexcept {
    std::scoped_lock lock(mutex_);
    return !worker_failed_ && (job_scanned_bytes_ < job_total_bytes_);
}

bool AsyncReferenceScanner::has_failed() const noexcept {
    std::scoped_lock lock(mutex_);
    return worker_failed_;
}

std::string AsyncReferenceScanner::last_error() const {
    std::scoped_lock lock(mutex_);
    return last_error_;
}

void AsyncReferenceScanner::record_worker_failure(std::uint64_t generation,
                                                  bool is_oom,
                                                  const char* what_msg) noexcept {
    {
        std::scoped_lock lock(mutex_);
        if (generation_ == generation) {
            job_scanned_bytes_ = job_.scanned_bytes();
            job_finished_ = true;
            worker_failed_ = true;
            pending_failure_incomplete_ = true;
            paused_.store(false, std::memory_order_release);
            if (is_oom) {
                constexpr std::string_view kOomMsg = "Out of memory during reference scan";
                if (last_error_.capacity() >= kOomMsg.size()) {
                    last_error_.assign(kOomMsg.data(), kOomMsg.size());
                }
            } else {
                const std::string_view msg =
                    (what_msg != nullptr && *what_msg != '\0')
                        ? std::string_view(what_msg)
                        : std::string_view("Unhandled exception in reference scan worker");
                if (last_error_.capacity() >= msg.size()) {
                    last_error_.assign(msg.data(), msg.size());
                } else {
                    try {
                        last_error_.assign(msg.data(), msg.size());
                    } catch (...) {
                        constexpr std::string_view kFallback = "Reference scan worker failed";
                        if (last_error_.capacity() >= kFallback.size()) {
                            last_error_.assign(kFallback.data(), kFallback.size());
                        }
                    }
                }
            }
            active_.store(false, std::memory_order_release);
        }
    }
    cv_.notify_all();
}

void AsyncReferenceScanner::worker_loop(std::stop_token stop, std::uint64_t generation) {
    while (!stop.stop_requested()) {
        std::size_t budget = 0;
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, stop, [this, generation] {
                return generation_ != generation ||
                       !paused_.load(std::memory_order_acquire);
            });
            if (stop.stop_requested() || generation_ != generation) {
                active_.store(false, std::memory_order_release);
                cv_.notify_all();
                return;
            }
            budget = desired_budget_;
        }

        job_.set_byte_budget(budget);
        if (job_.finished()) {
            std::scoped_lock lock(mutex_);
            if (desired_budget_ != budget) {
                continue;
            }
            job_scanned_bytes_ = job_.scanned_bytes();
            job_finished_ = true;
            active_.store(false, std::memory_order_release);
            cv_.notify_all();
            return;
        }

        // Disassemble one 256 KiB slice outside mutex_ so UI poll() never contends on Capstone.
        auto chunk = job_.step(stop);
        if (!chunk) {
            std::scoped_lock lock(mutex_);
            job_scanned_bytes_ = job_.scanned_bytes();
            active_.store(false, std::memory_order_release);
            cv_.notify_all();
            return;
        }

        {
            std::scoped_lock lock(mutex_);
            job_scanned_bytes_ = job_.scanned_bytes();
            if (generation_ != generation) {
                active_.store(false, std::memory_order_release);
                cv_.notify_all();
                return;
            }
            if (chunk->finished && desired_budget_ > budget) {
                job_.set_byte_budget(desired_budget_);
                if (!job_.finished()) {
                    chunk->finished = false;
                    chunk->incomplete = true;
                }
            }
            const bool done = chunk->finished;
            pending_chunks_.push_back(std::move(*chunk));
            if (done) {
                job_finished_ = true;
                active_.store(false, std::memory_order_release);
                cv_.notify_all();
                return;
            }
        }
    }
    {
        std::scoped_lock lock(mutex_);
        job_scanned_bytes_ = job_.scanned_bytes();
        active_.store(false, std::memory_order_release);
    }
    cv_.notify_all();
}

} // namespace viewe
