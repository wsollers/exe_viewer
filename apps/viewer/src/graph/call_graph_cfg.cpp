#include "graph/call_graph.hpp"
#include "graph/call_graph_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "disasm/disassembler.hpp"
#include "peelf/endian_reader.hpp"

namespace viewer {
using detail::format_hex;

namespace {

[[nodiscard]] int cfg_norm_x86_gpr(unsigned reg) noexcept {
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

[[nodiscard]] int cfg_norm_arm_gpr(int reg) noexcept {
    switch (reg) {
    case ARM_REG_R0: return 0; case ARM_REG_R1: return 1; case ARM_REG_R2: return 2; case ARM_REG_R3: return 3;
    case ARM_REG_R4: return 4; case ARM_REG_R5: return 5; case ARM_REG_R6: return 6; case ARM_REG_R7: return 7;
    case ARM_REG_R8: return 8; case ARM_REG_R9: return 9; case ARM_REG_R10: return 10; case ARM_REG_R11: return 11;
    case ARM_REG_R12: return 12; case ARM_REG_SP: return 13; case ARM_REG_LR: return 14; case ARM_REG_PC: return 15;
    default: return -1;
    }
}

[[nodiscard]] int cfg_norm_arm64_gpr(unsigned reg) noexcept {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return static_cast<int>(reg - ARM64_REG_X0);
    if (reg == ARM64_REG_FP) return 29;
    if (reg == ARM64_REG_LR) return 30;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return static_cast<int>(reg - ARM64_REG_W0);
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return 31;
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return 32;
    return -1;
}

[[nodiscard]] std::uint64_t cfg_read_uint(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    std::uint64_t v = 0;
    if (endian == peelf::Endianness::Big) {
        for (std::size_t i = 0; i < width; ++i) v = (v << 8u) | p[i];
    } else {
        for (std::size_t i = 0; i < width; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8u);
    }
    return v;
}

[[nodiscard]] std::int64_t cfg_read_sint(const std::uint8_t* p, std::size_t width, peelf::Endianness endian) noexcept {
    const std::uint64_t u = cfg_read_uint(p, width, endian);
    switch (width) {
    case 1: return static_cast<std::int8_t>(u & 0xFFu);
    case 2: return static_cast<std::int16_t>(u & 0xFFFFu);
    case 4: return static_cast<std::int32_t>(u & 0xFFFFFFFFu);
    default: return static_cast<std::int64_t>(u);
    }
}

void recover_cfg_jump_tables(
    std::span<const std::uint8_t> function_bytes,
    std::uint64_t virtual_address,
    peelf::Architecture architecture,
    peelf::Endianness endianness,
    bool thumb_mode,
    const std::vector<Instruction>& instructions,
    const std::map<std::uint64_t, std::size_t>& instruction_by_address,
    const GraphByteReader& read_virtual_bytes,
    std::set<std::uint64_t>& leaders,
    std::map<std::size_t, std::vector<std::uint64_t>>& jump_tables,
    std::vector<IndirectRecoveryNote>& recovery_notes) {

    const auto read_table = [&](std::uint64_t table_va, std::size_t byte_len) -> std::vector<std::uint8_t> {
        if (byte_len == 0) return {};
        if (table_va >= virtual_address) {
            const auto off = table_va - virtual_address;
            if (off <= function_bytes.size() && byte_len <= function_bytes.size() - static_cast<std::size_t>(off)) {
                return std::vector<std::uint8_t>(
                    function_bytes.begin() + static_cast<std::ptrdiff_t>(off),
                    function_bytes.begin() + static_cast<std::ptrdiff_t>(off + byte_len));
            }
        }
        if (read_virtual_bytes) {
            auto ext = read_virtual_bytes(table_va, byte_len);
            if (ext.size() == byte_len) return ext;
        }
        return {};
    };

    const auto has_direct_bypass = [&](std::size_t guard_idx, std::size_t dispatch_idx) {
        for (const Instruction& ins : instructions) {
            if (!ins.branch_target) continue;
            for (std::size_t k = guard_idx + 1u; k <= dispatch_idx; ++k) {
                if (*ins.branch_target == instructions[k].address) return true;
            }
        }
        return false;
    };

    cs_arch cs_target{};
    unsigned cs_mode_flags = endianness == peelf::Endianness::Big
        ? static_cast<unsigned>(CS_MODE_BIG_ENDIAN)
        : static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN);
    switch (architecture) {
    case peelf::Architecture::X86: cs_target = CS_ARCH_X86; cs_mode_flags = static_cast<unsigned>(CS_MODE_32); break;
    case peelf::Architecture::X86_64: cs_target = CS_ARCH_X86; cs_mode_flags = static_cast<unsigned>(CS_MODE_64); break;
    case peelf::Architecture::ARM:
        cs_target = CS_ARCH_ARM;
        cs_mode_flags |= thumb_mode ? static_cast<unsigned>(CS_MODE_THUMB) : static_cast<unsigned>(CS_MODE_ARM);
        break;
    case peelf::Architecture::ARM64: cs_target = CS_ARCH_ARM64; break;
    default: return;
    }

    ScopedCsHandle handle;
    if (cs_open(cs_target, static_cast<cs_mode>(cs_mode_flags), handle.put()) != CS_ERR_OK) return;
    cs_option(handle.get(), CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* raw_ptr = nullptr;
    const std::size_t count_insns = cs_disasm(
        handle.get(), function_bytes.data(), function_bytes.size(), virtual_address, 0, &raw_ptr);
    const ScopedCsInsn raw(raw_ptr, count_insns);
    if (count_insns == 0 || !raw) {
        return;
    }

    const std::size_t limit = std::min(count_insns, instructions.size());

    const auto x86_clobbers_gpr = [&](const cs_insn& ins, bool is_call, bool is_branch, int gpr) noexcept {
        if (gpr < 0 || !ins.detail) return false;
        const auto& x86 = ins.detail->x86;
        if (ins.id == X86_INS_DIV || ins.id == X86_INS_IDIV || ins.id == X86_INS_MUL) {
            return gpr == 0 || gpr == 2;
        }
        if (ins.id == X86_INS_CDQ || ins.id == X86_INS_CQO) {
            return gpr == 2;
        }
        if (x86.op_count >= 1 && x86.operands[0].type == X86_OP_REG &&
            ins.id != X86_INS_CMP && ins.id != X86_INS_TEST &&
            ins.id != X86_INS_PUSH && !is_call && !is_branch) {
            if (cfg_norm_x86_gpr(x86.operands[0].reg) == gpr) return true;
            if (ins.id == X86_INS_XCHG && x86.op_count == 2 &&
                x86.operands[1].type == X86_OP_REG &&
                cfg_norm_x86_gpr(x86.operands[1].reg) == gpr) {
                return true;
            }
        }
        return false;
    };

    const auto x86_clobbers_flags = [](const cs_insn& ins, bool is_call, bool is_branch) noexcept {
        const std::string_view mnem(ins.mnemonic);
        return !(ins.id == X86_INS_MOV || ins.id == X86_INS_MOVABS ||
                 ins.id == X86_INS_MOVZX || ins.id == X86_INS_MOVSX ||
                 ins.id == X86_INS_MOVSXD || ins.id == X86_INS_LEA ||
                 ins.id == X86_INS_NOP || ins.id == X86_INS_PUSH ||
                 ins.id == X86_INS_POP || ins.id == X86_INS_XCHG ||
                 ins.id == X86_INS_ENDBR64 || ins.id == X86_INS_ENDBR32 ||
                 mnem.starts_with("cmov") || (is_branch && !is_call));
    };

    const auto find_x86_guard = [&](std::size_t search_end_exclusive,
                                    int idx_reg,
                                    std::size_t& out_guard_idx) -> std::optional<std::size_t> {
        if (idx_reg < 0 || search_end_exclusive < 2) return std::nullopt;
        int tracked = idx_reg;
        bool saw_guard = false;
        bool strict_above = true;
        for (std::size_t pos = search_end_exclusive; pos-- > 0;) {
            const cs_insn& ins = raw[pos];
            if (!ins.detail) continue;
            const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
            const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
            const bool is_ret = cs_insn_group(handle.get(), &ins, CS_GRP_RET);
            if (is_call || is_ret || ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET) {
                break;
            }
            const auto& x86 = ins.detail->x86;
            if (!saw_guard) {
                if ((ins.id == X86_INS_JA || ins.id == X86_INS_JAE) &&
                    instructions[pos].branch_target &&
                    *instructions[pos].branch_target != instructions[search_end_exclusive].address) {
                    saw_guard = true;
                    strict_above = (ins.id == X86_INS_JA);
                    out_guard_idx = pos;
                    continue;
                }
                if ((ins.id == X86_INS_MOV || ins.id == X86_INS_MOVZX || ins.id == X86_INS_MOVSXD) &&
                    x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                    cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    tracked = cfg_norm_x86_gpr(x86.operands[1].reg);
                    if (tracked < 0) break;
                    continue;
                }
                if (x86_clobbers_gpr(ins, is_call, is_branch, tracked)) {
                    break;
                }
            } else {
                if (ins.id == X86_INS_CMP && x86.op_count == 2 &&
                    x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM &&
                    x86.operands[1].imm >= 0 && cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    const auto uimm = static_cast<std::uint64_t>(x86.operands[1].imm);
                    if (strict_above && uimm == std::numeric_limits<std::uint64_t>::max()) {
                        return std::nullopt;
                    }
                    const std::uint64_t cases = strict_above ? (uimm + 1u) : uimm;
                    if (cases >= 1u && cases <= 256u) return static_cast<std::size_t>(cases);
                    return std::nullopt;
                }
                if (x86_clobbers_flags(ins, is_call, is_branch)) {
                    break;
                }
                if ((ins.id == X86_INS_MOV || ins.id == X86_INS_MOVZX || ins.id == X86_INS_MOVSXD) &&
                    x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                    cfg_norm_x86_gpr(x86.operands[0].reg) == tracked) {
                    tracked = cfg_norm_x86_gpr(x86.operands[1].reg);
                    if (tracked < 0) break;
                    continue;
                }
                if (x86_clobbers_gpr(ins, is_call, is_branch, tracked)) {
                    break;
                }
            }
        }
        return std::nullopt;
    };

    for (std::size_t i = 2; i < limit; ++i) {
        const cs_insn& dispatch = raw[i];
        if (!dispatch.detail) continue;

        if (architecture == peelf::Architecture::X86 || architecture == peelf::Architecture::X86_64) {
            const auto& x86 = dispatch.detail->x86;
            // 1) Guarded absolute u32/u64 jump table
            if (dispatch.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_MEM) {
                const auto& mem = x86.operands[0].mem;
                const std::uint8_t esz = x86.operands[0].size;
                if (mem.base == X86_REG_INVALID && mem.index != X86_REG_INVALID &&
                    mem.segment == X86_REG_INVALID && mem.disp >= 0 &&
                    (esz == 4 || esz == 8) && mem.scale == esz) {
                    std::size_t guard_idx = 0;
                    const auto count = find_x86_guard(i, cfg_norm_x86_gpr(mem.index), guard_idx);
                    if (count && !has_direct_bypass(guard_idx, i)) {
                        const auto table_va = static_cast<std::uint64_t>(mem.disp);
                        const auto bytes = read_table(table_va, *count * esz);
                        if (!bytes.empty()) {
                            std::vector<std::uint64_t> targets;
                            targets.reserve(*count);
                            for (std::size_t c = 0; c < *count; ++c) {
                                const std::uint64_t dst = cfg_read_uint(bytes.data() + c * esz, esz, endianness);
                                if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                                targets.push_back(dst);
                            }
                            if (!targets.empty()) {
                                for (const auto t : targets) leaders.insert(t);
                                recovery_notes.push_back(IndirectRecoveryNote{
                                    .source_address = dispatch.address,
                                    .table_or_slot_address = table_va,
                                    .target_count = targets.size(),
                                    .confidence = "IndirectTable",
                                    .evidence = std::format("Guarded absolute u{} jump table @ 0x{:X} ({} cases)",
                                                            static_cast<unsigned>(esz * 8u), table_va, targets.size()),
                                });
                                jump_tables.emplace(i, std::move(targets));
                            }
                        }
                    }
                }
            }

            // 2) Guarded x86-64 RIP-relative signed 32-bit offset jump table
            if (architecture == peelf::Architecture::X86_64 &&
                dispatch.id == X86_INS_JMP && x86.op_count == 1 && x86.operands[0].type == X86_OP_REG) {
                const int jmp_reg = cfg_norm_x86_gpr(x86.operands[0].reg);
                int cand_a = -1;
                int cand_b = -1;
                int matched_base = -1;
                int matched_idx = -1;
                std::int64_t extra_disp = 0;
                std::size_t movsxd_pos = 0;
                bool found_movsxd = false;

                for (std::size_t p = i; p-- > 0 && (i - p) <= 12u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                    const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                    const bool is_ret = cs_insn_group(handle.get(), &ins, CS_GRP_RET);
                    if (is_call || is_ret || ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET) {
                        break;
                    }
                    const auto& d = ins.detail->x86;
                    if (cand_a < 0) {
                        if (ins.id == X86_INS_ADD && d.op_count == 2 &&
                            d.operands[0].type == X86_OP_REG && d.operands[1].type == X86_OP_REG &&
                            cfg_norm_x86_gpr(d.operands[0].reg) == jmp_reg) {
                            cand_a = jmp_reg;
                            cand_b = cfg_norm_x86_gpr(d.operands[1].reg);
                        } else if (ins.id == X86_INS_LEA && d.op_count == 2 &&
                                   d.operands[0].type == X86_OP_REG && d.operands[1].type == X86_OP_MEM &&
                                   cfg_norm_x86_gpr(d.operands[0].reg) == jmp_reg &&
                                   d.operands[1].mem.base != X86_REG_INVALID &&
                                   d.operands[1].mem.index != X86_REG_INVALID &&
                                   d.operands[1].mem.scale == 1 && d.operands[1].mem.disp == 0) {
                            cand_a = cfg_norm_x86_gpr(d.operands[1].mem.base);
                            cand_b = cfg_norm_x86_gpr(d.operands[1].mem.index);
                        } else if (x86_clobbers_gpr(ins, is_call, is_branch, jmp_reg)) {
                            break;
                        }
                    } else if ((ins.id == X86_INS_MOVSXD || ins.id == X86_INS_MOVSX) &&
                               d.op_count == 2 && d.operands[0].type == X86_OP_REG &&
                               d.operands[1].type == X86_OP_MEM && d.operands[1].mem.scale == 4 &&
                               d.operands[1].mem.base != X86_REG_INVALID &&
                               d.operands[1].mem.index != X86_REG_INVALID) {
                        const int dst_r = cfg_norm_x86_gpr(d.operands[0].reg);
                        const int base_r = cfg_norm_x86_gpr(d.operands[1].mem.base);
                        if ((dst_r == cand_a && base_r == cand_b) || (dst_r == cand_b && base_r == cand_a)) {
                            matched_base = base_r;
                            matched_idx = cfg_norm_x86_gpr(d.operands[1].mem.index);
                            extra_disp = d.operands[1].mem.disp;
                            movsxd_pos = p;
                            found_movsxd = true;
                            break;
                        }
                        if (x86_clobbers_gpr(ins, is_call, is_branch, cand_a) ||
                            x86_clobbers_gpr(ins, is_call, is_branch, cand_b)) {
                            break;
                        }
                    } else if (x86_clobbers_gpr(ins, is_call, is_branch, cand_a) ||
                               x86_clobbers_gpr(ins, is_call, is_branch, cand_b)) {
                        break;
                    }
                }

                if (found_movsxd && matched_base >= 0 && matched_idx >= 0) {
                    std::optional<std::uint64_t> anchor_va;
                    for (std::size_t p = movsxd_pos; p-- > 0 && (movsxd_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                        const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                        const bool is_ret = cs_insn_group(handle.get(), &ins, CS_GRP_RET);
                        if (is_call || is_ret || ins.id == X86_INS_JMP || ins.id == X86_INS_LJMP || ins.id == X86_INS_RET) {
                            break;
                        }
                        const auto& d = ins.detail->x86;
                        if (ins.id == X86_INS_LEA && d.op_count == 2 &&
                            d.operands[0].type == X86_OP_REG &&
                            cfg_norm_x86_gpr(d.operands[0].reg) == matched_base &&
                            d.operands[1].type == X86_OP_MEM &&
                            d.operands[1].mem.base == X86_REG_RIP &&
                            d.operands[1].mem.index == X86_REG_INVALID) {
                            if (const auto next_pc = peelf::checked_add_u64(ins.address, ins.size)) {
                                anchor_va =
                                    peelf::checked_apply_signed_displacement(*next_pc, d.operands[1].mem.disp);
                            }
                            break;
                        }
                        if (x86_clobbers_gpr(ins, is_call, is_branch, matched_base)) {
                            break;
                        }
                    }

                    std::size_t guard_idx = 0;
                    const auto count = find_x86_guard(movsxd_pos, matched_idx, guard_idx);
                    if (anchor_va && count && !has_direct_bypass(guard_idx, i)) {
                        const auto table_va =
                            peelf::checked_apply_signed_displacement(*anchor_va, extra_disp);
                        const auto table_bytes_len = peelf::checked_mul_u64(*count, 4u);
                        if (table_va && table_bytes_len &&
                            *table_bytes_len <= std::numeric_limits<std::size_t>::max()) {
                            const auto bytes =
                                read_table(*table_va, static_cast<std::size_t>(*table_bytes_len));
                            if (!bytes.empty()) {
                                std::vector<std::uint64_t> targets;
                                targets.reserve(*count);
                                for (std::size_t c = 0; c < *count; ++c) {
                                    const std::int64_t rel =
                                        cfg_read_sint(bytes.data() + c * 4u, 4u, endianness);
                                    const auto dst =
                                        peelf::checked_apply_signed_displacement(*anchor_va, rel);
                                    if (!dst || !instruction_by_address.contains(*dst)) {
                                        targets.clear();
                                        break;
                                    }
                                    targets.push_back(*dst);
                                }
                                if (!targets.empty()) {
                                    for (const auto t : targets) leaders.insert(t);
                                    recovery_notes.push_back(IndirectRecoveryNote{
                                        .source_address = dispatch.address,
                                        .table_or_slot_address = *table_va,
                                        .target_count = targets.size(),
                                        .confidence = "IndirectTable",
                                        .evidence = std::format(
                                            "RIP-relative i32 jump table @ 0x{:X} ({} cases)",
                                            *table_va,
                                            targets.size()),
                                    });
                                    jump_tables.emplace(i, std::move(targets));
                                }
                            }
                        }
                    }
                }
            }
        } else if (architecture == peelf::Architecture::ARM && thumb_mode) {
            const auto& arm = dispatch.detail->arm;
            if ((dispatch.id == ARM_INS_TBB || dispatch.id == ARM_INS_TBH) &&
                arm.op_count == 1 && arm.operands[0].type == ARM_OP_MEM &&
                arm.operands[0].mem.base == ARM_REG_PC && arm.operands[0].mem.index != ARM_REG_INVALID) {
                int tracked = cfg_norm_arm_gpr(arm.operands[0].mem.index);
                bool saw_guard = false;
                bool strict_above = true;
                std::size_t guard_idx = 0;
                std::optional<std::size_t> count;
                for (std::size_t p = i; p-- > 0 && (i - p) <= 8u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                    const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                    const bool is_ret = cs_insn_group(handle.get(), &ins, CS_GRP_RET);
                    const auto& d = ins.detail->arm;
                    if (is_call || is_ret ||
                        (is_branch && !is_call && (d.cc == ARM_CC_AL || d.cc == ARM_CC_INVALID))) {
                        break;
                    }
                    const std::string_view arm_mnem(ins.mnemonic);
                    const bool clobbers_tracked =
                        d.op_count >= 1 && d.operands[0].type == ARM_OP_REG &&
                        ins.id != ARM_INS_CMP && ins.id != ARM_INS_CMN &&
                        ins.id != ARM_INS_TST && ins.id != ARM_INS_TEQ &&
                        !arm_mnem.starts_with("str") && !arm_mnem.starts_with("stm") &&
                        !arm_mnem.starts_with("push") && !is_call && !is_branch &&
                        cfg_norm_arm_gpr(d.operands[0].reg) == tracked;
                    const bool clobbers_flags =
                        d.update_flags || is_call ||
                        ins.id == ARM_INS_CMP || ins.id == ARM_INS_CMN ||
                        ins.id == ARM_INS_TST || ins.id == ARM_INS_TEQ;
                    if (!saw_guard) {
                        if (ins.id == ARM_INS_B && (d.cc == ARM_CC_HI || d.cc == ARM_CC_HS)) {
                            saw_guard = true;
                            strict_above = (d.cc == ARM_CC_HI);
                            guard_idx = p;
                        } else if (ins.id == ARM_INS_MOV && d.op_count == 2 &&
                                   d.operands[0].type == ARM_OP_REG && d.operands[1].type == ARM_OP_REG &&
                                   cfg_norm_arm_gpr(d.operands[0].reg) == tracked) {
                            tracked = cfg_norm_arm_gpr(d.operands[1].reg);
                            if (tracked < 0) break;
                        } else if (clobbers_tracked) {
                            break;
                        }
                    } else {
                        if (ins.id == ARM_INS_CMP && d.op_count == 2 &&
                            d.operands[0].type == ARM_OP_REG && d.operands[1].type == ARM_OP_IMM &&
                            d.operands[1].imm >= 0 && cfg_norm_arm_gpr(d.operands[0].reg) == tracked) {
                            const auto uimm = static_cast<std::uint64_t>(d.operands[1].imm);
                            if (strict_above && uimm == std::numeric_limits<std::uint64_t>::max()) {
                                break;
                            }
                            const std::uint64_t cases = strict_above ? (uimm + 1u) : uimm;
                            if (cases >= 1u && cases <= 256u) count = static_cast<std::size_t>(cases);
                            break;
                        }
                        if (clobbers_flags) {
                            break;
                        }
                        if (ins.id == ARM_INS_MOV && d.op_count == 2 &&
                            d.operands[0].type == ARM_OP_REG && d.operands[1].type == ARM_OP_REG &&
                            cfg_norm_arm_gpr(d.operands[0].reg) == tracked) {
                            tracked = cfg_norm_arm_gpr(d.operands[1].reg);
                            if (tracked < 0) break;
                            continue;
                        }
                        if (clobbers_tracked) {
                            break;
                        }
                    }
                }
                if (count && !has_direct_bypass(guard_idx, i)) {
                    const std::size_t esz = (dispatch.id == ARM_INS_TBH) ? 2u : 1u;
                    const std::uint64_t table_va = dispatch.address + 4u;
                    const auto bytes = read_table(table_va, *count * esz);
                    if (!bytes.empty()) {
                        std::vector<std::uint64_t> targets;
                        targets.reserve(*count);
                        for (std::size_t c = 0; c < *count; ++c) {
                            const std::uint64_t e = cfg_read_uint(bytes.data() + c * esz, esz, endianness);
                            const std::uint64_t dst = (table_va + e * 2u) & ~std::uint64_t{1};
                            if (!instruction_by_address.contains(dst)) { targets.clear(); break; }
                            targets.push_back(dst);
                        }
                        if (!targets.empty()) {
                            for (const auto t : targets) leaders.insert(t);
                            recovery_notes.push_back(IndirectRecoveryNote{
                                .source_address = dispatch.address,
                                .table_or_slot_address = table_va,
                                .target_count = targets.size(),
                                .confidence = "IndirectTable",
                                .evidence = std::format("Thumb-2 {} jump table @ 0x{:X} ({} cases)",
                                                        dispatch.id == ARM_INS_TBH ? "tbh" : "tbb",
                                                        table_va, targets.size()),
                            });
                            jump_tables.emplace(i, std::move(targets));
                        }
                    }
                }
            }
        } else if (architecture == peelf::Architecture::ARM64) {
            const auto& a64 = dispatch.detail->arm64;
            if (dispatch.id == ARM64_INS_BR && a64.op_count == 1 && a64.operands[0].type == ARM64_OP_REG) {
                const int target_reg = cfg_norm_arm64_gpr(a64.operands[0].reg);

                const auto a64_is_uncond_stop = [&](const cs_insn& ins, bool is_call, bool is_branch) noexcept {
                    const bool is_ret = cs_insn_group(handle.get(), &ins, CS_GRP_RET);
                    if (is_call || is_ret) return true;
                    const auto& d = ins.detail->arm64;
                    return is_branch && !is_call &&
                           ins.id != ARM64_INS_CBZ && ins.id != ARM64_INS_CBNZ &&
                           ins.id != ARM64_INS_TBZ && ins.id != ARM64_INS_TBNZ &&
                           (d.cc == ARM64_CC_AL || d.cc == ARM64_CC_NV || d.cc == ARM64_CC_INVALID);
                };

                const auto a64_clobbers_gpr = [](const cs_insn& ins, bool is_call, bool is_branch, int gpr) noexcept {
                    if (gpr < 0 || gpr == 31 || !ins.detail) return false;
                    const auto& d = ins.detail->arm64;
                    const std::string_view mnem(ins.mnemonic);
                    return d.op_count >= 1 && d.operands[0].type == ARM64_OP_REG &&
                           ins.id != ARM64_INS_CMP && ins.id != ARM64_INS_CMN && ins.id != ARM64_INS_TST &&
                           ins.id != ARM64_INS_CBZ && ins.id != ARM64_INS_CBNZ &&
                           ins.id != ARM64_INS_TBZ && ins.id != ARM64_INS_TBNZ &&
                           !mnem.starts_with("st") && !is_call && !is_branch &&
                           cfg_norm_arm64_gpr(d.operands[0].reg) == gpr;
                };

                const auto resolve_a64_va = [&](std::size_t before_pos, int reg) -> std::optional<std::uint64_t> {
                    if (reg < 0) return std::nullopt;
                    int cur = reg;
                    std::optional<std::uint64_t> add_off;
                    for (std::size_t p = before_pos; p-- > 0 && (before_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                        const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                        if (a64_is_uncond_stop(ins, is_call, is_branch)) break;
                        const auto& d = ins.detail->arm64;
                        if ((ins.id == ARM64_INS_ADR || ins.id == ARM64_INS_ADRP) &&
                            d.op_count == 2 && d.operands[0].type == ARM64_OP_REG &&
                            cfg_norm_arm64_gpr(d.operands[0].reg) == cur &&
                            d.operands[1].type == ARM64_OP_IMM) {
                            return peelf::checked_add_u64(
                                static_cast<std::uint64_t>(d.operands[1].imm),
                                add_off.value_or(0ULL));
                        }
                        if (!add_off && ins.id == ARM64_INS_ADD && d.op_count == 3 &&
                            d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                            d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 &&
                            cfg_norm_arm64_gpr(d.operands[0].reg) == cur) {
                            const std::uint64_t sh = d.operands[2].shift.type == ARM64_SFT_LSL
                                ? d.operands[2].shift.value : 0u;
                            if (sh >= 64u) break;
                            add_off = static_cast<std::uint64_t>(d.operands[2].imm) << sh;
                            cur = cfg_norm_arm64_gpr(d.operands[1].reg);
                            if (cur < 0) break;
                            continue;
                        }
                        if (a64_clobbers_gpr(ins, is_call, is_branch, cur)) {
                            break;
                        }
                    }
                    return std::nullopt;
                };

                const auto find_a64_guard = [&](std::size_t before_pos,
                                                int idx_reg,
                                                std::size_t& out_guard) -> std::optional<std::size_t> {
                    if (idx_reg < 0 || before_pos < 2) return std::nullopt;
                    int tracked = idx_reg;
                    bool saw_guard = false;
                    bool strict_above = true;
                    for (std::size_t p = before_pos; p-- > 0 && (before_pos - p) <= 12u;) {
                        const cs_insn& ins = raw[p];
                        if (!ins.detail) continue;
                        const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                        const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                        if (a64_is_uncond_stop(ins, is_call, is_branch)) break;
                        const auto& d = ins.detail->arm64;
                        const bool clobbers_flags =
                            d.update_flags || is_call ||
                            ins.id == ARM64_INS_CMP || ins.id == ARM64_INS_CMN ||
                            ins.id == ARM64_INS_TST || ins.id == ARM64_INS_SUBS ||
                            ins.id == ARM64_INS_ADDS || ins.id == ARM64_INS_ANDS ||
                            ins.id == ARM64_INS_CCMP || ins.id == ARM64_INS_CCMN;
                        if (!saw_guard) {
                            if (ins.id == ARM64_INS_B && (d.cc == ARM64_CC_HI || d.cc == ARM64_CC_HS)) {
                                saw_guard = true;
                                strict_above = (d.cc == ARM64_CC_HI);
                                out_guard = p;
                            } else if (ins.id == ARM64_INS_MOV && d.op_count == 2 &&
                                       d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                                       cfg_norm_arm64_gpr(d.operands[0].reg) == tracked) {
                                tracked = cfg_norm_arm64_gpr(d.operands[1].reg);
                                if (tracked < 0) break;
                            } else if (a64_clobbers_gpr(ins, is_call, is_branch, tracked)) {
                                break;
                            }
                        } else {
                            if ((ins.id == ARM64_INS_CMP && d.op_count >= 2 &&
                                 d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_IMM &&
                                 d.operands[1].imm >= 0 && cfg_norm_arm64_gpr(d.operands[0].reg) == tracked) ||
                                (ins.id == ARM64_INS_SUBS && d.op_count >= 3 &&
                                 cfg_norm_arm64_gpr(d.operands[0].reg) == 31 &&
                                 d.operands[1].type == ARM64_OP_REG && d.operands[2].type == ARM64_OP_IMM &&
                                 d.operands[2].imm >= 0 && cfg_norm_arm64_gpr(d.operands[1].reg) == tracked)) {
                                const unsigned imm_op = (ins.id == ARM64_INS_SUBS) ? 2u : 1u;
                                const std::uint64_t sh = d.operands[imm_op].shift.type == ARM64_SFT_LSL
                                    ? d.operands[imm_op].shift.value : 0u;
                                if (sh >= 64u) return std::nullopt;
                                const std::uint64_t imm = static_cast<std::uint64_t>(d.operands[imm_op].imm) << sh;
                                if (strict_above && imm == std::numeric_limits<std::uint64_t>::max()) {
                                    return std::nullopt;
                                }
                                const std::uint64_t cases = strict_above ? (imm + 1u) : imm;
                                if (cases >= 1u && cases <= 256u) return static_cast<std::size_t>(cases);
                                return std::nullopt;
                            }
                            if (clobbers_flags) {
                                break;
                            }
                            if (ins.id == ARM64_INS_MOV && d.op_count == 2 &&
                                d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                                cfg_norm_arm64_gpr(d.operands[0].reg) == tracked) {
                                tracked = cfg_norm_arm64_gpr(d.operands[1].reg);
                                if (tracked < 0) break;
                                continue;
                            }
                            if (a64_clobbers_gpr(ins, is_call, is_branch, tracked)) {
                                break;
                            }
                        }
                    }
                    return std::nullopt;
                };

                for (std::size_t p = i; p-- > 0 && (i - p) <= 8u;) {
                    const cs_insn& ins = raw[p];
                    if (!ins.detail) continue;
                    const bool is_call = cs_insn_group(handle.get(), &ins, CS_GRP_CALL);
                    const bool is_branch = cs_insn_group(handle.get(), &ins, CS_GRP_JUMP);
                    if (a64_is_uncond_stop(ins, is_call, is_branch)) break;
                    const auto& d = ins.detail->arm64;
                    if (ins.id == ARM64_INS_ADD && d.op_count == 3 &&
                        d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
                        d.operands[2].type == ARM64_OP_REG &&
                        cfg_norm_arm64_gpr(d.operands[0].reg) == target_reg) {
                        const int anchor_r = cfg_norm_arm64_gpr(d.operands[1].reg);
                        const int off_r = cfg_norm_arm64_gpr(d.operands[2].reg);
                        const unsigned shift = d.operands[2].shift.value;
                        const bool ext_signed =
                            d.operands[2].ext == ARM64_EXT_SXTB ||
                            d.operands[2].ext == ARM64_EXT_SXTH ||
                            d.operands[2].ext == ARM64_EXT_SXTW;

                        for (std::size_t lp = p; lp-- > 0 && (p - lp) <= 8u;) {
                            const cs_insn& lins = raw[lp];
                            if (!lins.detail) continue;
                            const bool lis_call = cs_insn_group(handle.get(), &lins, CS_GRP_CALL);
                            const bool lis_branch = cs_insn_group(handle.get(), &lins, CS_GRP_JUMP);
                            if (a64_is_uncond_stop(lins, lis_call, lis_branch)) break;
                            const auto& ld = lins.detail->arm64;
                            if ((lins.id == ARM64_INS_LDRB || lins.id == ARM64_INS_LDRSB ||
                                 lins.id == ARM64_INS_LDRH || lins.id == ARM64_INS_LDRSH ||
                                 lins.id == ARM64_INS_LDRSW || lins.id == ARM64_INS_LDR) &&
                                ld.op_count == 2 && ld.operands[0].type == ARM64_OP_REG &&
                                cfg_norm_arm64_gpr(ld.operands[0].reg) == off_r &&
                                ld.operands[1].type == ARM64_OP_MEM &&
                                ld.operands[1].mem.base != ARM64_REG_INVALID &&
                                ld.operands[1].mem.index != ARM64_REG_INVALID &&
                                ld.operands[1].mem.disp == 0) {
                                std::size_t esz = 4;
                                bool is_signed = ext_signed;
                                switch (lins.id) {
                                case ARM64_INS_LDRB: esz = 1; break;
                                case ARM64_INS_LDRSB: esz = 1; is_signed = true; break;
                                case ARM64_INS_LDRH: esz = 2; break;
                                case ARM64_INS_LDRSH: esz = 2; is_signed = true; break;
                                case ARM64_INS_LDRSW: esz = 4; is_signed = true; break;
                                default: break;
                                }
                                const int base_r = cfg_norm_arm64_gpr(ld.operands[1].mem.base);
                                const int idx_r = cfg_norm_arm64_gpr(ld.operands[1].mem.index);
                                const auto table_va = resolve_a64_va(lp, base_r);
                                const auto anchor_va = (anchor_r == base_r) ? table_va : resolve_a64_va(p, anchor_r);
                                std::size_t guard_idx = 0;
                                const auto count = find_a64_guard(lp, idx_r, guard_idx);
                                if (table_va && anchor_va && count && shift < 64u &&
                                    !has_direct_bypass(guard_idx, i)) {
                                    const auto table_bytes_len = peelf::checked_mul_u64(*count, esz);
                                    const auto bytes =
                                        (table_bytes_len &&
                                         *table_bytes_len <= std::numeric_limits<std::size_t>::max())
                                            ? read_table(*table_va, static_cast<std::size_t>(*table_bytes_len))
                                            : std::vector<std::uint8_t>{};
                                    if (!bytes.empty()) {
                                        std::vector<std::uint64_t> targets;
                                        targets.reserve(*count);
                                        for (std::size_t c = 0; c < *count; ++c) {
                                            std::optional<std::uint64_t> dst_opt;
                                            if (is_signed) {
                                                const auto scaled = peelf::checked_scale_signed_displacement(
                                                    cfg_read_sint(bytes.data() + c * esz, esz, endianness),
                                                    shift);
                                                if (scaled.has_value()) {
                                                    dst_opt = peelf::checked_apply_signed_displacement(
                                                        *anchor_va, *scaled);
                                                }
                                            } else {
                                                const std::uint64_t uval =
                                                    cfg_read_uint(bytes.data() + c * esz, esz, endianness);
                                                if (shift == 0u ||
                                                    uval <= (std::numeric_limits<std::uint64_t>::max() >> shift)) {
                                                    dst_opt = peelf::checked_add_u64(*anchor_va, uval << shift);
                                                }
                                            }
                                            if (!dst_opt || !instruction_by_address.contains(*dst_opt)) {
                                                targets.clear();
                                                break;
                                            }
                                            targets.push_back(*dst_opt);
                                        }
                                        if (!targets.empty()) {
                                            for (const auto t : targets) leaders.insert(t);
                                            recovery_notes.push_back(IndirectRecoveryNote{
                                                .source_address = dispatch.address,
                                                .table_or_slot_address = *table_va,
                                                .target_count = targets.size(),
                                                .confidence = "IndirectTable",
                                                .evidence = std::format("ARM64 jump table @ 0x{:X} ({} cases)",
                                                                        *table_va, targets.size()),
                                            });
                                            jump_tables.emplace(i, std::move(targets));
                                        }
                                    }
                                }
                                break;
                            }
                            if (a64_clobbers_gpr(lins, lis_call, lis_branch, off_r) ||
                                a64_clobbers_gpr(lins, lis_call, lis_branch, anchor_r)) {
                                break;
                            }
                        }
                        break;
                    }
                    if (a64_clobbers_gpr(ins, is_call, is_branch, target_reg)) {
                        break;
                    }
                }
            }
        }
    }
}

} // namespace

CallGraph build_function_cfg_call_graph(std::span<const std::uint8_t> function_bytes,
                                        std::uint64_t virtual_address,
                                        peelf::Architecture architecture,
                                        peelf::Endianness endianness,
                                        std::optional<std::uint64_t> file_offset,
                                        std::string label,
                                        bool thumb_mode,
                                        bool reachable_only,
                                        const GraphByteReader& read_virtual_bytes) {
    CallGraph graph{
        .id = "function_cfg",
        .label = std::move(label),
        .architecture = architecture,
        .endianness = endianness,
        .nodes = {},
        .edges = {},
        .indirect_recoveries = {},
    };

    const std::optional<Architecture> arch = to_disassembler_architecture(architecture);
    if (!arch || function_bytes.empty()) {
        return graph;
    }
    if (function_bytes.size() > std::numeric_limits<std::uint64_t>::max() - virtual_address) return graph;
    if (file_offset && function_bytes.size() > std::numeric_limits<std::uint64_t>::max() - *file_offset) return graph;

    Disassembler disassembler;
    if (!disassembler.init(*arch, to_disassembler_endianness(endianness))) {
        return graph;
    }
    if (architecture == peelf::Architecture::ARM && !disassembler.set_thumb_mode(thumb_mode)) return graph;

    const std::vector<Instruction> instructions =
        disassembler.disassemble(function_bytes.data(), function_bytes.size(), virtual_address);
    if (instructions.empty()) {
        return graph;
    }

    std::map<std::uint64_t, std::size_t> instruction_by_address;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        instruction_by_address.emplace(instructions[index].address, index);
    }

    const std::uint64_t function_end =
        virtual_address + static_cast<std::uint64_t>(function_bytes.size());
    std::set<std::uint64_t> leaders{instructions.front().address};
    const auto conditional = [](const Instruction& i) { return i.flow == InstructionFlow::ConditionalBranch; };
    const auto branch = [](const Instruction& i) { return i.flow == InstructionFlow::Branch; };
    const auto returns = [](const Instruction& i) {
        return i.flow == InstructionFlow::Return || i.flow == InstructionFlow::ConditionalReturn;
    };
    const auto terminates = [&](const Instruction& i) { return conditional(i) || branch(i) || returns(i); };

    std::map<std::size_t, std::vector<std::uint64_t>> jump_tables;
    recover_cfg_jump_tables(
        function_bytes,
        virtual_address,
        architecture,
        endianness,
        thumb_mode,
        instructions,
        instruction_by_address,
        read_virtual_bytes,
        leaders,
        jump_tables,
        graph.indirect_recoveries);

    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const Instruction& instruction = instructions[index];
        const auto after = index + (instruction.delay_slot ? 2u : 1u);
        const std::uint64_t next_address = after < instructions.size() ? instructions[after].address : function_end;
        const std::optional<std::uint64_t> target = instruction.branch_target;
        const bool target_in_function = target && *target >= virtual_address && *target < function_end &&
                                        instruction_by_address.contains(*target);

        if (conditional(instruction)) {
            if (target_in_function) {
                leaders.insert(*target);
            }
            if (index + 1u < instructions.size()) {
                leaders.insert(next_address);
            }
        } else if (branch(instruction) || returns(instruction)) {
            if (target_in_function) {
                leaders.insert(*target);
            }
            if (index + 1u < instructions.size()) {
                leaders.insert(next_address);
            }
        }
    }

    struct Block {
        std::string id;
        std::size_t first_instruction = 0;
        std::size_t instruction_count = 0;
        std::uint64_t start = 0;
        std::uint64_t end = 0;
    };

    std::vector<Block> blocks;
    std::map<std::uint64_t, std::string> block_by_start;
    std::size_t index = 0;
    while (index < instructions.size()) {
        const std::size_t first = index;
        const std::uint64_t start = instructions[index].address;
        ++index;
        while (index < instructions.size() && !leaders.contains(instructions[index].address)) {
            const Instruction& previous = instructions[index - 1u];
            if (terminates(previous)) {
                if (previous.delay_slot && index < instructions.size()) ++index;
                break;
            }
            ++index;
        }

        const Instruction& last = instructions[index - 1u];
        const std::uint64_t end = last.address + static_cast<std::uint64_t>(last.bytes.size());
        const std::string id = "bb_" + std::to_string(blocks.size());
        block_by_start.emplace(start, id);
        blocks.push_back(Block{
            .id = id,
            .first_instruction = first,
            .instruction_count = index - first,
            .start = start,
            .end = end,
        });
    }

    graph.nodes.reserve(blocks.size() + 1u);
    for (const Block& block : blocks) {
        const std::optional<std::uint64_t> block_file_offset =
            file_offset ? std::optional(*file_offset + (block.start - virtual_address)) : std::nullopt;
        graph.nodes.push_back(CallGraphNode{
            .id = block.id,
            .label = "loc_" + format_hex(block.start),
            .kind = CallGraphNodeKind::BasicBlock,
            .bytes = GraphByteRange{
                .start = GraphAddress{
                    .virtual_address = block.start,
                    .relative_virtual_address = block.start - virtual_address,
                    .file_offset = block_file_offset,
                },
                .size = block.end - block.start,
            },
            .first_instruction_index = static_cast<std::uint64_t>(block.first_instruction),
            .instruction_count = static_cast<std::uint64_t>(block.instruction_count),
        });
        auto& node = graph.nodes.back();
        for (std::size_t i = block.first_instruction; i < block.first_instruction + block.instruction_count; ++i) {
            const auto& instruction = instructions[i];
            node.instructions.push_back({instruction.address, instruction.mnemonic, instruction.operands, instruction.branch_target});
        }
    }

    graph.nodes.push_back(CallGraphNode{
        .id = "return",
        .label = "return",
        .kind = CallGraphNodeKind::External,
    });

    for (std::size_t block_index = 0; block_index < blocks.size(); ++block_index) {
        const Block& block = blocks[block_index];
        const auto last_index = block.first_instruction + block.instruction_count - 1u;
        const auto control_index = block.instruction_count > 1 && instructions[last_index - 1].delay_slot &&
            terminates(instructions[last_index - 1]) ? last_index - 1 : last_index;
        const Instruction& last = instructions[control_index];
        const std::uint64_t next_address = block.end;
        const auto target = last.branch_target;
        const bool target_in_function = target && block_by_start.contains(*target);

        const auto unresolved = [&](CallGraphEdgeKind kind, std::string reason) {
            const auto id = "external_" + block.id;
            const auto known_target = kind == CallGraphEdgeKind::Unknown ? std::nullopt : target;
            graph.nodes.push_back(CallGraphNode{.id = id,
                .label = known_target ? format_hex(*known_target) + " (outside analyzed blocks)" : std::move(reason),
                .kind = known_target ? CallGraphNodeKind::External : CallGraphNodeKind::Unknown,
                .bytes = GraphByteRange{.start = GraphAddress{.virtual_address = known_target}}});
            graph.edges.push_back({block.id, id, kind, known_target ? "external" : "unresolved"});
        };

        if (last.annulled_delay_slot) {
            unresolved(CallGraphEdgeKind::Unknown, "Unresolved branch-likely (annulled delay slot)");
            continue;
        }
        if (last.delay_slot && control_index == last_index && terminates(last)) {
            unresolved(CallGraphEdgeKind::Unknown, "Missing delay slot");
            continue;
        }

        if (returns(last)) {
            graph.edges.push_back(CallGraphEdge{
                .from_node_id = block.id,
                .to_node_id = "return",
                .kind = CallGraphEdgeKind::Return,
                .label = "return",
            });
            if (last.flow == InstructionFlow::ConditionalReturn && block_by_start.contains(next_address))
                graph.edges.push_back({block.id, block_by_start.at(next_address), CallGraphEdgeKind::Fallthrough, "not returned"});
            continue;
        }

        if (conditional(last)) {
            if (target_in_function) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[*target],
                    .kind = CallGraphEdgeKind::ConditionalBranch,
                    .label = "taken",
                });
            } else {
                unresolved(CallGraphEdgeKind::ConditionalBranch, "Unresolved conditional branch");
            }
            if (block_by_start.contains(next_address)) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[next_address],
                    .kind = CallGraphEdgeKind::Fallthrough,
                    .label = "fallthrough",
                });
            }
            continue;
        }

        if (branch(last)) {
            if (const auto table = jump_tables.find(control_index); table != jump_tables.end()) {
                for (std::size_t case_index = 0; case_index < table->second.size(); ++case_index) {
                    graph.edges.push_back({block.id, block_by_start.at(table->second[case_index]),
                        CallGraphEdgeKind::UnconditionalBranch, "case " + std::to_string(case_index)});
                }
            } else if (target_in_function) {
                graph.edges.push_back(CallGraphEdge{
                    .from_node_id = block.id,
                    .to_node_id = block_by_start[*target],
                    .kind = CallGraphEdgeKind::UnconditionalBranch,
                    .label = "branch",
                });
            } else {
                unresolved(CallGraphEdgeKind::UnconditionalBranch, "Unresolved indirect branch / jump table");
            }
            continue;
        }

        if (block_index + 1u < blocks.size() && block_by_start.contains(next_address)) {
            graph.edges.push_back(CallGraphEdge{
                .from_node_id = block.id,
                .to_node_id = block_by_start[next_address],
                .kind = CallGraphEdgeKind::Fallthrough,
                .label = "fallthrough",
            });
        }
    }

    if (reachable_only) {
        std::set<std::string> reachable{"bb_0"};
        std::vector<std::string> pending{"bb_0"};
        for (std::size_t i = 0; i < pending.size(); ++i) {
            for (const auto& edge : graph.edges) {
                if (edge.from_node_id == pending[i] && reachable.insert(edge.to_node_id).second)
                    pending.push_back(edge.to_node_id);
            }
        }
        std::erase_if(graph.nodes, [&](const auto& node) { return !reachable.contains(node.id); });
        std::erase_if(graph.edges, [&](const auto& edge) {
            return !reachable.contains(edge.from_node_id) || !reachable.contains(edge.to_node_id);
        });
    }
    return graph;
}

} // namespace viewer
