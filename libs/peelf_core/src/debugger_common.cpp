#include <peelf/debugger.hpp>
#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <format>

namespace peelf::debugger {
namespace {

constexpr void store_u16(std::array<std::uint8_t, 4>& out,
                         std::uint16_t word,
                         Endianness endian) noexcept {
    if (endian == Endianness::Big) {
        out[0] = static_cast<std::uint8_t>((word >> 8u) & 0xFFu);
        out[1] = static_cast<std::uint8_t>(word & 0xFFu);
    } else {
        out[0] = static_cast<std::uint8_t>(word & 0xFFu);
        out[1] = static_cast<std::uint8_t>((word >> 8u) & 0xFFu);
    }
}

constexpr void store_u32(std::array<std::uint8_t, 4>& out,
                         std::uint32_t word,
                         Endianness endian) noexcept {
    if (endian == Endianness::Big) {
        out[0] = static_cast<std::uint8_t>((word >> 24u) & 0xFFu);
        out[1] = static_cast<std::uint8_t>((word >> 16u) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((word >> 8u) & 0xFFu);
        out[3] = static_cast<std::uint8_t>(word & 0xFFu);
    } else {
        out[0] = static_cast<std::uint8_t>(word & 0xFFu);
        out[1] = static_cast<std::uint8_t>((word >> 8u) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((word >> 16u) & 0xFFu);
        out[3] = static_cast<std::uint8_t>((word >> 24u) & 0xFFu);
    }
}

[[nodiscard]] std::optional<std::size_t> decode_x86_modrm_length(
    std::span<const std::uint8_t> bytes,
    std::size_t modrm_index,
    bool addr_size_16) noexcept {
    if (modrm_index >= bytes.size()) {
        return std::nullopt;
    }
    const std::uint8_t modrm = bytes[modrm_index];
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x3u);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x7u);

    if (mod == 0x3u) {
        return std::size_t{1};
    }

    if (addr_size_16) {
        std::size_t len = 1u;
        if (mod == 0x0u && rm == 0x6u) {
            len += 2u;
        } else if (mod == 0x1u) {
            len += 1u;
        } else if (mod == 0x2u) {
            len += 2u;
        }
        return (modrm_index + len <= bytes.size()) ? std::optional<std::size_t>(len) : std::nullopt;
    }

    std::size_t len = 1u;
    std::uint8_t sib_base = 0u;
    const bool has_sib = (rm == 0x4u);
    if (has_sib) {
        if (modrm_index + 1u >= bytes.size()) {
            return std::nullopt;
        }
        sib_base = static_cast<std::uint8_t>(bytes[modrm_index + 1u] & 0x7u);
        len += 1u;
    }

    if (mod == 0x0u) {
        if (rm == 0x5u || (has_sib && sib_base == 0x5u)) {
            len += 4u;
        }
    } else if (mod == 0x1u) {
        len += 1u;
    } else if (mod == 0x2u) {
        len += 4u;
    }

    return (modrm_index + len <= bytes.size()) ? std::optional<std::size_t>(len) : std::nullopt;
}

}  // namespace

Result<SoftwareTrapSpec> select_software_trap(
    Architecture arch,
    Endianness endian,
    bool thumb_mode) noexcept {
    SoftwareTrapSpec spec{};
    switch (arch) {
        case Architecture::X86:
        case Architecture::X86_64:
            spec.bytes = {0xCCu, 0u, 0u, 0u};
            spec.size = 1u;
            spec.rewinds_pc_on_hit = true;
            spec.mnemonic = "int3";
            return spec;

        case Architecture::ARM64:
            store_u32(spec.bytes, 0xD4200000u, endian);  // BRK #0 -> 00 00 20 D4 (LE)
            spec.size = 4u;
            spec.rewinds_pc_on_hit = false;
            spec.mnemonic = "brk #0";
            return spec;

        case Architecture::ARM:
            if (thumb_mode) {
                store_u16(spec.bytes, 0xBE00u, endian);  // Thumb BKPT #0 -> 00 BE (LE)
                spec.size = 2u;
                spec.rewinds_pc_on_hit = false;
                spec.mnemonic = "bkpt #0";
            } else {
                store_u32(spec.bytes, 0xE1200070u, endian);  // ARM BKPT #0 -> 70 00 20 E1 (LE)
                spec.size = 4u;
                spec.rewinds_pc_on_hit = false;
                spec.mnemonic = "bkpt #0";
            }
            return spec;

        case Architecture::RISCV32:
        case Architecture::RISCV64:
            store_u32(spec.bytes, 0x00100073u, endian);  // EBREAK -> 73 00 10 00 (LE)
            spec.size = 4u;
            spec.rewinds_pc_on_hit = false;
            spec.mnemonic = "ebreak";
            return spec;

        case Architecture::PowerPC:
        case Architecture::PowerPC64:
            store_u32(spec.bytes, 0x7FE00008u, endian);  // tw 31,0,0 (`trap`)
            spec.size = 4u;
            spec.rewinds_pc_on_hit = false;
            spec.mnemonic = "trap";
            return spec;

        case Architecture::MIPS32:
        case Architecture::MIPS64:
            store_u32(spec.bytes, 0x0000000Du, endian);  // break 0
            spec.size = 4u;
            spec.rewinds_pc_on_hit = false;
            spec.mnemonic = "break";
            return spec;

        case Architecture::Unknown:
            break;
    }
    return make_error("Cannot select software breakpoint trap for unknown CPU architecture");
}

void apply_software_breakpoint_shadow_filter(
    std::uint64_t read_address,
    std::span<std::uint8_t> buffer,
    std::span<const BreakpointDescriptor> breakpoints) noexcept {
    if (buffer.empty() || breakpoints.empty()) {
        return;
    }

    const std::uint64_t max_add = std::numeric_limits<std::uint64_t>::max() - read_address;
    const std::uint64_t clamped_len = std::min<std::uint64_t>(buffer.size(), max_add);
    const std::uint64_t read_end = read_address + clamped_len;

    for (const BreakpointDescriptor& bp : breakpoints) {
        if (bp.kind != BreakpointKind::Software || !bp.armed_in_target || bp.original_bytes.empty()) {
            continue;
        }
        const std::uint64_t bp_max = std::numeric_limits<std::uint64_t>::max() - bp.address;
        const std::uint64_t bp_len = std::min<std::uint64_t>(bp.original_bytes.size(), bp_max);
        const std::uint64_t bp_end = bp.address + bp_len;

        const std::uint64_t ov_start = std::max(read_address, bp.address);
        const std::uint64_t ov_end = std::min(read_end, bp_end);
        if (ov_start >= ov_end) {
            continue;
        }

        const auto buf_off = static_cast<std::size_t>(ov_start - read_address);
        const auto orig_off = static_cast<std::size_t>(ov_start - bp.address);
        const auto copy_len = static_cast<std::size_t>(ov_end - ov_start);
        std::copy_n(bp.original_bytes.data() + orig_off, copy_len, buffer.data() + buf_off);
    }
}

std::optional<std::uint64_t> compute_step_over_fallthrough(
    Architecture arch,
    Endianness endian,
    std::uint64_t instruction_pointer,
    std::span<const std::uint8_t> insn_bytes,
    bool thumb_mode) noexcept {
    if (insn_bytes.empty()) {
        return std::nullopt;
    }

    if (arch == Architecture::X86 || arch == Architecture::X86_64) {
        const bool is_64 = (arch == Architecture::X86_64);
        bool operand_size_override = false;
        bool address_size_override = false;
        std::size_t idx = 0u;

        // Consume legacy prefixes (bounded to 14 bytes max per x86 architectural 15-byte limit)
        while (idx < insn_bytes.size() && idx < 14u) {
            const std::uint8_t b = insn_bytes[idx];
            if (b == 0x66u) {
                operand_size_override = true;
                ++idx;
            } else if (b == 0x67u) {
                address_size_override = true;
                ++idx;
            } else if (b == 0xF0u || b == 0xF2u || b == 0xF3u ||
                       b == 0x26u || b == 0x2Eu || b == 0x36u || b == 0x3Eu ||
                       b == 0x64u || b == 0x65u) {
                ++idx;
            } else {
                break;
            }
        }

        // Optional REX prefix in 64-bit mode (`0x40..0x4F`)
        bool rex_w = false;
        if (is_64 && idx < insn_bytes.size() && (insn_bytes[idx] & 0xF0u) == 0x40u) {
            rex_w = (insn_bytes[idx] & 0x08u) != 0u;
            ++idx;
        }

        if (idx >= insn_bytes.size()) {
            return std::nullopt;
        }

        const std::uint8_t opcode = insn_bytes[idx++];

        // `E8 rel16/rel32` — near direct CALL
        if (opcode == 0xE8u) {
            const std::size_t disp_len = (!rex_w && operand_size_override) ? 2u : 4u;
            if (idx + disp_len <= insn_bytes.size()) {
                return instruction_pointer + idx + disp_len;
            }
            return std::nullopt;
        }

        // `9A ptr16:16/32` — far direct CALL (valid in 32-bit x86 mode only)
        if (!is_64 && opcode == 0x9Au) {
            const std::size_t ptr_len = operand_size_override ? 4u : 6u;
            if (idx + ptr_len <= insn_bytes.size()) {
                return instruction_pointer + idx + ptr_len;
            }
            return std::nullopt;
        }

        // `FF /2` (near indirect CALL r/m) or `FF /3` (far indirect CALL m16:16/32/64)
        if (opcode == 0xFFu && idx < insn_bytes.size()) {
            const std::uint8_t reg_op = static_cast<std::uint8_t>((insn_bytes[idx] >> 3u) & 0x7u);
            if (reg_op == 2u || reg_op == 3u) {
                const bool addr16 = !is_64 && address_size_override;
                if (const auto modrm_len = decode_x86_modrm_length(insn_bytes, idx, addr16)) {
                    return instruction_pointer + idx + *modrm_len;
                }
            }
        }

        return std::nullopt;
    }

    const EndianReader rd(insn_bytes, endian, AddressWidth::Bits64);

    if (arch == Architecture::ARM64) {
        const auto w = rd.read_u32(0u);
        if (!w.has_value()) {
            return std::nullopt;
        }
        // `BL imm26` (`100101...`) or `BLR Rn` (`1101011 0001 11111 000000 Rn 00000`)
        if ((*w & 0xFC000000u) == 0x94000000u || (*w & 0xFFFFFC1Fu) == 0xD63F0000u) {
            return instruction_pointer + 4u;
        }
        return std::nullopt;
    }

    if (arch == Architecture::ARM) {
        if (thumb_mode || (instruction_pointer & 1u) != 0u) {
            const std::uint64_t clean_pc = instruction_pointer & ~std::uint64_t{1u};
            const auto hw0 = rd.read_u16(0u);
            if (!hw0.has_value()) {
                return std::nullopt;
            }
            // 16-bit Thumb `BLX Rm`: `010001 11 1 Rm 000`
            if ((*hw0 & 0xFF87u) == 0x4780u) {
                return clean_pc + 2u;
            }
            // 32-bit Thumb-2 `BL` / `BLX imm`: `11110 S imm10` followed by `11 J1 1/0 J2 imm11`
            if ((*hw0 & 0xF800u) == 0xF000u) {
                if (const auto hw1 = rd.read_u16(2u); hw1.has_value() && (*hw1 & 0xC000u) == 0xC000u) {
                    return clean_pc + 4u;
                }
            }
            return std::nullopt;
        }

        const auto w = rd.read_u32(0u);
        if (!w.has_value()) {
            return std::nullopt;
        }
        // ARM32 conditional `BL imm24`, unconditional `BLX imm24`, or conditional `BLX Rm`
        if ((*w & 0x0F000000u) == 0x0B000000u ||
            (*w & 0xFE000000u) == 0xFA000000u ||
            (*w & 0x0FFFFFF0u) == 0x012FFF30u) {
            return instruction_pointer + 4u;
        }
        return std::nullopt;
    }

    if (arch == Architecture::RISCV32 || arch == Architecture::RISCV64) {
        const auto hw0 = rd.read_u16(0u);
        if (!hw0.has_value()) {
            return std::nullopt;
        }
        if ((*hw0 & 0x3u) != 0x3u) {
            // 16-bit compressed `C.JALR rs1` (`1001 rs1!=0 00000 10`) or RV32 `C.JAL` (`001 ... 01`)
            if (((*hw0 & 0xF07Fu) == 0x9002u && ((*hw0 >> 7u) & 0x1Fu) != 0u) ||
                (arch == Architecture::RISCV32 && (*hw0 & 0xE003u) == 0x2001u)) {
                return instruction_pointer + 2u;
            }
            return std::nullopt;
        }
        if (const auto w = rd.read_u32(0u); w.has_value()) {
            const std::uint32_t opcode = *w & 0x7Fu;
            const std::uint32_t rd_reg = (*w >> 7u) & 0x1Fu;
            // `JAL` (`0x6F`) or `JALR` (`0x67`) writing a link register (`rd != x0`)
            if ((opcode == 0x6Fu || opcode == 0x67u) && rd_reg != 0u) {
                return instruction_pointer + 4u;
            }
        }
        return std::nullopt;
    }

    if (arch == Architecture::PowerPC || arch == Architecture::PowerPC64) {
        if (const auto w = rd.read_u32(0u); w.has_value()) {
            // `bl` (`LK == 1`, opcode 18) or `bctrl` / `blrl` (`LK == 1`, opcode 19)
            const std::uint32_t opcd = (*w >> 26u) & 0x3Fu;
            const bool lk = (*w & 1u) != 0u;
            if (lk && (opcd == 18u || opcd == 19u)) {
                return instruction_pointer + 4u;
            }
        }
        return std::nullopt;
    }

    if (arch == Architecture::MIPS32 || arch == Architecture::MIPS64) {
        if (const auto w = rd.read_u32(0u); w.has_value()) {
            const std::uint32_t opcd = (*w >> 26u) & 0x3Fu;
            const std::uint32_t funct = *w & 0x3Fu;
            // `JAL` (`opcd == 3`) or `JALR` (`opcd == 0 && funct == 9`): +8 skips branch delay slot
            if (opcd == 3u || (opcd == 0u && funct == 9u)) {
                return instruction_pointer + 8u;
            }
        }
        return std::nullopt;
    }

    return std::nullopt;
}

ForgivingValue<X86DebugRegisterPlan> build_x86_debug_register_plan(
    Architecture arch,
    std::span<const BreakpointDescriptor> breakpoints) {
    if (arch != Architecture::X86 && arch != Architecture::X86_64) {
        return {
            std::nullopt,
            SubsystemStatus::unavailable(
                "debugger_hw",
                std::format("x86 DR0..DR7 hardware debug registers are unsupported on {}",
                            to_string(arch))),
        };
    }

    X86DebugRegisterPlan plan{};
    std::size_t active_hw_count = 0u;

    for (const BreakpointDescriptor& bp : breakpoints) {
        if (!is_hardware_breakpoint(bp.kind) || !bp.enabled) {
            continue;
        }
        ++active_hw_count;
        if (active_hw_count > 4u) {
            return {
                std::nullopt,
                SubsystemStatus::unavailable(
                    "debugger_hw",
                    "Hardware breakpoint limit exceeded: x86/x86_64 provides only 4 debug registers (DR0..DR3)"),
            };
        }

        // Validate condition & length per Intel SDM Vol. 3B §17.2.4
        std::uint64_t rw_bits = 0u;
        std::uint64_t len_bits = 0u;

        if (bp.kind == BreakpointKind::HardwareExecute) {
            if (bp.byte_size != 1u) {
                return {
                    std::nullopt,
                    SubsystemStatus::unavailable(
                        "debugger_hw",
                        std::format("HardwareExecute breakpoint at 0x{:X} must have 1-byte length (got {})",
                                    bp.address,
                                    bp.byte_size)),
                };
            }
            rw_bits = 0b00ULL;
            len_bits = 0b00ULL;
        } else {
            rw_bits = (bp.kind == BreakpointKind::HardwareWrite) ? 0b01ULL : 0b11ULL;
            switch (bp.byte_size) {
                case 1u: len_bits = 0b00ULL; break;
                case 2u: len_bits = 0b01ULL; break;
                case 4u: len_bits = 0b11ULL; break;
                case 8u:
                    if (arch != Architecture::X86_64) {
                        return {
                            std::nullopt,
                            SubsystemStatus::unavailable(
                                "debugger_hw",
                                "8-byte hardware watchpoints require 64-bit x86_64 mode"),
                        };
                    }
                    len_bits = 0b10ULL;
                    break;
                default:
                    return {
                        std::nullopt,
                        SubsystemStatus::unavailable(
                            "debugger_hw",
                            std::format("Unsupported hardware watchpoint size {} (expected 1, 2, 4, or 8)",
                                        bp.byte_size)),
                    };
            }
            if ((bp.address % bp.byte_size) != 0u) {
                return {
                    std::nullopt,
                    SubsystemStatus::unavailable(
                        "debugger_hw",
                        std::format("Hardware watchpoint address 0x{:X} must be {}-byte aligned",
                                    bp.address,
                                    bp.byte_size)),
                };
            }
        }

        std::optional<std::size_t> chosen_slot;
        if (bp.hardware_slot.has_value() && *bp.hardware_slot < 4u && !plan.slot_used[*bp.hardware_slot]) {
            chosen_slot = *bp.hardware_slot;
        } else {
            for (std::size_t s = 0u; s < 4u; ++s) {
                if (!plan.slot_used[s]) {
                    chosen_slot = s;
                    break;
                }
            }
        }

        if (!chosen_slot.has_value()) {
            return {
                std::nullopt,
                SubsystemStatus::unavailable(
                    "debugger_hw",
                    "All 4 hardware debug register slots (DR0..DR3) are occupied"),
            };
        }

        const std::size_t s = *chosen_slot;
        plan.slot_used[s] = true;
        plan.dr_address[s] = bp.address;
        plan.slot_owner_id[s] = bp.id;

        // Local enable `L_s` = bit `2 * s`; condition `R/W_s` & `LEN_s` = bits `16 + 4 * s .. 19 + 4 * s`
        plan.dr7 |= (1ULL << (s * 2u));
        plan.dr7 |= ((rw_bits & 0x3ULL) << (16u + s * 4u));
        plan.dr7 |= ((len_bits & 0x3ULL) << (18u + s * 4u));
    }

    plan.status = SubsystemStatus::available(
        "debugger_hw",
        std::format("Encoded {}/4 x86 hardware debug register slot(s) (DR7=0x{:X})",
                    active_hw_count,
                    plan.dr7));
    return {plan, plan.status};
}

std::optional<std::uint8_t> match_x86_dr6_triggered_slot(
    std::uint64_t dr6,
    const X86DebugRegisterPlan& plan) noexcept {
    for (std::uint8_t s = 0u; s < 4u; ++s) {
        if (plan.slot_used[s] && ((dr6 >> s) & 1ULL) != 0ULL) {
            return s;
        }
    }
    return std::nullopt;
}

}  // namespace peelf::debugger
