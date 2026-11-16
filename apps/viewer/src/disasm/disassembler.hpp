// disassembler.hpp
#pragma once

#include <capstone/capstone.h>
#include <peelf/binary_image.hpp>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace viewer {

enum class Architecture {
    X86_32,
    X86_64,
    ARM32,
    ARM64,
    MIPS32,
    MIPS64,
    PowerPC32,
    PowerPC64,
    RISCV32,
    RISCV64
};

enum class Endianness {
    Little,
    Big
};

enum class InstructionFlow : std::uint8_t { Normal, Call, ConditionalBranch, Branch, Return, ConditionalReturn };

struct AbsoluteJumpTableOperand {
    std::uint64_t address = 0;
    std::uint32_t index_register = 0;
    std::uint8_t entry_size = 0;
};

struct Instruction {
    std::uint64_t address;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string comment;
    std::optional<std::uint64_t> branch_target;
    InstructionFlow flow = InstructionFlow::Normal;
    bool delay_slot = false;
    bool annulled_delay_slot = false;
    std::optional<AbsoluteJumpTableOperand> jump_table;
    std::optional<std::uint64_t> compare_bound;
    std::uint32_t compare_register = 0;

    std::string to_string() const {
        return mnemonic + (operands.empty() ? "" : " " + operands);
    }
};

class Disassembler {
public:
    Disassembler() = default;
    ~Disassembler() { close(); }

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    Disassembler(Disassembler&& other) noexcept
        : handle_(other.handle_)
        , arch_(other.arch_)
        , endian_(other.endian_)
        , initialized_(other.initialized_)
    {
        other.handle_ = 0;
        other.initialized_ = false;
    }

    Disassembler& operator=(Disassembler&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            arch_ = other.arch_;
            endian_ = other.endian_;
            initialized_ = other.initialized_;
            other.handle_ = 0;
            other.initialized_ = false;
        }
        return *this;
    }

    bool init(Architecture arch, Endianness endian = Endianness::Little) {
        close();
        arch_ = arch;
        endian_ = endian;

        cs_arch cs_architecture;
        cs_mode cs_mode_flags;

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
                cs_mode_flags = static_cast<cs_mode>(CS_MODE_ARM | (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
                break;
            case Architecture::ARM64:
                cs_architecture = CS_ARCH_ARM64;
                cs_mode_flags = CS_MODE_LITTLE_ENDIAN;
                break;
            case Architecture::MIPS32:
                cs_architecture = CS_ARCH_MIPS;
                cs_mode_flags = static_cast<cs_mode>(
                    CS_MODE_MIPS32 | (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
                break;
            case Architecture::MIPS64:
                cs_architecture = CS_ARCH_MIPS;
                cs_mode_flags = static_cast<cs_mode>(
                    CS_MODE_MIPS64 | (endian == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
                break;
            case Architecture::PowerPC32:
                cs_architecture = CS_ARCH_PPC;
                cs_mode_flags = static_cast<cs_mode>(
                    endian == Endianness::Little ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN);
                break;
            case Architecture::PowerPC64:
                cs_architecture = CS_ARCH_PPC;
                cs_mode_flags = static_cast<cs_mode>(
                    CS_MODE_64 | (endian == Endianness::Little ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN));
                break;
            case Architecture::RISCV32:
                cs_architecture = CS_ARCH_RISCV;
                cs_mode_flags = CS_MODE_RISCV32;
                break;
            case Architecture::RISCV64:
                cs_architecture = CS_ARCH_RISCV;
                cs_mode_flags = CS_MODE_RISCV64;
                break;
            default:
                return false;
        }

        if (cs_open(cs_architecture, cs_mode_flags, &handle_) != CS_ERR_OK) {
            return false;
        }

        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);

        initialized_ = true;
        return true;
    }

    void close() {
        if (initialized_ && handle_ != 0) {
            cs_close(&handle_);
        }
        handle_ = 0;
        initialized_ = false;
    }

    [[nodiscard]] bool is_initialized() const { return initialized_; }
    [[nodiscard]] Architecture architecture() const { return arch_; }

    std::vector<Instruction> disassemble(const std::uint8_t* code, std::size_t size,
                                         std::uint64_t address) {
        std::vector<Instruction> result;
        if (!initialized_) return result;

        cs_insn* insn;
        std::size_t count = cs_disasm(handle_, code, size, address, 0, &insn);

        if (count > 0) {
            result.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                Instruction inst;
                inst.address = insn[i].address;
                inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
                inst.mnemonic = insn[i].mnemonic;
                inst.operands = insn[i].op_str;
                inst.branch_target = direct_target(insn[i]);
                inst.flow = instruction_flow(insn[i]);
                inst.delay_slot = (arch_ == Architecture::MIPS32 || arch_ == Architecture::MIPS64) &&
                    inst.flow != InstructionFlow::Normal;
                annotate_jump_table(insn[i], inst);
                inst.annulled_delay_slot = inst.delay_slot &&
                    (inst.mnemonic == "beql" || inst.mnemonic == "bnel" || inst.mnemonic == "blezl" ||
                     inst.mnemonic == "bgtzl" || inst.mnemonic == "bltzl" || inst.mnemonic == "bgezl");
                result.push_back(std::move(inst));
            }
            cs_free(insn, count);
        }

        return result;
    }

    std::vector<Instruction> disassemble_count(const std::uint8_t* code, std::size_t size,
                                                std::uint64_t address, std::size_t count) {
        std::vector<Instruction> result;
        if (!initialized_) return result;

        cs_insn* insn;
        std::size_t actual = cs_disasm(handle_, code, size, address, count, &insn);

        if (actual > 0) {
            result.reserve(actual);
            for (std::size_t i = 0; i < actual; ++i) {
                Instruction inst;
                inst.address = insn[i].address;
                inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
                inst.mnemonic = insn[i].mnemonic;
                inst.operands = insn[i].op_str;
                inst.branch_target = direct_target(insn[i]);
                inst.flow = instruction_flow(insn[i]);
                inst.delay_slot = (arch_ == Architecture::MIPS32 || arch_ == Architecture::MIPS64) &&
                    inst.flow != InstructionFlow::Normal;
                annotate_jump_table(insn[i], inst);
                inst.annulled_delay_slot = inst.delay_slot &&
                    (inst.mnemonic == "beql" || inst.mnemonic == "bnel" || inst.mnemonic == "blezl" ||
                     inst.mnemonic == "bgtzl" || inst.mnemonic == "bltzl" || inst.mnemonic == "bgezl");
                result.push_back(std::move(inst));
            }
            cs_free(insn, actual);
        }

        return result;
    }

    [[nodiscard]] const char* get_error() const {
        if (!initialized_) return "Not initialized";
        return cs_strerror(cs_errno(handle_));
    }

    bool set_thumb_mode(bool enable) {
        if (!initialized_ || arch_ != Architecture::ARM32) return false;
        const auto mode = static_cast<cs_mode>((enable ? CS_MODE_THUMB : CS_MODE_ARM) |
            (endian_ == Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
        return cs_option(handle_, CS_OPT_MODE, mode) == CS_ERR_OK;
    }

    static bool is_simd_instruction(const Instruction& inst) {
        const std::string& m = inst.mnemonic;
        if (m.empty()) return false;

        // AVX/AVX2/AVX-512 (v-prefixed)
        if (m[0] == 'v') return true;

        // Common SSE prefixes
        if (m.find("movap") == 0 || m.find("movup") == 0) return true;
        if (m.find("movdq") == 0 || m.find("movss") == 0 || m.find("movsd") == 0) return true;
        if (m.find("adds") == 0 || m.find("subs") == 0 || m.find("muls") == 0 || m.find("divs") == 0) return true;
        if (m.find("addp") == 0 || m.find("subp") == 0 || m.find("mulp") == 0 || m.find("divp") == 0) return true;
        if (m.find("sqrt") == 0 || m.find("rsqrt") == 0) return true;
        if (m.find("pand") == 0 || m.find("por") == 0 || m.find("pxor") == 0) return true;
        if (m.find("padd") == 0 || m.find("psub") == 0 || m.find("pmul") == 0) return true;
        if (m.find("pcmp") == 0 || m.find("pshuf") == 0 || m.find("punpck") == 0) return true;
        if (m.find("cvt") == 0) return true;
        if (m.find("shufp") == 0 || m.find("unpack") == 0) return true;

        return false;
    }

    static bool is_branch_instruction(const Instruction& inst) {
        const std::string& m = inst.mnemonic;
        if (m.empty()) return false;

        if (m[0] == 'j') return true;
        if (m == "call" || m == "ret" || m == "retn") return true;
        if (m == "loop" || m == "loope" || m == "loopne") return true;
        if (m == "syscall" || m == "sysret") return true;
        if (m == "b" || m == "bl" || m == "bx" || m == "blx") return true;
        if (m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") return true;

        return false;
    }

    static bool is_data_movement(const Instruction& inst) {
        const std::string& m = inst.mnemonic;
        if (m.find("mov") == 0) return true;
        if (m == "push" || m == "pop") return true;
        if (m == "lea") return true;
        if (m == "xchg") return true;
        if (m == "ldr" || m == "str" || m == "ldp" || m == "stp") return true;
        return false;
    }

    static bool is_nop(const Instruction& inst) {
        const std::string& m = inst.mnemonic;
        return m == "nop" || m == "int3" || m == "ud2";
    }

private:
    void annotate_jump_table(const cs_insn& insn, Instruction& result) const {
        if (!insn.detail || (arch_ != Architecture::X86_32 && arch_ != Architecture::X86_64)) return;
        const auto& detail = insn.detail->x86;
        if (insn.id == X86_INS_CMP && detail.op_count == 2 && detail.operands[0].type == X86_OP_REG &&
            detail.operands[1].type == X86_OP_IMM && detail.operands[1].imm >= 0) {
            result.compare_register = detail.operands[0].reg;
            result.compare_bound = static_cast<std::uint64_t>(detail.operands[1].imm);
        }
        if (insn.id != X86_INS_JMP || detail.op_count != 1 || detail.operands[0].type != X86_OP_MEM) return;
        const auto& operand = detail.operands[0];
        const auto& memory = operand.mem;
        if (memory.base != X86_REG_INVALID || memory.index == X86_REG_INVALID || memory.segment != X86_REG_INVALID ||
            memory.disp < 0 || memory.scale != operand.size || (operand.size != 4 && operand.size != 8)) return;
        result.jump_table = AbsoluteJumpTableOperand{static_cast<std::uint64_t>(memory.disp),
            static_cast<std::uint32_t>(memory.index), operand.size};
    }
    [[nodiscard]] InstructionFlow instruction_flow(const cs_insn& insn) const {
        if (!insn.detail) return InstructionFlow::Normal;
        const auto group = [&insn](std::uint8_t value) {
            for (std::uint8_t i = 0; i < insn.detail->groups_count; ++i)
                if (insn.detail->groups[i] == value) return true;
            return false;
        };
        const std::string_view m = insn.mnemonic;
        const std::string_view operands = insn.op_str;
        const bool conditional_arm = arch_ == Architecture::ARM32 && insn.detail->arm.cc != ARM_CC_AL &&
            insn.detail->arm.cc != ARM_CC_INVALID;
        const auto return_flow = conditional_arm ? InstructionFlow::ConditionalReturn : InstructionFlow::Return;
        if (group(CS_GRP_RET) || group(CS_GRP_IRET)) return return_flow;
        if (arch_ == Architecture::ARM32) {
            if ((insn.id == ARM_INS_BX && operands == "lr") ||
                ((insn.id == ARM_INS_POP || insn.id == ARM_INS_LDM) && operands.find("pc") != operands.npos))
                return return_flow;
        }
        if ((arch_ == Architecture::MIPS32 || arch_ == Architecture::MIPS64) &&
            m == "jr" && (operands == "$ra" || operands == "$31")) return InstructionFlow::Return;
        if ((arch_ == Architecture::MIPS32 || arch_ == Architecture::MIPS64) &&
            (insn.id == MIPS_INS_JAL || insn.id == MIPS_INS_JALR || insn.id == MIPS_INS_BAL || insn.id == MIPS_INS_JALX))
            return InstructionFlow::Call;
        if ((arch_ == Architecture::PowerPC32 || arch_ == Architecture::PowerPC64) && m == "blr")
            return InstructionFlow::Return;
        if ((arch_ == Architecture::RISCV32 || arch_ == Architecture::RISCV64) &&
            (m == "ret" || (m == "jr" && operands == "ra"))) return InstructionFlow::Return;
        if (arch_ == Architecture::RISCV32 || arch_ == Architecture::RISCV64) {
            const auto& detail = insn.detail->riscv;
            if (m == "j" || m == "jr" || m == "c.j" || m == "c.jr" ||
                ((insn.id == RISCV_INS_JAL || insn.id == RISCV_INS_JALR) && detail.op_count > 1 &&
                 detail.operands[0].type == RISCV_OP_REG && detail.operands[0].reg == RISCV_REG_X0))
                return InstructionFlow::Branch;
        }
        if ((arch_ == Architecture::PowerPC32 || arch_ == Architecture::PowerPC64) &&
            (insn.id == PPC_INS_BL || insn.id == PPC_INS_BLA || insn.id == PPC_INS_BCTRL || insn.id == PPC_INS_BLRL ||
             insn.id == PPC_INS_BCL || insn.id == PPC_INS_BCLA || insn.id == PPC_INS_BCCTRL || insn.id == PPC_INS_BCLRL))
            return InstructionFlow::Call;
        if (group(CS_GRP_CALL)) return InstructionFlow::Call;
        if (arch_ == Architecture::ARM32 && (insn.id == ARM_INS_TBB || insn.id == ARM_INS_TBH))
            return InstructionFlow::Branch;
        if (!group(CS_GRP_JUMP)) return InstructionFlow::Normal;
        switch (arch_) {
            case Architecture::X86_32: case Architecture::X86_64:
                return insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP ? InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
            case Architecture::ARM32:
                if (insn.id == ARM_INS_CBZ || insn.id == ARM_INS_CBNZ) return InstructionFlow::ConditionalBranch;
                return insn.detail->arm.cc == ARM_CC_AL || insn.detail->arm.cc == ARM_CC_INVALID ?
                    InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
            case Architecture::ARM64:
                return (insn.id == ARM64_INS_B && (insn.detail->arm64.cc == ARM64_CC_AL || insn.detail->arm64.cc == ARM64_CC_INVALID)) ||
                    insn.id == ARM64_INS_BR ? InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
            case Architecture::MIPS32: case Architecture::MIPS64:
                return m == "j" || m == "jr" || m == "b" ? InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
            case Architecture::PowerPC32: case Architecture::PowerPC64:
                return m == "b" || m == "ba" || m == "bctr" ? InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
            case Architecture::RISCV32: case Architecture::RISCV64:
                return m == "j" || m == "jr" || m == "jal" || m == "jalr" || m == "c.j" || m == "c.jr" ?
                    InstructionFlow::Branch : InstructionFlow::ConditionalBranch;
        }
        return InstructionFlow::Normal;
    }
    [[nodiscard]] std::optional<std::uint64_t> direct_target(const cs_insn& instruction) const {
        if (!instruction.detail) return std::nullopt;
        const auto flow = instruction_flow(instruction);
        bool branch = flow == InstructionFlow::Call || flow == InstructionFlow::Branch ||
            flow == InstructionFlow::ConditionalBranch;
        for (std::uint8_t i = 0; i < instruction.detail->groups_count; ++i)
            branch |= instruction.detail->groups[i] == CS_GRP_CALL || instruction.detail->groups[i] == CS_GRP_JUMP;
        if (!branch) return std::nullopt;
        std::optional<std::uint64_t> target;
        const auto scan = [&target](const auto& detail, auto immediate_type) {
            for (std::uint8_t i = 0; i < detail.op_count; ++i)
                if (detail.operands[i].type == immediate_type)
                    target = static_cast<std::uint64_t>(detail.operands[i].imm);
        };
        switch (arch_) {
            case Architecture::X86_32: case Architecture::X86_64: scan(instruction.detail->x86, X86_OP_IMM); break;
            case Architecture::ARM32: scan(instruction.detail->arm, ARM_OP_IMM); break;
            case Architecture::ARM64: scan(instruction.detail->arm64, ARM64_OP_IMM); break;
            case Architecture::MIPS32: case Architecture::MIPS64: scan(instruction.detail->mips, MIPS_OP_IMM); break;
            case Architecture::PowerPC32: case Architecture::PowerPC64: scan(instruction.detail->ppc, PPC_OP_IMM); break;
            case Architecture::RISCV32: case Architecture::RISCV64:
                if (instruction.id != RISCV_INS_JALR && instruction.id != RISCV_INS_C_JR && instruction.id != RISCV_INS_C_JALR) {
                    scan(instruction.detail->riscv, RISCV_OP_IMM);
                    if (target) {
                        *target += instruction.address;
                        if (arch_ == Architecture::RISCV32) *target &= 0xFFFFFFFFULL;
                    }
                }
                break;
        }
        return target;
    }
    csh handle_ = 0;
    Architecture arch_ = Architecture::X86_64;
    Endianness endian_ = Endianness::Little;
    bool initialized_ = false;
};

[[nodiscard]] constexpr std::optional<Architecture> to_disassembler_architecture(
    peelf::Architecture arch) noexcept {
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

[[nodiscard]] constexpr peelf::Architecture to_core_architecture(Architecture arch) noexcept {
    switch (arch) {
        case Architecture::X86_32:    return peelf::Architecture::X86;
        case Architecture::X86_64:    return peelf::Architecture::X86_64;
        case Architecture::ARM32:     return peelf::Architecture::ARM;
        case Architecture::ARM64:     return peelf::Architecture::ARM64;
        case Architecture::MIPS32:    return peelf::Architecture::MIPS32;
        case Architecture::MIPS64:    return peelf::Architecture::MIPS64;
        case Architecture::PowerPC32: return peelf::Architecture::PowerPC;
        case Architecture::PowerPC64: return peelf::Architecture::PowerPC64;
        case Architecture::RISCV32:   return peelf::Architecture::RISCV32;
        case Architecture::RISCV64:   return peelf::Architecture::RISCV64;
    }
    return peelf::Architecture::Unknown;
}

[[nodiscard]] constexpr Endianness to_disassembler_endianness(peelf::Endianness endian) noexcept {
    return endian == peelf::Endianness::Big ? Endianness::Big : Endianness::Little;
}

[[nodiscard]] constexpr peelf::Endianness to_core_endianness(Endianness endian) noexcept {
    return endian == Endianness::Big ? peelf::Endianness::Big : peelf::Endianness::Little;
}

[[nodiscard]] constexpr Architecture architecture_from_machine(std::uint16_t machine) noexcept {
    switch (machine) {
        case 0x014C: return Architecture::X86_32;
        case 0x8664: return Architecture::X86_64;
        case 0x01C0:
        case 0x01C4: return Architecture::ARM32;
        case 0xAA64: return Architecture::ARM64;
        default:     return Architecture::X86_64;
    }
}

} // namespace viewer
