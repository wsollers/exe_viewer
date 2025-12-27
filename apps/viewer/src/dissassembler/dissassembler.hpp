// disassembler.hpp
#pragma once

#include <capstone/capstone.h>
#include <cstdint>
#include <string>
#include <vector>

// Handle Capstone version differences for ARM64 architecture name
#if defined(CS_ARCH_AARCH64)
    #define CAPSTONE_ARM64_ARCH CS_ARCH_AARCH64
#elif defined(CS_ARCH_ARM64)
    #define CAPSTONE_ARM64_ARCH CS_ARCH_ARM64
#else
    // Fallback: try the numeric value (4 is typically ARM64)
    #define CAPSTONE_ARM64_ARCH ((cs_arch)4)
#endif

namespace viewer {

enum class Architecture {
    X86_32,
    X86_64,
    ARM32,
    ARM64
};

struct Instruction {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string comment;

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
            initialized_ = other.initialized_;
            other.handle_ = 0;
            other.initialized_ = false;
        }
        return *this;
    }

    bool init(Architecture arch) {
        close();
        arch_ = arch;

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
                cs_mode_flags = CS_MODE_ARM;
                break;
            case Architecture::ARM64:
                cs_architecture = CAPSTONE_ARM64_ARCH;
                cs_mode_flags = CS_MODE_ARM;
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

    std::vector<Instruction> disassemble(const uint8_t* code, size_t size, uint64_t address) {
        std::vector<Instruction> result;
        if (!initialized_) return result;

        cs_insn* insn;
        size_t count = cs_disasm(handle_, code, size, address, 0, &insn);

        if (count > 0) {
            result.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                Instruction inst;
                inst.address = insn[i].address;
                inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
                inst.mnemonic = insn[i].mnemonic;
                inst.operands = insn[i].op_str;
                result.push_back(std::move(inst));
            }
            cs_free(insn, count);
        }

        return result;
    }

    std::vector<Instruction> disassemble_count(const uint8_t* code, size_t size,
                                                uint64_t address, size_t count) {
        std::vector<Instruction> result;
        if (!initialized_) return result;

        cs_insn* insn;
        size_t actual = cs_disasm(handle_, code, size, address, count, &insn);

        if (actual > 0) {
            result.reserve(actual);
            for (size_t i = 0; i < actual; ++i) {
                Instruction inst;
                inst.address = insn[i].address;
                inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
                inst.mnemonic = insn[i].mnemonic;
                inst.operands = insn[i].op_str;
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
        cs_mode mode = enable ? CS_MODE_THUMB : CS_MODE_ARM;
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
    csh handle_ = 0;
    Architecture arch_ = Architecture::X86_64;
    bool initialized_ = false;
};

inline Architecture architecture_from_machine(uint16_t machine) {
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