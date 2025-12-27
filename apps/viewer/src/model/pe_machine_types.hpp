//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_MACHINE_TYPES_HPP
#define PEELF_EXPLORER_PE_MACHINE_TYPES_HPP
namespace pe {

// Machine types
namespace machine {
    constexpr uint16_t UNKNOWN      = 0x0000;  // Unknown / any machine type
    constexpr uint16_t ALPHA        = 0x0184;  // Alpha AXP, 32-bit
    constexpr uint16_t ALPHA64      = 0x0284;  // Alpha 64 / AXP64
    constexpr uint16_t AM33         = 0x01D3;  // Matsushita AM33
    constexpr uint16_t AMD64        = 0x8664;  // x64
    constexpr uint16_t ARM          = 0x01C0;  // ARM little endian
    constexpr uint16_t ARM64        = 0xAA64;  // ARM64 little endian
    constexpr uint16_t ARM64EC      = 0xA641;  // ARM64EC (emulation compatible)
    constexpr uint16_t ARM64X       = 0xA64E;  // ARM64X (hybrid)
    constexpr uint16_t ARMNT        = 0x01C4;  // ARM Thumb-2 little endian
    constexpr uint16_t AXP64        = 0x0284;  // Same as ALPHA64
    constexpr uint16_t EBC          = 0x0EBC;  // EFI byte code
    constexpr uint16_t I386         = 0x014C;  // Intel 386 or later
    constexpr uint16_t IA64         = 0x0200;  // Intel Itanium
    constexpr uint16_t LOONGARCH32  = 0x6232;  // LoongArch 32-bit
    constexpr uint16_t LOONGARCH64  = 0x6264;  // LoongArch 64-bit
    constexpr uint16_t M32R         = 0x9041;  // Mitsubishi M32R little endian
    constexpr uint16_t MIPS16       = 0x0266;  // MIPS16
    constexpr uint16_t MIPSFPU      = 0x0366;  // MIPS with FPU
    constexpr uint16_t MIPSFPU16    = 0x0466;  // MIPS16 with FPU
    constexpr uint16_t POWERPC      = 0x01F0;  // Power PC little endian
    constexpr uint16_t POWERPCFP    = 0x01F1;  // Power PC with floating point
    constexpr uint16_t R3000        = 0x0162;  // MIPS I, 32-bit little endian
    constexpr uint16_t R3000BE      = 0x0160;  // MIPS I, 32-bit big endian
    constexpr uint16_t R4000        = 0x0166;  // MIPS III, 64-bit little endian
    constexpr uint16_t R10000       = 0x0168;  // MIPS IV, 64-bit little endian
    constexpr uint16_t RISCV32      = 0x5032;  // RISC-V 32-bit
    constexpr uint16_t RISCV64      = 0x5064;  // RISC-V 64-bit
    constexpr uint16_t RISCV128     = 0x5128;  // RISC-V 128-bit
    constexpr uint16_t SH3          = 0x01A2;  // Hitachi SH3
    constexpr uint16_t SH3DSP       = 0x01A3;  // Hitachi SH3 DSP
    constexpr uint16_t SH4          = 0x01A6;  // Hitachi SH4
    constexpr uint16_t SH5          = 0x01A8;  // Hitachi SH5
    constexpr uint16_t THUMB        = 0x01C2;  // Thumb
    constexpr uint16_t WCEMIPSV2    = 0x0169;  // MIPS little-endian WCE v2
}

constexpr const char* get_machine_name(uint16_t machine_type) {
    switch (machine_type) {
        case machine::UNKNOWN:      return "Unknown";
        case machine::ALPHA:        return "Alpha AXP (32-bit)";
        case machine::ALPHA64:      return "Alpha 64 / AXP64";
        case machine::AM33:         return "Matsushita AM33";
        case machine::AMD64:        return "x64 (AMD64)";
        case machine::ARM:          return "ARM";
        case machine::ARM64:        return "ARM64";
        case machine::ARM64EC:      return "ARM64EC";
        case machine::ARM64X:       return "ARM64X";
        case machine::ARMNT:        return "ARM Thumb-2";
        case machine::EBC:          return "EFI Byte Code";
        case machine::I386:         return "x86 (i386)";
        case machine::IA64:         return "Intel Itanium";
        case machine::LOONGARCH32:  return "LoongArch 32-bit";
        case machine::LOONGARCH64:  return "LoongArch 64-bit";
        case machine::M32R:         return "Mitsubishi M32R";
        case machine::MIPS16:       return "MIPS16";
        case machine::MIPSFPU:      return "MIPS with FPU";
        case machine::MIPSFPU16:    return "MIPS16 with FPU";
        case machine::POWERPC:      return "PowerPC";
        case machine::POWERPCFP:    return "PowerPC with FPU";
        case machine::R3000:        return "MIPS R3000 (little endian)";
        case machine::R3000BE:      return "MIPS R3000 (big endian)";
        case machine::R4000:        return "MIPS R4000";
        case machine::R10000:       return "MIPS R10000";
        case machine::RISCV32:      return "RISC-V 32-bit";
        case machine::RISCV64:      return "RISC-V 64-bit";
        case machine::RISCV128:     return "RISC-V 128-bit";
        case machine::SH3:          return "Hitachi SH3";
        case machine::SH3DSP:       return "Hitachi SH3 DSP";
        case machine::SH4:          return "Hitachi SH4";
        case machine::SH5:          return "Hitachi SH5";
        case machine::THUMB:        return "Thumb";
        case machine::WCEMIPSV2:    return "MIPS WCE v2";
        default:                    return "Unknown";
    }
}

} // namespace pe
#endif //PEELF_EXPLORER_PE_MACHINE_TYPES_HPP