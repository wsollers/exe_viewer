//
// Created by wsoll on 12/26/2025.
//

#ifndef PEELF_EXPLORER_PE_MACHINE_TYPES_HPP
#define PEELF_EXPLORER_PE_MACHINE_TYPES_HPP

#include <cstdint>

namespace pe {

// Machine types
namespace machine {
    inline constexpr std::uint16_t UNKNOWN      = 0x0000u;  // Unknown / any machine type
    inline constexpr std::uint16_t ALPHA        = 0x0184u;  // Alpha AXP, 32-bit
    inline constexpr std::uint16_t ALPHA64      = 0x0284u;  // Alpha 64 / AXP64
    inline constexpr std::uint16_t AM33         = 0x01D3u;  // Matsushita AM33
    inline constexpr std::uint16_t AMD64        = 0x8664u;  // x64
    inline constexpr std::uint16_t ARM          = 0x01C0u;  // ARM little endian
    inline constexpr std::uint16_t ARM64        = 0xAA64u;  // ARM64 little endian
    inline constexpr std::uint16_t ARM64EC      = 0xA641u;  // ARM64EC (emulation compatible)
    inline constexpr std::uint16_t ARM64X       = 0xA64Eu;  // ARM64X (hybrid)
    inline constexpr std::uint16_t ARMNT        = 0x01C4u;  // ARM Thumb-2 little endian
    inline constexpr std::uint16_t AXP64        = 0x0284u;  // Same as ALPHA64
    inline constexpr std::uint16_t EBC          = 0x0EBCu;  // EFI byte code
    inline constexpr std::uint16_t I386         = 0x014Cu;  // Intel 386 or later
    inline constexpr std::uint16_t IA64         = 0x0200u;  // Intel Itanium
    inline constexpr std::uint16_t LOONGARCH32  = 0x6232u;  // LoongArch 32-bit
    inline constexpr std::uint16_t LOONGARCH64  = 0x6264u;  // LoongArch 64-bit
    inline constexpr std::uint16_t M32R         = 0x9041u;  // Mitsubishi M32R little endian
    inline constexpr std::uint16_t MIPS16       = 0x0266u;  // MIPS16
    inline constexpr std::uint16_t MIPSFPU      = 0x0366u;  // MIPS with FPU
    inline constexpr std::uint16_t MIPSFPU16    = 0x0466u;  // MIPS16 with FPU
    inline constexpr std::uint16_t POWERPC      = 0x01F0u;  // Power PC little endian
    inline constexpr std::uint16_t POWERPCFP    = 0x01F1u;  // Power PC with floating point
    inline constexpr std::uint16_t R3000        = 0x0162u;  // MIPS I, 32-bit little endian
    inline constexpr std::uint16_t R3000BE      = 0x0160u;  // MIPS I, 32-bit big endian
    inline constexpr std::uint16_t R4000        = 0x0166u;  // MIPS III, 64-bit little endian
    inline constexpr std::uint16_t R10000       = 0x0168u;  // MIPS IV, 64-bit little endian
    inline constexpr std::uint16_t RISCV32      = 0x5032u;  // RISC-V 32-bit
    inline constexpr std::uint16_t RISCV64      = 0x5064u;  // RISC-V 64-bit
    inline constexpr std::uint16_t RISCV128     = 0x5128u;  // RISC-V 128-bit
    inline constexpr std::uint16_t SH3          = 0x01A2u;  // Hitachi SH3
    inline constexpr std::uint16_t SH3DSP       = 0x01A3u;  // Hitachi SH3 DSP
    inline constexpr std::uint16_t SH4          = 0x01A6u;  // Hitachi SH4
    inline constexpr std::uint16_t SH5          = 0x01A8u;  // Hitachi SH5
    inline constexpr std::uint16_t THUMB        = 0x01C2u;  // Thumb
    inline constexpr std::uint16_t WCEMIPSV2    = 0x0169u;  // MIPS little-endian WCE v2
} // namespace machine

[[nodiscard]] constexpr const char* get_machine_name(std::uint16_t machine_type) noexcept {
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