//
// Created by wsoll on 12/22/2025.
//

#ifndef PEELF_EXPLORER_ELF_DEFINITIONS_H
#define PEELF_EXPLORER_ELF_DEFINITIONS_H



struct ElfSummary {
    std::uint8_t ei_class{};  // 1=32-bit, 2=64-bit
    std::uint8_t ei_data{};   // 1=little, 2=big
    std::uint16_t e_type{};
    std::uint16_t e_machine{};
};










#endif //PEELF_EXPLORER_ELF_DEFINITIONS_H