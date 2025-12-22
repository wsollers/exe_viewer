//
// Created by wsoll on 12/22/2025.
//

#ifndef PEELF_EXPLORER_PE_DEFINITIONS_H
#define PEELF_EXPLORER_PE_DEFINITIONS_H

struct PeSummary {
    std::uint16_t machine{};
    std::uint16_t number_of_sections{};
    std::uint32_t time_date_stamp{};
    std::uint16_t optional_magic{}; // 0x10b (PE32), 0x20b (PE32+)
};













#endif //PEELF_EXPLORER_PE_DEFINITIONS_H