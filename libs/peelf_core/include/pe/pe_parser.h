//
// Created by wsoll on 12/22/2025.
//
#include "peelf/peelf.hpp"
#include "pe/pe_definitions.h"

#ifndef PEELF_EXPLORER_PE_PARSER_H
#define PEELF_EXPLORER_PE_PARSER_H
namespace peelf {
    std::expected<FileInfo, Error> parse_pe_bytes(std::span<const std::uint8_t> bytes);
}
#endif //PEELF_EXPLORER_PE_PARSER_H