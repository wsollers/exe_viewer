#include <peelf/peelf.hpp>

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "peelf_viewer (scaffold)\n"
                  << "Usage: peelf_viewer <path-to-exe-or-shared-lib>\n";
        return 0;
    }

    auto info = peelf::parse_file(argv[1]);
    if (!info) {
        std::cerr << "Error: " << info.error().message << "\n";
        return 2;
    }

    std::cout << "Kind: " << peelf::to_string(info->kind) << "\n";

    if (auto elf = std::get_if<peelf::ElfSummary>(&info->summary)) {
        std::cout << "ELF: class=" << int(elf->ei_class)
                  << " data=" << int(elf->ei_data)
                  << " type=" << elf->e_type
                  << " machine=" << elf->e_machine << "\n";
    } else if (auto pe = std::get_if<peelf::PeSummary>(&info->summary)) {
        std::cout << "PE: machine=0x" << std::hex << pe->machine
                  << " sections=" << std::dec << pe->number_of_sections
                  << " timestamp=" << pe->time_date_stamp
                  << " opt_magic=0x" << std::hex << pe->optional_magic << std::dec << "\n";
    }

    return 0;
}
