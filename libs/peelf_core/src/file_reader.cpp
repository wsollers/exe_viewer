#include <peelf/peelf.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <vector>


#include"../include/pe/pe_parser.h"

namespace peelf {



std::string_view to_string(FileKind k) {
    switch (k) {
        case FileKind::ELF: return "ELF";
        case FileKind::PE: return "PE";
        default: return "Unknown";
    }
}

} // namespace peelf
