#include <peelf/peelf.hpp>

#include <string_view>

namespace peelf {



std::string_view to_string(FileKind k) {
    switch (k) {
        case FileKind::ELF: return "ELF";
        case FileKind::PE: return "PE";
        default: return "Unknown";
    }
}

} // namespace peelf
