#include <peelf/peelf.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <vector>

namespace peelf {

static std::expected<std::vector<std::uint8_t>, Error> slurp(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(Error{std::string("Failed to open file: ") + path.string()});
    }
    in.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> data(size);
    if (size && !in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) {
        return std::unexpected(Error{std::string("Failed to read file: ") + path.string()});
    }
    return data;
}

std::expected<FileInfo, Error> parse_elf_bytes(std::span<const std::uint8_t> bytes);
std::expected<FileInfo, Error> parse_pe_bytes(std::span<const std::uint8_t> bytes);

std::expected<FileInfo, Error> parse_file(const std::filesystem::path& path) {
    auto data = slurp(path);
    if (!data) return std::unexpected(data.error());

    const auto& b = *data;
    if (b.size() >= 4 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        return parse_elf_bytes(b);
    }
    if (b.size() >= 2 && b[0] == 'M' && b[1] == 'Z') {
        return parse_pe_bytes(b);
    }
    return FileInfo{.kind = FileKind::Unknown};
}

std::string_view to_string(FileKind k) {
    switch (k) {
        case FileKind::ELF: return "ELF";
        case FileKind::PE: return "PE";
        default: return "Unknown";
    }
}

} // namespace peelf
