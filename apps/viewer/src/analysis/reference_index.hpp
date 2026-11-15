#pragma once

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <peelf/binary_image.hpp>

namespace viewer {
enum class ReferenceKind { Call, Branch, Data, AddressConstant };
struct Reference {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
    ReferenceKind kind = ReferenceKind::Data;
    std::string instruction;
    std::string string_preview;
};
[[nodiscard]] std::string_view reference_kind_name(ReferenceKind kind) noexcept;

struct Annotation { std::string name; std::string comment; };
class AnnotationStore {
public:
    void set(std::uint64_t address, std::string name, std::string comment);
    [[nodiscard]] const Annotation* find(std::uint64_t address) const noexcept;
    [[nodiscard]] const std::map<std::uint64_t, Annotation>& records() const noexcept { return records_; }
    void clear() noexcept { records_.clear(); ++revision_; }
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
private:
    std::map<std::uint64_t, Annotation> records_;
    std::uint64_t revision_ = 0;
};

class ReferenceIndex {
public:
    // A conservative linear scan of executable file-backed sections, not proof of reachable code.
    [[nodiscard]] static ReferenceIndex build(const peelf::IBinaryImage& image,
        std::span<const std::uint8_t> bytes, bool thumb = false,
        std::size_t byte_budget = 4 * 1024 * 1024);
    // Appends references from one decoded region. Register-dependent targets stay unresolved.
    void add_code(std::span<const std::uint8_t> bytes, std::uint64_t address,
        peelf::Architecture architecture, peelf::Endianness endian, bool thumb = false);
    [[nodiscard]] std::span<const Reference> records() const noexcept { return records_; }
    [[nodiscard]] std::vector<const Reference*> incoming(std::uint64_t address, std::uint64_t size = 1) const;
    [[nodiscard]] std::vector<const Reference*> outgoing(std::uint64_t address, std::uint64_t size = 1) const;
    [[nodiscard]] std::size_t scanned_bytes() const noexcept { return scanned_bytes_; }
    [[nodiscard]] bool incomplete() const noexcept { return incomplete_; }
private:
    std::vector<Reference> records_;
    std::size_t scanned_bytes_ = 0;
    bool incomplete_ = false;
};
} // namespace viewer
