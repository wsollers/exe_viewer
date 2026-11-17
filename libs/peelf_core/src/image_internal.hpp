#pragma once

#include <peelf/binary_image.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace peelf::detail {

// ---------------------------------------------------------------------------
// Endian-aware fixed-width readers & writers. Callers ensure offsets are valid
// via fits_range(...) prior to invocation.
// ---------------------------------------------------------------------------
[[nodiscard]] constexpr std::uint16_t rd16(std::span<const std::uint8_t> b,
                                           std::size_t o,
                                           bool big) noexcept {
    return big
        ? static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[o]) << 8) | b[o + 1])
        : static_cast<std::uint16_t>(b[o] | (static_cast<std::uint16_t>(b[o + 1]) << 8));
}

[[nodiscard]] constexpr std::uint32_t rd32(std::span<const std::uint8_t> b,
                                           std::size_t o,
                                           bool big) noexcept {
    if (big) {
        return (static_cast<std::uint32_t>(b[o]) << 24) |
               (static_cast<std::uint32_t>(b[o + 1]) << 16) |
               (static_cast<std::uint32_t>(b[o + 2]) << 8) |
               (static_cast<std::uint32_t>(b[o + 3]));
    }
    return (static_cast<std::uint32_t>(b[o])) |
           (static_cast<std::uint32_t>(b[o + 1]) << 8) |
           (static_cast<std::uint32_t>(b[o + 2]) << 16) |
           (static_cast<std::uint32_t>(b[o + 3]) << 24);
}

[[nodiscard]] constexpr std::uint64_t rd64(std::span<const std::uint8_t> b,
                                           std::size_t o,
                                           bool big) noexcept {
    if (big) {
        return (static_cast<std::uint64_t>(rd32(b, o, true)) << 32) |
               static_cast<std::uint64_t>(rd32(b, o + 4, true));
    }
    return (static_cast<std::uint64_t>(rd32(b, o + 4, false)) << 32) |
           static_cast<std::uint64_t>(rd32(b, o, false));
}

constexpr void wr16_endian(std::vector<std::uint8_t>& b,
                           std::size_t off,
                           std::uint16_t v,
                           bool big) noexcept {
    if (big) {
        b[off + 0] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
        b[off + 1] = static_cast<std::uint8_t>(v & 0xFFu);
    } else {
        b[off + 0] = static_cast<std::uint8_t>(v & 0xFFu);
        b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    }
}

constexpr void wr32_endian(std::vector<std::uint8_t>& b,
                           std::size_t off,
                           std::uint32_t v,
                           bool big) noexcept {
    for (std::size_t i = 0; i < 4; ++i) {
        const std::size_t idx = big ? (off + 3 - i) : (off + i);
        b[idx] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

constexpr void wr64_endian(std::vector<std::uint8_t>& b,
                           std::size_t off,
                           std::uint64_t v,
                           bool big) noexcept {
    for (std::size_t i = 0; i < 8; ++i) {
        const std::size_t idx = big ? (off + 7 - i) : (off + i);
        b[idx] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

[[nodiscard]] constexpr bool fits_range(std::uint64_t offset,
                                        std::uint64_t size,
                                        std::uint64_t total) noexcept {
    return offset <= total && size <= (total - offset);
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add_u64(
    std::uint64_t lhs,
    std::uint64_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs) {
        return std::nullopt;
    }
    return lhs + rhs;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_mul_u64(
    std::uint64_t lhs,
    std::uint64_t rhs) noexcept {
    if (lhs != 0u && rhs > std::numeric_limits<std::uint64_t>::max() / lhs) {
        return std::nullopt;
    }
    return lhs * rhs;
}

[[nodiscard]] constexpr std::uint64_t align4(std::uint64_t value) noexcept {
    return (value + 3u) & ~std::uint64_t{3u};
}

[[nodiscard]] constexpr std::uint64_t align8(std::uint64_t value) noexcept {
    return (value + 7u) & ~std::uint64_t{7u};
}

[[nodiscard]] std::string read_c_string(std::span<const std::uint8_t> b,
                                        std::uint64_t offset,
                                        std::uint64_t max_len = 256);

[[nodiscard]] std::optional<std::uint64_t> pe_rva_to_file_offset(
    const std::vector<Section>& sections,
    std::uint64_t image_base,
    std::uint32_t rva) noexcept;

// ---------------------------------------------------------------------------
// Shared base implementation for concrete PE and ELF images.
// ---------------------------------------------------------------------------
class ImageBase : public IBinaryImage {
public:
    [[nodiscard]] Format format() const noexcept override { return format_; }
    [[nodiscard]] ImageKind kind() const noexcept override { return kind_; }
    [[nodiscard]] Architecture architecture() const noexcept override { return arch_; }
    [[nodiscard]] Endianness endianness() const noexcept override { return endian_; }
    [[nodiscard]] bool is_64bit() const noexcept override { return is_64_; }
    [[nodiscard]] std::uint64_t image_base() const noexcept override { return image_base_; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept override { return entry_; }
    [[nodiscard]] const std::vector<Section>& sections() const noexcept override { return sections_; }
    [[nodiscard]] const std::vector<Segment>& segments() const noexcept override { return segments_; }
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept override { return symbols_; }
    [[nodiscard]] const std::vector<ImportEntry>& imports() const noexcept override { return imports_; }
    [[nodiscard]] const std::vector<ExportEntry>& exports() const noexcept override { return exports_; }
    [[nodiscard]] const GnuDebugLink* gnu_debuglink() const noexcept override {
        return gnu_debuglink_.has_value() ? &*gnu_debuglink_ : nullptr;
    }
    [[nodiscard]] std::uint64_t container_slice_size() const noexcept override {
        return raw_bytes_.size();
    }
    [[nodiscard]] std::span<const std::string> parse_warnings() const noexcept override {
        return parse_warnings_;
    }

    [[nodiscard]] bool has_elf_pt_load() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override;
    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept override;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_bytes_at_offset(
        std::uint64_t file_offset,
        std::size_t size) const override;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_bytes_at_va(
        std::uint64_t virtual_address,
        std::size_t size) const override;

    void attach_raw_bytes(std::span<const std::uint8_t> bytes) {
        raw_bytes_.assign(bytes.begin(), bytes.end());
    }

    virtual void rebase_to_live_base(std::uint64_t live_base) = 0;

protected:
    Format       format_ = Format::Unknown;
    ImageKind    kind_   = ImageKind::Unknown;
    Architecture arch_   = Architecture::Unknown;
    Endianness   endian_ = Endianness::Little;
    bool         is_64_  = false;
    bool         is_live_mapped_ = false;
    std::uint64_t mapped_span_size_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint64_t entry_ = 0;
    std::vector<Section> sections_;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
    std::vector<ImportEntry> imports_;
    std::vector<ExportEntry> exports_;
    std::vector<std::string> parse_warnings_;
    std::optional<GnuDebugLink> gnu_debuglink_;
    std::vector<std::uint8_t> raw_bytes_;

    void add_warning(std::string warning) {
        if (!warning.empty()) {
            parse_warnings_.push_back(std::move(warning));
        }
    }

    void parse_gnu_debuglink_section(std::span<const std::uint8_t> b, bool big);
};

[[nodiscard]] Result<std::unique_ptr<ImageBase>> parse_pe_image_impl(
    std::span<const std::uint8_t> bytes);

[[nodiscard]] Result<std::unique_ptr<ImageBase>> parse_elf_image_impl(
    std::span<const std::uint8_t> bytes);

[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> parse_elf_mapped_image_impl(
    std::span<const std::uint8_t> mapped_bytes,
    std::uint64_t live_base);

} // namespace peelf::detail
