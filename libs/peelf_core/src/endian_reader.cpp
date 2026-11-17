#include <peelf/endian_reader.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>

namespace peelf {

namespace {

template <typename UInt>
[[nodiscard]] UInt load_native_unaligned(const std::uint8_t* src) noexcept {
    UInt value{};
    std::memcpy(&value, src, sizeof(UInt));
    return value;
}

template <typename UInt>
[[nodiscard]] UInt adjust_from_target(UInt raw, Endianness target_endian) noexcept {
    const bool host_is_little = (std::endian::native == std::endian::little);
    const bool target_is_little = (target_endian == Endianness::Little);
    if (host_is_little != target_is_little) {
        return std::byteswap(raw);
    }
    return raw;
}

template <typename UInt>
[[nodiscard]] std::vector<std::uint8_t> store_for_target(UInt value, Endianness target_endian) {
    const UInt encoded = adjust_from_target(value, target_endian);
    std::vector<std::uint8_t> out(sizeof(UInt));
    std::memcpy(out.data(), &encoded, sizeof(UInt));
    return out;
}

[[nodiscard]] std::uint16_t read_u16_unaligned(const std::uint8_t* src,
                                               Endianness endianness) noexcept {
    return adjust_from_target(load_native_unaligned<std::uint16_t>(src), endianness);
}

[[nodiscard]] std::uint32_t decode_next_utf8_codepoint(std::string_view text, std::size_t& idx) noexcept {
    const auto b0 = static_cast<std::uint8_t>(text[idx++]);
    if ((b0 & 0x80u) == 0) {
        return b0;
    }
    if ((b0 & 0xE0u) == 0xC0u && idx < text.size()) {
        const auto b1 = static_cast<std::uint8_t>(text[idx]);
        if ((b1 & 0xC0u) == 0x80u) {
            ++idx;
            const std::uint32_t cp = ((b0 & 0x1Fu) << 6) | (b1 & 0x3Fu);
            return cp >= 0x80u ? cp : 0xFFFDu;
        }
        return 0xFFFDu;
    }
    if ((b0 & 0xF0u) == 0xE0u && idx + 1 < text.size()) {
        const auto b1 = static_cast<std::uint8_t>(text[idx]);
        const auto b2 = static_cast<std::uint8_t>(text[idx + 1]);
        if ((b1 & 0xC0u) == 0x80u && (b2 & 0xC0u) == 0x80u) {
            idx += 2;
            const std::uint32_t cp =
                ((b0 & 0x0Fu) << 12) | ((b1 & 0x3Fu) << 6) | (b2 & 0x3Fu);
            if (cp >= 0x800u && !(cp >= 0xD800u && cp <= 0xDFFFu)) {
                return cp;
            }
        }
        return 0xFFFDu;
    }
    if ((b0 & 0xF8u) == 0xF0u && idx + 2 < text.size()) {
        const auto b1 = static_cast<std::uint8_t>(text[idx]);
        const auto b2 = static_cast<std::uint8_t>(text[idx + 1]);
        const auto b3 = static_cast<std::uint8_t>(text[idx + 2]);
        if ((b1 & 0xC0u) == 0x80u && (b2 & 0xC0u) == 0x80u && (b3 & 0xC0u) == 0x80u) {
            idx += 3;
            const std::uint32_t cp = ((b0 & 0x07u) << 18) | ((b1 & 0x3Fu) << 12) |
                                     ((b2 & 0x3Fu) << 6) | (b3 & 0x3Fu);
            if (cp >= 0x10000u && cp <= 0x10FFFFu) {
                return cp;
            }
        }
        return 0xFFFDu;
    }
    return 0xFFFDu;
}

}  // namespace

Result<std::uint8_t> EndianReader::read_u8(std::size_t offset) const {
    if (!can_read(offset, 1)) {
        return make_error("read_u8 out of bounds");
    }
    return bytes_[offset];
}

Result<std::int8_t> EndianReader::read_i8(std::size_t offset) const {
    auto v = read_u8(offset);
    if (!v) {
        return std::unexpected(v.error());
    }
    return static_cast<std::int8_t>(*v);
}

Result<std::uint16_t> EndianReader::read_u16(std::size_t offset) const {
    if (!can_read(offset, 2)) {
        return make_error("read_u16 out of bounds");
    }
    return adjust_from_target(load_native_unaligned<std::uint16_t>(bytes_.data() + offset),
                              layout_.endianness);
}

Result<std::int16_t> EndianReader::read_i16(std::size_t offset) const {
    auto v = read_u16(offset);
    if (!v) {
        return std::unexpected(v.error());
    }
    return static_cast<std::int16_t>(*v);
}

Result<std::uint32_t> EndianReader::read_u32(std::size_t offset) const {
    if (!can_read(offset, 4)) {
        return make_error("read_u32 out of bounds");
    }
    return adjust_from_target(load_native_unaligned<std::uint32_t>(bytes_.data() + offset),
                              layout_.endianness);
}

Result<std::int32_t> EndianReader::read_i32(std::size_t offset) const {
    auto v = read_u32(offset);
    if (!v) {
        return std::unexpected(v.error());
    }
    return static_cast<std::int32_t>(*v);
}

Result<std::uint64_t> EndianReader::read_u64(std::size_t offset) const {
    if (!can_read(offset, 8)) {
        return make_error("read_u64 out of bounds");
    }
    return adjust_from_target(load_native_unaligned<std::uint64_t>(bytes_.data() + offset),
                              layout_.endianness);
}

Result<std::int64_t> EndianReader::read_i64(std::size_t offset) const {
    auto v = read_u64(offset);
    if (!v) {
        return std::unexpected(v.error());
    }
    return static_cast<std::int64_t>(*v);
}

Result<float> EndianReader::read_f32(std::size_t offset) const {
    auto bits = read_u32(offset);
    if (!bits) {
        return std::unexpected(bits.error());
    }
    return std::bit_cast<float>(*bits);
}

Result<double> EndianReader::read_f64(std::size_t offset) const {
    auto bits = read_u64(offset);
    if (!bits) {
        return std::unexpected(bits.error());
    }
    return std::bit_cast<double>(*bits);
}

Result<std::uint64_t> EndianReader::read_pointer(std::size_t offset) const {
    if (layout_.address_width == AddressWidth::Bits64) {
        return read_u64(offset);
    }
    auto p32 = read_u32(offset);
    if (!p32) {
        return std::unexpected(p32.error());
    }
    return static_cast<std::uint64_t>(*p32);
}

Result<std::int64_t> EndianReader::read_signed_pointer(std::size_t offset) const {
    if (layout_.address_width == AddressWidth::Bits64) {
        return read_i64(offset);
    }
    auto p32 = read_i32(offset);
    if (!p32) {
        return std::unexpected(p32.error());
    }
    return static_cast<std::int64_t>(*p32);
}

Result<std::string> EndianReader::read_c_string(std::size_t offset, std::size_t max_bytes) const {
    if (offset > bytes_.size()) {
        return make_error("read_c_string out of bounds");
    }
    const std::size_t avail = std::min(max_bytes, bytes_.size() - offset);
    std::string out;
    for (std::size_t i = 0; i < avail; ++i) {
        const std::uint8_t ch = bytes_[offset + i];
        if (ch == 0) {
            break;
        }
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

void append_utf8_codepoint(std::string& out, std::uint32_t cp) {
    if (cp >= 0xD800u && cp <= 0xDFFFu) {
        cp = 0xFFFDu;
    }
    if (cp <= 0x7Fu) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FFu) {
        out.push_back(static_cast<char>(0xC0u | ((cp >> 6) & 0x1Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0xFFFFu) {
        out.push_back(static_cast<char>(0xE0u | ((cp >> 12) & 0x0Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0x10FFFFu) {
        out.push_back(static_cast<char>(0xF0u | ((cp >> 18) & 0x07u)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else {
        out.append("\xEF\xBF\xBD", 3u);
    }
}

std::string decode_utf16_to_utf8(std::span<const std::uint8_t> bytes,
                                 Endianness endianness,
                                 bool stop_at_nul,
                                 std::size_t max_code_units,
                                 Utf16DecodeDiagnostics* diagnostics) {
    if (diagnostics != nullptr) {
        *diagnostics = Utf16DecodeDiagnostics{};
        if ((bytes.size() & 1u) != 0u) {
            diagnostics->odd_trailing_byte = true;
        }
    }

    const std::size_t total_units = bytes.size() / 2u;
    const std::size_t unit_limit = std::min(total_units, max_code_units);
    std::string out;
    out.reserve(unit_limit);

    bool hit_nul = false;
    for (std::size_t i = 0; i < unit_limit; ++i) {
        const std::uint16_t u0 = read_u16_unaligned(bytes.data() + i * 2u, endianness);
        if (u0 == 0u) {
            if (stop_at_nul) {
                hit_nul = true;
                break;
            }
            continue;
        }
        if (u0 >= 0xD800u && u0 <= 0xDBFFu) {
            if (i + 1u < unit_limit) {
                const std::uint16_t u1 =
                    read_u16_unaligned(bytes.data() + (i + 1u) * 2u, endianness);
                if (u1 >= 0xDC00u && u1 <= 0xDFFFu) {
                    const std::uint32_t cp =
                        0x10000u + (((static_cast<std::uint32_t>(u0) - 0xD800u) << 10u) |
                                    (static_cast<std::uint32_t>(u1) - 0xDC00u));
                    append_utf8_codepoint(out, cp);
                    ++i;
                    continue;
                }
            }
            if (diagnostics != nullptr) {
                ++diagnostics->unpaired_high_surrogates;
            }
            out.append("\xEF\xBF\xBD", 3u);
        } else if (u0 >= 0xDC00u && u0 <= 0xDFFFu) {
            if (diagnostics != nullptr) {
                ++diagnostics->unpaired_low_surrogates;
            }
            out.append("\xEF\xBF\xBD", 3u);
        } else {
            append_utf8_codepoint(out, u0);
        }
    }

    if (diagnostics != nullptr && !hit_nul && total_units > max_code_units) {
        if (!stop_at_nul ||
            read_u16_unaligned(bytes.data() + unit_limit * 2u, endianness) != 0u) {
            diagnostics->truncated_at_max_units = true;
        }
    }
    return out;
}

Result<std::string> EndianReader::read_utf16_string(std::size_t offset,
                                                    std::size_t max_code_units) const {
    if (offset > bytes_.size()) {
        return make_error("read_utf16_string out of bounds");
    }
    const std::size_t avail_units = std::min(max_code_units, (bytes_.size() - offset) / 2u);
    return decode_utf16_to_utf8(bytes_.subspan(offset, avail_units * 2u),
                                layout_.endianness,
                                /*stop_at_nul=*/true,
                                avail_units);
}

std::vector<std::uint8_t> encode_u8(std::uint8_t value) {
    return {value};
}

std::vector<std::uint8_t> encode_i8(std::int8_t value) {
    return {static_cast<std::uint8_t>(value)};
}

std::vector<std::uint8_t> encode_u16(std::uint16_t value, Endianness endianness) {
    return store_for_target<std::uint16_t>(value, endianness);
}

std::vector<std::uint8_t> encode_i16(std::int16_t value, Endianness endianness) {
    return store_for_target<std::uint16_t>(static_cast<std::uint16_t>(value), endianness);
}

std::vector<std::uint8_t> encode_u32(std::uint32_t value, Endianness endianness) {
    return store_for_target<std::uint32_t>(value, endianness);
}

std::vector<std::uint8_t> encode_i32(std::int32_t value, Endianness endianness) {
    return store_for_target<std::uint32_t>(static_cast<std::uint32_t>(value), endianness);
}

std::vector<std::uint8_t> encode_u64(std::uint64_t value, Endianness endianness) {
    return store_for_target<std::uint64_t>(value, endianness);
}

std::vector<std::uint8_t> encode_i64(std::int64_t value, Endianness endianness) {
    return store_for_target<std::uint64_t>(static_cast<std::uint64_t>(value), endianness);
}

std::vector<std::uint8_t> encode_f32(float value, Endianness endianness) {
    return store_for_target<std::uint32_t>(std::bit_cast<std::uint32_t>(value), endianness);
}

std::vector<std::uint8_t> encode_f64(double value, Endianness endianness) {
    return store_for_target<std::uint64_t>(std::bit_cast<std::uint64_t>(value), endianness);
}

Result<std::vector<std::uint8_t>> encode_pointer(std::uint64_t value, TargetLayout layout) {
    if (layout.address_width == AddressWidth::Bits64) {
        return encode_u64(value, layout.endianness);
    }
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return make_error("encode_pointer: value exceeds 32-bit address width");
    }
    return encode_u32(static_cast<std::uint32_t>(value), layout.endianness);
}

std::vector<std::uint8_t> encode_utf16(std::string_view utf8, Endianness endianness) {
    std::vector<std::uint8_t> out;
    out.reserve(utf8.size() * 2u);
    std::size_t idx = 0;
    while (idx < utf8.size()) {
        const std::uint32_t cp = decode_next_utf8_codepoint(utf8, idx);
        if (cp <= 0xFFFFu) {
            const auto unit = encode_u16(static_cast<std::uint16_t>(cp), endianness);
            out.insert(out.end(), unit.begin(), unit.end());
        } else {
            const std::uint32_t adj = cp - 0x10000u;
            const auto hi =
                encode_u16(static_cast<std::uint16_t>(0xD800u + ((adj >> 10) & 0x3FFu)), endianness);
            const auto lo =
                encode_u16(static_cast<std::uint16_t>(0xDC00u + (adj & 0x3FFu)), endianness);
            out.insert(out.end(), hi.begin(), hi.end());
            out.insert(out.end(), lo.begin(), lo.end());
        }
    }
    return out;
}

}  // namespace peelf
