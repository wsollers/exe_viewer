// SPDX-License-Identifier: BSD-2-Clause
// Clean-room cross-platform MSF 7.00 & CodeView PDB debug symbol/type/line parser.
#include <peelf/pdb.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {
namespace {

constexpr std::size_t kMsf7SuperBlockSize = 56u;
constexpr std::uint32_t kNilStreamSize = 0xFFFF'FFFFu;
constexpr std::uint16_t kInvalidStreamIndex16 = 0xFFFFu;

// Defensive resource caps against hostile / malformed MSF 7.00 containers.
constexpr std::uint32_t kMaxDirectoryBytes = 64u * 1024u * 1024u;
constexpr std::uint32_t kMaxStreams = 262'144u;
constexpr std::uint32_t kMaxSingleStreamBytes = 256u * 1024u * 1024u;
constexpr std::size_t kMaxTotalMaterializedBytes = 384u * 1024u * 1024u;
constexpr std::uint64_t kMaxPdbFileBytes = 1024ull * 1024ull * 1024ull;
constexpr std::uint32_t kMaxTypeRecords = 1'000'000u;
constexpr std::size_t kMaxTypeResolveDepth = 16u;
constexpr std::size_t kMaxFieldListContinuations = 64u;
constexpr std::uint32_t kMaxNamedStreamBuckets = 65'536u;

constexpr std::array<std::uint8_t, 32> kMsf7Magic = {
    'M',  'i',  'c',  'r', 'o', 's', 'o', 'f', 't', ' ', 'C',  '/',  'C',  '+',  '+',  ' ',
    'M',  'S',  'F',  ' ', '7', '.', '0', '0', '\r', '\n', 0x1Au, 'D', 'S', 0x00u, 0x00u, 0x00u,
};

constexpr std::uint32_t kPdbNamesMagic = 0xEFFE'EFFEu;

// CodeView property flags (CV_prop_t).
constexpr std::uint16_t kCvPropForwardRef = 0x0080u;

// CodeView TPI leaf tags.
constexpr std::uint16_t kLfModifier = 0x1001u;
constexpr std::uint16_t kLfPointer = 0x1002u;
constexpr std::uint16_t kLfProcedure = 0x1008u;
constexpr std::uint16_t kLfMFunction = 0x1009u;
constexpr std::uint16_t kLfArgList = 0x1201u;
constexpr std::uint16_t kLfFieldList = 0x1203u;
constexpr std::uint16_t kLfBitfield = 0x1205u;
constexpr std::uint16_t kLfBClass = 0x1400u;
constexpr std::uint16_t kLfVBClass = 0x1401u;
constexpr std::uint16_t kLfIVBClass = 0x1402u;
constexpr std::uint16_t kLfIndex16 = 0x0404u;
constexpr std::uint16_t kLfIndex = 0x1404u;
constexpr std::uint16_t kLfVFuncTab = 0x1409u;
constexpr std::uint16_t kLfEnumerate = 0x1502u;
constexpr std::uint16_t kLfArray = 0x1503u;
constexpr std::uint16_t kLfClass = 0x1504u;
constexpr std::uint16_t kLfStructure = 0x1505u;
constexpr std::uint16_t kLfUnion = 0x1506u;
constexpr std::uint16_t kLfEnum = 0x1507u;
constexpr std::uint16_t kLfMember = 0x150du;
constexpr std::uint16_t kLfStMember = 0x150eu;
constexpr std::uint16_t kLfMethod = 0x150fu;
constexpr std::uint16_t kLfNestType = 0x1510u;
constexpr std::uint16_t kLfOneMethod = 0x1511u;
constexpr std::uint16_t kLfInterface = 0x1519u;

// CodeView variable-length numeric leaf tags.
constexpr std::uint16_t kLfNumericThreshold = 0x8000u;
constexpr std::uint16_t kLfChar = 0x8000u;
constexpr std::uint16_t kLfShort = 0x8001u;
constexpr std::uint16_t kLfUShort = 0x8002u;
constexpr std::uint16_t kLfLong = 0x8003u;
constexpr std::uint16_t kLfULong = 0x8004u;
constexpr std::uint16_t kLfReal32 = 0x8005u;
constexpr std::uint16_t kLfReal64 = 0x8006u;
constexpr std::uint16_t kLfReal80 = 0x8007u;
constexpr std::uint16_t kLfReal128 = 0x8008u;
constexpr std::uint16_t kLfQuadword = 0x8009u;
constexpr std::uint16_t kLfUQuadword = 0x800au;

// CodeView symbol record tags.
constexpr std::uint16_t kSLData32 = 0x110cu;
constexpr std::uint16_t kSGData32 = 0x110du;
constexpr std::uint16_t kSPub32 = 0x110eu;
constexpr std::uint16_t kSLProc32 = 0x110fu;
constexpr std::uint16_t kSGProc32 = 0x1110u;
constexpr std::uint16_t kSLProc32Id = 0x1146u;
constexpr std::uint16_t kSGProc32Id = 0x1147u;

constexpr std::uint32_t kPubSymFlagFunction = 0x0000'0002u;

// CodeView C13 module stream signature and subsection tags.
constexpr std::uint32_t kCvSignatureC13 = 4u;
constexpr std::uint32_t kDebugSLines = 0x0000'00F2u;
constexpr std::uint32_t kDebugSFileChksms = 0x0000'00F4u;
constexpr std::uint32_t kDebugSIgnoreFlag = 0x8000'0000u;
constexpr std::uint16_t kCvLinesHaveColumns = 0x0001u;

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add_u64(
    std::uint64_t lhs,
    std::uint64_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs) {
        return std::nullopt;
    }
    return lhs + rhs;
}

[[nodiscard]] constexpr bool is_valid_msf_block_size(std::uint32_t block_size) noexcept {
    return block_size == 512u || block_size == 1024u || block_size == 2048u ||
           block_size == 4096u || block_size == 8192u;
}

[[nodiscard]] std::uint16_t load_u16_le(std::span<const std::uint8_t> buf,
                                        std::size_t off) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(buf[off]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(buf[off + 1u]) << 8u));
}

[[nodiscard]] std::uint32_t load_u32_le(std::span<const std::uint8_t> buf,
                                        std::size_t off) noexcept {
    return static_cast<std::uint32_t>(buf[off]) |
           (static_cast<std::uint32_t>(buf[off + 1u]) << 8u) |
           (static_cast<std::uint32_t>(buf[off + 2u]) << 16u) |
           (static_cast<std::uint32_t>(buf[off + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t load_u64_le(std::span<const std::uint8_t> buf,
                                        std::size_t off) noexcept {
    const std::uint64_t lo = load_u32_le(buf, off);
    const std::uint64_t hi = load_u32_le(buf, off + 4u);
    return lo | (hi << 32u);
}

[[nodiscard]] Result<std::uint8_t> read_u8(std::span<const std::uint8_t> buf,
                                           std::size_t& cursor) {
    if (cursor >= buf.size()) {
        return make_error("Unexpected EOF reading uint8 in PDB record");
    }
    const std::uint8_t v = buf[cursor];
    ++cursor;
    return v;
}

[[nodiscard]] Result<std::uint16_t> read_u16(std::span<const std::uint8_t> buf,
                                             std::size_t& cursor) {
    if (cursor > buf.size() || buf.size() - cursor < 2u) {
        return make_error("Unexpected EOF reading uint16 in PDB record");
    }
    const std::uint16_t v = load_u16_le(buf, cursor);
    cursor += 2u;
    return v;
}

[[nodiscard]] Result<std::uint32_t> read_u32(std::span<const std::uint8_t> buf,
                                             std::size_t& cursor) {
    if (cursor > buf.size() || buf.size() - cursor < 4u) {
        return make_error("Unexpected EOF reading uint32 in PDB record");
    }
    const std::uint32_t v = load_u32_le(buf, cursor);
    cursor += 4u;
    return v;
}

[[nodiscard]] Result<std::int32_t> read_i32(std::span<const std::uint8_t> buf,
                                            std::size_t& cursor) {
    auto u = read_u32(buf, cursor);
    if (!u) {
        return std::unexpected(u.error());
    }
    return static_cast<std::int32_t>(*u);
}

[[nodiscard]] Result<std::uint64_t> read_u64(std::span<const std::uint8_t> buf,
                                             std::size_t& cursor) {
    if (cursor > buf.size() || buf.size() - cursor < 8u) {
        return make_error("Unexpected EOF reading uint64 in PDB record");
    }
    const std::uint64_t v = load_u64_le(buf, cursor);
    cursor += 8u;
    return v;
}

[[nodiscard]] Result<std::string> read_cstr(std::span<const std::uint8_t> buf,
                                            std::size_t& cursor) {
    if (cursor >= buf.size()) {
        return make_error("Unexpected EOF reading NUL-terminated string in PDB record");
    }
    const auto tail = buf.subspan(cursor);
    const auto it = std::ranges::find(tail, std::uint8_t{0u});
    if (it == tail.end()) {
        return make_error("Unterminated NUL-delimited string in PDB record");
    }
    const auto len = static_cast<std::size_t>(std::distance(tail.begin(), it));
    std::string out(reinterpret_cast<const char*>(tail.data()), len);
    cursor += len + 1u;
    return out;
}

[[nodiscard]] std::string extract_basename(std::string_view full_path) {
    const std::size_t sep = full_path.find_last_of("/\\");
    if (sep == std::string_view::npos) {
        return std::string(full_path);
    }
    return std::string(full_path.substr(sep + 1u));
}

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out(sv.size(), '\0');
    for (std::size_t i = 0; i < sv.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(sv[i])));
    }
    return out;
}

[[nodiscard]] bool has_archive_library_extension(std::string_view path_str) {
    const std::size_t dot = path_str.find_last_of('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    const std::string ext = to_lower_ascii(path_str.substr(dot));
    return ext == ".lib" || ext == ".a";
}

// ============================================================================
// MSF 7.00 Container
// ============================================================================

struct MsfSuperBlock {
    std::uint32_t block_size = 0;
    std::uint32_t free_block_map_block = 0;
    std::uint32_t num_blocks = 0;
    std::uint32_t num_directory_bytes = 0;
    std::uint32_t block_map_addr = 0;
};

struct MsfStreamEntry {
    std::uint32_t byte_size = 0;
    std::size_t first_block_index = 0;
    std::size_t block_count = 0;
    bool present = false;
};

struct MsfDirectory {
    MsfSuperBlock super{};
    std::vector<MsfStreamEntry> streams{};
    std::vector<std::uint32_t> block_indices{};
};

[[nodiscard]] Result<MsfSuperBlock> parse_msf7_superblock(
    std::span<const std::uint8_t> header_bytes,
    std::uint64_t total_file_bytes) {
    if (header_bytes.size() < kMsf7SuperBlockSize || total_file_bytes < kMsf7SuperBlockSize) {
        return make_error("PDB buffer is smaller than MSF 7.00 SuperBlock (56 bytes)");
    }
    if (!has_msf7_signature(header_bytes)) {
        return make_error("Invalid or unsupported PDB magic: expected MSF 7.00 signature");
    }

    MsfSuperBlock sb{};
    sb.block_size = load_u32_le(header_bytes, 32u);
    sb.free_block_map_block = load_u32_le(header_bytes, 36u);
    sb.num_blocks = load_u32_le(header_bytes, 40u);
    sb.num_directory_bytes = load_u32_le(header_bytes, 44u);
    sb.block_map_addr = load_u32_le(header_bytes, 52u);

    if (!is_valid_msf_block_size(sb.block_size)) {
        return make_error(std::format("Invalid MSF 7.00 block_size: {}", sb.block_size));
    }
    if (sb.num_blocks == 0u ||
        static_cast<std::uint64_t>(sb.num_blocks) > total_file_bytes / sb.block_size) {
        return make_error("MSF 7.00 num_blocks exceeds backing file size or is zero");
    }
    if (sb.block_map_addr == 0u || sb.block_map_addr >= sb.num_blocks) {
        return make_error("MSF 7.00 block_map_addr is out of bounds");
    }
    if (sb.num_directory_bytes < 4u || sb.num_directory_bytes > kMaxDirectoryBytes) {
        return make_error("MSF 7.00 num_directory_bytes is invalid or exceeds safety cap");
    }

    const std::uint64_t num_dir_blocks =
        (static_cast<std::uint64_t>(sb.num_directory_bytes) + sb.block_size - 1ull) /
        sb.block_size;
    const std::uint64_t block_map_offset =
        static_cast<std::uint64_t>(sb.block_map_addr) * sb.block_size;
    if (num_dir_blocks == 0ull ||
        num_dir_blocks > (total_file_bytes - block_map_offset) / 4ull) {
        return make_error("MSF 7.00 directory block map extends past end of file");
    }

    return sb;
}

[[nodiscard]] Result<MsfDirectory> parse_msf7_directory_bytes(
    const MsfSuperBlock& sb,
    std::span<const std::uint8_t> dir_bytes) {
    if (dir_bytes.size() < 4u) {
        return make_error("MSF 7.00 stream directory is truncated");
    }

    const std::uint32_t num_streams = load_u32_le(dir_bytes, 0u);
    if (num_streams < 2u || num_streams > kMaxStreams) {
        return make_error(
            std::format("MSF 7.00 num_streams ({}) is invalid or exceeds cap", num_streams));
    }
    if (static_cast<std::uint64_t>(num_streams) > (dir_bytes.size() - 4u) / 4u) {
        return make_error("MSF 7.00 stream size table extends past directory buffer");
    }

    MsfDirectory dir{};
    dir.super = sb;
    dir.streams.resize(num_streams);

    std::size_t total_block_refs = 0u;
    for (std::uint32_t i = 0; i < num_streams; ++i) {
        const std::uint32_t raw_size = load_u32_le(dir_bytes, 4u + static_cast<std::size_t>(i) * 4u);
        MsfStreamEntry& entry = dir.streams[i];
        if (raw_size == kNilStreamSize) {
            entry.present = false;
            entry.byte_size = 0u;
            entry.block_count = 0u;
            continue;
        }
        if (raw_size > kMaxSingleStreamBytes) {
            return make_error(
                std::format("MSF 7.00 stream {} size ({}) exceeds safety cap", i, raw_size));
        }
        entry.present = true;
        entry.byte_size = raw_size;
        const std::uint64_t blk_cnt64 =
            (raw_size == 0u)
                ? 0ull
                : (static_cast<std::uint64_t>(raw_size) + sb.block_size - 1ull) / sb.block_size;
        if (blk_cnt64 > (dir_bytes.size() / 4u) ||
            blk_cnt64 > std::numeric_limits<std::size_t>::max() - total_block_refs) {
            return make_error("MSF 7.00 stream block list overflows directory bounds");
        }
        entry.block_count = static_cast<std::size_t>(blk_cnt64);
        total_block_refs += entry.block_count;
    }

    std::size_t cursor = 4u + static_cast<std::size_t>(num_streams) * 4u;
    if (total_block_refs > (dir_bytes.size() - cursor) / 4u) {
        return make_error("MSF 7.00 stream block indices extend past directory buffer");
    }

    dir.block_indices.reserve(total_block_refs);
    for (std::uint32_t i = 0; i < num_streams; ++i) {
        MsfStreamEntry& entry = dir.streams[i];
        entry.first_block_index = dir.block_indices.size();
        for (std::size_t b = 0; b < entry.block_count; ++b) {
            const std::uint32_t blk = load_u32_le(dir_bytes, cursor);
            cursor += 4u;
            if (blk == 0u || blk >= sb.num_blocks) {
                return make_error(
                    std::format("MSF 7.00 stream {} references out-of-bounds block {}", i, blk));
            }
            dir.block_indices.push_back(blk);
        }
    }

    return dir;
}

class MsfMemoryReader {
public:
    static Result<MsfMemoryReader> open(std::span<const std::uint8_t> bytes) {
        auto sb = parse_msf7_superblock(bytes, bytes.size());
        if (!sb) {
            return std::unexpected(sb.error());
        }

        const std::size_t num_dir_blocks = static_cast<std::size_t>(
            (static_cast<std::uint64_t>(sb->num_directory_bytes) + sb->block_size - 1ull) /
            sb->block_size);
        const std::size_t block_map_off =
            static_cast<std::size_t>(static_cast<std::uint64_t>(sb->block_map_addr) * sb->block_size);

        std::vector<std::uint8_t> dir_bytes(sb->num_directory_bytes);
        std::size_t copied = 0u;
        for (std::size_t i = 0; i < num_dir_blocks; ++i) {
            const std::uint32_t blk = load_u32_le(bytes, block_map_off + i * 4u);
            if (blk == 0u || blk >= sb->num_blocks) {
                return make_error("MSF 7.00 directory block map contains out-of-bounds block index");
            }
            const std::size_t blk_byte_off =
                static_cast<std::size_t>(static_cast<std::uint64_t>(blk) * sb->block_size);
            const std::size_t chunk =
                std::min<std::size_t>(sb->block_size, dir_bytes.size() - copied);
            std::memcpy(dir_bytes.data() + copied, bytes.data() + blk_byte_off, chunk);
            copied += chunk;
        }

        auto dir = parse_msf7_directory_bytes(*sb, dir_bytes);
        if (!dir) {
            return std::unexpected(dir.error());
        }

        return MsfMemoryReader(bytes, std::move(*dir));
    }

    [[nodiscard]] std::uint32_t num_streams() const noexcept {
        return static_cast<std::uint32_t>(dir_.streams.size());
    }

    [[nodiscard]] bool has_stream(std::uint32_t stream_idx) const noexcept {
        return stream_idx < dir_.streams.size() && dir_.streams[stream_idx].present;
    }

    [[nodiscard]] std::uint32_t stream_size(std::uint32_t stream_idx) const noexcept {
        if (!has_stream(stream_idx)) {
            return 0u;
        }
        return dir_.streams[stream_idx].byte_size;
    }

    [[nodiscard]] Result<std::vector<std::uint8_t>> read_stream(std::uint32_t stream_idx) {
        if (stream_idx >= dir_.streams.size()) {
            return make_error(
                std::format("Requested MSF stream {} exceeds stream count {}", stream_idx, dir_.streams.size()));
        }
        const MsfStreamEntry& entry = dir_.streams[stream_idx];
        if (!entry.present) {
            return make_error(std::format("Requested MSF stream {} is nil (0xFFFFFFFF)", stream_idx));
        }
        if (entry.byte_size == 0u) {
            return std::vector<std::uint8_t>{};
        }
        if (entry.byte_size > kMaxTotalMaterializedBytes - materialized_bytes_) {
            return make_error("PDB cumulative materialized stream bytes exceed memory safety cap");
        }
        materialized_bytes_ += entry.byte_size;

        std::vector<std::uint8_t> out(entry.byte_size);
        std::size_t copied = 0u;
        const std::uint32_t block_size = dir_.super.block_size;
        for (std::size_t i = 0; i < entry.block_count; ++i) {
            const std::uint32_t blk = dir_.block_indices[entry.first_block_index + i];
            const std::size_t blk_off =
                static_cast<std::size_t>(static_cast<std::uint64_t>(blk) * block_size);
            const std::size_t chunk = std::min<std::size_t>(block_size, out.size() - copied);
            std::memcpy(out.data() + copied, bytes_.data() + blk_off, chunk);
            copied += chunk;
        }
        return out;
    }

    [[nodiscard]] Result<std::vector<std::uint8_t>> read_stream_prefix(std::uint32_t stream_idx,
                                                                       std::size_t max_bytes) const {
        if (!has_stream(stream_idx)) {
            return make_error(std::format("MSF stream {} is absent", stream_idx));
        }
        const MsfStreamEntry& entry = dir_.streams[stream_idx];
        const std::size_t target = std::min<std::size_t>(entry.byte_size, max_bytes);
        std::vector<std::uint8_t> out(target);
        std::size_t copied = 0u;
        const std::uint32_t block_size = dir_.super.block_size;
        for (std::size_t i = 0; i < entry.block_count && copied < target; ++i) {
            const std::uint32_t blk = dir_.block_indices[entry.first_block_index + i];
            const std::size_t blk_off =
                static_cast<std::size_t>(static_cast<std::uint64_t>(blk) * block_size);
            const std::size_t chunk = std::min<std::size_t>(block_size, target - copied);
            std::memcpy(out.data() + copied, bytes_.data() + blk_off, chunk);
            copied += chunk;
        }
        return out;
    }

private:
    MsfMemoryReader(std::span<const std::uint8_t> bytes, MsfDirectory dir)
        : bytes_(bytes), dir_(std::move(dir)) {}

    std::span<const std::uint8_t> bytes_{};
    MsfDirectory dir_{};
    std::size_t materialized_bytes_ = 0u;
};

// ============================================================================
// Stream 1 (PDB Info + Named Stream Map) & `/names` String Table
// ============================================================================

struct ParsedPdbInfo {
    PdbIdentity identity{};
    std::optional<std::uint32_t> names_stream_index{};
};

[[nodiscard]] Result<ParsedPdbInfo> parse_pdb_info_stream(std::span<const std::uint8_t> s1) {
    if (s1.size() < 28u) {
        return make_error("PDB Info Stream (Stream 1) is smaller than 28-byte header");
    }

    ParsedPdbInfo out{};
    out.identity.version = load_u32_le(s1, 0u);
    out.identity.signature = load_u32_le(s1, 4u);
    out.identity.info_age = load_u32_le(s1, 8u);
    std::copy_n(s1.data() + 12u, 16u, out.identity.guid.data());

    if (s1.size() == 28u) {
        return out;
    }

    std::size_t cursor = 28u;
    const auto str_buf_size = read_u32(s1, cursor);
    if (!str_buf_size) {
        return std::unexpected(str_buf_size.error());
    }
    if (*str_buf_size > s1.size() - cursor) {
        return make_error("PDB Named Stream Map string buffer extends past Stream 1");
    }

    const std::span<const std::uint8_t> str_buf = s1.subspan(cursor, *str_buf_size);
    cursor += *str_buf_size;

    // Allow zero-padded minimal synthetic Stream 1 without a trailing hash table.
    if (cursor == s1.size()) {
        return out;
    }

    const auto ht_size = read_u32(s1, cursor);
    const auto ht_capacity = read_u32(s1, cursor);
    if (!ht_size || !ht_capacity) {
        return make_error("Truncated PDB Named Stream Map hash header");
    }
    if (*ht_size > *ht_capacity || *ht_capacity > kMaxNamedStreamBuckets) {
        return make_error("Invalid PDB Named Stream Map hash capacity");
    }

    const auto present_words_cnt = read_u32(s1, cursor);
    if (!present_words_cnt || *present_words_cnt > 4096u ||
        *present_words_cnt > (s1.size() - cursor) / 4u) {
        return make_error("Invalid or truncated PDB Named Stream Map present bitset");
    }
    std::vector<std::uint32_t> present_words(*present_words_cnt);
    for (std::uint32_t i = 0; i < *present_words_cnt; ++i) {
        present_words[i] = load_u32_le(s1, cursor);
        cursor += 4u;
    }

    const auto deleted_words_cnt = read_u32(s1, cursor);
    if (!deleted_words_cnt || *deleted_words_cnt > 4096u ||
        *deleted_words_cnt > (s1.size() - cursor) / 4u) {
        return make_error("Invalid or truncated PDB Named Stream Map deleted bitset");
    }
    cursor += static_cast<std::size_t>(*deleted_words_cnt) * 4u;

    for (std::uint32_t w = 0; w < *present_words_cnt; ++w) {
        const std::uint32_t mask = present_words[w];
        if (mask == 0u) {
            continue;
        }
        for (std::uint32_t bit = 0; bit < 32u; ++bit) {
            if ((mask & (1u << bit)) == 0u) {
                continue;
            }
            const std::uint32_t bucket = w * 32u + bit;
            if (bucket >= *ht_capacity) {
                return make_error("PDB Named Stream Map present bit exceeds capacity");
            }
            const auto key_off = read_u32(s1, cursor);
            const auto stream_idx = read_u32(s1, cursor);
            if (!key_off || !stream_idx) {
                return make_error("Truncated PDB Named Stream Map bucket entry");
            }
            if (*key_off >= str_buf.size()) {
                return make_error("PDB Named Stream Map key offset exceeds string buffer");
            }
            std::size_t name_cursor = *key_off;
            const auto stream_name = read_cstr(str_buf, name_cursor);
            if (!stream_name) {
                return std::unexpected(stream_name.error());
            }
            if (*stream_name == "/names") {
                out.names_stream_index = *stream_idx;
            }
        }
    }

    return out;
}

class PdbNamesTable {
public:
    static Result<PdbNamesTable> parse(std::span<const std::uint8_t> raw) {
        if (raw.size() < 12u) {
            return make_error("PDB /names stream is smaller than 12-byte header");
        }
        const std::uint32_t magic = load_u32_le(raw, 0u);
        if (magic != kPdbNamesMagic) {
            return make_error("PDB /names stream has invalid signature");
        }
        const std::uint32_t hash_ver = load_u32_le(raw, 4u);
        if (hash_ver != 1u && hash_ver != 2u) {
            return make_error("Unsupported PDB /names hash version");
        }
        const std::uint32_t byte_size = load_u32_le(raw, 8u);
        if (byte_size > raw.size() - 12u) {
            return make_error("PDB /names string buffer extends past stream end");
        }

        PdbNamesTable table{};
        table.buffer_.assign(raw.begin() + 12, raw.begin() + 12 + static_cast<std::ptrdiff_t>(byte_size));
        return table;
    }

    [[nodiscard]] Result<std::string> lookup(std::uint32_t offset) const {
        if (buffer_.empty() && offset == 0u) {
            return std::string{};
        }
        if (offset >= buffer_.size()) {
            return make_error("PDB /names string offset out of bounds");
        }
        std::size_t cursor = offset;
        return read_cstr(buffer_, cursor);
    }

private:
    std::vector<std::uint8_t> buffer_{};
};

// ============================================================================
// Stream 2 (CodeView TPI Stream)
// ============================================================================

struct CvNumeric {
    std::uint64_t uval = 0;
    std::int64_t sval = 0;
    bool is_signed = false;
};

[[nodiscard]] Result<CvNumeric> read_cv_numeric(std::span<const std::uint8_t> buf,
                                                std::size_t& cursor) {
    const auto leaf = read_u16(buf, cursor);
    if (!leaf) {
        return std::unexpected(leaf.error());
    }
    if (*leaf < kLfNumericThreshold) {
        return CvNumeric{
            .uval = *leaf,
            .sval = static_cast<std::int64_t>(*leaf),
            .is_signed = false,
        };
    }

    switch (*leaf) {
    case kLfChar: {
        const auto v = read_u8(buf, cursor);
        if (!v) return std::unexpected(v.error());
        const std::int64_t sv = (*v >= 0x80u) ? (static_cast<std::int64_t>(*v) - 256)
                                              : static_cast<std::int64_t>(*v);
        return CvNumeric{.uval = static_cast<std::uint64_t>(sv), .sval = sv, .is_signed = true};
    }
    case kLfShort: {
        const auto v = read_u16(buf, cursor);
        if (!v) return std::unexpected(v.error());
        const auto sv = static_cast<std::int64_t>(static_cast<std::int16_t>(*v));
        return CvNumeric{.uval = static_cast<std::uint64_t>(sv), .sval = sv, .is_signed = true};
    }
    case kLfUShort: {
        const auto v = read_u16(buf, cursor);
        if (!v) return std::unexpected(v.error());
        return CvNumeric{
            .uval = *v,
            .sval = static_cast<std::int64_t>(*v),
            .is_signed = false,
        };
    }
    case kLfLong: {
        const auto v = read_i32(buf, cursor);
        if (!v) return std::unexpected(v.error());
        const auto sv = static_cast<std::int64_t>(*v);
        return CvNumeric{.uval = static_cast<std::uint64_t>(sv), .sval = sv, .is_signed = true};
    }
    case kLfULong: {
        const auto v = read_u32(buf, cursor);
        if (!v) return std::unexpected(v.error());
        return CvNumeric{
            .uval = *v,
            .sval = static_cast<std::int64_t>(*v),
            .is_signed = false,
        };
    }
    case kLfQuadword: {
        const auto v = read_u64(buf, cursor);
        if (!v) return std::unexpected(v.error());
        return CvNumeric{
            .uval = *v,
            .sval = static_cast<std::int64_t>(*v),
            .is_signed = true,
        };
    }
    case kLfUQuadword: {
        const auto v = read_u64(buf, cursor);
        if (!v) return std::unexpected(v.error());
        return CvNumeric{
            .uval = *v,
            .sval = static_cast<std::int64_t>(*v),
            .is_signed = false,
        };
    }
    case kLfReal32:
        if (cursor > buf.size() || buf.size() - cursor < 4u) {
            return make_error("Truncated LF_REAL32 numeric leaf");
        }
        cursor += 4u;
        return CvNumeric{};
    case kLfReal64:
        if (cursor > buf.size() || buf.size() - cursor < 8u) {
            return make_error("Truncated LF_REAL64 numeric leaf");
        }
        cursor += 8u;
        return CvNumeric{};
    case kLfReal80:
        if (cursor > buf.size() || buf.size() - cursor < 10u) {
            return make_error("Truncated LF_REAL80 numeric leaf");
        }
        cursor += 10u;
        return CvNumeric{};
    case kLfReal128:
        if (cursor > buf.size() || buf.size() - cursor < 16u) {
            return make_error("Truncated LF_REAL128 numeric leaf");
        }
        cursor += 16u;
        return CvNumeric{};
    default:
        return make_error(std::format("Unsupported CodeView numeric leaf {:#x}", *leaf));
    }
}

struct ResolvedTypeDesc {
    std::string name{};
    std::uint64_t byte_size = 0;
    std::uint8_t bit_size = 0;
    std::uint8_t bit_offset = 0;
    bool is_bitfield = false;
};

[[nodiscard]] ResolvedTypeDesc resolve_builtin_cv_type(std::uint32_t ti) {
    const std::uint32_t mode = (ti >> 8u) & 0x0Fu;
    const std::uint32_t kind = ti & 0xFFu;

    std::string base = "unknown";
    std::uint64_t size = 0u;

    switch (kind) {
    case 0x00u: base = "void"; size = 0u; break;
    case 0x03u: base = "void"; size = 0u; break;
    case 0x08u: base = "HRESULT"; size = 4u; break;
    case 0x10u:
    case 0x68u: base = "int8_t"; size = 1u; break;
    case 0x20u:
    case 0x69u: base = "uint8_t"; size = 1u; break;
    case 0x70u: base = "char"; size = 1u; break;
    case 0x71u: base = "wchar_t"; size = 2u; break;
    case 0x7au: base = "char16_t"; size = 2u; break;
    case 0x7bu: base = "char32_t"; size = 4u; break;
    case 0x7cu: base = "char8_t"; size = 1u; break;
    case 0x11u:
    case 0x72u: base = "int16_t"; size = 2u; break;
    case 0x21u:
    case 0x73u: base = "uint16_t"; size = 2u; break;
    case 0x74u: base = "int32_t"; size = 4u; break;
    case 0x75u: base = "uint32_t"; size = 4u; break;
    case 0x12u: base = "long"; size = 4u; break;
    case 0x22u: base = "unsigned long"; size = 4u; break;
    case 0x13u:
    case 0x76u: base = "int64_t"; size = 8u; break;
    case 0x23u:
    case 0x77u: base = "uint64_t"; size = 8u; break;
    case 0x78u: base = "int128_t"; size = 16u; break;
    case 0x79u: base = "uint128_t"; size = 16u; break;
    case 0x30u: base = "bool"; size = 1u; break;
    case 0x31u: base = "bool"; size = 2u; break;
    case 0x32u: base = "bool"; size = 4u; break;
    case 0x33u: base = "bool"; size = 8u; break;
    case 0x40u: base = "float"; size = 4u; break;
    case 0x41u: base = "double"; size = 8u; break;
    case 0x42u: base = "long double"; size = 10u; break;
    case 0x43u: base = "float128"; size = 16u; break;
    case 0x44u: base = "float48"; size = 6u; break;
    default:
        base = std::format("cv_builtin_{:#x}", kind);
        size = 0u;
        break;
    }

    if (mode != 0u) {
        std::uint64_t ptr_size = 8u;
        switch (mode) {
        case 0x01u: ptr_size = 2u; break;
        case 0x02u:
        case 0x03u:
        case 0x04u: ptr_size = 4u; break;
        case 0x05u: ptr_size = 6u; break;
        case 0x06u: ptr_size = 8u; break;
        case 0x07u: ptr_size = 16u; break;
        default: ptr_size = 8u; break;
        }
        return ResolvedTypeDesc{.name = base + "*", .byte_size = ptr_size};
    }

    return ResolvedTypeDesc{.name = std::move(base), .byte_size = size};
}

class TpiTable {
public:
    struct RawRecord {
        std::uint16_t kind = 0;
        std::size_t payload_offset = 0;
        std::size_t payload_size = 0;
    };

    struct AggregateHeader {
        PdbAggregateKind agg_kind = PdbAggregateKind::Struct;
        std::uint16_t properties = 0;
        std::uint32_t field_list_ti = 0;
        std::uint64_t byte_size = 0;
        std::string name{};
        bool is_forward_ref = false;
    };

    struct EnumHeader {
        std::uint16_t properties = 0;
        std::uint32_t underlying_ti = 0;
        std::uint32_t field_list_ti = 0;
        std::string name{};
        bool is_forward_ref = false;
    };

    static Result<TpiTable> parse(std::span<const std::uint8_t> stream_bytes) {
        TpiTable table{};
        if (stream_bytes.empty()) {
            return table;
        }
        if (stream_bytes.size() < 56u) {
            return make_error("PDB TPI stream (Stream 2) is smaller than 56-byte header");
        }

        const std::uint32_t header_size = load_u32_le(stream_bytes, 4u);
        const std::uint32_t ti_begin = load_u32_le(stream_bytes, 8u);
        const std::uint32_t ti_end = load_u32_le(stream_bytes, 12u);
        const std::uint32_t rec_bytes = load_u32_le(stream_bytes, 16u);

        if (header_size < 56u || header_size > stream_bytes.size()) {
            return make_error("Invalid PDB TPI header_size");
        }
        if (ti_begin < 0x1000u || ti_end < ti_begin || (ti_end - ti_begin) > kMaxTypeRecords) {
            return make_error("Invalid PDB TPI TypeIndex range");
        }
        if (rec_bytes > stream_bytes.size() - header_size) {
            return make_error("PDB TPI TypeRecordBytes extends past end of Stream 2");
        }

        table.ti_begin_ = ti_begin;
        table.ti_end_ = ti_end;
        table.stream_data_.assign(stream_bytes.begin(), stream_bytes.end());

        const std::uint32_t expected_count = ti_end - ti_begin;
        table.records_.reserve(expected_count);

        std::size_t cursor = header_size;
        const std::size_t end_off = static_cast<std::size_t>(header_size) + rec_bytes;
        for (std::uint32_t i = 0; i < expected_count; ++i) {
            if (cursor > end_off || end_off - cursor < 4u) {
                return make_error("Truncated CodeView TPI record framing");
            }
            const std::uint16_t rec_len = load_u16_le(table.stream_data_, cursor);
            if (rec_len < 2u || static_cast<std::size_t>(rec_len) > end_off - cursor - 2u) {
                return make_error("CodeView TPI record length exceeds stream bounds");
            }
            const std::uint16_t rec_kind = load_u16_le(table.stream_data_, cursor + 2u);
            table.records_.push_back(RawRecord{
                .kind = rec_kind,
                .payload_offset = cursor + 4u,
                .payload_size = static_cast<std::size_t>(rec_len - 2u),
            });
            cursor += 2u + static_cast<std::size_t>(rec_len);
        }

        // Pre-validate known leaf records and index full aggregate/enum definitions.
        for (std::uint32_t idx = 0; idx < expected_count; ++idx) {
            const std::uint32_t ti = ti_begin + idx;
            const RawRecord& rec = table.records_[idx];
            const auto payload = table.payload_of(rec);

            switch (rec.kind) {
            case kLfClass:
            case kLfStructure:
            case kLfInterface: {
                auto agg = parse_struct_like_header(rec.kind, payload);
                if (!agg) return std::unexpected(agg.error());
                if (!agg->is_forward_ref && !agg->name.empty()) {
                    table.full_agg_by_name_[agg->name] = ti;
                }
                table.agg_headers_[ti] = std::move(*agg);
                break;
            }
            case kLfUnion: {
                auto uni = parse_union_header(payload);
                if (!uni) return std::unexpected(uni.error());
                if (!uni->is_forward_ref && !uni->name.empty()) {
                    table.full_agg_by_name_[uni->name] = ti;
                }
                table.agg_headers_[ti] = std::move(*uni);
                break;
            }
            case kLfEnum: {
                auto en = parse_enum_header(payload);
                if (!en) return std::unexpected(en.error());
                if (!en->is_forward_ref && !en->name.empty()) {
                    table.full_enum_by_name_[en->name] = ti;
                }
                table.enum_headers_[ti] = std::move(*en);
                break;
            }
            case kLfModifier:
                if (payload.size() < 6u) return make_error("Truncated LF_MODIFIER record");
                break;
            case kLfPointer:
                if (payload.size() < 8u) return make_error("Truncated LF_POINTER record");
                break;
            case kLfBitfield:
                if (payload.size() < 6u) return make_error("Truncated LF_BITFIELD record");
                break;
            case kLfProcedure:
                if (payload.size() < 12u) return make_error("Truncated LF_PROCEDURE record");
                break;
            case kLfMFunction:
                if (payload.size() < 24u) return make_error("Truncated LF_MFUNCTION record");
                break;
            case kLfArgList: {
                if (payload.size() < 4u) return make_error("Truncated LF_ARGLIST record");
                const std::uint32_t cnt = load_u32_le(payload, 0u);
                if (cnt > (payload.size() - 4u) / 4u) {
                    return make_error("Truncated LF_ARGLIST argument array");
                }
                break;
            }
            case kLfArray: {
                if (payload.size() < 8u) return make_error("Truncated LF_ARRAY record");
                std::size_t c = 8u;
                const auto sz = read_cv_numeric(payload, c);
                if (!sz) return std::unexpected(sz.error());
                const auto nm = read_cstr(payload, c);
                if (!nm) return std::unexpected(nm.error());
                break;
            }
            default:
                break;
            }
        }

        return table;
    }

    [[nodiscard]] ResolvedTypeDesc resolve_type(std::uint32_t ti) const {
        std::vector<std::uint32_t> active_stack{};
        return resolve_type_impl(ti, 0u, active_stack);
    }

    [[nodiscard]] Result<void> populate_layouts(std::vector<PdbAggregateType>& out_types,
                                                std::vector<PdbEnumType>& out_enums) const {
        std::map<std::string, std::size_t> emitted_agg_index{};
        std::map<std::string, std::size_t> emitted_enum_index{};

        const std::uint32_t count = ti_end_ - ti_begin_;
        for (std::uint32_t idx = 0; idx < count; ++idx) {
            const std::uint32_t ti = ti_begin_ + idx;

            if (const auto agg_it = agg_headers_.find(ti); agg_it != agg_headers_.end()) {
                const AggregateHeader& hdr = agg_it->second;
                if (hdr.is_forward_ref) {
                    continue;
                }
                if (hdr.name.empty() || hdr.name == "<unnamed-tag>") {
                    continue;
                }

                PdbAggregateType agg{};
                agg.name = hdr.name;
                agg.kind = hdr.agg_kind;
                agg.byte_size = hdr.byte_size;

                if (hdr.field_list_ti != 0u) {
                    std::vector<std::uint32_t> visited_fl{};
                    auto fl_res = collect_aggregate_members(hdr.field_list_ti, agg.members, visited_fl);
                    if (!fl_res) {
                        return std::unexpected(fl_res.error());
                    }
                }

                if (const auto prev = emitted_agg_index.find(agg.name);
                    prev != emitted_agg_index.end()) {
                    PdbAggregateType& existing = out_types[prev->second];
                    if (agg.members.size() > existing.members.size() ||
                        (agg.members.size() == existing.members.size() &&
                         agg.byte_size > existing.byte_size)) {
                        existing = std::move(agg);
                    }
                } else {
                    emitted_agg_index[agg.name] = out_types.size();
                    out_types.push_back(std::move(agg));
                }
                continue;
            }

            if (const auto en_it = enum_headers_.find(ti); en_it != enum_headers_.end()) {
                const EnumHeader& hdr = en_it->second;
                if (hdr.is_forward_ref || hdr.name.empty() || hdr.name == "<unnamed-tag>") {
                    continue;
                }

                const ResolvedTypeDesc under = resolve_type(hdr.underlying_ti);
                PdbEnumType en{};
                en.name = hdr.name;
                en.underlying_type_name = under.name;
                en.byte_size = under.byte_size;

                if (hdr.field_list_ti != 0u) {
                    std::vector<std::uint32_t> visited_fl{};
                    auto fl_res = collect_enumerators(hdr.field_list_ti, en.enumerators, visited_fl);
                    if (!fl_res) {
                        return std::unexpected(fl_res.error());
                    }
                }

                if (const auto prev = emitted_enum_index.find(en.name);
                    prev != emitted_enum_index.end()) {
                    PdbEnumType& existing = out_enums[prev->second];
                    if (en.enumerators.size() > existing.enumerators.size()) {
                        existing = std::move(en);
                    }
                } else {
                    emitted_enum_index[en.name] = out_enums.size();
                    out_enums.push_back(std::move(en));
                }
            }
        }

        return {};
    }

private:
    [[nodiscard]] std::span<const std::uint8_t> payload_of(const RawRecord& rec) const noexcept {
        return std::span<const std::uint8_t>(
            stream_data_.data() + rec.payload_offset, rec.payload_size);
    }

    [[nodiscard]] const RawRecord* find_record(std::uint32_t ti) const noexcept {
        if (ti < ti_begin_ || ti >= ti_end_) {
            return nullptr;
        }
        return &records_[ti - ti_begin_];
    }

    static Result<AggregateHeader> parse_struct_like_header(
        std::uint16_t kind,
        std::span<const std::uint8_t> payload) {
        if (payload.size() < 18u) {
            return make_error("Truncated LF_STRUCTURE/LF_CLASS/LF_INTERFACE record");
        }
        AggregateHeader hdr{};
        if (kind == kLfClass) {
            hdr.agg_kind = PdbAggregateKind::Class;
        } else if (kind == kLfInterface) {
            hdr.agg_kind = PdbAggregateKind::Interface;
        } else {
            hdr.agg_kind = PdbAggregateKind::Struct;
        }
        hdr.properties = load_u16_le(payload, 2u);
        hdr.field_list_ti = load_u32_le(payload, 4u);
        hdr.is_forward_ref = (hdr.properties & kCvPropForwardRef) != 0u;

        std::size_t cursor = 16u;
        const auto sz = read_cv_numeric(payload, cursor);
        if (!sz) {
            return std::unexpected(sz.error());
        }
        hdr.byte_size = sz->uval;
        auto name = read_cstr(payload, cursor);
        if (!name) {
            return std::unexpected(name.error());
        }
        hdr.name = std::move(*name);
        return hdr;
    }

    static Result<AggregateHeader> parse_union_header(std::span<const std::uint8_t> payload) {
        if (payload.size() < 10u) {
            return make_error("Truncated LF_UNION record");
        }
        AggregateHeader hdr{};
        hdr.agg_kind = PdbAggregateKind::Union;
        hdr.properties = load_u16_le(payload, 2u);
        hdr.field_list_ti = load_u32_le(payload, 4u);
        hdr.is_forward_ref = (hdr.properties & kCvPropForwardRef) != 0u;

        std::size_t cursor = 8u;
        const auto sz = read_cv_numeric(payload, cursor);
        if (!sz) {
            return std::unexpected(sz.error());
        }
        hdr.byte_size = sz->uval;
        auto name = read_cstr(payload, cursor);
        if (!name) {
            return std::unexpected(name.error());
        }
        hdr.name = std::move(*name);
        return hdr;
    }

    static Result<EnumHeader> parse_enum_header(std::span<const std::uint8_t> payload) {
        if (payload.size() < 13u) {
            return make_error("Truncated LF_ENUM record");
        }
        EnumHeader hdr{};
        hdr.properties = load_u16_le(payload, 2u);
        hdr.underlying_ti = load_u32_le(payload, 4u);
        hdr.field_list_ti = load_u32_le(payload, 8u);
        hdr.is_forward_ref = (hdr.properties & kCvPropForwardRef) != 0u;

        std::size_t cursor = 12u;
        auto name = read_cstr(payload, cursor);
        if (!name) {
            return std::unexpected(name.error());
        }
        hdr.name = std::move(*name);
        return hdr;
    }

    [[nodiscard]] ResolvedTypeDesc resolve_type_impl(
        std::uint32_t ti,
        std::size_t depth,
        std::vector<std::uint32_t>& active_stack) const {
        if (ti < 0x1000u) {
            return resolve_builtin_cv_type(ti);
        }

        if (depth >= kMaxTypeResolveDepth ||
            std::ranges::find(active_stack, ti) != active_stack.end()) {
            if (const auto agg_it = agg_headers_.find(ti); agg_it != agg_headers_.end()) {
                return ResolvedTypeDesc{
                    .name = agg_it->second.name.empty() ? "recursive_type" : agg_it->second.name,
                    .byte_size = agg_it->second.byte_size,
                };
            }
            return ResolvedTypeDesc{.name = "recursive_type", .byte_size = 0u};
        }

        const RawRecord* rec = find_record(ti);
        if (rec == nullptr) {
            return ResolvedTypeDesc{.name = std::format("type_{:#x}", ti), .byte_size = 0u};
        }

        active_stack.push_back(ti);
        struct StackPopGuard {
            std::vector<std::uint32_t>* stack = nullptr;
            explicit StackPopGuard(std::vector<std::uint32_t>* s) noexcept : stack(s) {}
            StackPopGuard(const StackPopGuard&) = delete;
            StackPopGuard& operator=(const StackPopGuard&) = delete;
            StackPopGuard(StackPopGuard&&) = delete;
            StackPopGuard& operator=(StackPopGuard&&) = delete;
            ~StackPopGuard() noexcept {
                if (stack != nullptr) {
                    stack->pop_back();
                }
            }
        } const pop_guard{&active_stack};

        const auto payload = payload_of(*rec);
        switch (rec->kind) {
        case kLfClass:
        case kLfStructure:
        case kLfInterface:
        case kLfUnion: {
            const auto it = agg_headers_.find(ti);
            if (it == agg_headers_.end()) {
                return ResolvedTypeDesc{.name = "struct", .byte_size = 0u};
            }
            std::uint64_t sz = it->second.byte_size;
            if (sz == 0u && it->second.is_forward_ref && !it->second.name.empty()) {
                if (const auto full_it = full_agg_by_name_.find(it->second.name);
                    full_it != full_agg_by_name_.end() && full_it->second != ti) {
                    if (const auto full_hdr = agg_headers_.find(full_it->second);
                        full_hdr != agg_headers_.end()) {
                        sz = full_hdr->second.byte_size;
                    }
                }
            }
            return ResolvedTypeDesc{
                .name = it->second.name.empty() ? "anonymous_struct" : it->second.name,
                .byte_size = sz,
            };
        }
        case kLfEnum: {
            const auto it = enum_headers_.find(ti);
            if (it == enum_headers_.end()) {
                return ResolvedTypeDesc{.name = "enum", .byte_size = 4u};
            }
            std::uint32_t uti = it->second.underlying_ti;
            if (uti == 0u && it->second.is_forward_ref && !it->second.name.empty()) {
                if (const auto full_it = full_enum_by_name_.find(it->second.name);
                    full_it != full_enum_by_name_.end() && full_it->second != ti) {
                    if (const auto full_hdr = enum_headers_.find(full_it->second);
                        full_hdr != enum_headers_.end()) {
                        uti = full_hdr->second.underlying_ti;
                    }
                }
            }
            const ResolvedTypeDesc under = resolve_type_impl(uti, depth + 1u, active_stack);
            return ResolvedTypeDesc{
                .name = it->second.name.empty() ? under.name : it->second.name,
                .byte_size = under.byte_size,
            };
        }
        case kLfModifier: {
            const std::uint32_t mod_ti = load_u32_le(payload, 0u);
            const std::uint16_t mods = load_u16_le(payload, 4u);
            ResolvedTypeDesc inner = resolve_type_impl(mod_ti, depth + 1u, active_stack);
            std::string prefix;
            if ((mods & 0x0001u) != 0u) {
                prefix += "const ";
            }
            if ((mods & 0x0002u) != 0u) {
                prefix += "volatile ";
            }
            inner.name = prefix + inner.name;
            return inner;
        }
        case kLfPointer: {
            const std::uint32_t ref_ti = load_u32_le(payload, 0u);
            const std::uint32_t attrs = load_u32_le(payload, 4u);
            const std::uint32_t ptr_kind = attrs & 0x1Fu;
            const std::uint32_t ptr_mode = (attrs >> 5u) & 0x07u;
            std::uint64_t ptr_size = (attrs >> 13u) & 0x3Fu;
            if (ptr_size == 0u) {
                if (ptr_kind == 0x0au) {
                    ptr_size = 4u;
                } else if (ptr_kind == 0x00u) {
                    ptr_size = 2u;
                } else {
                    ptr_size = 8u;
                }
            }
            const ResolvedTypeDesc inner = resolve_type_impl(ref_ti, depth + 1u, active_stack);
            std::string suffix = "*";
            if (ptr_mode == 1u) {
                suffix = "&";
            } else if (ptr_mode == 4u) {
                suffix = "&&";
            }
            return ResolvedTypeDesc{.name = inner.name + suffix, .byte_size = ptr_size};
        }
        case kLfArray: {
            const std::uint32_t elem_ti = load_u32_le(payload, 0u);
            std::size_t cursor = 8u;
            const auto total_sz = read_cv_numeric(payload, cursor);
            const std::uint64_t arr_bytes = total_sz ? total_sz->uval : 0u;
            const ResolvedTypeDesc elem = resolve_type_impl(elem_ti, depth + 1u, active_stack);
            if (elem.byte_size > 0u) {
                const std::uint64_t count = arr_bytes / elem.byte_size;
                return ResolvedTypeDesc{
                    .name = std::format("{}[{}]", elem.name, count),
                    .byte_size = arr_bytes,
                };
            }
            return ResolvedTypeDesc{.name = elem.name + "[]", .byte_size = arr_bytes};
        }
        case kLfBitfield: {
            const std::uint32_t base_ti = load_u32_le(payload, 0u);
            const std::uint8_t bit_len = payload[4u];
            const std::uint8_t bit_pos = payload[5u];
            const ResolvedTypeDesc base = resolve_type_impl(base_ti, depth + 1u, active_stack);
            return ResolvedTypeDesc{
                .name = std::format("{} : {}", base.name, bit_len),
                .byte_size = base.byte_size,
                .bit_size = bit_len,
                .bit_offset = bit_pos,
                .is_bitfield = true,
            };
        }
        case kLfProcedure: {
            const std::uint32_t ret_ti = load_u32_le(payload, 0u);
            const std::uint32_t arglist_ti = load_u32_le(payload, 8u);
            const ResolvedTypeDesc ret = resolve_type_impl(ret_ti, depth + 1u, active_stack);
            const std::string args = format_arglist(arglist_ti, depth + 1u, active_stack);
            return ResolvedTypeDesc{
                .name = std::format("{}({})", ret.name, args),
                .byte_size = 0u,
            };
        }
        case kLfMFunction: {
            const std::uint32_t ret_ti = load_u32_le(payload, 0u);
            const std::uint32_t cls_ti = load_u32_le(payload, 4u);
            const std::uint32_t arglist_ti = load_u32_le(payload, 16u);
            const ResolvedTypeDesc ret = resolve_type_impl(ret_ti, depth + 1u, active_stack);
            const ResolvedTypeDesc cls = resolve_type_impl(cls_ti, depth + 1u, active_stack);
            const std::string args = format_arglist(arglist_ti, depth + 1u, active_stack);
            return ResolvedTypeDesc{
                .name = std::format("{}({}::*)({})", ret.name, cls.name, args),
                .byte_size = 0u,
            };
        }
        default:
            return ResolvedTypeDesc{
                .name = std::format("cv_leaf_{:#x}", rec->kind),
                .byte_size = 0u,
            };
        }
    }

    [[nodiscard]] std::string format_arglist(
        std::uint32_t arglist_ti,
        std::size_t depth,
        std::vector<std::uint32_t>& active_stack) const {
        if (depth >= kMaxTypeResolveDepth) {
            return "...";
        }
        const RawRecord* rec = find_record(arglist_ti);
        if (rec == nullptr || rec->kind != kLfArgList) {
            return "";
        }
        const auto payload = payload_of(*rec);
        if (payload.size() < 4u) {
            return "";
        }
        const std::uint32_t arg_count = std::min<std::uint32_t>(load_u32_le(payload, 0u), 16u);
        std::string out;
        for (std::uint32_t i = 0; i < arg_count; ++i) {
            if (4u + static_cast<std::size_t>(i) * 4u + 4u > payload.size()) {
                break;
            }
            if (i > 0u) {
                out += ", ";
            }
            const std::uint32_t param_ti = load_u32_le(payload, 4u + static_cast<std::size_t>(i) * 4u);
            out += resolve_type_impl(param_ti, depth + 1u, active_stack).name;
        }
        return out;
    }

    static Result<void> skip_fieldlist_padding(std::span<const std::uint8_t> payload,
                                               std::size_t& cursor) {
        while (cursor < payload.size()) {
            const std::uint8_t b = payload[cursor];
            if (b >= 0xF1u) {
                const auto pad = static_cast<std::size_t>(b & 0x0Fu);
                if (pad > payload.size() - cursor) {
                    return make_error("Truncated alignment padding in CodeView LF_FIELDLIST");
                }
                cursor += pad;
                continue;
            }
            if (b == 0xF0u) {
                ++cursor;
                continue;
            }
            break;
        }
        return {};
    }

    [[nodiscard]] Result<void> collect_aggregate_members(
        std::uint32_t fieldlist_ti,
        std::vector<PdbMemberInfo>& out_members,
        std::vector<std::uint32_t>& visited) const {
        if (visited.size() >= kMaxFieldListContinuations ||
            std::ranges::find(visited, fieldlist_ti) != visited.end()) {
            return {};
        }
        const RawRecord* rec = find_record(fieldlist_ti);
        if (rec == nullptr || rec->kind != kLfFieldList) {
            return {};
        }
        visited.push_back(fieldlist_ti);

        const auto payload = payload_of(*rec);
        std::size_t cursor = 0u;
        while (cursor < payload.size()) {
            if (auto pad_res = skip_fieldlist_padding(payload, cursor); !pad_res) {
                return pad_res;
            }
            if (cursor >= payload.size()) {
                break;
            }

            const auto sub_kind = read_u16(payload, cursor);
            if (!sub_kind) {
                return std::unexpected(sub_kind.error());
            }

            switch (*sub_kind) {
            case kLfMember: {
                const auto attrs = read_u16(payload, cursor);
                const auto member_ti = read_u32(payload, cursor);
                if (!attrs || !member_ti) {
                    return make_error("Truncated LF_MEMBER subrecord");
                }
                const auto offset = read_cv_numeric(payload, cursor);
                if (!offset) {
                    return std::unexpected(offset.error());
                }
                auto member_name = read_cstr(payload, cursor);
                if (!member_name) {
                    return std::unexpected(member_name.error());
                }

                const ResolvedTypeDesc resolved = resolve_type(*member_ti);
                out_members.push_back(PdbMemberInfo{
                    .name = std::move(*member_name),
                    .type_name = resolved.name,
                    .byte_offset = offset->uval,
                    .byte_size = resolved.byte_size,
                    .bit_size = resolved.bit_size,
                    .bit_offset = resolved.bit_offset,
                    .is_bitfield = resolved.is_bitfield,
                    .is_base_class = false,
                });
                break;
            }
            case kLfBClass: {
                const auto attrs = read_u16(payload, cursor);
                const auto base_ti = read_u32(payload, cursor);
                if (!attrs || !base_ti) {
                    return make_error("Truncated LF_BCLASS subrecord");
                }
                const auto offset = read_cv_numeric(payload, cursor);
                if (!offset) {
                    return std::unexpected(offset.error());
                }
                const ResolvedTypeDesc base_desc = resolve_type(*base_ti);
                out_members.push_back(PdbMemberInfo{
                    .name = "base_" + base_desc.name,
                    .type_name = base_desc.name,
                    .byte_offset = offset->uval,
                    .byte_size = base_desc.byte_size,
                    .is_base_class = true,
                });
                break;
            }
            case kLfIndex:
            case kLfIndex16: {
                const auto pad0 = read_u16(payload, cursor);
                const auto next_ti = read_u32(payload, cursor);
                if (!pad0 || !next_ti) {
                    return make_error("Truncated LF_INDEX continuation subrecord");
                }
                auto cont_res = collect_aggregate_members(*next_ti, out_members, visited);
                if (!cont_res) {
                    return cont_res;
                }
                break;
            }
            case kLfEnumerate: {
                const auto attrs = read_u16(payload, cursor);
                if (!attrs) return std::unexpected(attrs.error());
                const auto val = read_cv_numeric(payload, cursor);
                if (!val) return std::unexpected(val.error());
                const auto nm = read_cstr(payload, cursor);
                if (!nm) return std::unexpected(nm.error());
                break;
            }
            case kLfStMember:
            case kLfMethod:
            case kLfNestType: {
                if (cursor > payload.size() || payload.size() - cursor < 6u) {
                    return make_error("Truncated C++ class subrecord in LF_FIELDLIST");
                }
                cursor += 6u;
                const auto nm = read_cstr(payload, cursor);
                if (!nm) return std::unexpected(nm.error());
                break;
            }
            case kLfOneMethod: {
                const auto attrs = read_u16(payload, cursor);
                const auto mti = read_u32(payload, cursor);
                if (!attrs || !mti) {
                    return make_error("Truncated LF_ONEMETHOD subrecord");
                }
                const std::uint16_t mprop = (*attrs >> 2u) & 0x07u;
                if (mprop == 4u || mprop == 6u) {
                    if (!read_u32(payload, cursor)) {
                        return make_error("Truncated LF_ONEMETHOD vbase offset");
                    }
                }
                const auto nm = read_cstr(payload, cursor);
                if (!nm) return std::unexpected(nm.error());
                break;
            }
            case kLfVFuncTab: {
                if (cursor > payload.size() || payload.size() - cursor < 6u) {
                    return make_error("Truncated LF_VFUNCTAB subrecord");
                }
                cursor += 6u;
                break;
            }
            case kLfVBClass:
            case kLfIVBClass: {
                if (cursor > payload.size() || payload.size() - cursor < 10u) {
                    return make_error("Truncated LF_VBCLASS subrecord");
                }
                cursor += 10u;
                if (!read_cv_numeric(payload, cursor) || !read_cv_numeric(payload, cursor)) {
                    return make_error("Truncated LF_VBCLASS numeric offsets");
                }
                break;
            }
            default:
                return {};
            }
        }
        return {};
    }

    [[nodiscard]] Result<void> collect_enumerators(
        std::uint32_t fieldlist_ti,
        std::vector<PdbEnumeratorInfo>& out_enums,
        std::vector<std::uint32_t>& visited) const {
        if (visited.size() >= kMaxFieldListContinuations ||
            std::ranges::find(visited, fieldlist_ti) != visited.end()) {
            return {};
        }
        const RawRecord* rec = find_record(fieldlist_ti);
        if (rec == nullptr || rec->kind != kLfFieldList) {
            return {};
        }
        visited.push_back(fieldlist_ti);

        const auto payload = payload_of(*rec);
        std::size_t cursor = 0u;
        while (cursor < payload.size()) {
            if (auto pad_res = skip_fieldlist_padding(payload, cursor); !pad_res) {
                return pad_res;
            }
            if (cursor >= payload.size()) {
                break;
            }

            const auto sub_kind = read_u16(payload, cursor);
            if (!sub_kind) {
                return std::unexpected(sub_kind.error());
            }

            if (*sub_kind == kLfEnumerate) {
                const auto attrs = read_u16(payload, cursor);
                if (!attrs) return make_error("Truncated LF_ENUMERATE attributes");
                const auto val = read_cv_numeric(payload, cursor);
                if (!val) return std::unexpected(val.error());
                auto nm = read_cstr(payload, cursor);
                if (!nm) return std::unexpected(nm.error());
                out_enums.push_back(PdbEnumeratorInfo{
                    .name = std::move(*nm),
                    .signed_value = val->sval,
                    .unsigned_value = val->uval,
                    .is_signed = val->is_signed,
                });
            } else if (*sub_kind == kLfIndex || *sub_kind == kLfIndex16) {
                const auto pad0 = read_u16(payload, cursor);
                const auto next_ti = read_u32(payload, cursor);
                if (!pad0 || !next_ti) {
                    return make_error("Truncated LF_INDEX continuation in enum fieldlist");
                }
                auto cont_res = collect_enumerators(*next_ti, out_enums, visited);
                if (!cont_res) return cont_res;
            } else {
                break;
            }
        }
        return {};
    }

    std::uint32_t ti_begin_ = 0x1000u;
    std::uint32_t ti_end_ = 0x1000u;
    std::vector<std::uint8_t> stream_data_{};
    std::vector<RawRecord> records_{};
    std::unordered_map<std::uint32_t, AggregateHeader> agg_headers_{};
    std::unordered_map<std::uint32_t, EnumHeader> enum_headers_{};
    std::unordered_map<std::string, std::uint32_t> full_agg_by_name_{};
    std::unordered_map<std::string, std::uint32_t> full_enum_by_name_{};
};

// ============================================================================
// Section Header & OMAP RVA Translation
// ============================================================================

struct OmapEntry {
    std::uint32_t rva_from = 0;
    std::uint32_t rva_to = 0;
};

class SectionRvaTranslator {
public:
    static Result<std::vector<std::uint64_t>> parse_section_header_stream(
        std::span<const std::uint8_t> bytes) {
        if (bytes.size() % 40u != 0u) {
            return make_error("PDB IMAGE_SECTION_HEADER stream size is not a multiple of 40 bytes");
        }
        const std::size_t count = bytes.size() / 40u;
        std::vector<std::uint64_t> rvas(count);
        for (std::size_t i = 0; i < count; ++i) {
            rvas[i] = load_u32_le(bytes, i * 40u + 12u);
        }
        return rvas;
    }

    static Result<std::vector<OmapEntry>> parse_omap_stream(std::span<const std::uint8_t> bytes) {
        if (bytes.size() % 8u != 0u) {
            return make_error("PDB OMAP_FROM_SRC stream size is not a multiple of 8 bytes");
        }
        const std::size_t count = bytes.size() / 8u;
        std::vector<OmapEntry> entries(count);
        for (std::size_t i = 0; i < count; ++i) {
            entries[i] = OmapEntry{
                .rva_from = load_u32_le(bytes, i * 8u),
                .rva_to = load_u32_le(bytes, i * 8u + 4u),
            };
        }
        std::ranges::sort(entries, {}, &OmapEntry::rva_from);
        return entries;
    }

    static SectionRvaTranslator from_streams_or_fallback(
        std::vector<std::uint64_t> section_hdr_rvas,
        std::vector<std::uint64_t> section_hdr_orig_rvas,
        std::vector<OmapEntry> omap_from_src,
        std::span<const Section> fallback_pe_sections,
        std::uint64_t fallback_image_base) {
        SectionRvaTranslator tr{};
        tr.omap_ = std::move(omap_from_src);

        if (!tr.omap_.empty() && !section_hdr_orig_rvas.empty()) {
            tr.section_rvas_ = std::move(section_hdr_orig_rvas);
            return tr;
        }
        if (!section_hdr_rvas.empty()) {
            tr.section_rvas_ = std::move(section_hdr_rvas);
            return tr;
        }

        std::uint64_t effective_base = fallback_image_base;
        if (effective_base == 0u && !fallback_pe_sections.empty()) {
            std::uint64_t min_va = std::numeric_limits<std::uint64_t>::max();
            for (const Section& sec : fallback_pe_sections) {
                if (sec.virtual_address != 0u) {
                    min_va = std::min(min_va, sec.virtual_address);
                }
            }
            constexpr std::uint64_t kPeBaseAlignMask = ~std::uint64_t{0xFFFFu};
            if (min_va != std::numeric_limits<std::uint64_t>::max() &&
                (min_va & kPeBaseAlignMask) >= 0x0040'0000ull) {
                effective_base = min_va & kPeBaseAlignMask;
            }
        }

        tr.section_rvas_.reserve(fallback_pe_sections.size());
        for (const Section& sec : fallback_pe_sections) {
            if (sec.virtual_address >= effective_base) {
                tr.section_rvas_.push_back(sec.virtual_address - effective_base);
            } else {
                tr.section_rvas_.push_back(sec.virtual_address);
            }
        }
        return tr;
    }

    [[nodiscard]] std::optional<std::uint64_t> to_rva(std::uint16_t segment_1based,
                                                      std::uint32_t offset) const noexcept {
        if (segment_1based == 0u || segment_1based > section_rvas_.size()) {
            return std::nullopt;
        }
        const std::uint64_t base_rva = section_rvas_[segment_1based - 1u];
        const auto unmapped = checked_add_u64(base_rva, offset);
        if (!unmapped.has_value()) {
            return std::nullopt;
        }
        if (omap_.empty()) {
            return *unmapped;
        }

        const auto upper = std::ranges::upper_bound(
            omap_, *unmapped, {}, [](const OmapEntry& e) { return static_cast<std::uint64_t>(e.rva_from); });
        if (upper == omap_.begin()) {
            return *unmapped;
        }
        const OmapEntry& match = *(upper - 1);
        if (match.rva_to == 0u) {
            return std::nullopt;
        }
        return checked_add_u64(match.rva_to, *unmapped - match.rva_from);
    }

private:
    std::vector<std::uint64_t> section_rvas_{};
    std::vector<OmapEntry> omap_{};
};

// ============================================================================
// CodeView Symbol Records & C13 Line Info
// ============================================================================

[[nodiscard]] Result<void> parse_cv_symbol_stream(
    std::span<const std::uint8_t> sym_bytes,
    const SectionRvaTranslator& rva_translator,
    const TpiTable& tpi,
    std::string_view module_name,
    std::string_view library_name,
    std::vector<PdbSymbol>& out_symbols) {
    std::size_t cursor = 0u;
    while (cursor < sym_bytes.size()) {
        // Skip trailing zero-padding at the end of 4-byte aligned symbol substreams.
        if (sym_bytes.size() - cursor < 4u) {
            const bool all_zero = std::ranges::all_of(
                sym_bytes.subspan(cursor), [](std::uint8_t b) { return b == 0u; });
            if (all_zero) {
                break;
            }
            return make_error("Truncated CodeView symbol record header");
        }

        const std::uint16_t rec_len = load_u16_le(sym_bytes, cursor);
        if (rec_len == 0u) {
            const bool all_zero = std::ranges::all_of(
                sym_bytes.subspan(cursor), [](std::uint8_t b) { return b == 0u; });
            if (all_zero) {
                break;
            }
            return make_error("Invalid zero-length CodeView symbol record");
        }
        if (rec_len < 2u || static_cast<std::size_t>(rec_len) > sym_bytes.size() - cursor - 2u) {
            return make_error("Truncated CodeView symbol record payload");
        }

        const std::uint16_t rec_kind = load_u16_le(sym_bytes, cursor + 2u);
        const std::span<const std::uint8_t> payload =
            sym_bytes.subspan(cursor + 4u, static_cast<std::size_t>(rec_len - 2u));
        cursor += 2u + static_cast<std::size_t>(rec_len);

        switch (rec_kind) {
        case kSPub32: {
            if (payload.size() < 11u) {
                return make_error("Truncated S_PUB32 symbol record");
            }
            const std::uint32_t pub_flags = load_u32_le(payload, 0u);
            const std::uint32_t off = load_u32_le(payload, 4u);
            const std::uint16_t seg = load_u16_le(payload, 8u);
            std::size_t nc = 10u;
            auto name = read_cstr(payload, nc);
            if (!name) {
                return std::unexpected(name.error());
            }
            if (name->empty()) {
                break;
            }
            const auto rva = rva_translator.to_rva(seg, off);
            if (!rva.has_value() || *rva == 0u) {
                break;
            }
            out_symbols.push_back(PdbSymbol{
                .name = std::move(*name),
                .relative_address = *rva,
                .byte_size = 0u,
                .segment = seg,
                .segment_offset = off,
                .is_function = (pub_flags & kPubSymFlagFunction) != 0u,
                .is_public = true,
                .module_name = std::string(module_name),
                .library_name = std::string(library_name),
            });
            break;
        }
        case kSGProc32:
        case kSLProc32:
        case kSGProc32Id:
        case kSLProc32Id: {
            if (payload.size() < 36u) {
                return make_error("Truncated S_GPROC32/S_LPROC32 symbol record");
            }
            const std::uint32_t code_size = load_u32_le(payload, 12u);
            const std::uint32_t off = load_u32_le(payload, 28u);
            const std::uint16_t seg = load_u16_le(payload, 32u);
            std::size_t nc = 35u;
            auto name = read_cstr(payload, nc);
            if (!name) {
                return std::unexpected(name.error());
            }
            if (name->empty()) {
                break;
            }
            const auto rva = rva_translator.to_rva(seg, off);
            if (!rva.has_value() || *rva == 0u) {
                break;
            }
            out_symbols.push_back(PdbSymbol{
                .name = std::move(*name),
                .relative_address = *rva,
                .byte_size = code_size,
                .segment = seg,
                .segment_offset = off,
                .is_function = true,
                .is_public = false,
                .module_name = std::string(module_name),
                .library_name = std::string(library_name),
            });
            break;
        }
        case kSGData32:
        case kSLData32: {
            if (payload.size() < 11u) {
                return make_error("Truncated S_GDATA32/S_LDATA32 symbol record");
            }
            const std::uint32_t type_idx = load_u32_le(payload, 0u);
            const std::uint32_t off = load_u32_le(payload, 4u);
            const std::uint16_t seg = load_u16_le(payload, 8u);
            std::size_t nc = 10u;
            auto name = read_cstr(payload, nc);
            if (!name) {
                return std::unexpected(name.error());
            }
            if (name->empty()) {
                break;
            }
            const auto rva = rva_translator.to_rva(seg, off);
            if (!rva.has_value() || *rva == 0u) {
                break;
            }
            const std::uint64_t data_size = tpi.resolve_type(type_idx).byte_size;
            out_symbols.push_back(PdbSymbol{
                .name = std::move(*name),
                .relative_address = *rva,
                .byte_size = data_size,
                .segment = seg,
                .segment_offset = off,
                .is_function = false,
                .is_public = false,
                .module_name = std::string(module_name),
                .library_name = std::string(library_name),
            });
            break;
        }
        default:
            break;
        }
    }
    return {};
}

void merge_and_deduplicate_pdb_symbols(std::vector<PdbSymbol>& symbols) {
    struct ProcMetadata {
        std::uint64_t byte_size = 0;
        std::string module_name{};
        std::string library_name{};
    };
    std::unordered_map<std::uint64_t, ProcMetadata> proc_by_rva{};
    for (const PdbSymbol& sym : symbols) {
        if (!sym.is_public && sym.is_function) {
            ProcMetadata& meta = proc_by_rva[sym.relative_address];
            meta.byte_size = std::max(meta.byte_size, sym.byte_size);
            if (meta.module_name.empty() && !sym.module_name.empty()) {
                meta.module_name = sym.module_name;
            }
            if (meta.library_name.empty() && !sym.library_name.empty()) {
                meta.library_name = sym.library_name;
            }
        }
    }

    // Enrich S_PUB32 symbols that land on an exact PROC32 entry point with PROC32 size/provenance.
    for (PdbSymbol& sym : symbols) {
        if (sym.is_public) {
            if (const auto it = proc_by_rva.find(sym.relative_address); it != proc_by_rva.end()) {
                if (sym.byte_size == 0u) {
                    sym.byte_size = it->second.byte_size;
                }
                sym.is_function = true;
                if (sym.module_name.empty()) {
                    sym.module_name = it->second.module_name;
                }
                if (sym.library_name.empty()) {
                    sym.library_name = it->second.library_name;
                }
            }
        }
    }

    std::ranges::sort(symbols, [](const PdbSymbol& lhs, const PdbSymbol& rhs) {
        if (lhs.relative_address != rhs.relative_address) {
            return lhs.relative_address < rhs.relative_address;
        }
        if (lhs.name != rhs.name) {
            return lhs.name < rhs.name;
        }
        if (lhs.is_function != rhs.is_function) {
            return lhs.is_function > rhs.is_function;
        }
        if (lhs.byte_size != rhs.byte_size) {
            return lhs.byte_size > rhs.byte_size;
        }
        if (lhs.library_name != rhs.library_name) {
            return lhs.library_name > rhs.library_name;
        }
        return lhs.is_public < rhs.is_public;
    });

    std::vector<PdbSymbol> merged{};
    merged.reserve(symbols.size());
    for (PdbSymbol& sym : symbols) {
        if (!merged.empty() && merged.back().relative_address == sym.relative_address &&
            merged.back().name == sym.name) {
            PdbSymbol& dst = merged.back();
            dst.is_function = dst.is_function || sym.is_function;
            dst.is_public = dst.is_public || sym.is_public;
            dst.byte_size = std::max(dst.byte_size, sym.byte_size);
            if (dst.module_name.empty() && !sym.module_name.empty()) {
                dst.module_name = std::move(sym.module_name);
            }
            if (dst.library_name.empty() && !sym.library_name.empty()) {
                dst.library_name = std::move(sym.library_name);
            }
        } else {
            merged.push_back(std::move(sym));
        }
    }
    symbols = std::move(merged);
}

[[nodiscard]] Result<void> parse_c13_module_lines(
    std::span<const std::uint8_t> c13_bytes,
    const PdbNamesTable* names_table,
    const SectionRvaTranslator& rva_translator,
    std::vector<PdbLineEntry>& out_lines) {
    struct SubsectionSlice {
        std::uint32_t kind = 0;
        std::span<const std::uint8_t> payload{};
    };

    std::vector<SubsectionSlice> subsections{};
    std::size_t cursor = 0u;
    while (cursor < c13_bytes.size()) {
        if (c13_bytes.size() - cursor < 8u) {
            const bool all_zero = std::ranges::all_of(
                c13_bytes.subspan(cursor), [](std::uint8_t b) { return b == 0u; });
            if (all_zero) {
                break;
            }
            return make_error("Truncated C13 subsection header");
        }
        const std::uint32_t kind = load_u32_le(c13_bytes, cursor);
        const std::uint32_t length = load_u32_le(c13_bytes, cursor + 4u);
        cursor += 8u;
        if (length > c13_bytes.size() - cursor) {
            return make_error("Truncated C13 subsection payload");
        }
        if ((kind & kDebugSIgnoreFlag) == 0u) {
            subsections.push_back(SubsectionSlice{
                .kind = kind,
                .payload = c13_bytes.subspan(cursor, length),
            });
        }
        cursor += length;
        const std::size_t aligned_rem = (4u - (cursor & 3u)) & 3u;
        if (aligned_rem <= c13_bytes.size() - cursor) {
            cursor += aligned_rem;
        } else {
            cursor = c13_bytes.size();
        }
    }

    // Pass 1: collect DEBUG_S_FILECHKSMS offset -> resolved file path.
    std::unordered_map<std::uint32_t, std::string> file_by_chksum_offset{};
    for (const SubsectionSlice& sub : subsections) {
        if (sub.kind != kDebugSFileChksms) {
            continue;
        }
        std::size_t off = 0u;
        while (off < sub.payload.size()) {
            if (sub.payload.size() - off < 6u) {
                return make_error("Truncated DEBUG_S_FILECHKSMS entry header");
            }
            const auto entry_offset = static_cast<std::uint32_t>(off);
            const std::uint32_t name_ni = load_u32_le(sub.payload, off);
            const std::uint8_t chksum_len = sub.payload[off + 4u];
            if (6u + static_cast<std::size_t>(chksum_len) > sub.payload.size() - off) {
                return make_error("Truncated DEBUG_S_FILECHKSMS checksum bytes");
            }

            std::string file_path{};
            if (names_table != nullptr) {
                auto resolved_name = names_table->lookup(name_ni);
                if (!resolved_name) {
                    return std::unexpected(resolved_name.error());
                }
                file_path = std::move(*resolved_name);
            }
            file_by_chksum_offset[entry_offset] = std::move(file_path);

            const std::size_t raw_entry_len = 6u + static_cast<std::size_t>(chksum_len);
            const std::size_t aligned_len = (raw_entry_len + 3u) & ~std::size_t{3u};
            off = (aligned_len <= sub.payload.size() - off) ? (off + aligned_len) : sub.payload.size();
        }
    }

    // Pass 2: decode DEBUG_S_LINES fragments.
    for (const SubsectionSlice& sub : subsections) {
        if (sub.kind != kDebugSLines) {
            continue;
        }
        if (sub.payload.size() < 12u) {
            return make_error("Truncated DEBUG_S_LINES fragment header");
        }
        const std::uint32_t reloc_off = load_u32_le(sub.payload, 0u);
        const std::uint16_t reloc_seg = load_u16_le(sub.payload, 4u);
        const std::uint16_t line_flags = load_u16_le(sub.payload, 6u);
        const bool has_columns = (line_flags & kCvLinesHaveColumns) != 0u;

        const auto base_rva = rva_translator.to_rva(reloc_seg, reloc_off);
        std::size_t blk_cursor = 12u;
        while (blk_cursor < sub.payload.size()) {
            if (sub.payload.size() - blk_cursor < 12u) {
                return make_error("Truncated DEBUG_S_LINES block header");
            }
            const std::uint32_t off_file = load_u32_le(sub.payload, blk_cursor);
            const std::uint32_t num_lines = load_u32_le(sub.payload, blk_cursor + 4u);
            const std::uint32_t block_size = load_u32_le(sub.payload, blk_cursor + 8u);
            if (block_size < 12u || block_size > sub.payload.size() - blk_cursor) {
                return make_error("Invalid DEBUG_S_LINES block_size");
            }

            const std::uint64_t per_line_bytes = has_columns ? 12ull : 8ull;
            if (static_cast<std::uint64_t>(num_lines) > (block_size - 12u) / per_line_bytes) {
                return make_error("DEBUG_S_LINES num_lines exceeds block_size");
            }

            if (base_rva.has_value() && *base_rva != 0u) {
                std::string file_path{};
                if (const auto it = file_by_chksum_offset.find(off_file);
                    it != file_by_chksum_offset.end()) {
                    file_path = it->second;
                }
                const std::string file_name = extract_basename(file_path);

                const std::size_t lines_off = blk_cursor + 12u;
                const std::size_t cols_off =
                    lines_off + static_cast<std::size_t>(num_lines) * 8u;

                for (std::uint32_t i = 0; i < num_lines; ++i) {
                    const std::size_t entry_off = lines_off + static_cast<std::size_t>(i) * 8u;
                    const std::uint32_t code_delta = load_u32_le(sub.payload, entry_off);
                    const std::uint32_t packed_line = load_u32_le(sub.payload, entry_off + 4u);
                    const std::uint32_t line_start = packed_line & 0x00FF'FFFFu;
                    const bool is_stmt = (packed_line & 0x8000'0000u) != 0u;

                    // Skip compiler synthetic step-over / zero markers (0xFEEFEE, 0xF00F00).
                    if (line_start == 0u || line_start == 0x00FE'EFEEu || line_start == 0x00F0'0F00u) {
                        continue;
                    }

                    const auto line_rva = checked_add_u64(*base_rva, code_delta);
                    if (!line_rva.has_value()) {
                        continue;
                    }

                    std::uint32_t col_start = 0u;
                    if (has_columns) {
                        col_start = load_u16_le(
                            sub.payload, cols_off + static_cast<std::size_t>(i) * 4u);
                    }

                    out_lines.push_back(PdbLineEntry{
                        .relative_address = *line_rva,
                        .file_path = file_path,
                        .file_name = file_name,
                        .line = line_start,
                        .column = col_start,
                        .is_stmt = is_stmt,
                    });
                }
            }

            blk_cursor += block_size;
        }
    }

    return {};
}

} // namespace

bool has_msf7_signature(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < kMsf7Magic.size()) {
        return false;
    }
    return std::equal(kMsf7Magic.begin(), kMsf7Magic.end(), bytes.begin());
}

Result<PdbIdentity> read_pdb_identity(std::span<const std::uint8_t> bytes) {
    auto msf = MsfMemoryReader::open(bytes);
    if (!msf) {
        return std::unexpected(msf.error());
    }
    if (!msf->has_stream(1u) || msf->stream_size(1u) < 28u) {
        return make_error("PDB Stream 1 (PdbInfo) is absent or truncated");
    }

    auto s1_hdr = msf->read_stream_prefix(1u, 28u);
    if (!s1_hdr) {
        return std::unexpected(s1_hdr.error());
    }

    PdbIdentity id{};
    id.version = load_u32_le(*s1_hdr, 0u);
    id.signature = load_u32_le(*s1_hdr, 4u);
    id.info_age = load_u32_le(*s1_hdr, 8u);
    std::copy_n(s1_hdr->data() + 12u, 16u, id.guid.data());

    if (msf->has_stream(3u) && msf->stream_size(3u) >= 12u) {
        if (auto s3_hdr = msf->read_stream_prefix(3u, 12u); s3_hdr.has_value()) {
            id.dbi_age = load_u32_le(*s3_hdr, 8u);
        }
    }

    return id;
}

Result<PdbIdentity> read_pdb_identity(const std::filesystem::path& path) {
    std::error_code ec;
    const auto raw_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return make_error("Unable to stat PDB file: " + path.string());
    }
    const auto file_size = static_cast<std::uint64_t>(raw_size);

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return make_error("Unable to open PDB file: " + path.string());
    }

    std::array<std::uint8_t, kMsf7SuperBlockSize> sb_bytes{};
    if (!file.read(reinterpret_cast<char*>(sb_bytes.data()),
                   static_cast<std::streamsize>(sb_bytes.size()))) {
        return make_error("Failed reading MSF 7.00 SuperBlock from: " + path.string());
    }

    auto sb = parse_msf7_superblock(sb_bytes, file_size);
    if (!sb) {
        return std::unexpected(sb.error());
    }

    const std::size_t num_dir_blocks = static_cast<std::size_t>(
        (static_cast<std::uint64_t>(sb->num_directory_bytes) + sb->block_size - 1ull) /
        sb->block_size);
    const std::uint64_t block_map_off =
        static_cast<std::uint64_t>(sb->block_map_addr) * sb->block_size;

    std::vector<std::uint8_t> dir_map_bytes(num_dir_blocks * 4u);
    file.seekg(static_cast<std::streamoff>(block_map_off), std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(dir_map_bytes.data()),
                   static_cast<std::streamsize>(dir_map_bytes.size()))) {
        return make_error("Failed reading MSF 7.00 directory block map");
    }

    std::vector<std::uint8_t> dir_bytes(sb->num_directory_bytes);
    std::size_t copied = 0u;
    for (std::size_t i = 0; i < num_dir_blocks; ++i) {
        const std::uint32_t blk = load_u32_le(dir_map_bytes, i * 4u);
        if (blk == 0u || blk >= sb->num_blocks) {
            return make_error("MSF 7.00 directory block index out of bounds");
        }
        const std::size_t chunk =
            std::min<std::size_t>(sb->block_size, dir_bytes.size() - copied);
        file.seekg(
            static_cast<std::streamoff>(static_cast<std::uint64_t>(blk) * sb->block_size),
            std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(dir_bytes.data() + copied),
                       static_cast<std::streamsize>(chunk))) {
            return make_error("Failed reading MSF 7.00 directory block");
        }
        copied += chunk;
    }

    auto dir = parse_msf7_directory_bytes(*sb, dir_bytes);
    if (!dir) {
        return std::unexpected(dir.error());
    }

    if (dir->streams.size() < 2u || !dir->streams[1u].present ||
        dir->streams[1u].byte_size < 28u || dir->streams[1u].block_count == 0u) {
        return make_error("PDB Stream 1 (PdbInfo) is absent or truncated");
    }

    const auto read_prefix_from_file =
        [&](const MsfStreamEntry& entry, std::size_t count) -> Result<std::vector<std::uint8_t>> {
        std::vector<std::uint8_t> buf(count);
        std::size_t pos = 0u;
        for (std::size_t i = 0; i < entry.block_count && pos < count; ++i) {
            const std::uint32_t blk = dir->block_indices[entry.first_block_index + i];
            const std::size_t chunk = std::min<std::size_t>(sb->block_size, count - pos);
            file.seekg(
                static_cast<std::streamoff>(static_cast<std::uint64_t>(blk) * sb->block_size),
                std::ios::beg);
            if (!file.read(reinterpret_cast<char*>(buf.data() + pos),
                           static_cast<std::streamsize>(chunk))) {
                return make_error("Failed reading PDB header stream block");
            }
            pos += chunk;
        }
        return buf;
    };

    auto s1_hdr = read_prefix_from_file(dir->streams[1u], 28u);
    if (!s1_hdr) {
        return std::unexpected(s1_hdr.error());
    }

    PdbIdentity id{};
    id.version = load_u32_le(*s1_hdr, 0u);
    id.signature = load_u32_le(*s1_hdr, 4u);
    id.info_age = load_u32_le(*s1_hdr, 8u);
    std::copy_n(s1_hdr->data() + 12u, 16u, id.guid.data());

    if (dir->streams.size() >= 4u && dir->streams[3u].present &&
        dir->streams[3u].byte_size >= 12u && dir->streams[3u].block_count > 0u) {
        if (auto s3_hdr = read_prefix_from_file(dir->streams[3u], 12u); s3_hdr.has_value()) {
            id.dbi_age = load_u32_le(*s3_hdr, 8u);
        }
    }

    return id;
}

Result<PdbDebugData> parse_pdb_bytes(std::span<const std::uint8_t> bytes,
                                     std::span<const Section> fallback_pe_sections,
                                     std::uint64_t fallback_image_base) {
    auto msf = MsfMemoryReader::open(bytes);
    if (!msf) {
        return std::unexpected(msf.error());
    }

    // 1. Stream 1: PDB Info + Named Stream Map (`/names`).
    auto s1_bytes = msf->read_stream(1u);
    if (!s1_bytes) {
        return std::unexpected(s1_bytes.error());
    }
    auto pdb_info = parse_pdb_info_stream(*s1_bytes);
    if (!pdb_info) {
        return std::unexpected(pdb_info.error());
    }

    PdbDebugData result{};
    result.identity = pdb_info->identity;

    std::optional<PdbNamesTable> names_table{};
    if (pdb_info->names_stream_index.has_value()) {
        const std::uint32_t names_idx = *pdb_info->names_stream_index;
        if (names_idx == 0u || !msf->has_stream(names_idx)) {
            return make_error("PDB Named Stream Map references invalid /names stream index");
        }
        auto names_raw = msf->read_stream(names_idx);
        if (!names_raw) {
            return std::unexpected(names_raw.error());
        }
        if (!names_raw->empty()) {
            auto parsed_names = PdbNamesTable::parse(*names_raw);
            if (!parsed_names) {
                return std::unexpected(parsed_names.error());
            }
            names_table = std::move(*parsed_names);
        }
    }

    // 2. Stream 2: CodeView TPI types.
    TpiTable tpi{};
    if (msf->has_stream(2u) && msf->stream_size(2u) > 0u) {
        auto s2_bytes = msf->read_stream(2u);
        if (!s2_bytes) {
            return std::unexpected(s2_bytes.error());
        }
        auto parsed_tpi = TpiTable::parse(*s2_bytes);
        if (!parsed_tpi) {
            return std::unexpected(parsed_tpi.error());
        }
        tpi = std::move(*parsed_tpi);
        if (auto layout_res = tpi.populate_layouts(result.types, result.enums); !layout_res) {
            return std::unexpected(layout_res.error());
        }
    }

    // 3. Stream 3: DBI header, Optional Debug Header (section headers + OMAP), ModInfo, symbols & C13 lines.
    if (!msf->has_stream(3u) || msf->stream_size(3u) == 0u) {
        return result;
    }

    auto s3_bytes = msf->read_stream(3u);
    if (!s3_bytes) {
        return std::unexpected(s3_bytes.error());
    }
    if (s3_bytes->size() < 64u) {
        return make_error("PDB DBI stream (Stream 3) is smaller than 64-byte DbiStreamHeader");
    }

    const std::span<const std::uint8_t> dbi = *s3_bytes;
    result.identity.dbi_age = load_u32_le(dbi, 8u);
    const std::uint16_t sym_record_stream = load_u16_le(dbi, 20u);
    const auto mod_info_size = static_cast<std::int32_t>(load_u32_le(dbi, 24u));
    const auto sec_contr_size = static_cast<std::int32_t>(load_u32_le(dbi, 28u));
    const auto sec_map_size = static_cast<std::int32_t>(load_u32_le(dbi, 32u));
    const auto src_info_size = static_cast<std::int32_t>(load_u32_le(dbi, 36u));
    const auto ts_map_size = static_cast<std::int32_t>(load_u32_le(dbi, 40u));
    const auto opt_dbg_hdr_size = static_cast<std::int32_t>(load_u32_le(dbi, 48u));
    const auto ec_substream_size = static_cast<std::int32_t>(load_u32_le(dbi, 52u));
    result.machine = load_u16_le(dbi, 58u);

    if (mod_info_size < 0 || sec_contr_size < 0 || sec_map_size < 0 || src_info_size < 0 ||
        ts_map_size < 0 || opt_dbg_hdr_size < 0 || ec_substream_size < 0) {
        return make_error("PDB DbiStreamHeader contains negative substream size");
    }

    const std::uint64_t substreams_total =
        64ull + static_cast<std::uint64_t>(mod_info_size) +
        static_cast<std::uint64_t>(sec_contr_size) +
        static_cast<std::uint64_t>(sec_map_size) +
        static_cast<std::uint64_t>(src_info_size) +
        static_cast<std::uint64_t>(ts_map_size) +
        static_cast<std::uint64_t>(ec_substream_size) +
        static_cast<std::uint64_t>(opt_dbg_hdr_size);
    if (substreams_total > dbi.size()) {
        return make_error("PDB DBI substreams extend past end of Stream 3");
    }

    const std::size_t mod_info_off = 64u;
    const std::size_t opt_dbg_off = static_cast<std::size_t>(
        substreams_total - static_cast<std::uint64_t>(opt_dbg_hdr_size));

    const auto read_opt_dbg_stream_idx = [&](std::size_t slot) noexcept -> std::uint16_t {
        if (static_cast<std::size_t>(opt_dbg_hdr_size) < (slot + 1u) * 2u) {
            return kInvalidStreamIndex16;
        }
        return load_u16_le(dbi, opt_dbg_off + slot * 2u);
    };

    const std::uint16_t omap_from_src_idx = read_opt_dbg_stream_idx(4u);
    const std::uint16_t section_hdr_idx = read_opt_dbg_stream_idx(5u);
    const std::uint16_t section_hdr_orig_idx = read_opt_dbg_stream_idx(10u);

    std::vector<std::uint64_t> section_hdr_rvas{};
    if (section_hdr_idx != 0u && section_hdr_idx != kInvalidStreamIndex16) {
        auto sh_bytes = msf->read_stream(section_hdr_idx);
        if (!sh_bytes) {
            return std::unexpected(sh_bytes.error());
        }
        auto sh_rvas = SectionRvaTranslator::parse_section_header_stream(*sh_bytes);
        if (!sh_rvas) {
            return std::unexpected(sh_rvas.error());
        }
        section_hdr_rvas = std::move(*sh_rvas);
    }

    std::vector<std::uint64_t> section_hdr_orig_rvas{};
    if (section_hdr_orig_idx != 0u && section_hdr_orig_idx != kInvalidStreamIndex16) {
        auto sh_orig_bytes = msf->read_stream(section_hdr_orig_idx);
        if (!sh_orig_bytes) {
            return std::unexpected(sh_orig_bytes.error());
        }
        auto orig_rvas = SectionRvaTranslator::parse_section_header_stream(*sh_orig_bytes);
        if (!orig_rvas) {
            return std::unexpected(orig_rvas.error());
        }
        section_hdr_orig_rvas = std::move(*orig_rvas);
    }

    std::vector<OmapEntry> omap_from_src{};
    if (omap_from_src_idx != 0u && omap_from_src_idx != kInvalidStreamIndex16) {
        auto omap_bytes = msf->read_stream(omap_from_src_idx);
        if (!omap_bytes) {
            return std::unexpected(omap_bytes.error());
        }
        auto parsed_omap = SectionRvaTranslator::parse_omap_stream(*omap_bytes);
        if (!parsed_omap) {
            return std::unexpected(parsed_omap.error());
        }
        omap_from_src = std::move(*parsed_omap);
    }

    const SectionRvaTranslator rva_translator = SectionRvaTranslator::from_streams_or_fallback(
        std::move(section_hdr_rvas),
        std::move(section_hdr_orig_rvas),
        std::move(omap_from_src),
        fallback_pe_sections,
        fallback_image_base);

    // 4. Global / Public Symbol Record Stream (`SymRecordStream`).
    if (sym_record_stream != 0u && sym_record_stream != kInvalidStreamIndex16) {
        auto sym_raw = msf->read_stream(sym_record_stream);
        if (!sym_raw) {
            return std::unexpected(sym_raw.error());
        }
        if (auto sym_res = parse_cv_symbol_stream(
                *sym_raw, rva_translator, tpi, {}, {}, result.symbols);
            !sym_res) {
            return std::unexpected(sym_res.error());
        }
    }

    // 5. Module Info Substream -> per-module symbol streams and C13 line info.
    const std::span<const std::uint8_t> mod_sub =
        dbi.subspan(mod_info_off, static_cast<std::size_t>(mod_info_size));
    std::size_t mod_cursor = 0u;
    while (mod_cursor < mod_sub.size()) {
        if (mod_sub.size() - mod_cursor < 64u) {
            return make_error("Truncated DBI ModInfo record header");
        }

        const std::uint16_t mod_stream_idx = load_u16_le(mod_sub, mod_cursor + 34u);
        const std::uint32_t sym_byte_size = load_u32_le(mod_sub, mod_cursor + 36u);
        const std::uint32_t c11_byte_size = load_u32_le(mod_sub, mod_cursor + 40u);
        const std::uint32_t c13_byte_size = load_u32_le(mod_sub, mod_cursor + 44u);

        mod_cursor += 64u;
        const auto mod_name = read_cstr(mod_sub, mod_cursor);
        if (!mod_name) {
            return std::unexpected(mod_name.error());
        }
        const auto obj_name = read_cstr(mod_sub, mod_cursor);
        if (!obj_name) {
            return std::unexpected(obj_name.error());
        }
        mod_cursor = (mod_cursor + 3u) & ~std::size_t{3u};
        if (mod_cursor > mod_sub.size()) {
            mod_cursor = mod_sub.size();
        }

        if (mod_stream_idx == 0u || mod_stream_idx == kInvalidStreamIndex16) {
            continue;
        }

        auto mod_raw = msf->read_stream(mod_stream_idx);
        if (!mod_raw) {
            return std::unexpected(mod_raw.error());
        }

        const std::uint64_t required_mod_bytes =
            static_cast<std::uint64_t>(sym_byte_size) +
            static_cast<std::uint64_t>(c11_byte_size) +
            static_cast<std::uint64_t>(c13_byte_size);
        if (required_mod_bytes > mod_raw->size()) {
            return make_error("DBI ModInfo sym/c11/c13 byte sizes exceed module stream length");
        }

        const std::string lib_name =
            has_archive_library_extension(*obj_name) ? *obj_name : std::string{};

        if (sym_byte_size >= 4u) {
            const std::uint32_t cv_sig = load_u32_le(*mod_raw, 0u);
            if (cv_sig == kCvSignatureC13 && sym_byte_size > 4u) {
                const auto mod_syms = std::span<const std::uint8_t>(*mod_raw).subspan(
                    4u, sym_byte_size - 4u);
                if (auto sym_res = parse_cv_symbol_stream(
                        mod_syms, rva_translator, tpi, *mod_name, lib_name, result.symbols);
                    !sym_res) {
                    return std::unexpected(sym_res.error());
                }
            }
        }

        if (c13_byte_size > 0u) {
            const std::size_t c13_off =
                static_cast<std::size_t>(sym_byte_size) + static_cast<std::size_t>(c11_byte_size);
            const auto c13_span =
                std::span<const std::uint8_t>(*mod_raw).subspan(c13_off, c13_byte_size);
            const PdbNamesTable* names_ptr = names_table.has_value() ? &*names_table : nullptr;
            if (auto line_res = parse_c13_module_lines(
                    c13_span, names_ptr, rva_translator, result.lines);
                !line_res) {
                return std::unexpected(line_res.error());
            }
        }
    }

    merge_and_deduplicate_pdb_symbols(result.symbols);

    std::ranges::sort(result.lines, [](const PdbLineEntry& a, const PdbLineEntry& b) {
        if (a.relative_address != b.relative_address) {
            return a.relative_address < b.relative_address;
        }
        if (a.line != b.line) {
            return a.line < b.line;
        }
        return a.column < b.column;
    });
    const auto dup_lines = std::ranges::unique(
        result.lines, [](const PdbLineEntry& a, const PdbLineEntry& b) {
            return a.relative_address == b.relative_address && a.line == b.line &&
                   a.column == b.column && a.file_path == b.file_path;
        });
    result.lines.erase(dup_lines.begin(), dup_lines.end());

    return result;
}

Result<PdbDebugData> parse_pdb_file(const std::filesystem::path& path,
                                    std::span<const Section> fallback_pe_sections,
                                    std::uint64_t fallback_image_base) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return make_error("PDB file does not exist: " + path.string());
    }
    const auto raw_size = std::filesystem::file_size(path, ec);
    if (ec || raw_size > kMaxPdbFileBytes) {
        return make_error("Unable to read PDB file or file exceeds safety cap: " + path.string());
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return make_error("Failed to open PDB file: " + path.string());
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(raw_size));
    if (!bytes.empty() &&
        !file.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()))) {
        return make_error("Failed reading PDB file bytes: " + path.string());
    }

    return parse_pdb_bytes(bytes, fallback_pe_sections, fallback_image_base);
}

} // namespace peelf
