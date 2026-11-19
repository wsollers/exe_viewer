// BSD 2-Clause License -- Clean-room unit & adversarial tests for peelf/pdb.hpp (WU-34).

#include <peelf/binary_image.hpp>
#include <peelf/pdb.hpp>

#include "analysis/structure_interpreter.hpp"
#include "symbols/debug_symbols.hpp"
#include "test_temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class ByteWriter {
public:
    void u8(std::uint8_t v) { buf_.push_back(v); }

    void u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    }

    void u32(std::uint32_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
        buf_.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
    }

    void i32(std::int32_t v) { u32(static_cast<std::uint32_t>(v)); }

    void u64(std::uint64_t v) {
        u32(static_cast<std::uint32_t>(v & 0xFFFF'FFFFull));
        u32(static_cast<std::uint32_t>((v >> 32u) & 0xFFFF'FFFFull));
    }

    void bytes(std::span<const std::uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    void cstr(std::string_view s) {
        buf_.insert(buf_.end(), s.begin(), s.end());
        buf_.push_back(0u);
    }

    void fixed_ascii(std::string_view s, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) {
            buf_.push_back(i < s.size() ? static_cast<std::uint8_t>(s[i]) : 0u);
        }
    }

    void align4_zero() {
        while ((buf_.size() & 3u) != 0u) {
            buf_.push_back(0u);
        }
    }

    void align4_cv_pad() {
        const std::size_t rem = (4u - (buf_.size() & 3u)) & 3u;
        for (std::size_t pad = rem; pad > 0u; --pad) {
            buf_.push_back(static_cast<std::uint8_t>(0xF0u + pad));
        }
    }

    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return buf_; }
    [[nodiscard]] std::vector<std::uint8_t> take() noexcept { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_{};
};

void write_u16_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void write_u32_at(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFFu);
    buf[off + 1u] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    buf[off + 2u] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    buf[off + 3u] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

[[nodiscard]] std::vector<std::uint8_t> make_cv_record(std::uint16_t kind,
                                                       std::span<const std::uint8_t> body,
                                                       bool pad_to_4 = true) {
    ByteWriter rec{};
    rec.u16(0u); // placeholder for reclen
    rec.u16(kind);
    rec.bytes(body);
    if (pad_to_4) {
        while ((rec.size() & 3u) != 0u) {
            rec.u8(0u);
        }
    }
    auto out = rec.take();
    write_u16_at(out, 0u, static_cast<std::uint16_t>(out.size() - 2u));
    return out;
}

class Msf7Builder {
public:
    explicit Msf7Builder(std::uint32_t block_size = 4096u) : block_size_(block_size) {}

    std::uint32_t set_stream(std::size_t index, std::vector<std::uint8_t> content) {
        if (streams_.size() <= index) {
            streams_.resize(index + 1u);
        }
        streams_[index] = StreamSpec{.is_nil = false, .bytes = std::move(content)};
        return static_cast<std::uint32_t>(index);
    }

    std::uint32_t add_stream(std::vector<std::uint8_t> content) {
        streams_.push_back(StreamSpec{.is_nil = false, .bytes = std::move(content)});
        return static_cast<std::uint32_t>(streams_.size() - 1u);
    }

    std::uint32_t add_nil_stream() {
        streams_.push_back(StreamSpec{.is_nil = true, .bytes = {}});
        return static_cast<std::uint32_t>(streams_.size() - 1u);
    }

    // Builds an MSF 7.00 image. When `interleave_blocks` is true, stream blocks are
    // allocated round-robin across streams so multi-block streams are non-contiguous.
    [[nodiscard]] std::vector<std::uint8_t> build(bool interleave_blocks = true) const {
        // Block 0: SuperBlock
        // Block 1 & 2: FreeBlockMap 1 & 2
        std::uint32_t next_block = 3u;
        std::vector<std::vector<std::uint32_t>> stream_blocks(streams_.size());
        std::vector<std::size_t> needed_blocks(streams_.size(), 0u);
        std::size_t max_blocks_in_any_stream = 0u;

        for (std::size_t i = 0; i < streams_.size(); ++i) {
            if (!streams_[i].is_nil && !streams_[i].bytes.empty()) {
                needed_blocks[i] =
                    (streams_[i].bytes.size() + block_size_ - 1u) / block_size_;
                max_blocks_in_any_stream =
                    std::max(max_blocks_in_any_stream, needed_blocks[i]);
            }
        }

        if (interleave_blocks) {
            for (std::size_t blk_idx = 0; blk_idx < max_blocks_in_any_stream; ++blk_idx) {
                for (std::size_t s = 0; s < streams_.size(); ++s) {
                    if (blk_idx < needed_blocks[s]) {
                        stream_blocks[s].push_back(next_block++);
                    }
                }
            }
        } else {
            for (std::size_t s = 0; s < streams_.size(); ++s) {
                for (std::size_t blk_idx = 0; blk_idx < needed_blocks[s]; ++blk_idx) {
                    stream_blocks[s].push_back(next_block++);
                }
            }
        }

        ByteWriter dir{};
        dir.u32(static_cast<std::uint32_t>(streams_.size()));
        for (const auto& st : streams_) {
            dir.u32(st.is_nil ? 0xFFFF'FFFFu : static_cast<std::uint32_t>(st.bytes.size()));
        }
        for (std::size_t s = 0; s < streams_.size(); ++s) {
            for (const std::uint32_t blk : stream_blocks[s]) {
                dir.u32(blk);
            }
        }

        const auto dir_bytes = dir.take();
        const std::size_t num_dir_blocks =
            std::max<std::size_t>(1u, (dir_bytes.size() + block_size_ - 1u) / block_size_);
        std::vector<std::uint32_t> dir_blocks;
        dir_blocks.reserve(num_dir_blocks);
        for (std::size_t i = 0; i < num_dir_blocks; ++i) {
            dir_blocks.push_back(next_block++);
        }

        const std::uint32_t block_map_addr = next_block++;
        const std::uint32_t total_blocks = next_block;

        std::vector<std::uint8_t> image(
            static_cast<std::size_t>(total_blocks) * block_size_, 0u);

        static constexpr std::array<char, 32> kMagic = {
            'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ',
            'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1A', 'D', 'S', '\0', '\0', '\0',
        };
        std::memcpy(image.data(), kMagic.data(), kMagic.size());
        write_u32_at(image, 32u, block_size_);
        write_u32_at(image, 36u, 1u);
        write_u32_at(image, 40u, total_blocks);
        write_u32_at(image, 44u, static_cast<std::uint32_t>(dir_bytes.size()));
        write_u32_at(image, 48u, 0u);
        write_u32_at(image, 52u, block_map_addr);

        // Write stream payloads into their assigned blocks.
        for (std::size_t s = 0; s < streams_.size(); ++s) {
            if (streams_[s].is_nil || streams_[s].bytes.empty()) {
                continue;
            }
            std::size_t copied = 0u;
            for (const std::uint32_t blk : stream_blocks[s]) {
                const std::size_t chunk =
                    std::min<std::size_t>(block_size_, streams_[s].bytes.size() - copied);
                std::memcpy(image.data() + static_cast<std::size_t>(blk) * block_size_,
                            streams_[s].bytes.data() + copied,
                            chunk);
                copied += chunk;
            }
        }

        // Write Stream Directory blocks.
        {
            std::size_t copied = 0u;
            for (const std::uint32_t blk : dir_blocks) {
                const std::size_t chunk =
                    std::min<std::size_t>(block_size_, dir_bytes.size() - copied);
                std::memcpy(image.data() + static_cast<std::size_t>(blk) * block_size_,
                            dir_bytes.data() + copied,
                            chunk);
                copied += chunk;
            }
        }

        // Write BlockMap table.
        for (std::size_t i = 0; i < dir_blocks.size(); ++i) {
            write_u32_at(image,
                         static_cast<std::size_t>(block_map_addr) * block_size_ + i * 4u,
                         dir_blocks[i]);
        }

        return image;
    }

private:
    struct StreamSpec {
        bool is_nil = false;
        std::vector<std::uint8_t> bytes{};
    };

    std::uint32_t block_size_ = 4096u;
    std::vector<StreamSpec> streams_{4u};
};

struct NamesTableBuild {
    std::vector<std::uint8_t> stream_bytes{};
    std::vector<std::uint32_t> name_offsets{};
};

[[nodiscard]] NamesTableBuild make_names_stream(std::span<const std::string_view> strings) {
    ByteWriter pool{};
    pool.u8(0u); // Offset 0 = empty string

    std::vector<std::uint32_t> offsets{};
    offsets.reserve(strings.size());
    for (const std::string_view s : strings) {
        offsets.push_back(static_cast<std::uint32_t>(pool.size()));
        pool.cstr(s);
    }

    ByteWriter st{};
    st.u32(0xEFFEEFFEu); // Signature
    st.u32(1u);          // HashVersion
    st.u32(static_cast<std::uint32_t>(pool.size()));
    st.bytes(pool.data());
    st.u32(static_cast<std::uint32_t>(strings.size())); // Bucket count
    for (const std::uint32_t off : offsets) {
        st.u32(off);
    }

    return NamesTableBuild{
        .stream_bytes = st.take(),
        .name_offsets = std::move(offsets),
    };
}

[[nodiscard]] std::vector<std::uint8_t> make_pdb_info_stream(
    const std::array<std::uint8_t, 16>& guid,
    std::uint32_t age,
    std::optional<std::uint32_t> names_stream_index = std::nullopt) {
    ByteWriter st{};
    st.u32(20000404u);   // VC70
    st.u32(0x66001234u); // Signature
    st.u32(age);
    st.bytes(guid);

    if (!names_stream_index.has_value()) {
        st.u32(0u); // cbNames = 0
        st.u32(0u); // count = 0
        st.u32(0u); // capacity = 0
        st.u32(0u); // present words = 0
        st.u32(0u); // deleted words = 0
        return st.take();
    }

    constexpr std::string_view kNamesKey = "/names";
    st.u32(static_cast<std::uint32_t>(kNamesKey.size() + 1u));
    st.cstr(kNamesKey);
    st.u32(1u); // count = 1
    st.u32(1u); // capacity = 1
    st.u32(1u); // present bit vector words = 1
    st.u32(1u); // bit 0 set
    st.u32(0u); // deleted bit vector words = 0
    st.u32(0u); // key offset 0 ("/names")
    st.u32(*names_stream_index);
    return st.take();
}

[[nodiscard]] std::vector<std::uint8_t> make_tpi_stream(
    std::span<const std::vector<std::uint8_t>> type_records) {
    std::uint32_t record_bytes = 0u;
    for (const auto& rec : type_records) {
        record_bytes += static_cast<std::uint32_t>(rec.size());
    }

    ByteWriter st{};
    st.u32(20040203u); // V80
    st.u32(56u);       // HeaderSize
    st.u32(0x1000u);   // TypeIndexBegin
    st.u32(0x1000u + static_cast<std::uint32_t>(type_records.size())); // TypeIndexEnd
    st.u32(record_bytes);
    st.u16(0xFFFFu); // HashStreamIndex (nil)
    st.u16(0xFFFFu); // HashAuxStreamIndex (nil)
    st.u32(4u);      // HashKeySize
    st.u32(0x3FFFFu);
    st.i32(0);
    st.u32(0u);
    st.i32(0);
    st.u32(0u);
    st.i32(0);
    st.u32(0u);

    for (const auto& rec : type_records) {
        st.bytes(rec);
    }
    return st.take();
}

[[nodiscard]] std::vector<std::uint8_t> make_image_section_header(std::string_view name,
                                                                  std::uint32_t virtual_size,
                                                                  std::uint32_t virtual_address,
                                                                  std::uint32_t raw_size = 0x1000u,
                                                                  std::uint32_t raw_ptr = 0x400u,
                                                                  std::uint32_t characteristics = 0x60000020u) {
    ByteWriter sh{};
    sh.fixed_ascii(name, 8u);
    sh.u32(virtual_size);
    sh.u32(virtual_address);
    sh.u32(raw_size);
    sh.u32(raw_ptr);
    sh.u32(0u);
    sh.u32(0u);
    sh.u16(0u);
    sh.u16(0u);
    sh.u32(characteristics);
    return sh.take();
}

struct ModInfoSpec {
    std::uint16_t stream_index = 0xFFFFu;
    std::uint32_t sym_byte_size = 4u;
    std::uint32_t c13_byte_size = 0u;
    std::string module_name;
    std::string obj_file_name;
};

[[nodiscard]] std::vector<std::uint8_t> make_dbi_stream(
    std::uint32_t age,
    std::uint16_t sym_record_stream,
    std::span<const ModInfoSpec> modules,
    std::uint16_t section_hdr_stream = 0xFFFFu,
    std::uint16_t omap_from_src_stream = 0xFFFFu) {
    ByteWriter mod_sub{};
    for (const ModInfoSpec& m : modules) {
        mod_sub.u32(0u);
        // SectionContrEntry (28 bytes)
        for (int i = 0; i < 7; ++i) {
            mod_sub.u32(0u);
        }
        mod_sub.u16(0u); // flags
        mod_sub.u16(m.stream_index);
        mod_sub.u32(m.sym_byte_size);
        mod_sub.u32(0u); // c11_byte_size
        mod_sub.u32(m.c13_byte_size);
        mod_sub.u16(0u); // source_file_count
        mod_sub.u16(0u); // padding
        mod_sub.u32(0u); // unused2
        mod_sub.u32(0u); // source_file_name_index
        mod_sub.u32(0u); // pdb_file_path_name_index
        mod_sub.cstr(m.module_name);
        mod_sub.cstr(m.obj_file_name);
        mod_sub.align4_zero();
    }

    ByteWriter opt_dbg{};
    opt_dbg.u16(0xFFFFu);            // [0] FPO
    opt_dbg.u16(0xFFFFu);            // [1] Exception
    opt_dbg.u16(0xFFFFu);            // [2] Fixup
    opt_dbg.u16(0xFFFFu);            // [3] OmapToSrc
    opt_dbg.u16(omap_from_src_stream); // [4] OmapFromSrc
    opt_dbg.u16(section_hdr_stream); // [5] SectionHdr
    for (int i = 6; i < 11; ++i) {
        opt_dbg.u16(0xFFFFu);
    }

    // Minimal EC substream (non-zero to exercise EC-before-DbgHdr ordering).
    ByteWriter ec_sub{};
    ec_sub.u32(0xEFFEEFFEu);
    ec_sub.u32(1u);
    ec_sub.u32(1u);
    ec_sub.u8(0u);
    ec_sub.align4_zero();

    ByteWriter dbi{};
    dbi.i32(-1);        // VersionSignature
    dbi.u32(19990903u); // VersionHeader (V70)
    dbi.u32(age);
    dbi.u16(0xFFFFu);   // GlobalStreamIndex
    dbi.u16(0x8E0Bu);   // BuildNumber
    dbi.u16(0xFFFFu);   // PublicStreamIndex
    dbi.u16(0u);        // PdbDllVersion
    dbi.u16(sym_record_stream);
    dbi.u16(0u);        // PdbDllRbld
    dbi.i32(static_cast<std::int32_t>(mod_sub.size())); // [24] ModInfoSize
    dbi.i32(0);         // [28] SectionContributionSize
    dbi.i32(0);         // [32] SectionMapSize
    dbi.i32(0);         // [36] SourceInfoSize
    dbi.i32(0);         // [40] TypeServerSize
    dbi.u32(0u);        // [44] MFCTypeServerIndex
    dbi.i32(static_cast<std::int32_t>(opt_dbg.size())); // [48] OptionalDbgHeaderSize
    dbi.i32(static_cast<std::int32_t>(ec_sub.size()));  // [52] ECSubstreamSize
    dbi.u16(0u);        // [56] Flags
    dbi.u16(0x8664u);   // [58] Machine = AMD64
    dbi.u32(0u);        // [60] Padding

    dbi.bytes(mod_sub.data());
    dbi.bytes(ec_sub.data());
    dbi.bytes(opt_dbg.data());
    return dbi.take();
}

[[nodiscard]] std::vector<std::uint8_t> make_pub32_sym(std::uint32_t pub_flags,
                                                       std::uint16_t seg,
                                                       std::uint32_t off,
                                                       std::string_view name) {
    ByteWriter b{};
    b.u32(pub_flags);
    b.u32(off);
    b.u16(seg);
    b.cstr(name);
    return make_cv_record(0x110Eu, b.data());
}

[[nodiscard]] std::vector<std::uint8_t> make_proc32_sym(std::uint16_t kind,
                                                        std::uint16_t seg,
                                                        std::uint32_t off,
                                                        std::uint32_t code_len,
                                                        std::uint32_t type_index,
                                                        std::string_view name) {
    ByteWriter b{};
    b.u32(0u); // pParent
    b.u32(0u); // pEnd
    b.u32(0u); // pNext
    b.u32(code_len);
    b.u32(0u); // DbgStart
    b.u32(code_len); // DbgEnd
    b.u32(type_index);
    b.u32(off);
    b.u16(seg);
    b.u8(0u); // flags
    b.cstr(name);
    return make_cv_record(kind, b.data());
}

[[nodiscard]] std::vector<std::uint8_t> make_data32_sym(std::uint16_t kind,
                                                        std::uint16_t seg,
                                                        std::uint32_t off,
                                                        std::uint32_t type_index,
                                                        std::string_view name) {
    ByteWriter b{};
    b.u32(type_index);
    b.u32(off);
    b.u16(seg);
    b.cstr(name);
    return make_cv_record(kind, b.data());
}

[[nodiscard]] std::vector<std::uint8_t> make_pe64_with_rsds_and_text(
    const std::array<std::uint8_t, 16>& guid,
    std::uint32_t age,
    std::string_view pdb_name) {
    std::vector<std::uint8_t> buf(0x800u, 0u);
    buf[0] = 'M';
    buf[1] = 'Z';
    write_u32_at(buf, 0x3Cu, 0x80u);
    buf[0x80u] = 'P';
    buf[0x81u] = 'E';
    write_u16_at(buf, 0x84u, 0x8664u);
    write_u16_at(buf, 0x86u, 2u); // 2 sections (.text and .rdata)
    write_u16_at(buf, 0x94u, 0xF0u);
    write_u16_at(buf, 0x96u, 0x0022u);

    const std::size_t opt = 0x98u;
    write_u16_at(buf, opt + 0u, 0x020Bu);
    write_u32_at(buf, opt + 16u, 0x1020u); // AddressOfEntryPoint
    write_u32_at(buf, opt + 24u, 0x40000000u);
    write_u32_at(buf, opt + 28u, 0x00000001u); // ImageBase = 0x140000000
    write_u32_at(buf, opt + 32u, 0x1000u);
    write_u32_at(buf, opt + 36u, 0x200u);
    write_u32_at(buf, opt + 56u, 0x3000u); // SizeOfImage
    write_u32_at(buf, opt + 60u, 0x200u);  // SizeOfHeaders
    write_u32_at(buf, opt + 108u, 16u);
    // DataDirectory[6] = Debug at RVA 0x2000
    write_u32_at(buf, opt + 160u, 0x2000u);
    write_u32_at(buf, opt + 164u, 28u);

    // Section 1: .text @ RVA 0x1000, file 0x200..0x400
    const std::size_t sh1 = opt + 0xF0u;
    std::memcpy(buf.data() + sh1, ".text\0\0\0", 8u);
    write_u32_at(buf, sh1 + 8u, 0x200u);
    write_u32_at(buf, sh1 + 12u, 0x1000u);
    write_u32_at(buf, sh1 + 16u, 0x200u);
    write_u32_at(buf, sh1 + 20u, 0x200u);
    write_u32_at(buf, sh1 + 36u, 0x60000020u);

    // Section 2: .rdata @ RVA 0x2000, file 0x400..0x600
    const std::size_t sh2 = sh1 + 40u;
    std::memcpy(buf.data() + sh2, ".rdata\0\0", 8u);
    write_u32_at(buf, sh2 + 8u, 0x200u);
    write_u32_at(buf, sh2 + 12u, 0x2000u);
    write_u32_at(buf, sh2 + 16u, 0x200u);
    write_u32_at(buf, sh2 + 20u, 0x400u);
    write_u32_at(buf, sh2 + 36u, 0x40000040u);

    // Populate a deterministic `ret` + sample struct payload in .text / .rdata
    buf[0x220u] = 0xC3u; // RVA 0x1020

    // IMAGE_DEBUG_DIRECTORY at file 0x400 (RVA 0x2000)
    const std::size_t dbg = 0x400u;
    const auto rsds_len = static_cast<std::uint32_t>(24u + pdb_name.size() + 1u);
    write_u32_at(buf, dbg + 12u, 2u); // IMAGE_DEBUG_TYPE_CODEVIEW
    write_u32_at(buf, dbg + 16u, rsds_len);
    write_u32_at(buf, dbg + 20u, 0x2020u);
    write_u32_at(buf, dbg + 24u, 0x420u);

    const std::size_t rsds = 0x420u;
    std::memcpy(buf.data() + rsds, "RSDS", 4u);
    std::memcpy(buf.data() + rsds + 4u, guid.data(), guid.size());
    write_u32_at(buf, rsds + 20u, age);
    std::memcpy(buf.data() + rsds + 24u, pdb_name.data(), pdb_name.size());
    buf[rsds + 24u + pdb_name.size()] = 0u;
    return buf;
}

} // namespace

TEST(PdbParserTest, FragmentedMsf7StreamsAndNamedStrings) {
    const std::array<std::uint8_t, 16> kGuid = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    // Use 512-byte blocks and >160 dummy nil/empty streams so the Stream Directory
    // itself spans multiple blocks while stream payloads interleave across blocks.
    Msf7Builder msf(512u);
    for (int i = 0; i < 160; ++i) {
        (void)msf.add_nil_stream();
    }

    const std::array<std::string_view, 2> kFiles = {
        "C:\\repo\\src\\engine\\dispatcher.cpp",
        "/workspace/src/core/packet.cpp",
    };
    const auto names = make_names_stream(kFiles);
    const std::uint32_t names_idx = msf.add_stream(names.stream_bytes);

    ByteWriter sec_hdrs{};
    sec_hdrs.bytes(make_image_section_header(".text", 0x4000u, 0x1000u));
    const std::uint32_t sec_idx = msf.add_stream(sec_hdrs.take());

    // Build a multi-block SymRecordStream (> 1024 bytes) to exercise fragmented reassembly.
    ByteWriter sym_stream{};
    for (std::uint32_t i = 0; i < 36u; ++i) {
        const auto pub = make_pub32_sym(
            0x02u, 1u, 0x100u + i * 16u, "fragmented_symbol_" + std::to_string(i));
        sym_stream.bytes(pub);
    }
    const std::uint32_t sym_idx = msf.add_stream(sym_stream.take());

    msf.set_stream(1u, make_pdb_info_stream(kGuid, 5u, names_idx));
    msf.set_stream(2u, make_tpi_stream({}));
    msf.set_stream(
        3u,
        make_dbi_stream(
            4u, static_cast<std::uint16_t>(sym_idx), {}, static_cast<std::uint16_t>(sec_idx)));

    const auto pdb_bytes = msf.build(/*interleave_blocks=*/true);
    EXPECT_TRUE(peelf::has_msf7_signature(pdb_bytes));

    const auto id = peelf::read_pdb_identity(pdb_bytes);
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(id->guid, kGuid);
    EXPECT_EQ(id->info_age, 5u);
    ASSERT_TRUE(id->dbi_age.has_value());
    EXPECT_EQ(*id->dbi_age, 4u);

    const auto parsed = peelf::parse_pdb_bytes(pdb_bytes);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    EXPECT_EQ(parsed->identity.guid, kGuid);
    EXPECT_EQ(parsed->symbols.size(), 36u);
    EXPECT_EQ(parsed->symbols.front().name, "fragmented_symbol_0");
    EXPECT_EQ(parsed->symbols.front().relative_address, 0x1100u);
    EXPECT_TRUE(parsed->symbols.front().is_function);
}

TEST(PdbParserTest, ParsesCodeViewTypesStructsUnionsEnumsBitfieldsAndNumericLeaves) {
    std::vector<std::vector<std::uint8_t>> tpi_records{};
    const auto add_type = [&](std::uint16_t kind, const ByteWriter& body) -> std::uint32_t {
        const auto ti = static_cast<std::uint32_t>(0x1000u + tpi_records.size());
        tpi_records.push_back(make_cv_record(kind, body.data()));
        return ti;
    };

    // 0x1000: Forward-reference LF_STRUCTURE for PacketHeader (prop = 0x0080).
    {
        ByteWriter b{};
        b.u16(0u);
        b.u16(0x0080u); // CV_PROP_FWDREF
        b.u32(0u);
        b.u32(0u);
        b.u32(0u);
        b.u16(0u);
        b.cstr("PacketHeader");
        (void)add_type(0x1505u, b);
    }

    // 0x1001: LF_FIELDLIST for PacketHeader (magic: uint32_t @ 0, version: uint16_t @ 4).
    std::uint32_t packet_fields_ti = 0u;
    {
        ByteWriter fl{};
        fl.u16(0x150Du); // LF_MEMBER
        fl.u16(0x0003u); // public
        fl.u32(0x0075u); // T_UINT4
        fl.u16(0u);      // offset 0 (immediate)
        fl.cstr("magic");
        fl.align4_cv_pad();

        fl.u16(0x150Du); // LF_MEMBER
        fl.u16(0x0003u);
        fl.u32(0x0073u); // T_UINT2
        fl.u16(4u);      // offset 4
        fl.cstr("version");
        fl.align4_cv_pad();
        packet_fields_ti = add_type(0x1203u, fl);
    }

    // 0x1002: Full LF_STRUCTURE definition for PacketHeader (size = 8).
    const std::uint32_t packet_ti = [&] {
        ByteWriter b{};
        b.u16(2u);
        b.u16(0u);
        b.u32(packet_fields_ti);
        b.u32(0u);
        b.u32(0u);
        b.u16(8u);
        b.cstr("PacketHeader");
        return add_type(0x1505u, b);
    }();

    // 0x1003: LF_MODIFIER const char (`0x0070` = T_RCHAR).
    const std::uint32_t const_char_ti = [&] {
        ByteWriter b{};
        b.u32(0x0070u);
        b.u16(0x0001u); // const
        return add_type(0x1001u, b);
    }();

    // 0x1004: LF_POINTER 64-bit pointer to const char (mode = 6 << 5 = 0xC0, size = 8 << 13).
    const std::uint32_t const_char_ptr_ti = [&] {
        ByteWriter b{};
        b.u32(const_char_ti);
        b.u32((6u << 5u) | (8u << 13u));
        return add_type(0x1002u, b);
    }();

    // 0x1005: LF_ARRAY uint8_t[32] (size encoded via LF_USHORT 0x8002).
    const std::uint32_t byte_array_ti = [&] {
        ByteWriter b{};
        b.u32(0x0069u); // T_UINT1
        b.u32(0x0023u); // T_UQUAD index
        b.u16(0x8002u); // LF_USHORT
        b.u16(32u);
        b.u8(0u); // empty name
        return add_type(0x1503u, b);
    }();

    // 0x1006: LF_BITFIELD uint32_t : 5 @ bit 3.
    const std::uint32_t bitfield_ti = [&] {
        ByteWriter b{};
        b.u32(0x0075u); // T_UINT4
        b.u8(5u);       // length = 5 bits
        b.u8(3u);       // position = bit 3
        return add_type(0x1205u, b);
    }();

    // 0x1007: LF_ARGLIST (uint64_t, void*).
    const std::uint32_t arglist_ti = [&] {
        ByteWriter b{};
        b.u32(2u);
        b.u32(0x0077u); // T_UINT8
        b.u32(0x0603u); // 64-bit void*
        return add_type(0x1201u, b);
    }();

    // 0x1008: LF_PROCEDURE int32_t (uint64_t, void*) + 0x1009: LF_POINTER to procedure.
    const std::uint32_t proc_ti = [&] {
        ByteWriter b{};
        b.u32(0x0074u); // T_INT4
        b.u8(0u);
        b.u8(0u);
        b.u16(2u);
        b.u32(arglist_ti);
        return add_type(0x1008u, b);
    }();
    const std::uint32_t proc_ptr_ti = [&] {
        ByteWriter b{};
        b.u32(proc_ti);
        b.u32((6u << 5u) | (8u << 13u));
        return add_type(0x1002u, b);
    }();

    // 0x100A: LF_MFUNCTION + 0x100B: LF_POINTER to member function.
    const std::uint32_t mfunc_ti = [&] {
        ByteWriter b{};
        b.u32(0x0003u); // T_VOID
        b.u32(packet_ti);
        b.u32(0x0603u);
        b.u8(0u);
        b.u8(0u);
        b.u16(2u);
        b.u32(arglist_ti);
        b.i32(0);
        return add_type(0x1009u, b);
    }();
    const std::uint32_t mfunc_ptr_ti = [&] {
        ByteWriter b{};
        b.u32(mfunc_ti);
        b.u32((6u << 5u) | (8u << 13u));
        return add_type(0x1002u, b);
    }();

    // 0x100C: Continuation LF_FIELDLIST (used via LF_INDEX) with LF_ULONG & LF_UQUADWORD offsets.
    const std::uint32_t conn_fields_part2_ti = [&] {
        ByteWriter fl{};
        fl.u16(0x150Du); // LF_MEMBER callback
        fl.u16(0x0003u);
        fl.u32(proc_ptr_ti);
        fl.u16(0x8004u); // LF_ULONG
        fl.u32(56u);
        fl.cstr("on_packet");
        fl.align4_cv_pad();

        fl.u16(0x150Du); // LF_MEMBER handler
        fl.u16(0x0003u);
        fl.u32(mfunc_ptr_ti);
        fl.u16(0x800Au); // LF_UQUADWORD
        fl.u64(64ull);
        fl.cstr("member_hook");
        fl.align4_cv_pad();
        return add_type(0x1203u, fl);
    }();

    // 0x100D: Primary LF_FIELDLIST for ConnectionState (LF_BCLASS + members + LF_INDEX).
    const std::uint32_t conn_fields_ti = [&] {
        ByteWriter fl{};
        fl.u16(0x1400u); // LF_BCLASS
        fl.u16(0x0003u);
        fl.u32(packet_ti);
        fl.u16(0u);
        fl.align4_cv_pad();

        fl.u16(0x150Du); // label: const char* @ 8
        fl.u16(0x0003u);
        fl.u32(const_char_ptr_ti);
        fl.u16(8u);
        fl.cstr("label");
        fl.align4_cv_pad();

        fl.u16(0x150Du); // flags: bitfield @ 16
        fl.u16(0x0003u);
        fl.u32(bitfield_ti);
        fl.u16(16u);
        fl.cstr("flags");
        fl.align4_cv_pad();

        fl.u16(0x150Du); // scratch: uint8_t[32] @ 24
        fl.u16(0x0003u);
        fl.u32(byte_array_ti);
        fl.u16(24u);
        fl.cstr("scratch");
        fl.align4_cv_pad();

        fl.u16(0x1404u); // LF_INDEX -> conn_fields_part2_ti
        fl.u16(0u);
        fl.u32(conn_fields_part2_ti);
        fl.align4_cv_pad();
        return add_type(0x1203u, fl);
    }();

    // 0x100E: LF_CLASS ConnectionState (size encoded via LF_ULONG = 72).
    {
        ByteWriter b{};
        b.u16(6u);
        b.u16(0u);
        b.u32(conn_fields_ti);
        b.u32(0u);
        b.u32(0u);
        b.u16(0x8004u); // LF_ULONG
        b.u32(72u);
        b.cstr("ConnectionState");
        (void)add_type(0x1504u, b);
    }

    // 0x100F: LF_FIELDLIST + 0x1010: LF_UNION PayloadVariant (size = 8 at offset 8!).
    const std::uint32_t union_fields_ti = [&] {
        ByteWriter fl{};
        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x0077u); // T_UINT8
        fl.u16(0u);
        fl.cstr("raw_u64");
        fl.align4_cv_pad();

        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x0041u); // T_REAL64
        fl.u16(0u);
        fl.cstr("as_double");
        fl.align4_cv_pad();
        return add_type(0x1203u, fl);
    }();
    {
        ByteWriter b{};
        b.u16(2u);
        b.u16(0u);
        b.u32(union_fields_ti);
        b.u16(8u); // LF_UNION numeric size at offset 8
        b.cstr("PayloadVariant");
        (void)add_type(0x1506u, b);
    }

    // 0x1011: LF_INTERFACE ITransport (size = 8).
    {
        ByteWriter b{};
        b.u16(0u);
        b.u16(0u);
        b.u32(0u);
        b.u32(0u);
        b.u32(0u);
        b.u16(8u);
        b.cstr("ITransport");
        (void)add_type(0x1519u, b);
    }

    // 0x1012: LF_FIELDLIST + 0x1013: LF_ENUM ProtocolState (with signed negative LF_CHAR).
    const std::uint32_t enum_fields_ti = [&] {
        ByteWriter fl{};
        fl.u16(0x1502u); // LF_ENUMERATE
        fl.u16(0x0003u);
        fl.u16(0x8000u); // LF_CHAR
        fl.u8(static_cast<std::uint8_t>(-1));
        fl.cstr("Error");
        fl.align4_cv_pad();

        fl.u16(0x1502u);
        fl.u16(0x0003u);
        fl.u16(0u);
        fl.cstr("Idle");
        fl.align4_cv_pad();

        fl.u16(0x1502u);
        fl.u16(0x0003u);
        fl.u16(2u);
        fl.cstr("Connected");
        fl.align4_cv_pad();
        return add_type(0x1203u, fl);
    }();
    {
        ByteWriter b{};
        b.u16(3u);
        b.u16(0u);
        b.u32(0x0074u); // T_INT4 underlying
        b.u32(enum_fields_ti);
        b.cstr("ProtocolState");
        (void)add_type(0x1507u, b);
    }

    Msf7Builder msf(4096u);
    const std::array<std::uint8_t, 16> guid{1u};
    msf.set_stream(1u, make_pdb_info_stream(guid, 1u));
    msf.set_stream(2u, make_tpi_stream(tpi_records));
    msf.set_stream(3u, make_dbi_stream(1u, 0xFFFFu, {}));

    const auto parsed = peelf::parse_pdb_bytes(msf.build());
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;

    // Forward-reference PacketHeader was deduplicated in favor of the 8-byte full definition.
    EXPECT_EQ(std::ranges::count_if(parsed->types,
                                    [](const peelf::PdbAggregateType& t) {
                                        return t.name == "PacketHeader";
                                    }),
              1);

    const auto find_type = [&](std::string_view name) -> const peelf::PdbAggregateType* {
        const auto it = std::ranges::find(parsed->types, name, &peelf::PdbAggregateType::name);
        return it == parsed->types.end() ? nullptr : &(*it);
    };

    const auto* pkt = find_type("PacketHeader");
    ASSERT_NE(pkt, nullptr);
    EXPECT_EQ(pkt->kind, peelf::PdbAggregateKind::Struct);
    EXPECT_EQ(pkt->byte_size, 8u);
    ASSERT_EQ(pkt->members.size(), 2u);
    EXPECT_EQ(pkt->members[0].name, "magic");
    EXPECT_EQ(pkt->members[0].type_name, "uint32_t");
    EXPECT_EQ(pkt->members[0].byte_size, 4u);

    const auto* conn = find_type("ConnectionState");
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(conn->kind, peelf::PdbAggregateKind::Class);
    EXPECT_EQ(conn->byte_size, 72u);
    ASSERT_EQ(conn->members.size(), 6u);
    EXPECT_EQ(conn->members[0].name, "base_PacketHeader");
    EXPECT_EQ(conn->members[0].byte_size, 8u);
    EXPECT_EQ(conn->members[1].name, "label");
    EXPECT_EQ(conn->members[1].type_name, "const char*");
    EXPECT_EQ(conn->members[1].byte_offset, 8u);
    EXPECT_EQ(conn->members[1].byte_size, 8u);
    EXPECT_EQ(conn->members[2].name, "flags");
    EXPECT_TRUE(conn->members[2].is_bitfield);
    EXPECT_EQ(conn->members[2].bit_size, 5u);
    EXPECT_EQ(conn->members[2].bit_offset, 3u);
    EXPECT_NE(conn->members[2].type_name.find(": 5"), std::string::npos);
    EXPECT_EQ(conn->members[3].name, "scratch");
    EXPECT_EQ(conn->members[3].type_name, "uint8_t[32]");
    EXPECT_EQ(conn->members[3].byte_size, 32u);
    EXPECT_EQ(conn->members[4].name, "on_packet");
    EXPECT_EQ(conn->members[4].byte_offset, 56u);
    EXPECT_EQ(conn->members[4].type_name, "int32_t(uint64_t, void*)*");
    EXPECT_EQ(conn->members[5].name, "member_hook");
    EXPECT_EQ(conn->members[5].byte_offset, 64u);

    const auto* var = find_type("PayloadVariant");
    ASSERT_NE(var, nullptr);
    EXPECT_EQ(var->kind, peelf::PdbAggregateKind::Union);
    EXPECT_EQ(var->byte_size, 8u);
    ASSERT_EQ(var->members.size(), 2u);
    EXPECT_EQ(var->members[1].type_name, "double");

    const auto* iface = find_type("ITransport");
    ASSERT_NE(iface, nullptr);
    EXPECT_EQ(iface->kind, peelf::PdbAggregateKind::Interface);

    ASSERT_EQ(parsed->enums.size(), 1u);
    EXPECT_EQ(parsed->enums[0].name, "ProtocolState");
    EXPECT_EQ(parsed->enums[0].byte_size, 4u);
    ASSERT_EQ(parsed->enums[0].enumerators.size(), 3u);
    EXPECT_EQ(parsed->enums[0].enumerators[0].name, "Error");
    EXPECT_EQ(parsed->enums[0].enumerators[0].signed_value, -1);
    EXPECT_EQ(parsed->enums[0].enumerators[2].name, "Connected");
    EXPECT_EQ(parsed->enums[0].enumerators[2].signed_value, 2);
}

TEST(PdbParserTest, HandlesMaliciousCyclicTypesAndFieldListsWithoutInfiniteRecursion) {
    std::vector<std::vector<std::uint8_t>> tpi{};

    // 0x1000: Self-referential LF_POINTER -> 0x1000
    {
        ByteWriter b{};
        b.u32(0x1000u);
        b.u32((6u << 5u) | (8u << 13u));
        tpi.push_back(make_cv_record(0x1002u, b.data()));
    }

    // 0x1001 & 0x1002: Mutually cyclic LF_FIELDLIST records via LF_INDEX (0x1001 <-> 0x1002)
    {
        ByteWriter fl1{};
        fl1.u16(0x1404u); // LF_INDEX -> 0x1002
        fl1.u16(0u);
        fl1.u32(0x1002u);
        tpi.push_back(make_cv_record(0x1203u, fl1.data()));

        ByteWriter fl2{};
        fl2.u16(0x150Du);
        fl2.u16(0x0003u);
        fl2.u32(0x1004u); // Points to CycleNodeB
        fl2.u16(0u);
        fl2.cstr("b_member");
        fl2.align4_cv_pad();
        fl2.u16(0x1404u); // LF_INDEX -> 0x1001 (cycle!)
        fl2.u16(0u);
        fl2.u32(0x1001u);
        tpi.push_back(make_cv_record(0x1203u, fl2.data()));
    }

    // 0x1003: LF_STRUCTURE CycleNodeA using cyclic fieldlist 0x1001
    {
        ByteWriter b{};
        b.u16(1u);
        b.u16(0u);
        b.u32(0x1001u);
        b.u32(0u);
        b.u32(0u);
        b.u16(16u);
        b.cstr("CycleNodeA");
        tpi.push_back(make_cv_record(0x1505u, b.data()));
    }

    // 0x1004: LF_STRUCTURE CycleNodeB whose fieldlist 0x1005 embeds CycleNodeA (0x1003) & self-ptr (0x1000)
    {
        ByteWriter b{};
        b.u16(2u);
        b.u16(0u);
        b.u32(0x1005u);
        b.u32(0u);
        b.u32(0u);
        b.u16(24u);
        b.cstr("CycleNodeB");
        tpi.push_back(make_cv_record(0x1505u, b.data()));

        ByteWriter fl{};
        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x1003u); // CycleNodeA
        fl.u16(0u);
        fl.cstr("a_member");
        fl.align4_cv_pad();

        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x1000u); // self-pointer cycle
        fl.u16(16u);
        fl.cstr("evil_ptr");
        fl.align4_cv_pad();
        tpi.push_back(make_cv_record(0x1203u, fl.data()));
    }

    Msf7Builder msf(4096u);
    msf.set_stream(1u, make_pdb_info_stream({2u}, 1u));
    msf.set_stream(2u, make_tpi_stream(tpi));
    msf.set_stream(3u, make_dbi_stream(1u, 0xFFFFu, {}));

    const auto parsed = peelf::parse_pdb_bytes(msf.build());
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    EXPECT_EQ(parsed->types.size(), 2u);
}

TEST(PdbParserTest, EndToEndViewerLoadPdbSymbolsLinesStructureCatalogAndRebase) {
    const std::array<std::uint8_t, 16> kGuid = {
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAB, 0xCD,
    };

    // Build PE32+ image (`ImageBase = 0x140000000`) with a concrete 8-byte PacketHeader
    // instance placed in `.rdata` at RVA 0x2080 (file offset 0x480).
    auto pe_bytes = make_pe64_with_rsds_and_text(kGuid, 2u, "C:\\out\\engine.pdb");
    write_u32_at(pe_bytes, 0x480u, 0xCAFEBABEu); // magic = 0xCAFEBABE
    write_u16_at(pe_bytes, 0x484u, 7u);          // version = 7

    auto image_res = peelf::parse_image(pe_bytes);
    ASSERT_TRUE(image_res.has_value()) << image_res.error().message;
    const peelf::IBinaryImage& image = **image_res;

    // Build matching MSF 7.00 PDB:
    // - TPI defines `PacketHeader` { uint32_t magic; uint16_t version; } (8 bytes).
    // - SymRecordStream has S_PUB32 `engine_dispatch` (size 0) + S_GDATA32 `g_default_header`.
    // - Module 0 (`engine_core.lib`) has S_GPROC32 `engine_dispatch` (size 0x48) + S_LPROC32_ID
    //   `internal_tick` (size 0x1C) + C13 `DEBUG_S_LINES` (BEFORE `DEBUG_S_FILECHKSMS`!) with columns.
    // - Deliberately omit `OptionalDbgHeader` section headers so `fallback_pe_sections` + `image_base`
    //   translation (`peelf::Section::virtual_address - image_base`) is verified end-to-end!
    std::vector<std::vector<std::uint8_t>> tpi{};
    {
        ByteWriter fl{};
        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x0075u); // uint32_t
        fl.u16(0u);
        fl.cstr("magic");
        fl.align4_cv_pad();

        fl.u16(0x150Du);
        fl.u16(0x0003u);
        fl.u32(0x0073u); // uint16_t
        fl.u16(4u);
        fl.cstr("version");
        fl.align4_cv_pad();
        tpi.push_back(make_cv_record(0x1203u, fl.data()));

        ByteWriter st{};
        st.u16(2u);
        st.u16(0u);
        st.u32(0x1000u);
        st.u32(0u);
        st.u32(0u);
        st.u16(8u);
        st.cstr("PacketHeader");
        tpi.push_back(make_cv_record(0x1505u, st.data()));
    }

    Msf7Builder msf(1024u);
    const std::array<std::string_view, 1> kSourcePaths = {"C:\\work\\src\\engine\\core.cpp"};
    const auto names = make_names_stream(kSourcePaths);
    const std::uint32_t names_stream = msf.add_stream(names.stream_bytes);

    ByteWriter sym_rec{};
    sym_rec.bytes(make_pub32_sym(0x02u, 1u, 0x0020u, "engine_dispatch"));
    sym_rec.bytes(make_data32_sym(0x110Du, 2u, 0x0080u, 0x1001u, "g_default_header"));
    const std::uint32_t sym_stream = msf.add_stream(sym_rec.take());

    // Build Module 0 stream: CV_SIGNATURE_C13 (4), S_GPROC32 + S_LPROC32_ID, then C13 subsections.
    ByteWriter mod_syms{};
    mod_syms.u32(4u); // CV_SIGNATURE_C13
    mod_syms.bytes(make_proc32_sym(0x1110u, 1u, 0x0020u, 0x48u, 0u, "engine_dispatch"));
    mod_syms.bytes(make_proc32_sym(0x1146u, 1u, 0x0080u, 0x1Cu, 0u, "internal_tick"));
    const auto sym_byte_size = static_cast<std::uint32_t>(mod_syms.size());

    // Subsection 1: DEBUG_S_LINES (0xF2) with CV_LINES_HAVE_COLUMNS (0x0001) BEFORE FILECHKSMS.
    ByteWriter lines_payload{};
    lines_payload.u32(0x0020u); // offCon
    lines_payload.u16(1u);      // segCon (.text)
    lines_payload.u16(0x0001u); // flags = CV_LINES_HAVE_COLUMNS
    lines_payload.u32(0x48u);   // cbCon
    lines_payload.u32(0u);      // offFile = 0 in DEBUG_S_FILECHKSMS
    lines_payload.u32(2u);      // nLines = 2
    lines_payload.u32(12u + 2u * 8u + 2u * 4u); // cbBlock = 36
    // Line 0: offset +0, line 42, is_stmt = true
    lines_payload.u32(0u);
    lines_payload.u32(42u | 0x8000'0000u);
    // Line 1: offset +0x14, line 47, is_stmt = false
    lines_payload.u32(0x14u);
    lines_payload.u32(47u);
    // Columns: (col 5, end 20), (col 9, end 30)
    lines_payload.u16(5u);
    lines_payload.u16(20u);
    lines_payload.u16(9u);
    lines_payload.u16(30u);

    // Subsection 2: DEBUG_S_FILECHKSMS (0xF4) at offset 0 referencing names.name_offsets[0].
    ByteWriter chksms_payload{};
    chksms_payload.u32(names.name_offsets[0]);
    chksms_payload.u8(16u); // MD5 size
    chksms_payload.u8(1u);  // CHKSUM_TYPE_MD5
    for (int i = 0; i < 16; ++i) {
        chksms_payload.u8(static_cast<std::uint8_t>(i));
    }
    chksms_payload.align4_zero();

    ByteWriter c13{};
    c13.u32(0xF2u); // DEBUG_S_LINES
    c13.u32(static_cast<std::uint32_t>(lines_payload.size()));
    c13.bytes(lines_payload.data());
    c13.align4_zero();

    c13.u32(0xF4u); // DEBUG_S_FILECHKSMS
    c13.u32(static_cast<std::uint32_t>(chksms_payload.size()));
    c13.bytes(chksms_payload.data());
    c13.align4_zero();

    const auto c13_byte_size = static_cast<std::uint32_t>(c13.size());
    mod_syms.bytes(c13.data());
    const std::uint32_t mod0_stream = msf.add_stream(mod_syms.take());

    const std::array<ModInfoSpec, 1> kMods = {ModInfoSpec{
        .stream_index = static_cast<std::uint16_t>(mod0_stream),
        .sym_byte_size = sym_byte_size,
        .c13_byte_size = c13_byte_size,
        .module_name = "C:\\obj\\core.obj",
        .obj_file_name = "C:\\libs\\engine_core.lib",
    }};

    msf.set_stream(1u, make_pdb_info_stream(kGuid, 2u, names_stream));
    msf.set_stream(2u, make_tpi_stream(tpi));
    msf.set_stream(
        3u,
        make_dbi_stream(
            2u, static_cast<std::uint16_t>(sym_stream), kMods, /*section_hdr_stream=*/0xFFFFu));

    const auto pdb_bytes = msf.build(/*interleave_blocks=*/true);

    peelf_test::ScopedTempDir temp_dir("peelf_wu34_pdb_e2e");
    const auto exe_path = temp_dir.path() / "engine.exe";
    const auto pdb_path = temp_dir.path() / "engine.pdb";
    {
        std::ofstream exe_out(exe_path, std::ios::binary);
        exe_out.write(reinterpret_cast<const char*>(pe_bytes.data()),
                      static_cast<std::streamsize>(pe_bytes.size()));
        std::ofstream pdb_out(pdb_path, std::ios::binary);
        pdb_out.write(reinterpret_cast<const char*>(pdb_bytes.data()),
                      static_cast<std::streamsize>(pdb_bytes.size()));
    }

    const auto discovered = viewer::find_local_codeview_pdb(image, exe_path);
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(*discovered, pdb_path);

    const viewer::DebugSymbolLoadResult loaded = viewer::load_pdb_debug_symbols(pdb_path, image);
    ASSERT_EQ(loaded.status, viewer::DebugSymbolLoadStatus::Loaded) << loaded.diagnostic;

    // Symbols: `engine_dispatch` merged S_PUB32 + S_GPROC32 (`size = 0x48`, `library = engine_core.lib`),
    // `internal_tick` (`RVA = 0x1080`), and `g_default_header` (`RVA = 0x2080`, `size = 8`).
    ASSERT_EQ(loaded.symbols.size(), 3u);
    EXPECT_EQ(loaded.symbols[0].name, "engine_dispatch");
    EXPECT_EQ(loaded.symbols[0].relative_virtual_address, 0x1020u);
    EXPECT_EQ(loaded.symbols[0].virtual_address, 0x140001020ull);
    EXPECT_EQ(loaded.symbols[0].size, 0x48u);
    EXPECT_TRUE(loaded.symbols[0].function);
    EXPECT_NE(loaded.symbols[0].library.find("engine_core.lib"), std::string::npos);

    EXPECT_EQ(loaded.symbols[1].name, "internal_tick");
    EXPECT_EQ(loaded.symbols[1].relative_virtual_address, 0x1080u);
    EXPECT_EQ(loaded.symbols[1].size, 0x1Cu);

    EXPECT_EQ(loaded.symbols[2].name, "g_default_header");
    EXPECT_EQ(loaded.symbols[2].relative_virtual_address, 0x2080u);
    EXPECT_EQ(loaded.symbols[2].virtual_address, 0x140002080ull);
    EXPECT_EQ(loaded.symbols[2].size, 8u);
    EXPECT_FALSE(loaded.symbols[2].function);

    // Types -> StructureCatalog -> evaluate concrete `.rdata` bytes at 0x140002080!
    ASSERT_EQ(loaded.types.size(), 1u);
    EXPECT_EQ(loaded.types[0].name, "PacketHeader");
    const auto catalog = viewer::StructureCatalog::build(loaded.types);
    ASSERT_NE(catalog.find("PacketHeader"), nullptr);
    const viewer::StaticImageStructureByteSource byte_source(image, pe_bytes);
    const auto evaluated = viewer::evaluate_structure(
        catalog,
        "PacketHeader",
        0x140002080ull,
        /*is_file_offset=*/false,
        byte_source,
        viewer::StructureEvalOptions{});
    ASSERT_TRUE(evaluated.has_value()) << evaluated.error().message;
    ASSERT_EQ(evaluated->fields.size(), 2u);
    EXPECT_EQ(evaluated->fields[0].name, "magic");
    EXPECT_NE(evaluated->fields[0].decoded_value.find("3405691582"), std::string::npos)
        << evaluated->fields[0].decoded_value;
    EXPECT_EQ(evaluated->fields[1].name, "version");
    EXPECT_NE(evaluated->fields[1].decoded_value.find('7'), std::string::npos)
        << evaluated->fields[1].decoded_value;

    // C13 source lines:
    ASSERT_EQ(loaded.lines.size(), 2u);
    EXPECT_EQ(loaded.lines[0].relative_virtual_address, 0x1020u);
    EXPECT_EQ(loaded.lines[0].virtual_address, 0x140001020ull);
    EXPECT_EQ(loaded.lines[0].file_name, "core.cpp");
    EXPECT_EQ(loaded.lines[0].line, 42u);
    EXPECT_EQ(loaded.lines[0].column, 5u);
    EXPECT_TRUE(loaded.lines[0].is_stmt);
    EXPECT_EQ(loaded.lines[1].relative_virtual_address, 0x1034u);
    EXPECT_EQ(loaded.lines[1].line, 47u);
    EXPECT_EQ(loaded.lines[1].column, 9u);
    EXPECT_FALSE(loaded.lines[1].is_stmt);

    // Rebase symbols & source lines to an ASLR base + test overflow safety.
    const auto rebased_syms = viewer::rebase_debug_symbols(loaded.symbols, 0x7FF6'1000'0000ull);
    ASSERT_EQ(rebased_syms.size(), 3u);
    EXPECT_EQ(rebased_syms[0].virtual_address, 0x7FF6'1000'1020ull);
    const auto overflow_syms = viewer::rebase_debug_symbols(
        loaded.symbols, std::numeric_limits<std::uint64_t>::max() - 0x100ull);
    EXPECT_TRUE(overflow_syms.empty());

    const auto rebased_lines = viewer::rebase_source_lines(loaded.lines, 0x7FF6'1000'0000ull);
    ASSERT_EQ(rebased_lines.size(), 2u);
    EXPECT_EQ(rebased_lines[0].virtual_address, 0x7FF6'1000'1020ull);
    const auto overflow_lines = viewer::rebase_source_lines(
        loaded.lines, std::numeric_limits<std::uint64_t>::max() - 0x100ull);
    EXPECT_TRUE(overflow_lines.empty());

    // Mismatched RSDS GUID / Age must be rejected cleanly with an RSDS diagnostic.
    auto mismatched_pe = make_pe64_with_rsds_and_text(kGuid, 99u, "C:\\out\\engine.pdb");
    auto mismatched_image = peelf::parse_image(mismatched_pe);
    ASSERT_TRUE(mismatched_image.has_value());
    const auto rejected = viewer::load_pdb_debug_symbols(pdb_path, **mismatched_image);
    EXPECT_EQ(rejected.status, viewer::DebugSymbolLoadStatus::BackendError);
    EXPECT_NE(rejected.diagnostic.find("RSDS"), std::string::npos);
}

TEST(PdbParserTest, AppliesOmapFromSrcTranslationWhenPresent) {
    Msf7Builder msf(4096u);
    ByteWriter sec_hdrs{};
    sec_hdrs.bytes(make_image_section_header(".text", 0x2000u, 0x1000u));
    const std::uint32_t sec_stream = msf.add_stream(sec_hdrs.take());

    // OMAP_FROM_SRC remaps original RVA [0x1020..) -> target RVA [0x1840..).
    ByteWriter omap{};
    omap.u32(0x1000u);
    omap.u32(0x1000u);
    omap.u32(0x1020u);
    omap.u32(0x1840u);
    const std::uint32_t omap_stream = msf.add_stream(omap.take());

    ByteWriter sym_rec{};
    sym_rec.bytes(make_pub32_sym(0x02u, 1u, 0x0024u, "remapped_func"));
    const std::uint32_t sym_stream = msf.add_stream(sym_rec.take());

    msf.set_stream(1u, make_pdb_info_stream({7u}, 1u));
    msf.set_stream(2u, make_tpi_stream({}));
    msf.set_stream(3u,
                   make_dbi_stream(1u,
                                   static_cast<std::uint16_t>(sym_stream),
                                   {},
                                   static_cast<std::uint16_t>(sec_stream),
                                   static_cast<std::uint16_t>(omap_stream)));

    const auto parsed = peelf::parse_pdb_bytes(msf.build());
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->symbols.size(), 1u);
    // Original RVA = 0x1000 + 0x24 = 0x1024 -> OMAP entry (0x1020 -> 0x1840) + 4 = 0x1844.
    EXPECT_EQ(parsed->symbols[0].relative_address, 0x1844u);
}

TEST(PdbParserTest, RejectsAdversarialMalformedMsfAndTruncatedCodeViewInputs) {
    // 1. Truncated / wrong magic
    const std::array<std::uint8_t, 16> kShort = {0x4D, 0x5A};
    EXPECT_FALSE(peelf::has_msf7_signature(kShort));
    EXPECT_FALSE(peelf::read_pdb_identity(kShort).has_value());
    EXPECT_FALSE(peelf::parse_pdb_bytes(kShort).has_value());

    Msf7Builder valid_msf(4096u);
    valid_msf.set_stream(1u, make_pdb_info_stream({0x42u}, 1u));
    valid_msf.set_stream(2u, make_tpi_stream({}));
    valid_msf.set_stream(3u, make_dbi_stream(1u, 0xFFFFu, {}));
    const auto base = valid_msf.build();
    ASSERT_TRUE(peelf::parse_pdb_bytes(base).has_value());

    // 2. Unsupported block_size = 777
    {
        auto bad = base;
        write_u32_at(bad, 32u, 777u);
        EXPECT_FALSE(peelf::parse_pdb_bytes(bad).has_value());
    }

    // 3. num_blocks * block_size exceeds file size / wrap-around
    {
        auto bad = base;
        write_u32_at(bad, 40u, 0x0100'0000u);
        EXPECT_FALSE(peelf::parse_pdb_bytes(bad).has_value());
    }

    // 4. num_directory_bytes = 0xFFFFFFFF wrap-around
    {
        auto bad = base;
        write_u32_at(bad, 44u, 0xFFFF'FFFFu);
        EXPECT_FALSE(peelf::parse_pdb_bytes(bad).has_value());
    }

    // 5. Out-of-bounds block_map_addr
    {
        auto bad = base;
        write_u32_at(bad, 52u, 9999u);
        EXPECT_FALSE(peelf::parse_pdb_bytes(bad).has_value());
    }

    // 6. Out-of-bounds block index inside BlockMap
    {
        auto bad = base;
        const std::uint32_t bma =
            static_cast<std::uint32_t>(bad[52]) |
            (static_cast<std::uint32_t>(bad[53]) << 8u) |
            (static_cast<std::uint32_t>(bad[54]) << 16u) |
            (static_cast<std::uint32_t>(bad[55]) << 24u);
        write_u32_at(bad, static_cast<std::size_t>(bma) * 4096u, 0xDEAD'BEEFu);
        EXPECT_FALSE(peelf::parse_pdb_bytes(bad).has_value());
    }

    // 7. Nil Stream 1 (0xFFFFFFFF) must fail cleanly
    {
        Msf7Builder nil_info(4096u);
        nil_info.set_stream(2u, make_tpi_stream({}));
        auto bytes = nil_info.build();
        // Overwrite Stream 1 size in directory to 0xFFFFFFFF:
        const std::uint32_t bma =
            static_cast<std::uint32_t>(bytes[52]) |
            (static_cast<std::uint32_t>(bytes[53]) << 8u);
        const std::uint32_t dir_blk =
            static_cast<std::uint32_t>(bytes[static_cast<std::size_t>(bma) * 4096u]);
        write_u32_at(bytes, static_cast<std::size_t>(dir_blk) * 4096u + 8u, 0xFFFF'FFFFu);
        EXPECT_FALSE(peelf::read_pdb_identity(bytes).has_value());
        EXPECT_FALSE(peelf::parse_pdb_bytes(bytes).has_value());
    }

    // 8. Truncated CodeView TPI record (claims reclen = 512 inside 12-byte payload) fails cleanly
    {
        ByteWriter bad_tpi{};
        bad_tpi.u32(20040203u);
        bad_tpi.u32(56u);
        bad_tpi.u32(0x1000u);
        bad_tpi.u32(0x1001u);
        bad_tpi.u32(12u);
        for (int i = 0; i < 9; ++i) {
            bad_tpi.u32(0u);
        }
        bad_tpi.u16(512u); // reclen overflows record_bytes!
        bad_tpi.u16(0x1505u);
        bad_tpi.u64(0u);

        Msf7Builder msf(4096u);
        msf.set_stream(1u, make_pdb_info_stream({0x55u}, 1u));
        msf.set_stream(2u, bad_tpi.take());
        msf.set_stream(3u, make_dbi_stream(1u, 0xFFFFu, {}));
        const auto res = peelf::parse_pdb_bytes(msf.build());
        EXPECT_FALSE(res.has_value());
    }

    // 9. Truncated CodeView symbol stream record fails cleanly via Result error
    {
        ByteWriter trunc_sym{};
        trunc_sym.u16(200u); // reclen exceeds stream size!
        trunc_sym.u16(0x110Eu);
        trunc_sym.u32(0x02u);

        Msf7Builder msf(4096u);
        const std::uint32_t sym_idx = msf.add_stream(trunc_sym.take());
        msf.set_stream(1u, make_pdb_info_stream({0x66u}, 1u));
        msf.set_stream(2u, make_tpi_stream({}));
        msf.set_stream(3u, make_dbi_stream(1u, static_cast<std::uint16_t>(sym_idx), {}));
        const auto res = peelf::parse_pdb_bytes(msf.build());
        EXPECT_FALSE(res.has_value());
    }
}
