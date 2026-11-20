#include "peelf/crash_dump.hpp"

#include "image_internal.hpp"
#include "peelf/macho_image.hpp"
#include "peelf/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {
namespace {

// Darwin XNU `<mach/i386/thread_status.h>` thread & exception state flavors
constexpr std::uint32_t kX86ThreadState32    = 1u;  // count = 16 u32s (64 bytes)
constexpr std::uint32_t kX86ExceptionState32 = 3u;  // count = 3 u32s  (12 bytes)
constexpr std::uint32_t kX86ThreadState64    = 4u;  // count = 42 u32s (168 bytes)
constexpr std::uint32_t kX86FloatState64     = 5u;  // count = 131 u32s (524 bytes)
constexpr std::uint32_t kX86ExceptionState64 = 6u;  // count = 4 u32s  (16 bytes)
constexpr std::uint32_t kX86ThreadStateUniv  = 7u;  // universal wrapper [flavor, count, ...]
constexpr std::uint32_t kX86ExcStateUniv     = 9u;  // universal wrapper [flavor, count, ...]

// Darwin XNU `<mach/arm/thread_status.h>` thread & exception state flavors
constexpr std::uint32_t kArmThreadState32    = 1u;  // count = 17 u32s (68 bytes)
constexpr std::uint32_t kArmThreadState64    = 6u;  // count = 68 u32s (272 bytes)
constexpr std::uint32_t kArmExceptionState64 = 7u;  // count = 4 u32s  (16 bytes)

constexpr std::size_t kMaxUniversalSlices = 64u;
constexpr std::uint32_t kMaxCoreLoadCommands = 262'144u;

struct MachOCoreSliceInfo {
    std::size_t offset{0};
    std::size_t size{0};
    bool is_64bit{true};
    Endianness endianness{Endianness::Little};
};

struct CoreSegmentEntry {
    std::string segname{};
    std::uint64_t vmaddr{0};
    std::uint64_t vmsize{0};
    std::uint64_t slice_fileoff{0};
    std::uint64_t filesize{0};
    std::uint64_t backed_size{0};
    std::uint32_t maxprot{0};
    std::uint32_t initprot{0};
    std::uint32_t flags{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool truncated{false};

    [[nodiscard]] constexpr std::uint64_t vmend() const noexcept {
        return vmsize <= (std::numeric_limits<std::uint64_t>::max() - vmaddr)
                   ? (vmaddr + vmsize)
                   : std::numeric_limits<std::uint64_t>::max();
    }
};

[[nodiscard]] std::uint32_t read_u32_raw(std::span<const std::uint8_t> b,
                                         std::size_t off,
                                         Endianness endian) noexcept {
    if (off + 4u > b.size()) {
        return 0u;
    }
    if (endian == Endianness::Big) {
        return (static_cast<std::uint32_t>(b[off]) << 24u) |
               (static_cast<std::uint32_t>(b[off + 1u]) << 16u) |
               (static_cast<std::uint32_t>(b[off + 2u]) << 8u) |
               static_cast<std::uint32_t>(b[off + 3u]);
    }
    return static_cast<std::uint32_t>(b[off]) |
           (static_cast<std::uint32_t>(b[off + 1u]) << 8u) |
           (static_cast<std::uint32_t>(b[off + 2u]) << 16u) |
           (static_cast<std::uint32_t>(b[off + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_raw(std::span<const std::uint8_t> b,
                                         std::size_t off,
                                         Endianness endian) noexcept {
    if (off + 8u > b.size()) {
        return 0u;
    }
    if (endian == Endianness::Big) {
        return (static_cast<std::uint64_t>(read_u32_raw(b, off, Endianness::Big)) << 32u) |
               static_cast<std::uint64_t>(read_u32_raw(b, off + 4u, Endianness::Big));
    }
    return static_cast<std::uint64_t>(read_u32_raw(b, off, Endianness::Little)) |
           (static_cast<std::uint64_t>(read_u32_raw(b, off + 4u, Endianness::Little)) << 32u);
}

[[nodiscard]] bool inspect_thin_macho_header(std::span<const std::uint8_t> slice,
                                             bool& out_is_64bit,
                                             Endianness& out_endian,
                                             std::uint32_t& out_filetype) noexcept {
    if (slice.size() < 28u) {
        return false;
    }
    const std::uint32_t magic_be = read_u32_raw(slice, 0u, Endianness::Big);
    if (magic_be == macho::kMhMagic64) {
        if (slice.size() < 32u) {
            return false;
        }
        out_is_64bit = true;
        out_endian = Endianness::Big;
    } else if (magic_be == macho::kMhCigam64) {
        if (slice.size() < 32u) {
            return false;
        }
        out_is_64bit = true;
        out_endian = Endianness::Little;
    } else if (magic_be == macho::kMhMagic) {
        out_is_64bit = false;
        out_endian = Endianness::Big;
    } else if (magic_be == macho::kMhCigam) {
        out_is_64bit = false;
        out_endian = Endianness::Little;
    } else {
        return false;
    }
    out_filetype = read_u32_raw(slice, 12u, out_endian);
    return true;
}

[[nodiscard]] std::optional<MachOCoreSliceInfo> locate_macho_core_slice(
    std::span<const std::uint8_t> bytes) noexcept {
    bool is_64 = false;
    Endianness endian = Endianness::Little;
    std::uint32_t filetype = 0u;
    if (inspect_thin_macho_header(bytes, is_64, endian, filetype)) {
        if (filetype != macho::kMhCore) {
            return std::nullopt;
        }
        return MachOCoreSliceInfo{
            .offset = 0u,
            .size = bytes.size(),
            .is_64bit = is_64,
            .endianness = endian,
        };
    }

    if (bytes.size() < 8u) {
        return std::nullopt;
    }
    const std::uint32_t fat_magic = read_u32_raw(bytes, 0u, Endianness::Big);
    bool fat64 = false;
    Endianness fat_endian = Endianness::Big;
    if (fat_magic == macho::kFatMagic) {
        fat64 = false;
        fat_endian = Endianness::Big;
    } else if (fat_magic == macho::kFatCigam) {
        fat64 = false;
        fat_endian = Endianness::Little;
    } else if (fat_magic == macho::kFatMagic64) {
        fat64 = true;
        fat_endian = Endianness::Big;
    } else if (fat_magic == macho::kFatCigam64) {
        fat64 = true;
        fat_endian = Endianness::Little;
    } else {
        return std::nullopt;
    }

    const std::uint32_t nfat = read_u32_raw(bytes, 4u, fat_endian);
    if (nfat == 0u || nfat > kMaxUniversalSlices) {
        return std::nullopt;
    }
    const std::size_t arch_sz = fat64 ? 32u : 20u;
    const std::size_t table_end = 8u + static_cast<std::size_t>(nfat) * arch_sz;
    if (table_end > bytes.size()) {
        return std::nullopt;
    }

    std::optional<MachOCoreSliceInfo> first_core_slice{};
    for (std::uint32_t i = 0u; i < nfat; ++i) {
        const std::size_t entry_off = 8u + static_cast<std::size_t>(i) * arch_sz;
        const std::uint64_t sl_off = fat64
            ? read_u64_raw(bytes, entry_off + 8u, fat_endian)
            : static_cast<std::uint64_t>(read_u32_raw(bytes, entry_off + 8u, fat_endian));
        const std::uint64_t sl_sz = fat64
            ? read_u64_raw(bytes, entry_off + 16u, fat_endian)
            : static_cast<std::uint64_t>(read_u32_raw(bytes, entry_off + 12u, fat_endian));
        const auto sl_end = checked_add_u64(sl_off, sl_sz);
        if (!sl_end.has_value() || sl_off < table_end || sl_sz < 28u ||
            *sl_end > static_cast<std::uint64_t>(bytes.size())) {
            return std::nullopt;
        }
        const auto sub = bytes.subspan(
            static_cast<std::size_t>(sl_off), static_cast<std::size_t>(sl_sz));
        bool sl_64 = false;
        Endianness sl_endian = Endianness::Little;
        std::uint32_t sl_filetype = 0u;
        if (!inspect_thin_macho_header(sub, sl_64, sl_endian, sl_filetype)) {
            // Reject non-Mach-O payloads such as Java `.class` files sharing `0xCAFEBABE`.
            return std::nullopt;
        }
        if (sl_filetype == macho::kMhCore && !first_core_slice.has_value()) {
            first_core_slice = MachOCoreSliceInfo{
                .offset = static_cast<std::size_t>(sl_off),
                .size = static_cast<std::size_t>(sl_sz),
                .is_64bit = sl_64,
                .endianness = sl_endian,
            };
        }
    }
    return first_core_slice;
}

[[nodiscard]] Architecture map_macho_core_arch(std::uint32_t cputype) noexcept {
    switch (cputype) {
        case macho::kCpuTypeX86:       return Architecture::X86;
        case macho::kCpuTypeX86_64:    return Architecture::X86_64;
        case macho::kCpuTypeArm:       return Architecture::ARM;
        case macho::kCpuTypeArm64:
        case macho::kCpuTypeArm64_32:  return Architecture::ARM64;
        case macho::kCpuTypePowerPC:   return Architecture::PowerPC;
        case macho::kCpuTypePowerPC64: return Architecture::PowerPC64;
        default:                       return Architecture::Unknown;
    }
}

[[nodiscard]] std::string read_fixed_str16(std::span<const std::uint8_t> buf, std::size_t off) {
    if (off + 16u > buf.size()) {
        return {};
    }
    std::size_t len = 0u;
    while (len < 16u && buf[off + len] != 0u) {
        ++len;
    }
    return std::string(reinterpret_cast<const char*>(buf.data() + off), len);
}

[[nodiscard]] std::string join_notes(std::span<const std::string> notes) {
    std::string out;
    for (std::size_t i = 0u; i < notes.size(); ++i) {
        if (i > 0u) {
            out += "; ";
        }
        out += notes[i];
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u32_bytes(std::uint32_t v, Endianness e) {
    std::vector<std::uint8_t> out(4u, 0u);
    if (e == Endianness::Big) {
        out[0] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
        out[1] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
        out[3] = static_cast<std::uint8_t>(v & 0xFFu);
    } else {
        out[0] = static_cast<std::uint8_t>(v & 0xFFu);
        out[1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
        out[3] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u64_bytes(std::uint64_t v, Endianness e) {
    std::vector<std::uint8_t> out(8u, 0u);
    if (e == Endianness::Big) {
        for (std::size_t i = 0u; i < 8u; ++i) {
            out[i] = static_cast<std::uint8_t>((v >> ((7u - i) * 8u)) & 0xFFu);
        }
    } else {
        for (std::size_t i = 0u; i < 8u; ++i) {
            out[i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
        }
    }
    return out;
}

[[nodiscard]] RegisterValue make_macho_reg(std::string name,
                                           RegisterCategory cat,
                                           std::uint64_t val,
                                           std::uint16_t bit_width,
                                           Endianness endian) {
    if (bit_width == 64u) {
        return RegisterValue{
            .name = std::move(name),
            .category = cat,
            .bit_width = 64u,
            .value_u64 = val,
            .raw_bytes = encode_u64_bytes(val, endian),
            .formatted = std::format("0x{:016x}", val),
        };
    }
    const auto v32 = static_cast<std::uint32_t>(val);
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 32u,
        .value_u64 = v32,
        .raw_bytes = encode_u32_bytes(v32, endian),
        .formatted = std::format("0x{:08x}", v32),
    };
}

[[nodiscard]] std::vector<FlagBitInfo> decode_x86_flags_macho(std::uint64_t flags) {
    struct BitSpec {
        const char* name;
        std::uint8_t bit;
        const char* desc;
    };
    static constexpr std::array<BitSpec, 9> kSpecs{{
        {"CF", 0, "Carry Flag"},
        {"PF", 2, "Parity Flag"},
        {"AF", 4, "Auxiliary Carry Flag"},
        {"ZF", 6, "Zero Flag"},
        {"SF", 7, "Sign Flag"},
        {"TF", 8, "Trap Flag"},
        {"IF", 9, "Interrupt Enable Flag"},
        {"DF", 10, "Direction Flag"},
        {"OF", 11, "Overflow Flag"},
    }};
    std::vector<FlagBitInfo> out;
    out.reserve(kSpecs.size());
    for (const BitSpec& s : kSpecs) {
        out.push_back(FlagBitInfo{
            .name = s.name,
            .bit = s.bit,
            .set = ((flags >> s.bit) & 1ull) != 0ull,
            .description = s.desc,
        });
    }
    return out;
}

[[nodiscard]] std::vector<FlagBitInfo> decode_arm_flags_macho(std::uint64_t flags,
                                                              bool include_thumb) {
    std::vector<FlagBitInfo> out{
        {"N", 31, ((flags >> 31u) & 1ull) != 0ull, "Negative Condition Flag"},
        {"Z", 30, ((flags >> 30u) & 1ull) != 0ull, "Zero Condition Flag"},
        {"C", 29, ((flags >> 29u) & 1ull) != 0ull, "Carry Condition Flag"},
        {"V", 28, ((flags >> 28u) & 1ull) != 0ull, "Overflow Condition Flag"},
    };
    if (include_thumb) {
        out.push_back({"T", 5, ((flags >> 5u) & 1ull) != 0ull, "Thumb Execution State"});
    }
    return out;
}

[[nodiscard]] std::uint64_t strip_arm64e_pac_if_needed(std::uint64_t addr, bool is_arm64e) noexcept {
    if (!is_arm64e) {
        return addr;
    }
    const std::uint64_t top = addr >> 48u;
    if (top != 0u && top != 0xFFFFu) {
        return ((addr >> 55u) & 1ull) != 0ull
            ? (addr | 0xFFFF000000000000ull)
            : (addr & 0x0000FFFFFFFFFFFFull);
    }
    return addr;
}

[[nodiscard]] std::string x86_trap_fault_name(std::uint16_t trapno) {
    switch (trapno) {
        case 0u:  return "EXC_ARITHMETIC (#DE Divide Error)";
        case 1u:  return "EXC_BREAKPOINT (#DB Debug Trap)";
        case 3u:  return "EXC_BREAKPOINT (#BP Breakpoint)";
        case 4u:  return "EXC_ARITHMETIC (#OF Overflow)";
        case 5u:  return "EXC_SOFTWARE (#BR Bound Range)";
        case 6u:  return "EXC_BAD_INSTRUCTION (#UD Invalid Opcode)";
        case 11u: return "EXC_BAD_ACCESS (#NP Segment Not Present)";
        case 12u: return "EXC_BAD_ACCESS (#SS Stack-Segment Fault)";
        case 13u: return "EXC_BAD_ACCESS (#GP General Protection Fault)";
        case 14u: return "EXC_BAD_ACCESS (#PF Page Fault)";
        case 16u: return "EXC_ARITHMETIC (#MF x87 FP Exception)";
        case 17u: return "EXC_BAD_ACCESS (#AC Alignment Check)";
        case 19u: return "EXC_ARITHMETIC (#XM SIMD FP Exception)";
        default:  return std::format("EXC_X86_TRAP_{}", trapno);
    }
}

[[nodiscard]] std::string arm64_exception_fault_name(std::uint32_t esr, std::uint32_t exc_num) {
    const std::uint32_t ec = (esr >> 26u) & 0x3Fu;
    switch (ec) {
        case 0x20u:
        case 0x21u:
            return "EXC_BAD_ACCESS (Instruction Abort)";
        case 0x22u:
            return "EXC_BAD_ACCESS (PC Alignment Fault)";
        case 0x24u:
        case 0x25u:
            return "EXC_BAD_ACCESS (Data Abort)";
        case 0x26u:
            return "EXC_BAD_ACCESS (SP Alignment Fault)";
        case 0x0Eu:
            return "EXC_BAD_INSTRUCTION (Illegal Execution State)";
        case 0x2Cu:
            return "EXC_ARITHMETIC (FP Exception)";
        case 0x38u:
        case 0x3Cu:
            return "EXC_BREAKPOINT (BRK Trap)";
        default:
            break;
    }
    switch (exc_num) {
        case 1u: return "EXC_BAD_ACCESS";
        case 2u: return "EXC_BAD_INSTRUCTION";
        case 3u: return "EXC_ARITHMETIC";
        case 4u: return "EXC_EMULATION";
        case 5u: return "EXC_SOFTWARE";
        case 6u: return "EXC_BREAKPOINT";
        default:
            if (ec != 0u) {
                return std::format("EXC_ARM64_EC_0x{:02X}", ec);
            }
            return "EXC_BAD_ACCESS";
    }
}

[[nodiscard]] std::string basename_from_posix_path(std::string_view p) {
    while (p.size() > 1u && p.back() == '/') {
        p.remove_suffix(1u);
    }
    const std::size_t slash = p.rfind('/');
    return std::string(slash == std::string_view::npos ? p : p.substr(slash + 1u));
}

class MachOCoreSession final : public ICrashDumpSession {
public:
    MachOCoreSession(std::vector<std::uint8_t> bytes,
                     std::size_t slice_offset,
                     std::size_t slice_size,
                     ProcessInfo info,
                     CrashDumpSummary summary,
                     std::vector<CoreSegmentEntry> segments,
                     std::vector<MemoryRegion> regions,
                     std::vector<ModuleInfo> modules,
                     std::vector<ThreadInfo> threads,
                     std::unordered_map<ThreadId, ThreadContext> contexts,
                     ProcessInternalsSnapshot internals,
                     SubsystemStatus regions_status,
                     SubsystemStatus modules_status,
                     SubsystemStatus threads_status)
        : bytes_(std::move(bytes)),
          slice_offset_(slice_offset),
          slice_size_(slice_size),
          info_(std::move(info)),
          summary_(std::move(summary)),
          segments_(std::move(segments)),
          regions_(std::move(regions)),
          modules_(std::move(modules)),
          threads_(std::move(threads)),
          contexts_(std::move(contexts)),
          internals_(std::move(internals)),
          regions_status_(std::move(regions_status)),
          modules_status_(std::move(modules_status)),
          threads_status_(std::move(threads_status)) {}

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] const CrashDumpSummary& crash_summary() const noexcept override { return summary_; }
    [[nodiscard]] const ProcessInternalsSnapshot& crash_internals() const noexcept override {
        return internals_;
    }

    [[nodiscard]] SubsystemStatus memory_regions_status() const override { return regions_status_; }
    [[nodiscard]] SubsystemStatus modules_status() const override { return modules_status_; }
    [[nodiscard]] SubsystemStatus threads_status() const override { return threads_status_; }

    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
        return regions_;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        return modules_;
    }

    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        return threads_;
    }

    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        if (const auto it = contexts_.find(tid); it != contexts_.end()) {
            return it->second;
        }
        ThreadContext missing{};
        missing.tid = tid;
        missing.layout = target_layout();
        missing.status = SubsystemStatus::unavailable(
            "macho_core", std::format("TID {} has no decoded register state in Mach-O core dump", tid));
        return missing;
    }

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }

        const std::span<const std::uint8_t> slice(
            bytes_.data() + slice_offset_, slice_size_);

        std::size_t total_copied = 0u;
        std::uint64_t cursor = address;

        while (total_copied < buffer.size()) {
            const CoreSegmentEntry* seg = find_segment(cursor);
            if (seg == nullptr) {
                break;
            }
            const std::uint64_t rel = cursor - seg->vmaddr;
            const std::size_t rem = buffer.size() - total_copied;

            if (rel < seg->backed_size) {
                const std::uint64_t avail_backed = seg->backed_size - rel;
                const auto chunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(avail_backed, static_cast<std::uint64_t>(rem)));
                const auto src_off = checked_add_u64(seg->slice_fileoff, rel);
                if (!src_off.has_value() ||
                    !detail::fits_range(*src_off, chunk, static_cast<std::uint64_t>(slice.size()))) {
                    break;
                }
                std::memcpy(buffer.data() + total_copied,
                            slice.data() + static_cast<std::size_t>(*src_off),
                            chunk);
                total_copied += chunk;
                const auto next_cur = checked_add_u64(cursor, chunk);
                if (!next_cur.has_value()) {
                    break;
                }
                cursor = *next_cur;
                continue;
            }

            // Zero-fill `[file_size, virtual_size)` for non-truncated readable segments.
            if (!seg->truncated && rel < seg->vmsize) {
                const std::uint64_t avail_zero = seg->vmsize - rel;
                const auto chunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(avail_zero, static_cast<std::uint64_t>(rem)));
                std::memset(buffer.data() + total_copied, 0, chunk);
                total_copied += chunk;
                const auto next_cur = checked_add_u64(cursor, chunk);
                if (!next_cur.has_value()) {
                    break;
                }
                cursor = *next_cur;
                continue;
            }

            break;
        }

        if (total_copied == 0u) {
            return make_error(
                std::format("address 0x{:x} is not present in Mach-O MH_CORE dump", address));
        }
        return total_copied;
    }

    void set_discovered_modules_and_summary(std::vector<MemoryRegion> regions,
                                            std::vector<ModuleInfo> modules,
                                            std::string process_name,
                                            std::filesystem::path exe_path,
                                            SubsystemStatus mod_status) {
        regions_ = std::move(regions);
        modules_ = std::move(modules);
        modules_status_ = std::move(mod_status);
        summary_.module_count = modules_.size();
        summary_.region_count = regions_.size();
        if (!process_name.empty()) {
            info_.name = process_name;
            summary_.process_name = std::move(process_name);
        }
        if (!exe_path.empty()) {
            info_.executable_path = std::move(exe_path);
        }
    }

private:
    [[nodiscard]] const CoreSegmentEntry* find_segment(std::uint64_t va) const noexcept {
        // Prefer readable or file-backed segments covering `va`.
        for (const CoreSegmentEntry& seg : segments_) {
            if (va >= seg.vmaddr && va < seg.vmend() &&
                (seg.readable || seg.backed_size > 0u)) {
                return &seg;
            }
        }
        return nullptr;
    }

    std::vector<std::uint8_t> bytes_;
    std::size_t slice_offset_{0};
    std::size_t slice_size_{0};
    ProcessInfo info_;
    CrashDumpSummary summary_;
    std::vector<CoreSegmentEntry> segments_;
    std::vector<MemoryRegion> regions_;
    std::vector<ModuleInfo> modules_;
    std::vector<ThreadInfo> threads_;
    std::unordered_map<ThreadId, ThreadContext> contexts_;
    ProcessInternalsSnapshot internals_;
    SubsystemStatus regions_status_;
    SubsystemStatus modules_status_;
    SubsystemStatus threads_status_;
};

void discover_mapped_macho_modules(MachOCoreSession& session,
                                   const std::vector<CoreSegmentEntry>& core_segments,
                                   std::vector<MemoryRegion> regions,
                                   const std::filesystem::path& source_path,
                                   Endianness core_endian,
                                   std::vector<std::string>& mod_warnings) {
    struct CandidateImage {
        ModuleInfo mod{};
        std::uint64_t end_va{0};
    };
    std::vector<CandidateImage> found;

    auto already_covered = [&](std::uint64_t va) noexcept {
        for (const CandidateImage& c : found) {
            if (va >= c.mod.base_address && va < c.end_va) {
                return true;
            }
        }
        return false;
    };

    auto try_probe_header_at = [&](std::uint64_t header_va, std::uint64_t fallback_span) {
        if (already_covered(header_va)) {
            return;
        }
        std::array<std::uint8_t, 32> hdr{};
        const auto hdr_rd = session.read_memory(header_va, hdr);
        if (!hdr_rd.has_value() || *hdr_rd < 28u) {
            return;
        }

        bool img_64 = false;
        Endianness img_endian = core_endian;
        std::uint32_t filetype = 0u;
        if (!inspect_thin_macho_header(
                std::span<const std::uint8_t>(hdr.data(), *hdr_rd),
                img_64,
                img_endian,
                filetype)) {
            return;
        }
        if (filetype != macho::kMhExecute &&
            filetype != macho::kMhDylib &&
            filetype != macho::kMhDylinker &&
            filetype != macho::kMhBundle) {
            return;
        }

        const std::size_t hdr_sz = img_64 ? 32u : 28u;
        const std::uint32_t cputype = read_u32_raw(hdr, 4u, img_endian);
        const std::uint32_t cpusubtype = read_u32_raw(hdr, 8u, img_endian);
        const std::uint32_t ncmds = read_u32_raw(hdr, 16u, img_endian);
        const std::uint32_t sizeofcmds = read_u32_raw(hdr, 20u, img_endian);
        if (ncmds == 0u || ncmds > 4096u || sizeofcmds > 512u * 1024u) {
            return;
        }

        const std::size_t total_hdr = hdr_sz + static_cast<std::size_t>(sizeofcmds);
        std::vector<std::uint8_t> cmd_buf(total_hdr, 0u);
        const auto cmd_rd = session.read_memory(header_va, cmd_buf);
        if (!cmd_rd.has_value() || *cmd_rd < hdr_sz) {
            return;
        }
        const std::size_t avail_len = *cmd_rd;

        const bool is_arm64e =
            cputype == macho::kCpuTypeArm64 &&
            (cpusubtype & macho::kCpuSubtypeMask) == macho::kCpuSubtypeArm64e;

        std::optional<std::uint64_t> text_vmaddr{};
        std::uint64_t text_fileoff = 0u;
        std::optional<std::uint64_t> lowest_vmaddr{};
        struct ImgSeg {
            std::string name;
            std::uint64_t vmaddr{0};
            std::uint64_t vmsize{0};
            std::uint64_t fileoff{0};
            std::uint64_t filesize{0};
        };
        std::vector<ImgSeg> img_segs;
        std::string dylib_install_name{};
        std::optional<std::uint64_t> lc_main_entryoff{};
        std::optional<std::uint64_t> unixthread_entry{};
        std::uint32_t codesig_dataoff = 0u;
        std::uint32_t codesig_datasize = 0u;

        std::size_t cur = hdr_sz;
        for (std::uint32_t i = 0u; i < ncmds && cur + 8u <= avail_len; ++i) {
            const std::uint32_t cmd = read_u32_raw(cmd_buf, cur, img_endian);
            const std::uint32_t cmdsize = read_u32_raw(cmd_buf, cur + 4u, img_endian);
            if (cmdsize < 8u || cur + cmdsize > avail_len) {
                break;
            }

            if ((cmd == macho::kLcSegment64 && cmdsize >= 72u) ||
                (cmd == macho::kLcSegment && cmdsize >= 56u)) {
                const bool seg64 = (cmd == macho::kLcSegment64);
                std::string sname = read_fixed_str16(cmd_buf, cur + 8u);
                const std::uint64_t vmaddr = seg64
                    ? read_u64_raw(cmd_buf, cur + 24u, img_endian)
                    : static_cast<std::uint64_t>(read_u32_raw(cmd_buf, cur + 24u, img_endian));
                const std::uint64_t vmsize = seg64
                    ? read_u64_raw(cmd_buf, cur + 32u, img_endian)
                    : static_cast<std::uint64_t>(read_u32_raw(cmd_buf, cur + 28u, img_endian));
                const std::uint64_t fileoff = seg64
                    ? read_u64_raw(cmd_buf, cur + 40u, img_endian)
                    : static_cast<std::uint64_t>(read_u32_raw(cmd_buf, cur + 32u, img_endian));
                const std::uint64_t filesize = seg64
                    ? read_u64_raw(cmd_buf, cur + 48u, img_endian)
                    : static_cast<std::uint64_t>(read_u32_raw(cmd_buf, cur + 36u, img_endian));
                const std::uint32_t maxprot = seg64
                    ? read_u32_raw(cmd_buf, cur + 56u, img_endian)
                    : read_u32_raw(cmd_buf, cur + 40u, img_endian);
                const std::uint32_t initprot = seg64
                    ? read_u32_raw(cmd_buf, cur + 60u, img_endian)
                    : read_u32_raw(cmd_buf, cur + 44u, img_endian);

                if (sname != "__PAGEZERO" && (initprot != 0u || maxprot != 0u || filesize > 0u)) {
                    if (sname == "__TEXT" && !text_vmaddr.has_value()) {
                        text_vmaddr = vmaddr;
                        text_fileoff = fileoff;
                    }
                    if (!lowest_vmaddr.has_value() || vmaddr < *lowest_vmaddr) {
                        lowest_vmaddr = vmaddr;
                    }
                    img_segs.push_back(ImgSeg{
                        .name = std::move(sname),
                        .vmaddr = vmaddr,
                        .vmsize = vmsize,
                        .fileoff = fileoff,
                        .filesize = filesize,
                    });
                }
            } else if ((cmd == macho::kLcIdDylib && cmdsize >= 24u) ||
                       (cmd == macho::kLcIdDylinker && cmdsize >= 12u)) {
                const std::uint32_t str_off = read_u32_raw(cmd_buf, cur + 8u, img_endian);
                if (str_off >= 8u && str_off < cmdsize) {
                    const std::size_t abs_str = cur + static_cast<std::size_t>(str_off);
                    const std::size_t max_len = static_cast<std::size_t>(cmdsize - str_off);
                    std::size_t len = 0u;
                    while (len < max_len && cmd_buf[abs_str + len] != 0u) {
                        ++len;
                    }
                    if (len > 0u) {
                        dylib_install_name.assign(
                            reinterpret_cast<const char*>(cmd_buf.data() + abs_str), len);
                    }
                }
            } else if (cmd == macho::kLcMain && cmdsize >= 24u) {
                lc_main_entryoff = read_u64_raw(cmd_buf, cur + 8u, img_endian);
            } else if (cmd == macho::kLcUnixThread && !unixthread_entry.has_value()) {
                std::size_t tcur = cur + 8u;
                const std::size_t tend = cur + static_cast<std::size_t>(cmdsize);
                while (tcur + 8u <= tend) {
                    const std::uint32_t flv = read_u32_raw(cmd_buf, tcur, img_endian);
                    const std::uint32_t cnt = read_u32_raw(cmd_buf, tcur + 4u, img_endian);
                    const std::uint64_t sb = static_cast<std::uint64_t>(cnt) * 4u;
                    if (sb > static_cast<std::uint64_t>(tend - (tcur + 8u))) {
                        break;
                    }
                    const std::size_t soff = tcur + 8u;
                    if (cputype == macho::kCpuTypeX86_64 && flv == kX86ThreadState64 && sb >= 136u) {
                        unixthread_entry = read_u64_raw(cmd_buf, soff + 128u, img_endian);
                        break;
                    }
                    if (cputype == macho::kCpuTypeX86 && flv == kX86ThreadState32 && sb >= 44u) {
                        unixthread_entry = read_u32_raw(cmd_buf, soff + 40u, img_endian);
                        break;
                    }
                    if ((cputype == macho::kCpuTypeArm64 || cputype == macho::kCpuTypeArm64_32) &&
                        flv == kArmThreadState64 && sb >= 264u) {
                        unixthread_entry = strip_arm64e_pac_if_needed(
                            read_u64_raw(cmd_buf, soff + 256u, img_endian), is_arm64e);
                        break;
                    }
                    tcur = soff + static_cast<std::size_t>(sb);
                }
            } else if (cmd == macho::kLcCodeSignature && cmdsize >= 16u) {
                codesig_dataoff = read_u32_raw(cmd_buf, cur + 8u, img_endian);
                codesig_datasize = read_u32_raw(cmd_buf, cur + 12u, img_endian);
            }

            cur += cmdsize;
        }

        const std::uint64_t unslid_base = text_vmaddr.value_or(lowest_vmaddr.value_or(header_va));
        const std::uint64_t slide = header_va - unslid_base;

        std::uint64_t min_va = header_va;
        std::uint64_t max_va = checked_add_u64(header_va, std::max<std::uint64_t>(fallback_span, hdr_sz))
                                   .value_or(header_va);
        for (const ImgSeg& iseg : img_segs) {
            const std::uint64_t seg_va = iseg.vmaddr + slide;
            const auto seg_end = checked_add_u64(seg_va, iseg.vmsize);
            if (!seg_end.has_value() || *seg_end <= seg_va) {
                continue;
            }
            min_va = std::min(min_va, seg_va);
            max_va = std::max(max_va, *seg_end);
        }

        // Try to recover CodeDirectory identifier from mapped `__LINKEDIT` when `LC_ID_DYLIB` is absent.
        std::string codesig_ident{};
        if (dylib_install_name.empty() && codesig_dataoff != 0u && codesig_datasize >= 44u) {
            for (const ImgSeg& iseg : img_segs) {
                if (iseg.name == "__LINKEDIT" &&
                    codesig_dataoff >= iseg.fileoff &&
                    codesig_dataoff - iseg.fileoff < iseg.vmsize) {
                    const std::uint64_t cs_va =
                        (iseg.vmaddr + slide) + (codesig_dataoff - iseg.fileoff);
                    const std::size_t probe_sz = static_cast<std::size_t>(
                        std::min<std::uint64_t>(codesig_datasize, 4096u));
                    std::vector<std::uint8_t> cs_buf(probe_sz, 0u);
                    if (const auto cs_rd = session.read_memory(cs_va, cs_buf);
                        cs_rd.has_value() && *cs_rd >= 20u &&
                        read_u32_raw(cs_buf, 0u, Endianness::Big) == macho::kCsMagicEmbeddedSignature) {
                        const std::uint32_t blob_cnt =
                            std::min<std::uint32_t>(read_u32_raw(cs_buf, 8u, Endianness::Big), 16u);
                        for (std::uint32_t bi = 0u; bi < blob_cnt; ++bi) {
                            const std::size_t idx_off = 12u + static_cast<std::size_t>(bi) * 8u;
                            if (idx_off + 8u > *cs_rd) {
                                break;
                            }
                            const std::uint32_t slot_type = read_u32_raw(cs_buf, idx_off, Endianness::Big);
                            const std::uint32_t sub_off = read_u32_raw(cs_buf, idx_off + 4u, Endianness::Big);
                            if (slot_type == macho::kCsSlotCodeDirectory &&
                                sub_off + 28u <= *cs_rd &&
                                read_u32_raw(cs_buf, sub_off, Endianness::Big) == macho::kCsMagicCodeDirectory) {
                                const std::uint32_t ident_off =
                                    read_u32_raw(cs_buf, sub_off + 24u, Endianness::Big);
                                if (ident_off >= 28u && sub_off + ident_off < *cs_rd) {
                                    const std::size_t s_pos = sub_off + ident_off;
                                    std::size_t slen = 0u;
                                    while (s_pos + slen < *cs_rd && cs_buf[s_pos + slen] != 0u &&
                                           slen < 256u) {
                                        ++slen;
                                    }
                                    if (slen > 0u) {
                                        codesig_ident.assign(
                                            reinterpret_cast<const char*>(cs_buf.data() + s_pos), slen);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }

        ModuleInfo mod{};
        mod.base_address = min_va;
        mod.size = max_va >= min_va ? (max_va - min_va) : fallback_span;
        mod.format = Format::MachO;
        mod.is_main_module = (filetype == macho::kMhExecute);

        if (lc_main_entryoff.has_value() && *lc_main_entryoff >= text_fileoff) {
            mod.entry_point = checked_add_u64(header_va, *lc_main_entryoff - text_fileoff).value_or(0u);
        } else if (unixthread_entry.has_value()) {
            mod.entry_point = *unixthread_entry + slide;
        }

        if (!dylib_install_name.empty()) {
            mod.path = std::filesystem::path(dylib_install_name);
            mod.name = basename_from_posix_path(dylib_install_name);
        } else if (!codesig_ident.empty()) {
            mod.name = codesig_ident;
        } else if (filetype == macho::kMhExecute) {
            if (!source_path.empty()) {
                std::string stem = source_path.stem().string();
                if (stem.empty()) {
                    stem = source_path.filename().string();
                }
                mod.name = !stem.empty() ? std::move(stem) : std::string("macho_executable");
            } else {
                mod.name = "macho_executable";
            }
        } else if (filetype == macho::kMhDylinker) {
            mod.name = "dyld";
            mod.path = "/usr/lib/dyld";
        } else {
            mod.name = std::format("macho_dylib_0x{:x}", header_va);
        }

        found.push_back(CandidateImage{
            .mod = std::move(mod),
            .end_va = max_va,
        });
    };

    constexpr std::size_t kMaxPageProbes = 4096u;
    std::size_t page_probes = 0u;
    for (const CoreSegmentEntry& seg : core_segments) {
        if (seg.backed_size < 28u) {
            continue;
        }
        try_probe_header_at(seg.vmaddr, seg.vmsize);

        // Also scan 4 KiB-aligned page starts within executable file-backed segments
        // when multiple mapped Mach-O images share a coalesced core segment.
        if (seg.executable && seg.backed_size > 0x1000u && page_probes < kMaxPageProbes) {
            for (std::uint64_t off = 0x1000u;
                 off + 32u <= seg.backed_size && page_probes < kMaxPageProbes;
                 off += 0x1000u) {
                ++page_probes;
                if (const auto page_va = checked_add_u64(seg.vmaddr, off)) {
                    try_probe_header_at(*page_va, seg.vmsize - off);
                }
            }
        }
    }

    std::vector<ModuleInfo> modules;
    modules.reserve(found.size());
    for (CandidateImage& c : found) {
        for (MemoryRegion& reg : regions) {
            if (reg.start_address < c.end_va && reg.end_address > c.mod.base_address &&
                reg.kind != MemoryRegionKind::Stack) {
                reg.kind = MemoryRegionKind::Image;
                reg.module_name = c.mod.name;
                if (reg.pathname.empty() && !c.mod.path.empty()) {
                    reg.pathname = c.mod.path.string();
                }
                if (reg.start_address >= c.mod.base_address) {
                    reg.file_offset = reg.start_address - c.mod.base_address;
                }
            }
        }
        modules.push_back(std::move(c.mod));
    }

    std::ranges::sort(modules, [](const ModuleInfo& a, const ModuleInfo& b) {
        if (a.is_main_module != b.is_main_module) {
            return a.is_main_module;
        }
        return a.base_address < b.base_address;
    });

    std::string proc_name{};
    std::filesystem::path exe_path{};
    for (const ModuleInfo& m : modules) {
        if (m.is_main_module) {
            proc_name = m.name;
            exe_path = m.path;
            break;
        }
    }

    SubsystemStatus mod_status = !mod_warnings.empty()
        ? SubsystemStatus::partial("macho_core", join_notes(mod_warnings))
        : (!modules.empty()
               ? SubsystemStatus::available(
                     "macho_core",
                     std::format("Recovered {} mapped Mach-O image(s) from core segments",
                                 modules.size()))
               : SubsystemStatus::partial(
                     "macho_core",
                     "No mapped MH_EXECUTE/MH_DYLIB headers found at core segment boundaries"));

    session.set_discovered_modules_and_summary(
        std::move(regions),
        std::move(modules),
        std::move(proc_name),
        std::move(exe_path),
        std::move(mod_status));
}

}  // namespace

bool is_macho_core_dump(std::span<const std::uint8_t> bytes) noexcept {
    return locate_macho_core_slice(bytes).has_value();
}

Result<std::unique_ptr<ICrashDumpSession>> open_macho_core_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path) {
    const auto slice_info = locate_macho_core_slice(bytes);
    if (!slice_info.has_value()) {
        return make_error("buffer is not a valid Mach-O MH_CORE crash dump");
    }

    const std::span<const std::uint8_t> slice(
        bytes.data() + slice_info->offset, slice_info->size);
    const bool is_64 = slice_info->is_64bit;
    const Endianness endian = slice_info->endianness;
    const std::size_t hdr_sz = is_64 ? 32u : 28u;
    if (slice.size() < hdr_sz) {
        return make_error("truncated Mach-O MH_CORE header");
    }

    const std::uint32_t cputype = read_u32_raw(slice, 4u, endian);
    const std::uint32_t cpusubtype = read_u32_raw(slice, 8u, endian);
    const std::uint32_t filetype = read_u32_raw(slice, 12u, endian);
    const std::uint32_t ncmds = read_u32_raw(slice, 16u, endian);
    const std::uint32_t sizeofcmds = read_u32_raw(slice, 20u, endian);
    if (filetype != macho::kMhCore) {
        return make_error("Mach-O filetype is not MH_CORE (0x4)");
    }
    if (ncmds > kMaxCoreLoadCommands) {
        return make_error("Mach-O MH_CORE load command count exceeds safety ceiling");
    }
    const auto lc_end_u64 = checked_add_u64(hdr_sz, sizeofcmds);
    if (!lc_end_u64.has_value() || *lc_end_u64 > static_cast<std::uint64_t>(slice.size())) {
        return make_error("truncated Mach-O MH_CORE load command table");
    }

    const Architecture arch = map_macho_core_arch(cputype);
    const bool is_arm64e =
        cputype == macho::kCpuTypeArm64 &&
        (cpusubtype & macho::kCpuSubtypeMask) == macho::kCpuSubtypeArm64e;
    const TargetLayout layout = TargetLayout::from_arch(arch, is_64, endian);

    std::vector<std::string> mem_warnings;
    std::vector<std::string> mod_warnings;
    std::vector<std::string> thread_warnings;

    std::vector<CoreSegmentEntry> core_segments;
    std::vector<MemoryRegion> regions;
    std::vector<ThreadInfo> threads;
    std::unordered_map<ThreadId, ThreadContext> contexts;

    struct DecodedExceptionCandidate {
        CrashExceptionInfo info{};
        bool is_non_zero{false};
    };
    std::vector<DecodedExceptionCandidate> exc_candidates;

    const auto lc_table_end = static_cast<std::size_t>(*lc_end_u64);
    std::size_t cmd_off = hdr_sz;

    for (std::uint32_t cmd_idx = 0u; cmd_idx < ncmds; ++cmd_idx) {
        if (cmd_off + 8u > lc_table_end) {
            mem_warnings.push_back("Truncated Mach-O load command header");
            break;
        }
        const std::uint32_t cmd = read_u32_raw(slice, cmd_off, endian);
        const std::uint32_t cmdsize = read_u32_raw(slice, cmd_off + 4u, endian);
        if (cmdsize < 8u || cmd_off + static_cast<std::size_t>(cmdsize) > lc_table_end) {
            mem_warnings.push_back(std::format(
                "Malformed Mach-O load command size {} at index {}", cmdsize, cmd_idx));
            break;
        }

        if (cmd == macho::kLcSegment64 || cmd == macho::kLcSegment) {
            const bool seg64 = (cmd == macho::kLcSegment64);
            const std::size_t min_seg_sz = seg64 ? 72u : 56u;
            if (cmdsize < min_seg_sz) {
                mem_warnings.push_back("Truncated LC_SEGMENT(_64) command in MH_CORE");
                cmd_off += cmdsize;
                continue;
            }

            std::string segname = read_fixed_str16(slice, cmd_off + 8u);
            const std::uint64_t vmaddr = seg64
                ? read_u64_raw(slice, cmd_off + 24u, endian)
                : static_cast<std::uint64_t>(read_u32_raw(slice, cmd_off + 24u, endian));
            const std::uint64_t vmsize = seg64
                ? read_u64_raw(slice, cmd_off + 32u, endian)
                : static_cast<std::uint64_t>(read_u32_raw(slice, cmd_off + 28u, endian));
            const std::uint64_t fileoff = seg64
                ? read_u64_raw(slice, cmd_off + 40u, endian)
                : static_cast<std::uint64_t>(read_u32_raw(slice, cmd_off + 32u, endian));
            const std::uint64_t filesize = seg64
                ? read_u64_raw(slice, cmd_off + 48u, endian)
                : static_cast<std::uint64_t>(read_u32_raw(slice, cmd_off + 36u, endian));
            const std::uint32_t maxprot = seg64
                ? read_u32_raw(slice, cmd_off + 56u, endian)
                : read_u32_raw(slice, cmd_off + 40u, endian);
            const std::uint32_t initprot = seg64
                ? read_u32_raw(slice, cmd_off + 60u, endian)
                : read_u32_raw(slice, cmd_off + 44u, endian);
            const std::uint32_t seg_flags = seg64
                ? read_u32_raw(slice, cmd_off + 68u, endian)
                : read_u32_raw(slice, cmd_off + 52u, endian);

            if (vmsize == 0u && filesize == 0u) {
                cmd_off += cmdsize;
                continue;
            }

            const auto vm_end = checked_add_u64(vmaddr, vmsize);
            if (!vm_end.has_value()) {
                mem_warnings.push_back(std::format(
                    "Skipping overflowing LC_SEGMENT(_64) [vmaddr=0x{:x}, vmsize=0x{:x}]",
                    vmaddr, vmsize));
                cmd_off += cmdsize;
                continue;
            }

            const auto file_end = checked_add_u64(fileoff, filesize);
            if (!file_end.has_value()) {
                mem_warnings.push_back(std::format(
                    "Skipping overflowing LC_SEGMENT(_64) [fileoff=0x{:x}, filesize=0x{:x}]",
                    fileoff, filesize));
                cmd_off += cmdsize;
                continue;
            }
            if (filesize > 0u && fileoff >= static_cast<std::uint64_t>(slice.size())) {
                mem_warnings.push_back(std::format(
                    "Skipping out-of-bounds LC_SEGMENT(_64) [fileoff=0x{:x} >= slice=0x{:x}]",
                    fileoff, slice.size()));
                cmd_off += cmdsize;
                continue;
            }

            bool seg_truncated = false;
            std::uint64_t backed = std::min(filesize, vmsize);
            if (*file_end > static_cast<std::uint64_t>(slice.size())) {
                seg_truncated = true;
                backed = std::min<std::uint64_t>(
                    vmsize, static_cast<std::uint64_t>(slice.size()) - fileoff);
                mem_warnings.push_back(std::format(
                    "Truncated LC_SEGMENT(_64) payload at VA 0x{:x}: backed 0x{:x} of 0x{:x} bytes",
                    vmaddr, backed, filesize));
            } else if (filesize > vmsize) {
                mem_warnings.push_back(std::format(
                    "Clamping LC_SEGMENT(_64) filesize (0x{:x}) to vmsize (0x{:x}) at VA 0x{:x}",
                    filesize, vmsize, vmaddr));
            }

            const std::uint32_t eff_prot =
                (initprot != 0u)
                    ? initprot
                    : ((backed > 0u && segname != "__PAGEZERO") ? maxprot : 0u);
            const bool prot_r = (eff_prot & macho::kVmProtRead) != 0u;
            const bool prot_w = (eff_prot & macho::kVmProtWrite) != 0u;
            const bool prot_x = (eff_prot & macho::kVmProtExecute) != 0u;

            if (vmsize > 0u) {
                CoreSegmentEntry cseg{};
                cseg.segname = segname;
                cseg.vmaddr = vmaddr;
                cseg.vmsize = vmsize;
                cseg.slice_fileoff = fileoff;
                cseg.filesize = filesize;
                cseg.backed_size = backed;
                cseg.maxprot = maxprot;
                cseg.initprot = initprot;
                cseg.flags = seg_flags;
                cseg.readable = prot_r;
                cseg.writable = prot_w;
                cseg.executable = prot_x;
                cseg.truncated = seg_truncated;
                core_segments.push_back(cseg);

                MemoryRegion reg{};
                reg.start_address = vmaddr;
                reg.end_address = *vm_end;
                reg.protection.readable = prot_r;
                reg.protection.writable = prot_w;
                reg.protection.executable = prot_x;
                reg.kind = MemoryRegionKind::Anonymous;
                reg.file_offset = fileoff;
                reg.pathname = segname;
                if (!prot_r && !prot_w && !prot_x && backed == 0u) {
                    reg.usage.is_reserved_only = true;
                    reg.usage.committed_bytes = 0u;
                } else {
                    reg.usage.committed_bytes = vmsize;
                    reg.usage.rss_bytes = backed;
                }
                regions.push_back(std::move(reg));
            }
        } else if (cmd == macho::kLcThread || cmd == macho::kLcUnixThread) {
            const ThreadId tid = static_cast<ThreadId>(threads.size() + 1u);
            ThreadContext ctx{};
            ctx.tid = tid;
            ctx.layout = layout;
            ctx.status = SubsystemStatus::unavailable(
                "macho_core", "No supported GPR thread-state flavor decoded");

            bool decoded_gpr = false;
            std::optional<DecodedExceptionCandidate> thread_exc{};
            std::uint32_t saw_unsupported_flavor = 0u;

            std::size_t tcur = cmd_off + 8u;
            const std::size_t tend = cmd_off + static_cast<std::size_t>(cmdsize);

            while (tcur < tend) {
                if (tcur + 8u > tend) {
                    thread_warnings.push_back(std::format(
                        "Truncated LC_THREAD flavor header on thread {}", tid));
                    break;
                }
                std::uint32_t flavor = read_u32_raw(slice, tcur, endian);
                std::uint32_t count = read_u32_raw(slice, tcur + 4u, endian);
                const std::uint64_t state_bytes_u64 = static_cast<std::uint64_t>(count) * 4u;
                const std::size_t state_off = tcur + 8u;
                if (state_bytes_u64 > static_cast<std::uint64_t>(tend - state_off)) {
                    thread_warnings.push_back(std::format(
                        "Truncated LC_THREAD state payload (flavor={}, count={}) on thread {}",
                        flavor, count, tid));
                    break;
                }

                std::size_t payload_off = state_off;
                std::size_t payload_len = static_cast<std::size_t>(state_bytes_u64);

                // Unwrap Darwin universal x86 state header (`x86_THREAD_STATE` / `x86_EXCEPTION_STATE`)
                if ((cputype == macho::kCpuTypeX86_64 || cputype == macho::kCpuTypeX86) &&
                    (flavor == kX86ThreadStateUniv || flavor == kX86ExcStateUniv) &&
                    payload_len >= 8u) {
                    const std::uint32_t inner_flavor = read_u32_raw(slice, payload_off, endian);
                    const std::uint32_t inner_count = read_u32_raw(slice, payload_off + 4u, endian);
                    const std::uint64_t inner_bytes = static_cast<std::uint64_t>(inner_count) * 4u;
                    if (inner_bytes <= payload_len - 8u) {
                        flavor = inner_flavor;
                        count = inner_count;
                        payload_off += 8u;
                        payload_len = static_cast<std::size_t>(inner_bytes);
                    }
                }

                const auto payload = slice.subspan(payload_off, payload_len);

                if (cputype == macho::kCpuTypeX86_64 && flavor == kX86ThreadState64) {
                    if (payload_len < 42u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated x86_THREAD_STATE64 ({} bytes < 168) on thread {}",
                            payload_len, tid));
                    } else {
                        const auto r64 = [&](std::size_t idx) {
                            return read_u64_raw(payload, idx * 8u, endian);
                        };
                        const std::uint64_t rax    = r64(0);
                        const std::uint64_t rbx    = r64(1);
                        const std::uint64_t rcx    = r64(2);
                        const std::uint64_t rdx    = r64(3);
                        const std::uint64_t rdi    = r64(4);
                        const std::uint64_t rsi    = r64(5);
                        const std::uint64_t rbp    = r64(6);
                        const std::uint64_t rsp    = r64(7);
                        const std::uint64_t r8     = r64(8);
                        const std::uint64_t r9     = r64(9);
                        const std::uint64_t r10    = r64(10);
                        const std::uint64_t r11    = r64(11);
                        const std::uint64_t r12    = r64(12);
                        const std::uint64_t r13    = r64(13);
                        const std::uint64_t r14    = r64(14);
                        const std::uint64_t r15    = r64(15);
                        const std::uint64_t rip    = r64(16);
                        const std::uint64_t rflags = r64(17);
                        const std::uint64_t cs     = r64(18);
                        const std::uint64_t fs     = r64(19);
                        const std::uint64_t gs     = r64(20);

                        ctx.instruction_pointer = rip;
                        ctx.stack_pointer = rsp;
                        ctx.frame_pointer = rbp;
                        ctx.flags_value = rflags;
                        ctx.decoded_flags = decode_x86_flags_macho(rflags);
                        ctx.registers = {
                            make_macho_reg("rip", RegisterCategory::InstructionPointer, rip, 64u, endian),
                            make_macho_reg("rsp", RegisterCategory::StackPointer, rsp, 64u, endian),
                            make_macho_reg("rbp", RegisterCategory::FramePointer, rbp, 64u, endian),
                            make_macho_reg("rax", RegisterCategory::General, rax, 64u, endian),
                            make_macho_reg("rbx", RegisterCategory::General, rbx, 64u, endian),
                            make_macho_reg("rcx", RegisterCategory::General, rcx, 64u, endian),
                            make_macho_reg("rdx", RegisterCategory::General, rdx, 64u, endian),
                            make_macho_reg("rdi", RegisterCategory::General, rdi, 64u, endian),
                            make_macho_reg("rsi", RegisterCategory::General, rsi, 64u, endian),
                            make_macho_reg("r8",  RegisterCategory::General, r8,  64u, endian),
                            make_macho_reg("r9",  RegisterCategory::General, r9,  64u, endian),
                            make_macho_reg("r10", RegisterCategory::General, r10, 64u, endian),
                            make_macho_reg("r11", RegisterCategory::General, r11, 64u, endian),
                            make_macho_reg("r12", RegisterCategory::General, r12, 64u, endian),
                            make_macho_reg("r13", RegisterCategory::General, r13, 64u, endian),
                            make_macho_reg("r14", RegisterCategory::General, r14, 64u, endian),
                            make_macho_reg("r15", RegisterCategory::General, r15, 64u, endian),
                            make_macho_reg("rflags", RegisterCategory::Flags, rflags, 64u, endian),
                            make_macho_reg("cs",  RegisterCategory::SegmentOrTls, cs, 64u, endian),
                            make_macho_reg("fs",  RegisterCategory::SegmentOrTls, fs, 64u, endian),
                            make_macho_reg("gs",  RegisterCategory::SegmentOrTls, gs, 64u, endian),
                        };
                        ctx.status = SubsystemStatus::available(
                            "macho_core", "Decoded x86_THREAD_STATE64 registers");
                        decoded_gpr = true;
                    }
                } else if (cputype == macho::kCpuTypeX86_64 && flavor == kX86ExceptionState64) {
                    if (payload_len < 4u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated x86_EXCEPTION_STATE64 ({} bytes < 16) on thread {}",
                            payload_len, tid));
                    } else {
                        const EndianReader erd(payload, layout);
                        const std::uint16_t trapno = erd.read_u16(0u).value_or(0u);
                        const std::uint32_t err = erd.read_u32(4u).value_or(0u);
                        const std::uint64_t faultvaddr = erd.read_u64(8u).value_or(0u);

                        CrashExceptionInfo ex{};
                        ex.thread_id = tid;
                        ex.fault_code = trapno;
                        ex.fault_subcode = static_cast<std::int64_t>(err);
                        ex.fault_name = x86_trap_fault_name(trapno);
                        ex.fault_address = faultvaddr;
                        if (trapno == 14u) {
                            ex.access_operation =
                                ((err & 0x10u) != 0u)
                                    ? "execute"
                                    : (((err & 0x02u) != 0u) ? "write" : "read");
                        }
                        thread_exc = DecodedExceptionCandidate{
                            .info = std::move(ex),
                            .is_non_zero = (trapno != 0u || err != 0u || faultvaddr != 0u),
                        };
                    }
                } else if (cputype == macho::kCpuTypeX86 && flavor == kX86ThreadState32) {
                    if (payload_len < 16u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated x86_THREAD_STATE32 ({} bytes < 64) on thread {}",
                            payload_len, tid));
                    } else {
                        const auto r32 = [&](std::size_t idx) {
                            return read_u32_raw(payload, idx * 4u, endian);
                        };
                        const std::uint32_t eax    = r32(0);
                        const std::uint32_t ebx    = r32(1);
                        const std::uint32_t ecx    = r32(2);
                        const std::uint32_t edx    = r32(3);
                        const std::uint32_t edi    = r32(4);
                        const std::uint32_t esi    = r32(5);
                        const std::uint32_t ebp    = r32(6);
                        const std::uint32_t esp    = r32(7);
                        const std::uint32_t ss     = r32(8);
                        const std::uint32_t eflags = r32(9);
                        const std::uint32_t eip    = r32(10);
                        const std::uint32_t cs     = r32(11);
                        const std::uint32_t ds     = r32(12);
                        const std::uint32_t es     = r32(13);
                        const std::uint32_t fs     = r32(14);
                        const std::uint32_t gs     = r32(15);

                        ctx.instruction_pointer = eip;
                        ctx.stack_pointer = esp;
                        ctx.frame_pointer = ebp;
                        ctx.flags_value = eflags;
                        ctx.decoded_flags = decode_x86_flags_macho(eflags);
                        ctx.registers = {
                            make_macho_reg("eip", RegisterCategory::InstructionPointer, eip, 32u, endian),
                            make_macho_reg("esp", RegisterCategory::StackPointer, esp, 32u, endian),
                            make_macho_reg("ebp", RegisterCategory::FramePointer, ebp, 32u, endian),
                            make_macho_reg("eax", RegisterCategory::General, eax, 32u, endian),
                            make_macho_reg("ebx", RegisterCategory::General, ebx, 32u, endian),
                            make_macho_reg("ecx", RegisterCategory::General, ecx, 32u, endian),
                            make_macho_reg("edx", RegisterCategory::General, edx, 32u, endian),
                            make_macho_reg("edi", RegisterCategory::General, edi, 32u, endian),
                            make_macho_reg("esi", RegisterCategory::General, esi, 32u, endian),
                            make_macho_reg("eflags", RegisterCategory::Flags, eflags, 32u, endian),
                            make_macho_reg("cs",  RegisterCategory::SegmentOrTls, cs, 32u, endian),
                            make_macho_reg("ss",  RegisterCategory::SegmentOrTls, ss, 32u, endian),
                            make_macho_reg("ds",  RegisterCategory::SegmentOrTls, ds, 32u, endian),
                            make_macho_reg("es",  RegisterCategory::SegmentOrTls, es, 32u, endian),
                            make_macho_reg("fs",  RegisterCategory::SegmentOrTls, fs, 32u, endian),
                            make_macho_reg("gs",  RegisterCategory::SegmentOrTls, gs, 32u, endian),
                        };
                        ctx.status = SubsystemStatus::available(
                            "macho_core", "Decoded x86_THREAD_STATE32 registers");
                        decoded_gpr = true;
                    }
                } else if (cputype == macho::kCpuTypeX86 && flavor == kX86ExceptionState32) {
                    if (payload_len < 3u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated x86_EXCEPTION_STATE32 ({} bytes < 12) on thread {}",
                            payload_len, tid));
                    } else {
                        const EndianReader erd(payload, layout);
                        const std::uint16_t trapno = erd.read_u16(0u).value_or(0u);
                        const std::uint32_t err = erd.read_u32(4u).value_or(0u);
                        const std::uint32_t faultvaddr = erd.read_u32(8u).value_or(0u);

                        CrashExceptionInfo ex{};
                        ex.thread_id = tid;
                        ex.fault_code = trapno;
                        ex.fault_subcode = static_cast<std::int64_t>(err);
                        ex.fault_name = x86_trap_fault_name(trapno);
                        ex.fault_address = faultvaddr;
                        if (trapno == 14u) {
                            ex.access_operation =
                                ((err & 0x10u) != 0u)
                                    ? "execute"
                                    : (((err & 0x02u) != 0u) ? "write" : "read");
                        }
                        thread_exc = DecodedExceptionCandidate{
                            .info = std::move(ex),
                            .is_non_zero = (trapno != 0u || err != 0u || faultvaddr != 0u),
                        };
                    }
                } else if ((cputype == macho::kCpuTypeArm64 || cputype == macho::kCpuTypeArm64_32) &&
                           flavor == kArmThreadState64) {
                    if (payload_len < 68u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated ARM_THREAD_STATE64 ({} bytes < 272) on thread {}",
                            payload_len, tid));
                    } else {
                        const auto r64 = [&](std::size_t idx) {
                            return read_u64_raw(payload, idx * 8u, endian);
                        };
                        const std::uint64_t fp = strip_arm64e_pac_if_needed(r64(29), is_arm64e);
                        const std::uint64_t lr = strip_arm64e_pac_if_needed(r64(30), is_arm64e);
                        const std::uint64_t sp = strip_arm64e_pac_if_needed(r64(31), is_arm64e);
                        const std::uint64_t pc = strip_arm64e_pac_if_needed(r64(32), is_arm64e);
                        const std::uint32_t cpsr = read_u32_raw(payload, 264u, endian);

                        ctx.instruction_pointer = pc;
                        ctx.stack_pointer = sp;
                        ctx.frame_pointer = fp;
                        ctx.link_register = lr;
                        ctx.flags_value = cpsr;
                        ctx.decoded_flags = decode_arm_flags_macho(cpsr, false);
                        ctx.registers.reserve(34u);
                        ctx.registers.push_back(
                            make_macho_reg("pc", RegisterCategory::InstructionPointer, pc, 64u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("sp", RegisterCategory::StackPointer, sp, 64u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("fp", RegisterCategory::FramePointer, fp, 64u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("lr", RegisterCategory::General, lr, 64u, endian));
                        for (std::size_t i = 0u; i <= 28u; ++i) {
                            ctx.registers.push_back(make_macho_reg(
                                std::format("x{}", i), RegisterCategory::General, r64(i), 64u, endian));
                        }
                        ctx.registers.push_back(
                            make_macho_reg("cpsr", RegisterCategory::Flags, cpsr, 32u, endian));
                        ctx.status = SubsystemStatus::available(
                            "macho_core", "Decoded ARM_THREAD_STATE64 registers");
                        decoded_gpr = true;
                    }
                } else if ((cputype == macho::kCpuTypeArm64 || cputype == macho::kCpuTypeArm64_32) &&
                           flavor == kArmExceptionState64) {
                    if (payload_len < 4u * 4u) {
                        thread_warnings.push_back(std::format(
                            "Truncated ARM_EXCEPTION_STATE64 ({} bytes < 16) on thread {}",
                            payload_len, tid));
                    } else {
                        const std::uint64_t far = read_u64_raw(payload, 0u, endian);
                        const std::uint32_t esr = read_u32_raw(payload, 8u, endian);
                        const std::uint32_t exc_num = read_u32_raw(payload, 12u, endian);
                        const std::uint32_t ec = (esr >> 26u) & 0x3Fu;

                        CrashExceptionInfo ex{};
                        ex.thread_id = tid;
                        ex.fault_code = exc_num != 0u ? exc_num : ec;
                        ex.fault_subcode = static_cast<std::int64_t>(esr);
                        ex.fault_name = arm64_exception_fault_name(esr, exc_num);
                        ex.fault_address = far;
                        if (ec == 0x20u || ec == 0x21u || ec == 0x22u) {
                            ex.access_operation = "execute";
                        } else if (ec == 0x24u || ec == 0x25u) {
                            ex.access_operation = ((esr & (1u << 6u)) != 0u) ? "write" : "read";
                        }
                        thread_exc = DecodedExceptionCandidate{
                            .info = std::move(ex),
                            .is_non_zero = (far != 0u || esr != 0u || exc_num != 0u),
                        };
                    }
                } else if (cputype == macho::kCpuTypeArm && flavor == kArmThreadState32) {
                    if (payload_len >= 17u * 4u) {
                        const auto r32 = [&](std::size_t idx) {
                            return read_u32_raw(payload, idx * 4u, endian);
                        };
                        const std::uint32_t fp   = r32(11);
                        const std::uint32_t sp   = r32(13);
                        const std::uint32_t lr   = r32(14);
                        const std::uint32_t pc   = r32(15);
                        const std::uint32_t cpsr = r32(16);

                        ctx.instruction_pointer = pc;
                        ctx.stack_pointer = sp;
                        ctx.frame_pointer = fp;
                        ctx.link_register = lr;
                        ctx.flags_value = cpsr;
                        ctx.decoded_flags = decode_arm_flags_macho(cpsr, true);
                        ctx.registers.push_back(
                            make_macho_reg("pc", RegisterCategory::InstructionPointer, pc, 32u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("sp", RegisterCategory::StackPointer, sp, 32u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("r11", RegisterCategory::FramePointer, fp, 32u, endian));
                        ctx.registers.push_back(
                            make_macho_reg("lr", RegisterCategory::General, lr, 32u, endian));
                        for (std::size_t i = 0u; i <= 12u; ++i) {
                            if (i == 11u) {
                                continue;
                            }
                            ctx.registers.push_back(make_macho_reg(
                                std::format("r{}", i), RegisterCategory::General, r32(i), 32u, endian));
                        }
                        ctx.registers.push_back(
                            make_macho_reg("cpsr", RegisterCategory::Flags, cpsr, 32u, endian));
                        ctx.status = SubsystemStatus::available(
                            "macho_core", "Decoded ARM_THREAD_STATE32 registers");
                        decoded_gpr = true;
                    }
                } else if (flavor != kX86FloatState64) {
                    saw_unsupported_flavor = flavor;
                }

                tcur = state_off + static_cast<std::size_t>(state_bytes_u64);
            }

            ThreadInfo tinfo{};
            tinfo.tid = tid;
            tinfo.name = std::format("thread-{}", tid);
            tinfo.state = ThreadRunState::Stopped;
            tinfo.is_suspended = true;
            if (decoded_gpr) {
                tinfo.instruction_pointer = ctx.instruction_pointer;
                tinfo.stack_pointer = ctx.stack_pointer;
                tinfo.status = ctx.status;
                contexts.emplace(tid, ctx);
            } else {
                const std::string msg = saw_unsupported_flavor != 0u
                    ? std::format("Unsupported LC_THREAD state flavor {} on thread {}",
                                  saw_unsupported_flavor, tid)
                    : std::format("No decodable GPR state in LC_THREAD on thread {}", tid);
                thread_warnings.push_back(msg);
                tinfo.status = SubsystemStatus::partial("macho_core", msg);
                ctx.status = SubsystemStatus::unavailable("macho_core", msg);
                contexts.emplace(tid, ctx);
            }

            if (thread_exc.has_value()) {
                if (decoded_gpr && !thread_exc->info.instruction_pointer.has_value()) {
                    thread_exc->info.instruction_pointer = ctx.instruction_pointer;
                }
                exc_candidates.push_back(std::move(*thread_exc));
            }

            threads.push_back(std::move(tinfo));
        }

        cmd_off += static_cast<std::size_t>(cmdsize);
    }

    std::ranges::sort(core_segments, [](const CoreSegmentEntry& a, const CoreSegmentEntry& b) {
        if (a.vmaddr != b.vmaddr) {
            return a.vmaddr < b.vmaddr;
        }
        return a.vmsize < b.vmsize;
    });
    std::ranges::sort(regions, [](const MemoryRegion& a, const MemoryRegion& b) {
        if (a.start_address != b.start_address) {
            return a.start_address < b.start_address;
        }
        return a.end_address < b.end_address;
    });

    std::optional<CrashExceptionInfo> crash_exc{};
    for (const DecodedExceptionCandidate& cand : exc_candidates) {
        if (cand.is_non_zero) {
            crash_exc = cand.info;
            break;
        }
    }
    if (!crash_exc.has_value() && exc_candidates.size() == 1u) {
        crash_exc = exc_candidates.front().info;
    }
    if (crash_exc.has_value()) {
        std::string desc = std::format(
            "Thread {} faulted with {} (code 0x{:X})",
            crash_exc->thread_id.value_or(1u),
            crash_exc->fault_name,
            crash_exc->fault_code);
        if (!crash_exc->access_operation.empty() && crash_exc->fault_address.has_value()) {
            desc += std::format(
                " attempting {} at 0x{:X}",
                crash_exc->access_operation,
                *crash_exc->fault_address);
        } else if (crash_exc->fault_address.has_value() && *crash_exc->fault_address != 0u) {
            desc += std::format(" at 0x{:X}", *crash_exc->fault_address);
        }
        if (crash_exc->instruction_pointer.has_value()) {
            desc += std::format(" [IP 0x{:X}]", *crash_exc->instruction_pointer);
        }
        crash_exc->description = std::move(desc);

        if (crash_exc->thread_id.has_value()) {
            for (ThreadInfo& t : threads) {
                if (t.tid == *crash_exc->thread_id) {
                    t.wait_channel = "FAULTING THREAD (" + crash_exc->fault_name + ")";
                    break;
                }
            }
        }
    }

    const std::optional<ThreadId> main_tid =
        !threads.empty() ? std::optional<ThreadId>(threads.front().tid) : std::nullopt;
    attribute_thread_stacks(regions, threads, main_tid);

    std::string fallback_name = !source_path.empty()
        ? source_path.filename().string()
        : std::string("macho.core");

    ProcessInfo pinfo{};
    pinfo.pid = 1u;
    pinfo.name = fallback_name;
    pinfo.architecture = arch;
    pinfo.endianness = endian;
    pinfo.is_64bit = is_64;
    pinfo.access = ProcessAccessStatus::ReadOnly;

    ProcessInternalsSnapshot internals{};
    internals.handles = {
        std::nullopt,
        SubsystemStatus::unavailable(
            "macho_core", "Darwin file-descriptor table is not stored in Mach-O MH_CORE segments"),
    };
    internals.sockets = {
        std::nullopt,
        SubsystemStatus::unavailable(
            "macho_core", "Live socket table is not stored in Mach-O MH_CORE dumps"),
    };
    internals.security = {
        std::nullopt,
        SubsystemStatus::unavailable(
            "macho_core", "Darwin task entitlement/codesign token state is not stored in MH_CORE"),
    };

    SubsystemStatus regions_status = mem_warnings.empty()
        ? SubsystemStatus::available("macho_core", "Parsed LC_SEGMENT(_64) virtual memory regions")
        : SubsystemStatus::partial("macho_core", join_notes(mem_warnings));
    SubsystemStatus threads_status = thread_warnings.empty()
        ? SubsystemStatus::available("macho_core", "Parsed LC_THREAD / LC_UNIXTHREAD states")
        : SubsystemStatus::partial("macho_core", join_notes(thread_warnings));

    std::vector<std::string> all_diags;
    all_diags.insert(all_diags.end(), mem_warnings.begin(), mem_warnings.end());
    all_diags.insert(all_diags.end(), thread_warnings.begin(), thread_warnings.end());

    const std::filesystem::path saved_source_path = source_path;
    CrashDumpSummary summary{};
    summary.kind = CrashDumpKind::MachOCore;
    summary.dump_path = std::move(source_path);
    summary.sha256 = sha256_hex(bytes);
    summary.file_size = bytes.size();
    summary.os_summary = "Darwin / macOS (MH_CORE)";
    summary.cpu_summary = std::format(
        "{} ({}, {})",
        is_arm64e ? std::string_view("arm64e") : to_string(arch),
        is_64 ? "64-bit" : "32-bit",
        to_string(endian));
    summary.layout = layout;
    summary.pid = pinfo.pid;
    summary.process_name = std::move(fallback_name);
    summary.exception = std::move(crash_exc);
    summary.thread_count = threads.size();
    summary.region_count = regions.size();
    summary.diagnostics = all_diags;
    summary.status = all_diags.empty()
        ? SubsystemStatus::available("macho_core")
        : SubsystemStatus::partial("macho_core", join_notes(all_diags));

    const std::vector<CoreSegmentEntry> seg_copy = core_segments;
    std::vector<MemoryRegion> reg_copy = regions;
    auto session = std::make_unique<MachOCoreSession>(
        std::move(bytes),
        slice_info->offset,
        slice_info->size,
        std::move(pinfo),
        std::move(summary),
        std::move(core_segments),
        std::move(regions),
        std::vector<ModuleInfo>{},
        std::move(threads),
        std::move(contexts),
        std::move(internals),
        std::move(regions_status),
        SubsystemStatus::available("macho_core"),
        std::move(threads_status));

    discover_mapped_macho_modules(
        *session, seg_copy, std::move(reg_copy), saved_source_path, endian, mod_warnings);

    return session;
}

}  // namespace peelf
