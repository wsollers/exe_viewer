#include "peelf/crash_dump.hpp"

#include "image_internal.hpp"
#include "peelf/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <limits>
#include <unordered_map>
#include <utility>

namespace peelf {
namespace {

constexpr std::uint32_t kMinidumpSignature = 0x504D444Du;  // "MDMP" little-endian
constexpr std::uint16_t kMinidumpVersionLo = 0xA793u;

// MINIDUMP_STREAM_TYPE values
constexpr std::uint32_t kStreamUnused         = 0u;
constexpr std::uint32_t kStreamThreadList     = 3u;
constexpr std::uint32_t kStreamModuleList     = 4u;
constexpr std::uint32_t kStreamMemoryList     = 5u;
constexpr std::uint32_t kStreamException      = 6u;
constexpr std::uint32_t kStreamSystemInfo     = 7u;
constexpr std::uint32_t kStreamThreadExList   = 8u;
constexpr std::uint32_t kStreamMemory64List   = 9u;
constexpr std::uint32_t kStreamHandleData     = 12u;
constexpr std::uint32_t kStreamMiscInfo       = 15u;
constexpr std::uint32_t kStreamMemoryInfoList = 16u;

// Win32 PROCESSOR_ARCHITECTURE_* values
constexpr std::uint16_t kProcArchIntel   = 0u;
constexpr std::uint16_t kProcArchArm     = 5u;
constexpr std::uint16_t kProcArchAmd64   = 9u;
constexpr std::uint16_t kProcArchArm64   = 12u;
constexpr std::uint16_t kProcArchIa32Win64 = 10u;

// Win32 VirtualAlloc state/type/protect constants
constexpr std::uint32_t kMemCommit  = 0x00001000u;
constexpr std::uint32_t kMemReserve = 0x00002000u;
constexpr std::uint32_t kMemFree    = 0x00010000u;

constexpr std::uint32_t kMemPrivate = 0x00020000u;
constexpr std::uint32_t kMemMapped  = 0x00040000u;
constexpr std::uint32_t kMemImage   = 0x01000000u;

constexpr std::uint32_t kPageNoAccess         = 0x01u;
constexpr std::uint32_t kPageReadOnly         = 0x02u;
constexpr std::uint32_t kPageReadWrite        = 0x04u;
constexpr std::uint32_t kPageWriteCopy        = 0x08u;
constexpr std::uint32_t kPageExecute          = 0x10u;
constexpr std::uint32_t kPageExecuteRead      = 0x20u;
constexpr std::uint32_t kPageExecuteReadWrite = 0x40u;
constexpr std::uint32_t kPageExecuteWriteCopy = 0x80u;
constexpr std::uint32_t kPageGuard            = 0x100u;

struct DumpMemorySlice {
    std::uint64_t va_start{0};
    std::uint64_t size{0};
    std::size_t file_offset{0};

    [[nodiscard]] constexpr std::uint64_t va_end() const noexcept {
        return size <= (std::numeric_limits<std::uint64_t>::max() - va_start)
                   ? (va_start + size)
                   : std::numeric_limits<std::uint64_t>::max();
    }
};

[[nodiscard]] bool checked_range(std::size_t total_size,
                                 std::uint64_t offset,
                                 std::uint64_t size) noexcept {
    const auto end = checked_add_u64(offset, size);
    return end.has_value() && *end <= static_cast<std::uint64_t>(total_size);
}

[[nodiscard]] std::string join_stream_diagnostics(std::span<const std::string> notes) {
    std::string out;
    for (std::size_t i = 0u; i < notes.size(); ++i) {
        if (i > 0u) {
            out += "; ";
        }
        out += notes[i];
    }
    return out;
}

[[nodiscard]] std::string basename_win_or_posix(std::string_view full_path) {
    const std::size_t slash = full_path.find_last_of("/\\");
    if (slash == std::string_view::npos) {
        return std::string(full_path);
    }
    return std::string(full_path.substr(slash + 1u));
}

[[nodiscard]] std::optional<std::string> read_minidump_string(const EndianReader& rd,
                                                              std::uint32_t rva) {
    if (rva == 0u || !rd.can_read(rva, 4u)) {
        return std::nullopt;
    }
    const auto byte_len_res = rd.read_u32(rva);
    if (!byte_len_res) {
        return std::nullopt;
    }
    const std::uint32_t byte_len = *byte_len_res;
    if (byte_len > 65536u || !rd.can_read(static_cast<std::size_t>(rva) + 4u, byte_len)) {
        return std::nullopt;
    }
    const std::size_t units = static_cast<std::size_t>(byte_len / 2u);
    const std::size_t base = static_cast<std::size_t>(rva) + 4u;
    return decode_utf16_to_utf8(
        rd.bytes().subspan(base, units * 2u),
        rd.endianness(),
        /*stop_at_nul=*/true,
        units);
}

[[nodiscard]] MemoryProtection decode_win32_protect(std::uint32_t protect,
                                                    std::uint32_t state,
                                                    std::uint32_t mem_type) noexcept {
    MemoryProtection mp{};
    mp.shared = (mem_type == kMemMapped);
    if (state != kMemCommit) {
        return mp;
    }
    if ((protect & kPageGuard) != 0u) {
        mp.guarded = true;
    }
    const std::uint32_t base = protect & 0xFFu;
    switch (base) {
        case kPageReadOnly:
            mp.readable = true;
            break;
        case kPageReadWrite:
        case kPageWriteCopy:
            mp.readable = true;
            mp.writable = true;
            break;
        case kPageExecute:
            mp.executable = true;
            break;
        case kPageExecuteRead:
            mp.readable = true;
            mp.executable = true;
            break;
        case kPageExecuteReadWrite:
        case kPageExecuteWriteCopy:
            mp.readable = true;
            mp.writable = true;
            mp.executable = true;
            break;
        case kPageNoAccess:
        default:
            break;
    }
    return mp;
}

[[nodiscard]] RegisterValue reg_u64(std::string name, RegisterCategory cat, std::uint64_t val) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 64,
        .value_u64 = val,
        .raw_bytes = encode_u64(val, Endianness::Little),
        .formatted = std::format("0x{:016x}", val),
    };
}

[[nodiscard]] RegisterValue reg_u32(std::string name, RegisterCategory cat, std::uint32_t val) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 32,
        .value_u64 = val,
        .raw_bytes = encode_u32(val, Endianness::Little),
        .formatted = std::format("0x{:08x}", val),
    };
}

[[nodiscard]] RegisterValue reg_u16(std::string name, RegisterCategory cat, std::uint16_t val) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 16,
        .value_u64 = val,
        .raw_bytes = encode_u16(val, Endianness::Little),
        .formatted = std::format("0x{:04x}", val),
    };
}

[[nodiscard]] std::vector<FlagBitInfo> decode_x86_eflags(std::uint64_t flags) {
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

[[nodiscard]] std::vector<FlagBitInfo> decode_arm_cpsr(std::uint64_t flags, bool has_thumb_bit) {
    std::vector<FlagBitInfo> out{
        {"N", 31, ((flags >> 31u) & 1ull) != 0ull, "Negative Condition Flag"},
        {"Z", 30, ((flags >> 30u) & 1ull) != 0ull, "Zero Condition Flag"},
        {"C", 29, ((flags >> 29u) & 1ull) != 0ull, "Carry Condition Flag"},
        {"V", 28, ((flags >> 28u) & 1ull) != 0ull, "Overflow Condition Flag"},
    };
    if (has_thumb_bit) {
        out.push_back({"T", 5, ((flags >> 5u) & 1ull) != 0ull, "Thumb Execution State"});
    }
    return out;
}

[[nodiscard]] ThreadContext decode_minidump_thread_context(ThreadId tid,
                                                           TargetLayout layout,
                                                           std::optional<std::uint64_t> teb_va,
                                                           std::span<const std::uint8_t> ctx_bytes) {
    ThreadContext ctx{};
    ctx.tid = tid;
    ctx.layout = layout;
    ctx.teb_address = teb_va;
    ctx.tls_pointer = teb_va;

    const EndianReader rd(ctx_bytes, layout);

    if (layout.architecture == Architecture::X86_64) {
        // Win64 CONTEXT: Rip at +0xF8 requires >= 0x100 bytes.
        if (ctx_bytes.size() < 0x100u) {
            ctx.status = SubsystemStatus::unavailable(
                "minidump", "AMD64 CONTEXT record is truncated (< 256 bytes)");
            return ctx;
        }
        const std::uint64_t rax = rd.read_u64(0x78u).value_or(0);
        const std::uint64_t rcx = rd.read_u64(0x80u).value_or(0);
        const std::uint64_t rdx = rd.read_u64(0x88u).value_or(0);
        const std::uint64_t rbx = rd.read_u64(0x90u).value_or(0);
        const std::uint64_t rsp = rd.read_u64(0x98u).value_or(0);
        const std::uint64_t rbp = rd.read_u64(0xA0u).value_or(0);
        const std::uint64_t rsi = rd.read_u64(0xA8u).value_or(0);
        const std::uint64_t rdi = rd.read_u64(0xB0u).value_or(0);
        const std::uint64_t r8  = rd.read_u64(0xB8u).value_or(0);
        const std::uint64_t r9  = rd.read_u64(0xC0u).value_or(0);
        const std::uint64_t r10 = rd.read_u64(0xC8u).value_or(0);
        const std::uint64_t r11 = rd.read_u64(0xD0u).value_or(0);
        const std::uint64_t r12 = rd.read_u64(0xD8u).value_or(0);
        const std::uint64_t r13 = rd.read_u64(0xE0u).value_or(0);
        const std::uint64_t r14 = rd.read_u64(0xE8u).value_or(0);
        const std::uint64_t r15 = rd.read_u64(0xF0u).value_or(0);
        const std::uint64_t rip = rd.read_u64(0xF8u).value_or(0);
        const std::uint32_t eflags = rd.read_u32(0x44u).value_or(0);

        ctx.instruction_pointer = rip;
        ctx.stack_pointer = rsp;
        ctx.frame_pointer = rbp;
        ctx.flags_value = eflags;
        ctx.decoded_flags = decode_x86_eflags(eflags);

        ctx.registers = {
            reg_u64("rip", RegisterCategory::InstructionPointer, rip),
            reg_u64("rsp", RegisterCategory::StackPointer, rsp),
            reg_u64("rbp", RegisterCategory::FramePointer, rbp),
            reg_u64("rax", RegisterCategory::General, rax),
            reg_u64("rbx", RegisterCategory::General, rbx),
            reg_u64("rcx", RegisterCategory::General, rcx),
            reg_u64("rdx", RegisterCategory::General, rdx),
            reg_u64("rsi", RegisterCategory::General, rsi),
            reg_u64("rdi", RegisterCategory::General, rdi),
            reg_u64("r8",  RegisterCategory::General, r8),
            reg_u64("r9",  RegisterCategory::General, r9),
            reg_u64("r10", RegisterCategory::General, r10),
            reg_u64("r11", RegisterCategory::General, r11),
            reg_u64("r12", RegisterCategory::General, r12),
            reg_u64("r13", RegisterCategory::General, r13),
            reg_u64("r14", RegisterCategory::General, r14),
            reg_u64("r15", RegisterCategory::General, r15),
            reg_u32("eflags", RegisterCategory::Flags, eflags),
            reg_u16("cs", RegisterCategory::SegmentOrTls, rd.read_u16(0x38u).value_or(0)),
            reg_u16("ss", RegisterCategory::SegmentOrTls, rd.read_u16(0x42u).value_or(0)),
        };
        if (teb_va.has_value() && *teb_va != 0u) {
            ctx.registers.push_back(reg_u64("gs_teb", RegisterCategory::SegmentOrTls, *teb_va));
        }
        if (ctx_bytes.size() >= 0x2A0u) {
            for (std::size_t xm = 0; xm < 16u; ++xm) {
                const std::size_t off = 0x1A0u + xm * 16u;
                const auto span = ctx_bytes.subspan(off, 16u);
                std::string hex = "0x";
                for (std::size_t b = 16u; b > 0u; --b) {
                    hex += std::format("{:02x}", span[b - 1u]);
                }
                ctx.registers.push_back(RegisterValue{
                    .name = std::format("xmm{}", xm),
                    .category = RegisterCategory::Vector,
                    .bit_width = 128,
                    .value_u64 = rd.read_u64(off).value_or(0),
                    .raw_bytes = std::vector<std::uint8_t>(span.begin(), span.end()),
                    .formatted = std::move(hex),
                });
            }
        }
        ctx.status = SubsystemStatus::available("minidump", "Decoded AMD64 CONTEXT from minidump");
        return ctx;
    }

    if (layout.architecture == Architecture::X86) {
        if (ctx_bytes.size() < 0xCCu) {
            ctx.status = SubsystemStatus::unavailable(
                "minidump", "x86 CONTEXT record is truncated (< 204 bytes)");
            return ctx;
        }
        const std::uint32_t edi = rd.read_u32(0x9Cu).value_or(0);
        const std::uint32_t esi = rd.read_u32(0xA0u).value_or(0);
        const std::uint32_t ebx = rd.read_u32(0xA4u).value_or(0);
        const std::uint32_t edx = rd.read_u32(0xA8u).value_or(0);
        const std::uint32_t ecx = rd.read_u32(0xACu).value_or(0);
        const std::uint32_t eax = rd.read_u32(0xB0u).value_or(0);
        const std::uint32_t ebp = rd.read_u32(0xB4u).value_or(0);
        const std::uint32_t eip = rd.read_u32(0xB8u).value_or(0);
        const std::uint32_t eflags = rd.read_u32(0xC0u).value_or(0);
        const std::uint32_t esp = rd.read_u32(0xC4u).value_or(0);

        ctx.instruction_pointer = eip;
        ctx.stack_pointer = esp;
        ctx.frame_pointer = ebp;
        ctx.flags_value = eflags;
        ctx.decoded_flags = decode_x86_eflags(eflags);
        ctx.registers = {
            reg_u32("eip", RegisterCategory::InstructionPointer, eip),
            reg_u32("esp", RegisterCategory::StackPointer, esp),
            reg_u32("ebp", RegisterCategory::FramePointer, ebp),
            reg_u32("eax", RegisterCategory::General, eax),
            reg_u32("ebx", RegisterCategory::General, ebx),
            reg_u32("ecx", RegisterCategory::General, ecx),
            reg_u32("edx", RegisterCategory::General, edx),
            reg_u32("esi", RegisterCategory::General, esi),
            reg_u32("edi", RegisterCategory::General, edi),
            reg_u32("eflags", RegisterCategory::Flags, eflags),
            reg_u16("cs", RegisterCategory::SegmentOrTls, static_cast<std::uint16_t>(rd.read_u32(0xBCu).value_or(0))),
            reg_u16("ss", RegisterCategory::SegmentOrTls, static_cast<std::uint16_t>(rd.read_u32(0xC8u).value_or(0))),
            reg_u16("fs", RegisterCategory::SegmentOrTls, static_cast<std::uint16_t>(rd.read_u32(0x90u).value_or(0))),
        };
        if (teb_va.has_value() && *teb_va != 0u) {
            ctx.registers.push_back(reg_u32("fs_teb", RegisterCategory::SegmentOrTls, static_cast<std::uint32_t>(*teb_va)));
        }
        ctx.status = SubsystemStatus::available("minidump", "Decoded x86 CONTEXT from minidump");
        return ctx;
    }

    if (layout.architecture == Architecture::ARM64) {
        if (ctx_bytes.size() < 0x110u) {
            ctx.status = SubsystemStatus::unavailable(
                "minidump", "ARM64 CONTEXT record is truncated (< 272 bytes)");
            return ctx;
        }
        const std::uint32_t cpsr = rd.read_u32(0x04u).value_or(0);
        const std::uint64_t fp   = rd.read_u64(0xF0u).value_or(0);
        const std::uint64_t lr   = rd.read_u64(0xF8u).value_or(0);
        const std::uint64_t sp   = rd.read_u64(0x100u).value_or(0);
        const std::uint64_t pc   = rd.read_u64(0x108u).value_or(0);

        ctx.instruction_pointer = pc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = fp;
        ctx.link_register = lr;
        ctx.flags_value = cpsr;
        ctx.decoded_flags = decode_arm_cpsr(cpsr, false);

        ctx.registers.push_back(reg_u64("pc", RegisterCategory::InstructionPointer, pc));
        ctx.registers.push_back(reg_u64("sp", RegisterCategory::StackPointer, sp));
        ctx.registers.push_back(reg_u64("x29", RegisterCategory::FramePointer, fp));
        ctx.registers.push_back(reg_u64("x30", RegisterCategory::General, lr));
        for (std::size_t i = 0; i <= 28u; ++i) {
            ctx.registers.push_back(
                reg_u64(std::format("x{}", i), RegisterCategory::General, rd.read_u64(0x08u + i * 8u).value_or(0)));
        }
        ctx.registers.push_back(reg_u32("cpsr", RegisterCategory::Flags, cpsr));
        ctx.status = SubsystemStatus::available("minidump", "Decoded ARM64 CONTEXT from minidump");
        return ctx;
    }

    if (layout.architecture == Architecture::ARM) {
        if (ctx_bytes.size() < 0x48u) {
            ctx.status = SubsystemStatus::unavailable(
                "minidump", "ARM CONTEXT record is truncated (< 72 bytes)");
            return ctx;
        }
        const std::uint32_t r11  = rd.read_u32(0x30u).value_or(0);
        const std::uint32_t sp   = rd.read_u32(0x38u).value_or(0);
        const std::uint32_t lr   = rd.read_u32(0x3Cu).value_or(0);
        const std::uint32_t pc   = rd.read_u32(0x40u).value_or(0);
        const std::uint32_t cpsr = rd.read_u32(0x44u).value_or(0);

        ctx.instruction_pointer = pc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = r11;
        ctx.link_register = lr;
        ctx.flags_value = cpsr;
        ctx.decoded_flags = decode_arm_cpsr(cpsr, true);

        ctx.registers.push_back(reg_u32("pc", RegisterCategory::InstructionPointer, pc));
        ctx.registers.push_back(reg_u32("sp", RegisterCategory::StackPointer, sp));
        ctx.registers.push_back(reg_u32("r11", RegisterCategory::FramePointer, r11));
        ctx.registers.push_back(reg_u32("lr", RegisterCategory::General, lr));
        for (std::size_t i = 0; i <= 12u; ++i) {
            if (i == 11u) continue;
            ctx.registers.push_back(
                reg_u32(std::format("r{}", i), RegisterCategory::General, rd.read_u32(0x04u + i * 4u).value_or(0)));
        }
        ctx.registers.push_back(reg_u32("cpsr", RegisterCategory::Flags, cpsr));
        ctx.status = SubsystemStatus::available("minidump", "Decoded ARM CONTEXT from minidump");
        return ctx;
    }

    ctx.status = SubsystemStatus::unavailable("minidump", "Unsupported minidump processor architecture");
    return ctx;
}

[[nodiscard]] ProcessHandleKind classify_win32_handle_type(std::string_view type_name) noexcept {
    if (type_name == "File") return ProcessHandleKind::File;
    if (type_name == "Directory") return ProcessHandleKind::Directory;
    if (type_name == "Key") return ProcessHandleKind::KeyOrRegistry;
    if (type_name == "Process" || type_name == "Thread") return ProcessHandleKind::ProcessOrThread;
    if (type_name == "Mutant" || type_name == "Event" || type_name == "Semaphore" ||
        type_name == "Timer") {
        return ProcessHandleKind::SyncObject;
    }
    if (type_name == "Section") return ProcessHandleKind::Memfd;
    return ProcessHandleKind::Unknown;
}

class MinidumpSession final : public ICrashDumpSession {
public:
    MinidumpSession(std::vector<std::uint8_t> bytes,
                    ProcessInfo info,
                    CrashDumpSummary summary,
                    std::vector<DumpMemorySlice> slices,
                    std::vector<MemoryRegion> regions,
                    std::vector<ModuleInfo> modules,
                    std::vector<ThreadInfo> threads,
                    std::unordered_map<ThreadId, ThreadContext> contexts,
                    ProcessInternalsSnapshot internals,
                    SubsystemStatus regions_status,
                    SubsystemStatus modules_status,
                    SubsystemStatus threads_status)
        : bytes_(std::move(bytes)),
          info_(std::move(info)),
          summary_(std::move(summary)),
          slices_(std::move(slices)),
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
            "minidump", std::format("TID {} has no saved CONTEXT in minidump", tid));
        return missing;
    }

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }

        std::size_t total_copied = 0u;
        std::uint64_t cursor = address;
        while (total_copied < buffer.size()) {
            const auto it = std::upper_bound(
                slices_.begin(),
                slices_.end(),
                cursor,
                [](std::uint64_t addr, const DumpMemorySlice& s) { return addr < s.va_start; });
            if (it == slices_.begin()) {
                break;
            }
            const DumpMemorySlice& slice = *std::prev(it);
            if (cursor < slice.va_start || cursor >= slice.va_end()) {
                break;
            }
            const std::uint64_t delta = cursor - slice.va_start;
            const std::uint64_t avail = slice.size - delta;
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(avail, buffer.size() - total_copied));
            const auto src_off_u64 = checked_add_u64(slice.file_offset, delta);
            if (!src_off_u64.has_value() || !checked_range(bytes_.size(), *src_off_u64, chunk)) {
                break;
            }
            const auto src_off = static_cast<std::size_t>(*src_off_u64);
            std::copy_n(bytes_.data() + src_off, chunk, buffer.data() + total_copied);
            total_copied += chunk;
            const auto next_cursor = checked_add_u64(cursor, chunk);
            if (!next_cursor.has_value()) {
                break;
            }
            cursor = *next_cursor;
        }

        if (total_copied == 0u) {
            return make_error(std::format(
                "minidump has no captured memory bytes at VA 0x{:X}", address));
        }
        return total_copied;
    }

    [[nodiscard]] ForgivingValue<std::uint64_t> process_environment_block_address() override {
        const TargetLayout layout = target_layout();
        const std::uint64_t peb_offset_in_teb = layout.is_64bit() ? 0x60ull : 0x30ull;
        for (const ThreadInfo& th : threads_) {
            if (!th.teb_address.has_value() || *th.teb_address == 0u) {
                continue;
            }
            const auto peb_ptr_va = checked_add_u64(*th.teb_address, peb_offset_in_teb);
            if (!peb_ptr_va.has_value()) {
                continue;
            }
            std::array<std::uint8_t, 8> ptr_buf{};
            const std::size_t ptr_sz = layout.pointer_size();
            auto rd_res = read_memory(*peb_ptr_va,
                                      std::span<std::uint8_t>(ptr_buf.data(), ptr_sz));
            if (rd_res && *rd_res == ptr_sz) {
                const EndianReader rd(std::span<const std::uint8_t>(ptr_buf.data(), ptr_sz), layout);
                if (const auto peb = rd.read_pointer(0); peb && *peb != 0u) {
                    return {
                        *peb,
                        SubsystemStatus::available(
                            "minidump",
                            std::format("Resolved PEB 0x{:X} from TEB 0x{:X}", *peb, *th.teb_address)),
                    };
                }
            }
        }
        return {
            std::nullopt,
            SubsystemStatus::unavailable("minidump", "TEB/PEB memory pages were not captured in minidump"),
        };
    }

private:
    std::vector<std::uint8_t> bytes_;
    ProcessInfo info_;
    CrashDumpSummary summary_;
    std::vector<DumpMemorySlice> slices_;
    std::vector<MemoryRegion> regions_;
    std::vector<ModuleInfo> modules_;
    std::vector<ThreadInfo> threads_;
    std::unordered_map<ThreadId, ThreadContext> contexts_;
    ProcessInternalsSnapshot internals_;
    SubsystemStatus regions_status_{SubsystemStatus::available("minidump")};
    SubsystemStatus modules_status_{SubsystemStatus::available("minidump")};
    SubsystemStatus threads_status_{SubsystemStatus::available("minidump")};
};

}  // namespace

std::string_view windows_exception_code_name(std::uint32_t code) noexcept {
    switch (code) {
        case 0xC0000005u: return "EXCEPTION_ACCESS_VIOLATION";
        case 0xC0000006u: return "EXCEPTION_IN_PAGE_ERROR";
        case 0xC0000008u: return "STATUS_INVALID_HANDLE";
        case 0xC0000017u: return "STATUS_NO_MEMORY";
        case 0xC000001Du: return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case 0xC0000025u: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case 0xC0000026u: return "EXCEPTION_INVALID_DISPOSITION";
        case 0xC000008Cu: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case 0xC000008Du: return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case 0xC000008Eu: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case 0xC0000090u: return "EXCEPTION_FLT_INVALID_OPERATION";
        case 0xC0000094u: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case 0xC0000095u: return "EXCEPTION_INT_OVERFLOW";
        case 0xC0000096u: return "EXCEPTION_PRIV_INSTRUCTION";
        case 0xC00000FDu: return "EXCEPTION_STACK_OVERFLOW";
        case 0xC0000374u: return "STATUS_HEAP_CORRUPTION";
        case 0xC0000409u: return "STATUS_STACK_BUFFER_OVERRUN";
        case 0xC000041Du: return "STATUS_FATAL_USER_CALLBACK_EXCEPTION";
        case 0x80000001u: return "STATUS_GUARD_PAGE_VIOLATION";
        case 0x80000002u: return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case 0x80000003u: return "EXCEPTION_BREAKPOINT";
        case 0x80000004u: return "EXCEPTION_SINGLE_STEP";
        case 0x40000015u: return "STATUS_FATAL_APP_EXIT";
        case 0xE06D7363u: return "CPP_EH_EXCEPTION";
        case 0xE0434352u: return "CLR_MANAGED_EXCEPTION";
        default:          return "WIN32_EXCEPTION";
    }
}

bool is_windows_minidump(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 32u) {
        return false;
    }
    const EndianReader rd(bytes, Endianness::Little, AddressWidth::Bits64);
    const auto sig = rd.read_u32(0);
    const auto ver = rd.read_u32(4);
    return sig.has_value() && *sig == kMinidumpSignature &&
           ver.has_value() && ((*ver & 0xFFFFu) == kMinidumpVersionLo);
}

Result<std::unique_ptr<ICrashDumpSession>> open_minidump_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path) {
    if (!is_windows_minidump(bytes)) {
        return make_error("buffer does not begin with a valid Windows MDMP minidump header");
    }

    const EndianReader rd(bytes, Endianness::Little, AddressWidth::Bits64);
    const std::uint32_t stream_count = rd.read_u32(8u).value_or(0);
    const std::uint32_t dir_rva = rd.read_u32(12u).value_or(0);
    const std::uint32_t timestamp = rd.read_u32(20u).value_or(0);

    if (stream_count > 65536u ||
        !checked_range(bytes.size(), dir_rva, static_cast<std::uint64_t>(stream_count) * 12ull)) {
        return make_error("minidump stream directory exceeds file bounds");
    }

    struct DirEntry {
        std::uint32_t type{0};
        std::uint32_t size{0};
        std::uint32_t rva{0};
    };
    std::vector<DirEntry> streams;
    streams.reserve(stream_count);
    for (std::uint32_t i = 0; i < stream_count; ++i) {
        const std::size_t off = static_cast<std::size_t>(dir_rva) + static_cast<std::size_t>(i) * 12u;
        const std::uint32_t st_type = rd.read_u32(off).value_or(kStreamUnused);
        const std::uint32_t st_size = rd.read_u32(off + 4u).value_or(0);
        const std::uint32_t st_rva  = rd.read_u32(off + 8u).value_or(0);
        if (st_type == kStreamUnused || st_size == 0u) {
            continue;
        }
        if (!checked_range(bytes.size(), st_rva, st_size)) {
            return make_error(std::format(
                "minidump stream type {} (RVA 0x{:X}, size {}) exceeds file bounds",
                st_type, st_rva, st_size));
        }
        streams.push_back(DirEntry{st_type, st_size, st_rva});
    }

    // 1. SystemInfoStream & MiscInfoStream first so TargetLayout & PID are known.
    Architecture arch = Architecture::X86_64;
    bool is_64bit = true;
    std::string os_summary = "Windows";
    std::string cpu_summary = "x86_64";
    ProcessId pid = 0u;
    std::optional<std::uint64_t> proc_user_ns;
    std::optional<std::uint64_t> proc_kernel_ns;

    for (const DirEntry& s : streams) {
        if (s.type == kStreamSystemInfo && s.size >= 24u) {
            const std::uint16_t proc_arch = rd.read_u16(s.rva).value_or(0xFFFFu);
            const std::uint8_t num_cpus = rd.read_u8(static_cast<std::size_t>(s.rva) + 6u).value_or(0);
            const std::uint32_t maj = rd.read_u32(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
            const std::uint32_t min = rd.read_u32(static_cast<std::size_t>(s.rva) + 12u).value_or(0);
            const std::uint32_t bld = rd.read_u32(static_cast<std::size_t>(s.rva) + 16u).value_or(0);
            const std::uint32_t csd_rva = s.size >= 28u
                ? rd.read_u32(static_cast<std::size_t>(s.rva) + 24u).value_or(0)
                : 0u;

            switch (proc_arch) {
                case kProcArchIntel:
                case kProcArchIa32Win64:
                    arch = Architecture::X86;
                    is_64bit = false;
                    cpu_summary = "x86 (32-bit)";
                    break;
                case kProcArchAmd64:
                    arch = Architecture::X86_64;
                    is_64bit = true;
                    cpu_summary = "x86_64 (AMD64)";
                    break;
                case kProcArchArm:
                    arch = Architecture::ARM;
                    is_64bit = false;
                    cpu_summary = "ARM32";
                    break;
                case kProcArchArm64:
                    arch = Architecture::ARM64;
                    is_64bit = true;
                    cpu_summary = "ARM64";
                    break;
                default:
                    arch = Architecture::Unknown;
                    is_64bit = true;
                    cpu_summary = std::format("Arch({})", proc_arch);
                    break;
            }
            if (num_cpus > 0u) {
                cpu_summary += std::format(" ({} cores)", num_cpus);
            }
            os_summary = std::format("Windows {}.{}.{}", maj, min, bld);
            if (const auto csd = read_minidump_string(rd, csd_rva); csd && !csd->empty()) {
                os_summary += " (" + *csd + ")";
            }
        } else if (s.type == kStreamMiscInfo && s.size >= 12u) {
            const std::uint32_t flags1 = rd.read_u32(static_cast<std::size_t>(s.rva) + 4u).value_or(0);
            if ((flags1 & 0x1u) != 0u) {
                pid = rd.read_u32(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
            }
            if ((flags1 & 0x2u) != 0u && s.size >= 24u) {
                proc_user_ns = static_cast<std::uint64_t>(
                    rd.read_u32(static_cast<std::size_t>(s.rva) + 16u).value_or(0)) * 1'000'000'000ull;
                proc_kernel_ns = static_cast<std::uint64_t>(
                    rd.read_u32(static_cast<std::size_t>(s.rva) + 20u).value_or(0)) * 1'000'000'000ull;
            }
        }
    }

    const TargetLayout layout = TargetLayout::from_arch(arch, is_64bit, Endianness::Little);

    std::vector<std::string> mem_warnings;
    std::vector<std::string> mod_warnings;
    std::vector<std::string> thread_warnings;
    std::vector<std::string> handle_warnings;

    // 2. Collect memory slices (`Memory64ListStream` & `MemoryListStream`).
    std::vector<DumpMemorySlice> slices;
    const auto add_slice = [&](std::uint64_t va,
                               std::uint64_t sz,
                               std::uint64_t file_off,
                               std::string_view source_stream) -> bool {
        if (sz == 0u) {
            return true;
        }
        const auto va_end = checked_add_u64(va, sz);
        if (!va_end.has_value()) {
            mem_warnings.push_back(std::format(
                "Skipped {} range at VA 0x{:X} with overflowing size 0x{:X}",
                source_stream, va, sz));
            return false;
        }
        if (!checked_range(bytes.size(), file_off, sz)) {
            mem_warnings.push_back(std::format(
                "Truncated {} range [0x{:X}..0x{:X}) at RVA 0x{:X} exceeds file bounds",
                source_stream, va, *va_end, file_off));
            return false;
        }
        slices.push_back(DumpMemorySlice{
            .va_start = va,
            .size = sz,
            .file_offset = static_cast<std::size_t>(file_off),
        });
        return true;
    };

    for (const DirEntry& s : streams) {
        if (s.type == kStreamMemory64List) {
            if (s.size < 16u) {
                mem_warnings.push_back("Truncated Memory64ListStream header");
                continue;
            }
            const std::uint64_t num_ranges = rd.read_u64(s.rva).value_or(0);
            std::uint64_t data_rva = rd.read_u64(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
            const std::uint64_t max_entries = (s.size - 16u) / 16u;
            if (num_ranges > max_entries) {
                mem_warnings.push_back(std::format(
                    "Truncated Memory64ListStream: header declares {} ranges, stream holds {}",
                    num_ranges, max_entries));
            }
            const std::uint64_t count = std::min<std::uint64_t>(num_ranges, max_entries);
            for (std::uint64_t i = 0; i < count; ++i) {
                const std::size_t desc_off = static_cast<std::size_t>(s.rva) + 16u + static_cast<std::size_t>(i) * 16u;
                const std::uint64_t start_va = rd.read_u64(desc_off).value_or(0);
                const std::uint64_t range_sz = rd.read_u64(desc_off + 8u).value_or(0);
                (void)add_slice(start_va, range_sz, data_rva, "Memory64ListStream");
                const auto next_rva = checked_add_u64(data_rva, range_sz);
                if (!next_rva.has_value()) {
                    mem_warnings.push_back("Memory64ListStream RVA cursor overflowed 64-bit bounds");
                    break;
                }
                data_rva = *next_rva;
            }
        } else if (s.type == kStreamMemoryList) {
            if (s.size < 4u) {
                mem_warnings.push_back("Truncated MemoryListStream header");
                continue;
            }
            const std::uint32_t num_ranges = rd.read_u32(s.rva).value_or(0);
            const std::uint32_t max_entries = (s.size - 4u) / 16u;
            if (num_ranges > max_entries) {
                mem_warnings.push_back(std::format(
                    "Truncated MemoryListStream: header declares {} ranges, stream holds {}",
                    num_ranges, max_entries));
            }
            const std::uint32_t count = std::min(num_ranges, max_entries);
            for (std::uint32_t i = 0; i < count; ++i) {
                const std::size_t desc_off = static_cast<std::size_t>(s.rva) + 4u + static_cast<std::size_t>(i) * 16u;
                const std::uint64_t start_va = rd.read_u64(desc_off).value_or(0);
                const std::uint32_t range_sz = rd.read_u32(desc_off + 8u).value_or(0);
                const std::uint32_t mem_rva  = rd.read_u32(desc_off + 12u).value_or(0);
                (void)add_slice(start_va, range_sz, mem_rva, "MemoryListStream");
            }
        }
    }

    // 3. Parse `ModuleListStream` (`MINIDUMP_MODULE` = 108 bytes under #pragma pack(4)).
    std::vector<ModuleInfo> modules;
    for (const DirEntry& s : streams) {
        if (s.type != kStreamModuleList) {
            continue;
        }
        if (s.size < 4u) {
            mod_warnings.push_back("Truncated ModuleListStream header");
            continue;
        }
        const std::uint32_t num_mods = rd.read_u32(s.rva).value_or(0);
        const std::uint32_t max_mods = (s.size - 4u) / 108u;
        if (num_mods > max_mods) {
            mod_warnings.push_back(std::format(
                "Truncated ModuleListStream: header declares {} modules, stream holds {}",
                num_mods, max_mods));
        }
        const std::uint32_t count = std::min(num_mods, max_mods);
        modules.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t moff = static_cast<std::size_t>(s.rva) + 4u + static_cast<std::size_t>(i) * 108u;
            const std::uint64_t base_va = rd.read_u64(moff).value_or(0);
            const std::uint32_t size_img = rd.read_u32(moff + 8u).value_or(0);
            const std::uint32_t name_rva = rd.read_u32(moff + 20u).value_or(0);
            const auto mod_end = checked_add_u64(base_va, size_img);
            if (!mod_end.has_value()) {
                mod_warnings.push_back(std::format(
                    "Skipped ModuleListStream entry {} at 0x{:X} with overflowing SizeOfImage 0x{:X}",
                    i, base_va, size_img));
                continue;
            }
            const auto mod_path_opt = read_minidump_string(rd, name_rva);
            if (name_rva != 0u && !mod_path_opt.has_value()) {
                mod_warnings.push_back(std::format(
                    "ModuleListStream entry {} at 0x{:X} has truncated ModuleNameRva 0x{:X}",
                    i, base_va, name_rva));
            }
            const std::string mod_path_str = mod_path_opt.value_or("");
            std::string mod_name = basename_win_or_posix(mod_path_str);
            if (mod_name.empty()) {
                mod_name = std::format("module_{:X}.dll", base_va);
            }
            modules.push_back(ModuleInfo{
                .name = std::move(mod_name),
                .path = std::filesystem::path(mod_path_str),
                .base_address = base_va,
                .size = size_img,
                .entry_point = 0u,
                .format = Format::PE,
                .is_main_module = modules.empty(),
            });
        }
    }

    // 4. Parse `ThreadListStream` / `ThreadExListStream`.
    std::vector<ThreadInfo> threads;
    std::unordered_map<ThreadId, ThreadContext> contexts;
    struct ThreadStackHint {
        ThreadId tid{0};
        std::uint64_t start_va{0};
        std::uint64_t end_va{0};
    };
    std::vector<ThreadStackHint> stack_hints;

    for (const DirEntry& s : streams) {
        if (s.type != kStreamThreadList && s.type != kStreamThreadExList) {
            continue;
        }
        if (s.size < 4u) {
            thread_warnings.push_back("Truncated ThreadListStream header");
            continue;
        }
        const std::size_t stride = (s.type == kStreamThreadExList) ? 64u : 48u;
        const std::uint32_t num_threads = rd.read_u32(s.rva).value_or(0);
        const std::uint32_t max_threads = static_cast<std::uint32_t>((s.size - 4u) / stride);
        if (num_threads > max_threads) {
            thread_warnings.push_back(std::format(
                "Truncated ThreadListStream: header declares {} threads, stream holds {}",
                num_threads, max_threads));
        }
        const std::uint32_t count = std::min(num_threads, max_threads);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t toff = static_cast<std::size_t>(s.rva) + 4u + static_cast<std::size_t>(i) * stride;
            const ThreadId tid = rd.read_u32(toff).value_or(0);
            const std::uint32_t suspend_cnt = rd.read_u32(toff + 4u).value_or(0);
            const std::uint64_t teb = rd.read_u64(toff + 16u).value_or(0);
            const std::uint64_t stk_va = rd.read_u64(toff + 24u).value_or(0);
            const std::uint32_t stk_sz = rd.read_u32(toff + 32u).value_or(0);
            const std::uint32_t stk_rva = rd.read_u32(toff + 36u).value_or(0);
            const std::uint32_t ctx_sz = rd.read_u32(toff + 40u).value_or(0);
            const std::uint32_t ctx_rva = rd.read_u32(toff + 44u).value_or(0);

            bool stack_partial = false;
            if (stk_sz > 0u) {
                const auto stk_end = checked_add_u64(stk_va, stk_sz);
                if (!stk_end.has_value()) {
                    stack_partial = true;
                    thread_warnings.push_back(std::format(
                        "Thread {} stack descriptor [0x{:X} + 0x{:X}) overflows 64-bit bounds",
                        tid, stk_va, stk_sz));
                } else if (stk_rva != 0u) {
                    if (add_slice(stk_va, stk_sz, stk_rva, "ThreadListStream.Stack")) {
                        stack_hints.push_back(ThreadStackHint{tid, stk_va, *stk_end});
                    } else {
                        stack_partial = true;
                        thread_warnings.push_back(std::format(
                            "Thread {} stack slice at RVA 0x{:X} is truncated", tid, stk_rva));
                    }
                }
            }

            std::optional<std::uint64_t> opt_teb = (teb != 0u) ? std::optional<std::uint64_t>(teb) : std::nullopt;
            ThreadContext decoded{};
            if (ctx_sz > 0u && checked_range(bytes.size(), ctx_rva, ctx_sz)) {
                decoded = decode_minidump_thread_context(
                    tid,
                    layout,
                    opt_teb,
                    std::span<const std::uint8_t>(bytes.data() + ctx_rva, ctx_sz));
                contexts[tid] = decoded;
            } else if (ctx_sz > 0u) {
                thread_warnings.push_back(std::format(
                    "Thread {} CONTEXT at RVA 0x{:X} (size 0x{:X}) exceeds file bounds",
                    tid, ctx_rva, ctx_sz));
            }

            ThreadInfo tinfo{};
            tinfo.tid = tid;
            tinfo.name = std::format("Thread {}", tid);
            tinfo.state = ThreadRunState::Stopped;
            tinfo.is_suspended = true;
            if (decoded.instruction_pointer != 0u) {
                tinfo.instruction_pointer = decoded.instruction_pointer;
            }
            if (decoded.stack_pointer != 0u) {
                tinfo.stack_pointer = decoded.stack_pointer;
            }
            tinfo.teb_address = opt_teb;
            tinfo.tls_base = opt_teb;
            tinfo.wait_channel = suspend_cnt > 0u ? std::format("Suspended ({})", suspend_cnt) : "Crash Snapshot";
            if (i == 0u) {
                tinfo.user_time_ns = proc_user_ns;
                tinfo.kernel_time_ns = proc_kernel_ns;
            }
            if (stack_partial) {
                tinfo.status = SubsystemStatus::partial(
                    "minidump", "Thread stack or register context descriptor is truncated");
            } else {
                tinfo.status = decoded.status.availability == Availability::Available
                    ? decoded.status
                    : SubsystemStatus::partial("minidump", "Thread listed without full register context");
            }
            threads.push_back(std::move(tinfo));
        }
    }

    // Sort and deduplicate overlapping/duplicate slices (preferring first-seen full slice).
    std::ranges::sort(slices, [](const DumpMemorySlice& a, const DumpMemorySlice& b) {
        if (a.va_start != b.va_start) return a.va_start < b.va_start;
        return a.size > b.size;
    });
    std::vector<DumpMemorySlice> clean_slices;
    clean_slices.reserve(slices.size());
    for (const DumpMemorySlice& sl : slices) {
        if (clean_slices.empty()) {
            clean_slices.push_back(sl);
            continue;
        }
        DumpMemorySlice& prev = clean_slices.back();
        if (sl.va_end() <= prev.va_end()) {
            continue;
        }
        if (sl.va_start < prev.va_end()) {
            const std::uint64_t trim = prev.va_end() - sl.va_start;
            clean_slices.push_back(DumpMemorySlice{
                .va_start = prev.va_end(),
                .size = sl.size - trim,
                .file_offset = sl.file_offset + static_cast<std::size_t>(trim),
            });
        } else {
            clean_slices.push_back(sl);
        }
    }

    const auto captured_bytes_in_span = [&](std::uint64_t start_va, std::uint64_t end_va) -> std::uint64_t {
        std::uint64_t total = 0u;
        for (const DumpMemorySlice& sl : clean_slices) {
            if (sl.va_end() <= start_va) continue;
            if (sl.va_start >= end_va) break;
            const std::uint64_t lo = std::max(start_va, sl.va_start);
            const std::uint64_t hi = std::min(end_va, sl.va_end());
            if (hi > lo) total += (hi - lo);
        }
        return total;
    };

    // 5. Parse `ExceptionStream`.
    std::optional<CrashExceptionInfo> crash_exc;
    for (const DirEntry& s : streams) {
        if (s.type != kStreamException || s.size < 168u) {
            continue;
        }
        const ThreadId exc_tid = rd.read_u32(s.rva).value_or(0);
        const std::uint32_t exc_code = rd.read_u32(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
        const std::uint64_t exc_addr = rd.read_u64(static_cast<std::size_t>(s.rva) + 24u).value_or(0);
        const std::uint32_t num_params = rd.read_u32(static_cast<std::size_t>(s.rva) + 32u).value_or(0);
        const std::uint32_t ctx_sz = rd.read_u32(static_cast<std::size_t>(s.rva) + 160u).value_or(0);
        const std::uint32_t ctx_rva = rd.read_u32(static_cast<std::size_t>(s.rva) + 164u).value_or(0);

        CrashExceptionInfo ex{};
        ex.thread_id = exc_tid;
        ex.fault_code = exc_code;
        ex.fault_name = std::string(windows_exception_code_name(exc_code));
        if (exc_addr != 0u) {
            ex.instruction_pointer = exc_addr;
        }

        if ((exc_code == 0xC0000005u || exc_code == 0xC0000006u) && num_params >= 2u) {
            const std::uint64_t op_flag = rd.read_u64(static_cast<std::size_t>(s.rva) + 40u).value_or(0);
            const std::uint64_t target_va = rd.read_u64(static_cast<std::size_t>(s.rva) + 48u).value_or(0);
            ex.fault_subcode = static_cast<std::int64_t>(op_flag);
            ex.fault_address = target_va;
            if (op_flag == 0u) ex.access_operation = "read";
            else if (op_flag == 1u) ex.access_operation = "write";
            else if (op_flag == 8u) ex.access_operation = "execute (DEP)";
            else ex.access_operation = std::format("op({})", op_flag);
        } else {
            ex.fault_address = (exc_addr != 0u) ? std::optional<std::uint64_t>(exc_addr) : std::nullopt;
        }

        if (ctx_sz > 0u && checked_range(bytes.size(), ctx_rva, ctx_sz)) {
            std::optional<std::uint64_t> known_teb;
            for (const ThreadInfo& t : threads) {
                if (t.tid == exc_tid) {
                    known_teb = t.teb_address;
                    break;
                }
            }
            ThreadContext exc_ctx = decode_minidump_thread_context(
                exc_tid,
                layout,
                known_teb,
                std::span<const std::uint8_t>(bytes.data() + ctx_rva, ctx_sz));
            if (exc_ctx.status.availability == Availability::Available) {
                contexts[exc_tid] = exc_ctx;
                if (!ex.instruction_pointer.has_value() && exc_ctx.instruction_pointer != 0u) {
                    ex.instruction_pointer = exc_ctx.instruction_pointer;
                }
                for (ThreadInfo& t : threads) {
                    if (t.tid == exc_tid) {
                        t.instruction_pointer = exc_ctx.instruction_pointer;
                        t.stack_pointer = exc_ctx.stack_pointer;
                        t.wait_channel = "FAULTING THREAD (" + ex.fault_name + ")";
                        break;
                    }
                }
            }
        } else {
            for (ThreadInfo& t : threads) {
                if (t.tid == exc_tid) {
                    t.wait_channel = "FAULTING THREAD (" + ex.fault_name + ")";
                    if (!ex.instruction_pointer.has_value() && t.instruction_pointer.has_value()) {
                        ex.instruction_pointer = t.instruction_pointer;
                    }
                    break;
                }
            }
        }

        ex.description = std::format("Thread {} faulted with {} (0x{:08X})",
                                     exc_tid, ex.fault_name, exc_code);
        if (!ex.access_operation.empty() && ex.fault_address.has_value()) {
            ex.description += std::format(" attempting {} at 0x{:X}",
                                          ex.access_operation, *ex.fault_address);
        }
        if (ex.instruction_pointer.has_value()) {
            ex.description += std::format(" [IP 0x{:X}]", *ex.instruction_pointer);
        }
        crash_exc = std::move(ex);
        break;
    }

    // 6. Build VMMap `MemoryRegion`s from `MemoryInfoListStream` (or synthesize from slices + modules).
    std::vector<MemoryRegion> regions;
    for (const DirEntry& s : streams) {
        if (s.type != kStreamMemoryInfoList) {
            continue;
        }
        if (s.size < 16u) {
            mem_warnings.push_back("Truncated MemoryInfoListStream header");
            continue;
        }
        const std::uint32_t hdr_sz = rd.read_u32(s.rva).value_or(0);
        const std::uint32_t entry_sz = rd.read_u32(static_cast<std::size_t>(s.rva) + 4u).value_or(0);
        const std::uint64_t num_entries = rd.read_u64(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
        if (hdr_sz < 16u || entry_sz < 48u || hdr_sz > s.size) {
            mem_warnings.push_back("Malformed MemoryInfoListStream header sizes");
            continue;
        }
        const std::uint64_t max_entries = (s.size - hdr_sz) / entry_sz;
        if (num_entries > max_entries) {
            mem_warnings.push_back(std::format(
                "Truncated MemoryInfoListStream: header declares {} entries, stream holds {}",
                num_entries, max_entries));
        }
        const std::uint64_t count = std::min<std::uint64_t>(num_entries, max_entries);
        regions.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t i = 0; i < count; ++i) {
            const std::size_t eoff =
                static_cast<std::size_t>(s.rva) + hdr_sz + static_cast<std::size_t>(i) * entry_sz;
            const std::uint64_t base_addr = rd.read_u64(eoff).value_or(0);
            const std::uint64_t alloc_base = rd.read_u64(eoff + 8u).value_or(0);
            const std::uint64_t reg_size = rd.read_u64(eoff + 24u).value_or(0);
            const std::uint32_t state = rd.read_u32(eoff + 32u).value_or(0);
            const std::uint32_t protect = rd.read_u32(eoff + 36u).value_or(0);
            const std::uint32_t mtype = rd.read_u32(eoff + 40u).value_or(0);
            if (state == kMemFree || reg_size == 0u) {
                continue;
            }
            const auto end_addr = checked_add_u64(base_addr, reg_size);
            if (!end_addr.has_value()) {
                mem_warnings.push_back(std::format(
                    "Skipped MemoryInfoListStream entry at 0x{:X} with overflowing size 0x{:X}",
                    base_addr, reg_size));
                continue;
            }
            MemoryRegion reg{};
            reg.start_address = base_addr;
            reg.end_address = *end_addr;
            reg.protection = decode_win32_protect(protect, state, mtype);
            if (mtype == kMemImage) reg.kind = MemoryRegionKind::Image;
            else if (mtype == kMemMapped) reg.kind = MemoryRegionKind::MappedFile;
            else reg.kind = MemoryRegionKind::Anonymous;

            reg.usage.allocation_base = alloc_base;
            if (state == kMemReserve) {
                reg.usage.is_reserved_only = true;
                reg.usage.committed_bytes = 0u;
                reg.usage.rss_bytes = 0u;
            } else {
                reg.usage.committed_bytes = reg_size;
                const std::uint64_t cap = captured_bytes_in_span(reg.start_address, reg.end_address);
                reg.usage.rss_bytes = cap;
                if (mtype == kMemPrivate) {
                    reg.usage.private_dirty_bytes = cap;
                } else {
                    reg.usage.shared_clean_bytes = cap;
                }
            }
            regions.push_back(std::move(reg));
        }
    }

    if (regions.empty()) {
        for (const DumpMemorySlice& sl : clean_slices) {
            const auto sl_end = checked_add_u64(sl.va_start, sl.size);
            if (!sl_end.has_value()) {
                continue;
            }
            MemoryRegion reg{};
            reg.start_address = sl.va_start;
            reg.end_address = *sl_end;
            reg.protection = MemoryProtection{.readable = true, .writable = true, .executable = false};
            reg.kind = MemoryRegionKind::Anonymous;
            reg.usage.committed_bytes = sl.size;
            reg.usage.rss_bytes = sl.size;
            regions.push_back(std::move(reg));
        }
        for (const ModuleInfo& mod : modules) {
            if (mod.size == 0u) continue;
            const auto mod_end = checked_add_u64(mod.base_address, mod.size);
            if (!mod_end.has_value()) continue;
            bool covered = false;
            for (MemoryRegion& reg : regions) {
                if (reg.start_address >= mod.base_address && reg.end_address <= *mod_end) {
                    reg.kind = MemoryRegionKind::Image;
                    reg.protection.executable = true;
                    reg.protection.writable = false;
                    reg.module_name = mod.name;
                    reg.pathname = mod.path.string();
                    covered = true;
                }
            }
            if (!covered) {
                MemoryRegion mod_reg{};
                mod_reg.start_address = mod.base_address;
                mod_reg.end_address = *mod_end;
                mod_reg.protection = MemoryProtection{.readable = true, .writable = false, .executable = true};
                mod_reg.kind = MemoryRegionKind::Image;
                mod_reg.module_name = mod.name;
                mod_reg.pathname = mod.path.string();
                mod_reg.usage.committed_bytes = mod.size;
                mod_reg.usage.rss_bytes = captured_bytes_in_span(mod.base_address, *mod_end);
                regions.push_back(std::move(mod_reg));
            }
        }
    }

    // Annotate regions with module names & thread stack ownership.
    for (MemoryRegion& reg : regions) {
        for (const ModuleInfo& mod : modules) {
            if (mod.contains(reg.start_address)) {
                reg.kind = MemoryRegionKind::Image;
                reg.module_name = mod.name;
                if (reg.pathname.empty()) {
                    reg.pathname = mod.path.string();
                }
                reg.file_offset = reg.start_address - mod.base_address;
                break;
            }
        }
        for (const ThreadStackHint& sh : stack_hints) {
            if (reg.start_address < sh.end_va && reg.end_address > sh.start_va) {
                reg.kind = MemoryRegionKind::Stack;
                reg.usage.owner_tid = sh.tid;
                if (reg.pathname.empty()) {
                    reg.pathname = std::format("[stack:{}]", sh.tid);
                }
            }
        }
    }
    attribute_thread_stacks(regions, threads);
    std::ranges::sort(regions, [](const MemoryRegion& a, const MemoryRegion& b) {
        return a.start_address < b.start_address;
    });

    // 7. Parse `HandleDataStream` (`StreamType == 12`) when present.
    ProcessInternalsSnapshot internals{};
    std::vector<ProcessHandleEntry> handle_entries;
    bool has_handle_stream = false;
    for (const DirEntry& s : streams) {
        if (s.type != kStreamHandleData) {
            continue;
        }
        if (s.size < 16u) {
            has_handle_stream = true;
            handle_warnings.push_back("Truncated HandleDataStream header");
            continue;
        }
        const std::uint32_t hdr_sz = rd.read_u32(s.rva).value_or(0);
        const std::uint32_t desc_sz = rd.read_u32(static_cast<std::size_t>(s.rva) + 4u).value_or(0);
        const std::uint32_t num_desc = rd.read_u32(static_cast<std::size_t>(s.rva) + 8u).value_or(0);
        if (hdr_sz < 16u || desc_sz < 32u || hdr_sz > s.size) {
            has_handle_stream = true;
            handle_warnings.push_back("Malformed HandleDataStream descriptor header");
            continue;
        }
        has_handle_stream = true;
        const std::uint32_t max_desc = (s.size - hdr_sz) / desc_sz;
        if (num_desc > max_desc) {
            handle_warnings.push_back(std::format(
                "Truncated HandleDataStream: header declares {} handles, stream holds {}",
                num_desc, max_desc));
        }
        const std::uint32_t count = std::min(num_desc, max_desc);
        handle_entries.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t hoff =
                static_cast<std::size_t>(s.rva) + hdr_sz + static_cast<std::size_t>(i) * desc_sz;
            const std::uint64_t hval = rd.read_u64(hoff).value_or(0);
            const std::uint32_t type_rva = rd.read_u32(hoff + 8u).value_or(0);
            const std::uint32_t obj_rva = rd.read_u32(hoff + 12u).value_or(0);
            const std::uint32_t access = rd.read_u32(hoff + 20u).value_or(0);
            std::string type_name = read_minidump_string(rd, type_rva).value_or("Handle");
            std::string obj_name = read_minidump_string(rd, obj_rva).value_or("");
            handle_entries.push_back(ProcessHandleEntry{
                .handle_or_fd = hval,
                .kind = classify_win32_handle_type(type_name),
                .type_name = std::move(type_name),
                .target = std::move(obj_name),
                .access_or_flags = std::format("0x{:08X}", access),
            });
        }
    }
    if (has_handle_stream) {
        internals.total_os_handle_count = static_cast<std::uint32_t>(handle_entries.size());
        internals.handles = {
            handle_entries,
            handle_warnings.empty()
                ? SubsystemStatus::available(
                      "minidump",
                      std::format("Parsed {} handle descriptors from HandleDataStream", handle_entries.size()))
                : SubsystemStatus::partial("minidump", join_stream_diagnostics(handle_warnings)),
        };
    } else {
        internals.handles = {
            std::nullopt,
            SubsystemStatus::unavailable("minidump", "HandleDataStream not present in minidump"),
        };
    }
    internals.sockets = {
        std::nullopt,
        SubsystemStatus::unavailable("minidump", "Live socket table is not stored in Windows minidumps"),
    };
    internals.security = {
        std::nullopt,
        SubsystemStatus::unavailable("minidump", "Process token/mitigation stream not present in minidump"),
    };

    // Probe PE `AddressOfEntryPoint` from captured module header bytes when available.
    for (ModuleInfo& mod : modules) {
        const auto probe_end = checked_add_u64(mod.base_address, 0x200u);
        if (!probe_end.has_value() || (mod.size > 0u && mod.size < 0x200u)) {
            continue;
        }
        for (const DumpMemorySlice& sl : clean_slices) {
            const auto sl_end = checked_add_u64(sl.va_start, sl.size);
            if (!sl_end.has_value()) {
                continue;
            }
            if (mod.base_address >= sl.va_start && *probe_end <= *sl_end) {
                const auto off_u64 = checked_add_u64(sl.file_offset, mod.base_address - sl.va_start);
                if (!off_u64.has_value() || *off_u64 > bytes.size()) {
                    break;
                }
                const auto off = static_cast<std::size_t>(*off_u64);
                if (rd.can_read(off, 0x200u) &&
                    rd.read_u16(off).value_or(0) == 0x5A4Du) {
                    const std::uint32_t lfanew = rd.read_u32(off + 0x3Cu).value_or(0);
                    if (lfanew <= (0x200u - 44u) &&
                        rd.read_u32(off + lfanew).value_or(0) == 0x00004550u) {
                        const std::uint32_t ep_rva = rd.read_u32(off + lfanew + 24u + 16u).value_or(0);
                        if (ep_rva != 0u && (mod.size == 0u || ep_rva < mod.size)) {
                            if (const auto ep_va = checked_add_u64(mod.base_address, ep_rva)) {
                                mod.entry_point = *ep_va;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    std::string proc_name = !modules.empty()
        ? modules.front().name
        : (!source_path.empty() ? source_path.filename().string() : std::string("minidump.dmp"));
    std::filesystem::path exe_path = !modules.empty() ? modules.front().path : std::filesystem::path{};

    ProcessInfo pinfo{};
    pinfo.pid = pid;
    pinfo.name = proc_name;
    pinfo.executable_path = exe_path;
    pinfo.architecture = arch;
    pinfo.endianness = Endianness::Little;
    pinfo.is_64bit = is_64bit;
    pinfo.access = ProcessAccessStatus::ReadOnly;

    SubsystemStatus regions_status = mem_warnings.empty()
        ? SubsystemStatus::available("minidump", "Parsed minidump memory streams")
        : SubsystemStatus::partial("minidump", join_stream_diagnostics(mem_warnings));
    SubsystemStatus modules_status = mod_warnings.empty()
        ? SubsystemStatus::available("minidump", "Parsed ModuleListStream")
        : SubsystemStatus::partial("minidump", join_stream_diagnostics(mod_warnings));
    SubsystemStatus threads_status = thread_warnings.empty()
        ? SubsystemStatus::available("minidump", "Parsed ThreadListStream")
        : SubsystemStatus::partial("minidump", join_stream_diagnostics(thread_warnings));

    std::vector<std::string> all_diags;
    all_diags.insert(all_diags.end(), mem_warnings.begin(), mem_warnings.end());
    all_diags.insert(all_diags.end(), mod_warnings.begin(), mod_warnings.end());
    all_diags.insert(all_diags.end(), thread_warnings.begin(), thread_warnings.end());
    all_diags.insert(all_diags.end(), handle_warnings.begin(), handle_warnings.end());

    CrashDumpSummary summary{};
    summary.kind = CrashDumpKind::WindowsMinidump;
    summary.dump_path = std::move(source_path);
    summary.sha256 = sha256_hex(bytes);
    summary.file_size = bytes.size();
    summary.os_summary = std::move(os_summary);
    summary.cpu_summary = std::move(cpu_summary);
    summary.layout = layout;
    summary.pid = pid;
    summary.process_name = std::move(proc_name);
    summary.timestamp_unix = timestamp;
    summary.exception = std::move(crash_exc);
    summary.module_count = modules.size();
    summary.thread_count = threads.size();
    summary.region_count = regions.size();
    summary.handle_count = handle_entries.size();
    summary.diagnostics = all_diags;
    summary.status = all_diags.empty()
        ? SubsystemStatus::available("minidump")
        : SubsystemStatus::partial("minidump", join_stream_diagnostics(all_diags));

    return std::make_unique<MinidumpSession>(
        std::move(bytes),
        std::move(pinfo),
        std::move(summary),
        std::move(clean_slices),
        std::move(regions),
        std::move(modules),
        std::move(threads),
        std::move(contexts),
        std::move(internals),
        std::move(regions_status),
        std::move(modules_status),
        std::move(threads_status));
}

Result<std::unique_ptr<ICrashDumpSession>> open_crash_dump_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path) {
    if (is_windows_minidump(bytes)) {
        return open_minidump_bytes(std::move(bytes), std::move(source_path));
    }
    if (is_elf_core_dump(bytes)) {
        return open_elf_core_bytes(std::move(bytes), std::move(source_path));
    }
    if (is_macho_core_dump(bytes)) {
        return open_macho_core_bytes(std::move(bytes), std::move(source_path));
    }
    return make_error("file is neither a Windows MDMP minidump, Linux ELF ET_CORE, nor Mach-O MH_CORE dump");
}

Result<std::unique_ptr<ICrashDumpSession>> open_crash_dump_file(
    const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        return make_error("crash dump file does not exist: " + path.string());
    }
    const auto fsize = std::filesystem::file_size(path, ec);
    if (ec || fsize < 28u) {
        return make_error("crash dump file is empty or too small: " + path.string());
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return make_error("failed to open crash dump file: " + path.string());
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(fsize));
    if (!in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        return make_error("failed to read crash dump file: " + path.string());
    }
    return open_crash_dump_bytes(std::move(bytes), path);
}

}  // namespace peelf
