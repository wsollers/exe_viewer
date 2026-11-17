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

constexpr std::uint16_t kEtCore = 4u;

constexpr std::uint32_t kPtLoad = 1u;
constexpr std::uint32_t kPtNote = 4u;

constexpr std::uint32_t kPfX = 0x1u;
constexpr std::uint32_t kPfW = 0x2u;
constexpr std::uint32_t kPfR = 0x4u;

// ELF PT_NOTE types (`<elf.h>`)
constexpr std::uint32_t kNtPrstatus = 1u;
constexpr std::uint32_t kNtFpregset = 2u;
constexpr std::uint32_t kNtPrpsinfo = 3u;
constexpr std::uint32_t kNtAuxv     = 6u;
constexpr std::uint32_t kNtFile     = 0x46494C45u;  // "FILE"
constexpr std::uint32_t kNtSiginfo  = 0x53494749u;  // "SIGI"

// ELF `e_machine` constants
constexpr std::uint16_t kEm386     = 3u;
constexpr std::uint16_t kEmMips    = 8u;
constexpr std::uint16_t kEmPpc     = 20u;
constexpr std::uint16_t kEmPpc64   = 21u;
constexpr std::uint16_t kEmArm     = 40u;
constexpr std::uint16_t kEmX86_64  = 62u;
constexpr std::uint16_t kEmAarch64 = 183u;
constexpr std::uint16_t kEmRiscv   = 243u;

struct CoreLoadSegment {
    std::uint64_t vaddr{0};
    std::uint64_t memsz{0};
    std::uint64_t filesz{0};
    std::uint64_t file_offset{0};
    std::uint32_t flags{0};

    [[nodiscard]] constexpr std::uint64_t vend() const noexcept {
        return memsz <= (std::numeric_limits<std::uint64_t>::max() - vaddr)
                   ? (vaddr + memsz)
                   : std::numeric_limits<std::uint64_t>::max();
    }
};

struct CoreMappedFileEntry {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0};
    std::uint64_t byte_offset{0};
    std::string filename{};
};

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_align4(std::uint64_t n) noexcept {
    if (n > std::numeric_limits<std::uint64_t>::max() - 3ull ||
        n > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() - 3u)) {
        return std::nullopt;
    }
    return (n + 3ull) & ~std::uint64_t{3u};
}

[[nodiscard]] bool checked_span(std::size_t total,
                                std::uint64_t off,
                                std::uint64_t len) noexcept {
    const auto end = checked_add_u64(off, len);
    return end.has_value() && *end <= static_cast<std::uint64_t>(total);
}

[[nodiscard]] std::string join_diagnostics(std::span<const std::string> notes) {
    std::string out;
    for (std::size_t i = 0u; i < notes.size(); ++i) {
        if (i > 0u) {
            out += "; ";
        }
        out += notes[i];
    }
    return out;
}

[[nodiscard]] std::string trim_nul_and_spaces(std::span<const std::uint8_t> raw) {
    std::size_t end = 0u;
    while (end < raw.size() && raw[end] != 0u) {
        ++end;
    }
    while (end > 0u && (raw[end - 1u] == ' ' || raw[end - 1u] == '\t' ||
                        raw[end - 1u] == '\r' || raw[end - 1u] == '\n')) {
        --end;
    }
    return std::string(reinterpret_cast<const char*>(raw.data()), end);
}

[[nodiscard]] Architecture map_elf_machine(std::uint16_t e_machine, bool is_64bit) noexcept {
    switch (e_machine) {
        case kEm386:     return Architecture::X86;
        case kEmX86_64:  return Architecture::X86_64;
        case kEmArm:     return Architecture::ARM;
        case kEmAarch64: return Architecture::ARM64;
        case kEmRiscv:   return is_64bit ? Architecture::RISCV64 : Architecture::RISCV32;
        case kEmPpc:     return Architecture::PowerPC;
        case kEmPpc64:   return Architecture::PowerPC64;
        case kEmMips:    return is_64bit ? Architecture::MIPS64 : Architecture::MIPS32;
        default:         return Architecture::Unknown;
    }
}

[[nodiscard]] RegisterValue make_reg(std::string name,
                                     RegisterCategory cat,
                                     std::uint64_t val,
                                     TargetLayout layout) {
    if (layout.is_64bit()) {
        return RegisterValue{
            .name = std::move(name),
            .category = cat,
            .bit_width = 64,
            .value_u64 = val,
            .raw_bytes = encode_u64(val, layout.endianness),
            .formatted = std::format("0x{:016x}", val),
        };
    }
    const auto v32 = static_cast<std::uint32_t>(val);
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 32,
        .value_u64 = v32,
        .raw_bytes = encode_u32(v32, layout.endianness),
        .formatted = std::format("0x{:08x}", v32),
    };
}

[[nodiscard]] std::vector<FlagBitInfo> decode_x86_flags_core(std::uint64_t flags) {
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

[[nodiscard]] std::vector<FlagBitInfo> decode_arm_flags_core(std::uint64_t flags, bool include_thumb) {
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

[[nodiscard]] std::string signal_code_description(std::int32_t signo, std::int32_t si_code) {
    if (si_code <= 0) {
        if (si_code == 0) return "SI_USER";
        if (si_code == -6) return "SI_TKILL";
        return std::format("si_code({})", si_code);
    }
    if (signo == 11) {  // SIGSEGV
        if (si_code == 1) return "SEGV_MAPERR (address not mapped)";
        if (si_code == 2) return "SEGV_ACCERR (invalid permissions)";
    } else if (signo == 7) {  // SIGBUS
        if (si_code == 1) return "BUS_ADRALN (invalid alignment)";
        if (si_code == 2) return "BUS_ADRERR (non-existent physical address)";
    } else if (signo == 4) {  // SIGILL
        if (si_code == 1) return "ILL_ILLOPC (illegal opcode)";
        if (si_code == 2) return "ILL_ILLOPN (illegal operand)";
    } else if (signo == 8) {  // SIGFPE
        if (si_code == 1) return "FPE_INTDIV (integer divide by zero)";
        if (si_code == 3) return "FPE_FLTDIV (FP divide by zero)";
    }
    return std::format("code({})", si_code);
}

[[nodiscard]] ThreadContext decode_elf_prstatus_regs(ThreadId tid,
                                                     TargetLayout layout,
                                                     std::span<const std::uint8_t> reg_bytes) {
    ThreadContext ctx{};
    ctx.tid = tid;
    ctx.layout = layout;

    const EndianReader rd(reg_bytes, layout);
    const std::size_t word = layout.pointer_size();
    const auto reg_at = [&](std::size_t idx) -> std::uint64_t {
        return rd.read_pointer(idx * word).value_or(0);
    };

    if (layout.architecture == Architecture::X86_64 && reg_bytes.size() >= 27u * 8u) {
        const std::uint64_t r15    = reg_at(0);
        const std::uint64_t r14    = reg_at(1);
        const std::uint64_t r13    = reg_at(2);
        const std::uint64_t r12    = reg_at(3);
        const std::uint64_t rbp    = reg_at(4);
        const std::uint64_t rbx    = reg_at(5);
        const std::uint64_t r11    = reg_at(6);
        const std::uint64_t r10    = reg_at(7);
        const std::uint64_t r9     = reg_at(8);
        const std::uint64_t r8     = reg_at(9);
        const std::uint64_t rax    = reg_at(10);
        const std::uint64_t rcx    = reg_at(11);
        const std::uint64_t rdx    = reg_at(12);
        const std::uint64_t rsi    = reg_at(13);
        const std::uint64_t rdi    = reg_at(14);
        const std::uint64_t rip    = reg_at(16);
        const std::uint64_t cs     = reg_at(17);
        const std::uint64_t eflags = reg_at(18);
        const std::uint64_t rsp    = reg_at(19);
        const std::uint64_t ss     = reg_at(20);
        const std::uint64_t fs_base = reg_at(21);
        const std::uint64_t gs_base = reg_at(22);

        ctx.instruction_pointer = rip;
        ctx.stack_pointer = rsp;
        ctx.frame_pointer = rbp;
        if (fs_base != 0u) {
            ctx.tls_pointer = fs_base;
        }
        ctx.flags_value = eflags;
        ctx.decoded_flags = decode_x86_flags_core(eflags);
        ctx.registers = {
            make_reg("rip", RegisterCategory::InstructionPointer, rip, layout),
            make_reg("rsp", RegisterCategory::StackPointer, rsp, layout),
            make_reg("rbp", RegisterCategory::FramePointer, rbp, layout),
            make_reg("rax", RegisterCategory::General, rax, layout),
            make_reg("rbx", RegisterCategory::General, rbx, layout),
            make_reg("rcx", RegisterCategory::General, rcx, layout),
            make_reg("rdx", RegisterCategory::General, rdx, layout),
            make_reg("rsi", RegisterCategory::General, rsi, layout),
            make_reg("rdi", RegisterCategory::General, rdi, layout),
            make_reg("r8",  RegisterCategory::General, r8, layout),
            make_reg("r9",  RegisterCategory::General, r9, layout),
            make_reg("r10", RegisterCategory::General, r10, layout),
            make_reg("r11", RegisterCategory::General, r11, layout),
            make_reg("r12", RegisterCategory::General, r12, layout),
            make_reg("r13", RegisterCategory::General, r13, layout),
            make_reg("r14", RegisterCategory::General, r14, layout),
            make_reg("r15", RegisterCategory::General, r15, layout),
            make_reg("eflags", RegisterCategory::Flags, eflags, layout),
            make_reg("fs_base", RegisterCategory::SegmentOrTls, fs_base, layout),
            make_reg("gs_base", RegisterCategory::SegmentOrTls, gs_base, layout),
            make_reg("cs", RegisterCategory::SegmentOrTls, cs, layout),
            make_reg("ss", RegisterCategory::SegmentOrTls, ss, layout),
        };
        ctx.status = SubsystemStatus::available("elf_core", "Decoded x86_64 NT_PRSTATUS registers");
        return ctx;
    }

    if (layout.architecture == Architecture::X86 && reg_bytes.size() >= 17u * 4u) {
        const std::uint64_t ebx    = reg_at(0);
        const std::uint64_t ecx    = reg_at(1);
        const std::uint64_t edx    = reg_at(2);
        const std::uint64_t esi    = reg_at(3);
        const std::uint64_t edi    = reg_at(4);
        const std::uint64_t ebp    = reg_at(5);
        const std::uint64_t eax    = reg_at(6);
        const std::uint64_t eip    = reg_at(12);
        const std::uint64_t xcs    = reg_at(13);
        const std::uint64_t eflags = reg_at(14);
        const std::uint64_t esp    = reg_at(15);
        const std::uint64_t xss    = reg_at(16);

        ctx.instruction_pointer = eip;
        ctx.stack_pointer = esp;
        ctx.frame_pointer = ebp;
        ctx.flags_value = eflags;
        ctx.decoded_flags = decode_x86_flags_core(eflags);
        ctx.registers = {
            make_reg("eip", RegisterCategory::InstructionPointer, eip, layout),
            make_reg("esp", RegisterCategory::StackPointer, esp, layout),
            make_reg("ebp", RegisterCategory::FramePointer, ebp, layout),
            make_reg("eax", RegisterCategory::General, eax, layout),
            make_reg("ebx", RegisterCategory::General, ebx, layout),
            make_reg("ecx", RegisterCategory::General, ecx, layout),
            make_reg("edx", RegisterCategory::General, edx, layout),
            make_reg("esi", RegisterCategory::General, esi, layout),
            make_reg("edi", RegisterCategory::General, edi, layout),
            make_reg("eflags", RegisterCategory::Flags, eflags, layout),
            make_reg("cs", RegisterCategory::SegmentOrTls, xcs, layout),
            make_reg("ss", RegisterCategory::SegmentOrTls, xss, layout),
        };
        ctx.status = SubsystemStatus::available("elf_core", "Decoded x86 NT_PRSTATUS registers");
        return ctx;
    }

    if (layout.architecture == Architecture::ARM64 && reg_bytes.size() >= 34u * 8u) {
        const std::uint64_t fp     = reg_at(29);
        const std::uint64_t lr     = reg_at(30);
        const std::uint64_t sp     = reg_at(31);
        const std::uint64_t pc     = reg_at(32);
        const std::uint64_t pstate = reg_at(33);

        ctx.instruction_pointer = pc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = fp;
        ctx.link_register = lr;
        ctx.flags_value = pstate;
        ctx.decoded_flags = decode_arm_flags_core(pstate, false);
        ctx.registers.push_back(make_reg("pc", RegisterCategory::InstructionPointer, pc, layout));
        ctx.registers.push_back(make_reg("sp", RegisterCategory::StackPointer, sp, layout));
        ctx.registers.push_back(make_reg("x29", RegisterCategory::FramePointer, fp, layout));
        ctx.registers.push_back(make_reg("x30", RegisterCategory::General, lr, layout));
        for (std::size_t i = 0; i <= 28u; ++i) {
            ctx.registers.push_back(make_reg(std::format("x{}", i), RegisterCategory::General, reg_at(i), layout));
        }
        ctx.registers.push_back(make_reg("pstate", RegisterCategory::Flags, pstate, layout));
        ctx.status = SubsystemStatus::available("elf_core", "Decoded AArch64 NT_PRSTATUS registers");
        return ctx;
    }

    if (layout.architecture == Architecture::ARM && reg_bytes.size() >= 17u * 4u) {
        const std::uint64_t fp   = reg_at(11);
        const std::uint64_t sp   = reg_at(13);
        const std::uint64_t lr   = reg_at(14);
        const std::uint64_t pc   = reg_at(15);
        const std::uint64_t cpsr = reg_at(16);

        ctx.instruction_pointer = pc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = fp;
        ctx.link_register = lr;
        ctx.flags_value = cpsr;
        ctx.decoded_flags = decode_arm_flags_core(cpsr, true);
        ctx.registers.push_back(make_reg("pc", RegisterCategory::InstructionPointer, pc, layout));
        ctx.registers.push_back(make_reg("sp", RegisterCategory::StackPointer, sp, layout));
        ctx.registers.push_back(make_reg("r11", RegisterCategory::FramePointer, fp, layout));
        ctx.registers.push_back(make_reg("lr", RegisterCategory::General, lr, layout));
        for (std::size_t i = 0; i <= 12u; ++i) {
            if (i == 11u) continue;
            ctx.registers.push_back(make_reg(std::format("r{}", i), RegisterCategory::General, reg_at(i), layout));
        }
        ctx.registers.push_back(make_reg("cpsr", RegisterCategory::Flags, cpsr, layout));
        ctx.status = SubsystemStatus::available("elf_core", "Decoded ARM32 NT_PRSTATUS registers");
        return ctx;
    }

    if ((layout.architecture == Architecture::RISCV64 || layout.architecture == Architecture::RISCV32) &&
        reg_bytes.size() >= 32u * word) {
        const std::uint64_t pc = reg_at(0);
        const std::uint64_t ra = reg_at(1);
        const std::uint64_t sp = reg_at(2);
        const std::uint64_t tp = reg_at(4);
        const std::uint64_t s0 = reg_at(8);

        ctx.instruction_pointer = pc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = s0;
        ctx.link_register = ra;
        if (tp != 0u) ctx.tls_pointer = tp;
        ctx.registers.push_back(make_reg("pc", RegisterCategory::InstructionPointer, pc, layout));
        ctx.registers.push_back(make_reg("sp", RegisterCategory::StackPointer, sp, layout));
        ctx.registers.push_back(make_reg("s0", RegisterCategory::FramePointer, s0, layout));
        ctx.registers.push_back(make_reg("ra", RegisterCategory::General, ra, layout));
        ctx.registers.push_back(make_reg("tp", RegisterCategory::SegmentOrTls, tp, layout));
        for (std::size_t i = 3; i < 32u; ++i) {
            if (i == 4u || i == 8u) continue;
            ctx.registers.push_back(make_reg(std::format("x{}", i), RegisterCategory::General, reg_at(i), layout));
        }
        ctx.status = SubsystemStatus::available("elf_core", "Decoded RISC-V NT_PRSTATUS registers");
        return ctx;
    }

    if ((layout.architecture == Architecture::PowerPC64 || layout.architecture == Architecture::PowerPC) &&
        reg_bytes.size() >= 37u * word) {
        const std::uint64_t sp  = reg_at(1);
        const std::uint64_t fp  = reg_at(31);
        const std::uint64_t nip = reg_at(32);
        const std::uint64_t msr = reg_at(33);
        const std::uint64_t lr  = reg_at(36);

        ctx.instruction_pointer = nip;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = fp;
        ctx.link_register = lr;
        ctx.flags_value = msr;
        ctx.registers.push_back(make_reg("nip", RegisterCategory::InstructionPointer, nip, layout));
        ctx.registers.push_back(make_reg("r1", RegisterCategory::StackPointer, sp, layout));
        ctx.registers.push_back(make_reg("r31", RegisterCategory::FramePointer, fp, layout));
        ctx.registers.push_back(make_reg("lr", RegisterCategory::General, lr, layout));
        ctx.registers.push_back(make_reg("msr", RegisterCategory::Flags, msr, layout));
        for (std::size_t i = 0; i < 31u; ++i) {
            if (i == 1u) continue;
            ctx.registers.push_back(make_reg(std::format("r{}", i), RegisterCategory::General, reg_at(i), layout));
        }
        ctx.status = SubsystemStatus::available("elf_core", "Decoded PowerPC NT_PRSTATUS registers");
        return ctx;
    }

    if ((layout.architecture == Architecture::MIPS64 || layout.architecture == Architecture::MIPS32) &&
        reg_bytes.size() >= 41u * word) {
        // Linux MIPS `elf_gregset_t`: EF_REG0 = 6, r29(sp)=35, r30(fp)=36, r31(ra)=37, cp0_epc=40
        const std::uint64_t sp  = reg_at(35);
        const std::uint64_t fp  = reg_at(36);
        const std::uint64_t ra  = reg_at(37);
        const std::uint64_t epc = reg_at(40);

        ctx.instruction_pointer = epc;
        ctx.stack_pointer = sp;
        ctx.frame_pointer = fp;
        ctx.link_register = ra;
        ctx.registers.push_back(make_reg("pc", RegisterCategory::InstructionPointer, epc, layout));
        ctx.registers.push_back(make_reg("sp", RegisterCategory::StackPointer, sp, layout));
        ctx.registers.push_back(make_reg("fp", RegisterCategory::FramePointer, fp, layout));
        ctx.registers.push_back(make_reg("ra", RegisterCategory::General, ra, layout));
        for (std::size_t i = 0; i < 32u; ++i) {
            if (i >= 29u) continue;
            ctx.registers.push_back(make_reg(std::format("r{}", i), RegisterCategory::General, reg_at(6u + i), layout));
        }
        ctx.status = SubsystemStatus::available("elf_core", "Decoded MIPS NT_PRSTATUS registers");
        return ctx;
    }

    ctx.status = SubsystemStatus::partial(
        "elf_core", std::format("Raw NT_PRSTATUS register frame ({} bytes)", reg_bytes.size()));
    return ctx;
}

void append_fpregset_summary(ThreadContext& ctx,
                             TargetLayout layout,
                             std::span<const std::uint8_t> fpregs) {
    if (layout.architecture == Architecture::X86_64 && fpregs.size() >= 512u) {
        const EndianReader rd(fpregs, layout);
        const std::uint32_t mxcsr = rd.read_u32(24u).value_or(0);
        ctx.registers.push_back(RegisterValue{
            .name = "mxcsr",
            .category = RegisterCategory::FloatingPoint,
            .bit_width = 32,
            .value_u64 = mxcsr,
            .raw_bytes = encode_u32(mxcsr, layout.endianness),
            .formatted = std::format("0x{:08x}", mxcsr),
        });
        for (std::size_t xm = 0; xm < 16u; ++xm) {
            const std::size_t off = 160u + xm * 16u;
            const auto span = fpregs.subspan(off, 16u);
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
}

class ElfCoreSession final : public ICrashDumpSession {
public:
    ElfCoreSession(std::vector<std::uint8_t> bytes,
                   ProcessInfo info,
                   CrashDumpSummary summary,
                   std::vector<CoreLoadSegment> load_segments,
                   std::vector<CoreMappedFileEntry> mapped_files,
                   std::vector<MemoryRegion> regions,
                   std::vector<ModuleInfo> modules,
                   std::vector<ThreadInfo> threads,
                   std::unordered_map<ThreadId, ThreadContext> contexts,
                   std::vector<std::uint8_t> auxv_bytes,
                   ProcessInternalsSnapshot internals,
                   SubsystemStatus regions_status,
                   SubsystemStatus modules_status,
                   SubsystemStatus threads_status)
        : bytes_(std::move(bytes)),
          info_(std::move(info)),
          summary_(std::move(summary)),
          load_segments_(std::move(load_segments)),
          mapped_files_(std::move(mapped_files)),
          regions_(std::move(regions)),
          modules_(std::move(modules)),
          threads_(std::move(threads)),
          contexts_(std::move(contexts)),
          auxv_bytes_(std::move(auxv_bytes)),
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
            "elf_core", std::format("TID {} has no NT_PRSTATUS note in ELF core dump", tid));
        return missing;
    }

    [[nodiscard]] ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
        if (auxv_bytes_.empty()) {
            return {std::nullopt, SubsystemStatus::unavailable("elf_core", "NT_AUXV note not present in core dump")};
        }
        return {
            auxv_bytes_,
            SubsystemStatus::available("elf_core", std::format("Parsed {} bytes from NT_AUXV", auxv_bytes_.size())),
        };
    }

    [[nodiscard]] ForgivingValue<std::string> proc_status_text() override {
        std::string synth = std::format(
            "Name:\t{}\nPid:\t{}\nPPid:\t{}\nState:\tT (core dump)\nThreads:\t{}\n",
            info_.name, info_.pid, info_.parent_pid, threads_.size());
        if (info_.uid.has_value()) {
            synth += std::format("Uid:\t{}\t{}\t{}\t{}\n", *info_.uid, *info_.uid, *info_.uid, *info_.uid);
        }
        return {
            std::move(synth),
            SubsystemStatus::partial("elf_core", "Synthesized status fields from NT_PRPSINFO"),
        };
    }

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }

        std::size_t total_copied = 0u;
        std::uint64_t cursor = address;

        while (total_copied < buffer.size()) {
            const CoreLoadSegment* seg = find_load_segment(cursor);
            if (seg == nullptr) {
                if (const auto from_disk = try_read_from_nt_file(cursor, buffer.size() - total_copied);
                    from_disk > 0u) {
                    std::copy_n(disk_scratch_.data(), from_disk, buffer.data() + total_copied);
                    total_copied += from_disk;
                    const auto next_cursor = checked_add_u64(cursor, from_disk);
                    if (!next_cursor.has_value()) {
                        break;
                    }
                    cursor = *next_cursor;
                    continue;
                }
                break;
            }
            const std::uint64_t seg_delta = cursor - seg->vaddr;
            const std::uint64_t seg_avail = seg->memsz - seg_delta;
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(seg_avail, buffer.size() - total_copied));

            if (seg_delta < seg->filesz) {
                const std::size_t file_chunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(seg->filesz - seg_delta, want));
                const auto src_off = checked_add_u64(seg->file_offset, seg_delta);
                if (!src_off.has_value() || !checked_span(bytes_.size(), *src_off, file_chunk)) {
                    break;
                }
                std::copy_n(bytes_.data() + static_cast<std::size_t>(*src_off),
                            file_chunk,
                            buffer.data() + total_copied);
                total_copied += file_chunk;
                const auto next_cursor = checked_add_u64(cursor, file_chunk);
                if (!next_cursor.has_value()) {
                    break;
                }
                cursor = *next_cursor;
                continue;
            }

            // `seg_delta >= seg->filesz`:
            // 1. If `NT_FILE` maps `cursor` to an existing local file on disk, hydrate clean
            //    read-only code/rodata bytes omitted by Linux `coredump_filter`!
            if (const auto from_disk = try_read_from_nt_file(cursor, want);
                from_disk > 0u) {
                std::copy_n(disk_scratch_.data(), from_disk, buffer.data() + total_copied);
                total_copied += from_disk;
                const auto next_cursor = checked_add_u64(cursor, from_disk);
                if (!next_cursor.has_value()) {
                    break;
                }
                cursor = *next_cursor;
                continue;
            }

            // 2. If `seg->filesz > 0` (e.g. `.bss` zero tail of a captured RW segment), zero-fill.
            if (seg->filesz > 0u) {
                std::fill_n(buffer.data() + total_copied, want, std::uint8_t{0});
                total_copied += want;
                const auto next_cursor = checked_add_u64(cursor, want);
                if (!next_cursor.has_value()) {
                    break;
                }
                cursor = *next_cursor;
                continue;
            }

            // Uncaptured `p_filesz == 0` segment with no local backing file.
            break;
        }

        if (total_copied == 0u) {
            return make_error(std::format(
                "ELF core dump has no captured memory bytes at VA 0x{:X}", address));
        }
        return total_copied;
    }

    void set_modules_and_regions(std::vector<MemoryRegion> regions,
                                 std::vector<ModuleInfo> modules) {
        regions_ = std::move(regions);
        modules_ = std::move(modules);
        summary_.region_count = regions_.size();
        summary_.module_count = modules_.size();
    }

private:
    [[nodiscard]] const CoreLoadSegment* find_load_segment(std::uint64_t va) const noexcept {
        const auto it = std::upper_bound(
            load_segments_.begin(),
            load_segments_.end(),
            va,
            [](std::uint64_t addr, const CoreLoadSegment& s) { return addr < s.vaddr; });
        if (it == load_segments_.begin()) {
            return nullptr;
        }
        const CoreLoadSegment& cand = *std::prev(it);
        if (va >= cand.vaddr && va < cand.vend()) {
            return &cand;
        }
        return nullptr;
    }

    [[nodiscard]] std::size_t try_read_from_nt_file(std::uint64_t va, std::size_t max_len) {
        for (const CoreMappedFileEntry& mf : mapped_files_) {
            if (va < mf.start_va || va >= mf.end_va || mf.filename.empty()) {
                continue;
            }
            const auto file_off = checked_add_u64(mf.byte_offset, va - mf.start_va);
            if (!file_off.has_value() ||
                *file_off > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
                return 0u;
            }
            std::error_code ec;
            const std::filesystem::path p(strip_deleted_proc_suffix(mf.filename));
            if (!std::filesystem::is_regular_file(p, ec) || ec) {
                return 0u;
            }
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(mf.end_va - va, max_len));
            std::ifstream in(p, std::ios::binary);
            if (!in) {
                return 0u;
            }
            in.seekg(static_cast<std::streamoff>(*file_off), std::ios::beg);
            if (!in) {
                return 0u;
            }
            disk_scratch_.resize(chunk);
            in.read(reinterpret_cast<char*>(disk_scratch_.data()),
                    static_cast<std::streamsize>(chunk));
            const auto got = in.gcount();
            return got > 0 ? static_cast<std::size_t>(got) : 0u;
        }
        return 0u;
    }

    std::vector<std::uint8_t> bytes_;
    ProcessInfo info_;
    CrashDumpSummary summary_;
    std::vector<CoreLoadSegment> load_segments_;
    std::vector<CoreMappedFileEntry> mapped_files_;
    std::vector<MemoryRegion> regions_;
    std::vector<ModuleInfo> modules_;
    std::vector<ThreadInfo> threads_;
    std::unordered_map<ThreadId, ThreadContext> contexts_;
    std::vector<std::uint8_t> auxv_bytes_;
    ProcessInternalsSnapshot internals_;
    SubsystemStatus regions_status_{SubsystemStatus::available("elf_core")};
    SubsystemStatus modules_status_{SubsystemStatus::available("elf_core")};
    SubsystemStatus threads_status_{SubsystemStatus::available("elf_core")};
    std::vector<std::uint8_t> disk_scratch_;
};

}  // namespace

std::string_view posix_signal_name(std::int32_t signo) noexcept {
    switch (signo) {
        case 1:  return "SIGHUP";
        case 2:  return "SIGINT";
        case 3:  return "SIGQUIT";
        case 4:  return "SIGILL";
        case 5:  return "SIGTRAP";
        case 6:  return "SIGABRT";
        case 7:  return "SIGBUS";
        case 8:  return "SIGFPE";
        case 9:  return "SIGKILL";
        case 10: return "SIGUSR1";
        case 11: return "SIGSEGV";
        case 12: return "SIGUSR2";
        case 13: return "SIGPIPE";
        case 14: return "SIGALRM";
        case 15: return "SIGTERM";
        case 16: return "SIGSTKFLT";
        case 17: return "SIGCHLD";
        case 24: return "SIGXCPU";
        case 25: return "SIGXFSZ";
        case 31: return "SIGSYS";
        default: return "SIGNAL";
    }
}

bool is_elf_core_dump(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 52u) {
        return false;
    }
    if (bytes[0] != 0x7Fu || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F') {
        return false;
    }
    const std::uint8_t ei_class = bytes[4];
    const std::uint8_t ei_data = bytes[5];
    if ((ei_class != 1u && ei_class != 2u) || (ei_data != 1u && ei_data != 2u)) {
        return false;
    }
    if (ei_class == 2u && bytes.size() < 64u) {
        return false;
    }
    const Endianness endian = (ei_data == 2u) ? Endianness::Big : Endianness::Little;
    const EndianReader rd(bytes, endian, ei_class == 2u ? AddressWidth::Bits64 : AddressWidth::Bits32);
    const auto e_type = rd.read_u16(16u);
    return e_type.has_value() && *e_type == kEtCore;
}

Result<std::unique_ptr<ICrashDumpSession>> open_elf_core_bytes(
    std::vector<std::uint8_t> bytes,
    std::filesystem::path source_path) {
    if (!is_elf_core_dump(bytes)) {
        return make_error("buffer is not a valid Linux ELF ET_CORE dump");
    }

    const bool is_64 = (bytes[4] == 2u);
    const Endianness endian = (bytes[5] == 2u) ? Endianness::Big : Endianness::Little;
    const EndianReader hdr_rd(bytes, endian, is_64 ? AddressWidth::Bits64 : AddressWidth::Bits32);

    const std::uint16_t e_machine = hdr_rd.read_u16(18u).value_or(0);
    const Architecture arch = map_elf_machine(e_machine, is_64);
    const TargetLayout layout = TargetLayout::from_arch(arch, is_64, endian);
    const EndianReader rd(bytes, layout);

    const std::uint64_t e_phoff = is_64 ? rd.read_u64(32u).value_or(0) : rd.read_u32(28u).value_or(0);
    const std::uint16_t e_phentsize = rd.read_u16(is_64 ? 54u : 42u).value_or(0);
    const std::uint16_t e_phnum_raw = rd.read_u16(is_64 ? 56u : 44u).value_or(0);

    // Handle `PN_XNUM` (`0xFFFF`) extended program-header count in `shdr[0].sh_info` when present.
    std::uint32_t phnum = e_phnum_raw;
    if (e_phnum_raw == 0xFFFFu) {
        const std::uint64_t e_shoff = is_64 ? rd.read_u64(40u).value_or(0) : rd.read_u32(32u).value_or(0);
        const std::size_t sh_info_off = is_64 ? 44u : 28u;
        if (checked_span(bytes.size(), e_shoff, sh_info_off + 4u)) {
            phnum = rd.read_u32(static_cast<std::size_t>(e_shoff) + sh_info_off).value_or(0);
        }
    }

    const std::size_t min_phent = is_64 ? 56u : 32u;
    const auto ph_table_bytes =
        checked_mul_u64(static_cast<std::uint64_t>(phnum), static_cast<std::uint64_t>(e_phentsize));
    if (phnum > 0u && (e_phentsize < min_phent || !ph_table_bytes.has_value() ||
                       !checked_span(bytes.size(), e_phoff, *ph_table_bytes))) {
        return make_error("ELF ET_CORE program header table exceeds file bounds");
    }

    std::vector<CoreLoadSegment> load_segments;
    struct NoteSpan {
        std::size_t offset{0};
        std::size_t size{0};
    };
    std::vector<NoteSpan> note_spans;
    std::vector<std::string> reg_warnings;
    std::vector<std::string> mod_warnings;
    std::vector<std::string> thread_warnings;

    for (std::uint32_t i = 0; i < phnum; ++i) {
        const std::size_t poff = static_cast<std::size_t>(e_phoff) + static_cast<std::size_t>(i) * e_phentsize;
        const std::uint32_t p_type = rd.read_u32(poff).value_or(0);
        std::uint32_t p_flags = 0u;
        std::uint64_t p_offset = 0u;
        std::uint64_t p_vaddr = 0u;
        std::uint64_t p_filesz = 0u;
        std::uint64_t p_memsz = 0u;

        if (is_64) {
            p_flags  = rd.read_u32(poff + 4u).value_or(0);
            p_offset = rd.read_u64(poff + 8u).value_or(0);
            p_vaddr  = rd.read_u64(poff + 16u).value_or(0);
            p_filesz = rd.read_u64(poff + 32u).value_or(0);
            p_memsz  = rd.read_u64(poff + 40u).value_or(0);
        } else {
            p_offset = rd.read_u32(poff + 4u).value_or(0);
            p_vaddr  = rd.read_u32(poff + 8u).value_or(0);
            p_filesz = rd.read_u32(poff + 16u).value_or(0);
            p_memsz  = rd.read_u32(poff + 20u).value_or(0);
            p_flags  = rd.read_u32(poff + 24u).value_or(0);
        }

        if (p_type == kPtLoad && p_memsz > 0u) {
            if (p_filesz > 0u && !checked_span(bytes.size(), p_offset, p_filesz)) {
                return make_error(std::format(
                    "ELF ET_CORE PT_LOAD segment {} (offset 0x{:X}, filesz 0x{:X}) exceeds file bounds",
                    i, p_offset, p_filesz));
            }
            const auto vaddr_end = checked_add_u64(p_vaddr, p_memsz);
            if (!vaddr_end.has_value()) {
                return make_error(std::format(
                    "ELF ET_CORE PT_LOAD segment {} (vaddr 0x{:X}, memsz 0x{:X}) overflows 64-bit address space",
                    i, p_vaddr, p_memsz));
            }
            load_segments.push_back(CoreLoadSegment{
                .vaddr = p_vaddr,
                .memsz = p_memsz,
                .filesz = std::min(p_filesz, p_memsz),
                .file_offset = p_offset,
                .flags = p_flags,
            });
        } else if (p_type == kPtNote && p_filesz >= 12u) {
            if (!checked_span(bytes.size(), p_offset, p_filesz)) {
                return make_error("ELF ET_CORE PT_NOTE segment exceeds file bounds");
            }
            note_spans.push_back(NoteSpan{
                .offset = static_cast<std::size_t>(p_offset),
                .size = static_cast<std::size_t>(p_filesz),
            });
        }
    }

    std::ranges::sort(load_segments, [](const CoreLoadSegment& a, const CoreLoadSegment& b) {
        return a.vaddr < b.vaddr;
    });

    // Parse all `PT_NOTE` entries.
    ProcessId pid = 0u;
    ProcessId ppid = 0u;
    std::optional<std::uint32_t> uid_opt;
    std::string proc_name;
    std::string cmd_line;
    std::vector<ThreadInfo> threads;
    std::unordered_map<ThreadId, ThreadContext> contexts;
    std::optional<ThreadId> last_prstatus_tid;
    std::optional<ThreadId> first_signaled_tid;
    std::int32_t prstatus_signal = 0;
    std::optional<std::int32_t> siginfo_signo;
    std::optional<std::int32_t> siginfo_code;
    std::optional<std::uint64_t> siginfo_addr;
    std::vector<std::uint8_t> auxv_bytes;
    std::vector<CoreMappedFileEntry> mapped_files;

    for (const NoteSpan& ns : note_spans) {
        std::size_t cur = ns.offset;
        const auto end_u64 = checked_add_u64(ns.offset, ns.size);
        if (!end_u64.has_value() || *end_u64 > bytes.size()) {
            return make_error("ELF ET_CORE PT_NOTE span overflows buffer bounds");
        }
        const auto end = static_cast<std::size_t>(*end_u64);
        while (cur <= end && (end - cur) >= 12u) {
            const std::uint32_t namesz = rd.read_u32(cur).value_or(0);
            const std::uint32_t descsz = rd.read_u32(cur + 4u).value_or(0);
            const std::uint32_t ntype  = rd.read_u32(cur + 8u).value_or(0);
            cur += 12u;
            if (namesz > std::numeric_limits<std::uint32_t>::max() - 3u ||
                descsz > std::numeric_limits<std::uint32_t>::max() - 3u) {
                return make_error(std::format(
                    "ELF ET_CORE PT_NOTE entry (namesz=0x{:X}, descsz=0x{:X}) overflows 4-byte note alignment",
                    namesz, descsz));
            }
            const auto name_padded = checked_align4(namesz);
            const auto desc_padded = checked_align4(descsz);
            const auto note_body = (name_padded.has_value() && desc_padded.has_value())
                                       ? checked_add_u64(*name_padded, *desc_padded)
                                       : std::nullopt;
            if (!note_body.has_value()) {
                return make_error("ELF ET_CORE PT_NOTE entry alignment overflows 64-bit bounds");
            }
            const auto rem = static_cast<std::uint64_t>(end - cur);
            if (*name_padded > rem || *desc_padded > (rem - *name_padded)) {
                thread_warnings.push_back(std::format(
                    "Truncated PT_NOTE entry (type 0x{:X}, namesz 0x{:X}, descsz 0x{:X}) exceeds PT_NOTE bounds",
                    ntype, namesz, descsz));
                break;
            }
            const auto name_pad_sz = static_cast<std::size_t>(*name_padded);
            const auto desc_pad_sz = static_cast<std::size_t>(*desc_padded);
            const std::span<const std::uint8_t> desc(bytes.data() + cur + name_pad_sz, descsz);
            const EndianReader drd(desc, layout);
            cur += name_pad_sz + desc_pad_sz;

            if (ntype == kNtPrpsinfo && descsz >= 120u) {
                // Tail-anchored `elf_prpsinfo` decoding (works across 124/128/136-byte 32/64-bit layouts):
                // [descsz - 112] = pr_pid (i32), [descsz - 108] = pr_ppid (i32),
                // [descsz - 96 .. -80] = pr_fname[16], [descsz - 80 .. descsz] = pr_psargs[80].
                const std::size_t pid_off = descsz - 112u;
                pid = drd.read_u32(pid_off).value_or(0);
                ppid = drd.read_u32(pid_off + 4u).value_or(0);
                if (is_64 && pid_off >= 24u) {
                    uid_opt = drd.read_u32(16u).value_or(0);
                } else if (!is_64 && pid_off == 16u) {
                    uid_opt = drd.read_u32(8u).value_or(0);
                } else if (!is_64 && pid_off == 12u) {
                    uid_opt = drd.read_u16(8u).value_or(0);
                }
                proc_name = trim_nul_and_spaces(desc.subspan(descsz - 96u, 16u));
                cmd_line = trim_nul_and_spaces(desc.subspan(descsz - 80u, 80u));
            } else if (ntype == kNtPrstatus) {
                const std::size_t pid_off = is_64 ? 32u : 24u;
                const std::size_t reg_off = is_64 ? 112u : 72u;
                if (descsz < reg_off + layout.pointer_size()) {
                    continue;
                }
                const std::int32_t si_signo = drd.read_i32(0u).value_or(0);
                const std::int16_t cursig = drd.read_i16(12u).value_or(0);
                const ThreadId tid = drd.read_u32(pid_off).value_or(0);
                if (pid == 0u) {
                    pid = tid;
                }
                const std::int32_t eff_sig = (cursig != 0) ? static_cast<std::int32_t>(cursig) : si_signo;
                if (eff_sig != 0 && !first_signaled_tid.has_value()) {
                    first_signaled_tid = tid;
                    prstatus_signal = eff_sig;
                }

                // Subtract trailing `int pr_fpvalid` (+ 4-byte 64-bit pad) if present.
                const std::size_t reg_avail = descsz - reg_off;
                ThreadContext tctx = decode_elf_prstatus_regs(
                    tid, layout, desc.subspan(reg_off, reg_avail));
                contexts[tid] = tctx;
                last_prstatus_tid = tid;

                ThreadInfo tinfo{};
                tinfo.tid = tid;
                tinfo.name = threads.empty() && !proc_name.empty()
                    ? proc_name
                    : std::format("LWP {}", tid);
                tinfo.state = ThreadRunState::Stopped;
                tinfo.is_suspended = true;
                if (tctx.instruction_pointer != 0u) {
                    tinfo.instruction_pointer = tctx.instruction_pointer;
                }
                if (tctx.stack_pointer != 0u) {
                    tinfo.stack_pointer = tctx.stack_pointer;
                }
                tinfo.tls_base = tctx.tls_pointer;
                tinfo.wait_channel = eff_sig != 0
                    ? std::format("{} ({})", posix_signal_name(eff_sig), eff_sig)
                    : std::string("Core Snapshot");
                tinfo.status = tctx.status;
                threads.push_back(std::move(tinfo));
            } else if (ntype == kNtFpregset && last_prstatus_tid.has_value()) {
                if (auto it = contexts.find(*last_prstatus_tid); it != contexts.end()) {
                    append_fpregset_summary(it->second, layout, desc);
                }
            } else if (ntype == kNtAuxv && !desc.empty()) {
                auxv_bytes.assign(desc.begin(), desc.end());
            } else if (ntype == kNtSiginfo && descsz >= 16u) {
                const std::int32_t signo = drd.read_i32(0u).value_or(0);
                const std::int32_t scode = drd.read_i32(8u).value_or(0);
                siginfo_signo = signo;
                siginfo_code = scode;
                const std::size_t addr_off = is_64 ? 16u : 12u;
                if (descsz >= addr_off + layout.pointer_size()) {
                    siginfo_addr = drd.read_pointer(addr_off).value_or(0);
                }
            } else if (ntype == kNtFile && descsz >= 2u * layout.pointer_size()) {
                const std::size_t word = layout.pointer_size();
                const std::uint64_t count = drd.read_pointer(0u).value_or(0);
                const std::uint64_t page_sz = std::max<std::uint64_t>(1u, drd.read_pointer(word).value_or(1u));
                const auto entry_stride = checked_mul_u64(3u, static_cast<std::uint64_t>(word));
                const auto table_bytes = entry_stride.has_value()
                                             ? checked_mul_u64(count, *entry_stride)
                                             : std::nullopt;
                const auto hdr_and_table = table_bytes.has_value()
                                               ? checked_add_u64(2u * static_cast<std::uint64_t>(word), *table_bytes)
                                               : std::nullopt;
                if (count > 0u && (!hdr_and_table.has_value() || *hdr_and_table > desc.size())) {
                    const std::string msg = std::format(
                        "Truncated or overflowing NT_FILE table (count={}, desc_size={})",
                        count, desc.size());
                    reg_warnings.push_back(msg);
                    mod_warnings.push_back(msg);
                } else if (count > 0u && hdr_and_table.has_value() && *table_bytes > 0u) {
                    std::size_t str_cur = static_cast<std::size_t>(*hdr_and_table);
                    mapped_files.reserve(static_cast<std::size_t>(count));
                    for (std::uint64_t i = 0; i < count; ++i) {
                        const std::size_t roff = 2u * word + static_cast<std::size_t>(i) * 3u * word;
                        const std::uint64_t f_start = drd.read_pointer(roff).value_or(0);
                        const std::uint64_t f_end   = drd.read_pointer(roff + word).value_or(0);
                        const std::uint64_t f_pgoff = drd.read_pointer(roff + 2u * word).value_or(0);
                        std::string fname;
                        if (str_cur < desc.size()) {
                            std::size_t nul = str_cur;
                            while (nul < desc.size() && desc[nul] != 0u) {
                                ++nul;
                            }
                            fname.assign(reinterpret_cast<const char*>(desc.data() + str_cur), nul - str_cur);
                            str_cur = (nul < desc.size()) ? (nul + 1u) : desc.size();
                        }
                        if (f_end <= f_start) {
                            continue;
                        }
                        const auto byte_offset = checked_mul_u64(f_pgoff, page_sz);
                        const auto file_end_off = byte_offset.has_value()
                                                      ? checked_add_u64(*byte_offset, f_end - f_start)
                                                      : std::nullopt;
                        if (!file_end_off.has_value()) {
                            const std::string msg = std::format(
                                "Skipped NT_FILE entry [0x{:X}..0x{:X}) with overflowing page_offset*page_size",
                                f_start, f_end);
                            reg_warnings.push_back(msg);
                            mod_warnings.push_back(msg);
                            continue;
                        }
                        mapped_files.push_back(CoreMappedFileEntry{
                            .start_va = f_start,
                            .end_va = f_end,
                            .byte_offset = *byte_offset,
                            .filename = std::move(fname),
                        });
                    }
                }
            }
        }
    }

    // Build `MemoryRegion`s from `PT_LOAD` segments + `NT_FILE` correlation.
    std::vector<MemoryRegion> regions;
    regions.reserve(load_segments.size());
    for (const CoreLoadSegment& seg : load_segments) {
        MemoryRegion reg{};
        reg.start_address = seg.vaddr;
        reg.end_address = seg.vend();
        reg.protection = MemoryProtection{
            .readable = (seg.flags & kPfR) != 0u,
            .writable = (seg.flags & kPfW) != 0u,
            .executable = (seg.flags & kPfX) != 0u,
            .shared = false,
            .guarded = false,
        };
        reg.kind = MemoryRegionKind::Anonymous;
        reg.usage.committed_bytes = seg.memsz;
        reg.usage.rss_bytes = seg.filesz;
        if (reg.protection.writable) {
            reg.usage.private_dirty_bytes = seg.filesz;
        } else {
            reg.usage.private_clean_bytes = seg.filesz;
        }

        for (const CoreMappedFileEntry& mf : mapped_files) {
            if (reg.start_address >= mf.start_va && reg.start_address < mf.end_va) {
                if (const auto reg_foff = checked_add_u64(mf.byte_offset, reg.start_address - mf.start_va)) {
                    reg.pathname = strip_deleted_proc_suffix(mf.filename);
                    reg.file_offset = *reg_foff;
                    reg.kind = MemoryRegionKind::MappedFile;
                }
                break;
            }
        }
        regions.push_back(std::move(reg));
    }

    // Synthesize `MemoryRegion` entries for `NT_FILE` mappings omitted from `PT_LOAD` by Linux
    // `coredump_filter` (e.g. unmodified shared-library `.text`/`.rodata` pages) so VMMap and
    // `derive_modules_from_regions` surface every mapped shared object!
    for (const CoreMappedFileEntry& mf : mapped_files) {
        if (mf.end_va <= mf.start_va || mf.filename.empty()) {
            continue;
        }
        bool covered = false;
        for (const MemoryRegion& existing : regions) {
            if (existing.start_address < mf.end_va && existing.end_address > mf.start_va) {
                covered = true;
                break;
            }
        }
        if (!covered) {
            MemoryRegion synth{};
            synth.start_address = mf.start_va;
            synth.end_address = mf.end_va;
            synth.file_offset = mf.byte_offset;
            synth.pathname = strip_deleted_proc_suffix(mf.filename);
            synth.kind = MemoryRegionKind::MappedFile;
            synth.protection = MemoryProtection{.readable = true};
            synth.usage.committed_bytes = mf.end_va - mf.start_va;
            synth.usage.rss_bytes = 0u;
            regions.push_back(std::move(synth));
        }
    }

    std::ranges::sort(regions, [](const MemoryRegion& a, const MemoryRegion& b) {
        return a.start_address < b.start_address;
    });

    attribute_thread_stacks(regions, threads, pid != 0u ? std::optional<ThreadId>(pid) : std::nullopt);

    // Determine main executable path from `cmd_line` or first mapped executable in `NT_FILE`.
    std::filesystem::path main_exe_path;
    if (!mapped_files.empty()) {
        main_exe_path = std::filesystem::path(strip_deleted_proc_suffix(mapped_files.front().filename));
    }
    if (proc_name.empty()) {
        if (!main_exe_path.empty()) {
            proc_name = main_exe_path.filename().string();
        } else if (!source_path.empty()) {
            proc_name = source_path.filename().string();
        } else {
            proc_name = "core";
        }
    }

    // Build fault / signal `CrashExceptionInfo`.
    std::optional<CrashExceptionInfo> crash_exc;
    const std::int32_t final_signo = siginfo_signo.value_or(prstatus_signal);
    if (final_signo != 0 || !threads.empty()) {
        CrashExceptionInfo ex{};
        ex.thread_id = first_signaled_tid.has_value()
            ? first_signaled_tid
            : (!threads.empty() ? std::optional<ThreadId>(threads.front().tid) : std::nullopt);
        ex.fault_code = static_cast<std::uint64_t>(std::max<std::int32_t>(0, final_signo));
        ex.fault_subcode = siginfo_code.has_value()
            ? std::optional<std::int64_t>(*siginfo_code)
            : std::nullopt;
        ex.fault_name = final_signo != 0
            ? std::string(posix_signal_name(final_signo))
            : std::string("CORE_DUMP");
        if (siginfo_addr.has_value()) {
            ex.fault_address = *siginfo_addr;
        }
        if (siginfo_code.has_value() && final_signo != 0) {
            ex.access_operation = signal_code_description(final_signo, *siginfo_code);
        }
        if (ex.thread_id.has_value()) {
            if (const auto it = contexts.find(*ex.thread_id); it != contexts.end() && it->second.instruction_pointer != 0u) {
                ex.instruction_pointer = it->second.instruction_pointer;
            }
            for (ThreadInfo& t : threads) {
                if (t.tid == *ex.thread_id && final_signo != 0) {
                    t.wait_channel = std::format("FAULTING THREAD ({})", ex.fault_name);
                    break;
                }
            }
        }
        ex.description = std::format(
            "TID {} terminated with {} ({})",
            ex.thread_id.value_or(0),
            ex.fault_name,
            final_signo);
        if (!ex.access_operation.empty()) {
            ex.description += " [" + ex.access_operation + "]";
        }
        if (ex.fault_address.has_value()) {
            ex.description += std::format(" at fault address 0x{:X}", *ex.fault_address);
        }
        if (ex.instruction_pointer.has_value()) {
            ex.description += std::format(" [IP 0x{:X}]", *ex.instruction_pointer);
        }
        crash_exc = std::move(ex);
    }

    ProcessInternalsSnapshot internals{};
    internals.handles = {
        std::nullopt,
        SubsystemStatus::unavailable("elf_core", "Live /proc/<pid>/fd table is not stored in ELF core dumps"),
    };
    internals.sockets = {
        std::nullopt,
        SubsystemStatus::unavailable("elf_core", "Live /proc/net socket table is not stored in ELF core dumps"),
    };
    internals.security = {
        std::nullopt,
        SubsystemStatus::unavailable("elf_core", "Kernel capability/seccomp state not stored in ELF core dumps"),
    };

    ProcessInfo pinfo{};
    pinfo.pid = pid;
    pinfo.parent_pid = ppid;
    pinfo.name = proc_name;
    pinfo.executable_path = main_exe_path;
    pinfo.command_line = cmd_line;
    pinfo.uid = uid_opt;
    pinfo.architecture = arch;
    pinfo.endianness = endian;
    pinfo.is_64bit = is_64;
    pinfo.access = ProcessAccessStatus::ReadOnly;

    SubsystemStatus regions_status = reg_warnings.empty()
        ? SubsystemStatus::available("elf_core", "Parsed PT_LOAD and NT_FILE mappings")
        : SubsystemStatus::partial("elf_core", join_diagnostics(reg_warnings));
    SubsystemStatus modules_status = mod_warnings.empty()
        ? SubsystemStatus::available("elf_core", "Derived modules from NT_FILE mappings")
        : SubsystemStatus::partial("elf_core", join_diagnostics(mod_warnings));
    SubsystemStatus threads_status = thread_warnings.empty()
        ? SubsystemStatus::available("elf_core", "Parsed NT_PRSTATUS thread notes")
        : SubsystemStatus::partial("elf_core", join_diagnostics(thread_warnings));

    std::vector<std::string> all_diags;
    all_diags.insert(all_diags.end(), reg_warnings.begin(), reg_warnings.end());
    all_diags.insert(all_diags.end(), mod_warnings.begin(), mod_warnings.end());
    all_diags.insert(all_diags.end(), thread_warnings.begin(), thread_warnings.end());

    CrashDumpSummary summary{};
    summary.kind = CrashDumpKind::ElfCore;
    summary.dump_path = std::move(source_path);
    summary.sha256 = sha256_hex(bytes);
    summary.file_size = bytes.size();
    summary.os_summary = std::format("Linux ELF{} ({})",
                                     is_64 ? "64" : "32",
                                     endian == Endianness::Big ? "Big-Endian" : "Little-Endian");
    summary.cpu_summary = std::string(to_string(arch));
    summary.layout = layout;
    summary.pid = pid;
    summary.parent_pid = ppid;
    summary.process_name = proc_name;
    summary.command_line = cmd_line;
    summary.exception = std::move(crash_exc);
    summary.thread_count = threads.size();
    summary.diagnostics = all_diags;
    summary.status = all_diags.empty()
        ? SubsystemStatus::available("elf_core")
        : SubsystemStatus::partial("elf_core", join_diagnostics(all_diags));

    auto session = std::make_unique<ElfCoreSession>(
        std::move(bytes),
        std::move(pinfo),
        std::move(summary),
        std::move(load_segments),
        std::move(mapped_files),
        std::vector<MemoryRegion>{},
        std::vector<ModuleInfo>{},
        std::move(threads),
        std::move(contexts),
        std::move(auxv_bytes),
        std::move(internals),
        std::move(regions_status),
        std::move(modules_status),
        std::move(threads_status));

    // Derive `ModuleInfo` entries from `NT_FILE`-annotated regions and probe ELF headers in dump memory!
    std::vector<ModuleInfo> modules = derive_modules_from_regions(
        regions, main_exe_path.string(), session.get());
    session->set_modules_and_regions(std::move(regions), std::move(modules));
    return session;
}

}  // namespace peelf
