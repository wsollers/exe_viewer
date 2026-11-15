#include "reference_index.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <capstone/capstone.h>

namespace viewer {
std::string_view reference_kind_name(ReferenceKind kind) noexcept {
    switch (kind) {
    case ReferenceKind::Call: return "Call";
    case ReferenceKind::Branch: return "Branch";
    case ReferenceKind::Data: return "Data";
    case ReferenceKind::AddressConstant: return "Address constant";
    }
    return "Unknown";
}
void AnnotationStore::set(std::uint64_t address, std::string name, std::string comment) {
    if (name.empty() && comment.empty()) records_.erase(address);
    else records_.insert_or_assign(address, Annotation{std::move(name), std::move(comment)});
    ++revision_;
}
const Annotation* AnnotationStore::find(std::uint64_t address) const noexcept {
    const auto it = records_.find(address);
    return it == records_.end() ? nullptr : &it->second;
}
namespace {
struct Decoder {
    csh handle = 0;
    ~Decoder() { if (handle) cs_close(&handle); }
};
bool open(Decoder& decoder, peelf::Architecture arch, peelf::Endianness endian, bool thumb) {
    cs_arch target{};
    int mode = endian == peelf::Endianness::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    switch (arch) {
    case peelf::Architecture::X86: target = CS_ARCH_X86; mode = CS_MODE_32; break;
    case peelf::Architecture::X86_64: target = CS_ARCH_X86; mode = CS_MODE_64; break;
    case peelf::Architecture::ARM: target = CS_ARCH_ARM; mode |= thumb ? CS_MODE_THUMB : CS_MODE_ARM; break;
    case peelf::Architecture::ARM64: target = CS_ARCH_ARM64; break;
    case peelf::Architecture::MIPS32: target = CS_ARCH_MIPS; mode |= CS_MODE_MIPS32; break;
    case peelf::Architecture::MIPS64: target = CS_ARCH_MIPS; mode |= CS_MODE_MIPS64; break;
    case peelf::Architecture::PowerPC: target = CS_ARCH_PPC; break;
    case peelf::Architecture::PowerPC64: target = CS_ARCH_PPC; mode |= CS_MODE_64; break;
    case peelf::Architecture::RISCV32: target = CS_ARCH_RISCV; mode |= CS_MODE_RISCV32 | CS_MODE_RISCVC; break;
    case peelf::Architecture::RISCV64: target = CS_ARCH_RISCV; mode |= CS_MODE_RISCV64 | CS_MODE_RISCVC; break;
    default: return false;
    }
    return cs_open(target, static_cast<cs_mode>(mode), &decoder.handle) == CS_ERR_OK &&
           cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
}
bool contains(std::uint64_t start, std::uint64_t size, std::uint64_t value) {
    return value >= start && value - start < std::max<std::uint64_t>(size, 1);
}
}
void ReferenceIndex::add_code(std::span<const std::uint8_t> bytes, std::uint64_t address,
    peelf::Architecture architecture, peelf::Endianness endian, bool thumb) {
    Decoder decoder;
    if (!open(decoder, architecture, endian, thumb)) { incomplete_ = true; return; }
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - address) { incomplete_ = true; return; }
    cs_insn* instruction = cs_malloc(decoder.handle);
    if (!instruction) { incomplete_ = true; return; }
    const auto* data = bytes.data();
    auto remaining = bytes.size();
    auto pc = address;
    while (remaining) {
        if (!cs_disasm_iter(decoder.handle, &data, &remaining, &pc, instruction)) {
            incomplete_ = true;
            const std::size_t alignment = architecture == peelf::Architecture::X86 || architecture == peelf::Architecture::X86_64 ? 1 :
                (architecture == peelf::Architecture::ARM && thumb) || architecture == peelf::Architecture::RISCV32 ||
                architecture == peelf::Architecture::RISCV64 ? 2 : 4;
            const auto skip = std::min(remaining, alignment);
            data += skip; pc += skip; remaining -= skip;
            continue;
        }
        const auto& insn = *instruction;
        const auto& detail = *insn.detail;
        bool call = false, branch = false;
        for (unsigned i = 0; i < detail.groups_count; ++i) {
            call |= detail.groups[i] == CS_GRP_CALL;
            branch |= detail.groups[i] == CS_GRP_JUMP;
        }
        // Capstone's groups are incomplete for some link instructions, and RISC-V
        // JAL/JALR group membership does not distinguish an x0 destination.
        if (architecture == peelf::Architecture::MIPS32 || architecture == peelf::Architecture::MIPS64) {
            call |= insn.id == MIPS_INS_JAL || insn.id == MIPS_INS_JALX || insn.id == MIPS_INS_BAL;
            branch |= insn.id == MIPS_INS_J || insn.id == MIPS_INS_JR;
        }
        if ((architecture == peelf::Architecture::PowerPC || architecture == peelf::Architecture::PowerPC64) &&
            insn.size == 4) {
            std::uint32_t word = 0;
            for (unsigned i = 0; i < 4; ++i)
                word |= static_cast<std::uint32_t>(insn.bytes[i]) << ((endian == peelf::Endianness::Big ? 3 - i : i) * 8);
            const auto opcode = word >> 26;
            if (opcode == 16 || opcode == 18) { branch = true; call = (word & 1) != 0; }
        }
        if (architecture == peelf::Architecture::RISCV32 || architecture == peelf::Architecture::RISCV64) {
            if (insn.id == RISCV_INS_JAL || insn.id == RISCV_INS_JALR) {
                const auto destination = (static_cast<unsigned>(insn.bytes[0]) >> 7) |
                    ((static_cast<unsigned>(insn.bytes[1]) & 0x0F) << 1);
                call = destination != 0;
                branch = true;
            } else if (insn.id == RISCV_INS_C_J || insn.id == RISCV_INS_C_JR) { call = false; branch = true; }
        }
        const auto emit = [&](std::uint64_t target, ReferenceKind kind) {
            for (auto it = records_.rbegin(); it != records_.rend() && it->source == insn.address; ++it)
                if (it->target == target && it->kind == kind) return;
            records_.push_back({insn.address, target, kind,
                std::string(insn.mnemonic) + " " + insn.op_str, {}});
        };
        std::optional<std::uint64_t> immediate;
        const auto scan = [&](const auto& operands, auto immediate_type) {
            for (unsigned i = 0; i < operands.op_count; ++i)
                if (operands.operands[i].type == immediate_type) {
                    immediate = static_cast<std::uint64_t>(operands.operands[i].imm);
                    if (!call && !branch) emit(*immediate, ReferenceKind::AddressConstant);
                }
        };
        switch (architecture) {
        case peelf::Architecture::X86: case peelf::Architecture::X86_64:
            scan(detail.x86, X86_OP_IMM);
            for (unsigned i = 0; i < detail.x86.op_count; ++i) {
                const auto& operand = detail.x86.operands[i];
                if (operand.type != X86_OP_MEM || operand.mem.index != X86_REG_INVALID ||
                    operand.mem.segment != X86_REG_INVALID) continue;
                if (operand.mem.base == X86_REG_RIP || operand.mem.base == X86_REG_EIP) {
                    auto target = insn.address + insn.size + operand.mem.disp;
                    if (operand.mem.base == X86_REG_EIP) target &= 0xFFFFFFFFULL;
                    emit(target, ReferenceKind::Data);
                }
                else if (operand.mem.base == X86_REG_INVALID)
                    emit(static_cast<std::uint64_t>(operand.mem.disp), ReferenceKind::Data);
            }
            break;
        case peelf::Architecture::ARM:
            scan(detail.arm, ARM_OP_IMM);
            for (unsigned i = 0; i < detail.arm.op_count; ++i) {
                const auto& op = detail.arm.operands[i];
                if (op.type == ARM_OP_MEM && op.mem.base == ARM_REG_PC && op.mem.index == ARM_REG_INVALID)
                    emit(((insn.address + (thumb ? 4 : 8)) & ~std::uint64_t{3}) + op.mem.disp, ReferenceKind::Data);
            }
            break;
        case peelf::Architecture::ARM64: scan(detail.arm64, ARM64_OP_IMM); break;
        case peelf::Architecture::MIPS32: case peelf::Architecture::MIPS64: scan(detail.mips, MIPS_OP_IMM); break;
        case peelf::Architecture::PowerPC: case peelf::Architecture::PowerPC64:
            if (insn.id != PPC_INS_BCLR && insn.id != PPC_INS_BCLRL &&
                insn.id != PPC_INS_BCCTR && insn.id != PPC_INS_BCCTRL) scan(detail.ppc, PPC_OP_IMM);
            break;
        case peelf::Architecture::RISCV32: case peelf::Architecture::RISCV64:
            if (insn.id != RISCV_INS_JALR && insn.id != RISCV_INS_C_JR && insn.id != RISCV_INS_C_JALR) {
                scan(detail.riscv, RISCV_OP_IMM);
                if (immediate && (call || branch)) {
                    *immediate += insn.address;
                    if (architecture == peelf::Architecture::RISCV32) *immediate &= 0xFFFFFFFFULL;
                }
            }
            break;
        default: break;
        }
        if ((call || branch) && immediate) emit(*immediate, call ? ReferenceKind::Call : ReferenceKind::Branch);
    }
    scanned_bytes_ += bytes.size() - remaining;
    incomplete_ |= remaining != 0;
    cs_free(instruction, 1);
}
ReferenceIndex ReferenceIndex::build(const peelf::IBinaryImage& image,
    std::span<const std::uint8_t> bytes, bool thumb, std::size_t byte_budget) {
    ReferenceIndex result;
    for (const auto& section : image.sections()) {
        if (!section.executable || !section.file_size) continue;
        if (section.file_offset >= bytes.size()) { result.incomplete_ = true; continue; }
        const auto available = std::min<std::uint64_t>(section.file_size, bytes.size() - section.file_offset);
        const auto count = std::min<std::uint64_t>(available, byte_budget);
        result.incomplete_ |= count < section.file_size;
        result.add_code(bytes.subspan(static_cast<std::size_t>(section.file_offset), static_cast<std::size_t>(count)),
            section.virtual_address, image.architecture(), image.endianness(), thumb);
        byte_budget -= static_cast<std::size_t>(count);
    }
    std::erase_if(result.records_, [&](const Reference& ref) {
        return (ref.kind == ReferenceKind::Data || ref.kind == ReferenceKind::AddressConstant) &&
            !image.virtual_address_to_file_offset(ref.target).has_value();
    });
    for (auto& ref : result.records_) {
        if (ref.kind == ReferenceKind::Call || ref.kind == ReferenceKind::Branch) continue;
        const auto offset = image.virtual_address_to_file_offset(ref.target);
        if (!offset || *offset >= bytes.size()) continue;
        std::string preview;
        const auto limit = std::min<std::size_t>(bytes.size() - *offset, 128);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto ch = bytes[static_cast<std::size_t>(*offset) + i];
            if (!ch) { if (preview.size() >= 4) ref.string_preview = std::move(preview); break; }
            if (ch < 32 || ch > 126) break;
            preview.push_back(static_cast<char>(ch));
        }
    }
    return result;
}
std::vector<const Reference*> ReferenceIndex::incoming(std::uint64_t address, std::uint64_t size) const {
    std::vector<const Reference*> result;
    for (const auto& ref : records_) if (contains(address, size, ref.target)) result.push_back(&ref);
    return result;
}
std::vector<const Reference*> ReferenceIndex::outgoing(std::uint64_t address, std::uint64_t size) const {
    std::vector<const Reference*> result;
    for (const auto& ref : records_) if (contains(address, size, ref.source)) result.push_back(&ref);
    return result;
}
} // namespace viewer
