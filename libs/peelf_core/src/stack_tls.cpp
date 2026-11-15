#include "peelf/stack_tls.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] constexpr std::uint64_t align_up_u64(std::uint64_t value,
                                                   std::uint64_t align) noexcept {
    if (align <= 1ull) {
        return value;
    }
    if ((align & (align - 1ull)) == 0ull) {
        return (value + align - 1ull) & ~(align - 1ull);
    }
    const std::uint64_t rem = value % align;
    return rem == 0ull ? value : (value + (align - rem));
}

[[nodiscard]] constexpr bool is_link_register_arch(Architecture arch) noexcept {
    switch (arch) {
        case Architecture::ARM:
        case Architecture::ARM64:
        case Architecture::RISCV32:
        case Architecture::RISCV64:
        case Architecture::PowerPC:
        case Architecture::PowerPC64:
        case Architecture::MIPS32:
        case Architecture::MIPS64:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] TargetLayout resolve_effective_layout(const ThreadContext& context,
                                                    const IProcessSession& session,
                                                    const IBinaryImage* active_image) noexcept {
    TargetLayout layout = context.layout;
    if (layout.architecture == Architecture::Unknown) {
        const TargetLayout sess_layout = session.target_layout();
        if (sess_layout.architecture != Architecture::Unknown) {
            layout = sess_layout;
        } else if (active_image != nullptr) {
            layout = TargetLayout::from_arch(
                active_image->architecture(), active_image->is_64bit(), active_image->endianness());
        }
    }
    return layout;
}

struct StackBounds {
    std::uint64_t start{0};
    std::uint64_t end{0};
    bool from_regions{false};
};

[[nodiscard]] StackBounds locate_stack_bounds(std::uint64_t sp,
                                              std::span<const MemoryRegion> regions,
                                              std::size_t max_slots,
                                              std::size_t ptr_size) noexcept {
    for (std::size_t i = 0; i < regions.size(); ++i) {
        if (!regions[i].contains(sp)) {
            continue;
        }
        std::uint64_t start = regions[i].start_address;
        std::uint64_t end = regions[i].end_address;

        // Coalesce contiguous readable non-image stack sub-VMAs split by page permissions.
        std::size_t lo = i;
        while (lo > 0) {
            const MemoryRegion& prev = regions[lo - 1];
            if (prev.end_address == start && prev.protection.readable && !prev.protection.guarded &&
                prev.kind != MemoryRegionKind::Image) {
                start = prev.start_address;
                --lo;
            } else {
                break;
            }
        }
        std::size_t hi = i + 1;
        while (hi < regions.size()) {
            const MemoryRegion& next = regions[hi];
            if (next.start_address == end && next.protection.readable && !next.protection.guarded &&
                next.kind != MemoryRegionKind::Image) {
                end = next.end_address;
                ++hi;
            } else {
                break;
            }
        }
        return StackBounds{start, end, true};
    }

    // Nearest stack-classified region above SP if SP stepped slightly into red-zone / growth page.
    for (const MemoryRegion& reg : regions) {
        if (reg.kind == MemoryRegionKind::Stack && sp <= reg.start_address &&
            (reg.start_address - sp) <= 16384ull) {
            return StackBounds{sp, reg.end_address, true};
        }
    }

    const std::uint64_t fallback_span =
        std::max<std::uint64_t>(static_cast<std::uint64_t>(max_slots) * ptr_size, 65536ull);
    const std::uint64_t end =
        (sp > UINT64_MAX - fallback_span) ? UINT64_MAX : (sp + fallback_span);
    return StackBounds{sp, end, false};
}

class StackMemoryView {
public:
    StackMemoryView(IProcessSession& session,
                    TargetLayout layout,
                    std::span<const MemoryRegion> regions,
                    StackBounds bounds,
                    std::uint64_t sp,
                    std::size_t max_slots)
        : session_(session),
          layout_(layout),
          bounds_(bounds),
          window_base_(sp) {
        const std::size_t ptr_size = layout_.pointer_size();
        const std::uint64_t avail = bounds_.end > sp ? (bounds_.end - sp) : 0ull;
        const std::uint64_t want_slots = std::max<std::size_t>(max_slots, 512u);
        const std::uint64_t want_bytes = want_slots * static_cast<std::uint64_t>(ptr_size);
        const auto read_len = static_cast<std::size_t>(
            std::min<std::uint64_t>(avail, std::min<std::uint64_t>(want_bytes, 131072ull)));
        if (read_len > 0) {
            MemorySample sample = read_memory_tolerant(session_, regions, sp, read_len);
            if (sample.readable_count > 0) {
                std::size_t usable_len = sample.bytes.size();
                while (usable_len > 0 && sample.valid[usable_len - 1] == 0u) {
                    --usable_len;
                }
                usable_len = (usable_len / ptr_size) * ptr_size;
                sample.bytes.resize(usable_len);
                window_bytes_ = std::move(sample.bytes);
                readable_count_ = sample.readable_count;
            }
        }
    }

    [[nodiscard]] std::span<const std::uint8_t> window_bytes() const noexcept {
        return window_bytes_;
    }

    [[nodiscard]] std::size_t readable_count() const noexcept { return readable_count_; }

    [[nodiscard]] std::optional<std::uint64_t> read_pointer(std::uint64_t addr) const {
        const std::size_t ptr_size = layout_.pointer_size();
        if (addr < bounds_.start || addr > bounds_.end || (bounds_.end - addr) < ptr_size) {
            return std::nullopt;
        }
        if (addr >= window_base_ &&
            (addr - window_base_) + ptr_size <= window_bytes_.size()) {
            const EndianReader reader(window_bytes_, layout_);
            const auto res = reader.read_pointer(static_cast<std::size_t>(addr - window_base_));
            return res ? std::optional<std::uint64_t>{*res} : std::nullopt;
        }
        std::array<std::uint8_t, 8> buf{};
        const auto slice = std::span<std::uint8_t>(buf.data(), ptr_size);
        const auto got = session_.read_memory(addr, slice);
        if (!got || *got < ptr_size) {
            return std::nullopt;
        }
        const EndianReader reader(slice, layout_);
        const auto res = reader.read_pointer(0);
        return res ? std::optional<std::uint64_t>{*res} : std::nullopt;
    }

private:
    IProcessSession& session_;
    TargetLayout layout_;
    StackBounds bounds_;
    std::uint64_t window_base_{0};
    std::vector<std::uint8_t> window_bytes_;
    std::size_t readable_count_{0};
};

[[nodiscard]] bool is_executable_address(std::uint64_t addr,
                                         const StackBounds& stack_bounds,
                                         std::span<const MemoryRegion> regions,
                                         std::span<const ModuleInfo> modules,
                                         const IBinaryImage* active_image) noexcept {
    if (addr == 0) {
        return false;
    }
    if (addr >= stack_bounds.start && addr < stack_bounds.end) {
        return false;
    }

    bool matched_region = false;
    for (const MemoryRegion& reg : regions) {
        if (reg.contains(addr)) {
            matched_region = true;
            if (reg.protection.executable) {
                return true;
            }
        }
    }

    if (active_image != nullptr) {
        for (const Section& sec : active_image->sections()) {
            const std::uint64_t sec_len = std::max(sec.virtual_size, sec.file_size);
            if (addr >= sec.virtual_address && (addr - sec.virtual_address) < sec_len) {
                if (sec.executable) {
                    return true;
                }
                matched_region = true;
            }
        }
    }

    if (!matched_region) {
        for (const ModuleInfo& mod : modules) {
            if (mod.contains(addr)) {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] bool check_post_call_address(IProcessSession& session,
                                           const TargetLayout& layout,
                                           std::uint64_t ret_addr) {
    if (ret_addr < 8ull) {
        return false;
    }

    std::array<std::uint8_t, 8> prev{};
    const auto got = session.read_memory(ret_addr - 8ull, prev);
    if (!got || *got < 8u) {
        // Code pages unreadable (e.g., synthetic stack-only mock session or execute-only page):
        // allow executable-region membership to stand.
        return true;
    }
    const bool all_zero = std::ranges::all_of(prev, [](std::uint8_t b) { return b == 0u; });
    if (all_zero) {
        return true;
    }

    switch (layout.architecture) {
        case Architecture::X86:
        case Architecture::X86_64: {
            // E8 rel32 (5 bytes)
            if (prev[3] == 0xE8u) {
                return true;
            }
            // FF /2 indirect call variants:
            // 2 bytes: FF D0..D7 (call reg) or FF 10..17 (call [reg], mod=00)
            if (prev[6] == 0xFFu && ((prev[7] & 0x38u) == 0x10u)) {
                return true;
            }
            // 3 bytes: REX + FF D0..D7, FF 50..57 disp8, or FF 14 sib
            if (prev[5] == 0xFFu && ((prev[6] & 0x38u) == 0x10u)) {
                return true;
            }
            if ((prev[5] & 0xF0u) == 0x40u && prev[6] == 0xFFu && ((prev[7] & 0x38u) == 0x10u)) {
                return true;
            }
            // 4 bytes: REX + FF 50..57 disp8 / SIB+disp8
            if (prev[4] == 0xFFu && ((prev[5] & 0x38u) == 0x10u)) {
                return true;
            }
            if ((prev[4] & 0xF0u) == 0x40u && prev[5] == 0xFFu && ((prev[6] & 0x38u) == 0x10u)) {
                return true;
            }
            // 6 bytes: FF 15 disp32 (RIP-relative call) or FF 90..97 disp32
            if (prev[2] == 0xFFu && ((prev[3] & 0x38u) == 0x10u)) {
                return true;
            }
            // 7 bytes: REX/SIB + disp32 indirect call
            if (prev[1] == 0xFFu && ((prev[2] & 0x38u) == 0x10u)) {
                return true;
            }
            if ((prev[1] & 0xF0u) == 0x40u && prev[2] == 0xFFu && ((prev[3] & 0x38u) == 0x10u)) {
                return true;
            }
            // 9A ptr16:32 far call on x86
            if (layout.architecture == Architecture::X86 && prev[1] == 0x9Au) {
                return true;
            }
            return false;
        }
        case Architecture::ARM64: {
            const EndianReader er(prev, layout);
            const std::uint32_t insn = er.read_u32(4u).value_or(0u);
            // BL imm26 (0x94000000) or BLR Rn (0xD63F0000) or BLRAA/BLRAB
            return (insn & 0xFC000000u) == 0x94000000u ||
                   (insn & 0xFFFFFC1Fu) == 0xD63F0000u ||
                   (insn & 0xFEFFF800u) == 0xD63F0800u;
        }
        case Architecture::ARM: {
            const EndianReader er(prev, layout);
            const std::uint32_t insn = er.read_u32(4u).value_or(0u);
            // ARM BL / BLX imm / BLX Rm, or Thumb 32-bit BL/BLX
            if ((insn & 0x0F000000u) == 0x0B000000u ||
                (insn & 0xFE000000u) == 0xFA000000u ||
                (insn & 0x0FFFFFF0u) == 0x012FFF30u) {
                return true;
            }
            const std::uint16_t hw1 = er.read_u16(4u).value_or(0u);
            const std::uint16_t hw2 = er.read_u16(6u).value_or(0u);
            return ((hw1 & 0xF800u) == 0xF000u && (hw2 & 0xC000u) == 0xC000u) ||
                   (hw2 & 0xFF80u) == 0x4780u;
        }
        case Architecture::RISCV32:
        case Architecture::RISCV64: {
            const EndianReader er(prev, layout);
            const std::uint32_t insn32 = er.read_u32(4u).value_or(0u);
            const std::uint32_t opcode = insn32 & 0x7Fu;
            if (opcode == 0x6Fu || opcode == 0x67u) {
                return true;
            }
            // Compressed C.JAL / C.JALR
            const std::uint16_t insn16 = er.read_u16(6u).value_or(0u);
            return (insn16 & 0xE003u) == 0x2001u || (insn16 & 0xF07Fu) == 0x9002u;
        }
        default:
            return true;
    }
}

[[nodiscard]] const ModuleInfo* find_module_for_va(std::uint64_t va,
                                                   std::span<const ModuleInfo> modules) noexcept {
    for (const ModuleInfo& mod : modules) {
        if (mod.contains(va)) {
            return &mod;
        }
    }
    return nullptr;
}

[[nodiscard]] std::optional<std::pair<std::string, std::uint64_t>> lookup_image_symbol(
    const IBinaryImage* image,
    std::uint64_t va) {
    if (image == nullptr || va == 0) {
        return std::nullopt;
    }
    constexpr std::uint8_t kSttFunc = 2u;
    constexpr std::uint8_t kSttSection = 3u;
    constexpr std::uint8_t kSttFile = 4u;
    constexpr std::uint8_t kSttTls = 6u;

    const Symbol* best = nullptr;
    std::uint64_t best_dist = UINT64_MAX;
    for (const Symbol& sym : image->symbols()) {
        if (sym.name.empty() || sym.virtual_address == 0 || sym.virtual_address > va) {
            continue;
        }
        if (image->format() == Format::ELF &&
            (sym.type == kSttSection || sym.type == kSttFile || sym.type == kSttTls)) {
            continue;
        }
        const std::uint64_t dist = va - sym.virtual_address;
        if (sym.size > 0 && dist >= sym.size) {
            continue;
        }
        if (dist > 0x100000ull) {
            continue;
        }
        if (dist < best_dist ||
            (dist == best_dist && best != nullptr && sym.type == kSttFunc &&
             best->type != kSttFunc)) {
            best = &sym;
            best_dist = dist;
        }
    }
    if (best == nullptr) {
        return std::nullopt;
    }
    return std::make_pair(best->name, best_dist);
}

void split_resolved_symbol_text(std::string_view resolved,
                                std::string& out_name,
                                std::uint64_t& out_offset) {
    const std::size_t plus = resolved.rfind("+0x");
    if (plus != std::string_view::npos && plus > 0) {
        const std::string_view hex_part = resolved.substr(plus + 3u);
        std::uint64_t parsed = 0;
        bool valid_hex = !hex_part.empty();
        for (const char ch : hex_part) {
            parsed <<= 4u;
            if (ch >= '0' && ch <= '9') {
                parsed |= static_cast<std::uint64_t>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                parsed |= static_cast<std::uint64_t>(ch - 'a' + 10);
            } else if (ch >= 'A' && ch <= 'F') {
                parsed |= static_cast<std::uint64_t>(ch - 'A' + 10);
            } else {
                valid_hex = false;
                break;
            }
        }
        if (valid_hex) {
            out_name = std::string(resolved.substr(0, plus));
            out_offset = parsed;
            return;
        }
    }
    out_name = std::string(resolved);
    out_offset = 0;
}

void populate_frame_metadata(StackFrame& frame,
                             std::span<const ModuleInfo> modules,
                             const IBinaryImage* active_image,
                             const AddressSymbolResolver& symbol_resolver) {
    const ModuleInfo* mod = find_module_for_va(frame.instruction_pointer, modules);
    if (mod != nullptr) {
        frame.module_name = mod->name;
    }

    if (symbol_resolver) {
        const std::string resolved = symbol_resolver(frame.instruction_pointer);
        if (!resolved.empty()) {
            split_resolved_symbol_text(resolved, frame.symbol_name, frame.symbol_offset);
            return;
        }
    }

    if (const auto img_sym = lookup_image_symbol(active_image, frame.instruction_pointer)) {
        frame.symbol_name = img_sym->first;
        frame.symbol_offset = img_sym->second;
        return;
    }

    if (mod != nullptr) {
        frame.symbol_offset = frame.instruction_pointer - mod->base_address;
    }
}

[[nodiscard]] std::string resolve_address_label(std::uint64_t va,
                                                std::span<const ModuleInfo> modules,
                                                const IBinaryImage* active_image,
                                                const AddressSymbolResolver& symbol_resolver) {
    if (va == 0) {
        return {};
    }
    if (symbol_resolver) {
        const std::string res = symbol_resolver(va);
        if (!res.empty()) {
            return res;
        }
    }
    if (const auto img_sym = lookup_image_symbol(active_image, va)) {
        if (img_sym->second == 0) {
            return img_sym->first;
        }
        return std::format("{}+0x{:x}", img_sym->first, img_sym->second);
    }
    if (const ModuleInfo* mod = find_module_for_va(va, modules)) {
        return std::format("{}+0x{:x}", mod->name, va - mod->base_address);
    }
    return {};
}

struct PeUnwindStep {
    std::uint64_t return_address{0};
    std::uint64_t caller_rsp{0};
    std::uint64_t caller_rbp{0};
    std::optional<std::uint64_t> return_address_slot;
    std::optional<std::uint64_t> saved_fp_slot;
};

[[nodiscard]] const PeRuntimeFunction* find_pe_runtime_function(
    const std::vector<PeRuntimeFunction>& table,
    std::uint32_t lookup_rva) noexcept {
    for (const PeRuntimeFunction& rf : table) {
        if (lookup_rva >= rf.begin_address_rva && lookup_rva < rf.end_address_rva) {
            return &rf;
        }
    }
    return nullptr;
}

[[nodiscard]] std::optional<PeUnwindStep> try_pe_x64_pdata_unwind(
    IProcessSession& session,
    const StackMemoryView& stack_mem,
    const IBinaryImage* active_image,
    std::uint64_t current_ip,
    std::uint64_t current_rsp,
    std::uint64_t current_rbp,
    bool is_top_frame) {
    if (active_image == nullptr || active_image->format() != Format::PE ||
        active_image->architecture() != Architecture::X86_64) {
        return std::nullopt;
    }

    const auto& rfs = active_image->pe_runtime_functions();
    if (rfs.empty()) {
        return std::nullopt;
    }

    const std::uint64_t img_base = active_image->image_base();
    const std::uint64_t lookup_va =
        (!is_top_frame && current_ip > img_base) ? (current_ip - 1ull) : current_ip;
    if (lookup_va < img_base || (lookup_va - img_base) > 0xFFFFFFFFull) {
        return std::nullopt;
    }

    const auto lookup_rva = static_cast<std::uint32_t>(lookup_va - img_base);
    const PeRuntimeFunction* rf = find_pe_runtime_function(rfs, lookup_rva);
    if (rf == nullptr) {
        return std::nullopt;
    }

    std::uint64_t rsp = current_rsp;
    std::uint64_t rbp = current_rbp;
    std::optional<std::uint64_t> saved_fp_slot;
    bool machframe_handled = false;
    std::uint64_t machframe_rip = 0;
    std::optional<std::uint64_t> machframe_ret_slot;

    PeRuntimeFunction cur_rf = *rf;
    std::uint64_t cur_ip_offset =
        current_ip >= (img_base + cur_rf.begin_address_rva)
            ? (current_ip - (img_base + cur_rf.begin_address_rva))
            : 0ull;

    const TargetLayout le64 =
        TargetLayout::from_arch(Architecture::X86_64, true, Endianness::Little);

    for (std::size_t chain_depth = 0; chain_depth < 16u; ++chain_depth) {
        std::uint32_t unwind_rva = cur_rf.unwind_info_rva;
        // Bit 0 set in UnwindInfoAddress means an indirect RUNTIME_FUNCTION entry.
        if ((unwind_rva & 1u) != 0u) {
            std::array<std::uint8_t, 12> ind_buf{};
            const auto got = session.read_memory(img_base + (unwind_rva & ~1u), ind_buf);
            if (!got || *got < 12u) {
                return std::nullopt;
            }
            const EndianReader er(ind_buf, le64);
            cur_rf.begin_address_rva = er.read_u32(0).value_or(0);
            cur_rf.end_address_rva = er.read_u32(4).value_or(0);
            cur_rf.unwind_info_rva = er.read_u32(8).value_or(0);
            cur_ip_offset = 0xFFFFull;
            continue;
        }

        std::array<std::uint8_t, 532> uw_buf{};
        const auto got = session.read_memory(img_base + unwind_rva, uw_buf);
        if (!got || *got < 4u) {
            return std::nullopt;
        }
        const std::span<const std::uint8_t> uw_span(uw_buf.data(), *got);
        const EndianReader er(uw_span, le64);

        const std::uint8_t ver_flags = er.read_u8(0).value_or(0);
        const std::uint8_t version = ver_flags & 0x07u;
        const std::uint8_t flags = static_cast<std::uint8_t>((ver_flags >> 3u) & 0x1Fu);
        if (version != 1u && version != 2u) {
            return std::nullopt;
        }

        const std::uint8_t count_of_codes = er.read_u8(2).value_or(0);
        const std::uint8_t frame_reg_off = er.read_u8(3).value_or(0);
        const std::uint8_t frame_reg = frame_reg_off & 0x0Fu;
        const std::uint64_t frame_scaled_off =
            static_cast<std::uint64_t>((frame_reg_off >> 4u) & 0x0Fu) * 16ull;

        const std::size_t codes_bytes = static_cast<std::size_t>(count_of_codes) * 2u;
        if (4u + codes_bytes > uw_span.size()) {
            return std::nullopt;
        }

        std::size_t idx = 0;
        while (idx < count_of_codes) {
            const std::size_t off = 4u + idx * 2u;
            const std::uint8_t code_offset = er.read_u8(off).value_or(0);
            const std::uint8_t op_and_info = er.read_u8(off + 1u).value_or(0);
            const std::uint8_t uw_op = op_and_info & 0x0Fu;
            const std::uint8_t op_info = static_cast<std::uint8_t>((op_and_info >> 4u) & 0x0Fu);

            const auto slot_count_for_op = [&]() -> std::size_t {
                switch (uw_op) {
                    case 0u:  // UWOP_PUSH_NONVOL
                    case 2u:  // UWOP_ALLOC_SMALL
                    case 3u:  // UWOP_SET_FPREG
                    case 10u: // UWOP_PUSH_MACHFRAME
                        return 1u;
                    case 1u:  // UWOP_ALLOC_LARGE
                        return op_info == 0u ? 2u : 3u;
                    case 4u:  // UWOP_SAVE_NONVOL
                    case 6u:  // UWOP_EPILOG / SAVE_XMM
                    case 8u:  // UWOP_SAVE_XMM128
                        return 2u;
                    case 5u:  // UWOP_SAVE_NONVOL_FAR
                    case 7u:  // UWOP_SPARE / SAVE_XMM_FAR
                    case 9u:  // UWOP_SAVE_XMM128_FAR
                        return 3u;
                    default:
                        return 1u;
                }
            }();

            if (idx + slot_count_for_op > count_of_codes) {
                return std::nullopt;
            }

            // Skip unwind operations that have not yet executed at current_ip.
            if (code_offset > cur_ip_offset) {
                idx += slot_count_for_op;
                continue;
            }

            switch (uw_op) {
                case 0u: { // UWOP_PUSH_NONVOL
                    if (op_info == 5u) { // RBP
                        saved_fp_slot = rsp;
                        if (const auto val = stack_mem.read_pointer(rsp)) {
                            rbp = *val;
                        }
                    }
                    rsp += 8ull;
                    break;
                }
                case 1u: { // UWOP_ALLOC_LARGE
                    if (op_info == 0u) {
                        const std::uint16_t scaled = er.read_u16(off + 2u).value_or(0);
                        rsp += static_cast<std::uint64_t>(scaled) * 8ull;
                    } else {
                        const std::uint32_t raw_sz = er.read_u32(off + 2u).value_or(0);
                        rsp += raw_sz;
                    }
                    break;
                }
                case 2u: { // UWOP_ALLOC_SMALL
                    rsp += static_cast<std::uint64_t>(op_info) * 8ull + 8ull;
                    break;
                }
                case 3u: { // UWOP_SET_FPREG
                    if (frame_reg == 5u && rbp >= frame_scaled_off && rbp != 0) {
                        rsp = rbp - frame_scaled_off;
                    }
                    break;
                }
                case 4u: { // UWOP_SAVE_NONVOL
                    if (op_info == 5u) {
                        const std::uint64_t slot =
                            rsp + static_cast<std::uint64_t>(er.read_u16(off + 2u).value_or(0)) * 8ull;
                        saved_fp_slot = slot;
                        if (const auto val = stack_mem.read_pointer(slot)) {
                            rbp = *val;
                        }
                    }
                    break;
                }
                case 5u: { // UWOP_SAVE_NONVOL_FAR
                    if (op_info == 5u) {
                        const std::uint64_t slot = rsp + er.read_u32(off + 2u).value_or(0);
                        saved_fp_slot = slot;
                        if (const auto val = stack_mem.read_pointer(slot)) {
                            rbp = *val;
                        }
                    }
                    break;
                }
                case 10u: { // UWOP_PUSH_MACHFRAME
                    if (op_info == 1u) {
                        rsp += 8ull;
                    }
                    const auto rip_val = stack_mem.read_pointer(rsp);
                    const auto rsp_val = stack_mem.read_pointer(rsp + 24ull);
                    if (!rip_val || !rsp_val) {
                        return std::nullopt;
                    }
                    machframe_handled = true;
                    machframe_rip = *rip_val;
                    machframe_ret_slot = rsp;
                    rsp = *rsp_val;
                    break;
                }
                default:
                    break;
            }
            idx += slot_count_for_op;
        }

        // UNW_FLAG_CHAININFO = 0x04
        if ((flags & 0x04u) != 0u) {
            const std::size_t aligned_codes =
                (static_cast<std::size_t>(count_of_codes) + 1u) & ~std::size_t{1};
            const std::size_t chain_off = 4u + aligned_codes * 2u;
            if (chain_off + 12u > uw_span.size()) {
                return std::nullopt;
            }
            cur_rf.begin_address_rva = er.read_u32(chain_off).value_or(0);
            cur_rf.end_address_rva = er.read_u32(chain_off + 4u).value_or(0);
            cur_rf.unwind_info_rva = er.read_u32(chain_off + 8u).value_or(0);
            cur_ip_offset = 0xFFFFull;
            continue;
        }
        break;
    }

    if (machframe_handled) {
        if (machframe_rip == 0) {
            return std::nullopt;
        }
        return PeUnwindStep{
            .return_address = machframe_rip,
            .caller_rsp = rsp,
            .caller_rbp = rbp,
            .return_address_slot = machframe_ret_slot,
            .saved_fp_slot = saved_fp_slot,
        };
    }

    const auto ret_val = stack_mem.read_pointer(rsp);
    if (!ret_val || *ret_val == 0) {
        return std::nullopt;
    }

    return PeUnwindStep{
        .return_address = *ret_val,
        .caller_rsp = rsp + 8ull,
        .caller_rbp = rbp,
        .return_address_slot = rsp,
        .saved_fp_slot = saved_fp_slot,
    };
}

struct FpUnwindStep {
    std::uint64_t return_address{0};
    std::uint64_t caller_sp{0};
    std::uint64_t caller_fp{0};
    std::uint64_t return_address_slot{0};
    std::uint64_t saved_fp_slot{0};
};

[[nodiscard]] std::optional<FpUnwindStep> try_fp_chain_step(
    const StackMemoryView& stack_mem,
    const TargetLayout& layout,
    const StackBounds& bounds,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const IBinaryImage* active_image,
    std::uint64_t current_sp,
    std::uint64_t current_fp,
    const std::unordered_set<std::uint64_t>& visited_fps) {
    const std::size_t ptr_size = layout.pointer_size();

    // PowerPC / PowerPC64 SVR4 & ELFv2 stack backchain at [SP].
    if (layout.architecture == Architecture::PowerPC ||
        layout.architecture == Architecture::PowerPC64) {
        const std::uint64_t chain_base = (current_sp != 0) ? current_sp : current_fp;
        if (chain_base >= bounds.start && chain_base < bounds.end &&
            !visited_fps.contains(chain_base)) {
            if (const auto backchain = stack_mem.read_pointer(chain_base)) {
                if (*backchain > chain_base && *backchain + 3ull * ptr_size <= bounds.end) {
                    const std::uint64_t lr_off = layout.is_64bit() ? 16ull : 4ull;
                    const std::uint64_t lr_slot = *backchain + lr_off;
                    if (const auto lr_val = stack_mem.read_pointer(lr_slot);
                        lr_val &&
                        is_executable_address(*lr_val, bounds, regions, modules, active_image)) {
                        return FpUnwindStep{
                            .return_address = *lr_val,
                            .caller_sp = *backchain,
                            .caller_fp = *backchain,
                            .return_address_slot = lr_slot,
                            .saved_fp_slot = chain_base,
                        };
                    }
                }
            }
        }
    }

    if (current_fp == 0 || visited_fps.contains(current_fp)) {
        return std::nullopt;
    }

    const std::uint64_t align_mask =
        (layout.architecture == Architecture::X86) ? 1ull : static_cast<std::uint64_t>(ptr_size - 1u);
    if ((current_fp & align_mask) != 0ull) {
        return std::nullopt;
    }

    // RISC-V psABI stores ra at [fp - ptr_size] and saved s0/fp at [fp - 2*ptr_size].
    if (layout.architecture == Architecture::RISCV32 ||
        layout.architecture == Architecture::RISCV64) {
        if (current_fp >= bounds.start + 2ull * ptr_size && current_fp <= bounds.end &&
            (current_sp == 0 || current_fp >= current_sp)) {
            const std::uint64_t ra_slot = current_fp - ptr_size;
            const std::uint64_t s0_slot = current_fp - 2ull * ptr_size;
            const auto ra_val = stack_mem.read_pointer(ra_slot);
            const auto prev_fp = stack_mem.read_pointer(s0_slot);
            if (ra_val && prev_fp &&
                is_executable_address(*ra_val, bounds, regions, modules, active_image) &&
                (*prev_fp == 0 || (*prev_fp > current_fp && *prev_fp <= bounds.end))) {
                return FpUnwindStep{
                    .return_address = *ra_val,
                    .caller_sp = current_fp,
                    .caller_fp = *prev_fp,
                    .return_address_slot = ra_slot,
                    .saved_fp_slot = s0_slot,
                };
            }
        }
    }

    // Standard frame record: [fp] = saved_fp, [fp + ptr_size] = return_address.
    if (current_fp < bounds.start || current_fp > bounds.end ||
        (bounds.end - current_fp) < 2ull * ptr_size) {
        return std::nullopt;
    }
    if (current_sp != 0 && current_fp + 2ull * ptr_size < current_sp) {
        return std::nullopt;
    }

    const std::uint64_t saved_fp_slot = current_fp;
    const std::uint64_t ret_slot = current_fp + ptr_size;
    const auto next_fp = stack_mem.read_pointer(saved_fp_slot);
    const auto ret_addr = stack_mem.read_pointer(ret_slot);
    if (!next_fp || !ret_addr) {
        return std::nullopt;
    }
    if (!is_executable_address(*ret_addr, bounds, regions, modules, active_image)) {
        return std::nullopt;
    }
    if (*next_fp != 0 && (*next_fp <= current_fp || *next_fp >= bounds.end)) {
        return std::nullopt;
    }

    return FpUnwindStep{
        .return_address = *ret_addr,
        .caller_sp = current_fp + 2ull * ptr_size,
        .caller_fp = *next_fp,
        .return_address_slot = ret_slot,
        .saved_fp_slot = saved_fp_slot,
    };
}

[[nodiscard]] std::string format_tls_value_preview(std::span<const std::uint8_t> bytes,
                                                   const TargetLayout& layout) {
    if (bytes.empty()) {
        return "<empty>";
    }
    const EndianReader er(bytes, layout);
    if (bytes.size() == 1u) {
        const std::uint8_t v = bytes[0];
        return std::format("0x{:02x} ({})", v, v);
    }
    if (bytes.size() == 2u) {
        const std::uint16_t v = er.read_u16(0).value_or(0);
        return std::format("0x{:04x} ({})", v, v);
    }
    if (bytes.size() == 4u) {
        const std::uint32_t v = er.read_u32(0).value_or(0);
        return std::format("0x{:08x} ({})", v, v);
    }
    if (bytes.size() == 8u) {
        const std::uint64_t v = er.read_u64(0).value_or(0);
        return std::format("0x{:016x} ({})", v, v);
    }

    const std::size_t preview_len = std::min<std::size_t>(bytes.size(), 16u);
    std::string hex;
    std::string ascii;
    bool any_printable = false;
    for (std::size_t i = 0; i < preview_len; ++i) {
        if (i > 0) {
            hex.push_back(' ');
        }
        hex += std::format("{:02x}", bytes[i]);
        const unsigned char ch = bytes[i];
        if (ch >= 0x20u && ch <= 0x7Eu) {
            ascii.push_back(static_cast<char>(ch));
            any_printable = true;
        } else {
            ascii.push_back('.');
        }
    }
    if (bytes.size() > preview_len) {
        hex += " ...";
    }
    if (any_printable) {
        return std::format("{} \"{}\"", hex, ascii);
    }
    return hex;
}

[[nodiscard]] std::optional<std::uint64_t> read_session_pointer(IProcessSession& session,
                                                                const TargetLayout& layout,
                                                                std::uint64_t va) {
    if (va == 0) {
        return std::nullopt;
    }
    const std::size_t ptr_size = layout.pointer_size();
    std::array<std::uint8_t, 8> buf{};
    const auto slice = std::span<std::uint8_t>(buf.data(), ptr_size);
    const auto got = session.read_memory(va, slice);
    if (!got || *got < ptr_size) {
        return std::nullopt;
    }
    const EndianReader er(slice, layout);
    const auto res = er.read_pointer(0);
    return res ? std::optional<std::uint64_t>{*res} : std::nullopt;
}

[[nodiscard]] bool is_plausible_live_pointer(std::uint64_t addr,
                                             const TargetLayout& layout,
                                             std::span<const MemoryRegion> regions) noexcept {
    if (addr < 0x1000ull || (addr % layout.pointer_size()) != 0ull) {
        return false;
    }
    if (regions.empty()) {
        return true;
    }
    for (const MemoryRegion& reg : regions) {
        if (reg.contains(addr) && reg.protection.readable) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::vector<std::uint8_t> slice_elf_tls_template(
    const IBinaryImage& image,
    std::span<const std::uint8_t> static_or_module_bytes,
    IProcessSession* session,
    std::uint64_t template_start_va,
    std::uint64_t template_file_offset,
    std::uint64_t template_raw_size,
    std::uint64_t total_tls_size,
    std::uint64_t var_offset,
    std::uint64_t var_size) {
    if (var_size == 0 || var_offset >= total_tls_size) {
        return {};
    }
    const std::uint64_t capped_size =
        std::min<std::uint64_t>(var_size, std::min<std::uint64_t>(total_tls_size - var_offset, 4096ull));
    std::vector<std::uint8_t> out(static_cast<std::size_t>(capped_size), 0u);

    if (var_offset >= template_raw_size) {
        // Pure .tbss zero-fill range.
        return out;
    }

    const auto init_portion =
        static_cast<std::size_t>(std::min<std::uint64_t>(capped_size, template_raw_size - var_offset));

    // Try direct file/module buffer offset first.
    const std::uint64_t buf_off = template_file_offset + var_offset;
    if (!static_or_module_bytes.empty() && buf_off < static_or_module_bytes.size() &&
        init_portion <= static_or_module_bytes.size() - static_cast<std::size_t>(buf_off)) {
        std::copy_n(static_or_module_bytes.data() + static_cast<std::size_t>(buf_off),
                    init_portion,
                    out.data());
        return out;
    }

    // Try VA-to-file-offset translation if template_start_va is populated.
    if (!static_or_module_bytes.empty() && template_start_va != 0) {
        if (const auto mapped_off =
                image.virtual_address_to_file_offset(template_start_va + var_offset)) {
            if (*mapped_off < static_or_module_bytes.size() &&
                init_portion <= static_or_module_bytes.size() - static_cast<std::size_t>(*mapped_off)) {
                std::copy_n(static_or_module_bytes.data() + static_cast<std::size_t>(*mapped_off),
                            init_portion,
                            out.data());
                return out;
            }
        }
    }

    // Fallback: read initialized .tdata template from live mapped image VA if available.
    if (session != nullptr && template_start_va != 0) {
        const std::uint64_t live_template_va =
            template_start_va >= image.image_base()
                ? (template_start_va + var_offset)
                : (image.image_base() + template_start_va + var_offset);
        auto slice = std::span<std::uint8_t>(out.data(), init_portion);
        (void)session->read_memory(live_template_va, slice);
    }

    return out;
}

void inspect_pe_explicit_slots(IProcessSession& session,
                               const TargetLayout& layout,
                               std::uint64_t teb_va,
                               std::vector<PeTlsSlotEntry>& out_slots) {
    const bool is64 = layout.is_64bit();
    const std::size_t ptr_size = layout.pointer_size();

    // TEB.TlsSlots[64]: offset 0x1480 on Win64, 0x0E10 on Win32.
    const std::uint64_t primary_slots_va = teb_va + (is64 ? 0x1480ull : 0x0E10ull);
    std::vector<std::uint8_t> primary_buf(64u * ptr_size, 0u);
    if (const auto got = session.read_memory(primary_slots_va, primary_buf);
        got && *got >= ptr_size) {
        primary_buf.resize(*got);
        const EndianReader er(primary_buf, layout);
        const std::size_t count = primary_buf.size() / ptr_size;
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint64_t val = er.read_pointer(i * ptr_size).value_or(0);
            if (val != 0) {
                out_slots.push_back(PeTlsSlotEntry{
                    .slot_index = static_cast<std::uint32_t>(i),
                    .expansion_slot = false,
                    .slot_address = primary_slots_va + static_cast<std::uint64_t>(i) * ptr_size,
                    .value = val,
                    .annotation = std::format("TEB.TlsSlots[{}]", i),
                });
            }
        }
    }

    // TEB.TlsExpansionSlots: offset 0x1780 on Win64, 0x0F94 on Win32 (up to 1024 slots).
    const std::uint64_t exp_ptr_va = teb_va + (is64 ? 0x1780ull : 0x0F94ull);
    const auto exp_array_va = read_session_pointer(session, layout, exp_ptr_va);
    if (exp_array_va && *exp_array_va != 0) {
        std::vector<std::uint8_t> exp_buf(1024u * ptr_size, 0u);
        if (const auto got = session.read_memory(*exp_array_va, exp_buf);
            got && *got >= ptr_size) {
            exp_buf.resize(*got);
            const EndianReader er(exp_buf, layout);
            const std::size_t count = exp_buf.size() / ptr_size;
            for (std::size_t j = 0; j < count; ++j) {
                const std::uint64_t val = er.read_pointer(j * ptr_size).value_or(0);
                if (val != 0) {
                    out_slots.push_back(PeTlsSlotEntry{
                        .slot_index = static_cast<std::uint32_t>(64u + j),
                        .expansion_slot = true,
                        .slot_address = *exp_array_va + static_cast<std::uint64_t>(j) * ptr_size,
                        .value = val,
                        .annotation = std::format("TEB.TlsExpansionSlots[{}]", j),
                    });
                }
            }
        }
    }
}

}  // namespace

ThreadStackSnapshot unwind_and_inspect_stack(
    IProcessSession& session,
    const ThreadContext& context,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const IBinaryImage* active_image,
    AddressSymbolResolver symbol_resolver,
    std::size_t max_frames,
    std::size_t max_slots) {
    ThreadStackSnapshot snap;
    snap.tid = context.tid;
    snap.layout = resolve_effective_layout(context, session, active_image);

    const std::size_t ptr_size = snap.layout.pointer_size();

    if (context.stack_pointer == 0) {
        if (max_frames > 0 && context.instruction_pointer != 0) {
            StackFrame f0;
            f0.index = 0;
            f0.instruction_pointer = context.instruction_pointer;
            f0.frame_pointer = context.frame_pointer;
            f0.unwind_method = "register-ip";
            populate_frame_metadata(f0, modules, active_image, symbol_resolver);
            snap.frames.push_back(std::move(f0));
            snap.status = SubsystemStatus::partial(
                "Stack Unwinder", "stack pointer unavailable; captured register IP frame only");
            return snap;
        }
        snap.status =
            SubsystemStatus::unavailable("Stack Unwinder", "thread context has no stack pointer");
        return snap;
    }

    const std::uint64_t initial_sp = context.stack_pointer;
    const StackBounds bounds = locate_stack_bounds(initial_sp, regions, max_slots, ptr_size);
    snap.stack_region_start = bounds.start;
    snap.stack_region_end = bounds.end;

    const StackMemoryView stack_mem(session, snap.layout, regions, bounds, initial_sp, max_slots);

    std::uint64_t cur_ip = context.instruction_pointer;
    std::uint64_t cur_sp = initial_sp;
    std::uint64_t cur_fp = context.frame_pointer;

    if (max_frames > 0 && cur_ip != 0) {
        StackFrame f0;
        f0.index = 0;
        f0.instruction_pointer = cur_ip;
        f0.stack_pointer = cur_sp;
        f0.frame_pointer = cur_fp;
        f0.unwind_method = "register-ip";
        populate_frame_metadata(f0, modules, active_image, symbol_resolver);
        snap.frames.push_back(std::move(f0));
    }

    std::unordered_set<std::uint64_t> visited_fps;
    std::unordered_set<std::uint64_t> used_ret_slots;
    bool lr_consumed = false;
    std::uint64_t scan_cursor_sp = initial_sp;

    while (snap.frames.size() < max_frames) {
        const bool is_top_frame = (snap.frames.size() <= 1u && !lr_consumed);
        bool advanced = false;

        // 1. PE x64 .pdata / .xdata UNWIND_INFO virtual unwind.
        if (cur_ip != 0) {
            if (const auto pe_step = try_pe_x64_pdata_unwind(
                    session, stack_mem, active_image, cur_ip, cur_sp, cur_fp, is_top_frame)) {
                if (is_executable_address(
                        pe_step->return_address, bounds, regions, modules, active_image) &&
                    pe_step->caller_rsp >= cur_sp) {
                    if (pe_step->return_address_slot.has_value()) {
                        used_ret_slots.insert(*pe_step->return_address_slot);
                    }
                    StackFrame next;
                    next.index = snap.frames.size();
                    next.instruction_pointer = pe_step->return_address;
                    next.stack_pointer = pe_step->caller_rsp;
                    next.frame_pointer = pe_step->caller_rbp;
                    next.return_address_slot = pe_step->return_address_slot;
                    next.saved_fp_slot = pe_step->saved_fp_slot;
                    next.unwind_method = "pe-pdata";
                    populate_frame_metadata(next, modules, active_image, symbol_resolver);
                    snap.frames.push_back(std::move(next));

                    cur_ip = pe_step->return_address;
                    cur_sp = pe_step->caller_rsp;
                    cur_fp = pe_step->caller_rbp;
                    scan_cursor_sp = std::max(scan_cursor_sp, cur_sp);
                    advanced = true;
                }
            }
        }
        if (advanced) {
            continue;
        }

        // Pre-evaluate FP step so RISC link-register vs saved-frame-record can be disambiguated.
        const auto fp_candidate = try_fp_chain_step(
            stack_mem, snap.layout, bounds, regions, modules, active_image, cur_sp, cur_fp, visited_fps);

        // 2. Link register for leaf Frame 0 -> Frame 1 on RISC / ARM / PowerPC / MIPS targets.
        if (!lr_consumed && snap.frames.size() == 1u &&
            is_link_register_arch(snap.layout.architecture) && context.link_register.has_value()) {
            lr_consumed = true;
            const std::uint64_t lr = *context.link_register;
            if (lr != 0 && lr != cur_ip &&
                is_executable_address(lr, bounds, regions, modules, active_image)) {
                bool prefer_lr = !fp_candidate.has_value();
                if (fp_candidate.has_value() && fp_candidate->return_address != lr) {
                    // Check whether LR is merely a stale return address inside the current function
                    // after a non-leaf frame already saved its own caller return address in [fp].
                    const auto cur_sym = lookup_image_symbol(active_image, cur_ip);
                    const auto lr_sym = lookup_image_symbol(active_image, lr);
                    const bool lr_in_same_fn =
                        cur_sym.has_value() && lr_sym.has_value() && cur_sym->first == lr_sym->first;
                    if (!lr_in_same_fn && cur_fp > cur_sp) {
                        prefer_lr = true;
                    }
                }
                if (prefer_lr) {
                    StackFrame next;
                    next.index = snap.frames.size();
                    next.instruction_pointer = lr;
                    next.stack_pointer = cur_sp;
                    next.frame_pointer = cur_fp;
                    next.unwind_method = "link-register";
                    populate_frame_metadata(next, modules, active_image, symbol_resolver);
                    snap.frames.push_back(std::move(next));
                    cur_ip = lr;
                    continue;
                }
            }
        }

        // 3. Monotonic, cycle-safe frame-pointer chain walk.
        if (fp_candidate.has_value()) {
            visited_fps.insert(cur_fp != 0 ? cur_fp : cur_sp);
            used_ret_slots.insert(fp_candidate->return_address_slot);

            StackFrame next;
            next.index = snap.frames.size();
            next.instruction_pointer = fp_candidate->return_address;
            next.stack_pointer = fp_candidate->caller_sp;
            next.frame_pointer = fp_candidate->caller_fp;
            next.return_address_slot = fp_candidate->return_address_slot;
            next.saved_fp_slot = fp_candidate->saved_fp_slot;
            next.unwind_method = "frame-pointer";
            populate_frame_metadata(next, modules, active_image, symbol_resolver);
            snap.frames.push_back(std::move(next));

            cur_ip = fp_candidate->return_address;
            cur_sp = fp_candidate->caller_sp;
            cur_fp = fp_candidate->caller_fp;
            scan_cursor_sp = std::max(scan_cursor_sp, cur_sp);
            continue;
        }

        // 4. Conservative stack-slot scan for return addresses (-fomit-frame-pointer fallback).
        const std::uint64_t aligned_start =
            align_up_u64(std::max(scan_cursor_sp, initial_sp), static_cast<std::uint64_t>(ptr_size));
        const std::size_t scan_budget = std::min<std::size_t>(std::max<std::size_t>(max_slots, 64u), 256u);
        for (std::size_t s = 0; s < scan_budget; ++s) {
            const std::uint64_t slot_addr =
                aligned_start + static_cast<std::uint64_t>(s) * ptr_size;
            if (slot_addr + ptr_size > bounds.end) {
                break;
            }
            if (used_ret_slots.contains(slot_addr)) {
                continue;
            }
            const auto candidate_val = stack_mem.read_pointer(slot_addr);
            if (!candidate_val) {
                break;
            }
            if (!is_executable_address(*candidate_val, bounds, regions, modules, active_image)) {
                continue;
            }
            if (!check_post_call_address(session, snap.layout, *candidate_val)) {
                continue;
            }

            used_ret_slots.insert(slot_addr);
            StackFrame next;
            next.index = snap.frames.size();
            next.instruction_pointer = *candidate_val;
            next.stack_pointer = slot_addr + ptr_size;
            next.frame_pointer = 0;
            next.return_address_slot = slot_addr;
            next.unwind_method = "stack-scan";
            populate_frame_metadata(next, modules, active_image, symbol_resolver);
            snap.frames.push_back(std::move(next));

            cur_ip = *candidate_val;
            cur_sp = slot_addr + ptr_size;
            cur_fp = 0;
            scan_cursor_sp = slot_addr + ptr_size;
            advanced = true;
            break;
        }

        if (!advanced) {
            break;
        }
    }

    // Build color-role classified stack slots starting at SP.
    const std::span<const std::uint8_t> win = stack_mem.window_bytes();
    const EndianReader win_reader(win, snap.layout);
    const std::size_t avail_slots = win.size() / ptr_size;
    const std::size_t slot_count = std::min(max_slots, avail_slots);
    snap.slots.reserve(slot_count);

    for (std::size_t i = 0; i < slot_count; ++i) {
        const std::uint64_t slot_addr = initial_sp + static_cast<std::uint64_t>(i) * ptr_size;
        const std::uint64_t val = win_reader.read_pointer(i * ptr_size).value_or(0);

        StackSlotEntry entry;
        entry.slot_address = slot_addr;
        entry.value = val;
        entry.points_to_executable =
            is_executable_address(val, bounds, regions, modules, active_image);
        entry.points_to_stack = (val >= bounds.start && val < bounds.end);
        entry.resolved_symbol =
            resolve_address_label(val, modules, active_image, symbol_resolver);

        bool matched_role = false;

        for (const StackFrame& fr : snap.frames) {
            if (fr.return_address_slot.has_value() && *fr.return_address_slot == slot_addr) {
                entry.role = StackSlotRole::ReturnAddress;
                entry.frame_index = fr.index;
                entry.annotation =
                    std::format("Frame #{} return address ({})", fr.index, fr.unwind_method);
                matched_role = true;
                break;
            }
        }

        if (!matched_role && context.frame_pointer != 0 && slot_addr == context.frame_pointer) {
            entry.role = StackSlotRole::ActiveFramePointer;
            entry.frame_index = 0;
            for (const StackFrame& fr : snap.frames) {
                if (fr.saved_fp_slot.has_value() && *fr.saved_fp_slot == slot_addr) {
                    entry.frame_index = fr.index;
                    break;
                }
            }
            entry.annotation = "Active FP/BP frame record";
            matched_role = true;
        }

        if (!matched_role) {
            for (const StackFrame& fr : snap.frames) {
                if (fr.saved_fp_slot.has_value() && *fr.saved_fp_slot == slot_addr) {
                    entry.role = StackSlotRole::SavedFramePointer;
                    entry.frame_index = fr.index;
                    entry.annotation = std::format("Frame #{} saved FP/BP", fr.index);
                    matched_role = true;
                    break;
                }
            }
        }

        if (!matched_role && i == 0 && context.frame_pointer != 0 &&
            val == context.frame_pointer) {
            entry.role = StackSlotRole::ActiveFramePointer;
            entry.frame_index = 0;
            entry.annotation = "Points to active FP/BP";
            matched_role = true;
        }

        if (!matched_role && entry.points_to_executable &&
            check_post_call_address(session, snap.layout, val)) {
            entry.role = StackSlotRole::ReturnAddress;
            entry.annotation = "Candidate return address";
            matched_role = true;
        }

        if (!matched_role && i == 0) {
            entry.role = StackSlotRole::StackPointerTop;
            entry.frame_index = 0;
            entry.annotation = "Top of stack (SP)";
            matched_role = true;
        }

        if (entry.annotation.empty()) {
            if (entry.points_to_stack) {
                if (val >= initial_sp) {
                    entry.annotation = std::format("Stack ptr (SP+0x{:x})", val - initial_sp);
                } else {
                    entry.annotation = std::format("Stack ptr (SP-0x{:x})", initial_sp - val);
                }
            } else if (!entry.resolved_symbol.empty()) {
                entry.annotation = entry.resolved_symbol;
            }
        }

        snap.slots.push_back(std::move(entry));
    }

    if (snap.slots.empty() && max_slots > 0) {
        snap.status = SubsystemStatus::partial(
            "Stack Unwinder", "stack memory unreadable at SP; register frame only");
    } else {
        snap.status = SubsystemStatus::available(
            "Stack Unwinder",
            std::format("unwound {} frame(s), classified {} stack slot(s)",
                        snap.frames.size(),
                        snap.slots.size()));
    }
    return snap;
}

ThreadLocalSnapshot inspect_thread_locals(
    const IBinaryImage* image,
    std::span<const std::uint8_t> static_or_module_bytes,
    IProcessSession* session,
    const ThreadContext* thread,
    std::span<const MemoryRegion> regions,
    std::string_view module_name) {
    ThreadLocalSnapshot snap;
    if (thread != nullptr) {
        snap.tid = thread->tid;
        snap.layout = thread->layout;
        snap.thread_pointer =
            thread->tls_pointer.has_value() ? thread->tls_pointer : thread->teb_address;
    } else if (session != nullptr) {
        snap.layout = session->target_layout();
    }

    if (image != nullptr && snap.layout.architecture == Architecture::Unknown) {
        snap.layout = TargetLayout::from_arch(
            image->architecture(), image->is_64bit(), image->endianness());
    }

    const std::string mod_label =
        !module_name.empty() ? std::string(module_name) : std::string("<main>");

    if (image == nullptr) {
        if (session != nullptr && thread != nullptr) {
            const auto teb_va =
                thread->teb_address.has_value() ? thread->teb_address : thread->tls_pointer;
            if (teb_va.has_value() && *teb_va != 0) {
                inspect_pe_explicit_slots(*session, snap.layout, *teb_va, snap.pe_slots);
                snap.model = TlsModelKind::PeExplicitSlots;
                snap.status = SubsystemStatus::available(
                    "PE TEB TlsSlots", "inspected explicit TEB TLS slots without binary image");
                return snap;
            }
        }
        snap.status =
            SubsystemStatus::unavailable("TLS Inspector", "no binary image provided for TLS inspection");
        return snap;
    }

    // Ensure layout matches image endianness/width when inspecting cross-endian static binaries.
    if (session == nullptr && thread == nullptr) {
        snap.layout = TargetLayout::from_arch(
            image->architecture(), image->is_64bit(), image->endianness());
    }

    // -------------------------------------------------------------------------
    // ELF PT_TLS & Variant I / Variant II inspection
    // -------------------------------------------------------------------------
    if (image->format() == Format::ELF) {
        constexpr std::uint32_t kPtTls = 7u;
        constexpr std::uint64_t kShfTls = 0x400ull;
        constexpr std::uint32_t kShtNobits = 8u;
        constexpr std::uint8_t kSttTls = 6u;

        const ElfProgramHeader* pt_tls = nullptr;
        for (const ElfProgramHeader& ph : image->elf_program_headers()) {
            if (ph.type == kPtTls) {
                pt_tls = &ph;
                break;
            }
        }

        std::uint64_t sh_tls_start_va = 0;
        std::uint64_t sh_tls_file_off = 0;
        std::uint64_t sh_tdata_size = 0;
        std::uint64_t sh_tbss_size = 0;
        std::uint64_t sh_max_align = 1;
        bool found_sh_tls = false;
        for (const ElfSectionHeader& sh : image->elf_section_headers()) {
            if ((sh.flags & kShfTls) == 0ull) {
                continue;
            }
            if (!found_sh_tls) {
                sh_tls_start_va = sh.address;
                sh_tls_file_off = sh.offset;
                found_sh_tls = true;
            }
            sh_max_align = std::max(sh_max_align, sh.address_alignment);
            if (sh.type == kShtNobits) {
                sh_tbss_size += sh.size;
            } else {
                sh_tdata_size += sh.size;
            }
        }

        if (pt_tls == nullptr && !found_sh_tls) {
            snap.model = TlsModelKind::None;
            snap.status =
                SubsystemStatus::available("ELF TLS", "binary contains no PT_TLS segment or TLS sections");
            return snap;
        }

        std::uint64_t total_memsz = 0;
        std::uint64_t tls_align = 1;
        std::uint64_t template_file_off = 0;
        if (pt_tls != nullptr) {
            snap.template_start_va = pt_tls->virtual_address;
            template_file_off = pt_tls->offset;
            total_memsz = pt_tls->memory_size;
            tls_align = std::max<std::uint64_t>(pt_tls->alignment, 1ull);

            if (pt_tls->memory_size > pt_tls->file_size) {
                snap.template_raw_size = pt_tls->file_size;
                snap.template_zero_fill_size = pt_tls->memory_size - pt_tls->file_size;
            } else if (sh_tbss_size > 0 && sh_tbss_size <= total_memsz) {
                // rebase_to_live_base promotes ph.file_size to ph.memory_size; recover .tbss split
                // from SHF_TLS SHT_NOBITS sections when available.
                snap.template_raw_size = total_memsz - sh_tbss_size;
                snap.template_zero_fill_size = sh_tbss_size;
            } else {
                snap.template_raw_size = std::min(pt_tls->file_size, pt_tls->memory_size);
                snap.template_zero_fill_size = 0;
            }
        } else {
            snap.template_start_va = sh_tls_start_va;
            template_file_off = sh_tls_file_off;
            snap.template_raw_size = sh_tdata_size;
            snap.template_zero_fill_size = sh_tbss_size;
            total_memsz = sh_tdata_size + sh_tbss_size;
            tls_align = std::max<std::uint64_t>(sh_max_align, 1ull);
        }

        auto normalize_elf_tls_offset = [&](std::uint64_t raw_val) noexcept -> std::uint64_t {
            if (total_memsz == 0 || raw_val < total_memsz) {
                return raw_val;
            }
            if (snap.template_start_va > 0 && raw_val >= snap.template_start_va &&
                (raw_val - snap.template_start_va) < total_memsz) {
                return raw_val - snap.template_start_va;
            }
            const std::uint64_t img_base = image->image_base();
            if (img_base > 0 && raw_val >= img_base && (raw_val - img_base) < total_memsz) {
                return raw_val - img_base;
            }
            return raw_val;
        };

        std::unordered_set<std::string> seen_tls_syms;
        for (const ElfSymbol& esym : image->elf_symbols()) {
            if (esym.type != kSttTls || esym.section_index == 0u) {
                continue;
            }
            const std::uint64_t tls_off = normalize_elf_tls_offset(esym.value);
            const std::string sym_name =
                !esym.name.empty() ? esym.name : std::format("tls_0x{:x}", tls_off);
            const std::string dedup_key = std::format("{}:{}", tls_off, sym_name);
            if (!seen_tls_syms.insert(dedup_key).second) {
                continue;
            }

            std::uint64_t sym_size = esym.size;
            if (sym_size == 0 && tls_off < total_memsz) {
                sym_size = std::min<std::uint64_t>(
                    total_memsz - tls_off, static_cast<std::uint64_t>(snap.layout.pointer_size()));
            }

            TlsVariableEntry var;
            var.module_name = mod_label;
            var.name = sym_name;
            var.template_offset = tls_off;
            var.size = sym_size;
            var.template_bytes = slice_elf_tls_template(
                *image,
                static_or_module_bytes,
                session,
                snap.template_start_va,
                template_file_off,
                snap.template_raw_size,
                total_memsz,
                tls_off,
                sym_size);
            snap.variables.push_back(std::move(var));
        }

        if (snap.variables.empty()) {
            for (const Symbol& sym : image->symbols()) {
                if (sym.type != kSttTls || sym.section_index == 0u) {
                    continue;
                }
                const std::uint64_t tls_off = normalize_elf_tls_offset(sym.virtual_address);
                const std::string sym_name =
                    !sym.name.empty() ? sym.name : std::format("tls_0x{:x}", tls_off);
                std::uint64_t sym_size = sym.size;
                if (sym_size == 0 && tls_off < total_memsz) {
                    sym_size = std::min<std::uint64_t>(
                        total_memsz - tls_off,
                        static_cast<std::uint64_t>(snap.layout.pointer_size()));
                }
                TlsVariableEntry var;
                var.module_name = mod_label;
                var.name = sym_name;
                var.template_offset = tls_off;
                var.size = sym_size;
                var.template_bytes = slice_elf_tls_template(
                    *image,
                    static_or_module_bytes,
                    session,
                    snap.template_start_va,
                    template_file_off,
                    snap.template_raw_size,
                    total_memsz,
                    tls_off,
                    sym_size);
                snap.variables.push_back(std::move(var));
            }
        }

        std::ranges::sort(snap.variables, [](const TlsVariableEntry& a, const TlsVariableEntry& b) {
            if (a.template_offset != b.template_offset) {
                return a.template_offset < b.template_offset;
            }
            return a.name < b.name;
        });

        // If stripped of STT_TLS symbols, expose the raw .tdata / .tbss template blocks.
        if (snap.variables.empty() && total_memsz > 0) {
            if (snap.template_raw_size > 0) {
                TlsVariableEntry tdata_entry;
                tdata_entry.module_name = mod_label;
                tdata_entry.name = "<tdata>";
                tdata_entry.template_offset = 0;
                tdata_entry.size = snap.template_raw_size;
                tdata_entry.template_bytes = slice_elf_tls_template(
                    *image,
                    static_or_module_bytes,
                    session,
                    snap.template_start_va,
                    template_file_off,
                    snap.template_raw_size,
                    total_memsz,
                    0,
                    snap.template_raw_size);
                snap.variables.push_back(std::move(tdata_entry));
            }
            if (snap.template_zero_fill_size > 0) {
                TlsVariableEntry tbss_entry;
                tbss_entry.module_name = mod_label;
                tbss_entry.name = "<tbss>";
                tbss_entry.template_offset = snap.template_raw_size;
                tbss_entry.size = snap.template_zero_fill_size;
                tbss_entry.template_bytes = slice_elf_tls_template(
                    *image,
                    static_or_module_bytes,
                    session,
                    snap.template_start_va,
                    template_file_off,
                    snap.template_raw_size,
                    total_memsz,
                    snap.template_raw_size,
                    snap.template_zero_fill_size);
                snap.variables.push_back(std::move(tbss_entry));
            }
        }

        // Static mode or live without thread pointer: return template bytes cleanly.
        if (session == nullptr || thread == nullptr || !snap.thread_pointer.has_value() ||
            *snap.thread_pointer == 0) {
            snap.model = TlsModelKind::ElfStaticTemplateOnly;
            const SubsystemStatus var_st =
                (session == nullptr)
                    ? SubsystemStatus::available("ELF PT_TLS", "static TLS template")
                    : SubsystemStatus::partial(
                          "ELF PT_TLS", "thread pointer unavailable; showing static TLS template");
            for (TlsVariableEntry& var : snap.variables) {
                var.decoded_value = format_tls_value_preview(var.template_bytes, snap.layout);
                var.status = var_st;
            }
            snap.status = var_st;
            return snap;
        }

        // Live ELF TLS block calculation from thread pointer (TP).
        const std::uint64_t tp = *snap.thread_pointer;
        const auto ptr_size = static_cast<std::uint64_t>(snap.layout.pointer_size());
        const Architecture arch = snap.layout.architecture != Architecture::Unknown
                                      ? snap.layout.architecture
                                      : image->architecture();

        std::uint64_t tls_block = 0;
        if (arch == Architecture::X86_64 || arch == Architecture::X86) {
            snap.model = TlsModelKind::ElfVariantII;
            const std::uint64_t abi_block =
                tp - align_up_u64(total_memsz, std::max<std::uint64_t>(tls_align, ptr_size));
            tls_block = abi_block;

            // Inspect tcbhead_t.dtv at [tp + ptr_size] on x86 / x86-64.
            if (const auto dtv = read_session_pointer(*session, snap.layout, tp + ptr_size)) {
                if (is_plausible_live_pointer(*dtv, snap.layout, regions)) {
                    snap.dtv_address = *dtv;
                    // On glibc, tcbhead_t.tcb at [tp] and tcbhead_t.self at [tp + 2*ptr_size] equal tp,
                    // and dtv[1].pointer.val at [dtv + 2*ptr_size] gives the exact static TLS block VA
                    // (handling 4-byte aligned PT_TLS segments on 64-bit targets).
                    const auto tcb_self0 = read_session_pointer(*session, snap.layout, tp);
                    const auto tcb_self2 =
                        read_session_pointer(*session, snap.layout, tp + 2ull * ptr_size);
                    if (tcb_self0 && *tcb_self0 == tp && tcb_self2 && *tcb_self2 == tp) {
                        if (const auto dtv1 =
                                read_session_pointer(*session, snap.layout, *dtv + 2ull * ptr_size)) {
                            const std::uint64_t min_expected =
                                abi_block > 64ull ? (abi_block - 64ull) : 0ull;
                            if (*dtv1 >= min_expected && *dtv1 < tp &&
                                *dtv1 != UINT64_MAX && *dtv1 != 0xFFFFFFFFull) {
                                tls_block = *dtv1;
                            }
                        }
                    }
                }
            }
        } else {
            snap.model = TlsModelKind::ElfVariantI;
            switch (arch) {
                case Architecture::ARM64:
                case Architecture::ARM: {
                    if (const auto dtv = read_session_pointer(*session, snap.layout, tp)) {
                        if (is_plausible_live_pointer(*dtv, snap.layout, regions)) {
                            snap.dtv_address = *dtv;
                        }
                    }
                    tls_block = align_up_u64(tp + 2ull * ptr_size, tls_align);
                    break;
                }
                case Architecture::RISCV32:
                case Architecture::RISCV64: {
                    if (tp >= 2ull * ptr_size) {
                        if (const auto dtv =
                                read_session_pointer(*session, snap.layout, tp - 2ull * ptr_size)) {
                            if (is_plausible_live_pointer(*dtv, snap.layout, regions)) {
                                snap.dtv_address = *dtv;
                            }
                        }
                    }
                    tls_block = tp;
                    break;
                }
                case Architecture::PowerPC:
                case Architecture::PowerPC64:
                case Architecture::MIPS32:
                case Architecture::MIPS64:
                    tls_block = tp >= 0x7000ull ? (tp - 0x7000ull) : tp;
                    break;
                default:
                    tls_block = tp;
                    break;
            }
        }

        snap.tls_block_address = tls_block;
        std::size_t live_ok = 0;
        for (TlsVariableEntry& var : snap.variables) {
            const std::uint64_t live_va = tls_block + var.template_offset;
            var.live_address = live_va;

            const std::uint64_t read_sz =
                std::min<std::uint64_t>(var.size > 0 ? var.size : ptr_size, 4096ull);
            std::vector<std::uint8_t> buf(static_cast<std::size_t>(read_sz), 0u);
            if (const auto got = session->read_memory(live_va, buf); got && *got > 0) {
                buf.resize(*got);
                var.live_bytes = std::move(buf);
                var.decoded_value = format_tls_value_preview(var.live_bytes, snap.layout);
                var.status = SubsystemStatus::available("Live ELF TLS", "read from thread TLS block");
                ++live_ok;
            } else {
                var.decoded_value = format_tls_value_preview(var.template_bytes, snap.layout);
                var.status = SubsystemStatus::partial(
                    "Live ELF TLS", "thread TLS memory unreadable; showing static template");
            }
        }

        if (live_ok > 0 || snap.variables.empty()) {
            snap.status = SubsystemStatus::available(
                "Live ELF TLS",
                std::format("inspected {} TLS variable(s) at block 0x{:x}",
                            snap.variables.size(),
                            tls_block));
        } else {
            snap.status = SubsystemStatus::partial(
                "Live ELF TLS", "live TLS block unreadable; static template values shown");
        }
        return snap;
    }

    // -------------------------------------------------------------------------
    // PE Implicit TLS Directory + Explicit TEB TlsSlots inspection
    // -------------------------------------------------------------------------
    if (image->format() == Format::PE) {
        const PeTlsDirectory* tls_dir = image->pe_tls_directory();
        const bool is64 = snap.layout.is_64bit();
        const std::size_t ptr_size = snap.layout.pointer_size();

        std::optional<std::uint64_t> teb_va;
        if (thread != nullptr) {
            teb_va = thread->teb_address.has_value() ? thread->teb_address : thread->tls_pointer;
        }
        if (session != nullptr && teb_va.has_value() && *teb_va != 0) {
            snap.thread_pointer = *teb_va;
            inspect_pe_explicit_slots(*session, snap.layout, *teb_va, snap.pe_slots);
        }

        if (tls_dir == nullptr) {
            if (!snap.pe_slots.empty() || (session != nullptr && teb_va.has_value() && *teb_va != 0)) {
                snap.model = TlsModelKind::PeExplicitSlots;
                snap.status = SubsystemStatus::available(
                    "PE TEB TlsSlots",
                    std::format("no implicit TLS directory; {} active explicit slot(s)",
                                snap.pe_slots.size()));
            } else {
                snap.model = TlsModelKind::None;
                snap.status =
                    SubsystemStatus::available("PE TLS", "binary has no PE TLS directory");
            }
            return snap;
        }

        snap.model = TlsModelKind::PeImplicitTls;
        snap.template_start_va = tls_dir->raw_data_start_va;
        snap.template_raw_size =
            tls_dir->raw_data_end_va >= tls_dir->raw_data_start_va
                ? (tls_dir->raw_data_end_va - tls_dir->raw_data_start_va)
                : 0ull;
        snap.template_zero_fill_size = tls_dir->size_of_zero_fill;
        const std::uint64_t total_pe_tls = snap.template_raw_size + snap.template_zero_fill_size;

        auto slice_pe_template = [&](std::uint64_t off, std::uint64_t sz) {
            if (sz == 0 || off >= total_pe_tls) {
                return std::vector<std::uint8_t>{};
            }
            const std::uint64_t capped =
                std::min<std::uint64_t>(sz, std::min<std::uint64_t>(total_pe_tls - off, 4096ull));
            std::vector<std::uint8_t> out(static_cast<std::size_t>(capped), 0u);
            if (off < snap.template_raw_size) {
                const auto init_len = static_cast<std::size_t>(
                    std::min<std::uint64_t>(capped, snap.template_raw_size - off));
                bool copied = false;
                if (!static_or_module_bytes.empty()) {
                    if (const auto foff =
                            image->virtual_address_to_file_offset(tls_dir->raw_data_start_va + off)) {
                        if (*foff < static_or_module_bytes.size() &&
                            init_len <=
                                static_or_module_bytes.size() - static_cast<std::size_t>(*foff)) {
                            std::copy_n(
                                static_or_module_bytes.data() + static_cast<std::size_t>(*foff),
                                init_len,
                                out.data());
                            copied = true;
                        }
                    }
                }
                if (!copied && session != nullptr && tls_dir->raw_data_start_va != 0) {
                    auto slice = std::span<std::uint8_t>(out.data(), init_len);
                    (void)session->read_memory(tls_dir->raw_data_start_va + off, slice);
                }
            }
            return out;
        };

        // Populate symbols inside the PE .tls template range if COFF symbols exist.
        if (total_pe_tls > 0 && tls_dir->raw_data_start_va != 0) {
            for (const Symbol& sym : image->symbols()) {
                if (sym.name.empty()) {
                    continue;
                }
                if (sym.virtual_address >= tls_dir->raw_data_start_va &&
                    (sym.virtual_address - tls_dir->raw_data_start_va) < total_pe_tls) {
                    const std::uint64_t off = sym.virtual_address - tls_dir->raw_data_start_va;
                    const std::uint64_t sz =
                        sym.size > 0
                            ? sym.size
                            : std::min<std::uint64_t>(total_pe_tls - off,
                                                      static_cast<std::uint64_t>(ptr_size));
                    TlsVariableEntry var;
                    var.module_name = mod_label;
                    var.name = sym.name;
                    var.template_offset = off;
                    var.size = sz;
                    var.template_bytes = slice_pe_template(off, sz);
                    snap.variables.push_back(std::move(var));
                }
            }
        }

        if (snap.variables.empty() && total_pe_tls > 0) {
            TlsVariableEntry block_var;
            block_var.module_name = mod_label;
            block_var.name = "<pe_tls_template>";
            block_var.template_offset = 0;
            block_var.size = total_pe_tls;
            block_var.template_bytes = slice_pe_template(0, total_pe_tls);
            snap.variables.push_back(std::move(block_var));
        }

        if (session == nullptr) {
            for (TlsVariableEntry& var : snap.variables) {
                var.decoded_value = format_tls_value_preview(var.template_bytes, snap.layout);
                var.status = SubsystemStatus::available("PE TLS Directory", "static PE TLS template");
            }
            snap.status =
                SubsystemStatus::available("PE TLS Directory", "static PE TLS template inspected");
            return snap;
        }

        // Read live TlsIndex (u32) at AddressOfIndex.
        if (tls_dir->address_of_index != 0) {
            std::array<std::uint8_t, 4> idx_buf{};
            if (const auto got = session->read_memory(tls_dir->address_of_index, idx_buf);
                got && *got == 4u) {
                const EndianReader er(idx_buf, snap.layout);
                if (const auto idx = er.read_u32(0)) {
                    snap.pe_tls_index = *idx;
                }
            }
        }

        // Resolve TEB.ThreadLocalStoragePointer (0x58 on PE64, 0x2C on PE32) -> TlsArray[TlsIndex].
        if (teb_va.has_value() && *teb_va != 0 && snap.pe_tls_index.has_value() &&
            *snap.pe_tls_index < 1024u) {
            const std::uint64_t tls_ptr_field = *teb_va + (is64 ? 0x58ull : 0x2Cull);
            if (const auto tls_array = read_session_pointer(*session, snap.layout, tls_ptr_field);
                tls_array && *tls_array != 0) {
                snap.dtv_address = *tls_array;
                const std::uint64_t slot_va =
                    *tls_array + static_cast<std::uint64_t>(*snap.pe_tls_index) * ptr_size;
                if (const auto block_va = read_session_pointer(*session, snap.layout, slot_va);
                    block_va && *block_va != 0) {
                    snap.tls_block_address = *block_va;
                }
            }
        }

        std::size_t live_ok = 0;
        for (TlsVariableEntry& var : snap.variables) {
            if (snap.tls_block_address.has_value()) {
                const std::uint64_t live_va = *snap.tls_block_address + var.template_offset;
                var.live_address = live_va;
                const std::uint64_t read_sz =
                    std::min<std::uint64_t>(var.size > 0 ? var.size : ptr_size, 4096ull);
                std::vector<std::uint8_t> buf(static_cast<std::size_t>(read_sz), 0u);
                if (const auto got = session->read_memory(live_va, buf); got && *got > 0) {
                    buf.resize(*got);
                    var.live_bytes = std::move(buf);
                    var.decoded_value = format_tls_value_preview(var.live_bytes, snap.layout);
                    var.status = SubsystemStatus::available("PE Implicit TLS", "read from TEB TLS block");
                    ++live_ok;
                    continue;
                }
            }
            var.decoded_value = format_tls_value_preview(var.template_bytes, snap.layout);
            var.status = SubsystemStatus::partial(
                "PE Implicit TLS", "TEB TLS block unavailable; showing static template");
        }

        if (live_ok > 0) {
            snap.status = SubsystemStatus::available(
                "PE Implicit TLS",
                std::format("inspected live PE TLS block 0x{:x} (TlsIndex={})",
                            *snap.tls_block_address,
                            snap.pe_tls_index.value_or(0)));
        } else {
            snap.status = SubsystemStatus::partial(
                "PE Implicit TLS",
                "live TEB ThreadLocalStoragePointer unavailable; static PE TLS template shown");
        }
        return snap;
    }

    snap.status = SubsystemStatus::unavailable("TLS Inspector", "unsupported binary format");
    return snap;
}

}  // namespace peelf
