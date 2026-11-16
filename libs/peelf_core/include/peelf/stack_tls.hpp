#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class StackSlotRole : std::uint8_t {
    Ordinary,
    StackPointerTop,
    ReturnAddress,
    ActiveFramePointer,
    SavedFramePointer,
};

[[nodiscard]] constexpr std::string_view to_string(StackSlotRole role) noexcept {
    switch (role) {
        case StackSlotRole::Ordinary:            return "Value";
        case StackSlotRole::StackPointerTop:     return "SP Top";
        case StackSlotRole::ReturnAddress:       return "Return Address";
        case StackSlotRole::ActiveFramePointer:  return "Active FP/BP";
        case StackSlotRole::SavedFramePointer:   return "Saved FP/BP";
    }
    return "Value";
}

struct StackFrame {
    std::size_t index{0};
    std::uint64_t instruction_pointer{0};
    std::uint64_t stack_pointer{0};
    std::uint64_t frame_pointer{0};
    std::optional<std::uint64_t> return_address_slot;
    std::optional<std::uint64_t> saved_fp_slot;
    std::string module_name;
    std::string symbol_name;
    std::uint64_t symbol_offset{0};
    std::string unwind_method;
};

struct StackSlotEntry {
    std::uint64_t slot_address{0};
    std::uint64_t value{0};
    StackSlotRole role{StackSlotRole::Ordinary};
    std::optional<std::size_t> frame_index;
    std::string annotation;
    std::string resolved_symbol;
    bool points_to_executable{false};
    bool points_to_stack{false};
    std::uint8_t byte_size{8};
    std::uint8_t valid_byte_mask{0xFFu};
    std::array<std::uint8_t, 8> raw_bytes{};

    [[nodiscard]] constexpr std::uint8_t full_valid_mask() const noexcept {
        return byte_size >= 8u ? 0xFFu
                               : static_cast<std::uint8_t>((1u << byte_size) - 1u);
    }
    [[nodiscard]] constexpr bool all_bytes_valid() const noexcept {
        return byte_size != 0u && (valid_byte_mask & full_valid_mask()) == full_valid_mask();
    }
    [[nodiscard]] constexpr bool any_bytes_valid() const noexcept {
        return (valid_byte_mask & full_valid_mask()) != 0u;
    }
    [[nodiscard]] constexpr bool is_byte_valid(std::size_t idx) const noexcept {
        return idx < byte_size && idx < raw_bytes.size() &&
               ((valid_byte_mask >> idx) & 1u) != 0u;
    }
};

[[nodiscard]] std::string format_stack_slot_value(const StackSlotEntry& slot,
                                                  TargetLayout layout);

struct ThreadStackSnapshot {
    ThreadId tid{0};
    TargetLayout layout{};
    std::uint64_t stack_region_start{0};
    std::uint64_t stack_region_end{0};
    std::vector<StackFrame> frames;
    std::vector<StackSlotEntry> slots;
    SubsystemStatus status{};
};

using AddressSymbolResolver = std::function<std::string(std::uint64_t virtual_address)>;

[[nodiscard]] ThreadStackSnapshot unwind_and_inspect_stack(
    IProcessSession& session,
    const ThreadContext& context,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const IBinaryImage* active_image = nullptr,
    AddressSymbolResolver symbol_resolver = {},
    std::size_t max_frames = 64,
    std::size_t max_slots = 256);

enum class TlsModelKind : std::uint8_t {
    None,
    PeImplicitTls,
    PeExplicitSlots,
    ElfVariantI,
    ElfVariantII,
    ElfStaticTemplateOnly,
};

[[nodiscard]] constexpr std::string_view to_string(TlsModelKind kind) noexcept {
    switch (kind) {
        case TlsModelKind::None:                  return "None";
        case TlsModelKind::PeImplicitTls:         return "PE Implicit TLS";
        case TlsModelKind::PeExplicitSlots:       return "PE Explicit TlsSlots";
        case TlsModelKind::ElfVariantI:           return "ELF TLS Variant I (TP + offset)";
        case TlsModelKind::ElfVariantII:          return "ELF TLS Variant II (TP - memsz + offset)";
        case TlsModelKind::ElfStaticTemplateOnly: return "ELF PT_TLS Static Template";
    }
    return "None";
}

struct TlsVariableEntry {
    std::string module_name;
    std::string name;
    std::uint64_t template_offset{0};
    std::uint64_t size{0};
    std::optional<std::uint64_t> live_address;
    std::vector<std::uint8_t> template_bytes;
    std::vector<std::uint8_t> live_bytes;
    std::string decoded_value;
    SubsystemStatus status{};
};

struct PeTlsSlotEntry {
    std::uint32_t slot_index{0};
    bool expansion_slot{false};
    std::uint64_t slot_address{0};
    std::uint64_t value{0};
    std::string annotation;
};

struct ThreadLocalSnapshot {
    std::optional<ThreadId> tid;
    TargetLayout layout{};
    TlsModelKind model{TlsModelKind::None};
    std::optional<std::uint64_t> thread_pointer;
    std::optional<std::uint64_t> dtv_address;
    std::optional<std::uint64_t> tls_block_address;
    std::optional<std::uint32_t> pe_tls_index;
    std::uint64_t template_start_va{0};
    std::uint64_t template_raw_size{0};
    std::uint64_t template_zero_fill_size{0};
    std::vector<TlsVariableEntry> variables;
    std::vector<PeTlsSlotEntry> pe_slots;
    SubsystemStatus status{};
};

[[nodiscard]] ThreadLocalSnapshot inspect_thread_locals(
    const IBinaryImage* image,
    std::span<const std::uint8_t> static_or_module_bytes,
    IProcessSession* session = nullptr,
    const ThreadContext* thread = nullptr,
    std::span<const MemoryRegion> regions = {},
    std::string_view module_name = {});

}  // namespace peelf
