#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

enum class HandlerCategory : std::uint8_t {
    SehChain32,
    SafeSehTable,
    PeUnwindException,
    PeGuardEhContinuation,
    VehHandler,
    VchHandler,
    UnhandledExceptionFilter,
    TlsCallback,
    CrtInitializer,
    AtexitHandler,
    ElfInitFini,
    ElfEhFramePersonality,
    LinuxSignalDisposition,
};

[[nodiscard]] constexpr std::string_view to_string(HandlerCategory cat) noexcept {
    switch (cat) {
        case HandlerCategory::SehChain32:               return "SEH Chain (32-bit)";
        case HandlerCategory::SafeSehTable:             return "SafeSEH Handler";
        case HandlerCategory::PeUnwindException:        return "PE .pdata/.xdata Handler";
        case HandlerCategory::PeGuardEhContinuation:    return "GuardEH Continuation";
        case HandlerCategory::VehHandler:               return "VEH (Vectored Exception)";
        case HandlerCategory::VchHandler:               return "VCH (Vectored Continue)";
        case HandlerCategory::UnhandledExceptionFilter: return "Unhandled Exception Filter";
        case HandlerCategory::TlsCallback:              return "TLS Callback";
        case HandlerCategory::CrtInitializer:           return "CRT Init/Term Table";
        case HandlerCategory::AtexitHandler:            return "atexit / Exit Handler";
        case HandlerCategory::ElfInitFini:              return "ELF Init/Fini Handler";
        case HandlerCategory::ElfEhFramePersonality:    return "ELF .eh_frame Personality";
        case HandlerCategory::LinuxSignalDisposition:   return "Linux Signal Handler";
    }
    return "Handler";
}

struct HandlerEntry {
    HandlerCategory category{HandlerCategory::ElfInitFini};
    std::string category_label;
    std::string name;
    std::uint64_t handler_address{0};
    std::optional<std::uint64_t> record_address;
    std::optional<std::uint64_t> scope_start;
    std::optional<std::uint64_t> scope_end;
    std::optional<std::uint64_t> lsda_or_data_address;
    bool pointer_encoded{false};
    bool pointer_decoded{false};
    bool validated_safe{true};
    std::string symbol_name;
    std::string detail;
};

struct SignalDispositionEntry {
    int signal_number{0};
    std::string signal_name;
    bool caught{false};
    bool ignored{false};
    bool blocked{false};
    std::string detail;
};

struct HandlersReport {
    TargetLayout layout{};
    std::vector<HandlerEntry> entries;
    std::vector<SignalDispositionEntry> signals;

    SubsystemStatus static_handlers_status{};
    SubsystemStatus unwind_handlers_status{};
    SubsystemStatus live_seh_veh_status{};
    SubsystemStatus live_atexit_status{};
    SubsystemStatus signal_status{};
};

[[nodiscard]] HandlersReport inspect_handlers(
    const IBinaryImage* image,
    std::span<const std::uint8_t> static_or_module_bytes,
    IProcessSession* session = nullptr,
    std::span<const MemoryRegion> regions = {},
    std::span<const ModuleInfo> modules = {},
    const ThreadContext* selected_thread = nullptr,
    std::function<std::string(std::uint64_t)> symbol_resolver = {});

}  // namespace peelf
