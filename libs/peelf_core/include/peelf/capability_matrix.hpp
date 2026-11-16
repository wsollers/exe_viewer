#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/process.hpp>
#include <peelf/provenance.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace peelf {

/// ABI classification for a binary image or live session.
enum class AbiKind : std::uint8_t {
    Unknown = 0,
    PeWindows32,
    PeWindows64,
    SysV,
    GnuLinux,
    ArmEabi,
    AArch64SysV,
    FreeBsd,
    OpenBsd,
    NetBsd,
    Solaris,
    Standalone,
};

[[nodiscard]] constexpr std::string_view to_string(AbiKind abi) noexcept {
    switch (abi) {
        case AbiKind::Unknown:     return "Unknown";
        case AbiKind::PeWindows32: return "PeWindows32";
        case AbiKind::PeWindows64: return "PeWindows64";
        case AbiKind::SysV:        return "SysV";
        case AbiKind::GnuLinux:    return "GnuLinux";
        case AbiKind::ArmEabi:     return "ArmEabi";
        case AbiKind::AArch64SysV: return "AArch64SysV";
        case AbiKind::FreeBsd:     return "FreeBsd";
        case AbiKind::OpenBsd:     return "OpenBsd";
        case AbiKind::NetBsd:      return "NetBsd";
        case AbiKind::Solaris:     return "Solaris";
        case AbiKind::Standalone:  return "Standalone";
    }
    return "Unknown";
}

/// Operating system classification. Never inferred merely from `Format::ELF` without
/// explicit `EI_OSABI`, `.note.ABI-tag`, crash-dump metadata, or a live OS session.
enum class OsKind : std::uint8_t {
    Unknown = 0,
    Windows,
    Linux,
    FreeBsd,
    OpenBsd,
    NetBsd,
    Solaris,
    Android,
    BareMetal,
};

[[nodiscard]] constexpr std::string_view to_string(OsKind os) noexcept {
    switch (os) {
        case OsKind::Unknown:   return "Unknown";
        case OsKind::Windows:   return "Windows";
        case OsKind::Linux:     return "Linux";
        case OsKind::FreeBsd:   return "FreeBsd";
        case OsKind::OpenBsd:   return "OpenBsd";
        case OsKind::NetBsd:    return "NetBsd";
        case OsKind::Solaris:   return "Solaris";
        case OsKind::Android:   return "Android";
        case OsKind::BareMetal: return "BareMetal";
    }
    return "Unknown";
}

/// Complete target profile tuple `(Format, ImageKind, Architecture, Endianness,
/// AddressWidth, AbiKind, OsKind, BackendKind)`.
struct TargetProfile {
    Format format{Format::Unknown};
    ImageKind image_kind{ImageKind::Unknown};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Little};
    AddressWidth address_width{AddressWidth::Bits64};
    AbiKind abi{AbiKind::Unknown};
    OsKind os{OsKind::Unknown};
    BackendKind backend{BackendKind::StaticFile};
    std::uint8_t raw_elf_os_abi{0};

    [[nodiscard]] constexpr std::uint8_t pointer_byte_size() const noexcept {
        return address_width == AddressWidth::Bits64 ? 8u : 4u;
    }

    [[nodiscard]] constexpr bool is_completely_specified() const noexcept {
        return format != Format::Unknown &&
               architecture != Architecture::Unknown &&
               abi != AbiKind::Unknown &&
               os != OsKind::Unknown &&
               backend != BackendKind::Unknown;
    }

    auto operator<=>(const TargetProfile&) const = default;
};

/// Runtime availability of host/external tool providers, kept strictly distinct from
/// whether `peelf` has validated support for the target tuple.
struct ProviderFacts {
    OsKind host_os{OsKind::Unknown};
    Architecture host_arch{Architecture::Unknown};
    bool capstone_available{true};
    bool asmtk_available{true};
    bool llvm_mc_available{false};
    bool graphviz_dot_available{false};
    bool dia_sdk_available{false};
    bool ghidra_available{false};
    bool retdec_available{false};
    bool binary_ninja_available{false};
    bool native_process_attach_available{false};
    bool native_debugger_available{false};
    bool remote_gdb_stub_available{false};
    bool syscall_or_etw_trace_available{false};

    [[nodiscard]] static ProviderFacts detect_host_providers(
        std::string_view ghidra_install_dir = {},
        std::string_view retdec_decompiler_path = {},
        std::string_view binary_ninja_python = {});

    auto operator<=>(const ProviderFacts&) const = default;
};

/// Distinct analysis, inspection, editing, and debugging operations gated by `TargetCapabilityMatrix`.
enum class Operation : std::uint8_t {
    ImageParsing = 0,
    ExecutableSettings,
    Disassembly,
    ControlFlowGraph,
    ReferenceScan,
    StructuredDecompile,
    ExternalGhidraDecompile,
    ExternalRetDecDecompile,
    ExternalBinaryNinjaDecompile,
    InProcessAssemble,
    ExternalLlvmAssemble,
    StaticPatching,
    DebugSymbolsPdb,
    DebugSymbolsDwarf,
    SecurityAudit,
    LiveProcessAttach,
    DiskVsLiveDiff,
    StackUnwind,
    ThreadLocals,
    RuntimeStructures,
    ProcessInternals,
    ProcessSnapshotDiff,
    SoftwareBreakpoints,
    HardwareWatchpoints,
    ExecutionTimeline,
    SyscallOrEtwTimeline,
};

inline constexpr std::size_t kOperationCount = 26u;

[[nodiscard]] constexpr std::string_view to_string(Operation op) noexcept {
    switch (op) {
        case Operation::ImageParsing:                 return "ImageParsing";
        case Operation::ExecutableSettings:           return "ExecutableSettings";
        case Operation::Disassembly:                  return "Disassembly";
        case Operation::ControlFlowGraph:             return "ControlFlowGraph";
        case Operation::ReferenceScan:                return "ReferenceScan";
        case Operation::StructuredDecompile:          return "StructuredDecompile";
        case Operation::ExternalGhidraDecompile:      return "ExternalGhidraDecompile";
        case Operation::ExternalRetDecDecompile:      return "ExternalRetDecDecompile";
        case Operation::ExternalBinaryNinjaDecompile: return "ExternalBinaryNinjaDecompile";
        case Operation::InProcessAssemble:            return "InProcessAssemble";
        case Operation::ExternalLlvmAssemble:         return "ExternalLlvmAssemble";
        case Operation::StaticPatching:               return "StaticPatching";
        case Operation::DebugSymbolsPdb:              return "DebugSymbolsPdb";
        case Operation::DebugSymbolsDwarf:            return "DebugSymbolsDwarf";
        case Operation::SecurityAudit:                return "SecurityAudit";
        case Operation::LiveProcessAttach:            return "LiveProcessAttach";
        case Operation::DiskVsLiveDiff:               return "DiskVsLiveDiff";
        case Operation::StackUnwind:                  return "StackUnwind";
        case Operation::ThreadLocals:                 return "ThreadLocals";
        case Operation::RuntimeStructures:            return "RuntimeStructures";
        case Operation::ProcessInternals:             return "ProcessInternals";
        case Operation::ProcessSnapshotDiff:          return "ProcessSnapshotDiff";
        case Operation::SoftwareBreakpoints:          return "SoftwareBreakpoints";
        case Operation::HardwareWatchpoints:          return "HardwareWatchpoints";
        case Operation::ExecutionTimeline:            return "ExecutionTimeline";
        case Operation::SyscallOrEtwTimeline:         return "SyscallOrEtwTimeline";
    }
    return "ImageParsing";
}

/// Validation level for a `(TargetProfile, Operation)` pair.
enum class SupportState : std::uint8_t {
    Unsupported = 0,
    Partial,
    SupportedExperimental,
    SupportedValidated,
};

using SupportLevel = SupportState;

[[nodiscard]] constexpr std::string_view to_string(SupportState state) noexcept {
    switch (state) {
        case SupportState::Unsupported:           return "Unsupported";
        case SupportState::Partial:               return "Partial";
        case SupportState::SupportedExperimental: return "SupportedExperimental";
        case SupportState::SupportedValidated:    return "SupportedValidated";
    }
    return "Unsupported";
}

/// Capability entry separating target validation (`state`) from host provider readiness (`provider_available`).
struct Capability {
    Operation operation{Operation::ImageParsing};
    SupportState state{SupportState::Unsupported};
    bool provider_available{false};
    std::string provider_name{};
    std::string reason{};

    [[nodiscard]] constexpr bool is_supported() const noexcept {
        return state != SupportState::Unsupported;
    }

    [[nodiscard]] constexpr bool is_validated() const noexcept {
        return state == SupportState::SupportedValidated;
    }

    [[nodiscard]] constexpr bool can_execute() const noexcept {
        return is_supported() && provider_available;
    }

    [[nodiscard]] constexpr bool is_usable_now() const noexcept {
        return can_execute();
    }
};

/// Single source of truth for what operations are validated, partial, experimental, or
/// unsupported on a `TargetProfile`, alongside runtime `ProviderFacts`.
class TargetCapabilityMatrix {
public:
    TargetCapabilityMatrix();
    TargetCapabilityMatrix(TargetProfile profile,
                           ProviderFacts facts,
                           std::array<Capability, kOperationCount> entries);

    [[nodiscard]] const TargetProfile& profile() const noexcept { return profile_; }
    [[nodiscard]] const ProviderFacts& provider_facts() const noexcept { return facts_; }

    [[nodiscard]] const Capability& get(Operation op) const noexcept;
    [[nodiscard]] const Capability& operator[](Operation op) const noexcept { return get(op); }

    [[nodiscard]] std::span<const Capability> entries() const noexcept { return entries_; }

    [[nodiscard]] std::size_t validated_count() const noexcept;
    [[nodiscard]] std::size_t supported_count() const noexcept;
    [[nodiscard]] std::size_t missing_provider_count() const noexcept;

private:
    TargetProfile profile_{};
    ProviderFacts facts_{};
    std::array<Capability, kOperationCount> entries_{};
};

/// Derive an honest `TargetProfile` from a parsed `IBinaryImage` and/or `IProcessSession`.
/// Never assumes `OsKind::Linux` merely because `image->format() == Format::ELF`.
[[nodiscard]] TargetProfile derive_target_profile(
    const IBinaryImage* image,
    const IProcessSession* session = nullptr,
    bool active_debugger = false,
    bool remote_gdb_rsp = false);

/// Evaluate the full `TargetCapabilityMatrix` for `profile` and `facts`.
/// Unknown or contradictory `(Format, Architecture, Endianness, AddressWidth, AbiKind, OsKind, BackendKind)`
/// combinations default strictly to `SupportState::Unsupported`.
[[nodiscard]] TargetCapabilityMatrix capabilities_for(
    const TargetProfile& profile,
    const ProviderFacts& facts = {});

[[nodiscard]] inline TargetCapabilityMatrix compute_target_capabilities(
    const TargetProfile& profile,
    const ProviderFacts& facts = {}) {
    return capabilities_for(profile, facts);
}

} // namespace peelf
