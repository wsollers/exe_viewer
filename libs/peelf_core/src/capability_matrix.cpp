#include <peelf/capability_matrix.hpp>

#include <peelf/assembler.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/gdb_remote.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace peelf {
namespace {

[[nodiscard]] bool find_executable_on_path(std::string_view tool_stem) {
    const char* raw_path = nullptr;
#ifdef _WIN32
    char* dup_buf = nullptr;
    std::size_t dup_len = 0u;
    if (::_dupenv_s(&dup_buf, &dup_len, "PATH") == 0 && dup_buf != nullptr) {
        std::string path_copy(dup_buf);
        std::free(dup_buf);
        std::size_t start = 0u;
        while (start <= path_copy.size()) {
            const std::size_t sep = path_copy.find(';', start);
            const std::string_view dir = (sep == std::string::npos)
                ? std::string_view(path_copy).substr(start)
                : std::string_view(path_copy).substr(start, sep - start);
            if (!dir.empty()) {
                std::error_code ec;
                const std::filesystem::path base(dir);
                if (std::filesystem::is_regular_file(base / (std::string(tool_stem) + ".exe"), ec) ||
                    std::filesystem::is_regular_file(base / (std::string(tool_stem) + ".bat"), ec) ||
                    std::filesystem::is_regular_file(base / tool_stem, ec)) {
                    return true;
                }
            }
            if (sep == std::string::npos) {
                break;
            }
            start = sep + 1u;
        }
        return false;
    }
    return false;
#else
    raw_path = std::getenv("PATH");
    if (raw_path == nullptr) {
        return false;
    }
    const std::string_view path_view(raw_path);
    std::size_t start = 0u;
    while (start <= path_view.size()) {
        const std::size_t sep = path_view.find(':', start);
        const std::string_view dir = (sep == std::string_view::npos)
            ? path_view.substr(start)
            : path_view.substr(start, sep - start);
        if (!dir.empty()) {
            std::error_code ec;
            if (std::filesystem::is_regular_file(std::filesystem::path(dir) / tool_stem, ec)) {
                return true;
            }
        }
        if (sep == std::string_view::npos) {
            break;
        }
        start = sep + 1u;
    }
    return false;
#endif
}

[[nodiscard]] std::string read_env_var(const char* name) {
#ifdef _WIN32
    char* dup_buf = nullptr;
    std::size_t dup_len = 0u;
    if (::_dupenv_s(&dup_buf, &dup_len, name) == 0 && dup_buf != nullptr) {
        std::string val(dup_buf);
        std::free(dup_buf);
        return val;
    }
    return {};
#else
    const char* raw = std::getenv(name);
    return raw != nullptr ? std::string(raw) : std::string{};
#endif
}

enum class IsaTier : std::uint8_t {
    Invalid = 0,
    Experimental,
    Validated,
};

[[nodiscard]] constexpr IsaTier classify_isa_tuple(
    Architecture arch,
    AddressWidth width,
    Endianness endian) noexcept {
    switch (arch) {
        case Architecture::X86:
            return (width == AddressWidth::Bits32 && endian == Endianness::Little)
                       ? IsaTier::Validated
                       : IsaTier::Invalid;
        case Architecture::X86_64:
            return (width == AddressWidth::Bits64 && endian == Endianness::Little)
                       ? IsaTier::Validated
                       : IsaTier::Invalid;
        case Architecture::ARM:
            if (width != AddressWidth::Bits32) {
                return IsaTier::Invalid;
            }
            return endian == Endianness::Little ? IsaTier::Validated : IsaTier::Experimental;
        case Architecture::ARM64:
            if (width != AddressWidth::Bits64) {
                return IsaTier::Invalid;
            }
            return endian == Endianness::Little ? IsaTier::Validated : IsaTier::Experimental;
        case Architecture::RISCV32:
            return (width == AddressWidth::Bits32 && endian == Endianness::Little)
                       ? IsaTier::Validated
                       : IsaTier::Invalid;
        case Architecture::RISCV64:
            return (width == AddressWidth::Bits64 && endian == Endianness::Little)
                       ? IsaTier::Validated
                       : IsaTier::Invalid;
        case Architecture::MIPS32:
            return width == AddressWidth::Bits32 ? IsaTier::Validated : IsaTier::Invalid;
        case Architecture::MIPS64:
            return width == AddressWidth::Bits64 ? IsaTier::Validated : IsaTier::Invalid;
        case Architecture::PowerPC:
            if (width != AddressWidth::Bits32) {
                return IsaTier::Invalid;
            }
            return endian == Endianness::Big ? IsaTier::Validated : IsaTier::Experimental;
        case Architecture::PowerPC64:
            return width == AddressWidth::Bits64 ? IsaTier::Validated : IsaTier::Invalid;
        case Architecture::Unknown:
            return IsaTier::Invalid;
    }
    return IsaTier::Invalid;
}

[[nodiscard]] constexpr bool is_known_format(Format fmt) noexcept {
    return fmt == Format::PE || fmt == Format::ELF || fmt == Format::MachO || fmt == Format::Unknown;
}

[[nodiscard]] constexpr bool is_known_endianness(Endianness endian) noexcept {
    return endian == Endianness::Little || endian == Endianness::Big;
}

[[nodiscard]] constexpr bool is_known_width(AddressWidth width) noexcept {
    return width == AddressWidth::Bits32 || width == AddressWidth::Bits64;
}

[[nodiscard]] constexpr bool is_known_abi(AbiKind abi) noexcept {
    switch (abi) {
        case AbiKind::Unknown:
        case AbiKind::PeWindows32:
        case AbiKind::PeWindows64:
        case AbiKind::SysV:
        case AbiKind::GnuLinux:
        case AbiKind::ArmEabi:
        case AbiKind::AArch64SysV:
        case AbiKind::FreeBsd:
        case AbiKind::OpenBsd:
        case AbiKind::NetBsd:
        case AbiKind::Solaris:
        case AbiKind::Standalone:
            return true;
    }
    return false;
}

[[nodiscard]] constexpr bool is_known_os(OsKind os) noexcept {
    switch (os) {
        case OsKind::Unknown:
        case OsKind::Windows:
        case OsKind::Linux:
        case OsKind::FreeBsd:
        case OsKind::OpenBsd:
        case OsKind::NetBsd:
        case OsKind::Solaris:
        case OsKind::Android:
        case OsKind::BareMetal:
            return true;
    }
    return false;
}

[[nodiscard]] constexpr bool is_known_backend(BackendKind backend) noexcept {
    switch (backend) {
        case BackendKind::StaticFile:
        case BackendKind::LiveNativeReadOnly:
        case BackendKind::CrashDumpMinidump:
        case BackendKind::CrashDumpElfCore:
        case BackendKind::ActiveDebugger:
        case BackendKind::RemoteGdbRsp:
            return true;
        case BackendKind::Unknown:
            return false;
    }
    return false;
}

[[nodiscard]] constexpr bool is_pe_abi_os_coherent(const TargetProfile& p) noexcept {
    if (p.endianness != Endianness::Little) {
        return false;
    }
    if (p.os != OsKind::Windows && p.os != OsKind::Unknown && p.os != OsKind::BareMetal) {
        return false;
    }
    if (p.address_width == AddressWidth::Bits32) {
        return p.abi == AbiKind::PeWindows32 || p.abi == AbiKind::Unknown;
    }
    return p.abi == AbiKind::PeWindows64 || p.abi == AbiKind::Unknown;
}

[[nodiscard]] constexpr bool is_elf_abi_os_coherent(const TargetProfile& p) noexcept {
    if (p.os == OsKind::Windows) {
        return false;
    }
    if (p.abi == AbiKind::PeWindows32 || p.abi == AbiKind::PeWindows64) {
        return false;
    }
    if (p.abi == AbiKind::ArmEabi && p.architecture != Architecture::ARM) {
        return false;
    }
    if (p.abi == AbiKind::AArch64SysV && p.architecture != Architecture::ARM64) {
        return false;
    }
    return true;
}

[[nodiscard]] constexpr SupportState pe_static_support(const TargetProfile& p) noexcept {
    if (!is_pe_abi_os_coherent(p)) {
        return SupportState::Unsupported;
    }
    switch (p.architecture) {
        case Architecture::X86:
            return p.address_width == AddressWidth::Bits32
                       ? SupportState::SupportedValidated
                       : SupportState::Unsupported;
        case Architecture::X86_64:
            return p.address_width == AddressWidth::Bits64
                       ? SupportState::SupportedValidated
                       : SupportState::Unsupported;
        case Architecture::ARM:
            return p.address_width == AddressWidth::Bits32
                       ? SupportState::SupportedExperimental
                       : SupportState::Unsupported;
        case Architecture::ARM64:
            return p.address_width == AddressWidth::Bits64
                       ? SupportState::SupportedExperimental
                       : SupportState::Unsupported;
        case Architecture::RISCV32:
            return p.address_width == AddressWidth::Bits32
                       ? SupportState::SupportedExperimental
                       : SupportState::Unsupported;
        case Architecture::RISCV64:
            return p.address_width == AddressWidth::Bits64
                       ? SupportState::SupportedExperimental
                       : SupportState::Unsupported;
        default:
            return SupportState::Unsupported;
    }
}

[[nodiscard]] constexpr SupportState elf_static_support(
    const TargetProfile& p,
    IsaTier isa_tier) noexcept {
    if (!is_elf_abi_os_coherent(p) || isa_tier == IsaTier::Invalid) {
        return SupportState::Unsupported;
    }
    return isa_tier == IsaTier::Validated
               ? SupportState::SupportedValidated
               : SupportState::SupportedExperimental;
}

[[nodiscard]] constexpr SupportState macho_static_support(
    const TargetProfile& p,
    IsaTier isa_tier) noexcept {
    if (p.os == OsKind::Windows ||
        p.abi == AbiKind::PeWindows32 ||
        p.abi == AbiKind::PeWindows64 ||
        isa_tier == IsaTier::Invalid) {
        return SupportState::Unsupported;
    }
    return isa_tier == IsaTier::Validated
               ? SupportState::SupportedValidated
               : SupportState::SupportedExperimental;
}

[[nodiscard]] std::uint32_t read_note_u32(
    std::span<const std::uint8_t> desc,
    std::size_t offset,
    Endianness endian) noexcept {
    if (offset + 4u > desc.size()) {
        return 0xFFFF'FFFFu;
    }
    if (endian == Endianness::Big) {
        return (static_cast<std::uint32_t>(desc[offset]) << 24u) |
               (static_cast<std::uint32_t>(desc[offset + 1u]) << 16u) |
               (static_cast<std::uint32_t>(desc[offset + 2u]) << 8u) |
               static_cast<std::uint32_t>(desc[offset + 3u]);
    }
    return static_cast<std::uint32_t>(desc[offset]) |
           (static_cast<std::uint32_t>(desc[offset + 1u]) << 8u) |
           (static_cast<std::uint32_t>(desc[offset + 2u]) << 16u) |
           (static_cast<std::uint32_t>(desc[offset + 3u]) << 24u);
}

void classify_elf_abi_and_os(const IBinaryImage& image, TargetProfile& profile) {
    const ElfHeader* ehdr = image.elf_header();
    const std::uint8_t os_abi = ehdr != nullptr ? ehdr->os_abi : 0u;
    profile.raw_elf_os_abi = os_abi;

    switch (os_abi) {
        case 3u: // ELFOSABI_GNU / ELFOSABI_LINUX
            profile.os = OsKind::Linux;
            profile.abi = AbiKind::GnuLinux;
            return;
        case 9u: // ELFOSABI_FREEBSD
            profile.os = OsKind::FreeBsd;
            profile.abi = AbiKind::FreeBsd;
            return;
        case 12u: // ELFOSABI_OPENBSD
            profile.os = OsKind::OpenBsd;
            profile.abi = AbiKind::OpenBsd;
            return;
        case 2u: // ELFOSABI_NETBSD
            profile.os = OsKind::NetBsd;
            profile.abi = AbiKind::NetBsd;
            return;
        case 6u: // ELFOSABI_SOLARIS
            profile.os = OsKind::Solaris;
            profile.abi = AbiKind::Solaris;
            return;
        case 64u: // ELFOSABI_ARM_AEABI
            profile.os = OsKind::Unknown;
            profile.abi = AbiKind::ArmEabi;
            break;
        case 255u: // ELFOSABI_STANDALONE
            profile.os = OsKind::BareMetal;
            profile.abi = AbiKind::Standalone;
            return;
        default:
            break;
    }

    // Inspect ELF notes for explicit OS tags (.note.ABI-tag, FreeBSD/OpenBSD/NetBSD/Android notes).
    // Never infer OsKind::Linux when EI_OSABI == ELFOSABI_NONE (0) and no OS note is present!
    for (const ElfNote& note : image.elf_notes()) {
        if ((note.name == "Android" || note.name.starts_with("Android")) && note.type == 1u) {
            profile.os = OsKind::Android;
            profile.abi = profile.architecture == Architecture::ARM ? AbiKind::ArmEabi : AbiKind::GnuLinux;
            return;
        }
        if (note.name == "FreeBSD" || note.name.starts_with("FreeBSD")) {
            profile.os = OsKind::FreeBsd;
            profile.abi = AbiKind::FreeBsd;
            return;
        }
        if (note.name == "OpenBSD" || note.name.starts_with("OpenBSD")) {
            profile.os = OsKind::OpenBsd;
            profile.abi = AbiKind::OpenBsd;
            return;
        }
        if (note.name == "NetBSD" || note.name.starts_with("NetBSD")) {
            profile.os = OsKind::NetBsd;
            profile.abi = AbiKind::NetBsd;
            return;
        }
        // NT_GNU_ABI_TAG == 1, owner "GNU": descriptor[0..3] = OS (0=Linux, 1=Hurd, 2=Solaris, 3=FreeBSD, 4=NetBSD)
        if ((note.name == "GNU" || note.name.starts_with("GNU")) &&
            note.type == 1u &&
            note.descriptor.size() >= 16u) {
            const std::uint32_t gnu_os = read_note_u32(note.descriptor, 0u, image.endianness());
            switch (gnu_os) {
                case 0u:
                    profile.os = OsKind::Linux;
                    profile.abi = AbiKind::GnuLinux;
                    return;
                case 2u:
                    profile.os = OsKind::Solaris;
                    profile.abi = AbiKind::Solaris;
                    return;
                case 3u:
                    profile.os = OsKind::FreeBsd;
                    profile.abi = AbiKind::FreeBsd;
                    return;
                case 4u:
                    profile.os = OsKind::NetBsd;
                    profile.abi = AbiKind::NetBsd;
                    return;
                default:
                    break;
            }
        }
    }

    // Also inspect PT_INTERP when explicitly pointing to a known dynamic loader ABI,
    // while keeping bare/freestanding ELFOSABI_NONE files at OsKind::Unknown.
    const std::string_view interp = image.elf_interpreter();
    if (!interp.empty()) {
        if (interp.find("ld-linux") != std::string_view::npos ||
            interp.find("ld-musl") != std::string_view::npos) {
            profile.os = OsKind::Linux;
            profile.abi = AbiKind::GnuLinux;
            return;
        }
        if (interp.find("/system/bin/linker") != std::string_view::npos) {
            profile.os = OsKind::Android;
            profile.abi = profile.architecture == Architecture::ARM ? AbiKind::ArmEabi : AbiKind::GnuLinux;
            return;
        }
        if (interp.find("ld-elf.so") != std::string_view::npos &&
            interp.find("freebsd") != std::string_view::npos) {
            profile.os = OsKind::FreeBsd;
            profile.abi = AbiKind::FreeBsd;
            return;
        }
    }

    profile.os = OsKind::Unknown;
    if (profile.abi == AbiKind::Unknown) {
        if (profile.architecture == Architecture::ARM) {
            profile.abi = AbiKind::ArmEabi;
        } else if (profile.architecture == Architecture::ARM64) {
            profile.abi = AbiKind::AArch64SysV;
        } else if (os_abi == 0u) {
            profile.abi = AbiKind::SysV;
        }
    }
}

} // namespace

ProviderFacts ProviderFacts::detect_host_providers(
    std::string_view ghidra_install_dir,
    std::string_view retdec_decompiler_path,
    std::string_view binary_ninja_python) {
    ProviderFacts facts;
    facts.capstone_available = true;
    facts.asmtk_available = true;
    facts.llvm_mc_available = !LlvmMcAssemblerProvider{}.executable_path().empty();
    facts.graphviz_dot_available = find_executable_on_path("dot");

#if defined(__x86_64__) || defined(_M_X64)
    facts.host_arch = Architecture::X86_64;
#elif defined(__i386__) || defined(_M_IX86)
    facts.host_arch = Architecture::X86;
#elif defined(__aarch64__) || defined(_M_ARM64)
    facts.host_arch = Architecture::ARM64;
#elif defined(__arm__) || defined(_M_ARM)
    facts.host_arch = Architecture::ARM;
#endif

#ifdef _WIN32
    facts.host_os = OsKind::Windows;
    facts.dia_sdk_available = true;
    facts.native_process_attach_available = true;
    facts.native_debugger_available = true;
#elif defined(__linux__)
    facts.host_os = OsKind::Linux;
    facts.dia_sdk_available = false;
    facts.native_process_attach_available = true;
    facts.native_debugger_available = true;
#else
    facts.host_os = OsKind::Unknown;
    facts.dia_sdk_available = false;
    facts.native_process_attach_available = false;
    facts.native_debugger_available = false;
#endif

    std::error_code ec;
    const std::string ghidra_dir = !ghidra_install_dir.empty()
                                       ? std::string(ghidra_install_dir)
                                       : read_env_var("GHIDRA_INSTALL_DIR");
    if (!ghidra_dir.empty()) {
        const std::filesystem::path gpath(ghidra_dir);
        facts.ghidra_available =
            std::filesystem::is_regular_file(gpath / "support" / "analyzeHeadless", ec) ||
            std::filesystem::is_regular_file(gpath / "support" / "analyzeHeadless.bat", ec);
    } else {
        facts.ghidra_available = find_executable_on_path("analyzeHeadless");
    }

    if (!retdec_decompiler_path.empty()) {
        facts.retdec_available =
            std::filesystem::is_regular_file(std::filesystem::path(retdec_decompiler_path), ec);
    } else {
        const std::string env_retdec = read_env_var("RETDEC_DECOMPILER");
        facts.retdec_available = !env_retdec.empty()
            ? std::filesystem::is_regular_file(std::filesystem::path(env_retdec), ec)
            : find_executable_on_path("retdec-decompiler");
    }

    if (!binary_ninja_python.empty()) {
        facts.binary_ninja_available =
            std::filesystem::is_regular_file(std::filesystem::path(binary_ninja_python), ec);
    } else {
        const std::string env_bn = read_env_var("PEELF_BN_PYTHON");
        facts.binary_ninja_available =
            !env_bn.empty() && std::filesystem::is_regular_file(std::filesystem::path(env_bn), ec);
    }

    return facts;
}

TargetCapabilityMatrix::TargetCapabilityMatrix() {
    for (std::size_t i = 0u; i < kOperationCount; ++i) {
        entries_[i].operation = static_cast<Operation>(i);
        entries_[i].state = SupportState::Unsupported;
        entries_[i].provider_available = false;
        entries_[i].reason = "Target profile not evaluated";
    }
}

TargetCapabilityMatrix::TargetCapabilityMatrix(
    TargetProfile profile,
    ProviderFacts facts,
    std::array<Capability, kOperationCount> entries)
    : profile_(profile)
    , facts_(facts)
    , entries_(std::move(entries)) {}

const Capability& TargetCapabilityMatrix::get(Operation op) const noexcept {
    const auto idx = static_cast<std::size_t>(op);
    if (idx < kOperationCount) {
        return entries_[idx];
    }
    return entries_[0];
}

std::size_t TargetCapabilityMatrix::validated_count() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(
        entries_,
        [](const Capability& c) { return c.state == SupportState::SupportedValidated; }));
}

std::size_t TargetCapabilityMatrix::supported_count() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(
        entries_,
        [](const Capability& c) { return c.state != SupportState::Unsupported; }));
}

std::size_t TargetCapabilityMatrix::missing_provider_count() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(
        entries_,
        [](const Capability& c) {
            return c.state != SupportState::Unsupported && !c.provider_available;
        }));
}

TargetProfile derive_target_profile(
    const IBinaryImage* image,
    const IProcessSession* session,
    bool active_debugger,
    bool remote_gdb_rsp) {
    TargetProfile p;

    if (image != nullptr) {
        p.format = image->format();
        p.image_kind = image->kind();
        p.architecture = image->architecture();
        p.endianness = image->endianness();
        p.address_width = image->is_64bit() ? AddressWidth::Bits64 : AddressWidth::Bits32;

        if (p.format == Format::PE) {
            // PE Subsystem == 1 (NATIVE) may represent kernel/boot drivers; user-mode PE targets Windows.
            const PeHeader* pe = image->pe_header();
            if (pe != nullptr && (pe->subsystem >= 10u && pe->subsystem <= 13u)) {
                p.os = OsKind::BareMetal; // EFI application / driver / ROM
            } else {
                p.os = OsKind::Windows;
            }
            p.abi = p.address_width == AddressWidth::Bits64 ? AbiKind::PeWindows64 : AbiKind::PeWindows32;
        } else if (p.format == Format::ELF) {
            classify_elf_abi_and_os(*image, p);
        } else if (p.format == Format::MachO) {
            if (p.architecture == Architecture::ARM64) {
                p.abi = AbiKind::AArch64SysV;
            } else if (p.architecture == Architecture::ARM) {
                p.abi = AbiKind::ArmEabi;
            } else {
                p.abi = AbiKind::SysV;
            }
        }
    }

    if (session != nullptr) {
        if (session->is_crash_dump()) {
            const auto* dump = dynamic_cast<const ICrashDumpSession*>(session);
            if (dump != nullptr) {
                const CrashDumpSummary& cs = dump->crash_summary();
                p.backend = cs.kind == CrashDumpKind::WindowsMinidump
                                ? BackendKind::CrashDumpMinidump
                                : BackendKind::CrashDumpElfCore;
                if (p.architecture == Architecture::Unknown) {
                    p.architecture = cs.layout.architecture;
                    p.address_width = cs.layout.address_width;
                    p.endianness = cs.layout.endianness;
                }
                if (cs.kind == CrashDumpKind::WindowsMinidump) {
                    p.os = OsKind::Windows;
                    if (p.abi == AbiKind::Unknown) {
                        p.abi = p.address_width == AddressWidth::Bits64
                                    ? AbiKind::PeWindows64
                                    : AbiKind::PeWindows32;
                    }
                } else {
                    p.os = OsKind::Linux;
                    if (p.abi == AbiKind::Unknown || p.abi == AbiKind::SysV) {
                        p.abi = AbiKind::GnuLinux;
                    }
                }
            } else {
                p.backend = BackendKind::CrashDumpElfCore;
            }
        } else if (const auto* gdb = dynamic_cast<const IGdbRemoteSession*>(session);
                   gdb != nullptr) {
            const TargetProfile& gp = gdb->target_profile();
            p.backend = BackendKind::GdbRemote;
            if (p.architecture == Architecture::Unknown) {
                p.architecture = gp.architecture;
                p.address_width = gp.address_width;
                p.endianness = gp.endianness;
            }
            if (p.os == OsKind::Unknown) {
                p.os = gp.os;
            }
            if (p.abi == AbiKind::Unknown) {
                p.abi = gp.abi;
            }
            if (p.format == Format::Unknown) {
                p.format = gp.format;
                p.image_kind = gp.image_kind;
            }
        } else if (remote_gdb_rsp) {
            p.backend = BackendKind::RemoteGdbRsp;
            if (p.architecture == Architecture::Unknown &&
                session->info().architecture != Architecture::Unknown) {
                p.architecture = session->info().architecture;
                p.endianness = session->info().endianness;
            }
        } else {
            p.backend = active_debugger ? BackendKind::ActiveDebugger : BackendKind::LiveNativeReadOnly;
            if (p.architecture == Architecture::Unknown &&
                session->info().architecture != Architecture::Unknown) {
                p.architecture = session->info().architecture;
                p.endianness = session->info().endianness;
                const bool is32 = p.architecture == Architecture::X86 ||
                                  p.architecture == Architecture::ARM ||
                                  p.architecture == Architecture::RISCV32 ||
                                  p.architecture == Architecture::MIPS32 ||
                                  p.architecture == Architecture::PowerPC;
                p.address_width = is32 ? AddressWidth::Bits32 : AddressWidth::Bits64;
            }
#ifdef _WIN32
            if (p.os == OsKind::Unknown) {
                p.os = OsKind::Windows;
            }
            if (p.abi == AbiKind::Unknown) {
                p.abi = p.address_width == AddressWidth::Bits64
                            ? AbiKind::PeWindows64
                            : AbiKind::PeWindows32;
            }
#elif defined(__linux__)
            if (p.os == OsKind::Unknown) {
                p.os = OsKind::Linux;
            }
            if (p.abi == AbiKind::Unknown || p.abi == AbiKind::SysV) {
                p.abi = AbiKind::GnuLinux;
            }
#endif
        }
    } else {
        if (remote_gdb_rsp) {
            p.backend = BackendKind::RemoteGdbRsp;
        } else if (active_debugger) {
            p.backend = BackendKind::ActiveDebugger;
        } else {
            p.backend = BackendKind::StaticFile;
        }
    }

    return p;
}

TargetCapabilityMatrix capabilities_for(
    const TargetProfile& profile,
    const ProviderFacts& facts) {
    std::array<Capability, kOperationCount> entries{};
    for (std::size_t i = 0u; i < kOperationCount; ++i) {
        entries[i].operation = static_cast<Operation>(i);
        entries[i].state = SupportState::Unsupported;
        entries[i].provider_available = false;
        entries[i].reason = "Unsupported target profile combination";
    }

    auto set_cap = [&](Operation op,
                       SupportState st,
                       bool prov_ok,
                       std::string_view prov_name,
                       std::string reason) {
        Capability& c = entries[static_cast<std::size_t>(op)];
        c.operation = op;
        c.state = st;
        c.provider_available = prov_ok;
        c.provider_name = std::string(prov_name);
        c.reason = std::move(reason);
    };

    // Guard 1: Reject unknown/corrupt enum values or invalid ISA/width/endianness tuples immediately.
    if (!is_known_format(profile.format) ||
        !is_known_endianness(profile.endianness) ||
        !is_known_width(profile.address_width) ||
        !is_known_abi(profile.abi) ||
        !is_known_os(profile.os) ||
        !is_known_backend(profile.backend)) {
        return TargetCapabilityMatrix(profile, facts, std::move(entries));
    }

    const IsaTier isa_tier = classify_isa_tuple(
        profile.architecture,
        profile.address_width,
        profile.endianness);
    if (isa_tier == IsaTier::Invalid) {
        for (Capability& c : entries) {
            c.reason = std::format(
                "Invalid or unvalidated architecture/width/endianness tuple ({}, {}, {})",
                to_string(profile.architecture),
                to_string(profile.address_width),
                to_string(profile.endianness));
        }
        return TargetCapabilityMatrix(profile, facts, std::move(entries));
    }

    // Guard 2: Backend vs OS coherence (e.g. Windows Minidump with Linux OS, or ELF core with Windows OS).
    if ((profile.backend == BackendKind::CrashDumpMinidump &&
         profile.os != OsKind::Windows && profile.os != OsKind::Unknown) ||
        (profile.backend == BackendKind::CrashDumpElfCore &&
         profile.os == OsKind::Windows)) {
        for (Capability& c : entries) {
            c.reason = std::format(
                "Contradictory backend/OS combination ({} with {})",
                to_string(profile.backend),
                to_string(profile.os));
        }
        return TargetCapabilityMatrix(profile, facts, std::move(entries));
    }

    // Static format support tier
    SupportState format_tier = SupportState::Unsupported;
    if (profile.format == Format::PE) {
        format_tier = pe_static_support(profile);
    } else if (profile.format == Format::ELF) {
        format_tier = elf_static_support(profile, isa_tier);
    } else if (profile.format == Format::MachO) {
        format_tier = macho_static_support(profile, isa_tier);
    }

    if (profile.format != Format::Unknown && format_tier == SupportState::Unsupported) {
        for (Capability& c : entries) {
            c.reason = std::format(
                "Unsupported container/ISA/ABI/OS combination ({}, {}, {}, {}, {})",
                to_string(profile.format),
                to_string(profile.architecture),
                to_string(profile.endianness),
                to_string(profile.abi),
                to_string(profile.os));
        }
        return TargetCapabilityMatrix(profile, facts, std::move(entries));
    }

    const SupportState code_tier = (profile.format != Format::Unknown)
        ? format_tier
        : (isa_tier == IsaTier::Validated ? SupportState::SupportedValidated
                                          : SupportState::SupportedExperimental);

    // 1. ImageParsing & ExecutableSettings
    if (profile.format == Format::PE ||
        profile.format == Format::ELF ||
        profile.format == Format::MachO) {
        set_cap(Operation::ImageParsing,
                format_tier,
                true,
                "peelf_core",
                std::format("{} image parser ({})", to_string(profile.format), to_string(format_tier)));
        set_cap(Operation::ExecutableSettings,
                format_tier,
                true,
                "peelf_core",
                profile.format == Format::PE
                    ? "Bounded PE RT_MANIFEST, RT_VERSION, and CLR metadata extraction"
                    : (profile.format == Format::ELF
                           ? "Bounded ELF PT_INTERP, GNU notes, and dynamic settings extraction"
                           : "Bounded Mach-O LC_BUILD_VERSION, rpath, entitlements, and code-signature metadata extraction"));
    } else {
        set_cap(Operation::ImageParsing,
                SupportState::Unsupported,
                true,
                "peelf_core",
                "No parsed PE or ELF container header for active target");
        set_cap(Operation::ExecutableSettings,
                (profile.backend == BackendKind::LiveNativeReadOnly ||
                 profile.backend == BackendKind::ActiveDebugger ||
                 profile.backend == BackendKind::CrashDumpMinidump ||
                 profile.backend == BackendKind::CrashDumpElfCore)
                    ? SupportState::Partial
                    : SupportState::Unsupported,
                true,
                "peelf_core",
                "Declared file metadata unavailable without PE/ELF image; runtime sections only");
    }

    // 2. Disassembly, CFG, ReferenceScan, StructuredDecompile
    set_cap(Operation::Disassembly,
            code_tier,
            facts.capstone_available,
            "Capstone",
            facts.capstone_available
                ? std::format("Capstone disassembly for {} ({})",
                              to_string(profile.architecture),
                              to_string(profile.endianness))
                : "Capstone provider unavailable");

    set_cap(Operation::ControlFlowGraph,
            code_tier,
            facts.capstone_available,
            "peelf_cfg+Capstone",
            facts.graphviz_dot_available
                ? "Basic-block CFG recovery + Graphviz DOT layout"
                : "Basic-block CFG recovery (built-in Sugiyama layout; Graphviz 'dot' optional)");

    set_cap(Operation::ReferenceScan,
            code_tier,
            facts.capstone_available,
            "peelf_xref",
            "Cross-architecture instruction, pointer-slot, and string reference scanner");

    set_cap(Operation::StructuredDecompile,
            code_tier,
            facts.capstone_available,
            "peelf_structured_decompiler",
            "Built-in multi-architecture structured pseudo-C decompiler");

    // 3. External Decompiler Bridges (separate validated target support from runtime provider presence)
    set_cap(Operation::ExternalGhidraDecompile,
            code_tier,
            facts.ghidra_available,
            "Ghidra Headless",
            facts.ghidra_available
                ? "Ghidra analyzeHeadless bridge ready"
                : "Target supported by Ghidra bridge; set GHIDRA_INSTALL_DIR to enable execution");

    const bool retdec_arch_ok =
        profile.endianness == Endianness::Little &&
        (profile.architecture == Architecture::X86 ||
         profile.architecture == Architecture::X86_64 ||
         profile.architecture == Architecture::ARM ||
         profile.architecture == Architecture::ARM64 ||
         profile.architecture == Architecture::MIPS32 ||
         profile.architecture == Architecture::PowerPC);
    set_cap(Operation::ExternalRetDecDecompile,
            (retdec_arch_ok && profile.format != Format::Unknown)
                ? SupportState::SupportedExperimental
                : SupportState::Unsupported,
            facts.retdec_available,
            "RetDec",
            retdec_arch_ok
                ? (facts.retdec_available
                       ? "RetDec CLI decompiler ready"
                       : "Target supported experimentally by RetDec; configure retdec-decompiler path")
                : "RetDec does not support this architecture/endianness tuple");

    const bool bn_arch_ok =
        profile.architecture == Architecture::X86 ||
        profile.architecture == Architecture::X86_64 ||
        profile.architecture == Architecture::ARM ||
        profile.architecture == Architecture::ARM64 ||
        profile.architecture == Architecture::RISCV32 ||
        profile.architecture == Architecture::RISCV64 ||
        profile.architecture == Architecture::MIPS32 ||
        profile.architecture == Architecture::MIPS64 ||
        profile.architecture == Architecture::PowerPC;
    set_cap(Operation::ExternalBinaryNinjaDecompile,
            (bn_arch_ok && profile.format != Format::Unknown)
                ? SupportState::SupportedExperimental
                : SupportState::Unsupported,
            facts.binary_ninja_available,
            "Binary Ninja HLIL",
            bn_arch_ok
                ? (facts.binary_ninja_available
                       ? "Binary Ninja headless Python bridge ready"
                       : "Target supported experimentally by Binary Ninja bridge; configure PEELF_BN_PYTHON")
                : "Binary Ninja bridge unvalidated for this architecture");

    // 4. Assembly & Patching
    const bool is_x86_family =
        (profile.architecture == Architecture::X86 || profile.architecture == Architecture::X86_64) &&
        profile.endianness == Endianness::Little;
    const bool writable_target =
        profile.backend == BackendKind::StaticFile ||
        profile.backend == BackendKind::LiveNativeReadOnly ||
        profile.backend == BackendKind::ActiveDebugger;

    set_cap(Operation::InProcessAssemble,
            (is_x86_family && writable_target) ? SupportState::SupportedValidated : SupportState::Unsupported,
            facts.asmtk_available,
            "AsmJit/AsmTK",
            !writable_target
                ? "Crash dumps and read-only remote stubs do not permit instruction assembly patching"
                : (is_x86_family
                       ? "In-process AsmTK x86/x86_64 instruction assembler"
                       : "AsmTK only supports x86/x86_64; use ExternalLlvmAssemble (llvm-mc) for non-x86 ISAs"));

    set_cap(Operation::ExternalLlvmAssemble,
            writable_target ? code_tier : SupportState::Unsupported,
            facts.llvm_mc_available,
            "llvm-mc",
            !writable_target
                ? "Target session is strictly read-only"
                : (facts.llvm_mc_available
                       ? "External llvm-mc multi-architecture assembler available"
                       : "Target ISA supported via llvm-mc; install llvm-mc on PATH to enable"));

    set_cap(Operation::StaticPatching,
            (profile.backend == BackendKind::StaticFile &&
             (profile.format == Format::PE ||
              profile.format == Format::ELF ||
              profile.format == Format::MachO))
                ? format_tier
                : SupportState::Unsupported,
            true,
            "PagedBinaryImage",
            profile.backend == BackendKind::StaticFile
                ? "Transactional copy-on-write binary patching and code-cave allocation"
                : "Static file patching requires StaticFile backend");

    // 5. Debug Symbols (PDB & DWARF)
    if (profile.format == Format::PE) {
        set_cap(Operation::DebugSymbolsPdb,
                facts.dia_sdk_available ? format_tier : SupportState::Partial,
                facts.dia_sdk_available,
                "DIA SDK / RSDS",
                facts.dia_sdk_available
                    ? "CodeView RSDS GUID+Age verification and DIA PDB symbol/type/line loading"
                    : "RSDS GUID+Age parsed cross-platform; full PDB stream loading requires Windows DIA SDK");
        // MinGW PE images may also carry DWARF sections!
        set_cap(Operation::DebugSymbolsDwarf,
                format_tier,
                true,
                "peelf_dwarf",
                "Embedded DWARF v4/v5 symbol, type, and line reader (for MinGW/Clang PE builds)");
    } else if (profile.format == Format::ELF || profile.format == Format::MachO) {
        set_cap(Operation::DebugSymbolsPdb,
                SupportState::Unsupported,
                facts.dia_sdk_available,
                "DIA SDK",
                profile.format == Format::ELF
                    ? "PDB debug symbols apply to PE/COFF targets, not ELF"
                    : "PDB debug symbols apply to PE/COFF targets, not Mach-O");
        set_cap(Operation::DebugSymbolsDwarf,
                format_tier,
                true,
                "peelf_dwarf",
                profile.format == Format::ELF
                    ? "Built-in DWARF v4/v5 (.debug_info/.debug_line/.gnu_debuglink/build-id) reader"
                    : "Built-in DWARF v4/v5 (__DWARF / dSYM) symbol, type, and line reader");
    } else {
        set_cap(Operation::DebugSymbolsPdb,
                SupportState::Unsupported,
                facts.dia_sdk_available,
                "DIA SDK",
                "No PE container loaded");
        set_cap(Operation::DebugSymbolsDwarf,
                SupportState::Unsupported,
                true,
                "peelf_dwarf",
                "No ELF/PE/Mach-O container loaded");
    }

    // 6. Security Audit
    const bool is_live_or_dump =
        profile.backend == BackendKind::LiveNativeReadOnly ||
        profile.backend == BackendKind::ActiveDebugger ||
        profile.backend == BackendKind::CrashDumpMinidump ||
        profile.backend == BackendKind::CrashDumpElfCore;

    if (profile.format == Format::PE ||
        profile.format == Format::ELF ||
        profile.format == Format::MachO) {
        set_cap(Operation::SecurityAudit,
                format_tier,
                true,
                "peelf_security_audit",
                is_live_or_dump
                    ? "Static container mitigation rules + live RWX/unbacked-code/token rules"
                    : (profile.format == Format::MachO
                           ? "Static Mach-O mitigation, entitlements, and code-signature posture audit"
                           : "Static PE/ELF mitigation and hardening audit"));
    } else if (is_live_or_dump && (profile.os == OsKind::Linux || profile.os == OsKind::Windows)) {
        set_cap(Operation::SecurityAudit,
                SupportState::Partial,
                true,
                "peelf_security_audit",
                "Live-process memory/privilege audit only (no parsed static container)");
    } else {
        set_cap(Operation::SecurityAudit,
                SupportState::Unsupported,
                true,
                "peelf_security_audit",
                "Security audit requires a PE/ELF binary or supported Windows/Linux session");
    }

    // 7. Live / Crash-Dump / Debugger Operations
    const bool is_validated_live_os =
        (profile.os == OsKind::Linux || profile.os == OsKind::Windows);
    const bool host_matches_target_os =
        facts.host_os == OsKind::Unknown || facts.host_os == profile.os;
    const bool native_attach_provider_ok =
        facts.native_process_attach_available && host_matches_target_os;
    const bool native_dbg_provider_ok =
        facts.native_debugger_available && host_matches_target_os;

    // LiveProcessAttach tracks whether peelf supports attaching to this target OS/ISA,
    // separated cleanly from whether the current host OS can attach natively.
    const bool live_attach_arch_ok =
        profile.endianness == Endianness::Little &&
        (profile.architecture == Architecture::X86 ||
         profile.architecture == Architecture::X86_64 ||
         profile.architecture == Architecture::ARM ||
         profile.architecture == Architecture::ARM64 ||
         (profile.os == OsKind::Linux && profile.architecture == Architecture::RISCV64));
    set_cap(Operation::LiveProcessAttach,
            (is_validated_live_os && live_attach_arch_ok)
                ? (isa_tier == IsaTier::Validated ? SupportState::SupportedValidated
                                                  : SupportState::SupportedExperimental)
                : SupportState::Unsupported,
            native_attach_provider_ok,
            profile.os == OsKind::Windows ? "Win32ProcessSession" : "LinuxProcfsSession",
            !is_validated_live_os
                ? "Live process attach requires an explicit Windows or Linux target OS"
                : (!live_attach_arch_ok
                       ? "Live process attach unvalidated for target architecture"
                       : (native_attach_provider_ok
                              ? "Read-only native live process inspection available"
                              : "Target OS/ISA attach is validated in peelf, but requires matching host OS provider")));

    // SyscallOrEtwTimeline is reported honestly as Unsupported until a kernel/ptrace/ETW trace source is enabled.
    set_cap(Operation::SyscallOrEtwTimeline,
            facts.syscall_or_etw_trace_available && is_validated_live_os
                ? SupportState::SupportedExperimental
                : SupportState::Unsupported,
            facts.syscall_or_etw_trace_available,
            "syscall_etw_source",
            "Syscall stop / ETW kernel trace timeline source is not enabled");

    const bool session_provider_ok =
        (profile.backend == BackendKind::CrashDumpMinidump ||
         profile.backend == BackendKind::CrashDumpElfCore)
            ? true
            : (profile.backend == BackendKind::RemoteGdbRsp
                   ? facts.remote_gdb_stub_available
                   : native_attach_provider_ok);

    if (!is_live_or_dump && profile.backend != BackendKind::RemoteGdbRsp) {
        const std::string static_reason =
            "Requires an attached live process, crash dump, or active debug session";
        set_cap(Operation::DiskVsLiveDiff, SupportState::Unsupported, false, "peelf_diff", static_reason);
        set_cap(Operation::StackUnwind, SupportState::Unsupported, false, "peelf_unwind", static_reason);
        set_cap(Operation::ThreadLocals, SupportState::Partial, true, "peelf_tls",
                profile.format != Format::Unknown
                    ? "Static PT_TLS / IMAGE_TLS_DIRECTORY template inspection only (attach for live per-thread values)"
                    : static_reason);
        set_cap(Operation::RuntimeStructures, SupportState::Partial, true, "peelf_runtime",
                profile.format != Format::Unknown
                    ? "Static header mitigation flags only (attach for live PEB/TEB/auxv/r_debug)"
                    : static_reason);
        set_cap(Operation::ProcessInternals, SupportState::Unsupported, false, "peelf_internals", static_reason);
        set_cap(Operation::ProcessSnapshotDiff, SupportState::Unsupported, false, "peelf_snapshot", static_reason);
        set_cap(Operation::SoftwareBreakpoints, SupportState::Unsupported, native_dbg_provider_ok, "peelf_debugger",
                "Requires an opt-in ActiveDebugger or RemoteGdbRsp session");
        set_cap(Operation::HardwareWatchpoints, SupportState::Unsupported, native_dbg_provider_ok, "peelf_debugger",
                "Requires an opt-in ActiveDebugger or RemoteGdbRsp session");
        set_cap(Operation::ExecutionTimeline, SupportState::Unsupported, false, "peelf_timeline", static_reason);
    } else {
        // DiskVsLiveDiff
        set_cap(Operation::DiskVsLiveDiff,
                (profile.format == Format::PE || profile.format == Format::ELF) && is_validated_live_os
                    ? code_tier
                    : SupportState::Unsupported,
                session_provider_ok,
                "peelf_diff",
                (profile.format == Format::PE || profile.format == Format::ELF)
                    ? "Relocation-normalized on-disk vs. live RAM hook & integrity comparison"
                    : "Disk-vs-live diff requires a mapped PE or ELF module with on-disk backing");

        // StackUnwind
        const bool unwind_arch_validated =
            profile.architecture == Architecture::X86 ||
            profile.architecture == Architecture::X86_64 ||
            profile.architecture == Architecture::ARM ||
            profile.architecture == Architecture::ARM64 ||
            profile.architecture == Architecture::RISCV64;
        set_cap(Operation::StackUnwind,
                unwind_arch_validated ? SupportState::SupportedValidated : SupportState::Partial,
                session_provider_ok,
                "peelf_unwind",
                unwind_arch_validated
                    ? "Frame-pointer + return-address stack walk validated for target ISA"
                    : "Heuristic return-address stack scan only on this ISA");

        // ThreadLocals & RuntimeStructures
        set_cap(Operation::ThreadLocals,
                is_validated_live_os ? code_tier : SupportState::Unsupported,
                session_provider_ok,
                "peelf_tls",
                is_validated_live_os
                    ? "Static + live per-thread TLS slot/TCB/TEB inspection"
                    : "Live TLS layout unvalidated for target OS");

        set_cap(Operation::RuntimeStructures,
                is_validated_live_os ? code_tier : SupportState::Unsupported,
                session_provider_ok,
                "peelf_runtime",
                is_validated_live_os
                    ? "Live PEB/TEB or ELF auxv/r_debug/link_map inspection"
                    : "Live OS runtime structures require Windows or Linux session");

        // ProcessInternals & ProcessSnapshotDiff
        if (profile.backend == BackendKind::RemoteGdbRsp) {
            set_cap(Operation::ProcessInternals,
                    SupportState::Partial,
                    facts.remote_gdb_stub_available,
                    "gdb_rsp",
                    "Remote GDB RSP stubs expose threads/registers/memory; OS handle/socket tables may be unavailable");
            set_cap(Operation::ProcessSnapshotDiff,
                    SupportState::Partial,
                    facts.remote_gdb_stub_available,
                    "peelf_snapshot",
                    "Snapshot diff covers RSP-exposed modules, regions, and threads");
        } else {
            set_cap(Operation::ProcessInternals,
                    is_validated_live_os ? SupportState::SupportedValidated : SupportState::Unsupported,
                    session_provider_ok,
                    "peelf_internals",
                    is_validated_live_os
                        ? "Open handles/FDs, network sockets, and privilege/mitigation posture"
                        : "Process internals require Windows Win32 or Linux procfs/coredump notes");
            set_cap(Operation::ProcessSnapshotDiff,
                    is_validated_live_os ? SupportState::SupportedValidated : SupportState::Unsupported,
                    session_provider_ok,
                    "peelf_snapshot",
                    is_validated_live_os
                        ? "Timestamped ProcessStateSnapshot capture & identity-aware SnapshotDiff"
                        : "Snapshot diff unvalidated for target OS");
        }

        // Debugger operations (`SoftwareBreakpoints`, `HardwareWatchpoints`, `ExecutionTimeline`)
        const bool is_debug_backend =
            profile.backend == BackendKind::ActiveDebugger ||
            profile.backend == BackendKind::RemoteGdbRsp;
        const bool sw_bp_arch_ok =
            profile.architecture == Architecture::X86 ||
            profile.architecture == Architecture::X86_64 ||
            profile.architecture == Architecture::ARM ||
            profile.architecture == Architecture::ARM64 ||
            profile.architecture == Architecture::RISCV32 ||
            profile.architecture == Architecture::RISCV64;
        const bool hw_wp_arch_ok =
            (profile.architecture == Architecture::X86 ||
             profile.architecture == Architecture::X86_64 ||
             profile.architecture == Architecture::ARM64) &&
            profile.endianness == Endianness::Little;
        const bool dbg_prov_ok = profile.backend == BackendKind::RemoteGdbRsp
                                     ? facts.remote_gdb_stub_available
                                     : native_dbg_provider_ok;

        set_cap(Operation::SoftwareBreakpoints,
                (is_debug_backend && sw_bp_arch_ok)
                    ? SupportState::SupportedValidated
                    : SupportState::Unsupported,
                dbg_prov_ok,
                "peelf_debugger",
                !is_debug_backend
                    ? "Session is read-only; attach via opt-in ActiveDebugger or RemoteGdbRsp for software breakpoints"
                    : (sw_bp_arch_ok
                           ? "Software trap injection & shadow-read masking supported"
                           : "Software trap opcode unvalidated for target ISA"));

        set_cap(Operation::HardwareWatchpoints,
                (is_debug_backend && hw_wp_arch_ok)
                    ? SupportState::SupportedValidated
                    : SupportState::Unsupported,
                dbg_prov_ok,
                "peelf_debugger",
                !is_debug_backend
                    ? "Session is read-only; attach via ActiveDebugger or RemoteGdbRsp for hardware watchpoints"
                    : (hw_wp_arch_ok
                           ? "Hardware debug-register watchpoints supported"
                           : "Hardware watchpoints only validated on x86/x86_64 DR0-DR3 and ARM64 DBGWVR"));

        set_cap(Operation::ExecutionTimeline,
                is_debug_backend
                    ? SupportState::SupportedValidated
                    : (profile.backend == BackendKind::LiveNativeReadOnly && is_validated_live_os
                           ? SupportState::Partial
                           : SupportState::Unsupported),
                is_debug_backend ? dbg_prov_ok : session_provider_ok,
                "peelf_timeline",
                is_debug_backend
                    ? "Full debugger stop-event + snapshot-delta execution timeline"
                    : (profile.backend == BackendKind::LiveNativeReadOnly && is_validated_live_os
                           ? "Snapshot-diff timeline with explicit SamplingGap markers (no debugger traps in read-only mode)"
                           : "Offline crash dumps represent a single post-mortem instant"));
    }

    return TargetCapabilityMatrix(profile, facts, std::move(entries));
}

} // namespace peelf
