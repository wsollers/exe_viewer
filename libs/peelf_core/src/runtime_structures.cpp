#include <peelf/runtime_structures.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace peelf {

namespace {

[[nodiscard]] std::string hex_u64(std::uint64_t val, unsigned min_digits = 1u) {
    std::array<char, 32> buf{};
    std::snprintf(buf.data(),
                  buf.size(),
                  "0x%0*llX",
                  static_cast<int>(min_digits),
                  static_cast<unsigned long long>(val));
    return std::string(buf.data());
}

[[nodiscard]] std::string hex_ptr(std::uint64_t val, TargetLayout layout) {
    return hex_u64(val, layout.is_64bit() ? 16u : 8u);
}

[[nodiscard]] std::string_view trim_ws(std::string_view s) noexcept {
    while (!s.empty() &&
           (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
        s.remove_prefix(1);
    }
    while (!s.empty() &&
           (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] std::string basename_of(std::string_view path_str) {
    const std::size_t pos = path_str.find_last_of("/\\");
    if (pos == std::string_view::npos) {
        return std::string(path_str);
    }
    return std::string(path_str.substr(pos + 1u));
}

[[nodiscard]] bool ends_with_icase(std::string_view str, std::string_view suffix) noexcept {
    if (str.size() < suffix.size()) {
        return false;
    }
    const std::size_t start = str.size() - suffix.size();
    for (std::size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(str[start + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i]))) {
            return false;
        }
    }
    return true;
}

struct BitFlagSpec {
    std::uint64_t mask;
    std::string_view name;
    std::string_view description;
};

void append_mask_flags(std::vector<HarvestedFlagItem>& out,
                       std::string_view category,
                       std::uint64_t raw_mask,
                       std::span<const BitFlagSpec> specs,
                       bool only_active = false) {
    for (const BitFlagSpec& spec : specs) {
        const bool is_set = (raw_mask & spec.mask) == spec.mask && spec.mask != 0u;
        if (only_active && !is_set) {
            continue;
        }
        out.push_back(HarvestedFlagItem{
            .category = std::string(category),
            .name = std::string(spec.name),
            .mask = spec.mask,
            .active = is_set,
            .value_text = is_set ? "Set" : "Clear",
            .description = std::string(spec.description),
        });
    }
}

[[nodiscard]] std::string_view pe_subsystem_name(std::uint16_t subsystem) noexcept {
    switch (subsystem) {
        case 0:  return "IMAGE_SUBSYSTEM_UNKNOWN";
        case 1:  return "IMAGE_SUBSYSTEM_NATIVE";
        case 2:  return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
        case 3:  return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
        case 5:  return "IMAGE_SUBSYSTEM_OS2_CUI";
        case 7:  return "IMAGE_SUBSYSTEM_POSIX_CUI";
        case 8:  return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
        case 9:  return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
        case 10: return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
        case 11: return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
        case 12: return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
        case 13: return "IMAGE_SUBSYSTEM_EFI_ROM";
        case 14: return "IMAGE_SUBSYSTEM_XBOX";
        case 16: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
        default: return "IMAGE_SUBSYSTEM_OTHER";
    }
}

[[nodiscard]] std::string_view elf_osabi_name(std::uint8_t os_abi) noexcept {
    switch (os_abi) {
        case 0:   return "SYSV (UNIX System V)";
        case 1:   return "HP-UX";
        case 2:   return "NetBSD";
        case 3:   return "GNU/Linux";
        case 6:   return "Solaris";
        case 7:   return "AIX";
        case 8:   return "IRIX";
        case 9:   return "FreeBSD";
        case 10:  return "Tru64";
        case 11:  return "Novell Modesto";
        case 12:  return "OpenBSD";
        case 64:  return "ARM EABI";
        case 97:  return "ARM";
        case 255: return "Standalone";
        default:  return "Vendor/Other OSABI";
    }
}

void harvest_pe_header_flags(const IBinaryImage& image, HeaderFlagsReport& report) {
    const PeHeader* pe = image.pe_header();
    if (pe == nullptr) {
        report.status = SubsystemStatus::unavailable("pe_header", "PE header is not available");
        return;
    }

    report.raw_masks.push_back(DecodedField{
        .name = "COFF Characteristics",
        .offset = std::nullopt,
        .raw_value = pe->characteristics,
        .formatted_value = hex_u64(pe->characteristics, 4u),
        .description = "IMAGE_FILE_HEADER.Characteristics",
    });

    const std::string subsys_str =
        std::string(pe_subsystem_name(pe->subsystem)) + " (" + hex_u64(pe->subsystem, 4u) + ")";
    report.raw_masks.push_back(DecodedField{
        .name = "Subsystem",
        .offset = std::nullopt,
        .raw_value = pe->subsystem,
        .formatted_value = subsys_str,
        .description = "IMAGE_OPTIONAL_HEADER.Subsystem",
    });
    report.flags.push_back(HarvestedFlagItem{
        .category = "PE Subsystem",
        .name = std::string(pe_subsystem_name(pe->subsystem)),
        .mask = pe->subsystem,
        .active = true,
        .value_text = hex_u64(pe->subsystem, 4u),
        .description = "Required Windows execution subsystem",
    });

    report.raw_masks.push_back(DecodedField{
        .name = "DLL Characteristics",
        .offset = std::nullopt,
        .raw_value = pe->dll_characteristics,
        .formatted_value = hex_u64(pe->dll_characteristics, 4u),
        .description = "IMAGE_OPTIONAL_HEADER.DllCharacteristics",
    });

    static constexpr std::array<BitFlagSpec, 10> kCoffSpecs = {{
        {0x0001u, "IMAGE_FILE_RELOCS_STRIPPED", "Base relocations stripped from file"},
        {0x0002u, "IMAGE_FILE_EXECUTABLE_IMAGE", "Valid executable image"},
        {0x0020u, "IMAGE_FILE_LARGE_ADDRESS_AWARE", "Application can handle >2 GB addresses"},
        {0x0100u, "IMAGE_FILE_32BIT_MACHINE", "32-bit word architecture"},
        {0x0200u, "IMAGE_FILE_DEBUG_STRIPPED", "Debugging information removed"},
        {0x0400u, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", "Copy to swap if on removable media"},
        {0x0800u, "IMAGE_FILE_NET_RUN_FROM_SWAP", "Copy to swap if running from network"},
        {0x1000u, "IMAGE_FILE_SYSTEM", "Kernel/system mode image"},
        {0x2000u, "IMAGE_FILE_DLL", "Dynamic-link library (DLL)"},
        {0x4000u, "IMAGE_FILE_UP_SYSTEM_ONLY", "Uniprocessor machine only"},
    }};
    append_mask_flags(report.flags, "COFF Characteristics", pe->characteristics, kCoffSpecs);

    static constexpr std::array<BitFlagSpec, 11> kDllCharSpecs = {{
        {0x0020u, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", "64-bit high-entropy ASLR"},
        {0x0040u, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "ASLR (relocatable at load time)"},
        {0x0080u, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "Code integrity check enforced"},
        {0x0100u, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "DEP / NX non-executable data compatible"},
        {0x0200u, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", "Isolation-aware, do not isolate"},
        {0x0400u, "IMAGE_DLLCHARACTERISTICS_NO_SEH", "Image does not use SEH"},
        {0x0800u, "IMAGE_DLLCHARACTERISTICS_NO_BIND", "Do not bind image"},
        {0x1000u, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", "Must execute inside an AppContainer"},
        {0x2000u, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", "WDM kernel driver"},
        {0x4000u, "IMAGE_DLLCHARACTERISTICS_GUARD_CF", "Control Flow Guard (CFG) enabled"},
        {0x8000u, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", "Terminal Server aware"},
    }};
    append_mask_flags(report.flags, "DLL Characteristics", pe->dll_characteristics, kDllCharSpecs);

    const PeLoadConfigDirectory* load_cfg = image.pe_load_config_directory();
    if (load_cfg != nullptr) {
        report.raw_masks.push_back(DecodedField{
            .name = "LoadConfig GuardFlags",
            .offset = load_cfg->file_offset,
            .raw_value = load_cfg->guard_flags,
            .formatted_value = hex_u64(load_cfg->guard_flags, 8u),
            .description = "IMAGE_LOAD_CONFIG_DIRECTORY.GuardFlags",
        });

        static constexpr std::array<BitFlagSpec, 12> kGuardSpecs = {{
            {0x00000100u, "IMAGE_GUARD_CF_INSTRUMENTED", "Module performs CFG checks"},
            {0x00000200u, "IMAGE_GUARD_CFW_INSTRUMENTED", "Module performs CFG + write checks"},
            {0x00000400u, "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", "Valid CFG target table present"},
            {0x00000800u, "IMAGE_GUARD_SECURITY_COOKIE_UNUSED", "Security cookie unused"},
            {0x00001000u, "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", "Protect delay-load IAT"},
            {0x00002000u,
             "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
             "Delay-load IAT placed in dedicated section"},
            {0x00004000u,
             "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT",
             "CFG export suppression info present"},
            {0x00008000u,
             "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION",
             "CFG export suppression enabled"},
            {0x00010000u, "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", "CFG longjmp target table present"},
            {0x00020000u, "IMAGE_GUARD_RF_INSTRUMENTED", "Return Flow Guard instrumented"},
            {0x00400000u,
             "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT",
             "EH continuation target table present"},
            {0x00800000u,
             "IMAGE_GUARD_CET_SHADOW_STACK_PRESENT",
             "CET Hardware Shadow Stack / XFG flag"},
        }};
        append_mask_flags(report.flags, "LoadConfig GuardFlags", load_cfg->guard_flags, kGuardSpecs);
    }

    const PeClrHeader* clr = image.pe_clr_header();
    if (clr != nullptr) {
        report.raw_masks.push_back(DecodedField{
            .name = "CLR Runtime Flags",
            .offset = clr->file_offset,
            .raw_value = clr->flags,
            .formatted_value = hex_u64(clr->flags, 8u),
            .description = "IMAGE_COR20_HEADER.Flags",
        });

        static constexpr std::array<BitFlagSpec, 5> kClrSpecs = {{
            {0x00000001u, "COMIMAGE_FLAGS_ILONLY", "Pure MSIL managed assembly"},
            {0x00000002u, "COMIMAGE_FLAGS_32BITREQUIRED", "Requires 32-bit process"},
            {0x00000008u, "COMIMAGE_FLAGS_STRONGNAMESIGNED", "Strong-name signed assembly"},
            {0x00000010u, "COMIMAGE_FLAGS_NATIVE_ENTRYPOINT", "Native unmanaged entry point"},
            {0x00020000u, "COMIMAGE_FLAGS_32BITPREFERRED", "AnyCPU 32-bit preferred"},
        }};
        append_mask_flags(report.flags, "CLR Header", clr->flags, kClrSpecs);
    }

    static constexpr std::array<BitFlagSpec, 9> kPeSectionSpecs = {{
        {0x00000020u, "IMAGE_SCN_CNT_CODE", "Section contains executable code"},
        {0x00000040u, "IMAGE_SCN_CNT_INITIALIZED_DATA", "Section contains initialized data"},
        {0x00000080u, "IMAGE_SCN_CNT_UNINITIALIZED_DATA", "Section contains uninitialized BSS data"},
        {0x02000000u, "IMAGE_SCN_MEM_DISCARDABLE", "Section can be discarded as needed"},
        {0x04000000u, "IMAGE_SCN_MEM_NOT_CACHED", "Section cannot be cached"},
        {0x10000000u, "IMAGE_SCN_MEM_SHARED", "Section can be shared in memory"},
        {0x20000000u, "IMAGE_SCN_MEM_EXECUTE", "Section can be executed as code"},
        {0x40000000u, "IMAGE_SCN_MEM_READ", "Section can be read"},
        {0x80000000u, "IMAGE_SCN_MEM_WRITE", "Section can be written to"},
    }};

    std::vector<std::string> rwx_sections;
    for (const Section& sec : image.sections()) {
        const std::string label = sec.name.empty() ? "<unnamed>" : sec.name;
        report.raw_masks.push_back(DecodedField{
            .name = "Section " + label + " Characteristics",
            .offset = sec.file_offset,
            .raw_value = sec.raw_flags,
            .formatted_value = hex_u64(sec.raw_flags, 8u),
            .description = "IMAGE_SECTION_HEADER.Characteristics",
        });
        append_mask_flags(
            report.flags, "Section: " + label, sec.raw_flags, kPeSectionSpecs, /*only_active=*/true);

        const bool is_rwx =
            (sec.writable && sec.executable) || ((sec.raw_flags & 0xA0000000ull) == 0xA0000000ull);
        if (is_rwx) {
            rwx_sections.push_back(label);
        }
    }

    const bool dynamic_base = (pe->dll_characteristics & 0x0040u) != 0u;
    const bool relocs_stripped = (pe->characteristics & 0x0001u) != 0u;
    const bool aslr_enabled = dynamic_base && !relocs_stripped;
    report.security_summary.push_back(DecodedField{
        .name = "ASLR",
        .offset = std::nullopt,
        .raw_value = aslr_enabled ? 1u : 0u,
        .formatted_value = aslr_enabled
                               ? "Enabled"
                               : (dynamic_base ? "Disabled (RELOCS_STRIPPED)" : "Disabled"),
        .description = "Address Space Layout Randomization (DYNAMIC_BASE)",
    });

    const bool high_entropy =
        image.is_64bit() && aslr_enabled && ((pe->dll_characteristics & 0x0020u) != 0u);
    report.security_summary.push_back(DecodedField{
        .name = "High-Entropy ASLR",
        .offset = std::nullopt,
        .raw_value = high_entropy ? 1u : 0u,
        .formatted_value = image.is_64bit() ? (high_entropy ? "Enabled" : "Disabled")
                                            : "N/A (32-bit)",
        .description = "64-bit High-Entropy Virtual Address Space (HIGH_ENTROPY_VA)",
    });

    const bool nx_enabled = (pe->dll_characteristics & 0x0100u) != 0u;
    report.security_summary.push_back(DecodedField{
        .name = "DEP/NX",
        .offset = std::nullopt,
        .raw_value = nx_enabled ? 1u : 0u,
        .formatted_value = nx_enabled ? "Enabled" : "Disabled",
        .description = "Data Execution Prevention (NX_COMPAT)",
    });

    const bool cfg_dll = (pe->dll_characteristics & 0x4000u) != 0u;
    const bool cfg_inst = (load_cfg != nullptr) && ((load_cfg->guard_flags & 0x00000100u) != 0u);
    report.security_summary.push_back(DecodedField{
        .name = "Control Flow Guard (CFG)",
        .offset = std::nullopt,
        .raw_value = cfg_dll ? 1u : 0u,
        .formatted_value =
            cfg_dll ? (cfg_inst ? "Enabled (Instrumented)" : "Enabled") : "Disabled",
        .description = "Indirect call target validation (GUARD_CF)",
    });

    const bool no_seh = (pe->dll_characteristics & 0x0400u) != 0u;
    std::string seh_status;
    std::uint64_t seh_raw = 0u;
    if (no_seh) {
        seh_status = "NO_SEH (Disabled)";
        seh_raw = 1u;
    } else if (image.is_64bit() || image.architecture() == Architecture::ARM ||
               image.architecture() == Architecture::ARM64) {
        seh_status = "Table-Based SEH (.pdata)";
        seh_raw = 1u;
    } else if (load_cfg != nullptr && load_cfg->se_handler_table != 0u) {
        seh_status = "SafeSEH (" + std::to_string(load_cfg->se_handler_count) + " handlers)";
        seh_raw = 1u;
    } else {
        seh_status = "Unprotected (No SafeSEH)";
        seh_raw = 0u;
    }
    report.security_summary.push_back(DecodedField{
        .name = "SafeSEH / SEH",
        .offset = std::nullopt,
        .raw_value = seh_raw,
        .formatted_value = std::move(seh_status),
        .description = "Structured Exception Handling protection",
    });

    const auto& certs = image.pe_certificates();
    report.security_summary.push_back(DecodedField{
        .name = "Authenticode Signed",
        .offset = std::nullopt,
        .raw_value = static_cast<std::uint64_t>(certs.size()),
        .formatted_value =
            certs.empty() ? "Not Signed" : ("Present (" + std::to_string(certs.size()) + " cert)"),
        .description = "WIN_CERTIFICATE Authenticode signature table",
    });

    std::string rwx_text = "None";
    if (!rwx_sections.empty()) {
        rwx_text = "Warning (" + std::to_string(rwx_sections.size()) + "): ";
        for (std::size_t i = 0; i < rwx_sections.size(); ++i) {
            if (i > 0u) {
                rwx_text += ", ";
            }
            rwx_text += rwx_sections[i];
        }
    }
    report.security_summary.push_back(DecodedField{
        .name = "RWX Sections",
        .offset = std::nullopt,
        .raw_value = static_cast<std::uint64_t>(rwx_sections.size()),
        .formatted_value = std::move(rwx_text),
        .description = "Writable + executable sections",
    });

    report.status = SubsystemStatus::available("pe_header", "PE header flags harvested");
}

void decode_elf_arch_eflags(Architecture arch,
                            std::uint32_t eflags,
                            std::vector<HarvestedFlagItem>& out) {
    switch (arch) {
        case Architecture::ARM: {
            const std::uint32_t eabi_ver = (eflags >> 24u) & 0xFFu;
            out.push_back(HarvestedFlagItem{
                .category = "ELF ARM e_flags",
                .name = "EF_ARM_EABIMASK",
                .mask = 0xFF000000u,
                .active = eabi_ver != 0u,
                .value_text = "EABI v" + std::to_string(eabi_ver),
                .description = "ARM Embedded ABI version",
            });
            static constexpr std::array<BitFlagSpec, 2> kArmSpecs = {{
                {0x00000400u, "EF_ARM_ABI_FLOAT_HARD", "Hardware VFP floating-point ABI"},
                {0x00000200u, "EF_ARM_ABI_FLOAT_SOFT", "Software floating-point ABI"},
            }};
            append_mask_flags(out, "ELF ARM e_flags", eflags, kArmSpecs);
            break;
        }

        case Architecture::RISCV32:
        case Architecture::RISCV64: {
            static constexpr std::array<BitFlagSpec, 3> kRiscvBits = {{
                {0x0001u, "EF_RISCV_RVC", "Compressed 16-bit instructions (C extension)"},
                {0x0008u, "EF_RISCV_RVE", "Embedded 16-register RVE ABI"},
                {0x0010u, "EF_RISCV_TSO", "Total Store Ordering memory model"},
            }};
            append_mask_flags(out, "ELF RISC-V e_flags", eflags, kRiscvBits);

            const std::uint32_t fabi = eflags & 0x0006u;
            std::string_view fabi_name = "EF_RISCV_FLOAT_ABI_SOFT";
            if (fabi == 0x0002u) {
                fabi_name = "EF_RISCV_FLOAT_ABI_SINGLE";
            } else if (fabi == 0x0004u) {
                fabi_name = "EF_RISCV_FLOAT_ABI_DOUBLE";
            } else if (fabi == 0x0006u) {
                fabi_name = "EF_RISCV_FLOAT_ABI_QUAD";
            }
            out.push_back(HarvestedFlagItem{
                .category = "ELF RISC-V e_flags",
                .name = std::string(fabi_name),
                .mask = 0x0006u,
                .active = true,
                .value_text = hex_u64(fabi, 2u),
                .description = "RISC-V floating-point calling convention",
            });
            break;
        }

        case Architecture::MIPS32:
        case Architecture::MIPS64: {
            static constexpr std::array<BitFlagSpec, 4> kMipsBits = {{
                {0x00000001u, "EF_MIPS_NOREORDER", "Assembler noreorder directive used"},
                {0x00000002u, "EF_MIPS_PIC", "Position-independent code (PIC)"},
                {0x00000004u, "EF_MIPS_CPIC", "Calling PIC convention"},
                {0x00001000u, "EF_MIPS_ABI_O32", "MIPS O32 ABI"},
            }};
            append_mask_flags(out, "ELF MIPS e_flags", eflags, kMipsBits);

            const std::uint32_t arch_nibble = eflags & 0xF0000000u;
            std::string_view arch_name = "EF_MIPS_ARCH_1";
            switch (arch_nibble) {
                case 0x00000000u: arch_name = "EF_MIPS_ARCH_1"; break;
                case 0x10000000u: arch_name = "EF_MIPS_ARCH_2"; break;
                case 0x20000000u: arch_name = "EF_MIPS_ARCH_3"; break;
                case 0x30000000u: arch_name = "EF_MIPS_ARCH_4"; break;
                case 0x40000000u: arch_name = "EF_MIPS_ARCH_5"; break;
                case 0x50000000u: arch_name = "EF_MIPS_ARCH_32"; break;
                case 0x60000000u: arch_name = "EF_MIPS_ARCH_64"; break;
                case 0x70000000u: arch_name = "EF_MIPS_ARCH_32R2"; break;
                case 0x80000000u: arch_name = "EF_MIPS_ARCH_64R2"; break;
                case 0x90000000u: arch_name = "EF_MIPS_ARCH_32R6"; break;
                case 0xA0000000u: arch_name = "EF_MIPS_ARCH_64R6"; break;
                default:          arch_name = "EF_MIPS_ARCH_OTHER"; break;
            }
            out.push_back(HarvestedFlagItem{
                .category = "ELF MIPS e_flags",
                .name = std::string(arch_name),
                .mask = 0xF0000000u,
                .active = true,
                .value_text = hex_u64(arch_nibble, 8u),
                .description = "MIPS ISA revision level",
            });
            break;
        }

        case Architecture::PowerPC64: {
            const std::uint32_t abi = eflags & 0x03u;
            std::string abi_text = "Unspecified";
            if (abi == 1u) {
                abi_text = "ABIv1 (Function Descriptors)";
            } else if (abi == 2u) {
                abi_text = "ABIv2 (ELFv2)";
            }
            out.push_back(HarvestedFlagItem{
                .category = "ELF PowerPC64 e_flags",
                .name = "EF_PPC64_ABI",
                .mask = 0x03u,
                .active = abi != 0u,
                .value_text = std::move(abi_text),
                .description = "64-bit PowerPC ELF ABI version",
            });
            break;
        }

        case Architecture::Unknown:
        case Architecture::X86:
        case Architecture::X86_64:
        case Architecture::ARM64:
        case Architecture::PowerPC:
            break;
    }
}

struct GnuPropertyFeatures {
    bool x86_ibt{false};
    bool x86_shstk{false};
    bool aarch64_bti{false};
    bool aarch64_pac{false};
};

[[nodiscard]] GnuPropertyFeatures parse_gnu_property_notes(std::span<const ElfNote> notes,
                                                           TargetLayout layout) {
    GnuPropertyFeatures feat{};
    const std::size_t align = layout.pointer_size();

    for (const ElfNote& note : notes) {
        // NT_GNU_PROPERTY_TYPE_0 == 5
        if (note.type != 5u || !note.name.starts_with("GNU")) {
            continue;
        }
        const EndianReader reader(note.descriptor, layout);
        std::size_t offset = 0u;
        while (reader.can_read(offset, 8u)) {
            const auto pr_type = reader.read_u32(offset);
            const auto pr_datasz = reader.read_u32(offset + 4u);
            if (!pr_type || !pr_datasz) {
                break;
            }
            const auto data_sz = static_cast<std::size_t>(*pr_datasz);
            if (!reader.can_read(offset + 8u, data_sz)) {
                break;
            }
            if (data_sz >= 4u) {
                const auto bits = reader.read_u32(offset + 8u);
                if (bits) {
                    // GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
                    if (*pr_type == 0xC0000002u) {
                        feat.x86_ibt = feat.x86_ibt || ((*bits & 0x01u) != 0u);
                        feat.x86_shstk = feat.x86_shstk || ((*bits & 0x02u) != 0u);
                    }
                    // GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000
                    if (*pr_type == 0xC0000000u) {
                        feat.aarch64_bti = feat.aarch64_bti || ((*bits & 0x01u) != 0u);
                        feat.aarch64_pac = feat.aarch64_pac || ((*bits & 0x02u) != 0u);
                    }
                }
            }

            const std::size_t unaligned_step = 8u + data_sz;
            const std::size_t rem = unaligned_step % align;
            const std::size_t step = (rem == 0u) ? unaligned_step : (unaligned_step + (align - rem));
            if (step == 0u || offset > note.descriptor.size() - step) {
                offset = note.descriptor.size();
                break;
            }
            offset += step;
        }
    }
    return feat;
}

void harvest_elf_header_flags(const IBinaryImage& image, HeaderFlagsReport& report) {
    const ElfHeader* eh = image.elf_header();
    if (eh == nullptr) {
        report.status = SubsystemStatus::unavailable("elf_header", "ELF header is not available");
        return;
    }

    const auto& phdrs = image.elf_program_headers();
    const auto& dyns = image.elf_dynamic_entries();

    bool has_pt_interp = !image.elf_interpreter().empty();
    bool has_gnu_stack = false;
    std::uint32_t gnu_stack_flags = 0u;
    bool has_gnu_relro = false;
    std::size_t rwx_segments = 0u;

    for (const ElfProgramHeader& ph : phdrs) {
        if (ph.type == 3u) {  // PT_INTERP
            has_pt_interp = true;
        } else if (ph.type == 0x6474E551u) {  // PT_GNU_STACK
            has_gnu_stack = true;
            gnu_stack_flags = ph.flags;
        } else if (ph.type == 0x6474E552u) {  // PT_GNU_RELRO
            has_gnu_relro = true;
        } else if (ph.type == 1u) {  // PT_LOAD
            // PF_X = 0x1, PF_W = 0x2
            if ((ph.flags & 0x03u) == 0x03u) {
                ++rwx_segments;
            }
        }
    }

    if (phdrs.empty()) {
        for (const Segment& seg : image.segments()) {
            if (seg.type == 1u && seg.writable && seg.executable) {
                ++rwx_segments;
            }
        }
    }

    bool has_dt_bind_now = false;
    bool has_dt_textrel = false;
    std::optional<std::uint64_t> dt_flags;
    std::optional<std::uint64_t> dt_flags_1;

    for (const ElfDynamicEntry& dyn : dyns) {
        if (dyn.tag == 24u) {  // DT_BIND_NOW
            has_dt_bind_now = true;
        } else if (dyn.tag == 22u) {  // DT_TEXTREL
            has_dt_textrel = true;
        } else if (dyn.tag == 30u) {  // DT_FLAGS
            dt_flags = dyn.value;
        } else if (dyn.tag == 0x6FFFFFFBull) {  // DT_FLAGS_1
            dt_flags_1 = dyn.value;
        }
    }

    const bool df_pie = dt_flags_1.has_value() && ((*dt_flags_1 & 0x08000000ull) != 0u);
    const bool bind_now =
        has_dt_bind_now ||
        (dt_flags.has_value() && ((*dt_flags & 0x08ull) != 0u)) ||
        (dt_flags_1.has_value() && ((*dt_flags_1 & 0x01ull) != 0u));
    const bool textrel =
        has_dt_textrel || (dt_flags.has_value() && ((*dt_flags & 0x04ull) != 0u));

    const std::string osabi_str =
        std::string(elf_osabi_name(eh->os_abi)) + " (v" + std::to_string(eh->abi_version) + ")";
    report.raw_masks.push_back(DecodedField{
        .name = "ELF OS/ABI",
        .offset = 7u,
        .raw_value = eh->os_abi,
        .formatted_value = osabi_str,
        .description = "EI_OSABI / EI_ABIVERSION",
    });
    report.flags.push_back(HarvestedFlagItem{
        .category = "ELF Identity",
        .name = "EI_OSABI",
        .mask = eh->os_abi,
        .active = true,
        .value_text = std::string(elf_osabi_name(eh->os_abi)),
        .description = "Target operating system / ABI extension",
    });

    std::string etype_str = "ET_UNKNOWN";
    if (eh->type == 1u) {
        etype_str = "ET_REL (Relocatable Object)";
    } else if (eh->type == 2u) {
        etype_str = "ET_EXEC (Position-Dependent Executable)";
    } else if (eh->type == 3u) {
        etype_str = (df_pie || has_pt_interp) ? "ET_DYN (PIE Executable)"
                                              : "ET_DYN (Shared Library)";
    } else if (eh->type == 4u) {
        etype_str = "ET_CORE (Core Dump)";
    }

    report.raw_masks.push_back(DecodedField{
        .name = "ELF Object Type",
        .offset = 16u,
        .raw_value = eh->type,
        .formatted_value = etype_str,
        .description = "Elf_Ehdr.e_type",
    });
    report.flags.push_back(HarvestedFlagItem{
        .category = "ELF Identity",
        .name = "e_type",
        .mask = eh->type,
        .active = true,
        .value_text = etype_str,
        .description = "ELF object file classification",
    });

    report.raw_masks.push_back(DecodedField{
        .name = "ELF Processor Flags (e_flags)",
        .offset = std::nullopt,
        .raw_value = eh->flags,
        .formatted_value = hex_u64(eh->flags, 8u),
        .description = "Architecture-specific e_flags",
    });
    decode_elf_arch_eflags(image.architecture(), eh->flags, report.flags);

    if (dt_flags.has_value()) {
        report.raw_masks.push_back(DecodedField{
            .name = "DT_FLAGS",
            .offset = std::nullopt,
            .raw_value = *dt_flags,
            .formatted_value = hex_u64(*dt_flags, 8u),
            .description = "Dynamic section DT_FLAGS",
        });
        static constexpr std::array<BitFlagSpec, 5> kDtFlagsSpecs = {{
            {0x01u, "DF_ORIGIN", "$ORIGIN substitution enabled"},
            {0x02u, "DF_SYMBOLIC", "Symbolic symbol resolution"},
            {0x04u, "DF_TEXTREL", "Relocations modify read-only text"},
            {0x08u, "DF_BIND_NOW", "Eager PLT/GOT binding at startup"},
            {0x10u, "DF_STATIC_TLS", "Uses static Thread-Local Storage model"},
        }};
        append_mask_flags(report.flags, "ELF DT_FLAGS", *dt_flags, kDtFlagsSpecs);
    }

    if (dt_flags_1.has_value()) {
        report.raw_masks.push_back(DecodedField{
            .name = "DT_FLAGS_1",
            .offset = std::nullopt,
            .raw_value = *dt_flags_1,
            .formatted_value = hex_u64(*dt_flags_1, 8u),
            .description = "Dynamic section DT_FLAGS_1",
        });
        static constexpr std::array<BitFlagSpec, 4> kDtFlags1Specs = {{
            {0x00000001u, "DF_1_NOW", "Immediate symbol binding at load time"},
            {0x00000008u, "DF_1_NODELETE", "Object cannot be dlclose()-unloaded"},
            {0x00000040u, "DF_1_NOOPEN", "Object cannot be dlopen()-loaded"},
            {0x08000000u, "DF_1_PIE", "Position-Independent Executable"},
        }};
        append_mask_flags(report.flags, "ELF DT_FLAGS_1", *dt_flags_1, kDtFlags1Specs);
    }

    if (has_gnu_stack) {
        const bool nx_ok = (gnu_stack_flags & 0x01u) == 0u;
        report.flags.push_back(HarvestedFlagItem{
            .category = "ELF Program Headers",
            .name = "PT_GNU_STACK",
            .mask = gnu_stack_flags,
            .active = nx_ok,
            .value_text = nx_ok ? "NX (RW-)" : "Executable (RWE)",
            .description = "Stack segment execution permission",
        });
    }

    if (has_gnu_relro) {
        report.flags.push_back(HarvestedFlagItem{
            .category = "ELF Program Headers",
            .name = "PT_GNU_RELRO",
            .mask = 0x6474E552u,
            .active = true,
            .value_text = bind_now ? "Full RELRO" : "Partial RELRO",
            .description = "Read-only relocation segment after dynamic linking",
        });
    }

    const GnuPropertyFeatures prop =
        parse_gnu_property_notes(image.elf_notes(), report.layout);
    if (prop.x86_ibt) {
        report.flags.push_back(HarvestedFlagItem{
            .category = "GNU Property Notes",
            .name = "GNU_PROPERTY_X86_FEATURE_1_IBT",
            .mask = 0x01u,
            .active = true,
            .value_text = "Enabled",
            .description = "Intel CET Indirect Branch Tracking",
        });
    }
    if (prop.x86_shstk) {
        report.flags.push_back(HarvestedFlagItem{
            .category = "GNU Property Notes",
            .name = "GNU_PROPERTY_X86_FEATURE_1_SHSTK",
            .mask = 0x02u,
            .active = true,
            .value_text = "Enabled",
            .description = "Intel CET Hardware Shadow Stack",
        });
    }
    if (prop.aarch64_bti) {
        report.flags.push_back(HarvestedFlagItem{
            .category = "GNU Property Notes",
            .name = "GNU_PROPERTY_AARCH64_FEATURE_1_BTI",
            .mask = 0x01u,
            .active = true,
            .value_text = "Enabled",
            .description = "ARM64 Branch Target Identification",
        });
    }
    if (prop.aarch64_pac) {
        report.flags.push_back(HarvestedFlagItem{
            .category = "GNU Property Notes",
            .name = "GNU_PROPERTY_AARCH64_FEATURE_1_PAC",
            .mask = 0x02u,
            .active = true,
            .value_text = "Enabled",
            .description = "ARM64 Pointer Authentication",
        });
    }

    static constexpr std::array<BitFlagSpec, 7> kShfSpecs = {{
        {0x001u, "SHF_WRITE", "Writable during execution"},
        {0x002u, "SHF_ALLOC", "Occupies memory during execution"},
        {0x004u, "SHF_EXECINSTR", "Contains executable machine instructions"},
        {0x010u, "SHF_MERGE", "May be merged to eliminate duplication"},
        {0x020u, "SHF_STRINGS", "Contains NUL-terminated strings"},
        {0x400u, "SHF_TLS", "Holds Thread-Local Storage"},
        {0x800u, "SHF_COMPRESSED", "Compressed section data"},
    }};

    const auto& shdrs = image.elf_section_headers();
    if (!shdrs.empty()) {
        for (const ElfSectionHeader& sh : shdrs) {
            if (sh.flags == 0u) {
                continue;
            }
            const std::string label = sh.name.empty() ? "<unnamed>" : sh.name;
            append_mask_flags(
                report.flags, "Section: " + label, sh.flags, kShfSpecs, /*only_active=*/true);
        }
    } else {
        for (const Section& sec : image.sections()) {
            if (sec.raw_flags == 0u) {
                continue;
            }
            const std::string label = sec.name.empty() ? "<unnamed>" : sec.name;
            append_mask_flags(
                report.flags, "Section: " + label, sec.raw_flags, kShfSpecs, /*only_active=*/true);
        }
    }

    const bool is_pie = (eh->type == 3u) && (df_pie || has_pt_interp);
    std::string pie_text = "Disabled";
    std::uint64_t pie_raw = 0u;
    if (is_pie) {
        pie_text = "Enabled (PIE)";
        pie_raw = 1u;
    } else if (eh->type == 3u) {
        pie_text = "Shared Library (DSO)";
        pie_raw = 1u;
    } else if (eh->type == 1u) {
        pie_text = "Relocatable (ET_REL)";
    } else if (eh->type == 2u) {
        pie_text = "Disabled (ET_EXEC)";
    }
    report.security_summary.push_back(DecodedField{
        .name = "PIE / ASLR",
        .offset = std::nullopt,
        .raw_value = pie_raw,
        .formatted_value = std::move(pie_text),
        .description = "Position-Independent Executable / Shared Object",
    });

    const bool nx_stack = has_gnu_stack && ((gnu_stack_flags & 0x01u) == 0u);
    report.security_summary.push_back(DecodedField{
        .name = "NX Stack",
        .offset = std::nullopt,
        .raw_value = nx_stack ? 1u : 0u,
        .formatted_value = has_gnu_stack ? (nx_stack ? "Enabled" : "Disabled (Executable Stack)")
                                         : "Missing PT_GNU_STACK",
        .description = "Non-executable stack via PT_GNU_STACK",
    });

    std::string relro_text = "No RELRO";
    std::uint64_t relro_raw = 0u;
    if (has_gnu_relro && bind_now) {
        relro_text = "Full RELRO";
        relro_raw = 2u;
    } else if (has_gnu_relro) {
        relro_text = "Partial RELRO";
        relro_raw = 1u;
    }
    report.security_summary.push_back(DecodedField{
        .name = "RELRO",
        .offset = std::nullopt,
        .raw_value = relro_raw,
        .formatted_value = std::move(relro_text),
        .description = "GOT / relocation read-only hardening",
    });

    report.security_summary.push_back(DecodedField{
        .name = "TEXTREL",
        .offset = std::nullopt,
        .raw_value = textrel ? 1u : 0u,
        .formatted_value = textrel ? "Present (Writable Text Relocations)" : "None",
        .description = "Text segment runtime relocation status",
    });

    std::vector<std::string> cfi_parts;
    if (prop.x86_ibt) {
        cfi_parts.emplace_back("IBT");
    }
    if (prop.x86_shstk) {
        cfi_parts.emplace_back("SHSTK");
    }
    if (prop.aarch64_bti) {
        cfi_parts.emplace_back("BTI");
    }
    if (prop.aarch64_pac) {
        cfi_parts.emplace_back("PAC");
    }
    std::string cfi_text = "Not Advertised";
    if (!cfi_parts.empty()) {
        cfi_text.clear();
        for (std::size_t i = 0; i < cfi_parts.size(); ++i) {
            if (i > 0u) {
                cfi_text += " + ";
            }
            cfi_text += cfi_parts[i];
        }
    }
    report.security_summary.push_back(DecodedField{
        .name = "CET / BTI / PAC",
        .offset = std::nullopt,
        .raw_value = static_cast<std::uint64_t>(cfi_parts.size()),
        .formatted_value = std::move(cfi_text),
        .description = "Hardware control-flow integrity properties",
    });

    report.security_summary.push_back(DecodedField{
        .name = "RWX Segments",
        .offset = std::nullopt,
        .raw_value = static_cast<std::uint64_t>(rwx_segments),
        .formatted_value = (rwx_segments == 0u)
                               ? "None"
                               : ("Warning (" + std::to_string(rwx_segments) + " PT_LOAD)"),
        .description = "Writable + executable PT_LOAD segments",
    });

    report.status = SubsystemStatus::available("elf_header", "ELF header flags harvested");
}

[[nodiscard]] std::size_t clamp_to_region_end(std::span<const MemoryRegion> regions,
                                              std::uint64_t address,
                                              std::size_t requested) noexcept {
    for (const MemoryRegion& reg : regions) {
        if (reg.contains(address)) {
            const std::uint64_t avail = reg.end_address - address;
            return static_cast<std::size_t>(
                std::min<std::uint64_t>(static_cast<std::uint64_t>(requested), avail));
        }
    }
    return requested;
}

[[nodiscard]] std::vector<std::uint8_t> read_struct_forgiving(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    std::uint64_t address,
    std::initializer_list<std::size_t> candidate_sizes) {
    if (address == 0u) {
        return {};
    }
    for (const std::size_t req : candidate_sizes) {
        if (req == 0u) {
            continue;
        }
        const std::size_t capped = clamp_to_region_end(regions, address, req);
        if (capped == 0u) {
            continue;
        }
        std::vector<std::uint8_t> buf(capped);
        auto res = session.read_memory(address, buf);
        if (res && *res > 0u) {
            buf.resize(std::min(*res, buf.size()));
            return buf;
        }
    }
    return {};
}

[[nodiscard]] std::optional<std::string> read_remote_c_string(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    TargetLayout layout,
    std::uint64_t address,
    std::size_t max_len = 512u) {
    if (address == 0u || max_len == 0u) {
        return std::nullopt;
    }

    const std::size_t first_try = clamp_to_region_end(regions, address, max_len);
    const std::array<std::size_t, 5> tries = {
        first_try,
        std::min<std::size_t>(max_len, 128u),
        std::min<std::size_t>(max_len, 64u),
        std::min<std::size_t>(max_len, 16u),
        1u,
    };

    for (std::size_t attempt_sz : tries) {
        if (attempt_sz == 0u) {
            continue;
        }
        if (attempt_sz == 1u) {
            std::string out;
            std::array<std::uint8_t, 1> byte_buf{};
            for (std::size_t i = 0; i < max_len; ++i) {
                auto r = session.read_memory(address + static_cast<std::uint64_t>(i), byte_buf);
                if (!r || *r == 0u) {
                    return i > 0u ? std::optional<std::string>(std::move(out)) : std::nullopt;
                }
                if (byte_buf[0] == 0u) {
                    return out;
                }
                out.push_back(static_cast<char>(byte_buf[0]));
            }
            return out;
        }

        std::vector<std::uint8_t> buf(attempt_sz);
        auto res = session.read_memory(address, buf);
        if (res && *res > 0u) {
            const std::size_t got = std::min(*res, buf.size());
            const EndianReader reader(std::span<const std::uint8_t>(buf.data(), got), layout);
            auto str = reader.read_c_string(0u, got);
            if (str) {
                return *str;
            }
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> read_remote_unicode_string(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    TargetLayout layout,
    const EndianReader& struct_reader,
    std::size_t us_offset,
    std::uint64_t denorm_base = 0u) {
    const std::size_t ptr_sz = layout.pointer_size();
    const std::size_t buf_field_off = layout.is_64bit() ? (us_offset + 8u) : (us_offset + 4u);
    if (!struct_reader.can_read(us_offset, 4u) || !struct_reader.can_read(buf_field_off, ptr_sz)) {
        return std::nullopt;
    }

    const auto byte_len_res = struct_reader.read_u16(us_offset);
    const auto buf_ptr_res = struct_reader.read_pointer(buf_field_off);
    if (!byte_len_res || !buf_ptr_res) {
        return std::nullopt;
    }

    const std::uint16_t byte_len = *byte_len_res;
    std::uint64_t buf_va = *buf_ptr_res;
    if (byte_len == 0u || buf_va == 0u) {
        return std::string{};
    }
    if (denorm_base != 0u && buf_va < 0x100000ull) {
        buf_va += denorm_base;
    }

    const std::size_t capped_bytes =
        clamp_to_region_end(regions, buf_va, std::min<std::size_t>(byte_len, 4096u));
    if (capped_bytes < 2u) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> raw(capped_bytes);
    auto rd = session.read_memory(buf_va, raw);
    if (!rd || *rd < 2u) {
        return std::nullopt;
    }
    const std::size_t valid = std::min(*rd, raw.size());
    const EndianReader str_reader(std::span<const std::uint8_t>(raw.data(), valid), layout);
    auto decoded = str_reader.read_utf16_string(0u, valid / 2u);
    if (!decoded) {
        return std::nullopt;
    }
    return *decoded;
}

void populate_fallback_modules(std::span<const ModuleInfo> modules,
                               std::vector<RuntimeModuleEntry>& out) {
    out.clear();
    out.reserve(modules.size());
    for (const ModuleInfo& mod : modules) {
        out.push_back(RuntimeModuleEntry{
            .name = mod.name,
            .full_path = mod.path.string(),
            .base_address = mod.base_address,
            .size_or_dynamic_va = mod.size,
            .entry_point = mod.entry_point,
        });
    }
}

void inspect_pe_process_environment(IProcessSession& session,
                                    std::span<const MemoryRegion> regions,
                                    std::span<const ModuleInfo> modules,
                                    const ForgivingValue<std::uint64_t>& peb_val,
                                    const ForgivingValue<std::vector<std::string>>& env_val,
                                    ProcessEnvironmentSnapshot& snap) {
    const TargetLayout layout = snap.layout;
    const bool is64 = layout.is_64bit();

    if (env_val.has_value()) {
        const auto& vars = *env_val.value;
        const std::size_t count = std::min<std::size_t>(vars.size(), 64u);
        snap.environment_sample.assign(vars.begin(),
                                       vars.begin() + static_cast<std::ptrdiff_t>(count));
    }

    if (!peb_val.has_value() || *peb_val.value == 0u) {
        snap.core_status = peb_val.status.detail.empty()
                               ? SubsystemStatus::unavailable("peb", "PEB address unavailable")
                               : peb_val.status;
        snap.parameters_status =
            (!snap.command_line.empty() || !snap.image_path.empty())
                ? SubsystemStatus::partial("session_info",
                                           "Using OS session metadata (PEB unavailable)")
                : SubsystemStatus::unavailable("peb_params", "Process parameters unavailable");
        if (!modules.empty()) {
            populate_fallback_modules(modules, snap.loader_modules);
            snap.loader_status = SubsystemStatus::partial(
                "modules", "Populated from enumerated modules (PEB_LDR_DATA unavailable)");
        } else {
            snap.loader_status =
                SubsystemStatus::unavailable("peb_ldr", "PEB loader list unavailable");
        }
        snap.auxv_status =
            SubsystemStatus::unavailable("auxv", "Not applicable to Windows PE target");
        snap.status_fields_status =
            SubsystemStatus::unavailable("peb", "PEB security/debugging flags unavailable");
        return;
    }

    const std::uint64_t peb_addr = *peb_val.value;
    snap.block_address = peb_addr;
    snap.auxv_status = SubsystemStatus::unavailable("auxv", "Not applicable to Windows PE target");

    const std::vector<std::uint8_t> peb_bytes =
        is64 ? read_struct_forgiving(session, regions, peb_addr, {0x130u, 0x100u, 0xC0u, 0x40u})
             : read_struct_forgiving(session, regions, peb_addr, {0xB8u, 0x80u, 0x70u, 0x20u});

    if (peb_bytes.size() < (is64 ? 0x38u : 0x1Cu)) {
        snap.core_status =
            SubsystemStatus::unavailable("peb", "Failed to read PEB memory at " + hex_ptr(peb_addr, layout));
        snap.parameters_status =
            (!snap.command_line.empty() || !snap.image_path.empty())
                ? SubsystemStatus::partial("session_info", "PEB unreadable; using session info")
                : SubsystemStatus::unavailable("peb_params", "PEB unreadable");
        if (!modules.empty()) {
            populate_fallback_modules(modules, snap.loader_modules);
            snap.loader_status = SubsystemStatus::partial(
                "modules", "PEB unreadable; using enumerated modules");
        } else {
            snap.loader_status = SubsystemStatus::unavailable("peb_ldr", "PEB unreadable");
        }
        snap.status_fields_status = SubsystemStatus::unavailable("peb", "PEB unreadable");
        return;
    }

    const EndianReader peb(peb_bytes, layout);

    const std::uint8_t inherited_as = peb.read_u8(0x00u).value_or(0u);
    const std::uint8_t read_ifeo = peb.read_u8(0x01u).value_or(0u);
    const std::uint8_t being_debugged = peb.read_u8(0x02u).value_or(0u);
    const std::uint8_t bit_field = peb.read_u8(0x03u).value_or(0u);

    const std::size_t off_mutant = is64 ? 0x08u : 0x04u;
    const std::size_t off_image_base = is64 ? 0x10u : 0x08u;
    const std::size_t off_ldr = is64 ? 0x18u : 0x0Cu;
    const std::size_t off_params = is64 ? 0x20u : 0x10u;
    const std::size_t off_subsys = is64 ? 0x28u : 0x14u;
    const std::size_t off_heap = is64 ? 0x30u : 0x18u;
    const std::size_t off_num_procs = is64 ? 0xB8u : 0x64u;
    const std::size_t off_nt_global = is64 ? 0xBCu : 0x68u;
    const std::size_t off_os_major = is64 ? 0x118u : 0xA4u;
    const std::size_t off_os_minor = is64 ? 0x11Cu : 0xA8u;
    const std::size_t off_os_build = is64 ? 0x120u : 0xACu;

    const std::uint64_t mutant = peb.read_pointer(off_mutant).value_or(0u);
    const std::uint64_t image_base = peb.read_pointer(off_image_base).value_or(0u);
    const std::uint64_t ldr_addr = peb.read_pointer(off_ldr).value_or(0u);
    const std::uint64_t params_addr = peb.read_pointer(off_params).value_or(0u);
    const std::uint64_t subsys_data = peb.read_pointer(off_subsys).value_or(0u);
    const std::uint64_t proc_heap = peb.read_pointer(off_heap).value_or(0u);

    snap.core_fields.push_back(DecodedField{
        "InheritedAddressSpace", 0x00u, inherited_as, std::to_string(inherited_as),
        "Address space inherited from parent"});
    snap.core_fields.push_back(DecodedField{
        "ReadImageFileExecOptions", 0x01u, read_ifeo, std::to_string(read_ifeo),
        "IFEO registry key present"});
    snap.core_fields.push_back(DecodedField{
        "BeingDebugged", 0x02u, being_debugged, being_debugged != 0u ? "1 (True)" : "0 (False)",
        "User-mode debugger attached indicator"});
    snap.core_fields.push_back(DecodedField{
        "BitField", 0x03u, bit_field, hex_u64(bit_field, 2u),
        "PEB loader/mitigation bitfield"});
    snap.core_fields.push_back(DecodedField{
        "Mutant", off_mutant, mutant, hex_ptr(mutant, layout), "PEB Mutant handle"});
    snap.core_fields.push_back(DecodedField{
        "ImageBaseAddress", off_image_base, image_base, hex_ptr(image_base, layout),
        "Main executable load base"});
    snap.core_fields.push_back(DecodedField{
        "Ldr", off_ldr, ldr_addr, hex_ptr(ldr_addr, layout), "PEB_LDR_DATA pointer"});
    snap.core_fields.push_back(DecodedField{
        "ProcessParameters", off_params, params_addr, hex_ptr(params_addr, layout),
        "RTL_USER_PROCESS_PARAMETERS pointer"});
    snap.core_fields.push_back(DecodedField{
        "SubSystemData", off_subsys, subsys_data, hex_ptr(subsys_data, layout),
        "Subsystem-specific data pointer"});
    snap.core_fields.push_back(DecodedField{
        "ProcessHeap", off_heap, proc_heap, hex_ptr(proc_heap, layout),
        "Default process heap base"});

    if (const auto nprocs = peb.read_u32(off_num_procs)) {
        snap.core_fields.push_back(DecodedField{
            "NumberOfProcessors", off_num_procs, *nprocs, std::to_string(*nprocs),
            "Logical processor count"});
    }

    std::uint32_t nt_global_flag = 0u;
    bool have_nt_global = false;
    if (const auto ngf = peb.read_u32(off_nt_global)) {
        nt_global_flag = *ngf;
        have_nt_global = true;
        const bool debug_heap = (nt_global_flag & 0x70u) == 0x70u;
        std::string desc = "Global system/loader flags";
        if (debug_heap) {
            desc = "FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS (0x70)";
        }
        snap.core_fields.push_back(DecodedField{
            "NtGlobalFlag", off_nt_global, nt_global_flag, hex_u64(nt_global_flag, 8u),
            std::move(desc)});
    }

    if (const auto os_maj = peb.read_u32(off_os_major)) {
        const std::uint32_t os_min = peb.read_u32(off_os_minor).value_or(0u);
        const std::uint16_t os_bld = peb.read_u16(off_os_build).value_or(0u);
        snap.core_fields.push_back(DecodedField{
            "OSMajorVersion", off_os_major, *os_maj, std::to_string(*os_maj),
            "Windows major version"});
        snap.core_fields.push_back(DecodedField{
            "OSMinorVersion", off_os_minor, os_min, std::to_string(os_min),
            "Windows minor version"});
        snap.core_fields.push_back(DecodedField{
            "OSBuildNumber", off_os_build, os_bld, std::to_string(os_bld),
            "Windows build number"});
    }

    snap.debugger_present = (being_debugged != 0u);
    if (being_debugged != 0u && (nt_global_flag & 0x70u) != 0u) {
        snap.debugger_detail =
            "PEB.BeingDebugged=1, NtGlobalFlag=" + hex_u64(nt_global_flag, 2u) + " (debug heap)";
    } else if (being_debugged != 0u) {
        snap.debugger_detail = "PEB.BeingDebugged=1";
    } else if ((nt_global_flag & 0x70u) == 0x70u) {
        snap.debugger_detail = "PEB.BeingDebugged=0, NtGlobalFlag debug heap bits (0x70) set";
    } else {
        snap.debugger_detail = "PEB.BeingDebugged=0";
    }

    // Security & BitField breakdown
    static constexpr std::array<BitFlagSpec, 8> kPebBitSpecs = {{
        {0x01u, "ImageUsesLargePages", "Main image mapped with large pages"},
        {0x02u, "IsProtectedProcess", "Protected Process (PP)"},
        {0x04u, "IsImageDynamicallyRelocated", "ASLR relocated image at load"},
        {0x08u, "SkipPatchingUser32Forwarders", "Skip User32 forwarder patching"},
        {0x10u, "IsPackagedProcess", "MSIX / AppX packaged process"},
        {0x20u, "IsAppContainer", "Executing inside AppContainer token"},
        {0x40u, "IsProtectedProcessLight", "Protected Process Light (PPL)"},
        {0x80u, "IsLongPathAwareProcess", "Win32 long path aware"},
    }};
    for (const BitFlagSpec& spec : kPebBitSpecs) {
        const bool set = (bit_field & spec.mask) != 0u;
        snap.security_and_status_fields.push_back(DecodedField{
            .name = std::string(spec.name),
            .offset = 0x03u,
            .raw_value = set ? 1u : 0u,
            .formatted_value = set ? "True" : "False",
            .description = std::string(spec.description),
        });
    }
    if (have_nt_global) {
        const std::uint32_t heap_dbg = nt_global_flag & 0x70u;
        snap.security_and_status_fields.push_back(DecodedField{
            .name = "NtGlobalFlag Debug Heap (0x70)",
            .offset = off_nt_global,
            .raw_value = heap_dbg,
            .formatted_value = (heap_dbg != 0u) ? ("Active (" + hex_u64(heap_dbg, 2u) + ")")
                                                : "Clear (0x00)",
            .description = "FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FREE_CHECK (0x20) | VALIDATE_PARAMETERS (0x40)",
        });
    }
    snap.core_status = SubsystemStatus::available("peb", "PEB decoded from target memory");
    snap.status_fields_status =
        SubsystemStatus::available("peb", "PEB BitField and NtGlobalFlag decoded");

    // Parse RTL_USER_PROCESS_PARAMETERS
    if (params_addr != 0u) {
        const std::vector<std::uint8_t> param_bytes =
            is64 ? read_struct_forgiving(session, regions, params_addr, {0x90u, 0x88u, 0x80u})
                 : read_struct_forgiving(session, regions, params_addr, {0x50u, 0x4Cu, 0x48u});
        if (!param_bytes.empty()) {
            const EndianReader pr(param_bytes, layout);
            const std::uint32_t pflags = pr.read_u32(0x08u).value_or(1u);
            const std::uint64_t denorm = ((pflags & 0x01u) == 0u) ? params_addr : 0u;

            const std::size_t off_curdir = is64 ? 0x38u : 0x24u;
            const std::size_t off_dllpath = is64 ? 0x50u : 0x30u;
            const std::size_t off_imgpath = is64 ? 0x60u : 0x38u;
            const std::size_t off_cmdline = is64 ? 0x70u : 0x40u;
            const std::size_t off_envptr = is64 ? 0x80u : 0x48u;

            int decoded_strings = 0;
            if (const auto cwd =
                    read_remote_unicode_string(session, regions, layout, pr, off_curdir, denorm)) {
                if (!cwd->empty()) {
                    snap.current_directory = *cwd;
                }
                snap.process_parameters.push_back(DecodedField{
                    "CurrentDirectory", off_curdir, std::nullopt, *cwd,
                    "RTL_USER_PROCESS_PARAMETERS.CurrentDirectory"});
                ++decoded_strings;
            }
            if (const auto dllp =
                    read_remote_unicode_string(session, regions, layout, pr, off_dllpath, denorm)) {
                snap.process_parameters.push_back(DecodedField{
                    "DllPath", off_dllpath, std::nullopt, *dllp,
                    "RTL_USER_PROCESS_PARAMETERS.DllPath"});
                ++decoded_strings;
            }
            if (const auto img =
                    read_remote_unicode_string(session, regions, layout, pr, off_imgpath, denorm)) {
                if (!img->empty()) {
                    snap.image_path = *img;
                }
                snap.process_parameters.push_back(DecodedField{
                    "ImagePathName", off_imgpath, std::nullopt, *img,
                    "RTL_USER_PROCESS_PARAMETERS.ImagePathName"});
                ++decoded_strings;
            }
            if (const auto cmd =
                    read_remote_unicode_string(session, regions, layout, pr, off_cmdline, denorm)) {
                if (!cmd->empty()) {
                    snap.command_line = *cmd;
                }
                snap.process_parameters.push_back(DecodedField{
                    "CommandLine", off_cmdline, std::nullopt, *cmd,
                    "RTL_USER_PROCESS_PARAMETERS.CommandLine"});
                ++decoded_strings;
            }
            if (const auto env_ptr = pr.read_pointer(off_envptr)) {
                snap.process_parameters.push_back(DecodedField{
                    "Environment", off_envptr, *env_ptr, hex_ptr(*env_ptr, layout),
                    "UTF-16 process environment block pointer"});
                if (snap.environment_sample.empty() && *env_ptr != 0u) {
                    const std::vector<std::uint8_t> env_raw =
                        read_struct_forgiving(session, regions, *env_ptr, {4096u, 1024u, 256u});
                    if (env_raw.size() >= 4u) {
                        const EndianReader er(env_raw, layout);
                        std::size_t uoff = 0u;
                        while (uoff + 2u <= er.size() && snap.environment_sample.size() < 64u) {
                            const auto first_cu = er.read_u16(uoff);
                            if (!first_cu || *first_cu == 0u) {
                                break;
                            }
                            const auto entry =
                                er.read_utf16_string(uoff, (er.size() - uoff) / 2u);
                            if (!entry || entry->empty()) {
                                break;
                            }
                            while (uoff + 2u <= er.size()) {
                                const auto cu = er.read_u16(uoff);
                                uoff += 2u;
                                if (!cu || *cu == 0u) {
                                    break;
                                }
                            }
                            snap.environment_sample.push_back(*entry);
                        }
                    }
                }
            }

            snap.parameters_status =
                (decoded_strings >= 2)
                    ? SubsystemStatus::available("peb_params",
                                                 "RTL_USER_PROCESS_PARAMETERS decoded")
                    : SubsystemStatus::partial("peb_params",
                                               "Partial RTL_USER_PROCESS_PARAMETERS read");
        } else {
            snap.parameters_status = SubsystemStatus::partial(
                "session_info", "RTL_USER_PROCESS_PARAMETERS unreadable; using session info");
        }
    } else {
        snap.parameters_status = SubsystemStatus::partial(
            "session_info", "ProcessParameters pointer is NULL; using session info");
    }

    // Walk PEB_LDR_DATA.InLoadOrderModuleList
    bool ldr_ok = false;
    if (ldr_addr != 0u) {
        const std::size_t head_off = is64 ? 0x10u : 0x0Cu;
        const std::size_t ldr_read_sz = head_off + layout.pointer_size() * 2u;
        const std::vector<std::uint8_t> ldr_hdr =
            read_struct_forgiving(session, regions, ldr_addr, {ldr_read_sz});
        if (ldr_hdr.size() >= ldr_read_sz) {
            const EndianReader lr(ldr_hdr, layout);
            const std::uint64_t list_head = ldr_addr + static_cast<std::uint64_t>(head_off);
            std::uint64_t curr = lr.read_pointer(head_off).value_or(0u);

            std::unordered_set<std::uint64_t> visited;
            visited.insert(list_head);

            const std::size_t entry_sz = is64 ? 0x68u : 0x34u;
            const std::size_t off_dll_base = is64 ? 0x30u : 0x18u;
            const std::size_t off_entry_pt = is64 ? 0x38u : 0x1Cu;
            const std::size_t off_img_size = is64 ? 0x40u : 0x20u;
            const std::size_t off_full_name = is64 ? 0x48u : 0x24u;
            const std::size_t off_base_name = is64 ? 0x58u : 0x2Cu;

            while (curr != 0u && curr != list_head && snap.loader_modules.size() < 256u) {
                if (!visited.insert(curr).second) {
                    break;
                }
                const std::vector<std::uint8_t> ent_bytes =
                    read_struct_forgiving(session, regions, curr, {entry_sz});
                if (ent_bytes.size() < entry_sz) {
                    break;
                }
                const EndianReader er(ent_bytes, layout);
                const std::uint64_t next = er.read_pointer(0x00u).value_or(0u);
                const std::uint64_t dll_base = er.read_pointer(off_dll_base).value_or(0u);
                const std::uint64_t entry_pt = er.read_pointer(off_entry_pt).value_or(0u);
                const std::uint32_t size_img = er.read_u32(off_img_size).value_or(0u);

                if (dll_base == 0u && size_img == 0u) {
                    break;
                }

                std::string full_name =
                    read_remote_unicode_string(session, regions, layout, er, off_full_name)
                        .value_or(std::string{});
                std::string base_name =
                    read_remote_unicode_string(session, regions, layout, er, off_base_name)
                        .value_or(std::string{});
                if (base_name.empty() && !full_name.empty()) {
                    base_name = basename_of(full_name);
                }

                snap.loader_modules.push_back(RuntimeModuleEntry{
                    .name = std::move(base_name),
                    .full_path = std::move(full_name),
                    .base_address = dll_base,
                    .size_or_dynamic_va = size_img,
                    .entry_point = entry_pt,
                });
                ldr_ok = true;
                curr = next;
            }
        }
    }

    if (ldr_ok) {
        snap.loader_status = SubsystemStatus::available(
            "peb_ldr", "Walked PEB_LDR_DATA.InLoadOrderModuleList");
    } else if (!modules.empty()) {
        populate_fallback_modules(modules, snap.loader_modules);
        snap.loader_status = SubsystemStatus::partial(
            "modules", "PEB_LDR_DATA walk unavailable; populated from enumerated modules");
    } else {
        snap.loader_status =
            SubsystemStatus::unavailable("peb_ldr", "PEB_LDR_DATA module list unavailable");
    }
}

[[nodiscard]] std::string_view auxv_type_name(std::uint64_t type) noexcept {
    switch (type) {
        case 0:  return "AT_NULL";
        case 1:  return "AT_IGNORE";
        case 2:  return "AT_EXECFD";
        case 3:  return "AT_PHDR";
        case 4:  return "AT_PHENT";
        case 5:  return "AT_PHNUM";
        case 6:  return "AT_PAGESZ";
        case 7:  return "AT_BASE";
        case 8:  return "AT_FLAGS";
        case 9:  return "AT_ENTRY";
        case 11: return "AT_UID";
        case 12: return "AT_EUID";
        case 13: return "AT_GID";
        case 14: return "AT_EGID";
        case 15: return "AT_PLATFORM";
        case 16: return "AT_HWCAP";
        case 17: return "AT_CLKTCK";
        case 23: return "AT_SECURE";
        case 24: return "AT_BASE_PLATFORM";
        case 25: return "AT_RANDOM";
        case 26: return "AT_HWCAP2";
        case 31: return "AT_EXECFN";
        case 32: return "AT_SYSINFO";
        case 33: return "AT_SYSINFO_EHDR";
        case 51: return "AT_MINSIGSTKSZ";
        default: return "AT_OTHER";
    }
}

[[nodiscard]] std::string format_random_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr std::array<char, 16> kHex = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out;
    out.reserve(bytes.size() * 3u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0u) {
            out.push_back(' ');
        }
        out.push_back(kHex[static_cast<std::size_t>((bytes[i] >> 4u) & 0x0Fu)]);
        out.push_back(kHex[static_cast<std::size_t>(bytes[i] & 0x0Fu)]);
    }
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> find_elf_r_debug_address(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const IBinaryImage* main_image,
    TargetLayout layout,
    std::uint64_t at_phdr,
    std::uint64_t at_phent,
    std::uint64_t at_phnum) {
    // 1. Check if main_image already contains a live non-zero DT_DEBUG (tag 21).
    if (main_image != nullptr && main_image->format() == Format::ELF) {
        for (const ElfDynamicEntry& dyn : main_image->elf_dynamic_entries()) {
            if (dyn.tag == 21u && dyn.value != 0u) {
                return dyn.value;
            }
        }
    }

    std::uint64_t main_base = 0u;
    for (const ModuleInfo& mod : modules) {
        if (mod.is_main_module) {
            main_base = mod.base_address;
            break;
        }
    }
    if (main_base == 0u && !modules.empty()) {
        main_base = modules.front().base_address;
    }

    // 2. Locate PT_DYNAMIC virtual address in live memory via AT_PHDR or main_image.
    std::uint64_t dynamic_va = 0u;
    std::uint64_t dynamic_sz = 0u;

    const bool is64 = layout.is_64bit();
    const std::size_t expected_phent = is64 ? 56u : 32u;
    if (at_phdr != 0u && at_phnum > 0u && at_phnum <= 128u) {
        const std::size_t phent =
            (at_phent >= expected_phent && at_phent <= 128u) ? static_cast<std::size_t>(at_phent)
                                                             : expected_phent;
        const std::size_t total_ph_bytes = phent * static_cast<std::size_t>(at_phnum);
        const std::vector<std::uint8_t> ph_buf =
            read_struct_forgiving(session, regions, at_phdr, {total_ph_bytes});
        if (ph_buf.size() >= phent) {
            const EndianReader phr(ph_buf, layout);
            std::optional<std::uint64_t> load_bias;
            std::optional<std::uint64_t> first_load_vaddr;
            std::optional<std::uint64_t> dyn_p_vaddr;
            std::uint64_t dyn_p_memsz = 0u;

            const std::size_t count = ph_buf.size() / phent;
            for (std::size_t i = 0; i < count; ++i) {
                const std::size_t base = i * phent;
                const std::uint32_t p_type = phr.read_u32(base).value_or(0u);
                const std::uint64_t p_offset =
                    is64 ? phr.read_u64(base + 8u).value_or(0u)
                         : static_cast<std::uint64_t>(phr.read_u32(base + 4u).value_or(0u));
                const std::uint64_t p_vaddr =
                    is64 ? phr.read_u64(base + 16u).value_or(0u)
                         : static_cast<std::uint64_t>(phr.read_u32(base + 8u).value_or(0u));
                const std::uint64_t p_memsz =
                    is64 ? phr.read_u64(base + 40u).value_or(0u)
                         : static_cast<std::uint64_t>(phr.read_u32(base + 20u).value_or(0u));

                if (p_type == 6u) {  // PT_PHDR
                    load_bias = at_phdr - p_vaddr;
                } else if (p_type == 1u && !first_load_vaddr.has_value()) {  // first PT_LOAD
                    first_load_vaddr = p_vaddr - p_offset;
                } else if (p_type == 2u) {  // PT_DYNAMIC
                    dyn_p_vaddr = p_vaddr;
                    dyn_p_memsz = p_memsz;
                }
            }

            if (!load_bias.has_value() && main_base != 0u && first_load_vaddr.has_value()) {
                load_bias = main_base - *first_load_vaddr;
            }
            if (dyn_p_vaddr.has_value()) {
                dynamic_va = load_bias.value_or(0u) + *dyn_p_vaddr;
                dynamic_sz = dyn_p_memsz;
            }
        }
    }

    if (dynamic_va == 0u && main_image != nullptr && main_image->format() == Format::ELF) {
        std::optional<std::uint64_t> first_load_va;
        for (const ElfProgramHeader& ph : main_image->elf_program_headers()) {
            if (ph.type == 1u && !first_load_va.has_value()) {
                first_load_va = ph.virtual_address - ph.offset;
            } else if (ph.type == 2u) {
                dynamic_va = ph.virtual_address;
                dynamic_sz = ph.memory_size;
            }
        }
        if (dynamic_va != 0u && main_base != 0u && first_load_va.has_value() &&
            dynamic_va < main_base) {
            dynamic_va += (main_base - *first_load_va);
        }
    }

    if (dynamic_va == 0u) {
        return std::nullopt;
    }

    const std::size_t entry_bytes = layout.pointer_size() * 2u;
    const std::size_t max_dyn_read = static_cast<std::size_t>(
        std::clamp<std::uint64_t>(dynamic_sz == 0u ? 4096u : dynamic_sz,
                                  entry_bytes,
                                  16384u));
    const std::vector<std::uint8_t> dyn_buf =
        read_struct_forgiving(session, regions, dynamic_va, {max_dyn_read, 1024u, 256u});
    if (dyn_buf.size() < entry_bytes) {
        return std::nullopt;
    }

    const EndianReader dr(dyn_buf, layout);
    const std::size_t max_entries = dyn_buf.size() / entry_bytes;
    for (std::size_t i = 0; i < max_entries; ++i) {
        const std::size_t off = i * entry_bytes;
        const auto d_tag = dr.read_pointer(off);
        const auto d_val = dr.read_pointer(off + layout.pointer_size());
        if (!d_tag || !d_val || *d_tag == 0u) {
            break;
        }
        if (*d_tag == 21u && *d_val != 0u) {
            return *d_val;
        }
    }

    return std::nullopt;
}

void inspect_elf_process_environment(IProcessSession& session,
                                     std::span<const MemoryRegion> regions,
                                     std::span<const ModuleInfo> modules,
                                     const IBinaryImage* main_image,
                                     const ForgivingValue<std::vector<std::uint8_t>>& auxv_val,
                                     const ForgivingValue<std::string>& status_val,
                                     const ForgivingValue<std::vector<std::string>>& env_val,
                                     ProcessEnvironmentSnapshot& snap) {
    const TargetLayout layout = snap.layout;

    // Populate process_parameters & environment_sample
    if (!snap.image_path.empty()) {
        snap.process_parameters.push_back(DecodedField{
            "ExecutablePath", std::nullopt, std::nullopt, snap.image_path,
            "Resolved process executable image"});
    }
    if (!snap.command_line.empty()) {
        snap.process_parameters.push_back(DecodedField{
            "CommandLine", std::nullopt, std::nullopt, snap.command_line,
            "/proc/<pid>/cmdline"});
    }
    if (!snap.current_directory.empty()) {
        snap.process_parameters.push_back(DecodedField{
            "CurrentDirectory", std::nullopt, std::nullopt, snap.current_directory,
            "/proc/<pid>/cwd"});
    }
    if (env_val.has_value()) {
        const auto& vars = *env_val.value;
        const std::size_t keep = std::min<std::size_t>(vars.size(), 64u);
        snap.environment_sample.assign(vars.begin(),
                                       vars.begin() + static_cast<std::ptrdiff_t>(keep));
        snap.process_parameters.push_back(DecodedField{
            "EnvironmentCount",
            std::nullopt,
            static_cast<std::uint64_t>(vars.size()),
            std::to_string(vars.size()) + " variables",
            "/proc/<pid>/environ",
        });
        snap.parameters_status =
            SubsystemStatus::available("procfs", "Loaded cmdline, cwd, and environ");
    } else if (!snap.process_parameters.empty()) {
        snap.parameters_status = SubsystemStatus::partial(
            "procfs",
            env_val.status.detail.empty() ? "environ unavailable; cmdline/cwd populated"
                                          : env_val.status.detail);
    } else {
        snap.parameters_status = env_val.status;
    }

    // Parse /proc/<pid>/auxv
    std::uint64_t at_phdr = 0u;
    std::uint64_t at_phent = 0u;
    std::uint64_t at_phnum = 0u;

    if (auxv_val.has_value() && !auxv_val.value->empty()) {
        const EndianReader ar(*auxv_val.value, layout);
        const std::size_t ptr_sz = layout.pointer_size();
        const std::size_t pair_sz = ptr_sz * 2u;

        std::size_t off = 0u;
        while (ar.can_read(off, pair_sz)) {
            const auto t_res = ar.read_pointer(off);
            const auto v_res = ar.read_pointer(off + ptr_sz);
            off += pair_sz;
            if (!t_res || !v_res) {
                break;
            }
            const std::uint64_t a_type = *t_res;
            const std::uint64_t a_val = *v_res;
            if (a_type == 0u) {  // AT_NULL
                break;
            }

            AuxvEntry entry;
            entry.type = a_type;
            entry.type_name = std::string(auxv_type_name(a_type));
            entry.value = a_val;
            entry.formatted_value = hex_ptr(a_val, layout);

            switch (a_type) {
                case 3u:  // AT_PHDR
                    at_phdr = a_val;
                    entry.description = "Program headers virtual address";
                    snap.core_fields.push_back(DecodedField{
                        "AT_PHDR", std::nullopt, a_val, entry.formatted_value, entry.description});
                    break;
                case 4u:  // AT_PHENT
                    at_phent = a_val;
                    entry.formatted_value = std::to_string(a_val) + " bytes";
                    entry.description = "Program header entry size";
                    break;
                case 5u:  // AT_PHNUM
                    at_phnum = a_val;
                    entry.formatted_value = std::to_string(a_val);
                    entry.description = "Number of program headers";
                    break;
                case 6u:  // AT_PAGESZ
                    entry.formatted_value = std::to_string(a_val) + " (" + hex_u64(a_val) + ")";
                    entry.description = "System page size";
                    snap.core_fields.push_back(DecodedField{
                        "AT_PAGESZ", std::nullopt, a_val, entry.formatted_value, entry.description});
                    break;
                case 7u:  // AT_BASE
                    entry.description = "Dynamic linker (ld.so) base address";
                    snap.core_fields.push_back(DecodedField{
                        "AT_BASE", std::nullopt, a_val, entry.formatted_value, entry.description});
                    break;
                case 8u:  // AT_FLAGS
                    entry.description = "Auxiliary flags";
                    break;
                case 9u:  // AT_ENTRY
                    entry.description = "Executable entry point";
                    snap.core_fields.push_back(DecodedField{
                        "AT_ENTRY", std::nullopt, a_val, entry.formatted_value, entry.description});
                    break;
                case 11u:
                case 12u:
                case 13u:
                case 14u:
                    entry.formatted_value = std::to_string(a_val);
                    entry.description = "Process credential ID";
                    break;
                case 15u:  // AT_PLATFORM
                case 24u: {  // AT_BASE_PLATFORM
                    entry.description = "CPU platform string";
                    if (const auto plat =
                            read_remote_c_string(session, regions, layout, a_val, 64u)) {
                        entry.formatted_value = hex_ptr(a_val, layout) + " (\"" + *plat + "\")";
                    }
                    break;
                }
                case 16u:  // AT_HWCAP
                case 26u:  // AT_HWCAP2
                    entry.description = "CPU hardware capability mask";
                    break;
                case 17u:  // AT_CLKTCK
                    entry.formatted_value = std::to_string(a_val) + " Hz";
                    entry.description = "Clock ticks per second";
                    break;
                case 23u:  // AT_SECURE
                    entry.formatted_value = (a_val != 0u) ? "1 (AT_SECURE enabled)" : "0 (Normal)";
                    entry.description = "Secure execution mode (setuid/capabilities)";
                    break;
                case 25u: {  // AT_RANDOM
                    entry.description = "16-byte kernel random seed (stack canary source)";
                    const std::vector<std::uint8_t> rnd =
                        read_struct_forgiving(session, regions, a_val, {16u});
                    if (rnd.size() == 16u) {
                        entry.formatted_value =
                            hex_ptr(a_val, layout) + " [" + format_random_bytes(rnd) + "]";
                    }
                    snap.core_fields.push_back(DecodedField{
                        "AT_RANDOM", std::nullopt, a_val, entry.formatted_value, entry.description});
                    break;
                }
                case 31u: {  // AT_EXECFN
                    entry.description = "Executed filename string";
                    if (const auto fn =
                            read_remote_c_string(session, regions, layout, a_val, 512u)) {
                        entry.formatted_value = hex_ptr(a_val, layout) + " (\"" + *fn + "\")";
                        if (snap.image_path.empty() && !fn->empty()) {
                            snap.image_path = *fn;
                        }
                    }
                    break;
                }
                case 33u:  // AT_SYSINFO_EHDR
                    entry.description = "Kernel vDSO base address";
                    snap.core_fields.push_back(DecodedField{
                        "AT_SYSINFO_EHDR",
                        std::nullopt,
                        a_val,
                        entry.formatted_value,
                        entry.description,
                    });
                    break;
                default:
                    entry.description = "Auxiliary vector entry";
                    break;
            }

            snap.auxv_entries.push_back(std::move(entry));
        }

        snap.auxv_status =
            !snap.auxv_entries.empty()
                ? SubsystemStatus::available("procfs", "Decoded /proc/<pid>/auxv")
                : SubsystemStatus::partial("procfs", "auxv buffer contained no entries");
    } else {
        snap.auxv_status = auxv_val.status;
    }

    // Parse /proc/<pid>/status
    if (status_val.has_value() && !status_val.value->empty()) {
        const std::string_view text = *status_val.value;
        std::size_t pos = 0u;
        while (pos < text.size()) {
            const std::size_t nl = text.find('\n', pos);
            const std::string_view line =
                (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? text.size() : (nl + 1u);

            const std::size_t colon = line.find(':');
            if (colon == std::string_view::npos) {
                continue;
            }
            const std::string_view key = trim_ws(line.substr(0u, colon));
            const std::string_view val = trim_ws(line.substr(colon + 1u));

            if (key == "TracerPid") {
                std::int64_t tracer = 0;
                const auto [p, ec] =
                    std::from_chars(val.data(), val.data() + val.size(), tracer, 10);
                (void)p;
                if (ec == std::errc{}) {
                    snap.debugger_present = (tracer != 0);
                    snap.debugger_detail =
                        (tracer != 0) ? ("TracerPid=" + std::to_string(tracer))
                                      : "TracerPid=0 (Not traced)";
                    snap.security_and_status_fields.push_back(DecodedField{
                        "TracerPid",
                        std::nullopt,
                        static_cast<std::uint64_t>(tracer >= 0 ? tracer : 0),
                        snap.debugger_detail,
                        "Ptrace debugger / tracer PID",
                    });
                }
            } else if (key == "Seccomp") {
                std::uint64_t mode = 0u;
                (void)std::from_chars(val.data(), val.data() + val.size(), mode, 10);
                std::string formatted = std::string(val);
                if (mode == 0u) {
                    formatted = "0 (Disabled)";
                } else if (mode == 1u) {
                    formatted = "1 (Strict)";
                } else if (mode == 2u) {
                    formatted = "2 (BPF Filter)";
                }
                snap.security_and_status_fields.push_back(DecodedField{
                    "Seccomp", std::nullopt, mode, std::move(formatted),
                    "Kernel seccomp syscall sandboxing"});
            } else if (key == "NoNewPrivs") {
                std::uint64_t nnp = 0u;
                (void)std::from_chars(val.data(), val.data() + val.size(), nnp, 10);
                snap.security_and_status_fields.push_back(DecodedField{
                    "NoNewPrivs",
                    std::nullopt,
                    nnp,
                    (nnp != 0u) ? "1 (Restricted)" : "0",
                    "PR_SET_NO_NEW_PRIVS status",
                });
            } else if (key == "State" || key == "Tgid" || key == "Uid" || key == "Gid" ||
                       key == "VmPeak" || key == "VmSize" || key == "VmRSS" || key == "VmData" ||
                       key == "VmStk" || key == "VmExe" || key == "Threads" || key == "CapPrm" ||
                       key == "CapEff") {
                snap.security_and_status_fields.push_back(DecodedField{
                    std::string(key),
                    std::nullopt,
                    std::nullopt,
                    std::string(val),
                    "/proc/<pid>/status",
                });
            }
        }
        snap.status_fields_status =
            SubsystemStatus::available("procfs", "Parsed /proc/<pid>/status");
    } else {
        snap.status_fields_status = status_val.status;
    }

    // Walk dynamic loader r_debug -> link_map
    const std::optional<std::uint64_t> r_debug_va = find_elf_r_debug_address(
        session, regions, modules, main_image, layout, at_phdr, at_phent, at_phnum);

    bool walked_link_map = false;
    if (r_debug_va.has_value() && *r_debug_va != 0u) {
        snap.block_address = *r_debug_va;
        const bool is64 = layout.is_64bit();
        const std::size_t rdbg_sz = is64 ? 0x28u : 0x14u;
        const std::vector<std::uint8_t> rdbg_buf =
            read_struct_forgiving(session, regions, *r_debug_va, {rdbg_sz});
        if (rdbg_buf.size() >= rdbg_sz) {
            const EndianReader rr(rdbg_buf, layout);
            const std::int32_t r_version = rr.read_i32(0x00u).value_or(0);
            const std::uint64_t r_map = rr.read_pointer(is64 ? 0x08u : 0x04u).value_or(0u);
            const std::uint64_t r_brk = rr.read_pointer(is64 ? 0x10u : 0x08u).value_or(0u);
            const std::int32_t r_state = rr.read_i32(is64 ? 0x18u : 0x0Cu).value_or(0);
            const std::uint64_t r_ldbase = rr.read_pointer(is64 ? 0x20u : 0x10u).value_or(0u);

            std::string state_str = "RT_CONSISTENT (0)";
            if (r_state == 1) {
                state_str = "RT_ADD (1)";
            } else if (r_state == 2) {
                state_str = "RT_DELETE (2)";
            }

            snap.core_fields.push_back(DecodedField{
                "r_debug.r_version", 0x00u, static_cast<std::uint64_t>(r_version),
                std::to_string(r_version), "Dynamic linker debug protocol version"});
            snap.core_fields.push_back(DecodedField{
                "r_debug.r_map", is64 ? 0x08u : 0x04u, r_map, hex_ptr(r_map, layout),
                "Head of link_map doubly-linked list"});
            snap.core_fields.push_back(DecodedField{
                "r_debug.r_brk", is64 ? 0x10u : 0x08u, r_brk, hex_ptr(r_brk, layout),
                "Dynamic linker notification breakpoint"});
            snap.core_fields.push_back(DecodedField{
                "r_debug.r_state", is64 ? 0x18u : 0x0Cu,
                static_cast<std::uint64_t>(r_state >= 0 ? r_state : 0),
                std::move(state_str), "Dynamic linker map state"});
            snap.core_fields.push_back(DecodedField{
                "r_debug.r_ldbase", is64 ? 0x20u : 0x10u, r_ldbase, hex_ptr(r_ldbase, layout),
                "Dynamic linker load base"});

            const std::size_t lmap_sz = is64 ? 0x28u : 0x14u;
            const std::size_t off_l_name = is64 ? 0x08u : 0x04u;
            const std::size_t off_l_ld = is64 ? 0x10u : 0x08u;
            const std::size_t off_l_next = is64 ? 0x18u : 0x0Cu;

            std::unordered_set<std::uint64_t> visited;
            std::uint64_t curr = r_map;
            bool first_node = true;
            while (curr != 0u && snap.loader_modules.size() < 256u) {
                if (!visited.insert(curr).second) {
                    break;
                }
                const std::vector<std::uint8_t> lm_buf =
                    read_struct_forgiving(session, regions, curr, {lmap_sz});
                if (lm_buf.size() < lmap_sz) {
                    break;
                }
                const EndianReader lmr(lm_buf, layout);
                const std::uint64_t l_addr = lmr.read_pointer(0x00u).value_or(0u);
                const std::uint64_t l_name_ptr = lmr.read_pointer(off_l_name).value_or(0u);
                const std::uint64_t l_ld = lmr.read_pointer(off_l_ld).value_or(0u);
                const std::uint64_t l_next = lmr.read_pointer(off_l_next).value_or(0u);

                std::string full_path =
                    read_remote_c_string(session, regions, layout, l_name_ptr, 512u)
                        .value_or(std::string{});
                if (full_path.empty() && first_node) {
                    full_path = !snap.image_path.empty() ? snap.image_path : session.info().name;
                }
                std::string short_name = basename_of(full_path);
                if (short_name.empty()) {
                    short_name = first_node ? "[main]" : hex_ptr(l_addr, layout);
                }

                std::uint64_t entry_pt = 0u;
                for (const ModuleInfo& mod : modules) {
                    if (mod.base_address == l_addr ||
                        (first_node && mod.is_main_module)) {
                        entry_pt = mod.entry_point;
                        break;
                    }
                }

                snap.loader_modules.push_back(RuntimeModuleEntry{
                    .name = std::move(short_name),
                    .full_path = std::move(full_path),
                    .base_address = l_addr,
                    .size_or_dynamic_va = l_ld,
                    .entry_point = entry_pt,
                });

                walked_link_map = true;
                first_node = false;
                curr = l_next;
            }
        }
    }

    if (!snap.block_address.has_value() && at_phdr != 0u) {
        snap.block_address = at_phdr;
    }

    if (walked_link_map) {
        snap.loader_status =
            SubsystemStatus::available("r_debug", "Walked DT_DEBUG -> r_debug -> link_map");
        snap.core_status = SubsystemStatus::available(
            "elf_runtime", "Decoded ELF auxv and dynamic loader r_debug");
    } else {
        if (!modules.empty()) {
            populate_fallback_modules(modules, snap.loader_modules);
            snap.loader_status = SubsystemStatus::partial(
                "modules",
                "r_debug/link_map unavailable (static or stripped runtime); using mapped modules");
        } else {
            snap.loader_status =
                SubsystemStatus::unavailable("r_debug", "Dynamic loader link_map unavailable");
        }
        snap.core_status =
            !snap.core_fields.empty()
                ? SubsystemStatus::partial("auxv", "auxv core pointers available; r_debug unavailable")
                : SubsystemStatus::unavailable("elf_runtime",
                                               "ELF runtime structures unavailable");
    }
}

void populate_mapped_stack_bounds(std::optional<std::uint64_t> sp,
                                  std::span<const MemoryRegion> regions,
                                  ThreadEnvironmentSnapshot& snap) {
    if (sp.has_value() && *sp != 0u) {
        for (const MemoryRegion& reg : regions) {
            if (reg.contains(*sp)) {
                snap.stack_limit = reg.start_address;
                snap.stack_base = reg.end_address;
                return;
            }
        }
    }
    for (const MemoryRegion& reg : regions) {
        if (reg.kind == MemoryRegionKind::Stack) {
            snap.stack_limit = reg.start_address;
            snap.stack_base = reg.end_address;
            return;
        }
    }
}

void inspect_pe_thread_environment(IProcessSession& session,
                                   const ThreadInfo& thread_info,
                                   const ThreadContext* thread_ctx,
                                   std::span<const MemoryRegion> regions,
                                   std::optional<std::uint64_t> teb_opt,
                                   ThreadEnvironmentSnapshot& snap) {
    const TargetLayout layout = snap.layout;
    const bool is64 = layout.is_64bit();

    const std::optional<std::uint64_t> sp_opt =
        (thread_ctx != nullptr && thread_ctx->stack_pointer != 0u)
            ? std::optional<std::uint64_t>(thread_ctx->stack_pointer)
            : thread_info.stack_pointer;

    if (!teb_opt.has_value() || *teb_opt == 0u) {
        populate_mapped_stack_bounds(sp_opt, regions, snap);
        snap.fields.push_back(DecodedField{
            "TID", std::nullopt, snap.tid, std::to_string(snap.tid), "Thread ID"});
        snap.fields.push_back(DecodedField{
            "State", std::nullopt, std::nullopt, std::string(to_string(thread_info.state)),
            "Thread execution state"});
        snap.status =
            snap.stack_base.has_value()
                ? SubsystemStatus::partial("thread_info",
                                           "TEB address unavailable; mapped stack bounds located")
                : SubsystemStatus::unavailable("teb", "TEB address unavailable");
        return;
    }

    const std::uint64_t teb_addr = *teb_opt;
    snap.block_address = teb_addr;

    const std::size_t min_teb = is64 ? 0x70u : 0x38u;
    const std::vector<std::uint8_t> teb_bytes =
        read_struct_forgiving(session, regions, teb_addr, {0x80u, min_teb});
    if (teb_bytes.size() < min_teb) {
        populate_mapped_stack_bounds(sp_opt, regions, snap);
        snap.status = SubsystemStatus::unavailable(
            "teb", "Failed to read TEB memory at " + hex_ptr(teb_addr, layout));
        return;
    }

    const EndianReader tr(teb_bytes, layout);

    const std::size_t off_exc_list = 0x00u;
    const std::size_t off_stack_base = is64 ? 0x08u : 0x04u;
    const std::size_t off_stack_limit = is64 ? 0x10u : 0x08u;
    const std::size_t off_subsys_tib = is64 ? 0x18u : 0x0Cu;
    const std::size_t off_fiber_data = is64 ? 0x20u : 0x10u;
    const std::size_t off_arb_user = is64 ? 0x28u : 0x14u;
    const std::size_t off_self = is64 ? 0x30u : 0x18u;
    const std::size_t off_env_ptr = is64 ? 0x38u : 0x1Cu;
    const std::size_t off_cid_pid = is64 ? 0x40u : 0x20u;
    const std::size_t off_cid_tid = is64 ? 0x48u : 0x24u;
    const std::size_t off_tls_ptr = is64 ? 0x58u : 0x2Cu;
    const std::size_t off_peb_ptr = is64 ? 0x60u : 0x30u;
    const std::size_t off_last_err = is64 ? 0x68u : 0x34u;
    const std::size_t off_last_status = is64 ? 0x1250u : 0xBF4u;

    const std::uint64_t exc_list = tr.read_pointer(off_exc_list).value_or(0u);
    const std::uint64_t stack_base = tr.read_pointer(off_stack_base).value_or(0u);
    const std::uint64_t stack_limit = tr.read_pointer(off_stack_limit).value_or(0u);
    const std::uint64_t subsys_tib = tr.read_pointer(off_subsys_tib).value_or(0u);
    const std::uint64_t fiber_data = tr.read_pointer(off_fiber_data).value_or(0u);
    const std::uint64_t arb_user = tr.read_pointer(off_arb_user).value_or(0u);
    const std::uint64_t self_ptr = tr.read_pointer(off_self).value_or(0u);
    const std::uint64_t env_ptr = tr.read_pointer(off_env_ptr).value_or(0u);
    const std::uint64_t cid_pid = tr.read_pointer(off_cid_pid).value_or(0u);
    const std::uint64_t cid_tid = tr.read_pointer(off_cid_tid).value_or(0u);
    const std::uint64_t tls_ptr = tr.read_pointer(off_tls_ptr).value_or(0u);
    const std::uint64_t peb_ptr = tr.read_pointer(off_peb_ptr).value_or(0u);
    const std::uint32_t last_err = tr.read_u32(off_last_err).value_or(0u);

    snap.exception_list = exc_list;
    snap.stack_base = stack_base;
    snap.stack_limit = stack_limit;
    snap.tls_array_or_dtv = tls_ptr;
    snap.last_error_or_errno = last_err;

    snap.fields.push_back(DecodedField{
        "NT_TIB.ExceptionList", off_exc_list, exc_list, hex_ptr(exc_list, layout),
        "SEH registration chain head"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.StackBase", off_stack_base, stack_base, hex_ptr(stack_base, layout),
        "High address of thread stack"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.StackLimit", off_stack_limit, stack_limit, hex_ptr(stack_limit, layout),
        "Committed low limit of thread stack"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.SubSystemTib", off_subsys_tib, subsys_tib, hex_ptr(subsys_tib, layout),
        "Subsystem TIB pointer"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.FiberData", off_fiber_data, fiber_data, hex_ptr(fiber_data, layout),
        "Fiber data / TIB version"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.ArbitraryUserPointer", off_arb_user, arb_user, hex_ptr(arb_user, layout),
        "Application arbitrary user slot"});
    snap.fields.push_back(DecodedField{
        "NT_TIB.Self", off_self, self_ptr, hex_ptr(self_ptr, layout),
        "Linear self-pointer to TEB"});
    snap.fields.push_back(DecodedField{
        "EnvironmentPointer", off_env_ptr, env_ptr, hex_ptr(env_ptr, layout),
        "TEB environment pointer"});
    snap.fields.push_back(DecodedField{
        "ClientId.UniqueProcess", off_cid_pid, cid_pid, std::to_string(cid_pid),
        "Owning process ID"});
    snap.fields.push_back(DecodedField{
        "ClientId.UniqueThread", off_cid_tid, cid_tid, std::to_string(cid_tid),
        "Thread ID"});
    snap.fields.push_back(DecodedField{
        "ThreadLocalStoragePointer", off_tls_ptr, tls_ptr, hex_ptr(tls_ptr, layout),
        "Implicit TLS module array (__declspec(thread))"});
    snap.fields.push_back(DecodedField{
        "ProcessEnvironmentBlock", off_peb_ptr, peb_ptr, hex_ptr(peb_ptr, layout),
        "Pointer to owning PEB"});
    snap.fields.push_back(DecodedField{
        "LastErrorValue", off_last_err, last_err,
        std::to_string(last_err) + " (" + hex_u64(last_err, 8u) + ")",
        "Win32 GetLastError() slot"});

    const std::vector<std::uint8_t> status_bytes =
        read_struct_forgiving(session,
                              regions,
                              teb_addr + static_cast<std::uint64_t>(off_last_status),
                              {4u});
    if (status_bytes.size() == 4u) {
        const EndianReader sr(status_bytes, layout);
        if (const auto ntstatus = sr.read_u32(0u)) {
            snap.fields.push_back(DecodedField{
                "LastStatusValue", off_last_status, *ntstatus, hex_u64(*ntstatus, 8u),
                "Last NTSTATUS code"});
        }
    }

    snap.status = SubsystemStatus::available("teb", "Windows TEB decoded from target memory");
}

void inspect_elf_thread_environment(IProcessSession& session,
                                    const ThreadInfo& thread_info,
                                    const ThreadContext* thread_ctx,
                                    std::span<const MemoryRegion> regions,
                                    ThreadEnvironmentSnapshot& snap) {
    const TargetLayout layout = snap.layout;
    const bool is64 = layout.is_64bit();

    const std::optional<std::uint64_t> ip_opt =
        (thread_ctx != nullptr && thread_ctx->instruction_pointer != 0u)
            ? std::optional<std::uint64_t>(thread_ctx->instruction_pointer)
            : thread_info.instruction_pointer;
    const std::optional<std::uint64_t> sp_opt =
        (thread_ctx != nullptr && thread_ctx->stack_pointer != 0u)
            ? std::optional<std::uint64_t>(thread_ctx->stack_pointer)
            : thread_info.stack_pointer;

    std::optional<std::uint64_t> tp_opt;
    if (thread_ctx != nullptr && thread_ctx->tls_pointer.has_value() &&
        *thread_ctx->tls_pointer != 0u) {
        tp_opt = thread_ctx->tls_pointer;
    } else if (thread_info.tls_base.has_value() && *thread_info.tls_base != 0u) {
        tp_opt = thread_info.tls_base;
    }

    snap.fields.push_back(DecodedField{
        "TID", std::nullopt, snap.tid, std::to_string(snap.tid), "Kernel task ID"});
    if (!thread_info.name.empty()) {
        snap.fields.push_back(DecodedField{
            "Name", std::nullopt, std::nullopt, thread_info.name, "/proc/<pid>/task/<tid>/comm"});
    }

    std::string state_str(to_string(thread_info.state));
    if (thread_info.is_suspended) {
        state_str += " (Suspended)";
    }
    snap.fields.push_back(DecodedField{
        "State", std::nullopt, std::nullopt, std::move(state_str), "Scheduler run state"});

    if (ip_opt.has_value()) {
        snap.fields.push_back(DecodedField{
            "InstructionPointer", std::nullopt, *ip_opt, hex_ptr(*ip_opt, layout),
            "Current instruction pointer"});
    }
    if (sp_opt.has_value()) {
        snap.fields.push_back(DecodedField{
            "StackPointer", std::nullopt, *sp_opt, hex_ptr(*sp_opt, layout),
            "Current stack pointer"});
    }
    if (thread_info.syscall_number.has_value()) {
        const std::int64_t sc = *thread_info.syscall_number;
        snap.fields.push_back(DecodedField{
            "SyscallNumber",
            std::nullopt,
            sc >= 0 ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(sc)) : std::nullopt,
            sc < 0 ? "Userspace (-1)" : std::to_string(sc),
            "/proc/<pid>/task/<tid>/syscall",
        });
    }
    if (!thread_info.wait_channel.empty()) {
        snap.fields.push_back(DecodedField{
            "WaitChannel", std::nullopt, std::nullopt, thread_info.wait_channel,
            "/proc/<pid>/task/<tid>/wchan"});
    }

    populate_mapped_stack_bounds(sp_opt, regions, snap);
    if (snap.stack_base.has_value() && snap.stack_limit.has_value()) {
        snap.fields.push_back(DecodedField{
            "StackBase", std::nullopt, *snap.stack_base, hex_ptr(*snap.stack_base, layout),
            "High boundary of mapped thread stack"});
        snap.fields.push_back(DecodedField{
            "StackLimit", std::nullopt, *snap.stack_limit, hex_ptr(*snap.stack_limit, layout),
            "Low boundary of mapped thread stack"});
    }

    if (!tp_opt.has_value()) {
        const bool any_runtime = (snap.tid != 0u) || snap.stack_base.has_value() ||
                                 ip_opt.has_value() || sp_opt.has_value();
        snap.status =
            any_runtime
                ? SubsystemStatus::partial(
                      "procfs", "Thread runtime metadata available; TLS thread pointer unavailable")
                : SubsystemStatus::unavailable("thread", "Thread environment unavailable");
        return;
    }

    const std::uint64_t tp = *tp_opt;
    snap.block_address = tp;
    snap.fields.push_back(DecodedField{
        "ThreadPointer", std::nullopt, tp, hex_ptr(tp, layout),
        "Architecture TLS base (FS_BASE / GS_BASE / TPIDR_EL0 / tp)"});

    if (layout.architecture == Architecture::X86_64 || layout.architecture == Architecture::X86) {
        const std::size_t tcb_sz = is64 ? 0x38u : 0x1Cu;
        const std::vector<std::uint8_t> tcb_buf =
            read_struct_forgiving(session, regions, tp, {tcb_sz, is64 ? 0x30u : 0x18u});
        if (tcb_buf.size() >= (is64 ? 0x30u : 0x18u)) {
            const EndianReader tr(tcb_buf, layout);
            const std::size_t off_tcb = 0x00u;
            const std::size_t off_dtv = is64 ? 0x08u : 0x04u;
            const std::size_t off_self = is64 ? 0x10u : 0x08u;
            const std::size_t off_mult = is64 ? 0x18u : 0x0Cu;
            const std::size_t off_sysinfo = is64 ? 0x20u : 0x10u;
            const std::size_t off_sguard = is64 ? 0x28u : 0x14u;
            const std::size_t off_pguard = is64 ? 0x30u : 0x18u;

            const std::uint64_t tcb_ptr = tr.read_pointer(off_tcb).value_or(0u);
            const std::uint64_t dtv_ptr = tr.read_pointer(off_dtv).value_or(0u);
            const std::uint64_t self_ptr = tr.read_pointer(off_self).value_or(0u);
            const std::uint32_t multi_thr = tr.read_u32(off_mult).value_or(0u);
            const std::uint64_t sysinfo_ptr = tr.read_pointer(off_sysinfo).value_or(0u);
            const std::uint64_t sguard = tr.read_pointer(off_sguard).value_or(0u);

            snap.tls_array_or_dtv = dtv_ptr;
            snap.stack_guard_canary = sguard;

            snap.fields.push_back(DecodedField{
                "tcbhead_t.tcb", off_tcb, tcb_ptr, hex_ptr(tcb_ptr, layout),
                "TCB self-reference"});
            snap.fields.push_back(DecodedField{
                "tcbhead_t.dtv", off_dtv, dtv_ptr, hex_ptr(dtv_ptr, layout),
                "Dynamic Thread Vector (DTV)"});
            snap.fields.push_back(DecodedField{
                "tcbhead_t.self", off_self, self_ptr, hex_ptr(self_ptr, layout),
                "pthread descriptor pointer"});
            snap.fields.push_back(DecodedField{
                "tcbhead_t.multiple_threads", off_mult, multi_thr, std::to_string(multi_thr),
                "Multi-threaded process lock flag"});
            snap.fields.push_back(DecodedField{
                "tcbhead_t.sysinfo", off_sysinfo, sysinfo_ptr, hex_ptr(sysinfo_ptr, layout),
                "vDSO syscall entry pointer"});
            snap.fields.push_back(DecodedField{
                "tcbhead_t.stack_guard", off_sguard, sguard, hex_ptr(sguard, layout),
                "Per-thread stack protector canary"});

            if (tr.can_read(off_pguard, layout.pointer_size())) {
                const std::uint64_t pguard = tr.read_pointer(off_pguard).value_or(0u);
                snap.pointer_guard = pguard;
                snap.fields.push_back(DecodedField{
                    "tcbhead_t.pointer_guard", off_pguard, pguard, hex_ptr(pguard, layout),
                    "glibc pointer mangling guard"});
            }

            snap.status =
                SubsystemStatus::available("tcbhead_t", "Decoded Linux thread runtime and TCB");
            return;
        }
    } else {
        const std::size_t words_sz = layout.pointer_size() * 2u;
        const std::vector<std::uint8_t> tcb_words =
            read_struct_forgiving(session, regions, tp, {words_sz, layout.pointer_size()});
        if (tcb_words.size() >= layout.pointer_size()) {
            const EndianReader tr(tcb_words, layout);
            if (const auto dtv = tr.read_pointer(0x00u)) {
                snap.tls_array_or_dtv = *dtv;
                snap.fields.push_back(DecodedField{
                    "TCB.dtv", 0x00u, *dtv, hex_ptr(*dtv, layout),
                    "TLS Variant I Dynamic Thread Vector"});
            }
            if (tr.can_read(layout.pointer_size(), layout.pointer_size())) {
                if (const auto priv = tr.read_pointer(layout.pointer_size())) {
                    snap.fields.push_back(DecodedField{
                        "TCB.private", layout.pointer_size(), *priv, hex_ptr(*priv, layout),
                        "Implementation-reserved TCB slot"});
                }
            }
            snap.status = SubsystemStatus::available(
                "tls_tcb", "Decoded Linux thread runtime and Variant-I TCB");
            return;
        }
    }

    snap.status = SubsystemStatus::partial(
        "procfs", "Thread pointer known, but TCB memory could not be read");
}

}  // namespace

HeaderFlagsReport harvest_header_flags(const IBinaryImage& image) {
    HeaderFlagsReport report;
    report.format = image.format();
    report.layout = TargetLayout::from_image(image);

    switch (report.format) {
        case Format::PE:
            harvest_pe_header_flags(image, report);
            break;
        case Format::ELF:
            harvest_elf_header_flags(image, report);
            break;
        case Format::Unknown:
            report.status =
                SubsystemStatus::unavailable("binary_image", "Unknown binary container format");
            break;
    }

    return report;
}

ProcessEnvironmentSnapshot inspect_process_environment(IProcessSession& session,
                                                       std::span<const MemoryRegion> regions,
                                                       std::span<const ModuleInfo> modules,
                                                       const IBinaryImage* main_image) {
    ProcessEnvironmentSnapshot snap;
    snap.layout = session.target_layout();
    if (snap.layout.architecture == Architecture::Unknown && main_image != nullptr) {
        snap.layout = TargetLayout::from_image(*main_image);
    }

    const ProcessInfo& pinfo = session.info();
    snap.image_path = pinfo.executable_path.string();
    snap.command_line = pinfo.command_line;
    snap.current_directory = pinfo.working_directory.string();

    const auto peb_val = session.process_environment_block_address();
    const auto auxv_val = session.proc_auxv();
    const auto status_val = session.proc_status_text();
    const auto env_val = session.environment_variables();

    Format family = Format::Unknown;
    if (peb_val.has_value() && *peb_val.value != 0u) {
        family = Format::PE;
    } else if (auxv_val.has_value() || status_val.has_value()) {
        family = Format::ELF;
    } else if (main_image != nullptr && main_image->format() != Format::Unknown) {
        family = main_image->format();
    } else {
        for (const ModuleInfo& mod : modules) {
            if (mod.is_main_module && mod.format != Format::Unknown) {
                family = mod.format;
                break;
            }
        }
        if (family == Format::Unknown) {
            for (const ModuleInfo& mod : modules) {
                if (mod.format != Format::Unknown) {
                    family = mod.format;
                    break;
                }
            }
        }
        if (family == Format::Unknown) {
            if (ends_with_icase(snap.image_path, ".exe") ||
                ends_with_icase(pinfo.name, ".exe")) {
                family = Format::PE;
            } else {
#ifdef _WIN32
                family = Format::PE;
#else
                family = Format::ELF;
#endif
            }
        }
    }

    snap.os_family = family;
    if (family == Format::PE) {
        inspect_pe_process_environment(session, regions, modules, peb_val, env_val, snap);
    } else {
        inspect_elf_process_environment(
            session, regions, modules, main_image, auxv_val, status_val, env_val, snap);
    }

    return snap;
}

ThreadEnvironmentSnapshot inspect_thread_environment(IProcessSession& session,
                                                     const ThreadInfo& thread_info,
                                                     const ThreadContext* thread_ctx,
                                                     std::span<const MemoryRegion> regions) {
    ThreadEnvironmentSnapshot snap;
    snap.tid = (thread_info.tid != 0u) ? thread_info.tid
                                       : (thread_ctx != nullptr ? thread_ctx->tid : 0u);
    snap.layout = (thread_ctx != nullptr) ? thread_ctx->layout : session.target_layout();

    std::optional<std::uint64_t> teb_opt;
    if (thread_ctx != nullptr && thread_ctx->teb_address.has_value() &&
        *thread_ctx->teb_address != 0u) {
        teb_opt = thread_ctx->teb_address;
    } else if (thread_info.teb_address.has_value() && *thread_info.teb_address != 0u) {
        teb_opt = thread_info.teb_address;
    }

    Format family = Format::Unknown;
    if (teb_opt.has_value()) {
        family = Format::PE;
    } else if (thread_ctx != nullptr && thread_ctx->tls_pointer.has_value() &&
               *thread_ctx->tls_pointer != 0u) {
        family = Format::ELF;
    } else if (thread_info.tls_base.has_value() && *thread_info.tls_base != 0u) {
        family = Format::ELF;
    } else if (const auto peb_val = session.process_environment_block_address();
               peb_val.has_value() && *peb_val.value != 0u) {
        family = Format::PE;
    } else if (session.proc_auxv().has_value() || session.proc_status_text().has_value()) {
        family = Format::ELF;
    } else if (ends_with_icase(session.info().executable_path.string(), ".exe") ||
               ends_with_icase(session.info().name, ".exe")) {
        family = Format::PE;
    } else {
#ifdef _WIN32
        family = Format::PE;
#else
        family = Format::ELF;
#endif
    }

    snap.os_family = family;
    if (family == Format::PE) {
        inspect_pe_thread_environment(session, thread_info, thread_ctx, regions, teb_opt, snap);
    } else {
        inspect_elf_thread_environment(session, thread_info, thread_ctx, regions, snap);
    }

    return snap;
}

}  // namespace peelf
